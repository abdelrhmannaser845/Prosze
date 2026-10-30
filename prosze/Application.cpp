// prosze.cpp - removes sensitive details from a prompt BEFORE it goes to an AI.
//
// No AI involved: only regexes, checksums and your own list of names.
//
//   your prompt --> prosze --> AI --> prosze --> answer with real values back
//
// Build
//   Linux/macOS : g++ -std=c++17 -O2 -o prosze prosze.cpp
//   Windows     : cl /std:c++17 /O2 /EHsc prosze.cpp
//                 (or MinGW: g++ -std=c++17 -O2 -o prosze.exe prosze.cpp)
//
// Commands
//   prosze chat                       paste a prompt -> safe text; paste the reply -> real text
//   prosze redact  < prompt.txt       print the safe version
//   prosze restore < reply.txt        put the real values back
//   prosze check   < prompt.txt       exit code 1 if anything sensitive is found
//   prosze run [opts] -- cmd args...  redact stdin and args, run cmd, restore its output
//
// Note: the proxy subcommand has been removed. Use the Python CLI for proxy functionality.
// Options
//   --term "Acme Corp"            hide this name (repeatable)
//   --term CUSTOMER="Acme Corp"   same, placeholder becomes [[CUSTOMER_1]]
//   --terms FILE                  one term per line, optional LABEL=value, # comments
//                                 (./.prosze-terms is loaded automatically)
//   --env FILE                    also hide every value found in a .env file
//   --map FILE                    mapping file (default ./.prosze-map)
//   --names LEVEL                 automatic name finder: off | strict | normal (default) | aggressive
//   --explain                     print what was hidden (placeholder = real value) to stderr
//
// Hidden automatically: phone numbers, bank accounts / IBANs, e-mails, cards,
// SSNs, API keys / tokens / passwords, private keys, private IPs.
// Names of people, customers, companies and projects are found WITHOUT a list,
// by heuristics (no AI): capitalisation, context words (customer, contact, Dr,
// Dear...), company suffixes (Inc, Corp, GmbH, Sp. z o.o.) and a built-in
// first-name dictionary. Once a name is found, every later mention is hidden too
// (even in lower case). You can still add names yourself with --term/--terms.
//
// The mapping file holds the real values in clear text: keep it local, out of git.

#ifdef _WIN32
  #ifndef _CRT_SECURE_NO_WARNINGS
  #define _CRT_SECURE_NO_WARNINGS
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #define popen _popen
  #define pclose _pclose
  #define isatty _isatty
#else
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/wait.h>
  #include <unistd.h>
#endif
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

// ------------------------------------------------------------------ helpers
static string lower(string s)
{
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// '_' counts as a word character so "customer" never matches inside [[CUSTOMER_1]].
static bool word_char(unsigned char c) { return isalnum(c) || c == '_' || c >= 0x80; }

static int count_digits(const string& s)
{
    int n = 0;
    for (char c : s) if (isdigit((unsigned char)c)) ++n;
    return n;
}

static string trim(const string& s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    return s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1);
}

// ---------------------------------------------------------------- validators
static bool luhn_ok(const string& raw)
{
    string d;
    for (char c : raw) if (isdigit((unsigned char)c)) d += c;
    if (d.size() < 13 || d.size() > 19) return false;
    int sum = 0; bool dbl = false;
    for (auto it = d.rbegin(); it != d.rend(); ++it)
    {
        int v = *it - '0';
        if (dbl) { v *= 2; if (v > 9) v -= 9; }
        sum += v; dbl = !dbl;
    }
    return sum % 10 == 0;
}

static bool iban_ok(const string& raw)
{
    string t;
    for (char c : raw) if (c != ' ') t += (char)toupper((unsigned char)c);
    if (t.size() < 15 || t.size() > 34) return false;
    string r = t.substr(4) + t.substr(0, 4);
    int rem = 0;
    for (char c : r)
    {
        if (isdigit((unsigned char)c)) rem = (rem * 10 + (c - '0')) % 97;
        else if (isalpha((unsigned char)c)) rem = (rem * 100 + (c - 'A' + 10)) % 97;
        else return false;
    }
    return rem == 1;
}

static bool looks_random(const string& s)
{
    bool dig = false, alp = false;
    set<char> distinct;
    for (char c : s)
    {
        if (isdigit((unsigned char)c)) dig = true;
        if (isalpha((unsigned char)c)) alp = true;
        distinct.insert(c);
    }
    return dig && alp && distinct.size() >= 10;
}

static bool not_placeholder(const string& s) { return s.rfind("[[", 0) != 0; }

static bool kv_ok(const string& v)
{
    string l = lower(v);
    return not_placeholder(v) && l != "true" && l != "false" && l != "null" && l != "none";
}

static bool private_ip(const string& s)
{
    int a, b, c, d;
    if (sscanf(s.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    return a == 10 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31);
}

static bool phone_labeled_ok(const string& s) { int n = count_digits(s); return n >= 6 && n <= 15; }
static bool phone_intl_ok(const string& s)    { int n = count_digits(s); return n >= 8 && n <= 15; }

// Separated groups like "601 234 567": must not be a date or timestamp.
static bool phone_sep_ok(const string& s)
{
    static const regex date(R"(^\d{4}-\d{1,2}-\d{1,2})");
    int n = count_digits(s);
    return n >= 9 && n <= 15 && !regex_search(s, date);
}

// ------------------------------------------------------- mapping file escapes
static string esc(const string& s)
{
    string o;
    for (char c : s)
    {
        if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o += c;
    }
    return o;
}

static string unesc(const string& s)
{
    string o;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size())
        {
            char n = s[++i];
            o += (n == 'n') ? '\n' : (n == 'r') ? '\r' : (n == 't') ? '\t' : n;
        }
        else o += s[i];
    }
    return o;
}

// ------------------------------------------------------- automatic name finder
// Heuristics only: no AI, no network.
static set<string> make_set(const char* words, bool fold_case)
{
    set<string> out; istringstream in(words); string w;
    while (in >> w) out.insert(fold_case ? lower(w) : w);
    return out;
}

// Capitalised words that are NOT names (and common tech brands).
static const set<string>& stop_words()
{
    static const set<string> s = make_set(
        "i a an the this that these those it its he she we you they my our your their his her me us them "
        "and or but if then else when where what why how who whom which whose while for from with without "
        "into onto about above below over under after before during between among through to of in on at by "
        "as is are was were be been being am do does did done have has had having can could should would will "
        "shall may might must not no yes also just only very more most less some any all each every both "
        "either neither other another such than too so please thanks thank hi hello hey dear regards sincerely "
        "best cheers sorry ok okay sure note notes example examples step steps todo fixme warning error errors "
        "exception exceptions info debug trace traceback true false none null nil undefined void return returns "
        "class function method import export let var const static public private protected new delete get set "
        "add remove update create read write run runs running start stop open close check test tests testing "
        "build deploy install uninstall fix fixed bug bugs issue issues problem question answer answers help "
        "need needs want wants make makes using use used try tried see look find found show tell give take "
        "here there now today tomorrow yesterday monday tuesday wednesday thursday friday saturday sunday "
        "january february march april may june july august september october november december "
        "mon tue wed thu fri sat sun feb mar apr jun jul aug sep sept oct nov dec "
        "customer customers client clients project projects company companies contact attn attention "
        "mr mrs ms miss dr prof sir madam mme herr frau pan pani panie mgr ing ceo cto cfo manager director "
        "owner employee colleague boss developer engineer team teams version versions release latest first "
        "second third next last previous current user users admin root server database table file files "
        "folder path name names email phone address account number invoice payment order orders report data "
        "code api sdk ui ux ci cd "
        "i'm i've i'll i'd it's let's that's what's there's here's we're you're they're can't won't don't "
        "doesn't didn't isn't aren't wasn't weren't couldn't shouldn't wouldn't haven't hasn't he's she's "
        "we've you've they've "
        "python java javascript typescript linux windows macos ios android docker kubernetes git github "
        "gitlab bitbucket aws azure gcp google microsoft apple amazon oracle postgres postgresql mysql sqlite "
        "mongodb redis nginx apache react angular vue node nodejs django flask spring rust golang ruby rails "
        "php swift kotlin chrome firefox safari edge excel word powerpoint slack jira claude chatgpt openai "
        "anthropic gemini ubuntu debian centos redhat visual studio vscode json xml yaml html css sql http "
        "https tcp udp ssh ssl tls dns url uri "
        "proszę prosze cześć czesc dzień dzien dobry dziękuję dziekuje jak czy dlaczego gdzie kiedy który "
        "ktory jest nie tak ale oraz dla przez po na się sie to ten ta te co jestem mam mamy pomóż pomoz "
        "błąd blad projekt klient firma", true);
    return s;
}

static const set<string>& first_names()      // exact, Title-case
{
    static const set<string> s = make_set(
        "James John Robert Michael William David Richard Joseph Thomas Charles Christopher Daniel Matthew "
        "Anthony Mark Donald Steven Paul Andrew Joshua Kenneth Kevin Brian George Timothy Ronald Edward Jason "
        "Jeffrey Ryan Jacob Gary Nicholas Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel "
        "Gregory Alexander Patrick Frank Raymond Jack Dennis Jerry Tyler Aaron Jose Adam Nathan Henry Peter "
        "Zachary Douglas Harold Kyle Noah Ethan Jeremy Walter Christian Keith Roger Terry Austin Sean Gerald "
        "Carl Dylan Harry Jordan Jesse Bryan Lawrence Arthur Gabriel Bruce Logan Billy Joe Alan Juan Albert "
        "Elijah Wayne Randy Vincent Philip Eugene Russell Bobby Johnny Bradley Roy Ralph "
        "Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Sarah Karen Lisa Nancy Betty Margaret "
        "Sandra Ashley Kimberly Emily Donna Michelle Carol Amanda Dorothy Melissa Deborah Stephanie Rebecca "
        "Sharon Laura Cynthia Kathleen Amy Angela Shirley Anna Brenda Pamela Emma Nicole Helen Samantha "
        "Katherine Christine Debra Rachel Carolyn Janet Catherine Maria Heather Diane Ruth Julie Olivia Joyce "
        "Virginia Victoria Kelly Lauren Christina Joan Evelyn Judith Megan Andrea Cheryl Hannah Jacqueline "
        "Martha Gloria Teresa Ann Sara Madison Frances Kathryn Janice Jean Abigail Alice Julia Judy Sophia "
        "Grace Denise Amber Doris Marilyn Danielle Beverly Isabella Theresa Diana Natalie Brittany Charlotte "
        "Marie Kayla Alexis Lori "
        "Jan Piotr Krzysztof Andrzej Tomasz Pawe\xC5\x82 Micha\xC5\x82 Marcin Marek Grzegorz J\xC3\xB3zef "
        "\xC5\x81ukasz Zbigniew Jerzy Tadeusz Mateusz Dariusz Mariusz Wojciech Ryszard Jakub Henryk Rafa\xC5\x82 "
        "Kamil Stanis\xC5\x82" "aw Maciej S\xC5\x82" "awomir Artur Kazimierz Karol Bartosz Dawid Przemys\xC5\x82" "aw "
        "Konrad Jacek Adrian Rados\xC5\x82" "aw Waldemar Katarzyna Ma\xC5\x82gorzata Agnieszka Ewa Krystyna "
        "Magdalena El\xC5\xBC" "bieta Joanna Aleksandra Zofia Danuta Monika Beata Dorota Marta Halina Jadwiga "
        "Iwona Renata Justyna Karolina Natalia Weronika Paulina Kinga Ilona Wiktoria Oliwia "
        "Ahmed Ahmad Mohamed Mohammed Muhammad Ali Omar Hassan Hussein Ibrahim Youssef Yusuf Mahmoud Mustafa "
        "Khaled Karim Tarek Fatima Aisha Mariam Layla Nour Salma Hana", false);
    return s;
}

static const set<string>& org_suffixes()
{
    static const set<string> s = make_set(
        "inc corp corporation ltd llc llp plc gmbh ag spa srl sa sp co company group holdings holding bank "
        "technologies technology solutions systems labs partners associates industries enterprises consulting "
        "services", true);
    return s;
}
static const set<string> HONOR = make_set("mr mrs ms miss dr prof sir madam mme herr frau pan pani panie mgr in\xC5\xBC inz ing", true);
static const set<string> GREET = make_set("dear hi hello hey cze\xC5\x9B\xC4\x87 czesc witaj regards thanks sincerely cheers", true);
static const set<string> PCTX  = make_set("contact attn attention named ceo cto cfo manager director owner employee colleague boss", true);
static const set<string> CUSTX = make_set("customer client klient klienta", true);
static const set<string> COMPX = make_set("company firma organization organisation vendor supplier partner employer firm", true);
static const set<string> PROJX = make_set("project projekt codename repo repository product", true);
static const set<string> PARTICLES = make_set("von van de di da del der la le of", true);

struct Tok
{
    size_t b, e;
    string text, low;
    int chars;
    bool cap, allcaps, ident, initial, sstart, inph;
};

static size_t letter_len(const string& s, size_t i)
{
    unsigned char c = (unsigned char)s[i];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return 1;
    if (c >= 0xC3 && c <= 0xDF && i + 1 < s.size() && (((unsigned char)s[i + 1]) & 0xC0) == 0x80) return 2;
    return 0;
}

static bool upper_lead(const string& s, size_t i)
{
    unsigned char c = (unsigned char)s[i];
    if (c >= 'A' && c <= 'Z') return true;
    if (i + 1 >= s.size()) return false;
    unsigned char d = (unsigned char)s[i + 1];
    if (c == 0xC3) return d >= 0x80 && d <= 0x9E && d != 0x97;
    if (c == 0xC4) return d == 0x84 || d == 0x86 || d == 0x98;
    if (c == 0xC5) return d == 0x81 || d == 0x83 || d == 0x9A || d == 0xB9 || d == 0xBB;
    return false;
}

static bool at_sentence_start(const string& s, size_t b)
{
    long k = (long)b - 1;
    while (k >= 0)
    {
        unsigned char c = (unsigned char)s[k];
        if (c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '(' || c == '[' || c == '*' ||
            c == '#' || c == '>' || c == '-' || c >= 0x80) { --k; continue; }
        return c == '\n' || c == '\r' || c == '.' || c == '!' || c == '?' || c == ':' || c == ';';
    }
    return true;
}

static vector<Tok> tokenize(const string& s)
{
    vector<Tok> out;
    const size_t n = s.size();
    vector<pair<size_t, size_t>> ph;                       // [[PLACEHOLDER]] spans
    for (size_t p = 0; (p = s.find("[[", p)) != string::npos;)
    {
        size_t q = s.find("]]", p + 2);
        if (q == string::npos) break;
        ph.push_back({ p, q + 2 });
        p = q + 2;
    }
    auto ch = [&](long k) -> char { return (k >= 0 && k < (long)n) ? s[(size_t)k] : '\0'; };

    size_t i = 0;
    while (i < n)
    {
        if (!letter_len(s, i)) { ++i; continue; }
        size_t b = i;
        while (i < n)
        {
            size_t l = letter_len(s, i);
            if (l) { i += l; continue; }
            if ((s[i] == '\'' || s[i] == '-') && i + 1 < n && letter_len(s, i + 1)) { ++i; continue; }
            break;
        }
        size_t e = i;
        string txt = s.substr(b, e - b);
        if (txt.size() > 2 && lower(txt.substr(txt.size() - 2)) == "'s") { e -= 2; txt.resize(txt.size() - 2); }

        Tok t;
        t.b = b; t.e = e; t.text = txt; t.low = lower(txt);
        t.chars = 0;
        int up = 0, lo = 0, hi = 0;
        for (unsigned char c : txt)
        {
            if ((c & 0xC0) != 0x80) ++t.chars;
            if (c >= 'A' && c <= 'Z') ++up;
            else if (c >= 'a' && c <= 'z') ++lo;
            else if (c >= 0x80) ++hi;
        }
        t.cap = upper_lead(txt, 0);
        t.allcaps = (up >= 2 && lo == 0 && hi == 0);

        bool camel = false; int inner_up = 0;
        for (size_t k = 1; k < txt.size(); ++k)
            if (txt[k] >= 'A' && txt[k] <= 'Z' && txt[k - 1] >= 'a' && txt[k - 1] <= 'z') { camel = true; ++inner_up; }
        if (txt.size() > 2 && txt[0] == 'M' && txt[1] == 'c' && inner_up == 1) camel = false;   // McDonald

        bool ident = camel && !t.allcaps;                  // UserService, getName...
        char pc = ch((long)b - 1), nc = ch((long)e);
        if (isdigit((unsigned char)pc) || pc == '_' || isdigit((unsigned char)nc) || nc == '_') ident = true;
        if (pc == '.' && isalnum((unsigned char)ch((long)b - 2))) ident = true;   // obj.Name
        if (pc == ':' && ch((long)b - 2) == ':') ident = true;
        if (pc == '>' && ch((long)b - 2) == '-') ident = true;
        if (pc == '/' || pc == '\\' || pc == '$' || pc == '@' || pc == '#' || pc == '%') ident = true;
        if (nc == '(') ident = true;                                              // function call
        if (nc == '.' && isalnum((unsigned char)ch((long)e + 1))) ident = true;   // file.ext
        if (nc == ':' && ch((long)e + 1) == ':') ident = true;
        t.ident = ident;

        t.initial = (t.chars == 1 && t.cap && nc == '.');
        t.sstart = at_sentence_start(s, b);
        t.inph = false;
        for (auto& r : ph) if (b >= r.first && b < r.second) { t.inph = true; break; }
        out.push_back(t);
    }
    return out;
}

struct NameSpan { size_t b, e; string cat; };

static vector<NameSpan> detect_names(const string& s, int level)
{
    vector<NameSpan> out;
    if (level <= 0) return out;
    const vector<Tok> T = tokenize(s);
    const size_t N = T.size();

    auto cand = [&](const Tok& t) {
        return t.cap && !t.ident && !t.inph && !t.allcaps && t.chars >= 2 && !stop_words().count(t.low);
    };
    auto suffix = [&](const Tok& t) {
        return t.cap && !t.inph && org_suffixes().count(t.low) > 0 &&
               (!t.ident || t.low == "gmbh" || t.low == "spa");
    };
    auto gap_ok = [&](const Tok& a, const Tok& b) -> bool {
        size_t p = a.e;
        if (b.b <= p) return false;
        if (a.initial) { if (s[p] != '.') return false; ++p; }
        if (p >= b.b) return false;
        for (; p < b.b; ++p) if (s[p] != ' ' && s[p] != '\t') return false;
        return true;
    };
    // word right before token index k, if only light punctuation separates them
    auto prev_word = [&](size_t k) -> string {
        if (k == 0) return "";
        const Tok& p = T[k - 1];
        string g = s.substr(p.e, T[k].b - p.e);
        if (g.size() > 4) return "";
        bool dot = false;
        for (char c : g)
        {
            if (c == '.') dot = true;
            else if (c != ' ' && c != '\t' && c != ':' && c != ',' && c != '-' && c != '"' && c != '\'' && c != '(') return "";
        }
        if (dot && !HONOR.count(p.low)) return "";          // "Dr. Smith" yes, "...this. Smith" no
        return p.low;
    };

    vector<char> nl(N, 0);
    for (size_t i = 0; i < N; ++i)
        nl[i] = cand(T[i]) || suffix(T[i]) ||
                (T[i].initial && !T[i].ident && !T[i].inph && i + 1 < N && cand(T[i + 1]) && gap_ok(T[i], T[i + 1]));

    for (size_t i = 0; i < N;)
    {
        if (!nl[i]) { ++i; continue; }
        size_t first = i, last = i;
        while (last + 1 < N && last - first < 6)
        {
            size_t k = last + 1;
            if (!gap_ok(T[last], T[k])) break;
            if (nl[k]) { last = k; continue; }
            if (PARTICLES.count(T[k].low) && k + 1 < N && nl[k + 1] && gap_ok(T[k], T[k + 1])) { last = k + 1; continue; }
            break;
        }
        i = last + 1;

        // company suffix (Inc, Corp, GmbH, Sp. z o.o. ...)
        size_t ls = string::npos;
        for (size_t k = first; k <= last; ++k) if (suffix(T[k])) ls = k;
        bool org = false;
        if (ls != string::npos)
        {
            bool before = false;
            for (size_t k = first; k < ls; ++k) if (cand(T[k]) || T[k].initial) before = true;
            if (before) { org = true; last = ls; }
            else
            {
                while (first <= last && suffix(T[first]) && !cand(T[first])) ++first;
                if (first > last) continue;
            }
        }
        int ntok = 0;
        for (size_t k = first; k <= last; ++k) if (nl[k]) ++ntok;

        const string pw = prev_word(first);
        string fn = T[first].text.substr(0, T[first].text.find('-'));
        bool fname = first_names().count(fn) > 0;

        string cat;
        if (CUSTX.count(pw)) cat = "CUSTOMER";
        else if (PROJX.count(pw)) cat = "PROJECT";
        else if (org) cat = "ORG";
        else if (HONOR.count(pw) || GREET.count(pw) || PCTX.count(pw)) cat = "PERSON";
        else if (COMPX.count(pw)) cat = "ORG";
        else if (fname && ntok >= 2) cat = "PERSON";
        else if (fname && ntok == 1 && !T[first].sstart && level >= 2) cat = "PERSON";
        else if (ntok >= 2 && level >= 2) cat = "NAME";
        else if (ntok == 1 && !T[first].sstart && level >= 3) cat = "NAME";
        else continue;

        size_t endp = T[last].e;
        if (org && T[last].low == "sp")
        {
            if (s.compare(endp, 8, ". z o.o.") == 0) endp += 8;
            else if (s.compare(endp, 7, ". z o.o") == 0) endp += 7;
        }
        out.push_back({ T[first].b, endp, cat });
    }
    return out;
}

// -------------------------------------------------------------------- vault
struct Rule
{
    string cat;
    regex rx;
    size_t group;
    function<bool(const string&)> validate;
};

struct Term
{
    string cat;
    string low;      // lower-cased text
};

class prosze
{
    map<string, string> forward;     // placeholder -> real
    map<string, string> backward;    // real -> placeholder
    map<string, string> fold;        // cat + '\x01' + lowercase name -> placeholder
    map<string, int> counters;
    set<string> term_cats;
    vector<Rule> rules;
    vector<pair<string, string>> literals;   // exact .env values, longest first
    vector<Term> terms;                      // names, longest first
    map<string, string> name_fold;           // lowercase name -> placeholder (any name category)
public:
    vector<pair<string, string>> fresh;      // placeholders created by the last redact()
    int name_level = 2;                      // 0 off, 1 strict, 2 normal, 3 aggressive
    size_t hits = 0;
    bool dirty = false;

    prosze()
    {
        for (const char* c : { "PERSON", "ORG", "CUSTOMER", "PROJECT", "NAME" }) term_cats.insert(c);

        // Order matters: wide / specific patterns first.
        add("PASSWORD", R"RX(\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@)RX", 1, not_placeholder);
        add("EMAIL", R"RX([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})RX");

        add("TOKEN", R"RX(\b(?:AKIA|ASIA)[A-Z0-9]{16}\b)RX");
        add("TOKEN", R"RX(\bAIza[0-9A-Za-z_\-]{35}\b)RX");
        add("TOKEN", R"RX(\b(?:sk|pk|rk|ghp|gho|ghs|ghu|glpat|xox[baprs])[-_][A-Za-z0-9_\-]{12,}\b)RX");
        add("TOKEN", R"RX(\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b)RX");
        add("TOKEN", R"RX(\bBearer\s+([A-Za-z0-9_\-\.=]{16,}))RX", 1, not_placeholder);

        // name = value, where the name smells like a secret
        add("PASSWORD",
            R"RX(([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?([^\s"',;]{6,}))RX",
            2, kv_ok, true);

        // bank accounts, SSN, labeled phones
        add("IBAN", R"RX(\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b)RX", 0, iban_ok);
        add("ACCOUNT",
            R"RX(\b(?:account|acct|a/c|iban|konto|konta)\b\s*(?:no\.?|number|nr\.?|#)?\s*[:=#]?\s*((?:[A-Z]{2}\d{2} ?)?\d[\d \-]{5,30}\d))RX",
            1, not_placeholder, true);
        add("SSN", R"RX(\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b)RX");
        add("PHONE",
            R"RX(\b(?:phone|tel|telephone|mobile|cell|fax|whatsapp)\b\s*(?:no\.?|number|#)?\s*[:=]?\s*(\+?\d[\d ()./\-]{5,18}\d))RX",
            1, phone_labeled_ok, true);

        add("CARD", R"RX(\b\d(?:[ \-]?\d){12,18}\b)RX", 0, luhn_ok);
        add("APIKEY", R"RX(\b[A-Za-z0-9]{32}\b)RX", 0, looks_random);
        add("APIKEY", R"RX(\b[A-Fa-f0-9]{40,64}\b)RX");
        add("IP", R"RX(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)RX", 0, private_ip);

        // std::regex has no look-behind: the leading boundary is captured in
        // group 1 and only group 2 (the number) is replaced.
        add("PHONE", R"RX((^|[^\w.+\-])(\+\d[\d ()./\-]{7,18}\d)(?!\w))RX", 2, phone_intl_ok);
        add("PHONE",
            R"RX((^|[^\w.+/\-])(\(?\d{2,4}\)?[ .\-]\d{2,4}[ .\-]\d{2,4}(?:[ .\-]\d{2,4})?)(?![\w/\-]))RX",
            2, phone_sep_ok);
    }

    void add(const string& cat, const string& pat, size_t group = 0,
             function<bool(const string&)> v = nullptr, bool icase = false)
    {
        auto flags = regex::ECMAScript | (icase ? regex::icase : regex::ECMAScript);
        rules.push_back({ cat, regex(pat, flags), group, move(v) });
    }

    // "Acme Corp" or "CUSTOMER=Acme Corp"
    void add_term(const string& spec)
    {
        string s = trim(spec), cat = "TERM", text = s;
        size_t eq = s.find('=');
        if (eq != string::npos && eq >= 2 && eq <= 20)
        {
            string label = s.substr(0, eq);
            bool ok = isupper((unsigned char)label[0]) != 0;
            for (char c : label)
                if (!(isupper((unsigned char)c) || isdigit((unsigned char)c) || c == '_')) ok = false;
            if (ok) { cat = label; text = trim(s.substr(eq + 1)); }
        }
        if (text.size() < 2) return;
        terms.push_back({ cat, lower(text) });
        sort(terms.begin(), terms.end(),
             [](const Term& a, const Term& b) { return a.low.size() > b.low.size(); });
        term_cats.insert(cat);
        // names already present in a loaded map keep their placeholder
        for (auto& [k, v] : forward)
            if (k.rfind("[[" + cat + "_", 0) == 0) fold[cat + '\x01' + lower(v)] = k;
    }

    bool load_terms(const string& path)
    {
        ifstream in(path);
        if (!in) return false;
        string line;
        while (getline(in, line))
        {
            line = trim(line);
            if (!line.empty() && line[0] != '#') add_term(line);
        }
        return true;
    }

    void add_literal(const string& s)
    {
        if (s.size() < 4) return;     // "1", "yes"... would shred ordinary text
        literals.push_back({ s, "ENV" });
        sort(literals.begin(), literals.end(),
             [](auto& a, auto& b) { return a.first.size() > b.first.size(); });
    }

    bool load_env(const string& path)
    {
        ifstream in(path);
        if (!in) return false;
        string line;
        while (getline(in, line))
        {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            if (line.compare(0, 7, "export ") == 0) line = line.substr(7);
            size_t eq = line.find('=');
            if (eq == string::npos) continue;
            string v = trim(line.substr(eq + 1));
            if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front())
                v = v.substr(1, v.size() - 2);
            add_literal(v);
        }
        return true;
    }

    string save(const string& value, const string& cat)
    {
        ++hits;
        auto it = backward.find(value);
        if (it != backward.end()) return it->second;

        bool is_term = term_cats.count(cat) > 0;
        string fk = cat + '\x01' + lower(value);
        if (is_term)
        {
            auto f = fold.find(fk);
            if (f != fold.end()) return f->second;   // same name, other capitalisation
        }
        string key = "[[" + cat + "_" + to_string(++counters[cat]) + "]]";
        backward[value] = key;
        forward[key] = value;
        if (is_term) fold[fk] = key;
        dirty = true;
        fresh.push_back({ key, value });
        return key;
    }

    string redact(const string& input)
    {
        fresh.clear();
        string t = replace_literals(input);
        t = replace_key_blocks(t);
        for (const Rule& r : rules) t = apply(t, r);
        for (const Term& term : terms) t = replace_term(t, term);   // listed + learned names
        return auto_names(t);                                       // names nobody listed
    }

    bool set_level(const string& s)
    {
        if (s == "off") name_level = 0;
        else if (s == "strict") name_level = 1;
        else if (s == "normal") name_level = 2;
        else if (s == "aggressive") name_level = 3;
        else return false;
        return true;
    }

    void print_fresh(ostream& os) const
    {
        for (auto& [k, v] : fresh) os << "  " << k << " = " << v << '\n';
    }

    // Names found in earlier runs (stored in the map) keep being hidden.
    void learn_from_map()
    {
        static const set<string> auto_cats = { "PERSON", "ORG", "CUSTOMER", "PROJECT", "NAME" };
        for (auto& [k, v] : forward)
        {
            size_t us = k.rfind('_');
            if (k.size() < 6 || us == string::npos || us < 2) continue;
            string cat = k.substr(2, us - 2);
            if (!auto_cats.count(cat)) continue;
            learn(cat, v);
            for (auto& a : aliases_of(cat, v)) learn(cat, a);
            name_fold[lower(v)] = k;
            fold[cat + '\x01' + lower(v)] = k;
        }
    }

    string restore(const string& input) const
    {
        static const regex ph(R"RX(\[\[[A-Z][A-Z0-9_]*_\d+\]\])RX");
        string out; size_t last = 0;
        for (auto it = sregex_iterator(input.begin(), input.end(), ph);
             it != sregex_iterator(); ++it)
        {
            auto f = forward.find(it->str());
            if (f == forward.end()) continue;
            out.append(input, last, it->position(0) - last);
            out.append(f->second);
            last = it->position(0) + it->length(0);
        }
        out.append(input, last, string::npos);
        return out;
    }

    bool save_map(const string& path) const
    {
        { ofstream touch(path, ios::app); if (!touch) return false; }
#ifndef _WIN32
        chmod(path.c_str(), 0600);        // private before any secret is written
#endif
        ofstream out(path, ios::trunc);
        if (!out) return false;
        for (auto& [k, v] : forward) out << k << '\t' << esc(v) << '\n';
        return true;
    }

    void load_map(const string& path)
    {
        ifstream in(path);
        string line;
        while (getline(in, line))
        {
            size_t tab = line.find('\t');
            if (tab == string::npos) continue;
            string k = line.substr(0, tab), v = unesc(line.substr(tab + 1));
            forward[k] = v; backward[v] = k;
            if (k.size() > 5 && k.rfind("[[", 0) == 0)          // [[CAT_N]]
            {
                string inner = k.substr(2, k.size() - 4);
                size_t us = inner.rfind('_');
                if (us != string::npos)
                {
                    int n = atoi(inner.c_str() + us + 1);
                    int& c = counters[inner.substr(0, us)];
                    c = max(c, n);
                }
            }
        }
    }

private:
    static vector<string> aliases_of(const string& cat, const string& val)
    {
        vector<string> r;
        if (cat == "PERSON")
        {
            istringstream in(val); string w;
            while (in >> w)
            {
                while (!w.empty() && w.back() == '.') w.pop_back();
                string lw = lower(w);
                if (w.size() >= 3 && w != val && !stop_words().count(lw) && !PARTICLES.count(lw))
                    r.push_back(w);
            }
        }
        else if (cat == "ORG" || cat == "CUSTOMER")
        {
            size_t sp = val.find_last_of(' ');
            if (sp != string::npos && org_suffixes().count(lower(val.substr(sp + 1))))
            {
                string pre = trim(val.substr(0, sp));
                if (pre.size() >= 3 && !stop_words().count(lower(pre))) r.push_back(pre);
            }
        }
        return r;
    }

    void learn(const string& cat, const string& value)
    {
        if (value.size() < 3) return;
        string low = lower(value);
        for (auto& t : terms) if (t.low == low) return;
        terms.push_back({ cat, low });
        sort(terms.begin(), terms.end(),
             [](const Term& a, const Term& b) { return a.low.size() > b.low.size(); });
    }

    string save_name(const string& value, const string& cat)
    {
        string lk = lower(value);
        auto it = name_fold.find(lk);
        if (it != name_fold.end()) { ++hits; return it->second; }
        string key = save(value, cat);
        name_fold[lk] = key;
        return key;
    }

    string auto_names(const string& text)
    {
        vector<NameSpan> spans = detect_names(text, name_level);
        if (spans.empty()) return text;
        string out; size_t last = 0;
        vector<pair<string, string>> found;
        for (auto& sp : spans)
        {
            string val = text.substr(sp.b, sp.e - sp.b);
            if (val.size() < 3) continue;
            out.append(text, last, sp.b - last);
            out.append(save_name(val, sp.cat));
            last = sp.e;
            found.push_back({ sp.cat, val });
        }
        out.append(text, last, string::npos);
        for (auto& f : found) learn(f.first, f.second);
        for (auto& f : found) out = replace_term(out, Term{ f.first, lower(f.second) });   // other mentions

        // Parts of a name: "Jan Kowalski" -> "Jan", "Kowalski";  "Acme Corp" -> "Acme".
        vector<pair<string, string>> extra;
        for (auto& f : found)
            for (auto& a : aliases_of(f.first, f.second)) extra.push_back({ f.first, a });
        for (auto& x : extra) learn(x.first, x.second);
        for (auto& x : extra) out = replace_term(out, Term{ x.first, lower(x.second) });
        return out;
    }

    string replace_literals(string text)
    {
        for (auto& [lit, cat] : literals)
        {
            size_t pos = 0;
            while ((pos = text.find(lit, pos)) != string::npos)
            {
                string ph = save(lit, cat);
                text.replace(pos, lit.size(), ph);
                pos += ph.size();
            }
        }
        return text;
    }

    // Case-insensitive, whole-word match of a listed name.
    string replace_term(const string& text, const Term& term)
    {
        const string low = lower(text);
        const string& t = term.low;
        string out; size_t pos = 0, last = 0;
        while ((pos = low.find(t, pos)) != string::npos)
        {
            size_t end = pos + t.size();
            bool lb = !word_char((unsigned char)t.front()) || pos == 0 || !word_char((unsigned char)text[pos - 1]);
            bool rb = !word_char((unsigned char)t.back()) || end == text.size() || !word_char((unsigned char)text[end]);
            if (lb && rb)
            {
                out.append(text, last, pos - last);
                out.append(save(text.substr(pos, t.size()), term.cat));
                last = pos = end;
            }
            else ++pos;
        }
        out.append(text, last, string::npos);
        return out;
    }

    string replace_key_blocks(const string& text)
    {
        string out; size_t pos = 0;
        while (true)
        {
            size_t b = text.find("-----BEGIN ", pos);
            if (b == string::npos) break;
            size_t he = text.find("-----", b + 11);
            if (he == string::npos) break;
            string label = text.substr(b + 11, he - b - 11);
            if (label.find("PRIVATE KEY") == string::npos)
            {
                out.append(text, pos, he + 5 - pos);
                pos = he + 5;
                continue;
            }
            string endm = "-----END " + label + "-----";
            size_t e = text.find(endm, he);
            size_t stop = (e == string::npos) ? text.size() : e + endm.size();
            out.append(text, pos, b - pos);
            out.append(save(text.substr(b, stop - b), "PRIVKEY"));
            pos = stop;
        }
        out.append(text, pos, string::npos);
        return out;
    }

    string apply(const string& text, const Rule& r)
    {
        string out; size_t last = 0;
        for (auto it = sregex_iterator(text.begin(), text.end(), r.rx);
             it != sregex_iterator(); ++it)
        {
            const smatch& m = *it;
            if (r.group >= m.size() || !m[r.group].matched) continue;
            size_t start = (size_t)m.position(r.group), len = (size_t)m.length(r.group);
            if (len == 0 || start < last) continue;
            string value = m.str(r.group);
            if (r.validate && !r.validate(value)) continue;
            out.append(text, last, start - last);
            out.append(save(value, r.cat));
            last = start + len;
        }
        out.append(text, last, string::npos);
        return out;
    }
};

// ---------------------------------------------------------------- CLI plumbing
static string slurp_stdin()
{
    return string((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>());
}

// Writes content to a fresh private temp file; returns its path ("" on error).
static string make_temp(const string& content)
{
#ifdef _WIN32
    char dir[MAX_PATH], path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, dir) || !GetTempFileNameA(dir, "prz", 0, path))
        return "";
#else
    char path[] = "/tmp/prosze-XXXXXX";
    int fd = mkstemp(path);                 // created 0600
    if (fd < 0) return "";
    close(fd);
#endif
    FILE* f = fopen(path, "wb");
    if (!f) return "";
    bool ok = fwrite(content.data(), 1, content.size(), f) == content.size();
    fclose(f);
    if (!ok) { ::remove(path); return ""; }
    return path;
}

#ifdef _WIN32
static string windows_arg(const string& arg)
{
    bool quote = arg.empty() || arg.find_first_of(" \t\n\v\"") != string::npos;
    if (!quote) return arg;

    string out = "\"";
    size_t slashes = 0;
    for (char c : arg)
    {
        if (c == '\\') { ++slashes; continue; }
        if (c == '"')
        {
            out.append(slashes * 2 + 1, '\\');
            out += '"';
            slashes = 0;
            continue;
        }
        out.append(slashes, '\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, '\\');
    return out + '"';
}
#endif

// Run an already-separated argument vector without passing through a shell.
// Temporary files keep stdin/stdout deadlock-free even for large responses.
static int run_command(const vector<string>& args, const string& input, string& output)
{
    if (args.empty()) return -1;
    string input_path = make_temp(input), output_path = make_temp("");
    if (input_path.empty() || output_path.empty())
    {
        if (!input_path.empty()) ::remove(input_path.c_str());
        if (!output_path.empty()) ::remove(output_path.c_str());
        return -1;
    }

    int status = -1;
#ifdef _WIN32
    SECURITY_ATTRIBUTES inherit = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE input_handle = CreateFileA(input_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      &inherit, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE output_handle = CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       &inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input_handle != INVALID_HANDLE_VALUE && output_handle != INVALID_HANDLE_VALUE)
    {
        string command;
        for (const string& arg : args)
        {
            if (!command.empty()) command += ' ';
            command += windows_arg(arg);
        }
        vector<char> mutable_command(command.begin(), command.end());
        mutable_command.push_back('\0');
        HANDLE error_handle = GetStdHandle(STD_ERROR_HANDLE);
        vector<HANDLE> inherited_handles = { input_handle, output_handle };
        if (error_handle != nullptr && error_handle != INVALID_HANDLE_VALUE)
            inherited_handles.push_back(error_handle);

        SIZE_T attribute_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
        vector<unsigned char> attribute_storage(attribute_size);
        LPPROC_THREAD_ATTRIBUTE_LIST attributes =
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
        bool attributes_ready = attribute_size != 0 &&
            InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) != FALSE &&
            UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      inherited_handles.data(),
                                      inherited_handles.size() * sizeof(HANDLE), nullptr, nullptr) != FALSE;

        STARTUPINFOEXA startup = {};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input_handle;
        startup.StartupInfo.hStdOutput = output_handle;
        startup.StartupInfo.hStdError = error_handle;
        startup.lpAttributeList = attributes_ready ? attributes : nullptr;
        PROCESS_INFORMATION process = {};
        DWORD creation_flags = attributes_ready ? EXTENDED_STARTUPINFO_PRESENT : 0;
        if (CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, creation_flags,
                           nullptr, nullptr, &startup.StartupInfo, &process))
        {
            WaitForSingleObject(process.hProcess, INFINITE);
            DWORD exit_code = 1;
            GetExitCodeProcess(process.hProcess, &exit_code);
            status = (int)exit_code;
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        if (attributes_ready) DeleteProcThreadAttributeList(attributes);
    }
    if (input_handle != INVALID_HANDLE_VALUE) CloseHandle(input_handle);
    if (output_handle != INVALID_HANDLE_VALUE) CloseHandle(output_handle);
#else
    pid_t child = fork();
    if (child == 0)
    {
        int in = open(input_path.c_str(), O_RDONLY);
        int out = open(output_path.c_str(), O_WRONLY | O_TRUNC);
        if (in < 0 || out < 0) _exit(127);
        dup2(in, STDIN_FILENO);
        dup2(out, STDOUT_FILENO);
        close(in);
        close(out);
        vector<char*> argv;
        for (const string& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    if (child > 0 && waitpid(child, &status, 0) >= 0)
    {
        if (WIFEXITED(status)) status = WEXITSTATUS(status);
        else status = 1;
    }
#endif

    ifstream in(output_path, ios::binary);
    output.assign((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    ::remove(input_path.c_str());
    ::remove(output_path.c_str());
    return status;
}

static string selected_mode(int argc, char** argv)
{
    return argc < 2 ? "chat" : argv[1];
}

static int usage()
{
    cerr << "prosze - hide sensitive details from a prompt before it reaches an AI\n\n"
            "usage:\n"
            "  prosze                         launch the native interactive chat\n"
            "  prosze chat    [opts]                 paste prompt -> safe text; paste reply -> real text\n"
            "  prosze redact  [opts] < prompt.txt    print the safe version\n"
            "  prosze restore [opts] < reply.txt     put the real values back\n"
            "  prosze check   [opts] < prompt.txt    exit code 1 if anything sensitive is found\n"
            "  prosze run     [opts] -- cmd args...  redact stdin/args, run cmd, restore its output\n\n"
            "options:\n"
            "  --term \"Acme Corp\" | CUSTOMER=\"Acme Corp\"   hide a name (repeatable)\n"
            "  --terms FILE        names, one per line (./.prosze-terms is loaded automatically)\n"
            "  --env FILE          hide every value of a .env file\n"
            "  --map FILE          mapping file (default .prosze-map)\n"
            "  --names LEVEL       automatic name finder: off | strict | normal (default) | aggressive\n"
            "  --explain           print what was hidden (placeholder = real value) to stderr\n";
    return 2;
}

static bool read_block(const char* prompt, string& out)
{
    cout << prompt << flush;
    out.clear();
    string line;
    while (getline(cin, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == "END") return true;
        out += line + "\n";
    }
    return !out.empty();                    // EOF: accept what we have, then stop
}

static void chat(prosze& v, const string& map_path)
{
    cout << "Prosze - nothing leaves this window until you copy it yourself.\n";
    string text, reply;
    while (true)
    {
        if (!read_block("\nPaste your PROMPT, then a line with only END (Ctrl+Z / Ctrl+D quits):\n", text))
            return;
        size_t before = v.hits;
        string safe = v.redact(text);
        if (v.dirty) v.save_map(map_path);
        cout << "\n======== SAFE TO SEND (" << (v.hits - before) << " item(s) hidden) ========\n"
             << safe << "============================================\n";
        if (!v.fresh.empty())
        {
            cout << "Newly hidden (check for mistakes; local only):\n";
            v.print_fresh(cout);
        }
        if (!read_block("\nPaste the AI's REPLY (or just END to skip):\n", reply))
            return;
        if (!trim(reply).empty())
            cout << "\n======== RESTORED ========\n" << v.restore(reply)
                 << "==========================\n";
    }
}

#ifndef PROSZE_NO_MAIN
int main(int argc, char** argv)
{
    ios::sync_with_stdio(false);
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);    // no CRLF translation: keeps restore exact
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    const string mode = selected_mode(argc, argv);
    string map_path = ".prosze-map", names = "normal";
    bool explain = false;
    vector<string> envs, terms, term_files, cmd;

    for (int i = 2; i < argc; ++i)
    {
        string a = argv[i];
        auto next = [&]() -> string { if (i + 1 >= argc) { usage(); exit(2); } return argv[++i]; };
        if (a == "--map") map_path = next();
        else if (a == "--env") envs.push_back(next());
        else if (a == "--term") terms.push_back(next());
        else if (a == "--terms") term_files.push_back(next());
        else if (a == "--names") names = next();
        else if (a == "--explain") explain = true;
        else if (a == "--") { for (++i; i < argc; ++i) cmd.push_back(argv[i]); }
        else return usage();
    }
    if (mode != "chat" && mode != "redact" && mode != "restore" && mode != "check" && mode != "run")
        return usage();

    prosze v;
    v.load_map(map_path);
    if (!v.set_level(names)) { cerr << "prosze: --names must be off, strict, normal or aggressive\n"; return 2; }
    v.learn_from_map();
    for (auto& e : envs)
        if (!v.load_env(e)) { cerr << "prosze: cannot read " << e << '\n'; return 1; }
    for (auto& f : term_files)
        if (!v.load_terms(f)) { cerr << "prosze: cannot read " << f << '\n'; return 1; }
    v.load_terms(".prosze-terms");          // optional, silent if absent
    for (auto& t : terms) v.add_term(t);

    if (mode == "chat") { chat(v, map_path); return 0; }

    if (mode == "redact")
    {
        string safe = v.redact(slurp_stdin());
        cout << safe;
        if (explain) v.print_fresh(cerr);
        if (v.dirty && !v.save_map(map_path)) { cerr << "prosze: cannot write map\n"; return 1; }
        cerr << "prosze: " << v.hits << " item(s) hidden\n";
        return 0;
    }
    if (mode == "restore")
    {
        cout << v.restore(slurp_stdin());
        return 0;
    }
    if (mode == "check")
    {
        v.redact(slurp_stdin());
        if (explain) v.print_fresh(cerr);
        if (v.hits) { cerr << "prosze: " << v.hits << " sensitive item(s) found\n"; return 1; }
        return 0;
    }

    // run: nothing reaches the command unless it went through the redactor.
    if (cmd.empty()) return usage();
    vector<string> safe_cmd;
    for (auto& c : cmd) safe_cmd.push_back(v.redact(c));           // args can hold secrets too
    string safe = v.redact(isatty(0) ? string() : slurp_stdin());
    if (v.dirty && !v.save_map(map_path)) { cerr << "prosze: cannot write map\n"; return 1; }

    string reply;
    int status = run_command(safe_cmd, safe, reply);
    if (status < 0) { cerr << "prosze: cannot run command\n"; return 1; }

    cout << v.restore(reply);
    if (explain) v.print_fresh(cerr);
    cerr << "prosze: " << v.hits << " item(s) hidden before sending\n";
    return status;
}
#endif
