#define PROSZE_NO_MAIN
#include "../Application.cpp"

#include <cassert>
#include <chrono>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

static fs::path test_path(const char* name)
{
    return fs::temp_directory_path() / (string("prosze-cpp-") + name);
}

static void test_redaction_and_restoration()
{
    prosze vault;
    vault.name_level = 0;
    vault.add_term("CUSTOMER=Acme Corp");
    string safe = vault.redact("Contact Acme Corp at jane.doe@example.com.");
    assert(safe == "Contact [[CUSTOMER_1]] at [[EMAIL_1]].");
    assert(vault.restore(safe) == "Contact Acme Corp at jane.doe@example.com.");
}

static void test_env_and_tsv_map_compatibility()
{
    fs::path env_path = test_path("env");
    {
        ofstream env(env_path);
        env << "export SERVICE_TOKEN=abc-secret-value\n";
    }
    prosze env_vault;
    env_vault.name_level = 0;
    assert(env_vault.load_env(env_path.string()));
    assert(env_vault.redact("token=abc-secret-value") == "token=[[ENV_1]]");
    ::remove(env_path.string().c_str());

    fs::path map_path = fs::path("prosze") / "tests" / "fixtures" / "map.tsv";
    prosze loaded;
    loaded.load_map(map_path.string());
    assert(loaded.restore("[[CUSTOMER_4]] / [[TOKEN_2]]") == "Acme Corp / line\nvalue");
}

static vector<string> process_reader_command()
{
#ifdef _WIN32
    return { "cmd.exe", "/d", "/c", "more" };
#else
    return { "/bin/cat" };
#endif
}

static vector<string> process_exit_command()
{
#ifdef _WIN32
    return { "cmd.exe", "/d", "/c", "exit 7" };
#else
    return { "/bin/sh", "-c", "exit 7" };
#endif
}

static vector<string> exact_pipe_reader_command()
{
#ifdef _WIN32
    char exe_path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    assert(len > 0 && len < MAX_PATH);
    return { string(exe_path), "--cat-helper" };
#else
    return { "/bin/cat" };
#endif
}

struct ScopedEnvVar
{
    string name;
    bool had_value = false;
    string old_value;

    ScopedEnvVar(const char* n, const string& val) : name(n)
    {
#ifdef _WIN32
        char buf[32768];
        DWORD len = GetEnvironmentVariableA(name.c_str(), buf, sizeof(buf));
        if (len > 0 && len < sizeof(buf))
        {
            had_value = true;
            old_value.assign(buf, len);
        }
        SetEnvironmentVariableA(name.c_str(), val.c_str());
#else
        const char* cur = getenv(name.c_str());
        if (cur)
        {
            had_value = true;
            old_value = cur;
        }
        setenv(name.c_str(), val.c_str(), 1);
#endif
    }

    ~ScopedEnvVar()
    {
#ifdef _WIN32
        SetEnvironmentVariableA(name.c_str(), had_value ? old_value.c_str() : nullptr);
#else
        if (had_value) setenv(name.c_str(), old_value.c_str(), 1);
        else unsetenv(name.c_str());
#endif
    }
};

static void test_native_process_execution()
{
    string output;
    assert(run_command(process_reader_command(), "safe child input\n", output) == 0);
    assert(output == "safe child input\n" || output == "safe child input\r\n" || output == "safe child input\r\n\r\n");
    assert(run_command(process_exit_command(), "", output) == 7);
}

static void test_run_command_large_pipe_zero_temp_files()
{
    fs::path sandbox_tmp = test_path("pipe_sandbox");
    if (fs::exists(sandbox_tmp)) fs::remove_all(sandbox_tmp);
    fs::create_directories(sandbox_tmp);

    string payload;
    payload.reserve(200 * 1024);
    for (int i = 0; i < 4000; ++i)
    {
        payload += "line " + to_string(i) + ": safe piped payload segment 0123456789abcdef\n";
    }
    assert(payload.size() > 128 * 1024);

    {
        ScopedEnvVar guard_tmp("TMP", sandbox_tmp.string());
        ScopedEnvVar guard_temp("TEMP", sandbox_tmp.string());
        ScopedEnvVar guard_tmpdir("TMPDIR", sandbox_tmp.string());

        string output = "stale-data";
        int rc = run_command(exact_pipe_reader_command(), payload, output);
        assert(rc == 0);
        assert(output.size() == payload.size());
        assert(output == payload);
        assert(fs::is_empty(sandbox_tmp));

        // Early child exit with >128 KB stdin must not deadlock or crash on SIGPIPE
        string exit_out = "stale";
        assert(run_command(process_exit_command(), payload, exit_out) == 7);
        assert(exit_out.empty());
        assert(fs::is_empty(sandbox_tmp));
    }

    fs::remove_all(sandbox_tmp);
}

static void test_bare_invocation_selects_chat()
{
    char program[] = "prosze";
    char mode[] = "redact";
    char* bare[] = { program, nullptr };
    char* explicit_mode[] = { program, mode, nullptr };
    assert(selected_mode(1, bare) == "chat");
    assert(selected_mode(2, explicit_mode) == "redact");
}

static void test_ephemeral_vault_persistence()
{
    prosze vault;
    vault.ephemeral = true;
    vault.add_term("CUSTOMER=Acme Corp");
    string safe = vault.redact("Contact Acme Corp.");
    assert(safe == "Contact [[CUSTOMER_1]].");

    fs::path map_path = test_path("ephemeral.map");
    if (fs::exists(map_path)) fs::remove(map_path);

    assert(vault.save_map(map_path.string()));
    assert(!fs::exists(map_path));
    assert(vault.restore(safe) == "Contact Acme Corp.");
}

static void test_encrypted_vault_persistence_and_auth_failure()
{
    fs::path map_path = test_path("encrypted.map");
    if (fs::exists(map_path)) fs::remove(map_path);

    {
        prosze vault;
        vault.passphrase = "test-secret-key";
        vault.add_term("CUSTOMER=Acme Corp");
        string safe = vault.redact("Contact Acme Corp.");
        assert(safe == "Contact [[CUSTOMER_1]].");
        assert(vault.save_map(map_path.string()));
    }

    assert(fs::exists(map_path));
    ifstream in(map_path, ios::binary);
    string content((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    assert(content.rfind("#PROSZE_ENC_V1\t", 0) == 0);
    assert(content.find("Acme Corp") == string::npos);

    // Correct passphrase restores values
    {
        prosze loaded_ok;
        loaded_ok.passphrase = "test-secret-key";
        assert(loaded_ok.load_map(map_path.string()));
        assert(loaded_ok.restore("[[CUSTOMER_1]]") == "Acme Corp");
    }

    // Wrong passphrase fails closed
    {
        prosze loaded_bad;
        loaded_bad.passphrase = "wrong-password";
        assert(!loaded_bad.load_map(map_path.string()));
    }

    // Missing passphrase fails closed
    {
        prosze loaded_none;
        assert(!loaded_none.load_map(map_path.string()));
    }

    // Tampered tag fails closed
    {
        fs::path corrupt_path = test_path("corrupt.map");
        ofstream out(corrupt_path, ios::binary);
        out << content.substr(0, content.size() - 5) << "0000\n";
        out.close();

        prosze loaded_corrupt;
        loaded_corrupt.passphrase = "test-secret-key";
        assert(!loaded_corrupt.load_map(corrupt_path.string()));
        fs::remove(corrupt_path);
    }

    fs::remove(map_path);
}

static void test_cross_language_vector_compatibility()
{
    fs::path map_path = test_path("cross_vector.map");
    string line =
        "#PROSZE_ENC_V1\t000102030405060708090a0b0c0d0e0f\t"
        "f38d8b1f85097b81d4fd20222b994a82489064dc1d25540c44\t"
        "ca7ecee36077a45863657e8e95bee71bad5b73f40692ab7381187c35ca041f52\n";

    {
        ofstream out(map_path, ios::binary);
        out << line;
    }

    prosze loaded;
    loaded.passphrase = "test-secret-key";
    assert(loaded.load_map(map_path.string()));
    assert(loaded.restore("[[CUSTOMER_1]]") == "Acme Corp");

    fs::remove(map_path);
}

static void test_strict_restore_blocks_preloaded_placeholders()
{
    fs::path map_path = test_path("strict_restore.map");
    if (fs::exists(map_path)) fs::remove(map_path);

    {
        ofstream out(map_path, ios::binary);
        out << "[[CUSTOMER_1]]\tAcme Corp\n[[TOKEN_1]]\tsuper-secret-token\n";
    }

    // Default mode: strict_restore = false, all pre-existing placeholders restore
    {
        prosze v;
        assert(v.load_map(map_path.string()));
        assert(!v.strict_restore);
        assert(v.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]") == "Hello Acme Corp and super-secret-token");
    }

    // strict_restore = true: pre-existing placeholders not in this session remain unexpanded
    {
        prosze v;
        v.strict_restore = true;
        assert(v.load_map(map_path.string()));

        // No redaction in this session yet: neither placeholder expands
        assert(v.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]") == "Hello [[CUSTOMER_1]] and [[TOKEN_1]]");

        // Redacting Acme Corp emits and registers [[CUSTOMER_1]] into session_keys
        v.add_term("CUSTOMER=Acme Corp");
        string safe = v.redact("We are talking to Acme Corp today.");
        assert(safe == "We are talking to [[CUSTOMER_1]] today.");
        assert(v.session_keys.count("[[CUSTOMER_1]]") == 1);
        assert(v.session_keys.count("[[TOKEN_1]]") == 0);

        // [[CUSTOMER_1]] now expands, but [[TOKEN_1]] remains blocked
        assert(v.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]") == "Hello Acme Corp and [[TOKEN_1]]");
    }

    fs::remove(map_path);
}

static void test_cloud_and_ai_secret_rules_and_ips()
{
    prosze v;
    v.name_level = 0;

    // Hugging Face token
    string hf = "hf_012345678901234567890123456789";
    string s1 = v.redact("HuggingFace: " + hf);
    assert(s1 == "HuggingFace: [[TOKEN_1]]");
    assert(v.restore(s1) == "HuggingFace: " + hf);

    // GitHub fine-grained PAT
    string pat = "github_pat_11ABCD0123456789012345";
    string s2 = v.redact("GitHub PAT: " + pat);
    assert(s2 == "GitHub PAT: [[TOKEN_2]]");
    assert(v.restore(s2) == "GitHub PAT: " + pat);

    // Slack incoming webhook
    string slack_prefix = "https://hooks.slack.com/services/";
    string slack = slack_prefix + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
    string s3 = v.redact("Slack Webhook: " + slack);
    assert(s3 == "Slack Webhook: [[TOKEN_3]]");
    assert(v.restore(s3) == "Slack Webhook: " + slack);

    // Anthropic / OpenAI / Stripe tokens
    string ant = "sk-ant-api03-abcdef1234567890";
    string s4 = v.redact("Anthropic: " + ant);
    assert(s4 == "Anthropic: [[TOKEN_4]]");
    assert(v.restore(s4) == "Anthropic: " + ant);

    string sk_proj = "sk-proj-abcdef1234567890";
    string s5 = v.redact("OpenAI: " + sk_proj);
    assert(s5 == "OpenAI: [[TOKEN_5]]");
    assert(v.restore(s5) == "OpenAI: " + sk_proj);

    string sk_live = "sk_live_abcdef1234567890";
    string s6 = v.redact("Stripe: " + sk_live);
    assert(s6 == "Stripe: [[TOKEN_6]]");
    assert(v.restore(s6) == "Stripe: " + sk_live);

    string rk_live = "rk_live_abcdef1234567890";
    string s7 = v.redact("Stripe restricted: " + rk_live);
    assert(s7 == "Stripe restricted: [[TOKEN_7]]");
    assert(v.restore(s7) == "Stripe restricted: " + rk_live);

    // Cloud metadata IP
    string s_meta = v.redact("AWS metadata IP: 169.254.169.254");
    assert(s_meta == "AWS metadata IP: [[IP_1]]");
    assert(v.restore(s_meta) == "AWS metadata IP: 169.254.169.254");

    // Link-local IPv4
    string s_ll4 = v.redact("Link-local IPv4: 169.254.10.20");
    assert(s_ll4 == "Link-local IPv4: [[IP_2]]");
    assert(v.restore(s_ll4) == "Link-local IPv4: 169.254.10.20");

    // IPv6 ULA
    string s_ula1 = v.redact("IPv6 ULA prefix: fd00::");
    assert(s_ula1 == "IPv6 ULA prefix: [[IP_3]]");
    assert(v.restore(s_ula1) == "IPv6 ULA prefix: fd00::");

    string s_ula2 = v.redact("IPv6 ULA addr: fd12:3456:789a:1::1");
    assert(s_ula2 == "IPv6 ULA addr: [[IP_4]]");
    assert(v.restore(s_ula2) == "IPv6 ULA addr: fd12:3456:789a:1::1");

    // IPv6 link-local
    string s_ll6_1 = v.redact("IPv6 link-local prefix: fe80::");
    assert(s_ll6_1 == "IPv6 link-local prefix: [[IP_5]]");
    assert(v.restore(s_ll6_1) == "IPv6 link-local prefix: fe80::");

    string s_ll6_2 = v.redact("IPv6 link-local host: fe80::1");
    assert(s_ll6_2 == "IPv6 link-local host: [[IP_6]]");
    assert(v.restore(s_ll6_2) == "IPv6 link-local host: fe80::1");

    string s_ll6_3 = v.redact("IPv6 link-local full: fe80::20c:29ff:fe4b:8a12");
    assert(s_ll6_3 == "IPv6 link-local full: [[IP_7]]");
    assert(v.restore(s_ll6_3) == "IPv6 link-local full: fe80::20c:29ff:fe4b:8a12");

    // Public IPs should not be redacted
    string pub = "Public DNS: 8.8.8.8 and 2001:db8::1";
    assert(v.redact(pub) == pub);
}

static void test_base64_encoded_secret_scanner()
{
    prosze v;
    v.name_level = 0;

    // Base64 of "Bearer sk-example1234567890abcdef"
    string b64_token = "QmVhcmVyIHNrLWV4YW1wbGUxMjM0NTY3ODkwYWJjZGVm";
    string s1 = v.redact("Authorization: " + b64_token);
    assert(s1 == "Authorization: [[ENCODED_1]]");
    assert(v.restore(s1) == "Authorization: " + b64_token);

    // Base64 of "password=supersecret123"
    string b64_pwd = "cGFzc3dvcmQ9c3VwZXJzZWNyZXQxMjM=";
    string s2 = v.redact("Payload: " + b64_pwd);
    assert(s2 == "Payload: [[ENCODED_2]]");
    assert(v.restore(s2) == "Payload: " + b64_pwd);

    // Plain English base64: "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    string b64_plain = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
    string s3 = v.redact("Public note: " + b64_plain);
    assert(s3 == "Public note: " + b64_plain);

    // strict_restore verification on ENCODED placeholders
    v.strict_restore = true;
    assert(v.restore(s1) == "Authorization: " + b64_token);
    assert(v.restore("[[ENCODED_99]]") == "[[ENCODED_99]]");
}

static void test_aho_corasick_literals_terms_and_placeholder_immunity()
{
    // Direct AhoCorasick overlap and whole-word suffix fallback
    AhoCorasick ac(true);
    ac.build({ { "Big Acme", "ORG" }, { "Acme", "CUSTOMER" } });
    auto matches = ac.find_matches("xBig Acme and Big Acme", true);
    assert(matches.size() == 2);
    assert(matches[0].start == 5 && matches[0].end == 9 && matches[0].cat == "CUSTOMER");
    assert(matches[1].start == 14 && matches[1].end == 22 && matches[1].cat == "ORG");

    prosze v;
    v.name_level = 0;
    assert(!v.literals_dirty);
    assert(!v.terms_dirty);

    v.add_literal("Acme");
    v.add_literal("Acme Corp");
    v.add_literal("CUSTOMER_1");
    assert(v.literals_dirty);

    v.add_term("CUSTOMER=Acme");
    v.add_term("ORG=Acme Corp");
    v.add_term("PERSON=Jan");
    v.add_term("TERM=CUSTOMER_1");
    assert(v.terms_dirty);

    // Longest-match priority for literals ("Acme Corp" beats "Acme") and placeholder immunity
    string lit_out = v.redact("Hello Acme Corp, Acme, [[CUSTOMER_1]], and CUSTOMER_1.");
    assert(!v.literals_dirty);
    assert(!v.terms_dirty);
    assert(lit_out == "Hello [[ENV_1]], [[ENV_2]], [[CUSTOMER_1]], and [[ENV_3]].");
    assert(v.restore(lit_out) == "Hello Acme Corp, Acme, [[CUSTOMER_1]], and CUSTOMER_1.");

    // Case-insensitive whole-word term matching, boundary enforcement, and lazy dirty rebuild
    prosze tv;
    tv.name_level = 0;
    tv.add_term("ORG=Acme Corp");
    tv.add_term("PROJECT=Acme");
    tv.add_term("PERSON=Jan");
    tv.add_term("TERM=CUSTOMER_1");
    assert(tv.terms_dirty);

    string term_out = tv.redact("Dear Jan, Janek at ACME CORP and acme saw [[CUSTOMER_1]] and CUSTOMER_1.");
    assert(!tv.terms_dirty);
    assert(term_out == "Dear [[PERSON_1]], Janek at [[ORG_1]] and [[PROJECT_1]] saw [[CUSTOMER_1]] and [[TERM_1]].");
    assert(tv.restore(term_out) == "Dear Jan, Janek at ACME CORP and acme saw [[CUSTOMER_1]] and CUSTOMER_1.");

    // Lazy rebuild when a new literal/term is added after initial redact()
    tv.add_term("PROJECT=Apollo");
    tv.add_literal("new-secret-val");
    assert(tv.terms_dirty);
    assert(tv.literals_dirty);
    string second = tv.redact("apollo uses new-secret-val");
    assert(!tv.terms_dirty);
    assert(!tv.literals_dirty);
    assert(second == "[[PROJECT_2]] uses [[ENV_1]]");

    // auto_names learn() triggers lazy terms_ac rebuild for subsequent mentions & aliases
    prosze nv;
    string nout = nv.redact("Contact Jan Kowalski. Later jan kowalski and Kowalski replied.");
    assert(!nv.terms_dirty);
    assert(nout == "Contact [[PERSON_1]]. Later [[PERSON_1]] and [[PERSON_2]] replied.");
}

static void test_prefilter_accuracy_and_zero_match_fast_path()
{
    assert(scan_char_features("Plain prose without digits or special symbols") == FEAT_NONE);
    assert(scan_char_features("a@b.c") == (FEAT_AT | FEAT_DOT));
    assert(scan_char_features("k=v:1-2_3+4") == (FEAT_COLON_EQ | FEAT_DIGIT | FEAT_DASH_UNDER | FEAT_PLUS));

    prosze v;
    v.name_level = 0;

    // Plain prose zero-match fast path
    string prose = "Just ordinary English prose without any sensitive markers at all";
    assert(scan_char_features(prose) == FEAT_NONE);
    assert(v.redact(prose) == prose);
    assert(v.hits == 0);

    // Every secret category + zero-digit edge cases (fcab::cdef, digitless AKIA/AIza/Bearer/hex)
    assert(v.redact("url https://bob:secret99@host.internal/api").find("[[PASSWORD_1]]") != string::npos);
    assert(v.redact("mail alice@example.com").find("[[EMAIL_1]]") != string::npos);
    assert(v.redact("aws AKIAAAAAAAAAAAAAAAAA").find("[[TOKEN_1]]") != string::npos);
    assert(v.redact("gcp AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").find("[[TOKEN_2]]") != string::npos);
    assert(v.redact("hf hf_abcdefghijklmnopqrstuvwxyz012345").find("[[TOKEN_3]]") != string::npos);
    assert(v.redact("gh github_pat_11ABCD0123456789012345").find("[[TOKEN_4]]") != string::npos);
    assert(v.redact("slack https://hooks.slack.com/services/T11/B22/XYZ123").find("[[TOKEN_5]]") != string::npos);
    assert(v.redact("openai sk-proj-abcdef1234567890").find("[[TOKEN_6]]") != string::npos);
    assert(v.redact("jwt eyJabcdefgh.eyJijklmnop.signature12").find("[[TOKEN_7]]") != string::npos);
    assert(v.redact("auth Bearer AbCdEfGhIjKlMnOpQrSt").find("[[TOKEN_8]]") != string::npos);
    assert(v.redact("cfg password=mysecretpass").find("[[PASSWORD_2]]") != string::npos);
    assert(v.redact("iban DE89370400440532013000").find("[[IBAN_1]]") != string::npos);
    assert(v.redact("acct account 123456789").find("[[ACCOUNT_1]]") != string::npos);
    assert(v.redact("ssn 123-45-6789").find("[[SSN_1]]") != string::npos);
    assert(v.redact("tel phone: 555 123 4567").find("[[PHONE_1]]") != string::npos);
    assert(v.redact("card 4111111111111111").find("[[CARD_1]]") != string::npos);
    assert(v.redact("rand A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6").find("[[APIKEY_1]]") != string::npos);
    assert(v.redact("hex abcdefabcdefabcdefabcdefabcdefabcdefabcd").find("[[APIKEY_2]]") != string::npos);
    assert(v.redact("ipv4 192.168.1.50").find("[[IP_1]]") != string::npos);
    assert(v.redact("ipv6 fcab::cdef").find("[[IP_2]]") != string::npos);
    assert(v.redact("intl +48 601 234 567").find("[[PHONE_2]]") != string::npos);
    assert(v.redact("sep 601 234 567").find("[[PHONE_3]]") != string::npos);

    // Base64 < 24 fast path does not match short base64-like tokens
    string short_b64 = "cGFzc3dvcmQ9MTIz"; // 16 chars
    assert(v.redact(short_b64) == short_b64);
}

static void test_50kb_throughput()
{
    prosze v;
    v.name_level = 0;
    for (int i = 0; i < 100; ++i)
    {
        v.add_term("CUSTOMER=CustomerOrganization" + to_string(i));
    }
    for (int i = 0; i < 50; ++i)
    {
        v.add_literal("literal_secret_value_" + to_string(i));
    }

    string chunk = "The team reviewed architecture notes and deployment timelines during weekly planning. ";
    string payload;
    payload.reserve(55000);
    while (payload.size() < 50 * 1024)
    {
        payload += chunk;
    }
    payload += " Contact CustomerOrganization42 regarding literal_secret_value_17.";

    // Warm/include lazy build inside timed redaction
    auto t0 = chrono::steady_clock::now();
    string safe = v.redact(payload);
    auto t1 = chrono::steady_clock::now();
    double elapsed_ms = chrono::duration<double, milli>(t1 - t0).count();

    assert(safe.find("[[CUSTOMER_1]]") != string::npos);
    assert(safe.find("[[ENV_1]]") != string::npos);
    assert(elapsed_ms < 500.0);
}

static void test_streaming_redaction_and_restoration()
{
    prosze v;
    v.name_level = 0;
    v.add_term("CUSTOMER=Acme Corp");

    // Craft payload where tokens, emails, terms, and a private key block cross 32-byte chunk boundaries
    string key_block =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n"
        "0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "-----END PRIVATE KEY-----\n";

    // Pad prefixes so secrets/emails/terms intentionally straddle 32-byte boundaries (32, 64, 96...)
    string raw =
        "012345678901234567890123 alice.smith@example.com\n"
        "01234567890123456789012345 Acme Corp\n"
        "0123456789012345678901234 sk-proj-abcdef1234567890\n"
        + key_block +
        "Trailing 01234567890123456789 bob.jones@example.org end.";

    istringstream in(raw);
    ostringstream out;
    v.redact_stream(in, out, 32);
    string safe = out.str();

    assert(safe.find("alice.smith@example.com") == string::npos);
    assert(safe.find("Acme Corp") == string::npos);
    assert(safe.find("sk-proj-abcdef1234567890") == string::npos);
    assert(safe.find("MIIBVQIBADANBgkqhkiG9w0BAQEFAASC") == string::npos);
    assert(safe.find("bob.jones@example.org") == string::npos);
    assert(safe.find("[[EMAIL_1]]") != string::npos);
    assert(safe.find("[[CUSTOMER_1]]") != string::npos);
    assert(safe.find("[[TOKEN_1]]") != string::npos);
    assert(safe.find("[[PRIVKEY_1]]") != string::npos);
    assert(safe.find("[[EMAIL_2]]") != string::npos);
    assert(v.hits == 5);
    assert(v.dirty);
    assert(v.fresh.size() == 5);

    // Restore stream with chunk_size = 32, also testing a single '[' right at a 32-byte boundary
    string padded_for_split = "0123456789012345678901234567890[[CUSTOMER_1]] " + safe;
    istringstream rin(padded_for_split);
    ostringstream rout;
    v.restore_stream(rin, rout, 32);
    assert(rout.str() == "0123456789012345678901234567890Acme Corp " + raw);

    // Also test placeholder split right in the middle of "[[CUSTOMER_1]]" across 32-byte boundary
    string split_ph = "01234567890123456789012345[[CUSTOMER_1]] end";
    istringstream rin2(split_ph);
    ostringstream rout2;
    v.restore_stream(rin2, rout2, 32);
    assert(rout2.str() == "01234567890123456789012345Acme Corp end");

    // Verify unclosed "-----BEGIN " cap (> 64 KB) does not hang or retain unbounded memory
    string bogus_key_head = "-----BEGIN PRIVATE KEY-----\n";
    string bogus_payload = bogus_key_head;
    while (bogus_payload.size() < 72 * 1024)
    {
        bogus_payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    }
    bogus_payload += "afterwards mail@example.com";
    prosze v2;
    v2.name_level = 0;
    istringstream bin(bogus_payload);
    ostringstream bout;
    v2.redact_stream(bin, bout, 4096);
    assert(bout.str().find("[[EMAIL_1]]") != string::npos);
    assert(bout.str().find("mail@example.com") == string::npos);
}

int main(int argc, char** argv)
{
    if (argc >= 2 && string(argv[1]) == "--cat-helper")
    {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        char buf[16384];
        while (cin.read(buf, sizeof(buf)) || cin.gcount() > 0)
        {
            cout.write(buf, cin.gcount());
        }
        cout.flush();
        return 0;
    }
    test_redaction_and_restoration();
    test_env_and_tsv_map_compatibility();
    test_native_process_execution();
    test_run_command_large_pipe_zero_temp_files();
    test_bare_invocation_selects_chat();
    test_ephemeral_vault_persistence();
    test_encrypted_vault_persistence_and_auth_failure();
    test_cross_language_vector_compatibility();
    test_strict_restore_blocks_preloaded_placeholders();
    test_cloud_and_ai_secret_rules_and_ips();
    test_base64_encoded_secret_scanner();
    test_aho_corasick_literals_terms_and_placeholder_immunity();
    test_prefilter_accuracy_and_zero_match_fast_path();
    test_50kb_throughput();
    test_streaming_redaction_and_restoration();
    return 0;
}
