#define PROSZE_NO_MAIN
#include "../Application.cpp"

#include <cassert>
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

static void test_native_process_execution()
{
    string output;
    assert(run_command(process_reader_command(), "safe child input\n", output) == 0);
    assert(output == "safe child input\n" || output == "safe child input\r\n");
    assert(run_command(process_exit_command(), "", output) == 7);
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

int main()
{
    test_redaction_and_restoration();
    test_env_and_tsv_map_compatibility();
    test_native_process_execution();
    test_bare_invocation_selects_chat();
    test_ephemeral_vault_persistence();
    test_encrypted_vault_persistence_and_auth_failure();
    test_cross_language_vector_compatibility();
    test_strict_restore_blocks_preloaded_placeholders();
    test_cloud_and_ai_secret_rules_and_ips();
    test_base64_encoded_secret_scanner();
    return 0;
}
