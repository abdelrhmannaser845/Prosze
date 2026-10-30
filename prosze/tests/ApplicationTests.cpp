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

int main()
{
    test_redaction_and_restoration();
    test_env_and_tsv_map_compatibility();
    test_native_process_execution();
    test_bare_invocation_selects_chat();
    test_ephemeral_vault_persistence();
    test_encrypted_vault_persistence_and_auth_failure();
    test_cross_language_vector_compatibility();
    return 0;
}
