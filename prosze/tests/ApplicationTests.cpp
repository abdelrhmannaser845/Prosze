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

static void test_proxy_json_restoration_escapes_values()
{
    string restored = restore_json_strings(
        R"({"reply":"[[EMAIL_1]]","unchanged":"x"})",
        [](const string& value) {
            return value == "[[EMAIL_1]]" ? string("alice\"\\example") : value;
        });
    assert(restored == R"({"reply":"alice\"\\example","unchanged":"x"})");
}

int main()
{
    test_redaction_and_restoration();
    test_env_and_tsv_map_compatibility();
    test_native_process_execution();
    test_bare_invocation_selects_chat();
    test_proxy_json_restoration_escapes_values();
    return 0;
}
