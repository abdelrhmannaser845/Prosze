import io
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch


PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from prosze_core import (
    AhoCorasick,
    FEAT_AT,
    FEAT_COLON_EQ,
    FEAT_DASH_UNDER,
    FEAT_DIGIT,
    FEAT_DOT,
    FEAT_NONE,
    FEAT_PLUS,
    Vault,
    scan_char_features,
    walk,
)
from prosze_cli import cli_main


class ApplicationTests(unittest.TestCase):
    def make_vault(self, directory, ephemeral=False, passphrase=None):
        vault = Vault(str(Path(directory) / "map.tsv"), ephemeral=ephemeral, passphrase=passphrase)
        vault._ner_attempted = True
        return vault

    def test_vault_ephemeral_mode_does_not_create_map_file(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.make_vault(directory, ephemeral=True)
            vault.add_term("CUSTOMER=Acme Corp")
            safe, hits = vault.redact("Contact Acme Corp.")
            self.assertEqual(hits, 1)
            self.assertEqual(safe, "Contact [[CUSTOMER_1]].")
            self.assertEqual(vault.restore(safe), "Contact Acme Corp.")

            map_path = Path(directory) / "map.tsv"
            self.assertFalse(map_path.exists())

    def test_vault_encrypted_persistence_and_wrong_passphrase_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.make_vault(directory, passphrase="test-secret-key")
            vault.add_term("CUSTOMER=Acme Corp")
            safe, hits = vault.redact("Contact Acme Corp.")
            self.assertEqual(hits, 1)

            map_path = Path(directory) / "map.tsv"
            self.assertTrue(map_path.exists())
            with open(map_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertTrue(content.startswith("#PROSZE_ENC_V1\t"))
            self.assertNotIn("Acme Corp", content)

            # Correct passphrase restores values
            loaded_ok = self.make_vault(directory, passphrase="test-secret-key")
            self.assertEqual(loaded_ok.restore(safe), "Contact Acme Corp.")

            # Wrong passphrase raises ValueError
            with self.assertRaises(ValueError):
                self.make_vault(directory, passphrase="wrong-passphrase")

            # Missing passphrase raises ValueError
            with self.assertRaises(ValueError):
                self.make_vault(directory, passphrase=None)

    def test_cross_language_vector_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "map.tsv"
            known_line = (
                "#PROSZE_ENC_V1\t000102030405060708090a0b0c0d0e0f\t"
                "f38d8b1f85097b81d4fd20222b994a82489064dc1d25540c44\t"
                "ca7ecee36077a45863657e8e95bee71bad5b73f40692ab7381187c35ca041f52\n"
            )
            with open(map_path, "w", encoding="utf-8") as f:
                f.write(known_line)

            loaded = Vault(str(map_path), passphrase="test-secret-key")
            self.assertEqual(loaded.restore("[[CUSTOMER_1]]"), "Acme Corp")

    def test_cli_ephemeral_and_passphrase_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "map.tsv"
            command = [sys.executable, "-m", "prosze_cli"]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PACKAGE_DIR)

            # Ephemeral flag test
            ephem_res = subprocess.run(
                command + ["redact", "--no-ner", "--ephemeral", "--map", str(map_path), "--term", "CUSTOMER=Acme Corp"],
                cwd=PACKAGE_DIR,
                env=env,
                input="Please contact Acme Corp.",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ephem_res.returncode, 0)
            self.assertFalse(map_path.exists())

            # Passphrase flag test
            enc_res = subprocess.run(
                command + ["redact", "--no-ner", "--passphrase", "cli-key", "--map", str(map_path), "--term", "CUSTOMER=Acme Corp"],
                cwd=PACKAGE_DIR,
                env=env,
                input="Please contact Acme Corp.",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(enc_res.returncode, 0)
            self.assertTrue(map_path.exists())
            with open(map_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertTrue(content.startswith("#PROSZE_ENC_V1\t"))

            # Restore with correct passphrase
            dec_ok = subprocess.run(
                command + ["restore", "--no-ner", "--passphrase", "cli-key", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input=enc_res.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(dec_ok.returncode, 0)
            self.assertEqual(dec_ok.stdout, "Please contact Acme Corp.")

            # Restore with wrong passphrase fails closed (non-zero)
            dec_bad = subprocess.run(
                command + ["restore", "--no-ner", "--passphrase", "wrong-key", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input=enc_res.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(dec_bad.returncode, 0)

            # PROSZE_KEY env variable test
            env_with_key = env.copy()
            env_with_key["PROSZE_KEY"] = "cli-key"
            dec_env = subprocess.run(
                command + ["restore", "--no-ner", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env_with_key,
                input=enc_res.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(dec_env.returncode, 0)
            self.assertEqual(dec_env.stdout, "Please contact Acme Corp.")

    def test_vault_redacts_restores_and_persists_values(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.make_vault(directory)
            vault.add_term("CUSTOMER=Acme Corp")

            safe, hits = vault.redact("Contact Acme Corp about Acme Corp.")

            self.assertEqual(hits, 2)
            self.assertEqual(safe, "Contact [[CUSTOMER_1]] about [[CUSTOMER_1]].")
            self.assertEqual(vault.restore(safe), "Contact Acme Corp about Acme Corp.")

            loaded = self.make_vault(directory)
            self.assertEqual(loaded.restore(safe), "Contact Acme Corp about Acme Corp.")

    def test_json_walker_recurses_but_skips_metadata_and_base64(self):
        seen = []

        def mark(value):
            seen.append(value)
            return f"safe:{value}"

        payload = {
            "messages": [{"role": "user", "content": "secret"}],
            "nested": {"value": "another secret"},
            "model": "keep-model",
            "encoded": {"type": "base64", "data": "keep-bytes", "label": "secret"},
            "event": "data: keep-sse-prefix",
            "count": 3,
        }

        result = walk(payload, mark)

        self.assertEqual(seen, ["secret", "another secret", "secret"])
        self.assertEqual(result["messages"][0]["content"], "safe:secret")
        self.assertEqual(result["nested"]["value"], "safe:another secret")
        self.assertEqual(result["model"], "keep-model")
        self.assertEqual(result["encoded"]["data"], "keep-bytes")
        self.assertEqual(result["event"], "data: keep-sse-prefix")
        self.assertEqual(result["count"], 3)

    def test_cli_help_and_redact_restore_smoke(self):
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "map.tsv"
            command = [sys.executable, "-m", "prosze_cli"]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PACKAGE_DIR)

            help_result = subprocess.run(
                [sys.executable, "-m", "prosze_cli", "--help"],
                cwd=PACKAGE_DIR,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(help_result.returncode, 0)
            self.assertIn("Remove sensitive details", help_result.stdout)

            redact_result = subprocess.run(
                command + ["redact", "--no-ner", "--map", str(map_path), "--term", "CUSTOMER=Acme Corp"],
                cwd=PACKAGE_DIR,
                env=env,
                input="Please contact Acme Corp.",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(redact_result.returncode, 0)
            self.assertEqual(redact_result.stdout, "Please contact [[CUSTOMER_1]].")
            self.assertIn("1 item(s) hidden", redact_result.stderr)

            restore_result = subprocess.run(
                command + ["restore", "--no-ner", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input=redact_result.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(restore_result.returncode, 0)
            self.assertEqual(restore_result.stdout, "Please contact Acme Corp.")

    def test_bare_cli_launches_chat(self):
        with patch("prosze_cli.cmd_chat") as launch_chat:
            cli_main([])
        launch_chat.assert_called_once()

    def test_pyproject_metadata_references_existing_modules(self):
        pyproject_path = PACKAGE_DIR / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        project = pyproject_data.get("project", {})
        tool_setuptools = pyproject_data.get("tool", {}).get("setuptools", {})

        py_modules = tool_setuptools.get("py-modules", [])
        self.assertEqual(py_modules, ["prosze_core", "prosze_main"])
        for module_name in py_modules:
            module_file = PACKAGE_DIR / f"{module_name}.py"
            self.assertTrue(module_file.is_file(), f"Module file {module_file} does not exist on disk")

        self.assertNotIn("hermes_agent.plugins", project.get("entry-points", {}))
        self.assertEqual(project.get("dependencies"), [])

    def test_strict_restore_blocks_preloaded_placeholders(self):
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "map.tsv"
            with open(map_path, "w", encoding="utf-8") as f:
                f.write("[[CUSTOMER_1]]\tAcme Corp\n[[TOKEN_1]]\tsuper-secret-token\n")

            # Default mode (strict_restore=False)
            v_default = Vault(str(map_path), strict_restore=False)
            v_default._ner_attempted = True
            self.assertEqual(
                v_default.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]"),
                "Hello Acme Corp and super-secret-token",
            )

            # strict_restore=True
            v_strict = Vault(str(map_path), strict_restore=True)
            v_strict._ner_attempted = True

            # Before any redaction, nothing is in session_keys: both remain placeholders
            self.assertEqual(
                v_strict.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]"),
                "Hello [[CUSTOMER_1]] and [[TOKEN_1]]",
            )

            # Redacting Acme Corp registers [[CUSTOMER_1]] into session_keys
            v_strict.add_term("CUSTOMER=Acme Corp")
            safe, n = v_strict.redact("We are contacting Acme Corp today.")
            self.assertEqual(safe, "We are contacting [[CUSTOMER_1]] today.")
            self.assertIn("[[CUSTOMER_1]]", v_strict.session_keys)
            self.assertNotIn("[[TOKEN_1]]", v_strict.session_keys)

            # Only [[CUSTOMER_1]] is restored, [[TOKEN_1]] remains blocked
            self.assertEqual(
                v_strict.restore("Hello [[CUSTOMER_1]] and [[TOKEN_1]]"),
                "Hello Acme Corp and [[TOKEN_1]]",
            )

            # CLI verification of --strict-restore flag
            command = [sys.executable, "-m", "prosze_cli"]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PACKAGE_DIR)

            res_normal = subprocess.run(
                command + ["restore", "--no-ner", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input="Customer: [[CUSTOMER_1]]",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_normal.returncode, 0)
            self.assertEqual(res_normal.stdout, "Customer: Acme Corp")

            res_strict = subprocess.run(
                command + ["restore", "--no-ner", "--strict-restore", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input="Customer: [[CUSTOMER_1]]",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_strict.returncode, 0)
            self.assertEqual(res_strict.stdout, "Customer: [[CUSTOMER_1]]")

    def test_cloud_and_ai_secret_rules_and_ips(self):
        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)

            # Hugging Face token
            hf = "hf_012345678901234567890123456789"
            s1, _ = v.redact(f"HuggingFace: {hf}")
            self.assertEqual(s1, "HuggingFace: [[TOKEN_1]]")
            self.assertEqual(v.restore(s1), f"HuggingFace: {hf}")

            # GitHub fine-grained PAT
            pat = "github_pat_11ABCD0123456789012345"
            s2, _ = v.redact(f"GitHub PAT: {pat}")
            self.assertEqual(s2, "GitHub PAT: [[TOKEN_2]]")
            self.assertEqual(v.restore(s2), f"GitHub PAT: {pat}")

            # Slack incoming webhook
            slack_prefix = "https://hooks.slack.com/services/"
            slack = f"{slack_prefix}T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
            s3, _ = v.redact(f"Slack Webhook: {slack}")
            self.assertEqual(s3, "Slack Webhook: [[TOKEN_3]]")
            self.assertEqual(v.restore(s3), f"Slack Webhook: {slack}")

            # Anthropic / OpenAI / Stripe tokens
            ant = "sk-ant-api03-abcdef1234567890"
            s4, _ = v.redact(f"Anthropic: {ant}")
            self.assertEqual(s4, "Anthropic: [[TOKEN_4]]")
            self.assertEqual(v.restore(s4), f"Anthropic: {ant}")

            sk_proj = "sk-proj-abcdef1234567890"
            s5, _ = v.redact(f"OpenAI: {sk_proj}")
            self.assertEqual(s5, "OpenAI: [[TOKEN_5]]")
            self.assertEqual(v.restore(s5), f"OpenAI: {sk_proj}")

            sk_live = "sk_live_abcdef1234567890"
            s6, _ = v.redact(f"Stripe: {sk_live}")
            self.assertEqual(s6, "Stripe: [[TOKEN_6]]")
            self.assertEqual(v.restore(s6), f"Stripe: {sk_live}")

            rk_live = "rk_live_abcdef1234567890"
            s7, _ = v.redact(f"Stripe restricted: {rk_live}")
            self.assertEqual(s7, "Stripe restricted: [[TOKEN_7]]")
            self.assertEqual(v.restore(s7), f"Stripe restricted: {rk_live}")

            # Cloud metadata IP
            s_meta, _ = v.redact("AWS metadata IP: 169.254.169.254")
            self.assertEqual(s_meta, "AWS metadata IP: [[IP_1]]")
            self.assertEqual(v.restore(s_meta), "AWS metadata IP: 169.254.169.254")

            # Link-local IPv4
            s_ll4, _ = v.redact("Link-local IPv4: 169.254.10.20")
            self.assertEqual(s_ll4, "Link-local IPv4: [[IP_2]]")
            self.assertEqual(v.restore(s_ll4), "Link-local IPv4: 169.254.10.20")

            # IPv6 ULA
            s_ula1, _ = v.redact("IPv6 ULA prefix: fd00::")
            self.assertEqual(s_ula1, "IPv6 ULA prefix: [[IP_3]]")
            self.assertEqual(v.restore(s_ula1), "IPv6 ULA prefix: fd00::")

            s_ula2, _ = v.redact("IPv6 ULA addr: fd12:3456:789a:1::1")
            self.assertEqual(s_ula2, "IPv6 ULA addr: [[IP_4]]")
            self.assertEqual(v.restore(s_ula2), "IPv6 ULA addr: fd12:3456:789a:1::1")

            # IPv6 link-local
            s_ll6_1, _ = v.redact("IPv6 link-local prefix: fe80::")
            self.assertEqual(s_ll6_1, "IPv6 link-local prefix: [[IP_5]]")
            self.assertEqual(v.restore(s_ll6_1), "IPv6 link-local prefix: fe80::")

            s_ll6_2, _ = v.redact("IPv6 link-local host: fe80::1")
            self.assertEqual(s_ll6_2, "IPv6 link-local host: [[IP_6]]")
            self.assertEqual(v.restore(s_ll6_2), "IPv6 link-local host: fe80::1")

            s_ll6_3, _ = v.redact("IPv6 link-local full: fe80::20c:29ff:fe4b:8a12")
            self.assertEqual(s_ll6_3, "IPv6 link-local full: [[IP_7]]")
            self.assertEqual(v.restore(s_ll6_3), "IPv6 link-local full: fe80::20c:29ff:fe4b:8a12")

            # Public IPs should not be redacted
            pub = "Public DNS: 8.8.8.8 and 2001:db8::1"
            safe_pub, n = v.redact(pub)
            self.assertEqual(safe_pub, pub)
            self.assertEqual(n, 0)

    def test_base64_encoded_secret_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)

            # Base64 of "Bearer sk-example1234567890abcdef"
            b64_token = "QmVhcmVyIHNrLWV4YW1wbGUxMjM0NTY3ODkwYWJjZGVm"
            s1, n1 = v.redact(f"Authorization: {b64_token}")
            self.assertEqual(s1, "Authorization: [[ENCODED_1]]")
            self.assertEqual(n1, 1)
            self.assertEqual(v.restore(s1), f"Authorization: {b64_token}")

            # Base64 of "password=supersecret123"
            b64_pwd = "cGFzc3dvcmQ9c3VwZXJzZWNyZXQxMjM="
            s2, n2 = v.redact(f"Payload: {b64_pwd}")
            self.assertEqual(s2, "Payload: [[ENCODED_2]]")
            self.assertEqual(n2, 1)
            self.assertEqual(v.restore(s2), f"Payload: {b64_pwd}")

            # Plain English base64
            b64_plain = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4="
            s3, n3 = v.redact(f"Public note: {b64_plain}")
            self.assertEqual(s3, f"Public note: {b64_plain}")
            self.assertEqual(n3, 0)

            # strict_restore verification on ENCODED placeholders
            v.strict_restore = True
            self.assertEqual(v.restore(s1), f"Authorization: {b64_token}")
            self.assertEqual(v.restore("[[ENCODED_99]]"), "[[ENCODED_99]]")

    def test_aho_corasick_literals_terms_and_placeholder_immunity(self):
        # Direct AhoCorasick overlap and whole-word suffix fallback
        ac = AhoCorasick(case_fold=True)
        ac.build([("Big Acme", "ORG"), ("Acme", "CUSTOMER")])
        matches = ac.find_matches("xBig Acme and Big Acme", whole_word=True)
        self.assertEqual(matches, [(5, 9, "CUSTOMER"), (14, 22, "ORG")])

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            self.assertFalse(v.literals_dirty)
            self.assertFalse(v.terms_dirty)

            v.add_literal("Acme")
            v.add_literal("Acme Corp")
            v.add_literal("CUSTOMER_1")
            self.assertTrue(v.literals_dirty)

            lit_out, lit_hits = v.redact("Hello Acme Corp, Acme, [[CUSTOMER_1]], and CUSTOMER_1.")
            self.assertFalse(v.literals_dirty)
            self.assertEqual(lit_hits, 3)
            self.assertEqual(lit_out, "Hello [[ENV_1]], [[ENV_2]], [[CUSTOMER_1]], and [[ENV_3]].")
            self.assertEqual(v.restore(lit_out), "Hello Acme Corp, Acme, [[CUSTOMER_1]], and CUSTOMER_1.")

            tv = Vault(str(Path(directory) / "terms_map.tsv"))
            tv._ner_attempted = True
            tv.add_term("ORG=Acme Corp")
            tv.add_term("PROJECT=Acme")
            tv.add_term("PERSON=Jan")
            tv.add_term("TERM=CUSTOMER_1")
            self.assertTrue(tv.terms_dirty)

            term_out, term_hits = tv.redact("Dear Jan, Janek at ACME CORP and acme saw [[CUSTOMER_1]] and CUSTOMER_1.")
            self.assertFalse(tv.terms_dirty)
            self.assertEqual(term_hits, 4)
            self.assertEqual(
                term_out,
                "Dear [[PERSON_1]], Janek at [[ORG_1]] and [[PROJECT_1]] saw [[CUSTOMER_1]] and [[TERM_1]].",
            )
            self.assertEqual(
                tv.restore(term_out),
                "Dear Jan, Janek at ACME CORP and acme saw [[CUSTOMER_1]] and CUSTOMER_1.",
            )

            # Lazy rebuild after adding new literal and term post-redact
            tv.add_term("PROJECT=Apollo")
            tv.add_literal("new-secret-val")
            self.assertTrue(tv.terms_dirty)
            self.assertTrue(tv.literals_dirty)
            second, second_hits = tv.redact("apollo uses new-secret-val")
            self.assertFalse(tv.terms_dirty)
            self.assertFalse(tv.literals_dirty)
            self.assertEqual(second_hits, 2)
            self.assertEqual(second, "[[PROJECT_2]] uses [[ENV_1]]")

    def test_prefilter_accuracy_and_zero_match_fast_path(self):
        self.assertEqual(scan_char_features("Plain prose without digits or special symbols"), FEAT_NONE)
        self.assertEqual(scan_char_features("a@b.c"), FEAT_AT | FEAT_DOT)
        self.assertEqual(
            scan_char_features("k=v:1-2_3+4"),
            FEAT_COLON_EQ | FEAT_DIGIT | FEAT_DASH_UNDER | FEAT_PLUS,
        )

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)

            # Zero-match fast path on plain prose skips all non-zero-feature rules
            prose = "Just ordinary English prose without any sensitive markers at all"
            self.assertEqual(scan_char_features(prose), FEAT_NONE)

            class SpyRegex:
                def __init__(self):
                    self.calls = 0

                def finditer(self, text):
                    self.calls += 1
                    return iter(())

            spy = SpyRegex()
            orig_rules = v.rules
            v.rules = [("TEST", spy, 0, None, FEAT_AT | FEAT_DIGIT)]
            try:
                safe_prose, hits_prose = v.redact(prose)
                self.assertEqual(safe_prose, prose)
                self.assertEqual(hits_prose, 0)
                self.assertEqual(spy.calls, 0)
                self.assertFalse(v._contains_secret(prose))
                self.assertEqual(spy.calls, 0)
            finally:
                v.rules = orig_rules

            # Every secret category + zero-digit edge cases
            cases = [
                ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "[[PRIVKEY_1]]"),
                ("url https://bob:secret99@host.internal/api", "[[PASSWORD_1]]"),
                ("mail alice@example.com", "[[EMAIL_1]]"),
                ("aws AKIAAAAAAAAAAAAAAAAA", "[[TOKEN_1]]"),
                ("gcp AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "[[TOKEN_2]]"),
                ("hf hf_abcdefghijklmnopqrstuvwxyz012345", "[[TOKEN_3]]"),
                ("gh github_pat_11ABCD0123456789012345", "[[TOKEN_4]]"),
                ("slack https://hooks.slack.com/services/T11/B22/XYZ123", "[[TOKEN_5]]"),
                ("openai sk-proj-abcdef1234567890", "[[TOKEN_6]]"),
                ("jwt eyJabcdefgh.eyJijklmnop.signature12", "[[TOKEN_7]]"),
                ("auth Bearer AbCdEfGhIjKlMnOpQrSt", "[[TOKEN_8]]"),
                ("cfg password=mysecretpass", "[[PASSWORD_2]]"),
                ("iban DE89370400440532013000", "[[IBAN_1]]"),
                ("acct account 123456789", "[[ACCOUNT_1]]"),
                ("ssn 123-45-6789", "[[SSN_1]]"),
                ("tel phone: 555 123 4567", "[[PHONE_1]]"),
                ("card 4111111111111111", "[[CARD_1]]"),
                ("rand A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", "[[APIKEY_1]]"),
                ("hex abcdefabcdefabcdefabcdefabcdefabcdefabcd", "[[APIKEY_2]]"),
                ("ipv4 192.168.1.50", "[[IP_1]]"),
                ("ipv6 fcab::cdef", "[[IP_2]]"),
                ("intl +48 601 234 567", "[[PHONE_2]]"),
                ("sep 601 234 567", "[[PHONE_3]]"),
            ]
            for raw, expected_ph in cases:
                safe, hits = v.redact(raw)
                self.assertEqual(hits, 1, f"Expected 1 hit for {raw!r}, got {safe!r}")
                self.assertIn(expected_ph, safe)
                self.assertTrue(v._contains_secret(raw))

            # Base64 < 24 fast path does not alter short base64-like tokens
            short_b64 = "cGFzc3dvcmQ9MTIz"
            safe_short, hits_short = v.redact(short_b64)
            self.assertEqual(safe_short, short_b64)
            self.assertEqual(hits_short, 0)

    def test_50kb_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            for i in range(100):
                v.add_term(f"CUSTOMER=CustomerOrganization{i}")
            for i in range(50):
                v.add_literal(f"literal_secret_value_{i}")

            chunk = "The team reviewed architecture notes and deployment timelines during weekly planning. "
            payload = (chunk * ((50 * 1024 // len(chunk)) + 1))
            payload += " Contact CustomerOrganization42 regarding literal_secret_value_17."

            t0 = time.perf_counter()
            safe, hits = v.redact(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            self.assertEqual(hits, 2)
            self.assertIn("[[CUSTOMER_1]]", safe)
            self.assertIn("[[ENV_1]]", safe)
            self.assertLess(elapsed_ms, 500.0)

    def test_stream_redact_and_restore_chunk_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            v.add_term("CUSTOMER=Acme Corp")

            key_block = (
                "-----BEGIN PRIVATE KEY-----\n"
                "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n"
                "0123456789abcdef0123456789abcdef0123456789abcdef\n"
                "-----END PRIVATE KEY-----\n"
            )
            raw = (
                "012345678901234567890123 alice.smith@example.com\n"
                "01234567890123456789012345 Acme Corp\n"
                "0123456789012345678901234 sk-proj-abcdef1234567890\n"
                + key_block
                + "Trailing 01234567890123456789 bob.jones@example.org end."
            )

            out_buf = io.StringIO()
            total_hits = v.redact_stream(io.StringIO(raw), out_buf, chunk_size=32)
            safe = out_buf.getvalue()

            self.assertEqual(total_hits, 5)
            self.assertNotIn("alice.smith@example.com", safe)
            self.assertNotIn("Acme Corp", safe)
            self.assertNotIn("sk-proj-abcdef1234567890", safe)
            self.assertNotIn("MIIBVQIBADANBgkqhkiG9w0BAQEFAASC", safe)
            self.assertNotIn("bob.jones@example.org", safe)
            self.assertIn("[[EMAIL_1]]", safe)
            self.assertIn("[[CUSTOMER_1]]", safe)
            self.assertIn("[[TOKEN_1]]", safe)
            self.assertIn("[[PRIVKEY_1]]", safe)
            self.assertIn("[[EMAIL_2]]", safe)

            # Restore with "[[" split across 32-byte boundary (both '['|'[' and mid-placeholder)
            restored_out = io.StringIO()
            padded = "0123456789012345678901234567890[[CUSTOMER_1]] 0123456789012345[[CUSTOMER_1]] " + safe
            v.restore_stream(io.StringIO(padded), restored_out, chunk_size=32)
            self.assertEqual(
                restored_out.getvalue(),
                "0123456789012345678901234567890Acme Corp 0123456789012345Acme Corp " + raw,
            )

            # Binary streams with multi-byte UTF-8 across chunk boundary
            utf8_raw = ("Łódź — prefix 0123456789012345 alice.smith@example.com end").encode("utf-8")
            bin_safe = io.BytesIO()
            hits_bin = v.redact_stream(io.BytesIO(utf8_raw), bin_safe, chunk_size=32)
            self.assertEqual(hits_bin, 1)
            self.assertIn(b"[[EMAIL_1]]", bin_safe.getvalue())
            bin_restored = io.BytesIO()
            v.restore_stream(io.BytesIO(bin_safe.getvalue()), bin_restored, chunk_size=32)
            self.assertEqual(bin_restored.getvalue(), utf8_raw)

            # Unclosed "-----BEGIN " cap (> 64 KB) still completes and redacts trailing email
            bogus_payload = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 1150 + "tail mail@example.com"
            v2 = Vault(str(Path(directory) / "cap_map.tsv"))
            v2._ner_attempted = True
            cap_out = io.StringIO()
            cap_hits = v2.redact_stream(io.StringIO(bogus_payload), cap_out, chunk_size=4096)
            self.assertGreaterEqual(cap_hits, 1)
            self.assertIn("[[EMAIL_1]]", cap_out.getvalue())
            self.assertNotIn("mail@example.com", cap_out.getvalue())

    def test_cli_stream_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "map.tsv"
            command = [sys.executable, "-m", "prosze_cli"]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PACKAGE_DIR)

            payload = (
                "012345678901234567890123 alice.smith@example.com\n"
                "Please contact Acme Corp.\n"
            )
            redact_res = subprocess.run(
                command + ["redact", "--stream", "--no-ner", "--map", str(map_path), "--term", "CUSTOMER=Acme Corp"],
                cwd=PACKAGE_DIR,
                env=env,
                input=payload,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(redact_res.returncode, 0)
            self.assertIn("[[EMAIL_1]]", redact_res.stdout)
            self.assertIn("[[CUSTOMER_1]]", redact_res.stdout)
            self.assertIn("2 item(s) hidden", redact_res.stderr)

            restore_res = subprocess.run(
                command + ["restore", "--stream", "--no-ner", "--map", str(map_path)],
                cwd=PACKAGE_DIR,
                env=env,
                input=redact_res.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(restore_res.returncode, 0)
            self.assertEqual(restore_res.stdout, payload)


if __name__ == "__main__":
    unittest.main()
