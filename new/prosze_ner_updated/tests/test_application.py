import gzip
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
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

    def test_stream_restorer_chunk_boundaries_and_json_escaping(self):
        from prosze_cli.broker import StreamRestorer

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            v.add_term("CUSTOMER=Acme Corp")
            v.add_literal('secret "one"\ntwo\\three', cat="ENV")

            safe, hits = v.redact('Customer Acme Corp and secret "one"\ntwo\\three end.')
            self.assertEqual(hits, 2)
            self.assertEqual(safe, "Customer [[CUSTOMER_1]] and [[ENV_1]] end.")

            # Feed 1 character at a time (covers '[', '[[', mid-token, single ']', ']]')
            sr = StreamRestorer(v)
            chunks = [sr.feed(ch) for ch in safe]
            chunks.append(sr.flush())
            self.assertEqual("".join(chunks), 'Customer Acme Corp and secret "one"\ntwo\\three end.')

            # Non-placeholder brackets and over-60-char partial sequences do not stall stream
            sr2 = StreamRestorer(v)
            self.assertEqual(sr2.feed("arr[0] "), "arr[0] ")
            self.assertEqual(sr2.feed("[[not_ph "), "[[not_ph ")
            self.assertEqual(sr2.feed("[[A_1] x "), "[[A_1] x ")
            long_open = "[[" + ("A" * 65)
            out_long = sr2.feed(long_open)
            self.assertEqual(out_long, long_open)
            self.assertEqual(sr2.feed("tail [["), "tail ")
            self.assertEqual(sr2.flush(), "[[")

            # json_escaped=True produces valid escaped JSON across split boundaries
            sr_json = StreamRestorer(v, json_escaped=True)
            json_safe = '{"text":"[[CUSTOMER_1]]: [[ENV_1]]"}'
            j_parts = [sr_json.feed(json_safe[:15]), sr_json.feed(json_safe[15:26]), sr_json.feed(json_safe[26:])]
            j_parts.append(sr_json.flush())
            parsed = json.loads("".join(j_parts))
            self.assertEqual(parsed["text"], 'Acme Corp: secret "one"\ntwo\\three')

            # strict_restore=True blocks unredacted pre-loaded placeholders
            v_strict = Vault(str(Path(directory) / "strict_map.tsv"), strict_restore=True)
            v_strict._ner_attempted = True
            v_strict.fwd["[[TOKEN_1]]"] = "hidden-token"
            v_strict.bwd["hidden-token"] = "[[TOKEN_1]]"
            v_strict.add_term("CUSTOMER=Acme Corp")
            v_strict.redact("Acme Corp")
            sr_strict = StreamRestorer(v_strict)
            strict_out = sr_strict.feed("[[CUSTOMER") + sr_strict.feed("_1]] and [[TOKEN") + sr_strict.feed("_1]]") + sr_strict.flush()
            self.assertEqual(strict_out, "Acme Corp and [[TOKEN_1]]")

    def test_sse_restorer_split_events_and_preservation(self):
        from prosze_cli.broker import SSERestorer

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            v.add_term("CUSTOMER=Acme Corp")
            safe_prompt, _ = v.redact("Contact Acme Corp via alice@example.com")
            self.assertIn("[[CUSTOMER_1]]", safe_prompt)
            self.assertIn("[[EMAIL_1]]", safe_prompt)

            # OpenAI JSON SSE with split placeholders and arbitrary chunk splits
            sse_stream = (
                ": keepalive\n\n"
                "event: chunk\n"
                "id: 1\n"
                "retry: 1000\n"
                'data: {"id":"cmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi [["}}]}\n\n'
                'data: {"id":"cmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"CUSTOMER_1"}}]}\n\n'
                'data: {"id":"cmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"]] / [["}}]}\n\n'
                'data: {"id":"cmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"EMAIL_1]]!"}}]}\n\n'
                "data: [DONE]\n\n"
            )
            restorer = SSERestorer(v)
            pieces = []
            step = 19
            for i in range(0, len(sse_stream), step):
                pieces.append(restorer.feed(sse_stream[i:i + step]))
            pieces.append(restorer.flush())
            out = "".join(pieces)

            self.assertIn(": keepalive\n", out)
            self.assertIn("event: chunk\n", out)
            self.assertIn("id: 1\n", out)
            self.assertIn("retry: 1000\n", out)
            self.assertIn("data: [DONE]\n", out)

            assembled = []
            for line in out.splitlines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    obj = json.loads(line[6:])
                    assembled.append(obj["choices"][0]["delta"]["content"])
            self.assertEqual("".join(assembled), "Hi Acme Corp / alice@example.com!")

            # Plain-text SSE with split placeholder + metadata + [DONE]
            plain_sse = (
                ": comment\n\n"
                "event: text\n"
                "id: 9\n"
                "data: Tell [[\n\n"
                "data: CUSTOMER_1\n\n"
                "data: ]] now\n\n"
                "data: [DONE]\n\n"
            )
            plain_restorer = SSERestorer(v)
            plain_out = plain_restorer.feed(plain_sse) + plain_restorer.flush()
            self.assertIn(": comment\n", plain_out)
            self.assertIn("event: text\n", plain_out)
            self.assertIn("id: 9\n", plain_out)
            self.assertIn("data: [DONE]\n", plain_out)
            plain_data = "".join(
                line[6:] for line in plain_out.splitlines() if line.startswith("data: ") and line != "data: [DONE]"
            )
            self.assertEqual(plain_data, "Tell Acme Corp now")

            # Anthropic content_block_delta + trailing incomplete prefix flushed before [DONE]
            ant_sse = (
                "event: content_block_delta\n"
                'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi [["}}\n\n'
                "event: content_block_delta\n"
                'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"CUSTOMER_1]] and [[PARTIAL"}}\n\n'
                "data: [DONE]\n\n"
            )
            ant_restorer = SSERestorer(v)
            ant_out = ant_restorer.feed(ant_sse) + ant_restorer.flush()
            self.assertIn("event: content_block_delta\n", ant_out)
            self.assertIn("data: [DONE]\n", ant_out)
            ant_text = "".join(
                json.loads(line[6:])["delta"]["text"]
                for line in ant_out.splitlines()
                if line.startswith("data: ") and line != "data: [DONE]"
            )
            self.assertEqual(ant_text, "Hi Acme Corp and [[PARTIAL")
            self.assertLess(ant_out.index("[[PARTIAL"), ant_out.index("data: [DONE]"))

    def test_broker_validation_and_loopback_guards(self):
        from prosze_cli.broker import create_broker_server

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory, ephemeral=True)

            # Non-loopback hosts rejected unless allow_remote=True
            for bad_host in ("0.0.0.0", "192.168.1.50", "10.0.0.5", ""):
                with self.assertRaises(ValueError):
                    create_broker_server(v, host=bad_host, port=0)

            # allow_remote=True permits non-loopback
            remote_srv = create_broker_server(v, host="0.0.0.0", port=0, allow_remote=True)
            remote_srv.server_close()

            # Loopback hosts allowed by default
            for ok_host in ("127.0.0.1", "localhost", "::1"):
                srv = create_broker_server(v, host=ok_host, port=0)
                srv.server_close()

            # Invalid upstream URLs rejected
            for bad_upstream in ("ftp://example.com", "file:///etc/passwd", "https://", "not-a-url", ""):
                with self.assertRaises(ValueError):
                    create_broker_server(v, host="127.0.0.1", port=0, upstream=bad_upstream)

    def _start_dummy_upstream(self, handler_cls):
        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def _start_broker(self, vault, upstream_url):
        from prosze_cli.broker import create_broker_server

        broker = create_broker_server(vault, host="127.0.0.1", port=0, upstream=upstream_url)
        thread = threading.Thread(target=broker.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(broker.server_close)
        self.addCleanup(broker.shutdown)
        return broker

    def test_broker_gateway_json_text_and_sse_roundtrip(self):
        captured_requests = []

        class DummyUpstreamHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                captured_requests.append({
                    "method": "POST",
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                })

                if self.path == "/v1/chat/completions":
                    payload = json.loads(body.decode("utf-8"))
                    if payload.get("stream"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        events = [
                            ": stream-open\n\n",
                            'data: {"id":"1","choices":[{"index":0,"delta":{"content":"Hello [["}}]}\n\n',
                            'data: {"id":"1","choices":[{"index":0,"delta":{"content":"CUSTOMER_1"}}]}\n\n',
                            'data: {"id":"1","choices":[{"index":0,"delta":{"content":"]] & [["}}]}\n\n',
                            'data: {"id":"1","choices":[{"index":0,"delta":{"content":"EMAIL_1]]"}}]}\n\n',
                            "data: [DONE]\n\n",
                        ]
                        for ev in events:
                            self.wfile.write(ev.encode("utf-8"))
                            self.wfile.flush()
                        self.close_connection = True
                        return

                    resp_obj = {
                        "id": "cmpl-test",
                        "object": "chat.completion",
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Ack [[CUSTOMER_1]] / [[EMAIL_1]] / [[TOKEN_1]] / [[ENV_1]]"}}],
                    }
                    resp_bytes = json.dumps(resp_obj).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)
                    return

                if self.path == "/v1/text":
                    resp_bytes = f"Upstream saw: {body.decode('utf-8')}".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)

        upstream = self._start_dummy_upstream(DummyUpstreamHandler)
        upstream_url = f"http://127.0.0.1:{upstream.server_port}"

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            v.add_term("CUSTOMER=Acme Corp")
            v.add_literal('quote"secret\nline2', cat="ENV")
            broker = self._start_broker(v, upstream_url)
            b_host, b_port = broker.server_address

            # 1. JSON request/response round-trip + hop-by-hop & Accept-Encoding checks
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            req_body = json.dumps({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": 'Ask Acme Corp (alice@example.com, sk-proj-abcdef1234567890) about quote"secret\nline2'}],
                "attachment": {"type": "base64", "data": "keep-raw-base64"},
            }).encode("utf-8")
            conn.request(
                "POST",
                "/v1/chat/completions",
                body=req_body,
                headers={
                    "Content-Type": "application/json",
                    "Accept-Encoding": "gzip, br",
                    "Connection": "keep-alive, x-custom-hop",
                    "Keep-Alive": "timeout=5",
                    "Proxy-Connection": "keep-alive",
                    "X-Custom-Hop": "drop-me",
                    "Authorization": "Bearer public-test-header",
                },
            )
            resp = conn.getresponse()
            resp_data = json.loads(resp.read().decode("utf-8"))
            conn.close()

            self.assertEqual(resp.status, 200)
            self.assertEqual(
                resp_data["choices"][0]["message"]["content"],
                'Ack Acme Corp / alice@example.com / sk-proj-abcdef1234567890 / quote"secret\nline2',
            )

            up_req = captured_requests[-1]
            up_body_text = up_req["body"].decode("utf-8")
            self.assertNotIn("Acme Corp", up_body_text)
            self.assertNotIn("alice@example.com", up_body_text)
            self.assertNotIn("sk-proj-abcdef1234567890", up_body_text)
            self.assertIn("[[CUSTOMER_1]]", up_body_text)
            self.assertIn("[[EMAIL_1]]", up_body_text)
            self.assertIn("[[TOKEN_1]]", up_body_text)
            self.assertIn("[[ENV_1]]", up_body_text)
            up_json = json.loads(up_body_text)
            self.assertEqual(up_json["model"], "gpt-4o")
            self.assertEqual(up_json["attachment"]["data"], "keep-raw-base64")
            self.assertEqual(up_req["headers"].get("accept-encoding"), "identity")
            self.assertNotIn("keep-alive", up_req["headers"])
            self.assertNotIn("proxy-connection", up_req["headers"])
            self.assertNotIn("x-custom-hop", up_req["headers"])

            # 2. Plain text request/response round-trip
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            conn.request(
                "POST",
                "/v1/text",
                body=b"Notify alice@example.com at Acme Corp",
                headers={"Content-Type": "text/plain"},
            )
            t_resp = conn.getresponse()
            t_body = t_resp.read().decode("utf-8")
            conn.close()
            self.assertEqual(t_resp.status, 200)
            self.assertEqual(t_body, "Upstream saw: Notify alice@example.com at Acme Corp")
            self.assertEqual(captured_requests[-1]["body"], b"Notify [[EMAIL_1]] at [[CUSTOMER_1]]")

            # 2b. Chunked Transfer-Encoding request body redaction round-trip
            chunk_payload = b"Chunk secret: alice@example.com"
            with socket.create_connection((b_host, b_port), timeout=5) as sock:
                raw_chunked_req = (
                    b"POST /v1/text HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    + f"{len(chunk_payload):x}\r\n".encode("ascii")
                    + chunk_payload
                    + b"\r\n0\r\n\r\n"
                )
                sock.sendall(raw_chunked_req)
                raw_chunked_resp = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    raw_chunked_resp += part
            self.assertIn(b"200 OK", raw_chunked_resp)
            self.assertIn(b"Upstream saw: Chunk secret: alice@example.com", raw_chunked_resp)
            self.assertEqual(captured_requests[-1]["body"], b"Chunk secret: [[EMAIL_1]]")

            # 3. SSE streaming round-trip
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            conn.request(
                "POST",
                "/v1/chat/completions",
                body=json.dumps({"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "Hi Acme Corp"}]}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            s_resp = conn.getresponse()
            sse_raw = s_resp.read().decode("utf-8")
            conn.close()
            self.assertEqual(s_resp.status, 200)
            self.assertIn(": stream-open", sse_raw)
            self.assertIn("data: [DONE]", sse_raw)
            sse_content = "".join(
                json.loads(line[6:])["choices"][0]["delta"]["content"]
                for line in sse_raw.splitlines()
                if line.startswith("data: ") and line != "data: [DONE]"
            )
            self.assertEqual(sse_content, "Hello Acme Corp & alice@example.com")

            # 4. Bounded history metadata check (no raw secrets, max 100 entries)
            self.assertGreaterEqual(len(broker.history), 3)
            for entry in broker.history:
                self.assertEqual(set(entry.keys()), {"method", "path", "status", "redacted_count", "latency_ms"})
                self.assertGreaterEqual(entry["latency_ms"], 0.0)
            history_dump = json.dumps(broker.history)
            self.assertNotIn("Acme Corp", history_dump)
            self.assertNotIn("alice@example.com", history_dump)
            self.assertNotIn("sk-proj-abcdef1234567890", history_dump)
            self.assertEqual(broker.history[0]["redacted_count"], 4)

            for _ in range(105):
                conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
                conn.request("POST", "/v1/text", body=b"plain text", headers={"Content-Type": "text/plain"})
                r = conn.getresponse()
                r.read()
                conn.close()
            self.assertEqual(len(broker.history), 100)

            # 5. Concurrent requests remain thread-safe on vault + bounded history
            def worker(idx):
                c = http.client.HTTPConnection(b_host, b_port, timeout=5)
                c.request(
                    "POST",
                    "/v1/text",
                    body=f"Worker {idx} for Acme Corp".encode("utf-8"),
                    headers={"Content-Type": "text/plain"},
                )
                w_resp = c.getresponse()
                w_body = w_resp.read().decode("utf-8")
                c.close()
                self.assertEqual(w_resp.status, 200)
                self.assertEqual(w_body, f"Upstream saw: Worker {idx} for Acme Corp")

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=5)
                self.assertFalse(th.is_alive())
            self.assertEqual(len(broker.history), 100)
            self.assertNotIn("Acme Corp", json.dumps(broker.history))

    def test_broker_gateway_framing_size_and_compressed_502_guards(self):
        upstream_hits = 0

        class GuardDummyUpstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                return

            def do_POST(self):
                nonlocal upstream_hits
                upstream_hits += 1
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                if self.path == "/compressed":
                    body = b"\x1f\x8b\x08\x00fake-gzip"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                    return

                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "identity")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = self._start_dummy_upstream(GuardDummyUpstream)
        upstream_url = f"http://127.0.0.1:{upstream.server_port}"

        with tempfile.TemporaryDirectory() as directory:
            v = self.make_vault(directory)
            broker = self._start_broker(v, upstream_url)
            b_host, b_port = broker.server_address

            # 1. Both Content-Length and Transfer-Encoding -> 400 Bad Request
            with socket.create_connection((b_host, b_port), timeout=5) as sock:
                raw_req = (
                    b"POST /v1/chat/completions HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 5\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    b"0\r\n\r\n"
                )
                sock.sendall(raw_req)
                raw_resp = sock.recv(4096).decode("utf-8", "replace")
            self.assertTrue(raw_resp.startswith("HTTP/1.1 400 ") or raw_resp.startswith("HTTP/1.0 400 "))
            self.assertEqual(upstream_hits, 0)

            # 2. > 16 MiB Content-Length -> 413 Payload Too Large
            over_cap = (16 * 1024 * 1024) + 1
            with socket.create_connection((b_host, b_port), timeout=5) as sock:
                raw_req = (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\n"
                    f"Content-Length: {over_cap}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(raw_req)
                raw_resp = sock.recv(4096).decode("utf-8", "replace")
            self.assertTrue(raw_resp.startswith("HTTP/1.1 413 ") or raw_resp.startswith("HTTP/1.0 413 "))
            self.assertEqual(upstream_hits, 0)

            # 3. Compressed upstream Content-Encoding -> 502 Bad Gateway
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            conn.request("POST", "/compressed", body=b'{"x":1}', headers={"Content-Type": "application/json"})
            c_resp = conn.getresponse()
            c_resp.read()
            conn.close()
            self.assertEqual(c_resp.status, 502)

            # 4. Identity upstream Content-Encoding -> 200 OK
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            conn.request("POST", "/identity", body=b'{"x":1}', headers={"Content-Type": "application/json"})
            i_resp = conn.getresponse()
            i_body = i_resp.read()
            conn.close()
            self.assertEqual(i_resp.status, 200)
            self.assertEqual(i_body, b'{"ok":true}')

            # 5. Chunked Transfer-Encoding exceeding 16 MiB -> 413 Payload Too Large
            over_chunk_hex = f"{(16 * 1024 * 1024) + 1:x}"
            with socket.create_connection((b_host, b_port), timeout=5) as sock:
                raw_req = (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{over_chunk_hex}\r\n"
                ).encode("ascii")
                sock.sendall(raw_req)
                raw_resp = sock.recv(4096).decode("utf-8", "replace")
            self.assertTrue(raw_resp.startswith("HTTP/1.1 413 ") or raw_resp.startswith("HTTP/1.0 413 "))

            # 6. Unreachable upstream -> 502 Bad Gateway
            closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            closed_sock.bind(("127.0.0.1", 0))
            dead_port = closed_sock.getsockname()[1]
            closed_sock.close()
            dead_broker = self._start_broker(v, f"http://127.0.0.1:{dead_port}")
            d_host, d_port = dead_broker.server_address
            conn = http.client.HTTPConnection(d_host, d_port, timeout=5)
            conn.request("GET", "/v1/models")
            d_resp = conn.getresponse()
            d_resp.read()
            conn.close()
            self.assertEqual(d_resp.status, 502)

            # 7. Compressed request Content-Encoding (gzip / multi-coding) -> 415 Unsupported Media Type (upstream untouched)
            hits_before_415 = upstream_hits
            gz_payload = gzip.compress(b'{"prompt":"secret alice@example.com"}')
            for bad_ce in ("gzip", "gzip, identity"):
                conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
                conn.request(
                    "POST",
                    "/identity",
                    body=gz_payload,
                    headers={"Content-Type": "application/json", "Content-Encoding": bad_ce},
                )
                gz_resp = conn.getresponse()
                gz_resp.read()
                conn.close()
                self.assertEqual(gz_resp.status, 415)
            self.assertEqual(upstream_hits, hits_before_415)

            # Request with Content-Encoding: identity is allowed -> 200 OK
            conn = http.client.HTTPConnection(b_host, b_port, timeout=5)
            conn.request(
                "POST",
                "/identity",
                body=b'{"x":1}',
                headers={"Content-Type": "application/json", "Content-Encoding": "identity"},
            )
            id_req_resp = conn.getresponse()
            id_req_resp.read()
            conn.close()
            self.assertEqual(id_req_resp.status, 200)

            # 8. Multi-coding Transfer-Encoding (gzip, chunked) -> 400 Bad Request (upstream untouched)
            hits_before_te = upstream_hits
            gz_chunk = gzip.compress(b"secret alice@example.com")
            with socket.create_connection((b_host, b_port), timeout=5) as sock:
                raw_te_req = (
                    b"POST /identity HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Transfer-Encoding: gzip, chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    + f"{len(gz_chunk):x}\r\n".encode("ascii")
                    + gz_chunk
                    + b"\r\n0\r\n\r\n"
                )
                sock.sendall(raw_te_req)
                raw_te_resp = sock.recv(4096).decode("utf-8", "replace")
            self.assertTrue(raw_te_resp.startswith("HTTP/1.1 400 ") or raw_te_resp.startswith("HTTP/1.0 400 "))
            self.assertEqual(upstream_hits, hits_before_te)

    def test_cli_broker_serve_help_and_dispatch(self):
        command = [sys.executable, "-m", "prosze_cli"]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PACKAGE_DIR)

        help_res = subprocess.run(
            command + ["broker", "serve", "--help"],
            cwd=PACKAGE_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(help_res.returncode, 0)
        self.assertIn("--listen", help_res.stdout)
        self.assertIn("--upstream", help_res.stdout)
        self.assertIn("--allow-remote", help_res.stdout)
        self.assertIn("--ephemeral", help_res.stdout)

        err_buf = io.StringIO()
        with patch("sys.stderr", new=err_buf), patch("prosze_cli.broker.BrokerGateway.serve_forever") as mock_serve:
            cli_main([
                "broker", "serve",
                "--listen", "127.0.0.1:0",
                "--upstream", "http://127.0.0.1:9999",
                "--no-ner",
                "--ephemeral",
            ])
        mock_serve.assert_called_once()
        self.assertIn("prosze broker listening on http://127.0.0.1:", err_buf.getvalue())

        bad_err = io.StringIO()
        with patch("sys.stderr", new=bad_err), self.assertRaises(SystemExit) as cm:
            cli_main([
                "broker", "serve",
                "--listen", "0.0.0.0:8787",
                "--no-ner",
                "--ephemeral",
            ])
        self.assertNotEqual(cm.exception.code, 0)
        self.assertIn("refusing non-loopback listen host", bad_err.getvalue())


if __name__ == "__main__":
    unittest.main()
