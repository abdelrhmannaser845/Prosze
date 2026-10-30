import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch


PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from prosze_core import Vault, walk
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


if __name__ == "__main__":
    unittest.main()
