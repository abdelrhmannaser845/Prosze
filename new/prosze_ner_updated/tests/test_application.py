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


if __name__ == "__main__":
    unittest.main()
