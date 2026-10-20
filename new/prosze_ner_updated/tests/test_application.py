import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from prosze_core import Vault, walk
from prosze_cli import cli_main


class ApplicationTests(unittest.TestCase):
    def make_vault(self, directory):
        vault = Vault(str(Path(directory) / "map.tsv"))
        vault._ner_attempted = True
        return vault

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


if __name__ == "__main__":
    unittest.main()
