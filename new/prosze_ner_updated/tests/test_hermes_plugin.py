import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from prosze_proxy import Vault
import prosze_plugin


class MockHermesContext:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.commands = {}

    def register_tool(self, name: str, toolset: str, schema: dict, handler):
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
        }

    def register_hook(self, name: str, callback):
        self.hooks.setdefault(name, []).append(callback)

    def register_command(self, name: str, description: str, handler):
        self.commands[name] = {
            "description": description,
            "handler": handler,
        }


class HermesPluginTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.map_file = Path(self.temp_dir.name) / "test_map.tsv"
        self.vault = Vault(str(self.map_file))
        self.vault._ner_attempted = True
        prosze_plugin.set_vault(self.vault)

    def tearDown(self):
        prosze_plugin.set_vault(None)
        self.temp_dir.cleanup()

    def test_plugin_registration(self):
        ctx = MockHermesContext()
        prosze_plugin.register(ctx)

        # 6 registered tools
        expected_tools = {
            "prosze_redact",
            "prosze_restore",
            "prosze_check",
            "prosze_add_term",
            "prosze_vault_status",
            "prosze_clear_vault",
        }
        self.assertEqual(set(ctx.tools.keys()), expected_tools)
        for tname in expected_tools:
            self.assertEqual(ctx.tools[tname]["toolset"], "prosze")
            self.assertIn("parameters", ctx.tools[tname]["schema"])
            self.assertTrue(callable(ctx.tools[tname]["handler"]))

        # 4 lifecycle hooks
        expected_hooks = {
            "pre_api_request",
            "post_api_request",
            "pre_tool_call",
            "post_tool_call",
        }
        self.assertEqual(set(ctx.hooks.keys()), expected_hooks)

        # 1 slash command
        self.assertIn("prosze", ctx.commands)

    def test_tool_redact_and_restore(self):
        self.vault.add_term("PROJECT=ProjectX")

        # Redact
        raw_redact = prosze_plugin.handle_prosze_redact({
            "text": "The confidential code is ProjectX."
        })
        res_redact = json.loads(raw_redact)
        self.assertTrue(res_redact["success"])
        self.assertEqual(res_redact["hidden_count"], 1)
        self.assertTrue(res_redact["has_sensitive_data"])
        self.assertIn("[[PROJECT_1]]", res_redact["redacted_text"])
        self.assertNotIn("ProjectX", res_redact["redacted_text"])

        # Restore
        raw_restore = prosze_plugin.handle_prosze_restore({
            "text": res_redact["redacted_text"]
        })
        res_restore = json.loads(raw_restore)
        self.assertTrue(res_restore["success"])
        self.assertEqual(res_restore["restored_text"], "The confidential code is ProjectX.")

    def test_tool_check(self):
        self.vault.add_term("SECRET=TopSecretVal")

        # Clean text
        raw_clean = prosze_plugin.handle_prosze_check({"text": "Hello world, nothing here."})
        res_clean = json.loads(raw_clean)
        self.assertFalse(res_clean["has_sensitive_data"])
        self.assertEqual(res_clean["sensitive_count"], 0)

        # Sensitive text
        raw_sens = prosze_plugin.handle_prosze_check({"text": "Review TopSecretVal immediately."})
        res_sens = json.loads(raw_sens)
        self.assertTrue(res_sens["has_sensitive_data"])
        self.assertEqual(res_sens["sensitive_count"], 1)

    def test_tool_add_term(self):
        raw_add = prosze_plugin.handle_prosze_add_term({"term": "ORG=AcmeCorp"})
        res_add = json.loads(raw_add)
        self.assertTrue(res_add["success"])

        # Verify added term is now protected
        raw_redact = prosze_plugin.handle_prosze_redact({"text": "Welcome to AcmeCorp HQ."})
        res_redact = json.loads(raw_redact)
        self.assertIn("[[ORG_1]]", res_redact["redacted_text"])
        self.assertNotIn("AcmeCorp", res_redact["redacted_text"])

    def test_tool_vault_status_and_clear(self):
        self.vault.add_term("KEY=my_custom_secret_key_999")
        self.vault.redact("Use my_custom_secret_key_999 here.")

        raw_status = prosze_plugin.handle_prosze_vault_status()
        res_status = json.loads(raw_status)
        self.assertTrue(res_status["success"])
        self.assertEqual(res_status["active_mappings_count"], 1)
        self.assertIn("KEY", res_status["labels_breakdown"])
        # Ensure raw secret is NOT leaked in status
        self.assertNotIn("my_custom_secret_key_999", raw_status)

        # Clear vault
        raw_clear = prosze_plugin.handle_prosze_clear_vault()
        res_clear = json.loads(raw_clear)
        self.assertTrue(res_clear["success"])

        raw_status_after = prosze_plugin.handle_prosze_vault_status()
        res_status_after = json.loads(raw_status_after)
        self.assertEqual(res_status_after["active_mappings_count"], 0)

    def test_pre_api_request_hook_redacts_messages_and_payload(self):
        self.vault.add_term("API_KEY=my_secret_api_key_443")

        # Test with messages list
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My token is my_secret_api_key_443."},
        ]
        prosze_plugin.hook_pre_api_request(messages=messages)
        self.assertNotIn("my_secret_api_key_443", messages[1]["content"])
        self.assertIn("[[API_KEY_1]]", messages[1]["content"])

        # Test with payload dict
        payload = {
            "model": "nous/hermes-3",
            "messages": [{"role": "user", "content": "Another my_secret_api_key_443 query"}],
        }
        prosze_plugin.hook_pre_api_request(payload=payload)
        self.assertNotIn("my_secret_api_key_443", payload["messages"][0]["content"])
        self.assertIn("[[API_KEY_1]]", payload["messages"][0]["content"])

    def test_post_api_request_hook_restores_response(self):
        self.vault.add_term("API_KEY=my_secret_api_key_443")
        safe, _ = self.vault.redact("Token is my_secret_api_key_443")

        # Response string
        restored_str = prosze_plugin.hook_post_api_request(response=f"The answer uses {safe}.")
        self.assertIn("my_secret_api_key_443", restored_str)
        self.assertNotIn("[[API_KEY_1]]", restored_str)

        # Response dict
        resp_dict = {
            "choices": [
                {"message": {"content": f"Confirmed {safe}."}}
            ]
        }
        prosze_plugin.hook_post_api_request(response=resp_dict)
        self.assertIn("my_secret_api_key_443", resp_dict["choices"][0]["message"]["content"])

    def test_tool_call_hooks(self):
        self.vault.add_term("SERVER=prod-db.internal.net")
        safe, _ = self.vault.redact("Host prod-db.internal.net")

        # Pre-tool call should not crash
        prosze_plugin.hook_pre_tool_call(
            tool_name="bash",
            params={"command": "ping prod-db.internal.net"},
        )

        # Post-tool call restores output
        restored = prosze_plugin.hook_post_tool_call(
            tool_name="bash",
            params={"command": "echo"},
            result=f"Connected to {safe} ok",
        )
        self.assertIn("prod-db.internal.net", restored)

    def test_slash_command(self):
        output = prosze_plugin.handle_prosze_command()
        self.assertIn("[Prosze Privacy Shield]", output)
        self.assertIn("Active protected mappings", output)


if __name__ == "__main__":
    unittest.main()
