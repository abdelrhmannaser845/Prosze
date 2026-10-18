import io
import sys
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch


PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

import tui


class TuiTests(unittest.TestCase):
    def setUp(self):
        self.vault = SimpleNamespace(
            fwd={"[[PERSON_1]]": "Ada Lovelace"},
            _ner_attempted=True,
            ner=None,
        )
        self.config = SimpleNamespace(
            model="test-model",
            provider="local",
            system_prompt="",
            test_connection=lambda: (False, "offline", []),
        )
        self.session = SimpleNamespace(turns=[], clear=lambda: None, stop=lambda: None)

    def test_vault_summary_hides_value_and_metadata(self):
        summary = "\n".join(tui._vault_lines(self.vault))

        self.assertIn("[[PERSON_1]]", summary)
        self.assertIn("<hidden>", summary)
        self.assertNotIn("Ada Lovelace", summary)
        self.assertNotIn("chars", summary)

    def test_non_interactive_tui_uses_cli_fallback(self):
        with patch.object(tui, "terminal_is_interactive", return_value=False), patch.object(
            tui, "run_hermes_cli_chat"
        ) as fallback:
            tui.run_hermes_tui(self.vault, self.config)

        fallback.assert_called_once_with(self.vault, self.config)

    def test_fallback_documents_copy_and_keeps_vault_safe(self):
        output = io.StringIO()
        commands = iter(["/help", "/copy", "/vault", "/exit"])
        with patch("builtins.input", side_effect=lambda _prompt="": next(commands)), patch(
            "sys.stdout", output
        ):
            tui.run_hermes_cli_chat(self.vault, self.config, self.session)

        text = output.getvalue()
        self.assertIn("/copy", text)
        self.assertIn("No reply copied", text)
        self.assertIn("<hidden>", text)
        self.assertNotIn("Ada Lovelace", text)


if __name__ == "__main__":
    unittest.main()
