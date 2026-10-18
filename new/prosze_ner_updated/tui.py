"""Prosze TUI — Hermes-Style Interactive Console with Continuous AI Connector & Zero-Leak Redaction.

Usage:
    prosze tui
    python tui.py
    python prosze_main.py tui

Features:
    • Authentic Hermes Terminal CUI styling & banner
    • Continuous multi-turn dialogue with memory across turns
    • Zero-leak privacy shield: prompts are redacted locally BEFORE reaching the API
    • Automatic on-the-fly de-redaction of streaming replies
    • Hermes auto-connect: reads auth.json and config.yaml from local Hermes install
    • Slash commands: /help, /clear, /model, /models, /vault, /system, /copy, /exit
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Module imports with self-contained fallback
# ---------------------------------------------------------------------------
try:
    from .prosze_proxy import Vault as _Vault
    from .hermes_connector import HermesConfig, ContinuousChatSession
except (ImportError, ValueError):
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
    from prosze_proxy import Vault as _Vault
    from hermes_connector import HermesConfig, ContinuousChatSession


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def build_common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--map", default=".prosze-map", help="Mapping file path (default: .prosze-map)")
    p.add_argument("--env", action="append", default=[], help="Load sensitive values from .env file")
    p.add_argument("--term", action="append", default=[], help="Specific term to hide (e.g. CUSTOMER=Acme)")
    p.add_argument("--terms", action="append", default=[], help="File with terms to hide")
    p.add_argument("--no-ner", action="store_true", help="Disable local GLiNER name detection")
    p.add_argument("--api-key", default=None, help="Explicit API key (Bearer / x-api-key)")
    p.add_argument("--api-base", default=None, help="Custom API base URL")
    p.add_argument("--api-model", default=None, help="Custom model ID (e.g. upstage/solar-mini4:free)")
    return p


def build_vault(a) -> _Vault:
    v = _Vault(a.map)
    if getattr(a, "no_ner", False):
        v._ner_attempted = True
    for p in getattr(a, "env", []):
        v.load_env(p)
    tf = list(getattr(a, "terms", []) or [])
    if os.path.exists(".prosze-terms"):
        tf.append(".prosze-terms")
    for p in tf:
        v.load_terms(p)
    for t in getattr(a, "term", []) or []:
        v.add_term(t)
    return v


# ---------------------------------------------------------------------------
# Clipboard Helper
# ---------------------------------------------------------------------------
def copy_to_clipboard(text: str) -> bool:
    try:
        import win32clipboard as w
        w.OpenClipboard()
        w.EmptyClipboard()
        w.SetClipboardText(text)
        w.CloseClipboard()
        return True
    except Exception:
        pass
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    return False


def terminal_is_interactive() -> bool:
    """Return whether the process has a terminal suitable for the CUI."""
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, OSError):
        return False


def _masked_vault_value(value: object) -> str:
    """Describe a vault value without displaying any part of the value."""
    return "<hidden>"


def _vault_lines(v: _Vault) -> list[str]:
    """Build a privacy-safe vault summary shared by both terminal UIs."""
    lines = ["VAULT MAP (.prosze-map)", "-" * 30]
    if not v.fwd:
        lines.append("(No active redacting terms yet)")
    else:
        for key, value in sorted(v.fwd.items()):
            lines.append(f"- {key}: {_masked_vault_value(value)}")
    lines.extend(("", f"Total mappings: {len(v.fwd)}"))
    ner_state = "Active" if not getattr(v, "_ner_attempted", False) or v.ner else "Regex only"
    lines.append(f"GLiNER: {ner_state}")
    return lines


# ---------------------------------------------------------------------------
# Hermes CUI Application
# ---------------------------------------------------------------------------
def run_hermes_tui(v: _Vault, config: Optional[HermesConfig] = None) -> None:
    if config is None:
        config = HermesConfig.load()

    if not terminal_is_interactive():
        run_hermes_cli_chat(v, config)
        return

    try:
        from prompt_toolkit import Application
        from prompt_toolkit.buffer import Buffer
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import Layout, Window, HSplit, VSplit
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout.dimension import Dimension, D
        from prompt_toolkit.styles import Style
        from prompt_toolkit.widgets import TextArea
        from prompt_toolkit.formatted_text import HTML
    except ImportError as exc:
        sys.stderr.write(
            f"prosze: Hermes TUI import error: {exc}\n"
            "    Install dependencies with: pip install prompt_toolkit requests\n"
        )
        sys.exit(1)

    session = ContinuousChatSession(config, v)

    # State tracking
    state = {
        "is_streaming": False,
        "status_msg": "Ready. Type a prompt or /help for commands.",
        "show_vault_panel": False,
        "last_ai_reply": "",
        "conversation_history_text": "",
        "last_redacted_info": "",
    }

    # Initial Welcome message in chat history
    ner_status = "Online (GLiNER)" if not v._ner_attempted or v.ner is not None else "Regex only"
    welcome_text = (
        f"⚡ <b>HERMES CONSOLE</b> connected to <b>{config.api_base}</b>\n"
        f"• Active Model: <b>{config.model}</b>\n"
        f"• Privacy Shield: <b>ACTIVE</b> (all prompts sanitized locally before sending)\n"
        f"• Shortcut Guide: <b>[Enter]</b> Send  <b>[Alt+Enter]</b> Newline  <b>[Ctrl+C]</b> Cancel  <b>[Ctrl+K]</b> Vault Map  <b>[Ctrl+L]</b> Clear\n"
        f"• Type <b>/help</b> for commands (/models, /clear, /vault, /model &lt;name&gt;)\n"
        f"{'─' * 76}\n\n"
    )

    welcome_text = (
        f"<b>  ____  ____   ___  ____  _____ _____</b>\n"
        f" <b>|  _ \\|  _ \\ / _ \\/ ___||__  /| ____|</b>\n"
        f" <b>| |_) | |_) | | | \\___ \\  / / |  _|</b>\n"
        f" <b>|____/|____/  \\___/|____//____||_____|</b>\n\n"
        f"<style fg='ansigreen'>[GLiNER {'Active' if not v._ner_attempted or v.ner else 'Regex only'}]</style>  "
        f"<style fg='ansiblue'>[ZERO-LEAK SHIELD ACTIVE]</style>  "
        f"<style fg='ansiyellow'>[VAULT: {len(v.fwd)} entities]</style>\n\n"
        f"<b>HERMES CONSOLE</b>  {config.api_base}\n"
        f"<b>Model:</b> {config.model}\n"
        f"Type a prompt below, or use <b>/help</b>, <b>/models</b>, <b>/vault</b>, <b>/copy</b>, <b>/exit</b>.\n"
        f"{'-' * 76}\n\n"
    )

    # Chat history display area
    chat_display = TextArea(
        text="",
        read_only=True,
        scrollbar=True,
        wrap_lines=True,
        style="class:chat-area",
    )
    chat_display.text = welcome_text

    # User input area
    prompt_input = TextArea(
        height=Dimension.exact(1),
        prompt="❯ ",
        wrap_lines=False,
        multiline=False,
        style="class:prompt-input",
    )

    # Vault Map Inspector sidebar/window
    vault_display = TextArea(
        text="",
        read_only=True,
        scrollbar=True,
        wrap_lines=True,
        width=Dimension(min=24, max=42, preferred=32),
        style="class:vault-panel",
    )

    def refresh_vault_display():
        vault_display.text = "\n".join(_vault_lines(v))

    refresh_vault_display()

    # Dynamic status bar
    def get_status_text():
        stream_indicator = "⚡ STREAMING..." if state["is_streaming"] else "● READY"
        return [
            ("class:status-badge", f" {stream_indicator} "),
            ("class:status-info", f" | Model: {config.model} | Terms: {len(v.fwd)} | {state['status_msg']} "),
        ]

    status_bar = Window(
        content=FormattedTextControl(get_status_text),
        height=1,
        style="class:status-bar",
    )

    # Dynamic Header Banner
    def get_header_text():
        return [
            ("class:header-title", "  o  o  o  "),
            ("class:header-sub", "> prosze-shield : session_01 (zsh)  "),
            ("class:header-meta", f"[SHIELD ACTIVE]  [{config.provider.upper()}]  {config.model} "),
        ]
        return [
            ("class:header-title", " HERMES "),
            ("class:header-sub", "× PROSZE PRIVACY SHIELD  "),
            ("class:header-meta", f"[{config.provider.upper()}] {config.api_base} │ {config.model} "),
        ]

    header_bar = Window(
        content=FormattedTextControl(get_header_text),
        height=1,
        style="class:header",
    )

    # Key bindings
    kb = KeyBindings()

    @kb.add("enter")
    def _handle_enter(event):
        """Submit message on Enter (unless empty)."""
        if state["is_streaming"]:
            return
        text = prompt_input.text.strip()
        if not text:
            return
        prompt_input.text = ""
        process_user_message(text)

    @kb.add("escape", "enter")
    @kb.add("c-j")
    def _handle_newline(event):
        """Insert newline on Alt+Enter / Ctrl+J."""
        prompt_input.buffer.insert_text("\n")

    @kb.add("c-c")
    def _handle_cancel(event):
        """Interrupt active stream or clear prompt."""
        if state["is_streaming"]:
            session.stop()
            state["status_msg"] = "Generation stopped by user."
            app.invalidate()
        else:
            prompt_input.text = ""

    @kb.add("c-k")
    def _toggle_vault(event):
        """Toggle Vault Inspector panel."""
        state["show_vault_panel"] = not state["show_vault_panel"]
        refresh_vault_display()
        app.layout = Layout(build_root())
        app.invalidate()

    @kb.add("c-l")
    def _handle_clear(event):
        """Clear conversation."""
        session.clear()
        chat_display.text = welcome_text
        state["status_msg"] = "Conversation cleared."
        app.invalidate()

    @kb.add("c-y")
    def _handle_copy_last(event):
        """Copy last assistant response."""
        if state["last_ai_reply"]:
            if copy_to_clipboard(state["last_ai_reply"]):
                state["status_msg"] = "Copied last reply to clipboard."
            else:
                state["status_msg"] = "Failed to access clipboard."
        else:
            state["status_msg"] = "No assistant reply to copy."
        app.invalidate()

    # Commands & Message Dispatcher
    def process_user_message(user_msg: str):
        # 1. Handle Slash Commands
        if user_msg.startswith("/"):
            parts = user_msg.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("/exit", "/quit", "/q"):
                app.exit()
                return
            elif cmd in ("/clear", "/reset"):
                session.clear()
                chat_display.text = welcome_text
                state["status_msg"] = "Conversation reset."
                app.invalidate()
                return
            elif cmd == "/help":
                help_text = (
                    "\n<b>⚡ HERMES AVAILABLE COMMANDS</b>\n"
                    "• <b>/model &lt;name&gt;</b> : Switch active model (e.g. /model upstage/solar-mini4:free)\n"
                    "• <b>/models</b>       : List available models from API endpoint\n"
                    "• <b>/clear</b>        : Reset dialogue memory and clear screen\n"
                    "• <b>/vault</b>        : Show current active redaction vault entries\n"
                    "• <b>/system &lt;text&gt;</b> : Change the system prompt\n"
                    "• <b>/copy</b>         : Copy the last AI response to clipboard\n"
                    "• <b>/quit</b>         : Exit Hermes console\n\n"
                )
                chat_display.text += help_text
                app.invalidate()
                return
            elif cmd == "/vault":
                state["show_vault_panel"] = True
                refresh_vault_display()
                app.layout = Layout(build_root())
                app.invalidate()
                return
            elif cmd == "/model":
                if arg:
                    config.model = arg
                    state["status_msg"] = f"Model switched to {arg}"
                    chat_display.text += f"\n<i>[System] Active model changed to: <b>{arg}</b></i>\n\n"
                else:
                    chat_display.text += f"\n<i>[System] Current model: <b>{config.model}</b></i>\n\n"
                app.invalidate()
                return
            elif cmd == "/models":
                state["status_msg"] = "Fetching available models..."
                app.invalidate()

                def _fetch_models():
                    ok, msg, mlist = config.test_connection()
                    if ok and mlist:
                        top = mlist[:15]
                        res = "\n<b>Available Models (first 15):</b>\n" + "\n".join(f"• {m}" for m in top)
                        if len(mlist) > 15:
                            res += f"\n<i>...and {len(mlist) - 15} more.</i>"
                        chat_display.text += res + "\n\n"
                    else:
                        chat_display.text += f"\n<i>[API Error] {msg}</i>\n\n"
                    state["status_msg"] = "Models updated."
                    app.invalidate()

                threading.Thread(target=_fetch_models, daemon=True).start()
                return
            elif cmd == "/system":
                if arg:
                    config.system_prompt = arg
                    chat_display.text += f"\n<i>[System] System prompt updated to: \"{arg}\"</i>\n\n"
                else:
                    chat_display.text += f"\n<i>[System] System prompt: \"{config.system_prompt}\"</i>\n\n"
                app.invalidate()
                return
            elif cmd == "/copy":
                _handle_copy_last(None)
                return
            elif cmd == "/redact":
                if not arg:
                    chat_display.text += "\n<style fg='ansiyellow'>Usage: /redact &lt;text&gt;</style>\n\n"
                else:
                    safe_text, hidden_count = v.redact(arg)
                    chat_display.text += (
                        f"\n<style fg='ansiyellow'>[LOCAL REDACTION] {hidden_count} item(s) hidden</style>\n"
                        f"{safe_text}\n\n"
                    )
                    refresh_vault_display()
                    state["status_msg"] = "Prompt redacted locally."
                app.invalidate()
                return
            else:
                chat_display.text += f"\n<i>[Error] Unknown command: {cmd}. Type /help for options.</i>\n\n"
                app.invalidate()
                return

        # 2. Regular Prompt Streaming
        if not config.api_key:
            safe_text, hidden_count = v.redact(user_msg)
            chat_display.text += (
                "\n<style fg='ansiyellow'>[OFFLINE MODE] No API key configured; nothing was sent.</style>\n"
                f"<style fg='ansigreen'>[LOCAL REDACTION] {hidden_count} item(s) hidden</style>\n"
                f"{safe_text}\n\n"
            )
            state["last_ai_reply"] = safe_text
            state["status_msg"] = "Offline mode: prompt redacted locally."
            refresh_vault_display()
            app.invalidate()
            return
        state["is_streaming"] = True
        state["status_msg"] = "Redacting prompt and streaming response..."

        # Append User Prompt to Chat Display
        time_str = time.strftime("%H:%M:%S")
        user_header = f"<b>❯ You</b>  <style fg='ansibrightblack'>[{time_str}]</style>\n"
        chat_display.text += f"{user_header}{user_msg}\n\n"

        assistant_header = f"<b>◆ Hermes</b>  <style fg='ansicyan'>({config.model})</style>\n"
        chat_display.text += assistant_header
        app.invalidate()

        def _streaming_worker():
            ai_reply_chunks = []
            try:
                for event in session.stream_chat(user_msg):
                    etype = event.get("type")
                    if etype == "redacted":
                        hidden_n = event.get("hidden_count", 0)
                        if hidden_n > 0:
                            shield_note = (
                                f"<style fg='ansiyellow'>  🛡️  [Privacy Shield] {hidden_n} item(s) sanitized "
                                f"before transmission (held in vault)</style>\n"
                            )
                            # Prepend badge before assistant reply
                            pos = chat_display.text.rfind(assistant_header)
                            if pos != -1:
                                chat_display.text = chat_display.text[:pos] + shield_note + "\n" + chat_display.text[pos:]
                            refresh_vault_display()
                            app.invalidate()
                    elif etype == "chunk":
                        chunk_text = event.get("text", "")
                        ai_reply_chunks.append(chunk_text)
                        chat_display.text += chunk_text
                        app.invalidate()
                    elif etype == "info":
                        chat_display.text += f"\n<i>[Notice] {event.get('message', '')}</i>\n"
                        state["status_msg"] = "Notice received."
                        app.invalidate()
                    elif etype == "error":
                        chat_display.text += f"\n<style fg='ansired'><b>[Error]</b> {event.get('message', '')}</style>\n"
                        state["status_msg"] = "Request failed. See the conversation for details."
                        app.invalidate()
                    elif etype == "cancelled":
                        chat_display.text += "\n<style fg='ansiyellow'><i>[Stream interrupted]</i></style>\n"
                        state["status_msg"] = "Generation stopped by user."
                        app.invalidate()
                    elif etype == "done":
                        state["last_ai_reply"] = "".join(ai_reply_chunks)
                        state["status_msg"] = "Reply finished. Ready for next prompt."
                        chat_display.text += "\n\n" + ("─" * 76) + "\n\n"
                        app.invalidate()
            except Exception as exc:
                chat_display.text += f"\n<style fg='ansired'>[Exception] {exc}</style>\n\n"
                state["status_msg"] = "Unexpected error. See the conversation for details."
            finally:
                state["is_streaming"] = False
                app.invalidate()

        threading.Thread(target=_streaming_worker, daemon=True).start()

    # Layout builder
    def build_root():
        chat_col = HSplit([
            chat_display,
            Window(height=1, char="─", style="class:sep"),
            prompt_input,
        ])

        if state["show_vault_panel"]:
            main_split = VSplit([
                chat_col,
                Window(width=1, char="│", style="class:sep"),
                vault_display,
            ])
        else:
            main_split = chat_col

        return HSplit([
            header_bar,
            Window(height=1, char="─", style="class:sep"),
            main_split,
            status_bar,
        ])

    # Hermes Dark Palette
    hermes_style = Style.from_dict({
        "header": "bg:#0f172a fg:#38bdf8 bold",
        "header-title": "bg:#0284c7 fg:#ffffff bold",
        "header-sub": "bg:#0f172a fg:#e2e8f0 bold",
        "header-meta": "bg:#0f172a fg:#94a3b8",
        "chat-area": "fg:#f8fafc bg:#0b0f17",
        "prompt-input": "fg:#38bdf8 bg:#111827",
        "vault-panel": "fg:#cbd5e1 bg:#0d1117",
        "status-bar": "bg:#1e293b fg:#94a3b8",
        "status-badge": "bg:#0284c7 fg:#ffffff bold",
        "status-info": "bg:#1e293b fg:#e2e8f0",
        "sep": "fg:#334155",
    })

    try:
        app = Application(
            layout=Layout(build_root(), focused_element=prompt_input),
            key_bindings=kb,
            style=hermes_style,
            full_screen=True,
            mouse_support=True,
            erase_when_done=True,
        )
        app.run()
    except Exception:
        # Fall back gracefully to streaming terminal chat mode if screen buffer isn't available
        run_hermes_cli_chat(v, config, session)


def run_hermes_cli_chat(v: _Vault, config: HermesConfig, session: Optional[ContinuousChatSession] = None) -> None:
    """Terminal chat fallback when running without a full terminal screen buffer."""
    if session is None:
        session = ContinuousChatSession(config, v)

    banner = (
        "\n"
        "┌──────────────────────────────────────────────────────────────────────────┐\n"
        "│  ⚡ HERMES × PROSZE  ──  Zero-Leak Autonomous Console                    │\n"
        f"│  Model: {config.model:<24} │  Endpoint: {config.provider.title():<20}   │\n"
        f"│  Privacy Shield: ACTIVE            │  Vault Terms: {len(v.fwd):<20} │\n"
        "└──────────────────────────────────────────────────────────────────────────┘\n"
        "Commands: /help, /models, /model <name>, /vault, /system <text>, /copy, /clear, /exit\n"
        "──────────────────────────────────────────────────────────────────────────\n"
    )
    banner = (
        "\n"
        "+------------------------------------------------------------------------------+\n"
        "|  o  o  o       > prosze-shield : session_01              [* SHIELD ACTIVE]  |\n"
        "+------------------------------------------------------------------------------+\n"
        "│  ____  ____   ___  ____  _____ _____        [GLiNER] [ZERO-LEAK] [VAULT: "
        f"{len(v.fwd)}] │\n"
        "| |  _ \\|  _ \\ / _ \\/ ___||__  /| ____|        "
        f"[MODEL: {config.model[:24]:<24}] │\n"
        "│ | |_) | |_) | | | \\___ \\  / / |  _|          "
        f"[UPSTREAM: {config.provider.title():<17}] |\n"
        "| |____/|____/  \\___/|____//____||_____|                                      |\n"
        "|                                                                              |\n"
        "|  Privacy shield is active. Prompts are sanitized locally before sending.    |\n"
        "|  Type a prompt below, or use /help, /models, /vault, /copy, /exit.          |\n"
        "+------------------------------------------------------------------------------+\n"
        "|  MODE: ZERO-LEAK INTERACTIVE        [Enter] Send   [Ctrl+C] Cancel           |\n"
        "+------------------------------------------------------------------------------+\n"
    )
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    print(banner, flush=True)

    while True:
        try:
            prompt = input("\n❯ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Hermes console.")
            break

        if not prompt:
            continue

        if prompt.startswith("/"):
            parts = prompt.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("/exit", "/quit", "/q"):
                print("Exiting Hermes console.")
                break
            elif cmd in ("/clear", "/reset"):
                session.clear()
                print("Conversation history cleared.", flush=True)
                continue
            elif cmd == "/help":
                print(
                    "\n⚡ HERMES COMMANDS:\n"
                    "  /model <name>  - Switch active model\n"
                    "  /models        - List available models from endpoint\n"
                    "  /vault         - Display active .prosze-map mappings\n"
                    "  /clear         - Reset conversation context\n"
                    "  /system <text> - Set custom system prompt\n"
                    "  /copy          - Copy the last AI response to clipboard\n"
                    "  /exit          - Quit console\n",
                    flush=True
                )
                continue
            elif cmd == "/vault":
                print("\n" + "\n".join(f"  {line}" for line in _vault_lines(v)))
                continue
            elif cmd == "/redact":
                if not arg:
                    print("Usage: /redact <text>", flush=True)
                else:
                    safe_text, hidden_count = v.redact(arg)
                    print(f"\n[LOCAL REDACTION] {hidden_count} item(s) hidden:\n{safe_text}\n", flush=True)
                continue
            elif cmd == "/model":
                if arg:
                    config.model = arg
                    print(f"Switched model to: {arg}", flush=True)
                else:
                    print(f"Current model: {config.model}", flush=True)
                continue
            elif cmd == "/models":
                print("Querying models from endpoint...", flush=True)
                ok, msg, mlist = config.test_connection()
                if ok and mlist:
                    print("\nAvailable models:")
                    for m in mlist[:12]:
                        print(f"  • {m}")
                    if len(mlist) > 12:
                        print(f"  ...and {len(mlist) - 12} more.")
                else:
                    print(f"Model query notice: {msg}")
                continue

            elif cmd == "/system":
                if arg:
                    config.system_prompt = arg
                    print("System prompt updated.", flush=True)
                else:
                    print("Current system prompt is configured.", flush=True)
                continue
            elif cmd == "/copy":
                turns = getattr(session, "turns", [])
                reply = turns[-1].raw_content if turns else ""
                if reply and copy_to_clipboard(reply):
                    print("Copied last reply to clipboard.", flush=True)
                else:
                    print("No reply copied (clipboard unavailable or no reply).", flush=True)
                continue
            else:
                print(f"Unknown command: {cmd}. Type /help for options.", flush=True)
                continue

        # Normal prompt: stream via session
        if not config.api_key:
            safe_text, hidden_count = v.redact(prompt)
            print(
                "\n[OFFLINE MODE] No API key configured; nothing was sent."
                f"\n[LOCAL REDACTION] {hidden_count} item(s) hidden:\n{safe_text}\n",
                flush=True,
            )
            continue
        print(f"\n◆ Hermes ({config.model}):", flush=True)
        try:
            for event in session.stream_chat(prompt):
                etype = event.get("type")
                if etype == "redacted":
                    hidden_n = event.get("hidden_count", 0)
                    if hidden_n > 0:
                        print(f"  [🛡️ Shield: {hidden_n} item(s) sanitized locally]", flush=True)
                elif etype == "chunk":
                    sys.stdout.write(event.get("text", ""))
                    sys.stdout.flush()
                elif etype == "info":
                    print(f"\n[Notice] {event.get('message', '')}", flush=True)
                elif etype == "error":
                    print(f"\n[Error] {event.get('message', '')}", flush=True)
            print("", flush=True)
        except KeyboardInterrupt:
            session.stop()
            print("\n[Generation interrupted]", flush=True)


def main(argv: Optional[list[str]] = None) -> None:
    argv = argv or sys.argv[1:]
    parser = build_common_parser()
    ap = argparse.ArgumentParser(prog="prosze-tui", parents=[parser], description="Hermes Interactive CUI for Prosze.")
    a, _ = ap.parse_known_args(argv)

    v = build_vault(a)
    cfg = HermesConfig.load(
        api_key=a.api_key,
        api_base=a.api_base,
        model=a.api_model,
    )
    run_hermes_tui(v, cfg)


if __name__ == "__main__":
    main()
