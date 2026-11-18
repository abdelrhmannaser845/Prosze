"""Cloakroom Ticket interactive terminal UI (`prosze tui`)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Callable, Optional

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from prosze_core import (  # noqa: E402
    ANSI_PERFORATION,
    ANSI_PINE_MINT,
    ANSI_RESET,
    ANSI_SLATE,
    Vault,
    _is_binary_stream,
    _write_stream_text,
    highlight_tickets,
    should_use_color,
)


TUI_BANNER = "prosze — Keep what's yours. Nothing leaves until it has a ticket."
TUI_DIVIDER = "- - - - - - - - - - - -"


def _read_line(stream: Any) -> Optional[str]:
    try:
        raw = stream.readline()
    except (EOFError, OSError, ValueError):
        return None
    if not raw:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    return str(raw)


def _copy_to_clipboard(
    text: str,
    clipboard_fn: Optional[Callable[[str], Any]] = None,
) -> tuple[bool, str]:
    if clipboard_fn is not None:
        try:
            res = clipboard_fn(text)
        except Exception as exc:
            return False, f"Clipboard unavailable ({exc})."
        if res is False:
            return False, "Clipboard unavailable; please copy the text above directly."
        return True, "Copied latest output to clipboard."

    candidates: list[list[str]] = []
    if sys.platform == "darwin":
        candidates.append(["pbcopy"])
    elif os.name == "nt":
        candidates.append(["clip"])
    else:
        candidates.extend([
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
            ["wl-copy"],
            ["pbcopy"],
            ["clip"],
        ])

    for cmd in candidates:
        exe = shutil.which(cmd[0])
        if not exe:
            continue
        try:
            subprocess.run(
                [exe, *cmd[1:]],
                input=text.encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return True, "Copied latest output to clipboard."
        except (OSError, subprocess.SubprocessError):
            continue

    return False, "Clipboard tool unavailable (tried clip/pbcopy/xclip); copy the text above directly."


def run_tui(
    vault: Vault,
    in_stream: Any = None,
    out_stream: Any = None,
    color_mode: str = "auto",
    clipboard_fn: Optional[Callable[[str], Any]] = None,
) -> int:
    """Run the Cloakroom Ticket interactive TUI session."""
    resolved_in = getattr(sys.stdin, "buffer", sys.stdin) if in_stream is None else in_stream
    resolved_out = getattr(sys.stdout, "buffer", sys.stdout) if out_stream is None else out_stream
    binary_out = _is_binary_stream(resolved_out)
    use_color = should_use_color(color_mode, resolved_out)

    in_isatty = getattr(resolved_in, "isatty", None)
    try:
        interactive = bool(in_isatty and in_isatty())
    except Exception:
        interactive = False

    def emit(text: str) -> None:
        if not text:
            return
        _write_stream_text(resolved_out, text, binary_out)
        if hasattr(resolved_out, "flush"):
            resolved_out.flush()

    def style_banner() -> str:
        return f"{ANSI_PINE_MINT}{TUI_BANNER}{ANSI_RESET}" if use_color else TUI_BANNER

    def style_divider() -> str:
        return f"{ANSI_PERFORATION}{TUI_DIVIDER}{ANSI_RESET}" if use_color else TUI_DIVIDER

    def style_note(msg: str) -> str:
        return f"{ANSI_SLATE}{msg}{ANSI_RESET}" if use_color else msg

    def style_prompt() -> str:
        return f"{ANSI_PINE_MINT}prosze>{ANSI_RESET} " if use_color else "prosze> "

    emit(f"{style_banner()}\n")
    emit(f"{style_divider()}\n")
    emit(style_note("Enter text to redact, paste [[TICKET_N]] to restore, or type /help.\n"))

    last_output: Optional[str] = None

    while True:
        if interactive:
            emit(style_prompt())
        try:
            raw_line = _read_line(resolved_in)
        except KeyboardInterrupt:
            emit("\nHere you go. Cloakroom closed.\n")
            return 0
        if raw_line is None:
            if interactive:
                emit("\n")
            return 0

        line = raw_line.rstrip("\r\n")
        trimmed = line.strip()
        if not trimmed:
            continue

        if trimmed.startswith("/"):
            parts = trimmed.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "/help":
                emit(
                    "Commands:\n"
                    "  /help   List commands\n"
                    "  /vault  Show active tickets ([[CAT_N]] -> <hidden>)\n"
                    "  /copy   Copy the latest redacted or restored text to clipboard\n"
                    "  /clear  Clear the last buffered output\n"
                    "  /quit   Exit the cloakroom session (alias: /exit)\n"
                )
                emit(f"{style_divider()}\n")
            elif cmd == "/vault":
                lock = getattr(vault, "lock", None)
                if lock is not None:
                    with lock:
                        tickets = list(vault.fwd.keys())
                else:
                    tickets = list(vault.fwd.keys())
                if not tickets:
                    emit(style_note("Vault is empty — no active tickets.\n"))
                else:
                    for ticket in tickets:
                        disp = highlight_tickets(ticket) if use_color else ticket
                        emit(f"{disp} -> <hidden>\n")
                emit(f"{style_divider()}\n")
            elif cmd == "/copy":
                if last_output is None:
                    emit(style_note("Nothing to copy yet — enter text first.\n"))
                else:
                    _, msg = _copy_to_clipboard(last_output, clipboard_fn)
                    emit(f"{msg}\n")
                emit(f"{style_divider()}\n")
            elif cmd == "/clear":
                last_output = None
                emit("Cleared buffered output.\n")
                emit(f"{style_divider()}\n")
            elif cmd in ("/quit", "/exit"):
                emit("Here you go. Cloakroom closed.\n")
                return 0
            elif cmd == "/restore":
                if not arg:
                    emit("Usage: /restore <text with [[TICKET_N]]>\n")
                else:
                    restored = vault.restore(arg)
                    last_output = restored
                    emit(f"{restored}\n")
                    emit(f"{style_divider()}\n")
            elif cmd == "/redact":
                if not arg:
                    emit("Usage: /redact <text>\n")
                else:
                    safe, n = vault.redact(arg)
                    last_output = safe
                    display = highlight_tickets(safe) if use_color else safe
                    emit(f"{display}\n")
                    emit(style_note(f"prosze: {n} item(s) hidden\n"))
                    emit(f"{style_divider()}\n")
            else:
                emit(f"Unknown command: {cmd}. Type /help for commands.\n")
            continue

        safe, n = vault.redact(line)
        if n == 0 and "[[" in line:
            restored = vault.restore(line)
            if restored != line:
                last_output = restored
                emit("Restored:\n")
                emit(f"{restored}\n")
                emit(f"{style_divider()}\n")
                continue

        last_output = safe
        display = highlight_tickets(safe) if use_color else safe
        emit(f"{display}\n")
        emit(style_note(f"prosze: {n} item(s) hidden\n"))
        emit(f"{style_divider()}\n")
