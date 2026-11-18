"""Model Context Protocol (MCP) stdio privacy broker and interactive CLI wrapper.

Provides:
  - MCPBroker: bidirectional JSON-RPC 2.0 middleware (`prosze broker mcp`)
  - run_interactive_wrap: interactive CLI session wrapper (`prosze broker wrap`)
"""

from __future__ import annotations

import codecs
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from typing import Any, Callable, Optional

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from prosze_core import Vault, walk, _is_binary_stream, _write_stream_text  # noqa: E402
from prosze_cli.broker import StreamRestorer  # noqa: E402


_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_PEM_BLOCK_CAP = 65536


def _split_eol(raw_line: str) -> tuple[str, str]:
    if raw_line.endswith("\r\n"):
        return raw_line[:-2], "\r\n"
    if raw_line.endswith("\n"):
        return raw_line[:-1], "\n"
    return raw_line, ""


def _resolve_streams(in_stream: Any, out_stream: Any) -> tuple[Any, Any, bool]:
    resolved_in = getattr(sys.stdin, "buffer", sys.stdin) if in_stream is None else in_stream
    resolved_out = getattr(sys.stdout, "buffer", sys.stdout) if out_stream is None else out_stream
    return resolved_in, resolved_out, _is_binary_stream(resolved_out)


def _read_line_text(stream: Any) -> Optional[str]:
    raw = stream.readline()
    if not raw:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    return str(raw)


def _write_and_flush(stream: Any, text: str, binary_out: bool) -> None:
    if not text:
        return
    _write_stream_text(stream, text, binary_out)
    if hasattr(stream, "flush"):
        stream.flush()


def _close_quietly(stream: Any) -> None:
    try:
        stream.close()
    except (BrokenPipeError, OSError, ValueError):
        pass


def _spawn_piped_process(cmd: list[str]) -> subprocess.Popen:
    if not cmd:
        raise ValueError("prosze broker: empty command")
    resolved = shutil.which(cmd[0]) or cmd[0]
    return subprocess.Popen(
        [resolved, *cmd[1:]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=0,
    )


def _run_piped_session(
    cmd: list[str],
    in_stream: Any,
    out_stream: Any,
    stdin_worker: Callable[[Any, Any], None],
    stdout_worker: Callable[[Any, Any, bool], None],
) -> int:
    """Spawn a child command with unbuffered pipes and bridge stdin/stdout safely."""
    resolved_in, resolved_out, binary_out = _resolve_streams(in_stream, out_stream)
    with _spawn_piped_process(cmd) as proc:
        assert proc.stdin is not None and proc.stdout is not None
        in_thread = threading.Thread(
            target=stdin_worker,
            args=(resolved_in, proc.stdin),
            daemon=True,
        )
        in_thread.start()
        try:
            stdout_worker(proc.stdout, resolved_out, binary_out)
        except BaseException:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
            raise
        finally:
            if proc.poll() is None:
                proc.wait()
            in_thread.join(timeout=0.1)
    return proc.returncode if proc.returncode is not None else 0


def _transform_json_line(raw_line: str, mutate_msg: Callable[[dict[str, Any]], bool]) -> str:
    """Parse a JSON-RPC 2.0 single or batch message line and transform matching objects."""
    if not raw_line or not raw_line.strip():
        return raw_line
    body, eol = _split_eol(raw_line)
    try:
        parsed = json.loads(body)
    except ValueError:
        return raw_line

    if isinstance(parsed, dict):
        if not mutate_msg(parsed):
            return raw_line
        return json.dumps(parsed, ensure_ascii=False) + eol

    if isinstance(parsed, list):
        changed = False
        for item in parsed:
            if isinstance(item, dict) and mutate_msg(item):
                changed = True
        if not changed:
            return raw_line
        return json.dumps(parsed, ensure_ascii=False) + eol

    return raw_line


class MCPBroker:
    """Bidirectional JSON-RPC 2.0 privacy broker for MCP stdio transport."""

    def __init__(self, vault: Vault) -> None:
        self.vault = vault

    def _restore_obj(self, obj: Any) -> Any:
        lock = getattr(self.vault, "lock", None)
        if lock is not None:
            with lock:
                return walk(obj, self.vault.restore)
        return walk(obj, self.vault.restore)

    def _redact_obj(self, obj: Any) -> Any:
        return walk(obj, lambda s: self.vault.redact(s)[0])

    def process_client_message(self, raw_line: str) -> str:
        """Restore placeholders inside JSON-RPC 2.0 params from AI Host to MCP server."""

        def _restore_params(msg: dict[str, Any]) -> bool:
            if "params" not in msg:
                return False
            msg["params"] = self._restore_obj(msg["params"])
            return True

        return _transform_json_line(raw_line, _restore_params)

    def process_server_message(self, raw_line: str) -> str:
        """Redact raw secrets inside JSON-RPC 2.0 result, params, and error from MCP server."""

        def _redact_fields(msg: dict[str, Any]) -> bool:
            changed = False
            for key in ("result", "params", "error"):
                if key in msg:
                    msg[key] = self._redact_obj(msg[key])
                    changed = True
            return changed

        return _transform_json_line(raw_line, _redact_fields)

    def run_stdio_bridge(
        self,
        cmd: list[str],
        in_stream: Any = None,
        out_stream: Any = None,
    ) -> int:
        """Bridge AI Host stdio JSON-RPC messages with a local MCP server process."""

        def _bridge_stdin(resolved_in: Any, child_stdin: Any) -> None:
            try:
                while True:
                    line = _read_line_text(resolved_in)
                    if line is None:
                        break
                    out_line = self.process_client_message(line)
                    child_stdin.write(out_line.encode("utf-8"))
                    child_stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                _close_quietly(child_stdin)

        def _bridge_stdout(child_stdout: Any, resolved_out: Any, binary_out: bool) -> None:
            while True:
                line = _read_line_text(child_stdout)
                if line is None:
                    break
                out_line = self.process_server_message(line)
                _write_and_flush(resolved_out, out_line, binary_out)

        return _run_piped_session(cmd, in_stream, out_stream, _bridge_stdin, _bridge_stdout)


def run_interactive_wrap(
    vault: Vault,
    cmd: list[str],
    in_stream: Any = None,
    out_stream: Any = None,
) -> int:
    """Wrap an interactive CLI session with input redaction and strict stream restoration."""
    lock = getattr(vault, "lock", None)
    if lock is not None:
        with lock:
            vault.strict_restore = True
    else:
        vault.strict_restore = True

    restorer = StreamRestorer(vault)

    def _wrap_stdin(resolved_in: Any, child_stdin: Any) -> None:
        pending_pem: list[str] = []
        pending_len = 0

        def _flush_redacted(raw_text: str) -> None:
            safe, _ = vault.redact(raw_text)
            child_stdin.write(safe.encode("utf-8"))
            child_stdin.flush()

        try:
            while True:
                line = _read_line_text(resolved_in)
                if line is None:
                    if pending_pem:
                        _flush_redacted("".join(pending_pem))
                        pending_pem.clear()
                    break

                if pending_pem:
                    pending_pem.append(line)
                    pending_len += len(line)
                    if _PEM_END_RE.search(line) or pending_len >= _PEM_BLOCK_CAP:
                        _flush_redacted("".join(pending_pem))
                        pending_pem.clear()
                        pending_len = 0
                    continue

                if _PEM_BEGIN_RE.search(line) and not _PEM_END_RE.search(line):
                    pending_pem.append(line)
                    pending_len = len(line)
                    continue

                _flush_redacted(line)
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            _close_quietly(child_stdin)

    def _wrap_stdout(child_stdout: Any, resolved_out: Any, binary_out: bool) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        read_chunk = getattr(child_stdout, "read1", child_stdout.read)

        def _emit_decoded(text: str) -> None:
            if not text:
                return
            restored = restorer.feed(text)
            if restored:
                _write_and_flush(resolved_out, restored, binary_out)

        while True:
            raw = read_chunk(4096)
            if not raw:
                break
            _emit_decoded(decoder.decode(raw, final=False))
        _emit_decoded(decoder.decode(b"", final=True))
        final_tail = restorer.flush()
        if final_tail:
            _write_and_flush(resolved_out, final_tail, binary_out)
        elif hasattr(resolved_out, "flush"):
            resolved_out.flush()

    return _run_piped_session(cmd, in_stream, out_stream, _wrap_stdin, _wrap_stdout)
