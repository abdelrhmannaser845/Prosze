"""Local loopback HTTP/SSE privacy gateway (`prosze broker serve`).

Provides:
  - StreamRestorer: chunk-boundary placeholder reassembler and restorer
  - SSERestorer: stateful SSE (text/event-stream) placeholder restorer
  - BrokerGateway / create_broker_server: loopback ThreadingHTTPServer proxy
"""

from __future__ import annotations

import codecs
from collections import deque
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from typing import Any, Optional

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

import prosze_core  # noqa: E402


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_LISTEN = f"{DEFAULT_HOST}:{DEFAULT_PORT}"
DEFAULT_UPSTREAM = "https://api.openai.com"
MAX_REQUEST_BYTES = 16 * 1024 * 1024  # 16 MiB
MAX_HISTORY_ENTRIES = 100

_PARTIAL_PREFIX_RE = re.compile(r"(?:\[\[(?=[A-Z0-9_\]]{0,60}$)[A-Z0-9_]*\]?|\[)$")

_STREAM_TEXT_KEYS = frozenset({
    "content",
    "text",
    "delta",
    "arguments",
    "partial_json",
    "thinking",
    "reasoning",
    "reasoning_content",
    "output_text",
    "response",
    "chunk",
    "message",
})

_SSE_SKIP_KEYS = prosze_core.SKIP_KEYS | frozenset({
    "finish_reason",
    "stop_sequence",
    "service_tier",
    "system_fingerprint",
})

_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
})


def is_loopback_host(host: str) -> bool:
    """Return True if host resolves syntactically to a loopback address."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        return False
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def parse_listen_addr(spec: str, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """Parse a host:port listen address (supporting IPv6 brackets) into (host, port)."""
    s = (spec or "").strip()
    if not s:
        raise ValueError("prosze broker: empty listen address")

    if s.startswith("["):
        end_bracket = s.find("]")
        if end_bracket == -1:
            raise ValueError(f"prosze broker: invalid listen address {spec!r}")
        host = s[1:end_bracket]
        rest = s[end_bracket + 1:]
        if not rest:
            port = default_port
        elif rest.startswith(":"):
            port_str = rest[1:]
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError(f"prosze broker: invalid port in {spec!r}") from exc
        else:
            raise ValueError(f"prosze broker: invalid listen address {spec!r}")
    elif s.count(":") == 1:
        host, port_str = s.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError as exc:
            raise ValueError(f"prosze broker: invalid port in {spec!r}") from exc
    else:
        host = s
        port = default_port

    if not (0 <= port <= 65535):
        raise ValueError(f"prosze broker: port out of range in {spec!r}")
    return host, port


def validate_upstream_url(url: str) -> urllib.parse.SplitResult:
    """Validate that upstream URL is http:// or https:// with a valid hostname."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("prosze broker: empty upstream URL")
    if any(ch.isspace() for ch in url):
        raise ValueError(f"prosze broker: upstream URL contains whitespace: {url!r}")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"prosze broker: upstream scheme must be http or https, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError(f"prosze broker: upstream URL missing hostname: {url!r}")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"prosze broker: invalid upstream port in {url!r}") from exc
    return parsed


def _restore_locked(vault: prosze_core.Vault, text: str, json_escaped: bool = False) -> str:
    lock = getattr(vault, "lock", None)
    if lock is not None:
        with lock:
            return vault.restore(text, json_escaped=json_escaped)
    return vault.restore(text, json_escaped=json_escaped)


def _make_chan_key(path: tuple[Any, ...], top_index: Any) -> tuple[Any, ...]:
    if top_index is not None and path[:1] != (("idx", top_index),):
        return ("root", top_index) + path
    return path


class StreamRestorer:
    """Hold back partial trailing placeholder prefixes across chunk boundaries."""

    def __init__(self, vault: prosze_core.Vault, json_escaped: bool = False) -> None:
        self.vault = vault
        self.json_escaped = json_escaped
        self._buf = ""

    def has_pending(self) -> bool:
        """Return True if partial placeholder characters are currently buffered."""
        return bool(self._buf)

    def feed(self, chunk: str) -> str:
        """Consume a chunk and return any safely completable restored prefix."""
        if not chunk:
            return ""
        self._buf += chunk
        m = _PARTIAL_PREFIX_RE.search(self._buf)
        cut = m.start() if m is not None else len(self._buf)
        if cut <= 0:
            return ""
        emit = self._buf[:cut]
        self._buf = self._buf[cut:]
        return _restore_locked(self.vault, emit, json_escaped=self.json_escaped)

    def flush(self) -> str:
        """Restore and emit any remaining buffered tail at end of stream."""
        if not self._buf:
            return ""
        tail = self._buf
        self._buf = ""
        return _restore_locked(self.vault, tail, json_escaped=self.json_escaped)


class SSERestorer:
    """Stateful Server-Sent Events (text/event-stream) placeholder restorer."""

    def __init__(self, vault: prosze_core.Vault) -> None:
        self.vault = vault
        self._raw_buf = ""
        self._pending_lines: list[str] = []
        self._pending_eol = "\n"
        self._text_restorer = StreamRestorer(vault, json_escaped=False)
        self._json_restorers: dict[tuple[Any, ...], StreamRestorer] = {}
        self._json_templates: dict[tuple[Any, ...], dict[str, Any]] = {}

    def feed(self, chunk: str) -> str:
        """Feed an SSE text chunk and return restored complete SSE lines/events."""
        if not chunk:
            return ""
        self._raw_buf += chunk
        out: list[str] = []

        while True:
            nl = self._raw_buf.find("\n")
            if nl == -1:
                break
            raw_line = self._raw_buf[:nl]
            self._raw_buf = self._raw_buf[nl + 1:]
            if raw_line.endswith("\r"):
                line = raw_line[:-1]
                eol = "\r\n"
            else:
                line = raw_line
                eol = "\n"

            if line == "":
                if self._pending_lines:
                    out.append(self._process_event(self._pending_lines, self._pending_eol, eol))
                    self._pending_lines = []
                else:
                    out.append(eol)
            elif line.startswith(":") and not self._pending_lines:
                out.append(line + eol)
            else:
                if not self._pending_lines:
                    self._pending_eol = eol
                self._pending_lines.append(line)

        return "".join(out)

    def flush(self) -> str:
        """Flush any buffered incomplete SSE event and held placeholder tails."""
        out: list[str] = []
        if self._raw_buf:
            tail_line = self._raw_buf[:-1] if self._raw_buf.endswith("\r") else self._raw_buf
            self._raw_buf = ""
            if tail_line.startswith(":") and not self._pending_lines:
                out.append(tail_line + self._pending_eol)
            elif tail_line != "":
                self._pending_lines.append(tail_line)

        if self._pending_lines:
            out.append(self._process_event(self._pending_lines, self._pending_eol, self._pending_eol))
            self._pending_lines = []

        flushed = self._flush_pending_restorers(self._pending_eol)
        if flushed:
            out.append(flushed)
        return "".join(out)

    def _flush_pending_restorers(self, eol: str) -> str:
        out: list[str] = []
        if self._text_restorer.has_pending():
            tail = self._text_restorer.flush()
            if tail:
                data_block = eol.join(f"data: {part}" for part in tail.split("\n"))
                out.append(data_block + eol + eol)

        for chan_key, restorer in list(self._json_restorers.items()):
            if not restorer.has_pending():
                continue
            tail = restorer.flush()
            if not tail:
                continue
            envelope = self._build_flush_envelope(chan_key, tail)
            out.append(f"data: {json.dumps(envelope, ensure_ascii=False)}{eol}{eol}")

        return "".join(out)

    def _build_flush_envelope(self, chan_key: tuple[Any, ...], tail: str) -> dict[str, Any]:
        tmpl = self._json_templates.get(chan_key, {})
        meta = dict(tmpl.get("meta", {}))
        path = tmpl.get("path", chan_key)

        node: Any = tail
        for seg in reversed(path):
            if isinstance(seg, tuple) and len(seg) == 2 and seg[0] == "idx":
                item = dict(node) if isinstance(node, dict) else {}
                item["index"] = seg[1]
                node = [item]
            elif isinstance(seg, int):
                node = [node]
            else:
                node = {str(seg): node}

        if isinstance(node, dict):
            merged = dict(meta)
            merged.update(node)
            return merged
        return {"text": tail}

    def _process_event(self, lines: list[str], eol: str, end_eol: str) -> str:
        data_parts: list[str] = []
        header_lines: list[str] = []
        for line in lines:
            if line.startswith("data:"):
                val = line[5:]
                if val.startswith(" "):
                    val = val[1:]
                data_parts.append(val)
            else:
                header_lines.append(line)

        if not data_parts:
            return eol.join(lines) + eol + end_eol

        payload = "\n".join(data_parts)
        if payload == "[DONE]":
            prefix = self._flush_pending_restorers(eol)
            return prefix + eol.join(lines) + eol + end_eol

        stripped = payload.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(payload)
            except ValueError:
                parsed = None
            if parsed is not None:
                root_meta = self._extract_envelope_meta(parsed)
                top_index = parsed.get("index") if isinstance(parsed, dict) and "index" in parsed else None
                updated = self._walk_sse_json(parsed, (), top_index, root_meta)
                serialized = json.dumps(updated, ensure_ascii=False)
                out_lines = list(header_lines)
                out_lines.append(f"data: {serialized}")
                return eol.join(out_lines) + eol + end_eol

        restored = self._text_restorer.feed(payload)
        out_lines = list(header_lines)
        for part in restored.split("\n"):
            out_lines.append(f"data: {part}")
        return eol.join(out_lines) + eol + end_eol

    @staticmethod
    def _extract_envelope_meta(obj: Any) -> dict[str, Any]:
        if not isinstance(obj, dict):
            return {}
        meta: dict[str, Any] = {}
        for k in ("id", "object", "model", "type", "index"):
            if k in obj:
                meta[k] = obj[k]
        return meta

    def _walk_sse_json(
        self,
        obj: Any,
        path: tuple[Any, ...],
        top_index: Any,
        root_meta: dict[str, Any],
        key_name: Optional[str] = None,
    ) -> Any:
        if isinstance(obj, str):
            if obj.startswith("data:"):
                return obj
            if key_name in _STREAM_TEXT_KEYS:
                chan_key = _make_chan_key(path, top_index)
                restorer = self._json_restorers.get(chan_key)
                if restorer is None:
                    restorer = StreamRestorer(self.vault, json_escaped=False)
                    self._json_restorers[chan_key] = restorer
                self._json_templates[chan_key] = {"meta": root_meta, "path": path}
                return restorer.feed(obj)
            return _restore_locked(self.vault, obj)

        if isinstance(obj, list):
            out_list = []
            for idx, item in enumerate(obj):
                if isinstance(item, dict) and "index" in item:
                    seg: Any = ("idx", item["index"])
                else:
                    seg = idx
                out_list.append(self._walk_sse_json(item, path + (seg,), top_index, root_meta, key_name))
            return out_list

        if isinstance(obj, dict):
            b64 = obj.get("type") == "base64"
            out_dict: dict[str, Any] = {}
            for k, v in obj.items():
                if k in _SSE_SKIP_KEYS or (b64 and k == "data"):
                    out_dict[k] = v
                else:
                    out_dict[k] = self._walk_sse_json(v, path + (k,), top_index, root_meta, k)

            # Flush buffered choice delta text when OpenAI signals finish_reason with empty delta
            if obj.get("finish_reason") is not None and isinstance(out_dict.get("delta"), dict):
                delta_dict = out_dict["delta"]
                content_chan = _make_chan_key(path + ("delta", "content"), top_index)
                restorer = self._json_restorers.get(content_chan)
                if restorer is not None and restorer.has_pending() and not delta_dict.get("content"):
                    delta_dict["content"] = restorer.flush()
            return out_dict

        return obj


def _is_json_content_type(mime: str) -> bool:
    return mime == "application/json" or mime == "text/json" or mime.endswith("+json")


def _is_text_content_type(mime: str) -> bool:
    if mime.startswith("text/") and mime != "text/event-stream":
        return True
    if mime in {
        "application/x-www-form-urlencoded",
        "application/xml",
        "application/javascript",
        "application/problem+xml",
    }:
        return True
    return mime.endswith("+xml")


def _is_utf8_printable_or_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _connection_tokens(headers) -> set[str]:
    tokens: set[str] = set()
    for val in headers.get_all("Connection") or []:
        for tok in val.split(","):
            name = tok.strip().lower()
            if name:
                tokens.add(name)
    return tokens


def has_compressed_encoding(headers: Any) -> bool:
    """Return True if any Content-Encoding header specifies a non-identity coding."""
    ce_vals = headers.get_all("Content-Encoding") or []
    encodings = [
        tok.strip().lower()
        for val in ce_vals
        for tok in val.split(",")
        if tok.strip()
    ]
    return any(enc != "identity" for enc in encodings)


def _read_chunked_http_body(rfile: Any, max_bytes: int = MAX_REQUEST_BYTES) -> tuple[Optional[bytes], int, str]:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = rfile.readline(8192)
        if not line or not line.endswith(b"\n"):
            return None, 400, "Malformed chunked request"
        size_token = line.strip().split(b";", 1)[0]
        try:
            chunk_size = int(size_token, 16)
        except ValueError:
            return None, 400, "Invalid chunk size"
        if chunk_size < 0:
            return None, 400, "Negative chunk size"
        if chunk_size == 0:
            while True:
                trailer = rfile.readline(8192)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            return b"".join(chunks), 0, ""

        if total + chunk_size > max_bytes:
            return None, 413, "Request body exceeds 16 MiB limit"

        remaining = chunk_size
        while remaining > 0:
            piece = rfile.read(min(remaining, 65536))
            if not piece:
                return None, 400, "Truncated chunked body"
            chunks.append(piece)
            remaining -= len(piece)
        total += chunk_size

        crlf = rfile.read(2)
        if crlf != b"\r\n":
            return None, 400, "Malformed chunk terminator"


def read_http_request_body(
    headers: Any,
    rfile: Any,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> tuple[Optional[bytes], int, str]:
    """Read HTTP request body safely enforcing framing rules and size cap.

    Returns (body_bytes, error_status, error_message). On success error_status == 0.
    """
    cl_vals = headers.get_all("Content-Length") or []
    te_vals = headers.get_all("Transfer-Encoding") or []

    if cl_vals and te_vals:
        return None, 400, "Conflicting Content-Length and Transfer-Encoding headers"

    if cl_vals:
        parsed_lengths: set[int] = set()
        for raw_cl in cl_vals:
            try:
                val = int(raw_cl.strip())
            except ValueError:
                return None, 400, "Invalid Content-Length header"
            if val < 0:
                return None, 400, "Negative Content-Length header"
            parsed_lengths.add(val)
        if len(parsed_lengths) != 1:
            return None, 400, "Conflicting Content-Length headers"

        length = next(iter(parsed_lengths))
        if length > max_bytes:
            return None, 413, "Request body exceeds 16 MiB limit"
        if length == 0:
            return b"", 0, ""

        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            piece = rfile.read(min(remaining, 65536))
            if not piece:
                return None, 400, "Truncated request body"
            chunks.append(piece)
            remaining -= len(piece)
        return b"".join(chunks), 0, ""

    if te_vals:
        codings = [
            tok.strip().lower()
            for raw_te in te_vals
            for tok in raw_te.split(",")
            if tok.strip()
        ]
        if codings != ["chunked"]:
            return None, 400, "Unsupported Transfer-Encoding"
        return _read_chunked_http_body(rfile, max_bytes=max_bytes)

    return b"", 0, ""


class BrokerRequestHandler(BaseHTTPRequestHandler):
    """HTTP/SSE reverse-proxy handler that redacts requests and restores responses."""

    protocol_version = "HTTP/1.1"
    server: "BrokerGateway"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_error_json(self, status: int, message: str) -> None:
        payload = json.dumps({"error": {"message": message, "status": status}}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        self.wfile.flush()
        self.close_connection = True

    def _read_request_body(self) -> tuple[Optional[bytes], int, str]:
        return read_http_request_body(self.headers, self.rfile, max_bytes=MAX_REQUEST_BYTES)

    def _redact_request_body(self, raw_body: bytes, content_type: str) -> tuple[bytes, int]:
        if not raw_body:
            return b"", 0
        mime = content_type.split(";", 1)[0].strip().lower()
        vault = self.server.vault

        if _is_json_content_type(mime):
            if b"\x00" in raw_body:
                raise ValueError("Malformed JSON request body: NUL byte not allowed")
            try:
                text = raw_body.decode("utf-8")
                payload = json.loads(text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("Invalid UTF-8 or malformed JSON request body") from exc

            redacted_count = 0

            def _redact_str(s: str) -> str:
                nonlocal redacted_count
                safe, n = vault.redact(s)
                redacted_count += n
                return safe

            safe_payload = prosze_core.walk(payload, _redact_str)
            return json.dumps(safe_payload, ensure_ascii=False).encode("utf-8"), redacted_count

        if _is_text_content_type(mime) or not mime:
            if not _is_utf8_printable_or_text(raw_body):
                raise ValueError("Invalid UTF-8 or NUL byte in request body")
            safe_text, hits = vault.redact(raw_body.decode("utf-8"))
            return safe_text.encode("utf-8"), hits

        return raw_body, 0

    def _build_upstream_headers(self, body_len: int, send_content_length: bool) -> dict[str, str]:
        conn_tokens = _connection_tokens(self.headers)
        drop = _HOP_BY_HOP_HEADERS | conn_tokens | {"host", "content-length", "accept-encoding"}
        out: dict[str, str] = {}
        for k, v in self.headers.items():
            if k.lower() in drop:
                continue
            out[k] = v
        out["Accept-Encoding"] = "identity"
        if send_content_length:
            out["Content-Length"] = str(body_len)
        return out

    def _copy_response_headers(self, up_resp: http.client.HTTPResponse, *, keep_content_length: bool = False) -> None:
        conn_tokens = _connection_tokens(up_resp.headers)
        drop = _HOP_BY_HOP_HEADERS | conn_tokens | {"content-encoding", "server", "date"}
        if not keep_content_length:
            drop = drop | {"content-length"}
        for k, v in up_resp.headers.items():
            if k.lower() in drop:
                continue
            self.send_header(k, v)

    def _open_upstream_connection(self) -> http.client.HTTPConnection:
        up = self.server.upstream_parts
        assert up.hostname is not None
        if up.scheme.lower() == "https":
            port = up.port or 443
            return http.client.HTTPSConnection(
                up.hostname,
                port,
                timeout=self.server.upstream_timeout,
                context=ssl.create_default_context(),
            )
        port = up.port or 80
        return http.client.HTTPConnection(
            up.hostname,
            port,
            timeout=self.server.upstream_timeout,
        )

    @staticmethod
    def _has_compressed_encoding(headers: Any) -> bool:
        return has_compressed_encoding(headers)

    def _stream_sse_response(self, up_resp: http.client.HTTPResponse) -> None:
        self.send_response(up_resp.status, up_resp.reason)
        self._copy_response_headers(up_resp, keep_content_length=False)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        sse = SSERestorer(self.server.vault)
        try:
            while True:
                chunk = up_resp.read1(4096)
                if not chunk:
                    break
                text = decoder.decode(chunk, final=False)
                if text:
                    out_text = sse.feed(text)
                    if out_text:
                        self.wfile.write(out_text.encode("utf-8"))
                        self.wfile.flush()
            tail_text = decoder.decode(b"", final=True)
            if tail_text:
                out_text = sse.feed(tail_text)
                if out_text:
                    self.wfile.write(out_text.encode("utf-8"))
            final_sse = sse.flush()
            if final_sse:
                self.wfile.write(final_sse.encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError):
            # Headers were already sent; flush any buffered partial text and terminate stream cleanly.
            try:
                final_sse = sse.flush()
                if final_sse:
                    self.wfile.write(final_sse.encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _send_buffered_response(self, up_resp: http.client.HTTPResponse, resp_mime: str) -> None:
        raw_resp_body = up_resp.read()
        is_json = _is_json_content_type(resp_mime)
        if is_json or _is_text_content_type(resp_mime) or (not resp_mime and _is_utf8_printable_or_text(raw_resp_body)):
            body_text = raw_resp_body.decode("utf-8", "replace")
            restored_text = _restore_locked(self.server.vault, body_text, json_escaped=is_json)
            out_bytes = restored_text.encode("utf-8")
        else:
            out_bytes = raw_resp_body

        self.send_response(up_resp.status, up_resp.reason)
        self._copy_response_headers(up_resp, keep_content_length=False)
        self.send_header("Content-Length", str(len(out_bytes)))
        self.end_headers()
        if out_bytes:
            self.wfile.write(out_bytes)
        self.wfile.flush()

    def _handle_request(self) -> None:
        t0 = time.perf_counter()
        req_url = urllib.parse.urlsplit(self.path)
        history_path = req_url.path or "/"
        redacted_count = 0

        def finish(status: int) -> None:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self.server.record_history(self.command, history_path, status, redacted_count, latency_ms)

        raw_body, err_status, err_msg = self._read_request_body()
        if err_status:
            self._send_error_json(err_status, err_msg)
            finish(err_status)
            return

        assert raw_body is not None
        if self._has_compressed_encoding(self.headers):
            self._send_error_json(415, "Unsupported Content-Encoding; only identity is allowed")
            finish(415)
            return

        ct_vals = self.headers.get_all("Content-Type") or []
        if len(ct_vals) > 1:
            self._send_error_json(400, "Conflicting Content-Type headers")
            finish(400)
            return
        req_ct = ct_vals[0] if ct_vals else ""
        try:
            forwarded_body, redacted_count = self._redact_request_body(raw_body, req_ct)
        except ValueError as exc:
            self._send_error_json(400, str(exc))
            finish(400)
            return

        has_body = bool(forwarded_body) or (
            self.command in ("POST", "PUT", "PATCH")
            and (bool(self.headers.get_all("Content-Length")) or bool(self.headers.get_all("Transfer-Encoding")))
        )
        fwd_headers = self._build_upstream_headers(len(forwarded_body), has_body)

        base_path = self.server.upstream_parts.path.rstrip("/")
        sub_path = history_path if history_path.startswith("/") else "/" + history_path
        target_path = (base_path + sub_path) or "/"
        if req_url.query:
            target_path = f"{target_path}?{req_url.query}"

        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = self._open_upstream_connection()
            conn.request(
                self.command,
                target_path,
                body=forwarded_body if forwarded_body else None,
                headers=fwd_headers,
            )
            up_resp = conn.getresponse()

            if self._has_compressed_encoding(up_resp.headers):
                self._send_error_json(502, "Upstream returned compressed Content-Encoding")
                finish(502)
                return

            resp_ct = up_resp.getheader("Content-Type", "")
            resp_mime = resp_ct.split(";", 1)[0].strip().lower()

            if self.command == "HEAD" or up_resp.status in (204, 304):
                up_resp.read()
                self.send_response(up_resp.status, up_resp.reason)
                self._copy_response_headers(up_resp, keep_content_length=(self.command == "HEAD"))
                self.end_headers()
            elif resp_mime == "text/event-stream":
                self._stream_sse_response(up_resp)
            else:
                self._send_buffered_response(up_resp, resp_mime)
            finish(up_resp.status)
        except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
            try:
                self._send_error_json(502, f"Upstream error: {type(exc).__name__}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finish(502)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    do_GET = _handle_request
    do_POST = _handle_request
    do_PUT = _handle_request
    do_PATCH = _handle_request
    do_DELETE = _handle_request
    do_OPTIONS = _handle_request
    do_HEAD = _handle_request


class BrokerGateway(ThreadingHTTPServer):
    """Loopback ThreadingHTTPServer privacy broker gateway."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        vault: prosze_core.Vault,
        upstream: str = DEFAULT_UPSTREAM,
        allow_remote: bool = False,
        timeout: float = 60.0,
    ) -> None:
        host, port = server_address
        clean_host = (host or "").strip()
        if clean_host.startswith("[") and clean_host.endswith("]"):
            clean_host = clean_host[1:-1]

        if not allow_remote and not is_loopback_host(clean_host):
            raise ValueError(
                f"prosze broker: refusing non-loopback listen host {host!r}; pass --allow-remote to override"
            )
        if not isinstance(port, int) or not (0 <= port <= 65535):
            raise ValueError(f"prosze broker: invalid port {port!r}")

        self.upstream_parts = validate_upstream_url(upstream)
        self.upstream_url = upstream
        self.vault = vault
        self.allow_remote = allow_remote
        self.upstream_timeout = timeout
        self._history_lock = threading.Lock()
        self._history: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY_ENTRIES)

        if ":" in clean_host:
            self.address_family = socket.AF_INET6

        super().__init__((clean_host, port), BrokerRequestHandler)

    @property
    def history(self) -> list[dict[str, Any]]:
        """Return a thread-safe snapshot of recent request metadata (max 100 entries)."""
        with self._history_lock:
            return list(self._history)

    def record_history(
        self,
        method: str,
        path: str,
        status: int,
        redacted_count: int,
        latency_ms: float,
    ) -> None:
        """Append a redacted request metadata record to the bounded history."""
        entry = {
            "method": method,
            "path": path,
            "status": int(status),
            "redacted_count": int(redacted_count),
            "latency_ms": round(float(latency_ms), 2),
        }
        with self._history_lock:
            self._history.append(entry)


def create_broker_server(
    vault: prosze_core.Vault,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    upstream: str = DEFAULT_UPSTREAM,
    allow_remote: bool = False,
    timeout: float = 60.0,
) -> BrokerGateway:
    """Validate configuration and construct a BrokerGateway server instance."""
    return BrokerGateway(
        (host, port),
        vault=vault,
        upstream=upstream,
        allow_remote=allow_remote,
        timeout=timeout,
    )
