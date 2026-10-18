#!/usr/bin/env python3
"""prosze - removes sensitive details from a prompt BEFORE it is sent to an AI.

Sensitive patterns use local rules; optional local GLiNER NER detects names without a dictionary.

    your prompt --> prosze --> AI --> prosze --> answer with real values back

What it hides
    automatically : phone numbers, bank account / IBAN numbers, e-mails, cards,
                    SSNs, API keys / tokens / passwords, private keys, private IPs
    names: people, organizations, customers and projects can be detected by
           a local GLiNER model (no manually maintained name list required)

Commands
    prosze chat                       paste prompt -> get safe text; paste reply -> get real text
    prosze redact  < prompt.txt       print the safe version
    prosze restore < reply.txt        put the real values back
    prosze check   < prompt.txt       exit code 1 if anything sensitive is found
    prosze run -- cmd args...         redact stdin/args, run cmd, restore its output
    prosze proxy                      local proxy for AI clients (Claude Code, SDKs...)

Options (all commands)
    --term "Acme Corp"                hide this name (repeatable)
    --term CUSTOMER="Acme Corp"       same, placeholder becomes [[CUSTOMER_1]]
    --terms FILE                      one term per line (optional LABEL=value);
                                      ./.prosze-terms is loaded automatically
    --env .env                        also hide every value in a .env file
    --map FILE                        mapping file (default ./.prosze-map)

The mapping file holds the real values in clear text: keep it local, out of git.
"""
import argparse, codecs, copy, http.client, json, os, re, shutil, socket, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# ------------------------------------------------------------------ validators
def luhn_ok(s):
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, v in enumerate(reversed(d)):
        if i % 2:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0

def looks_random(s):
    return any(c.isdigit() for c in s) and any(c.isalpha() for c in s) and len(set(s)) >= 10

def not_placeholder(s):
    return not s.startswith("[[")

def kv_ok(s):
    return not_placeholder(s) and s.lower() not in ("true", "false", "null", "none")

def private_ip(s):
    try:
        a, b, c, d = (int(x) for x in s.split("."))
    except ValueError:
        return False
    if max(a, b, c, d) > 255:
        return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)

def digits_between(lo, hi):
    return lambda s: lo <= sum(c.isdigit() for c in s) <= hi

def iban_ok(s):
    t = s.replace(" ", "").upper()
    if not 15 <= len(t) <= 34 or not t.isalnum():
        return False
    return int("".join(str(int(c, 36)) for c in t[4:] + t[:4])) % 97 == 1

def phone_sep_ok(s):
    return digits_between(9, 15)(s) and not re.match(r"\d{4}-\d{1,2}-\d{1,2}", s)

def esc(s):
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

def unesc(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            i += 1
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(s[i], s[i]))
        else:
            out.append(s[i])
        i += 1
    return "".join(out)

# ----------------------------------------------------------------------- vault
RULES = [
    # (category, regex, group, validator, flags)
    ("PRIVKEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", 0, None, re.S),
    ("PASSWORD", r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@", 1, not_placeholder, 0),
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, None, 0),
    ("TOKEN", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, None, 0),
    ("TOKEN", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0, None, 0),
    ("TOKEN", r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|glpat|xox[baprs])[-_][A-Za-z0-9_\-]{12,}\b", 0, None, 0),
    ("TOKEN", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0, None, 0),
    ("TOKEN", r"\bBearer\s+([A-Za-z0-9_\-\.=]{16,})", 1, not_placeholder, 0),
    ("PASSWORD",
     r"""[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*["']?([^\s"',;]{6,})""",
     1, kv_ok, re.I),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban_ok, 0),
    ("ACCOUNT", r"\b(?:account|acct|a/c|iban|konto|konta)\b\s*(?:no\.?|number|nr\.?|#)?\s*[:=#]?\s*((?:[A-Z]{2}\d{2} ?)?\d[\d -]{5,30}\d)", 1, not_placeholder, re.I),
    ("SSN", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0, None, 0),
    ("PHONE", r"\b(?:phone|tel|telephone|mobile|cell|fax|whatsapp)\b\s*(?:no\.?|number|#)?\s*[:=]?\s*(\+?\d[\d ()./-]{5,18}\d)", 1, digits_between(6, 15), re.I),
    ("CARD", r"\b\d(?:[ -]?\d){12,18}\b", 0, luhn_ok, 0),
    ("APIKEY", r"\b[A-Za-z0-9]{32}\b", 0, looks_random, 0),
    ("APIKEY", r"\b[A-Fa-f0-9]{40,64}\b", 0, None, 0),
    ("IP", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, private_ip, 0),
    ("PHONE", r"(?<![\w.+-])\+\d[\d ()./-]{7,18}\d(?!\w)", 0, digits_between(8, 15), 0),
    ("PHONE", r"(?<![\w.+/-])\(?\d{2,4}\)?[ .-]\d{2,4}[ .-]\d{2,4}(?:[ .-]\d{2,4})?(?![\w/-])", 0, phone_sep_ok, 0),
]
PH = re.compile(r"\[\[[A-Z][A-Z0-9_]*_\d+\]\]")
PH_IDX = re.compile(r"^\[\[([A-Z][A-Z0-9_]*)_(\d+)\]\]$")


class Vault:
    def __init__(self, map_path):
        self.map_path = map_path
        self.fwd, self.bwd, self.counters = {}, {}, {}
        self.rules = [(c, re.compile(p, f), g, v) for c, p, g, v, f in RULES]
        self.literals = []
        self.term_rules = []
        self.fold = {}              # (category, lowercase text) -> placeholder, for names
        self.lock = threading.RLock()
        self._hits = 0
        self.ner = None
        self.ner_error = None
        self._ner_attempted = False
        self._load()

    def _load_ner(self):
        """Load GLiNER locally on first use; never sends prompt text to a service."""
        if self._ner_attempted:
            return self.ner
        self._ner_attempted = True
        try:
            from gliner import GLiNER
            # First run downloads the model from Hugging Face; later runs use its local cache.
            self.ner = GLiNER.from_pretrained("urchade/gliner_small-v2.1")
        except Exception as exc:
            self.ner_error = str(exc)
            self.ner = None
        return self.ner

    def _apply_ner(self, text):
        model = self._load_ner()
        if model is None or not text.strip():
            return text
        # Specific labels help avoid treating arbitrary capitalized words as names.
        labels = ["person", "organization", "company", "customer", "project"]
        try:
            entities = model.predict_entities(text, labels, threshold=0.45)
        except Exception as exc:
            self.ner_error = str(exc)
            return text
        existing_ph = [m.span() for m in PH.finditer(text)]
        spans = []
        for ent in entities:
            start, end = int(ent.get("start", -1)), int(ent.get("end", -1))
            value = text[start:end] if 0 <= start < end <= len(text) else ""
            if len(value.strip()) < 2 or PH.fullmatch(value.strip()):
                continue
            if any(max(start, ps) < min(end, pe) for ps, pe in existing_ph):
                continue
            label = str(ent.get("label", "person")).lower()
            cat = "PERSON" if label == "person" else ("PROJECT" if label == "project" else ("CUSTOMER" if label == "customer" else "ORG"))
            spans.append((start, end, cat, value))
        spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        out, last = [], 0
        for start, end, cat, value in spans:
            if start < last:
                continue
            out.extend((text[last:start], self.save(value, cat)))
            last = end
        if not spans:
            return text
        out.append(text[last:])
        return "".join(out)

    # -- configuration
    def add_literal(self, value, cat="ENV"):
        if len(value) >= 4:
            self.literals.append((value, cat))
            self.literals.sort(key=lambda t: -len(t[0]))

    def add_term(self, spec):
        """'Acme Corp' or 'CUSTOMER=Acme Corp' (case-insensitive, whole words)."""
        m = re.match(r"^([A-Z][A-Z0-9_]{1,19})=(.+)$", spec.strip())
        cat, text = (m[1], m[2].strip()) if m else ("TERM", spec.strip())
        if not text:
            return
        rx = re.compile(r"(?<!\w)" + re.escape(text) + r"(?!\w)", re.I)
        self.term_rules.append((len(text), (cat, rx, 0, None)))
        for k, val in self.fwd.items():         # names already in a loaded map
            m2 = PH_IDX.match(k)
            if m2 and m2[1] == cat:
                self.fold[(cat, val.lower())] = k
        self.term_rules.sort(key=lambda t: -t[0])

    def load_terms(self, path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add_term(line)

    def load_env(self, path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:]
                v = line.split("=", 1)[1].strip()
                if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
                    v = v[1:-1]
                self.add_literal(v, "ENV")

    # -- core
    def save(self, value, cat):
        self._hits += 1
        if value in self.bwd:
            return self.bwd[value]
        fk = (cat, value.lower())
        if fk in self.fold:                     # same name, different capitalisation
            return self.fold[fk]
        n = self.counters[cat] = self.counters.get(cat, 0) + 1
        key = f"[[{cat}_{n}]]"
        self.bwd[value], self.fwd[key] = key, value
        if any(c == cat for _, (c, *_r) in self.term_rules):
            self.fold[fk] = key
        return key

    def redact(self, text):
        """Returns (safe_text, number_of_replacements)."""
        with self.lock:
            before, before_n = self._hits, len(self.fwd)
            for lit, cat in self.literals:
                if lit in text:
                    text = text.replace(lit, self.save(lit, cat))
            for cat, rx, g, val in self.rules + [r for _, r in self.term_rules]:
                text = self._apply(text, cat, rx, g, val)
            text = self._apply_ner(text)
            if len(self.fwd) != before_n:
                self._persist()
            return text, self._hits - before

    def _apply(self, text, cat, rx, g, val):
        out, last = [], 0
        for m in rx.finditer(text):
            v = m.group(g)
            if v is None:
                continue
            s, e = m.span(g)
            if e == s or s < last or (val and not val(v)):
                continue
            out += [text[last:s], self.save(v, cat)]
            last = e
        out.append(text[last:])
        return "".join(out)

    def restore(self, text, json_escaped=False):
        def sub(m):
            v = self.fwd.get(m.group(0))
            if v is None:
                return m.group(0)
            return json.dumps(v, ensure_ascii=False)[1:-1] if json_escaped else v
        return PH.sub(sub, text)

    # -- map file (same TSV format as the C++ prosze, mode 0600)
    def _persist(self):
        tmp = self.map_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for k, v in self.fwd.items():
                f.write(f"{k}\t{esc(v)}\n")
        os.replace(tmp, self.map_path)

    def _load(self):
        if not os.path.exists(self.map_path):
            return
        with open(self.map_path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if "\t" not in line:
                    continue
                k, v = line.split("\t", 1)
                v = unesc(v)
                self.fwd[k], self.bwd[v] = v, k
                m = PH_IDX.match(k)
                if m:
                    self.counters[m[1]] = max(self.counters.get(m[1], 0), int(m[2]))


# ----------------------------------------------------------------- JSON walker
SKIP_KEYS = {"model", "role", "type", "id", "tool_use_id", "media_type",
             "stop_reason", "object", "tool_call_id"}

def walk(o, fn):
    if isinstance(o, str):
        return o if o.startswith("data:") else fn(o)
    if isinstance(o, list):
        return [walk(x, fn) for x in o]
    if isinstance(o, dict):
        b64 = o.get("type") == "base64"
        return {k: (v if k in SKIP_KEYS or (b64 and k == "data") else walk(v, fn))
                for k, v in o.items()}
    return o


# ------------------------------------------------------- streaming un-redaction
TAIL = re.compile(r"(?:\[\[[A-Z0-9_]*|\[\[[A-Z0-9_]*\])$|\[$")
EVENT_SPLIT = re.compile(r"\r?\n\r?\n")

class StreamRestorer:
    """Restores placeholders in SSE streams even when one is split across events."""
    def __init__(self, vault):
        self.v, self.held, self.buf = vault, {}, ""
        self.dec = codecs.getincrementaldecoder("utf-8")("replace")

    def _feed(self, key, text, escaped):
        buf = self.held.pop(key, "") + text
        m = TAIL.search(buf)
        if m:
            self.held[key] = m.group(0)
            buf = buf[:m.start()]
        return self.v.restore(buf, escaped)

    def _take(self, pred):
        return [(k, self.held.pop(k)) for k in [k for k in self.held if pred(k)]]

    @staticmethod
    def _render(name, data, metadata=()):
        head = "".join(f"{line}\n" for line in metadata)
        if name:
            head += f"event: {name}\n"
        return f"{head}data: {json.dumps(data, ensure_ascii=False)}\n\n"

    def feed_bytes(self, raw):
        self.buf += self.dec.decode(raw)
        parts = EVENT_SPLIT.split(self.buf)
        self.buf = parts.pop()
        return "".join(self._event(p) for p in parts).encode()

    def finish(self):
        self.buf += self.dec.decode(b"", final=True)
        out = self._event(self.buf) if self.buf.strip() else ""
        self.buf = ""
        for key, text in list(self.held.items()):
            self.held.pop(key, None)
            if key[0] == "a":
                kind = key[2]
                field = "text" if kind == "text" else "partial_json"
                delta = {"type": "text_delta" if kind == "text" else "input_json_delta",
                         field: self.v.restore(text, json_escaped=kind == "json")}
                out += self._render("content_block_delta",
                                    {"type": "content_block_delta", "index": key[1],
                                     "delta": delta})
            elif key[0] == "o":
                delta = {"content": self.v.restore(text)} if key[2] == "c" else {
                    "tool_calls": [{"index": key[3], "function": {
                        "arguments": self.v.restore(text, json_escaped=True)}}]}
                out += self._render(None, {"choices": [{"index": key[1],
                                                         "finish_reason": None,
                                                         "delta": delta}]})
        return out.encode()

    def _event(self, raw):
        name, data_lines, metadata = None, [], []
        for line in raw.split("\n"):
            line = line.rstrip("\r")
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif line:
                metadata.append(line)
        payload = "\n".join(data_lines)
        try:
            d = json.loads(payload)
        except Exception:
            return raw + "\n\n"            # [DONE], comments, pings...
        extra = ""
        t = d.get("type") if isinstance(d, dict) else None

        if t == "content_block_delta":                       # Anthropic
            i, dl = d.get("index"), d.get("delta", {})
            if dl.get("type") == "text_delta":
                dl["text"] = self._feed(("a", i, "text"), dl.get("text", ""), False)
            elif dl.get("type") == "input_json_delta":
                dl["partial_json"] = self._feed(("a", i, "json"), dl.get("partial_json", ""), True)
        elif t in ("content_block_stop", "message_stop"):
            for (_, i, kind), text in self._take(lambda k: k[0] == "a" and (t == "message_stop" or k[1] == d.get("index"))):
                dl = {"type": "text_delta", "text": self.v.restore(text)} if kind == "text" \
                    else {"type": "input_json_delta", "partial_json": self.v.restore(text, True)}
                extra += self._render("content_block_delta",
                                      {"type": "content_block_delta", "index": i, "delta": dl})
        elif isinstance(d, dict) and "choices" in d:         # OpenAI-style
            for ch in d["choices"]:
                i, dl = ch.get("index", 0), ch.get("delta") or {}
                if isinstance(dl.get("content"), str):
                    dl["content"] = self._feed(("o", i, "c"), dl["content"], False)
                for tc in dl.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    if isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self._feed(("o", i, "t", tc.get("index", 0)), fn["arguments"], True)
                if ch.get("finish_reason"):
                    for k, text in self._take(lambda k: k[0] == "o" and k[1] == i):
                        syn = copy.deepcopy(d)
                        syn["choices"] = [{"index": i, "finish_reason": None,
                                           "delta": {"content": self.v.restore(text)} if k[2] == "c" else
                                           {"tool_calls": [{"index": k[3], "function": {"arguments": self.v.restore(text, True)}}]}}]
                        extra += self._render(name, syn)
        return extra + self._render(name, d, metadata)


# ----------------------------------------------------------------------- proxy
HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding",
       "accept-encoding", "proxy-connection", "te", "upgrade"}
MAX_REQUEST_BYTES = 16 * 1024 * 1024
UPSTREAM_TIMEOUT = 60

def make_handler(vault, upstream, verbose):
    u = urlsplit(upstream)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("upstream must be an http(s) URL without credentials")
    https = u.scheme == "https"
    try:
        port = u.port or (443 if https else 80)
    except ValueError as exc:
        raise ValueError("upstream has an invalid port") from exc
    prefix = u.path.rstrip("/")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _read_body(self):
            transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
            content_lengths = self.headers.get_all("Content-Length", [])
            if transfer_encoding and content_lengths:
                raise ValueError("request must not contain both transfer-encoding and content-length")
            if transfer_encoding:
                if transfer_encoding.strip() != "chunked":
                    raise ValueError("unsupported transfer-encoding")
                body = bytearray()
                while True:
                    line = self.rfile.readline(8193)
                    if not line or len(line) > 8192 or not line.endswith(b"\n"):
                        raise ValueError("malformed chunk size")
                    try:
                        size = int(line.split(b";", 1)[0].strip(), 16)
                    except ValueError as exc:
                        raise ValueError("malformed chunk size") from exc
                    if size < 0 or len(body) + size > MAX_REQUEST_BYTES:
                        raise ValueError("request body is too large")
                    if size == 0:
                        while True:
                            trailer = self.rfile.readline(8193)
                            if not trailer or len(trailer) > 8192 or not trailer.endswith(b"\n"):
                                raise ValueError("malformed chunk trailer")
                            if trailer in (b"\n", b"\r\n"):
                                return bytes(body)
                    chunk = self.rfile.read(size)
                    if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                        raise ValueError("malformed chunk data")
                    body.extend(chunk)
            if len(content_lengths) > 1 or (content_lengths and content_lengths[0].strip() == ""):
                raise ValueError("malformed content-length")
            try:
                n = int(content_lengths[0]) if content_lengths else 0
            except ValueError as exc:
                raise ValueError("malformed content-length") from exc
            if n < 0 or n > MAX_REQUEST_BYTES:
                raise ValueError("request body is too large")
            body = self.rfile.read(n) if n else b""
            if len(body) != n:
                raise ValueError("incomplete request body")
            return body

        def _fail(self, code, msg):
            data = json.dumps({"error": {"type": "prosze_error", "message": msg}},
                              ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def _handle(self):
            try:
                body = self._read_body()
            except (ValueError, OSError) as exc:
                return self._fail(400, str(exc))
            hits = 0
            if body:
                try:
                    obj = json.loads(body)
                    count = [0]
                    def fn(s):
                        r, n = vault.redact(s)
                        count[0] += n
                        return r
                    body = json.dumps(walk(obj, fn), ensure_ascii=False).encode()
                    hits = count[0]
                except ValueError:                      # not JSON: fail closed, redact raw
                    text, hits = vault.redact(body.decode("utf-8", "replace"))
                    body = text.encode()
            if verbose and body:
                sys.stderr.write("[prosze] outbound (redacted): " + body[:2000].decode("utf-8", "replace") + "\n")
            sys.stderr.write(f"[prosze] {self.command} {self.path}: {hits} secret(s) hidden\n")

            connection_headers = {h.strip().lower() for h in self.headers.get("Connection", "").split(",")}
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in HOP and k.lower() not in connection_headers}
            headers["Host"] = u.netloc
            # Restoration requires plaintext bytes.  Never allow an upstream
            # gzip/br response to cross this boundary undecoded.
            headers["Accept-Encoding"] = "identity"
            headers["Content-Length"] = str(len(body))
            conn = None
            try:
                cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
                conn = cls(u.hostname, port, timeout=UPSTREAM_TIMEOUT)
                request_path = urlsplit(self.path).path or "/"
                request_query = urlsplit(self.path).query
                target = (prefix + "/" + request_path.lstrip("/")) if prefix else "/" + request_path.lstrip("/")
                if request_query:
                    target += "?" + request_query
                conn.request(self.command, target, body=body, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException, ValueError):
                if conn:
                    conn.close()
                return self._fail(502, "upstream unavailable")

            out_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP | {"content-encoding"}]
            encoded = resp.getheader("Content-Encoding", "identity").lower() != "identity"
            ctype = (resp.getheader("Content-Type") or "").lower()

            try:
                if encoded:
                    # A compliant upstream should honor identity.  Failing
                    # closed is safer than returning compressed data that may
                    # still contain the original secret.
                    resp.read()
                    return self._fail(502, "upstream returned compressed content")
                elif "text/event-stream" in ctype:
                    self.send_response(resp.status)
                    for k, v in out_headers:
                        self.send_header(k, v)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    sr = StreamRestorer(vault)
                    def chunk(data):
                        if data:
                            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                            self.wfile.flush()
                    while True:
                        raw = resp.read1(65536)
                        if not raw:
                            break
                        chunk(sr.feed_bytes(raw))
                    chunk(sr.finish())
                    self.wfile.write(b"0\r\n\r\n")
                else:
                    data = resp.read()
                    if "json" in ctype or ctype.startswith("text/"):
                        data = vault.restore(data.decode("utf-8", "replace"),
                                             json_escaped="json" in ctype).encode()
                    self.send_response(resp.status)
                    for k, v in out_headers:
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            except (OSError, http.client.HTTPException, socket.timeout):
                self.close_connection = True
            finally:
                conn.close()

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    return Handler


def read_stdin():
    return sys.stdin.buffer.read().decode("utf-8", "replace")

def read_block(prompt):
    print(prompt, flush=True)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            return "\n".join(lines) if lines else None
        if line.strip() == "END":
            return "\n".join(lines)
        lines.append(line)

def chat(v):
    print("Prosze - nothing leaves this window until you copy it yourself.")
    while True:
        text = read_block("\nPaste your PROMPT, then a line with only END (Ctrl+Z/Ctrl+D then Enter quits):")
        if text is None:
            return
        safe, n = v.redact(text)
        print(f"\n======== SAFE TO SEND ({n} item(s) hidden) ========\n{safe}\n" + "=" * 44)
        reply = read_block("\nPaste the AI's REPLY (or just END to skip):")
        if reply is None:
            return
        if reply.strip():
            print("\n======== RESTORED ========\n" + v.restore(reply) + "\n" + "=" * 24)

def main():
    argv, cmd = sys.argv[1:], []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd = argv[:i], argv[i + 1:]

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--map", default=".prosze-map")
    common.add_argument("--env", action="append", default=[])
    common.add_argument("--term", action="append", default=[])
    common.add_argument("--terms", action="append", default=[])
    common.add_argument("--no-ner", action="store_true", help="disable automatic model-based name detection")

    ap = argparse.ArgumentParser(prog="prosze", description="Remove sensitive details from prompts before they reach an AI.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("chat", "redact", "restore", "check", "run"):
        sub.add_parser(name, parents=[common])
    px = sub.add_parser("proxy", parents=[common])
    px.add_argument("--listen", default="127.0.0.1:8787")
    px.add_argument("--upstream", default="https://api.anthropic.com")
    px.add_argument("--verbose", action="store_true", help="print the redacted outbound body")
    a = ap.parse_args(argv)

    v = Vault(a.map)
    if a.no_ner:
        v._ner_attempted = True  # explicit opt-out; regex and manually supplied terms still work
    try:
        for p in a.env:
            v.load_env(p)
        for p in a.terms + ([".prosze-terms"] if os.path.exists(".prosze-terms") else []):
            v.load_terms(p)
    except OSError as e:
        sys.exit(f"prosze: {e}")
    for t in a.term:
        v.add_term(t)

    out = lambda text: sys.stdout.buffer.write(text.encode("utf-8"))
    if a.cmd == "chat":
        chat(v)
    elif a.cmd == "redact":
        safe, n = v.redact(read_stdin())
        out(safe)
        sys.stderr.write(f"prosze: {n} item(s) hidden\n")
    elif a.cmd == "restore":
        out(v.restore(read_stdin()))
    elif a.cmd == "check":
        _, n = v.redact(read_stdin())
        if n:
            sys.stderr.write(f"prosze: {n} sensitive item(s) found\n")
            sys.exit(1)
    elif a.cmd == "run":
        if not cmd:
            sys.exit("prosze: usage: prosze run [options] -- command args...")
        exe = shutil.which(cmd[0])
        if not exe:
            sys.exit(f"prosze: command not found: {cmd[0]}")
        total = 0
        args = []
        for c in cmd[1:]:
            r, n = v.redact(c)
            args.append(r)
            total += n
        safe = ""
        if not sys.stdin.isatty():
            safe, n = v.redact(read_stdin())
            total += n
        res = subprocess.run([exe] + args, input=safe.encode("utf-8"), stdout=subprocess.PIPE)
        out(v.restore(res.stdout.decode("utf-8", "replace")))
        sys.stderr.write(f"prosze: {total} item(s) hidden before sending\n")
        sys.exit(res.returncode)
    elif a.cmd == "proxy":
        host, _, port = a.listen.rpartition(":")
        if host not in ("127.0.0.1", "localhost", "::1"):
            sys.stderr.write("[prosze] WARNING: non-loopback address exposes your secret map to the network.\n")
        try:
            listen_port = int(port)
            if not 1 <= listen_port <= 65535:
                raise ValueError
            handler = make_handler(v, a.upstream, a.verbose)
            srv = ThreadingHTTPServer((host or "127.0.0.1", listen_port), handler)
        except ValueError as exc:
            sys.exit(f"prosze: invalid proxy address or upstream: {exc}")
        sys.stderr.write(f"[prosze] {a.listen} -> {a.upstream}   (map: {a.map})\n")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
