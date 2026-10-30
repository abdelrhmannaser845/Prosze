"""prosze_core - Vault, redaction engine, and interactive chat.

This module contains all core functionality that is NOT the proxy or plugin:
  - Vault: redaction/restoration state and map persistence
  - Utility functions: read_stdin, walk
  - chat(): interactive terminal session
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import threading
from typing import Optional, Tuple


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
    ("PRIVKEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\\Z)", 0, None, re.S),
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


# ---------------------------------------------------------------- authenticated encryption
def _derive_keys(passphrase: str, nonce_hex: str) -> Tuple[bytes, bytes]:
    pw_bytes = passphrase.encode("utf-8")
    k_enc = hmac.new(pw_bytes, f"prosze-enc-v1:{nonce_hex}".encode("utf-8"), hashlib.sha256).digest()
    k_mac = hmac.new(pw_bytes, f"prosze-mac-v1:{nonce_hex}".encode("utf-8"), hashlib.sha256).digest()
    return k_enc, k_mac


def _crypt_keystream(k_enc: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    block = b""
    for i in range(len(data)):
        if i % 32 == 0:
            counter = (i // 32).to_bytes(4, "big")
            block = hmac.new(k_enc, counter, hashlib.sha256).digest()
        out[i] = data[i] ^ block[i % 32]
    return bytes(out)


def encrypt_map(passphrase: str, plaintext: str) -> str:
    nonce = os.urandom(16)
    nonce_hex = nonce.hex().lower()
    k_enc, k_mac = _derive_keys(passphrase, nonce_hex)
    p_bytes = plaintext.encode("utf-8")
    c_bytes = _crypt_keystream(k_enc, p_bytes)
    cipher_hex = c_bytes.hex().lower()
    mac_data = f"{nonce_hex}\t{cipher_hex}".encode("utf-8")
    tag_hex = hmac.new(k_mac, mac_data, hashlib.sha256).hexdigest().lower()
    return f"#PROSZE_ENC_V1\t{nonce_hex}\t{cipher_hex}\t{tag_hex}\n"


def decrypt_map(passphrase: Optional[str], line: str) -> str:
    if not passphrase:
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")
    stripped = line.rstrip("\r\n")
    parts = stripped.split("\t")
    if len(parts) != 4 or parts[0] != "#PROSZE_ENC_V1":
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")
    nonce_hex, cipher_hex, tag_hex = parts[1], parts[2], parts[3]
    if len(nonce_hex) != 32 or len(tag_hex) != 64:
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")
    k_enc, k_mac = _derive_keys(passphrase, nonce_hex)
    mac_data = f"{nonce_hex}\t{cipher_hex}".encode("utf-8")
    expected_tag = hmac.new(k_mac, mac_data, hashlib.sha256).hexdigest().lower()
    if not hmac.compare_digest(tag_hex.lower(), expected_tag):
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")
    try:
        c_bytes = bytes.fromhex(cipher_hex)
    except ValueError:
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")
    p_bytes = _crypt_keystream(k_enc, c_bytes)
    try:
        return p_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("prosze: invalid passphrase or corrupted encrypted map")


class Vault:
    def __init__(self, map_path: str, ephemeral: bool = False, passphrase: Optional[str] = None):
        self.map_path = map_path
        self.ephemeral = ephemeral
        if passphrase is None:
            env_key = os.environ.get("PROSZE_KEY")
            if env_key:
                passphrase = env_key
        self.passphrase = passphrase
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
        if self.ephemeral:
            return
        tmp = f"{self.map_path}.tmp.{os.getpid()}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                if self.passphrase:
                    tsv_lines = "".join(f"{k}\t{esc(v)}\n" for k, v in self.fwd.items())
                    f.write(encrypt_map(self.passphrase, tsv_lines))
                else:
                    for k, v in self.fwd.items():
                        f.write(f"{k}\t{esc(v)}\n")
            os.replace(tmp, self.map_path)
        except Exception:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            raise

    def _load(self):
        if not os.path.exists(self.map_path):
            return
        with open(self.map_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        lines = content.splitlines()
        first_line = lines[0] if lines else ""
        if first_line.startswith("#PROSZE_ENC_V1\t"):
            tsv_content = decrypt_map(self.passphrase, first_line)
            lines = tsv_content.splitlines()

        for line in lines:
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


# ---------------------------------------------------------------- I/O helpers
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
