"""prosze_core - Vault, redaction engine, and interactive chat.

This module contains all core functionality that is NOT the proxy or plugin:
  - Vault: redaction/restoration state and map persistence
  - Utility functions: read_stdin, walk
  - chat(): interactive terminal session
"""
from __future__ import annotations

import base64
import bisect
import codecs
from collections import deque
import hashlib
import hmac
import io
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
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254)


def is_printable_text(data: bytes) -> bool:
    if not data:
        return False
    for b in data:
        if b in (9, 10, 13):
            continue
        if b < 0x20 or b == 0x7F:
            return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


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
FEAT_NONE = 0
FEAT_AT = 1 << 0
FEAT_COLON_EQ = 1 << 1
FEAT_DIGIT = 1 << 2
FEAT_DASH_UNDER = 1 << 3
FEAT_DOT = 1 << 4
FEAT_PLUS = 1 << 5

_DIGITS_SET = frozenset("0123456789")
_WORD_CHAR_RE = re.compile(r"\w")


def scan_char_features(text: str) -> int:
    """Compute a bitmask of character classes present in text in a single O(N) pass."""
    if not text:
        return FEAT_NONE
    chars = set(text)
    mask = FEAT_NONE
    if "@" in chars:
        mask |= FEAT_AT
    if ":" in chars or "=" in chars:
        mask |= FEAT_COLON_EQ
    if not chars.isdisjoint(_DIGITS_SET):
        mask |= FEAT_DIGIT
    if "-" in chars or "_" in chars:
        mask |= FEAT_DASH_UNDER
    if "." in chars:
        mask |= FEAT_DOT
    if "+" in chars:
        mask |= FEAT_PLUS
    return mask


def _is_word_char(ch: str) -> bool:
    return ch == "_" or ch.isalnum() or bool(_WORD_CHAR_RE.match(ch))


def _fold_char(ch: str) -> str:
    lc = ch.lower()
    return lc if len(lc) == 1 else ch


def _fold_str(s: str) -> str:
    if s.isascii():
        return s.lower()
    return "".join(_fold_char(ch) for ch in s)


def _find_placeholder_spans(text: str) -> list[tuple[int, int]]:
    if "[[" not in text:
        return []
    return [m.span() for m in PH.finditer(text)]


def _overlaps_placeholder(start: int, end: int, ph_spans: list[tuple[int, int]]) -> bool:
    if not ph_spans:
        return False
    lo, hi = 0, len(ph_spans)
    while lo < hi:
        mid = (lo + hi) // 2
        if ph_spans[mid][1] <= start:
            lo = mid + 1
        else:
            hi = mid
    return lo < len(ph_spans) and ph_spans[lo][0] < end


class AhoCorasick:
    """Dependency-free single-pass Aho-Corasick automaton with longest-first resolution."""

    def __init__(self, case_fold: bool = False):
        self.case_fold = case_fold
        self.patterns: list[tuple[str, str]] = []
        self.goto: list[dict[str, int]] = [{}]
        self.fail: list[int] = [0]
        self.out_pat: list[int] = [-1]
        self.dict_link: list[int] = [-1]
        self.match_head: list[int] = [-1]

    def build(self, items: list[tuple[str, str]]) -> None:
        self.patterns = []
        self.goto = [{}]
        self.fail = [0]
        self.out_pat = [-1]
        self.dict_link = [-1]
        self.match_head = [-1]
        fold = self.case_fold

        for raw_pat, cat in items:
            if not raw_pat:
                continue
            pat = _fold_str(raw_pat) if fold else raw_pat
            cur = 0
            for ch in pat:
                nxt = self.goto[cur].get(ch)
                if nxt is None:
                    nxt = len(self.goto)
                    self.goto[cur][ch] = nxt
                    self.goto.append({})
                    self.fail.append(0)
                    self.out_pat.append(-1)
                    self.dict_link.append(-1)
                    self.match_head.append(-1)
                cur = nxt
            if self.out_pat[cur] == -1:
                pid = len(self.patterns)
                self.patterns.append((pat, cat))
                self.out_pat[cur] = pid

        q: deque[int] = deque()
        for child in self.goto[0].values():
            self.fail[child] = 0
            self.dict_link[child] = -1
            self.match_head[child] = child if self.out_pat[child] != -1 else -1
            q.append(child)

        while q:
            u = q.popleft()
            for ch, v in self.goto[u].items():
                f = self.fail[u]
                while f and ch not in self.goto[f]:
                    f = self.fail[f]
                fc = self.goto[f].get(ch, 0)
                self.fail[v] = fc
                dl = fc if self.out_pat[fc] != -1 else self.dict_link[fc]
                self.dict_link[v] = dl
                self.match_head[v] = v if self.out_pat[v] != -1 else dl
                q.append(v)

    def _scan_candidates(self, text: str, whole_word: bool, ph_spans: list[tuple[int, int]]):
        if not self.patterns or not text:
            return
        goto = self.goto
        fail = self.fail
        match_head = self.match_head
        out_pat = self.out_pat
        dict_link = self.dict_link
        patterns = self.patterns
        goto0 = goto[0]
        state = 0
        fold = self.case_fold
        n = len(text)

        for idx, ch in enumerate(text):
            if fold:
                c = ch.lower()
                if len(c) != 1:
                    c = ch
            else:
                c = ch

            if state == 0:
                state = goto0.get(c, 0)
            else:
                nxt = goto[state].get(c)
                if nxt is None:
                    f = fail[state]
                    while f and c not in goto[f]:
                        f = fail[f]
                    state = goto[f].get(c, 0)
                else:
                    state = nxt

            m = match_head[state]
            if m != -1:
                end = idx + 1
                while m != -1:
                    pid = out_pat[m]
                    plen = len(patterns[pid][0])
                    start = end - plen
                    ok = True
                    if whole_word:
                        if start > 0 and _is_word_char(text[start - 1]):
                            ok = False
                        elif end < n and _is_word_char(text[end]):
                            ok = False
                    if ok and not _overlaps_placeholder(start, end, ph_spans):
                        yield (start, end, pid)
                    m = dict_link[m]

    def has_any_match(self, text: str, whole_word: bool = False, ph_spans: Optional[list[tuple[int, int]]] = None) -> bool:
        if not self.patterns or not text:
            return False
        if ph_spans is None:
            ph_spans = _find_placeholder_spans(text)
        return next(self._scan_candidates(text, whole_word, ph_spans), None) is not None

    def find_matches(self, text: str, whole_word: bool = False, ph_spans: Optional[list[tuple[int, int]]] = None) -> list[tuple[int, int, str]]:
        if not self.patterns or not text:
            return []
        if ph_spans is None:
            ph_spans = _find_placeholder_spans(text)
        candidates = list(self._scan_candidates(text, whole_word, ph_spans))
        if not candidates:
            return []
        if len(candidates) == 1:
            s, e, pid = candidates[0]
            return [(s, e, self.patterns[pid][1])]

        candidates.sort(key=lambda item: (-(item[1] - item[0]), item[0], item[2]))
        starts: list[int] = []
        ends: list[int] = []
        accepted: list[tuple[int, int, str]] = []
        patterns = self.patterns
        for s, e, pid in candidates:
            pos = bisect.bisect_left(starts, s)
            if pos < len(starts) and starts[pos] < e:
                continue
            if pos > 0 and ends[pos - 1] > s:
                continue
            starts.insert(pos, s)
            ends.insert(pos, e)
            accepted.append((s, e, patterns[pid][1]))
        accepted.sort(key=lambda item: item[0])
        return accepted


RULES = [
    # (category, regex, group, validator, flags, required_features)
    ("PRIVKEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\\Z)", 0, None, re.S, FEAT_DASH_UNDER),
    ("PASSWORD", r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@", 1, not_placeholder, 0, FEAT_AT | FEAT_COLON_EQ),
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, None, 0, FEAT_AT | FEAT_DOT),
    ("TOKEN", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, None, 0, FEAT_NONE),
    ("TOKEN", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0, None, 0, FEAT_NONE),
    ("TOKEN", r"\bhf_[A-Za-z0-9]{30,}\b", 0, None, 0, FEAT_DASH_UNDER),
    ("TOKEN", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", 0, None, 0, FEAT_DASH_UNDER),
    ("TOKEN", r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+", 0, None, 0, FEAT_DOT),
    ("TOKEN", r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|glpat|xox[baprs])[-_][A-Za-z0-9_\-]{12,}\b", 0, None, 0, FEAT_DASH_UNDER),
    ("TOKEN", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0, None, 0, FEAT_DOT),
    ("TOKEN", r"\bBearer\s+([A-Za-z0-9_\-\.=]{16,})", 1, not_placeholder, 0, FEAT_NONE),
    ("PASSWORD",
     r"""[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*["']?([^\s"',;]{6,})""",
     1, kv_ok, re.I, FEAT_COLON_EQ),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban_ok, 0, FEAT_DIGIT),
    ("ACCOUNT", r"\b(?:account|acct|a/c|iban|konto|konta)\b\s*(?:no\.?|number|nr\.?|#)?\s*[:=#]?\s*((?:[A-Z]{2}\d{2} ?)?\d[\d -]{5,30}\d)", 1, not_placeholder, re.I, FEAT_DIGIT),
    ("SSN", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0, None, 0, FEAT_DASH_UNDER | FEAT_DIGIT),
    ("PHONE", r"\b(?:phone|tel|telephone|mobile|cell|fax|whatsapp)\b\s*(?:no\.?|number|#)?\s*[:=]?\s*(\+?\d[\d ()./-]{5,18}\d)", 1, digits_between(6, 15), re.I, FEAT_DIGIT),
    ("CARD", r"\b\d(?:[ -]?\d){12,18}\b", 0, luhn_ok, 0, FEAT_DIGIT),
    ("APIKEY", r"\b[A-Za-z0-9]{32}\b", 0, looks_random, 0, FEAT_DIGIT),
    ("APIKEY", r"\b[A-Fa-f0-9]{40,64}\b", 0, None, 0, FEAT_NONE),
    ("IP", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, private_ip, 0, FEAT_DIGIT | FEAT_DOT),
    ("IP", r"\b(?:f[cd][0-9a-f]{2}|fe80):(?:[0-9a-f:]*:[0-9a-f]+|:)(?!:)", 0, None, re.I, FEAT_COLON_EQ),
    ("PHONE", r"(?<![\w.+-])\+\d[\d ()./-]{7,18}\d(?!\w)", 0, digits_between(8, 15), 0, FEAT_PLUS | FEAT_DIGIT),
    ("PHONE", r"(?<![\w.+/-])\(?\d{2,4}\)?[ .-]\d{2,4}[ .-]\d{2,4}(?:[ .-]\d{2,4})?(?![\w/-])", 0, phone_sep_ok, 0, FEAT_DIGIT),
]
PH = re.compile(r"\[\[[A-Z][A-Z0-9_]*_\d+\]\]")
PH_IDX = re.compile(r"^\[\[([A-Z][A-Z0-9_]*)_(\d+)\]\]$")
B64_CAND = re.compile(r"\b[A-Za-z0-9+/]{24,}(?:={1,2}(?![A-Za-z0-9+/=])|\b)")

# ---------------------------------------------------------------- brand & color
BRAND_PALETTE = {
    "cloakroom_pine": ("#12392F", (18, 57, 47)),
    "stamp_red": ("#E8432A", (232, 67, 42)),
    "stamp_red_dark": ("#FF6A4D", (255, 106, 77)),
    "ticket_cream": ("#F5EFE2", (245, 239, 226)),
    "ink": ("#0F1A17", (15, 26, 23)),
    "pine_mint": ("#8FD0B3", (143, 208, 179)),
    "slate": ("#56635D", (86, 99, 93)),
    "perforation": ("#D9D1BF", (217, 209, 191)),
}
COLOR_MODES = ("auto", "always", "never")
ANSI_RESET = "\x1b[0m"
ANSI_TICKET = "\x1b[1;38;2;255;106;77m"     # Dark-Ground Stamp Red (#FF6A4D)
ANSI_PINE_MINT = "\x1b[1;38;2;143;208;179m" # Pine Mint (#8FD0B3)
ANSI_PERFORATION = "\x1b[38;2;217;209;191m" # Perforation (#D9D1BF)
ANSI_SLATE = "\x1b[38;2;86;99;93m"          # Slate (#56635D)


def should_use_color(color_mode: str = "auto", stream=None) -> bool:
    """Return whether ANSI truecolor output is active for color_mode and stream."""
    mode = (color_mode or "auto").lower()
    if mode not in COLOR_MODES:
        raise ValueError(f"prosze: --color must be auto, always or never (got {color_mode!r})")
    if mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    target = sys.stdout if stream is None else stream
    isatty = getattr(target, "isatty", None)
    try:
        return bool(isatty and isatty())
    except Exception:
        return False


def highlight_tickets(text: str) -> str:
    """Highlight [[CAT_N]] placeholders in truecolor Dark-Ground Stamp Red (#FF6A4D)."""
    if "[[" not in text:
        return text
    return PH.sub(lambda m: f"{ANSI_TICKET}{m.group(0)}{ANSI_RESET}", text)


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


def _is_binary_stream(stream) -> bool:
    return isinstance(stream, (io.RawIOBase, io.BufferedIOBase)) or "b" in str(getattr(stream, "mode", ""))


def _write_stream_text(out_stream, text: str, binary_out: bool) -> None:
    if not text:
        return
    out_stream.write(text.encode("utf-8") if binary_out else text)


def _iter_stream_chunks(in_stream, chunk_size: int):
    decoder = None
    while True:
        raw = in_stream.read(chunk_size)
        if not raw:
            if decoder is not None:
                tail = decoder.decode(b"", final=True)
                if tail:
                    yield tail, False
            yield "", True
            return
        if isinstance(raw, (bytes, bytearray)):
            if decoder is None:
                decoder = codecs.getincrementaldecoder("utf-8")("replace")
            text = decoder.decode(bytes(raw), final=False)
            if text:
                yield text, False
        else:
            yield raw, False


class Vault:
    def __init__(self, map_path: str, ephemeral: bool = False, passphrase: Optional[str] = None, strict_restore: bool = False):
        self.map_path = map_path
        self.ephemeral = ephemeral
        if passphrase is None:
            env_key = os.environ.get("PROSZE_KEY")
            if env_key:
                passphrase = env_key
        self.passphrase = passphrase
        self.strict_restore = strict_restore
        self.session_keys: set[str] = set()
        self.fwd, self.bwd, self.counters = {}, {}, {}
        self.rules = [(c, re.compile(p, f), g, v, req) for c, p, g, v, f, req in RULES]
        self.literals = []
        self.term_rules = []
        self.term_cats: set[str] = set()
        self.literals_dirty = False
        self.terms_dirty = False
        self._literals_ac = AhoCorasick(case_fold=False)
        self._terms_ac = AhoCorasick(case_fold=True)
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
            self.literals_dirty = True

    def add_term(self, spec):
        """'Acme Corp' or 'CUSTOMER=Acme Corp' (case-insensitive, whole words)."""
        m = re.match(r"^([A-Z][A-Z0-9_]{1,19})=(.+)$", spec.strip())
        cat, text = (m[1], m[2].strip()) if m else ("TERM", spec.strip())
        if not text:
            return
        self.term_rules.append((_fold_str(text), cat))
        self.term_cats.add(cat)
        self.terms_dirty = True
        for k, val in self.fwd.items():         # names already in a loaded map
            m2 = PH_IDX.match(k)
            if m2 and m2[1] == cat:
                self.fold[(cat, _fold_str(val))] = k

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
            k = self.bwd[value]
            self.session_keys.add(k)
            return k
        fk = (cat, _fold_str(value))
        if fk in self.fold:                     # same name, different capitalisation
            k = self.fold[fk]
            self.session_keys.add(k)
            return k
        n = self.counters[cat] = self.counters.get(cat, 0) + 1
        key = f"[[{cat}_{n}]]"
        self.bwd[value], self.fwd[key] = key, value
        if cat in self.term_cats:
            self.fold[fk] = key
        self.session_keys.add(key)
        return key

    def _ensure_literals_ac(self) -> None:
        if self.literals_dirty:
            self._literals_ac.build(self.literals)
            self.literals_dirty = False

    def _ensure_terms_ac(self) -> None:
        if self.terms_dirty:
            self._terms_ac.build(self.term_rules)
            self.terms_dirty = False

    def _replace_ac(self, text: str, ac: AhoCorasick, whole_word: bool) -> str:
        if not text:
            return text
        matches = ac.find_matches(text, whole_word=whole_word)
        if not matches:
            return text
        out, last = [], 0
        for start, end, cat in matches:
            out.append(text[last:start])
            out.append(self.save(text[start:end], cat))
            last = end
        out.append(text[last:])
        return "".join(out)

    def _contains_secret(self, text: str) -> bool:
        with self.lock:
            ph_spans = _find_placeholder_spans(text)
            if self.literals:
                self._ensure_literals_ac()
                if self._literals_ac.has_any_match(text, whole_word=False, ph_spans=ph_spans):
                    return True
            features = scan_char_features(text)
            for cat, rx, g, val, req in self.rules:
                if (features & req) != req:
                    continue
                for m in rx.finditer(text):
                    v = m.group(g)
                    if v is None:
                        continue
                    s, e = m.span(g)
                    if e == s or (val and not val(v)):
                        continue
                    return True
            if self.term_rules:
                self._ensure_terms_ac()
                if self._terms_ac.has_any_match(text, whole_word=True, ph_spans=ph_spans):
                    return True
            return False

    def _scan_base64_secrets(self, text: str) -> str:
        if len(text) < 24:
            return text
        out, last = [], 0
        for m in B64_CAND.finditer(text):
            cand = m.group(0)
            s, e = m.span()
            if s < last:
                continue
            if s >= 2 and text[s - 2:s] == "[[" and e + 2 <= len(text) and text[e:e + 2] == "]]":
                continue
            rem = len(cand) % 4
            if rem == 1:
                continue
            pad = "=" * ((4 - rem) % 4)
            try:
                raw_bytes = base64.b64decode(cand + pad, validate=True)
            except Exception:
                continue
            if not is_printable_text(raw_bytes):
                continue
            try:
                decoded = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not self._contains_secret(decoded):
                continue
            out.extend((text[last:s], self.save(cand, "ENCODED")))
            last = e
        out.append(text[last:])
        return "".join(out)

    def redact(self, text):
        """Returns (safe_text, number_of_replacements)."""
        with self.lock:
            before, before_n = self._hits, len(self.fwd)
            if self.literals:
                self._ensure_literals_ac()
                text = self._replace_ac(text, self._literals_ac, whole_word=False)
            features = scan_char_features(text)
            for cat, rx, g, val, req in self.rules:
                if (features & req) != req:
                    continue
                text = self._apply(text, cat, rx, g, val)
            if self.term_rules:
                self._ensure_terms_ac()
                text = self._replace_ac(text, self._terms_ac, whole_word=True)
            text = self._scan_base64_secrets(text)
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
            k = m.group(0)
            if self.strict_restore and k not in self.session_keys:
                return k
            v = self.fwd.get(k)
            if v is None:
                return k
            return json.dumps(v, ensure_ascii=False)[1:-1] if json_escaped else v
        return PH.sub(sub, text)

    def redact_stream(self, in_stream, out_stream, chunk_size: int = 65536, color: bool = False) -> int:
        """Stream-redact in_stream to out_stream using a sliding window."""
        if chunk_size <= 0:
            chunk_size = 65536
        begin_block_cap = 65536
        ws_window = 4096
        max_unsplit = max(chunk_size, begin_block_cap)
        binary_out = _is_binary_stream(out_stream)

        total_hits = 0
        buf = ""

        def flush_prefix(count: int) -> None:
            nonlocal buf, total_hits
            if count <= 0:
                return
            prefix = buf[:count]
            buf = buf[count:]
            safe, n = self.redact(prefix)
            total_hits += n
            out_text = highlight_tickets(safe) if color else safe
            _write_stream_text(out_stream, out_text, binary_out)

        for chunk, at_eof in _iter_stream_chunks(in_stream, chunk_size):
            if chunk:
                buf += chunk
            if at_eof:
                if buf:
                    flush_prefix(len(buf))
                break
            if not buf:
                continue

            last_begin = buf.rfind("-----BEGIN ")
            min_block_end = 0
            if last_begin != -1:
                end_pos = buf.find("-----END ", last_begin + 11)
                end_close = buf.find("-----", end_pos + 9) if end_pos != -1 else -1
                if end_close == -1:
                    if (len(buf) - last_begin) < begin_block_cap:
                        continue
                else:
                    min_block_end = end_close + 5

            split: Optional[int] = None
            nl = buf.rfind("\n")
            if nl != -1 and (len(buf) - (nl + 1)) <= ws_window and (nl + 1) >= min_block_end:
                split = nl + 1
            else:
                win_start = max(min_block_end, len(buf) - ws_window)
                for idx in range(len(buf) - 1, win_start - 1, -1):
                    if buf[idx] in (" ", "\t", "\r", "\n"):
                        split = idx + 1
                        break
                if split is None and nl != -1 and (nl + 1) >= min_block_end:
                    split = nl + 1

            if split is None:
                block_len = (len(buf) - last_begin) if last_begin != -1 else len(buf)
                if block_len >= max_unsplit or len(buf) >= max_unsplit * 2:
                    split = len(buf)
                else:
                    continue

            flush_prefix(split)

        if hasattr(out_stream, "flush"):
            out_stream.flush()
        return total_hits

    def restore_stream(self, in_stream, out_stream, chunk_size: int = 65536) -> None:
        """Stream-restore in_stream to out_stream, holding back split placeholders."""
        if chunk_size <= 0:
            chunk_size = 65536
        hold_window = 64
        binary_out = _is_binary_stream(out_stream)
        buf = ""

        def flush_prefix(count: int) -> None:
            nonlocal buf
            if count <= 0:
                return
            prefix = buf[:count]
            buf = buf[count:]
            _write_stream_text(out_stream, self.restore(prefix), binary_out)

        for chunk, at_eof in _iter_stream_chunks(in_stream, chunk_size):
            if chunk:
                buf += chunk
            if at_eof:
                if buf:
                    flush_prefix(len(buf))
                break
            if not buf:
                continue

            win_start = max(0, len(buf) - hold_window)
            open_pos = buf.rfind("[[")
            hold_from = len(buf)
            if open_pos != -1 and open_pos >= win_start:
                if buf.find("]]", open_pos + 2) == -1:
                    hold_from = open_pos
            if hold_from == len(buf) and buf.endswith("["):
                hold_from = len(buf) - 1

            flush_prefix(hold_from)

        if hasattr(out_stream, "flush"):
            out_stream.flush()

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
    buf = getattr(sys.stdin, "buffer", None)
    if buf is not None:
        return buf.read().decode("utf-8", "replace")
    raw = sys.stdin.read()
    return raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw


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
