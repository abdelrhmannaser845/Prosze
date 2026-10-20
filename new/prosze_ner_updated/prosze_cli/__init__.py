"""Prosze CLI + Hermes Agent Plugin entry point.

Install:  pip install -e .
Run:     prosze --help          (CLI mode)
         prosze                 (interactive CLI chat)
         prosze redact < file  (pipe stdin through redaction)
         prosze plugin          (Hermes agent plugin info)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Optional

# ---- pull the real implementation from prosze_proxy.py -----------------
try:
    import prosze_proxy as _mod  # noqa: F401
except ImportError:
    import importlib.util

    _proj = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if _proj not in sys.path:
        sys.path.insert(0, _proj)

    _proxy_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "prosze_proxy.py")
    )
    if _proxy_path not in sys.modules:
        _spec = importlib.util.spec_from_file_location("prosze_proxy", _proxy_path)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        sys.modules["prosze_proxy"] = _mod
    else:
        _mod = sys.modules["prosze_proxy"]

Vault = _mod.Vault
PH = _mod.PH
read_stdin = _mod.read_stdin
walk = _mod.walk
make_handler = _mod.make_handler
ThreadingHTTPServer = _mod.ThreadingHTTPServer
BaseHTTPRequestHandler = _mod.BaseHTTPRequestHandler
_chat = _mod.chat


# ---- Hermes Agent plugin entrypoint hook --------------------------------
def register(ctx: object) -> None:
    """Plugin registration entry point for Hermes Agent."""
    try:
        import prosze_plugin
    except ImportError:
        _proj = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if _proj not in sys.path:
            sys.path.insert(0, _proj)
        import prosze_plugin
    prosze_plugin.register(ctx)


# ---- shared arg parsing -------------------------------------------------
def build_common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--map", default=".prosze-map")
    p.add_argument("--env", action="append", default=[])
    p.add_argument("--term", action="append", default=[])
    p.add_argument("--terms", action="append", default=[])
    p.add_argument("--no-ner", action="store_true", help="disable GLiNER name detection")
    return p


def build_vault(args: argparse.Namespace) -> Vault:
    v = Vault(getattr(args, "map", ".prosze-map"))
    if getattr(args, "no_ner", False):
        v._ner_attempted = True
    for p in getattr(args, "env", []):
        v.load_env(p)
    tf = list(getattr(args, "terms", []) or [])
    if os.path.exists(".prosze-terms"):
        tf.append(".prosze-terms")
    for p in tf:
        v.load_terms(p)
    for t in getattr(args, "term", []) or []:
        v.add_term(t)
    return v


# ---- CLI subcommand handlers -------------------------------------------
def cmd_chat(v: Vault) -> None:
    _chat(v)


def cmd_redact(v: Vault) -> None:
    safe, n = v.redact(read_stdin())
    sys.stdout.buffer.write(safe.encode("utf-8"))
    sys.stderr.write(f"prosze: {n} item(s) hidden\n")


def cmd_restore(v: Vault) -> None:
    sys.stdout.buffer.write(v.restore(read_stdin()).encode("utf-8"))


def cmd_check(v: Vault) -> None:
    _, n = v.redact(read_stdin())
    if n:
        sys.stderr.write(f"prosze: {n} sensitive item(s) found\n")
        sys.exit(1)


def cmd_run(v: Vault, cmd: list[str]) -> None:
    import shutil
    import subprocess
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
    sys.stdout.buffer.write(v.restore(res.stdout.decode("utf-8", "replace")).encode("utf-8"))
    sys.stderr.write(f"prosze: {total} item(s) hidden before sending\n")
    sys.exit(res.returncode)


def cmd_proxy(v: Vault, listen: str, upstream: str, verbose: bool) -> None:
    host, _, port = listen.rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write("[prosze] WARNING: non-loopback address exposes your secret map to the network.\n")
    try:
        listen_port = int(port)
        if not 1 <= listen_port <= 65535:
            raise ValueError
        handler = make_handler(v, upstream, verbose)
        srv = ThreadingHTTPServer((host or "127.0.0.1", listen_port), handler)
    except (OSError, ValueError) as exc:
        sys.exit(f"prosze: invalid proxy address or upstream: {exc}")
    sys.stderr.write(f"[prosze] {listen} -> {upstream}   (map: {v.map_path})\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_plugin(v: Vault) -> None:
    """Print Hermes Agent plugin status and capabilities."""
    try:
        import prosze_plugin
        print(prosze_plugin.handle_prosze_command())
    except Exception as exc:
        sys.stderr.write(f"prosze plugin error: {exc}\n")


# ---- CLI ----------------------------------------------------------------
def cli_main(argv: Optional[list[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    if "--" in argv:
        i = argv.index("--")
        cli_args, cmd = argv[:i], argv[i + 1:]
    else:
        cli_args, cmd = argv, []

    if not cli_args:
        cli_args = ["chat"]

    common = build_common_parser()
    ap = argparse.ArgumentParser(
        prog="prosze",
        description="Remove sensitive details from prompts before they reach an AI (Hermes Agent & CLI).",
    )
    sub = ap.add_subparsers(dest="cmd")
    for name in ("chat", "redact", "restore", "check", "run"):
        sub.add_parser(name, parents=[common])
    px = sub.add_parser("proxy", parents=[common])
    px.add_argument("--listen", default="127.0.0.1:8787")
    px.add_argument("--upstream", default="https://api.anthropic.com")
    px.add_argument("--verbose", action="store_true")

    sub.add_parser("plugin", parents=[common], help="Show Hermes Agent plugin status")

    a = ap.parse_args(cli_args)
    if not a.cmd:
        ap.print_help()
        return
    v = build_vault(a)

    if a.cmd == "chat":
        cmd_chat(v)
    elif a.cmd == "redact":
        cmd_redact(v)
    elif a.cmd == "restore":
        cmd_restore(v)
    elif a.cmd == "check":
        cmd_check(v)
    elif a.cmd == "run":
        cmd_run(v, cmd)
    elif a.cmd == "proxy":
        cmd_proxy(v, a.listen, a.upstream, a.verbose)
    elif a.cmd == "plugin":
        cmd_plugin(v)
    else:
        ap.print_help()


# ---- Hermes config readers (best-effort, non-fatal) ------------------------
_HERMES_AUTH = os.path.expanduser("~/AppData/Local/hermes/auth.json")
_HERMES_CONFIG = os.path.expanduser("~/AppData/Local/hermes/config.yaml")


def _read_hermes_api_key() -> str:
    """Try to pull an API key from Hermes's auth.json."""
    try:
        with open(_HERMES_AUTH, encoding="utf-8") as f:
            auth = json.load(f)
    except (OSError, json.JSONDecodeError):
        return ""

    providers = auth.get("providers") or {}
    for name in ("upstage", "solar", "nous", "openai", "anthropic"):
        entry = providers.get(name)
        if isinstance(entry, list) and entry:
            e = entry[0]
        elif isinstance(entry, dict):
            e = entry
        else:
            continue
        for field in ("api_key", "access_token", "agent_key"):
            val = e.get(field)
            if val and len(val) > 10:
                return val
        env_var = e.get("key_env")
        if env_var:
            return os.environ.get(env_var, "")
    return ""


def _read_hermes_base_url() -> str:
    """Try to read Hermes's configured AI base URL from config.yaml."""
    try:
        with open(_HERMES_CONFIG, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    m = re.search(r"base_url:\s*[\"']?([^\"'#\n]+)", text)
    if m:
        return m.group(1).strip().rstrip("/")
    return ""


def _read_hermes_model() -> str:
    """Try to read Hermes's default model from config.yaml."""
    try:
        with open(_HERMES_CONFIG, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    m = re.search(r"^\s*model:\s*\n\s+default:\s*[\"']?([^\"'#\n]+)", text, re.M)
    if m:
        return m.group(1).strip()
    m = re.search(r"^\s*model:\s*[\"']?([^\"'#\n]+)", text, re.M)
    if m:
        return m.group(1).strip()
    return ""


# ---- console script entry point ----------------------------------------
def main() -> None:
    cli_main()


if __name__ == "__main__":
    main()
