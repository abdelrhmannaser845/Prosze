"""Prosze CLI entry point.

Install:  pip install -e .
Run:      prosze --help          (CLI mode)
          prosze                 (interactive chat)
          prosze redact < file   (pipe stdin through redaction)
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

# Ensure the parent directory (containing prosze_core.py) is on the path.
_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from prosze_core import Vault, PH, read_stdin, walk, chat as _chat  # noqa: F401


# ---- shared arg parsing -------------------------------------------------
def build_common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--map", default=".prosze-map")
    p.add_argument("--env", action="append", default=[])
    p.add_argument("--term", action="append", default=[])
    p.add_argument("--terms", action="append", default=[])
    p.add_argument("--no-ner", action="store_true", help="disable GLiNER name detection")
    p.add_argument("--ephemeral", action="store_true", help="keep mapping in memory only, never write to disk")
    p.add_argument("--passphrase", default=None, metavar="KEY", help="encrypt mapping file with KEY (or PROSZE_KEY env)")
    p.add_argument("--strict-restore", action="store_true", help="only restore placeholders redacted during this session")
    p.add_argument("--stream", action="store_true", help="stream stdin/stdout in chunks")
    return p


def build_vault(args: argparse.Namespace) -> Vault:
    ephemeral = getattr(args, "ephemeral", False)
    passphrase = getattr(args, "passphrase", None)
    if not passphrase:
        env_key = os.environ.get("PROSZE_KEY")
        if env_key:
            passphrase = env_key
    strict_restore = getattr(args, "strict_restore", False)
    v = Vault(getattr(args, "map", ".prosze-map"), ephemeral=ephemeral, passphrase=passphrase, strict_restore=strict_restore)
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


def cmd_redact(v: Vault, stream: bool = False) -> None:
    if stream:
        n = v.redact_stream(sys.stdin.buffer, sys.stdout.buffer)
    else:
        safe, n = v.redact(read_stdin())
        sys.stdout.buffer.write(safe.encode("utf-8"))
    sys.stderr.write(f"prosze: {n} item(s) hidden\n")


def cmd_restore(v: Vault, stream: bool = False) -> None:
    if stream:
        v.restore_stream(sys.stdin.buffer, sys.stdout.buffer)
    else:
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
    v.strict_restore = True
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


def cmd_broker_serve(
    v: Vault,
    listen: str = "127.0.0.1:8787",
    upstream: str = "https://api.openai.com",
    allow_remote: bool = False,
) -> None:
    from prosze_cli.broker import create_broker_server, parse_listen_addr

    host, port = parse_listen_addr(listen)
    server = create_broker_server(v, host=host, port=port, upstream=upstream, allow_remote=allow_remote)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    display_host = f"[{bound_host}]" if ":" in bound_host else bound_host
    sys.stderr.write(f"prosze broker listening on http://{display_host}:{bound_port} -> {upstream}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _run_broker_command(subcmd: str, cmd: list[str], runner) -> None:
    if not cmd:
        sys.stderr.write(f"prosze: usage: prosze broker {subcmd} [options] -- command args...\n")
        sys.exit(1)
    try:
        rc = runner(cmd)
    except FileNotFoundError:
        sys.stderr.write(f"prosze: command not found: {cmd[0]}\n")
        sys.exit(1)
    except OSError as exc:
        sys.stderr.write(f"prosze: failed to start {cmd[0]}: {exc}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        return
    if rc:
        sys.exit(rc)


def cmd_broker_mcp(v: Vault, cmd: list[str]) -> None:
    from prosze_cli.mcp import MCPBroker

    _run_broker_command("mcp", cmd, MCPBroker(v).run_stdio_bridge)


def cmd_broker_wrap(v: Vault, cmd: list[str]) -> None:
    from prosze_cli.mcp import run_interactive_wrap

    _run_broker_command("wrap", cmd, lambda c: run_interactive_wrap(v, c))


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
        description="Remove sensitive details from prompts before they reach an AI.",
    )
    sub = ap.add_subparsers(dest="cmd")
    for name in ("chat", "redact", "restore", "check", "run"):
        sub.add_parser(name, parents=[common])

    broker_parser = sub.add_parser("broker", help="privacy broker gateways and wrappers")
    broker_sub = broker_parser.add_subparsers(dest="broker_cmd")
    serve_parser = broker_sub.add_parser(
        "serve",
        parents=[common],
        help="run local HTTP/SSE privacy gateway",
    )
    serve_parser.add_argument(
        "--listen",
        default="127.0.0.1:8787",
        help="listen address host:port (default: 127.0.0.1:8787)",
    )
    serve_parser.add_argument(
        "--upstream",
        default="https://api.openai.com",
        help="upstream AI API base URL (default: https://api.openai.com)",
    )
    serve_parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow binding to non-loopback hosts",
    )
    broker_sub.add_parser(
        "mcp",
        parents=[common],
        help="run stdio JSON-RPC 2.0 MCP privacy broker",
    )
    broker_sub.add_parser(
        "wrap",
        parents=[common],
        help="wrap an interactive CLI session with redaction and strict restoration",
    )

    a = ap.parse_args(cli_args)
    if not a.cmd:
        ap.print_help()
        return
    if a.cmd == "broker" and not getattr(a, "broker_cmd", None):
        broker_parser.print_help()
        return

    try:
        v = build_vault(a)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)

    if a.cmd == "chat":
        cmd_chat(v)
    elif a.cmd == "redact":
        cmd_redact(v, stream=getattr(a, "stream", False))
    elif a.cmd == "restore":
        cmd_restore(v, stream=getattr(a, "stream", False))
    elif a.cmd == "check":
        cmd_check(v)
    elif a.cmd == "run":
        cmd_run(v, cmd)
    elif a.cmd == "broker" and a.broker_cmd == "serve":
        try:
            cmd_broker_serve(
                v,
                listen=a.listen,
                upstream=a.upstream,
                allow_remote=a.allow_remote,
            )
        except ValueError as exc:
            sys.stderr.write(f"{exc}\n")
            sys.exit(1)
    elif a.cmd == "broker" and a.broker_cmd == "mcp":
        cmd_broker_mcp(v, cmd)
    elif a.cmd == "broker" and a.broker_cmd == "wrap":
        cmd_broker_wrap(v, cmd)
    else:
        ap.print_help()


# ---- console script entry point ----------------------------------------
def main() -> None:
    cli_main()


if __name__ == "__main__":
    main()
