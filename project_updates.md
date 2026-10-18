# Project Updates

## Overview

The project was completed and enhanced using three independent AGY subagents followed by focused reviews, fix loops, and final integration validation.

## Agent 1: CUI Improvements

Area: `new/prosze_ner_updated/tui.py`

- Improved the Hermes-style terminal layout with clearer separators, status presentation, and responsive sizing.
- Added graceful handling for non-interactive terminals by using the existing CLI fallback.
- Improved notices, API failures, cancellation messages, and unexpected-error handling.
- Added safe vault summaries that display `<hidden>` instead of real values or secret metadata.
- Preserved existing slash commands and added consistent `/copy` documentation and behavior.
- Added focused tests for CUI fallback routing, `/copy` documentation, and vault privacy.

Review fixes:

- Restored the non-interactive fallback after the first review identified a regression.
- Removed secret-length metadata from vault summaries.
- Documented `/copy` in the banner and help output.

## Agent 2: Proxy Improvements

Area: `new/prosze_ner_updated/prosze_proxy.py`

- Added strict request framing validation.
- Rejected ambiguous `Content-Length` and `Transfer-Encoding` combinations.
- Added a 16 MiB request-body limit and chunk validation.
- Added safer upstream URL and listen-address validation.
- Improved hop-by-hop header filtering and upstream response handling.
- Ensured malformed request errors close the client connection.
- Fixed upstream path-prefix joining so exactly one slash is used.
- Preserved SSE metadata and restored placeholders split across events or chunks.
- Updated stream finalization so held partial placeholder fragments are not silently dropped.
- Preserved OpenAI-compatible and Anthropic-compatible proxy behavior.

Review fixes:

- Added connection closure after malformed framing.
- Corrected prefixed upstream paths.
- Fixed final SSE fragment flushing.
- Added direct tests for these boundary cases.

## Agent 3: Application Testing

Area: `new/prosze_ner_updated/tests/`

- Added deterministic standard-library tests for vault redaction, restoration, and persistence.
- Tested recursive JSON walking, metadata skipping, and base64 protection.
- Tested SSE restoration across split placeholders and byte chunks.
- Added CLI help, redact, and restore smoke tests.
- Added a local proxy round-trip test without external network access.
- Added CUI tests for fallback behavior, `/copy`, and safe vault display.
- Relocated proxy boundary tests into the shared `tests/` directory so test discovery includes them.
- Prevented GLiNER downloads by disabling NER in tests.

## Integration Review

The review agents checked specification compliance, privacy behavior, proxy correctness, test determinism, and packaged CLI integration.

- Fixed packaged `prosze proxy` handling so invalid upstreams, ports, and hostnames exit with concise errors instead of tracebacks.
- Confirmed the normal proxy startup path remains available.
- Confirmed no test contacts external services or downloads models.

## Validation

Final validation completed successfully:

```powershell
python -m unittest discover -s new/prosze_ner_updated/tests -v
python -m compileall -q new/prosze_ner_updated
```

- 13 tests passed.
- Python compilation passed.
- Invalid proxy addresses exit cleanly without tracebacks.
- `git diff --check` passed.

## Bare Command Launch

The CLI entry point now launches the interactive CUI when `prosze` is run without a subcommand. Existing commands such as `prosze redact`, `prosze restore`, `prosze proxy`, and `prosze tui` remain available. A regression test confirms that an empty argument list dispatches to the TUI without consuming unrelated process arguments.


## Project Completion Agents

### Review agent

- Compared the README contract with the checked-in implementation and identified the missing native proxy, C++ process-execution risks, compressed-response handling, and test gaps.
- Established the delivery boundary: native C++ for deterministic core behavior and plaintext HTTP proxying; Python for HTTPS and provider-specific behavior.

### C++ core agent

- Updated `prosze/Application.cpp` so bare native invocation launches chat, `run` executes commands directly without shell construction, and exit codes are preserved.
- Added native C++ tests and a TSV map fixture covering redaction, restoration, `.env`/map behavior, process forwarding, exit status, and bare invocation.
- Verified native compilation, core tests, redaction/restoration, process execution, bare chat, and whitespace checks on Windows.

### Proxy agent

- Added `prosze/ProxyServer.h` and `prosze/ProxyServer.cpp`, integrated `prosze proxy`, and implemented loopback HTTP forwarding with request redaction, response restoration, SSE handling, framing limits, identity encoding, and socket timeouts.
- Kept the native proxy explicitly limited to plaintext HTTP upstreams; the Python proxy remains the HTTPS/provider-rich path.
- Hardened Python proxy response handling by requesting identity encoding and failing closed if an upstream still returns compressed content.
- Added deterministic identity-encoding coverage and verified a native proxy round trip.

### Documentation agent

- Rewrote this README to describe the delivered native/Python split, bare-command behavior, build/link commands, proxy limitations, privacy boundary, usage, and test commands.
- Preserved the earlier history and added this chronological completion record.

### Completion validation

- Native C++ build and tests passed with Winsock linkage.
- Native proxy round-trip passed.
- Python suite passed with 14 tests, and Python modules compiled successfully.
- `git diff --check` passed for the delivered changes.
### 2026-10-18 — Native proxy concurrency enhancement

- The native C++ proxy now handles each accepted client on a detached worker thread, so a slow upstream request no longer blocks unrelated loopback clients.
- Revalidated the C++ build, native tests, Python suite, CLI redaction/restoration, command exit propagation, and bare chat startup after the change.
