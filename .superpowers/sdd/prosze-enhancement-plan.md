# Prosze Enhancement Plan

## Global Constraints

- Keep the privacy boundary local: outbound content must be redacted before forwarding, and inbound content restored only from the local vault.
- Preserve the existing CLI commands and Python 3.11 compatibility.
- Keep UI and proxy changes in separate files so they can be integrated independently.
- Do not expose mapping values in normal status output or logs.
- Add or update focused tests for behavior changed by each task.

## Tasks

### Task 1: Improve terminal CUI

Improve `new/prosze_ner_updated/tui.py` for usability and resilience while preserving its existing slash commands and streaming privacy behavior. Use a clean terminal layout, clearer status/error presentation, safe vault display, and graceful non-interactive/terminal edge cases. Keep all UI-only changes in `tui.py` unless a tiny compatibility fix is required. Add focused tests only if needed.

### Task 2: Improve proxy

Improve `new/prosze_ner_updated/prosze_proxy.py` at the proxy boundary. Preserve existing redaction/restoration semantics and supported OpenAI/Anthropic/SSE behavior. Address correctness, robustness, and security issues found during review, including malformed requests, upstream failures, and response handling. Keep changes scoped to the proxy module and its direct tests.

### Task 3: Test the application

Add a focused automated test suite for the Python package under `new/prosze_ner_updated/tests/`. Cover vault redaction/restoration, JSON walking, SSE restoration, CLI smoke behavior, and a local proxy round trip without external network calls. Tests must be deterministic and avoid downloading GLiNER or contacting remote services.

