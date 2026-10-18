# Prosze

Prosze is a local privacy shield. It replaces sensitive values with placeholders before text is sent to an AI or another command, then restores those values in returned text. Redaction is deterministic and local; no AI model is required for the core rules.

```text
prompt -> prosze (redact) -> AI or command -> prosze (restore) -> answer
```

## Delivered architecture

- **Native C++ CLI core**: dependency-free redaction, restoration, `.env` and term loading, TSV map persistence, checks, chat, and safe direct process execution.
- **Native C++ proxy**: fast loopback HTTP proxy for plaintext `http://` upstreams. It redacts request bodies and restores response bodies, including SSE fragments.
- **Python proxy and CLI**: provider-rich behavior, HTTPS upstream support, optional GLiNER name detection, and the interactive terminal UI.
- **Privacy boundary**: the mapping file stays local. The proxy listens on loopback by default and sends only redacted content.

The native and Python paths use the same placeholder style, but their detection coverage is not identical. Use the Python path when you need HTTPS upstreams, provider-specific behavior, or GLiNER.

## Project structure

```text
prosze/
  Application.cpp       Native CLI and command dispatcher
  ProxyServer.h/.cpp    Native HTTP proxy implementation
  tests/                Deterministic C++ tests and fixtures
  prosze.vcxproj        Visual Studio project
new/prosze_ner_updated/
  prosze_proxy.py       Python CLI, redaction engine, and HTTPS-capable proxy
  tui.py                Interactive terminal UI
  hermes_connector.py   Optional streaming connector
  prosze_cli/            Packaged Python entry point
  tests/                Python tests
```

## Build

### Native C++ (Linux/macOS/MinGW)

`ProxyServer.cpp` is included by `Application.cpp`, so compile the application once:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze/Application.cpp -o prosze
```

On Windows MinGW, use `-lws2_32`:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze/Application.cpp -lws2_32 -o prosze.exe
```

### Native C++ (MSVC)

```bat
cl /std:c++17 /O2 /EHsc prosze\Application.cpp ws2_32.lib
```

Alternatively open `prosze/prosze.vcxproj` in Visual Studio and build the desired configuration. The native proxy requires Winsock linkage (`ws2_32.lib`).

### Python CLI and proxy

```bash
cd new/prosze_ner_updated
python -m pip install -e .
# Optional local NER support:
python -m pip install -r requirements-ner.txt
```

After installation, the packaged `prosze` command with no subcommand launches the Python interactive CUI. If an old executable is selected, reinstall the editable package and verify the command path with `where prosze` (Windows) or `which prosze` (Unix).

## Usage

The native binary and packaged Python command provide these core operations:

```bash
# Native interactive chat when no subcommand is supplied
prosze

# Redact or restore standard input
prosze redact < prompt.txt
prosze restore < reply.txt

# Exit with 1 when sensitive content is found
prosze check < prompt.txt

# Redact stdin and command arguments, run directly, then restore output
prosze run -- curl -X POST http://example.test/chat
```

Common options are supported by the native CLI and Python CLI:

```text
--term "Acme Corp"       Add an exact term (repeatable)
--term CUSTOMER="Acme"   Add a labelled term
--terms FILE             Load terms from a file
--env FILE               Hide values loaded from a .env file
--map FILE               Select the local mapping file
--names LEVEL            off, strict, normal, or aggressive
--explain                 Print placeholder details to stderr
```

`.prosze-terms` is loaded automatically when present in the current directory. The native `run` command uses direct process execution rather than a shell, so command arguments are not reinterpreted by shell metacharacters.

## Proxy modes

### Native C++ plaintext proxy

Build the native binary, then point it at a plaintext HTTP upstream:

```bash
prosze proxy --listen 127.0.0.1:8787 --upstream http://127.0.0.1:9000
```

The native proxy is loopback-only by default, supports JSON and SSE-style response data, applies framing and timeout limits, requests identity encoding, and closes malformed connections. It does **not** provide HTTPS upstream support. Do not pass an `https://` upstream to this mode.

### Python proxy

Use the installed Python command for HTTPS and provider-specific clients:

```bash
prosze proxy --listen 127.0.0.1:8787 --upstream https://api.anthropic.com
```

Point a compatible client at `http://127.0.0.1:8787`. The Python proxy handles HTTPS upstream connections and preserves provider-rich JSON/SSE behavior. Both proxy implementations should bind to `127.0.0.1`; binding publicly exposes the local mapping boundary.

### Interactive Python UI

```bash
prosze tui
```

The UI falls back cleanly in non-interactive terminals. `/redact` performs local redaction without requiring an API key; network-backed chat requires the configured provider credentials.

## Example

```text
Input:  Contact Jan Kowalski at jan.kowalski@example.com; token sk-example123.
Safe:   Contact [[PERSON_1]] at [[EMAIL_1]]; token [[TOKEN_1]].
```

The mapping file translates placeholders back to the original values when a response is restored.

## Tests

Run the Python suite from the repository root:

```powershell
python -m unittest discover -s new/prosze_ner_updated/tests -v
```

Build and run the native tests:

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\Application.cpp -lws2_32 -o .tmp-prosze.exe
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\tests\ApplicationTests.cpp -lws2_32 -o .tmp-prosze-tests.exe
.\.tmp-prosze-tests.exe
```

The tests are deterministic and do not contact external services or download models. Remove the temporary executables after local testing.

## Security and limitations

- `.prosze-map` contains original values in clear text. Keep it local, restrict access, and add it to `.gitignore`.
- The proxy must remain on loopback unless you have designed a separate protected deployment boundary.
- Redaction is heuristic for names and cannot guarantee detection of every secret. Add important values with `--term`, `--terms`, or `--env`.
- Native proxy support is plaintext HTTP only; use the Python proxy for HTTPS upstreams.
- The native C++ and Python implementations are compatible in placeholder/map intent, but detection details can differ.

## License

See [LICENSE](NER-CPP/LICENSE) for the reference NER-CPP library. The Prosze tool is provided as-is.
