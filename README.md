# Prosze

Prosze is a local privacy shield. It replaces sensitive values with placeholders before text is sent to an AI or another command, then restores those values in returned text. Redaction is deterministic and local; no AI model is required for the core rules.

```text
prompt -> prosze (redact) -> AI or command -> prosze (restore) -> answer
```

## Delivered architecture

- **Native C++ CLI core**: dependency-free redaction, restoration, `.env` and term loading, TSV map persistence, checks, chat, and safe direct process execution.
- **Python CLI**: provider-rich behavior, optional GLiNER name detection, and the interactive terminal UI.
- **Privacy boundary**: the mapping file stays local. Only redacted content ever leaves this tool.

## Project structure

```text
prosze/
  Application.cpp       Native CLI and command dispatcher
  tests/                Deterministic C++ tests and fixtures
  prosze.vcxproj        Visual Studio project
new/prosze_ner_updated/
  prosze_core.py        Core Vault, redaction engine, and chat session
  prosze_main.py        Console-script wrapper
  prosze_cli/            Packaged Python entry point
  tests/                Python tests
```

## Build

### Native C++ (Linux/macOS/MinGW)

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze/Application.cpp -o prosze
```

### Native C++ (MSVC)

```bat
cl /std:c++17 /O2 /EHsc prosze\Application.cpp
```

Alternatively open `prosze/prosze.vcxproj` in Visual Studio and build the desired configuration.

### Python CLI

```bash
cd new/prosze_ner_updated
python -m pip install -e .
# Optional local NER support:
python -m pip install -r requirements-ner.txt
```

After installation, the packaged `prosze` command with no subcommand launches the Python interactive chat. Verify the command path with `where prosze` (Windows) or `which prosze` (Unix).

## Usage

The native binary and packaged Python command provide these core operations:

```bash
# Interactive chat when no subcommand is supplied
prosze

# Redact or restore standard input
prosze redact < prompt.txt
prosze restore < reply.txt

# Exit with 1 when sensitive content is found
prosze check < prompt.txt

# Redact stdin and command arguments, run directly, then restore output
prosze run -- curl -X POST http://example.test/chat
```

Common options:

```text
--term "Acme Corp"       Add an exact term (repeatable)
--term CUSTOMER="Acme"   Add a labelled term
--terms FILE             Load terms from a file
--env FILE               Hide values loaded from a .env file
--map FILE               Select the local mapping file
--names LEVEL            off, strict, normal, or aggressive  (native C++ only)
--explain                 Print placeholder details to stderr (native C++ only)
```

`.prosze-terms` is loaded automatically when present in the current directory. The native `run` command uses direct process execution rather than a shell, so command arguments are not reinterpreted by shell metacharacters.

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
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\Application.cpp -o .tmp-prosze.exe
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\tests\ApplicationTests.cpp -o .tmp-prosze-tests.exe
.\.tmp-prosze-tests.exe
```

The tests are deterministic and do not contact external services or download models. Remove the temporary executables after local testing.

## Security and limitations

- `.prosze-map` contains original values in clear text. Keep it local, restrict access, and add it to `.gitignore`.
- Redaction is heuristic for names and cannot guarantee detection of every secret. Add important values with `--term`, `--terms`, or `--env`.
- The native C++ and Python implementations are compatible in placeholder/map intent, but detection details can differ.

## License

See [LICENSE](NER-CPP/LICENSE) for the reference NER-CPP library. The Prosze tool is provided as-is.
