# Prosze

**Hide sensitive details from your prompts _before_ they reach an AI.**

Prosze is a local privacy shield: it redacts secrets, names, and PII from your text using regex rules, checksums, and heuristic name detection — **no AI needed for the redaction itself**. When the AI replies using the placeholders, Prosze restores the real values.

```
your prompt ──▶ prosze (redact) ──▶ AI ──▶ prosze (restore) ──▶ answer with real values
```

## Features

- **Automatic detection** — phones, bank accounts / IBANs, emails, credit cards, SSNs, API keys / tokens / passwords, private keys, private IPs
- **Name detection** — people, companies, customers, and projects found by capitalisation heuristics, context words (Dr, Dear, customer…), company suffixes (Inc, GmbH, Sp. z o.o.), and a built-in first-name dictionary — no AI model required
- **Manual terms** — list names, projects, or companies via `--term` / `--terms` for exact matches
- **Reversible mapping** — a local `.prosze-map` file keeps the placeholder↔real mapping so replies can be accurately restored
- **.env integration** — load and hide every value from `.env` files
- **Multiple interfaces** — C++ CLI, Python CLI, AI proxy server, interactive TUI with Hermes connector

## Project Structure

```
prosze/
├── prosze/                 # Visual Studio C++ project
│   └── Application.cpp     # Self-contained C++17 CLI (single file, no deps)
├── new/prosze_ner_updated/  # Python package with enhanced features
│   ├── prosze_proxy.py      # Python redaction engine + AI proxy server
│   ├── hermes_connector.py  # Continuous streaming AI connector
│   ├── tui.py               # Interactive Hermes-style terminal UI
│   ├── prosze_cli/          # CLI entry point package
│   ├── pyproject.toml       # Python packaging configuration
│   └── prosze.cpp           # Enhanced C++ version with name detection
├── NER-CPP/                 # Reference NER library (upstream, read-only)
└── README.md
```

## Quick Start

### C++ CLI (zero dependencies)

Build the single-file C++ tool:

```bash
# Linux / macOS
g++ -std=c++17 -O2 -o prosze prosze/Application.cpp

# Windows (MSVC)
cl /std:c++17 /O2 /EHsc prosze\Application.cpp

# Windows (Visual Studio)
# Open prosze/prosze.vcxproj and build (Debug or Release, x64)
```

### Python CLI & Proxy

```bash
cd new/prosze_ner_updated
pip install -e .

# Optional: enable local GLiNER model for automatic name detection
pip install -r requirements-ner.txt
```

## Usage

### Commands

```bash
# Interactive chat mode — paste a prompt, get the safe version, paste the reply, get real text back
prosze chat

# Redact stdin and print the safe version
prosze redact < prompt.txt

# Restore placeholders back to real values
prosze restore < reply.txt

# Check if anything sensitive is found (exit code 1 if yes)
prosze check < prompt.txt

# Redact stdin and args, run a command, restore its output
prosze run [options] -- curl -X POST https://api.example.com/chat
```

### Options

| Option | Description |
|---|---|
| `--term "Acme Corp"` | Hide this exact name (repeatable) |
| `--term CUSTOMER="Acme Corp"` | Same, but placeholder becomes `[[CUSTOMER_1]]` |
| `--terms FILE` | One term per line, optional `LABEL=value`, `#` comments |
| `--env FILE` | Also hide every value from a `.env` file |
| `--map FILE` | Mapping file path (default: `.prosze-map`) |
| `--names LEVEL` | Name finder level: `off` \| `strict` \| `normal` (default) \| `aggressive` |
| `--explain` | Print what was hidden (placeholder = real value) to stderr |

> **Note:** `.prosze-terms` is loaded automatically if present in the current directory.

### Python-specific commands

```bash
# Start the local AI proxy (for Claude Code, SDKs, etc.)
prosze proxy --listen 127.0.0.1:8787 --upstream https://api.anthropic.com

# Interactive TUI with Hermes connector
prosze tui
```

## Example

**Input prompt:**
```
Dear Jan Kowalski,
Your account PL61 1090 1014 0000 0712 1981 2874 has been debited.
Contact us at jan.kowalski@acme.com or +48 601 234 567.
API key: sk-proj-abc123def456ghi789
```

**After `prosze redact`:**
```
Dear [[PERSON_1]],
Your account [[IBAN_1]] has been debited.
Contact us at [[EMAIL_1]] or [[PHONE_1]].
API key: [[TOKEN_1]]
```

The AI sees only placeholders. When it replies using `[[PERSON_1]]`, `prosze restore` puts the real values back.

## Proxy Mode

The proxy sits between your AI client and the API endpoint, automatically redacting outbound requests and restoring inbound responses — including SSE streams:

```bash
prosze proxy --listen 127.0.0.1:8787 --upstream https://api.anthropic.com

# Then point your AI client to http://127.0.0.1:8787 instead of the real API
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

## Security Notes

- The `.prosze-map` file contains real values in clear text — **keep it local and out of version control**
- Add `.prosze-map` to your `.gitignore`
- On Unix, the map file is created with mode `0600` (owner-only access)
- The proxy should only listen on `127.0.0.1` — binding to other addresses exposes your secret map

## How It Works

1. **Regex rules** detect structured secrets (emails, tokens, IBANs, etc.) with validators (Luhn check for cards, IBAN mod-97, entropy for API keys)
2. **Name heuristics** detect proper names by capitalisation patterns, honorifics, company suffixes, and a first-name dictionary — no ML model needed
3. **Optional GLiNER** (Python only) adds local neural NER for better name coverage
4. **Term lists** let you explicitly add names the heuristics might miss
5. Each detected value gets a unique placeholder like `[[EMAIL_1]]`, stored in a bidirectional map
6. On restore, placeholders are swapped back to real values

## License

See [LICENSE](NER-CPP/LICENSE) for the NER-CPP reference library. The prosze tool itself is provided as-is.
