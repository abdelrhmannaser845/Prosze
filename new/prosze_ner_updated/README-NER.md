# Automatic name detection (GLiNER)

`prosze_proxy.py` now supports model-based name detection without a manually maintained name list.
The GLiNER model runs locally; prompt text is not sent to a remote inference API. On the first use,
GLiNER downloads `urchade/gliner_small-v2.1` from Hugging Face and caches it for later runs.

## Install

```powershell
python -m pip install -r requirements-ner.txt
```

## Use

```powershell
Get-Content .\prompt.txt | python .\prosze_proxy.py redact
```

The first run may take longer while the model is downloaded and initialized. Detected names are
replaced with placeholders such as `[[PERSON_1]]`; the existing `.prosze-map` supports restoration.
The model recognizes likely people, organizations, companies, customers, and projects, but it is
not perfect. Review results before sending sensitive text to an external service.

To turn model-based recognition off for a command, pass `--no-ner`:

```powershell
Get-Content .\prompt.txt | python .\prosze_proxy.py redact --no-ner
```

## Hermes-Style Interactive CUI & Continuous API Connector

`tui.py` / `prosze tui` provides a terminal chat console styled after the Hermes Agent interface with an integrated zero-leak privacy shield:

```powershell
python tui.py
# or via CLI wrapper:
python prosze_main.py tui
```

### Key Features

- **Hermes Aesthetic**: Terminal interface with dark palette, status bar, and privacy shield alerts.
- **Continuous Multi-Turn AI Connector**: Maintains session history across turns while ensuring every outgoing message is redacted locally first.
- **On-the-Fly Streaming De-Redaction**: Streaming tokens from the LLM are de-redacted in real time across chunk boundaries, restoring original names and secrets on screen.
- **Automatic Hermes Discovery**: Detects credentials from `~/AppData/Local/hermes/auth.json` and model settings from `config.yaml` (supporting Nous Inference API, Upstage Solar, OpenAI, Anthropic, and local endpoints).
- **Interactive Slash Commands**:
  - `/model <name>`: Switch active model dynamically (e.g. `/model upstage/solar-mini4:free`).
  - `/models`: List available models from the provider.
  - `/vault`: Open/toggle the `.prosze-map` vault drawer to inspect active masked terms.
  - `/clear`: Clear conversation memory and reset dialogue.
  - `/system <prompt>`: Update system instructions.
  - `/copy`: Copy the latest assistant response to the clipboard.
  - `/help`: Display keyboard shortcuts and command reference.
  - `/quit` or `/exit`: Exit the console.

## Notes

- Existing regex detection and explicit `--term` / `--terms` behavior remain available.
- The standalone C++ `prosze.cpp` continues to use its built-in heuristic detector; this GLiNER
  integration is in the Python CLI/proxy path.
- Keep `.prosze-map` private because it contains original values.

