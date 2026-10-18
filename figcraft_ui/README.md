# FigCraft CLI App UI

A modern, high-fidelity Terminal / CLI Application User Interface designed for **FigCraft** (the native Rust UI/UX design tool & Figma alternative).

## Overview

This package contains automated design scripts and assets to generate an authentic, dark-mode terminal CLI application UI inside FigCraft:

```
┌────────────────────────────────────────────────────────────────────────┐
│  🔴 🟡 🟢      ❯ prosze-shield : session_01 (zsh)       [● SHIELD ACTIVE] │
├────────────────────────────────────────────────────────────────────────┤
│   ____  ____   ___  ____  _____ _____                                  │
│  |  _ \|  _ \ / _ \/ ___||__  /| ____|   v1.4.2 [Zero-Leak Shield]     │
│  |_|   |_| \_\\___/|____//____||_____|                                 │
│                                                                        │
│  [GLiNER Active]  [Proxy: 127.0.0.1:8080]  [Vault: 14 Entities]       │
│                                                                        │
│  user@host ❯ prosze redact --in customer_report.txt --ai claude-sonnet │
│                                                                        │
│  🔒 SHIELD INTERCEPTED & REDACTED 3 HIGH-RISK TOKENS:                  │
│    • [[NAME_PERSON_1]]      Sarah Jenkins          (99.4% GLiNER)      │
│    • [[KEY_STRIPE_1]]       sk_live_51M...38x      (4.88 bit/sym)      │
│    • [[IBAN_DE_1]]          DE8937040044053201...  (MOD-97 Valid)      │
│                                                                        │
│  ✦ AI ASSISTANT (RESTORED ON THE FLY):                                 │
│    Analysis complete for Sarah Jenkins. The subscription billing on    │
│    account DE89370400440532013000 was reconciled...                    │
│                                                                        │
│  ❯ Type prompt or /help, /models, /vault, /exit... █                   │
├────────────────────────────────────────────────────────────────────────┤
│  MODE: ZERO-LEAK    UPSTREAM: api.anthropic.com    [Enter] Send [^C]   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## File Contents

* **`figcraft_cli_ui.json`**: The complete FigCraft automation command script (120 commands: `create_node`, `set_properties`, auto-layouts, tokens, colors, drop shadows, and typography).
* **`figcraft_cli_ui_preview.svg`**: Standalone SVG vector preview of the exact rendered UI, ready to open in any web browser or design editor.
* **`build_figcraft_ui.py`**: Python generator to customize, extend, and regenerate the JSON script and SVG preview.

---

## How to Use with FigCraft

### 1. Headless Generation (CLI)

Run the script headlessly through `figcraft-cli` to compile the native `.figcraft` document:

```bash
figcraft-cli run figcraft_cli_ui.json --out cli_app_ui.figcraft
```

### 2. Live Canvas Automation (Attached Desktop Mode)

Watch the UI assemble in real-time in the FigCraft desktop application:

1. Launch FigCraft desktop with a local control port:
   ```bash
   figcraft --control 7979
   ```

2. Execute the commands over the local bridge:
   ```bash
   figcraft-cli run figcraft_cli_ui.json --attach 7979
   ```

### 3. AI Agent & MCP Integration

FigCraft includes a native Model Context Protocol (MCP) server. You can register `figcraft-cli` with Claude Code, Cursor, or your AI assistant:

```json
{
  "mcpServers": {
    "figcraft": {
      "command": "figcraft-cli",
      "args": ["mcp"]
    },
    "figcraft-live": {
      "command": "figcraft-cli",
      "args": ["mcp", "--attach", "7979"]
    }
  }
}
```

Once connected, your AI assistant can query and manipulate the UI layers using:
* `create_node`: Add new terminal sections, dialog boxes, or widgets.
* `set_properties`: Adjust themes (e.g., Catppuccin, Nord, Gruvbox, Tokyo Night).
* `inspect_document`: Inspect hierarchy, dimensions, and typography.
* `screenshot` / `export`: Export PNG/SVG renders.

---

## Customizing the UI

To change color schemes, add commands, or tweak the terminal layout, edit `build_figcraft_ui.py` and run:

```bash
python figcraft_ui/build_figcraft_ui.py
```
