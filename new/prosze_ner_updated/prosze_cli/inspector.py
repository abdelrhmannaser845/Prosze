"""Local loopback Cloakroom Ticket web inspector (`prosze ui`).

Provides:
  - InspectorServer: loopback-only ThreadingHTTPServer exposing `/` and JSON APIs
  - create_inspector_server: construct and validate an InspectorServer instance
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import sys
import urllib.parse
from typing import Any, Optional

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

import prosze_core  # noqa: E402
from prosze_cli.broker import (  # noqa: E402
    MAX_REQUEST_BYTES,
    has_compressed_encoding,
    is_loopback_host,
    read_http_request_body,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788
DEFAULT_LISTEN = f"{DEFAULT_HOST}:{DEFAULT_PORT}"

_KNOWN_PATHS = frozenset({"/", "/api/status", "/api/redact", "/api/restore"})

# Exact SVG mark & notched ticket icons from Visual identity/Prosze Visual Identity/
_SVG_MARK = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 289.45 201.16" '
    'class="brand-mark" aria-hidden="true">'
    '<g transform="translate(144.73,100.58) scale(1.0000)"><g transform="rotate(-6)">'
    '<path d="M-84.0,-70.0L29,-70.0A15,15 0 0 0 59,-70.0L84.0,-70.0A26,26 0 0 1 110.0,-44.0'
    'L110.0,44.0A26,26 0 0 1 84.0,70.0L59,70.0A15,15 0 0 0 29,70.0L-84.0,70.0A26,26 0 0 1 '
    '-110.0,44.0L-110.0,-44.0A26,26 0 0 1 -84.0,-70.0ZM44.00,-36.50H44.00A4.0,4.0 0 0 1 '
    '48.00,-32.50V-23.50A4.0,4.0 0 0 1 44.00,-19.50H44.00A4.0,4.0 0 0 1 40.00,-23.50V-32.50'
    'A4.0,4.0 0 0 1 44.00,-36.50ZM44.00,-8.50H44.00A4.0,4.0 0 0 1 48.00,-4.50V4.50A4.0,4.0 '
    '0 0 1 44.00,8.50H44.00A4.0,4.0 0 0 1 40.00,4.50V-4.50A4.0,4.0 0 0 1 44.00,-8.50ZM44.00,'
    '19.50H44.00A4.0,4.0 0 0 1 48.00,23.50V32.50A4.0,4.0 0 0 1 44.00,36.50H44.00A4.0,4.0 0 '
    '0 1 40.00,32.50V23.50A4.0,4.0 0 0 1 44.00,19.50Z" fill="#12392F" fill-rule="evenodd"/>'
    '<rect x="-80" y="-12" width="96" height="24" rx="12.0" fill="#E8432A"/>'
    "</g></g></svg>"
)

_SVG_ICON_REDACT = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96.00 96.00" '
    'class="ticket-icon" aria-hidden="true">'
    '<g transform="translate(48.00,48.00) scale(0.3600)">'
    '<path d="M-84.0,-70.0L29,-70.0A15,15 0 0 0 59,-70.0L84.0,-70.0A26,26 0 0 1 110.0,-44.0'
    'L110.0,44.0A26,26 0 0 1 84.0,70.0L59,70.0A15,15 0 0 0 29,70.0L-84.0,70.0A26,26 0 0 1 '
    '-110.0,44.0L-110.0,-44.0A26,26 0 0 1 -84.0,-70.0Z" fill="none" stroke="#12392F" '
    'stroke-width="11" stroke-linejoin="round"/>'
    '<path d="M44.00,-36.50H44.00A4.0,4.0 0 0 1 48.00,-32.50V-23.50A4.0,4.0 0 0 1 44.00,-19.50'
    'H44.00A4.0,4.0 0 0 1 40.00,-23.50V-32.50A4.0,4.0 0 0 1 44.00,-36.50ZM44.00,-8.50H44.00'
    'A4.0,4.0 0 0 1 48.00,-4.50V4.50A4.0,4.0 0 0 1 44.00,8.50H44.00A4.0,4.0 0 0 1 40.00,4.50'
    'V-4.50A4.0,4.0 0 0 1 44.00,-8.50ZM44.00,19.50H44.00A4.0,4.0 0 0 1 48.00,23.50V32.50'
    'A4.0,4.0 0 0 1 44.00,36.50H44.00A4.0,4.0 0 0 1 40.00,32.50V23.50A4.0,4.0 0 0 1 44.00,19.50Z" '
    'fill="#12392F"/>'
    '<rect x="-80" y="-12" width="96" height="24" rx="12" fill="#E8432A"/>'
    "</g></svg>"
)

_SVG_ICON_RESTORE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96.00 96.00" '
    'class="ticket-icon" aria-hidden="true">'
    '<g transform="translate(48.00,48.00) scale(0.3600)">'
    '<path d="M-84.0,-70.0L29,-70.0A15,15 0 0 0 59,-70.0L84.0,-70.0A26,26 0 0 1 110.0,-44.0'
    'L110.0,44.0A26,26 0 0 1 84.0,70.0L59,70.0A15,15 0 0 0 29,70.0L-84.0,70.0A26,26 0 0 1 '
    '-110.0,44.0L-110.0,-44.0A26,26 0 0 1 -84.0,-70.0Z" fill="none" stroke="#12392F" '
    'stroke-width="11" stroke-linejoin="round"/>'
    '<path d="M44.00,-36.50H44.00A4.0,4.0 0 0 1 48.00,-32.50V-23.50A4.0,4.0 0 0 1 44.00,-19.50'
    'H44.00A4.0,4.0 0 0 1 40.00,-23.50V-32.50A4.0,4.0 0 0 1 44.00,-36.50ZM44.00,-8.50H44.00'
    'A4.0,4.0 0 0 1 48.00,-4.50V4.50A4.0,4.0 0 0 1 44.00,8.50H44.00A4.0,4.0 0 0 1 40.00,4.50'
    'V-4.50A4.0,4.0 0 0 1 44.00,-8.50ZM44.00,19.50H44.00A4.0,4.0 0 0 1 48.00,23.50V32.50'
    'A4.0,4.0 0 0 1 44.00,36.50H44.00A4.0,4.0 0 0 1 40.00,32.50V23.50A4.0,4.0 0 0 1 44.00,19.50Z" '
    'fill="#12392F"/>'
    '<rect x="-80" y="-24" width="96" height="14" rx="7" fill="#12392F"/>'
    '<rect x="-80" y="10" width="60" height="14" rx="7" fill="#12392F"/>'
    "</g></svg>"
)

_SVG_ICON_CHECK = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96.00 96.00" '
    'class="ticket-icon" aria-hidden="true">'
    '<g transform="translate(48.00,48.00) scale(0.3600)">'
    '<path d="M-84.0,-70.0L29,-70.0A15,15 0 0 0 59,-70.0L84.0,-70.0A26,26 0 0 1 110.0,-44.0'
    'L110.0,44.0A26,26 0 0 1 84.0,70.0L59,70.0A15,15 0 0 0 29,70.0L-84.0,70.0A26,26 0 0 1 '
    '-110.0,44.0L-110.0,-44.0A26,26 0 0 1 -84.0,-70.0Z" fill="none" stroke="#12392F" '
    'stroke-width="11" stroke-linejoin="round"/>'
    '<path d="M44.00,-36.50H44.00A4.0,4.0 0 0 1 48.00,-32.50V-23.50A4.0,4.0 0 0 1 44.00,-19.50'
    'H44.00A4.0,4.0 0 0 1 40.00,-23.50V-32.50A4.0,4.0 0 0 1 44.00,-36.50ZM44.00,-8.50H44.00'
    'A4.0,4.0 0 0 1 48.00,-4.50V4.50A4.0,4.0 0 0 1 44.00,8.50H44.00A4.0,4.0 0 0 1 40.00,4.50'
    'V-4.50A4.0,4.0 0 0 1 44.00,-8.50ZM44.00,19.50H44.00A4.0,4.0 0 0 1 48.00,23.50V32.50'
    'A4.0,4.0 0 0 1 44.00,36.50H44.00A4.0,4.0 0 0 1 40.00,32.50V23.50A4.0,4.0 0 0 1 44.00,19.50Z" '
    'fill="#12392F"/>'
    '<path d="M-72,2L-48,26L-4,-26" fill="none" stroke="#E8432A" stroke-width="16" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    "</g></svg>"
)

_SVG_ICON_RUN = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96.00 96.00" '
    'class="ticket-icon" aria-hidden="true">'
    '<g transform="translate(48.00,48.00) scale(0.3600)">'
    '<path d="M-84.0,-70.0L29,-70.0A15,15 0 0 0 59,-70.0L84.0,-70.0A26,26 0 0 1 110.0,-44.0'
    'L110.0,44.0A26,26 0 0 1 84.0,70.0L59,70.0A15,15 0 0 0 29,70.0L-84.0,70.0A26,26 0 0 1 '
    '-110.0,44.0L-110.0,-44.0A26,26 0 0 1 -84.0,-70.0Z" fill="none" stroke="#12392F" '
    'stroke-width="11" stroke-linejoin="round"/>'
    '<path d="M44.00,-36.50H44.00A4.0,4.0 0 0 1 48.00,-32.50V-23.50A4.0,4.0 0 0 1 44.00,-19.50'
    'H44.00A4.0,4.0 0 0 1 40.00,-23.50V-32.50A4.0,4.0 0 0 1 44.00,-36.50ZM44.00,-8.50H44.00'
    'A4.0,4.0 0 0 1 48.00,-4.50V4.50A4.0,4.0 0 0 1 44.00,8.50H44.00A4.0,4.0 0 0 1 40.00,4.50'
    'V-4.50A4.0,4.0 0 0 1 44.00,-8.50ZM44.00,19.50H44.00A4.0,4.0 0 0 1 48.00,23.50V32.50'
    'A4.0,4.0 0 0 1 44.00,36.50H44.00A4.0,4.0 0 0 1 40.00,32.50V23.50A4.0,4.0 0 0 1 44.00,19.50Z" '
    'fill="#12392F"/>'
    '<path d="M-72,-26L-40,0L-72,26" fill="none" stroke="#12392F" stroke-width="14" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    '<rect x="-24" y="14" width="46" height="14" rx="7" fill="#E8432A"/>'
    "</g></svg>"
)

_INSPECTOR_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>prosze — Cloakroom Ticket Inspector</title>
  <style>
    :root {{
      --pine: #12392F;
      --stamp-red: #E8432A;
      --stamp-red-dark: #FF6A4D;
      --cream: #F5EFE2;
      --ink: #0F1A17;
      --mint: #8FD0B3;
      --slate: #56635D;
      --perforation: #D9D1BF;
      --font-display: 'Fraunces', Georgia, serif;
      --font-ui: 'Schibsted Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      background: var(--cream);
      color: var(--ink);
      font-family: var(--font-ui);
      font-size: 15px;
      line-height: 1.55;
    }}

    .cloakroom-header {{
      background: var(--pine);
      color: var(--cream);
      border-bottom: 3px dashed var(--perforation);
      padding: 20px 24px;
    }}

    .header-inner {{
      max-width: 1120px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}

    .brand-lockup {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}

    .mark-pad {{
      background: var(--cream);
      border-radius: 12px;
      padding: 10px 14px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }}

    .brand-mark {{
      width: 52px;
      height: 36px;
      display: block;
    }}

    .wordmark {{
      font-family: var(--font-display);
      font-weight: 600;
      font-size: 32px;
      line-height: 1;
      letter-spacing: -0.02em;
      color: var(--cream);
      margin: 0;
    }}

    .tagline {{
      margin: 4px 0 0;
      color: var(--mint);
      font-size: 13px;
      font-weight: 500;
    }}

    .vault-badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 11px;
      border-radius: 999px;
      background: var(--ink);
      color: var(--mint);
      font-family: var(--font-mono);
      font-size: 12px;
      border: 1px solid rgba(143, 208, 179, 0.25);
    }}

    .badge-accent {{
      color: var(--stamp-red-dark);
      border-color: rgba(255, 106, 77, 0.35);
    }}

    .container {{
      max-width: 1120px;
      margin: 24px auto 48px;
      padding: 0 24px;
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 24px;
    }}

    @media (max-width: 880px) {{
      .container {{ grid-template-columns: 1fr; }}
    }}

    .ticket-card {{
      position: relative;
      background: #FAF6EC;
      border: 1.5px solid var(--perforation);
      border-radius: 16px;
      padding: 20px 22px;
    }}

    .ticket-card::before,
    .ticket-card::after {{
      content: "";
      position: absolute;
      width: 16px;
      height: 16px;
      border-radius: 50%;
      background: var(--cream);
      border: 1.5px solid var(--perforation);
      top: 54px;
    }}

    .ticket-card::before {{ left: -9px; }}
    .ticket-card::after {{ right: -9px; }}

    .card-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 14px;
      margin-bottom: 16px;
      border-bottom: 2px dashed var(--perforation);
    }}

    .card-title {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 0;
      font-family: var(--font-display);
      font-weight: 500;
      font-size: 20px;
      color: var(--pine);
    }}

    .ticket-icon {{
      width: 24px;
      height: 24px;
      flex-shrink: 0;
    }}

    .muted {{
      color: var(--slate);
      font-size: 13px;
    }}

    textarea {{
      width: 100%;
      min-height: 138px;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1.5px solid var(--perforation);
      background: var(--cream);
      color: var(--ink);
      font-family: var(--font-mono);
      font-size: 13px;
      resize: vertical;
      outline: none;
      transition: border-color 250ms ease-out;
    }}

    textarea:focus {{
      border-color: var(--pine);
    }}

    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 14px 0;
    }}

    button {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1.5px solid var(--pine);
      border-radius: 10px;
      padding: 8px 14px;
      font-family: var(--font-ui);
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      background: var(--cream);
      color: var(--pine);
      transition: background-color 250ms ease-out, transform 250ms ease-out;
    }}

    button:hover {{
      background: #EDE5D4;
    }}

    button:active {{
      transform: translateY(1px);
    }}

    button.primary {{
      background: var(--pine);
      color: var(--cream);
    }}

    button.primary:hover {{
      background: #1A4B3E;
    }}

    .btn-icon {{
      width: 18px;
      height: 18px;
    }}

    .output-box {{
      min-height: 112px;
      padding: 14px;
      border-radius: 10px;
      border: 1.5px dashed var(--perforation);
      background: var(--cream);
      font-family: var(--font-mono);
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-word;
      opacity: 1;
      transform: translateY(0);
      transition: opacity 250ms ease-out, transform 250ms ease-out;
    }}

    .output-box.roundtrip-transition {{
      opacity: 0.45;
      transform: translateY(4px);
    }}

    .ticket-chip {{
      display: inline-block;
      background: var(--stamp-red);
      color: var(--cream);
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 12px;
      padding: 1px 7px;
      border-radius: 999px;
      margin: 0 1px;
      transition: transform 250ms ease-out, opacity 250ms ease-out;
    }}

    .status-line {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      font-size: 13px;
      color: var(--slate);
    }}

    .stack {{
      display: flex;
      flex-direction: column;
      gap: 24px;
    }}

    .category-pills {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 12px;
    }}

    .cat-pill {{
      background: var(--cream);
      border: 1px solid var(--perforation);
      border-radius: 999px;
      padding: 2px 10px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--pine);
    }}

    .ledger-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      max-height: 250px;
      overflow-y: auto;
    }}

    .ledger-item {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 4px;
      border-bottom: 1px dashed var(--perforation);
      font-family: var(--font-mono);
      font-size: 12.5px;
    }}

    .ledger-item:last-child {{ border-bottom: none; }}

    .hidden-mask {{
      color: var(--slate);
      font-style: italic;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
      font-size: 12px;
    }}

    th, td {{
      text-align: left;
      padding: 6px 4px;
      border-bottom: 1px dashed var(--perforation);
    }}

    th {{
      color: var(--slate);
      font-weight: 500;
    }}
  </style>
</head>
<body>
  <header class="cloakroom-header">
    <div class="header-inner">
      <div class="brand-lockup">
        <span class="mark-pad">{_SVG_MARK}</span>
        <div>
          <h1 class="wordmark">prosze</h1>
          <p class="tagline">Keep what&#39;s yours. Nothing leaves until it has a ticket.</p>
        </div>
      </div>
      <div class="vault-badges">
        <span class="badge badge-accent" id="badge-tickets">0 tickets</span>
        <span class="badge" id="badge-storage">ephemeral: --</span>
        <span class="badge" id="badge-encryption">encrypted: --</span>
        <span class="badge" id="badge-strict">strict: --</span>
      </div>
    </div>
  </header>

  <main class="container">
    <section class="ticket-card" aria-label="Redact and Restore Sandbox">
      <div class="card-head">
        <h2 class="card-title">{_SVG_ICON_REDACT}<span>Cloakroom Sandbox</span></h2>
        <span class="muted">Hand it over. Get it back.</span>
      </div>

      <label for="sandbox-input" class="muted">Input text (raw prompt to redact, or ticketed reply to restore)</label>
      <textarea id="sandbox-input" placeholder="Paste prompt text with emails, keys, or customer names..."></textarea>

      <div class="actions">
        <button type="button" class="primary" id="btn-redact">
          {_SVG_ICON_REDACT.replace('class="ticket-icon"', 'class="btn-icon"')}
          <span>Redact Prompt</span>
        </button>
        <button type="button" id="btn-restore">
          {_SVG_ICON_RESTORE.replace('class="ticket-icon"', 'class="btn-icon"')}
          <span>Restore Reply</span>
        </button>
        <button type="button" id="btn-swap">Use Output as Input</button>
      </div>

      <div id="sandbox-output" class="output-box" aria-live="polite">Here you go — redacted tickets render in Stamp Red pills here.</div>
      <div class="status-line">
        {_SVG_ICON_CHECK}
        <span id="sandbox-status">Ready on local loopback.</span>
      </div>
    </section>

    <div class="stack">
      <section class="ticket-card" aria-label="Vault Ticket Ledger">
        <div class="card-head">
          <h2 class="card-title">{_SVG_ICON_CHECK}<span>Vault Ticket Ledger</span></h2>
          <button type="button" id="btn-refresh">Refresh</button>
        </div>
        <div id="category-pills" class="category-pills"></div>
        <ul id="ticket-ledger" class="ledger-list">
          <li class="ledger-item"><span class="muted">Loading tickets...</span><span class="hidden-mask">&lt;hidden&gt;</span></li>
        </ul>
      </section>

      <section class="ticket-card" aria-label="Broker Activity">
        <div class="card-head">
          <h2 class="card-title">{_SVG_ICON_RUN}<span>Broker Activity</span></h2>
          <span class="muted" id="broker-summary">checking...</span>
        </div>
        <div id="broker-panel" class="muted">Loading broker status...</div>
      </section>
    </div>
  </main>

  <script>
    const TICKET_SPLIT_RE = /(\\[\\[[A-Z][A-Z0-9_]*_\\d+\\]\\])/g;
    const TICKET_EXACT_RE = /^\\[\\[[A-Z][A-Z0-9_]*_\\d+\\]\\]$/;
    let lastRawOutput = "";

    function renderTicketizedText(container, text) {{
      container.classList.add("roundtrip-transition");
      container.textContent = "";
      const parts = String(text || "").split(TICKET_SPLIT_RE);
      for (const part of parts) {{
        if (!part) continue;
        if (TICKET_EXACT_RE.test(part)) {{
          const chip = document.createElement("span");
          chip.className = "ticket-chip";
          chip.textContent = part;
          container.appendChild(chip);
        }} else {{
          container.appendChild(document.createTextNode(part));
        }}
      }}
      requestAnimationFrame(() => {{
        setTimeout(() => container.classList.remove("roundtrip-transition"), 30);
      }});
    }}

    async function refreshStatus() {{
      const resp = await fetch("/api/status", {{ cache: "no-store" }});
      if (!resp.ok) return;
      const data = await resp.json();

      document.getElementById("badge-tickets").textContent = `${{data.ticket_count}} ticket(s)`;
      document.getElementById("badge-storage").textContent = data.ephemeral ? "ephemeral" : "persisted";
      document.getElementById("badge-encryption").textContent = data.encrypted ? "encrypted" : "plaintext";
      document.getElementById("badge-strict").textContent = data.strict_restore ? "strict-restore" : "standard-restore";

      const pillsEl = document.getElementById("category-pills");
      pillsEl.textContent = "";
      for (const [cat, count] of Object.entries(data.categories || {{}})) {{
        const pill = document.createElement("span");
        pill.className = "cat-pill";
        pill.textContent = `${{cat}}: ${{count}}`;
        pillsEl.appendChild(pill);
      }}

      const ledgerEl = document.getElementById("ticket-ledger");
      ledgerEl.textContent = "";
      const tickets = data.tickets || [];
      if (tickets.length === 0) {{
        const li = document.createElement("li");
        li.className = "ledger-item";
        const span = document.createElement("span");
        span.className = "muted";
        span.textContent = "Vault is empty — no active tickets.";
        li.appendChild(span);
        ledgerEl.appendChild(li);
      }} else {{
        for (const t of tickets) {{
          const li = document.createElement("li");
          li.className = "ledger-item";
          const chip = document.createElement("span");
          chip.className = "ticket-chip";
          chip.textContent = t.placeholder;
          const mask = document.createElement("span");
          mask.className = "hidden-mask";
          mask.textContent = t.preview || "<hidden>";
          li.appendChild(chip);
          li.appendChild(mask);
          ledgerEl.appendChild(li);
        }}
      }}

      const broker = data.broker || {{}};
      const summaryEl = document.getElementById("broker-summary");
      const panelEl = document.getElementById("broker-panel");
      panelEl.textContent = "";

      if (!broker.attached) {{
        summaryEl.textContent = "standalone";
        const p = document.createElement("p");
        p.textContent = "Standalone inspector — run `prosze broker serve` to trace live HTTP/SSE gateway activity.";
        panelEl.appendChild(p);
      }} else {{
        summaryEl.textContent = `${{broker.request_count || 0}} req · ${{broker.total_redacted || 0}} redacted`;
        const hist = broker.history || [];
        if (hist.length === 0) {{
          const p = document.createElement("p");
          p.textContent = "Gateway attached; no requests recorded yet.";
          panelEl.appendChild(p);
        }} else {{
          const table = document.createElement("table");
          const thead = document.createElement("thead");
          const hr = document.createElement("tr");
          for (const h of ["Method", "Path", "Status", "Hidden", "ms"]) {{
            const th = document.createElement("th");
            th.textContent = h;
            hr.appendChild(th);
          }}
          thead.appendChild(hr);
          table.appendChild(thead);

          const tbody = document.createElement("tbody");
          for (const row of hist.slice(-12).reverse()) {{
            const tr = document.createElement("tr");
            for (const val of [row.method, row.path, row.status, row.redacted_count, row.latency_ms]) {{
              const td = document.createElement("td");
              td.textContent = String(val);
              tr.appendChild(td);
            }}
            tbody.appendChild(tr);
          }}
          table.appendChild(tbody);
          panelEl.appendChild(table);
        }}
      }}
    }}

    async function callEndpoint(path, bodyKey) {{
      const text = document.getElementById("sandbox-input").value;
      const resp = await fetch(path, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ text }})
      }});
      const data = await resp.json();
      if (!resp.ok) {{
        document.getElementById("sandbox-status").textContent = (data.error && data.error.message) || "Request failed";
        return;
      }}
      lastRawOutput = data[bodyKey] || "";
      renderTicketizedText(document.getElementById("sandbox-output"), lastRawOutput);
      if (path === "/api/redact") {{
        document.getElementById("sandbox-status").textContent = `${{data.hits}} item(s) ticketed (${{data.ticket_count}} total in vault).`;
      }} else {{
        document.getElementById("sandbox-status").textContent = "Restored matching session tickets.";
      }}
      await refreshStatus();
    }}

    document.getElementById("btn-redact").addEventListener("click", () => callEndpoint("/api/redact", "safe_text"));
    document.getElementById("btn-restore").addEventListener("click", () => callEndpoint("/api/restore", "restored_text"));
    document.getElementById("btn-swap").addEventListener("click", () => {{
      if (lastRawOutput) document.getElementById("sandbox-input").value = lastRawOutput;
    }});
    document.getElementById("btn-refresh").addEventListener("click", refreshStatus);
    refreshStatus();
  </script>
</body>
</html>
""".encode("utf-8")


def _with_vault_lock(vault: prosze_core.Vault, fn):
    lock = getattr(vault, "lock", None)
    if lock is not None:
        with lock:
            return fn()
    return fn()


def _build_status_payload(vault: prosze_core.Vault, gateway: Any) -> dict[str, Any]:
    def _snapshot():
        return (
            list(vault.fwd.keys()),
            bool(vault.ephemeral),
            bool(vault.passphrase),
            bool(vault.strict_restore),
        )

    placeholders, ephemeral, encrypted, strict_restore = _with_vault_lock(vault, _snapshot)

    categories: dict[str, int] = {}
    tickets: list[dict[str, str]] = []
    for k in placeholders:
        m = prosze_core.PH_IDX.match(k)
        cat = m.group(1) if m else "OTHER"
        categories[cat] = categories.get(cat, 0) + 1
        tickets.append({"placeholder": k, "preview": "<hidden>"})

    if gateway is not None:
        raw_history = list(getattr(gateway, "history", []) or [])
        sanitized_history = []
        total_redacted = 0
        for entry in raw_history:
            if not isinstance(entry, dict):
                continue
            rc = int(entry.get("redacted_count", 0))
            total_redacted += rc
            sanitized_history.append({
                "method": str(entry.get("method", "")),
                "path": str(entry.get("path", "")),
                "status": int(entry.get("status", 0)),
                "redacted_count": rc,
                "latency_ms": float(entry.get("latency_ms", 0.0)),
            })
        broker_info = {
            "attached": True,
            "request_count": len(sanitized_history),
            "total_redacted": total_redacted,
            "history": sanitized_history,
        }
    else:
        broker_info = {
            "attached": False,
            "request_count": 0,
            "total_redacted": 0,
            "history": [],
        }

    return {
        "status": "ok",
        "ticket_count": len(tickets),
        "categories": categories,
        "ephemeral": ephemeral,
        "encrypted": encrypted,
        "strict_restore": strict_restore,
        "tickets": tickets,
        "broker": broker_info,
    }


class InspectorRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local Cloakroom Ticket web inspector."""

    protocol_version = "HTTP/1.1"
    server: "InspectorServer"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send_bytes(
        self,
        status: int,
        content_type: str,
        payload: bytes,
        *,
        close: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._send_security_headers()
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD" and payload:
            self.wfile.write(payload)
        self.wfile.flush()

    def _send_json(self, status: int, data: Any, *, close: bool = False) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", payload, close=close)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": {"message": message, "status": status}}, close=True)

    def _read_json_text(self) -> tuple[Optional[str], int, str]:
        raw_body, err_status, err_msg = read_http_request_body(
            self.headers, self.rfile, max_bytes=MAX_REQUEST_BYTES
        )
        if err_status:
            return None, err_status, err_msg
        if has_compressed_encoding(self.headers):
            return None, 415, "Unsupported Content-Encoding; only identity is allowed"
        assert raw_body is not None
        try:
            text_body = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            return None, 400, "Request body must be valid UTF-8"
        try:
            payload = json.loads(text_body)
        except ValueError:
            return None, 400, "Request body must be valid JSON"
        if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
            return None, 400, 'JSON body must be an object with string field "text"'
        return payload["text"], 0, ""

    def _route_path(self) -> str:
        return urllib.parse.urlsplit(self.path).path or "/"

    def do_GET(self) -> None:
        path = self._route_path()
        if path == "/":
            self._send_bytes(200, "text/html; charset=utf-8", _INSPECTOR_HTML)
        elif path == "/api/status":
            self._send_json(200, _build_status_payload(self.server.vault, self.server.gateway))
        elif path in _KNOWN_PATHS:
            self._send_error_json(405, "Method not allowed")
        else:
            self._send_error_json(404, "Not found")

    do_HEAD = do_GET

    def do_POST(self) -> None:
        path = self._route_path()
        if path not in ("/api/redact", "/api/restore"):
            if path in _KNOWN_PATHS:
                self._send_error_json(405, "Method not allowed")
            else:
                self._send_error_json(404, "Not found")
            return

        text, err_status, err_msg = self._read_json_text()
        if err_status:
            self._send_error_json(err_status, err_msg)
            return
        assert text is not None

        vault = self.server.vault
        if path == "/api/redact":
            def _do_redact():
                safe_text, hits = vault.redact(text)
                return safe_text, hits, len(vault.fwd)

            safe_text, hits, ticket_count = _with_vault_lock(vault, _do_redact)
            self._send_json(200, {
                "safe_text": safe_text,
                "hits": hits,
                "ticket_count": ticket_count,
            })
        else:
            restored_text = _with_vault_lock(vault, lambda: vault.restore(text))
            self._send_json(200, {"restored_text": restored_text})

    def _handle_unsupported_method(self) -> None:
        path = self._route_path()
        if path in _KNOWN_PATHS:
            self._send_error_json(405, "Method not allowed")
        else:
            self._send_error_json(404, "Not found")

    do_PUT = _handle_unsupported_method
    do_PATCH = _handle_unsupported_method
    do_DELETE = _handle_unsupported_method
    do_OPTIONS = _handle_unsupported_method


class InspectorServer(ThreadingHTTPServer):
    """Loopback ThreadingHTTPServer serving the Cloakroom Ticket web inspector."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        vault: prosze_core.Vault,
        gateway: Any = None,
    ) -> None:
        host, port = server_address
        clean_host = (host or "").strip()
        if clean_host.startswith("[") and clean_host.endswith("]"):
            clean_host = clean_host[1:-1]

        if not is_loopback_host(clean_host):
            raise ValueError(
                f"prosze ui: refusing non-loopback listen host {host!r}; inspector is loopback-only"
            )
        if isinstance(port, bool) or not isinstance(port, int) or not (0 <= port <= 65535):
            raise ValueError(f"prosze ui: invalid port {port!r}")

        self.vault = vault
        self.gateway = gateway

        if ":" in clean_host:
            self.address_family = socket.AF_INET6

        super().__init__((clean_host, port), InspectorRequestHandler)


def create_inspector_server(
    vault: prosze_core.Vault,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    gateway: Any = None,
) -> InspectorServer:
    """Validate configuration and construct a loopback-only InspectorServer."""
    return InspectorServer((host, port), vault=vault, gateway=gateway)
