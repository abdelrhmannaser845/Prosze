#!/usr/bin/env python3
"""Build FigCraft script and SVG preview for a modern Terminal CLI App UI."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List


class FigCraftScriptBuilder:
    """Helper to construct FigCraft JSON command scripts."""

    def __init__(self) -> None:
        self.commands: List[Dict[str, Any]] = []
        self._next_id = 1

    def create_node(self, node_type: str, name: str, parent_id: int | None = None, **kwargs: Any) -> int:
        node_id = self._next_id
        self._next_id += 1
        params: Dict[str, Any] = {
            "nodeId": node_id,
            "type": node_type,
            "name": name,
        }
        if parent_id is not None:
            params["parentId"] = parent_id
        params.update(kwargs)
        self.commands.append({"command": "create_node", "params": params})
        return node_id

    def set_properties(self, node_id: int, **props: Any) -> None:
        self.commands.append({
            "command": "set_properties",
            "params": {
                "nodeId": node_id,
                "props": props
            }
        })

    def export_script(self) -> str:
        return json.dumps(self.commands, indent=2)


def generate_figcraft_script() -> tuple[str, list[dict[str, Any]]]:
    builder = FigCraftScriptBuilder()

    # 1. Main Canvas / Window Container Frame
    window_id = builder.create_node(
        node_type="frame",
        name="CLI App Window Frame",
        width=1000,
        height=720,
        x=40,
        y=40
    )
    builder.set_properties(
        window_id,
        fill="#0d1117",
        stroke="#30363d",
        strokeWidth=1,
        cornerRadius=14,
        layout="vertical",
        gap=0,
        padding=0,
        dropShadow={"color": "rgba(0,0,0,0.55)", "blur": 32, "x": 0, "y": 18}
    )

    # 2. Window Header Bar (Traffic Lights + Tabs + Status)
    header_id = builder.create_node(
        node_type="frame",
        name="Window Header Bar",
        parent_id=window_id,
        width=1000,
        height=44
    )
    builder.set_properties(
        header_id,
        fill="#161b22",
        stroke="#30363d",
        strokeWidth=1,
        layout="horizontal",
        alignment="center",
        justifyContent="space-between",
        padding=[0, 18, 0, 18],
        cornerRadius=[14, 14, 0, 0]
    )

    # Traffic light controls
    controls_id = builder.create_node(
        node_type="frame",
        name="Window Controls",
        parent_id=header_id,
        width=60,
        height=14
    )
    builder.set_properties(controls_id, layout="horizontal", gap=8, alignment="center")

    for color, name in [("#ff5f56", "Close"), ("#ffbd2e", "Minimize"), ("#27c93f", "Maximize")]:
        dot = builder.create_node("circle", name=f"Dot {name}", parent_id=controls_id, width=12, height=12)
        builder.set_properties(dot, fill=color)

    # Title & Tab Bar
    tab_bar_id = builder.create_node(
        node_type="frame",
        name="Tab Item",
        parent_id=header_id,
        height=32
    )
    builder.set_properties(
        tab_bar_id,
        layout="horizontal",
        gap=8,
        padding=[6, 14, 6, 14],
        fill="#0d1117",
        cornerRadius=6,
        stroke="#30363d",
        strokeWidth=1
    )
    tab_text = builder.create_node("text", name="Tab Label", parent_id=tab_bar_id)
    builder.set_properties(
        tab_text,
        text="❯ prosze-shield : session_01 (zsh)",
        fontSize=12,
        fontFamily="Fira Code, SF Mono, Menlo, monospace",
        fill="#c9d1d9"
    )

    # Status Pill on Header Right
    status_pill_id = builder.create_node(
        node_type="frame",
        name="Status Pill",
        parent_id=header_id,
        height=26
    )
    builder.set_properties(
        status_pill_id,
        layout="horizontal",
        gap=6,
        padding=[4, 10, 4, 10],
        fill="#1f242c",
        stroke="#388bfd33",
        strokeWidth=1,
        cornerRadius=12
    )
    status_dot = builder.create_node("circle", name="Status Live Dot", parent_id=status_pill_id, width=8, height=8)
    builder.set_properties(status_dot, fill="#3fb950")
    status_label = builder.create_node("text", name="Status Text", parent_id=status_pill_id)
    builder.set_properties(status_label, text="SHIELD ACTIVE", fontSize=11, fontWeight="bold", fill="#58a6ff")

    # 3. Terminal Body
    body_id = builder.create_node(
        node_type="frame",
        name="Terminal Canvas Body",
        parent_id=window_id,
        width=1000,
        height=626
    )
    builder.set_properties(
        body_id,
        fill="#0d1117",
        layout="vertical",
        gap=16,
        padding=24,
        justifyContent="space-between"
    )

    # Upper Content (Banner + Log streams)
    upper_content_id = builder.create_node(
        node_type="frame",
        name="Terminal Upper Log Container",
        parent_id=body_id,
        width=952
    )
    builder.set_properties(upper_content_id, layout="vertical", gap=14)

    # ASCII Logo / Banner Card
    banner_card = builder.create_node(
        node_type="frame",
        name="ASCII Banner Card",
        parent_id=upper_content_id,
        width=952
    )
    builder.set_properties(
        banner_card,
        fill="#161b22",
        stroke="#21262d",
        strokeWidth=1,
        cornerRadius=8,
        padding=[14, 18, 14, 18],
        layout="vertical",
        gap=8
    )

    banner_text = builder.create_node("text", name="Banner Text", parent_id=banner_card)
    banner_ascii = (
        "  ____  ____   ___  ____  _____ _____\n"
        " |  _ \\|  _ \\ / _ \\/ ___||__  /| ____|\n"
        " | |_) | |_) | | | \\___ \\  / / |  _|  \n"
        " |  __/|  _ <| |_| |___) |/ /_ | |___ \n"
        " |_|   |_| \\_\\\\___/|____//____||_____|  v1.4.2 [Zero-Leak Local Privacy Shield]"
    )
    builder.set_properties(
        banner_text,
        text=banner_ascii,
        fontSize=11,
        fontFamily="Fira Code, SF Mono, Menlo, monospace",
        fill="#58a6ff",
        lineHeight=1.35
    )

    # Badges Row inside Banner
    badges_row = builder.create_node(
        node_type="frame",
        name="Banner Badges Row",
        parent_id=banner_card,
        height=24
    )
    builder.set_properties(badges_row, layout="horizontal", gap=10)

    for badge_text, badge_color, border_color in [
        ("NER Engine: GLiNER (Active)", "#3fb950", "#238636"),
        ("Proxy: 127.0.0.1:8080", "#79c0ff", "#1f6feb"),
        ("Vault: 14 Entities Shielded", "#d29922", "#9e6a03"),
        ("AES-GCM Memory Protection", "#bc8cff", "#8957e5"),
    ]:
        b_frame = builder.create_node("frame", name=f"Badge {badge_text}", parent_id=badges_row)
        builder.set_properties(
            b_frame,
            fill="#0d1117",
            stroke=border_color,
            strokeWidth=1,
            cornerRadius=4,
            padding=[3, 8, 3, 8]
        )
        b_lbl = builder.create_node("text", name="Badge Label", parent_id=b_frame)
        builder.set_properties(b_lbl, text=badge_text, fontSize=11, fill=badge_color, fontFamily="monospace")

    # Command Execution 1 (User Input)
    cmd1_frame = builder.create_node("frame", name="Command Prompt 1", parent_id=upper_content_id)
    builder.set_properties(cmd1_frame, layout="horizontal", gap=8, alignment="center")

    cmd1_prompt = builder.create_node("text", name="Prompt Symbol", parent_id=cmd1_frame)
    builder.set_properties(cmd1_prompt, text="user@host ❯", fontSize=13, fill="#3fb950", fontWeight="bold")

    cmd1_cmd = builder.create_node("text", name="Command String", parent_id=cmd1_frame)
    builder.set_properties(
        cmd1_cmd,
        text="prosze redact --in customer_report.txt --stream --ai claude-3-5-sonnet",
        fontSize=13,
        fill="#f0f6fc",
        fontFamily="monospace"
    )

    # Interception Card (Privacy Shield Details)
    shield_card = builder.create_node("frame", name="Redaction Activity Card", parent_id=upper_content_id)
    builder.set_properties(
        shield_card,
        fill="#161b22",
        stroke="#30363d",
        strokeWidth=1,
        cornerRadius=8,
        padding=[12, 16, 12, 16],
        layout="vertical",
        gap=8
    )

    card_header = builder.create_node("text", name="Interception Header", parent_id=shield_card)
    builder.set_properties(
        card_header,
        text="🔒 SHIELD INTERCEPTED & REDACTED 3 HIGH-RISK TOKENS (PRE-FLIGHT):",
        fontSize=12,
        fontWeight="bold",
        fill="#f0883e"
    )

    # Items table
    for token_tag, original_type, entropy in [
        ("[[NAME_PERSON_1]]", "Full Name ('Sarah Jenkins')", "Confidence 99.4%"),
        ("[[KEY_STRIPE_SECRET_1]]", "API Key ('sk_live_51M...38x')", "Entropy 4.88 bit/sym"),
        ("[[IBAN_DE_1]]", "Bank Account ('DE89370400440532013000')", "Checksum Valid"),
    ]:
        row = builder.create_node("frame", name=f"Token Row {token_tag}", parent_id=shield_card)
        builder.set_properties(row, layout="horizontal", gap=16, alignment="center")

        t_node = builder.create_node("text", name="Tag", parent_id=row)
        builder.set_properties(t_node, text=token_tag, fontSize=12, fill="#58a6ff", fontFamily="monospace")

        o_node = builder.create_node("text", name="Detected As", parent_id=row)
        builder.set_properties(o_node, text=original_type, fontSize=12, fill="#8b949e")

        e_node = builder.create_node("text", name="Entropy Score", parent_id=row)
        builder.set_properties(e_node, text=entropy, fontSize=11, fill="#7ee787")

    # Streaming AI Response Area
    ai_response_frame = builder.create_node("frame", name="Streaming Output Block", parent_id=upper_content_id)
    builder.set_properties(
        ai_response_frame,
        fill="#090d13",
        stroke="#1f6feb33",
        strokeWidth=1,
        cornerRadius=8,
        padding=[12, 16, 12, 16],
        layout="vertical",
        gap=6
    )

    ai_header = builder.create_node("frame", name="AI Stream Header", parent_id=ai_response_frame)
    builder.set_properties(ai_header, layout="horizontal", gap=8, alignment="center")
    ai_badge = builder.create_node("text", name="AI Badge", parent_id=ai_header)
    builder.set_properties(ai_badge, text="✦ AI ASSISTANT (RESTORED ON THE FLY):", fontSize=11, fontWeight="bold", fill="#bc8cff")

    ai_body = builder.create_node("text", name="Stream Text", parent_id=ai_response_frame)
    builder.set_properties(
        ai_body,
        text=(
            "Analysis complete for Sarah Jenkins. The subscription billing on account DE89370400440532013000\n"
            "was reconciled against Stripe key sk_live_51M...38x. All transactions match ledger criteria.\n"
            "Total verified: $14,250.00 USD across 3 recurring customer invoices."
        ),
        fontSize=12,
        fill="#c9d1d9",
        lineHeight=1.45,
        fontFamily="Fira Code, SF Mono, Menlo, monospace"
    )

    # 4. Bottom Interactive Input Deck & Footer Status Bar
    bottom_deck = builder.create_node("frame", name="Bottom Terminal Deck", parent_id=body_id, width=952)
    builder.set_properties(bottom_deck, layout="vertical", gap=10)

    # Input Bar
    input_bar = builder.create_node("frame", name="Interactive Input Bar", parent_id=bottom_deck, height=44)
    builder.set_properties(
        input_bar,
        fill="#161b22",
        stroke="#58a6ff",
        strokeWidth=1.5,
        cornerRadius=6,
        padding=[10, 14, 10, 14],
        layout="horizontal",
        gap=10,
        alignment="center"
    )

    inp_glyph = builder.create_node("text", name="Prompt Glyph", parent_id=input_bar)
    builder.set_properties(inp_glyph, text="❯", fontSize=14, fontWeight="bold", fill="#58a6ff")

    inp_txt = builder.create_node("text", name="Input Cursor Text", parent_id=input_bar)
    builder.set_properties(
        inp_txt,
        text="Type your prompt or /help, /models, /vault, /exit... ",
        fontSize=13,
        fill="#8b949e",
        fontFamily="monospace"
    )

    cursor = builder.create_node("frame", name="Blinking Cursor", parent_id=input_bar, width=8, height=18)
    builder.set_properties(cursor, fill="#58a6ff", cornerRadius=1)

    # Status Bar Footer
    footer = builder.create_node("frame", name="Footer Status Bar", parent_id=bottom_deck, height=28)
    builder.set_properties(
        footer,
        fill="#090d13",
        stroke="#30363d",
        strokeWidth=1,
        cornerRadius=4,
        padding=[4, 12, 4, 12],
        layout="horizontal",
        justifyContent="space-between",
        alignment="center"
    )

    foot_left = builder.create_node("frame", name="Footer Left Badges", parent_id=footer)
    builder.set_properties(foot_left, layout="horizontal", gap=14)

    for seg_text, seg_color in [
        ("MODE: ZERO-LEAK INTERACTIVE", "#3fb950"),
        ("UPSTREAM: api.anthropic.com", "#58a6ff"),
        ("LATENCY: 142ms", "#79c0ff"),
    ]:
        f_lbl = builder.create_node("text", name="Footer Segment", parent_id=foot_left)
        builder.set_properties(f_lbl, text=seg_text, fontSize=10.5, fontWeight="bold", fill=seg_color, fontFamily="monospace")

    foot_right = builder.create_node("frame", name="Footer Right Shortcuts", parent_id=footer)
    builder.set_properties(foot_right, layout="horizontal", gap=12)

    for key_hint in ["[Enter] Send", "[Esc] Cancel", "[/help] Commands", "[^C] Exit"]:
        f_key = builder.create_node("text", name="Key Hint", parent_id=foot_right)
        builder.set_properties(f_key, text=key_hint, fontSize=10.5, fill="#8b949e", fontFamily="monospace")

    return builder.export_script(), builder.commands


def generate_svg_preview() -> str:
    """Create a high-fidelity SVG preview matching the FigCraft script UI."""
    return r"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 800" width="1080" height="800">
  <defs>
    <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%" filterUnits="userSpaceOnUse">
      <feGaussianBlur stdDeviation="16" in="SourceAlpha" />
      <feOffset dx="0" dy="12" />
      <feComponentTransfer><feFuncA type="linear" slope="0.55"/></feComponentTransfer>
      <feMerge>
        <feMergeNode />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
    <linearGradient id="headerGrad" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#1c2128" />
      <stop offset="100%" stop-color="#161b22" />
    </linearGradient>
    <linearGradient id="bannerGrad" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#161b22" />
      <stop offset="100%" stop-color="#1a2332" />
    </linearGradient>
  </defs>

  <!-- Background Canvas -->
  <rect width="100%" height="100%" fill="#06090e" />

  <!-- Main Window Frame -->
  <g transform="translate(40, 40)" filter="url(#shadow)">
    <!-- Window Body Background -->
    <rect width="1000" height="720" rx="14" fill="#0d1117" stroke="#30363d" stroke-width="1.5" />

    <!-- Header Bar -->
    <path d="M 0,14 Q 0,0 14,0 L 986,0 Q 1000,0 1000,14 L 1000,44 L 0,44 Z" fill="url(#headerGrad)" stroke="#30363d" stroke-width="1" />
    <line x1="0" y1="44" x2="1000" y2="44" stroke="#30363d" stroke-width="1" />

    <!-- Window Traffic Lights -->
    <g transform="translate(18, 16)">
      <circle cx="6" cy="6" r="6" fill="#ff5f56" stroke="#e0443e" stroke-width="0.5" />
      <circle cx="26" cy="6" r="6" fill="#ffbd2e" stroke="#dea123" stroke-width="0.5" />
      <circle cx="46" cy="6" r="6" fill="#27c93f" stroke="#1aab29" stroke-width="0.5" />
    </g>

    <!-- Header Tab / Title -->
    <g transform="translate(320, 7)">
      <rect width="360" height="30" rx="6" fill="#0d1117" stroke="#30363d" stroke-width="1" />
      <text x="180" y="20" fill="#c9d1d9" font-family="Fira Code, SF Mono, Menlo, monospace" font-size="12" font-weight="500" text-anchor="middle">
        ❯ prosze-shield : session_01 (zsh)
      </text>
    </g>

    <!-- Header Live Status Pill -->
    <g transform="translate(860, 9)">
      <rect width="122" height="26" rx="13" fill="#1f242c" stroke="#388bfd55" stroke-width="1" />
      <circle cx="16" cy="13" r="4.5" fill="#3fb950">
        <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite" />
      </circle>
      <text x="28" y="17" fill="#58a6ff" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="10.5" font-weight="700" letter-spacing="0.5">SHIELD ACTIVE</text>
    </g>

    <!-- Terminal Canvas Interior -->
    <g transform="translate(24, 60)">
      <!-- ASCII Logo / Banner Card -->
      <g>
        <rect width="952" height="114" rx="8" fill="url(#bannerGrad)" stroke="#21262d" stroke-width="1" />
        <text x="20" y="24" fill="#58a6ff" font-family="Fira Code, SF Mono, Menlo, monospace" font-size="11" line-height="1.3" xml:space="preserve">
  ____  ____   ___  ____  _____ _____
 |  _ \|  _ \ / _ \/ ___||__  /| ____|
 | |_) | |_) | | | \___ \  / / |  _|  
 |  __/|  _ &lt;| |_| |___) |/ /_ | |___ 
 |_|   |_| \_\\___/|____//____||_____|  v1.4.2 [Zero-Leak Local Privacy Shield]
        </text>

        <!-- Status Badges inside Banner -->
        <g transform="translate(20, 80)">
          <!-- Badge 1 -->
          <g>
            <rect width="180" height="22" rx="4" fill="#0d1117" stroke="#238636" stroke-width="1" />
            <text x="90" y="15" fill="#3fb950" font-family="monospace" font-size="10.5" text-anchor="middle">NER Engine: GLiNER (Active)</text>
          </g>
          <!-- Badge 2 -->
          <g transform="translate(190, 0)">
            <rect width="160" height="22" rx="4" fill="#0d1117" stroke="#1f6feb" stroke-width="1" />
            <text x="80" y="15" fill="#79c0ff" font-family="monospace" font-size="10.5" text-anchor="middle">Proxy: 127.0.0.1:8080</text>
          </g>
          <!-- Badge 3 -->
          <g transform="translate(360, 0)">
            <rect width="185" height="22" rx="4" fill="#0d1117" stroke="#9e6a03" stroke-width="1" />
            <text x="92" y="15" fill="#d29922" font-family="monospace" font-size="10.5" text-anchor="middle">Vault: 14 Entities Shielded</text>
          </g>
          <!-- Badge 4 -->
          <g transform="translate(555, 0)">
            <rect width="180" height="22" rx="4" fill="#0d1117" stroke="#8957e5" stroke-width="1" />
            <text x="90" y="15" fill="#bc8cff" font-family="monospace" font-size="10.5" text-anchor="middle">AES-GCM Memory Shield</text>
          </g>
        </g>
      </g>

      <!-- Terminal Command 1 -->
      <g transform="translate(0, 134)">
        <text x="0" y="18" fill="#3fb950" font-family="Fira Code, monospace" font-size="13" font-weight="700">user@host ❯</text>
        <text x="110" y="18" fill="#f0f6fc" font-family="Fira Code, monospace" font-size="13">prosze redact --in customer_report.txt --stream --ai claude-3-5-sonnet</text>
      </g>

      <!-- Redaction Activity Card -->
      <g transform="translate(0, 168)">
        <rect width="952" height="110" rx="8" fill="#161b22" stroke="#30363d" stroke-width="1" />
        <text x="16" y="24" fill="#f0883e" font-family="Fira Code, monospace" font-size="11.5" font-weight="700">
          🔒 SHIELD INTERCEPTED &amp; REDACTED 3 HIGH-RISK TOKENS (PRE-FLIGHT):
        </text>

        <!-- Redacted Items -->
        <g transform="translate(16, 38)">
          <text x="0" y="14" fill="#58a6ff" font-family="Fira Code, monospace" font-size="12">[[NAME_PERSON_1]]</text>
          <text x="210" y="14" fill="#8b949e" font-family="monospace" font-size="12">Full Name ('Sarah Jenkins')</text>
          <text x="560" y="14" fill="#7ee787" font-family="monospace" font-size="11">Confidence: 99.4% [GLiNER]</text>

          <text x="0" y="34" fill="#58a6ff" font-family="Fira Code, monospace" font-size="12">[[KEY_STRIPE_SECRET_1]]</text>
          <text x="210" y="34" fill="#8b949e" font-family="monospace" font-size="12">API Key ('sk_live_51M...38x')</text>
          <text x="560" y="34" fill="#7ee787" font-family="monospace" font-size="11">Entropy: 4.88 bit/sym [High Risk]</text>

          <text x="0" y="54" fill="#58a6ff" font-family="Fira Code, monospace" font-size="12">[[IBAN_DE_1]]</text>
          <text x="210" y="54" fill="#8b949e" font-family="monospace" font-size="12">Bank Account ('DE89370400440532013000')</text>
          <text x="560" y="54" fill="#7ee787" font-family="monospace" font-size="11">MOD-97 Validated</text>
        </g>
      </g>

      <!-- AI Response Card -->
      <g transform="translate(0, 292)">
        <rect width="952" height="110" rx="8" fill="#090d13" stroke="#1f6feb44" stroke-width="1" />
        <g transform="translate(16, 20)">
          <text x="0" y="0" fill="#bc8cff" font-family="Fira Code, monospace" font-size="11.5" font-weight="700">
            ✦ AI ASSISTANT (RESTORED ON THE FLY VIA LOCAL VAULT):
          </text>
          <text x="0" y="24" fill="#c9d1d9" font-family="Fira Code, SF Mono, Menlo, monospace" font-size="12" line-height="1.5">
            Analysis complete for Sarah Jenkins. The subscription billing on account DE89370400440532013000
          </text>
          <text x="0" y="44" fill="#c9d1d9" font-family="Fira Code, SF Mono, Menlo, monospace" font-size="12" line-height="1.5">
            was reconciled against Stripe key sk_live_51M...38x. All transactions match ledger criteria.
          </text>
          <text x="0" y="64" fill="#7ee787" font-family="Fira Code, SF Mono, Menlo, monospace" font-size="12" line-height="1.5">
            ✓ Total verified: $14,250.00 USD across 3 recurring customer invoices.
          </text>
        </g>
      </g>

      <!-- Bottom Interactive Input Deck -->
      <g transform="translate(0, 524)">
        <!-- Input Box -->
        <rect width="952" height="42" rx="6" fill="#161b22" stroke="#58a6ff" stroke-width="1.5" />
        <text x="16" y="26" fill="#58a6ff" font-family="monospace" font-size="15" font-weight="bold">❯</text>
        <text x="36" y="26" fill="#8b949e" font-family="Fira Code, monospace" font-size="12.5">
          Type prompt or /help, /models, /vault, /exit...
        </text>
        <rect x="410" y="12" width="8" height="18" fill="#58a6ff">
          <animate attributeName="opacity" values="1;0;1" dur="1s" repeatCount="indefinite" />
        </rect>

        <!-- Footer Status Bar -->
        <g transform="translate(0, 50)">
          <rect width="952" height="26" rx="4" fill="#090d13" stroke="#30363d" stroke-width="1" />
          <!-- Left Indicators -->
          <text x="12" y="17" fill="#3fb950" font-family="monospace" font-size="10.5" font-weight="700">MODE: ZERO-LEAK INTERACTIVE</text>
          <text x="220" y="17" fill="#58a6ff" font-family="monospace" font-size="10.5" font-weight="700">UPSTREAM: api.anthropic.com</text>
          <text x="440" y="17" fill="#79c0ff" font-family="monospace" font-size="10.5" font-weight="700">LATENCY: 142ms</text>

          <!-- Right Key Hints -->
          <text x="630" y="17" fill="#8b949e" font-family="monospace" font-size="10.5">[Enter] Send</text>
          <text x="720" y="17" fill="#8b949e" font-family="monospace" font-size="10.5">[Esc] Cancel</text>
          <text x="810" y="17" fill="#8b949e" font-family="monospace" font-size="10.5">[/help] Commands</text>
          <text x="900" y="17" fill="#8b949e" font-family="monospace" font-size="10.5">[^C] Exit</text>
        </g>
      </g>
    </g>
  </g>
</svg>"""


def main() -> None:
    target_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(target_dir, exist_ok=True)

    script_json_str, commands = generate_figcraft_script()
    json_path = os.path.join(target_dir, "figcraft_cli_ui.json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(script_json_str)

    svg_content = generate_svg_preview()
    svg_path = os.path.join(target_dir, "figcraft_cli_ui_preview.svg")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    print(f"Generated FigCraft CLI Script with {len(commands)} commands -> {json_path}")
    print(f"Generated Visual SVG Preview -> {svg_path}")


if __name__ == "__main__":
    main()
