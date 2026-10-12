"""Hermes Continuous API Connector for Prosze.

Provides zero-leak, multi-turn AI streaming using credentials from:
1. Command line options / environment variables
2. Hermes auth store (~/AppData/Local/hermes/auth.json or ~/.hermes/auth.json)
3. Hermes config (~/AppData/Local/hermes/config.yaml or ~/.hermes/config.yaml)
4. Upstage Solar / OpenAI / Anthropic / Local endpoints
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Generator, Iterator, Optional

try:
    import requests
except ImportError:
    requests = None


@dataclass
class HermesConfig:
    api_key: str = ""
    api_base: str = "https://inference-api.nousresearch.com/v1"
    model: str = "upstage/solar-mini4:free"
    provider: str = "nous"
    is_anthropic: bool = False
    system_prompt: str = "You are Hermes, an intelligent and helpful AI assistant. Answer clearly and concisely."
    available_models: list[str] = field(default_factory=list)

    @classmethod
    def load(
        cls,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> HermesConfig:
        """Auto-detect configuration from env vars, Hermes config/auth stores, or explicit parameters."""
        cfg = cls()

        # 1. Read Hermes config.yaml (if present)
        hermes_cfg_paths = [
            os.path.expanduser("~/AppData/Local/hermes/config.yaml"),
            os.path.expanduser("~/.hermes/config.yaml"),
            os.path.expanduser("~/.config/hermes/config.yaml"),
        ]
        conf_data: dict[str, Any] = {}
        for cp in hermes_cfg_paths:
            if os.path.exists(cp):
                try:
                    with open(cp, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    # Parse essential YAML fields without third-party pyyaml requirement
                    m_model = re.search(r"^\s*model:\s*\n\s+default:\s*[\"']?([^\"'#\n]+)", text, re.M)
                    if m_model:
                        conf_data["model"] = m_model.group(1).strip()
                    m_base = re.search(r"base_url:\s*[\"']?([^\"'#\n]+)", text)
                    if m_base:
                        conf_data["base_url"] = m_base.group(1).strip().rstrip("/")
                    m_prov = re.search(r"provider:\s*[\"']?([^\"'#\n]+)", text)
                    if m_prov:
                        conf_data["provider"] = m_prov.group(1).strip()
                    break
                except Exception:
                    pass

        # 2. Read Hermes auth.json (if present)
        hermes_auth_paths = [
            os.path.expanduser("~/AppData/Local/hermes/auth.json"),
            os.path.expanduser("~/.hermes/auth.json"),
            os.path.expanduser("~/.config/hermes/auth.json"),
        ]
        auth_data: dict[str, Any] = {}
        for ap in hermes_auth_paths:
            if os.path.exists(ap):
                try:
                    with open(ap, encoding="utf-8", errors="replace") as f:
                        auth_data = json.load(f)
                    break
                except Exception:
                    pass

        # 3. Resolve API Key & Endpoint
        detected_key = ""
        detected_base = ""
        detected_provider = conf_data.get("provider", "nous")

        # Check explicit env vars first
        env_key = (
            os.environ.get("NOUS_API_KEY")
            or os.environ.get("UPSTAGE_API_KEY")
            or os.environ.get("SOLAR_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
        )
        if env_key:
            detected_key = env_key

        # Check Hermes auth credentials if not set by env
        if not detected_key and auth_data:
            pool = auth_data.get("credential_pool") or {}
            providers = auth_data.get("providers") or {}

            # Priority order: active provider -> nous -> upstage -> solar -> openai -> anthropic
            candidate_keys = ["nous", "upstage", "solar", "openai", "anthropic"]
            active = auth_data.get("active_provider")
            if active and active in candidate_keys:
                candidate_keys.remove(active)
                candidate_keys.insert(0, active)

            for prov in candidate_keys:
                items = pool.get(prov) or providers.get(prov)
                if not items:
                    continue
                if isinstance(items, dict):
                    items = [items]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    token = (
                        item.get("agent_key")
                        or item.get("access_token")
                        or item.get("api_key")
                    )
                    if token and len(str(token)) > 10:
                        detected_key = str(token)
                        detected_provider = prov
                        if item.get("inference_base_url"):
                            detected_base = str(item["inference_base_url"])
                        elif item.get("base_url"):
                            detected_base = str(item["base_url"])
                        break
                if detected_key:
                    break

        # 4. Resolve Base URL
        env_base = os.environ.get("OPENAI_BASE_URL") or os.environ.get("UPSTAGE_API_BASE") or os.environ.get("ANTHROPIC_BASE_URL")
        final_base = api_base or env_base or detected_base or conf_data.get("base_url")

        if not final_base:
            if detected_provider == "nous":
                final_base = "https://inference-api.nousresearch.com/v1"
            elif detected_provider in ("upstage", "solar"):
                final_base = "https://api.upstage.ai/v1"
            elif detected_provider == "anthropic":
                final_base = "https://api.anthropic.com/v1"
            else:
                final_base = "https://api.openai.com/v1"

        final_base = final_base.rstrip("/")
        # If user passed full /chat/completions, strip it back to base
        if final_base.endswith("/chat/completions"):
            final_base = final_base[:-17]

        # 5. Resolve Model
        final_model = model or os.environ.get("HERMES_MODEL") or os.environ.get("UPSTAGE_MODEL") or conf_data.get("model")

        if not final_model:
            if "nousresearch" in final_base or detected_provider == "nous":
                # Default to verified free model on Nous to prevent 404 credit errors
                final_model = "upstage/solar-mini4:free"
            elif "upstage" in final_base:
                final_model = "solar-pro4"
            else:
                final_model = "gpt-4o-mini"

        # Model mapping for Nous endpoint
        if "nousresearch" in final_base:
            if final_model == "solar-mini4":
                final_model = "upstage/solar-mini4:free"
            elif final_model == "solar-pro4":
                # Default to free tier on Nous unless specified
                final_model = "upstage/solar-mini4:free"
            elif final_model.startswith("solar-") and not final_model.startswith("upstage/"):
                final_model = f"upstage/{final_model}"

        final_key = api_key or detected_key or ""
        is_anthropic = "anthropic" in final_base.lower() or detected_provider == "anthropic"

        cfg.api_key = final_key
        cfg.api_base = final_base
        cfg.model = final_model
        cfg.provider = detected_provider
        cfg.is_anthropic = is_anthropic
        if system_prompt:
            cfg.system_prompt = system_prompt

        return cfg

    def test_connection(self) -> tuple[bool, str, list[str]]:
        """Test API connectivity and return (success, message, list_of_models)."""
        if not requests:
            return False, "requests library is not installed (pip install requests)", []
        if not self.api_key:
            return False, "No API key configured.", []

        headers = self.get_headers()
        models_url = f"{self.api_base}/models"
        try:
            resp = requests.get(models_url, headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("id") for m in data.get("data", []) if m.get("id")]
                self.available_models = models
                return True, f"Connected ({len(models)} models available)", models
            elif resp.status_code == 404:
                # Some OpenAI-compatible servers don't expose /models, but chat works
                return True, "Connected (models endpoint unavailable)", []
            else:
                return False, f"HTTP {resp.status_code}: {resp.text[:120]}", []
        except Exception as exc:
            return False, f"Connection error: {exc}", []

    def get_headers(self) -> dict[str, str]:
        if self.is_anthropic:
            return {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


@dataclass
class ChatTurn:
    role: str
    raw_content: str       # Original text (with real names / secrets)
    safe_content: str      # Redacted text (with placeholders [[PERSON_1]])
    hidden_count: int = 0
    timestamp: str = ""


class ContinuousChatSession:
    """Manages continuous multi-turn dialogue with continuous API streaming and on-the-fly de-redaction."""

    def __init__(self, config: HermesConfig, vault: Any):
        self.config = config
        self.vault = vault
        self.turns: list[ChatTurn] = []
        self._stop_event = threading.Event()
        self.total_tokens_in = 0
        self.total_tokens_out = 0

    def clear(self) -> None:
        """Clear conversation history while keeping vault state."""
        self.turns.clear()
        self.total_tokens_in = 0
        self.total_tokens_out = 0

    def stop(self) -> None:
        """Cancel ongoing stream."""
        self._stop_event.set()

    def get_messages_payload(self, pending_safe_prompt: str) -> list[dict[str, str]]:
        """Construct the message payload sent to the LLM (purely safe text)."""
        messages = []
        if self.config.system_prompt and not self.config.is_anthropic:
            messages.append({"role": "system", "content": self.config.system_prompt})

        for turn in self.turns:
            messages.append({
                "role": turn.role,
                "content": turn.safe_content,
            })

        messages.append({"role": "user", "content": pending_safe_prompt})
        return messages

    def stream_chat(
        self,
        user_prompt: str,
        on_redact: Optional[Callable[[str, int], None]] = None,
        on_chunk: Optional[Callable[[str], None]] = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Stream a chat turn. Yields event dicts as streaming progresses."""
        if not requests:
            yield {"type": "error", "message": "requests package is missing. Install with: pip install requests"}
            return

        self._stop_event.clear()

        # Step 1: Redact user prompt through Vault
        safe_prompt, hidden_n = self.vault.redact(user_prompt)
        if on_redact:
            on_redact(safe_prompt, hidden_n)

        yield {
            "type": "redacted",
            "safe_prompt": safe_prompt,
            "hidden_count": hidden_n,
            "model": self.config.model,
            "endpoint": self.config.api_base,
        }

        # Step 2: Prepare payload
        payload_messages = self.get_messages_payload(safe_prompt)
        headers = self.config.get_headers()

        if self.config.is_anthropic:
            endpoint_url = f"{self.config.api_base}/v1/messages"
            req_body: dict[str, Any] = {
                "model": self.config.model,
                "max_tokens": 4096,
                "system": self.config.system_prompt,
                "messages": payload_messages,
                "stream": True,
            }
        else:
            endpoint_url = f"{self.config.api_base}/chat/completions"
            req_body = {
                "model": self.config.model,
                "messages": payload_messages,
                "stream": True,
                "temperature": 0.7,
                "max_tokens": 4096,
            }

        # Step 3: Stream request
        try:
            resp = requests.post(
                endpoint_url,
                json=req_body,
                headers=headers,
                stream=True,
                timeout=60,
            )
        except Exception as exc:
            yield {"type": "error", "message": f"Connection failed: {exc}"}
            return

        if resp.status_code != 200:
            err_body = resp.text[:300]
            # Handle credit notice / fallback suggestions
            if "insufficient_credits" in err_body and ":free" not in self.config.model:
                fallback_model = "upstage/solar-mini4:free"
                yield {
                    "type": "info",
                    "message": f"Model {self.config.model} requires credits. Auto-switching to free model {fallback_model}...",
                }
                self.config.model = fallback_model
                yield from self.stream_chat(user_prompt, on_redact, on_chunk)
                return

            yield {"type": "error", "message": f"API Error HTTP {resp.status_code}: {err_body}"}
            return

        # Step 4: Stream response and restore placeholders across chunks
        accumulated_raw = []
        accumulated_restored = []
        token_buffer = ""

        # Use regex to detect potential split placeholder prefix like '[[' or '[[PER'
        ph_prefix_re = re.compile(r"\[\[[A-Z0-9_]*$")

        for raw_line in resp.iter_lines():
            if self._stop_event.is_set():
                yield {"type": "cancelled"}
                break

            if not raw_line:
                continue

            line = raw_line.decode("utf-8", "replace")
            if not line.startswith("data: "):
                continue

            data = line[6:].strip()
            if data == "[DONE]":
                break

            try:
                chunk_obj = json.loads(data)
            except json.JSONDecodeError:
                continue

            if self.config.is_anthropic:
                delta = chunk_obj.get("content_block_delta", {})
                delta_text = delta.get("text", "")
            else:
                choices = chunk_obj.get("choices", [])
                delta_text = choices[0].get("delta", {}).get("content", "") if choices else ""

            if not delta_text:
                continue

            accumulated_raw.append(delta_text)
            token_buffer += delta_text

            # If the end of token_buffer looks like a partial placeholder (e.g. "[[PERS"),
            # hold it until more arrives or the placeholder completes
            m_split = ph_prefix_re.search(token_buffer)
            if m_split:
                ready_part = token_buffer[:m_split.start()]
                token_buffer = token_buffer[m_split.start():]
            else:
                ready_part = token_buffer
                token_buffer = ""

            if ready_part:
                restored_part = self.vault.restore(ready_part)
                accumulated_restored.append(restored_part)
                if on_chunk:
                    on_chunk(restored_part)
                yield {"type": "chunk", "text": restored_part}

        # Flush any remaining buffer
        if token_buffer:
            restored_part = self.vault.restore(token_buffer)
            accumulated_restored.append(restored_part)
            if on_chunk:
                on_chunk(restored_part)
            yield {"type": "chunk", "text": restored_part}

        full_raw_reply = "".join(accumulated_raw)
        full_restored_reply = "".join(accumulated_restored)

        # Save to continuous turn memory
        user_turn = ChatTurn(
            role="user",
            raw_content=user_prompt,
            safe_content=safe_prompt,
            hidden_count=hidden_n,
        )
        assistant_turn = ChatTurn(
            role="assistant",
            raw_content=full_restored_reply,
            safe_content=full_raw_reply,
            hidden_count=0,
        )
        self.turns.append(user_turn)
        self.turns.append(assistant_turn)

        yield {
            "type": "done",
            "reply": full_restored_reply,
            "turns_count": len(self.turns) // 2,
        }
