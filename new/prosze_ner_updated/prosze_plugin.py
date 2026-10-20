"""Prosze Privacy Plugin for Hermes Agent.

Provides zero-leak local privacy shielding for Hermes Agent:
1. Toolset:
   - prosze_redact: Redact sensitive keys, passwords, PII, names, and custom terms.
   - prosze_restore: Restore placeholders back to original secrets using the local vault.
   - prosze_check: Audit text for sensitive content without leaking secrets.
   - prosze_add_term: Dynamically register sensitive terms or labelled secrets.
   - prosze_vault_status: Inspect privacy shield vault status safely.
   - prosze_clear_vault: Reset session vault mappings.
2. Lifecycle Hooks:
   - pre_api_request: Redacts prompt messages before they reach external LLMs.
   - post_api_request: Restores privacy placeholders in LLM responses.
   - pre_tool_call: Audits or redacts sensitive parameters before tool calls.
   - post_tool_call: Restores placeholders or audits tool call outputs.
3. Commands:
   - /prosze: Displays shield vault status and protection metrics.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Ensure sibling modules can be imported
_CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

try:
    from prosze_proxy import Vault, walk
except ImportError:
    import importlib.util

    _proxy_file = os.path.join(_CURRENT_DIR, "prosze_proxy.py")
    if os.path.exists(_proxy_file):
        _spec = importlib.util.spec_from_file_location("prosze_proxy", _proxy_file)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        Vault = _mod.Vault
        walk = _mod.walk
    else:
        raise

logger = logging.getLogger("hermes.plugin.prosze")

# Singleton Vault for the Hermes Agent session
_SESSION_VAULT: Optional[Vault] = None


def get_vault(map_path: str = ".prosze-map", disable_ner: bool = False) -> Vault:
    """Retrieve or initialize the active session Vault."""
    global _SESSION_VAULT
    if _SESSION_VAULT is None:
        _SESSION_VAULT = Vault(map_path)
        if disable_ner or os.environ.get("PROSZE_NO_NER", "0") == "1":
            _SESSION_VAULT._ner_attempted = True

        # Load common local secret definitions if present
        if os.path.exists(".prosze-terms"):
            _SESSION_VAULT.load_terms(".prosze-terms")
        if os.path.exists(".env"):
            _SESSION_VAULT.load_env(".env")

    return _SESSION_VAULT


def set_vault(vault: Optional[Vault]) -> None:
    """Explicitly assign or reset the active session Vault."""
    global _SESSION_VAULT
    _SESSION_VAULT = vault


# ---------------------------------------------------------------------------
# Tool Schemas
# ---------------------------------------------------------------------------

PROSZE_REDACT_SCHEMA = {
    "name": "prosze_redact",
    "description": (
        "Redact sensitive data (API keys, bearer tokens, passwords, emails, IPs, "
        "custom terms, and person names) from text by replacing them with deterministic "
        "placeholders (e.g. [[KEY_1]], [[PERSON_1]])."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The input text containing sensitive information to redact.",
            }
        },
        "required": ["text"],
    },
}

PROSZE_RESTORE_SCHEMA = {
    "name": "prosze_restore",
    "description": (
        "Restore deterministic privacy placeholders (such as [[KEY_1]] or [[PERSON_1]]) "
        "back to their original values using the local session privacy vault."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The text containing placeholders to be restored.",
            }
        },
        "required": ["text"],
    },
}

PROSZE_CHECK_SCHEMA = {
    "name": "prosze_check",
    "description": (
        "Audit a text string to check if it contains sensitive information (credentials, "
        "tokens, PII, names) without leaking or exposing the underlying secrets."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The text to audit for sensitive content.",
            }
        },
        "required": ["text"],
    },
}

PROSZE_ADD_TERM_SCHEMA = {
    "name": "prosze_add_term",
    "description": (
        "Register a custom sensitive term or labelled secret into the privacy shield "
        "(e.g., 'Project Orion' or 'CLIENT=Acme Corp') so that it will be masked during "
        "subsequent calls."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "term": {
                "type": "string",
                "description": "The secret term or LABEL=secret pair to protect.",
            }
        },
        "required": ["term"],
    },
}

PROSZE_VAULT_STATUS_SCHEMA = {
    "name": "prosze_vault_status",
    "description": (
        "Retrieve safe summary metrics from the privacy vault (e.g., count of protected "
        "items, active labels, map file path) without disclosing raw secret values."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
    },
}

PROSZE_CLEAR_VAULT_SCHEMA = {
    "name": "prosze_clear_vault",
    "description": "Clear the in-memory privacy vault mappings for the current Hermes session.",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}


# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------

def handle_prosze_redact(params: Dict[str, Any], **kwargs: Any) -> str:
    vault = get_vault()
    text = str(params.get("text", ""))
    safe_text, count = vault.redact(text)
    return json.dumps({
        "success": True,
        "redacted_text": safe_text,
        "hidden_count": count,
        "has_sensitive_data": count > 0,
    })


def handle_prosze_restore(params: Dict[str, Any], **kwargs: Any) -> str:
    vault = get_vault()
    text = str(params.get("text", ""))
    restored_text = vault.restore(text)
    return json.dumps({
        "success": True,
        "restored_text": restored_text,
    })


def handle_prosze_check(params: Dict[str, Any], **kwargs: Any) -> str:
    vault = get_vault()
    text = str(params.get("text", ""))
    _, count = vault.redact(text)
    return json.dumps({
        "success": True,
        "has_sensitive_data": count > 0,
        "sensitive_count": count,
    })


def handle_prosze_add_term(params: Dict[str, Any], **kwargs: Any) -> str:
    vault = get_vault()
    term = str(params.get("term", "")).strip()
    if not term:
        return json.dumps({"success": False, "error": "Empty term provided"})
    vault.add_term(term)
    return json.dumps({
        "success": True,
        "message": f"Successfully registered term in privacy vault: {term}",
    })


def handle_prosze_vault_status(params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> str:
    vault = get_vault()
    labels: Dict[str, int] = {}
    for ph in vault.fwd.keys():
        label = ph.strip("[]").split("_")[0]
        labels[label] = labels.get(label, 0) + 1

    return json.dumps({
        "success": True,
        "active_mappings_count": len(vault.fwd),
        "labels_breakdown": labels,
        "map_path": vault.map_path,
        "ner_enabled": not getattr(vault, "_ner_attempted", False),
    })


def handle_prosze_clear_vault(params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> str:
    vault = get_vault()
    count_before = len(vault.fwd)
    vault.fwd.clear()
    vault.bwd.clear()
    vault.counters.clear()
    return json.dumps({
        "success": True,
        "message": f"Vault cleared ({count_before} mapping(s) removed)",
    })


# ---------------------------------------------------------------------------
# Lifecycle Hooks
# ---------------------------------------------------------------------------

def hook_pre_api_request(*args: Any, **kwargs: Any) -> Optional[Any]:
    """Hook invoked before an API request is dispatched to the LLM.
    Redacts sensitive content in message contents or prompts in place.
    """
    try:
        vault = get_vault()
        # Case 1: messages passed as keyword argument or first arg
        messages = kwargs.get("messages")
        if messages is None and args and isinstance(args[0], list):
            messages = args[0]

        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict) and "content" in msg and isinstance(msg["content"], str):
                    redacted, count = vault.redact(msg["content"])
                    if count > 0:
                        msg["content"] = redacted
                        logger.info(f"[prosze] Redacted {count} sensitive item(s) from message")

        # Case 2: payload dict passed
        payload = kwargs.get("payload")
        if payload is None and args and isinstance(args[0], dict):
            payload = args[0]

        if isinstance(payload, dict):
            transformed_payload = walk(payload, lambda s: vault.redact(s)[0])
            payload.clear()
            payload.update(transformed_payload)
            return payload

        return messages or None
    except Exception as exc:
        logger.warning(f"[prosze] pre_api_request hook warning: {exc}")
        return None


def hook_post_api_request(*args: Any, **kwargs: Any) -> Optional[Any]:
    """Hook invoked after an LLM response is received.
    Restores any placeholders so that the agent loop receives genuine content.
    """
    try:
        vault = get_vault()
        response = kwargs.get("response")
        if response is None and args:
            response = args[0]

        if isinstance(response, str):
            return vault.restore(response)

        if isinstance(response, dict):
            restored = walk(response, lambda s: vault.restore(s))
            response.clear()
            response.update(restored)
            return response

        return response
    except Exception as exc:
        logger.warning(f"[prosze] post_api_request hook warning: {exc}")
        return None


def hook_pre_tool_call(tool_name: str = "", params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
    """Audit tool call parameters before execution."""
    try:
        if not tool_name or tool_name.startswith("prosze_"):
            return
        vault = get_vault()
        p = params or kwargs.get("params") or {}
        if isinstance(p, dict):
            total_sensitive = 0
            for val in p.values():
                if isinstance(val, str):
                    _, count = vault.redact(val)
                    total_sensitive += count
            if total_sensitive > 0:
                logger.info(f"[prosze] Detected {total_sensitive} sensitive value(s) in tool arguments for '{tool_name}'")
    except Exception as exc:
        logger.warning(f"[prosze] pre_tool_call hook warning: {exc}")


def hook_post_tool_call(tool_name: str = "", params: Optional[Dict[str, Any]] = None, result: Any = None, **kwargs: Any) -> Optional[Any]:
    """Hook invoked after tool execution."""
    try:
        if not tool_name or tool_name.startswith("prosze_"):
            return result
        # Restore placeholders if tool returns text with placeholders
        vault = get_vault()
        if isinstance(result, str):
            return vault.restore(result)
        if isinstance(result, dict):
            restored = walk(result, lambda s: vault.restore(s))
            result.clear()
            result.update(restored)
            return result
        return result
    except Exception as exc:
        logger.warning(f"[prosze] post_tool_call hook warning: {exc}")
        return result


# ---------------------------------------------------------------------------
# Slash Command Handler
# ---------------------------------------------------------------------------

def handle_prosze_command(*args: Any, **kwargs: Any) -> str:
    """Command handler for `/prosze` in Hermes interactive session."""
    status_json = handle_prosze_vault_status()
    data = json.loads(status_json)
    lines = [
        "[Prosze Privacy Shield]",
        f"Active protected mappings: {data.get('active_mappings_count', 0)}",
        f"Vault map path: {data.get('map_path', '')}",
    ]
    labels = data.get("labels_breakdown", {})
    if labels:
        lines.append("Labels breakdown: " + ", ".join(f"{k}: {v}" for k, v in sorted(labels.items())))
    else:
        lines.append("No active secret mappings currently in vault.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registration Entry Point
# ---------------------------------------------------------------------------

def register(ctx: Any) -> None:
    """Register Prosze tools, hooks, and commands with Hermes Agent."""
    logger.info("Registering Prosze privacy plugin with Hermes Agent...")

    # 1. Register Tools
    toolset_name = "prosze"
    tools = [
        ("prosze_redact", PROSZE_REDACT_SCHEMA, handle_prosze_redact),
        ("prosze_restore", PROSZE_RESTORE_SCHEMA, handle_prosze_restore),
        ("prosze_check", PROSZE_CHECK_SCHEMA, handle_prosze_check),
        ("prosze_add_term", PROSZE_ADD_TERM_SCHEMA, handle_prosze_add_term),
        ("prosze_vault_status", PROSZE_VAULT_STATUS_SCHEMA, handle_prosze_vault_status),
        ("prosze_clear_vault", PROSZE_CLEAR_VAULT_SCHEMA, handle_prosze_clear_vault),
    ]

    for name, schema, handler in tools:
        if hasattr(ctx, "register_tool"):
            ctx.register_tool(
                name=name,
                toolset=toolset_name,
                schema=schema,
                handler=handler,
            )

    # 2. Register Lifecycle Hooks
    hooks = [
        ("pre_api_request", hook_pre_api_request),
        ("post_api_request", hook_post_api_request),
        ("pre_tool_call", hook_pre_tool_call),
        ("post_tool_call", hook_post_tool_call),
    ]

    for hook_name, hook_fn in hooks:
        if hasattr(ctx, "register_hook"):
            ctx.register_hook(hook_name, hook_fn)

    # 3. Register Slash Command if supported
    if hasattr(ctx, "register_command"):
        ctx.register_command(
            name="prosze",
            description="Display Prosze privacy vault metrics and shield status.",
            handler=handle_prosze_command,
        )


if __name__ == "__main__":
    print(handle_prosze_command())
