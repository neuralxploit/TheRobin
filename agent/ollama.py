"""
Ollama HTTP client — streaming chat with tool calling.
Uses stdlib urllib to avoid extra dependencies.

stream=True keeps the TCP connection alive during long generations
(report writing, large tool outputs) by sending tokens as they arrive.
Without streaming, the cloud proxy kills idle connections after ~60s.
"""

import json
import urllib.request
import urllib.error
from typing import Callable

OLLAMA_BASE = "http://localhost:11434"


class ContextOverflowError(Exception):
    """Raised when Ollama returns 500 due to context window overflow."""
    pass


def list_models() -> list[str]:
    """Return list of available model names from Ollama."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def _estimate_tokens(messages: list[dict]) -> int:
    """
    Rough token estimate: ~4 chars per token.
    Must count BOTH content AND tool_calls — assistant messages often have
    empty content but large tool_calls JSON that was previously ignored,
    causing the estimate to be 30-50% too low and compaction to fire twice.
    """
    total = 0
    for m in messages:
        total += len(str(m.get("content", "") or ""))
        tc = m.get("tool_calls")
        if tc:
            total += len(str(tc))
    return total // 4


def _handle_http_error(e: urllib.error.HTTPError) -> None:
    """Parse Ollama HTTPError and raise the right exception type."""
    body = ""
    try:
        body = e.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    if e.code == 500:
        body_lower = body.lower()
        cloud_drop = any(k in body_lower for k in (
            "unexpected eof", "connection refused", "connection reset",
            "post \"https://", "post \"http://", "dial tcp", "i/o timeout",
        ))
        if cloud_drop:
            raise ConnectionError(
                f"Cloud connection dropped (not a context overflow). "
                f"Ollama detail: {body[:300]}"
            )
        raise ContextOverflowError(
            f"Context window overflow (history too long). "
            f"Ollama detail: {body[:200]}"
        )
    raise ConnectionError(f"Ollama HTTP {e.code}: {body[:200]}")


def stream_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
    on_token: Callable = None,
) -> tuple[str, list[dict]]:
    """
    Non-streaming chat (stream=False). The on_token param is accepted for
    interface compatibility but not used — content is returned in one block.
    Uses stream=False because the cloud streaming endpoint causes 503 errors.
    """
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_ctx": 196608,
        },
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
            msg = data.get("message", {})
            return msg.get("content", ""), msg.get("tool_calls", [])

    except urllib.error.HTTPError as e:
        _handle_http_error(e)
    except urllib.error.URLError as e:
        raise ConnectionError(f"Cannot reach Ollama at {OLLAMA_BASE}: {e}")


def simple_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
) -> tuple[str, list[dict]]:
    """
    Non-streaming chat. Used only for compaction/summary calls (short, fast).
    Main agentic loop uses stream_chat instead.
    """
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_ctx": 196608,
        },
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
            msg = data.get("message", {})
            return msg.get("content", ""), msg.get("tool_calls", [])

    except urllib.error.HTTPError as e:
        _handle_http_error(e)
    except urllib.error.URLError as e:
        raise ConnectionError(f"Cannot reach Ollama at {OLLAMA_BASE}: {e}")
