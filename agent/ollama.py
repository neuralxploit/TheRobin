"""
Ollama HTTP client — streaming chat with tool calling.
Uses stdlib urllib to avoid extra dependencies.

stream=True keeps the TCP connection alive during long generations
(report writing, large tool outputs) by sending tokens as they arrive.
Without streaming, the cloud proxy kills idle connections after ~60s.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Callable

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


class ContextOverflowError(Exception):
    """Raised when Ollama returns 500 due to context window overflow."""
    pass


class OOMError(Exception):
    """Raised when Ollama can't allocate enough memory for the model + num_ctx."""
    pass


# Tracks the effective num_ctx — auto-reduced on OOM errors.
_effective_num_ctx = {}


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
        # Don't count images — they are processed separately by the vision model
        # and don't consume text context tokens
    return total // 4


def _handle_http_error(e: urllib.error.HTTPError) -> None:
    """Parse Ollama HTTPError and raise the right exception type."""
    body = ""
    try:
        body = e.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    if e.code == 413:
        raise ContextOverflowError(
            f"Request too large (HTTP 413) — history payload exceeded Ollama limit. "
            f"Ollama detail: {body[:200]}"
        )
    if e.code == 500:
        body_lower = body.lower()
        # OOM: model too large for available memory at current num_ctx
        if "requires more system memory" in body_lower or "out of memory" in body_lower:
            raise OOMError(
                f"Not enough RAM for current num_ctx. "
                f"Ollama detail: {body[:300]}"
            )
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


def _is_cloud_model(model: str) -> bool:
    """Cloud models use ':cloud' suffix or remote Ollama host."""
    if not model:
        return False
    return ":cloud" in model.lower() or OLLAMA_BASE != "http://localhost:11434"


def _get_num_ctx(model: str) -> int:
    """Pick num_ctx based on user override, OOM reduction, or auto-detect."""
    if model in _effective_num_ctx:
        return _effective_num_ctx[model]
    if _is_cloud_model(model):
        return 800_000
    return 32_768


def set_num_ctx(model: str, num_ctx: int):
    """Explicitly set num_ctx for a model (called when user sets COMPACT)."""
    _effective_num_ctx[model] = num_ctx


def _reduce_num_ctx(model: str) -> int:
    """Halve num_ctx for a model after OOM. Returns the new value."""
    current = _get_num_ctx(model)
    reduced = max(current // 2, 4096)
    _effective_num_ctx[model] = reduced
    return reduced


def get_compact_threshold(model: str) -> int:
    """Return a sensible compact threshold for the model type."""
    ctx = _get_num_ctx(model)
    # Compact at ~75% of the context window
    return int(ctx * 0.75)


def _strip_images(messages: list[dict]) -> list[dict]:
    """
    Strip all images from messages before sending to Ollama.
    Prevents HTTP 413 (payload too large) and HTTP 400 (model doesn't support vision).
    """
    result = []
    for m in messages:
        if m.get("images"):
            m = {k: v for k, v in m.items() if k != "images"}
        result.append(m)
    return result


def _do_chat(model: str, messages: list[dict], tools: list[dict], stream: bool,
             timeout: int = 300) -> tuple[str, list[dict]]:
    """Core chat call with OOM auto-retry — halves num_ctx up to 3 times on OOM."""
    clean_msgs = _strip_images(messages)

    for attempt in range(4):
        num_ctx = _get_num_ctx(model)
        payload = json.dumps({
            "model": model,
            "messages": clean_msgs,
            "tools": tools,
            "stream": stream,
            "options": {
                "temperature": 0.3,
                "num_ctx": num_ctx,
            },
        }).encode()

        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if not stream:
                        data = json.loads(resp.read())
                        msg = data.get("message", {})
                        return msg.get("content", ""), msg.get("tool_calls", [])
                    else:
                        content_parts = []
                        tool_calls = []
                        for line in resp:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                chunk = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            msg = chunk.get("message", {})
                            if msg.get("content"):
                                content_parts.append(msg["content"])
                            if msg.get("tool_calls"):
                                tool_calls.extend(msg["tool_calls"])
                            if chunk.get("done"):
                                break
                        return "".join(content_parts), tool_calls

            except urllib.error.HTTPError as e:
                _handle_http_error(e)  # may raise OOMError, ContextOverflowError, or ConnectionError
            except urllib.error.URLError as e:
                raise ConnectionError(f"Cannot reach Ollama at {OLLAMA_BASE}: {e}")

        except OOMError:
            if attempt < 3:
                new_ctx = _reduce_num_ctx(model)
                import sys
                print(f"  [OOM] num_ctx too large — reducing to {new_ctx:,} and retrying...",
                      file=sys.stderr)
                continue
            raise


def stream_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
    on_token: Callable = None,
) -> tuple[str, list[dict]]:
    """Non-streaming chat with OOM auto-retry."""
    return _do_chat(model, messages, tools, stream=False)


def simple_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
) -> tuple[str, list[dict]]:
    """Streaming chat with OOM auto-retry. Used for compaction/summary calls."""
    return _do_chat(model, messages, tools, stream=True)
