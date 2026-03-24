"""
LM Studio HTTP client — OpenAI-compatible chat with tool calling.
Uses stdlib urllib to avoid extra dependencies.

LM Studio serves an OpenAI-compatible API at http://localhost:1234/v1.
Models are prefixed with "lmstudio:" in TheRobin (e.g. lmstudio:qwen2.5-coder-32b).

Set LMSTUDIO_BASE to override the default URL (e.g. http://remote-host:1234).
"""

import json
import os
import urllib.request
import urllib.error
from typing import Callable

LMSTUDIO_BASE = os.environ.get("LMSTUDIO_BASE", "http://localhost:1234")
if not LMSTUDIO_BASE.startswith(("http://", "https://")):
    raise ValueError(f"LMSTUDIO_BASE must use http:// or https:// scheme, got: {LMSTUDIO_BASE}")

# Reuse the same ContextOverflowError class so loop.py's except clause catches it
from .ollama import ContextOverflowError


def list_models() -> list[str]:
    """Return list of available model names from LM Studio."""
    try:
        with urllib.request.urlopen(f"{LMSTUDIO_BASE}/v1/models", timeout=5) as resp:
            data = json.loads(resp.read())
            return [m["id"] for m in data.get("data", [])]
    except Exception:
        return []


def strip_prefix(model: str) -> str:
    """Remove the 'lmstudio:' routing prefix to get the actual model ID."""
    if model.lower().startswith("lmstudio:"):
        return model[len("lmstudio:"):]
    return model


def _handle_http_error(e: urllib.error.HTTPError) -> None:
    """Parse LM Studio HTTPError and raise the right exception type."""
    body = ""
    try:
        body = e.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    if e.code == 400:
        body_lower = body.lower()
        if "context" in body_lower or "too long" in body_lower or "maximum" in body_lower:
            raise ContextOverflowError(
                f"Context window overflow. LM Studio detail: {body[:300]}"
            )
    if e.code == 404:
        raise ConnectionError(
            f"Model not found in LM Studio. Load a model first. Detail: {body[:200]}"
        )
    raise ConnectionError(f"LM Studio HTTP {e.code}: {body[:300]}")


def stream_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
    on_token: Callable = None,
) -> tuple[str, list[dict]]:
    """
    Non-streaming chat with LM Studio. Returns (content, tool_calls) in Ollama format.
    The on_token param is accepted for interface compatibility.
    """
    actual_model = strip_prefix(model)

    # Convert tools from Ollama format (already OpenAI-compatible)
    # LM Studio expects OpenAI format: {"type": "function", "function": {...}}
    openai_tools = []
    for t in tools:
        if "function" in t:
            openai_tools.append(t)
        else:
            # Already in flat format, wrap it
            openai_tools.append({
                "type": "function",
                "function": t,
            })

    payload = {
        "model": actual_model,
        "messages": messages,
        "temperature": 0.3,
        "stream": False,
    }

    # Only include tools if non-empty (some models choke on empty tools array)
    if openai_tools:
        payload["tools"] = openai_tools

    data = json.dumps(payload).encode()

    req = urllib.request.Request(
        f"{LMSTUDIO_BASE}/v1/chat/completions",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            result = json.loads(resp.read())
            choice = result.get("choices", [{}])[0]
            msg = choice.get("message", {})
            content = msg.get("content", "") or ""
            tool_calls = _convert_tool_calls(msg.get("tool_calls", []))
            return content, tool_calls

    except urllib.error.HTTPError as e:
        _handle_http_error(e)  # always raises
    except urllib.error.URLError as e:
        raise ConnectionError(
            f"Cannot reach LM Studio at {LMSTUDIO_BASE}: {e}\n"
            f"Make sure LM Studio is running with a model loaded."
        )
    return "", []  # unreachable, but keeps return type explicit


def simple_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
) -> tuple[str, list[dict]]:
    """
    Streaming chat for compaction/summary calls.
    Uses SSE streaming so long generations don't time out.
    """
    actual_model = strip_prefix(model)

    openai_tools = []
    for t in tools:
        if "function" in t:
            openai_tools.append(t)
        else:
            openai_tools.append({"type": "function", "function": t})

    payload = {
        "model": actual_model,
        "messages": messages,
        "temperature": 0.3,
        "stream": True,
    }

    if openai_tools:
        payload["tools"] = openai_tools

    data = json.dumps(payload).encode()

    req = urllib.request.Request(
        f"{LMSTUDIO_BASE}/v1/chat/completions",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            content_parts = []
            tool_calls_by_idx = {}

            for line in resp:
                line = line.decode("utf-8", errors="replace").strip()
                if not line or not line.startswith("data: "):
                    continue
                chunk_str = line[6:]  # strip "data: "
                if chunk_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(chunk_str)
                except json.JSONDecodeError:
                    continue

                delta = chunk.get("choices", [{}])[0].get("delta", {})

                if delta.get("content"):
                    content_parts.append(delta["content"])

                # Accumulate streamed tool calls by index
                for tc in delta.get("tool_calls", []):
                    idx = tc.get("index", 0)
                    if idx not in tool_calls_by_idx:
                        tool_calls_by_idx[idx] = {
                            "id": tc.get("id", ""),
                            "name": "",
                            "arguments": "",
                        }
                    fn = tc.get("function", {})
                    if fn.get("name"):
                        tool_calls_by_idx[idx]["name"] = fn["name"]
                    if fn.get("arguments"):
                        tool_calls_by_idx[idx]["arguments"] += fn["arguments"]

            # Convert accumulated tool calls to Ollama format
            tool_calls = []
            for idx in sorted(tool_calls_by_idx):
                tc = tool_calls_by_idx[idx]
                args = tc["arguments"]
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError):
                    args = {"code": args} if args else {}
                tool_calls.append({
                    "function": {
                        "name": tc["name"],
                        "arguments": args,
                    },
                })

            return "".join(content_parts), tool_calls

    except urllib.error.HTTPError as e:
        _handle_http_error(e)  # always raises
    except urllib.error.URLError as e:
        raise ConnectionError(
            f"Cannot reach LM Studio at {LMSTUDIO_BASE}: {e}\n"
            f"Make sure LM Studio is running with a model loaded."
        )
    return "", []  # unreachable, but keeps return type explicit


def _convert_tool_calls(openai_tool_calls: list[dict]) -> list[dict]:
    """Convert OpenAI-format tool_calls to Ollama format."""
    if not openai_tool_calls:
        return []
    result = []
    for tc in openai_tool_calls:
        fn = tc.get("function", {})
        args = fn.get("arguments", "{}")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"code": args}
        result.append({
            "function": {
                "name": fn.get("name", ""),
                "arguments": args,
            },
        })
    return result
