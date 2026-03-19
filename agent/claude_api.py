"""
Claude API client — drop-in replacement for ollama.py.

Same interface: stream_chat() and simple_chat() both return (content, tool_calls)
where tool_calls use the Ollama/OpenAI format so loop.py works unchanged.

Requires: ANTHROPIC_API_KEY environment variable.
Optional: ANTHROPIC_MODEL to override the default model.

Usage: set model to "claude-sonnet-4-20250514" (or any claude-* model) in TheRobin
and the agent loop will route to this backend automatically.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Callable


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 8192


class ContextOverflowError(Exception):
    """Raised when Claude returns an error due to context being too large."""
    pass


def is_claude_model(model: str) -> bool:
    """Check if a model name refers to a Claude model."""
    return model.lower().startswith("claude")


def _get_api_key() -> str:
    """Get API key, checking env var at call time (not import time)."""
    key = os.environ.get("ANTHROPIC_API_KEY", "") or ANTHROPIC_API_KEY
    if not key:
        raise ConnectionError(
            "ANTHROPIC_API_KEY not set. Export it:\n"
            "  export ANTHROPIC_API_KEY=sk-ant-..."
        )
    return key


# ── Tool schema conversion ──────────────────────────────────────────────────
# Ollama/OpenAI tools use:  {"type": "function", "function": {"name": ..., "parameters": ...}}
# Claude tools use:         {"name": ..., "input_schema": ...}

def _convert_tools_to_claude(tools: list[dict]) -> list[dict]:
    """Convert OpenAI-format tool schemas to Claude format."""
    claude_tools = []
    for t in tools:
        fn = t.get("function", t)
        claude_tools.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return claude_tools


# ── Message conversion ──────────────────────────────────────────────────────
# Ollama messages: {"role": "system"|"user"|"assistant"|"tool", "content": str, "tool_calls": [...]}
# Claude messages: {"role": "user"|"assistant", "content": str|list[block]}
# Claude system prompt is a top-level param, not a message.

def _convert_messages_to_claude(messages: list[dict]) -> tuple[str, list[dict]]:
    """Convert Ollama-format messages to Claude format.

    Returns (system_prompt, claude_messages).
    Claude doesn't support 'tool' role — tool results go as user messages
    with tool_result content blocks. Tool IDs are generated with a global
    counter and matched 1:1 between tool_use and tool_result blocks.
    """
    system = ""
    claude_msgs = []

    # Collect pending tool results to batch into a single user message
    pending_tool_results = []
    # Queue of tool_use IDs from the last assistant message, consumed by tool results
    pending_tool_ids = []
    # Global counter for stable IDs
    tool_id_counter = 0

    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "") or ""

        if role == "system":
            system = content
            continue

        if role == "assistant":
            tool_calls = m.get("tool_calls", [])
            if tool_calls:
                # Flush any pending tool results first
                if pending_tool_results:
                    claude_msgs.append({
                        "role": "user",
                        "content": pending_tool_results,
                    })
                    pending_tool_results = []

                # Build content blocks: text (if any) + tool_use blocks
                blocks = []
                if content.strip():
                    blocks.append({"type": "text", "text": content})
                pending_tool_ids = []
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    args = fn.get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {"code": args}
                    tid = f"toolu_{tool_id_counter:06d}"
                    tool_id_counter += 1
                    pending_tool_ids.append(tid)
                    blocks.append({
                        "type": "tool_use",
                        "id": tid,
                        "name": fn.get("name", "unknown"),
                        "input": args,
                    })
                claude_msgs.append({"role": "assistant", "content": blocks})
            else:
                # Flush pending tool results
                if pending_tool_results:
                    claude_msgs.append({
                        "role": "user",
                        "content": pending_tool_results,
                    })
                    pending_tool_results = []
                claude_msgs.append({"role": "assistant", "content": content})

        elif role == "tool":
            # Pop the next tool_use ID from the queue
            if pending_tool_ids:
                tool_use_id = pending_tool_ids.pop(0)
            else:
                tool_use_id = f"toolu_{tool_id_counter:06d}"
                tool_id_counter += 1
            pending_tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content[:100000],  # Claude has a limit
            })

        elif role == "user":
            # Flush pending tool results
            if pending_tool_results:
                claude_msgs.append({
                    "role": "user",
                    "content": pending_tool_results,
                })
                pending_tool_results = []

            # Handle images for vision
            images = m.get("images", [])
            if images:
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content})
                for img_b64 in images:
                    blocks.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": img_b64,
                        },
                    })
                claude_msgs.append({"role": "user", "content": blocks})
            else:
                claude_msgs.append({"role": "user", "content": content})

    # Flush any remaining tool results
    if pending_tool_results:
        claude_msgs.append({
            "role": "user",
            "content": pending_tool_results,
        })

    # Claude requires alternating user/assistant — merge consecutive same-role
    claude_msgs = _fix_alternation(claude_msgs)

    return system, claude_msgs



def _fix_alternation(msgs: list[dict]) -> list[dict]:
    """Ensure strict user/assistant alternation for Claude API."""
    if not msgs:
        return msgs

    fixed = [msgs[0]]
    for msg in msgs[1:]:
        if msg["role"] == fixed[-1]["role"]:
            # Merge into previous — convert both to block format if needed
            prev_content = fixed[-1]["content"]
            new_content = msg["content"]

            if isinstance(prev_content, str):
                prev_content = [{"type": "text", "text": prev_content}] if prev_content else []
            if isinstance(new_content, str):
                new_content = [{"type": "text", "text": new_content}] if new_content else []

            fixed[-1]["content"] = prev_content + new_content
        else:
            fixed.append(msg)

    # Claude requires first message to be user
    if fixed and fixed[0]["role"] != "user":
        fixed.insert(0, {"role": "user", "content": "Begin."})

    return fixed


# ── Response conversion ─────────────────────────────────────────────────────
# Claude response tool_use blocks → Ollama-format tool_calls

def _convert_response_to_ollama(content_blocks: list[dict]) -> tuple[str, list[dict]]:
    """Convert Claude response content blocks to (text, ollama_tool_calls)."""
    text_parts = []
    tool_calls = []

    for block in content_blocks:
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            # Convert to Ollama format
            tool_calls.append({
                "function": {
                    "name": block.get("name", ""),
                    "arguments": block.get("input", {}),
                },
            })

    return "\n".join(text_parts), tool_calls


# ── Main chat functions ─────────────────────────────────────────────────────

def stream_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
    on_token: Callable = None,
) -> tuple[str, list[dict]]:
    """
    Non-streaming Claude chat. Returns (content, tool_calls) in Ollama format.
    """
    api_key = _get_api_key()
    system_prompt, claude_msgs = _convert_messages_to_claude(messages)
    claude_tools = _convert_tools_to_claude(tools)

    # Use the model name directly (e.g., "claude-sonnet-4-20250514")
    api_model = model if model else DEFAULT_CLAUDE_MODEL

    payload = json.dumps({
        "model": api_model,
        "max_tokens": MAX_TOKENS,
        "system": system_prompt,
        "messages": claude_msgs,
        "tools": claude_tools,
        "temperature": 0.3,
    }).encode()

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())

            # Check for errors
            if data.get("type") == "error":
                error_msg = data.get("error", {}).get("message", "Unknown error")
                if "context" in error_msg.lower() or "too long" in error_msg.lower():
                    raise ContextOverflowError(error_msg)
                raise ConnectionError(f"Claude API error: {error_msg}")

            content_blocks = data.get("content", [])
            return _convert_response_to_ollama(content_blocks)

    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass

        if e.code == 400 and "context" in body.lower():
            raise ContextOverflowError(f"Claude context overflow: {body[:300]}")
        if e.code == 401:
            raise ConnectionError("Invalid ANTHROPIC_API_KEY. Check your key.")
        if e.code == 429:
            raise ConnectionError(f"Claude rate limited. {body[:200]}")
        if e.code == 529 or e.code == 503:
            raise ConnectionError(f"Claude API overloaded. Retry shortly. {body[:200]}")
        raise ConnectionError(f"Claude HTTP {e.code}: {body[:300]}")

    except urllib.error.URLError as e:
        raise ConnectionError(f"Cannot reach Claude API: {e}")


def simple_chat(
    model: str,
    messages: list[dict],
    tools: list[dict],
) -> tuple[str, list[dict]]:
    """
    Simple chat for compaction/summary calls. Same as stream_chat for Claude
    since we use the non-streaming API.
    """
    return stream_chat(model, messages, tools)
