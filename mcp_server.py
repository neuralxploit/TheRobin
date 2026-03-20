#!/usr/bin/env python3
"""
TheRobin MCP Server — exposes pentest tools to Claude Code / OpenCode.

Implements the Model Context Protocol (MCP) over stdio using JSON-RPC 2.0.
No external dependencies — stdlib only, matching TheRobin's approach.

Tools exposed:
  run_python     — persistent Python REPL (variables survive between calls)
  bash           — shell command execution
  write_file     — save files to workspace
  read_file      — read files from workspace
  web_request    — HTTP requests with parsed responses
  browser_action — headless Chromium with screenshots (returned as images)
  osint_recon    — passive OSINT reconnaissance
"""

import json
import sys
import base64
import os

# Ensure TheRobin's root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.tools import TOOL_SCHEMAS, execute_tool


# ── Convert OpenAI-style tool schemas to MCP format ──────────────────────────

def _convert_schemas() -> list[dict]:
    """Convert TheRobin's OpenAI-format TOOL_SCHEMAS to MCP tool definitions."""
    mcp_tools = []
    for schema in TOOL_SCHEMAS:
        func = schema["function"]
        mcp_tools.append({
            "name": func["name"],
            "description": func["description"],
            "inputSchema": {
                "type": "object",
                "properties": func["parameters"].get("properties", {}),
                "required": func["parameters"].get("required", []),
            },
        })
    return mcp_tools


MCP_TOOLS = _convert_schemas()


# ── MCP Protocol Handler ─────────────────────────────────────────────────────

def _read_message() -> dict | None:
    """Read a JSON-RPC message from stdin using Content-Length framing."""
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None  # EOF
        line = line.decode("utf-8").strip()
        if line == "":
            break  # End of headers
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()

    length = int(headers.get("content-length", 0))
    if length == 0:
        return None

    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def _send_message(msg: dict):
    """Send a JSON-RPC message to stdout using Content-Length framing."""
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n"
    sys.stdout.buffer.write(header.encode("utf-8"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _result(id, result: dict):
    """Send a JSON-RPC success response."""
    _send_message({"jsonrpc": "2.0", "id": id, "result": result})


def _error(id, code: int, message: str):
    """Send a JSON-RPC error response."""
    _send_message({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})


def _notification(method: str, params: dict = None):
    """Send a JSON-RPC notification (no id)."""
    msg = {"jsonrpc": "2.0", "method": method}
    if params:
        msg["params"] = params
    _send_message(msg)


# ── Request Handlers ─────────────────────────────────────────────────────────

def handle_initialize(id, params: dict):
    """Handle the initialize handshake."""
    _result(id, {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {"listChanged": False},
        },
        "serverInfo": {
            "name": "robin-tools",
            "version": "1.0.0",
        },
    })


def handle_tools_list(id, params: dict):
    """Return the list of available tools."""
    _result(id, {"tools": MCP_TOOLS})


def handle_tools_call(id, params: dict):
    """Execute a tool and return the result."""
    name = params.get("name", "")
    args = params.get("arguments", {})

    # Execute via TheRobin's existing handler
    raw_result = execute_tool(name, args)

    # Parse the JSON result
    try:
        result_data = json.loads(raw_result)
    except (json.JSONDecodeError, TypeError):
        result_data = {"output": raw_result}

    # Check if this is a browser_action that returned a screenshot
    content = []
    screenshot_b64 = None

    if isinstance(result_data, dict):
        screenshot_b64 = result_data.pop("screenshot_base64", None)

    # Add the text result
    if isinstance(result_data, dict) and result_data.get("error"):
        content.append({
            "type": "text",
            "text": f"Error: {result_data['error']}",
        })
        _result(id, {"content": content, "isError": True})
        return

    content.append({
        "type": "text",
        "text": json.dumps(result_data, indent=2, default=str),
    })

    # Add screenshot as an image if present
    if screenshot_b64:
        content.append({
            "type": "image",
            "data": screenshot_b64,
            "mimeType": "image/png",
        })

    _result(id, {"content": content})


# ── Main Loop ────────────────────────────────────────────────────────────────

HANDLERS = {
    "initialize": handle_initialize,
    "notifications/initialized": lambda id, p: None,  # Client ack, ignore
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "ping": lambda id, p: _result(id, {}),
}


def main():
    """Run the MCP server — reads JSON-RPC messages from stdin, responds on stdout."""
    # Redirect stderr so debug prints don't corrupt the protocol
    log = open(os.path.join(os.path.dirname(__file__), "mcp_server.log"), "a")
    sys.stderr = log

    while True:
        msg = _read_message()
        if msg is None:
            break  # EOF — client disconnected

        method = msg.get("method", "")
        id = msg.get("id")
        params = msg.get("params", {})

        handler = HANDLERS.get(method)
        if handler:
            try:
                handler(id, params)
            except Exception as e:
                if id is not None:
                    _error(id, -32603, str(e))
                print(f"Error handling {method}: {e}", file=log, flush=True)
        elif id is not None:
            # Unknown method with an id — must respond
            _error(id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
