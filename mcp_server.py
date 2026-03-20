#!/usr/bin/env python3
"""
TheRobin MCP Server — exposes pentest tools to Claude Code / OpenCode.

Uses the official MCP Python SDK for proper protocol handling.
Tools are lazy-loaded on first call to avoid blocking startup.
"""

import json
import sys
import os

# Ensure TheRobin's root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("robin-tools")

# Lazy-loaded reference to agent.tools
_tools_module = None


def _get_tools():
    global _tools_module
    if _tools_module is None:
        from agent import tools as _t
        _tools_module = _t
    return _tools_module


# ── Tool Definitions ─────────────────────────────────────────────────────────

@mcp.tool()
def run_python(code: str) -> str:
    """Execute Python code in a PERSISTENT session REPL — like a Jupyter notebook.
    Variables, objects, and imports from PREVIOUS calls are still in scope.
    Already available: requests, BeautifulSoup, re, json, base64, hashlib,
    socket, ssl, time, urljoin, urlparse, urlencode, quote, unquote, parse_qs.
    Print findings with [CRITICAL]/[HIGH]/[MEDIUM]/[LOW]/[INFO] labels."""
    tools = _get_tools()
    return tools.execute_tool("run_python", {"code": code})


@mcp.tool()
def bash(command: str) -> str:
    """Execute a shell command. Use for nmap, curl, dig, whois, or other CLI tools.
    Prefer run_python for HTTP testing."""
    tools = _get_tools()
    return tools.execute_tool("bash", {"command": command})


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Save content to a file in the workspace directory."""
    tools = _get_tools()
    return tools.execute_tool("write_file", {"path": path, "content": content})


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace directory.
    Use to analyze HTML pages, cookies, or data saved by browser_action."""
    tools = _get_tools()
    return tools.execute_tool("read_file", {"path": path})


@mcp.tool()
def web_request(
    url: str,
    method: str = "GET",
    headers: str = "{}",
    data: str = "{}",
    json_data: str = "{}",
    cookies: str = "{}",
    verify_ssl: bool = True,
    allow_redirects: bool = True,
    timeout: int = 30,
) -> str:
    """Quick HTTP request — returns status_code, headers, cookies, body (max 8KB),
    final url, and redirect_history. For multi-step flows use run_python instead.
    Pass headers/data/json_data/cookies as JSON strings."""
    tools = _get_tools()
    args = {"url": url, "method": method, "verify_ssl": verify_ssl,
            "allow_redirects": allow_redirects, "timeout": timeout}
    # Parse JSON string args back to dicts
    for key, val in [("headers", headers), ("data", data),
                     ("json_data", json_data), ("cookies", cookies)]:
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if parsed and parsed != {}:
                args[key] = parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return tools.execute_tool("web_request", args)


@mcp.tool()
def browser_action(
    action: str,
    url: str = "",
    selector: str = "",
    by: str = "css",
    value: str = "",
    script: str = "",
    filename: str = "",
    seconds: float = 0,
    timeout: int = 10,
) -> str:
    """Control a persistent headless Chromium browser with VISION support.
    Use for JS-heavy sites, SPA login forms, React/Angular/Vue apps.
    Actions: navigate, source, find_elements, fill, click, submit,
    wait_for, execute_js, cookies, screenshot, wait, close.
    navigate/click/submit/screenshot return a screenshot you can SEE."""
    tools = _get_tools()
    args = {"action": action}
    if url: args["url"] = url
    if selector: args["selector"] = selector
    if by != "css": args["by"] = by
    if value: args["value"] = value
    if script: args["script"] = script
    if filename: args["filename"] = filename
    if seconds: args["seconds"] = seconds
    if timeout != 10: args["timeout"] = timeout
    return tools.execute_tool("browser_action", args)


@mcp.tool()
def osint_recon(
    action: str,
    target: str = "",
    query: str = "",
    max_results: int = 15,
) -> str:
    """Passive OSINT reconnaissance — no active scanning, all passive sources.
    Actions: dork (DuckDuckGo), subdomains (crt.sh + DNS brute),
    crtsh, dns, whois, wayback, harvester."""
    tools = _get_tools()
    args = {"action": action}
    if target: args["target"] = target
    if query: args["query"] = query
    if max_results != 15: args["max_results"] = max_results
    return tools.execute_tool("osint_recon", args)


@mcp.tool()
def compact_state(summary: str) -> str:
    """CALL THIS EVERY 3-4 PHASES to save your progress. This is your memory.
    Write a structured summary of everything done so far. Include:
    - Target URL and credentials used
    - Phases completed (by number)
    - ALL confirmed findings (severity, title, URL, proof)
    - ALL tested endpoints and what was tested on each
    - Current session state (authenticated? cookies? JS-heavy?)
    - What phase to continue with next

    If context gets too large and the user starts a new session,
    they can say 'continue pentest' and you read this file to recover.

    This is NOT optional — call it after every 3-4 phases to checkpoint."""
    import datetime
    tools = _get_tools()
    workspace = tools.WORKSPACE_DIR

    # Find the active session directory
    session_dir = workspace
    try:
        sessions = sorted(workspace.iterdir())
        for d in reversed(sessions):
            if d.is_dir() and "session" in d.name:
                session_dir = d
                break
    except Exception:
        pass

    # Write the summary
    memory_path = session_dir / "pentest_memory.md"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f"# Pentest Memory — Auto-Compacted\n"
    content += f"Updated: {timestamp}\n\n"
    content += summary

    memory_path.parent.mkdir(parents=True, exist_ok=True)
    memory_path.write_text(content)

    # Also save _G state via the REPL
    tools.execute_tool("run_python", {"code": "_save_state()"})

    return json.dumps({
        "status": "saved",
        "file": str(memory_path),
        "message": (
            f"State saved to {memory_path}. "
            "If context gets too large, user can start a new session and say "
            "'continue pentest' — you will read this file to recover all state."
        ),
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
