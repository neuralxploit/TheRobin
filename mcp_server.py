#!/usr/bin/env python3
"""
TheRobin MCP Server — exposes pentest tools to Claude Code / OpenCode.

Uses the official MCP Python SDK for proper protocol handling.
Tools are lazy-loaded on first call to avoid blocking startup.
"""

import json
import sys
import os
import threading

# Ensure TheRobin's root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("robin-tools")

# Lazy-loaded reference to agent.tools
_tools_module = None
_session_dir = None
_session_lock = threading.Lock()

# ── Input validation constants ────────────────────────────────────────────────
_MAX_CODE_SIZE = 100_000       # 100KB max for run_python code
_MAX_COMMAND_SIZE = 10_000     # 10KB max for bash commands
_MAX_URL_SIZE = 4_096          # 4KB max for URLs


def _get_tools():
    global _tools_module
    if _tools_module is None:
        from agent import tools as _t
        _tools_module = _t
    return _tools_module


def _get_workspace_root():
    """Walk up from tools.WORKSPACE_DIR to find the real workspace/ root,
    in case WORKSPACE_DIR already points inside a session folder."""
    tools = _get_tools()
    base = tools.WORKSPACE_DIR
    # Walk up while we're inside a session_* directory
    while base.name.startswith("session_") and base.parent.name != base.name:
        base = base.parent
    return base


def _get_or_create_session_dir():
    """Get or create the current session directory (workspace/session_YYYYMMDD_HHMMSS/)."""
    global _session_dir
    with _session_lock:
        if _session_dir is None:
            import datetime
            tools = _get_tools()
            base_workspace = _get_workspace_root()
            # Create a timestamped session folder
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            _session_dir = base_workspace / f"session_{ts}"
            _session_dir.mkdir(parents=True, exist_ok=True)
            # Update the tools module's WORKSPACE_DIR to point to this session
            tools.WORKSPACE_DIR = _session_dir
            print(f"[MCP] Session created: {_session_dir}", file=sys.stderr)
        return _session_dir


# ── Tool Definitions ─────────────────────────────────────────────────────────

@mcp.tool()
def run_python(code: str) -> str:
    """Execute Python code in a PERSISTENT session REPL — like a Jupyter notebook.
    Variables, objects, and imports from PREVIOUS calls are still in scope.
    Already available: requests, BeautifulSoup, re, json, base64, hashlib,
    socket, ssl, time, urljoin, urlparse, urlencode, quote, unquote, parse_qs.
    Print findings with [CRITICAL]/[HIGH]/[MEDIUM]/[LOW]/[INFO] labels."""
    if not isinstance(code, str) or len(code) > _MAX_CODE_SIZE:
        return json.dumps({"error": f"Code must be a string under {_MAX_CODE_SIZE // 1000}KB"})
    _get_or_create_session_dir()  # Ensure session folder exists
    tools = _get_tools()
    return tools.execute_tool("run_python", {"code": code})


@mcp.tool()
def bash(command: str) -> str:
    """Execute a shell command. Use for nmap, curl, dig, whois, or other CLI tools.
    Prefer run_python for HTTP testing."""
    if not isinstance(command, str) or len(command) > _MAX_COMMAND_SIZE:
        return json.dumps({"error": f"Command must be a string under {_MAX_COMMAND_SIZE // 1000}KB"})
    _get_or_create_session_dir()
    tools = _get_tools()
    return tools.execute_tool("bash", {"command": command})


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Save content to a file in the workspace directory."""
    _get_or_create_session_dir()
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
    verify_ssl: bool = False,
    allow_redirects: bool = True,
    timeout: int = 30,
) -> str:
    """Quick HTTP request — returns status_code, headers, cookies, body (max 8KB),
    final url, and redirect_history. For multi-step flows use run_python instead.
    Pass headers/data/json_data/cookies as JSON strings."""
    if not isinstance(url, str) or len(url) > _MAX_URL_SIZE:
        return json.dumps({"error": f"URL must be a string under {_MAX_URL_SIZE} bytes"})
    if not url.startswith(("http://", "https://")):
        return json.dumps({"error": "URL must start with http:// or https://"})
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
    """Control a persistent headless Chromium browser.
    Use for JS-heavy sites, SPA login forms, React/Angular/Vue apps.
    Actions: navigate, source, find_elements, fill, click, submit,
    wait_for, execute_js, cookies, screenshot, wait, close.
    Screenshots are saved to disk — use screenshot_file path to reference them."""
    _get_or_create_session_dir()
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
    _get_or_create_session_dir()
    tools = _get_tools()
    args = {"action": action}
    if target: args["target"] = target
    if query: args["query"] = query
    if max_results != 15: args["max_results"] = max_results
    return tools.execute_tool("osint_recon", args)


@mcp.tool()
def get_session_info() -> str:
    """Get current session information: directory, target URL, created time.
    Useful to know where screenshots and reports are being saved."""
    global _session_dir
    try:
        import json, datetime
        session_dir = _get_or_create_session_dir()

        # Try to read session metadata
        metadata_path = session_dir / "session_metadata.json"
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text())
        else:
            metadata = {}

        # Get current findings count from REPL
        tools = _get_tools()
        result = tools.execute_tool("run_python", {"code": """
import json
json.dumps({
    "findings_count": len(_G.get('FINDINGS', [])),
    "base": _G.get('BASE', ''),
    "target": _G.get('TARGET', ''),
    "has_session": 'SESSION_DIR' in _G
})
"""})

        try:
            repl_info = json.loads(result.get("stdout", "{}"))
        except json.JSONDecodeError:
            print(f"[MCP] Warning: Could not parse REPL state: {result.get('stdout', '')[:200]}", file=sys.stderr)
            repl_info = {"findings_count": 0, "base": "", "target": "", "has_session": False, "_parse_error": True}

        return json.dumps({
            "session_dir": str(session_dir),
            "session_name": session_dir.name,
            "target": repl_info.get("target") or metadata.get("target", ""),
            "base_url": repl_info.get("base", ""),
            "findings_count": repl_info.get("findings_count", 0),
            "created": metadata.get("timestamp", "unknown"),
            "has_session": repl_info.get("has_session", False)
        })
    except Exception as e:
        return json.dumps({
            "error": str(e),
            "session_dir": str(_session_dir) if _session_dir else "not_created"
        })


@mcp.tool()
def start_new_session(target_url: str = "", session_name: str = "") -> str:
    """Start a new pentest session with its own isolated workspace folder.
    Call this BEFORE starting a new penetration test to isolate all data.

    Args:
        target_url: Target URL for this pentest (e.g., http://example.com)
        session_name: Optional custom session name (default: auto-generated timestamp)

    Returns:
        Session directory path and initialization status."""
    global _session_dir
    import datetime

    # Validate target URL if provided
    if target_url:
        if not target_url.startswith(("http://", "https://")):
            return json.dumps({"error": "target_url must start with http:// or https://"})

    # Close browser and reset REPL from previous session if exists
    tools = _get_tools()
    try:
        tools.reset_browser()
        tools.reset_repl()
    except Exception as e:
        pass  # Ignore errors if nothing to reset

    # Create new session directory
    if session_name:
        # Sanitize session name (remove spaces, special chars)
        clean_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in session_name)
        session_ts = f"{clean_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    else:
        session_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create session folder under workspace/ root (not inside an existing session)
    base_workspace = _get_workspace_root()

    with _session_lock:
        _session_dir = base_workspace / f"session_{session_ts}"
        _session_dir.mkdir(parents=True, exist_ok=True)

        # Update tools module's WORKSPACE_DIR to point to this session
        tools.WORKSPACE_DIR = _session_dir

    # Initialize session in the REPL _G dict
    init_code = f"""
import json, os
BASE = "{target_url}"
_G['BASE'] = "{target_url}"
_G['SESSION_DIR'] = str(_session_dir)
_G['FINDINGS'] = []
_G['TARGET'] = "{target_url}"
_G['TIMESTAMP'] = "{datetime.datetime.now().isoformat()}"
print(f"[NEW SESSION] Workspace: {{_session_dir}}")
print(f"[NEW SESSION] Target: {target_url}")
"""
    tools.execute_tool("run_python", {"code": init_code})

    # Save session metadata
    metadata = {
        "target": target_url,
        "session_name": session_name or f"session_{session_ts}",
        "timestamp": datetime.datetime.now().isoformat(),
        "session_dir": str(_session_dir)
    }
    (_session_dir / "session_metadata.json").write_text(json.dumps(metadata, indent=2))

    return json.dumps({
        "success": True,
        "session_dir": str(_session_dir),
        "target_url": target_url,
        "session_name": session_name or f"session_{session_ts}",
        "message": f"New session started: {_session_dir.name}"
    })


@mcp.tool()
def generate_report(output_filename: str = "report.pdf") -> str:
    """Generate the final PDF penetration test report from the current session findings.
    All findings with screenshots will pull images from the session folder.
    The report is saved in the current session directory."""
    import sys
    # Ensure session directory exists
    session_dir = _get_or_create_session_dir()
    tools = _get_tools()

    # Import the PDF generator
    try:
        from agent.report_pdf import generate_pdf_report
    except ImportError as e:
        return json.dumps({
            "error": f"Failed to import report generator: {e}",
            "session_dir": str(session_dir)
        })

    # Save the current _G state to a file so the report generator can read it
    tools.execute_tool("run_python", {"code": "_save_state()"})

    # Read the saved _G state
    state_path = tools.WORKSPACE_DIR / ".pentest_state.json"
    if not state_path.exists():
        return json.dumps({
            "error": "No _G state found. Run run_python with analysis code first.",
            "session_dir": str(session_dir)
        })

    import json
    try:
        with open(state_path) as f:
            g_state = json.load(f)
    except Exception as e:
        return json.dumps({
            "error": f"Failed to read _G state: {e}",
            "state_path": str(state_path),
            "session_dir": str(session_dir)
        })

    # Sanitize filename — prevent path traversal
    output_filename = os.path.basename(output_filename)
    if not output_filename or output_filename.startswith('.'):
        output_filename = "report.pdf"

    # Generate the report
    output_path = session_dir / output_filename

    try:
        pdf_path = generate_pdf_report(
            g=g_state,
            output_path=str(output_path),
            session_dir=str(session_dir)
        )
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"Failed to generate report: {e}",
            "traceback": traceback.format_exc(),
            "session_dir": str(session_dir),
            "output_path": str(output_path)
        })

    return json.dumps({
        "success": True,
        "pdf_path": pdf_path,
        "session_dir": str(session_dir),
        "findings_count": len(g_state.get("FINDINGS", [])),
        "message": f"Report generated: {pdf_path}"
    })


@mcp.tool()
def restore_state_from_json() -> str:
    """Restore ALL session state from .pentest_state.json (complete state, not just summary).
    Call this when starting a new session to continue from where you left off.
    This restores ALL findings, tested endpoints, session data, etc."""
    import json
    session_dir = _get_or_create_session_dir()
    tools = _get_tools()

    # Check if state file exists
    state_path = session_dir / ".pentest_state.json"
    if not state_path.exists():
        return json.dumps({
            "error": "No state file found to restore. Was compact_state called?",
            "session_dir": str(session_dir)
        })

    # Try to read and verify state
    try:
        with open(state_path) as f:
            state_data = json.load(f)
    except Exception as e:
        return json.dumps({
            "error": f"Failed to read state file: {e}",
            "session_dir": str(session_dir)
        })

    # Restore the state into the REPL _G
    restore_code = f"""
import json, os

# Load state from file
with open('{state_path}') as f:
    saved_state = json.load(f)

# Restore all keys into _G
restored_count = 0
for key, value in saved_state.items():
    _G[key] = value
    restored_count += 1

print(f"[RESTORE] Restored {{restored_count}} keys from .pentest_state.json")
print(f"[RESTORE] Key items: BASE={_G.get('BASE', '')}, FINDINGS count={{len(_G.get('FINDINGS', []))}}")
print(f"[RESTORE] Tested endpoints: {{len(_G.get('ALL_LINKS', set()))}}")
"""

    result = tools.execute_tool("run_python", {"code": restore_code})

    return json.dumps({
        "success": True,
        "session_dir": str(session_dir),
        "state_file": str(state_path),
        "keys_restored": len(state_data),
        "findings_count": len(state_data.get("FINDINGS", [])),
        "base": state_data.get("BASE", ""),
        "output": result.get("stdout", ""),
        "message": f"Restored {len(state_data)} keys from .pentest_state.json"
    })


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
    session_dir = _get_or_create_session_dir()
    tools = _get_tools()

    # Write the summary
    memory_path = session_dir / "pentest_memory.md"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f"# Pentest Memory — Auto-Compacted\n"
    content += f"Updated: {timestamp}\n\n"
    content += summary

    memory_path.parent.mkdir(parents=True, exist_ok=True)
    memory_path.write_text(content)

    # Also save _G state via the REPL (THIS is the complete state!)
    tools.execute_tool("run_python", {"code": "_save_state()"})

    return json.dumps({
        "status": "saved",
        "file": str(memory_path),
        "message": (
            f"State saved to {memory_path} in session folder: {session_dir.name}. "
            "ALL _G data also saved to .pentest_state.json (complete state). "
            "To continue later, use restore_state_from_json() which loads the complete state, "
            "not just the summary."
        ),
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
