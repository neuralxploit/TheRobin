"""
Tool implementations and JSON schemas for the pentest agent.
These are the agent's "hands" — analogous to Claude Code's bash/file tools.

Key design: run_python uses a PERSISTENT REPL subprocess.
Variables defined in one call survive to the next — exactly like a notebook.
This means BASE, session, soup, links, etc. are all shared across calls.
"""

import subprocess
import tempfile
import threading
import os
import json
import sys
import time
import requests as _requests
from pathlib import Path
from . import osint as _osint

# Suppress urllib3 InsecureRequestWarning globally — verify=False is intentional
# in pentesting (targets often have self-signed or expired certs).
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

WORKSPACE_DIR = Path("workspace")

TOR_PROXY   = "socks5h://127.0.0.1:9050"
TOR_ENABLED = False


def _find_python() -> str:
    project_root = Path(__file__).parent.parent
    venv_python = project_root / "venv" / "bin" / "python3"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable

_PYTHON = _find_python()
_CLEAN_ENV = {**os.environ, "PYTHONWARNINGS": "ignore"}

# ─── Persistent REPL ──────────────────────────────────────────────────────────

# This code runs inside the persistent child process.
# It loops forever: read code → exec in shared globals → send back output.
# All variables in _G (globals dict) persist between iterations.
_REPL_BOOTSTRAP = r'''
import sys, io, traceback, json, os, warnings

os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")

# Pre-load everything the agent commonly uses.
# These are in globals so agent code can use them without importing.
import re, base64, hashlib, socket, ssl, time
from urllib.parse import urljoin, urlparse, urlencode, quote, unquote, parse_qs
import requests

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

try:
    from bs4 import BeautifulSoup
except ImportError:
    pass

# Tor proxy — patch requests.Session when PENTEST_TOR_PROXY env var is set
_tor_proxy = os.environ.get('PENTEST_TOR_PROXY', '')
if _tor_proxy:
    _orig_request = requests.Session.request
    def _proxied_request(self, *args, **kwargs):
        kwargs.setdefault('proxies', {'http': _tor_proxy, 'https': _tor_proxy})
        return _orig_request(self, *args, **kwargs)
    requests.Session.request = _proxied_request
    print(f'[Tor] requests proxied via {_tor_proxy}')

_SENTINEL = "<<<PENTEST_REPL_DONE_9F2A>>>"

# Shared namespace — everything lives here across all exec() calls
_G = {k: v for k, v in globals().items()}
_G["json"] = json
_G["__builtins__"] = __builtins__

while True:
    try:
        header = sys.stdin.readline()
        if not header:
            break
        n = int(header.strip())
        code = sys.stdin.read(n)

        _out = io.StringIO()
        _err = io.StringIO()
        _saved_out, _saved_err = sys.stdout, sys.stderr
        sys.stdout = _out
        sys.stderr = _err

        try:
            exec(compile(code, "<agent>", "exec"), _G)
        except SystemExit:
            pass
        except BaseException:
            sys.stderr = _err
            traceback.print_exc()
        finally:
            sys.stdout = _saved_out
            sys.stderr = _saved_err

        result = json.dumps({"stdout": _out.getvalue(), "stderr": _err.getvalue()})
        sys.stdout.write(result + "\n")
        sys.stdout.write(_SENTINEL + "\n")
        sys.stdout.flush()

    except Exception as e:
        sys.stdout = sys.__stdout__
        result = json.dumps({"stdout": "", "stderr": f"REPL loop error: {e}"})
        sys.stdout.write(result + "\n")
        sys.stdout.write("<<<PENTEST_REPL_DONE_9F2A>>>" + "\n")
        sys.stdout.flush()
'''

_SENTINEL = "<<<PENTEST_REPL_DONE_9F2A>>>"


class _PersistentREPL:
    """
    A long-running Python process that persists state across run_python calls.
    Protocol: send "{len}\n{code}" → read lines until sentinel → parse JSON result.
    """

    def __init__(self, python_path: str):
        self._python = python_path
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._bootstrap_path: str | None = None

    def _write_bootstrap(self):
        if self._bootstrap_path and Path(self._bootstrap_path).exists():
            return
        fd, path = tempfile.mkstemp(suffix=".py", prefix="pentest_repl_")
        with os.fdopen(fd, "w") as f:
            f.write(_REPL_BOOTSTRAP)
        self._bootstrap_path = path

    def _start(self):
        self._write_bootstrap()
        self._proc = subprocess.Popen(
            [self._python, "-W", "ignore", self._bootstrap_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=_CLEAN_ENV,
            cwd=str(WORKSPACE_DIR),
        )

    def _ensure_alive(self):
        if self._proc is None or self._proc.poll() is not None:
            self._start()

    def execute(self, code: str, timeout: int = 120) -> dict:
        with self._lock:
            self._ensure_alive()

            # Send: "{length}\n{code}"
            try:
                self._proc.stdin.write(f"{len(code)}\n")
                self._proc.stdin.write(code)
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                # REPL died — restart and retry once
                self._proc = None
                self._start()
                try:
                    self._proc.stdin.write(f"{len(code)}\n")
                    self._proc.stdin.write(code)
                    self._proc.stdin.flush()
                except Exception as e:
                    return {"stdout": "", "stderr": f"REPL failed to restart: {e}", "exit_code": -1}

            # Read output lines until sentinel (with timeout via thread)
            lines: list[str] = []
            timed_out = threading.Event()

            def _reader():
                try:
                    while True:
                        line = self._proc.stdout.readline()
                        if not line:
                            break
                        lines.append(line)
                        if line.rstrip("\n") == _SENTINEL:
                            break
                except Exception:
                    pass

            t = threading.Thread(target=_reader, daemon=True)
            t.start()
            t.join(timeout)

            if t.is_alive():
                # Timeout — kill the REPL so next call starts fresh
                try:
                    self._proc.kill()
                except Exception:
                    pass
                self._proc = None
                return {"stdout": "".join(lines), "stderr": f"Timeout after {timeout}s", "exit_code": -1}

            # The last meaningful line before the sentinel is the JSON result
            json_line = None
            for line in reversed(lines):
                stripped = line.rstrip("\n")
                if stripped and stripped != _SENTINEL:
                    json_line = stripped
                    break

            if json_line:
                try:
                    result = json.loads(json_line)
                    stdout = result.get("stdout", "")
                    stderr = result.get("stderr", "").strip()
                    return {
                        "stdout": stdout[-8000:] if stdout else "",
                        "stderr": stderr[-3000:] if stderr else "",
                        "exit_code": 1 if stderr else 0,
                    }
                except json.JSONDecodeError:
                    pass

            # Fallback — return raw output
            raw = "".join(l for l in lines if l.rstrip("\n") != _SENTINEL)
            return {"stdout": raw[-8000:], "stderr": "", "exit_code": 0}

    def reset(self):
        """Kill the REPL and clear all variables. Called on /clear."""
        with self._lock:
            if self._proc:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=2)
                except Exception:
                    pass
                self._proc = None

    def __del__(self):
        try:
            self.reset()
        except Exception:
            pass


# Module-level REPL instance — one per session, shared by all run_python calls
_repl = _PersistentREPL(_PYTHON)


# ─── Persistent Browser Session (Selenium + Firefox headless) ─────────────────

class _BrowserSession:
    """
    A persistent headless Firefox browser driven by Selenium.
    One instance per session — state (cookies, login, navigation) persists
    across browser_action calls, just like a real browser tab.
    """

    def __init__(self):
        self._driver = None
        self._lock = threading.Lock()

    def _find_firefox_binary(self) -> str:
        """Locate the real Firefox binary (handles snap wrapper)."""
        candidates = [
            "/snap/firefox/current/usr/lib/firefox/firefox",  # snap real binary
            "/usr/lib/firefox/firefox",
            "/usr/bin/firefox-esr",
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return "firefox"  # fallback — let Selenium find it

    def _start(self):
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service

        opts = Options()
        opts.binary_location = self._find_firefox_binary()
        opts.add_argument("--headless")
        opts.add_argument("--width=1920")
        opts.add_argument("--height=1080")
        opts.set_preference("security.tls.version.min", 1)
        opts.set_preference("accept_untrusted_certs", True)

        service = Service(log_output=subprocess.DEVNULL)
        self._driver = webdriver.Firefox(options=opts, service=service)
        self._driver.set_page_load_timeout(30)
        self._driver.implicitly_wait(5)

    def _ensure(self):
        if self._driver is None:
            self._start()

    def action(self, action: str, **kwargs) -> dict:
        with self._lock:
            try:
                self._ensure()
            except Exception as e:
                return {"error": f"Browser failed to start: {e}. Is geckodriver installed?"}
            try:
                return self._dispatch(action, **kwargs)
            except Exception as e:
                return {"error": str(e)}

    def _by(self, by_str: str):
        from selenium.webdriver.common.by import By
        return {
            "css": By.CSS_SELECTOR, "xpath": By.XPATH,
            "id": By.ID, "name": By.NAME, "tag": By.TAG_NAME,
        }.get(by_str.lower(), By.CSS_SELECTOR)

    def _dispatch(self, action: str, **kwargs) -> dict:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        import time

        d = self._driver
        ts = int(time.time())

        if action == "navigate":
            d.get(kwargs["url"])
            WebDriverWait(d, 15).until(
                lambda drv: drv.execute_script("return document.readyState") == "complete"
            )
            src = d.page_source
            fname = f"page_{ts}.html"
            path = WORKSPACE_DIR / fname
            path.write_text(src, encoding="utf-8")
            return {
                "title": d.title,
                "url": d.current_url,
                "source_file": fname,
                "bytes": len(src),
                "preview": src[:1000],
            }

        elif action == "source":
            src = d.page_source
            fname = f"page_{ts}.html"
            path = WORKSPACE_DIR / fname
            path.write_text(src, encoding="utf-8")
            return {
                "source_file": fname,
                "bytes": len(src),
                "preview": src[:1000],
                "url": d.current_url,
                "title": d.title,
            }

        elif action == "find_elements":
            els = d.find_elements(self._by(kwargs.get("by", "css")), kwargs["selector"])
            result = []
            for el in els[:20]:
                result.append({
                    "tag":         el.tag_name,
                    "text":        (el.text or "")[:80],
                    "type":        (el.get_attribute("type") or "")[:30],
                    "name":        (el.get_attribute("name") or "")[:30],
                    "id":          (el.get_attribute("id") or "")[:30],
                    "placeholder": (el.get_attribute("placeholder") or "")[:30],
                    "value":       (el.get_attribute("value") or "")[:30],
                    "href":        (el.get_attribute("href") or "")[:50],
                    "class":       (el.get_attribute("class") or "")[:30],
                    "displayed":   el.is_displayed(),
                })
            fname = f"elements_{ts}_{hash(kwargs['selector']) % 1000}.json"
            path = WORKSPACE_DIR / fname
            path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            return {"elements": result, "count": len(els), "file": fname}

        elif action == "fill":
            el = d.find_element(self._by(kwargs.get("by", "css")), kwargs["selector"])
            el.clear()
            el.send_keys(kwargs["value"])
            return {"success": True}

        elif action == "click":
            el = d.find_element(self._by(kwargs.get("by", "css")), kwargs["selector"])
            el.click()
            time.sleep(1.5)   # let JS/redirect settle
            return {"url": d.current_url, "title": d.title}

        elif action == "submit":
            el = d.find_element(self._by(kwargs.get("by", "css")), kwargs["selector"])
            el.submit()
            time.sleep(2)
            return {"url": d.current_url, "title": d.title}

        elif action == "execute_js":
            result = d.execute_script(kwargs["script"])
            return {"result": str(result)[:500]}

        elif action == "cookies":
            cookies = d.get_cookies()
            fname = f"cookies_{ts}.json"
            path = WORKSPACE_DIR / fname
            path.write_text(json.dumps(cookies, ensure_ascii=False), encoding="utf-8")
            return {"cookies": cookies[:10], "file": fname, "total_count": len(cookies)}

        elif action == "screenshot":
            fname = kwargs.get("filename", "screenshot.png")
            path = WORKSPACE_DIR / fname
            d.save_screenshot(str(path))
            return {"saved": str(path)}

        elif action == "wait":
            secs = float(kwargs.get("seconds", 2))
            time.sleep(secs)
            return {"url": d.current_url}

        elif action == "wait_for":
            # Wait for an element to appear (useful after JS login)
            sel = kwargs["selector"]
            by  = self._by(kwargs.get("by", "css"))
            timeout = int(kwargs.get("timeout", 10))
            try:
                WebDriverWait(d, timeout).until(EC.presence_of_element_located((by, sel)))
                return {"found": True, "url": d.current_url}
            except Exception:
                return {"found": False, "url": d.current_url}

        elif action == "close":
            d.quit()
            self._driver = None
            return {"closed": True}

        else:
            return {"error": f"Unknown action: {action}. Valid: navigate, source, find_elements, fill, click, submit, execute_js, cookies, screenshot, wait, wait_for, close"}

    def reset(self):
        with self._lock:
            if self._driver:
                try:
                    self._driver.quit()
                except Exception:
                    pass
                self._driver = None

    def __del__(self):
        try:
            self.reset()
        except Exception:
            pass


_browser = _BrowserSession()


def browser_action(action: str, **kwargs) -> dict:
    """Drive a persistent headless Firefox browser."""
    return _browser.action(action, **kwargs)


def reset_browser():
    """Close the browser. Called on /clear."""
    _browser.reset()


# ─── Tool Implementations ─────────────────────────────────────────────────────

def run_python(code: str) -> dict:
    """
    Execute Python code in the persistent session REPL.
    Variables, imports, and objects from previous calls are still available.
    """
    # Pre-validate syntax before sending to the REPL subprocess.
    # This gives the model a clean, actionable error without touching REPL state.
    try:
        compile(code, "<agent>", "exec")
    except SyntaxError as e:
        line_text = (e.text or "").rstrip()
        pointer = " " * ((e.offset or 1) - 1) + "^"
        msg = (
            f"SYNTAX ERROR — code was NOT executed. Fix it and call run_python again.\n"
            f"  Line {e.lineno}: {line_text}\n"
            f"           {pointer}\n"
            f"  Error: {e.msg}"
        )
        return {"stdout": "", "stderr": msg, "exit_code": 1}
    return _repl.execute(code)


def reset_repl():
    """Reset the REPL (clear all variables). Called on /clear."""
    _repl.reset()


def bash(command: str) -> dict:
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=60, cwd=str(WORKSPACE_DIR),
        )
        # Include workspace path in output so agent knows where files are
        return {
            "stdout": result.stdout[-6000:] if result.stdout else "",
            "stderr": result.stderr[-2000:] if result.stderr else "",
            "exit_code": result.returncode,
            "cwd": str(WORKSPACE_DIR),
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout after 60 seconds", "exit_code": -1, "cwd": str(WORKSPACE_DIR)}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": -1, "cwd": str(WORKSPACE_DIR)}


def write_file(path: str, content: str) -> dict:
    try:
        target = WORKSPACE_DIR / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(target), "bytes": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def read_file(path: str) -> dict:
    try:
        target = WORKSPACE_DIR / path
        content = target.read_text(encoding="utf-8")
        # Truncate large files to prevent context overflow
        max_return_size = 50000  # 50KB max in conversation
        truncated = len(content) > max_return_size
        return {"success": True, "content": content[:max_return_size], "bytes": len(content), "truncated": truncated}
    except FileNotFoundError:
        return {"success": False, "error": f"File not found: {path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def web_request(
    url: str,
    method: str = "GET",
    headers: dict = None,
    data: dict = None,
    json_data: dict = None,
    cookies: dict = None,
    verify_ssl: bool = False,
    allow_redirects: bool = True,
    timeout: int = 10,
) -> dict:
    try:
        default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        }
        if headers:
            default_headers.update(headers)

        proxies = {"http": TOR_PROXY, "https": TOR_PROXY} if TOR_ENABLED else None
        resp = _requests.request(
            method=method.upper(), url=url, headers=default_headers,
            data=data, json=json_data, cookies=cookies or {},
            verify=verify_ssl, allow_redirects=allow_redirects, timeout=timeout,
            proxies=proxies,
        )

        body = resp.text
        truncated = len(body) > 8192
        if truncated:
            body = body[:8192]

        return {
            "status_code": resp.status_code,
            "url": str(resp.url),
            "headers": dict(resp.headers),
            "cookies": dict(resp.cookies),
            "body": body,
            "body_truncated": truncated,
            "redirect_history": [str(r.url) for r in resp.history],
        }
    except _requests.exceptions.SSLError:
        return {"error": "SSL error — try verify_ssl: false"}
    except _requests.exceptions.ConnectionError as e:
        return {"error": f"Connection error: {e}"}
    except _requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except Exception as e:
        return {"error": str(e)}


# ─── OSINT Tool ───────────────────────────────────────────────────────────────

def osint_recon(action: str, target: str = "", query: str = "", max_results: int = 15) -> dict:
    """
    Passive OSINT reconnaissance. No active scanning — all passive sources.

    Actions:
      dork          — DuckDuckGo search with operator support (site:, inurl:, filetype:, intitle:)
      subdomains    — crt.sh certificate transparency + DNS brute force combined
      crtsh         — crt.sh certificate transparency logs only
      dns           — DNS record enumeration (A, AAAA, MX, TXT, NS, SOA)
      whois         — WHOIS registrar / ownership info
      wayback       — Wayback Machine historical URLs (forgotten endpoints)
      harvester     — theHarvester multi-source (emails, subdomains, IPs)
    """
    a = action.lower()

    if a == "dork":
        if not query:
            return {"error": "query is required for dork action. Example: site:target.com filetype:pdf"}
        return _osint.duckduckgo_dork(query, max_results=max_results)

    elif a == "subdomains":
        if not target:
            return {"error": "target domain required. Example: target='example.com'"}
        crt    = _osint.crtsh_subdomains(target)
        brute  = _osint.subdomain_bruteforce(target)
        all_subs = set(crt.get("subdomains", []))
        for host in brute.get("found", {}):
            all_subs.add(host)
        return {
            "domain":          target,
            "subdomains":      sorted(all_subs),
            "count":           len(all_subs),
            "from_crtsh":      len(crt.get("subdomains", [])),
            "from_bruteforce": len(brute.get("found", {})),
            "bruteforce_ips":  brute.get("found", {}),
        }

    elif a == "crtsh":
        if not target:
            return {"error": "target domain required"}
        return _osint.crtsh_subdomains(target)

    elif a == "dns":
        if not target:
            return {"error": "target domain required"}
        return _osint.dns_records(target)

    elif a == "whois":
        if not target:
            return {"error": "target domain required"}
        return _osint.whois_lookup(target)

    elif a == "wayback":
        if not target:
            return {"error": "target domain required"}
        return _osint.wayback_urls(target, limit=max_results * 5)

    elif a == "harvester":
        if not target:
            return {"error": "target domain required"}
        return _osint.theharvester(target)

    else:
        return {
            "error": f"Unknown action: {action}",
            "valid_actions": ["dork", "subdomains", "crtsh", "dns", "whois", "wayback", "harvester"],
        }


# ─── Tool Dispatch ────────────────────────────────────────────────────────────

TOOL_HANDLERS = {
    "run_python": run_python,
    "bash": bash,
    "write_file": write_file,
    "read_file": read_file,
    "web_request": web_request,
    "browser_action": browser_action,
    "osint_recon": osint_recon,
}


def execute_tool(name: str, args: dict) -> str:
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = handler(**args)
        return json.dumps(result, indent=2, default=str)
    except TypeError as e:
        return json.dumps({"error": f"Bad arguments: {e}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ─── Tool JSON Schemas ────────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "run_python",
            "description": (
                "Execute Python code in a PERSISTENT session REPL — exactly like a Jupyter notebook. "
                "Variables, objects, and imports from PREVIOUS calls are still in scope. "
                "If you set BASE='http://target.com' and session=requests.Session() in one call, "
                "they are available in the next call without re-defining them. "
                "Already available without importing: requests, BeautifulSoup, re, json, base64, "
                "hashlib, socket, ssl, time, urljoin, urlparse, urlencode, quote, unquote, parse_qs. "
                "Print all findings to stdout. Use [CRITICAL]/[HIGH]/[MEDIUM]/[LOW]/[INFO] labels."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": (
                            "Python code to execute. Variables from previous calls are available. "
                            "Keep each call focused on one test phase. "
                            "DO NOT re-fetch pages or re-define session if already done — reuse them."
                        ),
                    }
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": (
                "Execute a shell command. Use for nmap, curl, dig, whois, or other CLI tools. "
                "Prefer run_python for HTTP testing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute."}
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Save content to a file in the workspace. Use 'report.md' for the final report.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path inside workspace."},
                    "content": {"type": "string", "description": "File content to write."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a file from the workspace directory. "
                "Use this to analyze full HTML pages, cookies, or element data saved by browser_action. "
                "browser_action saves pages as 'page_<timestamp>.html' and other data similarly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path inside workspace."}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_request",
            "description": (
                "Quick HTTP request — returns status_code, headers, cookies, body (max 8KB), "
                "final url (after redirects), and redirect_history (list of URLs in the chain). "
                "allow_redirects=true by default — set to false to capture raw 3xx responses. "
                "For multi-step flows with persistent sessions, use run_python instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    },
                    "headers": {"type": "object"},
                    "data": {"type": "object"},
                    "json_data": {"type": "object"},
                    "cookies": {"type": "object"},
                    "verify_ssl": {"type": "boolean"},
                    "allow_redirects": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_action",
            "description": (
                "Control a persistent headless Firefox browser (Selenium). "
                "Use this for JavaScript-heavy sites, SPA login forms, React/Angular/Vue apps, "
                "or any page where the HTML is rendered by JS and not visible in raw HTTP responses. "
                "The browser keeps state (cookies, session, current page) between calls — "
                "navigate once, then fill/click without re-navigating. "
                "IMPORTANT: All page sources, elements, and cookies are saved to workspace files "
                "(page_<timestamp>.html, elements_<hash>.json, cookies_<timestamp>.json). "
                "Use read_file() to access full data when needed. "
                "Actions: "
                "navigate(url) — go to URL, wait for JS, saves page to file, returns title+preview; "
                "source() — save current page to file, returns preview; "
                "find_elements(selector, by) — find elements, saves to file (by: css/xpath/id/name); "
                "fill(selector, value, by) — type into an input field; "
                "click(selector, by) — click button/link, waits for navigation; "
                "submit(selector, by) — submit a form; "
                "wait_for(selector, by, timeout) — wait until element appears; "
                "execute_js(script) — run JavaScript, returns result; "
                "cookies() — save all cookies to file, returns preview; "
                "screenshot(filename) — save PNG to workspace; "
                "wait(seconds) — pause; "
                "close() — quit browser."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "source", "find_elements", "fill", "click",
                                 "submit", "wait_for", "execute_js", "cookies",
                                 "screenshot", "wait", "close"],
                        "description": "The browser action to perform.",
                    },
                    "url":      {"type": "string",  "description": "URL for navigate action."},
                    "selector": {"type": "string",  "description": "CSS selector, XPath, id, or name."},
                    "by":       {"type": "string",  "enum": ["css", "xpath", "id", "name", "tag"],
                                 "description": "How to locate element. Default: css."},
                    "value":    {"type": "string",  "description": "Text to type into input (fill action)."},
                    "script":   {"type": "string",  "description": "JavaScript to execute."},
                    "filename": {"type": "string",  "description": "Screenshot filename (e.g. login.png)."},
                    "seconds":  {"type": "number",  "description": "Seconds to wait."},
                    "timeout":  {"type": "integer", "description": "Timeout in seconds for wait_for."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "osint_recon",
            "description": (
                "Passive OSINT reconnaissance — no active scanning, all passive sources. "
                "Use this at the START of every engagement for information gathering. "
                "Actions: "
                "dork(query) — DuckDuckGo search with full operator support: "
                "  site:target.com  inurl:admin  intitle:login  filetype:pdf  \"exact phrase\" "
                "  Example queries: 'site:target.com filetype:pdf', "
                "  'site:github.com \"target.com\" api_key OR secret', "
                "  'site:target.com inurl:admin OR inurl:dashboard', "
                "  '\"target.com\" password filetype:txt site:pastebin.com'; "
                "subdomains(target) — combined crt.sh + DNS brute force subdomain enumeration; "
                "crtsh(target) — certificate transparency logs for subdomains; "
                "dns(target) — enumerate A/AAAA/MX/TXT/NS/SOA/CNAME records; "
                "whois(target) — registrar, creation date, name servers, registrant info; "
                "wayback(target) — Wayback Machine historical URLs (finds forgotten endpoints); "
                "harvester(target) — theHarvester multi-source (emails, IPs, subdomains). "
                "Use DuckDuckGo dorks instead of Google — same operators, no blocking."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["dork", "subdomains", "crtsh", "dns", "whois", "wayback", "harvester"],
                        "description": "OSINT action to perform.",
                    },
                    "target": {
                        "type": "string",
                        "description": "Domain or hostname (e.g. 'example.com'). Used by all actions except dork.",
                    },
                    "query": {
                        "type": "string",
                        "description": (
                            "Search query for dork action. Supports operators: "
                            "site: inurl: intitle: filetype: \"exact\" -exclude. "
                            "Example: 'site:example.com inurl:admin'"
                        ),
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Max results to return (default 15). For wayback, actual limit is 5x this.",
                    },
                },
                "required": ["action"],
            },
        },
    },
]
