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
import re as _re
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
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
_CLEAN_ENV = {**os.environ, "PYTHONWARNINGS": "ignore", "PENTEST_PROJECT_ROOT": _PROJECT_ROOT}

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
_re = re  # alias for LLM convenience
from urllib.parse import urljoin, urlparse, urlencode, quote, unquote, parse_qs

# Add project root to path so agent modules are importable (e.g. report_gen)
_proj_root = os.environ.get('PENTEST_PROJECT_ROOT', '')
if _proj_root and _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

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
_G["_G"] = _G  # so exec'd code can reference the persistent namespace

# Helper so LLM can call write_file()/read_file() inside run_python code
def _repl_write_file(fname, content):
    p = Path(fname)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    print(f"[OK] Saved: {fname} ({len(content)} bytes)")

def _repl_read_file(fname):
    return Path(fname).read_text()

_G["write_file"] = _repl_write_file
_G["read_file"] = _repl_read_file

# POC screenshot helper — take a named screenshot of a URL for finding evidence
def _poc_screenshot(url, name="poc"):
    """Navigate browser to URL and save a named POC screenshot.
    Returns the screenshot filename (saved in workspace).
    Usage: fname = poc_screenshot("http://target/search?q=<script>alert(1)</script>", "xss_search_q")
    """
    import subprocess as _sp, json as _j
    # Call browser_action via the parent process's tool
    # Since we're in the REPL, we use a simpler approach: save a marker file
    # that the parent process reads to trigger browser_action
    _marker = os.path.join(os.getcwd(), '.poc_screenshot_request.json')
    _j_data = _j.dumps({"url": url, "name": name})
    with open(_marker, 'w') as _f:
        _f.write(_j_data)
    print(f"[POC] Screenshot requested: {name} -> {url[:100]}")
    print(f"[POC] Use browser_action to capture: browser_action(action='navigate', url='{url[:100]}')")
    print(f"[POC] Then: browser_action(action='screenshot', filename='{name}.png')")
    return f"screenshot_{name}.png"

_G["poc_screenshot"] = _poc_screenshot

# ── State persistence: auto-save/restore critical _G keys across REPL restarts ──
_STATE_FILE = os.path.join(os.getcwd(), '.pentest_state.json')

# Keys to SKIP — these are builtins, modules, functions, or internal REPL plumbing
_STATE_SKIP = frozenset({
    '__builtins__', '__name__', '__doc__', '__package__', '__loader__',
    '__spec__', '__file__', '_G', 'json', 'sys', 'io', 'traceback', 'os',
    'warnings', 're', 'base64', 'hashlib', 'socket', 'ssl', 'time',
    'urljoin', 'urlparse', 'urlencode', 'quote', 'unquote', 'parse_qs',
    'requests', 'BeautifulSoup', 'Path',
    'write_file', 'read_file', '_repl_write_file', '_repl_read_file',
    'poc_screenshot', '_poc_screenshot',
    '_save_state', '_restore_state', '_STATE_FILE', '_STATE_SKIP',
    '_SENTINEL', '_orig_request', '_proxied_request', '_tor_proxy',
})

def _save_state():
    """Persist ALL serializable _G keys to disk so REPL restart recovers them."""
    try:
        state = {}
        for k, v in _G.items():
            if k.startswith('_') and k not in (
                '_G',  # skip internal
            ):
                # Save underscore keys only if they look like test data
                # (e.g. _cookie_xss_found), skip internal plumbing
                if k.startswith('__') or callable(v):
                    continue
            if k in _STATE_SKIP or callable(v):
                continue
            # Skip module / class / function objects
            if hasattr(v, '__module__') and not isinstance(v, (dict, list, tuple, str, int, float, bool, type(None))):
                continue
            try:
                # Convert sets to lists for JSON serialization
                if isinstance(v, set):
                    v = list(v)
                json.dumps(v)  # test serialization
                state[k] = v
            except (TypeError, ValueError, OverflowError):
                # Not serializable (sessions, sockets, compiled regex, etc.) — skip
                continue
        if state:
            with open(_STATE_FILE, 'w') as f:
                json.dump(state, f)
    except Exception:
        pass

def _restore_state():
    """Load saved state into _G on REPL restart. Also recreates requests.Session."""
    try:
        if os.path.exists(_STATE_FILE):
            with open(_STATE_FILE) as f:
                state = json.load(f)
            restored = []
            for k, v in state.items():
                if k not in _G:  # don't overwrite if already set
                    # Convert lists back to sets for known set-typed keys
                    if k in ('ALL_LINKS', 'API_ENDPOINTS') and isinstance(v, list):
                        _G[k] = set(v)
                    else:
                        _G[k] = v
                    restored.append(k)
            # Recreate a basic requests.Session if BASE is restored
            if 'BASE' in state and 'session' not in _G:
                _s = requests.Session()
                _s.verify = False
                _s.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0'
                _G['session'] = _s
                _G['session_a'] = _s
            if restored:
                print(f'[REPL] State restored ({len(restored)} keys): {", ".join(sorted(restored)[:15])}')
                if 'BASE' in state:
                    print(f'[REPL] BASE={state["BASE"]}')
                if 'session' not in state:
                    print(f'[REPL] WARNING: session cookies/auth lost — re-login may be needed')
    except Exception:
        pass

_restore_state()

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

        # ── Auto-capture findings from stdout ───────────────────────
        # LLMs often print [CRITICAL]/[HIGH]/etc but forget to store
        # in _G['FINDINGS']. Parse stdout and auto-add missing ones.
        _stdout_text = _out.getvalue()
        _findings = _G.setdefault('FINDINGS', [])
        _existing_titles = {f.get('title','') for f in _findings}
        import re as _re

        # Patterns that look like findings but are actually noise/summaries
        _JUNK_PATTERNS = [
            r'findings?\s*:\s*\d+',     # "findings : 4", "finding(s): 0"
            r'\d+\s*finding',           # "76 finding(s)", "2 finding(s)"
            r'found on \d+ \w+',        # "SSTI found on 4 parameter(s)!"
            r'\d+ potential\b',         # "81 potential DOM XSS..."
            r'chains? found',           # "81 ... chains found"
            r'summary',                  # summary lines
            r'^\s*#',                    # markdown headings
            r'tested\b.*\bsecret',       # "tested 30 secrets"
            r'^\s*\d+\s*(tested|checks|tests|endpoints|urls|cookies)',
            r'(good|ok|pass|safe|rejected|not\s+vulnerable)',  # negative results
            r'^\s*Done\b',              # "Done" status lines
            r'^\s*Phase\s+\d+',         # phase markers
            r'^\s*Testing\b',           # "Testing XSS..." status lines
            r'^\s*Checking\b',          # "Checking endpoint..." status
            r'stored\s+\d+',            # "Stored 5 JWTs in _G"
            r'skipping',                # "skipping deep JWT testing"
            r'investigate manually',    # not confirmed findings
        ]

        _stdout_lines = _stdout_text.split('\n')
        for _li, _line in enumerate(_stdout_lines):
            _m = _re.match(
                r'\s*\[?(CRITICAL|HIGH|MEDIUM|LOW)\]?\s*[—\-:\s]+(.+)',
                _line.strip()
            )
            if not _m:
                continue
            _sev = _m.group(1).upper()
            _rest = _m.group(2).strip()

            # Skip junk / summary / status lines
            _is_junk = False
            for _jp in _JUNK_PATTERNS:
                if _re.search(_jp, _rest, _re.IGNORECASE):
                    _is_junk = True
                    break
            if _is_junk:
                continue

            # Extract URL if present (http://... at end or after " — ")
            _url = ''
            _um = _re.search(r'(https?://\S+)', _rest)
            if _um:
                _url = _um.group(1).rstrip(')')
            # Clean title: remove URL part and trailing separators
            _title = _re.sub(r'\s*[—\-]+\s*https?://\S+', '', _rest).strip().rstrip(' —-:')
            if not _title or len(_title) < 5:
                continue
            # Skip if already stored (fuzzy: check if title is substring or vice versa)
            _dominated = False
            for _et in _existing_titles:
                if _title.lower() in _et.lower() or _et.lower() in _title.lower():
                    _dominated = True
                    break
            if _dominated:
                continue

            # ── Scan surrounding lines for labelled POC fields ──────────────
            # Look up to 30 lines after the severity line for structured output
            _poc_fields = {
                'url': _url, 'method': '', 'payload': '',
                'evidence': '', 'poc': '', 'request': '',
                'response': '', 'impact': '', 'remediation': '',
                'status_code': '', 'response_headers': '', 'cookie': '',
                'headers': '', 'test_code': '',
            }
            _scan_end = min(_li + 31, len(_stdout_lines))
            _evidence_buf = []
            _poc_buf = []
            _response_buf = []
            _in_evidence = False
            _in_poc = False
            _in_response = False
            for _sl in _stdout_lines[_li + 1:_scan_end]:
                _sl_strip = _sl.strip()
                # Stop at next severity line or empty-line after block ends
                if _re.match(r'\s*\[?(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]', _sl):
                    break
                # Multi-line block labels
                if _re.match(r'Evidence\s*:', _sl_strip, _re.IGNORECASE):
                    _in_evidence, _in_poc, _in_response = True, False, False
                    _val = _re.sub(r'^Evidence\s*:\s*', '', _sl_strip, flags=_re.IGNORECASE)
                    if _val:
                        _evidence_buf.append(_val)
                    continue
                if _re.match(r'curl\s+POC\s*:|POC\s*:', _sl_strip, _re.IGNORECASE):
                    _in_evidence, _in_poc, _in_response = False, True, False
                    _val = _re.sub(r'^(?:curl\s+)?POC\s*:\s*', '', _sl_strip, flags=_re.IGNORECASE)
                    if _val:
                        _poc_buf.append(_val)
                    continue
                if _re.match(r'(?:Full\s+)?Response\s*(?:\s*Headers)?\s*:|Server\s+Response\s*:', _sl_strip, _re.IGNORECASE):
                    _in_evidence, _in_poc, _in_response = False, False, True
                    _val = _re.sub(r'^(?:Full\s+)?(?:Server\s+)?Response\s*(?:\s*Headers)?\s*:\s*', '', _sl_strip, flags=_re.IGNORECASE)
                    if _val:
                        _response_buf.append(_val)
                    continue
                # Capture "Response Headers:" as a multi-line block for response_headers field
                if _re.match(r'Response[_ ]?Headers\s*:', _sl_strip, _re.IGNORECASE):
                    _in_evidence, _in_poc, _in_response = False, False, True
                    _val = _re.sub(r'^Response[_ ]?Headers\s*:\s*', '', _sl_strip, flags=_re.IGNORECASE)
                    if _val:
                        _response_buf.append(_val)
                    continue
                # Single-line labels (end multi-line blocks)
                _kv = _re.match(r'(URL|Method|Payload|Parameter|Impact|Remediation|Status[_ ]?Code|Status|Cookie|Headers|Request|Test[_ ]?Code)\s*:\s*(.+)', _sl_strip, _re.IGNORECASE)
                if _kv:
                    _in_evidence = _in_poc = _in_response = False
                    _k, _v = _kv.group(1).lower().replace(' ', '_').replace('-', '_'), _kv.group(2).strip()
                    if _k == 'url' and not _poc_fields['url']:
                        _poc_fields['url'] = _v
                    elif _k == 'method':
                        _poc_fields['method'] = _v
                    elif _k in ('payload', 'parameter'):
                        _poc_fields['payload'] = _v
                    elif _k == 'impact':
                        _poc_fields['impact'] = _v
                    elif _k == 'remediation':
                        _poc_fields['remediation'] = _v
                    elif _k in ('status_code', 'status'):
                        _poc_fields['status_code'] = _v
                    elif _k == 'cookie':
                        _poc_fields['cookie'] = _v
                    elif _k == 'headers':
                        _poc_fields['headers'] = _v
                    elif _k == 'request':
                        _poc_fields['request'] = _v
                    elif _k == 'test_code':
                        _poc_fields['test_code'] = _v
                    continue
                # Continuation lines for multi-line blocks
                if _in_evidence:
                    _evidence_buf.append(_sl)
                elif _in_poc:
                    _poc_buf.append(_sl)
                elif _in_response:
                    _response_buf.append(_sl)

            if _evidence_buf:
                _poc_fields['evidence'] = '\n'.join(_evidence_buf)
            if _poc_buf:
                _poc_fields['poc'] = '\n'.join(_poc_buf)
            if _response_buf:
                _poc_fields['response'] = '\n'.join(_response_buf)
            # ────────────────────────────────────────────────────────────────

            _findings.append({
                'severity': _sev,
                'title': _title,
                'url': _poc_fields['url'],
                'method': _poc_fields['method'],
                'payload': _poc_fields['payload'],
                'evidence': _poc_fields['evidence'],
                'poc': _poc_fields['poc'],
                'response': _poc_fields['response'],
                'impact': _poc_fields['impact'],
                'remediation': _poc_fields['remediation'],
                'auto_captured': True,
            })
            _existing_titles.add(_title)

        # Auto-save critical state after every execution
        _save_state()

        result = json.dumps({"stdout": _stdout_text, "stderr": _err.getvalue()})
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

    def execute(self, code: str, timeout: int = 300) -> dict:
        with self._lock:
            self._ensure_alive()

            # Pre-execution syntax check — catches errors before running
            try:
                compile(code, "<agent>", "exec")
            except SyntaxError as e:
                # Return short error message (saves tokens vs full traceback)
                error_msg = f"Syntax error line {e.lineno}: {e.msg}"
                if e.text:
                    error_msg += f"\n  {e.text.strip()}"
                return {"stdout": "", "stderr": error_msg, "exit_code": 1}

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
    A persistent headless Chromium browser driven by Selenium.
    One instance per session — state (cookies, login, navigation) persists
    across browser_action calls, just like a real browser tab.

    The 'screenshot' action returns base64 image data + simplified DOM
    so vision-capable models (Kimi K2.5) can see and reason about pages.
    """

    def __init__(self):
        self._driver = None
        self._lock = threading.Lock()

    def _find_chromium(self) -> tuple:
        """Locate Chromium/Chrome binary and chromedriver (Linux + macOS)."""
        import platform
        binary_candidates = [
            # Linux
            "/snap/chromium/current/usr/lib/chromium-browser/chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
        ]
        driver_candidates = [
            "/snap/chromium/current/usr/lib/chromium-browser/chromedriver",
            "/usr/bin/chromedriver",
            "/usr/local/bin/chromedriver",
        ]
        if platform.system() == "Darwin":
            binary_candidates = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/opt/homebrew/bin/chromium",
                "/usr/local/bin/chromium",
            ] + binary_candidates
            driver_candidates = [
                "/opt/homebrew/bin/chromedriver",
                "/usr/local/bin/chromedriver",
            ] + driver_candidates
        binary = next(
            (c for c in binary_candidates if os.path.isfile(c) and os.access(c, os.X_OK)),
            None,
        )
        driver = next(
            (c for c in driver_candidates if os.path.isfile(c) and os.access(c, os.X_OK)),
            None,
        )
        return binary, driver

    def _start(self):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service

        binary, chromedriver = self._find_chromium()
        if not binary:
            import platform
            if platform.system() == "Darwin":
                hint = "Install: brew install --cask chromium  (or use Google Chrome)"
            else:
                hint = "Install: sudo snap install chromium"
            raise RuntimeError(f"Chromium/Chrome not found. {hint}")

        tmp_dir = tempfile.mkdtemp(prefix="sel_")
        opts = Options()
        opts.binary_location = binary
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1280,900")
        opts.add_argument(f"--user-data-dir={tmp_dir}")
        opts.add_argument("--ignore-certificate-errors")
        opts.accept_insecure_certs = True

        svc_kwargs = {"log_output": subprocess.DEVNULL}
        if chromedriver:
            svc_kwargs["executable_path"] = chromedriver
        service = Service(**svc_kwargs)
        self._driver = webdriver.Chrome(options=opts, service=service)
        self._driver.set_page_load_timeout(30)
        self._driver.implicitly_wait(5)
        # Create live viewer HTML in workspace
        self._create_viewer()

    def _create_viewer(self):
        """Create an auto-refreshing HTML page to view browser screenshots live."""
        viewer = WORKSPACE_DIR / "browser_viewer.html"
        viewer.write_text("""<!DOCTYPE html>
<html><head><title>TheRobin — Live Browser View</title>
<style>
body{background:#1a1a2e;color:#e0e0e0;font-family:monospace;text-align:center;margin:0;padding:20px}
h1{color:#0ff;font-size:1.5em}
img{max-width:100%;border:2px solid #0ff;margin-top:10px}
#status{color:#888;font-size:0.9em;margin-top:5px}
</style>
<script>
let ts=0;
function refresh(){
  const img=document.getElementById('shot');
  img.src='latest_screenshot.png?t='+Date.now();
  document.getElementById('status').textContent='Last refresh: '+new Date().toLocaleTimeString();
}
setInterval(refresh,2000);
window.onload=refresh;
</script>
</head><body>
<h1>TheRobin — Live Browser View</h1>
<p id="status">Waiting for screenshots...</p>
<img id="shot" alt="Latest screenshot" onerror="this.style.display='none'" onload="this.style.display='block'">
</body></html>""", encoding="utf-8")

    def _ensure(self):
        if self._driver is None:
            self._start()

    def action(self, action: str, **kwargs) -> dict:
        with self._lock:
            try:
                self._ensure()
            except Exception as e:
                return {"error": f"Browser failed to start: {e}. Is chromium installed?"}
            try:
                return self._dispatch(action, **kwargs)
            except Exception as e:
                return {"error": str(e)}

    @staticmethod
    def _strip_dom(html: str, max_len: int = 3000) -> str:
        """Strip JS/CSS/attributes from HTML, keep structure + text + forms."""
        try:
            from bs4 import BeautifulSoup, Comment
            soup = BeautifulSoup(html, "html.parser")
            # Remove script, style, svg, noscript
            for tag in soup.find_all(["script", "style", "svg", "noscript", "link", "meta"]):
                tag.decompose()
            # Remove comments
            for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                c.extract()
            # Strip most attributes, keep only useful ones
            keep_attrs = {"href", "src", "action", "method", "name", "id",
                          "type", "value", "placeholder", "for", "role"}
            for tag in soup.find_all(True):
                attrs = dict(tag.attrs)
                for attr in attrs:
                    if attr not in keep_attrs:
                        del tag.attrs[attr]
            text = soup.prettify()
            if len(text) > max_len:
                text = text[:max_len] + "\n... (truncated)"
            return text
        except Exception:
            # Fallback: just truncate raw HTML
            return html[:max_len]

    def _by(self, by_str: str):
        from selenium.webdriver.common.by import By
        return {
            "css": By.CSS_SELECTOR, "xpath": By.XPATH,
            "id": By.ID, "name": By.NAME, "tag": By.TAG_NAME,
        }.get(by_str.lower(), By.CSS_SELECTOR)

    def _save_screenshot(self, b64: str, label: str = "auto") -> str:
        """Save a base64 screenshot to disk and update the live viewer."""
        import base64, time
        ts = int(time.time())
        fname = f"screenshot_{label}_{ts}.png"
        path = WORKSPACE_DIR / fname
        path.write_bytes(base64.b64decode(b64))
        # Update latest symlink / file for live viewer
        latest = WORKSPACE_DIR / "latest_screenshot.png"
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(path.name)
        except Exception:
            pass
        return fname

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
            b64 = d.get_screenshot_as_base64()
            shot_file = self._save_screenshot(b64, "navigate")
            return {
                "title": d.title,
                "url": d.current_url,
                "source_file": fname,
                "bytes": len(src),
                "screenshot_base64": b64,
                "screenshot_file": shot_file,
                "simplified_dom": self._strip_dom(src),
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
            b64 = d.get_screenshot_as_base64()
            shot_file = self._save_screenshot(b64, "click")
            return {
                "url": d.current_url,
                "title": d.title,
                "screenshot_base64": b64,
                "screenshot_file": shot_file,
                "simplified_dom": self._strip_dom(d.page_source),
            }

        elif action == "submit":
            el = d.find_element(self._by(kwargs.get("by", "css")), kwargs["selector"])
            el.submit()
            time.sleep(2)
            b64 = d.get_screenshot_as_base64()
            shot_file = self._save_screenshot(b64, "submit")
            return {
                "url": d.current_url,
                "title": d.title,
                "screenshot_base64": b64,
                "screenshot_file": shot_file,
                "simplified_dom": self._strip_dom(d.page_source),
            }

        elif action == "execute_js":
            result = d.execute_script(kwargs["script"])
            result_str = str(result)
            if len(result_str) > 3000:
                # Save full result to file, return truncated preview
                fname = f"js_result_{ts}.txt"
                path = WORKSPACE_DIR / fname
                path.write_text(result_str, encoding="utf-8")
                return {
                    "result": result_str[:2000] + "...(truncated)",
                    "full_result_file": fname,
                    "total_length": len(result_str),
                }
            return {"result": result_str}

        elif action == "cookies":
            cookies = d.get_cookies()
            fname = f"cookies_{ts}.json"
            path = WORKSPACE_DIR / fname
            path.write_text(json.dumps(cookies, ensure_ascii=False), encoding="utf-8")
            return {"cookies": cookies[:10], "file": fname, "total_count": len(cookies)}

        elif action == "screenshot":
            b64 = d.get_screenshot_as_base64()
            label = kwargs.get("filename", f"screenshot_{ts}.png").replace(".png", "")
            shot_file = self._save_screenshot(b64, label)
            dom = self._strip_dom(d.page_source)
            return {
                "saved": str(WORKSPACE_DIR / shot_file),
                "screenshot_base64": b64,
                "screenshot_file": shot_file,
                "url": d.current_url,
                "title": d.title,
                "simplified_dom": dom,
            }

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
    """Drive a persistent headless Chromium browser with vision support."""
    return _browser.action(action, **kwargs)


def reset_browser():
    """Close the browser. Called on /clear."""
    _browser.reset()


# ─── Tool Implementations ─────────────────────────────────────────────────────

# ─── Auto-Tracker ────────────────────────────────────────────────────────────
# Parses run_python output for [CRITICAL]/[HIGH]/[MEDIUM]/[LOW] findings
# and phase completions, then auto-updates plan.md and findings.log.

_FINDING_RE = _re.compile(
    r'\[(?P<sev>CRITICAL|HIGH|MEDIUM|LOW)\]\s*(?P<desc>.+)',
    _re.IGNORECASE,
)

# Match phase references in output — various formats the LLM uses:
#   "PHASE 2 — SECURITY HEADERS"        (start)
#   "Phase 3 COMPLETE"                   (end)
#   "PHASE 2-4: Security Headers..."     (range)
#   "PHASE 5-6: XSS and SQL Injection"  (range)
#   "[OK] Phase 1 initial recon complete"
_PHASE_RE = _re.compile(
    r'PHASE\s+(\d+)(?:\s*[-–]\s*(\d+))?',
    _re.IGNORECASE,
)
_PHASE_COMPLETE_RE = _re.compile(
    r'Phase\s+(\d+)\b.*(?:complete|done|finished)',
    _re.IGNORECASE,
)


def _auto_track(output: str):
    """Parse tool output and auto-update plan.md + findings.log."""
    if not output:
        return
    plan_path = WORKSPACE_DIR / "plan.md"
    log_path = WORKSPACE_DIR / "findings.log"

    # ── Extract findings ──────────────────────────────────────────────────
    # Patterns that are status/summary lines, NOT real findings
    _TRACK_JUNK = _re.compile(
        r'(\d+\s*finding|\bsummary\b|\btested\b|\bskipping\b|\bdone\b'
        r'|\bgood\b|\brejected\b|\bnot vulnerable\b|\bchecked\b|\bstored\s+\d+'
        r'|\bphase\s+\d+\b|\btesting\b|\binfo\b.*\bno\s)',
        _re.IGNORECASE,
    )
    new_findings = []
    seen = set()
    for line in output.splitlines():
        m = _FINDING_RE.search(line)
        if m:
            sev = m.group("sev").upper()
            desc = m.group("desc").strip()[:200]
            # Skip junk lines
            if _TRACK_JUNK.search(desc):
                continue
            key = f"{sev}:{desc[:60]}"
            if key not in seen:
                seen.add(key)
                new_findings.append(f"[{sev}] {desc}")

    # Append new findings to findings.log
    if new_findings:
        try:
            existing = log_path.read_text() if log_path.exists() else ""
            existing_lines = set(existing.splitlines())
            truly_new = [f for f in new_findings if f not in existing_lines]
            if truly_new:
                with open(log_path, "a") as fh:
                    for f in truly_new:
                        fh.write(f + "\n")
        except Exception:
            pass

    # ── Detect which phases this output covers ────────────────────────────
    # Collect ALL phase numbers mentioned (start headers, complete markers, ranges)
    touched_phases = set()

    for m in _PHASE_RE.finditer(output):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        for p in range(start, end + 1):
            touched_phases.add(p)

    for m in _PHASE_COMPLETE_RE.finditer(output):
        touched_phases.add(int(m.group(1)))

    if not touched_phases or not plan_path.exists():
        return

    # ── Update plan.md ────────────────────────────────────────────────────
    try:
        plan = plan_path.read_text()
        changed = False

        # Collect HIGH+ findings for annotation
        high_findings = [
            (f.split("] ", 1)[1][:40] if "] " in f else f[:40])
            for f in new_findings
            if any(s in f for s in ["CRITICAL", "HIGH"])
        ]

        for phase_num in sorted(touched_phases):
            old_pattern = f"- [ ] Phase {phase_num} "
            if old_pattern not in plan:
                continue  # already ticked or doesn't exist

            if high_findings:
                short = ", ".join(high_findings[:3])
                plan_lines = plan.split("\n")
                for i, ln in enumerate(plan_lines):
                    if old_pattern in ln:
                        base = ln.replace("- [ ]", "- [!]")
                        plan_lines[i] = f"{base}  (found: {short})"
                        changed = True
                        break
                plan = "\n".join(plan_lines)
            else:
                plan = plan.replace(old_pattern, f"- [x] Phase {phase_num} ", 1)
                changed = True

        # Append HIGH+ findings to ## Findings section
        if new_findings and "## Findings" in plan:
            high_entries = [f for f in new_findings if any(
                s in f for s in ["[CRITICAL]", "[HIGH]"]
            )]
            if high_entries:
                rest = plan[plan.index("## Findings"):]
                for f in high_entries:
                    if f not in rest:
                        plan = plan.rstrip() + f"\n- {f}\n"
                        changed = True

        if changed:
            plan_path.write_text(plan)
    except Exception:
        pass


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
    result = _repl.execute(code)
    # Auto-track findings and phase completions
    _auto_track(result.get("stdout", ""))
    return result


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
        # Fall back to project-root-relative path (for agent/phases/*.md etc.)
        if not target.exists():
            alt = Path(path)
            if alt.exists():
                target = alt
            else:
                proj_root = Path(__file__).resolve().parent.parent
                for prefix in ("", "agent/"):
                    alt2 = proj_root / (prefix + path)
                    if alt2.exists():
                        target = alt2
                        break
        content = target.read_text(encoding="utf-8")
        # Truncate large files to prevent context overflow
        max_return_size = 50000  # 50KB max in conversation
        truncated = len(content) > max_return_size
        return {"success": True, "path": path, "content": content[:max_return_size], "bytes": len(content), "truncated": truncated}
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
                "Control a persistent headless Chromium browser (Selenium) with VISION support. "
                "Use this for JavaScript-heavy sites, SPA login forms, React/Angular/Vue apps, "
                "or any page where the HTML is rendered by JS and not visible in raw HTTP responses. "
                "VISION: navigate/click/submit/screenshot actions return a screenshot image that "
                "you can SEE — use this to understand page layout, find buttons, and reason about "
                "what to click next. Combined with simplified_dom for precise selectors. "
                "The browser keeps state (cookies, session, current page) between calls — "
                "navigate once, then fill/click without re-navigating. "
                "Actions: "
                "navigate(url) — go to URL, returns screenshot + simplified DOM; "
                "source() — save current page HTML to file, returns preview; "
                "find_elements(selector, by) — find elements (by: css/xpath/id/name); "
                "fill(selector, value, by) — type into an input field; "
                "click(selector, by) — click button/link, returns screenshot + DOM; "
                "submit(selector, by) — submit a form, returns screenshot + DOM; "
                "wait_for(selector, by, timeout) — wait until element appears; "
                "execute_js(script) — run JavaScript, returns result; "
                "cookies() — get all cookies; "
                "screenshot(filename) — take screenshot, returns image; "
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
