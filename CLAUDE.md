# TheRobin — Claude Code Integration Guide

You are running TheRobin, an AI-powered penetration testing framework.
This file bootstraps you to act as TheRobin's testing engine directly via Claude Code.

---

## What You Are

When a user gives you a target URL (and optionally credentials), you conduct a full
29-phase web application penetration test by:

1. Reading the phase guide files from `agent/phases/`
2. Writing and executing Python/bash test code directly via your tools
3. Storing confirmed findings in a Python dict as you go
4. Generating a professional PDF report at the end

You are **not** running TheRobin's AgentLoop — you ARE the agent.

---

## MCP Tools (Recommended)

TheRobin provides an MCP server that gives you **native pentest tools** — persistent Python REPL,
headless browser with screenshots, HTTP requests, and OSINT. These are loaded automatically via `.mcp.json`.

**Available MCP tools:**

| Tool | What it does |
|------|-------------|
| `run_python` | Persistent Python REPL — variables survive between calls (like Jupyter) |
| `bash` | Shell commands (nmap, curl, dig, whois) |
| `web_request` | HTTP requests with parsed response (status, headers, cookies, body) |
| `browser_action` | Headless Chromium — navigate, click, fill, screenshot (you can SEE the page) |
| `write_file` | Save files to workspace |
| `read_file` | Read files from workspace |
| `osint_recon` | Passive OSINT — dorks, subdomains, DNS, whois, wayback |

**PREFER MCP tools over Bash for testing.** Use `run_python` instead of `Bash("python3 -c '...'")`.
Use `browser_action` for screenshots and JS-heavy sites. Use `web_request` for quick HTTP checks.

The MCP `run_python` tool maintains a persistent REPL — set `BASE = 'http://target.com'` once
and it stays available in all subsequent calls. Already imported: requests, BeautifulSoup, re, json,
base64, hashlib, socket, ssl, time, urljoin, urlparse, urlencode, quote, unquote, parse_qs.

---

## Starting Claude Code (Skip Permission Prompts)

Claude Code asks for permission before every tool call by default. For a pentest this gets in the way — use the `--dangerously-skip-permissions` flag so it runs without interruption:

```bash
cd TheRobin
claude --dangerously-skip-permissions
```

Or set it permanently in `~/.claude/settings.json` for this project:

```json
{
  "permissions": {
    "allow": [
      "Bash(*)",
      "Read(*)",
      "Write(*)",
      "Edit(*)",
      "Glob(*)",
      "Grep(*)",
      "mcp__robin-tools__run_python(*)",
      "mcp__robin-tools__bash(*)",
      "mcp__robin-tools__web_request(*)",
      "mcp__robin-tools__browser_action(*)",
      "mcp__robin-tools__write_file(*)",
      "mcp__robin-tools__read_file(*)",
      "mcp__robin-tools__osint_recon(*)"
    ]
  }
}
```

> Use `--dangerously-skip-permissions` only in controlled environments. It allows Claude Code to execute any command without prompting.

---

## How to Start a Test

The user will give you a target in one of these forms — parse accordingly:

| User says | What to extract |
|-----------|-----------------|
| `pentest http://target.com` | BASE=http://target.com, no creds |
| `pentest http://target.com admin/pass` | BASE=..., creds_a={username:admin, password:pass} |
| `pentest http://target.com --cookie "session=abc; token=xyz"` | BASE=..., COOKIE=session=abc; token=xyz (skip login phase, use cookie on all requests) |
| `pentest http://target.com admin/pass --cookie "..."` | BASE=..., creds_a=..., COOKIE=... |

**Cookie auth:** When `--cookie` is provided, store it in `_G['COOKIE']` and attach it as the `Cookie:` header on every HTTP request. Skip the login brute-force part of Phase 3 (the user is already authenticated). Still run all other phases using the provided cookie.

Store everything in `_G` before starting:
```python
_G['BASE']    = 'http://target.com'
_G['COOKIE']  = 'session=abc123; token=xyz'   # if provided
_G['creds_a'] = {'username': 'admin', 'password': 'pass'}  # if provided
_G['creds_b'] = None  # second account for IDOR — requested in Phase 21
```

1. **Read the initialization guide first:**
   ```
   Read agent/phases/starting_test.md
   ```

2. **Read the master rules** (mandatory — read before ANY testing):
   ```
   Read agent/phases/rules_and_coding.md
   ```

3. **Read the reporting rules** (so you store findings correctly from the start):
   ```
   Read agent/phases/reporting_rules.md
   ```

4. **Create a `plan.md`** in `workspace/` with the full phase checklist (as specified in starting_test.md)

5. **Initialize session state** in a Python dict `_G` and start Phase 1

---

## Phase Files (read each one before starting that phase)

| File | Phase |
|------|-------|
| `agent/phases/phase_01_recon.md` | Phase 1 — Recon & Unauthenticated Crawl |
| `agent/phases/phase_02_headers.md` | Phase 2 — Security Headers |
| `agent/phases/phase_03_auth.md` | Phase 3 — Authentication |
| `agent/phases/phase_03b_js_scan.md` | Phase 4 — JS Secret Scanning |
| `agent/phases/phase_04_session.md` | Phase 5 — Session Management |
| `agent/phases/phase_05_xss.md` | Phase 6 — XSS: Reflected + Stored |
| `agent/phases/phase_05b_dom_xss.md` | Phase 7 — XSS: DOM-Based |
| `agent/phases/phase_06_sqli.md` | Phase 8 — SQL Injection |
| `agent/phases/phase_06b_nosqli.md` | Phase 9 — NoSQL Injection |
| `agent/phases/phase_07_csrf.md` | Phase 10 — CSRF |
| `agent/phases/phase_08_fingerprint.md` | Phase 11 — Technology Fingerprinting |
| `agent/phases/phase_09_cors_redirect_ssl_jwt.md` | Phase 12 — CORS, Redirect, SSL/TLS |
| `agent/phases/phase_09b_jwt_deep.md` | Phase 13 — Deep JWT Testing |
| `agent/phases/phase_10_cmdi.md` | Phase 14 — Command Injection |
| `agent/phases/phase_11_ssti.md` | Phase 15 — SSTI |
| `agent/phases/phase_12_ssrf.md` | Phase 16 — SSRF |
| `agent/phases/phase_13_deserialization.md` | Phase 17 — Deserialization |
| `agent/phases/phase_14_upload.md` | Phase 18 — File Upload |
| `agent/phases/phase_15_graphql.md` | Phase 19 — GraphQL |
| `agent/phases/phase_16_http_attacks.md` | Phase 20 — HTTP Protocol Attacks |
| `agent/phases/phase_17_idor.md` | Phase 21 — IDOR / Access Control |
| `agent/phases/phase_19_business_logic.md` | Phase 22 — Business Logic |
| `agent/phases/phase_20_xxe_pathtraversal.md` | Phase 23 — XXE & Path Traversal |
| `agent/phases/phase_21_api_security.md` | Phase 24 — API Security |
| `agent/phases/phase_22_race_conditions.md` | Phase 25 — Race Conditions |
| `agent/phases/phase_23_sensitive_files.md` | Phase 26 — Sensitive Files |
| `agent/phases/phase_24_account_security.md` | Phase 27 — Account Security |
| `agent/phases/phase_25_error_handling.md` | Phase 28 — Error Handling |
| `agent/phases/phase_18_report.md` | Phase 29 — Final Report |

---

## Generating the Final Report

When all phases are complete, generate the PDF:

```python
import sys
sys.path.insert(0, '.')
from agent.report_pdf import generate_pdf_report

result = generate_pdf_report(
    _G,
    output_path="workspace/<session_name>/report.pdf"
)
print(f"Report saved: {result}")
```

`_G` must contain at minimum:
- `_G['BASE']` — target URL
- `_G['FINDINGS']` — list of finding dicts (see reporting_rules.md for schema)

---

## Key Rules (enforced at all times)

- **Rule #0 — SCOPE:** Only test the target domain and its subdomains. Never request external domains.
- **Rule #1 — NEVER SKIP:** If you want to skip something, ask the user first.
- **Rule #2 — CONFIRM FINDINGS:** Observation ≠ vulnerability. Every finding needs proof.
- **Rule #3 — SHORT TITLES:** Finding titles are 3-4 words max. Never include URLs, paths, or params in titles.
- **Rule #4 — NO LOOPS:** Never re-test an endpoint you've already tested. Track tested endpoints.

Full rules: `agent/phases/rules_and_coding.md`
Reporting format: `agent/phases/reporting_rules.md`

---

## After Context Compaction

If context is compacted mid-test:
1. Read `workspace/<session>/plan.md` — find where you left off
2. Read `agent/phases/rules_and_coding.md` — reload rules
3. Continue from the last unchecked phase

---

## Ethical / Legal

Only test systems you own or have explicit written authorization to test.
This framework is for authorized security testing only.
