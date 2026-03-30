<div align="center">

```
               · T h e ·
 ██████╗  ██████╗ ██████╗ ██╗███╗   ██╗
 ██╔══██╗██╔═══██╗██╔══██╗██║████╗  ██║
 ██████╔╝██║   ██║██████╔╝██║██╔██╗ ██║
 ██╔══██╗██║   ██║██╔══██╗██║██║╚██╗██║
 ██║  ██║╚██████╔╝██████╔╝██║██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
```

### AI Offensive Security & OSINT Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-orange.svg)](https://ollama.com)
[![LM Studio](https://img.shields.io/badge/LLM-LM%20Studio-purple.svg)](https://lmstudio.ai)
[![Claude](https://img.shields.io/badge/LLM-Claude%20API-blueviolet.svg)](https://console.anthropic.com)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

**Autonomous AI-driven penetration testing framework powered by LLMs.**
<br>
TheRobin executes a full 33-phase web application security assessment with mandatory exploitation escalation —
<br>
from reconnaissance to full exploitation to report generation — using an AI agent that writes, executes, and iterates on its own attack code.

[Getting Started](#installation) · [Usage](#usage) · [Test Lab](#-vulnerable-test-app) · [Tor Mode](#-tor--anonymity-support) · [Architecture](#architecture)

</div>

---

## Overview

TheRobin is an offensive security tool that uses Large Language Models via [Ollama](https://ollama.com), [LM Studio](https://lmstudio.ai), or the [Anthropic API](https://console.anthropic.com) to conduct autonomous penetration tests against web applications. Unlike traditional scanners that rely on signature matching, TheRobin's AI agent **reasons about responses**, **adapts its attack strategy**, **exploits confirmed vulnerabilities to maximum depth**, and **chains findings** before reporting them.

The agent operates through a persistent Python REPL — writing and executing code in real-time, chaining system tools (nmap, sqlmap, gobuster), and maintaining full session state across hundreds of interactions. It follows a structured 33-phase methodology with mandatory exploitation escalation — when a vulnerability is found, the agent doesn't just log it, it proves maximum impact through data extraction, privilege escalation, and attack chaining.

### Key Capabilities

| | Capability | Details |
|---|---|---|
| 🤖 | **Autonomous Agent** | AI writes & executes attack code in a persistent REPL — no manual scripting needed |
| 💥 | **Exploitation Escalation** | Mandatory deep exploitation — SQLi leads to data dumps, CMDi to system enum, SSRF to cloud credential theft |
| 🔗 | **Vulnerability Chaining** | Auto-detects and chains findings (SQLi+write=RCE, SSRF+metadata=takeover, XSS+no-HttpOnly=hijack) |
| 👁️ | **Browser Vision** | Headless Chromium with screenshot analysis — the AI *sees* pages, confirms findings visually, handles JS-heavy apps |
| 🔍 | **OSINT Recon** | Subdomain enumeration (crt.sh), DNS, WHOIS, Wayback Machine, DuckDuckGo dorking |
| 🌐 | **Full Web Testing** | SQLi, XSS, CSRF, IDOR, SSRF, SSTI, CMDi, WebSocket, OAuth/SSO, cache poisoning, mass assignment, and more |
| 🔐 | **2FA / Cookie Auth** | Paste a session cookie for targets with complex authentication |
| 🧅 | **Tor Routing** | Route all agent traffic through Tor with one flag |
| 📊 | **Professional Reports** | PDF, HTML, JSON, and XML reports with CVSS v3.1, ZDL risk matrix, OWASP classification, reproducible curl PoCs, and remediation |
| ✅ | **Zero False Positives** | Strict confirmation logic — every finding is screenshot-verified and confirmed, not just observed |
| 🖥️ | **Rich TUI** | Color-coded terminal interface with real-time tool output and phase tracking |

### Privacy Notice

TheRobin works with **local models** via Ollama or LM Studio (data never leaves your machine), **cloud-proxied models** via Ollama (`:cloud` suffix), or **Claude API** (data sent to Anthropic). Choose based on your operational security requirements.

---

## Testing Methodology

TheRobin follows a structured 33-phase approach with mandatory exploitation escalation — each vulnerability type gets its own dedicated phase, and every confirmed finding is exploited to maximum depth:

```
 Phase  1 │ Recon & Crawl          → Unauthenticated spider, tech stack, directory bruteforce
 Phase  2 │ Security Headers       → Missing headers, server disclosure
 Phase  3 │ Authentication         → Default creds, brute-force, login bypass, authenticated crawl
 Phase  4 │ JS Secret Scanning     → API keys, tokens, hardcoded credentials in JavaScript
 Phase  5 │ Session Management     → Cookie flags, session fixation, JWT analysis
 Phase  6 │ XSS: Reflected+Stored  → ALL forms, ALL params — reflected + stored
 Phase  7 │ XSS: DOM-Based         → DOM sinks/sources, template injection in client-side
 Phase  8 │ SQL Injection          → Error/blind/auth bypass — ALL forms, ALL params
 Phase  9 │ NoSQL Injection        → MongoDB/operator injection on all parameters
 Phase 10 │ CSRF                   → ALL state-changing POST forms
 Phase 11 │ Tech Fingerprinting    → Version detection, CVE lookup, JS analysis
 Phase 12 │ CORS / Redirect / SSL  → CORS misconfig, open redirect, SSL/TLS
 Phase 13 │ Deep JWT Testing       → Algorithm confusion, key brute-force, claim tampering
 Phase 14 │ Command Injection      → ALL forms — shell injection in every text input
 Phase 15 │ SSTI                   → Template injection — ALL text inputs
 Phase 16 │ SSRF                   → ALL URL-accepting params — internal/metadata/file
 Phase 17 │ Deserialization        → Pickle/YAML RCE on discovered endpoints
 Phase 18 │ File Upload            → Webshell, extension bypass, SVG/HTML XSS
 Phase 19 │ GraphQL                → Introspection, injection, auth bypass
 Phase 20 │ Protocol Attacks       → Host header injection, request smuggling, CRLF
 Phase 21 │ IDOR                   → Cross-user access control (2-account)
 Phase 22 │ Business Logic         → Price tampering, workflow bypass, rate limiting
 Phase 23 │ XXE & Path Traversal   → XML external entities, LFI/directory traversal
 Phase 24 │ API Security           → Endpoint enumeration, auth bypass, info disclosure
 Phase 25 │ Race Conditions        → TOCTOU, concurrent request exploitation
 Phase 26 │ Sensitive Files        → Config files, backup files, exposed directories
 Phase 27 │ Account Security       → Account enumeration, password policy, lockout testing
 Phase 28 │ Error Handling         → Error disclosure, stack traces, debug information
 Phase 29 │ WebSocket Security     → CSWSH, auth bypass, injection via WS, channel hijacking
 Phase 30 │ OAuth / SSO Abuse      → redirect_uri manipulation, PKCE bypass, SAML attacks
 Phase 31 │ Mass Assignment        → Parameter injection, HTTP param pollution, prototype pollution
 Phase 32 │ Cache Poisoning        → Unkeyed header injection, web cache deception, request smuggling
 Phase 33 │ Reporting              → Aggregated findings, curl PoCs, CVSS, PDF report
   ─────────────────────────────────────────────────────────────────────────────
   AUTO  │ Exploitation Escalation → Runs after EVERY confirmed vuln — SQLi data extraction,
         │                           CMDi system enum, SSTI RCE chains, SSRF cloud metadata theft,
         │                           IDOR mass extraction, file upload webshells, vuln chaining
```

Each finding is **confirmed before reporting** — the agent parses response bodies, checks actual behavior, and provides reproducible proof-of-concept commands. When a vulnerability is confirmed, the agent **must escalate exploitation** (minimum 3 steps) to prove maximum impact — SQLi leads to data dumps, command injection leads to system enumeration, SSRF leads to cloud credential theft. The agent also **chains findings** automatically (e.g., SQLi + file write = RCE).

### Screenshot-Verified Reporting

Every vulnerability finding goes through a strict evidence pipeline before it reaches the final report:

```
 Discovery → Confirmation → Exploitation Escalation → Screenshot Verification → Report Entry
     ↓             ↓                  ↓                        ↓                     ↓
  Detect via    Re-test to       Escalate to max         Open in browser,      Include all:
  requests/     confirm real      impact: extract         take screenshot,      test script,
  scanning      behavior          data, enum system,      AI analyzes image     server response,
                                  prove RCE, chain                              screenshot proof,
                                  with other vulns                              working curl PoC
```

**What every finding includes:**
- **Test Script** — the actual Python code used to detect and confirm the vulnerability
- **Server Response** — real HTTP response data (status, headers, body excerpt)
- **Screenshot Proof** — browser screenshot visually confirming the issue (requires vision model)
- **curl PoC** — working `curl` command with real cookies/tokens for manual reproduction

**False positive elimination:** The AI opens each finding URL in the browser and screenshots it. If the screenshot shows a 404, error page, or WAF block instead of the claimed vulnerability, the finding is automatically removed. No more phantom findings.

> **Note:** Screenshot verification requires a vision-capable model. Non-vision models still produce reports with test scripts, server responses, and curl PoCs but skip visual confirmation.

### Report Output Formats

Every scan automatically generates **4 report formats** in the session workspace:

| Format | File | Use Case |
|--------|------|----------|
| **PDF** | `report.pdf` | Client delivery — professional ZDL format with risk matrix, CVSS scoring, remediation steps |
| **HTML** | `report.html` | Interactive browser viewing with expandable findings and syntax-highlighted PoCs |
| **JSON** | `report.json` | Integration with DefectDojo, Jira, CI/CD pipelines, custom tooling |
| **XML** | `report.xml` | Compliance tools, SIEM import, enterprise reporting systems |

All four formats contain identical data: professional finding titles, CVSS v3.1 with vector strings, OWASP Top 10 classification, ZDL risk matrix (likelihood x severity), proof of concept with request/response, and remediation steps with CWE/OWASP references.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Python** | 3.10 or higher |
| **LLM Backend** | One of: [Ollama](https://ollama.com), [LM Studio](https://lmstudio.ai), or [Anthropic API key](https://console.anthropic.com) |
| **OS** | Linux (tested on Ubuntu/Debian), macOS, Windows (with `setup.ps1`) |
| **Optional** | `chromium` for browser vision / screenshot verification (`sudo snap install chromium`) |
| **Optional** | `nmap`, `nikto`, `gobuster`, `sqlmap` for extended scanning |
| **Optional** | `tor` for anonymous traffic routing |

## Installation

```bash
git clone https://github.com/neuralxploit/TheRobin.git
cd TheRobin
bash setup.sh
```

The setup script creates a virtual environment, installs all dependencies, and generates the run script.

### Option A: Ollama (Free / Local)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the recommended model
ollama pull glm-4.7:cloud
```

```bash
# Run with Ollama
./run.sh -t https://target.com -m glm-4.7:cloud
```

### Option B: Claude API (Anthropic)

TheRobin supports Claude models directly via the Anthropic API — no Ollama required. Claude has strong tool calling, 200K context, and vision support.

```bash
# Set your API key (get one at https://console.anthropic.com)
export ANTHROPIC_API_KEY=sk-ant-your-key-here

# Run with Claude
python main.py -t https://target.com -m claude-sonnet-4-20250514
```

To make the key permanent:
```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-your-key-here' >> ~/.bashrc
source ~/.bashrc
```

### Option C: Claude Code (CLI) — No Setup Required

**The fastest way to run TheRobin.** If you have [Claude Code](https://claude.ai/code) installed, you need no Ollama, no API key wiring, no virtual environment. Clone the repo, open it in Claude Code, and talk to it.

```bash
# Install Claude Code if you haven't already
npm install -g @anthropic-ai/claude-code

# Clone and open
git clone https://github.com/neuralxploit/TheRobin.git
cd TheRobin
claude
```

**Skip permission prompts** — Claude Code asks to confirm every tool call by default. For a pentest this is constant interruption. Launch with:

```bash
claude --dangerously-skip-permissions
```

Then just say:

```
pentest http://target.com admin/password123
```

Claude Code reads `CLAUDE.md` automatically and acts as the full pentest agent — it loads the phase guides, writes and runs test code via its built-in execution tools, tracks all findings, and generates the final PDF report. No model downloads, no config.

### Option D: OpenCode CLI — Free Models Available

OpenCode is an open-source AI coding agent with free models included. Works similarly to Claude Code with TUI and Build modes.

```bash
# Install OpenCode
curl -fsSL https://opencode.ai/install | bash

# Clone and open
git clone https://github.com/neuralxploit/TheRobin.git
cd TheRobin
opencode
```

Then start by reading the integration guide:

```
Read OPENCODE.md
```

Now run your pentest:

```
pentest http://target.com admin/password123
```

OpenCode will act as the full pentest agent — it loads the phase guides, writes and runs test code via its built-in execution tools, tracks all findings, and generates the final PDF report.

### Option E: LM Studio (Local / Free)

Run any GGUF model locally through LM Studio's OpenAI-compatible API:

```bash
# Start LM Studio, load a model, then:
./run.sh -t https://target.com -m lmstudio:qwen2.5-coder-32b
```

Set `LMSTUDIO_BASE` to point to a remote instance: `export LMSTUDIO_BASE=http://192.168.1.100:1234`

| | TheRobin Loop (Options A/B/E) | Claude Code (Option C) | OpenCode (Option D) |
|---|---|---|---|
| **Model** | Ollama / LM Studio / Anthropic API | Claude Code subscription | OpenCode (free models available) |
| **Setup** | `bash setup.sh` + model pull | `npm install -g @anthropic-ai/claude-code` | `curl -fsSL https://opencode.ai/install | bash` |
| **Interaction** | Autonomous — watch it run | Conversational — ask questions mid-test | Conversational — TUI/Build modes |
| **Phases** | Full 33-phase auto-run | Full 33-phase, you can steer | Full 33-phase, you can steer |
| **Report** | Auto-generated at end | Ask "generate the report" anytime | Ask "generate the report" anytime |

<details>
<summary><b>Available Models</b></summary>

**Claude API** (via Anthropic — requires API key):
| Model | Vision | Notes |
|-------|--------|-------|
| `claude-sonnet-4-20250514` | ✅ | **Recommended** — fast, strong tool calling, 200K context |
| `claude-opus-4-20250514` | ✅ | Most capable, slower, higher cost |
| `claude-haiku-4-5-20251001` | ✅ | Fastest, cheapest, good for simple targets |

**Ollama Cloud-proxied** (via Ollama infrastructure — data sent to provider):
| Model | Vision | Notes |
|-------|--------|-------|
| `glm-4.7:cloud` | ❌ | **Recommended for Ollama** — 128K context, best tool calling, follows all 33 phases reliably |
| `glm-5:cloud` | ❌ | Coding-specialized, strong tool calling |
| `kimi-k2.5:cloud` | ✅ | Vision + tools, but poor phase adherence — not recommended |
| `kimi-k2:1t-cloud` | ❌ | Strong reasoning, large context |
| `deepseek-v3.1:671b-cloud` | ❌ | High capability, slower |
| `qwen3-coder-next:cloud` | ❌ | Good coding performance |

**Ollama Local** (fully private — requires GPU with sufficient VRAM):
| Model | VRAM | Notes |
|-------|------|-------|
| `qwen2.5-coder:32b` | ~20GB | Strong coding, good for pentesting |
| `deepseek-coder-v2:16b` | ~10GB | Lighter option |
| `codellama:34b` | ~20GB | Meta's code model |

> **Claude models** connect directly to Anthropic's API. Target data is sent to Anthropic. For fully private testing, use a local Ollama model.
>
> **Cloud-proxied Ollama models** (`:cloud` suffix) route prompts through Ollama's cloud infrastructure. For sensitive engagements, use a locally-running model.
>
> **Vision models** (Claude, `kimi-k2.5:cloud`) can analyze browser screenshots — enabling visual confirmation of XSS popups, login pages, error messages, and JS-heavy apps.

</details>

---

## Usage

### Quick Start

```bash
# Interactive mode — configure target in the console
./run.sh

# Direct target
./run.sh -t https://target.com

# With credentials for authentication testing
./run.sh -t https://target.com -u admin -p password123

# OSINT-only mode (passive reconnaissance, no active testing)
./run.sh -t target.com --mode osint

# Full engagement (OSINT recon + webapp testing)
./run.sh -t target.com --mode full

# Route traffic through Tor
./run.sh -t https://target.com --tor

# Specific model
./run.sh -t https://target.com -m glm-4.7:cloud
```

### Console Commands

```
 /set TARGET <url>      Set the target URL
 /set MODEL <name>      Switch the LLM model
 /set COOKIE <string>   Set pre-authenticated session cookie (for 2FA apps)
 /set TOR on|off        Toggle Tor SOCKS5 proxy routing
 /set SCOPE dom1,dom2   Define in-scope domains
 /set HEADERS <string>  Custom headers for all requests (bug bounty auth)
 /options               Display current session configuration
 /model <name>          Quick model switch
 /report                Generate the final Markdown report
 /clear                 Reset conversation history
 /quit                  Exit TheRobin
```

### Pre-Authenticated Sessions (2FA Targets)

For targets with multi-factor authentication or complex login flows:

1. Log in manually via your browser
2. Open DevTools → Application → Cookies → copy the cookie string
3. Pass it to TheRobin:

```bash
./run.sh -t https://target.com
# then in console:
/set COOKIE JSESSIONID=abc123; csrf_token=xyz789; session_id=def456
```

The agent loads your authenticated session and skips login-phase testing. All subsequent phases run with your active session — curl PoCs in the report will include the session cookies for reproducibility.

---

## 🧪 Vulnerable Test App

An intentionally vulnerable Flask application is included in `vuln_app/` for safe testing and demonstrations.

```bash
# Terminal 1 — start the vulnerable app
cd vuln_app && python3 app.py
# → http://localhost:5000

# Terminal 2 — run TheRobin against it
./run.sh -t http://localhost:5000 -u admin -p admin123
```

<details>
<summary><b>Vulnerability Coverage (OWASP Top 10)</b></summary>

| OWASP Category | Vulnerabilities |
|---------------|-----------------|
| A01 Broken Access Control | IDOR on profiles/invoices, admin panel without role check, privilege escalation |
| A02 Cryptographic Failures | MD5 password hashes, sensitive data in plain cookies, weak session secret |
| A03 Injection | SQLi (login + search), reflected XSS, stored XSS, OS command injection |
| A04 Insecure Design | No account lockout, predictable password reset tokens |
| A05 Security Misconfiguration | Missing security headers, debug mode, verbose errors, default credentials |
| A06 Vulnerable Components | jQuery 1.6.1 (CVE-2011-4969), Bootstrap 3.3.6 |
| A07 Auth Failures | Default creds (admin/admin123), no rate limiting, session fixation |
| A08 Integrity Failures | No CSRF tokens, pickle deserialization endpoint |
| A09 Logging Failures | Failed logins not logged, no audit trail |
| A10 SSRF | Arbitrary URL fetch endpoint |

**Default credentials:** `admin/admin123` · `alice/password1` · `bob/123456` · `charlie/letmein`

</details>

---

## 🧅 Tor / Anonymity Support

Route all agent-generated HTTP traffic through the Tor network:

```bash
# Install and start Tor
sudo apt install tor && sudo systemctl start tor

# Launch with Tor
./run.sh -t https://target.com --tor
```

Or toggle at runtime: `/set TOR on`

| Component | Routed Through Tor |
|-----------|-------------------|
| `web_request` tool | ✅ Yes |
| OSINT lookups (crt.sh, Wayback, DuckDuckGo) | ✅ Yes |
| Agent-written `requests` code | ✅ Yes |
| Ollama API (localhost) | ❌ No — local, correct |
| DNS lookups, WHOIS | ❌ No — system resolver |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         main.py (CLI)                            │
│                  --targets-file / -T batch mode                  │
├──────────────────────────────────────────────────────────────────┤
│                     app.py (Session Manager)                     │
├───────────────────────────┬──────────────────────────────────────┤
│   agent/loop.py           │         ui/console.py                │
│   (Agentic Loop)          │         (Rich TUI)                   │
├───────────────────────────┴──────────────────────────────────────┤
│                       agent/tools.py (12 tools)                  │
│  ┌──────────┐ ┌──────┐ ┌───────────┐ ┌────────────┐ ┌────────┐  │
│  │run_python│ │ bash │ │web_request│ │browser_    │ │osint_  │  │
│  │  (REPL)  │ │      │ │           │ │action      │ │recon   │  │
│  └──────────┘ └──────┘ └───────────┘ └────────────┘ └────────┘  │
│  ┌──────────┐ ┌──────┐ ┌───────────┐ ┌────────────┐ ┌────────┐  │
│  │read_file │ │write │ │start_new_ │ │generate_   │ │compact │  │
│  │          │ │_file │ │session    │ │report      │ │_state  │  │
│  └──────────┘ └──────┘ └───────────┘ └────────────┘ └────────┘  │
│  ┌──────────────────┐ ┌────────────────────────────┐             │
│  │get_session_info  │ │restore_state_from_json     │             │
│  └──────────────────┘ └────────────────────────────┘             │
├──────────────────────────────────────────────────────────────────┤
│  agent/prompts.py  │ agent/ollama.py │ agent/lmstudio.py        │
│  (33-phase roadmap │ (Ollama HTTP    │ (LM Studio OpenAI-       │
│   + on-demand      │  client)        │  compatible client)       │
│   phase guides)    │                 │                           │
├────────────────────┼─────────────────┼───────────────────────────┤
│  agent/osint.py    │ agent/claude_api.py │ mcp_server.py         │
│  (crt.sh, DNS,     │ (Anthropic API      │ (MCP bridge for       │
│   WHOIS, Wayback)  │  client)            │  Claude Code)         │
├──────────────────────────────────────────────────────────────────┤
│                    agent/phases/ (34 phase guides)               │
│  33 detection/testing phases + exploitation escalation engine    │
└──────────────────────────────────────────────────────────────────┘
```

| File | Purpose |
|------|---------|
| `main.py` | CLI entry point — argument parsing, `--targets-file` batch mode |
| `app.py` | Session management, command handling, option configuration |
| `agent/loop.py` | Agentic loop — LLM ↔ tool execution cycle with context compaction |
| `agent/tools.py` | 12 tool implementations (REPL, bash, HTTP, browser, OSINT, session mgmt, reporting) + JSON schemas |
| `agent/prompts.py` | Lean system prompt — rules + phase roadmap (full code loaded on-demand from `agent/phases/`) |
| `agent/ollama.py` | Ollama HTTP client (stdlib `urllib`, zero external deps) |
| `agent/lmstudio.py` | LM Studio OpenAI-compatible client with streaming support |
| `agent/claude_api.py` | Anthropic Claude API client with tool calling |
| `agent/osint.py` | OSINT modules — crt.sh subdomains, DNS, WHOIS, Wayback, DuckDuckGo dorking |
| `mcp_server.py` | MCP server — exposes all 12 tools to Claude Code / OpenCode |
| `agent/phases/` | 34 phase guide files — 33 testing phases + exploitation escalation engine |
| `ui/console.py` | Rich-based terminal UI — panels, tool output blocks, status indicators |

---

## Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
>
> You must only use TheRobin against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is a criminal offense in most jurisdictions. The authors assume no liability for misuse of this software.
>
> Always obtain proper written authorization before conducting any penetration test.

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**TheRobin** — *Think like an attacker. Test like an engineer. Report like a professional.*

</div>
