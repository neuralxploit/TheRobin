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
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

**Autonomous AI-driven penetration testing framework powered by LLMs.**
<br>
TheRobin executes a full 12-phase web application security assessment autonomously —
<br>
from reconnaissance to report generation — using an AI agent that writes, executes, and iterates on its own attack code.

[Getting Started](#installation) · [Usage](#usage) · [Test Lab](#-vulnerable-test-app) · [Tor Mode](#-tor--anonymity-support) · [Architecture](#architecture)

</div>

---

## Overview

TheRobin is an offensive security tool that uses Large Language Models via [Ollama](https://ollama.com) to conduct autonomous penetration tests against web applications. Unlike traditional scanners that rely on signature matching, TheRobin's AI agent **reasons about responses**, **adapts its attack strategy**, and **confirms vulnerabilities** before reporting them.

The agent operates through a persistent Python REPL — writing and executing code in real-time, chaining system tools (nmap, sqlmap, gobuster), and maintaining full session state across hundreds of interactions. It follows a structured 12-phase methodology but adapts dynamically based on what it discovers.

### Key Capabilities

| | Capability | Details |
|---|---|---|
| 🤖 | **Autonomous Agent** | AI writes & executes attack code in a persistent REPL — no manual scripting needed |
| 👁️ | **Browser Vision** | Headless Chromium with screenshot analysis — the AI *sees* pages, confirms findings visually, and handles JS-heavy apps |
| 🔍 | **OSINT Recon** | Subdomain enumeration (crt.sh), DNS, WHOIS, Wayback Machine, DuckDuckGo dorking |
| 🌐 | **Full Web Testing** | SQLi, XSS, CSRF, IDOR, SSRF, CRLF, command injection, deserialization, and more |
| 🔐 | **2FA / Cookie Auth** | Paste a session cookie for targets with complex authentication |
| 🧅 | **Tor Routing** | Route all agent traffic through Tor with one flag |
| 📊 | **Professional Reports** | Markdown reports with CVSS v3.1 scores, reproducible curl PoCs, and remediation |
| ✅ | **Zero False Positives** | Strict confirmation logic — every finding is screenshot-verified and confirmed, not just observed |
| 🖥️ | **Rich TUI** | Color-coded terminal interface with real-time tool output and phase tracking |

### Privacy Notice

TheRobin works with both **local models** (data never leaves your machine) and **cloud-proxied models** via Ollama (`:cloud` suffix — data is sent to the model provider). Choose based on your operational security requirements.

---

## Testing Methodology

TheRobin follows a structured 12-phase approach covering the OWASP Top 10 and beyond:

```
 Phase  1 │ Reconnaissance         → Headers, tech stack, directory bruteforce, sitemap
 Phase  2 │ Authentication         → Default credentials, brute-force, login bypass
 Phase  3 │ Authenticated Crawl    → Form discovery, parameter harvesting, ID collection
 Phase  4 │ Session Management     → Cookie flags, session fixation, JWT analysis
 Phase  5 │ Cross-Site Scripting   → Reflected, stored, DOM-based XSS
 Phase  6 │ SQL Injection          → Error-based, blind boolean/time, auth bypass
 Phase  7 │ Access Control & CSRF  → Unauthenticated access, CSRF token verification
 Phase  8 │ Tech Fingerprinting    → Version detection, CVE lookup, JS static analysis
 Phase  9 │ Advanced Web Attacks   → CORS, open redirect, CRLF injection, SSL/TLS
 Phase 10 │ Protocol Attacks       → Host header injection, request smuggling, GraphQL
 Phase 11 │ IDOR                   → Cross-user access control testing (2-account)
 Phase 12 │ Reporting              → Aggregated findings, curl PoCs, CVSS, remediation
```

Each finding is **confirmed before reporting** — the agent parses response bodies, checks actual behavior, and provides reproducible proof-of-concept commands.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Python** | 3.10 or higher |
| **Ollama** | Running locally — [install here](https://ollama.com) |
| **OS** | Linux (tested on Ubuntu/Debian) — macOS may work |
| **Optional** | `nmap`, `nikto`, `gobuster`, `sqlmap` for extended scanning |
| **Optional** | `tor` for anonymous traffic routing |

## Installation

```bash
git clone https://github.com/neuralxploit/TheRobin.git
cd TheRobin
bash setup.sh
```

The setup script creates a virtual environment, installs all dependencies, and generates the run script.

### Ollama Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model (vision + tools + thinking)
ollama pull kimi-k2.5:cloud
```

<details>
<summary><b>Available Models</b></summary>

**Cloud-proxied** (via Ollama infrastructure — data sent to provider):
| Model | Vision | Notes |
|-------|--------|-------|
| `kimi-k2.5:cloud` | ✅ | **Default** — vision + tools + thinking, screenshot-verified findings |
| `glm-4.7:cloud` | ❌ | 198K context, coding-specialized, fast (no vision) |
| `kimi-k2:1t-cloud` | ❌ | Strong reasoning, large context |
| `deepseek-v3.1:671b-cloud` | ❌ | High capability, slower |
| `qwen3-coder-next:cloud` | ❌ | Good coding performance |

**Local** (fully private — requires GPU with sufficient VRAM):
| Model | VRAM | Notes |
|-------|------|-------|
| `qwen2.5-coder:32b` | ~20GB | Strong coding, good for pentesting |
| `deepseek-coder-v2:16b` | ~10GB | Lighter option |
| `codellama:34b` | ~20GB | Meta's code model |

> Cloud-proxied models (`:cloud` suffix) route prompts and target data through Ollama's cloud infrastructure to the model provider. For sensitive engagements, use a locally-running model.
>
> **Vision models** (like `kimi-k2.5:cloud`) can analyze browser screenshots — enabling visual confirmation of XSS popups, login pages, error messages, and JS-heavy single-page apps. Non-vision models still work but skip screenshot analysis.

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
┌─────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                        │
├─────────────────────────────────────────────────────────────┤
│                    app.py (Session Manager)                  │
├──────────────────────────┬──────────────────────────────────┤
│   agent/loop.py          │        ui/console.py             │
│   (Agentic Loop)         │        (Rich TUI)                │
├──────────────────────────┴──────────────────────────────────┤
│                      agent/tools.py                         │
│  ┌──────────┐ ┌──────┐ ┌───────────┐ ┌─────────┐ ┌──────┐  │
│  │run_python│ │ bash │ │web_request│ │read_file│ │write │  │
│  │  (REPL)  │ │      │ │           │ │         │ │_file │  │
│  └──────────┘ └──────┘ └───────────┘ └─────────┘ └──────┘  │
├─────────────────────────────────────────────────────────────┤
│  agent/prompts.py    │  agent/ollama.py  │  agent/osint.py  │
│  (4K lines of        │  (Ollama HTTP     │  (crt.sh, DNS,   │
│   methodology)       │   client)         │   WHOIS, Wayback)│
└─────────────────────────────────────────────────────────────┘
```

| File | Purpose |
|------|---------|
| `main.py` | CLI entry point — argument parsing |
| `app.py` | Session management, command handling, option configuration |
| `agent/loop.py` | Agentic loop — LLM ↔ tool execution cycle with context compaction |
| `agent/tools.py` | Tool implementations (REPL, bash, HTTP, file I/O) + JSON schemas |
| `agent/prompts.py` | System prompt — 4K lines of pentest methodology, code templates, confirmation logic |
| `agent/ollama.py` | Ollama HTTP client (stdlib `urllib`, zero external deps) |
| `agent/osint.py` | OSINT modules — crt.sh subdomains, DNS, WHOIS, Wayback, DuckDuckGo dorking |
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
