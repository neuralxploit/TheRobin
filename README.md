
```
               · T h e ·
 ██████╗  ██████╗ ██████╗ ██╗███╗   ██╗
 ██╔══██╗██╔═══██╗██╔══██╗██║████╗  ██║
 ██████╔╝██║   ██║██████╔╝██║██╔██╗ ██║
 ██╔══██╗██║   ██║██╔══██╗██║██║╚██╗██║
 ██║  ██║╚██████╔╝██████╔╝██║██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

    AI Offensive Security & OSINT Engine
```

# TheRobin

**Autonomous AI-powered penetration testing and OSINT engine.** TheRobin uses LLMs via [Ollama](https://ollama.com) to perform real-world web application security assessments — no cloud API keys required.

It works with both **local models** (data stays on your machine) and **cloud-proxied models** via Ollama (e.g. `glm-4.7:cloud`, `kimi-k2:1t-cloud`). Choose based on your privacy requirements.

The AI agent writes and executes Python code in a persistent REPL (like a Jupyter notebook), runs system tools (nmap, sqlmap, gobuster), and methodically works through a 12-phase pentest methodology. It thinks like a real attacker, tests like an engineer, and reports like a professional.

---

## Features

- **Fully autonomous** — give it a target, it runs a complete pentest (12 phases)
- **Ollama-powered** — works with local models (fully private) or cloud-proxied models via Ollama
- **Persistent REPL** — agent builds on previous code, maintains session state across calls
- **OSINT mode** — passive recon: subdomain enum (crt.sh), DNS, WHOIS, Wayback, DuckDuckGo dorking
- **Pre-authenticated sessions** — paste a cookie string for 2FA/complex auth targets
- **Tor support** — route all HTTP traffic through Tor (`--tor` flag or `set TOR on`)
- **Professional reports** — generates Markdown reports with CVSS scores, curl PoCs, and remediation
- **Zero false positives** — strict confirmation logic (parses response bodies, not just status codes)
- **Rich TUI** — color-coded console with real-time tool output and phase tracking

## What It Tests

| Phase | Coverage |
|-------|----------|
| 1 | Reconnaissance — headers, tech stack, directory bruteforce |
| 2 | Authentication — default creds, brute-force, login bypass |
| 3 | Authenticated crawl — form discovery, ID harvesting |
| 4 | Session management — cookie flags, fixation, JWT analysis |
| 5 | XSS — reflected, stored, DOM-based |
| 6 | SQL injection — error-based, blind, auth bypass |
| 7 | Access control & CSRF — unauth access, CSRF confirmation |
| 8 | Technology fingerprinting — version detection, CVE lookup, JS analysis |
| 9 | Advanced web — CORS, open redirect, CRLF, HTTP methods, SSL/TLS |
| 10 | HTTP protocol attacks — host header injection, request smuggling, GraphQL |
| 11 | IDOR — cross-user access control (requires 2nd account) |
| 12 | Report generation — findings summary, curl PoCs, CVSS, remediation |

## Architecture

```
main.py → app.py (App) → agent/loop.py (AgentLoop) + ui/console.py (TUI)
                          │
                          ├── agent/tools.py    — 5 tools: run_python, bash, write_file, read_file, web_request
                          ├── agent/prompts.py  — system prompt (~4K lines of pentest methodology)
                          ├── agent/ollama.py   — Ollama HTTP client (stdlib, no deps)
                          └── agent/osint.py    — OSINT modules (crt.sh, DNS, WHOIS, Wayback, dorking)
```

---

## Requirements

- **Python 3.10+**
- **[Ollama](https://ollama.com)** running locally with at least one model
- **Linux** (tested on Ubuntu/Debian) — macOS should work but is untested
- Optional: `nmap`, `nikto`, `gobuster`, `sqlmap` for system-level scanning
- Optional: `tor` for anonymous routing

## Installation

```bash
git clone https://github.com/neuralxploit/TheRobin.git
cd TheRobin
bash setup.sh
```

This creates a virtual environment, installs dependencies, and sets up the run script.

### Ollama Setup

Install Ollama and pull a model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull glm-4.7:cloud      # cloud-proxied, recommended — 198K context, fast, coding-specialized
```

**Cloud-proxied models** (via Ollama, data sent to provider):
`glm-4.7:cloud`, `kimi-k2:1t-cloud`, `deepseek-v3.1:671b-cloud`, `qwen3-coder-next:cloud`

**Local models** (fully private, requires GPU):
`qwen2.5-coder:32b`, `deepseek-coder-v2:16b`, `codellama:34b`, or any Ollama-compatible model

> **Note:** Cloud-proxied models (`:cloud` suffix) send prompts and target data through Ollama's cloud infrastructure to the model provider. For maximum privacy, use a locally-running model.

## Usage

```bash
# Interactive mode
./run.sh

# With target
./run.sh -t https://target.com

# With credentials
./run.sh -t https://target.com -u admin -p password123

# OSINT only (passive recon, no active testing)
./run.sh -t target.com --mode osint

# Full engagement (OSINT + webapp testing)
./run.sh -t target.com --mode full

# Through Tor
./run.sh -t https://target.com --tor

# Specific model
./run.sh -t https://target.com -m kimi-k2:1t-cloud
```

### Console Commands

| Command | Description |
|---------|-------------|
| `/set TARGET <url>` | Set target URL |
| `/set MODEL <name>` | Switch LLM model |
| `/set COOKIE <string>` | Pre-authenticated session cookie (for 2FA apps) |
| `/set TOR on\|off` | Toggle Tor proxy routing |
| `/set SCOPE dom1,dom2` | Set in-scope domains |
| `/options` | Show current session options |
| `/model <name>` | Quick model switch |
| `/report` | Generate final Markdown report |
| `/clear` | Reset conversation history |
| `/quit` | Exit |

### Pre-Authenticated Cookie (2FA Targets)

For targets with 2FA or complex auth that can't be automated:

1. Log in manually in your browser
2. Copy the cookies from DevTools (Application → Cookies → copy as string)
3. Set it in TheRobin:

```
/set COOKIE JSESSIONID=abc123; csrf_token=xyz789
```

The agent will skip login testing and use your authenticated session for all phases.

---

## Vulnerable Test App

A deliberately vulnerable Flask app is included in `vuln_app/` for testing and demos:

```bash
cd vuln_app
python3 app.py
# Runs on http://localhost:5000
```

**Default credentials:** `admin/admin123`, `alice/password1`, `bob/123456`

Covers OWASP Top 10: SQLi, XSS (reflected + stored), IDOR, CSRF, SSRF, command injection, insecure deserialization, broken access control, and more.

```bash
# Test TheRobin against the vuln app
./run.sh -t http://localhost:5000 -u admin -p admin123
```

---

## Tor Support

Route all agent HTTP traffic through Tor for anonymity during authorized engagements:

```bash
# Install and start Tor
sudo apt install tor
sudo systemctl start tor

# Use TheRobin through Tor
./run.sh -t https://target.com --tor
```

Or toggle at runtime: `/set TOR on`

What goes through Tor:
- `web_request` tool (direct HTTP)
- OSINT lookups (crt.sh, Wayback, DuckDuckGo)
- Agent-written Python `requests` calls

What stays direct (correct):
- Ollama API (localhost)
- DNS lookups, WHOIS (system resolver)

---

## Disclaimer

**This tool is for authorized security testing and educational purposes only.**

Only use TheRobin against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse of this tool.

Always obtain proper authorization before conducting any penetration test.

## License

[MIT](LICENSE) — see LICENSE file for details.
