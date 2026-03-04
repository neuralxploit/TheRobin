"""
App — wires the UI and Agent together, manages the session main loop.
"""

import sys
import threading
import time
import json
from pathlib import Path
from datetime import datetime

from agent.loop import AgentLoop
from agent.ollama import list_models
from agent.tools import WORKSPACE_DIR
from ui.console import PentestConsole


# Models known to support tool calling well with Ollama
PREFERRED_MODELS = [
    "glm-4.7",
    "glm-5",
    "glm-4",
    "kimi-k2",
    "deepseek",
    "qwen",
    "mistral",
]


def pick_default_model(models: list[str]) -> str | None:
    """Pick the best available model for tool calling."""
    for pref in PREFERRED_MODELS:
        for m in models:
            if pref in m.lower():
                return m
    return models[0] if models else None


class App:
    def __init__(
        self,
        model_override: str = None,
        target: str = None,
        username: str = None,
        password: str = None,
        scope: str = None,
        mode: str = "webapp",
        cookie: str = None,
        tor: bool = False,
    ):
        self.ui = PentestConsole()
        self.model_override = model_override
        self.model = None
        self.agent = None
        self._running = True
        self._agent_busy = threading.Event()

        # Session options — shown in Metasploit-style table, editable before run
        self.session = {
            "TARGET":   target   or "",
            "MODEL":    model_override or "",
            "USERNAME": username or "",
            "PASSWORD": password or "",
            "COOKIE":   cookie   or "",
            "SCOPE":    scope    or "",
            "MODE":     mode     or "webapp",
            "TOR":      "on" if tor else "off",
        }
        if tor:
            import agent.tools as _tools_mod
            _tools_mod.TOR_ENABLED = True
            _tools_mod._CLEAN_ENV["PENTEST_TOR_PROXY"] = _tools_mod.TOR_PROXY

    def _setup_workspace(self):
        """Create per-session workspace directory."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = WORKSPACE_DIR / f"session_{ts}"
        session_dir.mkdir(parents=True, exist_ok=True)
        # Update the tools module to use this session dir
        import agent.tools as tools_mod
        tools_mod.WORKSPACE_DIR = session_dir
        return session_dir

    def run(self):
        """Main application entry point."""
        session_dir = self._setup_workspace()

        # Detect Ollama models
        models = list_models()

        if self.session["MODEL"]:
            self.model = self.session["MODEL"]
        else:
            self.model = pick_default_model(models)
            self.session["MODEL"] = self.model or ""

        # Print banner
        self.ui.print_banner(models, self.model or "none")

        if not self.model:
            self.ui.print_system("No Ollama model available. Start Ollama first.")
            return

        # ── Metasploit-style setup phase ──────────────────────────────────────
        # Always show the options table and let the user configure before running
        self._setup_phase()
        if not self._running:
            return

        # Init agent with chosen model
        self.model = self.session["MODEL"] or self.model
        self.agent = AgentLoop(
            model=self.model,
            on_token=self._on_token,
            on_tool_call=self._on_tool_call,
            on_tool_result=self._on_tool_result,
            on_status=self._on_status,
            mode=self.session.get("MODE", "webapp"),
        )

        self.ui.print_system(f"Session workspace: {session_dir}")
        self.ui.print_system(f"Model: {self.model}  |  Mode: {self.session['MODE']}")

        # Auto-start agent with configured options
        initial = self._build_initial_message()
        if initial:
            self.ui.print_user(initial)
            self._run_agent(initial)

        # Main input loop
        while self._running:
            try:
                user_input = self.ui.prompt_user()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            if user_input.startswith("/"):
                handled = self._handle_command(user_input)
                if not handled:
                    self.ui.print_system(f"Unknown command: {user_input}")
                continue

            self.ui.print_user(user_input)
            self._run_agent(user_input)

    # Options with fixed allowed values
    _OPTION_CHOICES = {
        "MODE": ("webapp", "osint", "full"),
        "TOR":  ("on", "off"),
    }

    def _set_option(self, key: str, val: str) -> str:
        """
        Validate and set a session option.
        Returns an error string if invalid, empty string on success.
        """
        key = key.upper()
        if key not in self.session:
            return f"Unknown option: {key}. Valid: {', '.join(self.session.keys())}"
        if key in self._OPTION_CHOICES:
            choices = self._OPTION_CHOICES[key]
            if val.lower() not in choices:
                return f"{key} must be one of: {' | '.join(choices)}  (got: '{val}')"
            val = val.lower()
        self.session[key] = val
        if key == "MODEL" and self.agent:
            self.agent.set_model(val)
            self.model = val
        if key == "TOR":
            import agent.tools as _tools_mod
            from agent.tools import reset_repl
            _tools_mod.TOR_ENABLED = (val == "on")
            if val == "on":
                _tools_mod._CLEAN_ENV["PENTEST_TOR_PROXY"] = _tools_mod.TOR_PROXY
            else:
                _tools_mod._CLEAN_ENV.pop("PENTEST_TOR_PROXY", None)
            reset_repl()  # restart REPL so it picks up new env
        return ""

    def _setup_phase(self):
        """
        Metasploit-style options configuration before starting the agent.
        User can set TARGET, MODEL, USERNAME, PASSWORD, SCOPE, MODE.
        Type 'run' or press Enter on empty to start.
        """
        self.ui.print_options_table(self.session)
        self.ui.print_system("Configure options then type  run  to start the pentest.")

        while True:
            try:
                line = self.ui.prompt_setup()
            except (EOFError, KeyboardInterrupt):
                self._running = False
                return

            if not line:
                # Empty enter — if TARGET is set, start
                if self.session["TARGET"]:
                    return
                self.ui.print_system("TARGET is required. Example:  set TARGET https://target.com")
                continue

            parts = line.split(None, 2)
            cmd = parts[0].lower()

            if cmd in ("run", "start", "go", "exploit"):
                if not self.session["TARGET"]:
                    self.ui.print_system("[!] TARGET is required:  set TARGET https://target.com")
                    continue
                return

            elif cmd in ("quit", "exit", "q"):
                self._running = False
                return

            elif cmd == "show":
                self.ui.print_options_table(self.session)

            elif cmd == "help":
                self.ui.print_system("Available options: TARGET  MODEL  USERNAME  PASSWORD  COOKIE  SCOPE  MODE  TOR")
                self.ui.print_system("  set TARGET   https://target.com")
                self.ui.print_system("  set USERNAME admin")
                self.ui.print_system("  set PASSWORD secret123")
                self.ui.print_system("  set COOKIE   'session=abc123; csrf=xyz'  (use instead of user/pass for 2FA apps)")
                self.ui.print_system("  set SCOPE    target.com,api.target.com")
                self.ui.print_system("  set MODE     webapp | osint | full")
                self.ui.print_system("  set TOR      on | off  (route HTTP through Tor localhost:9050)")
                self.ui.print_system("  set MODEL    glm-4.7:cloud")
                self.ui.print_system("  run          — start the pentest")

            elif cmd == "set" and len(parts) >= 3:
                key = parts[1].upper()
                val = parts[2].strip()
                err = self._set_option(key, val)
                if err:
                    self.ui.print_system(f"  [!] {err}")
                else:
                    self.ui.print_system(f"  {key} => {self.session[key]}")
                    self.ui.print_options_table(self.session)

            elif cmd == "set" and len(parts) == 2:
                self.ui.print_system(f"  Usage: set {parts[1].upper()} <value>")

            else:
                self.ui.print_system(
                    f"  Unknown command: {cmd}. "
                    "Use: set <OPTION> <value>  |  show  |  run  |  help"
                )

    def _build_initial_message(self) -> str:
        """Build the first message sent to the agent from session options."""
        s = self.session
        mode = s.get("MODE", "webapp").lower()
        target = s.get("TARGET", "")

        if not target:
            return ""

        lines = []

        if mode == "osint":
            lines.append(f"Perform a full OSINT reconnaissance on: {target}")
            lines.append(
                "Focus only on passive recon — do NOT actively probe or attack.\n"
                "Use osint_recon for: subdomains, dns, whois, wayback, dorks, harvester.\n"
                "When done, write a full summary to osint_report.md using write_file."
            )
        elif mode == "full":
            lines.append(f"Full penetration test engagement on: {target}")
            lines.append(
                "Follow this exact sequence — do NOT skip any step:\n"
                "\n"
                "STEP 1 — OSINT (passive, no active probing):\n"
                "  - osint_recon subdomains, dns, whois, wayback, harvester, dorks\n"
                "  - DuckDuckGo dorks: filetype, admin panels, exposed files, GitHub secrets\n"
                "  - Note every subdomain, IP, email, SMTP server, technology found\n"
                "\n"
                "STEP 2 — Write plan.md using write_file with this exact structure:\n"
                "  # Engagement Plan\n"
                "  ## Targets Found\n"
                "  - [ ] <main target>\n"
                "  - [ ] <each subdomain found>\n"
                "  ## Email / SMTP\n"
                "  - [ ] SPF record check\n"
                "  - [ ] DKIM check\n"
                "  - [ ] DMARC check\n"
                "  - [ ] Email spoofing test\n"
                "  ## Per-Target Tests\n"
                "  - [ ] Security headers\n"
                "  - [ ] Authentication bypass\n"
                "  - [ ] SQL injection\n"
                "  - [ ] XSS\n"
                "  - [ ] IDOR / access control\n"
                "  - [ ] Sensitive file exposure\n"
                "  - [ ] CSRF\n"
                "\n"
                "STEP 3 — Test each item in plan.md one by one. After completing each:\n"
                "  - Update plan.md: mark [ ] as [x] (done) or [!] (vulnerable)\n"
                "  - If you find a vulnerability, document it immediately in findings.md\n"
                "  - Always re-read plan.md before starting the next item\n"
                "\n"
                "STEP 4 — After ALL targets done: write final report.md\n"
                "\n"
                "CRITICAL: After every context compaction, read plan.md first to know\n"
                "exactly where you left off. Never rely only on memory."
            )
        else:
            lines.append(f"Test this web application: {target}")

        if s.get("COOKIE"):
            lines.append(
                f"IMPORTANT: The target uses 2FA or complex auth. "
                f"Use this pre-authenticated session cookie directly — do NOT attempt to log in:\n"
                f"Cookie: {s['COOKIE']}\n"
                f"Store it immediately: import requests; _s = requests.Session(); "
                f"[parse and set each cookie from the string above into _s.cookies]; "
                f"_G['session'] = _s; _G['session_a'] = _s\n"
                f"Skip Phase 3 authentication testing (login is not applicable)."
            )
        else:
            if s.get("USERNAME"):
                lines.append(f"Username: {s['USERNAME']}")
            if s.get("PASSWORD"):
                lines.append(f"Password: {s['PASSWORD']}")
        if s.get("SCOPE"):
            lines.append(f"In-scope: {s['SCOPE']}")

        return "\n".join(lines)

    def _run_agent(self, message: str):
        """Run the agent synchronously in the main thread (blocking)."""
        self._agent_busy.set()
        try:
            self.agent.send(message)
        except KeyboardInterrupt:
            self.ui.print_status("Interrupted.")
        finally:
            self._agent_busy.clear()
            self.ui.print_status("Ready")

    def _on_token(self, text: str):
        """Called by agent loop when it has a text response."""
        self.ui.print_agent_message(text)

    def _on_tool_call(self, name: str, args: dict):
        """Called before a tool is executed."""
        self.ui.print_tool_call(name, args)

    def _on_tool_result(self, name: str, result: str):
        """Called after a tool executes with its result."""
        self.ui.print_tool_result(name, result)

    def _on_status(self, message: str):
        """Called with status updates."""
        self.ui.print_status(message)

    def _handle_command(self, cmd: str) -> bool:
        """Handle /commands. Returns True if handled."""
        parts = cmd.split(None, 1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command == "/quit" or command == "/exit":
            if self.ui.confirm_quit():
                self._running = False
            return True

        elif command == "/clear":
            self.agent.clear_history()
            from agent.tools import reset_repl, reset_browser
            reset_repl()     # kill REPL so all variables are gone
            reset_browser()  # close browser session
            self.ui.print_system("Session history, REPL state, and browser cleared.")
            return True

        elif command == "/set":
            # /set KEY VALUE  — update a session option mid-session
            set_parts = arg.split(None, 1)
            if len(set_parts) < 2:
                self.ui.print_options_table(self.session)
                return True
            key = set_parts[0].upper()
            val = set_parts[1].strip()
            err = self._set_option(key, val)
            if err:
                self.ui.print_system(f"  [!] {err}")
            else:
                self.ui.print_system(f"  {key} => {self.session[key]}")
            return True

        elif command == "/options":
            self.ui.print_options_table(self.session)
            return True

        elif command == "/model":
            if arg:
                self.agent.set_model(arg)
                self.model = arg
                self.session["MODEL"] = arg
                self.ui.print_system(f"Switched to model: {arg}")
            else:
                models = list_models()
                self.ui.print_system(f"Available: {', '.join(models)}")
                self.ui.print_system(f"Current:   {self.model}")
            return True

        elif command == "/compact":
            info = self.agent.compact()
            self.ui.print_system(info)
            return True

        elif command == "/report":
            self._run_agent(
                "Please generate a comprehensive penetration test report of everything we've found "
                "so far. Save it to 'report.md' using write_file. Include: Executive Summary, "
                "Scope, Methodology, Findings (with severity), Recommendations, and Conclusion."
            )
            return True

        elif command == "/help":
            self.ui.print_system("Commands:")
            self.ui.print_system("  /clear              — reset conversation history and REPL state")
            self.ui.print_system("  /compact            — free context by summarising old tool results")
            self.ui.print_system("  /model [name]       — switch Ollama model")
            self.ui.print_system("  /set <OPT> <value>  — update session option (TARGET, USERNAME, COOKIE, TOR, etc.)")
            self.ui.print_system("  /options            — show current session options table")
            self.ui.print_system("  /report             — generate final pentest report")
            self.ui.print_system("  /quit               — exit")
            self.ui.print_system("  Tip: set COOKIE 'session=abc123' to skip login on 2FA apps")
            self.ui.print_system("  Tip: set TOR on  — route web_request and osint through Tor (localhost:9050)")
            return True

        return False
