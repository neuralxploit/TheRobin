"""
Rich TUI console — visual layer for the AI Pentest Console.

Key improvements:
- Color-coded severity labels inline (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Section headers parsed and highlighted in tool output
- Findings summary count shown per result panel
- Web request results shown with rich formatting
- Clear "what is being tested" header for each code block
"""

import re
import json
import threading
import queue
import os
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.rule import Rule
from rich.table import Table
from rich import box

# ─── Readline setup — enables arrow keys, history, Ctrl+R search ─────────────
try:
    import readline as _rl
    _HISTORY_FILE = Path.home() / ".pentest_console_history"
    try:
        _rl.read_history_file(str(_HISTORY_FILE))
    except (FileNotFoundError, OSError, PermissionError):
        pass
    _rl.set_history_length(500)
    _rl.parse_and_bind("set editing-mode emacs")   # arrow keys + Ctrl+A/E/K/U
    _rl.parse_and_bind("tab: complete")
    import atexit
    atexit.register(_rl.write_history_file, str(_HISTORY_FILE))
    _READLINE_OK = True
except (ImportError, OSError):
    _READLINE_OK = False

# ─── Severity config ──────────────────────────────────────────────────────────

_SEVERITY = {
    "[CRITICAL]": ("✦ [CRITICAL]", "bold bright_red on red",   "bright_red"),
    "[HIGH]":     ("▲ [HIGH]    ", "bold red",                  "red"),
    "[MEDIUM]":   ("● [MEDIUM]  ", "bold yellow",               "yellow"),
    "[LOW]":      ("◆ [LOW]     ", "bold cyan",                 "cyan"),
    "[INFO]":     ("· [INFO]    ", "dim",                       "dim"),
    "[ERROR]":    ("✗ [ERROR]   ", "bold bright_red",           "bright_red"),
    "[OK]":       ("✓ [OK]      ", "bold green",                "green"),
    "[PASS]":     ("✓ [PASS]    ", "bold green",                "green"),
    "[SKIP]":     ("⊘ [SKIP]    ", "dim yellow",                "yellow"),
}


def _parse_output_line(line: str) -> Text:
    """
    Parse a single output line and return a colored Rich Text object.
    Handles severity tags, URLs, section headers, key=value pairs.
    """
    stripped = line.rstrip()

    # Section headers: lines like "=== AUTH TESTING ===" or "--- Phase 3 ---"
    if re.match(r"^\s*(={3,}|-{3,}|#{3,})", stripped) or re.match(r"^\s*(===|---|\*\*\*).+", stripped):
        t = Text()
        t.append("\n")
        t.append(stripped, style="bold white")
        return t

    # Lines that are purely section titles (like "1. Testing search.php for SQL injection")
    if re.match(r"^\s*\d+\.\s+", stripped):
        t = Text()
        t.append(stripped, style="bold white")
        return t

    # Check for severity tags anywhere in the line
    for tag, (display, line_style, _) in _SEVERITY.items():
        if tag in stripped:
            # Split: before tag, the tag, after tag
            idx = stripped.index(tag)
            before = stripped[:idx]
            after = stripped[idx + len(tag):]

            t = Text()
            if before.strip():
                t.append(before, style="dim white")
            t.append(f" {display.strip()} ", style=line_style)
            # Color the rest of the line based on severity
            rest_style = _SEVERITY[tag][2]
            t.append(after, style=rest_style)
            return t

    # Lines with URLs
    if re.search(r"https?://\S+", stripped):
        t = Text()
        # Indent prefix
        leading = len(stripped) - len(stripped.lstrip())
        t.append(" " * leading)
        rest = stripped.lstrip()
        # Colorize URLs inline
        url_re = re.compile(r"(https?://\S+)")
        parts = url_re.split(rest)
        for i, part in enumerate(parts):
            if i % 2 == 1:  # URL
                t.append(part, style="bold cyan underline")
            else:
                t.append(part, style="white")
        return t

    # Status code lines: "Status: 200", "HTTP 404", "→ 302"
    if re.search(r"\b(Status|HTTP|→)\s*:?\s*\d{3}\b", stripped):
        t = Text()
        # Color status codes
        def color_status(m):
            code = int(m.group(1))
            style = "bold green" if code < 300 else ("bold yellow" if code < 400 else "bold red")
            return (m.group(0), style)

        parts = re.split(r"(\d{3})", stripped)
        for i, part in enumerate(parts):
            if i % 2 == 1 and part.isdigit() and 100 <= int(part) <= 599:
                code = int(part)
                style = "bold green" if code < 300 else ("bold yellow" if code < 400 else "bold red")
                t.append(part, style=style)
            else:
                t.append(part, style="white")
        return t

    # Key: value lines (e.g., "  Server: Apache/2.4")
    kv_match = re.match(r"^(\s*)(\w[\w\-]+):\s+(.+)$", stripped)
    if kv_match:
        t = Text()
        t.append(kv_match.group(1))
        t.append(kv_match.group(2) + ": ", style="dim white")
        t.append(kv_match.group(3), style="white")
        return t

    # Default
    return Text(stripped, style="white")


def _render_stdout(stdout: str) -> tuple[Group, dict]:
    """
    Parse stdout and return (Rich Group of lines, severity_counts dict).
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    lines = stdout.split("\n")
    rendered = []

    for line in lines:
        if not line.strip():
            rendered.append(Text(""))
            continue

        # Count severities
        for tag in ["[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]"]:
            if tag in line:
                key = tag[1:-1]
                counts[key] = counts.get(key, 0) + 1

        rendered.append(_parse_output_line(line))

    return Group(*rendered), counts


def _severity_summary(counts: dict) -> Text:
    """Build a compact severity summary for the result panel title."""
    parts = []
    styles = {
        "CRITICAL": "bold bright_red",
        "HIGH":     "bold red",
        "MEDIUM":   "bold yellow",
        "LOW":      "bold cyan",
    }
    for key, style in styles.items():
        n = counts.get(key, 0)
        if n > 0:
            parts.append((f"  {n} {key}", style))

    if not parts:
        return Text("")
    t = Text("  findings:")
    for txt, style in parts:
        t.append(txt, style=style)
    return t


def _extract_test_summary(code: str) -> str:
    """
    Extract what the code is testing from its first print/comment/section header.
    Used as the tool call panel subtitle.
    """
    lines = code.split("\n")
    for line in lines:
        line = line.strip()
        # print("=== ... ===")
        m = re.search(r'print\(["\']([^"\']{5,})["\']', line)
        if m and "===" in m.group(1):
            return m.group(1).replace("===", "").strip()
        # # Comment header
        if line.startswith("#") and len(line) > 5 and not line.startswith("#!/"):
            return line[1:].strip()
        # print("Testing: ...")
        m2 = re.search(r'print\([f"\'](Testing[^"\']+)', line)
        if m2:
            return m2.group(1)
    return ""


# ─── Console class ────────────────────────────────────────────────────────────

class PentestConsole:
    def __init__(self):
        self.console = Console(highlight=False)

    def print_banner(self, models: list[str], default_model: str):
        self.console.print()
        self.console.print(Panel(
            Text.assemble(
                ("\n", ""),
                ("               · T h e ·\n", "dim white"),
                (" ██████╗  ██████╗ ██████╗ ██╗███╗   ██╗", "bold red"),
                ("   ._,\n", "bold #8B4513"),
                (" ██╔══██╗██╔═══██╗██╔══██╗██║████╗  ██║", "bold red"),
                ("  (", "bold #8B4513"), ("o", "bold white"), (" >\n", "bold yellow"),
                (" ██████╔╝██║   ██║██████╔╝██║██╔██╗ ██║", "bold yellow"),
                ("  //", "bold #8B4513"), ("●", "bold #ff6600"), (")\n", "bold #8B4513"),
                (" ██╔══██╗██║   ██║██╔══██╗██║██║╚██╗██║", "bold yellow"),
                ("  ^^\n", "bold #8B4513"),
                (" ██║  ██║╚██████╔╝██████╔╝██║██║ ╚████║\n", "bold green"),
                (" ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝\n", "bold green"),
                ("\n", ""),
                ("    AI Offensive Security & OSINT Engine\n", "bold white"),
                ("    Autonomous  ·  Stealth  ·  AI-Powered\n", "dim white"),
                ("\n", ""),
            ),
            box=box.DOUBLE,
            border_style="red",
            padding=(0, 4),
        ))
        self.console.print()
        if models:
            self.console.print(f"  [dim]Models:[/dim]  {', '.join(f'[cyan]{m}[/cyan]' for m in models[:5])}")
            self.console.print(f"  [dim]Active:[/dim]  [bold green]{default_model}[/bold green]")
        else:
            self.console.print("  [yellow]No Ollama models detected — is Ollama running?[/yellow]")

        self.console.print()
        self.console.print(
            "  [dim]Commands:[/dim] "
            "[bold]clear[/bold]  "
            "[bold]set <opt> <val>[/bold]  "
            "[bold]options[/bold]  "
            "[bold]model <name>[/bold]  "
            "[bold]report[/bold]  "
            "[bold]help[/bold]  "
            "[bold]quit[/bold]"
        )
        self.console.print(Rule(style="dim red"))
        self.console.print()

    def print_system(self, message: str):
        self.console.print(f"[dim italic]  {message}[/dim italic]")

    def print_user(self, message: str):
        self.console.print()
        self.console.print(Panel(
            Text(message, style="bold white"),
            title="[bold white] You [/bold white]",
            title_align="left",
            border_style="bright_white",
            box=box.ROUNDED,
            padding=(0, 1),
        ))

    def print_agent_message(self, text: str):
        self.console.print()
        self.console.print(Panel(
            Markdown(text),
            border_style="cyan",
            box=box.ROUNDED,
            title="[bold cyan] ◆ Agent [/bold cyan]",
            title_align="left",
            padding=(0, 1),
        ))

    def print_tool_call(self, name: str, args: dict):
        """Show the tool being invoked — with clear context of what's being tested."""
        self.console.print()

        if name == "run_python":
            code = args.get("code", "")
            summary = _extract_test_summary(code)
            label = f"[bold yellow] ▶ run_python [/bold yellow]"
            if summary:
                label += f"[dim]  —  {summary}[/dim]"
            content = Syntax(
                code, "python",
                theme="monokai",
                line_numbers=True,
                word_wrap=True,
                background_color="default",
            )

        elif name == "bash":
            cmd = args.get("command", "")
            label = f"[bold yellow] ▶ bash [/bold yellow][dim]  —  {cmd[:80]}[/dim]"
            content = Syntax(cmd, "bash", theme="monokai", word_wrap=True, background_color="default")

        elif name == "web_request":
            url   = args.get("url", "")
            method = args.get("method", "GET")
            label = f"[bold yellow] ▶ web_request [/bold yellow][dim]  {method}  [/dim][cyan]{url}[/cyan]"
            # Show only non-url args
            extra = {k: v for k, v in args.items() if k not in ("url", "method")}
            if extra:
                content = Syntax(json.dumps(extra, indent=2), "json", theme="monokai",
                                 word_wrap=True, background_color="default")
            else:
                content = Text(f"  {method}  {url}", style="cyan")

        elif name == "write_file":
            path = args.get("path", "")
            file_content = args.get("content", "")
            label = f"[bold yellow] ▶ write_file [/bold yellow][dim]  →  {path}[/dim]"
            content = Syntax(
                file_content[:3000], "markdown",
                theme="monokai", word_wrap=True, background_color="default"
            )

        elif name == "read_file":
            path = args.get("path", "")
            label = f"[bold yellow] ▶ read_file [/bold yellow][dim]  ←  {path}[/dim]"
            content = Text(f"  {path}", style="dim cyan")

        else:
            label = f"[bold yellow] ▶ {name} [/bold yellow]"
            content = Syntax(json.dumps(args, indent=2), "json", theme="monokai",
                             word_wrap=True, background_color="default")

        self.console.print(Panel(
            content,
            title=label,
            title_align="left",
            border_style="dark_orange",
            box=box.SIMPLE_HEAD,
            padding=(0, 1),
        ))

    def print_tool_result(self, name: str, result_json: str):
        """Render tool results with rich formatting and severity color coding."""
        try:
            result = json.loads(result_json)
        except Exception:
            result = {"raw": result_json}

        if name == "run_python":
            self._render_python_result(result)

        elif name == "bash":
            self._render_bash_result(result)

        elif name == "web_request":
            self._render_web_result(result)

        elif name == "write_file":
            success = result.get("success", False)
            path = result.get("path", "")
            err = result.get("error", "")
            if success:
                t = Text.assemble(
                    ("  ✓ Saved: ", "bold green"),
                    (path, "cyan"),
                    (f"  ({result.get('bytes', 0)} bytes)", "dim"),
                )
            else:
                t = Text(f"  ✗ Error: {err}", style="bold red")
            self.console.print(Panel(t, title="[bold green] ◀ Result [/bold green]",
                                     title_align="left", border_style="green",
                                     box=box.SIMPLE_HEAD, padding=(0, 1)))

        elif name == "read_file":
            content_str = result.get("content", "")
            err = result.get("error", "")
            if err:
                body = Text(f"  ✗ {err}", style="bold red")
            else:
                body = Text(content_str[:4000], style="white")
            self.console.print(Panel(body, title="[bold green] ◀ Result [/bold green]",
                                     title_align="left", border_style="green",
                                     box=box.SIMPLE_HEAD, padding=(0, 1)))
        else:
            display = json.dumps(result, indent=2)
            if len(display) > 3000:
                display = display[:3000] + "\n... (truncated)"
            self.console.print(Panel(
                Syntax(display, "json", theme="monokai", word_wrap=True, background_color="default"),
                title="[bold green] ◀ Result [/bold green]",
                title_align="left", border_style="green",
                box=box.SIMPLE_HEAD, padding=(0, 1)))

    def _render_python_result(self, result: dict):
        stdout    = result.get("stdout", "").strip()
        stderr    = result.get("stderr", "").strip()
        exit_code = result.get("exit_code", 0)

        parts = []

        if stdout:
            rendered_lines, counts = _render_stdout(stdout)
            summary = _severity_summary(counts)
            parts.append(rendered_lines)
        else:
            counts = {}
            summary = Text("")

        # Filter out harmless urllib3/requests SSL warnings — those are expected
        # when testing targets with self-signed or expired certs (verify=False).
        _NOISE_PATTERNS = (
            "InsecureRequestWarning",
            "urllib3/connectionpool",
            "Adding certificate verification",
            "warnings.warn(",
            "urllib3.readthedocs.io",
            "SubjectAltNameWarning",
            "NotOpenSSLWarning",
        )
        if stderr:
            real_lines = [
                ln for ln in stderr.split("\n")
                if ln.strip() and not any(p in ln for p in _NOISE_PATTERNS)
            ]
            if real_lines:
                parts.append(Text(""))
                parts.append(Text("  ── stderr ──────────────────────────────", style="dim red"))
                for line in real_lines:
                    if "Error" in line or "Traceback" in line:
                        parts.append(Text(f"  {line}", style="bold red"))
                    else:
                        parts.append(Text(f"  {line}", style="red"))

        if not stdout and not stderr:
            parts.append(Text("  (no output)", style="dim"))

        # Exit code pill
        exit_style = "bold green" if exit_code == 0 else "bold red"
        exit_label = f"exit {exit_code}"
        parts.append(Text(""))
        parts.append(Text(f"  {exit_label}", style=exit_style))

        # Build title with severity summary
        title = Text(" ◀ Output ", style="bold green")
        title.append_text(summary)

        self.console.print(Panel(
            Group(*parts),
            title=title,
            title_align="left",
            border_style="green",
            box=box.SIMPLE_HEAD,
            padding=(0, 1),
        ))

    def _render_bash_result(self, result: dict):
        stdout    = result.get("stdout", "").strip()
        stderr    = result.get("stderr", "").strip()
        exit_code = result.get("exit_code", 0)

        parts = []
        if stdout:
            parts.append(Text(stdout, style="bright_white"))
        if stderr:
            parts.append(Text(stderr, style="dim red"))
        if not stdout and not stderr:
            parts.append(Text("(no output)", style="dim"))

        exit_style = "bold green" if exit_code == 0 else "bold red"
        parts.append(Text(f"\n  exit {exit_code}", style=exit_style))

        self.console.print(Panel(
            Group(*parts),
            title="[bold green] ◀ Output [/bold green]",
            title_align="left",
            border_style="green",
            box=box.SIMPLE_HEAD,
            padding=(0, 1),
        ))

    def _render_web_result(self, result: dict):
        error = result.get("error")
        if error:
            self.console.print(Panel(
                Text(f"  ✗ {error}", style="bold red"),
                title="[bold red] ◀ Error [/bold red]",
                title_align="left", border_style="red",
                box=box.SIMPLE_HEAD, padding=(0, 1),
            ))
            return

        status     = result.get("status_code", "?")
        url        = result.get("url", "")
        hdrs       = result.get("headers", {})
        cookies_d  = result.get("cookies", {})
        body       = result.get("body", "")
        redirects  = result.get("redirect_history", [])

        # Status color
        if isinstance(status, int):
            if status < 300:   sc = "bold bright_green"
            elif status < 400: sc = "bold yellow"
            elif status < 500: sc = "bold red"
            else:              sc = "bold bright_red"
        else:
            sc = "white"

        t = Text()
        t.append(f"  {status} ", style=sc)
        t.append(f"  {url}\n", style="bold cyan")

        if redirects:
            t.append("  Redirected via: ", style="dim")
            t.append(" → ".join(redirects) + "\n", style="yellow")

        # Security headers table
        sec_headers = {
            "Content-Security-Policy":   ("CSP",          "HIGH"),
            "Strict-Transport-Security": ("HSTS",         "HIGH"),
            "X-Frame-Options":           ("X-Frame",      "MEDIUM"),
            "X-Content-Type-Options":    ("X-CTO",        "MEDIUM"),
            "Referrer-Policy":           ("Referrer",     "LOW"),
            "Permissions-Policy":        ("Permissions",  "LOW"),
        }
        info_headers = ["Server", "X-Powered-By", "Content-Type", "Set-Cookie"]

        t.append("\n  Security Headers:\n", style="dim white")
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        for header, (short, missing_sev) in sec_headers.items():
            val = hdrs_lower.get(header.lower())
            if val:
                t.append(f"    ✓ {short:<12} ", style="green")
                t.append(f"{val[:60]}\n", style="dim white")
            else:
                sev_style = "bold red" if missing_sev == "HIGH" else "bold yellow"
                t.append(f"    ✗ {short:<12} ", style=sev_style)
                t.append(f"[{missing_sev}] MISSING\n", style=sev_style)

        t.append("\n  Other Headers:\n", style="dim white")
        for h in info_headers:
            val = hdrs_lower.get(h.lower())
            if val:
                t.append(f"    {h}: ", style="dim")
                t.append(f"{val[:80]}\n", style="white")

        if cookies_d:
            t.append("\n  Cookies:\n", style="dim white")
            for name, value in cookies_d.items():
                t.append(f"    {name}=", style="cyan")
                t.append(f"{str(value)[:60]}\n", style="dim white")

        # Body preview
        if body:
            preview = body[:600].strip()
            t.append("\n  Body Preview:\n", style="dim white")
            t.append(f"  {preview}\n", style="dim white")

        self.console.print(Panel(
            t,
            title="[bold green] ◀ Response [/bold green]",
            title_align="left",
            border_style="green",
            box=box.SIMPLE_HEAD,
            padding=(0, 1),
        ))

    def print_status(self, message: str):
        if message and message not in ("Ready", ""):
            line = f"  ● {message}"
            self.console.print(f"[dim]{line:<80}[/dim]", end="\r", highlight=False)
        else:
            self.console.print(f"{'':80}", end="\r", highlight=False)

    def prompt_user(self) -> str:
        """
        Read a line of input.
        Arrow keys ←/→ move cursor, ↑/↓ scroll history, Ctrl+R searches history.
        All history is saved to ~/.pentest_console_history between sessions.

        Uses plain input() with ANSI codes wrapped in \\x01..\\x02 so readline
        correctly tracks cursor position — fixes arrow-key garbling with Rich.
        """
        self.console.print()
        try:
            # \x01..\x02 marks zero-width chars for readline cursor accounting
            prompt = "\x01\033[1;36m\x02>\x01\033[0m\x02 "
            line = input(prompt).strip()
            return line
        except (EOFError, KeyboardInterrupt):
            return "/quit"

    def confirm_quit(self) -> bool:
        try:
            prompt = "\n  \x01\033[33m\x02Quit? (y/N):\x01\033[0m\x02 "
            answer = input(prompt).strip().lower()
            return answer == "y"
        except (EOFError, KeyboardInterrupt):
            return True

    # ── Metasploit-style options table ────────────────────────────────────────

    _OPT_META = {
        "TARGET":   ("YES", "Target URL or domain"),
        "MODEL":    ("YES", "Ollama model"),
        "USERNAME": ("no",  "Login username"),
        "PASSWORD": ("no",  "Login password"),
        "COOKIE":   ("no",  "Session cookie (bypasses login — use for 2FA apps)"),
        "SCOPE":    ("no",  "In-scope hosts (comma-sep)"),
        "MODE":     ("no",  "webapp | osint | full"),
        "TOR":      ("no",  "Route HTTP through Tor (on | off)"),
        "HEADERS":  ("no",  "Custom headers for all requests (e.g. X-Bug-Bounty: HackerOne-user)"),
    }

    def print_options_table(self, options: dict):
        """Render a Metasploit-style options panel."""
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            padding=(0, 1),
        )
        table.add_column("Option",      style="bold yellow",   min_width=10)
        table.add_column("Value",       min_width=36)
        table.add_column("Required",    min_width=8)
        table.add_column("Description", style="dim")

        for key, value in options.items():
            req, desc = self._OPT_META.get(key, ("no", ""))
            if value:
                val_text = Text(str(value), style="bright_white")
            else:
                val_text = Text("(not set)", style="dim")
            req_text = (
                Text("YES", style="bold red")
                if req == "YES" and not value
                else Text(req, style="dim green" if value else "dim")
            )
            table.add_row(key, val_text, req_text, desc)

        self.console.print()
        self.console.print(Panel(
            table,
            title="[bold red] TheRobin [/bold red][dim]— session options[/dim]",
            title_align="left",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 1),
        ))
        self.console.print(
            "  [dim]Commands:[/dim]  "
            "[bold cyan]set[/bold cyan] [yellow]<OPTION>[/yellow] [white]<value>[/white]   "
            "[bold cyan]options[/bold cyan]   "
            "[bold cyan]run[/bold cyan]   "
            "[bold cyan]help[/bold cyan]   "
            "[bold cyan]quit[/bold cyan]"
        )
        self.console.print()

    def prompt_setup(self) -> str:
        """Input prompt for the setup / options phase."""
        try:
            prompt = "\x01\033[1;31m\x02therobin\x01\033[0m\x02\x01\033[2;37m\x02 ❯\x01\033[0m\x02 "
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return "quit"
