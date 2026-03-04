"""
Agentic loop — drives the conversation between the user and the Ollama model.

Context management (mirrors how Anthropic/Claude Code works):
  When history grows large, the LLM is asked to write a semantic summary of
  everything found so far. That summary replaces all old messages, so the model
  continues with full understanding — not truncated garbage.

  Step 1: ask the model  "Summarize every finding from this pentest so far"
  Step 2: model returns  a structured paragraph with all findings, phases done, etc.
  Step 3: rebuild history as:
            [system prompt]
            [assistant: PENTEST MEMORY — <summary>]
            [last N recent messages]
  Step 4: model continues — it knows everything, context is clean
"""

import json
import time
from typing import Callable
from .ollama import simple_chat, stream_chat, ContextOverflowError, _estimate_tokens
from .tools import TOOL_SCHEMAS, execute_tool
from .prompts import get_system_prompt

# System prompt is ~32K tokens. Threshold must be high enough to allow
# meaningful conversation but low enough that after compaction the rebuilt
# history (system 32K + summary 1K + 4 recent ~4K = ~37K) stays under it.
# 60K gives ~28K of working conversation space before compaction fires.
_COMPACT_THRESHOLD = 60_000

# 4 messages = last 2 tool call+result pairs. Small enough that:
#   system(32K) + summary(1K) + recent(4K) = 37K < 60K threshold
# So the rebuilt history never immediately re-triggers compaction.
_KEEP_RECENT = 4

# Summary request sent to the LLM
_SUMMARY_PROMPT = """STOP — do NOT call any tools. Do NOT continue the pentest yet.

You are about to have your context window compacted, exactly like Claude Code does.
Write a PENTEST MEMORY block that captures EVERYTHING found so far so you can
continue perfectly after the old messages are dropped.

Write it in this exact format (fill in real values — do not leave placeholders):

PENTEST MEMORY
==============
Target: <BASE URL>
Phases completed: <list which phases are done>
Current phase: <which phase you are on now>

CREDENTIALS USED
  Session A: username=... password=...
  Session B: username=... password=... (or: not yet obtained)

PAGES DISCOVERED
  <list every URL found, one per line>

FORMS FOUND
  <list each form: METHOD URL fields=[...]>

JAVASCRIPT SECRETS FOUND
  <list any JS findings: [CRITICAL/HIGH] Type - file:xxx.js - match:...>
  (or: No JavaScript secrets found if scan complete and clean)

VULNERABILITIES CONFIRMED
  [CRITICAL] <name> — <URL> — <one line proof>
  [HIGH]     <name> — <URL> — <one line proof>
  [MEDIUM]   ...
  (list every confirmed finding — do not skip any)

SUBDOMAINS / TARGETS FOUND
  <list every subdomain and IP discovered — mark which are tested vs pending>

EMAIL SECURITY
  SPF:   <value or MISSING>
  DKIM:  <value or MISSING>
  DMARC: <value or MISSING>
  MX:    <mail server hostnames>

VULNERABILITIES CONFIRMED
  [CRITICAL] <name> — <URL> — <one line proof>
  [HIGH]     <name> — <URL> — <one line proof>
  [MEDIUM]   ...
  (list every confirmed finding — do not skip any)

VULNERABILITIES STILL TO TEST
  <list phases or checks not yet done — include each pending subdomain>

OBJECT IDs HARVESTED
  <list endpoint patterns and IDs found, e.g. /invoice/{1,2,3}>

PLAN FILE
  plan.md exists: <yes/no>
  Next action: <exactly what to do next after compaction>
  IMPORTANT: After compaction, call read_file("plan.md") first to restore full task list.

NOTES
  <anything else important: cookies, tokens, session state, etc.>
==============

CRITICAL INSTRUCTION AFTER COMPACTION:
After writing this memory block, you will be given the instruction to CONTINUE THE PENTEST.
1. First: read_file("plan.md") to see which phases are done
2. If plan.md phases are all still [ ], UPDATE plan.md now to mark completed phases [x] and findings
3. Then continue with the next uncompleted phase immediately
Do NOT stop. Do NOT ask the user. Do NOT wait. Just run the next phase.

Write the memory block now. Nothing else."""


def _dumb_compact(history: list[dict]) -> list[dict]:
    """
    Fallback: truncate old tool results if the LLM summary call itself fails.
    Keeps the last _KEEP_RECENT messages intact, truncates everything older.
    CRITICAL: Preserves file paths and important metadata even after compaction.
    """
    if len(history) <= _KEEP_RECENT + 1:   # +1 for system
        return history

    system   = [m for m in history if m.get("role") == "system"]
    the_rest = [m for m in history if m.get("role") != "system"]
    recent   = the_rest[-_KEEP_RECENT:]
    old      = the_rest[:-_KEEP_RECENT]

    # Fields to preserve even when truncating
    PRESERVE_FIELDS = ["saved", "source_file", "file", "path", "cwd", "workspace_dir"]

    compacted_old = []
    for m in old:
        if m.get("role") == "tool":
            content = m.get("content", "")
            try:
                data = json.loads(content)
                # Build compacted version
                compacted = {}
                # Preserve important file/metadata fields
                for field in PRESERVE_FIELDS:
                    if field in data:
                        compacted[field] = data[field]
                # Add truncated output
                tail = (data.get("stdout") or data.get("stderr") or "")[-150:]
                compacted["stdout"] = tail + "…[compacted]"
                compacted["exit_code"] = data.get("exit_code", 0)
                compacted["compacted"] = True
                short = json.dumps(compacted)
            except Exception:
                short = content[-150:] + "…[compacted]"
            compacted_old.append({**m, "content": short})
        else:
            compacted_old.append(m)

    return system + compacted_old + recent


class AgentLoop:
    def __init__(
        self,
        model: str,
        on_token: Callable,
        on_tool_call: Callable,
        on_tool_result: Callable,
        on_status: Callable,
        mode: str = "webapp",
    ):
        self.model        = model
        self._system      = get_system_prompt(mode)
        self.history      = [{"role": "system", "content": self._system}]
        self.on_token     = on_token
        self.on_tool_call = on_tool_call
        self.on_tool_result = on_tool_result
        self.on_status    = on_status

    # ── token estimate ────────────────────────────────────────────────────────

    def _tokens(self) -> int:
        return _estimate_tokens(self.history)

    # ── semantic compaction (the Anthropic way) ───────────────────────────────

    def _semantic_compact(self) -> str:
        """
        Ask the LLM to summarize everything found so far, then rebuild history
        around that summary. The model retains full understanding of the pentest.

        Key: the summary request uses a MINIMAL snapshot — no system prompt
        (28K tokens), no raw tool output — only the text conversation.
        This keeps the summary request itself well within context limits.
        """
        self.on_status("Compacting — asking model to summarize findings...")

        # Build a minimal snapshot for the summarizer:
        #   - Replace the 28K system prompt with a tiny instruction
        #   - Keep all assistant/user TEXT messages intact (findings are here)
        #   - Tool results: preserve file paths, truncate output only
        #   - If bytes > 100KB, ALWAYS truncate content (avoid massive files)
        # Fields to carry over from tool results into the mini snapshot.
        # Includes browser-specific fields (preview, count) that were missing before.
        PRESERVE_FIELDS = [
            "saved", "source_file", "file", "path", "cwd", "workspace_dir",
            "bytes", "total_count", "title", "url", "truncated",
            "preview",      # browser page preview
            "count",        # element count from find_elements
            "status_code",  # HTTP status from web_request
            "success",      # write_file / fill result
            "found",        # wait_for result
        ]

        mini = [{"role": "system",
                 "content": "You are summarizing the findings from an ongoing penetration test."}]

        for m in self.history:
            role = m.get("role", "")
            if role == "system":
                continue          # skip big system prompt
            elif role == "tool":
                content = m.get("content", "")
                try:
                    data = json.loads(content)
                    compacted = {}
                    for field in PRESERVE_FIELDS:
                        if field in data:
                            compacted[field] = data[field]
                    # Truncate preview to keep mini small
                    if "preview" in compacted:
                        compacted["preview"] = compacted["preview"][:300]
                    # Add tail of stdout/stderr (run_python / bash results)
                    tail = (data.get("stdout") or data.get("stderr") or "")[-120:]
                    if tail:
                        compacted["stdout"] = tail + "…"
                    compacted["compacted"] = True
                    short = json.dumps(compacted, separators=(',', ':'))
                except Exception:
                    short = content[-120:] + "…"
                mini.append({"role": "tool", "content": short})
            elif role == "assistant":
                # Truncate long assistant messages — the model writes verbose reasoning
                # that doesn't help summarization but bloats the mini snapshot.
                content = str(m.get("content", ""))
                if len(content) > 2000:
                    content = "[…earlier reasoning truncated…]\n" + content[-1500:]
                # Strip tool_calls from mini — implied by the tool results
                mini.append({"role": "assistant", "content": content})
            else:
                mini.append(m)   # user messages kept in full

        mini.append({"role": "user", "content": _SUMMARY_PROMPT})

        # Retry summary call up to 3 times — cloud proxy drops idle connections
        summary_text = None
        last_err = None
        for attempt in range(3):
            try:
                summary_text, _ = simple_chat(self.model, mini, tools=[])
                break
            except Exception as e:
                last_err = e
                err_lower = str(e).lower()
                retryable = any(k in err_lower for k in (
                    "unexpected eof", "connection dropped", "connection reset",
                    "503", "502", "service unavailable", "bad gateway",
                ))
                if attempt < 2 and retryable:
                    wait = 3 * (attempt + 1)
                    self.on_status(f"Summary call failed — retrying in {wait}s...")
                    import time; time.sleep(wait)
                else:
                    break

        if summary_text is None or len(summary_text or "") < 50:
            self.history = _dumb_compact(self.history)
            reason = f"({last_err})" if last_err else "(empty summary)"
            return f"Summary call failed {reason} — used dumb compaction instead."

        if not summary_text or len(summary_text) < 50:
            self.history = _dumb_compact(self.history)
            return "Empty summary — used dumb compaction instead."

        # Rebuild history:
        #   [system prompt]
        #   [assistant: PENTEST MEMORY — <summary>]   ← replaces all old messages
        #   [last _KEEP_RECENT messages verbatim]      ← immediate context
        system  = [m for m in self.history if m.get("role") == "system"]
        all_msg = [m for m in self.history if m.get("role") != "system"]
        recent  = all_msg[-_KEEP_RECENT:]

        memory_msg = {
            "role": "assistant",
            "content": (
                "PENTEST MEMORY — semantic summary of everything found so far. "
                "All previous raw tool results have been compacted.\n\n"
                + summary_text
            ),
        }

        before_tokens = self._tokens()
        self.history  = system + [memory_msg] + recent
        after_tokens  = self._tokens()

        # Safety net: if rebuild is still large, drop recent messages progressively.
        # This prevents the "compaction made things worse" case where the LLM
        # wrote a verbose summary larger than what it replaced.
        if after_tokens > _COMPACT_THRESHOLD:
            recent = all_msg[-2:]   # drop to last 1 tool call+result pair
            self.history = system + [memory_msg] + recent
            after_tokens = self._tokens()

        saved = before_tokens - after_tokens
        return (
            f"Semantic compaction done: -{saved:,} tokens saved. "
            f"Summary: {len(summary_text)} chars. "
            f"{len(self.history)} messages remain."
        )

    def compact(self) -> str:
        """Public method — called by /compact command or automatically."""
        return self._semantic_compact()

    # ── Ollama call with overflow recovery ───────────────────────────────────

    def _call_ollama(self, on_token=None) -> tuple[str, list[dict]]:
        """
        Call the model with streaming enabled so the proxy connection stays alive.
        on_token is called for each content token as it arrives (for live display).
        Retries up to 3 times on cloud drops.
        """
        for attempt in range(3):
            try:
                return stream_chat(self.model, self.history, TOOL_SCHEMAS,
                                   on_token=on_token)

            except ContextOverflowError:
                # Real context overflow — compact then retry once
                self.on_status("Context overflow — running semantic compaction...")
                info = self._semantic_compact()
                _just_compacted = True   # prevent proactive compact next iteration
                self.on_token(
                    f"\n> **Context full** — compacted via LLM summary.\n> {info}\n\n"
                )
                try:
                    return stream_chat(self.model, self.history, TOOL_SCHEMAS,
                                       on_token=on_token)
                except ContextOverflowError:
                    # Nuclear option — still too large even after semantic compact.
                    memory_msgs = [
                        m for m in self.history
                        if m.get("role") == "assistant"
                        and "PENTEST MEMORY" in str(m.get("content", ""))
                    ]
                    non_tool = []
                    for m in self.history:
                        if m.get("role") in ("system", "tool"):
                            continue
                        if m.get("role") == "assistant" and m.get("tool_calls"):
                            txt = m.get("content", "") or ""
                            if txt.strip():
                                non_tool.append({"role": "assistant", "content": txt})
                        else:
                            non_tool.append(m)

                    mini_sys = [{
                        "role": "system",
                        "content": (
                            "You are a penetration tester mid-engagement. "
                            "Context was compacted due to size. "
                            "Read plan.md with read_file if it exists, then continue testing."
                        ),
                    }]
                    self.history = mini_sys + memory_msgs + non_tool[-6:]
                    self.on_token(
                        "> **Emergency compact** — stripped tool calls + mini system prompt.\n\n"
                    )
                    return stream_chat(self.model, self.history, TOOL_SCHEMAS,
                                       on_token=on_token)

            except ConnectionError as e:
                err = str(e)
                if attempt < 2 and any(k in err.lower() for k in (
                    "cloud connection dropped", "unexpected eof",
                    "connection refused", "connection reset",
                    "503", "502", "service unavailable", "bad gateway",
                )):
                    wait = 3 * (attempt + 1)
                    self.on_status(f"Cloud unavailable — retrying in {wait}s... (attempt {attempt+1}/3)")
                    time.sleep(wait)
                    continue
                raise

    # ── main loop ─────────────────────────────────────────────────────────────

    def send(self, user_message: str):
        """Process a user message through the full agentic loop."""
        self.history.append({"role": "user", "content": user_message})

        max_iterations = 500
        iteration      = 0
        _just_compacted = False

        while iteration < max_iterations:
            iteration += 1
            tokens = self._tokens()
            self.on_status(f"Thinking...  [{iteration}]  (~{tokens:,} tokens)")

            # Proactive semantic compaction — before hitting the wall.
            # Skip if we just compacted this iteration (error recovery already ran compact).
            if tokens > _COMPACT_THRESHOLD and not _just_compacted:
                self.on_status("Context growing — compacting now...")
                info = self._semantic_compact()
                self.on_token(
                    f"\n> **Auto-compacted** (proactive): {info}\n\n"
                )
                # Nudge the model to keep running after compaction — without this
                # the model often stops and waits for user input instead of continuing.
                from agent.tools import WORKSPACE_DIR as _ws
                self.history.append({
                    "role": "user",
                    "content": (
                        "Context compacted. Your PENTEST MEMORY above has all findings and state. "
                        f"Workspace directory: {_ws}\n"
                        "STEP 1: read_file('plan.md') to check your progress.\n"
                        "STEP 2: If plan.md phases are all still [ ], UPDATE it now — mark completed "
                        "phases [x] and add findings from your PENTEST MEMORY.\n"
                        "STEP 3: Continue with the next uncompleted phase. Do NOT stop or ask."
                    ),
                })
                _just_compacted = True
            else:
                _just_compacted = False   # reset each iteration

            try:
                # Pass no on_token callback — stream silently for connection keepalive.
                # The panel-based UI displays one complete message at the end anyway.
                content, tool_calls = self._call_ollama(on_token=None)
            except ConnectionError as e:
                self.on_status("")
                err_lower = str(e).lower()
                retryable = any(k in err_lower for k in (
                    "cloud connection dropped", "unexpected eof",
                    "connection refused", "connection reset",
                    "503", "502", "service unavailable", "bad gateway",
                ))
                if retryable and iteration < max_iterations:
                    self.on_token(
                        f"\n> **Cloud connection dropped** — waiting 10s then auto-resuming...\n\n"
                    )
                    time.sleep(10)
                    # Nudge agent to continue from where it left off
                    self.history.append({
                        "role": "user",
                        "content": (
                            "Connection was temporarily lost. Continue the penetration test "
                            "exactly where you left off. Check plan.md if needed."
                        ),
                    })
                    continue
                self.on_token(f"\n**Connection error:** {e}\n")
                return
            except Exception as e:
                self.on_status("")
                self.on_token(f"\n**Unexpected error:** {e}\n")
                return

            if tool_calls:
                self.history.append({
                    "role": "assistant",
                    "content": content or "",
                    "tool_calls": tool_calls,
                })

                for tc in tool_calls:
                    fn      = tc.get("function", {})
                    name    = fn.get("name", "unknown")
                    raw_args = fn.get("arguments", {})

                    if isinstance(raw_args, str):
                        try:
                            args = json.loads(raw_args)
                        except json.JSONDecodeError:
                            args = {"code": raw_args}
                    else:
                        args = raw_args

                    self.on_status("")
                    self.on_tool_call(name, args)

                    result = execute_tool(name, args)
                    self.on_tool_result(name, result)

                    self.history.append({"role": "tool", "content": result})

                continue

            else:
                self.on_status("")
                if content:
                    # Model confused after compaction — output raw <tool_call> tags
                    if "<tool_call>" in content and not tool_calls:
                        self.on_status("Model confused after compaction — nudging...")
                        self.history.append({
                            "role": "assistant",
                            "content": "[context was compacted — continuing test]",
                        })
                        self.history.append({
                            "role": "user",
                            "content": (
                                "Context was compacted but your PENTEST MEMORY block "
                                "above has all findings. Continue the penetration test "
                                "from where you left off — run the next phase now."
                            ),
                        })
                        continue
                    self.history.append({"role": "assistant", "content": content})
                    self.on_token(content)
                self.on_status("Ready")
                return

        self.on_status("Ready")
        self.on_token("\n*[Max iterations reached.]*\n")

    def clear_history(self):
        """Reset conversation and history, keeping system prompt."""
        self.history = [{"role": "system", "content": self._system}]

    def set_model(self, model: str):
        self.model = model
