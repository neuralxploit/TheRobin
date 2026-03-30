═══════════════════════════════════════════════════════
  STARTING A TEST
═══════════════════════════════════════════════════════
When given a target:

1. **Phase Selection (MANDATORY)**:
   Display the full numbered phase list and ask the user which phases to run.
   Format your output EXACTLY like this so the user can reply with numbers:

   ```
   Target initialized: [TARGET]

   Select phases to run (reply with numbers, ranges, or keywords):
     Examples: "all"  |  "1-10"  |  "1,3,6,8"  |  "1-5,12,21"  |  "autonomous"

    1  Recon & Unauthenticated Crawl
    2  Security Headers
    3  Authentication
    4  JS Secret Scanning
    5  Session Management
    6  XSS: Reflected + Stored
    7  XSS: DOM-Based
    8  SQL Injection
    9  NoSQL Injection
   10  CSRF
   11  Technology Fingerprinting & CVE
   12  CORS, Open Redirect, SSL/TLS
   13  Deep JWT Testing
   14  Command Injection
   15  SSTI
   16  SSRF
   17  Deserialization
   18  File Upload
   19  GraphQL
   20  HTTP Protocol & Header Attacks
   21  IDOR / Access Control
   22  Business Logic Flaws
   23  XXE & Path Traversal
   24  API Security & Info Disclosure
   25  Race Conditions
   26  Sensitive Files & Directories
   27  Account Security & Enumeration
   28  Error Handling & Info Disclosure
   29  WebSocket Security
   30  OAuth / SSO Abuse
   31  Mass Assignment, HPP & Prototype Pollution
   32  Cache Poisoning & Request Smuggling
   33  Final Report (always included)

   > Your selection:
   ```

   **Parse the user's reply:**
   - `all` or `autonomous` → run all phases 1-29 without stopping
   - `1-10` → run phases 1 through 10
   - `1,3,8` → run only those specific phases
   - `1-5,12,21` → mix of ranges and individual numbers
   - If the user provides a pre-selected list via `--phases "1,3,5-10"` flag, skip the prompt and use that list directly.

   Store the selected phase list before starting:
   ```python
   _G['SELECTED_PHASES'] = [1, 3, 5, 6, 7, 8]  # example — actual numbers from user input
   _G['AUTONOMOUS'] = False  # True if user chose "all" or "autonomous"
   ```

   **During execution:** Only run phases in `_G['SELECTED_PHASES']`. Skip any phase not in the list (mark it `[-]` in plan.md). Phase 29 (report) always runs at the end.

2. Confirm target URL and PRIMARY credentials only.
   A second account for IDOR will be requested in Phase 17.

   Store primary credentials in _G:
     _G['creds_a'] = {'username': '<USER_A>', 'password': '<PASS_A>'}
     _G['creds_b'] = None  # will be set in Phase 17

2. Write your test plan to plan.md using write_file — this is MANDATORY:
   ```
   # Penetration Test Plan
   Target: <URL>
   Started: <use today's real date from system prompt>

   ## Progress
   - [ ] Phase 1  — Recon & Unauthenticated Crawl
   - [ ] Phase 2  — Security Headers
   - [ ] Phase 3  — Authentication
   - [ ] Phase 4  — JS Secret Scanning
   - [ ] Phase 5  — Session Management
   - [ ] Phase 6  — XSS: Reflected + Stored — ALL forms, ALL params
   - [ ] Phase 7  — XSS: DOM-Based
   - [ ] Phase 8  — SQL Injection — ALL forms, ALL params
   - [ ] Phase 9  — NoSQL Injection
   - [ ] Phase 10 — CSRF — ALL POST forms
   - [ ] Phase 11 — Technology Fingerprinting & CVE
   - [ ] Phase 12 — CORS, Open Redirect, SSL/TLS
   - [ ] Phase 13 — Deep JWT Testing
   - [ ] Phase 14 — Command Injection — ALL forms
   - [ ] Phase 15 — SSTI — ALL text inputs
   - [ ] Phase 16 — SSRF — ALL URL-accepting params
   - [ ] Phase 17 — Deserialization
   - [ ] Phase 18 — File Upload
   - [ ] Phase 19 — GraphQL
   - [ ] Phase 20 — HTTP Protocol & Header Attacks
   - [ ] Phase 21 — IDOR / Access Control
   - [ ] Phase 22 — Business Logic Flaws
   - [ ] Phase 23 — XXE & Path Traversal
   - [ ] Phase 24 — API Security
   - [ ] Phase 25 — Race Conditions
   - [ ] Phase 26 — Sensitive Files & Directories
   - [ ] Phase 27 — Account Security & Enumeration
   - [ ] Phase 28 — Error Handling & Info Disclosure
   - [ ] Phase 29 — WebSocket Security
   - [ ] Phase 30 — OAuth / SSO Abuse
   - [ ] Phase 31 — Mass Assignment, HPP & Prototype Pollution
   - [ ] Phase 32 — Cache Poisoning & Request Smuggling
   - [ ] Phase 33 — Final Report

   ## Findings
   (updated as vulnerabilities are confirmed)
   ```

   After completing each phase, UPDATE plan.md:
     - Mark completed phases: `- [x] Phase N — ...`
     - Mark phases with vulns: `- [!] Phase N — ...  (found: SQLi, XSS)`
     - Add confirmed findings to the ## Findings section
   This file is your recovery checkpoint — after context compaction you MUST
   read plan.md first to know exactly where you left off.

3. Initialize the global request tracker (prevents duplicate testing across phases):
   ```python
   _G['_TESTED'] = {}  # tracks (endpoint, field, test_type) → already tested
   ```

  4. Start Phase 1 immediately — fetch the homepage

## Context Compaction & State Restoration

When the conversation gets too long and you're told to compact:

1. **Call `compact_state()` with a detailed summary**
   - This saves BOTH:
     - `pentest_memory.md` = your written summary (for reference)
     - `.pentest_state.json` = ALL _G data including FINDINGS, ALL_LINKS, etc. (complete state)

2. **IMPORTANT: .pentest_state.json is authoritative**
   - The JSON file contains EVERYTHING in _G (automatically saved after every run_python call)
   - The summary can be incomplete, but the JSON is ALWAYS complete
   - When continuing, LOAD FROM THE JSON, not just the summary

3. **To continue after compaction:**
   - Call `restore_state_from_json()` — this loads the complete .pentest_state.json
   - Then read `plan.md` to see which phases are completed
   - Continue from the next unchecked phase

4. **State is automatically saved:**
   - Every `run_python()` call automatically saves .pentest_state.json
   - You don't need to worry about losing data between phases
   - The JSON file is the only thing that matters for continuation
  """
