═══════════════════════════════════════════════════════
  STARTING A TEST
═══════════════════════════════════════════════════════
When given a target:

  1. Confirm target URL and PRIMARY credentials only.
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
   - [ ] Phase 29 — Final Report

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
