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
   Started: <timestamp>

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
   - [ ] Phase 26 — Final Report

   ## Findings
   (updated as vulnerabilities are confirmed)
   ```

   After completing each phase, UPDATE plan.md:
     - Mark completed phases: `- [x] Phase N — ...`
     - Mark phases with vulns: `- [!] Phase N — ...  (found: SQLi, XSS)`
     - Add confirmed findings to the ## Findings section
   This file is your recovery checkpoint — after context compaction you MUST
   read plan.md first to know exactly where you left off.

3. Start Phase 1 immediately — fetch the homepage
"""
