**Phase 18 — Final Report**

*** REPORT QUALITY GATE — READ BEFORE WRITING THE REPORT ***

THIS IS THE MOST IMPORTANT SECTION. A bad report destroys credibility. Follow EVERY rule.

QUALITY RULE 1 — REAL EVIDENCE ONLY (NO VAGUE DESCRIPTIONS):
  Every finding MUST include the ACTUAL server response — copy-paste from your test output.
  NEVER write descriptions of what "should" happen. Show what DID happen.

  ✗ BAD (vague description — NEVER do this):
    ```
    Pre-login:  JSESSIONID=ABC123
    Post-login: JSESSIONID=ABC123 (same value)
    ```

  ✓ GOOD (actual server response from your test):
    ```
    $ Pre-login cookies:
    Set-Cookie: Navajo=253abd0a6f9aPAycSIZNd5E1rDOi4uDjnPf3DkIQXHlkkNaCaZ6X04ABy0; Secure; HttpOnly; SameSite=Lax
    Set-Cookie: WWW-UAT-Session=!U8E1+26EKQ6kEkdAEjmrDffKNjmgrdOsaI; Secure; HttpOnly; SameSite=Lax

    $ Post-login cookies (after authentication):
    Set-Cookie: Navajo=253abd0a6f9aPAycSIZNd5E1rDOi4uDjnPf3DkIQXHlkkNaCaZ6X04ABy0; Secure; HttpOnly; SameSite=Lax
    (Navajo cookie value unchanged — session NOT regenerated after login)
    ```

  ✗ BAD: "Content-Length differs from GET response"
  ✓ GOOD: "PUT /path → 200, body: '<html><title>Error</title>...' (same error page as GET, PUT not actually processed)"

  ✗ BAD: "The health endpoint exposes application health status"
  ✓ GOOD: "GET /actuator/health → 404, body: '<html>Page Not Found</html>' — endpoint does NOT exist, FALSE POSITIVE"
  OR: "GET /actuator/health → 200, body: '{"status":"UP","components":{"db":{"status":"UP"}}}' — CONFIRMED"

QUALITY RULE 2 — SCREENSHOT-VERIFIED (NO UNVERIFIED FINDINGS):
  Before adding ANY finding to the report, you MUST have opened the vulnerable URL
  in the browser via browser_action and taken a screenshot. If you didn't screenshot it,
  GO BACK AND DO IT NOW before writing the report.

  Every [HIGH] and [CRITICAL] finding MUST reference a screenshot file:
    **Screenshot:** `session_fixation_proof.png` — shows dashboard accessible with pre-auth session

  If the screenshot shows a 404, error page, or WAF block → the finding is FALSE POSITIVE.
  REMOVE IT from the report. Do NOT include it even as [INFO].

QUALITY RULE 3 — WORKING CURL POC WITH REAL VALUES:
  Every PoC MUST be a working command someone can copy-paste and reproduce.
  Search your PoC for these strings. If ANY appear → the PoC is BROKEN, fix it:
    <TARGET>, <COOKIE>, <TOKEN>, <VALID_TOKEN>, <SESSION>, ABC123, xyz789,
    example.com, placeholder, [INSERT], [PASTE]

  MANDATORY: Get real cookie values from your test session:
    cookie_str = '; '.join(f'{c.name}={c.value}' for c in _G['session'].cookies)
  Paste these REAL cookies into every curl -b flag.

QUALITY RULE 4 — SHOW THE SCRIPT AND OUTPUT:
  For every finding, the evidence section should show:
  1. The EXACT Python code or curl command you ran
  2. The EXACT output/response you got back
  Not a summary. Not a description. The real thing.

  ✓ GOOD evidence format:
    ```
    # Test script:
    r = session.get('https://target.com/actuator/health', verify=False)
    print(f"Status: {r.status_code}")
    print(f"Headers: {dict(r.headers)}")
    print(f"Body: {r.text[:500]}")

    # Output:
    Status: 200
    Headers: {'Content-Type': 'application/json', ...}
    Body: {"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL"}}}}
    ```

QUALITY RULE 5 — ELIMINATE FALSE POSITIVES RUTHLESSLY:
  Common false positives to catch BEFORE including in the report:
    ✗ "Session fixation" → Did you ACTUALLY compare pre-login and post-login session IDs?
      Show BOTH real values. If you can't prove they're the same → NOT a finding.
    ✗ "PUT method enabled" → Did the PUT actually DO something? A 200 response with an error
      page is NOT "PUT enabled". A 405 Method Not Allowed is correct behavior, not a finding.
    ✗ "Actuator endpoint exposed" → Did it return ACTUAL data or a 404/error page?
    ✗ "CSRF token not HttpOnly" → CSRF tokens are DESIGNED to be readable by JS.
      This is BY DESIGN for frameworks that send CSRF via XHR headers. NOT a finding unless
      combined with a confirmed XSS vulnerability.
    ✗ "TLS cert expiring" → Is it actually expiring within 30 days? 83 days is not urgent.
      Only report as [INFO] if > 30 days remaining. Only [MEDIUM] if < 30 days.
    ✗ "Server version disclosure" → Only [LOW] if the version has known CVEs. Otherwise [INFO].

  ASK YOURSELF: "If I were a senior security reviewer reading this report, would I approve
  this finding? Or would I flag it as a false positive and question the tester's credibility?"

If you cannot provide real evidence for a finding → downgrade to [INFO] or remove it entirely.
A report with 3 confirmed findings is worth MORE than a report with 15 unverified ones.
An empty report that says "no vulnerabilities found" is BETTER than a report full of false positives.

All automated testing phases are now complete. Do the following immediately — do NOT wait for user input:

STEP 1 — Print a findings summary to the conversation:
```python
print("=" * 70)
print("PENTEST COMPLETE — FINDINGS SUMMARY")
print("=" * 70)

# Aggregate findings from all phase-specific keys + central FINDINGS list
all_findings = list(_G.get('FINDINGS', []))

# SQLi findings
for sf in _G.get('SQLI_FINDINGS', []):
    all_findings.append({
        'severity': 'CRITICAL',
        'title': f"SQL Injection — {sf.get('type','SQLi')} ({sf.get('field','')})",
        'url': sf.get('url', ''),
    })

# CMDi findings
for cf in _G.get('CMDI_FINDINGS', []):
    all_findings.append({
        'severity': 'CRITICAL',
        'title': f"Command Injection — {cf.get('param','')} ({cf.get('method','')})",
        'url': cf.get('url', ''),
    })

# XSS findings
for xf in _G.get('XSS_FINDINGS', []):
    all_findings.append({
        'severity': xf.get('severity', 'HIGH'),
        'title': f"XSS — {xf.get('type','XSS')} in {xf.get('param','')}",
        'url': xf.get('url', ''),
    })

# IDOR findings
for idf in _G.get('IDOR_FINDINGS', []):
    all_findings.append({
        'severity': idf.get('severity', 'HIGH'),
        'title': f"IDOR — {idf.get('type','IDOR')}",
        'url': idf.get('url', ''),
    })

# JS findings (secrets, DOM XSS sinks, prototype pollution)
for jf in _G.get('JS_FINDINGS', []):
    all_findings.append({
        'severity': jf.get('sev', jf.get('severity', 'HIGH')),
        'title': f"JS: {jf.get('type', 'JS Issue')}",
        'url': jf.get('file', jf.get('url', '')),
    })

if not all_findings:
    print("\n[INFO] No critical/high vulnerabilities confirmed during automated testing.")
    print("       All tested phases returned expected/safe results.")
else:
    by_sev = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
    for f in all_findings:
        sev = f.get('severity', 'INFO').upper()
        by_sev.setdefault(sev, []).append(f)

    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        items = by_sev.get(sev, [])
        if items:
            print(f"\n[{sev}] — {len(items)} finding(s):")
            for f in items:
                print(f"  • {f.get('title', 'Unknown')} — {f.get('url', '')}")

print("\n" + "=" * 70)
```

STEP 2 — Write the full report to report.md using write_file. Use this structure:

```
# Penetration Test Report
**Target:** <URL>
**Date:** <date>
**Tester:** TheRobin AI Agent

## Executive Summary
<3-5 sentences: what was tested, total findings by severity, overall risk level>

## Findings Summary Table
| Severity | Finding | URL |
|----------|---------|-----|
| [CRITICAL] | ... | ... |
| [HIGH] | ... | ... |

## Detailed Findings
<one full section per finding using the FINDING TEMPLATE from Rule #4>

## Remediation Priority
<ordered list: fix these first>

## Conclusion
<overall assessment>
```

STEP 3 — After writing the report, tell the user:
"Report saved to report.md. Would you like me to re-test anything, investigate further, or test additional endpoints?"

Then STOP and wait for user input.
