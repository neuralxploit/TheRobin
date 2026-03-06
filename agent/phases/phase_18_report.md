**Phase 18 — Final Report**

*** REPORT QUALITY GATE — READ BEFORE WRITING THE REPORT ***

QUALITY RULE 1 — REAL EVIDENCE ONLY:
  Every finding MUST include the ACTUAL server response — copy-paste from your test output.
  NEVER write descriptions of what "should" happen. Show what DID happen.

QUALITY RULE 2 — SCREENSHOT-VERIFIED:
  Every [HIGH] and [CRITICAL] finding MUST reference a screenshot file.
  If the screenshot shows a 404/error/WAF -> the finding is FALSE POSITIVE. REMOVE IT.

QUALITY RULE 3 — WORKING CURL POC WITH REAL VALUES:
  Every PoC MUST be a working command with real URLs, real cookies, real payloads.
  If any placeholder like <TARGET>, ABC123, example.com appears -> PoC is BROKEN, fix it.

QUALITY RULE 4 — ELIMINATE FALSE POSITIVES:
  "If I were a senior security reviewer, would I approve this finding?"
  A report with 3 confirmed findings > a report with 15 unverified ones.

---

All testing phases are complete. Execute the following steps immediately:

STEP 1 — Print findings summary to conversation:
```python
print("=" * 70)
print("PENTEST COMPLETE — FINDINGS SUMMARY")
print("=" * 70)

all_findings = list(_G.get('FINDINGS', []))

for sf in _G.get('SQLI_FINDINGS', []):
    all_findings.append({
        'severity': 'CRITICAL',
        'title': f"SQL Injection — {sf.get('type','SQLi')} ({sf.get('field','')})",
        'url': sf.get('url', ''),
    })
for cf in _G.get('CMDI_FINDINGS', []):
    all_findings.append({
        'severity': 'CRITICAL',
        'title': f"Command Injection — {cf.get('param','')} ({cf.get('method','')})",
        'url': cf.get('url', ''),
    })
for xf in _G.get('XSS_FINDINGS', []):
    all_findings.append({
        'severity': xf.get('severity', 'HIGH'),
        'title': f"XSS — {xf.get('type','XSS')} in {xf.get('param','')}",
        'url': xf.get('url', ''),
    })
for idf in _G.get('IDOR_FINDINGS', []):
    all_findings.append({
        'severity': idf.get('severity', 'HIGH'),
        'title': f"IDOR — {idf.get('type','IDOR')}",
        'url': idf.get('url', ''),
    })
for jf in _G.get('JS_FINDINGS', []):
    all_findings.append({
        'severity': jf.get('sev', jf.get('severity', 'HIGH')),
        'title': f"JS: {jf.get('type', 'JS Issue')}",
        'url': jf.get('file', jf.get('url', '')),
    })

if not all_findings:
    print("\n[INFO] No critical/high vulnerabilities confirmed.")
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
                print(f"  * {f.get('title', 'Unknown')} — {f.get('url', '')}")

print("\n" + "=" * 70)
```

STEP 2 — Generate the professional HTML report:
```python
from agent.report_gen import generate_report

html_path = generate_report(_G, output_path='report.html')
print(f"\n[OK] Professional HTML report saved to: {html_path}")
print("     Open in browser and print to PDF for client delivery.")
```

STEP 3 — ALSO write a Markdown version (report.md) using write_file for quick reference.
Use this structure — fill in REAL data from your findings, NOT placeholders:

```
# Penetration Test Report

**Target:** <actual URL>
**Date:** <actual date>
**Classification:** CONFIDENTIAL
**Overall Risk Rating:** <CRITICAL/POOR/MODERATE/GOOD/STRONG>

## Management Summary

<3-5 sentences for executives. What was tested, what was found (in business terms),
what is the risk, what should be done. NO technical jargon.>

## Worst-Case Impact Analysis

| Finding | Worst-Case Scenario | Business Impact |
|---------|---------------------|-----------------|
| <for each CRITICAL/HIGH finding — describe realistic attacker outcome> |

### Attack Chain

<Describe how vulnerabilities can be chained. Example:
SQLi (bypass auth) -> Admin Access -> CMDi (RCE) -> Full Server Compromise>

## Findings Summary

| # | Severity | Finding | CVSS | URL |
|---|----------|---------|------|-----|
<all findings sorted CRITICAL -> INFO>

## Detailed Findings

<For each finding use this format:>

### [SEVERITY] VULN-NNN: Finding Title

| Field | Details |
|-------|---------|
| URL | <exact url> |
| Method | GET/POST |
| Parameter | <field> |
| Payload | <exact payload> |
| CVSS v3.1 | <score> — <vector> |
| OWASP | <category> |

**Evidence:**
<actual test script + actual server response>

**Screenshot:** `<filename>.png`

**PoC:**
<working curl command with real cookies/values>

**Impact:** <specific to THIS app>
**Remediation:** <specific fix with code example>

---

## Positive Security Observations

<List what IS properly implemented — give credit where due>

## Remediation Roadmap

### Immediate (0-48h) — P1
<critical fixes>

### Short-Term (1-2 weeks) — P2
<high fixes>

### Medium-Term (1 month) — P3
<medium fixes>

### Long-Term — P4
<low/hardening>

### Strategic Recommendations
<broader security improvements relevant to findings>

## Conclusion

<overall assessment, safe for production?, re-test recommendation>
```

STEP 4 — Tell the user:
"Reports saved:
  - report.html — Professional HTML report (open in browser, print to PDF for client delivery)
  - report.md — Markdown version for quick reference

Would you like me to re-test anything, investigate further, or test additional endpoints?"

Then STOP and wait for user input.
