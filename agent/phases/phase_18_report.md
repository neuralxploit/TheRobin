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

# Deduplicate by title (phases now store directly in FINDINGS)
_seen_titles = set()
_deduped = []
for _f in all_findings:
    _key = _f.get('title', '')
    if _key not in _seen_titles:
        _seen_titles.add(_key)
        _deduped.append(_f)
all_findings = _deduped

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

STEP 2 — Generate the professional PDF report (MANDATORY — do NOT skip this):
```python
from agent.report_pdf import generate_pdf_report

# Count findings before generating
all_f = _G.get('FINDINGS', [])
print(f"\n[REPORT] Total findings in _G['FINDINGS']: {len(all_f)}")
for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
    count = sum(1 for f in all_f if f.get('severity','').upper() == sev)
    if count:
        print(f"  [{sev}] {count}")

pdf_path = generate_pdf_report(_G, output_path='report.pdf')
print(f"\n[OK] Professional PDF report saved to: {pdf_path}")
print("     Ready for client delivery.")

from agent.report_export import generate_json_report, generate_xml_report
json_path = generate_json_report(_G, output_path='report.json')
print(f"[OK] JSON report saved to: {json_path}")
xml_path = generate_xml_report(_G, output_path='report.xml')
print(f"[OK] XML report saved to: {xml_path}")
```

If _G['FINDINGS'] is empty, you FORGOT to store findings during testing.
Go back and add them before generating the report.

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

**Affected Endpoints** (list ALL paths where this vuln was confirmed):
- `POST /rest/user/login` — param: email
- `GET /rest/products/search?q=` — param: q
- `POST /api/comments` — param: comment

**Request Sent:**
```http
POST /rest/user/login HTTP/1.1
Content-Type: application/json

{"email":"' OR '1'='1' --","password":"x"}
```

**Server Response:**
```json
{"authentication":{"token":"eyJ...","bid":1}}
```

**Evidence:** <explain WHY this confirms the vulnerability>

**Screenshot:** `<filename>.png`

**PoC (working curl — NO placeholders):**
```bash
curl -s -X POST https://target.com/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --","password":"x"}'
```

**Impact:** <what an attacker can do with this — be specific>
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
  - report.pdf — Professional PDF report (ready for client delivery)
  - report.md — Markdown version for quick reference

Would you like me to re-test anything, investigate further, or test additional endpoints?"

Then STOP and wait for user input.
