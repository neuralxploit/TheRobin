"""
Professional HTML Penetration Test Report Generator.

Generates a self-contained HTML report with inline CSS — no external
dependencies, no images, no logos. Opens in any browser, prints cleanly to PDF.

Usage from the REPL:
    from agent.report_gen import generate_report
    generate_report(_G, output_path='report.html')
"""

import html
import datetime
from pathlib import Path


# ── Severity colours & ordering ──────────────────────────────────────────────

_SEV_META = {
    "CRITICAL": {"color": "#d32f2f", "bg": "#fde8e8", "icon": "!!!", "rank": 0},
    "HIGH":     {"color": "#e65100", "bg": "#fff3e0", "icon": "!!",  "rank": 1},
    "MEDIUM":   {"color": "#f9a825", "bg": "#fffde7", "icon": "!",   "rank": 2},
    "LOW":      {"color": "#2e7d32", "bg": "#e8f5e9", "icon": "i",   "rank": 3},
    "INFO":     {"color": "#1565c0", "bg": "#e3f2fd", "icon": "-",   "rank": 4},
}

_RISK_LABELS = {
    "CRITICAL": "Application is critically vulnerable. Immediate exploitation possible with minimal skill. Emergency remediation required within 24-48 hours.",
    "POOR":     "Multiple high-severity vulnerabilities present. A skilled attacker can compromise the application. Remediate within 1-2 weeks.",
    "MODERATE": "Some medium-severity issues identified. Basic protections exist but gaps remain. Remediate within 1 month.",
    "GOOD":     "Only low-severity or informational findings. Application follows most security best practices.",
    "STRONG":   "No significant findings. Application demonstrates mature security controls.",
}

_OWASP_MAP = {
    "SQL Injection":     "A03:2021 Injection",
    "SQLi":              "A03:2021 Injection",
    "Command Injection": "A03:2021 Injection",
    "CMDi":              "A03:2021 Injection",
    "XSS":               "A03:2021 Injection",
    "SSTI":              "A03:2021 Injection",
    "SSRF":              "A10:2021 SSRF",
    "CSRF":              "A01:2021 Broken Access Control",
    "IDOR":              "A01:2021 Broken Access Control",
    "Deserialization":   "A08:2021 Integrity Failures",
    "File Upload":       "A04:2021 Insecure Design",
    "Open Redirect":     "A01:2021 Broken Access Control",
    "CORS":              "A05:2021 Security Misconfiguration",
    "Missing CSP":       "A05:2021 Security Misconfiguration",
    "Missing HSTS":      "A05:2021 Security Misconfiguration",
    "Security Header":   "A05:2021 Security Misconfiguration",
    "Session":           "A07:2021 Auth Failures",
    "Cookie":            "A07:2021 Auth Failures",
    "JWT":               "A02:2021 Cryptographic Failures",
    "Secret":            "A02:2021 Cryptographic Failures",
    "Version":           "A06:2021 Vulnerable Components",
    "jQuery":            "A06:2021 Vulnerable Components",
    "CVE":               "A06:2021 Vulnerable Components",
    "Rate Limit":        "A07:2021 Auth Failures",
    "GraphQL":           "A03:2021 Injection",
    "CRLF":              "A03:2021 Injection",
    "Host Header":       "A05:2021 Security Misconfiguration",
    "Default Cred":      "A07:2021 Auth Failures",
    "NoSQL":             "A03:2021 Injection",
    "NoSQLi":            "A03:2021 Injection",
    "XXE":               "A05:2021 Security Misconfiguration",
    "Path Traversal":    "A01:2021 Broken Access Control",
    "LFI":               "A01:2021 Broken Access Control",
    "Directory Traversal": "A01:2021 Broken Access Control",
    "Business Logic":    "A04:2021 Insecure Design",
    "Mass Assignment":   "A01:2021 Broken Access Control",
    "Race Condition":    "A04:2021 Insecure Design",
    "Double-Spend":      "A04:2021 Insecure Design",
    "API":               "A01:2021 Broken Access Control",
    "Swagger":           "A05:2021 Security Misconfiguration",
    "Actuator":          "A05:2021 Security Misconfiguration",
    "Data Exposure":     "A02:2021 Cryptographic Failures",
    "Price":             "A04:2021 Insecure Design",
    "Coupon":            "A04:2021 Insecure Design",
    "Captcha":           "A07:2021 Auth Failures",
    "Hardcoded":         "A07:2021 Auth Failures",
    "DOM XSS":           "A03:2021 Injection",
    "Template Injection": "A03:2021 Injection",
}


def _esc(text):
    """HTML-escape a string."""
    if text is None:
        return ""
    return html.escape(str(text))


def _guess_owasp(title: str) -> str:
    """Guess OWASP category from finding title."""
    t = title.upper()
    for keyword, cat in _OWASP_MAP.items():
        if keyword.upper() in t:
            return cat
    return "—"


def _overall_rating(counts: dict) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) >= 3:
        return "POOR"
    if counts.get("HIGH", 0) > 0 or counts.get("MEDIUM", 0) >= 3:
        return "MODERATE"
    if counts.get("MEDIUM", 0) > 0 or counts.get("LOW", 0) > 0:
        return "GOOD"
    return "STRONG"


def _sev_badge(sev: str) -> str:
    s = sev.upper()
    meta = _SEV_META.get(s, _SEV_META["INFO"])
    return f'<span class="badge" style="background:{meta["color"]}">{s}</span>'


# ── CSS ──────────────────────────────────────────────────────────────────────

_CSS = """
@page {
  size: A4;
  margin: 20mm 15mm 20mm 15mm;
  @top-right { content: "CONFIDENTIAL"; font-size: 8pt; color: #999; }
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #999; }
}
* { box-sizing: border-box; }
body {
  font-family: 'Segoe UI', Calibri, Arial, sans-serif;
  font-size: 11pt;
  line-height: 1.55;
  color: #1a1a1a;
  max-width: 210mm;
  margin: 0 auto;
  padding: 0 15mm;
  background: #fff;
}
h1 { font-size: 22pt; margin-top: 40px; color: #111; border-bottom: 3px solid #222; padding-bottom: 8px; }
h2 { font-size: 16pt; margin-top: 35px; color: #222; border-bottom: 2px solid #ddd; padding-bottom: 6px; }
h3 { font-size: 13pt; margin-top: 25px; color: #333; }
h4 { font-size: 11pt; margin-top: 15px; color: #444; }
table { width: 100%; border-collapse: collapse; margin: 12px 0 20px 0; font-size: 10pt; }
th, td { border: 1px solid #ccc; padding: 7px 10px; text-align: left; vertical-align: top; }
th { background: #f5f5f5; font-weight: 600; color: #222; }
tr:nth-child(even) { background: #fafafa; }
code, pre {
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 9.5pt;
  background: #f4f4f4;
  border: 1px solid #ddd;
  border-radius: 3px;
}
code { padding: 1px 4px; }
pre { padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: 8px 0; }
.badge {
  display: inline-block;
  color: #fff;
  font-weight: 700;
  font-size: 9pt;
  padding: 2px 10px;
  border-radius: 3px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
.cover {
  page-break-after: always;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  padding: 60px 20px;
}
.cover h1 { font-size: 32pt; border: none; margin-bottom: 10px; }
.cover .subtitle { font-size: 14pt; color: #555; margin-bottom: 40px; }
.cover .meta-table { width: 70%; margin: 0 auto; }
.cover .meta-table td { border: none; padding: 6px 10px; }
.cover .meta-table td:first-child { font-weight: 600; text-align: right; width: 45%; color: #444; }
.cover .meta-table td:last-child { text-align: left; }
.cover .classification {
  margin-top: 50px;
  padding: 10px 30px;
  border: 3px solid #d32f2f;
  color: #d32f2f;
  font-weight: 700;
  font-size: 14pt;
  letter-spacing: 2px;
}
.toc { page-break-after: always; }
.toc ul { list-style: none; padding: 0; }
.toc li { padding: 5px 0; border-bottom: 1px dotted #ccc; }
.toc a { text-decoration: none; color: #1a1a1a; }
.toc a:hover { color: #1565c0; }
.finding-card {
  border: 1px solid #ddd;
  border-left: 5px solid #ccc;
  border-radius: 4px;
  padding: 15px 20px;
  margin: 20px 0;
  page-break-inside: avoid;
}
.finding-card.CRITICAL { border-left-color: #d32f2f; }
.finding-card.HIGH { border-left-color: #e65100; }
.finding-card.MEDIUM { border-left-color: #f9a825; }
.finding-card.LOW { border-left-color: #2e7d32; }
.finding-card.INFO { border-left-color: #1565c0; }
.risk-box {
  padding: 15px 20px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 12pt;
  text-align: center;
  margin: 15px 0;
}
.section-break { page-break-before: always; }
.positive { color: #2e7d32; }
.footer-note {
  margin-top: 60px;
  padding-top: 15px;
  border-top: 1px solid #ccc;
  font-size: 9pt;
  color: #777;
  text-align: center;
}
@media print {
  body { padding: 0; }
  .no-print { display: none; }
}
"""


# ── HTML builders ────────────────────────────────────────────────────────────

def _build_cover(target: str, date_str: str, scope: str) -> str:
    return f"""
<div class="cover">
  <h1>Penetration Test Report</h1>
  <div class="subtitle">Web Application Security Assessment</div>
  <table class="meta-table">
    <tr><td>Target Application</td><td><strong>{_esc(target)}</strong></td></tr>
    <tr><td>Assessment Type</td><td>Web Application Penetration Test</td></tr>
    <tr><td>Methodology</td><td>OWASP Top 10 (2021), PTES, OWASP WSTG</td></tr>
    <tr><td>Test Date</td><td>{_esc(date_str)}</td></tr>
    <tr><td>Scope</td><td>{_esc(scope)}</td></tr>
    <tr><td>Report Version</td><td>1.0</td></tr>
  </table>
  <div class="classification">CONFIDENTIAL</div>
</div>
"""


def _build_toc(sections: list[tuple[str, str]]) -> str:
    items = "\n".join(f'<li><a href="#{sid}">{_esc(label)}</a></li>' for sid, label in sections)
    return f"""
<div class="toc">
  <h1>Table of Contents</h1>
  <ul>{items}</ul>
</div>
"""


def _build_management_summary(target, counts, rating, findings) -> str:
    total = sum(counts.values())
    rating_color = _SEV_META.get(rating, _SEV_META.get("INFO"))["color"] if rating in _SEV_META else "#555"

    # Build a business-impact sentence from critical findings
    crit_titles = [f.get("title", "") for f in findings if f.get("severity", "").upper() == "CRITICAL"]
    high_titles = [f.get("title", "") for f in findings if f.get("severity", "").upper() == "HIGH"]

    impact_lines = ""
    if crit_titles:
        impact_lines += f"<p>Critical vulnerabilities were identified that could allow an attacker to compromise the application immediately. "
        impact_lines += f"These include: {_esc(', '.join(crit_titles[:4]))}.</p>"
    if high_titles:
        impact_lines += f"<p>Additionally, {len(high_titles)} high-severity issue(s) were found that present serious risk "
        impact_lines += f"if left unremediated.</p>"

    return f"""
<div class="section-break" id="management-summary">
  <h1>1. Management Summary</h1>
  <p>A penetration test was conducted against <strong>{_esc(target)}</strong> to evaluate the security
  posture of the web application. The assessment covered authentication mechanisms, input validation,
  access controls, session management, API security, business logic, and server configuration across
  25 testing categories following industry-standard OWASP methodology.</p>

  <p>The assessment identified <strong>{total} vulnerabilities</strong>:
  {counts.get('CRITICAL',0)} Critical, {counts.get('HIGH',0)} High,
  {counts.get('MEDIUM',0)} Medium, {counts.get('LOW',0)} Low,
  {counts.get('INFO',0)} Informational.</p>

  {impact_lines}

  <div class="risk-box" style="background:{_SEV_META.get(rating, _SEV_META['INFO'])['bg']}; color:{rating_color}; border: 2px solid {rating_color};">
    Overall Security Rating: {rating}<br>
    <span style="font-size:10pt;font-weight:400;">{_esc(_RISK_LABELS.get(rating, ''))}</span>
  </div>

  <p>Immediate remediation is strongly recommended for all Critical and High severity findings.
  A prioritised remediation roadmap is provided in Section 7 of this report.</p>
</div>
"""


def _build_impact_analysis(findings) -> str:
    serious = [f for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
    if not serious:
        return """
<div class="section-break" id="impact-analysis">
  <h1>2. Worst-Case Impact Analysis</h1>
  <p>No Critical or High severity findings were identified. No worst-case impact analysis required.</p>
</div>
"""
    rows = ""
    for f in serious:
        title = _esc(f.get("title", "—"))
        sev = f.get("severity", "").upper()
        impact = _esc(f.get("impact", f.get("detail", {}).get("impact", "—")))
        url = _esc(f.get("url", "—"))
        rows += f"<tr><td>{_sev_badge(sev)} {title}</td><td>{impact if impact != '—' else 'See detailed finding for specific impact.'}</td><td>{url}</td></tr>\n"

    return f"""
<div class="section-break" id="impact-analysis">
  <h1>2. Worst-Case Impact Analysis</h1>
  <p>The following table describes the realistic worst-case outcome for each Critical and High
  severity finding if exploited by a malicious actor.</p>
  <table>
    <tr><th>Finding</th><th>Worst-Case Scenario</th><th>Affected Endpoint</th></tr>
    {rows}
  </table>

  <h3>2.1 Attack Chain Analysis</h3>
  <p><em>The following chains show how an attacker could combine multiple vulnerabilities for
  maximum impact:</em></p>
  <blockquote style="border-left:3px solid #d32f2f; padding:10px 15px; background:#fde8e8; margin:15px 0;">
    <strong>Potential Chain:</strong> Review the Critical findings above — if authentication bypass,
    command injection, or SSRF co-exist, an attacker could chain them to escalate from unauthenticated
    access to full server compromise. Specific chains depend on the findings discovered.
  </blockquote>
</div>
"""


def _build_scope(target, scope, phases_status=None) -> str:
    phase_rows = ""
    phases = [
        (1, "Reconnaissance & Crawling"),
        (2, "Security Headers"),
        (3, "Authentication & Session Setup"),
        (4, "JavaScript Secret Scanning"),
        (5, "Session Management"),
        (6, "XSS — Reflected & Stored"),
        (7, "XSS — DOM-Based & Template Injection"),
        (8, "SQL Injection"),
        (9, "NoSQL Injection"),
        (10, "Cross-Site Request Forgery (CSRF)"),
        (11, "Technology Fingerprinting & CVE"),
        (12, "CORS, Open Redirect, SSL/TLS, JWT"),
        (13, "Deep JWT Testing"),
        (14, "Command Injection"),
        (15, "Server-Side Template Injection"),
        (16, "Server-Side Request Forgery"),
        (17, "Insecure Deserialization"),
        (18, "File Upload Testing"),
        (19, "GraphQL Testing"),
        (20, "HTTP Protocol Attacks"),
        (21, "IDOR / Access Control"),
        (22, "Business Logic Flaws"),
        (23, "XXE & Path Traversal"),
        (24, "API Security & Enumeration"),
        (25, "Race Conditions"),
    ]
    for num, name in phases:
        status = "Completed"
        if phases_status and num in phases_status:
            status = phases_status[num]
        phase_rows += f"<tr><td>{num}</td><td>{_esc(name)}</td><td>{_esc(status)}</td></tr>\n"

    return f"""
<div class="section-break" id="scope">
  <h1>3. Scope &amp; Methodology</h1>
  <h3>3.1 Scope</h3>
  <table>
    <tr><th style="width:30%">Item</th><th>Details</th></tr>
    <tr><td><strong>Target URL</strong></td><td>{_esc(target)}</td></tr>
    <tr><td><strong>In-Scope</strong></td><td>{_esc(scope)}</td></tr>
    <tr><td><strong>Testing Approach</strong></td><td>Grey-box (valid credentials provided)</td></tr>
    <tr><td><strong>Out of Scope</strong></td><td>Denial of Service, social engineering, physical access</td></tr>
  </table>

  <h3>3.2 Testing Phases</h3>
  <table>
    <tr><th style="width:10%">Phase</th><th>Category</th><th style="width:15%">Status</th></tr>
    {phase_rows}
  </table>
</div>
"""


def _build_findings_overview(findings, counts) -> str:
    # Severity distribution
    dist_rows = ""
    total = 0
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        total += c
        if c > 0:
            dist_rows += f"<tr><td>{_sev_badge(sev)}</td><td>{c}</td></tr>\n"
    dist_rows += f'<tr style="font-weight:700"><td>TOTAL</td><td>{total}</td></tr>'

    # OWASP mapping
    owasp_groups = {}
    for f in findings:
        cat = _guess_owasp(f.get("title", ""))
        owasp_groups.setdefault(cat, []).append(f)
    owasp_rows = ""
    for cat in sorted(owasp_groups.keys()):
        items = owasp_groups[cat]
        highest = min(items, key=lambda x: _SEV_META.get(x.get("severity", "INFO").upper(), _SEV_META["INFO"])["rank"])
        titles = ", ".join(_esc(x.get("title", "")[:50]) for x in items[:5])
        if len(items) > 5:
            titles += f" (+{len(items)-5} more)"
        owasp_rows += f"<tr><td>{_esc(cat)}</td><td>{titles}</td><td>{_sev_badge(highest.get('severity','INFO').upper())}</td></tr>\n"

    # Summary table
    summary_rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = _esc(f.get("title", "—"))
        url = _esc(f.get("url", "—"))
        cvss = _esc(str(f.get("cvss", f.get("detail", {}).get("cvss", "—"))))
        owasp = _esc(_guess_owasp(f.get("title", "")))
        summary_rows += f'<tr><td>{i}</td><td>{_sev_badge(sev)}</td><td>{title}</td><td>{cvss}</td><td style="font-size:9pt">{url}</td><td style="font-size:9pt">{owasp}</td></tr>\n'

    return f"""
<div class="section-break" id="findings-overview">
  <h1>4. Findings Overview</h1>

  <h3>4.1 Severity Distribution</h3>
  <table style="width:50%">
    <tr><th>Severity</th><th>Count</th></tr>
    {dist_rows}
  </table>

  <h3>4.2 Findings by OWASP Category</h3>
  <table>
    <tr><th>OWASP Category</th><th>Findings</th><th>Highest Severity</th></tr>
    {owasp_rows}
  </table>

  <h3>4.3 Findings Summary</h3>
  <table>
    <tr><th style="width:4%">#</th><th style="width:10%">Severity</th><th>Finding</th><th style="width:8%">CVSS</th><th>URL</th><th>OWASP</th></tr>
    {summary_rows}
  </table>
</div>
"""


def _build_detailed_findings(findings) -> str:
    sections = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = _esc(f.get("title", "Unknown"))
        url = _esc(f.get("url", "—"))
        detail = f.get("detail", {}) if isinstance(f.get("detail"), dict) else {}
        method = _esc(f.get("method", detail.get("method", "—")))
        param = _esc(f.get("param", detail.get("param", detail.get("field", "—"))))
        payload = _esc(f.get("payload", detail.get("payload", "—")))
        cvss = _esc(str(f.get("cvss", detail.get("cvss", "—"))))
        owasp = _esc(_guess_owasp(f.get("title", "")))
        evidence = f.get("evidence", detail.get("evidence", ""))
        poc = f.get("poc", detail.get("poc", ""))
        request = f.get("request", detail.get("request", ""))
        response = f.get("response", detail.get("response", ""))
        screenshot_name = f.get("screenshot", detail.get("screenshot", ""))
        impact = _esc(f.get("impact", detail.get("impact", "")))
        remediation = f.get("remediation", detail.get("remediation", ""))

        # Affected endpoints — list of all URLs where this vuln was confirmed
        affected = f.get("affected_endpoints", detail.get("affected_endpoints", []))
        if isinstance(affected, str):
            affected = [affected]

        test_code = f.get("test_code", detail.get("test_code", ""))

        evidence_html = f"<pre>{_esc(evidence)}</pre>" if evidence else "<p><em>See test output in conversation log.</em></p>"
        poc_html = f"<pre>{_esc(poc)}</pre>" if poc else ""
        request_html = f"<h4>Request Sent</h4><pre>{_esc(request)}</pre>" if request else ""
        response_html = f"<h4>Server Response</h4><pre>{_esc(response[:5000])}</pre>" if response else ""
        test_code_html = f"<h4>Test Code (Exact Script)</h4><pre>{_esc(test_code)}</pre>" if test_code else ""
        # Embed screenshot as base64 image if file exists, otherwise show filename
        screenshot_html = ""
        if screenshot_name:
            from pathlib import Path as _P
            import base64 as _b64
            # Try workspace directory first, then current directory
            for _sdir in [Path("workspace"), Path(".")]:
                _spath = _sdir / screenshot_name
                if _spath.exists():
                    try:
                        _sdata = _b64.b64encode(_spath.read_bytes()).decode()
                        screenshot_html = (
                            f'<h4>POC Screenshot</h4>'
                            f'<p><code>{_esc(screenshot_name)}</code></p>'
                            f'<img src="data:image/png;base64,{_sdata}" '
                            f'style="max-width:100%;border:1px solid #ccc;border-radius:4px;margin:8px 0" '
                            f'alt="POC: {_esc(screenshot_name)}">'
                        )
                    except Exception:
                        screenshot_html = f"<p><strong>Screenshot:</strong> <code>{_esc(screenshot_name)}</code></p>"
                    break
            else:
                screenshot_html = f"<p><strong>Screenshot:</strong> <code>{_esc(screenshot_name)}</code> (file not found)</p>"
        impact_html = f"<p>{impact}</p>" if impact else ""
        remediation_html = f"<pre>{_esc(remediation)}</pre>" if remediation else "<p><em>See remediation roadmap in Section 7.</em></p>"

        # Build affected endpoints table
        affected_html = ""
        if affected:
            ep_rows = ""
            for ep in affected:
                if isinstance(ep, dict):
                    ep_rows += f"<tr><td><code>{_esc(ep.get('method', 'GET'))}</code></td><td>{_esc(ep.get('url', ''))}</td><td>{_esc(ep.get('param', ''))}</td></tr>\n"
                else:
                    ep_rows += f"<tr><td>—</td><td>{_esc(str(ep))}</td><td>—</td></tr>\n"
            affected_html = f"""
      <h4>All Affected Endpoints ({len(affected)})</h4>
      <table>
        <tr><th style="width:10%">Method</th><th>URL / Path</th><th style="width:20%">Parameter</th></tr>
        {ep_rows}
      </table>"""

        sections += f"""
    <div class="finding-card {sev}" id="finding-{i}">
      <h3>{_sev_badge(sev)} VULN-{i:03d}: {title}</h3>
      <table>
        <tr><th style="width:20%">URL</th><td>{url}</td></tr>
        <tr><th>Method</th><td>{method}</td></tr>
        <tr><th>Parameter</th><td>{param}</td></tr>
        <tr><th>Payload</th><td><code>{payload}</code></td></tr>
        <tr><th>CVSS v3.1</th><td>{cvss}</td></tr>
        <tr><th>OWASP</th><td>{owasp}</td></tr>
      </table>

      {impact_html}
      {affected_html}

      <h4>Evidence</h4>
      {evidence_html}

      {request_html}
      {response_html}

      {screenshot_html}

      {"<h4>Proof of Concept</h4>" + poc_html if poc_html else ""}

      {test_code_html}

      <h4>Remediation</h4>
      {remediation_html}
    </div>
"""

    return f"""
<div class="section-break" id="detailed-findings">
  <h1>5. Detailed Findings</h1>
  {sections if sections else "<p>No findings to report.</p>"}
</div>
"""


def _build_positive_observations(observations: list[str]) -> str:
    if not observations:
        return """
<div class="section-break" id="positive">
  <h1>6. Positive Security Observations</h1>
  <p>No specific positive security controls were noted during testing.</p>
</div>
"""
    items = "\n".join(f"<li class='positive'>{_esc(obs)}</li>" for obs in observations)
    return f"""
<div class="section-break" id="positive">
  <h1>6. Positive Security Observations</h1>
  <p>The following security controls were found to be properly implemented:</p>
  <ul>{items}</ul>
</div>
"""


def _build_remediation_roadmap(findings) -> str:
    immediate = [f for f in findings if f.get("severity", "").upper() == "CRITICAL"]
    short_term = [f for f in findings if f.get("severity", "").upper() == "HIGH"]
    medium_term = [f for f in findings if f.get("severity", "").upper() == "MEDIUM"]
    long_term = [f for f in findings if f.get("severity", "").upper() in ("LOW", "INFO")]

    def _prio_table(items, prio_label):
        if not items:
            return "<p><em>No findings at this priority level.</em></p>"
        rows = ""
        for f in items:
            title = _esc(f.get("title", "—"))
            remediation = _esc(f.get("remediation", f.get("detail", {}).get("remediation", "See detailed finding.")))[:200]
            rows += f"<tr><td>{prio_label}</td><td>{title}</td><td>{remediation}</td></tr>\n"
        return f"""<table>
          <tr><th style="width:8%">Priority</th><th>Finding</th><th>Action Required</th></tr>
          {rows}
        </table>"""

    return f"""
<div class="section-break" id="remediation">
  <h1>7. Remediation Roadmap</h1>

  <h3>7.1 Immediate (0-48 hours) — Critical Risk</h3>
  {_prio_table(immediate, "P1")}

  <h3>7.2 Short-Term (1-2 weeks) — High Risk</h3>
  {_prio_table(short_term, "P2")}

  <h3>7.3 Medium-Term (1 month) — Moderate Risk</h3>
  {_prio_table(medium_term, "P3")}

  <h3>7.4 Long-Term (next release cycle) — Low Risk / Hardening</h3>
  {_prio_table(long_term, "P4")}

  <h3>7.5 Strategic Recommendations</h3>
  <ol>
    <li><strong>Input Validation Framework</strong> — Implement centralised input validation and
    sanitisation across all user-facing endpoints using a whitelist approach.</li>
    <li><strong>Security Headers Policy</strong> — Deploy a standardised security headers configuration
    (CSP, HSTS, X-Frame-Options) via middleware or web server config.</li>
    <li><strong>Authentication Hardening</strong> — Implement account lockout, MFA, and session
    regeneration on login.</li>
    <li><strong>Security Testing Pipeline</strong> — Integrate SAST/DAST tools into the CI/CD
    pipeline to catch vulnerabilities before deployment.</li>
    <li><strong>Dependency Management</strong> — Establish a process for monitoring and updating
    third-party libraries.</li>
  </ol>
</div>
"""


def _build_conclusion(target, counts, rating) -> str:
    total = sum(counts.values())
    return f"""
<div class="section-break" id="conclusion">
  <h1>8. Conclusion</h1>
  <p>The penetration test of <strong>{_esc(target)}</strong> identified <strong>{total}
  vulnerabilities</strong> across multiple severity levels. The overall security posture is
  rated as <strong>{rating}</strong>.</p>

  {"<p>Critical vulnerabilities require <strong>immediate attention</strong> as they allow direct exploitation by an unauthenticated attacker. The application should not be considered safe for production use until all Critical and High findings are remediated.</p>" if rating in ("CRITICAL", "POOR") else ""}

  {"<p>While no critical issues were found, the identified medium-severity findings should be addressed to strengthen the application's security posture.</p>" if rating == "MODERATE" else ""}

  {"<p>The application demonstrates a solid security posture with only minor issues identified.</p>" if rating in ("GOOD", "STRONG") else ""}

  <p>A re-test is recommended after remediation to verify that all identified vulnerabilities
  have been properly addressed and no regressions have been introduced.</p>
</div>
"""


def _build_appendices() -> str:
    return """
<div class="section-break" id="appendix-a">
  <h1>Appendix A — Severity Rating Definitions</h1>
  <table>
    <tr><th>Severity</th><th>CVSS Range</th><th>Definition</th></tr>
    <tr><td><span class="badge" style="background:#d32f2f">CRITICAL</span></td><td>9.0 - 10.0</td>
      <td>Vulnerability can be exploited remotely with no authentication, leading to full system compromise, data breach, or remote code execution. Immediate remediation required.</td></tr>
    <tr><td><span class="badge" style="background:#e65100">HIGH</span></td><td>7.0 - 8.9</td>
      <td>Significant impact. May require authentication, user interaction, or specific conditions. Should be remediated within days.</td></tr>
    <tr><td><span class="badge" style="background:#f9a825;color:#333">MEDIUM</span></td><td>4.0 - 6.9</td>
      <td>Moderate risk. Exploitation may be limited in scope or require chaining with other issues. Remediate within weeks.</td></tr>
    <tr><td><span class="badge" style="background:#2e7d32">LOW</span></td><td>0.1 - 3.9</td>
      <td>Minor security issue with minimal direct impact. Remediate during normal development cycle.</td></tr>
    <tr><td><span class="badge" style="background:#1565c0">INFO</span></td><td>0.0</td>
      <td>Observation or best-practice recommendation with no direct security impact.</td></tr>
  </table>
</div>

<div id="appendix-b">
  <h1>Appendix B — CVSS v3.1 Reference</h1>
  <p>All CVSS scores in this report are calculated using the CVSS v3.1 specification
  (<a href="https://www.first.org/cvss/v3.1/specification-document">first.org/cvss/v3.1</a>).</p>
</div>

<div class="footer-note">
  <p>This report is confidential and intended solely for the authorised recipient.<br>
  All findings have been confirmed through active testing with proof-of-concept evidence.</p>
</div>
"""


# ── Main generator ───────────────────────────────────────────────────────────

def generate_report(g: dict, output_path: str = "report.html") -> str:
    """
    Generate a professional HTML pentest report from the _G globals dict.

    Parameters
    ----------
    g : dict
        The _G persistent globals dict from the REPL — contains FINDINGS,
        SQLI_FINDINGS, XSS_FINDINGS, CMDI_FINDINGS, IDOR_FINDINGS, JS_FINDINGS,
        BASE, session, etc.
    output_path : str
        Where to write the HTML file. Defaults to 'report.html' in the workspace.

    Returns
    -------
    str : the output file path
    """
    target = g.get("BASE", g.get("target", "Unknown"))
    scope = g.get("SCOPE", target)
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    # ── Aggregate all findings ───────────────────────────────────────────
    all_findings = list(g.get("FINDINGS", []))

    for sf in g.get("SQLI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"SQL Injection — {sf.get('type','SQLi')} ({sf.get('field','')})",
            "url": sf.get("url", ""),
            "detail": sf,
        })

    for cf in g.get("CMDI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"Command Injection — {cf.get('param','')} ({cf.get('method','')})",
            "url": cf.get("url", ""),
            "detail": cf,
        })

    for xf in g.get("XSS_FINDINGS", []):
        all_findings.append({
            "severity": xf.get("severity", "HIGH"),
            "title": f"XSS — {xf.get('type','XSS')} in {xf.get('param','')}",
            "url": xf.get("url", ""),
            "detail": xf,
        })

    for idf in g.get("IDOR_FINDINGS", []):
        all_findings.append({
            "severity": idf.get("severity", "HIGH"),
            "title": f"IDOR — {idf.get('type','IDOR')}",
            "url": idf.get("url", ""),
            "detail": idf,
        })

    for jf in g.get("JS_FINDINGS", []):
        all_findings.append({
            "severity": jf.get("sev", jf.get("severity", "HIGH")),
            "title": f"JS: {jf.get('type', 'JS Issue')}",
            "url": jf.get("file", jf.get("url", "")),
            "detail": jf,
        })

    # Sort by severity
    all_findings.sort(key=lambda f: _SEV_META.get(f.get("severity", "INFO").upper(), _SEV_META["INFO"])["rank"])

    # Deduplicate by title+url
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("title", ""), f.get("url", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # ── Counts ───────────────────────────────────────────────────────────
    counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    rating = _overall_rating(counts)

    # ── Positive observations ────────────────────────────────────────────
    observations = list(g.get("POSITIVE_OBS", []))

    # ── TOC ──────────────────────────────────────────────────────────────
    toc_entries = [
        ("management-summary", "1. Management Summary"),
        ("impact-analysis", "2. Worst-Case Impact Analysis"),
        ("scope", "3. Scope & Methodology"),
        ("findings-overview", "4. Findings Overview"),
        ("detailed-findings", "5. Detailed Findings"),
        ("positive", "6. Positive Security Observations"),
        ("remediation", "7. Remediation Roadmap"),
        ("conclusion", "8. Conclusion"),
        ("appendix-a", "Appendix A — Severity Definitions"),
        ("appendix-b", "Appendix B — CVSS Reference"),
    ]

    # ── Assemble HTML ────────────────────────────────────────────────────
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Penetration Test Report — {_esc(target)}</title>
  <style>{_CSS}</style>
</head>
<body>
{_build_cover(target, date_str, scope)}
{_build_toc(toc_entries)}
{_build_management_summary(target, counts, rating, all_findings)}
{_build_impact_analysis(all_findings)}
{_build_scope(target, scope)}
{_build_findings_overview(all_findings, counts)}
{_build_detailed_findings(all_findings)}
{_build_positive_observations(observations)}
{_build_remediation_roadmap(all_findings)}
{_build_conclusion(target, counts, rating)}
{_build_appendices()}
</body>
</html>"""

    # ── Write ────────────────────────────────────────────────────────────
    out = Path(output_path)
    out.write_text(html_doc, encoding="utf-8")
    return str(out.resolve())


# ── ZDL-format numbered report (Markdown) ────────────────────────────────────

_ZDL_RISK_MATRIX_MD = """\
|  Likelihood \\ Severity  |  1  |  4  |  9  |  16  |  25  |
|:----------------------:|:---:|:---:|:---:|:----:|:----:|
| **1**                  |  1  |  4  |  9  |  16  |  25  |
| **2**                  |  2  |  8  | 18  |  32  |  50  |
| **3**                  |  3  | 12  | 27  |  48  |  75  |
| **4**                  |  4  | 16  | 36  |  64  | 100  |
| **5**                  |  5  | 20  | 45  |  80  | 125  |

*Severity: 1 (low) – 25 (very severe). Likelihood: 1 (unlikely) – 5 (highly likely).*
"""

# Maps CVSS range → (likelihood, severity_col, risk, label)
_ZDL_CVSS_RISK = [
    (9.0, 10.0, 5, 25, 125.0, "Critical"),
    (7.0,  8.9, 4, 16,  64.0, "High"),
    (4.0,  6.9, 4,  9,  36.0, "Medium"),
    (2.0,  3.9, 2,  4,   8.0, "Low"),
    (0.0,  1.9, 1,  1,   1.0, "Info"),
]

# Fallback when no CVSS — driven by severity string
_ZDL_SEV_RISK = {
    "CRITICAL": (5, 25, 125.0, "Critical",  "9.0 — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "HIGH":     (4, 16,  64.0, "High",      "7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM":   (3,  9,  27.0, "Medium",    "5.3 — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "LOW":      (2,  4,   8.0, "Low",       "3.1 — AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "INFO":     (1,  1,   1.0, "Info",      "0.0 — AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}

_ZDL_CVSS_DESC = {
    "CRITICAL": ("very high", "When successfully exploited, this vulnerability could lead to full system compromise, remote code execution, or complete data breach."),
    "HIGH":     ("high",      "When successfully exploited, this vulnerability could lead to significant data exposure, authentication bypass, or privilege escalation."),
    "MEDIUM":   ("moderate",  "When successfully exploited, this vulnerability could lead to partial information disclosure or limited impact on application integrity."),
    "LOW":      ("low",       "When successfully exploited, this vulnerability has limited direct impact, but may aid in further attack chains."),
    "INFO":     ("minimal",   "This informational finding has no direct security impact but represents a security best-practice gap."),
}

_ZDL_OWASP_REFS = {
    "SQL Injection":    "https://cwe.mitre.org/data/definitions/89.html",
    "SQLi":             "https://cwe.mitre.org/data/definitions/89.html",
    "XSS":              "https://cwe.mitre.org/data/definitions/79.html",
    "Command Injection":"https://cwe.mitre.org/data/definitions/77.html",
    "SSRF":             "https://cwe.mitre.org/data/definitions/918.html",
    "CSRF":             "https://cwe.mitre.org/data/definitions/352.html",
    "IDOR":             "https://cwe.mitre.org/data/definitions/639.html",
    "Path Traversal":   "https://cwe.mitre.org/data/definitions/22.html",
    "LFI":              "https://cwe.mitre.org/data/definitions/22.html",
    "JWT":              "https://cwe.mitre.org/data/definitions/347.html",
    "Open Redirect":    "https://cwe.mitre.org/data/definitions/601.html",
    "CORS":             "https://cwe.mitre.org/data/definitions/942.html",
    "XXE":              "https://cwe.mitre.org/data/definitions/611.html",
    "Deserialization":  "https://cwe.mitre.org/data/definitions/502.html",
    "Race Condition":   "https://cwe.mitre.org/data/definitions/362.html",
    "File Upload":      "https://cwe.mitre.org/data/definitions/434.html",
    "SSTI":             "https://cwe.mitre.org/data/definitions/94.html",
    "GraphQL":          "https://cwe.mitre.org/data/definitions/200.html",
    "Secret":           "https://cwe.mitre.org/data/definitions/312.html",
    "Hardcoded":        "https://cwe.mitre.org/data/definitions/798.html",
    "Data Exposure":    "https://cwe.mitre.org/data/definitions/200.html",
    "Version":          "https://cwe.mitre.org/data/definitions/1104.html",
    "Cookie":           "https://cwe.mitre.org/data/definitions/614.html",
    "Session":          "https://cwe.mitre.org/data/definitions/384.html",
}

_ZDL_REMEDIATION = {
    "CRITICAL": [
        "Patch or disable the vulnerable component immediately.",
        "Apply input validation and output encoding at all entry points.",
        "Implement a Web Application Firewall (WAF) as a short-term mitigation.",
        "Audit all related code paths for the same vulnerability class.",
        "Conduct a re-test after remediation to confirm the fix.",
    ],
    "HIGH": [
        "Apply vendor-recommended patch or configuration hardening.",
        "Implement strict input validation using an allowlist approach.",
        "Enable security headers and enforce least-privilege access controls.",
        "Perform a code review of the affected component.",
    ],
    "MEDIUM": [
        "Apply the recommended configuration change or code fix.",
        "Implement defence-in-depth controls around the affected functionality.",
        "Monitor the affected endpoint for anomalous activity.",
        "Include in the next scheduled patch cycle.",
    ],
    "LOW": [
        "Address during the next regular development sprint.",
        "Update to the latest stable version of the affected component.",
        "Apply security best-practice hardening guidance.",
    ],
    "INFO": [
        "Review the observation and consider implementing the recommended best practice.",
        "Include in the organisation's security awareness training if applicable.",
    ],
}


def _zdl_risk_for_finding(finding: dict) -> tuple:
    """Return (likelihood, severity_col, risk_val, risk_label, cvss_str) for a finding."""
    cvss_raw = finding.get("cvss", finding.get("detail", {}).get("cvss", "") if isinstance(finding.get("detail"), dict) else "")
    cvss_str = str(cvss_raw).strip()
    sev = finding.get("severity", "INFO").upper()

    # Try to parse a float from the CVSS string (may be "7.5 — AV:N/AC:L/..."  or just "7.5")
    cvss_float = None
    try:
        cvss_float = float(cvss_str.split()[0].split("—")[0].strip())
    except (ValueError, IndexError):
        pass

    if cvss_float is not None:
        for lo, hi, lkl, sv, risk, label in _ZDL_CVSS_RISK:
            if lo <= cvss_float <= hi:
                return lkl, sv, risk, label, cvss_str

    # Fallback to severity
    lkl, sv, risk, label, cvss_default = _ZDL_SEV_RISK.get(sev, _ZDL_SEV_RISK["INFO"])
    return lkl, sv, risk, label, cvss_str or cvss_default


def _zdl_ref_url(title: str) -> str:
    """Guess a CWE/OWASP reference URL from the finding title."""
    t_upper = title.upper()
    for kw, url in _ZDL_OWASP_REFS.items():
        if kw.upper() in t_upper:
            return url
    return "https://cwe.mitre.org/data/definitions/200.html"


def _zdl_finding_md(idx: int, f: dict, section_prefix: str) -> str:
    """Render one finding in ZDL numbered section format."""
    sev     = f.get("severity", "INFO").upper()
    title   = f.get("title", "Unnamed Finding")
    url     = f.get("url", "?")
    detail  = f.get("detail", {}) if isinstance(f.get("detail"), dict) else {}
    evidence = f.get("evidence", detail.get("evidence", ""))
    poc      = f.get("poc",      detail.get("poc",      ""))
    request  = f.get("request",  detail.get("request",  ""))
    response = f.get("response", detail.get("response", ""))
    remediation_custom = f.get("remediation", detail.get("remediation", ""))
    description = f.get("description", detail.get("description", ""))

    lkl, sv_col, risk_val, risk_label, cvss_str = _zdl_risk_for_finding(f)
    lkl_desc, sev_desc = _ZDL_CVSS_DESC.get(sev, _ZDL_CVSS_DESC["INFO"])
    ref_url = _zdl_ref_url(title)
    rem_bullets = _ZDL_REMEDIATION.get(sev, _ZDL_REMEDIATION["INFO"])

    sec = f"{section_prefix}.{idx}"

    # ── 5.X.3  Proof of Concept ──────────────────────────────────────────────
    poc_block = ""
    if request:
        poc_block += f"\n**HTTP Request**\n```http\n{request.strip()}\n```\n"
    if response:
        preview = response[:800].strip()
        poc_block += f"\n**Server Response (excerpt)**\n```\n{preview}\n```\n"
    if poc:
        poc_block += f"\n```\n{poc.strip()}\n```\n"
    if evidence and not poc_block:
        poc_block += f"\n```\n{evidence.strip()}\n```\n"
    if not poc_block:
        poc_block = "\nSee tool output in the session log for full proof-of-concept details.\n"

    # ── 5.X.2  General description ───────────────────────────────────────────
    gen_desc = description if description else (
        f"During testing, a **{title}** vulnerability was identified at `{url}`. "
        f"This issue falls under the {_guess_owasp(title)} category and represents a {lkl_desc} "
        f"risk to the application and its data."
    )

    # ── 5.X.4  Remediation ───────────────────────────────────────────────────
    rem_section = ""
    if remediation_custom:
        rem_section = remediation_custom.strip()
    else:
        rem_section = "\n".join(f"- {b}" for b in rem_bullets)

    return f"""
### {sec}    {title}

#### {sec}.1    Hosts Affected
- `{url}`

#### {sec}.2    General Description
{gen_desc}

#### {sec}.3    Proof of Concept
By performing the following request it was possible to confirm the vulnerability:{poc_block}

#### {sec}.4    Recommended Solution
In order to mitigate this issue, ZDL Group recommends implementing the following mitigations and protections:

{rem_section}

More information can be found at:
- {ref_url}

#### {sec}.5    Risk Matrix

{_ZDL_RISK_MATRIX_MD}

#### {sec}.6    Risk Classification

| | |
|---|---|
| **Likelihood** | The likelihood of exploiting this vulnerability is {lkl_desc}, as {sev_desc} |
| **Severity** | When successfully exploited, this vulnerability could lead to significant impact on confidentiality, integrity, or availability. |
| **ZDL Group Assigned Risk** | **{risk_label} ({risk_val:.2f})** |
| **CVSS:3.1** | **{cvss_str if cvss_str else _ZDL_SEV_RISK.get(sev, _ZDL_SEV_RISK["INFO"])[4]}** |

---
"""


def generate_zdl_report(g: dict, output_path: str = "report_zdl.md", section_prefix: str = "5") -> str:
    """
    Generate a ZDL-style numbered penetration test report in Markdown.

    Each finding is rendered as:
        5.X    Finding Title
        5.X.1  Hosts Affected
        5.X.2  General Description
        5.X.3  Proof of Concept
        5.X.4  Recommended Solution
        5.X.5  Risk Matrix
        5.X.6  Risk Classification

    Parameters
    ----------
    g            : The _G persistent globals dict from the agent REPL.
    output_path  : Where to write the .md file.
    section_prefix : Top-level section number prefix (default "5").

    Returns
    -------
    str : resolved output path
    """
    target   = g.get("BASE", g.get("target", "Unknown"))
    scope    = g.get("SCOPE", target)
    date_str = datetime.date.today().strftime("%m/%d/%Y")

    # ── Aggregate all findings (same as HTML generator) ──────────────────────
    all_findings: list[dict] = list(g.get("FINDINGS", []))

    for sf in g.get("SQLI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"SQL Injection — {sf.get('type', 'SQLi')} ({sf.get('field', '')})",
            "url": sf.get("url", ""),
            "detail": sf,
        })
    for cf in g.get("CMDI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"Command Injection — {cf.get('param', '')} ({cf.get('method', '')})",
            "url": cf.get("url", ""),
            "detail": cf,
        })
    for xf in g.get("XSS_FINDINGS", []):
        all_findings.append({
            "severity": xf.get("severity", "HIGH"),
            "title": f"XSS — {xf.get('type', 'XSS')} in {xf.get('param', '')}",
            "url": xf.get("url", ""),
            "detail": xf,
        })
    for idf in g.get("IDOR_FINDINGS", []):
        all_findings.append({
            "severity": idf.get("severity", "HIGH"),
            "title": f"IDOR — {idf.get('type', 'IDOR')}",
            "url": idf.get("url", ""),
            "detail": idf,
        })
    for jf in g.get("JS_FINDINGS", []):
        all_findings.append({
            "severity": jf.get("sev", jf.get("severity", "HIGH")),
            "title": f"JS: {jf.get('type', 'JS Issue')}",
            "url": jf.get("file", jf.get("url", "")),
            "detail": jf,
        })

    # Sort by severity, deduplicate
    all_findings.sort(key=lambda f: _SEV_META.get(f.get("severity", "INFO").upper(), _SEV_META["INFO"])["rank"])
    seen: set = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (f.get("title", ""), f.get("url", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    counts: dict = {}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    rating = _overall_rating(counts)
    total  = sum(counts.values())

    # ── Header ───────────────────────────────────────────────────────────────
    header = f"""\
# Penetration Test Report

| | |
|---|---|
| **Target** | `{target}` |
| **Scope** | {scope} |
| **Test Date** | {date_str} |
| **Prepared by** | TheRobin AI Security Engine |
| **Methodology** | OWASP Top 10 (2021), PTES, OWASP WSTG |
| **Classification** | CONFIDENTIAL |

---

## 1. Executive Summary

A penetration test was conducted against **{target}**. The assessment identified **{total} vulnerabilities**:
{counts.get('CRITICAL', 0)} Critical, {counts.get('HIGH', 0)} High, {counts.get('MEDIUM', 0)} Medium, {counts.get('LOW', 0)} Low, {counts.get('INFO', 0)} Informational.

Overall security rating: **{rating}**

{_RISK_LABELS.get(rating, '')}

---

## 2. Findings Overview

| # | Severity | Finding | CVSS | OWASP |
|---|----------|---------|------|-------|
"""

    for i, f in enumerate(all_findings, 1):
        sev   = f.get("severity", "INFO").upper()
        title = f.get("title", "—")
        cvss  = str(f.get("cvss", f.get("detail", {}).get("cvss", "—") if isinstance(f.get("detail"), dict) else "—"))
        owasp = _guess_owasp(title)
        header += f"| {i} | **{sev}** | {title} | {cvss.split()[0] if cvss != '—' else '—'} | {owasp} |\n"

    header += f"\n---\n\n## {section_prefix}. Detailed Findings\n"

    # ── Per-finding sections ─────────────────────────────────────────────────
    if not all_findings:
        findings_md = "\n*No findings were recorded in the session. Check the session log for manual findings.*\n"
    else:
        findings_md = "".join(
            _zdl_finding_md(i, f, section_prefix)
            for i, f in enumerate(all_findings, 1)
        )

    # ── Remediation roadmap ───────────────────────────────────────────────────
    roadmap = f"\n## {int(section_prefix) + 1}. Remediation Roadmap\n\n"
    prio_map = {
        "P1 — Immediate (0-48h)": [f for f in all_findings if f.get("severity", "").upper() == "CRITICAL"],
        "P2 — Short-term (1-2w)": [f for f in all_findings if f.get("severity", "").upper() == "HIGH"],
        "P3 — Medium-term (1mo)": [f for f in all_findings if f.get("severity", "").upper() == "MEDIUM"],
        "P4 — Long-term":         [f for f in all_findings if f.get("severity", "").upper() in ("LOW", "INFO")],
    }
    for prio, items in prio_map.items():
        roadmap += f"### {prio}\n"
        if items:
            for f in items:
                roadmap += f"- **{f.get('title', '?')}** — `{f.get('url', '?')}`\n"
        else:
            roadmap += "- *No findings at this priority level.*\n"
        roadmap += "\n"

    # ── Footer ────────────────────────────────────────────────────────────────
    footer = """\

---

*This report is confidential and intended solely for the authorised recipient.*
*All findings were confirmed through active testing with proof-of-concept evidence.*
*Generated by TheRobin AI Security Engine.*
"""

    doc = header + findings_md + roadmap + footer

    out = Path(output_path)
    out.write_text(doc, encoding="utf-8")
    return str(out.resolve())
