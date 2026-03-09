"""
Professional PDF Penetration Test Report Generator.

Uses ReportLab to build a styled, color-coded PDF report with cover page,
table of contents, severity badges, code blocks, and remediation roadmap.

Usage from the REPL:
    from agent.report_pdf import generate_pdf_report
    generate_pdf_report(_G, output_path='report.pdf')
"""

import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm, inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, Frame, PageTemplate,
    BaseDocTemplate, NextPageTemplate,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.colors import HexColor


# ── Severity colours ──────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": {"text": HexColor("#FFFFFF"), "bg": HexColor("#C62828"), "bar": HexColor("#C62828")},
    "HIGH":     {"text": HexColor("#FFFFFF"), "bg": HexColor("#E65100"), "bar": HexColor("#E65100")},
    "MEDIUM":   {"text": HexColor("#333333"), "bg": HexColor("#FFB300"), "bar": HexColor("#F9A825")},
    "LOW":      {"text": HexColor("#FFFFFF"), "bg": HexColor("#2E7D32"), "bar": HexColor("#2E7D32")},
    "INFO":     {"text": HexColor("#FFFFFF"), "bg": HexColor("#1565C0"), "bar": HexColor("#1565C0")},
}

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

RISK_LABELS = {
    "CRITICAL": "Application is critically vulnerable. Immediate exploitation possible. Emergency remediation required within 24-48 hours.",
    "POOR":     "Multiple high-severity vulnerabilities present. Remediate within 1-2 weeks.",
    "MODERATE": "Some medium-severity issues identified. Remediate within 1 month.",
    "GOOD":     "Only low-severity or informational findings. Application follows most security best practices.",
    "STRONG":   "No significant findings. Application demonstrates mature security controls.",
}

OWASP_MAP = {
    "SQL Injection": "A03:2021 Injection", "SQLi": "A03:2021 Injection",
    "Command Injection": "A03:2021 Injection", "CMDi": "A03:2021 Injection",
    "XSS": "A03:2021 Injection", "SSTI": "A03:2021 Injection",
    "SSRF": "A10:2021 SSRF", "CSRF": "A01:2021 Broken Access Control",
    "IDOR": "A01:2021 Broken Access Control",
    "Deserialization": "A08:2021 Integrity Failures",
    "File Upload": "A04:2021 Insecure Design",
    "Open Redirect": "A01:2021 Broken Access Control",
    "CORS": "A05:2021 Security Misconfiguration",
    "Missing CSP": "A05:2021 Security Misconfiguration",
    "Security Header": "A05:2021 Security Misconfiguration",
    "Session": "A07:2021 Auth Failures", "Cookie": "A07:2021 Auth Failures",
    "JWT": "A02:2021 Cryptographic Failures",
    "Secret": "A02:2021 Cryptographic Failures",
    "Version": "A06:2021 Vulnerable Components",
    "jQuery": "A06:2021 Vulnerable Components",
    "CVE": "A06:2021 Vulnerable Components",
    "Rate Limit": "A07:2021 Auth Failures",
    "GraphQL": "A03:2021 Injection", "CRLF": "A03:2021 Injection",
    "NoSQL": "A03:2021 Injection", "XXE": "A05:2021 Security Misconfiguration",
    "Path Traversal": "A01:2021 Broken Access Control",
    "Business Logic": "A04:2021 Insecure Design",
    "Mass Assignment": "A01:2021 Broken Access Control",
    "Race Condition": "A04:2021 Insecure Design",
    "API": "A01:2021 Broken Access Control",
    "Default Cred": "A07:2021 Auth Failures",
    "Data Exposure": "A02:2021 Cryptographic Failures",
}

# ── Mitigation templates ──────────────────────────────────────────────────────

MITIGATION_MAP = {
    "SQL Injection": {
        "desc": "The application does not properly validate or sanitize user input before incorporating it into SQL queries, allowing an attacker to manipulate database operations.",
        "steps": [
            "Use parameterized queries (prepared statements) for all database interactions.",
            "Implement an ORM (e.g., SQLAlchemy, Hibernate) instead of raw SQL queries.",
            "Apply input validation using a whitelist approach for expected data types.",
            "Implement least-privilege database accounts — the application should not use a DBA account.",
            "Deploy a Web Application Firewall (WAF) as an additional layer of defense.",
        ],
        "refs": [
            ("OWASP SQL Injection Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
        ],
    },
    "XSS": {
        "desc": "It was identified that the application does not properly encode or sanitize user-supplied input before rendering it in HTML responses, allowing injection of malicious scripts.",
        "steps": [
            "Implement context-aware output encoding for all user-supplied data (HTML, JavaScript, URL, CSS contexts).",
            "Deploy a strict Content Security Policy (CSP) header that prevents inline script execution.",
            "Use templating engines with auto-escaping enabled by default (e.g., Jinja2 with autoescape=True).",
            "Validate and sanitize all input on the server side using a whitelist approach.",
            "Set the HttpOnly flag on session cookies to prevent theft via XSS.",
        ],
        "refs": [
            ("OWASP XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ],
    },
    "Command Injection": {
        "desc": "The application passes user-controlled input directly to operating system commands without proper sanitization, allowing an attacker to execute arbitrary commands on the server.",
        "steps": [
            "Avoid calling OS commands directly — use language-native libraries instead.",
            "If OS commands are necessary, use parameterized APIs (e.g., subprocess with shell=False in Python).",
            "Implement strict input validation using a whitelist of allowed characters.",
            "Run the application with minimal OS privileges (principle of least privilege).",
            "Use sandboxing or containerization to limit the impact of command execution.",
        ],
        "refs": [
            ("OWASP Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
        ],
    },
    "CSRF": {
        "desc": "The application does not implement anti-CSRF tokens on state-changing forms, allowing an attacker to forge requests on behalf of authenticated users.",
        "steps": [
            "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing forms.",
            "Set the SameSite attribute on session cookies to 'Strict' or 'Lax'.",
            "Verify the Origin and Referer headers on state-changing requests.",
            "Require re-authentication for sensitive operations (password change, email change).",
        ],
        "refs": [
            ("OWASP CSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ],
    },
    "IDOR": {
        "desc": "The application does not enforce proper authorization checks when accessing resources by identifier, allowing users to access or modify other users' data by manipulating object references.",
        "steps": [
            "Implement server-side authorization checks for every resource access — verify the requesting user owns the resource.",
            "Use indirect object references (e.g., map internal IDs to per-session tokens).",
            "Log and monitor access patterns for anomalous behavior.",
            "Apply the principle of least privilege — users should only access their own resources.",
        ],
        "refs": [
            ("OWASP IDOR", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
        ],
    },
    "SSRF": {
        "desc": "The application accepts user-supplied URLs and fetches them server-side without proper validation, allowing an attacker to make the server send requests to internal services or cloud metadata endpoints.",
        "steps": [
            "Implement a URL allowlist — only permit requests to known, trusted external hosts.",
            "Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
            "Disable HTTP redirects when fetching user-supplied URLs.",
            "Use a dedicated HTTP proxy for outbound requests with network-level restrictions.",
            "If cloud-hosted, restrict access to the metadata service (169.254.169.254).",
        ],
        "refs": [
            ("OWASP SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ],
    },
    "SSTI": {
        "desc": "The application passes user input directly into server-side template rendering functions, allowing an attacker to inject template directives and achieve remote code execution.",
        "steps": [
            "Never pass user input directly to template rendering functions (e.g., render_template_string).",
            "Use template engines with sandboxed execution environments.",
            "Implement strict input validation — reject template syntax characters ({{ }}, <% %>, etc.).",
            "Use logic-less templates where possible.",
        ],
        "refs": [
            ("PortSwigger SSTI", "https://portswigger.net/web-security/server-side-template-injection"),
        ],
    },
    "Deserialization": {
        "desc": "The application deserializes untrusted data without validation, allowing an attacker to craft malicious serialized objects that execute arbitrary code upon deserialization.",
        "steps": [
            "Never deserialize data from untrusted sources.",
            "If deserialization is required, use safe formats (JSON) instead of native serialization (pickle, Java serialization).",
            "Implement integrity checks (HMAC) on serialized data before deserialization.",
            "Run deserialization in a sandboxed environment with minimal privileges.",
            "Use allowlists for permitted classes during deserialization.",
        ],
        "refs": [
            ("OWASP Deserialization", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"),
        ],
    },
    "Security Header": {
        "desc": "The application is missing important HTTP security headers that provide defense-in-depth against common web attacks.",
        "steps": [
            "Implement Content-Security-Policy (CSP) to prevent XSS and data injection attacks.",
            "Enable Strict-Transport-Security (HSTS) with a minimum max-age of 31536000.",
            "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.",
            "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
            "Remove the Server and X-Powered-By headers to reduce information disclosure.",
        ],
        "refs": [
            ("OWASP Secure Headers", "https://owasp.org/www-project-secure-headers/"),
        ],
    },
    "Default Cred": {
        "desc": "The application uses default or easily guessable credentials for user accounts, allowing unauthorized access without any exploitation.",
        "steps": [
            "Force password changes on first login for all default accounts.",
            "Implement a strong password policy (minimum length, complexity requirements).",
            "Remove or disable all default/test accounts in production.",
            "Implement account lockout after repeated failed login attempts.",
        ],
        "refs": [
            ("OWASP Authentication", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
        ],
    },
}

# Fallback for types not in the map
_DEFAULT_MITIGATION = {
    "desc": "A security vulnerability was identified in the application that could be exploited by an attacker.",
    "steps": [
        "Review the proof of concept and affected endpoints.",
        "Implement appropriate input validation and access controls.",
        "Follow OWASP guidelines for the specific vulnerability type.",
        "Conduct a re-test after applying fixes to confirm remediation.",
    ],
    "refs": [("OWASP Top 10", "https://owasp.org/www-project-top-ten/")],
}


def _get_mitigation(title: str) -> dict:
    """Get mitigation template based on finding title keywords."""
    t = title.upper()
    for keyword, mit in MITIGATION_MAP.items():
        if keyword.upper() in t:
            return mit
    return _DEFAULT_MITIGATION


def _guess_owasp(title: str) -> str:
    t = title.upper()
    for keyword, cat in OWASP_MAP.items():
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


def _trunc(text, maxlen=1500):
    """Truncate text safely."""
    if not text:
        return ""
    s = str(text)
    if len(s) > maxlen:
        return s[:maxlen] + "\n... [truncated]"
    return s


def _xml_safe(text):
    """Make text safe for ReportLab XML paragraphs."""
    if not text:
        return ""
    s = str(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace('"', "&quot;").replace("'", "&#39;")
    # Remove any control characters that would break XML
    s = "".join(c for c in s if ord(c) >= 32 or c in "\n\r\t")
    return s


# ── Styles ────────────────────────────────────────────────────────────────────

def _build_styles():
    """Build all paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=28, leading=34, alignment=TA_CENTER,
        spaceAfter=6, textColor=HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=14, leading=18, alignment=TA_CENTER,
        textColor=HexColor("#555555"), spaceAfter=30,
    ))
    styles.add(ParagraphStyle(
        "Confidential", parent=styles["Normal"],
        fontSize=14, leading=18, alignment=TA_CENTER,
        textColor=HexColor("#C62828"), fontName="Helvetica-Bold",
        borderWidth=2, borderColor=HexColor("#C62828"),
        borderPadding=10, spaceBefore=40,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle", parent=styles["Heading1"],
        fontSize=18, leading=22, spaceBefore=20, spaceAfter=10,
        textColor=HexColor("#1a1a1a"), fontName="Helvetica-Bold",
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "SubSection", parent=styles["Heading2"],
        fontSize=13, leading=16, spaceBefore=14, spaceAfter=6,
        textColor=HexColor("#333333"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=10, leading=14, alignment=TA_JUSTIFY,
        spaceBefore=4, spaceAfter=4,
        textColor=HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        "FindingTitle", parent=styles["Heading2"],
        fontSize=13, leading=16, spaceBefore=12, spaceAfter=6,
        textColor=HexColor("#1a1a1a"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "CodeBlock", parent=styles["Code"],
        fontSize=7.5, leading=10, fontName="Courier",
        backColor=HexColor("#F0F0F0"), borderWidth=1,
        borderColor=HexColor("#CCCCCC"), borderPadding=10,
        spaceBefore=2, spaceAfter=4, wordWrap="CJK",
        leftIndent=4, rightIndent=4,
    ))
    styles.add(ParagraphStyle(
        "SmallText", parent=styles["Normal"],
        fontSize=8, leading=10, textColor=HexColor("#666666"),
    ))
    styles.add(ParagraphStyle(
        "FooterText", parent=styles["Normal"],
        fontSize=7, leading=9, alignment=TA_CENTER,
        textColor=HexColor("#999999"),
    ))
    styles.add(ParagraphStyle(
        "RiskBox", parent=styles["Normal"],
        fontSize=14, leading=18, alignment=TA_CENTER,
        fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        "BulletItem", parent=styles["Normal"],
        fontSize=10, leading=13, leftIndent=20,
        bulletIndent=8, spaceBefore=2, spaceAfter=2,
        textColor=HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        "NumberedItem", parent=styles["Normal"],
        fontSize=10, leading=13, leftIndent=25,
        bulletIndent=10, spaceBefore=2, spaceAfter=2,
        textColor=HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        "FieldLabel", parent=styles["Normal"],
        fontSize=10, leading=13, fontName="Helvetica-Bold",
        textColor=HexColor("#333333"),
    ))
    styles.add(ParagraphStyle(
        "FieldValue", parent=styles["Normal"],
        fontSize=10, leading=13, textColor=HexColor("#1a1a1a"),
    ))
    return styles


# ── Severity badge as a mini-table ────────────────────────────────────────────

def _sev_badge(sev: str, styles):
    """Create a colored severity badge as a styled Paragraph.

    Using a Paragraph instead of a nested Table avoids ReportLab's
    row-height miscalculation that causes badges to overlap.
    """
    s = sev.upper()
    sc = SEV_COLORS.get(s, SEV_COLORS["INFO"])
    return Paragraph(
        f"<b>{s}</b>",
        ParagraphStyle(
            f"badge_{s}", fontSize=8, leading=12, alignment=TA_CENTER,
            textColor=sc["text"], fontName="Helvetica-Bold",
            backColor=sc["bg"],
            borderPadding=3,
            spaceBefore=0, spaceAfter=0,
        ),
    )


# ── Page template with header/footer ─────────────────────────────────────────

def _header_footer(canvas, doc):
    """Draw header and footer on each page."""
    canvas.saveState()
    width, height = A4

    # Footer
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(HexColor("#999999"))
    canvas.drawCentredString(width / 2, 15 * mm,
                             f"Page {doc.page}")
    canvas.drawString(15 * mm, 15 * mm, "CONFIDENTIAL")
    canvas.drawRightString(width - 15 * mm, 15 * mm,
                           "TheRobin — AI Penetration Test Report")

    # Top line
    if doc.page > 1:
        canvas.setStrokeColor(HexColor("#CCCCCC"))
        canvas.setLineWidth(0.5)
        canvas.line(15 * mm, height - 12 * mm, width - 15 * mm, height - 12 * mm)
        # Bottom line
        canvas.line(15 * mm, 20 * mm, width - 15 * mm, 20 * mm)

    canvas.restoreState()


def _cover_header_footer(canvas, doc):
    """Minimal footer for cover page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(HexColor("#999999"))
    canvas.drawCentredString(A4[0] / 2, 15 * mm, "CONFIDENTIAL")
    canvas.restoreState()


# ── Build sections ────────────────────────────────────────────────────────────

def _build_cover(target, date_str, scope, styles):
    """Build cover page elements."""
    elements = []
    elements.append(Spacer(1, 80 * mm))
    elements.append(Paragraph("Penetration Test Report", styles["CoverTitle"]))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph("Web Application Security Assessment", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 15 * mm))

    # Meta table
    meta_data = [
        ["Target Application", _xml_safe(target)],
        ["Assessment Type", "Web Application Penetration Test"],
        ["Methodology", "OWASP Top 10 (2021), PTES, OWASP WSTG"],
        ["Test Date", _xml_safe(date_str)],
        ["Scope", _xml_safe(scope)],
        ["Report Version", "1.0"],
    ]
    meta_table = Table(meta_data, colWidths=[55 * mm, 95 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#444444")),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, HexColor("#EEEEEE")),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 20 * mm))

    # Confidential stamp
    conf_table = Table(
        [[Paragraph("<b>C O N F I D E N T I A L</b>", ParagraphStyle(
            "conf", fontSize=14, leading=18, alignment=TA_CENTER,
            textColor=HexColor("#C62828"), fontName="Helvetica-Bold",
        ))]],
        colWidths=[80 * mm],
        style=TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 2, HexColor("#C62828")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]),
    )
    # Center the confidential box
    wrapper = Table([[conf_table]], colWidths=[180 * mm])
    wrapper.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    elements.append(wrapper)
    elements.append(PageBreak())
    return elements


def _section_hr():
    """A horizontal rule between sections."""
    return HRFlowable(width="100%", thickness=1, color=HexColor("#DDDDDD"),
                      spaceBefore=4, spaceAfter=8)


def _build_management_summary(target, counts, rating, findings, styles):
    """Build management summary section."""
    elements = []
    elements.append(Paragraph("1. Management Summary", styles["SectionTitle"]))
    elements.append(_section_hr())

    total = sum(counts.values())
    elements.append(Paragraph(
        f"A penetration test was conducted against <b>{_xml_safe(target)}</b> to evaluate the "
        f"security posture of the web application. The assessment covered authentication mechanisms, "
        f"input validation, access controls, session management, API security, business logic, and "
        f"server configuration across 25 testing categories following industry-standard OWASP methodology.",
        styles["Body"]
    ))
    elements.append(Paragraph(
        f"The assessment identified <b>{total} vulnerabilities</b>: "
        f"{counts.get('CRITICAL', 0)} Critical, {counts.get('HIGH', 0)} High, "
        f"{counts.get('MEDIUM', 0)} Medium, {counts.get('LOW', 0)} Low, "
        f"{counts.get('INFO', 0)} Informational.",
        styles["Body"]
    ))

    # Critical/High impact summary
    crit = [f for f in findings if f.get("severity", "").upper() == "CRITICAL"]
    high = [f for f in findings if f.get("severity", "").upper() == "HIGH"]
    if crit:
        titles = ", ".join(_xml_safe(f.get("title", ""))[:50] for f in crit[:4])
        elements.append(Paragraph(
            f"<b>Critical vulnerabilities</b> were identified that could allow an attacker to "
            f"compromise the application immediately. These include: {titles}.",
            styles["Body"]
        ))
    if high:
        elements.append(Paragraph(
            f"Additionally, <b>{len(high)} high-severity</b> issue(s) were found that present "
            f"serious risk if left unremediated.",
            styles["Body"]
        ))

    elements.append(Spacer(1, 4 * mm))

    # Risk rating box
    rating_color = SEV_COLORS.get(rating, SEV_COLORS.get("INFO"))
    risk_text = RISK_LABELS.get(rating, "")
    risk_table = Table(
        [[Paragraph(
            f"<b>Overall Security Rating: {rating}</b><br/>"
            f"<font size=9>{_xml_safe(risk_text)}</font>",
            ParagraphStyle("risk", fontSize=13, leading=16, alignment=TA_CENTER,
                           textColor=rating_color["bar"], fontName="Helvetica-Bold"),
        )]],
        colWidths=[160 * mm],
        style=TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 2, rating_color["bar"]),
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FAFAFA")),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]),
    )
    elements.append(risk_table)
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(
        "Immediate remediation is strongly recommended for all Critical and High severity findings. "
        "A prioritised remediation roadmap is provided in Section 5 of this report.",
        styles["Body"]
    ))
    elements.append(PageBreak())
    return elements


def _build_findings_overview(findings, counts, styles):
    """Build findings overview table."""
    elements = []
    elements.append(Paragraph("2. Findings Overview", styles["SectionTitle"]))
    elements.append(_section_hr())

    # Severity distribution
    elements.append(Paragraph("2.1 Severity Distribution", styles["SubSection"]))
    dist_data = [["Severity", "Count"]]
    total = 0
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        if c > 0:
            dist_data.append([_sev_badge(sev, styles), str(c)])
            total += c
    dist_data.append(["TOTAL", str(total)])

    dist_table = Table(dist_data, colWidths=[80 * mm, 40 * mm])
    dist_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("ALIGN", (0, 1), (0, -2), "CENTER"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(dist_table)
    elements.append(Spacer(1, 6 * mm))

    # Findings summary table
    elements.append(Paragraph("2.2 Findings Summary", styles["SubSection"]))
    summary_data = [["#", "Severity", "Finding", "CVSS", "OWASP"]]
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = _xml_safe(f.get("title", "—"))[:60]
        cvss = str(f.get("cvss", f.get("detail", {}).get("cvss", "—")))
        owasp = _guess_owasp(f.get("title", ""))
        summary_data.append([
            str(i),
            _sev_badge(sev, styles),
            Paragraph(title, styles["SmallText"]),
            cvss,
            Paragraph(_xml_safe(owasp), styles["SmallText"]),
        ])

    summary_table = Table(summary_data,
                          colWidths=[10 * mm, 22 * mm, 68 * mm, 16 * mm, 48 * mm],
                          repeatRows=1)
    summary_style = [
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ALIGN", (3, 0), (3, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    # Alternate row colors
    for i in range(1, len(summary_data)):
        if i % 2 == 0:
            summary_style.append(("BACKGROUND", (0, i), (-1, i), HexColor("#FAFAFA")))
    summary_table.setStyle(TableStyle(summary_style))
    elements.append(summary_table)
    elements.append(PageBreak())
    return elements


def _build_detailed_findings(findings, styles):
    """Build detailed findings section with professional cards."""
    elements = []
    elements.append(Paragraph("3. Detailed Findings", styles["SectionTitle"]))
    elements.append(_section_hr())

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = _xml_safe(f.get("title", "Unknown"))
        url = _xml_safe(f.get("url", "—"))
        detail = f.get("detail", {}) if isinstance(f.get("detail"), dict) else {}
        method = f.get("method", detail.get("method", "—"))
        param = f.get("param", detail.get("param", detail.get("field", "—")))
        payload = _xml_safe(f.get("payload", detail.get("payload", "—")))
        cvss = str(f.get("cvss", detail.get("cvss", "—")))
        owasp = _guess_owasp(f.get("title", ""))
        evidence = _trunc(f.get("evidence", detail.get("evidence", "")), 1200)
        poc = _trunc(f.get("poc", detail.get("poc", "")), 1200)
        request = _trunc(f.get("request", detail.get("request", "")), 1200)
        response = _trunc(f.get("response", detail.get("response", "")), 1200)
        impact = f.get("impact", detail.get("impact", ""))

        # Affected endpoints
        affected = f.get("affected_endpoints", detail.get("affected_endpoints", []))
        if isinstance(affected, str):
            affected = [affected]

        # Get mitigation template
        mitigation = _get_mitigation(f.get("title", ""))

        sc = SEV_COLORS.get(sev, SEV_COLORS["INFO"])
        card_elements = []

        # ── Finding header ────────────────────────────────────────────
        card_elements.append(Paragraph(
            f"<b>VULN-{i:03d}: {title}</b>",
            styles["FindingTitle"]
        ))

        # ── Meta table ────────────────────────────────────────────────
        meta_rows = [
            [Paragraph("<b>Severity</b>", styles["FieldLabel"]),
             _sev_badge(sev, styles)],
            [Paragraph("<b>Affected URL</b>", styles["FieldLabel"]),
             Paragraph(f"<font face='Courier' size=9>{url}</font>", styles["FieldValue"])],
            [Paragraph("<b>Method</b>", styles["FieldLabel"]),
             Paragraph(_xml_safe(str(method)), styles["FieldValue"])],
            [Paragraph("<b>Parameter</b>", styles["FieldLabel"]),
             Paragraph(f"<font face='Courier' size=9>{_xml_safe(str(param))}</font>", styles["FieldValue"])],
            [Paragraph("<b>Payload</b>", styles["FieldLabel"]),
             Paragraph(f"<font face='Courier' size=9>{payload}</font>", styles["FieldValue"])],
            [Paragraph("<b>CVSS v3.1</b>", styles["FieldLabel"]),
             Paragraph(_xml_safe(cvss), styles["FieldValue"])],
            [Paragraph("<b>OWASP</b>", styles["FieldLabel"]),
             Paragraph(_xml_safe(owasp), styles["FieldValue"])],
        ]
        meta_table = Table(meta_rows, colWidths=[35 * mm, 130 * mm])
        meta_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -2), 0.3, HexColor("#EEEEEE")),
            ("BACKGROUND", (0, 0), (0, -1), HexColor("#FAFAFA")),
        ]))
        card_elements.append(meta_table)
        card_elements.append(Spacer(1, 3 * mm))

        # ── Separator ─────────────────────────────────────────────────
        card_elements.append(HRFlowable(
            width="100%", thickness=0.5, color=HexColor("#DDDDDD"),
            spaceBefore=2, spaceAfter=4,
        ))

        # ── General Description ───────────────────────────────────────
        card_elements.append(Paragraph("<b>Description</b>", styles["SubSection"]))
        card_elements.append(Spacer(1, 2 * mm))
        card_elements.append(Paragraph(_xml_safe(mitigation["desc"]), styles["Body"]))
        if impact:
            card_elements.append(Spacer(1, 2 * mm))
            card_elements.append(Paragraph(
                f"<b>Impact:</b> {_xml_safe(impact)}", styles["Body"]))
        card_elements.append(Spacer(1, 4 * mm))

        # ── Affected Endpoints ────────────────────────────────────────
        if affected:
            card_elements.append(Paragraph(
                f"<b>Affected Endpoints ({len(affected)})</b>", styles["SubSection"]))
            ep_data = [["Method", "URL / Path", "Parameter"]]
            for ep in affected:
                if isinstance(ep, dict):
                    ep_data.append([
                        ep.get("method", "GET"),
                        Paragraph(f"<font face='Courier' size=8>{_xml_safe(ep.get('url', ''))}</font>",
                                  styles["SmallText"]),
                        ep.get("param", "—"),
                    ])
                else:
                    ep_data.append(["—",
                                    Paragraph(f"<font face='Courier' size=8>{_xml_safe(str(ep))}</font>",
                                              styles["SmallText"]),
                                    "—"])
            ep_table = Table(ep_data, colWidths=[18 * mm, 110 * mm, 35 * mm])
            ep_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            card_elements.append(ep_table)
            card_elements.append(Spacer(1, 2 * mm))

        # ── Proof of Concept ──────────────────────────────────────────
        card_elements.append(Paragraph("<b>Proof of Concept</b>", styles["SubSection"]))
        card_elements.append(Spacer(1, 2 * mm))

        if request:
            card_elements.append(Paragraph(
                "<b>Request Sent</b>",
                ParagraphStyle("poc_label", parent=styles["FieldLabel"],
                               spaceBefore=4, spaceAfter=2,
                               textColor=HexColor("#444444")),
            ))
            card_elements.append(Spacer(1, 1 * mm))
            card_elements.append(Paragraph(
                _xml_safe(request).replace("\n", "<br/>"),
                styles["CodeBlock"]
            ))
            card_elements.append(Spacer(1, 4 * mm))

        if response:
            card_elements.append(Paragraph(
                "<b>Server Response</b>",
                ParagraphStyle("poc_label2", parent=styles["FieldLabel"],
                               spaceBefore=4, spaceAfter=2,
                               textColor=HexColor("#444444")),
            ))
            card_elements.append(Spacer(1, 1 * mm))
            card_elements.append(Paragraph(
                _xml_safe(response).replace("\n", "<br/>"),
                styles["CodeBlock"]
            ))
            card_elements.append(Spacer(1, 4 * mm))

        if evidence and not request and not response:
            card_elements.append(Paragraph(
                "<b>Evidence</b>",
                ParagraphStyle("poc_label3", parent=styles["FieldLabel"],
                               spaceBefore=4, spaceAfter=2,
                               textColor=HexColor("#444444")),
            ))
            card_elements.append(Spacer(1, 1 * mm))
            card_elements.append(Paragraph(
                _xml_safe(evidence).replace("\n", "<br/>"),
                styles["CodeBlock"]
            ))
            card_elements.append(Spacer(1, 4 * mm))

        if poc:
            card_elements.append(Paragraph(
                "<b>Reproduction Command</b>",
                ParagraphStyle("poc_label4", parent=styles["FieldLabel"],
                               spaceBefore=4, spaceAfter=2,
                               textColor=HexColor("#444444")),
            ))
            card_elements.append(Spacer(1, 1 * mm))
            card_elements.append(Paragraph(
                _xml_safe(poc).replace("\n", "<br/>"),
                styles["CodeBlock"]
            ))

        card_elements.append(Spacer(1, 5 * mm))

        # ── Separator line before mitigation ──────────────────────────
        card_elements.append(HRFlowable(
            width="100%", thickness=0.5, color=HexColor("#DDDDDD"),
            spaceBefore=2, spaceAfter=4,
        ))

        # ── Mitigation ────────────────────────────────────────────────
        card_elements.append(Paragraph("<b>Mitigation</b>", styles["SubSection"]))
        card_elements.append(Spacer(1, 2 * mm))
        card_elements.append(Paragraph(
            "In order to mitigate this issue, we recommend the following measures:",
            styles["Body"]
        ))
        card_elements.append(Spacer(1, 2 * mm))
        for j, step in enumerate(mitigation["steps"], 1):
            card_elements.append(Paragraph(
                f"<b>{j}.</b> {_xml_safe(step)}",
                styles["NumberedItem"]
            ))

        # Reference links
        if mitigation.get("refs"):
            card_elements.append(Spacer(1, 4 * mm))
            for ref_name, ref_url in mitigation["refs"]:
                card_elements.append(Paragraph(
                    f'<b>Reference:</b> <a href="{_xml_safe(ref_url)}" '
                    f'color="#1565C0">{_xml_safe(ref_name)}</a>',
                    styles["SmallText"]
                ))

        # ── Wrap in a bordered card ───────────────────────────────────
        card_content = []
        for el in card_elements:
            card_content.append([el])

        card_table = Table(card_content, colWidths=[165 * mm])
        card_style = [
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            # Colored left border bar
            ("LINEBEFORE", (0, 0), (0, -1), 4, sc["bar"]),
            # Light outer border
            ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
            # Header row background
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F8F8F8")),
            # Bottom padding for card
            ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
        ]
        card_table.setStyle(TableStyle(card_style))

        elements.append(card_table)
        elements.append(Spacer(1, 8 * mm))

    if not findings:
        elements.append(Paragraph("No findings to report.", styles["Body"]))

    elements.append(PageBreak())
    return elements


def _build_scope_methodology(target, scope, styles):
    """Build scope and methodology section."""
    elements = []
    elements.append(Paragraph("4. Scope &amp; Methodology", styles["SectionTitle"]))
    elements.append(_section_hr())

    scope_data = [
        ["Item", "Details"],
        ["Target URL", _xml_safe(target)],
        ["In-Scope", _xml_safe(scope)],
        ["Testing Approach", "Grey-box (valid credentials provided)"],
        ["Out of Scope", "Denial of Service, social engineering, physical access"],
        ["Methodology", "OWASP Top 10 (2021), PTES, OWASP WSTG"],
    ]
    scope_table = Table(scope_data, colWidths=[45 * mm, 120 * mm])
    scope_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 1), (0, -1), HexColor("#FAFAFA")),
    ]))
    elements.append(scope_table)
    elements.append(Spacer(1, 6 * mm))

    # Testing phases
    elements.append(Paragraph("4.1 Testing Phases", styles["SubSection"]))
    phases = [
        (1, "Reconnaissance & Crawling"), (2, "Security Headers"),
        (3, "Authentication & Session Setup"), (4, "JavaScript Secret Scanning"),
        (5, "Session Management"), (6, "XSS — Reflected & Stored"),
        (7, "XSS — DOM-Based"), (8, "SQL Injection"),
        (9, "NoSQL Injection"), (10, "Cross-Site Request Forgery"),
        (11, "Technology Fingerprinting"), (12, "CORS, Redirect, SSL/TLS, JWT"),
        (13, "Deep JWT Testing"), (14, "Command Injection"),
        (15, "Server-Side Template Injection"), (16, "Server-Side Request Forgery"),
        (17, "Insecure Deserialization"), (18, "File Upload"),
        (19, "GraphQL"), (20, "HTTP Protocol Attacks"),
        (21, "IDOR / Access Control"), (22, "Business Logic"),
        (23, "XXE & Path Traversal"), (24, "API Security"),
        (25, "Race Conditions"),
    ]
    phase_data = [["Phase", "Category", "Status"]]
    for num, name in phases:
        phase_data.append([str(num), name, "Completed"])

    phase_table = Table(phase_data, colWidths=[18 * mm, 110 * mm, 30 * mm])
    phase_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    # Alternate row colors
    for i in range(1, len(phase_data)):
        if i % 2 == 0:
            phase_table._argW  # force init
    elements.append(phase_table)
    elements.append(PageBreak())
    return elements


def _build_remediation_roadmap(findings, styles):
    """Build remediation roadmap section."""
    elements = []
    elements.append(Paragraph("5. Remediation Roadmap", styles["SectionTitle"]))
    elements.append(_section_hr())

    priority_groups = [
        ("5.1 Immediate (0-48 hours) — Critical Risk", "P1", "CRITICAL"),
        ("5.2 Short-Term (1-2 weeks) — High Risk", "P2", "HIGH"),
        ("5.3 Medium-Term (1 month) — Moderate Risk", "P3", "MEDIUM"),
        ("5.4 Long-Term (next release) — Low Risk", "P4", "LOW"),
    ]

    for section_title, priority, sev_level in priority_groups:
        elements.append(Paragraph(section_title, styles["SubSection"]))
        items = [f for f in findings if f.get("severity", "").upper() == sev_level]
        if sev_level == "LOW":
            items += [f for f in findings if f.get("severity", "").upper() == "INFO"]

        if not items:
            elements.append(Paragraph(
                "<i>No findings at this priority level.</i>", styles["Body"]))
            continue

        prio_data = [["Priority", "Finding", "Action Required"]]
        for f in items:
            title = _xml_safe(f.get("title", "—"))[:50]
            mit = _get_mitigation(f.get("title", ""))
            action = _xml_safe(mit["steps"][0])[:100] if mit["steps"] else "See detailed finding."
            prio_data.append([
                priority,
                Paragraph(title, styles["SmallText"]),
                Paragraph(action, styles["SmallText"]),
            ])

        prio_table = Table(prio_data, colWidths=[18 * mm, 65 * mm, 82 * mm])
        prio_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(prio_table)
        elements.append(Spacer(1, 3 * mm))

    # Strategic recommendations
    elements.append(Paragraph("5.5 Strategic Recommendations", styles["SubSection"]))
    recommendations = [
        "Implement centralised input validation and sanitisation using a whitelist approach across all endpoints.",
        "Deploy standardised security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) via middleware.",
        "Implement account lockout, multi-factor authentication, and session regeneration on login.",
        "Integrate SAST/DAST tools into the CI/CD pipeline to catch vulnerabilities before deployment.",
        "Establish a process for monitoring and updating third-party libraries and dependencies.",
    ]
    for j, rec in enumerate(recommendations, 1):
        elements.append(Paragraph(f"<b>{j}.</b> {_xml_safe(rec)}", styles["NumberedItem"]))

    elements.append(PageBreak())
    return elements


def _build_conclusion(target, counts, rating, styles):
    """Build conclusion section."""
    elements = []
    elements.append(Paragraph("6. Conclusion", styles["SectionTitle"]))
    elements.append(_section_hr())

    total = sum(counts.values())
    elements.append(Paragraph(
        f"The penetration test of <b>{_xml_safe(target)}</b> identified <b>{total} "
        f"vulnerabilities</b> across multiple severity levels. The overall security posture is "
        f"rated as <b>{rating}</b>.",
        styles["Body"]
    ))

    if rating in ("CRITICAL", "POOR"):
        elements.append(Paragraph(
            "Critical vulnerabilities require <b>immediate attention</b> as they allow direct "
            "exploitation by an unauthenticated attacker. The application should not be considered "
            "safe for production use until all Critical and High findings are remediated.",
            styles["Body"]
        ))
    elif rating == "MODERATE":
        elements.append(Paragraph(
            "While no critical issues were found, the identified medium-severity findings should "
            "be addressed to strengthen the application's security posture.",
            styles["Body"]
        ))
    else:
        elements.append(Paragraph(
            "The application demonstrates a solid security posture with only minor issues identified.",
            styles["Body"]
        ))

    elements.append(Paragraph(
        "A re-test is recommended after remediation to verify that all identified vulnerabilities "
        "have been properly addressed and no regressions have been introduced.",
        styles["Body"]
    ))
    elements.append(PageBreak())
    return elements


def _build_appendix(styles):
    """Build severity definitions appendix."""
    elements = []
    elements.append(Paragraph("Appendix A — Severity Rating Definitions", styles["SectionTitle"]))
    elements.append(_section_hr())

    sev_data = [["Severity", "CVSS Range", "Definition"]]
    sev_defs = [
        ("CRITICAL", "9.0 - 10.0",
         "Vulnerability can be exploited remotely with no authentication, leading to full system "
         "compromise, data breach, or remote code execution. Immediate remediation required."),
        ("HIGH", "7.0 - 8.9",
         "Significant impact. May require authentication, user interaction, or specific conditions. "
         "Should be remediated within days."),
        ("MEDIUM", "4.0 - 6.9",
         "Moderate risk. Exploitation may be limited in scope or require chaining with other issues. "
         "Remediate within weeks."),
        ("LOW", "0.1 - 3.9",
         "Minor security issue with minimal direct impact. Remediate during normal development cycle."),
        ("INFO", "0.0",
         "Observation or best-practice recommendation with no direct security impact."),
    ]

    for sev, cvss_range, definition in sev_defs:
        sev_data.append([
            _sev_badge(sev, styles),
            cvss_range,
            Paragraph(_xml_safe(definition), styles["SmallText"]),
        ])

    sev_table = Table(sev_data, colWidths=[24 * mm, 25 * mm, 116 * mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("ALIGN", (0, 1), (0, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 10 * mm))

    elements.append(Paragraph("Appendix B — CVSS v3.1 Reference", styles["SectionTitle"]))
    elements.append(_section_hr())
    elements.append(Paragraph(
        'All CVSS scores in this report are calculated using the CVSS v3.1 specification. '
        'For more information see: <a href="https://www.first.org/cvss/v3.1/specification-document" '
        'color="#1565C0">first.org/cvss/v3.1</a>',
        styles["Body"]
    ))
    elements.append(Spacer(1, 20 * mm))

    # Footer disclaimer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC"),
                                spaceBefore=10, spaceAfter=6))
    elements.append(Paragraph(
        "This report is confidential and intended solely for the authorised recipient.<br/>"
        "All findings have been confirmed through active testing with proof-of-concept evidence.",
        styles["FooterText"]
    ))
    return elements


# ── Main generator ────────────────────────────────────────────────────────────

def generate_pdf_report(g: dict, output_path: str = "report.pdf") -> str:
    """
    Generate a professional PDF pentest report from the _G globals dict.

    Parameters
    ----------
    g : dict
        The _G persistent globals dict from the REPL.
    output_path : str
        Where to write the PDF file.

    Returns
    -------
    str : the output file path
    """
    target = g.get("BASE", g.get("target", "Unknown"))
    scope = g.get("SCOPE", target)
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    # ── Aggregate all findings ────────────────────────────────────────
    all_findings = list(g.get("FINDINGS", []))

    for sf in g.get("SQLI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"SQL Injection — {sf.get('type', 'SQLi')} ({sf.get('field', '')})",
            "url": sf.get("url", ""), "detail": sf,
        })
    for cf in g.get("CMDI_FINDINGS", []):
        all_findings.append({
            "severity": "CRITICAL",
            "title": f"Command Injection — {cf.get('param', '')} ({cf.get('method', '')})",
            "url": cf.get("url", ""), "detail": cf,
        })
    for xf in g.get("XSS_FINDINGS", []):
        all_findings.append({
            "severity": xf.get("severity", "HIGH"),
            "title": f"XSS — {xf.get('type', 'XSS')} in {xf.get('param', '')}",
            "url": xf.get("url", ""), "detail": xf,
        })
    for idf in g.get("IDOR_FINDINGS", []):
        all_findings.append({
            "severity": idf.get("severity", "HIGH"),
            "title": f"IDOR — {idf.get('type', 'IDOR')}",
            "url": idf.get("url", ""), "detail": idf,
        })
    for jf in g.get("JS_FINDINGS", []):
        all_findings.append({
            "severity": jf.get("sev", jf.get("severity", "HIGH")),
            "title": f"JS: {jf.get('type', 'JS Issue')}",
            "url": jf.get("file", jf.get("url", "")), "detail": jf,
        })

    # Sort by severity
    all_findings.sort(key=lambda f: SEV_RANK.get(f.get("severity", "INFO").upper(), 4))

    # Deduplicate
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("title", ""), f.get("url", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # ── Counts ────────────────────────────────────────────────────────
    counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    rating = _overall_rating(counts)

    # ── Build PDF ─────────────────────────────────────────────────────
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=25 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title=f"Penetration Test Report — {target}",
        author="TheRobin — AI Penetration Testing Framework",
        subject="Web Application Security Assessment",
    )

    elements = []

    # Cover page
    elements.extend(_build_cover(target, date_str, scope, styles))

    # Management summary
    elements.extend(_build_management_summary(target, counts, rating, all_findings, styles))

    # Findings overview
    elements.extend(_build_findings_overview(all_findings, counts, styles))

    # Detailed findings
    elements.extend(_build_detailed_findings(all_findings, styles))

    # Scope & methodology
    elements.extend(_build_scope_methodology(target, scope, styles))

    # Remediation roadmap
    elements.extend(_build_remediation_roadmap(all_findings, styles))

    # Conclusion
    elements.extend(_build_conclusion(target, counts, rating, styles))

    # Appendix
    elements.extend(_build_appendix(styles))

    # ── Build ─────────────────────────────────────────────────────────
    doc.build(elements, onFirstPage=_cover_header_footer, onLaterPages=_header_footer)

    out = Path(output_path)
    return str(out.resolve())
