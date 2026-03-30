"""
Multi-Finding Disclosure Report Generator.
Produces a professional responsible-disclosure PDF for multiple findings
(any mix of severities) — matching the single-finding disclosure template style.

Usage:
    from agent.report_disclosure_multi import generate_multi_disclosure

    findings = [
        {
            'severity':    'HIGH',          # HIGH / MEDIUM / LOW
            'cvss_score':  '8.6',
            'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
            'owasp':       'A05:2021-Security Misconfiguration',
            'title':       'XML-RPC Enabled with Multicall',
            'subtitle':    'One-line impact sentence shown in red under the title',
            'endpoint':    'https://target.com/xmlrpc.php',
            'summary':     'HTML-capable paragraph text...',
            'poc':         'curl -sk ...',   # plain text, shown in code block
            'remediation': 'HTML-capable paragraph text...',
        },
        # ... more findings
    ]

    target_info = {
        'name':             'target.com',
        'url':              'www.target.com',     # shown in header bar
        'researcher_email': 'cybersecdo@gmail.com',
    }

    generate_multi_disclosure(findings, target_info, '/path/to/output.pdf')
"""

import os
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY

# ── Colour palette ───────────────────────────────────────────────────────────
RED       = colors.HexColor('#C0392B')
ORANGE    = colors.HexColor('#E67E22')
DARK_GRAY = colors.HexColor('#2C3E50')
MID_GRAY  = colors.HexColor('#566573')
LIGHT_BG  = colors.HexColor('#FDFEFE')
TABLE_HDR = colors.HexColor('#2C3E50')
TABLE_ALT = colors.HexColor('#F2F3F4')
RED_BADGE = colors.HexColor('#FDEDEC')
ORANGE_BG = colors.HexColor('#FEF9E7')
BORDER    = colors.HexColor('#AEB6BF')
WHITE     = colors.white
SEV_HIGH  = colors.HexColor('#C0392B')
SEV_MED   = colors.HexColor('#E67E22')
SEV_LOW   = colors.HexColor('#2E86AB')

W, H = A4  # 595 x 842 pts


def _sev_color(sev):
    sev = sev.upper()
    if sev == 'HIGH' or sev == 'CRITICAL':
        return SEV_HIGH
    if sev == 'MEDIUM':
        return SEV_MED
    return SEV_LOW


def _sev_badge_bg(sev):
    sev = sev.upper()
    if sev in ('HIGH', 'CRITICAL'):
        return RED_BADGE
    if sev == 'MEDIUM':
        return ORANGE_BG
    return colors.HexColor('#EAF4FB')


def _highest_severity(findings):
    order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    for s in order:
        if any(f.get('severity', '').upper() == s for f in findings):
            return s
    return 'HIGH'


def generate_multi_disclosure(findings, target_info, output_path):
    """
    Generate a multi-finding responsible-disclosure PDF.

    Args:
        findings    : list of finding dicts (see module docstring for schema)
        target_info : dict with keys: name, url, researcher_email
        output_path : str — destination PDF path (directories must exist)

    Returns:
        str — absolute path to the generated PDF
    """
    output_path = str(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2.2*cm,
        title=f"Security Vulnerability Disclosure — {target_info.get('name', 'Target')}",
    )

    styles = getSampleStyleSheet()
    _id = [0]

    def S(base='Normal', **kw):
        _id[0] += 1
        return ParagraphStyle(f'_s{_id[0]}', parent=styles[base], **kw)

    # Shared styles
    sBody      = S(fontSize=9.5, leading=14, textColor=DARK_GRAY, fontName='Helvetica', spaceAfter=6, alignment=TA_JUSTIFY)
    sBodyBold  = S(fontSize=9.5, leading=14, textColor=DARK_GRAY, fontName='Helvetica-Bold', spaceAfter=4)
    sH1        = S(fontSize=12,  leading=16, textColor=WHITE,     fontName='Helvetica-Bold')
    sH2        = S(fontSize=11,  leading=15, textColor=DARK_GRAY, fontName='Helvetica-Bold', spaceAfter=4, spaceBefore=8)
    sCode      = S(fontSize=7.8, leading=11.5, textColor=colors.HexColor('#1A5276'), fontName='Courier')
    sSmall     = S(fontSize=8,   leading=11, textColor=MID_GRAY,  fontName='Helvetica')
    sCenterIta = S(fontSize=9,   leading=13, textColor=MID_GRAY,  fontName='Helvetica-Oblique', alignment=TA_CENTER)
    sTableCell = S(fontSize=8.5, leading=12, textColor=DARK_GRAY, fontName='Helvetica')
    sTableHdr  = S(fontSize=8.5, leading=12, textColor=WHITE,     fontName='Helvetica-Bold')

    researcher_email = target_info.get('researcher_email', 'cybersecdo@gmail.com')
    target_url       = target_info.get('url', 'target.com')
    target_name      = target_info.get('name', 'target.com')
    CW = W - 4*cm  # usable content width

    # ── Page callbacks ───────────────────────────────────────────────────────
    def header_footer(canvas, doc):
        canvas.saveState()
        Wp, Hp = A4
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, Hp - 1.2*cm, Wp, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.drawString(2*cm, Hp - 0.78*cm, 'SECURITY VULNERABILITY DISCLOSURE')
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(Wp - 2*cm, Hp - 0.78*cm, f'CONFIDENTIAL  |  {target_url}')
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, 0, Wp, 1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(2*cm, 0.35*cm, f'© {datetime.now().year} — Independent Security Research  |  {researcher_email}')
        canvas.drawRightString(Wp - 2*cm, 0.35*cm, f'Page {doc.page}')
        canvas.restoreState()

    def cover_footer(canvas, doc):
        canvas.saveState()
        Wp, Hp = A4
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, 0, Wp, 1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(2*cm, 0.35*cm, 'CONFIDENTIAL — FOR SECURITY TEAM USE ONLY')
        canvas.drawRightString(Wp - 2*cm, 0.35*cm, datetime.now().strftime('%Y-%m-%d'))
        canvas.restoreState()

    # ── Component builders ───────────────────────────────────────────────────
    def sec_hdr(title, color=DARK_GRAY):
        t = Table([[Paragraph(title, sH1)]], colWidths=[CW])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), color),
            ('LEFTPADDING',   (0,0),(-1,-1), 10),
            ('RIGHTPADDING',  (0,0),(-1,-1), 10),
            ('TOPPADDING',    (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
        ]))
        return t

    def kv_table(rows, col1=4.2*cm):
        col2 = CW - col1
        data = [[Paragraph(k, sBodyBold), Paragraph(v, sBody)] for k, v in rows]
        t = Table(data, colWidths=[col1, col2])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(0,-1), colors.HexColor('#EBF5FB')),
            ('BACKGROUND',    (1,0),(1,-1), LIGHT_BG),
            ('GRID',          (0,0),(-1,-1), 0.4, BORDER),
            ('LEFTPADDING',   (0,0),(-1,-1), 8),
            ('RIGHTPADDING',  (0,0),(-1,-1), 8),
            ('TOPPADDING',    (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('VALIGN',        (0,0),(-1,-1), 'TOP'),
        ]))
        return t

    def code_block(text):
        if not text:
            return Spacer(1, 0.1)
        rows = [[Paragraph(
            line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(' ', '&nbsp;'),
            sCode
        )] for line in text.split('\n')]
        t = Table(rows, colWidths=[CW])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), colors.HexColor('#EBF5FB')),
            ('LEFTPADDING',   (0,0),(-1,-1), 10),
            ('RIGHTPADDING',  (0,0),(-1,-1), 10),
            ('TOPPADDING',    (0,0),(-1,-1), 1),
            ('BOTTOMPADDING', (0,0),(-1,-1), 1),
            ('BOX',           (0,0),(-1,-1), 0.8, colors.HexColor('#2980B9')),
        ]))
        return t

    def sev_badge(sev, cvss):
        color = _sev_color(sev)
        bg    = _sev_badge_bg(sev)
        style = S(fontSize=13, leading=18, textColor=color, fontName='Helvetica-Bold', alignment=TA_CENTER)
        t = Table([[Paragraph(f'■  {sev.upper()} SEVERITY  —  CVSS v3.1: {cvss}', style)]], colWidths=[CW])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), bg),
            ('BOX',           (0,0),(-1,-1), 1.5, color),
            ('TOPPADDING',    (0,0),(-1,-1), 10),
            ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ]))
        return t

    # ── Build document ───────────────────────────────────────────────────────
    E = []
    highest = _highest_severity(findings)
    n = len(findings)

    # Severity counts for cover subtitle
    counts = {}
    for f in findings:
        s = f.get('severity', 'MEDIUM').upper()
        counts[s] = counts.get(s, 0) + 1
    count_str = ', '.join(f'{v} {k}' for k, v in sorted(counts.items(), key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x[0]) if x[0] in ['CRITICAL','HIGH','MEDIUM','LOW'] else 9))

    # Cover page
    top_cvss = findings[0].get('cvss_score', '—')
    E.append(Spacer(1, 1.4*cm))
    E.append(sev_badge(highest, top_cvss))
    E.append(Spacer(1, 0.6*cm))
    E.append(Paragraph('SECURITY VULNERABILITY REPORT',
        S(fontSize=11, fontName='Helvetica', textColor=MID_GRAY, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.3*cm))
    E.append(Paragraph(f'Security Vulnerabilities Identified — {target_name}',
        S(fontSize=20, fontName='Helvetica-Bold', textColor=DARK_GRAY, leading=26, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.15*cm))
    titles_short = ', '.join(f['title'].split(' — ')[0].split(' via ')[0][:35] for f in findings[:3])
    if n > 3:
        titles_short += f' +{n - 3} more'
    E.append(Paragraph(titles_short,
        S(fontSize=10, fontName='Helvetica', textColor=RED, alignment=TA_CENTER, leading=15)))
    E.append(Spacer(1, 0.6*cm))
    E.append(HRFlowable(width='100%', thickness=1.5, color=RED))
    E.append(Spacer(1, 0.5*cm))

    E.append(kv_table([
        ['Target',   f'https://{target_name}'],
        ['Date',     datetime.now().strftime('%Y-%m-%d')],
        ['Findings', f'{n} {"vulnerability" if n == 1 else "vulnerabilities"} ({count_str})'],
        ['Contact',  researcher_email],
    ], col1=3.8*cm))
    E.append(Spacer(1, 0.6*cm))

    # Findings overview table
    # Column widths: # 0.6 | Severity 2.3 | Vulnerability 7.3 | Endpoint 5.0 | CVSS 1.8
    hdr = [Paragraph(h, sTableHdr) for h in ['#', 'Severity', 'Vulnerability', 'Endpoint', 'CVSS']]
    trows = []
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'MEDIUM').upper()
        sev_style = S(fontSize=8.5, leading=12, textColor=_sev_color(sev),
                      fontName='Helvetica-Bold', alignment=TA_CENTER)
        short_title = f['title'].split(' — ')[0]
        endpoint    = f.get('endpoint', '').replace(f'https://{target_name}', '').replace(f'http://{target_name}', '')
        trows.append([
            Paragraph(str(i), sTableCell),
            Paragraph(sev, sev_style),
            Paragraph(short_title, sTableCell),
            Paragraph(endpoint, sTableCell),
            Paragraph(f.get('cvss_score', '—'), sTableCell),
        ])
    overview = Table([hdr] + trows, colWidths=[0.6*cm, 2.3*cm, 7.3*cm, 5.0*cm, 1.8*cm], repeatRows=1)
    overview.setStyle(TableStyle([
        ('BACKGROUND',     (0,0),(-1,0),  TABLE_HDR),
        ('ROWBACKGROUNDS', (0,1),(-1,-1), [TABLE_ALT, WHITE] * 20),
        ('GRID',           (0,0),(-1,-1), 0.3, BORDER),
        ('LEFTPADDING',    (0,0),(-1,-1), 7),
        ('RIGHTPADDING',   (0,0),(-1,-1), 7),
        ('TOPPADDING',     (0,0),(-1,-1), 6),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 6),
        ('VALIGN',         (0,0),(-1,-1), 'MIDDLE'),
    ]))
    E.append(overview)
    E.append(Spacer(1, 0.8*cm))
    E.append(Paragraph(
        'This report is submitted in good faith as part of responsible disclosure. Testing was limited '
        'to confirming exploitability. No data was exfiltrated or retained. Immediate remediation is recommended.',
        sCenterIta))
    E.append(PageBreak())

    # Individual finding sections
    for idx, f in enumerate(findings, 1):
        sev = f.get('severity', 'MEDIUM').upper()
        hc  = _sev_color(sev)

        E.append(sev_badge(sev, f.get('cvss_score', '—')))
        E.append(Spacer(1, 0.35*cm))
        E.append(Paragraph(f'FINDING {idx} OF {n}',
            S(fontSize=10, fontName='Helvetica', textColor=MID_GRAY, alignment=TA_CENTER)))
        E.append(Spacer(1, 0.15*cm))
        E.append(Paragraph(f['title'],
            S(fontSize=16, fontName='Helvetica-Bold', textColor=DARK_GRAY, leading=22, alignment=TA_CENTER)))
        E.append(Spacer(1, 0.1*cm))
        E.append(Paragraph(f.get('subtitle', ''),
            S(fontSize=10, fontName='Helvetica', textColor=RED, alignment=TA_CENTER, leading=14)))
        E.append(Spacer(1, 0.5*cm))
        E.append(HRFlowable(width='100%', thickness=1, color=BORDER))
        E.append(Spacer(1, 0.4*cm))

        meta = [
            ['Target',    f'https://{target_name}'],
            ['Endpoint',  f.get('endpoint', 'N/A')],
            ['Date',      datetime.now().strftime('%Y-%m-%d')],
            ['Severity',  sev],
            ['CVSS v3.1', f"{f.get('cvss_score','—')} — {f.get('cvss_vector','N/A')}"],
            ['OWASP',     f.get('owasp', 'N/A')],
            ['Contact',   researcher_email],
        ]
        E.append(kv_table(meta, col1=3.8*cm))
        E.append(Spacer(1, 0.8*cm))

        E.append(sec_hdr(f'{idx}.1  Executive Summary', color=hc))
        E.append(Spacer(1, 0.3*cm))
        E.append(Paragraph(f.get('summary', 'No summary provided.'), sBody))
        E.append(Spacer(1, 0.3*cm))

        E.append(sec_hdr(f'{idx}.2  Proof of Concept', color=hc))
        E.append(Spacer(1, 0.3*cm))
        E.append(Paragraph('<b>Reproduction Steps</b>', sH2))
        E.append(code_block(f.get('poc', '# No PoC provided')))
        E.append(Spacer(1, 0.3*cm))

        E.append(sec_hdr(f'{idx}.3  Remediation', color=hc))
        E.append(Spacer(1, 0.3*cm))
        E.append(Paragraph(f.get('remediation', 'Consult OWASP guidelines for this vulnerability class.'), sBody))
        E.append(PageBreak())

    # About + engagement page
    E.append(sec_hdr('About the Security Researcher'))
    E.append(Spacer(1, 0.3*cm))
    E.append(kv_table([
        ['Role',          'Independent Cybersecurity Consultant & Penetration Tester'],
        ['Experience',    '15+ years in cybersecurity | 7+ years in AI & machine learning'],
        ['Specialisation','Web Application Penetration Testing, API Security, Red Teaming, AI-Integrated Security Tooling'],
        ['AI Expertise',  'Deep specialist in AI-driven security — expertise spans adversarial ML, automated vulnerability discovery, and AI-integrated penetration testing frameworks.'],
        ['UAE Ambition',  'Actively establishing an independent cybersecurity consultancy in the UAE — offering penetration testing, red team engagements, API security audits, and AI-powered security services to GCC businesses.'],
        ['Contact',       researcher_email],
    ], col1=3.8*cm))
    E.append(Spacer(1, 0.7*cm))

    offer_hdr = Table([[Paragraph(
        'Full Security Assessment — Available to Engage',
        S(fontSize=13, fontName='Helvetica-Bold', textColor=WHITE)
    )]], colWidths=[CW])
    offer_hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), DARK_GRAY),
        ('LEFTPADDING',   (0,0),(-1,-1), 14),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('BOX',           (0,0),(-1,-1), 1.5, ORANGE),
    ]))
    E.append(offer_hdr)
    E.append(Spacer(1, 0.3*cm))
    E.append(Paragraph(
        f'Having identified these vulnerabilities through independent research, I am available to conduct '
        f'a comprehensive, professional penetration test of the entire {target_name} platform — covering all '
        f'OWASP Top 10 and OWASP API Security Top 10 vulnerability classes, plus advanced attack scenarios '
        f'specific to your technology stack.<br/><br/>'
        f'This is not a surface-level automated scan. It is a deep, manual, intelligence-driven assessment '
        f'of the kind that found the vulnerabilities described in this report — the type that automated tools routinely miss.',
        sBody))
    E.append(Spacer(1, 0.3*cm))

    phases = [
        ['Reconnaissance',  'Subdomain enum, DNS, JS bundle analysis, API discovery, technology stack',      'Full'],
        ['Authentication',  'Login bypass, brute-force, credential stuffing, CAPTCHA analysis, JWT',         'Full'],
        ['Authorisation',   'IDOR/BOLA across all endpoints, BFLA, privilege escalation, access control',    'Full'],
        ['Injection',       'SQLi, NoSQLi, SSTI, Command Injection, SSRF, XXE, Path Traversal',              'Full'],
        ['Client-Side',     'XSS (Reflected, Stored, DOM), CSRF, Clickjacking, CSP bypass',                  'Full'],
        ['API Security',    'All OWASP API Top 10, REST/GraphQL, rate limiting, mass assignment',             'Full'],
        ['Business Logic',  'Payment bypass, coupon abuse, race conditions, IDOR on orders/invoices',        'Full'],
        ['Infrastructure',  'SSL/TLS, HTTP headers, server fingerprinting, exposed files/backups',            'Full'],
        ['Reporting',       'Executive summary + full technical PoC report with CVSS scores + remediation',   'Full'],
    ]
    ph = [Paragraph(h, sTableHdr) for h in ['Phase', 'Coverage', 'Depth']]
    pb = [[Paragraph(r[0], sTableCell), Paragraph(r[1], sTableCell), Paragraph(r[2], sTableCell)]
          for r in phases]
    pt = Table([ph] + pb, colWidths=[3.8*cm, 10.5*cm, 1.3*cm], repeatRows=1)
    pt.setStyle(TableStyle([
        ('BACKGROUND',     (0,0),(-1,0),  TABLE_HDR),
        ('ROWBACKGROUNDS', (0,1),(-1,-1), [TABLE_ALT, WHITE] * 10),
        ('GRID',           (0,0),(-1,-1), 0.3, BORDER),
        ('LEFTPADDING',    (0,0),(-1,-1), 7),
        ('TOPPADDING',     (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 5),
        ('VALIGN',         (0,0),(-1,-1), 'MIDDLE'),
    ]))
    E.append(pt)
    E.append(Spacer(1, 0.4*cm))
    E.append(kv_table([
        ['Engagement Rate',    '$1,500 / day'],
        ['Typical Engagement', '3–5 days for a thorough web application + API assessment'],
        ['Deliverable',        'Detailed technical report with CVSS scores, PoC evidence, screenshots, and prioritised remediation roadmap'],
        ['Availability',       'Available immediately — flexible scheduling'],
        ['Contact',            researcher_email],
    ], col1=4.5*cm))
    E.append(Spacer(1, 0.6*cm))
    E.append(Paragraph(
        'This report was produced as part of responsible, independent security research. No customer data was '
        'exfiltrated or retained. No systems were modified. Testing was limited strictly to confirming '
        'exploitability. I am happy to cooperate fully with your security team during remediation, provide '
        'a technical walkthrough, or answer any questions about the findings.',
        sSmall))

    doc.build(E, onFirstPage=cover_footer, onLaterPages=header_footer)
    return output_path
