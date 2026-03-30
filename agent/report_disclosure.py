"""
Disclosure Report Generator.
High-fidelity, single-vulnerability PDF template for critical findings.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, Image, KeepTogether,
                                 PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus.flowables import HRFlowable

# ── Colour palette ──────────────────────────────────────────────────
RED       = colors.HexColor('#C0392B')
DARK_RED  = colors.HexColor('#922B21')
ORANGE    = colors.HexColor('#E67E22')
DARK_GRAY = colors.HexColor('#2C3E50')
MID_GRAY  = colors.HexColor('#566573')
LIGHT_BG  = colors.HexColor('#FDFEFE')
TABLE_HDR = colors.HexColor('#2C3E50')
TABLE_ALT = colors.HexColor('#F2F3F4')
RED_BADGE = colors.HexColor('#FDEDEC')
ORANGE_BG = colors.HexColor('#FEF9E7')
GREEN_BG  = colors.HexColor('#EAFAF1')
BORDER    = colors.HexColor('#AEB6BF')
WHITE     = colors.white

W, H = A4   # 595 x 842 pts

def generate_disclosure_report(finding, target_info, output_path, session_dir):
    """
    Generates a high-fidelity disclosure report for a single finding.
    
    finding: dict from _G['FINDINGS']
    target_info: dict with { 'name': '...', 'url': '...', 'contact': '...' }
    output_path: str destination for the PDF
    session_dir: str directory to look for screenshots
    """
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2.2*cm,
        title=f"Security Vulnerability Disclosure — {target_info.get('name', 'Target')}",
    )

    styles = getSampleStyleSheet()

    def S(name, **kw):
        base = kw.pop('parent', 'Normal')
        return ParagraphStyle(name, parent=styles[base], **kw)

    # ── Custom styles ────────────────────────────────────────────────────
    sTitle      = S('sTitle',      fontSize=22, leading=28, textColor=DARK_GRAY, fontName='Helvetica-Bold', spaceAfter=4)
    sSubtitle   = S('sSubtitle',   fontSize=12, leading=16, textColor=RED, fontName='Helvetica-Bold', spaceAfter=2)
    sMeta       = S('sMeta',       fontSize=9,  leading=13, textColor=MID_GRAY, fontName='Helvetica')
    sBody       = S('sBody',       fontSize=9.5, leading=14, textColor=DARK_GRAY, fontName='Helvetica', spaceAfter=6, alignment=TA_JUSTIFY)
    sBodyBold   = S('sBodyBold',   fontSize=9.5, leading=14, textColor=DARK_GRAY, fontName='Helvetica-Bold', spaceAfter=4)
    sH1         = S('sH1',         fontSize=13, leading=18, textColor=WHITE, fontName='Helvetica-Bold', spaceAfter=0, spaceBefore=14)
    sH2         = S('sH2',         fontSize=11, leading=15, textColor=DARK_GRAY, fontName='Helvetica-Bold', spaceAfter=4, spaceBefore=10)
    sCode       = S('sCode',       fontSize=8,  leading=12, textColor=colors.HexColor('#1A5276'), fontName='Courier', spaceAfter=4, backColor=colors.HexColor('#EBF5FB'), leftIndent=8, rightIndent=8)
    sBadge      = S('sBadge',      fontSize=14, leading=20, textColor=RED, fontName='Helvetica-Bold', spaceAfter=0, alignment=TA_CENTER)
    sSmall      = S('sSmall',      fontSize=8,  leading=11, textColor=MID_GRAY, fontName='Helvetica')
    sFooter     = S('sFooter',     fontSize=7.5, leading=10, textColor=MID_GRAY, fontName='Helvetica', alignment=TA_CENTER)
    sTableCell  = S('sTableCell',  fontSize=8.5, leading=12, textColor=DARK_GRAY, fontName='Helvetica')
    sTableHdr   = S('sTableHdr',   fontSize=8.5, leading=12, textColor=WHITE, fontName='Helvetica-Bold')

    # ── Header/footer callbacks ──────────────────────────────────────────
    def _page_header_footer(canvas, doc):
        canvas.saveState()
        W_pt, H_pt = A4
        # Top bar
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, H_pt - 1.2*cm, W_pt, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.drawString(2*cm, H_pt - 0.8*cm, 'SECURITY VULNERABILITY DISCLOSURE')
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(W_pt - 2*cm, H_pt - 0.8*cm, f"CONFIDENTIAL  |  {target_info.get('url', 'target.com')}")
        # Bottom bar
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, 0, W_pt, 1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(2*cm, 0.35*cm, f'© {datetime.now().year} — Independent Security Research  |  {target_info.get("researcher_email", "cybersecdo@gmail.com")}')
        canvas.drawRightString(W_pt - 2*cm, 0.35*cm, f'Page {doc.page}')
        canvas.restoreState()

    def _cover_no_header(canvas, doc):
        canvas.saveState()
        W_pt, H_pt = A4
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, 0, W_pt, 1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(2*cm, 0.35*cm, 'CONFIDENTIAL — FOR SECURITY TEAM USE ONLY')
        canvas.drawRightString(W_pt - 2*cm, 0.35*cm, datetime.now().strftime('%Y-%m-%d'))
        canvas.restoreState()

    # ── Helper builders ──────────────────────────────────────────────────
    def section_header(title):
        t = Table([[Paragraph(title, sH1)]], colWidths=[W - 4*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), DARK_GRAY),
            ('LEFTPADDING',  (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING',   (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('ROUNDEDCORNERS', [3]),
        ]))
        return t

    def kv_table(rows, col_widths=None):
        if col_widths is None:
            col_widths = [4.5*cm, W - 4*cm - 4.5*cm]
        data = [[Paragraph(k, sBodyBold), Paragraph(v, sBody)] for k,v in rows]
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (0,-1), colors.HexColor('#EBF5FB')),
            ('BACKGROUND',   (1,0), (1,-1), LIGHT_BG),
            ('GRID',         (0,0), (-1,-1), 0.4, BORDER),
            ('LEFTPADDING',  (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING',   (0,0), (-1,-1), 5),
            ('BOTTOMPADDING',(0,0), (-1,-1), 5),
            ('VALIGN',       (0,0), (-1,-1), 'TOP'),
        ]))
        return t

    def data_table(headers, rows, col_widths=None):
        hdr = [Paragraph(h, sTableHdr) for h in headers]
        body = []
        for i, row in enumerate(rows):
            body.append([Paragraph(str(c), sTableCell) for c in row])
        t = Table([hdr] + body, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (-1,0),  TABLE_HDR),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [TABLE_ALT, WHITE]),
            ('GRID',         (0,0), (-1,-1), 0.3, BORDER),
            ('LEFTPADDING',  (0,0), (-1,-1), 7),
            ('RIGHTPADDING', (0,0), (-1,-1), 7),
            ('TOPPADDING',   (0,0), (-1,-1), 5),
            ('BOTTOMPADDING',(0,0), (-1,-1), 5),
            ('VALIGN',       (0,0), (-1,-1), 'TOP'),
            ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ]))
        return t

    def code_block(text):
        if not text: return Spacer(1, 0.1)
        lines = [Paragraph(line.replace(' ', '&nbsp;').replace('<', '&lt;').replace('>', '&gt;'), sCode) for line in text.split('\n')]
        t = Table([[l] for l in lines], colWidths=[W - 4*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (-1,-1), colors.HexColor('#EBF5FB')),
            ('LEFTPADDING',  (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING',   (0,0), (-1,-1), 2),
            ('BOTTOMPADDING',(0,0), (-1,-1), 2),
            ('BOX',          (0,0), (-1,-1), 0.8, colors.HexColor('#2980B9')),
        ]))
        return t

    E = []
    sev = finding.get('severity', 'HIGH').upper()
    cvss_str = finding.get('cvss', '—')

    # COVER PAGE
    E.append(Spacer(1, 1.5*cm))
    badge_data = [[ Paragraph(f'⚠  {sev} SEVERITY  —  CVSS v3.1: {cvss_str.split(" ")[0]}', sBadge) ]]
    badge_tbl = Table(badge_data, colWidths=[W - 4*cm])
    badge_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), RED_BADGE),
        ('BOX',          (0,0), (-1,-1), 1.5, RED),
        ('TOPPADDING',   (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0), (-1,-1), 10),
    ]))
    E.append(badge_tbl)
    E.append(Spacer(1, 0.6*cm))

    E.append(Paragraph('SECURITY VULNERABILITY REPORT', S('ct', fontSize=11, fontName='Helvetica', textColor=MID_GRAY, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.3*cm))
    E.append(Paragraph(finding.get('title', 'Vulnerability Found'), S('ct2', fontSize=18, fontName='Helvetica-Bold', textColor=DARK_GRAY, leading=24, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.15*cm))
    E.append(Paragraph(finding.get('impact', 'Potential security risk identified'), S('ct3', fontSize=11, fontName='Helvetica', textColor=RED, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.8*cm))
    E.append(HRFlowable(width='100%', thickness=1.5, color=RED))
    E.append(Spacer(1, 0.6*cm))

    cover_meta = [
        ['Target',   target_info.get('url', 'Unknown')],
        ['Endpoint', finding.get('url', 'N/A')],
        ['Date',     datetime.now().strftime('%Y-%m-%d')],
        ['Severity', sev],
        ['CVSS v3.1', cvss_str],
        ['Impact',   finding.get('impact', 'N/A')],
        ['Contact',  target_info.get('researcher_email', 'cybersecdo@gmail.com')],
    ]
    E.append(kv_table(cover_meta, col_widths=[3.8*cm, W - 4*cm - 3.8*cm]))
    E.append(Spacer(1, 1*cm))
    E.append(Paragraph('This report is submitted in good faith as part of responsible disclosure. Testing was limited to confirming the vulnerability exists. Immediate remediation is recommended.', S('disc', fontSize=9, fontName='Helvetica-Oblique', textColor=MID_GRAY, alignment=TA_CENTER)))
    E.append(PageBreak())

    # 1. EXECUTIVE SUMMARY
    E.append(section_header('1. Executive Summary'))
    E.append(Spacer(1, 0.3*cm))
    summary_text = f"A {sev.lower()} severity vulnerability was identified on the {target_info.get('name', 'target')} platform. "
    summary_text += f"The endpoint <b>{finding.get('url', 'N/A')}</b> is susceptible to <b>{finding.get('title', 'security issues')}</b>. "
    summary_text += f"<br/><br/>{finding.get('impact', '')}"
    E.append(Paragraph(summary_text, sBody))
    E.append(Spacer(1, 0.3*cm))

    # 2. TECHNICAL DETAILS
    E.append(section_header('2. Technical Details'))
    E.append(Spacer(1, 0.3*cm))
    tech_rows = [
        ['Vulnerable URL', finding.get('url', 'N/A')],
        ['HTTP Method',    finding.get('method', 'GET')],
        ['Parameter',      finding.get('param', 'N/A')],
        ['Payload',        finding.get('payload', 'N/A')],
    ]
    E.append(kv_table(tech_rows, col_widths=[3.8*cm, W - 4*cm - 3.8*cm]))
    E.append(Spacer(1, 0.4*cm))

    # 3. PROOF OF CONCEPT
    E.append(section_header('3. Proof of Concept'))
    E.append(Spacer(1, 0.3*cm))
    E.append(Paragraph('<b>reproduction Steps</b>', sH2))
    poc_text = finding.get('poc', 'No PoC provided.')
    E.append(code_block(poc_text))
    E.append(Spacer(1, 0.4*cm))

    # 4. EVIDENCE
    E.append(section_header('4. Screenshot Evidence'))
    E.append(Spacer(1, 0.3*cm))
    ss_file = finding.get('screenshot')
    if ss_file:
        ss_path = Path(session_dir) / ss_file
        if ss_path.exists():
            E.append(Paragraph(f'<b>Figure 1:</b> Proof of vulnerability for {finding.get("title")}', sSmall))
            E.append(Spacer(1, 0.2*cm))
            img = Image(str(ss_path), width=W - 4*cm, height=10*cm, kind='proportional')
            E.append(img)
        else:
            E.append(Paragraph(f"[Screenshot {ss_file} not found in {session_dir}]", sBody))
    else:
        E.append(Paragraph("No screenshot evidence provided.", sBody))
    
    E.append(PageBreak())

    # 5. REMEDIATION
    E.append(section_header('5. Remediation Recommendations'))
    E.append(Spacer(1, 0.3*cm))
    rem_text = finding.get('remediation', 'Consult security best practices for this vulnerability type.')
    E.append(Paragraph(rem_text, sBody))
    E.append(PageBreak())

    # 6. ABOUT
    E.append(section_header('6. About the Security Researcher'))
    E.append(Spacer(1, 0.3*cm))
    about_rows = [
        ['Role', 'Independent Cybersecurity Consultant'],
        ['Contact', target_info.get('researcher_email', 'cybersecdo@gmail.com')],
    ]
    E.append(kv_table(about_rows))
    E.append(Spacer(1, 1*cm))
    
    # Engagement box
    offer_content = [
        [Paragraph('💼  Full Security Assessment — Available to Engage', S('oh', fontSize=13, fontName='Helvetica-Bold', textColor=WHITE))],
        [Paragraph(f'I am available to conduct a comprehensive security audit of {target_info.get("name")}.', S('ob', fontSize=10, fontName='Helvetica', textColor=WHITE, leading=15))],
    ]
    offer_tbl = Table(offer_content, colWidths=[W - 4*cm])
    offer_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), DARK_GRAY),
        ('LEFTPADDING',  (0,0), (-1,-1), 16),
        ('BOX',          (0,0), (-1,-1), 1.5, ORANGE),
    ]))
    E.append(offer_tbl)

    doc.build(E, onFirstPage=_cover_no_header, onLaterPages=_page_header_footer)
    return output_path
