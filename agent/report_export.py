"""
JSON & XML report export — same data as the PDF report.

Usage from the REPL:
    from agent.report_export import generate_json_report, generate_xml_report
    generate_json_report(_G, output_path='report.json')
    generate_xml_report(_G, output_path='report.xml')

Both functions use the same finding pipeline as report_pdf.py:
  - Aggregation from FINDINGS, SQLI_FINDINGS, XSS_FINDINGS, etc.
  - Junk filtering, smart deduplication
  - Professional title normalization
  - CVSS scoring with severity caps
  - ZDL risk calculation
  - Mitigation templates
  - OWASP classification
"""

import datetime
import json
import re as _re
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pathlib import Path

# Reuse everything from report_pdf — scoring, normalization, mitigation, etc.
from .report_pdf import (
    SEV_RANK,
    _normalize_title,
    _guess_cvss,
    _guess_owasp,
    _get_mitigation,
    _zdl_risk_for_pdf,
    _zdl_get_narrative,
    _ZDL_LIKELIHOOD_TEXTS,
    _ZDL_SEVERITY_TEXTS,
)


# ── Finding aggregation (shared with report_pdf.py) ─────────────────────────
# This duplicates the aggregation/dedup logic from generate_pdf_report() so
# that JSON/XML get the exact same cleaned finding list.

def _aggregate_findings(g: dict) -> list[dict]:
    """Aggregate, filter, dedup findings — identical to report_pdf pipeline."""

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

    # Filter junk
    _JUNK_RE = _re.compile(
        r'(findings?\s*:\s*\d+'
        r'|\d+\s*finding'
        r'|\bfound on \d+ \w+'
        r'|\d+ potential\b'
        r'|\bsummary\b|\btested\b|\bskipping\b|\bdone\b'
        r'|\bgood\b|\brejected\b|\bnot vulnerable\b|\bno\s+(issues|vulns?|findings?)\b'
        r'|\bphase\s+\d+\b|\bstored\s+\d+|\bchecked\b'
        r'|\bchains? found\b'
        r'|\binvestigate manually\b'
        r')',
        _re.IGNORECASE,
    )
    all_findings = [
        f for f in all_findings
        if not _JUNK_RE.search(f.get("title", ""))
        and len(f.get("title", "")) >= 8
    ]

    # ── Smart deduplication (same as report_pdf.py) ──────────────────
    _VULN_CATEGORIES = {
        'horizontal idor': 'Horizontal IDOR', 'vertical idor': 'Vertical IDOR',
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
        'command injection': 'Command Injection', 'cmdi': 'Command Injection',
        'xxe': 'XXE', 'xml external entity': 'XXE',
        'file upload': 'File Upload',
        'path traversal': 'Path Traversal', 'directory traversal': 'Path Traversal',
        'open redirect': 'Open Redirect', 'cors': 'CORS',
        'default credentials': 'Default Credentials',
        'account lockout': 'Account Lockout', 'no account lockout': 'Account Lockout',
        'password policy': 'Password Policy', 'weak password': 'Password Policy',
        'account enumeration': 'Account Enumeration',
        'information disclosure': 'Information Disclosure',
        'rate limit': 'Rate Limiting', 'no-rate-limit': 'Rate Limiting',
        'no rate limit': 'Rate Limiting',
        'api-docs': 'API Docs Exposed', 'api docs': 'API Docs Exposed',
        'swagger': 'API Docs Exposed', 'openapi': 'API Docs Exposed',
        'excessive data': 'Excessive Data Exposure',
        'hardcoded': 'Hardcoded Secrets',
        'business logic': 'Business Logic',
        'workflow bypass': 'Workflow Bypass', 'workflow-bypass': 'Workflow Bypass',
    }
    _COLLAPSE_ALL = {
        'Vertical IDOR', 'Unauthenticated API Access', 'Workflow Bypass', 'Rate Limiting',
        'Account Lockout', 'Password Policy', 'Account Enumeration', 'API Docs Exposed',
        'Default Credentials', 'Database Error Disclosure', 'Information Disclosure',
        'DOM XSS', 'Prototype Pollution', 'HTTP Smuggling', 'HTTP Method Override',
        'Metrics Exposed', 'Hardcoded Secrets', 'SSTI', 'Mass Assignment',
        'Excessive Data Exposure', 'Business Logic', 'Robots Disallowed Path',
    }

    def _extract_category(title):
        t = title.lower()
        for keyword, cat in sorted(_VULN_CATEGORIES.items(), key=lambda x: -len(x[0])):
            if keyword in t:
                return cat
        return None

    def _norm_url(url):
        u = _re.sub(r'[?#].*$', '', (url or "")).rstrip("/").lower()
        u = _re.sub(r'/\d+', '/N', u)
        return u

    def _norm_title(title):
        t = title.lower().strip()
        t = _re.sub(r'^\[?(critical|high|medium|low|info)\]?\s*[:\-—]*\s*', '', t)
        t = _re.sub(r'[\s\-—:]+', ' ', t).strip()
        t = _re.sub(r'https?://\S+', '', t).strip()
        return t

    seen_exact = set()
    collapse_map = {}
    category_url_map = {}
    title_map = {}
    deduped = []

    for f in all_findings:
        title = f.get("title", "")
        url = f.get("url", "")
        exact_key = (title, url)
        if exact_key in seen_exact:
            continue
        seen_exact.add(exact_key)

        norm_url = _norm_url(url)
        norm_title = _norm_title(title)
        category = _extract_category(title)
        sev_rank = SEV_RANK.get(f.get("severity", "INFO").upper(), 4)

        if category:
            if category in _COLLAPSE_ALL:
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
                cat_key = (category, norm_url)
                if cat_key in category_url_map:
                    existing_f, existing_rank = category_url_map[cat_key]
                    if sev_rank < existing_rank:
                        deduped[deduped.index(existing_f)] = f
                        category_url_map[cat_key] = (f, sev_rank)
                    continue
                category_url_map[cat_key] = (f, sev_rank)
        else:
            title_key = (norm_title, norm_url)
            if title_key in title_map:
                existing_f, existing_rank = title_map[title_key]
                if sev_rank < existing_rank:
                    deduped[deduped.index(existing_f)] = f
                    title_map[title_key] = (f, sev_rank)
                continue
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

    # Annotate collapsed findings
    for category, (best_f, _, count, urls) in collapse_map.items():
        if count > 1:
            real_urls = {u for u in urls if u}
            if real_urls:
                best_f["title"] = f"{best_f['title']} (+{count - 1} more endpoints)"
            else:
                best_f["title"] = f"{best_f['title']} ({count} instances)"

    return deduped


# ── Build enriched finding dict ──────────────────────────────────────────────

def _enrich_finding(f: dict, index: int) -> dict:
    """Build a fully enriched finding dict with all report fields."""
    sev = f.get("severity", "INFO").upper()
    raw_title = f.get("title", "Unknown")
    title = _normalize_title(raw_title)
    url = f.get("url", "")
    detail = f.get("detail", {}) if isinstance(f.get("detail"), dict) else {}

    description = f.get("description", detail.get("description", ""))
    impact = f.get("impact", detail.get("impact", ""))
    evidence = f.get("evidence", detail.get("evidence", ""))
    poc = f.get("poc", detail.get("poc", ""))
    request_raw = f.get("request", detail.get("request", ""))
    response_raw = f.get("response", detail.get("response", ""))
    test_code = f.get("test_code", detail.get("test_code", ""))
    remediation_custom = f.get("remediation", detail.get("remediation", ""))

    # CVSS
    raw_cvss = f.get("cvss", detail.get("cvss", ""))
    cvss_str = str(raw_cvss) if raw_cvss and str(raw_cvss) != "—" else _guess_cvss(raw_title, sev)
    cvss_score = ""
    cvss_vector = ""
    if cvss_str and cvss_str != "—":
        parts = cvss_str.split(" ", 1)
        cvss_score = parts[0]
        if len(parts) > 1:
            cvss_vector = parts[1].strip("()")

    # OWASP
    owasp = _guess_owasp(raw_title)

    # ZDL Risk
    lkl, sc_idx, sc_val, risk_val, risk_label = _zdl_risk_for_pdf(raw_title, sev, cvss_str)
    default_lkl = (
        f"The likelihood of this vulnerability being exploited is rated as {risk_label}. "
        "The finding was confirmed during testing and represents a real attack surface."
    )
    default_sev = (
        "When successfully exploited, this vulnerability may impact the confidentiality, "
        "integrity, or availability of the application and its data."
    )
    lkl_text = _zdl_get_narrative(raw_title, _ZDL_LIKELIHOOD_TEXTS, default_lkl)
    sev_text = _zdl_get_narrative(raw_title, _ZDL_SEVERITY_TEXTS, default_sev)

    # Mitigation
    mitigation = _get_mitigation(raw_title)
    mit_desc = mitigation.get("desc", "")
    mit_steps = mitigation.get("steps", [])
    mit_refs = mitigation.get("refs", [])

    # Use template description if finding has none
    if not description and mit_desc:
        description = mit_desc

    # Hosts affected
    hosts = [url] if url and url != "—" else []
    affected = f.get("affected_endpoints", detail.get("affected_endpoints", []))
    if isinstance(affected, str):
        affected = [affected]
    for ep in affected:
        ep_str = ep.get("url", str(ep)) if isinstance(ep, dict) else str(ep)
        if ep_str and ep_str not in hosts:
            hosts.append(ep_str)

    return {
        "id": f"FINDING-{index:03d}",
        "index": index,
        "title": title,
        "severity": sev,
        "cvss": {
            "score": cvss_score,
            "vector": cvss_vector,
        },
        "owasp_category": owasp,
        "risk": {
            "zdl_label": risk_label,
            "zdl_value": round(risk_val, 2),
            "likelihood": lkl,
            "likelihood_text": lkl_text,
            "severity_value": sc_val,
            "severity_text": sev_text,
        },
        "hosts_affected": hosts,
        "description": description,
        "impact": impact,
        "proof_of_concept": {
            "evidence": evidence,
            "request": request_raw,
            "response": response_raw,
            "test_code": test_code,
            "poc_command": poc,
        },
        "remediation": {
            "description": mit_desc,
            "steps": mit_steps,
            "custom": remediation_custom,
            "references": [
                {"title": ref[0], "url": ref[1]} for ref in mit_refs
            ],
        },
    }


# ── JSON Report ──────────────────────────────────────────────────────────────

def generate_json_report(g: dict, output_path: str = "report.json") -> str:
    """Generate a structured JSON pentest report.

    Parameters
    ----------
    g : dict
        The _G persistent globals dict from the REPL.
    output_path : str
        Where to write the JSON file.

    Returns
    -------
    str : the output file path
    """
    target = g.get("BASE", g.get("target", "Unknown"))
    scope = g.get("SCOPE", target)
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    all_findings = _aggregate_findings(g)

    # Severity counts
    counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Enrich each finding
    enriched = [_enrich_finding(f, i) for i, f in enumerate(all_findings, 1)]

    report = {
        "report": {
            "title": f"Penetration Test Report — {target}",
            "generator": "TheRobin — AI Penetration Testing Framework",
            "version": "1.0",
            "date": date_str,
            "target": target,
            "scope": scope,
        },
        "summary": {
            "total_findings": len(all_findings),
            "severity_distribution": {
                "critical": counts.get("CRITICAL", 0),
                "high": counts.get("HIGH", 0),
                "medium": counts.get("MEDIUM", 0),
                "low": counts.get("LOW", 0),
                "info": counts.get("INFO", 0),
            },
        },
        "findings": enriched,
    }

    # Write
    out = Path(output_path)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out)


# ── XML Report ───────────────────────────────────────────────────────────────

def _add_text_element(parent: ET.Element, tag: str, text: str) -> ET.Element:
    """Add a child element with text content."""
    el = ET.SubElement(parent, tag)
    el.text = str(text) if text else ""
    return el


def generate_xml_report(g: dict, output_path: str = "report.xml") -> str:
    """Generate a structured XML pentest report.

    Parameters
    ----------
    g : dict
        The _G persistent globals dict from the REPL.
    output_path : str
        Where to write the XML file.

    Returns
    -------
    str : the output file path
    """
    target = g.get("BASE", g.get("target", "Unknown"))
    scope = g.get("SCOPE", target)
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    all_findings = _aggregate_findings(g)

    # Severity counts
    counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Build XML tree
    root = ET.Element("pentest_report")
    root.set("generator", "TheRobin")
    root.set("version", "1.0")

    # Report metadata
    meta = ET.SubElement(root, "metadata")
    _add_text_element(meta, "title", f"Penetration Test Report — {target}")
    _add_text_element(meta, "date", date_str)
    _add_text_element(meta, "target", target)
    _add_text_element(meta, "scope", scope)
    _add_text_element(meta, "generator", "TheRobin — AI Penetration Testing Framework")

    # Summary
    summary = ET.SubElement(root, "summary")
    _add_text_element(summary, "total_findings", str(len(all_findings)))
    dist = ET.SubElement(summary, "severity_distribution")
    for sev_name in ("critical", "high", "medium", "low", "info"):
        _add_text_element(dist, sev_name, str(counts.get(sev_name.upper(), 0)))

    # Findings
    findings_el = ET.SubElement(root, "findings")

    for i, f in enumerate(all_findings, 1):
        enriched = _enrich_finding(f, i)
        finding_el = ET.SubElement(findings_el, "finding")
        finding_el.set("id", enriched["id"])
        finding_el.set("severity", enriched["severity"])

        _add_text_element(finding_el, "title", enriched["title"])
        _add_text_element(finding_el, "severity", enriched["severity"])

        # CVSS
        cvss_el = ET.SubElement(finding_el, "cvss")
        _add_text_element(cvss_el, "score", enriched["cvss"]["score"])
        _add_text_element(cvss_el, "vector", enriched["cvss"]["vector"])

        _add_text_element(finding_el, "owasp_category", enriched["owasp_category"])

        # Risk
        risk_el = ET.SubElement(finding_el, "risk")
        _add_text_element(risk_el, "zdl_label", enriched["risk"]["zdl_label"])
        _add_text_element(risk_el, "zdl_value", str(enriched["risk"]["zdl_value"]))
        _add_text_element(risk_el, "likelihood", str(enriched["risk"]["likelihood"]))
        _add_text_element(risk_el, "likelihood_text", enriched["risk"]["likelihood_text"])
        _add_text_element(risk_el, "severity_value", str(enriched["risk"]["severity_value"]))
        _add_text_element(risk_el, "severity_text", enriched["risk"]["severity_text"])

        # Hosts
        hosts_el = ET.SubElement(finding_el, "hosts_affected")
        for host in enriched["hosts_affected"]:
            _add_text_element(hosts_el, "host", host)

        # Description
        _add_text_element(finding_el, "description", enriched["description"])
        _add_text_element(finding_el, "impact", enriched["impact"])

        # POC
        poc_el = ET.SubElement(finding_el, "proof_of_concept")
        _add_text_element(poc_el, "evidence", enriched["proof_of_concept"]["evidence"])
        _add_text_element(poc_el, "request", enriched["proof_of_concept"]["request"])
        _add_text_element(poc_el, "response", enriched["proof_of_concept"]["response"])
        _add_text_element(poc_el, "test_code", enriched["proof_of_concept"]["test_code"])
        _add_text_element(poc_el, "poc_command", enriched["proof_of_concept"]["poc_command"])

        # Remediation
        rem_el = ET.SubElement(finding_el, "remediation")
        _add_text_element(rem_el, "description", enriched["remediation"]["description"])
        steps_el = ET.SubElement(rem_el, "steps")
        for step in enriched["remediation"]["steps"]:
            _add_text_element(steps_el, "step", step)
        _add_text_element(rem_el, "custom", enriched["remediation"]["custom"])
        refs_el = ET.SubElement(rem_el, "references")
        for ref in enriched["remediation"]["references"]:
            ref_el = ET.SubElement(refs_el, "reference")
            _add_text_element(ref_el, "title", ref["title"])
            _add_text_element(ref_el, "url", ref["url"])

    # Pretty-print XML
    rough_string = ET.tostring(root, encoding="unicode", xml_declaration=False)
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ", encoding=None)
    # Remove extra blank lines minidom adds
    pretty_xml = "\n".join(line for line in pretty_xml.split("\n") if line.strip())

    out = Path(output_path)
    out.write_text(pretty_xml, encoding="utf-8")
    return str(out)
