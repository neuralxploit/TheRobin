**Phase 2 — Security Headers**
  Check response headers and report with ACCURATE severity — do NOT over-rate headers.
  Missing headers are defence-in-depth controls, not direct vulnerabilities.

  Use EXACTLY these severities (based on OWASP and industry standard):

  Content-Security-Policy missing      → [MEDIUM]
    Reason: reduces XSS impact but is not itself exploitable. No direct attack path.

  Strict-Transport-Security missing    → [MEDIUM]
    Reason: only exploitable via active MITM/SSL-stripping. Site already on HTTPS.

  X-Frame-Options missing              → [LOW]
    Reason: clickjacking requires specific page content + social engineering.
    Upgrade to [MEDIUM] ONLY if the page has sensitive one-click actions (money transfers, deletes).

  X-Content-Type-Options missing       → [LOW]
    Reason: MIME-sniffing attacks are rare in modern browsers.

  Referrer-Policy missing              → [LOW]
    Reason: only leaks URLs to third-party resources. No direct exploit.

  Permissions-Policy missing           → [LOW]
    Reason: controls camera/mic/geo APIs — not a risk unless the app uses them.

  X-Powered-By / Server version leak  → [LOW]
    Reason: aids reconnaissance. Upgrade to [MEDIUM] only if version has active CVEs.

  DO NOT report X-XSS-Protection as a finding — it is deprecated since 2019,
  removed from Chrome/Firefox. Its absence is correct and expected.

  PRESENT as a clean table:
    print(f"{'Header':<35} {'Status':<10} {'Severity'}")
    print("-" * 60)
    for each header: print present (✓ [INFO]) or missing (✗ [SEVERITY])

---

**MANDATORY — Store header findings before moving on:**

After printing the header table above, store each missing header as a finding:

```python
_G.setdefault('FINDINGS', [])

_header_severity = {
    'Content-Security-Policy': 'MEDIUM',
    'Strict-Transport-Security': 'MEDIUM',
    'X-Frame-Options': 'LOW',
    'X-Content-Type-Options': 'LOW',
    'Referrer-Policy': 'LOW',
    'Permissions-Policy': 'LOW',
}

for _hdr, _sev in _header_severity.items():
    if _hdr.lower() not in [h.lower() for h in _resp_headers.keys()]:
        _G['FINDINGS'].append({
            'severity': _sev,
            'title': f'Missing Security Header: {_hdr}',
            'url': BASE,
            'evidence': f'Header {_hdr} was not present in the server response',
            'impact': f'Missing {_hdr} header may allow attacks like clickjacking, MIME sniffing, or content injection',
        })

# Server/version disclosure
for _hdr in ('Server', 'X-Powered-By'):
    if _hdr in _resp_headers:
        _G['FINDINGS'].append({
            'severity': 'LOW',
            'title': f'Server Version Disclosure: {_hdr}: {_resp_headers[_hdr]}',
            'url': BASE,
            'evidence': f'{_hdr}: {_resp_headers[_hdr]}',
            'impact': 'Technology fingerprinting aids targeted attacks',
        })

# Cookie flags
import requests as _req
_r = _req.get(BASE, verify=False, allow_redirects=True)
for _ck in _r.cookies:
    if not _ck.secure:
        _G['FINDINGS'].append({
            'severity': 'HIGH', 'title': f'Cookie Missing Secure Flag: {_ck.name}',
            'url': BASE, 'evidence': f'Cookie {_ck.name} does not have the Secure flag set',
            'impact': 'Cookie transmitted over unencrypted connections',
        })
    if not _ck.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(_ck).lower():
        _G['FINDINGS'].append({
            'severity': 'MEDIUM', 'title': f'Cookie Missing HttpOnly Flag: {_ck.name}',
            'url': BASE, 'evidence': f'Cookie {_ck.name} does not have the HttpOnly flag set',
            'impact': 'Cookie accessible to JavaScript — XSS can steal session',
        })

print(f"[+] Stored {len(_G['FINDINGS'])} header/cookie findings")
```
