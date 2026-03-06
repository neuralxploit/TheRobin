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
