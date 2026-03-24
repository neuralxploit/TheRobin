PHASE 3.5 — JAVASCRIPT SECRET SCANNING (MANDATORY)
   ═══════════════════════════════════════════════════════
   Scan ALL discovered JavaScript files for hardcoded secrets, API keys,
   credentials, internal endpoints, and sensitive data. This is MANDATORY
   for finding information disclosure vulnerabilities.

   Run this IMMEDIATELY after the authenticated crawl and ID harvesting:

     ```python
     import re, base64, json
     from urllib.parse import urljoin, urlparse
     from bs4 import BeautifulSoup

     BASE       = _G['BASE']
     AUTH_PAGES = _G['AUTH_PAGES']
     session    = _G['session']

     # ── Secret patterns ─────────────────────────────────────────────────────
     # Each entry: (pattern, flags)
     # API_KEY patterns are case-SENSITIVE — AWS/GitHub/Stripe formats are strict.
     # Do NOT use re.IGNORECASE on API_KEY patterns; it causes false positives
     # (e.g. AKIASIOcg0ACwwBC0EAI has lowercase letters so it is NOT a real AWS key).
    JS_SECRET_PATTERNS = {
        'API_KEY': [
            # Google API key (case-sensitive prefix AIza)
            (r'AIza[A-Za-z0-9_\-]{35}', 0),
            # AWS long-term key: MUST be AKIA + exactly 16 UPPERCASE alphanumeric
            (r'AKIA[A-Z0-9]{16}(?![A-Z0-9])', 0),
            # AWS temporary STS key
            (r'ASIA[A-Z0-9]{16}(?![A-Z0-9])', 0),
            # AWS other IAM identifiers
            (r'(?:AGPA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}(?![A-Z0-9])', 0),
            # Firebase API Key
            (r'AIzaSy[A-Za-z0-9_\-]{33}', 0),
            # Azure Search/Storage
            (r'[a-zA-Z0-9]{32}AzSe[a-zA-Z0-9]{8}', 0),
            # DigitalOcean
            (r'dop_v1_[a-f0-9]{64}', 0),
            # Heroku
            (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 0),
            # Stripe live/test secret key (exactly 24 chars after prefix)
            (r'sk_live_[A-Za-z0-9]{24}(?![A-Za-z0-9])', 0),
            (r'sk_test_[A-Za-z0-9]{24}(?![A-Za-z0-9])', 0),
            (r'rk_live_[A-Za-z0-9]{24}(?![A-Za-z0-9])', 0),
            # GitHub tokens (strict prefix + exact length)
            (r'ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])', 0),
            (r'gho_[A-Za-z0-9]{36}(?![A-Za-z0-9])', 0),
            (r'ghs_[A-Za-z0-9]{36}(?![A-Za-z0-9])', 0),
            (r'ghr_[A-Za-z0-9]{36}(?![A-Za-z0-9])', 0),
            (r'github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])', 0),
            # Slack (strict digit-block format — no IGNORECASE)
            (r'xoxb-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{24}', 0),
            (r'xoxp-[0-9]{8,13}-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{32}', 0),
            # SendGrid API key
            (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 0),
            # Private key PEM headers
            (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 0),
            # Twilio auth token
            (r'SK[a-f0-9]{32}', 0),
            # Mailgun API key
            (r'key-[a-f0-9]{32}', 0),
        ],
        'API_ENDPOINT_HINT': [
            # Extracts potential hidden API routes from JS strings
            (r'["\'](/(?:api|v[0-9]|rest|gql|graph|admin|v1|v2|v3)/[a-zA-Z0-9_\-/]+)["\']', 0),
        ],
        'SECRET_TOKEN': [

             # keyword = "value" or keyword: "value" with quotes required.
             # Value must be 20+ chars. Word boundary on the keyword.
             (r'\b(?:secret[_\-]?key|api[_\-]?secret|jwt[_\-]?secret|signing[_\-]?key|encryption[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-\.]{20,})["\']', re.IGNORECASE),
             (r'\b(?:auth[_\-]?token|access[_\-]?token|client[_\-]?secret|bearer[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-\.]{20,})["\']', re.IGNORECASE),
             (r'\b(?:private[_\-]?key|hmac[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-\.]{20,})["\']', re.IGNORECASE),
         ],
         'HARDCODED_CREDS': [
             # password/passwd with word boundary, value in quotes, 8+ non-trivial chars
             # Excludes template vars ${}, HTML entities, paths, empty strings
             (r'\bpassword\s*[:=]\s*["\']([^"\'<>${}\s\\]{8,})["\']', re.IGNORECASE),
             (r'\bpasswd\s*[:=]\s*["\']([^"\'<>${}\s\\]{8,})["\']', re.IGNORECASE),
             (r'\bdb[_\-]?pass(?:word)?\s*[:=]\s*["\']([^"\'<>${}\s\\]{8,})["\']', re.IGNORECASE),
         ],
         'INTERNAL_ENDPOINT': [
             # RFC-1918 private IP ranges only
             (r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)(?::\d+)?(?:/[^\s"\']*)?', 0),
             # .internal / .corp / .intranet / .lan TLDs
             # Use (?:label.)+ so the greedy group doesn't consume the TLD
             (r'https?://(?:[a-zA-Z0-9\-]+\.)+(?:internal|corp|intranet|lan)\b(?:/[^\s"\'<>]*)?', 0),
         ],
     }

     # ── Known false-positive placeholder values ──────────────────────────────
     _FP_EXACT = {
         '', 'null', 'none', 'undefined', 'true', 'false',
         'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
         'your_password', 'yourpassword', 'your_secret', 'yoursecret',
         'your_token', 'yourtoken', 'your_key', 'yourkey', 'your_api_key',
         'changeme', 'change_me', 'replace_me', 'replaceme', 'insert_here',
         'example', 'sample', 'test', 'demo', 'placeholder', 'dummy',
         'password123', 'secret123', 'admin123', 'hunter2', 'letmein',
         'mysecret', 'mysecretkey', 'secretkey', 'secretvalue',
         'xxxxxxxxxxxxxxxx', 'aaaaaaaaaaaaaaaa', '1234567890123456',
         'abcdefghijklmnop', 'abcdefgh', '12345678',
         'enter_your_key_here', 'put_key_here', 'add_your_key',
         '<your-api-key>', '<secret>', '<token>', '<password>', '<key>',
         '${api_key}', '${secret}', '${password}', '${token}', '${key}',
     }

     _FP_REGEX = [
         re.compile(r'^\$\{[^}]+\}$'),            # ${ANY_VAR}
         re.compile(r'^<[a-z_\-]+>$'),             # <placeholder>
         re.compile(r'^[x*#\-]{6,}$'),             # masked: xxxxxxxx
         re.compile(r'^[a-f0-9]{32}$', re.I),      # MD5 hash
         re.compile(r'^[a-f0-9]{40}$', re.I),      # SHA-1 hash
         re.compile(r'^[a-f0-9]{64}$', re.I),      # SHA-256 hash
         re.compile(r'^[a-f0-9]{128}$', re.I),     # SHA-512 hash
         re.compile(r'^\d+$'),                      # pure numbers
         re.compile(r'^[a-z_]+\.[a-z_]+$', re.I),  # dotted var refs
         re.compile(r'^/[a-zA-Z]'),                 # filesystem paths
         re.compile(r'^https?://', re.I),            # URLs (not secrets)
     ]

     def _is_fp(value):
         v = value.strip()
         if v.lower() in _FP_EXACT:
             return True
         for pat in _FP_REGEX:
             if pat.match(v):
                 return True
         # Low-entropy: fewer than 4 unique characters
         if len(v) > 0 and len(set(v.lower())) < 4:
             return True
         return False

     def decode_base64_candidate(encoded):
         """Decode base64 only if result looks like structured secret data."""
         try:
             padded = encoded + '=' * (-len(encoded) % 4)
             decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
             printable_ratio = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
             if printable_ratio < 0.85:
                 return ''
             # Require ≥2 secret keywords AND key:value structure
             secret_kws = ['key', 'secret', 'token', 'password', 'access', 'bearer', 'auth']
             kw_count = sum(1 for kw in secret_kws if kw in decoded.lower())
             if kw_count >= 2 and (':' in decoded or '=' in decoded):
                 return decoded
         except Exception:
             pass
         return ''

     _COMMENT_RE = re.compile(r'^\s*(?://|#|/\*|\*)')

     def scan_js_file(js_url, js_content):
         """Scan a JS file for secrets with strict false-positive filtering."""
         findings = []
         seen_matches = set()
         lines = js_content.split('\n')

         for line_num, line in enumerate(lines, 1):
             # Skip pure comment lines (example values in docs are not real secrets)
             if _COMMENT_RE.match(line):
                 continue

             for category, pattern_list in JS_SECRET_PATTERNS.items():
                 for pattern, flags in pattern_list:
                     try:
                         matches = re.finditer(pattern, line, flags)
                     except re.error:
                         continue
                     for match in matches:
                         match_text = match.group(0)
                         # Use captured group if present, else full match
                         captured = match.group(1) if match.lastindex else match_text

                         # False-positive filter on the captured value.
                         # Skip FP checks for API_KEY (fixed-format prefixes) and
                         # INTERNAL_ENDPOINT (the match IS a URL, not a token).
                         if category not in ('API_KEY', 'INTERNAL_ENDPOINT') and _is_fp(captured):
                             continue

                         # Deduplicate by (category, normalised value)
                         dedup_key = (category, captured.lower()[:40])
                         if dedup_key in seen_matches:
                             continue
                         seen_matches.add(dedup_key)

                         # Extra filter for INTERNAL_ENDPOINT
                         if category == 'INTERNAL_ENDPOINT':
                             skip_domains = [
                                 'cdn.', 'fonts.', 'static.', 'cdnjs.', 'unpkg.',
                                 'jsdelivr.', 'cloudflare.', 'amazonaws.com',
                                 'googleapis.com', 'gstatic.com', 'example.com',
                             ]
                             if any(d in match_text.lower() for d in skip_domains):
                                 continue

                         severity = 'CRITICAL' if category in ('API_KEY', 'HARDCODED_CREDS') else 'HIGH'
                         findings.append({
                             'type': category,
                             'severity': severity,
                             'match': match_text[:120],
                             'value': captured[:80],
                             'line': line_num,
                             'context': line.strip()[:200],
                             'url': js_url,
                         })

         # Base64 scanner — only on smaller files (skip minified bundles >500KB)
         if len(js_content) < 500_000:
             b64_candidates = re.findall(
                 r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{48,}={0,2})(?![A-Za-z0-9+/=])',
                 js_content
             )
             for candidate in b64_candidates:
                 # Skip pure hex strings (hashes, not base64 secrets)
                 if re.match(r'^[a-fA-F0-9]+$', candidate):
                     continue
                 dedup_key = ('BASE64', candidate[:40].lower())
                 if dedup_key in seen_matches:
                     continue
                 decoded = decode_base64_candidate(candidate)
                 if decoded:
                     seen_matches.add(dedup_key)
                     findings.append({
                         'type': 'BASE64_SECRET',
                         'severity': 'HIGH',
                         'match': candidate[:60] + ('...' if len(candidate) > 60 else ''),
                         'decoded': decoded[:120],
                         'url': js_url,
                     })

         return findings

     # Collect all JS files
     all_js = set()
     for url, body in AUTH_PAGES.items():
         soup = BeautifulSoup(body, 'html.parser')
         for script in soup.find_all('script'):
             src = script.get('src', '')
             if src and src.endswith('.js'):
                 js_url = urljoin(url, src)
                 parsed = urlparse(js_url)
                 base_parsed = urlparse(BASE)
                 if parsed.netloc and parsed.netloc == base_parsed.netloc:
                     all_js.add(js_url)

     print(f"\n[JS SCAN] Scanning {len(all_js)} JavaScript files for secrets...")
     js_findings = []

     for js_url in sorted(all_js):
         try:
             r = session.get(js_url, timeout=8)
             if r.status_code == 200:
                 findings = scan_js_file(js_url, r.text)
                 if findings:
                     js_findings.extend(findings)
                     print(f"  [CRIT] {js_url}: {len(findings)} secrets found!")
                 else:
                     print(f"  [OK] {js_url}: clean")
         except Exception as e:
             print(f"  [ERR] {js_url}: {e}")

     # Report summary
     print(f"\n=== JAVASCRIPT SECRET SCAN COMPLETE ===")
     print(f"Total files scanned: {len(all_js)}")
     print(f"Files with secrets: {len(set(f['url'] for f in js_findings))}")
     print(f"Total findings: {len(js_findings)}")

     if js_findings:
         print("\nDetailed findings:")
         for f in js_findings:
             severity = f['severity']
             emoji = {'CRITICAL': '[CRITICAL]', 'HIGH': '[HIGH]', 'MEDIUM': '[MEDIUM]', 'LOW': '[LOW]'}.get(severity, '[INFO]')
             print(f"  {emoji} {f['type']} in {f['url']}")
             print(f"    Match: {f['match']}")
             if 'value' in f and f['value'] != f['match']:
                 print(f"    Value: {f['value']}")
             if 'line' in f:
                 print(f"    Line:  {f['line']}")
             if 'decoded' in f:
                 print(f"    Decoded: {f['decoded']}")

     # Store findings globally for report generation
     _G['JS_FINDINGS'] = js_findings

      # Also store in main FINDINGS for PDF/ZDL report
      _G.setdefault('FINDINGS', [])
      for _jf in js_findings:
          _G['FINDINGS'].append({
              'severity': _jf.get('severity', 'HIGH'),
              'title': f"JS Secret: {_jf.get('type','')} in {_jf.get('url','').split('/')[-1]}",
              'url': _jf.get('url', ''),
              'method': 'GET',
              'evidence': _jf.get('match', _jf.get('evidence', '')),
              'impact': 'Exposed credentials or API keys in client-side JavaScript',
              'screenshot': '',
          })

      # POST-PHASE SCREENSHOT CHECKPOINT — verify JS secret findings with screenshots
      print("\n[SCREENSHOT CHECKPOINT] Verify all JavaScript secret findings:")
      for finding in _G['FINDINGS']:
          if 'JS Secret' in finding.get('title', '') or 'Secret' in finding.get('title', ''):
              if not finding.get('screenshot'):
                  print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
                  print(f"    Navigate to: {finding.get('url')}")
                  print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
                  print(f"    browser_action(action='screenshot', filename='phase_03b_js_secret_{finding.get('title').replace('JS Secret: ','').lower()[:40]}.png')")
                  print(f"    Update finding['screenshot'] with the filename")
      print("\n  For JS secret findings, verify by viewing the JavaScript file content in browser DevTools Sources tab. Screenshot should show the secret in context.")

     # REPORT SUMMARY TO CONVERSATION (MANDATORY)
     js_critical = [f for f in js_findings if f['severity'] == 'CRITICAL']
     js_high = [f for f in js_findings if f['severity'] == 'HIGH']

     print(f"\n=== JAVASCRIPT SECURITY SCAN RESULTS ===")
     print(f"Files scanned     : {len(all_js)}")
     print(f"CRITICAL findings : {len(js_critical)}")
     print(f"HIGH findings     : {len(js_high)}")
     print(f"Total findings    : {len(js_findings)}")

     if js_critical or js_high:
         print("\n[JAVASCRIPT SECURITY FINDINGS]")
         for f in js_critical:
             filename = f['url'].split('/')[-1] if 'url' in f else 'unknown'
             print(f"  [CRITICAL] {f['type']} in {filename}")
             print(f"    Match: {f['match'][:80]}")
             if 'line' in f:
                 print(f"    Line: {f['line']}")
         for f in js_high:
             filename = f['url'].split('/')[-1] if 'url' in f else 'unknown'
             print(f"  [HIGH] {f['type']} in {filename}")
             print(f"    Match: {f['match'][:80]}")
     else:
         print("\n[INFO] No API keys, secrets, or hardcoded credentials found in JavaScript files.")
     ```

   This scan automatically finds:
   - [CRITICAL] API keys (AWS AKIA*, Google AIza*, Stripe sk_live_*, GitHub ghp_*, Slack xoxb-*)
   - [CRITICAL] SSH/private keys, hardcoded passwords
   - [HIGH] Secret tokens, internal API endpoints (.internal, .corp, RFC-1918 IPs)
   - [HIGH] Base64 encoded secrets (structured key:value data only)

   FALSE POSITIVE PROTECTION built in:
   - AWS key pattern is case-SENSITIVE: AKIA[A-Z0-9]{16} — any lowercase letter = not a real key
   - All patterns require exact format + length (no loose IGNORECASE on key patterns)
   - Placeholder filter rejects: ${VAR}, <placeholder>, changeme, example, MD5/SHA hashes
   - Comment lines are skipped
   - Base64 scanner requires decoded content to have ≥2 secret keywords + key:value structure

   Run this AFTER the authenticated crawl and SAVE results to the PENTEST MEMORY.
