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

     # Regex patterns for secret detection
     JS_SECRET_PATTERNS = {
         'API_KEY': [
             r'AIza[A-Za-z0-9_-]{35}',  # Google API keys
             r'AKIA[A-Z0-9]{16}',       # AWS Access Key ID
             r'sk_live_[A-Za-z0-9]{24}', r'sk_test_[A-Za-z0-9]{24}',  # Stripe
             r'pk_live_[A-Za-z0-9]{24}', r'pk_test_[A-Za-z0-9]{24}',  # Stripe publishable
             r'xoxb-[0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+',  # Slack bot token
             r'ghp_[A-Za-z0-9]{36}',    # GitHub PAT
             r'gho_[A-Za-z0-9]{36}',    # GitHub OAuth
             r'ghs_[A-Za-z0-9]{36}',    # GitHub Server token
             r'github_pat_[A-Za-z0-9_]{82}',  # GitHub fine-grained PAT
             r'xox[p|o|s]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',  # Slack tokens
             r'ssh-rsa\\s+[A-Za-z0-9+/=]+',  # SSH keys
             r'-----BEGIN\\s+(?:OPENSSH|RSA|EC|DSA)\\s+PRIVATE\\s+KEY-----',
             r'BEGIN\\s+RSA\\s+PRIVATE\\s+KEY',
             r'BEGIN\\s+EC\\s+PRIVATE\\s+KEY',
         ],
         'SECRET_TOKEN': [
             r'secret[_-]?(?:key|token)?[\\'"]?\\s*[:=]\\s*[\\'"]([A-Za-z0-9_\\-]{20,})[\\'"]',
             r'token[_-]?(?:secret|key)?[\\'"]?\\s*[:=]\\s*[\\'"]([A-Za-z0-9_\\-]{20,})[\\'"]',
             r'api[_-]?secret[\\'"]?\\s*[:=]\\s*[\\'"]([A-Za-z0-9_\\-]{20,})[\\'"]',
             r'jwt[_-]?secret[\\'"]?\\s*[:=]\\s*[\\'"]([A-Za-z0-9_\\-]{20,})[\\'"]',
             r'auth[_-]?token[\\'"]?\\s*[:=]\\s*[\\'"]([A-Za-z0-9_\\-]{20,})[\\'"]',
         ],
         'HARDCODED_CREDS': [
             r'password[\\'"]?\\s*[:=]\\s*[\\'"]([^\\'\"\\s]{8,})[\\'"]',
             r'passwd[\\'"]?\\s*[:=]\\s*[\\'"]([^\\'\"\\s]{8,})[\\'"]',
             r'pwd[\\'"]?\\s*[:=]\\s*[\\'"]([^\\'\"\\s]{8,})[\\'"]',
             r'username[\\'"]?\\s*[:=]\\s*[\\'"]([^\\'\"\\s]{3,})[\\'"]',
             r'user[\\'"]?\\s*[:=]\\s*[\\'"]([^\\'\"\\s]{3,})[\\'"]',
             r'[\\'"](admin|root|test)[\\'"]\\s*:\\s*[\\'"]([^\\'\"]{8,})[\\'"]',
         ],
         'INTERNAL_ENDPOINT': [
             r'https?://(?:[a-zA-Z0-9-]+\\.)?(?:localhost|127\\.0\\.0\\.1|192\\.168\\.|172\\.[0-9]+\\.|10\\.)[:\\d]+',
             r'https?://[a-zA-Z0-9-]+\\.internal[^\\'"]*',
             r'https?://[a-zA-Z0-9-]+\\.dev[^\\'"]*',
             r'https?://[a-zA-Z0-9-]+\\.local[^\\'"]*',
             r'/api/(?:v[123])?/(?:admin|debug|test|internal|secret)',
             r'/(?:graphql|graph)[\\'\"\\s,]',
         ],
     }

     def decode_base64_candidate(encoded: str) -> str:
         \"\"\"Try to decode base64, return decoded string or empty.\"\"\"
         try:
             if len(encoded) % 4 == 0:
                 decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                 if decoded.isprintable() or ':' in decoded or '=' in decoded:
                     return decoded
         except Exception:
             pass
         return ''

     def scan_js_file(js_url: str, js_content: str) -> list:
         \"\"\"Scan a JavaScript file for secrets.\"\"\"
         findings = []
         lines = js_content.split('\\n')

         for line_num, line in enumerate(lines, 1):
             # Skip minified lines unless they have patterns
             if len(line) > 200 and not any(p in line.lower() for p in ['key', 'secret', 'token', 'password']):
                 continue

             for category, patterns in JS_SECRET_PATTERNS.items():
                 for pattern in patterns:
                     matches = re.finditer(pattern, line, re.IGNORECASE)
                     for match in matches:
                         match_text = match.group(0)
                         severity = 'CRITICAL' if category in ['API_KEY', 'HARDCODED_CREDS'] else 'HIGH'

                         # Check for false positives
                         skip = False
                         if category == 'INTERNAL_ENDPOINT':
                             if any(domain in match_text.lower() for domain in ['cdn.', 'fonts.', 'static.', 'cdnjs.', 'unpkg.']):
                                 skip = True

                         if not skip:
                             findings.append({
                                 'type': category,
                                 'severity': severity,
                                 'match': match_text[:100],
                                 'line': line_num,
                                 'context': line.strip()[:150] + '...' if len(line.strip()) > 150 else line.strip(),
                                 'url': js_url
                             })

         # Check for base64 encoded data
         base64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', js_content)
         for candidate in base64_candidates:
             if len(candidate) >= 40:
                 decoded = decode_base64_candidate(candidate)
                 if decoded and len(decoded) > 10 and any(k in decoded.lower() for k in ['key', 'secret', 'token', 'password', 'api', ':']):
                     findings.append({
                         'type': 'BASE64_SECRET',
                         'severity': 'HIGH',
                         'match': candidate[:50] + '...',
                         'decoded': decoded[:100] + '...' if len(decoded) > 100 else decoded,
                         'url': js_url
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

     print(f"\\n[JS SCAN] Scanning {len(all_js)} JavaScript files for secrets...")
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
     print(f"\\n=== JAVASCRIPT SECRET SCAN COMPLETE ===")
     print(f"Total files scanned: {len(all_js)}")
     print(f"Files with secrets: {len(set(f['url'] for f in js_findings))}")
     print(f"Total findings: {len(js_findings)}")

     if js_findings:
         print("\\nDetailed findings:")
         for f in js_findings:
             severity = f['severity']
             emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
             print(f"  {emoji} [{severity}] {f['type']} in {f['url']}")
             print(f"    Match: {f['match']}")
             if 'line' in f:
                 print(f"    Line: {f['line']}")
             if 'decoded' in f:
                 print(f"    Decoded: {f['decoded']}")
             if 'context' in f:
                 print(f"    Context: {f['context']}")

      # Store findings globally for report generation
      _G['JS_FINDINGS'] = js_findings

      # Also store in main FINDINGS for PDF report
      _G.setdefault('FINDINGS', [])
      for _jf in js_findings:
          _G['FINDINGS'].append({
              'severity': _jf.get('severity', 'HIGH'),
              'title': f"JS Secret: {_jf.get('type','')} in {_jf.get('url','').split('/')[-1]}",
              'url': _jf.get('url', ''),
              'evidence': _jf.get('match', _jf.get('evidence', '')),
              'impact': 'Exposed credentials or API keys in client-side JavaScript',
          })

      # REPORT SUMMARY TO CONVERSATION (MANDATORY)
      js_critical = [f for f in js_findings if f['severity'] == 'CRITICAL']
      js_high = [f for f in js_findings if f['severity'] == 'HIGH']

      print(f"\n=== JAVASCRIPT SECURITY SCAN RESULTS ===")
      print(f"Files scanned     : {len(all_js)}")
      print(f"CRITICAL findings : {len(js_critical)}")
      print(f"HIGH findings     : {len(js_high)}")
      print(f"Total findings     : {len(js_findings)}")

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
   - 🔴 CRITICAL: API keys (Google, Stripe, AWS, GitHub, Slack)
   - 🔴 CRITICAL: SSH/private keys, hardcoded credentials
   - 🟠 HIGH: Secret tokens, internal API endpoints
   - 🟠 HIGH: Base64 encoded secrets
   - 🟡 MEDIUM: URLs to internal systems

   Run this AFTER the authenticated crawl and SAVE results to the PENTEST MEMORY.
