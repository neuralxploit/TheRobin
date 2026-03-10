**Phase 25 — Error Handling & Information Disclosure**

  Intentionally trigger errors to find stack traces, debug info, database details,
  internal paths, and verbose error messages that help attackers. Works on ANY app.

  ```python
  import requests, time, json, re
  from urllib.parse import urljoin, urlparse, urlencode

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')

  _err_findings = []

  # ── 1. Trigger errors via malformed requests ──────────────────────
  print('[ERROR-HANDLING] Testing error responses for information disclosure...')

  # Error indicators in responses
  ERROR_PATTERNS = [
      (r'(?:Traceback|File\s+"[^"]+",\s+line\s+\d+)', 'Python stack trace', 'HIGH'),
      (r'(?:at\s+[\w.$]+\([\w.]+:\d+\))', 'Java/Node stack trace', 'HIGH'),
      (r'(?:Fatal error|Warning|Notice).*(?:in\s+/|on line)', 'PHP error with path', 'HIGH'),
      (r'(?:SQLSTATE|ORA-\d{5}|mysql_|pg_query|sqlite)', 'Database error', 'HIGH'),
      (r'(?:Microsoft|IIS|ASP\.NET).*(?:error|exception)', 'ASP.NET error', 'HIGH'),
      (r'(?:DEBUG\s*=\s*True|DJANGO_SETTINGS_MODULE)', 'Django debug mode', 'CRITICAL'),
      (r'/(?:usr|var|home|opt|etc|app)/[\w/.-]+\.\w{2,4}', 'Internal file path', 'MEDIUM'),
      (r'(?:root|www-data|apache|nginx|node):', 'System user disclosed', 'LOW'),
      (r'(?:X-Powered-By|X-AspNet-Version|X-Runtime)', 'Technology header', 'LOW'),
      (r'(?:MongoDB|PostgreSQL|MySQL|MariaDB|Redis|Elasticsearch)\s*[\d.]+', 'Database version', 'MEDIUM'),
  ]

  def _check_errors(resp, context):
      """Check response for error disclosure patterns."""
      body = resp.text
      found = False
      for pattern, desc, sev in ERROR_PATTERNS:
          m = re.search(pattern, body, re.IGNORECASE)
          if m:
              print(f'  [{sev}] {desc} in {context}')
              print(f'    Match: {m.group(0)[:120]}')
              _err_findings.append({
                  'severity': sev,
                  'title': f'Information disclosure — {desc}',
                  'url': context,
                  'evidence': m.group(0)[:200],
              })
              found = True
      return found

  # Test 1: Invalid URL paths (trigger 404 error handlers)
  ERROR_PATHS = [
      "/<script>alert(1)</script>",        # XSS in 404 page
      "/AAAAAAA" * 50,                     # Long URL
      "/..%2f..%2f..%2fetc%2fpasswd",      # Path traversal in 404
      "/%00",                              # Null byte
      "/test.php", "/test.asp", "/test.jsp",  # Wrong extension
      "/api/v99999/nonexistent",           # API version that doesn't exist
      "/undefined", "/null", "/NaN",       # JavaScript-like values
  ]

  for path in ERROR_PATHS:
      try:
          r = session.get(BASE + path, timeout=8, allow_redirects=False)
          if r.status_code >= 400:
              _check_errors(r, BASE + path[:80])
      except Exception:
          pass
      time.sleep(0.15)

  # Test 2: Malformed parameters on discovered endpoints
  print('\n[ERROR-HANDLING] Testing malformed parameters on API endpoints...')
  api_endpoints = [ep.get('url', '') for ep in _G.get('CONFIRMED_APIS', [])][:10]
  all_forms = _G.get('ALL_FORMS', [])[:5]

  FUZZ_VALUES = [
      "' OR 1=1--",           # SQL injection trigger
      "<script>",             # HTML injection
      "{{7*7}}",              # SSTI
      "${7*7}",               # Expression language
      "../../etc/passwd",     # Path traversal
      "[]",                   # Empty array (type error)
      "{}",                   # Empty object (type error)
      "-1",                   # Negative number
      "99999999999999999",    # Integer overflow
      "null",                 # Null string
      "",                     # Empty string
      "\x00",                 # Null byte
      "a" * 10000,            # Buffer overflow attempt
  ]

  for ep_url in api_endpoints:
      for fuzz in FUZZ_VALUES[:5]:
          try:
              # GET with fuzz in query
              r = session.get(ep_url, params={'id': fuzz, 'q': fuzz}, timeout=8)
              if r.status_code >= 400 or r.status_code == 500:
                  _check_errors(r, f'{ep_url}?id={fuzz[:30]}')

              # POST with fuzz in body
              r = session.post(ep_url, json={'id': fuzz, 'data': fuzz}, timeout=8)
              if r.status_code >= 400 or r.status_code == 500:
                  _check_errors(r, f'POST {ep_url} (fuzz={fuzz[:30]})')
          except Exception:
              pass
          time.sleep(0.2)

  # Test 3: Wrong Content-Type headers
  print('\n[ERROR-HANDLING] Testing wrong Content-Type handling...')
  test_urls = api_endpoints[:3] or [BASE + '/api/login', BASE + '/api/users']
  WRONG_TYPES = [
      ('text/xml', '<?xml version="1.0"?><root><test>1</test></root>'),
      ('application/x-www-form-urlencoded', 'test=value&id=1'),
      ('multipart/form-data; boundary=----', '------\r\nContent-Disposition: form-data; name="test"\r\n\r\nvalue\r\n------'),
  ]
  for url in test_urls:
      for ct, body in WRONG_TYPES:
          try:
              r = session.post(url, data=body, headers={'Content-Type': ct}, timeout=8)
              if r.status_code == 500:
                  _check_errors(r, f'POST {url} (Content-Type: {ct})')
          except Exception:
              pass
          time.sleep(0.2)

  # Test 4: HTTP method testing (unexpected methods)
  print('\n[ERROR-HANDLING] Testing unexpected HTTP methods...')
  for url in (api_endpoints[:3] or [BASE]):
      for method in ['PATCH', 'DELETE', 'OPTIONS', 'PUT', 'TRACE']:
          try:
              r = session.request(method, url, timeout=8)
              if r.status_code == 500:
                  _check_errors(r, f'{method} {url}')
              elif method == 'TRACE' and r.status_code == 200 and 'TRACE' in r.text:
                  print(f'  [MEDIUM] TRACE method enabled: {url}')
                  _err_findings.append({
                      'severity': 'MEDIUM',
                      'title': 'HTTP TRACE method enabled',
                      'url': url,
                      'evidence': 'TRACE method reflects request body — XST possible',
                  })
              elif method == 'OPTIONS' and r.status_code == 200:
                  allow = r.headers.get('Allow', '')
                  if allow:
                      print(f'  [INFO] OPTIONS {url}: Allow: {allow}')
          except Exception:
              pass
          time.sleep(0.1)

  # Test 5: Custom error pages vs default framework errors
  print('\n[ERROR-HANDLING] Checking for custom vs default error pages...')
  try:
      r = session.get(BASE + '/this_page_definitely_does_not_exist_12345', timeout=8)
      if r.status_code == 404:
          default_signs = ['Whitelabel Error', 'nginx/', 'Apache/', 'IIS',
                          'Not Found</h1>', 'django', 'express', 'flask',
                          'laravel', 'spring', 'tomcat']
          for sign in default_signs:
              if sign.lower() in r.text.lower():
                  print(f'  [LOW] Default error page detected (framework: {sign})')
                  _err_findings.append({
                      'severity': 'LOW',
                      'title': f'Default error page reveals framework: {sign}',
                      'url': BASE,
                      'evidence': f'404 page contains "{sign}"',
                  })
                  break
  except Exception:
      pass

  # ── Summary ───────────────────────────────────────────────────────
  print(f'\n=== ERROR HANDLING SUMMARY: {len(_err_findings)} issues found ===')
  for f in _err_findings:
      print(f"  [{f['severity']}] {f['title']}")
  if _err_findings:
      _G.setdefault('FINDINGS', []).extend(_err_findings)
  ```
