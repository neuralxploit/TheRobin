**Phase 21 — API Security & Enumeration**

  Tests REST/JSON API security: endpoint discovery, Swagger/OpenAPI exposure, excessive data exposure,
  broken function-level authorization, and API-specific injection vectors.

  ```python
  import time, json, re
  from urllib.parse import urljoin, urlparse

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  session_b = _G.get('session_b')
  ALL_LINKS = _G.get('ALL_LINKS', set())
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})

  api_findings = []

  # ══════════════════════════════════════════════════════════════
  # PART A — API Documentation Discovery (Swagger/OpenAPI)
  # ══════════════════════════════════════════════════════════════
  SWAGGER_PATHS = [
      '/swagger.json', '/swagger/v1/swagger.json', '/swagger-ui.html',
      '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
      '/openapi.json', '/openapi.yaml', '/api/openapi.json',
      '/swagger-resources', '/swagger-resources/configuration/ui',
      '/.well-known/openapi.json', '/docs', '/redoc',
      '/api/swagger.json', '/api/v1/swagger.json', '/api/docs',
      '/graphql', '/graphiql', '/playground',
      '/api/schema', '/api/spec', '/api/definition',
      '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
      '/actuator/beans', '/actuator/mappings', '/actuator/configprops',
      '/manage/health', '/health', '/info', '/env',
  ]

  print(f"[API] Probing {len(SWAGGER_PATHS)} API documentation/management endpoints")

  discovered_endpoints = []
  for path in SWAGGER_PATHS:
      url = urljoin(BASE, path)
      time.sleep(0.2)
      try:
          r = session.get(url, timeout=8, allow_redirects=True)
          if r.status_code == 200:
              body = r.text[:2000].lower()
              # Check it's not a SPA catch-all
              if 'swagger' in body or 'openapi' in body or 'api-docs' in body:
                  print(f"  [HIGH] API docs exposed: {url}")
                  api_findings.append({
                      'url': url, 'type': 'api-docs-exposed',
                      'desc': f'API documentation publicly accessible at {path}',
                      'evidence': r.text[:500],
                  })
                  # Try to parse and extract endpoints
                  try:
                      spec = r.json()
                      paths = spec.get('paths', {})
                      for ep_path, methods in paths.items():
                          for method in methods:
                              if method.upper() in ('GET','POST','PUT','DELETE','PATCH'):
                                  discovered_endpoints.append({
                                      'path': ep_path, 'method': method.upper()
                                  })
                      print(f"  Found {len(discovered_endpoints)} API endpoints in spec")
                  except Exception:
                      pass
              elif 'actuator' in path and ('"status"' in body or '"beans"' in body
                                           or '"activeProfiles"' in body):
                  print(f"  [HIGH] Spring Actuator exposed: {url}")
                  print(f"  Response: {r.text[:400]}")
                  api_findings.append({
                      'url': url, 'type': 'actuator-exposed',
                      'desc': f'Spring Boot Actuator endpoint exposed: {path}',
                      'evidence': r.text[:500],
                  })
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # PART B — API Endpoint Enumeration
  # ══════════════════════════════════════════════════════════════
  # Common REST API patterns
  API_ENUM_PATHS = [
      '/api/users', '/api/v1/users', '/api/user', '/api/admin',
      '/api/products', '/api/orders', '/api/items', '/api/customers',
      '/api/accounts', '/api/transactions', '/api/payments',
      '/api/config', '/api/settings', '/api/debug', '/api/test',
      '/api/v1/admin', '/api/internal', '/api/private',
      '/api/search', '/api/export', '/api/backup',
      '/api/logs', '/api/audit', '/api/events',
      '/api/files', '/api/uploads', '/api/media',
      '/api/keys', '/api/tokens', '/api/secrets',
      '/api/roles', '/api/permissions', '/api/privileges',
      '/rest/users', '/rest/admin', '/rest/products',
      '/v1/users', '/v2/users', '/v1/admin',
  ]

  # Add endpoints from Swagger spec if found
  for ep in discovered_endpoints:
      API_ENUM_PATHS.append(ep['path'])

  # CRITICAL: Add ALL paths from crawl that look like API/data endpoints
  # Not just /api/* — also check ALL authenticated pages with integer IDs
  for link in ALL_LINKS:
      path = urlparse(link).path
      if path not in API_ENUM_PATHS:
          if '/api/' in link or '/rest/' in link:
              API_ENUM_PATHS.append(path)

  # Add ALL discovered endpoints from AUTH_PAGES + ALL_PAGES that contain IDs
  # These are real endpoints the app serves — test them ALL for auth bypass
  for page_url in list(AUTH_PAGES.keys()) + list(ALL_PAGES.keys()):
      path = urlparse(page_url).path
      if path and path not in API_ENUM_PATHS:
          # Include any path with integer IDs (e.g., /profile/1, /invoice/3, /user/2/edit)
          if re.search(r'/\d+', path):
              API_ENUM_PATHS.append(path)
          # Include any path with API-like structure
          if any(seg in path.lower() for seg in ['user', 'profile', 'invoice', 'order',
                  'account', 'admin', 'config', 'setting', 'data', 'export', 'backup']):
              API_ENUM_PATHS.append(path)

  print(f"\n[API] Enumerating {len(API_ENUM_PATHS)} API endpoints")

  accessible_apis = []
  for path in list(set(API_ENUM_PATHS))[:50]:
      url = urljoin(BASE, path)
      time.sleep(0.2)
      try:
          r = session.get(url, timeout=8, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201) and len(r.text) > 20:
              try:
                  data = r.json()
                  # Check if it returned actual data (not error page)
                  if isinstance(data, (list, dict)):
                      data_str = json.dumps(data)
                      if len(data_str) > 50 and 'error' not in data_str.lower()[:100]:
                          accessible_apis.append({'url': url, 'path': path, 'data': data})
                          print(f"  [INFO] API accessible: {url} ({len(data_str)} bytes)")
              except Exception:
                  pass
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # PART C — Excessive Data Exposure (OWASP API3)
  # ══════════════════════════════════════════════════════════════
  SENSITIVE_FIELDS = ['password', 'passwd', 'pwd', 'hash', 'secret', 'token',
                      'api_key', 'apikey', 'private_key', 'credit_card', 'ccnum',
                      'ssn', 'social_security', 'salary', 'dob', 'date_of_birth',
                      'bank_account', 'routing_number', 'internal_id', 'admin_token',
                      'session_token', 'refresh_token', 'access_token']

  print(f"\n[API] Checking {len(accessible_apis)} accessible APIs for excessive data exposure")

  for api_info in accessible_apis:
      data_str = json.dumps(api_info['data']).lower()
      exposed_fields = [f for f in SENSITIVE_FIELDS if f in data_str]
      if exposed_fields:
          print(f"  [HIGH] Excessive data exposure: {api_info['url']}")
          print(f"  Sensitive fields: {exposed_fields}")
          print(f"  Data sample: {json.dumps(api_info['data'])[:400]}")
          api_findings.append({
              'url': api_info['url'], 'type': 'excessive-data-exposure',
              'desc': f"API returns sensitive fields: {', '.join(exposed_fields)}",
              'evidence': json.dumps(api_info['data'])[:500],
          })

  # ══════════════════════════════════════════════════════════════
  # PART D — Broken Function-Level Authorization (OWASP API5)
  # ══════════════════════════════════════════════════════════════
  # Test admin endpoints without auth / with low-priv session
  ADMIN_ENDPOINTS = [
      '/api/admin', '/api/admin/users', '/api/admin/settings',
      '/api/admin/config', '/api/admin/logs', '/api/admin/dashboard',
      '/api/users/all', '/api/v1/admin', '/admin/api',
      '/api/management', '/api/system', '/api/internal',
  ]

  print(f"\n[API] Testing broken function-level authorization")

  # Test with no auth
  no_auth = __import__('requests').Session()
  no_auth.verify = False
  for path in ADMIN_ENDPOINTS:
      url = urljoin(BASE, path)
      time.sleep(0.3)
      try:
          r = no_auth.get(url, timeout=8, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201):
              try:
                  data = r.json()
                  if isinstance(data, (list, dict)) and len(json.dumps(data)) > 50:
                      if 'error' not in json.dumps(data).lower()[:100]:
                          print(f"  [CRITICAL] Admin API accessible WITHOUT auth: {url}")
                          print(f"  Data: {json.dumps(data)[:300]}")
                          api_findings.append({
                              'url': url, 'type': 'broken-auth-admin',
                              'desc': f'Admin endpoint accessible without authentication',
                              'evidence': json.dumps(data)[:500],
                          })
              except Exception:
                  pass
      except Exception:
          continue

  # If we have session_b (low-priv), test admin endpoints with it
  if session_b:
      print("  Testing admin endpoints with low-privilege session...")
      for path in ADMIN_ENDPOINTS:
          url = urljoin(BASE, path)
          time.sleep(0.3)
          try:
              r = session_b.get(url, timeout=8, headers={'Accept': 'application/json'})
              if r.status_code in (200, 201):
                  try:
                      data = r.json()
                      if isinstance(data, (list, dict)) and len(json.dumps(data)) > 50:
                          print(f"  [HIGH] Admin API accessible with low-priv: {url}")
                          api_findings.append({
                              'url': url, 'type': 'broken-function-auth',
                              'desc': 'Admin endpoint accessible with low-privilege user',
                              'evidence': json.dumps(data)[:500],
                          })
                  except Exception:
                      pass
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART E — API Rate Limiting & Mass Operations
  # ══════════════════════════════════════════════════════════════
  print(f"\n[API] Testing API rate limiting")
  # Pick a few accessible API endpoints and send rapid requests
  test_apis = accessible_apis[:3]
  if not test_apis and ALL_LINKS:
      api_links = [l for l in ALL_LINKS if '/api/' in l][:3]
      test_apis = [{'url': l} for l in api_links]

  for api_info in test_apis:
      url = api_info['url']
      success_count = 0
      for i in range(20):
          try:
              r = session.get(url, timeout=5, headers={'Accept': 'application/json'})
              if r.status_code in (200, 201):
                  success_count += 1
              elif r.status_code == 429:
                  print(f"  [INFO] Rate limiting active on {url} after {i+1} requests")
                  break
          except Exception:
              break
      else:
          if success_count == 20:
              print(f"  [MEDIUM] No rate limiting on {url} (20/20 requests succeeded)")
              api_findings.append({
                  'url': url, 'type': 'no-rate-limit',
                  'desc': f'API endpoint has no rate limiting ({success_count}/20 rapid requests OK)',
              })

  # ══════════════════════════════════════════════════════════════
  # PART F — HTTP Method Tampering on API Endpoints
  # ══════════════════════════════════════════════════════════════
  print(f"\n[API] Testing HTTP method tampering on API endpoints")
  for api_info in accessible_apis[:10]:
      url = api_info['url']
      for method in ['PUT', 'DELETE', 'PATCH']:
          time.sleep(0.3)
          try:
              r = session.request(method, url, timeout=8,
                                  json={}, headers={'Content-Type': 'application/json'})
              if r.status_code in (200, 201, 204):
                  print(f"  [MEDIUM] {method} accepted: {url} (status {r.status_code})")
                  try:
                      resp_data = r.json()
                      if 'error' not in json.dumps(resp_data).lower()[:100]:
                          print(f"  [HIGH] {method} returned data: {json.dumps(resp_data)[:200]}")
                          api_findings.append({
                              'url': url, 'type': 'method-tampering',
                              'desc': f'{method} method accepted and returned data',
                              'evidence': json.dumps(resp_data)[:300],
                          })
                  except Exception:
                      pass
          except Exception:
              continue

  # Summary
  print(f"\n=== API SECURITY SUMMARY: {len(api_findings)} issues found ===")
  for f in api_findings:
      sev = 'CRITICAL' if f['type'] in ('broken-auth-admin', 'api-docs-exposed') else 'HIGH'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")
  if api_findings:
      _G.setdefault('FINDINGS', []).extend([
          {'severity': 'CRITICAL' if f['type'] in ('broken-auth-admin',) else 'HIGH',
           'title': f"API Security — {f['type']}",
           'url': f.get('url', ''),
           'method': 'GET',
           'evidence': f.get('evidence', ''),
           'impact': 'Unauthorized API access, data leakage, admin endpoint exposure',
           'screenshot': '',
           'detail': f} for f in api_findings
      ])

# POST-PHASE SCREENSHOT CHECKPOINT — verify API findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all API security findings:")
for finding in _G['FINDINGS']:
    if 'API' in finding.get('title', ''):
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_21_api_{finding.get('title').replace('API Security — ','').lower()[:40]}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  After confirming each finding: if screenshot shows 401/403/error, it's a FALSE POSITIVE — remove it")
  ```
