**Phase 19 — Business Logic Flaws**

  Tests for logic bugs that automated scanners miss: price manipulation, negative quantities,
  workflow bypasses, coupon abuse, and integer overflow. These are high-impact on e-commerce
  and financial applications.

  ```python
  import time, json, re, copy
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  ALL_FORMS  = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

  logic_findings = []

  # ══════════════════════════════════════════════════════════════
  # PART A — Price / Quantity Manipulation
  # ══════════════════════════════════════════════════════════════
  # Find forms with numeric fields (price, quantity, amount, total, qty)
  NUMERIC_KEYWORDS = ['price', 'amount', 'total', 'quantity', 'qty', 'count',
                      'cost', 'payment', 'charge', 'fee', 'rate', 'number',
                      'num', 'value', 'sum', 'balance', 'credit', 'points']

  numeric_forms = []
  for form in ALL_FORMS:
      fields = form.get('fields', [])
      numeric_fields = [f for f in fields if any(k in f.get('name','').lower() for k in NUMERIC_KEYWORDS)
                        or f.get('type') == 'number']
      if numeric_fields:
          numeric_forms.append((form, numeric_fields))

  print(f"[LOGIC] Found {len(numeric_forms)} forms with numeric fields")

  MANIPULATION_VALUES = [
      (-1, 'negative value'),
      (0, 'zero value'),
      (0.001, 'tiny fraction'),
      (99999999, 'very large number'),
      (2147483647, 'INT_MAX (32-bit)'),
      (9999999999999, 'overflow value'),
      (-99999, 'large negative'),
  ]

  for form, num_fields in numeric_forms:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      method = form.get('method', 'post').lower()
      fields = form.get('fields', [])

      print(f"\n  Testing {method.upper()} {url}")

      for nfield in num_fields:
          fname = nfield['name']
          for test_val, desc in MANIPULATION_VALUES:
              time.sleep(0.3)
              data = {f['name']: f.get('value', '') or 'test' for f in fields if f.get('name')}
              data[fname] = str(test_val)
              try:
                  if method == 'post':
                      r = session.post(url, data=data, timeout=10, allow_redirects=True)
                  else:
                      r = session.get(url, params=data, timeout=10)

                  # Check for server errors (500 = unhandled edge case)
                  if r.status_code == 500:
                      print(f"  [MEDIUM] Server error with {desc} in '{fname}' = {test_val}")
                      logic_findings.append({
                          'url': url, 'param': fname, 'value': test_val,
                          'type': 'server-error', 'desc': f"500 error with {desc}",
                      })
                      continue

                  # Check for success with manipulated values
                  body = r.text.lower()
                  success_signs = ['success', 'added', 'updated', 'confirmed', 'order',
                                   'receipt', 'thank', 'complete', 'processed']
                  if r.status_code == 200 and any(s in body for s in success_signs):
                      if test_val < 0:
                          print(f"  [HIGH] Negative value ACCEPTED: {fname}={test_val} ({desc})")
                          logic_findings.append({
                              'url': url, 'param': fname, 'value': test_val,
                              'type': 'negative-accepted', 'desc': desc,
                          })
                      elif test_val == 0:
                          print(f"  [MEDIUM] Zero value accepted: {fname}={test_val}")
                          logic_findings.append({
                              'url': url, 'param': fname, 'value': test_val,
                              'type': 'zero-accepted', 'desc': desc,
                          })
              except Exception:
                  continue

  # ══════════════════════════════════════════════════════════════
  # PART B — Coupon / Discount Code Abuse
  # ══════════════════════════════════════════════════════════════
  COUPON_KEYWORDS = ['coupon', 'promo', 'discount', 'voucher', 'code', 'gift',
                     'redeem', 'campaign', 'offer']
  coupon_forms = []
  for form in ALL_FORMS:
      fields = form.get('fields', [])
      coupon_fields = [f for f in fields if any(k in f.get('name','').lower() for k in COUPON_KEYWORDS)]
      if coupon_fields:
          coupon_forms.append((form, coupon_fields))

  if coupon_forms:
      print(f"\n[LOGIC] Found {len(coupon_forms)} coupon/discount forms")
      for form, cf in coupon_forms:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])
          for cfield in cf:
              fname = cfield['name']
              # Try to apply same coupon multiple times
              test_codes = ['DISCOUNT', 'PROMO', 'FREE', 'TEST', '100OFF', 'SAVE50']
              for code in test_codes:
                  data = {f['name']: f.get('value','') or 'test' for f in fields if f.get('name')}
                  data[fname] = code
                  try:
                      r1 = session.post(url, data=data, timeout=10, allow_redirects=True)
                      r2 = session.post(url, data=data, timeout=10, allow_redirects=True)
                      if r1.status_code == 200 and r2.status_code == 200:
                          if 'applied' in r2.text.lower() or 'success' in r2.text.lower():
                              print(f"  [HIGH] Coupon reuse: '{code}' accepted multiple times on {url}")
                              logic_findings.append({
                                  'url': url, 'param': fname, 'value': code,
                                  'type': 'coupon-reuse', 'desc': f"Coupon '{code}' reusable",
                              })
                  except Exception:
                      continue

  # ── PART B2 — REST API coupon/basket/order manipulation ──────────────────
  # Many SPAs use JSON APIs for cart/basket/coupon — test these directly
  BASKET_API_PATHS = ['/api/BasketItems', '/api/basket', '/api/cart', '/api/orders',
                      '/rest/basket', '/api/v1/cart', '/api/v1/orders', '/api/quantitys']
  COUPON_API_PATHS = ['/api/Coupons', '/rest/basket/coupon', '/api/coupon',
                      '/api/discount', '/api/promo', '/api/v1/coupon']

  print(f"\n[LOGIC] Testing REST API basket/coupon manipulation")

  # Test negative quantities via JSON API
  for bpath in BASKET_API_PATHS:
      burl = BASE.rstrip('/') + bpath
      for neg_qty in [-1, -100, 0, 0.001]:
          time.sleep(0.3)
          try:
              r = session.post(burl, json={'ProductId': 1, 'BasketId': '1', 'quantity': neg_qty},
                               timeout=10, headers={'Content-Type': 'application/json'})
              if r.status_code in (200, 201):
                  try:
                      data = r.json()
                      if isinstance(data, dict) and data.get('id'):
                          print(f"  [HIGH] Negative/zero quantity accepted: {burl} qty={neg_qty}")
                          print(f"    Response: {str(data)[:200]}")
                          logic_findings.append({
                              'url': burl, 'type': 'negative-quantity',
                              'desc': f'Quantity {neg_qty} accepted via API',
                              'evidence': str(data)[:300],
                          })
                          break
                  except Exception:
                      pass
          except Exception:
              continue

  # Test coupon code via JSON API
  for cpath in COUPON_API_PATHS:
      curl = BASE.rstrip('/') + cpath
      for coupon in ['', 'AAAA', 'null', 'undefined', '-1', '0']:
          time.sleep(0.3)
          try:
              r = session.put(curl, json={'coupon': coupon}, timeout=10,
                              headers={'Content-Type': 'application/json'})
              if r.status_code == 200:
                  try:
                      data = r.json()
                      if 'discount' in str(data).lower() or 'applied' in str(data).lower():
                          print(f"  [HIGH] Invalid coupon accepted: {curl} code='{coupon}'")
                          logic_findings.append({
                              'url': curl, 'type': 'coupon-bypass',
                              'desc': f"Coupon '{coupon}' accepted",
                              'evidence': str(data)[:300],
                          })
                  except Exception:
                      pass
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART C — Workflow / Step Bypass
  # ══════════════════════════════════════════════════════════════
  # Try accessing later steps without completing earlier ones
  CHECKOUT_PATTERNS = [
      '/checkout', '/payment', '/confirm', '/order', '/purchase', '/pay',
      '/basket/checkout', '/cart/checkout', '/api/orders', '/api/checkout',
      '/order/confirm', '/order/complete', '/api/payment',
  ]

  print(f"\n[LOGIC] Testing workflow bypass (direct access to checkout/payment)")
  for pattern in CHECKOUT_PATTERNS:
      url = urljoin(BASE, pattern)
      time.sleep(0.3)
      try:
          r = session.get(url, timeout=10)
          if r.status_code == 200 and 'login' not in r.url.lower():
              body = r.text.lower()
              checkout_signs = ['payment', 'checkout', 'order', 'total', 'cart',
                               'billing', 'shipping', 'credit card', 'confirm']
              if any(s in body for s in checkout_signs):
                  print(f"  [MEDIUM] Checkout step accessible directly: {url}")
                  logic_findings.append({
                      'url': url, 'type': 'workflow-bypass',
                      'desc': f"Direct access to {pattern} without completing prior steps",
                  })
          # Also try POST
          r = session.post(url, json={}, timeout=10,
                          headers={'Content-Type': 'application/json'})
          if r.status_code in (200, 201) and r.text:
              try:
                  data = r.json()
                  if 'order' in str(data).lower() or 'id' in str(data).lower():
                      print(f"  [HIGH] Order created via direct POST: {url}")
                      print(f"  Response: {str(data)[:300]}")
                      logic_findings.append({
                          'url': url, 'type': 'workflow-bypass-post',
                          'desc': f"Order/payment endpoint accepts direct POST",
                      })
              except Exception:
                  pass
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # PART D — API Parameter Tampering (hidden fields, extra params)
  # ══════════════════════════════════════════════════════════════
  # Try adding role/admin/isAdmin/price fields to registration/profile forms
  TAMPER_FIELDS = [
      ('role', 'admin'), ('isAdmin', 'true'), ('is_admin', 'true'),
      ('admin', 'true'), ('privilege', 'admin'), ('level', '0'),
      ('type', 'admin'), ('group', 'admin'), ('permission', 'all'),
      ('price', '0'), ('total', '0'), ('amount', '0'),
      ('discount', '100'), ('free', 'true'),
  ]

  # Find registration, profile edit, and order forms
  target_forms = [f for f in ALL_FORMS if any(
      k in (f.get('action','') + ' '.join(fld.get('name','') for fld in f.get('fields',[])))
      .lower() for k in ['register', 'signup', 'profile', 'edit', 'update', 'order', 'user']
  )]

  print(f"\n[LOGIC] Testing {len(target_forms)} forms for parameter tampering (mass assignment)")
  for form in target_forms[:10]:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      fields = form.get('fields', [])

      for extra_name, extra_val in TAMPER_FIELDS:
          time.sleep(0.3)
          data = {f['name']: f.get('value','') or 'test' for f in fields if f.get('name')}
          data[extra_name] = extra_val
          try:
              r = session.post(url, data=data, timeout=10, allow_redirects=True)
              # Also try JSON
              r_json = session.post(url, json=data, timeout=10, allow_redirects=True,
                                   headers={'Content-Type': 'application/json'})
              for resp in [r, r_json]:
                  if resp.status_code in (200, 201):
                      body = resp.text.lower()
                      if extra_val in body or f'"{extra_name}"' in body:
                          print(f"  [HIGH] Mass assignment: {url} accepted extra field {extra_name}={extra_val}")
                          logic_findings.append({
                              'url': url, 'param': extra_name, 'value': extra_val,
                              'type': 'mass-assignment',
                              'desc': f"Server accepted injected field {extra_name}={extra_val}",
                          })
                          break
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART E — Privilege Escalation (regular user → admin functions)
  # ══════════════════════════════════════════════════════════════
  # Test if a regular user can access admin endpoints discovered during crawl
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  discovered_creds = _G.get('discovered_creds', [])

  # Find admin paths from crawl
  ADMIN_KEYWORDS = ['admin', 'manage', 'moderator', 'staff', 'superuser',
                    'control-panel', 'backoffice', 'internal']
  admin_paths = set()
  for url in list(AUTH_PAGES.keys()) + list(_G.get('ALL_LINKS', set())):
      if any(kw in url.lower() for kw in ADMIN_KEYWORDS):
          admin_paths.add(url)

  # Also try common admin paths
  for path in ['/admin', '/admin/', '/admin/dashboard', '/admin/users', '/admin/settings',
               '/admin/config', '/admin/logs', '/manage', '/panel', '/staff']:
      admin_paths.add(urljoin(BASE, path))

  print(f"\n[LOGIC] Testing privilege escalation on {len(admin_paths)} admin paths")

  # Get a non-admin session (use discovered non-admin creds or session_b)
  session_b = _G.get('session_b')
  non_admin_session = session_b

  if not non_admin_session and discovered_creds:
      # Log in with a non-admin discovered account
      import requests as _req
      for dc in discovered_creds:
          if 'admin' not in dc.get('username', '').lower():
              ns = _req.Session()
              ns.verify = False
              login_url = _G.get('login_url', BASE + '/login')
              user_field = _G.get('user_field', 'username')
              pass_field = _G.get('pass_field', 'password')
              r = ns.post(login_url, data={
                  user_field: dc['username'], pass_field: dc['password']
              }, allow_redirects=True)
              if 'login' not in r.url.lower() or 'logout' in r.text.lower():
                  non_admin_session = ns
                  print(f"  Using {dc['username']} as non-admin user for privilege testing")
                  break

  if non_admin_session:
      for admin_url in sorted(admin_paths):
          time.sleep(0.3)
          try:
              r = non_admin_session.get(admin_url, timeout=8, allow_redirects=True)
              if r.status_code == 200 and 'login' not in r.url.lower():
                  body = r.text.lower()
                  # Check if it's a real admin page, not a redirect or error
                  if any(kw in body for kw in ['admin', 'manage', 'users', 'settings', 'dashboard', 'config']):
                      if 'access denied' not in body and 'forbidden' not in body and 'not authorized' not in body:
                          print(f"  [CRITICAL] Privilege escalation: non-admin can access {admin_url}")
                          print(f"    Response: {r.text[:200]}")
                          logic_findings.append({
                              'url': admin_url, 'type': 'privilege-escalation',
                              'desc': f'Non-admin user can access admin page',
                              'evidence': r.text[:300],
                          })
              elif r.status_code in (401, 403):
                  print(f"  [OK] {admin_url} — properly restricted ({r.status_code})")
          except Exception:
              continue
  else:
      print("  [INFO] No non-admin session available for privilege escalation testing")

  # ══════════════════════════════════════════════════════════════
  # PART F — Debug Mode / Information Disclosure
  # ══════════════════════════════════════════════════════════════
  DEBUG_PATHS = ['/debug', '/debug/', '/console', '/_debug',
                 '/server-info', '/server-status', '/status',
                 '/env', '/environment', '/config', '/phpinfo.php',
                 '/elmah.axd', '/trace.axd', '/_profiler']

  print(f"\n[LOGIC] Checking for debug/info disclosure endpoints")
  for path in DEBUG_PATHS:
      url = urljoin(BASE, path)
      try:
          r = session.get(url, timeout=6)
          if r.status_code == 200:
              body = r.text.lower()
              # Must contain actual debug/config data, not just an HTML page
              if any(kw in body for kw in ['traceback', 'debugger', 'stack trace', 'secret_key',
                                            'database', 'db_host', 'password', 'environment',
                                            'configuration', 'php version', 'debug = true']):
                  if '<html' not in body[:100] or len(r.text) > 5000:
                      print(f"  [HIGH] Debug/info disclosure: {url}")
                      print(f"    Preview: {r.text[:200]}")
                      logic_findings.append({
                          'url': url, 'type': 'debug-mode',
                          'desc': f'Debug/information disclosure endpoint active',
                          'evidence': r.text[:300],
                      })
      except Exception:
          continue

  # Summary
  print(f"\n=== BUSINESS LOGIC SUMMARY: {len(logic_findings)} issues found ===")
  for f in logic_findings:
      sev = 'HIGH' if f['type'] in ('negative-accepted','coupon-reuse','workflow-bypass-post',
                                     'mass-assignment') else 'MEDIUM'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")
  if logic_findings:
      _G.setdefault('FINDINGS', []).extend([
          {'severity': 'HIGH' if f['type'] in ('negative-accepted','coupon-reuse',
              'workflow-bypass-post','mass-assignment') else 'MEDIUM',
           'title': f"Business Logic — {f['type']}",
           'url': f.get('url', ''),
           'method': f.get('method', 'POST'),
           'evidence': f.get('evidence', ''),
           'detail': f,
           'impact': 'Financial loss, data manipulation, unauthorized operations',
           'screenshot': ''} for f in logic_findings
      ])

# POST-PHASE SCREENSHOT CHECKPOINT — verify business logic findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all business logic findings:")
for finding in _G['FINDINGS']:
    if 'Business Logic' in finding.get('title', ''):
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_19_logic_{finding.get('title').replace('Business Logic — ','').lower()[:40]}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  After confirming each finding: if screenshot shows error/rejection, it's a FALSE POSITIVE — remove it")
  ```
