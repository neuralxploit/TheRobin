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
           'url': f.get('url', ''), 'detail': f} for f in logic_findings
      ])
  ```
