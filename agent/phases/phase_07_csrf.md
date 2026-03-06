**Phase 7 — CSRF (Cross-Site Request Forgery)**

  Test EVERY state-changing POST form for CSRF. Run as one block.

  ```python
  import time
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  ALL_FORMS  = _G.get('ALL_FORMS', [])

  # Only test POST forms (state-changing). GET forms are not CSRF targets.
  post_forms = [f for f in AUTH_FORMS + ALL_FORMS if f.get('method','get').lower() == 'post']

  # Check SameSite cookie attribute
  samesite_set = False
  for cookie in session.cookies:
      # requests doesn't expose SameSite directly — check via previous header capture
      pass  # will check response headers below

  csrf_findings = []
  print(f"[CSRF] Testing {len(post_forms)} POST forms")

  for form in post_forms:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      fields = form.get('fields', [])
      csrf_token = form.get('csrf_token')
      page = form.get('page', url)

      # Build form data WITHOUT any CSRF token
      data = {}
      for f in fields:
          name = f.get('name', '')
          if not name:
              continue
          # Skip CSRF token fields
          if any(kw in name.lower() for kw in ['csrf', 'token', '_token', 'authenticity']):
              continue
          data[name] = f.get('value', '') or 'csrftest'

      if not data:
          continue

      print(f"\n  Testing: POST {url}  fields={list(data.keys())}")
      if csrf_token:
          print(f"    Form HAS csrf token field: {csrf_token['name']}")
      else:
          print(f"    Form has NO csrf token field")

      # Submit WITHOUT CSRF token, with cross-origin headers
      time.sleep(0.3)
      try:
          r = session.post(url, data=data,
              headers={'Origin': 'https://evil.com', 'Referer': 'https://evil.com/'},
              timeout=10, allow_redirects=True, verify=False)
      except Exception as e:
          print(f"    Error: {e}")
          continue

      body_lower = r.text.lower()
      rejected = (r.status_code in (403, 401)
                  or 'invalid' in body_lower or 'forbidden' in body_lower
                  or 'csrf' in body_lower or 'token' in body_lower)

      if rejected:
          print(f"    [INFO] CSRF protected — server rejected request ({r.status_code})")
      else:
          # Check if the action actually did something (not just returned a form)
          if r.status_code in (200, 302, 303):
              print(f"[HIGH] CSRF CONFIRMED: POST {url}")
              print(f"  Action succeeded without CSRF token (status {r.status_code})")
              print(f"  {'Has' if csrf_token else 'Missing'} CSRF token field")
              csrf_findings.append({
                  'url': url, 'has_token': bool(csrf_token),
                  'status': r.status_code, 'fields': list(data.keys()),
              })

  if csrf_findings:
      _G.setdefault('FINDINGS', [])
      for cf in csrf_findings:
          _G['FINDINGS'].append({
              'severity': 'HIGH',
              'title': f"CSRF — POST {cf['url']}",
              'url': cf['url'], 'detail': cf,
          })
  print(f"\n=== CSRF SUMMARY: {len(csrf_findings)} vulnerable forms ===")
  ```
