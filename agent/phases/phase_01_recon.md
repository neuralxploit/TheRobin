**Phase 1 — Recon**
  URL VALIDATION FIRST — before anything else, confirm the target resolves:
    import socket, time
    from urllib.parse import urlparse

    target = 'https://target.com'  # replace with actual target
    hostname = urlparse(target).hostname
    try:
        socket.getaddrinfo(hostname, 443)
        print(f"[INFO] DNS OK: {hostname} resolves")
    except socket.gaierror:
        # Common typo: wwww → www, missing www, wrong subdomain
        print(f"[ERROR] DNS failed for {hostname} — trying alternatives:")
        alternatives = []
        if hostname.startswith('wwww.'):
            alternatives.append(target.replace('wwww.', 'www.', 1))
        if not hostname.startswith('www.'):
            alternatives.append(target.replace('://', '://www.', 1))
        # Try stripping subdomains
        parts = hostname.split('.')
        if len(parts) > 2:
            alternatives.append(target.replace(hostname, '.'.join(parts[-2:])))
        working = None
        for alt in alternatives:
            try:
                alt_host = urlparse(alt).hostname
                socket.getaddrinfo(alt_host, 443)
                print(f"  Found working URL: {alt}")
                working = alt
                break
            except Exception:
                pass
        if working:
            BASE = working   # use the working URL going forward
            target = working
            print(f"[INFO] Using {working} as target")
        else:
            print(f"[ERROR] Cannot resolve target — check the URL and try again")

  - Fetch homepage and ALWAYS capture the final URL after redirects:
      session = requests.Session()
      session.verify = False
      session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0'
      r = session.get(target, timeout=15, allow_redirects=True)
      # Log redirect chain
      if r.history:
          print(f"Redirect chain ({len(r.history)} hops):")
          for h in r.history:
              print(f"  {h.status_code} → {h.headers.get('Location', '?')}")
      print(f"Final URL: {r.url}  (Status: {r.status_code})")
      # Set BASE to the ORIGIN of the target (scheme + host + port), NOT the redirect destination.
      # If target redirects / → /login, we still want BASE = http://host:port
      _parsed = urlparse(target)
      BASE = f"{_parsed.scheme}://{_parsed.netloc}".rstrip('/')
      soup = BeautifulSoup(r.text, 'html.parser')
  - Print: status code, server header, X-Powered-By, detected technologies
  - Identify: CMS? Framework? Language? Interesting paths?

  SPIDER — extract ALL pages, links, and forms (run this as a dedicated run_python call):
    Use this exact spider function. It crawls the entire app and builds a map you will
    use throughout ALL subsequent phases. Store results in global _G so other calls use them.

    ```python
    import requests, time
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urlparse

    BASE    = _G['BASE']           # always set from user input at session start
    session = _G.get('session', requests.Session())
    session.verify = False

    visited = set()
    queue = [BASE + '/']
    # Global maps — filled by spider, used in ALL later phases
    ALL_PAGES = {}    # url → response text
    ALL_FORMS = []    # list of {url, method, action, fields: [{name, type, value}]}
    ALL_LINKS = set() # every href found

    # Scope check: target domain + subdomains only
    _base_host = urlparse(BASE).netloc.split(':')[0].lstrip('www.')

    def _in_scope(check_url):
        h = urlparse(check_url).netloc.split(':')[0].lstrip('www.')
        return h == _base_host or h.endswith('.' + _base_host)

    def spider_page(url):
        url = url.split('#')[0].rstrip('/')  # strip anchors, trailing slash
        if url in visited:
            return
        # SCOPE CHECK — only crawl target domain and its subdomains
        if not _in_scope(url):
            return
        visited.add(url)
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
        except Exception as e:
            print(f"  [SKIP] {url} — {e}")
            return
        ALL_PAGES[url] = r.text
        soup = BeautifulSoup(r.text, 'html.parser')

        # Extract all links
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            full = urljoin(url, href).split('#')[0].rstrip('/')
            ALL_LINKS.add(full)
            if full not in visited:
                queue.append(full)

        # Extract all forms with every field
        for form in soup.find_all('form'):
            action = form.get('action', url)
            action_url = urljoin(url, action)
            method = form.get('method', 'get').lower()
            fields = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                fname = inp.get('name') or inp.get('id') or ''
                ftype = inp.get('type', 'text').lower()
                fval  = inp.get('value', '')
                if fname:
                    fields.append({'name': fname, 'type': ftype, 'value': fval})
            if fields:  # only record forms that have usable inputs
                ALL_FORMS.append({
                    'page': url,
                    'action': action_url,
                    'method': method,
                    'fields': fields,
                })
                print(f"  [FORM] {method.upper()} {action_url}")
                for f in fields:
                    print(f"         field: {f['name']} ({f['type']})")

    # BFS crawl
    while queue:
        url = queue.pop(0)
        spider_page(url)
        time.sleep(0.1)  # polite delay

    # ── Deduplicate parameterized URLs ──────────────────────────
    # /admin/user/1/edit, /admin/user/2/edit, /profile/3/edit are
    # the SAME form — test once, not N times.  Collapse numeric
    # path segments so later phases don't waste context retesting.
    import re as _re
    def _normalise_path(u):
        """Replace numeric path segments with {id} for dedup."""
        p = urlparse(u)
        parts = p.path.rstrip('/').split('/')
        norm = '/'.join('{id}' if _re.fullmatch(r'\d+', seg) else seg for seg in parts)
        return f"{p.scheme}://{p.netloc}{norm}"

    # Deduplicate forms: keep first form per (normalised_action, method, field_names)
    _seen_forms = set()
    DEDUPED_FORMS = []
    for form in ALL_FORMS:
        norm_action = _normalise_path(form['action'])
        field_names = tuple(sorted(f['name'] for f in form.get('fields', [])))
        key = (norm_action, form['method'], field_names)
        if key not in _seen_forms:
            _seen_forms.add(key)
            DEDUPED_FORMS.append(form)

    if len(DEDUPED_FORMS) < len(ALL_FORMS):
        print(f"\n  [DEDUP] Collapsed {len(ALL_FORMS)} forms → {len(DEDUPED_FORMS)} unique form templates")
    ALL_FORMS = DEDUPED_FORMS

    # Save to globals so all future run_python calls can access them
    _G['ALL_PAGES'] = ALL_PAGES
    _G['ALL_FORMS'] = ALL_FORMS
    _G['ALL_LINKS'] = ALL_LINKS

    print(f"\n=== SPIDER COMPLETE ===")
    print(f"Pages crawled : {len(ALL_PAGES)}")
    print(f"Forms found   : {len(ALL_FORMS)}")
    print(f"Links found   : {len(ALL_LINKS)}")
    print("\nAll pages:")
    for u in sorted(ALL_PAGES):
        print(f"  {u}  ({len(ALL_PAGES[u])} bytes)")
    print("\nAll forms:")
    for f in ALL_FORMS:
        print(f"  [{f['method'].upper()}] {f['action']}  (on page: {f['page']})")
    ```

  ═══════════════════════════════════════════════════════
  SPA DETECTION & JAVASCRIPT API EXTRACTION (mandatory after spider)
  ═══════════════════════════════════════════════════════
  Modern apps (Angular, React, Vue) serve a single HTML page with all routing
  in JavaScript. The spider above will find ZERO forms and ZERO links on SPAs.
  You MUST detect this and extract API endpoints from JS bundles.

  ```python
  import requests, re, time
  from urllib.parse import urljoin, urlparse

  BASE      = _G['BASE']
  session   = _G.get('session', requests.Session())
  ALL_PAGES = _G.get('ALL_PAGES', {})
  ALL_FORMS = _G.get('ALL_FORMS', [])
  ALL_LINKS = _G.get('ALL_LINKS', set())

  # ── SPA Detection ──────────────────────────────────────────────────
  homepage = list(ALL_PAGES.values())[0] if ALL_PAGES else ''
  SPA_INDICATORS = ['<app-root', '<div id="root"', '<div id="app"',
                    'ng-app=', 'ng-version=', 'data-reactroot',
                    '__NEXT_DATA__', '__NUXT__', 'vue-app',
                    'angular', 'react', 'vue.js', 'ember']
  is_spa = any(ind.lower() in homepage.lower() for ind in SPA_INDICATORS)
  # Also detect: very few forms found + JS bundles present
  if len(ALL_FORMS) <= 1 and ('<script' in homepage and '.js' in homepage):
      is_spa = True

  _G['IS_SPA'] = is_spa
  print(f"\n[SPA DETECTION] Is SPA: {is_spa}")
  if is_spa:
      print("  Angular/React/Vue detected — extracting API endpoints from JavaScript bundles")

  # ── Extract ALL JavaScript bundle URLs ────────────────────────────
  JS_URLS = set()
  for page_url, body in ALL_PAGES.items():
      for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I):
          js_url = urljoin(page_url, m.group(1))
          if urlparse(js_url).netloc == urlparse(BASE).netloc:
              JS_URLS.add(js_url)

  print(f"  Found {len(JS_URLS)} JavaScript files to analyze")

  # ── Download and parse JS bundles for API endpoints ───────────────
  API_ENDPOINTS = set()
  JS_SECRETS    = []  # API keys, tokens found in JS

  # Patterns to find API paths in JavaScript code
  API_PATTERNS = [
      # fetch/axios/http calls
      r'''(?:fetch|get|post|put|delete|patch|axios|http\.)\s*\(\s*[`'"](\/[a-zA-Z0-9/_.-]{2,})[`'"]''',
      # String assignments that look like API paths
      r'''[`'"](\/(?:api|rest|v[12]|graphql|auth|user|admin|product|order|basket|card|address|feedback|complaint|recycle|challenge|security|captcha|track|wallet|deliver)[a-zA-Z0-9/_.-]*)[`'"]''',
      # URL concatenation patterns
      r'''[`'"](\/rest\/[a-zA-Z0-9/_.-]+)[`'"]''',
      r'''[`'"](\/api\/[a-zA-Z0-9/_.-]+)[`'"]''',
      # Angular HttpClient patterns
      r'''\.(?:get|post|put|delete|patch)\s*(?:<[^>]*>)?\s*\(\s*[`'"](\/[a-zA-Z0-9/_.-]{2,})[`'"]''',
      # apiUrl/baseUrl concatenation
      r'''(?:apiUrl|baseUrl|endpoint|api_url|API_URL)\s*\+\s*[`'"](\/[a-zA-Z0-9/_.-]{2,})[`'"]''',
      r'''(?:apiUrl|baseUrl|endpoint|api_url|API_URL)\s*[:=]\s*[`'"]((?:https?:\/\/)?[a-zA-Z0-9._-]*\/[a-zA-Z0-9/_.-]+)[`'"]''',
  ]

  # Secret patterns
  SECRET_PATTERNS = [
      (r'''(?:api[_-]?key|apikey|api_secret|token|secret|password|passwd|authorization)\s*[:=]\s*[`'"]([a-zA-Z0-9_/+=.-]{8,})[`'"]''', 'API Key/Secret'),
      (r'''(?:Bearer|Basic)\s+([a-zA-Z0-9_/+=.-]{20,})''', 'Auth Token'),
      (r'''eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}''', 'JWT Token'),
  ]

  for js_url in sorted(JS_URLS):
      try:
          r = session.get(js_url, timeout=15)
          if r.status_code != 200:
              continue
          js_body = r.text
          print(f"  [JS] Analyzing {js_url} ({len(js_body)} bytes)")

          # Extract API paths
          for pattern in API_PATTERNS:
              for m in re.finditer(pattern, js_body, re.I):
                  path = m.group(1)
                  if path.startswith('/'):
                      full_url = BASE + path
                  elif path.startswith('http'):
                      full_url = path
                  else:
                      continue
                  API_ENDPOINTS.add(full_url)

          # Extract secrets
          for pattern, secret_type in SECRET_PATTERNS:
              for m in re.finditer(pattern, js_body, re.I):
                  val = m.group(1) if '(' in pattern else m.group(0)
                  JS_SECRETS.append({'type': secret_type, 'value': val[:80], 'file': js_url})

          time.sleep(0.1)
      except Exception as e:
          print(f"  [ERR] {js_url}: {e}")

  # ── Probe discovered API endpoints ────────────────────────────────
  CONFIRMED_APIS = []
  for api_url in sorted(API_ENDPOINTS):
      try:
          r = session.get(api_url, timeout=6, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201) and len(r.text.strip()) > 10:
              CONFIRMED_APIS.append({'url': api_url, 'status': r.status_code,
                                      'size': len(r.text), 'content_type': r.headers.get('Content-Type','')})
              # Also add to ALL_LINKS so later phases discover them
              ALL_LINKS.add(api_url)
              print(f"  [API] {api_url} — {r.status_code} ({len(r.text)} bytes)")
          elif r.status_code == 401:
              CONFIRMED_APIS.append({'url': api_url, 'status': 401, 'size': 0, 'content_type': ''})
              ALL_LINKS.add(api_url)
              print(f"  [API-AUTH] {api_url} — 401 (needs auth)")
      except Exception:
          pass

  # Also try common REST API paths not found in JS (generic — works on any app)
  SPA_COMMON_PATHS = [
      # Auth / user endpoints
      '/rest/user/login', '/rest/user/whoami',
      '/api/login', '/api/auth', '/api/me', '/api/profile', '/api/whoami',
      '/api/user', '/api/users', '/api/account', '/api/session',
      '/api/v1/login', '/api/v1/users', '/api/v1/me',
      # Data endpoints
      '/api/products', '/api/orders', '/api/items', '/api/data',
      '/api/search', '/api/config', '/api/settings', '/api/status',
      '/api/files', '/api/uploads', '/api/export', '/api/import',
      '/api/feedback', '/api/comments', '/api/reviews', '/api/messages',
      # Admin / system
      '/api/admin', '/api/admin/users', '/api/admin/config',
      '/api/logs', '/api/debug', '/api/health', '/api/metrics',
      '/api/keys', '/api/tokens', '/api/roles', '/api/permissions',
      # REST variants
      '/rest/products', '/rest/users', '/rest/admin',
      '/rest/search', '/rest/orders',
      # Common app paths
      '/profile', '/dashboard', '/admin', '/settings',
      '/upload', '/file-upload', '/support', '/contact',
      '/search', '/register', '/signup', '/forgot-password',
      '/graphql', '/graphiql',
  ]
  for path in SPA_COMMON_PATHS:
      url = BASE + path
      if url in API_ENDPOINTS:
          continue
      try:
          r = session.get(url, timeout=6, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201, 401, 403) and r.status_code != 404:
              ALL_LINKS.add(url)
              if r.status_code in (200, 201) and len(r.text.strip()) > 10:
                  CONFIRMED_APIS.append({'url': url, 'status': r.status_code,
                                          'size': len(r.text), 'content_type': r.headers.get('Content-Type','')})
                  print(f"  [API] {url} — {r.status_code} ({len(r.text)} bytes)")
              elif r.status_code == 401:
                  CONFIRMED_APIS.append({'url': url, 'status': 401, 'size': 0, 'content_type': ''})
                  print(f"  [API-AUTH] {url} — 401 (needs auth)")
      except Exception:
          pass

  _G['ALL_LINKS']      = ALL_LINKS
  _G['API_ENDPOINTS']  = API_ENDPOINTS
  _G['CONFIRMED_APIS'] = CONFIRMED_APIS
  _G['JS_SECRETS']     = JS_SECRETS

  print(f"\n=== JS API EXTRACTION COMPLETE ===")
  print(f"  API endpoints found in JS : {len(API_ENDPOINTS)}")
  print(f"  Confirmed live APIs       : {len(CONFIRMED_APIS)}")
  print(f"  Secrets found in JS       : {len(JS_SECRETS)}")
  if JS_SECRETS:
      for s in JS_SECRETS[:10]:
          print(f"    [{s['type']}] {s['value'][:40]}... in {s['file'].split('/')[-1]}")
  ```

  IMPORTANT: The unauthenticated spider runs BEFORE login.
  You MUST run a second spider AFTER login (see Phase 3 — AUTHENTICATED CRAWL below).
  Logged-in users see completely different pages (dashboard, profile, comments, admin).
  For SPAs: authenticated crawl should also re-probe all API_ENDPOINTS with the auth token.
