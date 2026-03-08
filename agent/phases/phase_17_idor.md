**Phase 17 — IDOR (Cross-User Access Control)**

  IDOR TESTING — AUTONOMOUS SECOND ACCOUNT ACQUISITION
  ─────────────────────────────────────────────────────────────────
  Rule #0 applies: NEVER stop, NEVER ask the user for input.
  You MUST autonomously obtain a second account using this priority order:

  1. Use _G['creds_b'] if already set (from CLI --user2/--pass2 or Phase 3 discovery)
  2. Use credentials discovered during Phase 3 default credential testing (_G['discovered_creds'])
  3. Try to self-register a new account on /register, /signup, /create-account, /api/register
  4. If all fail, proceed with vertical IDOR only (no horizontal testing)

  NEVER skip IDOR testing entirely. At minimum, always test:
  - Vertical IDOR: regular user accessing /admin/* paths
  - API IDOR: unauthenticated access to API endpoints
  - ID enumeration: incrementing/decrementing IDs on all discovered endpoints

  ─────────────────────────────────────────────────────────────────
  AUTO-REGISTER SECOND ACCOUNT (if no creds_b available):
  ─────────────────────────────────────────────────────────────────

  ```python
  import requests, time, re
  from urllib.parse import urljoin
  from bs4 import BeautifulSoup

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  creds_b = _G.get('creds_b')

  if not creds_b:
      # Try discovered creds from Phase 3 default testing
      discovered = _G.get('discovered_creds', [])
      if discovered:
          # Pick a non-admin account different from creds_a
          creds_a_user = _G.get('creds_a', {}).get('username', '')
          for dc in discovered:
              if dc.get('username') != creds_a_user and 'admin' not in dc.get('username', '').lower():
                  creds_b = dc
                  print(f"[IDOR] Using discovered credentials: {dc['username']}")
                  break
          if not creds_b and discovered:
              creds_b = discovered[0]  # use any discovered cred
              print(f"[IDOR] Using discovered credentials: {creds_b['username']}")

  if not creds_b:
      # Try self-registration
      REGISTER_PATHS = ['/register', '/signup', '/sign-up', '/create-account',
                        '/api/register', '/api/signup', '/api/users', '/join',
                        '/account/register', '/user/register']
      reg_session = requests.Session()
      reg_session.verify = False
      reg_session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120'

      new_user = f'idortest_{int(time.time()) % 10000}'
      new_pass = 'IdorTest123!'
      new_email = f'{new_user}@test.local'

      for reg_path in REGISTER_PATHS:
          reg_url = BASE + reg_path
          try:
              # Try GET first to find form
              r = reg_session.get(reg_url, timeout=6, allow_redirects=True)
              if r.status_code == 404:
                  continue

              # Try HTML form registration
              soup = BeautifulSoup(r.text, 'html.parser')
              form = soup.find('form')
              if form:
                  action = urljoin(reg_url, form.get('action', reg_url))
                  fields = {}
                  for inp in form.find_all(['input', 'textarea']):
                      name = inp.get('name', '')
                      if not name:
                          continue
                      if 'user' in name.lower() or 'name' in name.lower():
                          fields[name] = new_user
                      elif 'email' in name.lower():
                          fields[name] = new_email
                      elif 'pass' in name.lower():
                          fields[name] = new_pass
                      elif inp.get('type') == 'hidden':
                          fields[name] = inp.get('value', '')
                      else:
                          fields[name] = 'test'
                  if fields:
                      r2 = reg_session.post(action, data=fields, timeout=10, allow_redirects=True)
                      if r2.status_code in (200, 201, 302) and 'error' not in r2.text.lower()[:300]:
                          creds_b = {'username': new_user, 'password': new_pass}
                          print(f"[IDOR] Self-registered account: {new_user}")
                          break

              # Try JSON API registration
              for payload in [
                  {'username': new_user, 'password': new_pass, 'email': new_email},
                  {'user': new_user, 'pass': new_pass, 'email': new_email},
                  {'name': new_user, 'password': new_pass, 'email': new_email},
              ]:
                  r3 = reg_session.post(reg_url, json=payload, timeout=10)
                  if r3.status_code in (200, 201) and 'error' not in r3.text.lower()[:200]:
                      creds_b = {'username': new_user, 'password': new_pass}
                      print(f"[IDOR] Self-registered via API: {new_user}")
                      break
              if creds_b:
                  break
          except Exception:
              continue

  if creds_b:
      _G['creds_b'] = creds_b
      # Log in as Session B
      session_b = requests.Session()
      session_b.verify = False
      session_b.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120'
      login_url = _G.get('login_url', BASE + '/login')
      user_field = _G.get('user_field', 'username')
      pass_field = _G.get('pass_field', 'password')
      r_b = session_b.post(login_url, data={
          user_field: creds_b['username'],
          pass_field: creds_b['password'],
      }, allow_redirects=True)
      if 'login' not in r_b.url.lower() or 'logout' in r_b.text.lower():
          _G['session_b'] = session_b
          print(f"[OK] Session B logged in as {creds_b['username']}")
      else:
          print(f"[WARN] Session B login failed for {creds_b['username']} — vertical IDOR only")
          _G['session_b'] = None
  else:
      print("[INFO] No second account available — testing vertical IDOR + API IDOR only")
      _G['session_b'] = None
  ```

  IDOR TESTING — REPLAY HARVESTED IDs WITH SESSION B
  ─────────────────────────────────────────────────────────────────
  Strategy:
    1. Session A already crawled everything and built OBJECT_MAP (endpoint→IDs)
    2. Session B logs in, then replays EVERY endpoint+ID Session A discovered
    3. For each response: compare with Session A's cached snippet
       → if Session B gets Session A's private data = IDOR confirmed
    4. Then Session B crawls its own objects → Session A tests those too (bidirectional)

   Five IDOR types covered automatically:

   Run ALL IDOR tests using the harvested OBJECT_MAP:

    ```python
    import requests, time, re, json
    from urllib.parse import urlparse, urljoin, parse_qs

    BASE       = _G['BASE']
    session_a  = _G.get('session_a')
    session_b  = _G.get('session_b')
    creds_a    = _G.get('creds_a', {})
    creds_b    = _G.get('creds_b', {})
    OBJECT_MAP = _G.get('OBJECT_MAP', {})   # harvested during crawl
    AUTH_PAGES = _G.get('AUTH_PAGES', {})
    findings   = []

    print("\n" + "="*60)
    print("PHASE 11 — IDOR TESTING")
    print("="*60)
    print(f"Session A : {creds_a.get('username')}  (uid={_G.get('uid_a','?')})")
    print(f"Session B : {creds_b.get('username') if creds_b else 'NOT PROVIDED'}  (uid={_G.get('uid_b','?')})")
    print(f"OBJECT_MAP: {len(OBJECT_MAP)} endpoint patterns, "
          f"{sum(len(v) for v in OBJECT_MAP.values())} total URLs harvested from Session A")

    # If no session_b, skip horizontal IDOR but ALWAYS test vertical + API IDOR
    if not session_b:
        print("[INFO] No Session B — skipping horizontal IDOR, testing vertical + API only")

    # ── Helper: response_differs ──────────────────────────────────────────────
    def response_differs(body_a_snippet, body_b):
        # Returns True if body_b contains meaningful content from body_a
        # i.e. Session B got Session A's private data
        if not body_a_snippet or not body_b:
            return False
        # Look for unique tokens from A's response appearing in B's response
        # Extract words of 4+ chars from A's snippet, check if any appear in B
        words_a = set(re.findall(r'[A-Za-z0-9@._-]{4,}', body_a_snippet))
        words_b = set(re.findall(r'[A-Za-z0-9@._-]{4,}', body_b))
        overlap = words_a & words_b
        # Filter out common HTML/framework words
        noise = {'html','body','head','form','class','href','type','name',
                 'input','button','div','span','table','script','style',
                 'True','False','None','null','true','false','HTTP','https',
                 'Bootstrap','jQuery','navbar','panel','container','block',
                 'content','page','data','user','admin','login','logout',
                 'submit','email','pass','text','value','label','method',
                 'action','hidden','csrf','token','POST','GET','session'}
        meaningful = overlap - noise
        return len(meaningful) >= 3  # at least 3 unique tokens match

    def is_blocked(r, url):
        if r.status_code in [401, 403]:
            return True
        if 'login' in r.url.lower() and 'login' not in url.lower():
            return True
        # Some apps return 200 with "access denied" body
        body_lower = r.text.lower()
        if any(p in body_lower for p in ['access denied','forbidden','unauthorized',
                                          'not authorized','permission denied',
                                          'you do not have permission']):
            return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    # TYPE 1 — HORIZONTAL IDOR
    # Replay every URL Session A visited, using Session B's session.
    # If Session B gets the same private data Session A saw → IDOR confirmed.
    # Works for ALL ID formats: integers, UUIDs, hashes, slugs.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("TYPE 1 — HORIZONTAL IDOR (Session B replaying Session A's URLs)")
    print(f"{'─'*60}")

    if session_b:
        confirmed = 0
        for pattern, entries in OBJECT_MAP.items():
            for entry in entries:
                url_a  = entry['url']
                snap_a = entry.get('response_snippet', '')
                time.sleep(0.25)
                try:
                    r_b = session_b.get(url_a, allow_redirects=True, timeout=10)
                except Exception as e:
                    print(f"  [ERR] {url_a}: {e}")
                    continue

                if is_blocked(r_b, url_a):
                    print(f"  [PROTECTED] {url_a}  ({r_b.status_code})")
                    continue

                if response_differs(snap_a, r_b.text):
                    print(f"  [HIGH] Horizontal IDOR CONFIRMED")
                    print(f"         URL     : {url_a}")
                    print(f"         Pattern : {pattern}")
                    print(f"         ID type : {entry['id_type']}  value={entry['id']}")
                    print(f"         Session A snippet : {snap_a[:150]}")
                    print(f"         Session B got     : {r_b.text[:150]}")
                    findings.append({
                        'type': 'Horizontal IDOR',
                        'url': url_a,
                        'id': entry['id'],
                        'id_type': entry['id_type'],
                        'session_b_user': creds_b.get('username'),
                    })
                    confirmed += 1
                else:
                    print(f"  [OK]  {url_a}  — Session B response differs from Session A's (no IDOR)")

        print(f"\nHorizontal IDOR: {confirmed} confirmed out of {sum(len(v) for v in OBJECT_MAP.values())} URLs tested")
    else:
        print("[SKIP] No Session B provided")

    # ══════════════════════════════════════════════════════════════════════════
    # TYPE 2 — BIDIRECTIONAL IDOR
    # Now crawl as Session B, collect Session B's own object IDs,
    # then replay them using Session A. Tests BOTH directions.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("TYPE 2 — BIDIRECTIONAL (Session A accessing Session B's objects)")
    print(f"{'─'*60}")

    if session_b:
        # Quick crawl as Session B to harvest B's own IDs
        UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
        b_urls = set()
        try:
            r_dash = session_b.get(BASE + '/dashboard', timeout=10, allow_redirects=True)
            # Collect all hrefs from dashboard
            for m in re.finditer(r'href=["\']([^"\']+)["\']', r_dash.text):
                href = urljoin(BASE, m.group(1)).split('#')[0]
                if href.startswith(BASE):
                    b_urls.add(href)
            # Visit each link to find Session B's objects
            for u in list(b_urls)[:30]:
                try:
                    r = session_b.get(u, timeout=8, allow_redirects=True)
                    b_urls.add(r.url)
                    # Extract any IDs from links on this page
                    for m2 in re.finditer(r'href=["\']([^"\']+)["\']', r.text):
                        h2 = urljoin(BASE, m2.group(1)).split('#')[0]
                        if h2.startswith(BASE):
                            b_urls.add(h2)
                except Exception:
                    pass
                time.sleep(0.1)
        except Exception as e:
            print(f"  [WARN] Session B crawl failed: {e}")

        # For each URL session_b visited, try it with session_a
        crossed = 0
        for url_b in b_urls:
            if url_b == BASE + '/dashboard':
                continue
            # Only test URLs with IDs in them
            has_id = re.search(r'/\\d+|/[0-9a-f]{8}-[0-9a-f]{4}', url_b)
            if not has_id:
                continue
            time.sleep(0.2)
            try:
                r_b = session_b.get(url_b, timeout=8, allow_redirects=True)
                r_a = session_a.get(url_b, timeout=8, allow_redirects=True)
            except Exception:
                continue
            # If both get content AND it's the same content → same resource, not IDOR
            # If A gets B's data that's visible only to B → IDOR
            if not is_blocked(r_a, url_b) and response_differs(r_b.text, r_a.text):
                print(f"  [HIGH] Bidirectional IDOR — Session A can access Session B's object")
                print(f"         URL: {url_b}")
                print(f"         Session B owner: {creds_b.get('username')}")
                findings.append({'type':'Bidirectional IDOR','url':url_b})
                crossed += 1
            else:
                print(f"  [OK]  {url_b}")
        print(f"\nBidirectional: {crossed} confirmed")
    else:
        print("[SKIP] No Session B")

    # ══════════════════════════════════════════════════════════════════════════
    # TYPE 3 — VERTICAL IDOR (Session B → admin-only paths)
    # Use all /admin/* and privileged paths discovered during Session A's crawl.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("TYPE 3 — VERTICAL IDOR (Session B accessing privileged paths)")
    print(f"{'─'*60}")

    if session_b:
        # Collect all URLs Session A could access that contain 'admin', 'manage',
        # 'settings', 'config', 'report', 'dashboard' etc.
        privileged_urls = set()
        priv_keywords   = ['admin','manage','management','config','configuration',
                           'report','reports','settings','control','panel','staff',
                           'superuser','moderator','backstage','internal','private']
        for url in AUTH_PAGES:
            url_lower = url.lower()
            if any(kw in url_lower for kw in priv_keywords):
                privileged_urls.add(url)

        # Also test the IDs Session A collected on admin paths with Session B
        for pattern in OBJECT_MAP:
            if any(kw in pattern.lower() for kw in priv_keywords):
                for entry in OBJECT_MAP[pattern]:
                    privileged_urls.add(entry['url'])

        print(f"  Privileged URLs to test with Session B: {len(privileged_urls)}")
        vert_confirmed = 0
        for priv_url in sorted(privileged_urls):
            time.sleep(0.25)
            snap_a = AUTH_PAGES.get(priv_url, '')
            try:
                r_b = session_b.get(priv_url, allow_redirects=True, timeout=10)
            except Exception as e:
                print(f"  [ERR] {priv_url}: {e}")
                continue

            if is_blocked(r_b, priv_url):
                print(f"  [PROTECTED] {priv_url}  ({r_b.status_code})")
                continue

            if response_differs(snap_a, r_b.text):
                print(f"  [HIGH] Vertical IDOR CONFIRMED — Session B accessed privileged resource")
                print(f"         URL: {priv_url}")
                print(f"         Session B ({creds_b.get('username')}) got: {r_b.text[:200]}")
                findings.append({'type':'Vertical IDOR','url':priv_url,
                                 'session_b_user': creds_b.get('username')})
                vert_confirmed += 1
            else:
                print(f"  [OK/UNCONFIRMED] {priv_url}  (200 but responses differ — check manually)")
        print(f"\nVertical IDOR: {vert_confirmed} confirmed")
    else:
        print("[SKIP] No Session B")

    # ══════════════════════════════════════════════════════════════════════════
    # TYPE 4 — API IDOR (unauthenticated access to API endpoints)
    # Test every /api/* endpoint with NO session at all.
    # Also test all API endpoints Session A found using Session B.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("TYPE 4 — API IDOR (no auth + cross-user)")
    print(f"{'─'*60}")

    anon = requests.Session()
    anon.verify = False
    api_urls = set()
    for url in list(AUTH_PAGES.keys()) + list(_G.get('ALL_LINKS', set())):
        if '/api/' in url:
            api_urls.add(url)
    # Also try incrementing/decrementing IDs on api endpoints
    expanded_api = set(api_urls)
    for url in api_urls:
        m = re.search(r'(/\\d+)$', url)
        if m:
            base_path = url[:url.rfind('/')]
            cur_id    = int(m.group(1).strip('/'))
            for delta in [-2, -1, 1, 2, 3]:
                expanded_api.add(f"{base_path}/{cur_id + delta}")

    api_found = 0
    for api_url in sorted(expanded_api):
        time.sleep(0.15)
        try:
            r_anon = anon.get(api_url, allow_redirects=True, timeout=8)
        except Exception:
            continue
        if r_anon.status_code == 200 and len(r_anon.text.strip()) > 20:
            try:
                data = r_anon.json()
                print(f"  [HIGH] Unauthenticated API access: {api_url}")
                print(f"         Response: {str(data)[:300]}")
                findings.append({'type':'API IDOR (no auth)','url':api_url,
                                 'response': str(data)[:300]})
                api_found += 1
            except Exception:
                # Not JSON — check if it looks like real data
                if len(r_anon.text) > 100 and '<html' not in r_anon.text[:50].lower():
                    print(f"  [MEDIUM] Non-JSON API response (no auth): {api_url}")
                    print(f"           {r_anon.text[:200]}")
        elif r_anon.status_code in [401, 403]:
            print(f"  [OK]  {api_url}  — {r_anon.status_code} (properly protected)")
        elif r_anon.status_code == 404:
            pass  # endpoint doesn't exist
    print(f"\nAPI IDOR (no auth): {api_found} accessible endpoints found")

    # ══════════════════════════════════════════════════════════════════════════
    # TYPE 5 — WRITE/MUTATE IDOR
    # Session B POSTs to edit forms that belong to Session A's objects.
    # Confirms by fetching the object after the POST and looking for the marker.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("TYPE 5 — WRITE IDOR (Session B mutating Session A's objects)")
    print(f"{'─'*60}")

    if session_b:
        MARKER   = f'IDOR_WRITE_{creds_b.get("username","B")}'
        AUTH_FORMS = _G.get('AUTH_FORMS', [])
        write_confirmed = 0
        # Find forms from Session A that POST to paths containing Session A's IDs
        uid_a = _G.get('uid_a')
        id_a_vals = {str(uid_a)} if uid_a else set()
        # Also collect all ID values Session A owns
        for entries in OBJECT_MAP.values():
            for e in entries:
                id_a_vals.add(str(e['id']))

        for form in AUTH_FORMS:
            if form['method'] != 'post':
                continue
            action  = form['action']
            # Only test forms that contain one of Session A's IDs in the action URL
            action_ids = set(re.findall(r'\\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', action))
            if not action_ids.intersection(id_a_vals):
                continue  # form doesn't reference Session A's objects

            fields  = form['fields']
            # Build form data: inject marker into first text field
            data = {f['name']: f['value'] or 'test' for f in fields}
            text_fields = [f for f in fields if f['type'] in ('text','textarea','email','number','')]
            if not text_fields:
                continue
            data[text_fields[0]['name']] = MARKER

            time.sleep(0.4)
            try:
                r_post = session_b.post(action, data=data, allow_redirects=True, timeout=10)
            except Exception as e:
                print(f"  [ERR] POST {action}: {e}")
                continue

            if is_blocked(r_post, action):
                print(f"  [PROTECTED] POST {action}  ({r_post.status_code})")
                continue

            # Verify: fetch the display page and look for the marker
            display_url = form['page']
            try:
                r_check = session_b.get(display_url, timeout=8, allow_redirects=True)
                if MARKER in r_check.text:
                    print(f"  [CRITICAL] Write IDOR CONFIRMED")
                    print(f"             Session B ({creds_b.get('username')}) wrote to Session A's object")
                    print(f"             POST action : {action}")
                    print(f"             Marker found: {display_url}")
                    findings.append({'type':'Write IDOR','post_url':action,
                                     'display_url':display_url,'marker':MARKER})
                    write_confirmed += 1
                else:
                    print(f"  [INFO] POST {action} — marker not found in display page (blocked or different flow)")
            except Exception as e:
                print(f"  [ERR] GET {display_url}: {e}")

        print(f"\nWrite IDOR: {write_confirmed} confirmed")

    # ── Final summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"IDOR PHASE COMPLETE — {len(findings)} total finding(s)")
    for f in findings:
        print(f"  [{f['type']}]  {f.get('url') or f.get('post_url')}")
    if not findings:
        print("  No IDOR confirmed. All tested endpoints appear to enforce authorization.")
    ```

  IDOR CONFIRMATION RULE — only report if you saw REAL sensitive data:
  - Different usernames/emails/salaries/SSNs = confirmed IDOR
  - Page says "Access Denied" / redirected to login = NOT IDOR
  - Page returns 200 but shows YOUR OWN data = NOT IDOR
  - Page returns 200 but empty / generic = NOT IDOR

  - Check for directory listing: /uploads/, /admin/, /backup/, /files/
    (confirmed only if response contains file listings like "Index of /")
  - Check for sensitive files: robots.txt, sitemap.xml, .htaccess, config.php,
    backup.sql, .git/HEAD, .env, phpinfo.php, server-status

    *** CRITICAL — SENSITIVE FILE FALSE POSITIVE DETECTION ***
    Many SPAs (React, Angular, Vue) return the main index.html with status 200
    for EVERY route — including /.env, /.git/config, /backup.sql. This is NOT
    a real finding. You MUST verify the response CONTENT matches the expected file:

      /.env          → must contain KEY=VALUE lines (DB_HOST=, SECRET=, API_KEY=)
      /.git/HEAD     → must contain "ref: refs/heads/" (exactly)
      /.git/config   → must contain "[core]" and "repositoryformatversion"
      /backup.sql    → must contain "CREATE TABLE" or "INSERT INTO" or "DROP TABLE"
      /database.sql  → same as backup.sql
      /config.php    → must contain "<?php" or actual config values
      /phpinfo.php   → must contain "PHP Version" and "System"
      /.htaccess     → must contain "RewriteRule" or "Deny from" or "Options"

    HOW TO CHECK — verify content type AND body pattern:
    ```python
    r = session.get(url, timeout=8, verify=False)
    ct = r.headers.get('Content-Type', '').lower()
    body = r.text[:500].lower()

    # If response is HTML (SPA catch-all), it's NOT the real file
    if 'text/html' in ct or '<!doctype' in body or '<html' in body:
        print(f'[INFO] {path}: 200 but returns HTML page (SPA catch-all) — NOT exposed')
    else:
        # Check for expected content patterns
        print(f'[HIGH] {path}: Real file exposed — Content-Type: {ct}')
        print(f'  Preview: {r.text[:200]}')
    ```

    If ALL sensitive files return the SAME byte count → SPA catch-all, not real exposure.
    NEVER report a sensitive file finding without showing the actual file content as evidence.

    SCREENSHOT VERIFICATION (mandatory for exposed files/endpoints):
    After detecting a potential sensitive endpoint (actuator, phpinfo, .env, admin, debug, etc.),
    ALWAYS open it in the browser and screenshot before reporting:
      browser_action(action="navigate", url="https://target.com/actuator/health")
      # LOOK at the screenshot — does it show real data or a 404/error/blank page?
      # If 404 or error → FALSE POSITIVE, do not report
      # If real data visible → CONFIRMED, save screenshot as proof
  - Check CSRF: do state-changing forms have CSRF tokens?
    (Missing token on POST/PUT/DELETE forms = [HIGH])
