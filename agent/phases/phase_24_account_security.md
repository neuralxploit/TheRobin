**Phase 24 — Account Security & Enumeration**

  Test authentication mechanisms for account enumeration, weak password policies,
  lockout bypass, and password reset flaws. These apply to ANY web app with login.

  PART A — Account Enumeration:
  ```python
  import requests, time, json, re
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session') or requests.Session()
  session.verify = False

  _acct_findings = []

  # ── 1. Login endpoint enumeration ─────────────────────────────────
  # Test if the app reveals whether a username/email exists by giving
  # different error messages for valid vs invalid accounts.

  # Find the login endpoint (from Phase 3 discovery)
  login_url = _G.get('api_login_url') or _G.get('login_url')
  login_fields = _G.get('api_login_fields', {})
  is_json = bool(_G.get('api_login_url'))

  if not login_url:
      # Try common login paths
      for path in ['/rest/user/login', '/api/login', '/api/auth/login',
                   '/login', '/api/v1/login', '/api/users/login']:
          try:
              r = session.post(BASE + path,
                               json={'email': 'x@x.com', 'password': 'x'},
                               timeout=8)
              if r.status_code != 404:
                  login_url = BASE + path
                  is_json = True
                  break
          except Exception:
              pass
          try:
              r = session.post(BASE + path,
                               data={'username': 'x@x.com', 'password': 'x'},
                               timeout=8)
              if r.status_code != 404:
                  login_url = BASE + path
                  is_json = False
                  break
          except Exception:
              pass

  if login_url:
      print(f'[ACCT] Testing account enumeration on {login_url}')

      # Determine which field names the login uses
      user_field = 'email'
      pass_field = 'password'
      if login_fields:
          for k in login_fields:
              if k in ('email', 'username', 'user', 'login'):
                  user_field = k
              if k in ('password', 'passwd', 'pass'):
                  pass_field = k

      # Test with a DEFINITELY INVALID email/username
      invalid_users = [
          'definitelynotreal_user_xyz123@example.com',
          'nonexistent_test_account_000@nowhere.invalid',
      ]
      # Test with a LIKELY VALID email (admin accounts often exist)
      likely_valid = [
          'admin@juice-sh.op', 'admin@admin.com', 'admin@localhost',
          'admin', 'administrator', 'test@test.com', 'user@example.com',
      ]
      # Also use known creds if we have them
      known_user = _G.get('creds_a', {}).get('username', '')
      if known_user:
          likely_valid.insert(0, known_user)

      invalid_responses = []
      valid_responses = []

      for user in invalid_users:
          payload = {user_field: user, pass_field: 'WrongPassword123!'}
          try:
              if is_json:
                  r = session.post(login_url, json=payload, timeout=10)
              else:
                  r = session.post(login_url, data=payload, timeout=10)
              invalid_responses.append({
                  'user': user, 'status': r.status_code,
                  'length': len(r.text), 'body': r.text[:300],
                  'time': r.elapsed.total_seconds(),
              })
              time.sleep(0.5)
          except Exception as e:
              print(f'  [ERROR] {e}')

      for user in likely_valid[:3]:
          payload = {user_field: user, pass_field: 'WrongPassword123!'}
          try:
              if is_json:
                  r = session.post(login_url, json=payload, timeout=10)
              else:
                  r = session.post(login_url, data=payload, timeout=10)
              valid_responses.append({
                  'user': user, 'status': r.status_code,
                  'length': len(r.text), 'body': r.text[:300],
                  'time': r.elapsed.total_seconds(),
              })
              time.sleep(0.5)
          except Exception as e:
              print(f'  [ERROR] {e}')

      # Compare responses — different messages = enumeration possible
      if invalid_responses and valid_responses:
          inv = invalid_responses[0]
          for val in valid_responses:
              # Check for different error messages
              msg_diff = inv['body'] != val['body']
              status_diff = inv['status'] != val['status']
              len_diff = abs(inv['length'] - val['length']) > 20
              # Timing difference > 500ms suggests valid user triggers DB lookup
              time_diff = abs(inv['time'] - val['time']) > 0.5

              if msg_diff or status_diff:
                  print(f'  [MEDIUM] Account enumeration possible!')
                  print(f'    Invalid user ({inv["user"]}): status={inv["status"]}, len={inv["length"]}')
                  print(f'      Response: {inv["body"][:150]}')
                  print(f'    Valid user ({val["user"]}): status={val["status"]}, len={val["length"]}')
                  print(f'      Response: {val["body"][:150]}')
                  _acct_findings.append({
                      'severity': 'MEDIUM',
                      'title': 'Account enumeration via login response',
                      'url': login_url,
                      'evidence': f'Different responses for valid vs invalid users',
                  })
                  break
              if time_diff:
                  print(f'  [LOW] Possible timing-based account enumeration')
                  print(f'    Invalid user: {inv["time"]:.3f}s, Valid user: {val["time"]:.3f}s')
                  _acct_findings.append({
                      'severity': 'LOW',
                      'title': 'Timing-based account enumeration',
                      'url': login_url,
                      'evidence': f'Response time difference: {abs(inv["time"]-val["time"]):.3f}s',
                  })
                  break
          else:
              print(f'  [INFO] Login responses identical for valid/invalid users (good)')
  else:
      print('[INFO] No login endpoint found — skipping enumeration tests')

  # ── 2. Registration enumeration ───────────────────────────────────
  print(f'\n[ACCT] Testing registration endpoint for enumeration...')
  REG_PATHS = ['/api/Users', '/api/users', '/api/register', '/api/signup',
               '/register', '/signup', '/api/v1/register', '/api/v1/users',
               '/api/auth/register', '/rest/user/register']

  for path in REG_PATHS:
      url = BASE + path
      try:
          # Try registering with a random email
          r1 = session.post(url, json={
              'email': 'enum_test_xyz@example.com',
              'username': 'enum_test_xyz',
              'password': 'TestPass123!',
              'passwordRepeat': 'TestPass123!',
          }, timeout=10)
          if r1.status_code in (200, 201, 400, 409, 422):
              print(f'  [INFO] Registration endpoint found: {url} (status={r1.status_code})')
              # If 409 Conflict or "already exists" → enumeration
              if r1.status_code == 409 or 'already' in r1.text.lower() or 'exists' in r1.text.lower():
                  print(f'  [MEDIUM] Registration reveals existing accounts: {url}')
                  _acct_findings.append({
                      'severity': 'MEDIUM',
                      'title': 'Account enumeration via registration',
                      'url': url,
                      'evidence': f'Status {r1.status_code}: {r1.text[:200]}',
                  })
              break
      except Exception:
          pass

  # ── 3. Password reset enumeration ─────────────────────────────────
  print(f'\n[ACCT] Testing password reset for enumeration...')
  RESET_PATHS = ['/rest/user/reset-password', '/api/forgot-password',
                 '/api/password-reset', '/api/auth/forgot',
                 '/forgot-password', '/password-reset', '/api/v1/forgot-password']

  for path in RESET_PATHS:
      url = BASE + path
      try:
          r1 = session.post(url, json={'email': 'nonexistent_xyz@example.invalid'}, timeout=10)
          if r1.status_code != 404:
              r2 = session.post(url, json={'email': known_user or 'admin@admin.com'}, timeout=10)
              if r1.text != r2.text or r1.status_code != r2.status_code:
                  print(f'  [MEDIUM] Password reset reveals account existence: {url}')
                  print(f'    Invalid email: status={r1.status_code}, body={r1.text[:150]}')
                  print(f'    Valid email: status={r2.status_code}, body={r2.text[:150]}')
                  _acct_findings.append({
                      'severity': 'MEDIUM',
                      'title': 'Account enumeration via password reset',
                      'url': url,
                      'evidence': 'Different responses for valid vs invalid emails',
                  })
              break
      except Exception:
          pass
  ```

  PART B — Password Policy & Lockout:
  ```python
  # ── 4. Weak password policy ───────────────────────────────────────
  print(f'\n[ACCT] Testing password policy strength...')
  REG_URL = None
  for path in ['/api/Users', '/api/users', '/api/register', '/api/signup',
               '/api/v1/register', '/api/auth/register']:
      try:
          r = session.post(BASE + path, json={
              'email': 'pwtest_strong@example.com', 'username': 'pwtest_strong',
              'password': 'StrongP@ss123!', 'passwordRepeat': 'StrongP@ss123!',
          }, timeout=10)
          if r.status_code in (200, 201, 400, 409, 422):
              REG_URL = BASE + path
              break
      except Exception:
          pass

  if REG_URL:
      WEAK_PASSWORDS = [
          ('1', 'Single character'),
          ('123', 'Three digits only'),
          ('password', 'Dictionary word'),
          ('abc123', 'Simple alphanumeric'),
          ('aaaaaa', 'Repeated character'),
      ]
      import random, string
      _rand = ''.join(random.choices(string.ascii_lowercase, k=6))

      for weak_pw, desc in WEAK_PASSWORDS:
          try:
              r = session.post(REG_URL, json={
                  'email': f'weakpw_{_rand}_{weak_pw[:3]}@example.com',
                  'username': f'weakpw_{_rand}_{weak_pw[:3]}',
                  'password': weak_pw,
                  'passwordRepeat': weak_pw,
              }, timeout=10)
              if r.status_code in (200, 201):
                  print(f'  [MEDIUM] Weak password accepted: "{weak_pw}" ({desc})')
                  _acct_findings.append({
                      'severity': 'MEDIUM',
                      'title': f'Weak password policy — {desc} accepted',
                      'url': REG_URL,
                      'evidence': f'Password "{weak_pw}" was accepted for registration',
                  })
                  break  # One weak password finding is enough
          except Exception:
              pass
          time.sleep(0.3)
  else:
      print('  [INFO] No registration endpoint found — skipping password policy test')

  # ── 5. Account lockout / rate limiting ────────────────────────────
  print(f'\n[ACCT] Testing account lockout mechanism...')
  if login_url:
      user_field_name = user_field if 'user_field' in dir() else 'email'
      pass_field_name = pass_field if 'pass_field' in dir() else 'password'
      test_user = known_user or 'admin@admin.com'

      locked_out = False
      for i in range(10):
          payload = {user_field_name: test_user, pass_field_name: f'WrongPass{i}!'}
          try:
              if is_json:
                  r = session.post(login_url, json=payload, timeout=10)
              else:
                  r = session.post(login_url, data=payload, timeout=10)
              if r.status_code == 429 or 'locked' in r.text.lower() or 'too many' in r.text.lower():
                  print(f'  [INFO] Account lockout triggered after {i+1} attempts (good)')
                  locked_out = True
                  break
          except Exception:
              break
          time.sleep(0.3)

      if not locked_out:
          print(f'  [MEDIUM] No account lockout after 10 failed login attempts')
          _acct_findings.append({
              'severity': 'MEDIUM',
              'title': 'No account lockout mechanism',
              'url': login_url,
              'evidence': '10 failed login attempts accepted without lockout or rate limiting',
          })

  # ── 6. Default / common credentials ──────────────────────────────
  print(f'\n[ACCT] Testing default credentials...')
  DEFAULT_CREDS = [
      ('admin', 'admin'), ('admin', 'password'), ('admin', 'admin123'),
      ('admin', '123456'), ('admin', 'changeme'),
      ('root', 'root'), ('root', 'toor'), ('root', 'password'),
      ('test', 'test'), ('user', 'user'), ('guest', 'guest'),
      ('demo', 'demo'), ('admin', 'admin1234'),
  ]

  if login_url:
      for user, passwd in DEFAULT_CREDS:
          payload = {user_field_name: user, pass_field_name: passwd}
          try:
              if is_json:
                  r = session.post(login_url, json=payload, timeout=10)
              else:
                  r = session.post(login_url, data=payload, timeout=10)
              # Check for successful login indicators
              if r.status_code in (200, 201, 302):
                  body = r.text.lower()
                  cookies = dict(r.cookies)
                  has_token = ('token' in body or 'jwt' in body or
                              'access_token' in body or 'session' in str(cookies).lower())
                  has_success = ('success' in body or 'welcome' in body or
                                'dashboard' in body or 'authentication' in body)
                  if has_token or (r.status_code == 302 and 'login' not in r.headers.get('Location', '').lower()):
                      print(f'  [CRITICAL] Default credentials work: {user}:{passwd}')
                      _acct_findings.append({
                          'severity': 'CRITICAL',
                          'title': f'Default credentials accepted: {user}:{passwd}',
                          'url': login_url,
                          'evidence': f'Login succeeded with {user}:{passwd}',
                      })
                      break
          except Exception:
              pass
          time.sleep(0.5)
      else:
          print(f'  [INFO] No default credentials accepted (good)')

  # ── Summary ───────────────────────────────────────────────────────
  print(f'\n=== ACCOUNT SECURITY SUMMARY: {len(_acct_findings)} issues found ===')
  for f in _acct_findings:
      print(f"  [{f['severity']}] {f['title']}")
  if _acct_findings:
      _G.setdefault('FINDINGS', []).extend(_acct_findings)
  ```
