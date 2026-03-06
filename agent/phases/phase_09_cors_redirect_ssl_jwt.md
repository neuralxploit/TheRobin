**Phase 9 — CORS, Open Redirect, SSL/TLS, JWT**

  Each sub-test below is a SEPARATE run_python call. Do NOT skip any.

  **CORS Misconfiguration:**
  ```python
  # Test with attacker origin
  r = session.get(BASE, headers={'Origin': 'https://evil.com'}, timeout=10)
  acao = r.headers.get('Access-Control-Allow-Origin', '')
  acac = r.headers.get('Access-Control-Allow-Credentials', '')
  if acao == '*':
      print('[MEDIUM] CORS: wildcard origin allowed')
  if acao == 'https://evil.com':
      print(f'[HIGH] CORS: reflects attacker origin! Credentials: {acac}')
      if acac.lower() == 'true':
          print('[CRITICAL] CORS: reflects origin + credentials=true = full account takeover!')
  ```

  **Open Redirect — STRICT CONFIRMATION REQUIRED:**
  ```python
  # A real open redirect means the Location header hostname IS evil.com
  # (the browser lands on evil.com). It is NOT a finding if evil.com just
  # appears somewhere in the URL as a query param on the SAME site.
  #
  # FALSE POSITIVE EXAMPLES (NOT open redirects):
  #   Location: https://same-site.com/start?login&redirect=https://evil.com
  #     → hostname is same-site.com, evil.com is just a param value = NOT vulnerable
  #   Location: /login?next=https://evil.com&token=abc
  #     → relative redirect to same site, evil.com is a param value = NOT vulnerable
  #   Location: https://same-site.com/auth?returnUrl=https://evil.com
  #     → stays on same-site.com = NOT vulnerable
  #
  # TRUE POSITIVE (real open redirect):
  #   Location: https://evil.com
  #   Location: https://evil.com/path
  #   Location: //evil.com
  #     → browser navigates to evil.com = VULNERABLE
  #
  # WRONG check (causes false positives):
  #   if 'evil.com' in loc:  ← true even for /login?next=https://evil.com
  #
  # CORRECT check — parse the Location hostname:
  from urllib.parse import urlparse as _up

  redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'dest',
                     'destination', 'redir', 'redirect_uri', 'return_url', 'back', 'continue']
  target_host = _up(BASE).netloc.lower()   # e.g. www.example.com

  for param in redirect_params:
      time.sleep(0.3)
      test_url = f"{BASE}?{param}=https://evil.com"
      try:
          r = session.get(test_url, allow_redirects=False, timeout=10, verify=False)
      except Exception as e:
          print(f'  [ERROR] {param}: {e}')
          continue

      loc = r.headers.get('Location', '')
      if not loc:
          # No redirect at all — try with the full follow and check final URL
          r2 = session.get(test_url, allow_redirects=True, timeout=10, verify=False)
          final_host = _up(r2.url).netloc.lower()
          if 'evil.com' in final_host:
              print(f'[HIGH] CONFIRMED open redirect via ?{param}= → final URL: {r2.url}')
          else:
              print(f'[INFO] ?{param}= no redirect (final: {r2.url[:60]})')
          continue

      # Parse the Location header's hostname
      loc_parsed = _up(loc)
      loc_host = loc_parsed.netloc.lower()

      if 'evil.com' in loc_host:
          # Real open redirect — browser would land on evil.com
          print(f'[HIGH] CONFIRMED open redirect via ?{param}= → {loc}')
      elif loc_host == '' or loc_host == target_host or loc.startswith('/'):
          # Redirect stays on same site — NOT a finding
          print(f'[INFO] ?{param}= redirects within same site → {loc[:80]}')
      elif loc_host != target_host and 'evil.com' not in loc_host:
          # Redirects to a third-party site (not evil.com) — could be legit (CDN, SSO)
          print(f'[INFO] ?{param}= redirects to {loc_host} (third party, not our payload)')
      else:
          print(f'[INFO] ?{param}= no open redirect (Location: {loc[:80]})')
  ```

  **HTTP Methods — CONFIRM before reporting:**
  ```python
  # A 200 on PUT/DELETE does NOT confirm the method is "dangerous".
  # Many servers return 200 with an error body (e.g. "Method not allowed" in HTML).
  # You MUST check the response body to confirm the method actually did something.
  for method in ['TRACE', 'PUT', 'DELETE', 'OPTIONS']:
      time.sleep(0.3)
      r = session.request(method, BASE, timeout=10, verify=False)
      body_lower = r.text.lower()[:300]
      if method == 'TRACE':
          if r.status_code == 200 and 'trace' in body_lower:
              print(f'[MEDIUM] TRACE confirmed — server echoed the request back (XST risk)')
          else:
              print(f'[INFO] TRACE: {r.status_code} (blocked or no echo)')
      elif method == 'OPTIONS':
          allowed = r.headers.get('Allow', r.headers.get('Access-Control-Allow-Methods', ''))
          print(f'[INFO] OPTIONS allowed methods: {allowed or "(none disclosed)"}')
      elif r.status_code in [405, 403, 404, 501]:
          print(f'[INFO] {method}: {r.status_code} — properly blocked')
      elif r.status_code == 200:
          # Check if body indicates the method actually worked vs just a 200 error page
          denied_phrases = ['not allowed', 'not supported', 'forbidden', 'method',
                            'error', 'invalid', 'unauthorized', 'disallowed']
          if any(p in body_lower for p in denied_phrases):
              print(f'[INFO] {method}: 200 but body says denied — not a real finding')
              print(f'  Body preview: {r.text[:150]}')
          else:
              print(f'[MEDIUM] {method}: 200 with no denial message — investigate manually')
              print(f'  Body preview: {r.text[:200]}')
      else:
          print(f'[HIGH] {method} method returns {r.status_code} (not blocked)')
  ```

  **SSL/TLS Check (HTTPS targets only):**
  ```python
  import ssl, socket
  try:
      ctx = ssl.create_default_context()
      with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
          s.connect((hostname, 443))
          cert = s.getpeercert()
          ver = s.version()
          print(f'[INFO] TLS version: {ver}')
          # Check expiry
          import datetime
          exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
          days = (exp - datetime.datetime.utcnow()).days
          if days < 30:
              print(f'[HIGH] Certificate expires in {days} days!')
          elif days < 90:
              print(f'[MEDIUM] Certificate expires in {days} days')
  except ssl.SSLError as e:
      print(f'[HIGH] SSL error: {e}')
  ```

  **JWT Token Detection:**
  ```python
  import base64
  # After login, check cookies and response body for JWTs
  for cookie_name, cookie_val in session.cookies.items():
      if cookie_val.count('.') == 2 and cookie_val.startswith('ey'):
          print(f'[INFO] JWT found in cookie: {cookie_name}')
          parts = cookie_val.split('.')
          try:
              header = json.loads(base64.b64decode(parts[0] + '=='))
              payload = json.loads(base64.b64decode(parts[1] + '=='))
              alg = header.get('alg', 'unknown')
              print(f'  Algorithm: {alg}')
              if alg.lower() == 'none':
                  print('[CRITICAL] JWT uses "none" algorithm — forgeable!')
              if alg.startswith('HS'):
                  print(f'[MEDIUM] JWT uses symmetric {alg} — secret may be weak')
              print(f'  Payload: {json.dumps(payload, indent=2)[:300]}')
          except Exception as e:
              print(f'  [ERROR] Could not decode JWT: {e}')
  ```

  **Rate Limiting Test — CONFIRM before reporting:**
  ```python
  # Getting 200 on every request does NOT confirm no rate limiting.
  # The server may show a CAPTCHA, change response content, or block via WAF silently.
  # You MUST inspect response CONTENT across requests, not just status codes.
  url = BASE + '/login'  # or actual login endpoint found in Phase 1
  results = []
  baseline_text = None
  for i in range(15):
      try:
          r = session.post(url, data={'username': 'test', 'password': 'wrong'}, timeout=5)
          if baseline_text is None:
              baseline_text = r.text
          results.append({'status': r.status_code, 'len': len(r.text), 'text': r.text})
      except Exception as e:
          results.append({'status': 0, 'len': 0, 'text': str(e)})
  codes = [x['status'] for x in results]
  # Check for explicit rate limiting signals
  if 429 in codes:
      print('[INFO] Rate limiting confirmed — got HTTP 429')
  elif 503 in codes or 403 in codes:
      print('[INFO] Possible rate limiting — got 503/403 after repeated requests')
  else:
      # Check if response CONTENT changed (CAPTCHA appeared, account locked, etc.)
      captcha_signs = ['captcha', 'robot', 'too many', 'locked', 'blocked', 'unusual activity']
      last_text = results[-1]['text'].lower()
      if any(s in last_text for s in captcha_signs):
          print('[INFO] Rate limiting via CAPTCHA/lockout detected in response body')
      elif results[-1]['len'] != results[0]['len']:
          print(f'[INFO] Response size changed (req1={results[0]["len"]}b req15={results[-1]["len"]}b) — possible lockout')
      else:
          print('[MEDIUM] No rate limiting detected — all 15 requests returned identical responses')
          print('  Note: verify manually — some rate limiting only activates after 50+ requests')
  ```
