**Phase 8 — Technology Fingerprinting & CVE Detection**
  This phase identifies ALL technologies and checks them against known CVEs.

  Step 1 — Extract technology versions from HTML and headers:
  ```python
  import requests, re, json
  from bs4 import BeautifulSoup
  from urllib.parse import urljoin

  BASE = 'http://target.com'
  session = requests.Session()
  session.headers['User-Agent'] = 'Mozilla/5.0 Chrome/120'
  session.verify = False

  r = session.get(BASE, timeout=10)
  soup = BeautifulSoup(r.text, 'html.parser')

  techs = {}  # name -> version

  # Server headers
  for h in ['Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version']:
      if h in r.headers:
          techs[h] = r.headers[h]

  # JS libraries from <script src="...">
  for tag in soup.find_all('script', src=True):
      src = tag['src']
      # jQuery: jquery-3.4.1.min.js or jquery/3.4.1/
      m = re.search(r'jquery[/-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['jQuery'] = m.group(1)
      # Bootstrap
      m = re.search(r'bootstrap[/-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['Bootstrap'] = m.group(1)
      # Angular
      m = re.search(r'angular[^/]*[/-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['Angular'] = m.group(1)
      # React
      m = re.search(r'react[.-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['React'] = m.group(1)
      # Vue
      m = re.search(r'vue[.-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['Vue.js'] = m.group(1)
      # Lodash
      m = re.search(r'lodash[.-]([0-9]+[.][0-9]+[.0-9]*)', src, re.I)
      if m: techs['Lodash'] = m.group(1)

  # Meta generator tag
  gen = soup.find('meta', attrs={'name': 'generator'})
  if gen and gen.get('content'):
      techs['Generator'] = gen['content']

  # WordPress/Drupal/Joomla hints
  if '/wp-content/' in r.text: techs['CMS'] = 'WordPress'
  if '/sites/default/' in r.text: techs['CMS'] = 'Drupal'
  if '/components/com_' in r.text: techs['CMS'] = 'Joomla'

  print("=== Detected Technologies ===")
  for name, ver in techs.items():
      print(f"  {name}: {ver}")
  ```

  Step 2 — Query the NVD API for each detected version:
  ```python
  # For each technology found, search NVD
  for tech_name, version in techs.items():
      query = f"{tech_name} {version}".strip()
      api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
      try:
          resp = requests.get(api_url, timeout=15)
          if resp.status_code == 200:
              data = resp.json()
              total = data.get('totalResults', 0)
              if total > 0:
                  print(f"\n  [HIGH] {tech_name} {version} — {total} CVEs found:")
                  for item in data.get('vulnerabilities', [])[:3]:
                      cve = item.get('cve', {})
                      cve_id = cve.get('id', '')
                      desc = cve.get('descriptions', [{}])[0].get('value', '')[:120]
                      metrics = cve.get('metrics', {})
                      score = '?'
                      for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                          if key in metrics:
                              score = metrics[key][0].get('cvssData', {}).get('baseScore', '?')
                              break
                      print(f"    {cve_id}  CVSS:{score}  {desc}")
              else:
                  print(f"  [INFO] {tech_name} {version} — no CVEs found in NVD")
      except Exception as e:
          print(f"  [ERROR] NVD lookup failed for {tech_name}: {e}")
  ```

  Step 3 — Check well-known vulnerable version thresholds:
  - jQuery < 3.5.0 → CVE-2020-11022 (XSS via .html()) → [HIGH]
  - jQuery < 3.0.0 → CVE-2019-11358 (prototype pollution) → [HIGH]
  - Bootstrap < 3.4.1 or < 4.3.1 → XSS vulnerabilities → [MEDIUM]
  - Angular < 1.6.0 → sandbox escapes → [HIGH]
  - Lodash < 4.17.21 → prototype pollution → [HIGH]
  - Apache httpd: check for CVEs matching major.minor version

**Phase 8 (continued) — JavaScript File Analysis**

Download every JS file found during spidering and analyse the content for:
secrets, dangerous sinks, prototype pollution, and embedded library versions.

```python
import re, requests, time
from urllib.parse import urljoin

_js_session = _G.get('session_a') or _G.get('session') or requests.Session()
_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# ── Collect all JS URLs from spider + HTML script tags ────────────────────────
from bs4 import BeautifulSoup
BASE = _G['BASE']
_js_urls = set()

# From ALL_LINKS (spider results) — look for .js URLs
for _url in _G.get('ALL_LINKS', set()):
    if _url.endswith('.js') or '.js?' in _url:
        _js_urls.add(_url)

# From all pages discovered — re-parse script tags
_all_discovered = {**_G.get('ALL_PAGES', {}), **_G.get('AUTH_PAGES', {})}
for _page_url, _page_html in _all_discovered.items():
    try:
        _soup = BeautifulSoup(_page_html, 'html.parser')
        for _tag in _soup.find_all('script', src=True):
            _src = _tag['src']
            _full = _src if _src.startswith('http') else urljoin(BASE, _src)
            if BASE.split('/')[2] in _full or _full.startswith('/'):
                _js_urls.add(urljoin(BASE, _src))
    except Exception:
        pass

print(f'[JS] Found {len(_js_urls)} JS files to analyse')

# ── Patterns: secrets / API keys ──────────────────────────────────────────────
_SECRET_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}',                    'Google API Key',      'CRITICAL'),
    (r'AKIA[0-9A-Z]{16}',                           'AWS Access Key ID',   'CRITICAL'),
    (r'["\']?aws_secret["\']?\s*[:=]\s*["\'][^"\']{20,}', 'AWS Secret',   'CRITICAL'),
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+]{20,}["\']',
                                                    'Generic API Key',     'HIGH'),
    (r'["\']?secret["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{16,}["\']',
                                                    'Hardcoded Secret',    'HIGH'),
    (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
                                                    'Hardcoded Password',  'HIGH'),
    (r'["\']?token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_\.]{20,}["\']',
                                                    'Auth Token',          'HIGH'),
    (r'sk-[A-Za-z0-9]{32,}',                        'OpenAI API Key',      'CRITICAL'),
    (r'github_pat_[A-Za-z0-9_]{40,}',               'GitHub PAT',          'CRITICAL'),
    (r'mongodb(\+srv)?://[^\s"\']+',                 'MongoDB URI',         'CRITICAL'),
    (r'postgres://[^\s"\']+',                        'PostgreSQL URI',      'CRITICAL'),
    (r'mysql://[^\s"\']+',                           'MySQL URI',           'CRITICAL'),
    (r'https?://[a-zA-Z0-9\-]+\.internal[/:\s]',    'Internal URL',        'MEDIUM'),
    (r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+',       'Private IP',          'LOW'),
    (r'localhost:\d{4,5}',                           'Localhost endpoint',  'LOW'),
    (r'BEGIN (RSA |EC )?PRIVATE KEY',                'Private Key',         'CRITICAL'),
]

# ── Patterns: dangerous DOM sinks (DOM-based XSS) ─────────────────────────────
_SINK_PATTERNS = [
    (r'\.innerHTML\s*=',                   'innerHTML assignment',      'HIGH'),
    (r'\.outerHTML\s*=',                   'outerHTML assignment',      'HIGH'),
    (r'document\.write\s*\(',             'document.write()',          'HIGH'),
    (r'document\.writeln\s*\(',           'document.writeln()',        'HIGH'),
    (r'\beval\s*\(',                       'eval()',                    'HIGH'),
    (r'setTimeout\s*\(\s*["\`]',          'setTimeout(string)',        'MEDIUM'),
    (r'setInterval\s*\(\s*["\`]',         'setInterval(string)',       'MEDIUM'),
    (r'location\.href\s*=',               'location.href assignment',  'MEDIUM'),
    (r'location\.replace\s*\(',           'location.replace()',        'MEDIUM'),
    (r'window\.open\s*\(',                'window.open()',             'LOW'),
    (r'\$\s*\(\s*location|location\.hash','jQuery(location)',          'HIGH'),
    (r'\.insertAdjacentHTML\s*\(',        'insertAdjacentHTML()',      'HIGH'),
    (r'new\s+Function\s*\(',              'new Function()',            'HIGH'),
]

# ── Patterns: prototype pollution sinks in JS source ─────────────────────────
_PROTO_PATTERNS = [
    (r'__proto__',          'Prototype access __proto__'),
    (r'constructor\.prototype', 'constructor.prototype access'),
    (r'Object\.assign\s*\(', 'Object.assign (possible pollution sink)'),
    (r'merge\s*\(',          'Deep merge function (possible pollution)'),
    (r'extend\s*\(',         'Extend function (possible pollution)'),
    (r'\[["\']\w+["\']\]\s*=', 'Dynamic key assignment'),
]

# ── Analyse each JS file ──────────────────────────────────────────────────────
_js_findings = []

for _js_url in sorted(_js_urls):
    time.sleep(0.3)
    try:
        _jr = _js_session.get(_js_url, timeout=10, verify=False,
                              headers={'User-Agent': _UA})
        if _jr.status_code != 200:
            continue
        _content = _jr.text
        _fname = _js_url.split('/')[-1].split('?')[0][:40]
    except Exception as _e:
        print(f'[ERROR] {_js_url}: {_e}')
        continue

    _file_findings = []
    print(f'\n[JS] Analysing: {_fname} ({len(_content):,} chars)')

    # -- Version detection from content (handles bundled/minified libs) --------
    for _lib, _pat in [
        ('jQuery',    r'jquery[:\s]+["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
        ('Bootstrap', r'bootstrap[:\s]+["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
        ('Lodash',    r'lodash[:\s]+["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
        ('Angular',   r'angular[:\s]+["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
        ('React',     r'react[:\s]+["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    ]:
        _m = re.search(_pat, _content, re.I)
        if _m:
            print(f'  [INFO] {_lib} v{_m.group(1)} detected inside {_fname}')
            if _lib not in techs:
                techs[_lib] = _m.group(1)

    # -- Secret scanning -------------------------------------------------------
    for _pat, _desc, _sev in _SECRET_PATTERNS:
        for _match in re.finditer(_pat, _content, re.I):
            _snippet = _match.group(0)[:80]
            # Skip obvious placeholders
            if any(p in _snippet.lower() for p in ['example', 'placeholder', 'your_', 'xxx', '<', '>']):
                continue
            print(f'  [{_sev}] {_desc} in {_fname}')
            print(f'    Match: {_snippet}')
            _file_findings.append({'sev': _sev, 'type': _desc, 'file': _js_url,
                                   'snippet': _snippet})

    # -- Dangerous sink scanning (DOM XSS) -------------------------------------
    _sink_hits = []
    for _pat, _desc, _sev in _SINK_PATTERNS:
        _matches = re.findall(_pat, _content)
        if _matches:
            _sink_hits.append((_desc, _sev, len(_matches)))
            print(f'  [{_sev}] DOM sink: {_desc}  (×{len(_matches)}) in {_fname}')
    if _sink_hits:
        _file_findings.append({'sev': 'HIGH', 'type': 'DOM XSS sinks', 'file': _js_url,
                               'sinks': _sink_hits})

    # -- Prototype pollution source patterns -----------------------------------
    _proto_hits = []
    for _pat, _desc in _PROTO_PATTERNS:
        if re.search(_pat, _content):
            _proto_hits.append(_desc)
    if '__proto__' in _content or 'constructor.prototype' in _content:
        print(f'  [HIGH] Prototype pollution pattern in {_fname}: {_proto_hits}')
        _file_findings.append({'sev': 'HIGH', 'type': 'Prototype pollution source',
                               'file': _js_url, 'patterns': _proto_hits})

    if not _file_findings:
        print(f'  [OK] No issues found in {_fname}')
    else:
        _js_findings.extend(_file_findings)

_G['JS_FINDINGS'] = _js_findings
# Also store in main FINDINGS for PDF report
_G.setdefault('FINDINGS', [])
for _jf in _js_findings:
    _G['FINDINGS'].append({
        'severity': _jf.get('sev', 'HIGH'),
        'title': _jf.get('type', 'JS Secret Exposure'),
        'url': _jf.get('file', ''),
        'evidence': _jf.get('match', _jf.get('evidence', '')),
        'impact': 'Exposed secrets, credentials, or vulnerable code patterns in JavaScript',
        'remediation': 'Remove secrets and sensitive data from client-side JavaScript. Use environment variables server-side and restrict JS to non-sensitive logic.',
        'screenshot': '',
    })
print(f'\n[JS] External JS analysis complete — {len(_js_findings)} issue(s) across {len(_js_urls)} files')

# ── Scan inline <script> blocks + HTML pages for secrets / info disclosure ────
print(f'\n[INFO-DISC] Scanning {len(_all_discovered)} pages for inline secrets & info disclosure')
_inline_findings = []

for _page_url, _page_html in _all_discovered.items():
    try:
        _soup = BeautifulSoup(_page_html, 'html.parser')
    except Exception:
        continue

    # 1. Scan all inline <script> blocks for secrets
    for _script in _soup.find_all('script'):
        if _script.string and len(_script.string) > 20:
            for _pat, _desc, _sev in _SECRET_PATTERNS:
                for _match in re.finditer(_pat, _script.string, re.I):
                    _snippet = _match.group(0)[:80]
                    if any(p in _snippet.lower() for p in ['example', 'placeholder', 'your_', 'xxx', '<', '>']):
                        continue
                    print(f'  [{_sev}] {_desc} in inline script on {_page_url}')
                    print(f'    Match: {_snippet}')
                    _inline_findings.append({'sev': _sev, 'type': _desc, 'page': _page_url, 'snippet': _snippet})

    # 2. Scan HTML comments for sensitive info
    import re as _re2
    for _comment in _soup.find_all(string=lambda t: isinstance(t, type(_soup.new_string(''))) == False and '<!--' in str(t)):
        pass  # BeautifulSoup handles comments differently
    for _comment in _re2.findall(r'<!--(.*?)-->', _page_html, _re2.DOTALL):
        _comment_lower = _comment.lower()
        if any(kw in _comment_lower for kw in ['password', 'secret', 'key', 'token', 'api',
               'todo', 'fixme', 'hack', 'debug', 'admin', 'credential', 'internal']):
            _snippet = _comment.strip()[:120]
            if len(_snippet) > 5:
                print(f'  [MEDIUM] Sensitive HTML comment on {_page_url}')
                print(f'    Comment: {_snippet}')
                _inline_findings.append({'sev': 'MEDIUM', 'type': 'HTML comment disclosure', 'page': _page_url, 'snippet': _snippet})

    # 3. Check for JSON data embedded in pages (data attributes, script blocks with JSON)
    for _script in _soup.find_all('script', type=True):
        if 'json' in (_script.get('type', '').lower()):
            _json_text = _script.string or ''
            if len(_json_text) > 10:
                for _pat, _desc, _sev in _SECRET_PATTERNS:
                    for _match in re.finditer(_pat, _json_text, re.I):
                        _snippet = _match.group(0)[:80]
                        if any(p in _snippet.lower() for p in ['example', 'placeholder', 'your_', 'xxx']):
                            continue
                        print(f'  [{_sev}] {_desc} in JSON block on {_page_url}')
                        _inline_findings.append({'sev': _sev, 'type': _desc, 'page': _page_url, 'snippet': _snippet})

    # 4. Check for exposed data in page (emails, internal paths, debug info)
    _body_lower = _page_html.lower()
    if 'traceback' in _body_lower or 'debug' in _body_lower and 'debugger' not in _body_lower:
        if 'File "' in _page_html or 'line ' in _page_html:
            print(f'  [HIGH] Debug/traceback info exposed on {_page_url}')
            _inline_findings.append({'sev': 'HIGH', 'type': 'Debug info disclosure', 'page': _page_url})

if _inline_findings:
    _js_findings.extend(_inline_findings)
    _G['JS_FINDINGS'] = _js_findings
print(f'[INFO-DISC] Inline scan complete — {len(_inline_findings)} finding(s)')
```

**Phase 8 (continued) — Prototype Pollution Active Testing**

After JS static analysis, actively test if the app is vulnerable to prototype pollution via HTTP parameters:

```python
import requests, json, time

_pp_session = _G.get('session_a') or _G.get('session') or requests.Session()
_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# Prototype pollution via query string — these pollute Object.prototype in
# vulnerable server-side (Node.js/Express) or client-side parsing libraries
_PP_PAYLOADS = [
    {'__proto__[polluted]': 'pp_test_1'},
    {'constructor[prototype][polluted]': 'pp_test_2'},
    {'__proto__.polluted': 'pp_test_3'},
]

_pp_found = False
for _payload in _PP_PAYLOADS:
    time.sleep(0.5)
    # Test GET with polluted params
    try:
        _r = _pp_session.get(BASE, params=_payload, timeout=8, verify=False,
                             headers={'User-Agent': _UA})
        _body = _r.text.lower()
        if 'pp_test' in _body or 'polluted' in _body:
            print(f'[CRITICAL] Prototype Pollution CONFIRMED via GET param!')
            print(f'  Payload: {_payload}')
            print(f'  Evidence: {_r.text[:200]}')
            _pp_found = True
            break

        # Also test JSON body (Node.js apps with JSON parsers)
        _rj = _pp_session.post(BASE, json=_payload, timeout=8, verify=False,
                               headers={'User-Agent': _UA,
                                        'Content-Type': 'application/json'})
        if 'pp_test' in _rj.text.lower() or 'polluted' in _rj.text.lower():
            print(f'[CRITICAL] Prototype Pollution CONFIRMED via JSON body!')
            print(f'  Payload: {json.dumps(_payload)}')
            _pp_found = True
            break
    except Exception as _e:
        print(f'  [ERROR] PP test: {_e}')

# Also test known API endpoints
for _ep in list(_G.get('API_ENDPOINTS', [])) + [BASE + '/api']:
    if _pp_found:
        break
    for _payload in _PP_PAYLOADS:
        time.sleep(0.4)
        try:
            _rj = _pp_session.post(_ep, json=_payload, timeout=8, verify=False,
                                   headers={'User-Agent': _UA,
                                            'Content-Type': 'application/json'})
            if 'pp_test' in _rj.text.lower():
                print(f'[CRITICAL] Prototype Pollution CONFIRMED at {_ep}!')
                _pp_found = True
                break
        except Exception:
            pass

if not _pp_found:
    print('[INFO] No prototype pollution detected via active testing')
```

AFTER RUNNING THIS BLOCK — MANDATORY:
1. For each confirmed fingerprint/CVE finding, take a browser screenshot:
   browser_action(action="navigate", url="<url_showing_version>")
   browser_action(action="screenshot", filename="fingerprint_proof_<tech>.png")
2. Update each finding's 'screenshot' field in _G['FINDINGS']
3. If the screenshot shows a generic page with no version info → REMOVE the finding (false positive)
