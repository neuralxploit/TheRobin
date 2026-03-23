**Phase 23 — Sensitive Files, Directories & Configuration Exposure**

  Probe for exposed files, backup data, version control, admin panels, and
  configuration files that should never be publicly accessible. These are among
  the most common real-world findings on production apps.

  PART A — Version Control & Config Leaks:
  ```python
  import requests, time, json
  from urllib.parse import urljoin

  BASE    = _G['BASE']
  session = _G.get('session_a') or _G.get('session')

  _sens_findings = []

  # ── 1. Version control / dotfiles ─────────────────────────────────
  DOTFILE_PATHS = [
      ('/.git/HEAD',           'Git repository exposed'),
      ('/.git/config',         'Git config exposed (may contain credentials)'),
      ('/.gitignore',          'Gitignore exposed (reveals project structure)'),
      ('/.svn/entries',        'SVN repository exposed'),
      ('/.svn/wc.db',          'SVN working copy database exposed'),
      ('/.hg/store/00manifest.i', 'Mercurial repository exposed'),
      ('/.bzr/README',         'Bazaar repository exposed'),
      ('/.env',                'Environment file exposed (secrets/credentials)'),
      ('/.env.local',          'Local env file exposed'),
      ('/.env.production',     'Production env file exposed'),
      ('/.env.backup',         'Env backup exposed'),
      ('/env.js',              'Environment config JS exposed'),
      ('/config.js',           'Config file exposed'),
      ('/config.json',         'Config JSON exposed'),
      ('/config.yml',          'Config YAML exposed'),
      ('/config.yaml',         'Config YAML exposed'),
      ('/.DS_Store',           'macOS DS_Store exposed (directory listing)'),
      ('/Thumbs.db',           'Windows Thumbs.db exposed'),
      ('/.htaccess',           'Apache htaccess exposed'),
      ('/.htpasswd',           'Apache htpasswd exposed (password hashes)'),
      ('/web.config',          'IIS web.config exposed'),
      ('/WEB-INF/web.xml',     'Java WEB-INF exposed'),
      ('/crossdomain.xml',     'Flash crossdomain policy exposed'),
      ('/clientaccesspolicy.xml', 'Silverlight access policy exposed'),
  ]

  print('[SENSITIVE] Testing version control and config file exposure...')
  for path, desc in DOTFILE_PATHS:
      url = BASE + path
      try:
          r = session.get(url, timeout=8, allow_redirects=False)
          # Must be 200 with actual content (not a redirect to login or custom 404)
          if r.status_code == 200 and len(r.text.strip()) > 5:
              # Verify it's real content, not a catch-all SPA page
              ct = r.headers.get('Content-Type', '').lower()
              # SPA catch-all returns HTML for all routes — skip those
              if '<app-root' in r.text or '<div id="root"' in r.text:
                  continue
              # .git/HEAD should start with "ref:" or a SHA hash
              if '.git/HEAD' in path and not (r.text.strip().startswith('ref:') or len(r.text.strip()) == 40):
                  continue
              # .env should contain KEY=VALUE pairs
              if '.env' in path and '=' not in r.text:
                  continue

              sev = 'CRITICAL' if any(k in path for k in ['.env', '.htpasswd', 'web.xml', '.git/config']) else 'HIGH'
              print(f'  [{sev}] {desc}: {url}')
              print(f'    Size: {len(r.text)} bytes, Content-Type: {ct}')
              print(f'    Preview: {r.text[:200]}')
              _sens_findings.append({
                  'severity': sev, 'title': desc,
                  'url': url, 'evidence': r.text[:300],
              })
      except Exception:
          pass
      time.sleep(0.2)

  # ── 2. Backup & database files ────────────────────────────────────
  print('\n[SENSITIVE] Testing backup and database file exposure...')
  # Build backup paths from the target hostname
  from urllib.parse import urlparse
  _host = urlparse(BASE).hostname.replace('.', '_')
  _host_short = _host.split('_')[0] if '_' in _host else _host

  BACKUP_PATHS = [
      '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.tar',
      '/db.sql', '/database.sql', '/dump.sql', '/data.sql',
      '/db.sqlite', '/db.sqlite3', '/database.db',
      f'/{_host}.sql', f'/{_host}.zip', f'/{_host_short}.sql',
      '/site.zip', '/site.tar.gz', '/www.zip', '/public.zip',
      '/backup/', '/backups/', '/old/', '/temp/', '/tmp/',
      '/wp-config.php.bak', '/wp-config.php~', '/wp-config.old',
      '/config.php.bak', '/settings.php.bak',
      '/package.json', '/package-lock.json', '/composer.json',
      '/Gemfile', '/requirements.txt', '/Pipfile',
      '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
      '/.dockerenv',
  ]

  for path in BACKUP_PATHS:
      url = BASE + path
      try:
          r = session.get(url, timeout=8, allow_redirects=False)
          if r.status_code == 200 and len(r.content) > 20:
              ct = r.headers.get('Content-Type', '').lower()
              # Skip HTML catch-all pages (SPA)
              if 'text/html' in ct and ('<app-root' in r.text or '<div id="root"' in r.text):
                  continue
              # Real backup/DB files are binary or SQL
              is_interesting = (
                  'sql' in path or 'sqlite' in path or 'zip' in path or
                  'tar' in path or '.db' in path or
                  'application/' in ct or 'octet-stream' in ct or
                  'CREATE TABLE' in r.text[:500] or 'INSERT INTO' in r.text[:500] or
                  'SELECT' in r.text[:200]
              )
              # Package files are JSON
              if path.endswith('.json') and r.text.strip().startswith('{'):
                  is_interesting = True

              if is_interesting:
                  sev = 'CRITICAL' if any(k in path for k in ['.sql', '.sqlite', '.db', '.zip', '.tar']) else 'MEDIUM'
                  print(f'  [{sev}] Backup/data file exposed: {url} ({len(r.content)} bytes)')
                  _sens_findings.append({
                      'severity': sev, 'title': f'Backup/data file exposed: {path}',
                      'url': url, 'evidence': f'{len(r.content)} bytes, Content-Type: {ct}',
                  })
      except Exception:
          pass
      time.sleep(0.15)

  # ── 3. Admin / debug / monitoring panels ──────────────────────────
  print('\n[SENSITIVE] Testing admin and debug panel exposure...')
  ADMIN_PATHS = [
      ('/admin', 'Admin panel'),
      ('/admin/', 'Admin panel'),
      ('/administrator', 'Administrator panel'),
      ('/admin/login', 'Admin login'),
      ('/admin/dashboard', 'Admin dashboard'),
      ('/wp-admin', 'WordPress admin'),
      ('/wp-login.php', 'WordPress login'),
      ('/phpmyadmin', 'phpMyAdmin'),
      ('/phpinfo.php', 'PHP Info page'),
      ('/info.php', 'PHP Info page'),
      ('/server-status', 'Apache server-status'),
      ('/server-info', 'Apache server-info'),
      ('/debug', 'Debug panel'),
      ('/debug/', 'Debug panel'),
      ('/console', 'Debug console'),
      ('/trace', 'Trace endpoint'),
      ('/elmah.axd', 'ELMAH error log'),
      ('/actuator', 'Spring Actuator'),
      ('/actuator/env', 'Spring Actuator env (may contain secrets)'),
      ('/actuator/health', 'Spring Actuator health'),
      ('/actuator/configprops', 'Spring Actuator config'),
      ('/actuator/mappings', 'Spring Actuator route mappings'),
      ('/swagger-ui.html', 'Swagger UI'),
      ('/swagger-ui/', 'Swagger UI'),
      ('/api-docs', 'API documentation'),
      ('/api/swagger.json', 'Swagger JSON spec'),
      ('/openapi.json', 'OpenAPI spec'),
      ('/graphiql', 'GraphiQL IDE'),
      ('/playground', 'GraphQL Playground'),
      ('/__debug__/', 'Django debug toolbar'),
      ('/metrics', 'Prometheus metrics'),
      ('/health', 'Health check'),
      ('/status', 'Status page'),
      ('/stats', 'Statistics page'),
  ]

  for path, desc in ADMIN_PATHS:
      url = BASE + path
      try:
          r = session.get(url, timeout=8, allow_redirects=False)
          # 200 = accessible, 401/403 = exists but protected (still interesting)
          if r.status_code == 200 and len(r.text.strip()) > 50:
              # Skip SPA catch-all
              if '<app-root' in r.text or '<div id="root"' in r.text:
                  continue
              # Check for real admin/debug content
              admin_signs = ['admin', 'dashboard', 'manage', 'phpinfo', 'actuator',
                             'swagger', 'graphi', 'debug', 'panel', 'config', 'env']
              if any(s in r.text.lower()[:2000] for s in admin_signs) or r.status_code == 200:
                  sev = 'CRITICAL' if any(k in path for k in ['phpinfo', 'actuator/env', 'elmah', '__debug__', 'configprops']) else 'HIGH'
                  if any(k in path for k in ['swagger', 'api-docs', 'openapi', 'graphi', 'playground']):
                      sev = 'MEDIUM'  # API docs are informational
                  print(f'  [{sev}] {desc} accessible: {url}')
                  print(f'    Status: {r.status_code}, Size: {len(r.text)} bytes')
                  _sens_findings.append({
                      'severity': sev, 'title': f'{desc} accessible',
                      'url': url, 'evidence': f'HTTP {r.status_code}, {len(r.text)} bytes',
                  })
          elif r.status_code in (401, 403):
              print(f'  [INFO] {desc} exists but protected: {url} ({r.status_code})')
      except Exception:
          pass
      time.sleep(0.15)

  # ── 4. robots.txt & sitemap sensitive paths ───────────────────────
  print('\n[SENSITIVE] Checking robots.txt and sitemap for hidden paths...')
  for path in ['/robots.txt', '/sitemap.xml', '/sitemap_index.xml']:
      url = BASE + path
      try:
          r = session.get(url, timeout=8)
          if r.status_code == 200 and len(r.text.strip()) > 10:
              print(f'  [INFO] {path} found ({len(r.text)} bytes)')
              # Extract disallowed paths from robots.txt
              if 'robots' in path:
                  import re
                  disallowed = re.findall(r'Disallow:\s*(.+)', r.text)
                  if disallowed:
                      print(f'    Disallowed paths: {disallowed[:15]}')
                      # Probe disallowed paths — they're hidden for a reason
                      for dp in disallowed[:10]:
                          dp = dp.strip()
                          if not dp or dp == '/':
                              continue
                          dp_url = BASE + dp
                          try:
                              dr = session.get(dp_url, timeout=6, allow_redirects=False)
                              if dr.status_code == 200:
                                  print(f'    [MEDIUM] Disallowed path accessible: {dp_url}')
                                  _sens_findings.append({
                                      'severity': 'MEDIUM',
                                      'title': f'Robots.txt disallowed path accessible: {dp}',
                                      'url': dp_url,
                                  })
                          except Exception:
                              pass
                          time.sleep(0.1)
              # Extract URLs from sitemap
              if 'sitemap' in path:
                  import re
                  locs = re.findall(r'<loc>([^<]+)</loc>', r.text)
                  if locs:
                      print(f'    Sitemap URLs: {len(locs)} found')
                      # Add to ALL_LINKS for other phases to test
                      _G.setdefault('ALL_LINKS', set()).update(locs[:50])
      except Exception:
          pass

  # ── 5. Directory listing detection ────────────────────────────────
  print('\n[SENSITIVE] Testing for directory listing...')
  LISTING_PATHS = ['/', '/images/', '/img/', '/css/', '/js/', '/static/',
                   '/uploads/', '/files/', '/media/', '/assets/',
                   '/ftp/', '/public/', '/data/', '/docs/']
  for path in LISTING_PATHS:
      url = BASE + path
      try:
          r = session.get(url, timeout=8)
          if r.status_code == 200:
              listing_signs = ['Index of', 'Directory listing', '<pre>', 'Parent Directory',
                               '[DIR]', '[TXT]', 'Last modified']
              if any(s.lower() in r.text.lower() for s in listing_signs):
                  print(f'  [MEDIUM] Directory listing enabled: {url}')
                  _sens_findings.append({
                      'severity': 'MEDIUM',
                      'title': 'Directory listing enabled',
                      'url': url,
                      'evidence': r.text[:300],
                  })
      except Exception:
          pass
      time.sleep(0.1)

  # ── Summary ───────────────────────────────────────────────────────
  print(f'\n=== SENSITIVE FILES SUMMARY: {len(_sens_findings)} issues found ===')
  for f in _sens_findings:
      print(f"  [{f['severity']}] {f['title']}: {f['url']}")
  if _sens_findings:
      # Add screenshot field to each finding
      for f in _sens_findings:
          f['screenshot'] = ''
          f['method'] = 'GET'
          f['impact'] = 'Information disclosure, credential exposure, internal system access'
      _G.setdefault('FINDINGS', []).extend(_sens_findings)

# POST-PHASE SCREENSHOT CHECKPOINT — verify sensitive file findings with screenshots
print("\n[SCREENSHOT CHECKPOINT] Verify all sensitive file findings:")
for finding in _G['FINDINGS']:
    if any(kw in finding.get('title', '').lower() for kw in ['.git', '.env', 'backup', 'exposed', 'admin', 'debug', 'phpinfo', 'actuator']):
        if not finding.get('screenshot'):
            print(f"  [REQUIRED] Take screenshot for: {finding.get('title')}")
            print(f"    Navigate to: {finding.get('url')}")
            print(f"    browser_action(action='navigate', url='{finding.get('url')}')")
            print(f"    browser_action(action='screenshot', filename='phase_23_sens_{finding.get('title').lower()[:40]}.png')")
            print(f"    Update finding['screenshot'] with the filename")
print("\n  After confirming each finding:")
print("    - If screenshot shows catch-all HTML (not real file), it's FALSE POSITIVE — remove it")
print("    - Verify the screenshot shows ACTUAL file content (KEY=VALUE for .env, SQL statements for backup.sql, etc.)")
  ```
