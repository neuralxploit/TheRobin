#!/usr/bin/env python3
"""
VulnCorp Portal — Intentionally Vulnerable Web App
OWASP Top 10 (2021) Training Target

Vulnerabilities included:
  A01 Broken Access Control    — IDOR on /profile/<id>, /profile/<id>/edit, /api/user/<id>, /notes/<id>,
                                 /invoice/<id>, /api/invoice/<id>;
                                 Admin sub-paths /admin/user/<id>, /admin/user/<id>/edit, /admin/reports,
                                 /admin/config have NO role check — any authenticated user can access them.
                                 Privilege escalation: regular user can POST to /admin/user/1/edit to
                                 promote themselves to admin or change admin salary/email.
  A02 Cryptographic Failures   — MD5 passwords, sensitive data in plain cookies, weak session secret
  A03 Injection                — SQLi in /login + /search, reflected XSS in /search, stored XSS in /comments, CMDi in /ping
  A04 Insecure Design          — No account lockout, predictable password reset token
  A05 Security Misconfiguration— No security headers, debug mode on, verbose errors, default admin creds
  A06 Vulnerable Components    — jQuery 1.6.1 (CVE-2011-4969), Bootstrap 3.3.6
  A07 Auth Failures            — Default creds admin/admin123, no rate limiting, session fixation, weak passwords allowed
  A08 Integrity Failures       — No CSRF tokens, pickle deserialization at /deserialize
  A09 Logging Failures         — Failed logins not logged, no audit trail
  A10 SSRF                     — /fetch endpoint fetches arbitrary internal/external URLs

  JavaScript Vulnerabilities (static/js/app.js):
    - DOM-based XSS via location.hash, URL params (msg, page), document.referrer
    - Hardcoded API keys, AWS credentials, admin password, debug tokens in JS
    - Sensitive data (JWT, PII, API keys) stored in localStorage
    - postMessage handler with NO origin validation (accepts any origin)
    - eval() injection in calculator feature
    - Client-side access control bypass (admin panel hidden by JS, not server)
    - Open redirect via URL parameter (/redirect?url=https://evil.com)
    - Prototype pollution via jQuery $.extend with user-controlled JSON
    - JSONP callback injection (/api/data/export?callback=alert(1))
    - Source map exposure (/static/js/app.js.map reveals source + secrets)
    - Insecure WebSocket (ws:// not wss://, no auth, innerHTML from messages)
    - API config endpoint leaks secrets (/api/config)
    - Webhook registration SSRF (/api/webhooks)
    - JWT "none" algorithm bypass in client-side token verification
    - Debug/backdoor functions exposed globally (debugDump, enableDevMode)

Default credentials:
  admin   / admin123   (role: admin)
  alice   / password1  (role: user)
  bob     / 123456     (role: user)
  charlie / letmein    (role: user)

Run:  python3 app.py
"""

from flask import (Flask, request, render_template_string, redirect,
                   url_for, session, make_response, jsonify, g)
import sqlite3, hashlib, os, subprocess, urllib.request, urllib.error
import pickle, base64, time, re, json

# ── App config ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'weakkey123'          # A07: trivially guessable secret
app.config['DEBUG'] = True             # A05: debug mode exposes stack traces

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'corp.db')

# ── Database helpers ──────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'user',
            email      TEXT,
            department TEXT,
            salary     INTEGER,
            ssn        TEXT,
            notes      TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            author     TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS private_notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT,
            content    TEXT
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            username   TEXT,
            token      TEXT,
            created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            amount      REAL NOT NULL,
            description TEXT,
            status      TEXT DEFAULT 'pending',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    users = [
        ('admin',   hashlib.md5(b'admin123').hexdigest(),  'admin',
         'admin@corp.local',   'IT',      150000, '000-00-0001', 'Has full DB access'),
        ('alice',   hashlib.md5(b'password1').hexdigest(), 'user',
         'alice@corp.local',   'Finance',  85000, '000-00-0002', 'Salary review pending'),
        ('bob',     hashlib.md5(b'123456').hexdigest(),    'user',
         'bob@corp.local',     'HR',       72000, '000-00-0003', 'Performance: needs improvement'),
        ('charlie', hashlib.md5(b'letmein').hexdigest(),   'user',
         'charlie@corp.local', 'Sales',    68000, '000-00-0004', 'On probation'),
    ]
    for u in users:
        try:
            db.execute(
                "INSERT INTO users (username,password,role,email,department,salary,ssn,notes) VALUES (?,?,?,?,?,?,?,?)", u)
        except sqlite3.IntegrityError:
            pass

    seed_comments = [
        ('admin', 'Welcome to CorpPortal! Update your profile.'),
        ('alice', 'Team lunch Friday at noon!'),
        ('bob',   'Q3 reports due end of month.'),
    ]
    for c in seed_comments:
        if not db.execute("SELECT 1 FROM comments WHERE author=? AND content=?", c).fetchone():
            db.execute("INSERT INTO comments (author,content) VALUES (?,?)", c)

    notes = [
        (1, 'Credentials', 'DB root password: S3cr3tDB!2024\nAWS key: AKIA...EXAMPLE'),
        (2, 'Private',     'Salary negotiation target: $95k'),
        (3, 'Private',     'Performance review notes for team'),
        (4, 'Deal notes',  'Client: Acme Corp. Budget: $500k'),
    ]
    for n in notes:
        if not db.execute("SELECT 1 FROM private_notes WHERE user_id=? AND title=?", (n[0],n[1])).fetchone():
            db.execute("INSERT INTO private_notes (user_id,title,content) VALUES (?,?,?)", n)

    # A01: Invoice data — no ownership enforced on /invoice/<id>
    invoices = [
        (1, 9800.00, 'Annual Bonus Payment',        'paid'),
        (2, 1200.00, 'Training Budget Reimbursement','pending'),
        (3,  850.00, 'Equipment Allowance Q4',       'approved'),
        (4, 2300.00, 'Travel Reimbursement — NYC',   'pending'),
        (1, 4500.00, 'Q4 Executive Consulting Fee',  'paid'),
        (2, 3100.00, 'Software License Renewal',     'pending'),
        (3, 6750.00, 'Recruitment Agency Fee',       'approved'),
        (4,  400.00, 'Conference Registration',      'pending'),
    ]
    for inv in invoices:
        if not db.execute(
            "SELECT 1 FROM invoices WHERE user_id=? AND description=?", (inv[0], inv[2])
        ).fetchone():
            db.execute(
                "INSERT INTO invoices (user_id,amount,description,status) VALUES (?,?,?,?)", inv
            )

    db.commit()
    db.close()

# ── Base template ─────────────────────────────────────────────────────────────
BASE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CorpPortal — {% block title %}Home{% endblock %}</title>
  <!-- A06: jQuery 1.6.1 (CVE-2011-4969 XSS), Bootstrap 3.3.6 -->
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">
  <script src="https://code.jquery.com/jquery-1.6.1.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
  <!-- A05: No CSP, HSTS, X-Frame-Options, etc. -->
  <style>
    body { padding-top: 60px; background: #f5f5f5; }
    .vuln-badge { font-size:10px; color:#999; margin-left:6px; }
    .severity-critical { color:#d9534f; font-weight:bold; }
    .sidebar { background:#fff; border:1px solid #ddd; border-radius:4px; padding:15px; }
    .admin-only { display:none; }
    .ws-msg { padding:4px 8px; border-bottom:1px solid #eee; }
    .highlight { background:#ff0; padding:1px 2px; }
  </style>
  <!-- JS vulnerabilities: hardcoded secrets, DOM XSS, postMessage, eval, prototype pollution -->
  <script src="/static/js/app.js"></script>
</head>
<body>
<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <a class="navbar-brand" href="/">&#127970; CorpPortal</a>
    </div>
    <div class="collapse navbar-collapse">
      <ul class="nav navbar-nav">
        <li><a href="/search">Directory</a></li>
        <li><a href="/comments">Announcements</a></li>
        <li><a href="/admin">Admin</a></li>
        <li><a href="/admin/reports">Reports</a></li>
        <li><a href="/tools">Tools</a></li>
        <li><a href="/fetch">URL Fetch</a></li>
        <li><a href="/calculator">Calculator</a></li>
        <li><a href="/settings">Settings</a></li>
        <li><a href="/messages">Messages</a></li>
      </ul>
      <ul class="nav navbar-nav navbar-right">
        {% if session.username %}
        <li><a href="/profile/{{ session.user_id }}"
               data-user-id="{{ session.user_id }}"
               data-username="{{ session.username }}"
               data-email="{{ session.get('email','') }}"
               data-role="{{ session.get('role','user') }}">{{ session.username }}</a></li>
        <li><a href="/logout">Logout</a></li>
        {% else %}
        <li><a href="/login">Login</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  <div id="notification-area"></div>
  <div id="hash-content"></div>
  <div id="referrer-banner" class="text-muted small"></div>
  <div id="dynamic-content"></div>
  <div id="spa-content"></div>
  {% if flash %}<div class="alert alert-{{ flash.type }}">{{ flash.msg }}</div>{% endif %}
  {% block content %}{% endblock %}
</div>
</body></html>"""

def render(template, **kwargs):
    flash = session.pop('_flash', None)
    return render_template_string(BASE.replace("{% block content %}{% endblock %}", template),
                                  flash=flash, **kwargs)

def flash(msg, t='info'):
    session['_flash'] = {'msg': msg, 'type': t}

# ── Auth helpers ──────────────────────────────────────────────────────────────
def logged_in():
    return 'username' in session

def require_login():
    if not logged_in():
        flash('Please log in first.', 'warning')
        return redirect('/login')

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if logged_in():
        return redirect('/dashboard')
    return redirect('/login')


# ── A07 + A03: Login — SQLi, no rate limiting, session fixation, default creds ──
@app.route('/login', methods=['GET','POST'])
def login():
    error = ''
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        p_hash = hashlib.md5(p.encode()).hexdigest()

        db = get_db()
        # A03: Raw string concatenation — SQLi vulnerability
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p_hash}'"
        try:
            row = db.execute(query).fetchone()
        except Exception as e:
            # A05: Verbose error exposes SQL query
            error = f"Database error: {e} | Query: {query}"
            row = None

        if row:
            # A07: Session fixation — session ID not regenerated
            session['username']  = row['username']
            session['user_id']   = row['id']
            session['role']      = row['role']
            # A02: Sensitive data stored in session cookie (plaintext)
            session['salary']    = row['salary']
            session['email']     = row['email']
            return redirect('/dashboard')
        else:
            # A09: Failed login NOT logged
            error = 'Invalid username or password.'

    return render("""
    <div class="row"><div class="col-md-4 col-md-offset-4">
      <div class="panel panel-default">
        <div class="panel-heading"><h3 class="panel-title">Employee Login</h3></div>
        <div class="panel-body">
          {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
          <form method="POST">
            <div class="form-group">
              <label>Username</label>
              <input class="form-control" name="username" placeholder="username">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input class="form-control" type="password" name="password" placeholder="password">
            </div>
            <button class="btn btn-primary btn-block" type="submit">Sign In</button>
          </form>
          <hr><small><a href="/register">Register</a> &nbsp;|&nbsp; <a href="/reset">Forgot password?</a></small>
        </div>
      </div>
    </div></div>
    """, error=error)


@app.route('/logout')
def logout():
    # A07: session.clear() but session ID reused on next login (fixation)
    session.clear()
    return redirect('/login')


# ── A07: Register — no password complexity, no validation ────────────────────
@app.route('/register', methods=['GET','POST'])
def register():
    error = ''
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        e = request.form.get('email','')
        if not u or not p:
            error = 'Username and password required.'
        else:
            try:
                get_db().execute(
                    "INSERT INTO users (username,password,email) VALUES (?,?,?)",
                    (u, hashlib.md5(p.encode()).hexdigest(), e)
                )
                get_db().connection if hasattr(get_db(),'connection') else None
                get_db().commit() if hasattr(get_db(),'commit') else None
                db = get_db(); db.commit()
                flash('Account created. Please log in.', 'success')
                return redirect('/login')
            except sqlite3.IntegrityError:
                error = 'Username already taken.'

    return render("""
    <div class="row"><div class="col-md-4 col-md-offset-4">
      <div class="panel panel-default">
        <div class="panel-heading"><h3 class="panel-title">Register</h3></div>
        <div class="panel-body">
          {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
          <form method="POST">
            <div class="form-group"><label>Username</label>
              <input class="form-control" name="username"></div>
            <div class="form-group"><label>Password</label>
              <input class="form-control" type="password" name="password">
              <small class="text-muted">Any password accepted.</small></div>
            <div class="form-group"><label>Email</label>
              <input class="form-control" name="email"></div>
            <button class="btn btn-success btn-block">Create Account</button>
          </form>
        </div>
      </div>
    </div></div>
    """, error=error)


@app.route('/dashboard')
def dashboard():
    redir = require_login()
    if redir: return redir
    db = get_db()
    users = db.execute("SELECT id,username,department FROM users").fetchall()
    return render("""
    <h2>Welcome, {{ session.username }}
      {% if session.role == 'admin' %}<span class="label label-danger">ADMIN</span>{% endif %}
    </h2>
    <div class="row">
      <div class="col-md-8">
        <div class="panel panel-default">
          <div class="panel-heading">Employee Directory</div>
          <div class="panel-body">
            <table class="table table-hover">
              <tr><th>ID</th><th>Name</th><th>Department</th><th></th></tr>
              {% for u in users %}
              <tr>
                <td>{{ u['id'] }}</td>
                <td>{{ u['username'] }}</td>
                <td>{{ u['department'] or '—' }}</td>
                <td><a href="/profile/{{ u['id'] }}" class="btn btn-xs btn-default">View</a></td>
              </tr>
              {% endfor %}
            </table>
          </div>
        </div>
      </div>
      <div class="col-md-4 sidebar">
        <h4>Your Session</h4>
        <p><b>Role:</b> {{ session.role }}</p>
        <p><b>Email:</b> {{ session.email }}</p>
        <p><b>Salary:</b> ${{ session.salary }}</p>
        <hr>
        <a href="/notes" class="btn btn-default btn-block">My Private Notes</a>
        <a href="/invoices" class="btn btn-default btn-block">My Invoices</a>
        <a href="/search" class="btn btn-default btn-block">Search Directory</a>
        <hr>
        <!-- A01: link exposes /admin/user/<id> path — spider will find it and enumerate other IDs -->
        <a href="/admin/user/{{ session.user_id }}" class="btn btn-info btn-block">Account Settings</a>
      </div>
    </div>
    """, users=users)


# ── A01: IDOR — any user can view any profile including salary + SSN ──────────
@app.route('/profile/<int:user_id>')
def profile(user_id):
    redir = require_login()
    if redir: return redir
    # A01: No check that user_id == session['user_id']
    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return render("<div class='alert alert-danger'>User not found.</div>")
    notes = get_db().execute("SELECT * FROM private_notes WHERE user_id=?", (user_id,)).fetchall()
    return render("""
    <h2>{{ row['username'] }}'s Profile
      <span class="vuln-badge">[A01: IDOR — you can view any user's profile]</span>
    </h2>
    <div class="row">
      <div class="col-md-6">
        <table class="table table-bordered">
          <tr><th>Username</th><td>{{ row['username'] }}</td></tr>
          <tr><th>Email</th><td>{{ row['email'] }}</td></tr>
          <tr><th>Department</th><td>{{ row['department'] }}</td></tr>
          <tr class="danger"><th>Salary</th><td><b>${{ row['salary'] }}</b></td></tr>
          <tr class="danger"><th>SSN</th><td><b>{{ row['ssn'] }}</b></td></tr>
          <tr><th>Role</th><td>{{ row['role'] }}</td></tr>
          <tr><th>Internal Notes</th><td>{{ row['notes'] }}</td></tr>
        </table>
      </div>
      <div class="col-md-6">
        <h4>Private Notes</h4>
        {% for n in notes %}
        <div class="panel panel-warning">
          <div class="panel-heading">{{ n['title'] }}</div>
          <div class="panel-body">{{ n['content'] }}</div>
        </div>
        {% endfor %}
      </div>
    </div>
    <a href="/profile/{{ user_id - 1 }}" class="btn btn-default">← Prev User</a>
    <a href="/profile/{{ user_id + 1 }}" class="btn btn-default">Next User →</a>
    <a href="/profile/{{ user_id }}/edit" class="btn btn-warning">Edit Profile</a>
    """, row=row, notes=notes, user_id=user_id)


# ── A01: IDOR — profile edit, no ownership check ──────────────────────────────
@app.route('/profile/<int:user_id>/edit', methods=['GET','POST'])
def profile_edit(user_id):
    # A01: Any logged-in user can edit any other user's profile
    redir = require_login()
    if redir: return redir
    db  = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return render("<div class='alert alert-danger'>User not found.</div>")
    saved = ''
    if request.method == 'POST':
        email  = request.form.get('email', '')
        dept   = request.form.get('department', '')
        notes  = request.form.get('notes', '')
        # A08: No CSRF token  |  A01: No ownership check
        db.execute(
            "UPDATE users SET email=?,department=?,notes=? WHERE id=?",
            (email, dept, notes, user_id)
        )
        db.commit()
        saved = f"Profile updated by {session.get('username')} (UID={session.get('user_id')}) — IDOR!"
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    return render("""
    <h2>Edit Profile — {{ row['username'] }}
      <span class="vuln-badge">[A01: IDOR — any user can edit any profile]</span>
    </h2>
    {% if row['id'] != session.user_id %}
    <div class="alert alert-danger">
      <b>IDOR:</b> You ({{ session.username }}) are editing
      <b>{{ row['username'] }}</b>'s profile!
    </div>
    {% endif %}
    {% if saved %}<div class="alert alert-warning">{{ saved }}</div>{% endif %}
    <!-- A08: No CSRF token on this state-changing form -->
    <form method="POST">
      <div class="form-group">
        <label>Email</label>
        <input class="form-control" name="email" value="{{ row['email'] or '' }}">
      </div>
      <div class="form-group">
        <label>Department</label>
        <input class="form-control" name="department" value="{{ row['department'] or '' }}">
      </div>
      <div class="form-group">
        <label>Internal Notes</label>
        <textarea class="form-control" name="notes" rows="3">{{ row['notes'] or '' }}</textarea>
      </div>
      <button class="btn btn-warning">Save Changes</button>
      <a href="/profile/{{ row['id'] }}" class="btn btn-default">Cancel</a>
    </form>
    """, row=row, saved=saved)


# ── A03: SQLi + reflected XSS in search ───────────────────────────────────────
@app.route('/search')
def search():
    redir = require_login()
    if redir: return redir
    q = request.args.get('q', '')
    results = []
    error = ''
    if q:
        db = get_db()
        # A03: Raw string concat — SQLi
        sql = f"SELECT id,username,email,department,salary FROM users WHERE username LIKE '%{q}%' OR department LIKE '%{q}%'"
        try:
            results = db.execute(sql).fetchall()
        except Exception as e:
            error = f"Query error: {e}"  # A05: verbose SQL error

    return render("""
    <h2>Employee Search <span class="vuln-badge">[A03: SQLi + XSS]</span></h2>
    <form class="form-inline" method="GET">
      <div class="input-group" style="width:400px">
        <input class="form-control" name="q" value="{{ q }}" placeholder="Search name or department...">
        <span class="input-group-btn">
          <button class="btn btn-primary">Search</button>
        </span>
      </div>
    </form>
    <br>
    {% if q %}
      <!-- A03: XSS — q is rendered unescaped with |safe -->
      <p>Results for: <b>{{ q|safe }}</b></p>
      {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
      {% if results %}
      <table class="table table-hover">
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Dept</th><th>Salary</th></tr>
        {% for r in results %}
        <tr>
          <td>{{ r['id'] }}</td>
          <td><a href="/profile/{{ r['id'] }}">{{ r['username'] }}</a></td>
          <td>{{ r['email'] }}</td>
          <td>{{ r['department'] }}</td>
          <td>${{ r['salary'] }}</td>
        </tr>
        {% endfor %}
      </table>
      {% else %}
      <p class="text-muted">No results found.</p>
      {% endif %}
    {% endif %}
    """, q=q, results=results, error=error)


# ── A03: Stored XSS in comments ───────────────────────────────────────────────
@app.route('/comments', methods=['GET','POST'])
def comments():
    redir = require_login()
    if redir: return redir
    if request.method == 'POST':
        content = request.form.get('content','').strip()
        if content:
            # A08: No CSRF token check
            get_db().execute(
                "INSERT INTO comments (author,content) VALUES (?,?)",
                (session['username'], content)
            )
            get_db().commit()
    rows = get_db().execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()
    return render("""
    <h2>Announcements <span class="vuln-badge">[A03: Stored XSS — A08: No CSRF]</span></h2>
    <div class="row">
      <div class="col-md-8">
        {% for c in rows %}
        <div class="panel panel-default">
          <div class="panel-heading"><b>{{ c['author'] }}</b>
            <small class="text-muted pull-right">{{ c['created_at'] }}</small>
          </div>
          <!-- A03: Stored XSS — content rendered unescaped -->
          <div class="panel-body">{{ c['content']|safe }}</div>
        </div>
        {% endfor %}
      </div>
      <div class="col-md-4">
        <div class="panel panel-primary">
          <div class="panel-heading">Post Announcement</div>
          <div class="panel-body">
            <form method="POST">
              <!-- A08: No CSRF token -->
              <div class="form-group">
                <textarea class="form-control" name="content" rows="4"
                  placeholder="HTML allowed..."></textarea>
              </div>
              <button class="btn btn-primary btn-block">Post</button>
            </form>
          </div>
        </div>
      </div>
    </div>
    """, rows=rows)


# ── A01: Broken Access Control — /admin checks cookie only, not DB role ───────
@app.route('/admin')
def admin():
    # A01: Only checks session cookie — never validates against DB
    if session.get('role') != 'admin':
        # But session cookie is not HttpOnly or signed properly — can be forged
        return render("""
        <div class="alert alert-danger">
          <h4>Access Denied</h4>
          <p>Admin role required. <span class="vuln-badge">[A01: Try forging the session cookie]</span></p>
          <p><small>Hint: app.secret_key = 'weakkey123' — use flask-unsign to forge admin session</small></p>
        </div>
        """)
    users = get_db().execute("SELECT * FROM users").fetchall()
    return render("""
    <h2>Admin Panel <span class="vuln-badge">[A01: Broken Access Control]</span></h2>
    <div class="panel panel-danger">
      <div class="panel-heading">All Users (including passwords)</div>
      <div class="panel-body">
        <table class="table">
          <tr><th>ID</th><th>Username</th><th>Password (MD5)</th><th>Role</th><th>Email</th><th>Salary</th><th>SSN</th></tr>
          {% for u in users %}
          <tr>
            <td>{{ u['id'] }}</td>
            <td>{{ u['username'] }}</td>
            <td><code>{{ u['password'] }}</code></td>
            <td>{{ u['role'] }}</td>
            <td>{{ u['email'] }}</td>
            <td>${{ u['salary'] }}</td>
            <td>{{ u['ssn'] }}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
    """, users=users)


# ── A01: Admin sub-paths — NO role check (IDOR / Broken Object Level Auth) ────
#
#  Real-world scenario:
#    alice logs in (user_id=2) → sees "Account Settings" button → /admin/user/2
#    alice changes URL to /admin/user/1  → views/edits admin account
#    alice POSTs to /admin/user/1/edit  → sets role='admin', salary=999999
#    All admin sub-paths (/admin/reports, /admin/config) also have no role check.
#
@app.route('/admin/user/<int:uid>')
def admin_user_view(uid):
    # A01: Only login required — role NEVER checked
    redir = require_login()
    if redir: return redir
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return render("<div class='alert alert-danger'>User not found.</div>")
    invoices = get_db().execute(
        "SELECT * FROM invoices WHERE user_id=? ORDER BY created_at DESC", (uid,)
    ).fetchall()
    notes = get_db().execute(
        "SELECT * FROM private_notes WHERE user_id=?", (uid,)
    ).fetchall()
    return render("""
    <h2>Account Settings — {{ row['username'] }}
      <span class="vuln-badge">[A01: IDOR — no role check. You accessed UID={{ uid }}]</span>
    </h2>
    {% if uid != session.user_id %}
    <div class="alert alert-danger">
      <b>IDOR Confirmed:</b> You are viewing/editing another user's account settings!
      Logged in as: <b>{{ session.username }}</b> (UID={{ session.user_id }})
      but viewing: <b>{{ row['username'] }}</b> (UID={{ uid }})
    </div>
    {% endif %}
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Account Details</div>
          <div class="panel-body">
            <table class="table table-bordered">
              <tr><th>ID</th><td>{{ row['id'] }}</td></tr>
              <tr><th>Username</th><td>{{ row['username'] }}</td></tr>
              <tr><th>Email</th><td>{{ row['email'] }}</td></tr>
              <tr><th>Department</th><td>{{ row['department'] }}</td></tr>
              <tr class="danger"><th>Role</th><td><b>{{ row['role'] }}</b></td></tr>
              <tr class="danger"><th>Salary</th><td><b>${{ row['salary'] }}</b></td></tr>
              <tr class="danger"><th>SSN</th><td><b>{{ row['ssn'] }}</b></td></tr>
              <tr class="danger"><th>Password (MD5)</th><td><code>{{ row['password'] }}</code></td></tr>
            </table>
          </div>
        </div>
        <div class="panel panel-warning">
          <div class="panel-heading">Private Notes ({{ notes|length }})</div>
          <div class="panel-body">
            {% for n in notes %}
            <p><b>{{ n['title'] }}</b>: {{ n['content'] }}</p>
            {% else %}<p class="text-muted">None.</p>{% endfor %}
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="panel panel-danger">
          <div class="panel-heading">
            Edit Account
            <span class="vuln-badge">[A01: IDOR — you can edit ANY user's role/salary]</span>
          </div>
          <div class="panel-body">
            <!-- A08: No CSRF token, A01: No ownership check -->
            <form method="POST" action="/admin/user/{{ uid }}/edit">
              <div class="form-group">
                <label>Email</label>
                <input class="form-control" name="email" value="{{ row['email'] }}">
              </div>
              <div class="form-group">
                <label>Department</label>
                <input class="form-control" name="department" value="{{ row['department'] or '' }}">
              </div>
              <div class="form-group">
                <label>Salary</label>
                <input class="form-control" name="salary" type="number" value="{{ row['salary'] }}">
              </div>
              <div class="form-group">
                <label>Role <span class="text-danger">(admin/user)</span></label>
                <select class="form-control" name="role">
                  <option {% if row['role']=='user' %}selected{% endif %}>user</option>
                  <option {% if row['role']=='admin' %}selected{% endif %}>admin</option>
                </select>
              </div>
              <div class="form-group">
                <label>New Password (leave blank to keep)</label>
                <input class="form-control" name="password" placeholder="new password">
              </div>
              <button class="btn btn-danger btn-block">
                Save Changes for {{ row['username'] }}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
    <div class="panel panel-info">
      <div class="panel-heading">Invoices ({{ invoices|length }})</div>
      <div class="panel-body">
        <table class="table table-sm">
          <tr><th>ID</th><th>Amount</th><th>Description</th><th>Status</th></tr>
          {% for inv in invoices %}
          <tr>
            <td><a href="/invoice/{{ inv['id'] }}">#{{ inv['id'] }}</a></td>
            <td>${{ inv['amount'] }}</td>
            <td>{{ inv['description'] }}</td>
            <td><span class="label label-default">{{ inv['status'] }}</span></td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
    <!-- Navigation to enumerate other users — hints at IDOR -->
    <a href="/admin/user/{{ uid - 1 }}" class="btn btn-default">← User {{ uid - 1 }}</a>
    <a href="/admin/user/{{ uid + 1 }}" class="btn btn-default">User {{ uid + 1 }} →</a>
    """, row=row, uid=uid, invoices=invoices, notes=notes)


@app.route('/admin/user/<int:uid>/edit', methods=['POST'])
def admin_user_edit(uid):
    # A01: No role check — any logged-in user can change ANY user's role/salary/password
    redir = require_login()
    if redir: return redir
    email      = request.form.get('email', '')
    department = request.form.get('department', '')
    salary     = request.form.get('salary', 0)
    role       = request.form.get('role', 'user')
    new_pass   = request.form.get('password', '').strip()

    db = get_db()
    if new_pass:
        p_hash = hashlib.md5(new_pass.encode()).hexdigest()
        db.execute(
            "UPDATE users SET email=?,department=?,salary=?,role=?,password=? WHERE id=?",
            (email, department, salary, role, p_hash, uid)
        )
    else:
        db.execute(
            "UPDATE users SET email=?,department=?,salary=?,role=? WHERE id=?",
            (email, department, salary, role, uid)
        )
    db.commit()

    # If attacker just promoted themselves to admin, update their session too
    if uid == session.get('user_id'):
        session['role'] = role
        session['email'] = email
        session['salary'] = salary

    flash(
        f"A01 IDOR — User #{uid} ({role}) updated by "
        f"{session.get('username')} (UID={session.get('user_id')}, role={session.get('role')}). "
        f"No ownership or role check performed!",
        'danger'
    )
    return redirect(f'/admin/user/{uid}')


@app.route('/admin/reports')
def admin_reports():
    # A01: No role check — any authenticated user can view financial report
    redir = require_login()
    if redir: return redir
    users    = get_db().execute("SELECT id,username,department,salary,role FROM users ORDER BY salary DESC").fetchall()
    invoices = get_db().execute(
        "SELECT i.id, u.username, i.amount, i.description, i.status, i.created_at "
        "FROM invoices i JOIN users u ON i.user_id=u.id ORDER BY i.amount DESC"
    ).fetchall()
    total_payroll = sum(u['salary'] or 0 for u in users)
    return render("""
    <h2>Financial Reports
      <span class="vuln-badge">[A01: No role check — any logged-in user can view this]</span>
    </h2>
    <div class="alert alert-danger">
      <b>IDOR/Broken Access Control:</b> This page has no admin role verification.
      You are logged in as <b>{{ session.username }}</b> (role: {{ session.role }}).
    </div>
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-danger">
          <div class="panel-heading">Payroll — All Employees</div>
          <div class="panel-body">
            <table class="table">
              <tr><th>ID</th><th>Username</th><th>Department</th><th>Role</th><th>Salary</th></tr>
              {% for u in users %}
              <tr>
                <td><a href="/admin/user/{{ u['id'] }}">{{ u['id'] }}</a></td>
                <td>{{ u['username'] }}</td>
                <td>{{ u['department'] }}</td>
                <td><span class="label {% if u['role']=='admin' %}label-danger{% else %}label-default{% endif %}">
                  {{ u['role'] }}</span></td>
                <td><b>${{ u['salary'] }}</b></td>
              </tr>
              {% endfor %}
              <tr class="active"><td colspan="4"><b>Total Payroll</b></td><td><b>${{ total_payroll }}</b></td></tr>
            </table>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="panel panel-warning">
          <div class="panel-heading">All Invoices</div>
          <div class="panel-body">
            <table class="table">
              <tr><th>ID</th><th>User</th><th>Amount</th><th>Description</th><th>Status</th></tr>
              {% for inv in invoices %}
              <tr>
                <td><a href="/invoice/{{ inv['id'] }}">#{{ inv['id'] }}</a></td>
                <td>{{ inv['username'] }}</td>
                <td>${{ inv['amount'] }}</td>
                <td>{{ inv['description'] }}</td>
                <td>{{ inv['status'] }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>
        </div>
      </div>
    </div>
    """, users=users, invoices=invoices, total_payroll=total_payroll)


@app.route('/admin/config')
def admin_config():
    # A01 + A05: No auth at all — exposes full system config
    import platform
    return render("""
    <h2>System Configuration
      <span class="vuln-badge">[A01+A05: No auth — exposes SECRET_KEY, DB path, config]</span>
    </h2>
    <div class="alert alert-danger">
      <b>Critical:</b> This endpoint requires NO authentication.
      Anyone who guesses /admin/config can read the Flask secret key and forge session cookies.
    </div>
    <div class="panel panel-danger">
      <div class="panel-heading">Application Secrets</div>
      <div class="panel-body">
        <table class="table table-bordered">
          <tr><th>Flask SECRET_KEY</th><td><code class="severity-critical">{{ secret }}</code></td></tr>
          <tr><th>Database Path</th><td><code>{{ db_path }}</code></td></tr>
          <tr><th>Debug Mode</th><td><span class="text-danger">{{ debug }}</span></td></tr>
          <tr><th>Python Version</th><td>{{ pyver }}</td></tr>
          <tr><th>OS</th><td>{{ osname }}</td></tr>
          <tr><th>Working Dir</th><td>{{ cwd }}</td></tr>
        </table>
      </div>
    </div>
    <div class="panel panel-warning">
      <div class="panel-heading">Session Cookie Forge (A07)</div>
      <div class="panel-body">
        <p>With the secret key above, use <code>flask-unsign</code> to forge an admin session:</p>
        <pre>flask-unsign --sign --cookie "{'username':'alice','role':'admin','user_id':2}" --secret '{{ secret }}'</pre>
      </div>
    </div>
    """,
    secret=app.secret_key,
    db_path=DB,
    debug=app.config.get('DEBUG'),
    pyver=platform.python_version(),
    osname=platform.system(),
    cwd=os.getcwd())


# ── A01: Invoice IDOR — no ownership check ────────────────────────────────────
@app.route('/invoice/<int:invoice_id>')
def invoice(invoice_id):
    redir = require_login()
    if redir: return redir
    # A01: No check that invoice belongs to current user
    db  = get_db()
    inv = db.execute(
        "SELECT i.*, u.username, u.email, u.department FROM invoices i "
        "JOIN users u ON i.user_id=u.id WHERE i.id=?", (invoice_id,)
    ).fetchone()
    if not inv:
        return render("<div class='alert alert-danger'>Invoice not found.</div>")
    owns = (inv['user_id'] == session.get('user_id'))
    return render("""
    <h2>Invoice #{{ inv['id'] }}
      <span class="vuln-badge">[A01: IDOR — you can view any invoice by changing the ID]</span>
    </h2>
    {% if not owns %}
    <div class="alert alert-danger">
      <b>IDOR Confirmed:</b> You ({{ session.username }}, UID={{ session.user_id }})
      are viewing an invoice belonging to <b>{{ inv['username'] }}</b> (UID={{ inv['user_id'] }})
    </div>
    {% endif %}
    <div class="panel panel-{{ 'success' if inv['status'] == 'paid' else 'warning' }}">
      <div class="panel-heading">
        Invoice #{{ inv['id'] }} — {{ inv['status']|upper }}
      </div>
      <div class="panel-body">
        <table class="table table-bordered">
          <tr><th>Invoice ID</th><td>#{{ inv['id'] }}</td></tr>
          <tr><th>Employee</th><td>{{ inv['username'] }}</td></tr>
          <tr><th>Email</th><td>{{ inv['email'] }}</td></tr>
          <tr><th>Department</th><td>{{ inv['department'] }}</td></tr>
          <tr class="danger"><th>Amount</th><td><b>${{ inv['amount'] }}</b></td></tr>
          <tr><th>Description</th><td>{{ inv['description'] }}</td></tr>
          <tr><th>Status</th><td>{{ inv['status'] }}</td></tr>
          <tr><th>Created</th><td>{{ inv['created_at'] }}</td></tr>
        </table>
      </div>
    </div>
    <a href="/invoice/{{ inv['id'] - 1 }}" class="btn btn-default">← Invoice {{ inv['id'] - 1 }}</a>
    <a href="/invoice/{{ inv['id'] + 1 }}" class="btn btn-default">Invoice {{ inv['id'] + 1 }} →</a>
    <a href="/invoices" class="btn btn-default">All My Invoices</a>
    """, inv=inv, owns=owns)


@app.route('/invoices')
def invoices():
    redir = require_login()
    if redir: return redir
    # Shows only YOUR invoices — but /invoice/<id> has no ownership check (IDOR)
    my_invoices = get_db().execute(
        "SELECT * FROM invoices WHERE user_id=? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    return render("""
    <h2>My Invoices <span class="vuln-badge">[try /invoice/1 /invoice/2 ... to see others]</span></h2>
    {% if my_invoices %}
    <table class="table table-hover">
      <tr><th>ID</th><th>Amount</th><th>Description</th><th>Status</th><th></th></tr>
      {% for inv in my_invoices %}
      <tr>
        <td>#{{ inv['id'] }}</td>
        <td>${{ inv['amount'] }}</td>
        <td>{{ inv['description'] }}</td>
        <td>{{ inv['status'] }}</td>
        <td><a href="/invoice/{{ inv['id'] }}" class="btn btn-xs btn-default">View</a></td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p class="text-muted">No invoices found.</p>
    {% endif %}
    """, my_invoices=my_invoices)


@app.route('/api/invoice/<int:invoice_id>')
def api_invoice(invoice_id):
    # A01: No auth required — unauthenticated IDOR on API endpoint
    inv = get_db().execute(
        "SELECT i.*, u.username, u.email, u.ssn FROM invoices i "
        "JOIN users u ON i.user_id=u.id WHERE i.id=?", (invoice_id,)
    ).fetchone()
    if not inv:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "warning":     "A01: IDOR — no auth required on this invoice API endpoint",
        "invoice_id":  inv['id'],
        "user_id":     inv['user_id'],
        "username":    inv['username'],
        "employee_email": inv['email'],
        "employee_ssn":   inv['ssn'],   # A02: SSN exposed in API
        "amount":      inv['amount'],
        "description": inv['description'],
        "status":      inv['status'],
    })


# ── A01: IDOR on private notes ────────────────────────────────────────────────
@app.route('/notes')
@app.route('/notes/<int:note_id>')
def notes(note_id=None):
    redir = require_login()
    if redir: return redir
    db = get_db()
    if note_id:
        # A01: No check that note belongs to current user
        note = db.execute("SELECT * FROM private_notes WHERE id=?", (note_id,)).fetchone()
        if not note:
            return render("<div class='alert alert-danger'>Note not found.</div>")
        return render("""
        <h2>Note #{{ note_id }} <span class="vuln-badge">[A01: IDOR — any note ID works]</span></h2>
        <div class="panel panel-warning">
          <div class="panel-heading">{{ note['title'] }}</div>
          <div class="panel-body">{{ note['content'] }}</div>
        </div>
        <a href="/notes" class="btn btn-default">← All Notes</a>
        <a href="/notes/{{ note_id - 1 }}" class="btn btn-default">← Prev</a>
        <a href="/notes/{{ note_id + 1 }}" class="btn btn-default">Next →</a>
        """, note=note, note_id=note_id)

    my_notes = db.execute(
        "SELECT * FROM private_notes WHERE user_id=?", (session['user_id'],)
    ).fetchall()
    return render("""
    <h2>Private Notes <span class="vuln-badge">[A01: Try /notes/1 /notes/2 /notes/3]</span></h2>
    {% for n in my_notes %}
    <div class="panel panel-default">
      <div class="panel-heading">
        <b>{{ n['title'] }}</b>
        <a href="/notes/{{ n['id'] }}" class="btn btn-xs btn-default pull-right">View</a>
      </div>
    </div>
    {% else %}
    <p class="text-muted">No notes yet.</p>
    {% endfor %}
    """, my_notes=my_notes)


# ── A03: OS Command Injection ─────────────────────────────────────────────────
@app.route('/tools', methods=['GET','POST'])
def tools():
    redir = require_login()
    if redir: return redir
    output = ''
    if request.method == 'POST':
        action = request.form.get('action','')
        target = request.form.get('target','').strip()
        if action == 'ping' and target:
            try:
                # A03: Direct shell injection — no sanitization
                import platform as _plat
                ping_flag = "-n" if _plat.system() == "Windows" else "-c"
                result = subprocess.check_output(
                    f"ping {ping_flag} 2 {target}", shell=True,
                    stderr=subprocess.STDOUT, timeout=10
                )
                output = result.decode('utf-8', errors='replace')
            except subprocess.TimeoutExpired:
                output = "Timeout"
            except subprocess.CalledProcessError as e:
                output = e.output.decode('utf-8', errors='replace')
        elif action == 'whois' and target:
            try:
                result = subprocess.check_output(
                    f"whois {target}", shell=True,
                    stderr=subprocess.STDOUT, timeout=10
                )
                output = result.decode('utf-8', errors='replace')[:3000]
            except Exception as e:
                output = str(e)

    return render("""
    <h2>Network Tools <span class="vuln-badge">[A03: Command Injection in ping/whois]</span></h2>
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Diagnostic Tools</div>
          <div class="panel-body">
            <form method="POST">
              <div class="form-group">
                <label>Tool</label>
                <select class="form-control" name="action">
                  <option value="ping">Ping</option>
                  <option value="whois">Whois</option>
                </select>
              </div>
              <div class="form-group">
                <label>Target</label>
                <input class="form-control" name="target" placeholder="e.g. 8.8.8.8">
                <small class="text-muted">Try: 8.8.8.8; id</small>
              </div>
              <button class="btn btn-primary">Run</button>
            </form>
          </div>
        </div>
      </div>
      {% if output %}
      <div class="col-md-6">
        <div class="panel panel-info">
          <div class="panel-heading">Output</div>
          <div class="panel-body"><pre>{{ output }}</pre></div>
        </div>
      </div>
      {% endif %}
    </div>
    """, output=output)


# ── A10: SSRF ─────────────────────────────────────────────────────────────────
@app.route('/fetch')
def fetch():
    redir = require_login()
    if redir: return redir
    url     = request.args.get('url', '')
    content = ''
    error   = ''
    if url:
        try:
            # A10: No restriction on URL — can reach internal services
            req = urllib.request.Request(url, headers={'User-Agent': 'CorpPortal/1.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                content = resp.read(8192).decode('utf-8', errors='replace')
        except Exception as e:
            error = str(e)

    return render("""
    <h2>URL Fetcher <span class="vuln-badge">[A10: SSRF — try file:///etc/passwd, http://127.0.0.1:PORT]</span></h2>
    <form class="form-inline">
      <div class="input-group" style="width:500px">
        <input class="form-control" name="url" value="{{ url }}"
               placeholder="http://example.com or file:///etc/passwd">
        <span class="input-group-btn">
          <button class="btn btn-warning">Fetch</button>
        </span>
      </div>
    </form>
    <br>
    {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
    {% if content %}
    <div class="panel panel-info">
      <div class="panel-heading">Response</div>
      <div class="panel-body"><pre style="max-height:400px;overflow:auto">{{ content }}</pre></div>
    </div>
    {% endif %}
    """, url=url, content=content, error=error)


# ── A04: Predictable password reset token ────────────────────────────────────
@app.route('/reset', methods=['GET','POST'])
def reset():
    token  = request.args.get('token','')
    msg    = ''
    if token:
        db  = get_db()
        row = db.execute("SELECT * FROM reset_tokens WHERE token=?", (token,)).fetchone()
        if row and (time.time() - row['created_at']) < 3600:
            msg = f"Password reset link valid for user: {row['username']}"
        else:
            msg = "Invalid or expired token."
    elif request.method == 'POST':
        username = request.form.get('username','').strip()
        if username:
            # A04: Predictable token = MD5 of username+timestamp rounded to hour
            ts    = int(time.time() // 3600) * 3600
            token = hashlib.md5(f"{username}{ts}".encode()).hexdigest()
            db    = get_db()
            db.execute("INSERT INTO reset_tokens (username,token,created_at) VALUES (?,?,?)",
                       (username, token, time.time()))
            db.commit()
            msg = f"Reset link: /reset?token={token}"

    return render("""
    <h2>Password Reset <span class="vuln-badge">[A04: Predictable token = MD5(username+hour)]</span></h2>
    {% if msg %}<div class="alert alert-info">{{ msg }}</div>{% endif %}
    <form method="POST">
      <div class="form-group" style="max-width:300px">
        <label>Username</label>
        <input class="form-control" name="username">
      </div>
      <button class="btn btn-warning">Send Reset Link</button>
    </form>
    """, msg=msg)


# ── A08: Insecure deserialization (pickle) ─────────────────────────────────────
@app.route('/deserialize', methods=['GET','POST'])
def deserialize():
    redir = require_login()
    if redir: return redir
    result = ''
    error  = ''
    if request.method == 'POST':
        data = request.form.get('data','').strip()
        if data:
            try:
                # A08: Unsafe pickle.loads on user input — RCE possible
                obj = pickle.loads(base64.b64decode(data))
                result = str(obj)
            except Exception as e:
                error = str(e)

    # Safe pickle example for the UI
    example = base64.b64encode(pickle.dumps({'user':'alice','role':'user'})).decode()
    return render("""
    <h2>Data Import <span class="vuln-badge">[A08: Insecure Deserialization — RCE via pickle]</span></h2>
    <p class="text-muted">Paste a base64-encoded serialized object to import settings.</p>
    <form method="POST">
      <div class="form-group">
        <label>Serialized Data (base64)</label>
        <input class="form-control" name="data" value="{{ example }}">
        <small class="text-muted">Example above is a safe dict. Replace with malicious pickle for RCE.</small>
      </div>
      <button class="btn btn-danger">Deserialize</button>
    </form>
    {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
    {% if result %}<div class="alert alert-success">Result: {{ result }}</div>{% endif %}
    """, example=example, result=result, error=error)


# ── A05: Debug / info disclosure endpoints ─────────────────────────────────────
@app.route('/debug')
def debug():
    # A05: Exposes environment, config, user list
    import platform
    return jsonify({
        "warning": "A05: Security Misconfiguration — debug endpoint exposed",
        "python": platform.python_version(),
        "os": platform.system(),
        "cwd": os.getcwd(),
        "env_vars": {k: v for k, v in os.environ.items() if 'pass' not in k.lower()},
        "db_path": DB,
        "flask_secret": app.secret_key,
        "session_data": dict(session),
    })


@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    # A01: No authentication required, returns full user record
    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "warning": "A01: IDOR — no auth required on this API endpoint",
        "id":         row['id'],
        "username":   row['username'],
        "password":   row['password'],   # A02: MD5 hash exposed in API
        "role":       row['role'],
        "email":      row['email'],
        "department": row['department'],
        "salary":     row['salary'],
        "ssn":        row['ssn'],
    })


@app.route('/api/users')
def api_users():
    # A01: No auth, returns all users
    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


# ══════════════════════════════════════════════════════════════════════════════
# JavaScript Vulnerability Routes
# ══════════════════════════════════════════════════════════════════════════════

# ── JS: Calculator — eval() injection via JavaScript ──────────────────────────
@app.route('/calculator')
def calculator():
    redir = require_login()
    if redir: return redir
    return render("""
    <h2>Expense Calculator <span class="vuln-badge">[JS: eval() injection]</span></h2>
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Quick Calculator</div>
          <div class="panel-body">
            <p class="text-muted">Calculate expenses, budgets, and totals.</p>
            <div class="form-group">
              <label>Expression</label>
              <input class="form-control" id="calc-input" placeholder="e.g. 1500 + 2300 * 0.15">
              <small class="text-muted">Enter a math expression to calculate.</small>
            </div>
            <button class="btn btn-primary" onclick="
              var expr = document.getElementById('calc-input').value;
              var result = calculate(expr);
              document.getElementById('calc-result').innerHTML =
                '<div class=&quot;alert alert-success&quot;><b>Result:</b> ' + result + '</div>';
            ">Calculate</button>
            <div id="calc-result" style="margin-top:15px"></div>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="panel panel-info">
          <div class="panel-heading">Budget Templates</div>
          <div class="panel-body">
            <p>Common calculations:</p>
            <ul>
              <li><a href="#" onclick="document.getElementById('calc-input').value='(85000 + 12000) * 0.30'; return false;">Tax estimate (30%)</a></li>
              <li><a href="#" onclick="document.getElementById('calc-input').value='4500 * 12 + 2000'; return false;">Annual + bonus</a></li>
              <li><a href="#" onclick="document.getElementById('calc-input').value='(150000 - 45000) / 12'; return false;">Monthly net</a></li>
            </ul>
            <hr>
            <div class="alert alert-warning">
              <small><b>Vulnerability:</b> The calculator uses <code>eval()</code> on user input.
              Try: <code>alert(document.cookie)</code> or
              <code>fetch('/api/users').then(r=>r.text()).then(d=>document.getElementById('calc-result').innerHTML=d)</code></small>
            </div>
          </div>
        </div>
      </div>
    </div>
    """)


# ── JS: Settings — Prototype pollution + client-side access control ───────────
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    redir = require_login()
    if redir: return redir
    # Server side: handle JSON settings import
    result = ''
    if request.method == 'POST' and request.form.get('import_json'):
        import_data = request.form.get('import_json', '')
        try:
            parsed = json.loads(import_data)
            result = f"Imported {len(parsed)} settings keys: {list(parsed.keys())[:10]}"
        except Exception as e:
            result = f"Error: {e}"

    return render("""
    <h2>User Settings
      <span class="vuln-badge">[JS: Prototype Pollution + Client-Side Auth Bypass]</span>
    </h2>
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Preferences (JSON Import)</div>
          <div class="panel-body">
            <p class="text-muted">Import your settings as JSON. Merged with app defaults.</p>
            <div class="form-group">
              <label>Settings JSON</label>
              <textarea class="form-control" id="user-settings-json" rows="5"
                placeholder='{"theme": "dark", "language": "en"}'>{}</textarea>
              <small class="text-muted">
                Try: <code>{"__proto__": {"isAdmin": true, "polluted": "yes"}}</code>
              </small>
            </div>
            <button class="btn btn-warning" onclick="saveSettings()">Apply Settings</button>
            <div id="settings-result" style="margin-top:15px"></div>
            {% if result %}<div class="alert alert-info" style="margin-top:10px">{{ result }}</div>{% endif %}
          </div>
        </div>
        <div class="panel panel-default">
          <div class="panel-heading">Theme Preview</div>
          <div class="panel-body">
            <form method="POST">
              <div class="form-group">
                <label>Import Configuration (Server-side)</label>
                <textarea class="form-control" name="import_json" rows="3"
                  placeholder='{"theme":"dark"}'></textarea>
              </div>
              <button class="btn btn-default">Import</button>
            </form>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="panel panel-danger admin-only" id="admin-tools-panel">
          <div class="panel-heading">Admin Tools (Client-Side Access Control)</div>
          <div class="panel-body">
            <p><b>This panel is hidden by JavaScript for non-admin users.</b></p>
            <p>But the HTML is still in the DOM — view source or use DevTools.</p>
            <ul>
              <li><a href="/admin/config">System Configuration</a></li>
              <li><a href="/api/users">Export All Users (JSON)</a></li>
              <li><a href="/admin/reports">Financial Reports</a></li>
            </ul>
            <hr>
            <p class="text-muted"><small>Bypass: Open console, type:
            <code>enableDevMode()</code> or
            <code>sessionStorage.setItem('admin_flag','true'); checkAccess();</code></small></p>
          </div>
        </div>
        <div class="panel panel-info">
          <div class="panel-heading">localStorage Data</div>
          <div class="panel-body">
            <p class="text-muted">Your browser stores sensitive data in localStorage:</p>
            <pre id="local-storage-dump" style="max-height:200px; overflow:auto; font-size:11px"></pre>
            <button class="btn btn-xs btn-default" onclick="
              var dump = {};
              for(var i=0; i<localStorage.length; i++){
                var k = localStorage.key(i);
                dump[k] = localStorage.getItem(k);
              }
              document.getElementById('local-storage-dump').textContent = JSON.stringify(dump, null, 2);
            ">Show localStorage</button>
          </div>
        </div>
      </div>
    </div>
    <script>checkAccess();</script>
    """, result=result)


# ── JS: Messages — postMessage + DOM XSS via messages ─────────────────────────
@app.route('/messages')
def messages():
    redir = require_login()
    if redir: return redir
    return render("""
    <h2>Internal Messages
      <span class="vuln-badge">[JS: postMessage no origin check + DOM XSS]</span>
    </h2>
    <div class="row">
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Send Message</div>
          <div class="panel-body">
            <div class="form-group">
              <label>To</label>
              <input class="form-control" id="msg-to" placeholder="username">
            </div>
            <div class="form-group">
              <label>Message (HTML allowed)</label>
              <textarea class="form-control" id="msg-body" rows="3"
                placeholder="Type your message..."></textarea>
            </div>
            <button class="btn btn-primary" onclick="
              var body = document.getElementById('msg-body').value;
              window.postMessage(JSON.stringify({action:'renderHTML', html: body}), '*');
            ">Send via postMessage</button>
          </div>
        </div>
        <div class="panel panel-warning">
          <div class="panel-heading">Cross-Origin Message Test</div>
          <div class="panel-body">
            <p class="text-muted">This page accepts postMessage from <b>any origin</b>.</p>
            <p>Supported actions:</p>
            <ul>
              <li><code>renderHTML</code> — injects HTML into page</li>
              <li><code>navigate</code> — redirects user</li>
              <li><code>getToken</code> — returns auth token to sender</li>
              <li><code>updateProfile</code> — modifies user profile</li>
              <li><code>executeAction</code> — runs arbitrary JavaScript</li>
            </ul>
            <hr>
            <p><small><b>PoC:</b> Open console on another tab:
            <code>window.open('http://127.0.0.1:5001/messages').postMessage(
              '{"action":"getToken"}','*')</code></small></p>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="panel panel-default">
          <div class="panel-heading">Inbox</div>
          <div class="panel-body" id="message-inbox">
            <div class="text-muted">No messages yet. Messages rendered via postMessage will appear here.</div>
          </div>
        </div>
        <div class="panel panel-default">
          <div class="panel-heading">WebSocket Notifications</div>
          <div class="panel-body">
            <div id="ws-messages">
              <p class="text-muted">Real-time notifications (WebSocket — no auth required)</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- postMessage renders into dynamic-content div in base template -->
    """)


# ── JS: Open redirect via JavaScript ─────────────────────────────────────────
@app.route('/redirect')
def js_redirect():
    url = request.args.get('url', '') or request.args.get('next', '') or request.args.get('return', '')
    return render("""
    <h2>Redirecting... <span class="vuln-badge">[JS: Open Redirect]</span></h2>
    <p>You are being redirected to: <code id="redir-target">{{ url }}</code></p>
    <p><a href="{{ url }}">Click here if not redirected automatically.</a></p>
    <script>
      var target = '{{ url }}';
      if (target) {
        // VULN: No validation — open redirect to any URL
        setTimeout(function(){ window.location.href = target; }, 2000);
      }
    </script>
    """, url=url)


# ── JS: JSONP endpoint — callback injection ──────────────────────────────────
@app.route('/api/data/export')
def api_data_export():
    callback = request.args.get('callback', '')
    db = get_db()
    users = db.execute("SELECT id,username,email,department FROM users").fetchall()
    data = json.dumps([dict(u) for u in users])

    if callback:
        # VULN: JSONP callback injection — user controls function name
        # Payload: ?callback=alert(document.cookie)//
        response = app.response_class(
            response=f'{callback}({data})',
            status=200,
            mimetype='application/javascript'
        )
        return response
    return jsonify([dict(u) for u in users])


# ── JS: Source map exposure — reveals original source code ────────────────────
@app.route('/static/js/app.js.map')
def source_map():
    # VULN: Source map file exposed — reveals full original source code
    # Real-world: Many SPAs ship .map files that expose unminified source
    import json as _json
    try:
        with open(os.path.join(os.path.dirname(__file__), 'static', 'js', 'app.js'), 'r') as f:
            source = f.read()
    except Exception:
        source = '// source not available'
    return jsonify({
        "version": 3,
        "file": "app.js",
        "sourceRoot": "",
        "sources": ["../src/app.ts", "../src/config.ts", "../src/auth.ts"],
        "sourcesContent": [source, "// config.ts\nexport const API_KEY = 'FAKE_stripe_key_for_testing_do_not_use_1234567890';\nexport const DB_PASS = 'corp_db_2024!';\n", "// auth.ts\nconst ADMIN_HASH = '0192023a7bbd73250516f069df18b500';"],
        "names": [],
        "mappings": "AAAA,OAAO"
    })


# ── JS: API config endpoint — secrets in API response ─────────────────────────
@app.route('/api/config')
def api_config():
    # VULN: API endpoint leaks configuration including secrets
    return jsonify({
        "app_name": "CorpPortal",
        "version": "2.1.3",
        "environment": "production",
        "debug": True,
        "database": {
            "host": "localhost",
            "name": "corp.db",
            "user": "app_user",
            "password": "Db@ccess2024!",
        },
        "jwt_secret": "weakkey123",
        "api_keys": {
            "stripe": "FAKE_stripe_key_for_testing_do_not_use_1234567890",
            "sendgrid": "SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        },
        "smtp": {
            "host": "smtp.corp.local",
            "user": "noreply@corp.local",
            "password": "MailPass2024!",
        },
        "internal_services": {
            "cache": "redis://10.0.0.3:6379",
            "queue": "amqp://admin:admin@10.0.0.4:5672",
            "search": "http://10.0.0.5:9200",
        },
        "cors_origins": ["*"],
        "rate_limiting": False,
    })


# ── JS: User preferences — stored XSS via AJAX ──────────────────────────────
@app.route('/api/preferences', methods=['GET', 'POST'])
def api_preferences():
    if request.method == 'POST':
        # Store preferences as-is — no sanitization
        data = request.get_json(force=True, silent=True) or {}
        prefs = json.dumps(data)
        if logged_in():
            db = get_db()
            db.execute("UPDATE users SET notes=? WHERE id=?",
                       (prefs, session['user_id']))
            db.commit()
        return jsonify({"status": "saved", "preferences": data})

    if logged_in():
        row = get_db().execute("SELECT notes FROM users WHERE id=?",
                               (session['user_id'],)).fetchone()
        try:
            prefs = json.loads(row['notes']) if row and row['notes'] else {}
        except Exception:
            prefs = {}
        return jsonify(prefs)
    return jsonify({})


# ── JS: Webhook registration — SSRF + no auth ────────────────────────────────
@app.route('/api/webhooks', methods=['GET', 'POST'])
def api_webhooks():
    # VULN: Register webhook URLs — server will call them (SSRF)
    # VULN: No authentication required
    if request.method == 'POST':
        data = request.get_json(force=True, silent=True) or {}
        url = data.get('url', '')
        if url:
            try:
                # VULN: Server fetches user-supplied URL — SSRF
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'CorpPortal-Webhook/1.0',
                    'X-Webhook-Secret': app.secret_key,
                })
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
                return jsonify({"status": "registered", "url": url, "test_status": status})
            except Exception as e:
                return jsonify({"status": "error", "url": url, "error": str(e)})
    return jsonify({
        "webhooks": [],
        "note": "POST with {\"url\": \"http://...\"} to register a webhook",
    })


# ── Startup ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════╗
║         VulnCorp Portal — OWASP Top 10 Target            ║
║  ⚠  FOR SECURITY TESTING ONLY — NEVER EXPOSE PUBLICLY  ⚠  ║
╠══════════════════════════════════════════════════════════╣
║  URL:  http://127.0.0.1:5001                             ║
║  Creds: admin/admin123  alice/password1  bob/123456       ║
╚══════════════════════════════════════════════════════════╝
""")
    init_db()
    app.run(host='127.0.0.1', port=5001, debug=True)
