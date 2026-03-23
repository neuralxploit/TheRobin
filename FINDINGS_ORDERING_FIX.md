# Findings Ordering & Consolidation Fix

## Problem

The PDF report had two issues:
1. **Duplicate findings**: Same vulnerability type appeared multiple times (e.g., 8 "SQL Injection" entries)
2. **Poor ordering**: Related findings were scattered throughout the report

### Example of Bad Output:

```markdown
# Severity Finding
1  CRITICAL Information Disclosure
2  CRITICAL SQL Injection
3  CRITICAL SQL Injection
4  CRITICAL SQL Injection
5  CRITICAL SQL Injection
6  CRITICAL SQL Injection
7  CRITICAL SQL Injection
8  CRITICAL SQL Injection
9  CRITICAL SQL Injection
10 CRITICAL Vertical IDOR
11 CRITICAL Broken Authentication
...
36 HIGH API IDOR
37 HIGH Framework Template XSS
38 HIGH Reflected XSS
39 HIGH Stored XSS
40 HIGH Stored XSS
41 HIGH Stored XSS
42 HIGH Stored XSS
43 HIGH Stored XSS
44 HIGH Stored XSS
```

**Issues:**
- 9 SQL Injection entries (should be 1 with all endpoints)
- 6 Stored XSS entries (should be 1 with all endpoints)
- No consolidation of similar findings
- Hard to read and analyze

## Solution

### 1. Added Injection Types to `_COLLAPSE_ALL`

Previously, only certain vulnerability types were collapsed. Now ALL injection types collapse:

```python
_COLLAPSE_ALL = {
    'Vertical IDOR', 'Unauthenticated API Access', 'Workflow Bypass', 'Rate Limiting', 'Account Lockout',
    'Password Policy', 'Account Enumeration', 'API Docs Exposed',
    'Default Credentials', 'Database Error Disclosure', 'Information Disclosure',
    'DOM XSS', 'Prototype Pollution', 'HTTP Smuggling', 'HTTP Method Override',
    'Metrics Exposed', 'Hardcoded Secrets', 'SSTI', 'Mass Assignment',
    'Excessive Data Exposure', 'Business Logic', 'Robots Disallowed Path',
    # NEW: Injection vulnerabilities - consolidate all endpoints into ONE finding
    'SQLi', 'Command Injection', 'SSRF', 'XSS', 'Reflected XSS', 'Stored XSS',
    'Path Traversal', 'XXE', 'Insecure Deserialization', 'File Upload',
    'GraphQL Injection', 'NoSQL Injection',
}
```

### 2. Rewrote Collapse Logic to Merge POCs

The old logic only updated the title. The new logic:

1. **Collects ALL findings** for a category (not just the best one)
2. **Merges all POCs** into a single comprehensive section
3. **Lists all affected endpoints** at the top of the POC
4. **Shows the endpoint for each POC** with clear headers

```python
# Old: Just updated title
best_f["title"] = f"{title} (+{count} more endpoints)"

# New: Merge ALL POCs
best_f['poc'] = "# Affected Endpoints\n" + "\n".join(f"- {u}" for u in real_urls) + "\n\n" + "\n\n".join(all_pocs)
```

### 3. Added Missing Vulnerability Categories

Added NoSQL Injection, GraphQL Injection, deserialization, and other patterns to `_VULN_CATEGORIES`:

```python
'nosqli': 'NoSQL Injection', 'nosql injection': 'NoSQL Injection',
'graphql injection': 'GraphQL Injection', 'graphql': 'GraphQL Injection',
'deserialization': 'Insecure Deserialization', 'pickle': 'Insecure Deserialization',
'rce': 'Command Injection', 'lfi': 'Path Traversal',
```

## Example of New Output:

```markdown
## CRITICAL Findings

### SQL Injection (9 endpoints)

# Affected Endpoints
- http://target/login
- http://target/api/users
- http://target/api/products
- http://target/search
- ...

## Endpoint: http://target/login (param: username)
curl -sk -A "$UA" -X POST 'http://target/login' \
  --data-urlencode "username=' OR '1'='1' --" \
  -d 'password=x'

## Endpoint: http://target/api/users (param: id)
curl -sk -A "$UA" 'http://target/api/users?id=1+UNION+SELECT+...'

...

### Stored XSS (6 endpoints)
### Command Injection (3 endpoints)
...
```

## Benefits

1. **Single entry per vulnerability type**: 9 SQLi entries → 1 SQLi entry with all endpoints
2. **Comprehensive POC**: All affected endpoints listed with their specific POCs
3. **Clear structure**: Easy to see attack surface at a glance
4. **Professional appearance**: Clean, organized report
5. **Logical ordering**: Related findings grouped together