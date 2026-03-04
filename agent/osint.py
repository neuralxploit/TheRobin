"""
OSINT and passive reconnaissance engine.

Uses free, no-API-key sources:
  - DuckDuckGo  — Google-style dorks (site:, inurl:, filetype:, intitle:)
  - crt.sh      — certificate transparency / subdomain discovery
  - Wayback CDX — historical URL enumeration
  - DNS (dig)   — A, AAAA, MX, TXT, NS, SOA records
  - whois       — registrar / registration info
  - DNS brute   — common subdomain guessing

DuckDuckGo is preferred over Google because:
  - Supports the same operators (site:, inurl:, filetype:, intitle:, "exact phrase")
  - Far less aggressive bot-detection / IP banning
  - No API key or account needed
"""

import json
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error


# ─── HTTP helper ──────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
}


def _make_opener():
    """Build a urllib opener, routing through Tor if enabled."""
    from . import tools as _tools
    handlers = []
    if _tools.TOR_ENABLED:
        proxy = urllib.request.ProxyHandler({
            "http":  _tools.TOR_PROXY,
            "https": _tools.TOR_PROXY,
        })
        handlers.append(proxy)
    return urllib.request.build_opener(*handlers)


def _get(url: str, timeout: int = 20, headers: dict = None) -> str:
    h = {**_HEADERS, **(headers or {})}
    opener = _make_opener()
    req = urllib.request.Request(url, headers=h)
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ─── DuckDuckGo dork search ───────────────────────────────────────────────────

def duckduckgo_dork(query: str, max_results: int = 15) -> dict:
    """
    Search DuckDuckGo with full operator support.

    Supported operators (same as Google):
      site:example.com          — restrict to domain
      inurl:admin               — URL contains word
      intitle:login             — page title contains word
      filetype:pdf              — specific file type
      "exact phrase"            — exact match
      -word                     — exclude word

    Examples:
      site:target.com filetype:pdf
      site:target.com inurl:admin
      site:target.com intitle:login
      "target.com" password filetype:txt
      site:github.com "target.com" api_key
    """
    try:
        encoded = urllib.parse.quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}&kl=us-en"

        opener = _make_opener()
        req = urllib.request.Request(
            url,
            headers={
                **_HEADERS,
                "Referer": "https://duckduckgo.com/",
            },
        )
        with opener.open(req, timeout=20) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        results = []

        # Extract result blocks — each result is in a div.result
        # Title + link pattern
        link_re = re.compile(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            re.DOTALL | re.IGNORECASE,
        )
        snippet_re = re.compile(
            r'class="result__snippet"[^>]*>(.*?)</(?:a|span|div)>',
            re.DOTALL | re.IGNORECASE,
        )
        url_re = re.compile(
            r'class="result__url"[^>]*>(.*?)</(?:a|span)>',
            re.DOTALL | re.IGNORECASE,
        )

        links    = link_re.findall(html)
        snippets = snippet_re.findall(html)
        urls     = url_re.findall(html)

        def clean(text: str) -> str:
            text = re.sub(r"<[^>]+>", "", text)
            return text.strip()

        def decode_ddg_url(href: str) -> str:
            # DDG wraps URLs in redirect: /l/?uddg=<encoded>
            m = re.search(r"uddg=([^&]+)", href)
            if m:
                return urllib.parse.unquote(m.group(1))
            return href

        for i, (href, title) in enumerate(links[:max_results]):
            real_url = decode_ddg_url(href)
            snippet  = clean(snippets[i]) if i < len(snippets) else ""
            display  = clean(urls[i])     if i < len(urls)     else real_url
            results.append({
                "title":   clean(title),
                "url":     real_url,
                "display": display,
                "snippet": snippet[:300],
            })

        return {
            "query":   query,
            "engine":  "DuckDuckGo",
            "results": results,
            "count":   len(results),
            "note":    "Supports: site: inurl: intitle: filetype: \"exact\" -exclude",
        }

    except Exception as e:
        return {
            "error":   str(e),
            "query":   query,
            "results": [],
            "count":   0,
        }


# ─── Certificate Transparency (crt.sh) ───────────────────────────────────────

def crtsh_subdomains(domain: str) -> dict:
    """
    Query crt.sh for subdomains from SSL/TLS certificate logs.
    Free, highly reliable, no API key needed.
    Often finds dev/staging/internal subdomains not in DNS brute lists.
    """
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        raw = _get(url, timeout=30)
        entries = json.loads(raw)

        subdomains = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                sub = name.strip().lower().lstrip("*.")
                if sub and domain.lower() in sub and " " not in sub:
                    subdomains.add(sub)

        sorted_subs = sorted(subdomains)
        return {
            "domain":     domain,
            "subdomains": sorted_subs,
            "count":      len(sorted_subs),
            "source":     "crt.sh (certificate transparency)",
        }
    except Exception as e:
        return {
            "error":      str(e),
            "domain":     domain,
            "subdomains": [],
            "count":      0,
        }


# ─── DNS enumeration ──────────────────────────────────────────────────────────

def dns_records(domain: str) -> dict:
    """
    Enumerate DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA.
    Uses dig (or nslookup as fallback).
    """
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            r = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=10,
            )
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            if lines:
                records[rtype] = lines
        except FileNotFoundError:
            # dig not available — try nslookup
            try:
                r = subprocess.run(
                    ["nslookup", "-type=" + rtype, domain],
                    capture_output=True, text=True, timeout=10,
                )
                lines = [l.strip() for l in r.stdout.splitlines()
                         if l.strip() and "=" in l]
                if lines:
                    records[rtype] = lines
            except Exception:
                pass
        except Exception:
            pass

    # Direct resolution
    try:
        ip = socket.gethostbyname(domain)
        records["_resolved_ip"] = ip
    except Exception:
        pass

    return {"domain": domain, "records": records}


# ─── WHOIS ────────────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """
    WHOIS lookup — registrar, dates, name servers, registrant info.
    Useful for understanding target ownership and attack surface.
    """
    try:
        r = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=20,
        )
        output = r.stdout[:6000]

        patterns = {
            "registrar":         r"(?i)Registrar:\s*(.+)",
            "registrant_org":    r"(?i)Registrant Organi[sz]ation:\s*(.+)",
            "registrant_email":  r"(?i)Registrant Email:\s*(.+)",
            "registrant_country":r"(?i)Registrant Country:\s*(.+)",
            "created":           r"(?i)Creation Date:\s*(.+)",
            "expires":           r"(?i)(?:Registry Expiry|Expir(?:ation|y)) Date:\s*(.+)",
            "updated":           r"(?i)Updated Date:\s*(.+)",
            "name_servers":      r"(?i)Name Server:\s*(.+)",
            "status":            r"(?i)Domain Status:\s*(.+)",
            "tech_email":        r"(?i)Tech Email:\s*(.+)",
            "abuse_email":       r"(?i)Abuse (?:Contact )?Email:\s*(.+)",
        }

        fields = {}
        for key, pattern in patterns.items():
            matches = re.findall(pattern, output)
            if matches:
                if key in ("name_servers", "status"):
                    fields[key] = [m.strip() for m in matches[:5]]
                else:
                    fields[key] = matches[0].strip()

        return {"domain": domain, "parsed": fields, "raw": output}

    except FileNotFoundError:
        return {"error": "whois not installed (apt install whois)", "domain": domain}
    except Exception as e:
        return {"error": str(e), "domain": domain}


# ─── Wayback Machine URL enumeration ─────────────────────────────────────────

def wayback_urls(domain: str, limit: int = 100) -> dict:
    """
    Query Wayback Machine CDX API for historical URLs on the target.
    Excellent for finding forgotten endpoints, old admin panels, backup files.
    """
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{urllib.parse.quote(domain)}/*"
            f"&output=json&fl=original,statuscode,timestamp"
            f"&collapse=urlkey&limit={limit}"
            f"&filter=statuscode:200"
        )
        raw = _get(url, timeout=30)
        entries = json.loads(raw)

        # First row is header
        if not entries or len(entries) < 2:
            return {"domain": domain, "urls": [], "count": 0, "source": "Wayback Machine"}

        urls = []
        for row in entries[1:]:
            if len(row) >= 1:
                urls.append({
                    "url":       row[0],
                    "status":    row[1] if len(row) > 1 else "?",
                    "timestamp": row[2] if len(row) > 2 else "?",
                })

        return {
            "domain":  domain,
            "urls":    urls,
            "count":   len(urls),
            "source":  "web.archive.org (Wayback Machine CDX API)",
        }
    except Exception as e:
        return {"error": str(e), "domain": domain, "urls": [], "count": 0}


# ─── Subdomain brute force ────────────────────────────────────────────────────

_COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "dev", "development", "staging", "stage", "test", "uat", "qa", "demo",
    "api", "api2", "v1", "v2", "v3", "graphql", "rest", "ws",
    "admin", "portal", "dashboard", "panel", "manager", "control",
    "auth", "login", "sso", "oauth", "id", "account", "accounts",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "vpn", "remote", "secure", "ssl", "gateway",
    "app", "apps", "web", "webmail", "webdav",
    "git", "gitlab", "github", "bitbucket", "svn",
    "jira", "confluence", "wiki", "docs", "help", "support",
    "jenkins", "ci", "cd", "build", "deploy",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "s3", "storage", "backup", "archive",
    "monitor", "nagios", "zabbix", "grafana", "kibana", "splunk",
    "blog", "shop", "store", "pay", "payment", "checkout",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "internal", "intranet", "corp", "corporate",
    "old", "legacy", "beta", "alpha", "preview",
    "mobile", "m", "wap",
    "search", "status", "health",
]


def subdomain_bruteforce(domain: str, wordlist: list = None) -> dict:
    """
    Brute-force common subdomains via DNS resolution.
    Fast — only does DNS lookups, no HTTP requests.
    """
    words = wordlist or _COMMON_SUBDOMAINS
    found = {}

    for sub in words:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found[host] = ip
        except socket.gaierror:
            pass

    return {
        "domain": domain,
        "found":  found,
        "count":  len(found),
        "method": "dns-bruteforce",
    }


# ─── theHarvester wrapper (if installed) ─────────────────────────────────────

def theharvester(domain: str, sources: str = "duckduckgo,crtsh,dnsdumpster") -> dict:
    """
    Run theHarvester for email/subdomain/IP harvesting.
    Uses multiple OSINT sources simultaneously.
    """
    try:
        r = subprocess.run(
            ["theHarvester", "-d", domain, "-b", sources, "-l", "100"],
            capture_output=True, text=True, timeout=120,
        )
        output = r.stdout + r.stderr

        # Parse emails
        emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), output)))
        # Parse subdomains
        subs = list(set(re.findall(
            r"\b([a-zA-Z0-9\-]+\." + re.escape(domain) + r")\b", output
        )))
        # Parse IPs
        ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)))

        return {
            "domain":     domain,
            "sources":    sources,
            "emails":     emails,
            "subdomains": sorted(subs),
            "ips":        ips,
            "raw":        output[:5000],
        }
    except FileNotFoundError:
        return {
            "error":  "theHarvester not installed (pip install theHarvester or apt install theharvester)",
            "domain": domain,
        }
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester timed out after 120s", "domain": domain}
    except Exception as e:
        return {"error": str(e), "domain": domain}
