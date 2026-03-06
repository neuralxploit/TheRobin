**Phase 1 — Recon**
  URL VALIDATION FIRST — before anything else, confirm the target resolves:
    import socket, time
    from urllib.parse import urlparse

    target = 'https://target.com'  # replace with actual target
    hostname = urlparse(target).hostname
    try:
        socket.getaddrinfo(hostname, 443)
        print(f"[INFO] DNS OK: {hostname} resolves")
    except socket.gaierror:
        # Common typo: wwww → www, missing www, wrong subdomain
        print(f"[ERROR] DNS failed for {hostname} — trying alternatives:")
        alternatives = []
        if hostname.startswith('wwww.'):
            alternatives.append(target.replace('wwww.', 'www.', 1))
        if not hostname.startswith('www.'):
            alternatives.append(target.replace('://', '://www.', 1))
        # Try stripping subdomains
        parts = hostname.split('.')
        if len(parts) > 2:
            alternatives.append(target.replace(hostname, '.'.join(parts[-2:])))
        working = None
        for alt in alternatives:
            try:
                alt_host = urlparse(alt).hostname
                socket.getaddrinfo(alt_host, 443)
                print(f"  Found working URL: {alt}")
                working = alt
                break
            except Exception:
                pass
        if working:
            BASE = working   # use the working URL going forward
            target = working
            print(f"[INFO] Using {working} as target")
        else:
            print(f"[ERROR] Cannot resolve target — check the URL and try again")

  - Fetch homepage and ALWAYS capture the final URL after redirects:
      session = requests.Session()
      session.verify = False
      session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0'
      r = session.get(target, timeout=15, allow_redirects=True)
      # Log redirect chain
      if r.history:
          print(f"Redirect chain ({len(r.history)} hops):")
          for h in r.history:
              print(f"  {h.status_code} → {h.headers.get('Location', '?')}")
      print(f"Final URL: {r.url}  (Status: {r.status_code})")
      # Set BASE to the final landing URL — all links must be built from here
      BASE = r.url.rstrip('/')
      soup = BeautifulSoup(r.text, 'html.parser')
  - Print: status code, server header, X-Powered-By, detected technologies
  - Identify: CMS? Framework? Language? Interesting paths?

  SPIDER — extract ALL pages, links, and forms (run this as a dedicated run_python call):
    Use this exact spider function. It crawls the entire app and builds a map you will
    use throughout ALL subsequent phases. Store results in global _G so other calls use them.

    ```python
    import requests, time
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urlparse

    BASE    = _G['BASE']           # always set from user input at session start
    session = _G.get('session', requests.Session())
    session.verify = False

    visited = set()
    queue = [BASE + '/']
    # Global maps — filled by spider, used in ALL later phases
    ALL_PAGES = {}    # url → response text
    ALL_FORMS = []    # list of {url, method, action, fields: [{name, type, value}]}
    ALL_LINKS = set() # every href found

    def spider_page(url):
        url = url.split('#')[0].rstrip('/')  # strip anchors, trailing slash
        if url in visited:
            return
        parsed = urlparse(url)
        base_parsed = urlparse(BASE)
        # Only crawl same host
        if parsed.netloc and parsed.netloc != base_parsed.netloc:
            return
        visited.add(url)
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
        except Exception as e:
            print(f"  [SKIP] {url} — {e}")
            return
        ALL_PAGES[url] = r.text
        soup = BeautifulSoup(r.text, 'html.parser')

        # Extract all links
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            full = urljoin(url, href).split('#')[0].rstrip('/')
            ALL_LINKS.add(full)
            if full not in visited:
                queue.append(full)

        # Extract all forms with every field
        for form in soup.find_all('form'):
            action = form.get('action', url)
            action_url = urljoin(url, action)
            method = form.get('method', 'get').lower()
            fields = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                fname = inp.get('name') or inp.get('id') or ''
                ftype = inp.get('type', 'text').lower()
                fval  = inp.get('value', '')
                if fname:
                    fields.append({'name': fname, 'type': ftype, 'value': fval})
            if fields:  # only record forms that have usable inputs
                ALL_FORMS.append({
                    'page': url,
                    'action': action_url,
                    'method': method,
                    'fields': fields,
                })
                print(f"  [FORM] {method.upper()} {action_url}")
                for f in fields:
                    print(f"         field: {f['name']} ({f['type']})")

    # BFS crawl
    while queue:
        url = queue.pop(0)
        spider_page(url)
        time.sleep(0.1)  # polite delay

    # Save to globals so all future run_python calls can access them
    _G['ALL_PAGES'] = ALL_PAGES
    _G['ALL_FORMS'] = ALL_FORMS
    _G['ALL_LINKS'] = ALL_LINKS

    print(f"\n=== SPIDER COMPLETE ===")
    print(f"Pages crawled : {len(ALL_PAGES)}")
    print(f"Forms found   : {len(ALL_FORMS)}")
    print(f"Links found   : {len(ALL_LINKS)}")
    print("\nAll pages:")
    for u in sorted(ALL_PAGES):
        print(f"  {u}  ({len(ALL_PAGES[u])} bytes)")
    print("\nAll forms:")
    for f in ALL_FORMS:
        print(f"  [{f['method'].upper()}] {f['action']}  (on page: {f['page']})")
    ```

  IMPORTANT: The unauthenticated spider runs BEFORE login.
  You MUST run a second spider AFTER login (see Phase 3 — AUTHENTICATED CRAWL below).
  Logged-in users see completely different pages (dashboard, profile, comments, admin).
