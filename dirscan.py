#!/usr/bin/env python3
"""
dirscan - lightweight web directory / endpoint enumerator.

Features
  * Wordlist + extension brute forcing with a thread pool
  * Status-code include/exclude filtering
  * Wildcard / soft-404 detection (baseline of random paths)
  * Basic technology fingerprinting from headers, cookies, body markers,
    and the server's own error page

Only run this against systems you own or have written permission to test.

Examples
  python dirscan.py https://example.test -w wordlists/dirs.txt
  python dirscan.py http://10.0.0.5:8080 -w wordlists/dirs.txt -x php,bak -t 30 -s 200,301,403
  python dirscan.py https://example.test -w wordlists/dirs.txt -o results.json -H "Cookie: a=b"
"""
import argparse
import json
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# --------------------------------------------------------------------------
# Fingerprinting
# --------------------------------------------------------------------------

# Cookie name -> technology
COOKIE_SIGS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet/JSP)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "sessionid": "Django (probable)",
    "connect.sid": "Node.js / Express",
    "_rails_session": "Ruby on Rails",
    "CFID": "ColdFusion",
    "wordpress_": "WordPress",
    "__cfduid": "Cloudflare",
}

# Regex on response body of the home page -> technology
BODY_SIGS = [
    (r"/wp-content/|/wp-includes/", "WordPress"),
    (r"content=[\"']Drupal", "Drupal"),
    (r"/sites/default/files", "Drupal"),
    (r"content=[\"']Joomla", "Joomla"),
    (r"<meta name=[\"']generator[\"'] content=[\"']([^\"']+)", None),  # capture
    (r"__NEXT_DATA__|/_next/static", "Next.js"),
    (r"ng-version=|<app-root", "Angular"),
    (r"data-reactroot|react-dom", "React (probable)"),
    (r"__VIEWSTATE", "ASP.NET WebForms"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"Powered by Jenkins|Jenkins-Crumb|/static/[0-9a-f]{8}/", "Jenkins (probable)"),
]

# Signatures in a server-generated 404/error page -> technology
ERROR_PAGE_SIGS = [
    (r"nginx", "nginx"),
    (r"Apache(?:/[\d.]+)? (?:Server|Tomcat)|<address>Apache", "Apache httpd"),
    (r"Apache Tomcat", "Apache Tomcat"),
    (r"Microsoft-IIS|IIS (?:\d|Detailed)|Server Error in '/' Application", "Microsoft IIS / ASP.NET"),
    (r"Whitelabel Error Page", "Spring Boot"),
    (r"Using the URLconf defined in", "Django (DEBUG=True)"),
    (r"The requested URL was not found on the server", "Flask / Werkzeug"),
    (r"Cannot (?:GET|POST) /", "Express (Node.js)"),
    (r"Sinatra doesn.t know this ditty", "Sinatra (Ruby)"),
    (r"Laravel|Symfony\\\\Component", "PHP framework (Laravel/Symfony)"),
    (r"lighttpd", "lighttpd"),
    (r"openresty", "OpenResty"),
    (r"cloudflare", "Cloudflare"),
    (r"Caddy", "Caddy"),
    (r"Error 404 \(Not Found\)!!1", "Google frontend"),
    (r"<center>nginx</center>", "nginx"),
    (r"The page you were looking for doesn.t exist", "Ruby on Rails"),
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Cache",
    "CF-RAY", "X-Amz-Cf-Id", "X-Served-By", "X-Runtime", "X-Backend-Server",
]


def fingerprint(home, err):
    """Build a fingerprint dict from the home-page and error-page responses."""
    fp = {"headers": {}, "technologies": set(), "missing_security_headers": [],
          "error_page": None}

    for resp, label in ((home, "home"), (err, "error")):
        if resp is None:
            continue
        for h in INTERESTING_HEADERS:
            if h in resp.headers:
                fp["headers"][h] = resp.headers[h]
        server = resp.headers.get("Server")
        if server:
            fp["technologies"].add(f"Server: {server}")
        xp = resp.headers.get("X-Powered-By")
        if xp:
            fp["technologies"].add(f"X-Powered-By: {xp}")
        for cookie in resp.cookies.keys():
            for sig, tech in COOKIE_SIGS.items():
                if cookie.startswith(sig):
                    fp["technologies"].add(tech)

    if home is not None:
        body = home.text[:200_000]
        for pattern, tech in BODY_SIGS:
            m = re.search(pattern, body, re.I)
            if m:
                fp["technologies"].add(tech if tech else f"Generator: {m.group(1)}")
        fp["missing_security_headers"] = [
            h for h in SECURITY_HEADERS if h not in home.headers
        ]
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title:
            fp["title"] = " ".join(title.group(1).split())[:100]

    if err is not None:
        body = err.text[:50_000]
        hits = {tech for pat, tech in ERROR_PAGE_SIGS if re.search(pat, body, re.I)}
        fp["technologies"].update(f"{t} (from error page)" for t in hits)
        fp["error_page"] = {
            "status": err.status_code,
            "length": len(err.content),
            "matched": sorted(hits),
        }

    fp["technologies"] = sorted(fp["technologies"])
    return fp


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

class Scanner:
    def __init__(self, args):
        self.base = args.url.rstrip("/") + "/"
        self.args = args
        self.local = threading.local()
        self.lock = threading.Lock()
        self.results = []
        self.done = 0
        self.total = 0
        self.errors = 0
        self.baselines = []  # list of (status, length)
        self.headers = {"User-Agent": args.user_agent}
        for h in args.header or []:
            k, _, v = h.partition(":")
            self.headers[k.strip()] = v.strip()

    def session(self):
        s = getattr(self.local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update(self.headers)
            s.verify = not self.args.insecure
            self.local.s = s
        return s

    def get(self, path):
        return self.session().get(
            urljoin(self.base, path),
            timeout=self.args.timeout,
            allow_redirects=self.args.follow,
        )

    # -- calibration ---------------------------------------------------
    def calibrate(self):
        """Probe random paths to learn what 'not found' looks like here."""
        rnd = lambda: "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        probes = [rnd(), rnd() + "/", rnd() + ".php"]
        first_err = None
        for p in probes:
            try:
                r = self.get(p)
            except requests.RequestException:
                continue
            self.baselines.append((r.status_code, len(r.content)))
            first_err = first_err or r
        return first_err

    def is_soft_404(self, status, length):
        for b_status, b_len in self.baselines:
            tol = max(10, int(b_len * 0.03))
            if status == b_status and abs(length - b_len) <= tol:
                return True
        return False

    # -- main work -----------------------------------------------------
    def probe(self, path):
        if self.args.delay:
            time.sleep(self.args.delay)
        try:
            r = self.get(path)
        except requests.RequestException:
            with self.lock:
                self.errors += 1
            return None
        finally:
            with self.lock:
                self.done += 1
        length = len(r.content)
        if r.status_code not in self.args.include:
            return None
        if self.args.hide_length and length in self.args.hide_length:
            return None
        if not self.args.no_wildcard_filter and self.is_soft_404(r.status_code, length):
            return None
        return {
            "path": "/" + path,
            "status": r.status_code,
            "length": length,
            "redirect": r.headers.get("Location"),
            "content_type": r.headers.get("Content-Type", "").split(";")[0],
        }

    def paths(self, words):
        exts = [e.strip().lstrip(".") for e in (self.args.extensions or "").split(",") if e.strip()]
        for w in words:
            w = w.strip().lstrip("/")
            if not w or w.startswith("#"):
                continue
            yield w
            if self.args.dirs:
                yield w + "/"
            for e in exts:
                yield f"{w}.{e}"

    def progress(self):
        if self.args.quiet or not sys.stderr.isatty():
            return
        pct = 100 * self.done / max(self.total, 1)
        sys.stderr.write(f"\r  [{self.done}/{self.total}] {pct:5.1f}%  errors={self.errors}   ")
        sys.stderr.flush()

    def run(self, words):
        todo = list(dict.fromkeys(self.paths(words)))
        self.total = len(todo)
        with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            futures = [ex.submit(self.probe, p) for p in todo]
            try:
                for i, f in enumerate(as_completed(futures), 1):
                    res = f.result()
                    if res:
                        self.results.append(res)
                        self.show(res)
                    if i % 25 == 0:
                        self.progress()
            except KeyboardInterrupt:
                sys.stderr.write("\n[!] Interrupted, cancelling...\n")
                for f in futures:
                    f.cancel()
        self.progress()
        if sys.stderr.isatty():
            sys.stderr.write("\n")
        self.results.sort(key=lambda r: r["path"])

    def show(self, r):
        color = {2: "\033[32m", 3: "\033[36m", 4: "\033[33m", 5: "\033[31m"}.get(r["status"] // 100, "")
        reset = "\033[0m" if color and sys.stdout.isatty() else ""
        color = color if sys.stdout.isatty() else ""
        extra = f" -> {r['redirect']}" if r["redirect"] else ""
        with self.lock:
            if sys.stderr.isatty():
                sys.stderr.write("\r" + " " * 60 + "\r")
            print(f"{color}{r['status']}{reset}  {r['length']:>8}  {r['path']}{extra}", flush=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_codes(s):
    return {int(c) for c in s.split(",") if c.strip()}


def main():
    ap = argparse.ArgumentParser(description="Lightweight directory/endpoint enumerator",
                                 epilog="Use only on systems you are authorized to test.")
    ap.add_argument("url", help="Target base URL, e.g. https://example.test")
    ap.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    ap.add_argument("-x", "--extensions", help="Comma-separated extensions to try (php,html,bak)")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("-s", "--include", type=parse_codes, default=DEFAULT_STATUS,
                    help="Status codes to show (default: %s)" % ",".join(map(str, sorted(DEFAULT_STATUS))))
    ap.add_argument("-e", "--exclude", type=parse_codes, default=set(),
                    help="Status codes to hide (applied after --include)")
    ap.add_argument("--hide-length", type=lambda s: {int(x) for x in s.split(",")},
                    help="Hide responses with these body sizes")
    ap.add_argument("--dirs", action="store_true", help="Also try each word with a trailing slash")
    ap.add_argument("--follow", action="store_true", help="Follow redirects")
    ap.add_argument("-H", "--header", action="append", help='Custom header, e.g. -H "Cookie: a=b"')
    ap.add_argument("-A", "--user-agent", default="dirscan/1.0")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--delay", type=float, default=0.0, help="Per-request delay in seconds (per thread)")
    ap.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--no-wildcard-filter", action="store_true", help="Disable soft-404 filtering")
    ap.add_argument("--no-fingerprint", action="store_true")
    ap.add_argument("-o", "--output", help="Write JSON results to this file")
    ap.add_argument("-q", "--quiet", action="store_true", help="No progress/banner output")
    args = ap.parse_args()

    args.include = args.include - args.exclude
    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url

    try:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            words = f.read().splitlines()
    except OSError as e:
        sys.exit(f"Cannot read wordlist: {e}")

    sc = Scanner(args)
    if not args.quiet:
        print(f"[*] Target:   {args.url}\n[*] Threads:  {args.threads}\n"
              f"[*] Status:   {','.join(map(str, sorted(args.include)))}", file=sys.stderr)

    # Calibration + fingerprint
    err_resp = sc.calibrate()
    if not sc.baselines:
        sys.exit("[!] Target unreachable (no response to calibration requests).")
    home = None
    try:
        home = sc.get("")
    except requests.RequestException:
        pass

    fp = None
    if not args.no_fingerprint:
        fp = fingerprint(home, err_resp)
        if not args.quiet:
            print("\n[+] Fingerprint", file=sys.stderr)
            for k, v in fp["headers"].items():
                print(f"    {k}: {v}", file=sys.stderr)
            if fp.get("title"):
                print(f"    Title: {fp['title']}", file=sys.stderr)
            if fp["technologies"]:
                print("    Technologies: " + "; ".join(fp["technologies"]), file=sys.stderr)
            if fp["error_page"]:
                e = fp["error_page"]
                print(f"    404 behaviour: HTTP {e['status']}, {e['length']} bytes", file=sys.stderr)
            if fp["missing_security_headers"]:
                print("    Missing security headers: " + ", ".join(fp["missing_security_headers"]),
                      file=sys.stderr)
            if len({b[0] for b in sc.baselines}) == 1 and sc.baselines[0][0] != 404:
                print(f"    [!] Server returns HTTP {sc.baselines[0][0]} for unknown paths "
                      "(wildcard/soft-404) - filtering by size.", file=sys.stderr)
            print("\n[+] Results", file=sys.stderr)

    start = time.time()
    sc.run(words)
    elapsed = time.time() - start

    if not args.quiet:
        print(f"\n[*] {len(sc.results)} hits from {sc.total} requests in {elapsed:.1f}s "
              f"({sc.total / max(elapsed, 0.001):.0f} req/s), {sc.errors} errors", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"target": args.url, "fingerprint": fp, "results": sc.results}, f, indent=2)
        if not args.quiet:
            print(f"[*] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
