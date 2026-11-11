#!/usr/bin/env python3
"""
subenum - subdomain enumeration and attack-surface mapper.

Sources
  * Certificate Transparency logs via crt.sh
  * Optional DNS brute force from a wordlist
Then, for every candidate:
  * Resolve A / AAAA / CNAME (dnspython if installed, stdlib fallback)
  * Detect wildcard DNS and drop brute-force false positives
  * Flag dangling CNAMEs pointing at third-party services (takeover candidates)
  * Tag high-interest names (admin, staging, vpn, jenkins, ...)
Output
  * JSON data file and a self-contained HTML report with a radial map

Only enumerate domains you own or are authorised to assess. Everything used
here is passive/public data or ordinary DNS lookups.

Examples
  python subenum.py example.com
  python subenum.py example.com -w wordlists/subdomains.txt -t 50 -o example
"""
import argparse
import html
import json
import math
import random
import socket
import string
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

try:
    import dns.exception
    import dns.resolver
    HAVE_DNS = True
except ImportError:  # fall back to the OS resolver
    HAVE_DNS = False

# Third-party services where a dangling CNAME can often be claimed by an attacker.
TAKEOVER_SUFFIXES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Service",
    "trafficmanager.net": "Azure Traffic Manager", "blob.core.windows.net": "Azure Blob",
    "s3.amazonaws.com": "AWS S3", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "cloudfront.net": "AWS CloudFront", "fastly.net": "Fastly", "netlify.app": "Netlify",
    "pantheonsite.io": "Pantheon", "readme.io": "Readme", "ghost.io": "Ghost",
    "surge.sh": "Surge", "bitbucket.io": "Bitbucket", "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage", "helpscoutdocs.com": "Help Scout",
    "myshopify.com": "Shopify", "unbouncepages.com": "Unbounce", "wordpress.com": "WordPress.com",
}

# Substrings in a hostname that deserve a closer look.
INTERESTING = {
    "admin": "admin interface", "login": "auth", "sso": "auth", "auth": "auth",
    "vpn": "remote access", "rdp": "remote access", "ssh": "remote access",
    "dev": "non-production", "test": "non-production", "stage": "non-production",
    "staging": "non-production", "qa": "non-production", "uat": "non-production",
    "sandbox": "non-production", "beta": "non-production", "internal": "internal",
    "intranet": "internal", "corp": "internal", "jenkins": "CI/CD", "ci": "CI/CD",
    "gitlab": "source control", "git": "source control", "jira": "internal tooling",
    "grafana": "monitoring", "kibana": "monitoring", "prometheus": "monitoring",
    "db": "database", "sql": "database", "mongo": "database", "redis": "database",
    "backup": "backup", "old": "legacy", "legacy": "legacy", "api": "API",
}


# --------------------------------------------------------------------------
# Passive source: crt.sh
# --------------------------------------------------------------------------

def fetch_crtsh(domain, timeout=60, retries=3):
    """Return {hostname: {"first_seen": str, "issuers": set}} from CT logs."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, params=params, timeout=timeout,
                             headers={"User-Agent": "subenum/1.0"})
            if r.status_code == 200:
                return parse_crtsh(r.json(), domain)
            last_err = f"HTTP {r.status_code}"
        except (requests.RequestException, ValueError) as e:
            last_err = str(e)
        time.sleep(2 * attempt)  # crt.sh is often overloaded; back off
    print(f"[!] crt.sh failed after {retries} attempts ({last_err})", file=sys.stderr)
    return {}


def parse_crtsh(entries, domain):
    found = {}
    for e in entries:
        issuer = (e.get("issuer_name") or "").split("O=")[-1].split(",")[0].strip('" ')
        seen = (e.get("not_before") or "")[:10]
        for name in (e.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if not name or " " in name or "@" in name:
                continue
            if name != domain and not name.endswith("." + domain):
                continue
            rec = found.setdefault(name, {"first_seen": seen, "issuers": set()})
            if seen and (not rec["first_seen"] or seen < rec["first_seen"]):
                rec["first_seen"] = seen
            if issuer:
                rec["issuers"].add(issuer)
    return found


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

_resolver = None


def get_resolver(nameservers=None, timeout=4.0):
    global _resolver
    if HAVE_DNS and _resolver is None:
        _resolver = dns.resolver.Resolver()
        _resolver.lifetime = timeout
        _resolver.timeout = timeout
        if nameservers:
            _resolver.nameservers = nameservers
    return _resolver


def resolve_host(name):
    """Resolve a name. Returns dict(status, ips, cnames)."""
    out = {"status": "unresolved", "ips": [], "cnames": []}
    if not HAVE_DNS:
        try:
            canon, aliases, ips = socket.gethostbyname_ex(name)
            out.update(status="resolved", ips=sorted(set(ips)),
                       cnames=[a for a in aliases] + ([canon] if canon != name else []))
        except socket.gaierror:
            out["status"] = "nxdomain"
        return out

    res = get_resolver()
    current = name
    # Walk the CNAME chain manually so we can see where it ends.
    for _ in range(8):
        try:
            ans = res.resolve(current, "CNAME")
            current = str(ans[0].target).rstrip(".").lower()
            out["cnames"].append(current)
        except dns.resolver.NXDOMAIN:
            out["status"] = "dangling" if out["cnames"] else "nxdomain"
            return out
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            break
        except dns.exception.DNSException:
            break

    for rtype in ("A", "AAAA"):
        try:
            ans = res.resolve(current, rtype)
            out["ips"].extend(str(r) for r in ans)
        except dns.resolver.NXDOMAIN:
            out["status"] = "dangling" if out["cnames"] else "nxdomain"
            return out
        except dns.exception.DNSException:
            pass
    out["ips"] = sorted(set(out["ips"]))
    if out["ips"]:
        out["status"] = "resolved"
    elif out["cnames"]:
        out["status"] = "no-address"
    return out


def root_records(domain):
    """NS / MX / TXT for the apex - useful context for the report."""
    rec = {"NS": [], "MX": [], "TXT": []}
    if not HAVE_DNS:
        return rec
    res = get_resolver()
    for rtype in rec:
        try:
            for r in res.resolve(domain, rtype):
                rec[rtype].append(r.to_text().strip('"')[:200])
        except dns.exception.DNSException:
            pass
    return rec


def detect_wildcard(domain):
    ips = set()
    for _ in range(3):
        label = "".join(random.choices(string.ascii_lowercase, k=16))
        r = resolve_host(f"{label}.{domain}")
        if r["status"] == "resolved":
            ips.update(r["ips"])
    return ips


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def takeover_hint(rec):
    if rec["status"] != "dangling" or not rec["cnames"]:
        return None
    for target in rec["cnames"]:
        for suffix, provider in TAKEOVER_SUFFIXES.items():
            if target == suffix or target.endswith("." + suffix):
                return f"CNAME to {provider} ({target}) does not resolve - possible takeover; verify manually"
    return f"CNAME target {rec['cnames'][-1]} does not resolve (dangling record)"


def interest_tags(host, domain):
    prefix = host[: -len(domain)].rstrip(".")
    tokens = set()
    for part in prefix.replace("_", ".").split("."):
        tokens.update(t for t in part.replace("-", " ").split() if t)
        tokens.add(part)
    tags = sorted({INTERESTING[t] for t in tokens if t in INTERESTING})
    # digit-suffixed names like dev2 / api3
    for t in list(tokens):
        stem = t.rstrip(string.digits)
        if stem != t and stem in INTERESTING:
            tags.append(INTERESTING[stem])
    return sorted(set(tags))


def group_key(rec):
    """Cluster hosts by where they are hosted: CNAME provider, else IP /24."""
    if rec["cnames"]:
        parts = rec["cnames"][-1].split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else rec["cnames"][-1]
    for ip in rec["ips"]:
        if ":" not in ip:
            return ".".join(ip.split(".")[:3]) + ".0/24"
    if rec["ips"]:
        return ":".join(rec["ips"][0].split(":")[:3]) + "::/48"
    return "unresolved"


def enumerate_domain(domain, wordlist=None, threads=40, use_crt=True, quiet=False):
    log = (lambda *a: None) if quiet else (lambda *a: print(*a, file=sys.stderr))
    hosts = {}  # name -> {"sources": set, "first_seen":..., "issuers": []}

    if use_crt:
        log(f"[*] Querying crt.sh for %.{domain} ...")
        for name, meta in fetch_crtsh(domain).items():
            hosts[name] = {"sources": {"crt.sh"}, "first_seen": meta["first_seen"],
                           "issuers": sorted(meta["issuers"])}
        log(f"    {len(hosts)} unique names from certificate transparency")

    wildcard_ips = set()
    if wordlist:
        wildcard_ips = detect_wildcard(domain)
        if wildcard_ips:
            log(f"[!] Wildcard DNS detected ({', '.join(sorted(wildcard_ips))}); "
                "brute-force hits resolving only there will be dropped")
        for w in wordlist:
            w = w.strip().lower()
            if w and not w.startswith("#"):
                h = f"{w}.{domain}"
                hosts.setdefault(h, {"sources": set(), "first_seen": "", "issuers": []})
                hosts[h]["sources"].add("brute")
    hosts.setdefault(domain, {"sources": {"apex"}, "first_seen": "", "issuers": []})

    log(f"[*] Resolving {len(hosts)} candidates with {threads} threads "
        f"({'dnspython' if HAVE_DNS else 'stdlib resolver'}) ...")
    results, done = [], 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve_host, h): h for h in hosts}
        for f in as_completed(futs):
            h = futs[f]
            rec = f.result()
            meta = hosts[h]
            only_brute = meta["sources"] == {"brute"}
            if only_brute and rec["status"] in ("nxdomain", "unresolved"):
                continue
            if only_brute and wildcard_ips and set(rec["ips"]) <= wildcard_ips and not rec["cnames"]:
                continue
            rec.update(host=h, sources=sorted(meta["sources"]), first_seen=meta["first_seen"],
                       issuers=meta["issuers"], tags=interest_tags(h, domain),
                       takeover=takeover_hint(rec))
            rec["group"] = group_key(rec)
            results.append(rec)
            done += 1
            if not quiet and done % 50 == 0:
                sys.stderr.write(f"\r    {done} kept so far...")
    if not quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")
    results.sort(key=lambda r: (r["group"], r["host"]))
    return {
        "domain": domain,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "resolver": "dnspython" if HAVE_DNS else "stdlib",
        "wildcard_ips": sorted(wildcard_ips),
        "apex_records": root_records(domain),
        "hosts": results,
    }


# --------------------------------------------------------------------------
# HTML report with radial SVG map
# --------------------------------------------------------------------------

def node_class(r):
    if r["takeover"]:
        return "risk"
    if r["status"] != "resolved":
        return "dead"
    if r["tags"]:
        return "hot"
    return "live"


def build_map(data, size=1000):
    domain, hosts = data["domain"], [h for h in data["hosts"] if h["host"] != data["domain"]]
    cx = cy = size / 2
    r_group, r_node, stagger = 190, 330, 26
    groups = defaultdict(list)
    for h in hosts:
        groups[h["group"]].append(h)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    total, gap = len(hosts), 1.6
    denom = total + gap * len(ordered) or 1
    show_labels = total <= 120

    svg = [f'<svg id="map" viewBox="0 0 {size} {size}" role="img" '
           f'aria-label="Attack surface map for {html.escape(domain)}">']
    edges, nodes, labels = [], [], []
    angle = -math.pi / 2
    for gname, members in ordered:
        span = 2 * math.pi * (len(members) + gap) / denom
        mid = angle + span / 2
        # Wide wedges pull their hub toward the centre so it stays near its members.
        hub = max(100, r_group * (1 - 0.6 * span / (2 * math.pi)))
        gx, gy = cx + hub * math.cos(mid), cy + hub * math.sin(mid)
        edges.append(f'<line class="e0" x1="{cx}" y1="{cy}" x2="{gx:.1f}" y2="{gy:.1f}"/>')
        usable = span - 2 * (gap / 2) * 2 * math.pi / denom
        for i, h in enumerate(members):
            a = (mid - usable / 2 + usable * (i + 0.5) / len(members)) if len(members) > 1 else mid
            rad = r_node + (i % 3) * stagger
            x, y = cx + rad * math.cos(a), cy + rad * math.sin(a)
            cls = node_class(h)
            edges.append(f'<line class="e1" x1="{gx:.1f}" y1="{gy:.1f}" x2="{x:.1f}" y2="{y:.1f}"/>')
            tip = f"{h['host']} - {', '.join(h['ips'][:3]) or h['status']}"
            if h["takeover"]:
                tip += f" - {h['takeover']}"
            nodes.append(f'<circle class="n {cls}" data-host="{html.escape(h["host"])}" '
                         f'cx="{x:.1f}" cy="{y:.1f}" r="{5.5 if cls in ("risk", "hot") else 4}">'
                         f'<title>{html.escape(tip)}</title></circle>')
            if show_labels or cls in ("risk", "hot"):
                prefix = h["host"][: -len(domain) - 1]
                prefix = prefix if len(prefix) <= 22 else prefix[:21] + "…"
                deg = math.degrees(a)
                flip = math.cos(a) < 0
                lx, ly = cx + (rad + 11) * math.cos(a), cy + (rad + 11) * math.sin(a)
                rot = deg + 180 if flip else deg
                labels.append(
                    f'<text class="lb {cls}" data-host="{html.escape(h["host"])}" '
                    f'transform="translate({lx:.1f} {ly:.1f}) rotate({rot:.1f})" '
                    f'text-anchor="{"end" if flip else "start"}" dy="0.32em">{html.escape(prefix)}</text>')
        gl = html.escape(gname)
        nodes.append(f'<g class="grp"><rect x="{gx - 5 - 3.3 * len(gname):.1f}" y="{gy - 10:.1f}" '
                     f'width="{10 + 6.6 * len(gname):.1f}" height="20" rx="3"/>'
                     f'<text x="{gx:.1f}" y="{gy:.1f}" text-anchor="middle" dy="0.34em">{gl}</text></g>')
        angle += span
    svg += edges + nodes + labels
    svg.append(f'<circle class="root" cx="{cx}" cy="{cy}" r="62"/>'
               f'<text class="rt" x="{cx}" y="{cy}" text-anchor="middle" dy="0.34em">{html.escape(domain)}</text>')
    svg.append("</svg>")
    return "\n".join(svg)


REPORT_CSS = """
:root{--bg:#f3f1ee;--panel:#fff;--ink:#1c2230;--mute:#6a7283;--line:#d9d5ce;--live:#2f6f8f;
--hot:#c27a00;--risk:#c0392b;--dead:#9aa1ad;--grp:#1c2230;--grpt:#f3f1ee;--edge:#c9c4bb}
@media (prefers-color-scheme:dark){:root{--bg:#12161d;--panel:#1a2029;--ink:#e6e9ef;--mute:#8d96a6;
--line:#2c3441;--live:#5fb0d6;--hot:#e0a033;--risk:#ff6b5b;--dead:#59616f;--grp:#e6e9ef;--grpt:#12161d;--edge:#323b49}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Avenir Next",Avenir,"Segoe UI",system-ui,sans-serif}
header{padding:28px 32px 8px}
h1{margin:0;font:600 26px/1.2 ui-monospace,"IBM Plex Mono",Menlo,Consolas,monospace;letter-spacing:-.01em}
.sub{color:var(--mute);margin-top:4px}
.stats{display:flex;flex-wrap:wrap;gap:10px 28px;padding:14px 32px}
.stats div{min-width:84px}.stats b{display:block;font:600 22px ui-monospace,Menlo,Consolas,monospace}
.stats span{color:var(--mute);font-size:13px}
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px;padding:8px 32px 40px}
@media (max-width:1000px){main{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
#map{width:100%;height:auto;display:block}
.e0{stroke:var(--edge);stroke-width:1.4}.e1{stroke:var(--edge);stroke-width:.7}
.n{stroke:var(--panel);stroke-width:1.5;cursor:pointer;transition:r .12s}
.n.live{fill:var(--live)}.n.hot{fill:var(--hot)}.n.risk{fill:var(--risk)}.n.dead{fill:var(--dead)}
.n.sel{stroke:var(--ink);stroke-width:2.5}
.lb{font:9.5px ui-monospace,Menlo,Consolas,monospace;fill:var(--mute)}
.lb.hot{fill:var(--hot)}.lb.risk{fill:var(--risk);font-weight:700}.lb.sel{fill:var(--ink);font-weight:700}
.grp rect{fill:var(--grp)}.grp text{fill:var(--grpt);font:600 10.5px ui-monospace,Menlo,Consolas,monospace}
.root{fill:var(--grp)}.rt{fill:var(--grpt);font:600 12px ui-monospace,Menlo,Consolas,monospace}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;padding:10px 4px 2px;color:var(--mute);font-size:13px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.tools{display:flex;gap:10px;margin-bottom:10px}
input[type=search]{flex:1;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
.tbl{max-height:760px;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{position:sticky;top:0;background:var(--panel);text-align:left;color:var(--mute);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
td.nw{white-space:nowrap}td.h{font-family:ui-monospace,Menlo,Consolas,monospace}
tr.sel td{background:color-mix(in srgb,var(--hot) 14%,transparent)}
.pill{display:inline-block;white-space:nowrap;padding:0 7px;border-radius:9px;font-size:11.5px;border:1px solid var(--line);margin:0 4px 2px 0;color:var(--mute)}
.pill.risk{color:var(--risk);border-color:var(--risk)}
.note{color:var(--risk);font-size:12.5px;margin-top:2px}
section.apex{padding:0 32px 32px;color:var(--mute);font-size:13px}
section.apex code{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--ink)}
"""

REPORT_JS = """
const rows=[...document.querySelectorAll('#t tbody tr')];
const els=h=>document.querySelectorAll('[data-host="'+CSS.escape(h)+'"]');
function select(h,scroll){document.querySelectorAll('.sel').forEach(e=>e.classList.remove('sel'));
 els(h).forEach(e=>e.classList.add('sel'));if(scroll){const r=document.querySelector('tr[data-host="'+CSS.escape(h)+'"]');
 if(r)r.scrollIntoView({block:'center'})}}
document.querySelectorAll('circle.n').forEach(c=>c.addEventListener('click',()=>select(c.dataset.host,true)));
rows.forEach(r=>r.addEventListener('click',()=>select(r.dataset.host,false)));
document.getElementById('q').addEventListener('input',e=>{const v=e.target.value.toLowerCase();
 rows.forEach(r=>r.style.display=r.textContent.toLowerCase().includes(v)?'':'none')});
"""


def render_html(data):
    hosts = data["hosts"]
    n_live = sum(1 for h in hosts if h["status"] == "resolved")
    n_hot = sum(1 for h in hosts if h["tags"])
    n_risk = sum(1 for h in hosts if h["takeover"])
    n_groups = len({h["group"] for h in hosts})
    n_ips = len({ip for h in hosts for ip in h["ips"]})

    rows = []
    for h in hosts:
        pills = "".join(f'<span class="pill">{html.escape(t)}</span>' for t in h["tags"])
        if h["takeover"]:
            pills += '<span class="pill risk">dangling CNAME</span>'
        chain = " → ".join(h["cnames"]) if h["cnames"] else ""
        note = f'<div class="note">{html.escape(h["takeover"])}</div>' if h["takeover"] else ""
        rows.append(
            f'<tr data-host="{html.escape(h["host"])}"><td class="h">{html.escape(h["host"])}{note}</td>'
            f'<td class="nw">{html.escape(h["status"])}</td>'
            f'<td class="h nw">{html.escape(", ".join(h["ips"][:2]) or "-")}'
            f'{"<br>" + html.escape(chain) if chain else ""}</td>'
            f'<td>{pills}</td><td>{html.escape(", ".join(h["sources"]))}'
            f'{"<br>" + html.escape(h["first_seen"]) if h["first_seen"] else ""}</td></tr>')

    apex = data["apex_records"]
    apex_html = "".join(f'<div>{k}: <code>{html.escape("  |  ".join(v))}</code></div>'
                        for k, v in apex.items() if v)
    if data["wildcard_ips"]:
        apex_html += f'<div>Wildcard DNS: <code>{html.escape(", ".join(data["wildcard_ips"]))}</code></div>'

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack surface - {html.escape(data["domain"])}</title><style>{REPORT_CSS}</style></head><body>
<header><h1>{html.escape(data["domain"])}</h1>
<div class="sub">Subdomain attack surface · generated {html.escape(data["generated"])} · resolver: {data["resolver"]}</div></header>
<div class="stats">
<div><b>{len(hosts)}</b><span>hostnames</span></div><div><b>{n_live}</b><span>resolving</span></div>
<div><b>{n_ips}</b><span>unique IPs</span></div><div><b>{n_groups}</b><span>hosting groups</span></div>
<div><b>{n_hot}</b><span>high-interest</span></div><div><b>{n_risk}</b><span>dangling CNAME</span></div></div>
<main>
<div class="card">{build_map(data)}
<div class="legend"><span><i style="background:var(--live)"></i>resolving</span>
<span><i style="background:var(--hot)"></i>high-interest name</span>
<span><i style="background:var(--risk)"></i>dangling CNAME</span>
<span><i style="background:var(--dead)"></i>not resolving</span>
<span>Inner boxes: hosting group (CNAME provider or IP block)</span></div></div>
<div class="card"><div class="tools"><input id="q" type="search" placeholder="Filter hostnames, IPs, tags..."></div>
<div class="tbl"><table id="t"><thead><tr><th>Host</th><th>DNS</th><th>Address / CNAME</th><th>Tags</th><th>Source</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div></div></main>
<section class="apex">{apex_html}</section>
<script>{REPORT_JS}</script></body></html>"""
    return page


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Subdomain enumeration & attack surface mapper",
                                 epilog="Use only on domains you are authorised to assess.")
    ap.add_argument("domain", help="Target domain, e.g. example.com")
    ap.add_argument("-w", "--wordlist", help="Optional wordlist for DNS brute force")
    ap.add_argument("-t", "--threads", type=int, default=40)
    ap.add_argument("-r", "--resolver", action="append",
                    help="Custom DNS resolver IP (repeatable, requires dnspython)")
    ap.add_argument("--timeout", type=float, default=4.0, help="DNS timeout in seconds")
    ap.add_argument("--no-crt", action="store_true", help="Skip crt.sh")
    ap.add_argument("-o", "--output", help="Output prefix (writes PREFIX.json and PREFIX.html)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    domain = args.domain.lower().strip().rstrip(".")
    words = None
    if args.wordlist:
        try:
            words = open(args.wordlist, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError as e:
            sys.exit(f"Cannot read wordlist: {e}")
    if args.no_crt and not words:
        sys.exit("Nothing to do: --no-crt without a wordlist.")
    if not HAVE_DNS and not args.quiet:
        print("[!] dnspython not installed - using OS resolver (no CNAME-chain/dangling "
              "detection). pip install dnspython", file=sys.stderr)
    get_resolver(args.resolver, args.timeout)

    data = enumerate_domain(domain, words, args.threads, not args.no_crt, args.quiet)

    for h in data["hosts"]:
        flag = "!" if h["takeover"] else ("*" if h["tags"] else " ")
        addr = ", ".join(h["ips"][:2]) or h["status"]
        print(f"{flag} {h['host']:<45} {addr}")
    if not args.quiet:
        print(f"\n[*] {len(data['hosts'])} hosts ({sum(1 for h in data['hosts'] if h['takeover'])} "
              "dangling CNAMEs)", file=sys.stderr)

    prefix = args.output or domain.replace(".", "_")
    with open(prefix + ".json", "w") as f:
        json.dump(data, f, indent=2)
    with open(prefix + ".html", "w", encoding="utf-8") as f:
        f.write(render_html(data))
    if not args.quiet:
        print(f"[*] Wrote {prefix}.json and {prefix}.html", file=sys.stderr)


if __name__ == "__main__":
    main()
