import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import subenum as S

CRT = [
    {"name_value": "acme.test\n*.acme.test", "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "not_before": "2024-03-01T00:00:00"},
    {"name_value": "www.acme.test\nadmin.acme.test", "issuer_name": "O=Let's Encrypt", "not_before": "2023-01-10T00:00:00"},
    {"name_value": "old-blog.acme.test", "issuer_name": "O=Let's Encrypt", "not_before": "2021-02-02T00:00:00"},
    {"name_value": "evil.example.org\nuser@acme.test\nnotacme.test", "issuer_name": "", "not_before": "2020-01-01T00:00:00"},
]
DNS = {
    "acme.test": dict(status="resolved", ips=["203.0.113.10"], cnames=[]),
    "www.acme.test": dict(status="resolved", ips=["203.0.113.10"], cnames=[]),
    "admin.acme.test": dict(status="resolved", ips=["203.0.113.22"], cnames=[]),
    "old-blog.acme.test": dict(status="dangling", ips=[], cnames=["acmeblog.ghost.io"]),
    "dev.acme.test": dict(status="resolved", ips=["203.0.113.30"], cnames=[]),
    "mail.acme.test": dict(status="resolved", ips=["192.0.2.99"], cnames=[]),  # wildcard IP
}


def fake_resolve(name):
    if name in DNS:
        return dict(DNS[name])
    label = name.split(".")[0]
    if len(label) == 16:  # random wildcard probe
        return dict(status="resolved", ips=["192.0.2.99"], cnames=[])
    return dict(status="nxdomain", ips=[], cnames=[])


def test_parse_crtsh_filters_and_dates():
    parsed = S.parse_crtsh(CRT, "acme.test")
    assert set(parsed) == {"acme.test", "www.acme.test", "admin.acme.test", "old-blog.acme.test"}
    assert parsed["admin.acme.test"]["first_seen"] == "2023-01-10"


def test_pipeline(monkeypatch):
    monkeypatch.setattr(S, "resolve_host", fake_resolve)
    monkeypatch.setattr(S, "fetch_crtsh", lambda d, **k: S.parse_crtsh(CRT, d))
    monkeypatch.setattr(S, "root_records", lambda d: {"NS": [], "MX": [], "TXT": []})
    data = S.enumerate_domain("acme.test", ["dev", "mail", "zzz"], threads=4, quiet=True)
    hosts = {h["host"]: h for h in data["hosts"]}
    assert "mail.acme.test" not in hosts          # wildcard false positive dropped
    assert "zzz.acme.test" not in hosts           # NXDOMAIN brute hit dropped
    assert "dev.acme.test" in hosts
    assert "Ghost" in hosts["old-blog.acme.test"]["takeover"]
    assert "admin interface" in hosts["admin.acme.test"]["tags"]


def test_report_renders(monkeypatch):
    monkeypatch.setattr(S, "resolve_host", fake_resolve)
    monkeypatch.setattr(S, "fetch_crtsh", lambda d, **k: S.parse_crtsh(CRT, d))
    monkeypatch.setattr(S, "root_records", lambda d: {"NS": [], "MX": [], "TXT": []})
    page = S.render_html(S.enumerate_domain("acme.test", None, threads=4, quiet=True))
    assert "<svg" in page and "old-blog.acme.test" in page


def _wild_resolver(pool, cname=None, real=None):
    """Wildcard that rotates through `pool`; `real` hosts have their own address."""
    import itertools
    rot = itertools.cycle(pool)
    real = real or {}

    def resolve(name):
        if name in real:
            return dict(real[name])
        if name.endswith(".acme.test") and name != "acme.test":
            ip = [next(rot)]
            return dict(status="resolved", ips=ip, cnames=[cname] if cname else [])
        return dict(status="resolved", ips=[pool[0]], cnames=[])
    return resolve


def test_rotating_ip_wildcard_is_filtered(monkeypatch):
    pool = ["198.51.100.%d" % i for i in range(1, 7)]  # bigger than any single answer
    monkeypatch.setattr(S, "resolve_host", _wild_resolver(
        pool, real={"real.acme.test": dict(status="resolved", ips=["203.0.113.5"], cnames=[])}))
    monkeypatch.setattr(S, "root_records", lambda d: {"NS": [], "MX": [], "TXT": []})
    data = S.enumerate_domain("acme.test", ["admin", "vpn", "real", "x1", "x2"], use_crt=False, threads=1, quiet=True)
    assert {h["host"] for h in data["hosts"]} == {"acme.test", "real.acme.test"}


def test_cname_wildcard_is_filtered(monkeypatch):
    monkeypatch.setattr(S, "resolve_host", _wild_resolver(
        ["198.51.100.1", "198.51.100.2"], cname="lb-123.elb.example.net",
        real={"real.acme.test": dict(status="resolved", ips=["203.0.113.5"], cnames=["other.host.net"])}))
    monkeypatch.setattr(S, "root_records", lambda d: {"NS": [], "MX": [], "TXT": []})
    data = S.enumerate_domain("acme.test", ["admin", "vpn", "real"], use_crt=False, threads=1, quiet=True)
    assert {h["host"] for h in data["hosts"]} == {"acme.test", "real.acme.test"}
    assert data["wildcard_cnames"] == ["lb-123.elb.example.net"]


def _page(status=200, title="Welcome", length=500, loc=""):
    return {"scheme": "https", "status": status, "length": length, "title": title,
            "server": "", "location": loc, "loc_sig": loc}


def test_http_probe_separates_real_hosts_from_wildcard(monkeypatch):
    pool = ["198.51.100.%d" % i for i in range(1, 7)]
    monkeypatch.setattr(S, "resolve_host", _wild_resolver(pool))
    monkeypatch.setattr(S, "root_records", lambda d: {"NS": [], "MX": [], "TXT": []})

    def fake_probe(host, timeout=6.0):
        if host == "app.acme.test":
            return _page(200, "Acme App", 8000)            # real vhost, own content
        if host == "gone.acme.test":
            return None                                    # nothing listens
        return _page(404, "Not Found", 500)                # wildcard catch-all page
    monkeypatch.setattr(S, "probe_http", fake_probe)

    data = S.enumerate_domain("acme.test", ["app", "admin", "vpn", "gone"], use_crt=False,
                              threads=1, quiet=True, probe=True)
    hosts = {h["host"]: h for h in data["hosts"]}
    assert set(hosts) == {"acme.test", "app.acme.test"}
    assert hosts["app.acme.test"]["http"]["status"] == 200
    assert data["probed"] is True


def test_same_page_tolerates_small_size_jitter():
    assert S.same_page(_page(404, "x", 1000), _page(404, "x", 1020))
    assert not S.same_page(_page(404, "x", 1000), _page(200, "x", 1000))
    assert not S.same_page(_page(200, "A", 1000), _page(200, "B", 1000))
