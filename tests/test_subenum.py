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
