"""Proxy correctness checks: forwarded headers, Set-Cookie rewriting and the
timeout split of the /proxy/{id} reverse proxy.

Part 1 tests the pure helpers. Part 2 runs the real http_proxy_connection
handler against a local echo upstream on 127.0.0.1. User connections may not
target loopback (the outbound host policy), so this test, and only this test,
replaces the policy connector and the resolve checks with plain ones; the
policy itself is covered by tests/test_host_check.py and the ssrf smoke module.

Run:  venv/bin/python tests/test_proxyfix.py        (takes about 70 s)
"""

import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import host_check  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


SESSION = Config.SESSION_COOKIE_NAME

# ---------------------------------------------------------------------------
# Part 1: helpers
# ---------------------------------------------------------------------------

P = "/proxy/abc"

# timeout clamp
for given, want in [(None, 60), (60, 60), (1, 5), (0, 5), (-9, 5), (5, 5), (300, 300), (301, 300),
                    (99999, 300), ("30", 30), ("junk", 60), (True, 60), (12.9, 12),
                    (float("nan"), 60), (float("inf"), 60), ([], 60)]:
    check(f"timeout {given!r} -> {want}", server._proxy_timeout_seconds(given) == want,
          str(server._proxy_timeout_seconds(given)))
t = server._proxy_client_timeout({"timeout": 45})
check("client timeout: no total limit", t.total is None, str(t))
check("client timeout: connect is 10", t.connect == 10, str(t))
check("client timeout: sock_read is the setting", t.sock_read == 45, str(t))
check("client timeout: setting is clamped", server._proxy_client_timeout({"timeout": 5000}).sock_read == 300)

# Set-Cookie rewriting
rw = server._rewrite_set_cookie
check("cookie: Path=/ goes under the prefix", rw("a=1; Path=/; HttpOnly", P) == "a=1; HttpOnly; Path=/proxy/abc/",
      rw("a=1; Path=/; HttpOnly", P))
check("cookie: non-root Path is prefixed", rw("a=1; Path=/app", P) == "a=1; Path=/proxy/abc/app", rw("a=1; Path=/app", P))
check("cookie: missing Path becomes the prefix root", rw("a=1; Secure", P) == "a=1; Secure; Path=/proxy/abc/",
      rw("a=1; Secure", P))
check("cookie: Domain is dropped", rw("a=1; Domain=upstream.example; Path=/", P) == "a=1; Path=/proxy/abc/",
      rw("a=1; Domain=upstream.example; Path=/", P))
check("cookie: Domain with leading dot and odd case is dropped",
      "omain" not in rw("a=1; DOMAIN=.example.com; path=/x; SameSite=Lax", P)
      and rw("a=1; DOMAIN=.example.com; path=/x; SameSite=Lax", P) == "a=1; SameSite=Lax; Path=/proxy/abc/x",
      rw("a=1; DOMAIN=.example.com; path=/x; SameSite=Lax", P))
check("cookie: a value that looks like a Path attribute is left alone",
      rw("redir=path=/evil; Path=/", P) == "redir=path=/evil; Path=/proxy/abc/", rw("redir=path=/evil; Path=/", P))
check("cookie: Expires (with a comma) and Max-Age are kept",
      rw("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60; Path=/", P)
      == "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60; Path=/proxy/abc/")
check("cookie: invalid (relative) Path is treated as missing", rw("a=1; Path=app", P) == "a=1; Path=/proxy/abc/")
check("cookie: a Path already under the prefix is not prefixed twice",
      rw("a=1; Path=/proxy/abc/", P) == "a=1; Path=/proxy/abc/" and rw("a=1; Path=/proxy/abc/x", P) == "a=1; Path=/proxy/abc/x")
check("cookie: a cookie named like the portal session is dropped", rw(f"{SESSION}=evil; Path=/", P) is None)
check("cookie: a cookie that only contains the session name is kept", rw(f"x{SESSION}=1; Path=/", P) is not None)


class FakeTransport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, name, default=None):
        return (self.peer, 1234) if name == "peername" else default


class FakeRequest:
    def __init__(self, peer="203.0.113.50", headers=None, secure=False, host="portal.example"):
        self.transport = FakeTransport(peer)
        self.headers = headers
        self.secure = secure
        self.host = host


from multidict import CIMultiDict  # noqa: E402


def req(peer="203.0.113.50", headers=None, secure=False, host="portal.example"):
    r = FakeRequest(peer, None, secure, host)
    r.headers = CIMultiDict(headers or [])
    return r


def set_trusted(*nets):
    import ipaddress
    server._trusted_proxy_networks[:] = [ipaddress.ip_network(n) for n in nets]
    server._trusted_peer_cache.clear()


saved_nets = list(server._trusted_proxy_networks)
saved_hostname = Config.HOSTNAME
Config.HOSTNAME = "portal.example"
try:
    set_trusted("198.51.100.0/24")
    # untrusted peer: nothing it says about the scheme counts
    check("scheme: untrusted peer, plain connection -> http",
          server._proxy_forwarded_scheme(req(headers=[("X-Forwarded-Proto", "https")])) == "http")
    check("scheme: untrusted peer, TLS connection -> https",
          server._proxy_forwarded_scheme(req(secure=True, headers=[("X-Forwarded-Proto", "http")])) == "https")
    check("scheme: untrusted peer cannot claim https via CF-Visitor",
          server._proxy_forwarded_scheme(req(headers=[("CF-Visitor", '{"scheme":"https"}')])) == "http")
    # trusted peer
    check("scheme: trusted peer X-Forwarded-Proto https",
          server._proxy_forwarded_scheme(req("198.51.100.7", [("X-Forwarded-Proto", "https")])) == "https")
    check("scheme: trusted peer X-Forwarded-Proto http overrides a TLS leg",
          server._proxy_forwarded_scheme(req("198.51.100.7", [("X-Forwarded-Proto", "http")], secure=True)) == "http")
    check("scheme: trusted peer CF-Visitor",
          server._proxy_forwarded_scheme(req("198.51.100.7", [("CF-Visitor", '{"scheme":"https"}')])) == "https")
    check("scheme: trusted peer, last X-Forwarded-Proto hop wins",
          server._proxy_forwarded_scheme(req("198.51.100.7", [("X-Forwarded-Proto", "http, https")])) == "https")
    check("scheme: trusted peer with garbage falls back to the connection",
          server._proxy_forwarded_scheme(req("198.51.100.7", [("X-Forwarded-Proto", "gopher"), ("CF-Visitor", "{")])) == "http")

    # header builder
    cfg = {}
    h = server._proxy_request_headers(req(headers=[
        ("X-Forwarded-For", "6.6.6.6"), ("x-real-ip", "6.6.6.6"), ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Prefix", "/evil"), ("X-Forwarded-Port", "1"), ("Forwarded", "for=6.6.6.6"),
        ("X-Forwarded-Proto", "https"), ("Authorization", "Bearer secret"),
        ("Cookie", f"a=1; {SESSION}=SECRETSESSION; b=2")]), cfg, "up.example:8080", P, False)
    check("headers: default config forwards no client header at all",
          not any(k.lower() in ("authorization", "forwarded") or k.lower().startswith("x-")
                  and k.lower() not in ("x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
                                        "x-forwarded-prefix", "x-real-ip") for k in h), str(dict(h)))
    check("headers: X-Forwarded-For is the peer address (untrusted peer)", h.getall("X-Forwarded-For") == ["203.0.113.50"], str(dict(h)))
    check("headers: X-Real-IP is the peer address", h.getall("X-Real-IP") == ["203.0.113.50"])
    check("headers: X-Forwarded-Host and X-Forwarded-Prefix are not sent by default (client copies dropped too)",
          "X-Forwarded-Host" not in h and "X-Forwarded-Prefix" not in h and "evil" not in json.dumps(list(h.items())), str(dict(h)))
    for off in ({"forwarded_host": False}, {"forwarded_host": "true"}, {"forwarded_host": 1}, {"forwarded_host": None}):
        ho = server._proxy_request_headers(req(), off, "up.example:8080", P, False)
        check(f"headers: forwarded_host={off['forwarded_host']!r} is not the boolean true, so neither is sent",
              "X-Forwarded-Host" not in ho and "X-Forwarded-Prefix" not in ho, str(dict(ho)))
    check("headers: X-Forwarded-Proto, X-Forwarded-For and X-Real-IP are always sent",
          h.getall("X-Forwarded-Proto") == ["http"] and h.getall("X-Forwarded-For") == ["203.0.113.50"]
          and h.getall("X-Real-IP") == ["203.0.113.50"])
    on = server._proxy_request_headers(req(headers=[("X-Forwarded-Host", "evil.example"), ("X-Forwarded-Prefix", "/evil")]),
                                       {"forwarded_host": True}, "up.example:8080", P, False)
    check("headers: forwarded_host on sends X-Forwarded-Host, the portal host", on.getall("X-Forwarded-Host") == ["portal.example"], str(dict(on)))
    check("headers: forwarded_host on sends X-Forwarded-Prefix, the proxy path", on.getall("X-Forwarded-Prefix") == [P])
    check("headers: forwarded_host on still sends the other forwarding headers once",
          on.getall("X-Forwarded-For") == ["203.0.113.50"] and on.getall("X-Real-IP") == ["203.0.113.50"]
          and on.getall("X-Forwarded-Proto") == ["http"])
    hb = server._proxy_request_headers(req(), {"forwarded_host": True}, "example.com", P + "/https://example.com", True)
    check("headers: forwarded_host on does not change browser mode (scheme only)",
          "X-Forwarded-Host" not in hb and "X-Forwarded-Prefix" not in hb and "X-Forwarded-For" not in hb, str(dict(hb)))
    check("headers: X-Forwarded-Proto comes from the connection", h.getall("X-Forwarded-Proto") == ["http"])
    check("headers: Host is the upstream", h.getall("Host") == ["up.example:8080"])
    check("headers: session cookie is stripped from Cookie, others kept",
          h.getall("Cookie") == ["a=1; b=2"], str(h.getall("Cookie", [])))

    # a pattern that matches everything still cannot pass any of them
    cfg = {"forward_headers": ["*"], "forwarded_host": True}
    h = server._proxy_request_headers(req(headers=[
        ("X-Forwarded-For", "6.6.6.6"), ("X-REAL-IP", "6.6.6.6"), ("x-forwarded-host", "evil.example"),
        ("X-Forwarded-Prefix", "/evil"), ("X-Forwarded-Server", "evil"), ("Forwarded", "for=6.6.6.6"),
        ("Authorization", "Bearer secret"), ("Cookie", f"a=1; {SESSION}=SECRETSESSION; b=2"),
        ("Cookie", f"c=3; {SESSION}=SECRETSESSION"), ("X-Request-ID", "r1")]), cfg, "up", P, False)
    check("headers: forward_headers=['*'] still replaces X-Forwarded-For", h.getall("X-Forwarded-For") == ["203.0.113.50"], str(dict(h)))
    check("headers: forward_headers=['*'] still replaces X-Real-IP", h.getall("X-Real-IP") == ["203.0.113.50"])
    check("headers: forward_headers=['*'] still replaces X-Forwarded-Host", h.getall("X-Forwarded-Host") == ["portal.example"])
    check("headers: forward_headers=['*'] still replaces X-Forwarded-Prefix", h.getall("X-Forwarded-Prefix") == [P])
    check("headers: X-Forwarded-Server and Forwarded are not copied", "X-Forwarded-Server" not in h and "Forwarded" not in h)
    check("headers: Authorization is never copied", "Authorization" not in h)
    # client-address headers set by a CDN or another proxy are never copied either
    for pats in (["*"], ["cf-*", "true-*", "x-client-*"]):
        hh = server._proxy_request_headers(req(headers=[
            ("CF-Connecting-IP", "6.6.6.6"), ("True-Client-IP", "6.6.6.7"), ("X-Client-IP", "6.6.6.8"),
            ("Forwarded", "for=6.6.6.9"), ("X-Request-ID", "r1")]), {"forward_headers": pats}, "up", P, False)
        check(f"headers: forward_headers={pats} never copies CF-Connecting-IP, True-Client-IP, X-Client-IP or Forwarded",
              not any(n in hh for n in ("CF-Connecting-IP", "True-Client-IP", "X-Client-IP", "Forwarded"))
              and "6.6.6." not in json.dumps(list(hh.items())), str(dict(hh)))
    hh = server._proxy_request_headers(req(headers=[
        ("CF-Connecting-IP", "6.6.6.6"), ("True-Client-IP", "6.6.6.7"), ("X-Client-IP", "6.6.6.8")]),
        {"forward_headers": ["*"]}, "example.com", P + "/https://example.com", True)
    check("headers: browser mode with forward_headers=['*'] tells the site no client address",
          "6.6.6." not in json.dumps(list(hh.items())), str(dict(hh)))
    check("headers: the session cookie is never copied (two Cookie lines)",
          "SECRETSESSION" not in json.dumps(list(h.items())) and h.get("Cookie") == "a=1; b=2; c=3", str(h.get("Cookie")))
    check("headers: a whitelisted header is still copied", h.get("X-Request-ID") == "r1")

    # portal credentials sent as API-key headers are never copied either
    for pats in (["*"], ["x-*"], ["x-api-key", "x-stream-key"]):
        h = server._proxy_request_headers(req(headers=[
            ("X-API-Key", "portal_SECRETKEY"), ("X-Stream-Key", "live_SECRETKEY"), ("X-Request-ID", "r1")]),
            {"forward_headers": pats}, "up", P, False)
        check(f"headers: forward_headers={pats} never copies X-API-Key or X-Stream-Key",
              "X-API-Key" not in h and "X-Stream-Key" not in h and "SECRETKEY" not in json.dumps(list(h.items())), str(dict(h)))
        if pats != ["x-api-key", "x-stream-key"]:
            check(f"headers: forward_headers={pats} still copies an ordinary header", h.get("X-Request-ID") == "r1")

    # configured headers still win over the generated ones, without duplicates
    cfg = {"auth_header": "Bearer upstreamtoken", "forwarded_host": True,
           "extra_headers": {"x-forwarded-host": "app.example", "X-Extra": "1"}}
    h = server._proxy_request_headers(req(headers=[("Authorization", "Bearer secret")]), cfg, "up", P, False)
    check("headers: configured Authorization replaces the client's", h.getall("Authorization") == ["Bearer upstreamtoken"])
    check("headers: extra_headers override case-insensitively, no duplicate",
          h.getall("X-Forwarded-Host") == ["app.example"] and h.get("X-Extra") == "1", str(dict(h)))

    # trusted peer: the client address comes from get_client_ip
    h = server._proxy_request_headers(req("198.51.100.7", [
        ("CF-Connecting-IP", "192.0.2.77"), ("X-Forwarded-For", "6.6.6.6, 192.0.2.77"),
        ("X-Forwarded-Proto", "https"), ("X-Forwarded-Host", "evil.example")]), {"forwarded_host": True}, "up", P, False)
    check("headers: trusted peer, X-Forwarded-For is the real client", h.getall("X-Forwarded-For") == ["192.0.2.77"], str(dict(h)))
    check("headers: trusted peer, X-Real-IP is the real client", h.getall("X-Real-IP") == ["192.0.2.77"])
    check("headers: trusted peer, X-Forwarded-Proto https", h.getall("X-Forwarded-Proto") == ["https"])
    check("headers: client X-Forwarded-Host is not believed even from a trusted peer",
          h.getall("X-Forwarded-Host") == ["portal.example"])

    # browser mode: nothing about the member or the portal goes to arbitrary sites
    h = server._proxy_request_headers(req("198.51.100.7", [("CF-Connecting-IP", "192.0.2.77"),
                                                          ("X-Forwarded-For", "6.6.6.6"),
                                                          ("X-Forwarded-Proto", "https")]),
                                      {"forward_headers": ["x-*"]}, "example.com", P + "/https://example.com", True)
    check("headers: browser mode sends no client address, host or prefix",
          not any(n in h for n in ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Prefix")), str(dict(h)))
    check("headers: browser mode still sends the scheme", h.getall("X-Forwarded-Proto") == ["https"])
    bad = server._proxy_request_headers(req(host="bad host\r\nX: y"), {"forwarded_host": True}, "up", P, False)
    check("headers: an unusable Host is replaced by the configured host",
          bad.getall("X-Forwarded-Host", None) == ["portal.example"], str(dict(bad)))

    # X-Forwarded-Host is the configured portal host, never a name the client picked
    def xfh(host, hostname="portal.example"):
        Config.HOSTNAME = hostname
        try:
            return server._proxy_request_headers(req(host=host), {"forwarded_host": True}, "up", P, False).getall("X-Forwarded-Host", None)
        finally:
            Config.HOSTNAME = "portal.example"
    check("xfh: Host: attacker.example gives the configured host", xfh("attacker.example") == ["portal.example"], str(xfh("attacker.example")))
    check("xfh: Host: attacker.example:8443 gives the configured host", xfh("attacker.example:8443") == ["portal.example"])
    check("xfh: the configured name with the client's port is kept", xfh("portal.example:8443") == ["portal.example:8443"])
    check("xfh: the configured name matches regardless of case", xfh("Portal.Example") == ["Portal.Example"])
    check("xfh: a look-alike name is not accepted", xfh("portal.example.attacker.example") == ["portal.example"]
          and xfh("xportal.example") == ["portal.example"])
    check("xfh: an IP Host that is not the configured name is replaced", xfh("203.0.113.9:443") == ["portal.example"])
    check("xfh: a configured IP address is matched with its port", xfh("203.0.113.9:8506", "203.0.113.9") == ["203.0.113.9:8506"])
    check("xfh: nothing usable configured sends no header", xfh("attacker.example", "") is None)

    # Location rewriting (single-site mode: the browser follows the redirect)
    loc = lambda v: server._proxy_rewrite_location(v, P, "http://up.internal:8080")
    check("location: root-relative goes under the proxy path", loc("/login") == "/proxy/abc/login", loc("/login"))
    check("location: a value already under the proxy path is left alone",
          loc("/proxy/abc/login") == "/proxy/abc/login" and loc("/proxy/abc") == "/proxy/abc"
          and loc("/proxy/abc?x=1") == "/proxy/abc?x=1", loc("/proxy/abc/login"))
    check("location: a path that merely starts like the prefix is prefixed",
          loc("/proxy/abcd/login") == "/proxy/abc/proxy/abcd/login", loc("/proxy/abcd/login"))
    check("location: the upstream's own origin is mapped to the proxy path",
          loc("http://up.internal:8080/a?b=1") == "/proxy/abc/a?b=1", loc("http://up.internal:8080/a?b=1"))
    check("location: portal host URL without the prefix gets the prefix",
          loc("https://portal.example/login") == "/proxy/abc/login" and loc("https://portal.example:8443/") == "/proxy/abc/"
          and loc("http://PORTAL.example/x?y=2") == "/proxy/abc/x?y=2", loc("https://portal.example/login"))
    check("location: portal host URL already under the prefix is not prefixed twice",
          loc("https://portal.example/proxy/abc/login?n=1") == "/proxy/abc/login?n=1", loc("https://portal.example/proxy/abc/login?n=1"))
    check("location: protocol-relative values are handled as absolute ones",
          loc("//portal.example/login") == "/proxy/abc/login" and loc("//up.internal:8080/z") == "/proxy/abc/z",
          loc("//portal.example/login"))
    check("location: a relative value is left alone", loc("login") == "login" and loc("../x") == "../x")
    check("location: an unparsable absolute URL is left alone", loc("http://[bad/x") == "http://[bad/x", loc("http://[bad/x"))
    # the upstream's origin has to end where the Location says: no glueing onto a longer host or other port
    lan = lambda v: server._proxy_rewrite_location(v, P, "http://app.lan")
    check("location: a longer host name is not mistaken for the upstream's origin",
          lan("http://app.lan.evil.com/x") == "/proxy/abc/x", lan("http://app.lan.evil.com/x"))
    check("location: another port on the upstream's host is returned unchanged, never mapped onto the target",
          lan("http://app.lan:8443/ui") == "http://app.lan:8443/ui" and lan("http://app.lan:8443") == "http://app.lan:8443",
          lan("http://app.lan:8443/ui"))
    check("location: another scheme on the upstream's host is returned unchanged (http -> https loop)",
          lan("https://app.lan/") == "https://app.lan/" and lan("https://APP.lan/x") == "https://APP.lan/x"
          and lan("//app.lan:8443/x") == "http://app.lan:8443/x", lan("https://app.lan/"))
    check("location: a scheme or port change on another host is not mapped onto the target either",
          lan("https://other.example/x") == "https://other.example/x"
          and lan("http://other.example:81/x") == "http://other.example:81/x", lan("https://other.example/x"))
    check("location: the same origin in another spelling (upper case, explicit default port) is mapped",
          lan("HTTP://APP.LAN/x") == "/proxy/abc/x" and lan("http://app.lan:80/x?y=1") == "/proxy/abc/x?y=1"
          and lan("Http://App.Lan") == "/proxy/abc", lan("HTTP://APP.LAN/x"))
    check("location: an upper-case scheme is understood for portal host values too",
          server._proxy_rewrite_location("HTTPS://portal.example/login", P, "http://app.lan") == "/proxy/abc/login"
          and server._proxy_rewrite_location("HTTP://up.example/x", P, "http://up.example") == "/proxy/abc/x"
          and server._proxy_rewrite_location("https://up.example/x", P, "http://up.example") == "https://up.example/x",
          server._proxy_rewrite_location("HTTP://up.example/x", P, "http://up.example"))
    check("location: the origin followed by /, ?, # or nothing still maps to the proxy path",
          lan("http://app.lan/a") == "/proxy/abc/a" and lan("http://app.lan?x=1") == "/proxy/abc?x=1"
          and lan("http://app.lan#f") == "/proxy/abc#f" and lan("http://app.lan") == "/proxy/abc",
          lan("http://app.lan?x=1"))
    check("location: a port-prefixed look-alike (8080 vs 80801) is not the upstream's origin",
          loc("http://up.internal:80801/x") == "http://up.internal:80801/x", loc("http://up.internal:80801/x"))
    # redirect target: the portal's own names are mapped back onto the upstream before the portal dials anything
    nxt = lambda v, cur="http://up.internal:8080/start": server._proxy_redirect_url(v, cur, P, "http://up.internal:8080")
    check("redirect target: a prefix-aware Location (/proxy/abc/login) loses the prefix",
          nxt("/proxy/abc/login") == "http://up.internal:8080/login" and nxt("/proxy/abc") == "http://up.internal:8080/"
          and nxt("/proxy/abc/a?b=1") == "http://up.internal:8080/a?b=1", nxt("/proxy/abc/login"))
    check("redirect target: a path that only starts like the prefix is not stripped",
          nxt("/proxy/abcd/x") == "http://up.internal:8080/proxy/abcd/x", nxt("/proxy/abcd/x"))
    check("redirect target: a Location on the portal's host is mapped onto the upstream, any scheme or port",
          nxt("https://portal.example/login") == "http://up.internal:8080/login"
          and nxt("http://PORTAL.example:8443/proxy/abc/x?y=2") == "http://up.internal:8080/x?y=2"
          and nxt("//portal.example/z") == "http://up.internal:8080/z", nxt("https://portal.example/login"))
    check("redirect target: relative and own-origin values stay on the upstream",
          nxt("login") == "http://up.internal:8080/login" and nxt("HTTP://UP.internal:8080/q#f") == "http://up.internal:8080/q"
          and nxt("../x", "http://up.internal:8080/a/b/c") == "http://up.internal:8080/a/x", nxt("login"))
    check("redirect target: another host, or the upstream's host on another scheme or port, is requested as given",
          nxt("https://other.example/x") == "https://other.example/x"
          and nxt("https://up.internal:8080/x") == "https://up.internal:8080/x"
          and nxt("http://up.internal:9/x") == "http://up.internal:9/x", nxt("https://up.internal:8080/x"))
    check("redirect target: a value that is no http(s) URL is unusable",
          nxt("ftp://x/y") is None and nxt("http://[bad/x") is None, str(nxt("ftp://x/y")))
    # browser mode Location
    bl = lambda v: server._proxy_browser_location(v, "/proxy/abc", "http://site.example")
    check("browser location: root-relative goes under the site's path",
          bl("/x") == "/proxy/abc/http://site.example/x", bl("/x"))
    check("browser location: an absolute URL is wrapped, whatever the case of its scheme",
          bl("https://t.example/x") == "/proxy/abc/https://t.example/x"
          and bl("HTTPS://t.example/x") == "/proxy/abc/https://t.example/x"
          and bl("Http://t.example/x?y=1") == "/proxy/abc/http://t.example/x?y=1", bl("HTTPS://t.example/x"))
    check("browser location: a protocol-relative value goes to that host with the site's scheme, not under the site",
          bl("//cdn.example/login?a=1") == "/proxy/abc/http://cdn.example/login?a=1"
          and server._proxy_browser_location("//cdn.example/x", "/proxy/abc", "https://site.example")
          == "/proxy/abc/https://cdn.example/x", bl("//cdn.example/login?a=1"))
    check("browser location: a relative value is left alone", bl("next") == "next" and bl("") == "")
finally:
    Config.HOSTNAME = saved_hostname
    server._trusted_proxy_networks[:] = saved_nets
    server._trusted_peer_cache.clear()

# ---------------------------------------------------------------------------
# Part 2: the real handler against an echo upstream
# ---------------------------------------------------------------------------


async def echo(request):
    body = json.dumps({"headers": [[k, v] for k, v in request.headers.items()], "path": request.path_qs})
    resp = web.Response(text=body, content_type=request.query.get("ct", "text/plain"))
    resp.headers.add("Set-Cookie", "a=1; Path=/; Domain=upstream.example; HttpOnly")
    resp.headers.add("Set-Cookie", "b=2; Path=/app; Secure; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
    resp.headers.add("Set-Cookie", "c=3")
    resp.headers.add("Set-Cookie", f"{SESSION}=evil; Path=/")
    resp.headers.add("Link", "<a>; rel=x")
    resp.headers.add("Link", "<b>; rel=y")
    return resp


async def slow_stream(request):
    """A download longer than the per-request timeout, with data flowing."""
    resp = web.StreamResponse(headers={"Content-Type": "application/octet-stream"})
    await resp.prepare(request)
    for _ in range(int(request.query.get("chunks", "6"))):
        await resp.write(b"x" * 1000)
        await asyncio.sleep(float(request.query.get("gap", "2")))
    await resp.write_eof()
    return resp


async def stall_mid_stream(request):
    resp = web.StreamResponse(headers={"Content-Type": "application/octet-stream"})
    await resp.prepare(request)
    await resp.write(b"first")
    await asyncio.sleep(30)
    return resp


async def abort_mid_stream(request):
    """Sends a few bytes of a download, then drops the connection."""
    resp = web.StreamResponse(headers={"Content-Type": "application/octet-stream"})
    await resp.prepare(request)
    await resp.write(b"y" * 5000)
    await asyncio.sleep(0.2)
    request.transport.abort()
    await asyncio.sleep(5)
    return resp


async def redirect_prefix(request):
    """An app that honours X-Forwarded-Prefix."""
    return web.Response(status=302, headers={"Location": request.headers.get("X-Forwarded-Prefix", "") + "/login"})


async def redirect_host(request):
    """A Rack-style app: builds its redirect from X-Forwarded-Host."""
    return web.Response(status=302, headers={"Location": "http://" + request.headers.get("X-Forwarded-Host", "none") + "/login"})


async def redirect_portal_port(request):
    """Builds a Location on the portal's name but another port (a recorder, in the test)."""
    return web.Response(status=302, headers={"Location": f"http://localhost:{request.query['port']}/login"})


async def redirect_upper(request):
    return web.Response(status=302, headers={"Location": "HTTPS://tracker.example/x"})


async def redirect_to_echo_post(request):
    return web.Response(status=302, headers={"Location": "/echo"})


async def redirect_plain(request):
    return web.Response(status=302, headers={"Location": "/login"})


async def chain(request):
    """/chain/N redirects to /chain/N-1 until /chain/0, which answers."""
    n = int(request.match_info["n"])
    if n <= 0:
        return web.Response(text="CHAIN END")
    return web.Response(status=302, headers={"Location": f"/chain/{n - 1}"})


upstream_hits = {"count": 0, "slowchain": 0, "ws": 0}


async def count_hit(request):
    upstream_hits["count"] += 1
    return web.Response(text="COUNTED")


async def slow_chain(request):
    """/slowchain/N waits 0.3 s, then redirects to /slowchain/N-1 until 0."""
    upstream_hits["slowchain"] += 1
    n = int(request.match_info["n"])
    await asyncio.sleep(0.3)
    if n <= 0:
        return web.Response(text="SLOW CHAIN END")
    return web.Response(status=302, headers={"Location": f"/slowchain/{n - 1}"})


DOC_TYPES = {"html": "text/html; charset=utf-8", "svg": "image/svg+xml", "xhtml": "application/xhtml+xml",
             "xml": "text/xml", "plain": "text/plain", "js": "application/javascript", "png": "image/png"}


async def swdoc(request):
    """A malicious upstream: a document of the asked type that tries to widen a worker's scope."""
    kind = request.match_info["kind"]
    return web.Response(body=b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>" if kind == "svg" else b"<p>x</p>",
                        headers={"Content-Type": DOC_TYPES[kind], "Service-Worker-Allowed": "/"})


async def sxdoc(request):
    """A fake SearXNG: its image proxy answers an SVG with a script, its page answers HTML."""
    kind = request.match_info["kind"]
    ctype = {"svg": "image/svg+xml", "html": "text/html; charset=utf-8", "png": "image/png"}[kind]
    body = b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>" if kind == "svg" else b"<p>x</p>"
    return web.Response(body=body, headers={"Content-Type": ctype, "Service-Worker-Allowed": "/",
                                            **({"content-security-policy": "default-src 'none'"} if kind == "svg" else {}),
                                            **({"X-Page": "1"} if kind == "html" else {})})


ws_queries = []


async def ws_query_echo(request):
    """A WebSocket upstream that records the query string it was dialled with."""
    ws_queries.append(request.rel_url.raw_query_string)
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_str("hi")
    await ws.close()
    return ws


async def ws_count(request):
    """A WebSocket upstream that counts the connections made to it."""
    upstream_hits["ws"] += 1
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.close()
    return ws


async def redirect_cookie(request):
    """A redirect hop that sets a cookie (a login), then the page."""
    return web.Response(status=302, headers={"Location": "/login", "Set-Cookie": "hop=1; Path=/"})


async def redirect_elsewhere(request):
    """Redirects to another host name (localhost) on the recorder's port."""
    return web.Response(status=302, headers={"Location": f"http://localhost:{request.query['port']}/hop"})


async def created(request):
    """A 201 whose Location names the upstream itself (same origin) or another port."""
    if request.query.get("other"):
        return web.Response(status=201, headers={"Location": f"http://{request.host.rsplit(':', 1)[0]}:{request.query['other']}/new"})
    return web.Response(status=201, headers={"Location": f"http://{request.host}/new"})


async def trickle(request):
    """HTML that arrives a byte every 2 s for 12 s (never silent for long)."""
    resp = web.StreamResponse(headers={"Content-Type": "text/html"})
    await resp.prepare(request)
    for _ in range(6):
        await resp.write(b"x")
        await asyncio.sleep(2)
    await resp.write_eof()
    return resp


async def login_page(request):
    return web.Response(text="UPSTREAM LOGIN")


recorder_hits = []


async def recorder(request):
    recorder_hits.append([[k, v] for k, v in request.headers.items()])
    return web.Response(text="RECORDER")


async def hang_before_headers(request):
    await asyncio.sleep(30)
    return web.Response(text="late")


CONFIG = {}
NOW_CONNECTION = {}


REVOKED = False
QUERY_AUTH = False      # the fake login says the ?token= parameter authenticated the request


async def fake_auth(request):
    if REVOKED:
        return None
    if QUERY_AUTH:
        request[server._AUTH_VIA_QUERY_TOKEN] = True

    class T:
        user_id = 1
        token_id = "t"
    return T()


LOOKUP_DELAY = 0


async def fake_get_connection(conn_id, user_id):
    if LOOKUP_DELAY:
        await asyncio.sleep(LOOKUP_DELAY)
    return dict(NOW_CONNECTION, config=dict(CONFIG))


async def fake_usage(*a, **k):
    return None


async def fake_resolve(host, port=0):
    return []


async def main():
    up_app = web.Application()
    up_app.router.add_get("/echo", echo)
    up_app.router.add_get("/app/echo", echo)
    up_app.router.add_get("/slow", slow_stream)
    up_app.router.add_get("/stall", stall_mid_stream)
    up_app.router.add_get("/hang", hang_before_headers)
    up_app.router.add_get("/abort", abort_mid_stream)
    up_app.router.add_get("/r-prefix", redirect_prefix)
    up_app.router.add_get("/r-host", redirect_host)
    up_app.router.add_get("/r-plain", redirect_plain)
    up_app.router.add_get("/r-portalport", redirect_portal_port)
    up_app.router.add_get("/r-upper", redirect_upper)
    up_app.router.add_post("/r-post", redirect_to_echo_post)
    up_app.router.add_post("/echo", echo)
    up_app.router.add_get("/login", login_page)
    up_app.router.add_get("/chain/{n}", chain)
    up_app.router.add_get("/r-cookie", redirect_cookie)
    up_app.router.add_get("/r-elsewhere", redirect_elsewhere)
    up_app.router.add_get("/count", count_hit)
    up_app.router.add_get("/wscount", ws_count)
    up_app.router.add_get("/wsquery", ws_query_echo)
    up_app.router.add_get("/slowchain/{n}", slow_chain)
    up_app.router.add_get("/created", created)
    up_app.router.add_get("/trickle", trickle)
    up_app.router.add_get("/swdoc/{kind}", swdoc)
    up_app.router.add_get("/search/image_proxy/{kind}", sxdoc)
    upstream = TestServer(up_app, host="127.0.0.1")
    await upstream.start_server()
    site_b = TestServer(up_app, host="127.0.0.1")       # a second site (other origin), same behaviour
    await site_b.start_server()
    rec_app = web.Application()
    rec_app.router.add_route("*", "/{tail:.*}", recorder)
    rec = TestServer(rec_app, host="127.0.0.1")
    await rec.start_server()

    proxy_app = web.Application()
    proxy_app.router.add_route("*", "/proxy/{conn_id}", server.http_proxy_connection)
    proxy_app.router.add_route("*", "/proxy/{conn_id}/{path:.*}", server.http_proxy_connection)
    proxy_app.router.add_route("*", "/search/{path:.*}", server.http_searxng_proxy)
    portal = TestServer(proxy_app, host="127.0.0.1")
    await portal.start_server()

    NOW_CONNECTION.update({"id": 5, "type": "http", "host": "127.0.0.1", "port": upstream.port,
                           "name": "echo"})
    saved = (server.authenticate_request, server.db.get_accessible_connection,
             server.db.record_connection_usage, server.resolve_checked_host,
             server.resolve_checked_host_cached, server._SSRFSafeConnector)
    saved_cred = (server.db.get_user_by_id, server.db.is_token_valid)
    saved_sx_status = server._searxng_status

    async def fake_sx_status():
        return True, upstream.port
    server._searxng_status = fake_sx_status

    # The relay re-checks the credential once its socket is registered (user 1, session "t").
    async def fake_user(user_id):
        return {"id": user_id} if user_id == 1 else None

    async def fake_token_valid(token_id):
        return not REVOKED
    server.db.get_user_by_id = fake_user
    server.db.is_token_valid = fake_token_valid
    # Test-only: the real policy refuses a loopback upstream.
    server.authenticate_request = fake_auth
    server.db.get_accessible_connection = fake_get_connection
    server.db.record_connection_usage = fake_usage
    server.resolve_checked_host = fake_resolve
    server.resolve_checked_host_cached = fake_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)
    base = f"http://127.0.0.1:{portal.port}/proxy/xyz"
    Config.HOSTNAME = "127.0.0.1"       # the portal's configured name in this test
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c:
            # --- a malicious upstream: no widened worker scope, a policy on every kind of document
            CONFIG.clear()
            seen = {}
            for kind in DOC_TYPES:
                async with c.get(f"{base}/swdoc/{kind}") as r:
                    await r.read()
                    seen[kind] = (r.status, r.headers.get("Service-Worker-Allowed"), r.headers.get("Content-Security-Policy"))
            check("service worker: Service-Worker-Allowed is stripped from every proxied response (buffered and streamed)",
                  all(v[0] == 200 and v[1] is None for v in seen.values()), str(seen))
            check("csp: HTML, XHTML and XML documents get the policy without workers",
                  all(seen[k][2] and "worker-src 'none'" in seen[k][2] for k in ("html", "xhtml", "xml")), str(seen))
            check("csp: an SVG document is sandboxed without scripts, so an image it embeds still draws but no script runs",
                  seen["svg"][2] and seen["svg"][2].startswith("sandbox;") and "allow-scripts" not in seen["svg"][2]
                  and "img-src" in seen["svg"][2], str(seen["svg"]))
            check("csp: other types (text, script, image) get none from the proxy",
                  all(seen[k][2] is None for k in ("plain", "js", "png")), str(seen))
            check("service worker: the SearXNG proxy drops the header too",
                  "service-worker-allowed" in server._SEARXNG_RESPONSE_HOP_HEADERS)
            sx = {}
            for kind in ("svg", "html", "png"):
                async with c.get(f"http://127.0.0.1:{portal.port}/search/image_proxy/{kind}") as r:
                    await r.read()
                    sx[kind] = (r.status, r.headers.getall("Content-Security-Policy", []),
                                r.headers.get("Service-Worker-Allowed"))
            check("csp: an SVG from the SearXNG image proxy is sandboxed without scripts, one policy only",
                  sx["svg"][0] == 200 and sx["svg"][1] == [server._PROXY_SVG_CSP] and sx["svg"][2] is None, str(sx))
            check("csp: SearXNG HTML is left to the portal page policy (no proxy policy here) and other images get none",
                  sx["html"][1] == [] and sx["png"][1] == [], str(sx))
            # --- forwarded headers and cookies, streamed and buffered paths
            # default (forwarded_host off): neither X-Forwarded-Host nor X-Forwarded-Prefix is sent, client copies are dropped
            CONFIG.clear()
            async with c.get(f"{base}/echo", headers={
                    "X-Forwarded-Host": "evil.example", "X-Forwarded-Prefix": "/evil"}) as r:
                hdrs = {}
                for k, v in json.loads(await r.text())["headers"]:
                    hdrs.setdefault(k.lower(), []).append(v)
                check("default: upstream gets no X-Forwarded-Host and no X-Forwarded-Prefix",
                      "x-forwarded-host" not in hdrs and "x-forwarded-prefix" not in hdrs, str(hdrs))
                check("default: client address and scheme headers are still sent",
                      hdrs.get("x-forwarded-for") == ["127.0.0.1"] and hdrs.get("x-real-ip") == ["127.0.0.1"]
                      and hdrs.get("x-forwarded-proto") == ["http"], str(hdrs))
            for ct, label in (("text/plain", "streamed"), ("application/json", "buffered")):
                CONFIG.clear()
                CONFIG["forwarded_host"] = True
                async with c.get(f"{base}/echo?ct={ct}", headers={
                        "X-Forwarded-For": "6.6.6.6", "X-Real-IP": "6.6.6.6", "X-Forwarded-Host": "evil.example",
                        "X-Forwarded-Prefix": "/evil", "Authorization": "Bearer PORTALSECRET",
                        "Cookie": f"keep=1; {SESSION}=PORTALSESSION"}) as r:
                    raw = await r.text()
                    got = json.loads(raw)
                    hdrs = {}
                    for k, v in got["headers"]:
                        hdrs.setdefault(k.lower(), []).append(v)
                    cookies = r.headers.getall("Set-Cookie", [])
                    check(f"{label}: upstream sees the client address", hdrs.get("x-forwarded-for") == ["127.0.0.1"], str(hdrs))
                    check(f"{label}: spoofed X-Real-IP replaced", hdrs.get("x-real-ip") == ["127.0.0.1"], str(hdrs))
                    check(f"{label}: upstream sees X-Forwarded-Prefix=/proxy/xyz", hdrs.get("x-forwarded-prefix") == ["/proxy/xyz"], str(hdrs))
                    check(f"{label}: upstream sees the portal host", hdrs.get("x-forwarded-host") == [f"127.0.0.1:{portal.port}"], str(hdrs))
                    check(f"{label}: upstream sees the connection scheme (http here)", hdrs.get("x-forwarded-proto") == ["http"], str(hdrs))
                    check(f"{label}: portal session cookie and Authorization never reach the upstream",
                          "PORTALSESSION" not in raw and "PORTALSECRET" not in raw and "authorization" not in hdrs, raw[:300])
                    check(f"{label}: other cookies are forwarded", hdrs.get("cookie") == ["keep=1"], str(hdrs.get("cookie")))
                    check(f"{label}: no identity headers added", not any(k.startswith(("x-portal", "remote-user")) for k in hdrs), str(hdrs))
                    check(f"{label}: three cookies arrive (portal-session-named one dropped)", len(cookies) == 3, str(cookies))
                    check(f"{label}: Domain removed and Path moved under the proxy path (root)",
                          "a=1; HttpOnly; Path=/proxy/xyz/" in cookies, str(cookies))
                    check(f"{label}: non-root Path prefixed, Expires kept",
                          "b=2; Secure; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/proxy/xyz/app" in cookies, str(cookies))
                    check(f"{label}: cookie without Path gets the proxy root", "c=3; Path=/proxy/xyz/" in cookies, str(cookies))
                    check(f"{label}: no Domain attribute anywhere", not any("domain" in x.lower() for x in cookies))
                    check(f"{label}: other repeated headers are all kept", r.headers.getall("Link", []) == ["<a>; rel=x", "<b>; rel=y"],
                          str(r.headers.getall("Link", [])))

            # --- forward_headers=* cannot smuggle anything through
            CONFIG.clear()
            CONFIG["forward_headers"] = ["*"]
            CONFIG["forwarded_host"] = True
            async with c.get(f"{base}/echo", headers={
                    "X-Forwarded-Host": "evil.example", "x-forwarded-server": "evil", "X-Real-IP": "6.6.6.6",
                    "Authorization": "Bearer PORTALSECRET", "Cookie": f"{SESSION}=PORTALSESSION",
                    "X-Request-ID": "r1"}) as r:
                raw = await r.text()
                hdrs = {}
                for k, v in json.loads(raw)["headers"]:
                    hdrs.setdefault(k.lower(), []).append(v)
                check("forward_headers=*: client X-Forwarded-Host replaced", hdrs.get("x-forwarded-host") == [f"127.0.0.1:{portal.port}"], str(hdrs))
                check("forward_headers=*: X-Forwarded-Server not passed", "x-forwarded-server" not in hdrs)
                check("forward_headers=*: client X-Real-IP replaced", hdrs.get("x-real-ip") == ["127.0.0.1"])
                check("forward_headers=*: Authorization and portal session still stripped",
                      "authorization" not in hdrs and "cookie" not in hdrs and "PORTALSESSION" not in raw, raw[:300])
                check("forward_headers=*: whitelisted header passes", hdrs.get("x-request-id") == ["r1"])

            async with c.get(f"{base}/echo", headers={
                    "X-API-Key": "portal_SECRETKEY", "X-Stream-Key": "live_SECRETKEY", "X-Request-ID": "r1"}) as r:
                raw = await r.text()
                hdrs = {k.lower() for k, v in json.loads(raw)["headers"]}
                check("forward_headers=*: portal API key and stream key never reach the upstream",
                      "x-api-key" not in hdrs and "x-stream-key" not in hdrs and "SECRETKEY" not in raw, raw[:300])
                check("forward_headers=*: ordinary header still passes next to them", "x-request-id" in hdrs)

            # --- a client-chosen Host header does not reach the upstream as X-Forwarded-Host
            CONFIG.clear()
            CONFIG["forwarded_host"] = True
            async with c.get(f"{base}/echo", headers={"Host": "attacker.example"}) as r:
                hdrs = {}
                for k, v in json.loads(await r.text())["headers"]:
                    hdrs.setdefault(k.lower(), []).append(v)
                check("Host: attacker.example -> upstream sees the configured host, not the attacker's",
                      hdrs.get("x-forwarded-host") == ["127.0.0.1"], str(hdrs))

            # --- the member's ?token= parameter is not passed on to the upstream
            global QUERY_AUTH
            CONFIG.clear()

            async def upstream_path(qs, query_auth):
                global QUERY_AUTH
                QUERY_AUTH = query_auth
                try:
                    async with c.get(f"{base}/echo?{qs}") as r:
                        return json.loads(await r.text())["path"]
                finally:
                    QUERY_AUTH = False
            path = await upstream_path("token=SECRETJWT&a=1&b=x%26y", True)
            check("token: authenticated by ?token=, the parameter is removed and the others kept as sent",
                  path == "/echo?a=1&b=x%26y", path)
            path = await upstream_path("a=1&token=SECRETJWT&token=SECOND&TOKEN=keep&mytoken=keep2", True)
            check("token: every token parameter is removed, similar names are kept",
                  path == "/echo?a=1&TOKEN=keep&mytoken=keep2", path)
            path = await upstream_path("tok%65n=SECRETJWT&a=1", True)
            check("token: an escaped parameter name is removed too", path == "/echo?a=1", path)
            path = await upstream_path("token=SECRETJWT", True)
            check("token: when it was the only parameter no '?' is left", path == "/echo", path)
            path = await upstream_path("token=app-own-value&a=1", False)
            check("token: when something else authenticated the request, the app's own token parameter is kept",
                  path == "/echo?token=app-own-value&a=1", path)
            del ws_queries[:]
            QUERY_AUTH = True
            try:
                async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as wc:
                    async with wc.ws_connect(f"{base}/wsquery?token=SECRETJWT&a=1") as cws:
                        await asyncio.wait_for(cws.receive(), 5)
            finally:
                QUERY_AUTH = False
            check("token: the WebSocket upstream is not dialled with the ?token= parameter",
                  ws_queries == ["a=1"], str(ws_queries))
            CONFIG.clear()

            # --- redirects: followed by the portal (single-site mode), as before
            CONFIG.clear()
            async with c.get(f"{base}/r-plain", allow_redirects=False) as r:
                body = await r.text()
                check("redirect: a plain /login redirect is followed by the portal, the client gets the final page",
                      r.status == 200 and body == "UPSTREAM LOGIN", f"{r.status} {r.headers.get('Location')} {body[:80]}")
            async with c.get(f"{base}/chain/5", allow_redirects=False) as r:
                body = await r.text()
                check("redirect: five hops are followed", r.status == 200 and body == "CHAIN END", f"{r.status} {body[:60]}")
            async with c.get(f"{base}/chain/6", allow_redirects=False) as r:
                await r.read()
                check("redirect: a sixth hop is not followed (502)", r.status == 502, f"{r.status} {r.headers.get('Location')}")
            async with c.get(f"{base}/r-cookie", allow_redirects=False) as r:
                body = await r.text()
                check("redirect: a Set-Cookie sent by an intermediate hop is lost (known, unchanged from before)",
                      r.status == 200 and body == "UPSTREAM LOGIN" and not r.headers.getall("Set-Cookie", []),
                      str(r.headers.getall("Set-Cookie", [])))
            async with c.get(f"{base}/created", allow_redirects=False) as r:
                await r.read()
                check("redirect: a 201 Location on the upstream's own origin is put under the proxy path",
                      r.status == 201 and r.headers.get("Location") == "/proxy/xyz/new", f"{r.status} {r.headers.get('Location')}")
            async with c.get(f"{base}/created?other={rec.port}", allow_redirects=False) as r:
                await r.read()
                check("redirect: a Location on another port of the upstream's host is not mapped back onto the target",
                      r.status == 201 and r.headers.get("Location") == f"http://127.0.0.1:{rec.port}/new",
                      f"{r.status} {r.headers.get('Location')}")

            # an app that honours X-Forwarded-Prefix / X-Forwarded-Host: the portal maps its own names back onto the upstream
            async with c.get(f"{base}/r-prefix", allow_redirects=False) as r:
                body = await r.text()
                check("redirect: a prefix-aware app (Location /proxy/xyz/login) ends on the upstream's /login, not /proxy/xyz/login there",
                      r.status == 200 and body == "UPSTREAM LOGIN", f"{r.status} {body[:80]}")
            Config.HOSTNAME = "localhost"       # the portal's name differs from the upstream's (127.0.0.1)
            CONFIG["forwarded_host"] = True     # the app only builds such a Location when it is sent the host
            try:
                del recorder_hits[:]
                async with c.get(f"{base}/r-host", allow_redirects=False) as r:
                    body = await r.text()
                    check("redirect: a Rack-style app (Location built from X-Forwarded-Host) ends on the upstream's /login, not the portal's own page",
                          r.status == 200 and body == "UPSTREAM LOGIN", f"{r.status} {body[:80]}")
                async with c.get(f"{base}/r-portalport?port={rec.port}", allow_redirects=False) as r:
                    body = await r.text()
                    check("redirect: the portal's name on any port is mapped onto the upstream, nothing else is dialled",
                          r.status == 200 and body == "UPSTREAM LOGIN" and not recorder_hits, f"{r.status} {body[:80]} {recorder_hits}")
            finally:
                Config.HOSTNAME = "127.0.0.1"
            # a hop to another origin carries no cookie, credential, forwarded host or prefix of the upstream
            CONFIG["extra_headers"] = {"X-Upstream-Key": "SECRET"}
            CONFIG["auth_header"] = "Bearer UPSTREAMTOKEN"
            del recorder_hits[:]
            async with c.get(f"{base}/r-elsewhere?port={rec.port}", headers={"Cookie": "keep=1"}, allow_redirects=False) as r:
                body = await r.text()
                sent = {k.lower(): v for k, v in recorder_hits[0]} if recorder_hits else {}
                check("redirect: another origin is followed", r.status == 200 and body == "RECORDER", f"{r.status} {body[:60]}")
                check("redirect: the other origin gets its own Host and none of the upstream's cookie, credentials, forwarded host or prefix",
                      sent.get("host") == f"localhost:{rec.port}"
                      and not any(k in sent for k in ("cookie", "authorization", "x-upstream-key", "x-forwarded-host", "x-forwarded-prefix")),
                      str(sent))
                check("redirect: the other origin is not told the member's address (X-Forwarded-For, X-Real-IP)",
                      "x-forwarded-for" not in sent and "x-real-ip" not in sent, str(sent))
            CONFIG.clear()
            # a POST answered with 302 is repeated as a GET
            async with c.post(f"{base}/r-post", data=b"payload", allow_redirects=False) as r:
                got = json.loads(await r.text())
                check("redirect: a POST answered with 302 is followed as a GET to the new path",
                      r.status == 200 and got["path"] == "/echo", f"{r.status} {got}")

            # every hop goes through the policy connector: a redirect to a blocked name is refused
            saved_hc = (host_check.is_blocked_host, host_check.is_blocked_address, server._SSRFSafeConnector)
            host_check.is_blocked_host = lambda h: h.rstrip(".") == "localhost"
            host_check.is_blocked_address = lambda a: False
            server._SSRFSafeConnector = lambda ssl=None, **kw: host_check._CheckedConnector(ssl=ssl)
            del recorder_hits[:]
            try:
                async with c.get(f"{base}/r-elsewhere?port={rec.port}", allow_redirects=False) as r:
                    await r.read()
                    check("redirect: a hop to a host the policy blocks is refused (502) and never dialled",
                          r.status == 502 and not recorder_hits, f"{r.status} {recorder_hits}")
                async with c.get(f"{base}/chain/3", allow_redirects=False) as r:
                    body = await r.text()
                    check("redirect: hops to an allowed host still work through the real policy connector",
                          r.status == 200 and body == "CHAIN END", f"{r.status} {body[:60]}")
            finally:
                host_check.is_blocked_host, host_check.is_blocked_address, server._SSRFSafeConnector = saved_hc

            # browser mode: the redirect goes to the browser, with the Location under that site's path
            CONFIG["browser_mode"] = True
            async with c.get(f"{base}/http://127.0.0.1:{upstream.port}/r-plain", allow_redirects=False) as r:
                await r.read()
                check("redirect: in browser mode the 3xx goes to the browser, not followed",
                      r.status == 302 and r.headers.get("Location") == f"/proxy/xyz/http://127.0.0.1:{upstream.port}/login",
                      f"{r.status} {r.headers.get('Location')}")
            async with c.get(f"{base}/http://127.0.0.1:{upstream.port}/r-upper", allow_redirects=False) as r:
                await r.read()
                check("redirect: browser mode keeps an upper-case-scheme Location inside the proxy (no direct hop to the site)",
                      r.status == 302 and r.headers.get("Location") == "/proxy/xyz/https://tracker.example/x",
                      f"{r.status} {r.headers.get('Location')}")
            CONFIG.clear()

            # --- trusted proxy (loopback trusted here): real client, scheme from the proxy
            set_trusted("127.0.0.1/32")
            try:
                CONFIG.clear()
                async with c.get(f"{base}/echo", headers={
                        "CF-Connecting-IP": "192.0.2.77", "X-Forwarded-Proto": "https",
                        "X-Forwarded-Host": "evil.example"}) as r:
                    hdrs = {}
                    for k, v in json.loads(await r.text())["headers"]:
                        hdrs.setdefault(k.lower(), []).append(v)
                    check("trusted proxy: upstream sees the real client address", hdrs.get("x-forwarded-for") == ["192.0.2.77"]
                          and hdrs.get("x-real-ip") == ["192.0.2.77"], str(hdrs))
                    check("trusted proxy: upstream sees https", hdrs.get("x-forwarded-proto") == ["https"], str(hdrs))
            finally:
                set_trusted(*[str(n) for n in saved_nets])

            # --- browser mode: nothing about the member
            CONFIG.clear()
            CONFIG["browser_mode"] = True
            async with c.get(f"{base}/http://127.0.0.1:{upstream.port}/echo",
                             headers={"X-Forwarded-For": "6.6.6.6"}) as r:
                hdrs = {}
                for k, v in json.loads(await r.text())["headers"]:
                    hdrs.setdefault(k.lower(), []).append(v)
                check("browser mode: no address, host or prefix sent to the site",
                      not any(k in hdrs for k in ("x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-prefix")), str(hdrs))
                site = f"/proxy/xyz/http://127.0.0.1:{upstream.port}"
                check("browser mode: Set-Cookie rewritten for every cookie, Path under that site's own path",
                      len(r.headers.getall("Set-Cookie", [])) == 3
                      and all(f"Path={site}/" in x for x in r.headers.getall("Set-Cookie", [])), str(r.headers.getall("Set-Cookie", [])))

            # --- cookies in a real cookie jar: one site's cookies never go to another site
            def sent_cookie(raw):
                for k, v in json.loads(raw)["headers"]:
                    if k.lower() == "cookie":
                        return v
                return ""

            CONFIG.clear()
            CONFIG["browser_mode"] = True
            site_a = f"{base}/http://127.0.0.1:{upstream.port}"
            site_b_url = f"{base}/http://127.0.0.1:{site_b.port}"
            async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as jar_c:
                async with jar_c.get(f"{site_a}/echo") as r:
                    await r.read()
                async with jar_c.get(f"{site_a}/echo") as r:
                    again_a = sent_cookie(await r.text())
                async with jar_c.get(f"{site_b_url}/echo") as r:
                    to_b = sent_cookie(await r.text())
                check("cookies (browser mode): site A's cookies come back to site A", "c=3" in again_a, again_a)
                check("cookies (browser mode): site A's cookies are not sent to site B (two sites)", "c=3" not in to_b and "a=1" not in to_b, to_b)
                # site B's own cookie then stays with site B
                async with jar_c.get(f"{site_b_url}/echo") as r:
                    again_b = sent_cookie(await r.text())
                check("cookies (browser mode): site B's cookies come back to site B", "c=3" in again_b, again_b)
            CONFIG.clear()         # single-site mode: the cookie stays under /proxy/xyz/, not under another connection
            async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as jar_c:
                async with jar_c.get(f"{base}/echo") as r:
                    await r.read()
                async with jar_c.get(f"{base}/echo") as r:
                    same = sent_cookie(await r.text())
                async with jar_c.get(f"http://127.0.0.1:{portal.port}/proxy/other/echo") as r:
                    other = await r.text()
                check("cookies (single site): stored and sent back under /proxy/xyz/", "c=3" in same, same)
                check("cookies (single site): not sent to another connection's path /proxy/other/",
                      not other.startswith("{") or "c=3" not in sent_cookie(other), other[:200])

            # --- revocation ends in-flight proxied responses
            async def revoke_run(buffered, **close_kwargs):
                """Starts a long response, revokes the user after 1 s, returns (outcome, bytes, seconds)."""
                CONFIG.clear()
                CONFIG["timeout"] = 60
                path = "/trickle" if buffered else "/slow?chunks=200&gap=0.1"
                got = b""
                status = 0
                start = time.monotonic()
                outcome = "complete"

                async def reader():
                    nonlocal got, outcome, status
                    try:
                        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as rc:
                            async with rc.get(f"{base}{path}", allow_redirects=False) as r:
                                status = r.status
                                async for chunk in r.content.iter_any():
                                    got += chunk
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        outcome = type(e).__name__

                task = asyncio.create_task(reader())
                await asyncio.sleep(1)
                global REVOKED
                registered = len(server._user_proxy_calls.get(1, {}))
                REVOKED = True      # as after a real revocation: the credential no longer authenticates
                await server.close_user_websockets(1, **close_kwargs)
                try:
                    await asyncio.wait_for(task, 4 if close_kwargs else 25)
                except asyncio.TimeoutError:
                    task.cancel()
                    outcome = "still running"
                REVOKED = False
                return outcome, len(got), time.monotonic() - start, registered, status

            outcome, n, took, registered, status = await revoke_run(False)
            check("revocation: a streamed download is registered while it runs", registered == 1, str(registered))
            check("revocation: close_user_websockets cuts a streamed download within seconds, not as a clean end",
                  outcome not in ("complete", "still running") and took < 4 and 0 < n < 200000, f"{outcome} {n} {took:.1f}s")
            check("revocation: the registry is empty afterwards", not server._user_proxy_calls, str(server._user_proxy_calls))
            outcome, n, took, registered, status = await revoke_run(True)
            check("revocation: a rewritten (buffered) response is cut too",
                  outcome != "still running" and took < 4 and (outcome != "complete" or status != 200),
                  f"{outcome} {status} {n} {took:.1f}s")
            check("revocation: the registry is empty after the buffered one", not server._user_proxy_calls, str(server._user_proxy_calls))
            # the caller's own session (except_token_id) and kept credential kinds are not touched
            CONFIG.clear()
            async with c.get(f"{base}/slow?chunks=5&gap=0.3") as r:
                closer = asyncio.create_task(asyncio.sleep(0.4))
                await closer
                await server.close_user_websockets(1, except_token_id="t")
                await server.close_user_websockets(1, keep_prefixes=("t",))
                data = await r.read()
                check("revocation: the session named in except_token_id (and a kept prefix) keeps its download",
                      len(data) == 5000, str(len(data)))
            await asyncio.sleep(0.3)
            check("revocation: another user's downloads are not touched",
                  await server.close_user_websockets(2) == 0 and not server._user_proxy_calls)

            # --- a revocation that lands while the connection is still being looked up
            #     (after authentication, before the upstream is dialled) is not missed
            global LOOKUP_DELAY, REVOKED
            CONFIG.clear()
            upstream_hits["count"] = 0
            LOOKUP_DELAY = 1.0
            late_outcome = "complete"
            late_status = 0

            async def late_reader():
                nonlocal late_outcome, late_status
                try:
                    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as rc:
                        async with rc.get(f"{base}/count", allow_redirects=False) as r:
                            late_status = r.status
                            await r.read()
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    late_outcome = type(e).__name__

            task = asyncio.create_task(late_reader())
            await asyncio.sleep(0.4)
            registered_early = len(server._user_proxy_calls.get(1, {}))
            REVOKED = True      # as after a real revocation (a client retry would no longer authenticate)
            await server.close_user_websockets(1)
            await asyncio.wait_for(task, 5)
            REVOKED = False
            LOOKUP_DELAY = 0
            check("revocation: a call is registered as soon as the request is authenticated (during the lookup)",
                  registered_early == 1, str(registered_early))
            check("revocation: a revocation during the connection lookup stops the request before the upstream is called",
                  upstream_hits["count"] == 0 and late_status != 200, f"{upstream_hits} {late_outcome} {late_status}")
            check("revocation: the registry is empty after the early one", not server._user_proxy_calls, str(server._user_proxy_calls))

            # --- a revocation that lands while a WebSocket upgrade is being answered is not missed
            CONFIG.clear()
            upstream_hits["ws"] = 0
            real_ws_response = server.web.WebSocketResponse

            class SlowPrepareWs(real_ws_response):
                async def prepare(self, request):
                    result = await super().prepare(request)
                    await asyncio.sleep(0.8)        # the window: after the upgrade, before the relay is set up
                    return result

            server.web.WebSocketResponse = SlowPrepareWs
            ws_outcome = "open"

            async def ws_client():
                nonlocal ws_outcome
                try:
                    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as wc:
                        async with wc.ws_connect(f"{base}/wscount") as cws:
                            msg = await asyncio.wait_for(cws.receive(), 5)
                            ws_outcome = f"{msg.type.name} {cws.close_code}"
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    ws_outcome = type(e).__name__

            task = asyncio.create_task(ws_client())
            await asyncio.sleep(0.4)
            REVOKED = True
            await server.close_user_websockets(1)
            await asyncio.wait_for(task, 8)
            REVOKED = False
            await asyncio.sleep(0.3)
            server.web.WebSocketResponse = real_ws_response
            check("revocation: a revocation during the WebSocket upgrade ends the relay before the upstream is dialled",
                  upstream_hits["ws"] == 0 and ws_outcome != "open", f"{upstream_hits} {ws_outcome}")
            check("revocation: both registries are empty after the WebSocket one",
                  not server._user_proxy_calls and not server._user_websockets, f"{server._user_proxy_calls} {server._user_websockets}")

            # --- no further redirect hop is made once the call was aborted
            CONFIG.clear()
            upstream_hits["slowchain"] = 0

            async def chain_reader():
                try:
                    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as rc:
                        async with rc.get(f"{base}/slowchain/8", allow_redirects=False) as r:
                            await r.read()
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

            task = asyncio.create_task(chain_reader())
            await asyncio.sleep(0.8)
            REVOKED = True
            await server.close_user_websockets(1)
            await asyncio.wait_for(task, 5)
            REVOKED = False
            at_revoke = upstream_hits["slowchain"]
            await asyncio.sleep(3)
            check("revocation: a chain cut by a revocation answers and ends cleanly (end to end; the hop helper check below proves the stop)",
                  1 <= upstream_hits["slowchain"] <= 6,
                  f"at revoke {at_revoke}, later {upstream_hits['slowchain']}")
            check("revocation: the registry is empty after the chain", not server._user_proxy_calls, str(server._user_proxy_calls))

            # the hop loop itself: an aborted call gets the redirect as it is, no new hop is dialled
            # (aiohttp may also cancel the handler when the client goes, so this is checked on the helper)
            upstream_hits["slowchain"] = 0
            fake_call = server._ProxyHttpCall(None)
            origin = f"http://127.0.0.1:{upstream.port}"

            async def abort_soon():
                await asyncio.sleep(0.45)
                fake_call.aborted = True

            aborter = asyncio.create_task(abort_soon())
            async with aiohttp.ClientSession() as hop_session:
                async with server._proxy_open_upstream(
                        hop_session, "GET", f"{origin}/slowchain/8", {}, None, follow=True,
                        proxy_prefix="/proxy/xyz", target_origin=origin, own_headers=set(),
                        call=fake_call) as hop_resp:
                    hop_status = hop_resp.status
            await aborter
            await asyncio.sleep(1)
            check("revocation: _proxy_open_upstream makes no further hop once the call is aborted, and returns the redirect",
                  hop_status == 302 and upstream_hits["slowchain"] == 2, f"{hop_status} {upstream_hits['slowchain']}")

            # --- buffered path has a total time cap equal to the timeout
            CONFIG.clear()
            CONFIG["timeout"] = 5
            start = time.monotonic()
            async with c.get(f"{base}/trickle") as r:
                await r.read()
                took = time.monotonic() - start
                check("buffered: a rewritten response that trickles in is cut at the timeout in total (504 after about 5 s, not 200 after 12 s)",
                      r.status == 504 and 4 < took < 9, f"{r.status} {took:.1f}s")

            # --- timeout split
            CONFIG.clear()
            CONFIG["timeout"] = 5       # the smallest allowed

            async def long_download():
                start = time.monotonic()
                async with c.get(f"{base}/slow?chunks=6&gap=2") as r:
                    data = await r.read()
                return r.status, len(data), time.monotonic() - start

            async def stalled_download():
                try:
                    async with c.get(f"{base}/stall") as r:
                        await r.read()
                    return "complete"
                except (aiohttp.ClientPayloadError, aiohttp.ClientError, asyncio.TimeoutError) as e:
                    return type(e).__name__

            async def hung_upstream():
                start = time.monotonic()
                async with c.get(f"{base}/hang") as r:
                    await r.read()
                return r.status, time.monotonic() - start

            # --- the upstream drops the connection after the download began
            seen = b""
            outcome = "complete"
            status_abort = 0

            async def drop_download():
                nonlocal seen, outcome, status_abort
                try:
                    async with c.get(f"{base}/abort") as r:
                        status_abort = r.status
                        async for chunk in r.content.iter_any():
                            seen += chunk
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    outcome = type(e).__name__

            class Capture(logging.Handler):
                def __init__(self):
                    super().__init__(logging.DEBUG)
                    self.records = []

                def emit(self, record):
                    self.records.append(record)

            cap = Capture()
            logging.getLogger().addHandler(cap)
            old_level = logging.getLogger().level
            logging.getLogger().setLevel(logging.DEBUG)
            try:
                await asyncio.wait_for(drop_download(), 20)
            except asyncio.TimeoutError:
                outcome = "hung"
            await asyncio.sleep(0.3)
            noisy = [r for r in cap.records if r.levelno >= logging.ERROR or r.exc_info and r.levelno >= logging.WARNING]
            warns = [r for r in cap.records if r.levelno == logging.WARNING]
            check("mid-stream reset: logged as one warning line, no error, no traceback",
                  not noisy and len(warns) == 1 and "cut short" in warns[0].getMessage(),
                  str([(r.levelname, r.getMessage()[:80]) for r in cap.records if r.levelno >= logging.WARNING]))
            # an upstream that goes silent mid-download (idle timeout) is logged the same way
            del cap.records[:]
            CONFIG["timeout"] = 5
            outcome_idle = await asyncio.wait_for(stalled_download(), 20)
            await asyncio.sleep(0.3)
            noisy = [r for r in cap.records if r.levelno >= logging.ERROR or r.exc_info and r.levelno >= logging.WARNING]
            warns = [r for r in cap.records if r.levelno == logging.WARNING]
            check("idle timeout mid-stream: logged as one warning line, no error, no traceback",
                  outcome_idle != "complete" and not noisy and len(warns) == 1 and "cut short" in warns[0].getMessage(),
                  str([(r.levelname, r.getMessage()[:80]) for r in cap.records if r.levelno >= logging.WARNING]))
            logging.getLogger().removeHandler(cap)
            logging.getLogger().setLevel(old_level)
            check("mid-stream reset: the client gets no error page spliced into the download",
                  b"502" not in seen and b"Bad Gateway" not in seen and b"Cannot reach" not in seen and b"<html" not in seen,
                  seen[5000:5300].decode("latin-1"))
            check("mid-stream reset: the download is cut off, not ended as if complete",
                  status_abort == 200 and outcome not in ("complete", "hung") and len(seen) <= 5000, f"{status_abort} {outcome} {len(seen)}")

            long_res, stall_res, hang_res = await asyncio.gather(long_download(), stalled_download(), hung_upstream())
            status, size, took = long_res
            check("timeout: a 12 s download with data flowing survives a 5 s timeout",
                  status == 200 and size == 6000 and took > 10, f"{status} {size} bytes in {took:.1f}s")
            check("timeout: an upstream silent mid-download is cut off (not a clean end)",
                  stall_res != "complete", stall_res)
            check("timeout: an upstream silent before headers gives 504 after about 5 s",
                  hang_res[0] == 504 and 4 < hang_res[1] < 9, str(hang_res))
    finally:
        Config.HOSTNAME = saved_hostname
        (server.authenticate_request, server.db.get_accessible_connection,
         server.db.record_connection_usage, server.resolve_checked_host,
         server.resolve_checked_host_cached, server._SSRFSafeConnector) = saved
        server.db.get_user_by_id, server.db.is_token_valid = saved_cred
        server._searxng_status = saved_sx_status
        await portal.close()
        await upstream.close()
        await site_b.close()
        await rec.close()


asyncio.run(main())

# ---------------------------------------------------------------------------
# Part 3: the dead code is gone and a stored rewrite_urls is still accepted
# ---------------------------------------------------------------------------
from plugins.http_proxy import HTTPProxyPlugin  # noqa: E402
from plugins.base import PluginBase  # noqa: E402

check("http_proxy plugin no longer overrides handle_http", "handle_http" not in HTTPProxyPlugin.__dict__)
check("rewrite_urls is not in the config schema", "rewrite_urls" not in HTTPProxyPlugin.info.config_schema["properties"])
check("preserve_host is not in the config schema (it has no implementation)",
      "preserve_host" not in HTTPProxyPlugin.info.config_schema["properties"])
check("a stored config with preserve_host still validates", HTTPProxyPlugin().validate_config({"target_url": "http://x", "preserve_host": True})[0])
check("the timeout setting still documents 5-300",
      HTTPProxyPlugin.info.config_schema["properties"]["timeout"]["minimum"] == 5
      and HTTPProxyPlugin.info.config_schema["properties"]["timeout"]["maximum"] == 300)
check("a stored config with rewrite_urls validates", HTTPProxyPlugin().validate_config({"target_url": "http://x", "rewrite_urls": False})[0])
check("the base class default is kept", hasattr(PluginBase, "handle_http"))

print()
if failures:
    print(f"test_proxyfix: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("test_proxyfix: all checks passed")
