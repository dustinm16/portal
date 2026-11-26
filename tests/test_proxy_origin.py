"""Proxied pages must not be able to act as the person viewing them (release 1.24.1).

Part 1 is the pure rules (proxy_origin.py). Part 2 runs the real app on a loopback test server with a
temporary database (tests/grant_harness.py): a member's web connection shared with a member and with an
administrator, an administrator's own, one in browser mode, against a local upstream whose pages try to
plant cookies. What a page's script can then do in a browser is proven by tests/test_proxy_origin_browser.py
(skipped without Chromium); here the headers that make the browser isolate it, the credential in the path,
the cookie rules and the cross-site refusal are checked on the wire.

Run: venv/bin/python tests/test_proxy_origin.py
"""

import asyncio
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
from config import Config  # noqa: E402

try:
    import proxy_origin as po
except ImportError:                    # the code under test is missing: say so, do not crash
    po = None
    check("proxy_origin module exists", False)

DEADLINE = 150
SECRET = "s" * 64


def part1():
    if po is None:
        return
    d = po.decide
    base = dict(viewer_id=2, owner_id=1, owner_is_admin=False, browser_mode=False, marked_trusted=False)
    check("trust: a member's connection opened by someone else is isolated", d(**base) == "isolated")
    check("trust: the owner opening their own connection is trusted", d(**dict(base, viewer_id=1)) == "trusted")
    check("trust: an administrator's connection is trusted for anyone", d(**dict(base, owner_is_admin=True)) == "trusted")
    check("trust: a superadmin's mark makes it trusted", d(**dict(base, marked_trusted=True)) == "trusted")
    check("trust: browser mode is isolated for the owner", d(**dict(base, viewer_id=1, browser_mode=True)) == "isolated")
    check("trust: browser mode is isolated for an administrator's connection", d(**dict(base, owner_is_admin=True, browser_mode=True)) == "isolated")
    check("trust: browser mode is isolated even when marked trusted", d(**dict(base, marked_trusted=True, browser_mode=True)) == "isolated")

    conn = {"type": "http", "host": "example.org", "port": 80}
    f0 = po.target_fingerprint(conn, {})
    check("fingerprint: stable", f0 == po.target_fingerprint(dict(conn), {}))
    for label, c2, cfg2 in (("host", dict(conn, host="other.org"), {}), ("port", dict(conn, port=8080), {}),
                            ("type", dict(conn, type="https"), {}), ("target_url", conn, {"target_url": "http://x.org"}),
                            ("browser mode", conn, {"browser_mode": True})):
        check(f"fingerprint: a changed {label} no longer matches", po.target_fingerprint(c2, cfg2) != f0)
    check("fingerprint: unrelated config does not matter", po.target_fingerprint(conn, {"timeout": 30}) == f0)

    cap = po.mint(SECRET, user_id=7, token_id="tok1", conn_uuid="cid")
    ok = po.verify(SECRET, cap, conn_uuid="cid")
    check("capability: a good one verifies and names the viewer's session", ok and ok["user_id"] == 7 and ok["token_id"] == "tok1")
    check("capability: it is a plain path segment", "/" not in cap and cap.startswith("~") and len(cap) < 200, cap)
    check("capability: another connection is refused", po.verify(SECRET, cap, conn_uuid="other") is None)
    # (1.24.2, E34) the address is encrypted: a page that reads its own location learns no member id, session id or connection
    cap34 = po.mint(SECRET, user_id=987654, token_id="sessionid-abcdef", conn_uuid="conn-uuid-123")
    body34 = cap34[len(po.CAP_PREFIX):].partition(".")[0]
    raw34 = po._unb64(body34)
    check("E34 capability: the decoded body shows neither the member id, the session id nor the connection",
          b"987654" not in raw34 and b"sessionid-abcdef" not in raw34 and b"conn-uuid-123" not in raw34
          and b"987654" not in cap34.encode() and "sessionid-abcdef" not in cap34, raw34[:60])
    ok34 = po.verify(SECRET, cap34, conn_uuid="conn-uuid-123")
    check("E34 capability: it still names the member and the session", ok34 and ok34["user_id"] == 987654 and ok34["token_id"] == "sessionid-abcdef", ok34)
    check("E34 capability: it still binds the connection", po.verify(SECRET, cap34, conn_uuid="conn-uuid-124") is None)
    check("E34 capability: two mints of the same viewer differ (random nonce)",
          po.mint(SECRET, user_id=987654, token_id="sessionid-abcdef", conn_uuid="conn-uuid-123", now=1000) !=
          po.mint(SECRET, user_id=987654, token_id="sessionid-abcdef", conn_uuid="conn-uuid-123", now=1000))
    check("E34 capability: it stays a capability and is shorter than the limit", po.is_capability(cap34) and len(cap34) < po.CAP_MAX_LEN, len(cap34))
    # the 1.24.1 readable shape (valid MAC over a base64 JSON body) must no longer verify
    import base64 as _b64m, hashlib as _hl, hmac as _hm
    old_body = _b64m.urlsafe_b64encode(json.dumps([7, "tok1", "cid", int(time.time()) + 3600], separators=(",", ":")).encode()).decode().rstrip("=")
    old_key = _hl.sha256(b"portal-proxy-capability-v1|" + SECRET.encode()).digest()
    old_mac = _b64m.urlsafe_b64encode(_hm.new(old_key, old_body.encode(), _hl.sha256).digest()[:18]).decode().rstrip("=")
    old_cap = f"~pc1.{old_body}.{old_mac}"
    check("E34 capability: a readable 1.24.1 address is a capability by shape but no longer verifies",
          po.is_capability(old_cap) and po.verify(SECRET, old_cap, conn_uuid="cid") is None)
    check("E34 capability: a body that was encrypted under another secret does not verify",
          po.verify("t" * 64, po.mint(SECRET, user_id=7, token_id="tok1", conn_uuid="cid"), conn_uuid="cid") is None)
    check("capability: it is not bound to an address (mint and verify take none): a member whose address changes keeps the page", "ip" not in po.mint.__code__.co_varnames[:po.mint.__code__.co_argcount + po.mint.__code__.co_kwonlyargcount] and "ip" not in po.verify.__code__.co_varnames[:po.verify.__code__.co_argcount + po.verify.__code__.co_kwonlyargcount])
    check("capability: another secret is refused", po.verify("t" * 64, cap, conn_uuid="cid") is None)
    prefix = getattr(po, "CAP_PREFIX", "~")
    body, _, mac = cap[len(prefix):].partition(".")
    check("capability: a changed body is refused", po.verify(SECRET, prefix + body[:-1] + ("A" if body[-1] != "A" else "B") + "." + mac,
                                                             conn_uuid="cid") is None)
    check("capability: a cut mac is refused", po.verify(SECRET, cap[:-3], conn_uuid="cid") is None)
    old = po.mint(SECRET, user_id=7, token_id="tok1", conn_uuid="cid", now=time.time() - 10 * 3600)
    check("capability: an expired one is refused", po.verify(SECRET, old, conn_uuid="cid") is None)
    check("capability: junk is refused", all(po.verify(SECRET, j, conn_uuid="cid") is None
                                             for j in ("", "~", "~.", "~a.b", "x", "~" + "A" * 900, "~alice", "~pc1.", "~pc1.a.b")))
    # (1.24.1) only the exact minted shape is a capability: a path that merely starts with "~" is the application's own
    isc = getattr(po, "is_capability", None)
    check("capability shape: a minted one is recognised", isc is not None and isc(cap), cap)
    flipped = cap[:-1] + ("A" if cap[-1] != "A" else "B")
    check("capability shape: a well-formed one with a wrong MAC is still a capability (and refused by verify)",
          isc is not None and isc(flipped) and po.verify(SECRET, flipped, conn_uuid="cid") is None)
    check("capability shape: ~alice, ~user, ~pc1, ~pc1.x, a short MAC, other characters are not capabilities",
          isc is not None and not any(isc(j) for j in ("~alice", "~user", "~", "~pc1", "~pc1.", "~pc1.x", "~pc1.abc.def",
                                                      "~pc1.ab c." + mac, "~pc2." + body + "." + mac, "pc1." + body + "." + mac,
                                                      prefix + body + "." + mac + "x", prefix + body + "." + mac[:-1])))
    check("capability shape: split_path leaves ~alice/index.html as a normal path",
          po.split_path("~alice/index.html") == (None, "~alice/index.html") and po.split_path("~alice") == (None, "~alice"))
    check("capability shape: strip_capability leaves /proxy/abc/~alice/x alone",
          po.strip_capability("/proxy/abc/~alice/x") == "/proxy/abc/~alice/x")
    check("capability: split_path", po.split_path(cap + "/a/b") == (cap, "a/b") and po.split_path("a/b") == (None, "a/b")
          and po.split_path(cap) == (cap, ""))
    check("capability: removed from a shown address", po.strip_capability(f"/proxy/abc/{cap}/https://x.org/y") == "/proxy/abc/https://x.org/y")

    import logger as portal_logger
    red = portal_logger.redact(f"GET /proxy/abc/{cap}/page?x=1 200")
    check("capability: it is redacted from a log line, an application's own ~alice path is not",
          cap not in red and body not in red and "/proxy/abc/~[REDACTED]/page" in red
          and portal_logger.redact("GET /proxy/abc/~alice/page 200") == "GET /proxy/abc/~alice/page 200", red)

    own = {"portal.example", "stream.example"}
    r = po.cross_site_refusal
    check("fetch metadata: cross-site POST refused", r("POST", "/api/x", {"Sec-Fetch-Site": "cross-site"}, own) is not None)
    check("fetch metadata: same-origin POST allowed", r("POST", "/api/x", {"Sec-Fetch-Site": "same-origin", "Origin": "https://portal.example"}, own) is None)
    check("fetch metadata: same-site POST allowed", r("POST", "/api/x", {"Sec-Fetch-Site": "same-site"}, own) is None)
    check("fetch metadata: Origin null refused", r("DELETE", "/api/x", {"Origin": "null"}, own) is not None)
    # (1.24.2, E3) a same-origin form POST from a no-referrer page carries Origin null: only the null rule is skipped
    check("E3 fetch metadata: Origin null with same-origin metadata passes", r("POST", "/api/x", {"Origin": "null", "Sec-Fetch-Site": "same-origin"}, own) is None)
    check("E3 fetch metadata: Origin null with same-origin metadata still meets the Referer rule",
          r("POST", "/api/x", {"Origin": "null", "Sec-Fetch-Site": "same-origin", "Referer": "https://portal.example/proxy/abc/page"}, own) is not None)
    check("E3 fetch metadata: Origin null with cross-site metadata is refused", r("POST", "/api/x", {"Origin": "null", "Sec-Fetch-Site": "cross-site"}, own) is not None)
    check("E3 fetch metadata: Origin null with same-site metadata is refused", r("POST", "/api/x", {"Origin": "null", "Sec-Fetch-Site": "same-site"}, own) is not None)
    check("E3 fetch metadata: Origin null with no fetch metadata is refused", r("POST", "/api/x", {"Origin": "NULL"}, own) is not None)
    # (1.24.2, E7) a page on a sibling subdomain is same-site, not same-origin
    check("E7 fetch metadata: same-site with a foreign Origin is refused",
          r("POST", "/login", {"Sec-Fetch-Site": "same-site", "Origin": "https://evil.portal.example"}, own) == "same-site foreign origin")
    check("E7 fetch metadata: same-site with one of our own Origins (port included) is allowed",
          r("POST", "/api/x", {"Sec-Fetch-Site": "same-site", "Origin": "https://stream.example"}, own) is None
          and r("POST", "/api/x", {"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:9701"}, {"127.0.0.1:9701"}) is None)
    check("E7 fetch metadata: same-site with a scheme-less or unreadable foreign Origin is refused",
          r("POST", "/api/x", {"Sec-Fetch-Site": "same-site", "Origin": "evil"}, own) is not None)
    check("E7 fetch metadata: same-origin with our Origin is unchanged",
          r("POST", "/login", {"Sec-Fetch-Site": "same-origin", "Origin": "https://portal.example"}, own) is None)
    check("E7 fetch metadata: a safe method from a sibling is not judged",
          r("GET", "/api/x", {"Sec-Fetch-Site": "same-site", "Origin": "https://evil.portal.example"}, own) is None)
    check("fetch metadata: no metadata, foreign Origin refused", r("PUT", "/api/x", {"Origin": "https://evil.example"}, own) is not None)
    check("fetch metadata: no metadata, our Origin allowed", r("PUT", "/api/x", {"Origin": "https://portal.example"}, own) is None)
    check("fetch metadata: no headers at all (script, curl, OBS) allowed", r("POST", "/api/x", {}, own) is None)
    for ref in ("https://portal.example/proxy/abc/page", "https://portal.example/browser?connection=1",
                "https://portal.example/search/", "https://portal.example/proxy/abc/~tok/x"):
        check(f"fetch metadata: Referer {ref} refused", r("POST", "/api/x", {"Referer": ref}, own) is not None)
    check("fetch metadata: Referer of a portal page allowed", r("POST", "/api/x", {"Referer": "https://portal.example/dashboard"}, own) is None)
    check("fetch metadata: /proxyfoo is not under /proxy", r("POST", "/api/x", {"Referer": "https://portal.example/proxyfoo"}, own) is None)
    check("fetch metadata: sign-out from a /search page allowed", r("POST", "/logout", {"Referer": "https://portal.example/search/"}, own) is None)
    check("fetch metadata: push calls from a /search page allowed", r("POST", "/api/push/subscriptions", {"Referer": "https://portal.example/search/?q=a"}, own) is None)
    check("fetch metadata: sign-out from a proxied page refused", r("POST", "/logout", {"Referer": "https://portal.example/proxy/abc/"}, own) is not None)
    check("fetch metadata: other calls from a /search page refused", r("POST", "/api/admin/x", {"Referer": "https://portal.example/search/"}, own) is not None)
    check("fetch metadata: a safe method is never judged", r("GET", "/api/x", {"Sec-Fetch-Site": "cross-site"}, own) is None)
    check("fetch metadata: a cross-site WebSocket upgrade is refused", r("GET", "/ws/chat", {"Sec-Fetch-Site": "cross-site"}, own, websocket=True) is not None)

    check("cookie: the session name is forbidden in any letter case",
          po.forbidden_cookie_name(" Portal_Session ", "portal_session") and po.forbidden_cookie_name("PORTAL_SESSION", "portal_session"))
    check("cookie: other names are not", not po.forbidden_cookie_name("sid", "portal_session")
          and not po.forbidden_cookie_name("__Secure-next-auth.session-token", "portal_session"))
    # (1.24.2, E32) an empty name with the session cookie in the value is sent back by browsers as that cookie
    sn = "portal_session"
    check("E32 cookie: '=portal_session=x' (empty name) is forbidden when the value is given",
          po.forbidden_cookie_name("", sn, "portal_session=x") and po.forbidden_cookie_name(" ", sn, "  Portal_Session=x")
          and po.forbidden_cookie_name("", sn, "PORTAL_SESSION=x; Path=/"))
    check("E32 cookie: ordinary empty-name cookies and other names stay allowed",
          not po.forbidden_cookie_name("", sn, "other=x") and not po.forbidden_cookie_name("", sn, "portal_sessionx=1")
          and not po.forbidden_cookie_name("", sn, "") and not po.forbidden_cookie_name("", sn)
          and not po.forbidden_cookie_name("sid", sn, "portal_session=x")
          and not po.forbidden_cookie_name("", sn, "portal_session") and not po.forbidden_cookie_name("", sn, "portal_sessionx =1")
          and not po.forbidden_cookie_name("", sn, "my portal_session=1"))
    check("E32 cookie: white space between the name and the second '=' does not hide the session cookie",
          po.forbidden_cookie_name("", sn, "portal_session =x") and po.forbidden_cookie_name("", sn, "portal_session\t=x")
          and po.forbidden_cookie_name("", sn, " PORTAL_Session \t = x") and po.forbidden_cookie_name(" ", sn, "portal_session\t =x; Path=/"))
    rw = server._rewrite_set_cookie
    sc_name = Config.SESSION_COOKIE_NAME
    check("E32 cookie: the Set-Cookie rewrite drops '=<session>=x; Path=/' and keeps an ordinary one",
          rw(f"={sc_name}=x; Path=/", "/proxy/abc") is None and rw(f"={sc_name.upper()}=x", "/proxy/abc") is None
          and rw("sid=1; Path=/", "/proxy/abc") is not None and rw("=plain; Path=/", "/proxy/abc") is not None)
    check("E32 cookie: the Cookie header filter drops the pair too",
          server._cookies_without_portal_session(f"a=1; ={sc_name}=x; b=2") == ["a=1", "b=2"])
    check("cookie path: dot segments and relative paths are treated as missing",
          po.clean_cookie_path("/a/../b") == "" and po.clean_cookie_path("/a/%2e%2e/b") == "" and po.clean_cookie_path("a") == ""
          and po.clean_cookie_path("/a/b") == "/a/b")


# ---------------------------------------------------------------------------------------------------------
# Part 2: the real app
# ---------------------------------------------------------------------------------------------------------

PAGE = ("<!doctype html><html><head><title>t</title></head><body>hello"
        "<script>fetch('/api/me')</script></body></html>")


# (1.24.2) pages whose own text tries to keep the embedded browser's report script out or to run before it
FRAME_BODIES = {
    "comment": (b"<!doctype html><html><!--<head>--><head><title>c</title></head><body><h1>c</h1></body></html>", "text/html; charset=utf-8"),
    "early": (b"<!doctype html><script>window.EARLY=1</script><html><head><title>e</title></head><body></body></html>", "text/html"),
    "badutf": (b"<!doctype html><html><head><title>b</title></head><body><h1>x \xff</h1></body></html>", "text/html; charset=utf-8"),
    "upper": (b"<!doctype html><html><head><title>u</title></head><body>u</body></html>", "TEXT/HTML; Charset=UTF-8"),
    "bom": (b"\xef\xbb\xbf  <!-- note --><!DOCTYPE html><html><head></head><body>m</body></html>", "text/html"),
    "nodoc": (b"<p>fragment <b>only</b></p>", "text/html"),
    "badcharset": (b"<!doctype html><html><head><title>x</title></head><body>q</body></html>", "text/html; charset=no-such-charset"),
    "utf16": ("<!doctype html><html><body>w</body></html>".encode("utf-16"), "text/html; charset=utf-16"),
    "xhtml": (b'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>x</title></head><body><script>window.X=1</script></body></html>', "application/xhtml+xml"),
    "xml": (b'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body>x</body></html>', "application/xml"),
}


async def frame_body(request):
    body, ctype = FRAME_BODIES[request.match_info["kind"]]
    return web.Response(body=body, headers={"Content-Type": ctype})


async def page(request):
    resp = web.Response(text=PAGE, content_type="text/html")
    resp.headers.add("Set-Cookie", "sid=1; Path=/; HttpOnly")
    resp.headers.add("Set-Cookie", f"{Config.SESSION_COOKIE_NAME}=evil; Path=/proxy/x/")
    resp.headers.add("Set-Cookie", f"{Config.SESSION_COOKIE_NAME.upper()}=evil2; Path=/")
    resp.headers.add("Set-Cookie", "dots=1; Path=/proxy/abc/../../")
    resp.headers["Clear-Site-Data"] = '"cookies", "storage"'
    resp.headers["Referrer-Policy"] = "unsafe-url"      # (1.24.2, E4) must not reach an isolated page's browser
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Content-Security-Policy"] = "default-src *"
    for name, value in ORIGIN_WIDE.items():
        resp.headers[name] = value
    return resp


# Response headers that act on the whole portal origin (not on the one response): never passed on (1.24.1).
ORIGIN_WIDE = {
    "Strict-Transport-Security": "max-age=0", "Public-Key-Pins": 'pin-sha256="x"; max-age=1',
    "Public-Key-Pins-Report-Only": 'pin-sha256="x"; max-age=1', "Expect-CT": "max-age=0",
    "NEL": '{"report_to":"x","max_age":1}', "Report-To": '{"group":"x","max_age":1,"endpoints":[]}',
    "Origin-Agent-Cluster": "?0", "Accept-CH": "Sec-CH-UA", "Critical-CH": "Sec-CH-UA",
    "Accept-CH-Lifetime": "86400", "Alt-Svc": "clear",
}


async def binary(request):
    """A streamed (not rewritten) answer: its headers are final once sent, no middleware can mend them."""
    resp = web.Response(body=b"\x89PNG....", content_type="image/png")
    for name, value in ORIGIN_WIDE.items():
        resp.headers[name] = value
    return resp


async def data(request):
    return web.json_response({"cookie": request.headers.get("Cookie", ""), "method": request.method,
                              "origin": request.headers.get("Origin")})


async def echo_path(request):
    """Any other path (an Apache userdir style /~user/index.html among them): the upstream says what it was asked."""
    return web.json_response({"path": request.path, "cookie": request.headers.get("Cookie", "")})


async def set_named(request):
    """A cookie with the name in the path: lets two sites set different ones."""
    resp = web.json_response({"set": request.match_info["name"]})
    resp.headers.add("Set-Cookie", f"{request.match_info['name']}=1; Path=/")
    return resp


async def set_secure(request):
    """What an application on a plain-http LAN address behind the portal's https does: a Secure, HttpOnly cookie."""
    resp = web.json_response({"set": "tok"})
    resp.headers.add("Set-Cookie", "tok=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    return resp


async def set_raw(request):
    """Values with characters that aiohttp's default jar quotes when it sends them back (base64 padding,
    a slash, a comma, a space). A browser sends such a value as the upstream set it."""
    resp = web.json_response({"set": "raw"})
    resp.headers.add("Set-Cookie", "PHPSESSID=abc==/x,y; Path=/")
    resp.headers.add("Set-Cookie", "sp=a b; Path=/")
    resp.headers.add("Set-Cookie", "tail=Zm9vYg==; Path=/")
    return resp


async def redir(request):
    """A login that sets its cookie on the redirect the portal follows itself."""
    resp = web.Response(status=302, headers={"Location": "/data"})
    resp.headers.add("Set-Cookie", "hop=1; Path=/")
    return resp


async def wscookie(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_str(request.headers.get("Cookie", ""))
    await ws.close()
    return ws


async def sock(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_str("hi")
    await ws.close()
    return ws


async def bare(request):
    """No Content-Type at all: the sandbox still applies."""
    return web.Response(body=b"<script>1</script>", headers={"Content-Type": ""})


def jar_units():
    """The server-side jar of an isolated page: bounds and filters (no network)."""
    from yarl import URL
    from http.cookies import SimpleCookie
    J = getattr(server, "_IsolatedCookieJars", None)
    check("jars: the registry exists", J is not None)
    if J is None:
        return
    now = [1000.0]
    reg = J(clock=lambda: now[0])
    jar = reg.get(1, "t1", 5, "")
    check("jars: the same key gives the same jar", reg.get(1, "t1", 5, "") is jar and reg.get(1, "t2", 5, "") is not jar
          and reg.get(1, "t1", 6, "") is not jar and reg.get(1, "t1", 5, "http://a") is not jar and reg.get(2, "t1", 5, "") is not jar)
    url = URL("http://10.0.0.5:8080/app/x")
    sc = SimpleCookie()
    sc["sid"] = "1"
    sc["sid"]["path"] = "/"
    sc["sid"]["secure"] = True
    sc[Config.SESSION_COOKIE_NAME.upper()] = "evil"
    sc[Config.SESSION_COOKIE_NAME.upper()]["path"] = "/"
    sc["big"] = "x" * 5000
    sc["big"]["path"] = "/"
    jar.update_cookies(sc, url)
    sent = jar.filter_cookies(url)
    check("jars: a Secure cookie goes to an http upstream, the portal session name never does, even before trim",
          "sid" in sent and not any(n.lower() == Config.SESSION_COOKIE_NAME.lower() for n in sent), str(list(sent)))
    jar.trim()
    check("jars: trim drops the portal session name and a value over 4096 bytes", sorted(m.key for m in jar) == ["sid"], str([m.key for m in jar]))
    flood = SimpleCookie()
    for i in range(80):
        flood[f"c{i}"] = "v"
        flood[f"c{i}"]["path"] = "/"
    jar.update_cookies(flood, url)
    jar.trim()
    check("jars: more than 60 cookies empties the jar", len(jar) == 0, str(len(jar)))
    check("jars: a cookie is not sent to another host", not reg.get(1, "t3", 5, "").filter_cookies(URL("http://10.0.0.6/")))
    one = SimpleCookie()
    one["sid"] = "1"
    one["sid"]["path"] = "/"

    def made(r, u, t, c, site=""):
        jr = r.get(u, t, c, site)
        jr.update_cookies(one, url)
        r.keep(u, t, c, site, jr)
        return jr

    # one member's pages cannot push out another member's logins
    reg2 = J(clock=lambda: now[0])
    ja = made(reg2, 1, "a", 5)
    for i in range(300):           # a page of user 2 asking for a new site each time (browser mode), half of them setting a cookie
        site = f"http://s{i}.example"
        jb = reg2.get(2, "b", 7, site)
        if i % 2:
            jb.update_cookies(one, url)
        reg2.keep(2, "b", 7, site, jb)
    check("jars: 300 sites visited by one member do not push out another member's jar",
          reg2.get(1, "a", 5, "") is ja and len(ja) > 0, str(len(reg2.keys())))
    mine = [k for k in reg2.keys() if k[0] == 2]
    check("jars: a member's own jars are bounded by a quota of their own, their oldest going first",
          len(mine) == reg2.MAX_PER_USER and (2, "b", 7, "http://s1.example") not in mine and (2, "b", 7, "http://s299.example") in mine, str(len(mine)))
    ec = J(clock=lambda: now[0])
    for i in range(50):
        ec.keep(3, "c", 1, f"s{i}", ec.get(3, "c", 1, f"s{i}"))
    check("jars: a jar that holds no cookie is not kept (a page that visits many sites with none set fills nothing)", ec.keys() == [], str(len(ec.keys())))
    p1 = ec.get(3, "c", 1, "x")
    check("jars: concurrent requests of one viewer and site share one jar before any cookie is kept", ec.get(3, "c", 1, "x") is p1)
    # the whole is bounded: many members, each within their quota
    big = J(clock=lambda: now[0])
    for u in range(1, 40):
        for i in range(20):
            made(big, u, "t", i)
    check("jars: the whole registry is bounded, the oldest going first", len(big.keys()) == big.MAX_JARS and (1, "t", 0, "") not in big.keys()
          and (39, "t", 19, "") in big.keys(), str(len(big.keys())))
    now[0] += reg.IDLE_SECONDS + 1
    made(reg, 9, "late", 9)
    check("jars: an idle jar is dropped after the time limit", reg.keys() == [(9, "late", 9, "")], str(len(reg.keys())))
    made(reg, 9, "late2", 9)
    check("jars: forget drops the ones a predicate names", reg.forget(lambda k: k[1] == "late") == 1 and len(reg.keys()) == 1)


async def amain():
    jar_units()
    def make_upstream():
        up = web.Application()
        up.router.add_get("/page", page)
        up.router.add_get("/fj/{kind}", frame_body)
        up.router.add_get("/binary", binary)
        up.router.add_route("*", "/data", data)
        up.router.add_get("/ws", sock)
        up.router.add_get("/bare", bare)
        up.router.add_get("/set/{name}", set_named)
        up.router.add_get("/secure", set_secure)
        up.router.add_get("/redir", redir)
        up.router.add_get("/setraw", set_raw)
        up.router.add_get("/wscookie", wscookie)
        up.router.add_get("/{tail:.*}", echo_path)          # last: every path not named above
        return TestServer(up, host="127.0.0.1")
    upstream = make_upstream()
    await upstream.start_server()
    upstream_b = make_upstream()                              # a second site, for browser mode
    await upstream_b.start_server()

    # (1.24.2) an upstream that writes its answer byte for byte (aiohttp's own server would add a Content-Type of its
    # own to an answer that has none): repeated, comma-listed, empty, missing and odd Content-Type headers
    html_body = b"<!doctype html><html><head><title>raw</title></head><body><script>window.R=1</script></body></html>"
    xhtml_body = b'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body>x</body></html>'
    raw_cases = {
        "repeat": ([b"text/plain", b"text/html"], html_body), "comma": ([b"text/plain, text/html"], html_body),
        "missing": ([], html_body), "empty": ([b""], html_body), "three": ([b"text/html", b"text/plain", b"image/png"], html_body),
        "xhtml_comma": ([b"application/xhtml+xml, text/html"], xhtml_body), "junk": ([b"not a type"], html_body),
        "odd": ([b'TEXT/HTML ; Charset="UTF-8"'], html_body), "semicolon": ([b"text/html;"], html_body),
        "same_twice": ([b"text/html", b"Text/HTML"], html_body),
        "xhtml_odd": ([b"Application/XHTML+XML; charset=utf-8"], xhtml_body),
        "svg": ([b"IMAGE/SVG+XML"], b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>"),
        "bytes": ([b'multipart/byteranges; boundary="abc"'], b"--abc\r\n\r\nx\r\n--abc--"),
        "mixed": ([b"Multipart/X-Mixed-Replace; boundary=frame"], b"--frame\r\nContent-Type: text/html\r\n\r\n<script>1</script>\r\n--frame--"),
        "xsl": ([b"text/xsl"], b"<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>"),
    }
    # (1.24.2) charset reading of an isolated text/html answer: name -> (Content-Type lines, body, header expected, text the
    # body must come out as once the report script is taken away (bytes), or None when it is the body itself)
    cs_doc = "<!doctype html><html><head><title>caf\u00e9</title></head><body>caf\u00e9 \u20ac</body></html>"
    cs_latin = b'<!doctype html><html><head><meta charset="windows-1252"><title>t</title></head><body>caf\xe9 \x80</body></html>'
    cs_ascii = b"<!doctype html><html><head><title>t</title></head><body>x</body></html>"
    cs_hebrew = b"<!doctype html><title>t</title>" + "\u05e9\u05dc\u05d5\u05dd".encode("iso8859_8")
    cs_jis_meta = ('<!doctype html><meta charset="iso-2022-jp"><title>t</title>' + "\u65e5\u672c\u8a9e").encode("iso2022_jp")
    charset_cases = {
        "cs_u16le": ([b"text/html"], b"\xff\xfe" + cs_doc.encode("utf-16-le"), "text/html; charset=utf-8", cs_doc.encode("utf-8")),
        "cs_u16be": ([b"text/html"], b"\xfe\xff" + cs_doc.encode("utf-16-be"), "text/html; charset=utf-8", cs_doc.encode("utf-8")),
        "cs_u32le": ([b"text/html"], b"\xff\xfe\x00\x00" + cs_doc.encode("utf-32-le"), "text/html; charset=utf-8", cs_doc.encode("utf-8")),
        "cs_u16_declared": ([b"text/html; charset=windows-1252"], b"\xff\xfe" + cs_doc.encode("utf-16-le"), "text/html; charset=utf-8", cs_doc.encode("utf-8")),
        "cs_u8bom": ([b"text/html"], b"\xef\xbb\xbf" + cs_doc.encode("utf-8"), "text/html; charset=utf-8", None),
        "cs_u8bom_declared": ([b"text/html; charset=windows-1252"], b"\xef\xbb\xbf" + cs_doc.encode("utf-8"), "text/html; charset=utf-8", None),
        "cs_1252": ([b"text/html; charset=windows-1252"], cs_latin, "text/html; charset=windows-1252", None),
        "cs_none_utf8": ([b"text/html"], cs_doc.encode("utf-8"), "text/html; charset=utf-8", None),
        # a meta tag in the first bytes names the charset, as it does for a browser: it is sent, so the browser need not find it
        # again behind the scripts the proxy puts in front of it
        "cs_none_latin": ([b"text/html"], cs_latin, "text/html; charset=windows-1252", None),
        "cs_unknown_utf8": ([b"text/html; charset=no-such-charset"], cs_doc.encode("utf-8"), "text/html; charset=utf-8", None),
        "cs_unknown_latin": ([b"text/html; charset=no-such-charset"], cs_latin, "text/html; charset=windows-1252", None),
        # no label of any kind, not UTF-8: every byte is kept, no charset is sent
        "cs_nometa_latin": ([b"text/html"], cs_latin.replace(b'<meta charset="windows-1252">', b""), "text/html", None),
        # a label a browser does not know (EBCDIC) is none: the ASCII page is UTF-8 and the proxy's script stays readable
        "cs_ebcdic": ([b"text/html; charset=cp037"], cs_ascii, "text/html; charset=utf-8", None),
        "cs_utf7": ([b"text/html; charset=utf-7"], cs_ascii, "text/html; charset=utf-8", None),
        # a label a browser knows but Python does not name that way is used and sent as it was
        "cs_hebrew_i": ([b"text/html; charset=iso-8859-8-i"], cs_hebrew, "text/html; charset=iso-8859-8-i", None),
        "cs_sjis_label": ([b"text/html; charset=windows-31j"], cs_ascii + "\u65e5\u672c".encode("cp932"), "text/html; charset=windows-31j", None),
        "cs_1252_undefined": ([b"text/html; charset=windows-1252"], b"<!doctype html><title>t</title>\x81\x8d", "text/html; charset=windows-1252", None),
        # ISO-2022-JP is 7-bit: valid UTF-8 as well, but the meta tag decides, and without one nothing is claimed
        "cs_jis_meta": ([b"text/html"], cs_jis_meta, "text/html; charset=iso-2022-jp", None),
        "cs_jis_nometa": ([b"text/html"], cs_jis_meta.replace(b'<meta charset="iso-2022-jp">', b""), "text/html", None),
    }
    for _name, (_cts, _body, _hdr, _text) in charset_cases.items():
        raw_cases[_name] = (_cts, _body)

    async def raw_serve(reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            path = head.split(b" ", 2)[1].decode("latin-1").split("?")[0]
            cts, body = raw_cases.get(path.rsplit("/", 1)[-1], ([b"text/plain"], b"?"))
            lines = b"".join(b"Content-Type: " + v + b"\r\n" for v in cts)
            writer.write(b"HTTP/1.1 200 OK\r\n" + lines + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
    raw_up = await asyncio.start_server(raw_serve, "127.0.0.1", 0)
    raw_port = raw_up.sockets[0].getsockname()[1]

    env = await h.boot(names=("owner", "bob", "carol", "adm", "adm2"), superadmin=("adm", "adm2"))
    db = env.db
    owner, bob, adm = env.sessions["owner"], env.sessions["bob"], env.sessions["adm"]

    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    async def conn(who, name, config="{}"):
        uuid = await db.create_user_connection(env.uid[who], name, "http", "127.0.0.1", upstream.port, config)
        return uuid

    web_m = await conn("owner", "member-web")                       # a member's web connection
    web_raw = await db.create_user_connection(env.uid["owner"], "member-raw", "http", "127.0.0.1", raw_port, "{}")   # (1.24.2) the byte-for-byte upstream
    web_a = await conn("adm", "admin-web")                          # an administrator's
    br_a = await conn("adm", "admin-browser", json.dumps({"browser_mode": True}))
    br_m = await conn("owner", "member-browser", json.dumps({"browser_mode": True}))
    for u in (web_m, web_raw, web_a, br_a, br_m):
        for who in ("bob", "adm2"):
            cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
            if await db.get_user_connection_by_uuid(u, env.uid[who]) is None:
                await db.add_connection_share(cid, env.uid[who], env.uid["owner"], None)
    # the first-open notice (1.24.1) was answered with Continue by the two recipients, except for web_n below
    for u in (web_m, web_raw, web_a, br_a, br_m):
        for who in ("bob", "adm2"):
            async with env.sessions[who].post(f"{env.base}/api/connections/{u}/notice") as r:
                assert r.status == 200, (who, r.status)

    async def get(sess, url, **kw):
        kw.setdefault("allow_redirects", False)
        async with sess.get(env.base + url, **kw) as r:
            body = await r.read()
            return r.status, r.headers, body

    # ---- trusted: unchanged -----------------------------------------------------------------------------
    st, hd, body = await get(owner, f"/proxy/{web_m}/page")
    check("the owner opening their own web connection is served in place (no redirect)", st == 200 and b"hello" in body, str(st))
    csp = hd.getall("Content-Security-Policy", [])
    check("... with the permissive page policy and no sandbox", csp == [server._PROXY_HTML_CSP], str(csp))
    sc = hd.getall("Set-Cookie", [])
    check("... its cookies still arrive, moved under the proxy path", any(c.startswith("sid=1") and f"Path=/proxy/{web_m}/" in c for c in sc), str(sc))
    check("... but never one named like the portal session, in any letter case, and no dot-segment path",
          not any(c.lower().startswith(Config.SESSION_COOKIE_NAME) for c in sc) and not any(".." in c for c in sc), str(sc))
    check("... and Clear-Site-Data is not passed on", "Clear-Site-Data" not in hd, str(dict(hd)))
    check("... nor any header that acts on the whole portal origin (HSTS, key pins, Expect-CT, NEL, Report-To, "
          "Origin-Agent-Cluster, Accept-CH, Critical-CH, Alt-Svc)", not [n for n in ORIGIN_WIDE if n in hd and n != "Strict-Transport-Security"], str(dict(hd)))
    check("... so the portal's own HSTS stays", "max-age=31536000" in hd.get("Strict-Transport-Security", ""), str(hd.get("Strict-Transport-Security")))
    st, hd, body = await get(owner, f"/proxy/{web_m}/binary")
    check("a streamed (binary) answer drops them too, and carries no HSTS of the upstream",
          st == 200 and not [n for n in ORIGIN_WIDE if n in hd and (n != "Strict-Transport-Security" or "max-age=0" in hd[n])], str(dict(hd)))
    check("the search proxy drops the same set (and the HTTP proxy tests membership of it)",
          all(n.lower() in server._SEARXNG_RESPONSE_HOP_HEADERS for n in ORIGIN_WIDE)
          and all(n.lower() in server._UPSTREAM_ORIGIN_WIDE_HEADERS for n in ORIGIN_WIDE)
          and "or k in _UPSTREAM_ORIGIN_WIDE_HEADERS" in Path(server.__file__).read_text())
    st, hd, body = await get(bob, f"/proxy/{web_a}/page")
    check("an administrator's web connection opened by a member is served in place, unsandboxed",
          st == 200 and hd.getall("Content-Security-Policy", []) == [server._PROXY_HTML_CSP], f"{st} {hd.getall('Content-Security-Policy', [])}")
    st, hd, body = await get(adm, f"/proxy/{web_a}/page")
    check("an administrator opening their own is unchanged too", st == 200 and "sandbox" not in str(hd.getall("Content-Security-Policy", [])))
    st, hd, body = await get(owner, f"/proxy/{web_m}/page", headers={"Origin": "null"})
    check("E31: a trusted connection answers an Origin null request with no CORS grant of the portal (the upstream's own pass through)",
          st == 200 and "Access-Control-Allow-Origin" not in hd and "Vary" not in hd, str(dict(hd)))
    # a request that is isolated but carries no verified capability (a bearer token served in place) never gets the
    # credentialed answer, whatever its Origin says
    from multidict import CIMultiDict
    class _Req(dict):
        headers = {"Origin": "null"}
    hh = CIMultiDict()
    server._proxy_isolate_headers(hh, _Req())
    check("E31: without a verified capability on the request the answer stays * with no credentials",
          hh.get("Access-Control-Allow-Origin") == "*" and "Access-Control-Allow-Credentials" not in hh and "Vary" not in hh, str(dict(hh)))
    hh = CIMultiDict([("Vary", "Accept-Encoding"), ("Access-Control-Allow-Credentials", "true")])
    capreq = _Req()
    capreq[server._PROXY_CAP_TOKEN] = object()
    server._proxy_isolate_headers(hh, capreq)
    check("E31: with one, Origin null gets null + credentials and Vary: Origin is added next to the upstream's Vary",
          hh.get("Access-Control-Allow-Origin") == "null" and hh.getall("Access-Control-Allow-Credentials") == ["true"]
          and "Origin" in ", ".join(hh.getall("Vary")) and "Accept-Encoding" in ", ".join(hh.getall("Vary")), str(dict(hh)))
    # (1.24.2, E31) Vary: Origin on every answer to a request with a verified capability, merged, never duplicated
    class _ReqNoOrigin(dict):
        headers = {}
    nreq = _ReqNoOrigin()
    nreq[server._PROXY_CAP_TOKEN] = object()
    hh = CIMultiDict([("Vary", "Accept-Encoding")])
    server._proxy_isolate_headers(hh, nreq)
    check("E31: a capability request without Origin null gets '*' and Vary: Origin merged into the upstream's single Vary",
          hh.get("Access-Control-Allow-Origin") == "*" and hh.getall("Vary") == ["Accept-Encoding, Origin"], str(dict(hh)))
    hh = CIMultiDict([("Vary", "Origin"), ("vary", "Accept-Encoding")])
    server._proxy_isolate_headers(hh, nreq)
    server._proxy_isolate_headers(hh, capreq)
    check("E31: an existing Vary: Origin is not repeated, whichever answer is given and however often it is called",
          ", ".join(hh.getall("Vary")).lower().count("origin") == 1, str(hh.getall("Vary")))
    hh = CIMultiDict()
    server._proxy_isolate_headers(hh, capreq)
    check("E31: the credentialed answer gets Vary: Origin when the response had none", hh.getall("Vary") == ["Origin"], str(dict(hh)))
    # Expose-Headers: "*" on a non-credentialed answer, the response's own names on a credentialed one
    hh = CIMultiDict([("X-Total", "1"), ("ETag", "x"), ("Set-Cookie", "a=b"), ("Connection", "close"), ("Transfer-Encoding", "chunked"),
                      ("Access-Control-Allow-Headers", "x"), ("x-total", "2"), ("Bad Name", "1")])
    server._proxy_isolate_headers(hh, capreq)
    exposed = [n.strip() for n in hh.get("Access-Control-Expose-Headers", "").split(",")]
    check("E31: the credentialed answer lists the response's own header names instead of '*'",
          "*" not in exposed and "X-Total" in exposed and "ETag" in exposed and len([n for n in exposed if n.lower() == "x-total"]) == 1
          and hh.get("Access-Control-Allow-Credentials") == "true", str(dict(hh)))
    check("E31: ... never Set-Cookie, a hop-by-hop header, an Access-Control header or an invalid name",
          not any(n.lower() in ("set-cookie", "connection", "transfer-encoding", "bad name") or n.lower().startswith("access-control-") for n in exposed), str(exposed))
    hh = CIMultiDict([("X-Total", "1")])
    server._proxy_isolate_headers(hh, nreq)
    check("E31: a non-credentialed answer keeps Expose-Headers '*'", hh.get("Access-Control-Expose-Headers") == "*", str(dict(hh)))
    hh = CIMultiDict([(f"X-H{i}", "1") for i in range(200)])
    server._proxy_isolate_headers(hh, capreq)
    check("E31: the list of exposed names is bounded", len(hh.get("Access-Control-Expose-Headers", "").split(",")) <= 64, str(len(hh.get("Access-Control-Expose-Headers", ""))))
    hh = CIMultiDict([("Access-Control-Expose-Headers", "X-Evil")])
    server._proxy_isolate_headers(hh, capreq)
    check("E31: an Expose-Headers the upstream sent is replaced", "X-Evil" not in hh.get("Access-Control-Expose-Headers", ""), str(dict(hh)))

    # ---- a path that starts with "~" is the application's own, not a capability (1.24.1) ---------------------
    for label, sess, uuid in (("a member opening an administrator's", bob, web_a), ("the administrator opening their own", adm, web_a),
                              ("the owner opening their own", owner, web_m)):
        for shown, raw in (("~alice", "/~alice/index.html"), ("%7Ealice", "/%7Ealice/index.html"), ("~", "/~/x"), ("~pc1", "/~pc1/x")):
            st, hd, body = await get(sess, f"/proxy/{uuid}{raw}")
            got = ""
            try:
                got = json.loads(body).get("path", "") if st == 200 else ""
            except ValueError:
                pass
            check(f"{label} web connection: /proxy/<id>{raw} reaches the upstream with the path unchanged",
                  st == 200 and got == "/" + raw.split("/", 2)[1].replace("%7E", "~") + "/" + raw.split("/", 2)[2], f"{st} {got} {body[:80]!r}")
    st, hd, body = await get(bob, f"/proxy/{web_m}/~alice/index.html")
    loc = hd.get("Location", "")
    check("a member's isolated connection: /~alice/index.html is entered through the capability redirect, which keeps the path",
          st == 302 and loc.startswith(f"/proxy/{web_m}/~pc1.") and loc.endswith("/~alice/index.html"), f"{st} {loc}")
    st, hd, body = await get(bob, loc)
    check("... and through it the upstream is asked for /~alice/index.html",
          st == 200 and json.loads(body).get("path") == "/~alice/index.html", f"{st} {body[:80]!r}")

    # ---- isolated: a member's connection opened by another member or by an administrator -------------------
    for label, sess in (("member", bob), ("administrator", env.sessions["adm2"])):
        st, hd, body = await get(sess, f"/proxy/{web_m}/page?x=1")
        loc = hd.get("Location", "")
        check(f"{label}: a member's web connection is entered through a redirect to a capability address",
              st == 302 and loc.startswith(f"/proxy/{web_m}/~") and loc.endswith("/page?x=1"), f"{st} {loc}")
        check(f"{label}: the redirect is never cached", "no-store" in hd.get("Cache-Control", ""), str(dict(hd)))
        st, hd, body = await get(sess, loc, headers={"Cookie": ""})
        csp = hd.getall("Content-Security-Policy", [])
        check(f"{label}: the page is served at the capability address", st == 200 and b"hello" in body, str(st))
        check(f"{label}: it carries the sandbox without allow-same-origin, next to the page policy",
              server.proxy_origin.ISOLATED_SANDBOX in csp and server._PROXY_HTML_CSP in csp
              and not any("allow-same-origin" in c for c in csp), str(csp))
        check(f"{label}: no cookie is passed on, no CORS grant of the upstream's survives, nosniff is forced",
              "Set-Cookie" not in hd and hd.get("Access-Control-Allow-Credentials") is None
              and hd.get("Access-Control-Allow-Origin") == "*" and hd.get("X-Content-Type-Options") == "nosniff", str(dict(hd)))
        check(f"{label}: E4 an upstream Referrer-Policy unsafe-url is replaced by no-referrer (the address holds the capability)",
              hd.getall("Referrer-Policy", []) == ["no-referrer"], str(hd.getall("Referrer-Policy", [])))
        check(f"{label}: the frame script that reports address and title to the embedded browser is injected",
              b"portalFrame" in body)
    # the capability address works without any cookie, and for sub-resources and other methods
    st, hd, _ = await get(bob, f"/proxy/{web_m}/data")
    cap_base = hd["Location"].rsplit("/data", 1)[0]
    # (1.24.2) the report script of the embedded browser is the first thing in every isolated HTML document, whatever
    # the page's own text does, and XHTML and XML get no scripts at all (a script that runs without the report script
    # could not be told from a page that never reports)
    marker = b"<script>(function(){\"use strict\";var P=window.parent"
    served = {}
    for kind in ("comment", "early", "badutf", "upper", "bom", "nodoc", "badcharset"):
        st, hd, body = await get(bob, f"{cap_base}/fj/{kind}")
        served[kind] = body
        at = body.find(marker)
        before = body[:at]
        check(f"E1 report script: '{kind}' page is served with the report script", st == 200 and at >= 0 and body.count(marker) == 1, f"{st} {body[:120]!r}")
        check(f"E1 report script: '{kind}' page has nothing of its own before the script but a byte order mark, space, comments and a doctype",
              at >= 0 and not before.replace(b"\xef\xbb\xbf", b"").replace(b"<!-- note -->", b"").strip().lower().replace(b"<!doctype html>", b""), repr(before[:80]))
        check(f"E1 report script: '{kind}' page still has its own text", body.replace(marker, b"").count(FRAME_BODIES[kind][0][-12:]) == 1 or kind == "badutf", repr(body[-40:]))
    check("E1 report script: the report sent while the script runs, before any script of the page, is flagged first (and only that one)",
          served["comment"].count(b"first:1") == 1 and b"send(1);setInterval(send,700)" in served["comment"], repr(served["comment"][:700]))
    check("E1 report script: the flag depends on the argument being 1, so a listener (which gets an event) never sends it",
          b'post("",f===1)' in served["comment"] and b'post("",f)' not in served["comment"] and b'addEventListener("load",send)' in served["comment"], repr(served["comment"][:700]))
    body = served["comment"]
    check("E1 report script: a doctype stays first among the elements (no quirks mode) and the page's comment follows the script",
          body.startswith(b"<!doctype html><script>") and body.find(b"<!--<head>") > body.find(marker) >= 0, repr(body[:80]))
    body = served["badutf"]
    check("E1 report script: a body that is not valid text keeps its bytes (\\xff) and gets the script at byte level", b"\xff" in body and marker in body, repr(body[-60:]))
    st, hd, body = await get(bob, f"{cap_base}/fj/utf16")
    check("E1 report script: an UTF-16 page (byte order mark, declared utf-16) is injected as text and sent as UTF-8 without the mark",
          marker in body and not body.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")) and b"\x00" not in body
          and hd.getall("Content-Type", []) == ["text/html; charset=utf-8"], f"{hd.getall('Content-Type', [])} {body[:40]!r}")
    for kind in ("xhtml", "xml"):
        st, hd, body = await get(bob, f"{cap_base}/fj/{kind}")
        csp = hd.getall("Content-Security-Policy", [])
        check(f"E1 report script: an isolated {kind} document runs no script (the scriptless policy, not the HTML one)",
              st == 200 and server._PROXY_SVG_CSP in csp and server._PROXY_HTML_CSP not in csp and b"portalFrame" not in body, str(csp))
    st, hd, body = await get(owner, f"/proxy/{web_m}/fj/xhtml")
    check("E1 report script: a trusted page of the same type keeps the page policy", st == 200 and server._PROXY_HTML_CSP in hd.getall("Content-Security-Policy", []), str(st))

    # (1.24.2) One Content-Type, the one the proxy acted on. A browser reads repeated headers and comma lists differently
    # from the proxy (the last valid value), so an isolated answer carries exactly one header with one media type, and a
    # missing, empty or ambiguous one becomes application/octet-stream (never rendered, never sniffed).
    cap_raw = (await get(bob, f"/proxy/{web_raw}/ct/odd"))[1]["Location"].rsplit("/ct/odd", 1)[0]
    OCT = ["application/octet-stream"]
    for kind, want_ct, want_html, want_csp in (
            ("repeat", OCT, False, None), ("comma", OCT, False, None), ("missing", OCT, False, None), ("empty", OCT, False, None),
            ("xhtml_comma", OCT, False, None), ("three", OCT, False, None), ("junk", OCT, False, None),
            ("odd", ["text/html; charset=utf-8"], True, server._PROXY_HTML_CSP),
            ("semicolon", ["text/html; charset=utf-8"], True, server._PROXY_HTML_CSP),
            ("same_twice", ["text/html; charset=utf-8"], True, server._PROXY_HTML_CSP),
            ("xhtml_odd", ["application/xhtml+xml; charset=utf-8"], False, server._PROXY_SVG_CSP),
            ("svg", ["image/svg+xml"], False, server._PROXY_SVG_CSP),
            ("bytes", ["multipart/byteranges; boundary=\"abc\""], False, None),
            ("mixed", ["multipart/x-mixed-replace; boundary=\"frame\""], False, server._PROXY_SVG_CSP),
            ("xsl", ["text/xsl"], False, server._PROXY_SVG_CSP)):
        st, hd, body = await get(bob, f"{cap_raw}/ct/{kind}")
        csp = hd.getall("Content-Security-Policy", [])
        check(f"CT {kind}: the isolated answer has exactly one Content-Type, {want_ct}", hd.getall("Content-Type", []) == want_ct, str(hd.getall("Content-Type", [])))
        check(f"CT {kind}: ... and nosniff, and the sandbox", hd.get("X-Content-Type-Options") == "nosniff"
              and any("sandbox" in c for c in csp) and not any("allow-same-origin" in c for c in csp), str(dict(hd)))
        check(f"CT {kind}: the report script is in the page exactly when it is served as HTML",
              (body.count(marker) == 1) == want_html and body.count(marker) <= 1, f"{st} {body[:100]!r}")
        if want_csp:
            check(f"CT {kind}: the page policy follows the same type", want_csp in csp, str(csp))
        else:
            check(f"CT {kind}: no page policy (it is not a document that runs)", server._PROXY_HTML_CSP not in csp and server._PROXY_SVG_CSP not in csp, str(csp))
    # (1.24.2) The proxy and the browser read an isolated HTML document the same way: a byte order mark decides, then a
    # charset the proxy knows (used and sent), else UTF-8 when the bytes are valid UTF-8 (sent as such), else the bytes are
    # kept as they are (only ASCII is inserted) and no charset is sent. The script is in every one of these answers.
    script_b = server._ISOLATED_FRAME_JS.encode("ascii")
    for kind, (_cts, raw_body, want_hdr, want_text) in charset_cases.items():
        st, hd, body = await get(bob, f"{cap_raw}/ct/{kind}")
        check(f"CS {kind}: the answer carries the report script exactly once", st == 200 and body.count(script_b) == 1, f"{st} {body[:80]!r}")
        check(f"CS {kind}: the one Content-Type is exactly {want_hdr!r}", hd.getall("Content-Type", []) == [want_hdr], str(hd.getall("Content-Type", [])))
        want_body = want_text if want_text is not None else raw_body
        # (an answer the proxy reads as text also gets the portal's own address-rewriting script, which is no part of this rule)
        plain = re.sub(rb'<script>\(function\(\)\{"use strict";.*?\}\)\(\);</script>', b"", body, flags=re.S)
        check(f"CS {kind}: nothing but the scripts was added (every other byte is as the proxy read it)",
              plain == want_body, f"{plain[:120]!r}")
        if want_hdr == "text/html":
            check(f"CS {kind}: a page that is not text to the proxy gets the report script and nothing else, byte for byte",
                  body.replace(script_b, b"", 1) == raw_body, f"{body[:120]!r}")
        check(f"CS {kind}: it is a page, not a download", "Content-Disposition" not in hd, str(dict(hd)))
    # (1.24.2) what the proxy made of the pages above
    async def served_cs(kind):
        return (await get(bob, f"{cap_raw}/ct/{kind}"))[2]
    body = await served_cs("cs_jis_meta")
    check("CS cs_jis_meta: an ISO-2022-JP page is decoded, so the script goes in as text and the Japanese text is as it was",
          b"\x1b$B" in body and body.endswith(b"\x1b(B") and script_b in body, f"{body[-40:]!r}")
    # the pre-scan of a meta tag, as a browser's: comments and attributes are not tags, only the first 1024 bytes count
    pre = server._meta_declared_charset
    for what, doc, want in (
            ("charset attribute", b'<meta charset="Shift_JIS">', "shift_jis"),
            ("unquoted", b"<meta charset=utf-8>", "utf-8"),
            ("http-equiv", b'<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-2">', "iso-8859-2"),
            ("in a comment", b'<!-- <meta charset="shift_jis"> --><title>t</title>', None),
            ("in an attribute value", b'<div title="<meta charset=big5>">x</div>', None),
            ("an unknown label is skipped", b'<meta charset="cp037"><meta charset="koi8-r">', "koi8-r"),
            ("past 1024 bytes", b"<!-- " + b"x" * 1100 + b' --><meta charset="big5">', None),
            ("a meta without a charset", b'<meta name="a" content="charset=big5">', None),
            ("spaces around", b"<meta  charset =  'gbk' >", "gbk"),
            ("not a meta tag", b'<metadata charset="big5">', None),
            ("nothing", b"plain text", None)):
        check(f"meta pre-scan: {what}", pre(doc) == want, repr(pre(doc)))
    st, hd, body = await get(owner, f"/proxy/{web_raw}/ct/cs_u16le")
    check("CS: a trusted connection gets the UTF-16 answer byte for byte, with the Content-Type it had",
          st == 200 and body == charset_cases["cs_u16le"][1] and hd.getall("Content-Type", []) == ["text/html"], f"{hd.getall('Content-Type', [])} {body[:20]!r}")
    st, hd, body = await get(owner, f"/proxy/{web_raw}/ct/cs_unknown_latin")
    check("CS: ... and one with an unknown charset keeps that charset in its header",
          st == 200 and body == charset_cases["cs_unknown_latin"][1] and hd.getall("Content-Type", []) == ["text/html; charset=no-such-charset"], str(hd.getall("Content-Type", [])))
    st, hd, body = await get(owner, f"/proxy/{web_raw}/ct/repeat")
    check("CT: a trusted connection keeps the upstream's headers as they were (both Content-Type lines pass through, no nosniff)",
          st == 200 and hd.getall("Content-Type", []) == ["text/plain", "text/html"] and "X-Content-Type-Options" not in hd, str(hd.getall("Content-Type", [])))
    st_missing, hd_missing, body_missing = await get(owner, f"/proxy/{web_raw}/ct/missing")
    trusted_other = {}
    for kind in ("comma", "junk", "three", "empty"):
        st_o, hd_o, body_o = await get(owner, f"/proxy/{web_raw}/ct/{kind}")
        trusted_other[kind] = (st_o, hd_o.getall("Content-Type", []))
    st, hd, body = await get(owner, f"/proxy/{web_raw}/ct/mixed")
    check("CT: a trusted multipart/x-mixed-replace answer gets no policy of the isolated rule", st == 200 and server._PROXY_SVG_CSP not in hd.getall("Content-Security-Policy", []), str(dict(hd)))
    check("CT: ... and a trusted answer without any Content-Type is left as the proxy library makes it (aiohttp's own default, application/octet-stream), with no report script",
          st_missing == 200 and hd_missing.getall("Content-Type", []) == ["application/octet-stream"]
          and body_missing.count(marker) == 0, f"{st_missing} {hd_missing.getall('Content-Type', [])}")
    # (A missing header becomes application/octet-stream on a trusted answer anyway, so the check above cannot tell whether the
    # normalisation ran; these can: it would turn each of them into application/octet-stream.)
    check("CT: ... and trusted answers with a comma list, an unparseable, three different or an empty Content-Type keep it exactly as the upstream sent it",
          trusted_other == {"comma": (200, ["text/plain, text/html"]), "junk": (200, ["not a type"]),
                            "three": (200, ["text/html", "text/plain", "image/png"]), "empty": (200, [""])}, str(trusted_other))
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as bare_c:
        async with bare_c.get(env.base + cap_base + "/data") as r:
            check("a sub-resource under the capability needs no cookie", r.status == 200, str(r.status))
        async with bare_c.get(env.base + cap_base + "/bare") as r:
            await r.read()
            check("a response with no content type is sandboxed as well", server.proxy_origin.ISOLATED_SANDBOX in r.headers.getall("Content-Security-Policy", []),
                  str(dict(r.headers)))
        async with bare_c.post(env.base + cap_base + "/data", data=b"x", headers={"Origin": "null"}) as r:
            j = await r.json()
            check("a POST from the opaque origin goes through (the form of an isolated app)", r.status == 200 and j["method"] == "POST" and Config.SESSION_COOKIE_NAME not in j["cookie"], str(j))
        async with bare_c.options(env.base + cap_base + "/data", headers={
                "Origin": "null", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-a"}) as r:
            check("a preflight from the opaque origin is answered by the portal, with the credentialed null answer (E31)",
                  r.status == 204 and r.headers.get("Access-Control-Allow-Origin") == "null"
                  and r.headers.get("Access-Control-Allow-Credentials") == "true" and "Origin" in r.headers.get("Vary", "")
                  and r.headers.get("Access-Control-Allow-Headers") == "x-a", f"{r.status} {dict(r.headers)}")
        async with bare_c.options(env.base + cap_base + "/data", headers={
                "Origin": "https://other.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-a"}) as r:
            check("E31: a preflight from any other origin is answered as before: *, no credentials",
                  r.status == 204 and r.headers.get("Access-Control-Allow-Origin") == "*"
                  and r.headers.get("Access-Control-Allow-Credentials") is None, f"{r.status} {dict(r.headers)}")
        # (E31) a credentialed request from the opaque origin: the answer carries null + credentials, and nothing of the
        # viewer's portal session is passed on to the upstream
        async with bare_c.get(env.base + cap_base + "/data", headers={"Origin": "null", "Cookie": f"{Config.SESSION_COOKIE_NAME}=x"}) as r:
            j = await r.json()
            check("E31: a GET under the capability from the opaque origin gets Allow-Origin null, Allow-Credentials true and Vary: Origin",
                  r.status == 200 and r.headers.get("Access-Control-Allow-Origin") == "null"
                  and r.headers.get("Access-Control-Allow-Credentials") == "true" and "Origin" in r.headers.get("Vary", ""), f"{r.status} {dict(r.headers)}")
            check("E31: ... and the portal session cookie is still never passed upstream", Config.SESSION_COOKIE_NAME not in j["cookie"], str(j))
        async with bare_c.get(env.base + cap_base + "/binary", headers={"Origin": "null"}) as r:
            await r.read()
            check("E31: a streamed (binary) answer gets the same headers",
                  r.headers.get("Access-Control-Allow-Origin") == "null" and r.headers.get("Access-Control-Allow-Credentials") == "true", str(dict(r.headers)))
        for origin in ("https://other.example", None):
            async with bare_c.get(env.base + cap_base + "/data", headers={"Origin": origin} if origin else {}) as r:
                await r.read()
                check(f"E31: Origin {origin!r}: * and no credentials, with Vary: Origin",
                      r.headers.get("Access-Control-Allow-Origin") == "*" and r.headers.get("Access-Control-Allow-Credentials") is None
                      and "Origin" in r.headers.get("Vary", ""), str(dict(r.headers)))
        bad_cap = cap_base[:-1] + ("A" if cap_base[-1] != "A" else "B")
        async with bare_c.get(env.base + bad_cap + "/data", headers={"Origin": "null"}, allow_redirects=False) as r:
            check("E31: a request without a valid capability gets none of these headers",
                  r.status == 401 and not [n for n in r.headers if n.lower().startswith("access-control-")] and "Origin" not in r.headers.get("Vary", ""),
                  str(dict(r.headers)))
        async with bare_c.options(env.base + bad_cap + "/data", headers={"Origin": "null", "Access-Control-Request-Method": "POST"}, allow_redirects=False) as r:
            check("E31: a preflight without a valid capability gets none of them either",
                  not [n for n in r.headers if n.lower().startswith("access-control-")], f"{r.status} {dict(r.headers)}")
        async with bare_c.get(env.base + "/api/me", headers={"Origin": "null"}) as r:
            check("E31: a portal route outside the capability path gets none of them", r.headers.get("Access-Control-Allow-Credentials") is None
                  and r.headers.get("Access-Control-Allow-Origin") != "null", str(dict(r.headers)))
        async with bare_c.get(env.base + cap_base[:-1] + ("A" if cap_base[-1] != "A" else "B") + "/data", allow_redirects=False) as r:
            check("a well-formed capability that does not verify is a plain 401, not a login redirect, and not cached",
                  r.status == 401 and "no-store" in r.headers.get("Cache-Control", ""), str(r.status))
        async with bare_c.get(env.base + cap_base.replace("/~", "/~x") + "/data", allow_redirects=False) as r:
            check("a segment that is not capability-shaped is an ordinary path: no session, so the login redirect",
                  r.status == 302 and r.headers.get("Location", "").startswith("/login"), f"{r.status} {r.headers.get('Location')}")
        other = await get(owner, f"/proxy/{br_m}/data")          # a different connection (browser mode, owned by the member)
        other_cap = other[1]["Location"] if other[0] == 302 else ""
        check("(a member's browser-mode connection is isolated for its owner too)", other[0] == 302 and "/~" in other_cap, str(other[0]))
        swapped = f"/proxy/{br_m}/" + cap_base.rsplit("/", 1)[1] + "/data"
        async with bare_c.get(env.base + swapped, allow_redirects=False) as r:
            check("a capability of one connection does not open another", r.status == 401, str(r.status))
        async with bare_c.get(env.base + "/api/me", headers={"Origin": "null"}) as r:
            check("the capability address is the only door: /api/me answers 401 without the session", r.status == 401, str(r.status))
        ws = await bare_c.ws_connect(env.base.replace("http", "ws") + cap_base + "/ws", headers={"Origin": "null"})
        msg = await asyncio.wait_for(ws.receive(), 3)
        check("a WebSocket under the capability connects without a cookie, from an opaque origin", msg.data == "hi", str(msg))
        await ws.close()
        refused = False
        try:
            await bare_c.ws_connect(env.base.replace("http", "ws") + f"/proxy/{web_m}/ws", headers={"Origin": "null"})
        except aiohttp.WSServerHandshakeError:
            refused = True
        check("a WebSocket to the connection without a capability or a session is not served", refused)

    # a WebSocket with the session only (no capability) on an isolated connection is refused
    st403 = None
    try:
        await bob.ws_connect(env.base.replace("http", "ws") + f"/proxy/{web_m}/ws")
    except aiohttp.WSServerHandshakeError as e:
        st403 = e.status
    check("a session-only WebSocket to an isolated connection is refused", st403 == 403, str(st403))
    async with bob.post(env.base + f"/proxy/{web_m}/data", data=b"x") as r:
        check("a session-only POST to an isolated connection is refused", r.status == 403, str(r.status))

    # ---- browser mode: isolated for everybody, an administrator's included ------------------------------------
    for label, sess, uuid in (("administrator, own", adm, br_a), ("member, shared", bob, br_a), ("member, own", owner, br_m)):
        st, hd, _ = await get(sess, f"/proxy/{uuid}/http://127.0.0.1:{upstream.port}/page")
        check(f"browser mode ({label}): isolated", st == 302 and "/~" in hd.get("Location", ""), f"{st}")
        st2, hd2, body2 = await get(sess, hd["Location"], headers={"Cookie": ""})
        check(f"browser mode ({label}): sandboxed, no cookie", st2 == 200 and server.proxy_origin.ISOLATED_SANDBOX in hd2.getall("Content-Security-Policy", [])
              and "Set-Cookie" not in hd2, f"{st2} {hd2.getall('Content-Security-Policy', [])}")
        check(f"browser mode ({label}): rewritten links keep the capability",
              hd["Location"].split("/http://")[0].encode() in body2, "")

    # ---- an isolated page keeps its cookies on the server, not in the browser (1.24.1) -----------------------
    def cookie_of(body):
        return json.loads(body).get("cookie", "")
    st, hd, _ = await get(bob, f"/proxy/{web_m}/page")
    jb = hd["Location"].rsplit("/page", 1)[0]
    adm2 = env.sessions["adm2"]
    st, hd, _ = await get(adm2, f"/proxy/{web_m}/page")
    jb2 = hd["Location"].rsplit("/page", 1)[0]
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as cj:
        async with cj.get(env.base + jb + "/page") as r:
            await r.read()
            check("cookies: the page sets some and the browser is still sent none", r.status == 200 and "Set-Cookie" not in r.headers, str(dict(r.headers)))
        async with cj.get(env.base + jb + "/secure") as r:
            await r.read()
            check("cookies: a Secure cookie from a plain-http upstream is taken too", r.status == 200 and "Set-Cookie" not in r.headers)
        async with cj.get(env.base + jb + "/data") as r:
            sent = cookie_of(await r.read())
        check("cookies: the next request of the same viewer carries them to the upstream (an HttpOnly one and a Secure one too)",
              "sid=1" in sent and "tok=abc" in sent, sent)
        check("cookies: never one named like the portal session, never the dot-segment one",
              Config.SESSION_COOKIE_NAME not in sent and "evil" not in sent and "dots" not in sent, sent)
        async with cj.get(env.base + jb + "/set/bobonly") as r:
            await r.read()
        async with cj.get(env.base + jb2 + "/data") as r:
            other = cookie_of(await r.read())
        async with cj.get(env.base + jb + "/data") as r:
            mine_now = cookie_of(await r.read())
        check("cookies: another viewer of the same connection has a jar of their own", "bobonly" in mine_now and "bobonly" not in other, f"{mine_now} / {other}")
        async with cj.get(env.base + jb + "/setraw") as r:
            await r.read()
        async with cj.get(env.base + jb + "/data") as r:
            raw_sent = cookie_of(await r.read())
        # a value that was itself quoted by the upstream still loses its double quotes in aiohttp's parser;
        # that smaller difference is not covered here
        check("cookies: a value with '=', '/', ',' or a space reaches the upstream byte for byte, not quoted or escaped",
              all(p in raw_sent.split("; ") for p in ("PHPSESSID=abc==/x,y", "sp=a b", "tail=Zm9vYg==")), raw_sent)
        async with cj.get(env.base + jb + "/redir") as r:
            hop = cookie_of(await r.read())
        check("cookies: one set on a redirect the portal follows itself is sent on the hop and kept", "hop=1" in hop, hop)
        wsc = await cj.ws_connect(env.base.replace("http", "ws") + jb + "/wscookie")
        wsmsg = await asyncio.wait_for(wsc.receive(), 3)
        await wsc.close()
        check("cookies: the WebSocket upgrade of an isolated page carries the stored cookies", "sid=1" in str(wsmsg.data), str(wsmsg))
        async with cj.get(env.base + jb + "/data", headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}=x"}) as r:
            sent2 = cookie_of(await r.read())
        check("cookies: the portal session cookie a client sends is still never passed on", Config.SESSION_COOKIE_NAME not in sent2, sent2)
        # a second capability of the same session (the page is opened again from the portal) sees the same jar
        st, hd, _ = await get(bob, f"/proxy/{web_m}/data")
        async with cj.get(env.base + hd["Location"]) as r:
            again = cookie_of(await r.read())
        check("cookies: opening the connection again in the same session keeps the login", "sid=1" in again, again)

    # browser mode: one site's cookies never go to another site
    pa, pb = upstream.port, upstream_b.port
    st, hd, _ = await get(owner, f"/proxy/{br_m}/http://127.0.0.1:{pa}/set/a")
    bb = hd["Location"].split("/http://")[0]
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as cj:
        for url in (f"{bb}/http://127.0.0.1:{pa}/set/a", f"{bb}/http://127.0.0.1:{pb}/set/b"):
            async with cj.get(env.base + url) as r:
                await r.read()
                check("browser mode: no Set-Cookie reaches the browser", "Set-Cookie" not in r.headers)
        async with cj.get(env.base + f"{bb}/http://127.0.0.1:{pa}/data") as r:
            at_a = cookie_of(await r.read())
        async with cj.get(env.base + f"{bb}/http://127.0.0.1:{pb}/data") as r:
            at_b = cookie_of(await r.read())
        check("browser mode: site A gets its own cookie back and not site B's", "a=1" in at_a and "b=1" not in at_a, at_a)
        check("browser mode: site B gets its own cookie back and not site A's", "b=1" in at_b and "a=1" not in at_b, at_b)

    # ---- the capability dies with the session and with the share ----------------------------------------------
    st, hd, _ = await get(bob, f"/proxy/{web_m}/data")
    live = hd["Location"]
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c0:
        jbase = live.rsplit("/data", 1)[0]
        async with c0.get(env.base + jbase + "/set/mine") as r:
            await r.read()
        async with c0.get(env.base + live) as r:
            check("(a capability works before the share ends)", r.status == 200)
            check("(and its jar holds the cookie the upstream set)", "mine=1" in cookie_of(await r.read()))
        async with owner.delete(f"{env.base}/api/connections/{web_m}/shares/{env.uid['bob']}") as r:
            check("(the owner ends the share)", r.status == 200, str(r.status))
        async with c0.get(env.base + live) as r:
            check("a capability stops working when the share ends", r.status == 404, str(r.status))
        await db.add_connection_share((await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (web_m,))).fetchone())["id"],
                                      env.uid["bob"], env.uid["owner"], None)
        async with c0.get(env.base + live) as r:
            check("(and works again when it is back)", r.status == 200, str(r.status))
            check("the cookies a viewer had through a share are gone when the share ended and was made again",
                  cookie_of(await r.read()) == "")
        async with c0.get(env.base + jbase + "/set/again") as r:
            await r.read()
        jars = getattr(server, "_isolated_jars", None)
        mine = lambda: [k for k in jars.keys() if k[0] == env.uid["bob"]] if jars is not None else None
        check("(bob has a jar before he signs out)", bool(mine()), str(mine()))
        async with bob.post(env.base + "/logout") as r:
            await r.read()
        check("the jars of a session are gone when it signs out", mine() == [], str(mine()))
        async with c0.get(env.base + live) as r:
            check("a capability stops working when the session is revoked", r.status == 401, str(r.status))

    # ---- logged-out limit: an isolated page's own requests are not "logged out" ----------------------------------
    st, hd, _ = await get(env.sessions["adm2"], f"/proxy/{br_a}/http://127.0.0.1:{upstream.port}/data")
    cl = hd.get("Location", "")
    statuses = []
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c1:
        for _ in range(45):
            async with c1.get(env.base + cl) as r:
                await r.read()
                statuses.append(r.status)
    check("45 requests of one isolated page in a minute are not counted against the logged-out limit (no 429)",
          429 not in statuses and statuses.count(200) == 45, str(sorted(set(statuses))))

    # ---- a capability that no longer verifies: a page navigation goes back through the entry, nothing else does ------
    st, hd, _ = await get(owner, f"/proxy/{br_m}/data")
    seg = hd["Location"].split("/")[3]
    stale = po.mint(server.Config.JWT_SECRET, user_id=env.uid["owner"], token_id="gone", conn_uuid=br_m, now=time.time() - 10 * 3600)
    other_conn = po.mint(server.Config.JWT_SECRET, user_id=env.uid["owner"], token_id="gone", conn_uuid="someone-else")
    nav = {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "cross-site"}
    # a navigation made by the member's browser itself carries the session cookie; one made by an opaque-origin page does not
    sess_cookie = {"Cookie": f"{Config.SESSION_COOKIE_NAME}=" + [c.value for c in owner.cookie_jar if c.key == Config.SESSION_COOKIE_NAME][0]}
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c3:
        async def anon(url, **kw):
            async with c3.request(kw.pop("method", "GET"), env.base + url, allow_redirects=False, **kw) as r:
                return r.status, r.headers, await r.read()
        st, hd, body = await anon(f"/proxy/{br_m}/{stale}/data?x=1", headers=nav)
        check("E2: an expired capability on a navigation without the session cookie (a link clicked in an opaque-origin page) "
              "is a 401 'expired' page, not a redirect to the login page",
              st == 401 and "Location" not in hd and "no-store" in hd.get("Cache-Control", "") and b"This page expired. Reload the tab." in body
              and b"data-portal-expired" in body and b"x=1" not in body, f"{st} {hd.get('Location')} {body[:120]!r}")
        st, hd, body = await anon(f"/proxy/{br_m}/{stale}/data?x=1", headers=nav)
        check("E2: ... and asking again is the same answer (it is not a loop)", st == 401 and b"This page expired" in body, str(st))
        st, hd, _ = await anon(f"/proxy/{br_m}/{stale}/outside?x=1", headers={**nav, "Sec-Fetch-Site": "none"})
        check("E2: a navigation typed or followed from outside (Sec-Fetch-Site none) with no session still goes through the entry",
              st == 302 and hd["Location"] == f"/proxy/{br_m}/outside?x=1", f"{st} {hd.get('Location')}")
        st, hd, body = await anon(f"/proxy/{br_m}/{stale}/doc3?x=3", headers={**nav, "Sec-Fetch-Dest": "frame"})
        check("E2: a frame navigation (Sec-Fetch-Dest frame) with no session is still the 'expired' page", st == 401 and b"This page expired" in body, str(st))
        st, hd, body = await anon(f"/proxy/{br_m}/{stale}/doc3?x=3", headers={**nav, "Sec-Fetch-Dest": "document"})
        check("E2: a top-level navigation (Sec-Fetch-Dest document) with no session from another site goes through the entry, not to the 'expired' page",
              st == 302 and hd["Location"] == f"/proxy/{br_m}/doc3?x=3" and b"This page expired" not in body, f"{st} {hd.get('Location')}")
        st, hd, _ = await anon(hd["Location"], headers={**nav, "Sec-Fetch-Dest": "document"})
        check("E2: ... and the entry sends the signed-out visitor to the login page (a different address, so no loop)",
              st == 302 and "/login" in hd.get("Location", "") and "~pc1" not in hd.get("Location", ""), f"{st} {hd.get('Location')}")
        st, hd, body = await anon(f"/proxy/{br_m}/{stale}/doc3?x=3", headers={**nav, "Sec-Fetch-Dest": "document"})
        check("E2: ... the same stale link again at once is the plain 401 (the window guard)", st == 401 and "Location" not in hd, f"{st} {hd.get('Location')}")
        st, hd, _ = await anon(f"/proxy/{br_m}/{stale}/data?x=2", headers={**nav, **sess_cookie})
        check("an expired capability on a page navigation (iframe) that carries the session is sent through the entry, without the capability",
              st == 302 and hd["Location"] == f"/proxy/{br_m}/data?x=2" and "~pc1" not in hd["Location"], f"{st} {hd.get('Location')}")
        st, hd, _ = await anon(f"/proxy/{br_m}/{stale}/data?x=2", headers={**nav, **sess_cookie})
        check("... the same page again at once is a 401 (a re-entry that fails again is not repeated: no loop)", st == 401, str(st))
        st, hd, _ = await anon(f"/proxy/{br_m}/{other_conn}/deep/page", headers={**nav, **sess_cookie, "Sec-Fetch-Dest": "document"})
        check("a capability of another connection on a document navigation re-enters the same way",
              st == 302 and hd["Location"] == f"/proxy/{br_m}/deep/page", f"{st} {hd.get('Location')}")
        for label, kw in (("a script or image request", {"headers": {"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"}}),
                          ("a fetch", {"headers": {"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}}),
                          ("a request with no fetch metadata", {}),
                          ("a form post", {"method": "POST", "headers": nav, "data": b"a=1"}),
                          ("a socket upgrade", {"headers": {**nav, "Upgrade": "websocket", "Connection": "Upgrade"}})):
            st, hd, body = await anon(f"/proxy/{br_m}/{stale}/sub/{label.split()[1]}", **kw)
            check(f"{label} with an expired capability is a plain 401, never a redirect", st == 401 and "Location" not in hd, f"{st} {hd.get('Location')}")
    st, hd, _ = await get(owner, f"/proxy/{br_m}/data?x=1")
    check("and the entry gives a signed-in member a fresh capability address for the same page",
          st == 302 and "/~pc1." in hd["Location"] and hd["Location"].endswith("/data?x=1"), f"{st} {hd.get('Location')}")

    # ---- item 4: the first-open notice of a shared web connection ----------------------------------------------
    carol = env.sessions["carol"]
    web_n = await conn("owner", "member-notice")
    cid_n = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (web_n,))).fetchone())["id"]
    await db.add_connection_share(cid_n, env.uid["carol"], env.uid["owner"], None)
    st, hd, _ = await get(carol, f"/proxy/{web_n}/page?a=1", headers={"Accept": "text/html"})
    loc = hd.get("Location", "")
    check("a recipient's first open of a shared web connection goes to the notice, with the address to continue to",
          st == 302 and loc.startswith("/shared-app?connection=" + web_n) and "next=%2Fproxy%2F" in loc, f"{st} {loc}")
    st, hd, body = await get(carol, loc)
    text = body.decode()
    check("the notice names the connection and who shared it, and says isolated, with Continue and Cancel",
          st == 200 and "member-notice" in text and "<strong>owner</strong>" in text and "isolated" in text.lower()
          and "shared-continue" in text and "shared-cancel" in text and "onclick" not in text, text[:300])
    st, hd, body = await get(carol, f"/proxy/{web_n}/data", headers={"Accept": "*/*", "Sec-Fetch-Dest": "empty"})
    check("a request that is not a page (a fetch, a form, a socket) is refused until Continue", st == 403, str(st))
    st, hd, body = await get(carol, f"/browser?connection={web_n}")
    check("the embedded browser page asks too", st == 302 and hd.get("Location", "").startswith("/shared-app?connection="), f"{st} {hd.get('Location')}")
    st, hd, body = await get(carol, "/shared-app?connection=" + web_n + "&next=https%3A%2F%2Fevil.example%2F")
    check("the address to continue to can only be this connection's own", st == 200 and b"evil.example" not in body and f"/browser?connection={web_n}".encode() in body)
    st, hd, body = await get(owner, "/shared-app?connection=" + web_n)
    check("the owner has no notice for their own connection", st == 404, str(st))
    async with carol.post(f"{env.base}/api/connections/{web_n}/notice") as r:
        check("Continue is recorded", r.status == 200, str(r.status))
    st, hd, body = await get(carol, f"/proxy/{web_n}/page")
    check("after Continue the connection opens (isolated, through the capability address)", st == 302 and "/~" in hd.get("Location", ""), f"{st} {hd.get('Location')}")
    await db.conn.execute("UPDATE user_connections SET port = port + 1 WHERE id = ?", (cid_n,))
    await db.conn.commit()
    st, hd, body = await get(carol, f"/proxy/{web_n}/page", headers={"Accept": "text/html"})
    check("a changed target asks again", st == 302 and hd.get("Location", "").startswith("/shared-app?"), f"{st} {hd.get('Location')}")
    await db.conn.execute("UPDATE user_connections SET port = port - 1 WHERE id = ?", (cid_n,))
    await db.conn.commit()

    # ---- the superadmin's trust mark -------------------------------------------------------------------------
    adm2 = env.sessions["adm2"]
    async with owner.put(f"{env.base}/api/admin/connections/{web_n}/proxy-trust", json={"trusted": True}) as r:
        check("a member cannot mark a connection trusted", r.status == 403, str(r.status))
    async with adm2.put(f"{env.base}/api/admin/connections/{web_n}/proxy-trust", json={"trusted": True}) as r:
        check("nor can a plain administrator-session listing do it without superadmin rights being checked (adm2 is a superadmin: allowed)",
              r.status == 200, str(r.status))
    st, hd, body = await get(carol, f"/proxy/{web_n}/page")
    check("a marked connection is served in place to its recipient, unsandboxed", st == 200 and hd.getall("Content-Security-Policy", []) == [server._PROXY_HTML_CSP], f"{st}")
    async with adm2.get(f"{env.base}/api/admin/proxy-trust-connections") as r:
        rows = {x["id"]: x for x in (await r.json())["connections"]}
        check("the admin list shows it as trusted, and shows no host, port or config",
              rows.get(web_n, {}).get("trusted") is True and not any(k in rows[web_n] for k in ("host", "port", "config")), str(rows.get(web_n)))
    await db.conn.execute("UPDATE user_connections SET port = port + 1 WHERE id = ?", (cid_n,))
    await db.conn.commit()
    await db.accept_share_notice(cid_n, env.uid["carol"], server.proxy_origin.target_fingerprint(
        await db.get_connection_for_admin(web_n), (await db.get_connection_for_admin(web_n))["config"]))
    st, hd, body = await get(carol, f"/proxy/{web_n}/page")
    check("a changed port ends the mark: isolated again", st == 302 and "/~" in hd.get("Location", ""), f"{st} {hd.get('Location')}")
    await server._drop_stale_proxy_trust(web_n)
    check("and the stored mark is removed", (await db.get_connection_for_admin(web_n))["proxy_trusted_fp"] in (None, ""))
    async with adm2.put(f"{env.base}/api/admin/connections/{br_m}/proxy-trust", json={"trusted": True}) as r:
        check("a connection in browser mode cannot be marked", r.status == 400, str(r.status))
    audit = await (await db.conn.execute("SELECT action FROM audit_log WHERE action LIKE 'connection.proxy_%'")).fetchall()
    check("the mark is audited", [a["action"] for a in audit] == ["connection.proxy_trust"], str([a["action"] for a in audit]))

    # ---- the trust mark never reaches a caller ---------------------------------------------------------------------
    for label, sess in (("owner", owner), ("grantee", env.sessions["adm2"])):
        async with sess.get(f"{env.base}/api/connections") as r:
            txt = await r.text()
        async with sess.get(f"{env.base}/api/connections/{web_m}") as r:
            txt += await r.text()
        check(f"the {label}'s list and detail answers carry no trust mark and no marker", "proxy_trusted" not in txt, txt[:200])
    async with owner.put(f"{env.base}/api/admin/connections/{web_n}/proxy-trust", json={"trusted": True}) as r:
        pass
    key_name = Config.SESSION_COOKIE_NAME
    jwt_adm2 = [c.value for c in adm2.cookie_jar if c.key == key_name][0]
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as nc2:
        async with nc2.put(f"{env.base}/api/admin/connections/{web_n}/proxy-trust", json={"trusted": True},
                           headers={"Authorization": f"Bearer {jwt_adm2}"}) as r:
            check("the trust mark needs a browser session: a bearer token is refused", r.status in (401, 403), str(r.status))

    # ---- item 3: cookie-authenticated state changes ---------------------------------------------------------------
    owner2 = await h.login(env.base, "owner")
    url = f"{env.base}/api/connections/{web_m}/shares"

    async def post(sess, headers, u=url):
        async with sess.post(u, json={"usernames": ["carol"]}, headers=headers) as r:
            await r.read()
            return r.status

    check("cross-site POST with the session cookie is refused", await post(owner2, {"Sec-Fetch-Site": "cross-site"}) == 403)
    check("POST from an opaque origin is refused", await post(owner2, {"Origin": "null"}) == 403)
    check("POST with a Referer under /proxy/ is refused", await post(owner2, {"Referer": f"{env.base}/proxy/{web_a}/x", "Sec-Fetch-Site": "same-origin"}) == 403)
    check("POST with a Referer under /browser is refused", await post(owner2, {"Referer": f"{env.base}/browser?connection={web_a}"}) == 403)
    check("POST with a Referer under /search/ is refused", await post(owner2, {"Referer": f"{env.base}/search/"}) == 403)
    check("DELETE with a cross-site header is refused", (await _status(owner2.delete(f"{url}/{env.uid['carol']}", headers={"Sec-Fetch-Site": "cross-site"}))) == 403)
    check("PUT with a cross-site header is refused", (await _status(owner2.put(f"{env.base}/api/connections/{web_m}", json={}, headers={"Sec-Fetch-Site": "cross-site"}))) == 403)
    check("POST from the portal's own pages (same-origin, dashboard Referer) goes through",
          await post(owner2, {"Sec-Fetch-Site": "same-origin", "Origin": env.base, "Referer": f"{env.base}/dashboard"}) == 200)
    check("POST with no browser headers (a script) goes through", await post(owner2, {}) == 200)
    check("a GET is not judged", (await _status(owner2.get(f"{env.base}/api/me", headers={"Sec-Fetch-Site": "cross-site"}))) == 200)
    cookie_jwt = next(iter(owner2.cookie_jar)).value if False else [c.value for c in owner2.cookie_jar if c.key == Config.SESSION_COOKIE_NAME][0]
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as nc:
        check("a bearer token is not cookie-authenticated: cross-site metadata does not matter",
              await post(nc, {"Authorization": f"Bearer {cookie_jwt}", "Sec-Fetch-Site": "cross-site"}) == 200)
        check("a bad bearer next to the session cookie is still judged as the cookie",
              await post(owner2, {"Authorization": "Bearer nonsense", "Sec-Fetch-Site": "cross-site"}) == 403)
    async with owner2.ws_connect(env.base.replace("http", "ws") + "/ws/chat", headers={"Sec-Fetch-Site": "same-origin"}) as w:
        check("the chat socket opens from a same-origin page", not w.closed)
    for hdrs, label in (({"Sec-Fetch-Site": "cross-site"}, "cross-site"), ({"Origin": "null"}, "opaque origin")):
        code = None
        try:
            await owner2.ws_connect(env.base.replace("http", "ws") + "/ws/chat", headers=hdrs)
        except aiohttp.WSServerHandshakeError as e:
            code = e.status
        check(f"the chat socket refuses a {label} upgrade", code == 403, str(code))
    await owner2.close()

    await h.shutdown(env)
    await upstream.close()
    await upstream_b.close()
    raw_up.close()
    await raw_up.wait_closed()


async def _status(ctx):
    async with ctx as r:
        await r.read()
        return r.status


async def main():
    part1()
    await asyncio.wait_for(amain(), DEADLINE)


try:
    asyncio.run(main())
except asyncio.TimeoutError:
    check(f"finished within {DEADLINE} s", False)
except Exception as exc:               # an unexpected answer (old code): a failure, not a hang
    check("ran to the end without an exception", False, f"{type(exc).__name__}: {exc}")
h.finish("test_proxy_origin")
