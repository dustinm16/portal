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

    cap = po.mint(SECRET, user_id=7, token_id="tok1", conn_uuid="cid", ip="203.0.113.5")
    ok = po.verify(SECRET, cap, conn_uuid="cid", ip="203.0.113.5")
    check("capability: a good one verifies and names the viewer's session", ok and ok["user_id"] == 7 and ok["token_id"] == "tok1")
    check("capability: it is a plain path segment", "/" not in cap and cap.startswith("~") and len(cap) < 200, cap)
    check("capability: another connection is refused", po.verify(SECRET, cap, conn_uuid="other", ip="203.0.113.5") is None)
    check("capability: another address is refused", po.verify(SECRET, cap, conn_uuid="cid", ip="203.0.113.6") is None)
    check("capability: another secret is refused", po.verify("t" * 64, cap, conn_uuid="cid", ip="203.0.113.5") is None)
    prefix = getattr(po, "CAP_PREFIX", "~")
    body, _, mac = cap[len(prefix):].partition(".")
    check("capability: a changed body is refused", po.verify(SECRET, prefix + body[:-1] + ("A" if body[-1] != "A" else "B") + "." + mac,
                                                             conn_uuid="cid", ip="203.0.113.5") is None)
    check("capability: a cut mac is refused", po.verify(SECRET, cap[:-3], conn_uuid="cid", ip="203.0.113.5") is None)
    old = po.mint(SECRET, user_id=7, token_id="tok1", conn_uuid="cid", ip="203.0.113.5", now=time.time() - 10 * 3600)
    check("capability: an expired one is refused", po.verify(SECRET, old, conn_uuid="cid", ip="203.0.113.5") is None)
    check("capability: junk is refused", all(po.verify(SECRET, j, conn_uuid="cid", ip="1") is None
                                             for j in ("", "~", "~.", "~a.b", "x", "~" + "A" * 900, "~alice", "~pc1.", "~pc1.a.b")))
    # (1.24.1) only the exact minted shape is a capability: a path that merely starts with "~" is the application's own
    isc = getattr(po, "is_capability", None)
    check("capability shape: a minted one is recognised", isc is not None and isc(cap), cap)
    flipped = cap[:-1] + ("A" if cap[-1] != "A" else "B")
    check("capability shape: a well-formed one with a wrong MAC is still a capability (and refused by verify)",
          isc is not None and isc(flipped) and po.verify(SECRET, flipped, conn_uuid="cid", ip="203.0.113.5") is None)
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
    check("fetch metadata: Origin null refused even with same-origin metadata", r("POST", "/api/x", {"Origin": "null", "Sec-Fetch-Site": "same-origin"}, own) is not None)
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
    check("cookie path: dot segments and relative paths are treated as missing",
          po.clean_cookie_path("/a/../b") == "" and po.clean_cookie_path("/a/%2e%2e/b") == "" and po.clean_cookie_path("a") == ""
          and po.clean_cookie_path("/a/b") == "/a/b")


# ---------------------------------------------------------------------------------------------------------
# Part 2: the real app
# ---------------------------------------------------------------------------------------------------------

PAGE = ("<!doctype html><html><head><title>t</title></head><body>hello"
        "<script>fetch('/api/me')</script></body></html>")


async def page(request):
    resp = web.Response(text=PAGE, content_type="text/html")
    resp.headers.add("Set-Cookie", "sid=1; Path=/; HttpOnly")
    resp.headers.add("Set-Cookie", f"{Config.SESSION_COOKIE_NAME}=evil; Path=/proxy/x/")
    resp.headers.add("Set-Cookie", f"{Config.SESSION_COOKIE_NAME.upper()}=evil2; Path=/")
    resp.headers.add("Set-Cookie", "dots=1; Path=/proxy/abc/../../")
    resp.headers["Clear-Site-Data"] = '"cookies", "storage"'
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Content-Security-Policy"] = "default-src *"
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
    web_a = await conn("adm", "admin-web")                          # an administrator's
    br_a = await conn("adm", "admin-browser", json.dumps({"browser_mode": True}))
    br_m = await conn("owner", "member-browser", json.dumps({"browser_mode": True}))
    for u in (web_m, web_a, br_a, br_m):
        for who in ("bob", "adm2"):
            cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
            if await db.get_user_connection_by_uuid(u, env.uid[who]) is None:
                await db.add_connection_share(cid, env.uid[who], env.uid["owner"], None)
    # the first-open notice (1.24.1) was answered with Continue by the two recipients, except for web_n below
    for u in (web_m, web_a, br_a, br_m):
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
    st, hd, body = await get(bob, f"/proxy/{web_a}/page")
    check("an administrator's web connection opened by a member is served in place, unsandboxed",
          st == 200 and hd.getall("Content-Security-Policy", []) == [server._PROXY_HTML_CSP], f"{st} {hd.getall('Content-Security-Policy', [])}")
    st, hd, body = await get(adm, f"/proxy/{web_a}/page")
    check("an administrator opening their own is unchanged too", st == 200 and "sandbox" not in str(hd.getall("Content-Security-Policy", [])))

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
        check(f"{label}: the frame script that reports address and title to the embedded browser is injected",
              b"portalFrame" in body)
    # the capability address works without any cookie, and for sub-resources and other methods
    st, hd, _ = await get(bob, f"/proxy/{web_m}/data")
    cap_base = hd["Location"].rsplit("/data", 1)[0]
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
            check("a preflight is answered by the portal", r.status == 204 and r.headers.get("Access-Control-Allow-Origin") == "*"
                  and r.headers.get("Access-Control-Allow-Headers") == "x-a", f"{r.status} {dict(r.headers)}")
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
