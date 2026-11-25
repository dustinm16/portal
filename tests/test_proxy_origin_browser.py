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

# (1.24.2, E1 and E9) A page that lies about where it is, and one that asks the embedded browser to open tabs
# outside its connection. __PROXY__ is /proxy/<browser connection>.
FORGE = r"""<!doctype html><html><head><title>Bank</title></head><body><h1>forged</h1>
<script>
var P = '__PROXY__', i = 0;
var hrefs = [P + '/https://bank.example/login', 'https://bank.example/login', P + '/~/legit-path'];
setInterval(function(){ parent.postMessage({type: 'portalFrame', href: hrefs[i++ % 3], title: 'Bank'}, '*'); }, 250);
</script></body></html>"""

# The same lie, and then the page navigates itself once (location.replace) so the frame has a load after the first.
# Neither the report nor the load may move the bar to another site.
# (The second document also loads /slow.js, which answers after 0.8 s: its load event comes late, and the lie is the last
# report before it. The first document is replaced before it finishes loading.)
FORGE2 = r"""<!doctype html><html><head><title>Bank2</title></head><body><h1>forged again</h1>
__SLOW__
<script>
var P = '__PROXY__';
setInterval(function(){ parent.postMessage({type: 'portalFrame', href: P + '/https://bank.example/login', title: 'Bank2'}, '*'); }, 50);
if (location.search.indexOf('again=1') < 0) setTimeout(function(){ location.replace(location.pathname + '?again=1'); }, 700);
</script></body></html>"""

FORGE_TAB = r"""<!doctype html><html><head><title>tabs</title></head><body><h1>tabs</h1>
<script>
var P = '__PROXY__', bad = [P + '/../../api/me', P + '/%2e%2e/%2e%2e/api/me', P + '/%2E%2e/api/me', P + '/..%2f..%2fapi/me',
  P + '/a/../../api/me', P + '/..\\..\\api/me', 'https://bank.example/', '/api/me', P + '/./x'];
var n = 0;
var t = setInterval(function(){ bad.forEach(function(u){ parent.postMessage({type: 'openTab', url: u}, '*'); }); if (++n > 8) clearInterval(t); }, 250);
setTimeout(function(){ parent.postMessage({type: 'openTab', url: P + '/~/popup'}, '*'); }, 1500);
</script></body></html>"""

# (1.24.2, E31) A page that makes credentialed requests (fetch with credentials: 'include', XHR withCredentials) to its own
# capability address, and to one whose capability is wrong.
CRED = r"""<!doctype html><html><head><title>cred</title></head><body><h1>cred</h1>
<script>
(async function(){
  var out = {}, parts = location.pathname.split('/'), cap = parts[3];
  var bad = cap.slice(0, -1) + (cap.slice(-1) === 'A' ? 'B' : 'A');
  async function t(name, fn){ try { out[name] = await fn(); } catch(e) { out[name] = 'ERR ' + e.name; } }
  await t('fetch', async function(){ var r = await fetch('/credcheck', {credentials: 'include'}); return r.status + ' ' + (await r.text()); });
  await t('xhr', function(){ return new Promise(function(res, rej){ var x = new XMLHttpRequest(); x.open('GET', '/credcheck'); x.withCredentials = true;
        x.onload = function(){ res(x.status + ' ' + x.responseText); }; x.onerror = function(){ rej({name: 'XHRError'}); }; x.send(); }); });
  await t('post', async function(){ var r = await fetch('/credcheck', {method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json', 'X-A': '1'}, body: '{}'}); return r.status; });
  await t('plain', async function(){ var r = await fetch('/credcheck'); return r.status; });
  // the page's own fetch rewrites a path under the portal; a fetch of a fresh frame does not, so the wrong address is really asked for
  await t('badcap', async function(){ var i = document.createElement('iframe'); i.style.display = 'none'; document.body.appendChild(i);
        var r = await i.contentWindow.fetch(location.origin + '/' + parts[1] + '/' + parts[2] + '/' + bad + '/credcheck', {credentials: 'include'}); return r.status; });
  fetch('/__report?tag=cred', {method: 'POST', body: JSON.stringify(out)});
})();
</script></body></html>"""

# (1.24.2, E2) Two pages of a browser-mode site, the first with a link to the second.
STALE1 = "<!doctype html><html><head><title>stale-one</title></head><body><a id='go' href='/stale2'>next</a></body></html>"
STALE2 = "<!doctype html><html><head><title>stale-two</title></head><body><h1>second</h1></body></html>"

# (1.24.2, E1 follow-up) A page of one site with a link to a second site (another host name, so another proxied site).
XLINK = "<!doctype html><html><head><title>xsite-one</title></head><body><a id='go' href='http://localhost:__PORT__/xsecond'>other site</a></body></html>"
# (1.24.2) second-site pages that try to keep the old site's address on the bar: __KIND__ names the case
XL = "<!doctype html><html><head><title>xl-__KIND__</title></head><body><a id='go' href='http://__HOST__:__PORT__/xx/__KIND__'>go</a></body></html>"
XX_SILENT = b"<!doctype html><html><!--<head>--><head><title>xsite-silent</title></head><body><h1>LOOKS LIKE SITE ONE</h1></body></html>"
XX_FORGE = (b"<!doctype html><html><!--<head>--><head><title>xsite-forge</title></head><body><h1>LOOKS LIKE SITE ONE</h1>"
            b"<script>var h=location.href.replace('/http://localhost'+':','/http://127.0.0.1'+':').replace('/xx/forge','/xl/forge');"
            b"setInterval(function(){parent.postMessage({type:'portalFrame',href:h,title:'xl-forge'},'*')},200);</script></body></html>")
XX_BADUTF = b"<!doctype html><html><head><title>xsite-badutf</title></head><body><h1>LOOKS LIKE SITE ONE \xff</h1></body></html>"
XX_GIF = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
XX_NOTITLE = b"<!doctype html><html><head></head><body><h1>LOOKS LIKE SITE ONE</h1></body></html>"
# (1.24.2) an untitled page that stops the injected script's answer to the ping (a setter on Object.prototype that
# throws, as the answer used to set .ping on a plain object) and answers with a forged address of the typed site.
XX_PFORGE = (b"<!doctype html><html><head></head><body><h1>LOOKS LIKE SITE ONE</h1><script>"
             b"Object.defineProperty(Object.prototype,'ping',{set:function(){throw 1}});"
             b"var to=location.search.indexOf('r=1')>=0?'/xr/pforge':'/xl/pforge';"
             b"var h=location.href.replace('/http://localhost'+':','/http://127.0.0.1'+':').replace('/xx/pforge',to).split('?')[0];"
             b"addEventListener('message',function(e){if(e.data&&e.data.type==='portalPing')parent.postMessage({type:'portalFrame',href:h,ping:e.data.id},'*')});"
             b"</script></body></html>")
# (1.24.2) pages that stop the injected script's answer to the ping without touching Object.prototype, and answer with
# a forged address of the typed site: "psrc" makes MessageEvent.prototype.source read null (the injected listener
# returns early), "popen" calls document.open() once the parser is done (a call made while the parser runs is ignored), which removes
# every listener the window had, the injected one too, and only then adds its own forging listener.
XX_PSRC = (b"<!doctype html><html><head></head><body><h1>LOOKS LIKE SITE ONE</h1><script>"
           b"var g=Object.getOwnPropertyDescriptor(MessageEvent.prototype,'data').get;"
           b"Object.defineProperty(MessageEvent.prototype,'source',{get:function(){return null},configurable:true});"
           b"var to=location.search.indexOf('r=1')>=0?'/xr/psrc':'/xl/psrc';"
           b"var h=location.href.replace('/http://localhost'+':','/http://127.0.0.1'+':').replace('/xx/psrc',to).split('?')[0];"
           b"addEventListener('message',function(e){var d=g.call(e);if(d&&d.type==='portalPing')parent.postMessage({type:'portalFrame',href:h,ping:d.id},'*')});"
           b"</script></body></html>")
XX_POPEN = (b"<!doctype html><html><head></head><body><h1>LOOKS LIKE SITE ONE</h1><script>"
            b"var to=location.search.indexOf('r=1')>=0?'/xr/popen':'/xl/popen';"
            b"var h=location.href.replace('/http://localhost'+':','/http://127.0.0.1'+':').replace('/xx/popen',to).split('?')[0];"
            b"setTimeout(function(){document.open();document.write('<h1>LOOKS LIKE SITE ONE</h1>');document.close();"
            b"addEventListener('message',function(e){if(e.data&&e.data.type==='portalPing')parent.postMessage({type:'portalFrame',href:h,ping:e.data.id},'*')})},0);"
            b"</script></body></html>")
XX_HONEST = b"<!doctype html><html><head><title>xsite-honest</title></head><body>same site</body></html>"
XSECOND = "<!doctype html><html><head><title>xsite-two</title></head><body><h1>second site</h1></body></html>"

# (1.24.2) A hostile page behind a Content-Type that the proxy and a browser read differently (a comma list, repeated
# headers). It reports whether it ran and whether the report script of the embedded browser is in it.
CTPAGE = ("<!doctype html><html><head><title>ct-__KIND__</title></head><body><h1>ct page</h1><script>"
          "var inj=false;for(var i=0;i<document.scripts.length;i++){if((document.scripts[i].textContent||'').indexOf('portal'+'Frame')>=0)inj=true}"
          "fetch('/__report?tag=ct',{method:'POST',body:JSON.stringify({kind:'__KIND__',injected:inj,charset:document.characterSet})});</script></body></html>")

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
    from multidict import CIMultiDict
    from config import Config

    results = {}

    async def main():
        env = await h.boot(names=("owner", "bob", "carol", "adm", "adm2"), superadmin=("adm", "adm2"))
        db = env.db
        up = web.Application()
        state = {"uuid_web": "", "uuid_br": "", "posts": []}

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
        up.router.add_get("/forge", lambda r: web.Response(text=FORGE.replace("__PROXY__", "/proxy/" + state["uuid_br"]), content_type="text/html"))
        async def forge2(request):
            results.setdefault("forge2", []).append(request.query_string)
            slow = '<script async src="/slow.js"></script>' if "again=1" in request.query_string else ""
            return web.Response(text=FORGE2.replace("__PROXY__", "/proxy/" + state["uuid_br"]).replace("__SLOW__", slow), content_type="text/html")

        async def slow_js(request):
            await asyncio.sleep(0.8)
            return web.Response(text="window.SLOW = 1;", content_type="application/javascript")

        up.router.add_get("/forge2", forge2)
        up.router.add_get("/slow.js", slow_js)
        up.router.add_get("/forge-tab", lambda r: web.Response(text=FORGE_TAB.replace("__PROXY__", "/proxy/" + state["uuid_br"]), content_type="text/html"))
        up.router.add_get("/cred", lambda r: web.Response(text=CRED, content_type="text/html"))
        up.router.add_route("*", "/credcheck", lambda r: web.json_response({"cookie": r.headers.get("Cookie", ""), "method": r.method}))
        up.router.add_get("/stale", lambda r: web.Response(text=STALE1, content_type="text/html"))
        up.router.add_get("/xlink", lambda r: web.Response(text=XLINK.replace("__PORT__", str(r.url.port)), content_type="text/html"))
        up.router.add_get("/xsecond", lambda r: web.Response(text=XSECOND, content_type="text/html"))
        def xl(r):
            kind = r.match_info["kind"]
            host = "127.0.0.1" if kind == "honest" else "localhost"
            return web.Response(text=XL.replace("__KIND__", kind).replace("__HOST__", host).replace("__PORT__", str(r.url.port)), content_type="text/html")

        def xx(r):
            kind = r.match_info["kind"]
            body, ctype = {"silent": (XX_SILENT, "text/html"), "forge": (XX_FORGE, "text/html"), "badutf": (XX_BADUTF, "text/html; charset=utf-8"),
                           "plain": (b"LOOKS LIKE SITE ONE", "text/plain"), "image": (XX_GIF, "image/gif"), "honest": (XX_HONEST, "text/html"),
                           "notitle": (XX_NOTITLE, "text/html"), "pforge": (XX_PFORGE, "text/html"),
                           "psrc": (XX_PSRC, "text/html"), "popen": (XX_POPEN, "text/html")}[kind]
            return web.Response(body=body, headers={"Content-Type": ctype})

        def xr(r):      # (1.24.2, E1) an address that the upstream answers with a redirect to another site
            raise web.HTTPFound(f"http://localhost:{r.url.port}/xx/{r.match_info['kind']}" + ("?r=1" if r.match_info["kind"] in ("pforge", "psrc", "popen") else ""))

        up.router.add_get("/xr/{kind}", xr)

        def ctpage(r):
            kind = r.match_info["kind"]
            heads = CIMultiDict([("Content-Type", "text/plain, text/html")] if kind == "comma"
                                else [("Content-Type", "text/plain"), ("Content-Type", "text/html")] if kind == "repeat"
                                else [("Content-Type", "text/html")])
            body = CTPAGE.replace("__KIND__", kind)
            if kind == "u16":       # (1.24.2) no charset in the header, a UTF-16 byte order mark in the body
                return web.Response(body=body.encode("utf-16"), headers=heads)
            if kind == "latin":     # (1.24.2) no charset in the header, a latin-1 byte and a meta tag in the body
                # (bytes the proxy cannot read as text are left alone but for the report script, so this page gets no address
                # rewriting either: it reports to an address under its own path)
                body = body.replace("fetch('/__report", "fetch(location.pathname.split('/ct/')[0]+'/__report")
                return web.Response(body=body.replace("<head>", '<head><meta charset="windows-1252">').replace("ct page", "ct page \u00e9").encode("latin-1"), headers=heads)
            return web.Response(body=body.encode(), headers=heads)
        up.router.add_get("/ct/{kind}", ctpage)
        up.router.add_get("/xl/{kind}", xl)
        up.router.add_get("/xx/{kind}", xx)
        up.router.add_get("/stale2", lambda r: web.Response(text=STALE2, content_type="text/html"))

        # (E2) every capability the portal has verified so far can be made to count as expired, as after its 6 hours
        seen, dead = set(), set()
        real_verify = server.proxy_origin.verify

        def verify(secret, segment, *a, **kw):
            seen.add(segment)
            return None if segment in dead else real_verify(secret, segment, *a, **kw)
        server.proxy_origin.verify = verify

        async def expire(request):
            dead.update(seen)
            return web.json_response({"expired": len(dead)})
        up.router.add_get("/__expire", expire)
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
        state["uuid_br"] = br_m
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

        # 3b. (E1) an isolated page that reports a forged address cannot make the bar show it
        page.set_default_timeout(10000)
        td = page.evaluate("targetDisplay")

        def goto_bar(path):
            # what Enter in the bar does; typing would race with a page that reports its address every 50 ms
            # (each report rewrites the bar)
            page.evaluate("navigateTo", td + path)

        goto_bar("/forge")
        seen = []
        end = time.time() + 5
        while time.time() < end:
            seen.append(page.evaluate("(() => { const m = document.getElementById('url-reported'); "
                                      "return [document.getElementById('url-input').value, !!m && !m.hidden, m ? m.textContent : '']; })()"))
            time.sleep(0.1)
        check("E1: the forging page was shown (its own path appears in the bar)", any("forge" in v[0] for v in seen), seen[-3:])
        MARK = "reported by the page, not confirmed"
        check("E1: a forged address of another site is never shown in the bar without the 'not confirmed' marker",
              not any("bank.example" in v[0] and not v[1] for v in seen), [v for v in seen if "bank.example" in v[0] and not v[1]][:2])
        check("E1: the marker carries the fixed text, never text supplied by the page", all(v[2] == MARK for v in seen), [v for v in seen if v[2] != MARK][:2])
        check("E1: after the page reported another site the bar shows the reported address, with the marker visible",
              any("bank.example" in v[0] and v[1] for v in seen), seen[-3:])
        first_mark = next((i for i, v in enumerate(seen) if v[1]), len(seen))
        later = seen[first_mark:]
        check("E1: the marker was shown at all", first_mark < len(seen), seen[-3:])
        check("E1: once the page reported another site the marker stays (a later report cannot clear it)", all(v[1] for v in later), [v for v in later if not v[1]][:2])
        check("E1: from then on the bar never shows the address the portal gave the frame", not any(v[0].endswith("/forge") for v in later), [v for v in later if v[0].endswith("/forge")][:2])
        check("E1: the page's title is still the tab title", "Bank" in page.inner_text(".tab-bar"), page.inner_text(".tab-bar"))

        # 3b2. (E1) a page that reports another site and then navigates itself (so the frame has a load after the first)
        # still cannot make the bar, the marker or open-in-new-window show that site
        goto_bar("/forge2")
        seen2 = []
        end = time.time() + 5
        while time.time() < end:
            seen2.append(page.evaluate("(() => { const m = document.getElementById('url-reported'); "
                                       "return [document.getElementById('url-input').value, !!m && !m.hidden, m ? m.textContent : '']; })()"))
            time.sleep(0.1)
        hits = results().get("forge2", [])
        check("E1: the self-navigating forging page loaded twice (the second load is the one that must not count)",
              "" in hits and "again=1" in hits, hits)
        check("E1: a forged address of another site is never shown without the marker after the page navigated itself",
              not any("bank.example" in v[0] and not v[1] for v in seen2), [v for v in seen2 if "bank.example" in v[0] and not v[1]][:2])
        check("E1: the marker is still shown after the page navigated itself", all(v[1] for v in seen2[-20:]), seen2[-3:])
        page.evaluate("window.__opened = []; window.open = function(u){ window.__opened.push(String(u)); return null; }; true")
        page.evaluate("openExternal()")
        check("E1: open-in-new-window opens nothing while the address is not confirmed, and the button says why",
              page.evaluate("window.__opened") == [] and page.evaluate("document.getElementById('btn-external').disabled")
              and "cannot confirm" in page.evaluate("document.getElementById('btn-external').title"), page.evaluate("window.__opened"))

        # 3c. (E9) a page cannot open a tab whose address leaves its connection (dot segments, other sites)
        n_before = page.evaluate("tabs.length")
        goto_bar("/forge-tab")
        time.sleep(5)
        srcs = page.evaluate("tabs.map(t => t.iframe.getAttribute('src') || '')")
        check("E9: no tab was opened for a path that leaves the connection or for another site",
              not any("api/me" in x or "bank.example" in x or "/./" in x for x in srcs), srcs)
        check("E9: the one address under the connection did open a tab (and nothing else)", page.evaluate("tabs.length") == n_before + 1,
              (n_before, page.evaluate("tabs.length"), srcs))
        # 3e. (E2) a link clicked in an isolated page whose capability has expired: the tab loads again, the window stays
        goto_bar("/stale")
        wait_for(lambda: "stale-one" in page.inner_text(".tab-bar"), 10)
        check("E2: the first page of the site is shown", "stale-one" in page.inner_text(".tab-bar"), page.inner_text(".tab-bar"))
        check("E2: the portal made the capabilities expire", get_json(up + "/__expire")["expired"] >= 1)
        frame = next((f for f in page.frames if f.url.endswith("/stale")), None)
        check("E2: the page's frame was found", frame is not None, [f.url for f in page.frames])
        if frame is not None:
            frame.click("#go")
        wait_for(lambda: "stale-two" in page.inner_text(".tab-bar"), 15)
        check("E2: the tab shows the page that was clicked, through a fresh capability", "stale-two" in page.inner_text(".tab-bar"), page.inner_text(".tab-bar"))
        time.sleep(1.5)
        check("E2: the window is still the embedded browser (not sent to the login page)", "/browser" in page.url and "/login" not in page.url, page.url)

        ctx.close()

        # 3d0. (E1) a link clicked in an isolated page to a second proxied site: the old site is never shown as if it
        # were current. The bar shows what the page reports, with the 'not confirmed' marker; open-in-new-window opens
        # nothing; only a navigation the portal starts (the bar) confirms the address again.
        ctx = ctx_for("owner")
        page = ctx.new_page()
        page.set_default_timeout(10000)
        page.goto(f"{base}/browser?connection={info['br_m']}")
        wait_for(lambda: "evil-title" in page.inner_text(".tab-bar"), 10)      # the first page of the tab has loaded
        wait_for(lambda: page.evaluate("tabs.length") >= 2, 10)                 # and has opened its popup tab, which becomes the active one
        page.fill("#url-input", up + "/xlink")
        page.press("#url-input", "Enter")
        wait_for(lambda: "xsite-one" in page.inner_text(".tab-bar"), 10)
        frame = next((f for f in page.frames if f.url.endswith("/xlink")), None)
        check("E1: the first site's frame was found", frame is not None, [f.url for f in page.frames])
        BAR = ("(() => { const m = document.getElementById('url-reported'); "
               "return [document.getElementById('url-input').value, !!m && !m.hidden, m ? m.textContent : '', document.getElementById('btn-external').disabled]; })()")
        OPEN_EXTERNAL = ("(() => { window.__opened = []; window.open = function(u){ window.__opened.push(String(u)); return null; }; "
                         "document.getElementById('url-input').value = 'https://typed.example/'; openExternal(); return window.__opened; })()")
        SILENT_KINDS = ("plain", "image")      # not HTML: no injected script, so no report and no answer to the ping
        time.sleep(1.5)
        honest = []
        for _ in range(8):
            honest.append(page.evaluate(BAR))
            time.sleep(0.15)
        check("E1: an honest page reporting its own address under the site the portal resolved shows no marker",
              all(v[0].endswith("/xlink") and not v[1] and not v[3] for v in honest), honest[-2:])
        if frame is not None:
            frame.click("#go")
        wait_for(lambda: "xsite-two" in page.inner_text(".tab-bar"), 15)
        samples = []
        for _ in range(20):
            samples.append(page.evaluate(BAR))
            time.sleep(0.15)
        check("E1: after a link to another site the old site is never shown without the marker",
              not any(v[0].endswith("/xlink") and not v[1] for v in samples), [v for v in samples if v[0].endswith("/xlink") and not v[1]][:2])
        check("E1: after the link the bar shows the address the page reports, with the marker visible and the fixed text",
              samples[-1][0].endswith("/xsecond") and samples[-1][1] and samples[-1][2] == "reported by the page, not confirmed", samples[-1])
        page.evaluate("window.__opened = []; window.open = function(u){ window.__opened.push(String(u)); return null; }; true")
        page.evaluate("openExternal()")
        check("E1: open-in-new-window does not open the old site (nor anything) while the address is not confirmed",
              page.evaluate("window.__opened") == [] and samples[-1][3], page.evaluate("window.__opened"))
        # only a navigation the portal starts confirms the address again
        page.evaluate("navigateTo", up + "/xlink")
        wait_for(lambda: "xsite-one" in page.inner_text(".tab-bar") and not page.evaluate(BAR)[1], 10)
        time.sleep(1.5)
        after = [page.evaluate(BAR) for _ in range(1)]
        check("E1: a navigation started by the portal (the address bar) confirms the address again: no marker, the bar names the page, the button works",
              after[0][0].endswith("/xlink") and not after[0][1] and not after[0][3], after)
        ctx.close()

        # 3d1. (E1) a page on another site that stays silent, forges a report, cannot be decoded, or is not a page at all
        # must not leave the old site's address on the bar without the marker; a link inside the same site must not
        # raise the marker.
        def link_case(kind):
            ctx = ctx_for("owner")
            page = ctx.new_page()
            page.set_default_timeout(10000)
            page.goto(f"{base}/browser?connection={info['br_m']}")
            wait_for(lambda: "evil-title" in page.inner_text(".tab-bar"), 10)
            wait_for(lambda: page.evaluate("tabs.length") >= 2, 10)
            wait_for(lambda: page.evaluate("1") and any(f.url.endswith("/popup") for f in page.frames), 10)     # the popup tab has loaded: nothing of it can overtake the address typed next
            time.sleep(1)
            page.fill("#url-input", up + "/xl/" + kind)
            page.press("#url-input", "Enter")
            frame = None
            wait_for(lambda: page.evaluate("1") and any(f.url.endswith("/xl/" + kind) for f in page.frames), 10)
            frame = next((f for f in page.frames if f.url.endswith("/xl/" + kind)), None)
            check(f"E1 ({kind}): the first site's frame was found", frame is not None, page.evaluate("tabs.map(t => t.iframe.src.slice(-30) + '|' + t.title + '|' + document.getElementById('url-input').value.slice(-20))"))
            time.sleep(1.5)
            first = page.evaluate(BAR)
            check(f"E1 ({kind}): before the link the bar names the first site, with no marker", first[0].endswith("/xl/" + kind) and not first[1] and not first[3], first)
            if frame is not None:
                frame.click("#go")
            wait_for(lambda: page.evaluate("1") and any(("/xx/" + kind) in f.url for f in page.frames), 15)
            time.sleep(0.4)
            samples = []
            for _ in range(14):
                samples.append(page.evaluate(BAR))
                time.sleep(0.15)
            opened = page.evaluate(OPEN_EXTERNAL)
            ctx.close()
            return samples, opened
        for kind in ("silent", "forge", "badutf", "plain", "image", "pforge", "psrc", "popen"):
            samples, opened = link_case(kind)
            check(f"E1 ({kind}): the old site's address is never on the bar without the marker after a link to another site",
                  not any(v[0].endswith("/xl/" + kind) and not v[1] for v in samples), [v for v in samples if not v[1]][:2])
            if kind in SILENT_KINDS:
                # (1.24.2) the page is not HTML and never answers: the bar shows the address the portal last requested, with the tag
                # (never empty), and Open in new tab opens exactly that address
                check(f"E1 ({kind}): a page that never answers shows the address the portal requested, tagged, not an empty bar",
                      samples[-1][1] and samples[-1][0].endswith("/xl/" + kind) and samples[-1][2] == "requested address, not confirmed by the page"
                      and all(v[0] and (v[1] or not v[0].endswith("/xl/" + kind)) for v in samples), samples[-1])
                check(f"E1 ({kind}): ... and open-in-new-window stays enabled and opens the requested address", not samples[-1][3]
                      and len(opened) == 1 and opened[0].endswith("/xl/" + kind) and opened[0].startswith("http://"), (samples[-1], opened))
            else:
                check(f"E1 ({kind}): the marker is shown and open-in-new-window is disabled once the page has loaded", samples[-1][1] and samples[-1][3] and opened == [], (samples[-1], opened))
        samples, _ = link_case("honest")
        check("E1 (same site): a link to another page of the same site raises no marker and the bar follows the page",
              samples[-1][0].endswith("/xx/honest") and not samples[-1][1] and not samples[-1][3], samples[-3:])

        # 3d2. (E1) an address the portal itself loads (typed in the bar) that the upstream answers with a redirect to another
        # site: once the load is over the bar must name the site on screen, with the marker, whatever the page does.
        def redirect_case(kind):
            ctx = ctx_for("owner")
            page = ctx.new_page()
            page.set_default_timeout(10000)
            page.goto(f"{base}/browser?connection={info['br_m']}")
            wait_for(lambda: "evil-title" in page.inner_text(".tab-bar"), 10)
            wait_for(lambda: page.evaluate("tabs.length") >= 2, 10)
            wait_for(lambda: page.evaluate("1") and any(f.url.endswith("/popup") for f in page.frames), 10)
            time.sleep(1)
            page.fill("#url-input", up + "/xr/" + kind)
            page.press("#url-input", "Enter")
            wait_for(lambda: page.evaluate("1") and any(("/xx/" + kind) in f.url for f in page.frames), 15)
            time.sleep(3.5)
            samples = []
            for _ in range(8):
                samples.append(page.evaluate(BAR))
                time.sleep(0.15)
            opened = page.evaluate(OPEN_EXTERNAL)
            ctx.close()
            return samples, opened
        for kind in ("silent", "notitle", "image", "pforge", "psrc", "popen"):
            samples, opened = redirect_case(kind)
            check(f"E1 (redirect, {kind}): after a typed address was answered by a redirect to another site the old address is never on the bar without the marker",
                  not any(v[0].endswith("/xr/" + kind) and not v[1] for v in samples), [v for v in samples if not v[1]][:2])
            if kind in SILENT_KINDS:
                check(f"E1 (redirect, {kind}): a page that never answers shows the typed address, tagged as not confirmed, and open-in-new-window opens that address",
                      samples[-1][1] and samples[-1][0].endswith("/xr/" + kind) and not samples[-1][3]
                      and len(opened) == 1 and opened[0].endswith("/xr/" + kind), (samples[-1], opened))
            else:
                check(f"E1 (redirect, {kind}): the marker is shown and open-in-new-window is disabled", samples[-1][1] and samples[-1][3] and opened == [], (samples[-1], opened))

        # 3d. (E31) an isolated page can send credentialed requests to its own capability address, and only to that
        ctx = ctx_for("bob")
        page = ctx.new_page()
        page.goto(f"{base}/proxy/{info['web_m']}/cred")
        got = wait_for(lambda: results().get("cred"), 15)
        r = (got or [{}])[-1]
        check("E31: the credentialed page ran and reported", bool(got), r)
        check("E31: fetch with credentials: 'include' from the opaque origin succeeds", str(r.get("fetch", "")).startswith("200 "), r.get("fetch"))
        check("E31: XHR with withCredentials succeeds", str(r.get("xhr", "")).startswith("200 "), r.get("xhr"))
        check("E31: a credentialed JSON POST (preflighted) succeeds", r.get("post") == 200, r.get("post"))
        check("E31: a request without credentials still succeeds", r.get("plain") == 200, r.get("plain"))
        check("E31: the portal session cookie never reached the upstream", info["cookie_name"] not in str(r.get("fetch", "")) + str(r.get("xhr", "")),
              (r.get("fetch"), r.get("xhr")))
        check("E31: a request with a wrong capability gets no CORS grant, so the page cannot read the answer", str(r.get("badcap", "")).startswith("ERR"), r.get("badcap"))
        ctx.close()

        # 3e. (1.24.2) a hostile page behind a Content-Type that the proxy reads one way and a browser another (a comma
        # list, repeated headers): it is either not rendered as HTML (a download) or it carries the injected report script.
        # The control is a plain text/html answer, which is rendered and carries the script.
        for kind in ("html", "comma", "repeat", "u16", "latin"):
            ctx = ctx_for("bob")
            page = ctx.new_page()
            n_before = len(results().get("ct", []))
            started_download = False
            try:
                page.goto(f"{base}/proxy/{info['web_m']}/ct/{kind}")
            except Exception as exc:
                started_download = "Download is starting" in str(exc)
            time.sleep(2.0)
            got = results().get("ct", [])[n_before:]
            if kind in ("u16", "latin"):
                # (1.24.2) text/html without a charset: the proxy reads the document the way the browser does (a byte order
                # mark decides; bytes that are not UTF-8 are kept as they are), so the report script is in the page the
                # browser builds. (Before, the UTF-16 page was no page at all.)
                check(f"CS browser ({kind}): a page served as text/html without a charset is rendered and carries the report script",
                      bool(got) and got[-1].get("injected") is True and not started_download, (started_download, got))
                print(f"note: CS browser ({kind}): the browser read the page as {got[-1].get('charset') if got else None}")
            elif kind == "html":
                check("CT browser: the control (one text/html) is rendered and carries the report script", got and got[-1].get("injected") is True, got)
            else:
                check(f"CT browser ({kind}): the page is not rendered as HTML (a download), or it carries the report script",
                      all(g.get("injected") is True for g in got) and (started_download or bool(got)), (started_download, got))
                check(f"CT browser ({kind}): in fact it is not rendered at all", started_download and not got, (started_download, got))
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


def skip(reason):
    """No browser run is possible here. Exit 0 with a "skip:" line, unless REQUIRE_BROWSER=1 is set (the release
    checklist sets it): then this is a failure with exit code 3, so a skipped run is never read as a pass."""
    if os.environ.get("REQUIRE_BROWSER") == "1":
        print(f"FAIL: REQUIRE_BROWSER=1 and this run would skip: {reason}")
        sys.exit(3)
    print("skip: " + reason)


def main():
    if "--serve" in sys.argv:
        serve()
        return
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        skip("Playwright is not importable here")
        return
    if not Path(os.environ.get("CHROMIUM", "/usr/bin/chromium")).exists():
        skip("no Chromium")
        return
    py = os.environ.get("PORTAL_TEST_PYTHON") or (str(ROOT / "venv" / "bin" / "python") if (ROOT / "venv" / "bin" / "python").exists() else "")
    if not py:
        skip("no portal interpreter (set PORTAL_TEST_PYTHON)")
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
