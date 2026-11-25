"""A proxied HTML page of a connection that was only shared with the viewer carries no host or port (1.24.1).

Through the real /proxy/{uuid} handler (plain mode) against a local upstream, with the real database and share
routes. The script the proxy writes into every HTML page used to hold the connection's scheme://host:port
(var TO / var FO); the owner and administrators keep it, a grantee's page must not hold the address anywhere
(neither the body nor the headers). The page still gets its script (root-relative URLs are rewritten) and the
literal origin in the upstream's own markup is rewritten to the proxy path, as before.
Only the outbound host policy is replaced (it refuses a loopback upstream). Every run has a 60 second deadline.

Since the proxied-pages change of the same release (1.24.1) a page of a member's connection opened by somebody else, and
every page in browser mode, is an isolated page: its first request is answered with a redirect to an address that carries
a signed credential (/proxy/<id>/~pc1.<token>/...), after the recipient has answered the first-open notice. The test goes
through that entry like a browser (the notice, then the redirect) and takes the credential segment out of what it reads
(it holds the session and the viewer's own address, never the upstream's), so that what is compared is the page the proxy
wrote. The grantee's "~" alias comes after the credential.

Run: venv/bin/python tests/test_proxy_origin_hidden.py
"""

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402


async def page(request):
    origin = f"http://127.0.0.1:{request.url.port}"
    return web.Response(
        content_type="text/html",
        text=f'<html><head><title>t</title></head><body><a href="{origin}/next">next</a>'
             f'<img src="/pic.png"></body></html>')


async def bpage(request):
    origin = f"http://127.0.0.1:{request.url.port}"
    resp = web.Response(
        content_type="text/html",
        text=f'<html><head><title>b</title></head><body><a href="{origin}/next">own</a><a href="/rel">rel</a>'
             f'<a href="https://other.example/x">ext</a><img src="//127.0.0.1:{request.url.port}/pic.png">'
             f'<script>var u="{origin}/api";</script></body></html>')
    resp.set_cookie("sid", "1", path="/", domain="127.0.0.1")
    return resp


async def redir_abs(request):
    raise web.HTTPFound(f"http://127.0.0.1:{request.url.port}/landing?a=1")


async def redir_to(request):
    raise web.HTTPFound(request.query["to"].replace("PORT", str(request.url.port)))


async def redir_rel(request):
    raise web.HTTPFound("/landing")


CAP = re.compile(r"/~pc1\.[A-Za-z0-9_.-]+")


def no_cap(text):
    """The text without the isolated page's credential segment."""
    return CAP.sub("", text)


class _Answer:
    def __init__(self, headers):
        self.headers = headers


async def main():
    up = web.Application()
    up.router.add_get("/page", page)
    up.router.add_get("/bpage", bpage)
    up.router.add_get("/redir-abs", redir_abs)
    up.router.add_get("/redir-rel", redir_rel)
    up.router.add_get("/redir-to", redir_to)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()
    env = await h.boot()
    owner, bob, adm = env.sessions["owner"], env.sessions["bob"], env.sessions["adm"]

    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    uuid, cid = await h.connection(env, "owner", name="web", ctype="http", host="127.0.0.1", port=upstream.port)
    async with owner.post(f"{env.base}/api/connections/{uuid}/shares",
                          json={"usernames": ["bob", "adm"], "expires_in": "7d"}) as r:
        check("the owner shares the connection with bob and an administrator", r.status == 200, str(r.status))
    for who in ("bob", "adm"):          # the first-open notice of a shared web connection, answered with Continue
        async with env.sessions[who].post(f"{env.base}/api/connections/{uuid}/notice") as r:
            assert r.status == 200, (who, r.status)

    async def fetch(sess):
        async with sess.get(f"{env.base}/proxy/{uuid}/page") as r:      # follows the entry redirect of an isolated page
            return r.status, no_cap(await r.text()), no_cap("\n".join(f"{k}: {v}" for k, v in r.headers.items()))

    port = str(upstream.port)
    st, body, headers = await fetch(owner)
    check("the owner's page is proxied", st == 200 and "<title>t</title>" in body, str(st))
    check("the owner's page keeps the script's origin constants (unchanged for the owner)",
          f'var TO="http://127.0.0.1:{port}"' in body, body[:300])
    st, body, headers = await fetch(adm)
    check("an administrator it is shared with keeps them too (as on the browser page)", st == 200 and f'var TO="http://127.0.0.1:{port}"' in body, str(st))

    st, body, headers = await fetch(bob)
    check("the grantee's page is proxied", st == 200 and "<title>t</title>" in body, str(st))
    check("the grantee's page holds no host", "127.0.0.1" not in body and "localhost" not in body, body[:500])
    check("the grantee's page holds no port", port not in body and port not in headers, body[:500])
    check("the grantee's page still gets the proxy script", "<script>(function(){" in body and f'var B="/proxy/{uuid}"' in body)
    check("the grantee's page has the upstream's own absolute link rewritten to the proxy path",
          f'href="/proxy/{uuid}/next"' in body, body[:500])
    check("the grantee's root-relative link is rewritten as before", f'src="/proxy/{uuid}/pic.png"' in body, body[:500])

    # The viewer decision (is this member an administrator, so is the address hidden) is made once per proxied request.
    real_admin_check, role_lookups = server._is_recording_admin, []

    async def counting_admin_check(user_id):
        role_lookups.append(user_id)
        return await real_admin_check(user_id)
    server._is_recording_admin = counting_admin_check
    await fetch(bob)                                    # the entry redirect (no lookup) and the page itself
    check("a grantee's proxied page looks the viewer up once, not twice", len(role_lookups) == 1, str(role_lookups))
    server._is_recording_admin = real_admin_check

    # ---- browser mode (a connection that browses any site): its own site is addressed as /proxy/<id>/~/ ---------------
    buuid = await env.db.create_user_connection(env.uid["owner"], "web b", "http", "127.0.0.1", upstream.port,
                                                json.dumps({"browser_mode": True}))
    async with owner.post(f"{env.base}/api/connections/{buuid}/shares", json={"usernames": ["bob", "adm"], "expires_in": "7d"}) as r:
        check("browser mode: the owner shares the connection", r.status == 200, str(r.status))
    for who in ("bob", "adm"):
        async with env.sessions[who].post(f"{env.base}/api/connections/{buuid}/notice") as r:
            assert r.status == 200, (who, r.status)

    async def bfetch(sess, path, **kw):
        """Browser mode is always isolated: the first answer is the entry redirect to the address with the credential,
        the page is the answer at that address (its own redirect, if it has one, is not followed)."""
        async with sess.get(f"{env.base}/proxy/{buuid}/{path}", allow_redirects=False, **kw) as r0:
            entry = r0.headers.get("Location", "")
            assert r0.status == 302 and "/~pc1." in entry, (r0.status, entry)
        async with sess.get(env.base + entry, allow_redirects=False, **kw) as r:
            headers = {k: no_cap(v) for k, v in r.headers.items()}
            return r.status, no_cap(await r.text()), "\n".join(f"{k}: {v}" for k, v in headers.items()), _Answer(headers)

    base = f"/proxy/{buuid}"
    st, body, headers, _ = await bfetch(owner, "bpage")
    check("browser mode: the owner's page keeps the origin in the script and the links",
          st == 200 and f'var X="/http://127.0.0.1:{port}"' in body and f'href="{base}/http://127.0.0.1:{port}/next"' in body, body[:400])
    st, body, headers, _ = await bfetch(adm, "bpage")
    check("browser mode: an administrator it is shared with keeps them too", st == 200 and f'var X="/http://127.0.0.1:{port}"' in body, str(st))
    for entry, label in (("~/bpage", "through ~/"), ("bpage", "by a bare path")):
        st, body, headers, _ = await bfetch(bob, entry)
        check(f"browser mode: the grantee's page {label} is proxied", st == 200 and "<title>b</title>" in body, f"{st} {body[:200]}")
        check(f"browser mode {label}: no host, no port in the body or the headers",
              "127.0.0.1" not in body and "localhost" not in body and port not in body and port not in headers, body[:600] + headers)
        check(f"browser mode {label}: the own absolute link and the root-relative link are under ~",
              f'href="{base}/~/next"' in body and f'href="{base}/~/rel"' in body, body[:600])
        check(f"browser mode {label}: the protocol-relative resource and the script text are under ~",
              f'src="{base}/~/pic.png"' in body and f'"{base}/~/api"' in body, body[:700])
        check(f"browser mode {label}: another site is still wrapped with its own origin",
              f'href="{base}/https://other.example/x"' in body, body[:600])
        check(f"browser mode {label}: the script resolves the own site to ~ and still has its rewriting",
              'var X="/~"' in body and 'var O=' not in body and 'return B+X+u' in body, body[:900])
        check(f"browser mode {label}: the browser is sent no cookie of the upstream (the portal keeps it for the page, per site)",
              "Set-Cookie" not in headers, headers)
    # the rule for a cookie path of the own site, as the proxy writes it when it does pass a cookie on (a page that is not isolated)
    rewritten = server._rewrite_set_cookie("sid=1; Path=/; Domain=127.0.0.1", f"{base}/~")
    check("a cookie of the own site is moved under ~ (not the whole connection), without a Domain",
          re.search(rf"sid=1; .*Path={re.escape(base)}/~", rewritten) is not None and "Domain=" not in rewritten, rewritten)
    st, body, headers, r = await bfetch(bob, "~/redir-abs")
    check("browser mode: an absolute redirect to the own origin lands under ~", st == 302 and r.headers.get("Location") == f"{base}/~/landing?a=1",
          f"{st} {r.headers.get('Location')}")
    st, body, headers, r = await bfetch(bob, "~/redir-rel")
    check("browser mode: a root-relative redirect lands under ~", st == 302 and r.headers.get("Location") == f"{base}/~/landing", f"{st} {r.headers.get('Location')}")
    check("browser mode: no host or port in the redirect answers", "127.0.0.1" not in headers and port not in headers, headers)
    st, body, headers, r = await bfetch(owner, "redir-abs")
    check("browser mode: the owner's redirect keeps the origin", r.headers.get("Location") == f"{base}/http://127.0.0.1:{port}/landing?a=1", str(r.headers.get("Location")))
    # the same host on another scheme or at its default port is the connection itself, not another site (no host in the address bar)
    for to, want, label in ((f"http://127.0.0.1:PORT/same?x=1", f"{base}/~/same?x=1", "the configured origin itself"),
                            ("http://127.0.0.1/landing", f"{base}/~http/landing", "the same host at port 80"),
                            ("https://127.0.0.1/landing?a=1", f"{base}/~https/landing?a=1", "the same host on https (an upgrade)"),
                            ("HTTPS://127.0.0.1:443/up", f"{base}/~https/up", "the default port written out, any letter case"),
                            ("https://127.0.0.1", f"{base}/~https/", "no path")):
        st, body, headers, r = await bfetch(bob, "~/redir-to?to=" + to.replace(":", "%3A").replace("/", "%2F"))
        loc = r.headers.get("Location", "")
        check(f"browser mode: a redirect to {label} stays under an alias and shows no host or port",
              st == 302 and loc == want and "127.0.0.1" not in loc and port not in loc, f"{st} {loc}")
    for to, label in ((f"http://127.0.0.1:{int(port) + 1}/x", "the same host on another port"), ("https://other.example/x", "another host")):
        st, body, headers, r = await bfetch(bob, "~/redir-to?to=" + to.replace(":", "%3A").replace("/", "%2F"))
        check(f"browser mode: a redirect to {label} is still another site (wrapped with its origin)",
              st == 302 and r.headers.get("Location", "").startswith(f"{base}/{to.split('/x')[0]}/"), f"{st} {r.headers.get('Location')}")
    st, body, headers, r = await bfetch(bob, "~http/landing")
    check("the ~http address dials the host on port 80, not the configured port (nothing listens there: the proxy answers 502, not the page)",
          st in (502, 503, 504) and port not in body and "127.0.0.1" not in body, f"{st} {body[:200]}")
    st, body, headers, r = await bfetch(owner, f"redir-to?to=http%3A%2F%2F127.0.0.1%2Fx")
    check("the owner's own redirect is unchanged (the origin stays in the address)",
          st == 302 and r.headers.get("Location") == f"{base}/http://127.0.0.1/x", f"{st} {r.headers.get('Location')}")
    # another site by its full address is still reached and answered under its own origin path
    st, body, headers, r = await bfetch(bob, f"http://127.0.0.1:{port}/bpage")
    check("browser mode: a full address typed by the member is still served under the origin path",
          st == 200 and f'href="{base}/http://127.0.0.1:{port}/next"' in body and f'var X="/http://127.0.0.1:{port}"' in body, body[:300])

    await h.shutdown(env)
    await upstream.close()


asyncio.run(asyncio.wait_for(main(), 60))
h.finish("test_proxy_origin_hidden")
