"""Only a POST signs out (1.24.1): a link, an image or a navigation can no longer end a session.

Real app on a loopback test server (tests/grant_harness.py). GET /logout with a live session shows a page with a
Sign out button and changes nothing; with no session it redirects to the login page. POST signs out: a form post
(the button of that page, no script) is answered with a redirect, any other POST (push.js, an API client) with the
documented 200 {"success": true}. A POST the browser marks cross-site, or that comes from an opaque origin, is
refused and the session stays. push.js turns the navbar link into a POST and goes to /login, never to /logout.
Run: venv/bin/python tests/test_logout_post.py   (60 second deadline)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


async def alive(s, base):
    async with s.get(base + "/api/me") as r:
        return r.status == 200


async def main():
    env = await h.boot(names=("owner", "bob"), superadmin=())
    base = env.base
    bob = env.sessions["bob"]

    # ---- GET never signs out
    async with bob.get(base + "/logout", allow_redirects=False) as r:
        page = await r.text()
        check("GET /logout with a session shows a page (200, not a redirect)", r.status == 200, str(r.status))
        check("... with a form that posts to /logout and a Sign out button",
              'method="post" action="/logout"' in page and "Sign out</button>" in page, page[:300])
        check("... not cached", "no-store" in r.headers.get("Cache-Control", ""), str(r.headers.get("Cache-Control")))
    check("... and the session is still live afterwards", await alive(bob, base))
    for hdrs in ({"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
                 {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
                 {"Referer": f"{base}/proxy/abc/page"}):
        async with bob.get(base + "/logout", headers=hdrs, allow_redirects=False) as r:
            await r.read()
        check(f"GET /logout as a navigation or an image from elsewhere {sorted(hdrs)} does not sign out", await alive(bob, base))
    async with aiohttp_anon() as anon:
        async with anon.get(base + "/logout", allow_redirects=False) as r:
            check("GET /logout with no session redirects to the login page", r.status == 302 and r.headers["Location"] == "/login",
                  f"{r.status} {r.headers.get('Location')}")

    # ---- POST from elsewhere is refused and the session stays
    for hdrs, label in (({"Sec-Fetch-Site": "cross-site"}, "cross-site"), ({"Origin": "null"}, "an opaque origin"),
                        ({"Referer": f"{base}/proxy/abc/page"}, "a proxied page")):
        async with bob.post(base + "/logout", headers=hdrs, allow_redirects=False) as r:
            await r.read()
            check(f"POST /logout from {label} is refused", r.status == 403, str(r.status))
        check(f"... and the session stays after the POST from {label}", await alive(bob, base))

    # ---- a POST that carries no session cookie (a cross-site form: Lax cookies are not sent) must not delete the cookie either
    async with aiohttp_anon() as anon:
        for hdrs, kw, label in (({"Sec-Fetch-Site": "cross-site"}, {"data": {}}, "a cross-site form post"),
                                ({"Sec-Fetch-Site": "same-origin"}, {"json": {}}, "a JSON post")):
            async with anon.post(base + "/logout", headers=hdrs, allow_redirects=False, **kw) as r:
                await r.read()
                check(f"POST /logout without a session cookie ({label}) answers but sends no Set-Cookie",
                      r.status in (200, 303) and not r.headers.getall("Set-Cookie", []), f"{r.status} {r.headers.getall('Set-Cookie', [])}")
    check("... and a signed-in browser is untouched by it", await alive(bob, base))

    # ---- POST from the portal's own page signs out
    async with bob.post(base + "/logout", headers={"Sec-Fetch-Site": "same-origin"}, data={}, allow_redirects=False) as r:
        check("a form post (the page's button) redirects to the login page", r.status == 303 and r.headers.get("Location") == "/login",
              f"{r.status} {r.headers.get('Location')}")
        check("... and clears the session cookie of the browser that sent it", any("portal_session=" in c and ("Max-Age=0" in c or "expires" in c.lower())
              for c in r.headers.getall("Set-Cookie", [])), str(r.headers.getall("Set-Cookie", [])))
    check("... and the session is gone", not await alive(bob, base))
    owner = env.sessions["owner"]
    async with owner.post(base + "/logout", json={}, headers={"Sec-Fetch-Site": "same-origin"}) as r:
        body = await r.json()
        check("a JSON POST (the documented way for a script) answers 200 {success: true}", r.status == 200 and body == {"success": True},
              f"{r.status} {body}")
    check("... and ends the session", not await alive(owner, base))

    # ---- the pages
    js = (ROOT / "static" / "js" / "push.js").read_text()
    sign = js[js.index("Sign out (release 1.24.1)"):js.index("Every page load where push is on")]
    check("push.js intercepts every Logout link, posts, and goes to /login (never to /logout on success)",
          "preventDefault()" in sign and "method: 'POST'" in sign and "'/login'" in sign and "signedOut ? '/login' : '/logout'" in sign
          and "hinted() && canAct()" in sign and "if (!a || ev.defaultPrevented" in sign, sign[:200])
    check("... and the push endpoint goes in the body, not the address", "JSON.stringify({ endpoint: sub.endpoint })" in sign
          and "/logout?" not in sign)
    page_html = (ROOT / "static" / "logout.html").read_text()
    check("the sign-out page has no inline handler and no script of its own", "onclick" not in page_html and "<script>" not in page_html)
    await h.shutdown(env)


def aiohttp_anon():
    import aiohttp
    return aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())


asyncio.run(asyncio.wait_for(main(), 60))
h.finish("test_logout_post")
