"""POST /login is judged for cross-site origin even when it carries no session cookie (1.24.1).

A form posted from another site is sent without the SameSite=Lax cookie, and a successful login answers with
Set-Cookie, so an unjudged cross-site POST could replace the member's session cookie with the attacker's.
Real app on a loopback test server (tests/grant_harness.py): a cross-site, foreign-origin, opaque-origin or
proxied-page login POST is refused 403 with no Set-Cookie; the portal's own form, a JSON login and a script
that sends no fetch metadata still sign in.
Run: venv/bin/python tests/test_login_cross_site.py   (60 second deadline)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402


def anon():
    import aiohttp
    return aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())


async def main():
    env = await h.boot(names=("bob",), superadmin=())
    base = env.base
    form = {"username": "bob", "password": h.PW}
    async with anon() as s:
        for hdrs, label in (({"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, "a cross-site form"),
                            ({"Origin": "https://evil.example"}, "a foreign origin without fetch metadata"),
                            ({"Origin": "null"}, "an opaque origin"),
                            ({"Referer": f"{base}/proxy/abc/page"}, "a proxied page")):
            for kw, kind in (({"data": form}, "form"), ({"json": form}, "JSON")):
                async with s.post(base + "/login", headers=hdrs, allow_redirects=False, **kw) as r:
                    await r.read()
                    check(f"POST /login ({kind}) from {label} is refused with no Set-Cookie",
                          r.status == 403 and not r.headers.getall("Set-Cookie", []),
                          f"{r.status} {r.headers.getall('Set-Cookie', [])}")
        async with s.post(base + "/login", headers={"Sec-Fetch-Site": "cross-site"}, data={"username": "bob", "password": "wrong"},
                          allow_redirects=False) as r:
            await r.read()
            check("... a wrong password from another site is refused the same way (403)", r.status == 403, str(r.status))

        for hdrs, label in (({"Sec-Fetch-Site": "same-origin", "Origin": base}, "the portal's own login form"),
                            ({}, "a script that sends no fetch metadata"),
                            ({"Sec-Fetch-Site": "same-origin", "Origin": base, "Referer": base + "/login"}, "the login page with a referer")):
            async with s.post(base + "/login", headers=hdrs, data=form, allow_redirects=False) as r:
                await r.read()
                check(f"POST /login form from {label} still signs in (302 /dashboard + cookie)",
                      r.status == 302 and r.headers.get("Location") == "/dashboard"
                      and any(c.startswith("portal_session=") for c in r.headers.getall("Set-Cookie", [])),
                      f"{r.status} {r.headers.get('Location')}")
        for hdrs, label in (({"Sec-Fetch-Site": "same-origin", "Origin": base}, "same-origin"), ({}, "no fetch metadata")):
            async with s.post(base + "/login", headers=hdrs, json=form) as r:
                body = await r.json()
                check(f"POST /login JSON ({label}) still answers logged_in",
                      r.status == 200 and body.get("status") == "logged_in", f"{r.status} {body}")
    await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), 60))
h.finish("test_login_cross_site")
