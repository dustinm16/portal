"""POST /login is judged for cross-site origin even when it carries no session cookie (1.24.1).

A form posted from another site is sent without the SameSite=Lax cookie, and a successful login answers with
Set-Cookie, so an unjudged cross-site POST could replace the member's session cookie with the attacker's.
Real app on a loopback test server (tests/grant_harness.py): a cross-site, foreign-origin, opaque-origin or
proxied-page login POST is refused 403 with no Set-Cookie; the portal's own form, a JSON login and a script
that sends no fetch metadata still sign in.
Run: venv/bin/python tests/test_login_cross_site.py   (60 second deadline)
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402


def anon():
    import aiohttp
    return aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())


async def main():
    env = await h.boot(names=("bob", "eve"), superadmin=())
    base = env.base
    form = {"username": "bob", "password": h.PW}

    class Grab(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    grab = Grab()
    logging.getLogger().addHandler(grab)
    async with anon() as s:
        # (E28) the refusal log line says what was refused: a sign-in POST with no cookie is not "cookie-authenticated"
        async with s.post(base + "/login", headers={"Sec-Fetch-Site": "cross-site"}, data=form, allow_redirects=False) as r:
            await r.read()
        lines = [x for x in grab.lines if x.startswith("Refused")]
        check("E28: the refusal of a cross-site POST /login is logged as a sign-in POST, not a cookie-authenticated one",
              any(x.startswith("Refused a cross-site sign-in POST") for x in lines) and not any("cookie-authenticated POST /login" in x for x in lines),
              str(lines))
        del grab.lines[:]
        sess = env.sessions["bob"]
        async with sess.post(base + "/api/me/password", headers={"Sec-Fetch-Site": "cross-site"}, json={}) as r:
            await r.read()
            st = r.status
        lines = [x for x in grab.lines if x.startswith("Refused")]
        check("E28: any other refusal keeps the cookie-authenticated wording",
              st == 403 and any(x.startswith("Refused a cookie-authenticated POST /api/me/password") for x in lines), f"{st} {lines}")
    logging.getLogger().removeHandler(grab)
    async with anon() as s:
        for hdrs, label in (({"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, "a cross-site form"),
                            ({"Origin": "https://evil.example"}, "a foreign origin without fetch metadata"),
                            ({"Origin": "null"}, "an opaque origin"),
                            ({"Sec-Fetch-Site": "same-site", "Origin": "https://evil.sibling.example"}, "a sibling subdomain (same-site, foreign Origin)"),
                            ({"Referer": f"{base}/proxy/abc/page"}, "a proxied page")):
            for kw, kind in (({"data": form}, "form"), ({"json": form}, "JSON")):
                async with s.post(base + "/login", headers=hdrs, allow_redirects=False, **kw) as r:
                    await r.read()
                    check(f"POST /login ({kind}) from {label} is refused with no Set-Cookie",
                          r.status == 403 and not r.headers.getall("Set-Cookie", []),
                          f"{r.status} {r.headers.getall('Set-Cookie', [])}")
        # a valid session JWT in the action URL, a bearer header or an API-key header does not exempt /login
        jwt = next(c.value for c in env.sessions["bob"].cookie_jar if c.key == "portal_session")
        for url, extra, label in ((f"/login?token={jwt}", {}, "a ?token= session JWT in the form's URL"),
                                  ("/login", {"Authorization": f"Bearer {jwt}"}, "a bearer header")):
            for origin in ("https://evil.example", "null"):
                hdrs = {"Sec-Fetch-Site": "cross-site", "Origin": origin, **extra}
                async with s.post(base + url, headers=hdrs, data=form, allow_redirects=False) as r:
                    await r.read()
                    check(f"POST /login from Origin {origin} with {label} is refused with no Set-Cookie",
                          r.status == 403 and not r.headers.getall("Set-Cookie", []),
                          f"{r.status} {r.headers.getall('Set-Cookie', [])}")
        # (1.24.2, E29) other credentials on one request. authenticate_request reads a ?token= before the session cookie, so
        # a cookie request whose URL holds somebody's ?token= is that token's owner for every handler (POST /logout, which
        # reads the cookie itself, is the one place that differs); a valid API key (X-API-Key or Api-Key) is not a cookie
        # request either, and still must not let a cross-site POST /login through.
        import secrets
        import auth as _auth
        pfx = "portal_e29"
        full = (pfx + secrets.token_hex(31)[:61])[:71]
        await env.db.create_api_key(user_id=env.uid["bob"], name="e29", key_hash=_auth.hash_password(full), key_prefix=pfx[:10],
                                    scopes="*", expires_at=None)
        eve_jwt = next(c.value for c in env.sessions["eve"].cookie_jar if c.key == "portal_session")
        bob_cookie = {"Cookie": f"portal_session={jwt}"}
        cross = {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
        conn_body = {"type": "ssh", "host": "93.184.216.34", "port": 22}

        async def owner_of(name):
            row = await (await env.db.conn.execute("SELECT user_id FROM user_connections WHERE name = ?", (name,))).fetchone()
            return row["user_id"] if row else None

        async with s.post(base + f"/api/connections?token={eve_jwt}", headers={**cross, **bob_cookie},
                          json={"name": "e29-mixed", **conn_body}) as r:
            await r.read()
            check("E29: a cross-site cookie request whose URL holds another member's ?token= is let through as that member",
                  r.status != 403 and await owner_of("e29-mixed") == env.uid["eve"], f"{r.status} {await owner_of('e29-mixed')}")
        for hdrs, label in (({"X-API-Key": full}, "an X-API-Key header"), ({"Authorization": f"Api-Key {full}"}, "an Api-Key authorization header")):
            async with s.post(base + "/login", headers={**cross, **hdrs}, data=form, allow_redirects=False) as r:
                await r.read()
                check(f"E29: cross-site POST /login with {label} holding a valid key is refused with no Set-Cookie",
                      r.status == 403 and not r.headers.getall("Set-Cookie", []), f"{r.status} {r.headers.getall('Set-Cookie', [])}")
            name = "e29-" + label.split()[1].lower()
            async with s.post(base + "/api/connections", headers={**cross, **hdrs, **bob_cookie}, json={"name": name, **conn_body}) as r:
                await r.read()
                check(f"E29: a cross-site state change with the cookie and {label} is the key's request (let through, as its owner)",
                      r.status != 403 and await owner_of(name) == env.uid["bob"], f"{r.status} {await owner_of(name)}")
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
