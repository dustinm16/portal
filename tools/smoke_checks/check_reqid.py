"""Smoke checks: request IDs and the page for an unreachable service.

On the staged instance, over real TLS:
  - every answer (page, error, redirect, JSON) carries an X-Request-ID of 8 safe characters, a new one each time
  - an X-Request-ID sent by the client is never echoed, and its text never reaches the server log
  - a line the server logs for a request carries that request's ID
  - /search/ with the search service not running answers with the page (service name and ID, Retry-After)
    or, for JSON, with request_id, and the server log has one 'Upstream error' line under that ID

A down HTTP proxy connection cannot be made on a stage (the host policy refuses loopback targets), so that
path is proven by tests/test_reqid.py only. The user is made with a random suffix and the checks assert on
their own requests only, so the module also passes on a copy of a production database (--from-db).
"""

import asyncio
import re
import secrets

SUFFIX = secrets.token_hex(3)
USER = f"smoke_reqid_{SUFFIX}"
PASSWORD = "Smoke-Reqid-Pw-1!"
ID_RE = re.compile(r"^[a-z0-9]{8}$")
FORGED = f"FORGEDSMOKE{SUFFIX.upper()} [ERROR] portal: injected line"

CREATE_USER = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    if not await database.db.get_user_by_username({USER!r}):
        await create_user({USER!r}, {PASSWORD!r}, is_admin=False)
    await database.db.close()

asyncio.run(main())
"""


async def _log_has(ctx, needle, tries=15):
    for _ in range(tries):
        if needle in ctx.server_log():
            return True
        await asyncio.sleep(0.3)
    return False


async def run(ctx):
    base = ctx.base_url
    seen = []

    async with ctx.http() as anon:
        for name, path, kw in (("a page", "/login", {}), ("a refused API call", "/api/me", {}),
                               ("a missing page", f"/no-such-page-{SUFFIX}", {}),
                               ("a redirect", "/dashboard", {"allow_redirects": False})):
            async with anon.get(base + path, **kw) as r:
                await r.read()
                rid = r.headers.get("X-Request-ID", "")
                seen.append(rid)
                ctx.ok(f"reqid: {name} carries an X-Request-ID of 8 safe characters",
                       bool(ID_RE.match(rid)), f"{r.status} {rid!r}")
        ctx.ok("reqid: each request got a different ID", len(set(seen)) == len(seen), str(seen))

        async with anon.get(f"{base}/health", headers={"X-Request-ID": FORGED}) as r:
            await r.read()
            got = r.headers.get("X-Request-ID", "")
            ctx.ok("reqid: an ID sent by the client is not echoed, ours is used",
                   got != FORGED and bool(ID_RE.match(got)), repr(got))
        ctx.ok("reqid: the client's ID text is not in the server log",
               "FORGEDSMOKE" not in ctx.server_log())

    rc, out = await ctx.run_py(CREATE_USER)
    ctx.ok("reqid: create a plain test user", rc == 0, out.strip()[-200:])
    if rc != 0:
        return
    async with ctx.http() as user:
        resp = await ctx.login(user, USER, PASSWORD)
        await resp.read()
        if resp.status != 200:
            ctx.ok("reqid: test user login", False, f"status {resp.status}")
            return
        async with user.get(f"{base}/search/", headers={"Accept": "text/html"}, allow_redirects=False) as r:
            page = await r.text()
            status, retry, rid = r.status, r.headers.get("Retry-After"), r.headers.get("X-Request-ID", "")
        if status not in (502, 503):
            ctx.skip("reqid: search not running page", f"the search service answers here (status {status})")
            ctx.skip("reqid: search not running JSON", "the search service answers here")
            ctx.skip("reqid: the log line for the search error", "the search service answers here")
            return
        ctx.ok("reqid: the search error page names the service and shows the same ID as the header",
               ID_RE.match(rid) and "Search" in page and f">{rid}<" in page and bool(retry), f"{status} {rid!r} {retry!r}")
        ctx.ok("reqid: the page has the countdown script from a static file and no upstream address",
               "/static/js/upstream-error.js?v=1" in page and "127.0.0.1" not in page and "onclick" not in page)
        ctx.ok("reqid: the error is in the server log once under that ID, with a reason",
               await _log_has(ctx, f"[req={rid}] Upstream error {status} for service 'Search'")
               and ctx.server_log().count(f"[req={rid}]") == 1)
        async with user.get(f"{base}/search/?format=json") as r:
            data = await r.json(content_type=None)
            ctx.ok("reqid: the JSON answer carries request_id equal to the header",
                   r.status in (502, 503) and data.get("request_id") == r.headers.get("X-Request-ID")
                   and bool(data.get("error")), f"{r.status} {data}")
        async with user.get(f"{base}/search/", headers={"Accept": "text/html", "X-Request-ID": FORGED}) as r:
            await r.read()
            ctx.ok("reqid: a forged ID on the error page is neither shown nor logged",
                   r.headers.get("X-Request-ID") != FORGED and "FORGEDSMOKE" not in ctx.server_log())
    ctx.skip("reqid: a down HTTP proxy connection", "a stage refuses loopback targets; covered by tests/test_reqid.py")
