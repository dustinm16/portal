"""Smoke checks: the tight limit on logged-out /proxy, /search and /browser hits, over HTTP.

The staged server is restarted with TRUSTED_PROXIES=127.0.0.1,::1 in its process environment (never
in a file) so that each request can name its client in CF-Connecting-IP with a random public address
(loopback is never limited). The two settings are written into the staged database while the server
is stopped and removed or restored at the end. Requests do not follow redirects: a logged-out hit
is a 302 to /login until the limit answers 429.

Users and addresses carry a random suffix and the module asserts only on its own traffic, so it also
passes on a copy of a production database (--from-db). The settings-route check needs an admin
password and is skipped without one.
"""

import random
import secrets
import sqlite3

SUFFIX = secrets.token_hex(3)
USER = f"smoke_pl_{SUFFIX}"
PASSWORD = "Smoke-ProxyLimit-Pw-1!"
KEYS = ("proxy_limit_enabled", "proxy_limit_per_minute")

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


def _addr():
    return f"45.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"


def _sql(ctx, sql, args=()):
    c = sqlite3.connect(str(ctx.stage_dir / "portal.db"), timeout=30)
    try:
        rows = c.execute(sql, args).fetchall()
        c.commit()
        return rows
    finally:
        c.close()


async def _hits(ctx, session, addr, n, path=None, headers=None):
    """n GET requests from `addr`; returns (statuses, retry_after of the first 429 or None)."""
    path = path or f"/proxy/{secrets.token_hex(8)}/x"
    h = dict(headers or {})
    if addr:
        h["CF-Connecting-IP"] = addr
    got, retry = [], None
    for _ in range(n):
        async with session.get(f"{ctx.base_url}{path}", headers=h, allow_redirects=False) as r:
            await r.read()
            got.append(r.status)
            if r.status == 429 and retry is None:
                retry = r.headers.get("Retry-After")
    return got, retry


def _first_429(got):
    return got.index(429) + 1 if 429 in got else None


async def run(ctx):
    # The session cookie name is the staged server's own setting (a production .env may change it).
    rc, out = await ctx.run_py("from config import Config; print('NAME=' + Config.SESSION_COOKIE_NAME)")
    names = [ln[5:].strip() for ln in out.splitlines() if ln.startswith("NAME=")]
    COOKIE = names[0] if rc == 0 and names else "portal_session"
    rc, out = await ctx.run_py(CREATE_USER)
    ctx.ok("proxylimit: create a test user", rc == 0, out.strip()[-200:])
    if rc != 0:
        return

    a1, a2, a3, a4, a5 = (_addr() for _ in range(5))
    saved = {k: _sql(ctx, "SELECT value FROM settings WHERE key = ?", (k,)) for k in KEYS}
    envs = [e for e in (getattr(ctx, "_env", None), getattr(ctx.server, "env", None)) if e is not None]
    had_trust = [e.get("TRUSTED_PROXIES") for e in envs]
    try:
        await ctx.stop_server()
        for k in KEYS:
            _sql(ctx, "DELETE FROM settings WHERE key = ?", (k,))
        for e in envs:
            e["TRUSTED_PROXIES"] = "127.0.0.1,::1"
        await ctx.start_server(wait_healthy=True)
        if "loopback trusted: True" not in ctx.server_log():
            ctx.skip("proxylimit: limit checks", "the staged server did not take TRUSTED_PROXIES from its environment")
            return

        async with ctx.http() as s:
            # ---- on by default, logged out
            got, retry = await _hits(ctx, s, a1, 45)
            first = _first_429(got)
            ctx.ok("proxylimit: a logged-out client hammering /proxy/x gets 429 after about 30 requests (default, no setting saved)",
                   first is not None and 30 <= first <= 34 and set(got[:29]) == {302}, f"first 429 at {first}: {got[:5]}...")
            ctx.ok("proxylimit: the 429 carries Retry-After", retry is not None and retry.isdigit() and int(retry) >= 1, str(retry))
            for path in ("/health", "/login", "/static/portal.js", "/api/me"):
                async with s.get(f"{ctx.base_url}{path}", headers={"CF-Connecting-IP": a1}, allow_redirects=False) as r:
                    await r.read()
                    ctx.ok(f"proxylimit: {path} is not limited for the limited address", r.status != 429, str(r.status))
            got3, _ = await _hits(ctx, s, a3, 3)
            ctx.ok("proxylimit: another address is not affected", 429 not in got3, str(got3))

            # ---- a bogus cookie is logged out
            got, _ = await _hits(ctx, s, a2, 45, headers={"Cookie": f"{COOKIE}=bogus.cookie.value"})
            first = _first_429(got)
            ctx.ok("proxylimit: a client sending a bogus session cookie is limited the same",
                   first is not None and 30 <= first <= 34, f"first 429 at {first}")

            # ---- sign in from the limited address, then 300 assets
            async with s.post(f"{ctx.base_url}/login", json={"username": USER, "password": PASSWORD},
                              headers={"CF-Connecting-IP": a1}) as r:
                await r.read()
                status = r.status
                session_cookie = r.cookies.get(COOKIE)
            ctx.ok("proxylimit: login still works from the limited address", status == 200 and session_cookie is not None, str(status))
            if session_cookie is not None:
                ck = {"Cookie": f"{COOKIE}={session_cookie.value}"}
                got, _ = await _hits(ctx, s, a1, 300, f"/proxy/{secrets.token_hex(8)}/assets/app.js", ck)
                ctx.ok("proxylimit: a logged-in page loading 300 assets through /proxy is unaffected (none 429)",
                       len(got) == 300 and 429 not in got, str(sorted(set(got))))
                got, _ = await _hits(ctx, s, a1, 80, "/search/", ck)
                ctx.ok("proxylimit: a signed-in client on /search is not limited", 429 not in got, str(sorted(set(got))))
                got, _ = await _hits(ctx, s, a1, 80, f"/browser?connection={secrets.token_hex(4)}", ck)
                ctx.ok("proxylimit: a signed-in client on /browser is not limited", 429 not in got, str(sorted(set(got))))
                async with ctx.http() as anon:     # no cookie jar contents: the same address, logged out
                    got, _ = await _hits(ctx, anon, a1, 40)
                ctx.ok("proxylimit: the same address logged out is still limited", 429 in got, str(sorted(set(got))))

            # ---- loopback is exempt
            got, _ = await _hits(ctx, s, None, 60)
            ctx.ok("proxylimit: a loopback client is never limited", 429 not in got, str(sorted(set(got))))

        # ---- off, and a saved rate, applied at start
        await ctx.stop_server()
        _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_limit_enabled', '0')")
        await ctx.start_server(wait_healthy=True)
        async with ctx.http() as s:
            got, _ = await _hits(ctx, s, a4, 60)
            ctx.ok("proxylimit: switched off, nothing is limited", 429 not in got, str(sorted(set(got))))
        await ctx.stop_server()
        _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_limit_enabled', '1')")
        _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_limit_per_minute', '10')")
        await ctx.start_server(wait_healthy=True)
        async with ctx.http() as s:
            got, _ = await _hits(ctx, s, a5, 20)
            first = _first_429(got)
            ctx.ok("proxylimit: a saved rate of 10 limits from the 11th request", first is not None and 11 <= first <= 12, f"first 429 at {first}")

            if ctx.admin_password:
                async with ctx.http() as adm:
                    r = await ctx.login(adm, ctx.admin_user, ctx.admin_password)
                    if r.status != 200:
                        ctx.ok("proxylimit: admin login", False, f"status {r.status}")
                    else:
                        async with adm.get(f"{ctx.base_url}/api/admin/proxy-limit", headers={"Accept": "application/json"}) as r2:
                            cfg = await r2.json(content_type=None)
                        ctx.ok("proxylimit: the settings route shows what was saved",
                               cfg.get("enabled") is True and cfg.get("per_minute") == 10, str(cfg))
            else:
                ctx.skip("proxylimit: settings route", "no admin password (use --admin-password)")
    finally:
        try:
            await ctx.stop_server()
        except Exception:
            pass
        for k in KEYS:
            _sql(ctx, "DELETE FROM settings WHERE key = ?", (k,))
            if saved.get(k):
                _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, saved[k][0][0]))
        for e, was in zip(envs, had_trust):
            if was is None:
                e.pop("TRUSTED_PROXIES", None)
            else:
                e["TRUSTED_PROXIES"] = was
        await ctx.start_server(wait_healthy=True)
