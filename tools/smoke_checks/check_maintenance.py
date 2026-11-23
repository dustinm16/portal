"""Smoke checks: maintenance of a connection, the global flag and announcements, over real TLS.

On the staged instance:
  - a connection in maintenance answers a member on /proxy and /browser with 503, Retry-After and the page
    ("Down for maintenance until ..." and the escaped message), refuses the terminal WebSocket before the
    upgrade, lets its administrator owner through and tells a member without access exactly what it always did
  - the global flag blocks /proxy for a member, never /login, /api/me or /health, the administrator signs in
    and passes, and `maintenance_cli.maintenance_off` run against the database while the server is up clears it
    within a few seconds, with the audit row
  - an outage announcement with a script tag in its text is served as plain text to members, never to visitors
    until "show before sign-in" is ticked, and is gone once ended

The connection points at 169.254.169.254, an address the host policy refuses without dialling, so nothing is ever
sent out: the maintenance answer comes before the host check, and once the maintenance is over a request gets the
policy's 403 "Host not allowed" instead of a maintenance page.

The users carry a random suffix and the module asserts on its own rows only, so it also passes on a copy of a
production database (--from-db). At the end it removes the connection (and with it the shares) and the announcements
it made; the three users it created, their sessions and the audit rows stay (the names carry the random suffix).
No admin password is needed: the module makes its own administrator. If the global flag is already set on the
instance, the global part is skipped and nothing is changed.
"""

import asyncio
import re
import secrets
from datetime import datetime, timedelta, timezone

import aiohttp

SUFFIX = secrets.token_hex(3)
ADMIN = f"smoke_mt_adm_{SUFFIX}"
MEMBER = f"smoke_mt_mem_{SUFFIX}"
OUTSIDER = f"smoke_mt_out_{SUFFIX}"
PASSWORD = "Smoke-Maint-Pw-1!"
MARK = f"smokemark{SUFFIX}"
CONN = f"smoke-mt-{SUFFIX}"

SETUP = f"""
import asyncio
import database
from auth import create_user

async def main():
    db = database.db
    await db.connect()
    for name, admin in (({ADMIN!r}, True), ({MEMBER!r}, False), ({OUTSIDER!r}, False)):
        if not await db.get_user_by_username(name):
            await create_user(name, {PASSWORD!r}, is_admin=admin)
    adm = await db.get_user_by_username({ADMIN!r})
    await db.set_user_role(adm["id"], "superadmin")
    uuid = await db.create_user_connection(adm["id"], {CONN!r}, "http", "169.254.169.254", 80, "{{}}")
    print("UUID=" + uuid)
    await db.close()

asyncio.run(main())
"""

CLEAR = """
import maintenance_cli
from config import Config
raise SystemExit(maintenance_cli.maintenance_off(Config.DATABASE_PATH))
"""

AUDIT_COUNT = f"""
import asyncio
import database

async def main():
    db = database.db
    await db.connect()
    for tag, action in (("SET", "maintenance.global_set"), ("CLEAR", "maintenance.global_clear")):
        rows = await db.get_audit_log(limit=5, action=action)
        print(tag + "=" + str(sum(1 for r in rows if r["actor_username"].startswith(({ADMIN!r}, "(command line")) and {SUFFIX!r} in str(r.get("details") or "") + r["actor_username"] + str(r.get("target_name") or "") or (tag == "CLEAR" and r["actor_username"].startswith("(command line")))))
    await db.close()

asyncio.run(main())
"""

CLEANUP = f"""
import asyncio
import database

async def main():
    db = database.db
    await db.connect()
    await db.conn.execute("DELETE FROM user_connections WHERE name = ?", ({CONN!r},))
    await db.conn.execute("DELETE FROM announcements WHERE body LIKE ?", ('%{MARK}%',))
    await db.conn.commit()
    await db.close()

asyncio.run(main())
"""


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def run(ctx):
    base = ctx.base_url
    rc, out = await ctx.run_py(SETUP)
    ctx.ok("maintenance: create an administrator, two members and a connection", rc == 0 and "UUID=" in out, out.strip()[-200:])
    if rc != 0 or "UUID=" not in out:
        return
    uuid = out.split("UUID=")[1].split()[0]
    sessions = {}
    try:
        for name in (ADMIN, MEMBER, OUTSIDER):
            s = ctx.http()
            resp = await ctx.login(s, name, PASSWORD)
            if resp.status != 200:
                ctx.ok(f"maintenance: sign in as {name}", False, f"status {resp.status}")
                return
            sessions[name] = s
        adm, mem, out_s = sessions[ADMIN], sessions[MEMBER], sessions[OUTSIDER]

        async with adm.post(f"{base}/api/connections/{uuid}/shares", json={"usernames": [MEMBER]}) as r:
            ctx.ok("maintenance: share the connection with the member", r.status == 200, str(r.status))
        async with mem.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            await r.read()
            before = r.status
        async with out_s.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            outsider_before = (r.status, await r.text())

        # ---- one connection -----------------------------------------------------------------------------------
        until = datetime.now(timezone.utc) + timedelta(hours=2)
        msg = f"<b>{MARK}</b> disk swap"
        async with adm.put(f"{base}/api/connections/{uuid}", json={
                "maintenance": True, "maintenance_until": iso(until), "maintenance_message": msg}) as r:
            ctx.ok("maintenance: the administrator puts the connection in maintenance", r.status == 200, str(r.status))
        async with mem.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            page = await r.text()
            ctx.ok("maintenance: /proxy answers a member 503 with Retry-After and the maintenance page",
                   r.status == 503 and bool(r.headers.get("Retry-After")) and "Down for maintenance" in page
                   and f"&lt;b&gt;{MARK}&lt;/b&gt;" in page and f"<b>{MARK}" not in page, f"{r.status} {page[:200]}")
        async with mem.get(f"{base}/browser?connection={uuid}", allow_redirects=False) as r:
            ctx.ok("maintenance: /browser answers 503 too", r.status == 503, str(r.status))
        try:
            ws = await mem.ws_connect(f"{base.replace('https', 'wss')}/ws/user-connection/{uuid}")
            await ws.close()
            ctx.ok("maintenance: the terminal WebSocket is refused before the upgrade", False, "it opened")
        except aiohttp.WSServerHandshakeError as e:
            ctx.ok("maintenance: the terminal WebSocket is refused before the upgrade (503)", e.status == 503, str(e.status))
        async with adm.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            ctx.ok("maintenance: the administrator is not stopped by the maintenance page (the host policy refuses, nothing is dialled)",
                   r.status == 403 and "Down for maintenance" not in await r.text(), str(r.status))
        async with out_s.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            ctx.ok("maintenance: a member without access gets exactly the answer they got before",
                   (r.status, await r.text()) == outsider_before and outsider_before[0] == 404)
        async with adm.put(f"{base}/api/connections/{uuid}", json={"maintenance": False}) as r:
            ctx.ok("maintenance: the administrator ends it", r.status == 200)
        async with mem.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
            ctx.ok("maintenance: the member is no longer shown the maintenance page (the host policy refuses instead)",
                   r.status == 403 and "Down for maintenance" not in await r.text(), str(r.status))

        # ---- the global flag ------------------------------------------------------------------------------------------
        async with adm.get(f"{base}/api/admin/maintenance") as r:
            flag = await r.json()
        if flag.get("set"):
            ctx.skip("maintenance: the global flag", "it is already set on this instance; left alone")
        else:
            try:
                async with adm.put(f"{base}/api/admin/maintenance", json={"active": True, "message": f"{MARK} global"}) as r:
                    ctx.ok("maintenance: a superadmin sets the global flag", r.status == 200, str(r.status))
                await asyncio.sleep(3.5)       # the server reads the flag at most every 3 seconds
                async with mem.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
                    page = await r.text()
                    ctx.ok("maintenance: /proxy answers a member 503 with the global message",
                           r.status == 503 and f"{MARK} global" in page, f"{r.status}")
                for path in ("/login", "/api/me", "/health"):
                    async with mem.get(base + path, allow_redirects=False) as r:
                        await r.read()
                        ctx.ok(f"maintenance: {path} is not blocked by the global flag", r.status in (200, 302), str(r.status))
                async with ctx.http() as fresh:
                    resp = await ctx.login(fresh, ADMIN, PASSWORD)
                    ctx.ok("maintenance: the administrator can sign in while it is set", resp.status == 200, str(resp.status))
                    async with fresh.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
                        ctx.ok("maintenance: ... and passes through (to the host policy's refusal)",
                               r.status == 403 and "Down for maintenance" not in await r.text(), str(r.status))
                rc, out = await ctx.run_py(CLEAR)
                ctx.ok("maintenance: the command-line clear works while the server runs", rc == 0 and "cleared" in out, out.strip()[-200:])
                cleared = False
                for _ in range(12):
                    async with mem.get(f"{base}/proxy/{uuid}/", allow_redirects=False) as r:
                        if "Down for maintenance" not in await r.text():
                            cleared = True
                            break
                    await asyncio.sleep(1)
                ctx.ok("maintenance: the running server lets the member through within seconds, no restart", cleared)
                rc, out = await ctx.run_py(AUDIT_COUNT)
                ctx.ok("maintenance: the set and the command-line clear are in the audit log",
                       rc == 0 and re.search(r"SET=[1-9]", out) is not None and re.search(r"CLEAR=[1-9]", out) is not None,
                       out.strip()[-200:])
            finally:
                async with adm.put(f"{base}/api/admin/maintenance", json={"active": False}) as r:
                    await r.read()

        # ---- announcements ----------------------------------------------------------------------------------------------
        text = f"{MARK} <script>alert(1)</script> [x](javascript:alert(1)) **bold**"
        async with adm.post(f"{base}/api/admin/announcements", json={"level": "outage", "body": text}) as r:
            created = await r.json()
            ctx.ok("announcements: an administrator publishes an outage announcement", r.status == 201, str(r.status))
        aid = created.get("id")
        async with mem.get(f"{base}/api/announcements") as r:
            mine = [a for a in (await r.json())["announcements"] if MARK in a["body"]]
            ctx.ok("announcements: a member gets it as plain text (JSON, nothing turned into markup)",
                   len(mine) == 1 and mine[0]["body"] == text and r.headers["Content-Type"].startswith("application/json"))
        async with ctx.http() as anon:
            async with anon.get(f"{base}/api/announcements/public") as r:
                ctx.ok("announcements: a visitor does not get it (show before sign-in is off)", MARK not in await r.text())
            async with anon.get(f"{base}/login") as r:
                ctx.ok("announcements: the sign-in page does not contain it", MARK not in await r.text())
            async with adm.put(f"{base}/api/admin/announcements/{aid}", json={"show_before_signin": True}) as r:
                ctx.ok("announcements: show before sign-in can be ticked", r.status == 200)
            async with anon.get(f"{base}/api/announcements/public") as r:
                ctx.ok("announcements: now a visitor gets it", MARK in await r.text())
        async with mem.post(f"{base}/api/admin/announcements", json={"level": "info", "body": "x"}) as r:
            ctx.ok("announcements: a member cannot publish (403)", r.status == 403, str(r.status))
        async with adm.post(f"{base}/api/admin/announcements/{aid}/end") as r:
            ctx.ok("announcements: an administrator ends it", r.status == 200)
        async with mem.get(f"{base}/api/announcements") as r:
            ctx.ok("announcements: an ended announcement is gone for members", MARK not in await r.text())
        async with adm.delete(f"{base}/api/admin/announcements/{aid}") as r:
            ctx.ok("announcements: and can be deleted", r.status == 200)
    finally:
        for s in sessions.values():
            await s.close()
        await ctx.run_py(CLEANUP)
