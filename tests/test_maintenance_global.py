"""The global maintenance flag: set by a superadmin with a message and an optional end time, gating
/proxy, /browser and /search for everyone but administrators, never /login, /logout, /api, /admin,
/health, static files or any page, cleared from the command line while the server runs, audited.

The real app on a loopback test server with a temporary database (tests/grant_harness.py).

Run: venv/bin/python tests/test_maintenance_global.py
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
import maintenance  # noqa: E402
import maintenance_cli  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def main():
    async def ok_page(request):
        return web.Response(text="upstream-ok")

    up = web.Application()
    up.router.add_get("/{p:.*}", ok_page)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()

    env = await h.boot(names=("owner", "bob", "carol", "adm", "mod"))
    db = env.db
    await db.set_user_role(env.uid["mod"], "admin")
    # the role is read when a session is made: log mod in again
    await env.sessions["mod"].close()
    env.sessions["mod"] = await h.login(env.base, "mod")
    adm, bob, carol, mod = (env.sessions[n] for n in ("adm", "bob", "carol", "mod"))
    server._MAINT_CACHE_TTL = 0.05

    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    uuid, _ = await h.connection(env, "adm", name="web", ctype="http", host="127.0.0.1", port=upstream.port)
    box, _ = await h.connection(env, "adm", name="box")
    for u in (uuid, box):
        async with adm.post(f"{env.base}/api/connections/{u}/shares", json={"usernames": ["bob", "mod"]}) as r:
            assert r.status == 200
    await db.create_service("searxng", "/search", plugin="searxng", service_type="managed", host="127.0.0.1", port=8890)
    url = f"{env.base}/api/admin/maintenance"

    NEVER = ["/login", "/api/me", "/api/connections", "/api/services", "/health", "/static/js/portal.js",
             "/static/css/portal.css", "/dashboard", "/chat", "/admin", "/api/search/status", "/robots.txt",
             f"/api/connections/{uuid}"]

    async def statuses(sess):
        out = {}
        for p in NEVER:
            async with sess.get(env.base + p, allow_redirects=False) as r:
                out[p] = r.status
        return out

    bob_before = await statuses(bob)
    carol_before = {}
    async with carol.get(f"{env.base}/proxy/{uuid}/x") as r:
        carol_before = (r.status, await r.text())

    # ---- who may set it --------------------------------------------------------------------------------
    body = {"active": True, "message": "Moving to new disks <b>soon</b>",
            "until": iso(datetime.now(timezone.utc) + timedelta(hours=3))}
    for sess, label in ((bob, "a member"), (mod, "an admin who is not a superadmin")):
        async with sess.put(url, json=body) as r:
            check(f"{label} cannot set the global flag (403)", r.status == 403, str(r.status))
    async with bob.get(url) as r:
        check("a member cannot read the admin view (403)", r.status == 403)
    async with mod.get(url) as r:
        j = await r.json()
        check("an administrator can read it (nothing set yet)", r.status == 200 and j["set"] is False and j["active"] is False)
    for bad, why in (({"active": "yes"}, "a non-boolean flag"), ({"active": True, "until": "tomorrow"}, "a bad end time"),
                     ({"active": True, "until": iso(datetime.now(timezone.utc) - timedelta(hours=1))}, "a past end time"),
                     ({"active": True, "until": "0001-01-01T00:00:00+05:00"}, "an end time that overflows in UTC (early)"),
                     ({"active": True, "until": "9999-12-31T23:59:59-05:00"}, "an end time that overflows in UTC (late)"),
                     ({"active": True, "message": "x" * 201}, "a message over the limit"),
                     ({"active": True, "mesage": "typo"}, "an unknown field")):
        async with adm.put(url, json=bad) as r:
            check(f"{why} is refused (400)", r.status == 400, str(r.status))
    async with adm.get(url) as r:
        check("(nothing was stored by the refused requests)", (await r.json())["set"] is False)

    # ---- set -------------------------------------------------------------------------------------------
    async with adm.put(url, json=body) as r:
        j = await r.json()
        check("a superadmin sets the flag", r.status == 200 and j["active"] is True and j["message"] == body["message"]
              and j["until"] == body["until"] and j["set_by"] == "adm", str(j))
    check("the audit log has the set (who, was, now)",
          len(await db.get_audit_log(action="maintenance.global_set")) == 1)

    # ---- what it blocks ----------------------------------------------------------------------------------
    async with bob.get(f"{env.base}/proxy/{uuid}/x") as r:
        page = await r.text()
        check("/proxy: a member gets 503 with Retry-After, the end time and the escaped message",
              r.status == 503 and r.headers.get("Retry-After") and "Down for maintenance until" in page
              and "Moving to new disks &lt;b&gt;soon&lt;/b&gt;" in page and "<b>soon" not in page, page[:200])
    async with bob.get(f"{env.base}/browser?connection={uuid}") as r:
        check("/browser: 503", r.status == 503)
    async with bob.get(f"{env.base}/search/?q=x", headers={"Accept": "text/html"}) as r:
        check("/search: 503 with the maintenance page", r.status == 503 and "Down for maintenance" in await r.text())
    async with bob.get(f"{env.base}/search/?q=x&format=json") as r:
        check("/search: JSON for format=json", r.status == 503 and (await r.json()).get("maintenance") is True)
    for sess, label in ((adm, "a superadmin"), (mod, "an admin")):
        async with sess.get(f"{env.base}/proxy/{uuid}/x") as r:
            check(f"/proxy: {label} passes through", (r.status, await r.text()) == (200, "upstream-ok"))
        async with sess.get(f"{env.base}/browser?connection={uuid}") as r:
            check(f"/browser: {label} passes through", r.status == 200)
    async with carol.get(f"{env.base}/proxy/{uuid}/x") as r:
        check("someone without access gets the same 404 as before the flag", (r.status, await r.text()) == carol_before)

    check("never blocked: login, API, health, static files and every page answer a member as before",
          await statuses(bob) == bob_before, f"{bob_before} != {await statuses(bob)}")
    ws, msg = await h.open_ws(bob, env.base, box)
    check("terminal sockets are not covered by the global flag (only by a flag on the connection)",
          msg.type == aiohttp.WSMsgType.TEXT)
    await ws.close()
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        async with s.post(env.base + "/login", json={"username": "adm", "password": h.PW}) as r:
            check("the administrator can sign in while the flag is set", r.status == 200)
        async with s.get(f"{env.base}/api/admin/maintenance") as r:
            j = await r.json() if r.status == 200 else {}
            check("(and the admin API answers)", r.status == 200 and j.get("active") is True, f"{r.status} {j}")
        async with s.post(env.base + "/login", json={"username": "bob", "password": h.PW}) as r:
            check("so can a member (only the proxied paths are gated)", r.status == 200)

    # ---- an end time that passes needs no clean-up -------------------------------------------------------------
    past = iso(datetime.now(timezone.utc) - timedelta(seconds=5))
    stored = maintenance.encode_global("old", past, "adm")
    await db.set_setting(maintenance.GLOBAL_KEY, stored)
    await asyncio.sleep(0.1)
    async with bob.get(f"{env.base}/proxy/{uuid}/x") as r:
        check("a flag whose end time has passed no longer blocks", (r.status, await r.text()) == (200, "upstream-ok"))
    async with adm.get(url) as r:
        j = await r.json()
        check("(the admin view still shows it as set, and not active)", j["set"] is True and j["active"] is False)

    # ---- the command line clears it while the server runs ----------------------------------------------------------
    async with adm.put(url, json={"active": True, "message": "again"}) as r:
        check("set again, open-ended", r.status == 200 and (await r.json())["until"] is None)
    async with bob.get(f"{env.base}/proxy/{uuid}/x") as r:
        check("open-ended: blocked, Retry-After at the cap", r.status == 503
              and r.headers.get("Retry-After") == str(maintenance.RETRY_AFTER_CAP))
    env_vars = dict(os.environ, DATABASE_PATH=db.db_path, JWT_SECRET="x" * 64)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(ROOT / "server.py"), "maintenance-off", env=env_vars, cwd=str(ROOT),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await asyncio.wait_for(proc.communicate(), 60)
    check("server.py maintenance-off exits 0 and says it cleared the flag",
          proc.returncode == 0 and b"cleared" in out, out.decode()[-300:])
    await asyncio.sleep(0.15)
    async with bob.get(f"{env.base}/proxy/{uuid}/x") as r:
        check("the running server lets members through again without a restart", (r.status, await r.text()) == (200, "upstream-ok"))
    rows = await db.get_audit_log(limit=50, action="maintenance.global_clear")
    check("the command-line clear is in the audit log under a command-line actor",
          len(rows) == 1 and rows[0]["actor_username"].startswith("(command line"), str(rows))
    cur = await db.conn.execute("SELECT event, ip, details FROM security_events WHERE event = 'maintenance_changed' ORDER BY id")
    ev = await cur.fetchall()
    check("every set and clear is a security event too (two sets, one command-line clear)",
          len(ev) == 3 and "cli" in (ev[-1]["details"] or ""), str([dict(e) for e in ev]))
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(ROOT / "server.py"), "maintenance-off", env=env_vars, cwd=str(ROOT),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await asyncio.wait_for(proc.communicate(), 60)
    check("clearing again says it was not set and exits 0", proc.returncode == 0 and b"not set" in out)
    check("... and writes no second audit row",
          len(await db.get_audit_log(limit=50, action="maintenance.global_clear")) == 1)

    # ---- clear by the API ----------------------------------------------------------------------------------------------
    async with adm.put(url, json={"active": True, "message": "third"}) as r:
        assert r.status == 200
    async with adm.put(url, json={"active": False}) as r:
        j = await r.json()
        check("a superadmin clears it by the API", r.status == 200 and j["set"] is False and j["active"] is False)
    check("the audit log has set and clear from the API",
          len(await db.get_audit_log(limit=50, action="maintenance.global_set")) == 3
          and len(await db.get_audit_log(limit=50, action="maintenance.global_clear")) == 2)
    async with bob.get(f"{env.base}/proxy/{uuid}/x") as r:
        check("members pass after the clear", r.status == 200)

    # ---- the tool never makes a database ----------------------------------------------------------------------------------
    try:
        maintenance_cli.maintenance_off("/nonexistent/dir/none.db")
        check("the command never creates a missing database", False)
    except SystemExit as e:
        check("the command never creates a missing database", "no database" in str(e.code) and not Path("/nonexistent").exists())

    await h.shutdown(env)
    await upstream.close()


asyncio.run(main())
h.finish("test_maintenance_global")
