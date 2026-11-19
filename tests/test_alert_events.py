"""Alert events through the real server pieces: security_event hooks, system hooks, a
receiver on 127.0.0.1, the in-portal notification, backup and update emitters. Nothing
leaves this machine.

Run: venv/bin/python tests/test_alert_events.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import alerts  # noqa: E402
import backup_manager  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


got = []


async def receiver(request):
    got.append((request.path, dict(request.headers), await request.read()))
    return web.Response(status=204)


async def settle(n=40):
    for _ in range(n):
        await asyncio.sleep(0.02)
        if not alerts._tasks:
            break
    for _ in range(10):
        await asyncio.sleep(0.02)
    while alerts._tasks:
        await asyncio.gather(*list(alerts._tasks), return_exceptions=True)


async def hook(db, fmt, url, events, details=False, kind="system", uid=None):
    h = await db.create_webhook(uid, f"a-{fmt}", "outgoing", url=url, events=list(events), fmt=fmt,
                                include_details=details, allow_private=True, kind=kind)
    return h["id"]


async def notes(db, uid):
    cur = await db.conn.execute("SELECT type, data FROM notifications WHERE user_id = ?", (uid,))
    return [dict(r) for r in await cur.fetchall()]


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    db = server.db
    await db.conn.execute("INSERT INTO users (username, password_hash, role, is_admin) VALUES ('adm', 'x', 'admin', 1)")
    await db.conn.execute("INSERT INTO users (username, password_hash, role) VALUES ('plain', 'x', 'user')")
    await db.conn.commit()
    adm = (await (await db.conn.execute("SELECT id FROM users WHERE username='adm'")).fetchone())["id"]
    plain = (await (await db.conn.execute("SELECT id FROM users WHERE username='plain'")).fetchone())["id"]
    Config.TOTP_ISSUER = "Test Portal"
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", receiver)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    import secevents
    secevents.log.bind(db)
    alerts.reset_state()
    server._bind_alerts()

    # ---- nothing subscribed: nothing leaves, the admin is still told in the portal
    await server.security_event("role_changed", ip="203.0.113.5", user_id=adm, username="adm",
                                details={"target_user_id": plain, "target_username": "plain",
                                         "old_role": "user", "new_role": "moderator"})
    await settle()
    check("no hook: nothing was sent", got == [])
    n = await notes(db, adm)
    check("an administrator got an in-portal notification by default", any(x["type"] == "alert" for x in n), str(n))
    check("an ordinary member got none", await notes(db, plain) == [])
    cur = await db.conn.execute("SELECT COUNT(*) c FROM security_events WHERE event = 'role_changed'")
    check("the security event was written once (not duplicated by the alert)", (await cur.fetchone())["c"] == 1)

    # ---- '*' on a system hook, and a user hook naming the event: nothing
    await hook(db, "generic", base + "/star", ["*"])
    await hook(db, "discord", base + "/star2", ["*"])
    await hook(db, "generic", base + "/user", ["role.changed"], kind="user", uid=adm)
    alerts.reset_state()
    await server.security_event("role_changed", ip="203.0.113.5", user_id=adm, username="adm",
                                details={"target_user_id": plain, "target_username": "plain",
                                         "old_role": "moderator", "new_role": "user"})
    await settle()
    check("'*' system hooks and a user hook receive no alert", got == [], str([g[0] for g in got]))

    # ---- named subscriptions: generic minimal, discord minimal, generic with details
    await hook(db, "generic", base + "/g", ["role.changed"])
    await hook(db, "discord", base + "/d", ["role.changed"])
    await hook(db, "generic", base + "/gd", ["role.changed"], details=True)
    alerts.reset_state()
    await server.security_event("role_changed", ip="203.0.113.5", user_id=adm, username="adm",
                                details={"target_user_id": plain, "target_username": "plain",
                                         "old_role": "user", "new_role": "admin"})
    await settle()
    by = {p: (h, b) for p, h, b in got}
    check("three named hooks each received one delivery", sorted(by) == ["/d", "/g", "/gd"], str(sorted(by)))
    g = json.loads(by["/g"][1])
    check("generic: event, title and summary, signed, no details and no address",
          g["event"] == "role.changed" and "plain" in g["data"]["summary"] and "details" not in g["data"]
          and "203.0.113.5" not in by["/g"][1].decode() and "X-Portal-Signature" in by["/g"][0])
    check("discord: no address", b"203.0.113.5" not in by["/d"][1] and b"plain" in by["/d"][1])
    gd = json.loads(by["/gd"][1])
    check("include_details adds the address", gd["data"]["details"]["Address"] == "203.0.113.5")
    got.clear()

    # ---- failed-sign-in burst through the aggregated path
    await hook(db, "generic", base + "/b", ["auth.login_failed_burst"])
    alerts.reset_state()
    for i in range(5):
        server.security_event_nowait("login_failed", ip="198.51.100.20", username="plain", result="bad_password")
    await settle()
    check("five failed sign-ins: one burst alert", [p for p, _, _ in got].count("/b") == 1, str([g[0] for g in got]))
    for i in range(10):
        server.security_event_nowait("login_failed", ip="198.51.100.20", username="plain", result="bad_password")
    await settle()
    check("more failures inside the cooldown: no second alert", [p for p, _, _ in got].count("/b") == 1)
    cur = await db.conn.execute("SELECT COUNT(*) c FROM security_events WHERE event = 'login_failed_burst'")
    check("every burst writes one security event, the two held back by the cooldown included",
          (await cur.fetchone())["c"] == 3)
    got.clear()

    # ---- a delivery failure cannot break the action
    real_fire = server.fire_webhook_event

    async def broken(*a, **k):
        raise RuntimeError("boom")

    alerts.bind(fire=broken, notify=server._alert_notify_admins, get_setting=db.get_setting, set_setting=db.set_setting)
    alerts.reset_state()
    await server.security_event("2fa_disabled", ip="203.0.113.5", user_id=plain, username="plain")
    await settle()
    check("security_event returns normally when the alert path fails", True)
    server._bind_alerts()

    # ---- staged instance: nothing sent except to the sink
    Config.STAGE_MODE = True
    try:
        await hook(db, "generic", base + "/stage", ["2fa.disabled"])
        alerts.reset_state()
        await server.security_event("2fa_disabled", ip="203.0.113.5", user_id=plain, username="plain")
        await settle()
        check("staged: no delivery without the loopback sink setting", got == [], str([g[0] for g in got]))
        await db.set_setting("stage_webhook_sink_port", str(srv.port))
        alerts.reset_state()
        await server.security_event("2fa_disabled", ip="203.0.113.5", user_id=plain, username="plain")
        await settle()
        check("staged: delivered to the test receiver only", [p for p, _, _ in got] == ["/stage"], str([g[0] for g in got]))
    finally:
        Config.STAGE_MODE = False
    got.clear()

    # ---- backup emitters
    await hook(db, "generic", base + "/bk", ["backup.ok", "backup.failed"])
    alerts.reset_state()
    real_create = backup_manager.create_archive

    def ok_archive(*a, **k):
        return {"name": "portal-test.tar", "pruned": []}

    def bad_archive(*a, **k):
        raise OSError("disk full")

    backup_manager.create_archive = ok_archive
    await backup_manager.run_now("scheduled")
    backup_manager.create_archive = bad_archive
    try:
        await backup_manager.run_now("manual")
    except OSError:
        pass
    backup_manager.create_archive = real_create
    await settle()
    evs = [json.loads(b)["event"] for p, _, b in got if p == "/bk"]
    check("backup.ok and backup.failed are sent", sorted(evs) == ["backup.failed", "backup.ok"], str(evs))
    check("the error text is not in the default payload",
          all(b"disk full" not in b for p, _, b in got if p == "/bk"))
    n = await notes(db, adm)
    check("backup.ok makes no in-portal notification by default",
          not any("backup.ok" in x["data"] for x in n), str(n))
    got.clear()

    # ---- update.available through the update checker's hook
    await hook(db, "generic", base + "/up", ["update.available"])
    alerts.reset_state()
    import update_manager
    res = {"portal": {"update_available": True, "latest": "9.9.9", "current": "1.0.0"}}
    update_manager.announce_updates(res)
    await settle()
    update_manager.announce_updates(res)
    await settle()
    check("update.available once per version", [p for p, _, _ in got].count("/up") == 1)

    src = (Path(__file__).resolve().parent.parent / "server.py").read_text()
    for kind in ("timeout", "mute", "ban", "kick"):
        check(f"a {kind} calls the moderation alert", f'alerts.moderation_action(\n' in src and
              (f'"{kind}", actor=' in src))
    check("automod calls the automod alert", "alerts.automod_triggered(" in src)
    ban_src = src[src.index("async def http_create_stream_ban"):src.index("async def http_remove_stream_ban(")]
    check("the REST stream ban sends the moderation alert too", "alerts.moderation_action(" in ban_src
          and '"ban"' in ban_src and "anonymous=" in ban_src)
    check("every moderation call passes an anonymity flag", src.count("anonymous=") >= 5)

    Config.STAGE_MODE = False
    r = await server.http_admin_alerts_stage_reset(None)
    check("the stage-only reset route answers 404 on any other instance", r.status == 404)
    check("the alert groups are offered with the system hook list",
          [g["group"] for g in alerts.catalogue()] == ["security", "operations", "moderation"])

    await srv.close()
    await db.close()


asyncio.run(main())
if failures:
    print(f"\ntest_alert_events: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_alert_events: all checks passed")
