"""Admin announcements: who writes them, what a member and a signed-out visitor are told, the
active window with no clean-up job, the stored text (never turned into markup by the server),
the audit entries and the limits.

The real app on a loopback test server with a temporary database (tests/grant_harness.py).

Run: venv/bin/python tests/test_announcements.py
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
import announcements  # noqa: E402


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def rules():
    now = datetime(2030, 3, 4, 12, 0, 0, tzinfo=timezone.utc)
    ok = announcements.parse({"level": "outage", "body": "  Down <b>now</b>\r\nsecond line \x00 ", "show_before_signin": True}, now=now)
    check("rules: a create keeps the text as written (control characters out, trimmed, line breaks kept)",
          ok == {"level": "outage", "body": "Down <b>now</b>\nsecond line", "show_before_signin": 1}, str(ok))
    def bad(data, existing=None):
        try:
            announcements.parse(data, existing=existing, now=now)
            return False
        except ValueError:
            return True
    check("rules: a create needs a body", bad({"level": "info"}) and bad({"body": "   "}) and bad({"body": 5}))
    check("rules: the level must be info, warning or outage", bad({"body": "x", "level": "critical"}))
    check("rules: the body is limited", bad({"body": "x" * (announcements.BODY_MAX + 1)})
          and not bad({"body": "x" * announcements.BODY_MAX}))
    check("rules: unknown fields, a bad time and a flag that is not boolean are refused",
          bad({"body": "x", "extra": 1}) and bad({"body": "x", "starts_at": "soon"}) and bad({"body": "x", "show_before_signin": "yes"}))
    check("rules: the end must be after the start and ahead of now",
          bad({"body": "x", "starts_at": iso(now + timedelta(hours=2)), "ends_at": iso(now + timedelta(hours=1))})
          and bad({"body": "x", "ends_at": iso(now - timedelta(hours=1))})
          and not bad({"body": "x", "starts_at": iso(now + timedelta(hours=1)), "ends_at": iso(now + timedelta(hours=2))}))
    for extreme in ("0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"):
        check(f"rules: {extreme} is a ValueError (400), not an OverflowError (500)",
              bad({"body": "x", "ends_at": extreme}) and bad({"body": "x", "starts_at": extreme}))
    old = {"ends_at": iso(now - timedelta(days=1)), "starts_at": None}
    check("rules: an ended announcement can be edited without touching its end",
          not bad({"body": "new text"}, existing=old) and not bad({"ends_at": old["ends_at"]}, existing=old))
    row = {"starts_at": iso(now + timedelta(hours=1)), "ends_at": None}
    check("rules: status is scheduled, active or ended",
          announcements.status(row, now) == "scheduled"
          and announcements.status({"starts_at": None, "ends_at": None}, now) == "active"
          and announcements.status({"starts_at": None, "ends_at": iso(now)}, now) == "ended")


async def main():
    rules()
    env = await h.boot(names=("owner", "bob", "carol", "adm", "mod"))
    db = env.db
    await db.set_user_role(env.uid["mod"], "admin")
    await env.sessions["mod"].close()
    env.sessions["mod"] = await h.login(env.base, "mod")
    adm, bob, mod = env.sessions["adm"], env.sessions["bob"], env.sessions["mod"]
    admin_url = f"{env.base}/api/admin/announcements"
    anon = aiohttp.ClientSession()

    async def member_list(sess=bob):
        async with sess.get(f"{env.base}/api/announcements") as r:
            assert r.status == 200, r.status
            return (await r.json())["announcements"]

    async def public_list():
        async with anon.get(f"{env.base}/api/announcements/public") as r:
            assert r.status == 200, r.status
            return (await r.json())["announcements"]

    async with anon.get(f"{env.base}/api/announcements") as r:
        check("a signed-out visitor cannot read the member list (401)", r.status == 401, str(r.status))
    check("nothing yet: members and visitors see nothing", await member_list() == [] and await public_list() == [])

    # ---- who may write ---------------------------------------------------------------------------------
    body = {"level": "outage", "body": "Storage is down. <script>alert(1)</script> [x](javascript:alert(1)) **bold**"}
    async with bob.post(admin_url, json=body) as r:
        check("a member cannot create an announcement (403)", r.status == 403, str(r.status))
    async with bob.get(admin_url) as r:
        check("a member cannot list them with their schedule (403)", r.status == 403)
    async with anon.post(admin_url, json=body) as r:
        check("a visitor cannot create one (401)", r.status == 401)
    async with mod.post(admin_url, json=body) as r:
        created = await r.json()
        check("an administrator creates one", r.status == 201 and created["status"] == "active"
              and created["body"] == body["body"] and created["show_before_signin"] is False, str(created))
    aid = created["id"]
    for bad in ({"level": "info"}, {"level": "x", "body": "a"}, {"body": "x" * 1001}, {"body": "a", "ends_at": "yesterday"},
                {"body": "a", "ends_at": "0001-01-01T00:00:00+05:00"}, {"body": "a", "starts_at": "9999-12-31T23:59:59-05:00"}):
        async with mod.post(admin_url, json=bad) as r:
            check(f"create with {sorted(bad)} is refused (400)", r.status == 400, str(r.status))

    # ---- what members see ---------------------------------------------------------------------------------
    got = await member_list()
    check("a member sees it, with the text exactly as written (the server never turns it into markup)",
          len(got) == 1 and got[0]["body"] == body["body"] and got[0]["level"] == "outage"
          and set(got[0]) == {"id", "level", "body", "updated_at", "ends_at"}, str(got))
    async with bob.get(f"{env.base}/api/announcements") as r:
        check("... as JSON, not HTML, and never cached", r.headers["Content-Type"].startswith("application/json")
              and r.headers.get("Cache-Control") == "no-store")
    check("a visitor sees nothing: show before sign-in is off by default", await public_list() == [])
    async with anon.get(f"{env.base}/login") as r:
        page = await r.text()
        check("the login page carries no announcement text", "Storage is down" not in page and "alert(1)" not in page)

    # ---- show before sign-in -----------------------------------------------------------------------------------
    async with adm.put(f"{admin_url}/{aid}", json={"show_before_signin": True}) as r:
        check("an administrator ticks show before sign-in", r.status == 200 and (await r.json())["show_before_signin"] is True)
    pub = await public_list()
    check("a visitor now sees it (id, level, text; nothing about who wrote it or when it is scheduled)",
          len(pub) == 1 and pub[0]["body"] == body["body"] and "created_by" not in pub[0] and "starts_at" not in pub[0], str(pub))
    async with adm.post(admin_url, json={"level": "info", "body": "members only"}) as r:
        second = await r.json()
    pub = await public_list()
    check("an announcement without the tick never reaches a visitor", all("members only" not in p["body"] for p in pub))

    # ---- the window --------------------------------------------------------------------------------------------------
    future = iso(datetime.now(timezone.utc) + timedelta(hours=2))
    async with adm.post(admin_url, json={"level": "warning", "body": "later", "starts_at": future}) as r:
        sched = await r.json()
        check("a scheduled one is created as scheduled", r.status == 201 and sched["status"] == "scheduled")
    check("a scheduled announcement is not shown yet", all(a["id"] != sched["id"] for a in await member_list()))
    await db.conn.execute("UPDATE announcements SET starts_at = ?, ends_at = ? WHERE id = ?",
                          (iso(datetime.now(timezone.utc) - timedelta(hours=1)), iso(datetime.now(timezone.utc) + timedelta(hours=1)), sched["id"]))
    await db.conn.commit()
    check("once its start has passed it is shown (no job)", any(a["id"] == sched["id"] for a in await member_list()))
    await db.conn.execute("UPDATE announcements SET ends_at = ? WHERE id = ?",
                          (iso(datetime.now(timezone.utc) - timedelta(seconds=3)), sched["id"]))
    await db.conn.commit()
    check("once its end has passed it is gone (no job)", all(a["id"] != sched["id"] for a in await member_list()))

    # ---- edit shows again, end, delete, audit ----------------------------------------------------------------------------
    await db.conn.execute("UPDATE announcements SET updated_at = '2020-01-01T00:00:00Z' WHERE id = ?", (aid,))
    await db.conn.commit()
    async with adm.put(f"{admin_url}/{aid}", json={"body": "Storage is back soon", "level": "warning"}) as r:
        edited = await r.json()
        check("an edit changes the text and the level", r.status == 200 and edited["body"] == "Storage is back soon"
              and edited["level"] == "warning")
    check("an edit moves updated_at (a dismissal is remembered by id and that time, so it shows again)",
          edited["updated_at"] != "2020-01-01T00:00:00Z" and (await member_list())[-1]["updated_at"] == edited["updated_at"]
          or any(a["id"] == aid and a["updated_at"] == edited["updated_at"] for a in await member_list()))
    async with adm.put(f"{admin_url}/{aid}", json={}) as r:
        check("an edit with nothing in it is refused (400)", r.status == 400)
    async with adm.put(f"{admin_url}/99999", json={"body": "x"}) as r:
        check("an unknown id is 404", r.status == 404)
    async with adm.put(f"{admin_url}/abc", json={"body": "x"}) as r:
        check("a bad id is 400", r.status == 400)
    async with adm.post(f"{admin_url}/{aid}/end") as r:
        ended = await r.json()
        check("End now ends it and keeps it in the list as ended", r.status == 200 and ended["status"] == "ended")
    check("an ended announcement is not shown to members or visitors",
          all(a["id"] != aid for a in await member_list()) and await public_list() == [])
    async with adm.get(admin_url) as r:
        listing = (await r.json())["announcements"]
        check("the admin list still has it, with its status",
              {a["id"]: a["status"] for a in listing}.get(aid) == "ended")
    async with adm.delete(f"{admin_url}/{second['id']}") as r:
        check("an administrator deletes one", r.status == 200)
    async with adm.delete(f"{admin_url}/{second['id']}") as r:
        check("deleting it again is 404", r.status == 404)
    for action, n in (("announcement.create", 3), ("announcement.update", 2), ("announcement.end", 1), ("announcement.delete", 1)):
        rows = await db.get_audit_log(limit=50, action=action)
        check(f"audit: {action} x{n}", len(rows) == n, str(len(rows)))
    rows = await db.get_audit_log(limit=50, action="announcement.update")
    check("audit entries name the actor and carry the text excerpt and the level",
          {r["actor_username"] for r in rows} == {"adm"} and any("Storage is back soon" in (r["details"] or "") for r in rows),
          str([(r["actor_username"], r["details"]) for r in rows]))

    # ---- limits -----------------------------------------------------------------------------------------------------------
    announcements.MAX_ROWS = (await db.count_announcements())
    async with adm.post(admin_url, json={"body": "one too many"}) as r:
        check("there is a cap on the number of rows", r.status == 400)

    await anon.close()
    await h.shutdown(env)


asyncio.run(main())
h.finish("test_announcements")
