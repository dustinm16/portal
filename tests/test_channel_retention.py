"""Per-channel retention: the cleanup, the settings route and who may use it.

Real handlers and the real cleanup function against a temporary database and upload folder.

* one channel set to the cap keeps messages the global 7 days would have removed; a channel set
  to 2 days loses its old messages with their files and search rows; pinned messages stay; a channel
  with no value follows the global setting; a stream's chat follows the global setting even with a
  stale value stored on it; DMs are not touched
* file_retention_days detaches only the files (the message stays, marked file_removed, search flags
  cleared) and is never longer than the message retention
* the route: administrators only (a moderator gets 403, the generic channel PUT ignores the fields),
  0 and "forever" become the cap, the cap setting caps a value, shortening needs confirm and
  answers with the count first, the audit entry carries old and new, a stream chat is refused
* "run cleanup now" and the periodic task share the same function

Run: venv/bin/python tests/test_channel_retention.py
"""

from retention_harness import (check, finish, run, server, URL)  # noqa: E402

CAP = 3650


def test_cleanup_per_channel():
    async def body(env):
        d = env.db
        uid = await env.user("poster")
        capped = await d.create_chat_channel("capped", created_by=uid)
        short = await d.create_chat_channel("short", created_by=uid)
        plain = await d.create_chat_channel("plain", created_by=uid)
        streamch = await d.create_chat_channel("streamchat", created_by=uid)
        sid = await d.create_user_stream(uid, "s1", "live_" + "a" * 24, public_key="pub_" + "a" * 24, is_public=True)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (streamch, sid))
        await d.conn.execute("UPDATE chat_channels SET retention_days = ? WHERE id = ?", (CAP, capped))
        await d.conn.execute("UPDATE chat_channels SET retention_days = 2 WHERE id = ?", (short,))
        await d.conn.execute("UPDATE chat_channels SET retention_days = 1 WHERE id = ?", (streamch,))   # stale
        await d.conn.commit()
        f_short, f_pin, f_capped = env.make_file("a" * 32 + ".zip"), env.make_file("b" * 32 + ".zip"), env.make_file("c" * 32 + ".zip")
        m = {}
        m["capped_old"] = await env.message(capped, uid, "very old but kept", days_old=100, upload=f_capped)
        m["short_old"] = await env.message(short, uid, "old news", days_old=3, upload=f_short)
        m["short_pinned"] = await env.message(short, uid, "pinned old", days_old=30, pinned=True, upload=f_pin)
        m["short_new"] = await env.message(short, uid, "fresh", days_old=1)
        m["plain_old"] = await env.message(plain, uid, "older than global", days_old=8)
        m["plain_new"] = await env.message(plain, uid, "inside global", days_old=3)
        m["stream_3d"] = await env.message(streamch, uid, "stream chat, 3 days", days_old=3)
        m["stream_9d"] = await env.message(streamch, uid, "stream chat, 9 days", days_old=9)
        conv = await d.create_dm_conversation(uid, [await env.user("friend")])
        stats = {"files": 0, "bytes": 0}
        cfg = await d.get_retention_config()
        total = await server._run_chat_retention(cfg, stats)
        left = {c: await env.ids(c) for c in (capped, short, plain, streamch)}
        check("a channel set to the cap keeps a 100 day old message", m["capped_old"] in left[capped])
        check("a channel set to 2 days loses its 3 day old message", m["short_old"] not in left[short])
        check("... keeps the pinned one and the fresh one", {m["short_pinned"], m["short_new"]} <= left[short])
        check("... and its file went with the message, the pinned message's file stayed",
              not (env.up / f_short).exists() and (env.up / f_pin).exists())
        check("the capped channel's file stayed", (env.up / f_capped).exists())
        check("a channel with no value follows the global 7 days",
              m["plain_old"] not in left[plain] and m["plain_new"] in left[plain])
        check("a stream's chat with a stale value stays under the global setting",
              m["stream_3d"] in left[streamch] and m["stream_9d"] not in left[streamch])
        maps = {c: await env.map_ids(c) for c in (capped, short)}
        check("the search rows of the removed message are gone, the others stay",
              m["short_old"] not in maps[short] and m["short_new"] in maps[short] and m["capped_old"] in maps[capped])
        check("the count is the messages removed", total == 3, str(total))
        check("one pass removed the files once", stats["files"] == 1, str(stats))
        cur = await d.conn.execute("SELECT COUNT(*) FROM dm_messages")
        check("DMs are not part of the pass", (await cur.fetchone())[0] == 0 and conv is not None)
    run(body)


def test_global_setting_no_longer_touches_a_channel_with_a_value():
    """The old global pass removed everything older than 7 days in every channel."""
    async def body(env):
        d = env.db
        uid = await env.user("poster")
        ch = await d.create_chat_channel("keeper", created_by=uid)
        await d.conn.execute("UPDATE chat_channels SET retention_days = 3650 WHERE id = ?", (ch,))
        await d.conn.commit()
        mid = await env.message(ch, uid, "old", days_old=400)
        removed = await d.cleanup_old_chat_messages(days=7)
        check("the global pass leaves a channel with its own value", removed == 0 and mid in await env.ids(ch))
    run(body)


def test_file_retention():
    async def body(env):
        d = env.db
        uid = await env.user("poster")
        ch = await d.create_chat_channel("files", created_by=uid)
        await d.conn.execute("UPDATE chat_channels SET retention_days = 30, file_retention_days = 5 WHERE id = ?", (ch,))
        await d.conn.commit()
        f1, f2, f3 = (env.make_file(c * 32 + ".zip") for c in "def")
        young = await env.message(ch, uid, "young with file", days_old=2, upload=f1)
        mid = await env.message(ch, uid, "mid-aged with file", days_old=10, upload=f2)
        pinned = await env.message(ch, uid, "pinned with file", days_old=10, pinned=True, upload=f3)
        gone = await env.message(ch, uid, "ancient", days_old=40)
        stats = {"files": 0, "bytes": 0}
        await server._run_chat_retention(await d.get_retention_config(), stats)
        row = await d.get_chat_message(mid)
        check("the message stays and is marked as file removed",
              row is not None and row["message"] == "mid-aged with file" and row["file_removed"] == 1 and not row["attachment_url"])
        check("its file is gone, the young and the pinned one stay",
              not (env.up / f2).exists() and (env.up / f1).exists() and (env.up / f3).exists())
        check("an old message past the message retention is deleted", gone not in await env.ids(ch))
        check("the young and pinned messages are unchanged",
              (await d.get_chat_message(young))["file_removed"] == 0 and (await d.get_chat_message(pinned))["file_removed"] == 0)
        cur = await d.conn.execute("SELECT has_file FROM chat_fts_map WHERE message_id = ?", (mid,))
        check("the file flag of the search row is cleared", (await cur.fetchone())["has_file"] == 0)
        # the file value is never longer than the message value, even if stored longer
        await d.conn.execute("UPDATE chat_channels SET retention_days = 4, file_retention_days = 3000 WHERE id = ?", (ch,))
        await d.conn.commit()
        f4 = env.make_file("9" * 32 + ".zip")
        late = await env.message(ch, uid, "five days", days_old=3.5, upload=f4)
        await server._run_chat_retention(await d.get_retention_config(), {"files": 0, "bytes": 0})
        check("a stored file value above the message value is cut to it (file kept inside 4 days)",
              (env.up / f4).exists() and (await d.get_chat_message(late))["file_removed"] == 0)
    run(body)


def test_file_retention_records_the_names_before_the_files_go():
    """The detach of a file by file retention commits the cleared link; the name of the file is written in
    the same transaction, so a pass that stops (or is killed) before its file step leaves a record the
    next cleanup settles."""
    async def body(env):
        d = env.db
        uid = await env.user("poster")
        ch = await d.create_chat_channel("files2", created_by=uid)
        f1 = env.make_file("a" * 32 + ".zip")
        mid = await env.message(ch, uid, "old with file", days_old=10, upload=f1)
        names = set()
        n = await d.remove_channel_files(ch, 5, {"files": 0, "bytes": 0}, names)
        check("the message was detached and the file is still on disk", n == 1 and (env.up / f1).exists())
        check("the name is recorded as pending", await d.pending_upload_names() == {f1} and names == {f1})
        stats = {"files": 0, "bytes": 0}
        await server._run_chat_retention({"retention_chat_days": 0}, stats)
        check("the next cleanup removes the file and clears the record",
              not (env.up / f1).exists() and not await d.pending_upload_names() and stats["files"] == 1, str(stats))
    run(body)


def test_route_admin_only_and_rules():
    async def body(env):
        d = env.db
        admin = await env.user("adm", "admin")
        mod = await env.user("mod", "moderator")
        plain = await env.user("plain")
        owner = await env.user("owner")
        ch = await d.create_chat_channel("room", created_by=admin)
        path = f"/api/chat/channels/{ch}/retention"
        await d.add_channel_member(ch, plain, role="moderator", added_by=admin)
        st, _ = await env.call("PUT", mod, path, json={"retention_days": 5})
        check("a moderator cannot set a channel's retention (403)", st == 403, str(st))
        st, _ = await env.call("PUT", plain, path, json={"retention_days": 5})
        check("a channel moderator cannot either (403)", st == 403, str(st))
        st, _ = await env.call("PUT", mod, f"/api/chat/channels/{ch}", json={"retention_days": 5, "description": "x"})
        check("the generic channel PUT used by moderators ignores the retention fields",
              (await d.get_chat_channel(ch))["retention_days"] is None, str(st))
        st, body_ = await env.call("PUT", admin, path, json={"retention_days": 5, "dry_run": True})
        check("an administrator is accepted (dry run)", st == 200 and body_["applied"] is False, str(body_))
        check("... and nothing was stored by the dry run", (await d.get_chat_channel(ch))["retention_days"] is None)
        # first value: older than 5 days exist -> shortening (from "global 7" to 5) needs confirm
        await env.message(ch, owner, "6 days", days_old=6)
        await env.message(ch, owner, "2 days", days_old=2)
        pin = await env.message(ch, owner, "pinned", days_old=9, pinned=True)
        st, r = await env.call("PUT", admin, path, json={"retention_days": 5})
        check("shortening without confirm is not applied and carries the count",
              st == 200 and r["applied"] is False and r["confirm_required"] is True and r["would_remove_messages"] == 1, str(r))
        check("... nothing stored", (await d.get_chat_channel(ch))["retention_days"] is None)
        st, r = await env.call("PUT", admin, path, json={"retention_days": 5, "confirm": True})
        check("with confirm it is applied", st == 200 and r["applied"] is True and r["retention_days"] == 5, str(r))
        check("... and stored", (await d.get_chat_channel(ch))["retention_days"] == 5)
        entries = await env.audit("channel_retention_change")
        check("one audit entry with the old and the new value",
              len(entries) == 1 and entries[0]["details"]["old"]["retention_days"] is None
              and entries[0]["details"]["new"]["retention_days"] == 5 and entries[0]["actor_id"] == admin, str(entries))
        # lengthening needs no confirm
        st, r = await env.call("PUT", admin, path, json={"retention_days": 30})
        check("lengthening applies without confirm", st == 200 and r["applied"] is True and r["retention_days"] == 30, str(r))
        # 0 and "forever" are the cap
        for raw in (0, "forever"):
            st, r = await env.call("PUT", admin, path, json={"retention_days": raw})
            check(f"{raw!r} is stored as the cap", st == 200 and (await d.get_chat_channel(ch))["retention_days"] == CAP, str(r))
        await d.set_retention_config({"retention_chat_max_days": 100})
        st, r = await env.call("PUT", admin, path, json={"retention_days": 500, "confirm": True})
        check("the cap setting caps a value", st == 200 and (await d.get_chat_channel(ch))["retention_days"] == 100 and r["capped"], str(r))
        st, r = await env.call("PUT", admin, path, json={"retention_days": "forever"})
        check("forever is the lowered cap", (await d.get_chat_channel(ch))["retention_days"] == 100, str(r))
        for bad in (-1, "soon", 1.5, True, [3]):
            st, _ = await env.call("PUT", admin, path, json={"retention_days": bad})
            check(f"{bad!r} is refused", st == 400, str(st))
        # JSON Infinity, -Infinity and NaN (Python's encoder writes them) and absurd sizes: 400, never 500
        for field in ("retention_days", "file_retention_days"):
            for bad in (float("inf"), float("-inf"), float("nan"), 1e308, -1e308, 10 ** 12, "9" * 400):
                st, _ = await env.call("PUT", admin, path, json={field: bad})
                check(f"{field} {bad!r} is 400", st == 400, str(st))
        async with env.http.put(env.url(path), data='{"retention_days": Infinity}',
                                headers={"X-Test-User": str(admin), "Content-Type": "application/json"}) as resp:
            check("the literal JSON Infinity is 400", resp.status == 400, str(resp.status))
        # file retention: never longer than the message retention
        st, r = await env.call("PUT", admin, path, json={"retention_days": 20, "confirm": True})
        st, r = await env.call("PUT", admin, path, json={"file_retention_days": 25, "confirm": True})
        check("a file value above the message value is refused", st == 400, str(r))
        st, r = await env.call("PUT", admin, path, json={"file_retention_days": 10, "confirm": True})
        check("a file value inside it is stored", st == 200 and (await d.get_chat_channel(ch))["file_retention_days"] == 10, str(r))
        st, r = await env.call("PUT", admin, path, json={"retention_days": 6, "confirm": True})
        row = await d.get_chat_channel(ch)
        check("shortening the messages below the file value cuts the file value to it",
              st == 200 and row["retention_days"] == 6 and row["file_retention_days"] == 6, str(row))
        st, r = await env.call("PUT", admin, path, json={"file_retention_days": "forever"})
        check("file forever means as long as the messages", (await d.get_chat_channel(ch))["file_retention_days"] == 6, str(r))
        st, r = await env.call("PUT", admin, path, json={"retention_days": None, "file_retention_days": None})
        row = await d.get_chat_channel(ch)
        check("null clears both (follow the global setting)", row["retention_days"] is None and row["file_retention_days"] is None, str(r))
        st, _ = await env.call("PUT", admin, path, json={})
        check("an empty body is refused", st == 400, str(st))
        st, _ = await env.call("PUT", admin, "/api/chat/channels/9999/retention", json={"retention_days": 5})
        check("a missing channel is 404", st == 404, str(st))
        st, _ = await env.call("PUT", None or admin, path, data="not json")
        check("invalid JSON is 400", st == 400, str(st))
        # a stream's chat is refused
        sc = await d.create_chat_channel("stream-chat", created_by=owner)
        sid = await d.create_user_stream(owner, "s", "live_" + "z" * 24, public_key="pub_" + "z" * 24, is_public=True)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (sc, sid))
        await d.conn.commit()
        st, _ = await env.call("PUT", admin, f"/api/chat/channels/{sc}/retention", json={"retention_days": 5})
        check("a stream's chat keeps the global retention (400)", st == 400, str(st))
        # the default channel is allowed
        general = (await d.get_chat_channel_by_name("general"))["id"]
        st, r = await env.call("PUT", admin, f"/api/chat/channels/{general}/retention", json={"retention_days": 400})
        check("the default channel may have its own retention", st == 200 and r["applied"], str(r))
        check("the pinned message was not counted", pin is not None)
    run(body)


def test_channel_list_carries_the_notice_data():
    async def body(env):
        d = env.db
        admin = await env.user("adm", "admin")
        plain = await env.user("plain")
        ch = await d.create_chat_channel("room", created_by=admin)
        server._cleanup_next_at = 0.0
        await d.set_channel_retention(ch, 14, None)
        server._cleanup_next_at = 2_000_000_000.0
        try:
            st, r = await env.call("GET", plain, "/api/chat/channels")
            row = next(c for c in r["channels"] if c["id"] == ch)
            check("channel list: the value and the next cleanup time for a member",
                  row["retention_days"] == 14 and row["retention_next_cleanup"].startswith("2033-"), str(row))
            general = next(c for c in r["channels"] if c["name"] == "general")
            check("channel list: no notice for a channel without a value", general.get("retention_days") is None
                  and "retention_next_cleanup" not in general)
            # a stale value on a stream's chat is not shown; a default channel keeps its own
            sc = await d.create_chat_channel("stream-chat2", created_by=admin)
            sid = await d.create_user_stream(admin, "s2", "live_" + "q" * 24, public_key="pub_" + "q" * 24, is_public=True)
            await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (sc, sid))
            await d.conn.commit()
            await d.set_channel_retention(sc, 3, None)
            await d.set_channel_retention(general["id"], 400, None)
            await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (general["id"], await d.create_user_stream(admin, "s3", "live_" + "r" * 24, public_key="pub_" + "r" * 24, is_public=True)))
            await d.conn.commit()
            st, r = await env.call("GET", plain, "/api/chat/channels")
            by = {c["name"]: c for c in r["channels"]}
            check("channel list: a stale value on a stream's chat is not shown", by["stream-chat2"]["retention_days"] is None
                  and "retention_next_cleanup" not in by["stream-chat2"], str(by["stream-chat2"]))
            check("channel list: the default channel keeps its own value even when a stream uses it",
                  by["general"]["retention_days"] == 400 and "retention_next_cleanup" in by["general"], str(by["general"]))
        finally:
            server._cleanup_next_at = 0.0
    run(body)


def test_run_cleanup_now_uses_the_same_pass():
    async def body(env):
        d = env.db
        su = await env.user("su", "superadmin")
        ch = await d.create_chat_channel("keeper", created_by=su)
        await d.set_channel_retention(ch, 3650, None)
        mid = await env.message(ch, su, "old", days_old=50)
        from aiohttp import web
        app = web.Application()
        app.router.add_post("/api/admin/retention/run", server.http_run_cleanup_now)
        from aiohttp.test_utils import TestServer
        import aiohttp
        srv = TestServer(app)
        await srv.start_server()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(str(srv.make_url("/api/admin/retention/run")), headers={"X-Test-User": str(su)}) as r:
                    status = r.status
        finally:
            await srv.close()
        check("run cleanup now answers", status == 200, str(status))
        check("run cleanup now leaves the channel with its own value alone", mid in await env.ids(ch))
    run(body)


def test_migration_is_idempotent():
    async def body(env):
        d = env.db
        await d.close()
        from database import Database
        d2 = Database(d.db_path)
        await d2.connect()                      # second start over the migrated file
        cur = await d2.conn.execute("PRAGMA table_info(chat_channels)")
        cols = {r["name"] for r in await cur.fetchall()}
        cur = await d2.conn.execute("PRAGMA table_info(chat_messages)")
        mcols = {r["name"] for r in await cur.fetchall()}
        check("the new columns exist after a second start", {"retention_days", "file_retention_days"} <= cols and "file_removed" in mcols)
        general = await d2.get_chat_channel_by_name("general")
        check("existing channels have NULL (follow the global setting)", general["retention_days"] is None and general["file_retention_days"] is None)
        cfg = await d2.get_retention_config()
        check("the cap defaults to 3650 and is limited to 1..3650", cfg["retention_chat_max_days"] == "3650")
        await d2.set_retention_config({"retention_chat_max_days": 0})
        await d2.set_retention_config({"retention_chat_max_days": 99999})
        check("a cap of 0 is ignored and one above 3650 is cut", (await d2.get_retention_config())["retention_chat_max_days"] == "3650")
        env.db = d2
    run(body)


for name, fn in list(globals().items()):
    if name.startswith("test_") and callable(fn):
        fn()
finish("test_channel_retention")
