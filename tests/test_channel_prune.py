"""Manual prune of a channel: POST /api/chat/channels/{id}/prune.

Real handlers and the real chat websocket against a temporary database and upload folder.

* a dry run shows the count; the real run needs that count echoed back (409 when the live count is
  further off than the margin), answers 202 and runs as a background task
* pruning one user's messages from the last hour removes them (rows, search rows, files), a second
  connected viewer receives messages_pruned frames with ids only, and exactly one audit entry is written
* pinned messages survive unless skip_pinned is false
* who may: an administrator; the moderators of that chat (chat_mod_level: global staff, a stream's owner
  or stream mod); a stream mod of another chat, an ordinary member and a member who may not read the
  channel all get the 404 of a missing channel
* an anonymous poster: a user filter from anybody but an administrator never matches that poster's
  anonymous messages (the count would reveal them), an administrator's does; the frames and the
  audit entry carry no poster for a prune without a user filter; without one an anonymous post is
  rankless for everybody but an administrator (the count is the same whoever wrote it), and an
  administrator's range prune leaves them all alone when it has authors to exclude (the frames and
  status counts must not show which survived)
* one prune per channel at a time; the range is required with both ends

Run: venv/bin/python tests/test_channel_prune.py
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from retention_harness import (check, finish, run, server)  # noqa: E402


def iso(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


async def world(env):
    d = env.db
    w = type("W", (), {})()
    w.admin = await env.user("adm", "admin")
    w.gmod = await env.user("gmod", "moderator")
    w.owner = await env.user("owner")
    w.smod = await env.user("smod")             # stream mod of the owner's chat
    w.other_owner = await env.user("otherowner")
    w.other_mod = await env.user("othermod")    # stream mod of ANOTHER stream's chat
    w.talker = await env.user("talker")
    w.viewer = await env.user("viewer")
    w.chat = await d.create_chat_channel("chat-a", created_by=w.owner)
    sid = await d.create_user_stream(w.owner, "s-a", "live_" + "a" * 24, public_key="pub_" + "a" * 24, is_public=True)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (w.chat, sid))
    w.chat_b = await d.create_chat_channel("chat-b", created_by=w.other_owner)
    sid = await d.create_user_stream(w.other_owner, "s-b", "live_" + "b" * 24, public_key="pub_" + "b" * 24, is_public=True)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (w.chat_b, sid))
    await d.conn.commit()
    await d.add_channel_member(w.chat, w.smod, role="moderator", added_by=w.owner)
    await d.add_channel_member(w.chat_b, w.other_mod, role="moderator", added_by=w.other_owner)
    w.private = await d.create_chat_channel("private-room", created_by=w.admin)
    await d.update_chat_channel(w.private, visibility="private")
    await d.add_channel_member(w.private, w.talker, role="member", added_by=w.admin)
    w.general = (await d.get_chat_channel_by_name("general"))["id"]
    return w


def body_for(**kw):
    base = {"from": iso(3), "to": iso(0)}
    base.update(kw)
    return base


def test_prune_flow_and_frames():
    async def body(env):
        d = env.db
        w = await world(env)
        f1 = env.make_file("a" * 32 + ".zip")
        mine = [await env.message(w.chat, w.talker, f"spam {i}", hours_old=0.2 + i * 0.1,
                                  upload=f1 if i == 0 else None) for i in range(5)]
        pinned = await env.message(w.chat, w.talker, "pinned spam", hours_old=0.5, pinned=True)
        other = await env.message(w.chat, w.viewer, "somebody else", hours_old=0.3)
        old = await env.message(w.chat, w.talker, "yesterday", hours_old=30)
        sock = await env.sock(w.viewer)
        await sock.join(w.chat)
        path = f"/api/chat/channels/{w.chat}/prune"
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", dry_run=True))
        check("dry run: the count of the user's messages in range, pinned left out (5)", st == 200 and r["count"] == 5, str(r))
        check("dry run removed nothing", len(await env.ids(w.chat)) == 8)
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker"))
        check("a real run without expected_count is refused", st == 400, str(r))
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", expected_count=40))
        check("a count far from the live one is 409", st == 409 and r["count"] == 5, str(r))
        start = len(sock.events)
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", expected_count=5))
        check("the real run answers 202", st == 202 and r["started"] and r["count"] == 5, str(r))
        await env.wait_prune(w.chat)
        left = await env.ids(w.chat)
        check("the user's five messages in the range are gone", not (set(mine) & left), str(left))
        check("pinned, other users' and older messages stay", {pinned, other, old} <= left)
        check("the search rows went too", not (set(mine) & await env.map_ids(w.chat)))
        check("the file of a removed message went with it", not (env.up / f1).exists())
        frames = [e for e in sock.events[start:] if e.get("type") == "messages_pruned"]
        got = {i for f in frames for i in f["ids"]}
        check("a connected viewer got messages_pruned with exactly the removed ids", got == set(mine), str(frames))
        check("frames carry the channel and ids only",
              all(set(f) == {"type", "channel", "ids"} for f in frames), str(frames))
        entries = await env.audit("chat_prune")
        check("exactly one audit entry", len(entries) == 1, str(entries))
        det = entries[0]["details"]
        check("... with who, channel, range, user filter and count",
              entries[0]["actor_id"] == w.owner and entries[0]["channel_id"] == w.chat and det["count"] == 5
              and det["user"] == "talker" and det["from"] and det["to"] and det["status"] == "completed", str(entries))
        st, r = await env.call("GET", w.owner, path)
        check("the status route says it is done", st == 200 and r["running"] is False and r["removed"] == 5, str(r))
        # pinned included on request
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", skip_pinned=False, dry_run=True))
        check("with skip_pinned false the pinned message is counted", st == 200 and r["count"] == 1, str(r))
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", skip_pinned=False, expected_count=1))
        await env.wait_prune(w.chat)
        check("... and removed", pinned not in await env.ids(w.chat))
        check("a second prune is a second audit entry", len(await env.audit("chat_prune")) == 2)
    run(body)


def test_batches_and_margin():
    async def body(env):
        w = await world(env)
        server.PRUNE_BATCH = 3
        try:
            ids = [await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1) for i in range(10)]
            sock = await env.sock(w.viewer)
            await sock.join(w.chat)
            path = f"/api/chat/channels/{w.chat}/prune"
            st, r = await env.call("POST", w.admin, path, json=body_for(expected_count=9))   # 10 live, margin 2
            check("a count inside the margin (9 against 10) is accepted", st == 202, str(r))
            await env.wait_prune(w.chat)
            frames = [e for e in sock.events if e.get("type") == "messages_pruned"]
            check("one frame per batch of 3 (4 frames: 3, 3, 3, 1)", [len(f["ids"]) for f in frames] == [3, 3, 3, 1], str([len(f["ids"]) for f in frames]))
            check("everything in range is gone", not (set(ids) & await env.ids(w.chat)))
            entries = await env.audit("chat_prune")
            check("still ONE audit entry for the batches", len(entries) == 1 and entries[0]["details"]["count"] == 10)
            await env.message(w.chat, w.talker, "again", hours_old=0.1)
            st, r = await env.call("POST", w.admin, path, json=body_for(expected_count=4))
            check("a count off by more than the margin (4 against 1 is 3 > 2) is 409", st == 409, str(r))
        finally:
            server.PRUNE_BATCH = 200
    run(body)


def test_who_may_prune():
    async def body(env):
        w = await world(env)
        await env.message(w.chat, w.talker, "x", hours_old=0.1)
        await env.message(w.chat_b, w.talker, "y", hours_old=0.1)
        await env.message(w.private, w.talker, "z", hours_old=0.1)
        await env.message(w.general, w.talker, "g", hours_old=0.1)
        probe = body_for(dry_run=True)
        table = [
            ("admin, stream chat", w.admin, w.chat, 200), ("global moderator, stream chat", w.gmod, w.chat, 200),
            ("stream owner, own chat", w.owner, w.chat, 200), ("stream mod, own chat", w.smod, w.chat, 200),
            ("admin, private channel", w.admin, w.private, 200),
            ("moderator of ANOTHER chat", w.other_mod, w.chat, 404),
            ("owner of another stream", w.other_owner, w.chat, 404),
            ("ordinary member", w.viewer, w.chat, 404), ("ordinary member, general", w.viewer, w.general, 404),
            ("stream mod of chat a on chat b", w.smod, w.chat_b, 404),
            ("global moderator, private channel they are not in", w.gmod, w.private, 404),
            ("ordinary channel member, private channel", w.talker, w.private, 404),
            ("global moderator, general", w.gmod, w.general, 200),
            ("admin, a missing channel", w.admin, 99999, 404),
        ]
        for label, who, chan, want in table:
            st, r = await env.call("POST", who, f"/api/chat/channels/{chan}/prune", json=probe)
            check(f"{label}: {want}", st == want, f"{st} {r}")
        st, r = await env.call("POST", w.viewer, f"/api/chat/channels/{w.private}/prune", json=probe)
        st2, r2 = await env.call("POST", w.viewer, "/api/chat/channels/99999/prune", json=probe)
        check("an unreadable channel answers exactly like a missing one", (st, r) == (st2, r2), f"{r} {r2}")
        st, r = await env.call("GET", w.other_mod, f"/api/chat/channels/{w.chat}/prune")
        check("the status route has the same gate", st == 404, str(st))
        st, r = await env.call("POST", None, f"/api/chat/channels/{w.chat}/prune", json=probe)
        check("no credential is refused", st == 401, str(st))
        check("nothing was written by the refused calls", not await env.audit("chat_prune"))
    run(body)


def test_range_and_input():
    async def body(env):
        w = await world(env)
        path = f"/api/chat/channels/{w.chat}/prune"
        for label, payload in (
                ("no range", {"dry_run": True}), ("only from", {"from": iso(3), "dry_run": True}),
                ("only to", {"to": iso(0), "dry_run": True}),
                ("garbage date", {"from": "yesterday", "to": iso(0), "dry_run": True}),
                ("reversed range", {"from": iso(0), "to": iso(3), "dry_run": True}),
                ("skip_pinned not a boolean", body_for(skip_pinned="no", dry_run=True)),
                ("user is a list", body_for(user=[1], dry_run=True))):
            st, r = await env.call("POST", w.admin, path, json=payload)
            check(f"{label} is 400", st == 400, str(r))
        st, r = await env.call("POST", w.admin, path, data="nope")
        check("invalid JSON is 400", st == 400)
        await env.message(w.chat, w.talker, "inside", hours_old=1)
        await env.message(w.chat, w.talker, "outside", hours_old=5)
        st, r = await env.call("POST", w.admin, path, json={"from": iso(2), "to": iso(0), "dry_run": True})
        check("the range is respected (1 of 2)", st == 200 and r["count"] == 1, str(r))
        naive = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(tzinfo=None).isoformat()
        st, r = await env.call("POST", w.admin, path, json={"from": naive, "to": iso(0), "dry_run": True})
        check("a date without offset is UTC", st == 200 and r["count"] == 1, str(r))
        st, r = await env.call("POST", w.admin, path, json=body_for(user="nobody-by-that-name", dry_run=True))
        check("an unknown user matches nothing (no account lookup oracle)", st == 200 and r["count"] == 0, str(r))
        st, r = await env.call("POST", w.admin, path, json=body_for(user=w.talker, dry_run=True))
        check("a user can be given by account id", st == 200 and r["count"] == 1, str(r))
    run(body)


def test_anonymous_posters():
    async def body(env):
        w = await world(env)
        anon = await env.message(w.chat, w.talker, "hidden hello", hours_old=0.2, anonymous=True)
        named = await env.message(w.chat, w.talker, "named hello", hours_old=0.2)
        path = f"/api/chat/channels/{w.chat}/prune"
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", dry_run=True))
        check("a stream owner's user filter does not match the anonymous message (count 1)", r["count"] == 1, str(r))
        st, r = await env.call("POST", w.gmod, path, json=body_for(user="talker", dry_run=True))
        check("a global moderator's user filter does not match it either", r["count"] == 1, str(r))
        st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", dry_run=True))
        check("an administrator's user filter matches both (count 2)", r["count"] == 2, str(r))
        st, r = await env.call("POST", w.owner, path, json=body_for(dry_run=True))
        check("a prune of the whole range counts the anonymous message too", r["count"] == 2, str(r))
        sock = await env.sock(w.viewer)
        await sock.join(w.chat)
        st, r = await env.call("POST", w.owner, path, json=body_for(expected_count=2))
        await env.wait_prune(w.chat)
        entries = await env.audit("chat_prune")
        det = entries[0]["details"]
        blob = json.dumps(entries) + json.dumps([e for e in sock.events if e.get("type") == "messages_pruned"])
        check("the audit entry of a range prune has no user and the frames no poster",
              det["user"] is None and det["user_id"] is None and "talker" not in blob and str(w.talker) not in
              json.dumps([e for e in sock.events if e.get("type") == "messages_pruned"]), blob)
        check("both messages were removed", not ({anon, named} & await env.ids(w.chat)))
        # an administrator naming the poster: recorded for staff, flagged
        a2 = await env.message(w.chat, w.talker, "again anonymous", hours_old=0.2, anonymous=True)
        st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", expected_count=1))
        await env.wait_prune(w.chat)
        entries = await env.audit("chat_prune")
        check("an administrator's prune by user removes the anonymous message", a2 not in await env.ids(w.chat) and len(entries) == 2)
        check("... and the entry says anonymous messages were included",
              any(e["details"].get("anonymous_included") for e in entries))
    run(body)


async def rank_world(env):
    """The stream chat with one recent message from everybody who ranks differently, plus the owner's go-live card."""
    w = await world(env)
    w.adm2 = await env.user("adm2", "admin")
    msgs = {}
    for name, uid in (("owner", w.owner), ("smod", w.smod), ("gmod", w.gmod), ("adm", w.admin),
                      ("adm2", w.adm2), ("talker", w.talker)):
        msgs[name] = await env.message(w.chat, uid, f"from {name}", hours_old=0.2)
    msgs["card"] = await env.message(w.chat, w.owner, "go-live card", hours_old=0.2)
    await env.db.conn.execute("UPDATE chat_messages SET message_type = 'stream_card' WHERE id = ?", (msgs["card"],))
    await env.db.conn.commit()
    w.msgs = msgs
    return w


async def pruned_by(env, w, actor, **kw):
    """Names whose message is gone after `actor` pruned the whole range (with kw)."""
    path = f"/api/chat/channels/{w.chat}/prune"
    st, r = await env.call("POST", actor, path, json=body_for(dry_run=True, **kw))
    assert st == 200, (st, r)
    st, r = await env.call("POST", actor, path, json=body_for(expected_count=r["count"], **kw))
    assert st == 202, (st, r)
    await env.wait_prune(w.chat)
    left = await env.ids(w.chat)
    return {n for n, i in w.msgs.items() if i not in left}


def test_rank_rules_user_filter():
    """A prune of one user's messages obeys the rules of a single delete (_chat_may_act_on)."""
    async def body(env):
        w = await rank_world(env)
        path = f"/api/chat/channels/{w.chat}/prune"
        for label, actor, target, want in (
                ("a stream mod on the stream's owner", w.smod, w.owner, 0),
                ("a stream mod on a global moderator", w.smod, w.gmod, 0),
                ("a stream mod on an administrator", w.smod, w.admin, 0),
                ("the stream owner on an administrator", w.owner, w.admin, 0),
                ("a global moderator on an administrator", w.gmod, w.admin, 0),
                ("an administrator on another administrator", w.admin, w.adm2, 0),
                ("a stream mod on an ordinary member", w.smod, w.talker, 1),
                ("the stream owner on a stream mod", w.owner, w.smod, 1),
                ("a global moderator on a stream mod", w.gmod, w.smod, 1),
                ("an administrator on a global moderator", w.admin, w.gmod, 1),
                ("a stream mod on themselves", w.smod, w.smod, 1)):
            st, r = await env.call("POST", actor, path, json=body_for(user=target, dry_run=True))
            check(f"dry run, {label}: count {want}", st == 200 and r["count"] == want, str(r))
        gone = await pruned_by(env, w, w.smod, user=w.owner)
        check("a stream mod's real run on the owner removes nothing", not gone, str(gone))
        gone = await pruned_by(env, w, w.smod, user=w.admin)
        check("... nor on an administrator", not gone, str(gone))
        gone = await pruned_by(env, w, w.gmod, user=w.admin)
        check("a global moderator's real run on an administrator removes nothing", not gone, str(gone))
    run(body)


def test_rank_rules_range():
    """A prune of the whole range leaves alone what the caller could not delete one by one."""
    async def body(env):
        w = await rank_world(env)
        gone = await pruned_by(env, w, w.smod)
        check("a stream mod's range prune takes ordinary members' and its own posts only, not the owner's go-live card",
              gone == {"smod", "talker"}, str(gone))
    run(body)

    async def body_owner(env):
        w = await rank_world(env)
        gone = await pruned_by(env, w, w.owner)
        check("the stream owner's range prune keeps all staff and takes the rest, the go-live card too",
              gone == {"owner", "card", "smod", "talker"}, str(gone))
    run(body_owner)

    async def body_gmod(env):
        w = await rank_world(env)
        gone = await pruned_by(env, w, w.gmod)
        check("a global moderator's range prune keeps administrators",
              gone == {"owner", "card", "smod", "gmod", "talker"}, str(gone))
    run(body_gmod)

    async def body_admin(env):
        w = await rank_world(env)
        gone = await pruned_by(env, w, w.admin)
        check("an administrator's range prune keeps the other administrator and takes the rest",
              gone == {"owner", "card", "smod", "gmod", "adm", "talker"}, str(gone))
    run(body_admin)


def test_authorless_clause():
    """A post with no author (the delete path allows it to the owner and staff only): the clause."""
    import sqlite3
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE chat_messages (id INTEGER, channel_id INT, user_id INT, created_at TEXT, is_pinned INT, anonymous INT)")
    for i, uid in ((1, None), (2, 7), (3, 8)):
        c.execute("INSERT INTO chat_messages VALUES (?, 1, ?, '2026-01-01T00:00:00+00:00', 0, 0)", (i, uid))
    from database import Database
    db = Database.__new__(Database)

    def ids(**kw):
        where, params = db.prune_where(1, "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00", **kw)
        return {r[0] for r in c.execute(f"SELECT id FROM chat_messages WHERE {where}", params)}
    check("no exclusion: everything", ids() == {1, 2, 3})
    check("an excluded author goes, the authorless post stays for the owner and staff", ids(exclude_users=[7]) == {1, 3})
    check("a stream mod's prune leaves the authorless post too", ids(exclude_users=[7], allow_authorless=False) == {3})
    check("(the clause never fires on the real schema: user_id is NOT NULL)", True)


def test_shutdown_finishes_a_running_prune():
    """A graceful shutdown (PortalServer.stop, the real one) cancels and awaits the running prunes while
    the database is still open: the single entry says interrupted with the count actually removed, the
    upload files of the committed batches are recorded as pending (and the next start removes them), and
    nothing is logged as a failure."""
    import logging
    from database import Database

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    async def body(env):
        w = await world(env)
        server.PRUNE_BATCH = 2
        server.PRUNE_SHUTDOWN_WAIT = 0.5
        cap = Capture()
        server.logger.addHandler(cap)
        try:
            f1 = env.make_file("b" * 32 + ".zip")
            await env.message(w.chat, w.talker, "m0", hours_old=0.1, upload=f1)
            for i in range(1, 6):
                await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1)
            real = env.db._purge_messages
            seen = asyncio.Event()

            async def slow_purge(*a, on_batch=None, **kw):
                async def hold(ids, *x):
                    await on_batch(ids, *x)
                    seen.set()
                    await asyncio.sleep(30)          # still running when the shutdown comes
                return await real(*a, on_batch=hold, **kw)
            env.db._purge_messages = slow_purge
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(expected_count=6))
            check("the prune starts", st == 202, str(r))
            await asyncio.wait_for(seen.wait(), 5)
            await asyncio.wait_for(server.PortalServer().stop(), 30)     # the real stop(), the database closes in it
            check("no prune task is left", not [t for t in server._prune_tasks.values() if not t.done()])
            bad = [m for m in cap.lines if "closed database" in m or "no active connection" in m
                   or "failed" in m.lower() or "Traceback" in m]
            check("nothing was logged as a failure", not bad, str(bad))
            check("the stop did not start the file check of a prune it had stopped: the file is left",
                  (env.up / f1).exists())
            fresh = Database(str(Path(env.tmp.name) / "t.db"))
            await fresh.connect()
            try:
                rows = await fresh.get_audit_log(limit=50, action="chat_prune")
                det = []
                for r in rows:
                    d = r["details"]
                    while isinstance(d, str):      # stored as a JSON string, possibly encoded twice
                        d = json.loads(d)
                    det.append(d)
                check("one entry, interrupted, with the 2 messages actually removed",
                      len(det) == 1 and det[0]["status"] == "interrupted" and det[0]["count"] == 2, str(det))
                cur = await fresh.conn.execute("SELECT COUNT(*) FROM chat_messages WHERE channel_id = ?", (w.chat,))
                check("4 messages are left", (await cur.fetchone())[0] == 4)
                check("the file of the removed batch is recorded as pending for the next start",
                      f1 in await fresh.pending_upload_names())
            finally:
                await fresh.close()
        finally:
            server.PRUNE_BATCH = 200
            server.PRUNE_SHUTDOWN_WAIT = 20.0
            server.logger.removeHandler(cap)
            env.db._purge_messages = real
    run(body)


def test_shutdown_with_a_slow_file_step_orphans_no_file():
    """The bound of the shutdown cancels a prune whose upload-file step is still checking (that step
    can take minutes on a big channel). The prune's deleted rows named their files in chat_upload_pending
    in the same transaction, so a fresh database (the next start) still knows them and the cleanup
    removes the file; the start-up pass of the cleanup task does the same. Before, the cancel was
    swallowed and the file stayed with no record."""
    from database import Database

    async def body(env):
        w = await world(env)
        server.PRUNE_SHUTDOWN_WAIT = 0.5
        try:
            f1 = env.make_file("c" * 32 + ".zip")
            await env.message(w.chat, w.talker, "with file", hours_old=0.1, upload=f1)
            await env.message(w.chat, w.talker, "plain", hours_old=0.1)
            real = env.db.finish_purge_files
            entered = asyncio.Event()

            async def slow_finish(names, stats):
                entered.set()
                await asyncio.sleep(30)               # the reference check of a big channel
                await real(names, stats)
            env.db.finish_purge_files = slow_finish
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(expected_count=2))
            check("the prune starts", st == 202, str(r))
            await asyncio.wait_for(entered.wait(), 5)
            await asyncio.wait_for(server.PortalServer().stop(), 30)      # the real stop(): the bound cancels the file step
            env.db.finish_purge_files = real
            fresh = Database(str(Path(env.tmp.name) / "t.db"))
            await fresh.connect()
            fresh.chat_upload_dir = str(env.up)
            saved = server.db
            server.db = fresh
            try:
                check("the file is still on disk and recorded as pending", (env.up / f1).exists()
                      and await fresh.pending_upload_names() == {f1}, str(await fresh.pending_upload_names()))
                stats = {"files": 0, "bytes": 0}
                await server._run_chat_retention({"retention_chat_days": 0}, stats)
                check("the next cleanup removes it and clears the record",
                      not (env.up / f1).exists() and not await fresh.pending_upload_names() and stats["files"] == 1,
                      f"{stats} {await fresh.pending_upload_names()}")
                # the start-up pass of the cleanup task
                f2 = env.make_file("d" * 32 + ".zip")
                await fresh.conn.execute("INSERT INTO chat_upload_pending (name) VALUES (?)", (f2,))
                await fresh.conn.commit()
                task = asyncio.create_task(server.PortalServer()._data_cleanup_task())
                for _ in range(100):
                    if not (env.up / f2).exists():
                        break
                    await asyncio.sleep(0.05)
                task.cancel()
                check("the cleanup task removes a pending file when it starts, not after its first interval",
                      not (env.up / f2).exists() and not await fresh.pending_upload_names())
            finally:
                server.db = saved
                await fresh.close()
        finally:
            server.PRUNE_SHUTDOWN_WAIT = 20.0
    run(body)


def test_shutdown_asks_the_prunes_to_stop_before_the_server_drains():
    """stop() sets the stop flag of a running prune first, not only after the open connections have
    drained (that wait comes before runner.cleanup and used to add to the prune's own wind-down)."""
    async def body(env):
        w = await world(env)
        server.PRUNE_BATCH = 2
        server.PRUNE_SHUTDOWN_WAIT = 0.5
        try:
            for i in range(6):
                await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1)
            real = env.db._purge_messages
            seen = asyncio.Event()

            async def slow_purge(*a, on_batch=None, **kw):
                async def hold(ids, *x):
                    await on_batch(ids, *x)
                    seen.set()
                    await asyncio.sleep(30)
                return await real(*a, on_batch=hold, **kw)
            env.db._purge_messages = slow_purge
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(expected_count=6))
            await asyncio.wait_for(seen.wait(), 5)
            flags = []
            real_stop_rec = server.stop_all_recordings

            async def spy():                      # runs in stop() long before runner.cleanup()
                flags.append(bool(server._prune_status[w.chat].get("_stop")))
                await real_stop_rec()
            server.stop_all_recordings = spy
            try:
                await asyncio.wait_for(server.PortalServer().stop(), 30)
            finally:
                server.stop_all_recordings = real_stop_rec
                env.db._purge_messages = real
            check("the flag was already set when the early steps of stop() ran", flags == [True], str(flags))
        finally:
            server.PRUNE_BATCH = 200
            server.PRUNE_SHUTDOWN_WAIT = 20.0
    run(body)


def test_shutdown_stops_a_prune_between_batches_whenever_it_comes():
    """The shutdown comes at every database step of a running prune (each SELECT, DELETE and commit of
    each batch, the callback's lookups, the audit entry): the one entry counts exactly the rows that
    are gone, the upload file of every deleted row is gone or recorded as pending (and gone once the next
    start settled it) and of every surviving row stays, and every surviving message keeps its search
    row. (A cancel inside a batch left an uncommitted half batch.)"""
    total, batch = 8, 2

    def sweep_step(k):
        async def body(env):
            w = await world(env)
            server.PRUNE_BATCH = batch
            files = []
            for i in range(total):
                files.append(env.make_file(f"{i:032x}.zip"))
                await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1, upload=files[-1])
            for i in range(total, total + 2):       # pinned: the prune leaves them
                files.append(env.make_file(f"{i:032x}.zip"))
                await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1, upload=files[-1], pinned=True)
            conn = env.db.conn
            real_exec, real_commit = conn.execute, conn.commit
            st = {"n": 0, "armed": False, "stop": None}

            def tick():
                if st["armed"] and w.chat in server._prune_tasks:     # only the prune's own steps count
                    st["n"] += 1
                    if st["n"] == k:
                        st["armed"] = False
                        st["stop"] = asyncio.ensure_future(server._cancel_prune_tasks())

            def execute(*a, **kw):
                tick()
                return real_exec(*a, **kw)

            def commit(*a, **kw):
                tick()
                return real_commit(*a, **kw)
            conn.execute, conn.commit = execute, commit
            try:
                st["armed"] = True
                code, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune",
                                         json=body_for(expected_count=total))
                check(f"[step {k}] the prune starts", code == 202, str(r))
                task = server._prune_tasks.get(w.chat)
                if task is not None:
                    await asyncio.wait(
                        [task], timeout=30)
                if st["stop"] is not None:
                    await asyncio.wait_for(st["stop"], 30)
            finally:
                conn.execute, conn.commit = real_exec, real_commit
            left = await env.ids(w.chat)
            gone = total + 2 - len(left)
            entries = await env.audit("chat_prune")
            check(f"[step {k}] one entry", len(entries) == 1, str(entries))
            d = entries[0]["details"]
            check(f"[step {k}] the entry counts the rows that are gone ({gone})", d["count"] == gone, str(d))
            check(f"[step {k}] a prune that stopped early says interrupted",
                  d["status"] in ("completed", "interrupted") and (gone == total or d["status"] == "interrupted"), str(d))
            cur = await env.db.conn.execute("SELECT attachment_url FROM chat_messages WHERE channel_id = ?", (w.chat,))
            kept = {r["attachment_url"].rsplit("/", 1)[1] for r in await cur.fetchall()}
            pending = await env.db.pending_upload_names()
            orphans = [f for f in files if f not in kept and (env.up / f).exists() and f not in pending]
            lost = [f for f in kept if not (env.up / f).exists()]
            check(f"[step {k}] every upload file of a deleted row is gone or recorded as pending", not orphans, str(orphans))
            await env.db.finish_purge_files(set(pending), {"files": 0, "bytes": 0})      # what the next start does
            left_over = [f for f in files if f not in kept and (env.up / f).exists()]
            check(f"[step {k}] none is left after the next start settled the pending ones",
                  not left_over and not await env.db.pending_upload_names(), str(left_over))
            check(f"[step {k}] no upload file of a surviving row is removed", not lost, str(lost))
            check(f"[step {k}] every surviving message keeps its search row", left <= await env.map_ids(w.chat))
        try:
            run(body)
        finally:
            server.PRUNE_BATCH = 200

    for k in range(1, 41):
        sweep_step(k)


def test_anonymous_rank_not_revealed_by_a_range_prune():
    """An anonymous post is rankless in a prune for everybody but an administrator: the count of a
    narrow range around one is the same whoever wrote it (owner, stream mod, ordinary member, staff),
    so a dry run cannot tell the rank of the author; the real run removes them all and the frames
    carry them like any other id."""
    async def body(env):
        w = await world(env)
        w.adm2 = await env.user("adm2", "admin")
        posts = {}
        for i, (name, uid) in enumerate((("owner", w.owner), ("member", w.talker), ("admin", w.admin),
                                         ("smod", w.smod), ("adm2", w.adm2))):
            posts[name] = await env.message(w.chat, uid, f"anon {name}", hours_old=0.5 - i * 0.05, anonymous=True)
        named = await env.message(w.chat, w.talker, "named", hours_old=0.2)
        cur = await env.db.conn.execute("SELECT id, created_at FROM chat_messages WHERE channel_id = ?", (w.chat,))
        when = {r["id"]: datetime.fromisoformat(r["created_at"]) for r in await cur.fetchall()}
        path = f"/api/chat/channels/{w.chat}/prune"

        async def around(actor, mid):
            ts = when[mid]
            st, r = await env.call("POST", actor, path, json={
                "from": (ts - timedelta(milliseconds=100)).isoformat(),
                "to": (ts + timedelta(milliseconds=100)).isoformat(), "dry_run": True})
            return r["count"] if st == 200 else st
        for label, actor in (("a stream mod", w.smod), ("the stream owner", w.owner), ("a global moderator", w.gmod)):
            counts = {name: await around(actor, mid) for name, mid in posts.items()}
            check(f"{label}: the count around an anonymous post is the same whoever wrote it (1)",
                  set(counts.values()) == {1}, str(counts))
        # an administrator's prune without a user filter leaves every anonymous post alone (other
        # administrators exist), so its count around one is the same whoever wrote it too
        counts = {name: await around(w.admin, mid) for name, mid in posts.items()}
        check("an administrator's count around an anonymous post is the same whoever wrote it (0)",
              set(counts.values()) == {0}, str(counts))
        # the real run of a stream mod over the whole range: every anonymous post goes, whoever wrote it
        sock = await env.sock(w.viewer)
        await sock.join(w.chat)
        everything = set(posts.values()) | {named}
        st, r = await env.call("POST", w.smod, path, json=body_for(dry_run=True))
        check("a stream mod's whole-range count holds every anonymous post and the named one (6)",
              r["count"] == 6, str(r))
        st, r = await env.call("POST", w.smod, path, json=body_for(expected_count=6))
        await env.wait_prune(w.chat)
        check("after it none of them is left", not (everything & await env.ids(w.chat)), str(await env.ids(w.chat)))
        await sock.wait(lambda e: e.get("type") == "messages_pruned" and everything <= set(e["ids"]))
        seen = {i for e in sock.events if e.get("type") == "messages_pruned" for i in e["ids"]}
        check("an ordinary member's frames carry all of the ids", everything <= seen, str(seen))
        det = (await env.audit("chat_prune"))[0]["details"]
        check("the audit entry counts them all and names nobody",
              det["count"] == 6 and det["user"] is None and det["user_id"] is None, str(det))
    run(body)


def test_administrator_prune_does_not_show_the_rank_of_anonymous_authors():
    """An administrator's or superadmin's prune of a range with no user filter: whoever wrote the
    anonymous posts (owner, stream mod, ordinary member, global moderator, administrators, both
    superadmins), an ordinary viewer's frames, the stream owner's and a stream mod's status and what
    is left are the same: every anonymous post stays and the frames carry the named ones only, so
    nothing shows that one of them was written by a higher-ranked author. A user filter still reaches
    the anonymous posts of that one user (rank rules applying), and with nobody to exclude (the only
    superadmin) the anonymous posts go with the rest."""
    async def populate(env, w, authors):
        posts = {}
        for i, (name, uid) in enumerate(authors):
            posts[name] = await env.message(w.chat, uid, f"anon {name}", hours_old=0.5 - i * 0.02, anonymous=True)
        w.named = await env.message(w.chat, w.talker, "named", hours_old=0.1)
        return posts

    async def body(env, actor_name):
        w = await world(env)
        w.adm2 = await env.user("adm2", "admin")
        w.sup1 = await env.user("sup1", "superadmin")
        w.sup2 = await env.user("sup2", "superadmin")
        everybody = (("owner", w.owner), ("smod", w.smod), ("member", w.talker), ("gmod", w.gmod),
                     ("admin", w.admin), ("adm2", w.adm2), ("sup1", w.sup1), ("sup2", w.sup2))
        posts = await populate(env, w, everybody)
        actor = {"admin": w.admin, "sup1": w.sup1}[actor_name]
        path = f"/api/chat/channels/{w.chat}/prune"
        sock = await env.sock(w.viewer)
        await sock.join(w.chat)
        st, r = await env.call("POST", actor, path, json=body_for(dry_run=True))
        check(f"{actor_name}: the dry run counts the named post only", st == 200 and r["count"] == 1, str(r))
        st, r = await env.call("POST", actor, path, json=body_for(expected_count=1))
        check(f"{actor_name}: the prune starts", st == 202, f"{st} {r}")
        await env.wait_prune(w.chat)
        await sock.wait(lambda e: e.get("type") == "messages_pruned")
        left = await env.ids(w.chat)
        check(f"{actor_name}: every anonymous post is left, whoever wrote it (all or none)",
              set(posts.values()) <= left and w.named not in left, str(left))
        seen = {i for e in sock.events if e.get("type") == "messages_pruned" for i in e["ids"]}
        check(f"{actor_name}: an ordinary viewer's frames carry the named post and no anonymous one",
              seen == {w.named}, str(seen))
        for who, label in ((w.owner, "the stream owner"), (w.smod, "a stream mod"), (w.viewer, "an ordinary member")):
            st, r = await env.call("GET", who, path)
            if st == 200:
                check(f"{actor_name}: {label}'s status counts the named post only",
                      r.get("removed") == 1 and r.get("total") == 1, str(r))
        # the same range prune by the owner (rankless for anonymous posts) does not depend on the author
        st, r = await env.call("POST", w.owner, path, json=body_for(dry_run=True))
        check(f"{actor_name}: the owner's own dry run counts every anonymous post of the others (8)",
              st == 200 and r["count"] == 8, str(r))

    async def run_as(actor_name):
        async def go(env):
            await body(env, actor_name)
        run(go)
    for who in ("admin", "sup1"):
        asyncio.run(run_as(who)) if False else None

    async def body_admin(env):
        await body(env, "admin")
    run(body_admin)

    async def body_super(env):
        await body(env, "sup1")
    run(body_super)

    async def body_sole(env):
        w = await world(env)
        w.sup1 = await env.user("sup1", "superadmin")
        posts = await populate(env, w, (("owner", w.owner), ("member", w.talker), ("admin", w.admin),
                                        ("sup1", w.sup1)))
        path = f"/api/chat/channels/{w.chat}/prune"
        st, r = await env.call("POST", w.sup1, path, json=body_for(dry_run=True))
        check("the only superadmin's range prune has nobody to exclude: anonymous posts are counted (5)",
              r["count"] == 5, str(r))
        st, r = await env.call("POST", w.sup1, path, json=body_for(expected_count=5))
        await env.wait_prune(w.chat)
        check("... and go with the rest", not (set(posts.values()) & await env.ids(w.chat)))
    run(body_sole)

    async def body_filter(env):
        w = await world(env)
        w.adm2 = await env.user("adm2", "admin")
        mine = await env.message(w.chat, w.talker, "anon member", hours_old=0.3, anonymous=True)
        theirs = await env.message(w.chat, w.adm2, "anon adm2", hours_old=0.3, anonymous=True)
        path = f"/api/chat/channels/{w.chat}/prune"
        st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", dry_run=True))
        check("an administrator's user filter matches that user's anonymous post (1)", r["count"] == 1, str(r))
        st, r = await env.call("POST", w.admin, path, json=body_for(user="adm2", dry_run=True))
        check("... but the rank rules still keep another administrator's (0)", r["count"] == 0, str(r))
        st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", expected_count=1))
        await env.wait_prune(w.chat)
        left = await env.ids(w.chat)
        check("only the filtered user's anonymous post went", mine not in left and theirs in left, str(left))
    run(body_filter)


def test_anonymous_ids_stay_off_ordinary_frames():
    """An administrator's prune by user that includes the user's anonymous post: an ordinary member never
    gets the anonymous id (they would see it vanish with the named posts), staff and the author do."""
    async def body(env):
        w = await world(env)
        server.PRUNE_BATCH = 1
        try:
            named = await env.message(w.chat, w.talker, "named", hours_old=0.3)
            anon = await env.message(w.chat, w.talker, "hidden", hours_old=0.2, anonymous=True)
            named2 = await env.message(w.chat, w.talker, "named again", hours_old=0.1)
            socks = {}
            for who in ("viewer", "gmod", "talker", "owner"):
                socks[who] = await env.sock(getattr(w, who))
                await socks[who].join(w.chat)
            path = f"/api/chat/channels/{w.chat}/prune"
            st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", dry_run=True))
            check("the dry run counts all three", r["count"] == 3, str(r))
            st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", expected_count=3))
            await env.wait_prune(w.chat)
            await asyncio.sleep(0.3)

            def got(who):
                return [i for e in socks[who].events if e.get("type") == "messages_pruned" for i in e["ids"]]
            check("all three messages are gone", not ({named, anon, named2} & await env.ids(w.chat)))
            check("an ordinary viewer never receives the anonymous id", anon not in got("viewer"), str(got("viewer")))
            check("... but does receive the named ones", sorted(got("viewer")) == sorted([named, named2]), str(got("viewer")))
            check("the stream owner (not staff) does not get it either", anon not in got("owner"), str(got("owner")))
            check("a global moderator gets every id", sorted(got("gmod")) == sorted([named, anon, named2]), str(got("gmod")))
            check("the author gets every id", sorted(got("talker")) == sorted([named, anon, named2]), str(got("talker")))
        finally:
            server.PRUNE_BATCH = 200
    run(body)


def test_status_counts_do_not_reveal_anonymous_posts():
    """The status route after an administrator's user-filtered prune that included anonymous posts: the
    counts include them, so only staff and the one who started it get counts; a stream owner and a
    stream mod get running and status only (3 posts removed, the frames showed 2). A prune that cannot
    match anonymous posts still shows its counts to everybody who passes the gate."""
    async def body(env):
        w = await world(env)
        await env.message(w.chat, w.talker, "named", hours_old=0.3)
        await env.message(w.chat, w.talker, "hidden", hours_old=0.2, anonymous=True)
        await env.message(w.chat, w.talker, "hidden too", hours_old=0.15, anonymous=True)
        path = f"/api/chat/channels/{w.chat}/prune"
        st, r = await env.call("POST", w.admin, path, json=body_for(user="talker", expected_count=3))
        check("the administrator's prune starts", st == 202, f"{st} {r}")
        await env.wait_prune(w.chat)
        for who, label in ((w.owner, "the stream owner"), (w.smod, "a stream mod")):
            st, r = await env.call("GET", who, path)
            check(f"{label} gets running and status only", st == 200 and r == {"running": False, "status": "completed"}, str(r))
        for who, label in ((w.admin, "the administrator who ran it"), (w.gmod, "a global moderator")):
            st, r = await env.call("GET", who, path)
            check(f"{label} gets the counts", st == 200 and r.get("removed") == 3 and r.get("total") == 3
                  and "files" in r, str(r))
        check("no internal field leaks", not [k for k in r if k.startswith("_")], str(r))
        # a prune that is not matchable for anonymous posts shows its counts to the owner as before
        await env.message(w.chat, w.talker, "plain", hours_old=0.1)
        st, r = await env.call("POST", w.owner, path, json=body_for(user="talker", expected_count=1))
        await env.wait_prune(w.chat)
        st, r = await env.call("GET", w.smod, path)
        check("an owner's own prune shows counts to a stream mod", r.get("removed") == 1 and r.get("total") == 1, str(r))
    run(body)


def test_one_prune_per_channel():
    async def body(env):
        w = await world(env)
        for i in range(4):
            await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1)
        gate = asyncio.Event()
        real = env.db.prune_chat_messages

        async def slow(*a, **kw):
            await gate.wait()
            return await real(*a, **kw)
        env.db.prune_chat_messages = slow
        try:
            path = f"/api/chat/channels/{w.chat}/prune"
            st, r = await env.call("POST", w.admin, path, json=body_for(expected_count=4))
            check("the first prune starts", st == 202, str(r))
            st, r = await env.call("POST", w.admin, path, json=body_for(expected_count=4))
            check("a second one on the same channel is 409 while it runs", st == 409, str(r))
            st, r = await env.call("GET", w.admin, path)
            check("the status route says running", r["running"] is True, str(r))
            other = await env.message(w.general, w.talker, "elsewhere", hours_old=0.1)
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.general}/prune", json=body_for(expected_count=1))
            check("another channel is not blocked", st == 202, str(r))
        finally:
            gate.set()
            await env.wait_prune(w.chat)
            await env.wait_prune(w.general)
            env.db.prune_chat_messages = real
        check("after it finished a new prune is accepted again",
              (await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(dry_run=True)))[0] == 200)
        check("the entries: one per prune", len(await env.audit("chat_prune")) == 2)
    run(body)


def test_audit_once_even_when_it_fails():
    async def body(env):
        w = await world(env)
        await env.message(w.chat, w.talker, "m", hours_old=0.1)
        real = env.db.prune_chat_messages

        async def boom(*a, **kw):
            raise RuntimeError("disk gone")
        env.db.prune_chat_messages = boom
        try:
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(expected_count=1))
            await env.wait_prune(w.chat)
        finally:
            env.db.prune_chat_messages = real
        entries = await env.audit("chat_prune")
        check("a failing prune still writes its one entry, marked failed",
              len(entries) == 1 and entries[0]["details"]["status"] == "failed", str(entries))
    run(body)


def test_audit_once_when_cancelled():
    """A prune that is cancelled (shutdown) after some batches still writes its one entry, 'interrupted'."""
    async def body(env):
        w = await world(env)
        server.PRUNE_BATCH = 2
        try:
            for i in range(6):
                await env.message(w.chat, w.talker, f"m{i}", hours_old=0.1)
            real = env.db._purge_messages
            seen = asyncio.Event()

            async def slow_purge(*a, on_batch=None, **kw):
                async def hold(ids):
                    await on_batch(ids)
                    seen.set()
                    await asyncio.sleep(30)          # cancelled here, after the first batch
                return await real(*a, on_batch=hold, **kw)
            env.db._purge_messages = slow_purge
            st, r = await env.call("POST", w.admin, f"/api/chat/channels/{w.chat}/prune", json=body_for(expected_count=6))
            check("the prune starts", st == 202, str(r))
            await asyncio.wait_for(seen.wait(), 5)
            task = server._prune_tasks[w.chat]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            env.db._purge_messages = real
            entries = await env.audit("chat_prune")
            check("a cancelled prune writes exactly one entry, marked interrupted, with the batch it did",
                  len(entries) == 1 and entries[0]["details"]["status"] == "interrupted"
                  and entries[0]["details"]["count"] == 2, str(entries))
            check("the state says it stopped", server._prune_status[w.chat]["running"] is False
                  and server._prune_status[w.chat]["status"] == "interrupted", str(server._prune_status[w.chat]))
            check("the channel is free for another prune", w.chat not in server._prune_tasks)
        finally:
            server.PRUNE_BATCH = 200
    run(body)


for name, fn in list(globals().items()):
    if name.startswith("test_") and callable(fn):
        fn()
finish("test_channel_prune")
