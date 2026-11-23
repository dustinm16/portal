"""Saved messages and remind-me-later: the routes, the live resolution, the reminder tick.

Runs the real HTTP handlers in-process against a temporary database (only the authentication lookup
is replaced). No outbound network (tests/outbound_guard.py).

* save and unsave; the marks list; a message that does not exist and one the caller may not read
  answer with the same 404; a stream key or a scoped key is refused; caps on entries and reminders
* the list is resolved live: a member removed from a private channel, a DM left, a deleted message
  and a stream chat made private all give an entry with exactly the keys of "no longer available";
  access coming back makes it readable again; an anonymous post stays anonymous
* no copy of the text of a deleted message is left in any table
* reminder times: absolute UTC only, future only, within the horizon, null clears
* the tick: one indexed query, fires once, the notification has the fixed title, no text and ids only,
  falls back to the Saved view when the message is unreadable, caps a burst, never repeats (also on a
  second database connection to the same file = a restart), and a changed reminder is not fired
* the push carries the fixed text and no message text, author or channel name
* no clean-up removes a row because its message is gone (that would tell a member who lost access which message was deleted)
* the rows go with the user; the migration is idempotent

Run: venv/bin/python tests/test_saved.py
"""

import asyncio
import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import test_chat_access_loss as base  # noqa: E402
import server  # noqa: E402
from database import Database, SAVED_REMINDER_TITLE, decrypt_message  # noqa: E402

SECRET = "needle-9f3c1e-text"
UNAVAILABLE_KEYS = {"id", "saved_at", "remind_at", "reminded", "available"}
NOW = 1_800_000_000


class Env(base.Env):
    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", self.auth),
                            ("_credential_still_valid", base.fake_valid),
                            ("_saved_clock", lambda: self.now[0])):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        self.now = [NOW]
        server._history_hits.clear()
        app = web.Application()
        for method, path, handler in (
                ("GET", "/api/saved", server.http_get_saved),
                ("POST", "/api/saved", server.http_post_saved),
                ("GET", "/api/saved/marks", server.http_get_saved_marks),
                ("DELETE", "/api/saved/unavailable", server.http_delete_saved_unavailable),
                ("DELETE", "/api/saved/{id}", server.http_delete_saved),
                ("PUT", "/api/saved/{id}/remind", server.http_put_saved_remind)):
            app.router.add_route(method, path, handler)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    @staticmethod
    async def auth(request):
        uid = request.headers.get("X-Test-User")
        if not uid:
            return None
        tok = base.Tok(int(uid))
        if request.headers.get("X-Test-Kind"):
            tok.token_id = request.headers["X-Test-Kind"] + "-1"
        if request.headers.get("X-Test-Scopes"):
            tok.scopes = request.headers["X-Test-Scopes"].split(",")
        return tok

    async def call(self, method, user_id, path, headers=None, **kw):
        h = {"X-Test-User": str(user_id), **(headers or {})}
        async with self.http.request(method, self.url(path), headers=h, **kw) as r:
            return r.status, await r.json()


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


async def general(d):
    return next(c["id"] for c in await d.get_chat_channels() if c["name"] == "general")


async def save(env, uid, kind, mid):
    st, b = await env.call("POST", uid, "/api/saved", json={"kind": kind, "message_id": mid})
    assert st in (200, 201), (st, b)
    return b["saved"]["id"]


async def listing(env, uid, **q):
    st, b = await env.call("GET", uid, "/api/saved", params=q)
    assert st == 200, (st, b)
    return b


def iso(epoch):
    return server._saved_iso(epoch)


# ---------------------------------------------------------------------------

def test_save_list_marks_and_unsave():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m1 = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " one")
        m2 = await d.create_chat_message(gen, ids["bob"], "bob", "second")
        s1 = await save(env, ids["carol"], "channel", m1)
        s2 = await save(env, ids["carol"], "channel", m2)
        again = await env.call("POST", ids["carol"], "/api/saved", json={"kind": "channel", "message_id": m1})
        assert again[0] == 200 and again[1]["saved"]["id"] == s1           # saving twice is one entry
        b = await listing(env, ids["carol"])
        assert [i["id"] for i in b["items"]] == [s2, s1]                    # newest first
        first = b["items"][1]
        assert first["available"] and first["message"]["text"] == SECRET + " one"
        assert first["channel_id"] == gen and first["message_id"] == m1 and first["kind"] == "channel"
        assert b["limits"]["max_saved"] == 500
        st, marks = await env.call("GET", ids["carol"], "/api/saved/marks")
        assert {(m["kind"], m["message_id"], m["id"]) for m in marks["marks"]} == {
            ("channel", m1, s1), ("channel", m2, s2)}
        # nothing of carol's is visible to anyone else
        for other in ("bob", "boss", "viewer"):
            assert (await listing(env, ids[other]))["items"] == []
            st, marks = await env.call("GET", ids[other], "/api/saved/marks")
            assert marks["marks"] == []
            st, _ = await env.call("DELETE", ids[other], f"/api/saved/{s1}")
            assert st == 404
            st, _ = await env.call("PUT", ids[other], f"/api/saved/{s1}/remind",
                                   json={"remind_at": iso(NOW + 3600)})
            assert st == 404
        # paging
        p1 = await listing(env, ids["carol"], limit=1)
        assert len(p1["items"]) == 1 and p1["has_more"] and p1["next_before_id"] == s2
        p2 = await listing(env, ids["carol"], limit=1, before_id=p1["next_before_id"])
        assert [i["id"] for i in p2["items"]] == [s1] and not p2["has_more"]
        assert (await env.call("GET", ids["carol"], "/api/saved", params={"limit": "x"}))[0] == 400
        st, _ = await env.call("DELETE", ids["carol"], f"/api/saved/{s1}")
        assert st == 200
        assert [i["id"] for i in (await listing(env, ids["carol"]))["items"]] == [s2]
        assert (await env.call("DELETE", ids["carol"], f"/api/saved/{s1}"))[0] == 404
        assert (await env.call("DELETE", ids["carol"], "/api/saved/abc"))[0] == 404
    run(body)


def test_missing_and_unreadable_messages_answer_alike_and_bad_input_is_refused():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        pvt = await base.private_channel(d, ids)                 # alice and bob are members
        hidden = await d.create_chat_message(pvt, ids["alice"], "alice", "private words")
        dm = await d.create_dm_conversation(ids["alice"], [ids["bob"]])
        dm_msg = await d.create_dm_message(dm["id"], ids["alice"], "alice", "dm words")
        sid_gone = 999_999
        answers = []
        for uid, kind, mid in ((ids["carol"], "channel", hidden), (ids["carol"], "channel", sid_gone),
                               (ids["carol"], "dm", dm_msg), (ids["carol"], "dm", sid_gone),
                               (ids["carol"], "dm", hidden)):          # a channel message id as a DM
            answers.append(await env.call("POST", uid, "/api/saved", json={"kind": kind, "message_id": mid}))
        assert all(a == answers[0] for a in answers), answers
        assert answers[0][0] == 404
        for bad in ({}, {"kind": "x", "message_id": 1}, {"kind": "channel", "message_id": "1"},
                    {"kind": "channel", "message_id": True}, {"kind": "channel", "message_id": 0},
                    {"kind": "channel", "message_id": 2 ** 70}, []):
            st, _ = await env.call("POST", ids["carol"], "/api/saved", json=bad)
            assert st == 400, bad
        assert (await listing(env, ids["carol"]))["items"] == []
        # members of the places can save
        await save(env, ids["bob"], "channel", hidden)
        await save(env, ids["bob"], "dm", dm_msg)
        # a stream key and an API key are refused; so is no credential at all
        for kind in ("streamkey", "apikey"):
            st, _ = await env.call("GET", ids["bob"], "/api/saved", headers={"X-Test-Kind": kind})
            assert st == 403, kind
        async with env.http.get(env.url("/api/saved")) as r:
            assert r.status == 401
    run(body)


def test_a_narrowly_scoped_token_that_is_no_api_key_or_stream_key_is_refused_on_every_route():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "x")
        sid = await save(env, ids["bob"], "channel", m)
        narrow = {"X-Test-Scopes": "services:read"}          # token id "t<uid>": neither "apikey-" nor "streamkey-"
        when = {"remind_at": iso(NOW + 3600)}
        for method, path, kw in (("GET", "/api/saved", {}), ("GET", "/api/saved/marks", {}),
                                 ("POST", "/api/saved", {"json": {"kind": "channel", "message_id": m}}),
                                 ("DELETE", f"/api/saved/{sid}", {}), ("DELETE", "/api/saved/unavailable", {}),
                                 ("PUT", f"/api/saved/{sid}/remind", {"json": when})):
            st, _ = await env.call(method, ids["bob"], path, headers=narrow, **kw)
            assert st == 403, (method, path, st)
        # the refusals changed nothing: the entry is there and has no reminder
        row = await d.get_saved_message(ids["bob"], sid)
        assert row and row["remind_at"] is None
        # the same member's full-scope token is served
        assert (await env.call("GET", ids["bob"], "/api/saved"))[0] == 200
        assert (await env.call("GET", ids["bob"], "/api/saved/marks"))[0] == 200
    run(body)


def test_the_marks_route_counts_toward_the_history_budget_like_the_list():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "x")
        await save(env, ids["carol"], "channel", m)
        limit = server.HISTORY_RATE_LIMIT
        for i in range(limit):
            st, _ = await env.call("GET", ids["carol"], "/api/saved/marks")
            assert st == 200, (i, st)
        async with env.http.get(env.url("/api/saved/marks"), headers={"X-Test-User": str(ids["carol"])}) as r:
            assert r.status == 429 and int(r.headers["Retry-After"]) >= 1
            body_ = await r.json()
            assert "Too many" in body_["error"]                              # the shared limiter's answer
        # the list shares the same budget and another member has their own
        assert (await env.call("GET", ids["carol"], "/api/saved"))[0] == 429
        assert (await env.call("GET", ids["bob"], "/api/saved/marks"))[0] == 200
        # a mix of both routes spends one budget
        server._history_hits.clear()
        for i in range(limit // 2):
            assert (await env.call("GET", ids["carol"], "/api/saved/marks"))[0] == 200
            assert (await env.call("GET", ids["carol"], "/api/saved"))[0] == 200
        assert (await env.call("GET", ids["carol"], "/api/saved/marks"))[0] == 429
    run(body)


def test_caps_on_entries_and_pending_reminders():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        msgs = [await d.create_chat_message(gen, ids["bob"], "bob", f"m{i}") for i in range(4)]
        old = (server.SAVED_MAX_ENTRIES, server.SAVED_MAX_PENDING)
        server.SAVED_MAX_ENTRIES, server.SAVED_MAX_PENDING = 3, 2
        try:
            rows = [await save(env, ids["carol"], "channel", m) for m in msgs[:3]]
            st, b = await env.call("POST", ids["carol"], "/api/saved", json={"kind": "channel", "message_id": msgs[3]})
            assert st == 409 and "3" in b["error"]
            # saving what is already saved is not refused at the cap
            assert (await env.call("POST", ids["carol"], "/api/saved",
                                   json={"kind": "channel", "message_id": msgs[0]}))[0] == 200
            when = {"remind_at": iso(NOW + 3600)}
            assert (await env.call("PUT", ids["carol"], f"/api/saved/{rows[0]}/remind", json=when))[0] == 200
            assert (await env.call("PUT", ids["carol"], f"/api/saved/{rows[1]}/remind", json=when))[0] == 200
            st, b = await env.call("PUT", ids["carol"], f"/api/saved/{rows[2]}/remind", json=when)
            assert st == 409
            # changing one that is already pending is not a new one
            assert (await env.call("PUT", ids["carol"], f"/api/saved/{rows[1]}/remind",
                                   json={"remind_at": iso(NOW + 7200)}))[0] == 200
            # clearing makes room
            assert (await env.call("PUT", ids["carol"], f"/api/saved/{rows[0]}/remind", json={"remind_at": None}))[0] == 200
            assert (await env.call("PUT", ids["carol"], f"/api/saved/{rows[2]}/remind", json=when))[0] == 200
        finally:
            server.SAVED_MAX_ENTRIES, server.SAVED_MAX_PENDING = old
    run(body)


def test_reminder_times_are_absolute_utc_future_and_within_the_horizon():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        sid = await save(env, ids["carol"], "channel", await d.create_chat_message(gen, ids["bob"], "bob", "x"))
        url = f"/api/saved/{sid}/remind"
        horizon = server.SAVED_HORIZON_DAYS * 86400
        for bad in ("2027-01-01T09:00:00", "2027-01-01T09:00:00+02:00", "tomorrow", 1800003600, True, "",
                    iso(NOW), iso(NOW - 60), iso(NOW + horizon + 1), "2027-13-40T99:00:00Z"):
            st, b = await env.call("PUT", ids["carol"], url, json={"remind_at": bad})
            assert st == 400, (bad, st, b)
        assert (await env.call("PUT", ids["carol"], url, json={}))[0] == 400
        st, b = await env.call("PUT", ids["carol"], url, json={"remind_at": iso(NOW + 1)})
        assert st == 200 and b["remind_at"] == iso(NOW + 1) and b["reminded"] is False
        st, b = await env.call("PUT", ids["carol"], url, json={"remind_at": iso(NOW + horizon)})
        assert st == 200
        st, b = await env.call("PUT", ids["carol"], url, json={"remind_at": None})
        assert st == 200 and b["remind_at"] is None
        assert (await env.call("PUT", ids["carol"], "/api/saved/99999/remind",
                               json={"remind_at": iso(NOW + 60)}))[0] == 404
        # the row holds epoch seconds, never a client string
        await env.call("PUT", ids["carol"], url, json={"remind_at": iso(NOW + 3600)[:-1] + ".5Z"})
        cur = await env.db.conn.execute("SELECT remind_at FROM saved_messages WHERE id = ?", (sid,))
        assert (await cur.fetchone())["remind_at"] == NOW + 3600
    run(body)


def test_a_reminder_cannot_be_set_for_a_message_that_is_no_longer_available_and_the_answer_does_not_say_why():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids)
        gone = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " gone")
        s_gone = await save(env, ids["carol"], "channel", gone)
        hidden = await d.create_chat_message(pvt, ids["alice"], "alice", SECRET + " hidden")
        s_hidden = await save(env, ids["bob"], "channel", hidden)
        s_ok = await save(env, ids["carol"], "channel", await d.create_chat_message(gen, ids["bob"], "bob", "fine"))
        # a reminder that is already waiting when the message goes away
        s_wait = await pending(env, ids["carol"], "channel", await d.create_chat_message(gen, ids["bob"], "bob", "w"), NOW + 600)
        await d.delete_chat_message(gone)                       # reason one: the message is gone
        await d.remove_channel_member(pvt, ids["bob"])          # reason two: the member lost access
        when = {"remind_at": iso(NOW + 3600)}
        a = await env.call("PUT", ids["carol"], f"/api/saved/{s_gone}/remind", json=when)
        b = await env.call("PUT", ids["bob"], f"/api/saved/{s_hidden}/remind", json=when)
        assert a[0] == 409 and a == b, (a, b)                    # the same status and the same body
        assert SECRET not in json.dumps(a) and "gone" not in json.dumps(a).replace("no longer", "")
        for sid, uid in ((s_gone, ids["carol"]), (s_hidden, ids["bob"])):
            assert (await d.get_saved_message(uid, sid))["remind_at"] is None     # nothing was set
        # a readable entry still takes a reminder; another member's entry is still a 404
        assert (await env.call("PUT", ids["carol"], f"/api/saved/{s_ok}/remind", json=when))[0] == 200
        assert (await env.call("PUT", ids["bob"], f"/api/saved/{s_ok}/remind", json=when))[0] == 404
        # a bad time is still a 400 first, and clearing a waiting reminder of a gone message still works
        assert (await env.call("PUT", ids["carol"], f"/api/saved/{s_gone}/remind", json={"remind_at": "soon"}))[0] == 400
        await d.delete_chat_message((await d.get_saved_message(ids["carol"], s_wait))["message_id"])
        st, body_ = await env.call("PUT", ids["carol"], f"/api/saved/{s_wait}/remind", json={"remind_at": None})
        assert st == 200 and body_["remind_at"] is None
    run(body)


def test_the_list_is_resolved_live_and_an_unavailable_entry_shows_nothing_else():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        pvt = await base.private_channel(d, ids)
        m = await d.create_chat_message(pvt, ids["alice"], "alice", SECRET + " pvt")
        sid = await save(env, ids["bob"], "channel", m)
        assert (await listing(env, ids["bob"]))["items"][0]["available"] is True
        await d.remove_channel_member(pvt, ids["bob"])
        item = (await listing(env, ids["bob"]))["items"][0]
        assert set(item) == UNAVAILABLE_KEYS and item["available"] is False and item["id"] == sid
        assert SECRET not in json.dumps(item) and "pvt" not in json.dumps(item)
        await d.add_channel_member(pvt, ids["bob"], role="member", added_by=ids["boss"])
        assert (await listing(env, ids["bob"]))["items"][0]["available"] is True     # access came back
        # an admin reads every channel
        sid_admin = await save(env, ids["boss"], "channel", m)
        assert (await listing(env, ids["boss"]))["items"][0]["available"] is True

        # a direct message: left or closed
        dm = await d.create_dm_conversation(ids["alice"], [ids["bob"], ids["carol"]], name="g", conv_type="group")
        dmm = await d.create_dm_message(dm["id"], ids["alice"], "alice", SECRET + " dm")
        sd = await save(env, ids["carol"], "dm", dmm)
        it = [i for i in (await listing(env, ids["carol"]))["items"] if i["id"] == sd][0]
        assert it["available"] and it["kind"] == "dm" and it["conversation_id"] == dm["id"]
        await d.leave_dm_conversation(dm["id"], ids["carol"])
        it = [i for i in (await listing(env, ids["carol"]))["items"] if i["id"] == sd][0]
        assert set(it) == UNAVAILABLE_KEYS

        # a deleted message
        gen = await general(d)
        gm = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " gen")
        sg = await save(env, ids["carol"], "channel", gm)
        await d.delete_chat_message(gm)
        it = [i for i in (await listing(env, ids["carol"]))["items"] if i["id"] == sg][0]
        assert set(it) == UNAVAILABLE_KEYS and it["saved_at"] == iso(NOW)

        # the chat of a stream that is made private
        cid, stream_id = await base.stream_chat(d, ids, public=True)
        sm = await d.create_chat_message(cid, ids["owner"], "owner", SECRET + " stream")
        ss = await save(env, ids["viewer"], "channel", sm)
        assert [i for i in (await listing(env, ids["viewer"]))["items"] if i["id"] == ss][0]["available"]
        await d.conn.execute("UPDATE user_streams SET is_public = 0 WHERE id = ?", (stream_id,))
        await d.conn.commit()
        it = [i for i in (await listing(env, ids["viewer"]))["items"] if i["id"] == ss][0]
        assert set(it) == UNAVAILABLE_KEYS
        # and a saved row can no longer be made for it
        assert (await env.call("POST", ids["viewer"], "/api/saved", json={"kind": "channel", "message_id": sm}))[0] == 404
        # a row that names another channel for the same message id never resolves to it
        await d.conn.execute("UPDATE saved_messages SET scope_id = ? WHERE id = ?", (pvt, sg))
        await d.conn.commit()
        assert set([i for i in (await listing(env, ids["carol"]))["items"] if i["id"] == sg][0]) == UNAVAILABLE_KEYS
        assert sid_admin
    run(body)


def test_an_anonymous_post_stays_anonymous_in_the_saved_view():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "anon words", anonymous=True)
        sid = await save(env, ids["carol"], "channel", m)
        item = (await listing(env, ids["carol"]))["items"][0]
        assert item["message"]["anonymous"] is True and item["message"]["username"] == "Anonymous"
        assert "bob" not in json.dumps(item) and "user_id" not in json.dumps(item)
        assert not ({"user_id", "role", "nickname"} & set(item["message"]))
        assert item["id"] == sid
    run(body)


def _all_text(db_path):
    import sqlite3
    con = sqlite3.connect(db_path)
    blob = []
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        try:
            for row in con.execute(f'SELECT * FROM "{name}"'):
                blob.extend(str(c) for c in row)
        except sqlite3.Error:
            pass
    con.close()
    return "\n".join(blob)


def test_no_copy_of_the_text_exists_after_the_message_is_deleted():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " text")
        sid = await save(env, ids["carol"], "channel", m)
        await env.call("PUT", ids["carol"], f"/api/saved/{sid}/remind", json={"remind_at": iso(NOW + 60)})
        env.now[0] = NOW + 120
        assert await server._saved_tick_once(env.now[0]) == 1          # the notification exists too
        await d.conn.commit()
        assert SECRET not in _all_text(str(Path(env.tmp.name) / "t.db")), "the text is in a table"
        await d.delete_chat_message(m)
        await d.conn.commit()
        assert SECRET not in _all_text(str(Path(env.tmp.name) / "t.db"))
        cur = await d.conn.execute("SELECT * FROM saved_messages WHERE id = ?", (sid,))
        row = dict(await cur.fetchone())
        assert set(row) == {"id", "user_id", "kind", "scope_id", "message_id", "saved_at", "remind_at", "fired_at"}
    run(body)


# ---------------------------------------------------------------------------
# the tick

async def pending(env, uid, kind, mid, at, saved_at=NOW):
    sid = await save(env, uid, kind, mid)
    st, b = await env.call("PUT", uid, f"/api/saved/{sid}/remind", json={"remind_at": iso(at)})
    assert st == 200, b
    return sid


async def notes(d, uid):
    cur = await d.conn.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id", (uid,))
    return [dict(r) for r in await cur.fetchall()]


def test_marks_leave_out_what_the_list_shows_as_no_longer_available():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        pvt = await base.private_channel(d, ids)
        gen = await general(d)
        hidden = await d.create_chat_message(pvt, ids["alice"], "alice", "p")
        shown = await d.create_chat_message(gen, ids["alice"], "alice", "g")
        s_hidden = await save(env, ids["bob"], "channel", hidden)
        s_shown = await save(env, ids["bob"], "channel", shown)
        st, marks = await env.call("GET", ids["bob"], "/api/saved/marks")
        assert {m["id"] for m in marks["marks"]} == {s_hidden, s_shown}
        await d.remove_channel_member(pvt, ids["bob"])
        st, marks = await env.call("GET", ids["bob"], "/api/saved/marks")
        assert [m["id"] for m in marks["marks"]] == [s_shown], marks
        assert str(hidden) not in json.dumps([{k: v for k, v in m.items() if k != "id"} for m in marks["marks"]]) or hidden == shown
        await d.delete_chat_message(shown)
        st, marks = await env.call("GET", ids["bob"], "/api/saved/marks")
        assert marks["marks"] == []
    run(body)


def test_an_entry_never_shows_a_message_created_after_it_was_saved():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        dm = await d.create_dm_conversation(ids["alice"], [ids["bob"]])
        m = await d.create_chat_message(gen, ids["alice"], "alice", "first")
        dmm = await d.create_dm_message(dm["id"], ids["alice"], "alice", "dm first")
        sc = await save(env, ids["bob"], "channel", m)
        sd = await save(env, ids["bob"], "dm", dmm)
        both = lambda: {i["id"]: i for i in []}
        # the same ids now name messages made later (a restored or hand-rebuilt database)
        later = "2099-01-01T00:00:00+00:00"
        await d.conn.execute("UPDATE chat_messages SET created_at = ? WHERE id = ?", (later, m))
        await d.conn.execute("UPDATE dm_messages SET created_at = ? WHERE id = ?", ("2099-01-01 00:00:00", dmm))
        await d.conn.commit()
        items = {i["id"]: i for i in (await listing(env, ids["bob"]))["items"]}
        assert set(items[sc]) == UNAVAILABLE_KEYS and set(items[sd]) == UNAVAILABLE_KEYS
        st, marks = await env.call("GET", ids["bob"], "/api/saved/marks")
        assert marks["marks"] == []
        # a message made before the save is the one saved, in either stored time format
        await d.conn.execute("UPDATE chat_messages SET created_at = ? WHERE id = ?", ("2026-01-01 10:00:00", m))
        await d.conn.execute("UPDATE dm_messages SET created_at = ? WHERE id = ?", ("2026-01-01T10:00:00+02:00", dmm))
        await d.conn.commit()
        items = {i["id"]: i for i in (await listing(env, ids["bob"]))["items"]}
        assert items[sc]["available"] and items[sd]["available"]
        assert server._saved_epoch("2026-01-01 10:00:00") == server._saved_epoch("2026-01-01T10:00:00+00:00")
        assert server._saved_epoch("nonsense") is None and server._saved_epoch(None) is None
        assert both
    run(body)


def test_a_message_aged_out_by_the_retention_is_no_longer_available_and_leaves_no_copy():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        old = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " old")
        new = await d.create_chat_message(gen, ids["bob"], "bob", "recent")
        s_old = await save(env, ids["carol"], "channel", old)
        s_new = await save(env, ids["carol"], "channel", new)
        await env.call("PUT", ids["carol"], f"/api/saved/{s_old}/remind", json={"remind_at": iso(NOW + 60)})
        await d.conn.execute("UPDATE chat_messages SET created_at = '2020-01-01T00:00:00+00:00' WHERE id = ?", (old,))
        await d.conn.commit()
        assert await d.cleanup_old_chat_messages(days=30) >= 1
        items = {i["id"]: i for i in (await listing(env, ids["carol"]))["items"]}
        assert set(items[s_old]) == UNAVAILABLE_KEYS and items[s_new]["available"]
        assert await server._saved_tick_once(NOW + 61) == 1            # its reminder still fires
        n = await notes(d, ids["carol"])
        assert len(n) == 1 and json.loads(n[0]["data"])["saved"] == 1
        await d.conn.commit()
        assert SECRET not in _all_text(str(Path(env.tmp.name) / "t.db"))
    run(body)


def test_the_tick_fires_once_with_a_fixed_text_and_ids_only():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " tick")
        sid = await pending(env, ids["carol"], "channel", m, NOW + 600)
        assert await server._saved_tick_once(NOW + 599) == 0             # not due yet
        assert await notes(d, ids["carol"]) == []
        assert await server._saved_tick_once(NOW + 600) == 1
        assert await server._saved_tick_once(NOW + 601) == 0             # never twice
        assert await server._saved_tick_once(NOW + 10_000) == 0
        n = await notes(d, ids["carol"])
        assert len(n) == 1 and n[0]["type"] == "reminder"
        assert decrypt_message(n[0]["title"]) == SAVED_REMINDER_TITLE == "Reminder for a saved message"
        assert not n[0]["message"]
        data = json.loads(n[0]["data"])
        assert data == {"channel_id": gen, "message_id": m, "saved_id": sid}     # jump-to-message ids only
        for other in ("bob", "boss"):
            assert await notes(d, ids[other]) == []
        it = (await listing(env, ids["carol"]))["items"][0]
        assert it["reminded"] is True and it["remind_at"] == iso(NOW + 600)
        # setting it again makes it pending again, and it fires again once
        await env.call("PUT", ids["carol"], f"/api/saved/{sid}/remind", json={"remind_at": iso(NOW + 5000)})
        env.now[0] = NOW + 100
        assert await server._saved_tick_once(NOW + 5001) == 1
        assert len(await notes(d, ids["carol"])) == 2
    run(body)


def test_an_unreadable_message_still_fires_and_opens_the_saved_view():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        pvt = await base.private_channel(d, ids)
        m = await d.create_chat_message(pvt, ids["alice"], "alice", SECRET)
        await pending(env, ids["bob"], "channel", m, NOW + 60)
        await d.remove_channel_member(pvt, ids["bob"])
        gen = await general(d)
        gone = await d.create_chat_message(gen, ids["alice"], "alice", SECRET + "2")
        await pending(env, ids["carol"], "channel", gone, NOW + 60)
        await d.delete_chat_message(gone)
        dm = await d.create_dm_conversation(ids["alice"], [ids["bob"]])
        dmm = await d.create_dm_message(dm["id"], ids["alice"], "alice", SECRET + "3")
        await pending(env, ids["bob"], "dm", dmm, NOW + 60)
        assert await server._saved_tick_once(NOW + 61) == 3
        for uid, count in ((ids["bob"], 2), (ids["carol"], 1)):
            for n in await notes(d, uid):
                assert decrypt_message(n["title"]) == SAVED_REMINDER_TITLE and not n["message"]
                assert set(json.loads(n["data"])) == {"saved", "saved_id"} and json.loads(n["data"])["saved"] == 1
            assert len(await notes(d, uid)) == count
    run(body)


def test_a_burst_is_capped_per_tick_and_a_restart_does_not_repeat_anything():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        rows = []
        old_cap = server.SAVED_TICK_CAP
        for i in range(7):
            m = await d.create_chat_message(gen, ids["bob"], "bob", f"b{i}")
            rows.append(await pending(env, ids["carol"], "channel", m, NOW + 10 + i))
        server.SAVED_TICK_CAP = 3
        try:
            assert await server._saved_tick_once(NOW + 1000) == 3        # came due while "down": 3 per tick
            assert len(await notes(d, ids["carol"])) == 3
            # a restart: a second connection to the same file, a fresh start of the tick
            d2 = Database(str(Path(env.tmp.name) / "t.db"))
            await d2.connect()
            server.db = d2
            try:
                assert await server._saved_tick_once(NOW + 1001) == 3
                assert await server._saved_tick_once(NOW + 1002) == 1
                assert await server._saved_tick_once(NOW + 1003) == 0
                assert len(await notes(d2, ids["carol"])) == 7
                ids_seen = [json.loads(n["data"])["saved_id"] for n in await notes(d2, ids["carol"])]
                assert sorted(ids_seen) == sorted(rows)                 # each exactly once
            finally:
                server.db = d
                await d2.close()
        finally:
            server.SAVED_TICK_CAP = old_cap
    run(body)


def test_one_member_with_many_due_reminders_does_not_use_the_whole_tick():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        assert server.SAVED_TICK_PER_MEMBER == 10
        a_rows, b_rows = [], []
        for i in range(15):                                  # carol's are the oldest, and many
            m = await d.create_chat_message(gen, ids["bob"], "bob", f"a{i}")
            a_rows.append(await pending(env, ids["carol"], "channel", m, NOW + 10 + i))
        for i in range(3):                                   # bob's come due later
            m = await d.create_chat_message(gen, ids["alice"], "alice", f"b{i}")
            b_rows.append(await pending(env, ids["bob"], "channel", m, NOW + 100 + i))
        old = server.SAVED_TICK_CAP
        server.SAVED_TICK_CAP = 12                           # the global cap: 10 + 3 would be 13

        def seen(rows):
            return [json.loads(n["data"])["saved_id"] for n in rows]
        try:
            assert await server._saved_tick_once(NOW + 1000) == 12
            first_a = seen(await notes(d, ids["carol"]))
            first_b = seen(await notes(d, ids["bob"]))
            assert first_a == a_rows[:10], first_a                       # oldest first, at most 10
            assert first_b == b_rows[:2], first_b                        # the rest of the global cap
            assert await server._saved_tick_once(NOW + 1001) == 6        # carol 5 left, bob 1 left
            server.SAVED_TICK_CAP = 50
            while await server._saved_tick_once(NOW + 1003):
                pass
            all_a, all_b = seen(await notes(d, ids["carol"])), seen(await notes(d, ids["bob"]))
            assert sorted(all_a) == sorted(a_rows) and sorted(all_b) == sorted(b_rows)   # nothing lost
            assert len(all_a) == len(set(all_a)) and len(all_b) == len(set(all_b))        # nothing twice
            assert await server._saved_tick_once(NOW + 1004) == 0
        finally:
            server.SAVED_TICK_CAP = old
        # with the normal cap: 15 due for one member take two ticks, three for the other fire at once
        d2rows = []
        for i in range(15):
            m = await d.create_chat_message(gen, ids["bob"], "bob", f"c{i}")
            d2rows.append(await pending(env, ids["carol"], "channel", m, NOW + 2000 + i))
        for i in range(3):
            m = await d.create_chat_message(gen, ids["alice"], "alice", f"d{i}")
            await pending(env, ids["bob"], "channel", m, NOW + 2100 + i)
        n_a, n_b = len(await notes(d, ids["carol"])), len(await notes(d, ids["bob"]))
        assert await server._saved_tick_once(NOW + 3000) == 13
        assert len(await notes(d, ids["carol"])) - n_a == 10 and len(await notes(d, ids["bob"])) - n_b == 3
        assert await server._saved_tick_once(NOW + 3001) == 5
        assert await server._saved_tick_once(NOW + 3002) == 0
    run(body)


def test_re_armed_reminders_keep_a_bounded_number_of_notifications_per_member():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        old = server.SAVED_MAX_REMINDER_NOTES
        server.SAVED_MAX_REMINDER_NOTES = 5
        try:
            sids = []
            for i in range(3):
                m = await d.create_chat_message(gen, ids["bob"], "bob", f"r{i}")
                sids.append(await save(env, ids["carol"], "channel", m))
            m = await d.create_chat_message(gen, ids["bob"], "bob", "other")
            other = await save(env, ids["bob"], "channel", m)
            # bob's own reminder note must survive carol's flood
            st, _ = await env.call("PUT", ids["bob"], f"/api/saved/{other}/remind", json={"remind_at": iso(NOW + 1)})
            assert st == 200
            assert await server._saved_tick_once(NOW + 2) == 1
            clock = NOW + 2
            for cycle in range(6):                       # 18 firings for one member
                for sid in sids:
                    st, _ = await env.call("PUT", ids["carol"], f"/api/saved/{sid}/remind",
                                           json={"remind_at": iso(clock + 1)})
                    assert st == 200
                clock += 2
                assert await server._saved_tick_once(clock) == 3
            mine = await notes(d, ids["carol"])
            assert len(mine) == 5
            assert [n["id"] for n in mine] == sorted(n["id"] for n in mine)
            all_ids = [r["id"] for r in await (await d.conn.execute(
                "SELECT id FROM notifications WHERE user_id = ? ORDER BY id", (ids["carol"],))).fetchall()]
            assert all_ids == [n["id"] for n in mine]
            assert len(await notes(d, ids["bob"])) == 1
        finally:
            server.SAVED_MAX_REMINDER_NOTES = old
    run(body)


def test_a_reminder_changed_or_removed_after_it_was_read_is_not_fired():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "x")
        sid = await pending(env, ids["carol"], "channel", m, NOW + 60)
        due = await d.due_saved_reminders(NOW + 61, 10)
        assert [r["id"] for r in due] == [sid]
        await env.call("PUT", ids["carol"], f"/api/saved/{sid}/remind", json={"remind_at": iso(NOW + 9000)})
        assert await d.fire_saved_reminders([(sid, ids["carol"], due[0]["remind_at"], {})], NOW + 61) == []
        await env.call("DELETE", ids["carol"], f"/api/saved/{sid}")
        assert await d.fire_saved_reminders([(sid, ids["carol"], NOW + 9000, {})], NOW + 9001) == []
        assert await notes(d, ids["carol"]) == []
        # a cleared reminder does not fire either
        sid2 = await pending(env, ids["carol"], "channel", m, NOW + 60)
        await env.call("PUT", ids["carol"], f"/api/saved/{sid2}/remind", json={"remind_at": None})
        assert await server._saved_tick_once(NOW + 61) == 0
    run(body)


def test_the_tick_query_uses_the_partial_index_and_an_idle_tick_reads_one_query():
    async def body(env):
        d = env.db
        import database
        plan = await d.conn.execute("EXPLAIN QUERY PLAN " + database.DUE_SAVED_SQL, (NOW, 10, 50))
        text = " ".join(str(tuple(r)) for r in await plan.fetchall())
        # the table is read through the partial index only (the SCANs left are of the window's own subqueries)
        assert "SEARCH saved_messages USING INDEX idx_saved_messages_due" in text and "SCAN saved_messages" not in text, text
        # and this is the query the method runs
        src = (ROOT / "database.py").read_text().split("async def due_saved_reminders", 1)[1].split("async def fire_saved_reminders", 1)[0]
        assert "DUE_SAVED_SQL" in src
        # nothing due: the tick makes the one query and nothing else
        calls = []
        real = d._connection

        class Spy:
            def __getattr__(self, name):
                return getattr(real, name)

            async def execute(self, sql, *a, **k):
                calls.append(sql)
                return await real.execute(sql, *a, **k)
        d._connection = Spy()
        try:
            assert await server._saved_tick_once(NOW) == 0
        finally:
            d._connection = real
        assert len(calls) == 1 and "saved_messages" in calls[0], calls
    run(body)


def test_the_push_carries_the_fixed_text_and_no_message_text_author_or_channel():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " push")
        await d.conn.execute("INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)",
                             (ids["carol"], "https://push.example.test/e1", "k", "a"))
        await d.conn.commit()
        sent = []

        class FakePusher:
            db = d
            tasks = set()

            async def enabled(self):
                return True

            def send_push(self, uid, payload, **kw):
                sent.append((uid, payload, kw))

            def cancel_all(self):
                pass
        saved_fn = server._get_pusher
        server._get_pusher = lambda: FakePusher()
        try:
            sid = await pending(env, ids["carol"], "channel", m, NOW + 60)
            await pending(env, ids["boss"], "channel", m, NOW + 60)          # no device: no push
            assert await server._saved_tick_once(NOW + 61) == 2
        finally:
            server._get_pusher = saved_fn
        assert len(sent) == 1 and sent[0][0] == ids["carol"]
        payload = sent[0][1]
        assert payload["type"] == "reminder" and payload["title"] == SAVED_REMINDER_TITLE
        flat = json.dumps(payload)
        assert SECRET not in flat and "bob" not in flat and "general" not in flat
        assert payload["url"] == f"/chat?channel_id={gen}&message_id={m}"
        assert payload["tag"] == f"reminder-{sid}"
        # an entry that cannot be opened pushes the Saved view address, still with the fixed text
        sent.clear()
        server._get_pusher = lambda: FakePusher()
        try:
            gone = await d.create_chat_message(gen, ids["bob"], "bob", SECRET + " gone")
            sid_gone = await pending(env, ids["carol"], "channel", gone, NOW + 100)
            await d.delete_chat_message(gone)
            assert await server._saved_tick_once(NOW + 101) == 1
        finally:
            server._get_pusher = saved_fn
        assert len(sent) == 1 and sent[0][1]["url"] == "/chat?saved=1" and sent[0][1]["title"] == SAVED_REMINDER_TITLE
        assert SECRET not in json.dumps(sent[0][1]) and sent[0][1]["tag"] == f"reminder-{sid_gone}"
        # a member with push off for every kind still gets it only as a device-owning member: the
        # reminder kind is not one of the switchable kinds
        assert "reminder" not in server.db.PUSH_KINDS
    run(body)


def test_a_notification_frame_goes_to_the_members_own_sockets_only():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "x")
        frames = []

        class WS:
            closed = False

            def __init__(self, tag):
                self.tag = tag

            async def send_json(self, payload):
                frames.append((self.tag, payload))
        server.notification_subscribers[ids["carol"]] = {WS("carol")}
        server.notification_subscribers[ids["bob"]] = {WS("bob")}
        server.notification_subscribers[ids["boss"]] = {WS("boss")}
        try:
            await pending(env, ids["carol"], "channel", m, NOW + 60)
            assert frames == []                                  # saving and setting send no frame
            await server._saved_tick_once(NOW + 61)
        finally:
            for uid in ("carol", "bob", "boss"):
                server.notification_subscribers.pop(ids[uid], None)
        assert [f[0] for f in frames] == ["carol"]
        n = frames[0][1]["notification"]
        assert n["type"] == "reminder" and n["title"] == SAVED_REMINDER_TITLE and not n["message"]
    run(body)


def test_no_clean_up_tells_a_member_who_lost_access_whether_a_message_still_exists():
    """A saved row is never removed because its message is gone: a member who lost access (removed from a
    private channel, left a conversation) must not learn, through a row that vanishes, which of two
    messages was deleted. The table stays bounded by the cap of 500 per member and goes with the member."""
    async def body(env):
        d = env.db
        ids = await base.users(d)
        pvt = await base.private_channel(d, ids)
        kept = await d.create_chat_message(pvt, ids["alice"], "alice", "one")
        deleted = await d.create_chat_message(pvt, ids["alice"], "alice", "two")
        s_kept = await save(env, ids["bob"], "channel", kept)
        s_deleted = await save(env, ids["bob"], "channel", deleted)
        await d.remove_channel_member(pvt, ids["bob"])
        await d.delete_chat_message(deleted)
        grace = 7 * 86400
        # a clean-up pass long after the grace, if the code still has one
        for name in ("cleanup_saved_messages",):
            if hasattr(d, name):
                await getattr(d, name)(NOW + 10 * grace, grace)
        items = (await listing(env, ids["bob"]))["items"]
        assert {i["id"] for i in items} == {s_kept, s_deleted}          # both stay, both look the same
        assert all(set(i) == UNAVAILABLE_KEYS and not i["available"] for i in items)
        for sid in (s_kept, s_deleted):                                  # and both can be removed
            assert (await env.call("DELETE", ids["bob"], f"/api/saved/{sid}"))[0] == 200
        assert not hasattr(d, "cleanup_saved_messages") and not hasattr(server, "SAVED_CLEANUP_GRACE_SECONDS")
        assert "saved" not in inspect.getsource(server.PortalServer._data_cleanup_task).lower()
    run(body)


def test_the_reminder_task_ticks_repeatedly_and_stops_cleanly_when_cancelled():
    async def body(env):
        ticks = []

        async def fake_tick(now=None):
            ticks.append(1)
            if len(ticks) == 2:
                raise RuntimeError("one bad tick does not stop the loop")
            return 0
        saved = (server._saved_tick_once, server.SAVED_FIRST_TICK_SECONDS, server._saved_tick_interval)
        server._saved_tick_once, server.SAVED_FIRST_TICK_SECONDS = fake_tick, 0.01
        server._saved_tick_interval = lambda: 0.02
        try:
            srv = server.PortalServer()
            srv._saved_task = asyncio.create_task(srv._saved_reminder_task())
            await asyncio.sleep(0.3)
            assert len(ticks) >= 4, ticks
            task, srv._saved_task = srv._saved_task, None
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert task.done()
            n = len(ticks)
            await asyncio.sleep(0.1)
            assert len(ticks) == n                              # nothing runs after the stop
        finally:
            server._saved_tick_once, server.SAVED_FIRST_TICK_SECONDS, server._saved_tick_interval = saved
        src = (ROOT / "server.py").read_text()
        stop = src[src.index("    async def stop(self)"):]
        assert "self._saved_task" in stop[:1500] and "task.cancel()" in stop[:1500]
    run(body)


def test_the_rows_go_with_the_user_and_the_migration_is_idempotent():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        m = await d.create_chat_message(gen, ids["bob"], "bob", "x")
        await pending(env, ids["carol"], "channel", m, NOW + 60)
        d2 = Database(str(Path(env.tmp.name) / "t.db"))
        await d2.connect()                                    # every migration runs again on the same file
        cur = await d2.conn.execute("SELECT COUNT(*) AS n FROM saved_messages")
        assert (await cur.fetchone())["n"] == 1
        await d2.delete_user(ids["carol"])
        cur = await d2.conn.execute("SELECT COUNT(*) AS n FROM saved_messages")
        assert (await cur.fetchone())["n"] == 0
        await d2.close()
    run(body)


def test_remove_unavailable_removes_only_the_callers_entries_that_no_longer_resolve():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids)
        ok = await save(env, ids["bob"], "channel", await d.create_chat_message(gen, ids["alice"], "alice", "fine"))
        gone_msg = await d.create_chat_message(gen, ids["alice"], "alice", SECRET + " gone")
        gone = await save(env, ids["bob"], "channel", gone_msg)
        waiting = await pending(env, ids["bob"], "channel", await d.create_chat_message(gen, ids["alice"], "alice", "w"), NOW + 600)
        hidden = await save(env, ids["bob"], "channel", await d.create_chat_message(pvt, ids["alice"], "alice", SECRET + " hidden"))
        other = await save(env, ids["carol"], "channel", gone_msg)           # another member's entry for the same message
        await d.delete_chat_message(gone_msg)
        await d.delete_chat_message((await d.get_saved_message(ids["bob"], waiting))["message_id"])
        await d.remove_channel_member(pvt, ids["bob"])
        before = [i["id"] for i in (await listing(env, ids["bob"]))["items"]]
        st, b = await env.call("DELETE", ids["bob"], "/api/saved/unavailable")
        assert st == 200 and b == {"removed": 3}, (st, b)                      # a count and nothing else
        assert sorted(before) == sorted([ok, gone, waiting, hidden])
        assert [i["id"] for i in (await listing(env, ids["bob"]))["items"]] == [ok]
        assert await d.get_saved_message(ids["bob"], waiting) is None          # one with a pending reminder goes too
        assert await d.get_saved_message(ids["carol"], other) is not None      # another member's entry is not touched
        st, b = await env.call("DELETE", ids["bob"], "/api/saved/unavailable")
        assert st == 200 and b == {"removed": 0}                               # nothing left to remove
        # an entry whose access came back is not removed
        await d.add_channel_member(pvt, ids["bob"], role="member", added_by=ids["boss"])
        keep = await save(env, ids["bob"], "channel", await d.create_chat_message(pvt, ids["alice"], "alice", "x"))
        assert (await env.call("DELETE", ids["bob"], "/api/saved/unavailable"))[1] == {"removed": 0}
        assert await d.get_saved_message(ids["bob"], keep) is not None
        # the route is not mistaken for an entry id, and a stream key or an API key is refused like the other routes
        assert (await env.call("DELETE", ids["bob"], "/api/saved/unavailable", headers={"X-Test-Kind": "apikey"}))[0] == 403
        assert (await env.call("DELETE", ids["bob"], "/api/saved/unavailable", headers={"X-Test-Kind": "streamkey"}))[0] == 403
        assert (await env.call("DELETE", ids["bob"], "/api/saved/unavailable", headers={"X-Test-Scopes": "services:read"}))[0] == 403
        # it resolves up to 500 entries, so it spends the history budget like the list and the marks
        server._history_hits.clear()
        for _ in range(server.HISTORY_RATE_LIMIT):
            assert (await env.call("DELETE", ids["bob"], "/api/saved/unavailable"))[0] == 200
        async with env.http.delete(env.url("/api/saved/unavailable"), headers={"X-Test-User": str(ids["bob"])}) as r:
            assert r.status == 429 and int(r.headers["Retry-After"]) >= 1
    run(body)


def test_remove_unavailable_is_registered_before_the_entry_id_route():
    src = (ROOT / "server.py").read_text()
    assert src.index('"/api/saved/unavailable", http_delete_saved_unavailable') < src.index('"/api/saved/{id}", http_delete_saved)')


def test_the_saved_routes_write_no_audit_or_log_line_about_a_member_s_entries():
    src = (ROOT / "server.py").read_text()
    start = src.index("async def http_get_saved(")
    end = src.index("async def _broadcast_stream_info(")
    section = src[start:end]
    for needle in ("audit_log(", "security_event(", "logger.info(", "logger.warning(f\"Saved", "activity"):
        assert needle not in section.replace("logger.warning(f\"Reminder delivery failed", ""), needle


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    assert not outbound_guard.refused, outbound_guard.refused
    sys.exit(1 if failed else 0)
