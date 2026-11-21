"""Per-channel notification levels, timed mute and the channel_activity signal.

Runs the real chat websocket handler and the real HTTP handlers in-process against a
temporary database (only the authentication lookup is replaced), with real sockets.

* channel_activity carries the channel id and nothing else; it reaches online members who are
  not joined to the room, never the sender, never a member who is in the room
* a private channel's and a non-public stream chat's activity reaches only members who may read
  it, never another socket; a member removed from the channel stops receiving it on the next
  message (the remembered verdict is dropped by the eviction)
* a warm fan-out asks the database nothing per member
* level none or an active mute stops the activity; an @mention still notifies unless the level
  is none; an expired mute lets the activity through again
* the routes: own choice only, unreadable channel answers like a missing one, validation,
  write-through cache, the channel list carries the choice, the table migration is idempotent

Run: venv/bin/python tests/test_notify_levels.py
"""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import test_chat_access_loss as base  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402


class Env(base.Env):
    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", base.fake_auth),
                            ("_credential_still_valid", base.fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        self.saved["_notify_clock"] = server._notify_clock
        self.now = [1_800_000_000.0]
        server._notify_clock = lambda: self.now[0]
        server.chat_rooms.clear()
        server._chat_sockets.clear()
        server._notify_prefs_cache.clear()
        server._activity_verdicts.clear()
        server._activity_context.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/api/chat/channels", server.http_get_chat_channels)
        app.router.add_get("/api/chat/channels/{id}/notify", server.http_get_channel_notify)
        app.router.add_put("/api/chat/channels/{id}/notify", server.http_put_channel_notify)
        app.router.add_delete("/api/chat/channels/{id}/members/{user_id}", server.http_remove_channel_member)
        app.router.add_post("/api/chat/channels/{id}/members", server.http_add_channel_member)
        app.router.add_put("/api/chat/channels/{id}", server.http_update_chat_channel)
        app.router.add_put("/api/streams/{id}", server.http_update_user_stream)
        app.router.add_post("/api/streams/{id}/bans", server.http_create_stream_ban)
        app.router.add_delete("/api/streams/{id}/bans/{user_id}", server.http_remove_stream_ban)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


def activity(sock, start=0, cid=None):
    return [e for e in sock.events[start:] if e.get("type") == "channel_activity"
            and (cid is None or e.get("channel_id") == cid)]


async def settle():
    await asyncio.sleep(0.4)


async def general(d):
    chans = await d.get_chat_channels()
    return next(c["id"] for c in chans if c["name"] == "general")


async def pub_channel(d, ids, name="lobby"):
    return await d.create_chat_channel(name, created_by=ids["boss"])


# ---------------------------------------------------------------------------

def test_activity_reaches_members_outside_the_room_with_the_channel_id_only():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen, lobby = await general(d), await pub_channel(d, ids)
        poster, away, reader, other_tab = (await env.sock(ids["carol"]), await env.sock(ids["bob"]),
                                           await env.sock(ids["viewer"]), await env.sock(ids["carol"]))
        await poster.join(lobby)
        await reader.join(lobby)           # in the room: sees the message itself
        await away.join(gen)
        await other_tab.join(gen)          # the sender's second tab: not told about its own message
        marks = {s: s.mark() for s in (poster, away, reader, other_tab)}
        await poster.send(type="message", message="hello there")
        await away.wait(lambda e: e.get("type") == "channel_activity", marks[away])
        await settle()
        got = activity(away, marks[away])
        assert len(got) == 1 and got[0] == {"type": "channel_activity", "channel_id": lobby}, got
        assert not activity(reader, marks[reader]), "a member in the room must not get the badge signal"
        assert not activity(poster, marks[poster]) and not activity(other_tab, marks[other_tab])
        assert "hello there" not in json.dumps(got)
    run(body)


def test_an_anonymous_poster_is_not_named_in_the_signal():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen, lobby = await general(d), await pub_channel(d, ids)
        await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (ids["carol"],))
        await d.conn.commit()
        poster, away = await env.sock(ids["carol"]), await env.sock(ids["bob"])
        await poster.join(lobby)
        await away.join(gen)
        mark = away.mark()
        await poster.send(type="message", message="anon words")
        await away.wait(lambda e: e.get("type") == "channel_activity", mark)
        text = json.dumps(away.events[mark:])
        assert "carol" not in text and str(ids["carol"]) not in text.replace(str(lobby), "x"), text
    run(body)


def test_a_private_channel_signal_never_reaches_a_non_member():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids)             # members alice (moderator) and bob
        boss = await env.sock(ids["boss"])
        bob, carol, viewer, alice = (await env.sock(ids["bob"]), await env.sock(ids["carol"]),
                                     await env.sock(ids["viewer"]), await env.sock(ids["alice"]))
        await boss.join(pvt)
        for s in (bob, carol, viewer, alice):
            await s.join(gen)
        marks = {s: s.mark() for s in (bob, carol, viewer, alice)}
        await boss.send(type="message", message="members only")
        await bob.wait(lambda e: e.get("type") == "channel_activity", marks[bob])
        await alice.wait(lambda e: e.get("type") == "channel_activity", marks[alice])
        await settle()
        assert activity(bob, marks[bob], pvt) and activity(alice, marks[alice], pvt)
        for s in (carol, viewer):
            assert not activity(s, marks[s]), s.events[marks[s]:]
            assert "pvt" not in json.dumps(s.events[marks[s]:]), s.events[marks[s]:]
    run(body)


def test_a_member_removed_from_a_private_channel_stops_getting_the_signal():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids)
        boss, bob = await env.sock(ids["boss"]), await env.sock(ids["bob"])
        await boss.join(pvt)
        await bob.join(gen)
        mark = bob.mark()
        await boss.send(type="message", message="one")
        assert await bob.wait(lambda e: e.get("type") == "channel_activity", mark)   # verdict is now remembered
        st, _ = await env.call("DELETE", ids["boss"], f"/api/chat/channels/{pvt}/members/{ids['bob']}")
        assert st == 200
        mark = bob.mark()
        await boss.send(type="message", message="two")
        await settle()
        assert not activity(bob, mark), "removed member still told about the private channel"
    run(body)


def test_a_non_public_stream_chat_signal_reaches_only_those_who_may_read_it():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        cid, sid = await base.stream_chat(d, ids, public=False)
        owner, boss, viewer, carol = (await env.sock(ids["owner"]), await env.sock(ids["boss"]),
                                      await env.sock(ids["viewer"]), await env.sock(ids["carol"]))
        await owner.join(cid)
        for s in (boss, viewer, carol):
            await s.join(gen)
        marks = {s: s.mark() for s in (boss, viewer, carol)}
        await owner.send(type="message", message="private stream chat")
        await boss.wait(lambda e: e.get("type") == "channel_activity", marks[boss])
        await settle()
        assert activity(boss, marks[boss], cid)
        for s in (viewer, carol):
            assert not activity(s, marks[s]) and "strm" not in json.dumps(s.events[marks[s]:])
        # made public through the route (nothing is cleared by hand): members may read it and are told
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": True})
        assert st == 200, b
        mark = viewer.mark()
        await owner.send(type="message", message="now public")
        assert await viewer.wait(lambda e: e.get("type") == "channel_activity", mark)
    run(body)


def test_a_warm_fan_out_reads_nothing_per_member():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids, members=("alice", "bob", "carol", "viewer"))
        channel = await d.get_chat_channel(pvt)
        socks = [await env.sock(ids[n]) for n in ("alice", "bob", "carol", "viewer")]
        for s in socks:
            await s.join(gen)
        calls = {"member": 0, "stream": 0, "members": 0}
        real_member, real_stream = d.is_channel_member, d.get_stream_by_chat_channel
        real_members = d.get_channel_member_ids

        async def members(*a, **k):
            calls["members"] += 1
            return await real_members(*a, **k)
        d.get_channel_member_ids = members

        async def member(*a, **k):
            calls["member"] += 1
            return await real_member(*a, **k)

        async def stream(*a, **k):
            calls["stream"] += 1
            return await real_stream(*a, **k)
        d.is_channel_member, d.get_stream_by_chat_channel = member, stream
        try:
            assert await server._signal_channel_activity(channel, ids["boss"]) == 4
            cold = dict(calls)
            assert cold["member"] == 0 and cold["members"] == 1 and cold["stream"] == 1, cold   # per channel, not per member
            assert await server._signal_channel_activity(channel, ids["boss"]) == 4
            assert calls == cold, calls                          # warm: no read at all, not even the stream
        finally:
            d.is_channel_member, d.get_stream_by_chat_channel = real_member, real_stream
            d.get_channel_member_ids = real_members
    run(body)


def test_a_public_stream_chat_fan_out_reads_per_channel_not_per_member():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        cid, sid = await base.stream_chat(d, ids, public=True)
        channel = await d.get_chat_channel(cid)
        names = ("alice", "bob", "carol", "viewer", "boss")
        socks = [await env.sock(ids[n]) for n in names]
        for s_ in socks:
            await s_.join(gen)
        calls = {"stream": 0, "bans": 0, "ban": 0, "member": 0}
        real = (d.get_stream_by_chat_channel, d.get_banned_user_ids, d.is_user_banned_from_stream, d.is_channel_member)

        def counting(key, fn):
            async def wrapped(*a, **k):
                calls[key] += 1
                return await fn(*a, **k)
            return wrapped
        d.get_stream_by_chat_channel = counting("stream", real[0])
        d.get_banned_user_ids = counting("bans", real[1])
        d.is_user_banned_from_stream = counting("ban", real[2])
        d.is_channel_member = counting("member", real[3])
        try:
            assert await server._signal_channel_activity(channel, ids["owner"]) == len(names)
            cold = dict(calls)
            assert cold == {"stream": 1, "bans": 1, "ban": 0, "member": 0}, cold
            assert await server._signal_channel_activity(channel, ids["owner"]) == len(names)
            assert calls == cold, calls
            # memo expiry: the verdicts are asked again from the remembered stream and bans, not the database
            server._activity_verdicts.clear()
            assert await server._signal_channel_activity(channel, ids["owner"]) == len(names)
            assert calls == cold, calls
        finally:
            (d.get_stream_by_chat_channel, d.get_banned_user_ids,
             d.is_user_banned_from_stream, d.is_channel_member) = real
    run(body)


def test_a_ban_and_its_lifting_take_effect_on_the_next_message():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        cid, sid = await base.stream_chat(d, ids, public=True)
        owner, carol = await env.sock(ids["owner"]), await env.sock(ids["carol"])
        await owner.join(cid)
        await carol.join(gen)
        mark = carol.mark()
        await owner.send(type="message", message="one")
        assert await carol.wait(lambda e: e.get("type") == "channel_activity", mark)    # warm and allowed
        st, b = await env.call("POST", ids["owner"], f"/api/streams/{sid}/bans", json={"user_id": ids["carol"]})
        assert st in (200, 201), b
        mark = carol.mark()
        await owner.send(type="message", message="two")
        await settle()
        assert not activity(carol, mark, cid), "a banned member is still told"
        st, b = await env.call("DELETE", ids["owner"], f"/api/streams/{sid}/bans/{ids['carol']}")
        assert st == 200, b
        mark = carol.mark()
        await owner.send(type="message", message="three")
        assert await carol.wait(lambda e: e.get("type") == "channel_activity", mark), "ban lifted: no badge"
    run(body)


def test_a_member_added_to_a_private_channel_and_a_channel_made_public_get_the_signal_at_once():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids, members=("alice",))
        boss, bob = await env.sock(ids["boss"]), await env.sock(ids["bob"])
        await boss.join(pvt)
        await bob.join(gen)
        mark = bob.mark()
        await boss.send(type="message", message="one")
        await settle()
        assert not activity(bob, mark, pvt)                       # "not allowed" is now remembered
        st, b = await env.call("POST", ids["boss"], f"/api/chat/channels/{pvt}/members",
                               json={"user_id": ids["bob"], "role": "member"})
        assert st == 201, b
        mark = bob.mark()
        await boss.send(type="message", message="two")
        assert await bob.wait(lambda e: e.get("type") == "channel_activity", mark), "added member not told"
        # the other way: a channel made public (carol was never a member)
        carol = await env.sock(ids["carol"])
        await carol.join(gen)
        mark = carol.mark()
        await boss.send(type="message", message="three")
        await settle()
        assert not activity(carol, mark, pvt)
        st, b = await env.call("PUT", ids["boss"], f"/api/chat/channels/{pvt}", json={"visibility": "public"})
        assert st == 200, b
        mark = carol.mark()
        await boss.send(type="message", message="four")
        assert await carol.wait(lambda e: e.get("type") == "channel_activity", mark), "public channel: no badge"
    run(body)


def test_a_removed_member_is_evicted_before_the_mod_ended_step_runs():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await general(d)
        pvt = await base.private_channel(d, ids)
        bob = await env.sock(ids["bob"])
        await bob.join(pvt)
        seen = {}
        real_ended, real_row = server._stream_mod_ended, server._mod_row_of

        async def fake_row(channel_id, target_id):
            return {"id": 0}

        async def fake_ended(channel, *a, **k):
            seen["in_room"] = any(e[1] == ids["bob"] for e in server.chat_rooms.get("pvt", ()))
            seen["memo"] = pvt in server._activity_context or pvt in server._activity_verdicts
        server._mod_row_of, server._stream_mod_ended = fake_row, fake_ended
        server._activity_verdicts[pvt] = {(ids["bob"], "user"): (True, 1e18)}
        try:
            st, _ = await env.call("DELETE", ids["boss"], f"/api/chat/channels/{pvt}/members/{ids['bob']}")
            assert st == 200
        finally:
            server._mod_row_of, server._stream_mod_ended = real_row, real_ended
        assert seen == {"in_room": False, "memo": False}, seen
    run(body)


def test_a_socket_whose_levels_are_not_loaded_yet_gets_no_signal():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen, lobby = await general(d), await pub_channel(d, ids)
        await d.set_notify_pref(ids["bob"], lobby, "none", 0)
        carol = await env.sock(ids["carol"])
        await carol.join(lobby)
        gate = asyncio.Event()
        real = d.get_notify_prefs

        async def slow(user_id):
            if user_id == ids["bob"]:
                await gate.wait()
            return await real(user_id)
        d.get_notify_prefs = slow
        try:
            bob_ws = await env.http.ws_connect(env.url("/ws/chat"), headers={"X-Test-User": str(ids["bob"])})
            mark = carol.mark()
            await carol.send(type="message", message="while the levels load")
            await carol.wait(lambda e: e.get("type") == "message", mark)
            await asyncio.sleep(0.3)
            got = []
            while True:
                try:
                    got.append((await asyncio.wait_for(bob_ws.receive_json(), 0.2)))
                except Exception:
                    break
            assert not [e for e in got if e.get("type") == "channel_activity"], got
            gate.set()
            await asyncio.sleep(0.3)
            assert server._notify_prefs_cache.get(ids["bob"]) == {lobby: ("none", 0)}
            await bob_ws.close()
        finally:
            d.get_notify_prefs = real
            gate.set()
    run(body)


def test_mute_and_levels_stop_the_signal_but_a_mention_still_notifies():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen, lobby = await general(d), await pub_channel(d, ids)
        posters = [await env.sock(ids[n]) for n in ("carol", "viewer", "owner")]   # 5 messages per 5 s each
        bob = await env.sock(ids["bob"])
        for p in posters:
            await p.join(lobby)
        await bob.join(gen)
        turn = [0]

        async def post(text):
            mark = bob.mark()
            turn[0] += 1
            await posters[turn[0] % 3].send(type="message", message=text)
            await settle()
            return mark

        # default: a signal
        mark = await post("plain one")
        assert activity(bob, mark, lobby)
        # muted for 8 hours: no signal; an @mention still notifies
        st, b = await env.call("PUT", ids["bob"], f"/api/chat/channels/{lobby}/notify", json={"mute_hours": 8})
        assert st == 200 and b["muted_until"] == int(env.now[0] + 8 * 3600), b
        mark = await post("plain two")
        assert not activity(bob, mark)
        mark = await post("hey @bob")
        assert not activity(bob, mark)
        assert any(e.get("type") == "notification" and e["notification"]["type"] == "mention"
                   and e["notification"]["data"]["channel_id"] == lobby for e in bob.events[mark:]), bob.events[mark:]
        # the mute runs out
        env.now[0] += 8 * 3600 + 1
        mark = await post("plain three")
        assert activity(bob, mark, lobby)
        # level mentions: no ordinary signal, mention notifies
        await env.call("PUT", ids["bob"], f"/api/chat/channels/{lobby}/notify", json={"level": "mentions"})
        mark = await post("plain four")
        assert not activity(bob, mark)
        mark = await post("again @bob")
        assert any(e.get("type") == "notification" for e in bob.events[mark:])
        # level none: nothing, not even the mention
        await env.call("PUT", ids["bob"], f"/api/chat/channels/{lobby}/notify", json={"level": "none"})
        mark = await post("silence @bob")
        assert not activity(bob, mark) and not any(e.get("type") == "notification" for e in bob.events[mark:])
        # back to all: the signal returns at once (write-through cache)
        await env.call("PUT", ids["bob"], f"/api/chat/channels/{lobby}/notify", json={"level": "all"})
        mark = await post("plain five")
        assert activity(bob, mark, lobby)
    run(body)


def test_routes():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen, lobby = await general(d), await pub_channel(d, ids)
        pvt = await base.private_channel(d, ids)
        url = lambda c: f"/api/chat/channels/{c}/notify"          # noqa: E731
        # own choice, default first
        st, b = await env.call("GET", ids["bob"], url(lobby))
        assert st == 200 and b == {"channel_id": lobby, "notify_level": None, "muted_until": 0}, b
        st, b = await env.call("PUT", ids["bob"], url(lobby), json={"level": "mentions"})
        assert st == 200 and b["notify_level"] == "mentions"
        st, b = await env.call("GET", ids["carol"], url(lobby))
        assert b["notify_level"] is None, "another member's choice must not show"
        st, b = await env.call("PUT", ids["bob"], url(lobby), json={"mute_hours": 1})
        assert b["notify_level"] == "mentions" and b["muted_until"] == int(env.now[0] + 3600), b
        st, b = await env.call("PUT", ids["bob"], url(lobby), json={"mute_hours": 0})
        assert b["muted_until"] == 0 and b["notify_level"] == "mentions"
        # a mute on a default channel keeps showing level null
        st, b = await env.call("PUT", ids["carol"], url(lobby), json={"mute_hours": 24})
        assert st == 200 and b["notify_level"] is None and b["muted_until"] > 0, b
        st, b = await env.call("PUT", ids["carol"], url(lobby), json={"mute_hours": 0})
        assert (await d.get_notify_prefs(ids["carol"])) == {}, "an ended mute on the default leaves no row"
        # the channel list carries it
        st, b = await env.call("GET", ids["bob"], "/api/chat/channels")
        row = next(c for c in b["channels"] if c["id"] == lobby)
        assert row["notify_level"] == "mentions" and row["muted_until"] == 0
        # validation
        for bad in ({"level": "noisy"}, {"level": 3}, {"mute_hours": 2}, {"mute_hours": True}, {"mute_hours": "8"},
                    {}, {"other": 1}):
            st, b = await env.call("PUT", ids["bob"], url(lobby), json=bad)
            assert st == 400, (bad, st, b)
        # unreadable = missing, byte for byte
        async with env.http.get(env.url(url(pvt)), headers={"X-Test-User": str(ids["carol"])}) as r1:
            unreadable = (r1.status, await r1.read())
        async with env.http.get(env.url(url(99999)), headers={"X-Test-User": str(ids["carol"])}) as r2:
            missing = (r2.status, await r2.read())
        assert unreadable == missing and unreadable[0] == 404, (unreadable, missing)
        async with env.http.put(env.url(url(pvt)), json={"level": "none"},
                                headers={"X-Test-User": str(ids["carol"])}) as r3:
            assert (r3.status, await r3.read()) == missing
        assert pvt not in await d.get_notify_prefs(ids["carol"])
        st, b = await env.call("PUT", ids["bob"], url(pvt), json={"level": "none"})     # a member may
        assert st == 200
        async with env.http.get(env.url(url(lobby))) as r4:                              # no credential
            assert r4.status in (401, 403)
    run(body)


def test_the_table_migration_is_idempotent_and_a_user_delete_removes_the_rows():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await pub_channel(d, ids)
        await d.set_notify_pref(ids["bob"], lobby, "none", 0)
        await d.close()
        d2 = Database(d.db_path if hasattr(d, "db_path") else str(Path(env.tmp.name) / "t.db"))
        await d2.connect()                     # the migrations run again on the same file
        assert await d2.get_notify_prefs(ids["bob"]) == {lobby: ("none", 0)}
        await d2.delete_user(ids["bob"])
        cur = await d2.conn.execute("SELECT COUNT(*) AS n FROM channel_notify_prefs WHERE user_id = ?", (ids["bob"],))
        assert (await cur.fetchone())["n"] == 0
        await d2.close()
        env.db = d                              # the environment closes it again; harmless
        d.close = lambda: asyncio.sleep(0)
    run(body)


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
    sys.exit(1 if failed else 0)
