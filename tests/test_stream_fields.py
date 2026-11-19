"""Stream settings are checked by type (create and update), a stream's chat
binding never hides or deletes a default or shared channel, the room is emptied
of members who cannot read it after any update that leaves the stream private,
mention notifications follow the read rule, and typing frames are throttled.

Runs the real HTTP handlers and chat websocket in-process (only the
authentication lookup is replaced) against a temporary database.

Run: venv/bin/python tests/test_stream_fields.py
"""

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import server  # noqa: E402
from test_chat_access_loss import (  # noqa: E402
    assert_put_out, run, stream_chat, users)


async def channel_id(d, name):
    return (await d.get_chat_channel_by_name(name))["id"]


def test_a_client_cannot_set_server_owned_stream_fields():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        general = await channel_id(d, "general")
        before = await d.get_user_stream(sid)
        for payload in ({"chat_channel_id": general}, {"is_live": 1}, {"viewer_count": 999},
                        {"started_at": "2000-01-01T00:00:00", "ended_at": "2000-01-02T00:00:00"}):
            st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json=payload)
            assert st == 400, (payload, st, b)
        # mixed with a real edit: the edit is applied, the rest ignored
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}",
                               json={"name": "renamed", "description": "d2", "chat_channel_id": general,
                                     "is_live": 1, "viewer_count": 999, "started_at": "x", "ended_at": "y"})
        assert st == 200, b
        after = await d.get_user_stream(sid)
        assert after["name"] == "renamed" and after["description"] == "d2"
        for k in ("chat_channel_id", "is_live", "viewer_count", "started_at", "ended_at"):
            assert after[k] == before[k], (k, before[k], after[k])
        assert after["chat_channel_id"] == cid
        # the other settings the screen sends still work
        for payload in ({"is_public": False}, {"rtmp_enabled": 1}, {"allow_unauthenticated": True}):
            st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json=payload)
            assert st == 200, (payload, b)
        # the general channel is still listed for everyone
        st, b = await env.call("GET", ids["viewer"], "/api/chat/channels")
        assert "general" in {c["name"] for c in b["channels"]}
    run(body)


def test_a_default_or_shared_channel_is_not_hidden_or_deleted_by_a_stream():
    async def body(env):
        d = env.db
        ids = await users(d)
        general = await channel_id(d, "general")
        sid = await d.create_user_stream(ids["owner"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                         is_public=False)
        await d.update_user_stream(sid, chat_channel_id=general)       # server-side use stays possible
        stream = await d.get_stream_by_chat_channel(general)
        assert stream["chat_channel_shared"] is True
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is False
        st, b = await env.call("GET", ids["viewer"], "/api/chat/channels")
        assert "general" in {c["name"] for c in b["channels"]}
        st, b = await env.call("DELETE", ids["owner"], f"/api/streams/{sid}")
        assert st == 200, b
        assert await d.get_chat_channel(general), "default channel survives the stream delete"

        # one channel bound to two streams
        cid, s1 = await stream_chat(d, ids, public=False)
        s2 = await d.create_user_stream(ids["owner"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                        is_public=False)
        await d.update_user_stream(s2, chat_channel_id=cid)
        stream = await d.get_stream_by_chat_channel(cid)
        assert stream["chat_channel_shared"] is True
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is True, "several private streams: closed"
        assert server._stream_chat_hidden(stream, ids["owner"], "user") is False
        st, b = await env.call("DELETE", ids["owner"], f"/api/streams/{s1}")
        assert st == 200, b
        assert await d.get_chat_channel(cid), "a channel another stream uses survives"
        # now bound to one private stream: hidden, and deleted with it
        stream = await d.get_stream_by_chat_channel(cid)
        assert stream["chat_channel_shared"] is False
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is True
        st, b = await env.call("DELETE", ids["owner"], f"/api/streams/{s2}")
        assert st == 200, b
        assert await d.get_chat_channel(cid) is None, "the chat of a lone stream goes with it"
    run(body)


def test_updating_an_already_private_stream_puts_the_room_out():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        target = await d.create_chat_message(cid, ids["owner"], "owner", "owner words")
        viewer, owner = await env.sock(ids["viewer"]), await env.sock(ids["owner"])
        viewer.uid = ids["viewer"]
        for s in (viewer, owner):
            await s.join(cid)
        # private behind the sockets' back (no transition in the request below)
        await d.update_user_stream(sid, is_public=False)
        m = viewer.mark()
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": False})
        assert st == 200, b
        await assert_put_out(viewer, [owner], "strm", target, m)
    run(body)


def test_stream_settings_are_checked_by_type_before_anything_is_written():
    async def body(env):
        d = env.db
        ids = await users(d)
        sid = await d.create_user_stream(ids["owner"], "legacy", "live_" + "a" * 24,
                                         public_key="pub_" + "b" * 24, is_public=True)   # no chat channel yet
        before = await d.get_user_stream(sid)
        assert not before.get("chat_channel_id")
        bad = [{"is_public": "yes"}, {"is_public": 2}, {"is_public": None}, {"is_public": 1.0},
               {"allow_unauthenticated": "false"}, {"rtmp_enabled": [1]},
               {"name": ""}, {"name": "   "}, {"name": 5}, {"name": None}, {"name": "n" * 101},
               {"description": 5}, {"description": ["x"]}, {"description": "d" * 2001},
               {"name": "fine", "is_public": "no"}]
        for payload in bad:
            st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json=payload)
            assert st == 400, (payload, st, b)
        after = await d.get_user_stream(sid)
        assert after["name"] == before["name"] and after["is_public"] == before["is_public"]
        assert not after.get("chat_channel_id"), "no legacy chat channel was created by a refused request"
        assert await d.get_chat_channel_by_name(f"stream-owner-{sid}") is None
        # accepted forms: booleans and 0/1, stored as 0/1; name stripped; description string or null
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}",
                               json={"is_public": False, "allow_unauthenticated": True, "rtmp_enabled": 0,
                                     "name": "  ok name  ", "description": "d" * 2000})
        assert st == 200, b
        got = await d.get_user_stream(sid)
        assert (got["is_public"], got["allow_unauthenticated"], got["rtmp_enabled"]) == (0, 1, 0), got
        assert got["name"] == "ok name" and got["description"] == "d" * 2000
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": 1, "description": None})
        assert st == 200, b
        got = await d.get_user_stream(sid)
        assert got["is_public"] == 1 and not got["description"]
        # the create route uses the same checks
        for payload in ({"name": 5}, {"name": ""}, {}, {"name": "ok", "is_public": "false"},
                        {"name": "ok", "description": 7}, {"name": "n" * 101}, {"name": "ok", "is_public": 3}):
            st, b = await env.call("POST", ids["owner"], "/api/streams", json=payload)
            assert st == 400, (payload, st, b)
        assert len(await d.get_user_streams(ids["owner"])) == 1, "a refused create wrote nothing"
        st, b = await env.call("POST", ids["owner"], "/api/streams",
                               json={"name": " made ", "is_public": True, "description": "x"})
        assert st == 201, b
        assert b["stream"]["name"] == "made" and b["stream"]["is_public"] == 1
    run(body)


def test_a_channel_bound_to_several_streams_fails_closed():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, s1 = await stream_chat(d, ids, public=True)
        s2 = await d.create_user_stream(ids["carol"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                        is_public=False)
        await d.update_user_stream(s2, chat_channel_id=cid)
        stream = await d.get_stream_by_chat_channel(cid)
        assert stream["chat_channel_shared"] is True
        # one bound stream is private: closed to ordinary members, open to owners of either and admins
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is True
        assert server._stream_chat_hidden(stream, ids["owner"], "user") is False
        assert server._stream_chat_hidden(stream, ids["carol"], "user") is False
        assert server._stream_chat_hidden(stream, ids["boss"], "admin") is False
        st, b = await env.call("GET", ids["viewer"], "/api/chat/channels")
        assert "strm" not in {c["name"] for c in b["channels"]}
        st, b = await env.call("GET", ids["carol"], "/api/chat/channels")
        assert "strm" in {c["name"] for c in b["channels"]}
        viewer = await env.sock(ids["viewer"])
        err = await viewer.send(type="join", channel_id=cid) or await viewer.wait(
            lambda e: e.get("type") in ("history", "error"))
        assert err["type"] == "error" and err["message"] == "Channel not found", err
        # every bound stream public: open
        await d.update_user_stream(s2, is_public=True)
        stream = await d.get_stream_by_chat_channel(cid)
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is False
        # a default channel is never hidden by a binding
        general = await channel_id(d, "general")
        s3 = await d.create_user_stream(ids["owner"], "s3", "live_" + "e" * 24, public_key="pub_" + "f" * 24,
                                        is_public=False)
        await d.update_user_stream(s3, chat_channel_id=general)
        stream = await d.get_stream_by_chat_channel(general)
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is False
    run(body)


def test_a_stream_has_no_power_over_a_default_or_shared_channel():
    async def body(env):
        d = env.db
        ids = await users(d)
        general = await channel_id(d, "general")
        sid = await d.create_user_stream(ids["owner"], "s0", "live_" + "x" * 24, public_key="pub_" + "y" * 24,
                                         is_public=True)
        await d.update_user_stream(sid, chat_channel_id=general)
        cid, s_own = await stream_chat(d, ids, public=True)       # a stream with its own channel (control)
        mine = await d.create_chat_message(general, ids["bob"], "bob", "keep me")
        own = await d.create_chat_message(cid, ids["bob"], "bob", "clear me")

        async def count(channel):
            return len(await d.get_chat_messages(channel, limit=50))
        saved_stop, real_sleep = server.stop_vod_recording, asyncio.sleep

        async def no_vod(*a, **k):
            return None

        async def quick(t, *a, **k):
            return await real_sleep(0 if t == 7 else t)
        server.stop_vod_recording = no_vod
        server.asyncio.sleep = quick
        try:
            for finish in ("finalize", "grace"):
                for st_id in (sid, s_own):
                    await d.set_stream_live(st_id, True)
                    stream = await d.get_user_stream(st_id)
                    if finish == "finalize":
                        await server._finalize_stream_offline(stream)
                    else:
                        task = asyncio.create_task(server._handle_disconnect_grace(stream))
                        server._disconnect_grace_tasks[st_id] = task
                        await task
                    if st_id == s_own and finish == "finalize":
                        assert await count(cid) == 0, "the chat of a lone stream is cleared (control)"
                        own = await d.create_chat_message(cid, ids["bob"], "bob", "clear me")
                assert await count(general) == 1, f"default channel kept its messages ({finish})"
                if finish == "grace":
                    assert await count(cid) == 0, "grace path clears an own channel (control)"
        finally:
            server.stop_vod_recording = saved_stop
            server.asyncio.sleep = real_sleep
        # the shared case: a second stream on the same non-default channel
        s2 = await d.create_user_stream(ids["carol"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                        is_public=True)
        await d.update_user_stream(s2, chat_channel_id=cid)
        await d.create_chat_message(cid, ids["bob"], "bob", "shared words")
        await d.set_stream_live(s_own, True)
        server.stop_vod_recording = no_vod
        try:
            await server._finalize_stream_offline(await d.get_user_stream(s_own))
        finally:
            server.stop_vod_recording = saved_stop
        assert await count(cid) == 1, "a channel another stream uses keeps its messages"

        # ban, unban and bans over the socket: not as owner of a stream bound to a default channel
        owner, boss = await env.sock(ids["owner"]), await env.sock(ids["boss"])
        await owner.join(general)
        await boss.join(general)
        for payload, ok_type in (({"type": "ban", "user_id": ids["bob"]}, "ban_success"),
                                 ({"type": "get_bans"}, "bans_list")):
            m = owner.mark()
            await owner.send(**payload)
            err = await owner.wait(lambda e: e.get("type") in ("error", ok_type), m)
            assert err and err["type"] == "error" and err["message"] == "Not authorized", (payload, err)
        m = owner.mark()
        await owner.send(type="unban", user_id=ids["bob"])
        err = await owner.wait(lambda e: e.get("type") in ("error", "unban_success"), m)
        assert err and err["type"] == "error" and err["message"] == "Not authorized", err
        assert not await d.is_user_banned_from_stream(sid, ids["bob"])
        m = boss.mark()
        await boss.send(type="get_bans")
        got = await boss.wait(lambda e: e.get("type") in ("error", "bans_list"), m)
        assert got and got["type"] == "bans_list", "admins keep the action"
        # an owner of a stream with its own channel can still ban there (control)
        own_owner = await env.sock(ids["owner"])
        # s_own's channel is now shared with carol's stream: the owner is refused there too
        await own_owner.join(cid)
        m = own_owner.mark()
        await own_owner.send(type="get_bans")
        err = await own_owner.wait(lambda e: e.get("type") in ("error", "bans_list"), m)
        assert err and err["type"] == "error", err
    run(body)


def test_an_update_that_leaves_the_stream_private_puts_the_room_out_without_is_public():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        viewer = await env.sock(ids["viewer"])
        await viewer.join(cid)
        await d.update_user_stream(sid, is_public=False)
        m = viewer.mark()
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "renamed"})
        assert st == 200, b
        err = await viewer.wait(lambda e: e.get("type") == "error", m)
        assert err and err["message"] == "Channel not found", viewer.events[m:]
        # a public stream keeps its room
        cid2 = await d.create_chat_channel("pub2", created_by=ids["owner"])
        s2 = await d.create_user_stream(ids["owner"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                        is_public=True)
        await d.update_user_stream(s2, chat_channel_id=cid2)
        v2 = await env.sock(ids["viewer"])
        await v2.join(cid2)
        m = v2.mark()
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{s2}", json={"name": "renamed2"})
        assert st == 200, b
        await asyncio.sleep(0.4)
        assert "error" not in v2.types(m), v2.events[m:]
    run(body)


def test_the_channel_lost_frames_name_their_channel_and_the_page_acts_only_on_its_own():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        viewer = await env.sock(ids["viewer"])
        await viewer.join(cid)
        m = viewer.mark()
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": False})
        assert st == 200, b
        err = await viewer.wait(lambda e: e.get("type") == "error", m)
        assert err and err["message"] == "Channel not found" and err.get("channel") == "strm", err
        # a refused join names the channel too
        m = viewer.mark()
        await viewer.send(type="join", channel_id=cid)
        err = await viewer.wait(lambda e: e.get("type") in ("history", "error"), m)
        assert err["type"] == "error" and err.get("channel") == "strm", err
        m = viewer.mark()
        await viewer.send(type="join", channel="nosuchchannel")
        err = await viewer.wait(lambda e: e.get("type") in ("history", "error"), m)
        assert err["type"] == "error" and err.get("channel") == "nosuchchannel", err
    run(body)
    page = (ROOT / "static" / "chat.html").read_text()
    # the error handler compares the frame's channel with the open one
    assert "data.channel === currentChannel" in page
    assert "pendingJoin === currentChannel" in page
    # a direct message opening clears the unavailable state
    handler = page[page.index("case 'dm_conversation_opened':"):]
    handler = handler[:handler.index("break;")]
    assert "resetChannelUnavailable()" in handler, handler


def test_a_mention_notifies_only_members_who_can_read_the_channel():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=False)
        sent = []

        async def fake_notify(user_id, type, title, message=None, data=None):
            sent.append(user_id)
        saved = server.send_notification
        server.send_notification = fake_notify
        try:
            owner = await env.sock(ids["owner"])
            await owner.join(cid)
            await owner.send(type="message", message="hello @viewer, @boss!")
            await owner.wait(lambda e: e.get("type") == "message")
            await asyncio.sleep(0.5)
        finally:
            server.send_notification = saved
        assert ids["viewer"] not in sent, "a member who cannot read the chat is not notified"
        assert ids["boss"] in sent, sent
    run(body)


def test_typing_frames_are_throttled_per_socket():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await channel_id(d, "general")
        a, b = await env.sock(ids["carol"]), await env.sock(ids["bob"])
        await a.join(cid)
        await b.join(cid)
        calls = []
        real = d.get_chat_channel_by_name

        async def counting(name):
            calls.append(name)
            return await real(name)
        d.get_chat_channel_by_name = counting
        try:
            m = b.mark()
            for _ in range(6):
                await a.send(type="typing")
            await asyncio.sleep(0.5)
            assert len(calls) == 1, calls
            assert [e.get("type") for e in b.events[m:]].count("typing") == 1, b.events[m:]
            await asyncio.sleep(1.1)
            m = b.mark()
            await a.send(type="typing")
            assert await b.wait(lambda e: e.get("type") == "typing", m), "later frame passes"
        finally:
            d.get_chat_channel_by_name = real
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
