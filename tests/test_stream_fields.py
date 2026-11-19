"""Stream settings update takes only the client-editable fields, a stream's chat
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
        assert server._stream_chat_hidden(stream, ids["viewer"], "user") is False
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
