"""Access lost while a chat socket is joined: every per-socket action asks again,
and a socket that can no longer read its room is put out of it.

Runs the real chat websocket handler and the real HTTP handlers in-process
(only the authentication lookup is replaced) against a temporary database.

* A member removed from a private channel (the database row is deleted, nothing
  else happens) cannot edit, delete, pin, unpin, time out, mute, close a poll, send
  a typing signal or join the voice room on the socket that was already open.
* Stream made not public, member removed from a private channel, ban (message and
  route), channel made private: the sockets that lost access receive one
  "Channel not found" error and nothing more from the room (messages, edits,
  reactions, typing), and their voice entry in the room ends.
* GET /api/chat/channels leaves out the chat of a stream that is not public.

Run: venv/bin/python tests/test_chat_access_loss.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import server  # noqa: E402
from database import Database  # noqa: E402


class Tok:
    def __init__(self, user_id):
        self.user_id = user_id
        self.token_id = "t%d" % user_id
        self.scopes = ["*"]

    def has_scope(self, scope):
        return False


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    return Tok(int(uid)) if uid else None


async def fake_valid(token):
    return True


class Sock:
    """A chat socket with a background reader that keeps every frame."""

    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    self.events.append(json.loads(msg.data))
        except Exception:
            pass

    def mark(self):
        return len(self.events)

    async def send(self, **payload):
        await self.ws.send_json(payload)

    async def wait(self, pred, start=0, timeout=5.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.02)
        return None

    async def join(self, channel_id):
        start = self.mark()
        await self.send(type="join", channel_id=channel_id)
        got = await self.wait(lambda e: e.get("type") in ("history", "error"), start)
        assert got and got["type"] == "history", got
        await self.wait(lambda e: e.get("type") == "users", start)

    def types(self, start=0):
        return [e.get("type") for e in self.events[start:]]

    async def close(self):
        await self.ws.close()
        self.task.cancel()


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}
        self.socks = []

    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth),
                            ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.voice_state.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/api/chat/channels", server.http_get_chat_channels)
        app.router.add_put("/api/chat/channels/{id}", server.http_update_chat_channel)
        app.router.add_delete("/api/chat/channels/{id}/members/{user_id}", server.http_remove_channel_member)
        app.router.add_post("/api/streams", server.http_create_user_stream)
        app.router.add_put("/api/streams/{id}", server.http_update_user_stream)
        app.router.add_delete("/api/streams/{id}", server.http_delete_user_stream)
        app.router.add_post("/api/streams/{id}/bans", server.http_create_stream_ban)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        for s in self.socks:
            try:
                await s.close()
            except Exception:
                pass
        await self.http.close()
        await self.srv.close()
        for name, value in self.saved.items():
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.voice_state.clear()
        await self.db.close()
        self.tmp.cleanup()

    def url(self, path):
        return str(self.srv.make_url(path))

    async def sock(self, user_id):
        ws = await self.http.ws_connect(self.url("/ws/chat"), headers={"X-Test-User": str(user_id)})
        s = Sock(ws)
        self.socks.append(s)
        return s

    async def call(self, method, user_id, path, **kw):
        async with self.http.request(method, self.url(path), headers={"X-Test-User": str(user_id)}, **kw) as r:
            return r.status, await r.json()


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


async def users(d):
    ids = {}
    for name in ("boss", "alice", "bob", "carol", "owner", "viewer"):
        ids[name] = await d.create_user(name, "x")
    await d.set_user_role(ids["boss"], "admin")
    await d.set_user_role(ids["alice"], "moderator")   # a moderator reads a private channel only as a member
    return ids


async def private_channel(d, ids, members=("alice", "bob")):
    cid = await d.create_chat_channel("pvt", created_by=ids["boss"])
    await d.update_chat_channel(cid, visibility="private")
    for name in members:
        await d.add_channel_member(cid, ids[name], role="member", added_by=ids["boss"])
    return cid


async def stream_chat(d, ids, public=True):
    cid = await d.create_chat_channel("strm", created_by=ids["owner"])
    sid = await d.create_user_stream(ids["owner"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                     is_public=public)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
    await d.conn.commit()
    return cid, sid


async def room_activity(poster, target_msg):
    """What the others do in the room: a message, an edit, a reaction, typing."""
    await poster.send(type="message", message="after the loss")
    await poster.wait(lambda e: e.get("type") == "message" and e.get("message") == "after the loss")
    await poster.send(type="edit_message", message_id=target_msg, message="edited by the owner")
    await poster.send(type="react", message_id=target_msg, emoji="+1")
    await poster.send(type="typing")
    await asyncio.sleep(0.4)


# ---------------------------------------------------------------------------
# item 1: every per-socket action asks again

def test_a_member_removed_from_a_private_channel_cannot_act_on_the_open_socket():
    """Each action is judged on its own (a list of the ones that went through is
    asserted at the end), so one gap does not hide another."""
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await private_channel(d, ids)
        mine = await d.create_chat_message(cid, ids["alice"], "alice", "my old message")
        theirs = await d.create_chat_message(cid, ids["bob"], "bob", "bobs message")
        pid = await d.create_poll(cid, ids["alice"], "q", ["a", "b"])
        alice, bob = await env.sock(ids["alice"]), await env.sock(ids["bob"])
        await alice.join(cid)
        await bob.join(cid)
        # removed from the channel; the row is gone, nothing else happens (no eviction)
        await d.remove_channel_member(cid, ids["alice"])
        assert not await d.is_channel_member(cid, ids["alice"])
        went_through = []
        mark_a = alice.mark()

        await alice.send(type="edit_message", message_id=mine, message="rewritten after removal")
        err = await alice.wait(lambda e: e.get("type") == "error", mark_a)
        await asyncio.sleep(0.2)
        if (await d.get_chat_message(mine))["message"] != "my old message":
            went_through.append("edit_message")
        if not (err and err["message"] == "This channel is private" and "edit_rejected" in alice.types(mark_a)):
            went_through.append("edit_message answer: %r" % (alice.events[mark_a:],))

        await alice.send(type="delete", message_id=mine)
        await asyncio.sleep(0.3)
        if not await d.get_chat_message(mine):
            went_through.append("delete")
        await alice.send(type="pin_message", message_id=theirs)
        await asyncio.sleep(0.3)
        if await d.get_pinned_messages(cid):
            went_through.append("pin_message")
        await alice.send(type="unpin_message", message_id=theirs)
        await alice.send(type="timeout_user", target_user_id=ids["carol"], duration=60)
        await asyncio.sleep(0.3)
        if await d.is_user_timed_out(ids["carol"], cid):
            went_through.append("timeout_user")
        await d.remove_chat_timeout(ids["carol"], cid)
        await alice.send(type="mute_user", target_user_id=ids["carol"])
        await asyncio.sleep(0.3)
        if await d.is_user_timed_out(ids["carol"], cid):
            went_through.append("mute_user")
        await alice.send(type="unmute_user", target_user_id=ids["carol"])
        await alice.send(type="close_poll", poll_id=pid)
        await asyncio.sleep(0.3)
        if (await d.get_poll(pid))["is_closed"]:
            went_through.append("close_poll")
        await alice.send(type="typing")
        await alice.send(type="voice_join")
        await asyncio.sleep(0.5)
        if "voice_state" in alice.types(mark_a) or "pvt" in server.voice_state:
            went_through.append("voice_join")
        if "voice_denied" not in alice.types(mark_a):
            went_through.append("voice_join answer (the client waits for voice_denied): %r" % (alice.types(mark_a),))
        # what reached the room: bob saw none of it
        seen = [t for t in bob.types() if t in ("typing", "message_deleted", "message_pinned", "message_unpinned",
                                                "user_timed_out", "user_muted", "user_unmuted", "poll_closed",
                                                "message_edited")]
        assert not went_through and not seen, (went_through, seen)
    run(body)


class _FakeVoiceWs:
    closed = False

    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)


def test_voice_resume_and_the_voice_room_check_use_the_read_rule():
    """The voice room check is the channel read check: a stream chat closed to the
    member (not public, not the owner or an admin) is refused there too, so a
    held call cannot be resumed after the stream was made private."""
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        assert await server._voice_room_allowed("strm", ids["viewer"], "user")
        await d.update_user_stream(sid, is_public=False)
        assert not await server._voice_room_allowed("strm", ids["viewer"], "user")
        assert not await server._voice_room_allowed("strm", ids["alice"], "moderator")
        assert await server._voice_room_allowed("strm", ids["owner"], "user")
        assert await server._voice_room_allowed("strm", ids["boss"], "admin")
        assert not await server._voice_room_allowed("nosuchroom", ids["boss"], "admin")
        # a held call (the socket was lost) is not resumed once the chat is closed to the member
        old, new = _FakeVoiceWs(), _FakeVoiceWs()
        server.voice_state["strm"] = {ids["viewer"]: {
            "ws": old, "username": "viewer", "muted": False, "deafened": False, "speaking": False,
            "screen_sharing": False, "reconnecting": True, "resume_token": "tok", "token_id": "t1"}}
        state = {"anonymous": False, "nickname": None, "avatar": {}}
        room = await server._voice_resume(new, ids["viewer"], "user", "t2", state,
                                          {"resume": True, "resume_token": "tok", "room": "strm"})
        assert room is None and [m["type"] for m in new.sent] == ["voice_resume_failed"], new.sent
        assert ids["viewer"] not in server.voice_state.get("strm", {}), "the held call was kept"
    run(body)


def test_a_banned_member_cannot_edit_on_the_open_socket():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        mine = await d.create_chat_message(cid, ids["bob"], "bob", "old words")
        bob = await env.sock(ids["bob"])
        await bob.join(cid)
        assert await d.create_stream_ban(sid, ids["bob"], ids["owner"], "r")   # row only: no eviction
        m = bob.mark()
        await bob.send(type="edit_message", message_id=mine, message="new words")
        err = await bob.wait(lambda e: e.get("type") == "error", m)
        assert err and "banned" in err["message"], bob.events[m:]
        assert (await d.get_chat_message(mine))["message"] == "old words"
    run(body)


# ---------------------------------------------------------------------------
# item 2: a socket that lost access is put out of the room

async def assert_put_out(loser, others, name, target_msg, start):
    """One error frame with the answer for a missing channel, then silence, however
    active the room is; and the socket holds no voice entry there."""
    err = await loser.wait(lambda e: e.get("type") == "error", start)
    assert err and err["message"] == "Channel not found", loser.events[start:]
    for who in others:
        await room_activity(who, target_msg)
    # the one error frame; a member in the voice call also gets the usual voice_denied
    assert [e for e in loser.events[start:] if e.get("type") not in ("error", "voice_denied")] == [], loser.events[start:]
    assert len([e for e in loser.events[start:] if e.get("type") == "error"]) == 1, loser.events[start:]
    assert loser.ws.closed is False, "the socket stays open (only the room is lost)"
    assert not any(entry[1] == getattr(loser, "uid", None) for entry in server.chat_rooms.get(name, ()))


def test_removing_a_member_from_a_private_channel_puts_the_socket_out():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await private_channel(d, ids)
        target = await d.create_chat_message(cid, ids["bob"], "bob", "bobs message")
        alice, bob = await env.sock(ids["alice"]), await env.sock(ids["bob"])
        alice.uid = ids["alice"]
        await alice.join(cid)
        await bob.join(cid)
        await alice.send(type="voice_join")
        assert await alice.wait(lambda e: e.get("type") == "voice_state")
        assert ids["alice"] in server.voice_state.get("pvt", {})
        m = alice.mark()
        st, body_ = await env.call("DELETE", ids["boss"], f"/api/chat/channels/{cid}/members/{ids['alice']}")
        assert st == 200, body_
        await assert_put_out(alice, [bob], "pvt", target, m)
        assert ids["alice"] not in server.voice_state.get("pvt", {}), "voice entry kept"
        # the socket has no channel any more: a send goes nowhere
        before = len((await (await d.conn.execute("SELECT id FROM chat_messages WHERE channel_id = ?", (cid,))).fetchall()))
        await alice.send(type="message", message="still here?")
        await asyncio.sleep(0.3)
        after = len((await (await d.conn.execute("SELECT id FROM chat_messages WHERE channel_id = ?", (cid,))).fetchall()))
        assert before == after, "a message from the evicted socket was stored"
        # bob is told who left
        assert any(e.get("type") == "user_left" for e in bob.events)
    run(body)


def test_a_member_leaving_a_private_channel_puts_their_socket_out():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await private_channel(d, ids)
        target = await d.create_chat_message(cid, ids["bob"], "bob", "bobs message")
        alice, bob = await env.sock(ids["alice"]), await env.sock(ids["bob"])
        alice.uid = ids["alice"]
        await alice.join(cid)
        await bob.join(cid)
        m = alice.mark()
        st, _ = await env.call("DELETE", ids["alice"], f"/api/chat/channels/{cid}/members/{ids['alice']}")
        assert st == 200
        await assert_put_out(alice, [bob], "pvt", target, m)
    run(body)


def test_making_the_stream_private_puts_other_members_out_and_keeps_the_owner():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        target = await d.create_chat_message(cid, ids["owner"], "owner", "owner words")
        viewer, owner = await env.sock(ids["viewer"]), await env.sock(ids["owner"])
        boss = await env.sock(ids["boss"])
        viewer.uid = ids["viewer"]
        for s in (viewer, owner, boss):
            await s.join(cid)
        await viewer.send(type="voice_join")
        assert await viewer.wait(lambda e: e.get("type") == "voice_state")
        m, mo, mb = viewer.mark(), owner.mark(), boss.mark()
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": False})
        assert st == 200, b
        await assert_put_out(viewer, [owner], "strm", target, m)
        assert ids["viewer"] not in server.voice_state.get("strm", {}), "voice entry kept"
        # owner and admin stay: they got the activity
        assert "message" in boss.types(mb) and "message_edited" in boss.types(mb), boss.types(mb)
        assert not any(e.get("type") == "error" for e in owner.events[mo:] + boss.events[mb:])
    run(body)


def test_a_ban_puts_the_socket_out_by_route_and_by_message():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        target = await d.create_chat_message(cid, ids["owner"], "owner", "owner words")
        owner = await env.sock(ids["owner"])
        carol, bob = await env.sock(ids["carol"]), await env.sock(ids["bob"])
        carol.uid, bob.uid = ids["carol"], ids["bob"]
        for s in (owner, carol, bob):
            await s.join(cid)
        # by route
        m = carol.mark()
        st, b = await env.call("POST", ids["owner"], f"/api/streams/{sid}/bans", json={"user_id": ids["carol"]})
        assert st in (200, 201), b
        await assert_put_out(carol, [owner], "strm", target, m)
        # by the owner's ban message on the socket
        m = bob.mark()
        await owner.send(type="ban", user_id=ids["bob"])
        assert await owner.wait(lambda e: e.get("type") == "ban_success")
        await assert_put_out(bob, [owner], "strm", target, m)
    run(body)


def test_making_a_channel_private_puts_out_the_sockets_of_non_members():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await d.create_chat_channel("opened", created_by=ids["boss"])
        await d.add_channel_member(cid, ids["bob"], role="member", added_by=ids["boss"])
        target = await d.create_chat_message(cid, ids["bob"], "bob", "bobs message")
        carol, bob = await env.sock(ids["carol"]), await env.sock(ids["bob"])
        carol.uid = ids["carol"]
        await carol.join(cid)
        await bob.join(cid)
        m = carol.mark()
        st, b = await env.call("PUT", ids["boss"], f"/api/chat/channels/{cid}", json={"visibility": "private"})
        assert st == 200, b
        await assert_put_out(carol, [bob], "opened", target, m)
    run(body)


def test_a_socket_that_may_still_read_is_left_alone():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid = await private_channel(d, ids)
        alice, bob = await env.sock(ids["alice"]), await env.sock(ids["bob"])
        await alice.join(cid)
        await bob.join(cid)
        m = bob.mark()
        st, _ = await env.call("DELETE", ids["boss"], f"/api/chat/channels/{cid}/members/{ids['alice']}")
        assert st == 200
        await asyncio.sleep(0.3)
        assert not any(e.get("type") == "error" for e in bob.events[m:]), bob.events[m:]
        await alice.wait(lambda e: e.get("type") == "error")
        await bob.send(type="message", message="still works")
        assert await bob.wait(lambda e: e.get("type") == "message" and e.get("message") == "still works", m)
        # and a public channel's member removal evicts nobody
        gid = await d.create_chat_channel("open2", created_by=ids["boss"])
        carol = await env.sock(ids["carol"])
        await carol.join(gid)
        m = carol.mark()
        await env.call("DELETE", ids["boss"], f"/api/chat/channels/{gid}/members/{ids['carol']}")
        await asyncio.sleep(0.3)
        assert not any(e.get("type") == "error" for e in carol.events[m:])
    run(body)


# ---------------------------------------------------------------------------
# item 3: the channel list

def test_channel_list_leaves_out_the_chat_of_a_stream_that_is_not_public():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=False)
        names = lambda b: {c["name"] for c in b["channels"]}       # noqa: E731
        for who, want in (("viewer", False), ("carol", False), ("alice", False),     # a moderator is not an admin
                          ("owner", True), ("boss", True)):
            st, b = await env.call("GET", ids[who], "/api/chat/channels")
            assert st == 200
            assert ("strm" in names(b)) is want, (who, names(b))
            if not want:
                assert not any(c.get("stream_id") == sid or c.get("stream_owner") for c in b["channels"]), b
        await d.update_user_stream(sid, is_public=True)
        st, b = await env.call("GET", ids["viewer"], "/api/chat/channels")
        assert "strm" in names(b) and any(c.get("stream_id") == sid for c in b["channels"])
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
