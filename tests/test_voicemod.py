"""Voice moderation and the enforced room cap (1.20.0).

Runs the real chat websocket handler and the real admin handlers in-process (only the
authentication lookup is replaced) against a temporary database.

* voice_join refuses a timed-out or muted member (a moderator is exempt), a full room, a
  locked room (a moderator is admitted) and a rejoin inside the 60 s block after a kick.
  A refusal is one voice_denied frame with a code to the joiner and nothing to the room.
  A resume at the cap still works. A DM room has the cap only.
* voice_kick, voice_server_mute / _unmute, voice_lock_room / _unlock_room: role checks
  through chat_mod_level, one audit entry each, no action on oneself or on an equal or
  higher level, nothing in a DM call.
* A kicked member can no longer relay signalling; a timeout or mute removes the member
  from the voice room of that channel.
* The cap setting: cached, invalidated on write, validated, superadmin only.

Run: venv/bin/python tests/test_voicemod.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

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
        return True


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    return Tok(int(uid)) if uid else None


async def fake_valid(token):
    return True


class Sock:
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

    def since(self, start):
        """Voice and error frames after `start`: text-channel traffic (a member who joins the
        channel, the user list) is not what is being measured."""
        return [e for e in self.events[start:]
                if str(e.get("type")).startswith(("voice_", "screen_share_")) or e.get("type") == "error"]

    async def send(self, **payload):
        await self.ws.send_json(payload)

    async def wait(self, pred, start=0, timeout=3.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.02)
        return None

    async def settle(self, t=0.25):
        await asyncio.sleep(t)

    async def close(self):
        await self.ws.close()
        self.task.cancel()


def typ(name):
    return lambda e: e.get("type") == name


class Env:
    async def __aenter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}
        self.socks = []
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth),
                            ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        self.saved_block = server.VOICE_KICK_BLOCK
        server.chat_rooms.clear()
        server.voice_state.clear()
        server._voice_locked.clear()
        server._voice_kick_blocks.clear()
        server._voice_penalty_denies.clear()
        server.voice_cap_invalidate()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/api/admin/voice", server.http_get_voice_settings)
        app.router.add_put("/api/admin/voice", server.http_put_voice_settings)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        self.u = {}
        d = self.db
        for name in ("alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank", "ivy", "jack", "kim",
                     "admin", "admin2", "super", "gmod", "owner", "smod"):
            self.u[name] = await d.create_user(name, "x")
        for name, role in (("admin", "admin"), ("admin2", "admin"), ("super", "superadmin"),
                           ("gmod", "moderator")):
            await d.set_user_role(self.u[name], role)
        # a stream chat with an owner and a stream mod
        cid = await d.create_chat_channel("chat-s", created_by=self.u["owner"])
        sid = await d.create_user_stream(self.u["owner"], "s", "live_" + "a" * 24,
                                         public_key="pub_" + "a" * 24, is_public=True)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
        await d.conn.commit()
        await d.add_channel_member(cid, self.u["smod"], role="moderator", added_by=self.u["owner"])
        self.stream_chat = cid
        self.general = (await d.get_chat_channel_by_name("general"))["id"]
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
        server.VOICE_KICK_BLOCK = self.saved_block
        server.chat_rooms.clear()
        server.voice_state.clear()
        server._voice_locked.clear()
        server._voice_kick_blocks.clear()
        server._voice_penalty_denies.clear()
        server.voice_cap_invalidate()
        await self.db.close()
        self.tmp.cleanup()

    def url(self, path):
        return str(self.srv.make_url(path))

    async def sock(self, name, channel="general"):
        ws = await self.http.ws_connect(self.url("/ws/chat"), headers={"X-Test-User": str(self.u[name])})
        s = Sock(ws)
        self.socks.append(s)
        s.name = name
        s.uid = self.u[name]
        start = s.mark()
        cid = self.general if channel == "general" else self.stream_chat
        await s.send(type="join", channel_id=cid)
        got = await s.wait(lambda e: e.get("type") in ("history", "error"), start)
        assert got and got["type"] == "history", got
        await s.wait(typ("users"), start)
        return s

    async def voice(self, name, channel="general", expect="voice_state", **extra):
        """Open a socket for `name`, join its channel and ask for voice."""
        s = await self.sock(name, channel)
        start = s.mark()
        await s.send(type="voice_join", **extra)
        got = await s.wait(lambda e: e.get("type") in ("voice_state", "voice_denied", "error"), start)
        assert got is not None, ("no answer", name)
        assert got["type"] == expect, (name, got)
        s.last = got
        return s

    async def call(self, method, name, path, **kw):
        async with self.http.request(method, self.url(path), headers={"X-Test-User": str(self.u[name])}, **kw) as r:
            try:
                return r.status, await r.json()
            except Exception:
                return r.status, None

    async def audit(self, action):
        rows = await self.db.get_audit_log(limit=200)
        return [r for r in rows if r.get("action") == action]


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


PLAIN = ("alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank")


def test_timed_out_and_muted_cannot_join_and_a_moderator_can():
    async def body(env):
        d = env.db
        peer = await env.voice("alice")
        for name, kind in (("bob", "timeout"), ("carol", "mute")):
            await d.create_chat_timeout(env.u[name], env.u["admin"], kind, env.general, "r", 600 if kind == "timeout" else None)
        mark = peer.mark()
        for name in ("bob", "carol"):
            s = await env.voice(name, expect="voice_denied")
            assert s.last["code"] == "timed_out" and "cannot join" in s.last["message"], s.last
            assert env.u[name] not in server.voice_state.get("general", {})
        await peer.settle()
        assert peer.since(mark) == [], peer.since(mark)    # nothing to the room
        # a timeout in another channel does not matter, an expired one neither
        await d.create_chat_timeout(env.u["dave"], env.u["admin"], "timeout", env.stream_chat, "r", 600)
        await env.voice("dave")
        # staff with a penalty row are exempt
        await d.create_chat_timeout(env.u["gmod"], env.u["super"], "timeout", env.general, "r", 600)
        await env.voice("gmod")
        # a stream mod is exempt in the stream chat
        await d.create_chat_timeout(env.u["smod"], env.u["owner"], "timeout", env.stream_chat, "r", 600)
        await env.voice("smod", channel="stream")
    run(body)


def test_the_ninth_joiner_is_refused_and_a_resume_at_the_cap_works():
    async def body(env):
        socks = []
        for name in PLAIN:
            socks.append(await env.voice(name))
        assert len(server.voice_state["general"]) == 8
        mark = socks[0].mark()
        late = await env.voice("ivy", expect="voice_denied")
        assert late.last["code"] == "room_full" and "full" in late.last["message"], late.last
        await socks[0].settle()
        assert socks[0].since(mark) == [], socks[0].since(mark)
        # a resume of a member already counted is never refused for the cap: first socket drops,
        # the new one resumes with the token while the room is full
        victim = socks[1]
        token = victim.last["resume_token"]
        await victim.ws.close()
        await asyncio.sleep(0.2)
        assert env.u["bob"] in server.voice_state["general"]
        again = await env.sock("bob")
        start = again.mark()
        await again.send(type="voice_join", resume=True, room="general", resume_token=token)
        got = await again.wait(lambda e: e.get("type") in ("voice_state", "voice_resume_failed", "voice_denied"), start)
        assert got and got["type"] == "voice_state" and got.get("resumed") is True, got
        assert len(server.voice_state["general"]) == 8
        # leaving makes room for the ninth
        await socks[2].send(type="voice_leave")
        await socks[2].settle()
        await env.voice("ivy")
    run(body)


def test_the_cap_setting_is_cached_validated_and_superadmin_only():
    async def body(env):
        assert await server.voice_room_cap() == 8
        # cached: a direct database change is not seen until the setting is invalidated
        await env.db.set_setting("voice_room_cap", "3")
        assert await server.voice_room_cap() == 8
        server.voice_cap_invalidate()
        assert await server.voice_room_cap() == 3
        # an unusable stored value is the default
        for raw in ("1", "26", "abc", ""):
            await env.db.set_setting("voice_room_cap", raw)
            server.voice_cap_invalidate()
            assert await server.voice_room_cap() == 8, raw
        status, view = await env.call("GET", "admin", "/api/admin/voice")
        assert status == 200 and view["voice_room_cap"] == 8 and (view["min"], view["max"]) == (2, 25), (status, view)
        # an admin may read and not write
        status, _ = await env.call("PUT", "admin", "/api/admin/voice", json={"voice_room_cap": 4})
        assert status == 403, status
        for bad in (1, 26, "5", True, None, 2.5):
            status, _ = await env.call("PUT", "super", "/api/admin/voice", json={"voice_room_cap": bad})
            assert status == 400, (bad, status)
        status, _ = await env.call("PUT", "super", "/api/admin/voice", json={"voice_room_cap": 4, "x": 1})
        assert status == 400
        status, view = await env.call("PUT", "super", "/api/admin/voice", json={"voice_room_cap": 2})
        assert status == 200 and view["voice_room_cap"] == 2, (status, view)
        assert await env.db.get_setting("voice_room_cap") == "2"
        assert await server.voice_room_cap() == 2               # the write invalidated the copy
        assert len(await env.audit("voice.room_cap")) == 1
        await env.voice("alice")
        await env.voice("bob")
        await env.voice("carol", expect="voice_denied")
    run(body)


def test_kick():
    async def body(env):
        server.VOICE_KICK_BLOCK = 0.6
        adm = await env.voice("admin")
        bob = await env.voice("bob")
        carol = await env.voice("carol")
        mark_c = carol.mark()
        mark_b = bob.mark()
        # a plain member cannot kick, nobody kicks themselves
        await carol.send(type="voice_kick", target_user_id=env.u["bob"])
        got = await carol.wait(typ("error"), mark_c)
        assert got and "Moderator" in got["message"], got
        await adm.send(type="voice_kick", target_user_id=env.u["admin"])
        got = await adm.wait(typ("error"), 0)
        assert got is not None
        await carol.settle()
        assert env.u["bob"] in server.voice_state["general"] and env.u["admin"] in server.voice_state["general"]
        # a moderator-role member cannot kick an admin, an admin cannot kick another admin
        gm = await env.voice("gmod")
        adm2 = await env.voice("admin2")
        mark = gm.mark()
        await gm.send(type="voice_kick", target_user_id=env.u["admin"])
        assert await gm.wait(typ("error"), mark)
        mark = adm2.mark()
        await adm2.send(type="voice_kick", target_user_id=env.u["admin"])
        assert await adm2.wait(typ("error"), mark)
        assert env.u["admin"] in server.voice_state["general"]
        assert await env.audit("voice_kick") == []
        # the real kick
        mark_a = adm.mark()
        mark_c = carol.mark()
        await adm.send(type="voice_kick", target_user_id=env.u["bob"])
        denied = await bob.wait(typ("voice_denied"), mark_b)
        assert denied and denied["code"] == "kicked" and "removed" in denied["message"], denied
        left = await carol.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == env.u["bob"], mark_c)
        assert left, carol.since(mark_c)
        assert env.u["bob"] not in server.voice_state["general"]
        rows = await env.audit("voice_kick")
        assert len(rows) == 1 and rows[0]["target_id"] == env.u["bob"] and rows[0]["actor_id"] == env.u["admin"], rows
        # the target can no longer relay signalling (still holds a socket and its old room)
        mark_c = carol.mark()
        await bob.send(type="voice_signal", target_user_id=env.u["carol"], signal={"type": "offer", "sdp": "x"})
        await bob.send(type="voice_mute", muted=True)
        await carol.settle()
        assert carol.since(mark_c) == [], carol.since(mark_c)
        # and cannot come back inside the block
        mark = bob.mark()
        await bob.send(type="voice_join")
        got = await bob.wait(typ("voice_denied"), mark)
        assert got and got["code"] == "kicked", got
        await asyncio.sleep(0.7)
        mark = bob.mark()
        await bob.send(type="voice_join")
        got = await bob.wait(typ("voice_state"), mark)
        assert got, bob.since(mark)
    run(body)


def test_stream_owner_and_stream_mod_levels():
    async def body(env):
        owner = await env.voice("owner", channel="stream")
        smod = await env.voice("smod", channel="stream")
        alice = await env.voice("alice", channel="stream")
        # a stream mod kicks an ordinary viewer, not the owner
        mark = smod.mark()
        await smod.send(type="voice_kick", target_user_id=env.u["owner"])
        assert await smod.wait(typ("error"), mark)
        await smod.send(type="voice_kick", target_user_id=env.u["alice"])
        assert await alice.wait(typ("voice_denied"), 0)
        # the owner may server-mute the stream mod
        mark = smod.mark()
        await owner.send(type="voice_server_mute", target_user_id=env.u["smod"])
        got = await smod.wait(typ("voice_server_mute_changed"), mark)
        assert got and got["server_muted"] is True and got["user_id"] == env.u["smod"], got
        # the mod cannot undo it for itself
        mark = smod.mark()
        await smod.send(type="voice_server_unmute", target_user_id=env.u["smod"])
        assert await smod.wait(typ("error"), mark)
        assert server.voice_state["chat-s"][env.u["smod"]]["server_muted"] is True
    run(body)


def test_server_mute_is_shown_to_everyone_and_ends_when_the_member_leaves():
    async def body(env):
        adm = await env.voice("admin")
        bob = await env.voice("bob")
        carol = await env.voice("carol")
        marks = (adm.mark(), bob.mark(), carol.mark())
        await adm.send(type="voice_server_mute", target_user_id=env.u["bob"])
        for s, m in zip((adm, bob, carol), marks):
            got = await s.wait(typ("voice_server_mute_changed"), m)
            assert got and got["server_muted"] is True and got["user_id"] == env.u["bob"], (s.name, got)
        assert len(await env.audit("voice_server_mute")) == 1
        # a repeat changes nothing and adds no audit entry
        await adm.send(type="voice_server_mute", target_user_id=env.u["bob"])
        await adm.settle()
        assert len(await env.audit("voice_server_mute")) == 1
        # a newcomer sees the mark in the state
        dave = await env.voice("dave")
        marked = {u["user_id"]: u["server_muted"] for u in dave.last["users"]}
        assert marked[env.u["bob"]] is True and marked[env.u["carol"]] is False, marked
        # the member cannot unmute for the others through voice_mute
        mark = carol.mark()
        await bob.send(type="voice_mute", muted=False)
        got = await carol.wait(typ("voice_mute_changed"), mark)
        assert got and got["muted"] is True, got
        # unmute
        mark = carol.mark()
        await adm.send(type="voice_server_unmute", target_user_id=env.u["bob"])
        got = await carol.wait(typ("voice_server_mute_changed"), mark)
        assert got and got["server_muted"] is False
        assert len(await env.audit("voice_server_unmute")) == 1
        # leaving clears it
        await adm.send(type="voice_server_mute", target_user_id=env.u["carol"])
        await adm.settle()
        await carol.send(type="voice_leave")
        await adm.settle()
        again = await env.voice("carol")
        assert all(u["server_muted"] is False for u in again.last["users"] if u["user_id"] == env.u["carol"])
        # a plain member cannot
        mark = bob.mark()
        await bob.send(type="voice_server_mute", target_user_id=env.u["dave"])
        assert await bob.wait(typ("error"), mark)
    run(body)


def test_a_locked_room_refuses_members_and_admits_moderators():
    async def body(env):
        adm = await env.voice("admin")
        bob = await env.voice("bob")
        assert adm.last["can_moderate"] is True and bob.last["can_moderate"] is False
        marks = (adm.mark(), bob.mark())
        await bob.send(type="voice_lock_room")
        assert await bob.wait(typ("error"), marks[1])
        assert "general" not in server._voice_locked
        await adm.send(type="voice_lock_room")
        for s, m in zip((adm, bob), marks):
            got = await s.wait(typ("voice_room_lock_changed"), m)
            assert got and got["locked"] is True, got
        assert len(await env.audit("voice_lock")) == 1
        mark = adm.mark()
        carol = await env.voice("carol", expect="voice_denied")
        assert carol.last["code"] == "locked" and "locked" in carol.last["message"], carol.last
        await adm.settle()
        assert adm.since(mark) == [], adm.since(mark)
        gm = await env.voice("gmod")                       # a moderator is admitted
        assert gm.last["locked"] is True and gm.last["can_moderate"] is True
        await adm.send(type="voice_unlock_room")
        await adm.settle()
        assert len(await env.audit("voice_unlock")) == 1
        await env.voice("carol")
        # a lock does not outlive the room
        await adm.send(type="voice_lock_room")
        await adm.settle()
        assert "general" in server._voice_locked
        for name in ("admin", "bob", "gmod", "carol"):
            pass
        for uid in list(server.voice_state["general"]):
            await server._voice_remove("general", uid)
        assert "general" not in server._voice_locked
    run(body)


def test_signalling_is_dropped_unless_both_are_in_the_room():
    async def body(env):
        alice = await env.voice("alice")
        bob = await env.voice("bob")
        outsider = await env.sock("carol")                  # in the text channel, not in voice
        mark_a, mark_b = alice.mark(), bob.mark()
        offer = {"type": "offer", "sdp": "x"}
        await alice.send(type="voice_signal", target_user_id=env.u["bob"], signal=offer)
        got = await bob.wait(typ("voice_signal"), mark_b)
        assert got and got["from_user_id"] == env.u["alice"], got
        mark_b = bob.mark()
        # the sender is not in the room
        await outsider.send(type="voice_signal", target_user_id=env.u["bob"], signal=offer)
        # the target is not in the room
        await alice.send(type="voice_signal", target_user_id=env.u["carol"], signal=offer)
        await bob.settle()
        assert all(e.get("type") != "voice_signal" for e in bob.since(mark_b)), bob.since(mark_b)
        assert all(e.get("type") != "voice_signal" for e in outsider.events)
        assert all(e.get("type") != "voice_signal" for e in alice.since(mark_a))
        # a member of another voice room cannot reach this one
        other = await env.voice("dave", channel="stream")
        await other.send(type="voice_signal", target_user_id=env.u["bob"], signal=offer)
        await alice.send(type="voice_signal", target_user_id=env.u["dave"], signal=offer)
        await bob.settle()
        assert all(e.get("type") != "voice_signal" for e in bob.since(mark_b))
        assert all(e.get("type") != "voice_signal" for e in other.events)
    run(body)


def test_a_timeout_or_mute_takes_the_member_out_of_the_channel_voice_room():
    async def body(env):
        adm = await env.voice("admin")
        bob = await env.voice("bob")
        carol = await env.voice("carol")
        dave = await env.voice("dave", channel="stream")      # another channel's room is not touched
        mark_c = carol.mark()
        await adm.send(type="timeout_user", target_user_id=env.u["bob"], duration=60)
        denied = await bob.wait(typ("voice_denied"), 0)
        assert denied and denied["code"] == "timed_out", denied
        left = await carol.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == env.u["bob"], mark_c)
        assert left
        assert env.u["bob"] not in server.voice_state["general"]
        mark = bob.mark()
        await bob.send(type="voice_join")
        got = await bob.wait(typ("voice_denied"), mark)
        assert got and got["code"] == "timed_out"
        await adm.send(type="mute_user", target_user_id=env.u["carol"])
        assert await carol.wait(typ("voice_denied"), mark_c)
        assert env.u["carol"] not in server.voice_state["general"]
        assert env.u["dave"] in server.voice_state["chat-s"]
    run(body)


def test_a_penalty_landing_inside_the_join_lookup_window_is_not_missed():
    """The join reads the penalty table, then awaits again before it inserts; a timeout or mute that
    commits (and runs its voice drop) after that read must still keep the member out."""
    async def body(env):
        d = env.db
        general = await d.get_chat_channel(env.general)
        real = d.is_user_timed_out
        victims = {}

        async def stale_lookup(user_id, channel_id=None):
            result = await real(user_id, channel_id)           # what the join saw: no penalty yet
            kind = victims.pop(user_id, None)
            if kind:
                await d.create_chat_timeout(user_id, env.u["admin"], kind, env.general, "r",
                                            600 if kind == "timeout" else None)
                await server._voice_drop_for_penalty(user_id, general)   # nobody in voice yet: nothing to drop
            return result

        d.is_user_timed_out = stale_lookup
        try:
            for name, kind in (("bob", "timeout"), ("carol", "mute")):
                victims[env.u[name]] = kind
                s = await env.voice(name, expect="voice_denied")
                assert s.last["code"] == "timed_out", s.last
                assert env.u[name] not in server.voice_state.get("general", {}), name
        finally:
            d.is_user_timed_out = real
        # the deny is short and never applies to a moderator or to another room
        server._voice_penalty_denies.clear()
        await server._voice_drop_for_penalty(env.u["dave"], general)
        assert server._voice_join_refusal("general", env.u["dave"], cap=8, is_mod=True, timed_out=None) is None
        assert server._voice_join_refusal("stream-x", env.u["dave"], cap=8, is_mod=False, timed_out=None) is None
        assert server._voice_join_refusal("general", env.u["dave"], cap=8, is_mod=False, timed_out=None)[0] == "timed_out"
        server._voice_penalty_denies[("general", env.u["dave"])] = server.monotonic() - 1
        assert server._voice_join_refusal("general", env.u["dave"], cap=8, is_mod=False, timed_out=None) is None
        assert ("general", env.u["dave"]) not in server._voice_penalty_denies
    run(body)


def test_a_direct_message_call_has_the_cap_and_no_moderation():
    async def body(env):
        conv = await env.db.create_dm_conversation(
            env.u["alice"], [env.u["bob"], env.u["carol"], env.u["dave"]], name="g", conv_type="group")
        room = "dm:%d" % conv["id"]
        socks = []
        await env.db.set_setting("voice_room_cap", "2")
        server.voice_cap_invalidate()
        for name in ("alice", "bob"):
            socks.append(await env.voice(name, room=room))
        # a timeout in the channel does not matter in a DM; the cap does
        await env.db.create_chat_timeout(env.u["carol"], env.u["admin"], "timeout", env.general, "r", 600)
        third = await env.voice("carol", room=room, expect="voice_denied")
        assert third.last["code"] == "room_full", third.last
        assert socks[0].last["can_moderate"] is False
        mark = socks[1].mark()
        await socks[0].send(type="voice_kick", target_user_id=env.u["bob"])
        got = await socks[0].wait(typ("error"), 0)
        assert got and "direct message" in got["message"], got
        await socks[0].send(type="voice_lock_room")
        await socks[0].send(type="voice_server_mute", target_user_id=env.u["bob"])
        await socks[1].settle()
        assert socks[1].since(mark) == [] and room not in server._voice_locked
        assert not server.voice_state[room][env.u["bob"]].get("server_muted")
        # a non-participant is still refused
        await env.voice("dave", room="dm:999999", expect="error")
    run(body)


def test_kick_block_pruning_and_gate_are_synchronous():
    async def body(env):
        server._voice_kick_blocks[("x", 1)] = server.monotonic() - 1
        assert server._voice_kick_block_left("x", 1) == 0
        assert ("x", 1) not in server._voice_kick_blocks
        # the refusal check is a plain function: no await between it and the insert in _voice_join
        assert not asyncio.iscoroutinefunction(server._voice_join_refusal)
        server.voice_state["r"] = {i: {} for i in range(8)}
        try:
            r = server._voice_join_refusal("r", 99, cap=8, is_mod=True, timed_out=None)
            assert r and r[0] == "room_full"             # the cap holds for a moderator too
            assert server._voice_join_refusal("r", 99, cap=9, is_mod=False, timed_out=None) is None
        finally:
            server.voice_state.pop("r", None)
    run(body)


def test_new_markup_has_no_inline_handlers_and_the_pages_load_the_new_script():
    chat = (ROOT / "static" / "chat.html").read_text()
    watch = (ROOT / "static" / "watch.html").read_text()
    docs = (ROOT / "static" / "api-docs.html").read_text()
    for page, tag in ((chat, 'id="voice-lock-btn"'), (watch, 'id="wv-lock-btn"')):
        button = page[page.index(tag):].split(">", 1)[0]
        assert "onclick" not in button, button
        assert "/static/js/voice.js?v=15" in page
    assert 'data-voicecap-action="save"' in (ROOT / "static" / "admin.html").read_text()
    assert "onclick" not in docs.split("/api/admin/voice")[0].rsplit("<div", 1)[1]
    # the voice script: the new frames and the honest help text
    js = (ROOT / "static" / "js" / "voice.js").read_text()
    for needle in ("voice_server_mute_changed", "voice_room_lock_changed", "voice_kick", "cooperative",
                   "enforced against normal clients only"):
        assert needle in js, needle


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print("FAIL", name, type(e).__name__, e)
                failed += 1
    if outbound_guard.refused:
        print("FAIL: the guard refused a dial", outbound_guard.refused)
        failed += 1
    sys.exit(1 if failed else 0)
