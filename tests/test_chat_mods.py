"""Stream chat controls: chat_mod_level and every action that uses it.

Runs the real chat websocket handler and the real HTTP handlers in-process (only the
authentication lookup is replaced) against a temporary database.

* chat_mod_level: a table of (channel, member) -> level. Global staff, the owner of the stream
  the channel is bound to, a stream mod (a 'moderator' row on that same channel), nobody. Powers
  exist only in a real stream chat (never a default or shared channel), a mod of stream A has
  nothing in stream B's chat or a general channel, and a member who cannot read the chat
  (stream ban, stream made private) has none.
* _chat_may_act_on through chat_mod_may_act: a table of (actor, target) -> allowed. A stream mod
  cannot act on the owner, another mod or staff; the owner cannot act on staff; nobody acts on
  themselves; staff keep the global role order. A target who cannot read the chat keeps his rank.
* A table-driven run of every action on the socket (pin, unpin, timeout, delete, ban, unban,
  poll, slowmode) by every kind of actor, checked against the database.
* Slow mode 15 holds viewers back and not the owner or mods.
* HTTP: ban and unban by a mod, the mods routes (owner and admins only, cap, audit), the
  generic channel-member routes closed for a stream chat.

Run: venv/bin/python tests/test_chat_mods.py
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

NONE, MOD, OWNER, STAFF = (server.CHAT_LEVEL_NONE, server.CHAT_LEVEL_MOD,
                           server.CHAT_LEVEL_OWNER, server.CHAT_LEVEL_STAFF)


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

    async def wait(self, pred, start=0, timeout=4.0):
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

    async def act(self, ok_type, quiet=False, **payload):
        """Send one action; the answer is the success frame or the first error frame.
        quiet: a refusal may be silent (a delete that matched nothing): None after a short wait."""
        start = self.mark()
        await self.send(**payload)
        got = await self.wait(lambda e: e.get("type") in (ok_type, "error"), start,
                              timeout=0.6 if quiet else 4.0)
        assert got is not None or quiet, ("no answer", payload)
        return got

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
        server._slowmode_last_msg.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        for method, path, handler in (
                ("GET", "/api/streams/{id}/bans", server.http_get_stream_bans),
                ("POST", "/api/streams/{id}/bans", server.http_create_stream_ban),
                ("DELETE", "/api/streams/{id}/bans/{user_id}", server.http_remove_stream_ban),
                ("DELETE", "/api/streams/{id}/bans/id/{ban_id}", server.http_remove_stream_ban_by_id),
                ("GET", "/api/streams/{id}/mods", server.http_list_stream_mods),
                ("POST", "/api/streams/{id}/mods", server.http_add_stream_mod),
                ("DELETE", "/api/streams/{id}/mods/{user_id}", server.http_remove_stream_mod),
                ("GET", "/api/chat/channels/{id}/members", server.http_get_channel_members),
                ("POST", "/api/chat/channels/{id}/members", server.http_add_channel_member),
                ("DELETE", "/api/chat/channels/{id}/members/{user_id}", server.http_remove_channel_member),
                ("PUT", "/api/chat/channels/{id}/members/{user_id}", server.http_update_channel_member_role)):
            app.router.add_route(method, path, handler)
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
            try:
                return r.status, await r.json()
            except Exception:
                return r.status, None


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


class World:
    """Two streams with their own chats (A: owner, B: ownerb), a stream mod in each, a stream whose
    chat is shared, the default channel, and the members used by the tables."""

    async def build(self, d):
        self.d = d
        u = self.u = {}
        for name in ("owner", "friend", "mod2", "plain", "spammer", "admin", "admin2", "gmod", "gmod2",
                     "ownerb", "modb"):
            u[name] = await d.create_user(name, "x")
        for name, role in (("admin", "admin"), ("admin2", "admin"), ("gmod", "moderator"), ("gmod2", "moderator")):
            await d.set_user_role(u[name], role)
        self.chat = {}
        self.stream = {}
        for label, owner in (("a", "owner"), ("b", "ownerb")):
            cid = await d.create_chat_channel("chat-" + label, created_by=u[owner])
            sid = await d.create_user_stream(u[owner], "s-" + label, "live_" + label * 24,
                                             public_key="pub_" + label * 24, is_public=True)
            await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
            await d.conn.commit()
            self.chat[label], self.stream[label] = cid, sid
        await d.add_channel_member(self.chat["a"], u["friend"], role="moderator", added_by=u["owner"])
        await d.add_channel_member(self.chat["a"], u["mod2"], role="moderator", added_by=u["owner"])
        await d.add_channel_member(self.chat["b"], u["modb"], role="moderator", added_by=u["ownerb"])
        # a channel two streams point at, with a moderator row of the same kind
        self.chat["shared"] = await d.create_chat_channel("shared", created_by=u["owner"])
        for i, owner in enumerate(("owner", "ownerb")):
            sid = await d.create_user_stream(u[owner], "sh%d" % i, "live_" + "s%d" % i * 12,
                                             public_key="pub_" + "s%d" % i * 12, is_public=True)
            await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?",
                                 (self.chat["shared"], sid))
        await d.conn.commit()
        await d.add_channel_member(self.chat["shared"], u["friend"], role="moderator", added_by=u["owner"])
        self.chat["general"] = (await d.get_chat_channel_by_name("general"))["id"]
        await d.add_channel_member(self.chat["general"], u["friend"], role="moderator", added_by=u["owner"])
        return self

    async def channel(self, key):
        return await self.d.get_chat_channel(self.chat[key])

    async def user(self, name):
        return {"id": self.u[name], "role": server._user_role_of(await self.d.get_user_by_id(self.u[name]))}


# ---------------------------------------------------------------------------
# the helper

def test_chat_mod_level_table():
    async def body(env):
        d = env.db
        w = await World().build(d)
        # (channel, member, level)
        table = [
            ("a", "owner", OWNER), ("a", "friend", MOD), ("a", "mod2", MOD), ("a", "plain", NONE),
            ("a", "admin", STAFF), ("a", "gmod", STAFF), ("a", "ownerb", NONE), ("a", "modb", NONE),
            ("b", "friend", NONE), ("b", "owner", NONE), ("b", "modb", MOD), ("b", "ownerb", OWNER),
            ("b", "admin", STAFF),
            # a general (default) channel and a channel shared by two streams give no owner or mod power
            ("general", "friend", NONE), ("general", "owner", NONE), ("general", "admin", STAFF),
            ("shared", "friend", NONE), ("shared", "owner", NONE), ("shared", "ownerb", NONE),
            ("shared", "gmod", STAFF),
        ]
        for chan, who, want in table:
            got = await server.chat_mod_level(await w.channel(chan), await w.user(who))
            assert got == want, (chan, who, got, want)
        # without a role in the dict the role is looked up
        assert await server.chat_mod_level(await w.channel("a"), {"id": w.u["admin"]}) == STAFF
        assert await server.chat_mod_level(await w.channel("a"), {"id": w.u["friend"]}) == MOD
        assert await server.chat_mod_level(await w.channel("a"), None) == NONE
        assert await server.chat_mod_level(None, await w.user("owner")) == NONE
        # a plain 'member' row is not a mod
        await d.add_channel_member(w.chat["a"], w.u["plain"], role="member", added_by=w.u["owner"])
        assert await server.chat_mod_level(await w.channel("a"), await w.user("plain")) == NONE
        # looked up on every call: appointing and removing show at once
        await d.add_channel_member(w.chat["a"], w.u["plain"], role="moderator", added_by=w.u["owner"])
        assert await server.chat_mod_level(await w.channel("a"), await w.user("plain")) == MOD
        await d.remove_channel_member(w.chat["a"], w.u["plain"])
        assert await server.chat_mod_level(await w.channel("a"), await w.user("plain")) == NONE
        # a member who lost read access has no power: stream ban
        await d.create_stream_ban(w.stream["a"], w.u["friend"], w.u["owner"], "r")
        assert await server.chat_mod_level(await w.channel("a"), await w.user("friend")) == NONE
        await d.remove_stream_ban(w.stream["a"], w.u["friend"])
        assert await server.chat_mod_level(await w.channel("a"), await w.user("friend")) == MOD
        # ... and a stream made private: only the owner and admins read it, so a mod and a moderator lose
        await d.update_user_stream(w.stream["a"], is_public=0)
        for who, want in (("friend", NONE), ("gmod", NONE), ("owner", OWNER), ("admin", STAFF)):
            assert await server.chat_mod_level(await w.channel("a"), await w.user(who)) == want, who
    run(body)


def test_may_act_on_table():
    async def body(env):
        d = env.db
        w = await World().build(d)
        # (actor, target, allowed) in the chat of stream A
        table = [
            ("owner", "friend", True), ("owner", "plain", True), ("owner", "admin", False),
            ("owner", "gmod", False), ("owner", "owner", False),
            ("friend", "owner", False), ("friend", "mod2", False), ("friend", "admin", False),
            ("friend", "gmod", False), ("friend", "friend", False), ("friend", "plain", True),
            ("friend", "ownerb", True), ("friend", "modb", True),
            ("admin", "owner", True), ("admin", "friend", True), ("admin", "gmod", True),
            ("admin", "admin2", False), ("admin", "admin", False),
            ("gmod", "admin", False), ("gmod", "gmod2", False), ("gmod", "plain", True),
            ("gmod", "owner", True), ("gmod", "friend", True),
            ("plain", "spammer", False), ("modb", "spammer", False), ("ownerb", "spammer", False),
            ("owner", "nobody-at-all", False),
        ]
        ch = await w.channel("a")
        for actor, target, want in table:
            tid = w.u.get(target, 999999)
            got = await server.chat_mod_may_act(ch, await w.user(actor), tid)
            assert got == want, (actor, target, got, want)
        # staff keep their rank when they cannot read the chat (a banned admin is still an admin)
        await d.create_stream_ban(w.stream["a"], w.u["admin2"], w.u["owner"], "r")
        assert not await server.chat_mod_may_act(ch, await w.user("owner"), w.u["admin2"])
        # a mod who lost the chat is still a mod: another mod cannot act on him
        await d.create_stream_ban(w.stream["a"], w.u["mod2"], w.u["owner"], "r")
        assert not await server.chat_mod_may_act(ch, await w.user("friend"), w.u["mod2"])
        assert await server.chat_mod_may_act(ch, await w.user("owner"), w.u["mod2"])
        # in the default and shared channels the owner and the mod rows give nothing over a plain member
        for chan in ("general", "shared"):
            c2 = await w.channel(chan)
            assert not await server.chat_mod_may_act(c2, await w.user("friend"), w.u["plain"]), chan
            assert not await server.chat_mod_may_act(c2, await w.user("owner"), w.u["plain"]), chan
            assert await server.chat_mod_may_act(c2, await w.user("admin"), w.u["plain"]), chan
    run(body)


# ---------------------------------------------------------------------------
# every action on the socket, by every kind of actor

ACTORS = ("owner", "friend", "plain", "modb", "admin", "gmod")
POWER = {"owner": True, "friend": True, "plain": False, "modb": False, "admin": True, "gmod": True}


async def joined(env, w, name, chan="a"):
    s = await env.sock(w.u[name])
    await s.join(w.chat[chan])
    return s


def test_every_action_by_every_actor():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid = w.chat["a"]
        socks = {n: await joined(env, w, n) for n in ACTORS}
        spam_sock = await joined(env, w, "spammer")

        async def fresh_message():
            return await d.create_chat_message(cid, w.u["spammer"], "spammer", "buy now")

        for actor in ACTORS:
            s, allowed = socks[actor], POWER[actor]
            # pin and unpin
            mid = await fresh_message()
            got = await s.act("message_pinned", type="pin_message", message_id=mid)
            assert (got["type"] == "message_pinned") == allowed, ("pin", actor, got)
            assert bool((await d.get_chat_message(mid)).get("is_pinned")) == allowed, ("pin db", actor)
            await d.pin_message(mid, w.u["owner"])
            got = await s.act("message_unpinned", type="unpin_message", message_id=mid)
            assert (got["type"] == "message_unpinned") == allowed, ("unpin", actor, got)
            assert bool((await d.get_chat_message(mid)).get("is_pinned")) == (not allowed), ("unpin db", actor)
            # timeout
            await d.remove_chat_timeout(w.u["spammer"], cid)
            got = await s.act("user_timed_out", type="timeout_user", target_user_id=w.u["spammer"], duration=60)
            assert (got["type"] == "user_timed_out") == allowed, ("timeout", actor, got)
            assert bool(await d.is_user_timed_out(w.u["spammer"], cid)) == allowed, ("timeout db", actor)
            await d.remove_chat_timeout(w.u["spammer"], cid)
            # delete a message of somebody else
            mid = await fresh_message()
            got = await s.act("message_deleted", quiet=True, type="delete", message_id=mid)
            gone = (await d.get_chat_message(mid)) is None
            assert gone == allowed, ("delete", actor, got)
            # ban and unban
            await d.remove_stream_ban(w.stream["a"], w.u["spammer"])
            got = await s.act("ban_success", type="ban", user_id=w.u["spammer"], reason="spam")
            assert (got["type"] == "ban_success") == allowed, ("ban", actor, got)
            assert await d.is_user_banned_from_stream(w.stream["a"], w.u["spammer"]) == allowed, ("ban db", actor)
            await d.create_stream_ban(w.stream["a"], w.u["spammer"], w.u["owner"], "x")
            got = await s.act("unban_success", type="unban", user_id=w.u["spammer"])
            assert (got["type"] == "unban_success") == allowed, ("unban", actor, got)
            assert await d.is_user_banned_from_stream(w.stream["a"], w.u["spammer"]) == (not allowed), ("unban db", actor)
            await d.remove_stream_ban(w.stream["a"], w.u["spammer"])
            # polls: in a stream's own chat the owner, mods and staff only
            got = await s.act("poll_created", type="create_poll", question="best?", options=["x", "y"])
            assert (got["type"] == "poll_created") == allowed, ("poll", actor, got)
            # slow mode
            await d.update_chat_channel(cid, slowmode_seconds=0)
            got = await s.act("slowmode_changed", type="set_slowmode", seconds=15)
            assert (got["type"] == "slowmode_changed") == allowed, ("slowmode", actor, got)
            assert (await d.get_chat_channel(cid))["slowmode_seconds"] == (15 if allowed else 0), ("slowmode db", actor)
        # slow mode takes only 0, 5, 15, 30 and only in a real stream chat
        s = socks["owner"]
        for bad in (7, 60, -1, "15", None, True, 15.5):
            got = await s.act("slowmode_changed", type="set_slowmode", seconds=bad)
            assert got["type"] == "error", bad
        got = await s.act("slowmode_changed", type="set_slowmode", seconds=0)
        assert got["type"] == "slowmode_changed" and (await d.get_chat_channel(cid))["slowmode_seconds"] == 0
        # every refused action by a plain member and a mod of another stream leaves one error frame
        # and the actions of the allowed ones are in the audit log with actor, target and channel
        entries = await d.get_audit_log(limit=200, channel_id=cid)
        by_action = {}
        for e in entries:
            by_action.setdefault(e["action"], set()).add(e["actor_id"])
        for action in ("pin_message", "unpin_message", "user_timeout", "message_delete", "user_ban",
                       "user_unban", "poll_create", "slowmode_set"):
            actors = by_action.get(action, set())
            assert w.u["owner"] in actors and w.u["friend"] in actors, (action, actors)
            assert w.u["plain"] not in actors and w.u["modb"] not in actors, (action, actors)
        timeout_row = [e for e in entries if e["action"] == "user_timeout" and e["actor_id"] == w.u["friend"]][0]
        assert timeout_row["target_id"] == w.u["spammer"] and timeout_row["channel_id"] == cid
        # polls elsewhere keep their rule: any member opens one in a general channel
        gs = await joined(env, w, "plain", "general")
        got = await gs.act("poll_created", type="create_poll", question="lunch?", options=["a", "b"])
        assert got["type"] == "poll_created", got
        # and slow mode cannot be set in a general channel by its mod row or the owner of a stream
        for who in ("owner", "friend"):
            gsock = await joined(env, w, who, "general")
            got = await gsock.act("slowmode_changed", type="set_slowmode", seconds=5)
            assert got["type"] == "error", (who, got)
    run(body)


def test_targets_and_other_channels():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid = w.chat["a"]
        friend, owner = await joined(env, w, "friend"), await joined(env, w, "owner")
        await joined(env, w, "plain")
        # a stream mod cannot act on the owner, another mod, an admin, a moderator or himself
        for target in ("owner", "mod2", "admin", "gmod", "friend"):
            got = await friend.act("user_timed_out", type="timeout_user", target_user_id=w.u[target], duration=60)
            assert got["type"] == "error" and got["message"] == server._CHAT_REFUSED_TARGET, (target, got)
            got = await friend.act("ban_success", type="ban", user_id=w.u[target], reason="x")
            assert got["type"] == "error", (target, got)
            assert not await d.is_user_timed_out(w.u[target], cid), target
            assert not await d.is_user_banned_from_stream(w.stream["a"], w.u[target]), target
        # the owner cannot act on staff or himself, but can on a mod
        for target in ("admin", "gmod", "owner"):
            got = await owner.act("user_timed_out", type="timeout_user", target_user_id=w.u[target], duration=60)
            assert got["type"] == "error", (target, got)
            got = await owner.act("ban_success", type="ban", user_id=w.u[target], reason="x")
            assert got["type"] == "error", (target, got)
            assert not await d.is_user_banned_from_stream(w.stream["a"], w.u[target]), target
        got = await owner.act("user_timed_out", type="timeout_user", target_user_id=w.u["mod2"], duration=60)
        assert got["type"] == "user_timed_out"
        # timeout by the id of a message: an anonymous author is named to nobody, whoever it is
        await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id IN (?, ?)", (w.u["spammer"], w.u["owner"]))
        await d.conn.commit()
        anon_spam = await d.create_chat_message(cid, w.u["spammer"], "spammer", "anon spam", anonymous=True)
        anon_owner = await d.create_chat_message(cid, w.u["owner"], "owner", "anon boss", anonymous=True)
        # (1.24.1) an anonymous post is answered the same whoever wrote it: the owner's post is no refusal
        got = await friend.act("user_timed_out", type="timeout_user", message_id=anon_owner, duration=60)
        assert got["type"] == "user_timed_out" and got["username"] == "Anonymous" and got.get("user_id") is None, got
        assert await d.is_user_timed_out(w.u["owner"], cid)
        await d.remove_chat_timeout(w.u["owner"], cid)
        got = await friend.act("user_timed_out", type="timeout_user", message_id=anon_spam, duration=60)
        assert got["type"] == "user_timed_out" and got["username"] == "Anonymous" and got.get("user_id") is None, got
        assert await d.is_user_timed_out(w.u["spammer"], cid)
        # an anonymous post stays anonymous when its author has since turned anonymous mode off
        await d.conn.execute("UPDATE users SET chat_anonymous = 0 WHERE id = ?", (w.u["spammer"],))
        await d.conn.commit()
        await d.remove_chat_timeout(w.u["spammer"], cid)
        third = await joined(env, w, "plain")
        t_start = third.mark()
        f_start = friend.mark()
        got = await friend.act("user_timed_out", type="timeout_user", message_id=anon_spam, duration=60)
        assert got["type"] == "user_timed_out", got
        seen = await third.wait(lambda e: e.get("type") == "user_timed_out", t_start)
        assert seen and seen.get("user_id") is None and seen["username"] == "Anonymous", seen
        mine = [e for e in friend.events[f_start:] if e.get("type") == "user_timed_out"][0]
        assert mine.get("user_id") is None and mine["username"] == "Anonymous", mine
        assert "spammer" not in json.dumps(seen)
        entries = await d.get_audit_log(limit=50, channel_id=cid)
        last = [e for e in entries if e["action"] == "user_timeout" and e["actor_id"] == w.u["friend"]][0]
        assert last["target_name"] == "Anonymous", last
        # a message of another channel is not a way to name a target
        other = await d.create_chat_message(w.chat["b"], w.u["plain"], "plain", "elsewhere")
        await friend.act("user_timed_out", quiet=True, type="timeout_user", message_id=other, duration=60)
        assert not await d.is_user_timed_out(w.u["plain"], cid)
        # a mod message deleted by another mod: refused; by the owner: allowed; own message always
        m_mod = await d.create_chat_message(cid, w.u["mod2"], "mod2", "mod says")
        await friend.act("message_deleted", quiet=True, type="delete", message_id=m_mod)
        assert (await d.get_chat_message(m_mod)) is not None, "another mod's message stays"
        got = await owner.act("message_deleted", type="delete", message_id=m_mod)
        assert got["type"] == "message_deleted" and (await d.get_chat_message(m_mod)) is None
        m_own = await d.create_chat_message(cid, w.u["friend"], "friend", "my own")
        got = await friend.act("message_deleted", type="delete", message_id=m_own)
        assert got["type"] == "message_deleted"
        m_owner = await d.create_chat_message(cid, w.u["owner"], "owner", "boss says")
        await friend.act("message_deleted", quiet=True, type="delete", message_id=m_owner)
        assert (await d.get_chat_message(m_owner)) is not None, "a mod cannot delete the owner's message"
        # a mod of stream A has no power in the chat of stream B, in a general channel or in a shared one
        for chan in ("b", "general", "shared"):
            s = await joined(env, w, "friend", chan)
            mid = await d.create_chat_message(w.chat[chan], w.u["plain"], "plain", "x")
            for payload, ok in ((dict(type="pin_message", message_id=mid), "message_pinned"),
                                (dict(type="timeout_user", target_user_id=w.u["plain"], duration=60), "user_timed_out"),
                                (dict(type="ban", user_id=w.u["plain"]), "ban_success"),
                                (dict(type="delete", message_id=mid), "message_deleted")):
                got = await s.act(ok, quiet=True, **payload)
                assert got is None or got["type"] == "error", (chan, payload["type"], got)
            assert (await d.get_chat_message(mid)) is not None
            assert not await d.is_user_timed_out(w.u["plain"], w.chat[chan])
    run(body)


def test_a_new_timeout_does_not_replace_a_penalty_the_actor_may_not_touch():
    """A timeout replaces the old penalty row of the member. An owner or a stream mod must not use
    that to drop a mute, a site-wide penalty or a penalty of staff (unmute_user is staff only)."""
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid, spam = w.chat["a"], w.u["spammer"]
        socks = {n: await joined(env, w, n) for n in ("owner", "friend", "gmod")}

        async def penalty():
            return await d.is_user_timed_out(spam, cid)

        async def place(by, kind="timeout", channel=cid, seconds=3600, reason="x"):
            await d.remove_chat_timeout(spam, cid)
            await d.create_chat_timeout(spam, w.u[by], kind, channel, reason, seconds if kind == "timeout" else None)
            return (await penalty())["id"]

        # penalties the owner and the mod must leave alone, and the same for a mute of the owner
        # against the mod
        cases = [("owner", "gmod mute", dict(by="gmod", kind="mute")),
                 ("owner", "admin mute", dict(by="admin", kind="mute")),
                 ("owner", "gmod timeout", dict(by="gmod")),
                 ("owner", "site-wide timeout", dict(by="gmod", channel=None)),
                 ("owner", "automod timeout", dict(by="admin", reason="AutoMod: spam")),
                 ("friend", "gmod mute", dict(by="gmod", kind="mute")),
                 ("friend", "gmod timeout", dict(by="gmod")),
                 ("friend", "site-wide timeout", dict(by="gmod", channel=None)),
                 ("friend", "automod timeout", dict(by="admin", reason="AutoMod: spam")),
                 ("friend", "owner mute", dict(by="owner", kind="mute")),
                 ("friend", "owner timeout", dict(by="owner")),
                 ("friend", "timeout of another mod", dict(by="mod2"))]
        for actor, label, kw in cases:
            before = await place(**kw)
            got = await socks[actor].act("user_timed_out", type="timeout_user", target_user_id=spam, duration=1)
            assert got["type"] == "error" and got["message"] == server._CHAT_REFUSED_TARGET, (actor, label, got)
            now = await penalty()
            assert now and now["id"] == before, (actor, label, "the old penalty must stay", now)
        # what they may replace: their own timeout, and the owner replaces a stream mod's
        for actor, kw in (("friend", dict(by="friend")), ("owner", dict(by="owner")),
                          ("owner", dict(by="friend")), ("owner", dict(by="mod2"))):
            before = await place(**kw)
            got = await socks[actor].act("user_timed_out", type="timeout_user", target_user_id=spam, duration=60)
            assert got["type"] == "user_timed_out", (actor, kw, got)
            now = await penalty()
            assert now and now["id"] != before and now["moderator_id"] == w.u[actor], (actor, kw, now)
        # staff keep the power to replace anything
        for kw in (dict(by="friend"), dict(by="admin", kind="mute"), dict(by="gmod", channel=None)):
            before = await place(**kw)
            got = await socks["gmod"].act("user_timed_out", type="timeout_user", target_user_id=spam, duration=60)
            assert got["type"] == "user_timed_out", (kw, got)
            assert (await penalty())["id"] != before, kw
    run(body)


def test_lost_read_access_removes_the_power_on_an_open_socket():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid = w.chat["a"]
        friend = await joined(env, w, "friend")
        mid = await d.create_chat_message(cid, w.u["plain"], "plain", "pin me")
        # banned from the stream: the open socket is refused (and put out of the room)
        await d.create_stream_ban(w.stream["a"], w.u["friend"], w.u["owner"], "r")
        got = await friend.act("message_pinned", type="pin_message", message_id=mid)
        assert got["type"] == "error", got
        assert not (await d.get_chat_message(mid)).get("is_pinned")
        await d.remove_stream_ban(w.stream["a"], w.u["friend"])
        friend2 = await joined(env, w, "friend")
        got = await friend2.act("message_pinned", type="pin_message", message_id=mid)
        assert got["type"] == "message_pinned", got
        # the stream turns private: appointing never gave read access, so the mod is out
        await d.update_user_stream(w.stream["a"], is_public=0)
        got = await friend2.act("message_unpinned", type="unpin_message", message_id=mid)
        assert got["type"] == "error" and got["message"] == "Channel not found", got
        assert (await d.get_chat_message(mid)).get("is_pinned")
        friend3 = await env.sock(w.u["friend"])
        await friend3.send(type="join", channel_id=cid)
        err = await friend3.wait(lambda e: e.get("type") in ("history", "error"))
        assert err["type"] == "error", err
    run(body)


def test_slowmode_holds_viewers_and_not_owner_or_mods():
    async def body(env):
        d = env.db
        w = await World().build(d)
        owner, friend, plain = [await joined(env, w, n) for n in ("owner", "friend", "plain")]
        got = await owner.act("slowmode_changed", type="set_slowmode", seconds=15)
        assert got["type"] == "slowmode_changed" and got["seconds"] == 15
        got = await plain.wait(lambda e: e.get("type") == "slowmode_changed")
        assert got and got["seconds"] == 15, "the viewers are told"
        for s, blocked in ((plain, True), (owner, False), (friend, False)):
            first = await s.act("message", type="message", message="one")
            assert first["type"] == "message", first
            start = s.mark()
            await s.send(type="message", message="two")
            got = await s.wait(lambda e: e.get("type") == "error" or (e.get("type") == "message" and e.get("message") == "two"), start)
            assert got is not None
            if blocked:
                assert got["type"] == "error" and got.get("error_code") == "slowmode", got
            else:
                assert got["type"] == "message", got
        # a viewer's message carries no badge, the owner's and a mod's do
        msgs = [e for e in plain.events if e.get("type") == "message" and e.get("message") == "one"]
        roles = {e["username"]: e.get("stream_role") for e in msgs}
        assert roles.get("owner") == "owner" and roles.get("friend") == "mod" and roles.get("plain") is None, roles
        # 0 lifts it
        await owner.act("slowmode_changed", type="set_slowmode", seconds=0)
        await plain.send(type="message", message="three")
        got = await plain.wait(lambda e: e.get("type") == "message" and e.get("message") == "three")
        assert got is not None
    run(body)


def test_badges_in_history_never_on_anonymous_posts():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid = w.chat["a"]
        await d.create_chat_message(cid, w.u["owner"], "owner", "o")
        await d.create_chat_message(cid, w.u["friend"], "friend", "m")
        await d.create_chat_message(cid, w.u["plain"], "plain", "p")
        await d.create_chat_message(cid, w.u["friend"], "friend", "anon mod", anonymous=True)
        s = await env.sock(w.u["plain"])
        start = s.mark()
        await s.send(type="join", channel_id=cid)
        hist = await s.wait(lambda e: e.get("type") == "history", start)
        by_text = {m["message"]: m.get("stream_role") for m in hist["messages"]}
        assert by_text == {"o": "owner", "m": "mod", "p": None, "anon mod": None}, by_text
        info = await s.wait(lambda e: e.get("type") == "channel_info", start)
        assert info["mod_level"] == "none" and info["stream_chat"] is True
        f = await env.sock(w.u["friend"])
        await f.send(type="join", channel_id=cid)
        info = await f.wait(lambda e: e.get("type") == "channel_info")
        assert info["mod_level"] == "mod"
    run(body)


# ---------------------------------------------------------------------------
# HTTP

def test_http_bans_by_a_mod_and_the_mods_routes():
    async def body(env):
        d = env.db
        w = await World().build(d)
        sid, cid = w.stream["a"], w.chat["a"]
        u = w.u
        # a stream mod bans and unbans over HTTP; the owner, another mod, an admin and himself are refused
        st, _ = await env.call("POST", u["friend"], f"/api/streams/{sid}/bans", json={"user_id": u["spammer"]})
        assert st == 201
        assert await d.is_user_banned_from_stream(sid, u["spammer"])
        for target in ("owner", "mod2", "admin", "friend"):
            st, _ = await env.call("POST", u["friend"], f"/api/streams/{sid}/bans", json={"user_id": u[target]})
            assert st == 400, (target, st)
            assert not await d.is_user_banned_from_stream(sid, u[target])
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/bans", json={"user_id": u["admin"]})
        assert st == 400, "the owner cannot ban an admin"
        st, body_ = await env.call("GET", u["friend"], f"/api/streams/{sid}/bans")
        assert st == 200 and len(body_["bans"]) == 1
        st, _ = await env.call("POST", u["plain"], f"/api/streams/{sid}/bans", json={"user_id": u["spammer"]})
        assert st == 403
        st, _ = await env.call("POST", u["modb"], f"/api/streams/{sid}/bans", json={"user_id": u["plain"]})
        assert st == 403, "a mod of another stream has no power here"
        st, _ = await env.call("DELETE", u["friend"], f"/api/streams/{sid}/bans/{u['spammer']}")
        assert st == 200 and not await d.is_user_banned_from_stream(sid, u["spammer"])
        ban = await d.create_stream_ban(sid, u["spammer"], u["owner"], "x")
        st, _ = await env.call("DELETE", u["plain"], f"/api/streams/{sid}/bans/id/{ban}")
        assert st == 403
        st, _ = await env.call("DELETE", u["friend"], f"/api/streams/{sid}/bans/id/{ban}")
        assert st == 200
        # the owner of a stream whose chat is shared still bans from its playback (HTTP)
        shared_stream = (await (await d.conn.execute(
            "SELECT id FROM user_streams WHERE chat_channel_id = ? AND user_id = ?", (w.chat["shared"], u["owner"]))).fetchone())["id"]
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{shared_stream}/bans", json={"user_id": u["spammer"]})
        assert st == 201
        st, _ = await env.call("POST", u["friend"], f"/api/streams/{shared_stream}/bans", json={"user_id": u["plain"]})
        assert st == 403, "a mod row on a shared channel is nothing"

        # --- the mods routes
        st, got = await env.call("GET", u["owner"], f"/api/streams/{sid}/mods")
        assert st == 200 and {m["username"] for m in got["mods"]} == {"friend", "mod2"}
        st, got = await env.call("GET", u["admin"], f"/api/streams/{sid}/mods")
        assert st == 200
        for who in ("friend", "plain", "modb", "gmod"):
            st, _ = await env.call("GET", u[who], f"/api/streams/{sid}/mods")
            assert st == 404, who
            st, _ = await env.call("POST", u[who], f"/api/streams/{sid}/mods", json={"user_id": u["plain"]})
            assert st == 404, who
            st, _ = await env.call("DELETE", u[who], f"/api/streams/{sid}/mods/{u['mod2']}")
            assert st == 404, who
        st, _ = await env.call("GET", u["owner"], "/api/streams/99999/mods")
        assert st == 404
        assert await d.get_channel_moderator_ids(cid) == [u["friend"], u["mod2"]]
        # appoint
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/mods", json={"user_id": u["plain"]})
        assert st == 201
        assert await server.chat_mod_level(await w.channel("a"), await w.user("plain")) == MOD
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/mods", json={"user_id": u["plain"]})
        assert st == 409, "already a mod"
        for bad in ({"user_id": 987654}, {"user_id": "x"}, {}, {"user_id": u["owner"]}, {"user_id": -1}):
            st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/mods", json=bad)
            assert st in (400, 404), (bad, st)
        # a member banned from the stream is not appointed
        await d.create_stream_ban(sid, u["spammer"], u["owner"], "x")
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/mods", json={"user_id": u["spammer"]})
        assert st == 400
        # a stream with no chat of its own has no mods
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{shared_stream}/mods", json={"user_id": u["plain"]})
        assert st == 409
        # the cap
        extra = []
        for i in range(30):
            extra.append(await d.create_user("extra%d" % i, "x"))
        added = len(await d.get_channel_moderator_ids(cid))
        statuses = []
        for uid in extra:
            st, _ = await env.call("POST", u["owner"], f"/api/streams/{sid}/mods", json={"user_id": uid})
            statuses.append(st)
        assert len(await d.get_channel_moderator_ids(cid)) == server.MAX_STREAM_MODS == 20
        assert statuses[:server.MAX_STREAM_MODS - added] == [201] * (server.MAX_STREAM_MODS - added)
        assert set(statuses[server.MAX_STREAM_MODS - added:]) == {409}
        # remove
        st, _ = await env.call("DELETE", u["owner"], f"/api/streams/{sid}/mods/{u['plain']}")
        assert st == 200
        assert await server.chat_mod_level(await w.channel("a"), await w.user("plain")) == NONE
        st, _ = await env.call("DELETE", u["owner"], f"/api/streams/{sid}/mods/{u['plain']}")
        assert st == 404
        # audit: appoint and remove with actor, target and channel
        entries = await d.get_audit_log(limit=200, channel_id=cid)
        add = [e for e in entries if e["action"] == "stream_mod_add" and e["target_id"] == u["plain"]]
        rem = [e for e in entries if e["action"] == "stream_mod_remove" and e["target_id"] == u["plain"]]
        assert add and add[0]["actor_id"] == u["owner"] and add[0]["channel_id"] == cid
        assert rem and rem[0]["actor_id"] == u["owner"] and rem[0]["channel_id"] == cid
        ban_audit = [e for e in entries if e["action"] == "user_ban" and e["actor_id"] == u["friend"]]
        assert ban_audit and ban_audit[0]["target_id"] == u["spammer"], "HTTP bans are audited"
    run(body)


def test_mods_list_and_remove_refuse_a_default_or_shared_channel():
    """The moderator rows of a channel the stream does not own alone are not the owner's to list or end."""
    async def body(env):
        d = env.db
        w = await World().build(d)
        u = w.u
        sid_of = lambda cid, owner: d.conn.execute(
            "SELECT id FROM user_streams WHERE chat_channel_id = ? AND user_id = ?", (cid, u[owner]))
        shared_a = (await (await sid_of(w.chat["shared"], "owner")).fetchone())["id"]
        shared_b = (await (await sid_of(w.chat["shared"], "ownerb")).fetchone())["id"]
        # a stream of a plain member bound to the default channel
        gen_stream = await d.create_user_stream(u["plain"], "s-gen", "live_" + "g" * 24,
                                                public_key="pub_" + "g" * 24, is_public=True)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?",
                             (w.chat["general"], gen_stream))
        await d.conn.commit()
        for owner, sid, chan in (("owner", shared_a, "shared"), ("ownerb", shared_b, "shared"),
                                 ("plain", gen_stream, "general")):
            st, got = await env.call("GET", u[owner], f"/api/streams/{sid}/mods")
            assert st == 200 and got["mods"] == [], (chan, owner, st, got)
            st, _ = await env.call("DELETE", u[owner], f"/api/streams/{sid}/mods/{u['friend']}")
            assert st == 409, (chan, owner, st)
            assert await d.get_channel_member_role(w.chat[chan], u["friend"]) == "moderator", (chan, owner)
        # an admin gets the same answer: the rows belong to the channel
        st, got = await env.call("GET", u["admin"], f"/api/streams/{gen_stream}/mods")
        assert st == 200 and got["mods"] == []
        st, _ = await env.call("DELETE", u["admin"], f"/api/streams/{gen_stream}/mods/{u['friend']}")
        assert st == 409
        assert await d.get_channel_member_role(w.chat["general"], u["friend"]) == "moderator"
        # a stream with a chat of its own still lists and removes its mods
        st, got = await env.call("GET", u["owner"], f"/api/streams/{w.stream['a']}/mods")
        assert st == 200 and {m["username"] for m in got["mods"]} == {"friend", "mod2"}
        st, _ = await env.call("DELETE", u["owner"], f"/api/streams/{w.stream['a']}/mods/{u['mod2']}")
        assert st == 200
    run(body)


def test_generic_member_routes_do_not_make_or_unmake_stream_mods():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid, u = w.chat["a"], w.u
        # a stream mod (a channel moderator row) cannot list, add, remove or promote through the generic routes
        st, _ = await env.call("GET", u["friend"], f"/api/chat/channels/{cid}/members")
        assert st == 403
        st, _ = await env.call("DELETE", u["friend"], f"/api/chat/channels/{cid}/members/{u['mod2']}")
        assert st == 403
        assert u["mod2"] in await d.get_channel_moderator_ids(cid)
        st, _ = await env.call("POST", u["friend"], f"/api/chat/channels/{cid}/members", json={"user_id": u["plain"]})
        assert st == 403
        st, _ = await env.call("PUT", u["gmod"], f"/api/chat/channels/{cid}/members/{u['plain']}", json={"role": "moderator"})
        assert st == 403
        # a global moderator or an admin cannot appoint through them either (cap, checks and audit are on /mods)
        st, _ = await env.call("POST", u["admin"], f"/api/chat/channels/{cid}/members",
                               json={"user_id": u["plain"], "role": "moderator"})
        assert st == 400
        st, _ = await env.call("PUT", u["admin"], f"/api/chat/channels/{cid}/members/{u['plain']}", json={"role": "moderator"})
        assert st == 400
        assert u["plain"] not in await d.get_channel_moderator_ids(cid)
        st, got = await env.call("GET", u["admin"], f"/api/chat/channels/{cid}/members")
        assert st == 200
        # a general channel keeps working for the people it always worked for
        gid = w.chat["general"]
        st, _ = await env.call("POST", u["gmod"], f"/api/chat/channels/{gid}/members", json={"user_id": u["plain"]})
        assert st == 201
    run(body)


def test_a_ban_made_by_the_owner_on_staff_in_1_16_0_can_be_lifted():
    """1.16.0 let the owner ban anyone but himself, so a database can hold a stream ban on an admin or a
    superadmin. An admin or superadmin lifts any ban (over HTTP by account or by ban id, and on the
    socket), a banned one lifts his own, and the owner and mods still only lift bans on members they
    may act on."""
    async def body(env):
        d = env.db
        w = await World().build(d)
        u, sid = w.u, w.stream["a"]
        u["sa1"] = await d.create_user("sa1", "x")
        u["sa2"] = await d.create_user("sa2", "x")
        await d.set_user_role(u["sa1"], "superadmin")
        await d.set_user_role(u["sa2"], "superadmin")

        async def ban(name):
            await d.create_stream_ban(sid, u[name], u["owner"], "old")
            assert await d.is_user_banned_from_stream(sid, u[name])

        # the owner, a stream mod and a global moderator still cannot lift a ban on staff
        await ban("sa1")
        for who in ("owner", "friend", "gmod"):
            st, _ = await env.call("DELETE", u[who], f"/api/streams/{sid}/bans/{u['sa1']}")
            assert st in (400, 403), (who, st)
        assert await d.is_user_banned_from_stream(sid, u["sa1"])
        # an admin or another superadmin lifts it, by account
        st, _ = await env.call("DELETE", u["sa2"], f"/api/streams/{sid}/bans/{u['sa1']}")
        assert st == 200 and not await d.is_user_banned_from_stream(sid, u["sa1"])
        # the banned superadmin lifts his own ban
        await ban("sa1")
        st, _ = await env.call("DELETE", u["sa1"], f"/api/streams/{sid}/bans/{u['sa1']}")
        assert st == 200 and not await d.is_user_banned_from_stream(sid, u["sa1"])
        # by the id of the ban: a superadmin on an admin and on a superadmin, an admin on an admin
        await ban("sa1")
        row = await d.get_stream_bans(sid)
        bid = [b["id"] for b in row if b["user_id"] == u["sa1"]][0]
        st, _ = await env.call("DELETE", u["admin"], f"/api/streams/{sid}/bans/id/{bid}")
        assert st == 200 and not await d.is_user_banned_from_stream(sid, u["sa1"])
        await ban("admin2")
        st, _ = await env.call("DELETE", u["admin"], f"/api/streams/{sid}/bans/{u['admin2']}")
        assert st == 200 and not await d.is_user_banned_from_stream(sid, u["admin2"])
        # on the socket
        await ban("sa1")
        await ban("admin2")
        s = await joined(env, w, "sa2")
        got = await s.act("unban_success", type="unban", user_id=u["sa1"])
        assert got["type"] == "unban_success", got
        assert not await d.is_user_banned_from_stream(sid, u["sa1"])
        bid = [b["id"] for b in await d.get_stream_bans(sid) if b["user_id"] == u["admin2"]][0]
        got = await s.act("unban_success", type="unban", ban_id=bid)
        assert got["type"] == "unban_success", got
        assert not await d.is_user_banned_from_stream(sid, u["admin2"])
        # a banned member of no rank is still not a moderator
        await d.create_stream_ban(sid, u["friend"], u["owner"], "x")
        st, _ = await env.call("DELETE", u["friend"], f"/api/streams/{sid}/bans/{u['friend']}")
        assert st == 403
        assert await d.is_user_banned_from_stream(sid, u["friend"])
    run(body)


def test_pinned_list_on_join_does_not_name_an_anonymous_pinner():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid = w.chat["a"]
        await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (w.u["friend"],))
        await d.conn.commit()
        server.chat_user_state.pop(w.u["friend"], None)     # read from this database at the handshake
        mid = await d.create_chat_message(cid, w.u["plain"], "plain", "pin me")
        f = await joined(env, w, "friend")
        got = await f.act("message_pinned", type="pin_message", message_id=mid)
        assert got["type"] == "message_pinned" and got["pinned_by"] == server.ANON_MODERATOR_LABEL, got
        for name in ("plain", "owner", "admin"):
            s = await env.sock(w.u[name])
            start = s.mark()
            await s.send(type="join", channel_id=cid)
            pin = await s.wait(lambda e: e.get("type") == "pinned_messages", start)
            assert pin and pin["messages"][0]["id"] == mid, (name, pin)
            m = pin["messages"][0]
            assert "pinned_by" not in m and "pinned_by_username" not in m, (name, m)
            assert "friend" not in json.dumps(pin).replace("pin me", ""), (name, pin)
    run(body)
    server.chat_user_state.clear()      # the anonymous mode set here is not the next test's


def test_parallel_mod_appointments_keep_the_cap():
    async def body(env):
        d = env.db
        w = await World().build(d)
        sid, cid = w.stream["a"], w.chat["a"]
        extra = [await d.create_user("par%d" % i, "x") for i in range(25)]
        results = await asyncio.gather(*[
            env.call("POST", w.u["owner"], f"/api/streams/{sid}/mods", json={"user_id": uid}) for uid in extra])
        mods = await d.get_channel_moderator_ids(cid)
        assert len(mods) == server.MAX_STREAM_MODS, len(mods)
        statuses = sorted(r[0] for r in results)
        assert statuses.count(201) == server.MAX_STREAM_MODS - 2, statuses
        assert set(statuses) <= {201, 409}, statuses
    run(body)


def test_ids_beyond_the_sqlite_range_answer_an_error_and_keep_the_socket():
    async def body(env):
        d = env.db
        w = await World().build(d)
        huge = 2 ** 70
        owner = await joined(env, w, "owner")
        admin = await joined(env, w, "admin")
        cases = [(owner, {"type": "pin_message", "message_id": huge}),
                 (owner, {"type": "unpin_message", "message_id": huge}),
                 (owner, {"type": "delete", "message_id": huge}),
                 (owner, {"type": "timeout_user", "target_user_id": huge}),
                 (owner, {"type": "timeout_user", "message_id": huge}),
                 (owner, {"type": "ban", "user_id": huge}),
                 (owner, {"type": "ban", "message_id": huge}),
                 (owner, {"type": "unban", "user_id": huge}),
                 (owner, {"type": "unban", "ban_id": huge}),
                 (admin, {"type": "mute_user", "target_user_id": huge}),
                 (admin, {"type": "unmute_user", "target_user_id": huge}),
                 (owner, {"type": "close_poll", "poll_id": huge}),
                 (owner, {"type": "vote_poll", "poll_id": huge, "option_index": 0}),
                 (owner, {"type": "mark_read", "message_id": huge})]
        for sock, payload in cases:
            if payload["type"] in ("close_poll", "vote_poll", "mark_read"):
                await sock.send(**payload)         # silent refusals: only the socket must survive
            else:
                got = await sock.act("error", **payload)
                assert got and got["type"] == "error", (payload, got)
            assert not sock.ws.closed, payload
            got = await sock.act("slowmode_changed", type="set_slowmode", seconds=0)
            assert got["type"] == "slowmode_changed", (payload, got)
    run(body)


def test_an_anonymous_owner_or_mod_is_one_label_to_the_room_and_in_lists():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid, sid, u = w.chat["a"], w.stream["a"], w.u
        label = server.ANON_MODERATOR_LABEL
        for name in ("owner", "friend"):
            await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (u[name],))
        await d.conn.commit()
        server.chat_user_state.clear()
        owner = await joined(env, w, "owner")
        mod = await joined(env, w, "friend")
        plain = await joined(env, w, "plain")
        m1 = await d.create_chat_message(cid, u["plain"], "plain", "one")
        m2 = await d.create_chat_message(cid, u["plain"], "plain", "two")

        def clean(frame, *keys):
            text = json.dumps(frame)
            for who in ("owner", "friend"):
                assert who not in text.replace('"%s"' % label, ""), (who, frame)
                assert '%d' % u[who] not in [str(frame.get(k)) for k in keys], (who, frame)

        mark = plain.mark()
        await owner.act("message_pinned", type="pin_message", message_id=m1)
        got = await plain.wait(lambda e: e.get("type") == "message_pinned", mark)
        assert got["pinned_by"] == label, got
        clean(got)
        mark = plain.mark()
        await mod.act("user_timed_out", type="timeout_user", target_user_id=u["spammer"], duration=60)
        got = await plain.wait(lambda e: e.get("type") == "user_timed_out", mark)
        assert got["moderator"] == label, got
        mark = plain.mark()
        await owner.act("ban_success", type="ban", user_id=u["spammer"], reason="x")
        got = await plain.wait(lambda e: e.get("type") == "user_banned", mark)
        assert got["banned_by"] == label, got
        mark = plain.mark()
        hooks = []

        async def record(event, payload, *, meta=None):
            hooks.append((event, payload))
            return 0
        saved_hook, server.fire_webhook_event = server.fire_webhook_event, record
        try:
            await mod.act("message_deleted", type="delete", message_id=m2)
            got = await plain.wait(lambda e: e.get("type") == "message_deleted", mark)
            await asyncio.sleep(0.1)
        finally:
            server.fire_webhook_event = saved_hook
        assert got["deleted_by"] is None, got
        sent = [p for e, p in hooks if e == "message.deleted"]
        assert sent and sent[0]["deleted_by"] is None, hooks
        # the audit log still has the real actors
        entries = await d.get_audit_log(limit=200, channel_id=cid)
        assert any(e["action"] == "user_ban" and e["actor_id"] == u["owner"] for e in entries)
        assert any(e["action"] == "user_timeout" and e["actor_id"] == u["friend"] for e in entries)
        # ban list: ordinary members (here the other mod) and the owner's own view
        st, got = await env.call("GET", u["mod2"], f"/api/streams/{sid}/bans")
        assert st == 200 and got["bans"][0]["banned_by"] is None, got
        assert got["bans"][0]["banned_by_username"] == label, got
        assert "banned_by_anonymous" not in got["bans"][0] and "banned_by_role" not in got["bans"][0]
        st, got = await env.call("GET", u["admin"], f"/api/streams/{sid}/bans")
        assert got["bans"][0]["banned_by"] == u["owner"] and got["bans"][0]["banned_by_username"] == "owner", got
        st, got = await env.call("GET", u["owner"], f"/api/streams/{sid}/bans")
        assert got["bans"][0]["banned_by"] == u["owner"], got
        # a history page and the join frames never carry the pinner's id to an ordinary member
        late = await env.sock(u["mod2"])
        start = late.mark()
        await late.send(type="join", channel_id=cid)
        hist = await late.wait(lambda e: e.get("type") == "history", start)
        pinned = [m for m in hist["messages"] if m["id"] == m1]
        assert pinned and "pinned_by" not in pinned[0], pinned
        # global staff keep their naming
        await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (u["admin"],))
        await d.conn.commit()
        server.chat_user_state.pop(u["admin"], None)
        admin = await joined(env, w, "admin")
        mark = plain.mark()
        await admin.act("user_timed_out", type="timeout_user", target_user_id=u["mod2"], duration=60)
        got = await plain.wait(lambda e: e.get("type") == "user_timed_out", mark)
        assert got["moderator"] == "admin", got
    run(body)
    server.chat_user_state.clear()


def test_a_ban_list_masks_the_banner_as_he_was_at_the_time_of_the_ban():
    async def body(env):
        d = env.db
        w = await World().build(d)
        sid, u = w.stream["a"], w.u
        label = server.ANON_MODERATOR_LABEL
        spam2 = await d.create_user("spammer2", "x")
        spam3 = await d.create_user("spammer3", "x")
        server.chat_user_state.clear()
        # the mod bans over HTTP and the owner over the socket, both with anonymous chat on
        for name in ("friend", "owner"):
            await d.set_chat_anonymous(u[name], True)
        st, _ = await env.call("POST", u["friend"], f"/api/streams/{sid}/bans", json={"user_id": u["spammer"]})
        assert st == 201
        server.chat_user_state.clear()
        owner = await joined(env, w, "owner")
        got = await owner.act("ban_success", type="ban", user_id=spam2, reason="x")
        assert got["type"] == "ban_success", got
        # the same people turn anonymous chat off (what PUT /api/me/anonymous does) and the mod
        # makes a named ban afterwards
        for name in ("friend", "owner"):
            await d.set_chat_anonymous(u[name], False)
        server.chat_user_state.clear()
        st, _ = await env.call("POST", u["friend"], f"/api/streams/{sid}/bans", json={"user_id": spam3})
        assert st == 201

        async def listing(viewer):
            st, got = await env.call("GET", u[viewer], f"/api/streams/{sid}/bans")
            assert st == 200, st
            return {b["banned_username"] if b["user_id"] is None else
                    {u["spammer"]: "spammer", spam2: "spammer2", spam3: "spammer3"}[b["user_id"]]: b
                    for b in got["bans"]}
        for viewer in ("mod2", "owner"):
            rows = await listing(viewer)
            for victim, by in (("spammer", "friend"), ("spammer2", "owner")):
                if viewer == by:
                    continue            # his own ban is shown to himself by name
                row = rows[victim]
                assert row["banned_by"] is None and row["banned_by_username"] == label, (viewer, victim, row)
            row = rows["spammer3"]
            assert row["banned_by"] == u["friend"] and row["banned_by_username"] == "friend", (viewer, row)
        # staff and the banner himself still see who it was
        rows = await listing("admin")
        assert rows["spammer"]["banned_by"] == u["friend"] and rows["spammer2"]["banned_by"] == u["owner"], rows
        rows = await listing("friend")
        assert rows["spammer"]["banned_by"] == u["friend"], rows
        # turning anonymous on later does not hide a ban that was made by name
        await d.set_chat_anonymous(u["friend"], True)
        rows = await listing("mod2")
        assert rows["spammer3"]["banned_by"] == u["friend"], rows
        # the socket list goes through the same rule
        server.chat_user_state.clear()
        mod2 = await joined(env, w, "mod2")
        got = await mod2.act("bans_list", type="get_bans")
        masked = [b for b in got["bans"] if b["banned_by_username"] == label]
        assert len(masked) == 2 and all(b["banned_by"] is None for b in masked), got
    run(body)
    server.chat_user_state.clear()


def test_a_later_promotion_does_not_name_an_anonymous_banner_and_staff_stay_named():
    async def body(env):
        d = env.db
        w = await World().build(d)
        sid, u = w.stream["a"], w.u
        label = server.ANON_MODERATOR_LABEL
        spam2 = await d.create_user("spammer2", "x")
        server.chat_user_state.clear()
        await d.set_chat_anonymous(u["friend"], True)
        await d.set_chat_anonymous(u["admin"], True)
        st, _ = await env.call("POST", u["friend"], f"/api/streams/{sid}/bans", json={"user_id": u["spammer"]})
        assert st == 201
        # a staff member who bans with anonymous chat on stays named (the flag is never stored for him)
        st, _ = await env.call("POST", u["admin"], f"/api/streams/{sid}/bans", json={"user_id": spam2})
        assert st == 201

        async def rows(viewer):
            st, got = await env.call("GET", u[viewer], f"/api/streams/{sid}/bans")
            assert st == 200, st
            return {b["banned_username"] if b["user_id"] is None else
                    {u["spammer"]: "spammer", spam2: "spammer2"}[b["user_id"]]: b for b in got["bans"]}

        for role in ("moderator", "admin", "superadmin"):
            assert await d.set_user_role(u["friend"], role)
            for viewer in ("mod2", "owner"):
                got = await rows(viewer)
                row = got["spammer"]
                assert row["banned_by"] is None and row["banned_by_username"] == label, (role, viewer, row)
                assert "banned_by_role" not in row and "banned_by_anonymous" not in row, row
                row = got["spammer2"]
                assert row["banned_by"] == u["admin"] and row["banned_by_username"] == "admin", (role, viewer, row)
        server.chat_user_state.clear()
        mod2 = await joined(env, w, "mod2")
        got = await mod2.act("bans_list", type="get_bans")
        by_name = {b["banned_by_username"] for b in got["bans"]}
        assert label in by_name and "friend" not in by_name, got
    run(body)
    server.chat_user_state.clear()


class StuckWs:
    closed = False

    async def send_json(self, _payload):
        await asyncio.sleep(5)


def test_ending_a_mod_through_the_generic_routes_is_audited_and_pushed():
    async def body(env):
        d = env.db
        w = await World().build(d)
        cid, u = w.chat["a"], w.u
        name = (await w.channel("a"))["name"]
        friend = await joined(env, w, "friend")
        mod2 = await joined(env, w, "mod2")
        # a socket that never takes a frame must neither hold the answer nor the other sockets
        server.chat_rooms[name].add((StuckWs(), u["friend"], "friend", "user", "{}"))

        async def audit(action, target):
            entries = await d.get_audit_log(limit=200, channel_id=cid)
            return [e for e in entries if e["action"] == action and e["target_id"] == target]

        # demoted by an admin
        mark = friend.mark()
        t0 = asyncio.get_running_loop().time()
        st, _ = await env.call("PUT", u["admin"], f"/api/chat/channels/{cid}/members/{u['friend']}",
                               json={"role": "member"})
        assert st == 200 and asyncio.get_running_loop().time() - t0 < 1.5, "the answer waited for a socket"
        got = await friend.wait(lambda e: e.get("type") == "mod_level", mark)
        assert got and got["mod_level"] == server.CHAT_LEVEL_NAMES[NONE], got
        rows = await audit("stream_mod_remove", u["friend"])
        assert rows and rows[0]["actor_id"] == u["admin"], rows
        # a plain demotion of a member who was no mod writes nothing
        st, _ = await env.call("PUT", u["admin"], f"/api/chat/channels/{cid}/members/{u['plain']}",
                               json={"role": "member"})
        assert st == 200 and not await audit("stream_mod_remove", u["plain"])
        # removed by an admin
        mark = mod2.mark()
        st, _ = await env.call("DELETE", u["admin"], f"/api/chat/channels/{cid}/members/{u['mod2']}")
        assert st == 200
        got = await mod2.wait(lambda e: e.get("type") == "mod_level", mark)
        assert got and got["mod_level"] == server.CHAT_LEVEL_NAMES[NONE], got
        rows = await audit("stream_mod_remove", u["mod2"])
        assert rows and rows[0]["actor_id"] == u["admin"], rows
        # left by the mod himself
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{w.stream['a']}/mods", json={"user_id": u["plain"]})
        assert st == 201
        plain = await joined(env, w, "plain")
        mark = plain.mark()
        st, _ = await env.call("DELETE", u["plain"], f"/api/chat/channels/{cid}/members/{u['plain']}")
        assert st == 200
        rows = await audit("stream_mod_remove", u["plain"])
        assert rows and rows[0]["actor_id"] == u["plain"], rows
        assert rows[0]["details"] is not None and server.CHAT_LEVEL_NAMES[MOD] in str(rows[0]["details"]), rows[0]
        # added as a plain member over the generic route: the appointment ends the same way
        st, _ = await env.call("POST", u["owner"], f"/api/streams/{w.stream['a']}/mods", json={"user_id": u["plain"]})
        assert st == 201
        before = len(await audit("stream_mod_remove", u["plain"]))
        st, _ = await env.call("POST", u["admin"], f"/api/chat/channels/{cid}/members",
                               json={"user_id": u["plain"], "role": "member"})
        assert st == 201
        assert len(await audit("stream_mod_remove", u["plain"])) == before + 1
        assert u["plain"] not in await d.get_channel_moderator_ids(cid)
        await asyncio.wait_for(asyncio.gather(*list(server._mod_level_tasks)), 4)
    run(body)


def test_a_ban_over_the_socket_removes_the_viewer_and_his_whep_sessions():
    async def body(env):
        d = env.db
        w = await World().build(d)
        sid, u = w.stream["a"], w.u
        saved = server._viewers
        server._viewers = server._viewers_mod.ViewerTracker()
        server._webrtc_sessions.clear()
        try:
            server._viewers.touch(sid, user_id=u["spammer"])
            server._viewers.touch(sid, user_id=u["plain"])
            server._webrtc_session_remember("s-spam", "whep", sid, "p", u["spammer"])
            server._webrtc_session_remember("s-plain", "whep", sid, "p", u["plain"])
            owner = await joined(env, w, "owner")
            got = await owner.act("ban_success", type="ban", user_id=u["spammer"])
            assert got["type"] == "ban_success", got
            assert server._viewers.count(sid) == 1
            assert "s-spam" not in server._webrtc_sessions and "s-plain" in server._webrtc_sessions
        finally:
            server._viewers = saved
            server._webrtc_sessions.clear()
    run(body)


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
