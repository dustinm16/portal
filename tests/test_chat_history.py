"""Channel scrollback: older pages, jump-to-message windows and the access and
anonymity rules that every way of reading older messages shares.

Join, the WebSocket history_page message and GET /api/chat/channels/{id}/messages
all run through _can_read_channel and _enrich_channel_messages. This test runs
the real chat websocket handler and the real HTTP handler in-process (only the
authentication lookup is replaced) against a temporary database and compares
what the three paths send for the same viewer.

Run: venv/bin/python tests/test_chat_history.py
"""

import asyncio
import inspect
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

SERVER_SRC = (ROOT / "server.py").read_text(encoding="utf-8")

ANON_NAME = "anonreal_zq"
ANON_AVATAR = "AVATARZQ"
ANON_NICK = "NickZQ"


class Tok:
    def __init__(self, user_id):
        self.user_id = user_id
        self.token_id = "t%d" % user_id


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    return Tok(int(uid)) if uid else None


async def fake_valid(token):
    return True


class Env:
    """Temporary database, the real handlers on a loopback test server."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}

    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth),
                            ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server._history_hits.clear()
        server._search_rate_limits.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/api/chat/channels/{id}/messages", server.http_get_channel_messages)
        app.router.add_get("/api/chat/thread/{id}", server.http_get_chat_thread)
        app.router.add_get("/api/chat/search", server.http_search_messages)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        await self.http.close()
        await self.srv.close()
        for name, value in self.saved.items():
            setattr(server, name, value)
        server.chat_rooms.clear()
        await self.db.close()
        self.tmp.cleanup()

    def url(self, path):
        return str(self.srv.make_url(path))

    async def ws(self, user_id):
        sock = await self.http.ws_connect(self.url("/ws/chat"), headers={"X-Test-User": str(user_id)})
        return Sock(sock)

    async def get(self, user_id, channel_id, **params):
        async with self.http.get(self.url(f"/api/chat/channels/{channel_id}/messages"),
                                 params=params, headers={"X-Test-User": str(user_id)}) as r:
            return r.status, await r.json(), dict(r.headers)


    async def search(self, user_id, q, **params):
        async with self.http.get(self.url("/api/chat/search"), params=dict(q=q, **params),
                                 headers={"X-Test-User": str(user_id)}) as r:
            return r.status, await r.json()

    async def thread(self, user_id, message_id):
        async with self.http.get(self.url(f"/api/chat/thread/{message_id}"),
                                 headers={"X-Test-User": str(user_id)}) as r:
            return r.status, await r.json(), dict(r.headers)


class Sock:
    def __init__(self, ws):
        self.ws = ws

    async def send(self, **payload):
        await self.ws.send_json(payload)

    async def until(self, *types, timeout=5):
        while True:
            msg = await asyncio.wait_for(self.ws.receive(), timeout)
            if msg.type != aiohttp.WSMsgType.TEXT:
                raise AssertionError(f"socket ended: {msg.type}")
            data = json.loads(msg.data)
            if data.get("type") in types:
                return data

    async def join(self, channel_id):
        await self.send(type="join", channel_id=channel_id)
        return await self.until("history", "error")

    async def close(self):
        await self.ws.close()


def canon(m):
    return json.dumps(m, sort_keys=True)


async def seed(d):
    """Users, a public channel with 130 messages and the special cases."""
    ids = {}
    for name in ("alice", "bob", "mod", "boss", ANON_NAME, "reactor", "outsider", "carol"):
        ids[name] = await d.create_user(name, "x")
    await d.set_user_role(ids["mod"], "moderator")
    await d.set_user_role(ids["boss"], "admin")
    await d.set_user_nickname(ids["alice"], "Ally")
    await d.set_user_nickname(ids["carol"], "Caz")
    await d.set_avatar(ids[ANON_NAME], {"color": "#112233", "emoji": ANON_AVATAR, "initials": "ZQ"})
    await d.set_user_nickname(ids[ANON_NAME], ANON_NICK)
    await d.set_chat_anonymous(ids[ANON_NAME], True)
    await d.set_chat_anonymous(ids["reactor"], True)
    cid = await d.create_chat_channel("hist1", created_by=ids["alice"])
    msgs = {}
    for i in range(1, 131):
        who = "alice" if i % 3 else "bob"
        kw = {}
        text = f"message number {i}"
        if i == 3:      # the only post of a member with a nickname, long before the replies to it
            who = "carol"
        if i in (12, 55, 98, 121):
            who, kw = ANON_NAME, {"anonymous": True}
            text = f"anonymous post {i}"
        if i == 110:    # reply to an old message of a member who is not on this page
            kw = {"reply_to": msgs[3]["id"], "reply_preview_username": "carol", "reply_preview_text": "old"}
        if i == 111:    # reply to an anonymous message, on another page than its target
            kw = {"reply_to": msgs[12]["id"], "reply_preview_username": "Anonymous", "reply_preview_text": "x"}
        if i == 98:     # an anonymous reply
            kw.update(reply_to=msgs[60]["id"], reply_preview_username="alice", reply_preview_text="y")
        mid = await d.create_chat_message(cid, ids[who], who, text, **kw)
        msgs[i] = {"id": mid, "who": who}
    # a reply whose original is gone keeps the stored preview
    gone = await d.create_chat_message(cid, ids["bob"], "bob", "to be deleted")
    await d.create_chat_message(cid, ids["alice"], "alice", "reply to nothing", reply_to=gone,
                                reply_preview_username="bob", reply_preview_text="to be deleted")
    await d.delete_chat_message(gone)
    # reactions: by the anonymous participant and by an anonymous-mode reactor, and a plain one
    await d.toggle_reaction(msgs[100]["id"], ids[ANON_NAME], "+1")
    await d.toggle_reaction(msgs[100]["id"], ids["reactor"], "+1")
    await d.toggle_reaction(msgs[100]["id"], ids["bob"], "+1")
    await d.toggle_reaction(msgs[55]["id"], ids["reactor"], "ok")
    # a poll by the anonymous participant, an edit marker on an anonymous post
    pid = await d.create_poll(cid, ids[ANON_NAME], "which", ["a", "b"], message_id=msgs[121]["id"])
    assert pid
    await d.conn.execute("UPDATE chat_messages SET edited_at = ? WHERE id = ?",
                         ("2026-01-01T00:00:00+00:00", msgs[98]["id"]))
    await d.conn.commit()
    return ids, cid, msgs


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


# ---------------------------------------------------------------------------

def test_request_parsing():
    p = server._parse_history_request
    assert p(None, None, None) == (None, None, 50)
    assert p("7", None, "20") == (7, None, 20)
    assert p(None, 9, 5000) == (None, 9, 100), "size is capped at 100"
    assert p(None, None, "") == (None, None, 50)
    for bad in ((1, 2, None), ("x", None, None), (0, None, None), (-3, None, None),
                (None, "abc", None), (None, None, 0), (None, None, "x"), (True, None, None)):
        try:
            p(*bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")
    top = 2 ** 63 - 1
    assert p(top, None, None)[0] == top and p(None, top, None)[1] == top, "the largest SQLite id is fine"
    for bad in ((top + 1, None, None), (None, top + 1, None), (10 ** 20, None, None), (1e20, None, None),
                ("99999999999999999999", None, None), (float("inf"), None, None),
                (None, None, float("inf")), (float("nan"), None, None)):
        try:
            p(*bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_paging_walks_back_to_the_start_without_gaps_or_duplicates():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        ch = await env.db.get_chat_channel(cid)
        page = await server._channel_history(ch, ids["bob"], "user")
        got = [m["id"] for m in page["messages"]]
        assert len(got) == 50 and page["has_more"] and not page["has_newer"]
        pages = 1
        while page["has_more"]:
            page = await server._channel_history(ch, ids["bob"], "user", before_id=page["messages"][0]["id"])
            got = [m["id"] for m in page["messages"]] + got
            pages += 1
        cur = await env.db.conn.execute("SELECT id FROM chat_messages WHERE channel_id = ? ORDER BY id", (cid,))
        every = [r["id"] for r in await cur.fetchall()]
        assert got == every, "oldest first, every message once"
        assert pages == 3 and len(every) == 131
        # the size cap and a page that is exactly full
        big = await server._channel_history(ch, ids["bob"], "user", limit=100)
        assert len(big["messages"]) == 100 and big["has_more"]
        exact = await server._channel_history(ch, ids["bob"], "user", before_id=every[50], limit=50)
        assert len(exact["messages"]) == 50 and not exact["has_more"], "50 older exist, none beyond"
    run(body)


def test_around_window_and_missing_target():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        ch = await env.db.get_chat_channel(cid)
        target = msgs[60]["id"]
        w = await server._channel_history(ch, ids["bob"], "user", around_id=target, limit=50)
        got = [m["id"] for m in w["messages"]]
        assert target in got and got == sorted(got) and len(got) == 50
        assert w["found"] and w["has_more"] and w["has_newer"]
        first = await server._channel_history(ch, ids["bob"], "user", around_id=msgs[2]["id"], limit=50)
        assert first["found"] and not first["has_more"] and first["has_newer"]
        last = await server._channel_history(ch, ids["bob"], "user", around_id=msgs[130]["id"], limit=50)
        assert last["found"] and last["has_more"]
        cur = await env.db.conn.execute("SELECT MAX(id) AS m FROM chat_messages")
        newest = (await cur.fetchone())["m"]
        end = await server._channel_history(ch, ids["bob"], "user", around_id=newest, limit=50)
        assert not end["has_newer"]
        # another channel's message, a deleted one and an unknown id all read as not found
        other = await env.db.create_chat_channel("hist2")
        theirs = await env.db.create_chat_message(other, ids["bob"], "bob", "elsewhere")
        for missing in (theirs, 999999):
            r = await server._channel_history(ch, ids["bob"], "user", around_id=missing)
            assert r["found"] is False and r["messages"] == [] and not r["has_more"]
    run(body)


def test_access_rules():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        pub = await d.get_chat_channel(cid)
        can = server._can_read_channel
        assert await can(pub, ids["bob"], "user")
        assert not await can(None, ids["bob"], "user")
        priv_id = await d.create_chat_channel("secret1", created_by=ids["alice"])
        await d.update_chat_channel(priv_id, visibility="private")
        priv = await d.get_chat_channel(priv_id)
        assert not await can(priv, ids["bob"], "user")
        assert (await can(priv, ids["bob"], "user")).reason == "private"
        assert not await can(priv, ids["mod"], "moderator"), "moderators are not exempt from membership"
        assert await can(priv, ids["boss"], "admin") and await can(priv, ids["boss"], "superadmin")
        await d.add_channel_member(priv_id, ids["bob"])
        assert await can(priv, ids["bob"], "user")
        await d.remove_channel_member(priv_id, ids["bob"])
        assert not await can(priv, ids["bob"], "user"), "a removed member is out at once"
        # stream ban: the channel belongs to a stream and the member is banned from it
        sid = await d.create_user_stream(ids["alice"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                         is_public=True)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
        await d.conn.commit()
        assert await can(pub, ids["bob"], "user")
        await d.create_stream_ban(sid, ids["bob"], ids["alice"], "r")
        denied = await can(pub, ids["bob"], "user")
        assert not denied and denied.reason == "banned"
        assert await can(pub, ids["alice"], "user")
        # the caller may pass the stream it already has
        stream = await d.get_stream_by_chat_channel(cid)
        assert not await can(pub, ids["bob"], "user", stream)
        assert await can(pub, ids["bob"], "user", None), "None means: no stream, no ban to check"
    run(body)


def test_removed_member_gets_nothing_on_the_same_socket_and_over_http():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        priv_id = await d.create_chat_channel("secret2", created_by=ids["alice"])
        await d.update_chat_channel(priv_id, visibility="private")
        await d.add_channel_member(priv_id, ids["bob"])
        await d.create_chat_message(priv_id, ids["alice"], "alice", "members only text")
        sock = await env.ws(ids["bob"])
        hist = await sock.join(priv_id)
        assert hist["type"] == "history" and len(hist["messages"]) == 1
        status, body_, _ = await env.get(ids["bob"], priv_id)
        assert status == 200 and len(body_["messages"]) == 1
        await d.remove_channel_member(priv_id, ids["bob"])
        await sock.send(type="history_page", before_id=10**6, req=1)
        err = await sock.until("history_older", "history_around", "history_error")
        assert err["type"] == "history_error" and err["error_code"] == "not_found" and "messages" not in err, err
        assert "members only text" not in json.dumps(err)
        status, body_, _ = await env.get(ids["bob"], priv_id)
        assert status == 404 and body_ == {"error": "Channel not found"}
        # the same answer as for a channel that does not exist, and for one never joined
        status2, body2, _ = await env.get(ids["bob"], 987654)
        assert (status2, body2) == (404, {"error": "Channel not found"})
        status3, body3, _ = await env.get(ids["outsider"], priv_id)
        assert (status3, body3) == (404, {"error": "Channel not found"})
        await sock.close()
    run(body)


async def link_stream(d, ids, cid, public):
    sid = await d.create_user_stream(ids["alice"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                     is_public=public)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
    await d.conn.commit()
    return sid


def test_private_stream_chat_is_closed_to_everyone_but_owner_and_admins():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        ch = await d.get_chat_channel(cid)
        can = server._can_read_channel
        sid = await link_stream(d, ids, cid, public=False)
        for name, role in (("bob", "user"), ("mod", "moderator"), ("outsider", "user")):
            denied = await can(ch, ids[name], role)
            assert not denied and denied.reason == "hidden" and denied.message == "Channel not found", name
        # a banned member gets the same answer, not a hint that the stream exists
        await d.create_stream_ban(sid, ids["bob"], ids["alice"], "r")
        assert (await can(ch, ids["bob"], "user")).message == "Channel not found"
        for name, role in (("alice", "user"), ("boss", "admin"), (ids and "boss", "superadmin")):
            assert await can(ch, ids[name], role), name
        # the stream is made public: members read it again
        await d.update_user_stream(sid, is_public=1)
        assert await can(ch, ids["outsider"], "user")
        # a stream without a public flag at all counts as not public
        await d.conn.execute("UPDATE user_streams SET is_public = NULL WHERE id = ?", (sid,))
        await d.conn.commit()
        assert not await can(ch, ids["outsider"], "user")
        # a channel whose stream no longer exists behaves as any other channel
        await d.conn.execute("DELETE FROM user_streams WHERE id = ?", (sid,))
        await d.conn.commit()
        assert await can(ch, ids["outsider"], "user")
    run(body)


def test_private_stream_chat_join_page_route_thread_and_send():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        sid = await link_stream(d, ids, cid, public=True)
        # bob joins while the stream is public and keeps his socket
        bob = await env.ws(ids["bob"])
        assert (await bob.join(cid))["type"] == "history"
        status, body_, headers = await env.get(ids["bob"], cid)
        assert status == 200
        assert headers.get("Cache-Control") == "private, no-store", headers
        status, th, headers = await env.thread(ids["bob"], msgs[110]["id"])
        assert status == 200 and th["thread"] and headers.get("Cache-Control") == "private, no-store", headers
        # the owner turns the stream private
        await d.update_user_stream(sid, is_public=0)
        before = (await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_messages")).fetchone())["n"]
        # the open socket: no more pages, and sending is refused
        await bob.send(type="history_page", before_id=10 ** 6, req=1)
        err = await bob.until("history_older", "history_around", "history_error")
        assert err["type"] == "history_error" and err["error_code"] == "not_found" and "messages" not in err, err
        await bob.send(type="message", channel="hist1", message="typed into a closed chat")
        err = await bob.until("error", "message")
        assert err["type"] == "error" and err["message"] == "Channel not found", err
        await bob.send(type="edit_message", message_id=msgs[6]["id"], message="edited in a closed chat")
        err = await bob.until("error", "message_edited")
        assert err["type"] == "error" and err["message"] == "Channel not found", err
        after = (await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_messages")).fetchone())["n"]
        assert after == before, "nothing was stored"
        # joining by channel id, by stream key and by name: the answer of a missing channel
        other = await env.ws(ids["outsider"])
        for payload in ({"channel_id": cid}, {"channel": "hist1"}, {"stream_key": "pub_" + "b" * 24}):
            await other.send(type="join", **payload)
            err = await other.until("history", "error")
            assert err["type"] == "error" and err["message"] == "Channel not found", (payload, err)
        # HTTP: history and thread answer exactly as for a missing channel / message
        status, body_, headers = await env.get(ids["bob"], cid)
        assert (status, body_) == (404, {"error": "Channel not found"})
        status2, body2, _ = await env.get(ids["bob"], 987654)
        assert (status2, body2) == (status, body_)
        status, th, headers = await env.thread(ids["bob"], msgs[110]["id"])
        assert (status, th) == (404, {"error": "Message not found"}), (status, th)
        assert headers.get("Cache-Control") == "private, no-store"
        status2, th2, _ = await env.thread(ids["bob"], 987654)
        assert (status2, th2) == (status, th)
        # the owner and an admin read, join and write as before
        for name in ("alice", "boss"):
            status, body_, _ = await env.get(ids[name], cid)
            assert status == 200 and body_["messages"], name
            status, th, _ = await env.thread(ids[name], msgs[110]["id"])
            assert status == 200 and th["thread"], name
        owner = await env.ws(ids["alice"])
        assert (await owner.join(cid))["type"] == "history"
        await owner.send(type="message", channel="hist1", message="owner writes")
        got = await owner.until("message", "error")
        assert got["type"] == "message", got
        await bob.close()
        await other.close()
        await owner.close()
    run(body)


def test_refused_join_leaves_no_channel_to_send_to():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        closed = await d.create_chat_channel("streamchat", created_by=ids["alice"])
        sid = await d.create_user_stream(ids["alice"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                         is_public=False)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (closed, sid))
        await d.conn.commit()
        bob = await env.ws(ids["bob"])
        assert (await bob.join(cid))["type"] == "history"
        await bob.send(type="join", channel="streamchat")
        err = await bob.until("history", "error")
        assert err["type"] == "error" and err["message"] == "Channel not found", err
        before = (await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_messages")).fetchone())["n"]
        reacts = (await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_reactions")).fetchone())["n"]
        polls = (await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_polls")).fetchone())["n"]
        # the next sends are meant for the closed chat: none may land in the room that was left
        await bob.send(type="message", channel="streamchat", message="MEANT-FOR-STREAMCHAT")
        await bob.send(type="react", message_id=msgs[100]["id"], emoji="x1")
        await bob.send(type="create_poll", question="q?", options=["a", "b"])
        # a request that always answers, so the handler has gone through everything above
        await bob.send(type="history_page", before_id=10 ** 6, req=7)
        got = await bob.until("history_older", "history_around", "history_error", "error", "message",
                              "reaction_update", "poll_created")
        assert got["type"] == "history_error" and got["error_code"] == "not_found", got
        count = lambda t: d.conn.execute("SELECT COUNT(*) AS n FROM " + t)
        assert (await (await count("chat_messages")).fetchone())["n"] == before, "nothing was stored"
        assert (await (await count("chat_reactions")).fetchone())["n"] == reacts
        assert (await (await count("chat_polls")).fetchone())["n"] == polls
        # a refused join by channel id clears it the same way
        await bob.close()
        bob = await env.ws(ids["bob"])
        assert (await bob.join(cid))["type"] == "history"
        await bob.send(type="join", channel_id=closed)
        assert (await bob.until("history", "error"))["type"] == "error"
        await bob.send(type="message", channel="hist1", message="MEANT-FOR-STREAMCHAT-2")
        await bob.send(type="history_page", before_id=10 ** 6, req=8)
        assert (await bob.until("history_older", "history_around", "history_error"))["type"] == "history_error"
        row = await (await d.conn.execute("SELECT COUNT(*) AS n FROM chat_messages WHERE message LIKE 'MEANT-FOR%'")).fetchone()
        assert row["n"] == 0
        # a refused join does not break a later successful one
        assert (await bob.join(cid))["type"] == "history"
        await bob.send(type="message", channel="hist1", message="fine again")
        assert (await bob.until("message", "error"))["type"] == "message"
        await bob.close()
    run(body)


def test_open_socket_cannot_react_poll_or_vote_after_the_chat_closes():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        sid = await link_stream(d, ids, cid, public=True)
        poll_row = await (await d.conn.execute("SELECT id FROM chat_polls WHERE channel_id = ?", (cid,))).fetchone()
        poll_id = poll_row["id"]
        bob = await env.ws(ids["bob"])
        alice = await env.ws(ids["alice"])
        assert (await bob.join(cid))["type"] == "history"
        assert (await alice.join(cid))["type"] == "history"
        # while the stream is public all three work
        await bob.send(type="react", message_id=msgs[100]["id"], emoji="p1")
        assert (await bob.until("reaction_update", "error"))["type"] == "reaction_update"
        await bob.send(type="vote_poll", poll_id=poll_id, option_index=0)
        assert (await bob.until("poll_updated", "error"))["type"] == "poll_updated"
        await bob.send(type="create_poll", question="open?", options=["a", "b"])
        assert (await bob.until("poll_created", "error"))["type"] == "poll_created"
        count = lambda t, w="1": d.conn.execute("SELECT COUNT(*) AS n FROM " + t + " WHERE " + w)
        reacts = (await (await count("chat_reactions")).fetchone())["n"]
        votes = (await (await count("chat_poll_votes")).fetchone())["n"]
        polls = (await (await count("chat_polls")).fetchone())["n"]
        msgn = (await (await count("chat_messages")).fetchone())["n"]
        await d.update_user_stream(sid, is_public=0)
        for payload in (dict(type="react", message_id=msgs[100]["id"], emoji="p2"),
                        dict(type="vote_poll", poll_id=poll_id, option_index=1),
                        dict(type="create_poll", question="closed?", options=["a", "b"])):
            await bob.send(**payload)
            err = await bob.until("error", "reaction_update", "poll_updated", "poll_created")
            assert err["type"] == "error" and err["message"] == "Channel not found", (payload["type"], err)
        assert (await (await count("chat_reactions")).fetchone())["n"] == reacts
        assert (await (await count("chat_poll_votes")).fetchone())["n"] == votes
        assert (await (await count("chat_polls")).fetchone())["n"] == polls
        assert (await (await count("chat_messages")).fetchone())["n"] == msgn
        # the owner still does all three, and the stream-banned member is refused too
        await alice.send(type="react", message_id=msgs[100]["id"], emoji="p3")
        assert (await alice.until("reaction_update", "error"))["type"] == "reaction_update"
        await d.update_user_stream(sid, is_public=1)
        await d.create_stream_ban(sid, ids["bob"], ids["alice"], "r")
        for payload in (dict(type="react", message_id=msgs[100]["id"], emoji="p4"),
                        dict(type="vote_poll", poll_id=poll_id, option_index=1),
                        dict(type="create_poll", question="banned?", options=["a", "b"])):
            await bob.send(**payload)
            # (the owner's reaction above still reaches his open socket as a broadcast: skipped)
            err = await bob.until("error")
            assert "banned" in err["message"], (payload["type"], err)
        await bob.close()
        await alice.close()
    run(body)


def test_search_does_not_return_the_chat_of_a_private_stream():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        await d.create_chat_message(cid, ids["alice"], "alice", "zebrasecret plans")
        # a channel with no stream stays searchable for everyone
        status, got = await env.search(ids["outsider"], "zebrasecret")
        assert status == 200 and got["total"] == 1, got
        sid = await link_stream(d, ids, cid, public=False)
        for name in ("outsider", "bob", "mod"):
            for params in ({}, {"scope": "channels"}, {"channel_id": cid}):
                status, got = await env.search(ids[name], "zebrasecret", **params)
                assert status == 200 and got["results"] == [] and got["total"] == 0, (name, params, got)
        # the owner and admins still find it
        for name in ("alice", "boss"):
            status, got = await env.search(ids[name], "zebrasecret")
            assert status == 200 and got["total"] == 1 and got["results"][0]["source_name"] == "#hist1", (name, got)
        # the channel itself is still listed for others (only reading is closed)
        names = {c["name"] for c in await d.get_accessible_channels(ids["outsider"], "user")}
        assert "hist1" in names
        # public again: everyone finds it
        await d.update_user_stream(sid, is_public=1)
        status, got = await env.search(ids["outsider"], "zebrasecret")
        assert status == 200 and got["total"] == 1, got
    run(body)


def test_thread_route_follows_the_channel_rules():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        priv_id = await d.create_chat_channel("secret3", created_by=ids["alice"])
        await d.update_chat_channel(priv_id, visibility="private")
        await d.add_channel_member(priv_id, ids["bob"])
        root = await d.create_chat_message(priv_id, ids["alice"], "alice", "private root")
        reply = await d.create_chat_message(priv_id, ids["bob"], "bob", "private reply", reply_to=root)
        status, th, _ = await env.thread(ids["bob"], reply)
        assert status == 200 and [m["id"] for m in th["thread"]] == [root, reply]
        # a removed member and a non-member: 404, same as a message that does not exist
        await d.remove_channel_member(priv_id, ids["bob"])
        for who in ("bob", "outsider"):
            status, th, _ = await env.thread(ids[who], reply)
            assert (status, th) == (404, {"error": "Message not found"}), (who, status, th)
        status, th, _ = await env.thread(ids["bob"], 987654)
        assert (status, th) == (404, {"error": "Message not found"})
        status, th, _ = await env.thread(ids["bob"], 2 ** 63)
        assert (status, th) == (404, {"error": "Message not found"}), "an id beyond SQLite is a missing message"
        async with env.http.get(env.url("/api/chat/thread/abc"), headers={"X-Test-User": str(ids["bob"])}) as r:
            assert r.status == 400
        async with env.http.get(env.url(f"/api/chat/thread/{reply}")) as r:
            assert r.status == 401
        status, th, _ = await env.thread(ids["boss"], reply)
        assert status == 200, "admins read every channel"
        # a stream ban closes the thread too
        sid = await link_stream(d, ids, cid, public=True)
        status, th, _ = await env.thread(ids["bob"], msgs[110]["id"])
        assert status == 200
        await d.create_stream_ban(sid, ids["bob"], ids["alice"], "r")
        status, th, _ = await env.thread(ids["bob"], msgs[110]["id"])
        assert (status, th) == (404, {"error": "Message not found"})
        # same display data and masking as the history: reactions and anonymous authors
        status, th, _ = await env.thread(ids["carol"], msgs[111]["id"])
        assert status == 200
        raw = json.dumps(th)
        assert ANON_NAME not in raw and ANON_AVATAR not in raw and ANON_NICK not in raw, raw
        assert all("reactions" in m for m in th["thread"])
        status, th, _ = await env.thread(ids["boss"], msgs[111]["id"])
        assert status == 200 and th["thread"][0]["user_id"] == ids[ANON_NAME], "admins still get the author id"
        assert th["thread"][0]["username"] == "Anonymous"
    run(body)


def test_http_route_rules():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        async with env.http.get(env.url(f"/api/chat/channels/{cid}/messages")) as r:
            assert r.status == 401, "no credential, no history"
        status, body_, _ = await env.get(ids["bob"], cid)
        assert status == 200 and len(body_["messages"]) == 50 and body_["has_more"]
        status, body_, _ = await env.get(ids["bob"], cid, limit=1000)
        assert status == 200 and len(body_["messages"]) == 100
        for params in ({"limit": "0"}, {"limit": "x"}, {"before_id": "x"}, {"before_id": "5", "around_id": "6"}):
            status, body_, _ = await env.get(ids["bob"], cid, **params)
            assert status == 400 and "error" in body_, (params, status)
        async with env.http.get(env.url("/api/chat/channels/notanumber/messages"),
                                headers={"X-Test-User": str(ids["bob"])}) as r:
            assert r.status == 404
        # ids beyond what SQLite holds: a 400 / 404, never a 500
        for params in ({"before_id": str(2 ** 63)}, {"around_id": str(2 ** 63)},
                       {"before_id": "99999999999999999999"}):
            status, body_, _ = await env.get(ids["bob"], cid, **params)
            assert status == 400 and "error" in body_, (params, status)
        for big_id in (2 ** 63, 99999999999999999999):
            status, body_, _ = await env.get(ids["bob"], big_id)
            assert status == 404, (big_id, status)
    run(body)


def test_three_paths_send_identical_messages_and_never_unmask():
    async def body(env):
        d = env.db
        ids, cid, msgs = await seed(d)
        anon_ref = server._anon_ref("hist1", ids[ANON_NAME])
        newest = (await (await d.conn.execute("SELECT MAX(id) AS m FROM chat_messages")).fetchone())["m"]
        viewers = (("bob", "user"), ("alice", "user"), ("mod", "moderator"),
                   ("boss", "admin"), (ANON_NAME, "user"))
        for name, role in viewers:
            uid = ids[name]
            sock = await env.ws(uid)
            joined = await sock.join(cid)
            assert joined["type"] == "history" and joined["channel_id"] == cid
            seen = {m["id"]: m for m in joined["messages"]}
            sources = {"join": dict(seen)}
            # history_page: older pages down to the start, and a window around an old message
            older, cursor, hops = {}, joined["messages"][0]["id"], 0
            while True:
                await sock.send(type="history_page", before_id=cursor, req=hops)
                page = await sock.until("history_older", "history_error")
                assert page["type"] == "history_older" and page["req"] == hops, page
                older.update({m["id"]: m for m in page["messages"]})
                hops += 1
                if not page["has_more"]:
                    break
                cursor = page["messages"][0]["id"]
            sources["ws older"] = older
            await sock.send(type="history_page", around_id=msgs[60]["id"], limit=100, req="a")
            around = await sock.until("history_around", "history_error")
            assert around["type"] == "history_around" and around["found"], around
            sources["ws around"] = {m["id"]: m for m in around["messages"]}
            await sock.send(type="history_page", req="n")
            latest = await sock.until("history_around", "history_error")
            assert not latest["has_newer"] and latest["messages"][-1]["id"] == newest
            sources["ws latest"] = {m["id"]: m for m in latest["messages"]}
            # the HTTP route: the same three kinds of request
            http = {}
            status, b1, _ = await env.get(uid, cid)
            assert status == 200
            http.update({m["id"]: m for m in b1["messages"]})
            cursor = b1["messages"][0]["id"]
            while True:
                status, b2, _ = await env.get(uid, cid, before_id=cursor)
                assert status == 200
                http.update({m["id"]: m for m in b2["messages"]})
                if not b2["has_more"]:
                    break
                cursor = b2["messages"][0]["id"]
            status, b3, _ = await env.get(uid, cid, around_id=msgs[60]["id"], limit=100)
            assert status == 200 and b3["found"]
            sources["http around"] = {m["id"]: m for m in b3["messages"]}
            sources["http pages"] = http
            # every message that more than one path sent is byte-identical
            by_id = {}
            for label, got in sources.items():
                for mid, m in got.items():
                    by_id.setdefault(mid, []).append((label, canon(m)))
            overlap = 0
            for mid, versions in by_id.items():
                if len(versions) > 1:
                    overlap += 1
                    assert len({v for _, v in versions}) == 1, (name, mid, versions)
            assert overlap >= 100, (name, overlap)
            # all messages together came from the paths: the whole channel: 130 posts and one reply, the deleted original is gone
            assert len(by_id) == 131, (name, len(by_id))
            if (name, role) == ("bob", "user"):
                text = json.dumps(sources, sort_keys=True)
                for secret in (ANON_NAME, ANON_AVATAR, ANON_NICK, anon_ref):
                    assert secret not in text, f"member sees {secret!r}"
                for label, got in sources.items():
                    for m in got.values():
                        assert m.get("user_id") != ids[ANON_NAME], (label, m["id"])
                        if m.get("anonymous"):
                            assert m["user_id"] is None and m["role"] is None, (label, m)
                            assert m["username"] == "Anonymous" and m["avatar"] == {} and m["nickname"] is None
                        for r in m.get("reactions", []):
                            assert ids[ANON_NAME] not in r["user_ids"] and ids["reactor"] not in r["user_ids"], m
                        if m.get("poll"):
                            assert m["poll"]["user_id"] is None, m
                        for key in ("reply_preview",):
                            if m.get(key):
                                assert ANON_NAME not in json.dumps(m[key])
                sample = by_id[msgs[111]["id"]]
                assert json.loads(sample[0][1])["reply_preview"]["username"] == "Anonymous"
                assert json.loads(by_id[msgs[98]["id"]][0][1])["edited_at"], "the edit marker is kept"
                # a reply to a member with a nickname shows the nickname on every page, also when the
                # member's own post is on another page (it used to show the account name there)
                for label, got in sources.items():
                    if msgs[110]["id"] in got:
                        assert got[msgs[110]["id"]]["reply_preview"]["username"] == "Caz", label
                # reactions: the plain one is there, the anonymous ones lost their ids only
                for got in sources.values():
                    if msgs[100]["id"] in got:
                        r = got[msgs[100]["id"]]["reactions"][0]
                        assert r["count"] == 3 and r["user_ids"] == [ids["bob"]], r
            if name in ("mod", "boss", ANON_NAME):
                # staff and the author still get the id (edit, delete and moderation need it)
                m = sources["join"][msgs[121]["id"]] if msgs[121]["id"] in sources["join"] else None
                assert m and m["user_id"] == ids[ANON_NAME] and m["username"] == "Anonymous", (name, m)
                assert m["nickname"] is None and m["avatar"] == {}
                assert m["poll"]["user_id"] == ids[ANON_NAME]
            if name == "alice":
                m = sources["join"][msgs[121]["id"]]
                assert m["user_id"] is None
            # the deleted original: stored preview, flagged
            tail = sources["join"][newest]
            assert tail["reply_preview"]["deleted"] is True and tail["reply_preview"]["username"] == "bob"
            await sock.close()
    run(body)


def test_pages_do_not_mark_anything_as_read():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        sock = await env.ws(ids["bob"])
        joined = await sock.join(cid)
        await sock.until("users")
        cur = await env.db.conn.execute(
            "SELECT last_read_message_id AS m FROM channel_read_positions WHERE user_id = ? AND channel_id = ?",
            (ids["bob"], cid))
        at_join = (await cur.fetchone())["m"]
        assert at_join == joined["messages"][-1]["id"], "join still marks the channel read"
        await env.db.conn.execute("UPDATE channel_read_positions SET last_read_message_id = 1 "
                                  "WHERE user_id = ? AND channel_id = ?", (ids["bob"], cid))
        await env.db.conn.commit()
        await sock.send(type="history_page", before_id=joined["messages"][0]["id"])
        await sock.until("history_older")
        await sock.send(type="history_page", around_id=msgs[100]["id"])
        await sock.until("history_around")
        await sock.send(type="history_page")
        await sock.until("history_around")
        status, _, _ = await env.get(ids["bob"], cid, around_id=msgs[100]["id"])
        assert status == 200
        cur = await env.db.conn.execute(
            "SELECT last_read_message_id AS m FROM channel_read_positions WHERE user_id = ? AND channel_id = ?",
            (ids["bob"], cid))
        assert (await cur.fetchone())["m"] == 1
        await sock.close()
    run(body)


def test_rate_limit_is_per_user_across_sockets_and_http():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        clock = [1000.0]
        saved = server.monotonic
        server.monotonic = lambda: clock[0]
        try:
            a, b = await env.ws(ids["bob"]), await env.ws(ids["bob"])
            await a.join(cid)
            await b.join(cid)
            ok = 0
            for i in range(30):
                sock = a if i % 2 else b
                await sock.send(type="history_page", req=i)
                if (await sock.until("history_around", "history_error"))["type"] == "history_around":
                    ok += 1
            assert ok == 30
            await a.send(type="history_page", req="x")
            err = await a.until("history_around", "history_error")
            assert err["type"] == "history_error" and err["error_code"] == "rate_limited" and err["retry_after"] >= 1
            assert err["req"] == "x"
            status, body_, headers = await env.get(ids["bob"], cid)
            assert status == 429 and int(headers["Retry-After"]) >= 1, "the HTTP route shares the budget"
            # another user is not affected, and the window slides
            status, _, _ = await env.get(ids["alice"], cid)
            assert status == 200
            clock[0] += 61
            await b.send(type="history_page")
            assert (await b.until("history_around", "history_error"))["type"] == "history_around"
            await a.close()
            await b.close()
        finally:
            server.monotonic = saved
    run(body)


def test_bad_requests_get_an_error_with_the_request_token():
    async def body(env):
        ids, cid, msgs = await seed(env.db)
        sock = await env.ws(ids["bob"])
        await sock.send(type="history_page", req=5)    # not joined yet
        err = await sock.until("history_around", "history_older", "history_error")
        assert err["type"] == "history_error" and err["error_code"] == "not_found" and err["req"] == 5
        await sock.join(cid)
        await sock.send(type="history_page", before_id=3, around_id=4, req=6)
        err = await sock.until("history_around", "history_older", "history_error")
        assert err["error_code"] == "invalid" and err["req"] == 6
        # an id beyond what SQLite holds is an error reply and the socket stays usable
        for bad in (2 ** 63, 10 ** 20, 1e20):
            await sock.send(type="history_page", before_id=bad, req=11)
            err = await sock.until("history_around", "history_older", "history_error")
            assert err["type"] == "history_error" and err["error_code"] == "invalid" and err["req"] == 11, bad
        await sock.send(type="history_page", around_id=2 ** 63, req=12)
        err = await sock.until("history_around", "history_older", "history_error")
        assert err["error_code"] == "invalid" and err["req"] == 12
        await sock.ws.send_str('{"type": "history_page", "before_id": Infinity, "req": 13}')
        err = await sock.until("history_around", "history_older", "history_error")
        assert err["error_code"] == "invalid" and err["req"] == 13
        await sock.send(type="history_page", req=14)
        page = await sock.until("history_around", "history_older", "history_error")
        assert page["type"] == "history_around" and page["req"] == 14, "same socket still answers"
        # a channel named by the client is ignored: the socket's own channel answers
        other = await env.db.create_chat_channel("hist3")
        await env.db.create_chat_message(other, ids["bob"], "bob", "other channel text")
        await sock.send(type="history_page", channel_id=other, channel="hist3", before_id=10**6)
        page = await sock.until("history_older", "history_error")
        assert page["channel_id"] == cid and "other channel text" not in json.dumps(page)
        await sock.close()
    run(body)


def test_migration_adds_the_index_and_can_run_again():
    async def body(env):
        d = env.db
        cur = await d.conn.execute("PRAGMA index_list(chat_messages)")
        names = {r["name"] for r in await cur.fetchall()}
        assert "idx_chat_messages_channel_id_id" in names, names
        cur = await d.conn.execute("PRAGMA index_info(idx_chat_messages_channel_id_id)")
        assert [r["name"] for r in await cur.fetchall()] == ["channel_id", "id"]
        await d.conn.execute("DROP INDEX idx_chat_messages_channel_id_id")
        await d.conn.commit()
        await d.close()
        d2 = Database(d.db_path if hasattr(d, "db_path") else str(Path(env.tmp.name) / "t.db"))
        await d2.connect()
        await d2.close()
        await d2.connect()
        cur = await d2.conn.execute("PRAGMA index_list(chat_messages)")
        assert "idx_chat_messages_channel_id_id" in {r["name"] for r in await cur.fetchall()}
        env.db = d2
        server.db = d2
    run(body)


def test_every_reading_path_uses_the_two_helpers():
    # One implementation of the rules: the join branch, the history_page branch and
    # the HTTP handler each call the access helper and the history builder, and the
    # enrichment code exists once.
    join = SERVER_SRC[SERVER_SRC.index('if msg_type == "join":'):SERVER_SRC.index('elif msg_type == "history_page":')]
    paged = SERVER_SRC[SERVER_SRC.index('elif msg_type == "history_page":'):SERVER_SRC.index('elif msg_type == "message":')]
    http = inspect.getsource(server.http_get_channel_messages)
    for label, src in (("join", join), ("history_page", paged), ("http", http)):
        assert "_can_read_channel(" in src, label + " does not call _can_read_channel"
        assert "_channel_history(" in src or "_enrich_channel_messages(" in src, label
    thread = inspect.getsource(server.http_get_chat_thread)
    assert "_can_read_channel(" in thread and "_enrich_channel_messages(" in thread, "the thread route uses the two helpers"
    assert "is_channel_member" not in thread, "the thread route has no access check of its own"
    assert "_enrich_channel_messages(" in inspect.getsource(server._channel_history)
    assert SERVER_SRC.count("async def _enrich_channel_messages") == 1
    assert SERVER_SRC.count("_mask_reactor_ids(all_reactions") == 1, "reaction masking lives in the helper only"
    assert "msg_users_map" not in SERVER_SRC, "the join path no longer builds its own enrichment"
    assert "get_chat_messages(" not in join and "get_chat_messages(" not in paged
    # history reading never writes the read position
    assert "update_read_position" not in paged and "update_read_position" not in http
    assert "update_read_position" not in inspect.getsource(server._channel_history)


def test_rate_constants():
    assert server.HISTORY_PAGE_DEFAULT == 50 and server.HISTORY_PAGE_MAX == 100
    assert server.HISTORY_RATE_LIMIT == 30 and server.HISTORY_RATE_WINDOW == 60.0


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
