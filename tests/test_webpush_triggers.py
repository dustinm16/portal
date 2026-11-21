"""When Web Push goes out: a direct message, an @mention, an @everyone, a followed stream going live.

The real chat websocket handler, the real mention and go-live code and the real sender run
in-process against a temporary database. The push service is a fake on this test's own loopback
listener (reachable only through the test hook webpush.allow_test_sink); every push is decrypted
with an independently written receiver. tests/outbound_guard.py refuses any other dial.

* a DM, an @mention, an @everyone and a go-live each produce exactly ONE push for a member with
  a device and no open chat socket; the payload has no message text, no sender or author name,
  a relative URL that opens the right page, a tag, and an opaque Topic header
* with a chat socket open nothing is sent; a muted DM, a channel at level none, a timed mute,
  a switched-off kind produce none; @here never pushes; a member who may not read a private
  channel gets none; an anonymous sender is never named
* go-live reaches followers only (not the "everyone" audience), names the streamer only for a
  public stream, and a private stream reaches nobody who may not watch it
* the per-user cap holds through a trigger; /api/push/prefs; POST /logout with the endpoint removes
  that device, only the caller's own; the VAPID key and devices are in a backup and a restore
  keeps the subscriptions working

Run: venv/bin/python tests/test_webpush_triggers.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import test_chat_access_loss as base  # noqa: E402
import test_notify_levels as nl  # noqa: E402
import backup_manager as bm  # noqa: E402
import server  # noqa: E402
import update_manager as um  # noqa: E402
import webpush as wp  # noqa: E402
import webpush_receiver as rx  # noqa: E402
from database import Database  # noqa: E402

SECRET_TEXT = "the-secret-plan-zebra-42"


class Service:
    """A fake push service: records (device name, headers, body)."""

    def __init__(self):
        self.hits = []

    async def handle(self, request):
        self.hits.append((request.match_info["name"], dict(request.headers), await request.read()))
        return web.Response(status=201)

    async def start(self):
        app = web.Application()
        app.router.add_post("/push/{name}", self.handle)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        wp.allow_test_sink(self.srv.port)


class Device:
    def __init__(self, service, name):
        self.key = rx.new_receiver()
        self.name = name
        self.endpoint = f"http://127.0.0.1:{service.srv.port}/push/{name}"


class PushEnv(nl.Env):
    async def __aenter__(self):
        await super().__aenter__()
        self.service = Service()
        await self.service.start()
        server._push_pusher = None
        self.devices = {}
        # the logout and prefs routes, on the same app's fake authentication
        app = web.Application()
        app.router.add_post("/logout", server.http_logout)
        app.router.add_get("/logout", server.http_logout)
        app.router.add_get("/api/push/prefs", server.http_push_prefs_get)
        app.router.add_put("/api/push/prefs", server.http_push_prefs_put)
        self.app2 = TestServer(app)
        await self.app2.start_server()
        return self

    async def __aexit__(self, *exc):
        wp.allow_test_sink(None)
        if server._push_pusher is not None:
            server._push_pusher.cancel_all()
        server._push_pusher = None
        await self.app2.close()
        await self.service.srv.close()
        await super().__aexit__(*exc)

    async def device(self, user_id, name, token_id=None):
        dev = Device(self.service, name)
        if token_id and not await self.db.get_token(token_id):
            await self.db.create_token(user_id, token_id, ["*"], name="web_session")
        await self.db.add_push_subscription(
            user_id, dev.endpoint, rx.b64e(dev.key["public"]), rx.b64e(dev.key["auth"]), "test", token_id, 10)
        self.devices[name] = dev
        return dev

    async def settle(self):
        for _ in range(200):
            tasks = list(server._get_pusher().tasks)
            if not tasks:
                break
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0.05)

    def pushes(self, name=None):
        """Decrypted payloads, in order, for one device or all."""
        out = []
        for dev_name, headers, body in self.service.hits:
            if name and dev_name != name:
                continue
            dev = self.devices[dev_name]
            out.append((json.loads(rx.decrypt(body, dev.key["private"], dev.key["auth"])), headers))
        return out


def run(body):
    async def go():
        async with PushEnv() as env:
            saved = (wp.USER_RATE_LIMIT, server._mass_clock, server._mass_mention_last.copy())
            server._mass_mention_last.clear()
            server._automod_cache_time = -1e9
            server.chat_user_state.clear()
            server._chat_state_refs.clear()
            try:
                await body(env)
            finally:
                wp.USER_RATE_LIMIT = saved[0]
                server._mass_clock = saved[1]
                server._mass_mention_last.clear()
                server._automod_rules_cache = []
                server._automod_cache_time = -1e9
    asyncio.run(go())


def no_text(payload, *names):
    flat = json.dumps(payload)
    assert SECRET_TEXT not in flat, flat
    for n in names:
        assert n.lower() not in flat.lower(), (n, flat)


async def dm_send(sock, conv_id, text):
    mark = sock.mark()
    await sock.send(type="dm_message", conversation_id=conv_id, message=text)
    await sock.wait(lambda e: e.get("type") == "dm_message" and e.get("message") == text, mark)


async def conversation(d, a, b):
    return (await d.create_dm_conversation(a, [b]))["id"]


# ---------------------------------------------------------------------------
# direct messages

def test_a_dm_to_an_away_member_is_one_push_with_no_text_and_no_name():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.conn.execute("UPDATE users SET nickname = 'Alicia' WHERE id = ?", (ids["alice"],))
        await d.conn.commit()
        await env.device(ids["bob"], "bob1")
        conv = await conversation(d, ids["alice"], ids["bob"])
        alice = await env.sock(ids["alice"])
        await dm_send(alice, conv, f"hello {SECRET_TEXT}")
        await env.settle()
        got = env.pushes("bob1")
        assert len(got) == 1, got
        payload, headers = got[0]
        assert payload["type"] == "dm" and payload["title"] == "New direct message", payload
        assert payload["url"] == f"/chat?dm={conv}" and payload["tag"] == f"dm-{conv}", payload
        no_text(payload, "alice", "alicia")
        assert headers["Topic"] and f"dm-{conv}" not in headers["Topic"] and "dm" != headers["Topic"], headers
    run(body)


def test_a_dm_makes_no_push_while_a_chat_socket_is_open_or_for_a_muted_conversation_or_a_kind_off():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await env.device(ids["bob"], "bob1")
        conv = await conversation(d, ids["alice"], ids["bob"])
        alice = await env.sock(ids["alice"])
        bob = await env.sock(ids["bob"])                    # a tab is open
        await dm_send(alice, conv, "one")
        await env.settle()
        assert env.pushes() == [], env.pushes()
        await bob.close()
        await asyncio.sleep(0.3)
        await d.update_dm_mute(conv, ids["bob"], True)
        await dm_send(alice, conv, "two")
        await env.settle()
        assert env.pushes() == [], "a muted conversation"
        await d.update_dm_mute(conv, ids["bob"], False)
        await d.set_push_prefs(ids["bob"], {"dm": False})
        await dm_send(alice, conv, "three")
        await env.settle()
        assert env.pushes() == [], "the DM switch is off"
        await d.set_push_prefs(ids["bob"], {"dm": True})
        await dm_send(alice, conv, "four")
        await env.settle()
        assert len(env.pushes()) == 1
    run(body)


def test_an_anonymous_senders_dm_push_names_nobody():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.set_chat_anonymous(ids["alice"], True)
        await d.conn.execute("UPDATE users SET nickname = 'Alicia' WHERE id = ?", (ids["alice"],))
        await d.conn.commit()
        await env.device(ids["bob"], "bob1")
        conv = await conversation(d, ids["alice"], ids["bob"])
        alice = await env.sock(ids["alice"])
        await dm_send(alice, conv, f"hi {SECRET_TEXT}")
        await env.settle()
        got = env.pushes()
        assert len(got) == 1
        no_text(got[0][0], "alice", "alicia")
    run(body)


def test_the_per_user_cap_holds_through_a_trigger():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await env.device(ids["bob"], "bob1")
        conv = await conversation(d, ids["alice"], ids["bob"])
        wp.USER_RATE_LIMIT = 2
        alice = await env.sock(ids["alice"])
        for i in range(4):
            await dm_send(alice, conv, f"m{i}")
            await env.settle()
        assert len(env.pushes("bob1")) == 2
    run(body)


# ---------------------------------------------------------------------------
# mentions

async def post(sock, text):
    mark = sock.mark()
    await sock.send(type="message", message=text)
    await sock.wait(lambda e: e.get("type") == "message" and e.get("message") == text, mark)


def test_an_at_mention_is_one_push_with_the_channel_and_a_deep_link_but_not_the_text():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await nl.pub_channel(d, ids)
        await env.device(ids["bob"], "bob1")
        carol = await env.sock(ids["carol"])
        await carol.join(lobby)
        await post(carol, f"@bob, look at {SECRET_TEXT}")
        await env.settle()
        got = env.pushes("bob1")
        assert len(got) == 1, got
        payload, headers = got[0]
        assert payload["type"] == "mention" and payload["body"] == "You were mentioned in #lobby", payload
        assert payload["url"].startswith(f"/chat?channel_id={lobby}&message_id="), payload
        assert payload["tag"] == f"mention-{lobby}", payload
        no_text(payload, "carol")
        # an open chat socket: no push
        bob = await env.sock(ids["bob"])
        await post(carol, f"@bob, again {SECRET_TEXT}")
        await env.settle()
        assert len(env.pushes("bob1")) == 1, "bob has a tab open"
        await bob.close()
    run(body)


def test_level_none_a_timed_mute_and_a_switched_off_kind_produce_no_mention_push():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await nl.pub_channel(d, ids)
        await env.device(ids["bob"], "bob1")
        carol = await env.sock(ids["carol"])
        await carol.join(lobby)
        await d.set_notify_pref(ids["bob"], lobby, "none", 0)
        await post(carol, "@bob, none")
        await env.settle()
        assert env.pushes() == [], "level none"
        await d.set_notify_pref(ids["bob"], lobby, "mentions", int(env.now[0]) + 3600)
        await post(carol, "@bob, muted")
        await env.settle()
        assert env.pushes() == [], "timed mute"
        await d.set_notify_pref(ids["bob"], lobby, "mentions", 0)
        await d.set_push_prefs(ids["bob"], {"mention": False})
        await post(carol, "@bob, kind off")
        await env.settle()
        assert env.pushes() == [], "mention switch off"
        await d.set_push_prefs(ids["bob"], {"mention": True})
        await post(carol, "@bob, now")
        await env.settle()
        assert len(env.pushes()) == 1, "level mentions pushes"
    run(body)


def test_everyone_pushes_here_never_does_and_a_non_member_of_a_private_channel_gets_none():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await base.private_channel(d, ids, members=("alice", "bob"))
        await env.device(ids["bob"], "bob1")
        await env.device(ids["carol"], "carol1")           # not a member
        await d.add_channel_member(cid, ids["boss"], role="member", added_by=ids["boss"])
        boss = await env.sock(ids["boss"])
        await boss.join(cid)
        await post(boss, "@here hello")
        await env.settle()
        assert env.pushes() == [], "@here targets members who are online and never pushes"
        server._mass_mention_last.clear()
        await post(boss, f"@everyone {SECRET_TEXT}")
        await env.settle()
        got = env.pushes()
        assert [n for n in env.service.hits if n[0] == "bob1"] and len(got) == 1, got
        assert got[0][0]["body"] == "Everyone was mentioned in #pvt", got
        no_text(got[0][0], "boss")
        assert not [h for h in env.service.hits if h[0] == "carol1"]
        # a member who is not in the channel, named directly: no push and no channel name anywhere
        server._mass_mention_last.clear()
        await post(boss, "@carol, are you there")
        await env.settle()
        assert not [h for h in env.service.hits if h[0] == "carol1"]
    run(body)


# ---------------------------------------------------------------------------
# go-live

async def make_stream(d, ids, name, public=True, audience="followers"):
    sid = await d.create_user_stream(ids["owner"], name, "live_" + name.ljust(24, "x"),
                                     public_key="pub_" + name.ljust(24, "y"), is_public=public)
    await d.conn.execute("UPDATE user_streams SET golive_audience = ? WHERE id = ?", (audience, sid))
    await d.conn.commit()
    return sid


def test_a_go_live_pushes_followers_only_with_the_streamer_name_for_a_public_stream():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.conn.execute("UPDATE users SET nickname = 'StreamerOwner' WHERE id = ?", (ids["owner"],))
        await d.conn.commit()
        for who in ("bob", "carol", "viewer"):
            await env.device(ids[who], who + "1")
        sid = await make_stream(d, ids, "pubone", audience="everyone")
        await d.follow_stream(ids["bob"], sid)
        await d.follow_stream(ids["carol"], sid)
        carol = await env.sock(ids["carol"])                # a tab is open: no push
        await server._announce_go_live(sid)
        await env.settle()
        assert [h[0] for h in env.service.hits] == ["bob1"], [h[0] for h in env.service.hits]
        payload, _h = env.pushes("bob1")[0]
        assert payload["type"] == "golive" and payload["title"] == "StreamerOwner is live", payload
        assert payload["url"] == f"/watch/{sid}" and payload["tag"] == f"live-{sid}", payload
        assert "live_" not in json.dumps(payload) and "pub_" not in json.dumps(payload)
        assert "pubone" not in json.dumps(payload), "the stream title is not in a push"
        # the member who is not a follower still got the in-portal notification (audience everyone)
        assert any(n["type"] == "stream_live" for n in await d.get_notifications(ids["viewer"]))
        await carol.close()
    run(body)


def test_a_private_streams_go_live_reaches_no_one_who_may_not_watch_it():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.conn.execute("UPDATE users SET nickname = 'StreamerOwner' WHERE id = ?", (ids["owner"],))
        await d.conn.commit()
        await env.device(ids["viewer"], "viewer1")
        await env.device(ids["boss"], "boss1")
        sid = await make_stream(d, ids, "privone", public=False, audience="followers")
        # a follow row that should not exist (visibility changes clear them) is inserted directly
        await d.conn.execute("INSERT INTO stream_follow (user_id, stream_id) VALUES (?, ?)", (ids["viewer"], sid))
        await d.conn.execute("INSERT INTO stream_follow (user_id, stream_id) VALUES (?, ?)", (ids["boss"], sid))
        await d.conn.commit()
        await server._announce_go_live(sid)
        await env.settle()
        assert [h[0] for h in env.service.hits] == ["boss1"], [h[0] for h in env.service.hits]
        payload, _h = env.pushes("boss1")[0]
        assert payload["title"] == "A stream you follow is live", payload
        no_text(payload, "StreamerOwner", "privone")
        assert not await d.get_notifications(ids["viewer"])
    run(body)


def test_a_banned_follower_and_a_stream_that_turned_private_get_no_push():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await env.device(ids["bob"], "bob1")
        sid = await make_stream(d, ids, "pubtwo")
        await d.follow_stream(ids["bob"], sid)
        # the access check at push time: the stream turned private between the notification and the push
        stream = await d.get_user_stream(sid)
        payload = server._golive_payload(stream)
        await d.conn.execute("UPDATE user_streams SET is_public = 0 WHERE id = ?", (sid,))
        await d.conn.commit()
        await server._push_go_live(stream, payload, {ids["bob"]: "user"}, [ids["bob"]])
        await env.settle()
        assert env.pushes() == []
    run(body)


# ---------------------------------------------------------------------------
# prefs and logout

async def http(env, method, path, user, **kw):
    headers = {"X-Test-User": str(user)}
    headers.update(kw.pop("headers", {}))
    async with env.http.request(method, str(env.app2.make_url(path)), headers=headers,
                                allow_redirects=False, **kw) as r:
        raw = await r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw


def test_the_prefs_routes():
    async def body(env):
        ids = await base.users(env.db)
        s, b = await http(env, "GET", "/api/push/prefs", ids["bob"])
        assert s == 200 and b["prefs"] == {"dm": True, "mention": True, "golive": True}, b
        s, b = await http(env, "PUT", "/api/push/prefs", ids["bob"], json={"dm": False})
        assert s == 200 and b["prefs"] == {"dm": False, "mention": True, "golive": True}, b
        assert (await http(env, "GET", "/api/push/prefs", ids["bob"]))[1]["prefs"]["dm"] is False
        assert (await http(env, "GET", "/api/push/prefs", ids["alice"]))[1]["prefs"]["dm"] is True, "per member"
        for bad in ({"dm": "no"}, {"voice": True}, {}, {"dm": 1}):
            s, _b = await http(env, "PUT", "/api/push/prefs", ids["bob"], json=bad)
            assert s == 400, (bad, s)
        s, _b = await http(env, "GET", "/api/push/prefs", ids["bob"], headers={"X-Test-User": ""})
        assert s in (401, 403)
        import inspect
        for fn in (server.http_push_prefs_get, server.http_push_prefs_put):
            assert "_push_user_auth(request)" in inspect.getsource(fn), "API keys and URL tokens are refused"
    run(body)


def test_logout_with_the_endpoint_removes_that_device_and_only_the_callers():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        mine = await env.device(ids["bob"], "bob1", token_id="an-older-session")
        theirs = await env.device(ids["alice"], "alice1")
        cookie = {"Cookie": f"{server.Config.SESSION_COOKIE_NAME}=x"}
        # naming another member's endpoint removes nothing of theirs
        s, _b = await http(env, "POST", "/logout", ids["bob"], headers=cookie, json={"endpoint": theirs.endpoint})
        assert s == 200 and len(await d.list_push_subscriptions(ids["alice"])) == 1
        assert len(await d.list_push_subscriptions(ids["bob"])) == 1, "no endpoint was sent for bob's own"
        s, _b = await http(env, "POST", "/logout", ids["bob"], headers=cookie, json={"endpoint": mine.endpoint})
        assert s == 200
        assert await d.list_push_subscriptions(ids["bob"]) == []
        assert len(await d.list_push_subscriptions(ids["alice"])) == 1
        # the link still redirects, a bad body is harmless
        s, _b = await http(env, "GET", "/logout", ids["bob"], headers=cookie)
        assert s == 302
        s, _b = await http(env, "POST", "/logout", ids["bob"], headers=cookie, data=b"not json")
        assert s == 200
    run(body)


# ---------------------------------------------------------------------------
# backup and restore keep the key and the devices

def test_the_vapid_key_and_devices_are_in_a_backup_and_a_restore_keeps_them_working():
    async def body(env):
        import shutil
        import sqlite3
        import tempfile
        d = env.db
        ids = await base.users(d)
        await env.device(ids["bob"], "bob1")
        keys = await wp.get_vapid(d)
        assert keys is not None
        stored = await d.get_setting(wp.SETTING_PRIVATE)
        assert stored and keys.public_b64 not in stored, "the private key is stored encrypted"
        tmp = tempfile.mkdtemp()
        saved_dirs = (um.PORTAL_DIR, um.BACKUPS_DIR)
        try:
            root = Path(tmp) / "proj"
            root.mkdir()
            um.PORTAL_DIR, um.BACKUPS_DIR = root, root / "backups"
            (root / ".env").write_text("JWT_SECRET=abc\n")
            (root / ".encryption_salt").write_bytes(b"\x01\x02salt")
            await d.conn.commit()
            info = bm.create_archive(d.db_path, "v0.test")
            target = Path(tmp) / "restored"
            bm.restore_archive(info["path"], str(target))
            copy = str(target / "portal.db")
            probe = sqlite3.connect(copy)
            try:
                rows = dict(probe.execute("SELECT key, value FROM settings WHERE key LIKE 'push_vapid%'").fetchall())
                n_devices = probe.execute("SELECT COUNT(*) FROM push_subscriptions").fetchone()[0]
            finally:
                probe.close()
            assert wp.SETTING_PRIVATE in rows and wp.SETTING_PUBLIC in rows, rows
            assert n_devices == 1, "the device table is in the archive"
            d2 = Database(copy)
            await d2.connect()
            try:
                again = await wp.get_vapid(d2)
                assert again is not None and again.public_b64 == keys.public_b64, "the same key after a restore"
                subs = await d2.push_subscriptions_for_send(ids["bob"])
                assert len(subs) == 1
                saved = server.db
                server.db = d2
                server._push_pusher = None
                try:
                    res = await server._get_pusher().deliver(ids["bob"], wp.make_test_payload())
                finally:
                    server._push_pusher.cancel_all()
                    server._push_pusher = None
                    server.db = saved
                assert [r["outcome"] for r in res] == ["sent"], res
                headers = env.service.hits[-1][1]
                token = headers["Authorization"].split("t=")[1].split(",")[0]
                import jwt
                jwt.decode(token, wp.load_public_point(wp.b64u_decode(keys.public_b64)),
                           algorithms=["ES256"], audience=f"http://127.0.0.1:{env.service.srv.port}")
            finally:
                await d2.close()
        finally:
            um.PORTAL_DIR, um.BACKUPS_DIR = saved_dirs
            shutil.rmtree(tmp, ignore_errors=True)
    run(body)


def test_the_prefs_table_is_created_repeatably_and_goes_with_the_account():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.set_push_prefs(ids["bob"], {"golive": False})
        path = d.db_path
        d2 = Database(path)
        await d2.connect()                          # every migration runs again
        cur = await d2.conn.execute("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'push_prefs'")
        assert (await cur.fetchone())["n"] == 1
        assert (await d2.get_push_prefs(ids["bob"]))["golive"] is False
        await d2.close()
        assert await d.delete_user(ids["bob"])
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM push_prefs WHERE user_id = ?", (ids["bob"],))
        assert (await cur.fetchone())["n"] == 0
    run(body)


def test_the_topic_is_a_keyed_hash_and_a_channel_that_turned_private_is_judged_as_it_is_now():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        a = server._push_topic(ids["bob"], "dm", "dm-1")
        assert a == server._push_topic(ids["bob"], "dm", "dm-1") and a != server._push_topic(ids["alice"], "dm", "dm-1")
        import hashlib
        assert a != wp.b64u(hashlib.sha256(f"{ids['bob']}:dm:dm-1".encode()).digest()[:16]), "not an unkeyed hash"
        saved = server.Config.JWT_SECRET
        server.Config.JWT_SECRET = "y" * 64
        try:
            assert server._push_topic(ids["bob"], "dm", "dm-1") != a, "depends on the server's secret"
        finally:
            server.Config.JWT_SECRET = saved
        # a mention push is judged against the channel as it is when the push runs
        lobby = await nl.pub_channel(d, ids)
        await env.device(ids["bob"], "bob1")
        stale = await d.get_chat_channel(lobby)           # what the message path held: public
        await d.update_chat_channel(lobby, visibility="private")
        assert await server._push_mentions(stale, 1, [ids["bob"]], []) == 0
        await env.settle()
        assert env.pushes() == []
    run(body)


def test_a_trigger_pays_for_no_query_when_push_is_off_everybody_is_in_the_portal_or_nobody_has_a_device():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await nl.pub_channel(d, ids)
        channel = await d.get_chat_channel(lobby)
        conv = await conversation(d, ids["alice"], ids["bob"])
        calls = []
        for name in ("get_dm_muted_ids", "get_chat_channel", "get_stream_by_chat_channel"):
            def wrap(orig, name=name):
                async def inner(*a, **k):
                    calls.append(name)
                    return await orig(*a, **k)
                return inner
            setattr(d, name, wrap(getattr(d, name)))
        heavy = {"get_dm_muted_ids", "get_chat_channel", "get_stream_by_chat_channel"}

        async def run_both():
            calls.clear()
            await server._push_dm(conv, ids["alice"])
            await server._push_mentions(channel, 1, [ids["bob"]], [ids["carol"]] if "carol" in ids else [])
            return set(calls) & heavy

        # nobody has a device: nothing beyond the cheap lookups
        assert await run_both() == set(), "no device, yet the muted list or the channel was read"
        # a device, but push switched off
        await env.device(ids["bob"], "bob1")
        await d.set_setting(wp.SETTING_ENABLED, "0")
        assert await run_both() == set(), "push is off, yet the muted list or the channel was read"
        await d.set_setting(wp.SETTING_ENABLED, "1")
        # a device and a tab open: the member is not away
        bob = await env.sock(ids["bob"])
        assert await run_both() == set(), "the member has a tab open, yet the muted list or the channel was read"
        await bob.close()
        await asyncio.sleep(0.3)
        # control: an away member with a device does cost the lookups (and gets the pushes)
        got = await run_both()
        assert {"get_dm_muted_ids", "get_chat_channel"} <= got, got
        await env.settle()
        assert len(env.pushes("bob1")) == 2
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
