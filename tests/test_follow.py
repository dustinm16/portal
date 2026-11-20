"""Follows, the go-live audience, the announce cards and the live-now list.

The portal's own handlers run in-process against a temporary database: the follow, public
list, stream update and delete, live-now, history and settings routes over a real aiohttp
test server (a stand-in login replaces the credential check), and the MediaMTX publish hook
called directly. Webhook delivery is replaced by a recorder, recording and relay starters by
no-ops, tests/outbound_guard.py refuses any dial that is not loopback. Not proven here: a real
MediaMTX hook retry, OBS, a browser rendering the card or the strip, Cloudflare in front.

* follow: a member follows a stream they may watch; an unknown stream and a stream they may not
  watch give one identical 404; a stream key is not a login; unfollowing never reveals anything;
  a per-member cap; own follows only; the owner sees a count and never names; no route lists
  followers; making a stream private removes every follow and a later public switch does not
  bring them back
* audience: a new stream defaults to followers, a stream that existed before the column keeps
  everyone; followers get a notification only while they may still watch; the streamer never; a
  non-follower nothing; everyone mode reaches every member who may watch
* the hook answers at once while the fan-out is still running; the fan-out inserts in batches;
  one announcement per cooldown
* cards: a stream_card message with a plain-text fallback in the stream's own chat and, for a
  public stream, in the announce channel; never for a non-public stream outside a channel
  members cannot read; not into a private announce channel; removed from the announce channel
  when the stream becomes private and everywhere when it is deleted; retention removes the card
  row with the message; the author cannot reword a card; the setting validates its channel
* live-now: only streams the viewer may watch, no key of any kind

Run: venv/bin/python tests/test_follow.py
"""

import asyncio
import json
import os
import re
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
from config import Config  # noqa: E402
from database import Database  # noqa: E402
from test_golive import Clock, HookRequest  # noqa: E402

FULL = ["services:read", "access:*"]
ADMIN_IDS = set()


class Tok:
    def __init__(self, user_id, streamkey=False):
        self.user_id = user_id
        self.token_id = ("streamkey-%d" if streamkey else "t%d") % user_id
        self.scopes = ["stream:publish"] if streamkey else list(FULL)
        if user_id in ADMIN_IDS:
            self.scopes.append("admin")

    def has_scope(self, scope):
        return "*" in self.scopes or scope in self.scopes


async def fake_auth(request, allow_stream_key=True):
    uid = request.headers.get("X-Test-User")
    if not uid:
        return None
    if request.headers.get("X-Test-Streamkey"):
        return Tok(int(uid), streamkey=True) if allow_stream_key else None
    return Tok(int(uid))


async def fake_valid(token):
    return True


class World:
    async def build(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = d = Database(str(Path(self.tmp.name) / "t.db"))
        await d.connect()
        self.saved = {n: getattr(server, n) for n in (
            "db", "authenticate_request", "_credential_still_valid", "_golive_now", "_deliver_webhook",
            "start_vod_recording", "start_stream_relays", "_GOLIVE_BATCH")}
        server.db = d
        server.authenticate_request = fake_auth
        server._credential_still_valid = fake_valid
        self.clock = Clock()
        server._golive_now = self.clock
        self.sent = []

        async def record(webhook, event, payload, attempt=1, *, meta=None, **kw):
            self.sent.append((webhook["id"], event, payload))
            return {"sent": True, "success": True}

        async def noop(*a, **kw):
            return None

        server._deliver_webhook = record
        server.start_vod_recording = noop
        server.start_stream_relays = noop
        self.saved_cfg = (Config.HOSTNAME, Config.PUBLIC_BASE_URL)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = "portal.example.test", ""
        server.chat_rooms.clear()
        self.ids = {}
        for name, role in (("owner", "user"), ("admin", "admin"), ("m1", "user"), ("m2", "user"), ("m3", "user")):
            self.ids[name] = await d.create_user(name, "x")
            if role != "user":
                await d.set_user_role(self.ids[name], role)
                ADMIN_IDS.add(self.ids[name])
        app = web.Application()
        r = app.router
        r.add_get("/api/streams", server.http_list_user_streams)
        r.add_post("/api/streams", server.http_create_user_stream)
        r.add_get("/api/streams/public", server.http_get_public_streams)
        r.add_get("/api/streams/live", server.http_live_now)
        r.add_get("/api/me/follows", server.http_my_follows)
        r.add_get("/api/streams/{id}", server.http_get_user_stream)
        r.add_put("/api/streams/{id}", server.http_update_user_stream)
        r.add_delete("/api/streams/{id}", server.http_delete_user_stream)
        r.add_put("/api/streams/{id}/follow", server.http_follow_stream)
        r.add_delete("/api/streams/{id}/follow", server.http_unfollow_stream)
        r.add_get("/api/chat/channels/{id}/messages", server.http_get_channel_messages)
        r.add_get("/api/settings/permissions", server.http_get_feature_permissions)
        r.add_put("/api/settings/permissions", server.http_update_feature_permissions)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def close(self):
        await self.drain()
        await self.http.close()
        await self.srv.close()
        for n, v in self.saved.items():
            setattr(server, n, v)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = self.saved_cfg
        server.chat_rooms.clear()
        await self.db.close()
        self.tmp.cleanup()

    async def call(self, method, who, path, **kw):
        headers = {"X-Test-User": str(self.ids[who])} if who else {}
        headers.update(kw.pop("headers", {}))
        async with self.http.request(method, str(self.srv.make_url(path)), headers=headers, **kw) as r:
            try:
                body = await r.json()
            except Exception:
                body = None
            return r.status, body

    async def stream(self, label="s", public=True, audience="everyone", chat=True, owner="owner"):
        key, pub = "live_" + label * 20, "pub_" + label * 20
        sid = await self.db.create_user_stream(
            self.ids[owner], "Show " + label, key, public_key=pub, is_public=public, golive_audience=audience)
        if chat:
            cid = await self.db.create_chat_channel("stream-" + label + str(sid), created_by=self.ids[owner])
            await self.db.update_user_stream(sid, chat_channel_id=cid)
        return sid, key

    async def publish(self, key):
        resp = await server.http_stream_auth(HookRequest({
            "action": "publish", "path": "live/" + key, "ip": "198.51.100.7",
            "user": "", "password": "", "query": ""}))
        return resp.status

    async def drain(self):
        for _ in range(5):
            await asyncio.sleep(0)
        tasks = [t for t in list(server._golive_tasks) if t is not asyncio.current_task()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        pend = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                and ("_deliver_webhook" in repr(t.get_coro()) or "fire_webhook_event" in repr(t.get_coro()))]
        if pend:
            await asyncio.gather(*pend, return_exceptions=True)

    async def notes(self, who):
        return [n for n in await self.db.get_notifications(self.ids[who], limit=100) if n["type"] == "stream_live"]

    async def follow(self, who, sid):
        status, _ = await self.call("PUT", who, f"/api/streams/{sid}/follow")
        return status

    async def go_live_again(self, key, sid):
        await self.db.set_stream_live(sid, False)
        self.clock.now += 3600
        assert await self.publish(key) == 200
        await self.drain()

    async def cards(self, channel_id):
        return [m for m in await self.db.get_chat_messages(channel_id, limit=100) if m["message_type"] == "stream_card"]

    async def channel(self, name, private=False):
        cid = await self.db.create_chat_channel(name, created_by=self.ids["admin"])
        if private:
            await self.db.update_chat_channel(cid, visibility="private")
        return cid


def case(fn):
    def runner():
        async def go():
            server._stream_state_lock = asyncio.Lock()      # one per test loop, as in test_golive
            w = await World().build()
            try:
                await fn(w)
            finally:
                await w.close()
        asyncio.run(go())
    runner.__name__ = fn.__name__
    runner.__doc__ = fn.__doc__
    return runner


# ---------------------------------------------------------------------------
# follow

@case
async def test_a_member_follows_a_stream_they_may_watch(w):
    sid, _ = await w.stream("a", public=True)
    assert await w.follow("m1", sid) == 200
    assert await w.follow("m1", sid) == 200                     # again: still one row
    assert await w.db.get_followed_stream_ids(w.ids["m1"]) == [sid]
    assert await w.db.count_followers(sid) == 1
    status, body = await w.call("GET", "m1", "/api/me/follows")
    assert status == 200 and body == {"stream_ids": [sid]}
    status, body = await w.call("DELETE", "m1", f"/api/streams/{sid}/follow")
    assert status == 200 and body["following"] is False and await w.db.count_followers(sid) == 0


@case
async def test_an_unknown_and_an_unviewable_stream_are_one_identical_404(w):
    priv, _ = await w.stream("p", public=False)
    results = [await w.call("PUT", "m1", f"/api/streams/{priv}/follow"),
               await w.call("PUT", "m1", "/api/streams/99999/follow"),
               await w.call("PUT", "m1", "/api/streams/abc/follow")]
    assert [s for s, _ in results] == [404, 404, 404], results
    assert len({json.dumps(b, sort_keys=True) for _, b in results}) == 1, results
    assert await w.db.get_followed_stream_ids(w.ids["m1"]) == []
    # the owner and an administrator may watch it, so they may follow it
    assert await w.follow("owner", priv) == 200 and await w.follow("admin", priv) == 200
    # not signed in
    status, _ = await w.call("PUT", None, f"/api/streams/{priv}/follow")
    assert status == 401


@case
async def test_a_stream_key_is_not_a_login_for_following(w):
    sid, _ = await w.stream("k", public=True)
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}/follow", headers={"X-Test-Streamkey": "1"})
    assert status == 403, status        # a stream key authorises publishing only
    assert await w.db.count_followers(sid) == 0


@case
async def test_a_stream_key_reads_no_follow_state_from_the_older_routes(w):
    sid, _ = await w.stream("k", public=True)
    other, _ = await w.stream("o", public=True)
    assert await w.follow("owner", other) == 200
    key = {"X-Test-Streamkey": "1"}
    status, _ = await w.call("GET", "owner", "/api/me/follows", headers=key)
    assert status == 403
    # the owner's own session still sees its follows on both routes
    status, body = await w.call("GET", "owner", "/api/streams/public")
    assert status == 200 and {s["id"]: s["following"] for s in body["streams"]}[other] is True
    status, body = await w.call("GET", "owner", f"/api/streams/{other}")
    assert status == 200 and body["stream"]["following"] is True
    # the owner's stream key reads nothing from the stream routes (403, not even a list)
    for path in ("/api/streams/public", f"/api/streams/{other}", f"/api/streams/{sid}", "/api/streams/live"):
        status, body = await w.call("GET", "owner", path, headers=key)
        assert status == 403 and "streams" not in body and "stream" not in body, (path, status, body)


@case
async def test_unfollowing_answers_the_same_for_any_stream(w):
    priv, _ = await w.stream("p", public=False)
    a = await w.call("DELETE", "m1", f"/api/streams/{priv}/follow")
    b = await w.call("DELETE", "m1", "/api/streams/99999/follow")
    assert a[0] == 200 and b[0] == 200 and a[1]["following"] is False and b[1]["following"] is False


@case
async def test_the_follow_limit_per_member(w):
    old = server.db.FOLLOW_LIMIT_PER_USER
    server.db.FOLLOW_LIMIT_PER_USER = 2
    try:
        ids = [(await w.stream(c))[0] for c in "abc"]
        assert [await w.follow("m1", s) for s in ids] == [200, 200, 400]
        assert await w.follow("m1", ids[0]) == 200            # an existing follow is not refused
    finally:
        server.db.FOLLOW_LIMIT_PER_USER = old


@case
async def test_who_follows_whom_is_private(w):
    sid, _ = await w.stream("a", public=True)
    await w.follow("m1", sid)
    await w.follow("m2", sid)
    # a member sees only their own follow state
    _, pub = await w.call("GET", "m1", "/api/streams/public")
    mine = {s["id"]: s["following"] for s in pub["streams"]}
    assert mine == {sid: True}, pub
    _, pub2 = await w.call("GET", "m3", "/api/streams/public")
    assert {s["id"]: s["following"] for s in pub2["streams"]} == {sid: False}
    # the owner gets a count and never a name or an id
    status, own = await w.call("GET", "owner", "/api/streams")
    assert own["streams"][0]["follower_count"] == 2
    status, det = await w.call("GET", "owner", f"/api/streams/{sid}")
    assert det["stream"]["follower_count"] == 2
    for body in (own, det):
        text = json.dumps(body)
        assert '"m1"' not in text and '"m2"' not in text
        assert "followers" not in {k for k in (det["stream"].keys())}
    # a member, and an administrator who is not the owner, get no count
    for who in ("m1", "admin"):
        _, other = await w.call("GET", who, f"/api/streams/{sid}")
        assert "follower_count" not in other["stream"], who
    # the public list carries no count either
    assert all("follower_count" not in s for s in pub["streams"])
    # and no route lists followers
    src = (ROOT / "server.py").read_text()
    assert not re.search(r'add_(get|post|put|delete)\("[^"]*follower', src)
    assert not re.search(r'add_(get|post|put|delete)\("/api/[^"]*/follows?/', src)


@case
async def test_making_a_stream_private_removes_every_follow_and_a_later_public_switch_does_not_bring_them_back(w):
    sid, _ = await w.stream("a", public=True)
    for who in ("m1", "m2", "admin"):
        await w.follow(who, sid)
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    assert status == 200 and await w.db.count_followers(sid) == 0
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": True})
    assert status == 200 and await w.db.count_followers(sid) == 0
    assert await w.db.get_followed_stream_ids(w.ids["m1"]) == []


@case
async def test_editing_an_already_private_stream_keeps_its_follows(w):
    sid, _ = await w.stream("a", public=False)
    await w.follow("admin", sid)
    await w.follow("owner", sid)
    for body in ({"name": "Renamed"}, {"golive_message": "hi {title}"}, {"golive_audience": "everyone"},
                 {"rtmp_enabled": False}, {"is_public": False}):
        status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json=body)
        assert status == 200, body
        assert await w.db.count_followers(sid) == 2, body


@case
async def test_a_stale_follow_from_the_private_period_does_not_wake_up_on_a_public_switch(w):
    sid, _ = await w.stream("a", public=False)
    await w.follow("admin", sid)                         # allowed: an administrator may watch it
    await w.db.set_user_role(w.ids["admin"], "user")      # demoted: the follow is stale
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": True})
    assert status == 200 and await w.db.count_followers(sid) == 0


@case
async def test_deleting_a_stream_removes_its_follows(w):
    sid, _ = await w.stream("a", public=True)
    await w.follow("m1", sid)
    status, _ = await w.call("DELETE", "owner", f"/api/streams/{sid}")
    assert status == 200 and await w.db.get_followed_stream_ids(w.ids["m1"]) == []


@case
async def test_deleting_a_member_removes_their_follows(w):
    sid, _ = await w.stream("a", public=True)
    await w.follow("m1", sid)
    await w.db.delete_user(w.ids["m1"])
    assert await w.db.count_followers(sid) == 0


# ---------------------------------------------------------------------------
# audience

@case
async def test_a_new_stream_defaults_to_followers_and_an_old_row_keeps_everyone(w):
    status, body = await w.call("POST", "owner", "/api/streams", json={"name": "Fresh", "is_public": True})
    assert status == 201 and body["stream"]["golive_audience"] == "followers", body
    # a row inserted the way a database from before this column was filled: the column default
    await w.db.conn.execute(
        "INSERT INTO user_streams (user_id, name, stream_key, is_public) VALUES (?, 'Old', 'k', 1)", (w.ids["owner"],))
    await w.db.conn.commit()
    cur = await w.db.conn.execute("SELECT golive_audience FROM user_streams WHERE name = 'Old'")
    assert (await cur.fetchone())["golive_audience"] == "everyone"
    # the owner changes it; anything else is refused; a member cannot
    sid = body["stream"]["id"]
    assert (await w.call("PUT", "owner", f"/api/streams/{sid}", json={"golive_audience": "everyone"}))[0] == 200
    assert (await w.call("PUT", "owner", f"/api/streams/{sid}", json={"golive_audience": "nobody"}))[0] == 400
    assert (await w.call("PUT", "owner", f"/api/streams/{sid}", json={"golive_audience": 1}))[0] == 400
    assert (await w.call("PUT", "m1", f"/api/streams/{sid}", json={"golive_audience": "followers"}))[0] == 404
    assert (await w.call("POST", "owner", "/api/streams", json={"name": "X", "golive_audience": "all"}))[0] == 400


@case
async def test_followers_mode_notifies_followers_only(w):
    sid, key = await w.stream("a", public=True, audience="followers")
    await w.follow("m1", sid)
    await w.follow("owner", sid)                                # the streamer is never notified
    assert await w.publish(key) == 200
    await w.drain()
    assert len(await w.notes("m1")) == 1
    for who in ("m2", "m3", "admin", "owner"):
        assert await w.notes(who) == [], who


@case
async def test_everyone_mode_notifies_every_member_who_may_watch(w):
    sid, key = await w.stream("a", public=True, audience="everyone")
    assert await w.publish(key) == 200
    await w.drain()
    for who in ("m1", "m2", "m3", "admin"):
        assert len(await w.notes(who)) == 1, who
    assert await w.notes("owner") == []


@case
async def test_a_follower_who_may_no_longer_watch_is_not_notified(w):
    sid, key = await w.stream("a", public=True, audience="followers")
    await w.follow("m1", sid)
    await w.follow("admin", sid)
    # the stream is private now and the follows are stale (inserted behind the route's back)
    await w.db.conn.execute("UPDATE user_streams SET is_public = 0 WHERE id = ?", (sid,))
    await w.db.conn.commit()
    assert await w.publish(key) == 200
    await w.drain()
    assert await w.notes("m1") == []
    assert len(await w.notes("admin")) == 1                       # an administrator may watch it


@case
async def test_the_notification_carries_no_key_and_pushes_to_open_sockets(w):
    sid, key = await w.stream("a", public=True, audience="followers")
    await w.follow("m1", sid)
    frames = []

    class WS:
        closed = False

        async def send_json(self, payload):
            frames.append(payload)

    server.notification_subscribers[w.ids["m1"]] = {WS()}
    try:
        await w.publish(key)
        await w.drain()
    finally:
        server.notification_subscribers.pop(w.ids["m1"], None)
    assert len(frames) == 1 and frames[0]["notification"]["type"] == "stream_live", frames
    n = (await w.notes("m1"))[0]
    text = json.dumps(frames) + json.dumps(n, default=str)
    assert "live_" not in text and "pub_" not in text
    assert f"/watch/{sid}" in text


# ---------------------------------------------------------------------------
# the hook path

@case
async def test_the_hook_answers_at_once_while_the_fan_out_is_still_running(w):
    sid, key = await w.stream("a", public=True, audience="everyone")
    gate = asyncio.Event()
    real = w.db.create_notifications_bulk

    async def slow(rows):
        await gate.wait()
        return await real(rows)

    w.db.create_notifications_bulk = slow
    try:
        status = await asyncio.wait_for(w.publish(key), 2)      # does not wait for the gate
        assert status == 200
        await asyncio.sleep(0.05)
        assert len(server._golive_tasks) == 1 and await w.notes("m1") == []
        gate.set()
        await w.drain()
    finally:
        w.db.create_notifications_bulk = real
    assert len(await w.notes("m1")) == 1


@case
async def test_the_fan_out_inserts_in_batches(w):
    for i in range(8):
        await w.db.create_user("extra%d" % i, "x")
    sid, key = await w.stream("a", public=True, audience="everyone")
    server._GOLIVE_BATCH = 4
    sizes = []
    real = w.db.create_notifications_bulk

    async def spy(rows):
        sizes.append(len(rows))
        return await real(rows)

    w.db.create_notifications_bulk = spy
    try:
        await w.publish(key)
        await w.drain()
    finally:
        w.db.create_notifications_bulk = real
    users = len(await w.db.get_all_users()) - 1                 # everyone but the streamer
    assert sum(sizes) == users and max(sizes) <= 4 and len(sizes) >= 3, (sizes, users)


@case
async def test_one_announcement_per_cooldown_for_cards_and_notifications(w):
    sid, key = await w.stream("a", public=True, audience="everyone")
    for _ in range(3):
        assert await w.publish(key) == 200
        await w.db.set_stream_live(sid, False)
        w.clock.now += 60
    await w.drain()
    assert len(await w.notes("m1")) == 1
    cid = (await w.db.get_user_stream(sid))["chat_channel_id"]
    assert len(await w.cards(cid)) == 1
    await w.go_live_again(key, sid)                              # past the cooldown
    assert len(await w.notes("m1")) == 2 and len(await w.cards(cid)) == 2


@case
async def test_an_owner_broadcasts_to_everybody_once_per_cooldown_however_many_streams(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    a, akey = await w.stream("a", public=True, audience="everyone")
    b, bkey = await w.stream("b", public=True, audience="everyone")
    c, ckey = await w.stream("c", public=True, audience="followers")
    assert await w.follow("m1", b) == 200
    await w.publish(akey)
    await w.drain()
    w.clock.now += 60
    await w.publish(bkey)
    await w.publish(ckey)
    await w.drain()
    # a reached everybody; b (its own cooldown is free) reached only its follower; c is followers-only
    assert len(await w.notes("m2")) == 1 and len(await w.notes("m3")) == 1
    assert len(await w.notes("m1")) == 2, "a follower still gets the notice of the stream they follow"
    assert len(await w.notes("admin")) == 1
    # one card in the shared announce channel, and every stream's card in its own chat
    assert len(await w.cards(ann)) == 1 and "Show a" in (await w.cards(ann))[0]["message"]
    for sid in (a, b, c):
        assert len(await w.cards((await w.db.get_user_stream(sid))["chat_channel_id"])) == 1, sid
    # deleting the stream and making a new one does not reset it (the slot belongs to the owner)
    await w.db.delete_user_stream(a)
    d, dkey = await w.stream("d", public=True, audience="everyone")
    w.clock.now += 60
    await w.publish(dkey)
    await w.drain()
    assert len(await w.notes("m2")) == 1 and len(await w.cards(ann)) == 1
    # another owner is not held back by it
    e, ekey = await w.stream("e", public=True, audience="everyone", owner="admin")
    await w.publish(ekey)
    await w.drain()
    assert len(await w.notes("m2")) == 2
    # past the cooldown the owner's next stream reaches everybody again
    w.clock.now += 700
    f, fkey = await w.stream("f", public=True, audience="everyone")
    await w.publish(fkey)
    await w.drain()
    assert len(await w.notes("m2")) == 3 and len(await w.cards(ann)) == 3     # a, the other owner's e, f


@case
async def test_the_owner_slot_is_stored_and_one_claim_wins(w):
    uid = w.ids["owner"]
    results = await asyncio.gather(*[w.db.claim_golive_owner(uid, 1_000, 600) for _ in range(5)])
    assert results.count(True) == 1, results
    assert not await w.db.claim_golive_owner(uid, 1_599, 600)
    assert await w.db.claim_golive_owner(uid, 1_600, 600)
    assert await w.db.claim_golive_owner(uid, 100, 600), "a stored time in the future never blocks"
    assert await w.db.claim_golive_owner(w.ids["admin"], 100, 600), "per owner"


# ---------------------------------------------------------------------------
# cards

@case
async def test_a_card_goes_to_the_streams_own_chat_with_a_fallback_text(w):
    sid, key = await w.stream("a", public=True, audience="followers")
    cid = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.db.conn.execute("UPDATE users SET nickname = 'The Owner' WHERE id = ?", (w.ids["owner"],))
    await w.db.conn.commit()
    await w.publish(key)
    await w.drain()
    cards = await w.cards(cid)
    assert len(cards) == 1
    text = cards[0]["message"]
    assert "The Owner" in text and "Show a" in text and f"https://portal.example.test/watch/{sid}" in text, text
    assert "live_" not in text and "pub_" not in text
    # it is stored encrypted like any message
    cur = await w.db.conn.execute("SELECT message FROM chat_messages WHERE id = ?", (cards[0]["id"],))
    assert text not in (await cur.fetchone())["message"]
    # the card's own row is encrypted too: no plain title or streamer name at rest
    cur = await w.db.conn.execute("SELECT streamer, title FROM stream_cards")
    raw = await cur.fetchall()
    assert raw and all("Show a" not in r["title"] and "The Owner" not in r["streamer"] for r in raw), [dict(r) for r in raw]
    # history rebuilds the card for a viewer, with no key
    status, body = await w.call("GET", "m1", f"/api/chat/channels/{cid}/messages")
    assert status == 200
    m = [x for x in body["messages"] if x["message_type"] == "stream_card"][0]
    assert m["card"] == {"stream_id": sid, "streamer": "The Owner", "title": "Show a"}, m
    assert "live_" not in json.dumps(body) and "pub_" not in json.dumps(body)


@case
async def test_a_stream_created_with_a_go_live_message_and_audience_keeps_them(w):
    status, body = await w.call("POST", "owner", "/api/streams", json={
        "name": "Fresh", "golive_message": "{streamer} is on: {title}", "golive_audience": "everyone"})
    assert status in (200, 201), (status, body)
    sid = (body.get("stream") or body)["id"]
    row = await w.db.get_user_stream(sid)
    assert row["golive_message"] == "{streamer} is on: {title}" and row["golive_audience"] == "everyone", dict(row)
    status, body = await w.call("POST", "owner", "/api/streams", json={"name": "Plain"})
    assert status in (200, 201), (status, body)
    plain = await w.db.get_user_stream((body.get("stream") or body)["id"])
    assert not plain["golive_message"] and plain["golive_audience"] == "followers"


@case
async def test_a_card_is_stored_under_the_account_username_not_the_display_name(w):
    sid, key = await w.stream("a", public=True, audience="followers")
    cid = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.db.conn.execute("UPDATE users SET nickname = 'The Owner' WHERE id = ?", (w.ids["owner"],))
    await w.db.conn.commit()
    await w.publish(key)
    await w.drain()
    cards = await w.cards(cid)
    assert len(cards) == 1
    cur = await w.db.conn.execute("SELECT username FROM chat_messages WHERE id = ?", (cards[0]["id"],))
    assert (await cur.fetchone())["username"] == "owner"
    # the search index row carries the same account name, never the display name
    cur = await w.db.conn.execute("SELECT username FROM chat_fts_map WHERE message_id = ?", (cards[0]["id"],))
    row = await cur.fetchone()
    assert row is not None and row["username"] == "owner", row and dict(row)
    # the display name is kept in the card data
    status, body = await w.call("GET", "m1", f"/api/chat/channels/{cid}/messages")
    m = [x for x in body["messages"] if x["message_type"] == "stream_card"][0]
    assert m["card"]["streamer"] == "The Owner", m


@case
async def test_a_card_is_broadcast_to_the_room(w):
    sid, key = await w.stream("a", public=True)
    cid = (await w.db.get_user_stream(sid))["chat_channel_id"]
    name = (await w.db.get_chat_channel(cid))["name"]
    got = []
    real = server.broadcast_to_channel

    async def spy(channel, payload, **kw):
        got.append((channel, payload))

    server.broadcast_to_channel = spy
    try:
        await w.publish(key)
        await w.drain()
    finally:
        server.broadcast_to_channel = real
    cards = [p for c, p in got if p.get("message_type") == "stream_card"]
    assert len(cards) == 1 and cards[0]["card"]["stream_id"] == sid
    assert [c for c, p in got if p.get("message_type") == "stream_card"] == [name]
    assert cards[0]["type"] == "message" and "live_" not in json.dumps(cards[0])


@case
async def test_the_announce_channel_gets_a_public_streams_card_only(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    pub, pkey = await w.stream("a", public=True)
    priv, vkey = await w.stream("b", public=False)
    await w.publish(pkey)
    await w.publish(vkey)
    await w.drain()
    cards = await w.cards(ann)
    assert len(cards) == 1 and "Show a" in cards[0]["message"], cards
    # the private stream's card is in its own (closed) chat only, and nowhere a member can read
    own_priv = (await w.db.get_user_stream(priv))["chat_channel_id"]
    assert len(await w.cards(own_priv)) == 1
    own_pub = (await w.db.get_user_stream(pub))["chat_channel_id"]
    assert len(await w.cards(own_pub)) == 1
    other = await w.channel("other")
    assert await w.cards(other) == []


@case
async def test_a_private_announce_channel_gets_nothing(w):
    ann = await w.channel("announce", private=True)
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    pub, pkey = await w.stream("a", public=True)
    await w.publish(pkey)
    await w.drain()
    assert await w.cards(ann) == []
    # a channel that became the chat of a stream that is not public is not one either
    chat_priv, _ = await w.stream("c", public=False)
    cid = (await w.db.get_user_stream(chat_priv))["chat_channel_id"]
    await w.db.set_setting("stream_announce_channel_id", str(cid))
    await w.go_live_again(pkey, pub)
    assert await w.cards(cid) == []


@case
async def test_a_private_stream_bound_to_a_default_channel_gets_no_card_there(w):
    general = (await w.db.get_chat_channel_by_name("general"))["id"]
    sid, key = await w.stream("a", public=False, chat=False)
    await w.db.update_user_stream(sid, chat_channel_id=general)
    await w.publish(key)
    await w.drain()
    assert await w.cards(general) == []


@case
async def test_cards_leave_the_announce_channel_when_the_stream_becomes_private(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    own = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.publish(key)
    await w.drain()
    assert len(await w.cards(ann)) == 1 and len(await w.cards(own)) == 1
    deleted = []
    real = server.broadcast_to_channel

    async def spy(channel, payload, **kw):
        deleted.append((channel, payload))

    server.broadcast_to_channel = spy
    try:
        status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    finally:
        server.broadcast_to_channel = real
    assert status == 200
    assert await w.cards(ann) == []                              # gone where members read
    assert len(await w.cards(own)) == 1                          # the owner's closed chat keeps it
    assert [p["type"] for c, p in deleted if p.get("type") == "message_deleted"] == ["message_deleted"]
    assert await w.db.get_cards_of_stream(sid) and len(await w.db.get_cards_of_stream(sid)) == 1


@case
async def test_a_card_in_a_channel_that_became_private_goes_when_the_stream_does(w):
    # The announce channel became private (with a member) after the card was posted: the
    # member can still read the channel, so the card goes unless the stream is hers to watch
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    own = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.publish(key)
    await w.drain()
    assert len(await w.cards(ann)) == 1
    await w.db.update_chat_channel(ann, visibility="private")
    await w.db.add_channel_member(ann, w.ids["m1"])
    assert await server._can_read_channel(await w.db.get_chat_channel(ann), w.ids["m1"], "user")
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    assert status == 200
    assert await w.cards(ann) == []                              # not left for the channel's members
    status, body = await w.call("GET", "m1", f"/api/chat/channels/{ann}/messages")
    assert status == 200 and not [m for m in body["messages"] if m.get("message_type") == "stream_card"]
    assert len(await w.cards(own)) == 1                          # the closed own chat keeps it


@case
async def test_an_old_announce_channel_that_became_private_loses_the_card_too(w):
    # The setting moved on, the old channel kept the card and later became private
    old = await w.channel("old-announce")
    new = await w.channel("new-announce")
    await w.db.set_setting("stream_announce_channel_id", str(old))
    sid, key = await w.stream("a", public=True)
    await w.publish(key)
    await w.drain()
    assert len(await w.cards(old)) == 1
    await w.db.set_setting("stream_announce_channel_id", str(new))
    await w.db.update_chat_channel(old, visibility="private")
    await w.db.add_channel_member(old, w.ids["m2"])
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    assert status == 200 and await w.cards(old) == []


@case
async def test_a_private_stream_in_a_default_channel_loses_its_card_there(w):
    # Its own chat is a default channel (open to members): not a closed chat, so no card stays
    general = (await w.db.get_chat_channel_by_name("general"))["id"]
    sid, key = await w.stream("a", public=True, chat=False)
    await w.db.update_user_stream(sid, chat_channel_id=general)
    await w.publish(key)
    await w.drain()
    assert len(await w.cards(general)) == 1
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    assert status == 200 and await w.cards(general) == []


@case
async def test_the_race_check_also_clears_a_private_channel_with_members(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    stream = await w.db.get_user_stream(sid)
    payload = server._golive_payload(stream)
    real = server._post_go_live_card

    async def post_then_private(stream, payload, channel):
        out = await real(stream, payload, channel)
        if channel["id"] == ann:
            await w.db.update_chat_channel(ann, visibility="private")
            await w.db.add_channel_member(ann, w.ids["m1"])
            await w.db.conn.execute("UPDATE user_streams SET is_public = 0 WHERE id = ?", (sid,))
            await w.db.conn.commit()
        return out

    server._post_go_live_card = post_then_private
    try:
        await server._post_go_live_cards(stream, payload)
    finally:
        server._post_go_live_card = real
    assert await w.cards(ann) == []


@case
async def test_a_reply_to_a_removed_card_keeps_no_copy_of_it(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    await w.publish(key)
    await w.drain()
    card = (await w.cards(ann))[0]
    reply = await w.db.create_chat_message(
        ann, w.ids["m1"], "m1", "nice", reply_to=card["id"],
        reply_preview_username="The Owner", reply_preview_text=card["message"])
    status, _ = await w.call("PUT", "owner", f"/api/streams/{sid}", json={"is_public": False})
    assert status == 200 and await w.cards(ann) == []
    row = await w.db.get_chat_message(reply)
    assert not row["reply_preview_text"] and not row["reply_preview_username"], row


@case
async def test_a_card_written_while_the_stream_goes_private_is_removed(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    stream = await w.db.get_user_stream(sid)
    payload = server._golive_payload(stream)
    real = server._post_go_live_card

    async def post_then_private(stream, payload, channel):
        out = await real(stream, payload, channel)
        await w.db.conn.execute("UPDATE user_streams SET is_public = 0 WHERE id = ?", (sid,))
        await w.db.conn.commit()
        return out

    server._post_go_live_card = post_then_private
    try:
        await server._post_go_live_cards(stream, payload)
    finally:
        server._post_go_live_card = real
    assert await w.cards(ann) == []


@case
async def test_deleting_a_stream_removes_all_its_cards(w):
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    await w.publish(key)
    await w.drain()
    assert await w.cards(ann)
    status, _ = await w.call("DELETE", "owner", f"/api/streams/{sid}")
    assert status == 200 and await w.cards(ann) == []
    cur = await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_cards")
    assert (await cur.fetchone())["n"] == 0


async def _all_card_messages(w, channel_id):
    cur = await w.db.conn.execute(
        "SELECT id FROM chat_messages WHERE channel_id = ? AND message_type = 'stream_card'", (channel_id,))
    return [r["id"] for r in await cur.fetchall()]


async def _search_map_rows(w, ids):
    if not ids:
        return 0
    cur = await w.db.conn.execute(
        f"SELECT COUNT(*) AS n FROM chat_fts_map WHERE message_id IN ({','.join('?' * len(ids))})", list(ids))
    return (await cur.fetchone())["n"]


@case
async def test_a_card_written_while_the_stream_is_deleted_leaves_no_message(w):
    # Window (a): the message is inserted, the stream is deleted, linking the card fails
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    stream = await w.db.get_user_stream(sid)
    payload = server._golive_payload(stream)
    real = w.db.create_chat_message
    seen = []

    async def create_then_delete_stream(channel_id, *a, **kw):
        mid = await real(channel_id, *a, **kw)
        if channel_id == ann:
            seen.append(mid)
            status, _ = await w.call("DELETE", "owner", f"/api/streams/{sid}")
            assert status == 200
        return mid

    w.db.create_chat_message = create_then_delete_stream
    try:
        await server._post_go_live_cards(stream, payload)
    finally:
        w.db.create_chat_message = real
    assert seen
    assert await _all_card_messages(w, ann) == []
    assert await _search_map_rows(w, seen) == 0
    cur = await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_cards WHERE stream_id = ?", (sid,))
    assert (await cur.fetchone())["n"] == 0


@case
async def test_a_card_written_between_the_cards_removal_and_the_stream_delete_is_removed(w):
    # Window (b): a full card write, then the stream row goes (its card rows cascade away)
    ann = await w.channel("announce")
    await w.db.set_setting("stream_announce_channel_id", str(ann))
    sid, key = await w.stream("a", public=True)
    stream = await w.db.get_user_stream(sid)
    payload = server._golive_payload(stream)
    realpost = server._post_go_live_card
    written = []

    async def post_then_delete(stream, payload, channel):
        out = await realpost(stream, payload, channel)
        written.append(out)
        if channel["id"] == ann:
            await w.db.delete_user_stream(sid)
        return out

    server._post_go_live_card = post_then_delete
    try:
        await server._post_go_live_cards(stream, payload)
    finally:
        server._post_go_live_card = realpost
    own = stream["chat_channel_id"]
    assert written
    assert await _all_card_messages(w, ann) == []
    assert await _all_card_messages(w, own) == []     # the card in its own chat goes too, though the chat stays
    assert await _search_map_rows(w, written) == 0


@case
async def test_retention_removes_the_card_with_the_message(w):
    sid, key = await w.stream("a", public=True)
    own = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.publish(key)
    await w.drain()
    mid = (await w.cards(own))[0]["id"]
    await w.db.conn.execute("UPDATE chat_messages SET created_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (mid,))
    await w.db.conn.commit()
    assert await w.db.cleanup_old_chat_messages(days=7) >= 1
    assert await w.db.get_stream_cards([mid]) == {}


@case
async def test_the_streamer_cannot_reword_a_card(w):
    sid, key = await w.stream("a", public=True)
    own = (await w.db.get_user_stream(sid))["chat_channel_id"]
    await w.publish(key)
    await w.drain()
    card = (await w.cards(own))[0]
    assert card["user_id"] == w.ids["owner"]
    assert w.db.chat_message_editable(card, w.ids["owner"]) is False
    assert await w.db.edit_chat_message(card["id"], w.ids["owner"], "buy my stuff") is None
    # an ordinary message of theirs is still editable
    mid = await w.db.create_chat_message(own, w.ids["owner"], "owner", "hi")
    assert w.db.chat_message_editable(await w.db.get_chat_message(mid), w.ids["owner"]) is True


@case
async def test_the_announce_setting_is_checked(w):
    ann = await w.channel("announce")
    priv = await w.channel("closed", private=True)
    sid, _ = await w.stream("a", public=True)
    stream_chat = (await w.db.get_user_stream(sid))["chat_channel_id"]

    async def put(who, value):
        return await w.call("PUT", who, "/api/settings/permissions", json={"stream_announce_channel_id": value})

    assert (await put("m1", ann))[0] in (401, 403)
    assert (await put("admin", priv))[0] == 400
    assert (await put("admin", stream_chat))[0] == 400
    assert (await put("admin", 99999))[0] == 404
    assert (await put("admin", "7"))[0] == 400
    assert (await put("admin", True))[0] == 400
    assert (await put("admin", ann))[0] == 200
    status, body = await w.call("GET", "admin", "/api/settings/permissions")
    assert body["stream_announce_channel_id"] == ann
    assert (await put("admin", None))[0] == 200
    assert (await w.call("GET", "admin", "/api/settings/permissions"))[1]["stream_announce_channel_id"] is None


# ---------------------------------------------------------------------------
# live now

@case
async def test_live_now_lists_only_what_the_viewer_may_watch_and_no_key(w):
    pub, _ = await w.stream("a", public=True)
    priv, _ = await w.stream("b", public=False)
    off, _ = await w.stream("c", public=True)
    for s in (pub, priv):
        await w.db.set_stream_live(s, True)
    await w.follow("m1", pub)

    async def ids(who):
        status, body = await w.call("GET", who, "/api/streams/live")
        assert status == 200
        return {s["id"] for s in body["streams"]}, body

    assert (await ids("m1"))[0] == {pub}
    assert (await ids("owner"))[0] == {pub, priv}
    assert (await ids("admin"))[0] == {pub, priv}
    _, body = await ids("m1")
    assert body["streams"][0]["following"] is True
    text = json.dumps(body)
    for needle in ("live_", "pub_", "public_key", "stream_key", off and "Show c"):
        assert needle not in text, needle
    status, _ = await w.call("GET", None, "/api/streams/live")
    assert status == 401


# ---------------------------------------------------------------------------
# the pages (text checks: no browser here)

def test_a_go_live_card_is_not_offered_edit_and_copies_its_fallback_text():
    chat = (ROOT / "static" / "chat.html").read_text()
    js = (ROOT / "static" / "js" / "streams.js").read_text()
    # chat: the card keeps its stored fallback text; Edit is not offered; copy and reply use it
    assert "div.dataset.cardText = data.message" in chat
    assert "const canEdit = isOwner && !isCard && isWithinEditWindow(" in chat
    assert "contextMenuMessageText = isCard ? (msgEl.dataset.cardText" in chat
    assert "msgEl.classList.contains('stream-card-message') ? (msgEl.dataset.cardText" in chat
    # streams.js: a failed save puts the previous audience back (rejected PUT and network error)
    start = js.index("async function updateStreamGoLiveAudience(")
    fn = js[start:js.index("\n}\n", start)]
    assert "dataset.current" in fn and fn.count("restore();") == 2, fn
    assert "audienceSelect.dataset.current = audienceSelect.value" in js


def test_the_pages_use_the_servers_follow_state_and_build_cards_safely():
    chat = (ROOT / "static" / "chat.html").read_text()
    streams = (ROOT / "static" / "streams.html").read_text()
    watch = (ROOT / "static" / "watch.html").read_text()
    js = (ROOT / "static" / "js" / "streams.js").read_text()
    admin = (ROOT / "static" / "admin.html").read_text()
    # the localStorage gate for stream alerts is gone; the chat page follows on the server
    assert "_subscribedStreams" not in chat
    assert "localStorage.getItem('portal_notif_streams')" not in chat
    assert "/api/me/follows" in chat and "/follow`" in chat and "/api/streams/live" in chat
    # streams and watch pages have the toggle
    assert "data-follow-stream" in streams and "/follow`" in streams
    assert 'id="follow-btn"' in watch and "/follow`" in watch
    # the owner's settings carry the audience and a follower count
    assert "golive_audience" in js and "follower_count" in js
    assert "stream_announce_channel_id" in admin
    # the card is built from text nodes and a link from the numeric stream id only
    start = chat.index("data.message_type === 'stream_card'")
    block = chat[start:chat.index("// If message has a poll", start)]
    assert "Number(data.card.stream_id)" in block and "textContent = data.card.title" in block
    assert "innerHTML" not in block
    strip = chat[chat.index("function renderLiveNow"):]
    strip = strip[:strip.index("function updateStreamStatus")]
    assert "innerHTML" not in strip and "Number(st.id)" in strip


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
