"""Who may watch a stream: one decision for HLS, thumbnails, WHEP (and its sessions), the
info route and the MediaMTX hook's read action.

The real handlers run in-process against a temporary database with real sessions and
API keys; only the MediaMTX side is replaced by a fake HTTP client (nothing is dialled,
tests/outbound_guard.py refuses anything that is not loopback). Not proven here: a real
MediaMTX, OBS, VLC or a browser playing the stream (the stage smoke check and a real
run on the production host are for that).

* decision table: owner and admin always, a member only for a public stream, nobody
  logged in only for a public stream with the open link on and the stream's current
  pub_ key; a moderator is not an admin; stream keys (live_) never let anyone watch
* every refusal (private, wrong, rotated or unknown key) is the same 404 body
* credentials: session cookie, full-scope API key; a scoped key, a stream key header
  and an expired or revoked session do not count
* cache: per-segment requests read nothing from the database, entries expire after
  5 seconds, and are dropped on visibility, open-link, share-key and live-key changes,
  stream delete, and when the credential's owner is signed out; the cache is bounded
* headers: Access-Control-Allow-Origin only on an open share link, private caching
  otherwise; a ?token= is not passed to MediaMTX
* WHEP sessions need the same permission; the hook's read action follows the decision

Run: venv/bin/python tests/test_stream_access.py
"""

import asyncio
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import auth  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

NOT_FOUND_BODY = b'{"error": "Stream not found"}'


class Transport:
    def __init__(self, ip="203.0.113.9"):
        self.ip = ip

    def get_extra_info(self, name, default=None):
        return (self.ip, 5555) if name == "peername" else default


class FakeResp:
    def __init__(self, status=200, body=b"", content_type="application/vnd.apple.mpegurl", headers=None):
        self.status = status
        self._body = body
        self.content_type = content_type
        self.headers = headers or {}

    async def read(self):
        return self._body

    async def text(self):
        return self._body.decode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class FakeSession:
    """Stands in for aiohttp.ClientSession towards MediaMTX; remembers every call."""
    calls = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kw):
        FakeSession.calls.append(("GET", url))
        path = url.split("?")[0]
        if path.endswith(".m3u8"):
            body = ("#EXTM3U\n#EXTINF:1.0,\n/live/%s/seg0.mp4?session=abc\n" % path.split("/live/")[1].split("/")[0]).encode()
            return FakeResp(200, body)
        return FakeResp(200, b"SEGMENT", "video/mp4")

    def post(self, url, **kw):
        FakeSession.calls.append(("POST", url))
        return FakeResp(201, b"v=0 answer", "application/sdp", {"Location": "/x/whep/sess-" + url.rsplit("/", 2)[-2][-6:]})

    def request(self, method, url, **kw):
        FakeSession.calls.append((method, url))
        return FakeResp(204, b"", "application/json")


class World:
    """A temporary database with an owner, an admin, a moderator, two members and four streams."""

    async def build(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="streamaccess_")
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        self.old = (server.db, auth.db)
        server.db = self.db
        auth.db = self.db
        self.users = {}
        for name, role in (("owner", "user"), ("admin", "admin"), ("mod", "moderator"),
                           ("member", "user"), ("other", "user")):
            uid = await self.db.create_user(name, "x")
            if role != "user":
                await self.db.set_user_role(uid, role)
            self.users[name] = uid
        self.streams = {}
        for label, public, open_link in (("private", 0, 0), ("public", 1, 0), ("open", 1, 1), ("second", 0, 0)):
            sk, pk = "live_" + label * 3 + "K" * 12, "pub_" + label * 3 + "P" * 12
            sid = await self.db.create_user_stream(self.users["owner"] if label != "second" else self.users["other"],
                                                   label, sk, public_key=pk, is_public=bool(public))
            await self.db.update_user_stream(sid, allow_unauthenticated=open_link)
            await self.db.set_stream_live(sid, True)
            self.streams[label] = {"id": sid, "live": sk, "pub": pk}
        self.cookie = {}
        for name, uid in self.users.items():
            scopes = ["*"] if name == "admin" else ["services:read", "access:*"]
            self.cookie[name], _ = await auth.create_access_token(uid, scopes)
        server._playback_cache_forget(everything=True)
        server._webrtc_sessions.clear()
        server._thumbnail_cache.clear()
        FakeSession.calls = []

        async def mtx():
            return {"hls_port": 8888, "webrtc_port": 8889}

        self.saved = (server._get_mediamtx_config, server.aiohttp.ClientSession)
        server._get_mediamtx_config = mtx
        server.aiohttp.ClientSession = FakeSession
        self.reads = 0
        real_execute = self.db.conn.execute
        world = self

        async def counting_execute(*a, **kw):
            world.reads += 1
            return await real_execute(*a, **kw)

        self.db.conn.execute = counting_execute
        return self

    async def close(self):
        server._get_mediamtx_config, server.aiohttp.ClientSession = self.saved
        server.db, auth.db = self.old
        await self.db.close()
        self.tmp.cleanup()

    def req(self, key, user=None, method="GET", path="index.m3u8", headers=None, query="", peer="203.0.113.9",
            session=None, cookie=None):
        h = dict(headers or {})
        c = cookie if cookie is not None else (self.cookie[user] if user else None)
        if c:
            h["Cookie"] = f"{Config.SESSION_COOKIE_NAME}={c}"
        url = f"/api/stream/{key}/hls/{path}" + (f"?{query}" if query else "")
        mi = {"stream_key": key, "path": path}
        if session:
            mi["session_id"] = session
        return make_mocked_request(method, url, headers=h, match_info=mi, transport=Transport(peer))


def run(coro_fn):
    async def go():
        w = await World().build()
        try:
            await coro_fn(w)
        finally:
            await w.close()
    asyncio.run(go())


def hdr(resp, name):
    return resp.headers.get(name)


# ---------------------------------------------------------------------------

def test_decision_table():
    allowed = server._stream_read_allowed
    priv = {"user_id": 1, "is_public": 0, "allow_unauthenticated": 0}
    pub = {"user_id": 1, "is_public": 1, "allow_unauthenticated": 0}
    opn = {"user_id": 1, "is_public": 1, "allow_unauthenticated": 1}
    odd = {"user_id": 1, "is_public": 0, "allow_unauthenticated": 1}   # open flag without public
    rows = [
        # stream, user_id, role, via_pub_key, expected
        (priv, 1, "user", True, True), (priv, 1, "user", False, True),
        (priv, 9, "admin", False, True), (priv, 9, "superadmin", False, True),
        (priv, 9, "moderator", True, False), (priv, 9, "user", True, False),
        (pub, 9, "user", True, True), (pub, 9, "user", False, True),
        (priv, None, "user", True, False), (pub, None, "user", True, False),
        (opn, None, "user", True, True), (opn, None, "user", False, False),
        (odd, None, "user", True, False), (odd, 9, "user", True, False),
    ]
    for stream, uid, role, via, expected in rows:
        assert allowed(stream, uid, role, via) is expected, (stream, uid, role, via, expected)


def test_who_gets_in():
    async def body(w):
        async def ask(label, user=None, key="pub", **kw):
            k = w.streams[label][key]
            stream, err = await server._validate_stream_access(k, request=w.req(k, user, **kw))
            return bool(stream), err

        # no login
        assert (await ask("private"))[0] is False
        assert (await ask("public"))[0] is False                     # public but not open: needs a login
        assert (await ask("open"))[0] is True                        # the open share link
        assert (await ask("open", key="live"))[0] is False           # a live_ key is not a way to watch
        assert (await ask("private", key="live"))[0] is False
        # logged in
        assert (await ask("private", "owner"))[0] is True
        assert (await ask("private", "owner", key="live"))[0] is True   # the owner's own page may name it by live_ key
        assert (await ask("private", "admin"))[0] is True
        assert (await ask("private", "mod"))[0] is False                # a moderator is not an admin
        assert (await ask("private", "member"))[0] is False
        assert (await ask("public", "member"))[0] is True
        assert (await ask("public", "member", key="live"))[0] is True
        assert (await ask("open", "member"))[0] is True
        assert (await ask("second", "owner"))[0] is False               # another user's private stream
        err = (await ask("private"))[1]
        assert err == "Stream not found"
        # read without a request judges nothing
        assert (await server._validate_stream_access(w.streams["open"]["pub"]))[0] is None
    run(body)


def test_refusals_are_one_identical_404():
    async def body(w):
        bodies = set()
        statuses = set()
        # unknown key, private stream, rotated key, public stream not open: all logged out
        keys = ["pub_doesnotexist", "live_doesnotexist", w.streams["private"]["pub"], w.streams["private"]["live"],
                w.streams["public"]["pub"]]
        old = w.streams["open"]["pub"]
        assert await w.db.regenerate_public_key(w.streams["open"]["id"], "pub_rotatedrotatedrotated1")
        keys.append(old)
        for key in keys:
            for handler in (server.http_stream_hls_proxy, server.http_stream_thumbnail, server.http_stream_info,
                            server.http_stream_webrtc_whep):
                resp = await handler(w.req(key, method="POST" if handler is server.http_stream_webrtc_whep else "GET"))
                statuses.add(resp.status)
                bodies.add(resp.body)
        assert statuses == {404}, statuses
        assert bodies == {NOT_FOUND_BODY}, bodies
        assert not FakeSession.calls, "nothing reached MediaMTX"
        # a logged-in member asking for the private stream gets the same bytes
        resp = await server.http_stream_info(w.req(w.streams["private"]["pub"], "member"))
        assert resp.status == 404 and resp.body == NOT_FOUND_BODY
        # the rotated key: its owner (logged in) is still let in with the new one only
        resp = await server.http_stream_info(w.req(old, "owner"))
        assert resp.status == 404
        resp = await server.http_stream_info(w.req("pub_rotatedrotatedrotated1", "owner"))
        assert resp.status == 200
        # and logged out the new key of an open stream plays
        resp = await server.http_stream_hls_proxy(w.req("pub_rotatedrotatedrotated1"))
        assert resp.status == 200
    run(body)


def test_credentials():
    async def body(w):
        priv = w.streams["private"]["pub"]
        pubstream = w.streams["public"]["pub"]
        # a stream key sent as a credential does not make anyone a viewer, even of the
        # stream of an admin who owns it: the admin's own stream key authenticates as the admin
        await w.db.set_user_role(w.users["owner"], "admin")
        hdrs = {"X-Stream-Key": w.streams["private"]["live"]}
        resp = await server.http_stream_info(w.req(w.streams["second"]["pub"], headers=hdrs))
        assert resp.status == 404, "a stream key is not a way to watch someone else's stream"
        hdrs = {"Authorization": "Stream-Key " + w.streams["private"]["live"]}
        resp = await server.http_stream_info(w.req(w.streams["second"]["pub"], headers=hdrs))
        assert resp.status == 404
        # a valid session next to a stream key header still counts as the session
        server._playback_cache_forget(everything=True)
        resp = await server.http_stream_info(w.req(pubstream, "member", headers=hdrs))
        assert resp.status == 200
        await w.db.set_user_role(w.users["owner"], "user")
        server._playback_cache_forget(everything=True)

        # full-scope API key of the owner works; a scoped one does not
        full_key, full_hash, full_prefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["owner"], "full", full_hash, full_prefix, scopes="*")
        scoped_key, scoped_hash, scoped_prefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["owner"], "scoped", scoped_hash, scoped_prefix, scopes="services:read")
        resp = await server.http_stream_info(w.req(priv, headers={"X-API-Key": full_key}))
        assert resp.status == 200
        resp = await server.http_stream_info(w.req(priv, headers={"Authorization": "Api-Key " + full_key}))
        assert resp.status == 200
        resp = await server.http_stream_info(w.req(priv, headers={"X-API-Key": scoped_key}))
        assert resp.status == 404, "a scoped API key does not carry the viewing right"
        # a scoped key is judged as nobody logged in: an open link still plays
        resp = await server.http_stream_info(w.req(w.streams["open"]["pub"], headers={"X-API-Key": scoped_key}))
        assert resp.status == 200
        # a bearer token and a ?token= of the owner
        jwt, _ = await auth.create_access_token(w.users["owner"], ["*"])
        resp = await server.http_stream_info(w.req(priv, headers={"Authorization": "Bearer " + jwt}))
        assert resp.status == 200
        resp = await server.http_stream_info(w.req(priv, query="token=" + jwt))
        assert resp.status == 200
        # a revoked session no longer counts (after the cache time)
        jwt2, tid2 = await auth.create_access_token(w.users["owner"], ["*"])
        resp = await server.http_stream_info(w.req(priv, cookie=jwt2))
        assert resp.status == 200
        assert await w.db.revoke_token(tid2, w.users["owner"])
        server._playback_cache_forget(everything=True)
        resp = await server.http_stream_info(w.req(priv, cookie=jwt2))
        assert resp.status == 404
        # garbage cookie: nobody logged in
        resp = await server.http_stream_info(w.req(priv, cookie="garbage"))
        assert resp.status == 404
        resp = await server.http_stream_info(w.req(w.streams["open"]["pub"], cookie="garbage"))
        assert resp.status == 200
    run(body)


def test_segments_cost_no_database_reads_and_cache_expires():
    async def body(w):
        key = w.streams["public"]["pub"]
        clock = [1000.0]
        real_now = server._playback_now
        server._playback_now = lambda: clock[0]
        try:
            first = await server.http_stream_hls_proxy(w.req(key, "member"))
            assert first.status == 200
            reads_after_first = w.reads
            assert reads_after_first > 0
            for i in range(60):
                clock[0] += 0.05
                r = await server.http_stream_hls_proxy(w.req(key, "member", path=f"seg{i}.mp4", query="session=abc"))
                assert r.status == 200 and r.body == b"SEGMENT"
            assert w.reads == reads_after_first, f"{w.reads - reads_after_first} database reads for 60 segments"
            # logged-out viewers of an open link cost nothing either
            okey = w.streams["open"]["pub"]
            await server.http_stream_hls_proxy(w.req(okey))
            base = w.reads
            for i in range(60):
                await server.http_stream_hls_proxy(w.req(okey, path=f"seg{i}.mp4"))
            assert w.reads == base
            # after 5 seconds the decision is made again
            clock[0] += server._PLAYBACK_AUTH_TTL + 0.1
            base = w.reads
            r = await server.http_stream_hls_proxy(w.req(key, "member", path="seg99.mp4"))
            assert r.status == 200 and w.reads > base
            # the stream made private (straight in the database, as another process could): the
            # viewer is out within the cache time without anybody calling invalidate
            await w.db.update_user_stream(w.streams["public"]["id"], is_public=False)
            r = await server.http_stream_hls_proxy(w.req(key, "member", path="seg100.mp4"))
            assert r.status == 200, "still inside the cache time"
            clock[0] += server._PLAYBACK_AUTH_TTL + 0.1
            r = await server.http_stream_hls_proxy(w.req(key, "member", path="seg101.mp4"))
            assert r.status == 404
        finally:
            server._playback_now = real_now
    run(body)


def test_cache_is_bounded():
    async def body(w):
        key = w.streams["open"]["pub"]
        small = server._PLAYBACK_AUTH_MAX
        server._PLAYBACK_AUTH_MAX = 20
        try:
            for i in range(200):
                r = await server.http_stream_info(w.req(key, cookie="junk%d" % i))
                assert r.status == 200
                assert len(server._playback_auth_cache) <= 20
        finally:
            server._PLAYBACK_AUTH_MAX = small
    run(body)


def test_changes_drop_cached_decisions():
    async def body(w):
        # the real owner route is used, so the invalidation call sites are the ones that run
        owner_id = w.users["owner"]
        sid = w.streams["public"]["id"]
        key = w.streams["public"]["pub"]
        server.db = w.db

        async def watch(user="member"):
            return (await server.http_stream_hls_proxy(w.req(key, user, path="seg.mp4"))).status

        async def update(**data):
            req = make_mocked_request("PUT", f"/api/streams/{sid}", match_info={"id": str(sid)},
                                      headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"},
                                      transport=Transport())
            req.json = lambda: _coro(data)
            return await server.http_update_user_stream(req)

        assert await watch() == 200
        # made private: the member is out at once, the owner is not, the old key is gone
        resp = await update(is_public=False)
        assert resp.status == 200
        new_key = json.loads(resp.body)["public_key"]
        assert await watch() == 404
        assert await watch("owner") == 404, "the old pub_ key was rotated away"
        key = new_key
        assert await watch("owner") == 200
        assert await watch() == 404
        # public again: the member is back
        resp = await update(is_public=True)
        assert resp.status == 200 and await watch() == 200
        # open link switched on: logged out plays; switched off: stops at once
        assert await watch(None) == 404
        assert (await update(allow_unauthenticated=True)).status == 200
        assert await watch(None) == 200
        assert (await update(allow_unauthenticated=False)).status == 200
        assert await watch(None) == 404
        # share link rotation
        assert (await update(allow_unauthenticated=True)).status == 200
        assert await watch(None) == 200
        req = make_mocked_request("POST", f"/api/streams/{sid}/regenerate-public-key", match_info={"id": str(sid)},
                                  headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"},
                                  transport=Transport())
        resp = await server.http_regenerate_public_key(req)
        assert resp.status == 200
        assert await watch(None) == 404 and await watch("member") == 404
        key = json.loads(resp.body)["public_key"]
        assert await watch(None) == 200
        # a rotated live key: the stream path changes, so the cached record is dropped
        req = make_mocked_request("POST", f"/api/streams/{sid}/regenerate-key", match_info={"id": str(sid)},
                                  headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"},
                                  transport=Transport())
        before = len(server._playback_auth_cache)
        assert before > 0
        resp = await server.http_regenerate_stream_key(req)
        assert resp.status == 200
        assert not [v for v in server._playback_auth_cache.values() if v[2] == sid]
        # the stream deleted
        assert await watch(None) == 200
        req = make_mocked_request("DELETE", f"/api/streams/{sid}", match_info={"id": str(sid)},
                                  headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"},
                                  transport=Transport())
        assert (await server.http_delete_user_stream(req)).status == 200
        assert await watch(None) == 404
    run(body)


async def _coro(value):
    return value


def test_sign_out_drops_the_credentials_decisions():
    async def body(w):
        key = w.streams["public"]["pub"]
        assert (await server.http_stream_info(w.req(key, "member"))).status == 200
        assert (await server.http_stream_info(w.req(key, "other"))).status == 200
        assert any(v[1] == w.users["member"] for v in server._playback_auth_cache.values())
        # the revocation path: tokens revoked, then sockets closed (which clears the cache)
        await w.db.revoke_all_user_tokens(w.users["member"]) if hasattr(w.db, "revoke_all_user_tokens") else None
        await server.close_user_websockets(w.users["member"])
        assert not any(v[1] == w.users["member"] for v in server._playback_auth_cache.values())
        assert any(v[1] == w.users["other"] for v in server._playback_auth_cache.values()), "others stay"
    run(body)


def test_headers():
    async def body(w):
        for label, cors in (("open", True), ("public", False), ("private", False)):
            key = w.streams[label]["pub"]
            user = None if label == "open" else "owner"
            hls = await server.http_stream_hls_proxy(w.req(key, user))
            assert hls.status == 200
            assert (hdr(hls, "Access-Control-Allow-Origin") == "*") is cors, label
            assert hdr(hls, "Cache-Control") == ("no-cache" if cors else "private, no-cache"), (label, hls.headers)
            info = await server.http_stream_info(w.req(key, user))
            assert (hdr(info, "Access-Control-Allow-Origin") == "*") is cors
            server._thumbnail_cache[w.streams[label]["live"]] = (server.time(), b"JPEG")
            th = await server.http_stream_thumbnail(w.req(key, user))
            assert th.status == 200 and th.body == b"JPEG"
            assert (hdr(th, "Access-Control-Allow-Origin") == "*") is cors
            assert hdr(th, "Cache-Control") == ("public, max-age=5" if cors else "private, max-age=15"), hls.headers
            whep = await server.http_stream_webrtc_whep(_whep_request(w, key, user))
            assert whep.status == 201, (label, whep.status)
            assert (hdr(whep, "Access-Control-Allow-Origin") == "*") is cors
            assert (hdr(whep, "Access-Control-Expose-Headers") == "Location") is cors
            assert hdr(whep, "Location")
        # the refusal is not cached by anyone
        r = await server.http_stream_info(w.req(w.streams["private"]["pub"]))
        assert r.status == 404 and hdr(r, "Cache-Control") == "no-store" and not hdr(r, "Access-Control-Allow-Origin")
    run(body)


def _whep_request(w, key, user):
    req = w.req(key, user, method="POST")
    req.text = lambda: _coro("v=0 offer")
    return req


def test_token_in_the_query_is_not_passed_on():
    async def body(w):
        key = w.streams["private"]["pub"]
        jwt, _ = await auth.create_access_token(w.users["owner"], ["*"])
        r = await server.http_stream_hls_proxy(w.req(key, path="index.m3u8", query=f"session=abc&token={jwt}&x=1"))
        assert r.status == 200
        url = FakeSession.calls[-1][1]
        assert "token" not in url and jwt not in url and "session=abc" in url and "x=1" in url, url
        # a playlist is rewritten to the same key
        assert f"/api/stream/{key}/hls/seg0.mp4" in r.body.decode()
        # query without a token is passed through untouched
        await server.http_stream_hls_proxy(w.req(key, "owner", path="index.m3u8", query="session=a%2Bb&_HLS_msn=3"))
        assert FakeSession.calls[-1][1].endswith("?session=a%2Bb&_HLS_msn=3"), FakeSession.calls[-1][1]
    run(body)


def test_whep_sessions_follow_the_decision():
    async def body(w):
        sid = w.streams["public"]["id"]
        key = w.streams["public"]["pub"]
        r = await server.http_stream_webrtc_whep(_whep_request(w, key, "member"))
        assert r.status == 201
        session = r.headers["Location"].rsplit("/", 1)[1]
        assert session in server._webrtc_sessions
        # the member may end it; nobody logged out may touch it
        rec, err, status, _ = await server._authorize_webrtc_session(w.req(key, "member"), key, session)
        assert status == 200 and rec[0] == "whep"
        rec, err, status, _ = await server._authorize_webrtc_session(w.req(key), key, session)
        assert status == 404 and err == "Stream not found"
        # a publishing session still needs the publish key, and a viewer's decision does not help
        server._webrtc_session_remember("whip-1", "whip", sid, w.streams["public"]["live"])
        for who in ("member", "owner", None):
            rec, err, status, _ = await server._authorize_webrtc_session(w.req(key, who), key, "whip-1")
            assert status == 404
        rec, err, status, _ = await server._authorize_webrtc_session(w.req(w.streams["public"]["live"]),
                                                                    w.streams["public"]["live"], "whip-1")
        assert status == 200 and rec[0] == "whip"
        # the session handler answers 404 for a refused viewer, and the open header only for open streams
        resp = await server.http_stream_webrtc_session(w.req(key, None, method="PATCH", session=session))
        assert resp.status == 404 and resp.body == NOT_FOUND_BODY
        resp = await server.http_stream_webrtc_session(w.req(key, "member", method="PATCH", session=session))
        assert resp.status == 204 and not hdr(resp, "Access-Control-Allow-Origin")
        # made private: the viewers' sessions are forgotten, the member cannot touch the old one
        r2 = await server.http_stream_webrtc_whep(_whep_request(w, key, "member"))
        s2 = r2.headers["Location"].rsplit("/", 1)[1]
        server._stream_access_changed(sid, drop_sessions=False)     # a rename: sessions stay
        assert s2 in server._webrtc_sessions
        server._stream_access_changed(sid)
        assert s2 not in server._webrtc_sessions and "whip-1" in server._webrtc_sessions
    run(body)


class HookRequest:
    def __init__(self, data, peer="127.0.0.1"):
        self.transport = Transport(peer)
        self._data = data
        self.headers = {}

    async def json(self):
        return self._data


def test_hook_read_action():
    async def body(w):
        async def hook(path, ip, password="", action="read", peer="127.0.0.1"):
            resp = await server.http_stream_auth(HookRequest(
                {"action": action, "path": path, "ip": ip, "user": "", "password": password}, peer))
            return resp.status
        priv, pub = w.streams["private"]["live"], w.streams["public"]["live"]
        # the portal's own readers (loopback) are let through, for a live_ path and an rtmp_ one
        assert await hook("live/" + priv, "127.0.0.1") == 200
        assert await hook("live/rtmp_sometoken", "::1") == 200
        assert await hook("live/" + priv, "::ffff:127.0.0.1", action="playback") == 200
        # an outside reader is judged as a viewer, and a live_ path is not a credential
        assert await hook("live/" + pub, "198.51.100.4") == 403
        assert await hook("live/" + priv, "198.51.100.4") == 403
        key, key_hash, prefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["member"], "m", key_hash, prefix, scopes="*")
        assert await hook("live/" + pub, "198.51.100.4", key) == 200
        assert await hook("live/" + priv, "198.51.100.4", key) == 403
        okey, ohash, oprefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["owner"], "o", ohash, oprefix, scopes="*")
        assert await hook("live/" + priv, "198.51.100.4", okey) == 200
        # not from MediaMTX's own machine at all: forbidden
        assert await hook("live/" + priv, "127.0.0.1", peer="8.8.8.8") == 403
    run(body)


def test_every_playback_route_uses_the_decision():
    """A route that answered from a key alone would be a hole: the five playback handlers must
    not call the key lookups directly."""
    src = (ROOT / "server.py").read_text()
    for name in ("http_stream_hls_proxy", "http_stream_thumbnail", "http_stream_info",
                 "http_stream_webrtc_whep"):
        start = src.index(f"async def {name}(")
        end = src.index("\nasync def ", start + 10)
        chunk = src[start:end]
        assert "_validate_stream_access(" in chunk and "request=request" in chunk, name
        assert "get_stream_by_public_key" not in chunk and "get_stream_by_key" not in chunk, name
        assert '"Access-Control-Allow-Origin": "*"' not in chunk, name


# ---------------------------------------------------------------------------
# A stream key authorises publishing only; stream management and viewing routes
# need a session or a full-scope token / API key.

# (handler, method, path template, match_info keys)
_MANAGEMENT_CALLS = [
    ("http_list_user_streams", "GET", "/api/streams"),
    ("http_create_user_stream", "POST", "/api/streams"),
    ("http_get_public_streams", "GET", "/api/streams/public"),
    ("http_live_now", "GET", "/api/streams/live"),
    ("http_my_follows", "GET", "/api/me/follows"),
    ("http_follow_stream", "PUT", "/api/streams/{id}/follow"),
    ("http_unfollow_stream", "DELETE", "/api/streams/{id}/follow"),
    ("http_get_user_stream", "GET", "/api/streams/{id}"),
    ("http_update_user_stream", "PUT", "/api/streams/{id}"),
    ("http_delete_user_stream", "DELETE", "/api/streams/{id}"),
    ("http_regenerate_stream_key", "POST", "/api/streams/{id}/regenerate-key"),
    ("http_regenerate_public_key", "POST", "/api/streams/{id}/regenerate-public-key"),
    ("http_create_rtmp_token", "POST", "/api/streams/{id}/rtmp-token"),
    ("http_upload_stream_thumbnail", "POST", "/api/streams/{id}/thumbnail"),
    ("http_delete_stream_thumbnail", "DELETE", "/api/streams/{id}/thumbnail"),
    ("http_get_stream_bans", "GET", "/api/streams/{id}/bans"),
    ("http_create_stream_ban", "POST", "/api/streams/{id}/bans"),
    ("http_remove_stream_ban", "DELETE", "/api/streams/{id}/bans/{user_id}"),
    ("http_remove_stream_ban_by_id", "DELETE", "/api/streams/{id}/bans/id/{ban_id}"),
    ("http_list_relay_destinations", "GET", "/api/streams/{id}/relays"),
    ("http_create_relay_destination", "POST", "/api/streams/{id}/relays"),
    ("http_update_relay_destination", "PUT", "/api/streams/{id}/relays/{relay_id}"),
    ("http_delete_relay_destination", "DELETE", "/api/streams/{id}/relays/{relay_id}"),
    ("http_get_relay_logs", "GET", "/api/streams/{id}/relays/{relay_id}/logs"),
]


def test_a_stream_key_or_a_scoped_key_manages_no_stream():
    async def body(w):
        sid = w.streams["private"]["id"]
        before = await w.db.get_user_stream(sid)
        full_key, full_hash, full_prefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["owner"], "full", full_hash, full_prefix, scopes="*")
        scoped_key, scoped_hash, scoped_prefix = auth.generate_api_key()
        await w.db.create_api_key(w.users["owner"], "scoped", scoped_hash, scoped_prefix, scopes="services:read")
        refused = {
            "stream key (X-Stream-Key)": {"X-Stream-Key": w.streams["private"]["live"]},
            "stream key (Authorization)": {"Authorization": "Stream-Key " + w.streams["private"]["live"]},
            "scoped API key": {"X-API-Key": scoped_key},
        }
        for label, headers in refused.items():
            for name, method, tmpl in _MANAGEMENT_CALLS:
                path = tmpl.format(id=sid, relay_id=1, user_id=w.users["member"], ban_id=1)
                req = make_mocked_request(method, path, headers=dict(headers),
                                          match_info={"id": str(sid), "relay_id": "1",
                                                      "user_id": str(w.users["member"]), "ban_id": "1"},
                                          transport=Transport())
                resp = await getattr(server, name)(req)
                assert resp.status == 403, (label, name, resp.status, resp.body)
                assert b"live_" not in resp.body and b"pub_" not in resp.body, (label, name)
        after = await w.db.get_user_stream(sid)
        assert after is not None and after["stream_key"] == before["stream_key"] \
            and after["public_key"] == before["public_key"] and after["name"] == before["name"]
        # the full-scope API key and the owner's session still manage it
        for headers in ({"X-API-Key": full_key}, {"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"}):
            req = make_mocked_request("GET", "/api/streams", headers=headers, transport=Transport())
            resp = await server.http_list_user_streams(req)
            assert resp.status == 200 and sid in {x["id"] for x in json.loads(resp.body)["streams"]}
        # no credential at all stays 401
        resp = await server.http_list_user_streams(make_mocked_request("GET", "/api/streams", transport=Transport()))
        assert resp.status == 401
    run(body)


def test_stream_detail_is_decided_by_the_role_based_read_rule():
    async def body(w):
        sid = w.streams["private"]["id"]
        def get(user):
            return make_mocked_request("GET", f"/api/streams/{sid}", match_info={"id": str(sid)},
                                       headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"},
                                       transport=Transport())
        # a member (role "user") whose token carries "*" is no administrator: the old inline scope
        # test let it read the private stream; the role-based rule does not
        star, _ = await auth.create_access_token(w.users["member"], ["*"])
        mine = make_mocked_request("GET", f"/api/streams/{sid}", match_info={"id": str(sid)},
                                   headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={star}"}, transport=Transport())
        assert (await server.http_get_user_stream(mine)).status == 404
        # a moderator is not an administrator either
        assert (await server.http_get_user_stream(get("mod"))).status == 404
        assert (await server.http_get_user_stream(get("member"))).status == 404
        assert (await server.http_get_user_stream(get("owner"))).status == 200
        assert (await server.http_get_user_stream(get("admin"))).status == 200
        # and the decision goes through _stream_read_allowed, not an inline scope test
        src = (ROOT / "server.py").read_text()
        start = src.index("async def http_get_user_stream(")
        chunk = src[start:src.index("\nasync def ", start + 10)]
        assert "_stream_read_allowed(" in chunk and 'has_scope("admin")' not in chunk
    run(body)


def test_public_listings_carry_only_allow_listed_columns():
    async def body(w):
        for label in ("public", "open"):
            await w.db.update_user_stream(w.streams[label]["id"], golive_message="secret hello",
                                          golive_audience="everyone", rtmp_enabled=1)
            await w.db.conn.execute("UPDATE user_streams SET golive_announced_at = 5 WHERE id = ?",
                                    (w.streams[label]["id"],))
        await w.db.conn.commit()
        allowed = set(w.db.PUBLIC_STREAM_COLUMNS) | {"owner_username", "owner_nickname", "chat_channel_name"}
        banned = {"stream_key", "stream_key_hash", "public_key_hash", "golive_message", "golive_audience",
                  "golive_announced_at", "rtmp_enabled", "updated_at", "ended_at"}
        for rows in (await w.db.get_public_streams(), await w.db.get_open_streams(),
                     await w.db.get_public_streams(live_only=True)):
            assert rows
            for row in rows:
                assert set(row) <= allowed, set(row) - allowed
                assert not (set(row) & banned)
                assert row["public_key"].startswith("pub_")
        # the HTTP listings: a member's view and the logged-out one
        resp = await server.http_get_public_streams(make_mocked_request(
            "GET", "/api/streams/public", headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['member']}"},
            transport=Transport()))
        blob = resp.body.decode()
        assert resp.status == 200 and "secret hello" not in blob and "golive" not in blob and "live_" not in blob
        resp = await server.http_get_open_streams(make_mocked_request("GET", "/api/streams/open", transport=Transport()))
        blob = resp.body.decode()
        assert resp.status == 200 and "open" in blob and "secret hello" not in blob and "golive" not in blob \
            and "live_" not in blob and "rtmp_enabled" not in blob
    run(body)


def test_stream_detail_carries_only_allow_listed_columns_for_non_owners():
    async def body(w):
        sid = w.streams["public"]["id"]
        await w.db.update_user_stream(sid, golive_message="owner secret note",
                                      golive_audience="everyone", rtmp_enabled=1)
        await w.db.conn.execute("UPDATE user_streams SET golive_announced_at = 5 WHERE id = ?", (sid,))
        await w.db.conn.commit()
        allowed = set(w.db.PUBLIC_STREAM_COLUMNS) | {"owner_username", "owner_nickname", "chat_channel_name",
                                                     "following"}
        banned = {"stream_key", "stream_key_hash", "public_key_hash", "golive_message", "golive_audience",
                  "golive_announced_at", "rtmp_enabled", "updated_at", "ended_at"}

        async def get(user, ident=None):
            ident = str(sid) if ident is None else ident
            return await server.http_get_user_stream(make_mocked_request(
                "GET", f"/api/streams/{ident}", match_info={"id": ident},
                headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"}, transport=Transport()))
        for user in ("member", "admin"):
            for ident in (None, w.streams["public"]["pub"]):
                resp = await get(user, ident)
                assert resp.status == 200
                row = json.loads(resp.body)["stream"]
                assert set(row) <= allowed, set(row) - allowed
                assert not (set(row) & banned)
                assert row["public_key"].startswith("pub_") and row["name"] == "public"
                assert "owner secret note" not in resp.body.decode()
        # the owner still sees their own settings
        row = json.loads((await get("owner")).body)["stream"]
        assert row["golive_message"] == "owner secret note" and row["rtmp_enabled"] == 1 and row["stream_key"]
    run(body)


def test_vod_routes_refuse_a_stream_key():
    import re
    async def body(w):
        owner_key = w.streams["private"]["live"]
        for h, method in (("http_get_vod_storage", "GET"), ("http_save_vod_storage", "POST"),
                          ("http_delete_vod_storage", "DELETE"), ("http_test_vod_storage", "POST"),
                          ("http_accept_vod_host_key", "POST"), ("http_list_vods", "GET"),
                          ("http_download_vod", "GET"), ("http_download_vod_archive", "POST"),
                          ("http_delete_vod", "DELETE")):
            for hdrs in ({"X-Stream-Key": owner_key}, {"Authorization": "Stream-Key " + owner_key}):
                req = make_mocked_request(method, "/api/vods/x", match_info={"filename": "x"}, headers=hdrs,
                                          transport=Transport())
                resp = await getattr(server, h)(req)
                assert resp.status == 403, (h, resp.status)
        # the owner's own session still gets past authentication (no storage set up: 404)
        req = make_mocked_request("GET", "/api/vods", headers={
            "Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie['owner']}"}, transport=Transport())
        assert (await server.http_list_vods(req)).status == 404
    run(body)
    # source guard: no /api/vods handler authenticates with the plain call
    src = (ROOT / "server.py").read_text()
    routes = re.findall(r'app\.router\.add_\w+\("(/api/vods[^"]*)", (\w+)', src)
    assert len(routes) >= 9, routes
    for _p, h in routes:
        start = src.index(f"async def {h}(")
        m = re.search(r"\n(?:async def|def) ", src[start + 10:])
        chunk = src[start:start + 10 + m.start()]
        assert "_stream_user_auth(" in chunk and "await authenticate_request(request)" not in chunk, h


_ELSEWHERE_CALLS = [
    ("http_list_users", "GET", "/api/users", None),
    ("http_create_user", "POST", "/api/users", {"username": "intruder", "password": "Intruder-pass-12345", "role": "user"}),
    ("http_update_user_role", "PUT", "/api/users/{uid}/role", {"role": "moderator"}),
    ("http_reset_user_password", "POST", "/api/users/{uid}/reset-password", {"new_password": "Taken-over-pass-123"}),
    ("http_delete_user", "DELETE", "/api/users/{uid}", None),
    ("http_create_api_key", "POST", "/api/api-keys", {"name": "persist", "scopes": ["services:read", "access:*"]}),
    ("http_list_api_keys", "GET", "/api/api-keys", None),
    ("http_get_current_user", "GET", "/api/me", None),
    ("http_get_notifications", "GET", "/api/notifications", None),
    ("http_get_dm_conversations", "GET", "/api/dm/conversations", None),
]


def test_a_stream_key_signs_in_nowhere_not_even_as_an_admin():
    async def body(w):
        member = w.users["member"]
        for role in ("admin", "superadmin"):
            await w.db.set_user_role(w.users["owner"], role)
            before = await w.db.get_user_by_id(member)
            owner_keys_before = len(await w.db.get_user_api_keys(w.users["owner"]))
            for hdrs in ({"X-Stream-Key": w.streams["private"]["live"]},
                         {"Authorization": "Stream-Key " + w.streams["private"]["live"]}):
                # no handler gets a credential out of the key, and its role is only that of a user
                assert await server.authenticate_request(make_mocked_request(
                    "GET", "/api/me", headers=hdrs, transport=Transport())) is None
                tok = server.TokenPayload({"jti": "streamkey-1", "sub": str(w.users["owner"]), "scopes": ["*"]})
                assert await server.get_user_role_from_token(tok) == "user"
                for name, method, tmpl, payload in _ELSEWHERE_CALLS:
                    path = tmpl.format(uid=member)
                    req = make_mocked_request(method, path, headers=dict(hdrs), match_info={"id": str(member)},
                                              transport=Transport())
                    if payload is not None:
                        async def _json(p=payload):
                            return p
                        req.json = _json
                    resp = await getattr(server, name)(req)
                    assert resp.status in (401, 403), (role, name, resp.status, resp.body)
            after = await w.db.get_user_by_id(member)
            assert after["password_hash"] == before["password_hash"] and after["role"] == before["role"]
            assert await w.db.get_user_by_username("intruder") is None
            assert len(await w.db.get_user_api_keys(w.users["owner"])) == owner_keys_before
        await w.db.set_user_role(w.users["owner"], "user")
    run(body)


def test_authenticate_request_has_no_stream_key_branch():
    import inspect
    src = (ROOT / "server.py").read_text()
    assert "allow_stream_key" not in src
    # nothing outside its own definition calls authenticate_stream_key, so no route can sign a key in
    assert src.count("authenticate_stream_key(") == 1
    assert list(inspect.signature(server.authenticate_request).parameters) == ["request"]


# stream handlers that only publish (the MediaMTX hooks and WHIP): the key in the body or URL
# is the publish credential. Anything else under these prefixes must refuse stream keys.
_PUBLISH_SIDE = {"http_stream_auth", "http_stream_event", "http_stream_webrtc_whip",
                 "http_get_open_streams"}     # the last one needs no credential at all (open links only)
_REFUSES_STREAM_KEYS = ("_stream_user_auth(", "_follow_context(", "allow_stream_key=False",
                        "_validate_stream_access(", "_authorize_webrtc_session(")


def test_every_stream_handler_refuses_stream_keys_or_is_publish_side():
    import re
    src = (ROOT / "server.py").read_text()
    routes = re.findall(r'app\.router\.add_\w+\("(/api/(?:streams|stream|me/follows)[^"]*)", (\w+)', src)
    assert len(routes) >= 30, len(routes)
    handlers = {h for _p, h in routes}
    assert _PUBLISH_SIDE <= handlers
    for h in sorted(handlers - _PUBLISH_SIDE):
        start = src.index(f"async def {h}(")
        m = re.search(r"\n(?:async def|def) ", src[start + 10:])
        chunk = src[start:start + 10 + m.start()]
        assert any(mark in chunk for mark in _REFUSES_STREAM_KEYS), f"{h} accepts a stream key"
        # the plain call (stream keys allowed) is never the whole check
        assert "await authenticate_request(request)" not in chunk, h
    for h in _PUBLISH_SIDE:        # the allow-listed handlers never authenticates by stream key header either
        start = src.index(f"async def {h}(")
        m = re.search(r"\n(?:async def|def) ", src[start + 10:])
        assert "authenticate_request(" not in src[start:start + 10 + m.start()], h


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
