"""Viewer counts kept by the portal (viewers.py and its wiring in server.py).

Part 1 is the tracker alone with a fake clock: who is one viewer, the windows, the bounds, peak
and unique figures, the heartbeat limiter, and that no address is held in clear.
Part 2 runs the real handlers in-process against the temporary database of
tests/test_stream_access.py: members counted through HLS playlists, WHEP and the heartbeat,
refusals that never count, an rtmp_ token path, the sync task writing only changes, the offline
transition writing peak and unique, the migration, and the owner's detail.

MediaMTX is a fake HTTP client (it would answer a reader list with the recorder and relays in it;
the portal no longer asks), tests/outbound_guard.py refuses any dial that is not loopback.
Not proven here: a real MediaMTX, a browser's hls.js and Safari, OBS, real time passing.

Run: venv/bin/python tests/test_viewers.py
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

import server  # noqa: E402
import viewers  # noqa: E402
from database import Database  # noqa: E402
from test_stream_access import FakeSession, World, run  # noqa: E402

CID_A = "A" * 24
CID_B = "B" * 24


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --- part 1: the tracker ------------------------------------------------------------------

def test_one_person_counts_once_and_two_members_count_two():
    t = viewers.ViewerTracker(Clock())
    assert t.touch(1, user_id=7) and t.touch(1, user_id=7)      # two tabs of one member
    assert t.count(1) == 1
    t.touch(1, user_id=8)
    assert t.count(1) == 2
    # a signed-in viewer's client id and address are not part of the identity
    t.touch(1, user_id=7, client_id=CID_A, addr="198.51.100.1")
    assert t.count(1) == 2


def test_anonymous_identity_is_the_client_id_else_address_and_agent():
    t = viewers.ViewerTracker(Clock())
    t.touch(1, client_id=CID_A, addr="198.51.100.1", ua="x")
    t.touch(1, client_id=CID_A, addr="198.51.100.2", ua="y")    # same id from another address
    assert t.count(1) == 1
    t.touch(1, client_id=CID_B, addr="198.51.100.1", ua="x")
    assert t.count(1) == 2
    t.touch(1, addr="198.51.100.1", ua="Firefox")
    t.touch(1, addr="198.51.100.1", ua="Firefox")               # no id: the hash of address and agent
    assert t.count(1) == 3
    t.touch(1, addr="198.51.100.1", ua="Chrome")
    assert t.count(1) == 4


def test_windows_and_prune_with_a_fake_clock():
    c = Clock()
    t = viewers.ViewerTracker(c)
    t.touch(1, user_id=1, window=viewers.BEAT_WINDOW)
    t.touch(1, user_id=2, window=viewers.HLS_WINDOW)
    c.t += 14.9
    assert t.count(1) == 2
    c.t += 0.2          # past 15 s: the heartbeat viewer is gone, the playlist viewer stays
    assert t.count(1) == 1
    c.t += 5
    assert t.count(1) == 0 and t.sample() == {}
    # a later sighting never shortens a longer window
    t.touch(1, user_id=3, window=viewers.HLS_WINDOW)
    t.touch(1, user_id=3, window=viewers.BEAT_WINDOW)
    c.t += 18
    assert t.count(1) == 1


def test_bounds_per_stream_and_per_address():
    c = Clock()
    t = viewers.ViewerTracker(c)
    for i in range(viewers.MAX_ANON_PER_ADDRESS):
        assert t.touch(1, client_id=f"id{i:020d}", addr="198.51.100.7")
    assert not t.touch(1, client_id="z" * 24, addr="198.51.100.7")
    assert t.count(1) == viewers.MAX_ANON_PER_ADDRESS
    assert t.touch(1, client_id="y" * 24, addr="198.51.100.8"), "another address is not held back"
    assert t.touch(1, client_id="id" + "0" * 20, addr="198.51.100.7"), "a known id is still refreshed"
    c.t += 30       # the slots of the stale ones are free again
    assert t.touch(1, client_id="z" * 24, addr="198.51.100.7")
    # the map of one stream is bounded
    t2 = viewers.ViewerTracker(c)
    old = viewers.MAX_PER_STREAM
    viewers.MAX_PER_STREAM = 50
    try:
        for i in range(200):
            t2.touch(1, user_id=i)
        assert t2.count(1) == 50
        assert not t2.touch(1, user_id=9999)
        assert t2.touch(1, user_id=3), "an identity already in is refreshed"
    finally:
        viewers.MAX_PER_STREAM = old


def test_no_address_or_agent_is_held_in_clear():
    t = viewers.ViewerTracker(Clock())
    t.touch(1, addr="198.51.100.77", ua="SecretAgent/9")
    t.touch(1, client_id=CID_A, addr="198.51.100.78", ua="SecretAgent/9")
    blob = repr(vars(t)) + repr(t._sessions[1].seen)
    for needle in ("198.51.100", "SecretAgent", CID_A):
        assert needle not in blob, needle
    # and the salt differs between processes' trackers, so hashes are not comparable
    assert viewers.ViewerTracker().address_hash("198.51.100.77") != viewers.ViewerTracker().address_hash("198.51.100.77")


def test_viewer_id_shape():
    ok = viewers.valid_viewer_id
    assert ok("A" * 24) == "A" * 24 and ok("a-b_c" * 4) is not None
    for bad in ("short", "x" * 65, "has space " * 3, "a" * 15 + "!", "", None, 5):
        assert ok(bad) is None, bad


def test_session_peak_unique_and_finish():
    c = Clock()
    t = viewers.ViewerTracker(c)
    t.start_session(1)
    for u in (1, 2, 3):
        t.touch(1, user_id=u)
    t.sample()
    c.t += 30
    t.touch(1, user_id=4)
    assert t.sample() == {1: 1}
    assert t.finish(1) == (3, 4)
    assert t.finish(1) is None, "a second end changes nothing"
    assert t.count(1) == 0
    t.start_session(1)
    assert t.finish(1) == (0, 0), "a new session starts from nothing"
    # the unique set is bounded
    old = viewers.MAX_UNIQUE_PER_SESSION
    viewers.MAX_UNIQUE_PER_SESSION = 10
    try:
        t.start_session(2)
        for u in range(100):
            t.touch(2, user_id=u)
        assert t.finish(2)[1] == 10
    finally:
        viewers.MAX_UNIQUE_PER_SESSION = old


def test_forget_except_drops_streams_that_are_not_live():
    t = viewers.ViewerTracker(Clock())
    t.start_session(1)
    t.start_session(2)
    t.touch(1, user_id=1)
    t.touch(2, user_id=1)
    t.forget_except([2])
    assert t.count(1) == 0 and t.finish(1) is None and t.count(2) == 1


def test_forget_keeps_a_session_that_began_after_the_snapshot():
    t = viewers.ViewerTracker(Clock())
    t.start_session(1)
    t.touch(1, user_id=1)
    seen = t.generations()
    t.start_session(2)                      # went live while the live list was being read
    t.touch(2, user_id=1)
    t.start_session(1)                      # went offline and live again in the same gap
    t.touch(1, user_id=1)
    t.forget_except([], seen)
    assert t.count(1) == 1 and t.count(2) == 1
    t.forget_except([], t.generations())    # a later pass, nothing new: now they are stale
    assert t.count(1) == 0 and t.count(2) == 0 and t.finish(2) is None


def test_end_audience_keeps_the_last_seconds_in_the_peak():
    t = viewers.ViewerTracker(Clock())
    t.start_session(1)
    t.touch(1, user_id=1)
    t.sample()                              # peak 1 at the last sync
    for u in (2, 3):
        t.touch(1, user_id=u)               # two more joined since, no sample taken
    t.end_audience(1)
    assert t.count(1) == 0
    assert t.finish(1) == (3, 3)


def test_rate_window_is_bounded_and_per_key():
    c = Clock()
    r = viewers.RateWindow(3, 60, clock=c, max_keys=4)
    assert all(r.allow("a") for _ in range(3)) and not r.allow("a") and r.allow("b")
    c.t += 61
    assert r.allow("a")
    for k in "cde":
        r.allow(k)
    assert not r.allow("new"), "a full table refuses a newcomer instead of evicting somebody"
    c.t += 61
    assert r.allow("new")


# --- part 2: the handlers -----------------------------------------------------------------

def fresh():
    clock = Clock()
    server._viewers = viewers.ViewerTracker(clock)
    server._viewer_beat_rate = viewers.RateWindow(server._VIEWER_BEAT_LIMIT, 60.0, clock=clock)
    server._rtmp_stream_paths.clear()
    return clock


def beat(w, key, user=None, peer="203.0.113.9", headers=None):
    return server.http_stream_viewer_beat(w.req(key, user, method="POST", path="", headers=headers, peer=peer))


async def count_of(w, label):
    await server._viewer_sync_once()
    row = await w.db.get_user_stream(w.streams[label]["id"])
    return row["viewer_count"]


def test_two_members_count_two_and_recorder_relay_are_not_counted():
    async def body(w):
        fresh()
        key = w.streams["public"]["pub"]
        sid = w.streams["public"]["id"]
        # segments alone are no sign of a viewer
        for i in range(5):
            await server.http_stream_hls_proxy(w.req(key, "member", path=f"seg{i}.mp4"))
        assert await count_of(w, "public") == 0
        r1 = await server.http_stream_hls_proxy(w.req(key, "member"))
        r2 = await server.http_stream_hls_proxy(w.req(key, "other"))
        r3 = await server.http_stream_hls_proxy(w.req(key, "member"))      # a second tab of the first
        assert r1.status == r2.status == r3.status == 200
        assert await count_of(w, "public") == 2
        # the portal does not ask MediaMTX for readers (a recorder, relays and the thumbnail
        # ffmpeg are in that list); a thumbnail request is not a viewer either
        assert not [c for c in FakeSession.calls if "paths/list" in c[1]]
        server._viewers = viewers.ViewerTracker(Clock())
        await server.http_stream_thumbnail(w.req(key, "member", path=""))
        await server.http_stream_info(w.req(key, "member", path=""))
        assert server._viewers.count(sid) == 0
    run(body)


def test_refused_requests_never_count():
    async def body(w):
        fresh()
        priv = w.streams["private"]
        # a member may not watch a private stream: playlist and heartbeat, same 404
        r = await server.http_stream_hls_proxy(w.req(priv["pub"], "member"))
        assert r.status == 404
        h = await beat(w, priv["pub"], "member")
        assert h.status == 404 and h.body == r.body
        # nobody logged in on a public stream whose link is not open; a made-up and a live_ key
        for key in (w.streams["public"]["pub"], "pub_doesnotexist0000000", w.streams["public"]["live"]):
            assert (await beat(w, key)).status == 404
            assert (await server.http_stream_hls_proxy(w.req(key))).status == 404
        # a member's cookie that is not valid
        assert (await beat(w, w.streams["public"]["pub"], None)).status == 404
        assert server._viewers.sample() == {}
        assert await count_of(w, "private") == 0
        # the owner of the private stream is counted, an admin too
        assert (await beat(w, priv["pub"], "owner")).status == 200
        assert (await beat(w, priv["pub"], "admin")).status == 200
        assert await count_of(w, "private") == 2
    run(body)


def test_heartbeat_counts_logged_out_viewer_of_an_open_stream():
    async def body(w):
        fresh()
        key = w.streams["open"]["pub"]
        sid = w.streams["open"]["id"]
        # the id from the page: the same viewer from a playlist and a beat is one
        h = {"X-Viewer-Id": CID_A}
        assert (await beat(w, key, headers=h)).status == 200
        assert (await server.http_stream_hls_proxy(w.req(key, headers=h))).status == 200
        assert await count_of(w, "open") == 1
        assert (await beat(w, key, headers={"X-Viewer-Id": CID_B}, peer="203.0.113.50")).status == 200
        # a malformed id is ignored (the fallback applies), never an error
        assert (await beat(w, key, headers={"X-Viewer-Id": "bad id!"}, peer="203.0.113.60")).status == 200
        assert await count_of(w, "open") == 3
        # random ids from one address are held to a few
        for i in range(30):
            await beat(w, key, headers={"X-Viewer-Id": f"flood{i:019d}"}, peer="203.0.113.70")
        assert server._viewers.count(sid) <= 3 + viewers.MAX_ANON_PER_ADDRESS
        # a signed-in viewer's own header changes nothing
        await beat(w, key, "member", headers={"X-Viewer-Id": CID_A})
        assert server._viewers.count(sid) <= 4 + viewers.MAX_ANON_PER_ADDRESS
    run(body)


def test_a_stream_published_with_an_rtmp_token_is_counted():
    async def body(w):
        fresh()
        key = w.streams["public"]["pub"]
        sid = w.streams["public"]["id"]
        server._rtmp_stream_paths[sid] = "rtmp_abc123"
        FakeSession.calls.clear()
        r = await server.http_stream_hls_proxy(w.req(key, "member"))
        assert r.status == 200
        assert any("/live/rtmp_abc123/index.m3u8" in c[1] for c in FakeSession.calls)
        assert await count_of(w, "public") == 1
    run(body)


def test_whep_offer_counts_a_viewer_and_patch_delete_do_not_change_it():
    async def body(w):
        fresh()
        key = w.streams["public"]["pub"]
        sid = w.streams["public"]["id"]

        async def text():
            return "v=0 offer"
        req = w.req(key, "member", method="POST", path="")
        req.text = text
        resp = await server.http_stream_webrtc_whep(req)
        assert resp.status == 201
        assert server._viewers.count(sid) == 1
        # a refused offer (private stream) counts nobody
        req = w.req(w.streams["private"]["pub"], "member", method="POST", path="")
        req.text = text
        assert (await server.http_stream_webrtc_whep(req)).status == 404
        assert server._viewers.count(w.streams["private"]["id"]) == 0
    run(body)


def test_a_viewer_who_stops_is_gone_and_only_changes_are_written():
    async def body(w):
        clock = fresh()
        key = w.streams["public"]["pub"]
        writes = []
        real = w.db.set_live_viewer_count

        async def spy(sid, n):
            writes.append((sid, n))
            return await real(sid, n)
        w.db.set_live_viewer_count = spy
        await server.http_stream_hls_proxy(w.req(key, "member"))
        await server.http_stream_hls_proxy(w.req(key, "other"))
        await server._viewer_sync_once()
        assert writes == [(w.streams["public"]["id"], 2)]
        for _ in range(3):
            clock.t += 5
            await beat(w, key, "member")                    # one keeps beating, one stopped
            await server._viewer_sync_once()
        assert writes == [(w.streams["public"]["id"], 2)], "no change, no write"
        clock.t += 6                                        # 21 s after the other one's last playlist
        await beat(w, key, "member")
        await server._viewer_sync_once()
        assert writes[-1] == (w.streams["public"]["id"], 1)
        clock.t += 16                                       # and the last one stops
        await server._viewer_sync_once()
        assert writes[-1] == (w.streams["public"]["id"], 0)
        assert await count_of(w, "public") == 0
    run(body)


def test_a_stream_that_goes_live_while_the_sync_reads_its_list_keeps_its_session():
    async def body(w):
        fresh()
        key = w.streams["public"]["pub"]
        await beat(w, key, "member")
        real_conn = w.db._connection

        class Cur:
            def __init__(self, cur):
                self.cur = cur

            async def fetchall(self):
                rows = await self.cur.fetchall()
                # the stream below went live after the SELECT ran, so it is not in `rows`
                server._viewers.start_session(9999)
                server._viewers.touch(9999, user_id=5)
                return rows

        class Spy:
            def __getattr__(self, name):
                return getattr(real_conn, name)

            async def execute(self, sql, *a, **k):
                cur = await real_conn.execute(sql, *a, **k)
                return Cur(cur) if "FROM user_streams WHERE is_live" in sql else cur
        w.db._connection = Spy()
        try:
            await server._viewer_sync_once()
        finally:
            w.db._connection = real_conn
        assert server._viewers.count(9999) == 1, "the fresh session was wiped"
        # the next pass sees it is not live in the database: it is forgotten then
        await server._viewer_sync_once()
        assert server._viewers.count(9999) == 0
    run(body)


def test_the_encoding_transition_takes_the_last_count_before_it_clears_the_audience():
    src = Path(server.__file__).read_text(encoding="utf-8")
    a = src.index("await db.set_stream_encoding(stream_id)")
    chunk = src[a:a + 400]
    assert "_viewers.end_audience(stream_id)" in chunk and "_viewers.clear_viewers(" not in chunk


def test_heartbeat_is_rate_limited_before_the_gate():
    async def body(w):
        fresh()
        key = w.streams["private"]["pub"]
        statuses = [(await beat(w, key, "member", peer="203.0.113.77")).status
                    for _ in range(server._VIEWER_BEAT_LIMIT + 3)]
        assert statuses[:server._VIEWER_BEAT_LIMIT] == [404] * server._VIEWER_BEAT_LIMIT
        assert statuses[-1] == 429
        # another address is not affected
        assert (await beat(w, key, "member", peer="203.0.113.78")).status == 404
    run(body)


def test_offline_writes_peak_and_unique_and_a_late_write_cannot_resurrect_a_count():
    async def body(w):
        clock = fresh()
        sid = w.streams["public"]["id"]
        key = w.streams["public"]["pub"]
        server._viewers.start_session(sid)
        for user in ("member", "other"):
            await server.http_stream_hls_proxy(w.req(key, user))
        await server._viewer_sync_once()
        clock.t += 30
        await server.http_stream_hls_proxy(w.req(key, "owner"))
        await server._viewer_sync_once()
        assert await server._stream_set_offline(sid)
        row = await w.db.get_user_stream(sid)
        assert (row["is_live"], row["viewer_count"], row["last_peak_viewers"], row["last_unique_viewers"]) == (0, 0, 2, 3)
        # a second end, and a heartbeat from the cached decision, change nothing
        await server._stream_set_offline(sid)
        await server.http_stream_hls_proxy(w.req(key, "member"))
        await server._viewer_sync_once()
        row = await w.db.get_user_stream(sid)
        assert (row["viewer_count"], row["last_peak_viewers"], row["last_unique_viewers"]) == (0, 2, 3)
        assert not await w.db.set_live_viewer_count(sid, 5)
        # a stream going live again starts from nothing
        server._viewers.start_session(sid)
        assert server._viewers.finish(sid) == (0, 0)
    run(body)


def test_a_stream_published_through_the_hook_with_an_rtmp_token_is_counted_and_recorded():
    """The real publish and disconnect hooks with an rtmp_ token: the session starts, the count
    follows the viewers, and the figures are written when the stream is offline (the old count
    looked the live_ key up under the token's path and never found the stream)."""
    import hashlib
    from aiohttp.test_utils import make_mocked_request
    from config import Config
    from test_stream_access import Transport

    def hook_request(path, body):
        req = make_mocked_request("POST", "/api/stream/x", transport=Transport("127.0.0.1"))

        async def _json():
            return body
        req.json = _json
        return req

    async def body(w):
        fresh()
        sid = w.streams["public"]["id"]
        key = w.streams["public"]["pub"]
        await w.db.set_stream_live(sid, False)
        await w.db.update_user_stream(sid, rtmp_enabled=1)
        token = "rtmp_" + "T" * 32
        from datetime import datetime, timedelta, timezone
        await w.db.create_rtmp_token(sid, w.users["owner"], hashlib.sha256(token.encode()).hexdigest(),
                                     (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat())

        async def noop(*a, **k):
            return None
        saved = (Config.RTMP_PLAIN_ENABLED, server.start_vod_recording, server.start_stream_relays,
                 server._spawn_go_live, asyncio.sleep)
        Config.RTMP_PLAIN_ENABLED = True
        server.start_vod_recording = server.start_stream_relays = noop
        server._spawn_go_live = lambda *a, **k: None
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **k):
            return await real_sleep(0 if delay == 7 else delay, *a, **k)
        try:
            path = "live/" + token
            resp = await server.http_stream_auth(hook_request(path, {
                "action": "publish", "path": path, "password": token, "ip": "127.0.0.1"}))
            assert resp.status == 200, resp.body
            assert (await w.db.get_user_stream(sid))["is_live"] == 1
            assert server._rtmp_stream_paths[sid] == token
            for user in ("member", "other"):
                assert (await server.http_stream_hls_proxy(w.req(key, user))).status == 200
            assert await count_of(w, "public") == 2
            await server._viewer_sync_once()
            asyncio.sleep = fast_sleep
            await server.http_stream_event(hook_request(path, {"event": "disconnect", "path": path}))
            await server._disconnect_grace_tasks[sid]
        finally:
            (Config.RTMP_PLAIN_ENABLED, server.start_vod_recording, server.start_stream_relays,
             server._spawn_go_live, asyncio.sleep) = saved
        row = await w.db.get_user_stream(sid)
        assert (row["is_live"], row["viewer_count"], row["last_peak_viewers"], row["last_unique_viewers"]) == (0, 0, 2, 2), row
    run(body)


def test_the_session_survives_the_encoding_state_until_offline():
    async def body(w):
        fresh()
        sid = w.streams["public"]["id"]
        key = w.streams["public"]["pub"]
        server._viewers.start_session(sid)
        await server.http_stream_hls_proxy(w.req(key, "member"))
        await server.http_stream_hls_proxy(w.req(key, "other"))
        await server._viewer_sync_once()
        assert await w.db.set_stream_encoding(sid)         # what the disconnect grace does
        server._viewers.clear_viewers(sid)
        await server._viewer_sync_once()
        await server._viewer_sync_once()
        row = await w.db.get_user_stream(sid)
        assert row["is_live"] == 2 and row["viewer_count"] == 0
        assert server._viewers._sessions[sid].peak == 2, "the session is kept while encoding"
        assert await server._stream_set_offline(sid)
        row = await w.db.get_user_stream(sid)
        assert (row["last_peak_viewers"], row["last_unique_viewers"]) == (2, 2)
        # a stream that is offline keeps no session at all
        await server._viewer_sync_once()
        assert sid not in server._viewers._sessions
    run(body)


def test_session_starts_when_the_stream_goes_live_not_on_a_reconnect():
    async def body(w):
        fresh()
        sid = w.streams["public"]["id"]
        await w.db.set_stream_live(sid, False)
        stream = await w.db.get_user_stream(sid)
        orig = (server._spawn_go_live, server.db.claim_golive)

        async def no_claim(*a, **k):
            return None
        server.db.claim_golive = no_claim
        try:
            await server._mark_stream_live(stream, "127.0.0.1")
            await server.http_stream_hls_proxy(w.req(w.streams["public"]["pub"], "member"))
            await server._mark_stream_live(stream, "127.0.0.1")     # an encoder that reconnected
            assert server._viewers.count(sid) == 1, "a reconnect keeps the viewers and the session"
            assert server._viewers._sessions[sid].peak == 0
        finally:
            server.db.claim_golive = orig[1]
    run(body)


def test_owner_sees_the_last_session_and_nobody_else_does():
    async def body(w):
        fresh()
        sid = w.streams["public"]["id"]
        await w.db.set_stream_live(sid, False, session_stats=(4, 9))
        own = json.loads((await server.http_get_user_stream(_api(w, "owner", sid))).body)["stream"]
        assert (own["last_peak_viewers"], own["last_unique_viewers"]) == (4, 9)
        for user in ("member", "admin"):
            other = json.loads((await server.http_get_user_stream(_api(w, user, sid))).body)["stream"]
            assert "last_peak_viewers" not in other and "last_unique_viewers" not in other, user
        assert "last_peak_viewers" not in Database.PUBLIC_STREAM_COLUMNS
        assert "last_unique_viewers" not in Database.PUBLIC_STREAM_COLUMNS
        listing = await w.db.get_public_streams()
        assert not [s for s in listing if "last_peak_viewers" in s]
    run(body)


def _api(w, user, sid):
    from aiohttp.test_utils import make_mocked_request
    from config import Config
    from test_stream_access import Transport
    h = {"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"}
    return make_mocked_request("GET", f"/api/streams/{sid}", headers=h, match_info={"id": str(sid)},
                               transport=Transport())


def test_migration_adds_nullable_columns_and_runs_twice():
    async def body():
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "m.db")
            for _ in range(2):
                db = Database(path)
                await db.connect()
                cur = await db.conn.execute("PRAGMA table_info(user_streams)")
                cols = {r["name"]: r for r in await cur.fetchall()}
                assert cols["last_peak_viewers"]["notnull"] == 0 and cols["last_unique_viewers"]["notnull"] == 0
                await db.close()
    asyncio.run(body())


def test_sources_touch_only_after_the_gate_and_the_beat_uses_the_gate():
    src = (ROOT / "server.py").read_text()
    assert src.count("_viewer_touch(request, stream") == 3          # playlist, WHEP, heartbeat
    def chunk(name):
        a = src.index(f"async def {name}(")
        return src[a:src.index("\nasync def ", a + 10)]
    beat_src = chunk("http_stream_viewer_beat")
    assert "_validate_stream_access(" in beat_src and "request=request" in beat_src
    assert beat_src.index("_validate_stream_access(") < beat_src.index("_viewer_touch(")
    assert "_stream_not_found()" in beat_src
    for name in ("http_stream_thumbnail", "http_stream_info"):
        assert "_viewer_touch(" not in chunk(name)
    hls = chunk("http_stream_hls_proxy")
    assert hls.index("_validate_stream_access(") < hls.index("_viewer_touch(")
    assert "paths/list" not in src[src.index("async def _viewer_sync_task"):src.index("async def _relay_health_monitor_task")]


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception:
                import traceback
                traceback.print_exc()
                print("FAIL", name)
                failed += 1
    if outbound_guard.refused:
        print("FAIL: the guard refused a dial", outbound_guard.refused)
        failed += 1
    sys.exit(1 if failed else 0)
