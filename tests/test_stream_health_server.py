"""Stream health in server.py: the ingest tick, GET /api/streams/{id}/health and the administrator's live
operations (list, stop relays, End now), in-process against the temporary database of
tests/test_stream_access.py.

MediaMTX is a fake: the paths lists are the captures of tests/fixtures/mediamtx-1.21.3 with the path names
rewritten to the test streams' keys, and the control API is a small aiohttp app on a loopback port that
answers like the captured v1.21.3 exchanges. The portal's own tick fetches no paths list: the lists are
handed to _viewer_sync_once(paths=...). In production the lists come from MediaMTXService.health_check (the
30 s health check), which test_health_check_feeds_the_ingest_numbers drives against a loopback TLS fake of
the control API with a real MediaMTXService. tests/outbound_guard.py refuses any dial that is not loopback.

The 1.9.3 captures and the paging are exercised in tests/test_live_ops_fixes.py. Not proven here: a real encoder, a browser.

Run: venv/bin/python tests/test_stream_health_server.py
"""
import asyncio
import json
import os
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402

import server  # noqa: E402
import stream_health  # noqa: E402
from config import Config  # noqa: E402
from test_stream_access import Transport, World, run  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "mediamtx-1.21.3"
RELAY_URL = "rtmp://live.relay-host.example/app"
RELAY_KEY = "SECRETRELAYKEY123"


def fx(name):
    return json.loads((FIX / name).read_text())


def paths_for(name, **names):
    """A fixture's items renamed: {old path name: new key} -> live/<new key>."""
    data = fx(name)
    for it in data["items"]:
        old = it["name"].split("/", 1)[1]
        if old in names:
            it["name"] = "live/" + names[old]
    return data


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def fresh():
    server._ingest_stats.clear()
    server._ingest_invalidate()
    server._stream_state_lock = asyncio.Lock()
    server._stream_health_rate = server._viewers_mod.RateWindow(500, 60.0)
    server._live_ops_rate = server._viewers_mod.RateWindow(500, 60.0)
    server._live_ops_list_rate = server._viewers_mod.RateWindow(500, 60.0)
    server._rtmp_stream_paths.clear()
    server._relay_stop_held.clear()
    server._stream_sessions.clear()
    server._end_claims.clear()
    server._relay_stop_claims.clear()
    server._recorder_errors.clear()
    server.active_relays.clear()
    server.active_recordings.clear()
    server._vod_guard_state.clear()


def req(w, user, sid, method="GET", path="health", body=None, route="streams"):
    h = {"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"} if user else {}
    url = f"/api/{route}/{sid}/{path}"
    r = make_mocked_request(method, url, headers=h, match_info={"id": str(sid)}, transport=Transport())
    if body is not None:
        async def _json():
            return body
        r.json = _json
    return r


async def health(w, user, sid):
    resp = await server.http_stream_health(req(w, user, sid))
    return resp.status, (json.loads(resp.body) if resp.body else None), resp


async def tick(clock, payload, dt=5.0):
    clock.t += dt
    await server._viewer_sync_once(paths=payload)


def with_clock(fn):
    def runner():
        async def body(w):
            fresh()
            clock = Clock()
            saved = server.monotonic
            server.monotonic = clock
            try:
                await fn(w, clock)
            finally:
                server.monotonic = saved
        run(body)
    runner.__name__ = fn.__name__
    return runner


@with_clock
async def test_bitrate_within_ten_percent_and_only_owner_and_admin_see_it(w, clock):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    a = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)
    b = paths_for("paths_list_two_samples_5s_apart_b.json", livekey_a=key)
    await tick(clock, a)
    await tick(clock, b)
    for user in ("owner", "admin"):
        st, d, resp = await health(w, user, sid)
        assert st == 200 and resp.headers["Cache-Control"] == "no-store", (user, st)
        ing = d["ingest"]
        assert ing["available"] and abs(ing["bitrate_bps"] - 864_000) / 864_000 < 0.10, ing
        assert ing["source"] == "RTMP" and ing["codecs"] == ["H264", "MPEG-4 Audio"], ing
        assert d["live"] and d["load_average"] and d["warnings"] == []
    # everybody else: the same 404 as an unknown stream, a moderator included
    unknown = await health(w, "owner", 99999)
    assert unknown[0] == 404
    for user in ("mod", "member", "other"):
        st, d, resp = await health(w, user, sid)
        assert st == 404 and resp.body == unknown[2].body, user
    # no credential: 401; a stream key as credential never signs in
    anon = await server.http_stream_health(req(w, None, sid))
    assert anon.status in (401, 403)
    hk = make_mocked_request("GET", f"/api/streams/{sid}/health", headers={"Authorization": f"Bearer {key}"},
                             match_info={"id": str(sid)}, transport=Transport())
    assert (await server.http_stream_health(hk)).status in (401, 403)


@with_clock
async def test_rtmp_token_path_and_rtsp_source(w, clock):
    sid = w.streams["public"]["id"]
    server._rtmp_stream_paths[sid] = "rtmp_tokx"
    payload = fx("paths_list_rtsp_rtmp_prefixed.json")
    await tick(clock, payload)
    await tick(clock, fx("paths_list_empty.json"))                    # the path is gone: a reading with no path
    entry = server._ingest_stats[sid]
    assert entry["source_type"] == "rtspSession" and entry["codecs"] == ["H264"] and entry["ready"] is False
    assert not entry["samples"]


@with_clock
async def test_key_lookup_is_cached_and_invalidated_and_the_map_is_bounded(w, clock):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    calls = []
    real = w.db.get_live_stream_keys

    async def counting():
        calls.append(1)
        return await real()
    w.db.get_live_stream_keys = counting
    payload = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)
    for _ in range(5):
        await tick(clock, payload)
    assert len(calls) == 1, calls
    live_ids = {s["id"] for s in w.streams.values()}
    assert set(server._ingest_stats) <= live_ids
    # a stream going offline is forgotten at once and invalidates the cache
    other = w.streams["public"]["id"]
    await server._stream_set_offline(other)
    assert other not in server._ingest_stats
    await tick(clock, payload)
    assert len(calls) == 2
    # a stream that is not live any more is dropped by the tick even if nothing called the helper
    await w.db.set_stream_live(sid, False)
    await tick(clock, payload)
    assert sid not in server._ingest_stats
    # a new session: the key map is read again (go-live invalidates)
    n = len(calls)
    server._ingest_invalidate()
    await w.db.set_stream_live(sid, True)
    await tick(clock, payload)
    assert len(calls) == n + 1 and sid in server._ingest_stats
    assert "paths/list" not in _tick_source()


def _tick_source():
    src = Path(server.__file__).read_text()
    a = src.index("async def _viewer_sync_task")
    return src[a:src.index("async def _relay_health_monitor_task")]


@with_clock
async def test_stopped_data_warns_after_the_threshold_and_the_entry_goes_with_the_stream(w, clock):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    live = paths_for("paths_list_stalled_a.json", livekey_a=key)
    stall = paths_for("paths_list_stalled_b_publisher_stopped_by_SIGSTOP.json", livekey_a=key)
    saved = server.INGEST_NO_DATA_SECONDS
    server.INGEST_NO_DATA_SECONDS = 12          # the shortened threshold of the test
    try:
        await tick(clock, live)
        st, d, _ = await health(w, "owner", sid)
        assert d["warnings"] == []
        for _ in range(2):
            await tick(clock, stall)            # the counter does not move (captured SIGSTOP publisher)
        st, d, _ = await health(w, "owner", sid)
        assert d["warnings"] == [], d["warnings"]           # 10 s flat
        await tick(clock, stall)
        st, d, _ = await health(w, "owner", sid)
        assert [x["code"] for x in d["warnings"]] == ["no_data"], d
        assert d["ingest"]["bitrate_bps"] == 0 and d["thresholds"]["no_data_seconds"] == 12
    finally:
        server.INGEST_NO_DATA_SECONDS = saved
    await server._stream_set_offline(sid)
    assert sid not in server._ingest_stats
    st, d, _ = await health(w, "owner", sid)
    assert st == 200 and d["live"] is False and d["ingest"]["available"] is False and d["warnings"] == []


@with_clock
async def test_a_live_stream_without_a_feed_says_so(w, clock):
    sid = w.streams["private"]["id"]
    await server._viewer_sync_once()            # the real tick passes no list
    st, d, _ = await health(w, "owner", sid)
    assert st == 200 and d["ingest"]["available"] is False and "No ingest reading" in d["ingest"]["reason"]
    assert not server._ingest_stats


def _self_signed_cert(directory):
    key, crt = str(Path(directory) / "k.pem"), str(Path(directory) / "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True, timeout=30)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


def _counted(payload, total):
    """The fixture's paths list with the received-bytes counter of every item set to `total`."""
    out = json.loads(json.dumps(payload))
    for it in out["items"]:
        it["bytesReceived"] = it["inboundBytes"] = total
    return out


@with_clock
async def test_health_check_feeds_the_ingest_numbers(w, clock):
    """The production path: no call of _viewer_sync_once(paths=...), only MediaMTXService.health_check
    (what the service manager runs every 30 s) against a TLS fake of MediaMTX's control API."""
    from services import mediamtx as mtx_service
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    base = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)
    state = {"payload": base, "status": 200, "calls": 0}

    async def paths_list(request):
        state["calls"] += 1
        return web.json_response(state["payload"], status=state["status"])

    app = web.Application()
    app.router.add_get("/v3/paths/list", paths_list)
    with tempfile.TemporaryDirectory() as tmp:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=_self_signed_cert(tmp))
        await site.start()
        port = runner.addresses[0][1]
        saved = (server.aiohttp.ClientSession, mtx_service.monotonic)
        server.aiohttp.ClientSession = w.saved[1]            # the real client: this one talks to the fake
        mtx_service.monotonic = clock
        try:
            svc = mtx_service.MediaMTXService({"id": 1, "name": "mediamtx", "config": json.dumps({"api_port": port})})
            mtx_service.set_paths_listener(server._ingest_feed)
            clock.t += 30
            assert await svc.health_check() is True and state["calls"] == 1
            assert sid in server._ingest_stats and not server._ingest_stats[sid]["samples"]   # the first reading is a base
            st, d, _ = await health(w, "owner", sid)
            assert d["ingest"]["available"] is True and d["ingest"]["bitrate_bps"] is None and d["warnings"] == []
            # 3 Mbit/s for 30 s is 11.25 MB; the next reading arrives 30 s later
            first = base["items"][0]["bytesReceived"]
            clock.t += 30
            state["payload"] = _counted(base, first + 11_250_000)
            assert await svc.health_check() is True
            st, d, _ = await health(w, "owner", sid)
            ing = d["ingest"]
            assert ing["available"] and abs(ing["bitrate_bps"] - 3_000_000) / 3_000_000 < 0.10, ing
            assert ing["source"] == "RTMP" and len(ing["samples"]) == 1
            # 29 s after a reading with growth: still no warning (the old 20 s threshold would warn here)
            clock.t += 29
            st, d, _ = await health(w, "owner", sid)
            assert d["warnings"] == [], d["warnings"]
            # the stream stalls: the counter stays; readings 30 s and 60 s after the last growth are no warning
            clock.t += 1
            await svc.health_check()                                # t+60 s: counter flat, last growth 30 s old
            st, d, _ = await health(w, "owner", sid)
            assert d["warnings"] == [], d["warnings"]
            clock.t += 30
            await svc.health_check()                                # last growth 60 s old
            st, d, _ = await health(w, "owner", sid)
            assert d["warnings"] == [], d["warnings"]
            clock.t += 30
            await svc.health_check()                                # last growth 90 s old: over 75 s
            st, d, _ = await health(w, "owner", sid)
            assert [x["code"] for x in d["warnings"]] == ["no_data"], d["warnings"]
            # an unhealthy answer is not fed; a failing listener does not change the health result
            n = len(server._ingest_stats[sid]["samples"])
            state["status"] = 500
            clock.t += 30
            assert await svc.health_check() is False
            assert len(server._ingest_stats[sid]["samples"]) == n
            state["status"] = 200

            async def broken(payload, at):
                raise RuntimeError("listener failed")
            mtx_service.set_paths_listener(broken)
            assert await svc.health_check() is True
            # no listener: nothing is read from the answer and nothing changes
            mtx_service.set_paths_listener(None)
            assert await svc.health_check() is True and len(server._ingest_stats[sid]["samples"]) == n
        finally:
            mtx_service.set_paths_listener(None)
            server.aiohttp.ClientSession, mtx_service.monotonic = saved
            await runner.cleanup()
    # the portal registers the feed at startup, and the viewer tick still makes no MediaMTX call
    src = Path(server.__file__).read_text()
    assert "set_paths_listener(_ingest_feed)" in src
    assert "paths/list" not in _tick_source()


@with_clock
async def test_one_reading_is_used_once_and_stopping_the_listener_stops_the_feed(w, clock):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    base = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)
    clock.t += 30
    await server._ingest_feed(base, clock())
    clock.t += 30
    grown = _counted(base, base["items"][0]["bytesReceived"] + 11_250_000)
    await server._ingest_feed(grown, clock())
    assert len(server._ingest_stats[sid]["samples"]) == 1
    # the viewer ticks in between hand over no list: they add no sample, however many there are
    for _ in range(6):
        clock.t += 5
        await server._viewer_sync_once()
    assert len(server._ingest_stats[sid]["samples"]) == 1
    # the rate is measured between the fetch times given, not the time the feed ran
    assert abs(server._ingest_stats[sid]["samples"][0][1] - 3_000_000) / 3_000_000 < 0.01


@with_clock
async def test_failing_relay_shows_a_sanitised_error(w, clock):
    sid = w.streams["private"]["id"]
    rel = await w.db.create_relay_destination(sid, "custom", "My relay", RELAY_URL, RELAY_KEY)
    await w.db.update_relay_last_error(
        rel["id"], f"Exit code 1: [tcp] Connection to {RELAY_URL}/[KEY_REDACTED] failed: Connection refused")
    st, d, resp = await health(w, "owner", sid)
    assert st == 200
    r = d["relays"][0]
    assert r["state"] == "failed" and r["name"] == "My relay"
    assert r["last_error"] == "The destination refused the connection. (exit code 1)", r
    assert [x["code"] for x in d["warnings"]] == ["relay_failing"]
    text = resp.body.decode()
    for secret in ("relay-host", "SECRET", "rtmp://", "KEY_REDACTED", "example"):
        assert secret not in text, secret
    # while it runs there is no error and no warning
    server.active_relays[sid] = {rel["id"]: {"process": None, "dest": {}}}
    st, d, _ = await health(w, "owner", sid)
    assert d["relays"][0]["state"] == "running" and d["relays"][0]["last_error"] is None and d["warnings"] == []


@with_clock
async def test_recorder_backlog_guard_and_error(w, clock):
    sid = w.streams["private"]["id"]
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(3):
            (Path(tmp) / f"chunk_{i:03d}.mkv").write_bytes(b"x" * 100)

        class Proc:
            returncode = None
        from datetime import datetime, timezone
        server.active_recordings[sid] = {"process": Proc(), "session_dir": tmp, "uploaded": set(),
                                         "started_at": datetime.now(timezone.utc)}
        st, d, _ = await health(w, "owner", sid)
        rec = d["recorder"]
        assert rec["state"] == "recording" and rec["waiting_chunks"] == 2 and rec["waiting_bytes"] == 200, rec
        assert tmp not in json.dumps(d)
        server.active_recordings.clear()
    server._vod_guard_state[sid] = {"user_id": 1, "kind": "stopped", "code": "low_disk", "message": "x /srv/secret"}
    st, d, resp = await health(w, "owner", sid)
    assert d["recorder"]["state"] == "stopped_by_guard"
    assert [x["code"] for x in d["warnings"]] == ["recording_stopped_by_guard"]
    assert "/srv/secret" not in resp.body.decode()
    server._vod_guard_state.clear()
    server._recorder_errors[sid] = (0.0, stream_health.sanitise_error("Exit code 1: /tmp/secret/x: No space left on device"))
    st, d, resp = await health(w, "owner", sid)
    assert d["recorder"]["state"] == "failed" and "disk" in d["recorder"]["last_error"] and "/tmp" not in resp.body.decode()


@with_clock
async def test_health_goes_through_the_shared_limiter(w, clock):
    sid = w.streams["private"]["id"]
    server._stream_health_rate = server._viewers_mod.RateWindow(3, 60.0)
    got = [(await health(w, "owner", sid))[0] for _ in range(5)]
    assert got == [200, 200, 200, 429, 429], got
    assert (await health(w, "admin", sid))[0] == 200        # per account
    src = Path(server.__file__).read_text()
    a = src.index("async def http_stream_health")
    assert "_limited(" in src[a:a + 900] and "status=429" not in src[a:src.index("# ----- administrator live ops") if "# ----- administrator live ops" in src else a + 900]


# ---------------------------------------------------------------------------
# administrator live operations

class FakeMediaMTX:
    """The control API as captured on v1.21.3 (tests/fixtures/mediamtx-1.21.3/kick_exchanges.json)."""

    def __init__(self, source_type="rtmpConn", sid="69e7ffff-16c5-4590-b049-e36dffd0a1cd", has_path=True):
        self.calls, self.source_type, self.sid, self.has_path = [], source_type, sid, has_path

    async def start(self):
        app = web.Application()
        app.router.add_get("/v3/paths/get/{name:.*}", self.get_path)
        app.router.add_post("/v3/{kind}/kick/{id}", self.kick)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def get_path(self, r):
        self.calls.append(("GET", r.path))
        if not self.has_path:
            return web.json_response({"status": "error", "error": "path not found"}, status=404)
        return web.json_response({"name": r.match_info["name"], "ready": True,
                                  "source": {"type": self.source_type, "id": self.sid}})

    async def kick(self, r):
        self.calls.append(("POST", r.path))
        want = stream_health.KICK_ROUTES.get(self.source_type, "").replace("{id}", self.sid)
        if r.path == want:
            return web.json_response({"status": "ok"})
        return web.json_response({"status": "error", "error": "connection not found"}, status=404)

    async def stop(self):
        await self.runner.cleanup()


def with_mtx(source_type="rtmpConn", has_path=True):
    def deco(fn):
        def runner():
            async def body(w):
                fresh()
                mtx = await FakeMediaMTX(source_type, has_path=has_path).start()
                saved = (server._mediamtx_api_base, server._get_mediamtx_config, server.aiohttp.ClientSession)
                real_session = w.saved[1]
                server._mediamtx_api_base = lambda cfg: f"http://127.0.0.1:{mtx.port}"

                async def cfg():
                    return {"api_port": mtx.port}
                server._get_mediamtx_config = cfg
                server.aiohttp.ClientSession = real_session
                try:
                    await fn(w, mtx)
                finally:
                    server._mediamtx_api_base, server._get_mediamtx_config, server.aiohttp.ClientSession = saved
                    await mtx.stop()
            run(body)
        runner.__name__ = fn.__name__
        return runner
    return deco


async def audit_rows(w, action):
    return await w.db.get_audit_log(limit=50, action=action)


def admin_req(w, user, sid, path, body=None):
    return req(w, user, sid, "POST", path, body, route="admin/streams")


@with_mtx()
async def test_end_now_with_key_regeneration_refuses_the_old_key_and_audits_once(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    owner = w.users["owner"]
    server._rtmp_stream_paths.pop(sid, None)
    assert await w.db.get_stream_by_key(key)
    for user in ("owner", "mod", "member"):         # not administrators: 404 and nothing happens
        r = await server.http_admin_stream_end(admin_req(w, user, sid, "end", {}))
        assert r.status == 404, user
    assert (await w.db.get_user_stream(sid))["is_live"] == 1 and not mtx.calls
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {"regenerate_key": True}))
    assert r.status == 200, r.body
    out = json.loads(r.body)
    assert out["publisher_disconnected"] is True and out["key_replaced"] is True and out["source"] == "RTMP"
    assert ("POST", "/v3/rtmpconns/kick/69e7ffff-16c5-4590-b049-e36dffd0a1cd") in mtx.calls
    assert ("GET", f"/v3/paths/get/live/{key}") in mtx.calls
    row = await w.db.get_user_stream(sid)
    assert row["is_live"] == 0 and row["stream_key"] != key
    # a publisher with the old key is refused by the publish hook, with the old key it found the stream before
    assert await w.db.get_stream_by_key(key) is None
    hook = make_mocked_request("POST", "/api/stream/auth", transport=Transport("127.0.0.1"))

    async def _json():
        return {"action": "publish", "path": "live/" + key, "ip": "198.51.100.7", "user": "", "password": "", "query": ""}
    hook.json = _json
    assert (await server.http_stream_auth(hook)).status == 401
    rows = await audit_rows(w, "stream_end_now")
    assert len(rows) == 1 and rows[0]["target_id"] == sid
    d = json.loads(rows[0]["details"])
    assert d["regenerate_key"] is True and d["owner_id"] == owner
    assert key not in rows[0]["details"] and row["stream_key"] not in rows[0]["details"]
    notes = [n for n in await w.db.get_notifications(owner, limit=50) if n["type"] == "stream_ended"]
    assert len(notes) == 1 and notes[0]["message"] == (
        "An administrator ended your stream. The stream key was replaced: the encoder needs the new key from the stream settings.")
    assert "admin" not in (notes[0]["title"] + notes[0]["message"]).replace("administrator", "")
    # ending it again: the stream is not live
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {}))
    assert r.status == 409 and len(await audit_rows(w, "stream_end_now")) == 1


@with_mtx()
async def test_end_now_without_regeneration_keeps_the_key_and_never_deletes_recordings(w, mtx):
    sid, key = w.streams["public"]["id"], w.streams["public"]["live"]
    with tempfile.TemporaryDirectory() as tmp:
        chunk = Path(tmp) / "chunk_000.mkv"
        chunk.write_bytes(b"x" * 10)
        finalised = []

        async def fake_stop(stream_id, force=False, **kw):
            finalised.append(stream_id)
        saved = server.stop_vod_recording
        server.stop_vod_recording = fake_stop

        class Proc:
            returncode = None
        server.active_recordings[sid] = {"process": Proc(), "session_dir": tmp, "uploaded": set()}
        try:
            r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {"regenerate_key": False}))
            assert r.status == 200, r.body
            assert json.loads(r.body)["key_replaced"] is False, r.body
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and "_finalize_stream_offline" in repr(t.get_coro())]
            await asyncio.gather(*tasks)
        finally:
            server.stop_vod_recording = saved
        assert finalised == [sid]                       # the normal finalisation ran (recording finished, uploaded)
        assert chunk.exists()                           # and nothing was deleted by the action
    row = await w.db.get_user_stream(sid)
    assert row["stream_key"] == key and row["is_live"] == 0
    d = json.loads((await audit_rows(w, "stream_end_now"))[0]["details"])
    assert d["regenerate_key"] is False


@with_mtx(source_type="srtConn")
async def test_a_source_that_cannot_be_kicked_is_said_so_and_the_session_still_ends(w, mtx):
    sid = w.streams["private"]["id"]
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {}))
    out = json.loads(r.body)
    assert r.status == 200 and out["publisher_disconnected"] is False and "cannot be disconnected" in out["disconnect_note"]
    assert not [c for c in mtx.calls if c[0] == "POST"]
    assert (await w.db.get_user_stream(sid))["is_live"] == 0


@with_mtx(has_path=False)
async def test_no_publisher_connected_still_ends_the_session(w, mtx):
    sid = w.streams["private"]["id"]
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {}))
    out = json.loads(r.body)
    assert r.status == 200 and out["publisher_disconnected"] is False and out["disconnect_note"] == "no publisher is connected"


@with_mtx()
async def test_each_source_type_uses_its_own_kick_route(w, mtx):
    for stype, route in stream_health.KICK_ROUTES.items():
        mtx.source_type, mtx.calls = stype, []
        res = await server._mediamtx_kick_publisher("somekey")
        assert res["kicked"] is True, (stype, res)
        assert mtx.calls[-1] == ("POST", route.format(id=mtx.sid)), (stype, mtx.calls)


@with_mtx()
async def test_stop_relays_audit_and_holds_the_monitor_back(w, mtx):
    sid = w.streams["private"]["id"]
    stopped = []

    async def fake_stop(stream_id, force=False, **kw):
        stopped.append((stream_id, force))
        server.active_relays.pop(stream_id, None)
    saved = server.stop_stream_relays
    server.stop_stream_relays = fake_stop
    server.active_relays[sid] = {1: {"process": None, "dest": {}}, 2: {"process": None, "dest": {}}}
    try:
        r = await server.http_admin_stream_stop_relays(admin_req(w, "owner", sid, "stop-relays"))
        assert r.status == 404 and not stopped
        r = await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays"))
    finally:
        server.stop_stream_relays = saved
    assert r.status == 200 and json.loads(r.body)["stopped"] == 2 and stopped == [(sid, True)]
    rows = await audit_rows(w, "stream_stop_relays")
    assert len(rows) == 1 and json.loads(rows[0]["details"])["relays_running"] == 2
    assert sid in server._relay_stop_held
    assert (await w.db.get_user_stream(sid))["is_live"] == 1     # the stream itself goes on
    await server._stream_set_offline(sid)
    assert sid not in server._relay_stop_held


@with_mtx()
async def test_a_moderator_does_not_read_the_live_operation_entries_of_the_audit_log(w, mtx):
    sid = w.streams["private"]["id"]

    async def fake_stop(stream_id, force=False, **kw):
        server.active_relays.pop(stream_id, None)
    saved = server.stop_stream_relays
    server.stop_stream_relays = fake_stop
    try:
        assert (await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays"))).status == 200
        assert (await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {}))).status == 200
    finally:
        server.stop_stream_relays = saved

    async def read(user, query=""):
        h = {"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"}
        r = make_mocked_request("GET", "/api/audit-log?limit=200" + query, headers=h, transport=Transport())
        resp = await server.http_get_audit_log(r)
        assert resp.status == 200, (user, resp.status)
        return json.loads(resp.body)
    wanted = {"stream_end_now", "stream_stop_relays"}
    assert wanted <= {e["action"] for e in (await read("admin"))["entries"]}
    for query in ("", "&action=stream_end_now", "&action=stream_stop_relays"):
        got = await read("mod", query)
        assert not wanted & {e["action"] for e in got["entries"]}, query
    assert (await read("mod", "&action=stream_end_now"))["total"] == 0


@with_mtx()
async def test_stopped_relays_stay_stopped_for_the_restart_paths(w, mtx):
    """Stop relays also holds back the auto-restart of one relay and a start after an encoder reconnect."""
    sid = w.streams["private"]["id"]
    rel = await w.db.create_relay_destination(sid, "custom", "r", "rtmp://203.0.113.5/app", "KEYKEYKEY")
    spawned = []

    async def fake_exec(*a, **k):
        spawned.append(a)
        raise RuntimeError("must not start")
    async def fake_target(url, key):
        return [], "rtmp://relay.invalid/app/key"
    saved = (server._media_exec, asyncio.sleep, server._checked_relay_target)
    server._media_exec, server._checked_relay_target = fake_exec, fake_target
    real_sleep = saved[1]

    async def fast(delay, *a, **k):
        return await real_sleep(0)
    asyncio.sleep = fast
    try:
        server._relay_stop_held.add(sid)
        await server._restart_single_relay(sid, rel["id"], {"platform": "custom", "name": "r"})
        await server.start_stream_relays(await w.db.get_user_stream(sid), w.streams["private"]["live"])
        assert not spawned
        # without the hold the same restart path does try to start the relay (the test double refuses it)
        server._relay_stop_held.clear()
        await server._restart_single_relay(sid, rel["id"], {"platform": "custom", "name": "r"})
        assert spawned
    finally:
        server._media_exec, asyncio.sleep, server._checked_relay_target = saved
    src = Path(server.__file__).read_text()
    mon = src[src.index("async def _relay_health_monitor_task"):src.index("async def stop(self)")]
    assert "_relay_stop_held" in mon


@with_mtx()
async def test_the_disconnect_grace_does_nothing_for_a_stream_that_is_no_longer_live(w, mtx):
    sid = w.streams["private"]["id"]
    stream = await w.db.get_user_stream(sid)
    calls = []
    saved = (server.stop_stream_relays, server._record_stream_offline, asyncio.sleep)

    async def fake_stop(*a, **k):
        calls.append("relays")

    async def fake_rec(*a, **k):
        calls.append("offline-record")
    real_sleep = saved[2]

    async def fast(delay, *a, **k):
        return await real_sleep(0)
    server.stop_stream_relays, server._record_stream_offline, asyncio.sleep = fake_stop, fake_rec, fast
    try:
        server._disconnect_grace_tasks[sid] = asyncio.current_task()
        await server._stream_set_offline(sid)           # ended meanwhile (an administrator's End now)
        await server._handle_disconnect_grace(stream)
        assert calls == [], calls
        await w.db.set_stream_live(sid, True)           # a stream that is still live is ended as before
        server._disconnect_grace_tasks[sid] = asyncio.current_task()
        await server._handle_disconnect_grace(stream)
        assert calls == ["relays", "offline-record"], calls
        assert (await w.db.get_user_stream(sid))["is_live"] == 0
    finally:
        server.stop_stream_relays, server._record_stream_offline, asyncio.sleep = saved
        server._disconnect_grace_tasks.pop(sid, None)


@with_mtx(source_type="srtConn")
async def test_end_now_stops_relays_at_once_and_finishes_a_recorder_whose_source_stays(w, mtx):
    sid = w.streams["private"]["id"]
    seen = []

    async def fake_relays(stream_id, force=False):
        seen.append(("relays", force))

    async def fake_graceful(process):
        seen.append(("graceful", process.name))
        return "q"

    async def fake_stop(stream_id, force=False, **kw):
        seen.append(("stop_vod", force))

    class Proc:
        name = "rec"
        returncode = None
    saved = (server.stop_stream_relays, server._vod_graceful_stop, server.stop_vod_recording)
    server.stop_stream_relays, server._vod_graceful_stop, server.stop_vod_recording = fake_relays, fake_graceful, fake_stop
    server.active_recordings[sid] = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
    try:
        r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {}))
        assert r.status == 200 and json.loads(r.body)["publisher_disconnected"] is False
        await asyncio.gather(*[t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                               and ("_finalize_stream_offline" in repr(t.get_coro()) or "_vod_graceful_stop" in repr(t.get_coro()))])
    finally:
        server.stop_stream_relays, server._vod_graceful_stop, server.stop_vod_recording = saved
    assert seen[0] == ("relays", True), seen            # forced, before the session is ended
    assert ("graceful", "rec") in seen and ("stop_vod", False) in seen, seen


@with_mtx()
async def test_live_list_and_gate_for_api_keys_and_scopes(w, mtx):
    lst = await server.http_admin_live_streams(req(w, "admin", 0, path="", route="admin/live-streams"))
    assert lst.status == 200
    rows = json.loads(lst.body)["streams"]
    ids = {x["id"] for x in rows}
    assert {s["id"] for s in w.streams.values()} <= ids
    assert set(rows[0]) == {"id", "name", "owner", "uptime_s", "bitrate_bps", "viewers", "relays_running", "recording"}
    assert (await server.http_admin_live_streams(req(w, "mod", 0, path="", route="admin/live-streams"))).status == 404
    assert (await server.http_admin_live_streams(req(w, None, 0, path="", route="admin/live-streams"))).status == 401
    # an API key of an administrator is refused (403), as are scoped tokens
    real = server.authenticate_request

    async def as_key(request):
        t = await real(request)
        t.token_id = "apikey-7"
        return t
    server.authenticate_request = as_key
    try:
        r = await server.http_admin_stream_end(admin_req(w, "admin", w.streams["private"]["id"], "end", {}))
        assert r.status == 403
    finally:
        server.authenticate_request = real
    assert (await w.db.get_user_stream(w.streams["private"]["id"]))["is_live"] == 1 and not mtx.calls


def test_stage_mode_never_contacts_the_media_server():
    async def body():
        saved = Config.STAGE_MODE
        Config.STAGE_MODE = True
        try:
            res = await server._mediamtx_kick_publisher("k")
        finally:
            Config.STAGE_MODE = saved
        assert res["kicked"] is False and "staged" in res["reason"]
    asyncio.run(body())


def test_routes_are_registered_and_not_swallowed():
    app = web.Application()
    server.setup_routes(app) if hasattr(server, "setup_routes") else None
    src = Path(server.__file__).read_text()
    assert src.index('"/api/streams/{id}/health"') < src.index('"/api/streams/{id}/relays"')
    for line in ('"/api/admin/live-streams", http_admin_live_streams', '"/api/admin/streams/{id}/end", http_admin_stream_end',
                 '"/api/admin/streams/{id}/stop-relays", http_admin_stream_stop_relays'):
        assert line in src


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
    sys.exit(1 if failed else 0)
