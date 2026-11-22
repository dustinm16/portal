"""Watching a VOD chunk in the browser: routes, jobs and cache, against a real loopback SFTP server and
real ffmpeg / ffprobe on clips generated here (3 seconds, 160x120, well under 200 KB each).

The play routes run in a real aiohttp test server on loopback; only the sign-in is replaced (the header
X-U names the member), because the authentication rules are those of every /api/vods route and are
covered by tests/test_stream_access.py. Everything is written into temporary folders.

Run: venv/bin/python tests/test_vod_play.py
"""
import asyncio
import io
import json
import re
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402
import vod_play  # noqa: E402
import vod_staging  # noqa: E402

outbound_guard.install()
vod_staging.TEMP_ROOTS = ()  # the sandboxes below live under /tmp

import server  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request  # noqa: E402

from test_vod_guard import FakeDb  # noqa: E402
from test_vod_guard_stop import children_of_this_process  # noqa: E402
from test_vod_sweep import PW, Remote  # noqa: E402

CLIPS = tempfile.mkdtemp(prefix="vodplay_clips_")
OWNER, OTHER, ADMIN = 1, 2, 3
SESSION = "Show/2026-01-01"
NAME = f"{SESSION}/chunk_000.mkv"


def make(path, audio="aac", vcodec="libx264", seed=0):
    cmd = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", f"testsrc=size=160x120:rate=10:duration=3",
           "-f", "lavfi", "-i", f"sine=frequency={440 + seed}:duration=3"]
    cmd += ["-c:v", vcodec, "-preset", "ultrafast", "-crf", "35", "-pix_fmt", "yuv420p", "-g", "10"]
    if audio == "none":
        cmd = [c for c in cmd if c not in ("-f", "lavfi")]
        cmd = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10:duration=3",
               "-c:v", vcodec, "-preset", "ultrafast", "-crf", "35", "-pix_fmt", "yuv420p", "-g", "10"]
    else:
        cmd += ["-c:a", audio, "-b:a", "32k"]
    cmd.append(path)
    subprocess.run(cmd, check=True, timeout=60)
    return Path(path).read_bytes()


def clip(kind="aac", seed=0):
    path = os.path.join(CLIPS, f"{kind}{seed}.mkv")
    if not os.path.exists(path):
        make(path, audio=kind, seed=seed)
    return Path(path).read_bytes()


class Db(FakeDb):
    def __init__(self, remote, settings):
        super().__init__(settings)
        self.remote = remote

    async def delete_vod_storage(self, uid):
        self.deleted_storage = getattr(self, "deleted_storage", []) + [uid]
        return True

    async def get_vod_storage(self, uid):
        if uid == ADMIN:
            return None
        root = "/v" if uid == OWNER else "/w"
        return {"host": "127.0.0.1", "port": self.remote.port, "username": "u", "auth_method": "password",
                "remote_path": root, "config": {"password": PW, "host_key_ignore": True}}


class Env:
    """The play routes served on loopback, the SFTP storage, the cache folder, a spy on every ffmpeg start."""

    def __init__(self, t, settings=None, fast_wait=30.0, ttl=0.0):
        self.t, self.fast_wait, self.ttl = t, fast_wait, ttl
        self.settings = {"vod_play_cache_mb": "50", "vod_min_free_gb": "0"}
        self.settings.update(settings or {})
        self.spawned = []

    async def __aenter__(self):
        self.remote = await Remote(self.t).__aenter__()
        self.db = Db(self.remote, self.settings)
        self.cache_dir = os.path.join(self.t, "cache")
        env = self
        real_exec = server._media_exec

        async def spy(cmd, *a, **k):
            env.spawned.append(cmd[0])
            return await real_exec(cmd, *a, **k)

        async def resolve(host, port):
            return ["127.0.0.1"]

        async def fake_auth(request):
            uid = request.headers.get("X-U")
            if not uid:
                return None, web.json_response({"error": "no"}, status=401)
            return SimpleNamespace(user_id=int(uid)), None

        self.patches = [
            mock.patch.object(server, "db", self.db),
            mock.patch.object(server, "resolve_checked_host", resolve),
            mock.patch.object(server, "_media_exec", spy),
            mock.patch.object(server, "_stream_user_auth", fake_auth),
            mock.patch.object(server, "VOD_PLAY_FAST_WAIT", self.fast_wait),
            mock.patch.object(server, "VOD_PLAY_STAT_TTL", self.ttl),
            mock.patch.object(server, "VOD_TEMP_DIR", os.path.join(self.t, "stage")),
            mock.patch.dict(server.active_recordings, {}, clear=True),
        ]
        for p in self.patches:
            p.start()
        server._vod_play_jobs.clear()
        server._vod_play_stats.clear()
        server._vod_session_probes.clear()
        assert server._vod_play_setup(self.cache_dir) is None
        self.cache = server._vod_play_cache
        app = web.Application()
        app.router.add_get("/api/vods/play/{name:.+}", server.http_play_vod)
        app.router.add_get("/api/vods/play-status/{name:.+}", server.http_play_vod_status)
        app.router.add_get("/api/vods/session/{name:.+}", server.http_play_session)
        app.router.add_get("/api/vods/download/{filename:.*}", server.http_download_vod)
        app.router.add_get("/api/vods", server.http_list_vods)
        app.router.add_post("/api/vods/download-archive", server.http_download_vod_archive)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        return self

    async def __aexit__(self, *a):
        await server._vod_play_cancel_all()
        self.cache.cancel_flush()
        server._vod_session_probes.clear()
        await self.client.close()
        for p in reversed(self.patches):
            p.stop()
        server._vod_play_jobs.clear()
        server._vod_play_stats.clear()
        server._vod_play_cache = None
        await self.remote.__aexit__(*a)

    def put(self, name, data, root="/v", mtime=None):
        self.remote.put(f"{root}/{name}", data)
        if mtime:
            os.utime(self.remote.path(f"{root}/{name}"), (mtime, mtime))

    async def play(self, name=NAME, user=OWNER, **headers):
        h = {"X-U": str(user)}
        h.update(headers)
        return await self.client.get("/api/vods/play/" + name + ".mp4", headers=h)

    async def status(self, name=NAME, user=OWNER):
        r = await self.client.get("/api/vods/play-status/" + name + ".mp4", headers={"X-U": str(user)})
        return r.status, await r.json()

    async def wait_state(self, want, name=NAME, user=OWNER, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            _, body = await self.status(name, user)
            if body["state"] in want:
                return body
            await asyncio.sleep(0.1)
        raise AssertionError(f"state never reached {want}: {body}")

    def ffmpegs(self):
        return self.spawned.count("ffmpeg")


def probe(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_name", "-of", "csv=p=0", path],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout.split()


def run(coro):
    return asyncio.run(coro)


def with_env(fn=None, **kw):
    def deco(f):
        def wrapper():
            async def go():
                with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
                    async with Env(t, **kw) as env:
                        await f(env)
            run(go())
            assert children_of_this_process() == [], "a test left a child process running"
        wrapper.__name__ = f.__name__
        return wrapper
    return deco(fn) if fn else deco


@with_env
async def test_owner_gets_an_mp4_with_the_index_first_and_range_works(env):
    env.put(NAME, clip())
    r = await env.play()
    assert r.status == 200, await r.text()
    assert r.headers["Content-Type"] == "video/mp4"
    cc = r.headers["Cache-Control"].lower()
    assert "private" in cc and "public" not in cc and "max-age" not in cc
    body = await r.read()
    assert body[4:8] == b"ftyp"
    (cached,) = [os.path.join(env.cache.root, f) for f in os.listdir(env.cache.root) if f.endswith(".mp4")]
    code, codecs = probe(cached)
    assert code == 0 and "h264" in codecs and "aac" in codecs
    assert vod_play.index_first(cached), vod_play.top_level_boxes(cached)
    assert len(body) == os.path.getsize(cached)
    r2 = await env.play(Range="bytes=0-99")
    assert r2.status == 206 and r2.headers["Content-Range"] == f"bytes 0-99/{len(body)}"
    assert len(await r2.read()) == 100
    r3 = await env.play(Range=f"bytes={len(body) - 10}-")
    assert r3.status == 206 and len(await r3.read()) == 10
    assert oct(os.stat(env.cache.root).st_mode & 0o777) == "0o700" and oct(os.stat(cached).st_mode & 0o777) == "0o600"
    assert os.listdir(os.path.join(env.cache.root, "work")) == [] if os.path.isdir(
        os.path.join(env.cache.root, "work")) else True


@with_env
async def test_a_second_request_is_served_from_the_cache_without_a_job(env):
    env.put(NAME, clip())
    assert (await env.play()).status == 200
    spawned = len(env.spawned)
    for _ in range(3):
        assert (await env.play()).status == 200
    assert len(env.spawned) == spawned, env.spawned
    assert (await env.status())[1]["state"] == "ready"


@with_env(fast_wait=0)
async def test_an_unprepared_chunk_answers_202_and_the_status_route_says_when_it_is_ready(env):
    env.put(NAME, clip())
    t0 = time.time()
    r = await env.play()
    assert r.status == 202 and time.time() - t0 < 3
    body = await r.json()
    assert body["state"] == "preparing" and body["status_url"].startswith("/api/vods/play-status/")
    assert "private" in r.headers["Cache-Control"].lower() and r.headers.get("Retry-After")
    r = await env.client.get(body["status_url"], headers={"X-U": str(OWNER)})
    assert r.status == 200
    assert (await env.wait_state({"ready"}))["state"] == "ready"
    assert (await env.play()).status == 200


@with_env(fast_wait=0)
async def test_unsupported_audio_is_download_only_with_a_reason_and_leaves_nothing(env):
    env.put(NAME, clip("libopus"))
    await env.play()
    body = await env.wait_state({"unplayable", "failed"})
    assert body["state"] == "unplayable" and "opus" in body["reason"] and "Download" in body["message"]
    r = await env.play()
    assert r.status == 415
    j = await r.json()
    assert "opus" in j["error"] and j["state"] == "unplayable"
    assert "private" in r.headers["Cache-Control"].lower()
    spawned = len(env.spawned)
    assert (await env.play()).status == 415 and len(env.spawned) == spawned     # remembered, no new pull
    assert env.cache.entries == {} and env.cache.disk_bytes() < 2000
    assert not os.path.isdir(env.cache.work_root()) or os.listdir(env.cache.work_root()) == []


@with_env
async def test_h264_without_audio_is_playable(env):
    env.put(NAME, clip("none"))
    assert (await env.play()).status == 200
    env.put(f"{SESSION}/chunk_001.mkv", clip("aac", 1))
    assert (await env.play(f"{SESSION}/chunk_001.mkv")).status == 200


@with_env
async def test_another_member_and_an_administrator_get_404_and_never_the_owners_entry(env):
    data = clip()
    env.put(NAME, data, mtime=1700000000)
    assert (await env.play()).status == 200
    env.put(NAME, data, root="/w", mtime=1700000000)     # the other member has a file with the same path, size and time
    spawned = env.ffmpegs()
    # the owner's entry is not offered to anybody else: the other member prepares a copy of their own
    r = await env.play(user=OTHER)
    assert r.status == 200
    assert env.ffmpegs() > spawned
    assert sorted({e["owner"] for e in env.cache.entries.values()}) == [OWNER, OTHER]
    # the administrator has no storage holding this path: 404, whatever the path of the owner is
    r = await env.play(user=ADMIN)
    assert r.status == 404
    st, _ = await env.status(user=ADMIN)
    assert st == 404
    # a member whose storage lacks the path
    r = await env.play(f"{SESSION}/chunk_009.mkv", user=OTHER)
    assert r.status == 404
    r = await env.client.get("/api/vods/play/" + NAME + ".mp4")
    assert r.status == 401


@with_env
async def test_paths_that_are_not_a_listed_chunk_are_refused(env):
    env.put(NAME, clip())
    env.put("outside.mkv", clip(), root="/")
    for bad in ("../outside.mkv", "/etc/passwd.mkv", "Show/../../outside.mkv", "Show//x.mkv", "Show/.hidden/x.mkv",
                "Show\\x.mkv", "Show/x.mp4", "Show/x.mkv.txt", "", "Show/x\x00.mkv"):
        req = make_mocked_request("GET", "/api/vods/play/x", headers={"X-U": str(OWNER)},
                                  match_info={"name": bad + ".mp4"})
        with mock.patch.object(server, "_stream_user_auth", lambda r: _ok(OWNER)):
            resp = await server.http_play_vod(req)
        assert resp.status == 404, (bad, resp.status)
        req = make_mocked_request("GET", "/api/vods/play-status/x", headers={"X-U": str(OWNER)},
                                  match_info={"name": bad + ".mp4"})
        with mock.patch.object(server, "_stream_user_auth", lambda r: _ok(OWNER)):
            assert (await server.http_play_vod_status(req)).status == 404, bad
    assert env.spawned == []
    # an encoded dot segment is only a name nobody has: it is looked up in the owner's folder and is not there
    req = make_mocked_request("GET", "/api/vods/play/x", headers={"X-U": str(OWNER)},
                              match_info={"name": "Show/%2e%2e/x.mkv.mp4"})
    with mock.patch.object(server, "_stream_user_auth", lambda r: _ok(OWNER)):
        assert (await server.http_play_vod(req)).status == 404
    # a name without .mp4 and a directory
    r = await env.client.get("/api/vods/play/" + NAME, headers={"X-U": str(OWNER)})
    assert r.status == 404
    r = await env.client.get("/api/vods/play/Show.mkv.mp4", headers={"X-U": str(OWNER)})
    assert r.status == 404 and env.spawned == []


async def _ok(uid):
    return SimpleNamespace(user_id=uid), None


@with_env
async def test_cache_cap_holds_one_file_and_the_second_evicts_the_first(env):
    a, b = clip("aac", 0), clip("aac", 5)
    env.put(f"{SESSION}/chunk_000.mkv", a)
    env.put(f"{SESSION}/chunk_001.mkv", b)
    cap = vod_play.output_limit(max(len(a), len(b))) + 10_000      # holds one finished copy, not two
    env.db.settings["vod_play_cache_mb"] = str(cap / (1024 * 1024))
    peak = {"max": 0, "stop": False}

    async def watch():
        while not peak["stop"]:
            peak["max"] = max(peak["max"], env.cache.disk_bytes())
            await asyncio.sleep(0.003)
    watcher = asyncio.create_task(watch())
    try:
        assert (await env.play(f"{SESSION}/chunk_000.mkv")).status == 200
        first = set(env.cache.entries)
        assert len(first) == 1
        assert (await env.play(f"{SESSION}/chunk_001.mkv")).status == 200
        second = set(env.cache.entries)
        assert len(second) == 1 and first.isdisjoint(second)
        assert not os.path.exists(os.path.join(env.cache.root, next(iter(first)) + ".mp4"))
        spawned = env.ffmpegs()
        assert (await env.play(f"{SESSION}/chunk_000.mkv")).status == 200       # the first one is prepared again
        assert env.ffmpegs() > spawned
    finally:
        peak["stop"] = True
        await watcher
    # the cap counts stored copies; while a job works its pulled source and output are on disk besides
    assert peak["max"] <= cap + vod_play.job_reserve(max(len(a), len(b))), (peak["max"], cap)
    assert env.cache.disk_bytes() <= cap


@with_env
async def test_a_chunk_that_can_never_fit_is_download_only(env):
    data = clip()
    env.put(NAME, data)
    env.db.settings["vod_play_cache_mb"] = str(len(data) / (1024 * 1024))
    r = await env.play()
    assert r.status == 415 and "too large" in (await r.json())["error"]
    assert env.spawned.count("ffmpeg") == 0 and env.cache.disk_bytes() < 2000


@with_env
async def test_playback_off_with_zero_and_the_folder_is_emptied(env):
    env.put(NAME, clip())
    assert (await env.play()).status == 200 and env.cache.entries
    env.db.settings["vod_play_cache_mb"] = "0"
    r = await env.play()
    assert r.status == 503
    j = await r.json()
    assert j["code"] == "playback_off" and "switched off" in j["error"]
    assert env.cache.entries == {} and [f for f in os.listdir(env.cache.root) if f.endswith(".mp4")] == []
    assert (await env.status())[0] == 503
    pub = await server._vod_play_public()
    assert pub["enabled"] is False and "switched off" in pub["message"]
    env.db.settings["vod_play_cache_mb"] = "50"
    assert (await server._vod_play_public())["enabled"] is True


@with_env
async def test_a_changed_remote_chunk_is_never_served_from_an_old_entry(env):
    old = clip("aac", 0)
    env.put(NAME, old, mtime=1700000000)
    r = await env.play()
    assert r.status == 200
    first = await r.read()
    new = clip("aac", 9)
    assert len(new) != len(old) or new != old
    env.put(NAME, new, mtime=1700000500)
    r = await env.play()
    assert r.status == 200
    second = await r.read()
    assert first != second
    assert len(env.cache.entries) == 2          # both versions keyed apart (the old one ages out by LRU)
    # same size and content, only the time changed: still a new key
    keys = set(env.cache.entries)
    env.put(NAME, new, mtime=1700000900)
    assert (await env.play()).status == 200 and set(env.cache.entries) != keys


@with_env
async def test_a_failed_job_leaves_no_file(env):
    env.put(NAME, clip())
    with mock.patch.object(vod_play, "remux_argv", lambda s, o, n: ["ffmpeg", "-nostdin", "-bogus-option"]):
        r = await env.play()
        assert r.status in (500, 502), r.status
        assert "could not" in (await r.json())["error"].lower()
    assert env.cache.entries == {}
    assert [f for f in os.listdir(env.cache.root) if f.endswith(".mp4")] == []
    assert not os.path.isdir(env.cache.work_root()) or os.listdir(env.cache.work_root()) == []
    assert env.cache.reserved == 0
    assert (await env.status())[1]["state"] == "failed"
    # and the next request tries again and succeeds
    assert (await env.play()).status == 200


@with_env
async def test_a_garbage_file_is_download_only_and_leaves_no_file(env):
    env.put(NAME, b"not a video at all" * 100)
    r = await env.play()
    assert r.status == 415
    assert env.cache.entries == {} and env.cache.reserved == 0
    assert not os.path.isdir(env.cache.work_root()) or os.listdir(env.cache.work_root()) == []


@with_env
async def test_a_job_that_runs_too_long_is_killed_and_leaves_nothing(env):
    env.put(NAME, clip())
    with mock.patch.object(server, "VOD_PLAY_REMUX_TIMEOUT", 1.0), \
            mock.patch.object(vod_play, "remux_argv", lambda s, o, n: ["sleep", "60"]):
        t0 = time.time()
        r = await env.play()
        assert r.status == 500 and time.time() - t0 < 20, r.status
    assert children_of_this_process() == []
    assert env.cache.entries == {} and env.cache.reserved == 0
    assert not os.path.isdir(env.cache.work_root()) or os.listdir(env.cache.work_root()) == []


@with_env
async def test_an_output_far_larger_than_the_input_is_refused(env):
    env.put(NAME, clip())
    with mock.patch.object(vod_play, "OUTPUT_SLACK", 0), mock.patch.object(vod_play, "output_limit", lambda s: 1000):
        r = await env.play()
        assert r.status == 500
    assert env.cache.entries == {} and env.cache.reserved == 0


@with_env(fast_wait=0)
async def test_two_requests_for_one_chunk_share_one_job(env):
    env.put(NAME, clip())
    rs = await asyncio.gather(*[env.play() for _ in range(4)])
    assert [r.status for r in rs] == [202] * 4
    await env.wait_state({"ready"})
    assert env.spawned.count("ffmpeg") == 1, env.spawned            # one remux
    assert env.spawned.count("ffprobe") == 2                        # the source and the result
    assert len([j for j in server._vod_play_jobs.values()]) == 1


@with_env(fast_wait=0)
async def test_at_most_two_jobs_run_at_once_and_a_member_has_a_queue_limit(env):
    for i in range(4):
        env.put(f"{SESSION}/chunk_00{i}.mkv", clip("aac", i))
    running = {"now": 0, "max": 0}
    real = server._vod_play_run_tool

    async def slow(*a, **k):
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        try:
            await asyncio.sleep(0.4)
            return await real(*a, **k)
        finally:
            running["now"] -= 1
    with mock.patch.object(server, "_vod_play_run_tool", slow), mock.patch.object(server, "VOD_PLAY_MAX_PER_USER", 3):
        codes = [(await env.play(f"{SESSION}/chunk_00{i}.mkv")).status for i in range(4)]
        assert codes == [202, 202, 202, 429], codes
        r = await env.play(f"{SESSION}/chunk_003.mkv")
        assert r.status == 429 and r.headers.get("Retry-After")
        for i in range(3):
            await env.wait_state({"ready"}, f"{SESSION}/chunk_00{i}.mkv")
        assert running["max"] <= server.VOD_PLAY_SLOTS, running
        assert (await env.play(f"{SESSION}/chunk_003.mkv")).status == 202   # a slot is free again


@with_env(fast_wait=0, settings={"vod_min_free_gb": "1"})
async def test_free_space_check_counts_what_other_running_jobs_have_reserved(env):
    # two members: one member's jobs run one after the other, so their working space never adds up
    a, b = clip("aac", 0), clip("aac", 1)
    env.put(NAME, a)
    env.put(NAME, b, root="/w")
    floor = 1024 ** 3
    room = floor + max(vod_play.job_reserve(len(a)), vod_play.job_reserve(len(b))) + 10   # room for one job only
    real_pull = server._vod_play_pull

    async def slow_pull(*args, **kw):
        await asyncio.sleep(0.6)                     # the second job reserves while the first one pulls
        return await real_pull(*args, **kw)
    with mock.patch.object(vod_staging, "free_bytes", lambda path: room), \
            mock.patch.object(server, "_vod_play_pull", slow_pull):
        codes = [(await env.play(NAME, user=u)).status for u in (OWNER, OTHER)]
        assert codes == [202, 202], codes
        states = []
        for u in (OWNER, OTHER):
            states.append((await env.wait_state({"ready", "failed"}, NAME, user=u))["state"])
    assert sorted(states) == ["failed", "ready"], states
    assert len(env.cache.entries) == 1 and env.cache.reserved == 0


@with_env
async def test_the_newest_chunk_of_a_live_recording_is_excluded(env):
    env.put(f"{SESSION}/chunk_000.mkv", clip("aac", 0))
    env.put(f"{SESSION}/chunk_001.mkv", clip("aac", 1))
    server.active_recordings[7] = {"remote_session_dir": f"/v/{SESSION}", "user_id": OWNER}
    r = await env.play(f"{SESSION}/chunk_001.mkv")
    assert r.status == 409 and "live" in (await r.json())["error"]
    assert env.spawned == []
    assert (await env.play(f"{SESSION}/chunk_000.mkv")).status == 200          # older chunks are complete
    server.active_recordings.clear()
    assert (await env.play(f"{SESSION}/chunk_001.mkv")).status == 200          # the stream has ended


@with_env
async def test_removing_the_account_or_the_storage_removes_cached_files(env):
    env.put(NAME, clip())
    env.put(NAME, clip(), root="/w")
    assert (await env.play()).status == 200 and (await env.play(user=OTHER)).status == 200
    assert len(env.cache.entries) == 2
    server._vod_play_purge(owner=OWNER)
    assert {e["owner"] for e in env.cache.entries.values()} == {OTHER}
    assert len([f for f in os.listdir(env.cache.root) if f.endswith(".mp4")]) == 1
    assert (await env.status(user=OTHER))[1]["state"] == "ready"
    # a storage that now points elsewhere: only entries of the old storage go
    ident = vod_play.storage_ident(await env.db.get_vod_storage(OTHER))
    server._vod_play_purge(owner=OTHER, ident_not=ident)
    assert len(env.cache.entries) == 1
    server._vod_play_purge(owner=OTHER, ident_not="another")
    assert env.cache.entries == {} and [f for f in os.listdir(env.cache.root) if f.endswith(".mp4")] == []


@with_env(ttl=15.0)
async def test_a_new_playback_never_gets_an_old_entry_even_inside_the_memo_window(env):
    old, new = clip("aac", 0), clip("aac", 9)
    env.put(NAME, old, mtime=1700000000)
    r = await env.play()
    assert r.status == 200
    first = await r.read()
    env.put(NAME, new, mtime=1700000500)
    # a playback starts without a Range header or with a range from byte 0: read afresh, the new version
    r = await env.play(Range="bytes=0-0")
    assert r.status == 200 or r.status == 206
    second = await r.read()
    assert r.status == 206 and len(env.cache.entries) == 2, (r.status, len(env.cache.entries))
    r = await env.play()
    assert r.status == 200 and await r.read() != first
    # only the continuation of a playback may use the answer remembered for a few seconds
    env.put(NAME, old, mtime=1700000900)
    r = await env.play(Range="bytes=100-199")
    assert r.status == 206 and len(await r.read()) == 100
    assert len(env.cache.entries) == 2            # no job was started for the continuation
    r = await env.play(Range="bytes=0-")
    assert r.status in (200, 206) and len(env.cache.entries) == 3


@with_env
async def test_the_removal_hooks_run_in_the_real_handlers(env):
    env.put(NAME, clip())
    env.put(f"{SESSION}/chunk_001.mkv", clip("aac", 1))
    assert (await env.play()).status == 200 and (await env.play(f"{SESSION}/chunk_001.mkv")).status == 200
    assert len(env.cache.entries) == 2
    # deleting one chunk in My VODs drops its copy and keeps the other
    req = make_mocked_request("DELETE", "/api/vods/x", headers={"X-U": str(OWNER)},
                              match_info={"filename": NAME})
    resp = await server.http_delete_vod(req)
    assert resp.status == 200, resp.text
    assert [e["path"] for e in env.cache.entries.values()] == [f"{SESSION}/chunk_001.mkv"]
    assert len([f for f in os.listdir(env.cache.root) if f.endswith(".mp4")]) == 1
    # deleting the storage removes every copy of the member
    req = make_mocked_request("DELETE", "/api/vods/storage", headers={"X-U": str(OWNER)})
    resp = await server.http_delete_vod_storage(req)
    assert resp.status == 200 and env.db.deleted_storage == [OWNER]
    assert env.cache.entries == {} and [f for f in os.listdir(env.cache.root) if f.endswith(".mp4")] == []
    # the other hooks sit next to the database change they belong to
    src = (ROOT / "server.py").read_text()

    def body(name):
        start = src.index(f"async def {name}(")
        m = re.search(r"\n(?:async def|def) ", src[start + 10:])
        return src[start:start + 10 + m.start()]
    assert body("http_delete_user").index("await db.delete_user(user_id)") < body("http_delete_user").index(
        "_vod_play_purge(owner=user_id)")
    save = body("http_save_vod_storage")
    assert "_vod_play_purge(owner=token.user_id, ident_not=vod_play.storage_ident(" in save
    assert save.index("db.save_vod_storage(") < save.index("_vod_play_purge(")
    ret = body("http_set_retention_config")
    assert ret.index("db.set_retention_config(data)") < ret.index("evict_to(cap)") and "purge()" in ret
    server._vod_play_purge(owner=OWNER, ident_not="x")


@with_env
async def test_start_up_removes_files_the_index_does_not_know_and_owners_without_storage(env):
    env.put(NAME, clip())
    assert (await env.play()).status == 200
    stray = os.path.join(env.cache.root, "f" * 32 + ".mp4")
    Path(stray).write_bytes(b"x" * 1000)
    os.makedirs(os.path.join(env.cache.work_root(), "job-dead"), exist_ok=True)
    Path(env.cache.work_root(), "job-dead", "src.mkv").write_bytes(b"x" * 1000)
    assert server._vod_play_setup(env.cache_dir) is None
    assert not os.path.exists(stray) and os.listdir(env.cache.work_root()) == []
    assert len(server._vod_play_cache.entries) == 1
    env.db.get_vod_storage_orig = env.db.get_vod_storage

    async def no_storage(uid):
        return None
    env.db.get_vod_storage = no_storage
    await server._vod_play_reconcile_owners()
    assert server._vod_play_cache.entries == {}
    assert [f for f in os.listdir(env.cache.root) if f.endswith(".mp4")] == []


def test_a_cache_folder_that_is_not_ours_is_refused_and_left_untouched():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        foreign = os.path.join(t, "docs")
        os.mkdir(foreign)
        Path(foreign, "precious.txt").write_text("keep")
        try:
            why = server._vod_play_setup(foreign)
            assert why and server._vod_play_cache is None
            assert os.listdir(foreign) == ["precious.txt"]
            assert "not available" in server._vod_play_off_message(10 ** 9)
        finally:
            server._vod_play_refused = None


def test_a_cache_folder_around_or_inside_the_staging_or_recordings_folder_is_refused_at_start():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        saved = (server.VOD_TEMP_DIR, server.Config.RECORDINGS_DIR)
        try:
            cache = os.path.join(t, "cache")
            session = os.path.join(cache, "staging", "5_2026-11-22_1")
            os.makedirs(session)
            Path(session, "chunk_000.mkv").write_bytes(b"w" * 100)
            server.VOD_TEMP_DIR = os.path.join(cache, "staging")
            why = server._vod_play_setup(cache)
            assert why and "overlaps" in why and server._vod_play_cache is None, why
            assert not os.path.exists(os.path.join(cache, ".portal_vod_play_cache")), "the folder was marked"
            server.VOD_TEMP_DIR = os.path.join(t, "elsewhere")
            server.Config.RECORDINGS_DIR = os.path.join(cache, "rec")
            why = server._vod_play_setup(cache)
            assert why and "overlaps" in why, why
            assert os.path.exists(os.path.join(session, "chunk_000.mkv"))
        finally:
            server.VOD_TEMP_DIR, server.Config.RECORDINGS_DIR = saved
            server._vod_play_refused = None


def test_the_setting_is_a_retention_setting_with_a_bound_and_the_routes_exist():
    import database
    d = database.Database.__new__(database.Database)
    assert d._RETENTION_DEFAULTS["vod_play_cache_mb"] == "512"
    src = (ROOT / "server.py").read_text()
    assert 'add_get("/api/vods/play/{name:.+}", http_play_vod)' in src
    assert 'add_get("/api/vods/play-status/{name:.+}", http_play_vod_status)' in src
    for h in ("http_play_vod", "http_play_vod_status"):
        start = src.index(f"async def {h}(")
        m = re.search(r"\n(?:async def|def) ", src[start + 10:])
        body = src[start:start + 10 + m.start()]
        assert "_stream_user_auth(" in body and "authenticate_request(" not in body


@with_env
async def test_links_on_the_remote_do_not_lead_out_of_the_owners_root(env):
    """A file link or a folder link inside the owner's root that points into another root is a 404 on
    the play route, the session segment route and the download route; a plain file still plays."""
    env.put("Other/2026-01-01/chunk_000.mkv", clip(), root="/w")
    env.put(NAME, clip())                                   # the control: a real file of the owner
    leaf = env.remote.path("/v/Show/2026-01-01/chunk_001.mkv")
    os.symlink("../../../w/Other/2026-01-01/chunk_000.mkv", leaf)        # a file link out of the root
    os.symlink("../w", env.remote.path("/v/escape"))                     # a folder link out of the root
    inside = env.remote.path("/v/Show/2026-01-01/chunk_002.mkv")
    os.symlink("chunk_000.mkv", inside)                                  # a link to a file of the same root
    h = {"X-U": str(OWNER)}
    for name in ("Show/2026-01-01/chunk_001.mkv", "escape/Other/2026-01-01/chunk_000.mkv",
                 "Show/2026-01-01/chunk_002.mkv"):
        r = await env.play(name)
        assert r.status == 404, (name, r.status)
        r = await env.client.get("/api/vods/session/" + name.replace(".mkv", ".ts"), headers=h)
        assert r.status == 404, (name, "segment", r.status)
        r = await env.client.get("/api/vods/download/" + name, headers=h)
        assert r.status == 404, (name, "download", r.status)
    assert env.ffmpegs() == 0, env.spawned
    r = await env.play()
    assert r.status == 200, await r.text()
    r = await env.client.get("/api/vods/download/" + NAME, headers=h)
    assert r.status == 200


@with_env
async def test_delete_and_listing_do_not_follow_links_out_of_the_owners_root(env):
    """A delete through a folder link or a file link removes nothing outside the owner's root, and My VODs
    does not list what lies behind a link."""
    env.put("Other/2026-01-01/chunk_000.mkv", clip(), root="/w")
    env.put(NAME, clip())
    os.symlink("../w", env.remote.path("/v/escape"))
    os.symlink("../../../w/Other/2026-01-01/chunk_000.mkv", env.remote.path("/v/Show/2026-01-01/chunk_009.mkv"))
    h = {"X-U": str(OWNER)}
    r = await env.client.get("/api/vods", headers=h)
    names = [f["name"] for f in (await r.json())["files"]]
    assert names == [NAME], names
    victim = env.remote.path("/w/Other/2026-01-01/chunk_000.mkv")

    async def delete(name):
        return await server.http_delete_vod(make_mocked_request(
            "DELETE", "/api/vods/x", headers=h, match_info={"filename": name}))
    for name in ("escape/Other/2026-01-01/chunk_000.mkv", "Show/2026-01-01/chunk_009.mkv"):
        r = await delete(name)
        assert r.status == 404, (name, r.status)
        assert os.path.exists(victim), name
    assert os.path.islink(env.remote.path("/v/Show/2026-01-01/chunk_009.mkv"))   # the link itself is left alone too
    r = await delete(NAME)                                                         # a real chunk is still deleted
    assert r.status == 200 and not os.path.exists(env.remote.path("/v/" + NAME))


@with_env
async def test_the_zip_download_does_not_follow_links_out_of_the_owners_root(env):
    """The zip route reads each file through the same confinement as the single download: a folder link and
    a file link into another root add nothing from it to the archive, and a real chunk is still zipped."""
    env.put("Other/2026-01-01/chunk_000.mkv", b"SECRET-OF-OTHER", root="/w")
    env.put(NAME, clip())
    os.symlink("../w", env.remote.path("/v/escape"))
    os.symlink("../../../w/Other/2026-01-01/chunk_000.mkv", env.remote.path("/v/Show/2026-01-01/chunk_009.mkv"))
    h = {"X-U": str(OWNER)}
    for name in ("escape/Other/2026-01-01/chunk_000.mkv", "Show/2026-01-01/chunk_009.mkv"):
        r = await env.client.post("/api/vods/download-archive", json={"files": [name, NAME]}, headers=h)
        raw = await r.read()
        assert r.status == 200
        assert b"SECRET-OF-OTHER" not in raw, name
        zf = zipfile.ZipFile(io.BytesIO(raw))
        assert zf.namelist() == [NAME], (name, zf.namelist())
        assert zf.read(NAME) == clip()


def _setup_in_fresh_folder(prepare):
    """Run the real start-up of the cache on a folder that *prepare(folder)* has filled; returns
    (reason or None, cache, logged lines). The module's state is reset afterwards."""
    import logging
    lines = []

    class H(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = H(level=logging.DEBUG)
    log = logging.getLogger("portal")
    log.addHandler(handler)
    try:
        with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
            folder = os.path.join(t, "cache")
            server._vod_play_setup(folder)          # creates the folder with its marker
            server._vod_play_cache = server._vod_play_refused = None
            prepare(folder)
            why = server._vod_play_setup(folder)
            cache = server._vod_play_cache
            return why, cache, lines, t
    finally:
        log.removeHandler(handler)
        server._vod_play_cache = server._vod_play_refused = None


def _dur(at, path="S/d/chunk_000.mkv"):
    return {"owner": 1, "ident": "i", "path": path, "rsize": 5, "rmtime": 6, "duration": 3.0,
            "playable": True, "at": at}


def test_a_bad_entry_in_the_remembered_lengths_or_the_index_is_skipped_and_start_goes_on():
    def prepare(folder):
        good, bad = "a" * 32, "b" * 32
        Path(folder, "durations.json").write_text(json.dumps({"version": 1, "durations": {
            good: _dur(5.0), bad: _dur("junk", "S/d/chunk_001.mkv"), "c" * 32: _dur(1e999, "S/d/chunk_002.mkv"),
            "d" * 32: _dur([1], "S/d/chunk_003.mkv")}}).replace("Infinity", "1e999"))
        for key, used in (("1" * 32, 7), ("2" * 32, "junk"), ("3" * 32, [1])):
            Path(folder, key + ".mp4").write_bytes(b"x" * 10)
        entry = lambda k, used: {"file": k + ".mp4", "size": 10, "owner": 1, "rsize": 1, "rmtime": 1,
                                 "path": "S/d/" + k, "ident": "i", "used": used, "kind": "mp4"}
        Path(folder, "index.json").write_text(json.dumps({"version": 1, "entries": {
            k: entry(k, u) for k, u in (("1" * 32, 7), ("2" * 32, "junk"), ("3" * 32, [1]))}}))

    why, cache, lines, _t = _setup_in_fresh_folder(prepare)
    assert why is None and cache is not None, (why, lines)
    assert set(cache.durations) == {"a" * 32}, "only the entry with a usable time is kept"
    assert set(cache.entries) == {"1" * 32}, "an entry with a bad value is dropped, the others stay"


def test_a_deeply_nested_or_unreadable_cache_file_does_not_stop_the_start():
    def prepare(folder):
        deep = "[" * 200000 + "]" * 200000
        Path(folder, "durations.json").write_text(deep)
        Path(folder, "index.json").write_text(deep)

    why, cache, lines, _t = _setup_in_fresh_folder(prepare)
    assert why is None and cache is not None and cache.durations == {} and cache.entries == {}, (why, lines)


def test_any_error_while_the_cache_starts_turns_playback_off_with_one_logged_reason():
    patcher = mock.patch.object(vod_play.PlayCache, "reconcile", side_effect=RuntimeError("boom"))
    try:
        why, cache, lines, _t = _setup_in_fresh_folder(lambda folder: patcher.start())   # after the folder exists
    finally:
        patcher.stop()
    assert why and "boom" in why and cache is None, (why, cache)
    assert len([l for l in lines if "Browser playback of VODs is off" in l]) == 1, lines


def test_a_linked_work_folder_is_not_ours_nothing_in_it_is_removed_or_written():
    with tempfile.TemporaryDirectory(prefix="vodplay_target_") as target:
        victim = Path(target, "job-1234")
        victim.mkdir()
        Path(victim, "precious.txt").write_text("keep")

        def prepare(folder):
            os.symlink(target, os.path.join(folder, "work"))

        why, cache, lines, _t = _setup_in_fresh_folder(prepare)
        assert why and "work" in why and cache is None, (why, lines)
        assert [n for n in os.listdir(target)] == ["job-1234"] and (victim / "precious.txt").read_text() == "keep"
        # a link put in place after the start is refused by the job's own folder as well
        with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
            cache = vod_play.PlayCache(os.path.join(t, "cache"))
            os.mkdir(cache.root)
            os.symlink(target, cache.work_root())
            try:
                cache.new_work_dir()
                raise AssertionError("a linked work folder was used")
            except ValueError:
                pass
        assert sorted(os.listdir(target)) == ["job-1234"], "a job folder was made through the link"


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except BaseException as e:  # noqa: BLE001
                fails += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e!r}")
    import shutil
    shutil.rmtree(CLIPS, ignore_errors=True)
    print("FAILED" if fails else "all passed")
    sys.exit(1 if fails else 0)
