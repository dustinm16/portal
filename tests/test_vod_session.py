"""Whole-session VOD playback: the HLS playlist and the MPEG-TS segments of one session folder, against a
real loopback SFTP server and real ffmpeg / ffprobe on clips generated here (2 to 4 seconds, 160x120; the
cap test uses clips of about 0.4 MB). Everything is written into temporary folders and removed.

The routes run in a real aiohttp test server on loopback; only the sign-in is replaced (the header X-U
names the member), as in tests/test_vod_play.py.

Run: venv/bin/python tests/test_vod_session.py
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import test_vod_play as tvp  # noqa: E402  (installs the outbound guard and the staging patch)
import vod_play  # noqa: E402
from test_vod_play import ADMIN, OTHER, OWNER, Env, run, with_env  # noqa: E402
from test_vod_guard_stop import children_of_this_process  # noqa: E402

import server  # noqa: E402

CLIPS = tempfile.mkdtemp(prefix="vodsession_clips_")
FOLDER = "Show/2026-02-01"
DURATIONS = [2.0, 3.0, 4.0, 2.5]


def make(path, seconds, seed=0, kbps=None, nodur=False, vcodec="libx264", acodec="aac"):
    cmd = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", f"testsrc=size=160x120:rate=10:duration={seconds}",
           "-f", "lavfi", "-i", f"sine=frequency={440 + seed * 50}:duration={seconds}",
           "-c:v", vcodec, "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-g", "10", "-c:a", acodec, "-b:a", "32k"]
    if kbps:
        cmd += ["-b:v", f"{kbps}k", "-minrate", f"{kbps}k", "-maxrate", f"{kbps}k", "-bufsize", f"{kbps}k",
                "-x264-params", "nal-hrd=cbr"]
    else:
        cmd += ["-crf", "35"]
    if nodur:                       # written to a pipe: the matroska header has no duration
        proc = subprocess.run(cmd + ["-f", "matroska", "pipe:1"], capture_output=True, timeout=60, check=True)
        Path(path).write_bytes(proc.stdout)
    else:
        subprocess.run(cmd + [path], check=True, timeout=60)
    return Path(path).read_bytes()


def clip(seconds, seed=0, **kw):
    path = os.path.join(CLIPS, f"c_{seconds}_{seed}_{kw.get('kbps')}_{kw.get('nodur')}_{kw.get('vcodec')}.mkv")
    if not os.path.exists(path):
        make(path, seconds, seed, **kw)
    return Path(path).read_bytes()


def real_duration(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                       capture_output=True, text=True, timeout=30)
    return float(r.stdout.strip())


def put_session(env, durations=DURATIONS, folder=FOLDER, root="/v", **kw):
    for i, d in enumerate(durations):
        env.put(f"{folder}/chunk_{i:03d}.mkv", clip(d, i, **kw), root=root)


async def playlist(env, folder=FOLDER, user=OWNER, wait=30):
    """GET the playlist, polling while it answers 202; returns the final response."""
    end = time.time() + wait
    while True:
        r = await env.client.get(f"/api/vods/session/{folder}/index.m3u8", headers={"X-U": str(user)})
        if r.status != 202 or time.time() > end:
            return r
        await asyncio.sleep(0.2)


async def segment(env, name, folder=FOLDER, user=OWNER):
    return await env.client.get(f"/api/vods/session/{folder}/{name}", headers={"X-U": str(user)})


async def run_tool(argv, timeout=90):
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, out.decode(), err.decode()


def parse(text):
    lines = text.strip().splitlines()
    items, disc, pending = [], 0, None
    for ln in lines:
        if ln.startswith("#EXTINF:"):
            pending = float(ln[8:].rstrip(","))
        elif ln == "#EXT-X-DISCONTINUITY":
            disc += 1
        elif not ln.startswith("#"):
            items.append((ln, pending))
    return lines, items, disc


def probe_ts(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-f", "mpegts", "-show_entries", "stream=codec_name",
                        "-show_entries", "format=duration", "-of", "json", path],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    return [s["codec_name"] for s in info["streams"]], float(info["format"]["duration"])


# ---------------------------------------------------------------------------
# helpers without a server
# ---------------------------------------------------------------------------

def test_session_urls_and_chunk_order_and_playlist_text():
    f = vod_play.session_from_url
    assert f("Show/2026-02-01/index.m3u8") == ("Show/2026-02-01", "playlist", None)
    assert f("Show/2026-02-01/chunk_012.ts") == ("Show/2026-02-01", "segment", "chunk_012")
    assert f("Show/index.m3u8") == ("Show", "playlist", None)
    for bad in ("index.m3u8", "chunk_001.ts", "/Show/index.m3u8", "Show/../index.m3u8", "Show/.x/index.m3u8",
                "Show\\x/index.m3u8", "Show//index.m3u8", "Show/chunk_001.mp4", "Show/chunk_a.ts",
                "Show/chunk_001.ts/x", "Show/x\x00/index.m3u8", "Show/CHUNK_001.ts", "", "a/" * 20 + "index.m3u8"):
        assert f(bad) is None, bad
    names = [("chunk_999.mkv", 1, 1), ("chunk_1000.mkv", 1, 1), ("chunk_002.mkv", 1, 1), ("chunk_002.mp4", 1, 1),
             ("notes.txt", 1, 1), ("chunk_1.MKV", 1, 1)]
    assert [c[1] for c in vod_play.session_chunks(names)] == ["chunk_002.mkv", "chunk_999.mkv", "chunk_1000.mkv"]
    text = vod_play.playlist_text([("chunk_000.ts", 2.0), ("chunk_001.ts", 3.0412)], True)
    lines, items, disc = parse(text)
    assert lines[0] == "#EXTM3U" and "#EXT-X-PLAYLIST-TYPE:VOD" in lines and lines[-1] == "#EXT-X-ENDLIST"
    assert "#EXT-X-TARGETDURATION:4" in lines and disc == 1 and items == [("chunk_000.ts", 2.0), ("chunk_001.ts", 3.041)]
    live = vod_play.playlist_text([("chunk_000.ts", 2.0)], False)
    assert "#EXT-X-PLAYLIST-TYPE:EVENT" in live and "ENDLIST" not in live and "DISCONTINUITY" not in live


def test_ts_limit_holds_for_a_tiny_clip_and_a_five_minute_chunk_under_the_default_cap():
    # measured: a 3 second 45 KB chunk became a 62 KB segment (the per-second term, not the percentage)
    assert vod_play.output_limit(45092, "ts", 3.0) > 62040
    five_min = 225 * 1024 * 1024
    assert vod_play.job_reserve(five_min, "ts", 300.0) < vod_play.cache_cap_bytes(None)
    assert vod_play.output_limit(1000, "ts", None) > vod_play.output_limit(1000, "ts", 3.0)   # unknown: generous
    # the MP4 rule and key did not change
    assert vod_play.output_limit(1000) == 1000 + 200 + vod_play.OUTPUT_SLACK
    assert vod_play.entry_key(1, "i", "a/b.mkv", 5, 6) == vod_play.entry_key(1, "i", "a/b.mkv", 5, 6, "mp4")
    assert len({vod_play.entry_key(1, "i", "a/b.mkv", 5, 6, k) for k in ("mp4", "ts", "dur")}) == 3
    argv = vod_play.remux_argv("/x/src.mkv", "/x/out.ts", 1000, "ts")
    assert argv[argv.index("-f", argv.index("-c") + 2) + 1] == "mpegts" and "-movflags" not in argv
    assert "-protocol_whitelist" in argv and argv[argv.index("-protocol_whitelist") + 1] == "file"


def test_durations_are_kept_beside_the_index_purged_with_their_chunk_and_owner_and_survive_a_restart():
    with tempfile.TemporaryDirectory(prefix="vodsession_cache_") as t:
        root = os.path.join(t, "cache")
        vod_play.prepare_dir(root)
        cache = vod_play.PlayCache(root)
        cache.reconcile()
        cache.set_duration(1, "idA", "S/d/chunk_000.mkv", 10, 20, 3.5)
        cache.set_duration(1, "idA", "S/d/chunk_001.mkv", 11, 21, 4.5, False, "video codec vp9")
        cache.set_duration(2, "idB", "S/d/chunk_000.mkv", 10, 20, 9.0)
        cache.set_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22, 3.6)       # a new version replaces the old
        assert cache.get_duration(1, "idA", "S/d/chunk_000.mkv", 10, 20) is None
        assert cache.get_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22)["duration"] == 3.6
        assert cache.get_duration(1, "idA", "S/d/chunk_001.mkv", 11, 21)["playable"] is False
        assert [d["path"] for d in cache.session_durations(1, "idA", "S/d")] == ["S/d/chunk_000.mkv", "S/d/chunk_001.mkv"]
        assert cache.session_durations(1, "idA", "S") == []
        again = vod_play.PlayCache(root)
        stats = again.reconcile()
        assert again.get_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22)["duration"] == 3.6
        assert stats["strays"] == 0 and os.path.exists(os.path.join(root, vod_play.DURATIONS_NAME))
        assert again.owners() == {1: {"idA"}, 2: {"idB"}}
        assert oct(os.stat(os.path.join(root, vod_play.DURATIONS_NAME)).st_mode & 0o777) == "0o600"
        again.purge(owner=1, path="S/d/chunk_001.mkv")
        assert again.get_duration(1, "idA", "S/d/chunk_001.mkv", 11, 21) is None
        assert again.get_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22) is not None
        again.purge(owner=1, ident_not="idA")
        assert again.get_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22) is not None
        again.purge(owner=1)
        assert again.get_duration(1, "idA", "S/d/chunk_000.mkv", 12, 22) is None
        assert again.get_duration(2, "idB", "S/d/chunk_000.mkv", 10, 20) is not None
        # reserving ahead never evicts
        again.entries["k"] = {"file": "k.ts", "size": 90, "used": 1.0, "owner": 2, "ident": "idB", "path": "p"}
        assert again.try_reserve_free(10, 100) and not again.try_reserve_free(11, 100) and "k" in again.entries


def test_a_ts_entry_survives_reconcile_and_an_unknown_kind_is_dropped():
    with tempfile.TemporaryDirectory(prefix="vodsession_cache_") as t:
        root = os.path.join(t, "cache")
        vod_play.prepare_dir(root)
        cache = vod_play.PlayCache(root)
        cache.reconcile()
        work = cache.new_work_dir()
        out = os.path.join(work, "out.ts")
        Path(out).write_bytes(b"x" * 100)
        key = vod_play.entry_key(1, "i", "a/chunk_000.mkv", 5, 6, "ts")
        assert cache.add(key, out, {"owner": 1, "ident": "i", "path": "a/chunk_000.mkv", "rsize": 5, "rmtime": 6,
                                    "kind": "ts"}, 0)
        assert os.path.exists(os.path.join(root, key + ".ts"))
        again = vod_play.PlayCache(root)
        stats = again.reconcile()
        assert stats["kept"] == 1 and again.get(key) == os.path.join(root, key + ".ts")
        idx = json.loads(Path(root, "index.json").read_text())
        idx["entries"][key]["kind"] = "exe"
        Path(root, "index.json").write_text(json.dumps(idx))
        third = vod_play.PlayCache(root)
        assert third.reconcile()["dropped"] == 1 and not os.path.exists(os.path.join(root, key + ".ts"))


# ---------------------------------------------------------------------------
# the routes
# ---------------------------------------------------------------------------

@with_env
async def test_playlist_lists_the_chunks_in_order_with_measured_durations_and_pulls_no_chunk(env):
    put_session(env)
    pulls = []
    real_pull = server._vod_play_pull

    async def spy_pull(*a, **k):
        pulls.append(a[2])
        return await real_pull(*a, **k)

    with mock.patch.object(server, "_vod_play_pull", spy_pull):
        first = await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8", headers={"X-U": str(OWNER)})
        assert first.status == 202 and first.headers.get("Retry-After")
        body = await first.json()
        assert body["state"] == "preparing" and body["total"] == 4
        r = await playlist(env)
    assert r.status == 200, await r.text()
    assert r.headers["Content-Type"].startswith("application/vnd.apple.mpegurl")
    assert "no-store" in r.headers["Cache-Control"]
    lines, items, disc = parse(await r.text())
    assert lines[0] == "#EXTM3U" and "#EXT-X-PLAYLIST-TYPE:VOD" in lines and lines[-1] == "#EXT-X-ENDLIST"
    assert [n for n, _d in items] == ["chunk_000.ts", "chunk_001.ts", "chunk_002.ts", "chunk_003.ts"]
    assert disc == 3
    for (n, d), want in zip(items, DURATIONS):
        assert abs(d - want) < 0.25, (n, d, want)             # measured, never a flat 300 seconds
        assert "/" not in n and "?" not in n and "token" not in n.lower()      # relative, no credential
    assert max(d for _n, d in items) < 6 and f"#EXT-X-TARGETDURATION:{int(max(d for _n, d in items)) + 1}" in lines
    assert pulls == [], "a duration must come from the first bytes, not from pulling the chunks"
    assert env.ffmpegs() == 0 and env.cache.entries == {}
    # the second request needs nothing from anywhere but the folder listing
    before = list(env.spawned)
    again = await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8", headers={"X-U": str(OWNER)})
    assert again.status == 200 and env.spawned == before


@with_env
async def test_every_segment_is_valid_mpegts_and_ffmpeg_reads_one_timeline_through_the_server(env):
    put_session(env)
    assert (await playlist(env)).status == 200
    got = 0.0
    for i, want in enumerate(DURATIONS):
        r = await segment(env, f"chunk_{i:03d}.ts")
        assert r.status == 200 and r.headers["Content-Type"] == "video/mp2t"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        out = os.path.join(env.t, f"seg{i}.ts")
        Path(out).write_bytes(await r.read())
        codecs, dur = probe_ts(out)
        assert codecs == ["h264", "aac"] and abs(dur - want) < 0.3, (i, codecs, dur)
        got += dur
    # ffprobe and ffmpeg read the playlist through the real HTTP server: one timeline
    url = f"http://127.0.0.1:{env.client.server.port}/api/vods/session/{FOLDER}/index.m3u8"
    hdr = ["-headers", f"X-U: {OWNER}\r\n", "-protocol_whitelist", "http,tcp,file,crypto"]
    # (run as child processes the loop awaits: the test server shares this loop)
    code, out_text, err = await run_tool(["ffprobe", "-v", "error"] + hdr +
                                         ["-show_entries", "format=duration", "-of", "csv=p=0", url])
    assert code == 0, err
    assert abs(float(out_text.strip()) - sum(DURATIONS)) < 0.5, out_text
    out = os.path.join(env.t, "all.mkv")
    code, _o, err = await run_tool(["ffmpeg", "-v", "error", "-y"] + hdr + ["-i", url, "-c", "copy", "-f", "matroska", out])
    assert code == 0, err
    assert abs(real_duration(out) - sum(DURATIONS)) < 0.6, (real_duration(out), sum(DURATIONS))


@with_env
async def test_another_member_and_an_administrator_get_404_for_the_playlist_and_a_segment(env):
    put_session(env)
    put_session(env, durations=[2.0], root="/w")            # the other member has a session of the same name
    assert (await playlist(env)).status == 200
    assert (await segment(env, "chunk_000.ts")).status == 200
    while [j for j in server._vod_play_jobs.values() if j["finished"] is None]:     # the owner's read-ahead
        await asyncio.sleep(0.1)
    spawned = list(env.spawned)
    r = await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8", headers={"X-U": str(ADMIN)})
    assert r.status == 404
    assert (await segment(env, "chunk_000.ts", user=ADMIN)).status == 404
    # another member sees only their own storage: chunk_001 is not there
    assert (await segment(env, "chunk_001.ts", user=OTHER)).status == 404
    assert (await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8")).status == 401
    assert (await env.client.get(f"/api/vods/session/{FOLDER}/chunk_000.ts")).status == 401
    assert env.spawned == spawned, "the refusals started no tool at all"
    # chunk_000 exists in the other member's own storage: they get their own file, never the owner's entry
    mine = await segment(env, "chunk_000.ts", user=OTHER)
    assert mine.status == 200
    other = await playlist(env, user=OTHER)
    assert other.status == 200 and len(parse(await other.text())[1]) == 1
    owners = {e["owner"]: e["path"] for e in env.cache.entries.values() if e["kind"] == "ts" and e["owner"] == OTHER}
    assert owners == {OTHER: f"{FOLDER}/chunk_000.mkv"}
    assert len({e["file"] for e in env.cache.entries.values() if e["kind"] == "ts"
                and e["path"].endswith("chunk_000.mkv")}) == 2


@with_env
async def test_unlisted_folders_and_odd_names_are_404_and_start_nothing(env):
    put_session(env)
    for url in (f"/api/vods/session/Nope/2026/index.m3u8", f"/api/vods/session/{FOLDER}/chunk_009.ts",
                f"/api/vods/session/{FOLDER}/chunk_0.ts", "/api/vods/session/index.m3u8",
                f"/api/vods/session/%2e%2e/{FOLDER}/index.m3u8", f"/api/vods/session/Show/%2e%2e/index.m3u8",
                f"/api/vods/session/{FOLDER}/chunk_000.mp4", f"/api/vods/session/.hidden/x/index.m3u8"):
        r = await env.client.get(url, headers={"X-U": str(OWNER)})
        assert r.status == 404, (url, r.status)
    assert env.spawned == [] and env.cache.entries == {}


@with_env(settings={"vod_play_cache_mb": "50"})
async def test_the_cache_stays_under_a_cap_that_holds_two_segments_while_all_four_are_played_in_order(env):
    sizes = []
    for i, d in enumerate([3, 3, 3, 3]):
        sizes.append(len(clip(d, i, kbps=1200)))
        env.put(f"{FOLDER}/chunk_{i:03d}.mkv", clip(d, i, kbps=1200))
    top = max(sizes)
    ts_est = int(top * 1.1) + 3 * vod_play.TS_BYTES_PER_SECOND                 # what a segment takes, about
    cap = vod_play.job_reserve(top, "ts", 3.0) + 100 * 1024
    assert cap < 3 * ts_est and cap >= vod_play.job_reserve(top, "ts", 3.0)    # two segments fit, three do not
    env.db.settings["vod_play_cache_mb"] = str(cap / 1024 / 1024)
    pl = await playlist(env)
    assert pl.status == 200
    peaks = []
    real_add = env.cache.add

    def watch(*a, **k):
        r = real_add(*a, **k)
        peaks.append(env.cache.disk_bytes())
        return r

    with mock.patch.object(env.cache, "add", watch):
        for i in range(4):
            r = await segment(env, f"chunk_{i:03d}.ts")
            assert r.status == 200, (i, await r.text())
            Path(env.t, f"s{i}.ts").write_bytes(await r.read())
            assert probe_ts(os.path.join(env.t, f"s{i}.ts"))[0] == ["h264", "aac"]
            assert env.cache.used_bytes() <= cap, (i, env.cache.used_bytes(), cap)      # the cap counts stored copies
    assert max(peaks) <= cap
    assert sum(os.path.getsize(os.path.join(env.t, f"s{i}.ts")) for i in range(4)) > cap, "the cap must really bind"
    ts = [e for e in env.cache.entries.values() if e["kind"] == "ts"]
    assert 1 <= len(ts) <= 2, len(ts)
    assert [e["path"] for e in ts][-1].endswith("chunk_003.mkv")
    assert env.ffmpegs() >= 4
    # the remembered lengths outlive the evicted segments: the playlist is still served without any work
    n = len(env.spawned)
    assert (await playlist(env)).status == 200 and len(env.spawned) == n
    assert not [f for f in os.listdir(env.cache.root) if f.startswith("work")] or \
        os.listdir(os.path.join(env.cache.root, "work")) == []


@with_env
async def test_the_next_segment_is_prepared_ahead_when_it_fits(env):
    put_session(env)
    assert (await playlist(env)).status == 200
    assert (await segment(env, "chunk_000.ts")).status == 200
    for _ in range(100):
        if any(e["path"].endswith("chunk_001.mkv") and e["kind"] == "ts" for e in env.cache.entries.values()):
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError("the next segment was not prepared ahead")
    n = env.ffmpegs()
    r = await segment(env, "chunk_001.ts")            # already there: no new conversion for it
    assert r.status == 200 and env.ffmpegs() <= n + 2


@with_env(fast_wait=0.0)
async def test_a_segment_that_is_not_ready_in_time_answers_503_with_retry_after_never_202(env):
    put_session(env, durations=[2.0, 3.0])
    assert (await playlist(env)).status == 200
    real_pull = server._vod_play_pull

    async def slow_pull(*a, **k):
        await asyncio.sleep(0.6)
        return await real_pull(*a, **k)

    with mock.patch.object(server, "VOD_SESSION_SEG_WAIT", 0.01), mock.patch.object(server, "_vod_play_pull", slow_pull):
        r = await segment(env, "chunk_001.ts")
        assert r.status == 503 and r.headers.get("Retry-After")
        assert (await r.json())["state"] == "preparing"
        got = None
        for _ in range(100):
            await asyncio.sleep(0.2)
            r = await segment(env, "chunk_001.ts")
            if r.status == 200:
                got = r
                break
            assert r.status == 503
        assert got is not None
    assert (await got.read())[:1] == b"G"              # an MPEG-TS packet starts with 0x47


@with_env
async def test_a_header_without_duration_is_measured_by_converting_that_chunk_only(env):
    env.put(f"{FOLDER}/chunk_000.mkv", clip(2.0, 0))
    env.put(f"{FOLDER}/chunk_001.mkv", clip(3.0, 1, nodur=True))
    pulls = []
    real_pull = server._vod_play_pull

    async def spy_pull(*a, **k):
        pulls.append(a[2])
        return await real_pull(*a, **k)

    with mock.patch.object(server, "_vod_play_pull", spy_pull):
        r = await playlist(env)
    assert r.status == 200, await r.text()
    items = parse(await r.text())[1]
    assert abs(items[0][1] - 2.0) < 0.25 and abs(items[1][1] - 3.0) < 0.3, items
    assert pulls == [f"{FOLDER}/chunk_001.mkv"]


@with_env
async def test_a_chunk_the_browser_cannot_play_makes_the_session_download_only(env):
    env.put(f"{FOLDER}/chunk_000.mkv", clip(2.0, 0))
    env.put(f"{FOLDER}/chunk_001.mkv", clip(2.0, 1, vcodec="mpeg4"))
    r = await playlist(env)
    assert r.status == 415 and (await r.json())["state"] == "unplayable"
    s = await segment(env, "chunk_001.ts")
    assert s.status == 415
    assert (await segment(env, "chunk_000.ts")).status == 200          # the playable chunks still play one by one


@with_env
async def test_the_newest_chunk_of_a_live_session_is_left_out_and_the_playlist_is_not_a_finished_vod(env):
    put_session(env, durations=[2.0, 3.0, 2.0])
    server.active_recordings[7] = {"remote_session_dir": f"/v/{FOLDER}", "user_id": OWNER}
    r = await playlist(env)
    assert r.status == 200
    lines, items, disc = parse(await r.text())
    assert [n for n, _d in items] == ["chunk_000.ts", "chunk_001.ts"]
    assert "#EXT-X-PLAYLIST-TYPE:EVENT" in lines and "#EXT-X-ENDLIST" not in lines
    n = len(env.spawned)
    s = await segment(env, "chunk_002.ts")
    assert s.status == 409 and len(env.spawned) == n
    assert (await segment(env, "chunk_001.ts")).status == 200
    server.active_recordings.clear()
    assert (await segment(env, "chunk_002.ts")).status == 200          # the stream has ended: it plays and is cached
    server.active_recordings[7] = {"remote_session_dir": f"/v/{FOLDER}", "user_id": OWNER}
    assert (await segment(env, "chunk_002.ts")).status == 409, "left out even when an earlier copy is cached"
    server.active_recordings.clear()
    done = await playlist(env)
    lines, items, _ = parse(await done.text())
    assert len(items) == 3 and "#EXT-X-ENDLIST" in lines and "#EXT-X-PLAYLIST-TYPE:VOD" in lines
    # a session with one chunk that is live has nothing to offer yet
    env.put("Solo/2026-02-02/chunk_000.mkv", clip(2.0, 0))
    server.active_recordings[8] = {"remote_session_dir": "/v/Solo/2026-02-02", "user_id": OWNER}
    r = await env.client.get("/api/vods/session/Solo/2026-02-02/index.m3u8", headers={"X-U": str(OWNER)})
    assert r.status == 409 and (await r.json())["state"] == "live"


@with_env
async def test_the_recorder_stores_a_duration_at_upload_time_so_no_probe_is_needed(env):
    local = os.path.join(env.t, "chunk_000.mkv")
    Path(local).write_bytes(clip(3.0, 0))
    env.put(f"{FOLDER}/chunk_000.mkv", clip(3.0, 0))
    conn, sftp, error = await server._connect_vod_sftp(OWNER)
    assert not error
    try:
        await server._vod_record_chunk_duration(OWNER, sftp, f"/v/{FOLDER}/chunk_000.mkv", local)
        await server._vod_record_chunk_duration(OWNER, sftp, "/elsewhere/x/chunk_000.mkv", local)   # not ours: ignored
        await server._vod_record_chunk_duration(OWNER, sftp, "/v/chunk_000.mkv", local)              # no session folder
    finally:
        conn.close()
    assert len(env.cache.durations) == 1
    spawned = len(env.spawned)
    r = await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8", headers={"X-U": str(OWNER)})
    assert r.status == 200, "all durations known: offered at once, without a preparing state"
    assert abs(parse(await r.text())[1][0][1] - 3.0) < 0.25 and len(env.spawned) == spawned
    # a broken cache or ffprobe never fails the upload path
    with mock.patch.object(server, "_vod_play_cache", None):
        await server._vod_record_chunk_duration(OWNER, None, f"/v/{FOLDER}/chunk_000.mkv", local)


@with_env
async def test_deleting_a_chunk_forgets_its_duration_and_the_playlist_follows_the_folder(env):
    put_session(env, durations=[2.0, 3.0])
    assert (await playlist(env)).status == 200
    assert len(env.cache.durations) == 2
    env.cache.purge(owner=OWNER, path=f"{FOLDER}/chunk_000.mkv")
    os.unlink(env.remote.path(f"/v/{FOLDER}/chunk_000.mkv"))
    r = await playlist(env)
    assert r.status == 200 and [n for n, _d in parse(await r.text())[1]] == ["chunk_001.ts"]


@with_env
async def test_playback_off_and_a_stream_key_are_refused_like_the_single_chunk_route(env):
    put_session(env)
    env.db.settings["vod_play_cache_mb"] = "0"
    r = await env.client.get(f"/api/vods/session/{FOLDER}/index.m3u8", headers={"X-U": str(OWNER)})
    assert r.status == 503 and (await r.json())["code"] == "playback_off"
    assert (await segment(env, "chunk_000.ts")).status == 503


@with_env
async def test_a_session_segment_does_not_make_the_single_chunk_status_ready(env):
    put_session(env, durations=[2.0, 3.0])
    assert (await playlist(env)).status == 200
    assert (await segment(env, "chunk_000.ts")).status == 200
    while [j for j in server._vod_play_jobs.values() if j["finished"] is None]:
        await asyncio.sleep(0.1)
    server._vod_play_jobs.clear()
    assert any(e["kind"] == "ts" and e["path"] == f"{FOLDER}/chunk_000.mkv" for e in env.cache.entries.values())
    code, body = await env.status(f"{FOLDER}/chunk_000.mkv")
    assert body["state"] == "idle", body                 # a TS segment is not an MP4 a <video> could play
    assert (await env.play(f"{FOLDER}/chunk_000.mkv")).status == 200
    assert (await env.status(f"{FOLDER}/chunk_000.mkv"))[1]["state"] == "ready"


@with_env
async def test_too_many_chunks_being_prepared_answers_503_for_a_segment_not_429(env):
    put_session(env, durations=[2.0, 3.0])
    assert (await playlist(env)).status == 200
    with mock.patch.object(server, "VOD_PLAY_MAX_PER_USER", 0):
        r = await segment(env, "chunk_001.ts")
        assert r.status == 503 and r.headers.get("Retry-After") and (await r.json())["state"] == "busy"
        single = await env.play(f"{FOLDER}/chunk_001.mkv")
        assert single.status == 429                      # the single-chunk route keeps its answer


@with_env
async def test_the_wait_for_a_segment_is_counted_from_the_arrival_of_the_request(env):
    put_session(env, durations=[2.0, 3.0])
    assert (await playlist(env)).status == 200
    real = server._vod_play_remote_stat

    async def slow(*a, **k):
        await asyncio.sleep(1.2)                         # a slow storage lookup eats into the budget
        return await real(*a, **k)

    waits = []
    real_obtain = server._vod_play_obtain

    async def spy(*a, **k):
        waits.append(a[7])
        return await real_obtain(*a, **k)

    with mock.patch.object(server, "VOD_SESSION_SEG_WAIT", 1.5), mock.patch.object(server, "_vod_play_remote_stat", slow), \
            mock.patch.object(server, "_vod_play_obtain", spy):
        t0 = time.time()
        r = await segment(env, "chunk_001.ts")
        took = time.time() - t0
    assert waits and waits[0] <= 0.35, waits               # 1.5 s budget minus the 1.2 s lookup, never the full 1.5 s
    assert r.status in (200, 503) and took < 4, (r.status, took)


def test_the_uploader_removes_a_delivered_chunk_even_when_measuring_it_is_cancelled():
    src = (ROOT / "server.py").read_text()
    for marker in ("await _vod_record_chunk_duration(user_id, sftp, remote_path, str(local_path))",
                   "await _vod_record_chunk_duration(user_id, sftp, final, local)"):
        at = src.index(marker)
        assert "finally:" in src[at:at + 300] and ("unlink()" in src[at:at + 400] or "os.unlink(local)" in src[at:at + 400])


def test_the_session_route_uses_the_same_gate_and_is_registered():
    src = (ROOT / "server.py").read_text()
    assert 'add_get("/api/vods/session/{name:.+}", http_play_session)' in src
    start = src.index("async def http_play_session(")
    body = src[start:src.index("\nasync def ", start + 10)]
    assert "_stream_user_auth(" in body and "authenticate_request(" not in body
    # one job path for both outputs, not a second copy
    assert src.count("asyncio.create_task(_vod_play_job(") == 1
    assert src.count("async def _vod_play_pull(") == 1


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
    shutil.rmtree(tvp.CLIPS, ignore_errors=True)
    print("FAILED" if fails else "all passed")
    sys.exit(1 if fails else 0)
