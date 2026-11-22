"""Single-chunk playback, second pass: how long a request is held, what a storage failure answers, a chunk
deleted while it is prepared, what the cache cap counts, and a refusal that must not be remembered.

Same harness as tests/test_vod_play.py (real loopback SFTP, real ffmpeg on 3 second clips).

Run: venv/bin/python tests/test_vod_play_fixb.py
"""
import asyncio
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_vod_play as tvp  # noqa: E402  (installs the outbound guard and the staging patch)
import vod_play  # noqa: E402
from test_vod_play import ADMIN, NAME, OTHER, OWNER, SESSION, Db, Env, clip, with_env  # noqa: E402

import asyncssh  # noqa: E402
import server  # noqa: E402


class FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeSftp:
    """An SFTP client whose stat fails the way the test says."""

    def __init__(self, exc=None, hang=False):
        self.exc, self.hang = exc, hang

    async def stat(self, path):
        if self.hang:
            await asyncio.sleep(3600)
        raise self.exc


def fake_connect(sftp, dials=None):
    async def connect(uid):
        if dials is not None:
            dials.append(uid)
        return FakeConn(), sftp, None
    return connect


# -- item 2: a storage failure is 502, only "no such file" is 404 -----------------------------------

@with_env
async def test_a_stat_that_times_out_or_fails_is_502_and_only_a_missing_file_is_404(env):
    env.put(NAME, clip())
    cases = [(asyncio.TimeoutError(), 502), (OSError("boom"), 502), (asyncssh.SFTPFailure("no"), 502),
             (asyncssh.SFTPPermissionDenied("no"), 502), (asyncssh.ConnectionLost("gone"), 502),
             (asyncssh.SFTPNoSuchFile("no"), 404), (asyncssh.SFTPNoSuchPath("no"), 404)]
    for exc, want in cases:
        with mock.patch.object(server, "_connect_vod_sftp", fake_connect(FakeSftp(exc))):
            r = await env.play()
        assert r.status == want, (exc, r.status)
        body = await r.json()
        if want == 502:
            assert body["error"] == server._VOD_PLAY_STORAGE_DOWN
        else:
            assert body["error"] == "VOD not found"
        assert "private" in r.headers["Cache-Control"].lower()
    assert env.spawned == []
    # a hanging stat ends at the per-call budget and is 502 as well
    with mock.patch.object(server, "VOD_SFTP_META_TIMEOUT", 0.2), \
            mock.patch.object(server, "_connect_vod_sftp", fake_connect(FakeSftp(hang=True))):
        r = await asyncio.wait_for(env.play(), 10)
    assert r.status == 502


class DeadOwnerDb(Db):
    """The owner's storage points at a closed port; the other member's storage is the working one."""

    async def get_vod_storage(self, uid):
        s = await super().get_vod_storage(uid)
        if uid == OWNER and s:
            s = dict(s, port=1)
        return s


@with_env
async def test_the_502_belongs_to_the_callers_own_storage_and_tells_another_member_nothing(env):
    env.put(NAME, clip())
    env.db.__class__ = DeadOwnerDb
    dials = []
    real = server._connect_vod_sftp

    async def spy(uid):
        dials.append(uid)
        return await real(uid)

    with mock.patch.object(server, "_connect_vod_sftp", spy):
        # the owner's own storage is down: 502 with a fixed text that names no host, port, path or exception
        r = await env.play()
        assert r.status == 502
        text = await r.text()
        for leak in ("127.0.0.1", "chunk_000", "Show", "refused", "Errno", str(env.remote.port)):
            assert leak not in text, (leak, text)
        assert dials == [OWNER]
        # another member asking for the owner's path is answered from their own storage only (404: it is
        # not there), and the owner's dead storage is never touched
        dials.clear()
        r = await env.play(user=OTHER)
        assert r.status == 404 and (await r.json())["error"] == "VOD not found"
        assert dials == [OTHER]
        # an administrator without VOD storage: 404 before any remote call
        dials.clear()
        r = await env.play(user=ADMIN)
        assert r.status == 404 and dials == []
        st, _ = await env.status(user=ADMIN)
        assert st == 404 and dials == []
    assert env.spawned == []


# -- item 1: one connection, one deadline ------------------------------------------------------------

def dial_spy(dials):
    real = server._connect_vod_sftp

    async def spy(uid):
        dials.append(uid)
        return await real(uid)
    return spy


@with_env(fast_wait=0.1)
async def test_the_stat_and_the_live_check_share_one_connection(env):
    env.put(f"{SESSION}/chunk_000.mkv", clip("aac", 0))
    env.put(f"{SESSION}/chunk_001.mkv", clip("aac", 1))
    dials = []

    async def slow_job(job, storage, size, mtime):          # the job's own pull is not what is counted here
        try:
            await asyncio.sleep(30)
        finally:
            job["finished"] = time.monotonic()
            job["done"].set()

    with mock.patch.object(server, "_connect_vod_sftp", dial_spy(dials)), \
            mock.patch.object(server, "_vod_remote_dirs_in_use", lambda: {"*"}), \
            mock.patch.object(server, "_vod_play_job", slow_job):
        r = await env.play(f"{SESSION}/chunk_000.mkv")      # an older chunk of a folder being recorded: asks the folder
    assert r.status == 202, await r.text()
    assert dials == [OWNER], dials                           # one dial for the size and the folder listing


@with_env(ttl=15.0)
async def test_continuation_ranges_open_no_connection(env):
    env.put(NAME, clip())
    assert (await env.play()).status == 200
    dials = []
    with mock.patch.object(server, "_connect_vod_sftp", dial_spy(dials)):
        r = await env.play(Range="bytes=10-")
        assert r.status == 206
    assert dials == []


@with_env
async def test_a_hanging_storage_ends_the_request_at_the_deadline_with_a_retry_hint(env):
    env.put(NAME, clip())

    async def hang(uid):
        await asyncio.sleep(3600)

    t0 = time.time()
    with mock.patch.object(server, "VOD_PLAY_REQUEST_DEADLINE", 1.0), \
            mock.patch.object(server, "_connect_vod_sftp", hang):
        r = await asyncio.wait_for(env.play(), 8)
    assert r.status == 503 and time.time() - t0 < 6
    assert r.headers.get("Retry-After") and "private" in r.headers["Cache-Control"].lower()
    assert env.spawned == [] and env.cache.reserved == 0
    assert not server._vod_play_jobs


def test_the_sftp_subsystem_start_has_a_timeout_and_the_connection_is_closed():
    class Conn:
        closed = False

        async def start_sftp_client(self):
            await asyncio.sleep(3600)

        def close(self):
            self.closed = True

    conn = Conn()

    async def fake_connect(addrs, opts, **kw):
        return conn, None

    storage = {"host": "h", "port": 22, "username": "u", "auth_method": "password",
               "remote_path": "/v", "config": {"password": "x"}}

    async def go():
        with mock.patch.object(server.hostkeys, "connect_verified", fake_connect), \
                mock.patch.object(server, "VOD_SFTP_START_TIMEOUT", 0.2):
            return await asyncio.wait_for(server._vod_dial(1, storage, ["127.0.0.1"]), 5)

    c, sftp, error = asyncio.run(go())
    assert c is None and sftp is None and error == "Connection timed out" and conn.closed

# -- item 6: identical storage configurations never share a cached copy -----------------------------

class SameStorageDb(Db):
    """Two members whose VOD storage settings are identical (same host, port, user, folder)."""

    async def get_vod_storage(self, uid):
        return None if uid == ADMIN else await Db.get_vod_storage(self, OWNER)


@with_env
async def test_identical_storage_configurations_never_share_a_cached_copy(env):
    env.db.__class__ = SameStorageDb
    env.put(NAME, clip(), mtime=1700000000)
    a = vod_play.storage_ident(await env.db.get_vod_storage(OWNER))
    assert a == vod_play.storage_ident(await env.db.get_vod_storage(OTHER))
    assert (await env.play()).status == 200
    first = env.ffmpegs()
    assert first >= 1 and {e["owner"] for e in env.cache.entries.values()} == {OWNER}
    # the other member asks for the same path on the same storage: the owner's copy is not offered
    r = await env.play(user=OTHER)
    assert r.status == 200
    assert env.ffmpegs() > first, "the other member was served from the first member's cached copy"
    assert sorted(e["owner"] for e in env.cache.entries.values()) == [OWNER, OTHER]
    assert len({e["file"] for e in env.cache.entries.values()}) == 2
    # the keys differ only by the owner
    assert vod_play.entry_key(OWNER, a, NAME, 1, 1) != vod_play.entry_key(OTHER, a, NAME, 1, 1)
    # purging one member's copies leaves the other's alone
    env.cache.purge(owner=OTHER)
    assert {e["owner"] for e in env.cache.entries.values()} == {OWNER}
    spawned = env.ffmpegs()
    assert (await env.play()).status == 200 and env.ffmpegs() == spawned

# -- item 3: a chunk deleted (or an account removed) while it is prepared leaves nothing in the cache ---

class Gate:
    """Holds the remux of a job until the test lets it go."""

    def __init__(self):
        self.reached, self.release = asyncio.Event(), asyncio.Event()
        self.real = server._vod_play_run_tool

    async def run(self, argv, *a, **k):
        if argv[0] == "ffmpeg":
            self.reached.set()
            await self.release.wait()
        return await self.real(argv, *a, **k)


async def delete_chunk(name, user=OWNER):
    from aiohttp.test_utils import make_mocked_request

    async def auth(request):
        return SimpleNamespace(user_id=user), None

    req = make_mocked_request("DELETE", "/api/vods/x", match_info={"filename": name})
    with mock.patch.object(server, "_stream_user_auth", auth):
        return await server.http_delete_vod(req)


def nothing_left(env, name):
    assert env.cache.entries == {}, env.cache.entries
    assert [f for f in os.listdir(env.cache.root) if f.endswith((".mp4", ".ts"))] == []
    assert not [k for k in server._vod_play_jobs if k[1] == name]
    assert env.cache.reserved == 0
    work = env.cache.work_root()
    assert not os.path.isdir(work) or os.listdir(work) == []


@with_env(fast_wait=0)
async def test_deleting_a_chunk_while_it_is_prepared_cancels_the_job_and_leaves_no_copy(env):
    env.put(NAME, clip())
    gate = Gate()
    with mock.patch.object(server, "_vod_play_run_tool", gate.run):
        assert (await env.play()).status == 202
        await asyncio.wait_for(gate.reached.wait(), 20)
        r = await delete_chunk(NAME)
        assert r.status == 200
        assert not os.path.exists(env.remote.path("/v/" + NAME))
        gate.release.set()
        await asyncio.sleep(0.5)
    nothing_left(env, NAME)
    st, body = await env.status()
    assert st == 404 or body["state"] == "idle"


@with_env(fast_wait=0)
async def test_a_finishing_job_that_is_no_longer_in_the_table_adds_nothing(env):
    env.put(NAME, clip())
    gate = Gate()
    with mock.patch.object(server, "_vod_play_run_tool", gate.run):
        assert (await env.play()).status == 202
        await asyncio.wait_for(gate.reached.wait(), 20)
        (job,) = server._vod_play_jobs.values()
        server._vod_play_jobs.clear()               # dropped without being cancelled: only the re-check can stop it
        gate.release.set()
        await asyncio.wait_for(job["done"].wait(), 30)
    assert job["state"] == "failed"
    nothing_left(env, NAME)


@with_env(fast_wait=0)
async def test_removing_the_account_while_a_chunk_is_prepared_leaves_no_copy(env):
    env.put(NAME, clip())
    gate = Gate()
    with mock.patch.object(server, "_vod_play_run_tool", gate.run):
        assert (await env.play()).status == 202
        await asyncio.wait_for(gate.reached.wait(), 20)
        tasks = server._vod_play_purge(owner=OWNER)
        assert tasks
        gate.release.set()
        await asyncio.wait(tasks, timeout=10)
    nothing_left(env, NAME)


@with_env
async def test_deleting_a_chunk_removes_its_mp4_its_segments_and_remembered_lengths_and_only_its_own(env):
    other_name = f"{SESSION}/chunk_001.mkv"
    env.put(NAME, clip("aac", 0))
    env.put(other_name, clip("aac", 1))
    assert (await env.play()).status == 200 and (await env.play(other_name)).status == 200
    ident = vod_play.storage_ident(await env.db.get_vod_storage(OWNER))
    ts_key = vod_play.entry_key(OWNER, ident, NAME, 5, 5, "ts")
    env.cache.entries[ts_key] = {"owner": OWNER, "ident": ident, "path": NAME, "rsize": 5, "rmtime": 5,
                                 "kind": "ts", "file": ts_key + ".ts", "size": 3, "used": time.time()}
    Path(env.cache.root, ts_key + ".ts").write_bytes(b"abc")
    env.cache.set_duration(OWNER, ident, NAME, 5, 5, 3.0)
    assert (await delete_chunk(NAME)).status == 200
    assert {e["path"] for e in env.cache.entries.values()} == {other_name}
    assert not os.path.exists(os.path.join(env.cache.root, ts_key + ".ts"))
    assert not [d for d in env.cache.durations.values() if d["path"] == NAME]

# -- item 4: the cap counts stored copies, not working space -----------------------------------------

@with_env
async def test_a_chunk_whose_working_space_exceeds_the_cap_but_whose_copy_fits_is_played(env):
    data = clip()
    env.put(NAME, data)
    cap = vod_play.output_limit(len(data)) + 10_000
    assert vod_play.job_reserve(len(data)) > cap >= vod_play.output_limit(len(data))
    env.db.settings["vod_play_cache_mb"] = str(cap / (1024 * 1024))
    r = await env.play()
    assert r.status == 200, await r.text()
    assert len(env.cache.entries) == 1 and env.cache.used_bytes() <= cap and env.cache.reserved == 0


@with_env
async def test_the_free_space_floor_still_bounds_working_space_when_the_cap_is_small(env):
    data = clip()
    env.put(NAME, data)
    cap = vod_play.output_limit(len(data)) + 10_000
    env.db.settings["vod_play_cache_mb"] = str(cap / (1024 * 1024))
    env.db.settings["vod_min_free_gb"] = "1"
    with mock.patch.object(server.vod_staging, "free_bytes", lambda path: 1024 ** 3 + 10):
        r = await env.play()
    assert r.status == 503 and "free disk space" in (await r.json())["error"]
    assert env.cache.entries == {} and env.cache.reserved == 0 and env.spawned == []


@with_env(fast_wait=0.1)
async def test_one_member_prepares_one_chunk_at_a_time_and_different_members_in_parallel(env):
    names = [f"{SESSION}/chunk_00{i}.mkv" for i in range(3)]
    for i, n in enumerate(names):
        env.put(n, clip("aac", i))
    env.put(NAME, clip("aac", 9), root="/w")
    running = {"now": {}, "max": {}}
    real = server._vod_play_run_tool

    async def counting(argv, *a, **k):
        if argv[0] != "ffmpeg":
            return await real(argv, *a, **k)
        owner = current_owner.get()
        running["now"][owner] = running["now"].get(owner, 0) + 1
        running["max"][owner] = max(running["max"].get(owner, 0), running["now"][owner])
        running["all"] = max(running.get("all", 0), sum(running["now"].values()))
        try:
            await asyncio.sleep(0.4)
            return await real(argv, *a, **k)
        finally:
            running["now"][owner] -= 1

    import contextvars
    current_owner = contextvars.ContextVar("owner")
    real_job = server._vod_play_job

    async def tagged(job, *a):
        current_owner.set(job["owner"])
        return await real_job(job, *a)

    with mock.patch.object(server, "_vod_play_run_tool", counting), mock.patch.object(server, "_vod_play_job", tagged):
        for n in names:
            assert (await env.play(n)).status in (200, 202)
        assert (await env.play(NAME, user=OTHER)).status in (200, 202)
        for n in names:
            await env.wait_state({"ready"}, n)
        await env.wait_state({"ready"}, NAME, user=OTHER)
    assert running["max"][OWNER] == 1, running
    assert running["all"] == 2, running          # two members, two slots: they did run side by side


# -- item 5: a refusal because of the cap is not remembered -------------------------------------------

@with_env
async def test_raising_the_cap_helps_at_once_after_a_too_large_refusal(env):
    data = clip()
    env.put(NAME, data)
    env.db.settings["vod_play_cache_mb"] = str((vod_play.output_limit(len(data)) - 1) / (1024 * 1024))
    for _ in range(2):
        r = await env.play()
        assert r.status == 415 and "too large" in (await r.json())["error"]
    assert env.spawned == [] and not server._vod_play_jobs          # no job, nothing remembered
    st, body = await env.status()
    assert body["state"] == "idle"
    env.db.settings["vod_play_cache_mb"] = "50"
    r = await env.play()
    assert r.status == 200, await r.text()


@with_env
async def test_a_refusal_made_inside_the_job_is_not_remembered_either(env):
    env.put(NAME, clip())
    real_cap = server._vod_play_cap
    calls = {"n": 0}

    async def cap():
        calls["n"] += 1
        return 1000 if calls["n"] == 3 else await real_cap()        # prelude, obtain, then the job sees a lowered cap

    with mock.patch.object(server, "_vod_play_cap", cap):
        r = await env.play()
    assert r.status == 415 and "too large" in (await r.json())["error"]
    assert not server._vod_play_jobs and env.spawned == [] and env.cache.reserved == 0
    r = await env.play()
    assert r.status == 200, await r.text()

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
    shutil.rmtree(tvp.CLIPS, ignore_errors=True)
    print("FAILED" if fails else "all passed")
    sys.exit(1 if fails else 0)
