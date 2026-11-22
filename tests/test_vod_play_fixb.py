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
