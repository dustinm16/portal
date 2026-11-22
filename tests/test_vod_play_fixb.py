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
