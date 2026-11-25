"""A stalled storage in the middle of a VOD download or zip does not hold the request open.

Every f.read(CHUNK_SIZE) of the download route and of the zip route has a time limit
(server.VOD_READ_TIMEOUT, 30 s in production; the test lowers it). On a timeout the SFTP file is closed
(bounded), the response ends, and the zip closes with the central directory of the complete entries.
Real loopback SFTP server; the hanging read is a thin wrapper around the real file.

Run: venv/bin/python tests/test_vod_read_timeout.py
"""
import asyncio
import io
import os
import signal
import sys
import time
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402

outbound_guard.install()

from test_vod_play import NAME, OWNER, SESSION, _closed, server, with_env  # noqa: E402

DEADLINE = 90
BAD = f"{SESSION}/chunk_001.mkv"


class _HangingFile:
    """Reads the real file for `good` reads, then the next read never returns."""

    def __init__(self, real_cm, good):
        self._cm, self._good, self._f = real_cm, good, None
        self.closed = False

    async def __aenter__(self):
        self._f = await self._cm.__aenter__()
        return self

    async def __aexit__(self, *a):
        self.closed = True
        return await self._cm.__aexit__(*a)

    async def read(self, n):
        if self._good == 0:
            await asyncio.Event().wait()
        self._good -= 1
        return await self._f.read(n)


class _Client:
    def __init__(self, inner, good, only, files):
        self._inner, self._good, self._only, self._files = inner, good, only, files

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def open(self, path, *a, **k):
        if str(path).endswith(self._only):
            f = _HangingFile(self._inner.open(path, *a, **k), self._good)
            self._files.append(f)
            return f
        return self._inner.open(path, *a, **k)


def _link(only, good=1):
    real = server._connect_vod_sftp
    conns, files = [], []

    async def connect(uid):
        conn, sftp, error = await real(uid)
        if error:
            return conn, sftp, error
        conns.append(conn)
        return conn, _Client(sftp, good, only, files), None
    return mock.patch.object(server, "_connect_vod_sftp", connect), conns, files


def _fast():
    return mock.patch.object(server, "VOD_READ_TIMEOUT", 0.5)


@with_env
async def test_a_download_whose_read_hangs_ends_after_the_timeout(env):
    env.put(NAME, os.urandom(900_000))     # 4 reads of 256 KiB
    patch, conns, files = _link("chunk_000.mkv", good=1)
    t0 = time.monotonic()
    with patch, _fast():
        r = await asyncio.wait_for(env.client.get("/api/vods/download/" + NAME, headers={"X-U": str(OWNER)}), 20)
        try:
            body = await asyncio.wait_for(r.read(), 20)
        except Exception:
            body = b""      # a short body under a longer Content-Length: the client sees it as cut
    assert time.monotonic() - t0 < 15, "the response was held open"
    assert len(body) < 900_000
    assert files and files[0].closed, "the SFTP file was not closed"
    assert await _closed(conns), "the connection was left open"


@with_env
async def test_a_zip_whose_read_hangs_ends_with_the_complete_entries(env):
    data = {n: os.urandom(600_000) for n in (NAME, BAD, f"{SESSION}/chunk_002.mkv")}
    for n, d in data.items():
        env.put(n, d)
    patch, conns, files = _link("chunk_001.mkv", good=1)
    t0 = time.monotonic()
    with patch, _fast():
        r = await asyncio.wait_for(env.client.post(
            "/api/vods/download-archive", json={"files": list(data)}, headers={"X-U": str(OWNER)}), 20)
        raw = await asyncio.wait_for(r.read(), 20)
    assert time.monotonic() - t0 < 15, "the response was held open"
    zf = zipfile.ZipFile(io.BytesIO(raw))
    assert zf.namelist() == [NAME], zf.namelist()
    assert zf.testzip() is None
    assert zf.read(NAME) == data[NAME]
    assert files and files[0].closed, "the SFTP file was not closed"
    assert await _closed(conns), "the connection was left open"


@with_env
async def test_a_normal_download_is_unchanged(env):
    blob = os.urandom(700_000)
    env.put(NAME, blob)
    r = await asyncio.wait_for(env.client.get("/api/vods/download/" + NAME, headers={"X-U": str(OWNER)}), 20)
    assert r.status == 200 and await r.read() == blob


def _deadline(signum, frame):
    print("FAIL: test_vod_read_timeout timed out", flush=True)
    os._exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE * 2)
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except BaseException as e:  # noqa: BLE001
                failed += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e!r}")
    sys.exit(1 if failed else 0)
