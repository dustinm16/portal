"""The VOD zip route after a storage error in the middle of an entry.

The offset of every later central-directory entry counts the bytes really sent, and after an error that
cut an entry the archive ends there: the central directory lists the complete entries only, so the zip
opens and the missing file is visibly absent. An error before any data byte of an entry (the file cannot
be opened) still only skips that file. Real loopback SFTP server; the failing read is a thin wrapper.

Run: venv/bin/python tests/test_vod_zip_midfail.py
"""
import asyncio
import io
import os
import signal
import sys
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import asyncssh  # noqa: E402
from test_vod_play import NAME, OWNER, SESSION, _closed, server, with_env  # noqa: E402

DEADLINE = 90
BAD = f"{SESSION}/chunk_001.mkv"


class _FailingFile:
    """Reads the real file; after `good` reads the next read raises (or, with good=None, open fails)."""

    def __init__(self, real_cm, good, exc):
        self._cm, self._good, self._exc, self._f = real_cm, good, exc, None

    async def __aenter__(self):
        self._f = await self._cm.__aenter__()
        return self

    async def __aexit__(self, *a):
        return await self._cm.__aexit__(*a)

    async def read(self, n):
        if self._good == 0:
            raise self._exc
        self._good -= 1
        return await self._f.read(n)


class _Client:
    def __init__(self, inner, good, exc, open_fails):
        self._inner, self._good, self._exc, self._open_fails = inner, good, exc, open_fails

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def open(self, path, *a, **k):
        if str(path).endswith("chunk_001.mkv"):
            if self._open_fails:
                raise asyncssh.SFTPNoSuchFile("gone")
            return _FailingFile(self._inner.open(path, *a, **k), self._good, self._exc)
        return self._inner.open(path, *a, **k)


def _link(good=1, exc=None, open_fails=False):
    real = server._connect_vod_sftp
    conns = []

    async def connect(uid):
        conn, sftp, error = await real(uid)
        if error:
            return conn, sftp, error
        conns.append(conn)
        return conn, _Client(sftp, good, exc or OSError("storage went away"), open_fails), None
    return mock.patch.object(server, "_connect_vod_sftp", connect), conns


def _three(env):
    data = {n: os.urandom(600_000) for n in (NAME, BAD, f"{SESSION}/chunk_002.mkv")}   # 3 reads of 256 KiB each
    for n, d in data.items():
        env.put(n, d)
    return list(data), data


def _check_valid(raw, names, data):
    zf = zipfile.ZipFile(io.BytesIO(raw))
    assert zf.namelist() == names, zf.namelist()
    assert zf.testzip() is None
    for n in names:
        assert zf.read(n) == data[n], n


@with_env
async def test_an_error_in_the_middle_of_an_entry_ends_the_archive_with_the_complete_entries(env):
    names, data = _three(env)
    for exc in (OSError("storage went away"), asyncssh.SFTPFailure("failed"), asyncio.TimeoutError()):
        patch, conns = _link(good=1, exc=exc)
        with patch:
            r = await asyncio.wait_for(env.client.post(
                "/api/vods/download-archive", json={"files": names}, headers={"X-U": str(OWNER)}), 30)
            raw = await r.read()
        assert r.status == 200
        _check_valid(raw, [NAME], data)
        assert await _closed(conns), "the connection was left open"


@with_env
async def test_a_file_that_cannot_be_opened_is_skipped_and_the_later_ones_stay_readable(env):
    names, data = _three(env)
    patch, conns = _link(open_fails=True)
    with patch:
        r = await asyncio.wait_for(env.client.post(
            "/api/vods/download-archive", json={"files": names}, headers={"X-U": str(OWNER)}), 30)
        raw = await r.read()
    _check_valid(raw, [names[0], names[2]], data)


def _deadline(signum, frame):
    print("FAIL: test_vod_zip_midfail timed out", flush=True)
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
