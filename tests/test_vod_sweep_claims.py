"""The sweep's number claims (_vod_sweep_claims) do not pile up.

A claim is kept only while a recording uses (or is starting in) that remote folder; after the sweep of an
idle folder it is deleted. Real asyncssh SFTP server on loopback, temporary directories only.

Run: venv/bin/python tests/test_vod_sweep_claims.py
"""
import asyncio
import os
import signal
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Patched, Remote, SweepDb, REMOTE, run, server, session  # noqa: E402

DEADLINE = 90
OTHER = "/v/other/2026-01-01"


def test_after_a_sweep_the_claim_of_an_idle_folder_is_gone():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodclaims_") as t:
            async with Remote(t) as remote:
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"a", "chunk_001.mkv": b"b"})
                session(t, "2_other", {"chunk_000.mkv": b"c"}, remote=OTHER)
                server._vod_sweep_claims.clear()
                with Patched(t, remote, SweepDb(remote)):
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                    return remote.listing(REMOTE), remote.listing(OTHER), dict(server._vod_sweep_claims)

    mine, other, claims = run(go())
    assert mine == ["chunk_000.mkv", "chunk_001.mkv"] and other == ["chunk_000.mkv"], (mine, other)
    assert claims == {}, claims


def test_a_folder_a_recording_uses_keeps_its_claim_and_an_idle_one_loses_it():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodclaims_") as t:
            async with Remote(t) as remote:
                session(t, "2_other", {"chunk_000.mkv": b"c"}, remote=OTHER)
                server._vod_sweep_claims.clear()
                server._vod_sweep_claims.update({REMOTE: 5, "/v/idle/2026-01-01": 2})
                live = {"session_dir": os.path.join(t, "stage", "9_live"), "remote_session_dir": REMOTE}
                with Patched(t, remote, SweepDb(remote)):
                    with mock.patch.dict(server.active_recordings, {9: live}):
                        await asyncio.wait_for(server.recover_vod_staging(), 60)
                        return dict(server._vod_sweep_claims), remote.listing(OTHER)

    claims, other = run(go())
    assert other == ["chunk_000.mkv"], other
    assert claims == {REMOTE: 5}, claims


def test_a_recording_that_is_starting_in_the_folder_keeps_the_claim():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodclaims_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"a"})
                server._vod_sweep_claims.clear()
                server._vod_sweep_claims[REMOTE] = 4
                with Patched(t, remote, SweepDb(remote)):
                    with mock.patch.object(server, "_vod_busy_dirs", {str(d)}):
                        server._vod_prune_sweep_claims()
                        return dict(server._vod_sweep_claims)

    claims = run(go())
    assert claims == {REMOTE: 4}, claims


def _deadline(signum, frame):
    print("FAIL: test_vod_sweep_claims timed out", flush=True)
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
