"""Stale hidden part files on the owner's remote VOD storage are removed by the sweep.

After the sweep lists a remote session folder it deletes entries named .live_*.part and .sweep_*.part whose
modification time is more than 24 hours old, only in a folder no recording uses, a bounded number per pass,
only regular files (never a link), never any other name. Real asyncssh SFTP server on loopback with a
temporary directory as its root; the file ages are set with os.utime.

Run: venv/bin/python tests/test_vod_part_cleanup.py
"""
import asyncio
import os
import signal
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Logs, Patched, Remote, SweepDb, REMOTE, run, server, session  # noqa: E402

DEADLINE = 90
OTHER = "/v/other/2026-01-01"
DAY = 24 * 3600


def _put(remote, folder, name, age_hours, data=b"x"):
    remote.put(f"{folder}/{name}", data)
    when = time.time() - age_hours * 3600
    os.utime(remote.path(f"{folder}/{name}"), (when, when))


OLD_PARTS = (".live_chunk_000_aaaa1111.part", ".sweep_003_bbbb2222.part")
KEPT = (
    ".live_chunk_001_cccc3333.part",       # younger than 24 hours
    ".sweep_004_dddd4444.part",            # younger than 24 hours
    "chunk_000.mkv.part",                  # an old part, but not one of the two hidden patterns
    "chunk_001.mkv",                       # a finished chunk, old
    "notes.txt",
    ".live_notes.txt",                     # right prefix, wrong suffix
    ".sweep_x.part.bak",
    ".other_chunk.part",
    "live_chunk_000.part",                 # no leading dot
)


def _fill(remote, folder):
    for n in OLD_PARTS:
        _put(remote, folder, n, 48)
    _put(remote, folder, KEPT[0], 1)
    _put(remote, folder, KEPT[1], 23)
    for n in KEPT[2:]:
        _put(remote, folder, n, 72)


def test_only_old_parts_of_the_two_hidden_patterns_are_removed_and_the_chunks_still_arrive():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodparts_") as t:
            async with Remote(t) as remote:
                _fill(remote, REMOTE)
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"new-chunk"})
                with Patched(t, remote, SweepDb(remote)), Logs() as logs:
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                return remote.listing(REMOTE), logs.text()

    listing, log = run(go())
    for n in OLD_PARTS:
        assert n not in listing, f"{n} should have been removed"
    for n in KEPT:
        assert n in listing, f"{n} must never be removed"
    # the chunk was delivered next to the old ones: one above chunk_001.mkv, and chunk_000.mkv.part counts too
    assert "chunk_002.mkv" in listing, listing
    assert "stale part file" in log and OLD_PARTS[0] in log


def test_a_folder_that_a_recording_uses_is_not_cleaned():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodparts_") as t:
            async with Remote(t) as remote:
                _fill(remote, REMOTE)
                _fill(remote, OTHER)
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"a"})
                session(t, "2_other", {"chunk_000.mkv": b"b"}, remote=OTHER)
                live = {"session_dir": os.path.join(t, "stage", "9_live"), "remote_session_dir": OTHER}
                with Patched(t, remote, SweepDb(remote)):
                    with mock.patch.dict(server.active_recordings, {9: live}):
                        await asyncio.wait_for(server.recover_vod_staging(), 60)
                return remote.listing(REMOTE), remote.listing(OTHER)

    mine, other = run(go())
    assert not any(n in mine for n in OLD_PARTS), mine           # the idle folder was cleaned
    assert all(n in other for n in OLD_PARTS), other             # the folder in use was not touched
    assert "chunk_000.mkv" not in other


def test_a_link_with_a_part_name_is_never_followed_or_removed():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodparts_") as t:
            async with Remote(t) as remote:
                outside = remote.path("/v/elsewhere/precious.bin")
                remote.put("/v/elsewhere/precious.bin", b"keep me")
                os.utime(outside, (time.time() - 9 * DAY,) * 2)       # old too: only the link check protects it
                remote.put(f"{REMOTE}/chunk_000.mkv", b"c")
                link = remote.path(f"{REMOTE}/.live_chunk_005_eeee5555.part")
                os.symlink(outside, link)
                os.utime(link, (time.time() - 5 * DAY,) * 2, follow_symlinks=False)
                os.makedirs(remote.path(f"{REMOTE}/.sweep_006_ffff6666.part"))      # a folder with a part name
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"a"})
                with Patched(t, remote, SweepDb(remote)):
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                return (os.path.lexists(link), os.path.isdir(remote.path(f"{REMOTE}/.sweep_006_ffff6666.part")),
                        remote.read("/v/elsewhere/precious.bin"))

    link_left, dir_left, data = run(go())
    assert link_left and dir_left and data == b"keep me", (link_left, dir_left, data)


def test_at_most_a_bounded_number_is_removed_per_pass_and_the_next_pass_goes_on():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodparts_") as t:
            async with Remote(t) as remote:
                for i in range(5):
                    _put(remote, REMOTE, f".live_chunk_{i:03d}_aaaa000{i}.part", 48)
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"a"})
                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "VOD_PART_CLEAN_PER_PASS", 2):
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                    first = [n for n in remote.listing(REMOTE) if n.endswith(".part")]
                    session(t, "2_2026-01-01_6", {"chunk_000.mkv": b"b"})
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                    second = [n for n in remote.listing(REMOTE) if n.endswith(".part")]
                return first, second

    first, second = run(go())
    assert len(first) == 3 and len(second) == 1, (first, second)


def test_a_part_cleanup_that_fails_does_not_stop_the_delivery():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodparts_") as t:
            async with Remote(t) as remote:
                _fill(remote, REMOTE)
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"new-chunk"})

                async def boom(*a, **k):
                    raise OSError("storage trouble")
                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_vod_clean_stale_parts", boom):
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                return remote.listing(REMOTE)

    listing = run(go())
    assert "chunk_002.mkv" in listing and OLD_PARTS[0] in listing, listing


def _deadline(signum, frame):
    print("FAIL: test_vod_part_cleanup timed out", flush=True)
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
