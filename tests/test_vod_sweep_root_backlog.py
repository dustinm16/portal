"""A folder the sweep keeps because it was recorded under an earlier storage root does not count against the
owner's backlog limit, and it ages out like a folder whose storage is gone.

Without that, chunks stranded by a change of the storage root would count against vod_max_backlog_gb for
good and every new VOD recording of the owner would be refused. Real asyncssh SFTP server on loopback,
temporary directories only.

Run: venv/bin/python tests/test_vod_sweep_root_backlog.py
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Logs, Patched, Remote, SweepDb, REMOTE, _age, run, server, session  # noqa: E402
from test_vod_sweep_root import MovedDb  # noqa: E402

DEADLINE = 90
LIMIT_SETTING = {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0.00001"}     # about 10.7 KB


class BrokenDb(MovedDb):
    async def get_vod_storage(self, uid):
        raise OSError("database busy")


def _verdict(db_cls, root, remote_dir):
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodrootlog_") as t:
            async with Remote(t) as remote:
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x" * 20000}, remote=remote_dir)
                db = db_cls(remote, root) if db_cls is not SweepDb else SweepDb(remote)
                db.settings.update(LIMIT_SETTING)
                with Patched(t, remote, db):
                    return await server._vod_guard_check(owner_id=7)
    return run(asyncio.wait_for(go(), DEADLINE))


def test_a_backlog_left_under_an_earlier_root_does_not_refuse_a_new_recording():
    assert _verdict(MovedDb, "/moved", REMOTE) is None


def test_the_same_backlog_inside_the_current_root_still_refuses():
    verdict = _verdict(MovedDb, "/v", REMOTE)
    assert verdict and verdict[0] == "total_backlog", verdict


def test_an_unreadable_root_counts_everything_as_before():
    verdict = _verdict(BrokenDb, "/moved", REMOTE)
    assert verdict and verdict[0] == "total_backlog", verdict


def _sweep(age_days):
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodrootlog_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x" * 123})
                _age(str(d), age_days)
                db = MovedDb(remote, "/moved")
                with Patched(t, remote, db), Logs() as logs:
                    await server.recover_vod_staging()
                tree = [f for _b, _d, fs in os.walk(remote.root) for f in fs]
                return d.exists(), tree, db.activity, logs.text()
    return run(asyncio.wait_for(go(), DEADLINE))


def test_a_folder_outside_the_current_root_is_kept_while_young_and_removed_when_old():
    exists, tree, activity, _log = _sweep(5)
    assert exists and tree == [] and activity == [], (exists, tree, activity)
    exists, tree, activity, log = _sweep(400)
    assert not exists and tree == [], "an old folder outside the root is removed, nothing is uploaded"
    rows = [a for a in activity if a[1] == "vod_discarded"]
    assert len(rows) == 1 and rows[0][0] == 7 and "123 bytes" in rows[0][2] and "/" not in rows[0][2], rows
    assert "outside the current storage root" in log, log


def test_an_unreadable_root_never_ages_a_folder_out():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodrootlog_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x" * 123})
                _age(str(d), 400)
                with Patched(t, remote, BrokenDb(remote, "/moved")):
                    await server.recover_vod_staging()
                return d.exists()
    assert run(asyncio.wait_for(go(), DEADLINE)), "a folder must not be removed on a guess"


def test_a_relative_root_against_an_absolute_folder_is_never_aged_out():
    """"vods" and "/home/me/vods" can be the same folder: the sweep cannot tell, so it keeps the chunks."""
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodrootlog_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x" * 123})
                _age(str(d), 400)
                db = MovedDb(remote, "v")
                with Patched(t, remote, db):
                    await server.recover_vod_staging()
                return d.exists(), db.activity
    exists, activity = run(asyncio.wait_for(go(), DEADLINE))
    assert exists and not [a for a in activity if a[1] == "vod_discarded"], (exists, activity)


if __name__ == "__main__":
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
