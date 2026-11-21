"""Terminal recording retention: the setting, and age-based removal of file and row
with a path check under the recordings directory.

Run: venv/bin/python tests/test_recording_retention.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from config import Config  # noqa: E402
from database import Database  # noqa: E402
import plugins.terminal as term  # noqa: E402
import session_recording as sr  # noqa: E402
import recording_paths  # noqa: E402

# The sandboxes live under /tmp, which a recordings folder may not (see
# tests/test_recording_paths.py); these tests are about something else.
recording_paths.vod_staging.TEMP_ROOTS = ()


def run_with_db(body):
    """Run body(db, recordings_dir, tmp) with Config pointed at a temp tree."""
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = Config.RECORDINGS_DIR
            rec_dir = str(Path(tmp) / "recordings")
            Config.RECORDINGS_DIR = rec_dir
            recording_paths.reset()
            try:
                await body(d, rec_dir, Path(tmp))
            finally:
                Config.RECORDINGS_DIR = saved
                await d.close()
    asyncio.run(go())


async def make_ids(d):
    uid = await d.create_user("rec_user", "x")
    sid = await d.create_service(name="shell", path="/shell-rec", plugin="terminal")
    return uid, sid


async def add_row(d, uid, sid, filename, age_days):
    cur = await d.conn.execute(
        "INSERT INTO recordings (user_id, service_id, filename, created_at) "
        "VALUES (?, ?, ?, datetime('now', ?))", (uid, sid, filename, f"-{age_days} days"))
    await d.conn.commit()
    return cur.lastrowid


async def row_ids(d):
    cur = await d.conn.execute("SELECT id FROM recordings")
    return {r["id"] for r in await cur.fetchall()}


def test_default_retention_is_30_days_and_validated():
    async def body(d, rec_dir, tmp):
        cfg = await d.get_retention_config()
        assert cfg["retention_recordings_days"] == "30"
        await d.set_retention_config({"retention_recordings_days": "7"})
        assert (await d.get_retention_config())["retention_recordings_days"] == "7"
        await d.set_retention_config({"retention_recordings_days": "-1"})
        assert (await d.get_retention_config())["retention_recordings_days"] == "7"
        await d.set_retention_config({"retention_recordings_days": "99999"})
        assert (await d.get_retention_config())["retention_recordings_days"] == "3650"
    run_with_db(body)


def test_cleanup_removes_old_file_and_row_only():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        old, new = Path(rec_dir) / "old.cast", Path(rec_dir) / "new.cast"
        old.write_text("x")
        new.write_text("x")
        old_id = await add_row(d, uid, sid, "old.cast", 40)
        new_id = await add_row(d, uid, sid, "new.cast", 5)
        gone_id = await add_row(d, uid, sid, "already-gone.cast", 60)  # file missing: row still goes
        assert await d.cleanup_old_recordings(30) == 2
        assert not old.exists() and new.exists()
        assert await row_ids(d) == {new_id}
        assert old_id not in await row_ids(d) and gone_id not in await row_ids(d)
        assert await d.cleanup_old_recordings(30) == 0
    run_with_db(body)


def test_zero_days_keeps_everything():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir)
        (Path(rec_dir) / "a.cast").write_text("x")
        await add_row(d, uid, sid, "a.cast", 400)
        assert await d.cleanup_old_recordings(0) == 0
        assert (Path(rec_dir) / "a.cast").exists() and len(await row_ids(d)) == 1
    run_with_db(body)


def test_crafted_filenames_never_touch_files_outside_the_directory():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        outside = tmp / "outside.cast"
        outside.write_text("keep me")
        nested = Path(rec_dir) / "sub"
        nested.mkdir()
        (nested / "inner.cast").write_text("keep me too")
        ids = []
        for name in ("../outside.cast", str(outside), "sub/inner.cast", "..", ".", "", "a\x00b"):
            ids.append(await add_row(d, uid, sid, name, 90))
        assert await d.cleanup_old_recordings(30) == 0
        assert outside.read_text() == "keep me"
        assert (nested / "inner.cast").exists()
        assert await row_ids(d) == set(ids), "rows with unsafe names are left in place"
    run_with_db(body)


def test_symlink_inside_directory_removes_the_link_not_the_target():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        outside = tmp / "target.cast"
        outside.write_text("keep me")
        os.symlink(outside, Path(rec_dir) / "link.cast")
        await add_row(d, uid, sid, "link.cast", 90)
        assert await d.cleanup_old_recordings(30) == 1
        assert not os.path.lexists(Path(rec_dir) / "link.cast")
        assert outside.read_text() == "keep me"
    run_with_db(body)


def test_row_kept_when_file_cannot_be_removed():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        (Path(rec_dir) / "adir.cast").mkdir()  # unlink of a directory fails
        rid = await add_row(d, uid, sid, "adir.cast", 90)
        assert await d.cleanup_old_recordings(30) == 0
        assert await row_ids(d) == {rid}
    run_with_db(body)


def test_running_session_recording_survives_retention():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        saved = sr.db
        sr.db = d
        try:
            r = term.AsciicastRecorder(uid, sid)
            rid = await r.start()
            path = Path(rec_dir) / r.filename
            assert rid in d.live_recording_ids and r.filename in d.live_recording_files
            # a session older than the retention window, still open
            await d.conn.execute("UPDATE recordings SET created_at = datetime('now', '-40 days') WHERE id = ?", (rid,))
            await d.conn.commit()
            (Path(rec_dir) / "old.cast").write_text("x")
            old_id = await add_row(d, uid, sid, "old.cast", 40)
            assert await d.cleanup_old_recordings(30) == 1  # only the finished one
            assert old_id not in await row_ids(d) and rid in await row_ids(d)
            assert path.exists()
            r.record_output("still writing\r\n")
            assert b"still writing" in path.read_bytes()
            # a recorder that hit the size cap is still a running session
            r.max_bytes = 1
            r.record_output("more")
            assert r.truncated and rid in d.live_recording_ids
            assert await d.cleanup_old_recordings(30) == 0 and path.exists()
            await r.finish()
            assert not d.live_recording_ids and not d.live_recording_files
            assert await d.cleanup_old_recordings(30) == 1
            assert not path.exists() and rid not in await row_ids(d)
        finally:
            sr.db = saved
    run_with_db(body)


def set_age(path, seconds):
    t = __import__("time").time() - seconds
    os.utime(path, (t, t), follow_symlinks=False)


def test_orphan_sweep_removes_only_old_unreferenced_recording_files():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        R = Path(rec_dir)
        files = {n: R / n for n in ("orphan.cast", "fresh_orphan.cast", "kept.cast", "live.cast")}
        for p in files.values():
            p.write_text("x")
            set_age(p, 7200)
        set_age(files["fresh_orphan.cast"], 60)
        await add_row(d, uid, sid, "kept.cast", 1)
        d.live_recording_files.add("live.cast")
        outside = tmp / "outside.cast"
        outside.write_text("keep me")
        set_age(outside, 7200)
        os.symlink(outside, R / "link.cast")
        assert await d.cleanup_orphan_recordings() == 1
        assert not files["orphan.cast"].exists()
        for n in ("fresh_orphan.cast", "kept.cast", "live.cast"):
            assert files[n].exists(), n
        assert os.path.islink(R / "link.cast") and outside.read_text() == "keep me"
        assert await d.cleanup_orphan_recordings() == 0
        # the row goes (user deleted): its file is now an orphan, once old enough
        await d.conn.execute("DELETE FROM recordings")
        await d.conn.commit()
        assert await d.cleanup_orphan_recordings() == 1 and not files["kept.cast"].exists()
    run_with_db(body)


def test_orphan_sweep_after_user_deletion_and_with_no_directory():
    async def body(d, rec_dir, tmp):
        assert await d.cleanup_orphan_recordings() == 0  # no directory
        uid, sid = await make_ids(d)
        os.makedirs(rec_dir, mode=0o700)
        f = Path(rec_dir) / "rec_1.cast"
        f.write_text("x")
        set_age(f, 7200)
        await add_row(d, uid, sid, "rec_1.cast", 1)
        await d.conn.execute("DELETE FROM services WHERE id = ?", (sid,))  # cascades to the row
        await d.conn.commit()
        assert await row_ids(d) == set()
        assert await d.cleanup_orphan_recordings() == 1 and not f.exists()
    run_with_db(body)


def test_missing_directory_still_clears_old_rows():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        await add_row(d, uid, sid, "x.cast", 90)
        assert await d.cleanup_old_recordings(30) == 1
    run_with_db(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
