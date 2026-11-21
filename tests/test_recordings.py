"""Terminal recorder: append-as-you-go asciicast v2 file, private permissions,
size cap and output only.

Run: venv/bin/python tests/test_recordings.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""

import asyncio
import json
import os
import stat
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


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def run_with_db(body):
    """Run body(db, recordings_dir, tmp) with the plugin and Config pointed at a temp tree."""
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (Config.RECORDINGS_DIR, sr.db)
            rec_dir = str(Path(tmp) / "recordings")
            Config.RECORDINGS_DIR = rec_dir
            recording_paths.reset()
            sr.db = d
            try:
                await body(d, rec_dir, Path(tmp))
            finally:
                Config.RECORDINGS_DIR, sr.db = saved
                await d.close()
    asyncio.run(go())


async def make_ids(d):
    uid = await d.create_user("rec_user", "x")
    sid = await d.create_service(name="shell", path="/shell-rec", plugin="terminal")
    return uid, sid


def read_cast(path):
    lines = Path(path).read_text().splitlines()
    return json.loads(lines[0]), [json.loads(x) for x in lines[1:]]


def test_file_is_private_and_grows_while_recording():
    async def body(d, rec_dir, tmp):
        os.makedirs(rec_dir, mode=0o755)
        os.chmod(rec_dir, 0o755)
        uid, sid = await make_ids(d)
        r = term.AsciicastRecorder(uid, sid, 100, 30)
        assert await r.start()
        path = Path(rec_dir) / r.filename
        assert mode(rec_dir) == 0o700, "existing directory is tightened"
        assert mode(path) == 0o600
        sizes = [path.stat().st_size]
        r.record_output("hello\r\n")
        sizes.append(path.stat().st_size)
        r.record_output("\x1b[31mred\x1b[0m é �\r\n")
        sizes.append(path.stat().st_size)
        assert sizes[0] < sizes[1] < sizes[2], sizes
        # valid before the session even ends
        header, events = read_cast(path)
        assert header["version"] == 2 and header["width"] == 100 and header["height"] == 30
        assert isinstance(header["timestamp"], int)
        assert [e[1] for e in events] == ["o", "o"] and events[0][2] == "hello\r\n"
        times = [e[0] for e in events]
        assert all(isinstance(t, float) and t >= 0 for t in times) and times == sorted(times)
        await r.finish()
        row = await d.get_recording(r.recording_id) if r.recording_id else None
        assert row is None  # recording_id is cleared on finish
        cur = await d.conn.execute("SELECT size, duration FROM recordings")
        row = dict(await cur.fetchone())
        assert row["size"] == path.stat().st_size and row["duration"] >= 0
    run_with_db(body)


def test_prepare_tightens_an_existing_directory():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "recordings"
        d.mkdir()
        os.chmod(d, 0o755)
        assert term.prepare_recordings_dir(str(d)) == d
        assert mode(d) == 0o700
        term.prepare_recordings_dir(str(d))  # second call changes nothing
        assert mode(d) == 0o700
        fresh = Path(tmp) / "a" / "b"
        term.prepare_recordings_dir(str(fresh))
        assert mode(fresh) == 0o700


def test_startup_tightens_existing_files_without_following_symlinks():
    with tempfile.TemporaryDirectory() as tmp:
        recording_paths.reset()
        root = Path(tmp)
        d = root / "recordings"
        d.mkdir(mode=0o700)
        old = d / "rec_old.cast"
        old.write_text("{}\n")
        os.chmod(old, 0o644)
        other = d / "rec_old2.cast"
        other.write_text("{}\n")
        os.chmod(other, 0o664)
        outside = root / "outside.cast"
        outside.write_text("keep")
        os.chmod(outside, 0o644)
        os.symlink(outside, d / "link.cast")
        fifo = d / "pipe.cast"
        os.mkfifo(fifo, 0o644)
        assert term.tighten_recording_files(str(d)) == 2
        assert mode(old) == 0o600 and mode(other) == 0o600
        assert mode(outside) == 0o644, "the target of a symlink is not touched"
        assert mode(fifo) == 0o644, "only regular files"
        assert term.tighten_recording_files(str(d)) == 0
        assert term.tighten_recording_files(str(root / "missing")) == 0


def test_new_directory_is_0700_and_names_do_not_collide():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        a = term.AsciicastRecorder(uid, sid)
        b = term.AsciicastRecorder(uid, sid)
        assert await a.start() and await b.start()
        assert a.filename != b.filename
        assert mode(rec_dir) == 0o700
        await a.finish()
        await b.finish()
    run_with_db(body)


def test_input_is_never_recorded():
    assert not hasattr(term.AsciicastRecorder, "record_input")

    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        r = term.AsciicastRecorder(uid, sid)
        await r.start()
        r.record_output("secret-looking echo\r\n")
        path = Path(rec_dir) / r.filename
        await r.finish()
        _, events = read_cast(path)
        assert {e[1] for e in events} == {"o"}
    run_with_db(body)


def test_size_cap_stops_recording_and_keeps_valid_file():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        r = term.AsciicastRecorder(uid, sid, max_bytes=400)
        await r.start()
        path = Path(rec_dir) / r.filename
        for i in range(100):
            r.record_output("line %d\r\n" % i)
        assert r.truncated and not r._active
        assert path.stat().st_size <= 400, path.stat().st_size
        header, events = read_cast(path)  # every line still parses
        assert header["version"] == 2 and 0 < len(events) < 100
        # the file ends with a valid asciicast v2 marker event saying it was cut
        last = events[-1]
        assert last[1] == "m" and last[2] == term.RECORDING_TRUNCATED_NOTE
        assert isinstance(last[0], (int, float)) and last[0] >= events[-2][0]
        assert [e[1] for e in events[:-1]] == ["o"] * (len(events) - 1)
        n = len(events)
        r.record_output("more\r\n")  # silently ignored after the stop
        assert len(read_cast(path)[1]) == n
        await r.finish()
        cur = await d.conn.execute("SELECT size FROM recordings")
        assert (await cur.fetchone())["size"] == path.stat().st_size
    run_with_db(body)


def test_marker_is_skipped_when_it_cannot_fit_and_untruncated_files_have_none():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        ok = term.AsciicastRecorder(uid, sid)
        await ok.start()
        ok.record_output("short\r\n")
        await ok.finish()
        assert not ok.truncated
        assert all(e[1] == "o" for e in read_cast(Path(rec_dir) / ok.filename)[1])
        tiny = term.AsciicastRecorder(uid, sid, max_bytes=60)  # smaller than the header
        await tiny.start()
        tiny.record_output("x")
        await tiny.finish()
        text = (Path(rec_dir) / tiny.filename).read_text().splitlines()
        assert tiny.truncated and len(text) == 1 and json.loads(text[0])["version"] == 2
    run_with_db(body)


def test_resize_events_are_recorded_and_bounded():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        r = term.AsciicastRecorder(uid, sid, cols=100, rows=30)
        await r.start()
        r.record_output("a")
        r.record_resize(120, 40)
        for bad in ((0, 10), (10, 0), (5000, 10), ("x", 1), (None, None), ([1], 2), (float("inf"), 3)):
            r.record_resize(*bad)
        r.record_resize("90", "25")
        await r.finish()
        header, events = read_cast(Path(rec_dir) / r.filename)
        assert header["width"] == 100 and header["height"] == 30
        assert [(e[1], e[2]) for e in events] == [("o", "a"), ("r", "120x40"), ("r", "90x25")], events
        assert [e[0] for e in events] == sorted(e[0] for e in events)
        # a client-sent size that is not a sane integer never reaches the header either
        r2 = term.AsciicastRecorder(uid, sid, cols="wide", rows=[24])
        assert (r2.cols, r2.rows) == (80, 24)
    run_with_db(body)


def test_default_cap_is_50_mb():
    assert term.RECORDING_MAX_BYTES == 50 * 1024 * 1024
    assert term.AsciicastRecorder(1, 1).max_bytes == 50 * 1024 * 1024


def test_write_failure_turns_recording_off_without_raising():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        r = term.AsciicastRecorder(uid, sid)
        await r.start()
        os.close(r._fd)  # the next write fails with EBADF
        r.record_output("x")
        assert not r._active
        await r.finish()
    run_with_db(body)


def test_start_failure_returns_none_and_leaves_no_row():
    async def body(d, rec_dir, tmp):
        uid, sid = await make_ids(d)
        blocker = tmp / "blocker"
        blocker.write_text("a file, not a directory")
        Config.RECORDINGS_DIR = str(blocker / "sub")
        r = term.AsciicastRecorder(uid, sid)
        assert await r.start() is None
        r.record_output("x")
        await r.finish()
        assert not d.live_recording_ids and not d.live_recording_files
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM recordings")
        assert (await cur.fetchone())["n"] == 0
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
