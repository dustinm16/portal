"""Dangerous-location guard for the terminal recordings folder.

Run: venv/bin/python tests/test_recording_paths.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""

import asyncio
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
import vod_staging  # noqa: E402


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def test_dangerous_locations_are_refused():
    recording_paths.reset()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "proj"
        for sub in ("static", "backups/archives", "data/vod_tmp", "data/vod_tmp/x", "static/css"):
            (root / sub).mkdir(parents=True)
        home = Path(os.path.expanduser("~"))
        cases = {
            "/": "/",
            "/tmp": "/tmp",
            "below /tmp": tmp,
            "home": str(home),
            "project root": str(root),
            "static": str(root / "static"),
            "below static": str(root / "static" / "css"),
            "backups": str(root / "backups"),
            "archives": str(root / "backups" / "archives"),
            "vod_tmp": str(root / "data" / "vod_tmp"),
            "below vod_tmp": str(root / "data" / "vod_tmp" / "x"),
        }
        for label, path in cases.items():
            assert recording_paths.refusal_reason(path, str(root)), f"{label} ({path}) was accepted"
        # the portal's own default folder is fine even below /tmp
        assert recording_paths.refusal_reason(str(root / "recordings"), str(root)) is None


def test_content_rule():
    recording_paths.reset()
    vod_staging_roots = vod_staging.TEMP_ROOTS
    vod_staging.TEMP_ROOTS = ()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            d = Path(tmp) / "rec"
            assert recording_paths.refusal_reason(str(d), str(root)) is None, "a missing folder is fine"
            d.mkdir()
            assert recording_paths.refusal_reason(str(d), str(root)) is None, "an empty folder is fine"
            (d / "a.cast").write_text("{}")
            assert recording_paths.refusal_reason(str(d), str(root)) is None, "only .cast files is fine"
            (d / "notes.txt").write_text("x")
            assert "notes.txt" in recording_paths.refusal_reason(str(d), str(root))
            (d / "notes.txt").unlink()
            (d / "sub.cast").mkdir()
            assert recording_paths.refusal_reason(str(d), str(root)), "a sub-folder is other content"
            (d / "sub.cast").rmdir()
            (d / "sub").mkdir()
            assert recording_paths.refusal_reason(str(d), str(root)), "a sub-folder is other content"
    finally:
        vod_staging.TEMP_ROOTS = vod_staging_roots


def test_refused_folder_is_not_chmodded_not_swept_and_recording_goes_off():
    async def go():
        recording_paths.reset()
        saved = (Config.RECORDINGS_DIR, sr.db, vod_staging.TEMP_ROOTS)
        vod_staging.TEMP_ROOTS = ()
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            sr.db = d
            try:
                rec = Path(tmp) / "rec"
                rec.mkdir(mode=0o755)
                cast = rec / "old.cast"
                cast.write_text("{}\n")
                os.chmod(cast, 0o644)
                os.utime(cast, (1, 1))  # an old orphan: would be swept in a good folder
                other = rec / "important.txt"
                other.write_text("not a recording")
                os.chmod(other, 0o664)
                Config.RECORDINGS_DIR = str(rec)

                try:
                    term.prepare_recordings_dir(str(rec))
                    raise AssertionError("prepare_recordings_dir accepted a folder with other content")
                except term.RecordingsDirRefused:
                    pass
                assert mode(rec) == 0o755, "the refused folder was chmodded"
                assert term.tighten_recording_files(str(rec)) == 0
                assert mode(cast) == 0o644 and mode(other) == 0o664, "files in a refused folder were chmodded"
                assert await d.cleanup_orphan_recordings() == 0 and cast.exists(), "a refused folder was swept"
                uid = await d.create_user("rec_user", "x")
                sid = await d.create_service(name="shell", path="/shell-rec", plugin="terminal")
                r = term.AsciicastRecorder(uid, sid)
                assert await r.start() is None, "recording stayed on"
                assert sorted(p.name for p in rec.iterdir()) == ["important.txt", "old.cast"]
                # the refusal lasts for the run, even when the content is cleaned up
                other.unlink()
                assert await term.AsciicastRecorder(uid, sid).start() is None
                assert await d.cleanup_orphan_recordings() == 0 and cast.exists()
                # ... until the next run
                recording_paths.reset()
                assert await d.cleanup_orphan_recordings() == 1 and not cast.exists()
            finally:
                Config.RECORDINGS_DIR, sr.db, vod_staging.TEMP_ROOTS = saved
                await d.close()
    asyncio.run(go())


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                failed += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
