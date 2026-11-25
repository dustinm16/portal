"""A folder the sweep keeps is reported once at WARNING, then at INFO on every later pass.

Two kept cases: a folder without a usable session record, and a folder whose owner has no storage.
When the folder is gone the memory of it is dropped, so a new folder of the same name warns again.
Real asyncssh SFTP server on loopback (never reached here), temporary directories only.

Run: venv/bin/python tests/test_vod_sweep_kept_log.py
"""
import asyncio
import logging
import os
import signal
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Patched, Remote, SweepDb, run, server, session  # noqa: E402
import vod_staging  # noqa: E402

DEADLINE = 90
NAME = "1_2026-01-01_5"


class Records:
    def __enter__(self):
        self.items = []
        outer = self

        class H(logging.Handler):
            def emit(self, record):
                outer.items.append((record.levelname, record.getMessage()))

        self.h = H(level=logging.DEBUG)
        self.log = logging.getLogger("portal")
        self.old = self.log.level
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(self.h)
        return self

    def __exit__(self, *a):
        self.log.removeHandler(self.h)
        self.log.setLevel(self.old)

    def kept(self, level):
        return [m for lv, m in self.items if lv == level and "kept" in m and NAME in m]


def _two_passes(case):
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodkept_") as t:
            async with Remote(t) as remote:
                d = session(t, NAME, {"chunk_000.mkv": b"data"})
                kw = {}
                if case == "norecord":
                    os.unlink(d / vod_staging.SIDECAR_NAME)
                else:
                    kw["missing_storage"] = True
                with Patched(t, remote, SweepDb(remote, **kw)), Records() as rec:
                    for _ in range(3):
                        await server.recover_vod_staging()
                    first = (len(rec.kept("WARNING")), len(rec.kept("INFO")))
                    # the folder goes, a new one of the same name appears: it warns again
                    for f in d.iterdir():
                        f.unlink()
                    d.rmdir()
                    await server.recover_vod_staging()
                    d2 = session(t, NAME, {"chunk_000.mkv": b"data"})
                    if case == "norecord":
                        os.unlink(d2 / vod_staging.SIDECAR_NAME)
                    await server.recover_vod_staging()
                    return first, len(rec.kept("WARNING"))
    server._vod_kept_logged.clear() if hasattr(server, "_vod_kept_logged") else None
    return asyncio.run(asyncio.wait_for(go(), DEADLINE))


def test_a_folder_without_a_session_record_warns_once_per_life_of_the_folder():
    first, total = _two_passes("norecord")
    assert first == (1, 2), first
    assert total == 2, total


def test_a_folder_of_an_owner_without_storage_warns_once_per_life_of_the_folder():
    first, total = _two_passes("nostorage")
    assert first == (1, 2), first
    assert total == 2, total


def _deadline(signum, frame):
    print("FAIL: test_vod_sweep_kept_log timed out", flush=True)
    os._exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE * 3)
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
