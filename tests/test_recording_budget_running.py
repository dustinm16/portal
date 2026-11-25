"""A running recording re-checks the total budget and the free-space floor.

Two recordings start under a small total budget (recording_max_total_mb = 1) and write much more than
that, interleaved. The total must stay within the budget plus one check block per recording, each file
ends with the truncation marker, and the free-space floor stops a recording the same way.
Temporary folder and temporary database only.

Run: venv/bin/python tests/test_recording_budget_running.py
"""
import asyncio
import json
import os
import signal
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from config import Config  # noqa: E402
from database import Database  # noqa: E402
import session_recording as sr  # noqa: E402
import recording_paths  # noqa: E402
import plugins.terminal as term  # noqa: E402

recording_paths.vod_staging.TEMP_ROOTS = ()
DEADLINE = 60
BLOCK = 64 * 1024
MB = 1024 * 1024


def run_with_db(body):
    async def go():
        with tempfile.TemporaryDirectory(prefix="recbudget_") as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (Config.RECORDINGS_DIR, sr.db, getattr(sr, "BUDGET_CHECK_BYTES", None), sr._total_bytes)
            Config.RECORDINGS_DIR = str(Path(tmp) / "recordings")
            recording_paths.reset()
            sr.db = d
            sr._total_bytes = 0
            try:
                await body(d, Config.RECORDINGS_DIR)
            finally:
                Config.RECORDINGS_DIR, sr.db, sr.BUDGET_CHECK_BYTES, sr._total_bytes = saved
                await d.close()
    asyncio.run(asyncio.wait_for(go(), DEADLINE))


def last_event(path):
    return json.loads(Path(path).read_text().splitlines()[-1])


async def two_recorders(d, budget_mb="1"):
    await d.set_setting("recording_max_total_mb", budget_mb)
    uid = await d.create_user("rec_user", "x")
    sid = await d.create_service(name="shell", path="/shell-rec", plugin="terminal")
    a = term.AsciicastRecorder(uid, sid, 80, 24)
    b = term.AsciicastRecorder(uid, sid, 80, 24)
    assert await a.start() and await b.start()
    return a, b


def test_two_recordings_started_together_stay_within_the_budget_plus_one_block_each():
    async def body(d, rec_dir):
        sr.BUDGET_CHECK_BYTES = BLOCK
        a, b = await two_recorders(d)
        text = "x" * 4000
        for _ in range(2 * MB // 4000):         # 2 MB offered to each, 1 MB budget in all
            a.record_output(text)
            b.record_output(text)
        total = sr.recordings_total_bytes()
        assert total <= MB + 2 * (BLOCK + 4200), total
        for r in (a, b):
            assert r.truncated and not r._active, "the recording stopped"
            assert last_event(Path(rec_dir) / r.filename)[1] == "m", "closed with the truncation marker"
        await a.finish()
        await b.finish()
    run_with_db(body)


def test_a_recording_under_the_budget_is_not_cut():
    async def body(d, rec_dir):
        sr.BUDGET_CHECK_BYTES = BLOCK
        a, b = await two_recorders(d)
        for _ in range(100):
            a.record_output("y" * 1000)         # 100 KB in a 1 MB budget
        assert not a.truncated and a._active
        await a.finish()
        await b.finish()
    run_with_db(body)


def test_the_free_space_floor_stops_a_running_recording():
    async def body(d, rec_dir):
        sr.BUDGET_CHECK_BYTES = BLOCK
        a, b = await two_recorders(d, "0")
        real = sr._free_and_total
        sr._free_and_total = lambda path: (100 * MB, 100 * 1024 * MB)   # far below the floor
        try:
            for _ in range(2 * BLOCK // 1000):
                a.record_output("z" * 1000)
        finally:
            sr._free_and_total = real
        assert a.truncated and not a._active
        assert last_event(Path(rec_dir) / a.filename)[1] == "m"
        await a.finish()
        await b.finish()
    run_with_db(body)


def _deadline(signum, frame):
    print("FAIL: test_recording_budget_running timed out", flush=True)
    os._exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE * 4)
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
