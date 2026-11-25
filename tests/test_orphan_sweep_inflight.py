"""The orphan chat upload sweep never runs twice at once.

Two concurrent calls (an administrator's repeated clicks, or a click during the daily pass) run the scan
once and both receive the same report; a failed run clears the marker so the next call scans again;
a call that starts after the first has ended scans again.
Temporary folder and temporary database only.

Run: venv/bin/python tests/test_orphan_sweep_inflight.py
"""
import asyncio
import os
import signal
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import chat_uploads  # noqa: E402
from test_chat_uploads import make_file, run_with_db  # noqa: E402

DEADLINE = 60


class Counted:
    """chat_uploads.scan_text_sync wrapped: counts the calls, takes a moment, can fail."""

    def __init__(self, fail=False):
        self.calls, self.fail, self.lock = 0, fail, threading.Lock()
        self.real = chat_uploads.scan_text_sync

    def __enter__(self):
        def wrapped(*a, **kw):
            with self.lock:
                self.calls += 1
            time.sleep(0.4)
            if self.fail:
                raise RuntimeError("scan failed")
            return self.real(*a, **kw)
        chat_uploads.scan_text_sync = wrapped
        return self

    def __exit__(self, *a):
        chat_uploads.scan_text_sync = self.real


def test_two_concurrent_calls_scan_once_and_get_the_same_report():
    async def body(d, up, tmp):
        make_file(up, size=9, age_hours=48)
        with Counted() as c:
            r1, r2 = await asyncio.gather(d.sweep_orphan_chat_uploads(), d.sweep_orphan_chat_uploads())
            assert c.calls == 1, c.calls
            assert r1 is r2 and r1["orphans"] == 1, (r1, r2)
            r3 = await d.sweep_orphan_chat_uploads()       # nothing is running now: a new scan
            assert c.calls == 2 and r3["orphans"] == 1, c.calls
    run_with_db(body)


def test_a_failed_run_clears_the_marker_and_every_waiter_gets_the_answer():
    async def body(d, up, tmp):
        make_file(up, size=9, age_hours=48)
        with Counted(fail=True) as c:
            r1, r2 = await asyncio.gather(d.sweep_orphan_chat_uploads(), d.sweep_orphan_chat_uploads())
            assert c.calls == 1 and r1 is r2 and r1.get("skipped"), (c.calls, r1, r2)
        with Counted() as c:
            r3 = await d.sweep_orphan_chat_uploads()
            assert c.calls == 1 and r3["orphans"] == 1 and not r3.get("skipped"), (c.calls, r3)
    run_with_db(body)


def test_a_caller_that_is_cancelled_does_not_cancel_the_run_of_the_other():
    async def body(d, up, tmp):
        make_file(up, size=9, age_hours=48)
        with Counted() as c:
            first = asyncio.ensure_future(d.sweep_orphan_chat_uploads())
            await asyncio.sleep(0.1)
            second = asyncio.ensure_future(d.sweep_orphan_chat_uploads())
            await asyncio.sleep(0.05)
            first.cancel()
            r = await second
            assert c.calls == 1 and r["orphans"] == 1, (c.calls, r)
    run_with_db(body)


def _deadline(signum, frame):
    print("FAIL: test_orphan_sweep_inflight timed out", flush=True)
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
