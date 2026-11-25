"""The guard notice that My VODs shows an owner has an age limit and goes with its stream.

_vod_guard_public returns the owner's newest notice only while it is less than a day old (an older one is
dropped); _stream_state_forget (a deleted stream or account) removes the stream's notice.

Run: venv/bin/python tests/test_vod_guard_age.py
"""
import os
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402

DEADLINE = 60


def _note(uid, seq, age_hours, kind="stopped"):
    at = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    return {"user_id": uid, "seq": seq, "kind": kind, "code": "low_disk", "message": f"m{seq}",
            "stream_name": f"s{seq}", "at": at.isoformat()}


def test_a_notice_older_than_a_day_is_not_shown():
    server._vod_guard_state.clear()
    try:
        server._vod_guard_state[5] = _note(1, 1, 30)
        assert server._vod_guard_public(1) is None
        server._vod_guard_state[5] = _note(1, 1, 2)
        assert server._vod_guard_public(1)["message"] == "m1"
    finally:
        server._vod_guard_state.clear()


def test_an_old_newest_notice_does_not_hide_a_fresh_older_one():
    server._vod_guard_state.clear()
    try:
        server._vod_guard_state[5] = _note(1, 1, 2)       # fresh, older sequence
        server._vod_guard_state[6] = _note(1, 2, 40)      # newest sequence but stale
        shown = server._vod_guard_public(1)
        assert shown and shown["message"] == "m1", shown
        server._vod_guard_state[7] = _note(2, 3, 1)
        assert server._vod_guard_public(1)["message"] == "m1"
        assert server._vod_guard_public(3) is None
    finally:
        server._vod_guard_state.clear()


def test_a_notice_without_a_readable_time_is_dropped():
    server._vod_guard_state.clear()
    try:
        st = _note(1, 1, 1)
        st["at"] = "not a time"
        server._vod_guard_state[5] = st
        assert server._vod_guard_public(1) is None
    finally:
        server._vod_guard_state.clear()


def test_deleting_a_stream_clears_its_notice():
    server._vod_guard_state.clear()
    try:
        server._vod_guard_state[5] = _note(1, 1, 1)
        server._vod_guard_state[6] = _note(1, 2, 1)
        server._stream_state_forget(5)
        assert 5 not in server._vod_guard_state and 6 in server._vod_guard_state
        assert server._vod_guard_public(1)["message"] == "m2"
    finally:
        server._vod_guard_state.clear()


def _deadline(signum, frame):
    print("FAIL: test_vod_guard_age timed out", flush=True)
    os._exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE)
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
