"""log_activity no longer prunes the table to 50 rows; cleanup_old_activity_log(keep) is the only prune.

Scratch database only.

Run: venv/bin/python tests/test_activity_log_keep.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from database import Database  # noqa: E402

failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "t.db"))
        await d.connect()
        try:
            users = [await d.create_user(f"u{i}", "x") for i in range(3)]
            for n in range(60):
                uid = users[n % 3]
                await d.log_activity(uid, f"u{n % 3}", "login", f"event {n}")
            cur = await d.conn.execute("SELECT COUNT(*) FROM activity_log")
            check("all 60 events remain after the inserts", (await cur.fetchone())[0] == 60)
            check("the admin feed still honours its own limit", len(await d.get_recent_activity(limit=10)) == 10)
            deleted = await d.cleanup_old_activity_log(keep=40)
            cur = await d.conn.execute("SELECT COUNT(*) FROM activity_log")
            check("cleanup_old_activity_log(keep) trims to the newest 40", deleted == 20 and (await cur.fetchone())[0] == 40)
            cur = await d.conn.execute("SELECT detail FROM activity_log ORDER BY id DESC LIMIT 1")
            check("the newest event is the one kept", (await cur.fetchone())[0] == "event 59")
        finally:
            await d.close()


def _deadline():
    print("FAIL: test_activity_log_keep timed out", flush=True)
    os._exit(1)


async def guarded():
    try:
        await asyncio.wait_for(main(), 60)
    except asyncio.TimeoutError:
        _deadline()


asyncio.run(guarded())
if failures:
    print(f"\ntest_activity_log_keep: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_activity_log_keep: all checks passed")
