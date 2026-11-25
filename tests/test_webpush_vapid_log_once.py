"""A stored VAPID key that cannot be read is logged once per process and failure kind, not on every call
(the push config route calls get_vapid on every member page load). Replacing the key makes a later
failure log again.

Temporary database only; nothing is dialled.

Run: venv/bin/python tests/test_webpush_vapid_log_once.py
"""

import asyncio
import logging
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import webpush as wp  # noqa: E402
from database import Database  # noqa: E402

failures = []
DEADLINE = 60


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(record)


async def main():
    tmp = tempfile.TemporaryDirectory()
    db = Database(str(Path(tmp.name) / "t.db"))
    await db.connect()
    handler = Records()
    wp.logger.addHandler(handler)
    try:
        await db.set_setting(wp.SETTING_PRIVATE, "enc:not-a-sealed-value")
        check("an unreadable key gives no key", await wp.get_vapid(db) is None)
        check("(and a second call gives none either)", await wp.get_vapid(db) is None)
        check("(and a third)", await wp.get_vapid(db) is None)
        check("three calls log one error", len(handler.records) == 1, str([r.getMessage() for r in handler.records]))

        await db.set_setting(wp.SETTING_PRIVATE, "plain-text-value")
        await wp.get_vapid(db)
        await wp.get_vapid(db)
        check("another failure kind is logged once too", len(handler.records) == 2, str(len(handler.records)))

        n = await wp.reset_vapid(db)
        check("the key is replaced", n is not None and await wp.get_vapid(db) is not None)
        check("a working key logs nothing", len(handler.records) == 2, str(len(handler.records)))
        await db.set_setting(wp.SETTING_PRIVATE, "enc:not-a-sealed-value")
        await wp.get_vapid(db)
        check("a failure after the key was replaced is logged again", len(handler.records) == 3, str(len(handler.records)))
    finally:
        wp.logger.removeHandler(handler)
        await db.close()
        tmp.cleanup()


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check("finished within its deadline", False, f"{DEADLINE} s")
if failures:
    print(f"\ntest_webpush_vapid_log_once: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_webpush_vapid_log_once: all checks passed")
