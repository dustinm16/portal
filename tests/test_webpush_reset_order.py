"""Replacing the VAPID key stores the new key first and only then deletes the devices, so a
failure in between leaves the devices subscribed (with the old key) and the new key stored,
not deleted devices and the old key.

Temporary database only; nothing is dialled.

Run: venv/bin/python tests/test_webpush_reset_order.py
"""

import asyncio
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


async def main():
    tmp = tempfile.TemporaryDirectory()
    db = Database(str(Path(tmp.name) / "t.db"))
    await db.connect()
    try:
        keys = await wp.get_vapid(db)
        old_pub = await db.get_setting(wp.SETTING_PUBLIC)
        check("a first key is stored", keys is not None and bool(old_pub))

        deleted = []
        real_delete = db.delete_all_push_subscriptions

        async def failing_delete():
            deleted.append("tried")
            raise RuntimeError("database is locked")

        db.delete_all_push_subscriptions = failing_delete
        raised = None
        try:
            await wp.reset_vapid(db)
        except RuntimeError as e:
            raised = e
        new_pub = await db.get_setting(wp.SETTING_PUBLIC)
        check("the delete was attempted and its failure is not hidden", deleted == ["tried"] and raised is not None, str((deleted, raised)))
        check("the new key is stored although the device delete failed", new_pub and new_pub != old_pub, str((old_pub, new_pub)))
        check("the stored key still reads", await wp.vapid_state(db) == "ok")

        # a retry removes the devices
        db.delete_all_push_subscriptions = real_delete
        removed = await wp.reset_vapid(db)
        check("a retry replaces the key again and deletes the devices", removed == 0 and await db.get_setting(wp.SETTING_PUBLIC) != new_pub, str(removed))
    finally:
        await db.close()
        tmp.cleanup()
    print()
    print("FAILED: " + ", ".join(failures) if failures else "all checks passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        _rc = asyncio.run(asyncio.wait_for(main(), DEADLINE))
    except BaseException as exc:
        print(f"FAIL: test aborted with {type(exc).__name__}: {exc}", flush=True)
        os._exit(1)
    outbound_guard.report("test_webpush_reset_order")
    sys.exit(_rc)
