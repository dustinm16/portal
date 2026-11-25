"""Interested marks of an entry whose time zone cannot be loaded are dropped (with a log line)
instead of skipped for ever: the due list reads at most 500 rows with no zone filter, so 500
skipped marks would starve every other member's reminder in that window.

Temporary database; the clock of the schedule is moved by the test; nothing is dialled.

Run: venv/bin/python tests/test_schedule_bad_zone_drop.py
"""

import asyncio
import io
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402
from database import Database  # noqa: E402

failures = []
DEADLINE = 120


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def main():
    tmp = tempfile.TemporaryDirectory()
    db = Database(str(Path(tmp.name) / "t.db"))
    await db.connect()
    saved = (server.db, server._schedule_now, server._schedule_last_prune)
    server.db = db
    log = io.StringIO()
    handler = logging.StreamHandler(log)
    server.logger.addHandler(handler)
    try:
        owner = await db.create_user("owner", "x")
        sid = await db.create_user_stream(owner, "Show", "live_" + "a" * 20, public_key="pub_" + "a" * 20, is_public=True)
        base = 1_900_000_000 // 60 * 60                  # the occurrence: a minute-aligned moment
        local = datetime.fromtimestamp(base, timezone.utc).strftime("%Y-%m-%dT%H:%M")
        clean = {"title": "t", "local_start": local, "tz": "UTC", "duration_min": 60, "weekly": False}
        bad = await db.schedule_create(sid, owner, clean, base - 7200, 20, 60)
        good = await db.schedule_create(sid, owner, clean, base - 7200, 20, 60)
        await db.conn.execute("UPDATE stream_schedule SET tz = 'Mars/Olympus' WHERE id = ?", (bad,))
        await db.conn.commit()
        # 501 marks on the broken entry come first (older ids), then one member of the working entry
        for i in range(501):
            uid = await db.create_user(f"b{i}", "x")
            await db.rsvp_add(uid, bad, base, base - 7200, 100, False)
        member = await db.create_user("member", "x")
        await db.rsvp_add(member, good, base, base - 7200, 100, False)
        n_before = (await (await db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvps WHERE entry_id = ?", (bad,))).fetchone())["n"]
        check("501 marks stand on the broken entry", n_before == 501, str(n_before))

        server._schedule_now = lambda: base - 590
        server._schedule_last_prune = base - 590          # no prune in this tick
        sent = 0
        for _ in range(3):                                 # a tick reads 500 rows: a few ticks always get through
            sent += await server.schedule_reminder_pass()
        notes = [n for n in await db.get_notifications(member, limit=20) if n["type"] == "stream_reminder"]
        check("the working entry's member gets the reminder", sent == 1 and len(notes) == 1, str((sent, len(notes))))
        first = None
        left = (await (await db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvps WHERE entry_id = ?", (bad,))).fetchone())["n"]
        check("the marks of the broken entry are dropped", left == 0, str(left))
        lines = [l for l in log.getvalue().splitlines() if f"entry {bad}: dropped" in l]
        check("the broken entry is logged", len(lines) >= 1, str(lines))

        # a host whose zone data is missing as a whole (UTC cannot be loaded either) loses no mark
        keep_uid = await db.create_user("keeper", "x")
        await db.rsvp_add(keep_uid, good, base, base - 7200, 100, False)
        real = server.stream_schedule.zone_available
        server.stream_schedule.zone_available = lambda tz: False
        try:
            await server.schedule_reminder_pass()
        finally:
            server.stream_schedule.zone_available = real
        kept = (await (await db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvps WHERE entry_id = ? AND user_id = ?", (good, keep_uid))).fetchone())["n"]
        check("with no zone data on the host at all, no Interested mark is dropped", kept == 1, str(kept))
    finally:
        server.logger.removeHandler(handler)
        server.db, server._schedule_now, server._schedule_last_prune = saved
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
    outbound_guard.report("test_schedule_bad_zone_drop")
    sys.exit(_rc)
