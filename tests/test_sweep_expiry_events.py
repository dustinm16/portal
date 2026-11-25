"""An automatic ban that runs out is recorded as an ip_unblocked security event.

sweep_auto_bans deleted expired automatic blocks without a word; only the manual unblock route wrote
ip_unblocked. The sweep now writes one ip_unblocked event (result expired, details naming the address) per
expired block it deleted, at most SWEEP_EVENT_CAP singly and one summary row for the rest. Manual blocks and
blocks that have not run out write nothing.

Run: venv/bin/python tests/test_sweep_expiry_events.py
"""

import asyncio
import json
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
from database import Database  # noqa: E402


def run(body):
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            try:
                await body(d)
            finally:
                await d.close()
    asyncio.run(asyncio.wait_for(go(), 60))


async def add(d, ip, expires, source="auto", kind="login"):
    await d.conn.execute(
        "INSERT INTO blocked_ips (ip_address, reason, source, kind, expires_at) VALUES (?, 'test', ?, ?, ?)",
        (ip, source, kind, expires))
    await d.conn.commit()


async def events(d):
    cur = await d.conn.execute("SELECT * FROM security_events WHERE event = 'ip_unblocked' ORDER BY id")
    return [dict(r) for r in await cur.fetchall()]


PAST = "2000-01-01 00:00:00"
FUTURE = "2999-01-01 00:00:00"


def test_an_expired_automatic_ban_writes_one_ip_unblocked_event():
    async def body(d):
        await add(d, "203.0.113.5", PAST)
        await add(d, "203.0.113.6", FUTURE)
        await add(d, "203.0.113.7", PAST, source="manual", kind=None)
        assert await d.sweep_auto_bans() == 1
        ev = await events(d)
        assert len(ev) == 1, ev
        assert ev[0]["result"] == "expired" and ev[0]["ip"] == "203.0.113.5" and ev[0]["user_id"] is None, ev[0]
        det = json.loads(ev[0]["details"])
        assert det["target_ip"] == "203.0.113.5" and det["kind"] == "expired", det
        # nothing left to expire: a second sweep writes nothing more
        assert await d.sweep_auto_bans() == 0
        assert len(await events(d)) == 1
    run(body)


def test_a_flood_of_expiries_is_capped_per_sweep():
    async def body(d):
        n = Database.SWEEP_EVENT_CAP + 30
        for i in range(n):
            await add(d, f"198.51.{i // 250}.{i % 250 + 1}", PAST)
        assert await d.sweep_auto_bans() == n
        ev = await events(d)
        assert len(ev) == Database.SWEEP_EVENT_CAP + 1, len(ev)
        last = json.loads(ev[-1]["details"])
        assert last["kind"] == "expired" and last["more"] == 30, last
    run(body)


def test_a_failing_event_write_does_not_undo_the_sweep():
    async def body(d):
        await add(d, "203.0.113.5", PAST)

        async def boom(row):
            raise OSError("disk full")
        d.insert_security_event = boom
        assert await d.sweep_auto_bans() == 1
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM blocked_ips")
        assert (await cur.fetchone())["n"] == 0
    run(body)


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except BaseException as e:
                bad += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if bad else 0)
