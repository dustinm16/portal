"""Aggregated security events keep the member they name apart per source address and minute.

note() keyed an aggregated event (login_failed, 2fa_failed, rate_limited, ...) by address, event,
result and minute only, so a second member in the same bucket was counted under the first. The user id
is now part of the key when the event carries one. Events without a member still share one row, and an
event past the per-minute cap is still folded into the unattributed overflow bucket.

Run: venv/bin/python tests/test_secevents_users.py
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
import secevents  # noqa: E402
from database import Database  # noqa: E402

NOW = 1_800_000_000.0


def test_two_members_from_one_address_in_one_minute_get_two_rows():
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            try:
                a = await d.create_user("ann", "x")
                b = await d.create_user("ben", "x")
                log = secevents.SecurityEventLog(d)
                for uid, name in ((a, "ann"), (b, "ben"), (a, "ann"), (a, "ann")):
                    log.note("login_failed", ip="203.0.113.7", user_id=uid, username=name,
                             result="bad_password", now=NOW)
                log.note("login_failed", ip="203.0.113.7", username="nobody", result="bad_password", now=NOW)
                log.note("login_failed", ip="203.0.113.7", username="nobody2", result="bad_password", now=NOW)
                await log.flush()
                cur = await d.conn.execute(
                    "SELECT user_id, count FROM security_events WHERE event = 'login_failed' ORDER BY user_id")
                got = sorted(((r["user_id"], r["count"]) for r in await cur.fetchall()),
                             key=lambda t: (t[0] is not None, t[0] or 0))
                assert got == [(None, 2), (a, 3), (b, 1)], got
            finally:
                await d.close()
    asyncio.run(asyncio.wait_for(go(), 30))


def test_an_aggregated_member_row_past_the_minute_cap_is_not_filed_under_a_member():
    log = secevents.SecurityEventLog()
    for i in range(secevents.MINUTE_MAX_KEYS + 20):
        log.note("login_failed", ip=f"198.51.100.{i % 250}", user_id=1000 + i, username="u",
                 result="bad_password", now=NOW + (i % 2) * 0)
    users = {e["user_id"] for e in log._agg.values()}
    overflow = [e for e in log._agg.values() if e["ip"] == secevents.OVERFLOW_IP]
    assert overflow and all(e["user_id"] is None for e in overflow), overflow
    assert len(log._agg) <= secevents.MINUTE_MAX_KEYS + 1, len(log._agg)
    assert None in users


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
