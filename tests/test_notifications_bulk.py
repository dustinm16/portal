"""create_notifications_bulk is one atomic write on the shared connection.

* the rows come back in order with their ids and are all stored
* a write another coroutine has pending (not yet committed) is neither interleaved with the
  batch nor discarded when the batch fails: only the batch's own rows are rolled back
* a row that cannot be prepared (not serialisable) writes nothing, and loses nobody's pending write

Run: venv/bin/python tests/test_notifications_bulk.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402


async def make_db(tmp):
    d = Database(str(Path(tmp) / "t.db"))
    await d.connect()
    ids = [await d.create_user(n, "x") for n in ("ann", "ben", "cat")]
    return d, ids


async def count(d, where="1=1"):
    cur = await d.conn.execute(f"SELECT COUNT(*) AS n FROM notifications WHERE {where}")
    return (await cur.fetchone())["n"]


def run(body):
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d, ids = await make_db(tmp)
            try:
                await body(d, ids)
            finally:
                await d.close()
    asyncio.run(go())


def test_rows_come_back_in_order_and_are_stored():
    async def body(d, ids):
        out = await d.create_notifications_bulk(
            [(u, "mention", f"t{u}", "m", {"k": u}) for u in ids])
        assert [u for u, _ in out] == ids and len({n for _, n in out}) == 3, out
        assert await count(d) == 3
        assert await d.create_notifications_bulk([]) == []
    run(body)


def test_a_failing_batch_rolls_back_only_its_own_rows():
    async def body(d, ids):
        # another coroutine's write, pending (executed, not committed) on the shared connection
        await d.conn.execute("INSERT INTO notifications (user_id, type, title) VALUES (?, 'other', 'pending')",
                             (ids[0],))
        try:
            await d.create_notifications_bulk([
                (ids[0], "mention", "a", None, {}),
                (ids[1], None, "b", None, {}),          # NOT NULL violation on the second row
            ])
            raise AssertionError("the batch did not fail")
        except Exception as e:
            assert "NOT NULL" in str(e), e
        await d.conn.commit()
        assert await count(d, "type = 'mention'") == 0, "a row of the failed batch was kept"
        assert await count(d, "type = 'other'") == 1, "the pending write of another coroutine was discarded"
    run(body)


def test_a_row_that_cannot_be_prepared_writes_nothing_and_loses_nobody_elses_write():
    async def body(d, ids):
        async def other():
            await d.conn.execute("INSERT INTO notifications (user_id, type, title) VALUES (?, 'other', 'pending')",
                                 (ids[2],))
            await asyncio.sleep(0)
            await d.conn.commit()

        async def batch():
            try:
                await d.create_notifications_bulk([(ids[0], "mention", "a", None, {}),
                                                   (ids[1], "mention", "b", None, {"bad": {1, 2}})])
            except TypeError:
                return "failed"
        res = await asyncio.gather(batch(), other())
        assert res[0] == "failed"
        assert await count(d, "type = 'mention'") == 0
        assert await count(d, "type = 'other'") == 1, "an interleaved write was rolled back with the batch"
    run(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
