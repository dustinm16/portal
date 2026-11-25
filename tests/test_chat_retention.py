"""A fractional stored chat retention counts as no own value, like the route helper does.

database.py selects the channels with their own retention with the same rule as server._own_retention_value
(int() of the value, above 0): 0.5 is no value, so that channel follows the global setting instead of being
left out of both passes.

Run: venv/bin/python tests/test_chat_retention.py
"""

import os
import signal
import sys

from retention_harness import (check, finish, run, server)  # noqa: E402


def _deadline(signum, frame):
    print("FAIL: test_chat_retention timed out", flush=True)
    os._exit(1)


def test_fractional_retention_follows_global():
    async def body(env):
        d = env.db
        uid = await env.user("poster")
        half = await d.create_chat_channel("half", created_by=uid)
        three = await d.create_chat_channel("three", created_by=uid)
        fhalf = await d.create_chat_channel("fhalf", created_by=uid)
        await d.conn.execute("UPDATE chat_channels SET retention_days = 0.5 WHERE id = ?", (half,))
        await d.conn.execute("UPDATE chat_channels SET retention_days = 3 WHERE id = ?", (three,))
        await d.conn.execute("UPDATE chat_channels SET file_retention_days = 0.5 WHERE id = ?", (fhalf,))
        await d.conn.commit()
        m = {}
        m["half_old"] = await env.message(half, uid, "older than global", days_old=8)
        m["half_new"] = await env.message(half, uid, "inside global", days_old=3)
        m["three_old"] = await env.message(three, uid, "older than its own", days_old=4)
        m["three_new"] = await env.message(three, uid, "inside its own", days_old=2)
        own = {c["name"] for c in await d.get_channels_with_own_retention()}
        check("only the channel with a whole number of days has its own retention", own == {"three"}, str(own))
        files = {c["name"] for c in await d.get_channels_with_file_retention()}
        check("a fractional file retention is no value either", "fhalf" not in files, str(files))
        cfg = await d.get_retention_config()
        await server._run_chat_retention(cfg, {"files": 0, "bytes": 0})
        left = {c: await env.ids(c) for c in (half, three)}
        check("the 0.5 channel follows the global 7 days: 8 day old message gone, 3 day old kept",
              m["half_old"] not in left[half] and m["half_new"] in left[half])
        check("the 3 day channel uses its own value",
              m["three_old"] not in left[three] and m["three_new"] in left[three])
    run(body)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(90)
    test_fractional_retention_follows_global()
    finish("test_chat_retention")
