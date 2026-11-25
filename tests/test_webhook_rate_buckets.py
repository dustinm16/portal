"""The per-hook rate window is split in two: ordinary events (chat, stream, member events) and
ops alerts. A member spamming chat can fill the event window of a hook without starving an
alert that goes to the same hook, and the other way round.

The receiver is a local aiohttp server on 127.0.0.1; nothing leaves this machine.

Run: venv/bin/python tests/test_webhook_rate_buckets.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import alerts  # noqa: E402
import server  # noqa: E402

failures = []
DEADLINE = 60


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


got = []


async def receiver(request):
    got.append(request.path)
    return web.Response(status=204)


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    db = server.db
    app = web.Application()
    app.router.add_post("/{tail:.*}", receiver)
    rsrv = TestServer(app, host="127.0.0.1")
    await rsrv.start_server()
    base = f"http://127.0.0.1:{rsrv.port}"
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", 1)}), frozenset())
    alerts.reset_state()
    alerts._deliver = lambda *a, **k: None
    limit = server._WEBHOOK_RATE_LIMIT

    async def fresh(name):
        h = await db.create_webhook(None, name, "outgoing", url=base + "/" + name, events=["role.changed", "message.created"],
                                    kind="system", allow_private=True)
        return await db.get_webhook_for_delivery(h["id"])

    # chat spam fills the event window, an alert on the same hook still goes out
    hook = await fresh("a")
    for _ in range(limit):
        r = await server._deliver_webhook(hook, "message.created", {"x": 1})
        assert r["sent"], r
    r = await server._deliver_webhook(hook, "message.created", {"x": 1})
    check("the event window of the hook is full", r["error"] == "rate limited", str(r))
    del got[:]
    r = await server._deliver_webhook(hook, "role.changed", {"title": "t"})
    check("an alert is still delivered when the event window is full", r["sent"] and r["success"] and got == ["/a"], str((r, got)))

    # alerts fill their own window, ordinary events still go out
    hook = await fresh("b")
    for _ in range(limit):
        r = await server._deliver_webhook(hook, "role.changed", {"title": "t"})
        assert r["sent"], r
    r = await server._deliver_webhook(hook, "role.changed", {"title": "t"})
    check("the alert window of the hook is full", r["error"] == "rate limited", str(r))
    del got[:]
    r = await server._deliver_webhook(hook, "message.created", {"x": 1})
    check("an ordinary event is still delivered when the alert window is full", r["sent"] and r["success"] and got == ["/b"], str((r, got)))

    # two hooks do not share a window
    other = await fresh("c")
    r = await server._deliver_webhook(other, "role.changed", {"title": "t"})
    check("another hook has its own windows", r["sent"], str(r))

    # deleting a hook forgets both windows
    class _Req:
        match_info = {"id": str(hook["id"])}
    server._webhook_rate_limits.setdefault((hook["id"], "alert"), [1.0])
    server._webhook_rate_forget(hook["id"])
    check("forgetting a hook clears both of its windows",
          not any((k[0] if isinstance(k, tuple) else k) == hook["id"] for k in server._webhook_rate_limits))

    await rsrv.close()
    await db.conn.close()
    print()
    print("FAILED: " + ", ".join(failures) if failures else "all checks passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        _rc = asyncio.run(asyncio.wait_for(main(), DEADLINE))
    except BaseException as exc:   # a regression prints FAIL and exits, it never hangs on the db thread
        print(f"FAIL: test aborted with {type(exc).__name__}: {exc}", flush=True)
        os._exit(1)
    outbound_guard.report("test_webhook_rate_buckets")
    sys.exit(_rc)
