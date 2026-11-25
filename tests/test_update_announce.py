"""An update announcement counts as made only when a hook took it (or the in-portal notice was
raised), not when a delivery was merely started.

The real alerts module and the real server.fire_webhook_event, with system hooks pointed at a
receiver on 127.0.0.1 that answers what the test says; the retry waits run on a fake sleep.
Nothing leaves this machine, nothing listens except that receiver.

Run: venv/bin/python tests/test_update_announce.py
"""

import asyncio
import os
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import alerts  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402

DEADLINE = 90
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


hits = {"/a": 0, "/b": 0}
status = {"/a": 500, "/b": 204}


async def receiver(request):
    await request.read()
    hits[request.path] = hits.get(request.path, 0) + 1
    return web.Response(status=status[request.path], text="no")


DATA = {"portal": {"update_available": True, "latest": "9.9.9", "current": "1.0.0"}}


def deliveries():
    return [t for t in asyncio.all_tasks()
            if getattr(t.get_coro(), "__qualname__", "") == "_deliver_webhook"]


async def main():
    tmp = tempfile.mkdtemp()
    try:
        await body(tmp)
    finally:
        await server.db.close()
        shutil.rmtree(tmp, ignore_errors=True)


async def body(tmp):
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    db = server.db
    await db.conn.execute("INSERT INTO users (username, password_hash) VALUES ('owner', 'x')")
    await db.conn.commit()
    uid = (await (await db.conn.execute("SELECT id FROM users WHERE username='owner'")).fetchone())["id"]
    await db.set_user_role(uid, "superadmin")
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", receiver)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"

    async def fast_sleep(_s):
        await asyncio.sleep(0)
    server._webhook_sleep = fast_sleep

    settings = {}

    async def get(key):
        return settings.get(key)

    async def put(key, value):
        settings[key] = value

    def fresh():
        alerts.reset_state()
        settings.clear()
        server._webhook_rate_limits.clear()
        server._webhook_paused_until.clear()
        alerts.bind(fire=server.fire_webhook_event, notify=None, get_setting=get, set_setting=put)

    async def make_hook(path):
        h = await db.create_webhook(uid, "sys" + path, "outgoing", url=base + path, events=["update.available"],
                                    fmt="generic", allow_private=True, kind="system")
        return h["id"]

    async def settle():
        while alerts._tasks:
            await asyncio.gather(*list(alerts._tasks), return_exceptions=True)
        while deliveries():
            await asyncio.gather(*deliveries(), return_exceptions=True)

    a = await make_hook("/a")

    # ---- a hook that answers 500 on every try (its retries included)
    fresh()
    n = await alerts.note_updates(DATA)
    await settle()
    check("the only hook answers 500: nothing is announced", n == 0, n)
    check("and the version is not remembered, in memory or in the setting",
          not alerts._announced and "9.9.9" not in settings.get(alerts.UPDATE_STATE_KEY, ""), str((alerts._announced, settings)))
    check("the delivery really was tried and retried", hits["/a"] == 4, hits)
    await db.reset_webhook_failures(a)
    n = await alerts.note_updates(DATA)
    await settle()
    check("the next check tries again", n == 0 and hits["/a"] == 8, (n, hits))
    await db.reset_webhook_failures(a)

    # ---- the receiver recovers: the next check announces, the one after is silent
    status["/a"] = 204
    before = hits["/a"]
    n = await alerts.note_updates(DATA)
    await settle()
    check("the receiver took it: announced once", n == 1 and hits["/a"] == before + 1, (n, hits))
    check("and the version is remembered", "9.9.9" in settings.get(alerts.UPDATE_STATE_KEY, ""), str(settings))
    check("a later check sends nothing", await alerts.note_updates(DATA) == 0 and hits["/a"] == before + 1)

    # ---- two hooks, one failing: a delivery succeeded, so it is announced
    status["/a"] = 500
    status["/b"] = 204
    b = await make_hook("/b")
    fresh()
    await db.reset_webhook_failures(a)
    n = await alerts.note_updates(DATA)
    await settle()
    check("one hook fails, one takes it: announced", n == 1 and "9.9.9" in settings.get(alerts.UPDATE_STATE_KEY, ""), (n, settings))
    await db.disable_webhook(b)
    await db.reset_webhook_failures(a)

    # ---- the wait must not cut the retry chain short
    status["/a"] = 500
    fresh()
    await db.reset_webhook_failures(a)
    gate = asyncio.Event()

    async def slow_sleep(_s):
        await gate.wait()
    server._webhook_sleep = slow_sleep
    server._WEBHOOK_CONFIRM_WAIT = 0.3
    before = hits["/a"]
    n = await asyncio.wait_for(alerts.note_updates(DATA), 20)
    check("a delivery still waiting for its retry: not announced", n == 0 and not alerts._announced, (n, alerts._announced))
    live = deliveries()
    check("the retry chain is still alive after the wait gave up", len(live) == 1 and not live[0].done(), len(live))
    gate.set()
    await settle()
    check("and it ran to its end (first try plus three retries)", hits["/a"] == before + 4, (before, hits))
    server._webhook_sleep = fast_sleep

    await settle()
    await srv.close()


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check(f"finished within {DEADLINE} s", False)
if failures:
    print(f"{len(failures)} failed")
    sys.exit(1)
print("all passed")
