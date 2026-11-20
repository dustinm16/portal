"""Shared setup for the share and grant tests that need the real app on a loopback test
server with a temporary database (tests/test_grant_*.py). Not a test itself.

The terminal plugin is a fake that holds the socket open, so what is proven is that the portal
closes the grantee's socket; no SSH target is involved.
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

import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

PW = "Grant-fix-pass-12345!"
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class HoldPlugin:
    """A plugin that keeps the socket open until the client or the portal closes it."""

    async def handle_websocket(self, ws, target, user_id):
        await ws.send_json({"type": "ready"})
        async for _ in ws:
            pass


async def login(base, name):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with s.post(base + "/login", json={"username": name, "password": PW}) as r:
        assert r.status == 200, (name, r.status)
    return s


async def open_ws(s, base, uuid):
    ws = await s.ws_connect(base.replace("http", "ws") + f"/ws/terminal/{uuid}")
    msg = await asyncio.wait_for(ws.receive(), 3)
    return ws, msg


async def close_code(ws, wait=3.0):
    """The close code the portal ended the socket with, or None if it is still open."""
    try:
        while True:
            msg = await asyncio.wait_for(ws.receive(), wait)
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                return msg.data if msg.type == aiohttp.WSMsgType.CLOSE else ws.close_code
    except asyncio.TimeoutError:
        return None


class Env:
    """A booted app: env.db, env.base, env.uid[name], env.sessions[name] (logged-in)."""


async def boot(names=("owner", "bob", "carol", "adm"), superadmin=("adm",)):
    env = Env()
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    env.db = server.db
    for name in names:
        await create_user(name, PW, is_admin=(name in superadmin))
    for name in superadmin:
        await env.db.set_user_role((await env.db.get_user_by_username(name))["id"], "superadmin")
    env.uid = {n: (await env.db.get_user_by_username(n))["id"] for n in names}
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    env.srv = TestServer(server.create_app(), host="127.0.0.1")
    await env.srv.start_server()
    env.base = f"http://127.0.0.1:{env.srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()
    server.get_plugin = lambda name: HoldPlugin()
    env.sessions = {n: await login(env.base, n) for n in names}
    return env


async def shutdown(env):
    for s in env.sessions.values():
        await s.close()
    await env.srv.close()
    await env.db.conn.close()


async def connection(env, owner, name="box", ctype="ssh", host="93.184.216.34", port=22):
    uuid = await env.db.create_user_connection(env.uid[owner], name, ctype, host, port, "{}")
    cid = (await (await env.db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
    return uuid, cid


def finish(label):
    if failures:
        print(f"\n{label}: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print(f"\n{label}: all checks passed")
