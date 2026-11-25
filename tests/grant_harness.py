"""Shared setup for the share and grant tests that need the real app on a loopback test
server with a temporary database (tests/test_grant_*.py). Not a test itself.

The terminal plugin is a fake that holds the socket open, so what is proven is that the portal
closes the grantee's socket; no SSH target is involved.
"""

import asyncio
import atexit
import os
import shutil
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


_STATIC_COPY = None


def _isolate_static():
    """Point the app at a temporary copy of static/ so nothing a test uploads (chat files, thumbnails, emotes) is
    written into the checkout. The files are copied (a link would let a test change the checkout, and the static
    route does not follow links); static/uploads starts empty. The whole folder is removed at exit."""
    root = Path(tempfile.mkdtemp(prefix="portal-test-static-"))
    global _STATIC_COPY
    _STATIC_COPY = root
    atexit.register(shutil.rmtree, root, True)
    real = Path(server.STATIC_DIR)
    (root / "static").mkdir()
    for src in real.rglob("*"):
        rel = src.relative_to(real)
        if rel.parts[0] == "uploads":
            continue
        dst = root / "static" / rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        shutil.copy2(src, dst)
    uploads = root / "static" / "uploads"
    (uploads / "chat").mkdir(parents=True)
    # The upload handlers build their folders from the module's own location, so the module is placed in the
    # temporary folder (with a copy of server.py, which a few tests read); STATIC_DIR is where the app reads files from.
    shutil.copy2(server.__file__, root / "server.py")
    server.__file__ = str(root / "server.py")
    server.STATIC_DIR = root / "static"
    return root / "static"


STATIC_DIR = _isolate_static()
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
    env.db.chat_upload_dir = str(STATIC_DIR / "uploads" / "chat")
    env.static = STATIC_DIR
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


def run(main, deadline):
    """Run the async test body under a deadline. When it raises or runs out of time, print the failure and
    leave the process at once: the database thread of a booted app is not a daemon, so a plain exit would
    wait for it forever and the test would hang instead of failing."""
    try:
        asyncio.run(asyncio.wait_for(main(), deadline))
    except BaseException as e:
        import traceback
        traceback.print_exc()
        print(f"\nFAIL: the test did not run to the end ({type(e).__name__}: {e})", flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
        if _STATIC_COPY is not None:
            shutil.rmtree(_STATIC_COPY, ignore_errors=True)     # os._exit skips the atexit clean-up
        os._exit(1)


def finish(label):
    if failures:
        print(f"\n{label}: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print(f"\n{label}: all checks passed")
