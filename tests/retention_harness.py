"""Shared set-up of the per-channel retention and prune tests: the real chat websocket and HTTP
handlers in-process against a temporary database and a temporary upload folder (only the
authentication lookup is replaced; the caller sends X-Test-User)."""

import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import server  # noqa: E402
from database import Database  # noqa: E402

URL = "/static/uploads/chat/"
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Tok:
    def __init__(self, user_id):
        self.user_id = user_id
        self.token_id = "t%d" % user_id
        self.scopes = ["*"]

    def has_scope(self, scope):
        return False


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    return Tok(int(uid)) if uid else None


async def fake_valid(token):
    return True


class Sock:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    self.events.append(json.loads(msg.data))
        except Exception:
            pass

    async def wait(self, pred, start=0, timeout=4.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.02)
        return None

    async def join(self, channel_id):
        start = len(self.events)
        await self.ws.send_json({"type": "join", "channel_id": channel_id})
        got = await self.wait(lambda e: e.get("type") in ("history", "error"), start)
        assert got and got["type"] == "history", got
        await self.wait(lambda e: e.get("type") == "users", start)

    async def close(self):
        await self.ws.close()
        self.task.cancel()


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}
        self.socks = []

    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        self.up = Path(self.tmp.name) / "uploads"
        self.up.mkdir()
        self.db.chat_upload_dir = str(self.up)
        for name, value in (("db", self.db), ("authenticate_request", fake_auth),
                            ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.voice_state.clear()
        server._prune_tasks.clear()
        server._prune_status.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_put("/api/chat/channels/{id}", server.http_update_chat_channel)
        app.router.add_put("/api/chat/channels/{id}/retention", server.http_set_channel_retention)
        app.router.add_get("/api/chat/channels/{id}/prune", server.http_get_prune_status)
        app.router.add_post("/api/chat/channels/{id}/prune", server.http_prune_chat_channel)
        app.router.add_get("/api/chat/channels", server.http_get_chat_channels)
        app.router.add_get("/api/admin/audit-log", server.http_get_audit_log)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        for s in self.socks:
            try:
                await s.close()
            except Exception:
                pass
        for t in list(server._prune_tasks.values()):
            t.cancel()
        await self.http.close()
        await self.srv.close()
        for name, value in self.saved.items():
            setattr(server, name, value)
        server.chat_rooms.clear()
        await self.db.close()
        self.tmp.cleanup()

    def url(self, path):
        return str(self.srv.make_url(path))

    async def sock(self, user_id):
        ws = await self.http.ws_connect(self.url("/ws/chat"), headers={"X-Test-User": str(user_id)})
        s = Sock(ws)
        self.socks.append(s)
        return s

    async def call(self, method, user_id, path, **kw):
        headers = {"X-Test-User": str(user_id)} if user_id is not None else {}
        async with self.http.request(method, self.url(path), headers=headers, **kw) as r:
            try:
                return r.status, await r.json()
            except Exception:
                return r.status, None

    async def wait_prune(self, channel_id, timeout=10.0):
        task = server._prune_tasks.get(channel_id)
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), timeout)

    # -- data helpers
    async def user(self, name, role=None):
        uid = await self.db.create_user(name, "x")
        if role:
            await self.db.set_user_role(uid, role)
        return uid

    async def message(self, channel_id, user_id, text, days_old=0.0, hours_old=0.0, pinned=False,
                      upload=None, anonymous=False, username="u"):
        mid = await self.db.create_chat_message(
            channel_id, user_id, username, text, anonymous=anonymous,
            **({"attachment_url": URL + upload, "attachment_name": "a.bin", "attachment_type": "application/zip"}
               if upload else {}))
        ts = (datetime.now(timezone.utc) - timedelta(days=days_old, hours=hours_old)).isoformat()
        await self.db.conn.execute("UPDATE chat_messages SET created_at = ?, is_pinned = ? WHERE id = ?",
                                   (ts, 1 if pinned else 0, mid))
        await self.db.conn.execute("UPDATE chat_fts_map SET created_at = ? WHERE message_id = ?", (ts, mid))
        await self.db.conn.commit()
        return mid

    def make_file(self, name):
        (self.up / name).write_bytes(b"x" * 10)
        return name

    async def ids(self, channel_id):
        cur = await self.db.conn.execute("SELECT id FROM chat_messages WHERE channel_id = ?", (channel_id,))
        return {r["id"] for r in await cur.fetchall()}

    async def map_ids(self, channel_id):
        cur = await self.db.conn.execute("SELECT message_id FROM chat_fts_map WHERE channel_id = ?", (channel_id,))
        return {r["message_id"] for r in await cur.fetchall()}

    async def audit(self, action):
        """Audit rows of one action with `details` decoded to a dict (the callers store a JSON string)."""
        rows = await self.db.get_audit_log(limit=200, action=action)
        for r in rows:
            d = r.get("details")
            while isinstance(d, str):
                try:
                    d = json.loads(d)
                except ValueError:
                    break
            r["details"] = d
        return rows


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


def finish(name):
    if failures:
        print(f"\n{name}: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print(f"\n{name}: all checks passed")
