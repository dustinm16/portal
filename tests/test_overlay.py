"""Chat overlay for an OBS browser source (1.24.0): token routes, /ws/overlay, the fan-out and the page.

Runs the real handlers in-process (only the authentication lookup is replaced) against a temporary database.

* the reducer lets through only the five allow-listed frame types and the few fields a renderer needs
* the owner makes, regenerates and revokes the token; only a hash is stored; the token is shown once
* /ws/overlay: first-frame token within a few seconds, one generic close code, failed tokens rate limited per
  address, sockets per token capped, nothing a client sends is acted on, the session cookie is never read
* live frames of that one channel only; a moderator's delete removes a message; an anonymous post carries no identity
* regenerate and revoke close the old sockets at once; stream delete closes them
* a socket that never reads cannot delay broadcast_to_channel (a fake that never completes, and a raw socket that
  completes the handshake and never reads)
* no log record carries the token

Run: venv/bin/python tests/test_overlay.py
"""

import asyncio
import base64
import json
import logging
import os
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402,F401
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, make_mocked_request  # noqa: E402

import overlay_chat  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402

import logger as portal_logger  # noqa: E402

# Logging for the whole file, at DEBUG level, in two places: the portal's own file handler (with its redaction filter)
# in a temporary directory, and a handler of ours that sees every record as it was written, redaction or not. The
# portal's own loggers are set to DEBUG explicitly, so nothing is hidden by a level.
LOG_TMP = tempfile.TemporaryDirectory()
portal_logger.setup_logging(level="DEBUG", log_dir=Path(LOG_TMP.name), console_enabled=False, file_enabled=True)
for _name in list(logging.root.manager.loggerDict):
    if _name in ("portal", "database", "server", "overlay_chat", "aiosqlite") or _name.startswith("portal."):
        logging.getLogger(_name).setLevel(logging.DEBUG)
logging.getLogger("portal").setLevel(logging.DEBUG)


class Everything(logging.Handler):
    """Every record of the whole file as written (message, arguments, traceback), before any redaction."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.text = []
        self.names = set()
        self.debug_records = 0
        self.fmt = logging.Formatter("%(name)s %(levelname)s %(message)s")

    def emit(self, record):
        try:
            self.text.append(self.fmt.format(record))
        except Exception:
            self.text.append(str(record.msg))
        self.names.add(record.name)
        if record.levelno == logging.DEBUG:
            self.debug_records += 1


EVERYTHING = Everything()
logging.getLogger().handlers.insert(0, EVERYTHING)     # first: the portal's handlers redact the record in place
ALL_TOKENS: set = set()          # every overlay token this file made or sent, good or bad

failed = []


def reset_manage_rate():
    rate = getattr(server, "_overlay_manage_rate", None)      # absent before the limiter was added
    if rate is not None:
        rate._hits.clear()


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ("" if ok else f"  ({detail})"), flush=True)
    if not ok:
        failed.append(name)


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


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception:
            self.lines.append(str(record.msg))


class Chat:
    """A normal chat member socket that keeps every frame."""

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

    async def wait(self, pred, start=0, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.01)
        return None

    async def join(self, channel_id):
        await self.ws.send_json({"type": "join", "channel_id": channel_id})
        got = await self.wait(lambda e: e.get("type") in ("history", "error"))
        assert got and got["type"] == "history", got

    async def say(self, text):
        n = len(self.events)
        await self.ws.send_json({"type": "message", "message": text})
        return await self.wait(lambda e: e.get("type") == "message" and e.get("message") == text, n)


class Overlay:
    """An overlay socket: sends the token as its first frame and keeps every frame and the close code."""

    def __init__(self, ws):
        self.ws = ws
        self.frames = []
        self.code = None
        self.task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            while True:
                msg = await self.ws.receive()
                if msg.type == aiohttp.WSMsgType.TEXT:
                    self.frames.append(json.loads(msg.data))
                elif msg.type == aiohttp.WSMsgType.CLOSE:
                    self.code = msg.data          # the code in the server's close frame
                    break
                elif msg.type in (aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        if self.code is None:
            self.code = self.ws.close_code

    async def wait(self, pred, start=0, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for f in self.frames[start:]:
                if pred(f):
                    return f
            await asyncio.sleep(0.01)
        return None

    async def closed(self, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.task.done():
                return True
            await asyncio.sleep(0.01)
        return False


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}
        self.extra = []

    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth), ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.overlay_subscribers.clear()
        server._overlay_fail_hits.clear()
        server._overlay_pending.clear()
        self.ids = {}
        for name in ("owner", "viewer", "other"):
            self.ids[name] = await self.db.create_user(name, "x")
        reset_manage_rate()
        for name, role in (("mod", "moderator"), ("adm", "superadmin")):
            self.ids[name] = await self.db.create_user(name, "x")
            await self.db.set_user_role(self.ids[name], role)
        self.cid = await self.db.create_chat_channel("strm", created_by=self.ids["owner"])
        self.sid = await self.db.create_user_stream(self.ids["owner"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                                    is_public=True)
        await self.db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (self.cid, self.sid))
        # a second stream of the same owner, and its own chat: a token of one must never show the other
        self.cid2 = await self.db.create_chat_channel("strm2", created_by=self.ids["owner"])
        self.sid2 = await self.db.create_user_stream(self.ids["owner"], "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24,
                                                     is_public=True)
        await self.db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (self.cid2, self.sid2))
        await self.db.conn.commit()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/ws/overlay", server.handle_overlay_websocket)
        app.router.add_get("/overlay/stream/{id}", server.http_overlay_page)
        app.router.add_get("/api/streams/{id}/overlay", server.http_overlay_status)
        app.router.add_post("/api/streams/{id}/overlay", server.http_overlay_create)
        app.router.add_delete("/api/streams/{id}/overlay", server.http_overlay_revoke)
        app.router.add_delete("/api/streams/{id}", server.http_delete_user_stream)
        app.router.add_get("/api/admin/audit-log", server.http_get_audit_log)
        app.router.add_delete("/api/users/{id}", server.http_delete_user)
        app.router.add_post("/api/webhooks/incoming/{token}", server.http_incoming_webhook)
        app.router.add_post("/api/me/password", server.http_change_password)
        app.router.add_post("/api/users/{id}/reset-password", server.http_reset_user_password)
        app.router.add_post("/api/users/{id}/sessions/revoke", server.http_admin_revoke_user_sessions)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        for s in self.extra:
            try:
                await s.ws.close()
                s.task.cancel()
            except Exception:
                pass
        await self.http.close()
        await self.srv.close()
        for name, value in self.saved.items():
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.overlay_subscribers.clear()
        await self.db.close()
        self.tmp.cleanup()

    def url(self, path):
        return str(self.srv.make_url(path))

    async def call(self, method, user, path, **kw):
        headers = {"X-Test-User": str(self.ids[user])} if user else {}
        headers.update(kw.pop("headers", {}))
        async with self.http.request(method, self.url(path), headers=headers, **kw) as r:
            try:
                body = await r.json()
            except Exception:
                body = None
            if isinstance(body, dict) and "#t=" in str(body.get("url") or ""):
                ALL_TOKENS.add(body["url"].split("#t=", 1)[1])
            return r.status, body

    async def chat(self, user):
        ws = await self.http.ws_connect(self.url("/ws/chat"), headers={"X-Test-User": str(self.ids[user])})
        c = Chat(ws)
        self.extra.append(c)
        return c

    async def make_token(self, sid=None):
        status, body = await self.call("POST", "owner", f"/api/streams/{sid or self.sid}/overlay")
        assert status == 200, (status, body)
        return body["url"].split("#t=", 1)[1], body

    async def overlay(self, token, **kw):
        ws = await self.http.ws_connect(self.url("/ws/overlay"), **kw)
        if token is not None:
            ALL_TOKENS.add(str(token))
            await ws.send_json({"type": "auth", "token": token})
        o = Overlay(ws)
        self.extra.append(o)
        return o


def run(body, deadline=None):
    """Run one body against a fresh Env. A body that has a deadline prints FAIL and ends when it does not finish
    in time: a slow-client body whose broadcast has become blocking would otherwise hang the whole file. The second
    guard is a timer thread, for a body that blocks the loop itself (a cancelled await cannot end that)."""
    async def go():
        cap = Capture()
        logging.getLogger().addHandler(cap)
        logging.getLogger().setLevel(logging.DEBUG)
        try:
            async with Env() as env:
                env.cap = cap
                if deadline is None:
                    await body(env)
                    return
                try:
                    await asyncio.wait_for(body(env), deadline)
                except asyncio.TimeoutError:
                    check(f"{body.__name__} finished within its {deadline} s deadline", False,
                          "the broadcast to a stalled overlay client waits for it")
        finally:
            logging.getLogger().removeHandler(cap)

    guard = None
    if deadline is not None:
        def give_up():
            print(f"FAIL: {body.__name__} did not finish in {deadline + 10} s and did not stop when cancelled", flush=True)
            os._exit(1)
        guard = threading.Timer(deadline + 10, give_up)
        guard.daemon = True
        guard.start()
    try:
        asyncio.run(go())
    finally:
        if guard is not None:
            guard.cancel()


# ---------------------------------------------------------------------------------------------------- reducer
def reducer():
    r = overlay_chat.reduce_frame
    full = {"type": "message", "id": 5, "user_id": 9, "username": "Alice", "nickname": "Alice", "role": "admin", "anonymous": False,
            "avatar": {"x": 1}, "message": "hi :) \U0001F600", "channel": "c", "channel_id": 3, "created_at": "2026-01-01T00:00:00+00:00",
            "stream_role": "owner", "image_url": "/static/uploads/chat/a.png", "attachment_url": "/x", "reply_preview": {"a": 1}}
    out = r(full)
    check("a message keeps id, name, badge, text and time only",
          out == {"type": "message", "id": 5, "name": "Alice", "text": "hi :) \U0001F600", "time": "2026-01-01T00:00:00+00:00", "badge": "owner"}, out)
    anon = r({**full, "anonymous": True, "user_id": None})
    check("an anonymous message is named Anonymous and has no badge", anon["name"] == "Anonymous" and "badge" not in anon, anon)
    check("a go-live card and a message without text are not shown",
          r({**full, "message_type": "stream_card"}) is None and r({**full, "message": "  "}) is None)
    for kind in ("user_joined", "user_left", "users", "typing", "user_banned", "user_timed_out", "user_muted", "reaction_update",
                 "message_pinned", "poll_created", "stream_status", "channel_renamed", "user_nickname_changed", "history", "error",
                 "slowmode_changed", "user_status_changed", "channel_activity", "dm", "notification"):
        if r({"type": kind, "message_id": 1, "id": 1, "message": "x", "ids": [1]}) is not None:
            check(f"{kind} is not an overlay frame", False)
            break
    else:
        check("only the five allow-listed types pass; presence, typing, members, moderation and everything else is dropped", True)
    check("delete, edit, prune and clear are reduced",
          r({"type": "message_deleted", "message_id": 3, "deleted_by": 77}) == {"type": "delete", "id": 3}
          and r({"type": "message_edited", "message_id": 3, "message": "t", "edited_at": "x"}) == {"type": "edit", "id": 3, "text": "t"}
          and r({"type": "messages_pruned", "channel": "c", "ids": [1, 2, "x", True]}) == {"type": "prune", "ids": [1, 2]}
          and r({"type": "channel_cleared", "cleared_by": "boss", "message_count": 4}) == {"type": "clear"})
    check("a token is 43 url-safe characters after ov_, and only its hash is a hash", overlay_chat.wellformed(overlay_chat.new_token())
          and not overlay_chat.wellformed("ov_short") and not overlay_chat.wellformed("sf_" + "a" * 43)
          and len(overlay_chat.hash_token("ov_x")) == 64)


# ---------------------------------------------------------------------------------------------------- routes
async def routes_body(env):
    s, b = await env.call("GET", "owner", f"/api/streams/{env.sid}/overlay")
    check("status before a token: inactive, no token", s == 200 and b["active"] is False and "url" not in b, (s, b))
    s, b = await env.call("POST", "other", f"/api/streams/{env.sid}/overlay")
    check("somebody else's stream answers 404", s == 404, (s, b))
    s, b = await env.call("POST", None, f"/api/streams/{env.sid}/overlay")
    check("no credential: 401", s == 401, (s, b))
    s, b = await env.call("POST", None, f"/api/streams/{env.sid}/overlay", headers={"X-Stream-Key": "live_" + "a" * 24})
    check("a stream key is refused with 403", s == 403, (s, b))
    s, b = await env.call("POST", "owner", "/api/streams/99999/overlay")
    check("an unknown stream answers 404", s == 404, (s, b))
    token, body = await env.make_token()
    check("create returns the link with the token in the fragment, once",
          overlay_chat.wellformed(token) and "/overlay/stream/%d#t=" % env.sid in body["url"] and body["max_sockets"] == 3, body)
    s, b = await env.call("GET", "owner", f"/api/streams/{env.sid}/overlay")
    check("status afterwards: active, created, never the token or its hash",
          b["active"] and b["created_at"] and token not in json.dumps(b) and overlay_chat.hash_token(token) not in json.dumps(b), b)
    cur = await env.db.conn.execute("SELECT * FROM stream_overlay_tokens")
    rows = [dict(r) for r in await cur.fetchall()]
    check("one row per stream, hash only", len(rows) == 1 and rows[0]["token_hash"] == overlay_chat.hash_token(token)
          and token not in json.dumps(rows), rows)
    token2, _ = await env.make_token()
    cur = await env.db.conn.execute("SELECT COUNT(*) FROM stream_overlay_tokens WHERE stream_id = ?", (env.sid,))
    check("creating again replaces the token (one active)", token2 != token and (await cur.fetchone())[0] == 1)
    s, b = await env.call("DELETE", "other", f"/api/streams/{env.sid}/overlay")
    cur = await env.db.conn.execute("SELECT COUNT(*) FROM stream_overlay_tokens")
    check("somebody else cannot revoke it", s == 404 and (await cur.fetchone())[0] == 1, (s, b))
    s, b = await env.call("DELETE", "owner", f"/api/streams/{env.sid}/overlay")
    cur = await env.db.conn.execute("SELECT COUNT(*) FROM stream_overlay_tokens")
    check("revoke removes it", s == 200 and (await cur.fetchone())[0] == 0, (s, b))
    # a stream whose chat is a default channel is not "its own chat"
    await env.db.conn.execute("UPDATE chat_channels SET is_default = 1 WHERE id = ?", (env.cid2,))
    await env.db.conn.commit()
    s, b = await env.call("POST", "owner", f"/api/streams/{env.sid2}/overlay")
    check("a stream with no chat of its own cannot get an overlay (409)", s == 409, (s, b))
    await env.db.conn.execute("UPDATE chat_channels SET is_default = 0 WHERE id = ?", (env.cid2,))
    await env.db.conn.commit()


# ---------------------------------------------------------------------------------------------------- page
async def page_body(env):
    texts = set()
    heads = None
    for path in (f"/overlay/stream/{env.sid}", "/overlay/stream/999999", "/overlay/stream/abc"):
        async with env.http.get(env.url(path)) as r:
            texts.add(await r.text())
            heads = r.headers
            st = r.status
    check("the page is the same for every id", len(texts) == 1 and st == 200)
    html = texts.pop()
    h = {k.lower(): v for k, v in heads.items()}
    csp = h.get("content-security-policy", "")
    check("page headers: no-store, no-referrer, noindex, a strict CSP",
          h.get("cache-control") == "no-store" and h.get("referrer-policy") == "no-referrer"
          and "noindex" in h.get("x-robots-tag", "") and "unsafe-inline" not in csp and "default-src 'none'" in csp
          and "script-src 'self'" in csp and "img-src 'none'" in csp and "frame-ancestors 'none'" in csp, h)
    check("the page has no portal navbar, portal.js, theme.js, inline script, inline handler or cookie code",
          "portal.js" not in html and "theme.js" not in html and "navbar" not in html and "onclick" not in html.lower()
          and not re.search(r"<script(?![^>]*\bsrc=)", html) and "cookie" not in html.lower() and 'name="robots" content="noindex' in html, html)
    js = (ROOT / "static" / "js" / "overlay.js").read_text()
    check("the script never assigns innerHTML, never reads cookies, never puts the token in a path or query",
          not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.cookie|eval\(|\.src\s*=|location\.search|replaceState", js)
          and "/ws/overlay'" in js, "")
    async with env.http.get(env.url("/overlay/stream/1?t=ov_" + "a" * 43)) as r:
        check("a token in a query is not read by the page route", r.status == 200)


# ---------------------------------------------------------------------------------------------------- socket
async def socket_body(env):
    viewer = await env.chat("viewer")
    owner = await env.chat("owner")
    await viewer.join(env.cid)
    await owner.join(env.cid)
    await env.db.create_chat_message(env.cid, env.ids["viewer"], "viewer", "before the overlay")
    anon_id = await env.db.create_chat_message(env.cid, env.ids["other"], "other", "an old anonymous line", anonymous=True)
    await env.db.create_chat_message(env.cid2, env.ids["viewer"], "viewer", "other stream line")
    token, _ = await env.make_token()
    ov = await env.overlay(token)
    hist = await ov.wait(lambda f: f.get("type") == "history")
    texts = [m["text"] for m in (hist or {}).get("messages", [])]
    check("on connect: the history of that one channel", "before the overlay" in texts and "other stream line" not in texts, hist)
    anon = [m for m in hist["messages"] if m["text"] == "an old anonymous line"]
    check("history: an anonymous post is Anonymous and carries no id or account field",
          anon and anon[0]["name"] == "Anonymous" and set(anon[0]) <= {"id", "name", "text", "time"}, anon)
    check("history rows carry only id, name, text, time (and badge)", all(set(m) <= {"id", "name", "text", "time", "badge"} for m in hist["messages"]), hist)
    # live: a message, then a delete by the stream's owner (a moderator of its chat)
    n = len(ov.frames)
    mine = await viewer.say("hello obs \U0001F600 http://example.invalid/x.png")
    got = await ov.wait(lambda f: f.get("type") == "message" and "hello obs" in f.get("text", ""), n)
    check("a live message is rendered text with the name viewers see", got and got["name"] == "viewer" and set(got) <= {"type", "id", "name", "text", "time", "badge"}, got)
    await owner.ws.send_json({"type": "delete", "message_id": got["id"]})
    gone = await ov.wait(lambda f: f.get("type") == "delete" and f.get("id") == got["id"], n)
    check("a message a moderator deleted is told to the overlay as a delete of that id alone", gone == {"type": "delete", "id": got["id"]}, gone)
    # edit by author
    m2 = await viewer.say("typo")
    await viewer.ws.send_json({"type": "edit_message", "message_id": m2["id"], "message": "fixed"})
    ed = await ov.wait(lambda f: f.get("type") == "edit" and f.get("id") == m2["id"], n)
    check("an edit reaches the overlay as id and text", ed and ed["text"] == "fixed", ed)
    # an anonymous post live
    await env.db.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (env.ids["viewer"],))
    await env.db.conn.commit()
    server.chat_user_state[env.ids["viewer"]]["anonymous"] = True
    n2 = len(ov.frames)
    await viewer.say("secret author")
    an = await ov.wait(lambda f: f.get("type") == "message" and f.get("text") == "secret author", n2)
    check("a live anonymous post shows no author identity at all",
          an and an["name"] == "Anonymous" and "viewer" not in json.dumps(an) and set(an) == {"type", "id", "name", "text", "time"}, an)
    # nothing but messages: typing, joins, presence, other channels
    n3 = len(ov.frames)
    await viewer.ws.send_json({"type": "typing"})
    other = await env.chat("other")
    await other.join(env.cid)
    await server.broadcast_to_channel("strm", {"type": "users", "users": [{"id": 1, "username": "x"}]})
    await server.broadcast_to_channel("strm", {"type": "user_banned", "user_id": 5, "reason": "r"})
    await server.broadcast_to_channel("strm2", {"type": "message", "id": 777, "username": "z", "message": "elsewhere", "created_at": "t"})
    await asyncio.sleep(0.3)
    check("typing, joins, member lists, bans and other channels never reach the overlay", ov.frames[n3:] == [], ov.frames[n3:])
    # a prune and a clear
    await server.broadcast_to_channel("strm", {"type": "messages_pruned", "channel": "strm", "ids": [anon_id]})
    pr = await ov.wait(lambda f: f.get("type") == "prune", n3)
    check("a prune names the ids and nothing else", pr == {"type": "prune", "ids": [anon_id]}, pr)
    server._overlay_clear("strm")
    cl = await ov.wait(lambda f: f.get("type") == "clear", n3)
    check("a clear reaches the overlay even with nobody in the room", cl == {"type": "clear"})
    check("overlay sockets are in overlay_subscribers and never in chat_rooms",
          sum(len(v) for v in server.overlay_subscribers.values()) == 1
          and all(not isinstance(e[0], overlay_chat.Subscriber) for room in server.chat_rooms.values() for e in room))
    # anything the client sends closes the socket
    await ov.ws.send_json({"type": "message", "message": "I am a client"})
    check("a frame after the first closes the socket (nothing is acted on)", await ov.closed() and ov.code == overlay_chat.CLOSE_POLICY, ov.code)
    cur = await env.db.conn.execute("SELECT COUNT(*) FROM chat_messages WHERE message = 'I am a client'")
    check("and nothing was posted", (await cur.fetchone())[0] == 0)
    # the room still works
    n4 = len(viewer.events)
    check("the chat room is unaffected", await owner.say("still fine") is not None)


async def refusal_body(env):
    token, _ = await env.make_token()
    # a signed-in owner (header stands for the session cookie) without a token is still refused: no cookie is read
    ov = await env.overlay(None, headers={"X-Test-User": str(env.ids["owner"]), "Cookie": "session=whatever"})
    await ov.ws.send_json({"type": "join", "channel_id": env.cid})
    check("the session is never read: a signed-in socket without a token gets the generic code", await ov.closed() and ov.code == 4401, ov.code)
    codes = []
    for bad in ("ov_" + "a" * 43, "nonsense", token[:-1] + ("A" if token[-1] != "A" else "B")):
        o = await env.overlay(bad)
        await o.closed()
        codes.append(o.code)
    check("a bad or unknown token: one generic code", set(codes) == {4401}, codes)
    # first frame must arrive in time
    old = overlay_chat.AUTH_TIMEOUT
    overlay_chat.AUTH_TIMEOUT = 0.3
    try:
        o = await env.overlay(None)
        t0 = time.monotonic()
        await o.closed()
        check("no first frame within the time: closed with the same code", o.code == 4401 and time.monotonic() - t0 < 3, o.code)
    finally:
        overlay_chat.AUTH_TIMEOUT = old
    # binary or oversize first frame
    ws = await env.http.ws_connect(env.url("/ws/overlay"))
    await ws.send_bytes(b"\x00" * 10)
    o = Overlay(ws)
    env.extra.append(o)
    check("a binary first frame is refused", await o.closed() and o.code == 4401, o.code)
    # failed tokens per address: the limit then answers 429 on the upgrade, through the shared limiter
    server._overlay_fail_hits.clear()
    got429 = False
    for i in range(14):
        try:
            o = await env.overlay("ov_" + "b" * 43)
            await o.closed()
        except aiohttp.WSServerHandshakeError as e:
            got429 = e.status == 429
            break
    check("after ten failed tokens an address is answered 429", got429)
    async with env.http.get(env.url("/ws/overlay")) as r:
        check("429 carries Retry-After and no-store", r.status == 429 and r.headers.get("Retry-After") and r.headers.get("Cache-Control") == "no-store")
    server._overlay_fail_hits.clear()
    # a good token still works after the table is cleared (the limit is per failure)
    o = await env.overlay(token)
    check("a good token works", await o.wait(lambda f: f.get("type") == "history") is not None)
    # cap per token
    socks = [o]
    for _ in range(2):
        x = await env.overlay(token)
        await x.wait(lambda f: f.get("type") == "history")
        socks.append(x)
    extra = await env.overlay(token)
    check("a fourth socket on one token is turned away", await extra.closed() and extra.code == overlay_chat.CLOSE_SLOW, extra.code)
    check("the cap is three", overlay_chat.MAX_SOCKETS_PER_TOKEN == 3)


async def lifecycle_body(env):
    token, _ = await env.make_token()
    a = await env.overlay(token)
    b = await env.overlay(token)
    await a.wait(lambda f: f.get("type") == "history")
    await b.wait(lambda f: f.get("type") == "history")
    t0 = time.monotonic()
    new, _ = await env.make_token()
    ok = await asyncio.gather(a.closed(1.5), b.closed(1.5))
    check("regenerating closes the old sockets at once with the generic code", all(ok) and a.code == 4401 and b.code == 4401 and time.monotonic() - t0 < 1.5, (a.code, b.code))
    old = await env.overlay(token)
    check("the old token is refused", await old.closed() and old.code == 4401 and not old.frames)
    c = await env.overlay(new)
    check("the new token works", await c.wait(lambda f: f.get("type") == "history") is not None)
    s, _ = await env.call("DELETE", "owner", f"/api/streams/{env.sid}/overlay")
    check("revoking closes the socket at once", s == 200 and await c.closed(1.5) and c.code == 4401, c.code)
    again = await env.overlay(new)
    check("a revoked token is refused", await again.closed() and again.code == 4401 and not again.frames)
    # stream delete
    tok3, _ = await env.make_token()
    d = await env.overlay(tok3)
    await d.wait(lambda f: f.get("type") == "history")
    s, _ = await env.call("DELETE", "owner", f"/api/streams/{env.sid}")
    check("deleting the stream closes the socket", s == 200 and await d.closed(1.5) and d.code == 4401, (s, d.code))
    cur = await env.db.conn.execute("SELECT COUNT(*) FROM stream_overlay_tokens")
    check("and the token row is gone", (await cur.fetchone())[0] == 0)
    gone = await env.overlay(tok3)
    check("the token of a deleted stream is refused", await gone.closed() and gone.code == 4401)
    # owner account removed: the backstop pass and the explicit close
    tok4, _ = await env.make_token(env.sid2)
    e = await env.overlay(tok4)
    await e.wait(lambda f: f.get("type") == "history")
    await env.db.delete_user(env.ids["owner"])
    check("an account's deletion removes its token", (await (await env.db.conn.execute("SELECT COUNT(*) FROM stream_overlay_tokens")).fetchone())[0] == 0)
    n = await server._overlay_revalidate_pass()
    check("the revalidation pass closes the socket of a token that no longer resolves", n == 1 and await e.closed(1.5) and e.code == 4401, (n, e.code))
    f2 = await env.overlay(tok4)
    check("and the token is refused", await f2.closed() and f2.code == 4401)


async def other_routes_body(env):
    token, _ = await env.make_token()
    bearer = make_mocked_request("GET", "/api/me", headers={"Authorization": "Bearer " + token})
    apikey = make_mocked_request("GET", "/api/me", headers={"X-API-Key": token})
    query = make_mocked_request("GET", "/api/me?token=" + token + "&ticket=" + token)
    cookie = make_mocked_request("GET", "/api/me", headers={"Cookie": f"session={token}; token={token}; web_session={token}"})
    saved = server.authenticate_request
    server.authenticate_request = env.saved["authenticate_request"]
    try:
        results = []
        for name, req in (("bearer", bearer), ("api key", apikey), ("query", query), ("cookie", cookie)):
            try:
                results.append((name, await server.authenticate_request(req)))
            except web.HTTPException as e:
                results.append((name, None))
    finally:
        server.authenticate_request = saved
    check("every other credential path refuses an overlay token", all(r is None for _n, r in results), results)
    # first frame of /ws/chat
    ws = await env.http.ws_connect(env.url("/ws/chat"))
    await ws.send_json({"type": "join", "channel_id": env.cid, "token": token})
    frames = []
    try:
        async for m in ws:
            if m.type == aiohttp.WSMsgType.TEXT:
                frames.append(json.loads(m.data))
    except Exception:
        pass
    check("the chat socket does not take it either (no history, an error only)", all(f.get("type") == "error" for f in frames) and token not in json.dumps(frames), frames)
    # the overlay socket answers nothing to a user's credential and the owner routes need a user
    s, _ = await env.call("GET", None, f"/api/streams/{env.sid}/overlay", headers={"Authorization": "Bearer " + token})
    check("the owner routes do not take an overlay token", s == 401, s)


# ---------------------------------------------------------------------------------------------------- webhook lines
async def webhook_body(env):
    """A message an incoming webhook posts is shown to a viewer of the chat, so the overlay shows it too: live and in the
    history it is given on connect, under the name viewers see ("[hook] name")."""
    hook = await env.db.create_webhook(env.ids["owner"], "Deploy bot", "incoming", channel_id=env.cid)
    path = "/api/webhooks/incoming/" + hook["token"]
    st, _b = await env.call("POST", None, path, json={"content": "build 41 passed", "username": "CI"})
    check("the incoming webhook accepted the first message", st == 200, st)
    token, _ = await env.make_token()
    ov = await env.overlay(token)
    hist = await ov.wait(lambda f: f.get("type") == "history")
    old = [m for m in (hist or {}).get("messages", []) if m["text"] == "build 41 passed"]
    check("a webhook message posted before the overlay connected is in its history, named as in the chat",
          len(old) == 1 and old[0]["name"] == "[hook] CI" and "badge" not in old[0], hist)
    n = len(ov.frames)
    st, _b = await env.call("POST", None, path, json={"text": "build 42 failed"})
    live = await ov.wait(lambda f: f.get("type") == "message" and f.get("text") == "build 42 failed", n)
    check("a live webhook message reaches the overlay under the same kind of name, and with no other field",
          live is not None and live["name"] == "[hook] Deploy bot" and set(live) <= {"type", "id", "name", "text", "time", "badge"}, live)
    again = await env.overlay(token)
    hist2 = await again.wait(lambda f: f.get("type") == "history")
    names = [(m["name"], m["text"]) for m in (hist2 or {}).get("messages", [])]
    check("and a reconnect shows both, live and history alike", ("[hook] CI", "build 41 passed") in names and ("[hook] Deploy bot", "build 42 failed") in names, names)
    # other kinds are still not shown
    await env.db.create_chat_message(env.cid, env.ids["viewer"], "viewer", "a card", message_type="stream_card")
    third = await env.overlay(token)
    hist3 = await third.wait(lambda f: f.get("type") == "history")
    check("a go-live card is still not shown", all(m["text"] != "a card" for m in hist3["messages"]), hist3)
    # the other stream's overlay never gets it
    token2, _ = await env.make_token(env.sid2)
    other = await env.overlay(token2)
    h4 = await other.wait(lambda f: f.get("type") == "history")
    check("a webhook line of one stream's chat is not in another stream's overlay", all("build" not in m["text"] for m in h4["messages"]), h4)


# ---------------------------------------------------------------------------------------------------- credentials changed
async def credentials_body(env):
    """The overlay link ends with the owner's old credentials, exactly as the calendar link does since 1.23.0: a password
    change, an administrator's reset and an administrator signing the owner out everywhere, and the sockets of that
    token are closed at once. Somebody else's link and a refused change leave it alone."""
    env.ids["boss"] = await env.db.create_user("boss", "x")
    await env.db.conn.execute("UPDATE users SET role = 'superadmin', is_admin = 1 WHERE id = ?", (env.ids["boss"],))
    await env.db.update_password_hash(env.ids["owner"], server.hash_password("old-password-1"))
    cid3 = await env.db.create_chat_channel("strm3", created_by=env.ids["other"])
    sid3 = await env.db.create_user_stream(env.ids["other"], "s3", "live_" + "e" * 24, public_key="pub_" + "f" * 24, is_public=True)
    await env.db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid3, sid3))
    await env.db.conn.commit()
    st, body = await env.call("POST", "other", f"/api/streams/{sid3}/overlay")
    other_token = body["url"].split("#t=", 1)[1]
    other_sock = await env.overlay(other_token)
    await other_sock.wait(lambda f: f.get("type") == "history")

    async def state(token):
        _s, b = await env.call("GET", "owner", f"/api/streams/{env.sid}/overlay")
        probe = await env.overlay(token)
        got = await probe.wait(lambda f: f.get("type") == "history", timeout=1.0)
        if got is None:
            await probe.closed(2.0)
        else:
            await probe.ws.close()          # the token allows three sockets at a time
        return b["active"], got is not None, probe.code

    async def fresh():
        token, _ = await env.make_token()
        sock = await env.overlay(token)
        await sock.wait(lambda f: f.get("type") == "history")
        return token, sock

    token, sock = await fresh()
    check("(control) the link works", await state(token) == (True, True, None))
    st, _ = await env.call("POST", "owner", "/api/me/password", json={"current_password": "wrong-password", "new_password": "new-password-22"})
    check("(control) a refused password change leaves the overlay link alone", st == 401 and (await state(token))[:2] == (True, True), st)
    st, _ = await env.call("POST", "boss", f"/api/users/{env.ids['viewer']}/reset-password", json={"new_password": "Reset-by-admin-1"})
    check("(control) an administrator resetting somebody else's password leaves it alone", st == 200 and (await state(token))[:2] == (True, True), st)
    t0 = time.monotonic()
    st, _ = await env.call("POST", "owner", "/api/me/password", json={"current_password": "old-password-1", "new_password": "new-password-22"})
    closed = await sock.closed(3.0)
    check("changing the password ends the overlay link: no link, the old token refused, its open socket closed at once with 4401",
          st == 200 and (await state(token)) == (False, False, 4401) and closed and sock.code == 4401, f"{st} {sock.code}")
    print("note: password change to socket closed: %.0f ms" % ((time.monotonic() - t0) * 1000), flush=True)
    check("and the other member's link is untouched", not other_sock.ws.closed and (await env.call("GET", "other", f"/api/streams/{sid3}/overlay"))[1]["active"])
    token, sock = await fresh()
    check("the owner makes a new link afterwards and it works", await state(token) == (True, True, None))
    st, _ = await env.call("POST", "boss", f"/api/users/{env.ids['owner']}/reset-password", json={"new_password": "Reset-by-admin-2"})
    check("an administrator's password reset ends it and closes its socket",
          st == 200 and await sock.closed(3.0) and sock.code == 4401 and (await state(token))[:2] == (False, False), st)
    token, sock = await fresh()
    st, b = await env.call("POST", "boss", f"/api/users/{env.ids['owner']}/sessions/revoke")
    check("an administrator signing the owner out everywhere ends it and closes its socket",
          st == 200 and await sock.closed(3.0) and sock.code == 4401 and (await state(token))[:2] == (False, False), f"{st} {b}")
    check("a stream's other overlay link does not exist afterwards either (every stream of the account)",
          (await env.call("GET", "owner", f"/api/streams/{env.sid2}/overlay"))[1]["active"] is False)
    src = (ROOT / "server.py").read_text()
    for name in ("http_change_password", "http_reset_user_password", "http_admin_revoke_user_sessions"):
        body = src[src.index(f"async def {name}("):]
        body = body[:body.index("\nasync def ", 10)]
        check(f"{name} ends the overlay links where it ends the calendar link", "feed_token_delete" in body and "_overlay_links_end(" in body)
    cli = src[src.index("async def init_admin_user"):]
    branch = cli[cli.index("ADMIN PASSWORD RESET") - 1200:cli.index("ADMIN PASSWORD RESET")]
    check("the command line's admin password reset deletes the overlay links too (a running portal closes the sockets within 30 s)",
          "feed_token_delete(admin[\"id\"])" in branch and "overlay_tokens_delete_for_user(admin[\"id\"])" in branch, branch[-300:])


# ---------------------------------------------------------------------------------------------------- slow clients
class NeverWs:
    """A socket whose send never finishes: a stalled OBS client."""
    closed = False
    close_code = None

    def __init__(self):
        self.sent = 0

    async def send_str(self, data):
        self.sent += 1
        await asyncio.sleep(3600)

    async def close(self, code=1000):
        self.closed = True
        self.close_code = code
        return True


class Member:
    def __init__(self):
        self.closed = False
        self.got = []

    async def send_json(self, payload):
        self.got.append(payload)


async def fake_slow_body(env):
    old = overlay_chat.SEND_TIMEOUT
    overlay_chat.SEND_TIMEOUT = 0.3
    try:
        member = Member()
        server.chat_rooms["strm"] = {(member, env.ids["viewer"], "viewer", "user")}
        ws = NeverWs()
        sub = overlay_chat.Subscriber(ws, None, "strm", env.sid, env.ids["owner"], "d")
        sub.on_dead = server._overlay_remove
        server.overlay_subscribers.setdefault("strm", set()).add(sub)
        sub.writer = asyncio.create_task(sub.run(overlay_chat.encode({"type": "history", "messages": []})))
        await asyncio.sleep(0.05)       # the writer is now inside a send that never completes
        worst = 0.0
        for i in range(300):
            t0 = time.monotonic()
            await server.broadcast_to_channel("strm", {"type": "message", "id": i + 1, "username": "v", "message": "m%d" % i, "created_at": "t"})
            worst = max(worst, time.monotonic() - t0)
        check("a stalled overlay client: 300 broadcasts, the slowest took %.1f ms" % (worst * 1000), worst < 0.05, worst)
        check("and the member got every one of them", len(member.got) == 300)
        await asyncio.sleep(0.8)
        check("the stalled socket was dropped (queue full or send timeout) and closed", sub.dead and ws.closed and sub not in server.overlay_subscribers.get("strm", ()), (sub.dead, ws.closed))
        check("the registry is clean", "strm" not in server.overlay_subscribers)
    finally:
        overlay_chat.SEND_TIMEOUT = old
        server.chat_rooms.clear()


def _ws_text_frame(payload: bytes) -> bytes:
    mask = os.urandom(4)
    head = bytes([0x81, 0x80 | len(payload)]) if len(payload) < 126 else bytes([0x81, 0x80 | 126]) + len(payload).to_bytes(2, "big")
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


async def raw_slow_body(env):
    """A real TCP client that completes the WebSocket handshake, sends the token and then never reads."""
    token, _ = await env.make_token()
    old = overlay_chat.SEND_TIMEOUT
    overlay_chat.SEND_TIMEOUT = 0.5
    host, port = "127.0.0.1", env.srv.port
    loop = asyncio.get_running_loop()
    sock = socket.socket()
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    await loop.sock_connect(sock, (host, port))
    key = base64.b64encode(os.urandom(16)).decode()
    await loop.sock_sendall(sock, (f"GET /ws/overlay HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += await asyncio.wait_for(loop.sock_recv(sock, 1024), 5)
    await loop.sock_sendall(sock, _ws_text_frame(json.dumps({"type": "auth", "token": token}).encode()))
    await asyncio.sleep(0.3)
    try:
        member = Member()
        server.chat_rooms["strm"] = {(member, env.ids["viewer"], "viewer", "user")}
        (sub,) = list(server.overlay_subscribers["strm"])
        text = "x" * 900
        worst, sent = 0.0, 0
        t_all = time.monotonic()
        while not sub.dead and sent < 30000 and time.monotonic() - t_all < 40:
            t0 = time.monotonic()
            await server.broadcast_to_channel("strm", {"type": "message", "id": sent + 1, "username": "v", "message": text, "created_at": "t"})
            worst = max(worst, time.monotonic() - t0)
            sent += 1
            if sent % 50 == 0:
                await asyncio.sleep(0.01)
        for _ in range(60):
            if sub.dead:
                break
            await asyncio.sleep(0.1)
        check("a raw client that never reads: %d broadcasts, the slowest took %.1f ms" % (sent, worst * 1000), worst < 0.25, worst)
        check("and the socket was dropped", sub.dead, sent)
        check("every broadcast reached the member", len(member.got) == sent, (len(member.got), sent))
        print("note: raw slow client dropped after %d messages (%.0f KB offered)" % (sent, sent * 0.9), flush=True)
    finally:
        overlay_chat.SEND_TIMEOUT = old
        sock.close()
        server.chat_rooms.clear()


# ---------------------------------------------------------------------------------------------------- source guards
def source_guards():
    src = (ROOT / "server.py").read_text()
    b = src[src.index("async def broadcast_to_channel("):]
    b = b[:b.index("\n\n\n# ----")]
    check("broadcast_to_channel hands to the overlay before the room check and never awaits it",
          b.index("_overlay_fanout(channel, message)") < b.index("if channel not in chat_rooms") and "await _overlay" not in b)
    fan = src[src.index("def _overlay_fanout("):]
    fan = fan[:fan.index("\ndef _overlay_clear")]
    check("_overlay_fanout is synchronous and has no database call", "await" not in fan and "db." not in fan and not fan.startswith("async"))
    h = src[src.index("async def handle_overlay_websocket("):]
    h = h[:h.index("\nasync def _overlay_revalidate_pass")]
    check("the overlay socket never authenticates a user, reads cookies or touches chat_rooms",
          "authenticate_request" not in h and "cookies" not in h and "chat_rooms" not in h and "Cookie" not in h)
    check("the overlay socket never logs a frame", "logger" not in h)
    check("failed tokens go through the shared limiter path", "_limited(request, \"overlay_token\"" in h and "status=429" not in h)
    check("/ws/overlay is registered before the /ws/{path} relay", src.index('"/ws/overlay"') < src.index('"/ws/{path:.*}"'))
    check("the offline wipes tell the overlay", src.count("_overlay_clear(") >= 3)
    check("the registry has no unused task set left over (_overlay_close_tasks): a close is the subscriber's own close_task",
          "_overlay_close_tasks" not in src and "close_task" in (ROOT / "overlay_chat.py").read_text())
    check("no token appears in a log call of the overlay code", not re.search(r"logger\.\w+\([^)]*token", src[src.index("def _overlay_remove"):src.index("\nANON_VOICE_MESSAGE")]))


reducer()
source_guards()
run(routes_body)
run(page_body)
run(socket_body)
run(refusal_body)
run(lifecycle_body)
run(other_routes_body)
run(webhook_body)
run(credentials_body)
# each slow-client body has its own deadline (they take about 3 s each)
run(fake_slow_body, deadline=10)
run(raw_slow_body, deadline=20)


async def new_stream(env, user, name, public=False):
    """A stream of `user` with a chat of its own: (stream id, channel id)."""
    cid = await env.db.create_chat_channel("c-" + name, created_by=env.ids[user])
    sid = await env.db.create_user_stream(env.ids[user], name, "live_" + name.ljust(24, "x")[:24],
                                          public_key="pub_" + name.ljust(24, "y")[:24], is_public=public)
    await env.db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
    await env.db.conn.commit()
    return sid, cid


async def audit_moderator_body(env):
    """Making and revoking an overlay link name the stream; a moderator must not read them, for a stream that is not
    public least of all (it gets 404 on that stream's health route)."""
    sid, _ = await new_stream(env, "owner", "SecretPrivateShow", public=False)
    await env.make_token(sid)
    s, _b = await env.call("DELETE", "owner", f"/api/streams/{sid}/overlay")
    check("(setup) the private stream's link was made and revoked", s == 200, s)
    s, b = await env.call("GET", "adm", "/api/admin/audit-log?limit=200")
    names = [e["action"] for e in b["entries"]]
    check("(control) an administrator reads both entries, with the stream's name",
          s == 200 and "stream_overlay_create" in names and "stream_overlay_revoke" in names
          and any(e.get("target_name") == "SecretPrivateShow" for e in b["entries"]), (s, names))
    for q in ("", "&action=stream_overlay_create", "&action=stream_overlay_revoke", "&target_type=stream"):
        s, b = await env.call("GET", "mod", "/api/admin/audit-log?limit=200" + q)
        text = json.dumps(b)
        check(f"a moderator reads no overlay entry and no stream name from the audit log (filter '{q}')",
              s == 200 and "stream_overlay" not in text and "SecretPrivateShow" not in text, (s, text[:200]))


async def overlay_caps_body(env):
    """Overlay sockets are capped per owner and over the whole portal, not only per token."""
    owner_streams = [await new_stream(env, "owner", f"cap{i}") for i in range(7)]
    other_sid, _ = await new_stream(env, "other", "capother")
    check("(control) the per-owner cap is 9 (three tokens' worth) and the whole-portal cap holds 30 owners' worth of it",
          getattr(server, "_OVERLAY_MAX_PER_OWNER", None) == 9 and overlay_chat.MAX_SOCKETS_PER_TOKEN <= 9
          and server._OVERLAY_MAX_TOTAL >= 30 * server._OVERLAY_MAX_PER_OWNER)
    opened, refused = [], []
    for sid, _cid in owner_streams:
        tok, _ = await env.make_token(sid)
        for _ in range(3):
            o = await env.overlay(tok)
            await asyncio.sleep(0.02)
            await o.wait(lambda f: f.get("type") == "history", timeout=1.0)
            (opened if o.frames else refused).append(o)
    count = sum(len(v) for v in server.overlay_subscribers.values())
    check("21 sockets of one owner over seven streams: 9 are served, the rest closed with 1013",
          len(opened) == 9 and len(refused) == 12 and count == 9, (len(opened), len(refused), count))
    check("the refused one got the 'too many' close code",
          bool(refused) and await refused[0].closed() and refused[0].code == overlay_chat.CLOSE_SLOW, len(refused))
    # one owner at the cap does not take the room of another one: the whole-portal cap is a backstop
    s, made = await env.call("POST", "other", f"/api/streams/{other_sid}/overlay")
    tok = made["url"].split("#t=", 1)[1]
    got = []
    for _ in range(3):
        o = await env.overlay(tok)
        await asyncio.sleep(0.02)
        await o.wait(lambda f: f.get("type") == "history", timeout=1.0)
        got.append(o)
    check("another owner is served in full while the first owner sits at the per-owner cap",
          all(o.frames for o in got) and sum(len(v) for v in server.overlay_subscribers.values()) == 12,
          (len([o for o in got if o.frames]), sum(len(v) for v in server.overlay_subscribers.values())))
    # the whole-portal cap, lowered for the test so that it needs few sockets
    other_sid2, _ = await new_stream(env, "other", "capother2")
    saved = getattr(server, "_OVERLAY_MAX_TOTAL", 300)
    server._OVERLAY_MAX_TOTAL = 12
    try:
        s, made2 = await env.call("POST", "other", f"/api/streams/{other_sid2}/overlay")
        o = await env.overlay(made2["url"].split("#t=", 1)[1])
        await asyncio.sleep(0.02)
        await o.wait(lambda f: f.get("type") == "history", timeout=1.0)
        check("a socket over the whole-portal cap is refused although its owner has room",
              not o.frames and await o.closed() and o.code == overlay_chat.CLOSE_SLOW and
              sum(len(v) for v in server.overlay_subscribers.values()) == 12, (o.frames, o.code))
    finally:
        server._OVERLAY_MAX_TOTAL = saved
    # closing sockets frees room
    await env.call("DELETE", "owner", f"/api/streams/{owner_streams[0][0]}/overlay")
    await asyncio.sleep(0.2)
    check("closed sockets leave the count", sum(len(v) for v in server.overlay_subscribers.values()) < 12)


async def overlay_rate_body(env):
    """Making a link has a limiter on the shared path; revoking one never does."""
    reset_manage_rate()
    statuses = []
    for i in range(23):
        s, b = await env.call("POST", "owner", f"/api/streams/{env.sid}/overlay")
        statuses.append(s)
    check("the 21st make in a minute is refused with 429, the first 20 are not",
          statuses[:20] == [200] * 20 and statuses[20:] == [429] * 3, statuses)
    s, b = await env.call("DELETE", "owner", f"/api/streams/{env.sid}/overlay")
    check("a revoke works although the budget of making is spent (a leaked link must be revocable)",
          s == 200 and b == {"active": False}, (s, b))
    s, info = await env.call("GET", "owner", f"/api/streams/{env.sid}/overlay")
    check("the link is gone after that revoke", s == 200 and info["active"] is False, (s, info))
    again = [(await env.call("DELETE", "owner", f"/api/streams/{env.sid}/overlay"))[0] for _ in range(40)]
    check("revoking over and over is never refused", again == [200] * 40, again)
    cur = await env.db.conn.execute("SELECT action, COUNT(*) FROM audit_log WHERE action LIKE 'stream_overlay%' GROUP BY action")
    rows = {a: c for a, c in await cur.fetchall()}
    check("one audit entry per link made and one for the one link that was revoked, none for revokes of nothing",
          rows == {"stream_overlay_create": 20, "stream_overlay_revoke": 1}, rows)
    s, b = await env.call("POST", "other", f"/api/streams/{env.sid}/overlay")
    check("(control) another account is not held by it (404 for somebody else's stream, not 429)", s == 404, (s, b))
    reset_manage_rate()


async def delete_forgets_body(env):
    """A deleted stream (or an account's streams) leaves nothing in the in-memory live-state maps."""
    sid, _ = await new_stream(env, "other", "gone1")
    sid2, _ = await new_stream(env, "viewer", "gone2")
    for x in (sid, sid2):
        server._stream_sessions[x] = {"id": 900 + x, "at": 0.0, "ended": False, "ended_at": None, "path": None}
        server._end_claims[x] = {"session": server._stream_sessions[x]}
        server._relay_stop_held.add(x)
        server._recorder_errors[x] = (0.0, "x")
    s, b = await env.call("DELETE", "other", f"/api/streams/{sid}")
    check("(setup) the stream was deleted", s == 200, (s, b))
    check("deleting a stream forgets its session, end claim, relay hold and recorder error",
          sid not in server._stream_sessions and sid not in server._end_claims and sid not in server._relay_stop_held
          and sid not in server._recorder_errors, "")
    check("(control) another stream's entries are kept", sid2 in server._stream_sessions and sid2 in server._relay_stop_held)
    s, b = await env.call("DELETE", "adm", f"/api/users/{env.ids['viewer']}")
    check("(setup) the account was deleted", s == 200, (s, b))
    check("deleting an account forgets the same for its streams",
          sid2 not in server._stream_sessions and sid2 not in server._end_claims and sid2 not in server._relay_stop_held
          and sid2 not in server._recorder_errors, "")


async def shutdown_refuses_body(env):
    """A server that is stopping accepts no new overlay socket (503 before the upgrade, which the page retries); once
    it is not stopping any more, the same token is served."""
    token, _ = await env.make_token()
    server._shutting_down = True
    try:
        status = None
        try:
            await env.overlay(token)
        except aiohttp.WSServerHandshakeError as e:
            status = e.status
        check("while the server stops, a new overlay socket is refused with 503", status == 503, status)
        async with env.http.get(env.url("/ws/overlay")) as r:
            check("the refusal says when to try again and is not cached", r.headers.get("Retry-After") and r.headers.get("Cache-Control") == "no-store")
        check("(nothing was registered)", not any(overlay_subscribers_of(token)))
    finally:
        server._shutting_down = False
    o = await env.overlay(token)
    await o.wait(lambda f: f.get("type") == "history", timeout=2.0)
    check("(control) the same token is served when the server is not stopping", bool(o.frames))
    stop_src = __import__("inspect").getsource(server.PortalServer.stop)
    check("stop() sets the flag before it does anything else", stop_src.index("_shutting_down = True") < stop_src.index("_ask_prunes_to_stop()"))


def overlay_subscribers_of(token):
    digest = overlay_chat.hash_token(token)
    return [s for subs in server.overlay_subscribers.values() for s in subs if s.digest == digest]


run(audit_moderator_body)
run(overlay_caps_body)
run(overlay_rate_body)
run(delete_forgets_body)
run(shutdown_refuses_body, deadline=20)


async def log_body(env):
    token, _ = await env.make_token()
    o = await env.overlay(token)
    await o.wait(lambda f: f.get("type") == "history")
    v = await env.chat("viewer")
    await v.join(env.cid)
    await v.say("a line")
    bad = await env.overlay("ov_" + "z" * 43)
    await bad.closed()
    await env.call("POST", "owner", f"/api/streams/{env.sid}/overlay")
    await asyncio.sleep(0.2)
    text = "\n".join(env.cap.lines)
    # (at DEBUG level, aiosqlite logs the statements it runs, hash parameter included; the hash is not the credential)
    check("no log record of a full run, at DEBUG level, carries a token (good or bad)", token not in text and "ov_" + "z" * 43 not in text, "")
    from logger import redact
    check("the log redactor removes an overlay token anyway", token not in redact("GET /x?y=" + token + " ok") and "[OVERLAY_TOKEN_REDACTED]" in redact("a " + token))


run(log_body)


def whole_run_log():
    """After every body above (tokens made, sent, refused, regenerated, revoked; slow clients; credentials changed): the
    log of the whole file, at DEBUG level, holds no token."""
    logging.getLogger("portal").debug("canary: a debug line of a portal logger")
    logging.getLogger("portal.database").debug("canary: a debug line of the database logger")
    for h in logging.getLogger().handlers:
        h.flush()
    files = sorted(Path(LOG_TMP.name).glob("*.log*"))
    in_files = "\n".join(f.read_text(errors="replace") for f in files if f.is_file())
    # the one request this file makes with a token-shaped value in a query string, on purpose (page_body): its access line
    # carries it as written, and the file's redaction removes it (checked below); every other record is checked as written
    seen = "\n".join(l for l in EVERYTHING.text if "GET /overlay/stream/1?t=ov_" + "a" * 43 not in l)
    shape = re.compile(r"ov_[A-Za-z0-9_-]{43}")
    good = {t for t in ALL_TOKENS if overlay_chat.wellformed(t)}
    check("(control) the file saw many tokens: made, sent and refused ones", len(ALL_TOKENS) >= 8 and len(good) >= 6, f"{len(ALL_TOKENS)} {len(good)}")
    check("(control) the log was really written at DEBUG: the portal's own debug lines reached its file and the capture, "
          "and other loggers' debug records were seen too",
          "canary: a debug line of a portal logger" in in_files and "canary: a debug line of the database logger" in in_files
          and "canary: a debug line of a portal logger" in seen and EVERYTHING.debug_records > 20
          and "portal" in EVERYTHING.names, f"{EVERYTHING.debug_records} {sorted(EVERYTHING.names)[:8]}")
    check("(control) the log has the ordinary lines of the run", "User viewer connected" in in_files and "/ws/overlay" in in_files, in_files[:200])
    check("no log file of the whole run, at DEBUG level, holds an overlay token, good or bad", not any(t in in_files for t in ALL_TOKENS) and not shape.search(in_files), "")
    check("and no record as written (before redaction) holds one", not any(t in seen for t in ALL_TOKENS) and not shape.search(seen), "")
    marked = [l for l in in_files.splitlines() if "OVERLAY_TOKEN_REDACTED" in l]
    check("the redactor acted only for the one request this file made on purpose, a token in a query string of the page (the "
          "access log; the portal's own code never logged a token)",
          len(marked) == 1 and "GET /overlay/stream/" in marked[0] and "?t=[OVERLAY_TOKEN_REDACTED]" in marked[0], marked[:3])
    check("(control) a leak would show: the same checks find a token written to a portal logger",
          (lambda t: t in "portal " + t and shape.search("x " + t) is not None)(next(iter(good))))


whole_run_log()

check("the outbound guard refused no dial", not outbound_guard.refused, str(outbound_guard.refused))
if failed:
    print(f"\ntest_overlay: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_overlay: all checks passed")
