"""Chat overlay for an OBS browser source on a running instance.

Over HTTP and WebSocket against the staged server (real logins, the real chat socket, the real /ws/overlay): the
owner makes an overlay link (the token is in the URL fragment, shown once, never in the status route); the overlay
page is the same for a real and an unknown id and carries no-store, no-referrer, noindex and a CSP without
'unsafe-inline'; a socket that sends the token as its first frame receives the history and then a message a member
posts in that stream's chat, and a delete by the owner (a moderator of that chat) removes it; a socket whose token
is wrong, or that sends none, or that is signed in with the owner's cookie but sends no token, is closed with the
one code 4401; the token is refused by the other credential paths and by /ws/chat; a raw TLS client that
completes the handshake and then never reads does not delay a member's message (the delivery time is measured and
printed); regenerating the token closes the old socket at once (the time is printed) and the old token is
refused; revoking does the same; a stream's deletion closes its overlay socket; failed tokens from one address end
in 429 on the upgrade; the server log has no token after all of it.

Users and streams carry random suffixes and every assertion is about those rows, so the module also holds on a
stage started from a copy of a production database. It needs no admin password and dials nothing outside.

No browser is started here: a browser dials hosts of its maker on its own (updates, accounts, dictionaries), and a smoke
check dials nothing outside this machine. The page script is run against a fake DOM in tests/test_overlay_client.py
(the real overlay.js, loaded the way a browser loads it); here the page's policy is only checked as text, for the
connect-src 'self' that lets the page's own wss connection through.

Not proven here: OBS or any browser drawing the page, Cloudflare in front of a long-lived socket, a real encoder,
a congested network (the stalled client is a raw socket on loopback; chat is limited to 5 messages in 5 seconds
per member, so this module cannot send enough to fill the kernel buffers: tests/test_overlay.py does that
in-process and shows the stalled socket being dropped).
"""
import asyncio
import json
import re
import secrets
import socket
import ssl
import time

import aiohttp

PW = "Overlay-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "viewer"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def _stall(host, port, token, ready, stop_after):
    """A client that finishes the TLS and WebSocket handshakes, sends the token and then never reads."""
    import base64
    import os
    raw = socket.socket()
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    raw.connect((host, port))
    cx = ssl.create_default_context()
    cx.check_hostname = False
    cx.verify_mode = ssl.CERT_NONE
    s = cx.wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET /ws/overlay HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(1024)
    payload = json.dumps({"type": "auth", "token": token}).encode()
    mask = os.urandom(4)
    s.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    ready.set()
    time.sleep(stop_after)
    s.close()


async def run(ctx):
    pre = "ov" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    if rc != 0 or _result(out) is None:
        ctx.ok("overlay: setup", False, out[-500:])
        return
    base = ctx.base_url
    ws_base = base.replace("https://", "wss://")
    port = int(base.rsplit(":", 1)[1])
    streams = []
    tokens = []

    def ok(name, passed, detail=""):
        ctx.ok("overlay: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    class Sock:
        def __init__(self, ws):
            self.ws, self.frames, self.code = ws, [], None
            self.task = asyncio.create_task(self._pump())

        async def _pump(self):
            # The code is the one in the server's close frame. The client library's own close_code can read 1006
            # when the server drops the TCP connection right after that frame, before the library's reply.
            try:
                while True:
                    m = await self.ws.receive()
                    if m.type == aiohttp.WSMsgType.TEXT:
                        self.frames.append(json.loads(m.data))
                    elif m.type == aiohttp.WSMsgType.CLOSE:
                        self.code = m.data
                        break
                    elif m.type in (aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
            except Exception:
                pass
            if self.code is None:
                self.code = self.ws.close_code

        async def wait(self, pred, start=0, timeout=8.0):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                for f in self.frames[start:]:
                    if pred(f):
                        return f
                await asyncio.sleep(0.02)
            return None

        async def closed(self, timeout=5.0):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if self.task.done():
                    return True
                await asyncio.sleep(0.02)
            return False

    async def overlay(sess, token, **kw):
        ws = await sess.ws_connect(ws_base + "/ws/overlay", **kw)
        if token is not None:
            await ws.send_json({"type": "auth", "token": token})
        return Sock(ws)

    async with ctx.http() as owner, ctx.http() as viewer, ctx.http() as obs:
        socks = []
        try:
            for name, sess in (("owner", owner), ("viewer", viewer)):
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "s", "is_public": True})
            if st != 201:
                ok("stream is created", False, f"{st} {b}")
                return
            stream = b["stream"]
            sid = stream["id"]
            streams.append(sid)
            st, detail = await call(owner, "GET", f"/api/streams/{sid}")
            cid = (detail or {}).get("stream", {}).get("chat_channel_id")
            ok("the stream has a chat channel of its own", bool(cid), str(detail)[:200])
            if not cid:
                return

            # ---- the link
            st, status0 = await call(owner, "GET", f"/api/streams/{sid}/overlay")
            ok("status before a link: inactive", st == 200 and status0["active"] is False and status0["available"] is True, f"{st} {status0}")
            st, made = await call(owner, "POST", f"/api/streams/{sid}/overlay")
            token = ((made or {}).get("url") or "#t=").split("#t=", 1)[1]
            tokens.append(token)
            ok("the owner makes a link, the token in the fragment", st == 200 and token.startswith("ov_") and f"/overlay/stream/{sid}#t=" in made["url"], f"{st} {made}")
            st, status1 = await call(owner, "GET", f"/api/streams/{sid}/overlay")
            ok("status afterwards carries no token", st == 200 and status1["active"] and token not in json.dumps(status1), str(status1))
            st, b = await call(viewer, "POST", f"/api/streams/{sid}/overlay")
            ok("a member who does not own the stream is refused (404)", st == 404, f"{st} {b}")
            st, b = await call(obs, "GET", f"/api/streams/{sid}/overlay", headers={"Authorization": "Bearer " + token})
            ok("the owner routes do not take the token (no session: 401)", st == 401, f"{st} {b}")
            for how, kw in (("bearer", {"headers": {"Authorization": "Bearer " + token}}), ("query", {"params": {"token": token}}),
                            ("api key header", {"headers": {"X-API-Key": token}})):
                st, _b = await call(obs, "GET", "/api/me", **kw)
                if st != 401:
                    ok("the token is refused as a " + how, False, str(st))
                    break
            else:
                ok("the token is refused as a bearer token, a query token and an API key", True)
            paths = []
            for label, method, path, kw, want in (
                    ("calendar feed", "GET", f"/api/streams/schedule/feed/{token}.ics", {}, {404}),
                    ("incoming webhook", "POST", f"/api/webhooks/incoming/{token}", {"json": {"message": "x"}}, {401, 403, 404}),
                    ("playback key", "GET", f"/api/stream/{token}/hls/index.m3u8", {}, {404}),
                    ("publish hook password", "POST", "/api/stream/auth", {"json": {"action": "publish", "path": "live/" + token, "password": token, "ip": "127.0.0.1"}}, {401, 403, 404})):
                st, _b = await call(obs, method, path, **kw)
                paths.append((label, st))
                if st not in want:
                    ok("the token is refused by the " + label + " route", False, str((label, st)))
                    break
            else:
                ok("the token is refused by the calendar feed, incoming webhook, playback key and publish hook routes", True, str(paths))
            ws = await obs.ws_connect(ws_base + "/ws/chat")
            await ws.send_json({"type": "join", "channel_id": cid, "token": token})
            got = []
            try:
                async for m in ws:
                    if m.type == aiohttp.WSMsgType.TEXT:
                        got.append(json.loads(m.data))
            except Exception:
                pass
            ok("/ws/chat does not take the token (no history is sent)", all(f.get("type") == "error" for f in got), str(got)[:200])

            # ---- the page
            heads = []
            for path in (f"/overlay/stream/{sid}", "/overlay/stream/99999999", "/overlay/stream/x"):
                async with obs.get(base + path) as r:
                    heads.append((r.status, await r.text(), {k.lower(): v for k, v in r.headers.items()}))
            h = heads[0][2]
            ok("the overlay page is the same for a real and an unknown id", len({t for _s, t, _h in heads}) == 1 and all(s == 200 for s, _t, _h in heads))
            ok("the page is no-store, no-referrer, noindex, with a CSP that has no unsafe-inline",
               h.get("cache-control") == "no-store" and h.get("referrer-policy") == "no-referrer" and "noindex" in h.get("x-robots-tag", "")
               and "unsafe-inline" not in h.get("content-security-policy", "") and "default-src 'none'" in h.get("content-security-policy", ""), str(h))
            ok("the page's policy lets the page's own socket through (connect-src 'self') and loads nothing from another host",
               "connect-src 'self'" in h.get("content-security-policy", "") and "http" not in h.get("content-security-policy", "")
               and "img-src 'none'" in h.get("content-security-policy", ""), h.get("content-security-policy", ""))
            for asset in ("/static/js/overlay.js?v=3", "/static/css/overlay.css?v=1"):
                async with obs.get(base + asset) as r:
                    if r.status != 200:
                        ok("asset " + asset + " is served", False, str(r.status))
                        break
            else:
                ok("the page's own script and style are served", True)

            # ---- live chat
            vws = await viewer.ws_connect(ws_base + "/ws/chat")
            vsock = Sock(vws)
            socks.append(vsock)
            await vws.send_json({"type": "join", "channel_id": cid})
            ok("the member joins the stream's chat", await vsock.wait(lambda f: f.get("type") == "history") is not None)
            ov = await overlay(obs, token)
            socks.append(ov)
            hist = await ov.wait(lambda f: f.get("type") == "history")
            ok("a socket with the token gets the history frame first", hist is not None and ov.frames[0] is hist, str(ov.frames[:1]))
            text = "smoke " + secrets.token_hex(4) + " <b>bold</b> é"
            t0 = time.monotonic()
            await vws.send_json({"type": "message", "message": text})
            live = await ov.wait(lambda f: f.get("type") == "message" and f.get("text") == text)
            ok("a message the member posts reaches the overlay as text with the name viewers see",
               live is not None and live["name"] == pre + "viewer" and set(live) <= {"type", "id", "name", "text", "time", "badge"}, str(live))
            print(f"note: overlay delivery of one message took {1000 * (time.monotonic() - t0):.0f} ms", flush=True)
            own = await owner.ws_connect(ws_base + "/ws/chat")
            osock = Sock(own)
            socks.append(osock)
            await own.send_json({"type": "join", "channel_id": cid})
            await osock.wait(lambda f: f.get("type") == "history")
            if live:
                await own.send_json({"type": "delete", "message_id": live["id"]})
                gone = await ov.wait(lambda f: f.get("type") == "delete" and f.get("id") == live["id"])
                ok("a message the owner deleted disappears from the overlay", gone == {"type": "delete", "id": live["id"]}, str(gone))
            n = len(ov.frames)
            await vws.send_json({"type": "typing"})
            await asyncio.sleep(0.5)
            ok("typing and member frames never reach the overlay", ov.frames[n:] == [], str(ov.frames[n:]))
            await ov.ws.send_json({"type": "message", "message": "from the overlay"})
            ok("a frame from the overlay client closes it and posts nothing", await ov.closed() and ov.code == 1008, str(ov.code))

            # ---- refusals
            bad = await overlay(obs, "ov_" + secrets.token_urlsafe(32)[:43].ljust(43, "a"))
            socks.append(bad)
            ok("a wrong token gets the one generic code", await bad.closed() and bad.code == 4401, str(bad.code))
            cookie = await overlay(owner, None)
            await cookie.ws.send_json({"type": "join", "channel_id": cid})
            socks.append(cookie)
            ok("a socket signed in with the owner's cookie but with no token gets the same code", await cookie.closed() and cookie.code == 4401, str(cookie.code))

            # ---- a client that never reads
            loop = asyncio.get_running_loop()
            ready = asyncio.Event()
            ev = __import__("threading").Event()
            fut = loop.run_in_executor(None, _stall, "127.0.0.1", port, token, ev, 6)
            for _ in range(100):
                if ev.is_set():
                    break
                await asyncio.sleep(0.05)
            ok("a raw client that never reads is connected", ev.is_set())
            lat = []
            for i in range(4):
                msg = f"after the stall {i} {secrets.token_hex(3)}"
                t0 = time.monotonic()
                await vws.send_json({"type": "message", "message": msg})
                got = await osock.wait(lambda f, m=msg: f.get("type") == "message" and f.get("message") == m)
                lat.append(time.monotonic() - t0 if got else None)
                await asyncio.sleep(1.1)
            ok("a member still gets every message at once while an overlay client never reads (slowest %s ms)"
               % ("%.0f" % (1000 * max(x for x in lat if x is not None)) if any(x is not None for x in lat) else "-"),
               all(x is not None and x < 1.5 for x in lat), str(lat))
            await fut

            # ---- regenerate, revoke, delete
            ov2 = await overlay(obs, token)
            socks.append(ov2)
            await ov2.wait(lambda f: f.get("type") == "history")
            t0 = time.monotonic()
            st, made2 = await call(owner, "POST", f"/api/streams/{sid}/overlay")
            token2 = ((made2 or {}).get("url") or "#t=").split("#t=", 1)[1]
            tokens.append(token2)
            done = await ov2.closed(3.0)
            took = time.monotonic() - t0
            ok("regenerating closes the old socket at once with the generic code (%.0f ms)" % (took * 1000), st == 200 and done and ov2.code == 4401 and took < 2.0, f"{st} {ov2.code} {took}")
            old = await overlay(obs, token)
            socks.append(old)
            ok("the old token is refused", await old.closed() and old.code == 4401 and not old.frames, str(old.code))
            new = await overlay(obs, token2)
            socks.append(new)
            ok("the new token works", await new.wait(lambda f: f.get("type") == "history") is not None)
            st, _b = await call(owner, "DELETE", f"/api/streams/{sid}/overlay")
            ok("revoking closes its socket at once", st == 200 and await new.closed(3.0) and new.code == 4401, f"{st} {new.code}")
            st, made3 = await call(owner, "POST", f"/api/streams/{sid}/overlay")
            token3 = ((made3 or {}).get("url") or "#t=").split("#t=", 1)[1]
            tokens.append(token3)
            last = await overlay(obs, token3)
            socks.append(last)
            await last.wait(lambda f: f.get("type") == "history")
            st, _b = await call(owner, "DELETE", f"/api/streams/{sid}")
            streams.remove(sid)
            ok("deleting the stream closes its overlay socket", st == 200 and await last.closed(3.0) and last.code == 4401, f"{st} {last.code}")
            again = await overlay(obs, token3)
            socks.append(again)
            ok("and its token is refused", await again.closed() and again.code == 4401)

            # ---- failed tokens from one address (last: it limits this address for ten minutes)
            got429 = None
            for _ in range(14):
                try:
                    s = await overlay(obs, "ov_" + "q" * 43)
                    socks.append(s)
                    await s.closed()
                except aiohttp.WSServerHandshakeError as e:
                    got429 = e.status
                    break
            ok("ten failed tokens from one address end in 429 on the upgrade", got429 == 429, str(got429))
            log = ctx.server_log()
            files = []
            try:
                for f in sorted((ctx.stage_dir / "logs").glob("*")):
                    if f.is_file():
                        files.append(f.name)
                        log += f.read_text(errors="replace")
            except OSError:
                pass
            # The staged server logs at INFO (nothing in the stage can raise it), so this is the INFO-level check; the
            # DEBUG-level one, with the portal's own loggers at DEBUG, is in tests/test_overlay.py.
            ok("the stage wrote its log files (a log file was read, not only the server's output)", "portal.log" in files, ", ".join(files) or "none")
            ok("the server output and the log files (%s) have no overlay token after the whole run" % ", ".join(files or ["none"]),
               not any(t and t in log for t in tokens) and not re.search(r"ov_[A-Za-z0-9_-]{43}", log), "")
            ok("and the log redaction never had to act (no marker: no code logged a token)", "OVERLAY_TOKEN_REDACTED" not in log, "")
        finally:
            for s in socks:
                try:
                    await s.ws.close()
                except Exception:
                    pass
            for sid in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{sid}")
                except Exception:
                    pass
