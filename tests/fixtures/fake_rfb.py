"""A fake RFB 3.8 server (and control socket) on unix sockets, for tests and for stage mode.

It speaks just enough of the protocol for a client or a bridge to talk to: version handshake, security type
None, ServerInit 800x600 with a fixed name, one small raw rectangle for every FramebufferUpdateRequest. It
records every client message it receives (the tests read `records`), can send ServerCutText, and can be told
to stall (stop answering update requests).

The optional control socket answers the unit supervisor's operations: one JSON line per request,
{"op":"ping"} and {"op":"resize","w":..,"h":..} get {"ok": true}, {"op":"type","text":..} gets {"ok": true, "typed": n,
"skipped": 0, "complete": true} (n = the characters of the text; `type_reply` replaces the whole answer, None gives the answer of
an older unit, {"ok": false}), {"op":"clip"} gets {"ok": true, "text": CLIP_TEXT,
"truncated": false} (a fixed demo text, so the "Copy from the browser" path can be shown in stage mode), anything
else {"ok": false}.

    srv = FakeRfb("/tmp/x/vnc.sock", ctl_path="/tmp/x/ctl.sock")
    await srv.start(); ...; await srv.stop()

Only the standard library is used.
"""

import asyncio
import json
import os
import struct

SERVER_NAME = b"rbrowser-fake"
WIDTH = 800
HEIGHT = 600
RECT_W = 4
RECT_H = 4
RECT_PIXEL = b"\x10\x20\x30\x00"
CLIP_TEXT = "fake clipboard text"

_PIXEL_FORMAT = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)


class FakeRfb:
    def __init__(self, path, ctl_path=None, stall=False):
        self.path = str(path)
        self.ctl_path = str(ctl_path) if ctl_path else None
        self.type_reply = "default"
        self.stall = stall
        self.records = []            # [(message type, whole message bytes)] after the handshake
        self.handshake = []          # [version line, security choice, client init] of the last client
        self.connections = 0
        self.ctl_requests = []       # raw request lines seen on the control socket
        self._servers = []
        self._writers = set()

    async def start(self):
        for p in (self.path, self.ctl_path):
            if p and os.path.lexists(p):
                os.unlink(p)
        srv = await asyncio.start_unix_server(self._client, path=self.path)
        os.chmod(self.path, 0o600)
        self._servers.append(srv)
        if self.ctl_path:
            csrv = await asyncio.start_unix_server(self._ctl, path=self.ctl_path, limit=1 << 17)
            os.chmod(self.ctl_path, 0o600)
            self._servers.append(csrv)

    async def stop(self):
        for w in list(self._writers):
            try:
                w.close()
            except Exception:
                pass
        for s in self._servers:
            s.close()
        for s in self._servers:
            try:
                await asyncio.wait_for(s.wait_closed(), 2)
            except Exception:
                pass
        self._servers = []
        for p in (self.path, self.ctl_path):
            if p and os.path.lexists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def message_types(self):
        return [t for t, _ in self.records]

    async def send_cut_text(self, text: bytes):
        """ServerCutText to every connected client."""
        msg = struct.pack(">B3xI", 3, len(text)) + text
        for w in list(self._writers):
            w.write(msg)
            await w.drain()

    async def _client(self, reader, writer):
        self._writers.add(writer)
        self.connections += 1
        try:
            writer.write(b"RFB 003.008\n")
            version = await reader.readexactly(12)
            writer.write(bytes([1, 1]))                 # one security type: None
            sec = await reader.readexactly(1)
            writer.write(struct.pack(">I", 0))          # SecurityResult OK
            init = await reader.readexactly(1)
            self.handshake = [version, sec, init]
            writer.write(struct.pack(">HH", WIDTH, HEIGHT) + _PIXEL_FORMAT
                         + struct.pack(">I", len(SERVER_NAME)) + SERVER_NAME)
            await writer.drain()
            while True:
                head = await reader.readexactly(1)
                t = head[0]
                if t == 0:
                    rest = await reader.readexactly(19)
                elif t == 2:
                    h = await reader.readexactly(3)
                    (n,) = struct.unpack(">H", h[1:3])
                    rest = h + await reader.readexactly(4 * n)
                elif t == 3:
                    rest = await reader.readexactly(9)
                elif t == 4:
                    rest = await reader.readexactly(7)
                elif t == 5:
                    rest = await reader.readexactly(5)
                elif t == 6:
                    h = await reader.readexactly(7)
                    (n,) = struct.unpack(">I", h[3:7])
                    rest = h + await reader.readexactly(n)
                else:
                    self.records.append((t, head))
                    break                               # unknown type: a real server drops the client
                self.records.append((t, head + rest))
                if t == 3 and not self.stall:
                    writer.write(struct.pack(">BxH", 0, 1)
                                 + struct.pack(">HHHHi", 0, 0, RECT_W, RECT_H, 0)
                                 + RECT_PIXEL * (RECT_W * RECT_H))
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            try:
                writer.close()
            except Exception:
                pass

    async def _ctl(self, reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            self.ctl_requests.append(line)
            ok = False
            reply = None
            if 0 < len(line) <= 70000:
                try:
                    req = json.loads(line)
                    if isinstance(req, dict) and req.get("op") == "type":
                        if isinstance(req.get("text"), str):
                            if self.type_reply == "default":
                                reply = {"ok": True, "typed": len(req["text"]), "skipped": 0, "complete": True}
                            else:
                                reply = self.type_reply
                    elif len(line) <= 4096:
                        ok = isinstance(req, dict) and req.get("op") in ("ping", "resize", "clip")
                        if ok and req.get("op") == "clip":
                            reply = {"ok": True, "text": CLIP_TEXT, "truncated": False}
                except ValueError:
                    ok = False
            writer.write(json.dumps(reply if reply is not None else {"ok": ok}).encode() + b"\n")
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
