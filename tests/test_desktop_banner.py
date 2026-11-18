"""VNC banner peek: bytes read from the server are never lost, a host that is
not VNC is recognised, silence is not an error.

Run: venv/bin/python tests/test_desktop_banner.py
"""

import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from plugins import vnc  # noqa: E402


def run(coro):
    return asyncio.run(coro)


async def peek_after(chunks, eof=False, timeout=0.5):
    """Feed chunks (bytes, or a float to pause) into a reader and peek."""
    reader = asyncio.StreamReader()

    async def feeder():
        for c in chunks:
            if isinstance(c, float):
                await asyncio.sleep(c)
            else:
                reader.feed_data(c)
                await asyncio.sleep(0)
        if eof:
            reader.feed_eof()

    task = asyncio.ensure_future(feeder())
    result = await vnc.peek_banner(reader, timeout=timeout)
    await task
    return result, reader


# --- defaults ---------------------------------------------------------------
assert vnc.BANNER_PEEK_TIMEOUT == 5.0
assert vnc.CLOSE_RDP_HOST != vnc.CLOSE_NOT_VNC
for code, reason in vnc.CLOSE_REASONS.items():
    assert 4000 <= code <= 4999 and len(reason) <= 123
assert b"RDP" in vnc.CLOSE_REASONS[vnc.CLOSE_RDP_HOST]

# --- a whole RFB banner in one segment: only four bytes consumed, rest stays -
(data, eof), reader = run(peek_after([b"RFB 003.008\nmore"]))
assert data == b"RFB " and not eof, (data, eof)
assert vnc.classify_banner(data) == "rfb"

# --- fragmented delivery keeps every byte, in order -------------------------
async def fragmented():
    reader = asyncio.StreamReader()

    async def feeder():
        for part in (b"R", b"F", b"B", b" 003.008\n"):
            reader.feed_data(part)
            await asyncio.sleep(0.02)

    task = asyncio.ensure_future(feeder())
    first, eof = await vnc.peek_banner(reader, timeout=2)
    await task
    tail = await reader.read(100)
    return first, eof, tail

first, eof, tail = run(fragmented())
assert first + tail == b"RFB 003.008\n", (first, tail)
assert first == b"RFB " and not eof

# --- two bytes then a pause: consumed bytes are returned, not dropped -------
t0 = time.monotonic()
(data, eof), _ = run(peek_after([b"RF"], timeout=0.3))
assert data == b"RF" and not eof
assert 0.25 <= time.monotonic() - t0 < 1.5
assert vnc.classify_banner(data) == "rfb"

# --- silence: nothing consumed, waits about the timeout ---------------------
t0 = time.monotonic()
(data, eof), _ = run(peek_after([], timeout=0.3))
assert data == b"" and not eof
assert 0.25 <= time.monotonic() - t0 < 1.5
assert vnc.classify_banner(data) == "silent"

# --- server closes without speaking -----------------------------------------
(data, eof), _ = run(peek_after([], eof=True, timeout=2))
assert data == b"" and eof

# --- close after a partial banner: the partial bytes come back --------------
(data, eof), _ = run(peek_after([b"RF"], eof=True, timeout=2))
assert data == b"RF" and eof

# --- not VNC: decided at once, no wait for the timeout ----------------------
t0 = time.monotonic()
(data, eof), _ = run(peek_after([b"SSH-2.0-OpenSSH_9.2\r\n"], timeout=5))
assert time.monotonic() - t0 < 1.0
assert data.startswith(b"SSH-") and vnc.classify_banner(data) == "other"

(data, eof), _ = run(peek_after([b"HTTP/1.1 400 Bad Request\r\n"], timeout=5))
assert vnc.classify_banner(data) == "other"

# --- RDP style header (TPKT) -------------------------------------------------
(data, eof), _ = run(peek_after([b"\x03\x00\x00\x13\x0e\xd0"], timeout=5))
assert vnc.classify_banner(data) == "rdp"

# --- classify on its own ----------------------------------------------------
assert vnc.classify_banner(b"") == "silent"
assert vnc.classify_banner(b"RFB 003.003\n") == "rfb"
assert vnc.classify_banner(b"R") == "rfb"
assert vnc.classify_banner(b"RFX ") == "other"
assert vnc.classify_banner(b"\x03\x00") == "rdp"



# --- the plugin end to end against local fake servers ------------------------
from plugins.base import ServiceTarget  # noqa: E402
from aiohttp import WSMsgType  # noqa: E402


class FakeWS:
    """Stands in for the browser side: records what is sent, feeds scripted input."""

    def __init__(self, inbound=()):
        self.sent = []
        self.closed_with = None
        self.closed = False
        self._inbound = list(inbound)
        self._gate = asyncio.Event()

    async def send_bytes(self, data):
        self.sent.append(bytes(data))

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self, code=1000, message=b""):
        self.closed = True
        self.closed_with = (code, message)
        self._gate.set()

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        class Msg:
            pass
        for data in self._inbound:
            m = Msg()
            m.type = WSMsgType.BINARY
            m.data = data
            yield m
        await self._gate.wait()


async def relay(server_handler, inbound=(), peek=0.5, linger=0.4):
    """Run the plugin against a loopback fake server; returns (ws, server_got)."""
    got = bytearray()

    async def handler(reader, writer):
        await server_handler(reader, writer, got)

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    old = vnc.BANNER_PEEK_TIMEOUT
    vnc.BANNER_PEEK_TIMEOUT = peek
    ws = FakeWS(inbound)
    target = ServiceTarget(id="t", name="t", plugin="vnc", host="127.0.0.1", port=port,
                           config={"host": "127.0.0.1", "port": port, "_pinned_hosts": ["127.0.0.1"]})
    task = asyncio.ensure_future(vnc.VNCPlugin().handle_websocket(ws, target, 1))
    try:
        await asyncio.sleep(linger)
        if not ws.closed:
            await ws.close()
        await asyncio.wait_for(task, 5)
    finally:
        vnc.BANNER_PEEK_TIMEOUT = old
        srv.close()
        await srv.wait_closed()
    return ws, bytes(got)


BANNER = b"RFB 003.008\n"

# a real-looking RFB server: banner arrives in two pieces, client bytes pass through
async def rfb_server(reader, writer, got):
    writer.write(BANNER[:2]); await writer.drain()
    await asyncio.sleep(0.05)
    writer.write(BANNER[2:]); await writer.drain()
    got += await reader.read(100)
    writer.write(b"\x01\x02"); await writer.drain()
    await asyncio.sleep(0.2)
    writer.close()

ws, got = run(relay(rfb_server, inbound=[b"RFB 003.008\n"]))
assert b"".join(x for x in ws.sent if isinstance(x, bytes)) == BANNER + b"\x01\x02", ws.sent
assert got == b"RFB 003.008\n", got
assert ws.closed_with is None or ws.closed_with[0] == 1000, ws.closed_with

# a server that waits for the client: nothing is lost, the relay carries on
async def waiting_server(reader, writer, got):
    got += await reader.read(100)
    writer.write(b"RFB 003.008\n"); await writer.drain()
    await asyncio.sleep(0.2)
    writer.close()

class LateWS(FakeWS):
    def __init__(self):
        super().__init__()

    async def _iter(self):
        class Msg:
            pass
        await asyncio.sleep(0.4)  # after the peek timeout
        m = Msg(); m.type = WSMsgType.BINARY; m.data = b"HELLO"
        yield m
        await self._gate.wait()

async def waiting_case():
    got = bytearray()
    probes = []

    async def handler(reader, writer):
        # the first connection is the session, the second is the RDP probe
        if probes:
            probes.append(await reader.read(100))
            writer.close()
            return
        probes.append(b"")
        await waiting_server(reader, writer, got)

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    old = vnc.BANNER_PEEK_TIMEOUT
    old_rdp = vnc.RDP_PORT
    vnc.BANNER_PEEK_TIMEOUT = 0.2
    vnc.RDP_PORT = port
    ws = LateWS()
    target = ServiceTarget(id="t", name="t", plugin="vnc", host="127.0.0.1", port=port,
                           config={"host": "127.0.0.1", "port": port, "_pinned_hosts": ["127.0.0.1"]})
    task = asyncio.ensure_future(vnc.VNCPlugin().handle_websocket(ws, target, 1))
    try:
        await asyncio.sleep(1.2)
        if not ws.closed:
            await ws.close()
        await asyncio.wait_for(task, 5)
    finally:
        vnc.BANNER_PEEK_TIMEOUT = old
        vnc.RDP_PORT = old_rdp
        srv.close()
        await srv.wait_closed()
    return ws, bytes(got), probes

ws, got, probes = run(waiting_case())
assert got == b"HELLO", got
assert len(probes) == 2 and probes[1] == vnc.RDP_CONNECTION_REQUEST, probes
assert b"".join(x for x in ws.sent if isinstance(x, bytes)) == b"RFB 003.008\n", ws.sent

# an SSH-style banner: refused with the not-VNC code, nothing forwarded
async def ssh_server(reader, writer, got):
    writer.write(b"SSH-2.0-test\r\n"); await writer.drain()
    await asyncio.sleep(0.5)

ws, got = run(relay(ssh_server))
assert ws.closed_with == (vnc.CLOSE_NOT_VNC, vnc.CLOSE_REASONS[vnc.CLOSE_NOT_VNC]), ws.closed_with
assert not any(isinstance(x, bytes) for x in ws.sent)

# a TPKT header: refused with the RDP code
async def tpkt_server(reader, writer, got):
    writer.write(b"\x03\x00\x00\x0b"); await writer.drain()
    await asyncio.sleep(0.5)

ws, got = run(relay(tpkt_server))
assert ws.closed_with == (vnc.CLOSE_RDP_HOST, vnc.CLOSE_REASONS[vnc.CLOSE_RDP_HOST]), ws.closed_with


# --- silent host: an RDP server (answers a connection request) is refused ----
async def silent_rdp_server(reader, writer, got):
    req = await reader.read(100)
    got += req
    # X.224 Connection Confirm, TPKT framed
    writer.write(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x00\x00\x00\x00")
    await writer.drain()
    await asyncio.sleep(0.2)


async def rdp_case():
    # the first connection stays silent, later ones (the probe) get the RDP reply
    conns = []
    got = bytearray()

    async def handler(reader, writer):
        conns.append(1)
        if len(conns) == 1:
            await asyncio.sleep(1.5)
        else:
            await silent_rdp_server(reader, writer, got)

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    old = vnc.BANNER_PEEK_TIMEOUT
    old_rdp = vnc.RDP_PORT
    vnc.BANNER_PEEK_TIMEOUT = 0.2
    vnc.RDP_PORT = port
    ws = FakeWS()
    target = ServiceTarget(id="t", name="t", plugin="vnc", host="127.0.0.1", port=port,
                           config={"host": "127.0.0.1", "port": port, "_pinned_hosts": ["127.0.0.1"]})
    try:
        await asyncio.wait_for(vnc.VNCPlugin().handle_websocket(ws, target, 1), 5)
    finally:
        vnc.BANNER_PEEK_TIMEOUT = old
        vnc.RDP_PORT = old_rdp
        srv.close()
        await srv.wait_closed()
    return ws, bytes(got), len(conns)

ws, got, nconns = run(rdp_case())
assert ws.closed_with == (vnc.CLOSE_RDP_HOST, vnc.CLOSE_REASONS[vnc.CLOSE_RDP_HOST]), ws.closed_with
assert got == vnc.RDP_CONNECTION_REQUEST, got
assert nconns == 2, nconns

# the probe on its own: RDP answers, VNC-waits and closed ports do not
async def probe_against(handler):
    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        return await vnc.probe_rdp(["127.0.0.1"], port, timeout=0.5)
    finally:
        srv.close()
        await srv.wait_closed()

async def rdp_h(r, w):
    await r.read(100)
    w.write(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
    await w.drain()

async def silent_h(r, w):
    await asyncio.sleep(2)

async def closing_h(r, w):
    w.close()

async def vnc_h(r, w):
    await r.read(100)
    w.write(b"RFB 003.008\n")
    await w.drain()

assert run(probe_against(rdp_h)) is True
assert run(probe_against(silent_h)) is False
assert run(probe_against(closing_h)) is False
assert run(probe_against(vnc_h)) is False

async def refused_port():
    s = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = s.sockets[0].getsockname()[1]
    s.close()
    await s.wait_closed()
    return await vnc.probe_rdp(["127.0.0.1"], port, timeout=0.5)

assert run(refused_port()) is False
assert vnc.RDP_PROBE_TIMEOUT == 2.0
assert vnc.RDP_PORT == 3389
assert vnc.BANNER_PEEK_TIMEOUT == 5.0
assert len(vnc.RDP_CONNECTION_REQUEST) == 19 and vnc.RDP_CONNECTION_REQUEST[3] == 19


# --- the probe runs only on the standard RDP port ----------------------------
async def run_handler(server_handler, rdp_port_is_target, peek=0.2, hold=1.0, cancel_at=None, patch=None):
    """Run the plugin against a fake server. Returns (ws, connections, upstream_eof, outcome).

    upstream_eof is True when the first (session) connection saw its peer
    close. cancel_at cancels the handler task after that many seconds.
    """
    state = {"conns": 0, "eof": None, "first_reader": None}

    async def handler(reader, writer):
        state["conns"] += 1
        if state["conns"] == 1:
            state["first_reader"] = reader
            try:
                data = await asyncio.wait_for(reader.read(1), 4)
                state["eof"] = (data == b"")
            except asyncio.TimeoutError:
                state["eof"] = False
            writer.close()
        else:
            await server_handler(reader, writer)

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    old = (vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PORT, vnc.RDP_PROBE_TIMEOUT, vnc.probe_rdp)
    vnc.BANNER_PEEK_TIMEOUT = peek
    vnc.RDP_PORT = port if rdp_port_is_target else 1
    if patch:
        vnc.probe_rdp = patch
    ws = FakeWS()
    target = ServiceTarget(id="t", name="t", plugin="vnc", host="127.0.0.1", port=port,
                           config={"host": "127.0.0.1", "port": port, "_pinned_hosts": ["127.0.0.1"]})
    task = asyncio.ensure_future(vnc.VNCPlugin().handle_websocket(ws, target, 1))
    outcome = "returned"
    try:
        if cancel_at is not None:
            await asyncio.sleep(cancel_at)
            task.cancel()
        else:
            await asyncio.sleep(hold)
            if not ws.closed:
                await ws.close()
        try:
            await asyncio.wait_for(task, 5)
        except asyncio.CancelledError:
            outcome = "cancelled"
        except RuntimeError:
            outcome = "error"
        await asyncio.sleep(0.2)
    finally:
        vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PORT, vnc.RDP_PROBE_TIMEOUT, vnc.probe_rdp = old
        srv.close()
        await srv.wait_closed()
    return ws, state["conns"], state["eof"], outcome


async def never(r, w):
    await asyncio.sleep(2)

# silent host on a non-RDP port: no probe at all, the relay starts after the peek
ws, conns, eof, outcome = run(run_handler(never, rdp_port_is_target=False))
assert conns == 1, conns
assert ws.closed_with is None or ws.closed_with[0] == 1000, ws.closed_with

# the same silent host on the RDP port is probed (second connection)
ws, conns, eof, outcome = run(run_handler(never, rdp_port_is_target=True, hold=1.0))
assert conns == 2, conns

# default RDP port constant is what the handler compares against
assert vnc.VNCPlugin._is_rdp_port(3389) and vnc.VNCPlugin._is_rdp_port("3389")
assert not vnc.VNCPlugin._is_rdp_port(5900) and not vnc.VNCPlugin._is_rdp_port(None)

# --- the upstream socket is closed when the handler is cancelled or fails ----
# cancelled during the banner peek (peek is 3 s, cancel at 0.3 s)
ws, conns, eof, outcome = run(run_handler(never, rdp_port_is_target=False, peek=3.0, cancel_at=0.3))
assert outcome == "cancelled", outcome
assert conns == 1 and eof is True, (conns, eof)

# cancelled during the RDP probe (peek 0.2 s, probe stalls, cancel at 0.7 s)
ws, conns, eof, outcome = run(run_handler(never, rdp_port_is_target=True, peek=0.2, cancel_at=0.7))
assert outcome == "cancelled", outcome
assert conns == 2 and eof is True, (conns, eof)

# an error raised during the probe step closes the upstream socket too
async def boom(*a, **k):
    raise RuntimeError("probe failed")

ws, conns, eof, outcome = run(run_handler(never, rdp_port_is_target=True, peek=0.2, hold=1.0, patch=boom))
assert outcome == "error", outcome
assert conns == 1 and eof is True, (conns, eof)

print("ok")
