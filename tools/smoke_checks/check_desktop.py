"""Smoke check: honest desktop (VNC protocol) labelling, the VNC banner peek, and
the WHIP/WHEP caveats in the stream docs.

Hosts that user connections may dial are policy-checked, so the relay is
exercised in-process (ctx.run_py): the staged tree's VNC plugin runs behind a
real aiohttp WebSocket route against local fake servers, and a real WebSocket
client reads what the browser would receive. The labels, the type list, the
viewer page and the guides are checked over HTTP against the staged instance.
"""

import json
import re

USER = "smoke_desktop_user"
PASSWORD = "Smoke-Desktop-Pw-1!"
GOOD_HOST = "93.184.216.34"

CREATE_USER = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    if not await database.db.get_user_by_username({USER!r}):
        await create_user({USER!r}, {PASSWORD!r}, is_admin=False)
    await database.db.close()

asyncio.run(main())
"""

RELAY = r'''
import asyncio, json, time
import aiohttp
from aiohttp import web
from plugins import vnc
from plugins.base import ServiceTarget

BANNER = b"RFB 003.008\n"
DEFAULT_RDP_PORT = vnc.RDP_PORT
RDP_CC = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x00\x00\x00\x00"


async def serve(handler):
    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


def make_app(port, holder=None):
    async def ws_route(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        target = ServiceTarget(id="t", name="t", plugin="vnc", host="127.0.0.1", port=port,
                               config={"host": "127.0.0.1", "port": port, "_pinned_hosts": ["127.0.0.1"]})
        task = asyncio.ensure_future(vnc.VNCPlugin().handle_websocket(ws, target, 1))
        if holder is not None:
            holder["task"] = task
        try:
            await task
        except asyncio.CancelledError:
            if holder is None:
                raise
        if not ws.closed:
            await ws.close()
        return ws
    app = web.Application()
    app.router.add_get("/ws", ws_route)
    return app


async def client(app, script):
    """Run the app on a loopback port, connect, run script(ws), return its result."""
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    web_port = site._server.sockets[0].getsockname()[1]
    try:
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(f"http://127.0.0.1:{web_port}/ws") as ws:
                return await script(ws)
    finally:
        await runner.cleanup()


async def drain(ws, send=None, limit=8.0):
    """Collect binary frames until close; returns (frames, close code, reason)."""
    frames = []
    reason = None
    deadline = time.monotonic() + limit
    if send is not None:
        await ws.send_bytes(send)
    while time.monotonic() < deadline:
        try:
            m = await ws.receive(timeout=deadline - time.monotonic())
        except asyncio.TimeoutError:
            break
        if m.type == aiohttp.WSMsgType.BINARY:
            frames.append(m.data)
        else:
            if m.type == aiohttp.WSMsgType.CLOSE:
                reason = m.extra
            break
    return b"".join(frames), ws.close_code, reason


async def scenario_rfb():
    got = bytearray()
    async def handler(r, w):
        # a handshake that arrives in pieces, then a reply to the client
        w.write(BANNER[:1]); await w.drain(); await asyncio.sleep(0.05)
        w.write(BANNER[1:3]); await w.drain(); await asyncio.sleep(0.05)
        w.write(BANNER[3:]); await w.drain()
        got.extend(await r.readexactly(12))
        w.write(b"\x01\x02\x03"); await w.drain()
        await asyncio.sleep(0.2)
        w.close()
    srv, port = await serve(handler)
    async def script(ws):
        frames = []
        async def reader():
            async for m in ws:
                if m.type == aiohttp.WSMsgType.BINARY:
                    frames.append(m.data)
        task = asyncio.ensure_future(reader())
        await asyncio.sleep(0.4)
        await ws.send_bytes(BANNER)
        await asyncio.wait_for(task, 5)
        return b"".join(frames), ws.close_code
    t0 = time.monotonic()
    data, code = await client(make_app(port), script)
    srv.close()
    return {"data": data.hex(), "server_got": bytes(got).hex(), "close": code,
            "seconds": round(time.monotonic() - t0, 2)}


async def scenario_rdp():
    """A silent host that answers an RDP connection request."""
    n = []
    async def handler(r, w):
        n.append(1)
        if len(n) == 1:
            await asyncio.sleep(10)
            return
        await r.read(100)
        w.write(RDP_CC); await w.drain()
        await asyncio.sleep(0.2)
    srv, port = await serve(handler)
    vnc.RDP_PORT = port        # the probe only runs on the RDP port
    async def script(ws):
        t0 = time.monotonic()
        data, code, reason = await drain(ws, limit=12)
        return data, code, reason, time.monotonic() - t0
    data, code, reason, secs = await client(make_app(port), script)
    srv.close()
    vnc.RDP_PORT = DEFAULT_RDP_PORT
    return {"data": data.hex(), "close": code, "reason": reason, "seconds": round(secs, 2)}


async def scenario_silent_other_port():
    """A silent server on a port other than 3389: no probe, relayed after the peek."""
    seen = []
    async def handler(r, w):
        seen.append(1)
        got = await r.readexactly(5)
        w.write(BANNER + got); await w.drain()
        await asyncio.sleep(0.3)
        w.close()
    srv, port = await serve(handler)
    async def script(ws):
        t0 = time.monotonic()
        await asyncio.sleep(vnc.BANNER_PEEK_TIMEOUT + 0.5)
        await ws.send_bytes(b"HELLO")
        data, code, _ = await drain(ws, limit=8)
        return data, code, time.monotonic() - t0
    data, code, secs = await client(make_app(port), script)
    srv.close()
    return {"data": data.hex(), "close": code, "connections": len(seen), "seconds": round(secs, 2)}


async def scenario_cancel(stage):
    """Cancel the handler while it peeks or probes; the upstream socket must be closed."""
    state = {"n": 0, "eof": None}
    async def handler(r, w):
        state["n"] += 1
        if state["n"] == 1:
            try:
                state["eof"] = (await asyncio.wait_for(r.read(1), 4)) == b""
            except asyncio.TimeoutError:
                state["eof"] = False
            w.close()
        else:
            await asyncio.sleep(3)      # a probe that never answers
    srv, port = await serve(handler)
    old = (vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PORT)
    vnc.BANNER_PEEK_TIMEOUT = 3.0 if stage == "peek" else 0.2
    vnc.RDP_PORT = port if stage == "probe" else DEFAULT_RDP_PORT
    holder = {}
    async def script(ws):
        await asyncio.sleep(0.3 if stage == "peek" else 0.8)
        holder["task"].cancel()
        await asyncio.sleep(0.5)
    try:
        await client(make_app(port, holder), script)
    finally:
        vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PORT = old
        srv.close()
    return {"eof": state["eof"], "connections": state["n"]}


async def scenario_waiting_vnc():
    """A VNC server that waits for the client on the RDP port: the probe is one extra connection, the session still works."""
    seen = []
    async def handler(r, w):
        first = not seen
        seen.append(1)
        if not first:          # the RDP probe connection: ignore and hang up
            await r.read(100)
            w.close()
            return
        got = await r.readexactly(5)
        w.write(BANNER + got); await w.drain()
        await asyncio.sleep(0.3)
        w.close()
    srv, port = await serve(handler)
    old = (vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PROBE_TIMEOUT)
    vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PROBE_TIMEOUT = 0.3, 0.3
    vnc.RDP_PORT = port
    async def script(ws):
        t0 = time.monotonic()
        await asyncio.sleep(1.5)
        await ws.send_bytes(b"HELLO")
        data, code, _ = await drain(ws, limit=8)
        return data, code, time.monotonic() - t0
    try:
        data, code, secs = await client(make_app(port), script)
    finally:
        vnc.BANNER_PEEK_TIMEOUT, vnc.RDP_PROBE_TIMEOUT = old
        vnc.RDP_PORT = DEFAULT_RDP_PORT
        srv.close()
    return {"data": data.hex(), "close": code, "connections": len(seen)}


async def scenario_other(banner):
    async def handler(r, w):
        w.write(banner); await w.drain()
        await asyncio.sleep(1)
    srv, port = await serve(handler)
    async def script(ws):
        t0 = time.monotonic()
        data, code, reason = await drain(ws, limit=8)
        return data, code, reason, time.monotonic() - t0
    data, code, reason, secs = await client(make_app(port), script)
    srv.close()
    return {"data": data.hex(), "close": code, "reason": reason, "seconds": round(secs, 2)}


async def main():
    defaults = {"peek": vnc.BANNER_PEEK_TIMEOUT, "probe": vnc.RDP_PROBE_TIMEOUT, "port": DEFAULT_RDP_PORT}
    # Scenarios that end in silence read the module's RDP port, so they run one
    # after another; the ones that get a banner at once do not.
    rfb, ssh, tpkt = await asyncio.gather(
        scenario_rfb(), scenario_other(b"SSH-2.0-test\r\n"), scenario_other(b"\x03\x00\x00\x0b"))
    rdp = await scenario_rdp()
    silent = await scenario_silent_other_port()
    waiting = await scenario_waiting_vnc()
    cancel_peek = await scenario_cancel("peek")
    cancel_probe = await scenario_cancel("probe")
    print("OUT=" + json.dumps({
        "rfb": rfb, "rdp": rdp, "waiting": waiting, "ssh": ssh, "tpkt": tpkt,
        "silent": silent, "cancel_peek": cancel_peek, "cancel_probe": cancel_probe,
        "defaults": defaults,
        "peek_timeout": vnc.BANNER_PEEK_TIMEOUT, "codes": [vnc.CLOSE_RDP_HOST, vnc.CLOSE_NOT_VNC],
        "reasons": [vnc.CLOSE_REASONS[c].decode() for c in (vnc.CLOSE_RDP_HOST, vnc.CLOSE_NOT_VNC)],
    }))

asyncio.run(main())
'''


def _out(out):
    line = next((l for l in out.splitlines() if l.startswith("OUT=")), "")
    return json.loads(line[4:]) if line else None


async def run(ctx):
    rc, out = await ctx.run_py(CREATE_USER)
    ctx.ok("desktop: create non-admin test user", rc == 0, out.strip()[-200:])
    if rc != 0:
        return

    # ---- relay behaviour against fake servers ----------------------------
    rc, out = await ctx.run_py(RELAY, timeout=90)
    res = _out(out)
    ctx.ok("desktop: relay scenarios ran", rc == 0 and res is not None, out.strip()[-400:])
    if res is not None:
        ctx.ok("desktop: banner peek waits 5 seconds by default", res["peek_timeout"] == 5.0, str(res["peek_timeout"]))
        ctx.ok("desktop: RDP probe timeout is 2 seconds and applies to port 3389 only",
               res["defaults"] == {"peek": 5.0, "probe": 2.0, "port": 3389}, json.dumps(res["defaults"]))
        banner = b"RFB 003.008\n"
        ctx.ok("desktop: a real VNC handshake arrives byte for byte, both directions",
               res["rfb"]["data"] == (banner + b"\x01\x02\x03").hex() and res["rfb"]["server_got"] == banner.hex(),
               json.dumps(res["rfb"]))
        r = res["rdp"]
        ctx.ok("desktop: a silent RDP server is refused with the RDP close code and no data",
               r["close"] == res["codes"][0] and r["data"] == "" and r["seconds"] < 8, json.dumps(r))
        ctx.ok("desktop: the RDP close reason is sent on the wire",
               r["reason"] == res["reasons"][0] == "This host speaks RDP, not VNC", json.dumps(r))
        w = res["waiting"]
        ctx.ok("desktop: a VNC server that waits for the client is still relayed after the peek",
               w["data"] == (b"RFB 003.008\n" + b"HELLO").hex(), json.dumps(w))
        ctx.ok("desktop: the RDP probe is one extra connection, only on silence",
               w["connections"] == 2 and res["rfb"]["close"] != res["codes"][0], json.dumps(w))
        sl = res["silent"]
        ctx.ok("desktop: a silent server on a port other than 3389 is not probed and is relayed after the peek",
               sl["connections"] == 1 and sl["data"] == (b"RFB 003.008\n" + b"HELLO").hex() and sl["seconds"] < 8,
               json.dumps(sl))
        ctx.ok("desktop: the upstream socket is closed when the handler is cancelled during the banner peek",
               res["cancel_peek"] == {"eof": True, "connections": 1}, json.dumps(res["cancel_peek"]))
        ctx.ok("desktop: the upstream socket is closed when the handler is cancelled during the RDP probe",
               res["cancel_probe"] == {"eof": True, "connections": 2}, json.dumps(res["cancel_probe"]))
        ctx.ok("desktop: a non-VNC banner is refused at once with the not-VNC code",
               res["ssh"]["close"] == res["codes"][1] and res["ssh"]["data"] == "" and res["ssh"]["seconds"] < 3
               and res["ssh"]["reason"] == res["reasons"][1],
               json.dumps(res["ssh"]))
        ctx.ok("desktop: an RDP-framed banner is refused with the RDP code",
               res["tpkt"]["close"] == res["codes"][0] and res["tpkt"]["data"] == "", json.dumps(res["tpkt"]))

    # ---- HTTP: labels, type key, viewer page, guides ----------------------
    async with ctx.http() as s:
        resp = await ctx.login(s, USER, PASSWORD)
        ctx.ok("desktop: non-admin login", resp.status == 200, f"status {resp.status}")
        if resp.status != 200:
            return

        async with s.get(f"{ctx.base_url}/api/connections/types") as r:
            types = (await r.json()).get("types", {})
        rdp = types.get("rdp", {})
        ctx.ok("desktop: rdp type is labelled Desktop (VNC protocol), key kept, default port 5900",
               rdp.get("name") == "Desktop (VNC protocol)" and rdp.get("plugin") == "vnc"
               and rdp.get("default_port") == 5900, json.dumps({k: rdp.get(k) for k in ("name", "plugin", "default_port")}))
        ctx.ok("desktop: no type is still labelled RDP",
               not any("rdp" in (t.get("name") or "").lower() for t in types.values()),
               str([k for k, t in types.items() if "rdp" in (t.get("name") or "").lower()]))
        ctx.ok("desktop: vnc type label unchanged", types.get("vnc", {}).get("name") == "VNC Desktop", "")

        # A stored rdp connection (old rows carry username and domain) still saves and opens.
        async with s.post(f"{ctx.base_url}/api/connections", json={
                "name": "desk", "type": "rdp", "host": GOOD_HOST, "port": 3389,
                "config": {"username": "old", "domain": "old"}}) as r:
            body = await r.json()
            conn_id = body.get("id")
            ctx.ok("desktop: an rdp connection (with legacy fields) is still accepted",
                   r.status in (200, 201) and bool(conn_id), f"{r.status} {body}")
        if conn_id:
            async with s.get(f"{ctx.base_url}/vnc/connect", params={"connection": conn_id}) as r:
                page = await r.text()
                ctx.ok("desktop: viewer page for the connection loads", r.status == 200, f"status {r.status}")
            ctx.ok("desktop: viewer page maps the RDP close code to the RDP message",
                   "4010" in page and "This host speaks RDP, not VNC" in page and "new WebSocket(" in page
                   and "textContent" in page, "")
            ctx.ok("desktop: viewer page maps the not-VNC close code",
                   "4011" in page and "This host does not speak VNC" in page, "")
            ctx.ok("desktop: the disconnect handler does not overwrite the refusal",
                   "if (!refused) updateStatus('disconnected', 'Disconnected')" in page, "")

        async with s.get(f"{ctx.base_url}/guides") as r:
            guides = await r.text()
        sect = re.search(r'<section id="guide-rdp">(.*?)</section>', guides, re.S)
        sect = sect.group(1) if sect else ""
        ctx.ok("desktop: guide section says VNC protocol and that RDP is not supported",
               "VNC protocol" in sect and "does <strong>not</strong> speak Windows Remote Desktop" in sect, sect[:120])
        ctx.ok("desktop: guide gives 5900 as the default port for new connections and keeps saved ones",
               "<code>5900</code> for new connections" in sect and "keep the port they were saved with" in sect
               and "<code>3389</code> (kept" not in sect, sect[:120])
        ctx.ok("desktop: guide no longer claims RDP works",
               "Portal proxies the RDP connection" not in guides and "Enter Windows username" not in guides
               and "NLA" not in sect, "")
        ctx.ok("desktop: guide table of contents uses the new label",
               'href="#guide-rdp">Desktop (VNC protocol)<' in guides, "")

        async with s.get(f"{ctx.base_url}/api-docs") as r:
            docs = await r.text()
        ctx.ok("desktop: api-docs no longer says WHIP works through port 443",
               "Publish streams through port 443 using WebRTC WHIP" not in docs, "")
        ctx.ok("desktop: api-docs caveats WHIP and WHEP as same-network only",
               "same network only" in docs and "Not available through the public proxy" in docs
               and "same-network only" in docs, "")

    # ---- static files that carry the claims ------------------------------
    root = ctx.stage_dir
    uc = (root / "static" / "js" / "user-connections.js").read_text()
    idx = (root / "static" / "index.html").read_text()
    ctx.ok("desktop: connection form has no RDP username or domain fields",
           "connection-rdp-" not in uc and "connection-rdp-" not in idx, "")
    ctx.ok("desktop: no remaining RDP labels in the connection UI",
           "RDP Desktop" not in uc + idx and "RDP via VNC" not in idx, "")
    ctx.ok("desktop: the Desktop (VNC protocol) preset prefills port 5900",
           re.search(r"'rdp-server':\s*\{[^}]*type: 'rdp', port: 5900", uc) is not None, "")
    # the bumped script versions in the page that loads them
    m_uc = re.search(r"user-connections\.js\?v=(\d+)", idx)
    ctx.ok("desktop: user-connections.js version bumped", bool(m_uc) and int(m_uc.group(1)) >= 46,
           m_uc.group(0) if m_uc else "no match")
    for html in sorted((root / "static").glob("*.html")):
        text = html.read_text()
        for m in re.finditer(r"/static/js/portal\.js\?v=(\d+)", text):
            if int(m.group(1)) < 44:
                ctx.ok("desktop: portal.js version bumped in " + html.name, False, m.group(0))
                break
    else:
        ctx.ok("desktop: portal.js version bumped in every page", True, "")
    ctx.ok("desktop: stream URL docstrings caveat WebRTC",
           "same network" in (root / "services" / "mediamtx.py").read_text(), "")
