"""Web Browser on the server, lane B: the WebSocket bridge /ws/rbrowser/{sid}.

The real app on a loopback test server, the real registry, rbrowser.FakeLauncher and tests/fixtures/fake_rfb.py behind it
(stage mode with PORTAL_RBROWSER_FAKE=1). Nothing needs root and no unit is started.

Run: venv/bin/python -B tests/test_rbrowser_bridge.py
"""

import asyncio
import json
import os
import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
import rbrowser  # noqa: E402
import rbrowser_launch  # noqa: E402
import secevents  # noqa: E402

FACTS = {"resolvers": [], "ifaces": [], "gateways": [], "gateways_scoped": []}
BODY = {"width": 1280, "height": 720}


def plain():
    return aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())


async def drain_for(ws, seconds):
    """Everything the portal sends in `seconds`: (bytes received, close code or None)."""
    total, end = 0, time.monotonic() + seconds
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return total, None
        try:
            msg = await asyncio.wait_for(ws.receive(), left)
        except asyncio.TimeoutError:
            return total, None
        if msg.type == aiohttp.WSMsgType.BINARY:
            total += len(msg.data)
        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
            return total, (msg.data if msg.type == aiohttp.WSMsgType.CLOSE else ws.close_code)


async def handshake(ws):
    await ws.send_bytes(b"RFB 003.008\n")
    await ws.send_bytes(b"\x01")
    await ws.send_bytes(b"\x01")
    await asyncio.sleep(0.3)


async def main():
    tmp = tempfile.mkdtemp(prefix="rbbr-")
    env = await h.boot(names=("owner", "bob", "carol", "adm"))
    db, base = env.db, env.base
    wsb = base.replace("http", "ws")
    adm, bob, carol = env.sessions["adm"], env.sessions["bob"], env.sessions["carol"]
    server._MAINT_CACHE_TTL = 0.05
    rbrowser.configure(environ={"PORTAL_RBROWSER_FAKE": "1"}, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                       cgroup_root=os.path.join(tmp, "cg"), tmp_dir=os.path.join(tmp, "tmp"), cache_path=os.path.join(tmp, "pf.json"))
    reg = rbrowser.registry()
    clock = {"off": 0.0}
    reg.clock = lambda: time.time() + clock["off"]
    server._rbrowser_cfg.update(rbrowser_enabled=True, rbrowser_min_role="user", rbrowser_max_sessions=4, stage_mode=True,
                                stage_dir=os.path.join(tmp, "stage"))
    os.makedirs(server._rbrowser_cfg["stage_dir"], exist_ok=True)
    await server._rbrowser_start()
    check("the feature is up on the fake launcher", reg.ready and reg.stage_fake)

    async def make(sess):
        async with sess.post(f"{base}/api/rbrowser/session", json=BODY) as r:
            assert r.status in (200, 201), r.status
            return (await r.json())["sid"]

    async def attach(sess, sid, **kw):
        return await sess.ws_connect(f"{wsb}/ws/rbrowser/{sid}", **kw)

    sid = await make(bob)
    sess_b = rbrowser.get(sid)
    fake = reg._launcher.servers[sess_b.unit]

    # ---------------------------------------------------------------- who may attach
    ws = await attach(bob, sid)
    await handshake(ws)
    await ws.send_bytes(struct.pack(">BBHHHH", 3, 0, 0, 0, 64, 64))
    got, code = await drain_for(ws, 1.0)
    check("the owner attaches and the unit's bytes arrive (ServerInit, a rectangle)", got > 20 and code is None, str((got, code)))
    check("the member's bytes reached the unit through the filter (handshake and a request)", fake.handshake[:1] == [b"RFB 003.008\n"] and 3 in fake.message_types(),
          str(fake.handshake))
    check("the session knows it is attached", sess_b.viewer is not None)

    # activity: a framebuffer request is none, a key event and a pointer event are, the control frame is
    base_act = sess_b.last_activity
    clock["off"] += 50
    await ws.send_bytes(struct.pack(">BBHHHH", 3, 1, 0, 0, 64, 64))
    await asyncio.sleep(0.3)
    check("a FramebufferUpdateRequest is not activity", sess_b.last_activity == base_act)
    clock["off"] += 5
    await ws.send_bytes(struct.pack(">BBxxI", 4, 1, 0x61))
    await asyncio.sleep(0.3)
    a1 = sess_b.last_activity
    check("a key event is activity", a1 > base_act and 4 in fake.message_types())
    clock["off"] += 5
    await ws.send_bytes(struct.pack(">BBHH", 5, 0, 10, 10))
    await asyncio.sleep(0.3)
    a2 = sess_b.last_activity
    check("a pointer event is activity", a2 > a1 and 5 in fake.message_types())
    n_before = len(fake.records)
    clock["off"] += 15
    await ws.send_str(json.dumps({"op": "here"}))
    await asyncio.sleep(0.3)
    a3 = sess_b.last_activity
    check("the control frame {\"op\":\"here\"} is activity", a3 > a2)
    clock["off"] += 3
    await ws.send_str(json.dumps({"op": "here"}))
    await asyncio.sleep(0.3)
    check("and is accepted at most once per 10 seconds", sess_b.last_activity == a3)
    clock["off"] += 15
    for junk in ('{"op":"here","x":1}', '{"op":"stop"}', "not json", json.dumps({"op": "here", "pad": "x" * 300}), "[1]", '"here"'):
        await ws.send_str(junk)
    await asyncio.sleep(0.4)
    check("other text frames, extra keys and oversized frames are ignored", sess_b.last_activity == a3)
    check("no text frame ever reached the unit", len(fake.records) == n_before, f"{n_before} -> {len(fake.records)}")

    # another member, another sign-in, wrong credential kinds
    for who, sess in (("another member", carol),):
        w2 = await attach(sess, sid)
        _, code = await drain_for(w2, 2)
        check(f"{who}: 4004", code == 4004, str(code))
    bob2 = await h.login(base, "bob")
    w2 = await attach(bob2, sid)
    _, code = await drain_for(w2, 2)
    check("the same member with another sign-in: 4004 (same reason as a missing session)", code == 4004, str(code))
    w2 = await attach(bob, "doesnotexist12345")
    _, code = await drain_for(w2, 2)
    check("an unknown session: 4004", code == 4004)
    w2 = await attach(adm, sid)
    _, code = await drain_for(w2, 2)
    check("an administrator cannot attach to a member's session: 4004", code == 4004, str(code))
    async with plain().post(f"{base}/api/token", json={"username": "bob", "password": h.PW, "scopes": ["*"]}) as r:
        tok = (await r.json()).get("token")
    async with plain() as s:
        w2 = await s.ws_connect(f"{wsb}/ws/rbrowser/{sid}", headers={"Authorization": f"Bearer {tok}"})
        _, code = await drain_for(w2, 2)
        check("a bearer token (not the browser sign-in) gets 4003", code == 4003, str(code))
        w2 = await s.ws_connect(f"{wsb}/ws/rbrowser/{sid}", headers={"Cookie": f"{server.Config.SESSION_COOKIE_NAME}={tok}"})
        _, code = await drain_for(w2, 2)
        check("a script token sent in the Cookie header is not the browser sign-in: 4003 (not 4004)", code == 4003, str(code))
        w2 = await s.ws_connect(f"{wsb}/ws/rbrowser/{sid}?token={tok}")
        _, code = await drain_for(w2, 2)
        check("a ?token= credential gets 4003", code == 4003, str(code))
    async with plain() as s:
        try:
            await s.ws_connect(f"{wsb}/ws/rbrowser/{sid}")
            st = 101
        except aiohttp.WSServerHandshakeError as e:
            st = e.status
        check("no credential: refused before the upgrade (401)", st == 401, str(st))
    for hdr in ({"Origin": "https://evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}):
        try:
            await bob.ws_connect(f"{wsb}/ws/rbrowser/{sid}", headers=hdr)
            st = 101
        except aiohttp.WSServerHandshakeError as e:
            st = e.status
        check(f"an upgrade from another site or a sandboxed page is refused ({list(hdr)[0]}={list(hdr.values())[0]})", st == 403, str(st))

    # ---------------------------------------------------------------- the filter
    check("the first socket is still the viewer", sess_b.viewer is not None)
    # a second window of the same sign-in replaces the first (4012)
    wnew = await attach(bob, sid)
    _, code_old = await drain_for(ws, 2)
    check("the previous viewer is closed with 4012", code_old == 4012, str(code_old))
    await handshake(wnew)
    got, code = await drain_for(wnew, 1.0)
    check("and the new one gets the stream", got > 20 and code is None and sess_b.viewer is not None, str((got, code)))
    ws = wnew

    # what the unit receives is the filter's output, not the member's bytes
    n0 = len(fake.records)
    sent_encs = [-1063131698, 7, -312, 0, -313, 7, -223, -314]
    await ws.send_bytes(struct.pack(">BxH", 2, len(sent_encs)) + struct.pack(">%di" % len(sent_encs), *sent_encs))
    await asyncio.sleep(0.4)
    enc_recs = [m for t, m in fake.records[n0:] if t == 2]
    got_encs = list(struct.unpack(">%di" % struct.unpack(">H", enc_recs[0][2:4])[0], enc_recs[0][4:])) if enc_recs else None
    check("SetEncodings reaches the unit rewritten to the allow-list (extended clipboard, fence, continuous updates, repeats dropped)",
          len(enc_recs) == 1 and got_encs == [7, 0, -223], str((got_encs, len(enc_recs))))
    n1 = len(fake.records)
    key = struct.pack(">BBxxI", 4, 1, 0x61)
    await ws.send_bytes(key[:3])
    await asyncio.sleep(0.4)
    check("half of a KeyEvent in one frame is held back (nothing reaches the unit)", len(fake.records) == n1, str(fake.records[n1:]))
    await ws.send_bytes(key[3:])
    await asyncio.sleep(0.4)
    check("the rest in the next frame completes it: the unit gets exactly one whole 8-byte KeyEvent",
          [(t, len(m)) for t, m in fake.records[n1:]] == [(4, 8)] and fake.records[n1][1] == key, str(fake.records[n1:]))
    n2 = len(fake.records)
    ptr = struct.pack(">BBHH", 5, 0, 7, 7)
    await ws.send_bytes(key + ptr[:3])
    await asyncio.sleep(0.4)
    check("a whole message plus the start of the next: only the whole one is forwarded", [t for t, _ in fake.records[n2:]] == [4])
    await ws.send_bytes(ptr[3:])
    await asyncio.sleep(0.4)
    check("and the next one follows when it is whole", [t for t, _ in fake.records[n2:]] == [4, 5])

    # a protocol violation: an unknown message type, counted per member
    await ws.send_bytes(b"\x96" + b"\x00" * 7)
    _, code = await drain_for(ws, 2)
    check("an unknown RFB type closes the socket with 4013", code == 4013, str(code))
    msg_reason = ws.exception() if False else None
    await secevents.log.flush()
    cur = await db.conn.execute("SELECT event, user_id, details, count FROM security_events WHERE event = 'rbrowser_protocol_violation'")
    rows = [dict(x) for x in await cur.fetchall()]
    check("one rbrowser_protocol_violation event for that member, with a fixed word and no content",
          len(rows) >= 1 and rows[0]["user_id"] == env.uid["bob"] and "\x96" not in (rows[0]["details"] or "") and "reason" in (rows[0]["details"] or ""), str(rows))
    check("the session survives a protocol violation (it waits for a new window)", rbrowser.get(sid) is not None and sess_b.viewer is None)
    ws = await attach(bob, sid)
    await handshake(ws)
    await ws.send_bytes(struct.pack(">B3xI", 6, 4) + b"text")      # ClientCutText: the clipboard is off in both directions
    _, code = await drain_for(ws, 2)
    check("ClientCutText is a violation (clipboard off, always)", code == 4013 and 6 not in fake.message_types(), str(code))

    # the unit's bytes are not parsed: a ServerCutText passes through untouched (T6)
    ws = await attach(bob, sid)
    await handshake(ws)
    await drain_for(ws, 0.5)
    await fake.send_cut_text(b"abc")
    got = 0
    cut = b""
    end = time.monotonic() + 2
    while time.monotonic() < end and len(cut) < 12:
        try:
            m = await asyncio.wait_for(ws.receive(), 0.5)
        except asyncio.TimeoutError:
            continue
        if m.type == aiohttp.WSMsgType.BINARY:
            cut += m.data
    check("the unit-to-member stream is not parsed (T6): ServerCutText arrives as sent", b"\x03\x00\x00\x00\x00\x00\x00\x03abc" in cut, str(cut[-20:]))

    # ---------------------------------------------------------------- the token bucket and the slow client
    b = server._RbrowserBucket(1000, 1000, clock=lambda: 0.0)
    w1 = b.take(1000)
    w2_ = b.take(2000)
    check("the token bucket: a burst passes, then each byte costs its time", w1 == 0.0 and abs(w2_ - 2.0) < 1e-9)

    # replace the fake with a flooding server that never stops
    unit = sess_b.unit
    await fake.stop()
    flood = {"sent": 0}

    async def flooder(reader, writer):
        try:
            chunk = b"\x00" * 65536
            while True:
                writer.write(chunk)
                flood["sent"] += len(chunk)
                await writer.drain()
        except Exception:
            pass
    path = os.path.join(sess_b.runtime_dir, "vnc.sock")
    srv = await asyncio.start_unix_server(flooder, path=path)
    old_kbps, old_lim = rbrowser_launch.STREAM_KBPS, server.RBROWSER_SEND_LIMIT_S
    rbrowser_launch.STREAM_KBPS = 800                # 100 kB/s
    ws = await attach(bob, sid)
    t0 = time.monotonic()
    got, code = await drain_for(ws, 2.5)
    rbrowser_launch.STREAM_KBPS = old_kbps
    check("the rate cap holds the unit-to-member stream near STREAM_KBPS", got < 100_000 * (time.monotonic() - t0) + 250_000, f"{got} bytes")
    await ws.close()
    await asyncio.sleep(0.3)
    # a client that does not read: the unit side stops being read, the send limit closes the socket
    server.RBROWSER_SEND_LIMIT_S = 1
    rbrowser_launch.STREAM_KBPS = 800000             # no cap: only the client's stalled reading holds it back
    flood["sent"] = 0
    ws = await attach(bob, sid)
    await asyncio.sleep(4)
    stalled_at = flood["sent"]
    await asyncio.sleep(1)
    check("a slow client stops the read from the unit (memory stays bounded)", flood["sent"] == stalled_at and stalled_at < 64 * 1024 * 1024, str(flood))
    _, code = await drain_for(ws, 5)
    check("and is closed with 4013 after the send limit; the session stays", code == 4013 and rbrowser.get(sid) is not None, str(code))
    server.RBROWSER_SEND_LIMIT_S, rbrowser_launch.STREAM_KBPS = old_lim, old_kbps
    srv.close()
    await srv.wait_closed()

    # ---------------------------------------------------------------- the raw bytes the unit receives (no re-assembly on the unit's side)
    raw = bytearray()

    async def recorder(reader, writer):
        try:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                raw.extend(chunk)
        except Exception:
            pass
    srv = await asyncio.start_unix_server(recorder, path=path)
    ws = await attach(bob, sid)
    await handshake(ws)
    base_len = len(raw)
    check("raw: the handshake bytes reached the unit (version, security, ClientInit)", bytes(raw) == b"RFB 003.008\n\x01\x01", str(bytes(raw)))
    key = struct.pack(">BBxxI", 4, 1, 0x62)
    await ws.send_bytes(key[:3])
    await asyncio.sleep(0.4)
    check("raw: a KeyEvent split over two frames: nothing at all reaches the unit after the first part", len(raw) == base_len, str(len(raw) - base_len))
    await ws.send_bytes(key[3:])
    await asyncio.sleep(0.4)
    check("raw: after the second part exactly the 8 bytes of the message arrive, in one piece", bytes(raw[base_len:]) == key, str(bytes(raw[base_len:])))
    base_len = len(raw)
    await ws.send_bytes(struct.pack(">BxH", 2, 5) + struct.pack(">5i", -312, 7, -1063131698, 0, -223))
    await asyncio.sleep(0.4)
    check("raw: SetEncodings arrives as the allow-listed list and nothing else",
          bytes(raw[base_len:]) == struct.pack(">BBH", 2, 0, 3) + struct.pack(">3i", 7, 0, -223), str(bytes(raw[base_len:])))
    await ws.close()
    await asyncio.sleep(0.3)
    srv.close()
    await srv.wait_closed()

    # ---------------------------------------------------------------- one viewer per session: replacement, deterministic
    # A unit that streams for real and counts its concurrent connections (never two viewers pumping one session at once).
    unit_conns = {"now": 0, "max": 0, "total": 0, "closed": 0}

    async def streamer(reader, writer):
        unit_conns["now"] += 1
        unit_conns["total"] += 1
        unit_conns["max"] = max(unit_conns["max"], unit_conns["now"])
        try:
            writer.write(b"RFB 003.008\n")

            async def watch():
                while await reader.read(65536):
                    pass
            w = asyncio.ensure_future(watch())
            try:
                while not w.done():
                    writer.write(b"\x00" * 8192)
                    await writer.drain()
                    await asyncio.wait({w}, timeout=0.002)       # wakes at once when the portal closes its side
            finally:
                w.cancel()
        except Exception:
            pass
        finally:
            unit_conns["now"] -= 1
            unit_conns["closed"] += 1
            writer.close()
    srv = await asyncio.start_unix_server(streamer, path=path)

    def window(w):
        """Reads the window like a page does and keeps sending framebuffer requests, so there is unread data on the way in."""
        res = {"bytes": 0, "code": None, "reason": None, "ws": w}

        async def rd():
            while True:
                m = await w.receive()
                if m.type == aiohttp.WSMsgType.BINARY:
                    res["bytes"] += len(m.data)
                elif m.type == aiohttp.WSMsgType.CLOSE:
                    res["code"], res["reason"] = m.data, m.extra
                    return
                elif m.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                    res["code"] = w.close_code if w.close_code is not None else 1006
                    return

        async def snd():
            try:
                while not w.closed:
                    await w.send_bytes(struct.pack(">BBHHHH", 3, 1, 0, 0, 64, 64))
                    await asyncio.sleep(0.001)
            except Exception:
                pass
        res["rd"], res["snd"] = asyncio.ensure_future(rd()), asyncio.ensure_future(snd())
        return res

    async def open_window(sess_, sid_):
        w = await attach(sess_, sid_)
        await w.send_bytes(b"RFB 003.008\n")
        await w.send_bytes(b"\x01")
        await w.send_bytes(b"\x01")
        return window(w)

    async def until(pred, limit=5.0):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if pred():
                return True
            await asyncio.sleep(0.01)
        return pred()

    cur = await open_window(bob, sid)
    check("a streaming window is attached", await until(lambda: cur["bytes"] > 50_000) and unit_conns["now"] == 1)
    codes, reasons, starved = [], [], 0
    for i in range(100):
        nxt = await open_window(bob, sid)
        try:
            await asyncio.wait_for(cur["rd"], 10)
        except asyncio.TimeoutError:
            pass
        codes.append(cur["code"])
        reasons.append(cur["reason"])
        cur["snd"].cancel()
        if not await until(lambda: nxt["bytes"] > 20_000, 5):
            starved += 1
        cur = nxt
    check("100 replacements of a streaming window, each with an unread-data sender: the old window sees 4012 every time",
          codes == [4012] * 100, str({c: codes.count(c) for c in set(codes)}))
    check("and the reason text 'opened in another window' every time", all(r in ("opened in another window", b"opened in another window") for r in reasons), str(set(reasons)))
    check("the new window streams every time", starved == 0, str(starved))
    check("never two connections to the unit at once (never two viewers pumping)", unit_conns["max"] == 1, str(unit_conns))
    check("one viewer record for the session, and it is the current window",
          list(server._rbrowser_viewers) == [sid] and server._rbrowser_viewers[sid].ws is sess_b.viewer)

    # a refused attach does not disturb the current viewer
    viewer_before, rec_before = sess_b.viewer, server._rbrowser_viewers[sid]
    bob3 = await h.login(base, "bob")
    n_conn = unit_conns["total"]
    b0 = cur["bytes"]
    for what in ("another member", "another sign-in", "no such session", "feature off", "maintenance"):
        if what == "feature off":
            server._rbrowser_cfg["rbrowser_enabled"] = False
        if what == "maintenance":
            async with adm.put(f"{base}/api/admin/maintenance", json={"active": True, "message": "x"}) as r:
                assert r.status == 200
            await asyncio.sleep(0.1)
        who, target = {"another member": (carol, sid), "another sign-in": (bob3, sid), "no such session": (bob, "doesnotexist12345")}.get(what, (bob, sid))
        w = await attach(who, target)
        _, code = await drain_for(w, 2)
        want = {"another member": 4004, "another sign-in": 4004, "no such session": 4004, "feature off": 4003, "maintenance": 4503}[what]
        b1 = cur["bytes"]
        await asyncio.sleep(0.3)
        check(f"refused attach ({what}): {want}, and the current viewer is untouched (same socket, same record, still streaming)",
              code == want and cur["code"] is None and sess_b.viewer is viewer_before and server._rbrowser_viewers.get(sid) is rec_before
              and cur["bytes"] > b1 and not cur["ws"].closed, str((code, cur["code"])))
        if what == "feature off":
            server._rbrowser_cfg["rbrowser_enabled"] = True
        if what == "maintenance":
            async with adm.put(f"{base}/api/admin/maintenance", json={"active": False, "message": ""}) as r:
                assert r.status == 200
            await asyncio.sleep(0.1)
    check("a refused attach never opened the unit", unit_conns["total"] == n_conn and unit_conns["now"] == 1, str(unit_conns))

    # a new window whose previous one cannot finish closing in time: the previous one is aborted, the new one streams
    old_wait = server.RBROWSER_REPLACE_WAIT_S
    real_close = server._rbrowser_close
    stuck = sess_b.viewer
    rec_old = server._rbrowser_viewers[sid]

    async def hung_close(w, *a, **k):
        if w is stuck:
            await asyncio.sleep(60)
        return await real_close(w, *a, **k)
    server.RBROWSER_REPLACE_WAIT_S = 0.5
    server._rbrowser_close = hung_close
    t0 = time.monotonic()
    nxt = await open_window(bob, sid)
    ok_stream = await until(lambda: nxt["bytes"] > 20_000, 6)
    took = time.monotonic() - t0
    server.RBROWSER_REPLACE_WAIT_S = old_wait
    server._rbrowser_close = real_close
    check("an old window that cannot close in time is aborted and the new one streams (bounded wait)", ok_stream and took < 5, f"{took:.2f}s")
    check("the aborted viewer's record is finished and the unit has one connection (the new one)",
          rec_old.done.is_set() and server._rbrowser_viewers.get(sid) is not rec_old and await until(lambda: unit_conns["now"] == 1) and unit_conns["max"] == 1,
          str(unit_conns))
    check("the aborted window's socket is gone", await until(lambda: cur["rd"].done(), 3))
    cur["snd"].cancel()
    cur = nxt

    # two windows arriving together: one survives, the others are told 4012, never two pumping
    wins = await asyncio.gather(*[open_window(bob, sid) for _ in range(3)])
    await until(lambda: sum(1 for x in wins if x["code"] == 4012) >= 2 and cur["code"] is not None, 8)
    live = [x for x in wins if x["code"] is None]
    check("three windows at once: exactly one stays, the others see 4012", len(live) == 1 and sorted(x["code"] for x in wins if x["code"] is not None) == [4012, 4012] and cur["code"] == 4012,
          str([x["code"] for x in wins]))
    await asyncio.sleep(0.3)
    check("and the unit has one connection, never more than one in the whole run", unit_conns["now"] == 1 and unit_conns["max"] == 1, str(unit_conns))
    for x in wins + [cur]:
        x["snd"].cancel()
        await x["ws"].close()
    await asyncio.sleep(0.4)
    check("every exit closed the unit socket and left no viewer record", unit_conns["now"] == 0 and sid not in server._rbrowser_viewers and sess_b.viewer is None,
          str((unit_conns, list(server._rbrowser_viewers))))
    srv.close()
    await srv.wait_closed()

    # ---------------------------------------------------------------- a dead unit socket ends the session
    # (the registry's own check; the bridge only reports it)
    ws = await attach(bob, sid)
    _, code = await drain_for(ws, 3)
    check("a unit whose socket is gone ends the session as crash; the member sees 4013", code == 4013 and rbrowser.get(sid) is None
          and sess_b.end_reason == "crash", f"{code} {sess_b.end_reason}")
    await asyncio.sleep(0.5)
    cur = await db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'rbrowser_end' AND actor_id = ?", (env.uid["bob"],))
    check("and the end was audited by the bridge", (await cur.fetchone())[0] >= 1)

    # ---------------------------------------------------------------- feature or role withdrawn, maintenance, revocation, admin end
    sid = await make(bob)
    s2 = rbrowser.get(sid)
    server._rbrowser_cfg["rbrowser_min_role"] = "admin"
    ws = await attach(bob, sid)
    _, code = await drain_for(ws, 2)
    check("the role is re-read at attach: below it, 4003", code == 4003, str(code))
    server._rbrowser_cfg["rbrowser_min_role"] = "user"
    server._rbrowser_cfg["rbrowser_enabled"] = False
    ws = await attach(bob, sid)
    _, code = await drain_for(ws, 2)
    check("the feature switched off is re-read at attach: 4003", code == 4003, str(code))
    server._rbrowser_cfg["rbrowser_enabled"] = True
    async with adm.put(f"{base}/api/admin/maintenance", json={"active": True, "message": "x"}) as r:
        assert r.status == 200
    await asyncio.sleep(0.1)
    ws = await attach(bob, sid)
    _, code = await drain_for(ws, 2)
    check("global maintenance closes a member's attach with 4503", code == 4503, str(code))
    async with adm.put(f"{base}/api/admin/maintenance", json={"active": False}) as r:
        pass
    await asyncio.sleep(0.1)

    ws = await attach(bob, sid)
    await handshake(ws)
    await drain_for(ws, 0.3)
    async with adm.get(f"{base}/api/admin/rbrowser", headers={"Accept": "application/json"}) as r:
        rows = (await r.json())["sessions"]
        check("the admin list shows the session as attached", any(x["attached"] for x in rows))
    sp = sid[:6]
    async with adm.post(f"{base}/api/admin/rbrowser/sessions/{sp}/end", json={"confirm": True}) as r:
        check("an administrator ends the attached session", r.status == 200)
    _, code = await drain_for(ws, 3)
    check("the viewer is closed with 4013 'admin_end'", code == 4013, str(code))
    check("the reason text is a closed word", s2.end_reason == "admin_end")

    sid = await make(bob)
    s3 = rbrowser.get(sid)
    ws = await attach(bob, sid)
    await handshake(ws)
    await drain_for(ws, 0.3)
    async with bob.post(f"{base}/logout") as r:
        pass
    _, code = await drain_for(ws, 3)
    for _ in range(40):
        if s3.state == "ended":
            break
        await asyncio.sleep(0.1)
    check("revocation (sign-out) closes the socket (4001 or the session's own close) and ends the session as signed_out",
          code in (4001, 4013) and s3.state == "ended" and s3.end_reason == "signed_out", f"{code} {s3.state} {s3.end_reason}")
    n_end = 0
    for _ in range(40):                  # the audit row is written by the revocation task after the session ended
        cur = await db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'rbrowser_end' AND actor_id = ?", (env.uid["bob"],))
        n_end = (await cur.fetchone())[0]
        if n_end >= 3:
            break
        await asyncio.sleep(0.1)
    check("the sign-out end was audited", n_end >= 3, str(n_end))

    # a revocation that spares the session's own sign-in leaves it
    carol2 = await h.login(base, "carol")
    sid_c = await make(carol2)
    s4 = rbrowser.get(sid_c)
    tid = s4.token_id
    await server.close_user_websockets(env.uid["carol"], except_token_id=tid)
    await asyncio.sleep(0.3)
    check("a revocation that spares this sign-in does not end its session", s4.state == "running")
    await server.close_user_websockets(env.uid["carol"])
    for _ in range(40):
        if s4.state == "ended":
            break
        await asyncio.sleep(0.1)
    check("one that does not spare it ends the session at once", s4.state == "ended" and s4.end_reason == "signed_out")

    await server._rbrowser_stop()
    await carol2.close()
    await bob2.close()
    await h.shutdown(env)
    h.finish("test_rbrowser_bridge")


h.run(main, 180)
