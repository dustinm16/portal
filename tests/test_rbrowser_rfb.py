"""Server-side browser: the client-to-server RFB filter and the fake RFB server (design 5.4, 13).

Run: venv/bin/python tests/test_rbrowser_rfb.py

* ClientFilter handshake for RFB 3.3, 3.7 and 3.8; wrong version, wrong security type refused
* each allowed message type with its exact length, forwarded unchanged; the list of types returned
* messages split across chunks and merged within one chunk, at every byte offset
* SetEncodings rewritten to the allow-list (client order kept, extended clipboard, fence, continuous
  updates removed), n > 64 refused
* ClientCutText 262144 accepted, 262145 and a negative length refused, refused entirely with clipboard off
* types 150, 248, 250, 251, 255 and random bytes refused; the buffer bound; a dead filter stays dead
* the fake RFB server: handshake through the filter, update answer, record, ServerCutText, stall, ctl socket
* rbrowser.py: the contract imports without server.py, FakeLauncher serves both sockets
"""

import asyncio
import json
import os
import random
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import rbrowser  # noqa: E402
import rbrowser_rfb as rfb  # noqa: E402
from rbrowser_rfb import ClientFilter, Violation  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def refused(f, data):
    try:
        f.feed(data)
    except Violation as e:
        return e.reason
    return None


V38 = b"RFB 003.008\n"
V37 = b"RFB 003.007\n"
V33 = b"RFB 003.003\n"


def ready(clipboard=True, version=V38):
    f = ClientFilter(clipboard)
    hs = version + (b"" if version == V33 else b"\x01") + b"\x01"
    out, types = f.feed(hs)
    assert out == hs and types == []
    return f


def setpf():
    return b"\x00" + b"\x00" * 3 + struct.pack(">BBBBHHHBBB", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0) + b"\x00" * 3


def setenc(encs):
    return struct.pack(">BBH", 2, 0, len(encs)) + b"".join(struct.pack(">i", e) for e in encs)


def fbur():
    return struct.pack(">BBHHHH", 3, 1, 0, 0, 800, 600)


def key():
    return struct.pack(">BBxxI", 4, 1, 0x61)


def ptr():
    return struct.pack(">BBHH", 5, 1, 10, 20)


def cut(text):
    return struct.pack(">B3xI", 6, len(text)) + text


# ---- handshake
for name, ver in (("3.3", V33), ("3.7", V37), ("3.8", V38)):
    f = ClientFilter(True)
    hs = ver + (b"" if ver == V33 else b"\x01") + b"\x01"
    out, types = f.feed(hs)
    check(f"handshake {name} is forwarded unchanged and lists no type", out == hs and types == [])
check("version 3.5 refused", refused(ClientFilter(True), b"RFB 003.005\n") == "version")
check("a non-RFB first line refused", refused(ClientFilter(True), b"GET / HTTP/1.1\r\n\r\n") == "version")
check("security type 2 (VNC auth) refused", refused(ClientFilter(True), V38 + b"\x02") == "security")
check("security type 0 refused", refused(ClientFilter(True), V37 + b"\x00") == "security")
f = ClientFilter(True)
check("a partial version line waits", f.feed(b"RFB 003")[0] == b"")
check("3.3 sends no security byte: the next byte is ClientInit",
      ClientFilter(True).feed(V33 + b"\x00")[0] == V33 + b"\x00")

# ---- each allowed type
msgs = {0: setpf(), 3: fbur(), 4: key(), 5: ptr(), 6: cut(b"hello")}
for t, m in msgs.items():
    out, types = ready().feed(m)
    check(f"type {t} forwarded unchanged", out == m and types == [t], repr(out[:12]))
out, types = ready().feed(setenc([0, 1, 5, 6, 7, 16]))
check("type 2 (allowed encodings only) forwarded unchanged", out == setenc([0, 1, 5, 6, 7, 16]) and types == [2])
check("type 0 of 19 bytes waits", ready().feed(setpf()[:19]) == (b"", []))
allm = setpf() + setenc([0, 7]) + fbur() + key() + ptr() + cut(b"x")
out, types = ready().feed(allm)
check("all six types in one chunk, types in order", out == allm and types == [0, 2, 3, 4, 5, 6], str(types))

# ---- splitting at every offset
stream = V38 + b"\x01\x01" + allm + key() + key()
want_types = [0, 2, 3, 4, 5, 6, 4, 4]
ok_all = True
for cut_at in range(len(stream) + 1):
    f = ClientFilter(True)
    o1, t1 = f.feed(stream[:cut_at])
    o2, t2 = f.feed(stream[cut_at:])
    if o1 + o2 != stream or t1 + t2 != want_types:
        ok_all = False
        break
check("a stream split in two at every byte offset gives the same bytes and types", ok_all, f"offset {cut_at}")
f = ClientFilter(True)
o = b""
tl = []
for i in range(len(stream)):
    a, b = f.feed(stream[i:i + 1])
    o += a
    tl += b
check("the same stream one byte at a time", o == stream and tl == want_types)
f = ClientFilter(True)
o = b""
tl = []
for i in range(0, len(stream), 7):
    a, b = f.feed(stream[i:i + 7])
    o += a
    tl += b
check("the same stream in 7-byte chunks", o == stream and tl == want_types)

# ---- SetEncodings rewrite
dirty = [0, -1063131698, 1, -312, -313, 16, -23, -32, -33, -22, -247, -256, -257, -223, -224, -239, -307, -308,
         -258, 7, 1000, 0, 5, 6]
out, types = ready().feed(setenc(dirty))
want = [0, 1, 16, -23, -32, -247, -256, -223, -224, -239, -307, -308, 7, 5, 6]
(n,) = struct.unpack(">H", out[2:4])
got = list(struct.unpack(">%di" % n, out[4:]))
check("SetEncodings keeps allowed encodings in client order and drops the rest", got == want and out[:2] == b"\x02\x00", str(got))
check("SetEncodings length is recomputed", len(out) == 4 + 4 * len(want) and n == len(want))
check("extended clipboard (-1063131698), fence (-312) and continuous updates (-313) are removed",
      not ({-1063131698, -312, -313} & set(got)))
out, _ = ready().feed(setenc([-312, -313]))
check("SetEncodings with nothing allowed becomes an empty list", out == struct.pack(">BBH", 2, 0, 0))
out, _ = ready().feed(setenc([]))
check("an empty SetEncodings passes", out == struct.pack(">BBH", 2, 0, 0))
out, _ = ready().feed(setenc(list(range(0, 64))))
check("64 encodings accepted", out[:4] == struct.pack(">BBH", 2, 0, len([e for e in range(64) if e in rfb.ALLOWED_ENCODINGS])))
check("65 encodings refused at the header", refused(ready(), struct.pack(">BBH", 2, 0, 65)) == "encodings")
check("65 encodings refused whole", refused(ready(), setenc([0] * 65)) == "encodings")
check("n = 65535 refused without waiting for the body", refused(ready(), struct.pack(">BBH", 2, 0, 65535)) == "encodings")
check("allow-list pinned: JPEG -23..-32, compression -247..-256, 0 1 5 6 7 16",
      {e for e in rfb.ALLOWED_ENCODINGS if e >= 0} == {0, 1, 5, 6, 7, 16}
      and {e for e in rfb.ALLOWED_ENCODINGS if -32 <= e <= -23} == set(range(-32, -22))
      and {e for e in rfb.ALLOWED_ENCODINGS if -256 <= e <= -247} == set(range(-256, -246))
      and {e for e in rfb.ALLOWED_ENCODINGS if e < -256 or -246 <= e < -32}
      == {-223, -224, -239, -307, -308})

# ---- ClientCutText
out, types = ready().feed(cut(b"a" * 262144))
check("ClientCutText of 262144 bytes accepted", types == [6] and len(out) == 8 + 262144)
check("ClientCutText of 262145 refused", refused(ready(), cut(b"a" * 262145)) == "length")
check("ClientCutText header of 262145 refused before the text arrives",
      refused(ready(), struct.pack(">B3xI", 6, 262145)) == "length")
check("ClientCutText with a negative length refused", refused(ready(), struct.pack(">B3xi", 6, -1)) == "length")
check("ClientCutText with length 0xFFFFFFFF refused", refused(ready(), struct.pack(">B3xI", 6, 0xFFFFFFFF)) == "length")
check("ClientCutText of length 0 accepted", ready().feed(cut(b""))[1] == [6])
check("ClientCutText refused entirely when the clipboard is off", refused(ready(clipboard=False), cut(b"hi")) == "clipboard")
check("the default filter has the clipboard off (D4: the bridge builds it with no argument)", (lambda f: (f.feed(V38 + b"\x01\x01"), refused(f, cut(b"hi")))[1])(ClientFilter()) == "clipboard")
check("... even a one-byte start of it", refused(ready(clipboard=False), b"\x06") == "clipboard")
check("the other types still pass with the clipboard off",
      ready(clipboard=False).feed(key() + ptr() + fbur())[1] == [4, 5, 3])
f = ready()
big = cut(b"b" * 262144)
check("a 262152-byte message split in two halves is accepted",
      f.feed(big[:131000])[1] == [] and f.feed(big[131000:])[1] == [6])

# ---- refused types
for t in (1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 100, 150, 248, 250, 251, 255):
    check(f"type {t} refused", refused(ready(), bytes([t]) + b"\x00" * 30) == "type")
rnd = random.Random(7)
bad = [b for b in range(256) if b not in (0, 2, 3, 4, 5, 6)]
check("random bytes refused", all(refused(ready(), bytes([rnd.choice(bad)]) + os.urandom(16)) == "type" for _ in range(50)))
check("a refused type after valid messages: the valid ones do not leak out",
      refused(ready(), key() + b"\xfa" + b"\x00" * 9) == "type")

# ---- bound and dead state
f = ready()
try:
    f.feed(b"\x06" + b"\x00" * 3 + struct.pack(">I", 262144) + b"c" * 262144)
    check("the bound counts the residual, not the chunk: a 262152-byte chunk is fine", True)
except Violation as e:
    check("the bound counts the residual, not the chunk: a 262152-byte chunk is fine", False, e.reason)
f = ready()
o, t = f.feed((key() * 100000))
check("a chunk far above the bound made of whole messages is fine", len(o) == 800000 and len(t) == 100000)
# the length checks keep a legal residual below the bound; pin the constant and force the state
check("buffer bound is 262152", rfb.MAX_BUFFER == 262152)
f = ready()
f.feed(struct.pack(">B3xI", 6, 262144) + b"c" * 262143)
check("an incomplete ClientCutText of the longest size is held (residual 262151)", len(f._buf) == 262151)
_saved = rfb.MAX_BUFFER
rfb.MAX_BUFFER = 100
check("a residual above the bound refused (bound lowered for the test)",
      refused(ready(), struct.pack(">B3xI", 6, 200) + b"c" * 100) == "buffer")
rfb.MAX_BUFFER = _saved
f = ready()
refused(f, b"\xfa")
check("after a violation the filter stays dead", refused(f, key()) == "closed" and refused(f, b"") == "closed")
f = ready()
check("dead filter holds no buffer", (refused(f, b"\xfa"), len(f._buf))[1] == 0)

# ---- the fake server and the contract
import fake_rfb  # noqa: E402




async def fake_tests():
    with tempfile.TemporaryDirectory() as td:
        vnc = os.path.join(td, "vnc.sock")
        ctl = os.path.join(td, "ctl.sock")
        srv = fake_rfb.FakeRfb(vnc, ctl_path=ctl)
        await srv.start()
        try:
            r, w = await asyncio.open_unix_connection(vnc)
            filt = ClientFilter(True)
            ver = await r.readexactly(12)
            w.write(filt.feed(V38)[0])
            n = (await r.readexactly(1))[0]
            sec = await r.readexactly(n)
            check("fake: server says RFB 003.008 and offers only None", ver == V38 and sec == b"\x01")
            w.write(filt.feed(b"\x01")[0])
            res = await r.readexactly(4)
            w.write(filt.feed(b"\x01")[0])
            await w.drain()
            wh = struct.unpack(">HH", await r.readexactly(4))
            await r.readexactly(16)
            (nl,) = struct.unpack(">I", await r.readexactly(4))
            name = await r.readexactly(nl)
            check("fake: SecurityResult OK, ServerInit 800x600 with the fixed name",
                  res == b"\x00\x00\x00\x00" and wh == (800, 600) and name == fake_rfb.SERVER_NAME)
            body = setenc(dirty) + fbur() + key() + ptr() + cut(b"abc")
            fwd, types = filt.feed(body)
            w.write(fwd)
            await w.drain()
            upd = await asyncio.wait_for(r.readexactly(4 + 12 + 64), 3)
            check("fake: one small raw rectangle per update request",
                  upd[0] == 0 and struct.unpack(">H", upd[2:4])[0] == 1 and upd[4 + 8:4 + 12] == b"\x00" * 4)
            for _ in range(50):
                if len(srv.records) >= 5:
                    break
                await asyncio.sleep(0.02)
            check("fake: records the filtered messages in order", srv.message_types() == [2, 3, 4, 5, 6], str(srv.message_types()))
            rec_enc = srv.records[0][1]
            check("fake: it received the rewritten SetEncodings, not the client's",
                  rec_enc == ready().feed(setenc(dirty))[0])
            check("fake: records the handshake", srv.handshake == [V38, b"\x01", b"\x01"])
            await srv.send_cut_text(b"from the browser")
            sc = await asyncio.wait_for(r.readexactly(8 + 16), 3)
            check("fake: ServerCutText reaches the client", sc[0] == 3 and sc[8:] == b"from the browser")
            srv.stall = True
            w.write(fbur())
            await w.drain()
            try:
                await asyncio.wait_for(r.readexactly(1), 0.3)
                stalled = False
            except asyncio.TimeoutError:
                stalled = True
            check("fake: a stalled server answers no update request", stalled)
            w.close()
            # control socket
            out = []
            for line in (b'{"op":"ping"}\n', b'{"op":"resize","w":800,"h":600}\n', b'{"op":"navigate"}\n', b"nonsense\n"):
                cr, cw = await asyncio.open_unix_connection(ctl)
                cw.write(line)
                await cw.drain()
                out.append(json.loads(await asyncio.wait_for(cr.readline(), 3))["ok"])
                cw.close()
            check("fake ctl: ping and resize ok, other operations and bad JSON not ok", out == [True, True, False, False], str(out))
            # a violation at the unit: unknown type recorded and the connection dropped
            r2, w2 = await asyncio.open_unix_connection(vnc)
            await r2.readexactly(12)
            w2.write(V38)
            await r2.readexactly(2)
            w2.write(b"\x01")
            await r2.readexactly(4)
            w2.write(b"\x01")
            w2.write(b"\xfa")
            await w2.drain()
            await asyncio.sleep(0.2)
            check("fake: an unknown message type is recorded and the connection dropped",
                  srv.records[-1][0] == 250, str(srv.records[-1:]))
            w2.close()
        finally:
            await srv.stop()
        check("fake: stop removes both sockets", not os.path.exists(vnc) and not os.path.exists(ctl))


asyncio.run(fake_tests())


async def launcher_tests():
    with tempfile.TemporaryDirectory() as td:
        L = rbrowser.FakeLauncher(td)
        spec = rbrowser.LaunchSpec(ident="0123456789ab", width=800, height=600, clipboard="both",
                                   home_url="https://duckduckgo.com/", chromium="/usr/bin/chromium",
                                   memory_mb=2048, cpu_percent=150)
        res = await L.start(spec)
        check("FakeLauncher: unit name has the prefix, the id and .service", res.unit == "portal-rb-0123456789ab.service")
        check("FakeLauncher: expect_uid is this uid, expect_cgroup the fixed string, and cgroup_of agrees",
              res.expect_uid == os.getuid() and res.expect_cgroup == rbrowser.FAKE_CGROUP
              and L.cgroup_of(1) == rbrowser.FAKE_CGROUP)
        check("FakeLauncher: both sockets exist in the runtime directory",
              os.path.exists(os.path.join(res.runtime_dir, "vnc.sock")) and os.path.exists(os.path.join(res.runtime_dir, "ctl.sock")))
        st = os.lstat(os.path.join(res.runtime_dir, "vnc.sock"))
        import stat as _st
        check("FakeLauncher: vnc.sock is a socket owned by this uid", _st.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid())
        r, w = await asyncio.open_unix_connection(os.path.join(res.runtime_dir, "vnc.sock"))
        check("FakeLauncher: the RFB banner arrives", await r.readexactly(12) == V38)
        w.close()
        shown = await L.show([res.unit, "portal-rb-ffffffffffff.service"])
        check("FakeLauncher.show: active for the live unit, inactive for an unknown one",
              shown[res.unit]["ActiveState"] == "active" and shown["portal-rb-ffffffffffff.service"]["ActiveState"] == "inactive")
        await L.stop(res.unit)
        await L.stop(res.unit)
        check("FakeLauncher.stop is idempotent and removes the directory", not os.path.exists(res.runtime_dir))
        L2 = rbrowser.FakeLauncher(td, unit_prefix=rbrowser.TEST_PREFIX)
        res2 = await L2.start(spec)
        check("FakeLauncher takes a unit prefix", res2.unit.startswith("portal-rbtest-"))
        await L2.stop(res2.unit)
        # T1: the Launcher protocol has reset_failed and so does the fake: awaitable, answers None, no error for a unit that is not there
        check("T1: the Launcher protocol and FakeLauncher have an awaitable reset_failed (a unit that is not there is no error)",
              hasattr(rbrowser.Launcher, "reset_failed") and asyncio.iscoroutinefunction(rbrowser.FakeLauncher.reset_failed)
              and await L2.reset_failed(res2.unit) is None and await L2.reset_failed("portal-rb-0123456789ab.service") is None)


asyncio.run(launcher_tests())

s = rbrowser.Session(sid="s", unit="u", user_id=1, token_id="t", state="starting", runtime_dir="/x", expect_uid=1,
                     expect_cgroup="c", width=1, height=1)
check("Session defaults: not detached, no viewer, counters zero",
      s.detached_since is None and s.viewer is None and (s.bytes_in, s.bytes_out, s.net_in, s.net_out) == (0, 0, 0, 0))
names = ["availability", "preflight", "create", "get", "for_user", "all", "open_stream", "resize", "end", "usage",
         "note_activity", "boot_id", "seats", "tick", "on_revocation", "startup", "shutdown", "Launcher", "FakeLauncher",
         "Session", "Refused"]
check("every name of design section 9 exists", all(hasattr(rbrowser, n) for n in names),
      str([n for n in names if not hasattr(rbrowser, n)]))
try:
    _b1 = rbrowser.boot_id()
    _b2 = rbrowser.boot_id()
except Exception as _e:      # a stub body (lane A1's tree before the merge with lane A2) fails here instead of ending the script
    _b1 = _b2 = None
    print("   boot_id raised", _e.__class__.__name__)
check("boot_id() returns a non-empty str and two calls agree (the registry is real now)", isinstance(_b1, str) and _b1 != "" and _b1 == _b2)
src = (ROOT / "rbrowser.py").read_text()
check("rbrowser.py imports nothing from server.py and no third-party module at import time",
      not any(l.startswith(("import server", "from server", "import aiohttp", "from aiohttp", "import psutil", "from psutil"))
              for l in src.splitlines()))
check("rbrowser_rfb.py does no I/O", not any(w in (ROOT / "rbrowser_rfb.py").read_text() for w in ("import os", "import socket", "import asyncio", "open(")))

if failures:
    print(f"\ntest_rbrowser_rfb: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_rbrowser_rfb: all checks passed")
