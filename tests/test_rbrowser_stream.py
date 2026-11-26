"""Server-side browser: open_stream, the peer check and the control calls (design 5.3, A1 contract on ctl.sock). Real unix sockets in
a temp directory, no unit.

Run: venv/bin/python -B tests/test_rbrowser_stream.py

* a good connection passes; wrong uid, wrong cgroup and a symbolic link to another listener are refused (session ends crash, marker
  socket_mismatch); the other listener is never connected to
* connect failure ends the session crash without a marker; a stale socket file too
* open_stream (and every helper it uses) contains no word that names a kind of session; a session started by FakeLauncher goes through it
* the listener check runs before the first attach and is not repeated within 30 s
* resize and clip through ctl.sock: peer checks, the reply limits, ok:false kept apart from an empty clipboard, one clip at a time,
  nothing from the clipboard in any log record
"""

import asyncio
import inspect
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rbrowser  # noqa: E402
from rbrowser import FakeLauncher, Registry, Session, StreamRefused  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def nosleep(s=0):
    await asyncio.sleep(0)


FACTS = {"resolvers": [], "ifaces": [], "gateways": [], "gateways_scoped": []}
CFG = {"rbrowser_max_sessions": 2, "rbrowser_clipboard": "both"}
SENTINEL = "SENTINEL-clip-text-4711"


class Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception:
            self.lines.append("?")


class Rig:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="rbs-")
        self.launcher = FakeLauncher(os.path.join(self.dir, "fakes"))
        self.reg = Registry(launcher=self.launcher, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                            cgroup_root=os.path.join(self.dir, "cg"), tmp_dir=os.path.join(self.dir, "tmp"),
                            listener_scan=lambda pids: self.listeners, read_file=self.read_file)
        self.reg.ready = True
        self.reg._preflight = {"ok": True, "checks": []}
        self.listeners = False
        self.procs = "4242\n"      # the unit's cgroup.procs (an Exception instance is raised instead)
        self.servers = []
        self.seen = []        # connections the vnc listener accepted
        self.ctl_requests = []
        self.ctl_reply = lambda req: {"ok": True}
        self.ctl_raw = None   # bytes to send instead of the JSON reply
        self.ctl_delay = 0.0

    def read_file(self, path):
        if path.endswith("/cgroup.procs"):
            if isinstance(self.procs, Exception):
                raise self.procs
            return self.procs
        raise FileNotFoundError(path)

    def session(self, **over) -> Session:
        rt = os.path.join(self.dir, "rt")
        os.makedirs(rt, exist_ok=True)
        s = Session(sid="sid" + os.urandom(6).hex(), unit="portal-rb-0123456789ab.service", user_id=1, token_id="t", state="running", runtime_dir=rt,
                    expect_uid=os.getuid(), expect_cgroup=rbrowser.FAKE_CGROUP, width=1280, height=720, started=1.0, last_activity=1.0,
                    ident="0123456789ab", clipboard="both")
        for k, v in over.items():
            setattr(s, k, v)
        self.reg._sessions[s.sid] = s
        self.reg._by_user[s.user_id] = s
        self.reg._x[s.sid] = rbrowser._Ext(s.ident, "", s.unit)
        return s

    async def serve_vnc(self, path=None):
        async def handler(reader, writer):
            self.seen.append(1)
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            writer.close()
        srv = await asyncio.start_unix_server(handler, path=path or os.path.join(self.dir, "rt", "vnc.sock"))
        self.servers.append(srv)
        return srv

    async def serve_ctl(self):
        async def handler(reader, writer):
            line = await reader.readline()
            self.ctl_requests.append(line)
            if self.ctl_delay:
                await asyncio.sleep(self.ctl_delay)
            if self.ctl_raw is not None:
                writer.write(self.ctl_raw)
            else:
                try:
                    writer.write(json.dumps(self.ctl_reply(json.loads(line)), ensure_ascii=False).encode() + b"\n")
                except Exception:
                    pass
            try:
                await writer.drain()
            except Exception:
                pass
            writer.close()
        srv = await asyncio.start_unix_server(handler, path=os.path.join(self.dir, "rt", "ctl.sock"))
        self.servers.append(srv)

    async def close(self):
        for s in self.servers:
            s.close()
            try:
                await s.wait_closed()
            except Exception:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)


async def case(fn):
    rig = Rig()
    try:
        await fn(rig)
    finally:
        await rig.close()


# ---------------------------------------------------------------- open_stream

async def t_good(r):
    s = r.session()
    await r.serve_vnc()
    reader, writer = await rbrowser.Registry.open_stream(r.reg, s)
    greeting = await reader.readexactly(12)
    writer.close()
    check("a peer with the session's uid and cgroup passes", greeting == b"RFB 003.008\n" and s.state == "running")


async def t_wrong_uid(r):
    s = r.session(expect_uid=os.getuid() + 1)
    await r.serve_vnc()
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("wrong uid is refused with marker socket_mismatch", got is not None and got.reason == "socket_mismatch" and got.marker == "socket_mismatch" and got.ended)
    check("the session ends crash with the marker, the unit is stopped", s.state == "ended" and s.end_reason == "crash" and s.marker == "socket_mismatch")
    check("the exception text holds no path", "/" not in str(got) and str(got) == "socket_mismatch")


async def t_wrong_cgroup(r):
    s = r.session()
    await r.serve_vnc()
    r.launcher.cgroup_of = lambda pid: "/system.slice/somebody-else.service"
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("wrong cgroup is refused", got is not None and got.marker == "socket_mismatch" and s.end_reason == "crash" and s.marker == "socket_mismatch")


async def t_cgroup_reader_fails(r):
    s = r.session()
    await r.serve_vnc()

    def boom(pid):
        raise OSError("gone")
    r.launcher.cgroup_of = boom
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("a cgroup that cannot be read is a mismatch (unknown is refused)", got is not None and got.marker == "socket_mismatch")


async def t_symlink(r):
    s = r.session()
    other_dir = os.path.join(r.dir, "other")
    os.makedirs(other_dir)
    await r.serve_vnc(os.path.join(other_dir, "evil.sock"))
    os.symlink(os.path.join(other_dir, "evil.sock"), os.path.join(r.dir, "rt", "vnc.sock"))
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    await asyncio.sleep(0.05)
    check("a symbolic link to another listener is refused by lstat", got is not None and got.marker == "socket_mismatch" and s.marker == "socket_mismatch")
    check("the other listener was never connected to", r.seen == [])


async def t_not_a_socket(r):
    s = r.session()
    open(os.path.join(r.dir, "rt", "vnc.sock"), "w").close()
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("a regular file in place of the socket is a mismatch", got is not None and got.marker == "socket_mismatch")


async def t_connect_failure(r):
    s = r.session()
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("no socket: connect_failed, session ends crash without a marker", got is not None and got.reason == "connect_failed" and got.marker is None and got.ended
          and s.state == "ended" and s.end_reason == "crash" and s.marker is None)
    s2 = r.session()
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(os.path.join(r.dir, "rt", "vnc.sock"))      # a socket file with nobody listening: ECONNREFUSED
    try:
        await r.reg.open_stream(s2)
        got = None
    except StreamRefused as e:
        got = e
    stale.close()
    check("a stale socket file (connection refused) ends the session crash", got is not None and got.reason == "connect_failed" and s2.end_reason == "crash")


async def t_not_running(r):
    s = r.session(state="ended")
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("an ended session is refused as not_running", got is not None and got.reason == "not_running" and got.marker is None)


async def t_listener_check(r):
    s = r.session()
    await r.serve_vnc()
    cg = os.path.join(r.dir, "cg") + rbrowser.FAKE_CGROUP
    os.makedirs(cg)
    open(os.path.join(cg, "cgroup.procs"), "w").write("4242\n")
    r.listeners = True
    try:
        await r.reg.open_stream(s)
        got = None
    except StreamRefused as e:
        got = e
    check("a listener in the unit is found before the first attach: crash, marker listener_found",
          got is not None and got.reason == "listener_found" and got.marker == "listener_found" and s.marker == "listener_found" and s.end_reason == "crash")
    check("the unit was not connected to", r.seen == [])
    # a clean unit: checked once, not again within 30 s
    s2 = r.session()
    r.listeners = False
    calls = []
    r.reg._listener_scan = lambda pids: calls.append(pids) or False
    for _ in range(3):
        rd, wr = await r.reg.open_stream(s2)
        wr.close()
    check("the listener check is not repeated within 30 s", len(calls) == 1, str(len(calls)))
    r.reg._x[s2.sid].last_listener -= 31
    rd, wr = await r.reg.open_stream(s2)
    wr.close()
    check("it runs again after 30 s", len(calls) == 2)


def src_of(*objs):
    return "\n".join(inspect.getsource(o) for o in objs)


async def t_no_kind_branch(r):
    text = src_of(Registry.open_stream, Registry._connect_checked, Registry._connect_failed, Registry._mismatch, Registry._listener_check, rbrowser.open_stream)
    check("open_stream and its helpers contain no word 'fake' (no branch on the session kind)", "fake" not in text.lower())
    # a session started by FakeLauncher passes through the very same code
    reg = Registry(launcher=FakeLauncher(os.path.join(r.dir, "f2")), sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                   cgroup_root=os.path.join(r.dir, "cg2"), tmp_dir=os.path.join(r.dir, "tmp2"), read_file=r.read_file, listener_scan=lambda pids: False)
    reg.ready = True
    reg._preflight = {"ok": True, "checks": []}
    reg._pf_key = reg.preflight_key(CFG)
    s = await reg.create(1, "t", 1280, 720, CFG)
    reader, writer = await reg.open_stream(s)
    writer.write(b"RFB 003.008\n")
    ver = await asyncio.wait_for(reader.readexactly(12), 3)
    writer.close()
    check("a session of the fake launcher attaches through open_stream", ver.startswith(b"RFB 003.008") and s.expect_cgroup == rbrowser.FAKE_CGROUP)
    ok = await reg.resize(s, 1000, 700)
    check("and answers on ctl.sock (resize)", ok is True and (s.width, s.height) == (992, 688))
    await reg.end(s, "closed")


# ---------------------------------------------------------------- ctl.sock: resize and clip

async def t_resize(r):
    s = r.session()
    await r.serve_ctl()
    ok = await r.reg.resize(s, 1000, 700)
    req = json.loads(r.ctl_requests[0])
    check("resize sends op, w and h, clamped and snapped like the unit does", ok is True and req == {"op": "resize", "w": 992, "h": 688}, str(req))
    check("the session holds the new size", (s.width, s.height) == (992, 688))
    r.ctl_reply = lambda q: {"ok": False}
    check("ok false from the unit is False and the size is unchanged", await r.reg.resize(s, 800, 600) is False and (s.width, s.height) == (992, 688))
    r.ctl_reply = lambda q: {"ok": "yes"}
    check("only ok: true counts", await r.reg.resize(s, 800, 600) is False)
    r.ctl_raw = b"not json\n"
    check("an unparsable reply is False", await r.reg.resize(s, 800, 600) is False)
    check("a size that is not a number is False", await r.reg.resize(s, "x", 5) is False)
    r.ctl_raw = None
    r.ctl_reply = lambda q: {"ok": True}
    r.ctl_delay = 2.6
    t0 = asyncio.get_event_loop().time()
    saved = rbrowser.CTL_REPLY_S
    rbrowser.CTL_REPLY_S = 0.3
    check("a reply that comes too late is False after the time limit", await r.reg.resize(s, 800, 600) is False and asyncio.get_event_loop().time() - t0 < 2)
    rbrowser.CTL_REPLY_S = saved


async def t_ctl_peer_and_connect(r):
    s = r.session()
    check("no ctl.sock: resize is False and the session is NOT ended", await r.reg.resize(s, 800, 600) is False and s.state == "running")
    await r.serve_ctl()
    s.expect_uid += 1
    check("wrong uid on ctl.sock: False, and the session ends crash with marker socket_mismatch",
          await r.reg.resize(s, 800, 600) is False and s.state == "ended" and s.marker == "socket_mismatch" and s.end_reason == "crash")
    check("the request was never sent to the wrong peer", r.ctl_requests == [])
    ev = [e for e in r.reg.take_events() if e["kind"] == "marker"]
    check("the ctl.sock mismatch reaches lane B as a marker event", len(ev) == 1 and ev[0]["marker"] == "socket_mismatch" and ev[0]["event"] == "rbrowser_socket_mismatch"
          and ev[0]["user_id"] == 1, str(ev))


async def t_clip(r):
    s = r.session()
    await r.serve_ctl()
    rec = Records()
    logging.getLogger().addHandler(rec)
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        r.ctl_reply = lambda q: {"ok": True, "text": "héllo \U0001f600 " + SENTINEL, "truncated": False}
        res = await r.reg.clip(s)
        check("clip returns the text, ok true and truncated false", res == {"ok": True, "text": "héllo \U0001f600 " + SENTINEL, "truncated": False}, str(res)[:80])
        check("the request is exactly {op: clip}", json.loads(r.ctl_requests[-1]) == {"op": "clip"})
        r.ctl_reply = lambda q: {"ok": True, "text": "", "truncated": False}
        empty = await r.reg.clip(s)
        r.ctl_reply = lambda q: {"ok": False, "text": "", "truncated": False}
        failed = await r.reg.clip(s)
        check("an empty clipboard (ok true, text '') is not a failure", empty["ok"] is True and empty["text"] == "")
        check("ok false is kept apart from the empty clipboard", failed["ok"] is False and failed["text"] == "" and failed.get("why") == "failed" and empty != failed)
        r.ctl_reply = lambda q: {"ok": True, "text": "x" * 10, "truncated": True}
        check("truncated is passed on", (await r.reg.clip(s))["truncated"] is True)
        big = "\x01" * 262144
        r.ctl_reply = lambda q: {"ok": True, "text": big, "truncated": False}
        res = await r.reg.clip(s)
        check("a reply of about 1.5 MB (control characters escaped) is read to the newline", res["ok"] is True and res["text"] == big, f"{res['ok']} {res.get('why')}")
        r.ctl_reply = lambda q: {"ok": True, "text": "a" * 262145, "truncated": False}
        check("text above 262144 bytes is a failure", (await r.reg.clip(s))["ok"] is False)
        r.ctl_reply = lambda q: {"ok": True, "text": "€" * 90000, "truncated": False}
        check("the byte limit is in UTF-8 bytes", (await r.reg.clip(s))["ok"] is False)
        r.ctl_reply = lambda q: {"ok": True, "text": 5, "truncated": False}
        check("a non-string text is a failure", (await r.reg.clip(s))["ok"] is False)
        r.ctl_reply = lambda q: {"ok": True, "text": "a"}
        check("a reply without truncated is a failure", (await r.reg.clip(s))["ok"] is False)
        r.ctl_raw = b'{"ok": true, "text": "cut'
        check("a line without a newline (cut) is a failure", (await r.reg.clip(s))["ok"] is False)
        r.ctl_raw = b"[1, 2]\n"
        check("a reply that is not an object is a failure", (await r.reg.clip(s))["ok"] is False)
        r.ctl_raw = None
        r.ctl_reply = lambda q: {"ok": True, "text": SENTINEL, "truncated": False}
        await r.reg.clip(s)
    finally:
        logging.getLogger().removeHandler(rec)
    await r.reg.end(s, "closed")
    check("no log record holds clipboard text", not any(SENTINEL in line for line in rec.lines), str(rec.lines)[:200])


async def t_clip_gating(r):
    s = r.session(clipboard="to_browser")
    await r.serve_ctl()
    res = await r.reg.clip(s)
    check("clip is refused when the unit's clipboard is not both, and nothing is sent", res["ok"] is False and res["why"] == "refused" and r.ctl_requests == [])
    s.clipboard = "both"
    r.ctl_delay = 0.4
    r.ctl_reply = lambda q: {"ok": True, "text": "one", "truncated": False}
    a, b = await asyncio.gather(r.reg.clip(s), r.reg.clip(s))
    results = sorted([a, b], key=lambda x: x["ok"])
    check("one clip at a time per session: the second answers busy", results[0]["ok"] is False and results[0]["why"] == "busy" and results[1]["ok"] is True and len(r.ctl_requests) == 1)
    r.ctl_delay = 1.0
    saved = rbrowser.CLIP_REPLY_S
    rbrowser.CLIP_REPLY_S = 0.3
    slow = await r.reg.clip(s)
    rbrowser.CLIP_REPLY_S = saved
    check("a slow reply is a failure (unreachable or reply), never a text", slow["ok"] is False and slow["text"] == "")
    check("the reply wait is at least the unit's 5 s send time-out", rbrowser.CLIP_REPLY_S >= 5.0 and rbrowser.CONNECT_S == 2.0)
    s2 = r.session(state="ended")
    check("clip on an ended session is refused", (await r.reg.clip(s2))["ok"] is False)
    mod = await rbrowser.clip(s2)
    check("the module function delegates", mod["ok"] is False)


CASES = [t_good, t_wrong_uid, t_wrong_cgroup, t_cgroup_reader_fails, t_symlink, t_not_a_socket, t_connect_failure, t_not_running, t_listener_check,
         t_no_kind_branch, t_resize, t_ctl_peer_and_connect, t_clip, t_clip_gating]


async def main():
    for fn in CASES:
        print(f"# {fn.__name__}", flush=True)
        try:
            await asyncio.wait_for(case(fn), 60)
        except Exception as e:
            import traceback
            traceback.print_exc()
            check(fn.__name__ + " ran to the end", False, f"{e.__class__.__name__}: {e}")


asyncio.run(main())
check("PORTAL_RBROWSER_FAKE=1 without stage mode selects the real launcher", rbrowser.select_launcher_kind(False, {"PORTAL_RBROWSER_FAKE": "1"}) == "real"
      and rbrowser.select_launcher_kind(None, {"PORTAL_RBROWSER_FAKE": "1"}) == "real" and rbrowser.select_launcher_kind(True, {"PORTAL_RBROWSER_FAKE": "1"}) == "fake"
      and rbrowser.select_launcher_kind(True, {"PORTAL_RBROWSER_FAKE": "0"}) == "real")
print(f"\n{len(failures)} failure(s)" if failures else "\nall passed")
sys.exit(1 if failures else 0)
