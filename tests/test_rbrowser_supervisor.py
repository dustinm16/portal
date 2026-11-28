"""The unit supervisor rbrowser_unit/session.py and the probe's pure helpers (design 4.5, 8.2, 13).

Run: venv/bin/python tests/test_rbrowser_supervisor.py

Only text, numbers, pipes and socket pairs: no X server, no Chromium, no unit. The side-effect half of
session.py is exercised with fakes (processes with poll(), a recording xrandr runner, a fake debugging pipe).
"""

import ast
import importlib.util
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc:
        return True
    except Exception as e:
        print("   unexpected", type(e).__name__, e)
        return False
    return False


SRC = (ROOT / "rbrowser_unit" / "session.py").read_text()
S = load("rb_session_under_test", "rbrowser_unit/session.py")   # importing it must start nothing
import rbrowser_launch as L  # noqa: E402

# ---------------------------------------------------------------- source rules
tree = ast.parse(SRC)
imports = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports |= {a.name.split(".")[0] for a in node.names}
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.add(node.module.split(".")[0])
check("session.py imports only the standard library", imports <= set(sys.stdlib_module_names), str(imports - set(sys.stdlib_module_names)))
check("session.py imports nothing of the portal", not (imports & {"rbrowser", "rbrowser_launch", "rbrowser_policy", "rbrowser_rfb", "config", "aiohttp", "psutil"}))
check("main() runs only under the __main__ guard", 'if __name__ == "__main__":' in SRC and SRC.rstrip().endswith("sys.exit(main())"))
check("session.py has no shell and no eval", "shell=True" not in SRC and "os.system" not in SRC and "eval(" not in SRC)
check("session.py never writes RB_HOME anywhere but the Chromium command line",
      len(re.findall(r"cfg\[\"home\"\]", SRC)) == 1 and 'log(f"' in SRC and not re.search(r'log\([^)]*(home|url)', SRC, re.I))
check("session.py never asks Chromium for its targets (their descriptions carry URLs)",
      not any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("Target.") for n in ast.walk(tree)))
check("session.py names no screen capture or recording call",
      not any(w in SRC for w in ("captureScreenshot", "startScreencast", "session_recording", "recorder")))
check("the geometry constants equal the launcher's", (S.MIN_W, S.MAX_W, S.MAX_H) == (L.MIN_W, *L.CAPTURE_MAX), str((S.MIN_W, S.MAX_W, S.MAX_H)))

# ---------------------------------------------------------------- geometry
check("clamp: inside the range, snapped down to 16", S.clamp_geometry(1000, 700) == (992, 688))
check("clamp: too small", S.clamp_geometry(100, 50) == (560, 480))
check("clamp: too large", S.clamp_geometry(5000, 9000) == (1920, 1200))
check("clamp: the limits are kept", S.clamp_geometry(560, 480) == (560, 480) and S.clamp_geometry(500, 480) == (560, 480) and S.clamp_geometry(1920, 1200) == (1920, 1200))
check("clamp: every result is a multiple of 16 within range",
      all(560 <= w <= 1920 and 480 <= h <= 1200 and w % 16 == 0 and h % 16 == 0
          for w in range(1, 2500, 37) for h in range(1, 1500, 41) for (w, h) in [S.clamp_geometry(w, h)]))
check("clamp: refuses floats, booleans and text", all(raises(ValueError, S.clamp_geometry, *a) for a in ((1.5, 2), (True, 600), ("1", 2))))
check("parse_geometry: WxH", S.parse_geometry("1280x720") == (1280, 720))
check("parse_geometry: junk refused", all(raises(ValueError, S.parse_geometry, t) for t in ("", "1280", "1280x", "ax7", "1280x720x3", "-5x9", "1280 x720", None)))

# ---------------------------------------------------------------- arguments
check("home: https only", S.valid_home("https://duckduckgo.com/") and not any(S.valid_home(u) for u in
      ("--no-sandbox", "http://a.example/", "file:///etc/passwd", "https://a b/", "https://x\n/", "", None, "https://" + "a" * 400)))
check("clipboard modes", all(S.valid_clipboard(m) for m in ("both", "to_browser", "off")) and not S.valid_clipboard("x") and not S.valid_clipboard(None))
check("the clipboard flag function of the old modes is gone", not hasattr(S, "clipboard_flags"))

xv = S.xvfb_argv("/usr/bin/Xvfb", 7, "/run/x/xauth")
check("Xvfb: -displayfd with the pipe number, no TCP, no -nolisten local, RANDR, auth file",
      xv[:3] == ["/usr/bin/Xvfb", "-displayfd", "7"] and "-nolisten" in xv and xv[xv.index("-nolisten") + 1] == "tcp"
      and "local" not in xv and xv[xv.index("-auth") + 1] == "/run/x/xauth" and "RANDR" in xv and "1920x1200x24" in xv)
check("Xvfb: no fixed display number argument", not any(re.fullmatch(r":\d+", a) for a in xv))
vn = S.x11vnc_argv("/usr/bin/x11vnc", 12, "/run/x/xauth", "/run/x/vnc.sock")
vs = " ".join(vn)
check("x11vnc: unix socket only, no TCP port, no IPv6, safer, no commands",
      "-rfbport 0" in vs and "-rfbportv6 -1" in vs and "-noipv6" in vs and "-no6" in vs.split() and "-unixsock /run/x/vnc.sock" in vs
      and "-safer" in vn and "-nocmds" in vn and "-display :12" in vs and "-auth /run/x/xauth" in vs)
check("x11vnc: no -shared, forever, quiet, xrandr", "-shared" not in vn and "-forever" in vn and "-q" in vn and "-xrandr" in vn)
check("x11vnc: the selection exchange is off both ways, always (D4): the five flags and no -input C, no -seldir",
      all(f in vn for f in ("-nosel", "-noprimary", "-nosetprimary", "-noclipboard", "-nosetclipboard")) and "-seldir" not in vn
      and vn[vn.index("-input") + 1] == "KMB" and "C" not in vn[vn.index("-input") + 1])
check("x11vnc: the same arguments whatever the clipboard setting (it is not an argument any more)",
      raises(TypeError, S.x11vnc_argv, "x", 1, "a", "s", "both") and S.x11vnc_argv("x", 1, "a", "s") == S.x11vnc_argv("x", 1, "a", "s"))
ch = S.chromium_argv("/usr/bin/chromium", 1280, 720, "https://duckduckgo.com/")
check("Chromium: program first, home page last, window size", ch[0] == "/usr/bin/chromium" and ch[-1] == "https://duckduckgo.com/"
      and "--window-size=1280,720" in ch and "--window-position=0,0" in ch)
check("Chromium: no --no-sandbox, no debugging pipe, no debugging port (D3)", "--no-sandbox" not in ch and not any(a.startswith("--remote-debugging") for a in ch))
mk = (ROOT / "tools" / "make_screenshots.py").read_text()
offline = None
for node in ast.walk(ast.parse(mk)):
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "OFFLINE_CHROMIUM_ARGS" for t in node.targets):
        offline = ast.literal_eval(node.value)
check("Chromium: contains the whole offline set of make_screenshots.py, including --no-proxy-server",
      offline is not None and set(offline) <= set(ch) and "--no-proxy-server" in ch, str(set(offline or []) - set(ch)))
check("Chromium: the design's other flags", all(f in ch for f in ("--user-data-dir=/run/work/profile", "--password-store=basic", "--disable-gpu",
      "--disable-dev-shm-usage", "--mute-audio", "--disk-cache-size=134217728", "--media-cache-size=67108864", "--disable-logging")))
check("no argument of any child carries RB_ names or a display variable", not any("RB_" in a for a in xv + vn + ch))
env = S.child_env(5, "/run/x/xauth")
check("child_env: built from nothing, no proxy variable, display and authority set",
      set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "XAUTHORITY", "DISPLAY"} and env["DISPLAY"] == ":5" and env["PATH"] == "/usr/bin:/bin"
      and env["HOME"].startswith("/run/work/") and env["TMPDIR"] == "/run/work/tmp"
      and not any("proxy" in k.lower() for k in env))
check("the work area of the supervisor is the TemporaryFileSystem of the launch arguments", S.WORK_DIR == "/run/work" and S.PROFILE_DIR.startswith(S.WORK_DIR + "/"))
check("child_env: before the display is known there is no DISPLAY", "DISPLAY" not in S.child_env(xauth="/x"))

# ---------------------------------------------------------------- the authority file
ent = S.xauth_entry("00112233445566778899aabbccddeeff")
fam, = struct.unpack(">H", ent[:2])
check("xauth entry: wildcard family, empty address and number, MIT cookie, 16 data bytes",
      fam == 0xFFFF and ent[2:6] == b"\0\0\0\0" and b"MIT-MAGIC-COOKIE-1" in ent and ent[-16:] == bytes.fromhex("00112233445566778899aabbccddeeff")
      and len(ent) == 2 + 4 + 2 + 18 + 2 + 16)
check("displayfd: number and newline", S.parse_displayfd(b"12\n") == 12 and S.parse_displayfd(b"0") == 0)
check("displayfd: anything else refused", all(raises(ValueError, S.parse_displayfd, d) for d in (b"", b"x\n", b"-1\n", b"1 2\n", b"1\n2\n", None)))

# ---------------------------------------------------------------- display ownership proof
PROC_NET_UNIX = """Num       RefCount Protocol Flags    Type St Inode Path
ffff9a0000000000: 00000002 00000000 00010000 0001 01 5001 @/tmp/.X11-unix/X1
ffff9a0000000100: 00000002 00000000 00010000 0001 01 5002 /tmp/.X11-unix/X1
ffff9a0000000200: 00000003 00000000 00000000 0001 03 5003 @/tmp/.X11-unix/X1
ffff9a0000000300: 00000002 00000000 00010000 0001 01 5100 @/tmp/.X11-unix/X10
ffff9a0000000400: 00000002 00000000 00010000 0001 01 5200 /run/dbus/system_bus_socket
ffff9a0000000500: 00000003 00000000 00000000 0001 03 5300
"""
ents = S.parse_proc_net_unix(PROC_NET_UNIX)
check("proc/net/unix: lines with a path parsed, the header and path-less lines skipped", len(ents) == 5 and ents[0] == (5001, 0x10000, "@/tmp/.X11-unix/X1"), str(ents))
check("proc/net/unix: garbage lines are skipped", S.parse_proc_net_unix("h\nnot a line\nx: a b c d e f g h\n") == [])
check("socket_inodes: only socket links", S.socket_inodes(["socket:[5001]", "pipe:[9]", "/dev/null", "socket:[x]", "anon_inode:[eventfd]"]) == {5001})
check("display decision: owned (our Xvfb holds the listening socket; its accepted end is not a listener)", S.display_decision(ents, 1, {5001, 5002}) == "owned")
check("display decision: squatted (someone else holds the abstract name)", S.display_decision(ents, 1, {5002, 5003}) == "squatted")
check("display decision: missing", S.display_decision(ents, 7, {5001}) == "missing")
check("display decision: X1 is not X10 (exact match)", S.display_decision(ents, 10, {5100}) == "owned" and S.display_decision(ents, 10, {5001}) == "squatted")
check("display decision: a listener of ours plus one of someone else's is squatted",
      S.display_decision(ents + [(6000, 0x10000, "@/tmp/.X11-unix/X1")], 1, {5001}) == "squatted")
check("display decision: the filesystem socket alone does not count", S.display_decision([(5002, 0x10000, "/tmp/.X11-unix/X1")], 1, {5002}) == "missing")
check("display decision: a non-listening socket of that name does not count", S.display_decision([(5003, 0, "@/tmp/.X11-unix/X1")], 1, {5003}) == "missing")

# ---------------------------------------------------------------- xrandr
name, clock, t, flags = S.modeline(1280, 720)
check("modeline: name, consistent timings", name == "rb1280x720" and t[0] == 1280 and t[3] > t[2] > t[1] > t[0] and t[7] > t[6] > t[5] > t[4] == 720
      and float(clock) > 0 and flags == ["+hsync", "-vsync"])
QUERY = """Screen 0: minimum 1 x 1, current 1920 x 1200, maximum 1920 x 1200
screen connected primary 1920x1200+0+0 0mm x 0mm
   1920x1200     60.00*
   1280x720      60.00
   rb800x600     60.00 +
disconnected-thing disconnected
   9999x9999     60.00*
"""
check("xrandr query: first connected output, current mode, its modes", S.parse_xrandr_query(QUERY) == ("screen", "1920x1200", ["1920x1200", "1280x720", "rb800x600"]), str(S.parse_xrandr_query(QUERY)))
check("xrandr query: nothing connected", S.parse_xrandr_query("Screen 0: x\n") == (None, None, []))
nm, main, cleanup = S.resize_commands("/usr/bin/xrandr", "screen", "1920x1200", [], 1280, 720)
check("resize: only the output switch is an xrandr command (the mode is made by the mode holder), nothing to clean the first time",
      nm == "rb1280x720" and main == [["/usr/bin/xrandr", "--output", "screen", "--mode", "rb1280x720"]] and cleanup == [])
nm2, main2, cleanup2 = S.resize_commands("/usr/bin/xrandr", "screen", "rb1280x720", ["rb1280x720"], 1024, 768)
check("resize: the previous mode is removed after the switch (delmode then rmmode)",
      cleanup2 == [["/usr/bin/xrandr", "--delmode", "screen", "rb1280x720"], ["/usr/bin/xrandr", "--rmmode", "rb1280x720"]])
ma = S.mode_args(1280, 720)
check("mode args: name, dot clock in Hz, eight timings, +hsync -vsync as RandR flag bits",
      ma[0] == "rb1280x720" and ma[1] == int(round(float(S.modeline(1280, 720)[1]) * 1e6)) and ma[2] == S.modeline(1280, 720)[2] and ma[3] == 0x1 | 0x8, str(ma))


class FakeRunner:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv, env, timeout, stdin_bytes=None):
        self.calls.append(argv)
        return 1 if self.fail_on and self.fail_on in argv else 0


class FakeHolder:
    def __init__(self, ok=True):
        self.made, self.ok = [], ok

    def create(self, w, h):
        self.made.append((w, h))
        return self.ok


real_run = S._devnull_run
fr = FakeRunner()
S._devnull_run = fr
try:
    hold = FakeHolder()
    xr = S.Xrandr("/usr/bin/xrandr", {}, "screen", "1920x1200", hold)
    sizes = [(560 + 16 * i, 480 + 16 * (i % 7)) for i in range(20)]
    for w, h in sizes:
        assert xr.set_size(w, h, time.monotonic() + 5)
    made = [c[4] for c in fr.calls if c[1] == "--output"]
    removed = [c[2] for c in fr.calls if c[1] == "--rmmode" and len(c) > 2]
    check("20 resizes: 20 modes made by the holder and switched to, 19 removed, exactly one of ours left",
          len(hold.made) == 20 and len(made) == 20 and len(removed) == 19 and xr.created == [made[-1]] and xr.current == made[-1], str((len(made), len(removed))))
    n_before, h_before = len(fr.calls), len(hold.made)
    check("a resize to the size already set does nothing", xr.set_size(*sizes[-1], time.monotonic() + 5) and len(fr.calls) == n_before and len(hold.made) == h_before)
    fr2 = FakeRunner(fail_on="--output")
    S._devnull_run = fr2
    xr2 = S.Xrandr("/usr/bin/xrandr", {}, "screen", "1920x1200", FakeHolder())
    ok = xr2.set_size(800, 600, time.monotonic() + 5)
    check("a failed switch is reported, the new mode is taken back and nothing is recorded",
          not ok and xr2.current == "1920x1200" and xr2.created == [] and any(c[1] == "--rmmode" for c in fr2.calls))
    fr3 = FakeRunner()
    S._devnull_run = fr3
    xr3 = S.Xrandr("/usr/bin/xrandr", {}, "screen", "1920x1200", FakeHolder(ok=False))
    check("a mode the server refused is reported and no xrandr command runs", not xr3.set_size(800, 600, time.monotonic() + 5) and fr3.calls == [] and xr3.created == [])
finally:
    S._devnull_run = real_run

# ---------------------------------------------------------------- control requests
P = S.parse_ctl_request
check("ctl: ping", P(b'{"op":"ping"}\n') == ("ping",))
check("ctl: resize", P(b'{"op":"resize","w":1280,"h":720}\n') == ("resize", 1280, 720))
check("ctl: a request without a newline still parses", P(b'{"op":"ping"}') == ("ping",))
check("ctl: only the first line is read", P(b'{"op":"ping"}\n{"op":"kill"}\n') == ("ping",))
for label, data in (("unknown op", b'{"op":"navigate","url":"x"}'), ("no op", b'{}'), ("bad json", b'{op'), ("array", b'[1]'),
                    ("string", b'"ping"'), ("resize without sizes", b'{"op":"resize"}'), ("float size", b'{"op":"resize","w":1.5,"h":600}'),
                    ("bool size", b'{"op":"resize","w":true,"h":600}'), ("string size", b'{"op":"resize","w":"9","h":600}'),
                    ("zero size", b'{"op":"resize","w":0,"h":600}'), ("huge size", b'{"op":"resize","w":99999999,"h":600}'),
                    ("not utf-8", b'\xff\xfe'), ("insert", b'{"op":"insert","text":"x"}'), ("empty", b"")):
    check(f"ctl: {label} refused", raises(S.CtlError, P, data))
check("ctl: exactly 4096 bytes accepted, 4097 refused",
      P(b'{"op":"ping"}' + b" " * (4096 - 13)) == ("ping",) and raises(S.CtlError, P, b'{"op":"ping"}' + b" " * (4097 - 13)))
check("ctl: reply is one JSON line with only ok", S.ctl_reply(True) == b'{"ok": true}\n' and S.ctl_reply(0) == b'{"ok": false}\n')
check("ctl: the only operations in the source are ping, resize and clip", set(re.findall(r'op == "(\w+)"', SRC)) == {"ping", "resize", "clip"})
check("ctl: clip", P(b'{"op":"clip"}\n') == ("clip",) and P(b'{"op":"clip","text":"x"}') == ("clip",))
check("source: nothing of the debugging pipe is left",
      not any(w in SRC for w in ("CdpPipe", "cdp_frame", "reserve_pipe_fds", "remote-debugging", "window_bounds_params", "import fcntl", "Browser.", "pass_fds=(3")))

# ---------------------------------------------------------------- clip: the pure half
ck = S.clip_cut
check("clip_cut: short text unchanged", ck("héllo 😀 日本".encode()) == ("héllo 😀 日本", False))
check("clip_cut: exactly the limit is not cut", ck(b"a" * 262144) == ("a" * 262144, False))
check("clip_cut: one byte over is cut and flagged", ck(b"a" * 262145) == ("a" * 262144, True))
check("clip_cut: at most limit + 4 bytes are ever handed in, the cut is the limit", ck(b"a" * 262148) == ("a" * 262144, True))
emoji = "😀".encode()
for k in range(1, 4):
    d = b"a" * (262144 - k) + emoji + b"b" * 4
    txt, tr = ck(d)
    check(f"clip_cut: a 4-byte character split {k} byte(s) before the limit goes whole or not at all", tr and txt == "a" * (262144 - k) and "�" not in txt)
d = b"a" * 262140 + emoji + b"b" * 4
check("clip_cut: a character that ends exactly at the limit stays", ck(d) == ("a" * 262140 + "😀", True))
check("clip_cut: invalid bytes are replaced, not an error", ck(b"a\xffb") == ("a�b", False))
check("clip_cut: nothing", ck(b"") == ("", False))
rep = S.clip_reply(True, "😀 日本 é\n\"q\"", False)
check("clip_reply: one line of UTF-8 that is not ASCII-escaped", rep.endswith(b"\n") and rep.count(b"\n") == 1 and "😀".encode() in rep
      and json.loads(rep) == {"ok": True, "text": "😀 日本 é\n\"q\"", "truncated": False})
check("clip_reply: a failure carries no text and no truncation", json.loads(S.clip_reply(False, "secret", True)) == {"ok": False, "text": "", "truncated": False})
check("clip_reply: a cut text says so", json.loads(S.clip_reply(True, "a", True))["truncated"] is True)

# read_clipboard against small programs that stand in for xsel
import stat, tempfile  # noqa: E402
_tmp = Path(tempfile.mkdtemp(prefix="rbtest-clip-"))


def fake_xsel(name, body):
    p = _tmp / name
    p.write_text(f"#!{sys.executable}\nimport sys, time\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


rc = S.read_clipboard
t0 = time.monotonic()
check("read_clipboard: text with non-Latin letters and an emoji arrives whole",
      rc(fake_xsel("x1", "assert sys.argv[1:] == ['-o', '-b']\nsys.stdout.buffer.write('héllo 日本語 😀'.encode())"), {}) == (True, "héllo 日本語 😀", False))
check("read_clipboard: an empty clipboard is ok and empty", rc(fake_xsel("x2", "pass"), {}) == (True, "", False))
ok_, txt_, tr_ = rc(fake_xsel("x3", "sys.stdout.buffer.write(b'a' * 400000)"), {})
check("read_clipboard: 400000 bytes come back as 262144 and flagged", ok_ and len(txt_) == 262144 and tr_ is True)
ok_, txt_, tr_ = rc(fake_xsel("x4", "sys.stdout.buffer.write(b'a' * 262144)"), {})
check("read_clipboard: exactly 262144 bytes are not flagged", ok_ and len(txt_) == 262144 and tr_ is False)
t0 = time.monotonic()
check("read_clipboard: a program that does not answer is cut off at the time limit", rc(fake_xsel("x5", "time.sleep(30)"), {}, wait=0.4) == (False, "", False) and time.monotonic() - t0 < 4)
check("read_clipboard: a program that fails is a failure", rc(fake_xsel("x6", "sys.stdout.buffer.write(b'x'); sys.stdout.flush(); time.sleep(30)"), {}, wait=0.4) == (False, "", False))
check("read_clipboard: a missing program is a failure", rc(str(_tmp / "none"), {}) == (False, "", False))
check("read_clipboard: the time limit is 2 s and the byte limit 262144", S.CLIP_WAIT_S == 2.0 and S.CLIP_MAX == 262144)
import shutil as _sh  # noqa: E402
_sh.rmtree(_tmp, ignore_errors=True)

# ---------------------------------------------------------------- handle_ctl over a real socket pair


class FakeXr:
    def __init__(self, ok=True):
        self.ok, self.sizes = ok, []

    def set_size(self, w, h, deadline):
        self.sizes.append((w, h))
        return self.ok


class FakeWm:
    def __init__(self, conn_ref=None):
        self.refreshed, self.reply_seen_before, self.conn_ref = 0, None, conn_ref

    def refresh(self):
        self.refreshed += 1
        if self.conn_ref:
            try:
                self.reply_seen_before = self.conn_ref[0].recv(100, socket.MSG_DONTWAIT)
            except BlockingIOError:
                self.reply_seen_before = None
        return True


def ask(payload, xr=None, wm=None, clipboard="both", clip=None):
    a, b = socket.socketpair()
    a.sendall(payload)
    calls = []

    def fake_clip():
        calls.append(1)
        return clip if clip is not None else (True, "x", False)
    state = {"xrandr": xr or FakeXr(), "wm": wm or FakeWm(), "clipboard": clipboard, "clip": fake_clip, "clip_calls": calls}
    got = []

    def reader():
        a.settimeout(8)
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                chunk = a.recv(1 << 20)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        got.append(buf)
    th = threading.Thread(target=reader, daemon=True)
    th.start()
    S.handle_ctl(b, state)
    th.join(10)
    a.close()
    buf = got[0] if got else b""
    return buf, state


out, st = ask(b'{"op":"ping"}\n')
check("handle_ctl: ping answers ok", json.loads(out) == {"ok": True} and st["xrandr"].sizes == [] and st["wm"].refreshed == 0)
out, st = ask(b'{"op":"resize","w":1003,"h":9999}\n')
check("handle_ctl: resize clamps and snaps before it acts, then the window manager runs", json.loads(out) == {"ok": True}
      and st["xrandr"].sizes == [(992, 1200)] and st["wm"].refreshed == 1, str(st["xrandr"].sizes))
a_, b_ = socket.socketpair()
fw = FakeWm([a_])
a_.sendall(b'{"op":"resize","w":800,"h":600}\n')
S.handle_ctl(b_, {"xrandr": FakeXr(), "wm": fw, "clipboard": "both", "clip": None})
check("handle_ctl: the answer is sent after xrandr and the window manager pass, not before", fw.refreshed == 1 and fw.reply_seen_before is None
      and a_.recv(100) == b'{"ok": true}\n')
a_.close()
out, st = ask(b'{"op":"resize","w":800,"h":600}\n', xr=FakeXr(ok=False))
check("handle_ctl: a failed xrandr answers false and the window manager is not asked", json.loads(out) == {"ok": False} and st["wm"].refreshed == 0)
out, st = ask(b'{"op":"launch"}\n')
check("handle_ctl: an unknown operation answers false and does nothing", json.loads(out) == {"ok": False} and st["xrandr"].sizes == [])
out, st = ask(b'x' * 5000)
check("handle_ctl: an oversized request answers false", json.loads(out) == {"ok": False})
out, st = ask(b'{"op":"clip"}\n', clip=(True, "café \U0001F600", False))
check("handle_ctl: clip answers the text, ok and truncated", json.loads(out) == {"ok": True, "text": "café \U0001F600", "truncated": False} and st["clip_calls"] == [1])
out, st = ask(b'{"op":"clip"}\n', clip=(True, "a" * 262144, True))
check("handle_ctl: a long clip answer arrives whole and flagged", len(json.loads(out)["text"]) == 262144 and json.loads(out)["truncated"] is True)
out, st = ask(b'{"op":"clip"}\n', clip=(False, "", False))
check("handle_ctl: a failed read answers ok false with no text", json.loads(out) == {"ok": False, "text": "", "truncated": False})
for mode in ("off", "to_browser", None):
    out, st = ask(b'{"op":"clip"}\n', clipboard=mode)
    check(f"handle_ctl: clip with the setting {mode!r} answers false and never reads the clipboard", json.loads(out) == {"ok": False, "text": "", "truncated": False} and st["clip_calls"] == [])

# ---------------------------------------------------------------- the window manager: decisions
W = S.WmState
check("wm: the geometry is the whole screen at 0,0", W(1280, 720).geometry() == (0, 0, 1280, 720))
w = W(1280, 720)
check("wm: a map request is fitted, notified, mapped, raised and focused, in that order",
      w.map_request(5) == [("fit", 5), ("notify", 5), ("map", 5), ("raise", 5), ("focus", 5)] and w.stack == [5])
check("wm: a configure request gets the screen back and a notification, stacking asked for is ignored",
      w.configure_request(5) == [("fit", 5), ("notify", 5)] and w.configure_request(99) == [("fit", 99), ("notify", 99)] and w.stack == [5])
w.map_request(6)
check("wm: the newest window is on top", w.stack == [5, 6])
check("wm: a window mapped again moves to the top", (w.map_request(5), w.stack)[1] == [6, 5])
check("wm: when the top window goes, the next one is raised and focused", w.gone(5) == [("fit", 6), ("raise", 6), ("focus", 6)] and w.stack == [6])
check("wm: a window below the top going changes nothing visible", (w.map_request(7), w.map_request(8), w.gone(7), w.stack)[3] == [6, 8])
check("wm: an unmanaged window going gives nothing", w.gone(1234) == [])
check("wm: the last window going leaves nothing to raise", (w.gone(8), w.gone(6))[1] == [] and w.stack == [])
w = W(1280, 720)
w.map_request(1)
w.map_request(2)
check("wm: a new screen size moves every managed window", w.resize(800, 600) == [("fit", 1), ("notify", 1), ("fit", 2), ("notify", 2)] and w.geometry() == (0, 0, 800, 600))
check("wm: the same size again does nothing", w.resize(800, 600) == [])
w = W(800, 600)
for n in range(1, 200):
    w.map_request(n)
check("wm: the list of managed windows is bounded", len(w.stack) == S.WM_MAX_WINDOWS and w.stack[-1] == 199)
w = W(800, 600)
w.map_request(1)
check("wm_dispatch: kinds", S.wm_dispatch(w, "configure_request", 1) == [("fit", 1), ("notify", 1)] and S.wm_dispatch(w, "map_request", 2)[2] == ("map", 2)
      and S.wm_dispatch(w, "unmap", 2)[0] == ("fit", 1) and S.wm_dispatch(w, "destroy", 1) == [] and S.wm_dispatch(w, "bogus", 1) == [])
w.map_request(3)
check("wm_dispatch: a reparent to the root leaves the window managed, to anything else ends it",
      S.wm_dispatch(w, "reparent", 3, new_parent_is_root=True) == [] and w.stack == [3] and S.wm_dispatch(w, "reparent", 3) == [] and w.stack == [])

# the X structures: the window is at offset 40 (offset 32 is the event window, the root), 192 bytes per event
import ctypes  # noqa: E402
check("wm: X event layout (x86-64 Xlib)", ctypes.sizeof(S._XEvent) == 192 and S._XSubEvent.window.offset == 40 and S._XSubEvent.parent.offset == 32
      and ctypes.sizeof(S._XConfigureRequest) == 96 and S._XConfigureRequest.window.offset == 40 and S._XConfigureRequest.value_mask.offset == 88
      and S._XConfigureEvent.window.offset == 40 and S._XSubEvent.extra.offset == 48 and S._XErrorEvent.serial.offset == 24 and S._XErrorEvent.error_code.offset == 32)
check("wm: event numbers of X11.h", (S.EV_DESTROY_NOTIFY, S.EV_UNMAP_NOTIFY, S.EV_MAP_REQUEST, S.EV_REPARENT_NOTIFY, S.EV_CONFIGURE_NOTIFY, S.EV_CONFIGURE_REQUEST) == (17, 18, 20, 21, 22, 23)
      and S.MASK_SUBSTRUCTURE_REDIRECT == 1 << 20 and S.MASK_SUBSTRUCTURE_NOTIFY == 1 << 19 and S.BAD_ACCESS == 10)


# ---------------------------------------------------------------- the window manager on a fake Xlib
class FakeFunc:
    def __init__(self, lib, name):
        self.lib, self.name, self.restype, self.argtypes = lib, name, None, None

    def __call__(self, *a):
        lib, n = self.lib, self.name
        lib.calls.append((n, a))
        if n in lib.boom:
            raise OSError("boom")
        if n == "XPending":
            return len(lib.events)
        if n == "XNextEvent":
            ev = lib.events.pop(0)
            ctypes.memmove(ctypes.addressof(a[1]._obj), ctypes.addressof(ev), ctypes.sizeof(ev))
            return 0
        if n == "XGetGeometry":
            a[5]._obj.value, a[6]._obj.value = lib.size
            return 1
        if n == "XConnectionNumber":
            return 9
        if n == "XNextRequest":
            return 100
        if n == "XInternAtom":
            return lib.atoms.setdefault(a[1], 100 + len(lib.atoms))
        if n == "XGetWindowProperty":
            name = next((k for k, v in lib.atoms.items() if v == a[2]), None)
            if (a[1], name) in lib.fail_props:
                return 3                                                         # BadWindow: the call itself failed
            prop = lib.props.get((a[1], name), lib.default_props.get(name))
            if prop is None:
                a[7]._obj.value, a[11]._obj.value = 0, None
                return 0
            fmt, raw = prop
            buf = ctypes.create_string_buffer(raw, len(raw) + 1)
            lib.keep.append(buf)
            width = {8: 1, 16: 2, 32: ctypes.sizeof(ctypes.c_long)}[fmt]
            a[7]._obj.value, a[8]._obj.value, a[9]._obj.value, a[11]._obj.value = 31, fmt, len(raw) // width, ctypes.addressof(buf)
            a[10]._obj.value = 4 if (a[1], name) in lib.more_props else 0         # bytes_after
            return 0
        return 0


class FakeLib:
    def __init__(self):
        self.calls, self.events, self.size, self.boom, self._f = [], [], (800, 600), set(), {}
        self.fail_props, self.more_props = set(), set()                      # (window, name): the read fails / leaves bytes_after > 0
        self.atoms, self.props, self.keep = {}, {}, []                       # atom name -> id; (window, property name) -> (format, bytes)
        self.default_props = {b"WM_WINDOW_ROLE": (8, b"browser")}            # a Chromium browser window unless a test says otherwise

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._f.setdefault(name, FakeFunc(self, name))

    def named(self, n):
        return [a for name, a in self.calls if name == n]


class FakeHolder:
    def __init__(self, bad_access=False):
        self.x11, self.dpy, self.root, self.bad_access = FakeLib(), 1, 77, bad_access
        self.errors, self.recent = 0, []

    def errors_since(self, serial, code=None):
        return 1 if self.bad_access and code == S.BAD_ACCESS else 0


def xev(kind, parent, window, extra=0):
    ev = S._XEvent()
    sub = ctypes.cast(ctypes.byref(ev), ctypes.POINTER(S._XSubEvent)).contents
    sub.type, sub.parent, sub.window, sub.extra = kind, parent, window, extra
    return ev


hd = FakeHolder()
wmn = S.WindowManager(hd)
lib = hd.x11
check("wm start: the root is read, the substructure redirect is asked for and the connection is synced",
      wmn.state.geometry() == (0, 0, 800, 600) and wmn.fd == 9
      and lib.named("XSelectInput") == [(1, 77, S.MASK_SUBSTRUCTURE_REDIRECT | S.MASK_SUBSTRUCTURE_NOTIFY | S.MASK_STRUCTURE_NOTIFY)]
      and [n for n, a in lib.calls].index("XSync") < [n for n, a in lib.calls].index("XSelectInput")
      and [n for n, a in lib.calls][-1] == "XSync")
check("wm start: another window manager (BadAccess) ends the start", raises(S.SupervisorError, S.WindowManager, FakeHolder(bad_access=True)))
lib.calls.clear()
lib.events += [xev(S.EV_MAP_REQUEST, 77, 5)]
check("wm: pump serves a map request", wmn.pump() == 1 and wmn.state.stack == [5]
      and lib.named("XMoveResizeWindow") == [(1, 5, 0, 0, 800, 600)] and lib.named("XSetWindowBorderWidth") == [(1, 5, 0)]
      and lib.named("XMapWindow") == [(1, 5)] and lib.named("XRaiseWindow") == [(1, 5)] and lib.named("XSetInputFocus") == [(1, 5, S.REVERT_TO_POINTER_ROOT, 0)])
sent = lib.named("XSendEvent")
ce = ctypes.cast(ctypes.byref(sent[0][4]._obj), ctypes.POINTER(S._XConfigureEvent)).contents
check("wm: the synthetic ConfigureNotify names the window and the full screen", len(sent) == 1 and sent[0][1] == 5 and sent[0][4]._obj is not None
      and (ce.type, ce.window, ce.x, ce.y, ce.width, ce.height, ce.border_width) == (22, 5, 0, 0, 800, 600, 0))
# fix pass 2 (F2): a window that is not a Chromium browser window is never mapped (video Picture-in-Picture: no role, ABOVE and STICKY)
def _state_atoms(lib_, *names):
    import struct
    return (32, b"".join(struct.pack("@l", lib_.atoms.setdefault(n, 100 + len(lib_.atoms))) for n in names))


def _map_one(setup):
    """Serve a MapRequest of window 8 on a fresh fake X after `setup(lib)`; -> (the actions the fake saw, the stack)."""
    h = FakeHolder()
    m = S.WindowManager(h)
    setup(h.x11)
    h.x11.calls.clear()
    h.x11.events += [xev(S.EV_MAP_REQUEST, 77, 8)]
    m.pump()
    return {n for n, _a in h.x11.calls if n in ("XMapWindow", "XMoveResizeWindow", "XRaiseWindow", "XSetInputFocus", "XSendEvent")}, m.state.stack


_all_actions = {"XMapWindow", "XMoveResizeWindow", "XRaiseWindow", "XSetInputFocus", "XSendEvent"}
acts, stk = _map_one(lambda l_: None)
check("wm: a window with the role 'browser' and no state is shown (fitted, mapped, raised, focused)", acts == _all_actions and stk == [8])
acts, stk = _map_one(lambda l_: l_.props.update({(8, b"WM_WINDOW_ROLE"): (8, b"pop-up")}))
check("wm: a window with the role 'pop-up' is shown", acts == _all_actions and stk == [8])
def _pip(l_):
    l_.props[(8, b"WM_WINDOW_ROLE")] = None
    l_.default_props = {}
    l_.props[(8, b"_NET_WM_STATE")] = _state_atoms(l_, b"_NET_WM_STATE_ABOVE", b"_NET_WM_STATE_STICKY")
acts, stk = _map_one(_pip)
check("wm: the window video Picture-in-Picture makes (no role, no class, ABOVE and STICKY: as measured live) is NOT mapped, fitted, raised or focused, and is not managed",
      acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.default_props.clear())
check("wm: a window with no role at all is not mapped", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.props.update({(8, b"_NET_WM_STATE"): _state_atoms(l_, b"_NET_WM_STATE_ABOVE")}))
check("wm: a window with the right role but marked always-on-top is not mapped", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.props.update({(8, b"_NET_WM_STATE"): _state_atoms(l_, b"_NET_WM_STATE_STICKY")}))
check("wm: a window with the right role and another state (sticky) is shown", acts == _all_actions and stk == [8])
acts, stk = _map_one(lambda l_: l_.props.update({(8, b"WM_WINDOW_ROLE"): (8, b"x11-browser")}))
check("wm: any other role is not mapped", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.boom.add("XGetWindowProperty"))
check("wm: a property read that fails refuses the window (fail closed) and does not stop the manager", acts == set() and stk == [])
# R6: a failed read is not an absent property
acts, stk = _map_one(lambda l_: l_.fail_props.add((8, b"_NET_WM_STATE")))
check("wm: a failed read of _NET_WM_STATE (the role is fine) refuses the window: failed is not absent", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.fail_props.add((8, b"WM_WINDOW_ROLE")))
check("wm: a failed read of the role refuses the window", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: (l_.props.update({(8, b"_NET_WM_STATE"): _state_atoms(l_, b"_NET_WM_STATE_STICKY")}), l_.more_props.add((8, b"_NET_WM_STATE"))))
check("wm: bytes_after > 0 on _NET_WM_STATE (more atoms than were read) refuses the window", acts == set() and stk == [])
acts, stk = _map_one(lambda l_: l_.more_props.add((8, b"WM_WINDOW_ROLE")))
check("wm: bytes_after > 0 on the role refuses the window", acts == set() and stk == [])
_h6 = FakeHolder()
_m6 = S.WindowManager(_h6)
_h6.x11.fail_props.add((9, b"X"))
_h6.x11.props[(10, b"X")] = (32, b"")
check("wm: _property tells absent (None) from failed (PROP_FAILED) from present",
      _m6._property(11, b"NOPE") is None and _m6._property(9, b"X") is S.PROP_FAILED and _m6._property(8, b"WM_WINDOW_ROLE") == (8, b"browser"))
check("wm_may_show: only the roles browser and pop-up, only when not always-on-top; unknown is refused",
      S.wm_may_show("browser", False) and S.wm_may_show("pop-up", False) and not S.wm_may_show("browser", True) and not S.wm_may_show("", False)
      and not S.wm_may_show(None, False) and not S.wm_may_show("pip", False) and not S.wm_may_show("browser", None))
_wst = W(800, 600)
_wst.map_request(1)
check("WmState: map_request with show=False gives no action, manages nothing, and takes a window that was managed out of the stack",
      _wst.map_request(2, show=False) == [] and _wst.stack == [1] and _wst.map_request(1, show=False) == [] and _wst.stack == []
      and S.wm_dispatch(_wst, "map_request", 3, show=False) == [] and S.wm_dispatch(_wst, "map_request", 3)[2] == ("map", 3))
lib.calls.clear()
lib.events += [xev(S.EV_CONFIGURE_REQUEST, 77, 5), xev(S.EV_CONFIGURE_REQUEST, 77, 42)]
wmn.pump()
check("wm: a configure request is forced to the screen, also from a window that is not mapped yet",
      lib.named("XMoveResizeWindow") == [(1, 5, 0, 0, 800, 600), (1, 42, 0, 0, 800, 600)] and wmn.state.stack == [5])
lib.calls.clear()
lib.events += [xev(S.EV_MAP_REQUEST, 99, 6), xev(S.EV_UNMAP_NOTIFY, 99, 5), xev(S.EV_DESTROY_NOTIFY, 99, 5), xev(S.EV_REPARENT_NOTIFY, 99, 5, 99)]
wmn.pump()
check("wm: events that are not for the root's children are ignored", wmn.state.stack == [5] and lib.named("XMapWindow") == [])
lib.events += [xev(S.EV_MAP_REQUEST, 77, 6)]
wmn.pump()
lib.calls.clear()
lib.events += [xev(S.EV_UNMAP_NOTIFY, 77, 6)]
wmn.pump()
check("wm: when the top window is unmapped the one below is raised and focused again",
      wmn.state.stack == [5] and lib.named("XRaiseWindow") == [(1, 5)] and lib.named("XSetInputFocus") == [(1, 5, S.REVERT_TO_POINTER_ROOT, 0)])
lib.calls.clear()
lib.events += [xev(S.EV_DESTROY_NOTIFY, 77, 1234)]
wmn.pump()
check("wm: a window nobody manages going does nothing", lib.named("XRaiseWindow") == [] and wmn.state.stack == [5])
lib.size = (560, 480)
lib.calls.clear()
check("wm: refresh reads the screen and fits the managed window", wmn.refresh() and lib.named("XMoveResizeWindow") == [(1, 5, 0, 0, 560, 480)] and wmn.state.geometry() == (0, 0, 560, 480))
lib.calls.clear()
check("wm: refresh with the same size does nothing", wmn.refresh() and lib.named("XMoveResizeWindow") == [])
lib.size = (640, 480)
lib.events += [xev(S.EV_CONFIGURE_NOTIFY, 77, 77)]
lib.calls.clear()
wmn.pump()
check("wm: a ConfigureNotify of the root makes the windows follow", lib.named("XMoveResizeWindow") == [(1, 5, 0, 0, 640, 480)])
lib.calls.clear()
lib.events += [xev(S.EV_CONFIGURE_NOTIFY, 77, 5)]
wmn.pump()
check("wm: a ConfigureNotify of another window is not a screen change", lib.named("XGetGeometry") == [])
lib.boom.add("XMapWindow")
lib.events += [xev(S.EV_MAP_REQUEST, 77, 8), xev(S.EV_CONFIGURE_REQUEST, 77, 8)]
lib.calls.clear()
try:
    served = wmn.pump()
    ok_ = True
except Exception:
    served, ok_ = -1, False
check("wm: an exception while serving one event does not stop the next one and never leaves pump", ok_ and served == 2 and lib.named("XMoveResizeWindow") != [], str(served))
lib.boom.discard("XMapWindow")
lib.events += [xev(S.EV_CONFIGURE_REQUEST, 77, 5) for _ in range(300)]
check("Chromium's flags switch document Picture-in-Picture off, once, and no other --disable-features flag competes with it (G13 measured a full-screen PiP window without it)",
      S.CHROMIUM_FLAGS.count("--disable-features=DocumentPictureInPictureAPI") == 1 and sum(1 for f in S.CHROMIUM_FLAGS if f.startswith("--disable-features")) == 1
      and "--disable-features=DocumentPictureInPictureAPI" in S.chromium_argv("/usr/bin/chromium", 800, 600, "https://duckduckgo.com/")
      and re.search(r'"--disable-features=DocumentPictureInPictureAPI", ?', SRC) is not None)
check("wm: a pump drains a backlog of 300 events in one go (a time budget, not a count of 256)", wmn.pump() == 300 and len(lib.events) == 0)
lib.events += [xev(S.EV_CONFIGURE_REQUEST, 77, 5) for _ in range(300)]
_ticks = iter(range(0, 10 ** 6))
_n = wmn.pump(budget_s=100, clock=lambda: next(_ticks))
check("wm: a pump stops when its time budget is used up and leaves the rest for the next pass", 0 < _n < 300 and len(lib.events) == 300 - _n, str(_n))
check("wm: pending() tells whether Xlib holds events, and is False when XPending fails",
      wmn.pending() is True and (lib.events.clear() or wmn.pending() is False) and (lib.boom.add("XPending") or wmn.pending() is False))
lib.boom.discard("XPending")
check("wm: the loop does not sleep while events are pending (select timeout 0), and the pump has a time budget",
      "sel.select(0 if wm.pending() else LOOP_S)" in SRC and "WM_EVENTS_PER_PASS" not in SRC and S.WM_PUMP_BUDGET_S <= 0.5)
lib.events += [xev(S.EV_CONFIGURE_REQUEST, 77, 5) for _ in range(44)]
lib.boom.add("XPending")
check("wm: a failing XPending is caught", wmn.pump() == 0)
lib.boom.clear()

class OpenLib(FakeLib):
    def __init__(self, fail):
        super().__init__()
        self.fail, self.opens = fail, 0
        self.XOpenDisplay = lambda name: (setattr(self, "opens", self.opens + 1), 0 if self.opens <= self.fail else 1)[1]
        self.XDefaultRootWindow = lambda d: 77


class OpenCdll:
    def __init__(self, fail):
        self.lib = OpenLib(fail)

    def __call__(self, name):
        return self.lib if "X11" in name else FakeLib()


def holder_with(fail):
    cd = OpenCdll(fail)
    try:
        S.ModeHolder.__new__(S.ModeHolder)
        h = S.ModeHolder(1, "/dev/null", "screen", cdll=cd, sleep=lambda s: None)
        return cd.lib.opens, h
    except S.SupervisorError as e:
        return cd.lib.opens, str(e)


_o, _h = holder_with(3)
check("holder: a display that does not open at first is tried again", _o == 4)
_o, _h = holder_with(99)
check("holder: after OPEN_TRIES failures the start fails", _o == S.OPEN_TRIES and isinstance(_h, str) and "X connection" in _h, str((_o, _h)))

# the error handler of the holder: errors are kept with the serial of the request
hh = object.__new__(S.ModeHolder)
hh.errors, hh.recent, hh.on_lost = 0, __import__("collections").deque(maxlen=64), None
for serial, code in ((10, 3), (20, 10), (30, 8)):
    ee = S._XErrorEvent()
    ee.serial, ee.error_code = serial, code
    hh._on_error(None, ctypes.pointer(ee))
check("holder: errors are counted and kept with serial and code", hh.errors == 3 and list(hh.recent) == [(10, 3), (20, 10), (30, 8)])
check("holder: errors_since counts only the later requests, optionally one code",
      hh.errors_since(15) == 2 and hh.errors_since(15, S.BAD_ACCESS) == 1 and hh.errors_since(31) == 0 and hh.errors_since(0, 3) == 1)
for i in range(100):
    hh.recent.append((i, 0))
check("holder: the record of errors is bounded", len(hh.recent) == 64)

# ---------------------------------------------------------------- exit codes
check("exit: Chromium ended by itself with status 0 -> 0", S.exit_code(True, "chromium", 0, False) == 0)
check("exit: Chromium ended with another status -> 4", S.exit_code(True, "chromium", 1, False) == 4 and S.exit_code(True, "chromium", -9, False) == 4)
check("exit: Xvfb, x11vnc or the window manager gone -> 4, even with status 0", all(S.exit_code(True, n, 0, False) == 4 for n in ("xvfb", "x11vnc", "wm")))
check("exit: a stop request -> 4", S.exit_code(True, None, None, True) == 4 and S.exit_code(True, "chromium", 0, True) == 4)
check("exit: a failed display proof -> 3 whatever else happened", S.exit_code(False, None, None, False) == 3 and S.exit_code(False, "chromium", 0, True) == 3)
check("exit: a failed set-up -> 4", S.exit_code(True, "setup", 1, False) == 4)

# ---------------------------------------------------------------- the loop and the shutdown
class FakeProc:
    def __init__(self, name, dies_after=None, ignores_term=False, log=None):
        self.name, self.dies_after, self.ignores_term, self.log = name, dies_after, ignores_term, log
        self.rc, self.polls = None, 0

    def poll(self):
        self.polls += 1
        if self.rc is None and self.dies_after is not None and self.polls > self.dies_after:
            self.rc = 0
        return self.rc

    def terminate(self):
        self.log.append(("term", self.name))
        if not self.ignores_term:
            self.rc = 0

    def kill(self):
        self.log.append(("kill", self.name))
        self.rc = -9

    def wait(self, timeout=None):
        self.log.append(("wait", self.name))
        return self.rc


lg = []
kids = [("xvfb", FakeProc("xvfb", log=lg)), ("x11vnc", FakeProc("x11vnc", log=lg)), ("chromium", FakeProc("chromium", dies_after=3, log=lg))]
ticks = []
res = S.watch(kids, lambda: ticks.append(1), lambda: False)
check("watch: returns the first child that is gone, after waiting each second", res == ("chromium", 0) and len(ticks) == 4, str((res, len(ticks))))
kids = [("xvfb", FakeProc("xvfb", dies_after=0, log=lg)), ("x11vnc", FakeProc("x11vnc", log=lg)), ("chromium", FakeProc("chromium", log=lg))]
res = S.watch(kids, lambda: None, lambda: False)
check("watch: any of the three counts (Xvfb gone)", res == ("xvfb", 0))
kids = [("x11vnc", FakeProc("x11vnc", dies_after=0, log=lg)), ("chromium", FakeProc("chromium", log=lg))]
check("watch: x11vnc gone is noticed", S.watch(kids, lambda: None, lambda: False) == ("x11vnc", 0))
flag = {"n": 0}


def stop_after_two():
    flag["n"] += 1
    return flag["n"] > 2


kids = [("chromium", FakeProc("chromium", log=lg))]
check("watch: a stop request ends the loop with no child named", S.watch(kids, lambda: None, stop_after_two) == (None, None))

lg = []
procs = [("xvfb", FakeProc("xvfb", ignores_term=True, log=lg)), ("x11vnc", FakeProc("x11vnc", ignores_term=True, log=lg)), ("chromium", FakeProc("chromium", log=lg))]
S.stop_children(procs, sleep=lambda s: None, clock=time.monotonic)
check("stop: Chromium gets SIGTERM, x11vnc and Xvfb are killed outright, never terminated",
      ("term", "chromium") in lg and ("term", "x11vnc") not in lg and ("term", "xvfb") not in lg and ("kill", "x11vnc") in lg and ("kill", "xvfb") in lg
      and ("kill", "chromium") not in lg and all(p.rc is not None for _, p in procs), str(lg))
lg = []
stubborn = [("chromium", FakeProc("chromium", ignores_term=True, log=lg))]
clock = iter([0.0, 0.5, 1.0, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6])
S.stop_children(stubborn, sleep=lambda s: None, clock=lambda: next(clock))
check("stop: a Chromium that ignores SIGTERM is killed after the 2 s wait", ("kill", "chromium") in lg, str(lg))

# ---------------------------------------------------------------- configuration
ENV = {"RB_GEOMETRY": "1280x720", "RB_CLIPBOARD": "both", "RB_HOME": "https://duckduckgo.com/", "RB_CHROMIUM": "/usr/bin/chromium",
       "RUNTIME_DIRECTORY": "/run/portal-rb/s-0123456789ab"}
cfg = S.read_config(ENV, exists=lambda p: True)
check("config: values read, geometry clamped", cfg["geometry"] == (1280, 720) and cfg["runtime_dir"] == "/run/portal-rb/s-0123456789ab" and "wm" not in cfg and cfg["clipboard"] == "both")
check("config: RB_WM is not read any more (the window manager is built in)", "RB_WM" not in SRC and "wm" not in S.read_config({**ENV, "RB_WM": "/usr/bin/x"}, exists=lambda p: True))
for label, over in (("geometry", {"RB_GEOMETRY": "big"}), ("clipboard", {"RB_CLIPBOARD": "x"}), ("home flag", {"RB_HOME": "--no-sandbox"}), ("home http", {"RB_HOME": "http://a.example/"}),
                    ("browser path", {"RB_CHROMIUM": "chromium"}), ("runtime dir", {"RUNTIME_DIRECTORY": "run"}), ("two runtime dirs", {"RUNTIME_DIRECTORY": "/a:/b"})):
    check(f"config: bad {label} refused", raises(S.SupervisorError, S.read_config, {**ENV, **over}, exists=lambda p: True))
check("config: a missing runtime directory refused", raises(S.SupervisorError, S.read_config, ENV, exists=lambda p: False))
check("find_binary: first directory wins, nothing found gives None", S.find_binary("x", ("/a", "/b"), exists=lambda p: p == "/b/x") == "/b/x" and S.find_binary("x", ("/a",), exists=lambda p: False) is None)

# main() with a bad environment refuses without starting anything
check("main: a bad environment exits 4 and starts nothing", S.main({"RB_GEOMETRY": "x"}) == 4)


# ---------------------------------------------------------------- the probe's pure helpers (rbrowser_unit/probe.py)
import errno  # noqa: E402
import io  # noqa: E402
import contextlib  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import urllib.parse  # noqa: E402

PSRC = (ROOT / "rbrowser_unit" / "probe.py").read_text()
PR = load("rb_probe_under_test", "rbrowser_unit/probe.py")    # importing it must start nothing
ptree = ast.parse(PSRC)
pimports = set()
for node in ast.walk(ptree):
    if isinstance(node, ast.Import):
        pimports |= {a.name.split(".")[0] for a in node.names}
    elif isinstance(node, ast.ImportFrom) and node.module:
        pimports.add(node.module.split(".")[0])
check("probe.py imports only the standard library", pimports <= set(sys.stdlib_module_names), str(pimports - set(sys.stdlib_module_names)))
check("probe.py runs only under the __main__ guard", 'if __name__ == "__main__":' in PSRC)
check("probe.py names no third-party host and no URL but the two fixed test pages",
      not re.search(r"https?://", PSRC) and set(re.findall(r"(?:file|chrome)://[\w/.]+", PSRC)) == {"file:///etc/hostname", "chrome://sandbox"})
check("probe.py has no shell and no --no-sandbox", "shell=True" not in PSRC and "os.system" not in PSRC and "--no-sandbox" not in PSRC)
check("probe's time limits fit the 40 s budget", PR.TOTAL_S < 40 and PR.CONNECT_S == 2.0 and PR.CHROMIUM_RUN_S + 3 < PR.TOTAL_S + 5)

C = PR.classify_connect
check("connect: a time-out is blocked (IPAddressDeny drops the packet)", C("timeout") == "blocked")
check("connect: EPERM, EACCES and unreachable are blocked", all(C(e) == "blocked" for e in (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH)))
check("connect: success, refused and reset all mean the packet got through", C(0) == "reachable" and C(errno.ECONNREFUSED) == "reachable" and C(errno.ECONNRESET) == "reachable")
check("connect: an error nobody planned for is inconclusive, not a pass", C(errno.EINVAL) == "inconclusive" and C(errno.EMFILE) == "inconclusive")
# the zone of a link-local gateway must reach connect() as sin6_scope_id (a (host, port) tuple loses it: EINVAL)
_ifname, _ifidx = socket.if_nameindex()[0][1], socket.if_nameindex()[0][0]
_fam, _addr = PR._sockaddr(f"fe80::1%{_ifname}", 53)
check("connect: a zoned IPv6 gateway becomes a 4-tuple with the scope id of its interface",
      _fam == socket.AF_INET6 and len(_addr) == 4 and _addr[0] == "fe80::1" and _addr[1] == 53 and _addr[3] == _ifidx and _addr[3] != 0, str(_addr))
check("connect: an IPv6 address without a zone and an IPv4 address keep their plain form",
      PR._sockaddr("2001:db8::1", 53)[1][:2] == ("2001:db8::1", 53) and PR._sockaddr("2001:db8::1", 53)[1][3] == 0
      and PR._sockaddr("192.0.2.1", 53) == (socket.AF_INET, ("192.0.2.1", 53)))
check("connect: _sockaddr resolves numerically only (AI_NUMERICHOST), so a name is refused instead of looked up",
      "socket.AI_NUMERICHOST" in PSRC and raises(OSError, PR._sockaddr, "fe80::1%nosuchif0", 9))
check("connect: a host NAME raises (it is not looked up), a numeric IPv4 address does not",
      raises(socket.gaierror, PR._sockaddr, "localhost", 80) and raises(socket.gaierror, PR._sockaddr, "example.com", 80)
      and not raises(OSError, PR._sockaddr, "192.0.2.7", 80))
_gai = []
_real_gai = PR.socket.getaddrinfo
PR.socket.getaddrinfo = lambda *a, **k: (_gai.append((a, k)), _real_gai(*a, **k))[1]
try:
    PR._sockaddr("192.0.2.7", 80)
finally:
    PR.socket.getaddrinfo = _real_gai
check("connect: the IPv4 path goes through getaddrinfo with AI_NUMERICHOST as well",
      len(_gai) == 1 and _gai[0][0][2] == socket.AF_INET and _gai[0][0][5] & socket.AI_NUMERICHOST, str(_gai))
check("connect: _connect on a host name is inconclusive (never a verdict), not a crash and not a lookup",
      C(PR._connect("localhost", 80, 1)) == "inconclusive" and C(PR._connect("example.com", 80, 1)) == "inconclusive")


class _ConnSock:
    seen = []

    def __init__(self, fam, kind):
        self.fam = fam

    def settimeout(self, t): pass

    def connect(self, addr):
        _ConnSock.seen.append((self.fam, addr))
        raise socket.timeout()

    def close(self): pass


_real_socket = PR.socket.socket
PR.socket.socket = _ConnSock
try:
    _out = PR._connect(f"fe80::1%{_ifname}", 53, 1)
finally:
    PR.socket.socket = _real_socket
check("connect: _connect hands the scoped 4-tuple to connect() and reports the time-out as blocked",
      _out == "timeout" and _ConnSock.seen and _ConnSock.seen[0][1][3] == _ifidx and C(_out) == "blocked", str(_ConnSock.seen))
check("connect: a zone the host does not know is inconclusive, not a crash and not a pass",
      C(PR._connect("fe80::1%nosuchif0", 9, 1)) == "inconclusive")
B = PR.classify_bind
check("bind: EPERM and EACCES are the rule, success is a failure, in-use proves nothing",
      B(errno.EPERM) == "blocked" and B(errno.EACCES) == "blocked" and B(0) == "bound" and B(errno.EADDRINUSE) == "busy" and B(errno.EINVAL) == "inconclusive")

L_ = PR.classify_listen
check("listen: a listener that came up is reported, EPERM and EACCES are a refusal, anything else proves nothing",
      L_(0) == "listening" and L_(errno.EPERM) == "blocked" and L_(errno.EACCES) == "blocked" and L_(errno.EINVAL) == "inconclusive")


class FakeSock:
    """A socket whose bind/listen outcome is scripted: `bind_ok(addr)` and `listen_ok(bound)` -> raise or pass."""
    log = []
    made = []

    def __init__(self, fam, kind, bind_ok, listen_ok):
        self.fam, self.kind, self.bind_ok, self.listen_ok = fam, kind, bind_ok, listen_ok
        FakeSock.made.append(self)
        self.bound = None
        self.closed = False

    def bind(self, addr):
        self.bind_ok(self.kind, addr)
        self.bound = addr
        FakeSock.log.append(("bind", self.fam, self.kind, addr))

    def listen(self, n):
        self.listen_ok(self.bound)
        FakeSock.log.append(("listen", self.fam, self.kind, self.bound))

    def getsockname(self):
        return ("0.0.0.0", 40001)

    def close(self):
        self.closed = True


def deny(code):
    def f(*a):
        raise OSError(code, "scripted")
    return f


def allow(*a):
    return None


def factory(bind_ok, listen_ok):
    return lambda fam, kind: FakeSock(fam, kind, bind_ok, listen_ok)


def fixed_only_rule(kind, addr):
    """The kernel rule as systemd documents it: a bind with a positive port is refused, port 0 is not seen."""
    if addr[1] != 0:
        raise OSError(errno.EPERM, "SocketBindDeny")


# the documented hole: fixed ports refused, port 0 and the unbound listen() go through. They are REPORTED, not judged:
# the control for them is the ingress BPF filter (rbrowser_bpf), proven by the live test (G01b)
FakeSock.log = []
FakeSock.made = []
r1 = PR.check_bind(factory(fixed_only_rule, allow))
check("bind check: a rule that stops fixed ports but not port 0 or the unbound listen() PASSES the check", r1["ok"] is True, r1["detail"])
check("bind check: the detail names both port-0 forms and the port that was reached",
      "tcp4 bind to port 0 and listen listening (port 40001)" in r1["detail"] and "tcp6 listen without bind listening" in r1["detail"], r1["detail"])
check("bind check: the autobound port is in the JSON (listen_ports) for tcp4 and tcp6, both ways",
      r1["listen_ports"] == {"tcp4_bind0": 40001, "tcp4_autobind": 40001, "tcp6_bind0": 40001, "tcp6_autobind": 40001}, str(r1.get("listen_ports")))
check("bind check: the fixed-port part still says blocked for tcp4, udp4, tcp6 and udp6",
      all(f"{x} blocked" in r1["detail"] for x in ("tcp4", "udp4", "tcp6", "udp6")), r1["detail"])
check("bind check: it tried port 0 on both families and listen() with no bind on both",
      sum(1 for e in FakeSock.log if e[0] == "listen" and e[3] is None) == 2
      and sum(1 for e in FakeSock.log if e[0] == "listen" and e[3] is not None and e[3][1] == 0) == 2, str(FakeSock.log[-6:]))
check("bind check: the result is still the {name, ok, detail} shape of a check, detail within 300 characters",
      {"name", "ok", "detail"} <= set(r1) and r1["name"] == "bind" and len(r1["detail"]) <= 300 and not r1["detail"].endswith("..."), str(len(r1["detail"])))

# D1: the check judges nothing, a bind that works is only reported
def fixed_open(kind, addr):
    return None


r1b = PR.check_bind(factory(fixed_open, allow))
check("bind check (report-only): a fixed-port bind that works does NOT fail the check but is reported as bound",
      r1b["ok"] is True and "tcp4 bound" in r1b["detail"] and "udp6 bound" in r1b["detail"] and r1b["detail"].startswith("reported, not judged"), r1b["detail"])

# only the unbound listen() slips through: reported, the check passes
r2 = PR.check_bind(factory(deny(errno.EPERM), allow))
check("bind check: an unbound listen() that works does not fail the check when every bind is refused",
      r2["ok"] is True and "listen without bind listening" in r2["detail"] and "bind to port 0 and listen blocked" in r2["detail"], r2["detail"])
check("bind check: listen_ports has the port for the unbound listen and null where bind-then-listen was refused",
      r2["listen_ports"]["tcp4_autobind"] == 40001 and r2["listen_ports"]["tcp4_bind0"] is None, str(r2["listen_ports"]))

# everything refused (bind hook sees port 0, and the unbound listen is stopped too)
def refuse_listen(bound):
    raise OSError(errno.EPERM, "scripted")


r3 = PR.check_bind(factory(deny(errno.EPERM), refuse_listen))
check("bind check: passes when every attempt, port 0 and unbound listen included, is refused; no port is reported",
      r3["ok"] is True and set(r3["listen_ports"].values()) == {None}, r3["detail"])

# an error nobody planned for on the listen proves nothing but does not decide the check either
r4 = PR.check_bind(factory(deny(errno.EPERM), deny(errno.EINVAL)))
check("bind check: an unplanned error on the listen is reported as inconclusive and does not fail the check",
      r4["ok"] is True and "inconclusive" in r4["detail"], r4["detail"])
def no_ipv6(fam, kind):
    if fam == socket.AF_INET6:
        raise OSError(errno.EAFNOSUPPORT, "no ipv6")
    return FakeSock(fam, kind, deny(errno.EPERM), refuse_listen)


FakeSock.made = []
r5 = PR.check_bind(no_ipv6)
check("bind check: a host without IPv6 gives an answer (not a crash); the tcp6 bind is reported as inconclusive and the check still passes",
      r5["ok"] is True and "tcp6 inconclusive" in r5["detail"] and "tcp6 listen without bind inconclusive" in r5["detail"], r5["detail"])
check("bind check: every socket it opened was closed", all(m.closed for m in FakeSock.made), str(len(FakeSock.made)))
FakeSock.made = []
PR.check_bind(factory(fixed_only_rule, allow))
check("bind check: a udp6 attempt is made (family AF_INET6, datagram)",
      any(m.fam == socket.AF_INET6 and m.kind == socket.SOCK_DGRAM for m in FakeSock.made), str(len(FakeSock.made)))
_bind_src = PSRC[PSRC.index("def check_bind"):PSRC.index("def _try_connect_unix")]
check("bind check: its documentation says it is report-only and the control is the ingress filter",
      "REPORT-ONLY" in _bind_src and "ingress BPF filter" in _bind_src and "SYN-ACK" not in _bind_src and "firewall" not in _bind_src)
check("bind check: no verdict of the check can set ok to False (the source has no `ok = ok and`)", "ok = ok and" not in _bind_src and "ok = False" not in _bind_src)
_sm = PR.summarize([r1])
check("summarize: listen_ports of the bind check are in the JSON and never decide ok",
      _sm["listen_ports"] == r1["listen_ports"] and _sm["ok"] is True and PR.summarize([PR.result("x", True, "")])["listen_ports"] == {})

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    (td / "plain").write_text("x")
    (td / "dir_full").mkdir()
    (td / "dir_full" / "f").write_text("x")
    (td / "dir_empty").mkdir()
    (td / "dir_closed").mkdir()
    (td / "dir_closed").chmod(0)
    (td / "file_closed").write_text("x")
    (td / "file_closed").chmod(0)
    is_root = os.geteuid() == 0
    check("path_blocked: a missing path is blocked", PR.path_blocked(str(td / "nope"))[0] is True)
    check("path_blocked: a readable file and a listable directory are not", PR.path_blocked(str(td / "plain"))[0] is False and PR.path_blocked(str(td / "dir_full"))[0] is False)
    if not is_root:
        check("path_blocked: a mode-000 directory and a mode-000 file are blocked (the shape of an InaccessiblePaths node)",
              PR.path_blocked(str(td / "dir_closed"))[0] is True and PR.path_blocked(str(td / "file_closed"))[0] is True)
    check("path_blocked: an empty mode-000 directory (stat works, nothing inside) is blocked", PR.path_blocked(str(td / "dir_empty"), lstat=lambda p: os.stat_result((0o40000, 0, 0, 1, 0, 0, 0, 0, 0, 0)))[0] is True)
    (td / "dir_closed").chmod(0o700)
    (td / "file_closed").chmod(0o600)

    def denied(_):
        raise PermissionError(errno.EACCES, "no")
    check("path_blocked: EACCES from lstat is blocked", PR.path_blocked("/x", lstat=denied)[0] is True)
    check("path_blocked: some other error is not taken as blocked", PR.path_blocked("/x", lstat=lambda p: (_ for _ in ()).throw(OSError(errno.EIO, "io")))[0] is False)

    # sockets: found on a walk, our own directory skipped, depth limited
    a = td / "walk"
    (a / "d1" / "d2" / "d3" / "d4" / "d5").mkdir(parents=True)
    (a / "own").mkdir()
    socks = []
    for rel in ("top.sock", "d1/one.sock", "d1/d2/d3/four.sock", "d1/d2/d3/d4/d5/deep.sock", "own/mine.sock"):
        sk = socket.socket(socket.AF_UNIX)
        sk.bind(str(a / rel))
        socks.append(sk)
    found = PR._walk_sockets([str(a)], 4, str(a / "own"))
    check("walk: sockets found to the depth limit, the unit's own directory skipped",
          sorted(os.path.relpath(f, a) for f in found) == ["d1/d2/d3/four.sock", "d1/one.sock", "top.sock"], str(sorted(os.path.relpath(f, a) for f in found)))
    found2 = PR._walk_sockets([str(a)], 4, str(a / "own"), [str(a / "d1")])
    check("walk: a skipped directory (the probe's own X socket directory) is not looked at", sorted(os.path.relpath(f, a) for f in found2) == ["top.sock"]
          and PR.OWN_SOCKET_DIRS == ("/tmp/.X11-unix",))
    for sk in socks:
        sk.close()
    # the positive control of the unix check works in a directory of our own and leaves nothing behind
    import concurrent.futures as _cf
    own = td / "runtime"
    own.mkdir()
    real_roots = PR.WALK_ROOTS
    PR.WALK_ROOTS = (str(a),)       # never walk the real /run, /tmp or /var/lib in a test
    try:
        with _cf.ThreadPoolExecutor(4) as pool:
            res, n_abs = PR.check_unix_sockets(pool, str(own), proc_unix=str(td / "no-such-file"))
    finally:
        PR.WALK_ROOTS = real_roots
    check("unix check: the control connects, and a connectable socket on the walk fails the check", res["ok"] is False and "connectable" in res["detail"] and not os.listdir(own), str(res))

check("size_matches: exact and within 1 percent", PR.size_matches(768 << 20, 768 << 20) and PR.size_matches((768 << 20) + 4096, 768 << 20) and not PR.size_matches(1 << 30, 768 << 20) and not PR.size_matches(5, 0))
check("fstype: the longest matching mount point", PR._fstype("1 2 0:5 / /tmp rw - tmpfs t rw\n1 2 0:6 / / rw - ext4 /dev/x rw\n", "/tmp/a") == "tmpfs"
      and PR._fstype("1 2 0:6 / / rw - ext4 /dev/x rw\n", "/tmp/a") == "ext4")
_MI = ("1 2 259:1 / / rw - ext4 /dev/x rw\n"
       "3 1 259:1 /tmp/systemd-private-abc-portal-rb-x.service-QQ/tmp /tmp rw,nosuid - ext4 /dev/x rw\n"
       "4 1 259:1 /var/tmp/systemd-private-abc-portal-rb-x.service-RR/tmp /var/tmp rw - ext4 /dev/x rw\n"
       "5 1 0:51 / /run/work rw - tmpfs tmpfs rw\n")
check("mount root: a private /tmp and /var/tmp are told from the host's (root of the mount holds systemd-private-)",
      "systemd-private-" in PR._mount_root(_MI, "/tmp") and "systemd-private-" in PR._mount_root(_MI, "/var/tmp/x")
      and "systemd-private-" not in PR._mount_root("1 2 259:1 / / rw - ext4 /dev/x rw\n", "/tmp") and PR._mount_root(_MI, "/run/work/home") == "/"
      and PR._fstype(_MI, "/run/work/home") == "tmpfs")
check("userns: link parsed", PR.parse_userns("user:[4026531837]") == 4026531837 and PR.parse_userns("x") is None and PR.parse_userns(None) is None)
check("sandbox children: counted visible, readable, different",
      PR.sandbox_children([(1, "user:[10]"), (2, "user:[11]"), (3, None), (4, "user:[10]")], 10) == (4, 3, 1) and PR.sandbox_children([], 10) == (0, 0, 0))
check("sandbox page: both layers yes, in markup", PR.sandbox_page_ok("<tr><td>Namespace sandbox</td><td>Yes</td></tr><tr><td>Seccomp-BPF sandbox</td><td>Yes</td></tr>") is True
      and PR.sandbox_page_ok("<td>Namespace sandbox</td><td>No</td><td>Seccomp-BPF sandbox</td><td>Yes</td>") is False)
check("sandbox page: a page without the words is not ok", PR.sandbox_page_ok("<html></html>") is False and PR.sandbox_page_ok("") is False)
du = PR.data_url("rbp0123456789ab")
check("data page: the marker is not in the URL text, but the script assembles it",
      "rbp0123456789ab" not in du and "rbp012" in du and urllib.parse.unquote(du).count("rbp012") == 1 and ".join(" in urllib.parse.unquote(du)
      and du.startswith("data:text/html,"))
check("summarize: ok only when every check is ok", PR.summarize([PR.result("a", True, "x"), PR.result("b", True, "y")])["ok"] is True
      and PR.summarize([PR.result("a", True, "x"), PR.result("b", False, "y")])["ok"] is False and PR.summarize([])["ok"] is False)
check("result: detail is bounded", len(PR.result("a", True, "x" * 5000)["detail"]) == 300)
with tempfile.TemporaryDirectory() as td:
    good = Path(td) / "t.json"
    good.write_text(json.dumps({"version": 1, "tcp_denied": []}))
    bad = Path(td) / "b.json"
    bad.write_text(json.dumps({"version": 2}))
    check("targets file: version 1 read, another version or a missing file refused",
          PR.read_targets(str(good))["version"] == 1 and raises(ValueError, PR.read_targets, str(bad)) and raises(OSError, PR.read_targets, str(Path(td) / "none")))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = PR.main({}, str(Path(td) / "none"))
    one = json.loads(buf.getvalue())
    check("main: a missing targets file gives one JSON line, a failed check named setup and exit 1",
          code == 1 and buf.getvalue().count("\n") == 1 and one["ok"] is False and one["checks"][0]["name"] == "setup" and set(one) == {"ok", "checks", "abstract_connectable", "listen_ports"} and one["listen_ports"] == {})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        PR.main({}, str(good))
    one = json.loads(buf.getvalue())
    check("main: no RUNTIME_DIRECTORY or RB_CHROMIUM fails closed without starting anything", one["ok"] is False and one["checks"][0]["name"] == "setup")
check("probe: the eight checks of 8.2 are all wired", set(re.findall(r'^        "(\w+)": ', PSRC, re.M)) ==
      {"egress", "bind", "unix_sockets", "hidden_paths", "mounts", "display_proof", "chromium_policy", "sandbox_state"})
kid = subprocess.Popen(["/bin/sleep", "5"])
try:
    time.sleep(0.2)
    check("probe: the descendants of a process are found from /proc", kid.pid in PR._descendants(os.getpid()))
finally:
    kid.kill()
    kid.wait()
check("probe: abstract names from /proc/net/unix", PR._abstract_names(PROC_NET_UNIX) == ["@/tmp/.X11-unix/X1", "@/tmp/.X11-unix/X10"])
hs = PR.load_session()
check("probe: loads the supervisor by path for the display proof (same module code)", hs.xauth_entry is not None and hasattr(hs, "prove_display") and hasattr(hs, "start_xvfb"))

# ---- the probe's headless runs: a failed load is told by its error code, nothing else of stderr is kept
import tempfile as _tf  # noqa: E402
with _tf.TemporaryDirectory() as _d:
    _fake = Path(_d) / "fakechromium"
    _fake.write_text("#!/bin/sh\ncase \"$*\" in\n"
                     "  *blocked*) echo '[1:1:0101/000000.000000:ERROR:components/headless/command_handler/headless_command_handler.cc:403] Page load failed: net::ERR_BLOCKED_BY_ADMINISTRATOR' >&2; echo 'https://secret.example/path in a log line' >&2; exit 0;;\n"
                     "  *hangonce*) if [ ! -e \"$0.state\" ]; then : > \"$0.state\"; sleep 30; fi; echo '<html>rbp-ok</html>'; exit 0;;\n"
                     "  *hangalways*) sleep 30;;\n"
                     "  *lingering*) sleep 20 & echo '<html>rbp-ok</html>'; exit 0;;\n"
                     "  *ok*) echo '<html>rbp-ok</html>'; echo 'https://secret.example/other' >&2; exit 0;;\n"
                     "  *) exit 7;;\nesac\n")
    _fake.chmod(0o755)
    _S = load("rb_sess_for_probe", "rbrowser_unit/session.py")
    _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:blocked")
    check("dump_dom: a failed load gives its error code (and the policy marker is found), the log line with a URL is not kept",
          _rc == 0 and PR.BLOCK_MARKER in _out and "secret" not in _out and "[load failed: net::ERR_BLOCKED_BY_ADMINISTRATOR]" in _out, repr(_out))
    _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:ok")
    check("dump_dom: a page that loads gives its DOM and no marker, stderr is dropped", _rc == 0 and "rbp-ok" in _out and "load failed" not in _out and "secret" not in _out, repr(_out))
    _real_run_s = PR.CHROMIUM_RUN_S
    PR.CHROMIUM_RUN_S = 1.0
    try:
        _t0 = time.time()
        _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:hangonce")
        check("dump_dom: a run that hits the time limit is repeated once and the second run's answer counts", _rc == 0 and "rbp-ok" in _out and 1.0 <= time.time() - _t0 < 6, f"{_rc} {_out!r} {time.time() - _t0:.1f}s")
        _t0 = time.time()
        _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:hangalways")
        check("dump_dom: two runs that both hit the limit give 124, after two limits and no more", _rc == 124 and 2.0 <= time.time() - _t0 < 8 and PR.CHROMIUM_ATTEMPTS == 2, f"{_rc} {time.time() - _t0:.1f}s")
    finally:
        PR.CHROMIUM_RUN_S = _real_run_s
    check("probe time budget: two attempts at the limit plus the sandbox poll fit in the probe's total time", 2 * PR.CHROMIUM_RUN_S + PR.SANDBOX_POLL_S < PR.TOTAL_S)
    _t0 = time.time()
    _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:lingering")
    check("dump_dom: a helper process that outlives the browser and keeps the pipes open does not make the run wait for it",
          _rc == 0 and "rbp-ok" in _out and time.time() - _t0 < 5, f"{_rc} {_out!r} {time.time() - _t0:.1f}s")
    _rc, _out = PR._dump_dom(_S, str(_fake), "t", "data:other")
    check("dump_dom: the exit status is passed on", _rc == 7)
_hf = PR._headless_flags(_S, "t")
check("headless flags: the log goes to stderr (the error code is read from it), --disable-logging is dropped, no debugging pipe, own profile under the work area",
      "--enable-logging=stderr" in _hf and "--disable-logging" not in _hf and "--headless=new" in _hf and not any(f.startswith("--remote-debugging") for f in _hf)
      and f"--user-data-dir={_S.WORK_DIR}/probe-t" in _hf and "--no-proxy-server" in _hf)

# ---------------------------------------------------------------- 1.26.0: the member's portal theme (RB_THEME_MODE)
_plain = S.chromium_argv("/usr/bin/chromium", 1280, 720, "https://duckduckgo.com/")
check("theme: no mode, None, light or anything else leaves the Chromium arguments exactly as before",
      all(S.chromium_argv("/usr/bin/chromium", 1280, 720, "https://duckduckgo.com/", m) == _plain for m in (None, "light", "", "auto", "DARK", "dark ", "--no-sandbox", 1, ["dark"])))
_dark = S.chromium_argv("/usr/bin/chromium", 1280, 720, "https://duckduckgo.com/", "dark")
check("theme: dark adds exactly --force-dark-mode, before the window size and the home page (the page stays last)",
      [a for a in _dark if a not in _plain] == ["--force-dark-mode"] and len(_dark) == len(_plain) + 1 and _dark[-1] == "https://duckduckgo.com/"
      and _dark.index("--force-dark-mode") < _dark.index("--window-size=1280,720"))
check("theme: the switch is a constant of this file; no recolouring switch or feature of page content is anywhere in the source",
      S.THEME_DARK_FLAG == "--force-dark-mode" and "WebContentsForceDark" not in SRC and "enable-features" not in SRC.replace("disable-features", "") and "force-dark-mode" in SRC)
check("theme: the two modes are the only valid ones", S.THEME_MODES == ("dark", "light") and S.valid_theme_mode("dark") == "dark" and S.valid_theme_mode("light") == "light"
      and all(S.valid_theme_mode(m) is None for m in (None, "", "Dark", "x", "dark\n", 0, ["dark"], "dark;--no-sandbox")))
check("theme: config reads RB_THEME_MODE; absent or invalid is None and never an error",
      S.read_config(ENV, exists=lambda p: True)["theme_mode"] is None
      and S.read_config({**ENV, "RB_THEME_MODE": "dark"}, exists=lambda p: True)["theme_mode"] == "dark"
      and S.read_config({**ENV, "RB_THEME_MODE": "light"}, exists=lambda p: True)["theme_mode"] == "light"
      and all(S.read_config({**ENV, "RB_THEME_MODE": m}, exists=lambda p: True)["theme_mode"] is None for m in ("", "evil", "DARK", "dark\n", "--no-sandbox", "dark light")))
check("theme: the mode read from the environment is what reaches chromium_argv in main()", 'chromium_argv(cfg["chromium"], w, h, cfg["home"], cfg.get("theme_mode"))' in SRC)
check("theme: the colour never reaches the supervisor (no RB_THEME_COLOR anywhere in it)", "RB_THEME_COLOR" not in SRC and "BrowserThemeColor" not in SRC)

# ---- 1.26.1: the keyboard map is prepared before x11vnc and Chromium start (x11vnc adds a keysym on a key without symbols
# and gives it back only when it exits: 18 keys on this host's Xvfb, so the 19th different character was dropped)
XF = 0x1008FF11          # XF86AudioLowerVolume
XF_BACK = 0x1008FF26     # XF86Back
KM_W = 4


def km_rows(n, free=(), xf=(), nav=(), base=0x61):
    """n keys from keycode 8: ordinary letters, except the given positions (free, only XF86 symbols, a browser key)."""
    rows = []
    for i in range(n):
        if i in free:
            rows.append((0,) * KM_W)
        elif i in xf:
            rows.append((XF, 0, XF, 0))
        elif i in nav:
            rows.append((XF_BACK, 0, XF_BACK, 0))
        else:
            rows.append((base + i, 0x41 + i, base + i, 0x41 + i))
    return rows


KU = S.keymap_units()
KPAIRS = [u for u in KU if len(u) == 2]
KS = S.keymap_keysym


def novnc_lookup_table():
    """noVNC's keysymdef.js read as text: the table of code point -> keysym, and lookup() as it is written there."""
    js = (ROOT / "static" / "vendor" / "novnc" / "core" / "input" / "keysymdef.js").read_text(encoding="utf-8")
    table = {int(a, 16): int(b, 16) for a, b in re.findall(r"^\s*(0x[0-9a-fA-F]+):\s*(0x[0-9a-fA-F]+),", js, re.M)}
    body = js[js.index("lookup(u) {"):]
    shape_ok = ("(u >= 0x20) && (u <= 0xff)" in body and "return u;" in body and "codepoints[u]" in body and "0x01000000 | u" in body)
    return table, shape_ok


NOVNC, NOVNC_SHAPE = novnc_lookup_table()


def novnc_keysym(cp):
    return cp if 0x20 <= cp <= 0xFF else NOVNC.get(cp, 0x01000000 | cp)


check("keymap: the keysymdef.js of the vendored noVNC has the shape this test reads (a table, Latin-1 as itself, 0x01000000 | u at the end)", len(NOVNC) > 500 and NOVNC_SHAPE)
CPS = [cp for u in S.keymap_codepoint_units() for cp in u]
check("keymap: every keysym of the table is exactly what noVNC's keysymdef.js lookup gives for its code point (an updated noVNC cannot drift unseen)",
      all(KS(cp) == novnc_keysym(cp) for cp in CPS) and all(S.KEYMAP_KEYSYMS[cp] == novnc_keysym(cp) for cp in S.KEYMAP_KEYSYMS)
      and sorted(S.KEYMAP_KEYSYMS) == sorted({cp for cp in CPS if cp > 0xFF}), [hex(cp) for cp in CPS if KS(cp) != novnc_keysym(cp)][:5])
check("keymap: fixed pairs, legacy keysyms where X11 has one: Cyrillic a 0x06c1, Polish a-ogonek 0x01b1, euro 0x20ac, en dash 0x0aaa, e-acute 0xe9; none is the Unicode form",
      KS(0x430) == 0x6C1 and KS(0x105) == 0x1B1 and KS(0x20AC) == 0x20AC and KS(0x2013) == 0xAAA and KS(0xE9) == 0xE9
      and not any(KS(cp) == 0x01000000 + cp for cp in (0x430, 0x105, 0x20AC, 0x2013)))
check("keymap: units hold Latin-1 letters, sharp s, euro, Russian with yo, Ukrainian, Polish (as noVNC sends them)",
      all(any(KS(cp) in u for u in KU) for cp in (0xE9, 0xDF, 0xFF, 0x20AC, 0x451, 0x456, 0x491, 0x105, 0x17C, 0xB0, 0xBF)))
check("keymap: every unit has one or two different keysyms, none is ASCII, none twice",
      all(len(u) in (1, 2) and len(set(u)) == len(u) and all(k > 0x9F for k in u) for u in KU)
      and len({k for u in KU for k in u}) == sum(len(u) for u in KU))
check("keymap: a letter pair is lower case first (the key types it plain and with Shift gives the capital)",
      all(u[0] != u[1] for u in KPAIRS) and (0xE0, 0xC0) in KPAIRS and (KS(0xFF), KS(0x178)) in KPAIRS and (KS(0x430), KS(0x410)) in KPAIRS)
check("keymap: the micro sign is not paired with a Greek capital", not any(0xB5 in u and len(u) == 2 for u in KU))
check("keymap: the units fit the keys of this host's map (about 90 keys) and Russian is complete",
      len(KPAIRS) + (len(KU) - len(KPAIRS) + 1) // 2 <= 91
      and all((KS(c), KS(c - 0x20)) in KU for c in range(0x430, 0x450)))

PLAN_ROWS = km_rows(60, free=(0, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19), xf=tuple(range(20, 40)), nav=(40,))
PLAN = S.plan_keymap(PLAN_ROWS, 8)
KFREE = [8 + i for i, r in enumerate(PLAN_ROWS) if not any(r)]
KSPARE = [8 + i for i in range(20, 40)]
check("keymap plan: only keys with no symbols or with nothing but XF86 symbols are written, never the first key, never a browser key",
      PLAN and all(kc in KFREE[1:] + KSPARE for kc in PLAN) and 8 not in PLAN and 48 not in PLAN and 8 + 40 not in PLAN)
_after = {8 + i: r for i, r in enumerate(PLAN_ROWS)}
_after.update(PLAN)
_empty_after = [kc for kc, r in _after.items() if kc != 8 and not any(r)]
check("keymap plan: after the plan exactly the reserve of keys is empty (apart from the first key), emptying unused media keys if the free ones are too few",
      len(_empty_after) == S.KEYMAP_RESERVE, f"{len(_empty_after)} empty")
check("keymap plan: a key holds a pair as lower, capital, lower, capital (one key types both with and without Shift), as wide as the map",
      all(len(row) == KM_W and row[0] == row[2] and row[1] == row[3] for row in PLAN.values()))
_flat = [k for row in PLAN.values() for k in row[:2] if k]
check("keymap plan: no keysym is written twice", len(_flat) == len(set(_flat)))
rows2 = km_rows(60, free=tuple(range(1, 40)))
rows2[10] = (0xE9, 0xC9, 0xE9, 0xC9)
plan2 = S.plan_keymap(rows2, 8)
check("keymap plan: a unit whose keysym the map holds already is skipped", all(0xE9 not in r and 0xC9 not in r for r in plan2.values()) and plan2)
check("keymap plan: with a reserve as large as the keys no keysym is written (only emptied media keys); no rows is nothing",
      not any(any(r) for r in S.plan_keymap(PLAN_ROWS, 8, reserve=500).values()) and S.plan_keymap([], 8) == {})
check("keymap plan: a map with no free key and no media key is left alone", S.plan_keymap(km_rows(40), 8) == {})
check("keymap plan: the same map gives the same plan (no clock, no randomness)", S.plan_keymap(PLAN_ROWS, 8) == PLAN)


class KmFunc:
    def __init__(self, fn):
        self.fn, self.argtypes, self.restype = fn, None, None

    def __call__(self, *a):
        return self.fn(*a)


class KmLib:
    """Just enough libX11 for ModeHolder.prefill_keymap: a map in memory, the writes recorded."""

    def __init__(self, rows, lo=8, fail=False):
        self.rows, self.lo, self.written, self.fail, self.errors_after = rows, lo, [], fail, 0
        w = len(rows[0])
        self.XDisplayKeycodes = KmFunc(self._codes)
        self.XGetKeyboardMapping = KmFunc(lambda d, first, n, wref: (setattr(wref._obj, "value", w), (ctypes.c_ulong * (w * n))(*[k for r in self.rows[:n] for k in r]))[1])
        self.XChangeKeyboardMapping = KmFunc(lambda d, kc, w_, arr, n: self.written.append((kc, tuple(arr[:w_]))))
        self.XFree = KmFunc(lambda p: 0)
        self.XSync = KmFunc(lambda d, f: 0)
        self.XNextRequest = KmFunc(lambda d: 5)

    def _codes(self, d, lo, hi):
        lo._obj.value, hi._obj.value = self.lo, self.lo + len(self.rows) - 1


import ctypes
h = object.__new__(S.ModeHolder)
h.x11, h.dpy, h.recent, h.errors = KmLib(PLAN_ROWS), 1, __import__("collections").deque(maxlen=64), 0
n = h.prefill_keymap()
check("keymap: prefill_keymap reads the map, writes one key per planned key and returns how many", n == len(PLAN) and dict(h.x11.written) == PLAN, f"{n} {len(h.x11.written)}")
h = object.__new__(S.ModeHolder)
h.x11, h.dpy, h.recent, h.errors = KmLib(PLAN_ROWS), 1, __import__("collections").deque([(6, 8)], maxlen=64), 1
check("keymap: an X error during the writes means 0 and one neutral log line (the session goes on without)", h.prefill_keymap() == 0)
h = object.__new__(S.ModeHolder)
h.x11, h.dpy, h.recent, h.errors = KmLib(km_rows(40)), 1, __import__("collections").deque(maxlen=64), 0
check("keymap: nothing to write means no write at all", h.prefill_keymap() == 0 and h.x11.written == [])
_run = SRC[SRC.index("def run(cfg):"):]
check("keymap: run() prepares the map after the size and before x11vnc starts, and a failure there is not fatal",
      _run.index("holder.prefill_keymap()") > _run.index("xr.set_size") and _run.index("holder.prefill_keymap()") < _run.index("spawn(x11vnc_argv(")
      and _run[_run.index("try:\n            holder.prefill_keymap()"):].split("# 4.")[0].count("except Exception") == 1)
check("keymap: x11vnc's argument list did not change for it (the supervisor tests above pin the clipboard flags): no -add_keysyms/-remap/-xkb/-clear_keys flag",
      not any(f in S.x11vnc_argv("x", 1, "a", "s") for f in ("-add_keysyms", "-noadd_keysyms", "-remap", "-xkb", "-noxkb", "-clear_keys", "-clear_all", "-skip_keycodes", "-modtweak", "-nomodtweak")))

if failures:
    print(f"\n{len(failures)} check(s) failed:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("\ntest_rbrowser_supervisor: all checks passed")
