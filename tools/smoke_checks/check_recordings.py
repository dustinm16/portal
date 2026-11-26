"""Terminal recordings: private files that grow during the session, valid asciicast v2,
input never recorded, and age-based removal of file and row by a manual cleanup run.

A service with the terminal plugin and recording switched on is created in-process
(ctx.run_py); the session itself goes through the real /ws/terminal/<id> WebSocket.
The cleanup rows are planted in-process too, including rows whose filename points
outside the recordings directory.
"""
import asyncio
import json
import os
import stat
from pathlib import Path

PW = "recordings-admin-pass-1234"
SECRET_WORD = "typedsecret4711"
MARK = "smokemark8842"

SETUP = '''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    u = await create_user("rec_admin", %r, is_admin=True)
    await db.set_user_role(u["id"], "superadmin")
    sid = await db.create_service(name="rec shell", path="/rec-shell", plugin="terminal",
                                  config={"recording": True, "shell": "/bin/bash"})
    await db.close()
    print("RESULT " + json.dumps({"user": u["id"], "service": sid}))

asyncio.run(main())
''' % PW

PLANT = '''
import asyncio, json, os
from pathlib import Path
from config import Config
from database import db

async def add(name, age):
    cur = await db.conn.execute(
        "INSERT INTO recordings (user_id, service_id, filename, created_at) "
        "VALUES (?, ?, ?, datetime('now', ?))", (%(user)d, %(service)d, name, "-%%d days" %% age))
    await db.conn.commit()
    return cur.lastrowid

async def main():
    await db.connect()
    d = Path(Config.RECORDINGS_DIR)
    d.mkdir(mode=0o700, exist_ok=True)
    stage = d.parent
    out = {"dir": str(d), "outside": str(stage / "smoke_outside.cast")}
    (stage / "smoke_outside.cast").write_text("must survive")
    (d / "smoke_old.cast").write_text("old")
    (d / "smoke_new.cast").write_text("new")
    os.symlink(stage / "smoke_outside.cast", d / "smoke_link.cast")
    # files no row refers to: one old, one fresh, a symlink to a file outside
    import time
    (d / "smoke_orphan_old.cast").write_text("orphan")
    (d / "smoke_orphan_fresh.cast").write_text("orphan")
    os.symlink(stage / "smoke_outside.cast", d / "smoke_orphan_link.cast")
    old = time.time() - 7200
    os.utime(d / "smoke_orphan_old.cast", (old, old))
    os.utime(d / "smoke_orphan_link.cast", (old, old), follow_symlinks=False)
    out["old"] = await add("smoke_old.cast", 45)
    out["new"] = await add("smoke_new.cast", 3)
    out["link"] = await add("smoke_link.cast", 45)
    out["dotdot"] = await add("../smoke_outside.cast", 45)
    out["abs"] = await add(str(stage / "smoke_outside.cast"), 45)
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

STATE = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    cur = await db.conn.execute("SELECT id FROM recordings")
    ids = [r["id"] for r in await cur.fetchall()]
    await db.close()
    print("RESULT " + json.dumps(ids))

asyncio.run(main())
'''


TIGHTEN = '''
import json, os, stat
from pathlib import Path
from config import Config
from plugins.terminal import tighten_recording_files

d = Path(Config.RECORDINGS_DIR)
d.mkdir(mode=0o700, exist_ok=True)
stage = d.parent
(d / "smoke_legacy.cast").write_text("old")
os.chmod(d / "smoke_legacy.cast", 0o644)
(stage / "smoke_tighten_target").write_text("x")
os.chmod(stage / "smoke_tighten_target", 0o644)
os.symlink(stage / "smoke_tighten_target", d / "smoke_tighten_link.cast")
n = tighten_recording_files(str(d))
m = lambda p: stat.S_IMODE(os.stat(p).st_mode)
print("RESULT " + json.dumps({"changed": n, "legacy": m(d / "smoke_legacy.cast"),
                              "target": m(stage / "smoke_tighten_target")}))
os.unlink(d / "smoke_tighten_link.cast")
os.unlink(d / "smoke_legacy.cast")
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


BACKDATE = '''
import asyncio
from database import db

async def main():
    await db.connect()
    await db.conn.execute("UPDATE recordings SET created_at = datetime('now', ?) WHERE filename = ?", (%r, %r))
    await db.conn.commit()
    await db.close()

asyncio.run(main())
'''


async def _session(ctx, sess, service_id, rec_dir, while_open=None):
    """Run a terminal session; returns (sizes seen while open, file path or None).

    while_open(path), when given, is awaited once with the session still open."""
    sizes = []
    path = None
    url = ctx.base_url.replace("https", "wss") + f"/ws/terminal/{service_id}"
    async with sess.ws_connect(url, ssl=False) as ws:
        connected = False
        async with asyncio.timeout(15):
            while not connected:
                m = await ws.receive()
                if m.type == 1 and m.data.startswith("{"):
                    connected = json.loads(m.data).get("type") == "connected"
                elif m.type != 1:
                    return sizes, None

        def files():
            return sorted(Path(rec_dir).glob("rec_*.cast")) if Path(rec_dir).is_dir() else []

        for _ in range(50):
            if files():
                break
            await asyncio.sleep(0.1)
        found = files()
        path = found[-1] if found else None
        if path is None:
            return sizes, None
        sizes.append(path.stat().st_size)
        if while_open is not None:
            await while_open(path)
        for n in range(3):
            # the typed text is echoed back by the terminal, so a recorder that
            # also kept input would show it as an "i" event
            await ws.send_json({"type": "input", "data": f"echo {MARK}{n}; : {SECRET_WORD}\n"})
            for _ in range(50):
                await asyncio.sleep(0.1)
                if path.stat().st_size > sizes[-1]:
                    break
            sizes.append(path.stat().st_size)
    return sizes, path


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    ids = _result(out)
    ctx.ok("recordings: test user and recording-enabled terminal service created",
           rc == 0 and bool(ids), out[-300:])
    if not ids:
        return

    startup_dir = Path(ctx.stage_dir) / "recordings"
    ctx.ok("recordings: the directory exists with mode 0700 from startup, before any session",
           startup_dir.is_dir() and _mode(startup_dir) == 0o700,
           oct(_mode(startup_dir)) if startup_dir.is_dir() else "missing")

    rc, out = await ctx.run_py(TIGHTEN)
    t = _result(out) or {}
    ctx.ok("recordings: the startup tightening makes an older 0644 file 0600 and leaves a symlink target alone",
           rc == 0 and t.get("legacy") == 0o600 and t.get("target") == 0o644 and t.get("changed", 0) >= 1, out[-300:])

    async with ctx.http() as sess:
        resp = await ctx.login(sess, "rec_admin", PW)
        if resp.status != 200:
            ctx.ok("recordings: test user can log in", False, f"status {resp.status}")
            return

        rec_dir = Path(ctx.stage_dir) / "recordings"
        live = {}

        async def while_open(p):
            # The session is older than the retention window yet still running: a
            # cleanup run must leave its file and row alone.
            await ctx.run_py(BACKDATE % ("-40 days", p.name))
            r = await sess.post(ctx.base_url + "/api/admin/retention/run")
            live["status"] = r.status
            live["body"] = await r.json()
            rc, out = await ctx.run_py(STATE)
            live["rows"] = _result(out) or []
            live["exists"] = p.exists()

        sizes, path = await _session(ctx, sess, ids["service"], rec_dir, while_open)
        ctx.ok("recordings: cleanup leaves the recording of a running session alone",
               live.get("status") == 200 and live.get("exists") is True and len(live.get("rows", [])) == 1
               and live.get("body", {}).get("deleted", {}).get("recordings") == 0, str(live)[:300])
        if path is not None:
            await ctx.run_py(BACKDATE % ("0 days", path.name))
        ctx.ok("recordings: a terminal session creates a recording file", path is not None)
        if path is None:
            return
        ctx.ok("recordings: the file grows while the session is open",
               len(sizes) >= 3 and sizes[-1] > sizes[0] and sizes == sorted(sizes), f"sizes {sizes}")
        ctx.ok("recordings: file mode is 0600", _mode(path) == 0o600, oct(_mode(path)))
        ctx.ok("recordings: directory mode is 0700", _mode(rec_dir) == 0o700, oct(_mode(rec_dir)))

        # Closed session: wait for the finish step to store the final size.
        row = None
        for _ in range(50):
            rc, out = await ctx.run_py(
                "import asyncio, json\nfrom database import db\n"
                "async def m():\n await db.connect()\n"
                " cur = await db.conn.execute('SELECT filename, size, duration FROM recordings WHERE filename = ?', (%r,))\n"
                " r = await cur.fetchone()\n await db.close()\n"
                " print('RESULT ' + json.dumps(dict(r) if r else None))\nasyncio.run(m())\n" % path.name)
            row = _result(out)
            if row and row["size"] == path.stat().st_size and row["duration"] > 0:
                break
            await asyncio.sleep(0.2)
        ctx.ok("recordings: the row holds the final size and duration",
               bool(row) and row["size"] == path.stat().st_size and row["duration"] > 0, str(row))

        try:
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            events = [json.loads(x) for x in lines[1:]]
            valid = (header.get("version") == 2 and isinstance(header.get("width"), int)
                     and isinstance(header.get("height"), int) and len(events) > 0
                     and all(isinstance(e, list) and len(e) == 3 and isinstance(e[0], (int, float))
                             and e[1] in ("o", "i", "m", "r") and isinstance(e[2], str) for e in events)
                     and [e[0] for e in events] == sorted(e[0] for e in events))
            detail = f"{len(events)} events"
        except (ValueError, IndexError, OSError) as e:
            valid, events, detail = False, [], str(e)
        ctx.ok("recordings: the file is valid asciicast v2", valid, detail)
        ctx.ok("recordings: output is recorded", any(MARK in e[2] for e in events if e[1] == "o"))
        ctx.ok("recordings: input is never recorded as an event", all(e[1] == "o" for e in events))

        # Retention: planted rows, one manual cleanup run.
        rc, out = await ctx.run_py(PLANT % ids)
        planted = _result(out)
        ctx.ok("recordings: cleanup rows planted", rc == 0 and bool(planted), out[-300:])
        if not planted:
            return
        resp = await sess.put(ctx.base_url + "/api/admin/retention", json={"retention_recordings_days": 30})
        body = await resp.json()
        ctx.ok("recordings: retention_recordings_days is a retention setting",
               resp.status == 200 and body.get("config", {}).get("retention_recordings_days") == "30",
               f"status {resp.status}")
        resp = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await resp.json()
        ctx.ok("recordings: manual cleanup run reports removed recordings",
               resp.status == 200 and body.get("deleted", {}).get("recordings") == 2, str(body)[:300])

        d = Path(planted["dir"])
        rc, out = await ctx.run_py(STATE)
        left = set(_result(out) or [])
        ctx.ok("recordings: an old recording's file and row are removed",
               not (d / "smoke_old.cast").exists() and planted["old"] not in left)
        ctx.ok("recordings: a recent recording is kept, file and row",
               (d / "smoke_new.cast").exists() and planted["new"] in left)
        ctx.ok("recordings: the symlink in the directory is removed, its target is not",
               not os.path.lexists(d / "smoke_link.cast") and Path(planted["outside"]).read_text() == "must survive"
               and planted["link"] not in left)
        ctx.ok("recordings: the manual run also sweeps one old orphan file (no row, no live session)",
               body.get("deleted", {}).get("recording_orphans") == 1 and not (d / "smoke_orphan_old.cast").exists(),
               str(body.get("deleted"))[:200])
        ctx.ok("recordings: a fresh orphan, an orphan symlink and its target, and referenced files are kept",
               (d / "smoke_orphan_fresh.cast").exists() and os.path.islink(d / "smoke_orphan_link.cast")
               and Path(planted["outside"]).read_text() == "must survive"
               and (d / "smoke_new.cast").exists() and path.exists())
        ctx.ok("recordings: crafted filenames outside the directory are ignored",
               Path(planted["outside"]).exists() and planted["dotdot"] in left and planted["abs"] in left)

        # The size cap, through a real session: produce more output than the cap.
        cap = 50 * 1024 * 1024
        url = ctx.base_url.replace("https", "wss") + f"/ws/terminal/{ids['service']}"
        before = {p.name for p in rec_dir.glob("rec_*.cast")}
        big = None
        try:
            async with sess.ws_connect(url, ssl=False, max_msg_size=0) as ws:
                async with asyncio.timeout(120):
                    while True:
                        m = await ws.receive()
                        if m.type == 1 and m.data.startswith("{") and json.loads(m.data).get("type") == "connected":
                            break
                    await ws.send_json({"type": "input",
                                        "data": "head -c 60000000 /dev/zero | tr '\\0' 'a'; echo capdone$((40+2))\n"})
                    seen = b""
                    while b"capdone42" not in seen[-64:]:
                        m = await ws.receive()
                        if m.type == 1:
                            seen = (seen + m.data.encode())[-256:]
                        elif m.type == 2:
                            seen = (seen + m.data)[-256:]
                        else:
                            break
        except (asyncio.TimeoutError, TimeoutError) as e:
            ctx.ok("recordings: the capped session finished", False, f"timeout {e!r}")
        found = [p for p in rec_dir.glob("rec_*.cast") if p.name not in before]
        big = found[-1] if found else None
        if big is None:
            ctx.ok("recordings: a session that outputs more than the cap still records", False, "no file")
            return
        # The recorder may still be writing when the session output ends: read the size and the tail until the
        # truncation marker is the last line or the size has not changed over 0.3 s (limit 15 s), not after a fixed wait.
        def read_state():
            size = big.stat().st_size
            with open(big, "rb") as f:
                f.seek(max(0, size - 400))
                tail = f.read().splitlines()
            try:
                last = json.loads(tail[-1])
                marker = last[1] == "m" and "truncated" in last[2]
            except (ValueError, IndexError):
                marker = False
            return size, tail, marker
        size, tail, marker_ok = read_state()
        deadline = asyncio.get_running_loop().time() + 15
        while not marker_ok and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.3)
            again = read_state()
            stable = again[0] == size
            size, tail, marker_ok = again
            if stable:
                break
        ctx.ok("recordings: the file stops at the 50 MB cap", cap - 65536 < size <= cap, f"size {size}")
        ctx.ok("recordings: a capped file ends with a truncation marker event", marker_ok, str(tail[-1:])[:200])
