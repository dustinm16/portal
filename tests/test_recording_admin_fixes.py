"""Recordings, fix pass A: who may switch recording on, the disk budget, interrupted rows and
the truth of the delete audit trail.

Run: venv/bin/python tests/test_recording_admin_fixes.py

The real app runs on a loopback test server against a temporary database and a temporary
recordings folder. Nothing outside the temporary tree is touched and nothing is dialled.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import recording_paths  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
import session_recording  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402
from database import decrypt_config, encrypt_config  # noqa: E402

recording_paths.vod_staging.TEMP_ROOTS = ()

failures = []
PW = "Recording-fix-pass-12345!"


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def login(base, name):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with s.post(base + "/login", json={"username": name, "password": PW}) as r:
        assert r.status == 200, (name, r.status)
    return s


async def audit(db, action):
    cur = await db.conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,))
    return [dict(r) for r in await cur.fetchall()]


async def add_row(db, rec_dir, user_id, name="box", body=None, **cols):
    """A finished recording: a file in the folder and its row."""
    fname = f"rec_{user_id}_c1_{name}.cast"
    Path(rec_dir).mkdir(parents=True, exist_ok=True)
    if body is None:
        body = json.dumps({"version": 2, "width": 80, "height": 24}) + "\n" + json.dumps([0.5, "o", "hi"]) + "\n"
    (Path(rec_dir) / fname).write_text(body)
    os.chmod(Path(rec_dir) / fname, 0o600)
    cur = await db.conn.execute(
        "INSERT INTO recordings (user_id, service_id, filename, connection_name, kind, size, duration) "
        "VALUES (?, NULL, ?, ?, 'ssh', ?, ?)",
        (user_id, fname, name, cols.get("size", len(body)), cols.get("duration", 1.0)))
    await db.conn.commit()
    return cur.lastrowid, fname


async def main():
    tmp = tempfile.mkdtemp()
    rec_dir = str(Path(tmp) / "recordings")
    Config.RECORDINGS_DIR = rec_dir
    recording_paths.reset()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
    session_recording.db = db

    names = ("bob", "adm", "mod")
    for name in names:
        await create_user(name, PW, is_admin=(name == "adm"))
    uid = {n: (await db.get_user_by_username(n))["id"] for n in names}
    await db.set_user_role(uid["adm"], "admin")
    await db.set_user_role(uid["mod"], "moderator")
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()
    sess = {n: await login(base, n) for n in names}

    # ---- item 6: the delete audit trail tells the truth -----------------------------------------
    rid, fname = await add_row(db, rec_dir, uid["bob"], "del-fails")
    real_remove = session_recording.remove_recording_file

    def failing_remove(*a, **k):
        raise PermissionError(13, "Permission denied")
    session_recording.remove_recording_file = failing_remove
    async with sess["adm"].delete(f"{base}/api/recordings/{rid}") as r:
        check("a delete whose unlink fails answers 500", r.status == 500, str(r.status))
    session_recording.remove_recording_file = real_remove
    check("the failed delete left the file and the row", (Path(rec_dir) / fname).exists()
          and await db.get_recording(rid) is not None)
    intent = await audit(db, "recording_delete")
    failed = await audit(db, "recording_delete_failed")
    check("the request was audited first, as a request that does not claim success",
          len(intent) == 1 and intent[0]["target_id"] == rid, str(intent))
    check("a second entry records that the delete failed, with the reason",
          len(failed) == 1 and failed[0]["target_id"] == rid and failed[0]["id"] > intent[0]["id"], str(failed))
    from database import decrypt_message  # noqa: E402
    d_intent = json.loads(decrypt_message(intent[0]["details"]))
    d_failed = json.loads(decrypt_message(failed[0]["details"]))
    check("the first entry says requested, the second names the failure",
          d_intent.get("outcome") == "requested" and "Permission denied" in d_failed.get("reason", ""),
          f"{d_intent} {d_failed}")
    async with sess["mod"].get(f"{base}/api/admin/audit-log?limit=100") as r:
        entries = (await r.json())["entries"]
        check("a moderator sees neither recording entry", r.status == 200 and not any(
            e["action"].startswith("recording_") for e in entries), str([e["action"] for e in entries]))
    async with sess["mod"].get(f"{base}/api/admin/audit-log?action=recording_delete_failed") as r:
        check("nor when asking for the failed action by name", r.status == 200
              and (await r.json())["entries"] == [])
    async with sess["adm"].get(f"{base}/api/admin/audit-log?action=recording_delete_failed") as r:
        check("an administrator sees it", len((await r.json())["entries"]) == 1)
    async with sess["adm"].delete(f"{base}/api/recordings/{rid}") as r:
        check("the delete works once the file can be removed", r.status == 200, str(r.status))
    check("a successful delete adds no failed entry", len(await audit(db, "recording_delete_failed")) == 1)

    # ---- item 1: only an administrator sets or clears the recording flag -------------------------
    PUBLIC = "93.184.216.34"

    async def make(who, name, config):
        async with sess[who].post(f"{base}/api/connections", json={
                "name": name, "type": "ssh", "host": PUBLIC, "port": 22, "config": config}) as r:
            body = await r.json()
            assert r.status == 201, (r.status, body)
            return body["id"]

    async def stored(conn_id):
        cur = await db.conn.execute("SELECT config FROM user_connections WHERE uuid = ? OR id = ?", (conn_id, conn_id))
        row = await cur.fetchone()
        cfg = decrypt_config(row["config"])
        return json.loads(cfg) if isinstance(cfg, str) else cfg

    async def update(who, conn_id, config):
        async with sess[who].put(f"{base}/api/connections/{conn_id}", json={"config": config}) as r:
            return r.status

    base_cfg = {"username": "u", "auth_method": "password", "credential_mode": "prompt"}
    c_member = await make("bob", "m1", {**base_cfg, "recording": True})
    check("a member creating a connection with recording true gets no recording flag",
          "recording" not in await stored(c_member), str(await stored(c_member)))
    c_admin = await make("adm", "a1", {**base_cfg, "recording": True})
    check("an administrator creating one with recording true keeps it", (await stored(c_admin)).get("recording") is True)
    c_admin_text = await make("adm", "a2", {**base_cfg, "recording": "true"})
    check("an administrator's value is stored as sent", (await stored(c_admin_text)).get("recording") == "true")
    check("a member's update is not an error", await update("bob", c_member, {**base_cfg, "recording": True}) == 200)
    check("a member's update does not turn recording on", "recording" not in await stored(c_member))
    # a stored flag (set by an administrator, or by 1.19 data) survives the member's edit unchanged
    await db.conn.execute("UPDATE user_connections SET config = ? WHERE uuid = ?",
                          (encrypt_config(json.dumps({**base_cfg, "recording": True})), c_member))
    await db.conn.commit()
    check("a member's update of a recorded connection is accepted", await update("bob", c_member, {"recording": False, "username": "u2"}) == 200)
    check("a member cannot clear the flag", (await stored(c_member)).get("recording") is True, str(await stored(c_member)))
    check("the other fields of the member's update were applied", (await stored(c_member)).get("username") == "u2")
    check("an administrator can clear it", await update("adm", c_admin, {"recording": False}) == 200
          and (await stored(c_admin)).get("recording") is False)
    check("an administrator's update without the key keeps it", await update("adm", c_admin_text, {"username": "z"}) == 200
          and (await stored(c_admin_text)).get("recording") == "true")
    check("an administrator can set it on their own connection", await update("adm", c_admin, {"recording": True}) == 200
          and (await stored(c_admin)).get("recording") is True)
    async with sess["mod"].post(f"{base}/api/connections", json={
            "name": "mm", "type": "ssh", "host": PUBLIC, "port": 22, "config": {**base_cfg, "recording": True}}) as r:
        mid = (await r.json())["id"]
    check("a moderator is not an administrator here", "recording" not in await stored(mid))

    # the form: the toggle exists for administrators only, nothing inline, the text says what is recorded
    root = Path(__file__).resolve().parent.parent
    index = (root / "static" / "index.html").read_text()
    ucjs = (root / "static" / "js" / "user-connections.js").read_text()
    grp = index.split('id="connection-ssh-recording-group"', 1)[1].split("</div>", 1)[0]
    check("the form has a hidden Record sessions toggle with no inline handler",
          'style="display: none;"' in grp and 'id="connection-ssh-recording"' in grp and not re.search(r"\son[a-z]+\s*=", grp))
    check("the toggle says output is recorded, keystrokes are not, and only administrators play it back",
          "output of the session is recorded" in grp and "keystrokes are not" in grp
          and "Only administrators can play" in grp)
    check("the script shows the toggle to administrators only and sends the flag only for them",
          "Portal.isAdmin(currentUser)" in ucjs and "connectionRecordingAllowed()" in ucjs
          and "if (type === 'ssh' && connectionRecordingAllowed())" in ucjs)
    fn = re.search(r"function recordingFlagOn\(value\) \{.*?\n\}\n", ucjs, re.S).group(0)
    run = subprocess.run(["node", "-e", fn + "console.log(JSON.stringify([true,1,'1','true','TRUE',false,0,'yes',2,1.0,null,undefined,['true']].map(recordingFlagOn)))"],
                         capture_output=True, text=True, timeout=30)
    check("the form reads the stored flag like the server does",
          json.loads(run.stdout) == [True, True, True, True, True, False, False, False, False, True, False, False, False], run.stdout + run.stderr)

    # ---- item 2: the disk budget and the free-space floor ----------------------------------------
    import logging  # noqa: E402
    import time as _time  # noqa: E402
    for f in Path(rec_dir).glob("*.cast"):
        f.unlink()
    await db.conn.execute("DELETE FROM recordings")
    await db.conn.commit()
    check("the default budget is 2048 MB and it is a retention (superadmin) setting",
          (await db.get_retention_config()).get("recording_max_total_mb") == "2048")
    async with sess["adm"].put(f"{base}/api/admin/retention", json={"recording_max_total_mb": 1}) as r:
        check("an administrator who is not a superadmin cannot change it", r.status == 403, str(r.status))
    await db.set_retention_config({"recording_max_total_mb": "-5"})
    check("a negative value is ignored", (await db.get_retention_config())["recording_max_total_mb"] == "2048")

    class Cap(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, rec):
            self.records.append(rec)
    cap = Cap()
    logging.getLogger("portal.recording").addHandler(cap)

    def refusals():
        return [x for x in cap.records if x.levelno >= logging.WARNING and "Recording refused" in x.getMessage()]

    any_conn = (await (await db.conn.execute("SELECT id FROM user_connections LIMIT 1")).fetchone())["id"]

    async def attempt(n=1):
        rec = session_recording.AsciicastRecorder(uid["bob"], None, 80, 24, connection_id=any_conn, connection_name="b", kind="ssh")
        started = await rec.start()
        return rec, started

    session_recording._warned.clear()
    await session_recording.reconcile_total()
    rec1, s1 = await attempt()
    check("with room left a recording starts", s1 is not None and rec1.filename is not None)
    # the folder is not walked per session: a start must work with scandir broken
    real_scandir = os.scandir

    def no_walk(*a, **k):
        raise AssertionError("the recordings folder was walked at the start of a session")
    os.scandir = no_walk
    try:
        rec2, s2 = await attempt()
    finally:
        os.scandir = real_scandir
    check("starting a recording does not walk the folder", s2 is not None)
    rec1.record_output("x" * 1000)
    before = session_recording.recordings_total_bytes()
    rec1.record_output("y" * 500)
    check("the running total grows with what is written", session_recording.recordings_total_bytes() > before)
    await rec1.finish()
    await rec2.finish()
    await db.set_retention_config({"recording_max_total_mb": "1"})
    big = Path(rec_dir) / "rec_big.cast"
    big.write_bytes(b"x" * (1024 * 1024 + 1))
    os.chmod(big, 0o600)
    await session_recording.reconcile_total()
    check("reconciling counts what is in the folder", session_recording.recordings_total_bytes() >= 1024 * 1024)
    n_files = len(list(Path(rec_dir).glob("*.cast")))
    rows_before = len(await (await db.conn.execute("SELECT id FROM recordings")).fetchall())
    rec3, s3 = await attempt()
    check("over budget a recording is refused and nothing is created", s3 is None
          and len(list(Path(rec_dir).glob("*.cast"))) == n_files
          and len(await (await db.conn.execute("SELECT id FROM recordings")).fetchall()) == rows_before)
    check("an older recording is never deleted to make room", big.exists() and len(list(Path(rec_dir).glob("*.cast"))) == n_files)
    check("one warning is logged for the refusal", len(refusals()) == 1, str(len(refusals())))
    await attempt()
    await attempt()
    check("the warning is rate limited", len(refusals()) == 1, str(len(refusals())))
    session_recording._warned.clear()
    await attempt()
    check("it is logged again once the interval has passed", len(refusals()) == 2)
    await db.set_retention_config({"recording_max_total_mb": "0"})
    rec4, s4 = await attempt()
    check("0 means no limit", s4 is not None)
    await rec4.finish()
    # the free-space floor: under min(1 GiB, 5 percent) free is refused
    real_fs = session_recording._free_and_total
    GiB = 1024 ** 3
    session_recording._free_and_total = lambda path: (GiB // 2, 100 * GiB)
    rec5, s5 = await attempt()
    check("under 1 GB free the recording is refused", s5 is None)
    session_recording._free_and_total = lambda path: (3 * GiB, 100 * GiB)
    rec5, s5 = await attempt()
    check("over 1 GB free it starts (on a 100 GB disk 5 percent is 5 GB, the smaller floor is 1 GB)", s5 is not None)
    await rec5.finish()
    session_recording._free_and_total = lambda path: (GiB // 4, 4 * GiB)
    rec6, s6 = await attempt()
    check("on a small disk the floor is 5 percent: 256 MB free of 4 GB passes", s6 is not None)
    await rec6.finish()
    session_recording._free_and_total = lambda path: (GiB // 100, 4 * GiB)
    rec7, s7 = await attempt()
    check("and 10 MB free of 4 GB is refused", s7 is None)
    session_recording._free_and_total = real_fs
    logging.getLogger("portal.recording").removeHandler(cap)
    admin_html = (Path(__file__).resolve().parent.parent / "static" / "admin.html").read_text()
    check("the retention form has the budget field", 'id="ret-recording-max"' in admin_html
          and "recording_max_total_mb: pInt('ret-recording-max', 2048)" in admin_html)

    # ---- item 5: a session cut by a restart is closed off at the next start -----------------------
    for f in Path(rec_dir).glob("*.cast"):
        f.unlink()
    await db.conn.execute("DELETE FROM recordings")
    await db.conn.commit()
    hdr = json.dumps({"version": 2, "width": 80, "height": 24}) + "\n"
    body = hdr + json.dumps([0.5, "o", "a"]) + "\n" + json.dumps([3.25, "o", "b" * 300]) + "\n"
    cut, f_cut = await add_row(db, rec_dir, uid["bob"], "cut", body=body + '[9.9, "o", "par', size=len(hdr), duration=0)
    big, f_big = await add_row(db, rec_dir, uid["bob"], "bigline", size=len(hdr), duration=0,
                               body=hdr + json.dumps([1.0, "o", "x"]) + "\n" + json.dumps([7.5, "o", "z" * 5000]) + "\n")
    empty, f_empty = await add_row(db, rec_dir, uid["bob"], "empty", body=hdr, size=len(hdr), duration=0)
    done, _ = await add_row(db, rec_dir, uid["bob"], "done", duration=12.0, size=7)
    gone, _ = await add_row(db, rec_dir, uid["bob"], "gone", size=5, duration=0)
    (Path(rec_dir) / f"rec_{uid['bob']}_c1_gone.cast").unlink()
    livec, f_live = await add_row(db, rec_dir, uid["bob"], "running", body=body, size=len(hdr), duration=0)
    db.live_recording_ids.add(livec)
    session_recording._TAIL_WINDOW = 64  # a small window, so the 5000-byte last line forces it to grow
    n = await session_recording.finish_interrupted()
    rows = {r: await db.get_recording(r) for r in (cut, big, empty, done, gone, livec)}
    check("an unfinished row gets the size of its file and the time of its last complete event",
          rows[cut]["size"] == len(body.encode()) + len('[9.9, "o", "par') and rows[cut]["duration"] == 3.25, str(rows[cut]))
    check("a last event longer than the tail window is still found", rows[big]["duration"] == 7.5, str(rows[big]))
    check("a header-only file is closed off with duration 0", rows[empty]["duration"] == 0 and rows[empty]["interrupted"] == 1)
    check("a finished row is not touched", rows[done]["duration"] == 12.0 and rows[done]["size"] == 7 and not rows[done]["interrupted"])
    check("a row whose file is missing is left alone (nothing deleted)", rows[gone]["size"] == 5 and not rows[gone]["interrupted"])
    check("a row of a running session is left alone", rows[livec]["duration"] == 0 and not rows[livec]["interrupted"])
    check("the pass says how many it closed", n == 3, str(n))
    check("the files themselves are untouched", (Path(rec_dir) / f_cut).read_text().endswith('"par'))
    check("running it again changes nothing", await session_recording.finish_interrupted() == 0)
    db.live_recording_ids.discard(livec)
    check("the startup block runs the pass after the budget is counted",
          "await session_recording.reconcile_total()\n            try:\n                await session_recording.finish_interrupted()"
          in (Path(__file__).resolve().parent.parent / "server.py").read_text())
    async with sess["adm"].get(f"{base}/api/recordings?connection=cut") as r:
        item = (await r.json())["recordings"][0]
        check("the list shows it as ended and interrupted, with its duration",
              item["live"] is False and item["ended_at"] is not None and item["duration"] == 3.25
              and item["interrupted"] is True, str(item))
    async with sess["adm"].get(f"{base}/api/recordings?connection=empty") as r:
        item = (await r.json())["recordings"][0]
        check("a header-only interrupted recording still has an end time", item["ended_at"] is not None, str(item))
    async with sess["adm"].get(f"{base}/api/recordings?connection=done") as r:
        check("a normal recording is not marked interrupted", (await r.json())["recordings"][0]["interrupted"] is False)

    await srv.close()
    for s in sess.values():
        await s.close()
    await db.close()
    shutil.rmtree(tmp, ignore_errors=True)


try:
    asyncio.run(main())
except BaseException as exc:  # a crash must end the run, not leave the test server hanging
    import traceback
    traceback.print_exc()
    print(f"\ntest_recording_admin_fixes: CRASHED: {exc!r}", flush=True)
    os._exit(1)
outbound_guard.report("test_recording_admin_fixes")
if failures:
    print(f"\ntest_recording_admin_fixes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_recording_admin_fixes: all checks passed")
