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
