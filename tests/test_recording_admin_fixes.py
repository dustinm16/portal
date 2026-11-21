"""Recordings, fix pass A: who may switch recording on, the disk budget, interrupted rows and
the truth of the delete audit trail.

Run: venv/bin/python tests/test_recording_admin_fixes.py

The real app runs on a loopback test server against a temporary database and a temporary
recordings folder. Nothing outside the temporary tree is touched and nothing is dialled.
"""

import asyncio
import json
import os
import shutil
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
