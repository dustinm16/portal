"""SSH session recording and administrator-only playback of recordings.

Run: venv/bin/python tests/test_recording_playback.py

The real app runs on a loopback test server against a temporary database and a temporary
recordings folder. The real SSH plugin talks to a throwaway asyncssh server on 127.0.0.1
(generated host key, random password, a shell that stays open until the client leaves and
does not echo what it is told is a secret). Only the outbound host policy's name lookup is
answered with 127.0.0.1. No real remote SSH target is involved.
"""

import asyncio
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
import asyncssh  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import recording_paths  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
import session_recording  # noqa: E402
import sftp_browser  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402
from plugins import load_builtin_plugins  # noqa: E402

# The sandbox lives under /tmp, which a recordings folder may not (tests/test_recording_paths.py).
recording_paths.vod_staging.TEMP_ROOTS = ()

failures = []
PW = "Recording-pass-12345!"
SSH_PW = "S3cret-" + secrets.token_urlsafe(12)
PUBLIC = "93.184.216.34"
TYPED_SECRET = "hunter2-" + secrets.token_hex(4)


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Sshd(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == SSH_PW


async def shell(process):
    """first, then (after half a second) second. A line starting SECRET: is read and not echoed;
    anything else is echoed back as "echo:<text>"."""
    process.stdout.write("first\r\n")
    await asyncio.sleep(0.5)
    process.stdout.write("second\r\n")
    process.stderr.write("on-stderr\r\n")
    try:
        while not process.stdin.at_eof():
            try:
                data = await process.stdin.read(1024)
            except asyncssh.TerminalSizeChanged:
                continue  # a resize interrupts a read on the server side
            if not data:
                continue
            if data.startswith("SECRET:"):
                process.stdout.write("accepted\r\n")
            else:
                process.stdout.write("echo:" + data + "\r\n")
    finally:
        pass
    process.exit(0)


async def login(base, name):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with s.post(base + "/login", json={"username": name, "password": PW}) as r:
        assert r.status == 200, (name, r.status)
    return s


async def until_connected(ws, wait=10.0):
    """(connected frame or None, raw output seen before it)."""
    raw = []
    end = asyncio.get_event_loop().time() + wait
    while True:
        left = end - asyncio.get_event_loop().time()
        if left <= 0:
            return None, raw
        try:
            msg = await asyncio.wait_for(ws.receive(), left)
        except asyncio.TimeoutError:
            return None, raw
        if msg.type != aiohttp.WSMsgType.TEXT:
            return None, raw
        try:
            d = json.loads(msg.data)
        except ValueError:
            raw.append(msg.data)
            continue
        if d.get("type") in ("connected", "error", "host_key"):
            return d, raw


async def drain(ws, seconds):
    out = []
    end = asyncio.get_event_loop().time() + seconds
    while True:
        left = end - asyncio.get_event_loop().time()
        if left <= 0:
            return out
        try:
            msg = await asyncio.wait_for(ws.receive(), left)
        except asyncio.TimeoutError:
            return out
        if msg.type != aiohttp.WSMsgType.TEXT:
            return out
        out.append(msg.data)


def read_cast(path):
    lines = Path(path).read_text().splitlines()
    return json.loads(lines[0]), [json.loads(x) for x in lines[1:]]


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
    load_builtin_plugins()

    key_a = asyncssh.generate_private_key("ssh-ed25519")
    fp_a = key_a.get_fingerprint("sha256")
    # No line editor: with it asyncssh echoes input itself, which would hide whether the
    # portal records input.
    sshd = await asyncssh.create_server(
        Sshd, "127.0.0.1", 0, server_host_keys=[key_a], process_factory=shell, line_editor=False)
    port = sshd.sockets[0].getsockname()[1]

    async def _loopback(host, port=0, **kw):
        return ["127.0.0.1"]
    server.resolve_checked_host = _loopback
    sftp_browser.resolve_checked_host = _loopback

    names = ("owner", "bob", "adm", "sup", "mod")
    for name in names:
        await create_user(name, PW, is_admin=(name in ("adm", "sup")))
    uid = {n: (await db.get_user_by_username(n))["id"] for n in names}
    await db.set_user_role(uid["adm"], "admin")
    await db.set_user_role(uid["sup"], "superadmin")
    await db.set_user_role(uid["mod"], "moderator")
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()
    sess = {n: await login(base, n) for n in names}

    async def new_row(name, **extra):
        c = {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": SSH_PW,
             "host_key_fingerprint": fp_a, **extra}
        c = {k: v for k, v in c.items() if v is not None}
        uuid = await db.create_user_connection(uid["owner"], name, "ssh", PUBLIC, port, json.dumps(c))
        cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
        await db.add_connection_share(cid, uid["bob"], uid["owner"])
        return uuid, cid

    async def open_ws(who, uuid):
        return await sess[who].ws_connect(base.replace("http", "ws") + f"/ws/terminal/{uuid}")

    async def recordings_rows():
        cur = await db.conn.execute("SELECT * FROM recordings ORDER BY id")
        return [dict(r) for r in await cur.fetchall()]

    # ---- an unrecorded connection: no banner fact, no file --------------------------------------
    for n, (label, extra) in enumerate((("without the flag", {}), ("with the flag false", {"recording": False}),
                                        ("with the flag as text", {"recording": "true"}))):
        u, _ = await new_row(f"plain-{n}", **extra)
        ws = await open_ws("bob", u)
        conn, raw = await until_connected(ws)
        check(f"a connection {label} is not recorded and says so",
              conn is not None and conn.get("type") == "connected" and conn.get("recording") is False, str(conn))
        await drain(ws, 0.7)
        await ws.close()
    await asyncio.sleep(0.3)
    check("no recording row for an unrecorded connection", await recordings_rows() == [])
    Config.RECORDING_ENABLED = False
    u_off, _ = await new_row("globally-off", recording=True)
    ws = await open_ws("bob", u_off)
    conn, _ = await until_connected(ws)
    check("the portal-wide switch off keeps a flagged connection unrecorded",
          conn is not None and conn.get("recording") is False and await recordings_rows() == [], str(conn))
    await ws.close()
    Config.RECORDING_ENABLED = True

    # ---- a shared recorded SSH connection ------------------------------------------------------
    u_rec, cid = await new_row("rec box", recording=True)
    ws = await open_ws("bob", u_rec)
    conn, raw_before = await until_connected(ws)
    check("the frame announcing the connection says the session is recorded",
          conn is not None and conn.get("type") == "connected" and conn.get("recording") is True, str(conn))
    check("that frame arrives before any output", raw_before == [], str(raw_before))
    await asyncio.sleep(0.2)
    await ws.send_json({"type": "resize", "cols": 100, "rows": 30})
    await asyncio.sleep(0.8)  # "second" arrives about 0.5 s after "first"
    await ws.send_json({"type": "input", "data": "SECRET:" + TYPED_SECRET})
    await asyncio.sleep(0.2)
    await ws.send_json({"type": "input", "data": "hello"})
    seen = await drain(ws, 0.8)
    await ws.close()
    await asyncio.sleep(0.6)  # the session ends, the recorder finishes

    rows = await recordings_rows()
    check("exactly one recording row", len(rows) == 1, str(rows))
    row = rows[0]
    check("the grantee's session is recorded under the grantee's user id", row["user_id"] == uid["bob"], str(row))
    check("the row belongs to the connection, with its name, and no admin service",
          row["connection_id"] == cid and row["connection_name"] == "rec box" and row["service_id"] is None
          and row["kind"] == "ssh", str(row))
    check("size and duration were stored when the session ended",
          row["size"] > 50 and 0.4 < row["duration"] < 5, str(row))
    path = Path(rec_dir) / row["filename"]
    check("the file is 0600 in a 0700 folder",
          stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(rec_dir).st_mode) == 0o700)
    header, events = read_cast(path)
    check("asciicast v2 header with the size at the start", header.get("version") == 2 and header.get("width") == 80
          and header.get("height") == 24, str(header))
    outs = [(t, d) for t, k, d in events if k == "o"]
    first = next((t for t, d in outs if "first" in d), None)
    second = next((t for t, d in outs if "second" in d), None)
    check("output events carry the session's own timing (first, then second about 0.5 s later)",
          first is not None and second is not None and 0.4 <= second - first <= 2.0 and first < 1.0,
          f"first={first} second={second}")
    check("times never go backwards", [e[0] for e in events] == sorted(e[0] for e in events))
    check("a resize event is recorded", any(k == "r" and d == "100x30" for _t, k, d in events), str(events))
    check("what the remote sent on stderr is recorded too", any("on-stderr" in d for _t, d in outs))
    check("remote output of typed text is recorded", any("echo:hello" in d for _t, d in outs), str(events))
    check("keystrokes are never recorded: the typed secret is nowhere in the file",
          TYPED_SECRET not in path.read_text() and not any(k == "i" for _t, k, _d in events))
    check("only output, resize events and nothing else", {k for _t, k, _d in events} <= {"o", "r"}, str(events))
    check("the client still receives the output as before", any("echo:hello" in x for x in seen), str(seen))

    # the owner's own session is recorded under the owner's id
    ws = await open_ws("owner", u_rec)
    conn, _ = await until_connected(ws)
    await drain(ws, 0.3)
    await ws.close()
    await asyncio.sleep(0.6)
    rows = await recordings_rows()
    check("the owner's session is recorded under the owner's id",
          len(rows) == 2 and rows[1]["user_id"] == uid["owner"], str(rows))
    rid_bob, rid_owner = rows[0]["id"], rows[1]["id"]

    # ---- who may reach recordings -------------------------------------------------------------
    for who in ("bob", "owner", "mod"):
        for label, call in (("list", sess[who].get(base + "/api/recordings")),
                            ("cast of an existing id", sess[who].get(f"{base}/api/recordings/{rid_bob}/cast")),
                            ("cast of a missing id", sess[who].get(f"{base}/api/recordings/987654/cast")),
                            ("delete of an existing id", sess[who].delete(f"{base}/api/recordings/{rid_bob}")),
                            ("delete of a missing id", sess[who].delete(f"{base}/api/recordings/987654")),
                            ("a member's own recording", sess[who].get(f"{base}/api/recordings/{rid_owner}/cast"))):
            async with call as r:
                body = await r.text()
                check(f"{who}: {label} answers 404", r.status == 404, f"{r.status} {body[:80]}")
    async with aiohttp.ClientSession() as anon:
        async with anon.get(f"{base}/api/recordings", headers={"Accept": "application/json"}) as r:
            check("no credential at all is 401", r.status == 401, str(r.status))
    check("the member's attempts removed nothing", path.exists() and len(await recordings_rows()) == 2)

    # an API key, even a full one, is not a way to reach recordings
    async with sess["adm"].post(base + "/api/api-keys", json={"name": "k", "scopes": ["*"]}) as r:
        kd = await r.json()
    async with aiohttp.ClientSession() as k:
        for label, url, meth in (("list", "/api/recordings", "get"), ("cast", f"/api/recordings/{rid_bob}/cast", "get"),
                                 ("delete", f"/api/recordings/{rid_bob}", "delete")):
            async with getattr(k, meth)(base + url, headers={"X-API-Key": kd["key"]}) as r:
                check(f"an administrator's full API key cannot {label} recordings (403)", r.status == 403, str(r.status))
    async with sess["bob"].post(base + "/api/api-keys", json={"name": "kb", "scopes": ["*"]}) as r:
        kb = await r.json()
    async with aiohttp.ClientSession() as k:
        async with k.get(f"{base}/api/recordings/{rid_bob}/cast", headers={"X-API-Key": kb["key"]}) as r:
            check("a member's API key gets 404 like the member", r.status == 404, str(r.status))
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action LIKE 'recording_%'")
    check("refused attempts wrote no audit entry", (await cur.fetchone())["n"] == 0)

    # ---- the list ---------------------------------------------------------------------------------
    for who in ("adm", "sup"):
        async with sess[who].get(base + "/api/recordings") as r:
            data = await r.json()
            text = json.dumps(data)
            check(f"{who} lists recordings", r.status == 200 and data["total"] == 2 and len(data["recordings"]) == 2, text)
    item = data["recordings"][0]
    check("a row has id, user, connection, type, started, ended and size",
          {"id", "user", "connection", "type", "started_at", "ended_at", "size"} <= set(item)
          and item["connection"] == "rec box" and item["type"] == "ssh" and item["size"] > 0
          and item["started_at"].endswith("Z") and item["ended_at"] and item["ended_at"] >= item["started_at"], str(item))
    check("no file name or path anywhere in the list", ".cast" not in text and rec_dir not in text and "rec_" not in text
          and "filename" not in text, text)
    async with sess["adm"].get(base + "/api/recordings?user=BOB") as r:
        d = await r.json()
        check("filter by user (any case)", d["total"] == 1 and d["recordings"][0]["user"] == "bob", str(d))
    async with sess["adm"].get(base + "/api/recordings?connection=REC%20bo") as r:
        check("filter by part of the connection name", (await r.json())["total"] == 2)
    async with sess["adm"].get(base + "/api/recordings?connection=%25") as r:
        check("a wildcard in the filter is taken literally", (await r.json())["total"] == 0)
    async with sess["adm"].get(base + "/api/recordings?from=2999-01-01") as r:
        check("filter by date: nothing starts in the future", (await r.json())["total"] == 0)
    async with sess["adm"].get(base + "/api/recordings?from=2000-01-01&to=2999-01-01") as r:
        check("filter by date range", (await r.json())["total"] == 2)
    async with sess["adm"].get(base + "/api/recordings?from=yesterday") as r:
        check("a bad date is 400", r.status == 400)
    async with sess["adm"].get(base + "/api/recordings?limit=1&page=2") as r:
        d = await r.json()
        check("paging", d["total"] == 2 and len(d["recordings"]) == 1 and d["page"] == 2, str(d))
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action LIKE 'recording_%'")
    check("listing is not audited", (await cur.fetchone())["n"] == 0)

    # ---- playback -------------------------------------------------------------------------------
    async with sess["adm"].get(f"{base}/api/recordings/{rid_bob}/cast") as r:
        body = await r.read()
        check("the cast route returns the recording as it is on disk",
              r.status == 200 and body == path.read_bytes(), f"{r.status} {len(body)}")
        check("the cast is never cached", "no-store" in r.headers.get("Cache-Control", ""), str(dict(r.headers)))
        check("the cast is not served as HTML", "html" not in r.headers.get("Content-Type", ""))
        check("a play is not an attachment", "Content-Disposition" not in r.headers)
    cur = await db.conn.execute("SELECT * FROM audit_log WHERE action = 'recording_play'")
    audit = [dict(x) for x in await cur.fetchall()]
    check("one audit entry for the playback, naming the admin and the recording",
          len(audit) == 1 and audit[0]["actor_id"] == uid["adm"] and audit[0]["actor_username"] == "adm"
          and audit[0]["target_id"] == rid_bob and audit[0]["target_type"] == "recording", str(audit))
    details = json.loads(server.decrypt_message(audit[0]["details"])) if hasattr(server, "decrypt_message") else None
    if details is None:
        from database import decrypt_message
        details = json.loads(decrypt_message(audit[0]["details"]))
    check("the entry names the recording's owner and its connection",
          details.get("owner") == "bob" and details.get("owner_id") == uid["bob"]
          and details.get("connection") == "rec box" and details.get("recording_id") == rid_bob, str(details))
    async with sess["sup"].get(f"{base}/api/recordings/{rid_bob}/cast?download=1") as r:
        body = await r.read()
        check("download sends an attachment", r.status == 200 and "attachment" in r.headers.get("Content-Disposition", "")
              and body == path.read_bytes())
    cur = await db.conn.execute("SELECT * FROM audit_log WHERE action = 'recording_download'")
    check("the download is audited under its own action",
          len([x for x in await cur.fetchall()]) == 1)
    async with sess["adm"].get(f"{base}/api/admin/audit-log?limit=50") as r:
        acts = [e["action"] for e in (await r.json())["entries"]]
        check("an administrator sees the playback in the audit log", "recording_play" in acts, str(acts))
    async with sess["mod"].get(f"{base}/api/admin/audit-log?limit=50") as r:
        acts = [e["action"] for e in (await r.json())["entries"]]
        check("a moderator does not see who played which recording", not any(a.startswith("recording_") for a in acts), str(acts))

    async with sess["adm"].head(f"{base}/api/recordings/{rid_bob}/cast") as r:
        check("a HEAD request is not a playback (405)", r.status == 405, str(r.status))
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'recording_play'")
    check("and writes no audit entry", (await cur.fetchone())["n"] == 1)

    # the audit failing means nothing is served
    real_audit = db.create_audit_entry

    async def broken(*a, **kw):
        raise RuntimeError("disk full")
    db.create_audit_entry = broken
    async with sess["adm"].get(f"{base}/api/recordings/{rid_bob}/cast") as r:
        check("a playback that cannot be audited is refused (500) and serves nothing",
              r.status == 500 and b'"version"' not in await r.read(), str(r.status))
    db.create_audit_entry = real_audit

    # ---- rows that point somewhere they must not ------------------------------------------------
    outside = Path(tmp) / "outside.cast"
    outside.write_text('{"version": 2, "width": 80, "height": 24}\n[0.1, "o", "outside-secret"]\n')
    other_dir = Path(tmp) / "elsewhere"
    other_dir.mkdir()
    os.symlink(outside, Path(rec_dir) / "link.cast")
    os.symlink(other_dir, Path(rec_dir) / "dirlink.cast")
    planted = {}
    for label, fname in (("a parent folder", "../outside.cast"), ("an absolute path", str(outside)),
                         ("a nested path", "sub/x.cast"), ("a symlink", "link.cast"),
                         ("a symlinked folder", "dirlink.cast"), ("a non-recording name", "t.db"),
                         ("a missing file", "gone.cast")):
        cur = await db.conn.execute(
            "INSERT INTO recordings (user_id, service_id, filename, connection_name, kind) VALUES (?, NULL, ?, ?, 'ssh')",
            (uid["bob"], fname, "planted " + label))
        await db.conn.commit()
        planted[label] = cur.lastrowid
    for label, rid in planted.items():
        async with sess["adm"].get(f"{base}/api/recordings/{rid}/cast") as r:
            body = await r.text()
            want = 404 if label == "a missing file" else 403
            check(f"a row with {label} is refused, nothing is served", r.status == want and "outside-secret" not in body,
                  f"{r.status} {body[:80]}")
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'recording_play'")
    check("a refused playback is not logged as a playback", (await cur.fetchone())["n"] == 1)

    # ---- delete -------------------------------------------------------------------------------
    async with sess["adm"].delete(f"{base}/api/recordings/{planted['a parent folder']}") as r:
        d = await r.json()
        check("deleting a row with a path in its name removes the row only", r.status == 200
              and d["file_removed"] is False and outside.exists(), str(d))
    async with sess["adm"].delete(f"{base}/api/recordings/{planted['a symlink']}") as r:
        check("deleting a symlink row removes the link, never its target", r.status == 200
              and not (Path(rec_dir) / "link.cast").is_symlink() and outside.exists())
    db.live_recording_ids.add(rid_owner)
    async with sess["adm"].delete(f"{base}/api/recordings/{rid_owner}") as r:
        check("a session that is still running cannot be deleted (409)", r.status == 409, str(r.status))
    db.live_recording_ids.discard(rid_owner)
    owner_file = Path(rec_dir) / next(x for x in await recordings_rows() if x["id"] == rid_owner)["filename"]
    async with sess["adm"].delete(f"{base}/api/recordings/{rid_owner}") as r:
        d = await r.json()
        check("delete removes the file and the row", r.status == 200 and d["file_removed"] is True
              and not owner_file.exists() and all(x["id"] != rid_owner for x in await recordings_rows()), str(d))
    cur = await db.conn.execute("SELECT * FROM audit_log WHERE action = 'recording_delete' AND target_id = ?", (rid_owner,))
    check("the delete is audited", len(await cur.fetchall()) == 1)
    async with sess["adm"].delete(f"{base}/api/recordings/{rid_owner}") as r:
        check("deleting it again is 404", r.status == 404)

    # ---- deleting the connection keeps the record ------------------------------------------------
    await db.conn.execute("DELETE FROM user_connections WHERE id = ?", (cid,))
    await db.conn.commit()
    async with sess["adm"].get(f"{base}/api/recordings?user=bob") as r:
        d = await r.json()
        mine = [x for x in d["recordings"] if x["id"] == rid_bob]
        check("a recording outlives its deleted connection, still named", len(mine) == 1
              and mine[0]["connection"] == "rec box", str(d))

    sshd.close()
    await srv.close()
    for s in sess.values():
        await s.close()
    await db.close()
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
outbound_guard.report("test_recording_playback")
if failures:
    print(f"\ntest_recording_playback: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_recording_playback: all checks passed")
