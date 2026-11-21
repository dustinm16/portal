"""Smoke check: recording playback is for administrators only, and an SSH session on a
recording-enabled connection is recorded.

Users and services get random suffixes and the check is written for a production copy too:
no exact counts on shared tables, the administrator it needs is made in-process (no admin
password), and everything it creates it removes. The SSH session goes to a throwaway
asyncssh server (127.0.0.1, generated host key, random password) started by this module and
an admin ssh service that points at it with its host key pinned; the shell sends "first",
waits one and a half seconds and sends "second", and does not echo a line that starts with SECRET:.

Proves: the frame that announces a recorded session arrives before any output; the cast has
the session's timing and holds no keystrokes; the list never shows a path; the cast route
returns the file, is never cached and is audited; a member gets 404 for an existing and a
missing id; an API key gets 403; planted rows that point outside the folder or through a
symlink are refused; delete removes the file and the row.
"""

import asyncio
import json
import os
import secrets
from pathlib import Path

import asyncssh

PW = "Recording-Play-Pw-1!"
SSH_PW = secrets.token_urlsafe(18)
TYPED = "hunter2-" + secrets.token_hex(4)
SUFFIX = secrets.token_hex(3)
ADMIN = f"recpb_adm_{SUFFIX}"
MEMBER = f"recpb_mem_{SUFFIX}"


class _Sshd(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == SSH_PW


async def _shell(process):
    process.stdout.write("first\r\n")
    await asyncio.sleep(1.5)   # the recorder stamps events when it reads them, so the pause is long
    process.stdout.write("second\r\n")
    while not process.stdin.at_eof():
        try:
            data = await process.stdin.read(1024)
        except asyncssh.TerminalSizeChanged:
            continue
        if not data:
            continue
        process.stdout.write("accepted\r\n" if data.startswith("SECRET:") else "echo:" + data + "\r\n")
    process.exit(0)


SETUP = '''
import asyncio, json
from database import db
from auth import create_user

JOB = json.loads(%(job)r)

async def main():
    await db.connect()
    out = {}
    a = await create_user(JOB["admin"], JOB["pw"], is_admin=True)
    await db.set_user_role(a["id"], "superadmin")
    m = await create_user(JOB["member"], JOB["pw"], is_admin=False)
    out["admin_id"], out["member_id"] = a["id"], m["id"]
    out["pty"] = await db.create_service(name="recpb pty " + JOB["sfx"], path="/recpb-pty-" + JOB["sfx"],
                                         plugin="terminal", config={"recording": True, "shell": "/bin/bash"})
    out["ssh"] = await db.create_service(
        name="recpb ssh " + JOB["sfx"], path="/recpb-ssh-" + JOB["sfx"], plugin="ssh", host="127.0.0.1",
        port=JOB["port"], config={"username": "u", "auth_method": "password", "credential_mode": "stored",
                                  "password": JOB["ssh_pw"], "host_key_fingerprint": JOB["fp"],
                                  "recording": True})
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

PLANT = '''
import asyncio, json, os
from pathlib import Path
from config import Config
from database import db

JOB = json.loads(%(job)r)

async def add(name):
    cur = await db.conn.execute(
        "INSERT INTO recordings (user_id, service_id, filename, connection_name, kind) VALUES (?, ?, ?, ?, 'ssh')",
        (JOB["member_id"], JOB["service"], name, "recpb planted"))
    await db.conn.commit()
    return cur.lastrowid

async def main():
    await db.connect()
    d = Path(Config.RECORDINGS_DIR)
    d.mkdir(mode=0o700, exist_ok=True)
    outside = d.parent / ("recpb_outside_" + JOB["sfx"] + ".cast")
    outside.write_text("recpb-outside-secret")
    link = d / ("recpb_link_" + JOB["sfx"] + ".cast")
    os.symlink(outside, link)
    out = {"outside": str(outside), "link": str(link),
           "dotdot": await add("../" + outside.name), "abs": await add(str(outside)),
           "symlink": await add(link.name)}
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

CLEANUP = '''
import asyncio, json, os
from database import db

JOB = json.loads(%(job)r)

async def main():
    await db.connect()
    await db.conn.execute("DELETE FROM recordings WHERE user_id IN (?, ?) OR connection_name = 'recpb planted'",
                          (JOB["admin_id"], JOB["member_id"]))
    await db.conn.execute("DELETE FROM audit_log WHERE actor_id = ?", (JOB["admin_id"],))
    for sid in (JOB["pty"], JOB["ssh"]):
        await db.conn.execute("DELETE FROM services WHERE id = ?", (sid,))
    await db.conn.execute("DELETE FROM users WHERE id IN (?, ?)", (JOB["admin_id"], JOB["member_id"]))
    await db.conn.commit()
    await db.close()
    for p in JOB["files"]:
        try:
            os.unlink(p)
        except OSError:
            pass

asyncio.run(main())
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def _first_frames(ws, stop="connected", wait=15):
    """(frame dict or None, raw output seen before it)."""
    raw = []
    try:
        async with asyncio.timeout(wait):
            while True:
                m = await ws.receive()
                if m.type != 1:
                    return None, raw
                try:
                    d = json.loads(m.data)
                except ValueError:
                    raw.append(m.data)
                    continue
                if isinstance(d, dict) and d.get("type") in (stop, "error", "host_key"):
                    return d, raw
    except (asyncio.TimeoutError, TimeoutError):
        return None, raw


async def run(ctx):
    key = asyncssh.generate_private_key("ssh-ed25519")
    sshd = await asyncssh.create_server(_Sshd, "127.0.0.1", 0, server_host_keys=[key],
                                        process_factory=_shell, line_editor=False)
    port = sshd.sockets[0].getsockname()[1]
    job = {"admin": ADMIN, "member": MEMBER, "pw": PW, "sfx": SUFFIX, "port": port, "ssh_pw": SSH_PW,
           "fp": key.get_fingerprint("sha256")}
    rc, out = await ctx.run_py(SETUP % {"job": json.dumps(job)})
    ids = _result(out)
    ctx.ok("recording playback: users and services created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        sshd.close()
        return
    job.update(ids)
    rec_dir = Path(ctx.stage_dir) / "recordings"
    files = []
    try:
        async with ctx.http() as adm, ctx.http() as mem, ctx.http() as anon:
            r1 = await ctx.login(adm, ADMIN, PW)
            r2 = await ctx.login(mem, MEMBER, PW)
            if r1.status != 200 or r2.status != 200:
                ctx.ok("recording playback: the test users can sign in", False, f"{r1.status} {r2.status}")
                return
            wsbase = ctx.base_url.replace("https", "wss")

            # -- a terminal session and an SSH session, both recorded -----------------------------
            seen = {}
            for label, sid in (("terminal", ids["pty"]), ("ssh", ids["ssh"])):
                async with adm.ws_connect(f"{wsbase}/ws/terminal/{sid}", ssl=False) as ws:
                    frame, raw = await _first_frames(ws)
                    ctx.ok(f"recording playback: the {label} frame that announces recording arrives before any output",
                           bool(frame) and frame.get("type") == "connected" and frame.get("recording") is True
                           and raw == [], f"{frame} {raw[:2]}")
                    await asyncio.sleep(0.2)
                    await ws.send_json({"type": "resize", "cols": 90, "rows": 28})
                    await asyncio.sleep(0.9)
                    await ws.send_json({"type": "input", "data": "SECRET:" + TYPED + ("\n" if label == "terminal" else "")})
                    await asyncio.sleep(0.4)
                    await ws.send_json({"type": "input", "data": "echo smokemark\n" if label == "terminal" else "hello"})
                    await asyncio.sleep(1.8)   # the ssh shell's "second" comes 1.5 s after its "first"
                seen[label] = True
            await asyncio.sleep(1.0)

            # -- the list -----------------------------------------------------------------------------
            async with adm.get(f"{ctx.base_url}/api/recordings?user={ADMIN}") as r:
                data = await r.json()
            text = json.dumps(data)
            rows = {x["type"]: x for x in data.get("recordings", [])}
            ctx.ok("recording playback: the administrator lists both recordings, with no path or file name",
                   r.status == 200 and {"ssh", "terminal"} <= set(rows) and ".cast" not in text
                   and "recordings" not in {k for x in data["recordings"] for k in x}
                   and str(rec_dir) not in text, text[:300])
            ssh_row = rows.get("ssh")
            if ssh_row:
                files = [str(p) for p in rec_dir.glob(f"rec_{ids['admin_id']}_*.cast")]
                rid = ssh_row["id"]
                async with adm.get(f"{ctx.base_url}/api/recordings/{rid}/cast") as r:
                    body = await r.text()
                    cc = r.headers.get("Cache-Control", "")
                    status = r.status
                lines = [json.loads(x) for x in body.splitlines() if x.strip()]
                events = lines[1:]
                outs = [(e[0], e[2]) for e in events if e[1] == "o"]
                first_at = next((i for i, (t, d) in enumerate(outs) if "first" in d), None)
                second_at = next((i for i, (t, d) in enumerate(outs) if "second" in d), None)
                first = outs[first_at][0] if first_at is not None else None
                second = outs[second_at][0] if second_at is not None else None
                # The shell pauses 1.5 s between the two; the recorder stamps an event when it reads it,
                # so a slow start can only shrink the gap a little. 1.0 s is a gap the session had to
                # produce on its own; 6 s is far above anything but a broken clock.
                ctx.ok("recording playback: the cast route returns an asciicast with the session's own timing",
                       status == 200 and lines[0].get("version") == 2 and first_at is not None and second_at is not None
                       and first_at < second_at and 1.0 <= second - first <= 6.0,
                       f"{status} {first} {second} {first_at} {second_at}")
                ctx.ok("recording playback: the cast is not cached, holds a resize and no keystrokes",
                       "no-store" in cc and any(e[1] == "r" and e[2] == "90x28" for e in events)
                       and TYPED not in body and not any(e[1] == "i" for e in events), cc)
                rc, out = await ctx.run_py(
                    "import asyncio, json\nfrom database import db\nasync def m():\n await db.connect()\n"
                    " cur = await db.conn.execute(\"SELECT action, target_id FROM audit_log WHERE actor_id = %d "
                    "AND action = 'recording_play'\")\n rows = [dict(r) for r in await cur.fetchall()]\n"
                    " await db.close()\n print('RESULT ' + json.dumps(rows))\nasyncio.run(m())\n" % ids["admin_id"])
                audit = _result(out) or []
                ctx.ok("recording playback: the playback is in the audit log under the recording's id",
                       any(a["target_id"] == rid for a in audit), str(audit))
                async with mem.get(f"{ctx.base_url}/api/recordings/{rid}/cast") as r:
                    ctx.ok("recording playback: a member gets 404 for an existing id", r.status == 404, str(r.status))
                async with mem.get(f"{ctx.base_url}/api/recordings/987654321/cast") as r:
                    ctx.ok("recording playback: a member gets 404 for a missing id", r.status == 404, str(r.status))
                async with mem.get(f"{ctx.base_url}/api/recordings") as r:
                    ctx.ok("recording playback: a member cannot list", r.status == 404, str(r.status))
                async with mem.delete(f"{ctx.base_url}/api/recordings/{rid}") as r:
                    ctx.ok("recording playback: a member cannot delete", r.status == 404, str(r.status))
                async with anon.get(f"{ctx.base_url}/api/recordings", headers={"Accept": "application/json"}) as r:
                    ctx.ok("recording playback: no credential is 401", r.status == 401, str(r.status))
                async with adm.post(f"{ctx.base_url}/api/api-keys", json={"name": "recpb", "scopes": ["*"]}) as r:
                    key_body = await r.json()
                if key_body.get("key"):
                    async with anon.get(f"{ctx.base_url}/api/recordings", headers={"X-API-Key": key_body["key"]}) as r:
                        ctx.ok("recording playback: an administrator's full API key gets 403", r.status == 403, str(r.status))
                    async with adm.delete(f"{ctx.base_url}/api/api-keys/{key_body['id']}") as r:
                        pass
                else:
                    ctx.skip("recording playback: API key refused", f"no key made: {key_body}")

                # -- rows that point outside the folder -----------------------------------------------
                rc, out = await ctx.run_py(PLANT % {"job": json.dumps({**job, "service": ids["ssh"]})})
                planted = _result(out)
                ctx.ok("recording playback: unsafe rows planted", rc == 0 and bool(planted), out[-300:])
                if planted:
                    files += [planted["outside"], planted["link"]]
                    for label in ("dotdot", "abs", "symlink"):
                        async with adm.get(f"{ctx.base_url}/api/recordings/{planted[label]}/cast") as r:
                            body = await r.text()
                            ctx.ok(f"recording playback: a row with {label} is refused and nothing is served",
                                   r.status == 403 and "recpb-outside-secret" not in body, f"{r.status} {body[:80]}")
                    async with adm.delete(f"{ctx.base_url}/api/recordings/{planted['symlink']}") as r:
                        ctx.ok("recording playback: deleting the symlink row removes the link, never its target",
                               r.status == 200 and not os.path.lexists(planted["link"])
                               and Path(planted["outside"]).read_text() == "recpb-outside-secret", str(r.status))
                    async with adm.delete(f"{ctx.base_url}/api/recordings/{planted['dotdot']}") as r:
                        ctx.ok("recording playback: deleting a row with a path in its name touches no file",
                               r.status == 200 and Path(planted["outside"]).exists(), str(r.status))
                    async with adm.delete(f"{ctx.base_url}/api/recordings/{planted['abs']}") as r:
                        pass

                async with adm.delete(f"{ctx.base_url}/api/recordings/{rid}") as r:
                    ctx.ok("recording playback: the administrator deletes a recording", r.status == 200, str(r.status))
                async with adm.get(f"{ctx.base_url}/api/recordings/{rid}/cast") as r:
                    ctx.ok("recording playback: a deleted recording is gone (404)", r.status == 404, str(r.status))
            else:
                ctx.ok("recording playback: the SSH session produced a recording", False, text[:300])
    finally:
        sshd.close()
        job["files"] = files
        await ctx.run_py(CLEANUP % {"job": json.dumps(job)})
