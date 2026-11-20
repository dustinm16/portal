"""Smoke check: the stored SSH password of a shared connection, on a running instance.

A throwaway sshd (asyncssh's own server on 127.0.0.1: generated host key, random password, a
shell that stays open, chrooted SFTP) runs inside this module and records every password it is
asked to check. The outbound host policy blocks loopback for user connections and is not
weakened: the HTTP routes (create, read, edit, share) run against the staged server with a
public address, and the connect paths (terminal, SFTP, revoke) run in short-lived child
processes (ctx.run_py) that call the real WebSocket handler, the real SFTP helper and the real
revoke routine with only the name lookup answered with 127.0.0.1.

Proves: a grantee opens a shared password connection in one click (no prompt frame, the sshd
saw the stored password and nothing typed); with "Prompt each time" the prompt still appears and
only what was typed is sent; no API response of the owner, the grantee, the share lists or any
WebSocket frame carries the password; only the owner can set, change or clear it; a changed
host, port or username clears it; an unpinned key and a connection that skips the host key check
make the sshd see no password at all; the SFTP browser uses the same credential; closing the
share ends the grantee's open terminal (close code 4010, the handler returns) and SFTP session.

Users and connections carry random suffixes and every assertion is about those rows, so the
module also holds on a stage started from a copy of the production database. It needs no admin
password.

Not proven here: a real SSH server of another make, a browser, Cloudflare.
"""

import asyncio
import json
import secrets

import asyncssh

PW = "Sshpass-smoke-pw-1!"
GOOD_HOST = "93.184.216.34"      # literal public address: no DNS needed
SSH_PW = "S3cret-" + secrets.token_urlsafe(14)
TYPED_PW = "Typed-" + secrets.token_urlsafe(10)

attempts = []                    # every password the sshd was asked to check


class _Sshd(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        attempts.append(password)
        return password == SSH_PW


async def _shell(process):
    process.stdout.write("hello from the test sshd\n")
    while not process.stdin.at_eof():
        await process.stdin.read(1024)
    process.exit(0)


SETUP = r'''
import asyncio, json
import database
from auth import create_user

JOB = json.loads(%(job)r)

async def main():
    await database.db.connect()
    db = database.db
    pre = JOB["pre"]
    out = {"users": {}, "rows": {}}
    for name in ("owner", "grantee", "stranger"):
        out["users"][name] = (await create_user(pre + name, JOB["password"]))["id"]
    base = {"username": "u", "auth_method": "password", "host_key_fingerprint": JOB["fp"]}
    rows = {
        "stored": {**base, "credential_mode": "stored", "password": JOB["ssh_pw"]},
        "prompt": {**base, "credential_mode": "prompt"},
        "unpinned": {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": JOB["ssh_pw"]},
        "ignore": {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": JOB["ssh_pw"],
                   "host_key_ignore": True},
        "revoke_ws": {**base, "credential_mode": "stored", "password": JOB["ssh_pw"]},
        "revoke_sftp": {**base, "credential_mode": "stored", "password": JOB["ssh_pw"]},
    }
    for name, cfg in rows.items():
        uuid = await db.create_user_connection(out["users"]["owner"], pre + "-" + name, "ssh", JOB["host"],
                                               JOB["port"], json.dumps(cfg))
        c = await db.get_user_connection_by_uuid(uuid, out["users"]["owner"])
        await db.add_connection_share(c["id"], out["users"]["grantee"], out["users"]["owner"])
        out["rows"][name] = {"uuid": uuid, "id": c["id"]}
    await db.close()
    print("RESULT=" + json.dumps(out))

asyncio.run(main())
'''

DRIVER = r'''
import asyncio, json, faulthandler
from aiohttp import web, WSMessage, WSMsgType
faulthandler.dump_traceback_later(100, exit=True)
import database, server, sftp_browser
from auth import TokenPayload
from plugins import load_builtin_plugins

load_builtin_plugins()
JOB = json.loads(%(job)r)

async def _loopback(host, port=0, **kw):
    return ["127.0.0.1"]
server.resolve_checked_host = _loopback
sftp_browser.resolve_checked_host = _loopback


class FakeWS(web.WebSocketResponse):
    """A client socket: what the portal sends is recorded, it stays open until the portal closes it."""
    def __init__(self, inbound):
        super().__init__()
        self._inbound = list(inbound)
        self.sent, self.out, self._fclosed, self._fcode = [], [], False, None
        self._req = type("R", (), {"query": {}})()

    @property
    def closed(self):
        return self._fclosed

    @property
    def close_code(self):
        return self._fcode

    async def send_json(self, d, **kw):
        self.sent.append(d)

    async def send_str(self, s, **kw):
        self.out.append(s)

    async def close(self, code=1000, message=b""):
        self._fclosed, self._fcode = True, code
        return True

    async def receive(self, timeout=None):
        if self._inbound:
            return WSMessage(WSMsgType.TEXT, json.dumps(self._inbound.pop(0)), None)
        while not self._fclosed:
            await asyncio.sleep(0.1)
        return WSMessage(WSMsgType.CLOSE, 0, None)

    def __aiter__(self):
        return self._forever()

    async def _forever(self):
        while not self._fclosed:
            await asyncio.sleep(0.1)
        return
        yield


class FakeRequest:
    def __init__(self, conn_id):
        self.match_info = {"conn_id": conn_id}


def token(uid):
    return TokenPayload({"sub": str(uid), "scopes": ["services:read", "access:*"]})


async def until(pred, secs):
    end = asyncio.get_event_loop().time() + secs
    while asyncio.get_event_loop().time() < end:
        if pred():
            return True
        await asyncio.sleep(0.1)
    return False


async def main():
    await database.db.connect()
    kind = JOB["kind"]
    out = {}
    if kind in ("ws", "ws_revoke"):
        ws = FakeWS([{"type": "auth", "password": JOB.get("typed", "")}] if JOB.get("typed") else [])
        task = asyncio.ensure_future(server.handle_user_connection_ws(
            ws, "/ws/user-connection/" + JOB["uuid"], token(JOB["uid"]), "127.0.0.1"))
        await until(lambda: any(m.get("type") in ("connected", "error", "host_key") for m in ws.sent) or task.done(), 25)
        if kind == "ws_revoke":
            out["connected"] = any(m.get("type") == "connected" for m in ws.sent)
            n = await server.close_grant_dependents("conn", JOB["cid"], JOB["uid"])
            out["closed_n"] = n
            await until(lambda: task.done(), 8)
            out["handler_returned"] = task.done()
            out["closed"], out["code"] = ws.closed, ws.close_code
        else:
            # a typed password goes only when the prompt was shown
            await until(lambda: any(m.get("type") in ("connected", "error", "host_key") for m in ws.sent), 25)
            await asyncio.sleep(0.5)
            await server.close_grant_dependents("conn", JOB["cid"], JOB["uid"])
            await until(lambda: task.done(), 8)
        out["sent"] = ws.sent
        out["out"] = ws.out
    elif kind == "sftp":
        conn, sftp, err = await server._get_sftp_connection(FakeRequest(JOB["uuid"]), token(JOB["uid"]))
        if err:
            out = {"status": err.status, "body": json.loads(err.text)}
        else:
            out = {"status": 200, "listing": sorted(await sftp.listdir("/"))}
            conn.close()
    elif kind == "sftp_revoke":
        conn, sftp, err = await server._get_sftp_connection(FakeRequest(JOB["uuid"]), token(JOB["uid"]))
        out["opened"] = err is None
        if err is None:
            out["before"] = sorted(await sftp.listdir("/"))
            await server.close_grant_dependents("conn", JOB["cid"], JOB["uid"])
            await asyncio.sleep(0.5)
            try:
                await asyncio.wait_for(sftp.listdir("/"), 3)
                out["after_ok"] = True
            except Exception:
                out["after_ok"] = False
    await database.db.close()
    print("RESULT=" + json.dumps(out))

asyncio.run(main())
'''


def _parse(out):
    line = next((l for l in out.splitlines() if l.startswith("RESULT=")), "")
    return json.loads(line[7:]) if line else None


async def run(ctx):
    key = asyncssh.generate_private_key("ssh-ed25519")
    import shutil
    import tempfile
    root = tempfile.mkdtemp(prefix="sshpass-sftp-")
    open(root + "/marker.txt", "w").write("x")
    sshd = await asyncssh.create_server(
        _Sshd, "127.0.0.1", 0, server_host_keys=[key], process_factory=_shell,
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
    port = sshd.sockets[0].getsockname()[1]
    try:
        await _run(ctx, port, key.get_fingerprint("sha256"))
    finally:
        sshd.close()
        await sshd.wait_closed()
        shutil.rmtree(root, ignore_errors=True)


async def drive(ctx, code, job):
    rc, out = await ctx.run_py(code % {"job": json.dumps(job)}, timeout=120)
    res = _parse(out)
    if rc != 0 or res is None:
        return {"_failed": out.strip()[-600:]}
    return res


def types(res):
    return [m.get("type") for m in res.get("sent", [])]


async def _run(ctx, port, fp):
    pre = "sp" + secrets.token_hex(3)

    def ok(name, passed, detail=""):
        ctx.ok("sshpass: " + name, bool(passed), "" if passed else str(detail)[:300])

    setup = await drive(ctx, SETUP, {"pre": pre, "password": PW, "ssh_pw": SSH_PW, "fp": fp,
                                     "host": GOOD_HOST, "port": port})
    ok("set up users and connections", "_failed" not in setup, setup)
    if "_failed" in setup:
        return
    users, rows = setup["users"], setup["rows"]
    oid, gid = users["owner"], users["grantee"]
    url = ctx.base_url

    async with ctx.http() as owner, ctx.http() as grantee, ctx.http() as stranger:
        for sess, name in ((owner, "owner"), (grantee, "grantee"), (stranger, "stranger")):
            r = await ctx.login(sess, pre + name, PW)
            if r.status != 200:
                ok(f"{name} logs in", False, r.status)
                return

        # ---- terminal: one click, and the prompt when it is asked for ------------------------
        attempts.clear()
        res = await drive(ctx, DRIVER, {"kind": "ws", "uuid": rows["stored"]["uuid"], "cid": rows["stored"]["id"],
                                        "uid": gid, "typed": TYPED_PW})
        ok("grantee opens a stored-password connection with no prompt",
           "auth_required" not in types(res) and "connected" in types(res), res)
        ok("the sshd saw the stored password and nothing the client typed", attempts == [SSH_PW], attempts)
        ok("no frame sent to the grantee carries the password",
           SSH_PW not in json.dumps(res.get("sent", [])) + "".join(res.get("out", [])), "")

        attempts.clear()
        res = await drive(ctx, DRIVER, {"kind": "ws", "uuid": rows["prompt"]["uuid"], "cid": rows["prompt"]["id"],
                                        "uid": gid, "typed": TYPED_PW})
        ok("Prompt each time still shows the prompt", "auth_required" in types(res), types(res))
        ok("and only what was typed reaches the sshd", attempts == [TYPED_PW], attempts)

        for label, name in (("an unpinned host key", "unpinned"), ("a connection that skips the host key check", "ignore")):
            attempts.clear()
            res = await drive(ctx, DRIVER, {"kind": "ws", "uuid": rows[name]["uuid"], "cid": rows[name]["id"],
                                            "uid": gid, "typed": TYPED_PW})
            ok(f"{label}: refused, and the sshd saw no password", attempts == [] and "connected" not in types(res), f"{attempts} {types(res)}")
            if name == "unpinned":
                hk = next((m for m in res.get("sent", []) if m.get("type") == "host_key"), {})
                ok("an unpinned key is shown to the grantee without an accept button", hk.get("can_accept") is False, hk)

        # ---- SFTP ---------------------------------------------------------------------------
        res = await drive(ctx, DRIVER, {"kind": "sftp", "uuid": rows["stored"]["uuid"], "cid": rows["stored"]["id"], "uid": gid})
        ok("grantee: the file browser uses the stored password", res.get("status") == 200 and "marker.txt" in res.get("listing", []), res)
        attempts.clear()
        res = await drive(ctx, DRIVER, {"kind": "sftp", "uuid": rows["unpinned"]["uuid"], "cid": rows["unpinned"]["id"], "uid": gid})
        ok("file browser, unpinned key: 409 and no password sent", res.get("status") == 409 and attempts == [], f"{res} {attempts}")
        res = await drive(ctx, DRIVER, {"kind": "sftp", "uuid": rows["prompt"]["uuid"], "cid": rows["prompt"]["id"], "uid": gid})
        ok("file browser: a connection that prompts has nothing to use", res.get("status") == 502 and SSH_PW not in json.dumps(res), res)

        # ---- the password is never returned --------------------------------------------------
        ruuid = rows["stored"]["uuid"]
        async with owner.post(f"{url}/api/connections/{ruuid}/shares", json={"usernames": [pre + "stranger"]}) as r:
            ok("owner shares with a third member", r.status == 200, r.status)
        leaked = []
        for who, sess in (("owner", owner), ("grantee", grantee), ("third member", stranger)):
            for path in ("/api/connections", f"/api/connections/{ruuid}", f"/api/connections/{ruuid}/connect", "/api/me/shares"):
                async with sess.get(url + path) as r:
                    text = await r.text()
                    if SSH_PW in text or "S3cret" in text:
                        leaked.append((who, path))
        ok("no API response to the owner or a grantee carries the password", not leaked, leaked)
        async with grantee.get(f"{url}/api/connections/{ruuid}") as r:
            cfg = (await r.json()).get("config", {})
            ok("the grantee sees has_stored_password and the mode, not a value",
               cfg.get("has_stored_password") is True and cfg.get("credential_mode") == "stored" and "password" not in cfg, cfg)

        # ---- only the owner writes it; host, port or username clear it -------------------------
        async with grantee.put(f"{url}/api/connections/{ruuid}", json={"config": {"password": "x", "credential_mode": "stored"}}) as r:
            ok("a grantee cannot set the password", r.status == 404, r.status)
        async with grantee.put(f"{url}/api/connections/{ruuid}", json={"config": {"credential_mode": "prompt"}}) as r:
            ok("a grantee cannot clear it", r.status == 404, r.status)

        async with owner.post(f"{url}/api/connections", json={
                "name": pre + "-api", "type": "ssh", "host": GOOD_HOST, "port": 22,
                "config": {"username": "u", "credential_mode": "stored", "password": SSH_PW}}) as r:
            body = await r.json()
            ok("owner creates a connection with a stored password", r.status == 201 and SSH_PW not in json.dumps(body), f"{r.status} {body}")
        api_id = body.get("id")

        async def api_cfg():
            async with owner.get(f"{url}/api/connections/{api_id}") as r:
                return (await r.json()).get("config", {})

        ok("it reports has_stored_password", (await api_cfg()).get("has_stored_password") is True, "")
        async with owner.post(f"{url}/api/connections", json={
                "name": pre + "-bad", "type": "ssh", "host": GOOD_HOST,
                "config": {"username": "u", "credential_mode": "stored"}}) as r:
            ok("stored mode without a password is refused", r.status == 400, r.status)
        for label, put_body in (("host", {"host": "93.184.216.35"}), ("port", {"port": 2200}),
                                ("username", {"config": {"username": "someone-else"}})):
            async with owner.put(f"{url}/api/connections/{api_id}", json={
                    "host": GOOD_HOST, "port": 22, "config": {"username": "u", "credential_mode": "stored", "password": SSH_PW}}) as r:
                pass
            async with owner.put(f"{url}/api/connections/{api_id}", json=put_body) as r:
                data = await r.json()
                cfg = await api_cfg()
                ok(f"changing the {label} clears the stored password", r.status == 200 and "has_stored_password" not in cfg
                   and data.get("stored_password_cleared") is True, f"{r.status} {data} {cfg}")
        async with owner.put(f"{url}/api/connections/{api_id}", json={
                "config": {"credential_mode": "stored", "password": SSH_PW}}) as r:
            pass
        async with owner.put(f"{url}/api/connections/{api_id}", json={"config": {"credential_mode": "prompt"}}) as r:
            ok("Prompt each time clears it", r.status == 200 and "has_stored_password" not in await api_cfg(), r.status)

        # ---- revoking the share closes what the grantee holds open ------------------------------
        ruu = rows["revoke_ws"]
        res = await drive(ctx, DRIVER, {"kind": "ws_revoke", "uuid": ruu["uuid"], "cid": ruu["id"], "uid": gid})
        ok("grantee's terminal was open when the share was closed", res.get("connected") is True, res)
        ok("closing the share ends the terminal with 4010 and the handler returns",
           res.get("closed") is True and res.get("code") == 4010 and res.get("handler_returned") is True, res)
        rs = rows["revoke_sftp"]
        res = await drive(ctx, DRIVER, {"kind": "sftp_revoke", "uuid": rs["uuid"], "cid": rs["id"], "uid": gid})
        ok("closing the share ends the grantee's SFTP session",
           res.get("opened") is True and "marker.txt" in res.get("before", []) and res.get("after_ok") is False, res)
        # the routes themselves (real share deletion over HTTP) are proven in tests/test_sshpass.py
        async with owner.delete(f"{url}/api/connections/{ruuid}/shares/{gid}") as r:
            ok("owner revokes the share over HTTP", r.status == 200, r.status)
        async with grantee.get(f"{url}/api/connections/{ruuid}") as r:
            ok("the grantee is refused afterwards", r.status == 404, r.status)
