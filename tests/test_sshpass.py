"""Stored SSH password for shared connections.

Run: venv/bin/python tests/test_sshpass.py

The real app runs on a loopback test server against a temporary database, with the real SSH
plugin and SFTP browser talking to a throwaway asyncssh server on 127.0.0.1 (random password,
generated host key, a shell that stays open until the client leaves, chrooted SFTP). Only the
outbound host policy's name lookup is answered with 127.0.0.1 (the rows are stored with a
public address). No real remote SSH target is involved; the end of a grantee's session on
revoke is proven against this local server.
"""

import asyncio
import json
import logging
import os
import secrets
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
import asyncssh  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import grant_expiry  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
import sftp_browser  # noqa: E402
import sshpass_rules  # noqa: E402
from auth import TokenPayload, create_user  # noqa: E402
from config import Config  # noqa: E402
from plugins import load_builtin_plugins  # noqa: E402

failures = []
PW = "Sshpass-pass-12345!"
SSH_PW = "S3cret-" + secrets.token_urlsafe(12)
OTHER_PW = "Other-" + secrets.token_urlsafe(12)
PUBLIC = "93.184.216.34"


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


T0 = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
clock = {"now": T0}
grant_expiry.set_clock(lambda: clock["now"])

attempts = []          # every password the test sshd was asked to check
open_sessions = []     # shells currently open on the sshd


class Sshd(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        attempts.append(password)
        return password == SSH_PW


async def shell(process):
    open_sessions.append(process)
    process.stdout.write("welcome\n")
    try:
        while not process.stdin.at_eof():
            await process.stdin.read(1024)
    finally:
        if process in open_sessions:
            open_sessions.remove(process)
    process.exit(0)


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.text = []

    def emit(self, record):
        try:
            self.text.append(record.getMessage())
            if record.exc_info:
                self.text.append(repr(record.exc_info[1]))
        except Exception:
            pass


async def login(base, name):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with s.post(base + "/login", json={"username": name, "password": PW}) as r:
        assert r.status == 200, (name, r.status)
    return s


async def frames(ws, stop_types, wait=8.0):
    """JSON frames up to and including the first of stop_types; raw output is collected apart."""
    out, raw = [], []
    end = asyncio.get_event_loop().time() + wait
    while True:
        left = end - asyncio.get_event_loop().time()
        if left <= 0:
            return out, raw
        try:
            msg = await asyncio.wait_for(ws.receive(), left)
        except asyncio.TimeoutError:
            return out, raw
        if msg.type != aiohttp.WSMsgType.TEXT:
            return out, raw
        try:
            d = json.loads(msg.data)
        except ValueError:
            raw.append(msg.data)
            continue
        out.append(d)
        if d.get("type") in stop_types:
            return out, raw


async def close_code(ws, wait=5.0):
    try:
        while True:
            msg = await asyncio.wait_for(ws.receive(), wait)
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                return msg.data if msg.type == aiohttp.WSMsgType.CLOSE else ws.close_code
    except asyncio.TimeoutError:
        return None


class FakeRequest:
    def __init__(self, conn_id):
        self.match_info = {"conn_id": conn_id}


async def main():
    tmp = tempfile.mkdtemp()
    root = tempfile.mkdtemp(prefix="sshpass-sftp-")
    open(root + "/marker.txt", "w").write("x")
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
    load_builtin_plugins()
    cap = Capture()
    for name in ("", "portal", "portal.plugins.ssh"):
        logging.getLogger(name).addHandler(cap)
    logging.getLogger("portal").setLevel(logging.DEBUG)

    key_a = asyncssh.generate_private_key("ssh-ed25519")
    key_b = asyncssh.generate_private_key("ssh-ed25519")
    fp_a, fp_b = key_a.get_fingerprint("sha256"), key_b.get_fingerprint("sha256")
    sshd = await asyncssh.create_server(
        Sshd, "127.0.0.1", 0, server_host_keys=[key_a], process_factory=shell,
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
    port = sshd.sockets[0].getsockname()[1]

    async def _loopback(host, port=0, **kw):
        return ["127.0.0.1"]
    server.resolve_checked_host = _loopback
    sftp_browser.resolve_checked_host = _loopback

    for name in ("owner", "bob", "carol", "adm"):
        await create_user(name, PW, is_admin=(name == "adm"))
    await db.set_user_role((await db.get_user_by_username("adm"))["id"], "admin")
    uid = {n: (await db.get_user_by_username(n))["id"] for n in ("owner", "bob", "carol", "adm")}
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()
    owner, bob, carol, adm = [await login(base, n) for n in ("owner", "bob", "carol", "adm")]

    async def new_row(name, typ="ssh", **cfg):
        c = {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": SSH_PW,
             "host_key_fingerprint": fp_a, **cfg}
        c = {k: v for k, v in c.items() if v is not None}
        uuid = await db.create_user_connection(uid["owner"], name, typ, PUBLIC, port, json.dumps(c))
        cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
        await db.add_connection_share(cid, uid["bob"], uid["owner"])
        return uuid, cid

    async def stored_config(uuid):
        return (await db.get_user_connection_by_uuid(uuid, uid["owner"]))["config"]

    async def open_ws(sess, uuid):
        return await sess.ws_connect(base.replace("http", "ws") + f"/ws/terminal/{uuid}")

    # ---- rules of the module (pure) ---------------------------------------------------------
    check("terminal asks unless the mode is stored",
          sshpass_rules.terminal_password({"password": "x"}) is None
          and sshpass_rules.terminal_password({"password": "x", "credential_mode": "prompt"}) is None
          and sshpass_rules.terminal_password({"password": "x", "credential_mode": "stored"}) == "x")
    check("sftp keeps using a password of a connection without a mode, not one set to prompt",
          sshpass_rules.sftp_password({"password": "x"}) == "x"
          and sshpass_rules.sftp_password({"password": "x", "credential_mode": "prompt"}) is None)

    # ---- create ------------------------------------------------------------------------------
    body = {"name": "box", "type": "ssh", "host": PUBLIC, "port": 22,
            "config": {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": SSH_PW}}
    async with owner.post(base + "/api/connections", json=body) as r:
        created = await r.json()
        check("owner creates a connection with a stored password", r.status == 201, str(created))
    cuuid = created["id"]
    check("the create response does not carry the password", SSH_PW not in json.dumps(created))
    cfg = await stored_config(cuuid)
    check("the password and the mode are stored in the config",
          cfg.get("password") == SSH_PW and cfg.get("credential_mode") == "stored")
    raw = await (await db.conn.execute("SELECT config FROM user_connections WHERE uuid = ?", (cuuid,))).fetchone()
    check("the config column does not hold the password in clear", SSH_PW not in raw["config"])

    for label, cfg_bad in (
            ("stored mode without a password", {"username": "u", "credential_mode": "stored"}),
            ("an unknown mode", {"username": "u", "credential_mode": "sometimes"}),
            ("a non-string password", {"username": "u", "password": 12345}),
            ("a stored password on a connection that skips the host key check",
             {"username": "u", "credential_mode": "stored", "password": "p", "host_key_ignore": True}),
            ("a stored password with key authentication",
             {"username": "u", "auth_method": "key", "credential_mode": "stored", "password": "p"})):
        async with owner.post(base + "/api/connections", json={**body, "name": "bad-" + label[:8], "config": cfg_bad}) as r:
            check(f"create refuses {label}", r.status == 400, str(r.status))
    async with owner.post(base + "/api/connections", json={**body, "name": "prompting", "config": {"username": "u"}}) as r:
        check("a connection without the fields is created as before", r.status == 201)

    # ---- the password is never returned ------------------------------------------------------
    async with owner.post(f"{base}/api/connections/{cuuid}/shares", json={"usernames": ["bob"], "expires_in": "30d"}) as r:
        check("owner shares the connection", r.status == 200, str(r.status))

    seen = {}
    for who, sess in (("owner", owner), ("grantee", bob), ("admin", adm), ("stranger", carol)):
        for label, url in (("list", "/api/connections"), ("get", f"/api/connections/{cuuid}"),
                           ("connect", f"/api/connections/{cuuid}/connect"),
                           ("shares", f"/api/connections/{cuuid}/shares"), ("my shares", "/api/me/shares"),
                           ("all grants", "/api/admin/grants")):
            async with sess.get(base + url) as r:
                text = await r.text()
                seen[(who, label)] = (r.status, text)
                check(f"{who} / {label}: no password in the response", SSH_PW not in text and "S3cret" not in text,
                      f"{r.status}")
    for who in ("owner", "grantee"):
        d = json.loads(seen[(who, "get")][1])
        check(f"{who} sees has_stored_password and no password fields",
              d["config"].get("has_stored_password") is True and "password" not in d["config"]
              and "has_password" not in d["config"], str(d["config"]))
    check("a stranger gets no connection", seen[("stranger", "get")][0] == 404)

    # ---- only the owner can set, change or clear it ------------------------------------------
    for who, sess in (("grantee", bob), ("stranger", carol)):
        async with sess.put(f"{base}/api/connections/{cuuid}",
                            json={"config": {"password": "hijack", "credential_mode": "stored"}}) as r:
            check(f"{who} cannot set the password", r.status == 404, str(r.status))
        async with sess.put(f"{base}/api/connections/{cuuid}", json={"config": {"credential_mode": "prompt"}}) as r:
            check(f"{who} cannot clear the password", r.status == 404, str(r.status))
    check("the stored password is unchanged by them", (await stored_config(cuuid)).get("password") == SSH_PW)

    # ---- updates: keep, change, clear ---------------------------------------------------------
    put = lambda body: owner.put(f"{base}/api/connections/{cuuid}", json=body)
    async with put({"name": "box2", "config": {"shell": "/bin/bash"}}) as r:
        check("an edit that does not mention the password keeps it",
              r.status == 200 and (await stored_config(cuuid)).get("password") == SSH_PW, str(r.status))
    async with put({"config": {"password": OTHER_PW}}) as r:
        check("a new password replaces the stored one", r.status == 200
              and (await stored_config(cuuid)).get("password") == OTHER_PW)
    async with put({"config": {"password": ""}}) as r:
        c = await stored_config(cuuid)
        check("an empty password clears it and the mode falls back to prompt",
              r.status == 200 and "password" not in c and c.get("credential_mode") == "prompt", str(c))
    async with put({"config": {"credential_mode": "stored"}}) as r:
        check("stored mode with nothing stored is refused", r.status == 400, str(r.status))
    async with put({"config": {"credential_mode": "stored", "password": SSH_PW}}) as r:
        check("owner stores a password again", r.status == 200 and (await stored_config(cuuid)).get("password") == SSH_PW)
    async with put({"config": {"credential_mode": "prompt"}}) as r:
        c = await stored_config(cuuid)
        check("choosing Prompt each time clears the stored password", r.status == 200 and "password" not in c, str(c))
    async with put({"config": {"credential_mode": "stored", "password": SSH_PW}}) as r:
        pass
    async with put({"config": {"credential_mode": "stored", "host_key_ignore": True}}) as r:
        check("turning the host key check off on a stored password is refused", r.status == 400, str(r.status))
    async with put({"config": {"credential_mode": "stored", "password": 5}}) as r:
        check("a non-string password is refused on edit", r.status == 400, str(r.status))

    for label, body_in, expect_pin_gone in (
            ("the host", {"host": "93.184.216.35"}, True),
            ("the port", {"port": port + 1}, True),
            ("the username", {"config": {"username": "someone-else"}}, False)):
        async with put({"config": {"credential_mode": "stored", "password": SSH_PW, "username": "u"}, "host": PUBLIC, "port": port}) as r:
            pass
        await db.update_user_connection(
            (await db.get_user_connection_by_uuid(cuuid, uid["owner"]))["id"], uid["owner"],
            config={**await stored_config(cuuid), "host_key_fingerprint": fp_a})
        async with put(body_in) as r:
            c = await stored_config(cuuid)
            data = await r.json()
            check(f"changing {label} clears the stored password and says so",
                  r.status == 200 and "password" not in c and c.get("credential_mode") == "prompt"
                  and data.get("stored_password_cleared") is True, f"{r.status} {c} {data}")
        if expect_pin_gone:
            check(f"changing {label} also drops the host key pin", "host_key_fingerprint" not in c)
        async with owner.get(f"{base}/api/connections/{cuuid}") as r2:
            check(f"after changing {label} the API shows no stored password",
                  "has_stored_password" not in (await r2.json())["config"])
    async with put({"host": PUBLIC, "port": port,
                    "config": {"username": "u", "credential_mode": "stored", "password": SSH_PW}}) as r:
        pass
    async with put({"host": "93.184.216.35", "config": {"credential_mode": "stored", "password": OTHER_PW}}) as r:
        c = await stored_config(cuuid)
        check("a password sent in the same request as a host change is kept",
              r.status == 200 and c.get("password") == OTHER_PW and c.get("credential_mode") == "stored", str(c))
    async with put({"host": PUBLIC, "port": port, "config": {"auth_method": "key", "private_key": "x", "credential_mode": "prompt"}}) as r:
        check("key authentication holds no stored password", "password" not in await stored_config(cuuid))

    # ---- a row that leaves ssh/sftp keeps nothing of the stored password ----------------------
    for label, body_in in (("spice", {"type": "spice"}),
                           ("proxmox", {"type": "proxmox"}),
                           ("proxmox on another host", {"type": "proxmox", "host": "93.184.216.99"})):
        u_t, id_t = await new_row("leave-" + label.replace(" ", "-"))
        async with owner.put(f"{base}/api/connections/{u_t}", json=body_in) as r:
            data = await r.json()
            c = await stored_config(u_t)
            check(f"moving a stored-password row to {label} drops the password and the mode and says so",
                  r.status == 200 and "password" not in c and "credential_mode" not in c
                  and data.get("stored_password_cleared") is True, f"{r.status} {c} {data}")
        if body_in["type"] == "spice":
            for who, sess in (("owner", owner), ("grantee", bob)):
                ws = await sess.ws_connect(base.replace("http", "ws") + f"/ws/user-connection/{u_t}")
                got, _ = await frames(ws, {"auth", "error"}, wait=4.0)
                await ws.close()
                check(f"{who} gets no frame with the SSH password from the spice row",
                      SSH_PW not in json.dumps(got), str(got))
        async with owner.put(f"{base}/api/connections/{u_t}", json={"type": "ssh"}) as r:
            c = await stored_config(u_t)
            check(f"moving the {label} row back to ssh does not bring the password back",
                  r.status == 200 and "password" not in c, str(c))
    u_t, id_t = await new_row("leave-with-new-password")
    async with owner.put(f"{base}/api/connections/{u_t}", json={"type": "spice", "config": {"password": OTHER_PW}}) as r:
        data = await r.json()
        c = await stored_config(u_t)
        check("a password sent with the type change is kept as the new type's own, without a mode",
              r.status == 200 and c.get("password") == OTHER_PW and "credential_mode" not in c
              and "stored_password_cleared" not in data, f"{r.status} {c} {data}")

    # ---- terminal: one click for the grantee -------------------------------------------------
    u_ok, id_ok = await new_row("pinned-stored")
    attempts.clear()
    ws = await open_ws(bob, u_ok)
    fr, raw_out = await frames(ws, {"connected", "error", "host_key"})
    types = [f.get("type") for f in fr]
    check("grantee: no password prompt and the shell opens", "auth_required" not in types and "connected" in types, str(fr))
    check("grantee: the sshd saw the stored password and nothing else", attempts == [SSH_PW], str(attempts))
    check("grantee: no frame carries the password", SSH_PW not in json.dumps(fr) + "".join(raw_out))
    check("grantee: a shell is open on the sshd", len(open_sessions) == 1, str(len(open_sessions)))

    # ---- revoking the share closes the live terminal ----------------------------------------
    gid = uid["bob"]
    async with owner.delete(f"{base}/api/connections/{u_ok}/shares/{gid}") as r:
        check("owner revokes the share", r.status == 200, str(r.status))
    code = await close_code(ws)
    check("revoke closes the grantee's terminal with the access-ended code", code == server.GRANT_ENDED_CLOSE_CODE, str(code))
    await asyncio.sleep(0.5)
    check("the SSH session on the target is gone", not open_sessions, str(len(open_sessions)))
    ws2 = await open_ws(bob, u_ok)
    fr2, _ = await frames(ws2, {"error"})
    check("after the revoke the grantee cannot open it again", any(f.get("type") == "error" for f in fr2), str(fr2))
    check("a refused reopen sent no password", attempts == [SSH_PW], str(attempts))

    # ---- expiry closes it too ----------------------------------------------------------------
    u_exp, id_exp = await new_row("expiring")
    async with owner.post(f"{base}/api/connections/{u_exp}/shares", json={"usernames": ["bob"], "expires_in": "1h"}) as r:
        pass
    ws = await open_ws(bob, u_exp)
    fr, _ = await frames(ws, {"connected", "error", "host_key"})
    check("grantee opens the time-limited share", "connected" in [f.get("type") for f in fr], str(fr))
    clock["now"] = clock["now"] + timedelta(hours=2)
    await server.sweep_expired_grants_once()
    code = await close_code(ws)
    check("expiry closes the grantee's terminal", code == server.GRANT_ENDED_CLOSE_CODE, str(code))
    await asyncio.sleep(0.5)
    check("the session on the target is gone after expiry", not open_sessions)
    clock["now"] = T0

    # ---- prompt mode still prompts -----------------------------------------------------------
    for label, extra in (("prompt mode with a password left in the row", {"credential_mode": "prompt"}),
                         ("a row without a mode (as in 1.17.0)", {"credential_mode": None})):
        u_p, _ = await new_row("p-" + label[:6], **extra)
        attempts.clear()
        ws = await open_ws(bob, u_p)
        fr, _ = await frames(ws, {"auth_required", "connected", "error"})
        check(f"{label}: the prompt appears", [f.get("type") for f in fr][-1:] == ["auth_required"], str(fr))
        await ws.send_json({"type": "auth", "password": OTHER_PW})
        fr, _ = await frames(ws, {"connected", "error"})
        check(f"{label}: only what was typed is sent", attempts == [OTHER_PW], str(attempts))
        await ws.close()

    # ---- the host key rule ---------------------------------------------------------------------
    for label, extra, want in (("an unpinned key", {"host_key_fingerprint": None}, "host_key"),
                               ("a changed key", {"host_key_fingerprint": fp_b}, "host_key")):
        u_h, _ = await new_row("hk-" + label[3:8], **extra)
        attempts.clear()
        ws = await open_ws(bob, u_h)
        fr, _ = await frames(ws, {"host_key", "connected", "error"})
        hk = next((f for f in fr if f.get("type") == want), None)
        check(f"{label}: the grantee is refused and cannot accept it", hk is not None and hk.get("can_accept") is False, str(fr))
        check(f"{label}: the sshd saw no password at all", attempts == [], str(attempts))
        check(f"{label}: nothing in the frames carries the password", SSH_PW not in json.dumps(fr))
        await ws.close()
    u_i, _ = await new_row("hk-ignore", host_key_ignore=True, host_key_fingerprint=None)
    attempts.clear()
    ws = await open_ws(bob, u_i)
    fr, _ = await frames(ws, {"host_key", "connected", "error"})
    check("a row set to skip the host key check never gets the stored password",
          attempts == [] and any(f.get("type") == "error" for f in fr), f"{attempts} {fr}")
    await ws.close()

    # ---- SFTP uses the same credential under the same rules ---------------------------------
    u_s, _ = await new_row("sftp-ok")
    async with bob.get(f"{base}/api/sftp/{u_s}/list?path=/") as r:
        text = await r.text()
        check("grantee: the SFTP browser lists with the stored password", r.status == 200 and "marker.txt" in text, f"{r.status} {text[:200]}")
        check("grantee: the SFTP answer has no password", SSH_PW not in text)
    u_sp, _ = await new_row("sftp-prompt", credential_mode="prompt")
    attempts.clear()
    async with bob.get(f"{base}/api/sftp/{u_sp}/list?path=/") as r:
        text = await r.text()
        check("SFTP does not use a password of a connection set to prompt", r.status == 502 and attempts == [], f"{r.status} {attempts}")
    u_sl, _ = await new_row("sftp-legacy", typ="sftp", credential_mode=None)
    async with bob.get(f"{base}/api/sftp/{u_sl}/list?path=/") as r:
        check("a legacy sftp connection without a mode still lists", r.status == 200, str(r.status))
    for label, extra in (("an unpinned key", {"host_key_fingerprint": None}), ("a changed key", {"host_key_fingerprint": fp_b})):
        u_sh, _ = await new_row("sftp-" + label[3:8], **extra)
        attempts.clear()
        async with bob.get(f"{base}/api/sftp/{u_sh}/list?path=/") as r:
            text = await r.text()
            check(f"SFTP with {label}: refused with 409, no password sent, none in the answer",
                  r.status == 409 and attempts == [] and SSH_PW not in text, f"{r.status} {attempts}")
    u_si, _ = await new_row("sftp-ignore", host_key_ignore=True, host_key_fingerprint=None)
    attempts.clear()
    async with bob.get(f"{base}/api/sftp/{u_si}/list?path=/") as r:
        check("SFTP never sends a stored password to a host that skips the key check",
              r.status == 502 and attempts == [], f"{r.status} {attempts}")

    u_sn, _ = await new_row("sftp-ignore-nomode", typ="sftp", credential_mode=None, host_key_ignore=True, host_key_fingerprint=None)
    attempts.clear()
    async with bob.get(f"{base}/api/sftp/{u_sn}/list?path=/") as r:
        check("SFTP sends no password to a host that skips the key check, also when the row has no mode",
              r.status == 502 and attempts == [], f"{r.status} {attempts}")

    # ---- revoke closes the grantee's open SFTP connection ------------------------------------
    u_sr, id_sr = await new_row("sftp-revoke")
    tok = TokenPayload({"sub": str(gid), "scopes": ["services:read", "access:*"]})
    ssh_conn, sftp, err = await server._get_sftp_connection(FakeRequest(u_sr), tok)
    check("grantee holds an open SFTP session", err is None and sftp is not None, str(err))
    async with owner.delete(f"{base}/api/connections/{u_sr}/shares/{gid}") as r:
        pass
    await asyncio.sleep(0.5)
    try:
        await asyncio.wait_for(sftp.listdir("/"), 3)
        listed = True
    except Exception:
        listed = False
    check("revoking the share closes the grantee's SFTP connection", not listed)

    # ---- nothing leaked into a log line ----------------------------------------------------
    joined = "\n".join(cap.text)
    check("no log line holds a stored password", SSH_PW not in joined and OTHER_PW not in joined)

    sshd.close()
    await srv.close()
    for s in (owner, bob, adm, carol):
        await s.close()
    await db.close()
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
outbound_guard.report("test_sshpass")
if failures:
    print(f"\ntest_sshpass: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_sshpass: all checks passed")
