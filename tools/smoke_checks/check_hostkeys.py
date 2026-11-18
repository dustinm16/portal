"""Smoke check: SSH host-key pinning (trust on first use) for terminals, the
SFTP browser and VOD storage.

A throwaway sshd (asyncssh's own server, on 127.0.0.1, generated host key,
random password, chrooted SFTP) runs inside this module. The outbound host
policy blocks loopback for user connections, so it is not weakened: the HTTP
routes (create, edit, accept) run against the staged server with public
addresses, and the connect paths are driven in short-lived child processes
(ctx.run_py) that call the real WebSocket handlers, SFTP helper and VOD
connect directly with only their name lookup answered with 127.0.0.1. The
staged server itself keeps the policy.

Proves: first connect shows a fingerprint to the owner; after the host key is
regenerated the owner and a grantee are refused and the grantee gets no accept
button; neither a WebSocket message nor a grantee can pin a key; an explicit
opt-out connects; a pin cannot be overwritten by an edit and a changed host
clears it; no password reaches a host whose key was not accepted; VOD storage
pins on first use, then refuses and logs a changed key; admin services pin the
same way and only an admin accepts.
"""

import asyncio
import json
import secrets
import shutil
import tempfile

import asyncssh

OWNER = "smoke_hk_owner"
GRANTEE = "smoke_hk_grantee"
PASSWORD = "Smoke-Hostkey-Pw-1!"
GOOD_HOST = "93.184.216.34"      # literal public address: no DNS needed
SSH_PW = secrets.token_urlsafe(18)

attempts = []                    # every password the sshd was asked to check


class _Sshd(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        attempts.append(password)
        return password == SSH_PW


async def _session(process):
    process.stdout.write("hello from the test sshd\n")
    process.exit(0)


async def start_sshd(key, port, root):
    return await asyncssh.create_server(
        _Sshd, "127.0.0.1", port, server_host_keys=[key], process_factory=_session,
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))


SETUP = """
import asyncio, json
import database
from auth import create_user

JOB = json.loads(%(job)r)

async def main():
    await database.db.connect()
    db = database.db
    out = {}
    for name in (JOB["owner"], JOB["grantee"]):
        if not await db.get_user_by_username(name):
            await create_user(name, JOB["password"], is_admin=False)
    owner = await db.get_user_by_username(JOB["owner"])
    grantee = await db.get_user_by_username(JOB["grantee"])
    out["owner_id"], out["grantee_id"] = owner["id"], grantee["id"]
    base = {"username": "u", "auth_method": "password"}
    rows = {
        "shared": ("ssh", base),
        "ignore": ("ssh", {**base, "host_key_ignore": True}),
        "legacy": ("ssh", {**base, "known_hosts": "ignore"}),
        "sftp": ("sftp", {"username": "u", "password": JOB["ssh_pw"]}),
        "agent": ("ssh", {"username": "u", "auth_method": "agent"}),
        "keypath": ("ssh", {"username": "u", "auth_method": "key", "private_key_path": "/etc/hostname"}),
    }
    for name, (typ, cfg) in rows.items():
        out[name] = await db.create_user_connection(
            owner["id"], "hk-" + name, typ, "127.0.0.1", JOB["port"], json.dumps(cfg))
    cid = await db.get_user_connection_by_uuid(out["shared"], owner["id"])
    await db.add_connection_share(cid["id"], grantee["id"], owner["id"])
    sid = await db.get_user_connection_by_uuid(out["sftp"], owner["id"])
    await db.add_connection_share(sid["id"], grantee["id"], owner["id"])
    await db.save_vod_storage(
        owner["id"], host="127.0.0.1", port=JOB["port"], username="u", auth_method="password",
        remote_path="/", config=json.dumps({"password": JOB["ssh_pw"]}))
    await db.close()
    print("OUT=" + json.dumps(out))

asyncio.run(main())
"""

# One driver for every connect path. JOB["kind"]:
#   ws_user     real handle_user_connection_ws for a user connection
#   ws_service  real handle_relay_ws for an admin-defined service
#   sftp        real _get_sftp_connection (the SFTP browser's connect helper)
#   vod         real _connect_vod_sftp
#   vod_state   read the VOD storage pin and refused key
#   vod_refuse  record a refused key the way a refused transfer does
#   pin         read a connection's stored pin
DRIVER = """
import asyncio, json
from aiohttp import WSMessage, WSMsgType
import asyncssh
import database, host_check, hostkeys
import server, sftp_browser
from auth import TokenPayload
from plugins import load_builtin_plugins

load_builtin_plugins()
JOB = json.loads(%(job)r)

# Only this short-lived process answers name lookups with loopback so it can
# reach the test sshd; the staged server's own policy is untouched.
async def _loopback(host, port=0, **kw):
    return ["127.0.0.1"]
server.resolve_checked_host = _loopback
sftp_browser.resolve_checked_host = _loopback


# Record what every real connect site hands to asyncssh.connect.
CONNECTS = []
_real_connect = asyncssh.connect
def _spy(*a, **kw):
    CONNECTS.append({
        "client_keys_none": kw.get("client_keys", "unset") is None,
        "config": kw.get("config", "unset"), "agent_path": kw.get("agent_path", "unset"),
        "agent_forwarding": kw.get("agent_forwarding", "unset"), "gss_host": kw.get("gss_host", "unset"),
        "gss_kex": kw.get("gss_kex", "unset"), "gss_auth": kw.get("gss_auth", "unset"),
        "host_based_auth": kw.get("host_based_auth", "unset"),
        "client_host_keysign": kw.get("client_host_keysign", "unset"),
        "has_password": bool(kw.get("password")),
    })
    return _real_connect(*a, **kw)
asyncssh.connect = _spy


class FakeWS:
    def __init__(self, inbound):
        self.inbound, self.sent, self.out, self.closed, self.close_code = list(inbound), [], [], False, None

    async def send_json(self, d):
        self.sent.append(d)

    async def send_str(self, s):
        self.out.append(s)

    async def close(self, code=1000, message=b""):
        self.closed, self.close_code = True, code

    async def receive(self):
        if self.inbound:
            return WSMessage(WSMsgType.TEXT, json.dumps(self.inbound.pop(0)), None)
        await asyncio.sleep(60)

    def __aiter__(self):
        return self._forever()

    async def _forever(self):
        await asyncio.sleep(60)
        yield None


class FakeRequest:
    def __init__(self, conn_id):
        self.match_info = {"conn_id": conn_id}


def token(uid, scopes=()):
    return TokenPayload({"sub": str(uid), "scopes": list(scopes)})


async def main():
    await database.db.connect()
    out = {}
    kind = JOB["kind"]
    if kind in ("ws_user", "ws_service"):
        # a hostile client message first, then the password
        inbound = [{"type": "host_key_accept", "fingerprint": JOB.get("fp", "")},
                   {"type": "accept", "fingerprint": JOB.get("fp", "")},
                   {"type": "auth", "password": JOB["ssh_pw"]}]
        ws = FakeWS(inbound)
        if kind == "ws_user":
            await asyncio.wait_for(server.handle_user_connection_ws(
                ws, "/ws/user-connection/" + JOB["uuid"], token(JOB["uid"]), "127.0.0.1"), 30)
        else:
            await asyncio.wait_for(server.handle_relay_ws(
                ws, "/ws/terminal/" + str(JOB["service_id"]), token(JOB["uid"], ["*"]), "127.0.0.1"), 30)
        out = {"sent": ws.sent, "out": ws.out, "closed": ws.closed, "code": ws.close_code}
    elif kind == "sftp":
        conn, sftp, err = await server._get_sftp_connection(FakeRequest(JOB["uuid"]), token(JOB["uid"]))
        if err:
            out = {"status": err.status, "body": json.loads(err.text)}
        else:
            out = {"status": 200, "listing": sorted(await sftp.listdir("/"))}
            conn.close()
    elif kind == "vod":
        conn, sftp, err = await server._connect_vod_sftp(JOB["uid"])
        out = {"error": err}
        if conn:
            out["listing"] = sorted(await sftp.listdir("/"))
            conn.close()
        storage = await database.db.get_vod_storage(JOB["uid"])
        cfg = storage["config"]
        out["pin"] = cfg.get("host_key_fingerprint")
        out["refused"] = (cfg.get("host_key_refused") or {}).get("fingerprint")
        cur = await database.db.conn.execute(
            "SELECT action, detail FROM activity_log WHERE user_id = ? AND action LIKE 'vod_host_key%%' "
            "ORDER BY id", (JOB["uid"],))
        out["activity"] = [[r[0], r[1]] for r in await cur.fetchall()]
    elif kind == "vod_state":
        cfg = (await database.db.get_vod_storage(JOB["uid"]))["config"]
        out = {"pin": cfg.get("host_key_fingerprint"), "refused": (cfg.get("host_key_refused") or {}).get("fingerprint")}
    elif kind == "vod_refuse":
        storage = await database.db.get_vod_storage(JOB["uid"])
        await server._vod_note_host_key(JOB["uid"], storage, refused=JOB["fp"])
        cfg = (await database.db.get_vod_storage(JOB["uid"]))["config"]
        out = {"refused": (cfg.get("host_key_refused") or {}).get("fingerprint")}
    elif kind == "mint":
        c = await database.db.get_user_connection_by_uuid(JOB["uuid"], JOB["uid"])
        out = server._present_host_key({"fingerprint": JOB["fp"]}, "connection", c["id"], JOB["uid"],
                                       server._user_connection_ssh_target(c))
    elif kind == "no_validator":
        # a connect that finishes without the host-key validator being called
        class Fake:
            closed = False
            def close(self): self.closed = True
        fake = Fake()
        async def _dial(addrs, attempt, timeout):
            return fake
        hostkeys.try_each_address = _dial
        conn, sftp, err = await server._connect_vod_sftp(JOB["uid"])
        storage = await database.db.get_vod_storage(JOB["uid"])
        out = {"connected": bool(conn), "error": err, "closed": fake.closed,
               "pin": (storage["config"] or {}).get("host_key_fingerprint")}
    elif kind == "pin":
        c = await database.db.get_user_connection_by_uuid(JOB["uuid"], JOB["uid"])
        out = {"pin": c["config"].get("host_key_fingerprint"), "host": c["host"]}
    elif kind == "svcpin":
        svc = await database.db.get_service_by_id(JOB["service_id"])
        out = {"pin": (svc.get("config") or {}).get("host_key_fingerprint"), "host": svc["host"]}
    await database.db.close()
    if isinstance(out, dict):
        out["connects"] = CONNECTS
    print("OUT=" + json.dumps(out))

asyncio.run(main())
"""


def _parse(out):
    line = next((l for l in out.splitlines() if l.startswith("OUT=")), "")
    return json.loads(line[4:]) if line else None


async def drive(ctx, job):
    rc, out = await ctx.run_py((DRIVER if "kind" in job else SETUP) % {"job": json.dumps(job)}, timeout=90)
    res = _parse(out)
    if rc != 0 or res is None:
        return {"_failed": out.strip()[-600:]}
    return res


def host_key_msg(res):
    return next((m for m in res.get("sent", []) if m.get("type") == "host_key"), None)


def accept_body(msg, **over):
    """What the dialog sends: the fingerprint, host, port and token it was shown."""
    return {"fingerprint": msg["fingerprint"], "host": msg.get("host"), "port": msg.get("port"),
            "token": msg.get("accept_token"), **over}


def locked(connects):
    """Every asyncssh.connect a driver made carried the locked-down options."""
    return bool(connects) and all(
        c["client_keys_none"] and c["config"] == [] and c["agent_path"] is None
        and c["agent_forwarding"] is False and c["gss_host"] is None and c["gss_kex"] is False
        and c["gss_auth"] is False and c["host_based_auth"] is False
        and c["client_host_keysign"] is False for c in connects)


async def run(ctx):
    root = tempfile.mkdtemp(prefix="hk-sftp-")
    open(root + "/marker.txt", "w").write("x")
    key_a = asyncssh.generate_private_key("ssh-ed25519")
    key_b = asyncssh.generate_private_key("ssh-ed25519")
    fp_a, fp_b = key_a.get_fingerprint("sha256"), key_b.get_fingerprint("sha256")
    state = {"server": await start_sshd(key_a, 0, root)}
    port = state["server"].sockets[0].getsockname()[1]
    try:
        await _run(ctx, state, port, root, key_b, fp_a, fp_b)
    finally:
        state["server"].close()
        await state["server"].wait_closed()
        shutil.rmtree(root, ignore_errors=True)


async def _run(ctx, state, port, root, key_b, fp_a, fp_b):
    base = {"port": port, "ssh_pw": SSH_PW, "owner": OWNER, "grantee": GRANTEE, "password": PASSWORD}
    ids = await drive(ctx, base)
    ctx.ok("hostkeys: set up users, connections and VOD storage", "_failed" not in ids, str(ids)[:300])
    if "_failed" in ids:
        return
    oid, gid = ids["owner_id"], ids["grantee_id"]
    url = ctx.base_url

    async with ctx.http() as owner, ctx.http() as grantee, ctx.http() as admin:
        r1 = await ctx.login(owner, OWNER, PASSWORD)
        r2 = await ctx.login(grantee, GRANTEE, PASSWORD)
        ctx.ok("hostkeys: owner and grantee log in", r1.status == 200 and r2.status == 200,
               f"{r1.status} {r2.status}")
        has_admin = bool(ctx.admin_password)
        if has_admin:
            r3 = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
            has_admin = r3.status == 200

        # ---------------- pin storage rules, through the HTTP API ----------------
        forged = "SHA256:" + "F" * 43
        async with owner.post(f"{url}/api/connections", json={
            "name": "hk-api", "type": "ssh", "host": GOOD_HOST, "port": 22,
            "config": {"username": "u", "host_key_fingerprint": forged}}) as r:
            body = await r.json()
            api_id = body.get("id")
            ctx.ok("hostkeys: create ssh connection", r.status == 201 and bool(api_id), f"{r.status} {body}")

        async def get_cfg():
            async with owner.get(f"{url}/api/connections/{api_id}") as r:
                return (await r.json()).get("config", {})

        ctx.ok("hostkeys: a pin sent with a new connection is dropped",
               "host_key_fingerprint" not in await get_cfg(), "")

        async with owner.put(f"{url}/api/connections/{api_id}", json={
            "config": {"host_key_fingerprint": forged}}) as r:
            ctx.ok("hostkeys: an edit cannot set a pin", r.status == 200 and
                   "host_key_fingerprint" not in await get_cfg(), str(r.status))

        for bad in ("", "nonsense", "SHA256:short", "MD5:" + "a" * 43, None, 5):
            async with owner.post(f"{url}/api/connections/{api_id}/host-key/accept",
                                  json={"fingerprint": bad}) as r:
                if r.status != 400:
                    ctx.ok("hostkeys: accept rejects a malformed fingerprint", False, f"{bad!r}: {r.status}")
                    break
        else:
            ctx.ok("hostkeys: accept rejects a malformed fingerprint", True, "")

        # a prompt that no longer matches is refused (409) and pins nothing
        prompt = await drive(ctx, {"kind": "mint", "uuid": api_id, "uid": oid, "fp": fp_a})
        ctx.ok("hostkeys: a prompt carries host, port and a signed token",
               prompt.get("host") == GOOD_HOST and prompt.get("port") == 22
               and bool(prompt.get("accept_token")), str(prompt)[:200])
        stale = {
            "another host": accept_body(prompt, host="93.184.216.99"),
            "another port": accept_body(prompt, port=2222),
            "another fingerprint": accept_body(prompt, fingerprint=fp_b),
            "no token": accept_body(prompt, token=None),
            "a forged token": accept_body(prompt, token="9999999999." + "0" * 64),
        }
        for label, body in stale.items():
            async with owner.post(f"{url}/api/connections/{api_id}/host-key/accept", json=body) as r:
                res_body = await r.json()
                ctx.ok(f"hostkeys: accept is refused for {label}",
                       r.status == 409 and res_body.get("type") == "host_key_stale", f"{r.status} {res_body}")
        for label, body in {"no host": accept_body(prompt, host=None), "no port": accept_body(prompt, port=None),
                            "a text port": accept_body(prompt, port="22")}.items():
            async with owner.post(f"{url}/api/connections/{api_id}/host-key/accept", json=body) as r:
                ctx.ok(f"hostkeys: accept needs a valid host and port ({label})", r.status == 400, str(r.status))
        ctx.ok("hostkeys: none of the refused accepts pinned anything",
               "host_key_fingerprint" not in await get_cfg(), "")
        # the connection is retargeted while the dialog is open
        async with owner.put(f"{url}/api/connections/{api_id}", json={"host": "93.184.216.36"}) as r:
            ctx.ok("hostkeys: connection retargeted", r.status == 200, str(r.status))
        async with owner.post(f"{url}/api/connections/{api_id}/host-key/accept", json=accept_body(prompt)) as r:
            ctx.ok("hostkeys: an old dialog cannot pin a key onto the new host",
                   r.status == 409 and "host_key_fingerprint" not in await get_cfg(), str(r.status))
        async with owner.put(f"{url}/api/connections/{api_id}", json={"host": GOOD_HOST}) as r:
            ctx.ok("hostkeys: connection moved back", r.status == 200, str(r.status))
        prompt = await drive(ctx, {"kind": "mint", "uuid": api_id, "uid": oid, "fp": fp_a})
        async with owner.post(f"{url}/api/connections/{api_id}/host-key/accept", json=accept_body(prompt)) as r:
            ctx.ok("hostkeys: owner accepts a fingerprint", r.status == 200, str(r.status))
        ctx.ok("hostkeys: the pin is shown on the connection",
               (await get_cfg()).get("host_key_fingerprint") == fp_a, "")

        async with owner.put(f"{url}/api/connections/{api_id}", json={
            "name": "hk-api2", "config": {"host_key_fingerprint": forged, "username": "u2"}}) as r:
            cfg = await get_cfg()
            ctx.ok("hostkeys: an edit cannot overwrite the pin", r.status == 200
                   and cfg.get("host_key_fingerprint") == fp_a and cfg.get("username") == "u2",
                   f"{r.status} {cfg}")
        async with owner.put(f"{url}/api/connections/{api_id}", json={"config": {}}) as r:
            ctx.ok("hostkeys: an edit that omits the pin keeps it",
                   (await get_cfg()).get("host_key_fingerprint") == fp_a, "")
        async with owner.put(f"{url}/api/connections/{api_id}", json={
            "config": {"host_key_ignore": "yes"}}) as r:
            ctx.ok("hostkeys: the opt-out must be a boolean", r.status == 400, str(r.status))
        # a config sent as a JSON string would replace the whole stored config
        # and slip past the pin rules: it is refused on update and on create
        async with owner.put(f"{url}/api/connections/{api_id}", json={
            "config": json.dumps({"username": "u", "host_key_fingerprint": forged})}) as r:
            ctx.ok("hostkeys: a string config is refused on update and cannot set a pin",
                   r.status == 400 and (await get_cfg()).get("host_key_fingerprint") == fp_a,
                   str(r.status))
        async with owner.post(f"{url}/api/connections", json={
            "name": "hk-str", "type": "ssh", "host": GOOD_HOST, "port": 22,
            "config": json.dumps({"username": "u", "host_key_fingerprint": forged})}) as r:
            ctx.ok("hostkeys: a string config is refused on create", r.status == 400, str(r.status))
        async with owner.put(f"{url}/api/connections/{api_id}", json={"port": 2222}) as r:
            ctx.ok("hostkeys: changing the port clears the pin", r.status == 200
                   and "host_key_fingerprint" not in await get_cfg(), str(r.status))
        prompt = await drive(ctx, {"kind": "mint", "uuid": api_id, "uid": oid, "fp": fp_a})
        await owner.post(f"{url}/api/connections/{api_id}/host-key/accept", json=accept_body(prompt))
        async with owner.put(f"{url}/api/connections/{api_id}", json={"host": "93.184.216.35"}) as r:
            ctx.ok("hostkeys: changing the host clears the pin", r.status == 200
                   and "host_key_fingerprint" not in await get_cfg(), str(r.status))
        async with owner.put(f"{url}/api/connections/{api_id}", json={"config": {"host_key_ignore": True}}) as r:
            ctx.ok("hostkeys: owner can set the explicit opt-out", r.status == 200
                   and (await get_cfg()).get("host_key_ignore") is True, str(r.status))

        async with ctx.http() as anon:
            async with anon.post(f"{url}/api/connections/{api_id}/host-key/accept",
                                 json={"fingerprint": fp_a}) as r:
                ctx.ok("hostkeys: accept needs authentication", r.status in (401, 403), str(r.status))

        # ---------------- terminal: first connect, accept, regenerated key ----------------
        shared = ids["shared"]
        before = len(attempts)
        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": oid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_a})
        msg = owner_msg = host_key_msg(res)
        ctx.ok("hostkeys: first connect shows the owner the fingerprint",
               bool(msg) and msg["state"] == "unpinned" and msg["fingerprint"] == fp_a
               and msg["can_accept"] is True and msg.get("accept_url") == f"/api/connections/{shared}/host-key/accept"
               and msg.get("algorithm") == "ssh-ed25519"
               and msg.get("host") == "127.0.0.1" and msg.get("port") == port and bool(msg.get("accept_token")),
               str(res)[:300])
        ctx.ok("hostkeys: the terminal connects with locked-down client options",
               locked(res.get("connects", [])), str(res.get("connects"))[:300])
        ctx.ok("hostkeys: no password reaches an unverified host", len(attempts) == before, str(attempts))

        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": gid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_a})
        msg = host_key_msg(res)
        ctx.ok("hostkeys: a grantee is refused an unpinned host with no accept button",
               bool(msg) and msg["state"] == "unpinned" and msg["can_accept"] is False
               and "accept_url" not in msg and "owner" in msg["message"]
               and "accept_token" not in msg, str(res)[:300])

        pin = await drive(ctx, {"kind": "pin", "uuid": shared, "uid": oid})
        ctx.ok("hostkeys: websocket messages (including accept attempts) pin nothing",
               pin.get("pin") is None, str(pin))

        async with grantee.post(f"{url}/api/connections/{shared}/host-key/accept",
                                json={"fingerprint": fp_a}) as r:
            ctx.ok("hostkeys: a grantee cannot accept through the API", r.status == 404, str(r.status))
        pin = await drive(ctx, {"kind": "pin", "uuid": shared, "uid": oid})
        ctx.ok("hostkeys: the grantee's attempt pinned nothing", pin.get("pin") is None, str(pin))

        async with grantee.post(f"{url}/api/connections/{shared}/host-key/accept",
                                json=accept_body(owner_msg)) as r:
            ctx.ok("hostkeys: a grantee cannot replay the owner's prompt", r.status == 404, str(r.status))
        async with owner.post(f"{url}/api/connections/{shared}/host-key/accept",
                              json=accept_body(owner_msg, port=port + 1)) as r:
            ctx.ok("hostkeys: the owner's accept with a wrong port is refused", r.status == 409, str(r.status))
        async with owner.post(f"{url}/api/connections/{ids['sftp']}/host-key/accept",
                              json=accept_body(owner_msg)) as r:
            ctx.ok("hostkeys: a prompt for one connection cannot pin another", r.status == 409, str(r.status))
        async with owner.post(f"{url}/api/connections/{shared}/host-key/accept",
                              json=accept_body(owner_msg)) as r:
            ctx.ok("hostkeys: the owner accepts the key through the API", r.status == 200, str(r.status))

        before = len(attempts)
        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": oid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_a})
        ctx.ok("hostkeys: the owner connects once the key is accepted",
               any(m.get("type") == "connected" for m in res.get("sent", []))
               and any("hello from the test sshd" in o for o in res.get("out", [])) and len(attempts) == before + 1,
               str(res)[:300])
        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": gid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_a})
        ctx.ok("hostkeys: a grantee connects to a connection its owner has pinned",
               any(m.get("type") == "connected" for m in res.get("sent", [])), str(res)[:300])

        # SFTP browser, pinned
        res = sftp_owner = await drive(ctx, {"kind": "sftp", "uuid": ids["sftp"], "uid": oid, "port": port})
        ctx.ok("hostkeys: sftp browser refuses an unpinned host for the owner (409, accept offered)",
               res.get("status") == 409 and res["body"].get("state") == "unpinned"
               and res["body"].get("fingerprint") == fp_a and res["body"].get("can_accept") is True
               and res["body"].get("host") == "127.0.0.1" and res["body"].get("port") == port
               and bool(res["body"].get("accept_token")), str(res)[:300])
        res = await drive(ctx, {"kind": "sftp", "uuid": ids["sftp"], "uid": gid, "port": port})
        ctx.ok("hostkeys: sftp browser refuses an unpinned host for a grantee (no accept)",
               res.get("status") == 409 and res["body"].get("can_accept") is False
               and "accept_url" not in res["body"], str(res)[:300])
        async with owner.post(f"{url}/api/connections/{ids['sftp']}/host-key/accept",
                              json=accept_body(sftp_owner["body"], fingerprint=fp_b)) as r:
            ctx.ok("hostkeys: an sftp accept with another fingerprint than the one shown is refused",
                   r.status == 409, str(r.status))
        async with owner.post(f"{url}/api/connections/{ids['sftp']}/host-key/accept",
                              json=accept_body(sftp_owner["body"])) as r:
            ctx.ok("hostkeys: owner accepts the sftp connection's key", r.status == 200, str(r.status))
        res = await drive(ctx, {"kind": "sftp", "uuid": ids["sftp"], "uid": gid, "port": port})
        ctx.ok("hostkeys: sftp browser connects with a pinned key",
               res.get("status") == 200 and "marker.txt" in res.get("listing", []), str(res)[:300])
        ctx.ok("hostkeys: the sftp browser connects with locked-down client options",
               locked(res.get("connects", [])), str(res.get("connects"))[:300])

        # VOD storage: a connect that never showed its key to the validator is refused
        res = await drive(ctx, {"kind": "no_validator", "uid": oid, "port": port})
        ctx.ok("hostkeys: a connect that skipped the host-key check is closed and refused, nothing pinned",
               res.get("connected") is False and res.get("closed") is True and res.get("pin") is None
               and bool(res.get("error")), str(res)[:300])

        # VOD storage: pinned automatically on the first connect
        res = await drive(ctx, {"kind": "vod", "uid": oid, "port": port})
        ctx.ok("hostkeys: VOD storage connects and pins the key on first use",
               res.get("error") is None and res.get("pin") == fp_a and "marker.txt" in res.get("listing", [])
               and [a for a, _ in res.get("activity", [])] == ["vod_host_key_pinned"], str(res)[:300])
        ctx.ok("hostkeys: VOD storage connects with locked-down client options",
               locked(res.get("connects", [])), str(res.get("connects"))[:300])
        async with owner.get(f"{url}/api/vods/storage") as r:
            body = (await r.json()).get("storage") or {}
            ctx.ok("hostkeys: the VOD storage settings show the pinned fingerprint",
                   body.get("host_key_fingerprint") == fp_a and body.get("host_key_refused") is None
                   and "config" not in body, str(body)[:300])

        # Admin-defined service
        svc_id = None
        if has_admin:
            async with admin.post(f"{url}/api/services", json={
                "name": "hk-ssh-svc", "path": "/hk-ssh", "plugin": "ssh", "host": "127.0.0.1", "port": port,
                "config": {"username": "u", "auth_method": "password", "known_hosts": "ignore",
                           "host_key_fingerprint": "SHA256:" + "A" * 43}}) as r:
                body = await r.json()
                svc_id = body.get("id")
                ctx.ok("hostkeys: admin creates an ssh service with a pre-filled fingerprint",
                       r.status == 201 and bool(svc_id), f"{r.status} {body}")
            res = await drive(ctx, {"kind": "ws_service", "service_id": svc_id, "uid": 1, "port": port,
                                    "ssh_pw": SSH_PW})
            msg = svc_msg = host_key_msg(res)
            ctx.ok("hostkeys: a pre-filled fingerprint that does not match is refused as changed",
                   bool(msg) and msg["state"] == "changed" and msg["expected"] == "SHA256:" + "A" * 43
                   and msg["fingerprint"] == fp_a and msg["can_accept"] is True
                   and msg.get("accept_url") == f"/api/services/{svc_id}/host-key/accept"
                   and msg.get("host") == "127.0.0.1" and msg.get("port") == port
                   and bool(msg.get("accept_token")), str(res)[:300])
            async with grantee.post(f"{url}/api/services/{svc_id}/host-key/accept",
                                    json=accept_body(svc_msg)) as r:
                ctx.ok("hostkeys: a non-admin cannot accept a service's key", r.status == 403, str(r.status))
            for label, body in {"another host": accept_body(svc_msg, host="93.184.216.99"),
                                "another port": accept_body(svc_msg, port=port + 1),
                                "another fingerprint": accept_body(svc_msg, fingerprint=fp_b),
                                "no token": accept_body(svc_msg, token=None)}.items():
                async with admin.post(f"{url}/api/services/{svc_id}/host-key/accept", json=body) as r:
                    res_body = await r.json()
                    ctx.ok(f"hostkeys: a service accept is refused for {label}",
                           r.status == 409 and res_body.get("type") == "host_key_stale", f"{r.status} {res_body}")
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc_id})
            ctx.ok("hostkeys: the refused service accepts pinned nothing",
                   pin.get("pin") == "SHA256:" + "A" * 43, str(pin))
            async with admin.post(f"{url}/api/services/{svc_id}/host-key/accept", json=accept_body(svc_msg)) as r:
                ctx.ok("hostkeys: an admin accepts a service's key", r.status == 200, str(r.status))
            res = await drive(ctx, {"kind": "ws_service", "service_id": svc_id, "uid": 1, "port": port,
                                    "ssh_pw": SSH_PW})
            ctx.ok("hostkeys: the service connects once accepted",
                   any(m.get("type") == "connected" for m in res.get("sent", [])), str(res)[:300])
            async with admin.put(f"{url}/api/services/{svc_id}", json={
                "config": {"username": "u", "auth_method": "password"}}) as r:
                ctx.ok("hostkeys: editing a service keeps its pin", r.status == 200, str(r.status))
            res = await drive(ctx, {"kind": "ws_service", "service_id": svc_id, "uid": 1, "port": port,
                                    "ssh_pw": SSH_PW})
            ctx.ok("hostkeys: the service still connects after an edit",
                   any(m.get("type") == "connected" for m in res.get("sent", [])), str(res)[:300])
            # moving a service to another host or port drops its pin even when
            # the edit carries no config
            async with admin.post(f"{url}/api/services", json={
                "name": "hk-ssh-svc2", "path": "/hk-ssh2", "plugin": "ssh", "host": "127.0.0.1", "port": port,
                "config": {"username": "u", "auth_method": "password",
                           "host_key_fingerprint": fp_a}}) as r:
                svc2 = (await r.json()).get("id")
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc2})
            ctx.ok("hostkeys: a second service starts with its pre-filled pin", pin.get("pin") == fp_a, str(pin))
            async with admin.put(f"{url}/api/services/{svc2}", json={"host": GOOD_HOST}) as r:
                status = r.status
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc2})
            ctx.ok("hostkeys: changing a service's host without a config clears the pin",
                   status == 200 and pin.get("pin") is None and pin.get("host") == GOOD_HOST,
                   f"{status} {pin}")
            # the ssh plugin dials config.host / config.port when set: a config-only
            # edit that moves them drops the pin, an edit that keeps them does not
            async with admin.post(f"{url}/api/services", json={
                "name": "hk-ssh-svc3", "path": "/hk-ssh3", "plugin": "ssh", "host": "127.0.0.1", "port": port,
                "config": {"username": "u", "auth_method": "password", "host": GOOD_HOST, "port": "22",
                           "host_key_fingerprint": fp_a}}) as r:
                svc3 = (await r.json()).get("id")
            async with admin.put(f"{url}/api/services/{svc3}", json={"config": {
                    "username": "u2", "auth_method": "password", "host": GOOD_HOST, "port": 22}}) as r:
                status = r.status
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc3})
            ctx.ok("hostkeys: a config edit that keeps the dialled host and port keeps the pin",
                   status == 200 and pin.get("pin") == fp_a, f"{status} {pin}")
            async with admin.put(f"{url}/api/services/{svc3}", json={"config": {
                    "username": "u2", "auth_method": "password", "host": GOOD_HOST, "port": 2222}}) as r:
                status = r.status
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc3})
            ctx.ok("hostkeys: a config-only change of the dialled port clears the pin",
                   status == 200 and pin.get("pin") is None, f"{status} {pin}")
            async with admin.post(f"{url}/api/services", json={
                "name": "hk-ssh-svc4", "path": "/hk-ssh4", "plugin": "ssh", "host": "127.0.0.1", "port": port,
                "config": {"username": "u", "auth_method": "password", "host_key_fingerprint": fp_a}}) as r:
                svc4 = (await r.json()).get("id")
            async with admin.put(f"{url}/api/services/{svc4}", json={"config": {
                    "username": "u", "auth_method": "password", "host": "93.184.216.35"}}) as r:
                status = r.status
            pin = await drive(ctx, {"kind": "svcpin", "service_id": svc4})
            ctx.ok("hostkeys: a config-only change of the dialled host clears the pin",
                   status == 200 and pin.get("pin") is None, f"{status} {pin}")
        else:
            ctx.skip("hostkeys: admin service checks", "no admin password available")

        # ---------------- the server's host key is regenerated ----------------
        state["server"].close()
        await state["server"].wait_closed()
        state["server"] = await start_sshd(key_b, port, root)
        before = len(attempts)

        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": oid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_b})
        msg = owner_changed = host_key_msg(res)
        ctx.ok("hostkeys: after the key changed the owner is refused with a 'host key changed' message",
               bool(msg) and msg["state"] == "changed" and msg["expected"] == fp_a and msg["fingerprint"] == fp_b
               and msg["can_accept"] is True and "Host key changed" in msg["message"]
               and not any(m.get("type") == "connected" for m in res["sent"]), str(res)[:300])
        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": gid, "port": port,
                                "ssh_pw": SSH_PW, "fp": fp_b})
        msg = host_key_msg(res)
        ctx.ok("hostkeys: after the key changed a grantee is refused and has no accept button",
               bool(msg) and msg["state"] == "changed" and msg["can_accept"] is False
               and "accept_url" not in msg and "Host key changed" in msg["message"], str(res)[:300])
        ctx.ok("hostkeys: no password reaches a host whose key changed", len(attempts) == before, str(attempts))
        async with grantee.post(f"{url}/api/connections/{shared}/host-key/accept",
                                json={"fingerprint": fp_b}) as r:
            ctx.ok("hostkeys: a grantee cannot re-accept a changed key", r.status == 404, str(r.status))
        pin = await drive(ctx, {"kind": "pin", "uuid": shared, "uid": oid})
        ctx.ok("hostkeys: the old pin is still in place", pin.get("pin") == fp_a, str(pin))

        res = await drive(ctx, {"kind": "sftp", "uuid": ids["sftp"], "uid": oid, "port": port})
        ctx.ok("hostkeys: sftp browser refuses a changed key",
               res.get("status") == 409 and res["body"].get("state") == "changed"
               and res["body"].get("expected") == fp_a, str(res)[:300])
        res = await drive(ctx, {"kind": "sftp", "uuid": ids["sftp"], "uid": gid, "port": port})
        ctx.ok("hostkeys: sftp browser gives a grantee no accept button for a changed key",
               res.get("status") == 409 and res["body"].get("can_accept") is False, str(res)[:300])

        # explicit opt-out and the legacy setting
        res = await drive(ctx, {"kind": "ws_user", "uuid": ids["ignore"], "uid": oid, "port": port,
                                "ssh_pw": SSH_PW})
        ctx.ok("hostkeys: an 'ignore' connection still connects, with locked-down client options",
               any(m.get("type") == "connected" for m in res.get("sent", []))
               and locked(res.get("connects", [])), str(res)[:300])
        for name, needle in (("agent", "agent authentication is not supported"), ("keypath", "Key file paths")):
            before = len(attempts)
            res = await drive(ctx, {"kind": "ws_user", "uuid": ids[name], "uid": oid, "port": port,
                                    "ssh_pw": SSH_PW})
            ctx.ok(f"hostkeys: a user connection with '{name}' auth is refused before any connect",
                   any(needle in m.get("message", "") for m in res.get("sent", []))
                   and not res.get("connects") and len(attempts) == before, str(res)[:300])
        res = await drive(ctx, {"kind": "ws_user", "uuid": ids["legacy"], "uid": oid, "port": port,
                                "ssh_pw": SSH_PW})
        ctx.ok("hostkeys: the old 'known_hosts: ignore' setting no longer skips the check",
               (host_key_msg(res) or {}).get("state") == "unpinned", str(res)[:300])

        if svc_id:
            res = await drive(ctx, {"kind": "ws_service", "service_id": svc_id, "uid": 1, "port": port,
                                    "ssh_pw": SSH_PW})
            msg = host_key_msg(res)
            ctx.ok("hostkeys: an admin service refuses a changed key; an admin may accept",
                   bool(msg) and msg["state"] == "changed" and msg["can_accept"] is True, str(res)[:300])

        # VOD: refused and logged
        before = len(attempts)
        res = await drive(ctx, {"kind": "vod", "uid": oid, "port": port})
        acts = res.get("activity", [])
        ctx.ok("hostkeys: VOD storage refuses a changed key and logs it",
               bool(res.get("error")) and "Host key changed" in res["error"] and res.get("pin") == fp_a
               and res.get("refused") == fp_b and "vod_host_key_refused" in [a for a, _ in acts]
               and len(attempts) == before, str(res)[:400])
        async with owner.get(f"{url}/api/vods/storage") as r:
            body = (await r.json()).get("storage") or {}
            ctx.ok("hostkeys: the VOD settings show the refused key",
                   (body.get("host_key_refused") or {}).get("fingerprint") == fp_b
                   and body.get("host_key_fingerprint") == fp_a, str(body)[:300])
        async with owner.post(f"{url}/api/vods/storage/host-key/accept", json={"fingerprint": "bad"}) as r:
            ctx.ok("hostkeys: VOD accept rejects a malformed fingerprint", r.status == 400, str(r.status))
        async with owner.post(f"{url}/api/vods/storage/host-key/accept", json={"fingerprint": fp_a}) as r:
            res_body = await r.json()
            ctx.ok("hostkeys: VOD accept refuses a fingerprint other than the refused one that was shown (409)",
                   r.status == 409 and res_body.get("type") == "host_key_stale", f"{r.status} {res_body}")
        async with owner.post(f"{url}/api/vods/storage/host-key/accept",
                              json={"fingerprint": "SHA256:" + "C" * 43}) as r:
            ctx.ok("hostkeys: VOD accept refuses a well-formed fingerprint nobody was shown (409)",
                   r.status == 409, str(r.status))
        res = await drive(ctx, {"kind": "vod_state", "uid": oid})
        ctx.ok("hostkeys: the refused VOD accepts changed nothing",
               res.get("pin") == fp_a and res.get("refused") == fp_b, str(res)[:300])
        async with owner.post(f"{url}/api/vods/storage/host-key/accept", json={"fingerprint": fp_b}) as r:
            ctx.ok("hostkeys: the owner accepts the new VOD storage key", r.status == 200, str(r.status))
        async with owner.post(f"{url}/api/vods/storage/host-key/accept", json={"fingerprint": fp_b}) as r:
            ctx.ok("hostkeys: VOD accept with no refused key stored is refused (409)", r.status == 409, str(r.status))
        res = await drive(ctx, {"kind": "vod", "uid": oid, "port": port})
        ctx.ok("hostkeys: VOD storage connects with the accepted key",
               res.get("error") is None and res.get("pin") == fp_b and res.get("refused") is None, str(res)[:300])

        # owner accepts the regenerated key on the shared connection
        async with owner.post(f"{url}/api/connections/{shared}/host-key/accept",
                              json=accept_body(owner_changed)) as r:
            ctx.ok("hostkeys: the owner re-accepts a changed key", r.status == 200, str(r.status))
        res = await drive(ctx, {"kind": "ws_user", "uuid": shared, "uid": gid, "port": port, "ssh_pw": SSH_PW})
        ctx.ok("hostkeys: a grantee connects again after the owner re-accepted",
               any(m.get("type") == "connected" for m in res.get("sent", [])), str(res)[:300])

        # VOD settings: edits keep the pin and the stored password; a new target drops the pin
        vod = {"host": GOOD_HOST, "port": 22, "username": "u", "remote_path": "/v",
               "auth_method": "password", "password": "secret-1"}
        async with owner.post(f"{url}/api/vods/storage", json=vod) as r:
            ctx.ok("hostkeys: VOD storage saved for a new host", r.status == 200, str(r.status))
        # a transfer to the new host refuses its key (recorded by the real helper), then the owner accepts it
        res = await drive(ctx, {"kind": "vod_refuse", "uid": oid, "fp": fp_a})
        ctx.ok("hostkeys: a refused key is recorded for the new host", res.get("refused") == fp_a, str(res)[:300])
        async with owner.post(f"{url}/api/vods/storage/host-key/accept", json={"fingerprint": fp_a}) as r:
            ctx.ok("hostkeys: VOD key accepted for the new host", r.status == 200, str(r.status))
        async with owner.post(f"{url}/api/vods/storage", json={
                **vod, "password": "***", "remote_path": "/v2", "host_key_ignore": False}) as r:
            ctx.ok("hostkeys: VOD storage edit with the stored password kept works", r.status == 200, str(r.status))
        async with owner.get(f"{url}/api/vods/storage") as r:
            body = (await r.json()).get("storage") or {}
            ctx.ok("hostkeys: a VOD edit that keeps the host keeps the pin",
                   body.get("host_key_fingerprint") == fp_a and body.get("has_password") is True
                   and body.get("host_key_ignore") is False, str(body)[:300])
        async with owner.post(f"{url}/api/vods/storage", json={
                **vod, "password": "***", "host": "93.184.216.35", "host_key_ignore": True}) as r:
            ctx.ok("hostkeys: VOD edit to another host accepted", r.status == 200, str(r.status))
        async with owner.get(f"{url}/api/vods/storage") as r:
            body = (await r.json()).get("storage") or {}
            ctx.ok("hostkeys: a VOD edit to another host drops the pin and keeps the opt-out",
                   body.get("host_key_fingerprint") is None and body.get("host_key_ignore") is True,
                   str(body)[:300])
