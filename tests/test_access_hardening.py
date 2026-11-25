"""Small hardening of release 1.24.1, one section each: sign-in failures counted per exact address (rotating through an IPv6 /64 is not limited), 6to4 and Teredo
addresses are not exempt from automatic blocks, a push device on a token with no expiry goes stale, the stored
password of a SPICE or Proxmox connection does not follow a change of type or host, the API key buttons carry no
inline handler, a hook with allow_private cannot reach this host's own services unless listed, and the
MediaMTX plugin tells the viewer no address.

Run: venv/bin/python tests/test_access_hardening.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402

failures = []
ROOT = Path(__file__).resolve().parent.parent


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def section_login_counting():
    banned = []

    async def fake_ban(ip, kind, base_seconds, reason, details=None):
        banned.append(ip)
        return "later"

    async def not_known(canon):
        return False
    saved = (server._escalating_ban, server._login_address_known, dict(server._login_ban_cfg))
    server._escalating_ban, server._login_address_known = fake_ban, not_known
    server._login_ban_cfg.update({"enabled": True, "max_failures": 5, "find_minutes": 10, "base_minutes": 15})
    try:
        server._login_fails.clear()
        net = "2a00:1450:4001:828"
        for i in range(1, 6):
            await server._count_login_failure(f"{net}::{i:x}")           # five different addresses of one /64
        check("one failure from each of five addresses of one IPv6 /64 bans nobody (counted per address)", not banned, str(banned))
        banned.clear()
        server._login_fails.clear()
        for i in range(1, 16):                                           # 3 x max_failures addresses, one /64
            await server._count_login_failure(f"{net}::{i:x}")
        check("rotating through 3 x max_failures addresses of one /64 is not limited, and the notes say so", not banned, str(banned))
        for _ in range(5):
            await server._count_login_failure(f"{net}::99")              # five from one address
        check("five failures from one IPv6 address still ban that address", banned == [f"{net}::99"], str(banned))
        banned.clear()
        server._login_fails.clear()
        for i in range(1, 5):
            await server._count_login_failure(f"2a00:1450:4001:{i:x}::1")   # four different /64s
        check("failures from different /64s do not count together", not banned and len(server._login_fails) == 4, str(banned))
        server._login_fails.clear()
        for i in range(1, 5):
            await server._count_login_failure(f"93.184.216.{i}")
        check("IPv4 addresses are still counted one by one", not banned and len(server._login_fails) == 4)
        server._login_fails.clear()
        await server._count_login_failure(f"{net}::9")
        check("the count is kept under the exact address", list(server._login_fails) == [f"{net}::9"], str(list(server._login_fails)))
    finally:
        server._escalating_ban, server._login_address_known = saved[0], saved[1]
        server._login_ban_cfg.clear()
        server._login_ban_cfg.update(saved[2])
        server._login_fails.clear()


def section_tunnels():
    r = server._never_ban_reason
    check("a 6to4 address is not exempt from automatic blocks", r("2002:5db8:d801::1") is None, str(r("2002:5db8:d801::1")))
    check("a Teredo address is not exempt", r("2001:0:4136:e378:8000:63bf:3fff:fdd2") is None)
    check("private, loopback and link-local addresses still are",
          all(r(a) for a in ("10.1.2.3", "192.168.1.1", "127.0.0.1", "::1", "fd00::5", "fe80::1", "172.16.0.9")))
    check("the documentation range stays exempt (not routable)", r("2001:db8::1") is not None)
    check("an ordinary public address is not exempt", r("2a00:1450:4001:828::200e") is None and r("93.184.216.34") is None)
    check("Cloudflare's addresses are exempt as before", r("2606:4700::1") is not None and r("104.16.0.1") is not None)


async def section_push():
    from datetime import datetime, timedelta, timezone
    from auth import create_user
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    u = await create_user("pushuser", "Pass-12345-xyz!", is_admin=False)
    uid = u["id"]
    now = datetime.now(timezone.utc)
    await db.create_token(uid, "t-forever", ["*"], expires_at=None)
    await db.create_token(uid, "t-later", ["*"], expires_at=now + timedelta(days=5))
    await db.create_token(uid, "t-over", ["*"], expires_at=now - timedelta(days=1))
    rows = {}
    for label, token in (("never_old", "t-forever"), ("never_new", "t-forever"), ("later_old", "t-later"), ("over_old", "t-over")):
        res = await db.add_push_subscription(uid, f"https://push.example.test/{label}", "p", "a", "ua", token, 50)
        assert res == "created", (label, res)
        rows[label] = f"https://push.example.test/{label}"
    old = (now - timedelta(days=40)).strftime("%Y-%m-%d %H:%M:%S")
    for label in ("never_old", "later_old", "over_old"):
        await db.conn.execute("UPDATE push_subscriptions SET announced_at = ?, created_at = ? WHERE endpoint = ?", (old, old, rows[label]))
    await db.conn.commit()
    sendable = {r["endpoint"] for r in await db.push_subscriptions_for_send(uid)}
    check("a device on a never-expiring session not announced for 30 days gets nothing",
          rows["never_old"] not in sendable, str(sendable))
    check("a device on a never-expiring session announced lately still gets pushes", rows["never_new"] in sendable)
    check("a device on a session that expires later is kept however old", rows["later_old"] in sendable)
    check("a device on an expired session is stale as before", rows["over_old"] not in sendable)
    n = await db._delete_stale_push_subscriptions()
    await db.conn.commit()
    left = {r["endpoint"] for r in await db.list_push_subscriptions(uid)}
    check("the cleanup deletes the two stale devices and keeps the others", n == 2 and left == {rows["never_new"], rows["later_old"]}, f"{n} {left}")
    await db.close()


async def section_own_password():
    import json
    from types import SimpleNamespace
    from auth import create_user
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    u = await create_user("pwowner", "Pass-12345-xyz!", is_admin=False)
    uid = u["id"]
    saved = (server._connection_user_auth, server._user_targets_allowed)

    async def fake_auth(request):
        return SimpleNamespace(user_id=uid, jti="sess"), None

    async def allowed(*a, **k):
        return True
    server._connection_user_auth, server._user_targets_allowed = fake_auth, allowed

    async def new_row(name, typ, host="198.51.100.7"):
        uuid = await db.create_user_connection(uid, name, typ, host, 8006, json.dumps({"username": "root", "password": "OldSecret"}))
        return uuid

    async def put(uuid, body):
        async def get_json():
            return body
        req = SimpleNamespace(match_info={"id": uuid}, json=get_json)
        resp = await server.http_update_user_connection(req)
        return resp.status, json.loads(resp.body)

    async def stored(uuid):
        return (await db.get_user_connection_by_uuid(uuid, uid))["config"]
    try:
        for typ in ("proxmox", "spice"):
            a = await new_row(f"{typ}-host", typ)
            st, body = await put(a, {"host": "203.0.113.9"})
            check(f"{typ}: a new host clears the stored password", st == 200 and "password" not in await stored(a), f"{st} {body}")
            check(f"{typ}: the answer says the stored password was cleared", body.get("stored_password_cleared") is True, str(body))
            b = await new_row(f"{typ}-host-again", typ)
            st, _ = await put(b, {"host": "203.0.113.9", "config": {"username": "root", "password": "NewSecret"}})
            check(f"{typ}: a password sent with the new host is kept", (await stored(b)).get("password") == "NewSecret", str(st))
            c = await new_row(f"{typ}-type", typ)
            st, _ = await put(c, {"type": "vnc" if typ == "spice" else "spice"})
            check(f"{typ}: a new type clears the stored password", st == 200 and "password" not in await stored(c), str(st))
            d = await new_row(f"{typ}-rename", typ)
            st, body = await put(d, {"name": f"{typ}-renamed", "config": {"username": "root2"}})
            cfg = await stored(d)
            check(f"{typ}: an edit that moves nothing keeps the password", cfg.get("password") == "OldSecret" and cfg.get("username") == "root2"
                  and "stored_password_cleared" not in body, f"{st} {cfg} {body}")
            e = await new_row(f"{typ}-same-host", typ)
            st, _ = await put(e, {"host": "198.51.100.7", "type": typ})
            check(f"{typ}: naming the same host and type keeps the password", (await stored(e)).get("password") == "OldSecret", str(st))
        # Proxmox also stores an API token, which the plugin sends as a header to the configured host
        async def token_row(name, with_password=False):
            cfg = {"api_token": "root@pam!t=TokenSecret"}
            if with_password:
                cfg.update(username="root", password="OldSecret")
            return await db.create_user_connection(uid, name, "proxmox", "198.51.100.7", 8006, json.dumps(cfg))
        for label, body in (("host", {"host": "203.0.113.9"}), ("port", {"port": 9006}), ("type", {"type": "spice"})):
            r = await token_row(f"tok-{label}")
            st, resp = await put(r, body)
            check(f"proxmox: a new {label} clears the stored API token", st == 200 and "api_token" not in await stored(r), f"{st} {await stored(r)}")
            check(f"proxmox: the answer says so when only a token was stored ({label})", resp.get("stored_password_cleared") is True, str(resp))
        r = await token_row("tok-new")
        st, resp = await put(r, {"host": "203.0.113.9", "config": {"api_token": "root@pam!t2=NewSecret"}})
        check("proxmox: an API token sent with the new host is kept", (await stored(r)).get("api_token") == "root@pam!t2=NewSecret"
              and "stored_password_cleared" not in resp, f"{st} {await stored(r)} {resp}")
        r = await token_row("tok-both", with_password=True)
        st, resp = await put(r, {"host": "203.0.113.9", "config": {"username": "root", "password": "NewSecret"}})
        cfg = await stored(r)
        check("proxmox: a new password does not keep the old API token", st == 200 and cfg.get("password") == "NewSecret"
              and "api_token" not in cfg and resp.get("stored_password_cleared") is True, f"{st} {cfg} {resp}")
        r = await token_row("tok-rename", with_password=True)
        st, resp = await put(r, {"name": "tok-renamed", "config": {"username": "root2"}})
        cfg = await stored(r)
        check("proxmox: an edit that moves nothing keeps the API token", cfg.get("api_token") == "root@pam!t=TokenSecret"
              and cfg.get("password") == "OldSecret" and "stored_password_cleared" not in resp, f"{st} {cfg} {resp}")
    finally:
        server._connection_user_auth, server._user_targets_allowed = saved
        await db.close()


def section_api_key_buttons():
    import json
    import re
    import subprocess
    js = (ROOT / "static" / "js" / "user-connections.js").read_text()
    index = (ROOT / "static" / "index.html").read_text()
    check("the API key buttons have no inline handler", "onclick=\"confirmRevokeApiKey" not in js and "onclick=\"confirmDeleteApiKey" not in js)
    check("the page loads user-connections.js at the version after 61", "user-connections.js?v=62" in index)
    m = re.search(r"function renderApiKeys\(\) \{.*?\n\}\n", js, re.S)
    check("renderApiKeys is present", m is not None)
    if not m:
        return
    evil = "k'\\\"><img src=x onerror=alert(1)>\\'"
    script = """
let apiKeys = [{id: 7, name: %s, key_prefix: 'portal_ab', scopes: '*', revoked: false, created_at: null}];
const els = {};
let handler = null;
const calls = [];
function mk() { return {style: {}, dataset: {}, innerHTML: '', addEventListener: (t, f) => { handler = f; }, contains: () => true}; }
els['api-keys-table'] = mk(); els['api-keys-tbody'] = mk(); els['api-keys-empty'] = mk();
global.document = {getElementById: (id) => els[id]};
function escapeHtml(t) { const d = String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); return d; }
function formatDate(x) { return String(x); }
function confirmRevokeApiKey(id, name) { calls.push(['revoke', id, name]); }
function confirmDeleteApiKey(id, name) { calls.push(['delete', id, name]); }
""" % json.dumps(evil) + m.group(0) + """
renderApiKeys();
renderApiKeys();
const html = els['api-keys-tbody'].innerHTML;
const mkBtn = (action) => ({dataset: {apiKeyAction: action, apiKeyId: '7'}});
handler({target: {closest: () => mkBtn('revoke')}});
handler({target: {closest: () => mkBtn('delete')}});
handler({target: {closest: () => null}});
console.log(JSON.stringify({html, calls, listeners: els['api-keys-tbody'].dataset.keyActions}));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), r.stderr[-300:])
    if got:
        check("the row markup has no onclick and the key name only as escaped text", "onclick" not in got["html"] and "<img" not in got["html"] and got["html"].count("&lt;img") == 1, got["html"][:300])
        check("the buttons carry the key id and an action", 'data-api-key-id="7"' in got["html"] and 'data-api-key-action="revoke"' in got["html"] and 'data-api-key-action="delete"' in got["html"])
        check("a click confirms with the stored name unchanged, revoke and delete alike",
              got["calls"] == [["revoke", 7, evil], ["delete", 7, evil]], str(got["calls"]))
        check("a second render does not add a second listener", got["listeners"] == "1")


async def section_mediamtx_text():
    import logging
    from plugins.mediamtx import MediaMTXPlugin
    plugin = MediaMTXPlugin()
    sent = []

    class FakeWs:
        async def send_json(self, obj):
            sent.append(obj)

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    async def failing(api_url, timeout, session=None):
        raise ConnectionError("Cannot connect to host 10.9.8.7:9997 ssl:default [Connection refused]")
    plugin._get_streams = failing
    logged = []

    class Cap(logging.Handler):
        def emit(self, record):
            logged.append(record.getMessage())
    handler = Cap()
    logging.getLogger().addHandler(handler)
    try:
        await plugin._session_loop(FakeWs(), None, "http://10.9.8.7:9997", "http://10.9.8.7:8889", "", [], 5, 1)
    finally:
        logging.getLogger().removeHandler(handler)
    check("the viewer's socket is told a fixed sentence", sent == [{"type": "error", "message": "Failed to connect to MediaMTX"}], str(sent))
    check("the viewer's socket gets no host or port", "10.9.8.7" not in str(sent) and "9997" not in str(sent))
    check("the detail is in the log", any("10.9.8.7:9997" in m for m in logged), str(logged))


async def section_local_services():
    import json
    import subprocess
    from config import Config
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    child = subprocess.Popen(
        [sys.executable, "-I", "-c",
         "import socket,sys,time\ns=socket.socket();s.bind(('127.0.0.1',0));s.listen(1)\n"
         "print(s.getsockname()[1],flush=True)\ntime.sleep(60)"],
        stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        server._own_endpoints_cache = (0.0, frozenset(), frozenset())
        Config.WEBHOOK_LOCAL_ALLOW = ""
        own_port = Config.PORT
        v = server._validate_webhook_url
        r = await v(f"http://127.0.0.1:{port}/hook", True)
        check("a hook with allow_private cannot be saved for a service the portal started on loopback", r == "URL points at the portal itself", str(r))
        eps = await server._own_endpoints_async()
        check("the connector's check refuses it too", server._own_endpoint_blocked("127.0.0.1", port, eps))
        check("the same port on another address is not refused", not server._own_endpoint_blocked("10.9.9.9", port, eps))
        check("another loopback port nobody listens on is not refused", not server._own_endpoint_blocked("127.0.0.1", port + 1 if port < 65000 else port - 1, eps))
        Config.WEBHOOK_LOCAL_ALLOW = f"10.1.1.1:{port} [::1]:{port}"
        check("an entry for another address does not let it through", server._own_endpoint_blocked("127.0.0.1", port, eps))
        Config.WEBHOOK_LOCAL_ALLOW = f"nonsense, 127.0.0.1:x 127.0.0.1:{port}"
        check("an entry that is listed lets the destination through (bad entries are ignored)",
              await v(f"http://127.0.0.1:{port}/hook", True) is None and not server._own_endpoint_blocked("127.0.0.1", port, eps))
        Config.WEBHOOK_LOCAL_ALLOW = f"127.0.0.1:{own_port}"
        check("the portal's own port is refused even when it is listed",
              server._own_endpoint_blocked("127.0.0.1", own_port, (frozenset({("0.0.0.0", own_port)}), frozenset())))
        Config.WEBHOOK_LOCAL_ALLOW = ""
        # a managed service row: its configured ports are refused although nothing is running
        await db.create_service("media", "/media", plugin="mediamtx", host="127.0.0.1", port=19997,
                                config={"api_port": 19998}, service_type="managed", ports=[19996])
        eps = await server._own_endpoints_async()
        check("the ports a managed service row names are refused on loopback, running or not",
              server._own_endpoint_blocked("127.0.0.1", 19997, eps) and server._own_endpoint_blocked("127.0.0.1", 19998, eps)
              and server._own_endpoint_blocked("127.0.0.1", 19996, eps)
              and await v("http://127.0.0.1:19998/x", True) == "URL points at the portal itself")
        check("a port no service names stays reachable", await v("http://127.0.0.1:19999/x", True) is None)
        Config.WEBHOOK_LOCAL_ALLOW = "127.0.0.1:19998"
        check("a configured port can be listed too", await v("http://127.0.0.1:19998/x", True) is None)
        check("without allow_private nothing changes (loopback is refused anyway)", await v("http://127.0.0.1:19999/x", False) is not None)
    finally:
        Config.WEBHOOK_LOCAL_ALLOW = ""
        child.kill()
        child.wait(10)
        server._managed_service_ports = frozenset()
        await db.close()


async def main():
    await section_push()
    await section_own_password()
    section_tunnels()
    section_api_key_buttons()
    await section_login_counting()
    await section_mediamtx_text()
    await section_local_services()


try:
    asyncio.run(asyncio.wait_for(main(), 120))
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
