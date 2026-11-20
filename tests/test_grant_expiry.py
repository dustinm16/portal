"""Expiring connection shares and service grants.

Run: venv/bin/python tests/test_grant_expiry.py

The real app runs on a loopback test server against a temporary database. Time is moved with
grant_expiry.set_clock (the one clock behind the "is this row live" predicate). The terminal
plugin is a fake that holds the socket open, so what is proven here is that the portal closes
the grantee's socket; no SSH target is involved.
"""

import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import grant_expiry  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
from auth import TokenPayload, create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []
PW = "Expiry-pass-12345!"


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


T0 = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
clock = {"now": T0}
grant_expiry.set_clock(lambda: clock["now"])


def advance(**kw):
    clock["now"] = clock["now"] + timedelta(**kw)


class HoldPlugin:
    """A plugin that keeps the socket open until the client or the portal closes it."""

    async def handle_websocket(self, ws, target, user_id):
        await ws.send_json({"type": "ready"})
        async for _ in ws:
            pass


async def login(base, name):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with s.post(base + "/login", json={"username": name, "password": PW}) as r:
        assert r.status == 200, (name, r.status)
    return s


async def open_ws(s, base, uuid):
    ws = await s.ws_connect(base.replace("http", "ws") + f"/ws/terminal/{uuid}")
    msg = await asyncio.wait_for(ws.receive(), 3)
    return ws, msg


async def close_code(ws, wait=3.0):
    """The close code the portal ended the socket with, or None if it is still open."""
    try:
        while True:
            msg = await asyncio.wait_for(ws.receive(), wait)
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                return msg.data if msg.type == aiohttp.WSMsgType.CLOSE else ws.close_code
    except asyncio.TimeoutError:
        return None


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
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
    server.get_plugin = lambda name: HoldPlugin()

    cuuid = await db.create_user_connection(uid["owner"], "box", "ssh", "93.184.216.34", 22, "{}")
    cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (cuuid,))).fetchone())["id"]
    owner, bob, carol, adm = [await login(base, n) for n in ("owner", "bob", "carol", "adm")]
    share_url = f"{base}/api/connections/{cuuid}/shares"

    async def row(table, **where):
        cur = await db.conn.execute(
            f"SELECT * FROM {table} WHERE " + " AND ".join(f"{k} = ?" for k in where), tuple(where.values()))
        return await cur.fetchone()

    async def audits(prefix):
        out = [e for e in await db.get_audit_log(limit=200) if (e["action"] or "").startswith(prefix)]
        for e in out:
            if isinstance(e["details"], str):
                e["details"] = json.loads(e["details"])
        return out

    # ---- the duration is an allow-list the server turns into a timestamp --------------------
    for bad in ("2h", "", 3600, True, ["1h"], "NEVER", "1h; DROP"):
        async with owner.post(share_url, json={"usernames": ["bob"], "expires_in": bad}) as r:
            check(f"share with duration {bad!r} answers 400", r.status == 400, str(r.status))
    async with owner.post(share_url, json={"usernames": ["bob"], "expires_at": "2099-01-01 00:00:00"}) as r:
        check("a client-sent timestamp answers 400", r.status == 400, str(r.status))
    check("no row was written by the refused requests", await row("connection_shares", connection_id=cid) is None)

    async with owner.post(share_url, json={"usernames": ["bob"]}) as r:
        body = await r.json()
        check("a share without a duration is accepted and never expires (API default)",
              r.status == 200 and body["shares"][0]["expires_at"] is None and body["shares"][0]["expires_in"] is None,
              str(body))
    check("NULL stored for 'never'", (await row("connection_shares", connection_id=cid))["expires_at"] is None)
    advance(days=400)
    async with bob.get(f"{base}/api/connections/{cuuid}") as r:
        check("a share with NULL expiry still opens after 400 days (as before)", r.status == 200, str(r.status))
    advance(days=-400)

    # ---- a 1 h share is listed with its remaining time ---------------------------------------
    async with owner.post(share_url, json={"usernames": ["bob"], "expires_in": "1h"}) as r:
        body = await r.json()
        sh = body["shares"][0]
        check("re-sharing replaces the expiry (never -> 1h)", sh["expires_in"] == 3600 and sh["expires_at"] == "2030-01-01T13:00:00Z", str(sh))
        check("the share list names the grantor and the creation time",
              sh["granted_by_username"] == "owner" and sh["created_at"], str(sh))
    async with bob.get(f"{base}/api/connections") as r:
        mine = [c for c in (await r.json())["connections"] if c["id"] == cuuid]
        check("the grantee sees the shared connection with its remaining time",
              len(mine) == 1 and mine[0]["share_expires_in"] == 3600 and mine[0]["shared"] == 1, str(mine))
    async with owner.get(f"{base}/api/me/shares") as r:
        mine = (await r.json())["shares"]
        check("the owner's 'all shares' view shows grantee, grantor, created and expiry",
              len(mine) == 1 and mine[0]["username"] == "bob" and mine[0]["granted_by_username"] == "owner"
              and mine[0]["expires_in"] == 3600 and mine[0]["created_at"] and mine[0]["connection_name"] == "box", str(mine))
    async with adm.get(f"{base}/api/admin/grants") as r:
        allg = await r.json()
        check("the admin 'all grants' view lists the share", r.status == 200 and len(allg["connection_shares"]) == 1
              and allg["connection_shares"][0]["owner_username"] == "owner", str(allg))
    async with bob.get(f"{base}/api/admin/grants") as r:
        check("the admin 'all grants' view is closed to members", r.status == 403, str(r.status))

    # ---- an open terminal ends with the share ------------------------------------------------
    ws_term, first = await open_ws(bob, base, cuuid)
    check("the grantee opens the shared terminal", first.type == aiohttp.WSMsgType.TEXT and "ready" in first.data, str(first))
    ws_other = await bob.ws_connect(base.replace("http", "ws") + "/ws")
    await asyncio.wait_for(ws_other.receive(), 3)

    advance(minutes=59, seconds=59)
    async with bob.get(f"{base}/api/connections/{cuuid}") as r:
        check("one second before the expiry the share still works", r.status == 200, str(r.status))
    advance(seconds=1)
    async with bob.get(f"{base}/api/connections/{cuuid}") as r:
        check("at the expiry the grantee cannot open the connection by UUID (no sweeper involved)", r.status == 404, str(r.status))
    async with bob.get(f"{base}/api/connections") as r:
        check("at the expiry the grantee's list no longer has it",
              all(c["id"] != cuuid for c in (await r.json())["connections"]))
    async with bob.get(f"{base}/api/connections/{cuuid}/connect") as r:
        check("at the expiry the connect route refuses", r.status == 404, str(r.status))
    async with bob.get(f"{base}/api/sftp/{cuuid}/list?path=/") as r:
        check("at the expiry the SFTP route refuses", r.status == 404, str(r.status))
    ws2 = await bob.ws_connect(base.replace("http", "ws") + f"/ws/terminal/{cuuid}")
    seen = await asyncio.wait_for(ws2.receive(), 3)
    check("at the expiry a new terminal socket is refused",
          seen.type == aiohttp.WSMsgType.TEXT and "not found" in seen.data.lower() and await close_code(ws2) == 4004, str(seen))
    async with owner.get(f"{base}/api/connections/{cuuid}/shares") as r:
        check("at the expiry the owner's share list no longer shows it", (await r.json())["shares"] == [])
    async with owner.get(f"{base}/api/me/shares") as r:
        check("at the expiry the owner's all-shares view no longer shows it", (await r.json())["shares"] == [])
    async with adm.get(f"{base}/api/admin/grants") as r:
        check("at the expiry the admin view no longer shows it", (await r.json())["connection_shares"] == [])
    async with owner.get(f"{base}/api/connections/{cuuid}") as r:
        check("the owner is not affected", r.status == 200, str(r.status))
    check("the row is still there before the sweep", await row("connection_shares", connection_id=cid) is not None)
    check("the open terminal is not yet closed (the sweeper closes it)", await close_code(ws_term, 0.4) is None)

    n = await server.sweep_expired_grants_once()
    check("the sweep removed the one expired share", n == 1 and await row("connection_shares", connection_id=cid) is None, str(n))
    cc = await close_code(ws_term)
    check("the sweep closed the open terminal with the access-ended code", cc == server.GRANT_ENDED_CLOSE_CODE, str(cc))
    ent = await audits("connection.share_expired")
    check("the sweep wrote one audit entry for it",
          len(ent) == 1 and ent[0]["target_id"] == cid and ent[0]["details"]["grantee"] == "bob"
          and ent[0]["actor_username"] == "owner", str(ent))
    advance(seconds=1)
    await ws_other.send_json({"type": "ping"})
    msg = await asyncio.wait_for(ws_other.receive(), 3)
    check("the grantee's other sockets (a plain /ws) are left alone", msg.type == aiohttp.WSMsgType.TEXT and "pong" in msg.data, str(msg))
    await ws_other.close()
    check("a second sweep finds nothing", await server.sweep_expired_grants_once() == 0)

    # ---- manual revoke closes the socket too (it did not before) ---------------------------------
    async with owner.post(share_url, json={"usernames": ["bob", "carol"], "expires_in": "7d"}) as r:
        check("re-share to two users with 7d", r.status == 200)
    ws_b, _ = await open_ws(bob, base, cuuid)
    ws_c, _ = await open_ws(carol, base, cuuid)
    async with owner.delete(f"{share_url}/{uid['bob']}") as r:
        check("owner revokes bob", r.status == 200)
    check("revoking a share closes the grantee's open terminal", await close_code(ws_b) == server.GRANT_ENDED_CLOSE_CODE)
    check("revoking one grantee leaves the other grantee's terminal open", await close_code(ws_c, 0.4) is None)
    async with carol.delete(f"{share_url}/me") as r:
        check("a grantee leaves a share (me)", r.status == 200)
    check("leaving a share closes the leaver's open terminal", await close_code(ws_c) == server.GRANT_ENDED_CLOSE_CODE)

    # ---- the owner deleting the connection closes what the grantee holds -------------------------
    async with owner.post(share_url, json={"usernames": ["bob"], "expires_in": "30d"}) as r:
        check("share for the delete case", r.status == 200)
    ws_d, _ = await open_ws(bob, base, cuuid)
    async with owner.delete(f"{base}/api/connections/{cuuid}") as r:
        check("owner deletes the connection", r.status == 200)
    check("deleting the connection closes the grantee's open terminal", await close_code(ws_d) == server.GRANT_ENDED_CLOSE_CODE)

    # ---- re-sharing changes the end time only, not the grantor or the creation time ------------------
    cuuid5 = await db.create_user_connection(uid["owner"], "box5", "ssh", "93.184.216.34", 22, "{}")
    cid5 = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid=?", (cuuid5,))).fetchone())["id"]
    await db.add_connection_share(cid5, uid["bob"], uid["owner"], "1h")
    before = await row("connection_shares", connection_id=cid5)
    advance(minutes=5)
    await db.add_connection_share(cid5, uid["bob"], uid["carol"], "7d")
    after = await row("connection_shares", connection_id=cid5)
    check("re-sharing keeps the grantor and the creation time and replaces the end time",
          after["granted_by"] == uid["owner"] and after["created_at"] == before["created_at"]
          and after["expires_at"] != before["expires_at"])

    # ---- SSH connections and proxied calls opened through a share end with it ---------------------------
    from aiohttp.test_utils import make_mocked_request

    class FakeSsh:
        closed = 0

        def close(self):
            self.closed += 1

    class FakeTransport:
        aborted = False

        def abort(self):
            self.aborted = True

    class FakeRequest:
        transport = FakeTransport()

    fake_ssh = FakeSsh()

    async def connect_sftp(connection):
        return fake_ssh, object(), None

    real_connect = server.sftp_browser.connect_sftp
    server.sftp_browser.connect_sftp = connect_sftp
    cuuid4 = await db.create_user_connection(uid["owner"], "box4", "ssh", "93.184.216.34", 22, "{}")
    cid4 = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid=?", (cuuid4,))).fetchone())["id"]
    await db.add_connection_share(cid4, uid["bob"], uid["owner"], "1d")
    btok2 = TokenPayload({"sub": str(uid["bob"]), "jti": "t2", "scopes": ["*"], "iat": 0})
    req = make_mocked_request("GET", "/api/sftp/x/list", match_info={"conn_id": cuuid4})
    ssh, sftp, err = await server._get_sftp_connection(req, btok2)
    check("an SFTP connection through a live share is handed out", ssh is fake_ssh and err is None)
    call = server._ProxyHttpCall(FakeRequest())
    conn4 = await db.get_accessible_connection(cuuid4, uid["bob"])
    check("a proxied call through a live share is tracked", await server._track_shared_access(conn4, uid["bob"], call))
    async with owner.delete(f"{base}/api/connections/{cuuid4}/shares/{uid['bob']}") as r:
        check("owner revokes the share the SFTP connection and the call hang on", r.status == 200)
    check("revoking closed the SSH connection opened through the share", fake_ssh.closed == 1, str(fake_ssh.closed))
    check("revoking aborted the proxied call opened through the share", call.aborted and FakeRequest.transport.aborted)
    check("a connection looked up before a revoke that lands before registration is refused",
          not await server._track_shared_access(conn4, uid["bob"], server._ProxyHttpCall(FakeRequest())))
    ssh2, _, err2 = await server._get_sftp_connection(req, btok2)
    check("a new SFTP connection after the revoke is refused", ssh2 is None and err2.status == 404)
    server.sftp_browser.connect_sftp = real_connect
    owner_tok = TokenPayload({"sub": str(uid["owner"]), "jti": "t3", "scopes": ["*"], "iat": 0})
    check("the owner's own access is not tracked and not closed",
          await server._track_shared_access(await db.get_accessible_connection(cuuid4, uid["owner"]), uid["owner"], FakeSsh())
          and not [k for k in server._grant_dependents if k[2] == uid["owner"]])

    # ---- a renewal between the read and the delete is not swept ------------------------------------
    cuuid2 = await db.create_user_connection(uid["owner"], "box2", "ssh", "93.184.216.34", 22, "{}")
    cid2 = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (cuuid2,))).fetchone())["id"]
    await db.add_connection_share(cid2, uid["bob"], uid["owner"], "1h")
    advance(hours=2)
    await db.add_connection_share(cid2, uid["bob"], uid["owner"], "1d")   # renewed after the time passed
    check("a renewed share is live again", await db.get_accessible_connection(cuuid2, uid["bob"]) is not None)
    check("the sweep leaves a renewed share", await server.sweep_expired_grants_once() == 0
          and await row("connection_shares", connection_id=cid2) is not None)

    # ---- service grants ----------------------------------------------------------------------------
    sid = await db.create_service("mgd", "/mgd", plugin="mediamtx", service_type="managed")
    grant_url = f"{base}/api/managed-services/{sid}/grants"
    async with adm.post(grant_url, json={"usernames": ["bob"], "actions": ["control", "files"], "expires_in": "forever"}) as r:
        check("a grant with an unknown duration answers 400", r.status == 400, str(r.status))
    check("... and wrote nothing", await row("service_grants", service_id=sid) is None)
    async with adm.post(grant_url, json={"usernames": ["bob"], "actions": ["control", "files"], "expires_in": "8h"}) as r:
        body = await r.json()
        g = body["grants"][0]
        check("a grant with 8h lists its remaining time, grantor and creation",
              g["expires_in"] == 8 * 3600 and g["granted_by_username"] == "adm" and g["created_at"], str(body))
    btok = TokenPayload({"sub": str(uid["bob"]), "jti": "t", "scopes": ["read"], "iat": 0})
    check("the grant gives control", await db.user_service_grant(uid["bob"], sid) == {"control", "files"})
    check("_can_control_service honours the live grant", await server._can_control_service(btok, sid, "control"))
    check("the grant is in the granted-services set", sid in await db.get_user_granted_service_ids(uid["bob"]))
    async with adm.get(f"{base}/api/admin/grants") as r:
        sg = (await r.json())["service_grants"]
        check("the admin view lists the service grant with grantor and expiry",
              len(sg) == 1 and sg[0]["service_name"] == "mgd" and sg[0]["granted_by_username"] == "adm"
              and sg[0]["expires_in"] == 8 * 3600, str(sg))
    advance(hours=8)
    check("at the expiry user_service_grant is None", await db.user_service_grant(uid["bob"], sid) is None)
    check("at the expiry _can_control_service refuses", not await server._can_control_service(btok, sid, "control"))
    check("at the expiry the files path (_gs_access) refuses",
          not await server._gs_access(btok, {"service_id": sid}, "files"))
    check("at the expiry the granted-services set is empty", await db.get_user_granted_service_ids(uid["bob"]) == {})
    check("at the expiry the grant list is empty", await db.list_service_grants(sid) == [])
    check("the grant row is still there before the sweep", await row("service_grants", service_id=sid) is not None)
    check("the sweep deletes the grant", await server.sweep_expired_grants_once() == 1
          and await row("service_grants", service_id=sid) is None)
    ent = await audits("service.grant_expired")
    check("the sweep audits the grant", len(ent) == 1 and ent[0]["target_id"] == sid and ent[0]["details"]["grantee"] == "bob", str(ent))
    # a grant with no expiry is unchanged by time
    async with adm.post(grant_url, json={"usernames": ["bob"], "actions": ["logs"]}) as r:
        check("a grant without a duration never expires (API default)", (await r.json())["grants"][0]["expires_at"] is None)
    advance(days=900)
    check("... and still works 900 days on", await db.user_service_grant(uid["bob"], sid) == {"logs"})
    async with adm.post(grant_url, json={"usernames": ["bob"], "actions": ["logs"], "expires_in": "90d"}) as r:
        check("re-granting replaces the expiry", (await r.json())["grants"][0]["expires_in"] == 90 * 86400)
    async with adm.delete(f"{grant_url}/{uid['bob']}") as r:
        check("revoking a grant works", r.status == 200)

    # ---- every duration of the allow-list ------------------------------------------------------------
    want = {"1h": 3600, "8h": 8 * 3600, "1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "never": None}
    for key, secs in want.items():
        got = grant_expiry.describe(grant_expiry.expires_at_for(key))["expires_in"]
        check(f"duration {key} -> {secs}", got == secs, str(got))
    check("the allow-list is exactly the seven documented values", set(grant_expiry.DURATIONS) == set(want))

    # ---- the shared lists of a grantee: owner's own rows are not filtered ------------------------------
    cuuid3 = await db.create_user_connection(uid["owner"], "box3", "ssh", "93.184.216.34", 22, "{}")
    await db.add_connection_share((await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid=?", (cuuid3,))).fetchone())["id"], uid["bob"], uid["owner"], "1h")
    check("typed list of a grantee has the live share", any(c["uuid"] == cuuid3 for c in await db.get_user_connections_by_type(uid["bob"], "ssh")))
    advance(hours=1)
    check("typed list of a grantee drops the expired share", all(c["uuid"] != cuuid3 for c in await db.get_user_connections_by_type(uid["bob"], "ssh")))
    check("the owner still lists their own connection", any(c["uuid"] == cuuid3 for c in await db.get_user_connections(uid["owner"])))

    for s in (owner, bob, carol, adm):
        await s.close()
    await srv.close()
    await db.conn.close()


async def migration_check():
    """The new column is added to a database that has the old tables, rows keep NULL and stay
    live, and running the migrations again changes nothing."""
    from database import Database
    tmp = tempfile.mkdtemp()
    d = Database(str(Path(tmp) / "m.db"))
    await d.connect()
    u1 = await d.create_user("m1", "x")
    u2 = await d.create_user("m2", "x")
    cuuid = await d.create_user_connection(u1, "c", "ssh", "93.184.216.34", 22, "{}")
    cid = (await (await d.conn.execute("SELECT id FROM user_connections WHERE uuid=?", (cuuid,))).fetchone())["id"]
    # back to the 1.17.0 shape: no column, no index
    for idx in ("idx_conn_shares_expires", "idx_service_grants_expires"):
        await d.conn.execute(f"DROP INDEX IF EXISTS {idx}")
    await d.conn.execute("ALTER TABLE connection_shares DROP COLUMN expires_at")
    await d.conn.execute("ALTER TABLE service_grants DROP COLUMN expires_at")
    await d.conn.execute("INSERT INTO connection_shares (connection_id, grantee_user_id, granted_by) VALUES (?, ?, ?)", (cid, u2, u1))
    await d.conn.commit()
    await d._run_migrations()
    await d._run_migrations()
    cols = [r["name"] for r in await (await d.conn.execute("PRAGMA table_info(connection_shares)")).fetchall()]
    cols2 = [r["name"] for r in await (await d.conn.execute("PRAGMA table_info(service_grants)")).fetchall()]
    check("migration adds expires_at to both tables, once", cols.count("expires_at") == 1 and cols2.count("expires_at") == 1)
    check("an old share row is live with NULL expiry", (await d.get_accessible_connection(cuuid, u2)) is not None
          and (await (await d.conn.execute("SELECT expires_at FROM connection_shares")).fetchone())["expires_at"] is None)
    await d.conn.close()


asyncio.run(main())
asyncio.run(migration_check())
if failures:
    print(f"\ntest_grant_expiry: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_grant_expiry: all checks passed")
