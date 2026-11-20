"""Expiring connection shares and service grants on a running instance, over real HTTP and
real WebSockets (the real VPN-bridge plugin in SOCKS mode: it holds the socket open and dials
nothing, so no network target is needed).

The staged server is restarted once with a 2 second expiry sweep (PORTAL_GRANT_SWEEP_SECONDS,
honoured only in staged mode; the real interval is 60 seconds) and again at the end without it.

Proves: an unknown duration and a client-sent timestamp are refused with 400; a share made for
1 hour is listed to the grantee, the owner and an admin with its time left; after the expiry
(shortened in the database to a few seconds) the grantee no longer sees the connection, cannot
open it by UUID, and the terminal-class socket that was open is closed with code 4010; the row is
deleted and one audit entry written; a share with no duration never expires (still opens after
the sweeper has run several times); revoking a share closes the open socket too; a service grant
shows in /api/me for the grantee until it expires and then not, and the service routes refuse
him; re-sharing replaces the expiry.

Users, the connection and the service carry random suffixes and every assertion is about those
rows, so the module also holds on a stage started from a copy of the production database. It
makes its own admin user and needs no admin password.

Not proven here: a real SSH session being closed (the VPN bridge stands in for it), the pages in
a browser, anything behind Cloudflare.
"""

import asyncio
import json
import secrets
import sqlite3

import aiohttp

PW = "Expiry-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "grantee", "adm"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.set_user_role(out["users"]["adm"], "admin")
    out["uuid"] = await db.create_user_connection(out["users"]["owner"], P["pre"] + "-conn", "vpn_tunnel",
                                                  "93.184.216.34", 1080, "{}")
    out["service"] = await db.create_service(P["pre"] + "-svc", "/" + P["pre"] + "svc", plugin="mediamtx",
                                             service_type="managed")
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    rnd = secrets.token_hex(3)
    pre = "ex" + rnd
    db_path = ctx.stage_dir / "portal.db"
    env_path = ctx.stage_dir / ".env"
    original_env = env_path.read_text()

    def ok(name, passed, detail=""):
        ctx.ok("expiry: " + name, bool(passed), "" if passed else str(detail)[:300])

    def sql(query, args=()):
        con = sqlite3.connect(str(db_path), timeout=15)
        try:
            cur = con.execute(query, args)
            rows = cur.fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})})
    data = _result(out)
    if rc != 0 or data is None:
        ok("setup", False, out[-500:])
        return
    users, uuid, sid = data["users"], data["uuid"], data["service"]
    cid = sql("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))[0][0]

    # a fast sweeper for this module only
    env_path.write_text(original_env.rstrip("\n") + "\nPORTAL_GRANT_SWEEP_SECONDS=2\n")
    await ctx.stop_server()
    await ctx.start_server()
    try:
        async with ctx.http() as owner, ctx.http() as grantee, ctx.http() as adm:
            for sess, name in ((owner, "owner"), (grantee, "grantee"), (adm, "adm")):
                r = await ctx.login(sess, pre + name, PW)
                if r.status != 200:
                    ok(f"{name} logs in", False, r.status)
                    return
            base = ctx.base_url
            share_url = f"{base}/api/connections/{uuid}/shares"
            ws_url = base.replace("http", "ws", 1) + f"/ws/user-connection/{uuid}"

            async def jget(sess, path):
                async with sess.get(base + path) as r:
                    try:
                        return r.status, await r.json()
                    except Exception:
                        return r.status, None

            async def jsend(sess, method, url, **kw):
                async with sess.request(method, url, **kw) as r:
                    try:
                        return r.status, await r.json()
                    except Exception:
                        return r.status, None

            async def open_ws():
                ws = await grantee.ws_connect(ws_url)
                msg = await asyncio.wait_for(ws.receive(), 8)
                return ws, msg

            async def ended(ws, timeout=12):
                """The close code the portal ended the socket with, or None if it stayed open."""
                try:
                    while True:
                        msg = await asyncio.wait_for(ws.receive(), timeout)
                        if msg.type == aiohttp.WSMsgType.CLOSE:
                            return msg.data
                        if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                            return ws.close_code
                except asyncio.TimeoutError:
                    return None

            # ---- the duration is checked by the server --------------------------------------
            for body in ({"usernames": [pre + "grantee"], "expires_in": "2h"},
                         {"usernames": [pre + "grantee"], "expires_at": "2099-01-01 00:00:00"}):
                st, _ = await jsend(owner, "POST", share_url, json=body)
                ok(f"share with {list(body)[-1]}={list(body.values())[-1]!r} answers 400", st == 400, st)
            ok("the refused requests wrote nothing",
               not sql("SELECT 1 FROM connection_shares WHERE connection_id = ?", (cid,)))

            # ---- a 1 hour share is listed with its time left ---------------------------------
            st, body = await jsend(owner, "POST", share_url, json={"usernames": [pre + "grantee"], "expires_in": "1h"})
            share = (body or {}).get("shares", [{}])[0]
            ok("a 1 hour share is created and lists its time left",
               st == 200 and 3500 < (share.get("expires_in") or 0) <= 3600, f"{st} {body}")
            st, body = await jget(grantee, "/api/connections")
            mine = [c for c in (body or {}).get("connections", []) if c["id"] == uuid]
            ok("the grantee sees it with its time left", len(mine) == 1 and 3500 < (mine[0].get("share_expires_in") or 0) <= 3600, mine)
            st, body = await jget(owner, "/api/me/shares")
            mine = [s for s in (body or {}).get("shares", []) if s["connection_id"] == uuid]
            ok("the owner's all-shares view has grantor and expiry",
               len(mine) == 1 and mine[0]["granted_by_username"] == pre + "owner" and mine[0]["expires_at"], mine)
            st, body = await jget(adm, "/api/admin/grants")
            mine = [s for s in (body or {}).get("connection_shares", []) if s["connection_id"] == uuid]
            ok("the admin all-grants view has it", st == 200 and len(mine) == 1 and mine[0]["owner_username"] == pre + "owner", f"{st} {mine}")
            st, _ = await jget(grantee, "/api/admin/grants")
            ok("the admin view is closed to the grantee", st == 403, st)

            # ---- an open socket ends with the share --------------------------------------------
            ws, first = await open_ws()
            ok("the grantee opens the shared connection's socket", first.type == aiohttp.WSMsgType.BINARY, first)
            sql("UPDATE connection_shares SET expires_at = datetime('now', '+4 seconds') WHERE connection_id = ?", (cid,))
            await asyncio.sleep(5)
            st, _ = await jget(grantee, f"/api/connections/{uuid}")
            ok("past the expiry the grantee cannot open the connection by UUID", st == 404, st)
            st, body = await jget(grantee, "/api/connections")
            ok("past the expiry the grantee's list no longer has it",
               st == 200 and all(c["id"] != uuid for c in body["connections"]))
            code = await ended(ws)
            ok("the open socket was closed with 4010 (access ended)", code == 4010, code)
            ws2 = await grantee.ws_connect(ws_url)
            msg = await asyncio.wait_for(ws2.receive(), 8)
            ok("a new socket on it is refused", msg.type == aiohttp.WSMsgType.TEXT and "not found" in msg.data.lower(), msg)
            await ws2.close()
            await asyncio.sleep(2.5)
            ok("the sweeper deleted the row", not sql("SELECT 1 FROM connection_shares WHERE connection_id = ?", (cid,)))
            ok("one audit entry was written",
               len(sql("SELECT 1 FROM audit_log WHERE action = 'connection.share_expired' AND target_id = ?", (cid,))) == 1)
            st, _ = await jget(owner, f"/api/connections/{uuid}")
            ok("the owner is not affected", st == 200, st)

            # ---- no duration: never expires ----------------------------------------------------
            st, body = await jsend(owner, "POST", share_url, json={"usernames": [pre + "grantee"]})
            ok("a share without a duration has no expiry (API default)", st == 200 and body["shares"][0]["expires_at"] is None, f"{st} {body}")
            ws, first = await open_ws()
            await asyncio.sleep(7)
            st, _ = await jget(grantee, f"/api/connections/{uuid}")
            ok("a share without expiry survives several sweeps", st == 200, st)
            ok("... and its socket is still open", not ws.closed)
            # re-share replaces the expiry
            st, body = await jsend(owner, "POST", share_url, json={"usernames": [pre + "grantee"], "expires_in": "7d"})
            ok("sharing again replaces the expiry", st == 200 and 6 * 86400 < body["shares"][0]["expires_in"] <= 7 * 86400, f"{st} {body}")
            # ---- manual revoke closes the socket -------------------------------------------------
            st, _ = await jsend(owner, "DELETE", f"{share_url}/{users['grantee']}")
            ok("the owner revokes", st == 200, st)
            ok("revoking closed the open socket with 4010", await ended(ws, 8) == 4010)

            # ---- service grants ---------------------------------------------------------------------
            grant_url = f"{base}/api/managed-services/{sid}/grants"
            st, _ = await jsend(adm, "POST", grant_url, json={"usernames": [pre + "grantee"], "expires_in": "soon"})
            ok("a grant with an unknown duration answers 400", st == 400, st)
            st, body = await jsend(adm, "POST", grant_url, json={"usernames": [pre + "grantee"], "actions": ["control", "logs"],
                                                                 "expires_in": "1h"})
            g = (body or {}).get("grants", [{}])[0]
            ok("a 1 hour grant lists its time left, grantor and creation",
               st == 200 and 3500 < (g.get("expires_in") or 0) <= 3600 and g.get("granted_by_username") == pre + "adm" and g.get("created_at"),
               f"{st} {body}")
            st, me = await jget(grantee, "/api/me")
            ok("the grantee's /api/me lists the service", str(sid) in (me or {}).get("granted_services", {}), me)
            st, _ = await jget(grantee, f"/api/managed-services/{sid}/logs")
            ok("the grantee passes the logs permission check while the grant lives", st != 403, st)
            sql("UPDATE service_grants SET expires_at = datetime('now', '+3 seconds') WHERE service_id = ?", (sid,))
            await asyncio.sleep(4)
            st, me = await jget(grantee, "/api/me")
            ok("past the expiry /api/me no longer lists the service", str(sid) not in (me or {}).get("granted_services", {}), me)
            st, _ = await jget(grantee, f"/api/managed-services/{sid}/logs")
            ok("past the expiry the logs route refuses the grantee", st == 403, st)
            await asyncio.sleep(2.5)
            ok("the sweeper deleted the grant", not sql("SELECT 1 FROM service_grants WHERE service_id = ?", (sid,)))
            ok("one audit entry was written for the grant",
               len(sql("SELECT 1 FROM audit_log WHERE action = 'service.grant_expired' AND target_id = ?", (sid,))) == 1)
    finally:
        env_path.write_text(original_env)
        await ctx.stop_server()
        await ctx.start_server()
