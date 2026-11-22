"""Connection health checks on a running (staged) instance, over real HTTP.

A listener on 127.0.0.1 inside this module stands in for a member's SSH server. The staged
instance probes nothing but a literal 127.0.0.1 target whose port is in the stage-only setting
stage_health_target_ports, which this module writes together with the on switch
(connection_health_enabled); both are put back at the end. A staged instance makes a round every
second, so no restart is needed.

Proves: while the feature is off the status route answers {} and the route is not swallowed by
/api/connections/{id}; switched on, a pinned connection whose listener is open turns up (two
rounds), shows a latency, and the grantee gets the same entry; closing the listener turns it down
(three rounds) with a "since" time, a "down" row in connection_health_log (and only the two
transitions), and the grantee's answer carries no host, port or error text; an unpinned connection
and a connection to a port the harness did not name stay unknown (nothing dialled); a connection
to 127.0.0.1 that is not on the list is never probed (the listener's accept count is the proof);
reopening the listener brings it back up; switching the feature off answers {} again; the status
route needs a session.

Users and connections carry random suffixes and every assertion is about those rows, so the module
also holds on a stage started from a copy of the production database (real pinned connections are
never probed in a staged instance). It makes its own users and needs no admin password; it sets
the two global settings directly and restores what it found.

Not proven here: a real SSH server, DNS, the HTTP probe against a real web service (the
loopback HTTP probe is run in tests/test_connection_health.py), the dot in a browser, the alert
reaching a real hook (tests/test_connection_health.py runs the real alert module to a fake
delivery), anything behind Cloudflare.
"""

import asyncio
import json
import secrets
import sqlite3

PW = "Health-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "bob", "carol"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    out["pinned"] = await db.create_user_connection(out["users"]["owner"], P["pre"] + "-pinned", "ssh", "127.0.0.1", P["port"], "{}")
    out["plain"] = await db.create_user_connection(out["users"]["owner"], P["pre"] + "-plain", "ssh", "127.0.0.1", P["port"] + 1, "{}")
    out["other"] = await db.create_user_connection(out["users"]["owner"], P["pre"] + "-other", "ssh", "127.0.0.1", P["port"] + 2, "{}")
    out["stranger"] = await db.create_user_connection(out["users"]["owner"], P["pre"] + "-stranger", "ssh", "93.184.216.34", 22, "{}")
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
    pre = "hl" + rnd
    db_path = ctx.stage_dir / "portal.db"
    accepted = {"n": 0}
    other_accepted = {"n": 0}

    def ok(name, passed, detail=""):
        ctx.ok("health: " + name, bool(passed), "" if passed else str(detail)[:300])

    def sql(query, args=()):
        con = sqlite3.connect(str(db_path), timeout=15)
        try:
            rows = con.execute(query, args).fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    async def on_connect(reader, writer):
        accepted["n"] += 1
        writer.close()

    async def on_other(reader, writer):
        other_accepted["n"] += 1
        writer.close()

    server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    # a second real listener on the port of the pinned connection "other", which the harness does NOT name:
    # if the staged instance ever dialled it, this counter would say so
    other_server = None
    for _ in range(20):
        try:
            other_server = await asyncio.start_server(on_other, "127.0.0.1", port + 2)
            break
        except OSError:
            server.close()
            await server.wait_closed()
            server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
    keys = ("connection_health_enabled", "stage_health_target_ports", "connection_health_interval")
    saved = {k: (sql("SELECT value FROM settings WHERE key = ?", (k,)) or [[None]])[0][0] for k in keys}

    def put_setting(key, value):
        if value is None:
            sql("DELETE FROM settings WHERE key = ?", (key,))
        else:
            sql("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    try:
        rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre, "port": port})})
        data = _result(out)
        if rc != 0 or data is None:
            ok("setup", False, out[-500:])
            return
        users = data["users"]
        cid = {k: sql("SELECT id FROM user_connections WHERE uuid = ?", (data[k],))[0][0] for k in ("pinned", "plain", "other", "stranger")}
        # a share of the pinned connection to bob; the owner pins the pinned one and the unlisted-port one
        sql("INSERT INTO connection_shares (connection_id, grantee_user_id, granted_by) VALUES (?, ?, ?)",
            (cid["pinned"], users["bob"], users["owner"]))
        for k in ("pinned", "other", "stranger"):
            sql("INSERT INTO connection_user_prefs (user_id, connection_id, pinned) VALUES (?, ?, 1)", (users["owner"], cid[k]))
        base = ctx.base_url

        async with ctx.http() as owner, ctx.http() as bob, ctx.http() as carol, ctx.http() as anon:
            for sess, name in ((owner, "owner"), (bob, "bob"), (carol, "carol")):
                r = await ctx.login(sess, pre + name, PW)
                if r.status != 200:
                    ok(f"{name} logs in", False, r.status)
                    return

            async def status(sess):
                async with sess.get(base + "/api/connections/status") as r:
                    try:
                        return r.status, await r.json(content_type=None)
                    except Exception:
                        return r.status, None

            async def until(sess, uuid, want, timeout=30.0):
                end = asyncio.get_event_loop().time() + timeout
                last = None
                while asyncio.get_event_loop().time() < end:
                    st, body = await status(sess)
                    last = (body or {}).get(uuid) if isinstance(body, dict) else None
                    if last and last["status"] == want:
                        return last
                    await asyncio.sleep(0.5)
                return None

            # ---- off: the empty map, and the route is its own route -------------------------------
            put_setting("connection_health_enabled", "0")
            st, body = await status(owner)
            ok("off: the status route answers an empty map", st == 200 and body == {}, f"{st} {body}")
            async with owner.get(base + "/api/connections/status") as r:
                ok("the status route is not the connection-by-id route", r.status == 200 and "not found" not in (await r.text()).lower())
            async with anon.get(base + "/api/connections/status", allow_redirects=False) as r:
                ok("the status route needs a session", r.status in (401, 302, 403), r.status)
            await asyncio.sleep(2.5)
            ok("off: nothing was dialled", accepted["n"] == 0, accepted["n"])

            # ---- on --------------------------------------------------------------------------------
            put_setting("connection_health_interval", None)
            put_setting("stage_health_target_ports", str(port))
            put_setting("connection_health_enabled", "1")
            up = await until(owner, data["pinned"], "up")
            ok("a pinned connection with an open listener turns up with a latency", bool(up) and isinstance(up["latency_ms"], int) and up["since"], up)
            st, body = await status(bob)
            theirs = (body or {}).get(data["pinned"])
            ok("the grantee gets the same entry", st == 200 and theirs and theirs["status"] == "up" and set(theirs) == {"status", "latency_ms", "since"}, f"{st} {body}")
            st, body = await status(owner)
            ok("every entry has exactly status, latency_ms and since", all(set(v) == {"status", "latency_ms", "since"} for v in body.values()), body)
            ok("a connection that is not pinned is not listed as checked", body[data["plain"]]["status"] == "unknown", body.get(data["plain"]))
            ok("a pinned connection to a port the harness did not name stays unknown", body[data["other"]]["status"] == "unknown", body.get(data["other"]))
            ok("a pinned connection to a public address is not probed in a staged instance", body[data["stranger"]]["status"] == "unknown", body.get(data["stranger"]))
            st, body = await status(carol)
            ok("a member with no access sees nothing of it", st == 200 and body == {}, f"{st} {body}")
            seen = accepted["n"]
            await asyncio.sleep(3.5)
            ok("the listener is probed (and only it): dials are only to the one named port", accepted["n"] > seen, f"{seen} -> {accepted['n']}")

            # ---- the listener goes away ---------------------------------------------------------------
            server.close()
            await server.wait_closed()
            down = await until(owner, data["pinned"], "down")
            ok("closing the listener turns the dot down with a since time and no latency", bool(down) and down["since"] and down["latency_ms"] is None, down)
            st, body = await status(bob)
            text = json.dumps(body)
            ok("the grantee sees down too, and nothing else about it",
               body.get(data["pinned"], {}).get("status") == "down" and "127.0.0.1" not in text and str(port) not in text and "error" not in text.lower(), text)
            rows = sql("SELECT status FROM connection_health_log WHERE connection_id = ? ORDER BY id", (cid["pinned"],))
            ok("only the two transitions are stored (up, down)", [r[0] for r in rows] == ["up", "down"], rows)

            # ---- and comes back --------------------------------------------------------------------------
            server = await asyncio.start_server(on_connect, "127.0.0.1", port)
            back = await until(owner, data["pinned"], "up")
            ok("reopening the listener brings it back up", bool(back), back)
            rows = sql("SELECT status FROM connection_health_log WHERE connection_id = ? ORDER BY id", (cid["pinned"],))
            ok("the log has up, down, up", [r[0] for r in rows] == ["up", "down", "up"], rows)

            # ---- maintenance: a neutral dot for everybody who can reach the connection --------------------------
            sql("UPDATE user_connections SET maintenance = 1, maintenance_until = NULL, maintenance_message = 'smoke secret' WHERE id = ?", (cid["pinned"],))
            st_o, body_o = await status(owner)
            st_b, body_b = await status(bob)
            ok("a connection in maintenance reads maintenance for the owner and the grantee, with nothing else",
               (body_o or {}).get(data["pinned"]) == {"status": "maintenance", "latency_ms": None, "since": None}
               and (body_b or {}).get(data["pinned"]) == (body_o or {}).get(data["pinned"]), f"{body_o} {body_b}")
            ok("the maintenance message is not in the status answer", "smoke secret" not in json.dumps([body_o, body_b]))
            st_c, body_c = await status(carol)
            ok("a member with no access still sees nothing of it", st_c == 200 and body_c == {}, f"{st_c} {body_c}")
            sql("UPDATE user_connections SET maintenance = 0, maintenance_until = NULL, maintenance_message = NULL WHERE id = ?", (cid["pinned"],))
            back2 = await until(owner, data["pinned"], "up")
            ok("when the maintenance is cleared the real status shows again", bool(back2), back2)

            # ---- the stage rule, after many rounds ------------------------------------------------------------
            st, body = await status(owner)
            ok("after many rounds the unnamed port and the public address are still unknown",
               body[data["other"]]["status"] == "unknown" and body[data["stranger"]]["status"] == "unknown"
               and body[data["plain"]]["status"] == "unknown", body)
            ok("a real listener on the unnamed port was never dialled", other_accepted["n"] == 0, other_accepted["n"])

            # ---- off again -----------------------------------------------------------------------------------
            put_setting("connection_health_enabled", "0")
            await asyncio.sleep(1.5)
            st, body = await status(owner)
            ok("off again: the empty map", st == 200 and body == {}, f"{st} {body}")
            n = accepted["n"]
            await asyncio.sleep(3)
            ok("off again: nothing is dialled", accepted["n"] == n, f"{n} -> {accepted['n']}")
    finally:
        for k, v in saved.items():
            put_setting(k, v)
        server.close()
        await server.wait_closed()
        if other_server is not None:
            other_server.close()
            await other_server.wait_closed()
