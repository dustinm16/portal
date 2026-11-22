"""Dashboard organising on a running instance, over real HTTP: each member files the connections
they can reach in their own folders and tags (connection_user_prefs), and nobody sees anyone
else's filing.

Proves: a grantee files a shared connection under "Games" and neither the owner nor a second
grantee sees "Games" anywhere in their own list; a stranger's PUT answers exactly like a PUT on a
connection that does not exist (same status, same body) and stores nothing; a bad folder, tag,
open mode or field is 400 and nothing is stored; opening connections through the connect route
records last_opened_at, the list orders them newest first and the five newest are what the page
shows under Recently used; a second open within the minute does not move the time; revoking the
share deletes the grantee's rows; deleting the connection deletes everybody's; the served page
loads the organiser script and has the filter box.

Users and connections carry random suffixes and every assertion is about those rows, so the
module also holds on a stage started from a copy of the production database. It makes its own
users and needs no admin password.

Not proven here: how the page looks or behaves in a browser or at phone width (the drawing code
is run against a fake DOM in tests/), the 200-requests-one-write guard through the proxy (a unit
test with a loopback upstream covers it; a stage has no upstream), anything behind Cloudflare.
"""

import asyncio
import json
import re
import secrets
import sqlite3

PW = "Dashorg-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}, "uuids": []}
    for name in ("owner", "bob", "carol", "dave"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    for i in range(7):
        label = "Palworld" if i == 0 else "box%%d" %% i
        out["uuids"].append(await db.create_user_connection(
            out["users"]["owner"], P["pre"] + "-" + label, "vpn_tunnel", "93.184.216.34", 1080 + i, "{}"))
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
    pre = "do" + rnd
    db_path = ctx.stage_dir / "portal.db"

    def ok(name, passed, detail=""):
        ctx.ok("dashorg: " + name, bool(passed), "" if passed else str(detail)[:300])

    def sql(query, args=()):
        con = sqlite3.connect(str(db_path), timeout=15)
        try:
            rows = con.execute(query, args).fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})})
    data = _result(out)
    if rc != 0 or data is None:
        ok("setup", False, out[-500:])
        return
    uuids = data["uuids"]
    pal = uuids[0]
    ids = {u: sql("SELECT id FROM user_connections WHERE uuid = ?", (u,))[0][0] for u in uuids}

    async with ctx.http() as owner, ctx.http() as bob, ctx.http() as carol, ctx.http() as dave:
        sessions = {"owner": owner, "bob": bob, "carol": carol, "dave": dave}
        for name, sess in sessions.items():
            r = await ctx.login(sess, pre + name, PW)
            if r.status != 200:
                ok(f"{name} logs in", False, r.status)
                return
        base = ctx.base_url

        async def send(sess, method, path, **kw):
            async with sess.request(method, base + path, **kw) as r:
                return r.status, await r.text()

        async def listing(sess):
            st, text = await send(sess, "GET", "/api/connections")
            return st, text, {c["id"]: c for c in json.loads(text)["connections"]} if st == 200 else {}

        for u in uuids:
            st, _ = await send(owner, "POST", f"/api/connections/{u}/shares",
                               json={"usernames": [pre + "bob", pre + "carol"], "expires_in": "30d"})
            if st != 200:
                ok("the owner shares a connection", False, st)
                return

        # ---- a grantee files; nobody else sees it --------------------------------------------
        st, text = await send(bob, "PUT", f"/api/connections/{pal}/prefs",
                              json={"folder": "Games", "tags": ["Survival", "co-op"], "open_mode": "new", "pinned": True})
        ok("bob files the shared connection under Games", st == 200 and json.loads(text)["prefs"]["folder"] == "Games", f"{st} {text}")
        st, text, mine = await listing(bob)
        p = mine.get(pal, {}).get("prefs", {})
        ok("bob's list returns his filing with the item",
           p.get("folder") == "Games" and p.get("tags") == ["survival", "co-op"] and p.get("open_mode") == "new" and p.get("pinned") is True, p)
        for who in ("owner", "carol", "dave"):
            st, text, _ = await listing(sessions[who])
            ok(f"{who}'s list holds nothing of bob's filing", st == 200 and "Games" not in text and "survival" not in text, text[:200])
        st, text = await send(owner, "GET", f"/api/connections/{pal}")
        ok("the owner's single answer has none of it", st == 200 and "Games" not in text)
        st, _ = await send(carol, "PUT", f"/api/connections/{pal}/prefs", json={"folder": "Servers"})
        _, _, c_list = await listing(carol)
        _, _, b_list = await listing(bob)
        ok("carol files the same connection her own way, bob's stays",
           st == 200 and c_list[pal]["prefs"]["folder"] == "Servers" and b_list[pal]["prefs"]["folder"] == "Games")
        st, text = await send(bob, "PUT", f"/api/connections/{pal}/prefs", json={"open_mode": "same"})
        _, _, b_list = await listing(bob)
        pp = b_list[pal]["prefs"]
        ok("a request naming one field keeps the others", st == 200 and pp["open_mode"] == "same" and pp["folder"] == "Games" and pp["tags"] == ["survival", "co-op"], pp)

        # ---- authorisation and bounds -----------------------------------------------------------
        ghost = secrets.token_urlsafe(12)
        a = await send(dave, "PUT", f"/api/connections/{pal}/prefs", json={"folder": "Mine"})
        b = await send(dave, "PUT", f"/api/connections/{ghost}/prefs", json={"folder": "Mine"})
        ok("a stranger gets the answer of a connection that does not exist", a == b and a[0] == 404, f"{a} {b}")
        ok("and nothing is stored for him", not sql(
            "SELECT 1 FROM connection_user_prefs WHERE user_id = ?", (data["users"]["dave"],)))
        bad = {"long folder": {"folder": "x" * 41}, "markup tag": {"tags": ["<b>"]}, "eleven tags": {"tags": [f"t{i}" for i in range(11)]},
               "open mode": {"open_mode": "popup"}, "unknown field": {"colour": "red"}, "pinned as number": {"pinned": 1}}
        for label, body in bad.items():
            st, _ = await send(bob, "PUT", f"/api/connections/{pal}/prefs", json=body)
            ok(f"a bad {label} is 400", st == 400, st)
        _, _, b_list = await listing(bob)
        ok("none of them changed anything", b_list[pal]["prefs"]["folder"] == "Games" and b_list[pal]["prefs"]["open_mode"] == "same")

        # ---- last opened and Recently used -----------------------------------------------------------
        order = []
        for u in uuids[1:7]:
            st, _ = await send(bob, "GET", f"/api/connections/{u}/connect")
            order.append(u)
            ok("bob opens a connection through the connect route", st == 200, st)
            await asyncio.sleep(1.1)  # the stored time has a one second resolution
        _, _, b_list = await listing(bob)
        opened = sorted((c for c in b_list.values() if c["prefs"]["last_opened_at"]), key=lambda c: c["prefs"]["last_opened_at"], reverse=True)
        ok("the newest five opened are the last five, newest first", [c["id"] for c in opened[:5]] == list(reversed(order))[:5], [c["id"] for c in opened])
        before = b_list[order[-1]]["prefs"]["last_opened_at"]
        await send(bob, "GET", f"/api/connections/{order[-1]}/connect")
        _, _, b_list = await listing(bob)
        ok("a second open within the minute does not write again", b_list[order[-1]]["prefs"]["last_opened_at"] == before)
        _, _, c_list = await listing(carol)
        ok("carol's list has no opened time (bob's opens are his own)", all(c["prefs"]["last_opened_at"] is None for c in c_list.values()))
        _, _, o_list = await listing(owner)
        ok("nor does the owner's", all(c["prefs"]["last_opened_at"] is None for c in o_list.values()))

        # ---- the page ---------------------------------------------------------------------------------
        st, text = await send(bob, "GET", "/")
        m = re.search(r'conn-organise\.js\?v=(\d+)', text)
        ok("the dashboard loads the organiser script and has the filter box",
           st == 200 and m is not None and 'id="conn-filter"' in text and 'id="conn-organise-modal"' in text, st)
        if m:
            st, js = await send(bob, "GET", f"/static/js/conn-organise.js?v={m.group(1)}")
            ok("the script is served", st == 200 and "ConnOrganiser" in js, st)

        # ---- access ends: the filing goes -----------------------------------------------------------------
        bob_id, carol_id = data["users"]["bob"], data["users"]["carol"]
        ok("bob's rows exist before the revoke", len(sql("SELECT 1 FROM connection_user_prefs WHERE user_id = ?", (bob_id,))) >= 6)
        st, _ = await send(owner, "DELETE", f"/api/connections/{pal}/shares/{bob_id}")
        ok("the owner revokes bob's share of the connection", st == 200, st)
        ok("bob's filing of it is gone", not sql(
            "SELECT 1 FROM connection_user_prefs WHERE user_id = ? AND connection_id = ?", (bob_id, ids[pal])))
        ok("carol's filing of it is not touched", len(sql(
            "SELECT 1 FROM connection_user_prefs WHERE user_id = ? AND connection_id = ?", (carol_id, ids[pal]))) == 1)
        _, _, b_list = await listing(bob)
        ok("bob's list no longer has it", pal not in b_list)
        st, _ = await send(owner, "DELETE", f"/api/connections/{pal}")
        ok("the owner deletes the connection", st == 200, st)
        ok("everybody's filing of it is gone", not sql(
            "SELECT 1 FROM connection_user_prefs WHERE connection_id = ?", (ids[pal],)))
        ok("the other filing is intact", len(sql("SELECT 1 FROM connection_user_prefs WHERE user_id = ?", (bob_id,))) >= 5)
