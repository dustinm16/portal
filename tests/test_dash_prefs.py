"""Personal dashboard filing of connections (folder, tags, open mode, pin, last opened).

Real app on a loopback server with a temporary database (tests/grant_harness.py). Proves: a
grantee files a shared connection under "Games" and neither the owner nor another grantee sees
it anywhere in their own responses; PUT /api/connections/{id}/prefs answers a caller without
access exactly like a connection that does not exist; the values are validated and bounded;
last_opened_at is written when a connection is opened and at most once a minute per user and
connection (200 proxied requests, one write); the filing disappears when the share is revoked,
when it expires (never returned from the second it ran out, gone after the sweep, not back
after a new share), when the connection is deleted and when either user is deleted, and the
periodic clean-up removes rows nobody can use.

Run: venv/bin/python tests/test_dash_prefs.py
"""

import asyncio
import json
import sys
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
import dash_prefs  # noqa: E402
import grant_expiry  # noqa: E402

T0 = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
clock = {"now": T0}
grant_expiry.set_clock(lambda: clock["now"])


def unit_checks():
    ok, err = dash_prefs.validate({"folder": "  Games  ", "tags": ["Fun", "fun", "co-op"], "open_mode": "new", "pinned": True})
    check("validate keeps a clean request (folder trimmed, tags lower-cased and de-duplicated)",
          err is None and ok == {"folder": "Games", "tags": ["fun", "co-op"], "open_mode": "new", "pinned": True}, str((ok, err)))
    bad = {
        "folder too long": {"folder": "x" * 41},
        "folder with markup": {"folder": "<b>x</b>"},
        "folder not text": {"folder": 5},
        "tag too long": {"tags": ["y" * 25]},
        "tag with a space": {"tags": ["a b"]},
        "tag with markup": {"tags": ["<i>"]},
        "too many tags": {"tags": [f"t{i}" for i in range(11)]},
        "tags not a list": {"tags": "a,b"},
        "tag not text": {"tags": [1]},
        "unknown open mode": {"open_mode": "popup"},
        "pinned not a bool": {"pinned": 1},
        "unknown field": {"colour": "red"},
        "empty body": {},
        "not an object": [],
    }
    for label, body in bad.items():
        check("validate refuses " + label, dash_prefs.validate(body)[1] is not None)
    ok, _ = dash_prefs.validate({"folder": "", "tags": []})
    check("an empty folder and no tags clear the filing", ok == {"folder": "", "tags": []})
    t = {"now": 0.0}
    th = dash_prefs.OpenThrottle(interval=60, clock=lambda: t["now"])
    check("throttle: first take passes, the second within a minute does not", th.take(1, 2) and not th.take(1, 2))
    check("throttle: another user or connection has its own slot", th.take(2, 2) and th.take(1, 3))
    t["now"] = 61.0
    check("throttle: the slot returns after the interval", th.take(1, 2))
    small = dash_prefs.OpenThrottle(interval=60, clock=lambda: t["now"], max_entries=3)
    results = [small.take(1, i) for i in range(5)]
    check("throttle: a flood of distinct pairs stays bounded", results == [True, True, True, False, False] and len(small._last) <= 3, str(results))


async def main():
    unit_checks()
    up = web.Application()
    hits = {"n": 0}

    async def ok_page(request):
        hits["n"] += 1
        return web.Response(text="ok")
    up.router.add_get("/{tail:.*}", ok_page)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()

    env = await h.boot(names=("owner", "bob", "carol", "adm", "dave"))
    db, owner, bob, carol, adm = env.db, env.sessions["owner"], env.sessions["bob"], env.sessions["carol"], env.sessions["adm"]
    uid = env.uid
    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    palworld, pal_id = await h.connection(env, "owner", name="Palworld")
    other, other_id = await h.connection(env, "owner", name="Minecraft")
    web_uuid, web_id = await h.connection(env, "owner", name="webapp", ctype="http", host="127.0.0.1", port=upstream.port)
    for u in (palworld, other, web_uuid):
        async with owner.post(f"{env.base}/api/connections/{u}/shares",
                              json={"usernames": ["bob", "carol"], "expires_in": "30d"}) as r:
            assert r.status == 200

    async def listing(s):
        async with s.get(f"{env.base}/api/connections") as r:
            assert r.status == 200
            return await r.text()

    async def prefs_of(s, u):
        for c in json.loads(await listing(s))["connections"]:
            if c["id"] == u:
                return c["prefs"]

    async def put(s, u, body):
        async with s.put(f"{env.base}/api/connections/{u}/prefs", json=body) as r:
            return r.status, await r.text()

    # ---- a grantee files a shared connection; nobody else sees it ---------------------------------------
    check("the list carries default prefs before anything is filed",
          await prefs_of(owner, palworld) == {"folder": "", "tags": [], "open_mode": "default", "pinned": False, "last_opened_at": None})
    st, body = await put(bob, palworld, {"folder": "Games", "tags": ["Survival", "co-op"], "open_mode": "new", "pinned": True})
    check("bob files the shared connection under Games", st == 200 and json.loads(body)["prefs"]["folder"] == "Games", f"{st} {body}")
    p = await prefs_of(bob, palworld)
    check("bob's list returns his own filing with the item",
          p["folder"] == "Games" and p["tags"] == ["survival", "co-op"] and p["open_mode"] == "new" and p["pinned"] is True, str(p))
    for who, s in (("the owner", owner), ("another grantee", carol), ("an admin", adm)):
        text = await listing(s)
        check(f"{who} sees nothing of bob's filing in the list", "Games" not in text and "survival" not in text and "co-op" not in text)
    async with owner.get(f"{env.base}/api/connections/{palworld}") as r:
        check("the owner's single-connection answer has no trace of it either", "Games" not in await r.text())
    async with owner.get(f"{env.base}/api/me/shares") as r:
        check("nor does the owner's share list", "Games" not in await r.text())
    st, _ = await put(carol, palworld, {"folder": "Servers"})
    check("carol files the same connection her own way",
          st == 200 and (await prefs_of(carol, palworld))["folder"] == "Servers" and (await prefs_of(bob, palworld))["folder"] == "Games")
    st, _ = await put(bob, palworld, {"open_mode": "same"})
    p = await prefs_of(bob, palworld)
    check("a request that names one field keeps the others", p["open_mode"] == "same" and p["folder"] == "Games" and p["tags"] == ["survival", "co-op"], str(p))
    st, _ = await put(bob, palworld, {"folder": "", "tags": []})
    p = await prefs_of(bob, palworld)
    check("an empty folder and tags clear them", p["folder"] == "" and p["tags"] == [], str(p))
    await put(bob, palworld, {"folder": "Games"})

    # ---- authorisation: no access answers like a connection that does not exist ------------------------------------
    ghost = uuidlib.uuid4().hex[:16]
    s1 = await put(env.sessions["dave"], palworld, {"folder": "Mine"})
    s2 = await put(env.sessions["dave"], ghost, {"folder": "Mine"})
    check("a user with no access gets the answer of a connection that does not exist", s1 == s2 and s1[0] == 404, f"{s1} {s2}")
    s3 = await put(env.sessions["dave"], palworld, "not an object")
    check("(and the answer does not depend on the body)", s3 == s1, str(s3))
    row = await (await db.conn.execute("SELECT COUNT(*) c FROM connection_user_prefs WHERE user_id = ?", (uid["dave"],))).fetchone()
    check("nothing was stored for him", row["c"] == 0)
    async with aiohttp.ClientSession() as anon:
        async with anon.put(f"{env.base}/api/connections/{palworld}/prefs", json={"folder": "x"}) as r:
            check("a signed-out caller is refused", r.status in (401, 403, 302), str(r.status))
    for label, bodyv in (("long folder", {"folder": "x" * 41}), ("markup tag", {"tags": ["<b>"]}), ("open mode", {"open_mode": "x"}), ("unknown field", {"is_pinned": 1})):
        st, _ = await put(bob, palworld, bodyv)
        check(f"a bad {label} is 400", st == 400, str(st))
    async with bob.put(f"{env.base}/api/connections/{palworld}/prefs", data=b"{not json") as r:
        check("invalid JSON is 400", r.status == 400)

    # ---- an owner's older pin still counts, and the old toggle agrees ------------------------------------------------
    async with owner.post(f"{env.base}/api/connections/{other}/pin") as r:
        check("the owner pins with the older toggle", r.status == 200 and (await r.json())["is_pinned"] is True)
    check("the new list shows that pin", (await prefs_of(owner, other))["pinned"] is True)
    st, _ = await put(owner, other, {"pinned": False})
    check("unpinning through prefs also clears the older flag",
          st == 200 and (await prefs_of(owner, other))["pinned"] is False
          and (await (await db.conn.execute("SELECT is_pinned FROM user_connections WHERE id = ?", (other_id,))).fetchone())["is_pinned"] == 0)
    async with owner.post(f"{env.base}/api/connections/{other}/pin") as r:
        pass
    check("the older toggle after a prefs pin keeps both in step", (await prefs_of(owner, other))["pinned"] is True)

    # ---- last opened -------------------------------------------------------------------------------------------------
    server._open_throttle.clear()
    async with bob.get(f"{env.base}/api/connections/{other}/connect") as r:
        check("bob opens a connection (connect API)", r.status == 200)
    check("last_opened_at is set for bob", (await prefs_of(bob, other))["last_opened_at"] is not None)
    check("and not for carol or the owner", (await prefs_of(carol, other))["last_opened_at"] is None
          and (await prefs_of(owner, other))["last_opened_at"] is None)
    ws, first = await h.open_ws(carol, env.base, palworld)
    check("carol opens a terminal", "ready" in first.data)
    await ws.close()
    check("a terminal open sets last_opened_at", (await prefs_of(carol, palworld))["last_opened_at"] is not None)

    server._open_throttle.clear()
    writes = {"opened": 0, "usage": 0}
    orig_note, orig_use = db.note_connection_opened, db.record_connection_usage
    async def count_note(*a, **k):
        writes["opened"] += 1
        return await orig_note(*a, **k)
    async def count_use(*a, **k):
        writes["usage"] += 1
        return await orig_use(*a, **k)
    db.note_connection_opened, db.record_connection_usage = count_note, count_use
    hits["n"] = 0
    async def one(s):
        async with s.get(f"{env.base}/proxy/{web_uuid}/asset") as r:
            await r.read()
            return r.status
    codes = await asyncio.gather(*[one(bob if i % 2 else owner) for i in range(200)])
    db.note_connection_opened, db.record_connection_usage = orig_note, orig_use
    check("200 proxied requests reach the upstream", codes.count(200) == 200 and hits["n"] == 200, f"{codes.count(200)} {hits['n']}")
    check("they cause one last-opened write per user (two users, two writes)", writes["opened"] == 2, str(writes))
    check("and no per-request usage write either", writes["usage"] == 2, str(writes))
    check("the proxy entry set last_opened_at", (await prefs_of(bob, web_uuid))["last_opened_at"] is not None)
    import time as _t
    server._open_throttle.clock = lambda: _t.monotonic() + 61
    writes["opened"] = 0
    db.note_connection_opened = count_note
    await one(bob)
    db.note_connection_opened = orig_note
    check("a minute later the next open writes again", writes["opened"] == 1)
    server._open_throttle.clock = _t.monotonic
    server._open_throttle.clear()

    async def failing(*a, **k):
        raise RuntimeError("disk full")
    db.note_connection_opened = failing
    check("a failing write does not break the open", await one(bob) == 200)
    db.note_connection_opened = orig_note

    # ---- filing disappears when access ends ---------------------------------------------------------------------------
    async def stored(user, conn_id):
        r = await (await db.conn.execute("SELECT COUNT(*) c FROM connection_user_prefs WHERE user_id = ? AND connection_id = ?", (uid[user], conn_id))).fetchone()
        return r["c"]

    check("bob's rows exist before the revoke", await stored("bob", pal_id) == 1)
    async with owner.delete(f"{env.base}/api/connections/{palworld}/shares/{uid['bob']}") as r:
        check("the owner revokes bob's share", r.status == 200)
    check("bob's filing of it is deleted", await stored("bob", pal_id) == 0)
    check("carol's and the owner's are not touched", await stored("carol", pal_id) == 1)
    async with owner.post(f"{env.base}/api/connections/{palworld}/shares", json={"usernames": ["bob"], "expires_in": "30d"}) as r:
        pass
    check("a new share starts with nothing filed", (await prefs_of(bob, palworld))["folder"] == "")

    await put(bob, palworld, {"folder": "Games"})
    async with bob.delete(f"{env.base}/api/connections/{palworld}/shares/me") as r:
        check("bob leaves", r.status == 200)
    check("leaving removes the filing", await stored("bob", pal_id) == 0)

    # expiry: never returned from the second it runs out, removed by the sweep, not back after a new share
    async with owner.post(f"{env.base}/api/connections/{palworld}/shares", json={"usernames": ["bob"], "expires_in": "1h"}) as r:
        assert r.status == 200
    await put(bob, palworld, {"folder": "Games", "tags": ["x"]})
    clock["now"] = T0 + timedelta(hours=2)
    check("after the expiry the connection is not in bob's list", palworld not in await listing(bob))
    st, _ = await put(bob, palworld, {"folder": "Again"})
    check("and a PUT is refused as not found", st == 404)
    check("the row is still there, unreturned, until the sweep", await stored("bob", pal_id) == 1)
    check("the owner's list never held it", "Games" not in await listing(owner))
    n = await server.sweep_expired_grants_once()
    check("the sweep deletes the share", n >= 1)
    check("and the filing with it", await stored("bob", pal_id) == 0)

    async with owner.post(f"{env.base}/api/connections/{palworld}/shares", json={"usernames": ["bob"], "expires_in": "1h"}) as r:
        pass
    await put(bob, palworld, {"folder": "Old"})
    clock["now"] = T0 + timedelta(hours=4)
    async with owner.post(f"{env.base}/api/connections/{palworld}/shares", json={"usernames": ["bob"], "expires_in": "7d"}) as r:
        check("an expired share the sweeper has not removed is shared again", r.status == 200)
    check("the old filing does not come back with it", (await prefs_of(bob, palworld))["folder"] == "")
    check("the renewed share is live for bob", palworld in await listing(bob))

    # periodic clean-up: rows with no owner and no live share
    await db.conn.execute("INSERT INTO connection_user_prefs (user_id, connection_id, folder) VALUES (?, ?, 'stray')", (uid["dave"], pal_id))
    await db.conn.commit()
    check("a stray row exists", await stored("dave", pal_id) == 1)
    await server.sweep_expired_grants_once()
    check("the periodic sweep removes it and leaves live rows", await stored("dave", pal_id) == 0 and await stored("carol", pal_id) == 1)

    # connection delete
    await put(carol, other, {"folder": "Gone"})
    await put(owner, other, {"folder": "OwnerFolder"})
    async with owner.delete(f"{env.base}/api/connections/{other}") as r:
        check("the owner deletes a connection", r.status == 200)
    left = await (await db.conn.execute("SELECT COUNT(*) c FROM connection_user_prefs WHERE connection_id = ?", (other_id,))).fetchone()
    check("every user's filing of it is gone", left["c"] == 0, str(left["c"]))

    # user delete: grantee, then owner
    await put(carol, web_uuid, {"folder": "W"})
    async with adm.delete(f"{env.base}/api/users/{uid['carol']}") as r:
        check("an admin deletes a grantee", r.status == 200)
    left = await (await db.conn.execute("SELECT COUNT(*) c FROM connection_user_prefs WHERE user_id = ?", (uid["carol"],))).fetchone()
    check("the grantee's filing is gone", left["c"] == 0)
    await put(bob, web_uuid, {"folder": "W2"})
    async with adm.delete(f"{env.base}/api/users/{uid['owner']}") as r:
        check("an admin deletes the owner", r.status == 200)
    left = await (await db.conn.execute("SELECT COUNT(*) c FROM connection_user_prefs")).fetchone()
    check("nobody's filing of the owner's connections is left", left["c"] == 0, str(left["c"]))

    await upstream.close()
    await h.shutdown(env)
    h.finish("test_dash_prefs")


asyncio.run(main())
