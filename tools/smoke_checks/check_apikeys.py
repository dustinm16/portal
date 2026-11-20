"""API key least privilege over HTTP: a key bound to a network is refused from another
address with the generic 401 and works from inside, an unknown scope is a 400, a new key
defaults to 90 days, and the list shows the last-used address.

The staged instance sees every client as 127.0.0.1 (loopback is not a trusted proxy), so
"outside" is a key bound to 203.0.113.0/24 and "inside" a key bound to loopback. Users are
made here with a random suffix, and nothing counts rows of a shared table, so the check
also holds on a copy of a production database; no admin password is needed.
"""
import asyncio
import json
import secrets
from datetime import datetime, timezone

PW = "apikeys-pass-1234"

SETUP = '''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    m = await create_user(%r, %r)
    a = await create_user(%r, %r, is_admin=True)
    await db.set_user_role(a["id"], "admin")
    await db.close()
    print(json.dumps({"member": m["id"], "admin": a["id"]}))

asyncio.run(main())
'''

EVENTS = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    cur = await db.conn.execute(
        "SELECT event, result, ip, details FROM security_events WHERE user_id = ? AND event IN "
        "('api_key_created', 'api_key_revoked', 'api_key_ip_denied') ORDER BY id", (%d,))
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    print(json.dumps(rows))

asyncio.run(main())
'''


async def _call(session, ctx, method, path, **kw):
    async with session.request(method, ctx.base_url + path, **kw) as r:
        raw = await r.read()
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        return r.status, data, raw


async def _token(session, ctx, user):
    status, data, _ = await _call(session, ctx, "POST", "/api/token",
                                  json={"username": user, "password": PW, "scopes": ["*"]})
    return (data or {}).get("token") if status == 200 else None


async def run(ctx):
    sfx = secrets.token_hex(3)
    member, admin = f"akck_m_{sfx}", f"akck_a_{sfx}"
    rc, out = await ctx.run_py(SETUP % (member, PW, admin, PW))
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ctx.ok("apikeys: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return

    async with ctx.http() as s:
        mtok = await _token(s, ctx, member)
        atok = await _token(s, ctx, admin)
        ctx.ok("apikeys: both test users can get a token", bool(mtok) and bool(atok))
        if not (mtok and atok):
            return
        mh = {"Authorization": f"Bearer {mtok}"}
        ah = {"Authorization": f"Bearer {atok}"}

        # --- defaults and validation -------------------------------------------
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=ah, json={"name": "default"})
        days = None
        if st == 201 and d.get("expires_at"):
            days = (datetime.fromisoformat(d["expires_at"]) - datetime.now(timezone.utc)).total_seconds() / 86400
        ctx.ok("apikeys: a new key expires in 90 days by default", st == 201 and days is not None and 89 < days < 91, str(d))
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=ah,
                               json={"name": "never", "expires_days": "never"})
        ctx.ok("apikeys: 'never' is an explicit choice and a full-access key then carries a warning",
               st == 201 and d.get("expires_at") is None and bool(d.get("expiry_warning")), str(d))
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=ah,
                               json={"name": "badscope", "scopes": "frobnicate"})
        ctx.ok("apikeys: an unknown scope is a 400", st == 400, f"{st} {d}")
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=mh,
                               json={"name": "badscope2", "scopes": ["admin", "nope:x"]})
        ctx.ok("apikeys: a member's unknown scope is a 400 too", st == 400, f"{st} {d}")
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=ah,
                               json={"name": "badnet", "allowed_cidrs": ["203.0.113.0/24", "not-a-network"]})
        ctx.ok("apikeys: a bad network is a 400", st == 400, f"{st} {d}")
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=ah,
                               json={"name": "zero", "allowed_cidrs": "0.0.0.0/0"})
        ctx.ok("apikeys: a /0 network is a 400", st == 400, f"{st} {d}")
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=mh,
                               json={"name": "member-admin", "scopes": "admin"})
        ctx.ok("apikeys: a member asking for admin still gets only the limited scopes",
               st == 201 and d.get("scopes") == "services:read,access:*", f"{st} {d}")
        st, d, _ = await _call(s, ctx, "GET", "/api/api-keys/scopes", headers=mh)
        ctx.ok("apikeys: the scope list for a member names the registry and says he cannot choose",
               st == 200 and d.get("can_choose") is False and "admin" in [x["scope"] for x in d["scopes"]], str(d))

        # --- the binding ---------------------------------------------------------
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=mh,
                               json={"name": "outside", "allowed_cidrs": "203.0.113.0/24"})
        ctx.ok("apikeys: a bound key is created and echoes its binding",
               st == 201 and d.get("allowed_cidrs") == ["203.0.113.0/24"], str(d))
        outside = d.get("key")
        st, d, _ = await _call(s, ctx, "POST", "/api/api-keys", headers=mh,
                               json={"name": "inside", "allowed_cidrs": ["127.0.0.1", "::1"]})
        inside = d.get("key")
        ctx.ok("apikeys: a key bound to loopback is created", st == 201 and bool(inside), str(d))
        wrong = "portal_" + "0" * 64

        st1, d1, raw1 = await _call(s, ctx, "GET", "/api/api-keys", headers={
            "Authorization": f"Api-Key {outside}", "Accept": "application/json"})
        st2, d2, raw2 = await _call(s, ctx, "GET", "/api/api-keys", headers={
            "Authorization": f"Api-Key {wrong}", "Accept": "application/json"})
        ctx.ok("apikeys: a key bound to 203.0.113.0/24 used from another address is a 401 with the generic body",
               st1 == 401 and st2 == 401 and raw1 == raw2, f"{st1} {st2}")
        st, d, _ = await _call(s, ctx, "GET", "/api/api-keys", headers={"Authorization": f"Api-Key {inside}"})
        ctx.ok("apikeys: a key bound to the address it comes from works", st == 200 and bool(d and d.get("api_keys")), f"{st}")

        # --- last used, created, list --------------------------------------------
        st, d, _ = await _call(s, ctx, "GET", "/api/api-keys", headers=mh)
        by = {k["name"]: k for k in (d or {}).get("api_keys", [])}
        ins = by.get("inside", {})
        ctx.ok("apikeys: the list shows the last-used address and time",
               ins.get("last_used_ip") in ("127.0.0.1", "::1") and bool(ins.get("last_used_at")), str(ins))
        ctx.ok("apikeys: the list shows the created address and the binding",
               ins.get("created_ip") in ("127.0.0.1", "::1") and by.get("outside", {}).get("allowed_cidrs") == ["203.0.113.0/24"])
        ctx.ok("apikeys: the refused key shows no use", not by.get("outside", {}).get("last_used_ip"))
        ctx.ok("apikeys: a member's list has no stale flag", all("stale" not in k for k in by.values()))
        st, d, _ = await _call(s, ctx, "GET", "/api/api-keys", headers=ah)
        ctx.ok("apikeys: an administrator's list carries the stale flag, false for fresh keys",
               st == 200 and d["api_keys"] and all(k.get("stale") is False for k in d["api_keys"]), str(d)[:200])

        # --- revoke and events ----------------------------------------------------
        st, _, _ = await _call(s, ctx, "POST", f"/api/api-keys/{ins['id']}/revoke", headers=mh)
        ctx.ok("apikeys: revoke works", st == 200)
        st, _, _ = await _call(s, ctx, "GET", "/api/api-keys", headers={"Authorization": f"Api-Key {inside}"})
        ctx.ok("apikeys: a revoked key no longer works from inside", st == 401, str(st))

        rows = []
        for _ in range(10):      # the refusal is an aggregated event, flushed every few seconds
            rc, out = await ctx.run_py(EVENTS % ids["member"])
            rows = json.loads(out.strip().splitlines()[-1]) if rc == 0 else []
            if any(r["event"] == "api_key_ip_denied" for r in rows):
                break
            await asyncio.sleep(1.5)
        kinds = [r["event"] for r in rows]
        ctx.ok("apikeys: key creation is a security event with the binding",
               any(r["event"] == "api_key_created" and "203.0.113.0/24" in (r["details"] or "") for r in rows), str(kinds))
        ctx.ok("apikeys: the refused address is a security event with the real reason and no key",
               any(r["event"] == "api_key_ip_denied" and r["result"] == "address_not_allowed"
                   and outside not in json.dumps(r) for r in rows), str(rows))
        ctx.ok("apikeys: revoking a key is a security event", "api_key_revoked" in kinds, str(kinds))
