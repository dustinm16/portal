"""Token revocation checks: admin reset signs the target out, revoke is owner-scoped."""
import asyncio
import json
import time

import aiohttp

PW_A = "alpha-pass-1234"
PW_B = "bravo-pass-1234"
PW_B2 = "bravo-new-pass-5678"

SETUP = '''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    out = {}
    for name, pw in (("tok_user_a", %r), ("tok_user_b", %r)):
        u = await create_user(name, pw)
        out[name] = u["id"]
    u = await create_user("tok_admin_2", %r, is_admin=True)
    await db.set_user_role(u["id"], "admin")
    out["tok_admin_2"] = u["id"]
    u = await create_user("tok_admin_3", %r, is_admin=True)
    await db.set_user_role(u["id"], "admin")
    out["tok_admin_3"] = u["id"]
    await db.close()
    print(json.dumps(out))

asyncio.run(main())
''' % (PW_A, PW_B, PW_A, PW_A)

STATE = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    cur = await db.conn.execute(
        "SELECT token_id, revoked FROM tokens WHERE user_id = ? ORDER BY id", (%d,))
    rows = [dict(r) for r in await cur.fetchall()]
    cur = await db.conn.execute(
        "SELECT action, actor_id, target_id FROM audit_log ORDER BY id")
    audit = [dict(r) for r in await cur.fetchall()]
    await db.close()
    print(json.dumps({"tokens": rows, "audit": audit}))

asyncio.run(main())
'''


async def _state(ctx, user_id):
    rc, out = await ctx.run_py(STATE % user_id)
    return json.loads(out.strip().splitlines()[-1])


async def _status(session, ctx, method, path, **kw):
    async with session.request(method, ctx.base_url + path, **kw) as r:
        await r.read()
        return r.status


async def run(ctx):
    if not ctx.admin_password:
        # Every step signs in as the admin account; without its password (a --from-db run) the
        # check cannot run, and creating its users first would only leave them behind.
        ctx.skip("tokens: revocation checks", "no admin password (use --admin-password)")
        return
    rc, out = await ctx.run_py(SETUP)
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ctx.ok("tokens: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    uid_b = ids["tok_user_b"]

    async with ctx.http() as admin, ctx.http() as sess_a, ctx.http() as sess_b, ctx.http() as sess_b3:
        logins = []
        for s, u, p in ((admin, ctx.admin_user, ctx.admin_password),
                        (sess_a, "tok_user_a", PW_A),
                        (sess_b, "tok_user_b", PW_B)):
            r = await ctx.login(s, u, p)
            await r.read()
            logins.append(r.status)
        ctx.ok("tokens: users and admin can sign in", logins == [200, 200, 200], str(logins))
        if logins != [200, 200, 200]:
            return

        # A non-object JSON body is a client error, not a server error.
        for body in (["a"], None):
            st = await _status(sess_a, ctx, "POST", "/api/token/revoke", json=body)
            ctx.ok("tokens: non-object revoke body returns 400", st == 400, f"{body!r} -> {st}")

        for body in (["a"], "x", None):
            st = await _status(admin, ctx, "POST", f"/api/users/{uid_b}/reset-password", json=body)
            ctx.ok("tokens: non-object reset body returns 400", st == 400, f"{body!r} -> {st}")

        for body in (["user"], "x", None):
            st = await _status(admin, ctx, "PUT", f"/api/users/{uid_b}/role", json=body)
            ctx.ok("tokens: non-object role body returns 400", st == 400, f"{body!r} -> {st}")
        for body in (["a"], "x", None):
            st = await _status(sess_a, ctx, "POST", "/api/me/password", json=body)
            ctx.ok("tokens: non-object password body returns 400", st == 400, f"{body!r} -> {st}")
        for body in ({"current_password": PW_A, "new_password": 12345678},
                     {"current_password": 123, "new_password": PW_B2}):
            st = await _status(sess_a, ctx, "POST", "/api/me/password", json=body)
            ctx.ok("tokens: non-string password fields return 400", st == 400, f"{body!r} -> {st}")

        before = await _status(sess_b, ctx, "GET", "/api/me")
        ctx.ok("tokens: B session works before reset", before == 200, f"status {before}")

        # User A tries to revoke B's token by id: must look like it does not exist.
        b_tokens = (await _state(ctx, uid_b))["tokens"]
        b_token_id = b_tokens[0]["token_id"]
        st = await _status(sess_a, ctx, "POST", "/api/token/revoke",
                           json={"token_id": b_token_id})
        ctx.ok("tokens: non-owner revoke returns 404", st == 404, f"status {st}")
        st = await _status(sess_b, ctx, "GET", "/api/me")
        ctx.ok("tokens: B stays signed in after non-owner revoke", st == 200, f"status {st}")

        # A second, independent browser session for B, opened just before the reset.
        r = await ctx.login(sess_b3, "tok_user_b", PW_B)
        await r.read()
        st = await _status(sess_b3, ctx, "GET", "/api/me")
        ctx.ok("tokens: B second session works before reset", st == 200, f"status {st}")

        # B also holds an API key and an open chat WebSocket; both must die with the reset.
        async with sess_b.post(ctx.base_url + "/api/api-keys", json={"name": "tok-key"}) as r:
            key_body = await r.json()
            key_status = r.status
        api_key = key_body.get("key", "")
        ctx.ok("tokens: B can create an API key", key_status == 201 and bool(api_key),
               f"status {key_status}")
        async with ctx.http() as keyless:
            st = await _status(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": api_key})
        ctx.ok("tokens: B API key works before reset", st == 200, f"status {st}")
        ws = await sess_b.ws_connect(ctx.base_url + "/ws/chat")
        await ws.send_json({"type": "ping"})
        await asyncio.sleep(0.5)
        ctx.ok("tokens: B chat socket open before reset", not ws.closed)
        ws2 = await sess_b.ws_connect(ctx.base_url + "/ws")
        ctx.ok("tokens: B generic socket open before reset", not ws2.closed)

        # Admin resets B's password: B's browser sessions must stop working.
        st = await _status(admin, ctx, "POST", f"/api/users/{uid_b}/reset-password",
                           json={"new_password": PW_B2})
        ctx.ok("tokens: admin reset accepted", st == 200, f"status {st}")
        st = await _status(sess_b, ctx, "GET", "/api/me")
        ctx.ok("tokens: B old session gets 401 after admin reset", st == 401, f"status {st}")
        st = await _status(sess_b3, ctx, "GET", "/api/me")
        ctx.ok("tokens: B second session gets 401 after admin reset", st == 401, f"status {st}")
        async with ctx.http() as keyless:
            st = await _status(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": api_key})
        ctx.ok("tokens: B API key stops working after admin reset", st == 401, f"status {st}")

        # A burst of forged and revoked API keys must neither stall the event
        # loop nor slow down a valid key: unknown prefixes are rejected without
        # running the expensive hash.
        async with admin.post(ctx.base_url + "/api/api-keys", json={"name": "probe"}) as r:
            probe_key = (await r.json()).get("key", "")
        ctx.ok("tokens: admin can create a probe API key", bool(probe_key))

        async def _probe_full(key):
            async with ctx.http() as k:
                async with k.get(ctx.base_url + "/api/me", headers={"X-API-Key": key}) as r:
                    await r.read()
                    return r.status, r.headers.get("Retry-After")

        async def _probe_bad_key(key):
            return (await _probe_full(key))[0]

        # A second key that is never used before the burst: after a restart
        # every key looks like this, and it must not be turned away because
        # someone floods another key's prefix.
        async with admin.post(ctx.base_url + "/api/api-keys", json={"name": "cold"}) as r:
            cold_key = (await r.json()).get("key", "")
        ctx.ok("tokens: admin can create a cold API key",
               bool(cold_key) and cold_key[:10] != probe_key[:10])
        # The probe key is used once so it is known to the server, as a script
        # that has been calling the API would be.
        warm = await _probe_bad_key(probe_key)
        ctx.ok("tokens: probe API key works", warm == 200, f"status {warm}")
        # Forged keys use the probe key's real lookup prefix, which is the
        # case where the expensive hash cannot be skipped by prefix.
        forged = ["portal_zzz" + "%032x" % i for i in range(30)]
        forged += [probe_key[:10] + "%054x" % (i + 1) for i in range(60)]
        burst = [asyncio.ensure_future(_probe_full(k)) for k in forged]
        burst += [asyncio.ensure_future(_probe_full(api_key)) for _ in range(20)]
        await asyncio.sleep(0.15)
        t0 = time.monotonic()
        health = await _status(admin, ctx, "GET", "/health")
        health_s = time.monotonic() - t0
        t0 = time.monotonic()
        valid_st = await _probe_bad_key(probe_key)
        valid_s = time.monotonic() - t0
        t0 = time.monotonic()
        cold_st = await _probe_bad_key(cold_key)
        cold_s = time.monotonic() - t0
        results = await asyncio.gather(*burst)
        codes = {c for c, _ in results}
        ctx.ok("tokens: forged and revoked API key burst gets only 401 or 503", codes <= {401, 503}, str(sorted(codes)))
        ctx.ok("tokens: shed API key checks answer 503 with Retry-After",
               any(c == 503 and ra for c, ra in results)
               and all(ra for c, ra in results if c == 503), str(sorted(set(results), key=str)))
        ctx.ok("tokens: /health stays responsive during bad API key burst",
               health == 200 and health_s < 0.5, f"status {health} in {health_s:.3f}s")
        ctx.ok("tokens: valid API key is not delayed by a forged key burst",
               valid_st == 200 and valid_s < 1.5, f"status {valid_st} in {valid_s:.3f}s")
        ctx.ok("tokens: never-used API key still works during a burst on another prefix",
               cold_st == 200 and cold_s < 3, f"status {cold_st} in {cold_s:.3f}s")
        # The cap must be released once the burst is over.
        after = await _probe_bad_key(probe_key[:10] + "%054x" % 999)
        ctx.ok("tokens: forged key gets 401 again after the burst", after == 401, f"status {after}")

        async def server_close_code(sock):
            # Only a close frame sent by the server counts (a client-side timeout
            # would just mark the socket closed with code 1006).
            try:
                while True:
                    msg = await asyncio.wait_for(sock.receive(), 5)
                    if msg.type == aiohttp.WSMsgType.CLOSE:
                        return msg.data
                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING,
                                    aiohttp.WSMsgType.ERROR):
                        return None
            except asyncio.TimeoutError:
                return None

        code = await server_close_code(ws)
        ctx.ok("tokens: B chat socket closed by admin reset", code == 4001, f"close frame code {code}")
        code = await server_close_code(ws2)
        ctx.ok("tokens: B generic socket closed by admin reset", code == 4001, f"close frame code {code}")
        st = await _status(admin, ctx, "GET", "/api/me")
        ctx.ok("tokens: admin session survives reset of another user", st == 200, f"status {st}")

        # B can sign in with the new password and the owner can revoke their own token.
        async with ctx.http() as sess_b2:
            r = await ctx.login(sess_b2, "tok_user_b", PW_B2)
            await r.read()
            st = await _status(sess_b2, ctx, "GET", "/api/me")
            ctx.ok("tokens: B signs in with the new password", st == 200, f"status {st}")

            # An admin credential without admin scope cannot revoke other users' tokens.
            async with admin.post(ctx.base_url + "/api/api-keys",
                                  json={"name": "narrow", "scopes": "services:read"}) as r:
                narrow = (await r.json()).get("key", "")
            live = [t for t in (await _state(ctx, uid_b))["tokens"] if not t["revoked"]]
            async with ctx.http() as keyless:
                st = await _status(keyless, ctx, "POST", "/api/token/revoke",
                                   json={"token_id": live[0]["token_id"]},
                                   headers={"X-API-Key": narrow})
            ctx.ok("tokens: narrowly scoped admin key cannot revoke other users' tokens",
                   bool(narrow) and st == 404, f"status {st}")
            st = await _status(sess_b2, ctx, "GET", "/api/me")
            ctx.ok("tokens: B token untouched by narrowly scoped admin key", st == 200, f"status {st}")

            # Admin can revoke any user's token.
            live = [t for t in (await _state(ctx, uid_b))["tokens"] if not t["revoked"]]
            st = await _status(admin, ctx, "POST", "/api/token/revoke",
                               json={"token_id": live[0]["token_id"]})
            ctx.ok("tokens: admin can revoke another user's token", st == 200, f"status {st}")
            st = await _status(sess_b2, ctx, "GET", "/api/me")
            ctx.ok("tokens: revoked token no longer works", st == 401, f"status {st}")

        # A plain admin cannot revoke a superadmin's token (same hierarchy as resets).
        rc, out = await ctx.run_py(
            "import asyncio\nfrom database import db\n"
            "async def m():\n await db.connect()\n u = await db.get_user_by_username(%r)\n"
            " print(u['id'])\n await db.close()\nasyncio.run(m())\n" % ctx.admin_user)
        admin_id = int(out.strip().splitlines()[-1])
        async with ctx.http() as admin2:
            r = await ctx.login(admin2, "tok_admin_2", PW_A)
            await r.read()
            tok = [t for t in (await _state(ctx, admin_id))["tokens"] if not t["revoked"]]
            st = await _status(admin2, ctx, "POST", "/api/token/revoke",
                               json={"token_id": tok[0]["token_id"]})
            ctx.ok("tokens: plain admin cannot revoke a superadmin's token", st == 404, f"status {st}")
            st = await _status(admin, ctx, "GET", "/api/me")
            ctx.ok("tokens: superadmin session still valid", st == 200, f"status {st}")

        # Admin resetting their own password keeps the current session.
        st = await _status(admin, ctx, "POST", f"/api/users/{admin_id}/reset-password",
                           json={"new_password": ctx.admin_password})
        ctx.ok("tokens: admin self-reset accepted", st == 200, f"status {st}")
        st = await _status(admin, ctx, "GET", "/api/me")
        ctx.ok("tokens: admin keeps own session after self-reset", st == 200, f"status {st}")

        audit = (await _state(ctx, uid_b))["audit"]
        actions = [a["action"] for a in audit]
        reset_rows = [a for a in audit if a["action"] == "password_reset"
                      and a["target_id"] == uid_b and a["actor_id"] == admin_id]
        ctx.ok("tokens: admin reset of another user is audited with actor and target",
               bool(reset_rows), str(audit))
        ctx.ok("tokens: cross-user token revoke is audited",
               any(a["action"] == "token_revoke" and a["target_id"] == uid_b
                   and a["actor_id"] == admin_id for a in audit), ",".join(actions))

        # A role change revokes the user's API keys as well as their sessions.
        async with ctx.http() as sess_3, ctx.http() as keyless:
            r = await ctx.login(sess_3, "tok_admin_3", PW_A)
            await r.read()
            async with sess_3.post(ctx.base_url + "/api/api-keys", json={"name": "role-key"}) as r:
                role_key = (await r.json()).get("key", "")
            st = await _status(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": role_key})
            ctx.ok("tokens: admin API key works before demotion", bool(role_key) and st == 200, f"status {st}")
            st = await _status(admin, ctx, "PUT", f"/api/users/{ids['tok_admin_3']}/role",
                               json={"role": "user"})
            ctx.ok("tokens: demotion accepted", st == 200, f"status {st}")
            st = await _status(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": role_key})
            ctx.ok("tokens: demoted admin's API key gets 401", st == 401, f"status {st}")
            st = await _status(sess_3, ctx, "GET", "/api/me")
            ctx.ok("tokens: demoted admin's session gets 401", st == 401, f"status {st}")

        # Self-service password change keeps API keys (documented behaviour).
        async with ctx.http() as sess_k, ctx.http() as keyless:
            r = await ctx.login(sess_k, "tok_user_a", PW_A)
            await r.read()
            async with sess_k.post(ctx.base_url + "/api/api-keys", json={"name": "keep-key"}) as r:
                keep_key = (await r.json()).get("key", "")
            key_ws = await sess_k.ws_connect(ctx.base_url + "/ws", headers={"X-API-Key": keep_key})
            st = await _status(sess_k, ctx, "POST", "/api/me/password",
                               json={"current_password": PW_A, "new_password": PW_B2})
            ctx.ok("tokens: self-service password change accepted", st == 200, f"status {st}")
            st = await _status(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": keep_key})
            ctx.ok("tokens: own API key survives self-service password change",
                   bool(keep_key) and st == 200, f"status {st}")
            # The socket opened with that key was not revoked, so it stays open.
            closed, detail = False, "no close frame"
            try:
                while True:
                    msg = await asyncio.wait_for(key_ws.receive(), 1.5)
                    if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                    aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                        closed, detail = True, f"message type {msg.type} data {msg.data!r}"
                        break
            except asyncio.TimeoutError:
                pass
            ctx.ok("tokens: API key socket survives self-service password change",
                   not closed and not key_ws.closed, detail)
            await key_ws.close()
