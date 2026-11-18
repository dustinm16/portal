"""Sessions page checks: a phone and a laptop show as two rows, signing the other
devices out ends the phone (its next request and its WebSocket) and keeps the
laptop, and the sign-out routes refuse what they must.

Only rows made here are asserted on, so the check also holds on a copy of a
production database (nothing counts rows of a shared table).
"""
import asyncio
import base64
import json
import secrets

import aiohttp

PW = "sessions-pass-1234"
PHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1")
LAPTOP_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0")

SETUP = '''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    out = {}
    for name in (%r, %r):
        u = await create_user(name, %r)
        out[name] = u["id"]
    await db.close()
    print(json.dumps(out))

asyncio.run(main())
'''

ROWS = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    cur = await db.conn.execute(
        "SELECT name, ip, last_ip, user_agent, last_used_at, revoked FROM tokens WHERE user_id = ? ORDER BY id", (%d,))
    rows = [dict(r) for r in await cur.fetchall()]
    cur = await db.conn.execute(
        "SELECT actor_id, target_id, details FROM audit_log WHERE action = 'sessions_revoke' AND target_id = ?", (%d,))
    audit = [dict(r) for r in await cur.fetchall()]
    cur = await db.conn.execute(
        "SELECT result, details FROM security_events WHERE event = 'session_revoked' AND user_id = ? ORDER BY id", (%d,))
    events = [dict(r) for r in await cur.fetchall()]
    await db.close()
    print(json.dumps({"tokens": rows, "audit": audit, "events": events}))

asyncio.run(main())
'''


KEY_ROW = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    cur = await db.conn.execute("SELECT last_used_at FROM api_keys WHERE user_id = ? AND name = 'sessck-key'", (%d,))
    row = await cur.fetchone()
    await db.close()
    print(json.dumps(row[0] if row else None))

asyncio.run(main())
'''


async def _rows(ctx, user_id):
    rc, out = await ctx.run_py(ROWS % (user_id, user_id, user_id))
    return json.loads(out.strip().splitlines()[-1])


async def _req(session, ctx, method, path, **kw):
    async with session.request(method, ctx.base_url + path, **kw) as r:
        raw = await r.read()
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        return r.status, data, raw.decode("utf-8", "replace")


async def _login(ctx, session, username, password, ua):
    session.headers["User-Agent"] = ua
    r = await ctx.login(session, username, password)
    return r.status


def _jti(jwt_token):
    try:
        part = jwt_token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part)).get("jti", "")
    except Exception:
        return ""


async def _close_code(sock):
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


async def run(ctx):
    sfx = secrets.token_hex(3)
    name_a, name_b = f"sessck_a_{sfx}", f"sessck_b_{sfx}"
    rc, out = await ctx.run_py(SETUP % (name_a, name_b, PW))
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ctx.ok("sessions: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    uid_a, uid_b = ids[name_a], ids[name_b]

    async with ctx.http() as phone, ctx.http() as laptop, ctx.http() as other, ctx.http() as anon:
        codes = [await _login(ctx, phone, name_a, PW, PHONE_UA),
                 await _login(ctx, laptop, name_a, PW, LAPTOP_UA),
                 await _login(ctx, other, name_b, PW, LAPTOP_UA)]
        ctx.ok("sessions: phone, laptop and another member can sign in", codes == [200, 200, 200], str(codes))
        if codes != [200, 200, 200]:
            return

        st, data, raw = await _req(anon, ctx, "GET", "/api/me/sessions")
        ctx.ok("sessions: listing needs a sign-in", st == 401, f"status {st}")

        # The first authenticated request from each device.
        for s in (phone, laptop):
            await _req(s, ctx, "GET", "/api/me")

        st, data, raw = await _req(laptop, ctx, "GET", "/api/me/sessions")
        sessions = (data or {}).get("sessions", [])
        ctx.ok("sessions: the laptop sees two rows for its account", st == 200 and len(sessions) == 2,
               f"status {st}, {len(sessions)} rows")
        current = [s for s in sessions if s.get("current")]
        ctx.ok("sessions: exactly one row is marked as this device, the laptop",
               len(current) == 1 and current[0].get("browser") == "Firefox" and current[0].get("os") == "Linux",
               str(current))
        ctx.ok("sessions: the phone row is parsed from its user agent",
               any(s.get("device") == "Safari on iOS" and not s.get("current") for s in sessions), str(sessions))
        ctx.ok("sessions: rows carry the address and times",
               all(s.get("last_ip") == "127.0.0.1" and s.get("created_at", "").endswith("Z")
                   and s.get("last_used_at") for s in sessions), str(sessions))
        # No secret of any session may be in the answer: not the cookie, not its id.
        secrets_seen = []
        for s in (phone, laptop):
            for cookie in s.cookie_jar:
                secrets_seen.append(cookie.value)
                secrets_seen.append(_jti(cookie.value))
        secrets_seen = [x for x in secrets_seen if x]
        ctx.ok("sessions: the answer holds neither a session cookie nor a token id",
               bool(secrets_seen) and not any(x in raw for x in secrets_seen))

        rows = (await _rows(ctx, uid_a))["tokens"]
        ctx.ok("sessions: login stored address and user agent",
               len(rows) == 2 and all(r["ip"] == "127.0.0.1" for r in rows)
               and {r["user_agent"] for r in rows} == {PHONE_UA, LAPTOP_UA}, str(rows)[:300])

        # last_used is written at most once a minute: a burst changes nothing.
        before = {r["user_agent"]: r["last_used_at"] for r in rows}
        for _ in range(15):
            await _req(laptop, ctx, "GET", "/api/me")
        after = {r["user_agent"]: r["last_used_at"] for r in (await _rows(ctx, uid_a))["tokens"]}
        ctx.ok("sessions: a burst of requests does not rewrite last_used", before == after, f"{before} -> {after}")

        # Credentials that are not a full session are refused.
        st, data, _ = await _req(laptop, ctx, "POST", "/api/api-keys", json={"name": "sessck-key"})
        member_key = (data or {}).get("key", "")
        st, data, _ = await _req(laptop, ctx, "POST", "/api/streams", json={"name": f"sessck-{sfx}"})
        stream_key = ((data or {}).get("stream") or {}).get("stream_key") or ""
        refused = []
        async with ctx.http() as keyless:
            if member_key:
                st, _, _ = await _req(keyless, ctx, "GET", "/api/me/sessions", headers={"X-API-Key": member_key})
                refused.append(("member API key", st))
                st, _, _ = await _req(keyless, ctx, "POST", "/api/me/sessions/revoke-others",
                                      headers={"X-API-Key": member_key})
                refused.append(("member API key revoke-others", st))
            if stream_key:
                st, _, _ = await _req(keyless, ctx, "GET", "/api/me/sessions",
                                      headers={"Authorization": "Stream-Key " + stream_key})
                refused.append(("stream key", st))
        ctx.ok("sessions: an API key and a stream key get 403",
               len(refused) >= 2 and all(st == 403 for _, st in refused), str(refused))
        if not member_key or not stream_key:
            ctx.skip("sessions: key checks incomplete", f"key={bool(member_key)} stream key={bool(stream_key)}")

        # An API key's last_used is written at most once a minute: a burst changes nothing.
        if member_key:
            async with ctx.http() as keyless:
                st, _, _ = await _req(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": member_key})
                rc, out = await ctx.run_py(KEY_ROW % uid_a)
                first = json.loads(out.strip().splitlines()[-1])
                await asyncio.sleep(1.2)
                for _ in range(10):
                    await _req(keyless, ctx, "GET", "/api/me", headers={"X-API-Key": member_key})
                rc, out = await ctx.run_py(KEY_ROW % uid_a)
                second = json.loads(out.strip().splitlines()[-1])
            ctx.ok("sessions: a burst of API key requests does not rewrite the key's last_used",
                   st == 200 and bool(first) and first == second, f"status {st}: {first} -> {second}")

        # Single revoke guards.
        phone_id = next(s["id"] for s in sessions if not s["current"])
        current_id = current[0]["id"]
        st, data, _ = await _req(laptop, ctx, "DELETE", f"/api/me/sessions/{current_id}")
        ctx.ok("sessions: the current session cannot be signed out here (400 with a hint)",
               st == 400 and "Log out" in (data or {}).get("error", ""), f"{st} {data}")
        st, data, _ = await _req(laptop, ctx, "DELETE", "/api/me/sessions/" + "0" * 16)
        ctx.ok("sessions: an unknown id answers 404", st == 404, f"status {st}")
        st, other_list, _ = await _req(other, ctx, "GET", "/api/me/sessions")
        other_id = ((other_list or {}).get("sessions") or [{}])[0].get("id", "x")
        st, data, _ = await _req(laptop, ctx, "DELETE", f"/api/me/sessions/{other_id}")
        ctx.ok("sessions: another member's session id answers 404 and stays signed in",
               st == 404 and (await _req(other, ctx, "GET", "/api/me"))[0] == 200, f"status {st}")

        # Sign the other devices out: the phone's socket and next request end.
        phone_ws = await phone.ws_connect(ctx.base_url + "/ws")
        laptop_ws = await laptop.ws_connect(ctx.base_url + "/ws")
        st, data, _ = await _req(phone, ctx, "GET", "/api/me")
        ctx.ok("sessions: the phone works before the sign-out", st == 200, f"status {st}")
        st, data, _ = await _req(laptop, ctx, "POST", "/api/me/sessions/revoke-others")
        ctx.ok("sessions: sign out other devices is accepted", st == 200 and (data or {}).get("revoked") == 1,
               f"{st} {data}")
        events = (await _rows(ctx, uid_a))["events"]
        others = [e for e in events if e["result"] == "others"]
        ctx.ok("sessions: signing out other devices is one security event with the number ended",
               len(others) == 1 and json.loads(others[0]["details"]).get("sessions_revoked") == 1, str(events))
        st, _, _ = await _req(phone, ctx, "GET", "/api/me")
        ctx.ok("sessions: the phone's next request answers 401", st == 401, f"status {st}")
        code = await _close_code(phone_ws)
        ctx.ok("sessions: the phone's WebSocket is closed with 4001", code == 4001, f"close code {code}")
        st, _, _ = await _req(laptop, ctx, "GET", "/api/me")
        ctx.ok("sessions: the laptop stays signed in", st == 200 and not laptop_ws.closed, f"status {st}")
        await laptop_ws.close()
        st, data, _ = await _req(laptop, ctx, "GET", "/api/me/sessions")
        ctx.ok("sessions: afterwards the laptop is the only row, and current",
               st == 200 and len(data["sessions"]) == 1 and data["sessions"][0]["current"])
        st, _, _ = await _req(other, ctx, "GET", "/api/me")
        ctx.ok("sessions: another member is not affected", st == 200, f"status {st}")

        # Revoke one by id (a second sign-in first).
        async with ctx.http() as tablet:
            await _login(ctx, tablet, name_a, PW, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36")
            await _req(tablet, ctx, "GET", "/api/me")
            st, data, _ = await _req(laptop, ctx, "GET", "/api/me/sessions")
            tab = [s for s in data["sessions"] if not s["current"]]
            st, _, _ = await _req(laptop, ctx, "DELETE", f"/api/me/sessions/{tab[0]['id']}") if tab else (0, 0, 0)
            ctx.ok("sessions: one device can be signed out by its id", bool(tab) and st == 200, f"status {st}")
            events = (await _rows(ctx, uid_a))["events"]
            ctx.ok("sessions: signing out one device is a security event for the user",
                   len([e for e in events if e["result"] == "own"]) == 1, str(events))
            st, _, _ = await _req(tablet, ctx, "GET", "/api/me")
            ctx.ok("sessions: that device's next request answers 401", st == 401, f"status {st}")
            st, _, _ = await _req(laptop, ctx, "GET", "/api/me")
            ctx.ok("sessions: the laptop is still signed in", st == 200, f"status {st}")

        # A member cannot use the admin route.
        st, _, _ = await _req(laptop, ctx, "POST", f"/api/users/{uid_b}/sessions/revoke")
        ctx.ok("sessions: a member gets 403 on the admin sign-out route", st == 403, f"status {st}")
        st, _, _ = await _req(other, ctx, "GET", "/api/me")
        ctx.ok("sessions: and nobody was signed out by it", st == 200, f"status {st}")

        if not ctx.admin_password:
            ctx.skip("sessions: admin sign-out everywhere", "no admin password (copied database)")
            return

        async with ctx.http() as adm1, ctx.http() as adm2:
            r1 = await _login(ctx, adm1, ctx.admin_user, ctx.admin_password, LAPTOP_UA)
            r2 = await _login(ctx, adm2, ctx.admin_user, ctx.admin_password, PHONE_UA)
            ctx.ok("sessions: admin can sign in twice", r1 == 200 and r2 == 200, f"{r1} {r2}")
            if r1 != 200 or r2 != 200:
                return
            st, me, _ = await _req(adm1, ctx, "GET", "/api/me")
            admin_id = (me or {}).get("id") or (me or {}).get("user", {}).get("id")
            await _req(adm2, ctx, "GET", "/api/me")
            st, data, _ = await _req(adm1, ctx, "POST", f"/api/users/{admin_id}/sessions/revoke")
            ctx.ok("sessions: admin sign-out everywhere on themselves keeps the session in use",
                   st == 200 and (data or {}).get("kept_current_session") is True, f"{st} {data}")
            st, _, _ = await _req(adm1, ctx, "GET", "/api/me")
            ctx.ok("sessions: the admin stays signed in after signing themselves out everywhere", st == 200, f"status {st}")
            st, _, _ = await _req(adm2, ctx, "GET", "/api/me")
            ctx.ok("sessions: the admin's other session is signed out", st == 401, f"status {st}")

            st, _, _ = await _req(adm1, ctx, "POST", "/api/users/999999999/sessions/revoke")
            ctx.ok("sessions: an unknown user answers 404", st == 404, f"status {st}")
            st, data, _ = await _req(adm1, ctx, "POST", f"/api/users/{uid_b}/sessions/revoke")
            ctx.ok("sessions: admin sign-out everywhere on a member is accepted",
                   st == 200 and (data or {}).get("revoked", 0) >= 1, f"{st} {data}")
            st, _, _ = await _req(other, ctx, "GET", "/api/me")
            ctx.ok("sessions: the member's session is signed out", st == 401, f"status {st}")
            audit = (await _rows(ctx, uid_b))["audit"]
            ctx.ok("sessions: the admin action is audited with actor and target",
                   len(audit) == 1 and audit[0]["actor_id"] == admin_id, str(audit))
            events = [e for e in (await _rows(ctx, admin_id))["events"] if e["result"] == "admin_all"]
            hit = [e for e in events if json.loads(e["details"]).get("target_user_id") == uid_b]
            ctx.ok("sessions: the admin action is a security event with actor and target",
                   len(hit) == 1 and json.loads(hit[0]["details"]).get("target_username") == name_b, str(events)[:300])
            st, _, _ = await _req(laptop, ctx, "GET", "/api/me")
            ctx.ok("sessions: an unrelated member keeps their session", st == 200, f"status {st}")
