"""Security event log on a staged instance.

Failed logins for an unknown user, a wrong 2FA code and an API key creation
appear with IP and user agent; a 500-attempt scripted flood costs a few
aggregated rows, one IPv6 /64 rotating its address is one row and a bidi override in a typed
name is stripped; the log can be read and exported by a superadmin only; and no
password, code, token or key shows up in any row.

Everything is asserted on this module's own rows (unique user agents and
account names), never on totals of shared tables, so it also holds on a
production database copy. Steps that need the admin password are skipped
without one.
"""

import asyncio
import csv
import io
import json
import os
import secrets
import sqlite3
import time

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user, generate_totp_secret, generate_backup_codes

async def main():
    await db.connect()
    out = {}
    for name, twofa in (("se_plain", False), ("se_2fa", True)):
        pw = "Pw-" + name + "-12345!"
        user = await create_user(name, pw, is_admin=False)
        rec = {"id": user["id"], "password": pw}
        if twofa:
            secret = generate_totp_secret()
            await db.set_user_totp_secret(user["id"], secret)
            backup = generate_backup_codes(2)
            await db.enable_user_totp(user["id"], backup)
            rec["secret"] = secret
            rec["backup"] = backup
        out[name] = rec
    await db.conn.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

CAP_PROBE = r'''
import asyncio, json, time, secevents
from database import db

async def main():
    await db.connect()
    log = secevents.SecurityEventLog(db)
    now = float(int(time.time() // 60) * 60 - 3600)     # a minute boundary, an hour ago
    sent = 0
    for rnd in range(12):
        for i in range(secevents.BUFFER_MAX_KEYS + 500):
            sent += 1
            log.note("rate_limited", ip="10.%d.%d.%d" % ((sent >> 16) & 255, (sent >> 8) & 255, sent & 255),
                     result="{cap_tag}", now=now + rnd * 4)
        await log.flush()
    # each probe has its own minute: a minute's row budget is shared by every source
    for i in range(3000):
        log.note("login_failed", ip="2001:db8:ab:cd::%x" % (i + 1), result="{v6_tag}", now=now + 60)
    await log.flush()
    log.note("login_failed", ip="203.0.113.9", username={bidi!r}, result="{bidi_tag}", now=now + 120)
    await log.flush()
    await db.conn.close()
    print("RESULT " + json.dumps({{"cap": getattr(secevents, "MINUTE_MAX_KEYS", secevents.BUFFER_MAX_KEYS), "sent": sent, "net": "2001:db8:ab:cd::/64"}}))

asyncio.run(main())
'''

FLUSH_WAIT = 25.0       # the server flushes its buffer every few seconds


def _rows(ctx, where, params=()):
    conn = sqlite3.connect(os.path.join(ctx.stage_dir, "portal.db"))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM security_events WHERE {where} ORDER BY id", params)]
    finally:
        conn.close()


async def _wait_rows(ctx, where, params=(), minimum=1, timeout=FLUSH_WAIT):
    end = time.monotonic() + timeout
    while True:
        got = _rows(ctx, where, params)
        if len(got) >= minimum or time.monotonic() > end:
            return got
        await asyncio.sleep(0.5)


def _parse(output):
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    raise RuntimeError("no RESULT line in: " + output[-400:])


async def run(ctx):
    import pyotp

    rc, out = await ctx.run_py(SETUP)
    if rc != 0:
        ctx.ok("secevents: create test users", False, out[-400:])
        return
    users = _parse(out)
    ctx.ok("secevents: create test users", True)
    tag = secrets.token_hex(4)
    secrets_used = [users["se_plain"]["password"], users["se_2fa"]["password"],
                    users["se_2fa"]["secret"], *users["se_2fa"]["backup"]]

    conn = sqlite3.connect(os.path.join(ctx.stage_dir, "portal.db"))
    try:
        have_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'security_events'").fetchone()
    finally:
        conn.close()
    ctx.ok("secevents: the security_events table exists", bool(have_table))
    if not have_table:
        return

    # Aggregated rows are keyed by source and minute and keep the first
    # username and agent they see. Start the aggregated probes at the top of a
    # minute so no earlier module's row from the same minute owns the row.
    wait = 61 - (time.time() % 60)
    if wait < 59:
        await asyncio.sleep(wait)
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    ua_unknown = f"secevents-unknown/{tag}"
    ua_2fa = f"secevents-2fa/{tag}"
    ua_key = f"secevents-key/{tag}"
    ghost = f"se_ghost_{tag}"
    wrong_code = "918273"
    code_now = pyotp.TOTP(users["se_2fa"]["secret"]).now()
    if wrong_code == code_now:
        wrong_code = "123123"
    secrets_used.extend([wrong_code, code_now])

    def ua_http(ua):
        s = ctx.http()
        s.headers.update({"User-Agent": ua})
        return s

    # ---- unknown user, wrong password, 2FA failure, API key creation
    async with ua_http(ua_unknown) as s:
        r = await ctx.login(s, ghost, "whatever-password-1")
        ctx.ok("secevents: unknown-user login is refused", r.status == 401, str(r.status))
    got = await _wait_rows(ctx, "event = 'login_failed' AND user_agent = ?", (ua_unknown,))
    ctx.ok("secevents: unknown-user failure has ip, user agent and reason, and the fixed text instead of the typed name",
           len(got) == 1 and got[0]["ip"] == "127.0.0.1" and got[0]["user_agent"] == ua_unknown
           and got[0]["result"] == "unknown_user" and got[0]["user_id"] is None
           and got[0]["username_tried"] == "(unknown account)"
           and got[0]["category"] == "auth", str(got)[:300])
    ctx.ok("secevents: the typed name of an unknown account is in no row and not in the server log",
           not _rows(ctx, "username_tried = ? OR details LIKE ?", (ghost, f"%{ghost}%"))
           and ghost not in ctx.server_log() and "Failed web login for an unknown account" in ctx.server_log())

    async with ua_http(ua_2fa) as s:
        r = await ctx.login(s, "se_2fa", users["se_2fa"]["password"], totp_code=wrong_code)
        ctx.ok("secevents: wrong 2FA code is refused", r.status == 401, str(r.status))
    uid2 = users["se_2fa"]["id"]
    got = await _wait_rows(ctx, "event = '2fa_failed' AND user_id = ?", (uid2,))
    ctx.ok("secevents: 2FA failure has ip, user agent and the account",
           len(got) == 1 and got[0]["ip"] == "127.0.0.1" and got[0]["user_agent"] == ua_2fa
           and got[0]["username_tried"] == "se_2fa", str(got)[:300])

    session_cookie = None
    api_key = None
    async with ua_http(ua_key) as s:
        r = await ctx.login(s, "se_plain", users["se_plain"]["password"])
        ctx.ok("secevents: test user signs in", r.status == 200, str(r.status))
        async with s.post(ctx.base_url + "/api/api-keys", json={"name": f"se-key-{tag}"}) as r:
            body = await r.json(content_type=None)
            api_key = body.get("key")
            ctx.ok("secevents: API key is created", r.status == 201 and bool(api_key), str(r.status))
        if api_key:
            secrets_used.append(api_key)
        session_cookie = next((c.value for c in s.cookie_jar if c.key), None)
        if session_cookie:
            secrets_used.append(session_cookie)
        key_id = body.get("id")
        # a non-superadmin cannot read or export the log
        async with s.get(ctx.base_url + "/api/admin/security-events") as r:
            ctx.ok("secevents: a plain user cannot read the log", r.status in (401, 403), str(r.status))
        async with s.get(ctx.base_url + "/api/admin/security-events/export") as r:
            ctx.ok("secevents: a plain user cannot export the log", r.status in (401, 403), str(r.status))
        if key_id:
            async with s.post(ctx.base_url + f"/api/api-keys/{key_id}/revoke") as r:
                ctx.ok("secevents: API key is revoked", r.status == 200, str(r.status))
            async with s.delete(ctx.base_url + f"/api/api-keys/{key_id}") as r:
                ctx.ok("secevents: API key is deleted", r.status == 200, str(r.status))
    uid1 = users["se_plain"]["id"]
    for ev in ("login_success", "api_key_created", "api_key_revoked", "api_key_deleted"):
        got = await _wait_rows(ctx, "event = ? AND user_id = ?", (ev, uid1))
        ctx.ok(f"secevents: {ev} is written with ip and user agent",
               len(got) >= 1 and got[0]["ip"] == "127.0.0.1" and got[0]["user_agent"] == ua_key
               and got[0]["username_tried"] == "se_plain", str(got)[:300])
    got = _rows(ctx, "event = 'api_key_created' AND user_id = ?", (uid1,))
    ctx.ok("secevents: the API key row holds the key id and name, not the key",
           bool(got) and f"se-key-{tag}" in (got[0]["details"] or "") and api_key not in json.dumps(got), "")

    # ---- a 500-attempt flood from one address
    t0 = time.time()
    ua_flood = f"secevents-flood/{tag}"
    async with ua_http(ua_flood) as s:
        sem = asyncio.Semaphore(20)

        async def attempt(i):
            async with sem:
                async with s.post(ctx.base_url + "/login",
                                  json={"username": f"se_flood_{tag}_{i}", "password": "x"}) as r:
                    await r.read()
                    return r.status

        statuses = await asyncio.gather(*(attempt(i) for i in range(500)))
    ctx.ok("secevents: all 500 flood attempts were answered 401", set(statuses) == {401},
           str(sorted(set(statuses))))
    end_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    await asyncio.sleep(7)       # a flush interval and a margin
    flood_rows = _rows(ctx, "event = 'login_failed' AND result = 'unknown_user' AND ip = '127.0.0.1' "
                            "AND ts >= ?", (start,))
    total = sum(r["count"] for r in flood_rows)
    minutes = int((time.time() - (t0 - 60)) // 60) + 2
    ctx.ok("secevents: the flood is counted in full", total >= 501, f"count={total}")
    ctx.ok("secevents: the flood is a few aggregated rows",
           1 <= len(flood_rows) <= minutes, f"rows={len(flood_rows)} (window {start} .. {end_ts})")
    named = [r for r in _rows(ctx, "username_tried LIKE ?", (f"se_flood_{tag}_%",))]
    ctx.ok("secevents: the flood did not write one row per attempt", len(named) <= minutes, f"rows={len(named)}")

    # ---- the row cap holds across flushes, an IPv6 /64 is one source, and typed names are
    # stripped of bidi and zero-width characters. The staged server trusts no proxy header
    # (TRUSTED_PROXIES is empty), so these run the real writer against the stage database.
    cap_tag = f"cap{tag}"
    v6_tag = f"v6{tag}"
    bidi_name = f"\u202e{tag}nimda\u200b\u2066x\u2069"
    rc, out = await ctx.run_py(CAP_PROBE.format(cap_tag=cap_tag, v6_tag=v6_tag, bidi_tag=f"bidi{tag}", bidi=bidi_name), timeout=240)
    probe = {}
    try:
        probe = _parse(out)
    except Exception:
        pass
    ctx.ok("secevents: the row-cap probe ran", rc == 0 and bool(probe), f"rc={rc} {out[-300:]}")
    if probe:
        cap = probe["cap"]
        cap_rows = _rows(ctx, "event = 'rate_limited' AND result = ?", (cap_tag,))
        ctx.ok("secevents: 12 flushes of distinct sources in one minute stay within the row cap",
               len(cap_rows) <= cap + 1, f"rows={len(cap_rows)} cap={cap}")
        ctx.ok("secevents: every event of that flood is counted in a row or the overflow bucket",
               sum(r["count"] for r in cap_rows) == probe["sent"],
               f"{sum(r['count'] for r in cap_rows)} of {probe['sent']}")
        v6_rows = _rows(ctx, "event = 'login_failed' AND result = ?", (v6_tag,))
        ctx.ok("secevents: 3000 addresses of one IPv6 /64 are one row under the network",
               len(v6_rows) == 1 and v6_rows[0]["count"] == 3000 and v6_rows[0]["ip"] == probe["net"],
               str(v6_rows)[:300])
        bidi_rows = _rows(ctx, "event = 'login_failed' AND result = ?", (f"bidi{tag}",))
        ctx.ok("secevents: a typed name has no bidi or zero-width characters in its row",
               len(bidi_rows) == 1 and bidi_rows[0]["username_tried"] == f"{tag}nimdax", str(bidi_rows)[:300])

    # ---- command-line role change (the process binds the log itself)
    rc, out = await ctx.run_py("import asyncio, server; asyncio.run(server.set_admin_cli('se_plain'))")
    cli = _rows(ctx, "event = 'role_changed' AND user_id = ?", (uid1,))
    ctx.ok("secevents: a command-line role change is recorded",
           rc == 0 and len(cli) == 1 and '"via":"cli"' in cli[0]["details"]
           and '"new_role":"admin"' in cli[0]["details"], f"rc={rc} {out[-200:]} {cli}"[:300])

    # ---- no secret in any row
    blob = "\n".join(json.dumps(r) for r in _rows(ctx, "ts >= ?", (start,)))
    leaked = [x for x in secrets_used if x and x in blob]
    ctx.ok("secevents: no password, code, key or session token appears in any row since the start",
           not leaked and len(secrets_used) >= 6, f"leaked={len(leaked)}")

    # ---- reading and export: superadmin
    if not ctx.admin_password:
        for name in ("superadmin reads the Security view and the Auth filter",
                     "export returns the filtered rows (CSV and JSON)",
                     "each export is recorded once",
                     "retention setting is listed with its default"):
            ctx.skip("secevents: " + name, "no admin password (use --admin-password)")
        return

    async with ctx.http() as admin:
        r = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
        await r.read()
        base = ctx.base_url
        async with admin.get(base + "/api/admin/security-events?limit=1") as r:
            status = r.status
        if status == 403:
            for name in ("superadmin reads the Security view and the Auth filter",
                         "export returns the filtered rows (CSV and JSON)",
                         "each export is recorded once",
                         "retention setting is listed with its default"):
                ctx.skip("secevents: " + name, "the admin account is not a superadmin")
            return
        async with admin.get(base + f"/api/admin/security-events?event=api_key_created&since={start[:10]}"
                                    f"&limit=200") as r:
            data = await r.json(content_type=None)
        mine = [e for e in data.get("events", []) if e.get("user_agent") == ua_key]
        ctx.ok("secevents: the Security view lists the API key creation with ip and user agent",
               r.status == 200 and len(mine) == 1 and mine[0]["ip"] == "127.0.0.1", str(data)[:200])
        # The Security view sends no category: the failed login, the 2FA failure and the
        # API key creation must all be in it, each with ip and user agent.
        seen = {}
        for ua, ev in ((ua_unknown, "login_failed"), (ua_2fa, "2fa_failed"), (ua_key, "api_key_created")):
            async with admin.get(base + f"/api/admin/security-events?event={ev}&since={start[:10]}"
                                        f"&limit=200") as r:
                got = await r.json(content_type=None)
            seen[ev] = [e for e in got.get("events", [])
                        if e.get("user_agent") == ua and e.get("ip") == "127.0.0.1"]
        ctx.ok("secevents: the unfiltered Security view shows the failed login, the 2FA failure and the API key",
               all(len(v) == 1 for v in seen.values()), str({k: len(v) for k, v in seen.items()}))
        async with admin.get(base + f"/api/admin/security-events?category=auth&event=login_failed"
                                    f"&username=%28unknown%20account%29&since={start[:10]}&limit=200") as r:
            data = await r.json(content_type=None)
        ctx.ok("secevents: the Auth filter lists the unknown-user failure (under the fixed text) and only auth rows",
               r.status == 200 and sum(1 for e in data["events"] if e.get("user_agent") == ua_unknown) == 1
               and all(e["category"] == "auth" for e in data["events"]), str(data)[:200])
        async with admin.get(base + "/api/admin/security-events?category=security&username=se_plain") as r:
            data = await r.json(content_type=None)
        ctx.ok("secevents: the security category holds credential events and no auth rows",
               r.status == 200 and data["events"]
               and all(e["category"] == "security" for e in data["events"]), str(data)[:200])

        before = len(_rows(ctx, "event = 'security_log_export'"))
        q = f"event=api_key_created&since={start[:10]}"
        async with admin.get(base + f"/api/admin/security-events/export?format=csv&{q}") as r:
            text = await r.text()
            csv_status, disp = r.status, r.headers.get("Content-Disposition", "")
        parsed = list(csv.reader(io.StringIO(text)))
        header = parsed[0] if parsed else []
        ua_col = header.index("user_agent") if "user_agent" in header else -1
        csv_hits = [row for row in parsed[1:] if ua_col >= 0 and row[ua_col] == ua_key]
        async with admin.get(base + f"/api/admin/security-events/export?format=json&{q}") as r:
            exported = json.loads(await r.text())
            json_status = r.status
        json_hits = [e for e in exported.get("events", []) if e.get("user_agent") == ua_key]
        ctx.ok("secevents: CSV and JSON exports return the filtered rows",
               csv_status == 200 and json_status == 200 and "attachment" in disp
               and len(csv_hits) == 1 and len(json_hits) == 1
               and all(e["event"] == "api_key_created" for e in exported["events"])
               and exported["count"] == len(exported["events"]), f"{csv_status} {json_status} {len(parsed)}")
        async with admin.get(base + "/api/admin/security-events/export?format=json&since=2999-01-01") as r:
            empty = json.loads(await r.text())
        ctx.ok("secevents: the date range limits the export", empty["events"] == [])
        after = _rows(ctx, "event = 'security_log_export'")
        ctx.ok("secevents: each export is recorded once",
               len(after) - before == 3 and after[-1]["ip"] == "127.0.0.1", f"{len(after) - before} new")

        async with admin.get(base + "/api/admin/retention") as r:
            ret = await r.json(content_type=None)
        ctx.ok("secevents: the retention setting is listed",
               r.status == 200 and "retention_security_events_days" in ret, str(ret)[:200])
