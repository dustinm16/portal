"""Smoke checks: failed sign-in address bans, over HTTP against the staged server.

A real flood needs the client address to be somebody other than 127.0.0.1 (loopback is never
banned), so the staged server is restarted with TRUSTED_PROXIES=127.0.0.1,::1 in its process
environment (never in a file) and each request names its client in CF-Connecting-IP with a random
public address. Settings are written into the staged database while the server is stopped (the
module needs no admin password for that) and restored at the end; the server is restarted several
times to prove that a ban survives a restart, that an expired row is ignored when it is loaded and
that the command-line unblock clears a ban.

Users and addresses carry a random suffix and the module only asserts on its own rows, so it also
passes on a copy of a production database (--from-db). The admin list check needs an admin
password and is skipped without one.
"""

import json
import random
import secrets
import sqlite3

SUFFIX = secrets.token_hex(3)
USER_A = f"smoke_lb_a_{SUFFIX}"
USER_B = f"smoke_lb_b_{SUFFIX}"
PASSWORD = "Smoke-LoginBan-Pw-1!"
SETTING_KEYS = ("login_ban_enabled", "login_ban_max_failures", "login_ban_find_minutes", "login_ban_base_minutes")

CREATE_USERS = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    for name in ({USER_A!r}, {USER_B!r}):
        if not await database.db.get_user_by_username(name):
            await create_user(name, {PASSWORD!r}, is_admin=False)
    await database.db.close()

asyncio.run(main())
"""

CLI = """
import subprocess, sys
r = subprocess.run([sys.executable, 'server.py'] + sys.argv_list, capture_output=True, text=True)
print('RC=' + str(r.returncode))
print(r.stdout)
print(r.stderr)
"""


def _addr():
    return f"45.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"


def _sql(ctx, sql, args=()):
    c = sqlite3.connect(str(ctx.stage_dir / "portal.db"), timeout=30)
    try:
        rows = c.execute(sql, args).fetchall()
        c.commit()
        return rows
    finally:
        c.close()


def _row(ctx, addr):
    r = _sql(ctx, "SELECT kind, source, expires_at, expires_at > datetime('now') FROM blocked_ips WHERE ip_address = ?", (addr,))
    return r[0] if r else None


async def _wrong(ctx, session, addr, user, n):
    got = []
    for _ in range(n):
        async with session.post(f"{ctx.base_url}/login", json={"username": user, "password": "wrong-" + SUFFIX},
                                headers={"CF-Connecting-IP": addr}) as r:
            await r.read()
            got.append(r.status)
    return got


async def _health(ctx, session, addr):
    async with session.get(f"{ctx.base_url}/health", headers={"CF-Connecting-IP": addr}) as r:
        await r.read()
        return r.status


async def _restart(ctx):
    await ctx.stop_server()
    await ctx.start_server(wait_healthy=True)


async def run(ctx):
    rc, out = await ctx.run_py(CREATE_USERS)
    ctx.ok("loginban: create two test users", rc == 0, out.strip()[-200:])
    if rc != 0:
        return

    addr1, addr2, addr0 = _addr(), _addr(), _addr()
    saved = {k: _sql(ctx, "SELECT value FROM settings WHERE key = ?", (k,)) for k in SETTING_KEYS}
    envs = [e for e in (getattr(ctx, "_env", None), getattr(ctx.server, "env", None)) if e is not None]
    had_trust = [e.get("TRUSTED_PROXIES") for e in envs]
    try:
        # ---- loopback trusted as the proxy, setting absent (the default): nothing is banned
        await ctx.stop_server()
        for k in SETTING_KEYS:
            _sql(ctx, "DELETE FROM settings WHERE key = ?", (k,))
        for e in envs:
            e["TRUSTED_PROXIES"] = "127.0.0.1,::1"
        await ctx.start_server(wait_healthy=True)
        trusted = "loopback trusted: True" in ctx.server_log()
        if not trusted:
            ctx.skip("loginban: flood checks", "the staged server did not take TRUSTED_PROXIES from its environment")
            return

        async with ctx.http() as s:
            got = await _wrong(ctx, s, addr0, USER_A, 25)
            ctx.ok("loginban: off by default, 25 wrong passwords from one address are all refused with 401 and none blocked",
                   set(got) == {401} and _row(ctx, addr0) is None and await _health(ctx, s, addr0) == 200, str(got))

        # ---- turn it on (small numbers) while stopped, restart
        await ctx.stop_server()
        for k, v in (("login_ban_enabled", "1"), ("login_ban_max_failures", "3"),
                     ("login_ban_find_minutes", "10"), ("login_ban_base_minutes", "1")):
            _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
        await ctx.start_server(wait_healthy=True)

        async with ctx.http() as s:
            got = await _wrong(ctx, s, addr1, USER_A, 3)
            row = _row(ctx, addr1)
            ctx.ok("loginban: the third wrong password writes a temporary 'login' ban with an expiry",
                   row is not None and row[0] == "login" and row[1] == "auto" and row[2] and row[3] == 1, f"{got} {row}")
            ctx.ok("loginban: the banned address now gets 403 on every request", await _health(ctx, s, addr1) == 403)
            ev = _sql(ctx, "SELECT details FROM security_events WHERE event = 'ip_blocked' AND ip = ? ORDER BY id DESC LIMIT 1", (addr1,))
            det = json.loads(ev[0][0]) if ev and ev[0][0] else {}
            ctx.ok("loginban: the ban is a security event with kind, expiry and duration",
                   det.get("kind") == "login" and det.get("seconds") == 60 and det.get("offences") == 1, str(det))
            ctx.ok("loginban: other addresses are unaffected", await _health(ctx, s, addr0) == 200)

            got = await _wrong(ctx, s, "127.0.0.1", USER_A, 8)
            async with s.get(f"{ctx.base_url}/health") as r:
                await r.read()
                loop_status = r.status
            ctx.ok("loginban: the same flood from 127.0.0.1 bans nothing", set(got) == {401} and loop_status == 200, f"{got} {loop_status}")

            # household: a sign-in from addr2, then typos for the same user never ban; another user's do
            async with s.post(f"{ctx.base_url}/login", json={"username": USER_A, "password": PASSWORD},
                              headers={"CF-Connecting-IP": addr2}) as r:
                await r.read()
                good = r.status
            got = await _wrong(ctx, s, addr2, USER_A, 6)
            ctx.ok("loginban: typos against an account the address signed in to are not counted",
                   good == 200 and set(got) == {401} and _row(ctx, addr2) is None and await _health(ctx, s, addr2) == 200,
                   f"login {good} {got}")
            await _wrong(ctx, s, addr2, USER_B, 3)
            ctx.ok("loginban: the household exemption is for that account only", _row(ctx, addr2) is not None)

        # ---- the admin list shows kind and expiry
        if ctx.admin_password:
            async with ctx.http() as adm:
                r = await ctx.login(adm, ctx.admin_user, ctx.admin_password)
                if r.status != 200:
                    ctx.ok("loginban: admin login", False, f"status {r.status}")
                else:
                    async with adm.get(f"{ctx.base_url}/api/admin/blocked-ips", headers={"Accept": "application/json"}) as r2:
                        body = await r2.json(content_type=None)
                    mine = [b for b in body.get("blocked_ips", []) if b["ip_address"] == addr1]
                    ctx.ok("loginban: the admin address-blocks list shows the ban with its kind and expiry",
                           len(mine) == 1 and mine[0]["kind"] == "login" and bool(mine[0]["expires_at"]), str(mine))
                    async with adm.get(f"{ctx.base_url}/api/admin/login-ban", headers={"Accept": "application/json"}) as r3:
                        cfg = await r3.json(content_type=None)
                    ctx.ok("loginban: the settings route shows what was saved",
                           cfg.get("enabled") is True and cfg.get("max_failures") == 3 and cfg.get("base_minutes") == 1, str(cfg))
        else:
            ctx.skip("loginban: admin list and settings route", "no admin password (use --admin-password)")

        # ---- restart: the ban survives
        await _restart(ctx)
        async with ctx.http() as s:
            ctx.ok("loginban: the ban survives a restart", _row(ctx, addr1) is not None and await _health(ctx, s, addr1) == 403)

        # ---- an expired row is ignored when loaded, and swept
        await ctx.stop_server()
        _sql(ctx, "UPDATE blocked_ips SET expires_at = datetime('now', '-1 minute') WHERE ip_address = ?", (addr1,))
        await ctx.start_server(wait_healthy=True)
        async with ctx.http() as s:
            ctx.ok("loginban: an expired ban is ignored at start and its row is swept",
                   await _health(ctx, s, addr1) == 200 and _row(ctx, addr1) is None)

            # ---- second offence doubles
            await _wrong(ctx, s, addr1, USER_A, 3)
            ev = _sql(ctx, "SELECT details FROM security_events WHERE event = 'ip_blocked' AND ip = ? ORDER BY id DESC LIMIT 1", (addr1,))
            det = json.loads(ev[0][0]) if ev and ev[0][0] else {}
            ctx.ok("loginban: a second offence within 7 days doubles the time (60 s to 120 s)",
                   det.get("offences") == 2 and det.get("seconds") == 120, str(det))

        # ---- command-line unblock
        await ctx.stop_server()
        code = CLI.replace("sys.argv_list", repr(["unblock", addr1]))
        rc, out = await ctx.run_py(code)
        hist = _sql(ctx, "SELECT COUNT(*) FROM ip_ban_history WHERE ip_address = ?", (addr1,))[0][0]
        ctx.ok("loginban: `server.py unblock` removes the ban and its history and names its kind",
               "RC=0" in out and _row(ctx, addr1) is None and hist == 0 and "login" in out, out.strip()[-300:])
        await ctx.start_server(wait_healthy=True)
        async with ctx.http() as s:
            ctx.ok("loginban: the unblocked address is served again", await _health(ctx, s, addr1) == 200)
    finally:
        try:
            await ctx.stop_server()
        except Exception:
            pass
        for k in SETTING_KEYS:
            _sql(ctx, "DELETE FROM settings WHERE key = ?", (k,))
            if saved.get(k):
                _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, saved[k][0][0]))
        for a in (addr0, addr1, addr2):
            _sql(ctx, "DELETE FROM blocked_ips WHERE ip_address = ?", (a,))
            _sql(ctx, "DELETE FROM ip_ban_history WHERE ip_address = ?", (a,))
            _sql(ctx, "DELETE FROM login_addresses WHERE ip_address = ?", (a,))
        for e, was in zip(envs, had_trust):
            if was is None:
                e.pop("TRUSTED_PROXIES", None)
            else:
                e["TRUSTED_PROXIES"] = was
        await ctx.start_server(wait_healthy=True)
