"""Smoke checks: lockout-safe blocking foundations and the Cloudflare range refresh.

Covers, on the staged instance:
  - the never-ban list routes (superadmin only, strict validation, the effective list, the note about
    the saver's own address); every setting touched is restored at the end
  - the proxy-trust self-check: the startup warning in the server log, the admin endpoint after a burst
    of loopback requests carrying Cloudflare headers, and that trust is never changed by it
  - the Cloudflare refresh setting and last-result view (the refresh itself never runs in a stage; the
    parser, the swap and the fetcher are driven with injected text and a local HTTPS server by
    tests/test_cf_ranges.py, run here against the staged copy of the code)
  - tests/test_blocking.py against the staged copy of the code
  - the lockout recovery path: a block on 127.0.0.1 really locks the staged server, `server.py unblock`
    removes it with the server stopped, runs no migration, and the admin can log in again

Rows it creates carry a marker reason and are removed again; it asserts on its own rows only, so it also
passes on a copy of a production database (--from-db).
"""

import asyncio
import hashlib
import sqlite3

MARKER = "smoke-blocking-marker"
USER = "smoke_blocking_user"
PASSWORD = "Smoke-Blocking-Pw-1!"

CREATE_USER = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    if not await database.db.get_user_by_username({USER!r}):
        await create_user({USER!r}, {PASSWORD!r}, is_admin=False)
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


def _schema_hash(path) -> str:
    c = sqlite3.connect(str(path))
    try:
        rows = c.execute("SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name").fetchall()
    finally:
        c.close()
    return hashlib.sha256(repr(rows).encode()).hexdigest()[:16]


def _db(ctx):
    return ctx.stage_dir / "portal.db"


def _sql(ctx, sql, args=()):
    c = sqlite3.connect(str(_db(ctx)), timeout=30)
    try:
        cur = c.execute(sql, args)
        rows = cur.fetchall()
        c.commit()
        return rows
    finally:
        c.close()


async def _cli(ctx, *args):
    code = CLI.replace("sys.argv_list", repr(list(args)))
    rc, out = await ctx.run_py(code)
    line = next((l for l in out.splitlines() if l.startswith("RC=")), "RC=-1")
    return int(line[3:]), out


async def _health_status(ctx, tries=120):
    """Status of GET /health once the server answers at all (any status), or None."""
    async with ctx.http() as s:
        for _ in range(tries):
            try:
                async with s.get(f"{ctx.base_url}/health") as r:
                    await r.read()
                    return r.status
            except Exception:
                await asyncio.sleep(0.5)
    return None


def _ok(ctx, name, passed, detail=""):
    """Record a result; the detail is only worth printing when it failed."""
    ctx.ok(name, passed, "" if passed else detail)


async def run(ctx):
    base = ctx.base_url

    rc, out = await ctx.run_py(CREATE_USER)
    _ok(ctx, "blocking: create a plain test user", rc == 0, out.strip()[-200:])

    rc, out = await ctx.run_py("from config import Config; print('TP=' + repr(Config.TRUSTED_PROXIES)); print('NB=' + repr(Config.NEVER_BAN_CIDRS))")
    tp = next((l for l in out.splitlines() if l.startswith("TP=")), "TP=''")
    loopback_trusted = "127." in tp or "::1" in tp or "0.0.0.0" in tp or "/0" in tp

    # ------------------------------------------------------------------
    # Routes: anonymous and plain-user access
    # ------------------------------------------------------------------
    async with ctx.http() as anon:
        for method, path in (("GET", "/api/admin/never-ban"), ("PUT", "/api/admin/never-ban"),
                             ("GET", "/api/admin/proxy-trust"), ("GET", "/api/admin/cf-ranges"),
                             ("PUT", "/api/admin/cf-ranges"), ("POST", "/api/admin/cf-ranges/reset")):
            async with anon.request(method, base + path, json={}, headers={"Accept": "application/json"}) as r:
                await r.read()
                _ok(ctx, f"blocking: anonymous {method} {path} is refused", r.status in (401, 403), str(r.status))
    async with ctx.http() as user:
        resp = await ctx.login(user, USER, PASSWORD)
        if resp.status == 200:
            for method, path in (("GET", "/api/admin/never-ban"), ("PUT", "/api/admin/never-ban"),
                                 ("GET", "/api/admin/proxy-trust"), ("GET", "/api/admin/cf-ranges"),
                                 ("PUT", "/api/admin/cf-ranges"), ("POST", "/api/admin/cf-ranges/reset")):
                async with user.request(method, base + path, json={"entries": ["203.0.113.0/24"], "enabled": False},
                                        headers={"Accept": "application/json"}) as r:
                    await r.read()
                    _ok(ctx, f"blocking: a plain user's {method} {path} is refused", r.status == 403, str(r.status))
        else:
            _ok(ctx, "blocking: plain test user login", False, f"status {resp.status}")

    # ------------------------------------------------------------------
    # Proxy-trust self-check (log lines need no password)
    # ------------------------------------------------------------------
    if loopback_trusted:
        ctx.skip("blocking: proxy-trust self-check", f"the copied .env trusts loopback ({tp})")
    else:
        log = ctx.server_log()
        _ok(ctx, "blocking: startup log warns that loopback is not a trusted proxy while listening on loopback",
               "Listening on 127.0.0.1 only" in log and "loopback is not a trusted proxy" in log)
        # a scanner pattern from a loopback peer that carries Cloudflare headers never creates a block
        statuses = []
        async with ctx.http() as sess:
            for _ in range(3):
                for path in ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/"):
                    async with sess.get(f"{base}{path}", allow_redirects=False,
                                        headers={"CF-Connecting-IP": "1.2.3.4", "CF-Ray": "smoke-LHR"}) as r:
                        await r.read()
                        statuses.append(r.status)
            async with sess.get(f"{base}/health") as r:
                health = r.status
        _ok(ctx, "blocking: scanner paths from a loopback peer carrying Cloudflare headers create no block",
            403 not in statuses and health == 200, f"{len(statuses)} probes, 403s={statuses.count(403)}, /health {health}")

    # ------------------------------------------------------------------
    # Admin-only parts
    # ------------------------------------------------------------------
    if not ctx.admin_password:
        for name in ("never-ban routes", "proxy-trust endpoint", "Cloudflare range setting"):
            ctx.skip(f"blocking: {name}", "no admin password (use --admin-password)")
    else:
        async with ctx.http() as adm:
            r = await ctx.login(adm, ctx.admin_user, ctx.admin_password)
            if r.status != 200:
                _ok(ctx, "blocking: admin login", False, f"status {r.status}")
                return
            await _admin_checks(ctx, adm, loopback_trusted)

    # ------------------------------------------------------------------
    # The unit tests, against the staged copy of the code
    # ------------------------------------------------------------------
    for name in ("test_blocking", "test_cf_ranges"):
        rc, out = await ctx.run_py(f"import runpy; runpy.run_path('tests/{name}.py', run_name='__main__')", timeout=170)
        results = [l for l in out.splitlines() if l.startswith(("ok:   ", "FAIL: "))]
        bad = [l for l in results if l.startswith("FAIL")]
        _ok(ctx, f"blocking: tests/{name}.py passes on the staged code ({len(results)} checks)",
               rc == 0 and bool(results) and not bad and "all checks passed" in out,
               (bad[0] if bad else out.strip()[-200:]))

    # ------------------------------------------------------------------
    # Lockout recovery: block 127.0.0.1, prove the lockout, remove it with the CLI, log in again
    # ------------------------------------------------------------------
    await _lockout_recovery(ctx)


async def _admin_checks(ctx, adm, loopback_trusted):
    base = ctx.base_url
    hdr = {"Accept": "application/json"}

    async with adm.get(f"{base}/api/admin/never-ban", headers=hdr) as r:
        status = r.status
        body = await r.json(content_type=None) if status == 200 else {}
    if status == 403:
        ctx.skip("blocking: never-ban routes", "the admin account is not a superadmin")
        superadmin = False
    else:
        superadmin = True
        original = body.get("entries", [])
        groups = {g["source"]: g for g in body.get("effective", [])}
        _ok(ctx, "blocking: GET never-ban shows the effective list by source",
               status == 200 and {"loopback", "private", "host", "cloudflare", "trusted_proxies", "env", "admin"} <= set(groups)
               and len(groups["cloudflare"]["entries"]) >= 15, str(sorted(groups)))
        _ok(ctx, "blocking: GET never-ban reports the limits",
               body.get("limits", {}).get("max_entries") == 100 and body["limits"].get("min_prefix_ipv4") == 8
               and body["limits"].get("min_prefix_ipv6") == 16, str(body.get("limits")))
        if not loopback_trusted:
            _ok(ctx, "blocking: the saver's own address (loopback here) is reported as covered",
                   body.get("your_ip") == "127.0.0.1" and body.get("your_ip_covered") is True, str(body.get("your_ip")))
        async def _never_ban_events():
            async with adm.get(f"{base}/api/admin/security-events?event=never_ban_changed&limit=5", headers=hdr) as er:
                return await er.json(content_type=None)
        events_before = (await _never_ban_events()).get("total", 0)
        try:
            for label, entries in {
                "0.0.0.0/0": ["0.0.0.0/0"], "::/0": ["::/0"], "an IPv4 prefix shorter than /8": ["1.0.0.0/7"],
                "an IPv6 prefix shorter than /16": ["2000::/15"], "the IPv4-mapped range": ["::ffff:0:0/96"],
                "host bits set": ["203.0.113.7/24"], "text": ["not an ip"], "101 entries": [f"10.1.{i}.0/24" for i in range(101)],
                "a non-list": "203.0.113.7", "a missing body field": None,
            }.items():
                async with adm.put(f"{base}/api/admin/never-ban", json={"entries": entries}, headers=hdr) as r:
                    await r.read()
                    _ok(ctx, f"blocking: PUT never-ban refuses {label}", r.status == 400, str(r.status))
            async with adm.put(f"{base}/api/admin/never-ban", data="not json", headers=hdr) as r:
                await r.read()
                _ok(ctx, "blocking: PUT never-ban refuses a body that is not JSON", r.status == 400, str(r.status))
            async with adm.get(f"{base}/api/admin/never-ban", headers=hdr) as r:
                after_bad = (await r.json(content_type=None)).get("entries")
            _ok(ctx, "blocking: refused saves leave the list unchanged", after_bad == original, f"{original} -> {after_bad}")

            async with adm.put(f"{base}/api/admin/never-ban", json={"entries": ["203.0.113.0/24", "198.51.100.7", "45.9.9.0/24", "203.0.113.0/24"]},
                               headers=hdr) as r:
                saved = await r.json(content_type=None)
                _ok(ctx, "blocking: PUT never-ban saves, normalises and deduplicates",
                       r.status == 200 and saved.get("entries") == ["203.0.113.0/24", "198.51.100.7/32", "45.9.9.0/24"], str(saved.get("entries")))
            ev = await _never_ban_events()
            newest = (ev.get("events") or [{}])[0]
            _ok(ctx, "blocking: a saved never-ban list is a security event (counts, actor), refused saves are not",
                   ev.get("total") == events_before + 1 and '"entries":3' in (newest.get("details") or "")
                   and newest.get("user_id") is not None and "203.0.113" not in (newest.get("details") or ""),
                   f"{events_before} -> {ev.get('total')} {newest}")
            admin_group = next((g for g in saved.get("effective", []) if g["source"] == "admin"), {})
            _ok(ctx, "blocking: the effective list shows the saved entries under the admin source",
                   "45.9.9.0/24" in admin_group.get("entries", []))
            async with adm.get(f"{base}/api/admin/never-ban", headers=hdr) as r:
                again = (await r.json(content_type=None)).get("entries")
            _ok(ctx, "blocking: the saved list is what GET returns", again == saved.get("entries"))
            async with adm.put(f"{base}/api/admin/never-ban", json={"entries": ["203.0.113.7", "1.2.3.4"]}, headers=hdr) as r:
                note = await r.json(content_type=None)
            _ok(ctx, "blocking: the response says whether the saver's own address is covered (informational, not an error)",
                   r.status == 200 and "your_ip_covered" in note and "your_ip" in note, str(note.get("your_ip_covered")))
        finally:
            async with adm.put(f"{base}/api/admin/never-ban", json={"entries": original}, headers=hdr) as r:
                await r.read()
                _ok(ctx, "blocking: the never-ban list is restored", r.status == 200, str(r.status))

    # ---- Cloudflare range setting ---------------------------------------
    async with adm.get(f"{base}/api/admin/cf-ranges", headers=hdr) as r:
        cf = await r.json(content_type=None)
    _ok(ctx, "blocking: GET cf-ranges reports the list in use and that a stage does not refresh",
           r.status == 200 and cf.get("v4", 0) >= 10 and cf.get("v6", 0) >= 5 and cf.get("stage_mode") is True
           and cf.get("source") in ("built-in", "fetched"), str(cf))
    if superadmin:
        was = cf.get("enabled")
        try:
            async with adm.put(f"{base}/api/admin/cf-ranges", json={"enabled": "yes"}, headers=hdr) as r:
                await r.read()
                _ok(ctx, "blocking: PUT cf-ranges refuses a non-boolean", r.status == 400, str(r.status))
            async with adm.put(f"{base}/api/admin/cf-ranges", json={"enabled": not was}, headers=hdr) as r:
                flipped = await r.json(content_type=None)
            _ok(ctx, "blocking: PUT cf-ranges flips the weekly refresh", r.status == 200 and flipped.get("enabled") is (not was), str(flipped))
        finally:
            async with adm.put(f"{base}/api/admin/cf-ranges", json={"enabled": bool(was)}, headers=hdr) as r:
                await r.read()
                _ok(ctx, "blocking: the refresh setting is restored", r.status == 200, str(r.status))

        # ---- "use the built-in list": route, audit entry, security event ------
        async def _events(name):
            async with adm.get(f"{base}/api/admin/security-events?event={name}&limit=5", headers=hdr) as er:
                return await er.json(content_type=None)
        async def _audits(name):
            async with adm.get(f"{base}/api/admin/audit-log?action={name}&limit=5", headers=hdr) as er:
                return await er.json(content_type=None)
        ev_before = (await _events("cf_ranges_reset")).get("total", 0)
        au_before = (await _audits("cf_ranges.reset")).get("total", 0)
        async with adm.post(f"{base}/api/admin/cf-ranges/reset", headers=hdr) as r:
            reset = await r.json(content_type=None)
        _ok(ctx, "blocking: POST cf-ranges/reset puts the built-in list in use and clears the saved one",
               r.status == 200 and reset.get("source") == "built-in" and reset.get("saved_list") is False
               and reset.get("v4", 0) >= 10 and reset.get("reset") is True, str(reset))
        ev = await _events("cf_ranges_reset")
        au = await _audits("cf_ranges.reset")
        _ok(ctx, "blocking: the reset is a security event and an audit entry",
               ev.get("total") == ev_before + 1 and au.get("total") == au_before + 1
               and (ev.get("events") or [{}])[0].get("user_id") is not None, f"{ev.get('total')} {au.get('total')}")
    else:
        ctx.skip("blocking: PUT cf-ranges", "the admin account is not a superadmin")

    # ---- a manual block is one block however the address is spelled -------
    typed = "2001:DB8:5EED::17"
    canon = "2001:db8:5eed::17"
    try:
        async with adm.post(f"{base}/api/admin/blocked-ips", json={"ip_address": typed, "reason": "smoke canonical"}, headers=hdr) as r:
            made = await r.json(content_type=None)
        _ok(ctx, "blocking: a manual block on an upper-case IPv6 address is stored in canonical form",
               r.status == 201 and made.get("ip_address") == canon, f"{r.status} {made}")
        async with adm.post(f"{base}/api/admin/blocked-ips", json={"ip_address": canon, "reason": "smoke canonical"}, headers=hdr) as r:
            await r.read()
        async with adm.get(f"{base}/api/admin/blocked-ips", headers=hdr) as r:
            listed = [b["ip_address"] for b in (await r.json(content_type=None)).get("blocked_ips", [])]
        _ok(ctx, "blocking: both spellings are one row in the block list",
               listed.count(canon) == 1 and typed not in listed, str([x for x in listed if "5eed" in x.lower()]))
        async with adm.delete(f"{base}/api/admin/blocked-ips/{typed}", headers=hdr) as r:
            await r.read()
            _ok(ctx, "blocking: the other spelling removes it", r.status == 200, str(r.status))
        async with adm.delete(f"{base}/api/admin/blocked-ips/{canon}", headers=hdr) as r:
            await r.read()
            _ok(ctx, "blocking: and nothing is left to remove", r.status == 404, str(r.status))
    finally:
        async with adm.delete(f"{base}/api/admin/blocked-ips/{canon}", headers=hdr) as r:
            await r.read()

    # ---- proxy-trust self-check through the endpoint ---------------------
    if loopback_trusted:
        ctx.skip("blocking: proxy-trust endpoint", "the copied .env trusts loopback")
        return
    cf_headers = {"CF-Connecting-IP": "1.2.3.4", "CF-Ray": "smoke-LHR"}
    async with ctx.http() as burst:
        for _ in range(130):
            async with burst.get(f"{base}/health", headers=cf_headers) as r:
                await r.read()
        async with adm.get(f"{base}/api/admin/proxy-trust", headers={**hdr, **cf_headers}) as r:
            st = await r.json(content_type=None)
        _ok(ctx, "blocking: loopback requests carrying Cloudflare headers trip the proxy-trust note",
               r.status == 200 and st.get("suspect") is True and "127.0.0.1" in st.get("peers", [])
               and "TRUSTED_PROXIES" in (st.get("message") or "")
               and "really is your own proxy" in (st.get("message") or ""), str(st))
        _ok(ctx, "blocking: the server log carries the proxy-trust warning",
               "that address is not a trusted proxy" in ctx.server_log())
        if superadmin:
            async with adm.get(f"{base}/api/admin/never-ban", headers={**hdr, **cf_headers}) as r:
                who = await r.json(content_type=None)
            _ok(ctx, "blocking: the self-check never changes trust (a CF-Connecting-IP header from loopback is still ignored)",
                   who.get("your_ip") == "127.0.0.1", str(who.get("your_ip")))
        for _ in range(130):
            async with burst.get(f"{base}/health") as r:
                await r.read()
        async with adm.get(f"{base}/api/admin/proxy-trust", headers=hdr) as r:
            st = await r.json(content_type=None)
        _ok(ctx, "blocking: the proxy-trust note clears once ordinary requests dominate again",
               r.status == 200 and st.get("suspect") is False, str(st))


async def _lockout_recovery(ctx):
    base = ctx.base_url
    try:
        await ctx.stop_server()
        _sql(ctx, "DELETE FROM blocked_ips WHERE ip_address = '127.0.0.1'")
        _sql(ctx, "INSERT INTO blocked_ips (ip_address, reason) VALUES ('127.0.0.1', ?)", (MARKER,))
        await ctx.start_server(wait_healthy=False)
        status = await _health_status(ctx)
        _ok(ctx, "blocking: a block on 127.0.0.1 really locks the staged server out (403 on /health)", status == 403, str(status))
        await ctx.stop_server()

        before = _schema_hash(_db(ctx))
        rc, out = await _cli(ctx, "unblock", "127.0.0.1")
        left = _sql(ctx, "SELECT COUNT(*) FROM blocked_ips WHERE ip_address = '127.0.0.1'")[0][0]
        _ok(ctx, "blocking: `server.py unblock 127.0.0.1` on the stopped server removes the ban and prints what it removed",
               rc == 0 and left == 0 and MARKER in out and "127.0.0.1" in out, out.strip()[-300:])
        _ok(ctx, "blocking: the CLI ran no migration (schema unchanged)", _schema_hash(_db(ctx)) == before)

        rc, out = await _cli(ctx, "unblock", "127.0.0.1")
        _ok(ctx, "blocking: unblocking an address with no block says so and exits non-zero", rc == 1 and "No database block" in out, out.strip()[-200:])
        rc, out = await _cli(ctx, "unblock", "not-an-ip")
        _ok(ctx, "blocking: unblock refuses text that is not an address", rc == 2, out.strip()[-200:])

        _sql(ctx, "INSERT OR REPLACE INTO blocked_ips (ip_address, reason) VALUES ('127.0.0.1', ?)", (MARKER,))
        _sql(ctx, "INSERT OR REPLACE INTO blocked_ips (ip_address, reason) VALUES ('45.9.9.9', ?)", (MARKER + "-2",))
        rc, out = await _cli(ctx, "clear-bans")
        left = _sql(ctx, "SELECT COUNT(*) FROM blocked_ips")[0][0]
        _ok(ctx, "blocking: `server.py clear-bans` removes every ban and lists them",
               rc == 0 and left == 0 and MARKER in out and MARKER + "-2" in out, out.strip()[-300:])
        _ok(ctx, "blocking: clear-bans ran no migration either", _schema_hash(_db(ctx)) == before)

        was = _sql(ctx, "SELECT value FROM settings WHERE key = 'cf_ranges_list'")
        _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_ranges_list', ?)", ('{"v4": [], "v6": []}',))
        ev_before = _sql(ctx, "SELECT COUNT(*) FROM security_events WHERE event = 'cf_ranges_reset' AND ip = 'cli'")[0][0]
        rc, out = await _cli(ctx, "cf-ranges-reset")
        left = _sql(ctx, "SELECT COUNT(*) FROM settings WHERE key = 'cf_ranges_list'")[0][0]
        ev_after = _sql(ctx, "SELECT COUNT(*) FROM security_events WHERE event = 'cf_ranges_reset' AND ip = 'cli'")[0][0]
        _ok(ctx, "blocking: `server.py cf-ranges-reset` on the stopped server clears the saved list, records a cli security event and runs no migration",
               rc == 0 and left == 0 and ev_after == ev_before + 1 and _schema_hash(_db(ctx)) == before, out.strip()[-300:])
        if was:
            _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_ranges_list', ?)", (was[0][0],))

        await ctx.start_server(wait_healthy=True)
        status = await _health_status(ctx, tries=5)
        _ok(ctx, "blocking: after the CLI the staged server answers 200 again", status == 200, str(status))
        if ctx.admin_password:
            async with ctx.http() as s:
                r = await ctx.login(s, ctx.admin_user, ctx.admin_password)
                _ok(ctx, "blocking: the admin can log in after the CLI unblock", r.status == 200, f"status {r.status}")
        else:
            ctx.skip("blocking: login after the CLI unblock", "no admin password (use --admin-password)")
    finally:
        # later modules must find a running, unblocked server
        try:
            if ctx.server.proc is None or ctx.server.proc.poll() is not None:
                await ctx.stop_server()
                _sql(ctx, "DELETE FROM blocked_ips WHERE reason IN (?, ?)", (MARKER, MARKER + "-2"))
                await ctx.start_server(wait_healthy=True)
            else:
                _sql(ctx, "DELETE FROM blocked_ips WHERE reason IN (?, ?)", (MARKER, MARKER + "-2"))
        except Exception as e:  # pragma: no cover
            _ok(ctx, "blocking: staged server is running again after the check", False, str(e)[:200])
