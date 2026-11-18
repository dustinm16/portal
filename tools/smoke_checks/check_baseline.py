"""Baseline smoke checks: the portal starts, serves its public pages, lets the
admin in, refuses anonymous API calls and does not ban a loopback client for
scanner-style requests."""

_PROBE_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/info.php", "/cgi-bin/test.cgi"]


async def run(ctx) -> None:
    base = ctx.base_url

    async with ctx.http() as anon:
        # /health
        async with anon.get(f"{base}/health") as r:
            body = await r.json(content_type=None)
            ctx.ok("/health returns 200", r.status == 200 and body.get("status") == "healthy", f"status {r.status}")

        # /login page
        async with anon.get(f"{base}/login", allow_redirects=False) as r:
            text = await r.text()
            ctx.ok("/login page returns 200", r.status == 200 and len(text) > 0, f"status {r.status}")

        # unauthenticated API call is refused
        async with anon.get(f"{base}/api/me", allow_redirects=False) as r:
            ctx.ok("anonymous /api/me is refused", r.status in (401, 403), f"status {r.status}")
        async with anon.get(f"{base}/api/users", allow_redirects=False) as r:
            ctx.ok("anonymous /api/users is refused", r.status in (401, 403), f"status {r.status}")

    # admin login, admin page, /api/me
    if not ctx.admin_password:
        for name in ("admin login succeeds", "authenticated /admin returns 200", "authenticated /api/me returns 200"):
            ctx.skip(name, "no admin password (use --admin-password)")
    else:
        async with ctx.http() as sess:
            r = await ctx.login(sess, ctx.admin_user, ctx.admin_password)
            try:
                data = await r.json(content_type=None)
            except Exception:
                data = {}
            ctx.ok("admin login succeeds", r.status == 200 and data.get("status") == "logged_in",
                   f"status {r.status}")
            async with sess.get(f"{base}/admin", allow_redirects=False) as r2:
                await r2.read()
                ctx.ok("authenticated /admin returns 200", r2.status == 200, f"status {r2.status}")
            async with sess.get(f"{base}/api/me", allow_redirects=False) as r3:
                me = await r3.json(content_type=None) if r3.status == 200 else {}
                ctx.ok("authenticated /api/me returns 200", r3.status == 200 and me.get("username") == ctx.admin_user,
                       f"status {r3.status}")

    # Many modules share the loopback address, so the stage must not enforce the production request limit.
    rc, out = await ctx.run_py("from config import Config; print(Config.RATE_LIMIT_REQUESTS)")
    last = out.strip().splitlines()[-1] if out.strip() else ""
    limit = int(last) if rc == 0 and last.isdigit() else 0
    ctx.ok("stage request limit is raised for loopback checks", limit >= 10000, f"RATE_LIMIT_REQUESTS={limit}")

    # A loopback peer asking for scanner-style paths must not get blocked.
    rc, out = await ctx.run_py("from config import Config; print(Config.PROBE_BLOCK_STRIKES)")
    strikes = int(out.strip().splitlines()[-1]) if rc == 0 and out.strip().splitlines()[-1].isdigit() else 0
    if strikes <= 0:
        ctx.ok("probe blocking is enabled in the stage (check is meaningful)", False, f"strikes={strikes}")
        return
    async with ctx.http() as sess:
        statuses = []
        for _ in range(2):                      # more requests than the strike limit
            for path in _PROBE_PATHS:
                async with sess.get(f"{base}{path}", allow_redirects=False) as r:
                    await r.read()
                    statuses.append(r.status)
        blocked_during = [s for s in statuses if s == 403]
        async with sess.get(f"{base}/health") as r:
            health = r.status
        async with sess.get(f"{base}/login", allow_redirects=False) as r:
            login = r.status
        ctx.ok("loopback client is not blocked after scanner-style requests",
               not blocked_during and health == 200 and login == 200,
               f"{len(statuses)} probes with limit {strikes}; 403s={len(blocked_during)}, /health {health}, /login {login}")
