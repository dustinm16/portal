"""Smoke checks: reference IDs on block and rate-limit answers, the administrator lookup and the unblock.

On the staged instance, over real TLS. The staged server is restarted with TRUSTED_PROXIES=127.0.0.1,::1 in
its process environment (never in a file) so that each request names its client in CF-Connecting-IP with a
random public address; the block row for that address is written while the server is stopped, so nothing
depends on the administrator's own address. Then:
  - a blocked address gets a 403 page (Accept: text/html) and JSON with the same ref; 20 requests make no
    second row; the page names neither the reason nor the address
  - a client that hits the logged-out /proxy limit (set to 5 a minute for this run, then restored) gets a 429 with a ref (JSON and page)
  - with an administrator password: the lookup finds the block and the limiter event, a member (made here,
    random suffix) gets 403, an unknown ID gets 404, the one-click unblock (the existing route with ?ref=)
    lets the address through again and is a security event and an activity entry
  - without one: those steps are skipped and the rows are read from the database instead
The checks assert on their own random addresses only, restore the two limit settings they change
(they flood until the first 429) and pass on a copy of a production database (--from-db).
"""

import json
import random
import re
import secrets
import sqlite3

SUFFIX = secrets.token_hex(3)
MEMBER = f"smoke_ref_{SUFFIX}"
PASSWORD = "Smoke-BlockRef-Pw-1!"
REASON = f"smoke-reason-{SUFFIX}"
REF_RE = re.compile(r"[A-Z2-9]{4}-[A-Z2-9]{4}")

CREATE_MEMBER = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    if not await database.db.get_user_by_username({MEMBER!r}):
        await create_user({MEMBER!r}, {PASSWORD!r}, is_admin=False)
    await database.db.close()

asyncio.run(main())
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


async def run(ctx):
    base = ctx.base_url
    rc, out = await ctx.run_py(CREATE_MEMBER)
    ctx.ok("blockref: create a member", rc == 0, out.strip()[-200:])
    if rc != 0:
        return
    blocked, limited = _addr(), _addr()
    envs = [e for e in (getattr(ctx, "_env", None), getattr(ctx.server, "env", None)) if e is not None]
    had_trust = [e.get("TRUSTED_PROXIES") for e in envs]
    keys = ("proxy_limit_enabled", "proxy_limit_per_minute")
    saved = {k: _sql(ctx, "SELECT value FROM settings WHERE key = ?", (k,)) for k in keys}
    try:
        await ctx.stop_server()
        _sql(ctx, "INSERT OR REPLACE INTO blocked_ips (ip_address, reason, source, expires_at) VALUES (?, ?, 'manual', NULL)",
             (blocked, REASON))
        for k, v in (("proxy_limit_enabled", "1"), ("proxy_limit_per_minute", "5")):
            _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
        for e in envs:
            e["TRUSTED_PROXIES"] = "127.0.0.1,::1"
        await ctx.start_server(wait_healthy=True)
        if "loopback trusted: True" not in ctx.server_log():
            ctx.skip("blockref: all checks", "the staged server did not take TRUSTED_PROXIES from its environment")
            return

        hb = {"CF-Connecting-IP": blocked}
        refs = set()
        async with ctx.http() as s:
            async with s.get(f"{base}/dashboard", headers={**hb, "Accept": "text/html"}, allow_redirects=False) as r:
                page = await r.text()
                ctx.ok("blockref: a blocked browser gets a 403 page with a reference and the one sentence",
                       r.status == 403 and "Give this reference to an administrator." in page and bool(REF_RE.search(page))
                       and "Retry-After" not in r.headers, f"{r.status}")
            page_ref = (REF_RE.search(page) or [""])[0] if REF_RE.search(page) else ""
            ctx.ok("blockref: the page does not name the reason or the address",
                   REASON not in page and blocked not in page and "permanent" not in page.lower())
            async with s.get(f"{base}/api/me", headers={**hb, "Accept": "application/json"}) as r:
                body = await r.json(content_type=None)
                ctx.ok("blockref: an API client gets the old error text and a ref, nothing else",
                       r.status == 403 and body.get("error") == "Access denied" and set(body) == {"error", "ref"}, str(body))
            for _ in range(20):
                async with s.get(f"{base}/api/me", headers=hb) as r:
                    refs.add((await r.json(content_type=None)).get("ref"))
            refs.add(body.get("ref"))
            ctx.ok("blockref: 21 requests from the blocked address show one ID (the page's too)",
                   len(refs) == 1 and page_ref in refs, str(refs))
            rows = _sql(ctx, "SELECT ref, kind, limiter, source, reason, hits FROM block_refs WHERE subject = ?", (blocked,))
            ctx.ok("blockref: and made one row, with the block's type and reason",
                   len(rows) == 1 and rows[0][1] == "block" and rows[0][3] == "manual" and rows[0][4] == REASON
                   and rows[0][0] == page_ref.replace("-", ""), str(rows))
            block_ref = page_ref

            # a rate-limited client: the logged-out limit on /proxy (5 a minute for this run)
            hl = {"CF-Connecting-IP": limited}
            path = f"/proxy/{secrets.token_hex(8)}/x"
            got = None
            for _ in range(40):
                async with s.get(f"{base}{path}", headers={**hl, "Accept": "application/json"}, allow_redirects=False) as r:
                    if r.status == 429:
                        got = await r.json(content_type=None)
                        break
                    await r.read()
            ctx.ok("blockref: past the limit the answer is 429 with its old text and a ref",
                   bool(got) and got.get("error") == "Too many requests, retry shortly" and bool(REF_RE.fullmatch(got.get("ref", ""))), str(got))
            async with s.get(f"{base}{path}", headers={**hl, "Accept": "text/html"}, allow_redirects=False) as r:
                lp = await r.text()
                ctx.ok("blockref: the same client's browser gets a 429 page with the same ID",
                       r.status == 429 and bool(got) and got["ref"] in lp and "Give this reference to an administrator." in lp
                       and bool(r.headers.get("Retry-After")), str(r.status))
            limit_ref = (got or {}).get("ref", "")
            rows = _sql(ctx, "SELECT kind, limiter, subject FROM block_refs WHERE ref = ?", (limit_ref.replace("-", ""),))
            ctx.ok("blockref: the limiter event is stored under that ID", rows == [("limit", "logged_out_proxy", limited)], str(rows))

        if not ctx.admin_password:
            ctx.skip("blockref: the administrator lookup, the member refusal and the unblock", "no admin password (use --admin-password)")
        else:
            async with ctx.http() as adm, ctx.http() as mem:
                r = await ctx.login(adm, ctx.admin_user, ctx.admin_password)
                await r.read()
                if r.status != 200:
                    ctx.ok("blockref: admin login", False, f"status {r.status}")
                    return
                hdr = {"Accept": "application/json"}
                async with adm.get(f"{base}/api/admin/blocks/ref/{block_ref}", headers=hdr) as r:
                    d = await r.json(content_type=None)
                    ctx.ok("blockref: the lookup shows the block, its reason, that it is active and that it can be unblocked",
                           r.status == 200 and d.get("kind") == "block" and d.get("address") == blocked and d.get("reason") == REASON
                           and d.get("active") is True and d.get("can_unblock") is True, str(d))
                async with adm.get(f"{base}/api/admin/blocks/ref/{limit_ref.lower() or 'none'}", headers=hdr) as r:
                    d2 = await r.json(content_type=None)
                    ctx.ok("blockref: the lookup finds the limiter event (lower case accepted)",
                           r.status == 200 and d2.get("kind") == "limit" and d2.get("limiter") == "logged_out_proxy"
                           and d2.get("address") == limited and d2.get("can_unblock") is False, str(d2))
                async with adm.get(f"{base}/api/admin/blocks/ref/ZZZZ-ZZZZ", headers=hdr) as r:
                    a = (r.status, await r.read())
                async with adm.get(f"{base}/api/admin/blocks/ref/not-an-id", headers=hdr) as r:
                    b = (r.status, await r.read())
                ctx.ok("blockref: an unknown ID and a malformed one get the same 404", a[0] == 404 and a == b, f"{a} {b}")

                lr = await ctx.login(mem, MEMBER, PASSWORD)
                await lr.read()
                async with mem.get(f"{base}/api/admin/blocks/ref/{block_ref}", headers=hdr) as r:
                    txt = await r.text()
                    ctx.ok("blockref: a member cannot use the lookup", lr.status == 200 and r.status == 403
                           and REASON not in txt and blocked not in txt, f"{lr.status} {r.status}")

                async with adm.delete(f"{base}/api/admin/blocked-ips/{blocked}?ref={block_ref}", headers=hdr) as r:
                    await r.read()
                    ctx.ok("blockref: the one-click unblock (the existing route with the reference) works", r.status == 200, str(r.status))
                async with ctx.http() as s2:
                    async with s2.get(f"{base}/health", headers=hb) as r:
                        await r.read()
                        ctx.ok("blockref: the address is let through afterwards", r.status == 200, str(r.status))
                async with adm.get(f"{base}/api/admin/blocks/ref/{block_ref}", headers=hdr) as r:
                    d3 = await r.json(content_type=None)
                    ctx.ok("blockref: the lookup now shows the block as no longer active", d3.get("active") is False, str(d3))
                ev = _sql(ctx, "SELECT user_id, details FROM security_events WHERE event = 'ip_unblocked' AND details LIKE ? ORDER BY id DESC LIMIT 1",
                          (f"%{blocked}%",))
                det = json.loads(ev[0][1]) if ev else {}
                ctx.ok("blockref: the unblock is a security event naming the administrator and the reference",
                       bool(ev) and ev[0][0] is not None and det.get("ref") == block_ref.replace("-", ""), str(ev))
                act = _sql(ctx, "SELECT action, detail FROM activity_log WHERE action = 'ip_unblock' AND detail LIKE ?", (f"%{blocked}%",))
                ctx.ok("blockref: and an activity entry", bool(act) and block_ref in act[0][1], str(act))
    finally:
        try:
            await ctx.stop_server()
        except Exception:
            pass
        _sql(ctx, "DELETE FROM blocked_ips WHERE ip_address = ?", (blocked,))
        _sql(ctx, "DELETE FROM block_refs WHERE subject IN (?, ?)", (blocked, limited))
        for k in keys:
            _sql(ctx, "DELETE FROM settings WHERE key = ?", (k,))
            if saved.get(k):
                _sql(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, saved[k][0][0]))
        for e, was in zip(envs, had_trust):
            if was is None:
                e.pop("TRUSTED_PROXIES", None)
            else:
                e["TRUSTED_PROXIES"] = was
        await ctx.start_server(wait_healthy=True)
