"""Smoke check: the /proxy/{id} reverse proxy (forwarded headers, Set-Cookie
rewriting, timeout split) and the removal of the unused rewrite_urls option.

The echo-upstream behaviour is proved by tests/test_proxyfix.py, which runs the
real http_proxy_connection handler against a local echo server. It cannot go
through the staged server: user connections may not target loopback or private
addresses (the outbound host policy, which must stay in force), and a staged
host has no public address of its own. This module therefore (a) runs that
script against this staged copy of the code, one result per check, and (b)
checks through the staged server that the policy still refuses a loopback
upstream on the /proxy path, even when the client sends forwarding headers,
and that the plugin schema and saved configs handle rewrite_urls as intended.
"""

import json

USER = "smoke_proxyfix_user"
PASSWORD = "Smoke-Proxyfix-Pw-1!"
GOOD_HOST = "93.184.216.34"

SETUP = f"""
import asyncio, json
import database
from auth import create_user

async def main():
    await database.db.connect()
    user = await database.db.get_user_by_username({USER!r})
    if not user:
        await create_user({USER!r}, {PASSWORD!r}, is_admin=False)
        user = await database.db.get_user_by_username({USER!r})
    # a connection row with a loopback upstream, as an old or edited row would look
    cid = await database.db.create_user_connection(
        user["id"], "pf-loop", "http", "127.0.0.1", 9, json.dumps({{"rewrite_urls": True}}))
    await database.db.close()
    print("CID=" + str(cid))

asyncio.run(main())
"""


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    line = next((l for l in out.splitlines() if l.startswith("CID=")), "")
    ctx.ok("proxyfix: create test user and a loopback connection row", rc == 0 and bool(line), out.strip()[-200:])
    if not line:
        return
    loop_id = line[4:]

    async with ctx.http() as s:
        resp = await ctx.login(s, USER, PASSWORD)
        ctx.ok("proxyfix: test user login", resp.status == 200, f"status {resp.status}")
        if resp.status != 200:
            return

        # Outbound host policy is still in force on the proxy path.
        for headers in ({}, {"X-Forwarded-For": "6.6.6.6", "X-Forwarded-Host": "evil.example",
                             "X-Forwarded-Prefix": "/evil", "X-Real-IP": "6.6.6.6"}):
            async with s.get(f"{ctx.base_url}/proxy/{loop_id}/echo", headers=headers, allow_redirects=False) as r:
                await r.read()
                ctx.ok("proxyfix: /proxy still refuses a loopback upstream"
                       + (" (with forwarding headers)" if headers else ""), r.status == 403, str(r.status))

        # rewrite_urls is gone from the form schema, timeout bounds are kept.
        async with s.get(f"{ctx.base_url}/api/connections/types") as r:
            body = await r.json()
        props = body.get("types", {}).get("http", {}).get("config_schema", {}).get("properties", {})
        ctx.ok("proxyfix: web interface schema has no rewrite_urls", bool(props) and "rewrite_urls" not in props, str(sorted(props)))
        ctx.ok("proxyfix: web interface schema has no preserve_host", bool(props) and "preserve_host" not in props, str(sorted(props)))
        fh = props.get("forwarded_host", {})
        ctx.ok("proxyfix: web interface schema has forwarded_host, a boolean that is off by default",
               fh.get("type") == "boolean" and fh.get("default") is False, str(fh))
        ctx.ok("proxyfix: web interface schema keeps timeout 5-300",
               props.get("timeout", {}).get("minimum") == 5 and props.get("timeout", {}).get("maximum") == 300,
               str(props.get("timeout")))

        # A config that still carries rewrite_urls is accepted on create and update.
        async with s.post(f"{ctx.base_url}/api/connections", json={
                "name": "pf-ok", "type": "http", "host": GOOD_HOST, "port": 80,
                "config": {"rewrite_urls": True, "preserve_host": True, "forwarded_host": True, "timeout": 30}}) as r:
            created = await r.json()
            ctx.ok("proxyfix: create with stored rewrite_urls and preserve_host keys is accepted",
                   r.status in (200, 201) and bool(created.get("id")), f"{r.status} {created}")
        if created.get("id"):
            async with s.put(f"{ctx.base_url}/api/connections/{created['id']}", json={
                    "config": {"rewrite_urls": False, "preserve_host": False, "timeout": 30}}) as r:
                await r.read()
                ctx.ok("proxyfix: update with stored rewrite_urls and preserve_host keys is accepted", r.status == 200, str(r.status))

    # The handler against a local echo upstream, using the staged copy of the code.
    rc, out = await ctx.run_py("import runpy; runpy.run_path('tests/test_proxyfix.py', run_name='__main__')", timeout=300)
    results = [l for l in out.splitlines() if l.startswith(("ok:   ", "FAIL: "))]
    for l in results:
        ctx.ok("proxyfix: " + l[6:].split("  (")[0], l.startswith("ok:"), l[6:] if l.startswith("FAIL") else "")
    ctx.ok("proxyfix: in-process handler test finished cleanly", rc == 0 and bool(results)
           and "all checks passed" in out, f"rc {rc}, {len(results)} results; tail: {out.strip()[-200:]}")
