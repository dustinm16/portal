"""Notification channels on outgoing webhooks, on a staged instance.

A receiver on 127.0.0.1 inside this module stands in for ntfy, Gotify, Discord and
Slack: nothing leaves the machine. The staged server sends only to the loopback
sink port this module writes to its settings (PORTAL_STAGE_MODE refuses every other
destination, including the real hooks of a production copy), and only for a hook that
a superadmin in a browser session marked allow_private.

Checks: each format's Test posts a minimal message and reports the receiver's status;
a generic hook is still HMAC-signed; a 429 is reported and does not count toward
auto-disable; a delivery waiting out a 429 stops when its hook is deleted; a switch to generic never exposes the
stored address; allow_private needs a superadmin browser session and the portal's own
port, link-local and metadata addresses stay refused; system hooks are superadmin
only; a message in a private channel never reaches a non-generic hook; the private
destination and every token are absent from API answers, the database file and the
server log; existing hooks of a copied database kept their old behaviour.

Own users, channels and hooks carry a random suffix and no assertion counts rows of a
shared table, so the module also holds on a production database copy. It needs no
admin password: it creates its own superadmin.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import sqlite3
import os

from aiohttp import web

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    out = {}
    sa = await create_user("{sa}", "{pw}", is_admin=True)
    await db.set_user_role(sa["id"], "superadmin")
    ad = await create_user("{ad}", "{pw}", is_admin=True)
    await db.set_user_role(ad["id"], "admin")
    await db.conn.execute("INSERT INTO chat_channels (name, visibility) VALUES (?, 'public')", ("{pub}",))
    await db.conn.execute("INSERT INTO chat_channels (name, visibility) VALUES (?, 'private')", ("{priv}",))
    await db.conn.commit()
    for key, name in (("pub", "{pub}"), ("priv", "{priv}")):
        cur = await db.conn.execute("SELECT id FROM chat_channels WHERE name = ?", (name,))
        out[key] = (await cur.fetchone())["id"]
    await db.set_setting("stage_webhook_sink_port", "{port}")
    await db.conn.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _parse(output):
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    raise RuntimeError("no RESULT line in: " + output[-300:])


async def run(ctx):
    tag = secrets.token_hex(3)
    pw = "Wc-" + secrets.token_hex(6) + "!"
    names = {"sa": f"wc_sa_{tag}", "ad": f"wc_ad_{tag}", "pub": f"wc_pub_{tag}", "priv": f"wc_priv_{tag}"}
    tokens = {"ntfy": "tk_" + secrets.token_hex(8), "gotify": "GT" + secrets.token_hex(8),
              "path": "PATH" + secrets.token_hex(8)}

    got = []
    answer = [204]

    async def receiver(request):
        got.append((request.path, dict(request.headers), await request.read()))
        if request.path == "/rl":
            return web.Response(status=429, headers={"Retry-After": "3"}, text="receiver-body")
        return web.Response(status=answer[0], text="receiver-body")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", receiver)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    rbase = f"http://127.0.0.1:{port}"
    try:
        await _checks(ctx, tag, pw, names, tokens, got, answer, port, rbase)
    finally:
        await runner.cleanup()


async def _checks(ctx, tag, pw, names, tokens, got, answer, port, rbase):
    code = SETUP
    for key, val in (("sa", names["sa"]), ("ad", names["ad"]), ("pw", pw), ("pub", names["pub"]),
                     ("priv", names["priv"]), ("port", str(port))):
        code = code.replace("{" + key + "}", val)
    rc, out = await ctx.run_py(code)
    if rc != 0:
        ctx.ok("webhook channels: set up users, channels and the sink port", False, out[-300:])
        return
    ids = _parse(out)
    ctx.ok("webhook channels: set up users, channels and the sink port", True)
    api = ctx.base_url + "/api"
    db_path = os.path.join(ctx.stage_dir, "portal.db")

    async def call(sess, method, path, body=None):
        async with sess.request(method, api + path, json=body) as r:
            try:
                data = await r.json(content_type=None)
            except Exception:
                data = None
            return r.status, data

    async with ctx.http() as sa, ctx.http() as ad:
        r1 = await ctx.login(sa, names["sa"], pw)
        r2 = await ctx.login(ad, names["ad"], pw)
        if r1.status != 200 or r2.status != 200:
            ctx.ok("webhook channels: sign in as the module's own superadmin and admin", False, f"{r1.status}/{r2.status}")
            return
        ctx.ok("webhook channels: sign in as the module's own superadmin and admin", True)

        # ---- system hooks, one per format, aimed at the sink
        hooks = {}
        specs = {
            "ntfy": {"url": rbase + "/" + tokens["path"], "format_config": {"token": tokens["ntfy"]}},
            "gotify": {"url": rbase, "format_config": {"token": tokens["gotify"]}},
            "discord": {"url": rbase + "/api/webhooks/1/" + tokens["path"]},
            "slack": {"url": rbase + "/services/T/B/" + tokens["path"]},
        }
        for fmt, extra in specs.items():
            st, h = await call(sa, "POST", "/admin/webhooks", {
                "name": f"wc_{fmt}_{tag}", "format": fmt, "events": ["user.joined"], "allow_private": True, **extra})
            ctx.ok(f"webhook channels: system {fmt} hook created with allow_private", st == 201, f"{st} {h}")
            if st != 201:
                return
            hooks[fmt] = h
            blob = json.dumps(h)
            ctx.ok(f"webhook channels: {fmt} create answer shows no token, no path, no secret",
                   not any(t in blob for t in tokens.values()) and h.get("url") is None and "secret" not in h, blob[:200])

        answer[0] = 204
        for fmt in ("ntfy", "gotify", "discord", "slack"):
            got.clear()
            st, r = await call(sa, "POST", f"/admin/webhooks/{hooks[fmt]['id']}/test")
            ok = st == 200 and r.get("success") and r.get("status") == 204 and len(got) == 1
            ctx.ok(f"webhook channels: {fmt} Test reaches the receiver and reports status 204", ok, f"{st} {r} {len(got)}")
            if not got:
                continue
            path, hdrs, body = got[0]
            text = body.decode("utf-8", "replace")
            if fmt == "ntfy":
                ctx.ok("webhook channels: ntfy message has title, priority and bearer token, no signature",
                       path == "/" + tokens["path"] and "Title" in hdrs and hdrs.get("Priority") == "3"
                       and hdrs.get("Authorization") == "Bearer " + tokens["ntfy"] and "X-Portal-Signature" not in hdrs, str(hdrs))
            elif fmt == "gotify":
                ctx.ok("webhook channels: gotify posts /message with the token in a header only",
                       path == "/message" and hdrs.get("X-Gotify-Key") == tokens["gotify"] and tokens["gotify"] not in text
                       and "title" in json.loads(text), f"{path} {text[:120]}")
            elif fmt == "discord":
                emb = json.loads(text)
                ctx.ok("webhook channels: discord gets an embed with allowed_mentions none",
                       emb.get("allowed_mentions") == {"parse": []} and emb["embeds"][0]["title"], text[:160])
            else:
                ctx.ok("webhook channels: slack gets one text field", "text" in json.loads(text), text[:160])

        # a 429 is reported and never counts toward auto-disable
        answer[0] = 429
        st, r = await call(sa, "POST", f"/admin/webhooks/{hooks['discord']['id']}/test")
        st2, h = await call(sa, "GET", f"/admin/webhooks/{hooks['discord']['id']}")
        ctx.ok("webhook channels: a 429 is reported to the Test button and does not count as a failure",
               r.get("status") == 429 and not r.get("success") and h.get("consecutive_failures") == 0 and h.get("enabled"),
               f"{r} {h}")
        answer[0] = 500
        st, r = await call(sa, "POST", f"/admin/webhooks/{hooks['slack']['id']}/test")
        st2, h = await call(sa, "GET", f"/admin/webhooks/{hooks['slack']['id']}")
        ctx.ok("webhook channels: a 500 still counts as a failure", r.get("status") == 500 and h.get("consecutive_failures") == 1, f"{r} {h}")
        answer[0] = 204

        # ---- generic hooks stay signed
        st, g = await call(sa, "POST", "/webhooks", {
            "name": f"wc_generic_{tag}", "events": ["user.joined"], "url": rbase + "/generic", "allow_private": True})
        ctx.ok("webhook channels: generic hook with allow_private created, secret shown once",
               st == 201 and g.get("secret") and g.get("format") == "generic", f"{st} {g}")
        got.clear()
        st, r = await call(sa, "POST", f"/webhooks/{g['id']}/test")
        if got:
            _, hdrs, body = got[0]
            want = "sha256=" + hmac.new(g["secret"].encode(), body, hashlib.sha256).hexdigest()
            ctx.ok("webhook channels: a generic hook is still HMAC-signed", hdrs.get("X-Portal-Signature") == want and r.get("success"), str(hdrs))
        else:
            ctx.ok("webhook channels: a generic hook is still HMAC-signed", False, f"{st} {r}")

        # ---- who may do what
        st, e = await call(ad, "POST", "/webhooks", {"name": f"wc_x_{tag}", "events": ["*"], "format": "ntfy",
                                                    "url": rbase + "/x", "allow_private": True})
        ctx.ok("webhook channels: an ordinary admin cannot enable allow_private", st == 403, f"{st} {e}")
        st, e = await call(ad, "GET", "/admin/webhooks")
        ctx.ok("webhook channels: an ordinary admin cannot list system hooks", st in (401, 403), str(st))
        st, e = await call(ad, "GET", f"/webhooks/{hooks['ntfy']['id']}")
        ctx.ok("webhook channels: a system hook is not reachable through the user routes", st == 404, str(st))
        stage_port = ctx.base_url.rsplit(":", 1)[1]
        for label, url in (("the portal's own port", f"http://127.0.0.1:{stage_port}/x"),
                           ("the metadata address", "http://169.254.169.254/latest"),
                           ("a link-local IPv6 address", "http://[fe80::1]/x"),
                           ("the unspecified address", "http://0.0.0.0:9/x")):
            st, e = await call(sa, "POST", "/admin/webhooks", {"name": f"wc_bad_{tag}", "events": ["*"], "format": "ntfy",
                                                               "url": url, "allow_private": True})
            ctx.ok(f"webhook channels: allow_private still refuses {label}", st == 400, f"{st} {e}")
        st, e = await call(sa, "POST", "/admin/webhooks", {"name": f"wc_bad_{tag}", "events": ["*"], "format": "generic",
                                                           "url": rbase + "/x"})
        ctx.ok("webhook channels: without allow_private a loopback URL is refused", st == 400, f"{st} {e}")

        # ---- second-pass rules (validation only: nothing is dialled)
        for label, url in (("plain http to a public address", "http://93.184.216.34/x"),
                           ("an address in 0.0.0.0/8", "http://0.1.2.3/x")):
            st, e = await call(sa, "POST", "/admin/webhooks", {"name": f"wc_bad_{tag}", "events": ["user.joined"], "format": "ntfy",
                                                               "url": url, "allow_private": True})
            ctx.ok(f"webhook channels: allow_private refuses {label}", st == 400, f"{st} {e}")
        st, e = await call(sa, "POST", "/admin/webhooks", {"name": f"wc_bad_{tag}", "events": ["user.joined"], "format": "ntfy",
                                                           "url": "https://93.184.216.34/x", "allow_private": True})
        ctx.ok("webhook channels: allow_private accepts https to a public address", st == 201, f"{st} {e}")
        if st == 201 and e.get("id"):
            await call(sa, "DELETE", f"/admin/webhooks/{e['id']}")
        async with sa.post(ctx.base_url + "/api/token", json={"username": names["sa"], "password": pw}) as r:
            tok = (await r.json(content_type=None) or {}).get("token", "")
        async with sa.post(api + "/webhooks", headers={"Authorization": "Bearer " + tok}, json={
                "name": f"wc_x_{tag}", "events": ["user.joined"], "format": "ntfy", "url": rbase + "/x", "allow_private": True}) as r:
            ctx.ok("webhook channels: a bearer token cannot enable allow_private even with the superadmin cookie in the request",
                   bool(tok) and r.status == 403, str(r.status))
        st, own = await call(sa, "POST", "/webhooks", {"name": f"wc_off_{tag}", "events": ["user.joined"], "format": "ntfy",
                                                       "url": rbase + "/off", "allow_private": True})
        if st == 201:
            st, e = await call(ad, "PUT", f"/webhooks/{own['id']}", {"allow_private": False})
            ctx.ok("webhook channels: any editor can switch allow_private off", st == 200 and not e.get("allow_private"), f"{st} {e}")
            await call(sa, "DELETE", f"/webhooks/{own['id']}")
        else:
            ctx.ok("webhook channels: any editor can switch allow_private off", False, f"{st} {own}")
        st, e = await call(sa, "POST", "/webhooks", {"name": f"wc_x_{tag}", "events": ["webhook.test"], "format": "ntfy",
                                                    "url": "https://93.184.216.34/x"})
        ctx.ok("webhook channels: a user hook cannot subscribe to a system-only event", st == 400, f"{st} {e}")

        # ---- outside destinations are never contacted from a staged instance
        st, outside = await call(sa, "POST", "/admin/webhooks", {
            "name": f"wc_out_{tag}", "format": "discord", "events": ["*"], "url": "https://93.184.216.34/api/webhooks/9/" + tokens["path"]})
        st2, r = await call(sa, "POST", f"/admin/webhooks/{outside['id']}/test") if st == 201 else (0, {})
        ctx.ok("webhook channels: a staged instance does not send to an outside destination",
               st == 201 and st2 == 200 and r.get("sent") is False and not r.get("success"), f"{st} {st2} {r}")

        # ---- switching a non-generic hook to generic never exposes its stored address
        if outside and outside.get("id"):
            st, e = await call(sa, "PUT", f"/admin/webhooks/{outside['id']}", {"format": "generic"})
            ctx.ok("webhook channels: switching to generic without a new url is refused and shows no address",
                   st == 400 and tokens["path"] not in json.dumps(e), f"{st} {e}")
            st, lst = await call(sa, "GET", "/admin/webhooks")
            ctx.ok("webhook channels: the refused switch left the hook non-generic and its address hidden",
                   st == 200 and tokens["path"] not in json.dumps(lst), str(st))
        else:
            ctx.ok("webhook channels: switching to generic without a new url is refused", False, "no hook to switch")

        # ---- a delivery waiting out a 429 stops when its hook is deleted
        st, rl = await call(sa, "POST", "/admin/webhooks", {
            "name": f"wc_rl_{tag}", "format": "ntfy", "events": ["message.created"], "url": rbase + "/rl",
            "allow_private": True})
        ctx.ok("webhook channels: ntfy hook aimed at a receiver that always answers 429", st == 201, f"{st} {rl}")
        st, ih = await call(sa, "POST", "/webhooks", {"name": f"wc_in_rl_{tag}", "type": "incoming", "channel_id": ids["pub"]})
        if st == 201 and rl.get("id"):
            got.clear()
            async with ctx.http() as anon:
                async with anon.post(f"{api}/webhooks/incoming/{ih['token']}", json={"content": "rl-" + secrets.token_hex(3)}) as r:
                    ctx.ok("webhook channels: a message is posted to trigger the 429 hook", r.status == 200, str(r.status))
            for _ in range(40):
                if any(p == "/rl" for p, _h, _b in got):
                    break
                await asyncio.sleep(0.1)
            st, _e = await call(sa, "DELETE", f"/admin/webhooks/{rl['id']}")
            await asyncio.sleep(5)
            hits = [p for p, _h, _b in got if p == "/rl"]
            ctx.ok("webhook channels: a hook deleted while its delivery waits for Retry-After gets no further POST",
                   st == 200 and len(hits) == 1, f"{st} {len(hits)}")
        else:
            ctx.ok("webhook channels: incoming hook for the 429 check", False, f"{st} {ih}")

        # ---- private channel never reaches a non-generic hook
        st, sub = await call(sa, "POST", "/admin/webhooks", {
            "name": f"wc_msg_{tag}", "format": "ntfy", "events": ["message.created"], "url": rbase + "/messages",
            "allow_private": True, "include_details": True})
        ctx.ok("webhook channels: ntfy hook subscribed to message.created by name", st == 201, f"{st} {sub}")
        incoming = {}
        for key in ("pub", "priv"):
            st, ih = await call(sa, "POST", "/webhooks", {"name": f"wc_in_{key}_{tag}", "type": "incoming", "channel_id": ids[key]})
            if st != 201:
                ctx.ok(f"webhook channels: incoming hook for the {key} channel", False, f"{st} {ih}")
                return
            incoming[key] = ih["token"]
        got.clear()
        marker_priv = "PRIVATE-" + secrets.token_hex(4)
        marker_pub = "PUBLIC-" + secrets.token_hex(4)
        async with ctx.http() as anon:
            for key, marker in (("priv", marker_priv), ("pub", marker_pub)):
                async with anon.post(f"{api}/webhooks/incoming/{incoming[key]}", json={"content": marker}) as r:
                    ctx.ok(f"webhook channels: a message is posted to the {key} channel", r.status == 200, str(r.status))
        for _ in range(40):
            if any(p == "/messages" for p, _h, _b in got):
                break
            await asyncio.sleep(0.25)
        await asyncio.sleep(1.5)
        bodies = [b.decode("utf-8", "replace") for p, _h, b in got if p == "/messages"]
        ctx.ok("webhook channels: the public channel's message reaches the ntfy hook", len(bodies) == 1 and names["pub"] in bodies[0], str(bodies))
        ctx.ok("webhook channels: the private channel's message never leaves the portal",
               not any(names["priv"] in b or marker_priv in b for b in bodies), str(bodies))

        # ---- existing hooks of a copied database kept their behaviour
        conn = sqlite3.connect(db_path)
        try:
            bad = conn.execute(
                "SELECT COUNT(*) FROM webhooks WHERE created_by IS NULL AND "
                "(kind != 'user' OR format != 'generic' OR allow_private != 0 OR include_details != 0 OR user_id IS NULL)").fetchone()[0]
            # Every hook made by this version records its creator (created_by); the rows
            # without one are the ones that existed before the upgrade.
            ctx.ok("webhook channels: every hook from before the upgrade is a generic user hook with no new privileges", bad == 0, str(bad))
            dump = "\n".join(str(r) for r in conn.execute("SELECT url, secret, format_config FROM webhooks"))
            sec = conn.execute("SELECT format, secret FROM webhooks WHERE type = 'outgoing' AND name LIKE ?",
                               (f"%_{tag}",)).fetchall()
            logs = "\n".join(str(r) for r in conn.execute(
                "SELECT request_payload, response_body FROM webhook_logs WHERE webhook_id IN (SELECT id FROM webhooks WHERE name LIKE ?)",
                (f"%_{tag}",)))
        finally:
            conn.close()
        ctx.ok("webhook channels: only generic hooks of this module hold a signing secret (a version without formats must skip the others)",
               bool(sec) and any(f == "generic" for f, _ in sec) and any(f != "generic" for f, _ in sec)
               and all(bool(sv) == (f == "generic") for f, sv in sec), str([(f, bool(sv)) for f, sv in sec]))
        ctx.ok("webhook channels: no token or destination path is readable in the database file",
               not any(t in dump + logs for t in tokens.values()) and "receiver-body" not in logs)
        ctx.ok("webhook channels: no token is in the server log", not any(t in ctx.server_log() for t in tokens.values()))
