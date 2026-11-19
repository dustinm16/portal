"""Ops and security alert events, on a staged instance.

A receiver on 127.0.0.1 inside this module stands in for the outside world; nothing leaves
the machine (the staged server sends only to the loopback sink port this module writes to
its settings). Own users, hooks and a wrapper service carry a random suffix and nothing here
counts rows of a shared table, so the module also holds on a production database copy. It
needs no admin password: it makes its own superadmin.

The limiter state (cooldowns, the global cap, burst counters) is shared by everything the
earlier modules did from 127.0.0.1, so this module first calls the stage-only reset route
(it answers 404 on any instance that is not staged).

Checks: nothing is sent while no hook names an event; "*" and a user hook receive no alert;
a named system hook gets a minimal alert (no address), one with include_details gets the
address; a role change, an API key and five failed sign-ins each send one alert and a
continued burst sends no second; the administrators get an in-portal notification; a stopped
(inactive, enabled) wrapper service sends one 'down' alert after three checks through the
real health loop and a switch to a running unit one 'up' alert (skipped when no suitable
systemd unit exists); who may read or change the alert settings.
"""

import asyncio
import json
import secrets
import subprocess

from aiohttp import web

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    for name, role in (("{sa}", "superadmin"), ("{ad}", "admin"), ("{pl}", "user")):
        u = await create_user(name, "{pw}", is_admin=(role != "user"))
        await db.set_user_role(u["id"], role)
    await db.set_setting("stage_webhook_sink_port", "{port}")
    await db.set_setting("stage_health_interval", "0.4")
    cur = await db.conn.execute("SELECT id FROM users WHERE username = ?", ("{pl}",))
    pid = (await cur.fetchone())["id"]
    # a stream owner, a named target, an anonymous target and ten more targets for the REST ban checks
    ids = {}
    for name in ["{ow}", "{tg}", "{an}"] + ["{tg}_%d" % i for i in range(10)]:
        u = await create_user(name, "{pw}")
        ids[name] = u["id"]
    await db.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (ids["{an}"],))
    await db.conn.commit()
    import server
    sid = await db.create_user_stream(user_id=ids["{ow}"], name="al stream {tag}", stream_key=server.generate_stream_key(),
                                      public_key=server.generate_public_key(), is_public=False)
    cid = await db.create_chat_channel(name="stream-{ow}-%d" % sid, created_by=ids["{ow}"])
    await db.update_user_stream(sid, chat_channel_id=cid)
    await db.conn.close()
    print("RESULT " + json.dumps({"pl": pid, "stream": sid, "tg": ids["{tg}"], "an": ids["{an}"],
                                  "more": [ids["{tg}_%d" % i] for i in range(10)]}))

asyncio.run(main())
'''


def _parse(output):
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    raise RuntimeError("no RESULT line in: " + output[-300:])


def _systemd_units(state):
    """Plain service names in a state, or []. Read-only systemctl."""
    try:
        out = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", f"--state={state}", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    names = []
    for line in out.splitlines():
        unit = line.split(" ", 1)[0] if line.strip() else ""
        if unit.endswith(".service") and "@" not in unit and unit.count(".") == 1:
            names.append(unit[:-len(".service")])
    return names


async def run(ctx):
    tag = secrets.token_hex(3)
    pw = "Al-" + secrets.token_hex(6) + "!"
    names = {"sa": f"al_sa_{tag}", "ad": f"al_ad_{tag}", "pl": f"al_pl_{tag}",
             "ow": f"al_ow_{tag}", "tg": f"al_tg_{tag}", "an": f"al_an_{tag}", "tag": tag}
    got = []

    async def receiver(request):
        got.append((request.path, dict(request.headers), await request.read()))
        return web.Response(status=204)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", receiver)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        await _checks(ctx, tag, pw, names, got, port, f"http://127.0.0.1:{port}")
    finally:
        await runner.cleanup()


async def _checks(ctx, tag, pw, names, got, port, rbase):
    code = SETUP
    for key, val in (("sa", names["sa"]), ("ad", names["ad"]), ("pl", names["pl"]), ("ow", names["ow"]),
                     ("tg", names["tg"]), ("an", names["an"]), ("tag", tag), ("pw", pw), ("port", str(port))):
        code = code.replace("{" + key + "}", val)
    rc, out = await ctx.run_py(code)
    if rc != 0:
        ctx.ok("alerts: set up users, the sink port and the stage health interval", False, out[-300:])
        return
    setup = _parse(out)
    pl_id = setup["pl"]
    ctx.ok("alerts: set up users, the sink port and the stage health interval", True)
    api = ctx.base_url + "/api"

    async def call(sess, method, path, body=None):
        async with sess.request(method, api + path, json=body) as r:
            try:
                data = await r.json(content_type=None)
            except Exception:
                data = None
            return r.status, data

    async def wait_for(pred, timeout=8.0):
        end = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end:
            if pred():
                return True
            await asyncio.sleep(0.1)
        return pred()

    def count(path, event=None):
        n = 0
        for p, _, b in got:
            if p != path:
                continue
            if event is None or json.loads(b).get("event") == event:
                n += 1
        return n

    def svc_count(path):
        """Health alerts about this module's own wrapper service only: a production copy holds
        real enabled services that a staged instance never starts, and they count as down."""
        return sum(1 for p, _, b in got if p == path and json.loads(b).get("event") == "service.health_changed"
                   and tag in json.loads(b)["data"]["summary"])

    async with ctx.http() as sa, ctx.http() as ad:
        r1 = await ctx.login(sa, names["sa"], pw)
        r2 = await ctx.login(ad, names["ad"], pw)
        if r1.status != 200 or r2.status != 200:
            ctx.ok("alerts: sign in as the module's own superadmin and admin", False, f"{r1.status}/{r2.status}")
            return
        ctx.ok("alerts: sign in as the module's own superadmin and admin", True)

        # ---- who may read and change the alert settings
        st, d = await call(ad, "GET", "/admin/alerts")
        ctx.ok("alerts: an ordinary admin cannot read the alert settings", st in (401, 403), str(st))
        st, d = await call(sa, "GET", "/admin/alerts")
        ctx.ok("alerts: the superadmin reads three event groups and the notification switches",
               st == 200 and [g["group"] for g in d["groups"]] == ["security", "operations", "moderation"]
               and d["notify"].get("role.changed") is True and d["notify"].get("backup.ok") is False, f"{st} {d}")
        st, d = await call(sa, "PUT", "/admin/alerts/notify", {"event": "nope", "enabled": True})
        ctx.ok("alerts: an unknown alert event is refused", st == 400, str(st))
        st, d = await call(ad, "PUT", "/admin/alerts/notify", {"event": "role.changed", "enabled": True})
        ctx.ok("alerts: an ordinary admin cannot change the notification switches", st in (401, 403), str(st))
        st, d = await call(ad, "POST", "/admin/alerts/stage-reset")
        ctx.ok("alerts: an ordinary admin cannot call the stage reset", st in (401, 403), str(st))
        st, d = await call(sa, "POST", "/admin/alerts/stage-reset")
        ctx.ok("alerts: the superadmin resets the limiter state on a staged instance", st == 200, f"{st} {d}")

        # ---- nothing is sent while no hook names an event
        st, d = await call(sa, "PUT", f"/users/{pl_id}/role", {"role": "moderator"})
        await asyncio.sleep(1.0)
        ctx.ok("alerts: a role change with no subscribed hook sends nothing", st == 200 and not got, f"{st} {len(got)}")

        # ---- hooks: minimal, with details, '*', and a user hook that names an alert
        events = ["role.changed", "auth.login_failed_burst", "apikey.created", "service.health_changed",
                  "moderation.action"]
        hooks = {}
        for key, extra in (("min", {"events": events}), ("det", {"events": events, "include_details": True}),
                           ("star", {"events": ["*"]})):
            st, h = await call(sa, "POST", "/admin/webhooks", {
                "name": f"al_{key}_{tag}", "format": "generic", "url": rbase + "/" + key,
                "allow_private": True, **extra})
            ctx.ok(f"alerts: system hook '{key}' created", st == 201, f"{st} {h}")
            if st != 201:
                return
            hooks[key] = h
        st, e = await call(sa, "POST", "/webhooks", {"name": f"al_user_{tag}", "url": rbase + "/user",
                                                    "events": ["role.changed"], "allow_private": True})
        ctx.ok("alerts: a user hook may not subscribe to an alert", st == 400, f"{st} {e}")

        # ---- role change: one alert per hook
        await call(sa, "POST", "/admin/alerts/stage-reset")
        got.clear()
        st, d = await call(sa, "PUT", f"/users/{pl_id}/role", {"role": "user"})
        ok = await wait_for(lambda: count("/min", "role.changed") >= 1 and count("/det", "role.changed") >= 1)
        await asyncio.sleep(0.6)
        ctx.ok("alerts: a role change reaches the named hooks once and the '*' hook not at all",
               st == 200 and ok and count("/min", "role.changed") == 1 and count("/det", "role.changed") == 1
               and count("/star") == 0 and count("/user") == 0, f"{st} {[g[0] for g in got]}")
        mins = [json.loads(b) for p, _, b in got if p == "/min" and json.loads(b)["event"] == "role.changed"]
        dets = [json.loads(b) for p, _, b in got if p == "/det" and json.loads(b)["event"] == "role.changed"]
        if mins and dets:
            body = next(b for p, _, b in got if p == "/min" and json.loads(b)["event"] == "role.changed").decode()
            ctx.ok("alerts: the minimal body names the account and says nothing of an address or agent",
                   names["pl"] in mins[0]["data"]["summary"] and "details" not in mins[0]["data"]
                   and "127.0.0.1" not in body and "Python" not in body, body[:200])
            ctx.ok("alerts: the include_details hook also gets the address",
                   dets[0]["data"].get("details", {}).get("Address") not in (None, ""), str(dets[0]))
            hdrs = next(h for p, h, b in got if p == "/min" and json.loads(b)["event"] == "role.changed")
            ctx.ok("alerts: an alert to a generic hook is still signed", "X-Portal-Signature" in hdrs)

        # ---- API key
        got.clear()
        st, d = await call(sa, "POST", "/api-keys", {"name": f"al_key_{tag}"})
        ok = await wait_for(lambda: count("/min", "apikey.created") >= 1)
        body = next((b.decode() for p, _, b in got if p == "/min" and json.loads(b)["event"] == "apikey.created"), "")
        ctx.ok("alerts: creating an API key sends one alert that does not contain the key",
               st in (200, 201) and ok and count("/min", "apikey.created") == 1
               and (not isinstance(d, dict) or not d.get("key") or d["key"] not in body), f"{st} {[g[0] for g in got]}")

        # ---- a stream ban over the REST route sends the same moderation alert as the websocket
        await call(sa, "POST", "/admin/alerts/stage-reset")
        got.clear()
        async with ctx.http() as ow:
            r = await ctx.login(ow, names["ow"], pw)
            if r.status != 200:
                ctx.ok("alerts: sign in as the stream owner", False, str(r.status))
            else:
                bans = f"/streams/{setup['stream']}/bans"
                st, d = await call(ow, "POST", bans, {"user_id": setup["tg"], "reason": "smoke " + tag})
                ok = await wait_for(lambda: count("/min", "moderation.action") >= 1)
                evs = [json.loads(b) for p, _, b in got if p == "/min" and json.loads(b)["event"] == "moderation.action"]
                ctx.ok("alerts: a stream ban over the REST route sends one moderation alert naming both accounts",
                       st == 201 and ok and len(evs) == 1 and names["ow"] in evs[0]["data"]["summary"]
                       and names["tg"] in evs[0]["data"]["summary"] and "banned" in evs[0]["data"]["summary"],
                       f"{st} {[e['data']['summary'] for e in evs]}")
                got.clear()
                st, d = await call(ow, "POST", bans, {"user_id": setup["an"]})
                ok = await wait_for(lambda: count("/min", "moderation.action") >= 1)
                evs = [b.decode() for p, _, b in got if p == "/min" and json.loads(b)["event"] == "moderation.action"]
                ctx.ok("alerts: a REST ban of an anonymous member does not name the member",
                       st == 201 and ok and len(evs) == 1 and names["an"] not in evs[0]
                       and "anonymous member" in evs[0], f"{st} {evs}")

                # ---- what a member can set off cannot use up the room of the other alerts
                got.clear()
                for uid in setup["more"]:
                    await call(ow, "POST", bans, {"user_id": uid})
                await asyncio.sleep(1.0)
                sent = count("/min", "moderation.action")
                ctx.ok("alerts: ten more REST bans stay inside the member sub-cap of five in all (two were sent above)",
                       sent == 3, str(sent))
                got.clear()
                st, d = await call(sa, "PUT", f"/users/{setup['tg']}/role", {"role": "moderator"})
                ok = await wait_for(lambda: count("/min", "role.changed") >= 1)
                ctx.ok("alerts: a role change right after the ban flood still sends its alert",
                       st == 200 and ok, f"{st} {[(p, json.loads(b).get('event')) for p, _, b in got]}")
                # a second, different change of the same account inside the 60 s cooldown is heard too
                got.clear()
                st, d = await call(sa, "PUT", f"/users/{setup['tg']}/role", {"role": "admin"})
                ok = await wait_for(lambda: count("/min", "role.changed") >= 1)
                ctx.ok("alerts: a second, different role change of the same account within a minute sends its alert",
                       st == 200 and ok, f"{st} {[(p, json.loads(b).get('event')) for p, _, b in got]}")
                await call(sa, "PUT", f"/users/{setup['tg']}/role", {"role": "user"})
                # the moderation bucket is full: an account-security alert still goes out
                got.clear()
                st, d = await call(sa, "POST", "/api-keys", {"name": f"al_key2_{tag}"})
                ok = await wait_for(lambda: count("/min", "apikey.created") >= 1)
                ctx.ok("alerts: a new API key sends its alert although the moderation sub-cap is used up",
                       st in (200, 201) and ok, f"{st} {[(p, json.loads(b).get('event')) for p, _, b in got]}")
                # the member bucket is full: a superadmin's ban of the same kind still alerts (staff bypass)
                got.clear()
                st, d = await call(sa, "POST", bans, {"user_id": pl_id, "reason": "staff " + tag})
                ok = await wait_for(lambda: count("/min", "moderation.action") >= 1)
                ctx.ok("alerts: a superadmin's stream ban still alerts although the member moderation cap is used up",
                       st == 201 and ok, f"{st} {[(p, json.loads(b).get('event')) for p, _, b in got]}")

        # ---- five failed sign-ins in a minute: one burst alert
        got.clear()
        for i in range(5):
            async with ctx.http() as anon:
                resp = await ctx.login(anon, names["pl"], "wrong-" + secrets.token_hex(4))
                if resp.status == 429:
                    break
        ok = await wait_for(lambda: count("/min", "auth.login_failed_burst") >= 1)
        await asyncio.sleep(0.5)
        for i in range(4):
            async with ctx.http() as anon:
                await ctx.login(anon, names["pl"], "wrong-" + secrets.token_hex(4))
        await asyncio.sleep(1.0)
        ctx.ok("alerts: five failed sign-ins send one burst alert, and more inside the cooldown none",
               ok and count("/min", "auth.login_failed_burst") == 1 and count("/det", "auth.login_failed_burst") == 1,
               str([(p, json.loads(b).get("event")) for p, _, b in got]))
        body = next((b.decode() for p, _, b in got if p == "/min" and json.loads(b)["event"] == "auth.login_failed_burst"), "")
        ctx.ok("alerts: the burst summary has no address and no account name; the include_details hook has the account",
               "127.0.0.1" not in body and names["pl"] not in json.loads(body)["data"]["summary"]
               and any(names["pl"] == json.loads(b)["data"].get("details", {}).get("Account")
                       for p, _, b in got if p == "/det"), body[:200])

        # ---- in-portal notification for administrators
        st, d = await call(sa, "GET", "/notifications?limit=50")
        kinds = [n.get("type") for n in (d or {}).get("notifications", [])]
        ctx.ok("alerts: the superadmin got in-portal notifications of type alert", st == 200 and "alert" in kinds, str(kinds[:6]))

        # ---- service health through the real loop (wrapper over inactive then running units)
        inactive = [u for u in _systemd_units("inactive") if u not in ("systemd-networkd-wait-online",)]
        active = _systemd_units("active")
        if not inactive or not active:
            ctx.skip("alerts: service down and up alerts through the health loop", "no suitable systemd units on this host")
        else:
            await call(sa, "POST", "/admin/alerts/stage-reset")
            got.clear()
            svc_name = f"al-svc-{tag}"
            st, s = await call(sa, "POST", "/managed-services", {
                "name": svc_name, "type": "systemd", "display_name": f"AL Service {tag}",
                "config": {"unit": inactive[0]}, "enabled": False})
            sid = ((s or {}).get("service") or {}).get("id")
            if st not in (200, 201) or not sid:
                ctx.ok("alerts: wrapper service created for the health check", False, f"{st} {s}")
            else:
                try:
                    st, s = await call(sa, "PUT", f"/managed-services/{sid}", {"enabled": True})
                    ok = await wait_for(lambda: svc_count("/min") >= 1, 15.0)
                    await asyncio.sleep(2.0)
                    ctx.ok("alerts: an enabled stopped service sends one 'down' alert after three checks, no repeats",
                           ok and svc_count("/min") == 1, str([(p, b[:80]) for p, _, b in got]))
                    first = next((json.loads(b) for p, _, b in got if p == "/min" and tag in b.decode()), {})
                    ctx.ok("alerts: the down alert says the service is down",
                           "down" in first.get("data", {}).get("summary", ""), str(first))
                    st, s = await call(sa, "PUT", f"/managed-services/{sid}", {"config": {"unit": active[0]}})
                    ok = await wait_for(lambda: svc_count("/min") >= 2, 15.0)
                    await asyncio.sleep(2.0)
                    ctx.ok("alerts: switching to a running unit sends one 'up' alert",
                           ok and svc_count("/min") == 2, str([(p, b[:80]) for p, _, b in got]))
                finally:
                    await call(sa, "DELETE", f"/managed-services/{sid}")

        # ---- clean up: the hooks, and the fast health cadence for the modules that follow
        for h in hooks.values():
            await call(sa, "DELETE", f"/admin/webhooks/{h['id']}")
        await ctx.run_py("import asyncio\nfrom database import db\n\nasync def main():\n"
                         "    await db.connect()\n    await db.delete_setting('stage_health_interval')\n"
                         "    await db.conn.close()\n\nasyncio.run(main())\n")
