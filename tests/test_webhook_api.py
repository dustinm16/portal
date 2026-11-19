"""Webhook API: formats and credentials on user hooks, masking, allow_private authority,
system hooks (superadmin only, own routes, no payloads in the delivery list), event
classes, and the Test route reporting the receiver's status.

Receiver: a local aiohttp server on 127.0.0.1. Nothing leaves this machine.

Run: venv/bin/python tests/test_webhook_api.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()  # a fixture URL that is not loopback can never be dialled
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
import webhook_formats as wf  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


PW = {"sa": "Sa-pass-12345!", "adm": "Adm-pass-12345!", "u1": "U1-pass-12345!"}
got = []
answer = [204]


async def receiver(request):
    got.append((request.path, dict(request.headers), await request.read()))
    return web.Response(status=answer[0], text="BODY-FROM-RECEIVER")


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
    ids = {}
    for name, role in (("sa", "superadmin"), ("adm", "admin"), ("u1", None)):
        u = await create_user(name, PW[name], is_admin=role in ("admin", "superadmin"))
        if role:
            await db.set_user_role(u["id"], role)
        ids[name] = u["id"]

    rapp = web.Application()
    rapp.router.add_route("*", "/{tail:.*}", receiver)
    rsrv = TestServer(rapp, host="127.0.0.1")
    await rsrv.start_server()
    rbase = f"http://127.0.0.1:{rsrv.port}"
    # the receiver lives in this process: pin "own sockets" to the portal's port only
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())

    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()

    def client():
        return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def login(sess, name):
        async with sess.post(base + "/login", json={"username": name, "password": PW[name]}) as r:
            assert r.status == 200, await r.text()

    async def call(sess, method, path, body=None, headers=None):
        async with sess.request(method, base + path, json=body, headers=headers) as r:
            try:
                data = await r.json(content_type=None)
            except Exception:
                data = None
            return r.status, data

    async with client() as sa, client() as adm, client() as u1, client() as sa_api:
        await login(sa, "sa")
        await login(adm, "adm")
        await login(u1, "u1")
        # a superadmin credential that is not a browser session
        st, tok = await call(sa_api, "POST", "/api/token", {"username": "sa", "password": PW["sa"]})
        bearer = {"Authorization": "Bearer " + (tok or {}).get("token", "")}
        check("got a non-cookie superadmin bearer token", st in (200, 201) and bearer["Authorization"] != "Bearer ", str((st, tok)))

        # ---------------- user hooks
        st, h = await call(adm, "POST", "/api/webhooks", {
            "name": "family", "events": ["stream.live"], "format": "discord",
            "url": "https://discord.com/api/webhooks/42/DISCORDSECRETTOKEN"})
        check("admin creates a discord hook (https public)", st == 201 and h["format"] == "discord", str((st, h)))
        check("create response: no url, no secret, masked host, nothing sensitive",
              h["url"] is None and "secret" not in h and h["url_host"] == "https://discord.com"
              and "DISCORDSECRETTOKEN" not in json.dumps(h))
        hid = h["id"]
        for path in ("/api/webhooks", f"/api/webhooks/{hid}"):
            st, data = await call(adm, "GET", path)
            check(f"GET {path} shows no destination path", "DISCORDSECRETTOKEN" not in json.dumps(data))
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["*"], "format": "ntfy", "url": "http://ntfy.example/topic"})
        check("non-generic needs https without allow_private", st == 400, str((st, e)))
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["*"], "format": "gotify", "url": "https://93.184.216.34"})
        check("gotify without a token is refused", st == 400, str((st, e)))
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["*"], "format": "discord",
                                                          "url": "https://93.184.216.34/x", "format_config": {"token": "t"}})
        check("credentials on a format that takes none are refused", st == 400)
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["webhook.test"], "format": "slack", "url": "https://93.184.216.34/x"})
        check("a user hook cannot subscribe to a system-only event", st == 400, str((st, e)))
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["*"], "format": "bogus", "url": "https://93.184.216.34/x"})
        check("unknown format is refused", st == 400)
        st, e = await call(adm, "POST", "/api/webhooks", {"name": "x", "events": ["*"], "url": rbase + "/x"})
        check("generic hook to loopback is refused as before", st == 400)

        # allow_private authority
        body = {"name": "lan-ntfy", "events": ["user.joined"], "format": "ntfy", "url": rbase + "/topic",
                "format_config": {"token": "tk_NTFYTOKEN"}, "allow_private": True}
        st, e = await call(adm, "POST", "/api/webhooks", body)
        check("an ordinary admin cannot set allow_private", st == 403, str((st, e)))
        st, e = await call(sa_api, "POST", "/api/webhooks", body, headers=bearer)
        check("a superadmin without a browser session cannot either", st == 403, str((st, e)))
        st, e = await call(sa, "POST", "/api/webhooks", body, headers=bearer)
        check("a bearer token cannot set it even with a superadmin session cookie in the same request", st == 403, str((st, e)))
        st, e = await call(adm, "POST", "/api/webhooks", body, headers=bearer)
        check("nor with another user's session cookie (actor and authority are one token)", st == 403, str((st, e)))
        st, e = await call(sa, "POST", "/api/admin/webhooks", {"name": "s", "events": ["*"], "format": "gotify", "url": rbase,
                                                              "allow_private": True, "format_config": {"token": "T"}}, headers=bearer)
        check("system route: bearer plus a superadmin cookie is refused too", st == 403, str((st, e)))
        st, e = await call(sa, "POST", "/api/webhooks", body, headers={"X-API-Key": "portal_nonsense"})
        check("a request carrying an API key header is refused whatever the cookie says", st == 403, str((st, e)))
        qtok = (tok or {}).get("token", "")
        n_hooks = len(await db.get_all_webhooks())
        st, e = await call(sa, "POST", "/api/webhooks?token=" + qtok, body)
        check("?token=<api token> with a superadmin cookie cannot set allow_private", st == 403, str((st, e)))
        st, e = await call(sa, "POST", "/api/admin/webhooks?token=" + qtok, {
            "name": "s", "events": ["*"], "format": "gotify", "url": rbase, "allow_private": True,
            "format_config": {"token": "T"}})
        check("nor on the system route", st == 403, str((st, e)))
        check("and nothing was created by those two requests", len(await db.get_all_webhooks()) == n_hooks)
        before = len(await secevents_rows())
        st, lan = await call(sa, "POST", "/api/webhooks", body)
        check("superadmin with a cookie session can", st == 201 and lan["allow_private"] is True
              and lan["has_format_secret"] is True and "tk_NTFYTOKEN" not in json.dumps(lan), str((st, lan)))
        await secevents.log.flush()
        evs = [r for r in await secevents_rows() if r["event"] == "webhook_allow_private"]
        check("enabling allow_private wrote a security event without url or token",
              len(evs) == 1 and evs[0]["result"] == "enabled" and "tk_NTFYTOKEN" not in json.dumps(evs)
              and rbase not in json.dumps(evs), str(evs))
        audits = await db.get_audit_log(action="webhook_allow_private")
        check("and an audit entry", len(audits) == 1 and "tk_NTFYTOKEN" not in json.dumps(audits, default=str), str(audits))
        lid = lan["id"]
        st, e = await call(adm, "PUT", f"/api/webhooks/{lid}", {"url": rbase + "/other"})
        check("an admin cannot re-aim a private hook", st == 403, str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{lid}", {"name": "renamed"})
        check("but can rename it, and the token survives",
              st == 200 and (await db.get_webhook_for_delivery(lid))["format_config"] == {"token": "tk_NTFYTOKEN"})
        st, e = await call(adm, "PUT", f"/api/webhooks/{lid}", {"allow_private": False})
        check("any editor can switch allow_private off, even when the stored address is now refused",
              st == 200 and e["allow_private"] in (False, 0)
              and (await db.get_webhook_for_delivery(lid))["url"] == rbase + "/topic", str((st, e)))
        st, e = await call(sa, "PUT", f"/api/webhooks/{lid}", {"allow_private": True})
        check("switching it back on re-checks and is allowed for a browser superadmin", st == 200 and e["allow_private"] in (True, 1), str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{lid}", {"allow_private": False, "name": "lan-ntfy"})
        check("switching it off together with an unchanged name also works", st == 200, str((st, e)))
        st, e = await call(sa, "PUT", f"/api/webhooks/{lid}", {"allow_private": True})
        check("and on again", st == 200)
        st, e = await call(sa, "PUT", f"/api/webhooks/{lid}", {"format_config": {"token": "tk_NEW"}})
        check("superadmin rotates the token",
              st == 200 and (await db.get_webhook_for_delivery(lid))["format_config"]["token"] == "tk_NEW")
        st, e = await call(sa, "PUT", f"/api/webhooks/{lid}", {"url": f"http://127.0.0.1:{Config.PORT}/x"})
        check("even a superadmin cannot aim at the portal's own port", st == 400, str((st, e)))
        st, e = await call(sa, "PUT", f"/api/webhooks/{lid}", {"url": "http://169.254.169.254/latest"})
        check("or at the metadata address", st == 400)

        # test route
        answer[0] = 204
        st, r = await call(sa, "POST", f"/api/webhooks/{lid}/test")
        check("Test reports the receiver's status", st == 200 and r["status"] == 204 and r["success"] and r["format"] == "ntfy", str((st, r)))
        path, hdrs, _ = got[-1]
        check("Test arrived with title, priority and the new bearer token",
              path == "/topic" and "Title" in hdrs and hdrs["Priority"] == "3" and hdrs["Authorization"] == "Bearer tk_NEW")
        answer[0] = 429
        st, r = await call(sa, "POST", f"/api/webhooks/{lid}/test")
        check("Test reports a 429 at once, without the receiver's body",
              r["status"] == 429 and not r["success"] and "BODY-FROM-RECEIVER" not in json.dumps(r), str(r))
        w = await db.get_webhook(lid)
        check("that 429 did not count toward auto-disable", w["consecutive_failures"] == 0)
        answer[0] = 500
        st, r = await call(sa, "POST", f"/api/webhooks/{lid}/test")
        w = await db.get_webhook(lid)
        check("a 500 does count", r["status"] == 500 and w["consecutive_failures"] == 1)
        answer[0] = 204

        # logs of a user hook
        st, lg = await call(adm, "GET", f"/api/webhooks/{lid}/logs")
        check("delivery log of a non-generic hook has no payload", st == 200 and lg["logs"]
              and all(x["request_payload"] is None for x in lg["logs"]))

        # regenerate only for generic
        st, e = await call(adm, "POST", f"/api/webhooks/{lid}/regenerate-secret")
        check("signing secret regeneration is generic-only", st == 400)

        # switching to generic must not expose the stored credential URL
        SECRET_URL = "https://93.184.216.34/api/webhooks/42/DISCORDSECRETTOKEN"
        st, dh = await call(adm, "POST", "/api/webhooks", {
            "name": "sw", "events": ["stream.live"], "format": "discord", "url": SECRET_URL})
        check("create answer shows no discord url", st == 201 and "DISCORDSECRETTOKEN" not in json.dumps(dh), str((st, dh)))
        did = dh["id"]
        st, e = await call(adm, "PUT", f"/api/webhooks/{did}", {"format": "generic"})
        check("switching to generic without a new url is refused and leaks nothing",
              st == 400 and "DISCORDSECRETTOKEN" not in json.dumps(e), str((st, e)))
        st, lst = await call(adm, "GET", "/api/webhooks")
        st2, one = await call(adm, "GET", f"/api/webhooks/{did}")
        check("the hook is unchanged and its url still not shown",
              "DISCORDSECRETTOKEN" not in json.dumps([lst, one]) and (await db.get_webhook(did))["format"] == "discord",
              str((lst, one)))
        st, e = await call(sa, "PUT", f"/api/webhooks/{did}", {"format": "generic", "name": "sw2"})
        check("a superadmin gets the same refusal", st == 400 and "DISCORDSECRETTOKEN" not in json.dumps(e), str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{did}", {"format": "generic", "url": "https://93.184.216.34/new-generic"})
        check("switching to generic with a new url works, the new url is the generic one",
              st == 200 and e["url"] == "https://93.184.216.34/new-generic" and "DISCORDSECRETTOKEN" not in json.dumps(e), str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{did}", {"format": "slack"})
        check("any format change without a new url is refused (the stored address is never reused for another service)",
              st == 400 and "url" in (e.get("error") or ""), str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{did}", {"format": "slack", "url": "https://93.184.216.34/slack-hook"})
        check("a format change with a new url works, the address is masked", st == 200 and e["url"] is None and e["url_host"], str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{did}", {"format": "slack", "name": "renamed"})
        check("an edit that repeats the unchanged format needs no url", st == 200, str((st, e)))
        sid2 = (await call(sa, "POST", "/api/admin/webhooks", {"name": "fmt-sys", "events": ["webhook.test"], "format": "ntfy",
                                                               "url": "https://93.184.216.34/fmt"}))[1]["id"]
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sid2}", {"format": "discord"})
        check("the system hook route refuses a format change without a url too", st == 400, str((st, e)))
        await call(sa, "DELETE", f"/api/admin/webhooks/{sid2}")
        st, e = await call(adm, "DELETE", f"/api/webhooks/{did}")

        # ---------------- system hooks
        sbody = {"name": "ops-ntfy", "events": ["*"], "format": "ntfy", "url": "https://93.184.216.34/ops",
                 "format_config": {"username": "u", "password": "PASSWORD-X"}}
        for sess, label, hdr in ((adm, "admin", None), (u1, "user", None)):
            st, e = await call(sess, "POST", "/api/admin/webhooks", sbody)
            check(f"{label} cannot create a system hook", st in (401, 403), str(st))
            st, e = await call(sess, "GET", "/api/admin/webhooks")
            check(f"{label} cannot list system hooks", st in (401, 403))
        st, s1 = await call(sa_api, "POST", "/api/admin/webhooks", sbody, headers=bearer)
        check("superadmin creates a system hook (any full credential)", st == 201 and s1["kind"] == "system"
              and s1["user_id"] is None and "PASSWORD-X" not in json.dumps(s1), str((st, s1)))
        sid = s1["id"]
        st, lst = await call(sa, "GET", "/api/admin/webhooks")
        check("list shows system hooks only, with formats and event classes",
              st == 200 and [x["id"] for x in lst["webhooks"]] == [sid] and "ntfy" in lst["formats"]
              and "webhook.test" in lst["system_only_events"]
              and set(wf.ALERT_EVENTS) <= set(lst["system_only_events"]) and set(wf.ALERT_EVENTS) <= set(lst["events"])
              and [g["group"] for g in lst["alert_groups"]] == ["security", "operations", "moderation"])
        st, mine = await call(adm, "GET", "/api/webhooks")
        check("the ordinary list leaves system hooks out", all(x["id"] != sid for x in mine["webhooks"]))
        for method, suffix in (("GET", ""), ("PUT", ""), ("DELETE", ""), ("GET", "/logs"), ("POST", "/test"),
                               ("POST", "/regenerate-secret")):
            st, e = await call(adm, method, f"/api/webhooks/{sid}{suffix}", {"name": "z"} if method == "PUT" else None)
            check(f"{method} /api/webhooks/<system id>{suffix} is 404 for an admin", st == 404, str(st))
            st, e = await call(sa, method, f"/api/webhooks/{sid}{suffix}", {"name": "z"} if method == "PUT" else None)
            check(f"{method} /api/webhooks/<system id>{suffix} is 404 even for a superadmin (own routes)", st == 404, str(st))
        st, e = await call(sa_api, "POST", "/api/admin/webhooks", {**sbody, "allow_private": True, "url": rbase + "/x"}, headers=bearer)
        check("system hook allow_private also needs a browser session", st == 403)
        st, s2 = await call(sa, "POST", "/api/admin/webhooks", {"name": "sys-lan", "events": ["*"], "format": "gotify",
                                                               "url": rbase, "allow_private": True,
                                                               "format_config": {"token": "GTK"}})
        check("system LAN hook created from a browser session", st == 201, str((st, s2)))
        answer[0] = 200
        got.clear()
        st, r = await call(sa_api, "POST", f"/api/admin/webhooks/{s2['id']}/test", headers=bearer)
        check("system hook Test reports status; Gotify path and header",
              r["status"] == 200 and got and got[-1][0] == "/message" and got[-1][1].get("X-Gotify-Key") == "GTK", str((r, got)))
        st, lg = await call(sa, "GET", f"/api/admin/webhooks/{s2['id']}/logs")
        check("system delivery list: status only, no payload or response bodies",
              st == 200 and lg["logs"] and set(lg["logs"][0]) == {"id", "event", "response_status", "success", "attempt", "duration_ms", "created_at"}
              and "BODY-FROM-RECEIVER" not in json.dumps(lg))
        # the admin form sends the whole hook back, including the unchanged URL of a generic hook
        st, sg = await call(sa, "POST", "/api/admin/webhooks", {"name": "sys-generic-lan", "events": ["stream.live"],
                                                               "format": "generic", "url": rbase + "/g", "allow_private": True})
        check("generic system hook with allow_private created from a browser session", st == 201, str((st, sg)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", {
            "name": "sys-generic-lan", "format": "generic", "events": ["stream.live"], "include_details": False,
            "allow_private": False, "url": rbase + "/g", "enabled": True})
        check("the admin form can switch allow_private off on a generic LAN hook (same URL sent again)",
              st == 200 and e["allow_private"] in (False, 0), str((st, e)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", {
            "name": "sys-generic-lan", "format": "generic", "events": ["stream.live"], "allow_private": False,
            "url": rbase + "/g2", "enabled": True})
        check("but sending a different URL with it is checked against the default policy", st == 400, str((st, e)))
        form = {"name": "sys-generic-lan", "format": "generic", "events": ["stream.live"], "include_details": False,
                "allow_private": False, "url": rbase + "/g", "enabled": True}
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", form)
        check("a narrowed hook saves again with the same form body", st == 200, str((st, e)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", {**form, "enabled": False})
        check("a narrowed generic hook can be disabled from the form (same URL, allow_private off)",
              st == 200 and e["enabled"] in (0, False), str((st, e)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", {**form, "name": "renamed", "events": ["*"]})
        check("and renamed and given other events", st == 200 and e["name"] == "renamed" and e["events"] == ["*"], str((st, e)))
        await call(sa, "DELETE", f"/api/admin/webhooks/{sg['id']}")
        # a non-generic hook over plain http to loopback, narrowed, then edited again from the form
        st, sn = await call(sa, "POST", "/api/admin/webhooks", {"name": "sys-ntfy-lan", "events": ["stream.live"],
                                                               "format": "ntfy", "url": rbase + "/t", "allow_private": True,
                                                               "format_config": {"token": "NT"}})
        check("ntfy system hook over http with allow_private created", st == 201, str((st, sn)))
        nform = {"name": "sys-ntfy-lan", "format": "ntfy", "events": ["stream.live"], "include_details": False,
                 "allow_private": False, "enabled": True}
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sn['id']}", nform)
        check("switching allow_private off on it is allowed", st == 200, str((st, e)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sn['id']}", {**nform, "enabled": False})
        check("a narrowed plain-http ntfy hook can be disabled from the form",
              st == 200 and e["enabled"] in (0, False), str((st, e)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sn['id']}", {**nform, "url": rbase + "/t2"})
        check("a changed URL on it is still refused (non-generic needs https)", st == 400, str((st, e)))
        await call(sa, "DELETE", f"/api/admin/webhooks/{sn['id']}")
        # the user route
        st, ul = await call(sa, "POST", "/api/webhooks", {"name": "user-lan", "events": ["user.joined"], "format": "ntfy",
                                                         "url": rbase + "/u", "allow_private": True,
                                                         "format_config": {"token": "UT"}})
        check("user hook with allow_private created", st == 201, str((st, ul)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{ul['id']}", {"allow_private": False})
        check("an admin switches it off", st == 200, str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{ul['id']}", {"allow_private": False, "enabled": False})
        check("and can then disable it", st == 200 and e["enabled"] in (0, False), str((st, e)))
        await call(sa, "DELETE", f"/api/webhooks/{ul['id']}")
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{s2['id']}", {"enabled": False})
        check("system hook can be disabled", st == 200 and e["enabled"] in (0, False))
        st, e = await call(sa, "POST", f"/api/admin/webhooks/{s2['id']}/test")
        check("a disabled hook is not tested", st == 400)
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{s2['id']}", {"events": ["webhook.test", "stream.live"], "enabled": True})
        check("a system hook may list system-only events", st == 200 and "webhook.test" in e["events"], str((st, e)))
        cur = await db.conn.execute("SELECT action FROM audit_log WHERE action LIKE 'webhook_%'")
        acts = {r["action"] for r in await cur.fetchall()}
        check("audit entries for system hook create/update", {"webhook_system_create", "webhook_system_update"} <= acts, str(acts))
        # a creating superadmin's deletion leaves system hooks alone
        await db.conn.execute("DELETE FROM users WHERE id = ?", (ids["sa"],))
        await db.conn.commit()
        check("deleting the creator keeps the system hook", await db.get_webhook(sid) is not None)
        # raw db holds no credential in the clear
        cur = await db.conn.execute("SELECT url, secret, format_config FROM webhooks")
        dump = json.dumps([list(r) for r in await cur.fetchall()])
        check("no token, password or URL in the clear in the table",
              not any(t in dump for t in ("tk_NEW", "tk_NTFYTOKEN", "PASSWORD-X", "GTK", "DISCORDSECRETTOKEN", "93.184.216.34")))

    await srv.close()
    await rsrv.close()
    await db.conn.close()


async def secevents_rows():
    cur = await server.db.conn.execute("SELECT * FROM security_events ORDER BY id")
    return [dict(r) for r in await cur.fetchall()]


asyncio.run(main())
outbound_guard.report("test_webhook_api")
if failures:
    print(f"{len(failures)} failed")
sys.exit(1 if failures else 0)
