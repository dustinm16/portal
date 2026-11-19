"""Webhook review fixes: stored credentials do not follow a hook to a new destination,
credential scope on the user webhook routes, anonymous and appear-offline events in the
generic format, the receiver's answer is read in a bounded way, and an event dropped
while a hook is paused by a 429 still counts into the alerts notice.

Receivers are local aiohttp servers on 127.0.0.1; validation-only cases use 93.184.216.34
and 198.51.100.x names, which are never connected to.

Run: venv/bin/python tests/test_webhook_review_fixes.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


PW = {"sa": "Sa-pass-12345!", "adm": "Adm-pass-12345!", "adm2": "Adm2-pass-12345!", "u1": "U1-pass-12345!"}


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
    ids = {}
    for name, role in (("sa", "superadmin"), ("adm", "admin"), ("adm2", "admin"), ("u1", None)):
        u = await create_user(name, PW[name], is_admin=role in ("admin", "superadmin"))
        if role:
            await db.set_user_role(u["id"], role)
        ids[name] = u["id"]
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

    async def stored(hid):
        return await db.get_webhook_for_delivery(hid)

    async with client() as sa, client() as adm, client() as plain:
        await login(sa, "sa")
        await login(adm, "adm")

        # ---------------- 1. credentials stay with their destination
        H = "https://93.184.216.34"
        st, g = await call(adm, "POST", "/api/webhooks", {
            "name": "g", "events": ["stream.live"], "format": "gotify", "url": H + "/gotify",
            "format_config": {"token": "GOTIFYTOKEN"}})
        check("gotify hook created", st == 201, str((st, g)))
        gid = g["id"]
        st, e = await call(adm, "PUT", f"/api/webhooks/{gid}", {"url": "https://93.184.216.35/gotify"})
        check("gotify: a new host without format_config is refused and says to send the credential again",
              st == 400 and "again" in json.dumps(e), str((st, e)))
        w = await stored(gid)
        check("gotify: the refused edit changed nothing", w["url"] == H + "/gotify" and w["format_config"] == {"token": "GOTIFYTOKEN"})
        st, e = await call(adm, "PUT", f"/api/webhooks/{gid}", {"url": H + "/other/path"})
        w = await stored(gid)
        check("gotify: a path-only change keeps the token", st == 200 and w["format_config"] == {"token": "GOTIFYTOKEN"}, str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{gid}", {"url": H + ":8443/x"})
        check("gotify: a new port is a new destination", st == 400, str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{gid}", {"url": "https://93.184.216.35/g", "format_config": {"token": "NEWTOKEN"}})
        w = await stored(gid)
        check("gotify: a new host with a token sent again is saved", st == 200 and w["format_config"] == {"token": "NEWTOKEN"}, str((st, e)))

        st, n = await call(adm, "POST", "/api/webhooks", {
            "name": "n", "events": ["stream.live"], "format": "ntfy", "url": H + "/topic",
            "format_config": {"token": "NTFYTOKEN", "username": "u", "password": "p"}})
        nid = n["id"]
        check("ntfy hook created with credentials", st == 201 and (await stored(nid))["format_config"]["token"] == "NTFYTOKEN", str((st, n)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{nid}", {"url": H + "/topic2", "name": "n2"})
        check("ntfy: a path-only change keeps the credentials", st == 200 and (await stored(nid))["format_config"]["token"] == "NTFYTOKEN", str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{nid}", {"url": "https://93.184.216.35/topic"})
        w = await stored(nid)
        check("ntfy: a new host drops the stored credentials", st == 200 and not w["format_config"] and w["url"] == "https://93.184.216.35/topic", str((st, e, w)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{nid}", {"format_config": {"token": "T2"}})
        st, e = await call(adm, "PUT", f"/api/webhooks/{nid}", {"url": "https://93.184.216.34/t", "format_config": {"username": "u2"}})
        check("ntfy: a partial format_config on a new host does not borrow the stored password", st == 400, str((st, e)))
        st, e = await call(adm, "PUT", f"/api/webhooks/{nid}", {"url": "https://93.184.216.34/t", "format_config": {"token": "T3"}})
        check("ntfy: credentials sent with the new destination are kept", st == 200 and (await stored(nid))["format_config"] == {"token": "T3"}, str((st, e)))

        # allow_private switched off in the same request as a URL change
        st, p = await call(sa, "POST", "/api/webhooks", {
            "name": "p", "events": ["stream.live"], "format": "ntfy", "url": "http://127.0.0.1:9/topic",
            "allow_private": True, "format_config": {"token": "LANTOKEN"}})
        check("a superadmin session creates a private ntfy hook", st == 201 and p["allow_private"], str((st, p)))
        pid = p["id"]
        st, e = await call(sa, "PUT", f"/api/webhooks/{pid}", {"allow_private": False, "url": H + "/topic"})
        w = await stored(pid)
        check("private switched off with a URL change drops the credentials", st == 200 and not w["format_config"] and not w["allow_private"], str((st, e, w)))
        st, p2 = await call(sa, "POST", "/api/webhooks", {
            "name": "p2", "events": ["stream.live"], "format": "ntfy", "url": "http://127.0.0.1:9/topic",
            "allow_private": True, "format_config": {"token": "LANTOKEN"}})
        st, e = await call(sa, "PUT", f"/api/webhooks/{p2['id']}", {"allow_private": False})
        check("private switched off alone keeps the credentials", st == 200 and (await stored(p2["id"]))["format_config"] == {"token": "LANTOKEN"}, str((st, e)))

        # system hooks
        st, sg = await call(sa, "POST", "/api/admin/webhooks", {
            "name": "sg", "events": ["webhook.test"], "format": "gotify", "url": H + "/gotify",
            "format_config": {"token": "SYSTOKEN"}})
        check("system gotify hook created", st == 201, str((st, sg)))
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sg['id']}", {"url": "https://93.184.216.35/gotify"})
        check("system gotify: a new host without the token is refused", st == 400 and "again" in json.dumps(e), str((st, e)))
        check("system gotify: nothing changed", (await stored(sg["id"]))["format_config"] == {"token": "SYSTOKEN"})
        st, sn = await call(sa, "POST", "/api/admin/webhooks", {
            "name": "sn", "events": ["webhook.test"], "format": "ntfy", "url": H + "/t", "format_config": {"token": "SYSNTFY"}})
        st, e = await call(sa, "PUT", f"/api/admin/webhooks/{sn['id']}", {"url": "https://93.184.216.35/t"})
        check("system ntfy: a new host drops the credentials", st == 200 and not (await stored(sn["id"]))["format_config"], str((st, e)))

        # ---------------- 2. credential scope on the webhook routes
        keys = {}
        for who, sess in (("adm", adm), ("sa", sa)):
            for label, scopes in (("full", "*"), ("narrow", "services:read"), ("admin", "admin")):
                st, k = await call(sess, "POST", "/api/api-keys", {"name": f"{who}-{label}", "scopes": scopes})
                assert st == 201, (st, k)
                keys[(who, label)] = {"X-API-Key": k["key"]}
        real_by_key = db.get_stream_by_key

        async def fake_stream(key):
            if key == "live_adm_stream":
                return {"id": 71, "user_id": ids["adm"]}
            if key == "live_sa_stream":
                return {"id": 72, "user_id": ids["sa"]}
            return await real_by_key(key)
        db.get_stream_by_key = fake_stream
        sk_adm = {"X-Stream-Key": "live_adm_stream"}
        sk_sa = {"X-Stream-Key": "live_sa_stream"}

        own = await db.create_webhook(ids["adm"], "own", "outgoing", url="https://93.184.216.34/x", events=["stream.live"])
        foreign = await db.create_webhook(ids["u1"], "foreign", "outgoing", url="https://93.184.216.34/y", events=["stream.live"])
        oid, fid = own["id"], foreign["id"]
        adm_hooks = len(await db.get_webhooks_for_user(ids["adm"]))
        adm_ids = {w["id"] for w in await db.get_webhooks_for_user(ids["adm"])}
        routes = [("GET", "/api/webhooks", None), ("POST", "/api/webhooks", {"name": "z", "events": ["*"], "url": "https://93.184.216.34/z"}),
                  ("GET", f"/api/webhooks/{oid}", None), ("PUT", f"/api/webhooks/{oid}", {"name": "renamed"}),
                  ("DELETE", f"/api/webhooks/{oid}", None), ("GET", f"/api/webhooks/{oid}/logs", None),
                  ("POST", f"/api/webhooks/{oid}/test", None), ("POST", f"/api/webhooks/{oid}/regenerate-secret", None)]
        for method, path, body in routes:
            st, e = await call(plain, method, path, body, sk_adm)
            check(f"a stream key is refused on {method} {path.replace(str(oid), '{id}')}", st == 403, str((st, e)))
        check("the refused stream-key calls changed nothing",
              (await db.get_webhook(oid))["name"] == "own" and len(await db.get_webhooks_for_user(ids["adm"])) == adm_hooks)
        narrow = keys[("adm", "narrow")]
        for method, path, body in (("POST", "/api/webhooks", routes[1][2]), ("PUT", f"/api/webhooks/{oid}", {"name": "renamed"}),
                                   ("DELETE", f"/api/webhooks/{oid}", None), ("POST", f"/api/webhooks/{oid}/regenerate-secret", None)):
            st, e = await call(plain, method, path, body, narrow)
            check(f"a narrowly scoped key cannot {method} {path.replace(str(oid), '{id}')}", st == 403, str((st, e)))
        check("the narrow key's refused calls changed nothing", (await db.get_webhook(oid)) is not None
              and (await db.get_webhook(oid))["name"] == "own")
        st, e = await call(plain, "GET", f"/api/webhooks/{oid}", None, narrow)
        check("a narrowly scoped key can still read its own hook", st == 200, str((st, e)))
        st, e = await call(plain, "GET", f"/api/webhooks/{fid}", None, narrow)
        check("a narrowly scoped key of an administrator cannot read another user's hook", st == 404, str((st, e)))
        st, e = await call(plain, "GET", "/api/webhooks", None, narrow)
        check("... and lists only its own", st == 200 and {w["id"] for w in e["webhooks"]} == adm_ids, str((st, e)))
        st, e = await call(plain, "GET", f"/api/webhooks/{fid}", None, keys[("adm", "full")])
        check("an all-scope administrator key reads another user's hook", st == 200, str((st, e)))
        st, e = await call(plain, "GET", "/api/webhooks", None, keys[("adm", "admin")])
        check("an admin-scope key lists every hook", st == 200 and {oid, fid} <= {w["id"] for w in e["webhooks"]}, str((st, e)))
        st, e = await call(plain, "POST", "/api/webhooks", routes[1][2], keys[("adm", "admin")])
        check("an admin-only scope is not enough to create a hook", st == 403, str((st, e)))
        st, e = await call(plain, "PUT", f"/api/webhooks/{fid}", {"name": "by-full-key"}, keys[("adm", "full")])
        check("an all-scope administrator key edits another user's hook", st == 200, str((st, e)))
        st, e = await call(plain, "POST", "/api/webhooks", routes[1][2], keys[("adm", "full")])
        check("an all-scope key creates its own hook", st == 201, str((st, e)))

        # system hook routes
        sysh = await db.create_webhook(None, "sys", "outgoing", url="https://93.184.216.34/s", events=["webhook.test"], kind="system")
        sid = sysh["id"]
        sroutes = [("GET", "/api/admin/webhooks", None), ("POST", "/api/admin/webhooks", {"name": "s2", "events": ["webhook.test"], "url": "https://93.184.216.34/s2"}),
                   ("GET", f"/api/admin/webhooks/{sid}", None), ("PUT", f"/api/admin/webhooks/{sid}", {"name": "x"}),
                   ("DELETE", f"/api/admin/webhooks/{sid}", None), ("GET", f"/api/admin/webhooks/{sid}/logs", None),
                   ("POST", f"/api/admin/webhooks/{sid}/test", None), ("POST", f"/api/admin/webhooks/{sid}/regenerate-secret", None)]
        for label, hdr in (("a stream key", sk_sa), ("a narrowly scoped key", keys[("sa", "narrow")])):
            for method, path, body in sroutes:
                st, e = await call(plain, method, path, body, hdr)
                check(f"system route {method} {path.replace(str(sid), '{id}')} refuses {label}", st == 403, str((st, e)))
        check("the refused system calls changed nothing", (await db.get_webhook(sid))["name"] == "sys")
        db.get_stream_by_key = real_by_key

        # ---------------- 3, 4, 5: payloads, bounded answer, alerts dropped by a 429
        # no hook but the ones below may exist: the earlier sections aimed some at public addresses
        await db.conn.execute("DELETE FROM webhooks")
        await db.conn.commit()
        got = []
        big = {"written": 0}

        async def receiver(request):
            body = await request.read()
            got.append((request.path, body))
            if request.path == "/big":
                resp = web.StreamResponse(status=200)
                await resp.prepare(request)
                chunk = b"A" * 65536
                try:
                    for _ in range(640):                   # 40 MB on offer
                        await resp.write(chunk)
                        big["written"] += len(chunk)
                except Exception:
                    pass
                return resp
            return web.Response(status=204)

        rapp = web.Application()
        rapp.router.add_route("*", "/{tail:.*}", receiver)
        rsrv = TestServer(rapp, host="127.0.0.1")
        await rsrv.start_server()
        rbase = f"http://127.0.0.1:{rsrv.port}"

        async def settle(n, secs=5.0):
            for _ in range(int(secs * 20)):
                if len(got) >= n:
                    break
                await asyncio.sleep(0.05)

        gen = await db.create_webhook(ids["adm"], "gen", "outgoing", url=rbase + "/gen",
                                      events=["message.created", "message.deleted", "user.connected", "user.disconnected"],
                                      allow_private=True)
        # 3. anonymous posts carry no user id in the generic body
        anon = server._message_webhook_payload(5, "general", ids["u1"], "Anonymous", "hi", "2026-01-01T00:00:00Z", anonymous=True)
        named = server._message_webhook_payload(6, "general", ids["u1"], "u1", "hi", "2026-01-01T00:00:00Z", anonymous=False)
        check("anonymous message.created has user_id null and no real name", anon["user_id"] is None and "u1" not in json.dumps(anon), str(anon))
        check("a named message.created keeps the user id", named["user_id"] == ids["u1"])
        check("message.deleted by the anonymous author names nobody",
              server._message_deleted_webhook_payload(5, "general", ids["u1"], {"anonymous": 1, "user_id": ids["u1"]})["deleted_by"] is None)
        check("message.deleted by a moderator keeps the moderator, a named author's delete keeps deleted_by",
              server._message_deleted_webhook_payload(5, "general", ids["adm"], {"anonymous": 1, "user_id": ids["u1"]})["deleted_by"] == ids["adm"]
              and server._message_deleted_webhook_payload(5, "general", ids["u1"], {"anonymous": 0, "user_id": ids["u1"]})["deleted_by"] == ids["u1"])
        n = await server.fire_webhook_event("message.created", anon, meta={"channel_id": 1, "anonymous": True})
        await settle(1)
        body = json.loads(got[-1][1]) if got else {}
        check("the generic body of an anonymous post has user_id null on the wire", n == 1 and body.get("data", {}).get("user_id", "x") is None
              and str(ids["u1"]) not in json.dumps(body.get("data", {}).get("username")), str(body))

        src = (Path(__file__).resolve().parent.parent / "server.py").read_text()
        check("the chat socket builds both message events through the masking helpers",
              'fire_webhook_event("message.created", _message_webhook_payload(' in src
              and 'fire_webhook_event("message.deleted", _message_deleted_webhook_payload(' in src)

        # presence: appear-offline is announced to no hook, generic included
        got.clear()
        await db.set_user_status(ids["u1"], "online", update_preference=True)
        n_on = await server.fire_webhook_event("user.connected", {"user_id": ids["u1"], "username": "u1"}, meta={"user_id": ids["u1"]})
        await settle(1)
        check("an online member's user.connected reaches a generic hook", n_on == 1 and len(got) == 1, str((n_on, len(got))))
        got.clear()
        await db.set_user_status(ids["u1"], "offline", update_preference=True)
        for ev in ("user.connected", "user.disconnected"):
            n_off = await server.fire_webhook_event(ev, {"user_id": ids["u1"], "username": "u1"}, meta={"user_id": ids["u1"]})
            check(f"{ev} of an appear-offline member is sent to no hook (generic included)", n_off == 0, str(n_off))
        await asyncio.sleep(0.3)
        check("nothing reached the receiver for the appear-offline member", len(got) == 0, str(got))
        check("presence without a user id in meta fails closed",
              await server.fire_webhook_event("user.connected", {"user_id": ids["u1"]}, meta=None) == 0)

        # 4. only the first 4096 bytes of the answer are read
        bighook = await db.create_webhook(ids["adm"], "big", "outgoing", url=rbase + "/big", events=["message.created"], allow_private=True)
        res = await server._deliver_webhook(await db.get_webhook_for_delivery(bighook["id"]), "webhook.test", {"x": 1}, single=True)
        check("a receiver answering with 40 MB is not read to the end", res["success"] and big["written"] < 20 * 1024 * 1024, str(big))
        logs = await db.get_webhook_logs(bighook["id"], limit=5, offset=0)
        check("the logged answer is at most 4096 bytes", logs and len(logs[0]["response_body"] or "") <= 4096, str(logs[:1])[:200])

        await rsrv.close()

    check("admin form says a new destination needs the credentials again",
          "does not keep the stored token or login" in (Path(__file__).resolve().parent.parent / "static" / "admin.html").read_text())

    await srv.close()
    await db.conn.close()
    print()
    print("FAILED: " + ", ".join(failures) if failures else "all checks passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
