"""Web push foundation on a running instance: the public worker and manifest, the device routes,
and delivery to a fake push service in this process.

Over HTTPS against the staged server with real sign-ins. The fake push service is a decrypting
receiver on this process's loopback; the staged server may send only there, through the setting
stage_push_sink_port (honoured only in stage mode), never to a real push service.

Checks: /sw.js and /manifest.webmanifest need no session, carry nothing private, the worker has
no fetch handler and its scope is limited; the dashboard page names the manifest and keeps its
worker policy; the device routes refuse no credential, a stream key and an API key; an endpoint
outside the allow-list is refused; a member subscribes a device, lists it without endpoint or keys,
and signing out removes it; with an administrator password: a test push arrives decrypted with a
valid VAPID header, and a 410 from the push service removes the device.

Users carry random suffixes and the stage sink setting is removed again, so the module holds on a
production-copy rehearsal too (the administrator steps are skipped without the password).

Not proven here: a browser registering the worker, a phone, a real push service (FCM, Mozilla,
Apple, Windows), Cloudflare in front, the real name lookup of an allow-listed host.
"""
import asyncio
import json
import secrets
import sys
from pathlib import Path

from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tests"))
import webpush_receiver as rx  # noqa: E402

PW = "Push-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

async def main():
    await db.connect()
    uid = (await create_user(%(name)r, %(pw)r))["id"]
    await db.close()
    print("RESULT " + json.dumps({"id": uid}))

asyncio.run(main())
'''

SETTING = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    if %(port)d:
        await db.set_setting("stage_push_sink_port", str(%(port)d))
    else:
        await db.delete_setting("stage_push_sink_port")
    await db.close()
    print("RESULT {}")

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


class Sink:
    def __init__(self):
        self.hits = []
        self.status = 201

    async def handle(self, request):
        self.hits.append((request.match_info["name"], dict(request.headers), await request.read()))
        return web.Response(status=self.status)

    async def start(self):
        app = web.Application()
        app.router.add_post("/push/{name}", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]

    async def stop(self):
        await self.runner.cleanup()


async def run(ctx):
    name = "push" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"name": name, "pw": PW}, timeout=120)
    if rc != 0 or _result(out) is None:
        ctx.ok("push: setup", False, out[-400:])
        return
    base = ctx.base_url
    sink = Sink()
    await sink.start()

    def ok(label, passed, detail=""):
        ctx.ok("push: " + label, bool(passed), "" if passed else str(detail)[:300])

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, allow_redirects=False, **kw) as r:
            raw = await r.read()
            try:
                return r.status, json.loads(raw), r.headers
            except ValueError:
                return r.status, raw, r.headers

    try:
        async with ctx.http() as anon, ctx.http() as member, ctx.http() as admin:
            # ---- public worker and manifest
            st, body, h = await call(anon, "GET", "/sw.js")
            text = body.decode() if isinstance(body, bytes) else ""
            ok("/sw.js needs no session and is served as a script with no-cache and a limited scope",
               st == 200 and h.get("Content-Type", "").startswith("text/javascript") and h.get("Cache-Control") == "no-cache"
               and h.get("Service-Worker-Allowed") == "/push-sw/", f"{st} {dict(h)}")
            ok("/sw.js has push and notificationclick handlers and no fetch handler",
               "addEventListener('push'" in text and "addEventListener('notificationclick'" in text
               and "addEventListener('fetch'" not in text and "respondWith" not in text)
            st, mf, h = await call(anon, "GET", "/manifest.webmanifest")
            ok("the manifest needs no session and names icons that can be fetched",
               st == 200 and h.get("Content-Type", "").startswith("application/manifest+json")
               and mf.get("start_url") == "/" and len(mf.get("icons", [])) >= 2 and "Set-Cookie" not in h, f"{st}")
            icon_ok = True
            for icon in mf.get("icons", []):
                s2, b2, _h = await call(anon, "GET", icon["src"])
                icon_ok = icon_ok and s2 == 200 and isinstance(b2, bytes) and b2[:4] == b"\x89PNG"
            ok("every icon is a PNG without a session", icon_ok)

            resp = await ctx.login(member, name, PW)
            if resp.status != 200:
                ok("the test member signs in", False, resp.status)
                return
            async with member.get(base + "/dashboard") as r:
                page = await r.text()
                csp = r.headers.get("Content-Security-Policy", "")
            ok("the dashboard names the manifest and the client script; its policy still allows a same-origin worker only",
               'rel="manifest"' in page and "/static/js/push.js?v=" in page and "worker-src 'self' blob:" in csp, csp[:200])

            # ---- auth
            routes = [("GET", "/api/push/config"), ("GET", "/api/push/subscriptions"), ("POST", "/api/push/subscriptions"),
                      ("DELETE", "/api/push/subscriptions"), ("POST", "/api/push/unsubscribe")]
            codes = [(await call(anon, m, p, json={}))[0] for m, p in routes]
            ok("without a credential every device route refuses", all(c in (401, 403) for c in codes), str(codes))
            codes = [(await call(anon, m, p, json={}, headers={"X-Stream-Key": "live_" + "a" * 32}))[0] for m, p in routes]
            ok("a stream key is refused (403)", set(codes) == {403}, str(codes))
            st, key, _h = await call(member, "POST", "/api/api-keys", json={"name": "push-smoke"})
            if st == 201 and key.get("key"):
                codes = [(await call(anon, m, p, json={}, headers={"Authorization": "Api-Key " + key["key"]}))[0] for m, p in routes]
                ok("an API key is refused (403)", set(codes) == {403}, str(codes))
            else:
                ctx.skip("push: an API key is refused", f"could not make a key ({st})")

            # ---- config and refusals
            st, cfg, _h = await call(member, "GET", "/api/push/config")
            ok("a member reads the config with a public key", st == 200 and cfg.get("enabled") and len(cfg.get("public_key") or "") > 80, f"{st} {cfg}")
            dev = rx.new_receiver()
            keys = {"p256dh": rx.b64e(dev["public"]), "auth": rx.b64e(dev["auth"])}
            for label, endpoint in (("an endpoint outside the allow-list", "https://evil.example/push/x"),
                                    ("plain http to a real push host", "http://fcm.googleapis.com/x"),
                                    ("a loopback endpoint with no sink configured", f"http://127.0.0.1:{sink.port}/push/a"),
                                    ("a metadata address", "https://169.254.169.254/latest")):
                st, b, _h = await call(member, "POST", "/api/push/subscriptions", json={"endpoint": endpoint, "keys": keys})
                ok(f"{label} is refused (400)", st == 400, f"{st} {b}")
            st, b, _h = await call(member, "GET", "/api/push/subscriptions")
            ok("nothing was stored by the refused calls", st == 200 and b.get("devices") == [], f"{st} {b}")

            # ---- subscribe through the stage sink
            rc, out = await ctx.run_py(SETTING % {"port": sink.port}, timeout=60)
            if rc != 0:
                ok("the stage sink is set", False, out[-300:])
                return
            endpoint = f"http://127.0.0.1:{sink.port}/push/member"
            st, b, _h = await call(member, "POST", "/api/push/subscriptions", json={"endpoint": endpoint, "keys": keys})
            ok("a member subscribes a device", st == 201, f"{st} {b}")
            st, b, _h = await call(member, "GET", "/api/push/subscriptions")
            dump = json.dumps(b)
            ok("the list shows the device without its endpoint or keys",
               st == 200 and len(b["devices"]) == 1 and "/push/member" not in dump and keys["auth"] not in dump, dump[:300])

            # ---- an administrator: test push, VAPID, decryption, 410
            if ctx.admin_password:
                resp = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
                if resp.status != 200:
                    ctx.skip("push: administrator steps", f"administrator sign-in answered {resp.status}")
                else:
                    adev = rx.new_receiver()
                    akeys = {"p256dh": rx.b64e(adev["public"]), "auth": rx.b64e(adev["auth"])}
                    aend = f"http://127.0.0.1:{sink.port}/push/admin" + secrets.token_hex(3)
                    st, b, _h = await call(admin, "POST", "/api/push/subscriptions", json={"endpoint": aend, "keys": akeys})
                    if st != 201:
                        ok("the administrator subscribes a device", False, f"{st} {b}")
                    else:
                        before = len(sink.hits)
                        st, b, _h = await call(admin, "POST", "/api/admin/push/test")
                        if st == 403:
                            ctx.skip("push: test push", "the sign-in account is not a superadmin")
                        else:
                            ok("the test push is sent and reports sent", st == 200 and b.get("results") and b["results"][0]["outcome"] == "sent", f"{st} {b}")
                            hit = sink.hits[-1] if len(sink.hits) > before else None
                            if hit:
                                plain = json.loads(rx.decrypt(hit[2], adev["private"], adev["auth"]))
                                auth = hit[1].get("Authorization", "")
                                token = auth[len("vapid t="):].split(",")[0]
                                pub = rx.b64d(auth.split("k=")[1])
                                h64, c64, s64 = token.split(".")
                                claims = json.loads(rx.b64d(c64))
                                st2, cfg2, _h = await call(admin, "GET", "/api/push/config")
                                ok("the message decrypts and the VAPID header is valid and matches the served key",
                                   plain.get("type") == "test" and plain.get("url") == "/"
                                   and rx.ecdsa_ok(pub, (h64 + "." + c64).encode(), rx.b64d(s64))
                                   and rx.b64e(pub) == cfg2.get("public_key") and claims["aud"] == f"http://127.0.0.1:{sink.port}"
                                   and hit[1].get("Content-Encoding") == "aes128gcm", f"{plain} {claims}")
                            else:
                                ok("the test push reached the fake push service", False, "no request received")
                            sink.status = 410
                            st, b, _h = await call(admin, "POST", "/api/admin/push/test")
                            st2, lst, _h = await call(admin, "GET", "/api/push/subscriptions")
                            ok("a 410 from the push service removes the device",
                               st == 200 and b["results"][0]["outcome"] == "gone"
                               and not any(True for d in lst.get("devices", [])), f"{b} {lst}")
                            sink.status = 201
                        await call(admin, "DELETE", "/api/push/subscriptions")
            else:
                ctx.skip("push: test push, VAPID header and 410 prune", "no administrator password")

            # ---- signing out removes the device of that session
            async with member.post(base + "/logout", allow_redirects=False) as r:
                ok("logout (POST) answers 200", r.status == 200, r.status)
            resp = await ctx.login(member, name, PW)
            st, b, _h = await call(member, "GET", "/api/push/subscriptions")
            ok("after signing out the device of that session is gone", st == 200 and b.get("devices") == [], f"{st} {b}")
    finally:
        await ctx.run_py(SETTING % {"port": 0}, timeout=60)
        await sink.stop()
