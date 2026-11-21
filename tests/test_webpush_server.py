"""Web Push through the portal's own handlers, in-process against a temporary database.

A fake push service runs on this test's own loopback listener (reachable only through the
test hook webpush.allow_test_sink, which production never calls); it decrypts what it receives
with an independently written receiver and checks the VAPID header. tests/outbound_guard.py
refuses every other dial; DNS is stubbed.

* auth: browser session and bearer token only; API keys, stream keys, a ?token= value and
  narrow tokens are refused on every device route
* subscribe: an endpoint outside the allow-list, plain http, a name that resolves to a private,
  loopback, link-local or metadata address, and bad keys are refused; 10 devices per user;
  lists never show endpoint or keys; one owner per endpoint
* lifecycle: logout, session revoke, sign-out-everywhere, password change and account deletion
  remove the affected devices; unsubscribe-by-endpoint and delete-all
* delivery: decryptable message, valid VAPID, TTL/urgency, 410 and 404 prune, 429 pauses
  without counting, failures count and prune, redirect not followed, per-user cap, flag off,
  no device means nothing sent, a revoked session's device gets nothing, a staged instance
  sends only to its sink, the outbound connector refuses a private resolution at send time
* /sw.js and the manifest: public, headers, no fetch handler, behaviour of push and click
  (node harness); CSP of portal pages and of proxied pages unchanged

Run: venv/bin/python tests/test_webpush_server.py
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
import jwt  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import host_check  # noqa: E402
import server  # noqa: E402
import webpush as wp  # noqa: E402
import webpush_receiver as rx  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

FULL = ["services:read", "access:*"]
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Tok:
    def __init__(self, user_id, token_id, scopes):
        self.user_id, self.token_id, self.scopes = user_id, token_id, scopes

    def has_scope(self, scope):
        return "*" in self.scopes or scope in self.scopes


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    if not uid:
        return None
    if request.headers.get("X-Test-Query"):
        request[server._AUTH_VIA_QUERY_TOKEN] = True
    scopes = request.headers.get("X-Test-Scopes")
    scopes = scopes.split(",") if scopes else list(FULL)
    if "superadmin" in request.headers.get("X-Test-Roles", ""):
        scopes.append("admin")
    return Tok(int(uid), request.headers.get("X-Test-Tid") or f"t{uid}", scopes)


DNS = {}            # host -> addresses; anything else resolves to a public address


async def fake_resolve(host, port):
    return DNS.get(host, ["142.250.80.1"])


class Receiver:
    """One device: keys as a browser holds them, and a fake push service endpoint."""

    def __init__(self, service, name):
        self.key = rx.new_receiver()
        self.service, self.name = service, name
        self.endpoint = f"http://127.0.0.1:{service.port}/push/{name}"

    def sub(self, endpoint=None):
        return {"endpoint": endpoint or self.endpoint,
                "keys": {"p256dh": rx.b64e(self.key["public"]), "auth": rx.b64e(self.key["auth"])}}


class FakePushService:
    def __init__(self):
        self.hits = []            # (name, headers, body)
        self.script = {}          # name -> list of (status, headers)
        self.landed = []

    async def handle(self, request):
        name = request.match_info["name"]
        if name == "landed":
            self.landed.append(1)
            return web.Response(status=201)
        self.hits.append((name, dict(request.headers), await request.read()))
        if name == "redirect":
            raise web.HTTPFound("/push/landed")
        steps = self.script.get(name)
        if steps:
            status, headers = steps.pop(0) if len(steps) > 1 else steps[0]
            return web.Response(status=status, headers=headers, text="no")
        return web.Response(status=201)

    async def start(self):
        app = web.Application()
        app.router.add_post("/push/{name}", self.handle)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        self.port = self.srv.port

    def count(self, name):
        return sum(1 for h in self.hits if h[0] == name)


class World:
    async def build(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = d = Database(str(Path(self.tmp.name) / "t.db"))
        await d.connect()
        self.saved = {n: getattr(server, n) for n in ("db", "authenticate_request")}
        server.db = d
        server.authenticate_request = fake_auth
        server._push_pusher = None
        server._push_subscribe_log.clear()
        self.saved_limit = server._PUSH_SUBSCRIBE_LIMIT
        self.saved_resolve = host_check._resolve
        host_check._resolve = fake_resolve
        self.ids = {}
        for name in ("alice", "bob", "root"):
            self.ids[name] = await d.create_user(name, server.hash_password("old-password-1"))
        await d.set_user_role(self.ids["root"], "superadmin")
        for uid in self.ids.values():
            await d.create_token(uid, f"t{uid}", FULL, name="web_session")
        self.service = FakePushService()
        await self.service.start()
        wp.allow_test_sink(self.service.port)
        app = web.Application(middlewares=[server.security_headers_middleware])
        r = app.router
        r.add_get("/sw.js", server.http_service_worker)
        r.add_get("/manifest.webmanifest", server.http_web_manifest)
        r.add_get("/api/push/config", server.http_push_config)
        r.add_get("/api/push/subscriptions", server.http_push_list)
        r.add_post("/api/push/subscriptions", server.http_push_subscribe)
        r.add_delete("/api/push/subscriptions", server.http_push_delete_all)
        r.add_delete("/api/push/subscriptions/{id}", server.http_push_delete)
        r.add_post("/api/push/unsubscribe", server.http_push_unsubscribe)
        r.add_get("/api/admin/push", server.http_admin_push_get)
        r.add_put("/api/admin/push", server.http_admin_push_put)
        r.add_post("/api/admin/push/test", server.http_admin_push_test)
        r.add_post("/api/me/password", server.http_change_password)
        r.add_get("/logout", server.http_logout)
        r.add_post("/api/me/sessions/others", server.http_revoke_my_other_sessions)
        r.add_delete("/api/admin/users/{id}", server.http_delete_user)
        r.add_post("/api/users/{id}/sessions/revoke", server.http_admin_revoke_user_sessions)
        r.add_get("/html", self.html)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    @staticmethod
    async def html(request):
        return web.Response(text="<html></html>", content_type="text/html")

    async def close(self):
        wp.allow_test_sink(None)
        server._PUSH_SUBSCRIBE_LIMIT = self.saved_limit
        host_check._resolve = self.saved_resolve
        if server._push_pusher is not None:
            server._push_pusher.cancel_all()
        await self.http.close()
        await self.srv.close()
        await self.service.srv.close()
        for n, v in self.saved.items():
            setattr(server, n, v)
        server._push_pusher = None
        await self.db.close()
        self.tmp.cleanup()

    async def call(self, method, who, path, **kw):
        headers = {}
        if who:
            headers["X-Test-User"] = str(self.ids[who])
            if who == "root":
                headers["X-Test-Roles"] = "superadmin"
        headers.update(kw.pop("headers", {}))
        async with self.http.request(method, str(self.srv.make_url(path)), headers=headers,
                                     allow_redirects=False, **kw) as r:
            raw = await r.read()
            try:
                body = json.loads(raw)
            except Exception:
                body = raw
            return r.status, body, r.headers

    async def subscribe(self, who, dev, **kw):
        s, b, _h = await self.call("POST", who, "/api/push/subscriptions", json=dev.sub(), **kw)
        return s, b

    async def rows(self, who):
        return await self.db.list_push_subscriptions(self.ids[who])

    async def deliver(self, who, payload=None, **kw):
        return await server._get_pusher().deliver(self.ids[who], payload or wp.make_test_payload(), **kw)


async def main():
    w = await World().build()
    try:
        # ------------------------------------------------------------ auth
        paths = [("GET", "/api/push/config"), ("GET", "/api/push/subscriptions"),
                 ("POST", "/api/push/subscriptions"), ("DELETE", "/api/push/subscriptions"),
                 ("DELETE", "/api/push/subscriptions/1"), ("POST", "/api/push/unsubscribe")]
        dev0 = Receiver(w.service, "d0")
        ok = True
        for method, path in paths:
            s, _b, _h = await w.call(method, None, path, json={})
            ok = ok and s in (401, 403)
        check("no credential: every device route refuses", ok)
        for label, hdr in (("an API key", {"X-Test-Tid": "apikey-7"}), ("a stream key", {"X-Test-Tid": "streamkey-3"}),
                           ("a token in the URL", {"X-Test-Query": "1"}),
                           ("a narrow token", {"X-Test-Scopes": "services:read"}),
                           ("an admin-only token", {"X-Test-Scopes": "admin"})):
            codes = []
            for method, path in paths:
                s, _b, _h = await w.call(method, "alice", path, headers=hdr, json=dev0.sub())
                codes.append(s)
            check(f"{label} is refused on every device route (403)", set(codes) == {403}, str(codes))
        check("nothing was stored by the refused calls", await w.rows("alice") == [])
        s, b, _h = await w.call("GET", "alice", "/api/push/config", headers={"X-Test-Scopes": "*"})
        check("a bearer token with the all-scope is accepted", s == 200 and b["enabled"])

        # ------------------------------------------------------------ subscribe rate limit
        server._PUSH_SUBSCRIBE_LIMIT = 3
        codes = [(await w.call("POST", "bob", "/api/push/subscriptions",
                               json={"endpoint": "https://fcm.googleapis.com/fcm/send/rl", "keys": dev0.sub()["keys"]}))[0]
                 for _ in range(5)]
        check("subscribe lookups are limited per member (3 per minute here), 429 after", codes == [201, 200, 200, 429, 429], str(codes))
        await w.call("DELETE", "bob", "/api/push/subscriptions")
        server._PUSH_SUBSCRIBE_LIMIT = 10000
        server._push_subscribe_log.clear()

        # ------------------------------------------------------------ config
        s, cfg, _h = await w.call("GET", "alice", "/api/push/config")
        keys = await wp.get_vapid(w.db)
        check("config serves the public VAPID key, the worker and its scope",
              s == 200 and cfg["public_key"] == keys.public_b64 and cfg["worker_url"] == "/sw.js"
              and cfg["worker_scope"] == "/push-sw/" and cfg["max_devices"] == 10)
        check("the private key row is encrypted and never in a response",
              (await w.db.get_setting(wp.SETTING_PRIVATE)).startswith("enc:")
              and "enc:" not in json.dumps(cfg))

        # ------------------------------------------------------------ subscribe refusals
        good_keys = dev0.sub()["keys"]
        refused = {}
        for label, endpoint in (("evil host", "https://evil.example/push/x"),
                                ("plain http", "http://fcm.googleapis.com/x"),
                                ("loopback ip", "https://127.0.0.1/x"),
                                ("metadata ip", "https://169.254.169.254/latest"),
                                ("lookalike", "https://fcm.googleapis.com.evil.example/x"),
                                ("userinfo", "https://fcm.googleapis.com@evil.example/x"),
                                ("loopback http not the sink port", f"http://127.0.0.1:{w.service.port + 1}/x")):
            s, b, _h = await w.call("POST", "alice", "/api/push/subscriptions",
                                    json={"endpoint": endpoint, "keys": good_keys})
            refused[label] = s
        check("endpoints outside the allow-list are refused with 400", set(refused.values()) == {400}, str(refused))
        for label, addrs in (("private", ["10.1.2.3"]), ("loopback", ["127.0.0.1"]), ("link-local", ["169.254.1.1"]),
                             ("metadata", ["169.254.169.254"]), ("mixed", ["142.250.80.1", "192.168.1.5"]),
                             ("ipv6 loopback", ["::1"]), ("cgnat", ["100.64.0.9"])):
            DNS["fcm.googleapis.com"] = addrs
            s, b, _h = await w.call("POST", "alice", "/api/push/subscriptions",
                                    json={"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": good_keys})
            check(f"an allow-listed name resolving to a {label} address is refused", s == 400 and not any(a in json.dumps(b) for a in addrs), f"{s} {b}")
        DNS.clear()
        for label, k in (("bad p256dh", {"p256dh": "AAAA", "auth": good_keys["auth"]}),
                         ("bad auth", {"p256dh": good_keys["p256dh"], "auth": "AAAA"}),
                         ("missing keys", {})):
            s, _b, _h = await w.call("POST", "alice", "/api/push/subscriptions",
                                     json={"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": k})
            check(f"subscribe with {label} is refused", s == 400)
        s, _b, _h = await w.call("POST", "alice", "/api/push/subscriptions", data=b"not json")
        check("subscribe with a body that is not JSON is 400", s == 400)
        wp.allow_test_sink(None)
        s, _b = await w.subscribe("alice", dev0)
        check("the loopback endpoint is refused when the test hook is off", s == 400)
        wp.allow_test_sink(w.service.port)
        check("nothing stored by the refused subscribes", await w.rows("alice") == [])

        # ------------------------------------------------------------ subscribe, list, cap
        s, b = await w.subscribe("alice", dev0, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"})
        check("a real allow-listed https endpoint is accepted (201)",
              (await w.call("POST", "alice", "/api/push/subscriptions",
                            json={"endpoint": "https://fcm.googleapis.com/fcm/send/real-1", "keys": Receiver(w.service, "x").sub()["keys"]}))[0] == 201)
        check("the loopback sink endpoint is accepted through the hook (201)", s == 201 and b["status"] == "created", f"{s} {b}")
        s, b, _h = await w.call("GET", "alice", "/api/push/subscriptions")
        dump = json.dumps(b)
        check("the list shows label, service host and times, never an endpoint path or key",
              s == 200 and len(b["devices"]) == 2 and "real-1" not in dump and "/push/d0" not in dump
              and dev0.sub()["keys"]["p256dh"] not in dump and dev0.sub()["keys"]["auth"] not in dump
              and {d["service"] for d in b["devices"]} == {"127.0.0.1", "fcm.googleapis.com"}
              and any("Firefox" in d["label"] for d in b["devices"]) and any(d["this_session"] for d in b["devices"]), dump)
        s, b = await w.subscribe("alice", dev0)
        check("subscribing the same endpoint again updates it (200) and keeps one row",
              s == 200 and len(await w.rows("alice")) == 2)
        s, b, _h = await w.call("GET", "bob", "/api/push/subscriptions")
        check("another member sees none of it", b["devices"] == [])
        s, b, _h = await w.call("POST", "bob", "/api/push/subscriptions",
                                json=Receiver(w.service, "other").sub(endpoint=dev0.endpoint))
        check("the same endpoint with other keys cannot be taken over by another account (409)",
              s == 409 and len(await w.rows("alice")) == 2 and not await w.rows("bob"))
        s, b, _h = await w.call("POST", "bob", "/api/push/subscriptions", json=dev0.sub())
        check("the same endpoint with the same keys (one browser, another sign-in) moves to the new owner, one owner only",
              s == 201 and len(await w.rows("alice")) == 1 and len(await w.rows("bob")) == 1)
        await w.call("DELETE", "bob", "/api/push/subscriptions")
        await w.subscribe("alice", dev0)
        devs = [Receiver(w.service, f"c{i}") for i in range(10)]
        codes = [(await w.subscribe("bob", d))[0] for d in devs]
        check("10 devices per user, the 11th is refused (409)", codes[:10] == [201] * 10 and (await w.subscribe("bob", Receiver(w.service, "c11")))[0] == 409, str(codes))
        check("re-subscribing an existing device at the cap still works", (await w.subscribe("bob", devs[0]))[0] == 200)
        s, b, _h = await w.call("GET", "bob", "/api/push/subscriptions")
        victim = b["devices"][0]["id"]
        s, _b, _h = await w.call("DELETE", "alice", f"/api/push/subscriptions/{victim}")
        check("a member cannot delete another member's device (404)", s == 404 and len(await w.rows("bob")) == 10)
        s, _b, _h = await w.call("DELETE", "bob", f"/api/push/subscriptions/{victim}")
        check("a member deletes their own device by id", s == 200 and len(await w.rows("bob")) == 9)
        s, _b, _h = await w.call("POST", "bob", "/api/push/unsubscribe", json={"endpoint": devs[1].endpoint})
        check("unsubscribe by endpoint removes that device", s == 200 and len(await w.rows("bob")) == 8)
        s, _b, _h = await w.call("POST", "bob", "/api/push/unsubscribe", json={"endpoint": dev0.endpoint})
        check("unsubscribe of another member's endpoint answers the same and removes nothing",
              s == 200 and len(await w.rows("alice")) == 2)
        s, b, _h = await w.call("DELETE", "bob", "/api/push/subscriptions")
        check("unsubscribe-all removes every device of the caller, only theirs",
              s == 200 and b["removed"] == 8 and not await w.rows("bob") and len(await w.rows("alice")) == 2)
        await w.call("DELETE", "alice", "/api/push/subscriptions")

        # ------------------------------------------------------------ delivery
        d1 = Receiver(w.service, "dev1")
        await w.subscribe("alice", d1)
        res = await w.deliver("alice", wp.build_payload("test", "Hello", "World", "/chat?c=1"), ttl=120, urgency="high")
        hit = w.service.hits[-1]
        plain = json.loads(rx.decrypt(hit[2], d1.key["private"], d1.key["auth"]))
        check("a push arrives and decrypts to the payload",
              res and res[0]["outcome"] == "sent" and plain == {"type": "test", "title": "Hello", "body": "World", "url": "/chat?c=1"}, str(res))
        hd = hit[1]
        auth = hd["Authorization"]
        token = auth[len("vapid t="):].split(",")[0]
        pub = rx.b64d(auth.split("k=")[1])
        claims = jwt.decode(token, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub),
                            algorithms=["ES256"], audience=f"http://127.0.0.1:{w.service.port}")
        check("the VAPID header is valid, for the push service origin, signed by the served key",
              auth.startswith("vapid t=") and pub == keys.public and claims["sub"].startswith("https://")
              and 0 < claims["exp"] - __import__("time").time() <= 86400, str(claims))
        check("content-encoding, TTL and urgency headers", hd["Content-Encoding"] == "aes128gcm" and hd["TTL"] == "120"
              and hd["Urgency"] == "high" and hd["Content-Type"] == "application/octet-stream")
        rows = await w.rows("alice")
        check("success sets last success and keeps the failure count at 0", rows[0]["last_success_at"] and rows[0]["failure_count"] == 0)

        async def outcome(name, script, user="alice"):
            w.service.script[name] = script
            return (await w.deliver(user))[0]

        r = await outcome("dev1", [(410, {})])
        check("410 deletes the subscription", r["outcome"] == "gone" and await w.rows("alice") == [])
        await w.subscribe("alice", d1)
        w.service.script["dev1"] = [(404, {})]
        r = (await w.deliver("alice"))[0]
        check("404 deletes the subscription", r["outcome"] == "gone" and await w.rows("alice") == [])
        w.service.script.clear()
        await w.subscribe("alice", d1)
        n = w.service.count("dev1")
        w.service.script["dev1"] = [(429, {"Retry-After": "120"})]
        r = (await w.deliver("alice"))[0]
        r2 = (await w.deliver("alice"))[0]
        check("429 pauses the device without counting a failure and without another request",
              r["outcome"] == "slow_down" and r2["outcome"] == "paused" and w.service.count("dev1") == n + 1
              and (await w.rows("alice"))[0]["failure_count"] == 0)
        server._get_pusher()._paused.clear()
        w.service.script["dev1"] = [(500, {})]
        old = wp.PRUNE_AFTER_FAILURES
        wp.PRUNE_AFTER_FAILURES = 3
        try:
            r = (await w.deliver("alice"))[0]
            check("another failure counts", r["outcome"] == "failed" and (await w.rows("alice"))[0]["failure_count"] == 1)
            await w.deliver("alice")
            r = (await w.deliver("alice"))[0]
            check("the subscription is pruned at the threshold", r["outcome"] == "pruned" and await w.rows("alice") == [])
        finally:
            wp.PRUNE_AFTER_FAILURES = old
        w.service.script.clear()
        await w.subscribe("alice", d1)
        w.service.script["dev1"] = [(500, {}), (201, {})]
        await w.deliver("alice")
        await w.deliver("alice")
        check("a success resets the failure count", (await w.rows("alice"))[0]["failure_count"] == 0)
        w.service.script.clear()

        d2 = Receiver(w.service, "redirect")
        await w.subscribe("bob", d2)
        r = (await w.deliver("bob"))[0]
        check("a redirect is not followed and counts as a failure",
              r["outcome"] == "failed" and r["status"] == 302 and not w.service.landed and (await w.rows("bob"))[0]["failure_count"] == 1)
        await w.call("DELETE", "bob", "/api/push/subscriptions")

        check("a user with no device: nothing is sent", await w.deliver("bob") == [])
        before = len(w.service.hits)
        task = server.send_push(w.ids["alice"], wp.make_test_payload())
        await task
        check("send_push is a fire-and-forget task that delivers", len(w.service.hits) == before + 1)
        await w.db.set_setting(wp.SETTING_ENABLED, "0")
        before = len(w.service.hits)
        await server.send_push(w.ids["alice"], wp.make_test_payload())
        s, _b, _h = await w.call("POST", "alice", "/api/push/subscriptions", json=d1.sub())
        s2, c2, _h = await w.call("GET", "alice", "/api/push/config")
        check("flag off: nothing is sent, subscribe is refused, config says disabled without a key",
              len(w.service.hits) == before and s == 403 and not c2["enabled"] and c2["public_key"] is None)
        await w.db.set_setting(wp.SETTING_ENABLED, "1")

        old = wp.USER_RATE_LIMIT
        wp.USER_RATE_LIMIT = 2
        server._get_pusher()._rates.clear()
        try:
            outs = [(await w.deliver("alice"))[0]["outcome"] for _ in range(3)]
            check("the per-user cap stops the third push in the window", outs == ["sent", "sent", "rate_limited"], str(outs))
        finally:
            wp.USER_RATE_LIMIT = old
            server._get_pusher()._rates.clear()

        # a revoked session's device gets nothing; an expired session's device still does
        await w.db.create_token(w.ids["alice"], "t-extra", FULL, name="web_session")
        d3 = Receiver(w.service, "dev3")
        await w.subscribe("alice", d3, headers={"X-Test-Tid": "t-extra"})
        before = w.service.count("dev3")
        await w.db.conn.execute("UPDATE tokens SET revoked = 1 WHERE token_id = 't-extra'")
        await w.db.conn.commit()
        outs = await w.deliver("alice")
        check("a device of a revoked session is skipped", w.service.count("dev3") == before and len(outs) == 1)
        await w.db.conn.execute("UPDATE tokens SET revoked = 0, expires_at = '2020-01-01T00:00:00+00:00' WHERE token_id = 't-extra'")
        await w.db.conn.commit()
        outs = await w.deliver("alice")
        check("a device of a session that only expired still receives (nothing would register it again)",
              w.service.count("dev3") == before + 1 and len(outs) == 2)
        await w.db.cleanup_expired_tokens()
        check("cleaning up expired sessions does not remove their devices", len(await w.rows("alice")) == 2)
        await w.call("DELETE", "alice", "/api/push/subscriptions")
        await w.subscribe("alice", d1)

        # outbound guard at send time
        await w.call("DELETE", "alice", "/api/push/subscriptions")
        wp.allow_test_sink(None)
        await w.db.set_setting(wp.SETTING_EXTRA_HOSTS, "push.example.org")
        await w.db.conn.execute(
            "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)",
            (w.ids["alice"], "https://push.example.org/x", d1.sub()["keys"]["p256dh"], d1.sub()["keys"]["auth"]))
        await w.db.conn.commit()
        import aiohttp.resolver
        real_resolve = aiohttp.resolver.DefaultResolver.resolve

        async def evil_resolve(self, host, port=0, family=0):
            return [{"hostname": host, "host": "10.0.0.5", "port": port, "family": 2, "proto": 6, "flags": 0}]
        aiohttp.resolver.DefaultResolver.resolve = evil_resolve
        outbound_guard.refused.clear()
        try:
            r = (await w.deliver("alice"))[0]
        finally:
            aiohttp.resolver.DefaultResolver.resolve = real_resolve
        check("at send time a name that now resolves to a private address is not dialled",
              r["outcome"] == "error" and not outbound_guard.refused and (await w.rows("alice"))[0]["failure_count"] == 1,
              f"{r} {outbound_guard.refused}")
        await w.db.set_setting(wp.SETTING_EXTRA_HOSTS, "")
        r = (await w.deliver("alice"))[0]
        check("an endpoint whose host left the allow-list is not contacted", r["outcome"] == "refused")
        await w.call("DELETE", "alice", "/api/push/subscriptions")
        wp.allow_test_sink(w.service.port)

        # staged instance
        await w.subscribe("alice", d1)
        Config.STAGE_MODE = True
        saved_sink = wp._test_sink_port
        wp.allow_test_sink(None)
        try:
            before = len(w.service.hits)
            r = (await w.deliver("alice"))[0]
            check("a staged instance sends nothing without a sink", r["outcome"] == "staged" and len(w.service.hits) == before)
            await w.db.set_setting(wp.SETTING_STAGE_SINK, str(w.service.port))
            r = (await w.deliver("alice"))[0]
            check("a staged instance sends to its sink port only", r["outcome"] == "sent" and len(w.service.hits) == before + 1)
            # a production copy holds real subscriptions: with the sink set they must still go nowhere
            k = d1.sub()["keys"]
            await w.db.conn.execute(
                "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)",
                (w.ids["alice"], "https://fcm.googleapis.com/fcm/send/real-device", k["p256dh"], k["auth"]))
            await w.db.conn.commit()
            outbound_guard.refused.clear()
            outs = await w.deliver("alice")
            real = [o for o in outs if o["outcome"] != "sent"]
            rows = await w.db.conn.execute("SELECT failure_count FROM push_subscriptions WHERE endpoint LIKE 'https://fcm%'")
            check("a staged instance with a sink set drops a real push service endpoint as staged: not dialled, not counted, not pruned",
                  [o["outcome"] for o in real] == ["staged"] and not outbound_guard.refused
                  and [r["failure_count"] for r in await rows.fetchall()] == [0], f"{outs} {outbound_guard.refused}")
            await w.db.conn.execute("DELETE FROM push_subscriptions WHERE endpoint LIKE 'https://fcm%'")
            await w.db.conn.commit()
        finally:
            Config.STAGE_MODE = False
            wp.allow_test_sink(saved_sink)
        s, _b = await w.subscribe("alice", d1)
        check("the stage sink setting does nothing outside stage mode", s == 200)
        await w.db.set_setting(wp.SETTING_STAGE_SINK, "1")
        wp.allow_test_sink(None)
        s, _b = await w.subscribe("alice", d1)
        check("outside stage mode and without the hook a loopback endpoint stays refused", s == 400)
        wp.allow_test_sink(w.service.port)

        # ------------------------------------------------------------ lifecycle
        await w.call("DELETE", "alice", "/api/push/subscriptions")
        await w.db.create_token(w.ids["alice"], "t-b", FULL, name="web_session")
        da, dbb = Receiver(w.service, "la"), Receiver(w.service, "lb")
        await w.subscribe("alice", da)                                   # session t<alice>
        await w.subscribe("alice", dbb, headers={"X-Test-Tid": "t-b"})   # session t-b
        s, _b, _h = await w.call("POST", "alice", "/api/me/sessions/others")
        left = [r["endpoint"] for r in await w.rows("alice")]
        check("sign out other sessions removes their devices and keeps the current session's", left == [da.endpoint], str(left))
        await w.subscribe("alice", dbb, headers={"X-Test-Tid": "t-b"})
        await w.db.revoke_token("t-b")
        check("revoking one session removes the devices it registered",
              [r["endpoint"] for r in await w.rows("alice")] == [da.endpoint])
        await w.db.revoke_user_tokens(w.ids["alice"])
        check("sign-out-everywhere removes all devices", await w.rows("alice") == [])
        await w.db.create_token(w.ids["alice"], "t-c", FULL, name="web_session")
        await w.subscribe("alice", da, headers={"X-Test-Tid": "t-c"})
        await w.subscribe("alice", dbb, headers={"X-Test-Tid": "t-c"})
        async with w.http.get(str(w.srv.make_url("/logout")), allow_redirects=False,
                              headers={"X-Test-User": str(w.ids["alice"]), "X-Test-Tid": "t-c",
                                       "Cookie": f"{Config.SESSION_COOKIE_NAME}=x"}) as lr:
            check("logout redirects to the login page", lr.status == 302)
        check("logout removes the devices of that session", await w.rows("alice") == [])
        await w.db.create_token(w.ids["alice"], "t-d", FULL, name="web_session")
        await w.subscribe("alice", da, headers={"X-Test-Tid": "t-d"})
        dbob = Receiver(w.service, "bobdev")
        await w.subscribe("bob", dbob)
        s, _b, _h = await w.call("POST", "alice", "/api/me/password", headers={"X-Test-Tid": "t-d"},
                                 json={"current_password": "old-password-1", "new_password": "new-password-22"})
        check("a password change removes devices of other sessions, keeps the current one's",
              s == 200 and [r["endpoint"] for r in await w.rows("alice")] == [da.endpoint], str(s))
        await w.db.create_token(w.ids["alice"], "t-e", FULL, name="web_session")
        await w.subscribe("alice", dbb, headers={"X-Test-Tid": "t-e"})
        await w.subscribe("alice", Receiver(w.service, "ev1"), headers={"X-Test-Tid": "t-e"})
        await w.subscribe("alice", Receiver(w.service, "ev2"))
        s, _b, _h = await w.call("POST", "root", f"/api/users/{w.ids['alice']}/sessions/revoke")
        check("the admin sign-out-everywhere route removes every device of the user, whatever the session",
              s == 200 and await w.rows("alice") == [], str(s))
        droot = Receiver(w.service, "rootdev")
        await w.subscribe("root", droot)
        s, _b, _h = await w.call("POST", "root", f"/api/users/{w.ids['root']}/sessions/revoke")
        check("on the admin's own account it removes every device too, the current session's included",
              s == 200 and await w.rows("root") == [], str(s))
        await w.subscribe("alice", Receiver(w.service, "ev3"), headers={"X-Test-Tid": "t-e"})
        s, _b, _h = await w.call("DELETE", "root", f"/api/admin/users/{w.ids['alice']}")
        check("deleting an account removes its devices and nobody else's",
              s == 200 and await w.rows("alice") == [] and len(await w.rows("bob")) == 1, str(s))
        c = await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM push_subscriptions WHERE user_id = ?", (w.ids["alice"],))).fetchone()
        check("no row of the deleted account is left", c["n"] == 0)

        # ------------------------------------------------------------ admin routes
        s, _b, _h = await w.call("GET", "alice" if False else "bob", "/api/admin/push")
        check("the admin push routes refuse an ordinary member (403)", s == 403
              and (await w.call("PUT", "bob", "/api/admin/push", json={"enabled": False}))[0] == 403
              and (await w.call("POST", "bob", "/api/admin/push/test"))[0] == 403)
        s, _b, _h = await w.call("GET", "root", "/api/admin/push", headers={"X-Test-Tid": "apikey-1"})
        check("an API key of a superadmin is refused too", s == 403)
        s, st, _h = await w.call("GET", "root", "/api/admin/push")
        check("superadmin reads the settings", s == 200 and st["enabled"] and st["default_hosts"] == list(wp.DEFAULT_ALLOWED_HOSTS))
        s, st, _h = await w.call("PUT", "root", "/api/admin/push", json={"allowed_hosts": ["push.example.org"], "subject": "https://portal.example.org"})
        check("superadmin extends the allow-list and sets the subject", s == 200 and st["allowed_hosts"] == ["push.example.org"] and st["subject"] == "https://portal.example.org")
        for bad in ({"allowed_hosts": ["127.0.0.1"]}, {"allowed_hosts": ["localhost"]}, {"allowed_hosts": "*.com"},
                    {"subject": "mailto:someone@example.org"}, {"subject": "http://x.example"}, {"enabled": "yes"}):
            s, _b, _h = await w.call("PUT", "root", "/api/admin/push", json=bad)
            check(f"a bad setting is refused: {list(bad)[0]}={str(list(bad.values())[0])[:20]}", s == 400)
        await w.call("PUT", "root", "/api/admin/push", json={"allowed_hosts": [], "subject": None})
        s, b, _h = await w.call("POST", "root", "/api/admin/push/test")
        check("the test push with no device of the superadmin sends to none", s == 200 and b["devices"] == 0)
        dr = Receiver(w.service, "devroot")
        await w.subscribe("root", dr)
        s, b, _h = await w.call("POST", "root", "/api/admin/push/test")
        got = json.loads(rx.decrypt(w.service.hits[-1][2], dr.key["private"], dr.key["auth"]))
        check("the test push goes to the caller's own devices and arrives",
              s == 200 and b["devices"] == 1 and b["results"][0]["outcome"] == "sent" and got["type"] == "test")

        # ------------------------------------------------------------ sw.js and manifest
        s, body, h = await w.call("GET", None, "/sw.js")
        text = body.decode()
        check("sw.js is public with the right type, no-cache and a scope limited to an unused path",
              s == 200 and h["Content-Type"].startswith("text/javascript") and h["Cache-Control"] == "no-cache"
              and h["Service-Worker-Allowed"] == "/push-sw/" and "Set-Cookie" not in h)
        check("sw.js has push and notificationclick handlers and no fetch handler or cache",
              "addEventListener('push'" in text and "addEventListener('notificationclick'" in text
              and not re.search(r"""addEventListener\(\s*['"](fetch|install|activate|sync|message)""", text)
              and "caches" not in text and "respondWith" not in text)
        s2, body2, _h = await w.call("GET", "alice", "/sw.js")
        check("sw.js is the same for everyone", body2 == body)
        s, mb, h = await w.call("GET", None, "/manifest.webmanifest")
        check("the manifest is public JSON of the right type and carries no per-site data",
              s == 200 and h["Content-Type"].startswith("application/manifest+json") and "Set-Cookie" not in h
              and mb["start_url"] == "/" and mb["scope"] == "/" and mb["display"] == "standalone"
              and set(mb) == {"name", "short_name", "description", "start_url", "scope", "display",
                              "background_color", "theme_color", "icons"})
        icons_ok = True
        for icon in mb["icons"]:
            f = ROOT / icon["src"].lstrip("/")
            icons_ok = icons_ok and f.is_file() and f.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        check("every icon the manifest names exists and is a PNG", icons_ok and len(mb["icons"]) >= 2)
        node = shutil.which("node")
        if node:
            out = json.loads(subprocess.run([node, str(ROOT / "tests" / "webpush_sw_harness.js"), str(ROOT / "static" / "sw.js")],
                                            capture_output=True, text=True, timeout=30).stdout)
            c = out["cases"]
            check("worker: only push and notificationclick listeners", out["listeners"] == ["notificationclick", "push"])
            check("worker: a good push shows title, body and the relative URL",
                  c["good"][0]["title"] == "Hello" and c["good"][0]["options"]["data"]["url"] == "/chat?c=3")
            check("worker: malformed, empty and non-object pushes still show a notification",
                  all(len(c[k]) == 1 and c[k][0]["title"] == "Portal" for k in ("malformed", "nodata", "notobject")))
            check("worker: an absolute, protocol-relative, backslash or script URL becomes /",
                  all(c[k][0]["options"]["data"]["url"] == "/" for k in ("absolute", "protorel", "backslash", "script")))
            check("worker: control characters are stripped", c["control"][0]["title"] == "AB" and c["control"][0]["options"]["body"] == "xy")
            check("worker: a click opens the URL, or focuses the tab that already shows it",
                  c["click_open"]["opened"] == ["https://portal.test/chat?c=3"] and c["click_open"]["closed"]
                  and c["click_focus"]["focused"] == ["https://portal.test/chat?c=3"] and not c["click_focus"]["opened"])
            check("worker: a tab of another origin is never focused",
                  c["click_other_origin_tab"]["opened"] == ["https://portal.test/chat?c=3"] and not c["click_other_origin_tab"]["focused"])
            check("worker: a tampered or missing click URL opens the portal root only",
                  all(c[k]["opened"] == ["https://portal.test/"] for k in ("click_tampered", "click_tampered2", "click_nodata")))
        else:
            print("skip: node is not installed, the worker behaviour was not run")

        # ------------------------------------------------------------ fix pass: revoked sessions, cap, races
        for name in ("erin", "fay"):       # alice was deleted above; fresh members for this block
            w.ids[name] = await w.db.create_user(name, server.hash_password("old-password-1"))
            await w.db.create_token(w.ids[name], f"t{w.ids[name]}", FULL, name="web_session")
        server._push_subscribe_log.clear()
        server._PUSH_SUBSCRIBE_LIMIT = 1000
        aid, bid = w.ids["erin"], w.ids["fay"]
        # cleanup of revoked sessions takes their devices first: they must not come back to life
        await w.db.create_token(aid, "t-gone", FULL, name="web_session")
        dg = Receiver(w.service, "gone")
        s, _b = await w.subscribe("erin", dg, headers={"X-Test-Tid": "t-gone"})
        await w.db.conn.execute("UPDATE tokens SET revoked = 1 WHERE token_id = 't-gone'")   # a path that did not delete
        await w.db.conn.commit()
        check("before cleanup the revoked session's device is skipped", await w.db.push_subscriptions_for_send(aid) == [])
        await w.db.cleanup_expired_tokens()
        check("cleaning up revoked sessions removes the devices they registered (they do not become live again)",
              await w.db.push_subscriptions_for_send(aid) == [] and await w.rows("erin") == [])
        # a subscribe that was in flight while the session was revoked leaves no row
        await w.db.create_token(aid, "t-late", FULL, name="web_session")
        await w.db.revoke_token("t-late")
        s, _b = await w.subscribe("erin", dg, headers={"X-Test-Tid": "t-late"})
        check("a subscribe with an already revoked session is refused (401) and stores nothing",
              s == 401 and await w.rows("erin") == [], str(s))
        # the logout route: revoked first, then the named device removed
        await w.db.create_token(aid, "t-out", FULL, name="web_session")
        await w.subscribe("erin", dg, headers={"X-Test-Tid": "t-out"})
        await w.db.revoke_token("t-out")
        check("revoking a session removes its device in the same step", await w.rows("erin") == [])

        # the cap holds under concurrent subscribes
        devs = [Receiver(w.service, f"cap{i}") for i in range(15)]
        res = await asyncio.gather(*(w.db.add_push_subscription(
            aid, d.endpoint, d.sub()["keys"]["p256dh"], d.sub()["keys"]["auth"], "x", f"t{aid}",
            wp.MAX_DEVICES_PER_USER) for d in devs))
        n = len(await w.rows("erin"))
        check("15 concurrent subscribes leave exactly 10 devices (the cap is atomic)",
              n == wp.MAX_DEVICES_PER_USER and res.count("created") == 10 and res.count("limit") == 5, f"{n} {res}")
        await w.call("DELETE", "erin", "/api/push/subscriptions")
        # the same endpoint twice at once: created and updated, no error
        dd = Receiver(w.service, "twice")
        outs = await asyncio.gather(*(w.call("POST", "erin", "/api/push/subscriptions", json=dd.sub()) for _ in range(4)))
        codes = sorted(o[0] for o in outs)
        check("concurrent subscribes of one endpoint answer 201 once and 200 for the rest (no 500)",
              codes == [200, 200, 200, 201] and len(await w.rows("erin")) == 1, str(codes))
        # ownership: the newest sign-in on the same browser (same keys) owns the endpoint; other keys never take it
        s, b = await w.subscribe("fay", dd)
        check("the same browser signed in as another member moves the device: one row, the other member's is gone",
              s == 201 and len(await w.rows("fay")) == 1 and await w.rows("erin") == [], f"{s} {b}")
        other = Receiver(w.service, "twice")           # same endpoint, different keys
        s, _b = await w.subscribe("erin", other)
        check("another key pair cannot take over a registered endpoint (409), the owner's row stays",
              s == 409 and len(await w.rows("fay")) == 1 and await w.rows("erin") == [], str(s))
        await w.call("DELETE", "fay", "/api/push/subscriptions")
        server._PUSH_SUBSCRIBE_LIMIT = 3

        # ------------------------------------------------------------ CSP
        s, _b, h = await w.call("GET", None, "/html")
        old_csp = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net blob:; "
                   "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; "
                   "font-src 'self' https://cdn.jsdelivr.net; connect-src 'self' wss:; media-src 'self' blob:; "
                   "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; "
                   "worker-src 'self' blob:; frame-ancestors 'self'; base-uri 'self'; form-action 'self';")
        csp = h["Content-Security-Policy"]
        check("portal pages: the policy is byte for byte what it was before this change", csp == old_csp)
        check("portal pages already allow a same-origin worker and manifest (worker-src 'self', manifest falls back to default-src 'self')",
              "worker-src 'self' blob:" in csp and "manifest-src" not in csp and "default-src 'self'" in csp)
        s, _b, h = await w.call("GET", None, "/sw.js")
        check("the worker script itself carries no page policy and no extra header from the middleware",
              "Content-Security-Policy" not in h)
        src = (ROOT / "server.py").read_text()
        proxied = ('"default-src * \'unsafe-inline\' \'unsafe-eval\' data: blob:; "\n'
                   '                        "worker-src \'none\'; "\n'
                   '                        "frame-ancestors \'self\';"')
        check("proxied HTML still gets worker-src 'none' from the proxy, as written before", src.count(proxied) == 1)
    finally:
        await w.close()


asyncio.run(main())

# --- proxied responses: the real proxy handler, an upstream with its own service worker
async def proxied():
    up = web.Application()

    async def page(request):
        return web.Response(text="<html><head></head><body><script>navigator.serviceWorker.register('/sw.js')</script></body></html>",
                            content_type="text/html")

    async def upstream_sw(request):
        return web.Response(text="self.addEventListener('fetch',function(){});", content_type="text/javascript",
                            headers={"Service-Worker-Allowed": "/"})
    up.router.add_get("/page", page)
    up.router.add_get("/sw.js", upstream_sw)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()
    app = web.Application(middlewares=[server.security_headers_middleware])
    app.router.add_get("/sw.js", server.http_service_worker)
    app.router.add_route("*", "/proxy/{conn_id}", server.http_proxy_connection)
    app.router.add_route("*", "/proxy/{conn_id}/{path:.*}", server.http_proxy_connection)
    portal = TestServer(app, host="127.0.0.1")
    await portal.start_server()
    conn = {"id": 5, "type": "http", "host": "127.0.0.1", "port": upstream.port, "name": "app", "config": {}}

    async def auth(request):
        class T:
            user_id = 1
            token_id = "t"
            scopes = FULL
        return T()

    async def get_conn(conn_id, user_id):
        return dict(conn)

    async def nothing(*a, **k):
        return None

    async def user(uid):
        return {"id": uid}

    async def valid(tid):
        return True

    saved = (server.authenticate_request, server.db.get_accessible_connection, server.db.record_connection_usage,
             server.resolve_checked_host, server.resolve_checked_host_cached, server._SSRFSafeConnector,
             server.db.get_user_by_id, server.db.is_token_valid)
    server.authenticate_request = auth
    server.db.get_accessible_connection = get_conn
    server.db.record_connection_usage = nothing
    server.resolve_checked_host = server.resolve_checked_host_cached = lambda *a, **k: asyncio.sleep(0, [])
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)
    server.db.get_user_by_id = user
    server.db.is_token_valid = valid
    try:
        async with aiohttp.ClientSession() as http:
            async with http.get(str(portal.make_url("/proxy/xyz/page"))) as r:
                page_headers = dict(r.headers)
                await r.read()
            async with http.get(str(portal.make_url("/proxy/xyz/sw.js"))) as r:
                sw_headers, sw_body = dict(r.headers), await r.text()
            async with http.get(str(portal.make_url("/sw.js"))) as r:
                own_headers, own_body = dict(r.headers), await r.text()
        check("a proxied page keeps the proxy's policy: worker-src 'none', frame-ancestors 'self', no manifest or worker allowance",
              page_headers.get("Content-Security-Policy") == "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; worker-src 'none'; frame-ancestors 'self';",
              str(page_headers.get("Content-Security-Policy")))
        check("a proxied app's own /sw.js is its own file, served under its prefix, not ours",
              "addEventListener('fetch'" in sw_body and "addEventListener('push'" not in sw_body)
        check("the portal's /sw.js stays the push worker even when an app has a /sw.js of its own",
              "addEventListener('push'" in own_body and "addEventListener('fetch'" not in own_body
              and own_headers.get("Service-Worker-Allowed") == "/push-sw/")
        check("proxied responses are still no-store", page_headers.get("Cache-Control") == "private, no-store")
    finally:
        (server.authenticate_request, server.db.get_accessible_connection, server.db.record_connection_usage,
         server.resolve_checked_host, server.resolve_checked_host_cached, server._SSRFSafeConnector,
         server.db.get_user_by_id, server.db.is_token_valid) = saved
        await portal.close()
        await upstream.close()


async def proxied_with_db():
    tmp = tempfile.TemporaryDirectory()
    d = Database(str(Path(tmp.name) / "p.db"))
    await d.connect()
    old = server.db
    server.db = d
    try:
        await proxied()
    finally:
        server.db = old
        await d.close()
        tmp.cleanup()


asyncio.run(proxied_with_db())

# --- the test hook is not reachable from production code
src = (ROOT / "server.py").read_text()
check("server.py never calls the test hook", "allow_test_sink" not in src)
check("the hook is off by default", wp._test_sink_port is None)

if failures:
    print(f"\ntest_webpush_server: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_webpush_server: all checks passed")
