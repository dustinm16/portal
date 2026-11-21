"""When Web push goes out, on a running instance: a direct message and a followed stream going live
reach a member's device once, with no text and no names; nothing is sent while the member has a chat
socket open or after the kind was switched off; signing out names and removes the device.

Over HTTPS against the staged server with real sign-ins and real chat sockets. The fake push
service is a decrypting receiver on this process's loopback; the staged server may send only
there, through the setting stage_push_sink_port (honoured only in stage mode), never to a real push
service. The go-live goes through the MediaMTX publish hook POST /api/stream/auth from loopback.

Users and the stream carry random suffixes and the sink setting is removed again, so the module
also holds on a production-copy rehearsal. It needs no administrator password.

Not proven here: a browser or a phone receiving the notice, a real push service, Cloudflare in front,
how the tap opens the page.
"""
import asyncio
import json
import secrets
import sys
from pathlib import Path

from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tests"))
import webpush_receiver as rx  # noqa: E402

PW = "Pushwire-smoke-pw-1"
SECRET_TEXT = "the-secret-plan-zebra-42"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user
import server

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("sender", "rcpt", "owner"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    sk, pk = server.generate_stream_key(), server.generate_public_key()
    sid = await db.create_user_stream(user_id=out["users"]["owner"], name=P["pre"] + "show", stream_key=sk,
                                      public_key=pk, is_public=True, golive_audience="followers")
    out["stream"] = {"id": sid, "live": sk}
    await db.close()
    print("RESULT " + json.dumps(out))

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

    async def handle(self, request):
        self.hits.append((request.match_info["name"], dict(request.headers), await request.read()))
        return web.Response(status=201)

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


class Sock:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self._task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                if msg.type == 1:
                    self.events.append(json.loads(msg.data))
        except Exception:
            pass

    async def wait(self, pred, start=0, timeout=8.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.03)
        return None

    async def send(self, **payload):
        await self.ws.send_json(payload)

    def close(self):
        self._task.cancel()


async def run(ctx):
    pre = "pw" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("pushwire: setup", False, out[-500:])
        return
    ids, stream = data["users"], data["stream"]
    base = ctx.base_url
    sink = Sink()
    await sink.start()

    def ok(label, passed, detail=""):
        ctx.ok("pushwire: " + label, bool(passed), "" if passed else str(detail)[:300])

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, allow_redirects=False, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def settle(n_before, wait=1.5, expect=None):
        """Wait for pushes to arrive (expect: stop as soon as that many are new) or for quiet."""
        end = asyncio.get_running_loop().time() + wait
        while asyncio.get_running_loop().time() < end:
            if expect is not None and len(sink.hits) - n_before >= expect:
                await asyncio.sleep(0.3)         # a second one would show now
                break
            await asyncio.sleep(0.1)
        return sink.hits[n_before:]

    try:
        rc, o = await ctx.run_py(SETTING % {"port": sink.port}, timeout=60)
        if rc != 0:
            ok("the stage sink is set", False, o[-300:])
            return
        async with ctx.http() as sender, ctx.http() as rcpt, ctx.http() as hook:
            for sess, who in ((sender, "sender"), (rcpt, "rcpt")):
                resp = await ctx.login(sess, pre + who, PW)
                if resp.status != 200:
                    ok("the test members sign in", False, f"{who}: {resp.status}")
                    return
            dev = rx.new_receiver()
            keys = {"p256dh": rx.b64e(dev["public"]), "auth": rx.b64e(dev["auth"])}
            endpoint = f"http://127.0.0.1:{sink.port}/push/{pre}"
            st, b = await call(rcpt, "POST", "/api/push/subscriptions", json={"endpoint": endpoint, "keys": keys})
            ok("the recipient subscribes a device", st == 201, f"{st} {b}")

            def plain(hit):
                return json.loads(rx.decrypt(hit[2], dev["private"], dev["auth"]))

            # ---- a direct message, recipient with no socket
            ws = await sender.ws_connect(f"{base}/ws/chat", max_msg_size=0)
            sock = Sock(ws)
            await sock.send(type="dm_open", user_id=ids["rcpt"])
            opened = await sock.wait(lambda e: e.get("type") == "dm_conversation_opened")
            conv = (opened or {}).get("conversation", {}).get("id")
            ok("the sender opens a conversation", bool(conv), opened)
            n0 = len(sink.hits)
            await sock.send(type="dm_message", conversation_id=conv, message=f"hello {SECRET_TEXT}")
            got = await settle(n0, expect=1)
            ok("one push for the DM", len(got) == 1, len(got))
            if got:
                p = plain(got[0])
                dump = json.dumps(p)
                ok("it names no text and no sender, and opens the conversation",
                   p.get("type") == "dm" and p.get("url") == f"/chat?dm={conv}" and SECRET_TEXT not in dump
                   and pre + "sender" not in dump and got[0][1].get("Topic"), dump)

            # ---- the recipient has a tab open: nothing
            rws = await rcpt.ws_connect(f"{base}/ws/chat", max_msg_size=0)
            rsock = Sock(rws)
            await rsock.wait(lambda e: e.get("type") in ("channels", "history", "dm_conversations_list"), timeout=3)
            n1 = len(sink.hits)
            await sock.send(type="dm_message", conversation_id=conv, message="while you look")
            got = await settle(n1, wait=1.5)
            ok("nothing is sent while a chat socket is open", len(got) == 0, len(got))
            rsock.close()
            await rws.close()
            await asyncio.sleep(0.5)

            # ---- the DM switch off: nothing
            st, b = await call(rcpt, "PUT", "/api/push/prefs", json={"dm": False})
            ok("the DM switch is stored", st == 200 and b["prefs"]["dm"] is False, f"{st} {b}")
            n2 = len(sink.hits)
            await sock.send(type="dm_message", conversation_id=conv, message="after switch off")
            got = await settle(n2, wait=1.5)
            ok("a switched-off kind sends nothing", len(got) == 0, len(got))
            await call(rcpt, "PUT", "/api/push/prefs", json={"dm": True})
            sock.close()
            await ws.close()

            # ---- a followed stream goes live (followers only)
            st, b = await call(rcpt, "PUT", f"/api/streams/{stream['id']}/follow")
            ok("the recipient follows the public stream", st == 200, f"{st} {b}")
            n3 = len(sink.hits)
            async with hook.post(base + "/api/stream/auth", json={
                    "action": "publish", "path": "live/" + stream["live"], "password": stream["live"],
                    "ip": "127.0.0.1"}) as r:
                ok("the publish hook admits the stream", r.status == 200, r.status)
            got = await settle(n3, wait=6.0, expect=1)
            ok("one push for the go-live", len(got) == 1, len(got))
            if got:
                p = plain(got[0])
                dump = json.dumps(p)
                ok("it names the streamer, opens the watch page and carries no key or title",
                   p.get("type") == "golive" and p.get("url") == f"/watch/{stream['id']}"
                   and p.get("title") == pre + "owner is live" and "live_" not in dump and "pub_" not in dump
                   and pre + "show" not in dump, dump)

            # ---- signing out names and removes the device
            st, b = await call(rcpt, "POST", "/logout", json={"endpoint": endpoint})
            ok("POST /logout with the endpoint answers 200", st == 200, f"{st} {b}")
            resp = await ctx.login(rcpt, pre + "rcpt", PW)
            st, b = await call(rcpt, "GET", "/api/push/subscriptions")
            ok("the device is gone after signing out", st == 200 and b.get("devices") == [], f"{st} {b}")
    finally:
        await ctx.run_py(SETTING % {"port": 0}, timeout=60)
        await sink.stop()
