"""Stream chat controls on a running instance: appointed mods, the permission rules, slow mode and
the playback ban.

Over HTTP and the chat websocket against the staged server (real logins): the owner appoints a
friend as mod (owner and admins only, anybody else gets 404); the mod pins a message, times a
spammer out and opens a poll, and is refused on the owner, on an administrator and on himself; the
spammer cannot pin, time out or open a poll; a mod of one stream has no power in the chat of the
owner's other stream; slow mode 15 holds a viewer's second message back and not the mod's; a
signed-in member banned by the mod gets the one 404 on the info route (and the detail route says
"banned"), and the ban is lifted again at once; the mods are in the audit log; the generic
channel-member routes cannot make a stream mod.

Users and streams carry random suffixes and every assertion is about those rows, so the module also
holds on a stage started from a copy of a production database. It needs no admin password (the
administrator used here is made by the setup step).

Not proven here (needs the real thing): a browser rendering the menu, banner, poll or the settings
window, a real MediaMTX HLS playlist being refused (the info route stands in for the shared gate),
media already flowing over WebRTC when a ban is made.
"""
import asyncio
import json
import secrets
import time

PW = "Modctl-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "friend", "spammer", "viewer", "adm"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.set_user_role(out["users"]["adm"], "admin")
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


class Reader:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.ensure_future(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                try:
                    self.events.append(json.loads(msg.data))
                except Exception:
                    pass
        except Exception:
            pass

    async def wait(self, pred, start=0, timeout=6.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.1)
        return None

    async def act(self, ok_type, **payload):
        start = len(self.events)
        await self.ws.send_json(payload)
        return await self.wait(lambda e: e.get("type") in (ok_type, "error"), start)

    async def join(self, channel_id):
        start = len(self.events)
        await self.ws.send_json({"type": "join", "channel_id": channel_id})
        return await self.wait(lambda e: e.get("type") in ("history", "error"), start)


async def run(ctx):
    pre = "mc" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    res = _result(out) if rc == 0 else None
    if res is None:
        ctx.ok("modctl: setup", False, out[-500:])
        return
    ids = res["users"]
    base = ctx.base_url
    streams = []
    readers = []

    def ok(name, passed, detail=""):
        ctx.ok("modctl: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async with ctx.http() as owner, ctx.http() as friend, ctx.http() as spam, ctx.http() as viewer, ctx.http() as adm:
        sessions = {"owner": owner, "friend": friend, "spammer": spam, "viewer": viewer, "adm": adm}
        try:
            for name, sess in sessions.items():
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return
            made = {}
            for label in ("a", "b"):
                st, b = await call(owner, "POST", "/api/streams", json={"name": pre + label, "is_public": True})
                if st != 201:
                    ok("stream " + label + " is created", False, f"{st} {b}")
                    return
                made[label] = b["stream"]
                streams.append(b["stream"]["id"])
            sid = made["a"]["id"]
            st, b = await call(viewer, "GET", f"/api/streams/{sid}")
            chan_a = (b or {}).get("stream", {}).get("chat_channel_id")
            st, b = await call(viewer, "GET", f"/api/streams/{made['b']['id']}")
            chan_b = (b or {}).get("stream", {}).get("chat_channel_id")
            ok("both streams have a chat of their own", chan_a and chan_b and chan_a != chan_b, f"{chan_a} {chan_b}")
            if not (chan_a and chan_b):
                return

            # ---- appointing
            st, _ = await call(friend, "POST", f"/api/streams/{sid}/mods", json={"user_id": ids["friend"]})
            ok("a member cannot appoint (404)", st == 404, str(st))
            st, _ = await call(friend, "GET", f"/api/streams/{sid}/mods")
            ok("a member cannot list the mods (404)", st == 404, str(st))
            st, b = await call(owner, "POST", f"/api/streams/{sid}/mods", json={"user_id": ids["friend"]})
            ok("the owner appoints a friend", st == 201, f"{st} {b}")
            st, b = await call(owner, "POST", f"/api/streams/{sid}/mods", json={"user_id": ids["friend"]})
            ok("appointing twice is refused", st == 409, f"{st} {b}")
            st, b = await call(owner, "POST", f"/api/streams/{sid}/mods", json={"user_id": ids["owner"]})
            ok("the owner is not appointed", st == 400, f"{st} {b}")
            st, b = await call(owner, "GET", f"/api/streams/{sid}/mods")
            ok("the owner lists the mod", st == 200 and [m["username"] for m in b["mods"]] == [pre + "friend"], f"{st} {b}")
            st, b = await call(adm, "GET", f"/api/streams/{sid}/mods")
            ok("an administrator lists the mods", st == 200, str(st))

            # ---- the mod's powers
            async def sock(sess, channel):
                ws = await sess.ws_connect(f"{base}/ws/chat", max_msg_size=0)
                r = Reader(ws)
                readers.append(r)
                joined = await r.join(channel)
                return r, joined

            fr, j = await sock(friend, chan_a)
            ok("the mod joins the chat", j and j["type"] == "history", str(j))
            info = await fr.wait(lambda e: e.get("type") == "channel_info")
            ok("the mod's channel_info says mod", info and info.get("mod_level") == "mod" and info.get("stream_chat"), str(info))
            sp, _ = await sock(spam, chan_a)
            info = await sp.wait(lambda e: e.get("type") == "channel_info")
            ok("a viewer's channel_info says none", info and info.get("mod_level") == "none", str(info))
            ow, _ = await sock(owner, chan_a)
            ad, _ = await sock(adm, chan_a)

            await sp.ws.send_json({"type": "message", "message": pre + " buy my stuff"})
            msg = await sp.wait(lambda e: e.get("type") == "message" and pre in (e.get("message") or ""))
            ok("the viewer posts a message", msg is not None, "")
            mid = (msg or {}).get("id")
            got = await sp.act("message_pinned", type="pin_message", message_id=mid)
            ok("a viewer cannot pin", got and got["type"] == "error", str(got))
            got = await fr.act("message_pinned", type="pin_message", message_id=mid)
            ok("the mod pins the message", got and got["type"] == "message_pinned", str(got))
            joiner, _ = await sock(viewer, chan_a)
            pins = await joiner.wait(lambda e: e.get("type") == "pinned_messages")
            ok("a viewer who joins later gets the pinned message", pins and any(m["id"] == mid for m in pins["messages"]), str(pins))
            got = await fr.act("message_unpinned", type="unpin_message", message_id=mid)
            ok("the mod unpins it", got and got["type"] == "message_unpinned", str(got))

            got = await sp.act("user_timed_out", type="timeout_user", target_user_id=ids["owner"], duration=60)
            ok("a viewer cannot time anybody out", got and got["type"] == "error", str(got))
            for target, label in (("owner", "the owner"), ("adm", "an administrator"), ("friend", "himself")):
                got = await fr.act("user_timed_out", type="timeout_user", target_user_id=ids[target], duration=60)
                ok("the mod cannot time out " + label, got and got["type"] == "error", str(got))
            got = await ow.act("user_timed_out", type="timeout_user", target_user_id=ids["adm"], duration=60)
            ok("the owner cannot time out an administrator", got and got["type"] == "error", str(got))
            got = await fr.act("user_timed_out", type="timeout_user", message_id=mid, duration=60)
            ok("the mod times the spammer out (by message id)", got and got["type"] == "user_timed_out", str(got))
            got = await sp.act("message", type="message", message=pre + " again")
            ok("the timed-out viewer cannot post", got and got["type"] == "error", str(got))

            got = await sp.act("poll_created", type="create_poll", question="q?", options=["a", "b"])
            ok("a viewer cannot open a poll in a stream chat", got and got["type"] == "error", str(got))
            got = await fr.act("poll_created", type="create_poll", question=pre + " best?", options=["a", "b"])
            ok("the mod opens a poll", got and got["type"] == "poll_created", str(got))

            # ---- a mod of stream A has nothing in stream B
            fb, _ = await sock(friend, chan_b)
            info = await fb.wait(lambda e: e.get("type") == "channel_info")
            ok("in the other stream's chat the friend is nobody", info and info.get("mod_level") == "none", str(info))
            bmsg = await fb.act("message", type="message", message=pre + " hi b")
            bid = (bmsg or {}).get("id")
            got = await fb.act("message_pinned", type="pin_message", message_id=bid)
            ok("the mod of stream A cannot pin in stream B", got and got["type"] == "error", str(got))
            got = await fb.act("slowmode_changed", type="set_slowmode", seconds=5)
            ok("or set slow mode there", got and got["type"] == "error", str(got))

            # ---- slow mode
            got = await ow.act("slowmode_changed", type="set_slowmode", seconds=15)
            ok("the owner sets slow mode 15", got and got["type"] == "slowmode_changed" and got["seconds"] == 15, str(got))
            got = await fr.act("slowmode_changed", type="set_slowmode", seconds=7)
            ok("a value other than 0, 5, 15, 30 is refused", got and got["type"] == "error", str(got))
            await asyncio.sleep(0.3)
            first = await joiner.act("message", type="message", message=pre + " v1")
            second = await joiner.act("message", type="message", message=pre + " v2")
            ok("a viewer's first message goes through and the second waits",
               first and first["type"] == "message" and second and second["type"] == "error"
               and second.get("error_code") == "slowmode", f"{first} {second}")
            one = await fr.act("message", type="message", message=pre + " m1")
            two = await fr.act("message", type="message", message=pre + " m2")
            ok("the mod is not held back", one and two and one["type"] == "message" and two["type"] == "message",
               f"{one} {two}")
            await ow.act("slowmode_changed", type="set_slowmode", seconds=0)

            # ---- the playback ban
            pub = made["a"]["public_key"]
            st, _ = await call(viewer, "GET", f"/api/stream/{pub}/info")
            ok("before the ban the viewer reads the info route", st == 200, str(st))
            st, b = await call(friend, "POST", f"/api/streams/{sid}/bans", json={"user_id": ids["viewer"], "reason": "x"})
            ok("the mod bans the viewer", st == 201, f"{st} {b}")
            t0 = time.monotonic()
            st, b = await call(viewer, "GET", f"/api/stream/{pub}/info")
            ok("the banned viewer gets the 404 at once (not after 5 s)", st == 404 and time.monotonic() - t0 < 5,
               f"{st} {b}")
            st, b = await call(viewer, "GET", f"/api/streams/{sid}")
            ok("the detail route tells him he is banned", st == 403 and (b or {}).get("banned") is True, f"{st} {b}")
            st, _ = await call(owner, "GET", f"/api/stream/{pub}/info")
            ok("the owner is never banned", st == 200, str(st))
            for target, label in (("owner", "the owner"), ("adm", "an administrator")):
                st, _ = await call(friend, "POST", f"/api/streams/{sid}/bans", json={"user_id": ids[target]})
                ok("the mod cannot ban " + label, st == 400, str(st))
            st, _ = await call(friend, "DELETE", f"/api/streams/{sid}/bans/{ids['viewer']}")
            ok("the mod lifts the ban", st == 200, str(st))
            st, _ = await call(viewer, "GET", f"/api/stream/{pub}/info")
            ok("and the viewer reads again at once", st == 200, str(st))

            # ---- the generic channel routes cannot make or remove a stream mod
            st, _ = await call(friend, "POST", f"/api/chat/channels/{chan_a}/members",
                               json={"user_id": ids["spammer"], "role": "moderator"})
            ok("a mod cannot appoint through the channel-member route", st in (400, 403), str(st))
            st, _ = await call(adm, "POST", f"/api/chat/channels/{chan_a}/members",
                               json={"user_id": ids["spammer"], "role": "moderator"})
            ok("nor can an administrator (the stream's mods list is the way)", st == 400, str(st))

            # ---- audit and removal
            st, b = await call(adm, "GET", f"/api/admin/audit-log?limit=200&channel_id={chan_a}")
            if st == 200:
                actions = {(e.get("action"), e.get("actor_username")) for e in b.get("entries", [])}
                need = {("stream_mod_add", pre + "owner"), ("pin_message", pre + "friend"),
                        ("user_timeout", pre + "friend"), ("user_ban", pre + "friend"), ("slowmode_set", pre + "owner")}
                ok("the audit log has the appointment and the mod's actions", need <= actions, str(need - actions))
            else:
                ctx.skip("modctl: audit log read", f"audit route answered {st}")
            st, _ = await call(owner, "DELETE", f"/api/streams/{sid}/mods/{ids['friend']}")
            ok("the owner removes the mod", st == 200, str(st))
            got = await fr.act("message_pinned", type="pin_message", message_id=mid)
            ok("who was removed can no longer pin, on the open socket", got and got["type"] == "error", str(got))
        finally:
            for r in readers:
                r.task.cancel()
                try:
                    await r.ws.close()
                except Exception:
                    pass
            for x in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{x}")
                except Exception:
                    pass
