"""Access lost while a chat socket is joined, on a running instance, over real
sockets and the real routes: a member who leaves a private channel, a stream made
not public and a stream chat ban each put the sockets that can no longer read the
room out of it (one "Channel not found" error, then nothing from the room), and
the channel list leaves out the chat of a stream that is not public.

Users, channels and streams are created with ctx.run_py; every name carries a
random suffix and every assertion is about those rows, so the check also holds on
a stage started from a copy of the production database. Nothing here needs the
admin password.

Not covered: the chat page itself (how it shows the error toast).
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "Access-check-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

P = json.loads(%(params)r)

async def main():
    await db.connect()
    try:
        out = {"users": {}}
        pw = hash_password(P["pw"])
        for name in P["names"]:
            u = await db.get_user_by_username(P["pre"] + name)
            out["users"][name] = u["id"] if u else await db.create_user(P["pre"] + name, pw)
        ids = out["users"]
        pre = P["pre"]
        priv = await db.create_chat_channel(pre + "-priv", created_by=ids["owner"])
        await db.update_chat_channel(priv, visibility="private")
        await db.add_channel_member(priv, ids["member"])
        await db.add_channel_member(priv, ids["mate"])
        out["priv"] = priv
        for key in ("pub", "ban"):
            room = await db.create_chat_channel(pre + "-" + key, created_by=ids["owner"])
            sid = await db.create_user_stream(ids["owner"], pre + key, "live_" + key[0] * 24,
                                              public_key="pub_" + key[0] * 24, is_public=True)
            await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (room, sid))
            await db.conn.commit()
            out[key] = {"room": room, "sid": sid, "name": pre + "-" + key}
        # a stream that is not public from the start, with its chat
        closed = await db.create_chat_channel(pre + "-closed", created_by=ids["owner"])
        csid = await db.create_user_stream(ids["owner"], pre + "closed", "live_" + "c" * 24,
                                           public_key="pub_" + "c" * 24, is_public=False)
        await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (closed, csid))
        await db.conn.commit()
        out["closed"] = {"room": closed, "sid": csid, "name": pre + "-closed"}
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


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

    async def wait(self, pred, start=0, timeout=10.0):
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
    rnd = secrets.token_hex(3)
    pre = "al" + rnd
    names = ("owner", "member", "mate", "viewer", "viewer2")
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "names": names, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("access loss: setup", False, out[-500:])
        return
    ids = data["users"]

    def ok(name, passed, detail=""):
        ctx.ok("access loss: " + name, bool(passed), "" if passed else detail)

    async with AsyncExitStack() as stack:
        async def login(name):
            sess = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess, pre + name, PW)
            if resp.status != 200:
                raise RuntimeError(f"{name} cannot log in: {resp.status}")
            return sess

        async def connect(sess, channel_id):
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat", max_msg_size=0))
            sock = Sock(ws)
            stack.callback(sock.close)
            await sock.send(type="join", channel_id=channel_id)
            joined = await sock.wait(lambda e: e.get("type") in ("history", "error"))
            await sock.wait(lambda e: e.get("type") == "users")
            return sock, bool(joined and joined["type"] == "history")

        try:
            sess = {n: await login(n) for n in names}
        except RuntimeError as e:
            ctx.ok("access loss: users can log in", False, str(e))
            return

        async def api(method, user, path, **kw):
            async with sess[user].request(method, f"{ctx.base_url}{path}", **kw) as r:
                try:
                    return r.status, await r.json()
                except Exception:
                    return r.status, None

        async def put_out(loser, start, others, expect_voice=False):
            """One error with the answer for a missing channel, then silence from the room."""
            err = await loser.wait(lambda e: e.get("type") == "error", start)
            if not (err and err.get("message") == "Channel not found"):
                return False, "no Channel not found error: %r" % (loser.events[start:],)
            mark = len(loser.events)
            for poster, text in others:
                await poster.send(type="message", message=text)
                await poster.wait(lambda e, t=text: e.get("type") == "message" and e.get("message") == t)
                await poster.send(type="typing")
            await asyncio.sleep(1.0)
            later = loser.events[mark:]
            if later:
                return False, "frames after the error: %r" % (later,)
            return True, ""

        # --- the channel list ------------------------------------------------
        for who in ("viewer", "member", "owner"):
            st, body = await api("GET", who, "/api/chat/channels")
            listed = {c["name"] for c in (body or {}).get("channels", [])}
            if who == "owner":
                ok("the owner's channel list has the chat of a stream that is not public",
                   st == 200 and data["closed"]["name"] in listed, str(sorted(listed))[:300])
            else:
                ok(f"{who}'s channel list leaves out the chat of a stream that is not public",
                   st == 200 and data["closed"]["name"] not in listed, str(sorted(listed))[:300])
        st, body = await api("GET", "viewer", "/api/chat/channels")
        listed = {c["name"] for c in (body or {}).get("channels", [])}
        ok("a public stream's chat is still listed", st == 200 and data["pub"]["name"] in listed, str(sorted(listed))[:300])

        # --- a member leaves a private channel --------------------------------
        member, joined_m = await connect(sess["member"], data["priv"])
        mate, joined_t = await connect(sess["mate"], data["priv"])
        ok("members join the private channel", joined_m and joined_t)
        start = len(member.events)
        st, body = await api("DELETE", "member", f"/api/chat/channels/{data['priv']}/members/{ids['member']}")
        ok("a member can leave a private channel", st == 200, f"{st} {body}")
        good, detail = await put_out(member, start, [(mate, pre + " after leaving")])
        ok("a member who left the private channel gets one error and nothing from the room", good, detail)

        # --- a stream made not public ----------------------------------------
        owner, _ = await connect(sess["owner"], data["pub"]["room"])
        viewer, joined_v = await connect(sess["viewer"], data["pub"]["room"])
        ok("a viewer joins a public stream's chat", joined_v)
        start = len(viewer.events)
        st, body = await api("PUT", "owner", f"/api/streams/{data['pub']['sid']}", json={"is_public": False})
        ok("the owner can make the stream not public", st == 200, f"{st} {body}")
        good, detail = await put_out(viewer, start, [(owner, pre + " owner after private")])
        ok("a stream made not public puts the viewer out of its chat", good, detail)
        # the owner is still in the room
        await owner.send(type="message", message=pre + " owner still here")
        ok("...and the owner is still in the room",
           await owner.wait(lambda e: e.get("type") == "message" and e.get("message") == pre + " owner still here"))

        # --- a ban ----------------------------------------------------------
        owner2, _ = await connect(sess["owner"], data["ban"]["room"])
        viewer2, joined_v2 = await connect(sess["viewer2"], data["ban"]["room"])
        ok("a second viewer joins another public stream's chat", joined_v2)
        start = len(viewer2.events)
        st, body = await api("POST", "owner", f"/api/streams/{data['ban']['sid']}/bans",
                             json={"user_id": ids["viewer2"], "reason": "check"})
        ok("the owner can ban the viewer", st in (200, 201), f"{st} {body}")
        good, detail = await put_out(viewer2, start, [(owner2, pre + " owner after the ban")])
        ok("a ban puts the viewer out of the stream chat", good, detail)


