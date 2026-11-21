"""Per-channel notification levels and the channel_activity signal, on a running instance, over
real sockets and the real routes: a member of a private channel who sits in another room is told
(channel id only) when it has a new message, an outsider on a socket in the same room is not, a
timed mute stops the signal, the level routes answer an unreadable channel like a missing one, and
the channel list carries the choice.

Users and channels are created with ctx.run_py with a random suffix and every assertion is about
those rows, so the check also holds on a stage started from a copy of the production database.
Nothing here needs the admin password.

Not covered: the chat page (badges, the bell menu, the sound), a real push service.
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "Notify-check-pw-1"

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
        await db.add_channel_member(priv, ids["owner"])
        await db.add_channel_member(priv, ids["member"])
        out["priv"] = priv
        out["room"] = await db.create_chat_channel(pre + "-room", created_by=ids["owner"])
        out["pub"] = await db.create_chat_channel(pre + "-pub", created_by=ids["owner"])
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
    rnd = secrets.token_hex(3)
    pre = "nt" + rnd
    names = ("owner", "member", "outsider")
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "names": names, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("notify: setup", False, out[-500:])
        return

    def ok(name, passed, detail=""):
        ctx.ok("notify: " + name, bool(passed), "" if passed else detail)

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
            ctx.ok("notify: users can log in", False, str(e))
            return

        async def api(method, user, path, **kw):
            async with sess[user].request(method, f"{ctx.base_url}{path}", **kw) as r:
                raw = await r.read()
                try:
                    return r.status, json.loads(raw)
                except Exception:
                    return r.status, raw

        priv, room = data["priv"], data["room"]
        owner, joined_o = await connect(sess["owner"], priv)
        member, joined_m = await connect(sess["member"], room)
        outsider, joined_x = await connect(sess["outsider"], room)
        ok("the sockets join", joined_o and joined_m and joined_x)

        def acts(sock, start, cid):
            return [e for e in sock.events[start:] if e.get("type") == "channel_activity" and e.get("channel_id") == cid]

        # a message in the private channel: the member (in another room) is told, the outsider is not
        m_mark, x_mark = len(member.events), len(outsider.events)
        await owner.send(type="message", message=pre + " private words")
        got = await member.wait(lambda e: e.get("type") == "channel_activity", m_mark)
        await asyncio.sleep(1.0)
        ok("a member outside the room is told with the channel id and nothing else",
           got == {"type": "channel_activity", "channel_id": priv}, repr(got))
        ok("an outsider's socket gets nothing about the private channel",
           not acts(outsider, x_mark, priv) and (pre + "-priv") not in json.dumps(outsider.events[x_mark:]),
           repr(outsider.events[x_mark:])[:300])
        ok("every signal holds the type and the channel id only",
           all(set(e) == {"type", "channel_id"} for e in member.events if e.get("type") == "channel_activity"))

        # the level routes
        st, body = await api("GET", "member", f"/api/chat/channels/{priv}/notify")
        ok("GET shows the default", st == 200 and body.get("notify_level") is None and body.get("muted_until") == 0, f"{st} {body}")
        st, body = await api("PUT", "member", f"/api/chat/channels/{priv}/notify", json={"mute_hours": 8})
        ok("PUT mute 8 hours", st == 200 and body.get("muted_until", 0) > 0, f"{st} {body}")
        st, listed = await api("GET", "member", "/api/chat/channels")
        row = next((c for c in (listed or {}).get("channels", []) if c["id"] == priv), None)
        ok("the channel list carries the mute", row is not None and row.get("muted_until", 0) > 0, repr(row)[:200])
        m_mark = len(member.events)
        await owner.send(type="message", message=pre + " second")
        await asyncio.sleep(1.2)
        ok("a muted channel sends no signal", not acts(member, m_mark, priv), repr(member.events[m_mark:]))
        st, body = await api("PUT", "member", f"/api/chat/channels/{priv}/notify", json={"mute_hours": 0})
        m_mark = len(member.events)
        await owner.send(type="message", message=pre + " third")
        ok("ending the mute brings the signal back",
           await member.wait(lambda e: e.get("type") == "channel_activity", m_mark) is not None)

        # unreadable looks like missing
        st1, b1 = await api("GET", "outsider", f"/api/chat/channels/{priv}/notify")
        st2, b2 = await api("GET", "outsider", "/api/chat/channels/987654321/notify")
        ok("an unreadable channel answers like a missing one", st1 == st2 == 404 and b1 == b2, f"{st1} {b1!r} / {st2} {b2!r}")
        st, b = await api("PUT", "outsider", f"/api/chat/channels/{priv}/notify", json={"level": "none"})
        ok("an outsider cannot set a level on it", st == 404 and b == b2, f"{st} {b!r}")
        st, b = await api("PUT", "member", f"/api/chat/channels/{data['pub']}/notify", json={"level": "noisy"})
        ok("an unknown level is refused", st == 400, f"{st} {b!r}")
        st, b = await api("PUT", "member", f"/api/chat/channels/{data['pub']}/notify", json={"level": "mentions"})
        ok("a public channel takes a level", st == 200 and b.get("notify_level") == "mentions", f"{st} {b!r}")
