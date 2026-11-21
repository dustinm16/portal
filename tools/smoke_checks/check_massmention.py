"""@here and @everyone on a running instance, over real sockets and the real routes.

A moderator's "@everyone dinner at 7" in a private channel puts exactly one mention notification
on every member and none on the sender or an outsider; a regular member's @everyone in a channel
whose switch is off notifies nobody and gets no notice; a second one of the moderator within a
minute is limited (the message is still posted, a notice frame says so); once the moderator
switches the channel on a regular member may, and is limited the same way.

Everything happens in a private channel the check creates, with users it creates under a random
suffix, so no real account is notified and every assertion is about those rows (the check also holds
on a stage started from a copy of the production database). Nothing here needs the admin
password. An enabled mention_spam rule with a limit under 5 would block the first message; the
check says so and skips instead.

Not covered: the chat page (the autocomplete, the switch button), a real push service.
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "Mass-check-pw-1"

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
        await db.set_user_role(ids["mod"], "moderator")
        priv = await db.create_chat_channel(P["pre"] + "-mass", created_by=ids["mod"])
        await db.update_chat_channel(priv, visibility="private")
        for n in ("mod", "m1", "m2", "regular"):
            await db.add_channel_member(priv, ids[n])
        out["priv"] = priv
        limits = []
        for r in await db.get_automod_rules(enabled_only=True):
            if r["type"] == "mention_spam":
                cfg = r["config"] if isinstance(r["config"], dict) else json.loads(r["config"])
                limits.append(cfg.get("max_mentions", 5))
        out["spam_limit"] = min(limits) if limits else None
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
    pre = "mm" + rnd
    names = ("mod", "m1", "m2", "regular", "outsider")
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "names": names, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("massmention: setup", False, out[-500:])
        return

    def ok(name, passed, detail=""):
        ctx.ok("massmention: " + name, bool(passed), "" if passed else detail)

    if data["spam_limit"] is not None and data["spam_limit"] < 5:
        ctx.ok("massmention: skipped, an enabled mention_spam rule allows only "
               f"{data['spam_limit']} mentions (it would block the test message)", True)
        return
    priv = data["priv"]

    async with AsyncExitStack() as stack:
        sess = {}
        for n in names:
            s = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(s, pre + n, PW)
            if resp.status != 200:
                ctx.ok("massmention: users can log in", False, f"{n}: {resp.status}")
                return
            sess[n] = s

        async def connect(name):
            ws = await stack.enter_async_context(sess[name].ws_connect(f"{ctx.base_url}/ws/chat", max_msg_size=0))
            sock = Sock(ws)
            stack.callback(sock.close)
            await sock.send(type="join", channel_id=priv)
            got = await sock.wait(lambda e: e.get("type") in ("history", "error"))
            await sock.wait(lambda e: e.get("type") == "users")
            return sock, bool(got and got["type"] == "history")

        async def mentions(name):
            async with sess[name].get(f"{ctx.base_url}/api/notifications?limit=100") as r:
                body = await r.json()
            found = []
            for n in body.get("notifications", []):
                d = n.get("data") or {}
                if isinstance(d, str):
                    try:
                        d = json.loads(d)
                    except ValueError:
                        d = {}
                if n.get("type") == "mention" and d.get("channel_id") == priv:
                    found.append({**n, "data": d})
            return found

        async def counts():
            return {n: len(await mentions(n)) for n in names}

        mod, joined = await connect("mod")
        regular, joined_r = await connect("regular")
        ok("the members join the private channel", joined and joined_r)
        out_sock, joined_x = await connect("outsider")
        ok("an outsider cannot join it", not joined_x)

        # the moderator's @everyone: every member once, nobody else
        await mod.send(type="message", message=f"@everyone dinner at 7 {pre}")
        await asyncio.sleep(1.5)
        got = await counts()
        ok("a moderator's @everyone notifies each member exactly once",
           got["m1"] == 1 and got["m2"] == 1 and got["regular"] == 1, repr(got))
        ok("not the sender and not an outsider", got["mod"] == 0 and got["outsider"] == 0, repr(got))
        row = (await mentions("m1"))[0]
        ok("the notification names the channel and the message",
           row["data"].get("channel") == pre + "-mass" and row["data"].get("message_id"), repr(row)[:300])

        # a second one within the minute: posted, limited, a notice, no new rows
        m_mark = len(mod.events)
        await mod.send(type="message", message=f"@everyone again {pre}")
        notice = await mod.wait(lambda e: e.get("type") == "notice" and e.get("code") == "mass_mention_limited", m_mark)
        await asyncio.sleep(1.0)
        ok("a second @everyone within 60 seconds gets a notice", notice is not None and notice.get("retry_after", 0) > 0,
           repr(mod.events[m_mark:])[:300])
        ok("the message is still posted",
           await mod.wait(lambda e: e.get("type") == "message" and e.get("message") == f"@everyone again {pre}", m_mark) is not None)
        got = await counts()
        ok("and notifies nobody again", got["m1"] == 1 and got["m2"] == 1 and got["regular"] == 1, repr(got))

        # a regular member, switch off: nothing and no notice
        r_mark = len(regular.events)
        await regular.send(type="message", message=f"@everyone hello {pre}")
        await asyncio.sleep(1.5)
        got = await counts()
        ok("a regular member's @everyone without the switch notifies nobody",
           got["m1"] == 1 and got["m2"] == 1 and got["mod"] == 0, repr(got))
        ok("and the sender gets no notice there",
           not [e for e in regular.events[r_mark:] if e.get("type") == "notice"], repr(regular.events[r_mark:])[:300])

        # the switch: the moderator turns it on, a regular member may, once a minute
        m_mark = len(mod.events)
        await mod.send(type="set_mass_mentions", allowed=True)
        ok("the moderator switches it on",
           await mod.wait(lambda e: e.get("type") == "mass_mentions_changed" and e.get("allowed") is True, m_mark) is not None)
        await regular.send(type="set_mass_mentions", allowed=False)
        r_err = await regular.wait(lambda e: e.get("type") == "error", r_mark)
        ok("a regular member cannot change the switch", r_err is not None and r_err.get("message") == "Not authorized",
           repr(r_err))
        await asyncio.sleep(0.3)
        await regular.send(type="message", message=f"@everyone with the switch {pre}")
        await asyncio.sleep(1.5)
        got = await counts()
        ok("with the switch on a regular member's @everyone reaches the others once",
           got["m1"] == 2 and got["m2"] == 2 and got["mod"] == 1 and got["regular"] == 1 and got["outsider"] == 0,
           repr(got))
        r_mark = len(regular.events)
        await regular.send(type="message", message=f"@here too soon {pre}")
        notice = await regular.wait(lambda e: e.get("type") == "notice" and e.get("code") == "mass_mention_limited", r_mark)
        ok("and is limited to one a minute", notice is not None, repr(regular.events[r_mark:])[:300])
