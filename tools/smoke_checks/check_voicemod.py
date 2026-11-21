"""Voice moderation and the enforced room cap, over real WebSockets.

Covers: a timed-out member cannot join voice (the join is refused with a code and the room
hears nothing); the member after the cap is refused with a clear message; a resume at the cap
still works; a moderator's kick removes the member's tile for everyone, the kicked member
cannot relay signalling afterwards and cannot rejoin for 60 seconds; a locked room refuses a
member and admits a moderator; the room is unlocked again.
Everything uses random-suffix users and a random-suffix channel, reads the cap from the
database (a production copy may have another one) and needs no admin password. When the
cap is above 12 the check skips (it would need too many accounts).
The browser parts (the buttons, the server-muted mark, a real microphone) are manual checks.
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "Voice-mod-check-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        raw = await db.get_setting("voice_room_cap")
        try:
            cap = int(raw)
            if not 2 <= cap <= 25:
                cap = 8
        except (TypeError, ValueError):
            cap = 8
        out = {"cap": cap, "users": {}}
        if cap <= 12:
            pw = hash_password(%(pw)r)
            names = ["vm%(sfx)s_p%%d" %% i for i in range(cap + 1)] + ["vm%(sfx)s_mod", "vm%(sfx)s_mod2", "vm%(sfx)s_late"]
            for name in names:
                out["users"][name] = await db.create_user(name, pw)
            for name in ("vm%(sfx)s_mod", "vm%(sfx)s_mod2"):
                await db.set_user_role(out["users"][name], "moderator")
            chan = "vm%(sfx)s-room"
            out["channel_id"] = await db.create_chat_channel(chan, created_by=out["users"]["vm%(sfx)s_mod"])
            out["channel"] = chan
            late = out["users"]["vm%(sfx)s_late"]
            await db.create_chat_timeout(late, out["users"]["vm%(sfx)s_mod"], "timeout", out["channel_id"], "check", 600)
        print(json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''


async def _pump(ws, events):
    try:
        async for msg in ws:
            if msg.type == 1:
                events.append(json.loads(msg.data))
    except Exception:
        pass


class Conn:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(_pump(ws, self.events))

    def mark(self):
        return len(self.events)

    async def send(self, **kw):
        await self.ws.send_json(kw)

    async def wait(self, pred, timeout=8.0, start=0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.05)
        return None

    def voice_events(self, start=0):
        return [e for e in self.events[start:] if str(e.get("type", "")).startswith(("voice_", "screen_share_"))]

    async def close(self):
        await self.ws.close()
        self.task.cancel()


def _t(name):
    return lambda e: e.get("type") == name


async def run(ctx):
    def ok(name, passed, detail=""):
        ctx.ok(name, bool(passed), "" if passed else detail)

    sfx = secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"pw": PW, "sfx": sfx})
    try:
        info = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        info = None
    ok("voicemod: test users and channel created", rc == 0 and bool(info), out[-300:])
    if not info:
        return
    cap = info["cap"]
    if cap > 12:
        ctx.skip("voicemod: the room cap scenarios", f"the cap is {cap}; too many accounts to fill a room")
        return
    ids, channel = info["users"], info["channel"]
    p = [f"vm{sfx}_p{i}" for i in range(cap + 1)]
    mod, mod2, late = f"vm{sfx}_mod", f"vm{sfx}_mod2", f"vm{sfx}_late"

    async with AsyncExitStack() as stack:
        conns = []

        async def connect(name):
            s = await stack.enter_async_context(ctx.http())
            r = await ctx.login(s, name, PW)
            if r.status != 200:
                return None
            ws = await s.ws_connect(f"{ctx.base_url}/ws/chat")
            c = Conn(ws)
            conns.append(c)
            await c.send(type="join", channel=channel)
            await c.wait(_t("users"))
            return c

        async def join_voice(c):
            m = c.mark()
            await c.send(type="voice_join")
            return await c.wait(lambda e: e.get("type") in ("voice_state", "voice_denied", "error"), start=m)

        # timed out member
        cl = await connect(late)
        ok("voicemod: the members can sign in", cl is not None)
        if cl is None:
            return
        got = await join_voice(cl)
        ok("voicemod: a timed-out member cannot join voice",
           got and got["type"] == "voice_denied" and got.get("code") == "timed_out", json.dumps(got))

        # fill the room to the cap: cap-1 members and the moderator
        members = {}
        for name in p[:cap - 1]:
            members[name] = await connect(name)
        cmod = await connect(mod)
        for name, c in members.items():
            got = await join_voice(c)
            ok(f"voicemod: {name[-2:]} joins voice", got and got["type"] == "voice_state", json.dumps(got))
        got = await join_voice(cmod)
        ok("voicemod: the moderator joins and may moderate", got and got["type"] == "voice_state" and got.get("can_moderate") is True, json.dumps(got))
        first = members[p[0]]
        marks = {n: c.mark() for n, c in members.items()}
        extra = await connect(p[cap - 1])
        got = await join_voice(extra)
        ok(f"voicemod: member number {cap + 1} is refused with a clear message",
           got and got["type"] == "voice_denied" and got.get("code") == "room_full" and "full" in got.get("message", ""), json.dumps(got))
        await asyncio.sleep(0.5)
        ok("voicemod: the refusal sent the room nothing",
           all(not c.voice_events(marks[n]) for n, c in members.items()),
           json.dumps([c.voice_events(marks[n]) for n, c in members.items()][:2]))

        # a resume at the cap
        vs = next((e for e in first.events if e.get("type") == "voice_state"), {})
        token = vs.get("resume_token")
        await first.close()
        await asyncio.sleep(0.5)
        again = await connect(p[0])
        m = again.mark()
        await again.send(type="voice_join", resume=True, room=channel, resume_token=token)
        got = await again.wait(lambda e: e.get("type") in ("voice_state", "voice_resume_failed", "voice_denied"), start=m)
        ok("voicemod: a resume at the cap still works", got and got["type"] == "voice_state" and got.get("resumed") is True, json.dumps(got))

        # kick
        victim_name = p[1]
        victim, watcher = members[victim_name], members[p[2]]
        vm_, wm_ = victim.mark(), watcher.mark()
        await cmod.send(type="voice_kick", target_user_id=ids[victim_name])
        den = await victim.wait(_t("voice_denied"), start=vm_)
        ok("voicemod: the kicked member is told they were removed", den and den.get("code") == "kicked", json.dumps(den))
        left = await watcher.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == ids[victim_name], start=wm_)
        ok("voicemod: everyone else sees the tile go", left is not None)
        wm_ = watcher.mark()
        await victim.send(type="voice_signal", target_user_id=ids[p[2]], signal={"type": "offer", "sdp": "x"})
        await victim.send(type="voice_mute", muted=True)
        await asyncio.sleep(0.6)
        ok("voicemod: the kicked member can no longer relay signalling", not watcher.voice_events(wm_), json.dumps(watcher.voice_events(wm_)))
        got = await join_voice(victim)
        ok("voicemod: the kicked member cannot rejoin for a while",
           got and got["type"] == "voice_denied" and got.get("code") == "kicked", json.dumps(got))
        plain_kick = members[p[3]] if cap > 3 else None
        if plain_kick:
            m = plain_kick.mark()
            await plain_kick.send(type="voice_kick", target_user_id=ids[p[2]])
            err = await plain_kick.wait(_t("error"), start=m)
            ok("voicemod: a plain member cannot kick", err is not None and "Moderator" in err.get("message", ""), json.dumps(err))

        # lock
        wm_ = watcher.mark()
        await cmod.send(type="voice_lock_room")
        got = await watcher.wait(_t("voice_room_lock_changed"), start=wm_)
        ok("voicemod: the room is locked and everyone is told", got and got.get("locked") is True, json.dumps(got))
        got = await join_voice(extra)
        ok("voicemod: a locked room refuses a member", got and got["type"] == "voice_denied" and got.get("code") == "locked", json.dumps(got))
        cmod2 = await connect(mod2)
        got = await join_voice(cmod2)
        ok("voicemod: a locked room admits a moderator", got and got["type"] == "voice_state" and got.get("locked") is True, json.dumps(got))
        await cmod.send(type="voice_unlock_room")
        got = await watcher.wait(lambda e: e.get("type") == "voice_room_lock_changed" and e.get("locked") is False, start=wm_)
        ok("voicemod: the room is unlocked again", got is not None)
        # still timed out: refused for that, not for the cap
        got = await join_voice(cl)
        ok("voicemod: a timed-out member is still refused (and told why, not 'full')", got and got.get("code") == "timed_out", json.dumps(got))
        for c in conns:
            try:
                await c.close()
            except Exception:
                pass
