"""Smoke check: per-user voice volume and local mute.

Proves what can be proven without a browser or a phone:
  - the chat page and the watch page are served with voice.js v15 and the
    popover hooks, and voice.js is served as JavaScript;
  - the served voice.js passes the same Node harness as tests/test_voicevol.py
    (fake AudioContext, gain nodes, audio elements, DOM, peer connections and
    localStorage): 40% on one peer and a local mute on another change only
    those peers, deafen silences everyone, the settings survive a rejoin and a
    reload, a resumed or replaced stream gets its gain node again, a peer that
    leaves loses its nodes, iOS plays through the element capped at 100%;
  - nothing about volume is ever sent to the server (no new message type or
    field is needed, and no database change: preferences stay in localStorage);
  - an anonymous member is not exposed to other members by this feature: in a
    channel they cannot be in a voice call, and the user list an ordinary
    member receives carries no account id for them (the popover takes the id
    only from a real user_id); in a direct-message call the payload shows the
    name "Anonymous", as before.
Left to a manual check on real devices: audibility with three browsers, an
iPhone (slider capped at 100% and audio plays), the long press on a phone.
"""
import asyncio
import json
import shutil
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path

PW = "Voicevol-check-pw-1"
NAMES = ("vvalice", "vvbob")
HARNESS = Path(__file__).resolve().parents[2] / "tests" / "voicevol_harness.js"

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        out = {}
        for name in %(names)r:
            u = await db.get_user_by_username(name)
            out[name] = u["id"] if u else await db.create_user(name, hash_password(%(pw)r))
        print(json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
''' % {"names": NAMES, "pw": PW}


async def _pump(ws, events):
    try:
        async for msg in ws:
            if msg.type == 1:  # TEXT
                events.append(json.loads(msg.data))
    except Exception:
        pass


class Conn:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(_pump(ws, self.events))

    async def send(self, **kw):
        await self.ws.send_json(kw)

    async def wait(self, pred, timeout=10.0, start=0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.05)
        return None

    async def close(self):
        await self.ws.close()
        self.task.cancel()


def _t(name):
    return lambda e: e.get("type") == name


async def run(ctx):
    def ok(name, passed, detail=""):
        ctx.ok(name, bool(passed), "" if passed else detail)

    rc, out = await ctx.run_py(SETUP)
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ok("voicevol: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    alice, bob = ids["vvalice"], ids["vvbob"]

    async with AsyncExitStack() as stack:
        sessions = {}
        for name in NAMES:
            s = await stack.enter_async_context(ctx.http())
            r = await ctx.login(s, name, PW)
            sessions[name] = s if r.status == 200 else None
        ok("voicevol: users can log in", all(sessions.values()))
        if not all(sessions.values()):
            return
        s_alice, s_bob = sessions["vvalice"], sessions["vvbob"]

        # ---- pages and script as served ------------------------------------
        for label, url in (("chat page", "/chat"), ("watch page", "/watch/1")):
            async with s_alice.get(ctx.base_url + url) as r:
                body = await r.text()
                status = r.status
            ok(f"voicevol: the {label} loads", status == 200, f"status {status}")
            ok(f"voicevol: the {label} loads voice.js v15 and wires the popover",
               "/static/js/voice.js?v=15" in body and "voice.js?v=14" not in body
               and "VoiceChat.attachUserMenu" in body and "data-voice-uid" in body, "")
        async with s_alice.get(f"{ctx.base_url}/static/js/voice.js?v=15") as r:
            script = await r.text()
            ctype = r.headers.get("Content-Type", "")
            status = r.status
        ok("voicevol: voice.js v15 is served as JavaScript", status == 200 and "javascript" in ctype, f"{status} {ctype}")
        ok("voicevol: the served script has the per-user API and no markup injection",
           "setPeerVolume" in script and "attachUserMenu" in script and "innerHTML" not in script, "")

        # ---- the served script, in the harness --------------------------------
        node = shutil.which("node")
        if not node:
            ctx.skip("voicevol: gain, mute, deafen, resume and popover behaviour", "node is not installed")
        elif not HARNESS.exists():
            ctx.skip("voicevol: gain, mute, deafen, resume and popover behaviour", f"{HARNESS} not found")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                served = Path(tmp) / "voice.js"
                served.write_text(script)
                proc = await asyncio.create_subprocess_exec(
                    node, str(HARNESS), str(served),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                raw, _ = await asyncio.wait_for(proc.communicate(), 60)
            rows = []
            for line in raw.decode("utf-8", "replace").splitlines():
                if line.startswith("RESULT "):
                    rows.append(json.loads(line[7:]))
            bad = [r for r in rows if not r["ok"]]
            ok(f"voicevol: the served voice.js passes {len(rows)} behaviour checks under Node",
               rows and not bad and len(rows) >= 90,
               "; ".join(f"{r['name']}: {r['detail'][:80]}" for r in bad[:5]) or raw.decode()[-200:])

        # ---- anonymous members --------------------------------------------------
        async def connect(session, channel="general"):
            c = Conn(await session.ws_connect(f"{ctx.base_url}/ws/chat"))
            await c.send(type="join", channel=channel)
            await c.wait(_t("users"))
            return c

        async def set_anon(value):
            async with s_alice.put(f"{ctx.base_url}/api/me/anonymous", json={"anonymous": value}) as resp:
                return resp.status

        cb = await connect(s_bob)
        try:
            st = await set_anon(True)
            ok("voicevol: alice switches anonymous mode on", st == 200, f"status {st}")
            ca = await connect(s_alice)
            await ca.send(type="voice_join")
            den = await ca.wait(_t("voice_denied"))
            ok("voicevol: an anonymous member cannot join a channel voice call", den is not None, json.dumps(ca.events[-3:]))
            # what an ordinary member receives about her in the user list
            ulist = await cb.wait(lambda e: e.get("type") == "users" and any(
                u.get("username") == "Anonymous" and u.get("anonymous") for u in e.get("users", [])), timeout=8)
            if ulist is None:
                # bob's list is re-sent when she joins; ask for it again
                await cb.send(type="join", channel="general")
                ulist = await cb.wait(lambda e: e.get("type") == "users" and any(
                    u.get("anonymous") and u.get("username") == "Anonymous" for u in e.get("users", [])), timeout=8,
                    start=len(cb.events) - 1)
            masked = [u for u in (ulist or {}).get("users", []) if u.get("anonymous")
                      and not (u.get("user_id") == bob)]
            ok("voicevol: bob sees an anonymous entry", bool(masked), json.dumps(ulist)[:300])
            mine = [u for u in masked if u.get("anon_ref")]
            ok("voicevol: the entry carries no account id for an ordinary member (the popover never gets one)",
               bool(mine) and all(u.get("user_id") is None and not u.get("in_voice") for u in mine)
               and all(v != alice for u in mine for v in u.values()), json.dumps(mine))
            await ca.close()

            # direct-message call: allowed, the name stays "Anonymous"
            async with s_alice.post(f"{ctx.base_url}/api/dm/conversations", json={"user_ids": [bob]}) as resp:
                body = await resp.json() if resp.status == 200 else {}
            dm_id = (body.get("conversation") or {}).get("id")
            ok("voicevol: a direct-message conversation exists", bool(dm_id), json.dumps(body)[:200])
            if dm_id:
                room = f"dm:{dm_id}"
                ca2 = await connect(s_alice)
                await ca2.send(type="voice_join", room=room)
                vs_a = await ca2.wait(_t("voice_state"))
                await cb.send(type="voice_join", room=room)
                vs_b = await cb.wait(lambda e: e.get("type") == "voice_state" and e.get("channel") == room)
                names = {u["user_id"]: u["username"] for u in (vs_b or {}).get("users", [])}
                ok("voicevol: in a direct-message call the anonymous member shows as Anonymous",
                   bool(vs_a) and names.get(alice) == "Anonymous", json.dumps(vs_b)[:300])
                keys = {k for u in (vs_b or {}).get("users", []) for k in u}
                ok("voicevol: the voice payload carries no volume or preference field",
                   keys <= {"user_id", "username", "muted", "deafened", "speaking", "screen_sharing", "reconnecting", "server_muted"},
                   str(sorted(keys)))
                await ca2.send(type="voice_leave")
                await cb.send(type="voice_leave")
                await ca2.close()
        finally:
            await set_anon(False)
            await cb.close()
