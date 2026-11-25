"""Voice sessions across reconnects and tabs, over real WebSockets.

Covers: closing a second tab leaves the call alone, a second tab cannot join or
take over, a dropped socket is held for 20 seconds and resumed with the join's
token (other members see "reconnecting" then "resumed", never "left"), an
unresumed call ends with "left" after the grace period, and leaving, a password
reset or anonymous mode end the call at once with no grace period.
The phone and browser parts (Wi-Fi switched off and on, how the tiles look) are
manual checks; see the release notes.
"""

import asyncio
import json
import time
from contextlib import AsyncExitStack

PW = "Voice-check-pw-1"
NAMES = ("vcalice", "vcbob", "vceve", "vcvic1", "vcvic2")
GRACE_LOW, GRACE_HIGH = 18.0, 26.0

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

    def mark(self):
        return len(self.events)

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

    def types(self, start=0):
        return [e.get("type") for e in self.events[start:]]

    async def close(self):
        await self.ws.close()
        self.task.cancel()


def _t(name):
    return lambda e: e.get("type") == name


async def run(ctx):
    def ok(name, passed, detail=""):
        # event dumps are only useful when a check fails
        ctx.ok(name, bool(passed), "" if passed else detail)

    rc, out = await ctx.run_py(SETUP)
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ok("voice: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    alice, bob = ids["vcalice"], ids["vcbob"]

    async with AsyncExitStack() as stack:
        async def login(name, password=PW):
            s = await stack.enter_async_context(ctx.http())
            r = await ctx.login(s, name, password)
            return s if r.status == 200 else None

        async def connect(session):
            ws = await session.ws_connect(f"{ctx.base_url}/ws/chat")
            c = Conn(ws)
            await c.send(type="join", channel="general")
            await c.wait(_t("users"))
            return c

        sessions = {}
        for name in NAMES:
            sessions[name] = await login(name)
        ok("voice: users can log in", all(sessions.values()),
           str([n for n, s in sessions.items() if not s]))
        if not all(sessions.values()):
            return
        # A rehearsal against a copy of real data (--from-db) has no admin
        # password: everything else still runs, the password-reset cases skip.
        admin = None
        if ctx.admin_password:
            admin = await stack.enter_async_context(ctx.http())
            r = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
            ok("voice: the admin can log in", r.status == 200, f"status {r.status}")
            if r.status != 200:
                admin = None

        async def set_anon(value):
            async with sessions["vcalice"].put(f"{ctx.base_url}/api/me/anonymous",
                                               json={"anonymous": value}) as resp:
                return resp.status

        # --- bob listens in the voice room -------------------------------
        cb = await connect(sessions["vcbob"])
        await cb.send(type="voice_join")
        vs = await cb.wait(_t("voice_state"))
        ok("voice: voice_join returns a resume token to the joiner only",
               bool(vs and vs.get("resume_token")), json.dumps(vs))

        # --- alice joins voice on tab 1 -----------------------------------
        a1 = await connect(sessions["vcalice"])
        m = cb.mark()
        await a1.send(type="voice_join")
        vs = await a1.wait(_t("voice_state"))
        token = (vs or {}).get("resume_token")
        ok("voice: alice joins voice with a resume token", bool(token), json.dumps(vs))
        if not token:
            return
        joined = await cb.wait(lambda e: e.get("type") == "voice_user_joined" and e.get("user_id") == alice, start=m)
        ok("voice: bob sees alice join", joined is not None)
        ok("voice: the token is not in anything bob received",
               token not in json.dumps(cb.events))

        # --- second tab: opening, being refused, closing ------------------
        m = cb.mark()
        a2 = await connect(sessions["vcalice"])
        await a2.send(type="voice_join")
        den = await a2.wait(_t("voice_denied"))
        ok("voice: a second tab joining voice is refused", den is not None and
               "Already" in den.get("message", ""), json.dumps(a2.events[-3:]))
        await a2.send(type="voice_leave")
        await a2.send(type="voice_mute", muted=True)
        await a2.send(type="voice_signal", target_user_id=bob, signal={"type": "offer", "sdp": "x"})
        await a2.send(type="voice_join", resume=True, room="general", resume_token="not-the-token")
        failed = await a2.wait(_t("voice_resume_failed"))
        ok("voice: resume with a wrong token is refused", failed is not None, json.dumps(a2.events[-3:]))
        await a2.close()
        await asyncio.sleep(1.0)
        bad = [e for e in cb.events[m:] if str(e.get("type", "")).startswith(("voice_", "screen_share_"))
               and e.get("type") not in ("voice_state",)]
        ok("voice: opening and closing a second tab sends bob no voice event", not bad, json.dumps(bad))
        await a1.send(type="voice_mute", muted=True)
        ok_mute = await cb.wait(lambda e: e.get("type") == "voice_mute_changed" and e.get("user_id") == alice, start=m)
        ok("voice: alice's call still works on tab 1 (mute reaches bob)", ok_mute is not None)
        await a1.send(type="voice_mute", muted=False)

        # --- another account cannot use alice's token ---------------------
        ce = await connect(sessions["vceve"])
        await ce.send(type="voice_join", resume=True, room="general", resume_token=token)
        failed = await ce.wait(_t("voice_resume_failed"))
        ok("voice: another account cannot resume with alice's token", failed is not None,
               json.dumps(ce.events[-3:]))

        # --- tab 1 drops: reconnecting, then resumed ----------------------
        m = cb.mark()
        t_drop = time.monotonic()
        await a1.close()
        rec = await cb.wait(lambda e: e.get("type") == "voice_user_reconnecting" and e.get("user_id") == alice,
                            start=m, timeout=10)
        ok("voice: bob sees alice reconnecting when her socket drops", rec is not None, json.dumps(cb.events[m:]))
        ok("voice: the reconnecting event carries only the user id",
               rec is not None and set(rec) == {"type", "user_id"}, json.dumps(rec))
        ulist = await cb.wait(lambda e: e.get("type") == "users" and any(
            u.get("user_id") == alice and u.get("voice_reconnecting") for u in e.get("users", [])), start=m)
        ok("voice: bob's users list shows alice as a reconnecting voice member", ulist is not None)

        # while held: another tab, another account, a wrong token all fail
        a_other = await connect(sessions["vcalice"])
        await a_other.send(type="voice_join")
        den = await a_other.wait(_t("voice_denied"))
        ok("voice: a new tab cannot join while the call is held", den is not None)
        await a_other.send(type="voice_join", resume=True, room="general", resume_token="guess")
        failed = await a_other.wait(_t("voice_resume_failed"))
        ok("voice: a new tab without the token cannot take the held call", failed is not None)
        await a_other.close()
        await ce.send(type="voice_join", resume=True, room="general", resume_token=token)
        await asyncio.sleep(0.5)
        ok("voice: another account cannot take the held call",
               ce.types().count("voice_resume_failed") == 2, json.dumps(ce.types()))
        left_early = [e for e in cb.events[m:] if e.get("type") == "voice_user_left"]
        ok("voice: none of that ended alice's call", not left_early)

        # resume on a new socket, no channel join first
        a3 = Conn(await sessions["vcalice"].ws_connect(f"{ctx.base_url}/ws/chat"))
        await a3.send(type="voice_join", resume=True, room="general", resume_token=token)
        vs = await a3.wait(_t("voice_state"))
        elapsed = time.monotonic() - t_drop
        # the page joins the channel text chat on its new socket as well
        await a3.send(type="join", channel="general")
        ok("voice: resume within the grace period is accepted",
               bool(vs and vs.get("resumed") and vs.get("resume_token") == token), json.dumps(vs))
        res = await cb.wait(lambda e: e.get("type") == "voice_user_resumed" and e.get("user_id") == alice, start=m)
        ok("voice: bob sees resumed", res is not None and set(res) == {"type", "user_id"}, json.dumps(res))
        ok("voice: bob saw reconnecting then resumed and no left",
               "voice_user_left" not in cb.types(m) and cb.types(m).index("voice_user_reconnecting")
               < cb.types(m).index("voice_user_resumed"), json.dumps(cb.types(m)))
        ulist = await cb.wait(lambda e: e.get("type") == "users" and any(
            u.get("user_id") == alice and u.get("in_voice") and not u.get("voice_reconnecting")
            for u in e.get("users", [])), start=m)
        ok("voice: bob's users list shows alice as connected again", ulist is not None)
        mm = cb.mark()
        await a3.send(type="voice_mute", muted=True)
        ok_mute = await cb.wait(lambda e: e.get("type") == "voice_mute_changed" and e.get("user_id") == alice, start=mm)
        ok("voice: the resumed socket controls the call", ok_mute is not None)
        await a3.send(type="voice_mute", muted=False)
        await asyncio.sleep(max(0.0, 22.0 - elapsed) if elapsed < 22 else 0)  # past the original deadline
        ok("voice: a resumed call is not removed when the old grace period would have ended",
               "voice_user_left" not in cb.types(m), json.dumps(cb.types(m)))

        # --- no reconnect: left about 20 seconds later ---------------------
        m = cb.mark()
        t_drop = time.monotonic()
        await a3.close()
        rec = await cb.wait(_t("voice_user_reconnecting"), start=m, timeout=10)
        left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == alice,
                             start=m, timeout=GRACE_HIGH + 5)
        waited = time.monotonic() - t_drop
        ok("voice: without a reconnect bob sees reconnecting, then left",
               rec is not None and left is not None and cb.types(m).index("voice_user_reconnecting")
               < cb.types(m).index("voice_user_left"), json.dumps(cb.types(m)))
        ok("voice: left arrives about 20 seconds after the drop",
               left is not None and GRACE_LOW <= waited <= GRACE_HIGH, f"{waited:.1f}s")
        ulist = await cb.wait(lambda e: e.get("type") == "users" and not any(
            u.get("user_id") == alice and u.get("in_voice") for u in e.get("users", [])), start=m)
        ok("voice: bob's users list no longer shows alice in voice", ulist is not None)
        a4 = await connect(sessions["vcalice"])
        await a4.send(type="voice_join", resume=True, room="general", resume_token=token)
        failed = await a4.wait(_t("voice_resume_failed"))
        ok("voice: resuming after the grace period fails", failed is not None)

        # --- explicit leave: immediate, no grace ---------------------------
        await a4.send(type="voice_join")
        vs = await a4.wait(_t("voice_state"))
        ok("voice: alice can join again after the grace period",
               bool(vs and vs.get("resume_token") and vs.get("resume_token") != token), json.dumps(vs))
        m = cb.mark()
        t0 = time.monotonic()
        await a4.send(type="voice_leave")
        left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == alice, start=m, timeout=5)
        ok("voice: leaving ends the call at once, with no reconnecting state",
               left is not None and time.monotonic() - t0 < 3 and "voice_user_reconnecting" not in cb.types(m),
               json.dumps(cb.types(m)))
        await a4.close()
        await asyncio.sleep(0.5)
        ok("voice: closing the socket after leaving sends nothing more",
               cb.types(m).count("voice_user_left") == 1 and "voice_user_reconnecting" not in cb.types(m),
               json.dumps(cb.types(m)))

        # --- Leave clicked while disconnected: ended from the new socket ----
        a7 = await connect(sessions["vcalice"])
        await a7.send(type="voice_join")
        vs = await a7.wait(_t("voice_state"))
        tok7 = (vs or {}).get("resume_token")
        m = cb.mark()
        await a7.close()
        rec = await cb.wait(_t("voice_user_reconnecting"), start=m)
        ok("voice: a dropped call is held before the leave", rec is not None)
        a8 = await connect(sessions["vcalice"])
        await a8.send(type="voice_leave", room="general", resume_token="not-the-token")
        await asyncio.sleep(0.5)
        ok("voice: a leave with a wrong token does not end the held call",
               "voice_user_left" not in cb.types(m), json.dumps(cb.types(m)))
        t0 = time.monotonic()
        await a8.send(type="voice_leave", room="general", resume_token=tok7)
        left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == alice,
                             start=m, timeout=5)
        ok("voice: a leave with the resume token ends a held call at once",
               left is not None and time.monotonic() - t0 < 3, json.dumps(cb.types(m)))
        await a8.send(type="voice_join")
        vs = await a8.wait(_t("voice_state"))
        ok("voice: alice can join again right after leaving a held call",
               bool(vs and vs.get("resume_token")), json.dumps(a8.events[-3:]))
        await a8.send(type="voice_leave")
        await a8.close()
        await asyncio.sleep(0.3)

        # --- removed from a call room: out of the call at once -------------
        eve = ids["vceve"]
        async with sessions["vcalice"].post(f"{ctx.base_url}/api/dm/conversations",
                                            json={"user_ids": [bob, eve]}) as resp:
            dm_body = await resp.json() if resp.status == 200 else {}
        dm_id = (dm_body.get("conversation") or {}).get("id")
        ok("voice: a group DM is created for the removal check", bool(dm_id), json.dumps(dm_body)[:200])
        if dm_id:
            a9 = await connect(sessions["vcalice"])
            await a9.send(type="voice_join", room=f"dm:{dm_id}")
            vs = await a9.wait(_t("voice_state"))
            ok("voice: alice joins the group DM call", bool(vs and vs.get("resume_token")), json.dumps(vs))
            t0 = time.monotonic()
            async with sessions["vcalice"].post(f"{ctx.base_url}/api/dm/conversations/{dm_id}/leave") as resp:
                st = resp.status
            den = await a9.wait(_t("voice_denied"), timeout=5)
            ok("voice: leaving the group DM takes alice out of its call at once",
                   st == 200 and den is not None and time.monotonic() - t0 < 4, f"status {st}, {a9.types()}")
            await a9.send(type="voice_join")
            vs = await a9.wait(lambda e: e.get("type") in ("voice_state", "voice_denied"),
                               start=a9.mark())
            ok("voice: alice is free to join a call after being removed",
                   bool(vs and vs.get("type") == "voice_state"), json.dumps(vs))
            await a9.send(type="voice_leave")
            await a9.close()
            await asyncio.sleep(0.3)

        # --- anonymous mode while the call is held -------------------------
        a5 = await connect(sessions["vcalice"])
        await a5.send(type="voice_join")
        vs = await a5.wait(_t("voice_state"))
        tok5 = (vs or {}).get("resume_token")
        m = cb.mark()
        await a5.close()
        rec = await cb.wait(_t("voice_user_reconnecting"), start=m)
        ok("voice: a held call is shown as reconnecting", rec is not None)
        t0 = time.monotonic()
        try:
            st = await set_anon(True)
            left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == alice,
                                 start=m, timeout=5)
            ok("voice: switching anonymous mode on ends a held call at once",
                   st == 200 and left is not None and time.monotonic() - t0 < 4, f"status {st}, {cb.types(m)}")
            a6 = await connect(sessions["vcalice"])
            await a6.send(type="voice_join", resume=True, room="general", resume_token=tok5)
            failed = await a6.wait(lambda e: e.get("type") in ("voice_resume_failed", "voice_denied"))
            ok("voice: an anonymous member cannot resume into a channel voice room",
                   failed is not None, json.dumps(a6.events[-3:]))
            await a6.send(type="voice_join")
            den = await a6.wait(_t("voice_denied"))
            ok("voice: an anonymous member still cannot join channel voice", den is not None)
            await a6.close()
        finally:
            await set_anon(False)

        # --- revoked sessions: immediate, no grace -------------------------
        if admin is None:
            ctx.skip("voice: an admin password reset ends the call at once", "no admin password for this instance")
        for label, name, held in (("live call", "vcvic1", False), ("held call", "vcvic2", True)):
            if admin is None:
                break
            vic = await connect(sessions[name])
            await vic.send(type="voice_join")
            vs = await vic.wait(_t("voice_state"))
            m = cb.mark()
            if held:
                await vic.close()
                rec = await cb.wait(_t("voice_user_reconnecting"), start=m)
                ok("voice: %s: the call is held after the socket drops" % label, rec is not None)
            t0 = time.monotonic()
            async with admin.post(f"{ctx.base_url}/api/users/{ids[name]}/reset-password",
                                  json={"new_password": PW + "-new"}) as resp:
                st = resp.status
            left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == ids[name],
                                 start=m, timeout=5)
            ok("voice: %s: an admin password reset ends the call at once" % label,
                   st == 200 and left is not None and time.monotonic() - t0 < 4, f"status {st}, {cb.types(m)}")
            if not held:
                ok("voice: live call: no reconnecting state before left",
                       "voice_user_reconnecting" not in cb.types(m), json.dumps(cb.types(m)))
                close = await asyncio.wait_for(_closed(vic), 5) if not vic.ws.closed else vic.ws.close_code
                ok("voice: live call: the socket is closed with code 4001", close == 4001, str(close))
            await asyncio.sleep(0.3)
            if not held:
                await vic.close()

        # --- logout: that session's sockets and call end, others stay ------
        lo = await stack.enter_async_context(ctx.http())
        r = await ctx.login(lo, "vcalice", PW)
        ok("voice: a second session of alice can log in", r.status == 200, f"status {r.status}")
        if r.status == 200:
            keep = await connect(sessions["vcalice"])
            lc = await connect(lo)
            await lc.send(type="voice_join")
            vs = await lc.wait(_t("voice_state"))
            ok("voice: alice joins voice on the session that will log out", bool(vs and vs.get("resume_token")))
            m = cb.mark()
            t0 = time.monotonic()
            async with lo.post(f"{ctx.base_url}/logout", allow_redirects=False) as resp:
                st = resp.status
            left = await cb.wait(lambda e: e.get("type") == "voice_user_left" and e.get("user_id") == alice,
                                 start=m, timeout=5)
            ok("voice: logout ends the call at once, with no reconnecting state",
                   st in (200, 302, 303) and left is not None and time.monotonic() - t0 < 4
                   and "voice_user_reconnecting" not in cb.types(m), f"status {st}, {cb.types(m)}")
            close = await asyncio.wait_for(_closed(lc), 5) if not lc.ws.closed else lc.ws.close_code
            ok("voice: logout closes that session's chat socket with code 4001", close == 4001, str(close))
            await asyncio.sleep(0.3)
            ok("voice: logout leaves the account's other session's socket open", not keep.ws.closed)
            await keep.close()

        await cb.send(type="voice_leave")
        await cb.close()
        await ce.close()


async def _closed(conn):
    while not conn.ws.closed:
        await asyncio.sleep(0.05)
    return conn.ws.close_code
