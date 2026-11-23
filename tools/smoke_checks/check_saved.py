"""Saved messages and remind-me-later on a running instance, over the real routes and a real chat socket.

The staged server is restarted with a 2 second reminder tick (PORTAL_SAVED_TICK_SECONDS, honoured only in
staged mode; the real tick is 30 seconds) and again at the end without it.

Proves: a member saves a message of a private channel and of a direct message and lists them with their text;
an outsider's save of the same message answers exactly like a save of a message that does not exist; a
reminder set a few seconds ahead creates one notification when it is due (fixed title, empty text, only ids in
its data) and not a second one however long we wait, also after a restart of the server; a reminder that came
due while the server was down fires once after the start; after the member is removed from the private channel
the entry says "no longer available" with nothing else, and the same after the message is deleted; the saved
rows and the notification hold no copy of the text; nobody else (an outsider, an administrator) sees the entry,
and a socket of another member receives no frame while the member saves, sets a reminder and removes it.

Users, channels and messages carry random suffixes and every assertion is about those rows, so the module also
holds on a stage started from a copy of the production database. It needs no admin password.

Not proven here: the chat page (marker, menu, Saved view) in a browser, a real push service, a phone.
"""

import asyncio
import json
import secrets
import sqlite3
import time
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone

PW = "Saved-check-pw-1"
UNAVAILABLE_KEYS = {"id", "saved_at", "remind_at", "reminded", "available"}

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
        await db.set_user_role(ids["adm"], "admin")
        pre = P["pre"]
        priv = await db.create_chat_channel(pre + "-priv", created_by=ids["owner"])
        await db.update_chat_channel(priv, visibility="private")
        await db.add_channel_member(priv, ids["owner"])
        await db.add_channel_member(priv, ids["member"])
        out["priv"] = priv
        out["m_priv"] = await db.create_chat_message(priv, ids["owner"], pre + "owner", pre + " " + P["needle"] + " private")
        out["m_second"] = await db.create_chat_message(priv, ids["owner"], pre + "owner", pre + " " + P["needle"] + " second")
        out["m_third"] = await db.create_chat_message(priv, ids["owner"], pre + "owner", pre + " " + P["needle"] + " third")
        conv = await db.create_dm_conversation(ids["owner"], [ids["member"]])
        out["conv"] = conv["id"]
        out["m_dm"] = await db.create_dm_message(conv["id"], ids["owner"], pre + "owner", pre + " " + P["needle"] + " dm")
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''

CHANGE = r'''
import asyncio, json
from database import db

P = json.loads(%(params)r)

async def main():
    await db.connect()
    try:
        if P.get("remove_member"):
            await db.remove_channel_member(P["priv"], P["remove_member"])
        if P.get("delete_message"):
            await db.delete_chat_message(P["delete_message"])
        print("RESULT {}")
    finally:
        await db.close()

asyncio.run(main())
'''


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def iso_in(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    def close(self):
        self._task.cancel()


async def run(ctx):
    rnd = secrets.token_hex(3)
    pre = "sv" + rnd
    needle = "needle" + secrets.token_hex(5)
    names = ("owner", "member", "outsider", "adm")
    db_path = ctx.stage_dir / "portal.db"
    env_path = ctx.stage_dir / ".env"
    original_env = env_path.read_text()

    def ok(name, passed, detail=""):
        ctx.ok("saved: " + name, bool(passed), "" if passed else str(detail)[:300])

    def sql(query, args=()):
        con = sqlite3.connect(str(db_path), timeout=15)
        try:
            return con.execute(query, args).fetchall()
        finally:
            con.close()

    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "names": names, "pre": pre, "needle": needle})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ok("setup", False, out[-500:])
        return
    ids = data["users"]

    env_path.write_text(original_env.rstrip("\n") + "\nPORTAL_SAVED_TICK_SECONDS=2\n")
    await ctx.stop_server()
    await ctx.start_server()
    stack = AsyncExitStack()
    try:
        if True:
            sess = {}
            for n in names:
                s = await stack.enter_async_context(ctx.http())
                r = await ctx.login(s, pre + n, PW)
                if r.status != 200:
                    ok(f"{n} logs in", False, r.status)
                    return
                sess[n] = s

            async def api(user, method, path, **kw):
                async with sess[user].request(method, f"{ctx.base_url}{path}", **kw) as r:
                    raw = await r.read()
                    try:
                        return r.status, json.loads(raw)
                    except Exception:
                        return r.status, raw

            async def notes(user):
                st, b = await api(user, "GET", "/api/notifications?limit=100")
                out = [n for n in (b or {}).get("notifications", []) if n.get("type") == "reminder"]
                for n in out:
                    if isinstance(n.get("data"), str):
                        n["data"] = json.loads(n["data"] or "{}")        # the list route sends the data as text
                return out

            async def wait_notes(user, count, timeout=15):
                end = time.monotonic() + timeout
                while time.monotonic() < end:
                    got = await notes(user)
                    if len(got) >= count:
                        return got
                    await asyncio.sleep(0.5)
                return await notes(user)

            # a socket of another member: it must see nothing of this
            ws = await stack.enter_async_context(sess["outsider"].ws_connect(f"{ctx.base_url}/ws/chat", max_msg_size=0))
            other = Sock(ws)
            stack.callback(other.close)
            await asyncio.sleep(0.5)
            mark = len(other.events)

            # ---- save, and the same answer for a message that is missing and one that may not be read
            st, b = await api("member", "POST", "/api/saved", json={"kind": "channel", "message_id": data["m_priv"]})
            sid = b["saved"]["id"] if st == 201 else None
            ok("a member saves a message of a private channel", st == 201 and sid, f"{st} {b}")
            st, b = await api("member", "POST", "/api/saved", json={"kind": "dm", "message_id": data["m_dm"]})
            sid_dm = b["saved"]["id"] if st == 201 else None
            ok("and a message of a direct message", st == 201 and sid_dm, f"{st} {b}")
            st1, b1 = await api("outsider", "POST", "/api/saved", json={"kind": "channel", "message_id": data["m_priv"]})
            st2, b2 = await api("outsider", "POST", "/api/saved", json={"kind": "channel", "message_id": 2 ** 40})
            ok("an outsider's save of it answers like a save of a message that does not exist", st1 == st2 == 404 and b1 == b2, f"{st1} {b1} / {st2} {b2}")
            st, b = await api("member", "GET", "/api/saved")
            items = {i["id"]: i for i in (b or {}).get("items", [])}
            ok("the list shows the texts, resolved now", st == 200 and sid in items and sid_dm in items
               and needle in items[sid]["message"]["text"] and items[sid]["channel_id"] == data["priv"]
               and items[sid_dm]["conversation_id"] == data["conv"], f"{st} {b}"[:300])
            for who in ("outsider", "adm", "owner"):
                st, b = await api(who, "GET", "/api/saved")
                ok(f"{who} sees nothing of it", st == 200 and b["items"] == [], f"{st} {b}")

            # ---- a reminder: fires once, with a fixed text
            st, b = await api("member", "PUT", f"/api/saved/{sid}/remind", json={"remind_at": iso_in(4)})
            ok("a reminder is set for a few seconds ahead", st == 200 and b["remind_at"], f"{st} {b}")
            st, b = await api("member", "PUT", f"/api/saved/{sid}/remind", json={"remind_at": "2020-01-01T00:00:00Z"})
            ok("a past time is refused", st == 400, f"{st} {b}")
            got = await wait_notes("member", 1)
            ok("one notification appears when it is due", len(got) == 1, got)
            if got:
                n = got[0]
                ok("its title is fixed, its text empty and its data holds ids only",
                   n["title"] == "Reminder for a saved message" and not n.get("message")
                   and set(n["data"]) == {"channel_id", "message_id", "saved_id"} and n["data"]["message_id"] == data["m_priv"]
                   and needle not in json.dumps(n), json.dumps(n)[:300])
            await asyncio.sleep(7)
            ok("it does not fire a second time", len(await notes("member")) == 1)
            ok("nobody else got one", not await notes("owner") and not await notes("outsider") and not await notes("adm"))

            # ---- across a restart: no repeat; a reminder that came due while down fires once
            st, b = await api("member", "POST", "/api/saved", json={"kind": "channel", "message_id": data["m_second"]})
            sid2 = b["saved"]["id"]
            await api("member", "PUT", f"/api/saved/{sid2}/remind", json={"remind_at": iso_in(5)})
            frames_seen = list(other.events[mark:])
            await stack.aclose()
            await ctx.stop_server()
            await asyncio.sleep(7)
            await ctx.start_server()
            stack = AsyncExitStack()
            await stack.__aenter__()
            for n in ("owner", "member"):
                s = await stack.enter_async_context(ctx.http())
                r = await ctx.login(s, pre + n, PW)
                if r.status != 200:
                    ok(f"{n} logs in again after the restart", False, r.status)
                    return
                sess[n] = s
            got = await wait_notes("member", 2)
            await asyncio.sleep(6)
            got = await notes("member")
            ok("the reminder that came due while the server was down fired once after the start, and the first one did not repeat",
               len(got) == 2 and sorted(x["data"]["saved_id"] for x in got) == sorted([sid, sid2]), json.dumps(got)[:300])

            # ---- access lost, message deleted
            rc, out = await ctx.run_py(CHANGE % {"params": json.dumps({"priv": data["priv"], "remove_member": ids["member"]})})
            st, b = await api("member", "GET", "/api/saved")
            items = {i["id"]: i for i in (b or {}).get("items", [])}
            ok("a member removed from the private channel sees only 'no longer available' for it",
               rc == 0 and sid in items and set(items[sid]) == UNAVAILABLE_KEYS and items[sid]["available"] is False
               and sid_dm in items and items[sid_dm]["available"] is True, json.dumps(items)[:300])
            ok("and not a word of it in that entry", sid in items and needle not in json.dumps(items[sid]) and pre not in json.dumps(items[sid]))
            st3, _b3 = await api("member", "POST", "/api/saved", json={"kind": "channel", "message_id": data["m_second"]})
            ok("a new save of a message there is refused", st3 == 404, st3)

            st, b = await api("owner", "POST", "/api/saved", json={"kind": "channel", "message_id": data["m_third"]})
            sid3 = b["saved"]["id"]
            await api("owner", "PUT", f"/api/saved/{sid3}/remind", json={"remind_at": iso_in(3)})
            rc, out = await ctx.run_py(CHANGE % {"params": json.dumps({"priv": data["priv"], "delete_message": data["m_third"]})})
            await asyncio.sleep(1)
            st, b = await api("owner", "GET", "/api/saved")
            it = {i["id"]: i for i in b["items"]}.get(sid3)
            ok("after the message is deleted the entry says it is no longer available", it and set(it) == UNAVAILABLE_KEYS, it)
            got = await wait_notes("owner", 1)
            ok("its reminder still fires, with the same fixed text, and opens the Saved view",
               len(got) == 1 and got[0]["title"] == "Reminder for a saved message" and got[0]["data"].get("saved") == 1
               and "message_id" not in got[0]["data"], json.dumps(got)[:300])

            # ---- no copy of any text
            rows = sql("SELECT * FROM saved_messages WHERE id IN (?, ?, ?)", (sid, sid2, sid3))
            notes_rows = sql("SELECT title, message, data FROM notifications WHERE user_id IN (?, ?)", (ids["member"], ids["owner"]))
            ok("the saved rows and the notifications hold no copy of the text",
               needle not in json.dumps(rows) and needle not in json.dumps(notes_rows) and len(rows) == 3, str(rows)[:200])
            ok("a socket of another member got no frame about any of it",
               not any("saved" in json.dumps(e).lower() or "remind" in json.dumps(e).lower() for e in frames_seen), str(frames_seen)[:300])
    finally:
        try:
            await stack.aclose()
        except Exception:
            pass
        env_path.write_text(original_env)
        await ctx.stop_server()
        await ctx.start_server()
