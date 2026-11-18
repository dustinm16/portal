"""Automod on edits, rule validation, and regex rules that cannot stall chat.

Drives a running instance over the chat websocket and the admin API. Rules are
created through the API (which also clears the server's rule cache). Users are
created in the stage database with ctx.run_py because registration is rate
limited.

Not covered here (needs a browser): that a rejected edit snaps back to the old
text on the author's screen (chat.html handles the edit_rejected event).
"""

import asyncio
import json
import secrets
import time
from contextlib import AsyncExitStack

PW = "Automod-check-pw-1"
NAMES = ("amalice", "amcarl", "amobs", "ammod")

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
        await db.set_user_role(out["ammod"], "moderator")
        cur = await db.conn.execute("SELECT id FROM chat_channels WHERE name = 'general'")
        out["channel"] = (await cur.fetchone())["id"]
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
''' % {"names": NAMES, "pw": PW}

# Reads what is stored for a message, whether the search index finds given words,
# and the timeout / automod-action rows of the listed users.
STATE = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    try:
        out = {}
        msg = await db.get_chat_message(%(mid)d)
        out["stored"] = msg["message"]
        out["edited_at"] = msg.get("edited_at")
        hits = {}
        for word in %(words)r:
            res = await db.search_messages(word, %(uid)d, scope="channels", channel_id=%(ch)d, user_role="superadmin")
            hits[word] = res["total"]
        out["hits"] = hits
        cur = await db.conn.execute("SELECT user_id, type FROM chat_timeouts")
        out["timeouts"] = [dict(r) for r in await cur.fetchall()]
        cur = await db.conn.execute("SELECT user_id FROM automod_actions")
        out["actions"] = [r["user_id"] for r in await cur.fetchall()]
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''


# Stores a regex rule that would be refused today, as one saved before validation existed.
STORE_STALE = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    try:
        rid = await db.create_automod_rule("word_filter", %(name)r, {"words": ["(a+)+$", "fine"], "match_mode": "regex"},
                                           "delete", %(uid)d)
        print("RESULT " + json.dumps({"id": rid}))
    finally:
        await db.close()

asyncio.run(main())
'''


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def _pump(ws, events):
    try:
        async for msg in ws:
            if msg.type == 1:
                events.append(json.loads(msg.data))
    except Exception:
        pass


async def _wait_for(events, pred, timeout=10.0, start=0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        for e in events[start:]:
            if pred(e):
                return e
        await asyncio.sleep(0.02)
    return None


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("automod: setup", False, out[-400:])
        return
    ch = data["channel"]
    rnd = secrets.token_hex(3)

    async with AsyncExitStack() as stack:
        admin = await stack.enter_async_context(ctx.http())
        resp = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
        if resp.status != 200:
            ctx.ok("automod: admin can log in", False, f"status {resp.status}")
            return
        sess, ws, ev = {}, {}, {}
        for name in NAMES:
            sess[name] = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess[name], name, PW)
            if resp.status != 200:
                ctx.ok(f"automod: {name} can log in", False, f"status {resp.status}")
                return
            ws[name] = await stack.enter_async_context(sess[name].ws_connect(f"{ctx.base_url}/ws/chat", max_msg_size=0))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws[name], ev[name]))
            stack.callback(pump.cancel)
            await ws[name].send_json({"type": "join", "channel_id": ch})
            if await _wait_for(ev[name], lambda e: e.get("type") == "users") is None:
                ctx.ok(f"automod: {name} joined the channel", False, "no users list")
                return

        async def api(method, path, body=None):
            async with admin.request(method, f"{ctx.base_url}{path}", json=body) as r:
                try:
                    payload = await r.json()
                except Exception:
                    payload = {}
                return r.status, payload

        async def make_rule(name, rule_type, config, action="delete", duration=None):
            body = {"type": rule_type, "name": f"{name} {rnd}", "config": config, "action": action}
            if duration:
                body["action_duration"] = duration
            return await api("POST", "/api/admin/automod", body)

        async def post(name, text):
            mark = len(ev[name])
            await ws[name].send_json({"type": "message", "message": text})
            got = await _wait_for(ev[name], lambda e: e.get("type") == "message" and e.get("message") == text, start=mark)
            return got["id"] if got else None

        async def state(mid, uid, words):
            rc, out = await ctx.run_py(STATE % {"mid": mid, "uid": uid, "ch": ch, "words": words})
            return _result(out) or {"error": out[-300:]}

        old = {n: f"plain {n} {rnd}" for n in ("amalice", "amcarl", "ammod")}
        ids = {n: await post(n, old[n]) for n in old}
        ctx.ok("automod: members and moderator can post before any rule exists", all(ids.values()), str(ids))
        if not all(ids.values()):
            return

        # ---- an edit that adds a blocked word is refused ----
        status, body = await make_rule("blocked word", "word_filter", {"words": ["blockedword"], "match_mode": "contains"})
        ctx.ok("automod: word rule is created", status == 201, f"{status} {body}")
        rule_blocked = body.get("id")

        # sending the word is refused too (the same helper serves both paths)
        mark = len(ev["amalice"])
        await ws["amalice"].send_json({"type": "message", "message": "sending blockedword"})
        err = await _wait_for(ev["amalice"], lambda e: e.get("type") == "error" and e.get("error_code") == "automod", start=mark)
        ctx.ok("automod: sending a blocked word is still refused", err is not None, "no automod error")

        marks = {n: len(ev[n]) for n in NAMES}
        await ws["amalice"].send_json({"type": "edit_message", "message_id": ids["amalice"], "message": "now blockedword"})
        err = await _wait_for(ev["amalice"], lambda e: e.get("type") == "error" and e.get("error_code") == "automod", start=marks["amalice"])
        rej = await _wait_for(ev["amalice"], lambda e: e.get("type") == "edit_rejected", start=marks["amalice"])
        ctx.ok("automod: an edit adding a blocked word gets an automod error for its author",
               err is not None and "not changed" in err.get("message", ""), json.dumps(err))
        ctx.ok("automod: the author is sent the stored text so the screen can undo the edit",
               rej is not None and rej.get("message") == old["amalice"] and rej.get("message_id") == ids["amalice"], json.dumps(rej))
        st = await state(ids["amalice"], data["amalice"], ["blockedword", f"plain"])
        ctx.ok("automod: the old text is kept in the database after a refused edit",
               st.get("stored") == old["amalice"] and not st.get("edited_at"), json.dumps(st))
        ctx.ok("automod: the search index holds the old text, not the refused one",
               st.get("hits", {}).get("blockedword") == 0 and st.get("hits", {}).get("plain", 0) >= 1, json.dumps(st.get("hits")))

        # a good edit goes through, and also works as the marker that the refused one sent nothing
        await ws["amalice"].send_json({"type": "edit_message", "message_id": ids["amalice"], "message": f"fine edit {rnd}"})
        got = await _wait_for(ev["amobs"], lambda e: e.get("type") == "message_edited" and e.get("message_id") == ids["amalice"], start=marks["amobs"])
        seen = ev["amobs"][marks["amobs"]:]
        ctx.ok("automod: an allowed edit is still broadcast",
               got is not None and got.get("message") == f"fine edit {rnd}", json.dumps(got))
        ctx.ok("automod: nobody but the author saw the refused edit",
               "blockedword" not in json.dumps(seen) and "automod" not in json.dumps(seen), json.dumps(seen)[:400])

        # ---- timeout action on edits, staff exempt ----
        status, body = await make_rule("timeout word", "word_filter", {"words": ["timeoutword"], "match_mode": "contains"},
                                       action="timeout", duration=60)
        rule_timeout = body.get("id")
        marks = {n: len(ev[n]) for n in NAMES}
        await ws["amcarl"].send_json({"type": "edit_message", "message_id": ids["amcarl"], "message": "x timeoutword"})
        await ws["ammod"].send_json({"type": "edit_message", "message_id": ids["ammod"], "message": "x timeoutword"})
        # a member trying someone else's message: refused for ownership, no penalty
        await ws["amobs"].send_json({"type": "edit_message", "message_id": ids["amalice"], "message": "x timeoutword"})
        e_carl = await _wait_for(ev["amcarl"], lambda e: e.get("type") == "error" and e.get("error_code") == "automod", start=marks["amcarl"])
        e_mod = await _wait_for(ev["ammod"], lambda e: e.get("type") == "error" and e.get("error_code") == "automod", start=marks["ammod"])
        e_obs = await _wait_for(ev["amobs"], lambda e: e.get("type") == "error", start=marks["amobs"])
        timed = await _wait_for(ev["amobs"], lambda e: e.get("type") == "user_timed_out", start=marks["amobs"])
        await asyncio.sleep(0.5)
        st_c = await state(ids["amcarl"], data["amcarl"], [])
        st_m = await state(ids["ammod"], data["ammod"], [])
        timed_ids = [t["user_id"] for t in st_c.get("timeouts", [])]
        ctx.ok("automod: a member's refused edit gets the timeout, a moderator's does not",
               e_carl is not None and e_mod is not None and data["amcarl"] in timed_ids and data["ammod"] not in timed_ids,
               json.dumps({"timeouts": st_c.get("timeouts"), "carl": bool(e_carl), "mod": bool(e_mod)}))
        ctx.ok("automod: the timeout is announced to the channel for the member only",
               timed is not None and timed.get("user_id") == data["amcarl"], json.dumps(timed))
        ctx.ok("automod: both refused edits kept the old text",
               st_c.get("stored") == old["amcarl"] and st_m.get("stored") == old["ammod"],
               json.dumps([st_c.get("stored"), st_m.get("stored")]))
        ctx.ok("automod: editing another member's message fails on ownership first (no automod error, no penalty)",
               e_obs is not None and e_obs.get("error_code") != "automod" and data["amobs"] not in timed_ids
               and data["amobs"] not in st_c.get("actions", []), json.dumps([e_obs, st_c.get("actions")]))
        for rid in (rule_blocked, rule_timeout):
            await api("DELETE", f"/api/admin/automod/{rid}")

        # ---- validation on create and update ----
        status, body = await make_rule("nested", "word_filter", {"words": ["(a+)+$"], "match_mode": "regex"})
        ctx.ok("automod: creating a nested-quantifier rule is refused with 400", status == 400, f"{status} {body}")
        status, body = await make_rule("long", "word_filter", {"words": ["a" * 501], "match_mode": "regex"})
        ctx.ok("automod: creating a 501-character pattern is refused with 400", status == 400, f"{status} {body}")
        status, body = await make_rule("fine", "word_filter", {"words": ["colou?r", "a" * 500], "match_mode": "regex"})
        ctx.ok("automod: an ordinary regex rule is accepted", status == 201, f"{status} {body}")
        fine = body.get("id")
        status, body = await api("PUT", f"/api/admin/automod/{fine}",
                                 {"config": {"words": ["(a+)+$"], "match_mode": "regex"}})
        ctx.ok("automod: updating a rule to (a+)+$ is refused with 400", status == 400, f"{status} {body}")
        status, body = await api("PUT", f"/api/admin/automod/{fine}",
                                 {"config": {"words": ["a" * 501], "match_mode": "regex"}})
        ctx.ok("automod: updating a rule to a 501-character pattern is refused with 400", status == 400, f"{status} {body}")
        status, body = await api("PUT", f"/api/admin/automod/{fine}", {"config": "not an object"})
        ctx.ok("automod: updating a rule to a non-object config is refused with 400", status == 400, f"{status} {body}")
        status, rules = await api("GET", "/api/admin/automod")
        stored = next((r for r in rules.get("rules", []) if r["id"] == fine), {})
        ctx.ok("automod: a refused update leaves the stored rule unchanged",
               "colou?r" in json.dumps(stored.get("config")) and "(a+)" not in json.dumps(stored.get("config")), json.dumps(stored))
        status, body = await api("PUT", f"/api/admin/automod/{fine}", {"enabled": False})
        ctx.ok("automod: other updates still work", status == 200, f"{status} {body}")
        # changing only the type: the stored config is checked against the new type
        status, body = await make_rule("typed", "link_filter", {"words": ["(a+)+$"], "match_mode": "regex"})
        typed = body.get("id")
        status2, body2 = await api("PUT", f"/api/admin/automod/{typed}", {"type": "word_filter"})
        ctx.ok("automod: changing only the type checks the stored config (400)", status == 201 and status2 == 400, f"{status} {status2} {body2}")
        status, body = await api("PUT", "/api/admin/automod/999999", {"config": {"words": ["x"]}})
        ctx.ok("automod: updating a missing rule is 404", status == 404, f"{status} {body}")
        status, body = await make_rule("spam", "spam_filter", {"max_messages": 5})
        ctx.ok("automod: the spam_filter type is still accepted (stored, not enforced)", status == 201, f"{status} {body}")
        for rid in (fine, typed, body.get("id")):
            if rid:
                await api("DELETE", f"/api/admin/automod/{rid}")

        # ---- a pattern that ends in ')' must be saved and must not break the chat socket ----
        status, body = await make_rule("group end", "word_filter", {"words": ["(foo|bar)"], "match_mode": "regex"})
        ctx.ok("automod: a regex rule ending in a closing parenthesis is accepted", status == 201, f"{status} {body}")
        group_rule = body.get("id")
        mark = len(ev["amalice"])
        await ws["amalice"].send_json({"type": "message", "message": f"say FOO now {rnd}"})
        err = await _wait_for(ev["amalice"], lambda e: e.get("type") == "error" and e.get("error_code") == "automod", start=mark)
        ctx.ok("automod: a rule ending in a closing parenthesis blocks a matching message", err is not None, "no automod error")
        after = await post("amalice", f"still connected {rnd}")
        ctx.ok("automod: the sender's chat socket survives a message checked against that rule", after is not None, "no echo")
        if group_rule:
            await api("DELETE", f"/api/admin/automod/{group_rule}")

        # ---- open-ended repeats are caught by the nested-quantifier check ----
        for pat in (r"(a{,})+$", r"(a{2,})+$", r"(a+){,}$"):
            status, body = await make_rule("open ended", "word_filter", {"words": [pat], "match_mode": "regex"})
            ctx.ok(f"automod: nested open-ended repeat {pat} is refused (400)", status == 400, f"{status} {body}")
            if status == 201 and body.get("id"):
                await api("DELETE", f"/api/admin/automod/{body['id']}")

        # ---- a stored rule that now fails validation is marked in the admin list ----
        # Rules saved before validation existed cannot be created through the API, so store one directly.
        rc, out = await ctx.run_py(STORE_STALE % {"name": f"stale {rnd}", "uid": data["ammod"]})
        stale = _result(out)
        ctx.ok("automod: a stale unsafe rule is stored for the check", rc == 0 and stale is not None, out[-300:])
        if stale:
            status, body = await api("GET", "/api/admin/automod")
            rules = {r["id"]: r for r in body.get("rules", [])} if status == 200 else {}
            mine = rules.get(stale["id"], {})
            reason = mine.get("not_enforced_reason") or ""
            ctx.ok("automod: the list gives the reason a stale unsafe rule is not enforced",
                   status == 200 and "(a+)+$" in reason and "nested quantifier" in reason, f"{status} {reason!r}")
            others = [r for rid, r in rules.items() if rid != stale["id"] and r.get("not_enforced_reason")]
            ctx.ok("automod: rules that are enforced carry no reason", not others, str([r["name"] for r in others]))
            await api("DELETE", f"/api/admin/automod/{stale['id']}")

        # ---- a slow regex rule cannot stall other users ----
        # Not caught by the heuristic (sequential overlapping repeats), so the worker limit is what protects chat.
        status, body = await make_rule("slow", "word_filter", {"words": ["a*a*a*a*a*a*!"], "match_mode": "regex"})
        ctx.ok("automod: a polynomial pattern passes the heuristic (documented limit)", status == 201, f"{status} {body}")
        slow_rule = body.get("id")

        async def round_trip(name, text):
            t0 = time.monotonic()
            mid = await post(name, text)
            return (time.monotonic() - t0) if mid else None

        base = await round_trip("amobs", "baseline " + rnd)
        t0 = time.monotonic()
        attack = asyncio.create_task(round_trip("amalice", "a" * 1999))
        await asyncio.sleep(0.03)
        victim = await round_trip("amobs", "while the slow rule runs " + rnd)
        attacked = await attack
        total = time.monotonic() - t0
        ctx.ok("automod: another user's message is delivered while a slow pattern is being tested",
               base is not None and victim is not None and victim < 1.5,
               f"baseline {base}, during attack {victim}, attacker message {attacked}")
        ctx.ok("automod: the slow pattern is stopped (the attacking message returns, bounded)",
               attacked is not None and total < 3.0, f"attacker round trip {attacked}, total {total:.2f}s")
        # the same pattern is now skipped for a while: a second attack costs nothing
        again = await round_trip("amalice", "a" * 1998)
        ctx.ok("automod: a pattern that overran its limit is skipped afterwards",
               again is not None and again < 0.5, f"{again}")

        # a 50 KB message: dropped by the length limit before any rule runs, nobody else is held up
        mark = len(ev["amobs"])
        await ws["amalice"].send_json({"type": "message", "message": "b" * 50000})
        victim2 = await round_trip("amobs", "after the big one " + rnd)
        ctx.ok("automod: a 50 KB message does not stall chat for others",
               victim2 is not None and victim2 < 1.5, f"{victim2}")
        ctx.ok("automod: a 50 KB message is not delivered (over the 4000 character limit)",
               not any(e.get("type") == "message" and len(e.get("message", "")) > 4000 for e in ev["amobs"][mark:]), "delivered")
        await api("DELETE", f"/api/admin/automod/{slow_rule}")
