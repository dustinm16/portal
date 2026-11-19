"""Channel scrollback on a running instance: older pages over the chat websocket
and the HTTP route, windows around one message, access, anonymity and rate limit.

Users, channels and 300+ messages are created in the stage database with
ctx.run_py (registration is rate limited); everything is read back through the
real endpoints. Names carry a random suffix and every assertion is about those
rows, so the check also holds on a stage started from a copy of the production
database. Nothing here needs the admin password.

Not covered (needs a browser, see the final report): that scrolling to the top
keeps the reader's position, the highlight after a jump, the Jump to present
button, and the buffering of live messages in an around view.
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "History-check-pw-1"
PAGES = 300        # posts in the big channel (plus a few extras made by SETUP)

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
        await db.set_user_nickname(ids["alice"], P["pre"] + "Ally")
        await db.set_avatar(ids["anon"], {"color": "#112233", "emoji": P["pre"] + "AV", "initials": "ZQ"})
        await db.set_user_nickname(ids["anon"], P["pre"] + "Shadow")
        await db.set_chat_anonymous(ids["anon"], True)
        await db.set_chat_anonymous(ids["reactor"], True)

        big = await db.create_chat_channel(P["pre"] + "-big", created_by=ids["alice"])
        mids = []
        for i in range(1, P["count"] + 1):
            kw = {}
            who = "alice" if i %% 2 else "bob"
            if i %% 40 == 7:
                who, kw = "anon", {"anonymous": True}
            if i == P["count"] - 5:
                # a reply to a message 200 back, by the anonymous participant
                who, kw = "anon", {"anonymous": True, "reply_to": mids[i - 201],
                                   "reply_preview_username": "stored", "reply_preview_text": "stored"}
            mids.append(await db.create_chat_message(big, ids[who], P["pre"] + who, "%%s text %%d" %% (P["pre"], i), **kw))
        out["big"] = big
        out["mids"] = mids
        out["reply_id"] = mids[P["count"] - 6]
        out["reply_target"] = mids[P["count"] - 6 - 200]
        out["anon_post"] = mids[6]
        await db.toggle_reaction(mids[50], ids["anon"], "+1")
        await db.toggle_reaction(mids[50], ids["reactor"], "+1")
        await db.toggle_reaction(mids[50], ids["bob"], "+1")
        await db.create_poll(big, ids["anon"], "which", ["a", "b"], message_id=mids[46])
        await db.conn.execute("UPDATE chat_messages SET edited_at = ? WHERE id = ?",
                              ("2026-01-01T00:00:00+00:00", mids[86]))
        await db.conn.commit()

        priv = await db.create_chat_channel(P["pre"] + "-priv", created_by=ids["alice"])
        await db.update_chat_channel(priv, visibility="private")
        await db.add_channel_member(priv, ids["rm"])
        await db.add_channel_member(priv, ids["alice"])
        out["priv_msg"] = await db.create_chat_message(priv, ids["alice"], P["pre"] + "alice", P["pre"] + " members only")
        out["priv"] = priv

        # a stream whose chat channel a member is banned from after joining
        room = await db.create_chat_channel(P["pre"] + "-stream", created_by=ids["alice"])
        await db.create_chat_message(room, ids["alice"], P["pre"] + "alice", P["pre"] + " stream chat")
        sid = await db.create_user_stream(ids["alice"], P["pre"] + "s", "live_" + "h" * 24, public_key="pub_" + "i" * 24,
                                          is_public=True)
        await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (room, sid))
        await db.conn.commit()
        out["room"], out["sid"] = room, sid

        # a second stream chat, public at first; the check closes it later (is_public off)
        closed = await db.create_chat_channel(P["pre"] + "-closed", created_by=ids["alice"])
        out["closed_msg"] = await db.create_chat_message(closed, ids["alice"], P["pre"] + "alice", P["pre"] + " closed stream text")
        csid = await db.create_user_stream(ids["alice"], P["pre"] + "c", "live_" + "j" * 24, public_key="pub_" + "k" * 24,
                                           is_public=True)
        await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (closed, csid))
        await db.conn.commit()
        out["closed"], out["csid"] = closed, csid
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''

ACT = r'''
import asyncio, json
from database import db

P = json.loads(%(params)r)

async def main():
    await db.connect()
    try:
        out = {}
        if P["act"] == "remove":
            out["done"] = await db.remove_channel_member(P["channel"], P["user"])
        elif P["act"] == "set_public":
            await db.update_user_stream(P["sid"], is_public=P["value"])
            out["done"] = True
        elif P["act"] == "ban":
            out["done"] = bool(await db.create_stream_ban(P["sid"], P["user"], P["owner"], "check"))
        elif P["act"] == "read":
            cur = await db.conn.execute("SELECT last_read_message_id AS m FROM channel_read_positions "
                                        "WHERE user_id = ? AND channel_id = ?", (P["user"], P["channel"]))
            row = await cur.fetchone()
            out["read"] = row["m"] if row else None
        elif P["act"] == "set_read":
            await db.conn.execute("UPDATE channel_read_positions SET last_read_message_id = ? "
                                  "WHERE user_id = ? AND channel_id = ?", (P["value"], P["user"], P["channel"]))
            await db.conn.commit()
        elif P["act"] == "indexes":
            cur = await db.conn.execute("PRAGMA index_list(chat_messages)")
            out["indexes"] = [r["name"] for r in await cur.fetchall()]
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
    """A chat websocket that keeps everything it receives and waits for a type."""

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

    async def wait(self, *types, timeout=10.0, start=0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if e.get("type") in types:
                    return e
            await asyncio.sleep(0.02)
        return None

    async def ask(self, **payload):
        start = len(self.events)
        await self.ws.send_json({"type": "history_page", **payload})
        return await self.wait("history_older", "history_around", "history_error", start=start)

    def close(self):
        self._task.cancel()


def canon(m):
    return json.dumps(m, sort_keys=True)


async def run(ctx):
    rnd = secrets.token_hex(3)
    pre = "hs" + rnd
    names = ("alice", "bob", "anon", "reactor", "mod", "member", "rm", "banned", "outsider", "limit")
    params = {"pw": PW, "names": names, "pre": pre, "count": PAGES}
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps(params)}, timeout=240)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("history: setup", False, out[-500:])
        return
    ids, big, mids = data["users"], data["big"], data["mids"]
    anon_id, anon_name = ids["anon"], pre + "anon"
    anon_secrets = [anon_name, pre + "AV", pre + "Shadow"]

    async def act(**kw):
        rc2, out2 = await ctx.run_py(ACT % {"params": json.dumps(kw)})
        return _result(out2) if rc2 == 0 else None

    async with AsyncExitStack() as stack:
        async def login(name):
            sess = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess, pre + name, PW)
            if resp.status != 200:
                raise RuntimeError(f"{name} cannot log in: {resp.status}")
            return sess

        async def connect(sess):
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat", max_msg_size=0))
            sock = Sock(ws)
            stack.callback(sock.close)
            return sock

        async def http_get(sess, channel, **params):
            async with sess.get(f"{ctx.base_url}/api/chat/channels/{channel}/messages", params=params) as r:
                try:
                    body = await r.json()
                except Exception:
                    body = None
                return r.status, body, dict(r.headers)

        try:
            sessions = {n: await login(n) for n in ("alice", "member", "mod", "anon", "rm", "banned", "outsider", "limit")}
        except RuntimeError as e:
            ctx.ok("history: users can log in", False, str(e))
            return

        # ---- the index and the migration are in place and can run again ------------
        info = await act(act="indexes")
        ctx.ok("history: composite message index exists", bool(info) and "idx_chat_messages_channel_id_id" in info["indexes"],
               str(info))

        # ---- join, then every older page: no gaps, no duplicates --------------------
        member = await connect(sessions["member"])
        await member.ws.send_json({"type": "join", "channel_id": big})
        joined = await member.wait("history")
        ctx.ok("history: join sends the newest 50 with has_more",
               bool(joined) and len(joined["messages"]) == 50 and joined["has_more"] is True
               and joined["channel_id"] == big and joined["messages"][-1]["id"] == max(mids))
        if not joined:
            return
        seen = {m["id"]: m for m in joined["messages"]}
        by_path = {"join": dict(seen)}
        older, order, cursor, pages, last = {}, [m["id"] for m in joined["messages"]], joined["messages"][0]["id"], 0, None
        while True:
            last = await member.ask(before_id=cursor, req=pages)
            pages += 1
            if not last or last["type"] != "history_older":
                break
            for m in last["messages"]:
                older[m["id"]] = m
            order = [m["id"] for m in last["messages"]] + order
            if not last["has_more"]:
                break
            cursor = last["messages"][0]["id"]
        ctx.ok("history: older pages reach the first message with has_more false",
               last is not None and last.get("has_more") is False and pages == 5, f"pages={pages} last={str(last)[:200]}")
        ctx.ok("history: every message of the channel arrives once, oldest first",
               order == mids, f"{len(order)} of {len(mids)}")
        by_path["older"] = older

        # ---- a reply 200 back: the target is found in a window around it ------------
        target = data["reply_target"]
        win = await member.ask(around_id=target, limit=100, req="w")
        ctx.ok("history: a window around a message 200 back contains it",
               bool(win) and win["type"] == "history_around" and win["found"] is True
               and target in [m["id"] for m in win["messages"]] and win["has_newer"] is True, str(win)[:200])
        if win:
            by_path["around"] = {m["id"]: m for m in win["messages"]}
        reply_row = joined and by_path["join"].get(data["reply_id"])
        ctx.ok("history: the reply preview names the original it points at",
               bool(reply_row) and reply_row["reply_preview"]["id"] == target
               and reply_row["reply_preview"]["username"] != anon_name)
        gone = await member.ask(around_id=999999999)
        ctx.ok("history: an unknown message id is reported as not found",
               bool(gone) and gone["type"] == "history_around" and gone["found"] is False and gone["messages"] == [])

        # ---- the HTTP route gives the same messages ---------------------------------
        status, body, _ = await http_get(sessions["member"], big)
        ctx.ok("history: HTTP newest page", status == 200 and len(body["messages"]) == 50 and body["has_more"] is True)
        http, cursor = {m["id"]: m for m in body["messages"]}, body["messages"][0]["id"]
        for _ in range(10):
            status, body, _ = await http_get(sessions["member"], big, before_id=cursor)
            if status != 200:
                break
            http.update({m["id"]: m for m in body["messages"]})
            if not body["has_more"]:
                break
            cursor = body["messages"][0]["id"]
        status2, wbody, _ = await http_get(sessions["member"], big, around_id=target, limit=100)
        by_path["http"] = http
        if status2 == 200:
            by_path["http around"] = {m["id"]: m for m in wbody["messages"]}
        ctx.ok("history: HTTP pages cover the whole channel", sorted(http) == sorted(mids), f"{len(http)}")
        versions = {}
        for label, got in by_path.items():
            for mid, m in got.items():
                versions.setdefault(mid, set()).add(canon(m))
        differ = [mid for mid, v in versions.items() if len(v) > 1]
        ctx.ok("history: join, history_page and HTTP send identical message objects", not differ and len(versions) == len(mids),
               f"differ={differ[:3]}")

        # ---- anonymity: a member never learns who wrote an anonymous post ------------
        member_text = json.dumps(by_path, sort_keys=True)
        ctx.ok("history: a member never receives the anonymous author's name, avatar or nickname",
               not any(s in member_text for s in anon_secrets))
        leaks = [m["id"] for got in by_path.values() for m in got.values() if m.get("user_id") == anon_id]
        ctx.ok("history: a member never receives the anonymous author's account id", not leaks, str(leaks[:3]))
        anon_rows = [m for m in by_path["older"].values() if m.get("anonymous")]
        ctx.ok("history: anonymous posts on old pages are still shown as anonymous",
               len(anon_rows) >= 5 and all(m["username"] == "Anonymous" and m["user_id"] is None and m["role"] is None
                                           and m["avatar"] == {} and m["nickname"] is None for m in anon_rows))
        react = by_path["older"].get(mids[50], {}).get("reactions", [])
        ctx.ok("history: reactions keep their counts but drop anonymous reactors' ids",
               len(react) == 1 and react[0]["count"] == 3 and react[0]["user_ids"] == [ids["bob"]], str(react))
        poll_row = by_path["older"].get(mids[46], {})
        ctx.ok("history: an anonymous poll creator's id is removed", bool(poll_row.get("poll")) and poll_row["poll"]["user_id"] is None)
        ctx.ok("history: the edit marker of an anonymous post is kept without identity",
               bool(by_path["older"].get(mids[86], {}).get("edited_at")))
        # staff and the author still get the id
        mod = await connect(sessions["mod"])
        await mod.ws.send_json({"type": "join", "channel_id": big})
        await mod.wait("history")
        mod_page = await mod.ask(before_id=mids[60], limit=100, req=1)
        mod_row = {m["id"]: m for m in (mod_page or {}).get("messages", [])}.get(data["anon_post"])
        ctx.ok("history: a moderator still receives the id of an anonymous author",
               bool(mod_row) and mod_row["user_id"] == anon_id and mod_row["username"] == "Anonymous")
        st, mbody, _ = await http_get(sessions["anon"], big, before_id=mids[60], limit=100)
        own = {m["id"]: m for m in (mbody or {}).get("messages", [])}.get(data["anon_post"])
        ctx.ok("history: the anonymous author gets their own id back over HTTP",
               st == 200 and bool(own) and own["user_id"] == anon_id)

        # ---- nothing is marked as read by fetching pages ----------------------------
        await act(act="set_read", user=ids["member"], channel=big, value=1)
        await member.ask(before_id=mids[100], req="r1")
        await member.ask(around_id=mids[150], req="r2")
        await member.ask(req="r3")
        await http_get(sessions["member"], big, around_id=mids[150])
        pos = await act(act="read", user=ids["member"], channel=big)
        ctx.ok("history: fetching pages does not move the read position", bool(pos) and pos["read"] == 1, str(pos))

        # ---- access: removed member, outsider, banned member, bad requests ------------
        rm = await connect(sessions["rm"])
        await rm.ws.send_json({"type": "join", "channel_id": data["priv"]})
        rm_join = await rm.wait("history", "error")
        ctx.ok("history: a member of a private channel reads it", bool(rm_join) and rm_join["type"] == "history"
               and len(rm_join["messages"]) == 1)
        st, b, _ = await http_get(sessions["rm"], data["priv"])
        ctx.ok("history: ... and over HTTP", st == 200 and len(b["messages"]) == 1)
        removed = await act(act="remove", channel=data["priv"], user=ids["rm"])
        ctx.ok("history: member removed", bool(removed) and removed["done"] is True)
        err = await rm.ask(before_id=10 ** 9, req=7)
        ctx.ok("history: a removed member gets nothing from history_page",
               bool(err) and err["type"] == "history_error" and err["error_code"] == "not_found" and "messages" not in err
               and (pre + " members only") not in json.dumps(err))
        st, b, _ = await http_get(sessions["rm"], data["priv"])
        st_missing, b_missing, _ = await http_get(sessions["rm"], 2 ** 40)
        ctx.ok("history: ... and gets 404, identical to a channel that does not exist",
               st == 404 and (st, b) == (st_missing, b_missing), f"{st} {b} / {st_missing} {b_missing}")
        st, b, _ = await http_get(sessions["outsider"], data["priv"])
        ctx.ok("history: a non-member gets 404 for a private channel", st == 404 and b == {"error": "Channel not found"})

        banned = await connect(sessions["banned"])
        await banned.ws.send_json({"type": "join", "channel_id": data["room"]})
        bj = await banned.wait("history", "error")
        ctx.ok("history: a stream chat is readable before the ban", bool(bj) and bj["type"] == "history")
        ban = await act(act="ban", sid=data["sid"], user=ids["banned"], owner=ids["alice"])
        ctx.ok("history: member banned from the stream chat", bool(ban) and ban["done"] is True)
        err = await banned.ask(before_id=10 ** 9, req=8)
        ctx.ok("history: a banned member gets nothing from history_page",
               bool(err) and err["type"] == "history_error" and err["error_code"] == "not_found")
        st, b, _ = await http_get(sessions["banned"], data["room"])
        ctx.ok("history: ... and 404 over HTTP", st == 404)

        # ---- the chat of a stream that is not public; the thread route; no-store -------
        async def http_thread(sess, message_id):
            async with sess.get(f"{ctx.base_url}/api/chat/thread/{message_id}") as r:
                try:
                    body = await r.json()
                except Exception:
                    body = None
                return r.status, body, dict(r.headers)

        st, b, headers = await http_get(sessions["member"], big)
        ctx.ok("history: the messages route is not cacheable", st == 200 and headers.get("Cache-Control") == "private, no-store",
               headers.get("Cache-Control", ""))
        st, b, headers = await http_thread(sessions["member"], data["reply_id"])
        ctx.ok("history: the thread route answers with the chain, in the history's message shape, and is not cacheable",
               st == 200 and headers.get("Cache-Control") == "private, no-store"
               and [m["id"] for m in b["thread"]][-1] == data["reply_id"] and all("reactions" in m for m in b["thread"])
               and not any(sec in json.dumps(b) for sec in anon_secrets), f"{st} {str(b)[:200]}")
        st, b, _ = await http_thread(sessions["rm"], data["priv_msg"])
        st_missing, b_missing, headers = await http_thread(sessions["rm"], 2 ** 40)
        ctx.ok("history: the thread of a private channel the member was removed from is 404, identical to a missing message",
               st == 404 and (st, b) == (st_missing, b_missing) and headers.get("Cache-Control") == "private, no-store",
               f"{st} {b} / {st_missing} {b_missing}")
        st, b, _ = await http_thread(sessions["outsider"], data["priv_msg"])
        ctx.ok("history: ... and for a member who never belonged", st == 404, f"{st} {b}")
        st, b, _ = await http_thread(sessions["alice"], data["priv_msg"])
        ctx.ok("history: ... while a member of the channel reads it", st == 200 and b["thread"][0]["id"] == data["priv_msg"], f"{st}")
        st, b, _ = await http_thread(sessions["banned"], data["closed_msg"])
        ctx.ok("history: the thread route of a stream chat is readable while the stream is public", st == 200, f"{st}")

        closed_name = pre + "-closed"
        outs = await connect(sessions["outsider"])
        await outs.ws.send_json({"type": "join", "channel_id": data["closed"]})
        oj = await outs.wait("history", "error")
        ctx.ok("history: a member joins the chat of a public stream", bool(oj) and oj["type"] == "history", str(oj)[:150])
        shut = await act(act="set_public", sid=data["csid"], value=0)
        ctx.ok("history: the stream is made private", bool(shut) and shut["done"] is True)
        err = await outs.ask(before_id=10 ** 9, req=21)
        ctx.ok("history: the socket that joined earlier gets nothing more from history_page",
               bool(err) and err["type"] == "history_error" and err["error_code"] == "not_found" and "messages" not in err
               and (pre + " closed stream text") not in json.dumps(err), str(err)[:150])
        start = len(outs.events)
        text_sent = pre + " typed into the closed chat"
        await outs.ws.send_json({"type": "message", "channel": closed_name, "message": text_sent})
        refused = await outs.wait("error", "message", start=start)
        ctx.ok("history: ... and cannot send to it", bool(refused) and refused["type"] == "error"
               and refused["message"] == "Channel not found", str(refused)[:150])
        # reactions and new polls on the closed chat are refused too (the socket is still in the room)
        for what, payload in (("a reaction", {"type": "react", "message_id": data["closed_msg"], "emoji": "ok"}),
                              ("a new poll", {"type": "create_poll", "question": pre + " closed poll?", "options": ["a", "b"]})):
            start = len(outs.events)
            await outs.ws.send_json(payload)
            got = await outs.wait("error", "reaction_update", "poll_created", start=start)
            ctx.ok(f"history: ... and cannot add {what} to it",
                   bool(got) and got["type"] == "error" and got["message"] == "Channel not found", str(got)[:150])
        st, b, _ = await http_get(sessions["alice"], data["closed"])
        closed_msgs = b["messages"] if st == 200 and b else []
        ctx.ok("history: ... and neither was stored",
               st == 200 and not any(m["reactions"] for m in closed_msgs)
               and not any(m.get("poll") for m in closed_msgs) and (pre + " closed poll?") not in json.dumps(b), f"{st}")
        st, b, _ = await http_get(sessions["outsider"], data["closed"])
        st_missing, b_missing, _ = await http_get(sessions["outsider"], 2 ** 40)
        ctx.ok("history: HTTP answers 404, identical to a channel that does not exist",
               st == 404 and (st, b) == (st_missing, b_missing), f"{st} {b}")
        st, b, _ = await http_thread(sessions["outsider"], data["closed_msg"])
        ctx.ok("history: the thread route answers 404 for it", st == 404, f"{st} {b}")
        start = len(outs.events)
        await outs.ws.send_json({"type": "join", "channel_id": data["closed"]})
        rejoin = await outs.wait("history", "error", start=start)
        ctx.ok("history: joining it again is refused as a missing channel",
               bool(rejoin) and rejoin["type"] == "error" and rejoin["message"] == "Channel not found", str(rejoin)[:150])
        # a refused join leaves the member in no channel: what he types next is not
        # delivered to the room he had open before
        start = len(outs.events)
        await outs.ws.send_json({"type": "join", "channel_id": big})
        back = await outs.wait("history", "error", start=start)
        start = len(outs.events)
        await outs.ws.send_json({"type": "join", "channel_id": data["closed"]})
        refused_join = await outs.wait("history", "error", start=start)
        stray = pre + " meant for the closed chat"
        await outs.ws.send_json({"type": "message", "channel": closed_name, "message": stray})
        await outs.ws.send_json({"type": "react", "message_id": max(mids), "emoji": "zz"})
        late = await outs.ask(req=22)
        st, b, _ = await http_get(sessions["alice"], big)
        ctx.ok("history: a refused join leaves no channel behind, so the next send does not reach the room left before",
               bool(back) and back["type"] == "history" and bool(refused_join) and refused_join["type"] == "error" and refused_join["message"] == "Channel not found"
               and bool(late) and late["type"] == "history_error" and st == 200 and stray not in json.dumps(b)
               and not any(m["id"] == max(mids) and m["reactions"] and any(r["emoji"] == "zz" for r in m["reactions"])
                           for m in b["messages"]), str(late)[:150])
        st, b, _ = await http_get(sessions["alice"], data["closed"])
        ctx.ok("history: the stream owner still reads it, without the refused message",
               st == 200 and any(m["id"] == data["closed_msg"] for m in b["messages"]) and text_sent not in json.dumps(b), f"{st}")
        st, b, _ = await http_thread(sessions["alice"], data["closed_msg"])
        ctx.ok("history: ... and its thread", st == 200, f"{st}")


        async def search_hits(sess, text):
            async with sess.get(f"{ctx.base_url}/api/chat/search", params={"q": text, "scope": "channels"}) as r:
                try:
                    body = await r.json()
                except Exception:
                    body = None
                return r.status, body

        closed_text = pre + " closed stream text"
        st, b = await search_hits(sessions["outsider"], closed_text)
        ctx.ok("history: search does not return the text of a private stream's chat to another member",
               st == 200 and b["total"] == 0 and b["results"] == [], f"{st} {str(b)[:200]}")
        st, b = await search_hits(sessions["alice"], closed_text)
        ctx.ok("history: ... while search finds it for the stream owner",
               st == 200 and any(r["message"] == closed_text for r in b["results"]), f"{st} {str(b)[:200]}")
        if ctx.admin_password:
            admin = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
            if resp.status == 200:
                st, b, _ = await http_get(admin, data["closed"])
                ctx.ok("history: an admin reads the chat of a private stream", st == 200, f"{st}")
                st, b = await search_hits(admin, closed_text)
                ctx.ok("history: ... and search finds it for an admin",
                       st == 200 and any(r["message"] == closed_text for r in b["results"]), f"{st} {str(b)[:200]}")

        async with ctx.http() as anonymous_session:
            async with anonymous_session.get(f"{ctx.base_url}/api/chat/channels/{big}/messages") as r:
                ctx.ok("history: HTTP without a credential is refused", r.status in (401, 403, 302), f"status {r.status}")
        for params, label in (({"limit": "0"}, "limit 0"), ({"before_id": "x"}, "bad before_id"),
                              ({"before_id": "5", "around_id": "6"}, "both cursors")):
            st, b, _ = await http_get(sessions["member"], big, **params)
            ctx.ok(f"history: {label} is a 400", st == 400 and "error" in (b or {}), f"{st} {b}")
        for params, label in (({"before_id": str(2 ** 63)}, "before_id above 2**63-1"),
                              ({"around_id": "99999999999999999999"}, "around_id of 20 digits")):
            st, b, _ = await http_get(sessions["member"], big, **params)
            ctx.ok(f"history: {label} is a 400, not a 500", st == 400 and "error" in (b or {}), f"{st} {b}")
        st, b, _ = await http_get(sessions["member"], 99999999999999999999)
        ctx.ok("history: a channel id above 2**63-1 is a 404", st == 404, f"{st}")
        st, b, _ = await http_get(sessions["member"], big, limit=5000)
        ctx.ok("history: a page is capped at 100 messages", st == 200 and len(b["messages"]) == 100, f"{st}")
        err = await member.ask(before_id=10 ** 20, req=10)
        ctx.ok("history: an id too large for the database is an error reply, not a dropped socket",
               bool(err) and err["type"] == "history_error" and err["error_code"] == "invalid" and err["req"] == 10)
        again = await member.ask(before_id=mids[100], req=11)
        ctx.ok("history: ... and the same socket still answers", bool(again) and again["type"] == "history_older")
        err = await member.ask(before_id=5, around_id=6, req=9)
        ctx.ok("history: history_page with both cursors is an error with the request token",
               bool(err) and err["type"] == "history_error" and err["error_code"] == "invalid" and err["req"] == 9)

        # ---- rate limit: 30 a minute per user over all sockets and the route ----------
        lim_a, lim_b = await connect(sessions["limit"]), await connect(sessions["limit"])
        for s in (lim_a, lim_b):
            await s.ws.send_json({"type": "join", "channel_id": big})
            await s.wait("history")
        replies = []
        for i in range(30):
            replies.append(await (lim_a if i % 2 else lim_b).ask(req=i))
        ctx.ok("history: 30 requests in a minute are answered, over two sockets",
               all(r and r["type"] == "history_around" for r in replies), str([r and r["type"] for r in replies][:5]))
        limited = await lim_a.ask(req="31")
        ctx.ok("history: the 31st request on either socket is rate limited",
               bool(limited) and limited["type"] == "history_error" and limited["error_code"] == "rate_limited"
               and limited.get("retry_after", 0) >= 1 and limited["req"] == "31")
        st, b, headers = await http_get(sessions["limit"], big)
        ctx.ok("history: the HTTP route shares that budget (429 with Retry-After)",
               st == 429 and int(headers.get("Retry-After", "0")) >= 1)
        st, b, _ = await http_get(sessions["member"], big)
        ctx.ok("history: another member is not affected", st == 200)

        # ---- the page ships the client code -----------------------------------------
        async with sessions["member"].get(f"{ctx.base_url}/static/js/portal.js", params={"v": "45"}) as r:
            text = await r.text()
            ctx.ok("history: portal.js jumps to a message from a notification",
                   r.status == 200 and "chatJumpToMessage" in text)
        async with sessions["member"].get(f"{ctx.base_url}/chat") as r:
            text = await r.text()
            ctx.ok("history: the chat page has the scrollback client",
                   r.status == 200 and "history_page" in text and "history-jump-btn" in text)
            ctx.ok("history: the chat page keeps buffered messages current and follows a send and a jump",
                   all(n in text for n in ("bufferApplyEdit(data)", "bufferApplyReaction(data)", "bufferApplyPoll(poll)",
                                           "jumpToPresentAfterSend()", "markNewestPageRead(data.messages)")))
