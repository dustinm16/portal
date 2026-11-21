"""Smoke check for the "leaks" fixes: anonymous author search and live
payloads, WebRTC session proxy authorisation, secret redaction in log files.

(The redaction patterns themselves are unit-tested in tests/test_log_redaction.py;
the check here proves real requests to a running instance end up redacted.)
"""

import asyncio
import json
import secrets
from contextlib import AsyncExitStack

PW = "Leaks-check-pw-1"
STATUS_TEXT = "back Monday - dentist"  # alice's status message: must not reach members while she is anonymous
NICK = "Zorbaleak"  # alice's nickname: must not show up on her anonymous post
WORD = "zebrafinch"  # distinctive search word used in both messages

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        await body()
    finally:
        await db.close()

async def body():
    out = {}
    for name in ("leakalice", "leakbob", "leakmod", "leakowner", "leaktoggle", "leakcarol"):
        u = await db.get_user_by_username(name)
        out[name] = u["id"] if u else await db.create_user(name, hash_password(%(pw)r))
    await db.set_user_role(out["leakmod"], "moderator")
    # legacy account: admin flag set, no role value
    lg = await db.get_user_by_username("leaklegacy")
    out["leaklegacy"] = lg["id"] if lg else await db.create_user("leaklegacy", hash_password(%(pw)r), is_admin=True)
    await db.conn.execute("UPDATE users SET role = NULL WHERE id = ?", (out["leaklegacy"],))
    await db.conn.commit()
    cur = await db.conn.execute("SELECT id FROM chat_channels WHERE name = 'general'")
    ch = (await cur.fetchone())["id"]
    out["channel"] = ch
    a = out["leakalice"]
    await db.set_user_nickname(a, "%(nick)s")
    await db.set_chat_anonymous(a, True)
    await db.set_user_status(a, "busy", "%(status)s")
    # a stream owned by leakowner (plain user role) with its own chat channel
    owner = out["leakowner"]
    sid = await db.create_user_stream(owner, "leakownerstream", "live_LeakOwnerKey1" + "x" * 8, public_key="pub_LeakOwnerKey1" + "x" * 8,
                                    is_public=True)   # a non-public stream's chat is closed to other members
    sch = await db.create_chat_channel("leakownerchat", "stream chat", owner)
    await db.update_user_stream(sid, chat_channel_id=sch)
    out["stream_channel"] = sch
    out["anon_id"] = await db.create_chat_message(ch, a, "leakalice", "%(w)s anon post", anonymous=True)
    out["norm_id"] = await db.create_chat_message(ch, a, "leakalice", "%(w)s normal post", anonymous=False)
    await db.pin_message(out["anon_id"], out["leakbob"])
    # reactions on the anonymous post: by the author (anonymous) and by a member
    await db.toggle_reaction(out["anon_id"], a, "+1")
    await db.toggle_reaction(out["anon_id"], out["leakcarol"], "+1")
    await db.toggle_reaction(out["anon_id"], out["leakbob"], "+1")
    print("RESULT " + json.dumps(out))

asyncio.run(main())
''' % {"pw": PW, "w": WORD, "nick": NICK, "status": STATUS_TEXT}

SESSIONS = r'''
import asyncio, json, secrets
from database import db
import server

async def main():
    await db.connect()
    try:
        await body()
    finally:
        await db.close()

async def body():
    u = await db.get_user_by_username("leakalice")
    other = await db.get_user_by_username("leakbob")
    sfx = secrets.token_hex(4)
    live, pub = "live_LeakCheckPublishKey1" + sfx, "pub_LeakCheckPlayKey1" + sfx
    live2, pub2 = "live_LeakCheckPublishKey2" + sfx, "pub_LeakCheckPlayKey2" + sfx
    sid = await db.create_user_stream(u["id"], "leakcheck", live, public_key=pub)
    sid2 = await db.create_user_stream(other["id"], "leakcheck2", live2, public_key=pub2)
    server._webrtc_session_remember("sess-whip", "whip", sid, live)
    server._webrtc_session_remember("sess-whep", "whep", sid, live)
    res = {}
    import auth
    from aiohttp.test_utils import make_mocked_request
    from config import Config

    class Transport:
        def get_extra_info(self, name, default=None):
            return ("203.0.113.9", 5555) if name == "peername" else default

    # a playback session is authorised like playback itself: leakalice owns the stream
    alice_jwt, _ = await auth.create_access_token(u["id"], ["services:read", "access:*"])

    def rq(path, key, session=None, method="GET"):
        mi = {"stream_key": key}
        if session:
            mi["session_id"] = session
        return make_mocked_request(method, path, match_info=mi, transport=Transport(),
                                   headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={alice_jwt}"})

    for label, key, session in (
        ("whip_with_pub", pub, "sess-whip"),
        ("whip_with_live", live, "sess-whip"),
        ("whep_with_pub", pub, "sess-whep"),
        ("whep_with_live", live, "sess-whep"),
        ("unknown_with_live", live, "sess-nope"),
        ("whip_other_stream_pub", pub2, "sess-whip"),
        ("whip_other_stream_live", live2, "sess-whip"),
        ("bad_key", "pub_notakey", "sess-whep"),
    ):
        rec, err, status, _s = await server._authorize_webrtc_session(rq("/x", key, session), key, session)
        res[label] = {"status": status, "kind": rec[0] if rec else None, "path": rec[2] if rec else None}
    res["live_key"] = live
    res["pub_key"] = pub

    # Flooding playback sessions (per stream, then across streams up to the
    # global limit) must not evict the publisher's record.
    for i in range(server._WEBRTC_SESSION_MAX + 50):
        server._webrtc_session_remember("flood-a-%d" % i, "whep", sid, live)
    res["whep_per_stream"] = sum(1 for v in server._webrtc_sessions.values() if v[0] == "whep" and v[1] == sid)
    for i in range(server._WEBRTC_SESSION_MAX + 50):
        server._webrtc_session_remember("flood-b-%d" % i, "whep", 100000 + i, live2)
    res["table_size"] = len(server._webrtc_sessions)
    rec, err, status, _s = await server._authorize_webrtc_session(rq("/x", live), live, "sess-whip")
    res["whip_after_flood"] = {"status": status, "kind": rec[0] if rec else None}
    rec, err, status, _s = await server._authorize_webrtc_session(rq("/x", pub), pub, "sess-whip")
    res["whip_pub_after_flood"] = {"status": status, "kind": None}

    # The session handler must build the MediaMTX URL from the recorded type.
    from aiohttp.test_utils import make_mocked_request
    seen = []

    class FakeResp:
        status = 204
        content_type = "application/json"
        async def read(self):
            return b""
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    def fake_request(self, method, url, **kw):
        seen.append((method, url))
        return FakeResp()

    async def fake_cfg():
        return {"webrtc_port": 8889}

    server._get_mediamtx_config = fake_cfg
    server.aiohttp.ClientSession.request = fake_request
    server._webrtc_session_remember("sess-url-whip", "whip", sid, live)
    server._webrtc_session_remember("sess-url-whep", "whep", sid, live)
    for sess, key in (("sess-url-whip", live), ("sess-url-whep", pub), ("sess-url-whip", pub)):
        req = rq("/api/stream/%s/webrtc/session/%s" % (key, sess), key, sess, "PATCH")
        resp = await server.http_stream_webrtc_session(req)
        res.setdefault("handler", []).append({"status": resp.status})
    res["urls"] = [u for _, u in seen]
    print("RESULT " + json.dumps(res))

asyncio.run(main())
'''


REACTION_EMOJI = "+1"


def _reactor_ids(msgs):
    out = []
    for m in msgs:
        for r in m.get("reactions", []):
            if r.get("emoji") == REACTION_EMOJI:
                out.append((r.get("count"), sorted(r.get("user_ids", []))))
    return out


async def _anon_payloads(ctx, s, data):
    """Fetch the anonymous message through the thread endpoint and over the chat
    websocket (history and pinned list) as the logged-in user of session s."""
    out = {}
    async with s.get(f"{ctx.base_url}/api/chat/thread/{data['anon_id']}") as r:
        body = await r.json()
        out["thread"] = [m for m in body.get("thread", []) if m.get("id") == data["anon_id"]]
    hist, pinned = [], []
    async with s.ws_connect(f"{ctx.base_url}/ws/chat") as ws:
        await ws.send_json({"type": "join", "channel_id": data["channel"]})
        try:
            async with asyncio.timeout(10):
                while not (hist and pinned):
                    msg = await ws.receive_json()
                    if msg.get("type") == "history":
                        hist = [m for m in msg["messages"] if m.get("id") == data["anon_id"]]
                    elif msg.get("type") == "pinned_messages":
                        pinned = [m for m in msg["messages"] if m.get("id") == data["anon_id"]]
        except (asyncio.TimeoutError, TimeoutError):
            pass
    out["history"], out["pinned"] = hist, pinned
    return out


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    data = await _main(ctx)
    if data is not None:
        await _live_payloads(ctx, data)
        await _stream_owner_payloads(ctx, data)
        await _ban_after_switch_off(ctx, data)
        await _masked_ban_records(ctx, data)
        ctx.ok("leaks: the opaque handle of an anonymous user differs between channels",
               bool(data.get("general_ref")) and bool(data.get("stream_ref"))
               and data["general_ref"] != data["stream_ref"],
               json.dumps([data.get("general_ref"), data.get("stream_ref")]))
        await _voice_payloads(ctx, data)
    await _log_redaction(ctx)


async def _main(ctx):
    # ---- anonymous author filter -------------------------------------
    rc, out = await ctx.run_py(SETUP)
    data = _result(out)
    ctx.ok("leaks: setup users and messages", rc == 0 and data is not None, out[-300:] if data is None else "")
    if data is None:
        return None

    async with ctx.http() as s:
        resp = await ctx.login(s, "leakbob", PW)
        ctx.ok("leaks: second user can log in", resp.status == 200, f"status {resp.status}")
        if resp.status != 200:
            return None

        async def search(**params):
            async with s.get(f"{ctx.base_url}/api/chat/search", params={"q": WORD, **params}) as r:
                return r.status, await r.json()

        # Author filter must return only the non-anonymous message
        st, body = await search(**{"from": "leakalice"})
        ids = [r.get("id") for r in body.get("results", [])]
        ctx.ok("leaks: from: filter returns the normal message",
               st == 200 and data["norm_id"] in ids, f"ids={ids}")
        ctx.ok("leaks: from: filter omits the anonymous message",
               st == 200 and data["anon_id"] not in ids, f"ids={ids}")
        ctx.ok("leaks: from: total matches the visible results",
               body.get("total") == len(ids), f"total={body.get('total')} ids={ids}")

        # Plain search: anonymous hit exists but must not reveal the author
        st, body = await search()
        by_id = {r.get("id"): r for r in body.get("results", [])}
        anon = by_id.get(data["anon_id"])
        ctx.ok("leaks: plain search still finds the anonymous message", anon is not None, f"ids={list(by_id)}")
        if anon is not None:
            blob = json.dumps(anon)
            ctx.ok("leaks: anonymous result has no real username or user id",
                   "leakalice" not in blob and anon.get("user_id") != data["leakalice"]
                   and anon.get("username") == "Anonymous", blob)
        norm = by_id.get(data["norm_id"])
        ctx.ok("leaks: normal result keeps its author",
               norm is not None and norm.get("username") == "leakalice", json.dumps(norm))

    # ---- anonymous author in thread / history / pinned payloads ---------
    async with ctx.http() as s:
        resp = await ctx.login(s, "leakbob", PW)
        other = await _anon_payloads(ctx, s, data) if resp.status == 200 else {}
    for kind in ("thread", "history", "pinned"):
        msgs = other.get(kind) or []
        blob = json.dumps(msgs)
        ctx.ok(f"leaks: {kind} payload of an anonymous post hides the author from other users",
               len(msgs) == 1 and msgs[0].get("user_id") is None and msgs[0].get("username") == "Anonymous"
               and not msgs[0].get("role") and not msgs[0].get("nickname")
               and "author_nickname" not in msgs[0] and "author_role" not in msgs[0]
               and "leakalice" not in blob and NICK not in blob,
               blob)
    async with ctx.http() as s:
        resp = await ctx.login(s, "leakalice", PW)
        own = await _anon_payloads(ctx, s, data) if resp.status == 200 else {}
    for kind in ("thread", "history", "pinned"):
        msgs = own.get(kind) or []
        ctx.ok(f"leaks: {kind} payload keeps the author's own id for the author",
               len(msgs) == 1 and msgs[0].get("user_id") == data["leakalice"], json.dumps(msgs))
    async with ctx.http() as s:
        resp = await ctx.login(s, "leakmod", PW)
        staff = await _anon_payloads(ctx, s, data) if resp.status == 200 else {}
    for kind in ("thread", "history", "pinned"):
        msgs = staff.get(kind) or []
        ctx.ok(f"leaks: {kind} payload keeps the author's id for a moderator, still named Anonymous",
               len(msgs) == 1 and msgs[0].get("user_id") == data["leakalice"]
               and msgs[0].get("username") == "Anonymous" and not msgs[0].get("nickname"),
               json.dumps(msgs))

    # ---- reactor ids in history -----------------------------------------
    alice, bob, carol = data["leakalice"], data["leakbob"], data["leakcarol"]
    ctx.ok("leaks: history reactions keep the count but drop the id of an anonymous reactor for a member",
           _reactor_ids(other.get("history", [])) == [(3, sorted([carol, bob]))],
           json.dumps(_reactor_ids(other.get("history", []))))
    ctx.ok("leaks: history reactions keep the viewer's own id",
           bob in (_reactor_ids(other.get("history", [])) or [(0, [])])[0][1], "")
    ctx.ok("leaks: history reactions list the anonymous reactor's own id for that reactor",
           _reactor_ids(own.get("history", [])) == [(3, sorted([alice, carol, bob]))],
           json.dumps(_reactor_ids(own.get("history", []))))
    ctx.ok("leaks: history reactions keep every id for a moderator",
           _reactor_ids(staff.get("history", [])) == [(3, sorted([alice, carol, bob]))],
           json.dumps(_reactor_ids(staff.get("history", []))))

    # ---- thread endpoint honours the legacy admin flag --------------------
    async with ctx.http() as s:
        resp = await ctx.login(s, "leaklegacy", PW)
        legacy = await _anon_payloads(ctx, s, data) if resp.status == 200 else {}
    msgs = legacy.get("thread") or []
    ctx.ok("leaks: thread payload treats a legacy admin-flag account as staff, like the websocket path",
           len(msgs) == 1 and msgs[0].get("user_id") == alice
           and (legacy.get("history") or [{}])[0].get("user_id") == alice, json.dumps([msgs, legacy.get("history")]))

    # ---- anonymous toggle is rate limited -------------------------------
    async with ctx.http() as s:
        resp = await ctx.login(s, "leaktoggle", PW)
        codes = []
        if resp.status == 200:
            for i in range(8):
                async with s.put(f"{ctx.base_url}/api/me/anonymous", json={"anonymous": bool(i % 2 == 0)}) as r:
                    codes.append(r.status)
    ctx.ok("leaks: anonymous toggle allows a few changes then answers 429",
           codes[:5] == [200] * 5 and codes[5:] == [429] * 3, str(codes))

    # ---- WebRTC session proxy: authorisation / routing -----------------
    # The session record lives in the server process, so the routing and
    # authorisation function is exercised directly through run_py, not over
    # HTTP (a publishing session cannot be opened without MediaMTX).
    rc, out = await ctx.run_py(SESSIONS)
    res = _result(out)
    ctx.ok("leaks: session authorisation snippet ran", rc == 0 and res is not None, out[-400:] if res is None else "")
    if res is None:
        return data
    ctx.ok("leaks: playback key refused on a publishing session, same answer as an unknown session",
           res["whip_with_pub"]["status"] == 404 and res["whip_other_stream_pub"]["status"] == 404
           and res["unknown_with_live"]["status"] == 404, json.dumps(res["whip_with_pub"]))
    ctx.ok("leaks: playback sessions are capped per stream",
           res["whep_per_stream"] <= 64, f"whep records for one stream: {res['whep_per_stream']}")
    ctx.ok("leaks: playback flood stays within the global limit",
           res["table_size"] <= 4096, f"table size {res['table_size']}")
    ctx.ok("leaks: publisher session survives a playback flood, playback key still refused",
           res["whip_after_flood"]["status"] == 200 and res["whip_pub_after_flood"]["status"] == 404,
           json.dumps([res["whip_after_flood"], res["whip_pub_after_flood"]]))
    live_k = res["live_key"]
    ctx.ok("leaks: session handler builds the MediaMTX URL from the recorded session type",
           res["urls"] == [f"http://127.0.0.1:8889/{live_k}/whip/sess-url-whip",
                           f"http://127.0.0.1:8889/{live_k}/whep/sess-url-whep"]
           and [h["status"] for h in res["handler"]] == [204, 204, 404],
           json.dumps([res["urls"], res["handler"]]))
    ctx.ok("leaks: publish key accepted on a publishing session, routed as whip",
           res["whip_with_live"]["status"] == 200 and res["whip_with_live"]["kind"] == "whip",
           json.dumps(res["whip_with_live"]))
    ctx.ok("leaks: playback key still works on a playback session, routed as whep",
           res["whep_with_pub"]["status"] == 200 and res["whep_with_pub"]["kind"] == "whep"
           and res["whep_with_pub"]["path"] == res["live_key"], json.dumps(res["whep_with_pub"]))
    ctx.ok("leaks: unknown session refused", res["unknown_with_live"]["status"] == 404,
           json.dumps(res["unknown_with_live"]))
    ctx.ok("leaks: another stream's keys cannot touch the session",
           res["whip_other_stream_pub"]["status"] == 404 and res["whip_other_stream_live"]["status"] == 404,
           json.dumps([res["whip_other_stream_pub"], res["whip_other_stream_live"]]))
    ctx.ok("leaks: invalid key refused (the same 404 as a missing stream)", res["bad_key"]["status"] == 404, json.dumps(res["bad_key"]))

    # ---- WebRTC session proxy: real HTTP route --------------------------
    async with ctx.http() as s:
        base = f"{ctx.base_url}/api/stream"
        async with s.delete(f"{base}/{res['pub_key']}/webrtc/session/no-such-session") as r:
            ctx.ok("leaks: DELETE with a playback key on an unknown session is refused over HTTP",
                   r.status in (403, 404), f"status {r.status}")
        async with s.delete(f"{base}/pub_notakey/webrtc/session/x") as r:
            ctx.ok("leaks: DELETE with an invalid key is 404 over HTTP", r.status == 404, f"status {r.status}")
    return data


# ---- live websocket payloads ---------------------------------------------

async def _pump(ws, events):
    try:
        async for msg in ws:
            if msg.type == 1:  # aiohttp.WSMsgType.TEXT
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
        await asyncio.sleep(0.05)
    return None


def _has_value(node, key, value):
    """True if any dict inside node has node[key] == value."""
    if isinstance(node, dict):
        return any((k == key and v == value) or _has_value(v, key, value) for k, v in node.items())
    if isinstance(node, list):
        return any(_has_value(v, key, value) for v in node)
    return False


async def _live_payloads(ctx, data):
    """Three accounts in one channel: an ordinary member, a moderator and the
    author, who posts in anonymous mode. The live events must hide the author's
    id from the member and keep it for the moderator and the author."""
    alice = data["leakalice"]
    text = "live anon " + secrets.token_hex(4)
    ev = {}
    marks = {}
    async with AsyncExitStack() as stack:
        sockets, sessions = {}, {}
        for name in ("leakbob", "leakmod", "leakalice"):
            if name == "leakalice":
                for who in ("leakbob", "leakmod"):
                    marks[who] = len(ev[who])
            sess = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess, name, PW)
            if resp.status != 200:
                ctx.ok("leaks: live: %s can log in" % name, False, f"status {resp.status}")
                return
            sessions[name] = sess
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat"))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws, ev[name]))
            stack.callback(pump.cancel)
            await ws.send_json({"type": "join", "channel_id": data["channel"]})
            got = await _wait_for(ev[name], lambda e: e.get("type") == "users")
            if got is None:
                ctx.ok("leaks: live: %s joined the channel" % name, False, "no users list")
                return
            sockets[name] = ws
        # alice's join reaches the others, then she posts and a moderator acts on her
        await _wait_for(ev["leakbob"], lambda e: e.get("type") == "users" and any(
            u.get("anonymous") for u in e.get("users", [])), start=marks["leakbob"])
        await sockets["leakalice"].send_json({"type": "message", "message": text})
        for name in ("leakbob", "leakmod", "leakalice"):
            await _wait_for(ev[name], lambda e: e.get("type") == "message" and e.get("message") == text)
        own = await _wait_for(ev["leakalice"], lambda e: e.get("type") == "message" and e.get("message") == text)
        await sockets["leakalice"].send_json({"type": "react", "message_id": own.get("id"), "emoji": "+1"})
        for name in ("leakbob", "leakmod", "leakalice"):
            await _wait_for(ev[name], lambda e: e.get("type") == "reaction_update")
        # a new status text while anonymous must not reach members either
        async with sessions["leakalice"].put(f"{ctx.base_url}/api/me/status",
                                             json={"status": "dnd", "status_message": STATUS_TEXT + " 2"}) as r:
            status_code = r.status
        for name in ("leakbob", "leakmod", "leakalice"):
            await _wait_for(ev[name], lambda e: e.get("type") == "user_status_changed")
        await sockets["leakalice"].send_json({"type": "delete", "message_id": own.get("id")})
        for name in ("leakbob", "leakmod", "leakalice"):
            await _wait_for(ev[name], lambda e: e.get("type") == "message_deleted")
        await sockets["leakmod"].send_json({"type": "timeout_user", "target_user_id": alice,
                                            "duration": 1, "reason": "smoke"})
        for name in ("leakbob", "leakmod", "leakalice"):
            await _wait_for(ev[name], lambda e: e.get("type") == "user_timed_out")
        await sockets["leakalice"].close()
        await _wait_for(ev["leakbob"], lambda e: e.get("type") == "user_left" and e.get("user_id") in (None, alice),
                        start=marks["leakbob"])
        await _wait_for(ev["leakmod"], lambda e: e.get("type") == "user_left" and e.get("user_id") in (None, alice),
                        start=marks["leakmod"])

    def first(name, etype, **kw):
        for e in ev[name][marks.get(name, 0):]:
            if e.get("type") == etype and all(e.get(k) == v for k, v in kw.items()):
                return e
        return None

    seen = ev["leakbob"][marks["leakbob"]:]
    blob = json.dumps(seen)
    ctx.ok("leaks: live: events about an anonymous author never carry the author's id or name to a member",
           bool(seen) and not _has_value(seen, "user_id", alice) and "leakalice" not in blob and NICK not in blob,
           blob[:600])
    ctx.ok("leaks: live: status text of an anonymous user never reaches a member",
           status_code == 200 and "dentist" not in blob, blob[:600])
    rb, rm = first("leakbob", "reaction_update"), first("leakmod", "reaction_update")
    ctx.ok("leaks: live: reaction by an anonymous user hides the reactor's id from a member, not from a moderator",
           rb is not None and rb.get("user_id") is None and rm is not None and rm.get("user_id") == alice,
           json.dumps([rb, rm]))
    sb, sm = first("leakbob", "user_status_changed", username="Anonymous"), first("leakmod", "user_status_changed", user_id=alice)
    ctx.ok("leaks: live: status change of an anonymous user carries no status text or id to a member",
           sb is not None and sb.get("user_id") is None and sb.get("status_message") is None
           and sb.get("status") == "online"
           and sm is not None and sm.get("user_id") == alice and sm.get("status_message") == STATUS_TEXT + " 2"
           and sm.get("status") == "dnd",
           json.dumps([sb, sm]))
    msg_bob = first("leakbob", "message", message=text)
    ctx.ok("leaks: live: new anonymous message reaches a member without author id or role",
           msg_bob is not None and msg_bob.get("user_id") is None and not msg_bob.get("role")
           and msg_bob.get("username") == "Anonymous" and not msg_bob.get("nickname"), json.dumps(msg_bob))
    msg_mod = first("leakmod", "message", message=text)
    ctx.ok("leaks: live: new anonymous message reaches a moderator with the author id, named Anonymous",
           msg_mod is not None and msg_mod.get("user_id") == alice and msg_mod.get("username") == "Anonymous",
           json.dumps(msg_mod))
    msg_own = first("leakalice", "message", message=text)
    ctx.ok("leaks: live: the author receives their own id on the new message",
           msg_own is not None and msg_own.get("user_id") == alice, json.dumps(msg_own))

    def anon_entry(name):
        for e in reversed(ev[name]):
            if e.get("type") == "users":
                for u in e.get("users", []):
                    if u.get("anonymous"):
                        return u
        return None

    ub = anon_entry("leakbob")
    data["general_ref"] = (ub or {}).get("anon_ref")
    ctx.ok("leaks: live: member's online list shows the anonymous user without id, role, nickname or avatar",
           ub is not None and ub.get("user_id") is None and ub.get("role") is None and not ub.get("nickname")
           and not ub.get("avatar") and ub.get("username") == "Anonymous" and ub.get("anon_ref"), json.dumps(ub))
    ctx.ok("leaks: live: member's online list shows no status text or last-seen time for the anonymous user",
           ub is not None and not ub.get("status_message") and not ub.get("last_seen_at"), json.dumps(ub))
    um = anon_entry("leakmod")
    ctx.ok("leaks: live: moderator's online list keeps the anonymous user's id",
           um is not None and um.get("user_id") == alice and um.get("username") == "Anonymous"
           and not um.get("nickname"), json.dumps(um))
    jb = first("leakbob", "user_joined")
    ctx.ok("leaks: live: join notice for an anonymous user hides the id from a member",
           jb is not None and jb.get("user_id") is None and jb.get("username") == "Anonymous", json.dumps(jb))
    jm = first("leakmod", "user_joined")
    ctx.ok("leaks: live: join notice for an anonymous user keeps the id for a moderator",
           jm is not None and jm.get("user_id") == alice, json.dumps(jm))
    tb = first("leakbob", "user_timed_out")
    tm = first("leakmod", "user_timed_out")
    ctx.ok("leaks: live: moderation notice about an anonymous user hides name and id from a member",
           tb is not None and tb.get("user_id") is None and tb.get("username") == "Anonymous"
           and tm is not None and tm.get("user_id") == alice, json.dumps([tb, tm]))
    db_ = first("leakbob", "message_deleted")
    dm_ = first("leakmod", "message_deleted")
    da_ = first("leakalice", "message_deleted")
    ctx.ok("leaks: live: delete notice for an anonymous message hides who deleted it from a member",
           db_ is not None and db_.get("deleted_by") is None and db_.get("message_id") == msg_own.get("id"),
           json.dumps(db_))
    ctx.ok("leaks: live: delete notice keeps the id for a moderator and for the author",
           dm_ is not None and dm_.get("deleted_by") == alice and da_ is not None and da_.get("deleted_by") == alice,
           json.dumps([dm_, da_]))
    lb = first("leakbob", "user_left")
    ctx.ok("leaks: live: leave notice for an anonymous user hides the id from a member",
           lb is not None and lb.get("user_id") is None, json.dumps(lb))


async def _stream_owner_payloads(ctx, data):
    """In a stream's own chat the owner (plain user role) is an ordinary member:
    no id of an anonymous author reaches them. Their ban of that author goes
    through the message id, and nothing in the answers names the author."""
    alice, owner = data["leakalice"], data["leakowner"]
    text = "owner anon " + secrets.token_hex(4)
    ev = {}
    async with AsyncExitStack() as stack:
        sockets = {}
        for name in ("leakbob", "leakowner", "leakalice"):
            sess = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess, name, PW)
            if resp.status != 200:
                ctx.ok("leaks: stream owner: %s can log in" % name, False, f"status {resp.status}")
                return
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat"))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws, ev[name]))
            stack.callback(pump.cancel)
            await ws.send_json({"type": "join", "channel_id": data["stream_channel"]})
            if await _wait_for(ev[name], lambda e: e.get("type") == "users") is None:
                ctx.ok("leaks: stream owner: %s joined the stream chat" % name, False, "no users list")
                return
            sockets[name] = ws
        await _wait_for(ev["leakowner"], lambda e: e.get("type") == "users" and any(
            u.get("anonymous") for u in e.get("users", [])), start=0)
        await sockets["leakalice"].send_json({"type": "message", "message": text})
        for name in ("leakbob", "leakowner"):
            await _wait_for(ev[name], lambda e: e.get("type") == "message" and e.get("message") == text)
        mo = next((e for e in ev["leakowner"] if e.get("type") == "message" and e.get("message") == text), None)
        msg_id = (mo or {}).get("id")

        # a member who does not own the stream cannot ban through a message id
        await sockets["leakbob"].send_json({"type": "ban", "message_id": msg_id})
        denied = await _wait_for(ev["leakbob"], lambda e: e.get("type") in ("ban_success", "error")
                                 and e.get("message") != "You are banned from this stream's chat")
        # a message of another channel is refused, even for the owner
        await sockets["leakowner"].send_json({"type": "ban", "message_id": data["anon_id"]})
        foreign = await _wait_for(ev["leakowner"], lambda e: e.get("type") in ("ban_success", "error"))
        mark = len(ev["leakowner"])

        await sockets["leakowner"].send_json({"type": "ban", "message_id": msg_id, "reason": "smoke"})
        banned = await _wait_for(ev["leakowner"], lambda e: e.get("type") == "ban_success", start=mark)
        for name in ("leakbob", "leakowner"):
            await _wait_for(ev[name], lambda e: e.get("type") == "user_banned")

    def find(name, etype, **kw):
        for e in ev[name]:
            if e.get("type") == etype and all(e.get(k) == v for k, v in kw.items()):
                return e
        return None

    mb = find("leakbob", "message", message=text)
    ctx.ok("leaks: stream owner: gets no author id or real name on an anonymous message, like any member",
           mo is not None and mo.get("user_id") is None and mo.get("username") == "Anonymous"
           and not mo.get("nickname") and not mo.get("role") and "leakalice" not in json.dumps(mo),
           json.dumps(mo))
    ctx.ok("leaks: stream owner: another member gets no id on that message either",
           mb is not None and mb.get("user_id") is None, json.dumps(mb))
    owner_blob = json.dumps([e for e in ev["leakowner"] if e.get("type") in ("users", "message", "user_joined")])
    ctx.ok("leaks: stream owner: the online list and join notices carry no id or real name of the anonymous user",
           not _has_value(json.loads(owner_blob), "user_id", alice) and "leakalice" not in owner_blob, owner_blob[:500])
    ctx.ok("leaks: stream owner: a non-owner member cannot ban by message id",
           denied is not None and denied.get("type") == "error", json.dumps(denied))
    ctx.ok("leaks: stream owner: a message from another channel is refused",
           foreign is not None and foreign.get("type") == "error", json.dumps(foreign))
    ctx.ok("leaks: stream owner: ban by message id succeeds without naming the author",
           banned is not None and banned.get("user_id") is None and banned.get("username") == "Anonymous"
           and "leakalice" not in json.dumps(banned), json.dumps(banned))
    ub = find("leakowner", "user_banned")
    ubb = find("leakbob", "user_banned")
    ctx.ok("leaks: stream owner: ban notice to the owner and to members hides the author",
           ub is not None and ub.get("user_id") is None and ub.get("username") == "Anonymous"
           and ubb is not None and ubb.get("user_id") is None and ubb.get("username") == "Anonymous",
           json.dumps([ub, ubb]))
    rc, out = await ctx.run_py(CHECK_BAN % {"alice": alice, "stream": "leakownerstream"})
    res = _result(out) or {}
    ctx.ok("leaks: stream owner: the author is banned from the stream chat afterwards",
           res.get("banned") is True and res.get("only_one") is True, out[-300:])
    ctx.ok("leaks: stream owner: the ban does not reach the author in other streams",
           res.get("other_channel_banned") is False, out[-300:])
    # The banned author is put out of the room by the ban, so the newest list may no longer hold
    # the anonymous entry: take the handle from the newest list that still does.
    ref_b = None
    for e in reversed(ev["leakbob"]):
        if e.get("type") == "users":
            ref_b = next((u.get("anon_ref") for u in e.get("users", []) if u.get("anonymous")), None)
            if ref_b:
                break
    data["stream_ref"] = ref_b
    last_users = next((e for e in reversed(ev["leakbob"]) if e.get("type") == "users"), {"users": []})
    flags = [bool(u.get("anonymous")) for u in last_users["users"]]
    ctx.ok("leaks: member's online list puts anonymous entries after the named ones",
           bool(flags) and flags == sorted(flags), json.dumps(flags))


async def _ban_after_switch_off(ctx, data):
    """An anonymous post stays anonymous for ban purposes even after its author
    has switched anonymous mode off: the owner's ban by message id must not
    name the author."""
    carol = data["leakcarol"]
    text = "switched off " + secrets.token_hex(4)
    ev = {}
    async with AsyncExitStack() as stack:
        sockets, sessions = {}, {}
        for name in ("leakbob", "leakowner", "leakcarol"):
            sess = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess, name, PW)
            if resp.status != 200:
                ctx.ok("leaks: switched-off ban: %s can log in" % name, False, f"status {resp.status}")
                return
            sessions[name] = sess
            if name == "leakcarol":
                async with sess.put(f"{ctx.base_url}/api/me/anonymous", json={"anonymous": True}) as r:
                    if r.status != 200:
                        ctx.ok("leaks: switched-off ban: author can switch anonymous mode on", False, f"status {r.status}")
                        return
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat"))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws, ev[name]))
            stack.callback(pump.cancel)
            await ws.send_json({"type": "join", "channel_id": data["stream_channel"]})
            if await _wait_for(ev[name], lambda e: e.get("type") == "users") is None:
                ctx.ok("leaks: switched-off ban: %s joined the stream chat" % name, False, "no users list")
                return
            sockets[name] = ws
        await sockets["leakcarol"].send_json({"type": "message", "message": text})
        posted = await _wait_for(ev["leakowner"], lambda e: e.get("type") == "message" and e.get("message") == text)
        async with sessions["leakcarol"].put(f"{ctx.base_url}/api/me/anonymous", json={"anonymous": False}) as r:
            off_status = r.status
        await _wait_for(ev["leakowner"], lambda e: e.get("type") == "user_anonymous_changed")
        await sockets["leakowner"].send_json({"type": "ban", "message_id": (posted or {}).get("id"), "reason": "smoke"})
        success = await _wait_for(ev["leakowner"], lambda e: e.get("type") in ("ban_success", "error"))
        for name in ("leakbob", "leakowner"):
            await _wait_for(ev[name], lambda e: e.get("type") == "user_banned")
    banned = {n: next((e for e in ev[n] if e.get("type") == "user_banned"), None) for n in ("leakbob", "leakowner")}
    blob = json.dumps([success, banned])
    ctx.ok("leaks: switched-off ban: author switched anonymous mode off and the post reached the owner masked",
           off_status == 200 and posted is not None and posted.get("user_id") is None, json.dumps(posted))
    ctx.ok("leaks: switched-off ban: ban by message id of a post made while anonymous does not name the author",
           success is not None and success.get("type") == "ban_success" and success.get("user_id") is None
           and success.get("username") == "Anonymous"
           and all(b is not None and b.get("user_id") is None and b.get("username") == "Anonymous"
                   for b in banned.values())
           and not _has_value(json.loads(blob), "user_id", carol) and "leakcarol" not in blob, blob[:600])


SETUP_BANS = r"""
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        out = {}
        for name in ("leakdave", "leakeve", "leakfrank"):
            u = await db.get_user_by_username(name)
            out[name] = u["id"] if u else await db.create_user(name, hash_password(%(pw)r))
            await db.set_chat_anonymous(out[name], True)
        # an account that is NOT in anonymous mode, as a ban-by-id target
        gina = await db.get_user_by_username("leakgina")
        out["leakgina"] = gina["id"] if gina else await db.create_user("leakgina", hash_password(%(pw)r))
        await db.set_chat_anonymous(out["leakgina"], False)
        cur = await db.conn.execute("SELECT id FROM user_streams WHERE name = 'leakownerstream'")
        out["stream"] = (await cur.fetchone())["id"]
        # a second stream (other owner) that already has a masked ban of its own
        bob = await db.get_user_by_username("leakbob")
        other = await db.create_user_stream(bob["id"], "leakotherstream", "live_LeakOtherKey1" + "x" * 8,
                                            public_key="pub_LeakOtherKey1" + "x" * 8)
        out["other_ban"] = await db.create_stream_ban(other, out["leakeve"], bob["id"], "x", anonymous=True, message_id=1)
        out["other_stream"] = other
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
""" % {"pw": PW}

CHECK_BANS = r"""
import asyncio, json
from database import db

async def main():
    await db.connect()
    try:
        res = {}
        for label, uid in (("dave", %(dave)d), ("eve", %(eve)d), ("frank", %(frank)d)):
            res[label] = await db.is_user_banned_from_stream(%(stream)d, uid)
        cur = await db.conn.execute("SELECT COUNT(*) AS n FROM stream_bans WHERE id = ?", (%(other_ban)d,))
        res["other_row_left"] = (await cur.fetchone())["n"]
        print("RESULT " + json.dumps(res))
    finally:
        await db.close()

asyncio.run(main())
"""


async def _masked_ban_records(ctx, data):
    """Bans made from anonymous posts must not reveal the author to the stream
    owner (a plain member): not in the ban list, not through the answers to
    ban and unban by account id, not through the answer to a second ban of the
    same author. Only a ban id lifts such a ban."""
    rc, out = await ctx.run_py(SETUP_BANS)
    bd = _result(out)
    ctx.ok("leaks: masked bans: setup", rc == 0 and bd is not None, out[-300:] if bd is None else "")
    if bd is None:
        return
    dave, eve, frank, sid = bd["leakdave"], bd["leakeve"], bd["leakfrank"], bd["stream"]
    names = ("leakdave", "leakeve", "leakfrank")
    stamp = secrets.token_hex(3)
    texts = {k: "masked %s %s" % (k, stamp) for k in ("d1", "d2", "e1")}
    ev, ids = {}, {}
    admin_ok = bool(ctx.admin_password)
    async with AsyncExitStack() as stack:
        sockets, sessions = {}, {}
        who = ["leakbob", "leakowner", "leakdave", "leakeve"]
        for name in who + (["__admin__"] if admin_ok else []):
            sess = await stack.enter_async_context(ctx.http())
            if name == "__admin__":
                resp = await ctx.login(sess, ctx.admin_user, ctx.admin_password)
            else:
                resp = await ctx.login(sess, name, PW)
            if resp.status != 200:
                ctx.ok("leaks: masked bans: %s can log in" % name, False, f"status {resp.status}")
                return
            sessions[name] = sess
            ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat"))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws, ev[name]))
            stack.callback(pump.cancel)
            await ws.send_json({"type": "join", "channel_id": data["stream_channel"]})
            if await _wait_for(ev[name], lambda e: e.get("type") == "users") is None:
                ctx.ok("leaks: masked bans: %s joined the stream chat" % name, False, "no users list")
                return
            sockets[name] = ws
        owner_ws, owner_ev = sockets["leakowner"], ev["leakowner"]

        async def ask(payload, types=("ban_success", "unban_success", "bans_list", "error")):
            mark = len(owner_ev)
            await owner_ws.send_json(payload)
            return await _wait_for(owner_ev, lambda e: e.get("type") in types, start=mark)

        async def rest(method, path):
            async with getattr(sessions["leakowner"], method)(f"{ctx.base_url}{path}") as r:
                try:
                    body = await r.json()
                except Exception:
                    body = None
                return r.status, body

        # two anonymous posts of one author and one of another
        for key, name in (("d1", "leakdave"), ("d2", "leakdave"), ("e1", "leakeve")):
            await sockets[name].send_json({"type": "message", "message": texts[key]})
            m = await _wait_for(owner_ev, lambda e, t=texts[key]: e.get("type") == "message" and e.get("message") == t)
            ids[key] = (m or {}).get("id")
        ctx.ok("leaks: masked bans: the owner received the three anonymous posts without author ids",
               all(ids.values()), json.dumps(ids))

        # bans of anonymous posts that earlier checks left in this stream
        earlier = {b["id"] for b in ((await ask({"type": "get_bans"})) or {}).get("bans", [])}

        # the author of e1 is already banned by name: a ban by message must answer like any other
        named_eve = await ask({"type": "ban", "user_id": eve, "reason": "named"})
        mark = len(owner_ev)
        bob_start = len(ev["leakbob"])
        answers = {}
        for key in ("d1", "d2", "e1"):
            answers[key] = await ask({"type": "ban", "message_id": ids[key], "reason": "smoke"})
        notices = [e for e in owner_ev[mark:] if e.get("type") == "user_banned"]
        await _wait_for(ev["leakbob"], lambda e: e.get("type") == "user_banned" and e.get("reason") == "smoke",
                        start=bob_start)
        member_notices = [e for e in ev["leakbob"][bob_start:]
                          if e.get("type") == "user_banned" and e.get("reason") == "smoke"]
        masked = {"type": "ban_success", "user_id": None, "username": "Anonymous"}
        ctx.ok("leaks: masked bans: ban by message answers the same for a fresh author, a second post "
               "of the same author and an author who is already banned by name",
               all(a == masked for a in answers.values()), json.dumps(answers))
        ctx.ok("leaks: masked bans: every ban by message is announced, masked, to the owner and to members",
               len(notices) >= 3 and all(n.get("user_id") is None and n.get("username") == "Anonymous"
                                         and "anon_ref" not in n for n in notices)
               and member_notices and all(n.get("user_id") is None and n.get("username") == "Anonymous"
                                          and "anon_ref" not in n for n in member_notices),
               json.dumps([notices, member_notices])[:500])

        # the ban list
        wl = await ask({"type": "get_bans"})
        wl_bans = (wl or {}).get("bans", [])
        st, rl = await rest("get", f"/api/streams/{sid}/bans")
        rl_bans = (rl or {}).get("bans", [])
        masked_rows = [b for b in wl_bans if b.get("user_id") is None and b["id"] not in earlier]
        for label, bans in (("websocket", wl_bans), ("REST", rl_bans)):
            blob = json.dumps(bans)
            anon_rows = [b for b in bans if b.get("banned_username") == "Anonymous" and b["id"] not in earlier]
            ctx.ok("leaks: masked bans: the owner's %s ban list shows the three bans of anonymous posts without "
                   "account or name, each with a ban id" % label,
                   len(anon_rows) == 3 and all(b.get("user_id") is None and b.get("id") for b in anon_rows)
                   and len({b["id"] for b in anon_rows}) == 3
                   and not _has_value(json.loads(blob), "user_id", dave)
                   and "leakdave" not in blob and "message_id" not in blob
                   and not any(b.get("anonymous") and b.get("user_id") for b in bans)
                   and not any(b.get("banned_username") != "Anonymous" and b.get("anonymous") for b in bans),
                   blob[:600])
        ctx.ok("leaks: masked bans: the ban list route answers 200 for the owner", st == 200, f"status {st}")

        # probing account ids: the author with only masked bans behaves like an account that was never banned
        un_author = await ask({"type": "unban", "user_id": dave})
        un_other = await ask({"type": "unban", "user_id": frank})
        ctx.ok("leaks: masked bans: unban by account id answers the same for the author of a masked ban "
               "and for an account that is not banned",
               un_author == un_other and un_author is not None and un_author.get("type") == "error",
               json.dumps([un_author, un_other]))
        st_a, body_a = await rest("delete", f"/api/streams/{sid}/bans/{dave}")
        st_o, body_o = await rest("delete", f"/api/streams/{sid}/bans/{frank}")
        ctx.ok("leaks: masked bans: REST unban by account id answers the same for both (404)",
               (st_a, body_a) == (st_o, body_o) and st_a == 404, json.dumps([[st_a, body_a], [st_o, body_o]]))
        # ban by account id: the answer and the announcement must not depend on whether the
        # target is in anonymous mode (dave and frank are, gina is not)
        gina = bd["leakgina"]
        len_before = len((await ask({"type": "get_bans"}) or {}).get("bans", []))
        owner_mark, bob_mark = len(owner_ev), len(ev["leakbob"])
        ban_author = await ask({"type": "ban", "user_id": dave, "reason": "probe"})
        ban_other = await ask({"type": "ban", "user_id": frank, "reason": "probe"})
        ban_plain = await ask({"type": "ban", "user_id": gina, "reason": "probe"})
        len_after = len((await ask({"type": "get_bans"}) or {}).get("bans", []))
        await _wait_for(ev["leakbob"], lambda e: e.get("type") == "user_banned" and e.get("username") == "leakgina",
                        start=bob_mark)
        by_id = {"leakdave": ban_author, "leakfrank": ban_other, "leakgina": ban_plain}
        ctx.ok("leaks: masked bans: ban by account id answers alike for anonymous and non-anonymous targets "
               "(same shape, named after the id the caller supplied) and adds one entry each",
               all(a is not None and a.get("type") == "ban_success" and set(a) == set(ban_plain)
                   and a.get("user_id") == uid and a.get("username") == n
                   for (n, a), uid in zip(by_id.items(), (dave, frank, gina)))
               and len_after - len_before == 3,
               json.dumps([by_id, len_before, len_after]))
        id_notices = {}
        for who, events, mark in (("owner", owner_ev, owner_mark), ("member", ev["leakbob"], bob_mark)):
            for n, uid in (("leakdave", dave), ("leakfrank", frank), ("leakgina", gina)):
                id_notices[who + ":" + n] = next(
                    (e for e in events[mark:] if e.get("type") == "user_banned" and e.get("username") == n), None)
        ctx.ok("leaks: masked bans: the announcement of a ban by account id is named and has the same shape "
               "for anonymous and non-anonymous targets, for the owner and for members",
               all(e is not None and e.get("user_id") == {"leakdave": dave, "leakfrank": frank, "leakgina": gina}[k.split(":")[1]]
                   and set(e) == set(id_notices["owner:leakgina"]) for k, e in id_notices.items()),
               json.dumps(id_notices)[:600])
        all_notices = [e for e in owner_ev + ev["leakbob"] if e.get("type") == "user_banned"]
        ctx.ok("leaks: masked bans: no ban notice carries an anon_ref",
               bool(all_notices) and not any("anon_ref" in e for e in all_notices),
               json.dumps(all_notices)[:600])
        un_author = await ask({"type": "unban", "user_id": dave})
        un_other = await ask({"type": "unban", "user_id": frank})
        un_plain = await ask({"type": "unban", "user_id": gina})
        ctx.ok("leaks: masked bans: unban by account id after that removes only the named entry, for all three",
               all(a is not None and a.get("type") == "unban_success" for a in (un_author, un_other, un_plain)),
               json.dumps([un_author, un_other, un_plain]))
        rc, out = await ctx.run_py(CHECK_BANS % {**bd, "dave": dave, "eve": eve, "frank": frank, "stream": sid})
        res = _result(out) or {}
        ctx.ok("leaks: masked bans: the author of the masked bans is still banned after unban by account id, "
               "an unrelated account is not",
               res.get("dave") is True and res.get("frank") is False, out[-300:])

        # a ban id of another stream is refused and leaves that ban alone
        other_ws = await ask({"type": "unban", "ban_id": bd["other_ban"]})
        st_x, _ = await rest("delete", f"/api/streams/{sid}/bans/id/{bd['other_ban']}")
        rc, out = await ctx.run_py(CHECK_BANS % {**bd, "dave": dave, "eve": eve, "frank": frank, "stream": sid})
        res = _result(out) or {}
        ctx.ok("leaks: masked bans: a ban id of another stream is refused over the websocket and REST and the "
               "ban stays",
               other_ws is not None and other_ws.get("type") == "error" and st_x == 404
               and res.get("other_row_left") == 1, json.dumps([other_ws, st_x, res]))

        # a member who does not own the stream cannot list or lift bans
        await sockets["leakbob"].send_json({"type": "unban", "ban_id": masked_rows[0]["id"] if masked_rows else 0})
        denied = await _wait_for(ev["leakbob"], lambda e: e.get("type") in ("unban_success", "error")
                                 and e.get("message") != "You are banned from this stream's chat")
        ctx.ok("leaks: masked bans: a member who does not own the stream cannot unban by ban id",
               denied is not None and denied.get("type") == "error", json.dumps(denied))

        # staff see the accounts
        if admin_ok:
            await sockets["__admin__"].send_json({"type": "get_bans"})
            al = await _wait_for(ev["__admin__"], lambda e: e.get("type") in ("bans_list", "error"))
            abans = (al or {}).get("bans", [])
            ctx.ok("leaks: masked bans: an admin sees the account behind a ban made from an anonymous post",
                   al is not None and al.get("type") == "bans_list"
                   and any(b.get("anonymous") and b.get("user_id") == dave and b.get("banned_username") == "leakdave"
                           for b in abans), json.dumps(al)[:500])
        else:
            ctx.skip("leaks: masked bans: an admin sees the account behind a ban", "no admin password")

        # lifting by ban id: websocket for the first post of the author, REST for the second
        # (ids grow with the order of the bans: first post, second post, other author)
        row_ids = sorted(b["id"] for b in masked_rows)
        un_ws = await ask({"type": "unban", "ban_id": row_ids[0]}) if len(row_ids) == 3 else None
        mid_rest = (await rest("delete", f"/api/streams/{sid}/bans/id/{row_ids[1]}")) if len(row_ids) == 3 else (None, None)
        again = (await rest("delete", f"/api/streams/{sid}/bans/id/{row_ids[1]}")) if len(row_ids) == 3 else (None, None)
        ctx.ok("leaks: masked bans: unban by ban id works over the websocket without naming the author",
               un_ws is not None and un_ws.get("type") == "unban_success" and un_ws.get("user_id") is None
               and un_ws.get("username") == "Anonymous" and "leakdave" not in json.dumps(un_ws)
               and "leakeve" not in json.dumps(un_ws), json.dumps(un_ws))
        ctx.ok("leaks: masked bans: unban by ban id works over REST once, then answers 404",
               mid_rest[0] == 200 and again[0] == 404, json.dumps([mid_rest, again]))
        final = await ask({"type": "get_bans"})
        fbans = (final or {}).get("bans", [])
        ctx.ok("leaks: masked bans: the lifted bans are gone from the list and the other author's ban stays",
               not any(b.get("id") in row_ids[:2] for b in fbans) and any(b.get("id") == row_ids[2] for b in fbans),
               json.dumps(fbans)[:500])
    rc, out = await ctx.run_py(CHECK_BANS % {**bd, "dave": dave, "eve": eve, "frank": frank, "stream": sid})
    res = _result(out) or {}
    ctx.ok("leaks: masked bans: once all bans of an account are lifted it can chat again, the other author stays banned",
           res.get("dave") is False and res.get("eve") is True, out[-300:])


CHECK_BAN = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    try:
        cur = await db.conn.execute("SELECT stream_id, user_id FROM stream_bans")
        rows = [dict(r) for r in await cur.fetchall()]
        cur = await db.conn.execute("SELECT id FROM user_streams WHERE name = ?", (%(stream)r,))
        sid = (await cur.fetchone())["id"]
        mine = [r for r in rows if r["user_id"] == %(alice)d]
        print("RESULT " + json.dumps({
            "banned": any(r["stream_id"] == sid for r in mine),
            "only_one": len(mine) == 1,
            "other_channel_banned": any(r["stream_id"] != sid for r in mine)}))
    finally:
        await db.close()

asyncio.run(main())
'''


async def _voice_payloads(ctx, data):
    """Voice payloads carry real account ids, so an anonymous member must not
    be in a channel voice room: joining is refused, and switching anonymous
    mode on removes the member from a room they are already in."""
    alice = data["leakalice"]
    # An earlier step of this module timed her out for a minute; a member who is timed out cannot join
    # voice (the intended rule), so her timeout is lifted here and not left to run out on its own
    # (a moderator's unmute over the chat socket: it also clears the short voice deny a timeout leaves in memory)
    async with ctx.http() as mod_sess:
        resp = await ctx.login(mod_sess, "leakmod", PW)
        if resp.status != 200:
            ctx.ok("leaks: voice: the moderator can log in to lift the timeout", False, f"status {resp.status}")
            return
        async with mod_sess.ws_connect(f"{ctx.base_url}/ws/chat") as mod_ws:
            mod_ev = []
            mod_pump = asyncio.create_task(_pump(mod_ws, mod_ev))
            try:
                await mod_ws.send_json({"type": "join", "channel_id": data["channel"]})
                await _wait_for(mod_ev, lambda e: e.get("type") == "users")
                await mod_ws.send_json({"type": "unmute_user", "target_user_id": alice})
                lifted = await _wait_for(mod_ev, lambda e: e.get("type") == "user_unmuted")
            finally:
                mod_pump.cancel()
        ctx.ok("leaks: voice: the moderator lifts the member's earlier timeout", lifted is not None,
               json.dumps(mod_ev[-3:]))
    ev = {}
    async with AsyncExitStack() as stack:
        sess, sockets = {}, {}
        for name in ("leakbob", "leakalice"):
            sess[name] = await stack.enter_async_context(ctx.http())
            resp = await ctx.login(sess[name], name, PW)
            if resp.status != 200:
                ctx.ok("leaks: voice: %s can log in" % name, False, f"status {resp.status}")
                return
            ws = await stack.enter_async_context(sess[name].ws_connect(f"{ctx.base_url}/ws/chat"))
            ev[name] = []
            pump = asyncio.create_task(_pump(ws, ev[name]))
            stack.callback(pump.cancel)
            await ws.send_json({"type": "join", "channel_id": data["channel"]})
            if await _wait_for(ev[name], lambda e: e.get("type") == "users") is None:
                ctx.ok("leaks: voice: %s joined the channel" % name, False, "no users list")
                return
            sockets[name] = ws

        async def set_anon(value):
            async with sess["leakalice"].put(f"{ctx.base_url}/api/me/anonymous",
                                             json={"anonymous": value}) as r:
                return r.status

        try:
            # anonymous author is refused; a member joining sees no trace of her
            await sockets["leakalice"].send_json({"type": "voice_join"})
            den = await _wait_for(ev["leakalice"], lambda e: e.get("type") == "voice_denied")
            ctx.ok("leaks: voice: joining a channel voice room in anonymous mode is refused", den is not None,
                   json.dumps(ev["leakalice"][-3:]))
            await sockets["leakbob"].send_json({"type": "voice_join"})
            vs = await _wait_for(ev["leakbob"], lambda e: e.get("type") == "voice_state")
            ctx.ok("leaks: voice: a member's voice state does not include the anonymous user",
                   vs is not None and not _has_value(vs, "user_id", alice) and "Anonymous" not in json.dumps(vs),
                   json.dumps(vs))
            # switching anonymous mode on removes her from a room she is in
            st = await set_anon(False)
            ctx.ok("leaks: voice: anonymous mode can be switched off", st == 200, f"status {st}")
            mark = len(ev["leakbob"])
            await sockets["leakalice"].send_json({"type": "voice_join"})
            joined = await _wait_for(ev["leakbob"], lambda e: e.get("type") == "voice_user_joined", start=mark)
            ctx.ok("leaks: voice: a member joins voice normally", joined is not None, "no voice_user_joined")
            mark_a, mark_b = len(ev["leakalice"]), len(ev["leakbob"])
            st = await set_anon(True)
            ctx.ok("leaks: voice: anonymous mode can be switched on", st == 200, f"status {st}")
            den = await _wait_for(ev["leakalice"], lambda e: e.get("type") == "voice_denied", start=mark_a)
            left = await _wait_for(ev["leakbob"], lambda e: e.get("type") == "voice_user_left", start=mark_b)
            ctx.ok("leaks: voice: switching anonymous mode on ends the voice session",
                   den is not None and left is not None, json.dumps([den, left]))
            mark_b = len(ev["leakbob"])
            await sockets["leakalice"].send_json({"type": "voice_mute", "muted": True})
            await sockets["leakalice"].send_json({"type": "voice_signal", "target_user_id": 1,
                                                  "signal": {"type": "offer"}})
            await asyncio.sleep(0.5)
            rest = [e for e in ev["leakbob"][mark_b:] if str(e.get("type", "")).startswith("voice_")]
            ctx.ok("leaks: voice: no voice events about the anonymous user reach a member afterwards",
                   not rest, json.dumps(rest))
        finally:
            await set_anon(True)


# ---- log redaction over real requests ------------------------------------

async def _log_redaction(ctx):
    """Send requests whose URLs carry secrets and read the instance's log files:
    none of the secrets may be there, the redaction markers must be."""
    rnd = secrets.token_hex(8)
    play_key = "pub_LogCheckKey" + rnd
    bare_key = "BareLogCheckKey" + rnd
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsb2djaGVjayJ9.sig" + rnd
    sess_val = "SessionValue" + rnd
    hook = "HookToken" + rnd
    secrets_seen = [play_key, bare_key, jwt, sess_val, hook, "eyJzdWIiOiJsb2djaGVjayJ9"]
    paths = [
        f"/api/stream/{play_key}/hls/index.m3u8?token={jwt}&session={sess_val}",
        f"/api/stream/{bare_key}/hls/seg0.ts?session={sess_val}&x=1",
        f"/api/webhooks/incoming/{hook}",
    ]
    async with ctx.http() as s:
        for path in paths:
            async with s.get(f"{ctx.base_url}{path}") as r:
                await r.read()
        async with s.post(f"{ctx.base_url}/api/webhooks/incoming/{hook}", json={"text": "x"}) as r:
            await r.read()

    files = list((ctx.stage_dir / "logs").glob("*.log")) + [ctx.stage_dir / "server.log"]

    def read_all():
        text = ""
        for f in files:
            try:
                text += f.read_text(errors="replace")
            except OSError:
                pass
        return text

    text = ""
    for _ in range(50):
        text = read_all()
        if "/api/webhooks/incoming/[REDACTED]" in text and "[STREAM_KEY_REDACTED]" in text:
            break
        await asyncio.sleep(0.1)
    leaked = [x for x in secrets_seen if x in text]
    ctx.ok("leaks: logs: request URLs reach the log with redaction markers (not vacuous)",
           "/api/webhooks/incoming/[REDACTED]" in text and "/api/stream/[STREAM_KEY_REDACTED]" in text,
           "log files read: %d" % len(files))
    ctx.ok("leaks: logs: playback keys, token and session values and webhook tokens are absent from log files",
           not leaked, "found: %s" % leaked)
    ctx.ok("leaks: logs: token= and session= query values are replaced by the marker",
           "token=[REDACTED]" in text and "session=[REDACTED]" in text, "no marker for token= / session=")
