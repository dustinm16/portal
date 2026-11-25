"""Stored stream_live and stream_reminder notifications do not outlive access (1.24.1).

They name the streamer and the stream and link to it. When a stream turns private, everybody but its owner
and the administrators loses them; when a member is banned from a stream (HTTP route, websocket ban by account id
and by message id) that member's own are deleted and nobody else's. The delete matches the stream id inside the
notification's JSON by number, touches only those two types, survives a row whose
data is not JSON, and runs in bounded batches.

The real app on a loopback test server with a temporary database (tests/grant_harness.py). Not proven here: an
open page keeps what it already shows until it is reloaded, and a push already sent is not recalled.

Run: venv/bin/python tests/test_stream_notifications_withdrawn.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402


async def titles(db, user_id, kind=None):
    cur = await db.conn.execute("SELECT type, data FROM notifications WHERE user_id = ?", (user_id,))
    return [(r["type"], r["data"]) for r in await cur.fetchall() if kind is None or r["type"] == kind]


async def count(db, user_id, sid, types=("stream_live", "stream_reminder")):
    n = 0
    for t, data in await titles(db, user_id):
        try:
            d = json.loads(data)
        except ValueError:
            continue
        if t in types and d.get("stream_id") == sid:
            n += 1
    return n


async def seed(db, uids, sid, other_sid):
    rows = []
    for uid in uids:
        rows.append((uid, "stream_live", "x is live!", "msg", {"stream_id": sid, "streamer": "x", "title": "t"}))
        rows.append((uid, "stream_reminder", "x starts in 10 minutes", "", {"stream_id": sid}))
        rows.append((uid, "stream_live", "y is live!", "msg", {"stream_id": other_sid, "streamer": "y"}))
        rows.append((uid, "mention", "mentioned", "msg", {"stream_id": sid}))
    await db.create_notifications_bulk(rows)
    for uid in uids:
        await db.conn.execute("INSERT INTO notifications (user_id, type, title, data) VALUES (?, 'stream_live', 't', 'not json')", (uid,))
    await db.conn.commit()


async def main():
    env = await h.boot(names=("owner", "bob", "carol", "dave", "adm"))
    db = env.db
    u = env.uid
    owner = env.sessions["owner"]

    async def make_stream(name):
        cid = await db.create_chat_channel(f"chat-{name}", created_by=u["owner"])
        sid = await db.create_user_stream(u["owner"], name, "live_" + name * 12, public_key="pub_" + name * 12, is_public=1)
        await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
        await db.conn.commit()
        return sid, cid

    s1, c1 = await make_stream("a")
    s2, c2 = await make_stream("b")
    for _ in range(3):
        await db.create_user_stream(u["owner"], f"filler{_}", "live_" + str(_) * 24, public_key="pub_" + str(_) * 24, is_public=1)
    uids = [u[n] for n in ("owner", "bob", "carol", "dave", "adm")]
    await seed(db, uids, s1, s2)

    # ---- a ban over HTTP: only the banned member's rows of that stream go -----------------------------------------
    async with owner.post(f"{env.base}/api/streams/{s1}/bans", json={"user_id": u["bob"]}) as r:
        check("the owner bans a member over HTTP", r.status == 201, str(r.status))
    check("the banned member has no stored notification naming the stream", await count(db, u["bob"], s1) == 0)
    check("another stream's notification of the banned member stays", await count(db, u["bob"], s2) == 1)
    check("a mention of the banned member stays", await count(db, u["bob"], s1, ("mention",)) == 1)
    check("the row that is not JSON stays", any(d == "not json" for _, d in await titles(db, u["bob"])))
    for n in ("carol", "dave", "adm", "owner"):
        check(f"{n} keeps hers after somebody else's ban", await count(db, u[n], s1) == 2, str(await titles(db, u[n])))

    # ---- websocket ban by account id and by message id ------------------------------------------------------------
    async def ws_ban(session, cid, payload):
        ws = await session.ws_connect(env.base.replace("http", "ws") + "/ws/chat")
        await ws.send_json({"type": "join", "channel_id": cid})
        for _ in range(20):
            m = await asyncio.wait_for(ws.receive_json(), 5)
            if m.get("type") in ("history", "error"):
                break
        await ws.send_json({"type": "ban", **payload})
        for _ in range(30):
            m = await asyncio.wait_for(ws.receive_json(), 5)
            if m.get("type") in ("ban_success", "error", "user_banned"):
                break
        await ws.close()
        return m

    m = await ws_ban(owner, c1, {"user_id": u["carol"], "reason": "r"})
    check("a websocket ban by account id", m.get("type") != "error", str(m))
    check("the member banned over the websocket has none naming the stream", await count(db, u["carol"], s1) == 0)
    mid = await db.create_chat_message(c1, u["dave"], "dave", "anon", anonymous=True)
    m = await ws_ban(owner, c1, {"message_id": mid, "reason": "r"})
    check("a websocket ban by message id", m.get("type") != "error", str(m))
    check("the member banned from an anonymous post has none naming the stream", await count(db, u["dave"], s1) == 0)
    check("the owner and the administrator still have theirs", await count(db, u["owner"], s1) == 2 and await count(db, u["adm"], s1) == 2)

    # ---- the stream turns private: everybody but the owner and administrators -------------------------------------
    await seed(db, [u["bob"], u["carol"]], s1, s2)
    async with owner.put(f"{env.base}/api/streams/{s1}", json={"is_public": False}) as r:
        check("the owner makes the stream private", r.status == 200, str(r.status))
    for n in ("bob", "carol", "dave"):
        check(f"{n} has none naming the private stream", await count(db, u[n], s1) == 0)
        check(f"{n} keeps the other stream's", await count(db, u[n], s2) >= 1)
    check("the owner keeps hers", await count(db, u["owner"], s1) == 2)
    check("an administrator keeps hers", await count(db, u["adm"], s1) == 2)
    check("the other stream's notifications of the administrator and owner stay",
          await count(db, u["adm"], s2) == 1 and await count(db, u["owner"], s2) == 1)

    # ---- bounded: many rows go in batches, the neighbours stay -------------------------------------------------------
    await db.create_notifications_bulk([(u["bob"], "stream_live", "t", "m", {"stream_id": s2}) for _ in range(1200)])
    before = await count(db, u["bob"], s2)
    n = await db.withdraw_stream_notifications(s2, user_id=u["bob"], batch=100)
    check("a large number is deleted in batches", n == before and await count(db, u["bob"], s2) == 0, f"{n} {before}")
    check("the neighbouring stream's rows of that member stay", await count(db, u["carol"], s2) >= 1)

    await h.shutdown(env)
    h.finish("test_stream_notifications_withdrawn")


async def guarded():
    try:
        await asyncio.wait_for(main(), 100)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        import os
        os._exit(1)


asyncio.run(guarded())
