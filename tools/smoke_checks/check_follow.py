"""Follows, the go-live audience, announce cards and the live-now list on a running instance.

Over HTTP against the staged server (real logins, the MediaMTX publish hook POST /api/stream/auth
from loopback, which is the path MediaMTX uses): a member follows a public stream (200) and is
refused a private one with the same 404 as an unknown id; a member sees only their own follows and
the owner a follower count and no names; a new stream announces to followers and a go-live reaches
the follower and nobody else (not the streamer); the publish hook answers at once; a stream_card
message with a plain-text fallback and a Watch link appears in the stream's own chat and, for a
public stream, in the announce channel the administrator chose (a private channel is refused as
the announce channel); a private stream's card is in no channel a member can read; making the
stream private removes the card from the announce channel, also one that turned private with a
member in it, and every follow, and making it public
again does not bring the follows back; the live-now list shows a member only what they may
watch, with no key; switching the audience to everyone reaches a member who does not follow; the
streams, watch and chat pages carry the follow toggle; a stream key reads no follow list and no
`following` flag from the public list or the stream detail.

Users, streams and channels carry random suffixes, every assertion is about those rows, and the
announce channel setting is put back as found, so the module also holds on a stage started from a
copy of a production database. It needs no admin password.

Not proven here (needs the real thing): a real MediaMTX retrying its hook, OBS, a browser
rendering the toggle, the card or the strip, a go-live fan-out to a community of hundreds.
"""
import asyncio
import json
import secrets
import time

PW = "Follow-smoke-pw-1"
_UNREAD = object()      # the announce setting was not read, so it is not put back

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "m1", "m2", "adm"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.set_user_role(out["users"]["adm"], "admin")
    out["announce"] = await db.create_chat_channel(P["pre"] + "announce", created_by=out["users"]["adm"])
    out["closed"] = await db.create_chat_channel(P["pre"] + "closed", created_by=out["users"]["adm"])
    await db.update_chat_channel(out["closed"], visibility="private")
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

RESET = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    await db.set_stream_live(%(sid)d, False)
    await db.conn.execute("UPDATE user_streams SET golive_announced_at = NULL WHERE id = ?", (%(sid)d,))
    # the streamer's own broadcast slot (one per owner) is part of the cooldown too
    await db.conn.execute("DELETE FROM golive_owner_cooldown WHERE user_id = "
                          "(SELECT user_id FROM user_streams WHERE id = ?)", (%(sid)d,))
    await db.conn.commit()
    await db.close()
    print("RESULT {}")

asyncio.run(main())
'''

CLEAN = r'''
import asyncio, json
from database import db

async def main():
    await db.connect()
    for cid in %(channels)r:
        await db.delete_chat_channel(cid)
    await db.close()
    print("RESULT {}")

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    pre = "fw" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("follow: setup", False, out[-500:])
        return
    announce, closed = data["announce"], data["closed"]
    channels = [announce, closed]
    streams = []

    def ok(name, passed, detail=""):
        ctx.ok("follow: " + name, bool(passed), "" if passed else detail)

    base = ctx.base_url

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def text(sess, path):
        async with sess.get(base + path) as r:
            return r.status, await r.text()

    async def publish(hook, key):
        t0 = time.monotonic()
        async with hook.post(base + "/api/stream/auth", json={
                "action": "publish", "path": "live/" + key, "password": key, "ip": "127.0.0.1"}) as r:
            return r.status, time.monotonic() - t0

    async def notes(sess, sid):
        _, body = await call(sess, "GET", "/api/notifications?limit=100")
        return [n for n in (body or {}).get("notifications", []) if n.get("type") == "stream_live"
                and f'"stream_id": {sid}' in (n.get("data") or "")]

    async def wait_for(sess, sid, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if await notes(sess, sid):
                return True
            await asyncio.sleep(0.2)
        return False

    async def cards(sess, channel_id):
        st, body = await call(sess, "GET", f"/api/chat/channels/{channel_id}/messages?limit=100")
        if st != 200 or not body:
            return st, []
        return st, [m for m in body.get("messages", []) if m.get("message_type") == "stream_card"]

    previous = _UNREAD
    async with ctx.http() as owner, ctx.http() as m1, ctx.http() as m2, ctx.http() as adm, ctx.http() as hook:
        try:
            for name, sess in (("owner", owner), ("m1", m1), ("m2", m2), ("adm", adm)):
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return

            # ---- streams: the default audience is followers
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "pub", "is_public": True})
            pub = (b or {}).get("stream", {})
            st2, b2 = await call(owner, "POST", "/api/streams", json={"name": pre + "priv", "is_public": False})
            priv = (b2 or {}).get("stream", {})
            if st != 201 or st2 != 201:
                ok("streams are created", False, f"{st} {st2} {b} {b2}")
                return
            streams = [pub["id"], priv["id"]]
            ok("a new stream announces to followers by default",
               pub.get("golive_audience") == "followers" and priv.get("golive_audience") == "followers",
               f"{pub.get('golive_audience')} {priv.get('golive_audience')}")
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "x", "golive_audience": "nobody"})
            ok("an unknown audience is refused (400)", st == 400, f"{st} {b}")

            # ---- follow rules
            s_pub, b_pub = await call(m1, "PUT", f"/api/streams/{pub['id']}/follow")
            ok("a member follows a public stream", s_pub == 200 and b_pub.get("following") is True, f"{s_pub} {b_pub}")
            s_priv, b_priv = await call(m1, "PUT", f"/api/streams/{priv['id']}/follow")
            s_unk, b_unk = await call(m1, "PUT", "/api/streams/987654321/follow")
            ok("a private stream and an unknown one give the same 404",
               s_priv == 404 and s_unk == 404 and b_priv == b_unk, f"{s_priv} {b_priv} / {s_unk} {b_unk}")
            s_adm, _ = await call(adm, "PUT", f"/api/streams/{priv['id']}/follow")
            ok("an administrator may follow a private stream", s_adm == 200, str(s_adm))
            st, b = await call(m1, "GET", "/api/me/follows")
            ok("a member's list holds their own follows only", st == 200 and b.get("stream_ids") == [pub["id"]], f"{st} {b}")
            st, b = await call(owner, "GET", "/api/streams")
            mine = {s["id"]: s for s in (b or {}).get("streams", [])}
            body = json.dumps(b)
            ok("the owner sees a follower count and no names",
               mine.get(pub["id"], {}).get("follower_count") == 1 and mine.get(priv["id"], {}).get("follower_count") == 1
               and pre + "m1" not in body and pre + "adm" not in body, body[:300])
            st, b = await call(m2, "GET", f"/api/streams/{pub['id']}")
            ok("another member sees no count", st == 200 and "follower_count" not in b.get("stream", {}), f"{st}")
            st, b = await call(m1, "GET", "/api/streams/public")
            flags = {s["id"]: s.get("following") for s in (b or {}).get("streams", [])}
            ok("the public list marks only the viewer's own follow", flags.get(pub["id"]) is True, str(flags.get(pub["id"])))
            st, b = await call(m2, "GET", "/api/streams/public")
            flags = {s["id"]: s.get("following") for s in (b or {}).get("streams", [])}
            ok("another member's list does not show it", flags.get(pub["id"]) is False, str(flags.get(pub["id"])))

            # ---- the announce channel setting
            st, cur = await call(adm, "GET", "/api/settings/permissions")
            if st != 200:
                ok("the administrator reads the permission settings", False, f"{st} {cur}")
                return
            previous = cur.get("stream_announce_channel_id")
            st, b = await call(adm, "PUT", "/api/settings/permissions", json={"stream_announce_channel_id": closed})
            ok("a private channel is refused as the announce channel (400)", st == 400, f"{st} {b}")
            st, b = await call(m1, "PUT", "/api/settings/permissions", json={"stream_announce_channel_id": announce})
            ok("a member cannot set it", st in (401, 403), str(st))
            st, b = await call(adm, "PUT", "/api/settings/permissions", json={"stream_announce_channel_id": announce})
            ok("the administrator sets it", st == 200, f"{st} {b}")

            # ---- a public stream goes live: followers only, the hook answers at once
            status, took = await publish(hook, pub["stream_key"])
            ok("the publish hook accepts the stream", status == 200, str(status))
            ok("and answers at once (under 3 s)", took < 3.0, f"{took:.2f}")
            ok("the follower is notified", await wait_for(m1, pub["id"]))
            ok("a member who does not follow is not", not await notes(m2, pub["id"]))
            ok("the streamer is not", not await notes(owner, pub["id"]))
            rows = await notes(m1, pub["id"])
            blob = json.dumps(rows)
            ok("the notification names the stream's page and carries no key",
               rows and f"/watch/{pub['id']}" in blob and not any(x in blob for x in ("live_", "pub_", "rtmp")), blob[:300])
            st, found = await cards(m2, announce)
            mine_cards = [m for m in found if (m.get("card") or {}).get("stream_id") == pub["id"]]
            ok("a card is in the announce channel", st == 200 and len(mine_cards) == 1, f"{st} {len(found)}")
            if mine_cards:
                c = mine_cards[0]
                ok("it has the streamer, the title and a plain-text fallback with the watch link",
                   c["card"].get("streamer") == pre + "owner" and c["card"].get("title") == pre + "pub"
                   and f"/watch/{pub['id']}" in c.get("message", "") and pre + "pub" in c.get("message", ""), str(c)[:300])
                ok("and no key", not any(x in json.dumps(c) for x in (pub["stream_key"], pub["public_key"], "live_", "pub_")))
            _, own = await call(owner, "GET", f"/api/streams/{pub['id']}")
            own_channel = own["stream"].get("chat_channel_id")
            st, found = await cards(m1, own_channel)
            ok("a card is in the stream's own chat", st == 200 and len(found) == 1, f"{st} {len(found)}")

            # ---- a private stream: followed by the administrator only
            status, _ = await publish(hook, priv["stream_key"])
            ok("the private stream is accepted", status == 200, str(status))
            ok("its follower, an administrator, is notified", await wait_for(adm, priv["id"]))
            ok("an ordinary member is not", not await notes(m1, priv["id"]) and not await notes(m2, priv["id"]))
            st, found = await cards(m1, announce)
            ok("no card of the private stream is in the announce channel",
               st == 200 and not [m for m in found if (m.get("card") or {}).get("stream_id") == priv["id"]], f"{st}")
            _, ownp = await call(owner, "GET", f"/api/streams/{priv['id']}")
            priv_chat = ownp["stream"].get("chat_channel_id")
            st, _ = await cards(m1, priv_chat)
            ok("its own chat is closed to a member (404)", st == 404, str(st))
            st, found = await cards(owner, priv_chat)
            ok("its card is in its own chat, for its owner", st == 200 and len(found) == 1, f"{st} {len(found)}")

            # ---- live now
            st, b = await call(m1, "GET", "/api/streams/live")
            ids = {s["id"] for s in (b or {}).get("streams", [])}
            ok("live-now shows a member the public live stream and not the private one",
               st == 200 and pub["id"] in ids and priv["id"] not in ids, f"{st} {ids}")
            st, b = await call(adm, "GET", "/api/streams/live")
            ids = {s["id"] for s in (b or {}).get("streams", [])}
            ok("and an administrator both", pub["id"] in ids and priv["id"] in ids, str(ids))
            blob = json.dumps(b)
            ok("live-now carries no key", not any(x in blob for x in (pub["stream_key"], pub["public_key"], "live_", "pub_", "stream_key", "public_key")), blob[:200])

            # ---- a stream key authorises publishing only: every stream route refuses it
            st, b = await call(owner, "PUT", f"/api/streams/{pub['id']}/follow")
            ok("the owner follows their own public stream", st == 200, f"{st} {b}")
            st, b = await call(owner, "GET", "/api/streams/public")
            mine = {s["id"]: s.get("following") for s in (b or {}).get("streams", [])}
            ok("the owner's session sees the follow in the public list", st == 200 and mine.get(pub["id"]) is True, f"{st} {mine}")
            async with ctx.http() as keyed:
                hdr = {"X-Stream-Key": pub["stream_key"]}
                st, _ = await call(keyed, "GET", "/api/me/follows", headers=hdr)
                ok("the stream key cannot read the follow list (403)", st == 403, str(st))
                for what, path in (("the public list", "/api/streams/public"), ("the stream detail", f"/api/streams/{pub['id']}"),
                                   ("the stream list", "/api/streams"), ("the live list", "/api/streams/live")):
                    st, b = await call(keyed, "GET", path, headers=hdr)
                    ok(f"the stream key reads {what}: refused (403), no stream in the answer",
                       st == 403 and "stream" not in (b or {}) and "streams" not in (b or {}), f"{st} {b}")
            st, b = await call(owner, "DELETE", f"/api/streams/{pub['id']}/follow")
            ok("the owner unfollows again", st == 200, f"{st}")

            # ---- the audience switches to everyone
            st, b = await call(owner, "PUT", f"/api/streams/{pub['id']}", json={"golive_audience": "everyone"})
            ok("the owner sets the audience to everyone", st == 200 and b["stream"]["golive_audience"] == "everyone", f"{st}")
            st, b = await call(m2, "PUT", f"/api/streams/{pub['id']}", json={"golive_audience": "followers"})
            ok("another member cannot (404)", st == 404, str(st))
            rc, out = await ctx.run_py(RESET % {"sid": pub["id"]})
            ok("the stream is taken offline and its cooldowns (stream and streamer) cleared", rc == 0, out[-200:])
            await publish(hook, pub["stream_key"])
            ok("a member who does not follow is now notified", await wait_for(m2, pub["id"]))
            ok("the streamer still is not", not await notes(owner, pub["id"]))

            # ---- the toggle is on the pages
            for page, needle in (("/streams", "data-follow-stream"), (f"/watch/{pub['id']}", 'id="follow-btn"'), ("/chat", "/api/me/follows")):
                st, html = await text(m1, page)
                ok(f"{page} carries the follow toggle", st == 200 and needle in html, f"{st}")

            # ---- the announce channel became private with a member in it after the card was posted
            st, b = await call(adm, "PUT", f"/api/chat/channels/{announce}", json={"visibility": "private"})
            ok("the administrator makes the announce channel private", st == 200, f"{st} {b}")
            st, b = await call(adm, "POST", f"/api/chat/channels/{announce}/members", json={"user_id": data["users"]["m1"]})
            ok("and adds a member", st in (200, 201), f"{st} {b}")
            st, found = await cards(m1, announce)
            ok("the member can read the card there while the stream is public",
               st == 200 and [m for m in found if (m.get("card") or {}).get("stream_id") == pub["id"]], f"{st}")

            # ---- private means the cards and the follows go
            st, b = await call(owner, "PUT", f"/api/streams/{pub['id']}", json={"is_public": False})
            ok("the owner makes the stream private", st == 200, f"{st} {b}")
            st, found = await cards(m1, announce)
            ok("its card leaves the announce channel, also for a member of a private one",
               st == 200 and not [m for m in found if (m.get("card") or {}).get("stream_id") == pub["id"]], f"{st}")
            st, b = await call(m1, "GET", "/api/me/follows")
            ok("its follows are gone", st == 200 and pub["id"] not in b.get("stream_ids", []), f"{st} {b}")
            await call(owner, "PUT", f"/api/streams/{pub['id']}", json={"is_public": True})
            st, b = await call(m1, "GET", "/api/me/follows")
            ok("and a later public switch does not bring them back", st == 200 and pub["id"] not in b.get("stream_ids", []), f"{st} {b}")

            # ---- deleting a stream takes its card
            for sid in list(streams):
                await call(owner, "DELETE", f"/api/streams/{sid}")
            streams = []
            st, found = await cards(m1, announce)
            ok("deleting the streams removes their cards",
               st == 200 and not [m for m in found if (m.get("card") or {}).get("stream_id") in (pub["id"], priv["id"])], f"{st}")
        finally:
            for sid in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{sid}")
                except Exception:
                    pass
            # put the announce setting back as it was found
            if previous is not _UNREAD:
                try:
                    await call(adm, "PUT", "/api/settings/permissions", json={"stream_announce_channel_id": previous})
                except Exception:
                    pass
            await ctx.run_py(CLEAN % {"channels": channels})
