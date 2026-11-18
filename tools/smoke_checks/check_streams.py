"""Private stream playback keys: go-live notification scoping, listings, rotation, migration.

Go-live is triggered through the MediaMTX publish hook (POST /api/stream/auth from
loopback), which is the same code path MediaMTX uses; no MediaMTX is needed because
the stage has no VOD storage and no relay destinations. The outgoing webhook payload
is checked in-process (ctx.run_py) with the delivery function replaced by a recorder.
"""
import asyncio
import json
import re
from pathlib import Path

PW_A = "streams-owner-pass-1234"
PW_B = "streams-other-pass-1234"

SETUP = '''
import asyncio, json
from database import db
from auth import create_user
import server

async def main():
    await db.connect()
    out = {}
    for name, pw in (("str_owner", %r), ("str_other", %r)):
        out[name] = (await create_user(name, pw))["id"]
    for label, uid, public in (("priv", out["str_owner"], False), ("pub", out["str_owner"], True)):
        sk = server.generate_stream_key()
        pk = server.generate_public_key()
        sid = await db.create_user_stream(user_id=uid, name="smoke " + label, stream_key=sk,
                                          public_key=pk, is_public=public)
        cid = await db.create_chat_channel(name="stream-str_owner-%%d" %% sid, created_by=uid)
        await db.update_user_stream(sid, chat_channel_id=cid)
        out[label] = {"id": sid, "stream_key": sk, "public_key": pk}
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
''' % (PW_A, PW_B)

WEBHOOK = '''
import asyncio, json
from unittest import mock
from database import db
import server

class Req:
    def __init__(self, body):
        self._body = body
        self.transport = mock.Mock()
        self.transport.get_extra_info.return_value = ("127.0.0.1", 1)
        self.headers = {}
        self.remote = "127.0.0.1"
    async def json(self):
        return self._body

async def main():
    await db.connect()
    server.db = db
    calls = []
    def rec(event, payload, *a, **k):
        calls.append([event, payload])
        async def _n(): return None
        return _n()
    server.fire_webhook_event = rec
    out = {}
    for label, key in (("priv", %r), ("pub", %r)):
        await db.set_stream_live(%d if label == "priv" else %d, False)
        await server.http_stream_auth(Req({"action": "publish", "path": "live/" + key, "password": key, "ip": "127.0.0.1"}))
    await asyncio.sleep(0.2)
    await db.close()
    print("RESULT " + json.dumps(calls))

asyncio.run(main())
'''

MIGRATE = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    c = db.conn
    await c.execute("DELETE FROM settings WHERE key = 'private_stream_keys_rotated_v1'")
    await c.execute("INSERT INTO notifications (user_id, type, title, message, data) VALUES (?, 'stream_live', 't', 'm', ?)",
                    (%d, json.dumps({"stream_id": %d, "public_key": "pub_legacyleak"})))
    await c.execute("INSERT INTO notifications (user_id, type, title, message, data) VALUES (?, 'other_type', 't', 'm', ?)",
                    (%d, json.dumps({"keep": "pub_untouched"})))
    await c.commit()
    await db.close()
    print("RESULT {}")

asyncio.run(main())
'''

READ_STATE = '''
import asyncio, json
from database import db

async def main():
    await db.connect()
    out = {}
    for label, sid in (("priv", %d), ("pub", %d)):
        out[label] = (await db.get_user_stream(sid))["public_key"]
    cur = await db.conn.execute("SELECT type, data FROM notifications WHERE data LIKE '%%legacyleak%%' OR data LIKE '%%untouched%%'")
    out["rows"] = [dict(r) for r in await cur.fetchall()]
    cur = await db.conn.execute("SELECT value FROM settings WHERE key = 'private_stream_keys_rotated_v1'")
    r = await cur.fetchone()
    out["flag"] = r["value"] if r else None
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("no RESULT line in: " + out[-500:])


async def _get_json(sess, ctx, path):
    async with sess.get(ctx.base_url + path) as r:
        text = await r.text()
        try:
            body = json.loads(text)
        except ValueError:
            body = {}
        return r.status, body, text


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    if rc != 0:
        ctx.ok("streams: staged users and streams created", False, out[-300:])
        return
    st = _result(out)
    priv, pub = st["priv"], st["pub"]
    ctx.ok("streams: staged users and streams created", True)

    async with ctx.http() as owner, ctx.http() as other, ctx.http() as hook:
        for s, u, p in ((owner, "str_owner", PW_A), (other, "str_other", PW_B)):
            r = await ctx.login(s, u, p)
            if r.status != 200:
                ctx.ok("streams: login " + u, False, f"status {r.status}")
                return

        # --- go-live through the MediaMTX publish hook, private then public stream
        for label, s in (("private", priv), ("public", pub)):
            async with hook.post(ctx.base_url + "/api/stream/auth",
                                 json={"action": "publish", "path": "live/" + s["stream_key"],
                                       "password": s["stream_key"], "ip": "127.0.0.1"}) as r:
                body = await r.json(content_type=None)
                ctx.ok(f"streams: publish hook accepts the {label} stream",
                       r.status == 200 and body.get("allowed") is True, f"status {r.status}")

        # --- the other user's notifications
        status, body, text = await _get_json(other, ctx, "/api/notifications")
        ctx.ok("streams: other user's notifications contain no private-stream key",
               status == 200 and priv["public_key"] not in text and "pub_" not in text.replace(pub["public_key"], ""),
               f"status {status}")
        notifs = body.get("notifications", [])
        about_priv = [n for n in notifs if str(priv["id"]) in (n.get("data") or "")
                      and f'"stream_id": {priv["id"]}' in (n.get("data") or "")]
        ctx.ok("streams: other user gets no go-live notification for the private stream",
               status == 200 and not about_priv, f"{len(about_priv)} row(s)")
        about_pub = [n for n in notifs if f'"stream_id": {pub["id"]}' in (n.get("data") or "")]
        ctx.ok("streams: public stream go-live notification still reaches other user, without a key",
               len(about_pub) == 1 and "public_key" not in about_pub[0]["data"] and "pub_" not in about_pub[0]["data"],
               f"{len(about_pub)} row(s)")

        # --- a private stream sends no go-live notification at all (not even to the owner)
        status, body, text = await _get_json(owner, ctx, "/api/notifications")
        own = [n for n in body.get("notifications", []) if f'"stream_id": {priv["id"]}' in (n.get("data") or "")]
        ctx.ok("streams: owner gets no go-live notification for the private stream, none carries a key",
               status == 200 and not own and priv["public_key"] not in text, f"{len(own)} row(s)")

        # --- chat channel listing
        status, body, text = await _get_json(other, ctx, "/api/chat/channels")
        chans = {c.get("stream_id"): c for c in body.get("channels", []) if c.get("is_stream_channel")}
        ctx.ok("streams: other user's channel list has no private-stream key",
               status == 200 and priv["id"] in chans and not chans[priv["id"]].get("stream_public_key")
               and priv["public_key"] not in text, f"status {status}")
        ctx.ok("streams: public stream's channel still lists its key",
               chans.get(pub["id"], {}).get("stream_public_key") == pub["public_key"])
        status, body, text = await _get_json(owner, ctx, "/api/chat/channels")
        chans = {c.get("stream_id"): c for c in body.get("channels", []) if c.get("is_stream_channel")}
        ctx.ok("streams: owner's channel list has the private-stream key",
               chans.get(priv["id"], {}).get("stream_public_key") == priv["public_key"])

        # --- chat WebSocket join of the stream's channel
        async def _channel_info(sess, channel_id):
            async with sess.ws_connect(ctx.base_url.replace("https", "wss") + "/ws/chat") as ws:
                await ws.send_json({"type": "join", "channel_id": channel_id})
                for _ in range(30):
                    msg = await asyncio.wait_for(ws.receive_json(), 10)
                    if msg.get("type") == "channel_info":
                        return msg
            return {}

        for label, sess, want_key in (("other user", other, False), ("owner", owner, True)):
            status, body, _ = await _get_json(sess, ctx, "/api/chat/channels")
            cid = next((c["id"] for c in body.get("channels", []) if c.get("stream_id") == priv["id"]), None)
            try:
                info = await _channel_info(sess, cid)
            except Exception as e:
                info = {"error": str(e)}
            got = info.get("stream_public_key")
            ctx.ok(f"streams: chat join channel_info for {label} " + ("has" if want_key else "has no") + " private-stream key",
                   info.get("type") == "channel_info" and ((got == priv["public_key"]) if want_key else not got),
                   json.dumps(info)[:120] if info.get("type") != "channel_info" else "")

        # --- stream API
        status, _, text = await _get_json(other, ctx, f"/api/streams/{priv['id']}")
        ctx.ok("streams: other user cannot read the private stream", status == 404 and priv["public_key"] not in text,
               f"status {status}")
        status, body, _ = await _get_json(other, ctx, "/api/streams/public")
        ctx.ok("streams: public listing has the public key only for the public stream",
               status == 200 and priv["public_key"] not in json.dumps(body) and pub["public_key"] in json.dumps(body))

        # --- watch page data path for the owner (numeric id, as the watch page does)
        status, body, _ = await _get_json(owner, ctx, f"/api/streams/{priv['id']}")
        ctx.ok("streams: owner's watch-page lookup returns the playback key",
               status == 200 and body.get("stream", {}).get("public_key") == priv["public_key"], f"status {status}")
        status, body, _ = await _get_json(owner, ctx, f"/api/stream/{priv['public_key']}/info")
        ctx.ok("streams: playback info resolves with the playback key", status == 200 and body.get("name"), f"status {status}")

        # --- rotation
        async with other.post(ctx.base_url + f"/api/streams/{priv['id']}/regenerate-public-key") as r:
            await r.read()
            ctx.ok("streams: another user cannot rotate the share link", r.status in (403, 404), f"status {r.status}")
        async with owner.post(ctx.base_url + f"/api/streams/{priv['id']}/regenerate-public-key") as r:
            rot_status = r.status
            try:
                rot = await r.json(content_type=None)
            except Exception:
                rot = {}
        if not isinstance(rot, dict):
            rot = {}
        new_key = rot.get("public_key", "")
        ctx.ok("streams: rotation returns a new playback key",
               rot_status == 200 and new_key.startswith("pub_") and new_key != priv["public_key"],
               f"status {rot_status}")
        status, body, _ = await _get_json(owner, ctx, "/api/streams")
        listed = {s["id"]: s.get("public_key") for s in body.get("streams", [])}
        ctx.ok("streams: owner's listing shows the new key", listed.get(priv["id"]) == new_key)
        status, _, _ = await _get_json(owner, ctx, f"/api/streams/{priv['public_key']}")
        ctx.ok("streams: old key no longer resolves a stream", status == 404, f"status {status}")
        status, _, _ = await _get_json(owner, ctx, f"/api/stream/{priv['public_key']}/info")
        ctx.ok("streams: old key no longer resolves playback info", status in (403, 404), f"status {status}")
        status, _, _ = await _get_json(owner, ctx, f"/api/stream/{new_key}/info")
        ctx.ok("streams: new key resolves playback info", status == 200, f"status {status}")
        status, body, _ = await _get_json(owner, ctx, f"/api/streams/{priv['id']}")
        ctx.ok("streams: watch-page lookup after rotation returns the new key",
               status == 200 and body.get("stream", {}).get("public_key") == new_key)
        if new_key.startswith("pub_"):
            priv["public_key"] = new_key

        # --- public -> private switch rotates the playback key and returns the new one
        old_pub_key = pub["public_key"]
        async with other.put(ctx.base_url + f"/api/streams/{pub['id']}", json={"is_public": False}) as r:
            await r.read()
            ctx.ok("streams: another user cannot switch the stream to private", r.status in (403, 404), f"status {r.status}")
        async with owner.put(ctx.base_url + f"/api/streams/{pub['id']}", json={"name": "smoke pub renamed"}) as r:
            body = await r.json(content_type=None)
            ctx.ok("streams: an update that keeps the stream public keeps its key",
                   r.status == 200 and body.get("stream", {}).get("public_key") == old_pub_key and "public_key" not in body,
                   f"status {r.status}")
        async with owner.put(ctx.base_url + f"/api/streams/{pub['id']}", json={"is_public": False}) as r:
            sw_status = r.status
            sw = await r.json(content_type=None)
        if not isinstance(sw, dict):
            sw = {}
        sw_key = sw.get("public_key", "")
        ctx.ok("streams: switching public to private returns a rotated playback key",
               sw_status == 200 and sw_key.startswith("pub_") and sw_key != old_pub_key
               and sw.get("stream", {}).get("public_key") == sw_key, f"status {sw_status}")
        status, _, _ = await _get_json(owner, ctx, f"/api/stream/{old_pub_key}/info")
        ctx.ok("streams: key from before the switch to private no longer resolves", status in (403, 404), f"status {status}")
        status, _, _ = await _get_json(owner, ctx, f"/api/stream/{sw_key}/info")
        ctx.ok("streams: rotated key resolves for the owner", status == 200, f"status {status}")
        async with owner.put(ctx.base_url + f"/api/streams/{pub['id']}", json={"is_public": False}) as r:
            body = await r.json(content_type=None)
            ctx.ok("streams: repeating the private setting does not rotate again",
                   r.status == 200 and "public_key" not in body and body.get("stream", {}).get("public_key") == sw_key,
                   f"status {r.status}")
        async with owner.put(ctx.base_url + f"/api/streams/{pub['id']}", json={"is_public": True}) as r:
            body = await r.json(content_type=None)
            ctx.ok("streams: switching private to public keeps the key",
                   r.status == 200 and "public_key" not in body and body.get("stream", {}).get("public_key") == sw_key,
                   f"status {r.status}")
        if sw_key.startswith("pub_"):
            pub["public_key"] = sw_key

    # --- dashboard: switching to private must refresh the open details modal with the rotated key
    js_path = Path(__file__).resolve().parents[2] / "static" / "js" / "streams.js"
    try:
        js = js_path.read_text()
    except OSError:
        js = ""
    m = re.search(r"async function toggleStreamPublic\(.*?\n}\n", js, re.S)
    body_js = m.group(0) if m else ""
    ctx.ok("streams: dashboard reads the rotated key after a switch to private",
           "const data = await response.json()" in body_js
           and "data.public_key" in body_js and "showStreamDetails(streamId)" in body_js,
           "toggleStreamPublic must call showStreamDetails when the response carries public_key")

    # --- outgoing webhook payload (in-process, delivery replaced by a recorder)
    rc, out = await ctx.run_py(WEBHOOK % (priv["stream_key"], pub["stream_key"], priv["id"], pub["id"]))
    try:
        calls = _result(out) if rc == 0 else []
    except RuntimeError:
        calls = []
    live = {c[1].get("stream_id"): c[1] for c in calls if c[0] == "stream.live"}
    ctx.ok("streams: stream.live payload for a private stream has no playback key",
           priv["id"] in live and "public_key" not in live[priv["id"]] and "pub_" not in json.dumps(live[priv["id"]]),
           f"{len(calls)} event(s)" if live else out[-300:])
    ctx.ok("streams: stream.live payload for a public stream is unchanged",
           live.get(pub["id"], {}).get("public_key") == pub["public_key"])

    # --- one-time migration: flag-guarded, rotates private keys, scrubs notification rows
    rc, out = await ctx.run_py(READ_STATE % (priv["id"], pub["id"]))
    before = _result(out)
    rc, out = await ctx.run_py(MIGRATE % (st["str_other"], priv["id"], st["str_other"]))
    ctx.ok("streams: migration fixture inserted", rc == 0, "" if rc == 0 else out[-200:])
    rc, out = await ctx.run_py(READ_STATE % (priv["id"], pub["id"]))   # connect() runs the migration
    after = _result(out)
    ctx.ok("streams: migration rotated the private stream key", after["priv"] != before["priv"])
    ctx.ok("streams: migration left the public stream key alone", after["pub"] == before["pub"])
    leak = [r for r in after["rows"] if "legacyleak" in r["data"]]
    keep = [r for r in after["rows"] if "untouched" in r["data"]]
    ctx.ok("streams: migration removed the key from go-live notification rows", not leak and len(keep) == 1)
    ctx.ok("streams: migration set its once-only flag", after["flag"] == "1")
    rc, out = await ctx.run_py(READ_STATE % (priv["id"], pub["id"]))   # second start: must not rotate again
    again = _result(out)
    ctx.ok("streams: migration does not run a second time", again["priv"] == after["priv"] and again["pub"] == after["pub"])
