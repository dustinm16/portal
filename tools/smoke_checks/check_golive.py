"""Go-live announcement on a running instance: one per cooldown, the owner's message, a payload
with no key, and who is told.

Over HTTP (the real server, real logins, the MediaMTX publish hook POST /api/stream/auth from
loopback, which is the path MediaMTX uses): the owner edits the go-live message (200), a member
may not (404), a 201-character message and a multi-megabyte one are refused (400), control characters are
stripped, a message with double quotes is stored and read back as typed; an
encoder that restarts three times announces once (one notification per viewer), the watch URL in
it is built from the configured host and not from the request's Host header, '{0.__class__}'
renders literally; a private stream notifies its administrators and nobody else; no notification
carries a stream key, a pub_ key or an RTMP address.

In-process (ctx.run_py, the real handlers and the stage database, webhook delivery replaced by a
recorder so nothing is sent): the cooldown set by the running server is still in force in a fresh
process (it is stored, not held in memory); five concurrent publishes announce once; a public
stream reaches a system hook and a member's own hook, a private stream only the system hook; the
payload has the streamer, title and watch URL and no key.

Users, streams and hooks carry random suffixes and every assertion is about those rows (the
copy of a production database has many other users and hooks), so the module also holds on a
stage started from such a copy. It needs no admin password.

Not proven here (needs the real thing): a real MediaMTX retrying its hook, OBS reconnecting, a
real Discord or ntfy post, the page in a browser.
"""
import json
import secrets

PW = "Golive-smoke-pw-1"
LIVE_MSG = "{streamer} plays {title} at {url} {0.__class__}"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user
import server

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}, "streams": {}}
    for name in ("owner", "member", "adm"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.set_user_role(out["users"]["adm"], "admin")
    for label, public in (("pub", True), ("priv", False)):
        sk, pk = server.generate_stream_key(), server.generate_public_key()
        sid = await db.create_user_stream(user_id=out["users"]["owner"], name=P["pre"] + label, stream_key=sk,
                                          public_key=pk, is_public=public)
        out["streams"][label] = {"id": sid, "live": sk, "pub": pk}
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

OFFLINE = r'''
import asyncio
from database import db

async def main():
    await db.connect()
    await db.set_stream_live(%(sid)d, False)
    await db.close()
    print("RESULT {}")

asyncio.run(main())
'''

INPROC = r'''
import asyncio, json
from unittest import mock
from database import db
import server

P = json.loads(%(params)r)

class Req:
    def __init__(self, body):
        self._body = body
        self.transport = mock.Mock()
        self.transport.get_extra_info.return_value = ("127.0.0.1", 1)
        self.headers = {}
        self.remote = "127.0.0.1"
    async def json(self):
        return self._body

async def drain():
    for _ in range(5):
        await asyncio.sleep(0)
    pend = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()
            and ("fire_webhook_event" in repr(t.get_coro()) or "_deliver_webhook" in repr(t.get_coro()))]
    if pend:
        await asyncio.gather(*pend, return_exceptions=True)

async def main():
    await db.connect()
    server.db = db
    S = P["streams"]
    sent = []

    async def rec(webhook, event, payload, attempt=1, **kw):
        sent.append([webhook["id"], event, payload])
        return {"sent": True, "success": True}

    async def noop(*a, **kw):
        return None
    server._deliver_webhook = rec
    server.start_vod_recording = noop
    server.start_stream_relays = noop

    sysh = await db.create_webhook(None, P["pre"] + "sys", "outgoing", url="https://93.184.216.34/h",
                                   events=["stream.live"], kind="system", created_by=P["users"]["adm"])
    mine = await db.create_webhook(P["users"]["member"], P["pre"] + "mine", "outgoing",
                                   url="https://93.184.216.34/m", events=["stream.live"])
    out = {"sys": sysh["id"], "mine": mine["id"]}

    # the server process announced these streams a moment ago: the cooldown is in the database
    out["claim_after_http"] = {k: await db.claim_golive(S[k]["id"], int(__import__("time").time()), 600) for k in S}

    async def publish(label):
        await db.set_stream_live(S[label]["id"], False)
        await db.conn.execute("UPDATE user_streams SET golive_announced_at = NULL WHERE id = ?", (S[label]["id"],))
        await db.conn.commit()
        rs = await asyncio.gather(*[server.http_stream_auth(Req(
            {"action": "publish", "path": "live/" + S[label]["live"], "password": S[label]["live"], "ip": "127.0.0.1"}))
            for _ in range(5)])
        await drain()
        return [r.status for r in rs]

    for label in ("pub", "priv"):
        sent.clear()
        out[label + "_status"] = await publish(label)
        mine_hooks = [x for x in sent if x[0] in (out["sys"], out["mine"]) and x[1] == "stream.live"
                      and x[2].get("stream_id") == S[label]["id"]]
        out[label + "_sys"] = len([x for x in mine_hooks if x[0] == out["sys"]])
        out[label + "_mine"] = len([x for x in mine_hooks if x[0] == out["mine"]])
        out[label + "_payload"] = next((x[2] for x in mine_hooks if x[0] == out["sys"]), None)
    for hook_id in (out["sys"], out["mine"]):
        await db.conn.execute("DELETE FROM webhooks WHERE id = ?", (hook_id,))
    await db.conn.commit()
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    pre = "gl" + secrets.token_hex(3)
    params = json.dumps({"pw": PW, "pre": pre})
    rc, out = await ctx.run_py(SETUP % {"params": params}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("go-live: setup", False, out[-500:])
        return
    S, U = data["streams"], data["users"]
    pub, priv = S["pub"], S["priv"]

    def ok(name, passed, detail=""):
        ctx.ok("go-live: " + name, bool(passed), "" if passed else detail)

    async def notes(sess, sid):
        async with sess.get(ctx.base_url + "/api/notifications?limit=100") as r:
            body = await r.json(content_type=None)
        rows = [n for n in body.get("notifications", []) if n.get("type") == "stream_live"
                and f'"stream_id": {sid}' in (n.get("data") or "")]
        return rows

    async def publish(sess, s):
        async with sess.post(ctx.base_url + "/api/stream/auth", headers={"Host": "evil.example.invalid"},
                             json={"action": "publish", "path": "live/" + s["live"], "password": s["live"],
                                   "ip": "127.0.0.1"}) as r:
            return r.status

    async with ctx.http() as owner, ctx.http() as member, ctx.http() as adm, ctx.http() as hook:
        for name, sess in (("owner", owner), ("member", member), ("adm", adm)):
            resp = await ctx.login(sess, pre + name, PW)
            if resp.status != 200:
                ok(name + " can sign in", False, str(resp.status))
                return

        # ---- the owner's message
        async def put(sess, sid, body):
            async with sess.put(f"{ctx.base_url}/api/streams/{sid}", json=body) as r:
                return r.status, await r.json(content_type=None)

        st, b = await put(owner, pub["id"], {"golive_message": LIVE_MSG})
        ok("the owner sets a go-live message", st == 200, f"{st} {b}")
        st, b = await put(member, pub["id"], {"golive_message": "hijacked"})
        ok("another member cannot set it (404)", st == 404, f"{st} {b}")
        st, b = await put(owner, pub["id"], {"golive_message": "x" * 201})
        ok("201 characters are refused (400)", st == 400, f"{st} {b}")
        st, b = await put(owner, pub["id"], {"golive_message": "x" * 2000})
        ok("a 2000-character message is refused (400) before it is cleaned", st == 400, f"{st} {b}")
        st, b = await put(owner, pub["id"], {"golive_message": "\x00" * 5_000_000})
        ok("a 5 MB message of control characters is refused (400)", st == 400, f"{st}")
        quoted = 'Come watch "{title}" now'
        st, b = await put(owner, priv["id"], {"golive_message": quoted})
        ok("a message with double quotes is stored as typed",
           st == 200 and (b.get("stream") or b).get("golive_message") == quoted, f"{st} {b}")
        async with owner.get(f"{ctx.base_url}/api/streams/{priv['id']}") as r:
            one = (await r.json(content_type=None)).get("stream", {})
        ok("and read back unchanged for the settings screen", one.get("golive_message") == quoted, str(one.get("golive_message")))
        st, b = await put(owner, pub["id"], {"golive_message": 5})
        ok("a non-string message is refused (400)", st == 400, f"{st} {b}")
        st, b = await put(owner, priv["id"], {"golive_message": "go\x00 live\x1b[0m {title}"})
        ok("control characters are stripped from a saved message",
           st == 200 and (b.get("stream") or b).get("golive_message", "") == "go live[0m {title}", f"{st} {b}")
        async with owner.get(ctx.base_url + "/api/streams") as r:
            listed = {s["id"]: s for s in (await r.json(content_type=None)).get("streams", [])}
        ok("the owner's stream list returns the saved message",
           listed.get(pub["id"], {}).get("golive_message") == LIVE_MSG, str(listed.get(pub["id"], {}).get("golive_message")))

        # ---- a public stream: three encoder restarts within the cooldown
        for cycle in range(3):
            if cycle:
                rc, out = await ctx.run_py(OFFLINE % {"sid": pub["id"]})
                ok(f"stream taken offline before restart {cycle}", rc == 0, out[-200:])
            status = await publish(hook, pub)
            ok(f"publish hook accepts the public stream (start {cycle + 1})", status == 200, str(status))
        rows_m, rows_a, rows_o = await notes(member, pub["id"]), await notes(adm, pub["id"]), await notes(owner, pub["id"])
        ok("three starts give each member one notification", len(rows_m) == 1 and len(rows_a) == 1,
           f"{len(rows_m)} {len(rows_a)}")
        ok("the owner is not notified of their own stream", not rows_o, str(len(rows_o)))
        if rows_m:
            msg = rows_m[0]["message"]
            ok("the message is the owner's template, filled", msg.startswith(f"{pre}owner plays {pre}pub at ")
               and msg.endswith("{0.__class__}") and f"/watch/{pub['id']}" in msg, msg)
            ok("the watch URL is not built from the Host header", "evil.example" not in msg
               and "evil.example" not in rows_m[0]["data"], msg)
        text = json.dumps(rows_m + rows_a)
        ok("no notification carries a stream key, a pub_ key or an RTMP address",
           all(x not in text for x in (pub["live"], pub["pub"], priv["live"], priv["pub"], "live_", "pub_", "rtmp")), text[:300])

        # ---- a private stream: only those who may watch it
        for cycle in range(2):
            if cycle:
                await ctx.run_py(OFFLINE % {"sid": priv["id"]})
            await publish(hook, priv)
        pm, pa, po = await notes(member, priv["id"]), await notes(adm, priv["id"]), await notes(owner, priv["id"])
        ok("a private stream notifies its administrator once", len(pa) == 1, str(len(pa)))
        ok("a private stream notifies no ordinary member and not its owner", not pm and not po, f"{len(pm)} {len(po)}")
        ok("the private stream's notification has no key", all(
            x not in json.dumps(pa) for x in (priv["live"], priv["pub"], "pub_", "live_")))

    # ---- in-process: the stored cooldown, concurrency, hooks and payload
    rc, out = await ctx.run_py(INPROC % {"params": json.dumps({"pre": pre, "streams": S, "users": U})}, timeout=180)
    r = _result(out) if rc == 0 else None
    if r is None:
        ok("in-process checks ran", False, out[-500:])
        return
    ok("the cooldown set by the server process holds in another process (stored)",
       r["claim_after_http"] == {"pub": False, "priv": False}, str(r["claim_after_http"]))
    ok("five concurrent publishes are all accepted", r["pub_status"] == [200] * 5 and r["priv_status"] == [200] * 5,
       str((r["pub_status"], r["priv_status"])))
    ok("five concurrent publishes of a public stream reach the system hook and a member's hook once each",
       r["pub_sys"] == 1 and r["pub_mine"] == 1, f"{r['pub_sys']} {r['pub_mine']}")
    ok("a private stream reaches the system hook once and no member's own hook",
       r["priv_sys"] == 1 and r["priv_mine"] == 0, f"{r['priv_sys']} {r['priv_mine']}")
    pl = r["pub_payload"] or {}
    body = json.dumps(pl)
    ok("the payload has the streamer, title and watch URL",
       pl.get("streamer") == pre + "owner" and pl.get("title") == pre + "pub"
       and pl.get("url", "").endswith(f"/watch/{pub['id']}") and pl["url"].startswith("http"), body[:300])
    ok("the payload has no key and no stream address",
       all(x not in body for x in (pub["live"], pub["pub"], "live_", "pub_", "rtmp", "public_key", "stream_key")), body[:300])
