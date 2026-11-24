"""Stream health and administrator live operations on a running instance.

Over HTTP against the staged server (real logins; the MediaMTX publish hook is posted from loopback, which
is the path MediaMTX uses): the owner and an administrator read GET /api/streams/{id}/health (live, a
recorder section, a list of warnings, the ingest section saying why it is empty because the stage has no
media server and the tick fetches no paths list), while a stream moderator, another member and an unknown
id get the same 404 and a request with no login is refused; a relay with a stored failure shows its error
only as a fixed sentence (no host, no key); the administrator's live list holds the stream and a
non-administrator gets 404; Stop relays and End now write one audit entry each, End now with key
replacement takes the stream offline, the old key is refused by the publish hook, the owner has a
notification without detail, ending a stream that is not live is 409, and the stage never contacts a
media server (publisher_disconnected is false with the staged-instance note).

Users and streams carry random suffixes and every assertion is about those rows, so the module also holds
on a stage started from a copy of a production database. It creates its own administrator (no admin
password needed). The relay it stores is switched off, so nothing is dialled.

Not proven here (needs the real thing): a real MediaMTX (kick routes are covered by tests with a fake of
the captured v1.21.3 API), bitrate numbers from a live publisher, a browser, OBS.
"""
import json
import secrets

PW = "Streamhealth-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "mod", "member", "adm"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.set_user_role(out["users"]["adm"], "admin")
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

RELAY = r'''
import asyncio, json
from database import db

P = json.loads(%(params)r)

async def main():
    await db.connect()
    rel = await db.create_relay_destination(P["sid"], "custom", "smoke relay", "rtmp://relay-host.invalid/app", "SMOKESECRETKEY99")
    await db.conn.execute("UPDATE stream_relay_destinations SET enabled = 0 WHERE id = ?", (rel["id"],))
    await db.conn.commit()
    await db.update_relay_last_error(rel["id"], "Exit code 1: rtmp://relay-host.invalid/app/[KEY_REDACTED]: Connection refused")
    await db.close()
    print("RESULT " + json.dumps({"id": rel["id"]}))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    pre = "sh" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    res = _result(out)
    if rc != 0 or res is None:
        ctx.ok("streamhealth: setup", False, out[-500:])
        return
    uid = res["users"]
    base = ctx.base_url

    def ok(name, passed, detail=""):
        ctx.ok("streamhealth: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            raw = await r.read()
            try:
                return r.status, json.loads(raw), raw
            except Exception:
                return r.status, None, raw

    async with ctx.http() as owner, ctx.http() as mod, ctx.http() as member, ctx.http() as adm, ctx.http() as anon, ctx.http() as hk:
        for name, sess in (("owner", owner), ("mod", mod), ("member", member), ("adm", adm)):
            resp = await ctx.login(sess, pre + name, PW)
            if resp.status != 200:
                ok(name + " can sign in", False, str(resp.status))
                return
        st, b, _ = await call(owner, "POST", "/api/streams", json={"name": pre + "s", "is_public": False})
        if st != 201:
            ok("the stream is created", False, f"{st} {b}")
            return
        stream = b["stream"]
        sid, key = stream["id"], stream["stream_key"]
        st, b, _ = await call(owner, "POST", f"/api/streams/{sid}/mods", json={"user_id": uid["mod"]})
        ok("a stream moderator is appointed", st in (200, 201), f"{st} {b}")

        async def publish(k):
            async with hk.post(base + "/api/stream/auth", json={"action": "publish", "path": "live/" + k, "password": k,
                                                                "ip": "127.0.0.1"}) as r:
                return r.status
        ok("the stream goes live", await publish(key) == 200)

        # ---- who may read the health
        st_o, d_o, _ = await call(owner, "GET", f"/api/streams/{sid}/health")
        ok("the owner reads the health", st_o == 200 and d_o and d_o["live"] is True and isinstance(d_o["warnings"], list)
           and "recorder" in d_o and "relays" in d_o, f"{st_o} {d_o}")
        ok("the ingest section says why it is empty", d_o and d_o["ingest"]["available"] is False and d_o["ingest"].get("reason"),
           str(d_o and d_o.get("ingest")))
        st_a, d_a, _ = await call(adm, "GET", f"/api/streams/{sid}/health")
        ok("an administrator reads it too", st_a == 200 and d_a and d_a["stream_id"] == sid, f"{st_a}")
        st_u, _, raw_u = await call(owner, "GET", f"/api/streams/{99999000 + int(secrets.token_hex(2), 16)}/health")
        outs = [await call(mod, "GET", f"/api/streams/{sid}/health"), await call(member, "GET", f"/api/streams/{sid}/health")]
        ok("a stream moderator and another member get the same 404 as an unknown stream",
           st_u == 404 and all(s == 404 and raw == raw_u for s, _b, raw in outs), f"{st_u} {[(s, raw) for s, _b, raw in outs]}")
        st_n, _, _ = await call(anon, "GET", f"/api/streams/{sid}/health")
        ok("no login is refused", st_n in (401, 403), str(st_n))

        # ---- a stored relay failure is shown as a fixed sentence
        rc, out = await ctx.run_py(RELAY % {"params": json.dumps({"sid": sid})}, timeout=60)
        ok("a switched-off relay with a stored failure is added", rc == 0 and _result(out) is not None, out[-300:])
        st, d, raw = await call(owner, "GET", f"/api/streams/{sid}/health")
        relay = (d or {}).get("relays", [{}])[0] if st == 200 and d and d.get("relays") else {}
        ok("its error is a fixed sentence with no host and no key",
           relay.get("last_error", "").startswith("The destination refused the connection.")
           and all(x not in raw.decode() for x in ("relay-host", "SMOKESECRET", "rtmp://", "KEY_REDACTED")), str(relay))

        # ---- the administrator's list and actions
        st, d, _ = await call(adm, "GET", "/api/admin/live-streams")
        mine = [r for r in (d or {}).get("streams", []) if r["id"] == sid]
        ok("the live list holds the stream with its owner", st == 200 and len(mine) == 1 and mine[0]["owner"] == pre + "owner", f"{st}")
        for name, sess in (("the owner", owner), ("a moderator", mod), ("a member", member)):
            st, _, _ = await call(sess, "GET", "/api/admin/live-streams")
            ok(name + " gets 404 for the live list", st == 404, str(st))
            st, _, _ = await call(sess, "POST", f"/api/admin/streams/{sid}/end", json={})
            ok(name + " gets 404 for End now and nothing happens", st == 404, str(st))
        st, d, _ = await call(owner, "GET", f"/api/streams/{sid}")
        ok("the stream is still live", d and d["stream"]["is_live"] == 1, str(st))

        st, d, _ = await call(adm, "POST", f"/api/admin/streams/{sid}/stop-relays", json={})
        ok("Stop relays answers", st == 200 and d and d["success"] is True and d["stopped"] == 0, f"{st} {d}")
        st, d, _ = await call(adm, "GET", "/api/admin/audit-log?action=stream_stop_relays&limit=200")
        rows = [e for e in (d or {}).get("entries", d.get("logs", []) if d else []) if e.get("target_id") == sid]
        ok("Stop relays wrote one audit entry", len(rows) == 1, f"{st} {len(rows)} {list((d or {}).keys())}")

        st, d, _ = await call(adm, "POST", f"/api/admin/streams/{sid}/end", json={"regenerate_key": True})
        ok("End now answers and does not contact a media server on the stage",
           st == 200 and d and d["success"] is True and d["publisher_disconnected"] is False and "staged" in (d.get("disconnect_note") or ""), f"{st} {d}")
        st, d2, _ = await call(owner, "GET", f"/api/streams/{sid}")
        ok("the stream is offline and has a new key", d2 and d2["stream"]["is_live"] == 0 and d2["stream"]["stream_key"] != key, str(st))
        ok("a publisher with the old key is refused", await publish(key) == 401)
        st, d, _ = await call(adm, "GET", "/api/admin/audit-log?action=stream_end_now&limit=200")
        rows = [e for e in (d or {}).get("entries", d.get("logs", []) if d else []) if e.get("target_id") == sid]
        ok("End now wrote one audit entry that names the administrator", len(rows) == 1 and rows[0].get("actor_username") == pre + "adm", f"{st} {len(rows)}")
        st, d, raw = await call(owner, "GET", "/api/notifications?limit=100")
        notes = [n for n in (d or {}).get("notifications", []) if n.get("type") == "stream_ended"]
        ok("the owner has a notification without detail", len(notes) == 1 and notes[0]["message"] == "An administrator ended your stream."
           and key not in raw.decode(), f"{st} {notes}")
        st, _, _ = await call(adm, "POST", f"/api/admin/streams/{sid}/end", json={})
        ok("ending a stream that is not live is 409", st == 409, str(st))
        st, d, _ = await call(owner, "GET", f"/api/streams/{sid}/health")
        ok("the health of an offline stream says so", st == 200 and d["live"] is False and d["ingest"]["available"] is False, str(st))
