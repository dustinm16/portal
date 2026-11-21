"""Per-channel retention and the manual prune on a running instance.

Over HTTP and the chat websocket against the staged server (real logins): an administrator sets one
channel to "forever" (the cap) and another to 2 days (the shortening is first answered with the count
and applied only with confirm), a moderator cannot set it; "run cleanup now" (a superadmin made by the
setup step) keeps the capped channel's old message and prunes the 2 day channel's old message with its
file and search row, pinned and fresh messages stay; a global moderator prunes one user's messages of
the last hour after a dry run, a second connected viewer receives messages_pruned with exactly those
ids, the pinned one survives, exactly one audit entry is written, a wrong count is 409, a member and a
member of nothing get the 404 of a missing channel, and a user filter does not reach an anonymous post.

Users and channels carry random suffixes and every assertion is about those rows, so the module also
holds on a stage started from a copy of a production database. The cleanup run is the stage's own
(on a copy it also runs the other retention steps, which is what a real cleanup does).

On a stage started from a copy of a production database, "run cleanup now" also runs every other retention
step and decrypts all message text once for the upload reference check; its request has a 150 second
timeout for that.

Not proven here (needs the real thing): a browser rendering the windows, the periodic task firing on its
own interval (run cleanup now is the same function), a very large channel.
"""
import asyncio
import json
import secrets
import time

import aiohttp

PW = "Retention-smoke-pw-1"

SETUP = r'''
import asyncio, json, os
from datetime import datetime, timedelta, timezone
from database import db, encrypt_message
from auth import create_user

P = json.loads(%(params)r)

def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()

async def msg(ch, uid, uname, text, when, pinned=False, upload=None, anonymous=False):
    kw = {}
    if upload:
        kw = {"attachment_url": "/static/uploads/chat/" + upload, "attachment_name": "a.bin", "attachment_type": "application/zip"}
    mid = await db.create_chat_message(ch, uid, uname, text, anonymous=anonymous, **kw)
    await db.conn.execute("UPDATE chat_messages SET created_at = ?, is_pinned = ? WHERE id = ?", (when, 1 if pinned else 0, mid))
    await db.conn.execute("UPDATE chat_fts_map SET created_at = ? WHERE message_id = ?", (when, mid))
    await db.conn.commit()
    return mid

async def main():
    await db.connect()
    pre = P["pre"]
    out = {"users": {}, "ch": {}, "m": {}}
    for name in ("sadmin", "adm", "gmod", "viewer", "talker", "outsider"):
        out["users"][name] = (await create_user(pre + name, P["pw"]))["id"]
    u = out["users"]
    await db.set_user_role(u["sadmin"], "superadmin")
    await db.set_user_role(u["adm"], "admin")
    await db.set_user_role(u["gmod"], "moderator")
    for key in ("capped", "short", "prune", "private"):
        out["ch"][key] = await db.create_chat_channel(pre + "-" + key, created_by=u["adm"])
    await db.update_chat_channel(out["ch"]["private"], visibility="private")
    await db.add_channel_member(out["ch"]["private"], u["talker"], role="member", added_by=u["adm"])
    os.makedirs(db.chat_upload_dir, exist_ok=True)
    files = {}
    for key in ("short_old", "short_pinned"):
        files[key] = P[key + "_name"]
        with open(os.path.join(db.chat_upload_dir, files[key]), "wb") as f:
            f.write(b"x" * 16)
    out["files"] = files
    c = out["ch"]
    m = out["m"]
    m["capped_old"] = await msg(c["capped"], u["talker"], pre + "talker", pre + " kept forever", ago(days=100))
    m["short_old"] = await msg(c["short"], u["talker"], pre + "talker", pre + " old news", ago(days=3), upload=files["short_old"])
    m["short_pinned"] = await msg(c["short"], u["talker"], pre + "talker", pre + " pinned old", ago(days=30), pinned=True, upload=files["short_pinned"])
    m["short_new"] = await msg(c["short"], u["talker"], pre + "talker", pre + " fresh", ago(days=1))
    m["spam"] = [await msg(c["prune"], u["talker"], pre + "talker", pre + " spam %%d" %% i, ago(minutes=10 + i)) for i in range(4)]
    m["anon"] = await msg(c["prune"], u["talker"], pre + "talker", pre + " hidden", ago(minutes=12), anonymous=True)
    m["pinned"] = await msg(c["prune"], u["talker"], pre + "talker", pre + " pinned spam", ago(minutes=11), pinned=True)
    m["other"] = await msg(c["prune"], u["viewer"], pre + "viewer", pre + " somebody else", ago(minutes=9))
    m["old"] = await msg(c["prune"], u["talker"], pre + "talker", pre + " yesterday", ago(hours=30))
    m["private"] = await msg(c["private"], u["talker"], pre + "talker", pre + " private", ago(minutes=5))
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

VERIFY = r'''
import asyncio, json, os
from database import db

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {}
    cur = await db.conn.execute("SELECT id, is_pinned FROM chat_messages WHERE channel_id IN (?, ?, ?, ?)", tuple(P["channels"]))
    out["rows"] = {r["id"]: r["is_pinned"] for r in await cur.fetchall()}
    cur = await db.conn.execute("SELECT message_id FROM chat_fts_map WHERE channel_id IN (?, ?, ?, ?)", tuple(P["channels"]))
    out["map"] = [r["message_id"] for r in await cur.fetchall()]
    out["files"] = {k: os.path.exists(os.path.join(db.chat_upload_dir, v)) for k, v in P["files"].items()}
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
    pre = "rt" + secrets.token_hex(3)
    names = {"short_old_name": secrets.token_hex(16) + ".zip", "short_pinned_name": secrets.token_hex(16) + ".zip"}
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre, **names})}, timeout=120)
    res = _result(out) if rc == 0 else None
    if res is None:
        ctx.ok("retention: setup", False, out[-500:])
        return
    u, c, m, files = res["users"], res["ch"], res["m"], res["files"]
    base = ctx.base_url

    def ok(name, passed, detail=""):
        ctx.ok("retention: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def verify():
        rc2, out2 = await ctx.run_py(VERIFY % {"params": json.dumps({"channels": [c["capped"], c["short"], c["prune"], c["private"]], "files": files})}, timeout=120)
        return _result(out2) if rc2 == 0 else None

    sockets = []
    async with ctx.http() as sadmin, ctx.http() as adm, ctx.http() as gmod, ctx.http() as viewer, ctx.http() as outsider:
        sess = {"sadmin": sadmin, "adm": adm, "gmod": gmod, "viewer": viewer, "outsider": outsider}
        try:
            for name, s in sess.items():
                resp = await ctx.login(s, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return

            # ---- retention settings
            st, _ = await call(gmod, "PUT", f"/api/chat/channels/{c['short']}/retention", json={"retention_days": 2, "confirm": True})
            ok("a moderator cannot set a channel's retention (403)", st == 403, str(st))
            st, r = await call(adm, "PUT", f"/api/chat/channels/{c['capped']}/retention", json={"retention_days": "forever"})
            ok("an administrator sets a channel to forever, stored as the cap",
               st == 200 and r["applied"] and r["retention_days"] == r["cap_days"], f"{st} {r}")
            st, r = await call(adm, "PUT", f"/api/chat/channels/{c['short']}/retention", json={"retention_days": 2})
            ok("shortening is answered with the count and not applied",
               st == 200 and r["applied"] is False and r["confirm_required"] and r["would_remove_messages"] == 1, f"{st} {r}")
            st, r = await call(adm, "PUT", f"/api/chat/channels/{c['short']}/retention", json={"retention_days": 2, "confirm": True})
            ok("with confirm it is applied", st == 200 and r["applied"] and r["retention_days"] == 2, f"{st} {r}")
            st, r = await call(adm, "PUT", f"/api/chat/channels/{c['short']}/retention", json={"file_retention_days": 9, "confirm": True})
            ok("a file retention longer than the message retention is refused", st == 400, f"{st} {r}")
            st, r = await call(viewer, "GET", "/api/chat/channels")
            row = next((x for x in (r or {}).get("channels", []) if x["id"] == c["short"]), None)
            ok("the channel list carries the value for a member", row and row.get("retention_days") == 2, str(row))
            st, r = await call(gmod, "GET", f"/api/admin/audit-log?action=channel_retention_change&channel_id={c['short']}")
            entries = (r or {}).get("entries") or (r or {}).get("logs") or []
            ok("exactly one retention change is audited for the channel", st == 200 and len(entries) == 1, f"{st} {str(r)[:300]}")

            # ---- the cleanup
            before = await verify()
            ok("before the cleanup every message exists", before and all(str(i) in {str(k) for k in before["rows"]}
               for i in (m["capped_old"], m["short_old"], m["short_pinned"], m["short_new"])), str(before and before["rows"]))
            # on a copy of a production database this runs every step and reads the text of every message once
            # (the upload reference check), so it gets a longer timeout than the session default
            st, r = await call(sadmin, "POST", "/api/admin/retention/run",
                               timeout=aiohttp.ClientTimeout(total=150))
            ok("run cleanup now answers", st == 200, f"{st} {str(r)[:200]}")
            after = await verify()
            rows = {int(k): v for k, v in (after or {"rows": {}})["rows"].items()}
            ok("the channel at the cap keeps its 100 day old message", m["capped_old"] in rows, str(rows))
            ok("the 2 day channel lost its 3 day old message", m["short_old"] not in rows)
            ok("... and its pinned and fresh messages stay", m["short_pinned"] in rows and m["short_new"] in rows)
            ok("... its search row is gone and the others stay", m["short_old"] not in after["map"] and m["short_new"] in after["map"])
            ok("... its file is gone, the pinned message's file stays", after["files"]["short_old"] is False and after["files"]["short_pinned"] is True, str(after["files"]))

            # ---- prune
            path = f"/api/chat/channels/{c['prune']}/prune"
            now = time.time()
            body = {"from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600)),
                    "to": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 60)), "user": pre + "talker"}
            ws = await viewer.ws_connect(f"{base}/ws/chat", max_msg_size=0)
            events = []
            sockets.append(ws)

            async def pump():
                try:
                    async for msg in ws:
                        try:
                            events.append(json.loads(msg.data))
                        except Exception:
                            pass
                except Exception:
                    pass
            pump_task = asyncio.ensure_future(pump())
            await ws.send_json({"type": "join", "channel_id": c["prune"]})
            for _ in range(60):
                if any(e.get("type") == "history" for e in events):
                    break
                await asyncio.sleep(0.1)
            ok("a second viewer is in the channel", any(e.get("type") == "history" for e in events), str(events[:2]))
            st, r = await call(outsider, "POST", path, json={**body, "dry_run": True})
            ok("a member with no moderator level gets the 404 of a missing channel", st == 404, f"{st} {r}")
            st, r = await call(gmod, "POST", f"/api/chat/channels/{c['private']}/prune", json={**body, "dry_run": True})
            ok("a global moderator who is not in a private channel gets 404", st == 404, f"{st} {r}")
            st, r = await call(gmod, "POST", path, json={**body, "dry_run": True})
            ok("the dry run counts the user's four messages of the last hour (pinned and anonymous left out)",
               st == 200 and r["count"] == 4, f"{st} {r}")
            st, r = await call(gmod, "POST", path, json={**body, "expected_count": 40})
            ok("a wrong count is 409", st == 409, f"{st} {r}")
            st, r = await call(gmod, "POST", path, json={**body, "expected_count": 4})
            ok("the real run is accepted", st == 202 and r["count"] == 4, f"{st} {r}")
            state = {}
            for _ in range(100):
                st, state = await call(gmod, "GET", path)
                if st == 200 and state and state.get("running") is False:
                    break
                await asyncio.sleep(0.1)
            ok("the prune finished", state and state.get("status") == "completed" and state.get("removed") == 4, str(state))
            for _ in range(30):
                if sum(len(e["ids"]) for e in events if e.get("type") == "messages_pruned") >= 4:
                    break
                await asyncio.sleep(0.1)
            got = {i for e in events if e.get("type") == "messages_pruned" for i in e["ids"]}
            ok("the other viewer got messages_pruned with exactly the removed ids", got == set(m["spam"]), str(got))
            after = await verify()
            rows = {int(k) for k in after["rows"]}
            ok("the user's messages are gone, pinned, anonymous, other and older ones stay",
               not (set(m["spam"]) & rows) and {m["pinned"], m["anon"], m["other"], m["old"]} <= rows, str(rows))
            ok("their search rows are gone too", not (set(m["spam"]) & set(after["map"])))
            st, r = await call(gmod, "GET", f"/api/admin/audit-log?action=chat_prune&channel_id={c['prune']}")
            entries = (r or {}).get("entries") or (r or {}).get("logs") or []
            ok("exactly one audit entry for the prune", st == 200 and len(entries) == 1, f"{st} {str(r)[:300]}")
            pump_task.cancel()
        finally:
            for w in sockets:
                try:
                    await w.close()
                except Exception:
                    pass
