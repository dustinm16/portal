"""Smoke check: the VOD disk guard settings and the refusal a streamer and My VODs can see.

A stage has no MediaMTX stream, so the refusal runs in-process (ctx.run_py) against the staged
database with the real start_vod_recording: with the free-space floor above what is free a new
recording is refused, no folder and no ffmpeg start, the owner's activity log says why, the state
that My VODs shows is set and exactly one alert is raised however often the stream reconnects.
The settings round trip (GET and PUT /api/admin/retention) needs the superadmin of the stage and is
skipped when no admin password is known. Users carry random suffixes; no shared count is assumed, and
the settings the check changes are put back.

Not proven here: a real ffmpeg stopped by the guard (tests/test_vod_guard.py does that), a browser.
"""
import json
import secrets

PW = "vodguard-smoke-pw-1"

SCRIPT = r'''
import asyncio, json, os
from unittest import mock
from database import db
import server, vod_staging, alerts
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    server.db = db
    uid = (await create_user(P["pre"] + "owner", P["pw"]))["id"]
    out = {}
    cfg = await db.get_retention_config()
    out["defaults_present"] = all(k in cfg for k in ("vod_min_free_gb", "vod_max_backlog_gb", "vod_orphan_max_age_days"))
    fired = []
    async def fire(event, payload):
        fired.append(event)
        return 1
    async def notify(*a):
        pass
    alerts.reset_state()
    alerts.bind(fire=fire, notify=notify)
    real_storage = db.get_vod_storage
    async def storage(u):
        return {"remote_path": "/vods", "host": "127.0.0.1", "port": 22} if u == uid else await real_storage(u)
    async def mtx():
        return {"x": 1}
    async def no_exec(*a, **k):
        raise AssertionError("ffmpeg must not start")
    saved = {k: await db.get_setting(k) for k in ("vod_min_free_gb", "vod_max_backlog_gb")}
    await db.set_retention_config({"vod_min_free_gb": "1000000", "vod_max_backlog_gb": "0"})
    stream = {"id": 987001, "user_id": uid, "name": "Guard Smoke", "owner_username": P["pre"] + "owner"}
    before = sorted(os.listdir(server.VOD_TEMP_DIR))
    try:
        with mock.patch.object(db, "get_vod_storage", storage), \
                mock.patch.object(server, "_get_mediamtx_config", mtx), \
                mock.patch.object(server.asyncio, "create_subprocess_exec", no_exec):
            await server.start_vod_recording(stream, "live_guard_smoke")
            await server.start_vod_recording(stream, "live_guard_smoke")
    finally:
        for k, v in saved.items():
            if v is None:
                await db.conn.execute("DELETE FROM settings WHERE key = ?", (k,))
            else:
                await db.set_setting(k, v)
        await db.conn.commit()
    await asyncio.sleep(0.3)
    out["not_started"] = 987001 not in server.active_recordings
    out["no_folder"] = sorted(os.listdir(server.VOD_TEMP_DIR)) == before
    cur = await db.conn.execute("SELECT action, detail FROM activity_log WHERE user_id = ?", (uid,))
    rows = [dict(r) for r in await cur.fetchall()]
    out["activity"] = [r for r in rows if r["action"] == "vod_skipped"]
    out["public"] = server._vod_guard_public(uid)
    out["alerts"] = [e for e in fired if e == "vod.recording_stopped"]
    out["limits_back"] = (await server._vod_guard_limits())[0] != 1000000 * 1024 ** 3
    print("RESULT " + json.dumps(out))
    await db.close()

asyncio.run(main())
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("no RESULT line in: " + out[-300:])


async def run(ctx):
    pre = "vg" + secrets.token_hex(3) + "-"
    code = SCRIPT % {"params": json.dumps({"pre": pre, "pw": PW})}
    rc, out = await ctx.run_py(code)
    try:
        r = _result(out)
    except RuntimeError as e:
        ctx.ok("vodguard: refusal scenario ran", False, str(e))
        r = None
    if r is not None:
        ctx.ok("vodguard: the three new settings are part of the retention settings", r["defaults_present"] is True)
        ctx.ok("vodguard: below the free-space floor a new recording is refused (no ffmpeg, no folder)",
               r["not_started"] and r["no_folder"], str(r)[:200])
        ctx.ok("vodguard: the refusal and its reason are in the owner's activity log",
               len(r["activity"]) >= 1 and all("was not started" in a["detail"] and "free" in a["detail"] for a in r["activity"]),
               str(r["activity"])[:200])
        ctx.ok("vodguard: My VODs gets the refusal as recording_guard (kind, code, message)",
               bool(r["public"]) and r["public"]["kind"] == "refused" and r["public"]["code"] == "low_free_space"
               and "free" in r["public"]["message"], str(r["public"])[:200])
        ctx.ok("vodguard: one admin alert however often the stream reconnects", r["alerts"] == ["vod.recording_stopped"], str(r["alerts"]))
        ctx.ok("vodguard: the settings the check changed were put back", r["limits_back"] is True)

    if not ctx.admin_password:
        ctx.skip("vodguard: settings round trip through /api/admin/retention", "no admin password known")
        return
    async with ctx.http() as s:
        resp = await ctx.login(s, ctx.admin_user, ctx.admin_password)
        if resp.status != 200:
            ctx.skip("vodguard: settings round trip through /api/admin/retention", f"admin sign-in answered {resp.status}")
            return
        async with s.get(ctx.base_url + "/api/admin/retention") as g:
            before = await g.json()
        ctx.ok("vodguard: GET /api/admin/retention lists the three settings",
               all(k in before for k in ("vod_min_free_gb", "vod_max_backlog_gb", "vod_orphan_max_age_days")), str(before)[:200])
        async with s.put(ctx.base_url + "/api/admin/retention",
                         json={"vod_min_free_gb": "0.5", "vod_max_backlog_gb": 0, "vod_orphan_max_age_days": 21}) as p:
            status = p.status
            body = await p.json()
        cfg = body.get("config", {}) if isinstance(body, dict) else {}
        ctx.ok("vodguard: PUT accepts fractions of a gigabyte and 0 (check off)",
               status == 200 and cfg.get("vod_min_free_gb") == "0.5" and cfg.get("vod_max_backlog_gb") == "0"
               and cfg.get("vod_orphan_max_age_days") == "21", str(body)[:200])
        async with s.put(ctx.base_url + "/api/admin/retention", json={"vod_min_free_gb": "-3", "vod_max_backlog_gb": "x"}) as p2:
            body2 = await p2.json()
        cfg2 = body2.get("config", {}) if isinstance(body2, dict) else {}
        ctx.ok("vodguard: invalid values are ignored", cfg2.get("vod_min_free_gb") == "0.5", str(body2)[:200])
        async with s.put(ctx.base_url + "/api/admin/retention",
                         json={k: before[k] for k in ("vod_min_free_gb", "vod_max_backlog_gb", "vod_orphan_max_age_days")}) as p3:
            ctx.ok("vodguard: the previous values were put back", p3.status == 200)
