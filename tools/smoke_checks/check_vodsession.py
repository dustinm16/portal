"""Smoke check: whole-session VOD playback (HLS playlist of a session folder, MPEG-TS segments).

Same arrangement as check_vodplay: a staged server cannot dial loopback, so the scenario runs in a
short-lived child process against the staged database with the real handlers, a real asyncssh SFTP server
on 127.0.0.1 (generated host key, random password, chrooted) and real ffmpeg / ffprobe on four generated
clips of 2, 3, 4 and 2.5 seconds, only the sign-in of that child replaced by a header and the name lookup
answered with 127.0.0.1. The routes on the staged server itself are then checked over HTTP with real
sessions: authentication, a path that is not a session, the player page with its whole-session button,
hls.js from the host the live page uses, and the script version.

Users get random suffixes and are removed again; nothing assumes a count in a shared table or a global
setting (the settings the child changes are put back); no admin password is needed.

Proves: the playlist lists the four chunks in order with measured lengths and discontinuities, every
segment is MPEG-TS that ffprobe accepts, ffprobe reading the playlist over HTTP sees a length equal to the
sum of the chunks, another member and a member without storage get 404 and start no tool, the newest
chunk of a live session is left out and its playlist is not a finished VOD.

Not proven here: a browser, hls.js playing it, a phone, Safari, a real remote storage, Cloudflare.
"""
import json
import re
import secrets

PW = "vodsession-smoke-pw-1"
DURATIONS = [2.0, 3.0, 4.0, 2.5]

SCRIPT = r'''
import asyncio, json, os, subprocess, tempfile, time
from types import SimpleNamespace
from unittest import mock
import asyncssh
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from database import db
import server, vod_play, vod_staging
from auth import create_user

vod_staging.TEMP_ROOTS = ()
P = json.loads(%(params)r)
DUR = %(durations)s


class Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def validate_password(self, username, password):
        return password == P["sshpw"]


def clip(path, seconds, seed):
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", f"testsrc=size=160x120:rate=10:duration={seconds}",
                    "-f", "lavfi", "-i", f"sine=frequency={440 + 50 * seed}:duration={seconds}", "-c:v", "libx264",
                    "-preset", "ultrafast", "-crf", "35", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "32k", path],
                   check=True, timeout=60, stdin=subprocess.DEVNULL)


async def tool(argv):
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    o, e = await asyncio.wait_for(proc.communicate(), 90)
    return proc.returncode, o.decode(), e.decode()


def probe_ts(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-f", "mpegts", "-show_entries", "stream=codec_name",
                        "-show_entries", "format=duration", "-of", "json", path], capture_output=True, text=True, timeout=30,
                       stdin=subprocess.DEVNULL)
    info = json.loads(r.stdout or "{}")
    return r.returncode, [s["codec_name"] for s in info.get("streams", [])], float(info.get("format", {}).get("duration", 0))


async def main():
    await db.connect()
    server.db = db
    out = {}
    base = tempfile.mkdtemp(prefix="vodsession_smoke_")
    remote = os.path.join(base, "remote")
    folder = "S/2026-02-01"
    os.makedirs(os.path.join(remote, "v", folder))
    os.makedirs(os.path.join(remote, "w"))
    for i, d in enumerate(DUR):
        clip(os.path.join(remote, "v", folder, f"chunk_{i:03d}.mkv"), d, i)
    key = asyncssh.generate_private_key("ssh-ed25519")
    sshd = await asyncssh.create_server(Srv, "127.0.0.1", 0, server_host_keys=[key],
                                        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=remote))
    port = sshd.sockets[0].getsockname()[1]
    ids = {}
    for who in ("owner", "other", "nostorage"):
        ids[who] = (await create_user(P["pre"] + who, P["pw"]))["id"]
    for who, root in (("owner", "/v"), ("other", "/w")):
        await db.save_vod_storage(ids[who], name="smoke", host="127.0.0.1", port=port, username="u",
                                  auth_method="password", remote_path=root,
                                  config=json.dumps({"password": P["sshpw"], "host_key_ignore": True}))
    out["ids"] = ids
    keys = ("vod_play_cache_mb", "vod_min_free_gb")
    saved = {k: await db.get_setting(k) for k in keys}
    await db.set_setting("vod_play_cache_mb", "50")
    await db.set_setting("vod_min_free_gb", "0")
    spawned = []
    real_exec = server._media_exec
    async def spy(cmd, *a, **k):
        spawned.append(cmd[0])
        return await real_exec(cmd, *a, **k)
    async def resolve(host, port):
        return ["127.0.0.1"]
    async def auth(request):
        uid = request.headers.get("X-U")
        return (SimpleNamespace(user_id=int(uid)), None) if uid else (None, web.json_response({"error": "no"}, status=401))
    cache_dir = os.path.join(base, "cache")
    try:
        with mock.patch.object(server, "_media_exec", spy), mock.patch.object(server, "resolve_checked_host", resolve), \
                mock.patch.object(server, "_stream_user_auth", auth), mock.patch.object(server, "VOD_PLAY_FAST_WAIT", 30.0), \
                mock.patch.object(server, "VOD_PLAY_STAT_TTL", 0.0), mock.patch.object(server, "VOD_SESSION_SEG_WAIT", 40.0), \
                mock.patch.object(server, "VOD_PLAY_FREE_MARGIN_BYTES", 0):     # the floor is 0 here so it runs on any disk
            assert server._vod_play_setup(cache_dir) is None
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            async def get(path, who, **h):
                hdr = {"X-U": str(ids[who])} if who else {}
                hdr.update(h)
                return await client.get("/api/vods/session/" + path, headers=hdr)
            async def playlist(f, who):
                end = time.time() + 60
                while True:
                    r = await get(f + "/index.m3u8", who)
                    if r.status != 202 or time.time() > end:
                        return r
                    await asyncio.sleep(0.3)
            first = await get(folder + "/index.m3u8", "owner")
            out["first"] = (first.status, bool(first.headers.get("Retry-After")), (await first.json()).get("state"))
            r = await playlist(folder, "owner")
            text = await r.text()
            out["pl_status"], out["pl_type"] = r.status, r.headers.get("Content-Type")
            lines = text.strip().splitlines()
            out["lines"] = lines
            out["no_tool_but_probe"] = "ffmpeg" not in spawned
            segs = []
            for i, d in enumerate(DUR):
                s = await get(f"{folder}/chunk_{i:03d}.ts", "owner")
                data = await s.read()
                p = os.path.join(base, f"s{i}.ts")
                open(p, "wb").write(data)
                rc, codecs, dur = probe_ts(p)
                segs.append((s.status, s.headers.get("Content-Type"), rc, codecs, round(dur, 2)))
            out["segs"] = segs
            url = f"http://127.0.0.1:{client.server.port}/api/vods/session/{folder}/index.m3u8"
            rc, o, e = await tool(["ffprobe", "-v", "error", "-headers", f"X-U: {ids['owner']}\r\n",
                                   "-protocol_whitelist", "http,tcp,file,crypto", "-show_entries", "format=duration",
                                   "-of", "csv=p=0", url])
            out["timeline"] = (rc, float(o.strip() or 0), sum(DUR))
            # others: the same 404 as a folder that does not exist, and no tool started for it
            while [j for j in server._vod_play_jobs.values() if j["finished"] is None]:
                await asyncio.sleep(0.1)
            n = len(spawned)
            out["other"] = [(await get(folder + "/index.m3u8", "other")).status,
                            (await get(folder + "/chunk_000.ts", "other")).status,
                            (await get(folder + "/index.m3u8", "nostorage")).status,
                            (await get(folder + "/chunk_000.ts", "nostorage")).status]
            out["other_no_tool"] = len(spawned) == n
            out["anon"] = [(await get(folder + "/index.m3u8", None)).status, (await get(folder + "/chunk_000.ts", None)).status]
            out["bad"] = [(await get(b, "owner")).status for b in ("index.m3u8", "S/%%2e%%2e/index.m3u8", "S/2026-02-01/chunk_9.ts",
                                                                 "Nope/x/index.m3u8")]
            # live: the newest chunk is left out and it is not a finished VOD
            server.active_recordings[999999] = {"remote_session_dir": "/v/" + folder, "user_id": ids["owner"]}
            lr = await playlist(folder, "owner")
            ltext = await lr.text()
            ls = await get(f"{folder}/chunk_003.ts", "owner")
            out["live"] = (lr.status, ltext.count(".ts"), "#EXT-X-ENDLIST" in ltext, "EVENT" in ltext, ls.status)
            server.active_recordings.pop(999999, None)
            await client.close()
    finally:
        server.active_recordings.pop(999999, None)
        for k, v in saved.items():
            if v is None:
                await db.conn.execute("DELETE FROM settings WHERE key = ?", (k,))
            else:
                await db.set_setting(k, v)
        await db.conn.commit()
        server._vod_play_cache = None
        sshd.close()
        await sshd.wait_closed()
        import shutil
        shutil.rmtree(base, ignore_errors=True)
    print("RESULT " + json.dumps(out))
    await db.close()

try:
    asyncio.run(main())
except BaseException:
    import traceback
    traceback.print_exc()
    os._exit(1)          # the database thread would keep a failed scenario alive
'''

CLEANUP = r'''
import asyncio, json
from database import db
P = json.loads(%(params)r)
async def main():
    await db.connect()
    for uid in P["ids"].values():
        await db.delete_vod_storage(uid)
        await db.delete_user(uid)
    print("RESULT {}")
    await db.close()
asyncio.run(main())
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("no RESULT line in: " + out[-400:])


async def run(ctx):
    pre = "vs" + secrets.token_hex(3) + "_"
    params = {"pre": pre, "pw": PW, "sshpw": secrets.token_urlsafe(18)}
    rc, out = await ctx.run_py(SCRIPT % {"params": json.dumps(params), "durations": repr(DURATIONS)}, timeout=150)
    r = None
    try:
        r = _result(out)
    except RuntimeError as e:
        ctx.ok("vodsession: session scenario ran", False, str(e))
    ids = (r or {}).get("ids") or {}
    try:
        if r is not None:
            lines = r["lines"]
            items, disc, pending = [], 0, None
            for ln in lines:
                if ln.startswith("#EXTINF:"):
                    pending = float(ln[8:].rstrip(","))
                elif ln == "#EXT-X-DISCONTINUITY":
                    disc += 1
                elif not ln.startswith("#"):
                    items.append((ln, pending))
            ctx.ok("vodsession: the first playlist request answers 202 preparing with Retry-After",
                   r["first"] == [202, True, "preparing"], str(r["first"]))
            ctx.ok("vodsession: the playlist is a VOD playlist with the four chunks in order and three discontinuities",
                   r["pl_status"] == 200 and "mpegurl" in (r["pl_type"] or "") and "#EXT-X-PLAYLIST-TYPE:VOD" in lines
                   and lines[-1] == "#EXT-X-ENDLIST" and [n for n, _d in items] == [f"chunk_{i:03d}.ts" for i in range(4)]
                   and disc == 3, str(lines)[:300])
            ctx.ok("vodsession: the lengths are the measured ones, not a flat 300 seconds",
                   len(items) == 4 and all(abs(d - w) < 0.3 for (_n, d), w in zip(items, DURATIONS)), str(items))
            ctx.ok("vodsession: the playlist needed no conversion", r["no_tool_but_probe"] is True)
            ctx.ok("vodsession: every segment is MPEG-TS that ffprobe accepts (H.264 and AAC, the right length)",
                   all(s[0] == 200 and s[1] == "video/mp2t" and s[2] == 0 and s[3] == ["h264", "aac"] and abs(s[4] - w) < 0.4
                       for s, w in zip(r["segs"], DURATIONS)), str(r["segs"]))
            ctx.ok("vodsession: ffprobe reading the playlist over HTTP sees one timeline of the summed length",
                   r["timeline"][0] == 0 and abs(r["timeline"][1] - r["timeline"][2]) < 0.6, str(r["timeline"]))
            ctx.ok("vodsession: another member and a member without storage get 404 for the playlist and a segment, and no tool starts",
                   r["other"] == [404, 404, 404, 404] and r["other_no_tool"] is True, str(r["other"]))
            ctx.ok("vodsession: no credential is 401", r["anon"] == [401, 401], str(r["anon"]))
            ctx.ok("vodsession: a path that is not a session, a traversal and a missing chunk are 404",
                   all(c == 404 for c in r["bad"]), str(r["bad"]))
            ctx.ok("vodsession: a live session leaves out its newest chunk, is not a finished VOD and refuses that segment (409)",
                   r["live"] == [200, 3, False, True, 409], str(r["live"]))

        if ids:
            async with ctx.http() as s:
                resp = await ctx.login(s, pre + "owner", PW)
                ctx.ok("vodsession: the owner signs in", resp.status == 200, str(resp.status))
                async with s.get(ctx.base_url + "/api/vods/session/S/2026-02-01/index.m3u8") as g:
                    ctx.ok("vodsession: on the staged server a storage the policy may not dial answers 502 (503 when playback is off here), never cached by a shared cache",
                           g.status in (502, 503, 404) and "private" in g.headers.get("Cache-Control", "").lower(), f"{g.status} {g.headers.get('Cache-Control')}")
                async with s.get(ctx.base_url + "/api/vods/session/..%2Fx/index.m3u8") as g:
                    ctx.ok("vodsession: a traversal path is 404 over HTTP", g.status == 404, str(g.status))
                async with s.get(ctx.base_url + "/vods/play?name=S%2F2026-02-01%2Fchunk_000.mkv&mode=session", allow_redirects=False) as g:
                    page = await g.text()
                    ctx.ok("vodsession: the player page loads vod-player.js v3 and the hls.js file of the live page from the same host",
                           g.status == 200 and "/static/js/vod-player.js?v=3" in page
                           and "https://cdn.jsdelivr.net/npm/hls.js@1.5.17" in page and 'id="vp-mode"' in page, str(g.status))
                    ctx.ok("vodsession: the player page has no inline handler", not re.search(r"onclick=", page.split("</nav>")[-1]))
                async with s.get(ctx.base_url + "/static/js/vod-player.js?v=3") as g:
                    js = await g.text()
                    ctx.ok("vodsession: the player script is served and knows the session route",
                           g.status == 200 and "/api/vods/session/" in js and "onclick=" not in js, str(g.status))
            async with ctx.http() as anon:
                async with anon.get(ctx.base_url + "/api/vods/session/S/x/index.m3u8") as g:
                    ctx.ok("vodsession: the playlist route needs a credential", g.status == 401, str(g.status))
                async with anon.get(ctx.base_url + "/api/vods/session/S/x/chunk_000.ts") as g:
                    ctx.ok("vodsession: the segment route needs a credential", g.status == 401, str(g.status))
    finally:
        if ids:
            await ctx.run_py(CLEANUP % {"params": json.dumps({"ids": ids})})
