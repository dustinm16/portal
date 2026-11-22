"""Smoke check: watching a VOD chunk in the browser (remux to MP4, byte-capped cache, owner only).

A staged server cannot dial loopback (the outbound host policy stays on), so the conversion runs in a
short-lived child process (ctx.run_py) against the staged database with the real handlers, a real
asyncssh SFTP server on 127.0.0.1 (generated host key, random password, chrooted) and real ffmpeg on two
generated 3-second clips (H.264/AAC and H.264/Opus), only the sign-in of that child replaced by a header
and the name lookup answered with 127.0.0.1. The routes on the staged server itself are then checked over
HTTP with real sessions: authentication, the answers for a storage it may not dial, a path that is not
a chunk, an administrator-less member without storage, the player page and its static file.

Users get random suffixes and are removed again; nothing assumes a count in a shared table or a global
setting (the settings the child changes are put back); no admin password is needed.

Proves: the owner gets an MP4 with the index first that answers Range, a second request is served
without another ffmpeg, Opus audio is 415 with a reason, another member and a member without storage get
404, a traversal path is refused, a cap of 0 answers 503 and empties the cache, a chunk too large for the
cap is download only, the cache folder is 0700 with 0600 files and the staged server made its own.

Not proven here: a browser, a phone, a real remote storage, Cloudflare.
"""
import json
import re
import secrets

PW = "vodplay-smoke-pw-1"

SCRIPT = r'''
import asyncio, json, os, subprocess, tempfile
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


class Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def validate_password(self, username, password):
        return password == P["sshpw"]


def clip(path, audio):
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10:duration=3",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=3", "-c:v", "libx264", "-preset", "ultrafast",
                    "-crf", "35", "-pix_fmt", "yuv420p", "-c:a", audio, "-b:a", "32k", path], check=True, timeout=60)


async def main():
    await db.connect()
    server.db = db
    out = {}
    base = tempfile.mkdtemp(prefix="vodplay_smoke_")
    remote = os.path.join(base, "remote")
    os.makedirs(os.path.join(remote, "v", "S", "2026-01-01"))
    os.makedirs(os.path.join(remote, "w"))
    clip(os.path.join(remote, "v", "S", "2026-01-01", "chunk_000.mkv"), "aac")
    clip(os.path.join(remote, "v", "S", "2026-01-01", "chunk_001.mkv"), "libopus")
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
                mock.patch.object(server, "VOD_PLAY_STAT_TTL", 0.0):
            assert server._vod_play_setup(cache_dir) is None
            # the server's own application: its middleware (security headers, ...) is in the way of the answers
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            good = "S/2026-01-01/chunk_000.mkv"
            opus = "S/2026-01-01/chunk_001.mkv"
            async def get(name, who, **h):
                hdr = {"X-U": str(ids[who])} if who else {}
                hdr.update(h)
                return await client.get("/api/vods/play/" + name + ".mp4", headers=hdr)
            r = await get(good, "owner")
            body = await r.read()
            out["owner_status"], out["ctype"], out["cc"] = r.status, r.headers.get("Content-Type"), r.headers.get("Cache-Control", "")
            out["nosniff"] = r.headers.get("X-Content-Type-Options")
            out["length_ok"] = len(body) == int(r.headers.get("Content-Length", -1))
            files = [f for f in os.listdir(cache_dir) if f.endswith(".mp4")]
            out["one_file"] = len(files) == 1
            if files:
                p = os.path.join(cache_dir, files[0])
                out["index_first"] = vod_play.index_first(p)
                out["mode"] = oct(os.stat(p).st_mode & 0o777)
                pr = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_name", "-of", "csv=p=0", p],
                                    capture_output=True, text=True, timeout=30)
                out["probe"] = pr.stdout.split()
            out["dir_mode"] = oct(os.stat(cache_dir).st_mode & 0o777)
            r2 = await get(good, "owner", Range="bytes=0-9")
            out["range"] = (r2.status, r2.headers.get("Content-Range", "").startswith("bytes 0-9/"), len(await r2.read()))
            out["range_headers"] = (r2.headers.get("Content-Type"), "private" in r2.headers.get("Cache-Control", "").lower(),
                                    r2.headers.get("Accept-Ranges"))
            n = len(spawned)
            r3 = await get(good, "owner")
            await r3.read()
            out["second"] = (r3.status, len(spawned) == n)
            r4 = await get(opus, "owner")
            j = await r4.json()
            out["opus"] = (r4.status, "opus" in (j.get("error") or "").lower())
            out["other"] = (await get(good, "other")).status
            out["nostorage"] = (await get(good, "nostorage")).status
            out["traversal"] = [(await get(b, "owner")).status for b in ("../x.mkv", "S/../../x.mkv", "/etc/x.mkv")]
            out["anon"] = (await get(good, None)).status
            await db.set_setting("vod_play_cache_mb", "0")
            r5 = await get(good, "owner")
            out["off"] = (r5.status, (await r5.json()).get("code"))
            out["emptied"] = [f for f in os.listdir(cache_dir) if f.endswith(".mp4")] == []
            await db.set_setting("vod_play_cache_mb", "0.05")
            r6 = await get(good, "owner")
            out["too_large"] = r6.status
            await client.close()
    finally:
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

asyncio.run(main())
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
    pre = "vp" + secrets.token_hex(3) + "_"
    params = {"pre": pre, "pw": PW, "sshpw": secrets.token_urlsafe(18)}
    rc, out = await ctx.run_py(SCRIPT % {"params": json.dumps(params)}, timeout=240)
    r = None
    try:
        r = _result(out)
    except RuntimeError as e:
        ctx.ok("vodplay: conversion scenario ran", False, str(e))
    ids = (r or {}).get("ids") or {}
    try:
        if r is not None:
            ctx.ok("vodplay: the owner gets an MP4 (video/mp4, private cache control)",
                   r["owner_status"] == 200 and r["ctype"] == "video/mp4" and "private" in r["cc"].lower()
                   and "public" not in r["cc"].lower(), str(r)[:300])
            ctx.ok("vodplay: through the server's own middleware the full and the Range answer keep video/mp4, Content-Length, Content-Range and private caching",
                   r["length_ok"] is True and r["range_headers"] == ["video/mp4", True, "bytes"], str(r["range_headers"]))
            ctx.ok("vodplay: it is H.264 with AAC and the index comes before the media data",
                   r.get("probe") and "h264" in r["probe"] and "aac" in r["probe"] and r.get("index_first") is True, str(r.get("probe")))
            ctx.ok("vodplay: the cache folder is 0700 and the copy 0600", r.get("dir_mode") == "0o700" and r.get("mode") == "0o600",
                   f"{r.get('dir_mode')} {r.get('mode')}")
            ctx.ok("vodplay: Range requests are answered with 206", r["range"] == [206, True, 10], str(r["range"]))
            ctx.ok("vodplay: a second request is served from the cache without another ffmpeg", r["second"] == [200, True], str(r["second"]))
            ctx.ok("vodplay: Opus audio is 415 with the reason", r["opus"] == [415, True], str(r["opus"]))
            ctx.ok("vodplay: another member and a member without storage get 404", r["other"] == 404 and r["nostorage"] == 404,
                   f"{r['other']} {r['nostorage']}")
            ctx.ok("vodplay: a traversal or absolute path is refused (404, or 405 where the client folded ../ away before sending)", all(c in (404, 405) for c in r["traversal"]), str(r["traversal"]))
            ctx.ok("vodplay: no credential is 401", r["anon"] == 401, str(r["anon"]))
            ctx.ok("vodplay: a cap of 0 answers 503 playback_off and empties the cache",
                   r["off"] == [503, "playback_off"] and r["emptied"] is True, str(r["off"]))
            ctx.ok("vodplay: a chunk larger than the cap allows is download only", r["too_large"] == 415, str(r["too_large"]))

        if ids:
            async with ctx.http() as s:
                resp = await ctx.login(s, pre + "owner", PW)
                ctx.ok("vodplay: the owner signs in", resp.status == 200, str(resp.status))
                async with s.get(ctx.base_url + "/api/vods/play/S/2026-01-01/chunk_000.mkv.mp4") as g:
                    ctx.ok("vodplay: on the staged server a storage the policy may not dial answers 502 (503 when playback is off here), never cached by a shared cache",
                           g.status in (502, 503) and "private" in g.headers.get("Cache-Control", "").lower(), f"{g.status} {g.headers.get('Cache-Control')}")
                async with s.get(ctx.base_url + "/api/vods/play/..%2Fx.mkv.mp4") as g:
                    ctx.ok("vodplay: a traversal path is 404 over HTTP", g.status == 404, str(g.status))
                async with s.get(ctx.base_url + "/api/vods/play-status/S/2026-01-01/chunk_000.mkv.mp4") as g:
                    body = await g.json()
                    ctx.ok("vodplay: the status route says idle and starts nothing", g.status in (200, 503) and
                           (g.status == 503 or body.get("state") == "idle"), f"{g.status} {body}")
                async with s.get(ctx.base_url + "/vods/play?name=S%2Fx.mkv", allow_redirects=False) as g:
                    page = await g.text()
                    ctx.ok("vodplay: the player page loads vod-player.js v1 and has no inline handler",
                           g.status == 200 and "/static/js/vod-player.js?v=1" in page
                           and not re.search(r"onclick=", page.split("</nav>")[-1]), str(g.status))
                async with s.get(ctx.base_url + "/static/js/vod-player.js?v=1") as g:
                    ctx.ok("vodplay: the player script is served", g.status == 200)
            async with ctx.http() as anon:
                async with anon.get(ctx.base_url + "/vods/play?name=x", allow_redirects=False) as g:
                    ctx.ok("vodplay: the player page sends a signed-out visitor to the sign-in", g.status in (301, 302, 303) and
                           "/login" in g.headers.get("Location", ""), f"{g.status} {g.headers.get('Location')}")
                async with anon.get(ctx.base_url + "/api/vods/play/x.mkv.mp4") as g:
                    ctx.ok("vodplay: the play route needs a credential", g.status == 401, str(g.status))
        cache = ctx.stage_dir / "data" / "vod_play_cache"
        ctx.ok("vodplay: the staged server made its own cache folder (0700, with its marker)",
               cache.is_dir() and (cache.stat().st_mode & 0o777) == 0o700 and (cache / ".portal_vod_play_cache").exists(), str(cache))
    finally:
        if ids:
            await ctx.run_py(CLEANUP % {"params": json.dumps({"ids": ids})})
