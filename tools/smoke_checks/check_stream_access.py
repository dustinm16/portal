"""Who may watch a stream, on a running instance: HLS, thumbnail, WHEP, the WHEP session
route and the info route answer by one decision (owner and admins always, a logged-in
member for a public stream, nobody logged in only for a public stream whose open link is
on and only with its current pub_ key), and every refusal is the same 404.

Over HTTP (the real server, real logins): refusals, the open share link, a rotated key,
a stream made private or public, the open link switched off, a stream key sent as a
credential, response headers, and the cache time of a change made behind the portal's back.
A stage has no MediaMTX, so an allowed request is judged by "not the portal's refusal" (404
with the body {"error": "Stream not found"}); a fresh stage answers 503 "MediaMTX not
configured", a stage with a production database copy may reach a real MediaMTX that answers 404
or 502 for the made-up stream, which is still an allowed request.

In-process (ctx.run_py, the real handlers and the stage database, a fake MediaMTX HLS
server with TLS on loopback): a playlist is rewritten, segments pass, and 60 segment
requests of one viewer cause no database read after the first request; a refused request
never reaches the upstream; signing the viewer out drops the decision.

Users, streams and keys carry random suffixes and every assertion is about those rows, so
the check also holds on a stage started from a copy of the production database. The admin
steps run only when ctx.admin_password is set.

Not proven here (needs the real thing): a real MediaMTX, OBS, VLC or a browser playing the
stream, WebRTC media (which never passes through the portal), and Cloudflare in front.
"""
import asyncio
import json
import secrets

PW = "Stream-access-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user
import server

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}, "streams": {}}
    for name in ("owner", "member", "other"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    for label, public, open_link in (("private", False, False), ("public", True, False),
                                     ("open", True, True), ("switch", True, False),
                                     ("inproc", True, False), ("inopen", True, True)):
        sk, pk = server.generate_stream_key(), server.generate_public_key()
        sid = await db.create_user_stream(user_id=out["users"]["owner"], name=P["pre"] + label, stream_key=sk,
                                          public_key=pk, is_public=public)
        await db.update_user_stream(sid, allow_unauthenticated=int(open_link))
        await db.set_stream_live(sid, True)
        out["streams"][label] = {"id": sid, "live": sk, "pub": pk}
    # a stream of another member, for the stream-key-as-credential check
    sk, pk = server.generate_stream_key(), server.generate_public_key()
    sid = await db.create_user_stream(user_id=out["users"]["other"], name=P["pre"] + "theirs", stream_key=sk,
                                      public_key=pk, is_public=False)
    await db.set_stream_live(sid, True)
    out["streams"]["theirs"] = {"id": sid, "live": sk, "pub": pk}
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

# The real handlers against the stage database and a fake MediaMTX HLS server (TLS, loopback)
INPROC = r'''
import asyncio, json, ssl
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from database import db
from config import Config
import auth, server

P = json.loads(%(params)r)

class Transport:
    def get_extra_info(self, name, default=None):
        return ("203.0.113.9", 5555) if name == "peername" else default

async def main():
    await db.connect()
    server.db = db
    S = P["streams"]
    hits = []

    async def upstream(request):
        hits.append(request.rel_url.path_qs)
        tail = request.match_info["tail"]
        key = request.match_info["key"]
        if tail.endswith(".m3u8"):
            return web.Response(body=("#EXTM3U\n#EXTINF:1.0,\n/live/%%s/seg0.mp4?session=abc\n" %% key).encode(),
                                content_type="application/vnd.apple.mpegurl")
        return web.Response(body=b"SEGMENT", content_type="video/mp4")

    app = web.Application()
    app.router.add_get("/live/{key}/{tail:.*}", upstream)
    ctx_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx_ssl.load_cert_chain(Config.SSL_CERT, Config.SSL_KEY)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ctx_ssl)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    async def mtx():
        return {"hls_port": port, "webrtc_port": 1}
    server._get_mediamtx_config = mtx

    jwt, tid = await auth.create_access_token(P["users"]["member"], ["services:read", "access:*"])

    def req(key, path="index.m3u8", cookie=None, query=""):
        h = {"Cookie": "%%s=%%s" %% (Config.SESSION_COOKIE_NAME, cookie)} if cookie else {}
        return make_mocked_request("GET", "/api/stream/%%s/hls/%%s" %% (key, path) + (("?" + query) if query else ""),
                                   headers=h, match_info={"stream_key": key, "path": path}, transport=Transport())

    out = {}
    server._playback_cache_forget(everything=True)
    reads = [0]
    real = db.conn.execute
    async def counting(*a, **kw):
        reads[0] += 1
        return await real(*a, **kw)
    db.conn.execute = counting

    pub = S["inproc"]["pub"]
    r = await server.http_stream_hls_proxy(req(pub, cookie=jwt))
    out["playlist_status"] = r.status
    out["playlist_rewritten"] = ("/api/stream/%%s/hls/seg0.mp4?session=abc" %% pub) in r.body.decode()
    out["first_reads"] = reads[0]
    base = reads[0]
    ok = 0
    for i in range(60):
        r = await server.http_stream_hls_proxy(req(pub, "seg%%d.mp4" %% i, cookie=jwt, query="session=abc"))
        ok += (r.status == 200 and r.body == b"SEGMENT")
    out["segments_ok"] = ok
    out["segment_reads"] = reads[0] - base
    out["segment_cors"] = r.headers.get("Access-Control-Allow-Origin")
    out["segment_cache"] = r.headers.get("Cache-Control")

    # the open link, logged out: no cookie, no read after the first
    opub = S["inopen"]["pub"]
    await server.http_stream_hls_proxy(req(opub))
    base = reads[0]
    for i in range(60):
        r = await server.http_stream_hls_proxy(req(opub, "seg%%d.mp4" %% i))
    out["open_segment_reads"] = reads[0] - base
    out["open_cors"] = r.headers.get("Access-Control-Allow-Origin")

    # refused requests never reach MediaMTX
    n = len(hits)
    refused = []
    for key, cookie in ((S["private"]["pub"], None), (S["private"]["pub"], jwt), (S["public"]["pub"], None),
                        (S["private"]["live"], None), ("pub_nosuchkey", jwt)):
        r = await server.http_stream_hls_proxy(req(key, cookie=cookie))
        refused.append([r.status, r.body.decode()])
    out["refused"] = refused
    out["refused_upstream_hits"] = len(hits) - n

    # signing the viewer out drops the cached decision at once
    out["cached_before_signout"] = any(v[1] == P["users"]["member"] for v in server._playback_auth_cache.values())
    await db.revoke_token(tid, P["users"]["member"])
    await server.close_user_websockets(P["users"]["member"], only_token_id=tid)
    out["cached_after_signout"] = any(v[1] == P["users"]["member"] for v in server._playback_auth_cache.values())
    r = await server.http_stream_hls_proxy(req(pub, "seg1.mp4", cookie=jwt))
    out["after_signout_status"] = r.status

    db.conn.execute = real
    await runner.cleanup()
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
    pre = "sa" + secrets.token_hex(3)
    params = json.dumps({"pw": PW, "pre": pre})
    rc, out = await ctx.run_py(SETUP % {"params": params}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("stream access: setup", False, out[-500:])
        return
    S = data["streams"]
    base = ctx.base_url + "/api/stream"

    def ok(name, passed, detail=""):
        ctx.ok("stream access: " + name, bool(passed), "" if passed else detail)

    refused_bodies = set()
    NOT_FOUND = b'{"error": "Stream not found"}'

    def gone(status, body):
        """The portal's refusal: 404 with the one body. A bare 404 is not it: on a stage with a
        production database copy a real MediaMTX may answer 404 for an allowed request."""
        return status == 404 and body == NOT_FOUND

    async def get(sess, url, **kw):
        async with sess.get(url, allow_redirects=False, **kw) as r:
            return r.status, await r.read(), r

    async def surfaces(sess, key):
        """Status of every playback surface for one key."""
        out = {}
        out["hls"] = (await get(sess, f"{base}/{key}/hls/index.m3u8"))[0:2]
        out["thumb"] = (await get(sess, f"{base}/{key}/thumbnail"))[0:2]
        out["info"] = (await get(sess, f"{base}/{key}/info"))[0:2]
        async with sess.post(f"{base}/{key}/webrtc/whep", data="v=0\r\n", headers={"Content-Type": "application/sdp"}) as r:
            out["whep"] = (r.status, await r.read())
        async with sess.delete(f"{base}/{key}/webrtc/session/nosuchsession") as r:
            out["session"] = (r.status, await r.read())
        return out

    def all_refused(res):
        for name, (status, body) in res.items():
            refused_bodies.add(body)
        return all(gone(status, body) for status, body in res.values())

    def none_refused(res):
        # allowed: anything but the portal's refusal (the stage has no usable MediaMTX). The
        # session route is left out: an allowed viewer asking for an unknown session gets it too.
        return all(not gone(status, body) for name, (status, body) in res.items() if name != "session")

    async with ctx.http() as anon, ctx.http() as owner, ctx.http() as member, ctx.http() as other:
        for name, sess, user in (("owner", owner, "owner"), ("member", member, "member"), ("other", other, "other")):
            resp = await ctx.login(sess, pre + user, PW)
            if resp.status != 200:
                ctx.ok("stream access: " + name + " can sign in", False, str(resp.status))
                return

        # ---- logged out
        res = await surfaces(anon, S["private"]["pub"])
        ok("logged out, a private stream's pub_ link is 404 on HLS, thumbnail, info, WHEP and sessions", all_refused(res), str(res))
        res = await surfaces(anon, S["public"]["pub"])
        ok("logged out, a public stream without the open link is 404 everywhere", all_refused(res), str(res))
        res = await surfaces(anon, S["private"]["live"])
        ok("a live_ key in the URL is not a way to watch, logged out", all_refused(res), str(res))
        res = await surfaces(anon, "pub_" + secrets.token_urlsafe(16))
        ok("an unknown key is 404 everywhere", all_refused(res), str(res))
        ok("every refusal has the same body", len(refused_bodies) == 1, str(refused_bodies))
        res = await surfaces(anon, S["open"]["pub"])
        ok("logged out, the open share link is not refused on HLS, thumbnail, info and WHEP", none_refused(res), str(res))
        res = await surfaces(anon, S["open"]["live"])
        ok("logged out, the open stream's live_ key is still refused", all_refused(res), str(res))

        # ---- logged in
        res = await surfaces(member, S["private"]["pub"])
        ok("a logged-in member gets 404 for a private stream", all_refused(res), str(res))
        res = await surfaces(member, S["public"]["pub"])
        ok("a logged-in member may watch a public stream (no open link needed)", none_refused(res), str(res))
        res = await surfaces(owner, S["private"]["pub"])
        ok("the owner may watch their private stream", none_refused(res), str(res))
        res = await surfaces(owner, S["private"]["live"])
        ok("the owner's page may name the stream by its live_ key", none_refused(res), str(res))
        res = await surfaces(other, S["private"]["live"])
        ok("another member with the live_ key of a private stream gets 404", all_refused(res), str(res))

        # ---- a stream key sent as a credential never opens another stream
        for hdr in ({"X-Stream-Key": S["theirs"]["live"]}, {"Authorization": "Stream-Key " + S["theirs"]["live"]}):
            st, body, _ = await get(anon, f"{base}/{S['private']['pub']}/info", headers=hdr)
            ok("a stream key header is not a viewing credential (%s)" % list(hdr)[0], gone(st, body), str(st))

        # ---- headers
        st, body, r = await get(anon, f"{base}/{S['open']['pub']}/info")
        ok("the open share link may be read from other sites (CORS header)",
           st == 200 and r.headers.get("Access-Control-Allow-Origin") == "*", f"{st} {dict(r.headers)}")
        st, body, r = await get(member, f"{base}/{S['public']['pub']}/info")
        ok("anything else has no CORS header and is private to the viewer",
           st == 200 and "Access-Control-Allow-Origin" not in r.headers
           and "private" in r.headers.get("Cache-Control", ""), f"{st} {dict(r.headers)}")
        st, body, r = await get(member, f"{base}/{S['private']['pub']}/info")
        ok("a refusal is not cached and has no CORS header",
           gone(st, body) and r.headers.get("Cache-Control") == "no-store" and "Access-Control-Allow-Origin" not in r.headers,
           f"{st} {dict(r.headers)}")

        # ---- the owner changes the stream: viewers lose access at once
        sw = S["switch"]
        st, body, _ = await get(member, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("before the change the member may watch the stream", not gone(st, body), str(st))
        async with owner.put(f"{ctx.base_url}/api/streams/{sw['id']}", json={"allow_unauthenticated": True}) as r:
            await r.read()
            ok("the owner switches the open link on", r.status == 200, str(r.status))
        st, body, _ = await get(anon, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("now it plays logged out", not gone(st, body), str(st))
        async with owner.put(f"{ctx.base_url}/api/streams/{sw['id']}", json={"allow_unauthenticated": False}) as r:
            await r.read()
        st, body, _ = await get(anon, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("switching the open link off stops it at once", gone(st, body), str(st))
        st, body, _ = await get(member, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("...and the logged-in member still plays", not gone(st, body), str(st))
        async with owner.put(f"{ctx.base_url}/api/streams/{sw['id']}", json={"is_public": False}) as r:
            body = await r.json(content_type=None)
            new_key = (body or {}).get("public_key", "")
        st, body, _ = await get(member, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("a stream made private puts the viewer out at once, on the old key", gone(st, body), str(st))
        st, body, _ = await get(member, f"{base}/{new_key}/hls/index.m3u8")
        ok("...and on the rotated key", gone(st, body), str(st))
        st, body, _ = await get(owner, f"{base}/{new_key}/hls/index.m3u8")
        ok("...while the owner plays with the new key", not gone(st, body), str(st))
        st, body, _ = await get(owner, f"{base}/{sw['pub']}/hls/index.m3u8")
        ok("the old key is dead for the owner too", gone(st, body), str(st))
        # share-link rotation of the open stream
        op = S["open"]
        async with owner.post(f"{ctx.base_url}/api/streams/{op['id']}/regenerate-public-key") as r:
            rot = (await r.json(content_type=None)) or {}
        st, body, _ = await get(anon, f"{base}/{op['pub']}/hls/index.m3u8")
        ok("a rotated share link is 404 at once, logged out", gone(st, body), str(st))
        st, body, _ = await get(anon, f"{base}/{rot.get('public_key', 'x')}/hls/index.m3u8")
        ok("the new share link plays", not gone(st, body), str(st))

        # ---- a change made behind the portal's back is picked up within the cache time
        pub = S["public"]
        st, body, _ = await get(member, f"{base}/{pub['pub']}/hls/index.m3u8")
        ok("a public stream plays for the member", not gone(st, body), str(st))
        rc, out = await ctx.run_py(
            "import asyncio\nfrom database import db\nasync def m():\n    await db.connect()\n"
            f"    await db.update_user_stream({pub['id']}, is_public=0)\n    await db.close()\nasyncio.run(m())\n")
        ok("(stream made private directly in the database)", rc == 0, out[-200:])
        await asyncio.sleep(6.5)
        st, body, _ = await get(member, f"{base}/{pub['pub']}/hls/index.m3u8")
        ok("within the cache time (5 s) the viewer is out without any portal call", gone(st, body), str(st))

    # ---- admin sees every stream (only when the admin password is known)
    if ctx.admin_password:
        async with ctx.http() as adm:
            resp = await ctx.login(adm, ctx.admin_user, ctx.admin_password)
            if resp.status == 200:
                res = await surfaces(adm, S["theirs"]["pub"])
                ok("an admin may watch any private stream", none_refused(res), str(res))
            else:
                ctx.ok("stream access: admin can sign in", False, str(resp.status))
    else:
        ctx.skip("stream access: an admin may watch any private stream", "no admin password given")

    # ---- the real handlers against a fake MediaMTX with TLS, and the database read count
    rc, out = await ctx.run_py(INPROC % {"params": json.dumps({**data, "pre": pre})}, timeout=120)
    r = _result(out)
    if rc != 0 or r is None:
        ctx.ok("stream access: in-process proxy run", False, out[-600:])
        return
    ok("a playlist passes the proxy and is rewritten to the same key", r["playlist_status"] == 200 and r["playlist_rewritten"], str(r))
    ok("60 segment requests of one viewer all pass", r["segments_ok"] == 60, str(r["segments_ok"]))
    ok("...with no database read after the first request (member)", r["segment_reads"] == 0, f"{r['segment_reads']} reads")
    ok("...and none for the open link logged out", r["open_segment_reads"] == 0, f"{r['open_segment_reads']} reads")
    ok("the first request costs a few reads (the decision is really made)", 0 < r["first_reads"] <= 12, str(r["first_reads"]))
    ok("a public stream's segments are private to the viewer, no CORS",
       r["segment_cors"] is None and "private" in (r["segment_cache"] or ""), f"{r['segment_cors']} {r['segment_cache']}")
    ok("the open link's segments carry the open CORS header", r["open_cors"] == "*", str(r["open_cors"]))
    ok("refused requests are 404 with the one body and never reach MediaMTX",
       all(s == 404 and b == '{"error": "Stream not found"}' for s, b in r["refused"]) and r["refused_upstream_hits"] == 0,
       str(r["refused"]) + " hits " + str(r["refused_upstream_hits"]))
    ok("signing the viewer out drops the cached decision and the next segment is refused",
       r["cached_before_signout"] and not r["cached_after_signout"] and r["after_signout_status"] == 404,
       str([r["cached_before_signout"], r["cached_after_signout"], r["after_signout_status"]]))

