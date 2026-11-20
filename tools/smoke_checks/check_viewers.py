"""Viewer counts on a running instance.

Over HTTP against the staged server (real logins; the MediaMTX publish and disconnect hooks are
posted from loopback, which is the path MediaMTX uses): two members who beat the heartbeat
(POST /api/stream/{key}/viewer) on a public live stream show as 2 in the owner's stream detail
within a few seconds, one member in two tabs counts once; a private stream's heartbeat from a
member is the same 404 as an unknown key and counts nobody, the owner's counts; a logged-out
viewer counts on an open-link stream with a client id and is refused (404) on a stream without
the open link; a viewer who stops is gone from the count within about 30 seconds while another
goes on; when the stream goes offline the owner's detail carries the peak and unique viewers of
the session and nobody else's does.

Users and streams carry random suffixes and every assertion is about those rows, so the module
also holds on a stage started from a copy of a production database. It needs no admin password.

Not proven here (needs the real thing): a real MediaMTX (the stage has none, so HLS playlists and
WHEP offers are covered by tests/test_viewers.py with a fake MediaMTX only), a browser's hls.js or
Safari sending the viewer id, OBS publishing with an rtmp_ token.
"""
import asyncio
import json
import secrets
import time

PW = "Viewers-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "m1", "m2"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
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
    pre = "vw" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    if rc != 0 or _result(out) is None:
        ctx.ok("viewers: setup", False, out[-500:])
        return
    base = ctx.base_url
    streams = []

    def ok(name, passed, detail=""):
        ctx.ok("viewers: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def hook(sess, path, body):
        async with sess.post(base + path, json=body) as r:
            return r.status

    async def beat(sess, key, cid=None):
        return await call(sess, "POST", f"/api/stream/{key}/viewer",
                          headers={"X-Viewer-Id": cid} if cid else {})

    async def count(sess, sid):
        _, b = await call(sess, "GET", f"/api/streams/{sid}")
        return (b or {}).get("stream", {}).get("viewer_count")

    async def wait_count(sess, sid, want, keep=(), timeout=15.0):
        """Poll the owner's detail until the count is `want`; `keep` are (session, key) pairs
        that keep beating while waiting."""
        end = time.monotonic() + timeout
        got = None
        while time.monotonic() < end:
            for s, k in keep:
                await beat(s, k)
            got = await count(sess, sid)
            if got == want:
                return True, got
            await asyncio.sleep(2.0)
        return False, got

    async with ctx.http() as owner, ctx.http() as m1, ctx.http() as m2, ctx.http() as anon, ctx.http() as hk:
        try:
            for name, sess in (("owner", owner), ("m1", m1), ("m2", m2)):
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return
            made = {}
            for label, body in (("pub", {"is_public": True}), ("priv", {"is_public": False}),
                                ("open", {"is_public": True, "allow_unauthenticated": True})):
                st, b = await call(owner, "POST", "/api/streams", json={"name": pre + label, **body})
                if st != 201:
                    ok("stream " + label + " is created", False, f"{st} {b}")
                    return
                made[label] = b["stream"]
                if body.get("allow_unauthenticated"):
                    st, b2 = await call(owner, "PUT", f"/api/streams/{b['stream']['id']}", json={"allow_unauthenticated": True})
                    if st != 200:
                        ok("the open link is switched on", False, f"{st} {b2}")
                        return
                streams.append(b["stream"]["id"])
                s = await hook(hk, "/api/stream/auth", {"action": "publish", "path": "live/" + b["stream"]["stream_key"],
                                                        "password": b["stream"]["stream_key"], "ip": "127.0.0.1"})
                ok(label + " goes live", s == 200, str(s))
            pub, priv, opn = made["pub"], made["priv"], made["open"]

            # ---- two members, one of them in two tabs
            sa, _ = await beat(m1, pub["public_key"])
            sb, _ = await beat(m1, pub["public_key"], cid=secrets.token_urlsafe(18))
            sc, _ = await beat(m2, pub["public_key"])
            ok("the heartbeat is accepted for a member", sa == sb == sc == 200, f"{sa} {sb} {sc}")
            good, got = await wait_count(owner, pub["id"], 2, keep=[(m1, pub["public_key"]), (m2, pub["public_key"])])
            ok("two members, one in two tabs, show as 2", good, f"count {got}")

            # ---- a private stream
            st_priv, b_priv = await beat(m1, priv["public_key"])
            st_unk, b_unk = await beat(m1, "pub_" + secrets.token_hex(12))
            ok("a member's heartbeat on a private stream is the same 404 as an unknown key",
               st_priv == 404 and st_unk == 404 and b_priv == b_unk, f"{st_priv} {b_priv} / {st_unk} {b_unk}")
            st_own, _ = await beat(owner, priv["public_key"])
            ok("the owner's heartbeat is accepted", st_own == 200, str(st_own))
            good, got = await wait_count(owner, priv["id"], 1, keep=[(owner, priv["public_key"])])
            ok("only the owner is counted on the private stream", good, f"count {got}")
            st, b = await call(m1, "GET", f"/api/streams/{priv['id']}")
            ok("and a member cannot read its count (404)", st == 404, str(st))

            # ---- logged out
            st_open, _ = await beat(anon, opn["public_key"], cid=secrets.token_urlsafe(18))
            st_closed, b_closed = await beat(anon, pub["public_key"], cid=secrets.token_urlsafe(18))
            st_live, _ = await beat(anon, opn["stream_key"], cid=secrets.token_urlsafe(18))
            ok("a logged-out viewer is accepted on an open link only, and a stream key is no way in",
               st_open == 200 and st_closed == 404 and st_live == 404, f"{st_open} {st_closed} {st_live}")
            good, got = await wait_count(owner, opn["id"], 1)
            ok("the logged-out viewer is counted", good, f"count {got}")

            # ---- a viewer who stops: m2 stops, m1 keeps going
            t0 = time.monotonic()
            good, got = await wait_count(owner, pub["id"], 1, keep=[(m1, pub["public_key"])], timeout=40.0)
            ok("a viewer who stops is gone within about 30 seconds while the other stays",
               good, f"count {got} after {time.monotonic() - t0:.0f} s")

            # ---- offline: peak and unique of the session
            s = await hook(hk, "/api/stream/event", {"event": "disconnect", "path": "live/" + pub["stream_key"]})
            ok("the disconnect hook is accepted", s == 200, str(s))
            end = time.monotonic() + 20
            detail = {}
            while time.monotonic() < end:
                _, b = await call(owner, "GET", f"/api/streams/{pub['id']}")
                detail = (b or {}).get("stream", {})
                if detail.get("is_live") == 0:
                    break
                await asyncio.sleep(1.0)
            ok("the stream goes offline", detail.get("is_live") == 0, str(detail.get("is_live")))
            ok("the owner's detail carries the peak and unique viewers of the session",
               detail.get("last_peak_viewers") == 2 and detail.get("last_unique_viewers") == 2
               and detail.get("viewer_count") == 0, f"{detail.get('last_peak_viewers')} {detail.get('last_unique_viewers')} {detail.get('viewer_count')}")
            st, b = await call(m1, "GET", f"/api/streams/{pub['id']}")
            other = (b or {}).get("stream", {})
            ok("another member's view of it has neither", st == 200 and "last_peak_viewers" not in other
               and "last_unique_viewers" not in other, f"{st} {sorted(other)}")

            # ---- a stream published with an rtmp_ token path (plain RTMP must be enabled on the stage)
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "rtmp", "is_public": True,
                                                                    "rtmp_enabled": True})
            if st != 201:
                ok("the rtmp stream is created", False, f"{st} {b}")
                return
            rs = b["stream"]
            streams.append(rs["id"])
            st, tok = await call(owner, "POST", f"/api/streams/{rs['id']}/rtmp-token")
            if st != 200:
                ctx.skip("viewers: a stream published with an rtmp_ token is counted",
                         f"plain RTMP is not enabled on this instance ({st})")
            else:
                path = "live/" + tok["token"]
                s = await hook(hk, "/api/stream/auth", {"action": "publish", "path": path,
                                                        "password": tok["token"], "ip": "127.0.0.1"})
                ok("the publish hook accepts the rtmp_ token", s == 200, str(s))
                sb, _ = await beat(m1, rs["public_key"])
                good, got = await wait_count(owner, rs["id"], 1, keep=[(m1, rs["public_key"])])
                ok("a stream published with an rtmp_ token is counted", sb == 200 and good, f"{sb} count {got}")
                s = await hook(hk, "/api/stream/event", {"event": "disconnect", "path": path})
                end = time.monotonic() + 20
                detail = {}
                while time.monotonic() < end:
                    _, b = await call(owner, "GET", f"/api/streams/{rs['id']}")
                    detail = (b or {}).get("stream", {})
                    if detail.get("is_live") == 0:
                        break
                    await asyncio.sleep(1.0)
                ok("its session figures are written when it goes offline",
                   detail.get("is_live") == 0 and detail.get("last_peak_viewers") == 1
                   and detail.get("last_unique_viewers") == 1, f"{detail.get('is_live')} {detail.get('last_peak_viewers')} {detail.get('last_unique_viewers')}")
        finally:
            for sid in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{sid}")
                except Exception:
                    pass
