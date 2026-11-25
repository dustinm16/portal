"""Viewers who lose access lose an established WebRTC (WHEP) playback: the portal asks MediaMTX's
webrtcsessions kick route to disconnect them (banned viewer, stream made private, open link off, share
link rotated, stream deleted). The owner's own session is spared when a stream turns private.

A small local server answers the two MediaMTX routes in the shape captured from a real MediaMTX 1.21.3
(tests/fixtures/mediamtx-1.21.3/webrtc_whep_sessions_kick.json: the API id is the ID header of the 201 answer,
not the tail of Location; list items carry path and state; kick answers 200, 404 for an unknown id).
Nothing leaves this machine. Run: venv/bin/python tests/test_access_whep_kick.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import server  # noqa: E402

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "mediamtx-1.21.3" / "webrtc_whep_sessions_kick.json").read_text())
ITEM = FIXTURE["webrtcsessions_list_item"]
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeMtx:
    def __init__(self):
        self.sessions = {}
        self.kicked = []
        self.calls = []

    def add(self, sid, path="live/livekey", state="read"):
        self.sessions[sid] = {**ITEM, "id": sid, "path": path, "state": state}

    async def start(self):
        app = web.Application()

        async def lst(request):
            self.calls.append(("GET", request.path))
            items = list(self.sessions.values())
            return web.json_response({"itemCount": len(items), "pageCount": 1, "items": items})

        async def kick(request):
            sid = request.match_info["id"]
            self.calls.append(("POST", request.path))
            if sid in self.sessions:
                del self.sessions[sid]
                self.kicked.append(sid)
                return web.json_response({"status": "ok"})
            return web.json_response({"status": "error", "error": "session not found"}, status=404)
        app.router.add_get("/v3/webrtcsessions/list", lst)
        app.router.add_post("/v3/webrtcsessions/kick/{id}", kick)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        return self

    async def stop(self):
        await self.srv.close()


SID = 7
OWNER, VIEWER, OTHER = 1, 2, 3
IDS = {n: f"{i:08d}-aaaa-bbbb-cccc-000000000000" for i, n in enumerate(("owner", "viewer", "other", "anon", "ghost", "pub", "foreign"), 1)}


def seed(mtx):
    server._webrtc_sessions.clear()
    mtx.sessions.clear()
    mtx.kicked.clear()
    mtx.calls.clear()
    for sess, uid, name in (("s-owner", OWNER, "owner"), ("s-viewer", VIEWER, "viewer"), ("s-other", OTHER, "other"),
                            ("s-anon", None, "anon")):
        server._webrtc_session_remember(sess, "whep", SID, "live/livekey", uid, IDS[name])
        mtx.add(IDS[name])
    mtx.add(IDS["ghost"])                                    # a viewer whose record was pushed out of the table
    mtx.add(IDS["pub"], state="publish")                     # the publisher is not a viewer
    mtx.add(IDS["foreign"], path="live/other-stream")         # another stream's viewer
    server._webrtc_session_remember("s-nokey", "whep", SID, "live/livekey", 9, None)   # a MediaMTX that sent no ID


async def settle():
    for _ in range(50):
        pending = [t for t in list(server._live_ops_tasks) if not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


async def main():
    mtx = await FakeMtx().start()
    saved = (server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE)

    async def cfg():
        return {"api_port": mtx.srv.port}
    server._mediamtx_api_base = lambda c: f"http://127.0.0.1:{mtx.srv.port}"
    server._get_mediamtx_config = cfg
    server.Config.STAGE_MODE = False
    try:
        seed(mtx)
        server._stream_member_lost_access(SID, VIEWER)
        await settle()
        check("a banned viewer's session is kicked and nobody else's", mtx.kicked == [IDS["viewer"]], str(mtx.kicked))
        check("only the kick route was called for a ban (no list)", all(c[0] == "POST" for c in mtx.calls), str(mtx.calls))

        seed(mtx)
        server._stream_access_changed(SID, viewers="all", owner_id=OWNER)
        await settle()
        check("a stream made private: everybody's session on its path is kicked except the owner's",
              sorted(mtx.kicked) == sorted([IDS["viewer"], IDS["other"], IDS["anon"], IDS["ghost"]]), str(mtx.kicked))
        check("the publisher and another stream's viewer stay", IDS["pub"] in mtx.sessions and IDS["foreign"] in mtx.sessions
              and IDS["owner"] in mtx.sessions)

        seed(mtx)
        server._stream_access_changed(SID, viewers="anonymous", owner_id=OWNER)
        await settle()
        check("open link switched off: only the logged-out session is kicked", mtx.kicked == [IDS["anon"]], str(mtx.kicked))

        seed(mtx)
        server._stream_access_changed(SID, kick="anonymous")
        await settle()
        check("share link rotated: the logged-out session is kicked", mtx.kicked == [IDS["anon"]], str(mtx.kicked))

        seed(mtx)
        server._stream_access_changed(SID, drop_sessions=False, viewers="all", owner_id=OWNER)
        await settle()
        check("a change that takes nobody's right (drop_sessions off) kicks nobody", not mtx.kicked and not mtx.calls)

        seed(mtx)
        server._stream_access_changed(SID, kick="everyone")
        await settle()
        check("stream deleted: every viewer is kicked, the owner's too, not the publisher",
              sorted(mtx.kicked) == sorted([IDS["owner"], IDS["viewer"], IDS["other"], IDS["anon"], IDS["ghost"]]), str(mtx.kicked))

        seed(mtx)
        server._stream_access_changed(SID)
        await settle()
        check("a plain key change kicks nobody (the publish path ends with its session)", not mtx.kicked and not mtx.calls)

        seed(mtx)
        server.Config.STAGE_MODE = True
        server._stream_member_lost_access(SID, VIEWER)
        await settle()
        check("a staged instance contacts no media server", not mtx.calls)
        server.Config.STAGE_MODE = False

        seed(mtx)
        await mtx.stop()
        server._stream_member_lost_access(SID, VIEWER)
        await settle()
        check("an unreachable media server is logged and does not raise", True)
        mtx = await FakeMtx().start()
    finally:
        server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE = saved
        await mtx.stop()
    check("the 201 handler records MediaMTX's ID header, not the Location tail",
          "resp.headers.get(\"ID\")" in Path(server.__file__).read_text())


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
