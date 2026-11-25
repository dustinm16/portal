"""WHEP kick completeness, three cases of release 1.24.1.

1. A deleted stream (or the stream of a deleted account) is kicked from its MediaMTX paths even when the portal
   holds no record of the viewer (after a restart): the key is read before the row goes.
2. A stream made private keeps the sessions of everybody who may still watch it: an administrator is not kicked.
3. An owner session whose record has no MediaMTX id cannot be told apart in MediaMTX's list, so the sweep of
   unrecorded sessions is skipped (only recorded sessions of members who lost access are kicked).

MediaMTX is a local fake (shape of tests/fixtures/mediamtx-1.21.3/webrtc_whep_sessions_kick.json).
Run: venv/bin/python tests/test_access_whep_keep.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, make_mocked_request  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402

ITEM = json.loads((Path(__file__).parent / "fixtures" / "mediamtx-1.21.3" / "webrtc_whep_sessions_kick.json").read_text())["webrtcsessions_list_item"]
failures = []
DEADLINE = 60
KEY = "live_keepkey0123456789"


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeMtx:
    def __init__(self):
        self.sessions, self.kicked = {}, []

    def add(self, sid, path, state="read"):
        self.sessions[sid] = {**ITEM, "id": sid, "path": path, "state": state}

    async def start(self):
        app = web.Application()

        async def lst(request):
            items = list(self.sessions.values())
            return web.json_response({"itemCount": len(items), "pageCount": 1, "items": items})

        async def kick(request):
            sid = request.match_info["id"]
            if sid in self.sessions:
                del self.sessions[sid]
                self.kicked.append(sid)
                return web.json_response({"status": "ok"})
            return web.json_response({"status": "error"}, status=404)
        app.router.add_get("/v3/webrtcsessions/list", lst)
        app.router.add_post("/v3/webrtcsessions/kick/{id}", kick)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        return self

    async def stop(self):
        await self.srv.close()


def mid(n):
    return f"{n:08d}-aaaa-bbbb-cccc-000000000000"


async def settle():
    for _ in range(50):
        pending = [t for t in list(server._live_ops_tasks) if not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


async def main():
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    secevents.log.bind(db)
    ids = {}
    for name, role in (("sa", "superadmin"), ("owner", "user"), ("adm", "admin"), ("mem", "user"), ("gone", "user")):
        u = await create_user(name, "Pass-12345-xyz!", is_admin=role in ("admin", "superadmin"))
        await db.set_user_role(u["id"], role)
        ids[name] = u["id"]
    mtx = await FakeMtx().start()

    async def cfg():
        return {"api_port": mtx.srv.port}
    saved = (server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE)
    server._mediamtx_api_base = lambda c: f"http://127.0.0.1:{mtx.srv.port}"
    server._get_mediamtx_config = cfg
    server.Config.STAGE_MODE = False

    async def auth(request):
        return server.TokenPayload({"jti": "s", "sub": str(ids["sa"]), "scopes": ["*"]})
    server.authenticate_request = auth
    try:
        # --- 1. deleted stream, no record of the viewer
        for owner, label in (("owner", "route"), ("gone", "account")):
            key = KEY + label
            sid = await db.create_user_stream(ids[owner], label, key, public_key="pub_" + label * 6, is_public=True)
            server._webrtc_sessions.clear()
            mtx.sessions.clear()
            mtx.kicked.clear()
            mtx.add(mid(1), "live/" + key)
            mtx.add(mid(2), key)
            mtx.add(mid(3), "live/other-stream")
            mtx.add(mid(4), "live/" + key, state="publish")
            if label == "route":
                async def tok(request):
                    return server.TokenPayload({"jti": "s", "sub": str(ids["owner"]), "scopes": ["*"]})
                server.authenticate_request = tok
                req = make_mocked_request("DELETE", f"/api/streams/{sid}", match_info={"id": str(sid)})
                r = await server.http_delete_user_stream(req)
                server.authenticate_request = auth
                what = "deleting the stream"
            else:
                req = make_mocked_request("DELETE", f"/api/users/{ids[owner]}", match_info={"id": str(ids[owner])})
                r = await server.http_delete_user(req)
                what = "deleting the account"
            await settle()
            check(f"{what} answers 200", r.status == 200, str(r.status))
            check(f"{what} kicks viewers the portal holds no record of (both path forms), not the publisher or another stream",
                  sorted(mtx.kicked) == [mid(1), mid(2)], str(mtx.kicked))

        # --- 2 and 3. made private
        key = "live_keepprivate0123456"
        sid = await db.create_user_stream(ids["owner"] if "owner" in ids and False else ids["mem"], "p", key, public_key="pub_pppppp", is_public=False)
        OWNER = ids["mem"]

        def seed(owner_has_id=True, with_admin=True):
            server._webrtc_sessions.clear()
            mtx.sessions.clear()
            mtx.kicked.clear()
            rec = [("s-owner", OWNER, mid(1) if owner_has_id else None), ("s-viewer", ids["owner"], mid(3))]
            if with_admin:
                rec.append(("s-adm", ids["adm"], mid(2)))
            for sess, uid, api in rec:
                server._webrtc_session_remember(sess, "whep", sid, "live/" + key, uid, api)
            for n in (1, 2, 3):
                mtx.add(mid(n), "live/" + key)
            mtx.add(mid(5), "live/" + key)                      # a viewer with no record
        seed()
        server._stream_access_changed(sid, viewers="all", owner_id=OWNER)
        await settle()
        check("stream made private: the administrator's and the owner's sessions are kept",
              mid(1) not in mtx.kicked and mid(2) not in mtx.kicked, str(mtx.kicked))
        check("stream made private: the other viewer and the unrecorded one are kicked", sorted(mtx.kicked) == [mid(3), mid(5)], str(mtx.kicked))

        seed(owner_has_id=False)
        server._stream_access_changed(sid, viewers="all", owner_id=OWNER)
        await settle()
        check("an owner session whose record has no MediaMTX id is not kicked", mid(1) not in mtx.kicked, str(mtx.kicked))
        check("then only recorded sessions of members who lost access are kicked (no sweep of unrecorded ones)",
              mtx.kicked == [mid(3)] and mid(5) in mtx.sessions, str(mtx.kicked))

        seed(with_admin=False)
        server._stream_access_changed(sid, viewers="all", owner_id=OWNER)
        await settle()
        check("with nobody to keep but an owner whose session has an id, the sweep still runs", sorted(mtx.kicked) == [mid(2), mid(3), mid(5)], str(mtx.kicked))
    finally:
        server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE = saved
        await mtx.stop()


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check("finished within the deadline", False, f"{DEADLINE} s")
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
