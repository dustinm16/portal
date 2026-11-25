"""A viewer who loses access at account level loses an established WebRTC (WHEP) playback: a demotion kicks the
sessions on streams the account can no longer read (and only those), a deletion kicks all of the account's
sessions, also on other people's streams. MediaMTX is a small local fake (shape of the 1.21.3 capture in
tests/fixtures/mediamtx-1.21.3/webrtc_whep_sessions_kick.json). Nothing leaves this machine.
Run: venv/bin/python tests/test_access_whep_account.py
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


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeMtx:
    def __init__(self):
        self.kicked = []

    async def start(self):
        app = web.Application()

        async def kick(request):
            self.kicked.append(request.match_info["id"])
            return web.json_response({"status": "ok"})

        async def lst(request):
            return web.json_response({"itemCount": 0, "pageCount": 1, "items": []})
        app.router.add_get("/v3/webrtcsessions/list", lst)
        app.router.add_post("/v3/webrtcsessions/kick/{id}", kick)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        return self


async def settle():
    for _ in range(50):
        pending = [t for t in list(server._live_ops_tasks) if not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


def aid(n):
    return f"{n:08d}-aaaa-bbbb-cccc-000000000000"


async def main():
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    secevents.log.bind(db)
    ids = {}
    for name, role in (("sa", "superadmin"), ("owner", "user"), ("adm", "admin"), ("viewer", "user")):
        u = await create_user(name, "Pass-12345-xyz!", is_admin=role == "superadmin")
        await db.set_user_role(u["id"], role)
        ids[name] = u["id"]
    private = await db.create_user_stream(ids["owner"], "p", "live_" + "p" * 8, public_key="pub_" + "p" * 8, is_public=False)
    members = await db.create_user_stream(ids["owner"], "m", "live_" + "m" * 8, public_key="pub_" + "m" * 8, is_public=True)
    mine = await db.create_user_stream(ids["adm"], "a", "live_" + "a" * 8, public_key="pub_" + "a" * 8, is_public=False)

    mtx = await FakeMtx().start()
    saved = (server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE, server.authenticate_request)

    async def cfg():
        return {"api_port": mtx.srv.port}

    async def fake_auth(request):
        return server.TokenPayload({"jti": "s1", "sub": str(ids["sa"]), "scopes": ["*"]})
    server._mediamtx_api_base = lambda c: f"http://127.0.0.1:{mtx.srv.port}"
    server._get_mediamtx_config = cfg
    server.Config.STAGE_MODE = False
    server.authenticate_request = fake_auth
    try:
        server._webrtc_sessions.clear()
        rem = server._webrtc_session_remember
        rem("r1", "whep", private, "live_" + "p" * 8, ids["adm"], aid(1))      # an administrator on a private stream
        rem("r2", "whep", members, "live_" + "m" * 8, ids["adm"], aid(2))      # the same on a members-only stream
        rem("r3", "whep", mine, "live_" + "a" * 8, ids["adm"], aid(3))         # on their own stream
        rem("r4", "whep", members, "live_" + "m" * 8, ids["viewer"], aid(4))   # another member
        rem("r5", "whep", members, "live_" + "m" * 8, ids["viewer"], aid(5))   # the same member, a second tab
        rem("r6", "whep", private, "live_" + "p" * 8, ids["owner"], aid(6))    # the owner

        req = make_mocked_request("PUT", f"/api/users/{ids['adm']}/role", match_info={"id": str(ids["adm"])})

        async def _json():
            return {"role": "user"}
        req.json = _json
        resp = await server.http_update_user_role(req)
        await settle()
        check("the demotion was accepted", resp.status == 200, str(resp.status))
        check("a demoted administrator's session on a stream they can no longer read is kicked",
              aid(1) in mtx.kicked, str(mtx.kicked))
        check("nothing else is kicked by a demotion (still readable, their own, other members, the owner)",
              sorted(mtx.kicked) == [aid(1)], str(mtx.kicked))
        check("the kicked session's record is forgotten, the others stay",
              "r1" not in server._webrtc_sessions and all(k in server._webrtc_sessions for k in ("r2", "r3", "r4", "r5", "r6")))

        mtx.kicked.clear()
        req = make_mocked_request("DELETE", f"/api/users/{ids['viewer']}", match_info={"id": str(ids['viewer'])})
        resp = await server.http_delete_user(req)
        await settle()
        check("the deletion was accepted", resp.status == 200, str(resp.status))
        check("a deleted account's sessions on other people's streams are kicked, nobody else's",
              sorted(mtx.kicked) == [aid(4), aid(5)], str(mtx.kicked))
    finally:
        server._mediamtx_api_base, server._get_mediamtx_config, server.Config.STAGE_MODE, server.authenticate_request = saved
        await mtx.srv.close()


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
