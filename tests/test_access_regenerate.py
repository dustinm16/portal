"""Regenerating the stream key: while live it ends the live session like End now (after the owner confirms
in the request), the old key's sockets are closed, and the disconnect hook finds a stream by the path its
session published on when the key no longer names it.

World and fake MediaMTX of the live operations tests. Run: venv/bin/python tests/test_access_regenerate.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import test_live_ops_fixes as base  # noqa: E402
from test_live_ops_fixes import Spy, publish_hook, rotate_key, with_mtx  # noqa: E402
from test_stream_health_server import req  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from test_stream_access import Transport  # noqa: E402
import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def regen(w, user, sid, body=None):
    r = req(w, user, sid, "POST", "regenerate-key", body, route="streams")
    resp = await server.http_regenerate_stream_key(r)
    return resp.status, (json.loads(resp.body) if resp.body else None)


class FakeWS:
    def __init__(self):
        self.closed_with = None

    async def close(self, code=None, message=b""):
        self.closed_with = code


@with_mtx()
async def live_cases(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    owner = w.users["owner"]
    old_ws, sess_ws = FakeWS(), FakeWS()
    server._user_websockets.setdefault(owner, {})[old_ws] = f"streamkey-{sid}"
    server._user_websockets[owner][sess_ws] = "t-session"
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        st, out = await regen(w, "owner", sid)
        check("a live stream: regenerate without the confirmation answers 409 and says it is live",
              st == 409 and out.get("live") is True, str((st, out)))
        row = await w.db.get_user_stream(sid)
        check("nothing changed: still live, same key, nobody kicked", row["is_live"] == 1 and row["stream_key"] == key and not mtx.calls)
        check("a member who does not own it is refused as before", (await regen(w, "member", sid, {"end_live_session": True}))[0] == 403)
        st, out = await regen(w, "owner", sid, {"end_live_session": True})
        check("with the confirmation: 200, the new key, the session ended", st == 200 and out["ended_live_session"] is True
              and out["stream_key"] != key and out["publisher_disconnected"] is True, str((st, out)))
        row = await w.db.get_user_stream(sid)
        check("the stream is offline with the new key and the old key resolves to nothing",
              row["is_live"] == 0 and row["stream_key"] == out["stream_key"] and await w.db.get_stream_by_key(key) is None)
        check("the publisher was disconnected on the session's path", ("GET", f"/v3/paths/get/live/{key}") in mtx.calls
              and ("POST", "/v3/rtmpconns/kick/69e7ffff-16c5-4590-b049-e36dffd0a1cd") in mtx.calls, str(mtx.calls))
        check("no administrator audit entry and no 'an administrator ended your stream' notice",
              not await w.db.get_audit_log(limit=20, action="stream_end_now")
              and not [n for n in await w.db.get_notifications(owner, limit=50) if n["type"] == "stream_ended"])
        check("the old key's socket was closed, the session's was not", old_ws.closed_with is not None and sess_ws.closed_with is None)
    server._user_websockets.get(owner, {}).pop(old_ws, None)
    server._user_websockets.get(owner, {}).pop(sess_ws, None)


@with_mtx()
async def offline_case(w, mtx):
    sid = w.streams["public"]["id"]
    row = await w.db.get_user_stream(sid)
    if row["is_live"] == 1:
        await w.db.set_stream_live(sid, False)
    st, out = await regen(w, "owner", sid)
    check("an offline stream: plain regeneration, no confirmation needed, nobody contacted",
          st == 200 and out["ended_live_session"] is False and out["stream_key"] and not mtx.calls, str((st, out)))
    ws = FakeWS()
    server._user_websockets.setdefault(w.users["owner"], {})[ws] = f"streamkey-{sid}"
    await regen(w, "owner", sid)
    check("its old key's sockets are closed on any regeneration", ws.closed_with is not None)
    server._user_websockets.get(w.users["owner"], {}).pop(ws, None)


@with_mtx()
async def hook_case(w, mtx):
    sid, key = w.streams["public"]["id"], w.streams["public"]["live"]
    async with Spy(w):
        await w.db.set_stream_live(sid, False)
        assert (await publish_hook(w, key)).status == 200
        new = await rotate_key(w, sid)                  # replaced by a path that does not end the session
        check("the stored key no longer names the old path", await w.db.get_stream_by_key(key) is None)
        check("the session still knows its path", server._stream_id_by_session_path("live/" + key) == sid
              and server._stream_id_by_session_path(key) == sid and server._stream_id_by_session_path("live/" + new) is None)
        hook = make_mocked_request("POST", "/api/stream/event", transport=Transport("127.0.0.1"))

        async def _json():
            return {"event": "disconnect", "path": "live/" + key}
        hook.json = _json
        server._disconnect_grace_tasks.pop(sid, None)
        resp = await server.http_stream_event(hook)
        task = server._disconnect_grace_tasks.get(sid)
        check("the disconnect hook starts the grace period for the stream by its session path", resp.status == 200 and task is not None)
        if task:
            task.cancel()
            server._disconnect_grace_tasks.pop(sid, None)


for fn in (live_cases, offline_case, hook_case):
    try:
        fn()
    except Exception as e:
        import traceback
        traceback.print_exc()
        check(fn.__name__ + " ran", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
