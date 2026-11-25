"""End now and Stop relays need an explicit {"confirm": true}; an absent regenerate_key keeps the key.

Reuses the world and the fake MediaMTX of the live operations tests. Run: venv/bin/python tests/test_access_confirm.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import test_live_ops_fixes as base  # noqa: E402  (loads the outbound guard first)
from test_live_ops_fixes import Spy, publish_hook, with_mtx  # noqa: E402
from test_stream_health_server import admin_req  # noqa: E402
import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


@with_mtx()
async def confirm_cases(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        for label, body in (("no body", "bare"), ("an empty object", {"__x": 1}), ("confirm false", {"confirm": False}),
                            ("confirm as text", {"confirm": "true"}), ("confirm 1", {"confirm": 1})):
            req = admin_req(w, "admin", sid, "end", "bare")
            payload = {} if body == "bare" else body
            if body != "bare":
                req.json = (lambda p: (lambda: _coro(p)))(payload)
            r = await server.http_admin_stream_end(req)
            check(f"End now with {label} answers 400", r.status == 400, str(r.status))
            req = admin_req(w, "admin", sid, "stop-relays", "bare")
            if body != "bare":
                req.json = (lambda p: (lambda: _coro(p)))(payload)
            r = await server.http_admin_stream_stop_relays(req)
            check(f"Stop relays with {label} answers 400", r.status == 400, str(r.status))
        row = await w.db.get_user_stream(sid)
        check("nothing happened: still live, key unchanged, no audit entry, no kick",
              row["is_live"] == 1 and not mtx.calls and not await w.db.get_audit_log(limit=10, action="stream_end_now"))
        # the page's request: confirm and its checkbox
        r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {"confirm": True}))
        out = json.loads(r.body)
        check("End now with only confirm: ends, and keeps the key", r.status == 200 and out["key_replaced"] is False, str(out))
        check("the stored key is the one the stream had", (await w.db.get_user_stream(sid))["stream_key"] == key)
    check("a non-administrator still gets 404 before the confirm question",
          (await server.http_admin_stream_end(admin_req(w, "owner", sid, "end", "bare"))).status == 404)


async def _coro(p):
    return p


@with_mtx()
async def regenerate_when_asked(w, mtx):
    sid, key = w.streams["public"]["id"], w.streams["public"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {"regenerate_key": True}))
        check("regenerate_key true replaces the key", r.status == 200 and json.loads(r.body)["key_replaced"] is True)


for fn in (confirm_cases, regenerate_when_asked):
    try:
        fn()
    except Exception as e:
        import traceback
        traceback.print_exc()
        check(fn.__name__ + " ran", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
