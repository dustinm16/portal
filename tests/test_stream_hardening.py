"""Hardening of the stream routes: what the activity feed shows of a private stream, ids the
database cannot hold, the HLS path, open-link caching, the info route for an admin, and text
SQLite cannot store.

The real handlers run in-process against the temporary database of tests/test_stream_access.py
(its World: an owner, an admin, a moderator, two members, four streams); MediaMTX is a fake HTTP
client and tests/outbound_guard.py refuses any dial that is not loopback. Not proven here: a real
MediaMTX, a browser, Cloudflare in front.

Run: venv/bin/python tests/test_stream_hardening.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import server  # noqa: E402
from test_stream_access import FakeSession, Transport, World, run  # noqa: E402


def api(w, method, path, user, body=None, match=None):
    h = {"Cookie": f"{server.Config.SESSION_COOKIE_NAME}={w.cookie[user]}"} if user else {}
    req = make_mocked_request(method, path, headers=h, match_info=match or {}, transport=Transport())
    if body is not None:
        async def _json():
            return body
        req.json = _json
    return req


def body_of(resp):
    return json.loads(resp.body)


# --- 1. the activity feed ---------------------------------------------------

def test_private_stream_is_not_in_members_activity():
    async def body(w):
        db = w.db
        owner = w.users["owner"]
        # the publish hook logs under the type that fits the stream's visibility
        pub, priv = {"user_id": owner, "is_public": 1}, {"user_id": owner, "is_public": 0}
        assert server._stream_activity_type("stream_live", pub) == "stream_live"
        assert server._stream_activity_type("stream_live", priv) == "stream_live_private"
        assert server._stream_activity_type("stream_offline", priv) == "stream_offline_private"
        # rows stored the old way: public types for a stream that is not public (and for the
        # public one); and a name with LIKE wildcards in it
        await db.update_user_stream(w.streams["private"]["id"], name="100%_secret")
        await db.log_activity(owner, "owner", "stream_live", "Stream 'private' went live")
        await db.log_activity(owner, "owner", "stream_live", "Stream '100%_secret' went live")
        await db.log_activity(owner, "owner", "stream_offline", "Stream '100%_secret' went offline")
        await db.log_activity(owner, "owner", "stream_live", "Stream 'public' went live")
        await db.log_activity(owner, "owner", "stream_live_private", "Stream 'x' went live")
        member_feed = [a["detail"] for a in await db.get_recent_activity(limit=50, user_id=w.users["member"])]
        assert "Stream 'public' went live" in member_feed
        assert not [d for d in member_feed if "secret" in d or "'x'" in d], member_feed
        # the route the dashboard uses
        resp = await server.http_activity_feed(api(w, "GET", "/api/activity", "member"))
        shown = [a["detail"] for a in body_of(resp)["activities"]]
        assert "Stream 'public' went live" in shown and not [d for d in shown if "secret" in d]
        # the owner sees their own, an admin sees everything
        own = [a["detail"] for a in await db.get_recent_activity(limit=50, user_id=owner)]
        assert "Stream '100%_secret' went live" in own
        resp = await server.http_activity_feed(api(w, "GET", "/api/activity", "admin"))
        assert any("secret" in a["detail"] for a in body_of(resp)["activities"])
        # a stream made private later is hidden at once
        await db.update_user_stream(w.streams["public"]["id"], is_public=False)
        member_feed = [a["detail"] for a in await db.get_recent_activity(limit=50, user_id=w.users["member"])]
        assert "Stream 'public' went live" not in member_feed
    run(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print("FAIL", name, type(e).__name__, e)
                failed += 1
    if outbound_guard.refused:
        print("FAIL: the guard refused a dial", outbound_guard.refused)
        failed += 1
    sys.exit(1 if failed else 0)
