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


# --- 2. ids the database cannot hold ---------------------------------------

HUGE = "9" * 25
BIG = str(2 ** 63)


def test_out_of_range_ids_answer_as_unknown_streams():
    async def body(w):
        member_id = w.users["member"]
        routes = [
            ("member", server.http_follow_stream, None),
            ("member", server.http_get_user_stream, None),
            ("owner", server.http_update_user_stream, {"name": "x"}),
            ("owner", server.http_delete_user_stream, None),
            ("owner", server.http_get_stream_bans, None),
            ("owner", server.http_create_stream_ban, {"user_id": member_id}),
            ("owner", server.http_list_relay_destinations, None),
            ("owner", server.http_regenerate_stream_key, None),
            ("owner", server.http_regenerate_public_key, None),
        ]
        for user, handler, payload in routes:
            reference = (await handler(api(w, "GET", "/x", user, payload, match={"id": "99999"}))).status
            assert reference in (403, 404), (handler.__name__, reference)
            for raw in (HUGE, BIG, "0", "-5"):
                r = await handler(api(w, "GET", "/x", user, payload, match={"id": raw}))
                assert r.status == reference, (handler.__name__, raw, r.status, reference)
        for raw in (HUGE, BIG, "0", "-5"):
            r = await server.http_unfollow_stream(api(w, "DELETE", "/x", "member", match={"id": raw}))
            assert r.status == 404, (raw, r.status)
        r = await server.http_unfollow_stream(api(w, "DELETE", "/x", "member", match={"id": "99999"}))
        assert r.status == 200
        sid = str(w.streams["private"]["id"])
        for raw in (HUGE, BIG):
            m = {"id": sid, "user_id": raw, "ban_id": raw, "relay_id": raw}
            r = await server.http_remove_stream_ban(api(w, "DELETE", "/x", "owner", match=m))
            assert r.status < 500, r.status
            r = await server.http_remove_stream_ban_by_id(api(w, "DELETE", "/x", "owner", match=m))
            assert r.status < 500, r.status
            r = await server.http_get_relay_logs(api(w, "GET", "/x", "owner", match=m))
            assert r.status == 404, r.status
            r = await server.http_delete_relay_destination(api(w, "DELETE", "/x", "owner", match=m))
            assert r.status == 404, r.status
        r = await server.http_create_stream_ban(api(w, "POST", "/x", "owner", {"user_id": 2 ** 70}, match={"id": sid}))
        assert r.status == 400, r.status
        # a number that is fine still works, an unreadable one is still a 400
        r = await server.http_follow_stream(api(w, "PUT", "/x", "member", match={"id": str(w.streams["public"]["id"])}))
        assert r.status == 200, r.status
        r = await server.http_get_user_stream(api(w, "GET", "/x", "member", match={"id": "abc"}))
        assert r.status == 400
    run(body)


def test_announce_channel_is_checked_before_anything_is_saved():
    async def body(w):
        db = w.db
        await db.set_setting("allow_user_streams", "true")
        await db.set_setting("allow_user_connections", "true")
        for value in (2 ** 63, 2 ** 70, 0, -1, True, "7"):
            r = await server.http_update_feature_permissions(
                api(w, "PUT", "/api/settings/permissions", "admin",
                    {"allow_user_streams": False, "allow_user_connections": False,
                     "stream_announce_channel_id": value}))
            assert r.status == 400, (value, r.status)
            assert await db.get_setting("allow_user_streams") == "true", value
            assert await db.get_setting("allow_user_connections") == "true", value
        # a channel that does not exist is refused the same way, nothing saved
        r = await server.http_update_feature_permissions(
            api(w, "PUT", "/x", "admin", {"allow_user_streams": False, "stream_announce_channel_id": 987654}))
        assert r.status == 404 and await db.get_setting("allow_user_streams") == "true"
        # a valid request still saves
        r = await server.http_update_feature_permissions(
            api(w, "PUT", "/x", "admin", {"allow_user_streams": False, "stream_announce_channel_id": None}))
        assert r.status == 200 and await db.get_setting("allow_user_streams") == "false"
    run(body)


# --- 3. the HLS path --------------------------------------------------------

def test_hls_path_is_one_plain_file_name():
    async def body(w):
        key = w.streams["private"]["pub"]
        other = w.streams["second"]["live"]
        refused_body = (await server.http_stream_hls_proxy(w.req("pub_nope" + "x" * 12, "owner"))).body
        bad = ["../index.m3u8", "..", "a/../b.m3u8", f"../{other}/index.m3u8", f"../../live/{other}/index.m3u8",
               "/etc/passwd", "/index.m3u8", "\\index.m3u8", "..\\index.m3u8", "a\\b.m3u8",
               "%2e%2e/index.m3u8", "%2e%2e%2findex.m3u8", "..%2findex.m3u8", "%252e%252e%252findex.m3u8",
               "%5cindex.m3u8", "sub/index.m3u8", "./index.m3u8", ".hidden.m3u8", "a..m3u8",
               "index.m3u8/", "index.m3u8\n", "", "index", "index.php", "x" * 200 + ".mp4"]
        for path in bad:
            FakeSession.calls = []
            r = await server.http_stream_hls_proxy(w.req(key, "owner", path=path))
            assert r.status == 404 and r.body == refused_body, (path, r.status)
            assert not FakeSession.calls, (path, FakeSession.calls)
        for path in ("index.m3u8", "stream.m3u8", "main_stream.m3u8", "video1_stream.m3u8", "seg0.mp4",
                     "init.mp4", "a1b2c3d4_seg12.mp4", "prog_0.m4s", "segment.ts", "audio.aac"):
            FakeSession.calls = []
            r = await server.http_stream_hls_proxy(w.req(key, "owner", path=path))
            assert r.status == 200, (path, r.status)
            assert FakeSession.calls[-1][1].startswith(f"https://127.0.0.1:8888/live/{w.streams['private']['live']}/{path}"), FakeSession.calls
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
