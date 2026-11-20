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
from database import Database  # noqa: E402
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


def test_stored_activity_rows_follow_the_stream_into_private_and_through_a_rename():
    async def body(w):
        db = w.db
        owner = w.users["owner"]

        async def actions(detail):
            cur = await db.conn.execute("SELECT action FROM activity_log WHERE detail = ? ORDER BY id", (detail,))
            return [r["action"] for r in await cur.fetchall()]

        def feed():
            return db.get_recent_activity(limit=100, user_id=w.users["member"])

        async def put(stream, body):
            sid = str(w.streams[stream]["id"])
            resp = await server.http_update_user_stream(
                api(w, "PUT", f"/api/streams/{sid}", "owner", body=body, match={"id": sid}))
            assert resp.status == 200, resp.body

        # 1. rows stored while the stream was public go to the private types when it is switched
        await db.log_activity(owner, "owner", "stream_live", "Stream 'public' went live")
        await db.log_activity(owner, "owner", "stream_offline", "Stream 'public' went offline")
        await db.log_activity(owner, "owner", "stream_live", "Stream 'open' went live")
        assert "Stream 'public' went live" in [a["detail"] for a in await feed()]
        await put("public", {"is_public": False})
        assert await actions("Stream 'public' went live") == ["stream_live_private"]
        assert await actions("Stream 'public' went offline") == ["stream_offline_private"]
        assert await actions("Stream 'open' went live") == ["stream_live"], "another stream's row is left alone"
        # 2. renaming it (now not public) brings nothing back: not under the old, not under the new name
        await put("public", {"name": "renamed"})
        shown = [a["detail"] for a in await feed()]
        assert not [d for d in shown if "'public'" in d or "'renamed'" in d], shown
        assert "Stream 'open' went live" in shown
        # 3. old rows of a stream that was already private (stored public-typed) go on a rename too
        await db.log_activity(owner, "owner", "stream_live", "Stream 'private' went live")
        await db.conn.execute("UPDATE activity_log SET action = 'stream_live' WHERE detail = ?",
                              ("Stream 'private' went live",))
        await db.conn.commit()
        await put("private", {"name": "elsewhere"})
        assert await actions("Stream 'private' went live") == ["stream_live_private"]
        assert not [a for a in await feed() if "'private'" in a["detail"] or "'elsewhere'" in a["detail"]]
        # 4. start-up pass: relabels what is left for non-public streams, not a public stream's rows,
        # and a second pass changes nothing
        await db.log_activity(owner, "owner", "stream_live", "Stream 'elsewhere' went live")
        assert await actions("Stream 'elsewhere' went live") == ["stream_live"]
        await db._relabel_private_stream_activity_at_start()
        assert await actions("Stream 'elsewhere' went live") == ["stream_live_private"]
        assert await actions("Stream 'open' went live") == ["stream_live"]
        assert await db.relabel_private_stream_activity(owner, ["elsewhere", "renamed"]) == 0
    run(body)


# --- 2. ids the database cannot hold ---------------------------------------

HUGE = "9" * 25
BIG = str(2 ** 63)


def test_relabel_runs_only_when_a_stream_became_non_public_or_a_non_public_stream_was_renamed():
    async def body(w):
        db = w.db
        calls = []
        real = db.relabel_private_stream_activity

        async def counting(user_id, names, commit=True):
            calls.append(sorted(n for n in names if n))
            return await real(user_id, names, commit=commit)

        db.relabel_private_stream_activity = counting
        try:
            async def put(stream, body):
                sid = str(w.streams[stream]["id"])
                resp = await server.http_update_user_stream(
                    api(w, "PUT", f"/api/streams/{sid}", "owner", body=body, match={"id": sid}))
                assert resp.status == 200, resp.body
                return resp

            # a stream that is not public: an edit of the go-live message, the description, the
            # audience, or a name sent back unchanged, relabels nothing
            await put("private", {"golive_message": "hello"})
            await put("private", {"description": "text", "golive_audience": "everyone"})
            private_name = (await db.get_user_stream(w.streams["private"]["id"]))["name"]
            await put("private", {"name": private_name})
            assert calls == [], calls
            # the same edit of a public stream relabels nothing either
            await put("public", {"golive_message": "hello"})
            assert calls == [], calls
            # a rename of a non-public stream does, under the old and the new name
            await put("private", {"name": "renamed-private"})
            assert calls == [sorted([private_name, "renamed-private"])], calls
            # so does a public stream becoming non-public
            calls.clear()
            await put("public", {"is_public": False})
            assert len(calls) == 1, calls
            # and the message edit that follows does not
            calls.clear()
            await put("public", {"golive_message": "again"})
            assert calls == [], calls
        finally:
            db.relabel_private_stream_activity = real
    run(body)


def test_activity_log_has_the_owner_action_index_and_a_second_start_changes_nothing():
    async def body(w):
        async def schema(conn):
            cur = await conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
            return [tuple(r) for r in await cur.fetchall()]

        cur = await w.db.conn.execute("PRAGMA index_info(idx_activity_log_user_action)")
        assert [r["name"] for r in await cur.fetchall()] == ["user_id", "action"]
        cur = await w.db.conn.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM activity_log WHERE user_id = 1 AND action = 'stream_live' AND detail = 'x'")
        plan = " ".join(str(tuple(r)) for r in await cur.fetchall())
        assert "idx_activity_log_user_action" in plan, plan
        before = await schema(w.db.conn)
        second = Database(w.db.db_path)
        await second.connect()
        try:
            assert await schema(second.conn) == before
        finally:
            await second.close()
    run(body)

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


# --- 4. open-link thumbnails, the decision cache ----------------------------

def _max_age(resp):
    value = resp.headers["Cache-Control"]
    return value, int(value.split("max-age=")[1].split(",")[0])


def test_open_link_thumbnail_is_kept_at_most_five_seconds():
    async def body(w):
        for label in ("open", "public", "private"):
            key = w.streams[label]["pub"]
            user = None if label == "open" else "owner"
            for fresh in (True, False):
                server._thumbnail_cache[w.streams[label]["live"]] = (server.time() - (0 if fresh else 100), b"JPEG")
                if fresh:
                    r = await server.http_stream_thumbnail(w.req(key, user))
                else:
                    r = server._stale_thumbnail_response(w.streams[label]["live"], await _stream(w, label))
                value, age = _max_age(r)
                if label == "open":
                    assert value.startswith("public, ") and age <= 5, value
                else:
                    assert value.startswith("private, "), value
    run(body)


async def _stream(w, label):
    return await w.db.get_user_stream(w.streams[label]["id"])


def test_full_decision_cache_evicts_expired_then_oldest():
    async def body(w):
        key = w.streams["open"]["pub"]
        clock = [1000.0]
        real_now, small = server._playback_now, server._PLAYBACK_AUTH_MAX
        server._playback_now = lambda: clock[0]
        server._PLAYBACK_AUTH_MAX = 16
        try:
            server._playback_cache_forget(everything=True)
            for i in range(16):
                clock[0] += 0.1
                await server.http_stream_info(w.req(key, cookie="junk%d" % i))
            assert len(server._playback_auth_cache) == 16
            first_keys = list(server._playback_auth_cache)
            # full of live entries: one more must not wipe the others
            clock[0] += 0.1
            await server.http_stream_info(w.req(key, cookie="newcomer"))
            kept = [k for k in first_keys if k in server._playback_auth_cache]
            assert 8 <= len(kept) < 16, len(kept)
            assert first_keys[0] not in server._playback_auth_cache      # the oldest went
            assert first_keys[-1] in server._playback_auth_cache          # the newest stayed
            assert len(server._playback_auth_cache) <= 16
            # expired entries go first: a full cache whose entries have all expired keeps only the newcomer
            server._playback_cache_forget(everything=True)
            for i in range(16):
                await server.http_stream_info(w.req(key, cookie="old%d" % i))
            assert len(server._playback_auth_cache) == 16
            clock[0] += server._PLAYBACK_AUTH_TTL + 1
            await server.http_stream_info(w.req(key, cookie="late"))
            assert len(server._playback_auth_cache) == 1
        finally:
            server._playback_now, server._PLAYBACK_AUTH_MAX = real_now, small
    run(body)


# --- 5. the info route for an admin -----------------------------------------

def test_admin_gets_the_public_key_of_a_private_stream_never_the_stream_key():
    async def body(w):
        private = w.streams["private"]
        match = {"id": str(private["id"])}
        r = await server.http_get_user_stream(api(w, "GET", "/x", "admin", match=match))
        stream = body_of(r)["stream"]
        assert r.status == 200 and stream["public_key"] == private["pub"], stream
        assert "stream_key" not in stream and "stream_key_hash" not in stream and "public_key_hash" not in stream
        assert private["live"] not in json.dumps(stream)
        # the owner has both, a member and a moderator are refused, as before
        stream = body_of(await server.http_get_user_stream(api(w, "GET", "/x", "owner", match=match)))["stream"]
        assert stream["public_key"] == private["pub"] and stream["stream_key"] == private["live"]
        for user in ("member", "mod"):
            r = await server.http_get_user_stream(api(w, "GET", "/x", user, match=match))
            assert r.status == 404, (user, r.status)
        # a public stream shows its public key to everybody, never the stream key
        match = {"id": str(w.streams["public"]["id"])}
        for user in ("admin", "member"):
            stream = body_of(await server.http_get_user_stream(api(w, "GET", "/x", user, match=match)))["stream"]
            assert stream["public_key"] == w.streams["public"]["pub"] and "stream_key" not in stream
        # the watch page plays and chats with the public key it is given, for any viewer
        page = (ROOT / "static" / "watch.html").read_text()
        assert "streamData.public_key || streamData.stream_key" in page
        assert "/api/stream/${viewKey}/hls/index.m3u8" in page
    run(body)


# --- 6. text SQLite cannot store --------------------------------------------

def test_lone_surrogates_in_stream_text_are_a_400():
    async def body(w):
        await w.db.set_setting("allow_user_streams", "true")
        sid = str(w.streams["private"]["id"])
        for field in ("name", "description", "golive_message"):
            for bad in ("a\ud800b", "\udfff", "ok\udc00"):
                payload = {"name": "fine", field: bad}
                r = await server.http_update_user_stream(api(w, "PUT", "/x", "owner", payload, match={"id": sid}))
                assert r.status == 400, (field, r.status)
                r = await server.http_create_user_stream(api(w, "POST", "/api/streams", "owner", payload))
                assert r.status == 400, (field, r.status)
        clean, problem = server._validate_stream_fields({"name": "bad\ud800"})
        assert clean is None and problem
        # real text, including characters outside the basic plane, is untouched
        good = {"name": "caf\u00e9 \U00010348", "description": "d\u00e9j\u00e0", "golive_message": "{title} \u2014 live"}
        clean, problem = server._validate_stream_fields(good)
        assert problem is None and clean["name"] == good["name"]
        r = await server.http_update_user_stream(api(w, "PUT", "/x", "owner", good, match={"id": sid}))
        assert r.status == 200, r.status
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
