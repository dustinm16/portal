"""Follow-ups to the stream night: what is logged and announced when a stream goes offline, the
activity rows of a deleted private stream, and who is counted as a viewer after access is lost.

Runs the real handlers in-process against the temporary database of tests/test_stream_access.py.
Not proven here: a real MediaMTX, a real VOD finalisation, a browser.

Run: venv/bin/python tests/test_stream_followups.py
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
import viewers  # noqa: E402
from config import Config  # noqa: E402
from test_stream_access import Transport, _coro, _whep_request, run  # noqa: E402
from test_viewers import Clock, beat  # noqa: E402


async def activity(w, user, like="Stream %"):
    cur = await w.db.conn.execute(
        "SELECT action, detail FROM activity_log WHERE user_id = ? AND detail LIKE ? ORDER BY id", (user, like))
    return [(r[0], r[1]) for r in await cur.fetchall()]


def owner_request(w, method, path, match, data=None, user="owner"):
    req = make_mocked_request(method, path, match_info=match,
                              headers={"Cookie": f"{Config.SESSION_COOKIE_NAME}={w.cookie[user]}"},
                              transport=Transport())
    if data is not None:
        req.json = lambda: _coro(data)
    return req


class Offline:
    """Fake out the VOD stop and the webhook dispatch; record what the webhook was given."""

    def __enter__(self):
        self.calls = []
        self.saved = (server.stop_vod_recording, server.fire_webhook_event, server.asyncio.sleep)
        real_sleep = server.asyncio.sleep

        async def no_vod(*a, **k):
            return None

        async def hook(event, payload, *, meta=None):
            self.calls.append((event, payload, meta))
            return 0

        async def quick(t, *a, **k):
            return await real_sleep(0 if t == 7 else t)
        server.stop_vod_recording, server.fire_webhook_event, server.asyncio.sleep = no_vod, hook, quick
        return self

    def __exit__(self, *exc):
        server.stop_vod_recording, server.fire_webhook_event, server.asyncio.sleep = self.saved


async def finish(path, stream, sid):
    if path == "finalize":
        await server._finalize_stream_offline(stream)
    else:
        task = asyncio.create_task(server._handle_disconnect_grace(stream))
        server._disconnect_grace_tasks[sid] = task
        await task
    await asyncio.sleep(0.05)       # the webhook is a background task


def test_offline_is_logged_and_announced_by_what_the_stream_is_now():
    async def body(w):
        owner = w.users["owner"]
        sid = w.streams["public"]["id"]
        with Offline() as off:
            for path in ("finalize", "grace"):
                for case in ("still public", "made private", "renamed private", "deleted"):
                    off.calls.clear()
                    await w.db.conn.execute("DELETE FROM activity_log")
                    await w.db.conn.commit()
                    await w.db.update_user_stream(sid, is_public=True, name="public")
                    await w.db.set_stream_live(sid, True)
                    captured = await w.db.get_user_stream(sid)      # taken at disconnect
                    if case == "made private":
                        await w.db.update_user_stream(sid, is_public=False)
                    elif case == "renamed private":
                        await w.db.update_user_stream(sid, is_public=False, name="renamed")
                    elif case == "deleted":
                        await w.db.delete_user_stream(sid, user_id=owner)
                    await finish(path, captured, sid)
                    rows = await activity(w, owner)
                    meta = [c[2] for c in off.calls if c[0] == "stream.offline"]
                    assert len(rows) == 1 and len(meta) == 1, (path, case, rows, meta)
                    if case == "still public":
                        assert rows[0][0] == "stream_offline" and meta[0]["stream_public"] is True, (path, rows, meta)
                    else:
                        assert rows[0][0] == "stream_offline_private", (path, case, rows)
                        assert meta[0]["stream_public"] is False, (path, case, meta)
                    if case == "renamed private":
                        assert rows[0][1] == "Stream 'renamed' went offline", rows
                    if case == "deleted":
                        # put the stream back for the next round
                        w.streams["public"]["id"] = sid = await w.db.create_user_stream(
                            owner, "public", w.streams["public"]["live"], public_key=w.streams["public"]["pub"],
                            is_public=True)
    run(body)


def test_deleting_a_private_stream_keeps_its_public_time_rows_out_of_the_feed():
    async def body(w):
        owner = w.users["owner"]
        priv = w.streams["private"]
        await w.db.log_activity(owner, "owner", "stream_live", "Stream 'private' went live")
        await w.db.log_activity(owner, "owner", "stream_offline", "Stream 'private' went offline")
        await w.db.log_activity(owner, "owner", "stream_live", "Stream 'public' went live")
        resp = await server.http_delete_user_stream(
            owner_request(w, "DELETE", f"/api/streams/{priv['id']}", {"id": str(priv['id'])}))
        assert resp.status == 200
        rows = dict(await activity(w, owner, "Stream %"))
        assert sorted(a for a, d in await activity(w, owner)) == [
            "stream_live", "stream_live_private", "stream_offline_private"], await activity(w, owner)
        # a deleted public stream's rows are left as they were
        pub = w.streams["public"]
        resp = await server.http_delete_user_stream(
            owner_request(w, "DELETE", f"/api/streams/{pub['id']}", {"id": str(pub['id'])}))
        assert resp.status == 200
        assert ("stream_live", "Stream 'public' went live") in await activity(w, owner)
    run(body)


def fresh_viewers():
    clock = Clock()
    server._viewers = viewers.ViewerTracker(clock)
    server._viewer_beat_rate = viewers.RateWindow(server._VIEWER_BEAT_LIMIT, 60.0, clock=clock)
    return clock


def test_tracker_removals():
    t = viewers.ViewerTracker(Clock())
    for u in (1, 2, 3):
        t.touch(10, user_id=u)
    t.touch(10, client_id="c" * 20, addr="198.51.100.4")
    t.touch(11, user_id=2)
    assert t.remove_user(10, 2) == 1 and t.count(10) == 3 and t.count(11) == 1
    assert t.remove_user_everywhere(2) == 1 and t.count(11) == 0
    assert t.remove_except_owner(10, 1, anonymous_only=True) == 1 and t.count(10) == 2
    assert t.remove_except_owner(10, 1) == 1 and t.count(10) == 1
    # the per-address slot of a removed anonymous viewer is free again
    for i in range(viewers.MAX_ANON_PER_ADDRESS):
        assert t.touch(12, client_id=("%016d" % i), addr="198.51.100.5")
    assert not t.touch(12, client_id="z" * 16, addr="198.51.100.5")
    t.remove_except_owner(12, None, anonymous_only=True)
    assert t.touch(12, client_id="z" * 16, addr="198.51.100.5")


def test_viewers_are_removed_at_once_when_access_is_lost():
    async def body(w):
        fresh_viewers()
        server.db = w.db
        pub, opened = w.streams["public"], w.streams["open"]
        # made non-public: everybody but the owner goes
        for who in ("owner", "member", "other", "admin"):
            assert (await beat(w, pub["pub"], who)).status == 200
        assert server._viewers.count(pub["id"]) == 4
        resp = await server.http_update_user_stream(owner_request(
            w, "PUT", f"/api/streams/{pub['id']}", {"id": str(pub["id"])}, {"is_public": False}))
        assert resp.status == 200
        assert server._viewers.count(pub["id"]) == 1
        # an open link switched off: the logged-out viewer goes, the member stays
        assert (await beat(w, opened["pub"], "member")).status == 200
        assert (await beat(w, opened["pub"])).status == 200
        assert server._viewers.count(opened["id"]) == 2
        resp = await server.http_update_user_stream(owner_request(
            w, "PUT", f"/api/streams/{opened['id']}", {"id": str(opened["id"])}, {"allow_unauthenticated": False}))
        assert resp.status == 200
        assert server._viewers.count(opened["id"]) == 1
        # an edit that takes nobody's right (a rename) removes nobody
        resp = await server.http_update_user_stream(owner_request(
            w, "PUT", f"/api/streams/{opened['id']}", {"id": str(opened["id"])}, {"name": "open2"}))
        assert resp.status == 200 and server._viewers.count(opened["id"]) == 1
        # signed out everywhere (and the same call an account deletion makes)
        await server.close_user_websockets(w.users["member"])
        assert server._viewers.count(opened["id"]) == 0
    run(body)


def test_a_stream_ban_removes_the_viewer_and_forgets_his_whep_sessions():
    async def body(w):
        fresh_viewers()
        server.db = w.db
        pub = w.streams["public"]
        r = await server.http_stream_webrtc_whep(_whep_request(w, pub["pub"], "member"))
        assert r.status == 201
        # (the fake MediaMTX gives every offer the same session id: the other member's is added by hand)
        server._webrtc_session_remember("sess-other", "whep", pub["id"], "p", w.users["other"])
        assert (await beat(w, pub["pub"], "other")).status == 200
        assert server._viewers.count(pub["id"]) == 2
        mine = [k for k, v in server._webrtc_sessions.items() if v[4] == w.users["member"]]
        theirs = [k for k, v in server._webrtc_sessions.items() if v[4] == w.users["other"]]
        assert len(mine) == 1 and len(theirs) == 1
        resp = await server.http_create_stream_ban(owner_request(
            w, "POST", f"/api/streams/{pub['id']}/bans", {"id": str(pub["id"])}, {"user_id": w.users["member"]}))
        assert resp.status == 201, resp.body
        assert server._viewers.count(pub["id"]) == 1
        assert mine[0] not in server._webrtc_sessions and theirs[0] in server._webrtc_sessions
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
