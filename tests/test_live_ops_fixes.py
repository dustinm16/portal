"""Fixes to the stream health panel and the administrator's live operations (fix pass A of 1.24.0).

In-process against the temporary database of tests/test_stream_access.py, with the fake MediaMTX control
API of tests/test_stream_health_server.py. Nothing leaves this machine (tests/outbound_guard.py).

Item 1: a session of a stream is identified; ending an earlier session never touches the next one.
Item 2: an End now (and a Stop relays) is claimed per stream; the loser answers 409.
Item 3: the path a session was published on is remembered and used for the ingest reading and the kick.
Item 4: relays an administrator stopped are shown as such, not as failing.
Item 5: the Live streams list has its own limiter.
Item 6: the paths list is read page by page; kick and parser handle MediaMTX 1.9.3 and 1.21.3.

Run: venv/bin/python tests/test_live_ops_fixes.py
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402
import stream_health  # noqa: E402
from aiohttp import web  # noqa: E402
from test_stream_access import run  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from test_stream_access import Transport  # noqa: E402
from test_stream_health_server import (  # noqa: E402
    _counted, _self_signed_cert, admin_req, fresh, health, paths_for, req, tick, with_clock, with_mtx,
)


class Proc:
    name = "rec"
    returncode = None


def with_world(fn):
    def runner():
        async def body(w):
            fresh()
            await fn(w)
        run(body)
    runner.__name__ = fn.__name__
    return runner


class Spy:
    """Replaces what a finalisation reaches outside the database and records the calls."""

    def __init__(self, w):
        self.w = w
        self.webhooks, self.broadcasts, self.cleared, self.finished = [], [], [], []

    async def __aenter__(self):
        w = self.w
        self.saved = (server.fire_webhook_event, server.broadcast_to_channel, server._spawn_go_live,
                      server._schedule_note_go_live, server._viewers.finish, w.db.clear_channel_messages)

        async def hook(event, payload, *, meta=None):
            self.webhooks.append((event, payload))
            return 0

        async def bc(channel, message, *a, **k):
            self.broadcasts.append((channel, message))

        async def noop(*a, **k):
            return None
        real_finish = server._viewers.finish
        real_clear = w.db.clear_channel_messages

        def finish(sid):
            self.finished.append(sid)
            return real_finish(sid)

        async def clear(cid, stats=None):
            self.cleared.append(cid)
            return await real_clear(cid, stats=stats)
        server.fire_webhook_event, server.broadcast_to_channel = hook, bc
        server._spawn_go_live, server._schedule_note_go_live = (lambda sid: None), noop
        server._viewers.finish = finish
        w.db.clear_channel_messages = clear
        return self

    async def __aexit__(self, *exc):
        w = self.w
        (server.fire_webhook_event, server.broadcast_to_channel, server._spawn_go_live,
         server._schedule_note_go_live, server._viewers.finish, w.db.clear_channel_messages) = self.saved


async def with_chat(w, sid):
    cid = await w.db.create_chat_channel("held-" + str(sid), None, w.users["owner"])
    await w.db.update_user_stream(sid, chat_channel_id=cid)
    return cid


async def offline_rows(w, sid):
    cur = await w.db.conn.execute("SELECT detail FROM activity_log WHERE detail LIKE ?", ("%went offline%",))
    return [r[0] for r in await cur.fetchall()]


@with_world
async def test_reconnect_during_a_held_finalisation_leaves_the_new_session_live(w):
    sid = w.streams["public"]["id"]
    cid = await with_chat(w, sid)
    stream = await w.db.get_user_stream(sid)
    async with Spy(w) as spy:
        await server._mark_stream_live(stream, "198.51.100.7")          # the first session
        rec = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
        server.active_recordings[sid] = rec
        hold, popped = asyncio.Event(), []

        async def held_stop(stream_id, force=False, only=None):
            popped.append(only)
            await hold.wait()
        saved = server.stop_vod_recording
        server.stop_vod_recording = held_stop
        try:
            await server._stream_end_session(stream)                    # End now: encoding, finalisation held
            assert (await w.db.get_user_stream(sid))["is_live"] == 2
            fin = [t for t in asyncio.all_tasks() if "_finalize_stream_offline" in repr(t.get_coro())]
            assert len(fin) == 1
            server.active_recordings.pop(sid, None)
            # the key box was off: the encoder reconnects at once and the stream is live again
            await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
            assert (await w.db.get_user_stream(sid))["is_live"] == 1
            before = list(spy.broadcasts)
            hold.set()
            await asyncio.gather(*fin)
        finally:
            server.stop_vod_recording = saved
        row = await w.db.get_user_stream(sid)
        assert row["is_live"] == 1, "the new session was marked offline by the finalisation of the old one"
        assert not await offline_rows(w, sid), "an offline record was written for a stream that is live"
        assert [e for e, _p in spy.webhooks if e == "stream.offline"] == [], spy.webhooks
        assert spy.cleared == [] and spy.finished == [], (spy.cleared, spy.finished)
        assert not [m for _c, m in spy.broadcasts[len(before):] if m.get("is_live") == 0], spy.broadcasts
    assert cid


@with_world
async def test_reconnect_before_the_encoding_write_is_not_ended_either(w):
    sid = w.streams["public"]["id"]
    stream = await w.db.get_user_stream(sid)
    async with Spy(w) as spy:
        await server._mark_stream_live(stream, "198.51.100.7")
        server.active_recordings[sid] = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
        saved = server.stop_stream_relays

        async def relays_then_reconnect(stream_id, force=False):
            # the encoder reconnects while the relays are being stopped; the stream is still marked live
            await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        server.stop_stream_relays = relays_then_reconnect
        try:
            await server._stream_end_session(stream)
        finally:
            server.stop_stream_relays = saved
            server.active_recordings.pop(sid, None)
        assert (await w.db.get_user_stream(sid))["is_live"] == 1
        assert not [t for t in asyncio.all_tasks() if "_finalize_stream_offline" in repr(t.get_coro())]
        assert not await offline_rows(w, sid) and spy.webhooks == [] and spy.finished == []


@with_world
async def test_a_plain_end_still_ends_the_session_and_clears_the_chat(w):
    sid = w.streams["public"]["id"]
    await with_chat(w, sid)
    stream = await w.db.get_user_stream(sid)
    async with Spy(w) as spy:
        await server._mark_stream_live(stream, "198.51.100.7")
        await server._stream_end_session(await w.db.get_user_stream(sid))
        await asyncio.sleep(0.05)
        assert (await w.db.get_user_stream(sid))["is_live"] == 0
        assert len(await offline_rows(w, sid)) == 1
        assert [e for e, _p in spy.webhooks] == ["stream.offline"], spy.webhooks
        assert len(spy.cleared) == 1 and spy.finished == [sid]
        assert any(m.get("is_live") == 0 for _c, m in spy.broadcasts)


@with_world
async def test_a_recording_of_a_newer_session_is_not_stopped_by_the_older_one(w):
    sid = w.streams["public"]["id"]
    old = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
    new = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
    server.active_recordings[sid] = new
    await server.stop_vod_recording(sid, only=old)
    assert server.active_recordings.get(sid) is new


async def end_now(w, sid, body=None):
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", body if body is not None else {}))
    return r.status, (json.loads(r.body) if r.body else None)


async def audit_count(w, action):
    return len(await w.db.get_audit_log(limit=50, action=action))


@with_mtx()
async def test_two_end_now_requests_at_once_end_the_stream_once(w, mtx):
    sid = w.streams["public"]["id"]
    async with Spy(w) as spy:
        await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        a, b = await asyncio.gather(end_now(w, sid, {"regenerate_key": False}),
                                    end_now(w, sid, {"regenerate_key": False}))
        await asyncio.sleep(0.05)
        assert sorted([a[0], b[0]]) == [200, 409], (a, b)
        loser = a if a[0] == 409 else b
        assert "already being ended" in loser[1]["error"] and "/" not in loser[1]["error"]
        assert await audit_count(w, "stream_end_now") == 1
        assert len(await offline_rows(w, sid)) == 1
        assert [e for e, _p in spy.webhooks].count("stream.offline") == 1, spy.webhooks
        notes = [n for n in await w.db.get_notifications(w.users["owner"], limit=50) if n["type"] == "stream_ended"]
        assert len(notes) == 1
    assert not server._end_claims


@with_mtx()
async def test_a_second_end_now_while_the_first_is_uploading_is_refused_and_the_claim_is_released(w, mtx):
    sid = w.streams["public"]["id"]
    async with Spy(w) as spy:
        await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        server.active_recordings[sid] = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
        hold = asyncio.Event()

        async def held_stop(stream_id, force=False, only=None):
            await hold.wait()
            raise RuntimeError("the upload failed")
        saved = (server.stop_vod_recording, server._vod_graceful_stop)

        async def graceful(p):
            return "q"
        server.stop_vod_recording, server._vod_graceful_stop = held_stop, graceful
        try:
            st, _ = await end_now(w, sid, {"regenerate_key": False})
            assert st == 200 and sid in server._end_claims          # held until the finalisation is over
            st, body = await end_now(w, sid, {"regenerate_key": False})
            assert st == 409 and await audit_count(w, "stream_end_now") == 1
            hold.set()
            await asyncio.gather(*[t for t in asyncio.all_tasks() if "_finalize_stream_offline" in repr(t.get_coro())])
        finally:
            server.stop_vod_recording, server._vod_graceful_stop = saved
        assert sid not in server._end_claims, "a failed finalisation must release the claim"
        assert (await w.db.get_user_stream(sid))["is_live"] == 0        # the failure path still ends it
        await asyncio.sleep(0.05)               # the webhook is a background task
        assert [e for e, _p in spy.webhooks].count("stream.offline") <= 1     # the failure path records none (as before)


@with_mtx()
async def test_the_disconnect_grace_and_end_now_do_not_end_the_same_session_twice(w, mtx):
    sid = w.streams["public"]["id"]
    async with Spy(w) as spy:
        await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        release, started = asyncio.Event(), asyncio.Event()
        saved = (server.stop_stream_relays, asyncio.sleep)

        async def slow_relays(stream_id, force=False):
            started.set()
            await release.wait()
        real_sleep = saved[1]

        async def fast(t, *a, **k):
            return await real_sleep(0)
        server.stop_stream_relays, asyncio.sleep = slow_relays, fast
        try:
            stream = await w.db.get_user_stream(sid)
            task = asyncio.create_task(server._handle_disconnect_grace(stream, server._stream_sessions.get(sid)))
            server._disconnect_grace_tasks[sid] = task
            await started.wait()                        # the grace task holds the claim and is ending the session
            st, body = await end_now(w, sid, {"regenerate_key": False})
            assert st == 409 and await audit_count(w, "stream_end_now") == 0, (st, body)
            release.set()
            await task
        finally:
            server.stop_stream_relays, asyncio.sleep = saved
            server._disconnect_grace_tasks.pop(sid, None)
        await asyncio.sleep(0.05)
        assert [e for e, _p in spy.webhooks].count("stream.offline") == 1
        assert not server._end_claims


@with_mtx()
async def test_two_stop_relays_requests_at_once_stop_them_once(w, mtx):
    sid = w.streams["private"]["id"]
    release, entered = asyncio.Event(), []
    saved = server.stop_stream_relays

    async def slow(stream_id, force=False):
        entered.append(stream_id)
        await release.wait()
    server.stop_stream_relays = slow
    try:
        async def stop():
            r = await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays", {}))
            return r.status, json.loads(r.body)
        t1 = asyncio.create_task(stop())
        await asyncio.sleep(0.05)
        t2 = asyncio.create_task(stop())
        await asyncio.sleep(0.05)
        release.set()
        results = await asyncio.gather(t1, t2)
    finally:
        server.stop_stream_relays = saved
    assert sorted(r[0] for r in results) == [200, 409], results
    assert len(entered) == 1 and await audit_count(w, "stream_stop_relays") == 1
    assert not server._relay_stop_claims
    again = await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays", {}))
    assert again.status == 200                  # the claim is gone once the first one is done


async def publish_hook(w, path):
    """The MediaMTX publish hook for live/<path>, as the portal receives it (loopback)."""
    hook = make_mocked_request("POST", "/api/stream/auth", transport=Transport("127.0.0.1"))

    async def _json():
        return {"action": "publish", "path": "live/" + path, "ip": "198.51.100.7", "user": "", "password": "", "query": ""}
    hook.json = _json
    return await server.http_stream_auth(hook)


async def publish_hook_on(w, path, password=""):
    """The MediaMTX publish hook for any path name, as it arrives (a browser publish is on "<key>")."""
    hook = make_mocked_request("POST", "/api/stream/auth", transport=Transport("127.0.0.1"))

    async def _json():
        return {"action": "publish", "path": path, "ip": "198.51.100.7", "user": "", "password": password, "query": ""}
    hook.json = _json
    return await server.http_stream_auth(hook)


async def rotate_key(w, sid):
    """The owner replaces the stream key while the encoder keeps publishing on the old path."""
    new = "live_" + "N" * 24
    await w.db.regenerate_stream_key(sid, new)
    server._ingest_invalidate()
    server._stream_access_changed(sid)
    return new


@with_clock
async def test_a_key_replaced_while_live_does_not_lose_the_ingest_numbers(w, clock):
    sid, old = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, old)).status == 200
        new = await rotate_key(w, sid)
        assert new != old and await w.db.get_stream_by_key(old) is None
        a = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=old)
        b = paths_for("paths_list_two_samples_5s_apart_b.json", livekey_a=old)
        await tick(clock, a)
        await tick(clock, b)
        for i in range(20):                                         # 100 s of growing readings: past the no-data limit
            await tick(clock, _counted(b, 10_000_000 + i * 500_000), dt=5.0)
        st, d, _resp = await health(w, "owner", sid)
        assert st == 200 and d["ingest"]["available"], d["ingest"]
        assert d["ingest"]["bitrate_bps"] is not None
        assert "no_data" not in [x["code"] for x in d["warnings"]], d["warnings"]
        await asyncio.sleep(0.05)


@with_mtx()
async def test_end_now_after_a_key_replacement_kicks_the_path_the_session_publishes_on(w, mtx):
    sid, old = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, old)).status == 200
        new = await rotate_key(w, sid)
        st, body = await end_now(w, sid, {"regenerate_key": False})
        assert st == 200 and body["publisher_disconnected"] is True, body
        asked = [p for m, p in mtx.calls if m == "GET"]
        assert asked == [f"/v3/paths/get/live/{old}"], asked
        assert new not in "".join(p for _m, p in mtx.calls)


@with_world
async def test_a_new_publish_sets_the_path_and_the_end_clears_it(w):
    sid, key = w.streams["public"]["id"], w.streams["public"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        assert server._session_path(sid) == "live/" + key, server._session_path(sid)
        await server._stream_end_session(await w.db.get_user_stream(sid))
        assert server._session_path(sid) is None                  # no path for an ended session
        await w.db.set_stream_live(sid, True)


@with_clock
async def test_a_browser_publish_gets_ingest_readings_on_its_own_path(w, clock):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook_on(w, key)).status == 200          # WHIP: MediaMTX's path is <key>, no live/
        assert server._session_path(sid) == key
        a = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)
        b = paths_for("paths_list_two_samples_5s_apart_b.json", livekey_a=key)
        for data in (a, b):
            for it in data["items"]:
                if it["name"] == "live/" + key:
                    it["name"] = key
        await tick(clock, a)
        await tick(clock, b)
        for i in range(20):
            await tick(clock, _counted(b, 10_000_000 + i * 500_000), dt=5.0)
        st, d, _resp = await health(w, "owner", sid)
        assert st == 200 and d["ingest"]["available"], d["ingest"]
        assert d["ingest"]["bitrate_bps"] is not None, d["ingest"]
        await asyncio.sleep(0.05)


@with_mtx("webRTCSession")
async def test_end_now_disconnects_a_browser_publish_on_its_own_path(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook_on(w, key)).status == 200
        st, body = await end_now(w, sid, {"regenerate_key": False})
        assert st == 200 and body["publisher_disconnected"] is True, body
        assert [p for m, p in mtx.calls if m == "GET"] == [f"/v3/paths/get/{key}"], mtx.calls
        assert ("POST", "/v3/webrtcsessions/kick/" + mtx.sid) in mtx.calls, mtx.calls


async def owner_notice(w, sid):
    notes = [n for n in await w.db.get_notifications(w.users["owner"], limit=50) if n["type"] == "stream_ended"]
    assert len(notes) == 1, notes
    return notes[0]["message"]


BASE = "An administrator ended your stream."
KEY_SENTENCE = " The stream key was replaced: the encoder needs the new key from the stream settings."
STILL_SENDING = " The encoder could not be disconnected and may still be sending."


@with_mtx()
async def test_the_owner_is_told_about_a_replaced_key_only_when_it_was_replaced(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        assert (await end_now(w, sid, {"regenerate_key": False}))[0] == 200
        assert await owner_notice(w, sid) == BASE


@with_mtx()
async def test_the_owner_is_told_the_key_was_replaced(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        st, body = await end_now(w, sid, {})
        assert st == 200 and body["key_replaced"] is True and body["publisher_disconnected"] is True
        assert await owner_notice(w, sid) == BASE + KEY_SENTENCE


@with_mtx("srtConn")
async def test_the_owner_is_told_when_the_encoder_could_not_be_disconnected(w, mtx):
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    async with Spy(w):
        assert (await publish_hook(w, key)).status == 200
        st, body = await end_now(w, sid, {})
        assert st == 200 and body["publisher_disconnected"] is False, body
        assert await owner_notice(w, sid) == BASE + KEY_SENTENCE + STILL_SENDING
        for forbidden in (key, "SRT", "admin_", "198.51"):
            assert forbidden not in await owner_notice(w, sid)


@with_mtx("srtConn")
async def test_the_still_sending_sentence_stays_off_when_the_key_is_kept_and_nothing_is_connected(w, mtx):
    sid = w.streams["private"]["id"]
    mtx.has_path = False                                # MediaMTX has no publisher on the path
    async with Spy(w):
        await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        st, body = await end_now(w, sid, {"regenerate_key": False})
        assert st == 200 and body["disconnect_note"] == "no publisher is connected", body
        assert await owner_notice(w, sid) == BASE


@with_world
async def test_the_hook_path_is_remembered_only_when_it_ends_in_the_accepted_key(w):
    sid, key = w.streams["public"]["id"], w.streams["public"]["live"]
    async with Spy(w):
        # OBS with the key as the password and some other path: the path is not the key's, so it is not trusted
        assert (await publish_hook_on(w, "live/someone_elses_path", password=key)).status == 200
        assert server._session_path(sid) == "live/" + key, server._session_path(sid)
        await server._stream_end_session(await w.db.get_user_stream(sid))
        assert (await publish_hook_on(w, "live/../../x/" + key)).status == 200
        assert server._session_path(sid) == "live/" + key, server._session_path(sid)


@with_mtx()
async def test_the_live_list_poll_cannot_use_up_the_budget_of_the_actions(w, mtx):
    sid = w.streams["private"]["id"]
    # the real limits: open tabs poll the list far more than 30 times a minute in all
    server._live_ops_rate = server._viewers_mod.RateWindow(server._LIVE_OPS_LIMIT, 60.0)
    list_limit = getattr(server, "_LIVE_OPS_LIST_LIMIT", server._LIVE_OPS_LIMIT)
    server._live_ops_list_rate = server._viewers_mod.RateWindow(list_limit, 60.0)
    statuses = []
    for _ in range(60):                           # five tabs for a minute
        r = await server.http_admin_live_streams(req(w, "admin", 0, path="", route="admin/live-streams"))
        statuses.append(r.status)
    assert statuses == [200] * 60, set(statuses)
    r = await server.http_admin_stream_end(admin_req(w, "admin", sid, "end", {"regenerate_key": False}))
    assert r.status == 200, "a confirmed End now was refused after list polling"
    # each has its own limit and its own name for the administrator's lookup
    for _ in range(list_limit):
        await server.http_admin_live_streams(req(w, "admin", 0, path="", route="admin/live-streams"))
    over = await server.http_admin_live_streams(req(w, "admin", 0, path="", route="admin/live-streams"))
    assert over.status == 429 and over.headers.get("Retry-After") == "10"
    assert (await server.http_admin_stream_stop_relays(admin_req(w, "admin", w.streams["public"]["id"], "stop-relays", {}))).status == 200
    src = Path(server.__file__).read_text()
    assert '"live_ops_list"' in src and "status=429" not in src[src.index("async def _live_ops_gate"):src.index("async def http_admin_live_streams")]


@with_mtx()
async def test_relays_an_administrator_stopped_are_not_reported_as_failing(w, mtx):
    sid = w.streams["private"]["id"]
    rel = await w.db.create_relay_destination(sid, "custom", "Twitch", "rtmp://203.0.113.5/app", "KEYKEYKEY")
    await w.db.update_relay_last_error(rel["id"], "Exit code -15: rtmp://203.0.113.5/app/KEYKEYKEY")
    # the relay was running, an administrator stopped it: the process ended with SIGTERM
    st, d, _ = await health(w, "owner", sid)
    assert d["relays"][0]["state"] == "failed" and "relay_failing" in [x["code"] for x in d["warnings"]]      # the unheld case is a failure
    r = await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays", {}))
    assert r.status == 200
    for user in ("owner", "admin"):
        st, d, resp = await health(w, user, sid)
        assert d["relays"][0]["state"] == "stopped_by_admin", d["relays"]
        assert d["relays"][0]["last_error"] is None and d["relays"][0]["last_error_at"] is None
        assert "relay_failing" not in [x["code"] for x in d["warnings"]], d["warnings"]
        assert "-15" not in resp.body.decode() and "203.0.113.5" not in resp.body.decode()
    await server._stream_set_offline(sid)           # the hold ends with the session
    assert sid not in server._relay_stop_held


FIX193 = ROOT / "tests" / "fixtures" / "mediamtx-1.9.3"


def fx193(name):
    return json.loads((FIX193 / name).read_text())


def _paged(total_pages, per_page, target_item, filler_prefix="live/other_"):
    """A fake paged answer of /v3/paths/list: the item to find sits on the last page."""
    pages = []
    for n in range(total_pages):
        items = [{"name": f"{filler_prefix}{n}_{i}", "ready": True, "bytesReceived": 1000, "source": {"type": "rtmpConn"}}
                 for i in range(per_page)]
        pages.append(items)
    pages[-1].append(target_item)
    return pages


async def with_paged_api(w, clock, pages_by_call, fn):
    """Run fn(svc, state) against a TLS fake control API that answers /v3/paths/list by `page` (from 0)."""
    from services import mediamtx as mtx_service
    state = {"pages": pages_by_call, "asked": [], "fail_page": None, "page_count": None}

    async def paths_list(request):
        page = int(request.query.get("page", "0"))
        state["asked"].append(page)
        if state["fail_page"] == page:
            return web.json_response({"error": "boom"}, status=500)
        pages = state["pages"]
        body = {"itemCount": sum(len(x) for x in pages), "pageCount": state["page_count"] or len(pages),
                "items": pages[page] if page < len(pages) else []}
        return web.json_response(body)

    app = web.Application()
    app.router.add_get("/v3/paths/list", paths_list)
    with tempfile.TemporaryDirectory() as tmp:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=_self_signed_cert(tmp))
        await site.start()
        port = runner.addresses[0][1]
        saved = (server.aiohttp.ClientSession, mtx_service.monotonic)
        server.aiohttp.ClientSession = w.saved[1]
        mtx_service.monotonic = clock
        try:
            svc = mtx_service.MediaMTXService({"id": 1, "name": "mediamtx", "config": json.dumps({"api_port": port})})
            mtx_service.set_paths_listener(server._ingest_feed)
            await fn(svc, state)
        finally:
            mtx_service.set_paths_listener(None)
            server.aiohttp.ClientSession, mtx_service.monotonic = saved
            await runner.cleanup()


@with_clock
async def test_streams_beyond_the_first_page_of_paths_get_numbers(w, clock):
    from services import mediamtx as mtx_service
    sid, key = w.streams["private"]["id"], w.streams["private"]["live"]
    item = paths_for("paths_list_two_samples_5s_apart_a.json", livekey_a=key)["items"][0]

    async def body(svc, state):
        clock.t += 30
        state["pages"] = _paged(3, 100, item)                       # 301 paths on three pages
        assert await svc.health_check() is True
        assert state["asked"] == [0, 1, 2], state["asked"]          # the pages the API reported, from 0
        assert sid in server._ingest_stats and server._ingest_stats[sid]["bytes"] == item["bytesReceived"]
        clock.t += 30
        state["asked"].clear()
        state["pages"] = _paged(3, 100, {**item, "bytesReceived": item["bytesReceived"] + 11_250_000, "inboundBytes": item["bytesReceived"] + 11_250_000})
        assert await svc.health_check() is True
        st, d, _ = await health(w, "owner", sid)
        assert d["ingest"]["available"] and abs(d["ingest"]["bitrate_bps"] - 3_000_000) / 3_000_000 < 0.10, d["ingest"]
        # the number of pages read is bounded, whatever the API says
        state["asked"].clear()
        state["page_count"] = 500
        assert await svc.health_check() is True
        assert state["asked"] == list(range(mtx_service.MAX_PATH_PAGES)), state["asked"]
        assert mtx_service.MAX_PATH_PAGES == 10
        # a page that cannot be read: the health result stands (page one answered), nothing half-read is handed over
        state["page_count"], state["fail_page"] = None, 1
        before = (server._ingest_stats[sid]["bytes"], server._ingest_stats[sid]["at"])
        clock.t += 30
        assert await svc.health_check() is True
        assert (server._ingest_stats[sid]["bytes"], server._ingest_stats[sid]["at"]) == before
        # one page, no pageCount (v1.21.3 captures carry none): one call, as before
        state["fail_page"], state["asked"] = None, []
        state["pages"] = [[item]]
        state["page_count"] = None
        await svc.health_check()
        assert state["asked"] == [0]
    await with_paged_api(w, clock, None, body)


def test_the_parser_and_the_kick_handle_the_1_9_3_captures():
    a, b = fx193("paths_list_rtmp_rtsp_a.json"), fx193("paths_list_rtmp_rtsp_b.json")
    parsed = stream_health.parse_paths(a)
    assert set(parsed) == {"live/key_rtmp_a", "live/key_rtsp_b"}
    r, t = parsed["live/key_rtmp_a"], parsed["live/key_rtsp_b"]
    assert r["source_type"] == "rtmpConn" and t["source_type"] == "rtspSession"
    assert r["source_id"] and t["source_id"] and r["codecs"] == ["H264", "MPEG-4 Audio"]
    assert r["bytes"] == 227598 and r["ready"] and r["ready_at"]
    entry = stream_health.new_entry(100.0)
    stream_health.observe(entry, r, 100.0)
    stream_health.observe(entry, stream_health.parse_paths(b)["live/key_rtmp_a"], 105.0)
    bps = entry["samples"][-1][1]
    assert 200_000 < bps < 600_000, bps                      # about 5 s apart, a 300 kbit/s video plus audio test source
    for stype in ("rtmpConn", "rtspSession"):
        assert stream_health.KICK_ROUTES[stype] in fx193("kick_exchanges.json")["source_type_to_kick_route"].values()

    async def body(w):
        fresh()
        info = fx193("paths_get_rtmp.json")
        calls = []

        async def get_path(request):
            calls.append(("GET", request.path))
            return web.json_response(info)

        async def kick(request):
            calls.append(("POST", request.path))
            ok = request.path == "/v3/rtmpconns/kick/" + info["source"]["id"]
            # 1.9.3: 200 with an empty body on success, 404 {"error": ...} otherwise
            return web.Response(status=200) if ok else web.json_response({"error": "connection not found"}, status=404)
        app = web.Application()
        app.router.add_get("/v3/paths/get/{name:.*}", get_path)
        app.router.add_post("/v3/{kind}/kick/{id}", kick)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        saved = (server._mediamtx_api_base, server._get_mediamtx_config, server.aiohttp.ClientSession)

        async def cfg():
            return {"api_port": port}
        server._mediamtx_api_base = lambda c: f"http://127.0.0.1:{port}"
        server._get_mediamtx_config = cfg
        server.aiohttp.ClientSession = w.saved[1]
        try:
            res = await server._mediamtx_kick_publisher("key_rtmp_a")
        finally:
            server._mediamtx_api_base, server._get_mediamtx_config, server.aiohttp.ClientSession = saved
            await runner.cleanup()
        assert res["kicked"] is True and res["source"] == "RTMP", res
        assert calls[-1] == ("POST", "/v3/rtmpconns/kick/" + info["source"]["id"])
    run(body)


@with_mtx()
async def test_a_relay_hold_does_not_outlive_its_session_when_the_encoder_comes_back(w, mtx):
    sid = w.streams["private"]["id"]
    await w.db.create_relay_destination(sid, "custom", "Twitch", "rtmp://203.0.113.5/app", "KEYKEYKEY")
    async with Spy(w):
        await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")
        assert (await server.http_admin_stream_stop_relays(admin_req(w, "admin", sid, "stop-relays", {}))).status == 200
        assert sid in server._relay_stop_held
        server.active_recordings[sid] = {"process": Proc(), "session_dir": "/nonexistent", "uploaded": set()}
        hold = asyncio.Event()

        async def held_stop(stream_id, force=False, only=None):
            await hold.wait()
        saved = (server.stop_vod_recording, server._vod_graceful_stop)

        async def graceful(p):
            return "q"
        server.stop_vod_recording, server._vod_graceful_stop = held_stop, graceful
        try:
            assert (await end_now(w, sid, {"regenerate_key": False}))[0] == 200
            server.active_recordings.pop(sid, None)
            await server._mark_stream_live(await w.db.get_user_stream(sid), "198.51.100.7")   # the encoder is back: a new session
            hold.set()
            await asyncio.gather(*[t for t in asyncio.all_tasks() if "_finalize_stream_offline" in repr(t.get_coro())])
        finally:
            server.stop_vod_recording, server._vod_graceful_stop = saved
        assert (await w.db.get_user_stream(sid))["is_live"] == 1
        assert sid not in server._relay_stop_held, "the hold of the ended session carried over into the new one"
        st, d, _ = await health(w, "owner", sid)
        assert "stopped_by_admin" not in [r["state"] for r in d["relays"]], d["relays"]


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception:
                import traceback
                traceback.print_exc()
                print("FAIL", name)
                failed += 1
    sys.exit(1 if failed else 0)
