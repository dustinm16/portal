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
from test_stream_access import run  # noqa: E402
from test_stream_health_server import (  # noqa: E402
    admin_req, fresh, req, with_mtx,
)


class Proc:
    name = "rec"
    returncode = None


def with_world(fn):
    def runner():
        async def body(w):
            fresh()
            server._end_claims.clear() if hasattr(server, "_end_claims") else None
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
