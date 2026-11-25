"""A legacy stream update that fails leaves no orphan chat channel.

A stream from before chat channels had none. The first settings update creates a
stream-<user>-<id> channel and binds it with the same update. When that update does not
go through (it answers false or raises), the channel made in this request is deleted again.
A channel the stream already had is never deleted.

Run: venv/bin/python tests/test_stream_update_orphan.py
"""

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402
outbound_guard.install()
import server  # noqa: E402
import test_chat_access_loss as base  # noqa: E402


def run(body):
    async def go():
        async with base.Env() as env:
            await body(env)
    asyncio.run(asyncio.wait_for(go(), 60))


async def legacy_stream(d, ids):
    sid = await d.create_user_stream(ids["owner"], "old", "live_" + "a" * 24, public_key="pub_" + "b" * 24,
                                     is_public=True)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = NULL WHERE id = ?", (sid,))
    await d.conn.commit()
    return sid


async def stream_channels(d):
    return [c["name"] for c in await d.get_chat_channels() if c["name"].startswith("stream-")]


def failing(kind):
    async def update(*a, **k):
        if kind == "raise":
            raise OSError("disk full")
        return False
    return update


def test_a_failed_update_of_a_legacy_stream_removes_the_channel_it_made():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        sid = await legacy_stream(d, ids)
        real = d.update_user_stream
        for kind in ("false", "raise"):
            d.update_user_stream = failing(kind)
            try:
                try:
                    st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "new"})
                except Exception:
                    st = 500
            finally:
                d.update_user_stream = real
            assert st == 500, (kind, st)
            assert await stream_channels(d) == [], (kind, await stream_channels(d))
            assert not (await d.get_user_stream(sid)).get("chat_channel_id")
        # the same update without a fault creates and binds the channel
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "new"})
        assert st == 200, b
        assert len(await stream_channels(d)) == 1
        assert (await d.get_user_stream(sid))["chat_channel_id"]
    run(body)


def test_a_failed_update_never_deletes_a_channel_the_stream_already_had():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid, sid = await base.stream_chat(d, ids, public=True)
        real = d.update_user_stream
        d.update_user_stream = failing("false")
        try:
            st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "new"})
        finally:
            d.update_user_stream = real
        assert st == 500, (st, b)
        assert await d.get_chat_channel(cid) is not None
        assert (await d.get_user_stream(sid))["chat_channel_id"] == cid
    run(body)


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except BaseException as e:
                bad += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if bad else 0)
