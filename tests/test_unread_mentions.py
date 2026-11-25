"""The channel list carries unread_mentions: the caller's own unread mention notifications per
channel they may read, counted only for messages after their read position.

Runs the real HTTP handler in-process against a temporary database (only the authentication lookup
is replaced). The page side (seeding the badge from it after a reload) is in
tests/test_unread_mentions_client.py.

Run: venv/bin/python tests/test_unread_mentions.py
"""

import asyncio
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402

outbound_guard.install()

import test_chat_access_loss as base  # noqa: E402


def _deadline(seconds=90):
    def boom():
        print("FAIL deadline: the test did not finish in %d s" % seconds, flush=True)
        import os
        os._exit(2)
    t = threading.Timer(seconds, boom)
    t.daemon = True
    t.start()
    return t


async def mention(d, user_id, channel_id, message_id, read=0, **extra):
    nid = await d.create_notification(user_id, "mention", "someone mentioned you", "",
                                      {"channel": "x", "channel_id": channel_id, "message_id": message_id, **extra})
    if read:
        await d.mark_notification_read(nid, user_id)
    return nid


async def listing(env, user_id):
    st, body = await env.call("GET", user_id, "/api/chat/channels")
    assert st == 200, (st, body)
    return {c["id"]: c for c in body["channels"]}


def test_the_channel_list_counts_unread_mentions_the_caller_may_read():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = next(c["id"] for c in await d.get_chat_channels() if c["name"] == "general")
        lobby = await d.create_chat_channel("lobby", created_by=ids["boss"])
        quiet = await d.create_chat_channel("quiet", created_by=ids["boss"])
        pvt = await base.private_channel(d, ids, members=("alice", "bob"))
        hidden, _ = await base.stream_chat(d, ids, public=False)
        bob = ids["bob"]
        await mention(d, bob, lobby, 10)
        await mention(d, bob, lobby, 11, mass="everyone")          # a mass mention row counts like any other
        await mention(d, bob, lobby, 12, read=1)                   # read in the bell: not counted
        await mention(d, bob, gen, 5)
        await mention(d, bob, pvt, 7)
        await mention(d, bob, hidden, 3)                           # a chat bob may not see
        await mention(d, ids["carol"], lobby, 13)                  # someone else's row
        await mention(d, ids["carol"], quiet, 14)
        await d.create_notification(bob, "dm", "a dm", "", {"channel_id": lobby, "message_id": 20})  # not a mention
        got = await listing(env, bob)
        assert got[lobby]["unread_mentions"] == 2, got[lobby]
        assert got[gen]["unread_mentions"] == 1
        assert got[pvt]["unread_mentions"] == 1
        assert got[quiet]["unread_mentions"] == 0
        assert hidden not in got, "a hidden stream chat is not listed, so it has no count either"
        assert all(isinstance(c["unread_mentions"], int) for c in got.values())
        # every existing field is still there
        for field in ("unread_count", "notify_level", "muted_until", "is_stream_channel", "name", "id"):
            assert field in got[lobby], field
        carol = await listing(env, ids["carol"])
        assert carol[lobby]["unread_mentions"] == 1 and carol[quiet]["unread_mentions"] == 1
        assert pvt not in carol
        # access lost: the private channel's row no longer shows anywhere for bob
        await d.remove_channel_member(pvt, bob)
        got = await listing(env, bob)
        assert pvt not in got
    base.run(body)


def test_a_mention_the_member_has_read_in_the_room_is_not_counted():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await d.create_chat_channel("lobby", created_by=ids["boss"])
        bob = ids["bob"]
        await mention(d, bob, lobby, 10)
        await mention(d, bob, lobby, 20)
        assert (await listing(env, bob))[lobby]["unread_mentions"] == 2
        await d.update_read_position(bob, lobby, 10)
        assert (await listing(env, bob))[lobby]["unread_mentions"] == 1
        await d.update_read_position(bob, lobby, 25)
        assert (await listing(env, bob))[lobby]["unread_mentions"] == 0
        # the bell is untouched: both rows are still unread there
        assert await d.get_unread_notification_count(bob) == 2
    base.run(body)


def test_an_odd_row_does_not_break_the_list():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await d.create_chat_channel("lobby", created_by=ids["boss"])
        bob = ids["bob"]
        await d.conn.execute("INSERT INTO notifications (user_id, type, title, message, data) VALUES (?, 'mention', 't', '', 'not json')", (bob,))
        await d.conn.execute("INSERT INTO notifications (user_id, type, title, message, data) VALUES (?, 'mention', 't', '', '{}')", (bob,))
        await d.conn.commit()
        await mention(d, bob, lobby, 4)
        assert (await listing(env, bob))[lobby]["unread_mentions"] == 1
    base.run(body)


if __name__ == "__main__":
    timer = _deadline()
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    timer.cancel()
    sys.exit(1 if failed else 0)
