"""An @everyone in a stream chat or a private channel reads bans and members once.

_mass_mention_recipients used to ask the database once per candidate whether that member is
banned from the stream or belongs to the private channel. The ban list and the member list are now
read once and handed to the read gate. The recipients are the same as before, and the number of
reads does not grow with the number of candidates.

Run: venv/bin/python tests/test_mass_mention_queries.py
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402
outbound_guard.install()
import test_chat_access_loss as base  # noqa: E402
import test_notify_levels as nl  # noqa: E402
import server  # noqa: E402


def run(body):
    async def go():
        async with nl.Env() as env:
            await body(env)
    asyncio.run(asyncio.wait_for(go(), 60))


class Counter:
    def __init__(self, db, names):
        self.db, self.names, self.n, self.real = db, names, {n: 0 for n in names}, {}

    def __enter__(self):
        for name in self.names:
            real = getattr(self.db, name)
            self.real[name] = real

            def make(name, real):
                async def counted(*a, **k):
                    self.n[name] += 1
                    return await real(*a, **k)
                return counted
            setattr(self.db, name, make(name, real))
        return self

    def __exit__(self, *exc):
        for name, real in self.real.items():
            setattr(self.db, name, real)


READS = ("is_user_banned_from_stream", "is_channel_member", "get_banned_user_ids", "get_channel_member_ids")


def test_stream_chat_everyone_skips_banned_members_with_constant_reads():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        extra = [await d.create_user(f"extra{i}", "x") for i in range(12)]
        cid, sid = await base.stream_chat(d, ids, public=True)
        channel = await d.get_chat_channel(cid)
        stream = await d.get_stream_by_chat_channel(cid)
        await d.create_stream_ban(sid, ids["bob"], ids["owner"])
        await d.create_stream_ban(sid, extra[3], ids["owner"])
        with Counter(d, READS) as c:
            out, capped = await server._mass_mention_recipients(channel, "everyone", ids["carol"], stream)
        assert not capped
        assert ids["bob"] not in out and extra[3] not in out, out
        assert ids["alice"] in out and ids["owner"] in out and extra[0] in out, out
        assert ids["carol"] not in out
        assert c.n["is_user_banned_from_stream"] == 0, c.n
        assert c.n["get_banned_user_ids"] == 1, c.n
        # the same call with more candidates reads no more
        more = [await d.create_user(f"more{i}", "x") for i in range(20)]
        with Counter(d, READS) as c2:
            out2, _ = await server._mass_mention_recipients(channel, "everyone", ids["carol"], stream)
        assert c2.n == c.n, (c.n, c2.n)
        assert set(more) <= set(out2)
    run(body)


def test_private_channel_everyone_reaches_members_only_with_constant_reads():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await base.private_channel(d, ids, members=("alice", "bob", "carol"))
        channel = await d.get_chat_channel(cid)
        with Counter(d, READS) as c:
            out, _ = await server._mass_mention_recipients(channel, "everyone", ids["carol"], None)
        assert sorted(out) == sorted([ids["alice"], ids["bob"]]), out
        assert c.n["is_channel_member"] == 0, c.n
        assert c.n["get_channel_member_ids"] <= 1, c.n
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
