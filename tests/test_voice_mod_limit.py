"""Voice moderation frames are limited per socket.

A member who is in a voice room and sends voice_kick over and over gets the first frames
answered with the ordinary refusal; once the limit (20 frames per 10 s on one socket) is used
up, later frames are answered with a rate error and cost no database read. A moderator's
normal use (a few locks, mutes and kicks) is never refused.

Run: venv/bin/python tests/test_voice_mod_limit.py
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_voicemod as vm  # noqa: E402
import server  # noqa: E402


def run(body):
    async def go():
        async with vm.Env() as env:
            await body(env)
    asyncio.run(asyncio.wait_for(go(), 90))


def test_a_member_flooding_voice_kick_is_refused_without_database_reads():
    async def body(env):
        await env.voice("admin")
        bob = await env.voice("bob")
        carol = await env.voice("carol")
        calls = [0]
        real = server.db.get_chat_channel_by_name

        async def counted(*a, **k):
            calls[0] += 1
            return await real(*a, **k)
        server.db.get_chat_channel_by_name = counted
        try:
            mark = carol.mark()
            for _ in range(25):
                await carol.send(type="voice_kick", target_user_id=env.u["bob"])
            await carol.settle(0.8)
            errors = [e for e in carol.since(mark) if e.get("type") == "error"]
            assert len(errors) == 25, len(errors)
            limited = [e for e in errors if "rate" in e["message"].lower()]
            assert len(limited) == 5, (len(limited), [e["message"] for e in errors])
            assert calls[0] == 20, f"{calls[0]} channel reads for 25 frames"
        finally:
            server.db.get_chat_channel_by_name = real
        assert env.u["bob"] in server.voice_state["general"]
    run(body)


def test_a_moderators_normal_use_is_not_limited():
    async def body(env):
        adm = await env.voice("admin")
        await env.voice("bob")
        mark = adm.mark()
        for _ in range(4):
            await adm.send(type="voice_lock_room")
            await adm.send(type="voice_unlock_room")
        await adm.send(type="voice_server_mute", target_user_id=env.u["bob"])
        await adm.send(type="voice_server_unmute", target_user_id=env.u["bob"])
        await adm.settle(0.6)
        assert not [e for e in adm.since(mark) if e.get("type") == "error"], adm.since(mark)
        assert len(await env.audit("voice_lock")) == 4
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
