"""Lifting a ban made from an anonymous post over HTTP (DELETE /api/streams/{id}/bans/id/{ban_id}) answers the same for a
stream mod whoever the hidden member is (1.24.1). A ban on a named member keeps the rank rules.

The real app on a loopback test server with a temporary database (tests/grant_harness.py).
Run: venv/bin/python tests/test_anonymous_unban_http.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402


async def main():
    env = await h.boot(names=("owner", "mod1", "member", "adm"), superadmin=("adm",))
    db, u = env.db, env.uid
    cid = await db.create_chat_channel("c241", created_by=u["owner"])
    sid = await db.create_user_stream(u["owner"], "s", "live_" + "a" * 24, public_key="pub_" + "b" * 24, is_public=1)
    await db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
    await db.conn.commit()
    assert await db.add_channel_moderator_capped(cid, u["mod1"], u["owner"], 20)
    mod = env.sessions["mod1"]
    answers = {}
    for who in ("member", "owner", "adm"):
        mid = await db.create_chat_message(cid, u[who], who, f"anon {who}", anonymous=True)
        ban = await db.create_stream_ban(sid, u[who], u["owner"], "r", anonymous=True, message_id=mid)
        async with mod.delete(f"{env.base}/api/streams/{sid}/bans/id/{ban}") as r:
            answers[who] = (r.status, await r.text())
        check(f"the ban made from {who}'s anonymous post is lifted", await db.get_stream_ban(sid, ban) is None, str(answers[who]))
    check("one answer for every hidden member", len(set(answers.values())) == 1, str(answers))
    # a ban on a named member keeps the rank rules: a stream mod may not lift the owner's named ban of an admin
    ban = await db.create_stream_ban(sid, u["adm"], u["owner"], "r")
    async with mod.delete(f"{env.base}/api/streams/{sid}/bans/id/{ban}") as r:
        check("a named ban of a higher rank is still refused to a stream mod", r.status == 400, str(r.status))
    await h.shutdown(env)
    h.finish("test_anonymous_unban_http")


async def guarded():
    try:
        await asyncio.wait_for(main(), 100)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        import os
        os._exit(1)


asyncio.run(guarded())
