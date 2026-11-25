"""Ids that SQLite cannot hold, and a body that is not an object, do not break the chat.

* react and edit_message frames of a channel, and dm_delete, dm_react, dm_edit, dm_mark_read, dm_message,
  dm_typing and dm_history frames, with an id of 10**30 answer an error frame (or are ignored)
  and the socket stays open and usable afterwards
* POST /api/chat/channels/{id}/members with user_id 10**30 answers 400, a body that is not a JSON
  object answers 400

Run: venv/bin/python tests/test_chat_ids_bounded.py
"""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402
outbound_guard.install()
import test_chat_access_loss as base  # noqa: E402
import test_notify_levels as nl  # noqa: E402

HUGE = 10 ** 30


def run(body):
    async def go():
        async with nl.Env() as env:
            await body(env)
    asyncio.run(asyncio.wait_for(go(), 60))


async def post_raw(env, user_id, path, raw):
    async with env.http.post(env.url(path), data=raw, headers={
            "X-Test-User": str(user_id), "Content-Type": "application/json"}) as r:
        return r.status, await r.text()


async def alive(sock, conv_id, frame=None):
    """The socket still answers: a DM history request is served."""
    mark = sock.mark()
    await sock.send(type="dm_history", conversation_id=conv_id)
    got = await sock.wait(lambda e: e.get("type") == "dm_history", mark)
    assert got, f"the socket no longer answers after {frame}"


def test_huge_ids_in_chat_and_dm_frames_leave_the_socket_open():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await nl.pub_channel(d, ids)
        conv = await d.create_dm_conversation(ids["alice"], [ids["bob"]])
        s = await env.sock(ids["alice"])
        await s.join(lobby)
        frames = [
            dict(type="react", message_id=HUGE, emoji="x"),
            dict(type="edit_message", message_id=HUGE, message="new text"),
            dict(type="dm_delete", conversation_id=conv["id"], message_id=HUGE),
            dict(type="dm_react", conversation_id=conv["id"], message_id=HUGE, emoji="x"),
            dict(type="dm_edit", conversation_id=conv["id"], message_id=HUGE, message="new text"),
            dict(type="dm_mark_read", conversation_id=conv["id"], message_id=HUGE),
            dict(type="dm_delete", conversation_id=HUGE, message_id=1),
            dict(type="dm_message", conversation_id=HUGE, message="hi"),
            dict(type="dm_typing", conversation_id=HUGE),
            dict(type="dm_history", conversation_id=conv["id"], before_id=HUGE),
            dict(type="dm_history", conversation_id=HUGE),
        ]
        for f in frames:
            await s.send(**f)
            await alive(s, conv['id'], f)
            assert not s.ws.closed, f"socket closed after {f}"
        await asyncio.sleep(0.2)
        assert not s.ws.closed
    run(body)


def test_member_route_rejects_a_huge_id_and_a_non_object_body():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await nl.pub_channel(d, ids)
        path = f"/api/chat/channels/{cid}/members"
        for payload in ({"user_id": HUGE}, {"user_id": "abc"}, {"user_id": 1e400}):
            st, js = await post_raw(env, ids["boss"], path, json.dumps(payload))
            assert st == 400, (payload, st, js)
        for raw in ("[1, 2]", "5", "null", '"text"'):
            st, js = await post_raw(env, ids["boss"], path, raw)
            assert st == 400, (raw, st, js)
        st, js = await env.call("POST", ids["boss"], path, json={"user_id": ids["bob"]})
        assert st == 201, (st, js)
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
