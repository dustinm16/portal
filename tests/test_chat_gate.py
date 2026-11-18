"""A chat edit passes the same gate as a send, and automod never penalises
a member who is already timed out or muted.

Run: venv/bin/python tests/test_chat_gate.py

Uses a temporary database. The chat websocket handler itself is covered by the
staged smoke run (tools/smoke_checks/check_automod.py); here the shared helper
and the order of the calls in the handler are checked.
"""

import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import server  # noqa: E402
from database import Database  # noqa: E402


class FakeWs:
    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)


def with_db(body):
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = server.db
            server.db = d
            try:
                await body(d)
            finally:
                server.db = saved
                await d.close()
    asyncio.run(go())


async def setup(d, slowmode=0):
    owner = await d.create_user("owner1", "x")
    member = await d.create_user("member1", "x")
    cid = await d.create_chat_channel("room1", created_by=owner)
    if slowmode:
        await d.update_chat_channel(cid, slowmode_seconds=slowmode)
    return owner, member, await d.get_chat_channel_by_name("room1")


def gate(ws, channel, user_id, role="user", times=None, limit=5):
    return server._chat_member_blocked(ws, channel, user_id=user_id, user_role=role,
                                       msg_times=[] if times is None else times,
                                       rate_limit=limit, rate_window=5.0)


def test_clean_member_passes_and_counts_against_the_rate_limit():
    async def body(d):
        owner, member, ch = await setup(d)
        ws, times = FakeWs(), []
        assert await gate(ws, ch, member, times=times) is False
        assert ws.sent == [] and len(times) == 1
    with_db(body)


def test_timed_out_and_muted_members_get_the_send_path_errors():
    async def body(d):
        owner, member, ch = await setup(d)
        await d.create_chat_timeout(member, owner, "timeout", ch["id"], "r", 60)
        ws, times = FakeWs(), []
        assert await gate(ws, ch, member, times=times) is True
        assert ws.sent[0]["error_code"] == "timeout" and "expires_at" in ws.sent[0]
        assert times == [], "a refused member does not use up the rate limit"
        await d.create_chat_timeout(member, owner, "mute", ch["id"], "r")
        ws = FakeWs()
        assert await gate(ws, ch, member) is True
        assert ws.sent == [{"type": "error", "error_code": "muted", "message": "You are muted in this channel"}]
    with_db(body)


def test_stream_ban_is_refused():
    async def body(d):
        owner, member, ch = await setup(d)
        sid = await d.create_user_stream(owner, "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (ch["id"], sid))
        await d.conn.commit()
        assert await d.create_stream_ban(sid, member, owner, "r")
        ws = FakeWs()
        assert await gate(ws, ch, member) is True
        assert ws.sent == [{"type": "error", "message": "You are banned from this stream's chat"}]
    with_db(body)


def test_rate_limit_and_slow_mode():
    async def body(d):
        owner, member, ch = await setup(d, slowmode=30)
        ws, times = FakeWs(), []
        for _ in range(5):
            assert await gate(ws, ch, member, role="moderator", times=times) is False
        assert await gate(ws, ch, member, role="moderator", times=times) is True
        assert ws.sent[-1]["message"].startswith("Slow down!")
        # slow mode: a member who sent a moment ago waits, staff do not
        server._slowmode_last_msg[(ch["id"], member)] = server.monotonic()
        ws = FakeWs()
        assert await gate(ws, ch, member) is True
        assert ws.sent[0]["error_code"] == "slowmode" and ws.sent[0]["cooldown_remaining"] >= 1
        assert await gate(FakeWs(), ch, member, role="admin") is False
        server._slowmode_last_msg.clear()
    with_db(body)


def test_automod_books_no_second_penalty_for_a_member_already_timed_out():
    async def body(d):
        owner, member, ch = await setup(d)
        await d.create_automod_rule("word_filter", "bad", {"words": ["badword"], "match_mode": "contains"},
                                    "timeout", owner, action_duration=60)
        server._automod_cache_time = 0
        await d.create_chat_timeout(member, owner, "timeout", ch["id"], "earlier", 600)
        before = await d.conn.execute("SELECT id FROM chat_timeouts WHERE user_id = ?", (member,))
        before = [r["id"] for r in await before.fetchall()]
        broadcasts = []

        async def fake_broadcast(*a, **k):
            broadcasts.append(a)

        saved = server.broadcast_to_channel
        server.broadcast_to_channel = fake_broadcast
        try:
            ws = FakeWs()
            blocked = await server.apply_automod(ws, "a badword", user_id=member, user_role="user", channel=ch,
                                                 channel_name="room1", username="member1", my_state={})
            assert blocked is True and ws.sent and ws.sent[0]["error_code"] == "automod"
            ws = FakeWs()
            edit_of = {"id": 1, "message": "old"}
            assert await server.apply_automod(ws, "a badword", user_id=member, user_role="user", channel=ch,
                                              channel_name="room1", username="member1", my_state={},
                                              edit_of=edit_of) is True
            assert [m["type"] for m in ws.sent] == ["error", "edit_rejected"]
        finally:
            server.broadcast_to_channel = saved
        after = await d.conn.execute("SELECT id FROM chat_timeouts WHERE user_id = ?", (member,))
        assert [r["id"] for r in await after.fetchall()] == before, "a new timeout row was booked"
        assert broadcasts == [], "the channel was told again"
        # a member who is not yet timed out still gets the penalty
        other = await d.create_user("other1", "x")
        saved = server.broadcast_to_channel
        server.broadcast_to_channel = fake_broadcast
        try:
            await server.apply_automod(FakeWs(), "a badword", user_id=other, user_role="user", channel=ch,
                                       channel_name="room1", username="other1", my_state={})
        finally:
            server.broadcast_to_channel = saved
        assert await d.is_user_timed_out(other, ch["id"]) and len(broadcasts) == 1
    with_db(body)


def _handler_section(src, start, end):
    return src[src.index(start):src.index(end, src.index(start))]


def test_edit_and_send_run_the_gate_before_automod():
    src = (ROOT / "server.py").read_text()
    edit = _handler_section(src, 'elif msg_type == "edit_message":', 'elif msg_type == "pin_message":')
    assert "_chat_member_blocked(" in edit
    assert edit.index("_chat_member_blocked(") < edit.index("apply_automod(") < edit.index("db.edit_chat_message(")
    # the ownership and window refusals stay first: a refused edit costs no rate-limit slot
    assert edit.index("chat_message_editable(") < edit.index("_chat_member_blocked(")
    # a gate refusal gives the author the stored text back (the client shows edits optimistically)
    refusal = edit[edit.index("_chat_member_blocked("):edit.index("apply_automod(")]
    assert '"type": "edit_rejected"' in refusal and 'edit_msg["message"]' in refusal and "continue" in refusal
    send_at = src.index('elif msg_type == "message":')
    send = src[send_at:src.index("elif msg_type ==", send_at + 10)]
    assert send.index("_chat_member_blocked(") < send.index("apply_automod(") < send.index("db.create_chat_message(")


def test_dm_edit_has_the_checks_a_dm_send_has():
    src = (ROOT / "server.py").read_text()
    edit = _handler_section(src, 'elif msg_type == "dm_edit":', 'elif msg_type == "dm_mark_read":')
    assert "_dm_participant_blocked(" in edit and "chat_msg_times" in edit
    assert edit.index("_dm_participant_blocked(") < edit.index("chat_msg_times") < edit.index("db.edit_dm_message(")
    send = _handler_section(src, 'elif msg_type == "dm_message":', 'elif msg_type == "dm_edit":')
    assert "_dm_participant_blocked(" in send


def test_dm_blocked_helper():
    async def body(d):
        a = await d.create_user("dma", "x")
        b = await d.create_user("dmb", "x")
        saved = server.db
        calls = {}

        class Fake:
            async def get_dm_participant_ids(self, conv):
                return [a, b]

            async def is_blocked_bidirectional(self, x, y):
                return calls.get("blocked", False)
        server.db = Fake()
        try:
            assert await server._dm_participant_blocked(a, 1) is False
            calls["blocked"] = True
            assert await server._dm_participant_blocked(a, 1) is True
        finally:
            server.db = saved
    with_db(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                traceback.print_exc()
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
