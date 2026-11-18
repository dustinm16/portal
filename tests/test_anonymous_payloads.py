"""Anonymous chat identity checks: the helpers that decide who receives the
real account id of an anonymous participant.

Policy: ordinary members never get the id or role; the participant themself,
staff (moderator, admin, superadmin) do. The owner of a stream is an ordinary
member in that stream's chat.

Run: venv/bin/python tests/test_anonymous_payloads.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402

AUTHOR = 7


class FakeWs:
    def __init__(self):
        self.closed = False
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)


def message(**kw):
    m = {"id": 1, "user_id": AUTHOR, "username": "Anonymous", "role": "user",
         "nickname": "Nick", "anonymous": True, "author_nickname": "Nick", "author_role": "user"}
    m.update(kw)
    return m


def test_mask_member_loses_id_role_nickname():
    m = message()
    server._mask_anonymous_author(m, 9, "user")
    assert m["user_id"] is None and m["role"] is None and m["nickname"] is None, m
    assert "author_nickname" not in m and "author_role" not in m, m


def test_mask_staff_and_author_keep_id_but_not_nickname():
    for viewer, role in ((9, "moderator"), (9, "admin"), (9, "superadmin"), (AUTHOR, "user")):
        m = message()
        server._mask_anonymous_author(m, viewer, role)
        assert m["user_id"] == AUTHOR and m["role"] == "user", (viewer, role, m)
        assert m["nickname"] is None and "author_nickname" not in m, m


def test_helpers_take_no_stream_owner_argument():
    import inspect
    assert not hasattr(server, "chat_room_owner")
    assert list(inspect.signature(server._viewer_sees_identity).parameters) == [
        "viewer_id", "viewer_role", "subject_id"]
    assert list(inspect.signature(server._mask_anonymous_author).parameters) == [
        "m", "viewer_id", "viewer_role"]


def test_mask_ignores_normal_messages():
    m = message(anonymous=False, username="alice")
    server._mask_anonymous_author(m, 9, "user")
    assert m["user_id"] == AUTHOR and m["nickname"] == "Nick", m


def test_mask_hides_poll_creator():
    m = message(poll={"id": 3, "user_id": AUTHOR})
    server._mask_anonymous_author(m, 9, "user")
    assert m["poll"]["user_id"] is None, m


def test_broadcast_per_recipient():
    async def run():
        member, staff, author, other_staff = FakeWs(), FakeWs(), FakeWs(), FakeWs()
        server.chat_rooms["t"] = {
            (member, 1, "m", "user"), (staff, 2, "s", "moderator"),
            (author, AUTHOR, "a", "user"), (other_staff, 3, "x", "admin"),
        }
        try:
            payload = {"type": "message", "user_id": AUTHOR, "role": "user", "username": "Anonymous"}
            await server.broadcast_to_channel("t", payload, anon_subject=AUTHOR)
            assert member.sent[0]["user_id"] is None and member.sent[0]["role"] is None, member.sent
            for w in (staff, author, other_staff):
                assert w.sent[0]["user_id"] == AUTHOR and w.sent[0]["role"] == "user", w.sent
            assert payload["user_id"] == AUTHOR  # the shared payload is not modified
            # Without a subject everyone gets the payload unchanged
            await server.broadcast_to_channel("t", payload)
            assert member.sent[1]["user_id"] == AUTHOR
        finally:
            server.chat_rooms.pop("t", None)
    asyncio.run(run())


def test_stream_owner_is_a_member_for_identity():
    async def run():
        owner, member = FakeWs(), FakeWs()
        server.chat_rooms["t"] = {(owner, 20, "o", "user"), (member, 1, "m", "user")}
        try:
            await server.broadcast_to_channel(
                "t", {"type": "message", "user_id": AUTHOR, "role": "user"}, anon_subject=AUTHOR)
            assert owner.sent[0]["user_id"] is None, owner.sent
            assert member.sent[0]["user_id"] is None, member.sent
            rows = [{"id": AUTHOR, "username": "a", "chat_anonymous": 1, "role": "user"}]
            assert server._chat_users_list(rows, "t", 20, "user")[0]["user_id"] is None
        finally:
            server.chat_rooms.pop("t", None)
    asyncio.run(run())


def test_anon_ref_differs_per_channel_and_user():
    a1, a2 = server._anon_ref("one", AUTHOR), server._anon_ref("two", AUTHOR)
    assert a1 != a2 and a1 == server._anon_ref("one", AUTHOR)
    assert a1 != server._anon_ref("one", AUTHOR + 1)
    p = server._hide_subject({"type": "user_joined", "user_id": AUTHOR}, AUTHOR, "one")
    assert p["anon_ref"] == a1
    rows = [{"id": AUTHOR, "username": "a", "chat_anonymous": 1, "role": "user"}]
    assert server._chat_users_list(rows, "one", 1, "user")[0]["anon_ref"] == a1
    assert server._chat_users_list(rows, "two", 1, "user")[0]["anon_ref"] == a2


def test_users_list_masked_entries_last_in_id_independent_order():
    rows = []
    for i in range(1, 13):
        rows.append({"id": i, "username": "u%d" % i, "chat_anonymous": 1 if i % 2 else 0, "role": "user"})
    out = server._chat_users_list(rows, "c", 100, "user")
    kinds = [bool(u["anonymous"]) for u in out]
    assert kinds == sorted(kinds), kinds  # open entries first, masked ones last
    assert [u["username"] for u in out if not u["anonymous"]] == ["u2", "u4", "u6", "u8", "u10", "u12"]
    refs = [u["anon_ref"] for u in out if u["anonymous"]]
    assert refs == sorted(refs), refs
    # staff see the ids and need no hiding
    staff = server._chat_users_list(rows, "c", 100, "moderator")
    assert [u["user_id"] for u in staff] == list(range(1, 13))


def test_reactor_ids_hidden_for_members():
    class FakeDb:
        async def get_users_status(self, ids):
            return [{"id": i, "chat_anonymous": 1 if i == AUTHOR else 0} for i in ids]

    def reactions():
        return {1: [{"emoji": "+1", "count": 3, "user_ids": [AUTHOR, 9, 4]},
                    {"emoji": "x", "count": 1, "user_ids": [AUTHOR]}]}

    async def run():
        real = server.db
        server.db = FakeDb()
        try:
            r = reactions()
            await server._mask_reactor_ids(r, 4, "user")
            assert r[1][0]["user_ids"] == [9, 4] and r[1][0]["count"] == 3, r
            assert r[1][1]["user_ids"] == [] and r[1][1]["count"] == 1, r
            r = reactions()  # the author keeps their own id
            await server._mask_reactor_ids(r, AUTHOR, "user")
            assert r == reactions(), r
            r = reactions()  # staff keep every id
            await server._mask_reactor_ids(r, 4, "moderator")
            assert r == reactions(), r
        finally:
            server.db = real
    asyncio.run(run())


def test_reaction_event_hides_reactor():
    async def run():
        member, author = FakeWs(), FakeWs()
        server.chat_rooms["t"] = {(member, 1, "m", "user"), (author, AUTHOR, "a", "user")}
        try:
            await server.broadcast_to_channel(
                "t", {"type": "reaction_update", "message_id": 5, "user_id": AUTHOR}, anon_subject=AUTHOR)
            assert member.sent[0]["user_id"] is None, member.sent
            assert author.sent[0]["user_id"] == AUTHOR, author.sent
        finally:
            server.chat_rooms.pop("t", None)
    asyncio.run(run())


def test_status_event_hides_status_text():
    p = server._hide_subject({"type": "user_status_changed", "user_id": AUTHOR, "status": "busy",
                              "status_message": "back Monday", "last_seen_at": "x"}, AUTHOR)
    assert p["status_message"] is None and p["last_seen_at"] is None and p["user_id"] is None, p
    assert p["status"] == "online", p


def test_presence_event_gets_opaque_handle():
    p = server._hide_subject({"type": "user_joined", "user_id": AUTHOR, "role": "user", "username": "Anonymous"}, AUTHOR)
    assert p["user_id"] is None and p["role"] is None and p["anon_ref"], p
    q = server._hide_subject({"type": "user_joined", "user_id": AUTHOR + 1}, AUTHOR + 1)
    assert q["anon_ref"] != p["anon_ref"]
    assert "anon_ref" not in server._hide_subject({"type": "message", "user_id": AUTHOR}, AUTHOR)


def test_only_presence_events_carry_the_handle():
    for t in ("user_joined", "user_left", "user_status_changed", "user_anonymous_changed"):
        assert server._hide_subject({"type": t, "user_id": AUTHOR}, AUTHOR, "c").get("anon_ref"), t
    for t in ("user_banned", "user_timed_out", "user_muted", "user_unmuted", "message_deleted"):
        p = server._hide_subject({"type": t, "user_id": AUTHOR}, AUTHOR, "c")
        assert "anon_ref" not in p and p["user_id"] is None, (t, p)


def test_users_list_per_viewer():
    rows = [
        {"id": AUTHOR, "username": "alice", "nickname": "Nick", "chat_anonymous": 1, "role": "admin",
         "avatar": json.dumps({"emoji": "x"}), "status": "busy",
         "status_message": "back Monday", "last_seen_at": "2026-01-01 10:00:00"},
        {"id": 8, "username": "bob", "nickname": None, "chat_anonymous": 0, "role": "user", "avatar": None},
    ]
    member = server._chat_users_list(rows, "c", 8, "user")
    anon = [u for u in member if u["anonymous"]][0]
    assert anon["user_id"] is None and anon["role"] is None and anon["nickname"] is None, anon
    assert anon["avatar"] == {} and anon["username"] == "Anonymous" and anon["anon_ref"], anon
    assert anon["status_message"] is None and anon["last_seen_at"] is None, anon
    assert anon["status"] == "online", anon
    assert "alice" not in json.dumps(member) and "Nick" not in json.dumps(member)
    assert "Monday" not in json.dumps(member)
    assert [u for u in member if not u["anonymous"]][0]["user_id"] == 8
    for viewer, role in ((1, "moderator"), (AUTHOR, "user")):
        anon = [u for u in server._chat_users_list(rows, "c", viewer, role) if u["anonymous"]][0]
        assert anon["user_id"] == AUTHOR and anon["role"] == "admin", anon
        assert anon["nickname"] is None and anon["username"] == "Anonymous", anon
        assert anon["status_message"] == "back Monday", anon


def test_delete_notice_hides_deleter():
    async def run():
        member, author = FakeWs(), FakeWs()
        server.chat_rooms["t"] = {(member, 1, "m", "user"), (author, AUTHOR, "a", "user")}
        try:
            await server.broadcast_to_channel(
                "t", {"type": "message_deleted", "message_id": 5, "deleted_by": AUTHOR}, anon_subject=AUTHOR)
            assert member.sent[0]["deleted_by"] is None and member.sent[0]["message_id"] == 5, member.sent
            assert author.sent[0]["deleted_by"] == AUTHOR, author.sent
        finally:
            server.chat_rooms.pop("t", None)
    asyncio.run(run())


def test_ban_list_masks_anonymous_rows_for_members_only():
    rows = [
        {"id": 1, "user_id": AUTHOR, "banned_username": "alice", "anonymous": 1},
        {"id": 2, "user_id": 8, "banned_username": "bob", "anonymous": 0},
    ]
    owner = server._mask_ban_rows(rows, 5, "user")
    assert owner[0]["user_id"] is None and owner[0]["banned_username"] == "Anonymous", owner
    assert owner[0]["id"] == 1, owner
    assert owner[1]["user_id"] == 8 and owner[1]["banned_username"] == "bob", owner
    assert rows[0]["user_id"] == AUTHOR, "input must not be modified"
    for viewer, role in ((9, "moderator"), (9, "admin"), (9, "superadmin"), (AUTHOR, "user")):
        out = server._mask_ban_rows(rows, viewer, role)
        assert out[0]["user_id"] == AUTHOR and out[0]["banned_username"] == "alice", (viewer, role, out)


def test_anonymous_member_is_dropped_from_channel_voice():
    async def run():
        anon_ws, peer_ws, dm_ws = FakeWs(), FakeWs(), FakeWs()
        base = {"muted": False, "deafened": False, "speaking": False, "screen_sharing": False}
        server.voice_state["vc"] = {AUTHOR: {"ws": anon_ws, "username": "x", **base},
                                    9: {"ws": peer_ws, "username": "y", **base}}
        server.voice_state["dm:1"] = {AUTHOR: {"ws": dm_ws, "username": "x", **base}}
        try:
            await server.drop_channel_voice(AUTHOR)
            assert AUTHOR not in server.voice_state["vc"] and 9 in server.voice_state["vc"]
            assert any(m.get("type") == "voice_denied" for m in anon_ws.sent), anon_ws.sent
            assert any(m.get("type") == "voice_user_left" for m in peer_ws.sent), peer_ws.sent
            assert AUTHOR in server.voice_state["dm:1"] and not dm_ws.sent
        finally:
            server.voice_state.pop("vc", None)
            server.voice_state.pop("dm:1", None)
    asyncio.run(run())


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
    sys.exit(1 if failed else 0)
