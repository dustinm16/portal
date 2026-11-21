"""Voice sessions across reconnects and tabs: ownership, the reconnect grace
period, resume rules and immediate removal for revoked sessions.

Run: venv/bin/python tests/test_voice_resume.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402

ALICE, BOB, EVE = 11, 12, 13
ROOM = "vc-test"
DM = "dm:900"


class FakeWs:
    def __init__(self):
        self.closed = False
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)

    def types(self):
        return [m.get("type") for m in self.sent]


def entry(ws, token="tok-a", token_id="sess-a", **kw):
    e = {"ws": ws, "username": "u", "muted": False, "deafened": False, "speaking": False,
         "screen_sharing": False, "reconnecting": False, "resume_token": token, "token_id": token_id}
    e.update(kw)
    return e


STATE = {"anonymous": False, "nickname": None, "avatar": {}}


def fresh(grace=0.05):
    server.voice_state.clear()
    server.VOICE_RESUME_GRACE = grace

    async def allowed(room, user_id, role):
        return True
    server._voice_room_allowed = allowed


def resume(ws, user_id, token, room=ROOM, state=STATE, token_id="sess-new"):
    return server._voice_resume(ws, user_id, "user", token_id, state,
                                {"resume": True, "resume_token": token, "room": room})


def test_closing_a_second_socket_keeps_the_call():
    async def run():
        fresh()
        tab_a, tab_b, peer = FakeWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(tab_a), BOB: entry(peer, "tok-b")}
        await server._voice_socket_closed(tab_b, ALICE)
        assert not server.voice_state[ROOM][ALICE]["reconnecting"]
        assert peer.sent == [], peer.sent
        await asyncio.sleep(0.15)
        assert ALICE in server.voice_state[ROOM] and peer.sent == [], peer.sent
    asyncio.run(run())


def test_owned_socket_close_goes_reconnecting_then_left_after_grace():
    async def run():
        fresh(0.1)
        tab_a, peer = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(tab_a), BOB: entry(peer, "tok-b")}
        await server._voice_socket_closed(tab_a, ALICE)
        assert peer.types() == ["voice_user_reconnecting"], peer.sent
        assert server.voice_state[ROOM][ALICE]["reconnecting"]
        await asyncio.sleep(0.25)
        assert peer.types() == ["voice_user_reconnecting", "voice_user_left"], peer.sent
        assert ALICE not in server.voice_state[ROOM]
    asyncio.run(run())


def test_resume_within_grace_gives_resumed_not_left():
    async def run():
        fresh(0.2)
        old, new, peer = FakeWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old), BOB: entry(peer, "tok-b")}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        room = await resume(new, ALICE, "tok-a")
        assert room == ROOM
        assert peer.types() == ["voice_user_reconnecting", "voice_user_resumed"], peer.sent
        assert new.sent[0]["type"] == "voice_state" and new.sent[0]["resumed"] is True
        assert new.sent[0]["resume_token"] == "tok-a"
        assert server.voice_state[ROOM][ALICE]["ws"] is new
        await asyncio.sleep(0.4)
        assert ALICE in server.voice_state[ROOM] and "voice_user_left" not in peer.types(), peer.sent
        # the old socket's own handler, finishing late, must not disturb the new owner
        await server._voice_socket_closed(old, ALICE)
        assert not server.voice_state[ROOM][ALICE]["reconnecting"]
    asyncio.run(run())


def test_resume_needs_the_token_and_the_same_account():
    async def run():
        fresh(0.5)
        old, other = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old)}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        # right token, wrong account: the caller's own id is used for the lookup
        assert await resume(other, EVE, "tok-a") is None
        assert other.types() == ["voice_resume_failed"], other.sent
        # right account, wrong token and missing token
        for bad in ("nope", "", None, 5):
            w = FakeWs()
            assert await resume(w, ALICE, bad) is None
            assert w.types() == ["voice_resume_failed"], (bad, w.sent)
        # wrong room
        w = FakeWs()
        assert await resume(w, ALICE, "tok-a", room="other") is None
        assert server.voice_state[ROOM][ALICE]["reconnecting"]
        assert server.voice_state[ROOM][ALICE]["ws"] is old
        server.voice_state[ROOM][ALICE]["grace_task"].cancel()
    asyncio.run(run())


def test_active_entry_is_taken_over_only_with_the_token():
    async def run():
        fresh(0.5)
        first, second, third = FakeWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(first)}
        assert await resume(second, ALICE, "wrong") is None
        assert server.voice_state[ROOM][ALICE]["ws"] is first
        assert await resume(second, ALICE, "tok-a") == ROOM
        assert server.voice_state[ROOM][ALICE]["ws"] is second
        await asyncio.sleep(0.05)
        assert "voice_denied" in first.types(), first.sent  # replaced socket is told
        # the old socket can no longer act on the session
        assert server._voice_owned(ROOM, ALICE, first) is None
        assert server._voice_owned(ROOM, ALICE, second) is not None
        assert third.sent == []
    asyncio.run(run())


def test_second_join_blocked_while_reconnecting():
    async def run():
        fresh(0.5)
        old = FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old)}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        # voice_join without resume looks for any entry of the account
        assert server._voice_find(ALICE)[1] is not None
        server.voice_state[ROOM][ALICE]["grace_task"].cancel()
    asyncio.run(run())


def test_broadcast_skips_reconnecting_members():
    async def run():
        fresh()
        gone, peer = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(gone, reconnecting=True), BOB: entry(peer, "tok-b")}
        await server.broadcast_to_voice_room(ROOM, {"type": "x"})
        assert gone.sent == [] and peer.sent == [{"type": "x"}]
    asyncio.run(run())


def test_users_payload_and_users_list_show_reconnecting():
    fresh()
    server.voice_state[ROOM] = {ALICE: entry(FakeWs(), reconnecting=True), BOB: entry(FakeWs(), "tok-b")}
    payload = {u["user_id"]: u["reconnecting"] for u in server._voice_users_payload(ROOM)}
    assert payload == {ALICE: True, BOB: False}, payload
    users = [{"id": ALICE, "username": "alice", "chat_anonymous": 0},
             {"id": BOB, "username": "bob", "chat_anonymous": 0}]
    out = {u["user_id"]: u for u in server._chat_users_list(users, ROOM, BOB, "user")}
    assert out[ALICE]["in_voice"] and out[ALICE]["voice_reconnecting"] is True, out[ALICE]
    assert out[BOB]["in_voice"] and out[BOB]["voice_reconnecting"] is False, out[BOB]


def test_revoked_session_leaves_at_once_without_grace():
    async def run():
        fresh(5)
        live, held, peer = FakeWs(), FakeWs(), FakeWs()
        # alice has one live call on session s1; bob's call is being held on session s2
        server.voice_state[ROOM] = {ALICE: entry(live, token_id="s1"),
                                    BOB: entry(held, "tok-b", token_id="s2", reconnecting=True),
                                    EVE: entry(peer, "tok-e", token_id="s3")}
        held.closed = True
        await server.close_user_websockets(ALICE)
        assert ALICE not in server.voice_state[ROOM]
        assert peer.types() == ["voice_user_left"], peer.sent
        await server.close_user_websockets(BOB)
        assert BOB not in server.voice_state[ROOM]
        assert peer.types() == ["voice_user_left", "voice_user_left"], peer.sent
        assert "voice_user_reconnecting" not in peer.types()
        # the spared session keeps its call
        await server.close_user_websockets(EVE, except_token_id="s3")
        assert EVE in server.voice_state[ROOM]
    asyncio.run(run())


def test_revocation_still_closes_sockets_when_the_voice_announcement_fails():
    async def run():
        fresh(5)

        class ClosableWs(FakeWs):
            close_code = None

            async def close(self, code=1000, message=b""):
                self.closed = True
                self.close_code = code

        live, peer = ClosableWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(live, token_id="s1"), BOB: entry(peer, "tok-b")}
        server._register_user_ws(ALICE, live, "s1")
        real = server.broadcast_users_list

        async def boom(channel):
            raise RuntimeError("database is locked")
        server.broadcast_users_list = boom
        try:
            closed = await server.close_user_websockets(ALICE)
        finally:
            server.broadcast_users_list = real
            server._unregister_user_ws(ALICE, live)
        assert closed == 1 and live.closed and live.close_code == 4001, (closed, live.closed, live.close_code)
        assert ALICE not in server.voice_state[ROOM]
    asyncio.run(run())


def test_leave_removes_at_once_and_ignores_other_sockets():
    async def run():
        fresh(5)
        owner, other, peer = FakeWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(owner), BOB: entry(peer, "tok-b")}
        assert server._voice_owned(ROOM, ALICE, other) is None
        assert server._voice_owned(ROOM, ALICE, owner) is not None
        assert await server._voice_remove(ROOM, ALICE)
        assert peer.types() == ["voice_user_left"], peer.sent
        assert not await server._voice_remove(ROOM, ALICE)
    asyncio.run(run())


def test_grace_timer_does_not_remove_a_resumed_entry():
    async def run():
        fresh(0.1)
        old, new = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old)}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        task = server.voice_state[ROOM][ALICE]["grace_task"]
        assert await resume(new, ALICE, "tok-a") == ROOM
        await asyncio.sleep(0.3)
        assert task.cancelled() or task.done()
        assert ALICE in server.voice_state[ROOM]
    asyncio.run(run())


def test_anonymous_user_cannot_resume_a_channel_room():
    async def run():
        fresh(0.5)
        old, new = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old)}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        anon = {"anonymous": True, "nickname": None, "avatar": {}}
        assert await resume(new, ALICE, "tok-a", state=anon) is None
        assert new.types() == ["voice_denied"], new.sent
        assert ALICE not in server.voice_state.get(ROOM, {})
        # a direct message call is still resumable by an anonymous member
        server.voice_state[DM] = {ALICE: entry(old)}
        assert await resume(new, ALICE, "tok-a", room=DM, state=anon) == DM
    asyncio.run(run())


def test_refused_room_access_drops_the_session():
    async def run():
        fresh(0.5)
        old, new = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old)}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)

        async def denied(room, user_id, role):
            return False
        server._voice_room_allowed = denied
        assert await resume(new, ALICE, "tok-a") is None
        assert new.types() == ["voice_resume_failed"] and ALICE not in server.voice_state.get(ROOM, {})
    asyncio.run(run())


class ClosableWs(FakeWs):
    close_code = None

    async def close(self, code=1000, message=b""):
        self.closed = True
        self.close_code = code


def test_close_user_websockets_only_token_spares_other_sessions():
    async def run():
        fresh(5)
        s1, s2, peer = ClosableWs(), ClosableWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(s2, token_id="sess-2"), BOB: entry(peer, "tok-b")}
        server._register_user_ws(ALICE, s1, "sess-1")
        server._register_user_ws(ALICE, s2, "sess-2")
        try:
            closed = await server.close_user_websockets(ALICE, only_token_id="sess-1")
            # the call belongs to session 2, so it and its socket stay
            assert closed == 1 and s1.close_code == 4001 and not s2.closed, (closed, s1.close_code, s2.closed)
            assert ALICE in server.voice_state[ROOM] and peer.sent == [], peer.sent
            closed = await server.close_user_websockets(ALICE, only_token_id="sess-2")
            assert closed == 1 and s2.close_code == 4001
            assert ALICE not in server.voice_state[ROOM] and peer.types() == ["voice_user_left"], peer.sent
        finally:
            server._unregister_user_ws(ALICE, s1)
            server._unregister_user_ws(ALICE, s2)
    asyncio.run(run())


def test_logout_closes_only_that_sessions_sockets_and_call():
    async def run():
        fresh(5)
        s1, s2, peer = ClosableWs(), ClosableWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(s1, token_id="sess-1"), BOB: entry(peer, "tok-b")}
        server._register_user_ws(ALICE, s1, "sess-1")
        server._register_user_ws(ALICE, s2, "sess-2")

        class Tok:
            token_id, user_id = "sess-1", ALICE

        class Req:
            method = "GET"      # the sign-out link

            class cookies:
                @staticmethod
                def get(name):
                    return "cookie"

        revoked = []

        async def auth(request):
            return Tok

        async def revoke(token_id):
            revoked.append(token_id)
        real_auth, real_revoke = server.authenticate_request, server.db.revoke_token
        server.authenticate_request, server.db.revoke_token = auth, revoke
        try:
            try:
                await server.http_logout(Req)
                raise AssertionError("logout should redirect")
            except server.web.HTTPFound:
                pass
        finally:
            server.authenticate_request, server.db.revoke_token = real_auth, real_revoke
            server._unregister_user_ws(ALICE, s1)
            server._unregister_user_ws(ALICE, s2)
        assert revoked == ["sess-1"]
        assert s1.close_code == 4001 and not s2.closed, (s1.close_code, s2.closed)
        assert ALICE not in server.voice_state[ROOM] and peer.types() == ["voice_user_left"], peer.sent
    asyncio.run(run())


def test_voice_leave_with_token_removes_a_held_entry_at_once():
    async def run():
        fresh(5)
        old, new, peer = FakeWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old), BOB: entry(peer, "tok-b")}
        old.closed = True
        await server._voice_socket_closed(old, ALICE)
        task = server.voice_state[ROOM][ALICE]["grace_task"]
        assert peer.types() == ["voice_user_reconnecting"]
        # wrong token, missing token, wrong room, another account: nothing happens
        assert not await server._voice_leave_with_token(ALICE, {"resume_token": "nope"})
        assert not await server._voice_leave_with_token(ALICE, {})
        assert not await server._voice_leave_with_token(ALICE, {"resume_token": 5})
        assert not await server._voice_leave_with_token(ALICE, {"resume_token": "tok-a", "room": "other"})
        assert not await server._voice_leave_with_token(EVE, {"resume_token": "tok-a"})
        assert ALICE in server.voice_state[ROOM] and peer.types() == ["voice_user_reconnecting"]
        # the right token: removed at once, no resume needed, the grace timer is cancelled
        assert await server._voice_leave_with_token(ALICE, {"resume_token": "tok-a", "room": ROOM})
        assert ALICE not in server.voice_state[ROOM]
        assert peer.types() == ["voice_user_reconnecting", "voice_user_left"], peer.sent
        await asyncio.sleep(0)
        assert task.cancelled() or task.done()
        # a later resume has nothing to take over
        assert await resume(new, ALICE, "tok-a") is None
        assert new.types() == ["voice_resume_failed"], new.sent
        assert not await server._voice_leave_with_token(ALICE, {"resume_token": "tok-a"})
    asyncio.run(run())


def test_voice_leave_with_token_ends_a_live_entry_of_an_older_socket():
    async def run():
        fresh(5)
        old, peer = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(old), BOB: entry(peer, "tok-b")}
        assert await server._voice_leave_with_token(ALICE, {"resume_token": "tok-a"})
        assert ALICE not in server.voice_state[ROOM] and peer.types() == ["voice_user_left"]
    asyncio.run(run())


def test_voice_enter_grace_survives_a_failing_announcement():
    async def run():
        fresh(5)
        gone, peer = FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(gone), BOB: entry(peer, "tok-b")}
        real = server.broadcast_users_list

        async def boom(channel):
            raise RuntimeError("database is locked")
        server.broadcast_users_list = boom
        try:
            await server._voice_socket_closed(gone, ALICE)
        finally:
            server.broadcast_users_list = real
        e = server.voice_state[ROOM][ALICE]
        assert e["reconnecting"] and e.get("grace_task") is not None
        e["grace_task"].cancel()
    asyncio.run(run())


def test_voice_close_failure_is_logged_and_does_not_raise():
    async def run():
        fresh(5)
        real = server._voice_socket_closed

        async def boom(ws, user_id):
            raise RuntimeError("anything")
        server._voice_socket_closed = boom
        try:
            await server._voice_close_safely(FakeWs(), ALICE)
        finally:
            server._voice_socket_closed = real
    asyncio.run(run())


def test_member_who_lost_access_is_removed_from_the_call_at_once():
    async def run():
        fresh(5)
        ws, peer, held = ClosableWs(), FakeWs(), FakeWs()
        server.voice_state[ROOM] = {ALICE: entry(ws), BOB: entry(peer, "tok-b"),
                                    EVE: entry(held, "tok-e", reconnecting=True)}

        async def role(user_id):
            return "user"
        real_role = server._chat_role_of_user
        server._chat_role_of_user = role
        try:
            # still allowed: nothing happens
            await server._voice_eject_if_not_allowed(ALICE)
            assert ALICE in server.voice_state[ROOM] and ws.sent == []

            async def denied(room, user_id, r):
                return False
            server._voice_room_allowed = denied
            await server._voice_eject_if_not_allowed(ALICE)
            assert ALICE not in server.voice_state[ROOM]
            assert ws.types() == ["voice_denied"], ws.sent
            assert peer.types() == ["voice_user_left"], peer.sent
            # a held entry is removed too, without a message to its dead socket
            await server._voice_eject_if_not_allowed(EVE)
            assert EVE not in server.voice_state[ROOM] and held.sent == []
            # not in a call: nothing happens, no error
            await server._voice_eject_if_not_allowed(ALICE)
            # a failing check is logged and never raised
            server.voice_state[ROOM][ALICE] = entry(ws)

            async def boom(room, user_id, r):
                raise RuntimeError("db")
            server._voice_room_allowed = boom
            await server._voice_eject_if_not_allowed(ALICE)
            assert ALICE in server.voice_state[ROOM]
        finally:
            server._chat_role_of_user = real_role
    asyncio.run(run())


def test_making_a_channel_private_ejects_the_members_who_may_not_stay():
    class Req:
        match_info = {"id": "9"}

        def __init__(self, data):
            self._data = data

        async def json(self):
            return self._data

    async def run(data, ejected_expected):
        fresh(5)
        a, b, c = FakeWs(), FakeWs(), FakeWs()
        server.voice_state["secret-room"] = {ALICE: entry(a), BOB: entry(b, "tok-b"), EVE: entry(c, "tok-e")}
        server.voice_state["other-room"] = {13: entry(FakeWs(), "tok-x")}

        async def auth(request):
            return type("T", (), {"user_id": 1, "has_scope": lambda self, s: True})()

        async def get_user(uid):
            return {"id": uid, "username": "mod", "role": "moderator"}

        async def get_channel(cid):
            return {"id": cid, "name": "secret-room", "is_default": 0, "visibility": "public"}

        async def no_stream(cid):
            return None

        async def update(cid, **kw):
            return True

        async def audit(*args, **kw):
            return None

        async def role(user_id):
            return "user"

        async def allowed(room, user_id, r):
            return user_id == BOB       # only Bob is a member of the private channel
        saved = (server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel,
                 server.db.get_stream_by_chat_channel, server.db.update_chat_channel, server.audit_log,
                 server._chat_role_of_user, server._voice_room_allowed)
        (server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel,
         server.db.get_stream_by_chat_channel, server.db.update_chat_channel, server.audit_log,
         server._chat_role_of_user, server._voice_room_allowed) = (
            auth, get_user, get_channel, no_stream, update, audit, role, allowed)
        try:
            resp = await server.http_update_chat_channel(Req(data))
            assert resp.status == 200, resp.status
        finally:
            (server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel,
             server.db.get_stream_by_chat_channel, server.db.update_chat_channel, server.audit_log,
             server._chat_role_of_user, server._voice_room_allowed) = saved
        left = set(server.voice_state.get("secret-room", {}))
        assert left == ejected_expected, left
        return a, b, c

    # to private: Alice and Eve are not members, so they are taken out, with a notice; Bob stays
    a, b, c = asyncio.run(run({"visibility": "private"}, {BOB}))
    assert a.types() == ["voice_denied"] and "voice_denied" in c.types(), (a.sent, c.sent)
    assert "voice_user_left" in b.types() and "voice_denied" not in b.types(), b.sent
    assert 13 in server.voice_state["other-room"]
    # any other change leaves the call alone
    asyncio.run(run({"description": "x"}, {ALICE, BOB, EVE}))
    asyncio.run(run({"visibility": "public"}, {ALICE, BOB, EVE}))


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
            except Exception as e:  # noqa: BLE001
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
