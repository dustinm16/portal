"""Dead DM sockets leave no empty set in dm_user_connections.

_broadcast_to_dm and _send_dm_to_user drop closed sockets from the user's set. A set that is
emptied that way is removed too, so 'user not in dm_user_connections' keeps meaning 'offline'.

Run: venv/bin/python tests/test_dm_dead_sockets.py
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402
outbound_guard.install()
import server  # noqa: E402


class FakeSock:
    def __init__(self, closed=False, fail=False):
        self.closed, self.fail, self.sent = closed, fail, []

    async def send_json(self, message):
        if self.fail:
            raise ConnectionResetError("gone")
        self.sent.append(message)


class FakeDb:
    async def get_dm_participant_ids(self, conversation_id):
        return [1, 2, 3]


def run(coro):
    saved_db = server.db
    saved = dict(server.dm_user_connections)
    server.dm_user_connections.clear()
    server.db = FakeDb()
    try:
        asyncio.run(asyncio.wait_for(coro, 10))
    finally:
        server.db = saved_db
        server.dm_user_connections.clear()
        server.dm_user_connections.update(saved)


def test_broadcast_with_only_dead_sockets_removes_the_key():
    async def body():
        server.dm_user_connections[1] = {FakeSock(closed=True)}
        server.dm_user_connections[2] = {FakeSock(fail=True), FakeSock(closed=True)}
        live = FakeSock()
        server.dm_user_connections[3] = {live, FakeSock(closed=True)}
        await server._broadcast_to_dm(5, {"type": "dm_message"})
        assert 1 not in server.dm_user_connections, dict(server.dm_user_connections)
        assert 2 not in server.dm_user_connections, dict(server.dm_user_connections)
        assert server.dm_user_connections[3] == {live}
        assert live.sent == [{"type": "dm_message"}]
    run(body())


def test_send_to_user_with_only_dead_sockets_removes_the_key():
    async def body():
        server.dm_user_connections[7] = {FakeSock(closed=True), FakeSock(fail=True)}
        await server._send_dm_to_user(7, {"type": "x"})
        assert 7 not in server.dm_user_connections, dict(server.dm_user_connections)
        live = FakeSock()
        server.dm_user_connections[8] = {live, FakeSock(closed=True)}
        await server._send_dm_to_user(8, {"type": "x"})
        assert server.dm_user_connections[8] == {live}
    run(body())


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
