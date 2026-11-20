"""Stream ban storage: bans made from anonymous posts are separate records, the
old table layout is migrated, and unbanning by account id leaves them alone.

Run: venv/bin/python tests/test_stream_bans.py
"""

import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402


def run_db(body, setup=None):
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "t.db")
            if setup:
                setup(path)
            d = Database(path)
            try:
                await d.connect()
                await body(d)
            finally:
                await d.close()
    asyncio.run(go())


async def make_stream(d):
    owner = await d.create_user("owner1", "x")
    author = await d.create_user("author1", "x")
    other = await d.create_user("other1", "x")
    sid = await d.create_user_stream(owner, "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24)
    return owner, author, other, sid


def test_anonymous_ban_does_not_collide_with_named_ban():
    async def body(d):
        owner, author, other, sid = await make_stream(d)
        a1 = await d.create_stream_ban(sid, author, owner, "r", anonymous=True, message_id=11)
        n1 = await d.create_stream_ban(sid, author, owner, "r")
        assert a1 and n1 and a1 != n1
        assert await d.create_stream_ban(sid, author, owner, "r") == 0, "second named ban refused"
        # a second post by the same author is a second record, the same post is not
        a2 = await d.create_stream_ban(sid, author, owner, "r", anonymous=True, message_id=12)
        assert a2 and a2 not in (a1, n1)
        assert await d.create_stream_ban(sid, author, owner, "r", anonymous=True, message_id=11) == a1
        rows = await d.get_stream_bans(sid)
        assert len(rows) == 3 and sorted(r["anonymous"] for r in rows) == [0, 1, 1], rows
        assert all("message_id" not in r for r in rows)
    run_db(body)


def test_unban_by_user_id_leaves_anonymous_rows_unless_asked():
    async def body(d):
        owner, author, other, sid = await make_stream(d)
        await d.create_stream_ban(sid, author, owner, anonymous=True, message_id=5)
        assert not await d.remove_stream_ban(sid, author), "same answer as for a user never banned"
        assert not await d.remove_stream_ban(sid, other)
        assert await d.is_user_banned_from_stream(sid, author)
        assert await d.remove_stream_ban(sid, author, include_anonymous=True)
        assert not await d.is_user_banned_from_stream(sid, author)
    run_db(body)


def test_unban_by_ban_id_is_scoped_to_the_stream():
    async def body(d):
        owner, author, other, sid = await make_stream(d)
        sid2 = await d.create_user_stream(other, "s2", "live_" + "c" * 24, public_key="pub_" + "d" * 24)
        bid = await d.create_stream_ban(sid, author, owner, anonymous=True, message_id=5)
        assert await d.remove_stream_ban_by_id(sid2, bid) is None
        row = await d.remove_stream_ban_by_id(sid, bid)
        assert row and row["anonymous"] == 1 and row["user_id"] == author
        assert await d.remove_stream_ban_by_id(sid, bid) is None
    run_db(body)


OLD_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL DEFAULT 'x');
CREATE TABLE user_streams (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT);
CREATE TABLE stream_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    banned_by INTEGER NOT NULL,
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(stream_id, user_id)
);
CREATE INDEX idx_stream_bans_stream ON stream_bans(stream_id);
INSERT INTO users (id, username) VALUES (1, 'o'), (2, 'a');
INSERT INTO user_streams (id, user_id, name) VALUES (1, 1, 's');
INSERT INTO stream_bans (id, stream_id, user_id, banned_by, reason) VALUES (7, 1, 2, 1, 'old');
"""


def test_old_table_is_migrated_and_migration_is_repeatable():
    def setup(path):
        con = sqlite3.connect(path)
        con.executescript(OLD_SCHEMA)
        con.commit()
        con.close()

    async def body(d):
        cur = await d.conn.execute("SELECT id, user_id, reason, anonymous, message_id FROM stream_bans")
        rows = [dict(r) for r in await cur.fetchall()]
        assert rows == [{"id": 7, "user_id": 2, "reason": "old", "anonymous": 0, "message_id": None}], rows
        # the old UNIQUE(stream_id, user_id) is gone: a masked ban fits next to the named one
        assert await d.create_stream_ban(1, 2, 1, anonymous=True, message_id=3)
        assert await d.create_stream_ban(1, 2, 1, "dup") == 0
        # the banner's anonymity at the time of the ban is stored; old rows count as named
        cur = await d.conn.execute("SELECT banned_by_anonymous FROM stream_bans WHERE id = 7")
        assert (await cur.fetchone())["banned_by_anonymous"] == 0
        assert await d.create_stream_ban(1, 2, 1, anonymous=True, message_id=4, banned_by_anonymous=True)
        rows = sorted(r["banned_by_anonymous"] for r in await d.get_stream_bans(1))
        assert rows == [0, 0, 1], rows
        # running the migration again changes nothing
        await d._migrate_stream_bans_anonymous()
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM stream_bans")
        assert (await cur.fetchone())["n"] == 3
        cur = await d.conn.execute("PRAGMA index_list(stream_bans)")
        assert not any(r["origin"] == "u" for r in await cur.fetchall())
    run_db(body, setup)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
