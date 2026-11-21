"""The recordings table rebuild (service_id nullable, connection columns): rows and ids survive,
it can run twice, a recording of a user connection can be stored, and deleting the connection
leaves the recording.

Run: venv/bin/python tests/test_recordings_migration.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402

OLD_DDL = """CREATE TABLE recordings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'asciicast',
    size INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
)"""
failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "t.db")
        d = Database(path)
        await d.connect()
        uid = await d.create_user("rec_user", "x")
        sid = await d.create_service(name="shell", path="/shell-m", plugin="terminal")
        # put the database back into the 1.19.0 shape, with rows
        await d.conn.execute("PRAGMA foreign_keys = OFF")
        await d.conn.execute("DROP TABLE recordings")
        await d.conn.execute(OLD_DDL)
        await d.conn.execute("CREATE INDEX idx_recordings_user_id ON recordings(user_id)")
        await d.conn.execute("CREATE INDEX idx_recordings_service_id ON recordings(service_id)")
        for i in (3, 7, 9):
            await d.conn.execute(
                "INSERT INTO recordings (id, user_id, service_id, filename, size, duration, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, '2026-01-02 03:04:05')", (i, uid, sid, f"old{i}.cast", i * 10, i * 1.5))
        await d.conn.commit()
        await d.conn.execute("PRAGMA foreign_keys = ON")
        await d.close()

        d = Database(path)
        await d.connect()
        cur = await d.conn.execute("SELECT * FROM recordings ORDER BY id")
        rows = [dict(r) for r in await cur.fetchall()]
        check("rows and ids survive the rebuild", [r["id"] for r in rows] == [3, 7, 9]
              and rows[1]["filename"] == "old7.cast" and rows[1]["size"] == 70 and rows[1]["duration"] == 10.5
              and rows[1]["created_at"] == "2026-01-02 03:04:05", str(rows))
        info = {r["name"]: r for r in await (await d.conn.execute("PRAGMA table_info(recordings)")).fetchall()}
        check("service_id is nullable and the connection columns exist",
              not info["service_id"]["notnull"] and {"connection_id", "connection_name", "kind"} <= set(info))
        got = await d.get_recording(7)
        check("an old row reads with the service's name and type", got["connection_name"] == "shell"
              and got["type"] == "terminal" and got["username"] == "rec_user", str(got))
        await d.close()

        d = Database(path)  # a second start does nothing more
        await d.connect()
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM recordings")
        check("a second run leaves the rows alone", (await cur.fetchone())["n"] == 3)
        idx = {r["name"] for r in await (await d.conn.execute("PRAGMA index_list(recordings)")).fetchall()}
        check("indexes exist", {"idx_recordings_user_id", "idx_recordings_service_id",
                                "idx_recordings_connection_id"} <= idx, str(idx))

        uuid = await d.create_user_connection(uid, "box", "ssh", "93.184.216.34", 22, "{}")
        cid = (await (await d.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
        rid = await d.create_recording(uid, None, "c.cast", connection_id=cid, connection_name="box", kind="ssh")
        got = await d.get_recording(rid)
        check("a recording of a user connection is stored", got["service_id"] is None and got["connection_id"] == cid
              and got["connection_name"] == "box" and got["type"] == "ssh", str(got))
        check("ids continue after the old ones", rid > 9, str(rid))
        await d.conn.execute("DELETE FROM user_connections WHERE id = ?", (cid,))
        await d.conn.commit()
        got = await d.get_recording(rid)
        check("deleting the connection leaves the recording, still named",
              got is not None and got["connection_id"] is None and got["connection_name"] == "box", str(got))
        await d.conn.execute("DELETE FROM services WHERE id = ?", (sid,))
        await d.conn.commit()
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM recordings")
        check("deleting a service still removes its recordings", (await cur.fetchone())["n"] == 1)
        await d.close()


asyncio.run(main())
if failures:
    print(f"\ntest_recordings_migration: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_recordings_migration: all checks passed")
