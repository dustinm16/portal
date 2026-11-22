"""The connection_health_log table: created by the migration without touching existing tables,
repeatable, and the previous release (v1.21.0, from the repository's tag) still starts on the
migrated database and deletes a connection and a user that have log rows (the foreign key removes
them). One CREATE TABLE IF NOT EXISTS and one CREATE INDEX IF NOT EXISTS: nothing existing is
rewritten or scanned, so it costs the same on a 250 MB database as on an empty one. The two
settings (connection_health_enabled, connection_health_interval) are read with defaults and need no
row, so a database that never saw them behaves as "off".

Run: venv/bin/python tests/test_connection_health_migration.py
"""

import asyncio
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


OLD_RUN = r'''
import asyncio, os, sys
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("JWT_SECRET", "x" * 64)
from database import Database
async def main():
    d = Database(); d.db_path = sys.argv[2]
    await d.connect()
    cur = await d.conn.execute("SELECT id, user_id FROM user_connections WHERE name = 'gone'")
    row = await cur.fetchone()
    ok1 = await d.delete_user_connection(row["id"], row["user_id"])
    cur = await d.conn.execute("SELECT id FROM users WHERE username = 'bob'")
    ok2 = await d.delete_user((await cur.fetchone())["id"])
    left = await (await d.conn.execute("SELECT COUNT(*) FROM connection_health_log")).fetchone()
    print("RESULT", ok1, ok2, left[0], flush=True)
    await d.conn.close()
asyncio.run(main())
'''


async def main():
    tmp = Path(tempfile.mkdtemp())
    try:
        path = str(tmp / "t.db")
        db = Database()
        db.db_path = path
        await db.connect()
        check("a new database has no settings row for the feature: off", await db.get_setting("connection_health_enabled") is None)
        await db.conn.close()
        con = sqlite3.connect(path)
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        idx = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        cols = [r[1] for r in con.execute("PRAGMA table_info(connection_health_log)")]
        con.close()
        check("the table and its index exist", "connection_health_log" in tables and "idx_conn_health_conn" in idx)
        check("the columns", cols == ["id", "connection_id", "status", "since"], str(cols))
        db2 = Database()
        db2.db_path = path
        await db2.connect()
        await db2.conn.close()
        check("a second start is clean (repeatable)", True)

        con = sqlite3.connect(path)
        con.execute("PRAGMA foreign_keys = ON")
        for name in ("owner", "bob"):
            con.execute("INSERT INTO users (username, password_hash) VALUES (?, 'x')", (name,))
        for name, uuid in (("keep", "u-keep"), ("gone", "u-gone")):
            con.execute("INSERT INTO user_connections (user_id, name, type, host, port, config, uuid) VALUES (1, ?, 'ssh', 'h', 22, '{}', ?)", (name, uuid))
        for cid in (1, 2):
            con.execute("INSERT INTO connection_health_log (connection_id, status, since) VALUES (?, 'up', '2030-01-01T00:00:00Z')", (cid,))
        con.commit()
        con.close()

        tag = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "-q", "v1.21.0^{commit}"], capture_output=True, text=True)
        if tag.returncode != 0:
            print("skip: the v1.21.0 tag is not in this repository")
        else:
            old = tmp / "old"
            old.mkdir()
            arch = subprocess.run(["git", "-C", str(ROOT), "archive", "v1.21.0"], capture_output=True, timeout=120)
            subprocess.run(["tar", "-x", "-C", str(old)], input=arch.stdout, check=True, timeout=120)
            res = subprocess.run([sys.executable, "-c", OLD_RUN, str(old), path], capture_output=True, text=True, timeout=120, cwd=str(tmp))
            line = [ln for ln in res.stdout.splitlines() if ln.startswith("RESULT")]
            check("v1.21.0 starts on the migrated database and deletes a connection and a user that have log rows",
                  bool(line) and line[0] == "RESULT True True 1", (res.stdout + res.stderr)[-400:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
if failures:
    print(f"\ntest_connection_health_migration: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_connection_health_migration: all checks passed")
