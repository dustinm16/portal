"""The connection_user_prefs table: created by the migration without touching existing tables,
repeatable, and the previous release (v1.21.0, taken from the repository's tag) still starts on
the migrated database and can delete a connection and a user that have filing rows (the foreign
keys remove the rows). The migration is one CREATE TABLE IF NOT EXISTS and one CREATE INDEX IF
NOT EXISTS: nothing existing is rewritten or scanned, so it costs the same on a 250 MB database
as on an empty one.

Run: venv/bin/python tests/test_dash_prefs_migration.py
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
    cur = await d.conn.execute("SELECT id FROM user_connections WHERE name = 'gone'")
    cid = (await cur.fetchone())["id"]
    cur = await d.conn.execute("SELECT id, user_id FROM user_connections WHERE id = ?", (cid,))
    row = await cur.fetchone()
    ok1 = await d.delete_user_connection(cid, row["user_id"])
    cur = await d.conn.execute("SELECT id FROM users WHERE username = 'bob'")
    bob = (await cur.fetchone())["id"]
    ok2 = await d.delete_user(bob)
    left = await (await d.conn.execute("SELECT COUNT(*) FROM connection_user_prefs")).fetchone()
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
        await db.conn.close()
        con = sqlite3.connect(path)
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        idx = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        cols = [r[1] for r in con.execute("PRAGMA table_info(connection_user_prefs)")]
        con.close()
        check("the table and its index exist", "connection_user_prefs" in tables and "idx_conn_prefs_conn" in idx)
        check("the columns", cols == ["user_id", "connection_id", "folder", "tags", "open_mode", "pinned", "last_opened_at"], str(cols))

        db2 = Database()
        db2.db_path = path
        await db2.connect()
        await db2.conn.close()
        check("a second start is clean (repeatable)", True)

        # rows: an owner, a grantee, two connections, a share, filing rows
        con = sqlite3.connect(path)
        con.execute("PRAGMA foreign_keys = ON")
        for name in ("owner", "bob"):
            con.execute("INSERT INTO users (username, password_hash) VALUES (?, 'x')", (name,))
        for name, uuid in (("keep", "u-keep"), ("gone", "u-gone")):
            con.execute("INSERT INTO user_connections (user_id, name, type, host, port, config, uuid) VALUES (1, ?, 'ssh', 'h', 22, '{}', ?)", (name, uuid))
        con.execute("INSERT INTO connection_shares (connection_id, grantee_user_id, granted_by) VALUES (1, 2, 1)")
        con.execute("INSERT INTO connection_shares (connection_id, grantee_user_id, granted_by) VALUES (2, 2, 1)")
        for uid, cid in ((1, 1), (1, 2), (2, 1), (2, 2)):
            con.execute("INSERT INTO connection_user_prefs (user_id, connection_id, folder) VALUES (?, ?, 'Games')", (uid, cid))
        con.commit()
        con.close()

        # the table is the only thing the migration added
        before = {}
        con = sqlite3.connect(path)
        for t in ("users", "user_connections", "connection_shares"):
            before[t] = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
        con.close()
        check("existing tables have no new columns from this change",
              "folder" not in before["user_connections"] and "folder" not in before["connection_shares"])

        # v1.21.0 on the migrated database
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
            check("v1.21.0 starts on the migrated database and deletes a connection and a user that have filing rows",
                  bool(line) and line[0] == "RESULT True True 1", (res.stdout + res.stderr)[-400:])
            con = sqlite3.connect(path)
            rows = con.execute("SELECT user_id, connection_id FROM connection_user_prefs").fetchall()
            con.close()
            check("only the surviving owner's filing of the surviving connection is left", rows == [(1, 1)], str(rows))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
if failures:
    print(f"\ntest_dash_prefs_migration: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_dash_prefs_migration: all checks passed")
