"""The household check of a failed login looks up tokens by address through an index (1.24.2).

has_recent_login_from_anyone asks "SELECT 1 FROM tokens WHERE ip = ? ..." on every failed sign-in; without an
index on tokens(ip) that scans the table. The schema now creates idx_tokens_ip, and the query plan uses it.
A temporary database only.

Run: venv/bin/python tests/test_tokens_ip_index.py   (30 second deadline)
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402
from grant_harness import check, finish  # noqa: E402

QUERY = "SELECT 1 FROM tokens WHERE ip = ? AND created_at >= datetime('now', ?) LIMIT 1"


async def main():
    tmp = tempfile.mkdtemp()
    db = Database(str(Path(tmp) / "t.db"))
    await db.connect()
    cur = await db.conn.execute("EXPLAIN QUERY PLAN " + QUERY, ("203.0.113.9", "-30 days"))
    plan = " | ".join(str(r["detail"]) for r in await cur.fetchall())
    check("the household lookup by address uses idx_tokens_ip", "idx_tokens_ip" in plan, plan)
    cur = await db.conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_tokens_ip'")
    check("the index exists", await cur.fetchone() is not None)
    check("has_recent_login_from_anyone still answers False for an unknown address",
          await db.has_recent_login_from_anyone("203.0.113.9") is False)
    await db.conn.close()
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(asyncio.wait_for(main(), 30))
finish("test_tokens_ip_index")
