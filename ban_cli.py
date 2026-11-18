"""Command-line removal of IP blocks, for an admin who is locked out.

`server.py unblock <ip>` and `server.py clear-bans` open the database directly
with the standard library. They never start the server, never run migrations
and never create a missing database. Run them with the server stopped: a
running server keeps its block list in memory until it restarts, and scanner
blocks (which are only in memory) disappear on restart.
"""

import ipaddress
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote


def _canon(text):
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _connect(db_path: str):
    path = Path(db_path)
    if not path.is_file():
        raise SystemExit(f"error: no database at {path}")
    try:
        conn = sqlite3.connect(f"file:{quote(str(path))}?mode=rw", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn
    except sqlite3.Error as e:
        raise SystemExit(f"error: cannot open {path}: {e}")


def _rows(conn):
    """All block rows. Tolerates a database from before the `source` column existed."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(blocked_ips)")}
    if not cols:
        return []
    source = "source" if "source" in cols else "'manual' AS source"
    return list(conn.execute(
        f"SELECT id, ip_address, reason, expires_at, created_at, {source} FROM blocked_ips ORDER BY id"
    ))


def _describe(row) -> str:
    until = row["expires_at"] or "permanent"
    reason = f" reason: {row['reason']}" if row["reason"] else ""
    return f"  {row['ip_address']}  ({row['source']}, until {until}){reason}"


def _delete(conn, rows) -> None:
    conn.executemany("DELETE FROM blocked_ips WHERE id = ?", [(r["id"],) for r in rows])
    conn.commit()


def _after_note(removed: int) -> None:
    if removed:
        print("Restart the portal if it is running: it keeps its block list in memory.\n"
              "Temporary scanner blocks are held in memory only and clear on restart.")


def unblock(ip: str, db_path: str) -> int:
    """Remove every block row for `ip`. Returns the exit status."""
    want = _canon(ip)
    if want is None:
        print(f"error: {ip!r} is not an IP address", file=sys.stderr)
        return 2
    conn = _connect(db_path)
    try:
        # Rows hold the text the admin typed, so IPv6 case and compression vary: compare canonically.
        rows = [r for r in _rows(conn) if (_canon(r["ip_address"]) or r["ip_address"]) == want]
        if not rows:
            print(f"No database block found for {want}.")
            _after_note(0)
            return 1
        _delete(conn, rows)
    finally:
        conn.close()
    print(f"Removed {len(rows)} block(s) for {want}:")
    for r in rows:
        print(_describe(r))
    _after_note(len(rows))
    return 0


def clear_bans(db_path: str) -> int:
    """Remove every block row, manual and automatic. Returns the exit status."""
    conn = _connect(db_path)
    try:
        rows = _rows(conn)
        if rows:
            _delete(conn, rows)
    finally:
        conn.close()
    print(f"Removed {len(rows)} block(s):" if rows else "There were no blocks in the database.")
    for r in rows:
        print(_describe(r))
    _after_note(len(rows))
    return 0
