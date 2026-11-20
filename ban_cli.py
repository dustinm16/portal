"""Command-line removal of IP blocks and of the saved Cloudflare range list, for an admin who is locked out.

`server.py unblock <ip>` and `server.py clear-bans` open the database directly
with the standard library. They never start the server, never run migrations
and never create a missing database. Run them with the server stopped: a
running server keeps its block list in memory until it restarts, and scanner
blocks of either kind ('login' and 'probe', written to the database with an expiry) are
removed like any other row, together with the escalation history of the address, so
the next offence starts at the base duration again. Each removal is also
recorded as an ``ip_unblocked`` security event (source ``cli``), in the same
transaction, when the database already has the security event table.

`server.py cf-ranges-reset` works the same way: it deletes the saved fetched
Cloudflare list (setting `cf_ranges_list`) so the next start uses the built-in
list, and records a ``cf_ranges_reset`` security event with the source ``cli``. A list
held for approval (setting `cf_ranges_pending`) and a dismissal are cleared with it.
It writes no audit_log entry: that table needs an account as its actor and
holds encrypted details, and this tool has neither.
"""

import ipaddress
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

import secevents

# Same columns and order as Database._SEC_COLS (a test keeps them equal).
_EVENT_COLUMNS = ("ts", "event", "category", "user_id", "username_tried", "ip",
                  "user_agent", "result", "details", "count", "agg_key")


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
    kind = "kind" if "kind" in cols else "NULL AS kind"
    return list(conn.execute(
        f"SELECT id, ip_address, reason, expires_at, created_at, {source}, {kind} FROM blocked_ips ORDER BY id"
    ))


def _printable(value) -> str:
    """Text for the terminal: anything not printable (escape sequences, line
    breaks, other control characters) is dropped from what was stored."""
    return "".join(ch for ch in str(value) if ch.isprintable())


def _describe(row) -> str:
    until = _printable(row["expires_at"] or "permanent")
    reason = f" reason: {_printable(row['reason'])}" if row["reason"] else ""
    kind = f", {_printable(row['kind'])}" if row["kind"] else ""
    return f"  {_printable(row['ip_address'])}  ({_printable(row['source'])}{kind}, until {until}){reason}"


def _record_event(conn, details: dict, event: str = "ip_unblocked") -> None:
    """Write one security event (default ip_unblocked) in the open transaction.

    Skipped without a word when the database has no security_events table yet
    (this tool never migrates). The row has no client address: it names the
    command line as its source.
    """
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'security_events'").fetchone()
    if not has_table:
        return
    row = secevents.SecurityEventLog._row(
        event, "cli", None, None, None, "cli", {**details, "kind": "cli"})
    row["count"] = 1
    row["agg_key"] = None
    conn.execute(
        f"INSERT INTO security_events ({', '.join(_EVENT_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)})",
        tuple(row.get(c) for c in _EVENT_COLUMNS))


def _forget_history(conn, addresses=None) -> None:
    """Drop the escalation history of the given addresses (all when None), when the table exists."""
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ip_ban_history'").fetchone():
        return
    if addresses is None:
        conn.execute("DELETE FROM ip_ban_history")
    else:
        conn.executemany("DELETE FROM ip_ban_history WHERE ip_address = ?", [(a,) for a in addresses])


def _delete(conn, rows, event_details: dict, forget=None) -> None:
    """Delete the rows and record the security event in one transaction.
    `forget` is the list of addresses whose escalation history goes too (None: all of it)."""
    conn.executemany("DELETE FROM blocked_ips WHERE id = ?", [(r["id"],) for r in rows])
    _forget_history(conn, forget)
    _record_event(conn, event_details)
    conn.commit()


def _after_note(removed: int) -> None:
    if removed:
        print("Restart the portal if it is running: it keeps its block list in memory.")


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
            _forget_history(conn, [want])
            conn.commit()
            print(f"No database block found for {want}.")
            _after_note(0)
            return 1
        _delete(conn, rows, {"target_ip": want, "removed": len(rows)}, forget=[want])
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
            _delete(conn, rows, {"scope": "all", "removed": len(rows),
                                 "target_ips": [r["ip_address"] for r in rows[:10]]})
    finally:
        conn.close()
    print(f"Removed {len(rows)} block(s):" if rows else "There were no blocks in the database.")
    for r in rows:
        print(_describe(r))
    _after_note(len(rows))
    return 0


def cf_ranges_reset(db_path: str) -> int:
    """Delete the saved Cloudflare list so the built-in list is used at the next start."""
    conn = _connect(db_path)
    try:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settings'").fetchone()
        removed = 0
        if has_table:
            removed = conn.execute("DELETE FROM settings WHERE key = 'cf_ranges_list'").rowcount
            # A held (pending) list and a dismissal belong to the list that is being reset.
            conn.execute("DELETE FROM settings WHERE key IN ('cf_ranges_pending', 'cf_ranges_dismissed')")
        if removed:
            _record_event(conn, {"removed": removed}, event="cf_ranges_reset")
        conn.commit()
    finally:
        conn.close()
    if removed:
        print("Removed the saved Cloudflare range list. The built-in list is used from the next start.")
        print("Restart the portal if it is running: it keeps the list in memory.\n"
              "Or use Admin > Settings > Cloudflare ranges > Use the built-in list while it runs.")
    else:
        print("There was no saved Cloudflare range list in the database.")
    return 0
