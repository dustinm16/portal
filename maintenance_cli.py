"""Command-line removal of the global maintenance flag: `server.py maintenance-off`.

For an administrator who cannot reach the Admin page (or does not want to). It opens the
database directly with the standard library, never starts the server, never runs a migration
and never creates a missing database, and works while the server runs or is stopped: SQLite
serialises the write and the server re-reads the flag within a few seconds (it holds no
copy for longer than that), so nothing needs a restart.

The clear is recorded twice, in the same transaction: as a `maintenance_changed` security
event with the source `cli` (like the other command-line tools), and as an `audit_log` row
whose actor is the oldest superadmin account and whose actor name says it came from the
command line (the table needs an account as actor; the row has no details, which are
encrypted with a key this tool does not load). Without a superadmin account the audit row is
skipped and the event is still written.
"""

import sys

import ban_cli
from maintenance import GLOBAL_KEY

ACTOR_NAME = "(command line: server.py maintenance-off)"


def maintenance_off(db_path: str) -> int:
    """Delete the global flag. Returns the exit status (0 also when it was not set)."""
    conn = ban_cli._connect(db_path)
    try:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settings'").fetchone()
        removed = 0
        if has_table:
            removed = conn.execute("DELETE FROM settings WHERE key = ?", (GLOBAL_KEY,)).rowcount
        if removed:
            ban_cli._record_event(conn, {"change": "cleared", "scope": "global"}, event="maintenance_changed")
            has_audit = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'").fetchone()
            actor = conn.execute(
                "SELECT id FROM users WHERE role = 'superadmin' ORDER BY id LIMIT 1").fetchone() \
                if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone() else None
            if has_audit and actor:
                conn.execute(
                    "INSERT INTO audit_log (action, actor_id, actor_username, target_type, target_name) "
                    "VALUES ('maintenance.global_clear', ?, ?, 'maintenance', 'global')",
                    (actor[0], ACTOR_NAME))
        conn.commit()
    finally:
        conn.close()
    if removed:
        print("The global maintenance flag is cleared. A running portal notices within a few seconds.")
    else:
        print("The global maintenance flag was not set.")
    return 0


if __name__ == "__main__":
    sys.exit(maintenance_off(sys.argv[1]))
