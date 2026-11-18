"""Chat upload files (static/uploads/chat): which rows refer to them, and the
only code that removes them.

Rules every function here follows:
  * only plain generated names are ever considered (32 hex characters and an
    optional short extension, the shape http_chat_upload writes); anything else
    in the directory, and any URL that is not exactly that, is ignored;
  * the directory is opened once with O_NOFOLLOW (an upload folder that is
    itself a link is refused) and every file is handled by name relative to that
    descriptor with follow_symlinks=False, so a link, a directory or a file
    outside the folder can never be reached;
  * a file is unlinked only if it is a regular file.

Which rows count as a reference. Plain columns (URL_COLUMNS): `image_url` and
`attachment_url` of `chat_messages` (which also holds the pinned messages) and
`dm_messages`, and any mention of an upload URL in a user's status message, a
channel topic or description, or a stream's name and description. Encrypted free
text (TEXT_COLUMNS): message text and reply previews of chat and DM rows, and
poll questions and options; these are decrypted and searched. A file named
anywhere in these is kept, wherever in the text the URL sits. Not counted: the
logged webhook payloads (log data; a dead link there is harmless), and anything
that is not one of the listed columns. Emotes and stream thumbnails have their
own folders, avatars are colours and initials, link previews are not stored.

Reading all message text is slow, so it never runs on the event loop: scan_text_sync
runs in a worker thread on its own read-only connection. Rows written while it
runs are caught by finalize_sync, which runs in the same kind of thread, holds the
write lock (BEGIN IMMEDIATE), re-checks exactly the candidate files against the
plain columns and against the rows written since the scan, and unlinks before
releasing the lock. If any message cannot be decrypted, or the lock is not
granted, nothing is deleted.
"""

import os
import re
import sqlite3
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_DIR = Path(__file__).resolve().parent / "static" / "uploads" / "chat"
URL_PREFIX = "/static/uploads/chat/"

# An unreferenced file younger than this is never touched by the sweeper.
GRACE_SECONDS = 24 * 3600

# What http_chat_upload writes: uuid4 hex plus an optional short extension.
NAME_RE = re.compile(r"[0-9a-f]{32}(?:\.[a-z0-9]{1,10})?")
URL_RE = re.compile(re.escape(URL_PREFIX) + r"(" + NAME_RE.pattern + r")")
_STEM_IN_TEXT_RE = re.compile(re.escape(URL_PREFIX) + r"([0-9a-fA-F]{32})")

_CHUNK = 50           # stems per reference query (at most 2 bind variables each, per table)


class Undecryptable(Exception):
    """A message could not be read, so what it refers to is unknown."""


def stems_in(text) -> set:
    """Every upload file stem (32 hex, lowercased) mentioned in `text`, whatever
    surrounds it: a bare URL, a full URL, trailing punctuation, any extension."""
    if not isinstance(text, str) or URL_PREFIX not in text:
        return set()
    return {m.lower() for m in _STEM_IN_TEXT_RE.findall(text)}


def stem_of(name: str) -> str:
    return name.split(".", 1)[0]


def name_from_url(url) -> Optional[str]:
    """The file name a stored URL names, or None unless it is exactly the URL of
    one generated file in the chat upload folder."""
    if not isinstance(url, str):
        return None
    m = URL_RE.fullmatch(url)
    return m.group(1) if m else None


def open_dir(dir_path) -> Optional[int]:
    """A directory descriptor for the upload folder, or None if it is missing, is
    a symbolic link, or cannot be opened."""
    try:
        return os.open(str(dir_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None


def scan_candidates(dir_path, older_than: float):
    """Regular files with a generated name and an mtime at or before `older_than`.

    Returns (candidates, scanned) where candidates is a sorted list of
    (name, size) and scanned is the number of generated-name regular files seen,
    or None when the folder cannot be opened."""
    fd = open_dir(dir_path)
    if fd is None:
        return None
    found, scanned = [], 0
    try:
        with os.scandir(fd) as it:
            names = [e.name for e in it if NAME_RE.fullmatch(e.name)]
        for name in names:
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            scanned += 1
            if st.st_mtime <= older_than:
                found.append((name, st.st_size))
    finally:
        os.close(fd)
    found.sort()
    return found, scanned


def unlink_names(dir_path, names: Iterable[str], older_than: Optional[float] = None):
    """Unlink the named regular files in the upload folder.

    Returns (files removed, bytes removed). Names that are not generated names,
    links, directories and files newer than `older_than` (when given) are left
    alone. Synchronous on purpose: nothing can interleave between a caller's last
    reference check and these unlinks."""
    fd = open_dir(dir_path)
    if fd is None:
        return 0, 0
    files = size_total = 0
    try:
        for name in names:
            if not NAME_RE.fullmatch(name):
                continue
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    continue
                if older_than is not None and st.st_mtime > older_than:
                    continue
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                continue
            except OSError:
                continue
            files += 1
            size_total += st.st_size
    finally:
        os.close(fd)
    return files, size_total


def cutoff(now: Optional[float] = None) -> float:
    return (time.time() if now is None else now) - GRACE_SECONDS


# Plain-text columns in which an upload URL can appear. A file named in any of
# them counts as referenced; there is no finer rule, the text is not parsed
# beyond finding the URL.
URL_COLUMNS = (
    ("chat_messages", ("image_url", "attachment_url")),
    ("dm_messages", ("image_url", "attachment_url")),
    ("users", ("status_message",)),
    ("chat_channels", ("topic", "description")),
    ("user_streams", ("name", "description")),      # the stream's title is `name`
)

# Encrypted free-text columns: (table, columns, column that changes when a row is
# edited or None). They are decrypted with database.decrypt_message_strict.
TEXT_COLUMNS = (
    ("chat_messages", ("message", "reply_preview_text"), "edited_at"),
    ("dm_messages", ("message", "reply_preview_text"), "edited_at"),
    ("chat_polls", ("question", "options"), None),
)

# Rows edited this long before a scan started are checked again at the end.
_EDIT_MARGIN = timedelta(minutes=2)
_BUSY_SECONDS = 5


class TextScan:
    """What a read-only scan of every message text found, and where it stopped:
    `stems` are the files named in the rows that existed at that moment, `marks`
    the highest row id per table at that moment and `since` the time to compare
    `edited_at` with, so that rows written afterwards can be read again."""

    def __init__(self, stems: set, marks: dict, since: str):
        self.stems, self.marks, self.since = stems, marks, since


def _open(db_path, mode: str):
    uri = Path(db_path).resolve().as_uri() + "?mode=" + mode
    conn = sqlite3.connect(uri, uri=True, timeout=_BUSY_SECONDS, isolation_level=None)
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_SECONDS * 1000}")
    return conn


def column_references(conn, stems: Iterable[str]) -> set:
    """Which of `stems` are named by any plain URL column (URL_COLUMNS)."""
    wanted = sorted({s.lower() for s in stems})
    hit = set()
    for i in range(0, len(wanted), _CHUNK):
        chunk = wanted[i:i + _CHUNK]
        needles = [URL_PREFIX + s for s in chunk]
        for table, cols in URL_COLUMNS:
            clause = " OR ".join(f"instr(lower({c}), ?) > 0" for c in cols for _ in chunk)
            params = [n for _ in cols for n in needles]
            for row in conn.execute(f"SELECT {', '.join(cols)} FROM {table} WHERE {clause}", params):
                for value in row:
                    hit |= stems_in((value or "").lower())
    return hit & set(wanted)


def references_sync(db_path, stems: Iterable[str]) -> set:
    """column_references on a read-only connection of its own (worker thread)."""
    conn = _open(db_path, "ro")
    try:
        return column_references(conn, stems)
    finally:
        conn.close()


def _read_texts(conn, decrypt, query: str, params: tuple, ncols: int, label: str) -> set:
    hit = set()
    for row in conn.execute(query, params):
        for raw in row[1:1 + ncols]:
            if not raw:
                continue
            try:
                text = decrypt(raw)
            except Exception:
                raise Undecryptable(f"{label} id {row[0]}") from None
            hit |= stems_in(text)
    return hit


def scan_text_sync(db_path, decrypt) -> TextScan:
    """Every stem named in the decrypted free text of every chat message, DM and
    poll (TEXT_COLUMNS), read in one read transaction on a read-only connection
    of its own. Runs in a worker thread, never on the event loop. `decrypt` must
    raise when a stored value cannot be read (database.decrypt_message_strict);
    Undecryptable is raised then. The decrypted text is never inspected beyond
    finding upload URLs: a member can post any string, including the placeholder
    used for unreadable rows, as an ordinary message."""
    since = (datetime.now(timezone.utc) - _EDIT_MARGIN).isoformat()
    conn = _open(db_path, "ro")
    try:
        conn.execute("BEGIN")
        marks = {}
        for table, _cols, _edit in TEXT_COLUMNS:
            marks[table] = conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
        hit = set()
        for table, cols, _edit in TEXT_COLUMNS:
            hit |= _read_texts(conn, decrypt, f"SELECT id, {', '.join(cols)} FROM {table} WHERE id <= ?",
                               (marks[table],), len(cols), table)
        conn.execute("COMMIT")
    finally:
        conn.close()
    return TextScan(hit, marks, since)


def finalize_sync(db_path, dir_path, names: Iterable[str], decrypt, scan: TextScan,
                  unlink: bool, older_than: Optional[float] = None):
    """The last reference check for exactly `names`, and the unlink, inside one
    transaction that holds the database write lock (BEGIN IMMEDIATE), so no row
    can be written between the check and the unlink. In it, the plain URL columns
    are queried again for those stems (a row that still names a file, or was
    written since and names it, keeps it) and the encrypted text of the rows
    written since `scan` (new ids, or edited since) is decrypted and searched.
    Returns (names nothing refers to, files removed, bytes removed); with
    `unlink` false nothing is removed. Raises Undecryptable or sqlite3.Error
    (for example when the lock is not granted in time); then nothing is removed."""
    names = sorted(set(names))
    conn = _open(db_path, "rw")
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            used = column_references(conn, {stem_of(n) for n in names})
            for table, cols, edit in TEXT_COLUMNS:
                where, params = "id > ?", [scan.marks.get(table, 0)]
                if edit:
                    where += f" OR {edit} >= ?"
                    params.append(scan.since)
                used |= _read_texts(conn, decrypt, f"SELECT id, {', '.join(cols)} FROM {table} WHERE {where}",
                                    tuple(params), len(cols), table)
            free = [n for n in names if stem_of(n) not in used]
            files = size = 0
            if unlink and free:
                files, size = unlink_names(dir_path, free, older_than=older_than)
        finally:
            conn.execute("ROLLBACK")
    finally:
        conn.close()
    return free, files, size
