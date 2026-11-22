"""Personal filing of connections on the dashboard: folder, tags, open mode, pin.

Each user files the connections they can reach (their own and the ones shared with them) in
their own way; the rows live in connection_user_prefs and are never shown to anybody else.
This module holds the rules that decide what may be stored (validate) and the in-memory
guard that keeps "last opened" to one database write per user and connection per minute
(OpenThrottle), so a proxied page with hundreds of sub-requests writes once.

Managed services (the admin-defined cards on the Services tab) are not filed: they are the
same for everybody, so there is nothing personal to remember. Connections only.
"""

import json
import re
import time
from typing import Optional

FOLDER_MAX = 40
TAG_MAX = 24
TAGS_MAX = 10
OPEN_MODES = ("default", "same", "new", "embedded")
FIELDS = ("folder", "tags", "open_mode", "pinned")
BODY_MAX = 8192             # bytes of a prefs request; a larger one is refused with 413 before it is parsed

# letters and digits of any language, space, and a few separators; no control characters
_FOLDER_RE = re.compile(r"^[\w .&'()+-]+$")
_TAG_RE = re.compile(r"^[\w.+#-]+$")


def validate(body) -> tuple[Optional[dict], Optional[str]]:
    """The cleaned fields of a prefs request, or (None, message). Only the fields the
    request names are returned (an absent field keeps its stored value). folder "" means
    no folder; tags is a list of at most TAGS_MAX names, lower-cased, de-duplicated."""
    if not isinstance(body, dict):
        return None, "Invalid request"
    unknown = [k for k in body if k not in FIELDS]
    if unknown:
        return None, "Unknown field"
    if not body:
        return None, "Nothing to change"
    out = {}
    if "folder" in body:
        f = body["folder"]
        if f is None:
            f = ""
        if not isinstance(f, str):
            return None, "Folder must be text"
        f = " ".join(f.split())
        if len(f) > FOLDER_MAX:
            return None, f"Folder is longer than {FOLDER_MAX} characters"
        if f and not _FOLDER_RE.match(f):
            return None, "Folder has a character that is not allowed"
        out["folder"] = f
    if "tags" in body:
        t = body["tags"]
        if t is None:
            t = []
        if not isinstance(t, list):
            return None, "Tags must be a list"
        if len(t) > TAGS_MAX * 4:
            return None, f"At most {TAGS_MAX} tags"
        seen, tags = set(), []
        for item in t:
            if not isinstance(item, str):
                return None, "A tag must be text"
            item = item.strip().lower()
            if not item:
                continue
            if len(item) > TAG_MAX:
                return None, f"A tag is longer than {TAG_MAX} characters"
            if not _TAG_RE.match(item):
                return None, "A tag has a character that is not allowed"
            if item not in seen:
                seen.add(item)
                tags.append(item)
        if len(tags) > TAGS_MAX:
            return None, f"At most {TAGS_MAX} tags"
        out["tags"] = tags
    if "open_mode" in body:
        m = body["open_mode"]
        if not isinstance(m, str) or m not in OPEN_MODES:
            return None, "Unknown open mode"
        out["open_mode"] = m
    if "pinned" in body:
        if not isinstance(body["pinned"], bool):
            return None, "Pinned must be true or false"
        out["pinned"] = body["pinned"]
    return out, None


def decode_tags(raw) -> list:
    """The tag list of a stored value (a damaged value reads as no tags)."""
    try:
        v = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []
    return [t for t in v if isinstance(t, str)] if isinstance(v, list) else []


def describe(row, owner_pinned: bool = False) -> dict:
    """The prefs object the list API returns with an item. `row` is the stored row or None
    (nothing filed yet); an owner's older pin (user_connections.is_pinned) counts until a
    row says otherwise."""
    if row is None:
        return {"folder": "", "tags": [], "open_mode": "default",
                "pinned": bool(owner_pinned), "last_opened_at": None}
    pinned = row["pinned"]
    return {"folder": row["folder"] or "", "tags": decode_tags(row["tags"]),
            "open_mode": row["open_mode"] if row["open_mode"] in OPEN_MODES else "default",
            "pinned": bool(owner_pinned) if pinned is None else bool(pinned),
            "last_opened_at": row["last_opened_at"]}


class OpenThrottle:
    """At most one "opened" write per (user, connection) per interval.

    The slot is taken before the caller awaits anything, so a burst of concurrent
    requests lets exactly one through. The clock is injectable for tests."""

    def __init__(self, interval: float = 60.0, clock=time.monotonic, max_entries: int = 4096):
        self.interval = interval
        self.clock = clock
        self.max_entries = max_entries
        self._last: dict = {}

    def take(self, user_id: int, conn_id: int) -> bool:
        now = self.clock()
        key = (user_id, conn_id)
        last = self._last.get(key)
        if last is not None and now - last < self.interval:
            return False
        if len(self._last) >= self.max_entries:
            cutoff = now - self.interval
            self._last = {k: v for k, v in self._last.items() if v > cutoff}
            if len(self._last) >= self.max_entries:
                return False  # a flood of distinct pairs: skip rather than grow without bound
        self._last[key] = now
        return True

    def forget(self, user_id: int, conn_id: int) -> None:
        self._last.pop((user_id, conn_id), None)

    def clear(self) -> None:
        self._last.clear()
