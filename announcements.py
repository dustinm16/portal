"""Admin announcements: validation and the "active now" rule, with no database and no web framework.

An announcement has a level (info, warning, outage), a body of plain text (the page shows a small
safe subset of markup, built with DOM nodes: **bold**, *italic*, `code`, [text](http or https link),
bare http and https links and line breaks; the server stores the text exactly as written, apart from
control characters) and an optional start and end time (UTC text `YYYY-MM-DDTHH:MM:SSZ`). It is
active while now is at or after the start (when set) and before the end (when set); nothing has to
run to end one. `show_before_signin` (default off) is the only way its text reaches a signed-out visitor.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

LEVELS = ("info", "warning", "outage")
BODY_MAX = 1000
MAX_ROWS = 200
# A start or end more than this far ahead is a typo.
HORIZON_DAYS = 3 * 366

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ​-‏‪-‮⁦-⁩﻿]")


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_stamp(now: Optional[datetime] = None) -> str:
    return _stamp(now or datetime.now(timezone.utc))


def _parse_time(value, field: str, now: datetime) -> Optional[str]:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a date and time")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"{field} must be a date and time such as 2026-11-23T20:00:00Z")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if dt > now + timedelta(days=HORIZON_DAYS):
        raise ValueError(f"{field} is too far ahead")
    if dt < now - timedelta(days=HORIZON_DAYS):
        raise ValueError(f"{field} is too far back")
    return _stamp(dt)


def clean_body(value) -> str:
    """The body as stored: control characters (not line breaks) removed, trimmed. Raises ValueError."""
    if not isinstance(value, str):
        raise ValueError("The text is required")
    text = _CONTROL_RE.sub("", value.replace("\r\n", "\n").replace("\r", "\n")).strip()
    if not text:
        raise ValueError("The text is required")
    if len(text) > BODY_MAX:
        raise ValueError(f"The text is limited to {BODY_MAX} characters")
    return text


def parse(data: dict, *, existing: Optional[dict] = None, now: Optional[datetime] = None) -> dict:
    """The validated column values for a create (existing None: level and body required) or an edit
    (only the fields present). Raises ValueError with a message for the client."""
    now = now or datetime.now(timezone.utc)
    unknown = sorted(str(k) for k in data if k not in ("level", "body", "starts_at", "ends_at", "show_before_signin"))
    if unknown:
        raise ValueError(f"Unknown field: {unknown[0][:40]}")
    out = {}
    if "level" in data or existing is None:
        level = data.get("level", "info")
        if level not in LEVELS:
            raise ValueError("level must be info, warning or outage")
        out["level"] = level
    if "body" in data or existing is None:
        out["body"] = clean_body(data.get("body"))
    if "starts_at" in data:
        out["starts_at"] = _parse_time(data["starts_at"], "starts_at", now)
    if "ends_at" in data:
        end = _parse_time(data["ends_at"], "ends_at", now)
        if end is not None and (existing is None or end != (existing or {}).get("ends_at")) \
                and end <= _stamp(now):
            raise ValueError("ends_at is in the past (use End now to end an announcement)")
        out["ends_at"] = end
    if "show_before_signin" in data:
        if not isinstance(data["show_before_signin"], bool):
            raise ValueError("show_before_signin must be true or false")
        out["show_before_signin"] = 1 if data["show_before_signin"] else 0
    start = out.get("starts_at", (existing or {}).get("starts_at"))
    end = out.get("ends_at", (existing or {}).get("ends_at"))
    if start and end and end <= start:
        raise ValueError("ends_at must be after starts_at")
    return out


def status(row: dict, now: Optional[datetime] = None) -> str:
    """"active", "scheduled" (starts later) or "ended"."""
    stamp = now_stamp(now)
    if row.get("ends_at") and row["ends_at"] <= stamp:
        return "ended"
    if row.get("starts_at") and row["starts_at"] > stamp:
        return "scheduled"
    return "active"


def member_view(row: dict) -> dict:
    """What a signed-in member (or a visitor, for a show-before-sign-in one) is told: the text and the
    time of its last change (the page remembers a dismissal by id and that time)."""
    return {"id": row["id"], "level": row["level"], "body": row["body"],
            "updated_at": row.get("updated_at") or row.get("created_at"), "ends_at": row.get("ends_at")}


def admin_view(row: dict, now: Optional[datetime] = None) -> dict:
    out = dict(member_view(row))
    out.update({"starts_at": row.get("starts_at"), "show_before_signin": bool(row.get("show_before_signin")),
                "created_by": row.get("created_by"), "created_at": row.get("created_at"),
                "status": status(row, now), "body_max": BODY_MAX})
    return out
