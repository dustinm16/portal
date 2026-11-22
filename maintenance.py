"""Maintenance mode: the rules, with no database and no web framework.

A service or a connection is "in maintenance" while its `maintenance` flag is set and
`maintenance_until` (UTC, stored as `YYYY-MM-DDTHH:MM:SSZ`) is empty (open-ended) or still
in the future. Nothing clears an expired row: `state()` compares the stored time with the
clock every time, so an end time that has passed simply stops applying.

The global flag is one JSON value in the `settings` table (key `maintenance_global`). It
holds the same three things (message, end time) plus who set it and when.

Every function that needs "now" takes it as a parameter so tests can move the clock.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

MESSAGE_MAX = 200
# The longest an end time may lie ahead: a typo (year 2206) must not park a service for ever.
UNTIL_MAX_DAYS = 366
# Retry-After never says more than this (the page reloads itself at most this often).
RETRY_AFTER_CAP = 300
GLOBAL_KEY = "maintenance_global"
FIELDS = ("maintenance", "maintenance_until", "maintenance_message")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ​-‏‪-‮⁦-⁩﻿]")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stored(value) -> Optional[datetime]:
    """A stored end time as an aware UTC datetime, or None (empty, or unreadable: open-ended)."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        # 0001-01-01T00:00:00+05:00 and 9999-12-31T23:59:59-05:00 cannot be shown in UTC
        return None


def clean_message(value) -> Optional[str]:
    """A one-line message of at most MESSAGE_MAX characters, or None when empty.
    Raises ValueError for text that is not a string. Control characters are dropped."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("The message must be text")
    text = " ".join(_CONTROL_RE.sub(" ", value).split())
    if len(text) > MESSAGE_MAX:
        raise ValueError(f"The message is limited to {MESSAGE_MAX} characters")
    return text or None


def parse_until(value, now: Optional[datetime] = None) -> Optional[str]:
    """The stored form of an end time sent by a client. None (or an empty string) means
    open-ended. A string without an offset counts as UTC. Raises ValueError for text that is
    not a time, a time that has passed, or one more than UNTIL_MAX_DAYS ahead."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError("The end time must be a date and time")
    dt = parse_stored(value)
    if dt is None:
        raise ValueError("The end time must be a date and time such as 2026-11-23T20:00:00Z")
    now = now or utcnow()
    if dt <= now:
        raise ValueError("The end time is in the past")
    if dt > now + timedelta(days=UNTIL_MAX_DAYS):
        raise ValueError(f"The end time is more than {UNTIL_MAX_DAYS} days ahead")
    return _stamp(dt)


def parse_update(data: dict, now: Optional[datetime] = None) -> dict:
    """The column values for the maintenance fields present in a request body (a dict of
    maintenance, maintenance_until, maintenance_message), validated. Empty when the body has none
    of the fields. Turning maintenance off clears the end time and the message. Raises ValueError
    with a message for the client."""
    if not any(k in data for k in FIELDS):
        return {}
    flag = data.get("maintenance")
    if "maintenance" in data and not isinstance(flag, bool):
        raise ValueError("maintenance must be true or false")
    if "maintenance" in data and not flag:
        return {"maintenance": 0, "maintenance_until": None, "maintenance_message": None}
    out = {}
    if "maintenance" in data:
        out["maintenance"] = 1
    if "maintenance_until" in data:
        out["maintenance_until"] = parse_until(data["maintenance_until"], now)
    elif flag:
        # Turning it on without an end time is open-ended: an old end time must not linger.
        out["maintenance_until"] = None
    if "maintenance_message" in data:
        out["maintenance_message"] = clean_message(data["maintenance_message"])
    return out


def state(row: Optional[dict], now: Optional[datetime] = None) -> Optional[dict]:
    """None when the row is not in maintenance now; else {"until": datetime or None, "message": str}.
    An end time that has passed means no maintenance (no clean-up needed)."""
    if not row or not row.get("maintenance"):
        return None
    until = parse_stored(row.get("maintenance_until"))
    if row.get("maintenance_until") and until is None:
        # An end time that cannot be read must not park the service for ever by accident: an
        # unreadable value ends the maintenance. (The API never writes one.)
        return None
    now = now or utcnow()
    if until is not None and until <= now:
        return None
    return {"until": until, "message": row.get("maintenance_message") or ""}


def public_fields(row: dict, now: Optional[datetime] = None) -> dict:
    """The maintenance fields for an API answer: a real boolean, the end time and message, and
    `maintenance_active` (the flag set and the end time still ahead)."""
    st = state(row, now)
    return {
        "maintenance": bool(row.get("maintenance")),
        "maintenance_until": row.get("maintenance_until") or None,
        "maintenance_message": row.get("maintenance_message") or None,
        "maintenance_active": st is not None,
    }


def retry_after(until: Optional[datetime], now: Optional[datetime] = None) -> int:
    """Seconds to wait: the time left, at least 1 and at most RETRY_AFTER_CAP; the cap when open-ended."""
    if until is None:
        return RETRY_AFTER_CAP
    now = now or utcnow()
    return max(1, min(RETRY_AFTER_CAP, int((until - now).total_seconds()) + 1))


def describe_until(until: Optional[datetime], now: Optional[datetime] = None) -> str:
    """"Down for maintenance until 20:00 UTC" (the date is added when it is not today, UTC)."""
    if until is None:
        return "Down for maintenance"
    now = now or utcnow()
    if until.date() == now.astimezone(timezone.utc).date():
        return f"Down for maintenance until {until:%H:%M} UTC"
    return f"Down for maintenance until {until:%Y-%m-%d %H:%M} UTC"


# --- the global flag -------------------------------------------------------

def encode_global(message, until_stored: Optional[str], set_by: str, now: Optional[datetime] = None) -> str:
    return json.dumps({
        "message": message or "",
        "until": until_stored,
        "set_by": set_by,
        "set_at": _stamp(now or utcnow()),
    })


def decode_global(raw) -> Optional[dict]:
    """The stored global flag as a dict, or None (absent or unreadable)."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {
        "message": str(data.get("message") or "")[:MESSAGE_MAX],
        "until": data.get("until") if isinstance(data.get("until"), str) else None,
        "set_by": str(data.get("set_by") or "")[:80],
        "set_at": data.get("set_at") if isinstance(data.get("set_at"), str) else None,
    }


def global_state(flag: Optional[dict], now: Optional[datetime] = None) -> Optional[dict]:
    """Same shape as state(): None when the flag is absent or its end time has passed."""
    if not flag:
        return None
    return state({"maintenance": 1, "maintenance_until": flag.get("until"),
                  "maintenance_message": flag.get("message")}, now)
