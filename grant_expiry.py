"""Expiry of connection shares and service grants.

A share or grant row may carry `expires_at` (UTC, "YYYY-MM-DD HH:MM:SS", the same
text SQLite's CURRENT_TIMESTAMP writes). NULL means it never expires, exactly as
before the column existed.

Everything that turns such a row into access goes through live_sql(), the one
"is this row live" predicate, bound to now() so the cut-off is the clock and not
the sweeper: a row whose time has passed is refused the moment it passes, and the
sweeper only deletes it afterwards (and closes what depended on it).

Durations come from the DURATIONS allow-list below; the server turns the chosen
key into a timestamp, a client never sends one.
"""

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

# duration key -> seconds (None = never expires)
DURATIONS: dict = {
    "1h": 3600,
    "8h": 8 * 3600,
    "1d": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "never": None,
}

# What an API call that omits the field gets when there is no share or grant yet (kept for
# compatibility: before expiry existed every share and grant was permanent). When a live
# row already exists, an omitted field keeps its end time (see the add_* functions of the
# database layer). The dialogs preselect UI_DEFAULT for a new share and "keep" for an
# existing one.
API_DEFAULT = "never"
UI_DEFAULT = "30d"

_FMT = "%Y-%m-%d %H:%M:%S"

# Tests move time by setting this; None means the real clock.
_clock: Optional[Callable[[], datetime]] = None


def set_clock(clock: Optional[Callable[[], datetime]]) -> None:
    global _clock
    _clock = clock


def now() -> datetime:
    return _clock() if _clock is not None else datetime.now(timezone.utc)


def fmt(moment: datetime) -> str:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime(_FMT)


def now_str() -> str:
    return fmt(now())


def live_sql(alias: str) -> str:
    """The one predicate: SQL text for "the row aliased `alias` is not expired".

    It has one `?` placeholder; bind live_param() to it."""
    return f"({alias}.expires_at IS NULL OR {alias}.expires_at > ?)"


def live_param() -> str:
    return now_str()


def duration_from_body(data) -> Optional[str]:
    """The duration key a request asks for; None when the field is missing or null, which
    means "keep the end time of an existing row, never for a new one".

    Raises ValueError (message safe to return) for an unknown key, a non-string
    value, or a body that carries a timestamp of its own."""
    if not isinstance(data, dict):
        raise ValueError("Invalid body")
    if "expires_at" in data:
        raise ValueError("Send a duration (expires_in), not a timestamp")
    value = data.get("expires_in")
    if value is None:
        return None
    if not isinstance(value, str) or value not in DURATIONS:
        raise ValueError("Unknown duration; use one of: " + ", ".join(DURATIONS))
    return value


def expires_at_for(duration: Optional[str]) -> Optional[str]:
    """The timestamp text stored for a duration key (None for "never"; a missing duration
    is API_DEFAULT, the value for a row that does not exist yet)."""
    if duration is None:
        duration = API_DEFAULT
    seconds = DURATIONS[duration]
    if seconds is None:
        return None
    return fmt(now() + timedelta(seconds=seconds))


def parse(expires_at: Optional[str]) -> Optional[datetime]:
    if not expires_at:
        return None
    try:
        return datetime.strptime(str(expires_at)[:19], _FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def describe(expires_at: Optional[str]) -> dict:
    """API fields for a stored expiry: ISO time with Z and the seconds left,
    both None for a row that never expires (clients never parse the stored text)."""
    moment = parse(expires_at)
    if moment is None:
        return {"expires_at": None, "expires_in": None}
    return {
        "expires_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_in": max(0, int((moment - now()).total_seconds())),
    }
