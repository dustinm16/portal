"""Security event log: every authentication and credential event.

audit_log cannot hold an unknown-user failure (its actor is a NOT NULL foreign
key), so security events live in their own table, ``security_events``, with no
foreign key to ``users``: rows outlive the account they describe.

Two write paths, chosen by event name:

* Events an outsider can trigger at will (wrong passwords, bad 2FA codes,
  probe and rate-limit trips) are *aggregated*. They are counted in memory per
  (ip, event, result, minute) and flushed in one transaction every few seconds
  and at shutdown, as an upsert on ``agg_key`` that adds to ``count``. A flood
  therefore costs one row per source per minute and a bounded number of
  writes, however many requests it sends. An IPv6 source counts as its /64, and
  one minute creates at most MINUTE_MAX_KEYS rows across all flushes: further
  sources that minute are added to one shared row per event and result.
* Successes and credential changes are written at once, but at most
  IMMEDIATE_PER_MINUTE rows per (user id or address, event) and minute: a member
  who loops a sign-in or a sign-out cannot grow the table without bound. Further
  events of that kind in the minute are counted in the aggregate buffer, one
  counted row per minute. Admin and configuration events (CAP_EXEMPT) are not
  capped: they need a staff session, and their details must not be lost.

Nothing here raises into a caller, and a database error never stops a login.
Secrets (passwords, 2FA and backup codes, tokens, API keys, invite codes) are
never passed in; ``clean_details`` also drops any detail key that looks like
one, as a second line of defence.
"""

import asyncio
import csv
import io
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# event -> category. "auth" is sign-in and session events; everything else is
# "security". The admin "Security" view shows both; "Auth" shows the first.
EVENTS = {
    "login_success": "auth",
    "login_failed": "auth",
    "2fa_required": "auth",
    "2fa_passed": "auth",
    "2fa_failed": "auth",
    "2fa_throttled": "auth",
    "backup_code_used": "auth",
    "logout": "auth",
    "session_revoked": "auth",
    "register_failed": "auth",
    "2fa_enabled": "security",
    "2fa_disabled": "security",
    "2fa_disable_failed": "security",
    "api_key_created": "security",
    "api_key_revoked": "security",
    "api_key_deleted": "security",
    "password_changed": "security",
    "password_change_failed": "security",
    "password_reset": "security",
    "user_created": "security",
    "user_deleted": "security",
    "role_changed": "security",
    "invite_created": "security",
    "invite_deactivated": "security",
    "ip_blocked": "security",
    "ip_unblocked": "security",
    "probe_block": "security",
    "never_ban_changed": "security",
    "cf_ranges_refreshed": "security",
    "cf_ranges_reset": "security",
    "cf_ranges_approved": "security",
    "cf_ranges_dismissed": "security",
    "cf_refresh_toggled": "security",
    "security_retention_changed": "security",
    "security_events_pruned": "security",
    "rate_limited": "security",
    "host_key_accepted": "security",
    "security_log_export": "security",
    "webhook_allow_private": "security",
}

# Events an outsider can cause without any credential (or with a stolen
# session, for the two "failed" ones on authenticated routes): aggregated.
AGGREGATED = frozenset({
    "login_failed", "2fa_required", "2fa_failed", "2fa_throttled",
    "register_failed", "password_change_failed", "2fa_disable_failed",
    "probe_block", "rate_limited",
})

# Admin and configuration actions. They need an authenticated staff session (or run from
# the weekly job or the command line), so a flood from outside cannot reach them, and each
# one must keep its details: they are never held to the per-minute cap and never go into
# the aggregate buffer. ip_blocked and ip_unblocked are exempt only with a user id (an
# administrator's action); without one they take the capped path like any other event.
CAP_EXEMPT = frozenset({
    "role_changed", "user_deleted", "password_reset", "never_ban_changed",
    "cf_ranges_refreshed", "cf_ranges_reset", "cf_refresh_toggled",
    "cf_ranges_approved", "cf_ranges_dismissed",
    "security_retention_changed", "security_events_pruned", "security_log_export",
    "webhook_allow_private",
})
CAP_EXEMPT_WITH_USER = frozenset({"ip_blocked", "ip_unblocked"})

CATEGORIES = ("auth", "security")

# What a failed login or registration stores when the typed name is not an account:
# people paste passwords into the user name box, so the typed text is never kept.
UNKNOWN_ACCOUNT = "(unknown account)"
USERNAME_MAX = 64
USER_AGENT_MAX = 200
RESULT_MAX = 32
DETAILS_MAX = 1000
DETAIL_VALUE_MAX = 200
BUFFER_MAX_KEYS = 2000          # distinct (ip, event, result, minute) kept in memory
MINUTE_MAX_KEYS = 300           # distinct aggregate rows one minute may create, across flushes
MINUTES_TRACKED = 3             # how many recent minutes keep their key set
FLUSH_INTERVAL = 5.0            # seconds between flushes of the aggregate buffer
IMMEDIATE_TIMEOUT = 2.0         # most a caller waits for an immediate write
IMMEDIATE_PER_MINUTE = 30       # immediate rows per (user id or address, event) and minute
IMMEDIATE_MAX_KEYS = 5000       # distinct such keys remembered for the current minute
EXPORT_MAX_ROWS = 50000
EXPORT_PAGE = 500
OVERFLOW_IP = "*"

# Control characters, line and paragraph separators (U+2028, U+2029), zero-width
# characters (U+200B-U+200F, U+FEFF) and bidi overrides and isolates (U+202A-U+202E,
# U+2066-U+2069): none of them may reach a row, the admin table or an export.
_CONTROL_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
# Detail keys that must never carry a value, whatever a caller passes.
_CLEAN_SLICE_FACTOR = 4
_SECRET_KEY_RE = re.compile(
    r"pass|secret|totp|code|jwt|bearer|hash|credential|authorization|cookie|^token$|^key$|api_?key$|private",
    re.IGNORECASE,
)


def clean_text(value, limit: int) -> Optional[str]:
    """A bounded one-line string: control characters removed, cut to ``limit``."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    # Cut before the regex pass: a multi-megabyte value must not cost a full
    # scan. A few times the limit leaves room for the characters removed.
    value = value[:limit * _CLEAN_SLICE_FACTOR]
    value = _CONTROL_RE.sub("", value)
    return value[:limit]


def clean_details(details) -> Optional[str]:
    """JSON text for the details column: scalar values, bounded, no secret-looking keys."""
    if not details or not isinstance(details, dict):
        return None
    out = {}
    for key, value in details.items():
        key = clean_text(key, 40)
        if not key or _SECRET_KEY_RE.search(key):
            continue
        if isinstance(value, (bool, int, float)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            out[key] = [clean_text(v, DETAIL_VALUE_MAX) for v in list(value)[:20]]
        else:
            out[key] = clean_text(value, DETAIL_VALUE_MAX)
    if not out:
        return None
    text = json.dumps(out, separators=(",", ":"), ensure_ascii=True)
    if len(text) > DETAILS_MAX:
        text = json.dumps({"truncated": True}, separators=(",", ":"))
    return text


def aggregate_ip(ip: str) -> str:
    """The source an aggregated row is counted under.

    An IPv6 address is grouped to its /64 (one subscriber holds that many
    addresses and can rotate through them freely), written as ``prefix/64``.
    IPv4, an IPv4-mapped IPv6 address and anything that is not an address
    (``unknown``) stay as they are.
    """
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network((addr, 64), strict=False))
    return str(addr)


def ip_filter_values(text: str) -> list:
    """The ``ip`` column values an admin's typed address or network should match.

    An aggregated row from an IPv6 source is stored as its /64 (``aggregate_ip``),
    so a full IPv6 address also matches that /64, next to its own immediate rows.
    A typed network is matched in its canonical written form (a typed /64 finds
    the aggregated row). Anything else (``unknown``, ``*``) is matched as typed.
    """
    text = (text or "").strip()
    values = [text]
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        try:
            values.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError:
            pass
    else:
        values.append(str(addr))
        values.append(aggregate_ip(text))
    return list(dict.fromkeys(values))


def _clock() -> float:
    """The time the per-minute cap counts in (replaced in tests)."""
    return time.time()


def now_ts(now: Optional[float] = None) -> str:
    """UTC timestamp in the one format this table uses (and every cutoff and filter)."""
    dt = datetime.fromtimestamp(time.time() if now is None else now, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_bound(text: str, end: bool = False) -> str:
    """Normalise a since/until filter to the stored timestamp format.

    Accepts YYYY-MM-DD (an ``until`` date covers that whole day), a space or T
    separated date and time, and an optional Z or numeric UTC offset.
    Raises ValueError for anything else.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text + (" 23:59:59" if end else " 00:00:00")
    iso = text.replace(" ", "T", 1)
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def user_agent_of(request) -> Optional[str]:
    try:
        return clean_text(request.headers.get("User-Agent"), USER_AGENT_MAX)
    except Exception:
        return None


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

CSV_COLUMNS = ("id", "ts", "event", "category", "user_id", "username_tried", "ip",
               "user_agent", "result", "count", "details")


def csv_cell(value):
    """A CSV cell that a spreadsheet will not run as a formula.

    Text starting with = + - @ tab (or carriage return) gets a leading
    apostrophe. Numbers and None pass through.
    """
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def csv_line(values) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\r\n").writerow([csv_cell(v) for v in values])
    return buf.getvalue()


def row_values(row: dict) -> list:
    return [row.get(c) for c in CSV_COLUMNS]


# --------------------------------------------------------------------------
# The writer
# --------------------------------------------------------------------------

class SecurityEventLog:
    """Aggregate buffer plus the immediate-write path, over one Database."""

    def __init__(self, database=None):
        self._db = database
        self._agg: dict = {}
        # minute -> agg keys that minute has created; survives flushes so the
        # cap below limits rows written per minute, not just keys per flush.
        self._minute_keys: dict = {}
        # (minute, who, event) -> immediate rows written; only the current minute is kept.
        self._immediate_minute: str = ""
        self._immediate_counts: dict = {}
        self._task: Optional[asyncio.Task] = None
        self._flush_lock: Optional[asyncio.Lock] = None
        self.dropped = 0          # rows lost to a failed flush that could not be re-queued

    def bind(self, database) -> None:
        self._db = database

    # -- building a row -----------------------------------------------------

    @staticmethod
    def _row(event, ip, user_agent, user_id, username, result, details, ts=None) -> dict:
        return {
            "ts": ts or now_ts(),
            "event": event,
            "category": EVENTS.get(event, "security"),
            "user_id": user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else None,
            "username_tried": clean_text(username, USERNAME_MAX),
            "ip": clean_text(ip, 64) or "unknown",
            "user_agent": clean_text(user_agent, USER_AGENT_MAX),
            "result": clean_text(result, RESULT_MAX),
            "details": clean_details(details),
        }

    # -- aggregated path (synchronous, no I/O) --------------------------------

    def note(self, event: str, *, ip=None, user_agent=None, user_id=None, username=None,
             result=None, details=None, now: Optional[float] = None) -> None:
        """Count one attacker-triggered event. Never raises, never touches the database."""
        try:
            row = self._row(event, ip, user_agent, user_id, username, result, details,
                            ts=now_ts(now))
            minute = row["ts"][:16]
            row["ip"] = aggregate_ip(row["ip"])
            key = (row["ip"], event, row["result"] or "", minute)
            if event not in AGGREGATED and row["user_id"] is not None:
                # An event over the immediate cap (see write): two accounts behind one
                # address are counted apart, so a count is never filed under another account.
                key += (f"u{row['user_id']}",)
            entry = self._agg.get(key)
            if entry is None:
                known = self._minute_keys.get(minute)
                if known is None:
                    known = self._minute_keys[minute] = set()
                    while len(self._minute_keys) > MINUTES_TRACKED:
                        oldest = min(m for m in self._minute_keys if m != minute)
                        del self._minute_keys[oldest]
                # A key this minute already wrote only adds to its count (the
                # upsert), so it costs no new row. A new key costs one.
                if key not in known and (
                        len(known) >= MINUTE_MAX_KEYS or len(self._agg) >= BUFFER_MAX_KEYS):
                    # Many distinct sources: fold into one overflow bucket per
                    # event and result so rows per minute and memory stay bounded.
                    row["ip"] = OVERFLOW_IP
                    row["user_agent"] = None
                    row["details"] = None
                    if event not in AGGREGATED and row["user_id"] is not None:
                        # An over-cap row of a signed-in account is folded per account
                        # (still bounded: accounts times events), never into the
                        # bucket that has no actor.
                        key = (OVERFLOW_IP, event, row["result"] or "", minute, f"u{row['user_id']}")
                    else:
                        row["username_tried"] = None
                        row["user_id"] = None
                        key = (OVERFLOW_IP, event, row["result"] or "", minute)
                    entry = self._agg.get(key)
                else:
                    known.add(key)
                if entry is None:
                    entry = row
                    entry["count"] = 0
                    entry["agg_key"] = "|".join(key)
                    self._agg[key] = entry
            entry["count"] += 1
        except Exception:
            logger.debug("security event not buffered", exc_info=True)

    def pending(self) -> int:
        return sum(e["count"] for e in self._agg.values())

    # -- flushing -------------------------------------------------------------

    async def flush(self) -> int:
        """Write the buffer in one transaction. Returns rows written; never raises."""
        if not self._agg or self._db is None:
            return 0
        if self._flush_lock is None:
            self._flush_lock = asyncio.Lock()
        async with self._flush_lock:
            batch, self._agg = self._agg, {}
            if not batch:
                return 0
            try:
                await self._db.upsert_security_events(list(batch.values()))
                return len(batch)
            except Exception as e:
                logger.warning(f"[SecurityEvents] flush failed ({len(batch)} rows): {e}")
                # Put the counts back (bounded) so a passing error loses nothing.
                for key, entry in batch.items():
                    existing = self._agg.get(key)
                    if existing is not None:
                        existing["count"] += entry["count"]
                    elif len(self._agg) < BUFFER_MAX_KEYS * 2:
                        self._agg[key] = entry
                    else:
                        self.dropped += entry["count"]
                return 0

    async def _flush_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(FLUSH_INTERVAL)
                await self.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[SecurityEvents] flush loop error: {e}")

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._flush_loop())

    async def shutdown(self) -> None:
        """Stop the flusher and write what is left."""
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self.flush()

    # -- immediate path -------------------------------------------------------

    def _immediate_allowed(self, event: str, user_id, ip, minute: str) -> bool:
        """Count one immediate row for (user id or address, event) in this minute; False over the cap."""
        if minute != self._immediate_minute:
            self._immediate_minute = minute
            self._immediate_counts = {}
        who = ("u", user_id) if isinstance(user_id, int) and not isinstance(user_id, bool) \
            else ("i", clean_text(ip, 64) or "unknown")
        key = (who, event)
        used = self._immediate_counts.get(key)
        if used is None:
            if len(self._immediate_counts) >= IMMEDIATE_MAX_KEYS:
                return False            # a flood of distinct keys: aggregate rather than remember them all
            used = 0
        if used >= IMMEDIATE_PER_MINUTE:
            return False
        self._immediate_counts[key] = used + 1
        return True

    @staticmethod
    def _cap_exempt(event: str, user_id) -> bool:
        """True for an admin or configuration event that is never capped (see CAP_EXEMPT)."""
        if event in CAP_EXEMPT:
            return True
        return (event in CAP_EXEMPT_WITH_USER
                and isinstance(user_id, int) and not isinstance(user_id, bool))

    async def write(self, event: str, *, ip=None, user_agent=None, user_id=None, username=None,
                    result=None, details=None) -> None:
        """Write one event now. Never raises; waits at most IMMEDIATE_TIMEOUT."""
        try:
            if self._db is None:
                return
            now = _clock()
            if not self._cap_exempt(event, user_id) and not self._immediate_allowed(
                    event, user_id, ip, now_ts(now)[:16]):
                self.note(event, ip=ip, user_agent=user_agent, user_id=user_id, username=username,
                          result=result, details=details, now=now)
                return
            row = self._row(event, ip, user_agent, user_id, username, result, details)
            row["count"] = 1
            row["agg_key"] = None
            task = asyncio.ensure_future(self._db.insert_security_event(row))
            task.add_done_callback(_swallow)
            await asyncio.wait_for(asyncio.shield(task), IMMEDIATE_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"[SecurityEvents] could not record {event}: {type(e).__name__}")


def _swallow(task: "asyncio.Future") -> None:
    """Retrieve a background write's exception so it is not reported as unhandled."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.warning(f"[SecurityEvents] write failed: {type(exc).__name__}: {exc}")


log = SecurityEventLog()
