"""Stream schedule: the rules that need no database (1.23.0).

A schedule entry belongs to one stream: a title, a wall-clock start in the owner's IANA time zone,
a duration and optionally a weekly recurrence. An occurrence is identified by the entry and its start
as a UTC epoch second. For a weekly entry the occurrences keep the same wall-clock time in the zone,
so the UTC instant moves by an hour when the zone changes its offset (daylight saving).

This module holds the date arithmetic, the input checks and the hand-written RFC 5545 output
(VCALENDAR, VTIMEZONE built from the zone's real transitions, text escaping, 75 octet folding, CRLF).
The standard library only (zoneinfo).
"""

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo, available_timezones

TITLE_MAX = 100
DURATION_DEFAULT = 60
DURATION_MIN = 5
DURATION_MAX = 1440
MAX_ENTRIES_PER_STREAM = 20          # entries (one-off or weekly) of one stream
MAX_ENTRIES_PER_OWNER = 60           # entries of one member over all their streams
MAX_FUTURE_RSVPS_PER_MEMBER = 200    # occurrences one member is interested in
MAX_CANCELLED_PER_ENTRY = 60         # cancelled occurrences kept per entry (older ones are forgotten)
REMINDER_LEAD_SECONDS = 600          # a reminder goes out 10 minutes before the start
GOLIVE_BEFORE_SECONDS = 15 * 60      # a go-live from 15 minutes before the start ...
GOLIVE_AFTER_SECONDS = 30 * 60       # ... to 30 minutes after it belongs to the slot
LATE_GRACE_SECONDS = 15 * 60         # an occurrence that began less than this ago still counts down ("starting now")
START_PAST_LIMIT_SECONDS = 15 * 60   # a new start may not be older than this
START_FUTURE_LIMIT_DAYS = 730
START_MAX = 4102444800               # 2100-01-01 UTC: an occurrence start named in a URL is never beyond this
FEED_TOKEN_PREFIX = "sf_"
FEED_TOKEN_RE = re.compile(r"^sf_[A-Za-z0-9_-]{43}$")
LOCAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")
WEEK = 7 * 86400


# --------------------------------------------------------------------------- zones and dates
@lru_cache(maxsize=1)
def _zones() -> frozenset:
    return frozenset(available_timezones())


def valid_tz(name) -> bool:
    return isinstance(name, str) and name in _zones() and len(name) <= 64


def parse_local(text: str) -> datetime:
    """'YYYY-MM-DDTHH:MM' as a naive wall-clock datetime. ValueError otherwise."""
    if not isinstance(text, str) or not LOCAL_RE.match(text):
        raise ValueError("start must look like 2026-12-04T21:00")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M")


def local_to_utc(local: datetime, tz: str) -> int:
    """The UTC epoch second of a wall-clock time in a zone. A time that does not exist (the hour skipped by
    a spring-forward change) is read with the offset from before the change, as zoneinfo does."""
    return int(local.replace(tzinfo=ZoneInfo(tz)).timestamp())


def utc_to_local(epoch: int, tz: str) -> datetime:
    """The wall-clock time (naive) in the zone of a UTC epoch second."""
    return datetime.fromtimestamp(epoch, ZoneInfo(tz)).replace(tzinfo=None)


def occurrence_local(entry: dict, n: int) -> datetime:
    return parse_local(entry["local_start"]) + timedelta(days=7 * n)


def occurrence_start(entry: dict, n: int) -> int:
    """The n-th occurrence (0 is the first) as a UTC epoch second."""
    return local_to_utc(occurrence_local(entry, n), entry["tz"])


def occurrence_index(entry: dict, start: int):
    """The n of the occurrence whose UTC start is `start` (0 is the first), or None when it is none of the
    entry's own occurrences. The wall-clock time the rule produces for that n is occurrence_local(entry, n)."""
    try:
        first = occurrence_start(entry, 0)
        if not entry.get("weekly"):
            return 0 if start == first else None
        guess = round((start - first) / WEEK)
        for n in (guess, guess - 1, guess + 1):
            if n >= 0 and occurrence_start(entry, n) == start:
                return n
    except (OverflowError, ValueError, OSError):
        pass
    return None


def occurrences(entry: dict, after: int, until: int, limit: int = 200) -> list:
    """UTC starts of the entry's occurrences with after <= start <= until, oldest first.
    A one-off entry has one; a weekly entry one per week at the same wall-clock time."""
    first = occurrence_start(entry, 0)
    if not entry.get("weekly"):
        return [first] if after <= first <= until else []
    n = max(0, (after - first) // WEEK - 1)
    out = []
    while len(out) < limit:
        start = occurrence_start(entry, n)
        if start > until:
            break
        if start >= after:
            out.append(start)
        n += 1
    return out


def next_occurrences(entry: dict, now: int, cancelled=(), started=(), count: int = 3,
                     grace: int = LATE_GRACE_SECONDS, horizon_days: int = 400) -> list:
    """The next occurrences that are still to come (or began within `grace` and have not been marked
    started), skipping cancelled and started ones."""
    skip = set(cancelled) | set(started)
    found = []
    for start in occurrences(entry, now - grace, now + horizon_days * 86400, limit=count + len(skip) + 2):
        if start in skip:
            continue
        found.append(start)
        if len(found) >= count:
            break
    return found


def is_occurrence(entry: dict, start: int) -> bool:
    """Whether `start` is one of the entry's own occurrences (not a made-up time). A time the date arithmetic
    cannot represent is no occurrence."""
    if not isinstance(start, int) or isinstance(start, bool) or not 0 < start <= START_MAX:
        return False
    try:
        return start in occurrences(entry, start, start, limit=2)
    except (OverflowError, ValueError, OSError):
        return False


def occurrence_covering(entry: dict, now: int, cancelled=(), started=()):
    """The occurrence a go-live at `now` belongs to: from GOLIVE_BEFORE_SECONDS before its start to
    GOLIVE_AFTER_SECONDS after it, not cancelled and not started. The nearest one wins. None otherwise."""
    skip = set(cancelled) | set(started)
    best = None
    for start in occurrences(entry, now - GOLIVE_AFTER_SECONDS, now + GOLIVE_BEFORE_SECONDS, limit=6):
        if start in skip:
            continue
        if best is None or abs(start - now) < abs(best - now):
            best = start
    return best


# --------------------------------------------------------------------------- input
def clean_title(value):
    if not isinstance(value, str):
        return None, "title must be text"
    title = " ".join(_CTRL_RE.sub(" ", value).split())
    if not title:
        return None, "title is required"
    if len(title) > TITLE_MAX:
        return None, f"title must be at most {TITLE_MAX} characters"
    return title, None


def validate_entry(data: dict, now: int, existing: dict = None):
    """(clean, error) for a create (existing None: title, start and tz are required) or an edit
    (only the fields given are checked). `clean` holds title, local_start, tz, duration_min, weekly."""
    if not isinstance(data, dict):
        return None, "Invalid JSON"
    clean = {}
    if existing is None or "title" in data:
        title, err = clean_title(data.get("title"))
        if err:
            return None, err
        clean["title"] = title
    if existing is None or "start" in data:
        try:
            local = parse_local(data.get("start"))
        except (ValueError, TypeError) as e:
            return None, str(e)
        clean["local_start"] = local.strftime("%Y-%m-%dT%H:%M")
    if existing is None or "tz" in data:
        if not valid_tz(data.get("tz")):
            return None, "tz must be an IANA time zone name such as Europe/Berlin"
        clean["tz"] = data["tz"]
    if existing is None or "duration_min" in data:
        raw = data.get("duration_min", DURATION_DEFAULT)
        if isinstance(raw, bool) or not isinstance(raw, int) or not DURATION_MIN <= raw <= DURATION_MAX:
            return None, f"duration_min must be a whole number from {DURATION_MIN} to {DURATION_MAX}"
        clean["duration_min"] = raw
    if existing is None or "recurrence" in data:
        rec = data.get("recurrence")
        if rec not in (None, "weekly"):
            return None, 'recurrence must be "weekly" or null'
        clean["weekly"] = rec == "weekly"
    if existing is not None and not clean:
        return None, "Nothing to change"
    merged = {**(existing or {}), **clean}
    if "local_start" in clean or "tz" in clean:
        start = local_to_utc(parse_local(merged["local_start"]), merged["tz"])
        # A new start may not be in the past; an edit that leaves the start alone (a zone or a title change on a
        # weekly entry whose first week is long gone) is not held to it
        if "local_start" in clean and start < now - START_PAST_LIMIT_SECONDS:
            return None, "The start is in the past"
        if start > now + START_FUTURE_LIMIT_DAYS * 86400:
            return None, f"The start is more than {START_FUTURE_LIMIT_DAYS} days away"
    return clean, None


# --------------------------------------------------------------------------- feed token
def new_feed_token() -> str:
    return FEED_TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_feed_token(token: str) -> str:
    """SHA-256 of a token that is 256 random bits: nothing to brute-force, so a plain hash is the right tool and
    the stored value reveals nothing a leaked database could use."""
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()


def feed_token_wellformed(token) -> bool:
    return isinstance(token, str) and FEED_TOKEN_RE.match(token) is not None


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# --------------------------------------------------------------------------- RFC 5545
def escape_text(text: str) -> str:
    """TEXT value escaping: backslash, semicolon, comma and line breaks."""
    t = str(text).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")
    return t.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def fold_line(line: str) -> str:
    """Fold a content line to at most 75 octets (UTF-8) per physical line, CRLF + one space between the
    parts. A multi-byte character is never split."""
    raw = line.encode("utf-8")
    if len(raw) <= 75:
        return line
    parts, current, size = [], "", 0
    limit = 75
    for ch in line:
        n = len(ch.encode("utf-8"))
        if size + n > limit:
            parts.append(current)
            current, size, limit = "", 0, 74       # a continuation line starts with the one-octet space
        current += ch
        size += n
    parts.append(current)
    return "\r\n ".join(parts)


def _fmt_local(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%S")


def _fmt_utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _fmt_offset(seconds: int) -> str:
    sign = "+" if seconds >= 0 else "-"
    seconds = abs(int(seconds))
    return f"{sign}{seconds // 3600:02d}{(seconds % 3600) // 60:02d}"


def _offset_at(epoch: int, zone: ZoneInfo) -> int:
    return int(datetime.fromtimestamp(epoch, zone).utcoffset().total_seconds())


def zone_transitions(tz: str, start_epoch: int, end_epoch: int) -> list:
    """[(utc_epoch, offset_from, offset_to, is_dst, name)] for every offset change of the zone in the range,
    found by scanning the zone's own offsets (zoneinfo exposes no rules) and bisecting to the second."""
    zone = ZoneInfo(tz)
    out = []
    step = 5 * 86400
    t = start_epoch
    prev = _offset_at(t, zone)
    while t < end_epoch:
        nxt = min(t + step, end_epoch)
        cur = _offset_at(nxt, zone)
        if cur != prev:
            lo, hi = t, nxt
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if _offset_at(mid, zone) == prev:
                    lo = mid
                else:
                    hi = mid
            local = datetime.fromtimestamp(hi, zone)
            out.append((hi, prev, cur, bool(local.dst()), local.tzname() or ""))
            prev = cur
        t = nxt
    return out


def vtimezone(tz: str, first_year: int, last_year: int) -> list:
    """The VTIMEZONE lines of a zone: one observance for the offset at the start of the range and one per
    transition up to the end of it. Every observance is explicit (a single DTSTART, no RRULE), so a client
    needs no rule parser and the offsets are exactly the ones zoneinfo gives."""
    zone = ZoneInfo(tz)
    start = int(datetime(first_year, 1, 1, tzinfo=timezone.utc).timestamp())
    end = int(datetime(last_year, 1, 1, tzinfo=timezone.utc).timestamp())
    base_off = _offset_at(start, zone)
    base = datetime.fromtimestamp(start, zone)
    lines = ["BEGIN:VTIMEZONE", f"TZID:{tz}"]

    def block(kind, onset_local, off_from, off_to, name):
        lines.extend([f"BEGIN:{kind}", f"DTSTART:{_fmt_local(onset_local)}", f"TZOFFSETFROM:{_fmt_offset(off_from)}",
                      f"TZOFFSETTO:{_fmt_offset(off_to)}", f"TZNAME:{escape_text(name)}", f"END:{kind}"])

    block("DAYLIGHT" if base.dst() else "STANDARD", datetime(first_year - 1, 1, 1), base_off, base_off,
          base.tzname() or "")
    for when, off_from, off_to, is_dst, name in zone_transitions(tz, start, end):
        onset = datetime.fromtimestamp(when + off_from, timezone.utc).replace(tzinfo=None)   # local time before the change
        block("DAYLIGHT" if is_dst else "STANDARD", onset, off_from, off_to, name)
    lines.append("END:VTIMEZONE")
    return lines


def build_calendar(items: list, host: str, now: int, name: str = "Stream schedule") -> str:
    """The text of an .ics feed. `items`: dicts with entry fields (id, title, local_start, tz, duration_min,
    weekly, updated_at), `streamer` (display name), `url` (absolute watch URL or "") and `cancelled`
    (UTC starts of cancelled occurrences). A weekly entry becomes one VEVENT with RRULE:FREQ=WEEKLY and the
    zone's VTIMEZONE: DTSTART is local time with TZID, so every week keeps its wall-clock time across a change of
    offset. A cancelled occurrence is an EXDATE in the same form. A one-off entry that is cancelled is left out."""
    zones = sorted({it["tz"] for it in items})
    now_year = datetime.fromtimestamp(now, timezone.utc).year
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Open Relay Portal//Stream schedule//EN",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH", f"X-WR-CALNAME:{escape_text(name)}"]
    for tz in zones:
        years = [parse_local(it["local_start"]).year for it in items if it["tz"] == tz]
        lines.extend(vtimezone(tz, max(min(years), now_year - 3), now_year + 9))
    for it in items:
        weekly = bool(it.get("weekly"))
        cancelled = sorted(set(it.get("cancelled") or ()))
        first = occurrence_start(it, 0)
        if not weekly and first in cancelled:
            continue
        summary = f"{it['streamer']}: {it['title']}" if it.get("streamer") else it["title"]
        lines += ["BEGIN:VEVENT", f"UID:schedule-{int(it['id'])}@{host}", f"DTSTAMP:{_fmt_utc(now)}",
                  f"LAST-MODIFIED:{_fmt_utc(int(it.get('updated_at') or now))}",
                  f"DTSTART;TZID={it['tz']}:{_fmt_local(parse_local(it['local_start']))}",
                  f"DURATION:PT{int(it['duration_min'])}M", f"SUMMARY:{escape_text(summary)}"]
        if it.get("url"):
            lines.append(f"URL:{it['url']}")
        if weekly:
            lines.append("RRULE:FREQ=WEEKLY")
            # the wall-clock time the RRULE itself produces for that week, not the local reading of the UTC
            # instant: they differ for a week whose time falls in the hour a spring-forward change skips
            ex = []
            for c in cancelled:
                n = occurrence_index(it, c)
                if n is not None:
                    ex.append(_fmt_local(occurrence_local(it, n)))
            if ex:
                lines.append(f"EXDATE;TZID={it['tz']}:" + ",".join(ex))
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    return "".join(fold_line(line) + "\r\n" for line in lines)
