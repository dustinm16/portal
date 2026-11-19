"""Ops, security and moderation alert events.

One place decides whether an alert may be sent, so that no bug elsewhere can flood a
channel. server.py binds the delivery functions at start (``bind``); until then (a
command-line run, a test) every emitter does nothing.

What an alert is:

* A title and a one-line summary (the default payload, see webhook_formats). Account
  names may appear in the summary of an admin or moderation event. IP addresses, user
  agents, rule names and free text (reasons) go into ``details`` only, which a hook
  receives only with include_details. A member who posts anonymously is never named in a
  moderation or automod alert: the summary says "an anonymous member" and no id or
  name is put in the details either.
* Delivered to system webhooks that list the event by name (nothing is subscribed by
  default, and ``*`` does not include an alert), and optionally as an in-portal
  notification to the administrators (a per-event setting, ``NOTIFY_DEFAULTS``).

Every emitter has a cooldown or a transition rule, and all of them share one safety cap:
at most ``CAP_ALERTS`` alerts in ``CAP_WINDOW`` seconds over all events, then one
"alerts suppressed" alert (counted in the window like any other, but never refused by a cap itself)
and silence until the window has room again. Whenever anything is held back a notice is due: the first is
sent ``NOTICE_DELAY`` seconds after the first refusal, then at most one per ``NOTICE_INTERVAL``; each
names every kind held back since the previous notice with its count and why (the global limit, the
reserve, a per-kind limit, or a receiver that asked to slow down and so had alerts dropped), then clears those counts. There is no per-trip state a refusal could
extend, so a member who keeps one cap tripped cannot keep later refusals from being reported. Events that a stranger or an ordinary member can trigger have a
smaller cap of their own (``SUB_CAPS``), so they can never use up the room the other alerts
need: failed sign-in bursts and automatic blocks (strangers), and moderation actions, automod
hits (any member, ``BUCKET_OF``: one shared bucket), new API keys and turned-off two-factor
sign-in (any member, a bucket each, so that moderation cannot hold back an account-security alert).
Those sub-caps apply only to alerts caused by non-staff actors. An alert whose actor is a
moderator, admin or superadmin, or whose subject is a staff account, and every operations alert,
bypasses them and is limited by its own cooldown or transition rule and the global cap. The
global cap also keeps a reserve (``MEMBER_RESERVE`` of the ``CAP_ALERTS``) that an alert subject
to a sub-cap can never use. The one exception is a failed sign-in burst against a staff account name (a
stranger can set it off): it may use at most ``STAFF_BURST_RESERVE_USE`` of the reserved slots.

``emit`` never blocks and never raises: it schedules the delivery as a background task
whose errors are logged. A failure to deliver an alert cannot break the action that
caused it.
"""

import asyncio
import json
import logging
import math
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Callable, Optional

import secevents
import webhook_formats

logger = logging.getLogger(__name__)

# group -> (label, events). The admin page offers these as event groups.
GROUPS = {
    "security": ("Security", (
        "auth.login_failed_burst", "2fa.disabled", "apikey.created", "role.changed", "ip.blocked")),
    "operations": ("Operations", (
        "update.available", "service.health_changed", "cert.expiring", "cert.renewal_failed",
        "gameserver.crashed", "backup.ok", "backup.failed", "alerts.suppressed")),
    "moderation": ("Moderation", ("moderation.action", "automod.triggered")),
}
GROUP_OF = {name: group for group, (_label, names) in GROUPS.items() for name in names}
EVENT_NAMES = frozenset(GROUP_OF)
assert EVENT_NAMES == webhook_formats.ALERT_EVENTS, "alerts.GROUPS and webhook_formats.ALERT_EVENTS differ"

# In-portal notification default per event (a setting overrides it): on for the security and
# operations alerts, off for backup.ok (routine) and for the moderation group (frequent).
NOTIFY_OFF_BY_DEFAULT = frozenset({"backup.ok", "moderation.action", "automod.triggered"})
NOTIFY_SETTING_PREFIX = "alert_notify_"

# Cooldown in seconds per (event, key). The burst, block, health and certificate rules
# below add their own transition rules on top.
COOLDOWNS = {
    "auth.login_failed_burst": 600.0,
    "2fa.disabled": 60.0,
    "apikey.created": 60.0,
    "role.changed": 60.0,
    "ip.blocked": 60.0,
    "update.available": 0.0,           # once per version, kept in a setting
    "service.health_changed": 60.0,
    "cert.expiring": 0.0,              # once per threshold and serial, kept in a setting
    "cert.renewal_failed": 3600.0,
    "gameserver.crashed": 600.0,
    "backup.ok": 3600.0,
    "backup.failed": 3600.0,
    "moderation.action": 60.0,
    "automod.triggered": 60.0,
    "alerts.suppressed": 0.0,
}
SEVERITY = {
    "auth.login_failed_burst": "warning", "2fa.disabled": "warning", "apikey.created": "notice",
    "role.changed": "warning", "ip.blocked": "notice", "update.available": "notice",
    "service.health_changed": "warning", "cert.expiring": "warning", "cert.renewal_failed": "critical",
    "gameserver.crashed": "warning", "backup.ok": "info", "backup.failed": "warning",
    "moderation.action": "info", "automod.triggered": "info", "alerts.suppressed": "warning",
}

CAP_ALERTS = 30
CAP_WINDOW = 600.0
# Smaller caps, in the same window, for what an unauthenticated actor (failed sign-ins, probes
# that get blocked) or any member can set off. They are counted per bucket, which is the event
# name unless BUCKET_OF or the emitter names another. With these, at least CAP_ALERTS minus their
# sum (20) minus the one notice (9 slots) stays free for everything else.
MEMBER_BUCKET = "member"
SUB_CAPS = {
    "auth.login_failed_burst": 5,
    "ip.blocked:auto": 5,
    MEMBER_BUCKET: 5,
    # Account-security signals have a bucket each, apart from moderation and automod: a member
    # who bans raiders from their own stream chat must not be able to silence the alert for a
    # turned-off two-factor sign-in, and creating API keys must not silence it either.
    "2fa.disabled": 3,
    "apikey.created": 2,
}
# Events any signed-in member can set off, with or without a role: a stream owner bans from
# their own stream chat, any message can hit an automod rule. These two share one bucket.
# A new API key and a turned-off two-factor sign-in are within reach of every member too, but
# each has a bucket of its own (SUB_CAPS) and a cooldown per account.
BUCKET_OF = {
    "moderation.action": MEMBER_BUCKET,
    "automod.triggered": MEMBER_BUCKET,
}
# Of the CAP_ALERTS slots of the window, this many can never be used by an alert that is subject
# to a sub-cap (one caused by a non-staff actor): an alert of that kind is held back once
# CAP_ALERTS - MEMBER_RESERVE slots are used, so a staff alert or an operations alert still
# has room however many members act.
MEMBER_RESERVE = 10
# A notice is sent this long after the first alert is held back, so that it can say what was held back,
# and then at most once per NOTICE_INTERVAL.
NOTICE_DELAY = 30.0
NOTICE_INTERVAL = 600.0
# A notice that a hook could not take (the hook is paused by a 429 or over its rate limit) is
# sent again once that pause ends, with its counts put back; at most this many times in a row,
# and never later than this many seconds after the refusal.
NOTICE_RETRY_MAX = 5
NOTICE_RETRY_LIMIT = 900.0
# Staff-subject sign-in bursts (a stranger can set one off by guessing a staff account name) have no
# sub-cap of the ordinary kind, but may use at most this many of the MEMBER_RESERVE reserved slots per
# window (they are held back once CAP_ALERTS - MEMBER_RESERVE + this many slots are used), so the rest
# of the reserve stays for operations alerts and staff-actor alerts.
STAFF_BURST_BUCKET = "auth.login_failed_burst:staff"
STAFF_BURST_RESERVE_USE = 5
STAFF_ROLES = frozenset(("moderator", "admin", "superadmin"))
STAFF_REFRESH = 30.0
COOLDOWN_MAX_KEYS = 2000

BURST_THRESHOLD = 5                # failures ...
BURST_WINDOW = 60.0                # ... within this many seconds, per address or per account
BURST_MAX_KEYS = 2000

AUTO_BLOCK_WINDOW = 60.0           # automatic blocks are reported once per this window, with a count
AUTO_BLOCK_ADDRESSES = 5           # addresses named in the details of one such alert

DETAIL_LIMIT = 200
SUMMARY_LIMIT = 300

_sleep = asyncio.sleep             # replaceable in tests


def _clock() -> float:
    """Monotonic time the cooldowns count in (replaced in tests)."""
    return time.monotonic()


def _wall() -> datetime:
    """Wall-clock time for the certificate rule (replaced in tests)."""
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Binding
# --------------------------------------------------------------------------

_fire: Optional[Callable] = None            # async (event, payload) -> None
_notify: Optional[Callable] = None          # async (event, title, summary) -> None
_get_setting: Optional[Callable] = None     # async (key) -> str | None
_set_setting: Optional[Callable] = None     # async (key, value) -> None
_tasks: set = set()


def bind(*, fire: Callable, notify: Optional[Callable] = None, get_setting: Optional[Callable] = None,
         set_setting: Optional[Callable] = None) -> None:
    global _fire, _notify, _get_setting, _set_setting
    _fire, _notify, _get_setting, _set_setting = fire, notify, get_setting, set_setting


def unbind() -> None:
    bind(fire=None)


def bound() -> bool:
    return _fire is not None


# --------------------------------------------------------------------------
# State: cooldowns, the global cap, counters
# --------------------------------------------------------------------------

_cooldowns: "OrderedDict[tuple, float]" = OrderedDict()
_sent: deque = deque()                       # times of delivered alerts (the notice too) inside the cap window
_sent_by: "dict[str, deque]" = {}            # the same per sub-cap bucket
_held: "dict[str, int]" = {}                 # alerts held back since the last notice, per event name
_held_why: "dict[str, set]" = {}             # the limits that held each kind back (WHY_TEXT keys)
_notice_scheduled = False                    # a notice is waiting to be sent
_notice_sent_at: Optional[float] = None      # when the last notice was sent
_notice_gen = 0                              # bumped by reset_state: older notice tasks do nothing
_last_notice: "Optional[tuple]" = None      # (generation, held, why) of the notice just sent, until a hook refuses it
_notice_retries = 0                          # consecutive notices a hook refused (bounded by NOTICE_RETRY_MAX)
_burst: "OrderedDict[tuple, deque]" = OrderedDict()
_auto_blocks: dict = {"count": 0, "addresses": [], "scheduled": False}
_announced: set = set()                      # (component, version) of update alerts sent since start


def reset_state() -> None:
    """Forget every cooldown, the cap and all counters (tests, and the stage-only reset route)."""
    global _notice_scheduled, _notice_sent_at, _notice_gen, _staff_at, _last_notice, _notice_retries
    _cooldowns.clear()
    _held.clear()
    _held_why.clear()
    _staff_ids.clear()
    _staff_names.clear()
    _staff_at = None
    _sent.clear()
    _sent_by.clear()
    _burst.clear()
    _announced.clear()
    _notice_scheduled = False
    _notice_sent_at = None
    _notice_gen += 1
    _last_notice = None
    _notice_retries = 0
    _auto_blocks.update(count=0, addresses=[], scheduled=False)


def suppressed_count() -> int:
    """Alerts held back since the last notice."""
    return sum(_held.values())


def _keys_of(key) -> tuple:
    """The cooldown keys of one alert. A list means several independent keys; anything else,
    a tuple included, is ONE key (a composite such as (rule, member) must not be split)."""
    if isinstance(key, list):
        return tuple(key) or ("",)
    return (key,)


def _cooling(name: str, keys: tuple, cooldown: float, now: float) -> bool:
    """True when every key of this alert is still inside its cooldown."""
    if cooldown <= 0:
        return False
    return all(now - _cooldowns.get((name, k), -1e18) < cooldown for k in keys)


def _stamp(name: str, keys: tuple, now: float) -> None:
    for k in keys:
        ident = (name, k)
        _cooldowns.pop(ident, None)
        _cooldowns[ident] = now
    while len(_cooldowns) > COOLDOWN_MAX_KEYS:
        _cooldowns.popitem(last=False)


WHY_GLOBAL, WHY_RESERVE, WHY_KIND = "global", "reserve", "kind"
WHY_SLOW = "slow"          # not a cap: a receiver answered 429 and an alert for it was dropped


def _cap_refusal(now: float, bucket: str, capped: bool = True) -> Optional[str]:
    """None when the alert may be sent, else which limit holds it back: WHY_GLOBAL (the cap over all
    alerts), WHY_RESERVE (for an alert subject to the sub-caps: a non-staff actor, an event with a
    bucket in SUB_CAPS, the reserve is untouched) or WHY_KIND (the bucket's own cap)."""
    while _sent and now - _sent[0] >= CAP_WINDOW:
        _sent.popleft()
    if len(_sent) >= CAP_ALERTS:
        return WHY_GLOBAL
    if bucket == STAFF_BURST_BUCKET:
        return WHY_RESERVE if len(_sent) >= CAP_ALERTS - MEMBER_RESERVE + STAFF_BURST_RESERVE_USE else None
    limit = SUB_CAPS.get(bucket)
    if not capped or limit is None:
        return None
    if len(_sent) >= CAP_ALERTS - MEMBER_RESERVE:
        return WHY_RESERVE
    return WHY_KIND if _ring_full(now, bucket, limit) else None


def _ring_full(now: float, bucket: str, limit: int) -> bool:
    ring = _sent_by.get(bucket)
    if ring is None:
        return False
    while ring and now - ring[0] >= CAP_WINDOW:
        ring.popleft()
    return len(ring) >= limit


def _count_sent(now: float, bucket: Optional[str], capped: bool = True) -> None:
    _sent.append(now)
    if capped and bucket in SUB_CAPS:
        _sent_by.setdefault(bucket, deque()).append(now)


# --------------------------------------------------------------------------
# Staff accounts: who is exempt from the sub-caps
# --------------------------------------------------------------------------

_staff_ids: set = set()
_staff_names: set = set()
_staff_at: Optional[float] = None
_staff_loader: Optional[Callable] = None      # async () -> iterable of (user id, username) of staff accounts
_staff_busy = False


def set_staff(ids=(), names=()) -> None:
    """Replace the staff registry (the loader's answer; tests)."""
    global _staff_at
    _staff_ids.clear()
    _staff_ids.update(i for i in ids if i is not None)
    _staff_names.clear()
    _staff_names.update(str(n) for n in names if n)
    _staff_at = _clock()


def bind_staff(loader: Optional[Callable]) -> None:
    """Where the registry comes from: an async function returning (id, username) pairs of every
    moderator, admin and superadmin. Read again every STAFF_REFRESH seconds and after a role change.
    Until the first answer nobody counts as staff, which is the old, stricter behaviour."""
    global _staff_loader, _staff_at
    _staff_loader = loader
    _staff_at = None
    _staff_refresh_soon(force=True)


def is_staff(user_id=None, username=None, role=None) -> bool:
    if role in STAFF_ROLES:
        return True
    if user_id is not None:
        # The account is known: the id decides. Account names are case-sensitive and unique, so
        # a member named 'BOSS' is not the staff account 'boss'.
        return user_id in _staff_ids
    return bool(username) and str(username) in _staff_names


def _staff_refresh_soon(force: bool = False) -> None:
    if _staff_loader is None or _staff_busy:
        return
    if not force and _staff_at is not None and _clock() - _staff_at < STAFF_REFRESH:
        return
    _spawn(_staff_refresh())


async def _staff_refresh() -> None:
    global _staff_busy
    loader = _staff_loader
    if loader is None or _staff_busy:
        return
    _staff_busy = True
    try:
        pairs = list(await loader())
        set_staff([p[0] for p in pairs], [p[1] for p in pairs])
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning("[Alerts] could not read the staff accounts: %s", type(e).__name__)
    finally:
        _staff_busy = False


# --------------------------------------------------------------------------
# The emit helper
# --------------------------------------------------------------------------

def _clean(value, limit: int = DETAIL_LIMIT) -> str:
    return secevents.clean_text(" ".join(str(value if value is not None else "").split()), limit) or ""


def _spawn(coro) -> bool:
    try:
        task = asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        coro.close()
        return False
    _tasks.add(task)
    task.add_done_callback(_task_done)
    return True


def _task_done(task: "asyncio.Future") -> None:
    _tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.warning("[Alerts] delivery task failed: %s: %s", type(exc).__name__, exc)


def emit(name: str, *, summary: str, details: Optional[dict] = None, key="",
         cooldown: Optional[float] = None, severity: Optional[str] = None,
         record: Optional[dict] = None, local_summary: Optional[str] = None,
         bucket: Optional[str] = None, staff: bool = False,
         third_party: Optional[dict] = None, result: Optional["asyncio.Future"] = None) -> bool:
    """Admit and send one alert. Returns True when it was admitted (not held back by
    its cooldown or a cap). Synchronous, never raises, never waits.

    ``key`` (or a list of keys) names what the cooldown counts per; with a list the
    alert is held back only when all of its keys are cooling, and all are stamped. A tuple
    is a single composite key.
    ``bucket`` names the sub-cap the alert counts against when it is not the event's own.
    ``record`` names a security event to write for an alert that has none of its own
    (``{"event": ..., "details": {...}, "ip": ...}``); it is written when a cap holds the
    alert back too, so the security log stays complete. ``local_summary`` is the text of the
    in-portal notification when it may say more than a webhook may (an account name).
    ``staff`` marks an alert caused by (or about) a moderator, admin or superadmin: it does not
    count against, and is not held back by, the sub-caps or the reserve (only by the global cap).
    ``third_party`` ({"summary", "details"}) is what the non-generic formats are given instead of
    the summary and details (a private channel's name stays out of them). ``result`` is a future
    set to whether a hook was sent the alert or the in-portal notice was raised.
    """
    try:
        if _fire is None or name not in EVENT_NAMES:
            return False
        now = _clock()
        _staff_refresh_soon()
        keys = _keys_of(key)
        cd = COOLDOWNS.get(name, 0.0) if cooldown is None else cooldown
        if _cooling(name, keys, cd, now):
            # Held back by its cooldown, the event behind it is still written to the security log.
            if record:
                _spawn(_record_security_event(record))
            return False
        bucket = bucket or BUCKET_OF.get(name, name)
        capped = not staff and bucket in SUB_CAPS
        why = _cap_refusal(now, bucket, capped)
        if why:
            _hold_back(name, why, now)
            if record:
                _spawn(_record_security_event(record))
            return False
        _stamp(name, keys, now)
        _count_sent(now, bucket, capped)
        alert = _build(name, summary, details, severity)
        alert["local_summary"] = _clean(local_summary, SUMMARY_LIMIT) if local_summary else alert["summary"]
        if third_party:
            alert["third_party"] = _build_third_party(third_party)
        alert["result"] = result
        _deliver(alert)
        if record:
            _spawn(_record_security_event(record))
        return True
    except Exception as e:
        logger.warning("[Alerts] could not emit %s: %s", name, type(e).__name__)
        return False


def _hold_back(name: str, why: str, now: float) -> None:
    """Count one alert held back by a cap and make sure a notice is due."""
    global _notice_scheduled
    _held[name] = _held.get(name, 0) + 1
    _held_why.setdefault(name, set()).add(why)
    if _notice_scheduled:
        return
    delay = NOTICE_DELAY
    if _notice_sent_at is not None:
        delay = max(delay, _notice_sent_at + NOTICE_INTERVAL - now)
    _notice_scheduled = _spawn(_send_notice(delay, _notice_gen))


def note_dropped(name: str, retry_in: Optional[float] = None) -> None:
    """An alert event was dropped for a hook that is paused after a 429 ("receiver asked to slow
    down") or is over its rate limit: count it into the next "alerts held back" notice so a
    receiver cannot swallow alerts unseen. The caller counts each event once, not once per hook.

    The notice itself is never counted (it would announce itself forever). When a hook could not
    take the notice, its counts are put back and a new notice is scheduled for `retry_in` seconds
    from now (when the hook's pause ends), so the counts are not lost."""
    if name == "alerts.suppressed":
        _notice_undelivered(retry_in)
    elif name in EVENT_NAMES:
        _hold_back(name, WHY_SLOW, _clock())


def _notice_undelivered(retry_in: Optional[float]) -> None:
    """The notice just sent was refused by a hook: keep its counts and send it again once the
    hook can take it. One refusal puts the counts back once (the same notice refused by two
    hooks is one refusal); at most one retry is pending; the retries are bounded."""
    global _last_notice, _notice_retries, _notice_scheduled
    last, _last_notice = _last_notice, None
    if last is None or last[0] != _notice_gen:
        return                      # already put back, or the state was reset meanwhile
    _, held, why = last
    _notice_retries += 1
    if _notice_retries > NOTICE_RETRY_MAX:
        # A receiver that keeps refusing: give up on this notice's counts. Counts held back since
        # (never refused) are left alone.
        _notice_retries = 0
        logger.warning("[Alerts] a held-back notice was refused %d times in a row; its counts were dropped",
                       NOTICE_RETRY_MAX + 1)
        return
    for k, n in held.items():
        _held[k] = _held.get(k, 0) + n
        _held_why.setdefault(k, set()).update(why.get(k, ()))
    if _notice_scheduled:
        return                      # a notice is already pending and will carry the counts
    delay = min(max(float(retry_in or 0.0), NOTICE_DELAY), NOTICE_RETRY_LIMIT)
    _notice_scheduled = _spawn(_send_notice(delay, _notice_gen))


WHY_LABEL = {WHY_GLOBAL: "global limit", WHY_RESERVE: "reserve", WHY_KIND: "per-kind limit",
             WHY_SLOW: "receiver asked to slow down"}


def _why_sentence(why: str) -> str:
    if why == WHY_GLOBAL:
        return f"Limit of {CAP_ALERTS} alerts in {int(CAP_WINDOW // 60)} minutes reached"
    if why == WHY_RESERVE:
        return (f"Reserve reached: the last slots of the {CAP_ALERTS} in {int(CAP_WINDOW // 60)} minutes "
                "are kept for staff and operations alerts")
    if why == WHY_SLOW:
        return "A receiver asked to slow down, so alerts for it were dropped"
    return "Per-kind limit reached (a cap on what strangers or members can set off)"


async def _send_notice(delay: float, gen: int) -> None:
    """The "alerts suppressed" alert: every kind held back since the previous notice, with its count
    and the limit that held it back, then the counts are cleared."""
    global _notice_scheduled, _notice_sent_at, _last_notice, _notice_retries
    try:
        await _sleep(delay)
    except asyncio.CancelledError:
        if gen == _notice_gen:
            _notice_scheduled = False
        raise
    if gen != _notice_gen:
        return                      # the state was reset meanwhile
    _notice_scheduled = False
    if _last_notice is not None:
        _notice_retries = 0         # the previous notice was not refused by any hook
    held, why = dict(_held), {k: set(v) for k, v in _held_why.items()}
    _held.clear()
    _held_why.clear()
    if not held:
        return
    _last_notice = (gen, held, why)  # put back by note_dropped if a hook refuses this notice
    now = _clock()
    _notice_sent_at = now
    _count_sent(now, None, False)       # counted in the window, never refused by a cap
    ranked = sorted(held.items(), key=lambda kv: (-kv[1], kv[0]))
    reasons = set().union(*why.values()) if why else set()
    mixed = len(reasons) > 1

    def label(k):
        return f" ({' and '.join(WHY_LABEL[w] for w in (WHY_GLOBAL, WHY_RESERVE, WHY_KIND, WHY_SLOW) if w in why.get(k, ()))})"

    items = [f"{k}: {n}" + (label(k) if mixed else "") for k, n in ranked]
    tail = "" if mixed or not reasons else ". " + _why_sentence(next(iter(reasons)))
    _deliver(_build("alerts.suppressed", _notice_summary(items, sum(held.values()), tail),
                    {"Held back": ", ".join(items)}, None))


def _notice_summary(items, total: int, tail: str) -> str:
    """The kinds held back come first so the summary limit cuts the fixed text, not the list;
    kinds that still do not fit are given as a count."""
    head = f"Held back ({total}): "
    full = ", ".join(items)
    if len(head) + len(full) + len(tail) > SUMMARY_LIMIT:
        tail = ""       # the list matters more than the reason
    budget = SUMMARY_LIMIT - len(head) - len(tail)
    shown = []
    used = 0
    for i, item in enumerate(items):
        more = len(items) - i - 1
        extra = len(f", and {more} more kinds") if more else 0
        if used + (2 if shown else 0) + len(item) + extra > budget and shown:
            break
        used += (2 if shown else 0) + len(item)
        shown.append(item)
    rest = len(items) - len(shown)
    text = ", ".join(shown) + (f", and {rest} more kinds" if rest else "")
    return head + text + tail


def _build_third_party(tp: dict) -> dict:
    out = {"summary": _clean(tp.get("summary"), SUMMARY_LIMIT), "details": {}}
    for label, value in list((tp.get("details") or {}).items())[:webhook_formats.ALERT_DETAIL_MAX]:
        text = _clean(value)
        if text:
            out["details"][_clean(label, 40)] = text
    return out


def _build(name: str, summary: str, details: Optional[dict], severity: Optional[str]) -> dict:
    clean_details = {}
    for label, value in list((details or {}).items())[:webhook_formats.ALERT_DETAIL_MAX]:
        text = _clean(value)
        if text:
            clean_details[_clean(label, 40)] = text
    return {
        "event": name,
        "title": webhook_formats.ALERT_TITLES[name],
        "summary": _clean(summary, SUMMARY_LIMIT),
        "severity": severity if severity in webhook_formats.SEVERITY_PRIORITY else SEVERITY.get(name, "notice"),
        "group": GROUP_OF[name],
        "details": clean_details,
    }


def _deliver(alert: dict) -> None:
    _spawn(_dispatch(alert))


async def _dispatch(alert: dict) -> None:
    name = alert["event"]
    reached = False
    try:
        if _notify is not None:
            try:
                if await notify_enabled(name):
                    await asyncio.wait_for(
                        _notify(name, alert["title"], alert.get("local_summary") or alert["summary"]), 20)
                    reached = True
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("[Alerts] in-portal notification for %s failed: %s", name, type(e).__name__)
        if _fire is not None:
            try:
                payload = {k: alert[k] for k in ("title", "summary", "severity", "group", "details")}
                if alert.get("third_party"):
                    payload["third_party"] = alert["third_party"]
                sent = await asyncio.wait_for(_fire(name, payload), 30)
                if isinstance(sent, int) and not isinstance(sent, bool) and sent > 0:
                    reached = True
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("[Alerts] webhook dispatch for %s failed: %s", name, type(e).__name__)
    finally:
        fut = alert.get("result")
        if fut is not None and not fut.done():
            fut.set_result(reached)


async def _record_security_event(record: dict) -> None:
    rec = _record_hook
    if rec is not None:
        await rec(record["event"], record.get("details"), record.get("ip"))


_record_hook: Optional[Callable] = None


def bind_record(fn: Optional[Callable]) -> None:
    """Where ``record`` goes: an async (event name, details, address) writer for the security event log."""
    global _record_hook
    _record_hook = fn


# --------------------------------------------------------------------------
# Per-event in-portal notification setting
# --------------------------------------------------------------------------

def notify_setting_key(name: str) -> str:
    return NOTIFY_SETTING_PREFIX + name.replace(".", "_")


def notify_default(name: str) -> bool:
    return name not in NOTIFY_OFF_BY_DEFAULT


async def notify_enabled(name: str) -> bool:
    if _notify is None:
        return False
    default = notify_default(name)
    if _get_setting is None:
        return default
    try:
        value = await _get_setting(notify_setting_key(name))
    except Exception:
        return default
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


async def notify_settings() -> dict:
    return {name: await notify_enabled(name) for name in sorted(EVENT_NAMES)}


async def set_notify(name: str, enabled: bool) -> None:
    if name not in EVENT_NAMES or _set_setting is None:
        raise ValueError("unknown alert event")
    await _set_setting(notify_setting_key(name), "1" if enabled else "0")


def catalogue() -> list:
    """For the admin page: groups with their events, titles and defaults."""
    return [{"group": g, "label": label,
             "events": [{"event": n, "title": webhook_formats.ALERT_TITLES[n],
                         "notify_default": notify_default(n)} for n in names]}
            for g, (label, names) in GROUPS.items()]


# --------------------------------------------------------------------------
# Security-event hook: one mapping, no second call site
# --------------------------------------------------------------------------

def _who(username) -> str:
    name = secevents.clean_text(username, secevents.USERNAME_MAX) if username else ""
    return f"'{name}'" if name and name != secevents.UNKNOWN_ACCOUNT else "an account"


def on_security_event(event: str, *, ip=None, user_agent=None, user_id=None, username=None,
                      details=None, result=None) -> None:
    """Called by server.security_event for every security event, after it was recorded.
    Turns the few that are alerts into alerts; ignores everything else. Never raises."""
    try:
        if _fire is None:
            return
        details = details if isinstance(details, dict) else {}
        _staff_refresh_soon()
        if event in ("login_failed", "2fa_failed"):
            account = username if username and username != secevents.UNKNOWN_ACCOUNT else None
            note_login_failure(ip, account, user_agent=user_agent)
        elif event == "2fa_disabled":
            emit("2fa.disabled", key=user_id if user_id is not None else username or "",
                 staff=is_staff(user_id, username),
                 summary="Two-factor sign-in was turned off for an account",
                 local_summary=f"Two-factor sign-in was turned off for {_who(username)}",
                 details={"Account": username, "Address": ip, "User agent": user_agent})
        elif event == "api_key_created":
            emit("apikey.created", key=user_id if user_id is not None else "",
                 staff=is_staff(user_id, username),
                 summary="A new API key was created",
                 local_summary=f"A new API key was created by {_who(username)}",
                 details={"Created by": username, "Key name": details.get("name"), "Scopes": details.get("scopes"),
                          "Expires": details.get("expires_at"), "Address": ip})
        elif event == "role_changed":
            _staff_refresh_soon(force=True)
            target = details.get("target_username")
            # One key per target AND transition: a second, different change (user to admin, then
            # admin to superadmin) within the cooldown must still be heard.
            emit("role.changed",
                 key=("target", details.get("target_user_id"), details.get("old_role"), details.get("new_role")),
                 summary=(f"The role of {_who(target)} changed from {_clean(details.get('old_role'), 20)} "
                          f"to {_clean(details.get('new_role'), 20)}"),
                 details={"Changed by": username, "Address": ip, "Via": details.get("via")})
        elif event == "ip_blocked":
            if user_id is not None and details.get("kind") != "auto":
                emit("ip.blocked", key=("manual", details.get("target_ip")),
                     summary=(f"{_who(username)} blocked an address" if username
                              else "An administrator blocked an address"),
                     details={"Blocked address": details.get("target_ip"), "Expires": details.get("expires_at"),
                              "Reason": details.get("reason"), "Requested from": ip})
            else:
                note_auto_block(details.get("target_ip") or ip)
        elif event == "probe_block":
            note_auto_block(ip)
    except Exception as e:
        logger.debug("[Alerts] security event hook failed: %s", type(e).__name__)


# --------------------------------------------------------------------------
# Failed-sign-in bursts
# --------------------------------------------------------------------------

def note_login_failure(ip, account: Optional[str], *, user_agent=None) -> None:
    """Count one failed sign-in for its address and (when it names an existing account)
    its account. Five in a minute for either raises one alert; each key then rests for
    ten minutes. In-memory, bounded: a ring of the last BURST_THRESHOLD times per key and
    at most BURST_MAX_KEYS keys (the oldest are dropped first)."""
    if _fire is None:
        return
    now = _clock()
    keys = []
    if ip:
        keys.append(("ip", secevents.aggregate_ip(str(ip))))
    if account:
        # The exact name: account names are case-sensitive, so a member 'Boss' must not share a
        # ring or a cooldown with the staff account 'boss'.
        keys.append(("acct", str(account)[:secevents.USERNAME_MAX]))
    tripped = []
    for k in keys:
        ring = _burst.pop(k, None)
        if ring is None:
            ring = deque(maxlen=BURST_THRESHOLD)
        ring.append(now)
        _burst[k] = ring
        if len(ring) >= BURST_THRESHOLD and now - ring[0] <= BURST_WINDOW:
            tripped.append(k)
            ring.clear()
    while len(_burst) > BURST_MAX_KEYS:
        _burst.popitem(last=False)
    if not tripped:
        return
    who = account if any(k[0] == "acct" for k in tripped) else None
    # A burst against a staff account name is a staff-subject alert: no sub-cap, but then it is
    # limited by a cooldown on that account alone, so rotating addresses cannot repeat it.
    staff = bool(who) and is_staff(None, who)
    if staff:
        tripped = [k for k in tripped if k[0] == "acct"]
    # The account name is a detail for a webhook (a brute-force target is not for a chat channel);
    # the in-portal copy, which stays on the machine, names it.
    if who:
        summary = f"{BURST_THRESHOLD} failed sign-ins in a minute for one account"
        local = f"{BURST_THRESHOLD} failed sign-ins in a minute for the account '{_clean(who, 64)}'"
    else:
        summary = local = f"{BURST_THRESHOLD} failed sign-ins in a minute from one address"
    emit("auth.login_failed_burst", key=[f"{k[0]}:{k[1]}" for k in tripped], summary=summary,
         local_summary=local, staff=staff, bucket=STAFF_BURST_BUCKET if staff else None,
         details={"Address": ip, "Account": who, "User agent": user_agent},
         record={"event": "login_failed_burst", "ip": str(ip) if ip else None,
                 "details": {"threshold": BURST_THRESHOLD, "window_seconds": int(BURST_WINDOW),
                             "by": "+".join(k[0] for k in tripped)}})


# --------------------------------------------------------------------------
# Automatic blocks: one alert per minute with a count
# --------------------------------------------------------------------------

def note_auto_block(ip) -> None:
    if _fire is None:
        return
    _auto_blocks["count"] += 1
    addr = _clean(ip, 64)
    if addr and addr not in _auto_blocks["addresses"] and len(_auto_blocks["addresses"]) < AUTO_BLOCK_ADDRESSES:
        _auto_blocks["addresses"].append(addr)
    if not _auto_blocks["scheduled"]:
        _auto_blocks["scheduled"] = True
        _spawn(_auto_block_timer())


async def _auto_block_timer() -> None:
    try:
        await _sleep(AUTO_BLOCK_WINDOW)
    finally:
        flush_auto_blocks()


def flush_auto_blocks() -> bool:
    """Send the coalesced automatic-block alert, if any block was counted."""
    count, addrs = _auto_blocks["count"], list(_auto_blocks["addresses"])
    _auto_blocks.update(count=0, addresses=[], scheduled=False)
    if not count:
        return False
    word = "address was" if count == 1 else "addresses were"
    return emit("ip.blocked", key="auto", cooldown=0.0, bucket="ip.blocked:auto",
                summary=f"{count} {word} blocked automatically in the last minute",
                details={"Blocked addresses": ", ".join(addrs) + (" and more" if count > len(addrs) else "")})


# --------------------------------------------------------------------------
# Moderation and automod
# --------------------------------------------------------------------------

_MOD_VERBS = {"timeout": "timed out", "mute": "muted", "ban": "banned", "kick": "removed"}


def moderation_action(action: str, *, actor: str, target: Optional[str], anonymous: bool,
                      actor_id=None, target_id=None, channel: Optional[str] = None,
                      reason: Optional[str] = None, duration: Optional[int] = None,
                      where: Optional[str] = None, actor_anonymous: bool = False,
                      actor_role: Optional[str] = None, private: bool = False) -> bool:
    """A timeout, mute, ban or kick by a person. An anonymous target is never named: not in
    the summary, not in the details. The same goes for a moderator who is chatting anonymously.
    ``actor_role`` (or the staff registry) marks a staff actor, whose alert bypasses the sub-caps.
    ``private`` is set for a private channel, a conversation or the chat of a stream that is not
    public: the non-generic formats then get the alert without the channel or stream name."""
    if action not in _MOD_VERBS:
        return False
    who = "an anonymous member" if anonymous or not target else f"'{_clean(target, 64)}'"
    actor = "a moderator" if actor_anonymous or not actor else actor
    details = {"Channel": channel, "Reason": reason, "Duration seconds": duration, "Stream": where}
    summary = f"'{_clean(actor, 64)}' {_MOD_VERBS[action]} {who}"
    third_party = None
    if private:
        third_party = {"summary": summary + " in a private channel",
                       "details": {"Where": "a private channel", "Reason": reason, "Duration seconds": duration}}
    return emit("moderation.action", key=(actor_id, target_id, action),
                staff=is_staff(actor_id, None, actor_role), summary=summary, details=details,
                third_party=third_party)


def automod_triggered(*, rule_id, rule_name: str, rule_action: str, member: Optional[str],
                      member_id, anonymous: bool, channel: Optional[str] = None,
                      member_role: Optional[str] = None, private: bool = False) -> bool:
    """At most once per rule and member per minute. Rule names and patterns are details.
    A staff member's hit bypasses the sub-caps; ``private`` keeps the channel name from the
    non-generic formats (see moderation_action)."""
    who = "an anonymous member" if anonymous or not member else f"'{_clean(member, 64)}'"
    summary = f"An auto-moderation rule ({_clean(rule_action, 20)}) caught a message from {who}"
    third_party = None
    if private:
        third_party = {"summary": summary + " in a private channel", "details": {"Rule": rule_name}}
    return emit("automod.triggered", key=(rule_id, member_id), staff=is_staff(member_id, None, member_role),
                summary=summary, details={"Rule": rule_name, "Channel": channel}, third_party=third_party)


# --------------------------------------------------------------------------
# Updates: once per version
# --------------------------------------------------------------------------

UPDATE_STATE_KEY = "alert_update_seen"


async def note_updates(data: dict) -> int:
    """Alert for a component whose newest version was not announced before. ``data`` is the
    update checker's answer ({"portal": {...}, "mediamtx": {...}}). Returns alerts sent."""
    if _fire is None or _get_setting is None or _set_setting is None or not isinstance(data, dict):
        return 0
    try:
        seen = json.loads(await _get_setting(UPDATE_STATE_KEY) or "{}")
        if not isinstance(seen, dict):
            seen = {}
    except Exception:
        seen = {}
    sent = 0
    pending = []
    loop = asyncio.get_running_loop()
    for comp, label in (("portal", "Portal"), ("mediamtx", "MediaMTX")):
        res = data.get(comp)
        if not isinstance(res, dict) or not res.get("update_available"):
            continue
        latest = _clean(res.get("latest"), 40)
        if not latest or latest == "unknown" or seen.get(comp) == latest or (comp, latest) in _announced:
            continue
        # No await between this check and the mark below, so two overlapping checks that both
        # read an empty state cannot both announce the same version.
        fut = loop.create_future()
        if emit("update.available", key=f"{comp}:{latest}", cooldown=0.0, result=fut,
                summary=f"{label} {latest} is available",
                details={"Component": label, "Installed": res.get("current"), "Available": latest}):
            _announced.add((comp, latest))
            pending.append((comp, latest, fut))
    # A version counts as announced only when a hook was sent the alert or the in-portal notice
    # was raised; otherwise the next check tries again.
    for comp, latest, fut in pending:
        try:
            reached = await asyncio.wait_for(fut, 60)
        except Exception:
            reached = False
        if reached:
            seen[comp] = latest
            sent += 1
        else:
            _announced.discard((comp, latest))
    if sent:
        try:
            await _set_setting(UPDATE_STATE_KEY, json.dumps(seen))
        except Exception as e:
            logger.warning("[Alerts] could not save the update state: %s", type(e).__name__)
    return sent


# --------------------------------------------------------------------------
# Services and game servers
# --------------------------------------------------------------------------

def service_event(event: str, data: dict) -> None:
    """The ServiceManager's on_event hook."""
    try:
        if event == "service.health_changed":
            name = _clean(data.get("display_name") or data.get("name"), 80)
            if data.get("state") == "down":
                emit(event, key=("svc", data.get("id")), severity="warning",
                     summary=f"Service '{name}' is down",
                     details={"Service": data.get("name"), "Status": data.get("status"),
                              "Failed checks": data.get("failed_checks")})
            else:
                emit(event, key=("svc", data.get("id")), cooldown=0.0, severity="info",
                     summary=f"Service '{name}' is back up",
                     details={"Service": data.get("name"), "Status": data.get("status")})
        elif event == "gameserver.crashed":
            name = _clean(data.get("display_name") or data.get("name"), 80)
            emit(event, key=("gs", data.get("id")),
                 summary=f"Game server '{name}' stopped unexpectedly",
                 details={"Unit": data.get("unit"), "Service": data.get("name")})
    except Exception as e:
        logger.debug("[Alerts] service event failed: %s", type(e).__name__)


# --------------------------------------------------------------------------
# Certificate: daily check, thresholds, once per serial
# --------------------------------------------------------------------------

CERT_THRESHOLDS = (14, 7, 1)          # days left
CERT_STATE_KEY = "alert_cert_state"
RENEWAL_WINDOW_DAYS = 20              # certbot renews at 30 days left; still older than this is a failure


def _days_left(not_after_iso: str, now: datetime) -> float:
    na = datetime.fromisoformat(not_after_iso)
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    return (na - now).total_seconds() / 86400.0


CERT_UNREADABLE_KEY = "alert_cert_unreadable_day"


async def _cert_unreadable_notice(now: datetime) -> None:
    """The certificate file cannot be read, so its expiry is not being watched: one in-portal notice
    per day to the administrators (not a webhook alert: there is nothing about the certificate to
    report, and the in-portal copy stays on the machine)."""
    if _notify is None or _get_setting is None or _set_setting is None:
        return
    try:
        day = now.date().isoformat()
        if await _get_setting(CERT_UNREADABLE_KEY) == day:
            return
        if not await notify_enabled("cert.expiring"):
            return
        await asyncio.wait_for(_notify(
            "cert.expiring", "Certificate check failed",
            "The server certificate file could not be read, so its expiry is not being watched. "
            "Check the certificate path and permissions."), 20)
        await _set_setting(CERT_UNREADABLE_KEY, day)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning("[Alerts] could not raise the certificate-unreadable notice: %s", type(e).__name__)


async def check_certificate(cert_path: str, now: Optional[datetime] = None) -> Optional[str]:
    """Look at the served certificate file once. Returns what it did (for tests):
    None, "expiring:<days>", "renewal_failed" or both joined with ",".

    Each threshold (14, 7 and 1 days) is sent once per certificate serial: the state
    {"serial", "sent": [...]} is kept in a setting, so a restart or a repeated check says
    nothing twice, and a renewed certificate (a new serial) starts again. A certificate
    first seen with less time left than several thresholds sends the lowest one only and
    marks the higher ones sent. A Let's Encrypt certificate that is past the renewal window
    sends cert.renewal_failed once per serial: a heuristic, since the renewal itself is
    done by certbot outside the portal.
    """
    if _fire is None or _get_setting is None or _set_setting is None:
        return None
    import cert_manager
    now = now or _wall()
    try:
        info = await asyncio.to_thread(cert_manager.get_cert_info, cert_path)
    except Exception as e:
        logger.warning("[Alerts] certificate check could not read the file: %s", type(e).__name__)
        await _cert_unreadable_notice(now)
        return None
    serial = str(info.get("serial_number"))
    days = _days_left(info["not_after"], now)
    try:
        state = json.loads(await _get_setting(CERT_STATE_KEY) or "{}")
        if not isinstance(state, dict):
            state = {}
    except Exception:
        state = {}
    if state.get("serial") != serial:
        state = {"serial": serial, "sent": [], "renewal": False}
    did = []
    crossed = [t for t in CERT_THRESHOLDS if days <= t]
    if crossed:
        lowest = min(crossed)
        if lowest not in state["sent"]:
            if days <= 0:
                summary = "The server certificate has expired"
            elif days < 1:
                summary = "The server certificate expires in less than a day"
            else:
                summary = f"The server certificate expires in {math.ceil(days)} days"
            if emit("cert.expiring", key=f"{serial}:{lowest}", cooldown=0.0, summary=summary,
                    severity="critical" if lowest == 1 else "warning",
                    details={"Expires": info.get("not_after"), "Subject": (info.get("subject") or {}).get("CN"),
                             "Serial": serial, "Method": info.get("method")},
                    record={"event": "cert_expiring", "details": {"days_left": math.ceil(days), "threshold": lowest}}):
                state["sent"] = sorted(set(state["sent"]) | {t for t in CERT_THRESHOLDS if t >= lowest})
                did.append(f"expiring:{math.ceil(days)}")
    if (info.get("method") == "letsencrypt" and days < RENEWAL_WINDOW_DAYS and not state.get("renewal")):
        if emit("cert.renewal_failed", key=f"{serial}", cooldown=0.0,
                summary=f"The Let's Encrypt certificate has {max(int(days), 0)} days left and was not renewed",
                details={"Expires": info.get("not_after"), "Serial": serial},
                record={"event": "cert_renewal_failed", "details": {"days_left": int(days), "kind": "overdue"}}):
            state["renewal"] = True
            did.append("renewal_failed")
    try:
        await _set_setting(CERT_STATE_KEY, json.dumps(state))
    except Exception as e:
        logger.warning("[Alerts] could not save the certificate state: %s", type(e).__name__)
    return ",".join(did) or None
