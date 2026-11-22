"""Reference IDs for the answers of IP blocks and rate limiters (1.22.0).

A client that is refused with 403 (an IP block) or 429 (a rate limiter) is shown a short random ID.
An administrator pastes it into Admin > System > Network > Reference lookup and sees the stored event.
The ID is never derived from an address or an account (it comes from the `secrets` module), and it
is the only thing the answer tells the client.

Bounds (all constants below, stated in the README):

* One ID per (kind, limiter, address, account) for REUSE_SECONDS: a client that keeps hitting the same
  block or limiter gets the same ID and costs no row, no database read and no log line after the first.
  10,000 requests from one blocked address are one row.
* At most NEW_PER_MINUTE new IDs a minute for IP blocks and, separately, NEW_PER_MINUTE for rate
  limiters (two budgets of their own, 120 rows a minute at most in all): a flood over a limiter, for
  example anonymous requests from many addresses against the sign-in limiter, cannot use up the budget
  of the blocks, so a member who is blocked still gets an ID of their own. Past a budget, every further
  new client of that kind in that minute is given one shared "overflow" ID (one row a minute at most
  per kind), so a flood of distinct addresses cannot fill the table; the overflow row says so. A rate
  limiter's ID is kept per address, an IPv6 address as its /64 network (the caller does that).
* An ID is dropped when its block is removed or written again (forget), so a later block of the same
  address gets a new ID and a new row, never the old one with the old source and reason.
* The table keeps at most MAX_ROWS rows (the oldest go on insert) and no row older than MAX_AGE_DAYS
  (removed on insert at most every PRUNE_SECONDS, by the daily retention sweep, and a lookup never
  returns one). The in-memory map is capped at CACHE_MAX entries, least recently used first.

Nothing here raises into a caller: a failed write or read gives an answer without an ID.
"""

import logging
import re
import secrets
import time
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger("portal")

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # 32 characters, no 0/O/1/I
REF_LENGTH = 8                                     # shown as ABCD-EFGH
REUSE_SECONDS = 3600
NEW_PER_MINUTE = 60
MAX_ROWS = 5000
MAX_AGE_DAYS = 7
CACHE_MAX = 5000
PRUNE_SECONDS = 600
HITS_FLUSH_SECONDS = 60
REASON_MAX = 200
LOOKUP_PER_MINUTE = 20                             # lookups per administrator

KINDS = ("block", "limit", "overflow")
_REF_RE = re.compile(r"^[A-Z2-9]{8}$")


def new_ref() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(REF_LENGTH))


def display(ref: str) -> str:
    """The form shown to people: ABCD-EFGH."""
    return f"{ref[:4]}-{ref[4:]}" if ref and len(ref) == REF_LENGTH else (ref or "")


def normalize(text) -> Optional[str]:
    """The stored form of what an administrator typed (case, spaces and a hyphen ignored), or
    None when it cannot be an ID."""
    if not isinstance(text, str) or len(text) > 40:
        return None
    ref = re.sub(r"[\s-]", "", text).upper()
    return ref if _REF_RE.match(ref) and not set(ref) - set(ALPHABET) else None


class RefIssuer:
    """Hands out IDs and keeps the rows. `db` needs insert_block_ref, touch_block_ref, prune_block_refs;
    `clock` is monotonic seconds (injectable for tests)."""

    def __init__(self, db, clock=time.monotonic):
        self.db = db
        self.clock = clock
        self._cache: "OrderedDict[tuple, dict]" = OrderedDict()
        self._minutes: dict = {}                       # kind -> [minute, new IDs made in it]
        self._last_prune = None

    def reset(self) -> None:
        self._cache.clear()
        self._minutes.clear()
        self._last_prune = None

    def forget(self, kind: str, limiter: str, subject: Optional[str]) -> None:
        """Drop the held ID of an address for good (its block was removed or written again), so the
        next refusal gets a new ID and a new row. Without an account in the key: block IDs have none."""
        self._cache.pop((kind, limiter, subject, None), None)

    def cached(self, key: tuple) -> Optional[str]:
        """The ID for `key` when one is held and still fresh. Counts the hit."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if self.clock() >= entry["until"]:
            del self._cache[key]
            return None
        entry["hits"] += 1
        self._cache.move_to_end(key)
        return entry["ref"]

    def _budget_left(self, now: float, kind: str) -> bool:
        """One budget of NEW_PER_MINUTE new IDs a minute for each kind ("block" and "limit")."""
        minute = int(now // 60)
        slot = self._minutes.get(kind)
        if slot is None or slot[0] != minute:
            slot = self._minutes[kind] = [minute, 0]
        if slot[1] >= NEW_PER_MINUTE:
            return False
        slot[1] += 1
        return True

    def _store(self, key: tuple, ref: str, now: float, until: float) -> dict:
        while len(self._cache) >= CACHE_MAX:
            self._cache.popitem(last=False)
        entry = {"ref": ref, "until": until, "hits": 1, "flushed_hits": 1, "flushed_at": now}
        self._cache[key] = entry
        return entry

    async def _write(self, first, ref_kind, limiter, source, subject, reason, user_id) -> Optional[str]:
        """Insert a row under `first`, the ID already handed to concurrent requests; only a clash
        with an existing ID draws another one."""
        ref = first
        for attempt in range(3):
            if attempt:
                ref = new_ref()
            try:
                await self.db.insert_block_ref(ref, ref_kind, limiter, source, subject,
                                               (reason or None) and str(reason)[:REASON_MAX], user_id, MAX_ROWS)
                return ref
            except Exception as e:
                if "UNIQUE" in str(e).upper():
                    continue
                logger.warning(f"Could not store a reference ID ({type(e).__name__})")
                return None
        return None

    async def _maybe_prune(self, now: float) -> None:
        if self._last_prune is not None and now - self._last_prune < PRUNE_SECONDS:
            return
        self._last_prune = now
        try:
            await self.db.prune_block_refs(MAX_AGE_DAYS)
        except Exception as e:
            logger.debug(f"Reference ID prune failed ({type(e).__name__})")

    async def _flush_hits(self, entry: dict, now: float) -> None:
        if now - entry["flushed_at"] < HITS_FLUSH_SECONDS or entry["hits"] == entry["flushed_hits"]:
            return
        entry["flushed_at"], entry["flushed_hits"] = now, entry["hits"]
        try:
            await self.db.touch_block_ref(entry["ref"], entry["hits"])
        except Exception as e:
            logger.debug(f"Reference ID hit count not written ({type(e).__name__})")

    async def issue(self, kind: str, limiter: str, subject: Optional[str], *, source: Optional[str] = None,
                    reason: Optional[str] = None, user_id: Optional[int] = None,
                    loader=None) -> Optional[str]:
        """The ID for this refusal: the held one for the same client, else a new row.

        `loader` is an async callable returning (source, reason), called only when a row is
        written (so a block's stored reason is read once, not per request). Returns None when the
        row could not be stored."""
        try:
            key = (kind, limiter, subject, user_id)
            ref = self.cached(key)
            if ref is not None:
                entry = self._cache[key]
                await self._flush_hits(entry, self.clock())
                return ref
            now = self.clock()
            if self._budget_left(now, kind):
                until = now + REUSE_SECONDS
                entry = self._store(key, "", now, until)       # reserved: a concurrent request waits no row
                entry["ref"] = pending = new_ref()
                if loader is not None:
                    try:
                        source, reason = await loader()
                    except Exception as e:
                        logger.debug(f"Reference ID detail not read ({type(e).__name__})")
                row_kind, row_limiter, row_subject = kind, limiter, subject
            else:
                okey = ("overflow", kind, None, None)
                ref = self.cached(okey)
                if ref is not None:
                    return ref
                until = now + 60
                entry = self._store(okey, "", now, until)
                entry["ref"] = pending = new_ref()
                key = okey
                row_kind, row_limiter, row_subject = "overflow", kind, None
                source, reason, user_id = None, f"more than {NEW_PER_MINUTE} new sources in one minute", None
            ref = await self._write(pending, row_kind, row_limiter, source, row_subject, reason, user_id)
            if ref is None:
                self._cache.pop(key, None)
                return None
            if ref != pending:
                entry["ref"] = ref          # a clash on `pending` (about 1 in 10^12) was retried under another ID
            await self._maybe_prune(now)
            return ref
        except Exception as e:
            logger.warning(f"Reference ID failed ({type(e).__name__})")
            return None
