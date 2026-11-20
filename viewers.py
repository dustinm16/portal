"""Portal-side viewer counts for live streams.

MediaMTX's reader list is not the audience: it contains the recorder, the relays, the
thumbnail grabber and the portal's own HLS proxy, and it names streams published with an
rtmp_ token under a path the old lookup did not understand. The portal knows who watches,
because every viewer's playlist fetch, WHEP offer and heartbeat passes its read gate.

Everything here is in memory. Nothing is stored or logged that names an address: the
anonymous identity is a salted hash (salt random per process, never written anywhere), the
per-address cap counts hashes, and the identity of a signed-in viewer is the account id.

Pure logic with an injectable clock; server.py wires it to the read gate, the routes, the
sync task and the go-live/offline transitions.
"""

import hashlib
import hmac
import re
import secrets
from collections import Counter
from time import monotonic
from typing import Callable, Optional

# How long a sighting counts. A heartbeat comes every ~10 s; an HLS player polls the
# playlist about every segment (1-2 s) but pauses and stalls, so its window is longer.
BEAT_WINDOW = 15.0
HLS_WINDOW = 20.0
# Identities counted per stream at one time; a flood of random ids stops here.
MAX_PER_STREAM = 5000
# Anonymous identities one address may hold on one stream (a household, a small office).
MAX_ANON_PER_ADDRESS = 5
# Distinct identities remembered for the "unique viewers" figure of one live session.
MAX_UNIQUE_PER_SESSION = 20000
# Client-generated viewer id (watch.html): letters, digits, - and _, bounded length.
VIEWER_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")
MAX_UA = 200


def valid_viewer_id(value) -> Optional[str]:
    return value if isinstance(value, str) and VIEWER_ID_RE.match(value) else None


class _Session:
    __slots__ = ("peak", "seen")

    def __init__(self):
        self.peak = 0
        self.seen: set = set()


class ViewerTracker:
    def __init__(self, clock: Callable[[], float] = monotonic):
        self._clock = clock
        self._salt = secrets.token_bytes(16)
        # stream id -> identity -> expiry
        self._live: dict[int, dict[str, float]] = {}
        # stream id -> address hash -> anonymous identities held (for the per-address cap)
        self._addr_of: dict[int, dict[str, str]] = {}
        self._addr_n: dict[int, Counter] = {}
        self._sessions: dict[int, _Session] = {}

    def _hash(self, *parts: str) -> str:
        mac = hmac.new(self._salt, "\0".join(parts).encode("utf-8", "surrogatepass"), hashlib.sha256)
        return mac.hexdigest()[:24]

    def address_hash(self, addr: str) -> str:
        """A salted hash of a client address, for keys of in-memory tables only."""
        return self._hash("addr", addr or "")

    def _identity(self, user_id, client_id, addr, ua):
        """(identity, address hash or None). A signed-in viewer is the account (two tabs, one
        viewer); a logged-out one the client's own id, or failing that the hash of address and
        user agent."""
        if user_id is not None:
            return f"u:{int(user_id)}", None
        ah = self.address_hash(addr)
        if client_id:
            return "c:" + self._hash("cid", client_id), ah
        return "a:" + self._hash("ua", addr or "", (ua or "")[:MAX_UA]), ah

    # --- sessions ------------------------------------------------------------------

    def start_session(self, stream_id: int) -> None:
        """A stream went live: fresh peak and unique figures, nobody counted yet."""
        self.clear_viewers(stream_id)
        self._sessions[stream_id] = _Session()

    def finish(self, stream_id: int) -> Optional[tuple[int, int]]:
        """The stream's live session ended: (peak, unique), or None when there is no session
        (so a second call changes nothing). Viewers of the stream are forgotten."""
        sess = self._sessions.pop(stream_id, None)
        if sess is None:
            self.clear_viewers(stream_id)
            return None
        peak = max(sess.peak, self.count(stream_id))
        self.clear_viewers(stream_id)
        return peak, len(sess.seen)

    def clear_viewers(self, stream_id: int) -> None:
        self._live.pop(stream_id, None)
        self._addr_of.pop(stream_id, None)
        self._addr_n.pop(stream_id, None)

    def forget_except(self, stream_ids) -> None:
        """Drop everything held for streams that are not in `stream_ids` (not live any more)."""
        keep = set(stream_ids)
        for sid in {*self._live, *self._sessions} - keep:
            self.clear_viewers(sid)
            self._sessions.pop(sid, None)

    # --- sightings -----------------------------------------------------------------

    def touch(self, stream_id: int, *, user_id=None, client_id=None, addr="", ua="",
              window: float = BEAT_WINDOW) -> bool:
        """Note that somebody who passed the read gate is watching. True when counted."""
        now = self._clock()
        ident, ah = self._identity(user_id, client_id, addr, ua)
        live = self._live.setdefault(stream_id, {})
        if ident not in live:
            if len(live) >= MAX_PER_STREAM:
                self._prune_stream(stream_id, now)
                live = self._live.setdefault(stream_id, {})
                if len(live) >= MAX_PER_STREAM:
                    return False
            if ah is not None:
                n = self._addr_n.setdefault(stream_id, Counter())
                if n[ah] >= MAX_ANON_PER_ADDRESS:
                    # a stale entry of this address may be holding the slot
                    self._prune_stream(stream_id, now)
                    live = self._live.setdefault(stream_id, {})
                    n = self._addr_n.setdefault(stream_id, Counter())
                    if n[ah] >= MAX_ANON_PER_ADDRESS:
                        return False
                n[ah] += 1
                self._addr_of.setdefault(stream_id, {})[ident] = ah
        live[ident] = max(live.get(ident, 0.0), now + window)
        sess = self._sessions.get(stream_id)
        if sess is None:
            sess = self._sessions[stream_id] = _Session()
        if len(sess.seen) < MAX_UNIQUE_PER_SESSION:
            sess.seen.add(ident)
        return True

    def _prune_stream(self, stream_id: int, now: float) -> None:
        live = self._live.get(stream_id)
        if not live:
            return
        addr_of = self._addr_of.get(stream_id, {})
        n = self._addr_n.get(stream_id)
        for ident in [i for i, exp in live.items() if exp <= now]:
            del live[ident]
            ah = addr_of.pop(ident, None)
            if ah is not None and n is not None:
                n[ah] -= 1
                if n[ah] <= 0:
                    del n[ah]
        if not live:
            self.clear_viewers(stream_id)

    def count(self, stream_id: int) -> int:
        self._prune_stream(stream_id, self._clock())
        return len(self._live.get(stream_id, ()))

    def sample(self) -> dict[int, int]:
        """Prune everything stale, raise the peaks, return stream id -> viewers now."""
        now = self._clock()
        for sid in list(self._live):
            self._prune_stream(sid, now)
        out = {sid: len(v) for sid, v in self._live.items()}
        for sid, n in out.items():
            sess = self._sessions.get(sid)
            if sess is not None and n > sess.peak:
                sess.peak = n
        return out


class RateWindow:
    """At most `limit` hits per `window` seconds for each key; the table is bounded."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = monotonic,
                 max_keys: int = 10000):
        self.limit, self.window, self._clock, self.max_keys = limit, window, clock, max_keys
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = self._clock()
        start = now - self.window
        if key not in self._hits and len(self._hits) >= self.max_keys:
            for k in [k for k, v in self._hits.items() if not v or v[-1] <= start]:
                del self._hits[k]
            if len(self._hits) >= self.max_keys:
                return False        # full of live keys: refuse the newcomer, never evict others
        hits = [t for t in self._hits.get(key, ()) if t > start]
        if len(hits) >= self.limit:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True
