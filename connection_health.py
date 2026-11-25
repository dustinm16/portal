"""Opt-in health checks of members' connections, shown as status dots on the dashboard.

Off by default; a superadmin switches it on (setting `connection_health_enabled`) and may set
the round interval (`connection_health_interval`, 60 to 900 seconds, default 60). While on, ONE
background task runs a round every interval (+- 10 % jitter) and probes only the connections
that are pinned or were opened in the last 7 days by somebody who still has access
(Database.list_health_candidates). Nothing a member types decides what is probed: the target is
what the connection already holds, exactly as a real connection attempt of that type dials it.

What is probed
  * TCP connect to the connection's host and port, for the ssh and vnc plugins and the tunnel
    plugins (tcp_tunnel, secure_tunnel; databases and the like ride on those). A TCP connect that
    is closed again at once: nothing is written and no banner is read.
  * HEAD (GET on 405 or 501, the body read only up to BODY_CAP bytes) of "/" on the origin the
    HTTP proxy would dial (the connection's target_url, else scheme://host:port by the proxy's
    own scheme rule), for the http_proxy plugin. Redirects are NOT followed. No cookie, header,
    credential or stored secret is sent; TLS verification follows the connection (verify_ssl).
  * Not probed, always "unknown": vpn_tunnel, github, mediamtx, spice, proxmox, a browser_mode
    connection (it has no fixed target), a connection with no usable host or port.

Host policy: every probe goes through host_check.resolve_checked_host exactly as the real
attempt does (same refusals: loopback, private, link-local, metadata, CGNAT) and then dials one
of the CHECKED addresses (TCP: try_each_address; HTTP: the checked connector with a resolver
that can only answer with the checked addresses, so no second DNS lookup happens). A target the
policy refuses is never dialled and reads "unknown", not "down".

Results: a probe is ok, fail, refused (policy) or error (the probe itself raised: no change).
A connection is "down" after DOWN_AFTER (3) failures in a row and "up" after UP_AFTER (2)
successes in a row; unknown until then. HTTP status below 500 counts as up (any answer means
the service is there, a 401 or 404 included), 5xx, a refused or reset connection and a timeout
count as a failure. Only the status class and the latency are kept from a response.

State is in memory; only a change of status is stored (connection_health_log). Stored rows are
bounded three ways: at most STORE_PER_DAY (24) transitions per connection per UTC day (after
that the status still changes in memory and is shown, but nothing more is stored or alerted
until the next day), LOG_KEEP_DAYS, and a global row cap LOG_MAX_ROWS with oldest-first pruning
(never the latest row of a connection). service.health_changed fires once per change between up
and down (a connection that was never up never alerts), in a bucket of its own (alerts.HEALTH_BUCKET)
so a flapping upstream cannot hold back moderation, automod or account-security alerts, and at
most once per connection per ALERT_PERIOD (10 minutes); third-party formats get a text with no
name and no host. A stored "down" older than SEED_MAX_AGE (30 minutes) is not remembered as
"known" after a restart or after the feature is switched off and on, so a recovery then sends no
"back up" for a "down" nobody was told about recently.

Maintenance: a connection that is in maintenance (maintenance.state) is probed as usual but its
transitions fire no alert while the maintenance lasts; an alert it would have sent is owed and is
sent once afterwards if the status is still what it was (an up and a down in between cancel
each other). The status shows "maintenance" for everybody who can reach the connection.

Limits: PROBE_ROUND_CAP (100) probes per round over all members, at most PER_OWNER_PROBES (10)
distinct targets per owner per round, filled in rotation across owners (the owner whose oldest
check is the oldest goes first) and, within an owner, least recently probed first; a target
several connections share is probed once and counts once, against whichever owner's turn picked
it. An owner looks at no more than OWNER_SCAN (100) of their connections per round; the excess is
probed less often and reads "unknown" once stale. At most PROBE_PARALLEL (5) at once,
PROBE_TIMEOUT seconds each, never two probes of one target at once. A target that the host policy
refuses is remembered with a backoff (REFUSED_BACKOFF doubling to REFUSED_BACKOFF_MAX): not
resolved again until it ends, one warning when it starts and one when it ends.

Staged instance (PORTAL_STAGE_MODE): rounds run every second and nothing is probed, except a literal 127.0.0.1 target whose
port is in the stage_health_target_ports setting (comma separated), under the LAN policy
(loopback allowed, metadata and link-local still refused). The setting is read only when the
instance is staged; a production process never looks at it.
"""

import asyncio
import logging
import os
import random
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp
import aiohttp.abc
import aiohttp.resolver
from yarl import URL

import alerts
import host_check
import maintenance
from host_check import (HostBlockedError, HostCheckError, _CheckedConnector, resolve_checked_host,
                        try_each_address)

logger = logging.getLogger("portal")

SETTING_ENABLED = "connection_health_enabled"
SETTING_INTERVAL = "connection_health_interval"
SETTING_STAGE_PORTS = "stage_health_target_ports"

INTERVAL_DEFAULT, INTERVAL_MIN, INTERVAL_MAX = 60, 60, 900
RECENT_DAYS = 7
DOWN_AFTER = 3
UP_AFTER = 2
PROBE_ROUND_CAP = 100
PER_OWNER_PROBES = 10        # distinct targets one owner may have probed in one round
OWNER_SCAN = 100             # connections of one owner looked at (decoded) in one round
PROBE_PARALLEL = 5
PROBE_TIMEOUT = 6.0          # whole probe, resolve included
RESOLVE_TIMEOUT = 3.0
CONNECT_TIMEOUT = 4.0
BODY_CAP = 1024
CANDIDATE_LIMIT = 1000       # connection rows decoded in one round, all owners together
CANDIDATE_REF_LIMIT = 50000  # safety bound on the (id, owner) list the round chooses from
LOG_KEEP_DAYS = 14
LOG_MAX_ROWS = 50000         # stored transitions, all connections; the oldest go first
STORE_PER_DAY = 24           # stored (and alerted) transitions per connection per UTC day
PRUNE_EVERY = 3600.0
ALERT_PERIOD = 600.0         # at most one alert per connection in this many seconds
SEED_MAX_AGE = 1800.0        # a stored "down" older than this is not "known" after a restart
REFUSED_BACKOFF = 600.0      # a target the host policy refuses is not tried again for this long,
REFUSED_BACKOFF_MAX = 3600.0 # doubling up to this
REFUSED_MAX = 1000           # remembered refused targets
LOG_BUDGET = 20              # [Health] warnings per hour about refused targets
JITTER = 0.10
STAGE_ROUND_SECONDS = 1.0     # a staged instance rounds every second (it probes only its own loopback test targets)

# the proxy's own rule for the scheme of a connection with no target_url
HTTPS_TYPES = frozenset({"https", "portainer", "truenas", "pfsense", "nextcloud", "cockpit"})
TCP_PLUGINS = frozenset({"ssh", "vnc", "tcp_tunnel", "secure_tunnel"})
HTTP_PLUGINS = frozenset({"http_proxy"})


def proxy_scheme(conn_type: str, port) -> str:
    """http or https for a connection with no target_url (the HTTP proxy and the probe both use this)."""
    return "https" if (conn_type in HTTPS_TYPES or port == 443) else "http"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent(stamp, now_dt: datetime) -> bool:
    """True when the stored timestamp is within SEED_MAX_AGE of now; an unreadable one is not."""
    try:
        t = datetime.strptime(str(stamp), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    return timedelta(0) <= now_dt - t <= timedelta(seconds=SEED_MAX_AGE)


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    kind: str                 # "tcp" or "http"
    host: str                 # what is resolved, checked and dialled
    port: int
    scheme: str = ""          # http only
    verify_ssl: bool = False  # http only
    url: str = ""             # http only: origin plus "/", no user info, no query

    @property
    def key(self) -> tuple:
        return (self.kind, self.scheme, self.host.lower(), self.port, self.verify_ssl)


def _port_ok(value) -> Optional[int]:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 65536 else None


def target_of(conn: dict, types: dict) -> Optional[Target]:
    """The probe target of a connection row (config decoded), or None when it is not probed.
    Mirrors what a real connection attempt dials; only the target is kept, never the config."""
    try:
        conn_type = conn.get("type") or "custom"
        info = types.get(conn_type, {"plugin": "tcp_tunnel"})
        plugin = info.get("plugin")
        config = conn.get("config")
        if not isinstance(config, dict):
            config = {}
        host = (conn.get("host") or "").strip()
        if plugin in TCP_PLUGINS:
            port = _port_ok(conn.get("port") or info.get("default_port"))
            if not host or port is None:
                return None
            return Target("tcp", host, port)
        if plugin in HTTP_PLUGINS:
            if config.get("browser_mode"):
                return None
            verify = bool(config.get("verify_ssl", False))
            tu = config.get("target_url")
            if isinstance(tu, str) and tu.strip():
                u = URL(tu.strip())
                if u.scheme not in ("http", "https") or not u.raw_host:
                    return None
                origin = u.origin().with_path("/")
                port = _port_ok(origin.port)
                if port is None:
                    return None
                return Target("http", origin.raw_host, port, origin.scheme, verify, str(origin))
            port = _port_ok(conn.get("port") or config.get("port") or info.get("default_port", 80))
            if not host or port is None:
                return None
            scheme = proxy_scheme(conn_type, port)
            default = 443 if scheme == "https" else 80
            origin = URL.build(scheme=scheme, host=host, port=None if port == default else port, path="/")
            if not origin.raw_host:
                return None
            return Target("http", origin.raw_host, port, scheme, verify, str(origin))
    except (ValueError, TypeError, UnicodeError):
        return None
    return None


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Result:
    kind: str                         # ok, fail, refused, error
    latency_ms: Optional[int] = None
    status_class: Optional[str] = None


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    """Answers only with the addresses that already passed the host check."""

    def __init__(self, addrs: dict):
        self._addrs = {k.lower(): list(v) for k, v in addrs.items()}

    async def resolve(self, host, port=0, family=socket.AF_INET):
        addrs = self._addrs.get(host.lower())
        if not addrs:
            raise OSError("host was not checked")
        out = []
        for a in addrs:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            if family not in (0, socket.AF_UNSPEC, fam):
                continue
            out.append({"hostname": host, "host": a, "port": port, "family": fam, "proto": 0,
                        "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV})
        return out

    async def close(self):
        pass


def _ms(seconds: float) -> int:
    return max(0, int(round(seconds * 1000)))


async def _probe_tcp(target: Target, lan: bool) -> Result:
    addrs = await resolve_checked_host(target.host, target.port, timeout=RESOLVE_TIMEOUT, allow_private=lan)
    t0 = time.monotonic()
    _reader, writer = await try_each_address(
        addrs, lambda a: asyncio.open_connection(a, target.port), CONNECT_TIMEOUT)
    latency = _ms(time.monotonic() - t0)
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:
        pass
    return Result("ok", latency)


async def _probe_http(target: Target, lan: bool) -> Result:
    addrs = await resolve_checked_host(target.host, target.port, timeout=RESOLVE_TIMEOUT, allow_private=lan)
    connector = _CheckedConnector(resolver=_PinnedResolver({target.host: addrs}), allow_private=lan,
                                  ssl=target.verify_ssl, force_close=True, limit=1, use_dns_cache=False)
    session = aiohttp.ClientSession(
        connector=connector, cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False, trust_env=False,
        headers={"User-Agent": "OpenRelayPortal-health", "Accept": "*/*"},
        timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT))
    try:
        t0 = time.monotonic()
        async with session.request("HEAD", target.url, allow_redirects=False) as resp:
            status = resp.status
        if status in (405, 501):
            async with session.request("GET", target.url, allow_redirects=False) as resp:
                status = resp.status
                await resp.content.read(BODY_CAP)
                resp.close()
        latency = _ms(time.monotonic() - t0)
    finally:
        await session.close()
    return Result("ok" if status < 500 else "fail", latency, f"{status // 100}xx")


async def probe_target(target: Target, *, lan: bool = False) -> Result:
    """One probe. `lan` (a staged test target only) applies the LAN policy instead of the default."""
    quiet = host_check.quiet_refusals.set(True)       # the monitor logs a refused target once, itself
    try:
        inner = _probe_tcp(target, lan) if target.kind == "tcp" else _probe_http(target, lan)
        return await asyncio.wait_for(inner, PROBE_TIMEOUT)
    except HostBlockedError:
        return Result("refused")
    except aiohttp.ClientConnectorError as e:
        if isinstance(getattr(e, "os_error", None), HostBlockedError) or isinstance(e.__cause__, HostBlockedError):
            return Result("refused")
        return Result("fail")
    except (asyncio.TimeoutError, OSError, aiohttp.ClientError, HostCheckError):
        return Result("fail")
    finally:
        host_check.quiet_refusals.reset(quiet)


# ---------------------------------------------------------------------------
# state with hysteresis
# ---------------------------------------------------------------------------

class Entry:
    __slots__ = ("key", "status", "since", "known", "fails", "oks", "latency_ms", "status_class", "checked", "owed")

    def __init__(self, key=None, status="unknown", since=None, known=None):
        self.key = key
        self.status = status
        self.since = since
        self.known = known           # last status that was up or down
        self.fails = 0
        self.oks = 0
        self.latency_ms = None
        self.status_class = None
        self.checked = None          # monotonic time of the last result in this process
        self.owed = None             # "up" or "down": an alert held back by maintenance


@dataclass
class Transition:
    conn_id: int
    old: str
    new: str
    since: str
    alert: Optional[str]             # "down", "up" or None
    store: bool = True               # False: an alert owed from maintenance, the change itself is stored already


class HealthState:
    def __init__(self):
        self.entries: dict[int, Entry] = {}

    def seed(self, rows: dict, now_dt: Optional[datetime] = None) -> None:
        """Read the stored states back. The last known "down" is remembered only when it is recent
        (SEED_MAX_AGE): the alert for an old one was sent long ago, or never, and a recovery now must
        not announce "back up" for it. The status itself (down since...) is kept for the view."""
        now_dt = now_dt or datetime.now(timezone.utc)
        out = {}
        for cid, row in rows.items():
            st, since, known = row[0], row[1], row[2]
            known_since = row[3] if len(row) > 3 else since
            if known == "down" and not _recent(known_since, now_dt):
                known = None
            out[cid] = Entry(None, st if st in ("up", "down", "unknown") else "unknown", since, known)
        self.entries = out

    def apply(self, conn_id: int, key: tuple, result: Result, now: float, iso: str,
              quiet: bool = False) -> Optional[Transition]:
        """Fold one result in. `quiet` (the connection is in maintenance) holds an alert back: it is
        owed and sent by a later call that is not quiet, if the status is still the one it was for."""
        tr = self._apply(conn_id, key, result, now, iso)
        e = self.entries[conn_id]
        if tr is not None and tr.alert:
            if quiet:
                e.owed = None if (e.owed and e.owed != tr.alert) else tr.alert
                tr.alert = None
            else:
                e.owed = None
        elif tr is not None and tr.new != e.owed:
            e.owed = None                  # it left the state the alert was owed for
        if not quiet and e.owed and tr is None and result.kind in ("ok", "fail") and e.status == e.owed:
            tr = Transition(conn_id, e.status, e.status, e.since or iso, e.owed, store=False)
            e.owed = None
        return tr

    def _apply(self, conn_id: int, key: tuple, result: Result, now: float, iso: str) -> Optional[Transition]:
        e = self.entries.get(conn_id)
        if e is None:
            e = self.entries[conn_id] = Entry(key, "unknown", None, None)
        tr = None
        if e.key is not None and e.key != key:
            # the connection now points somewhere else: what was known about the old target is void
            e.fails = e.oks = 0
            e.known = None
            e.latency_ms = None
            if e.status != "unknown":
                tr = Transition(conn_id, e.status, "unknown", iso, None)
                e.status, e.since = "unknown", iso
        e.key = key
        e.checked = now
        if result.kind == "error":
            return tr
        if result.kind == "refused":
            e.fails = e.oks = 0
            e.latency_ms = None
            if e.status != "unknown":
                tr = Transition(conn_id, e.status, "unknown", iso, None)
                e.status, e.since = "unknown", iso
            return tr
        e.status_class = result.status_class
        if result.kind == "ok":
            e.oks += 1
            e.fails = 0
            e.latency_ms = result.latency_ms
            if e.status != "up" and e.oks >= UP_AFTER:
                tr = Transition(conn_id, e.status, "up", iso, "up" if e.known == "down" else None)
                e.status, e.since, e.known = "up", iso, "up"
        else:
            e.fails += 1
            e.oks = 0
            e.latency_ms = None
            if e.status != "down" and e.fails >= DOWN_AFTER:
                tr = Transition(conn_id, e.status, "down", iso, "down" if e.known == "up" else None)
                e.status, e.since, e.known = "down", iso, "down"
        return tr

    def view(self, conn_id: int, now: float, stale: float) -> dict:
        e = self.entries.get(conn_id)
        if e is None or e.checked is None or now - e.checked > stale or e.status == "unknown":
            return {"status": "unknown", "latency_ms": None, "since": None}
        return {"status": e.status, "latency_ms": e.latency_ms if e.status == "up" else None, "since": e.since}


def stale_after(interval: float) -> float:
    return max(5 * interval, 300.0)


def clamp_interval(value) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return INTERVAL_DEFAULT
    return n if INTERVAL_MIN <= n <= INTERVAL_MAX else INTERVAL_DEFAULT


def parse_ports(raw) -> frozenset:
    out = set()
    for part in str(raw or "").split(","):
        n = _port_ok(part.strip())
        if n:
            out.add(n)
    return frozenset(out)


# ---------------------------------------------------------------------------
# the monitor
# ---------------------------------------------------------------------------

class Monitor:
    def __init__(self, db, types: dict, *, stage_mode: bool = False, emit=None, probe=None,
                 clock=time.monotonic, wall=None, rng=None):
        self.db = db
        self.types = types
        self.stage_mode = stage_mode
        self.emit = emit or alerts.emit
        self.probe = probe or probe_target
        self.clock = clock
        self.wall = wall or (lambda: datetime.now(timezone.utc))
        self.rng = rng or random
        self.state = HealthState()
        self.interval = INTERVAL_DEFAULT
        self.enabled = False
        self._seeded = False
        self._inflight: set = set()
        self._task: Optional[asyncio.Task] = None
        self._last_prune: Optional[float] = None
        self._stored_since_prune = 0
        self._stored_today: dict[int, tuple] = {}     # connection id -> (UTC date, rows stored that day)
        self._refused: dict = {}                      # target key -> [retry at, delay]; bounded by REFUSED_MAX
        self._warn_window: Optional[float] = None
        self._warned = 0
        self._warn_suppressed = 0
        self.rounds = 0

    # -- settings

    async def read_settings(self) -> tuple:
        raw = await self.db.get_setting(SETTING_ENABLED)
        enabled = str(raw).strip() == "1"
        interval = clamp_interval(await self.db.get_setting(SETTING_INTERVAL))
        stage_ports = parse_ports(await self.db.get_setting(SETTING_STAGE_PORTS)) if self.stage_mode else frozenset()
        self.enabled, self.interval = enabled, interval
        return enabled, interval, stage_ports

    # -- log lines about refused targets, a few per hour at most

    def _warn(self, now: float, message: str, *args) -> None:
        if self._warn_window is None or now - self._warn_window >= 3600.0:
            if self._warn_suppressed:
                logger.warning("[Health] %d more message(s) about refused targets were not written", self._warn_suppressed)
            self._warn_window, self._warned, self._warn_suppressed = now, 0, 0
        if self._warned >= LOG_BUDGET:
            self._warn_suppressed += 1
            return
        self._warned += 1
        logger.warning(message, *args)

    def _refused_now(self, key: tuple, now: float) -> bool:
        """True while a refused target is inside its backoff (it is not resolved or dialled)."""
        hit = self._refused.get(key)
        return hit is not None and now < hit[0]

    def _note_refused(self, target: Target, now: float) -> None:
        hit = self._refused.get(target.key)
        if hit is None:
            while len(self._refused) >= REFUSED_MAX:
                self._refused.pop(next(iter(self._refused)))
            self._refused[target.key] = [now + REFUSED_BACKOFF, REFUSED_BACKOFF]
            self._warn(now, "[Health] the host %r resolves to an address the host policy refuses; it is not "
                       "probed and its connections read unknown (looked at again in %d s)",
                       target.host[:100], int(REFUSED_BACKOFF))
        else:
            hit[1] = min(hit[1] * 2, REFUSED_BACKOFF_MAX)
            hit[0] = now + hit[1]

    def _note_not_refused(self, target: Target, now: float) -> None:
        if self._refused.pop(target.key, None) is not None:
            self._warn(now, "[Health] the host %r is no longer refused by the host policy and is probed again",
                       target.host[:100])

    # -- one round

    def _lan_allowed(self, target: Target, stage_ports: frozenset) -> bool:
        return self.stage_mode and target.host == "127.0.0.1" and target.port in stage_ports

    def _age(self, cid: int) -> float:
        """When the connection was last probed in this process; never probed sorts before everything."""
        e = self.state.entries.get(cid)
        return -1.0 if e is None or e.checked is None else e.checked

    async def run_round(self) -> int:
        """One round. Returns the number of probes made (0 with the feature off)."""
        enabled, interval, stage_ports = await self.read_settings()
        if not enabled:
            self.state = HealthState()
            self._seeded = False
            self._refused.clear()
            return 0
        now_dt = self.wall()
        if not self._seeded:
            try:
                self.state.seed(await self.db.load_health_state(), now_dt)
            except Exception as e:
                logger.warning("[Health] could not read the stored states: %s", type(e).__name__)
            self._seeded = True
        since = _iso(now_dt - timedelta(days=RECENT_DAYS))
        refs = await self.db.list_health_candidate_refs(since, CANDIDATE_REF_LIMIT)

        # Who is looked at: each owner's least recently probed OWNER_SCAN connections, in turn across
        # owners (the owner with the oldest check first) until CANDIDATE_LIMIT rows are decoded, so one
        # member's hundreds of connections never push another's out.
        by_owner: dict = {}
        for cid, oid in refs:
            by_owner.setdefault(oid, []).append(cid)
        for lst in by_owner.values():
            lst.sort(key=lambda c: (self._age(c), c))
        owners = sorted(by_owner, key=lambda o: (self._age(by_owner[o][0]), o))
        chosen: list = []
        for rank in range(OWNER_SCAN):
            for o in owners:
                if len(chosen) >= CANDIDATE_LIMIT:
                    break
                if rank < len(by_owner[o]):
                    chosen.append(by_owner[o][rank])
        rowmap = {r["id"]: r for r in await self.db.get_health_candidate_rows(chosen)}

        now = self.clock()
        groups: dict = {}                 # target key -> (target, [rows])
        owner_keys: dict = {}             # owner -> target keys in the order they are to be probed
        unprobed = []
        for o in owners:
            mine: list = []
            for cid in by_owner[o][:OWNER_SCAN]:
                row = rowmap.get(cid)
                if row is None:
                    continue
                t = target_of(row, self.types)
                if t is None or (self.stage_mode and not self._lan_allowed(t, stage_ports)):
                    unprobed.append((row, ("none",)))
                    continue
                if self._refused_now(t.key, now):
                    unprobed.append((row, t.key))
                    continue
                if t.key in mine:
                    groups[t.key][1].append(row)
                elif len(mine) < PER_OWNER_PROBES:
                    mine.append(t.key)
                    groups.setdefault(t.key, (t, []))[1].append(row)
                # else: this owner's excess, not probed this round
            owner_keys[o] = mine
        iso = _iso(now_dt)
        transitions = []
        for row, key in unprobed:
            # not probeable (or not allowed here, or refused and waiting): reads "unknown", nothing is dialled
            tr = self.state.apply(row["id"], key, Result("refused"), now, iso, quiet=self._quiet(row, now_dt))
            if tr:
                transitions.append((row, tr))

        # fill the round in rotation: first target of every owner, then the second of every owner, ...
        ordered: list = []
        taken: set = set()
        for rank in range(PER_OWNER_PROBES):
            for o in owners:
                if len(ordered) >= PROBE_ROUND_CAP:
                    break
                lst = owner_keys[o]
                if rank < len(lst) and lst[rank] not in taken:
                    taken.add(lst[rank])
                    ordered.append(groups[lst[rank]])
        sem = asyncio.Semaphore(PROBE_PARALLEL)

        async def one(target: Target, members: list):
            if target.key in self._inflight:
                return None
            self._inflight.add(target.key)
            try:
                async with sem:
                    try:
                        return await self.probe(target, lan=self._lan_allowed(target, stage_ports))
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.warning("[Health] a probe raised %s", type(e).__name__)
                        return Result("error")
            finally:
                self._inflight.discard(target.key)

        results = await asyncio.gather(*(one(t, m) for t, m in ordered))
        now = self.clock()
        probes = 0
        for (target, members), res in zip(ordered, results):
            if res is None:
                continue
            probes += 1
            if res.kind == "refused":
                self._note_refused(target, now)
            elif res.kind in ("ok", "fail"):
                self._note_not_refused(target, now)
            for row in members:
                tr = self.state.apply(row["id"], target.key, res, now, iso, quiet=self._quiet(row, now_dt))
                if tr:
                    transitions.append((row, tr))
        for row, tr in transitions:
            await self._persist_and_alert(row, tr, now_dt, now)
        keep = {cid for cid, _ in refs}
        limit = stale_after(interval)
        for cid in [c for c, e in self.state.entries.items()
                    if c not in keep and (e.checked is None or now - e.checked > limit)]:
            del self.state.entries[cid]
        today = now_dt.strftime("%Y-%m-%d")
        for cid in [c for c, (d, _n) in self._stored_today.items() if d != today or c not in self.state.entries]:
            del self._stored_today[cid]
        for key in [k for k, (until, delay) in self._refused.items() if now - until > 2 * REFUSED_BACKOFF_MAX]:
            del self._refused[key]
        if self._stored_since_prune >= LOG_MAX_ROWS // 10:
            await self._prune(now)
        self.rounds += 1
        return probes

    @staticmethod
    def _quiet(row: dict, now_dt: datetime) -> bool:
        """The connection is in maintenance now: its transitions send no alert."""
        return maintenance.state(row, now_dt) is not None

    async def _prune(self, now: float) -> None:
        self._last_prune = now
        self._stored_since_prune = 0
        try:
            n = await self.db.prune_health_log(LOG_KEEP_DAYS, LOG_MAX_ROWS)
            if n:
                logger.info("[Health] pruned %d old status change(s)", n)
        except Exception as e:
            logger.warning("[Health] could not prune the status changes: %s", type(e).__name__)

    async def _persist_and_alert(self, row: dict, tr: Transition, now_dt: datetime, now: float) -> None:
        # At most STORE_PER_DAY changes per connection per UTC day are stored or alerted; the status
        # itself keeps changing in memory and is shown.
        cid = tr.conn_id
        day = now_dt.strftime("%Y-%m-%d")
        d, n = self._stored_today.get(cid, (day, 0))
        if d != day:
            n = 0
        if n >= STORE_PER_DAY:
            self._stored_today[cid] = (day, n)
            return
        self._stored_today[cid] = (day, n + 1)
        if tr.store:
            try:
                await self.db.add_health_transition(cid, tr.new, tr.since)
                self._stored_since_prune += 1
            except Exception as e:
                logger.warning("[Health] could not store a status change: %s", type(e).__name__)
        if not tr.alert:
            return
        name = str(row.get("name") or "a connection")[:80]
        owner = str(row.get("owner_username") or "")
        try:
            if tr.alert == "down":
                self.emit("service.health_changed", key=("conn", cid), bucket=alerts.HEALTH_BUCKET,
                          cooldown=ALERT_PERIOD, severity="warning", summary=f"Connection '{name}' is down",
                          details={"Connection": name, "Owner": owner, "Type": row.get("type")},
                          third_party={"summary": "A member's connection is down", "details": {}})
            else:
                self.emit("service.health_changed", key=("conn", cid), bucket=alerts.HEALTH_BUCKET,
                          cooldown=ALERT_PERIOD, severity="info", summary=f"Connection '{name}' is back up",
                          details={"Connection": name, "Owner": owner, "Type": row.get("type")},
                          third_party={"summary": "A member's connection is back up", "details": {}})
        except Exception as e:
            logger.warning("[Health] alert failed: %s", type(e).__name__)

    # -- what the API shows

    async def statuses_for(self, user_id: int) -> dict:
        """{uuid: {status, latency_ms, since}} for the connections the user can reach; {} when off.
        A connection in maintenance reads "maintenance" for everybody who can reach it (no more than
        the maintenance page says)."""
        raw = await self.db.get_setting(SETTING_ENABLED)
        if str(raw).strip() != "1":
            return {}
        interval = clamp_interval(await self.db.get_setting(SETTING_INTERVAL))
        stale = stale_after(self._round_seconds(interval))
        now = self.clock()
        now_dt = self.wall()
        out = {}
        # A grantee's pin makes the portal probe a connection. The owner's own dot must not show that: an
        # owned connection shows a status only when the owner's own pin or use qualifies (a grantee's does not).
        qualified = await self.db.owner_health_qualified_ids(
            user_id, _iso(now_dt - timedelta(days=RECENT_DAYS)))
        owned = await self.db.owned_connection_ids(user_id)
        for cid, uuid, maint in await self.db.list_accessible_connection_refs(user_id):
            if maintenance.state(maint, now_dt) is not None:
                out[uuid] = {"status": "maintenance", "latency_ms": None, "since": None}
            elif cid in owned and cid not in qualified:
                out[uuid] = {"status": "unknown", "latency_ms": None, "since": None}
            else:
                out[uuid] = self.state.view(cid, now, stale)
        return out

    # -- the task

    def _round_seconds(self, interval: float) -> float:
        return STAGE_ROUND_SECONDS if self.stage_mode else float(interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug("[Health] task ended with %s", type(e).__name__)

    async def _run(self) -> None:
        delay = 0.2 if self.stage_mode else self.rng.uniform(5, 15)
        while True:
            try:
                await asyncio.sleep(delay)
                await self.run_round()
                if self.enabled and (self._last_prune is None or self.clock() - self._last_prune > PRUNE_EVERY):
                    await self._prune(self.clock())
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("[Health] round failed: %s", type(e).__name__)
            base = self._round_seconds(self.interval)
            delay = base if self.stage_mode else base * self.rng.uniform(1 - JITTER, 1 + JITTER)
