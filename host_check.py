"""Outbound host policy: which addresses user-supplied targets may reach.

This module is the single definition of a "blocked" address (`is_blocked_host`)
and the single way to apply it to something a user typed:

  * `resolve_checked_host()` resolves a name off the event loop, refuses it if
    ANY resolved address is blocked, and returns the checked addresses so the
    caller can connect to one of them (pinning: a second DNS answer cannot
    differ from the one that was checked).
  * `_SSRFSafeConnector()` gives aiohttp the same policy at connect time,
    including IP literals and redirect targets, with TLS SNI and the Host
    header still using the original hostname.

Callers must treat every `HostCheckError` as "Host not allowed" towards the
user. Exception text never carries the resolved address; it is logged
server-side instead.
"""

import asyncio
import ipaddress
import logging
import re
import socket
import time

import aiohttp
import aiohttp.resolver

logger = logging.getLogger("portal")

# Blocked hosts for user connections (security - no local server access)
BLOCKED_HOSTS = {'localhost', '127.0.0.1', '::1', '0.0.0.0',
                 'host.docker.internal', 'kubernetes.default',
                 '169.254.169.254', 'metadata.google.internal'}


_CGNAT_V4 = ipaddress.ip_network('100.64.0.0/10')


def is_blocked_host(host: str) -> bool:
    """Check if host is blocked for user connections.

    Blocks localhost variants, cloud metadata, and RFC 1918/6598 private ranges
    to prevent SSRF attacks against internal network services.
    """
    if not host:
        return True
    h = host.lower().strip()
    # Direct matches
    if h in BLOCKED_HOSTS:
        return True
    # 127.x.x.x range
    if h.startswith('127.'):
        return True
    # IPv6 localhost variants
    if h.startswith('::ffff:127.'):
        return True
    # IP range checks (loopback, link-local, private, shared)
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            return True
        # RFC 6598 shared address space (100.64.0.0/10): not covered by
        # is_private, so check it explicitly. is_reserved is extra safety.
        if ip.is_reserved:
            return True
        # Deprecated IPv6 site-local fec0::/10: not covered by is_private
        if ip.version == 6 and ip.is_site_local:
            return True
        if ip.version == 4 and ip in _CGNAT_V4:
            return True
    except ValueError:
        pass
    return False


class HostCheckError(OSError):
    """Base class: the target host may not be dialled. Text is always generic."""


class HostBlockedError(HostCheckError):
    """The host, or an address it resolves to, is blocked."""

    def __init__(self):
        super().__init__("Host not allowed")


class HostResolveError(HostCheckError):
    """The host could not be resolved (so it cannot be checked or dialled)."""

    def __init__(self):
        super().__init__("Host could not be resolved")


# Legacy numeric IPv4 spellings that the C resolver accepts: 2130706433,
# 0x7f000001, 0177.0.0.1, 127.1 (and plain dotted quads).
_NUMERIC_V4_RE = re.compile(r'^(0[xX][0-9a-fA-F]+|[0-9]+)(\.(0[xX][0-9a-fA-F]+|[0-9]+)){0,3}$')


def _normalise_ip(text: str) -> str | None:
    """Canonical text for an IP literal or legacy numeric IPv4 form, else None."""
    t = text.strip()
    if t.startswith('[') and t.endswith(']'):
        t = t[1:-1]
    if '%' in t:                       # IPv6 zone id
        t = t.split('%', 1)[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass
    if _NUMERIC_V4_RE.match(t):
        try:
            return socket.inet_ntoa(socket.inet_aton(t))
        except (OSError, ValueError):
            return None
    return None


def is_blocked_address(addr: str) -> bool:
    """is_blocked_host() applied to an address, also in its IPv4-mapped form.

    The check is made on the raw text and, for an IPv4-mapped IPv6 address,
    on the embedded IPv4 address too; blocked if either is blocked.
    """
    if is_blocked_host(addr):
        return True
    try:
        ip = ipaddress.ip_address(addr.strip().split('%', 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, 'ipv4_mapped', None)
    return bool(mapped) and is_blocked_host(str(mapped))


async def _resolve(host: str, port: int) -> list[str]:
    """Resolve host to address strings (stream sockets, any family). Stubbed in tests."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port or None, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        addr = info[4][0].split('%', 1)[0]
        if addr not in out:
            out.append(addr)
    return out


async def resolve_checked_host(host: str, port: int = 0, *, timeout: float = 5.0) -> list[str]:
    """Resolve `host` and return its addresses, all of which passed the policy.

    Raises HostBlockedError if the literal host or ANY resolved address is
    blocked, HostResolveError if it cannot be resolved (fail closed). Numeric
    spellings of IPv4 addresses are normalised and checked without DNS.
    """
    if not isinstance(host, str) or not host.strip():
        raise HostBlockedError()
    h = host.strip()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    if is_blocked_host(h) or is_blocked_host(h.rstrip('.')):
        raise HostBlockedError()

    literal = _normalise_ip(h)
    if literal is not None:
        if is_blocked_address(literal):
            raise HostBlockedError()
        return [literal]

    try:
        addrs = await asyncio.wait_for(_resolve(h.rstrip('.') or h, port), timeout)
    except (asyncio.TimeoutError, socket.gaierror, UnicodeError, OSError, ValueError):
        raise HostResolveError() from None
    if not addrs:
        raise HostResolveError()
    for addr in addrs:
        if is_blocked_address(addr):
            logger.warning(f"Outbound host check: {h!r} resolves to a blocked address ({addr})")
            raise HostBlockedError()
    return addrs


_CACHE_TTL = 30.0
_CACHE_MAX = 512
# host -> (expiry on the monotonic clock, addresses, or True when blocked)
_check_cache: dict[str, tuple[float, object]] = {}


async def resolve_checked_host_cached(host: str, port: int = 0, *, ttl: float = _CACHE_TTL) -> list[str]:
    """resolve_checked_host() with a short per-host result cache.

    For callers that check many requests to the same few names (the browser
    proxy): a repeat within `ttl` seconds does not resolve again. Both the
    checked addresses and a "blocked" verdict are cached; a resolve failure
    never is. The cache is bounded. It only saves a lookup: the connector's
    own connect-time check stays authoritative for the actual dial.
    """
    if not isinstance(host, str):
        raise HostBlockedError()
    key = host.strip().lower()
    now = time.monotonic()
    hit = _check_cache.get(key)
    if hit and hit[0] > now:
        if hit[1] is True:
            raise HostBlockedError()
        return list(hit[1])
    try:
        addrs = await resolve_checked_host(host, port)
    except HostBlockedError:
        _cache_put(key, now + ttl, True)
        raise
    _cache_put(key, now + ttl, list(addrs))
    return addrs


def _cache_put(key: str, expiry: float, value) -> None:
    if len(_check_cache) >= _CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, v in _check_cache.items() if v[0] <= now]:
            del _check_cache[k]
        while len(_check_cache) >= _CACHE_MAX:
            _check_cache.pop(next(iter(_check_cache)))
    _check_cache[key] = (expiry, value)


def pick_dial_address(addrs: list[str]) -> str:
    """Choose the address to connect to: first IPv4 if any, else the first."""
    for a in addrs:
        if ':' not in a:
            return a
    return addrs[0]


def dial_order(addrs: list[str]) -> list[str]:
    """All checked addresses, IPv4 first (same preference as pick_dial_address)."""
    return [a for a in addrs if ':' not in a] + [a for a in addrs if ':' in a]


async def try_each_address(addrs: list[str], attempt, timeout: float | None):
    """Await `attempt(address)` for each checked address until one succeeds.

    `attempt` is a callable returning an awaitable (for example
    ``lambda a: asyncio.open_connection(a, port)``). Only connect-level
    failures (OSError, timeout) move on to the next address; any other error
    (authentication, protocol) is raised at once, so a login is never retried
    against another address. `timeout` is the total budget, shared evenly by
    the addresses that are left, so a hanging address cannot use it all up;
    with None the attempts are not time-limited here (the caller's own
    connect timeout applies to each).
    The last connect-level error is raised if every address fails.
    """
    order = dial_order(addrs)
    if not order:
        raise HostResolveError()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + (timeout or 0)
    last: BaseException = HostResolveError()
    for i, addr in enumerate(order):
        share = None if timeout is None else max(deadline - loop.time(), 0.1) / (len(order) - i)
        try:
            return await asyncio.wait_for(attempt(addr), share)
        except (OSError, asyncio.TimeoutError) as e:
            last = e
    raise last


# ---------------------------------------------------------------------------
# aiohttp: same policy at connect time (pins every connection, redirect hops
# and IP literals included; SNI and Host stay on the hostname)
# ---------------------------------------------------------------------------

# The connector override below relies on this private hook. If an aiohttp
# upgrade renames it, fail loudly at import instead of silently failing open.
if not hasattr(aiohttp.TCPConnector, "_resolve_host"):
    raise RuntimeError("aiohttp.TCPConnector._resolve_host missing: update host_check._CheckedConnector")


class _SSRFSafeResolver(aiohttp.resolver.DefaultResolver):
    """DNS resolver that rejects blocked addresses at connection time.

    Prevents DNS rebinding: even if a hostname changes its DNS between
    the initial check and the actual connection, this resolver catches it.
    """

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        result = await super().resolve(host, port, family)
        for entry in result:
            if is_blocked_address(entry["host"]):
                logger.warning(f"Outbound host check: {host!r} resolved to a blocked address at connect time")
                raise HostBlockedError()
        return result


class _CheckedConnector(aiohttp.TCPConnector):
    """TCPConnector that applies the policy to every host it is asked to dial."""

    async def _resolve_host(self, host, port, traces=None):
        if is_blocked_host(host) or is_blocked_host(host.rstrip('.')):
            raise HostBlockedError()
        literal = _normalise_ip(host)
        if literal is not None and is_blocked_address(literal):
            raise HostBlockedError()
        result = await super()._resolve_host(host, port, traces)
        for entry in result:
            if is_blocked_address(entry["host"]):
                logger.warning(f"Outbound host check: {host!r} resolved to a blocked address at connect time")
                raise HostBlockedError()
        return result


def _SSRFSafeConnector(**kwargs):
    """Create a TCPConnector that validates resolved IPs against the SSRF blocklist."""
    return _CheckedConnector(resolver=_SSRFSafeResolver(), **kwargs)
