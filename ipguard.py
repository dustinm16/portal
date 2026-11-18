"""Address-list helpers for lockout-safe blocking and the Cloudflare range refresh.

Pure functions plus one small fetcher; nothing here touches the database or the
running server. server.py owns the state and calls these to validate input.
"""

import ipaddress
import re
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit

# A never-ban entry must not be able to switch protection off by covering most
# of the internet: nothing broader than these prefixes is accepted.
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 16
MAX_NEVER_BAN_ENTRIES = 100

# Cloudflare list sanity limits.
CF_MIN_V4 = 10
CF_MIN_V6 = 5
CF_MAX_PER_FAMILY = 100
CF_MAX_BYTES = 64 * 1024
CF_TIMEOUT_SECONDS = 10
CF_MAX_REDIRECTS = 2
CF_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
CF_USER_AGENT = "Mozilla/5.0 (compatible; ip-list-refresh)"

_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_ENTRY_RE = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$")


class ListError(ValueError):
    """An address list or entry was refused. The message is safe to show."""


def _check_breadth(net) -> None:
    floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    if net.prefixlen < floor:
        raise ListError(
            f"{net} is too broad: IPv{net.version} ranges must be /{floor} or narrower"
        )


def parse_cidr_entry(text) -> "ipaddress._BaseNetwork":
    """One never-ban entry: an IP address or a strict CIDR network."""
    if not isinstance(text, str):
        raise ListError("each entry must be a string")
    s = text.strip()
    if not s or len(s) > 64 or not _ENTRY_RE.match(s):
        raise ListError(f"{s[:40]!r} is not an IP address or CIDR network")
    try:
        net = ipaddress.ip_network(s, strict=True)
    except ValueError as e:
        raise ListError(f"{s}: {e}")
    if net.version == 6 and net.overlaps(_V4_MAPPED):
        raise ListError(f"{s} overlaps the IPv4-mapped range; write the IPv4 form instead")
    _check_breadth(net)
    return net


def validate_cidr_list(entries) -> list:
    """Validate an admin-supplied list. Returns normalised networks (deduplicated, input order).

    Raises ListError naming the first problem. At most MAX_NEVER_BAN_ENTRIES entries.
    """
    if not isinstance(entries, list):
        raise ListError("entries must be a list")
    if len(entries) > MAX_NEVER_BAN_ENTRIES:
        raise ListError(f"at most {MAX_NEVER_BAN_ENTRIES} entries are allowed")
    seen, out = set(), []
    for item in entries:
        net = parse_cidr_entry(item)
        if net not in seen:
            seen.add(net)
            out.append(net)
    return out


def parse_env_cidrs(text: str) -> tuple:
    """NEVER_BAN_CIDRS: comma or space separated. Returns (networks, warnings).

    Same rules as the admin list; a bad entry is skipped with a warning rather
    than stopping the server from starting.
    """
    nets, warnings, seen = [], [], set()
    for item in re.split(r"[,\s]+", text or ""):
        if not item:
            continue
        if len(nets) >= MAX_NEVER_BAN_ENTRIES:
            warnings.append(f"more than {MAX_NEVER_BAN_ENTRIES} entries; the rest are ignored")
            break
        try:
            net = parse_cidr_entry(item)
        except ListError as e:
            warnings.append(f"ignored NEVER_BAN_CIDRS entry: {e}")
            continue
        if net not in seen:
            seen.add(net)
            nets.append(net)
    return nets, warnings


def addr_in_networks(addr, nets: Iterable) -> bool:
    return any(addr.version == n.version and addr in n for n in nets)


# ---------------------------------------------------------------------------
# Cloudflare published lists
# ---------------------------------------------------------------------------

def parse_cf_list(text: str, version: int) -> list:
    """Parse one published list (one network per line). Any bad line refuses the whole list."""
    nets, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not _ENTRY_RE.match(line) or len(line) > 64:
            raise ListError(f"line is not a network: {line[:40]!r}")
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError:
            raise ListError(f"line is not a network: {line[:40]!r}")
        if net.version != version:
            raise ListError(f"{net} is not an IPv{version} range")
        _check_breadth(net)
        if (not net.is_global or net.is_private or net.is_loopback or net.is_reserved
                or net.is_link_local or net.is_multicast or net.is_unspecified):
            raise ListError(f"{net} is not a public range")
        if net not in seen:
            seen.add(net)
            nets.append(net)
    return nets


def validate_cf_lists(v4_text: str, v6_text: str, current: Optional[Iterable] = None) -> list:
    """Parse both lists, enforce the size and shrink rules, return the combined networks.

    `current` is the set of Cloudflare ranges trusted now. A new list that no
    longer covers more than half of them is refused: that is a damaged or
    poisoned answer, not an update.
    """
    v4 = parse_cf_list(v4_text, 4)
    v6 = parse_cf_list(v6_text, 6)
    if len(v4) < CF_MIN_V4:
        raise ListError(f"IPv4 list has {len(v4)} ranges, at least {CF_MIN_V4} are required")
    if len(v6) < CF_MIN_V6:
        raise ListError(f"IPv6 list has {len(v6)} ranges, at least {CF_MIN_V6} are required")
    if len(v4) > CF_MAX_PER_FAMILY or len(v6) > CF_MAX_PER_FAMILY:
        raise ListError(f"a list has more than {CF_MAX_PER_FAMILY} ranges")
    new = v4 + v6
    current = list(current or [])
    if current:
        dropped = [c for c in current if not any(c.version == n.version and c.subnet_of(n) for n in new)]
        if len(dropped) * 2 > len(current):
            raise ListError(
                f"the new list drops {len(dropped)} of {len(current)} trusted ranges; refusing it"
            )
    return new


class FetchError(Exception):
    """A fetch failed. The message is safe to show in the admin page."""


async def fetch_text(url: str, ssl_context=None) -> str:
    """GET one plain-text list over HTTPS and return it as ASCII text.

    Certificate verification is on (ssl_context is only for tests that must
    trust a local certificate). Redirects are followed only within the same
    host and over HTTPS; there is a 10 s timeout, a 64 KB cap and no cookies.
    Nothing from the portal or its users is sent.
    """
    import aiohttp

    first = urlsplit(url)
    if first.scheme != "https" or not first.hostname:
        raise FetchError("the list URL must be https")
    headers = {"User-Agent": CF_USER_AGENT, "Accept": "text/plain", "Accept-Encoding": "identity"}
    timeout = aiohttp.ClientTimeout(total=CF_TIMEOUT_SECONDS)
    current = url
    try:
        async with aiohttp.ClientSession(
            timeout=timeout, cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
            connector=aiohttp.TCPConnector(ssl=ssl_context if ssl_context is not None else True),
        ) as session:
            for _ in range(CF_MAX_REDIRECTS + 1):
                async with session.get(current, allow_redirects=False, headers=headers) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        target = urljoin(current, resp.headers.get("Location", ""))
                        parts = urlsplit(target)
                        if (parts.scheme != "https" or parts.hostname != first.hostname
                                or (parts.port or 443) != (first.port or 443)):
                            raise FetchError("redirected to a different host; refused")
                        current = target
                        continue
                    if resp.status != 200:
                        raise FetchError(f"HTTP status {resp.status}")
                    declared = resp.content_length
                    if declared is not None and declared > CF_MAX_BYTES:
                        raise FetchError("response is larger than 64 KB")
                    data = bytearray()
                    async for chunk in resp.content.iter_chunked(4096):
                        data += chunk
                        if len(data) > CF_MAX_BYTES:
                            raise FetchError("response is larger than 64 KB")
                    try:
                        return bytes(data).decode("ascii")
                    except UnicodeDecodeError:
                        raise FetchError("response is not plain ASCII text")
            raise FetchError("too many redirects")
    except FetchError:
        raise
    except aiohttp.ClientConnectorCertificateError:
        raise FetchError("certificate verification failed")
    except aiohttp.ClientSSLError:
        raise FetchError("TLS error")
    except TimeoutError:
        raise FetchError("timed out")
    except aiohttp.ClientError as e:
        raise FetchError(f"request failed ({type(e).__name__})")
    except OSError as e:
        raise FetchError(f"network error ({type(e).__name__})")
