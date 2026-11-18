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

# Cloudflare's published edge ranges (https://www.cloudflare.com/ips/), shipped with
# the release. A fetched list is judged against this one: it sets the broadest range
# a fetched list may hold and the part of it that must still be present.
CF_BUILTIN = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

# Cloudflare list sanity limits.
CF_MAX_NEW_PER_REFRESH = 5      # ranges per family that may be new compared with the trusted list
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


def canonical_ip(text) -> Optional[str]:
    """The one written form of an address: lower case, compressed, an IPv4-mapped
    IPv6 address folded to IPv4. None when the text is not an address.

    Blocks are stored and looked up in this form, so '2001:DB8::1' and
    '2001:db8::1' are the same block.
    """
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def broad_networks(nets: Iterable) -> list:
    """The networks broader than a never-ban entry may be (/8 IPv4, /16 IPv6)."""
    return [n for n in nets
            if n.prefixlen < (MIN_PREFIX_V4 if n.version == 4 else MIN_PREFIX_V6)]


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


def cf_builtin_networks() -> list:
    return [ipaddress.ip_network(n) for n in CF_BUILTIN]


def _cf_family(nets, version: int) -> list:
    return [n for n in nets if n.version == version]


def _covers(new_nets, old) -> bool:
    """True if one of `new_nets` equals `old` or contains it."""
    return any(n.version == old.version and old.subnet_of(n) for n in new_nets)


def validate_cf_lists(v4_text: str, v6_text: str, current: Optional[Iterable] = None,
                      compare_new: bool = True) -> list:
    """Parse both lists, enforce the size, breadth and shrink rules, return the combined networks.

    * No range may be broader than the broadest built-in range of its family
      (/13 IPv4, /29 IPv6 today): the list may not widen what is trusted.
    * Per family, at most CF_MAX_NEW_PER_REFRESH ranges may be new compared with
      `current`, the list trusted now (the built-in list until a refresh has
      worked). A range that is inside a current range is not new. Skipped with
      compare_new=False, for a list saved earlier that is checked again at start.
    * Per family, the list must still cover at least half of the built-in
      ranges, and (when `current` is given) at least half of the current ones.
      A range that equals or contains one counts as covering it.
    """
    builtin = cf_builtin_networks()
    v4 = parse_cf_list(v4_text, 4)
    v6 = parse_cf_list(v6_text, 6)
    if len(v4) < CF_MIN_V4:
        raise ListError(f"IPv4 list has {len(v4)} ranges, at least {CF_MIN_V4} are required")
    if len(v6) < CF_MIN_V6:
        raise ListError(f"IPv6 list has {len(v6)} ranges, at least {CF_MIN_V6} are required")
    if len(v4) > CF_MAX_PER_FAMILY or len(v6) > CF_MAX_PER_FAMILY:
        raise ListError(f"a list has more than {CF_MAX_PER_FAMILY} ranges")
    current = list(current or []) or builtin
    for version, nets in ((4, v4), (6, v6)):
        base = _cf_family(builtin, version)
        floor = min(n.prefixlen for n in base)
        for n in nets:
            if n.prefixlen < floor:
                raise ListError(
                    f"{n} is broader than any range Cloudflare publishes today: "
                    f"IPv{version} ranges must be /{floor} or narrower")
        if compare_new:
            have = _cf_family(current, version)
            new = [n for n in nets if not any(n.subnet_of(c) for c in have)]
            if len(new) > CF_MAX_NEW_PER_REFRESH:
                raise ListError(
                    f"{len(new)} new IPv{version} ranges in one refresh; at most "
                    f"{CF_MAX_NEW_PER_REFRESH} are accepted")
        for label, ref in (("built-in", base), ("current", _cf_family(current, version))):
            dropped = [r for r in ref if not _covers(nets, r)]
            if len(dropped) * 2 > len(ref):
                raise ListError(
                    f"the new IPv{version} list drops {len(dropped)} of {len(ref)} {label} ranges; "
                    f"refusing it")
    return v4 + v6


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
