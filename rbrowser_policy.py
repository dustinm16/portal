"""Egress deny list and Chromium managed policy for the server-side browser (design sections 6 and 7.1).

Pure functions: every input is injected (resolvers, interface addresses, gateways, the admin's list, the home
URL), nothing is read from the host here except by the small text parsers, which take the text as an argument.
Malformed input raises ValueError: the caller fails closed and starts no unit.

deny_list() -> the CIDR strings for the unit's IPAddressDeny=.  build_policy() -> the dict that is written as
/etc/chromium/policies/managed/portal.json inside the unit.
"""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit

# ---- 6.1 deny list: fixed ranges
FIXED_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
)
# mapped, NAT64, Teredo and 6to4 forms can carry an IPv4 destination; ::/96 is the deprecated IPv4-compatible form
# (::127.0.0.1) and ::ffff:0:0:0/96 the IPv4-translated one (::ffff:0:a9fe:a9fe, RFC 2765 / 6145)
FIXED_V6 = (
    "::/128", "::1/128", "::/96", "::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16",
    "fc00::/7", "fe80::/10", "ff00::/8",
)
# Cloud control addresses outside the ranges above (Azure WireServer). The metadata services of AWS, GCP,
# Oracle, DigitalOcean and Alibaba are inside the fixed ranges already.
CLOUD = ("168.63.129.16/32",)

# The prefix-length rule for the on-link prefix of an interface address (6.1 item 5).
ONLINK_MIN_V4 = 16
ONLINK_MIN_V6 = 48

MAX_EXTRA_DENY = 32
HOME_URL_MAX = 300

# ---- 6.2 DNS and 6.3 search
DOH_TEMPLATE = "https://1.1.1.1/dns-query"
SEARCH_URL = "https://duckduckgo.com/?q={searchTerms}"
DEFAULT_HOME_URL = "https://duckduckgo.com/"

# ---- 7.1: hosts that are always listed in URLBlocklist, and what may load
BLOCK_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "169.254.169.254", "168.63.129.16")
ALLOWLIST = ("http://*", "https://*", "about:blank", "data:*", "blob:*",
             "chrome://version", "chrome://policy", "chrome://sandbox")


def _strip_zone(text: str) -> str:
    return text.split("%", 1)[0]


def _addr(value) -> ipaddress._BaseAddress:
    """An IP address from text, a zone id (fe80::1%eth0) dropped and brackets removed. Raises ValueError."""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if not isinstance(value, str):
        raise ValueError("not an address")
    t = _strip_zone(value.strip())
    if t.startswith("[") and t.endswith("]"):
        t = t[1:-1]
    if not t or "/" in t:
        raise ValueError("not an address")
    return ipaddress.ip_address(t)


def _host(a) -> str:
    return f"[{a}]" if a.version == 6 else str(a)


def _iface_item(item):
    """(address, prefixlen or None) from 'addr', 'addr/len' or (addr, len-or-None)."""
    if isinstance(item, (tuple, list)):
        if len(item) != 2:
            raise ValueError("bad interface entry")
        addr, plen = item
    elif isinstance(item, str) and "/" in item:
        addr, _, p = item.partition("/")
        if not p.isdigit():
            raise ValueError("bad prefix length")
        plen = int(p)
    else:
        addr, plen = item, None
    a = _addr(addr)
    if plen is not None:
        if isinstance(plen, bool) or not isinstance(plen, int) or not (0 <= plen <= a.max_prefixlen):
            raise ValueError("bad prefix length")
    return a, plen


def _net_text(net) -> str:
    return str(net)


def deny_list(resolvers, iface_addrs, gateways, extra) -> list:
    """The IPAddressDeny list (CIDR strings), duplicates removed, fixed ranges first. Raises ValueError.

    resolvers: nameserver addresses of the host's resolv.conf files.
    iface_addrs: addresses of the local interfaces, each 'addr', 'addr/prefixlen' or (addr, prefixlen|None).
    gateways: default-gateway addresses.
    extra: the admin's list of CIDRs (rbrowser_extra_deny), validated by validate_extra_deny().
    """
    out = []
    seen = set()

    def add(text):
        if text not in seen:
            seen.add(text)
            out.append(text)

    for c in FIXED_V4 + FIXED_V6 + CLOUD:
        add(c)
    for r in resolvers or ():
        a = _addr(r)
        add(f"{a}/{a.max_prefixlen}")
    for item in iface_addrs or ():
        a, plen = _iface_item(item)
        add(f"{a}/{a.max_prefixlen}")
        floor = ONLINK_MIN_V4 if a.version == 4 else ONLINK_MIN_V6
        if plen is not None and plen >= floor and plen < a.max_prefixlen:
            add(_net_text(ipaddress.ip_network(f"{a}/{plen}", strict=False)))
    for g in gateways or ():
        a = _addr(g)
        add(f"{a}/{a.max_prefixlen}")
    for c in validate_extra_deny(extra or ()):
        add(c)
    return out


def literal_hosts(resolvers, iface_addrs, gateways) -> list:
    """Every resolver, interface and gateway address as a literal host for URLBlocklist (IPv6 in brackets)."""
    out = []
    seen = set()
    items = [_addr(r) for r in resolvers or ()]
    items += [_iface_item(i)[0] for i in iface_addrs or ()]
    items += [_addr(g) for g in gateways or ()]
    for a in items:
        h = _host(a)
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


# ---- text parsers for the inputs (pure: the caller reads the file)

def parse_resolv_conf(text: str) -> list:
    """Nameserver addresses of a resolv.conf; lines that are not an address are skipped."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                a = _addr(parts[1])
            except ValueError:
                continue
            if str(a) not in out:
                out.append(str(a))
    return out


def parse_proc_net_route(text: str) -> list:
    """Default gateways from /proc/net/route (hex, little-endian)."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        try:
            dest, gw, mask = int(f[1], 16), int(f[2], 16), int(f[7], 16)
        except ValueError:
            continue
        if dest == 0 and mask == 0 and gw != 0:
            a = str(ipaddress.IPv4Address(int.from_bytes(gw.to_bytes(4, "big"), "little")))
            if a not in out:
                out.append(a)
    return out


def parse_proc_net_ipv6_route(text: str) -> list:
    """Default gateways from /proc/net/ipv6_route."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 10 or len(f[0]) != 32 or len(f[4]) != 32:
            continue
        if int(f[0], 16) == 0 and int(f[1], 16) == 0 and int(f[4], 16) != 0:
            a = str(ipaddress.IPv6Address(bytes.fromhex(f[4])))
            if a not in out:
                out.append(a)
    return out


def parse_proc_net_ipv6_route_scoped(text: str) -> list:
    """Like parse_proc_net_ipv6_route, but a link-local gateway keeps its device as the zone (fe80::1%eth0), which
    is what a connect() to it needs. Every other gateway stays a plain address. For probe_targets(); deny_list()
    and literal_hosts() drop the zone again, so either form may be passed to them."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 10 or len(f[0]) != 32 or len(f[4]) != 32:
            continue
        if int(f[0], 16) == 0 and int(f[1], 16) == 0 and int(f[4], 16) != 0:
            a = ipaddress.IPv6Address(bytes.fromhex(f[4]))
            dev = f[9]
            text_a = str(a)
            if a.is_link_local and re.fullmatch(r"[A-Za-z0-9._-]{1,15}", dev):
                text_a = f"{text_a}%{dev}"
            if text_a not in out:
                out.append(text_a)
    return out


def iface_from_psutil(mapping) -> list:
    """[(address, prefixlen or None)] from psutil.net_if_addrs(): only AF_INET and AF_INET6 entries."""
    out = []
    for entries in mapping.values():
        for e in entries:
            fam = getattr(e.family, "name", str(e.family))
            if fam not in ("AF_INET", "AF_INET6"):
                continue
            plen = None
            mask = getattr(e, "netmask", None)
            if mask:
                try:
                    m = ipaddress.ip_address(_strip_zone(mask))
                    inv = int(m) ^ ((1 << m.max_prefixlen) - 1)
                    if inv & (inv + 1) == 0:  # contiguous mask
                        plen = bin(int(m)).count("1")
                except ValueError:
                    plen = None
            out.append((_strip_zone(e.address), plen))
    return out


# ---- validators

def validate_extra_deny(value) -> list:
    """The admin's list: a list of strings or one text split on commas and white space. Each entry a CIDR with
    no host bits set (a bare address is a /32 or /128); /0 refused; at most 32; duplicates removed.
    Returns the normalised strings. Raises ValueError."""
    if isinstance(value, str):
        entries = [p for p in re.split(r"[,\s]+", value.strip()) if p]
    else:
        entries = list(value)
    out = []
    for e in entries:
        if not isinstance(e, str):
            raise ValueError("not a CIDR")
        e = e.strip()
        if not e or e.isspace() or "%" in e:
            raise ValueError("not a CIDR")
        net = ipaddress.ip_network(e, strict=True)
        if net.prefixlen == 0:
            raise ValueError("a /0 would deny everything")
        t = str(net)
        if t not in out:
            out.append(t)
    if len(out) > MAX_EXTRA_DENY:
        raise ValueError(f"at most {MAX_EXTRA_DENY} entries")
    return out


_BAD_URL_CHARS = set(' "<>\\^`{}|%\'')

_DENIED_NETS = tuple(ipaddress.ip_network(n) for n in FIXED_V4 + FIXED_V6 + CLOUD)


def _denied_literal(ip) -> bool:
    """True when this address is inside the fixed deny list (the same networks as deny_list(): loopback, private,
    link-local, metadata, multicast, mapped / NAT64 / Teredo / 6to4 forms) or is not global. An IPv4-mapped IPv6
    address is also judged by the IPv4 address it carries."""
    if not ip.is_global:
        return True
    if any(ip.version == n.version and ip in n for n in _DENIED_NETS):
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped is not None and _denied_literal(mapped)


def validate_home_url(url) -> str:
    """An https URL of at most 300 printable ASCII characters, with a host name or a global IP literal, no
    user information, no percent signs. Returns it unchanged. Raises ValueError."""
    if not isinstance(url, str) or not url or len(url) > HOME_URL_MAX:
        raise ValueError("home URL empty or longer than 300 characters")
    if any(not (0x21 <= ord(c) <= 0x7E) or c in _BAD_URL_CHARS for c in url):
        raise ValueError("home URL has a character that is not allowed")
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError as e:
        raise ValueError("home URL does not parse") from e
    if parts.scheme != "https":
        raise ValueError("home URL must be https")
    if not host or "@" in parts.netloc:
        raise ValueError("home URL needs a host and no user information")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("bad port")
    host = host.lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _denied_literal(ip):
            raise ValueError("home URL names a non-public address")
    else:
        # one trailing dot (the absolute form, https://localhost./) is the same name
        host = host[:-1] if host.endswith(".") else host
        if host == "localhost" or host.endswith(".localhost") or "." not in host:
            raise ValueError("home URL needs a public host name")
        labels = host.split(".")
        if any(not l or len(l) > 63 or l.startswith("-") or l.endswith("-")
               or not re.fullmatch(r"[a-z0-9-]+", l) for l in labels):
            raise ValueError("bad host name")
        # a numeric last label is an IPv4 form (2130706433, 0x7f.1) to a browser
        if labels[-1].isdigit() or labels[-1].startswith("0x"):
            raise ValueError("home URL host looks like a number")
    return url


def validate_doh_template(template) -> str:
    """https://<IP literal>[:port]/path - a host name would need the host resolver, which is denied."""
    if not isinstance(template, str) or not re.fullmatch(r"https://[0-9A-Fa-f.:\[\]]+(:[0-9]{1,5})?/[A-Za-z0-9._~/-]+", template):
        raise ValueError("DoH template must be https://<IP literal>[:port]/path")
    parts = urlsplit(template)
    host = parts.hostname
    ip = ipaddress.ip_address(host)  # raises ValueError for a name
    if _denied_literal(ip):
        raise ValueError("DoH template names a non-public address")
    if parts.port is not None and not (1 <= parts.port <= 65535):
        raise ValueError("bad port")
    return template


def _block_literal(value) -> str:
    if isinstance(value, str) and ("/" in value or "*" in value):
        raise ValueError("URLBlocklist takes literal hosts, never ranges or wildcards")
    return _host(_addr(value))


# ---- 7.1 the managed policy

def build_policy(home_url, literal_hosts) -> dict:
    """The JSON object of section 7.1. literal_hosts: resolver, interface and gateway addresses (any form
    _addr accepts); they are added to URLBlocklist as literal hosts, never as ranges."""
    validate_home_url(home_url)
    validate_doh_template(DOH_TEMPLATE)
    block = ["*"] + list(BLOCK_HOSTS)
    for h in literal_hosts or ():
        lit = _block_literal(h)
        if lit not in block:
            block.append(lit)
    return {
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": DOH_TEMPLATE,
        "URLBlocklist": block,
        "URLAllowlist": list(ALLOWLIST),
        "ExternalProtocolDialogShowAlwaysOpenCheckbox": False,
        "ProxyMode": "direct",
        "QuicAllowed": False,
        "FullscreenAllowed": False,
        "AllowFileSelectionDialogs": False,
        "DownloadRestrictions": 3,
        "DeveloperToolsAvailability": 2,
        "ExtensionInstallBlocklist": ["*"],
        "BlockExternalExtensions": True,
        "PasswordManagerEnabled": False,
        "AutofillAddressEnabled": False,
        "AutofillCreditCardEnabled": False,
        "PaymentMethodQueryEnabled": False,
        "BrowserSignin": 0,
        "SyncDisabled": True,
        "BrowserAddPersonEnabled": False,
        "BrowserGuestModeEnabled": False,
        "MetricsReportingEnabled": False,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
        "UserFeedbackAllowed": False,
        "ComponentUpdatesEnabled": False,
        "BackgroundModeEnabled": False,
        "SafeBrowsingProtectionLevel": 0,
        "SearchSuggestEnabled": False,
        "NetworkPredictionOptions": 2,
        "AlternateErrorPagesEnabled": False,
        "TranslateEnabled": False,
        "SpellcheckEnabled": False,
        "PromotionalTabsEnabled": False,
        "DefaultBrowserSettingEnabled": False,
        "PrintingEnabled": False,
        "EnableMediaRouter": False,
        "AudioCaptureAllowed": False,
        "VideoCaptureAllowed": False,
        "ScreenCaptureAllowed": False,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "DefaultGeolocationSetting": 2,
        "DefaultNotificationsSetting": 2,
        "DefaultSensorsSetting": 2,
        "DefaultWebBluetoothGuardSetting": 2,
        "DefaultWebUsbGuardSetting": 2,
        "DefaultSerialGuardSetting": 2,
        "DefaultWebHidGuardSetting": 2,
        "DefaultFileSystemReadGuardSetting": 2,
        "DefaultFileSystemWriteGuardSetting": 2,
        "DefaultLocalFontsSetting": 2,
        "DefaultWindowManagementSetting": 2,
        "GenAiDefaultSettings": 2,
        "ShowFullUrlsInAddressBar": True,
        "BookmarkBarEnabled": False,
        "EditBookmarksEnabled": False,
        "HomepageLocation": home_url,
        "HomepageIsNewTabPage": False,
        "NewTabPageLocation": home_url,
        "RestoreOnStartup": 5,
        "DefaultSearchProviderEnabled": True,
        "DefaultSearchProviderName": "Search",
        "DefaultSearchProviderSearchURL": SEARCH_URL,
    }


def policy_text(policy: dict) -> str:
    return json.dumps(policy, indent=2) + "\n"


# The preflight probe and the live test's page loads run headless Chromium (`--dump-dom`), which reads the page through
# the DevTools machinery: with DeveloperToolsAvailability=2 it hangs until killed (bisected on the live host, round 1).
# So those runs get the managed policy without this one key; the real sessions have the full policy (they start no
# debugging channel since D3, so nothing there needs the key).
PROBE_POLICY_DROP = ("DeveloperToolsAvailability",)


def probe_policy(policy: dict) -> dict:
    """The policy of a headless probe unit: every key of `policy` except PROBE_POLICY_DROP."""
    return {k: v for k, v in policy.items() if k not in PROBE_POLICY_DROP}


# ---- the member's portal theme (release 1.26.0): two validated values, nothing else
#
# The page sends a colour (#rrggbb) and a mode (dark | light). The colour reaches Chromium only as the managed policy
# BrowserThemeColor, in a file of its own that theme_policy() builds from the validated value (never from a member's
# string); the mode reaches the supervisor as RB_THEME_MODE (rbrowser_unit/session.py turns "dark" into
# --force-dark-mode). The measurement (Chromium 156 under Xvfb) is in the 1.26.0 notes: BrowserThemeColor colours the tab
# strip and toolbar and picks the text contrast; the BrowserColorScheme policy changed neither the browser UI nor
# prefers-color-scheme here, --force-dark-mode changed both and did not recolour page content.
THEME_COLOR_RE = re.compile(r"#[0-9a-f]{6}")
THEME_MODES = ("dark", "light")
THEME_POLICY_KEYS = ("BrowserThemeColor",)     # the only keys the per-session theme file may hold
THEME_FILE_NAME = "portal-theme.json"
# Chromium merges every file of the managed directory in file-name order and the LATER name wins a duplicate key (measured: with
# portal.json, a.json and z.json each setting BrowserThemeColor, z.json won; portal-theme.json against portal.json: portal.json won).
# "portal-theme.json" sorts before "portal.json" ('-' is 0x2d, '.' is 0x2e), so even a duplicate key could never override the main file.
THEME_PLACEHOLDER_TEXT = "{}\n"


def normalise_theme(color, mode) -> tuple:
    """(color or None, mode or None). The colour is "#rrggbb" after lower-casing, the mode "dark" or "light"; anything else
    (a wrong type, other text, a missing value) is None, which means the neutral default. Never raises."""
    c = m = None
    if isinstance(color, str) and len(color) == 7:
        low = color.lower()
        if THEME_COLOR_RE.fullmatch(low):
            c = low
    if isinstance(mode, str) and len(mode) <= 5:
        low = mode.lower()
        if low in THEME_MODES:
            m = low
    return c, m


def theme_policy(color, mode) -> dict:
    """The policy document of the per-session theme file: exactly THEME_POLICY_KEYS (BrowserThemeColor) and only when the
    colour is valid; {} otherwise. The mode is validated and takes no key (it is the supervisor's --force-dark-mode).
    Built from the validated values only, so no member-supplied text can add a key or change a value."""
    c, _m = normalise_theme(color, mode)
    return {"BrowserThemeColor": c} if c else {}
