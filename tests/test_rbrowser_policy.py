"""Server-side browser: the egress deny list and the Chromium managed policy (design 6.1, 6.2, 7.1, 13).

Run: venv/bin/python tests/test_rbrowser_policy.py

* deny_list: the fixed IPv4 and IPv6 ranges (incl. mapped, NAT64, Teredo, 6to4), the cloud address, resolver,
  interface, on-link prefix (prefix-length rule), gateway and admin inputs; zone ids; malformed input raises
* the text parsers for resolv.conf, /proc/net/route, /proc/net/ipv6_route and psutil's interface table
* build_policy returns exactly the JSON of section 7.1 (a full copy is pinned below, so a missing, extra or
  changed key fails); URLBlocklist[0] == "*", no CIDR and no *.localhost in it; the allow-list is exact
* DOH_TEMPLATE is an IP literal; validators for home_url, extra_deny and the DoH template
"""

import ipaddress
from urllib.parse import urlsplit
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rbrowser_policy as P  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def raises(fn, *a, **k):
    try:
        fn(*a, **k)
    except ValueError:
        return True
    except Exception as e:  # a wrong exception type is a failure
        print("   unexpected", type(e).__name__, e)
        return False
    return False


# The policy of design section 7.1, copied. "@BLOCK@" and "@HOME@" stand for the computed values.
EXPECTED_TEXT = r'''
{
  "DnsOverHttpsMode": "secure",
  "DnsOverHttpsTemplates": "https://1.1.1.1/dns-query",
  "URLBlocklist": "@BLOCK@",
  "URLAllowlist": ["http://*", "https://*", "about:blank", "data:*", "blob:*",
    "chrome://version", "chrome://policy", "chrome://sandbox"],
  "ExternalProtocolDialogShowAlwaysOpenCheckbox": false,
  "ProxyMode": "direct",
  "QuicAllowed": false,
  "FullscreenAllowed": false,
  "AllowFileSelectionDialogs": false,
  "DownloadRestrictions": 3,
  "DeveloperToolsAvailability": 2,
  "ExtensionInstallBlocklist": ["*"],
  "BlockExternalExtensions": true,
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "PaymentMethodQueryEnabled": false,
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "BrowserAddPersonEnabled": false,
  "BrowserGuestModeEnabled": false,
  "MetricsReportingEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "UserFeedbackAllowed": false,
  "ComponentUpdatesEnabled": false,
  "BackgroundModeEnabled": false,
  "SafeBrowsingProtectionLevel": 0,
  "SearchSuggestEnabled": false,
  "NetworkPredictionOptions": 2,
  "AlternateErrorPagesEnabled": false,
  "TranslateEnabled": false,
  "SpellcheckEnabled": false,
  "PromotionalTabsEnabled": false,
  "DefaultBrowserSettingEnabled": false,
  "PrintingEnabled": false,
  "EnableMediaRouter": false,
  "AudioCaptureAllowed": false,
  "VideoCaptureAllowed": false,
  "ScreenCaptureAllowed": false,
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
  "ShowFullUrlsInAddressBar": true,
  "BookmarkBarEnabled": false,
  "EditBookmarksEnabled": false,
  "HomepageLocation": "@HOME@",
  "HomepageIsNewTabPage": false,
  "NewTabPageLocation": "@HOME@",
  "RestoreOnStartup": 5,
  "DefaultSearchProviderEnabled": true,
  "DefaultSearchProviderName": "Search",
  "DefaultSearchProviderSearchURL": "https://duckduckgo.com/?q={searchTerms}"
}
'''

# ---- deny_list
def covers(deny, addr):
    a = ipaddress.ip_address(addr)
    return any(a in ipaddress.ip_network(c) for c in deny if ipaddress.ip_network(c).version == a.version)


base = P.deny_list([], [], [], [])
FIX4 = "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4".split()
FIX6 = "::/128 ::1/128 ::/96 ::ffff:0:0/96 ::ffff:0:0:0/96 64:ff9b::/96 64:ff9b:1::/48 2001::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8".split()
check("fixed IPv4 ranges all present", all(c in base for c in FIX4), str([c for c in FIX4 if c not in base]))
check("fixed IPv6 ranges all present (mapped, NAT64, Teredo, 6to4 included)", all(c in base for c in FIX6), str([c for c in FIX6 if c not in base]))
check("the Azure WireServer is in the list", "168.63.129.16/32" in base)
check("with no inputs the list is exactly groups 1 to 3", base == FIX4 + FIX6 + ["168.63.129.16/32"], str(base))
check("metadata addresses are covered (169.254.169.254, fd00:ec2::254, 100.100.100.200)",
      all(covers(base, a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")))
check("loopback, mapped loopback and mapped metadata are covered",
      all(covers(base, a) for a in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254")))
check("the IPv4-compatible and IPv4-translated forms are covered (::127.0.0.1, ::169.254.169.254, ::ffff:0:a9fe:a9fe)",
      all(covers(base, a) for a in ("::127.0.0.1", "::169.254.169.254", "::ffff:0:a9fe:a9fe", "::ffff:0:7f00:1")))
check("a public address is not covered", not covers(base, "1.1.1.1") and not covers(base, "2606:4700::1111"))
check("every entry is a valid CIDR with no host bits", all(str(ipaddress.ip_network(c)) == c for c in base))

d = P.deny_list(["8.8.8.8", "fe80::53%eth0", "[2001:4860:4860::8888]"], [], [], [])
check("resolver addresses become /32 and /128 entries",
      "8.8.8.8/32" in d and "fe80::53/128" in d and "2001:4860:4860::8888/128" in d, str(d[-3:]))
d = P.deny_list([], [("203.0.113.9", 24)], [], [])
check("interface address: /32 and its on-link prefix when the prefix is /16 or longer",
      "203.0.113.9/32" in d and "203.0.113.0/24" in d)
d = P.deny_list([], [("203.0.113.9", 16)], [], [])
check("IPv4 prefix /16 counts (the boundary)", "203.0.0.0/16" in d)
d = P.deny_list([], [("203.0.113.9", 15)], [], [])
check("IPv4 prefix /15 adds the address only", "203.0.113.9/32" in d and not any(c.startswith("203.0.") and c != "203.0.113.9/32" for c in d))
d = P.deny_list([], [("203.0.113.9", 32)], [], [])
check("IPv4 /32 adds only the address once", d.count("203.0.113.9/32") == 1 and len(d) == len(base) + 1)
d = P.deny_list([], [("2001:db8:1:2::5", 64)], [], [])
check("IPv6 prefix /64 adds the address and the prefix", "2001:db8:1:2::5/128" in d and "2001:db8:1:2::/64" in d)
d = P.deny_list([], [("2001:db8:1:2::5", 48)], [], [])
check("IPv6 prefix /48 counts (the boundary)", "2001:db8:1::/48" in d)
d = P.deny_list([], [("2001:db8:1:2::5", 47)], [], [])
check("IPv6 prefix /47 adds the address only", "2001:db8:1:2::5/128" in d and not any(c.endswith("/47") for c in d))
d = P.deny_list([], [("fe80::1%eth0", 64)], [], [])
check("a zone id is stripped from an interface address", "fe80::1/128" in d and not any("%" in c for c in d))
d = P.deny_list([], ["203.0.113.9/24", "203.0.113.9"], [], [])
check("interface entries may be 'addr/len' or a bare address", "203.0.113.0/24" in d and d.count("203.0.113.9/32") == 1)
d = P.deny_list([], [], ["203.0.113.1", "2001:db8::1"], [])
check("gateways become single-address entries", "203.0.113.1/32" in d and "2001:db8::1/128" in d)
d = P.deny_list([], [], [], ["198.51.100.0/24", "2001:db8:abcd::/48", "203.0.113.5"])
check("extra list entries are added, a bare address is a /32",
      "198.51.100.0/24" in d and "2001:db8:abcd::/48" in d and "203.0.113.5/32" in d)
d = P.deny_list(["8.8.8.8", "8.8.8.8"], [("8.8.8.8", 32)], ["8.8.8.8"], ["8.8.8.8"])
check("duplicates appear once", d.count("8.8.8.8/32") == 1)
d1 = P.deny_list(["9.9.9.9"], [("203.0.113.9", 24)], ["203.0.113.1"], ["198.51.100.0/24"])
d2 = P.deny_list(["9.9.9.9"], [("203.0.113.9", 24)], ["203.0.113.1"], ["198.51.100.0/24"])
check("the result is deterministic", d1 == d2)
check("malformed resolver raises", raises(P.deny_list, ["not-an-ip"], [], [], []))
check("malformed interface address raises", raises(P.deny_list, [], ["999.1.1.1"], [], []))
check("bad prefix length raises", raises(P.deny_list, [], [("203.0.113.9", 33)], [], []) and raises(P.deny_list, [], [("2001:db8::1", 129)], [], []))
check("malformed gateway raises", raises(P.deny_list, [], [], ["1.2.3"], []))
check("malformed extra entry raises", raises(P.deny_list, [], [], [], ["10.0.0.0/33"]))
check("an extra entry with host bits set raises", raises(P.deny_list, [], [], [], ["203.0.113.5/24"]))
check("an extra /0 raises", raises(P.deny_list, [], [], [], ["0.0.0.0/0"]) and raises(P.deny_list, [], [], [], ["::/0"]))
check("a non-string extra entry raises", raises(P.deny_list, [], [], [], [123]))

# ---- validate_extra_deny
check("extra: text split on commas, spaces and newlines", P.validate_extra_deny("198.51.100.0/24, 203.0.113.5\n2001:db8::/32") ==
      ["198.51.100.0/24", "203.0.113.5/32", "2001:db8::/32"])
check("extra: empty text is an empty list", P.validate_extra_deny("") == [] and P.validate_extra_deny([]) == [])
check("extra: 32 entries accepted, 33 refused",
      len(P.validate_extra_deny([f"198.51.100.{i}" for i in range(32)])) == 32
      and raises(P.validate_extra_deny, [f"198.51.100.{i}" for i in range(33)]))
check("extra: a name, a range with a space and a zone id are refused",
      all(raises(P.validate_extra_deny, [x]) for x in ("example.com", "10.0.0.1 - 10.0.0.9", "fe80::1%eth0", "10.0.0.0/8x")))

# ---- parsers
RESOLV = """# generated
nameserver 168.63.129.16
nameserver fe80::1%eth0   # comment
nameserver bogus
search example.com
options edns0
;nameserver 9.9.9.9
nameserver 168.63.129.16
"""
check("resolv.conf parser", P.parse_resolv_conf(RESOLV) == ["168.63.129.16", "fe80::1"], str(P.parse_resolv_conf(RESOLV)))
ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0
"""
check("/proc/net/route: only default routes with a gateway, little-endian decoded",
      P.parse_proc_net_route(ROUTE) == ["192.168.0.1", "192.168.1.1"], str(P.parse_proc_net_route(ROUTE)))
ROUTE6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
          "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
          "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")
check("/proc/net/ipv6_route: only default routes with a next hop",
      P.parse_proc_net_ipv6_route(ROUTE6) == ["fe80::1"], str(P.parse_proc_net_ipv6_route(ROUTE6)))
ROUTE6_GUA = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003 eth1\n")
check("/proc/net/ipv6_route scoped: a link-local gateway keeps its device as the zone, a global one stays plain",
      P.parse_proc_net_ipv6_route_scoped(ROUTE6) == ["fe80::1%eth0"] and P.parse_proc_net_ipv6_route_scoped(ROUTE6_GUA) == ["2001:db8::1"],
      str(P.parse_proc_net_ipv6_route_scoped(ROUTE6)))
check("scoped gateways go through deny_list and literal_hosts unchanged (the zone is dropped there)",
      P.deny_list([], [], ["fe80::1%eth0"], []) == P.deny_list([], [], ["fe80::1"], []) and P.literal_hosts([], [], ["fe80::1%eth0"]) == P.literal_hosts([], [], ["fe80::1"]))
check("route parsers survive garbage", P.parse_proc_net_route("junk\nx y z\n") == [] and P.parse_proc_net_ipv6_route("junk\n") == [] and P.parse_proc_net_ipv6_route_scoped("junk\n") == [])


class _Fam:
    def __init__(self, name):
        self.name = name


class _Addr:
    def __init__(self, fam, address, netmask):
        self.family, self.address, self.netmask = _Fam(fam), address, netmask


mapping = {"eth0": [_Addr("AF_INET", "10.1.2.3", "255.255.255.0"), _Addr("AF_PACKET", "aa:bb:cc:dd:ee:ff", None),
                    _Addr("AF_INET6", "fe80::1%eth0", "ffff:ffff:ffff:ffff::")],
           "lo": [_Addr("AF_INET", "127.0.0.1", "255.0.0.0"), _Addr("AF_INET", "1.2.3.4", "255.0.255.0")]}
got = P.iface_from_psutil(mapping)
check("psutil table: AF_INET and AF_INET6 only, mask turned into a prefix length, zone stripped, odd mask -> None",
      got == [("10.1.2.3", 24), ("fe80::1", 64), ("127.0.0.1", 8), ("1.2.3.4", None)], str(got))
d = P.deny_list([], got, [], [])
check("psutil table feeds deny_list", "10.1.2.0/24" in d and "fe80::/64" in d)

# ---- literal hosts
lh = P.literal_hosts(["8.8.8.8"], [("203.0.113.9", 24), ("2001:db8::5", 64), ("fe80::1%eth0", 64)], ["203.0.113.1", "8.8.8.8"])
check("literal hosts: addresses only, IPv6 in brackets, no zone, no ranges, once each",
      lh == ["8.8.8.8", "203.0.113.9", "[2001:db8::5]", "[fe80::1]", "203.0.113.1"], str(lh))

# ---- policy
HOME = "https://duckduckgo.com/"
EXPECTED = json.loads(EXPECTED_TEXT.replace('"@BLOCK@"', "[]").replace("@HOME@", HOME))
pol = P.build_policy(HOME, [])
want = dict(EXPECTED)
want["URLBlocklist"] = ["*", "localhost", "127.0.0.1", "0.0.0.0", "[::1]", "169.254.169.254", "168.63.129.16"]
check("policy equals the section 7.1 JSON exactly (same keys, same values)", pol == want,
      str({k for k in set(pol) | set(want) if pol.get(k) != want.get(k)}))
check("policy has exactly the keys of section 7.1, in order", list(pol) == list(want) and len(pol) == 62, str(len(pol)))
check("the pinned expectation itself has 62 keys", len(EXPECTED) == 62)
check("URLBlocklist[0] == '*'", pol["URLBlocklist"][0] == "*")
check("URLAllowlist exact", pol["URLAllowlist"] == ["http://*", "https://*", "about:blank", "data:*", "blob:*",
                                                    "chrome://version", "chrome://policy", "chrome://sandbox"])
for k, v in (("FullscreenAllowed", False), ("QuicAllowed", False), ("ProxyMode", "direct"), ("DownloadRestrictions", 3),
             ("DeveloperToolsAvailability", 2), ("AllowFileSelectionDialogs", False), ("DnsOverHttpsMode", "secure"),
             ("ExtensionInstallBlocklist", ["*"]), ("WebRtcIPHandling", "disable_non_proxied_udp"),
             ("PasswordManagerEnabled", False), ("RestoreOnStartup", 5), ("SafeBrowsingProtectionLevel", 0),
             ("DefaultSearchProviderSearchURL", "https://duckduckgo.com/?q={searchTerms}")):
    check(f"policy {k} = {v!r}", pol[k] == v)
_pp = P.probe_policy(pol)
check("probe policy: the same policy without DeveloperToolsAvailability (headless Chromium hangs under it), the input untouched",
      "DeveloperToolsAvailability" not in _pp and len(_pp) == len(pol) - 1 and all(_pp[k] == pol[k] for k in _pp) and pol["DeveloperToolsAvailability"] == 2
      and list(_pp) == [k for k in pol if k != "DeveloperToolsAvailability"] and P.PROBE_POLICY_DROP == ("DeveloperToolsAvailability",))
check("home URL lands in HomepageLocation and NewTabPageLocation",
      pol["HomepageLocation"] == HOME and pol["NewTabPageLocation"] == HOME)
pol2 = P.build_policy("https://example.org/start", [])
check("another home keeps the search URL constant", pol2["HomepageLocation"] == "https://example.org/start"
      and pol2["DefaultSearchProviderSearchURL"] == P.SEARCH_URL)
pol3 = P.build_policy(HOME, ["8.8.8.8", "203.0.113.9", "fe80::1%eth0", "[2001:db8::5]", "8.8.8.8", "127.0.0.1"])
bl = pol3["URLBlocklist"]
check("literal hosts are appended, IPv6 bracketed, no zone id, no duplicates",
      bl[7:] == ["8.8.8.8", "203.0.113.9", "[fe80::1]", "[2001:db8::5]"] and len(bl) == len(set(bl)), str(bl))
check("no CIDR and no wildcard other than '*' in URLBlocklist",
      not any("/" in h for h in bl) and all("*" not in h for h in bl[1:]))
check("no *.localhost in URLBlocklist", not any(h.startswith("*.") or h.endswith(".localhost") for h in bl))
check("a CIDR passed as a literal host raises", raises(P.build_policy, HOME, ["10.0.0.0/8"]))
check("a wildcard or a name passed as a literal host raises", raises(P.build_policy, HOME, ["*"]) and raises(P.build_policy, HOME, ["example.com"]))
check("a bad home URL stops build_policy", raises(P.build_policy, "http://example.org/", []))
check("policy_text round-trips", json.loads(P.policy_text(pol3)) == pol3)
check("the policy is JSON-serialisable with only plain types", isinstance(json.dumps(pol3), str))

# ---- DoH
check("DOH_TEMPLATE is https://1.1.1.1/dns-query", P.DOH_TEMPLATE == "https://1.1.1.1/dns-query")
check("DOH_TEMPLATE validates and its host is an IP literal",
      P.validate_doh_template(P.DOH_TEMPLATE) == P.DOH_TEMPLATE and isinstance(ipaddress.ip_address("1.1.1.1"), ipaddress.IPv4Address))
check("DoH: port and IPv6 literal accepted", P.validate_doh_template("https://1.1.1.1:8443/dns-query") and P.validate_doh_template("https://[2606:4700:4700::1111]/dns-query"))
check("DoH: a host name, http, no path, a query and a bad port are refused",
      all(raises(P.validate_doh_template, x) for x in ("https://cloudflare-dns.com/dns-query", "http://1.1.1.1/dns-query",
                                                      "https://1.1.1.1", "https://1.1.1.1/dns-query?x=1", "https://1.1.1.1:99999/dns-query",
                                                      "https://1.1.1.1@evil.example/x", "")))

# ---- home URL
check("home: ordinary https URLs accepted", all(P.validate_home_url(u) == u for u in (
    "https://duckduckgo.com/", "https://example.org:8443/a/b?q=1#x", "https://sub.example.co.uk", "https://1.1.1.1/")))
BADHOME = ["http://example.org/", "ftp://example.org/", "javascript:alert(1)", "https://", "https:///x", "//example.org/",
           "https://user@example.org/", "https://user:pw@example.org/", "https://example.org/a b", "https://example.org/\n",
           "https://example.org/%41", 'https://example.org/"', "https://example.org/<x>", "https://example.org\\@evil.com/",
           "https://localhost/", "https://foo.localhost/", "https://127.0.0.1/", "https://[::1]/", "https://10.1.2.3/",
           "https://169.254.169.254/", "https://2130706433/", "https://0x7f.1/", "https://intranet/", "https://exa_mple.org/",
           "https://-bad.example.org/", "https://example.org:0/", "https://example.org:99999/", "https://éxample.org/",
           "", None, 5, "https://example.org/" + "a" * 300]
check("home: every bad URL refused", all(raises(P.validate_home_url, u) for u in BADHOME),
      str([u for u in BADHOME if not raises(P.validate_home_url, u)]))
check("home: 300 characters is the limit", P.validate_home_url("https://example.org/" + "a" * (300 - 20)) and
      raises(P.validate_home_url, "https://example.org/" + "a" * (301 - 20)))

# ---- the validators and the deny list agree (review finding: loopback, NAT64, mapped and private forms got through)
def _lit(a):
    return f"[{a}]" if a.version == 6 else str(a)


_probe_addrs = []
for _n in P.FIXED_V4 + P.FIXED_V6 + P.CLOUD:
    _net = ipaddress.ip_network(_n)
    _probe_addrs.append(_net.network_address)
    if _net.num_addresses > 1:
        _probe_addrs.append(_net.network_address + 1)
        _probe_addrs.append(_net.broadcast_address)
_probe_addrs += [ipaddress.ip_address(x) for x in ("::ffff:8.8.8.8", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::808:808",
                                                  "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2")]
_bad_home = [f"https://{_lit(a)}/" for a in _probe_addrs]
check("home: no address inside the fixed deny list (every network: first, second and last address) is accepted",
      all(raises(P.validate_home_url, u) for u in _bad_home), str([u for u in _bad_home if not raises(P.validate_home_url, u)][:6]))
_bad_doh = [f"https://{_lit(a)}/dns-query" for a in _probe_addrs] + ["https://10.0.0.1:8443/dns-query", "https://169.254.169.254/dns-query"]
check("DoH: no address inside the fixed deny list is accepted either",
      all(raises(P.validate_doh_template, u) for u in _bad_doh), str([u for u in _bad_doh if not raises(P.validate_doh_template, u)][:6]))
check("home: the exact forms of the review are refused (trailing dot, NAT64 of 127.0.0.1, mapped 8.8.8.8)",
      all(raises(P.validate_home_url, u) for u in ("https://localhost./", "https://foo.localhost./", "https://LOCALHOST./",
                                                    "https://[64:ff9b::7f00:1]/", "https://[::ffff:8.8.8.8]/", "https://localhost../")))
check("home: the IPv4-compatible and IPv4-translated forms of loopback and metadata are refused (Python 3.11 calls them global, only the deny list stops them)",
      all(raises(P.validate_home_url, u) for u in ("https://[::127.0.0.1]/", "https://[::ffff:0:a9fe:a9fe]/", "https://[::a9fe:a9fe]/", "https://[::ffff:0:7f00:1]/")))
check("DoH: the same forms are refused", all(raises(P.validate_doh_template, u) for u in ("https://[::127.0.0.1]/x", "https://[::ffff:0:a9fe:a9fe]/x")))
check("DoH: the exact forms of the review are refused",
      all(raises(P.validate_doh_template, u) for u in ("https://127.0.0.1/x", "https://[::ffff:127.0.0.1]/x",
                                                        "https://169.254.169.254/dns-query", "https://10.0.0.1:8443/dns-query")))
check("home: public literals and absolute host names still pass",
      all(P.validate_home_url(u) == u for u in ("https://8.8.8.8/", "https://[2606:4700:4700::1111]/", "https://example.com./", "https://sub.example.co.uk./x")))
check("home: a fragment that looks like user information is accepted (the host is example.com; the page never leaves it)",
      P.validate_home_url("https://example.com#@127.0.0.1") == "https://example.com#@127.0.0.1" and
      urlsplit("https://example.com#@127.0.0.1").hostname == "example.com")
check("home: build_policy refuses the same forms", raises(P.build_policy, "https://[64:ff9b::7f00:1]/", []) and raises(P.build_policy, "https://localhost./", []))
check("DoH: the constant and a public IPv6 literal still validate", P.validate_doh_template(P.DOH_TEMPLATE) == P.DOH_TEMPLATE
      and P.validate_doh_template("https://[2606:4700:4700::1111]:853/dns-query"))

# ---- the member's portal theme (1.26.0)
check("theme: a valid colour is lower-cased and kept, the mode too", P.normalise_theme("#1A1A2E", "Dark") == ("#1a1a2e", "dark")
      and P.normalise_theme("#f0e6d2", "light") == ("#f0e6d2", "light"))
bad_colors = (None, "", "#fff", "#12345", "#1234567", "1a1a2e", "#1a1a2g", "#1a1a2e ", " #1a1a2e", "#1a1a2e\n", "red", "rgb(1,2,3)", 123, b"#1a1a2e",
              ["#1a1a2e"], "#1a1a2e;", "#1a1a2e\"}", "#\u0661a1a2e", "javascript:alert(1)", "#" + "a" * 5000)
check("theme: every malformed colour is None", all(P.normalise_theme(c, "dark")[0] is None for c in bad_colors))
bad_modes = (None, "", "auto", "darkk", "dar", " dark", "dark\n", "DARK1", 1, True, ["dark"], "dark" * 1000, "system", "device")
check("theme: every other mode is None", all(P.normalise_theme("#1a1a2e", m)[1] is None for m in bad_modes))
check("theme: the two values are judged separately", P.normalise_theme("#1a1a2e", "x") == ("#1a1a2e", None)
      and P.normalise_theme("x", "light") == (None, "light") and P.normalise_theme(None, None) == (None, None))
check("theme: normalise never raises", all(P.normalise_theme(a, b) is not None for a in (object(), 1.5, {}, "\ud800") for b in (object(), {}, "\ud800")))
check("theme: the colour pattern and the mode set are the decided ones",
      P.THEME_COLOR_RE.pattern == "#[0-9a-f]{6}" and P.THEME_MODES == ("dark", "light"))
doc = P.theme_policy("#1A1A2E", "dark")
check("theme: the document has exactly the allowed keys", set(doc) == set(P.THEME_POLICY_KEYS) == {"BrowserThemeColor"} and doc == {"BrowserThemeColor": "#1a1a2e"})
check("theme: the document is the same for either mode (the mode takes no policy key)", P.theme_policy("#1a1a2e", "light") == doc and P.theme_policy("#1a1a2e", None) == doc)
check("theme: no valid colour gives an empty document", P.theme_policy(None, "dark") == {} and P.theme_policy("evil", "dark") == {} and P.theme_policy("#12", None) == {})
main = P.build_policy("https://duckduckgo.com/", [])
check("theme: no key of the theme document is a key of the security policy (nothing it could override or duplicate)",
      not (set(P.theme_policy("#1a1a2e", "dark")) & set(main)) and not (set(P.THEME_POLICY_KEYS) & set(P.probe_policy(main))))
check("theme: the theme document carries only a colour string, no list, no URL", all(isinstance(v, str) and P.THEME_COLOR_RE.fullmatch(v) for v in doc.values()))
check("theme: the file name sorts before portal.json (Chromium lets the later file win a duplicate key; measured on 156)",
      P.THEME_FILE_NAME == "portal-theme.json" and P.THEME_FILE_NAME < "portal.json")
check("theme: the placeholder is an empty policy document", json.loads(P.THEME_PLACEHOLDER_TEXT) == {})
check("theme: the main policy is unchanged by the theme work (no theme key in it)", "BrowserThemeColor" not in main and "BrowserColorScheme" not in main)

if failures:
    print(f"\ntest_rbrowser_policy: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_rbrowser_policy: all checks passed")
