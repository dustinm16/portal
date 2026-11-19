"""The allow_private host policy for webhooks (loopback and LAN allowed, link-local,
metadata and unspecified addresses refused) and the default policy left as it was.

Run: venv/bin/python tests/test_webhook_host_policy.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import host_check  # noqa: E402
from host_check import HostBlockedError, is_blocked_address_lan, resolve_checked_host  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def run(coro):
    return asyncio.run(coro)


def stub(table):
    async def _fake(host, port):
        if host not in table:
            raise OSError("no such host")
        return list(table[host])
    host_check._resolve = _fake


PUBLIC = "93.184.216.34"

# --- address policy -------------------------------------------------------
for a in ["127.0.0.1", "127.9.9.9", "::1", "10.0.0.5", "192.168.1.20", "172.16.4.4",
          "100.64.0.9", "fd12:3456::1", "::ffff:192.168.1.20", PUBLIC, "2606:4700:4700::1111"]:
    check(f"LAN policy allows {a}", not is_blocked_address_lan(a))
for a in ["169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200",
          "0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255", "::ffff:0.1.2.3", "::", "224.0.0.1", "ff02::1", "240.0.0.1", "::ffff:169.254.169.254",
          "::ffff:0.0.0.0", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "2002:7f00:1::1",
          "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001::1", "192.0.0.192", "169.254.170.2", "nonsense", ""]:
    check(f"LAN policy refuses {a!r}", is_blocked_address_lan(a))

# --- resolve_checked_host -------------------------------------------------
stub({
    "lan.example": ["192.168.1.20"],
    "loop.example": ["127.0.0.1"],
    "meta.example": ["169.254.169.254"],
    "mixed.example": ["192.168.1.20", "169.254.169.254"],
    "pub.example": [PUBLIC],
})


async def resolves(host, **kw):
    try:
        return await resolve_checked_host(host, 80, **kw)
    except HostBlockedError:
        return "blocked"


check("default policy refuses a LAN name", run(resolves("lan.example")) == "blocked")
check("default policy refuses 127.0.0.1", run(resolves("127.0.0.1")) == "blocked")
check("allow_private accepts a LAN name", run(resolves("lan.example", allow_private=True)) == ["192.168.1.20"])
check("allow_private accepts 127.0.0.1", run(resolves("127.0.0.1", allow_private=True)) == ["127.0.0.1"])
check("allow_private accepts localhost-like numeric 2130706433",
      run(resolves("2130706433", allow_private=True)) == ["127.0.0.1"])
check("allow_private refuses a name resolving to metadata", run(resolves("meta.example", allow_private=True)) == "blocked")
check("allow_private refuses a name with one blocked address", run(resolves("mixed.example", allow_private=True)) == "blocked")
check("allow_private refuses the metadata literal", run(resolves("169.254.169.254", allow_private=True)) == "blocked")
check("allow_private refuses metadata.google.internal", run(resolves("metadata.google.internal", allow_private=True)) == "blocked")
check("allow_private refuses 0.0.0.0", run(resolves("0.0.0.0", allow_private=True)) == "blocked")
check("allow_private still resolves public names", run(resolves("pub.example", allow_private=True)) == [PUBLIC])


# --- the connector --------------------------------------------------------
async def connector_checks():
    own = {("127.0.0.1", 8801)}
    lan = host_check._SSRFSafeConnector(allow_private=True,
                                        endpoint_blocked=lambda a, p: (a, p) in own)
    dflt = host_check._SSRFSafeConnector()
    http_lan = host_check._SSRFSafeConnector(allow_private=True, private_only=True)
    out = {}
    try:
        for label, conn, host, port in [
            ("lan_loop", lan, "127.0.0.1", 9000), ("lan_priv", lan, "10.1.2.3", 80),
            ("lan_meta", lan, "169.254.169.254", 80), ("lan_ll6", lan, "fe80::1", 80),
            ("lan_own_port", lan, "127.0.0.1", 8801), ("lan_name", lan, "localhost", 9000),
            ("lan_zero", lan, "0.0.0.0", 80), ("dflt_loop", dflt, "127.0.0.1", 9000),
            ("lan_pub", lan, PUBLIC, 443),
            ("http_pub", http_lan, PUBLIC, 80), ("http_priv", http_lan, "192.168.1.5", 80),
            ("http_loop", http_lan, "127.0.0.1", 80), ("http_cgnat", http_lan, "100.64.0.9", 80),
            ("http_ula6", http_lan, "fd12:3456::1", 80), ("http_pub6", http_lan, "2606:4700:4700::1111", 80),
        ]:
            try:
                r = await conn._resolve_host(host, port)
                out[label] = r[0]["host"]
            except HostBlockedError:
                out[label] = "blocked"
    finally:
        await lan.close()
        await dflt.close()
        await http_lan.close()
    return out


res = run(connector_checks())
check("LAN connector dials loopback", res["lan_loop"] == "127.0.0.1", str(res))
check("LAN connector dials a private address", res["lan_priv"] == "10.1.2.3", str(res))
check("LAN connector refuses metadata, link-local and unspecified",
      res["lan_meta"] == res["lan_ll6"] == res["lan_zero"] == "blocked", str(res))
check("LAN connector refuses the portal's own (address, port) but not other ports",
      res["lan_own_port"] == "blocked" and res["lan_loop"] != "blocked", str(res))
check("LAN connector resolves localhost to loopback", res["lan_name"] in ("127.0.0.1", "::1"), str(res))
check("default connector still refuses loopback", res["dflt_loop"] == "blocked", str(res))
check("LAN connector reaches public addresses", res["lan_pub"] == PUBLIC, str(res))
check("plain-http LAN connector refuses a public address, v4 and v6",
      res["http_pub"] == res["http_pub6"] == "blocked", str(res))
check("plain-http LAN connector dials loopback, private, CGNAT and ULA addresses",
      res["http_loop"] == "127.0.0.1" and res["http_priv"] == "192.168.1.5"
      and res["http_cgnat"] == "100.64.0.9" and res["http_ula6"] == "fd12:3456::1", str(res))
check("is_private_or_loopback_address",
      host_check.is_private_or_loopback_address("10.0.0.1") and host_check.is_private_or_loopback_address("::1")
      and not host_check.is_private_or_loopback_address(PUBLIC) and not host_check.is_private_or_loopback_address("nonsense"))

sys.exit(1 if failures else 0)
