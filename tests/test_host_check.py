"""Plain-assert tests for host_check (no framework, no network).

Run:  venv/bin/python tests/test_host_check.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import host_check  # noqa: E402
from host_check import (  # noqa: E402
    HostBlockedError, HostResolveError, is_blocked_host, pick_dial_address,
    resolve_checked_host,
)

PUBLIC = "93.184.216.34"
calls = []


def stub(table):
    async def _fake(host, port):
        calls.append(host)
        if host not in table:
            raise OSError("no such host")
        return list(table[host])
    host_check._resolve = _fake


def run(coro):
    return asyncio.run(coro)


def expect_blocked(host, label=None):
    try:
        run(resolve_checked_host(host, 80))
    except HostBlockedError as e:
        assert str(e) == "Host not allowed", str(e)
        return
    raise AssertionError(f"{label or host!r} was not refused")


# --- names that resolve to blocked addresses are refused -------------------
stub({
    "loop4.example": ["127.0.0.1"],
    "loop6.example": ["::1"],
    "rfc1918.example": ["10.0.0.5"],
    "meta.example": ["169.254.169.254"],
    "cgnat.example": ["100.64.0.1"],
    "mapped.example": ["::ffff:127.0.0.1"],
    "mappedhex.example": ["::ffff:7f00:1"],
    "mappedpriv.example": ["::ffff:10.0.0.5"],
    "linklocal.example": ["fe80::1"],
    "mixed.example": [PUBLIC, "10.0.0.5"],
    "mixed2.example": ["10.0.0.5", PUBLIC],
    "public.example": [PUBLIC],
    "public6.example": ["2606:4700:4700::1111"],
    "dual.example": ["2606:4700:4700::1111", PUBLIC],
})
for name in ["loop4.example", "loop6.example", "rfc1918.example", "meta.example",
             "cgnat.example", "mapped.example", "mappedhex.example",
             "mappedpriv.example", "linklocal.example", "mixed.example",
             "mixed2.example"]:
    expect_blocked(name)

# --- public addresses are allowed and returned for pinning -----------------
assert run(resolve_checked_host("public.example", 443)) == [PUBLIC]
assert run(resolve_checked_host("public6.example", 443)) == ["2606:4700:4700::1111"]
assert pick_dial_address(run(resolve_checked_host("dual.example", 443))) == PUBLIC

# --- literals and numeric spellings are refused without any DNS ------------
calls.clear()
for lit in ["127.0.0.1", "127.1", "::1", "[::1]", "0.0.0.0", "10.1.2.3",
            "192.168.1.1", "169.254.169.254", "100.64.0.1", "::ffff:127.0.0.1",
            "localhost", "LOCALHOST", "localhost.", "metadata.google.internal",
            "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.1", "017700000001",
            "2852039166", "1681915905", "", "   "]:
    expect_blocked(lit)
assert calls == [], f"literal checks must not use DNS, got {calls}"

# numeric spelling of a PUBLIC address is allowed, and returned canonical
assert run(resolve_checked_host("1572395042", 80)) == ["93.184.216.34"]
assert run(resolve_checked_host(PUBLIC, 80)) == [PUBLIC]

# --- fail closed on resolution problems ------------------------------------
try:
    run(resolve_checked_host("nxdomain.example", 80))
    raise AssertionError("unresolvable name must raise")
except HostResolveError as e:
    assert not isinstance(e, HostBlockedError)

stub({"empty.example": []})
try:
    run(resolve_checked_host("empty.example", 80))
    raise AssertionError("empty answer must raise")
except HostResolveError:
    pass


async def _slow(host, port):
    await asyncio.sleep(5)
    return [PUBLIC]


host_check._resolve = _slow
try:
    run(resolve_checked_host("slow.example", 80, timeout=0.1))
    raise AssertionError("timeout must raise")
except HostResolveError:
    pass

# --- exception text never carries the resolved address ---------------------
stub({"leak.example": ["10.9.8.7"]})
try:
    run(resolve_checked_host("leak.example", 80))
except HostBlockedError as e:
    assert "10.9.8.7" not in str(e) and "10.9.8.7" not in repr(e)

# --- policy single definition: is_blocked_host unchanged in spirit ---------
assert is_blocked_host("100.64.0.1") and is_blocked_host("100.127.255.254")
assert not is_blocked_host("100.128.0.1") and not is_blocked_host(PUBLIC)
assert host_check.is_blocked_address("::ffff:100.64.0.1")
assert not host_check.is_blocked_address("2606:4700:4700::1111")


# --- aiohttp connector: literals (which skip the resolver) are refused -----
async def connector_checks():
    conn = host_check._SSRFSafeConnector()
    try:
        for h in ["127.0.0.1", "10.0.0.5", "::1", "::ffff:127.0.0.1", "localhost",
                  "169.254.169.254", "100.64.0.1"]:
            try:
                await conn._resolve_host(h, 80)
            except HostBlockedError:
                continue
            raise AssertionError(f"connector accepted {h}")
        r = await conn._resolve_host(PUBLIC, 80)
        assert r and r[0]["host"] == PUBLIC
    finally:
        await conn.close()

run(connector_checks())

# --- connecting tries each checked address (IPv4 first), connect errors only
async def fallback_checks():
    from host_check import dial_order, try_each_address
    assert dial_order(["2606:4700:4700::1111", PUBLIC, "93.184.216.35"]) == [
        PUBLIC, "93.184.216.35", "2606:4700:4700::1111"]
    tried = []

    async def attempt_ok_second(a):
        tried.append(a)
        if a == PUBLIC:
            raise ConnectionRefusedError()
        return a

    assert await try_each_address([PUBLIC, "93.184.216.35"], attempt_ok_second, 5) == "93.184.216.35"
    assert tried == [PUBLIC, "93.184.216.35"]

    async def hang_first(a):
        if a == PUBLIC:
            await asyncio.sleep(30)     # hanging address must not eat the budget
        return a

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    assert await try_each_address([PUBLIC, "93.184.216.35"], hang_first, 2) == "93.184.216.35"
    assert loop.time() - t0 < 2.5

    async def all_fail(a):
        raise ConnectionRefusedError()

    try:
        await try_each_address([PUBLIC, "93.184.216.35"], all_fail, 5)
        raise AssertionError("must raise when every address fails")
    except ConnectionRefusedError:
        pass

    tried.clear()

    class AuthError(Exception):
        pass

    async def auth_fail(a):
        tried.append(a)
        raise AuthError()

    try:
        await try_each_address([PUBLIC, "93.184.216.35"], auth_fail, 5)
        raise AssertionError("non-connect errors must propagate")
    except AuthError:
        assert tried == [PUBLIC], "a login must not be retried on another address"

run(fallback_checks())


# --- mediamtx: user connections use the policy connector, no redirects -----
async def mediamtx_checks():
    from plugins.mediamtx import MediaMTXPlugin
    import aiohttp
    plugin = MediaMTXPlugin()
    session = aiohttp.ClientSession(connector=host_check._SSRFSafeConnector())
    try:
        for url in ["http://127.0.0.1:1/", "http://2130706433:1/", "http://[::1]:1/",
                    "http://localhost.:1/", "http://10.1.2.3:1/"]:
            try:
                await plugin._get_streams(url, 3, session)
                raise AssertionError(f"mediamtx session dialled {url}")
            except aiohttp.ClientConnectorError as e:
                # aiohttp wraps what the connector raised
                assert isinstance(e.__cause__, HostBlockedError), repr(e.__cause__)
    finally:
        await session.close()

run(mediamtx_checks())

# --- deprecated IPv6 site-local range is refused ---------------------------
assert host_check.is_blocked_address("fec0::1") and is_blocked_host("fec0::1")
assert not host_check.is_blocked_address("2606:4700:4700::1111")


# --- proxmox: the handler-built user config gets the checked connector -----
async def proxmox_checks():
    from plugins.proxmox import ProxmoxPlugin
    plugin = ProxmoxPlugin()
    # exactly the keys the user-connection handler sets
    user_cfg = {"host": "public.example", "port": 8006,
                "_pinned_hosts": [PUBLIC], "_server_hostname": "public.example"}
    client = plugin._get_client(user_cfg)
    assert client.restrict_hosts, "user connection must be restricted"
    session = await client._get_session()
    try:
        assert isinstance(session.connector, host_check._CheckedConnector)
    finally:
        await client.close()
    # admin-defined service (no handler keys): plain connector as before
    admin = plugin._get_client({"host": "10.0.0.5", "port": 8006})
    assert not admin.restrict_hosts
    session = await admin._get_session()
    try:
        assert not isinstance(session.connector, host_check._CheckedConnector)
    finally:
        await admin.close()
    # the key the plugin reads is the key the handler sets and resets
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server.py")).read()
    assert 'config["_pinned_hosts"] = list(_addrs)' in src
    assert 'config.pop("_pinned_hosts", None)' in src

run(proxmox_checks())


# --- http_proxy: user policy only for connections the handler marked -------
async def http_proxy_checks():
    from plugins.http_proxy import HTTPProxyPlugin, _check_proxy_target, _new_connector
    import aiohttp
    from plugins.base import ServiceTarget
    stub({"loop4.example": ["127.0.0.1"], "public.example": [PUBLIC]})
    user = {"_ssrf_safe": True}
    assert not await _check_proxy_target("http://loop4.example/", user)
    assert not await _check_proxy_target("http://10.1.2.3/", user)
    assert await _check_proxy_target("http://public.example:8080/", user)
    c = _new_connector(user, False)
    assert isinstance(c, host_check._CheckedConnector)
    await c.close()
    # admin-defined service: literal-name check as before, plain connector, no DNS
    calls.clear()
    assert await _check_proxy_target("http://nas.lan:8123/", {})
    assert await _check_proxy_target("http://loop4.example/", {})
    assert not await _check_proxy_target("http://127.0.0.1:8123/", {})
    assert not await _check_proxy_target(None, {})
    assert calls == [], "admin services must not trigger a resolve check"
    c = _new_connector({}, False)
    assert not isinstance(c, host_check._CheckedConnector)
    await c.close()
    # health_check is admin-only: a local backend still reports its status
    from aiohttp import web
    app = web.Application()
    app.router.add_route("*", "/{p:.*}", lambda r: web.Response(text="ok"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        res = await HTTPProxyPlugin().health_check(ServiceTarget(
            id="t", name="t", plugin="http_proxy", host="127.0.0.1", port=port,
            config={"target_url": f"http://127.0.0.1:{port}/"}))
        assert res["healthy"] and res["message"] == "HTTP 200", res
    finally:
        await runner.cleanup()

run(http_proxy_checks())

# --- mediamtx ICE resource: only the configured webrtc_url origin ----------
def ice_resource_checks():
    from plugins.mediamtx import resolve_ice_resource as r
    base = "http://media.example:8889"
    assert r(base, "/cam/whep/abc") == "http://media.example:8889/cam/whep/abc"
    assert r(base + "/", "http://media.example:8889/cam/whep/abc?x=1") == "http://media.example:8889/cam/whep/abc?x=1"
    assert r(base, "http://MEDIA.example:8889/p") == "http://media.example:8889/p"
    assert r("https://media.example", "https://media.example:443/p") == "https://media.example/p"
    for bad in ("http://169.254.169.254/latest", "http://127.0.0.1:8889/x", "http://127.0.0.1:9997/x",
                "http://media.example:9997/x", "https://media.example:8889/x", "//evil.example/x",
                "http://media.example:8889@evil.example/x", "http://evil.example\\@media.example:8889/x",
                "http://media.example:8889/x y", "http://media.example:8889/x\r\nHost: a",
                "file:///etc/passwd", "", None, 5, ["x"], "http://media.example:bad/x"):
        assert r(base, bad) is None, bad
    assert r("not a url", "/x") is None
    assert r(None, "/x") is None

ice_resource_checks()


# --- short per-host cache for the browser proxy ----------------------------
async def cache_checks():
    host_check._check_cache.clear()
    stub({"a.example": [PUBLIC], "loop.example": ["127.0.0.1"]})
    calls.clear()
    assert await host_check.resolve_checked_host_cached("a.example", 80) == [PUBLIC]
    assert await host_check.resolve_checked_host_cached("A.example", 443) == [PUBLIC]
    assert calls == ["a.example"], calls          # second call served from cache
    for _ in range(2):
        try:
            await host_check.resolve_checked_host_cached("loop.example", 80)
            raise AssertionError("blocked name accepted")
        except HostBlockedError:
            pass
    assert calls.count("loop.example") == 1
    # resolve failures are never cached
    for _ in range(2):
        try:
            await host_check.resolve_checked_host_cached("gone.example", 80)
            raise AssertionError("unresolvable name accepted")
        except HostResolveError:
            pass
    assert calls.count("gone.example") == 2
    # entries expire
    host_check._check_cache.clear()
    await host_check.resolve_checked_host_cached("a.example", 80, ttl=0)
    n = calls.count("a.example")
    await host_check.resolve_checked_host_cached("a.example", 80)
    assert calls.count("a.example") == n + 1
    # bounded size
    host_check._check_cache.clear()
    table = {f"h{i}.example": [PUBLIC] for i in range(host_check._CACHE_MAX + 20)}
    stub(table)
    for h in table:
        await host_check.resolve_checked_host_cached(h, 80)
    assert len(host_check._check_cache) <= host_check._CACHE_MAX
    host_check._check_cache.clear()

run(cache_checks())


# --- vpn_tunnel: user connections may only use SOCKS mode ------------------
async def vpn_mode_checks():
    from plugins.vpn_tunnel import VPNTunnelPlugin
    from plugins.base import ServiceTarget

    class FakeWS:
        def __init__(self):
            self.sent = []
        async def send_bytes(self, b):
            self.sent.append(b)

    plugin = VPNTunnelPlugin()
    started = []
    async def fake_tun(*a, **k):
        started.append("tun")
    async def fake_socks(*a, **k):
        started.append("socks")
    plugin._handle_tun_tunnel = fake_tun
    plugin._handle_socks_tunnel = fake_socks
    def tgt(cfg):
        return ServiceTarget(id="t", name="t", plugin="vpn_tunnel", host="", port=0, config=cfg)
    for mode in ("tun", "tap", "bogus"):
        ws = FakeWS()
        await plugin.handle_websocket(ws, tgt({"mode": mode, "_ssrf_safe": True}), 1)
        assert ws.sent, mode
    assert started == [], started
    await plugin.handle_websocket(FakeWS(), tgt({"mode": "socks", "_ssrf_safe": True}), 1)
    await plugin.handle_websocket(FakeWS(), tgt({"mode": "tun"}), 1)      # admin-defined
    assert started == ["socks", "tun"], started
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server.py")).read()
    assert 'elif plugin_name == "vpn_tunnel":' in src

run(vpn_mode_checks())


# --- save-time rules for user connections (server helpers) -----------------
import server  # noqa: E402

# hls_url is optional, api_url and webrtc_url are not.
assert server._mediamtx_missing_urls("stream", {"api_url": "http://a", "webrtc_url": "http://b"}) == []
assert server._mediamtx_missing_urls("mediamtx", '{"api_url": "http://a", "webrtc_url": "http://b", "hls_url": ""}') == []
assert server._mediamtx_missing_urls("stream", {"webrtc_url": "http://b", "hls_url": "http://c"}) == ["api_url"]
assert server._mediamtx_missing_urls("stream", {}) == ["api_url", "webrtc_url"]
assert server._mediamtx_missing_urls("tcp_tunnel", {}) == []

# user vpn_tunnel connections: socks (or no mode) only.
assert not server._vpn_mode_refused("vpn_tunnel", {})
assert not server._vpn_mode_refused("vpn_tunnel", {"mode": "socks"})
assert not server._vpn_mode_refused("vpn_tunnel", '{"mode": "socks"}')
for bad in ("tun", "tap", "TUN", "", None, 5):
    assert server._vpn_mode_refused("vpn_tunnel", {"mode": bad}), bad
assert server._vpn_mode_refused("vpn_tunnel", '{"mode": "tap"}')
assert not server._vpn_mode_refused("tcp_tunnel", {"mode": "tun"})

print("test_host_check: all checks passed")
