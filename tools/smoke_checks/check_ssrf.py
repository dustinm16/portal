"""Smoke check: user-supplied hosts that resolve or spell out an internal
address are refused with a generic error, while a public address is accepted.

Uses numeric spellings and 'localhost.' variants so no outbound DNS is needed.
"""

import json

USER = "smoke_hosts_user"
PASSWORD = "Smoke-Hosts-Pw-1!"

CREATE_USER = f"""
import asyncio
import database
from auth import create_user

async def main():
    await database.db.connect()
    if not await database.db.get_user_by_username({USER!r}):
        await create_user({USER!r}, {PASSWORD!r}, is_admin=False)
    await database.db.close()

asyncio.run(main())
"""

# Internal targets in spellings that a literal-string check would miss.
BAD_HOSTS = [
    "127.0.0.1",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "127.1",
    "localhost.",
    "LOCALHOST",
    "[::1]",
    "::ffff:127.0.0.1",
    "10.1.2.3",
    "169.254.169.254",
    "100.64.0.1",
]
# Literal public address: needs no DNS on the staging host.
GOOD_HOST = "93.184.216.34"

# Rows inserted straight into the database, bypassing the save-time checks, to
# exercise the connect-time paths (what an older or edited row would look like).
# name -> (type, host, port, config)
ROWS = {
    "ssh_dot": ("ssh", "localhost.", 22, {"username": "u", "password": "p"}),
    "tcp_num": ("tcp_tunnel", "2130706433", 22, {}),
    "tcp_hex": ("tcp_tunnel", "0x7f000001", 22, {}),
    "http_loop": ("http", "127.0.0.1", 80, {}),
    "http_browser": ("http", GOOD_HOST, 80, {"browser_mode": True}),
    "http_internal_url": ("http", GOOD_HOST, 80, {"target_url": "http://127.0.0.1:8464/"}),
    # host is only a placeholder here: the (public) target_url is what is dialled
    "http_placeholder": ("http", "placeholder.invalid", 80,
                         {"target_url": "http://" + GOOD_HOST + ":81/", "timeout": 2}),
    "stream_nourl": ("stream", "cam.example", 554, {"protocol": "rtsp"}),
    "stream_internal": ("mediamtx", "cam.example", 8554,
                        {"api_url": "http://2130706433:9997", "webrtc_url": "http://" + GOOD_HOST + ":8889",
                         "hls_url": "http://" + GOOD_HOST + ":8888"}),
}

INSERT_ROWS = f"""
import asyncio, json
import database

ROWS = json.loads({json.dumps(json.dumps(ROWS))})

async def main():
    await database.db.connect()
    user = await database.db.get_user_by_username({USER!r})
    out = {{}}
    for name, (typ, host, port, cfg) in ROWS.items():
        out[name] = await database.db.create_user_connection(
            user["id"], name, typ, host, port, json.dumps(cfg))
    await database.db.close()
    print("ROWS=" + json.dumps(out))

asyncio.run(main())
"""

INSERT_VPN_ROWS = f"""
import asyncio, json
import database

async def main():
    await database.db.connect()
    user = await database.db.get_user_by_username({USER!r})
    out = {{}}
    for name, mode in (("vpn_tun", "tun"), ("vpn_socks", "socks")):
        out[name] = await database.db.create_user_connection(
            user["id"], name, "vpn_tunnel", "bridge.example", 0, json.dumps({{"mode": mode}}))
    await database.db.close()
    print("VPN=" + json.dumps(out))

asyncio.run(main())
"""

# Relay destination re-check (what runs just before ffmpeg is started), with
# DNS stubbed so a name that was public when saved now points at a LAN address.
RELAY_CHECK = """
import asyncio, json
import host_check
import server

TABLE = {"rebind.example": ["10.0.0.5"], "public.example": ["93.184.216.34"]}

async def fake(host, port):
    if host not in TABLE:
        raise OSError("nx")
    return TABLE[host]

host_check._resolve = fake
out = {}

async def attempt(label, url):
    try:
        out[label] = await server._checked_relay_target(url, "KEY")
    except host_check.HostBlockedError:
        out[label] = "blocked"
    except host_check.HostCheckError as e:
        out[label] = "error:" + type(e).__name__

async def main():
    await attempt("rebound_rtmp", "rtmp://rebind.example:1935/app")
    await attempt("rebound_rtmps", "rtmps://rebind.example/app")
    await attempt("literal", "rtmp://127.0.0.1/app")
    await attempt("public_rtmp", "rtmp://u:pw@public.example:1936/app/sub/")
    await attempt("public_rtmps", "rtmps://public.example/app")

asyncio.run(main())
print("OUT=" + json.dumps(out))
"""

# Plugin clients for user connections: built from the keys the connection
# handler sets, they must carry the policy connector; admin services must not.
PLUGIN_CLIENT_CHECK = """
import asyncio, inspect, json
import host_check
import server
from plugins.proxmox import ProxmoxPlugin
from plugins.http_proxy import _new_connector

out = {}

async def main():
    plugin = ProxmoxPlugin()
    cfg = {"host": "pve.example", "port": 8006,
           "_pinned_hosts": ["93.184.216.34"], "_server_hostname": "pve.example"}
    c = plugin._get_client(cfg)
    s = await c._get_session()
    out["proxmox_user"] = isinstance(s.connector, host_check._CheckedConnector)
    await c.close()
    c = plugin._get_client({"host": "10.0.0.5", "port": 8006})
    s = await c._get_session()
    out["proxmox_admin_plain"] = not isinstance(s.connector, host_check._CheckedConnector)
    await c.close()
    k = _new_connector({"_ssrf_safe": True}, False)
    out["http_user"] = isinstance(k, host_check._CheckedConnector)
    await k.close()
    k = _new_connector({}, False)
    out["http_admin_plain"] = not isinstance(k, host_check._CheckedConnector)
    await k.close()
    src = inspect.getsource(server)
    out["handler_keys"] = ('config["_pinned_hosts"] = list(_addrs)' in src
                           and 'config.pop("_pinned_hosts", None)' in src
                           and 'config["_ssrf_safe"] = True' in src)

asyncio.run(main())
print("OUT=" + json.dumps(out))
"""


# MediaMTX ICE candidates: an admin-defined service (shared session, no policy
# connector) must still dial only the configured webrtc_url origin. Two local
# listeners stand in for the media server (A) and an internal service (B).
ICE_CHECK = """
import asyncio, json
import aiohttp
from aiohttp import web
from plugins.mediamtx import MediaMTXPlugin
from plugins.vpn_tunnel import VPNTunnelPlugin
from plugins.base import ServiceTarget

hits = {"A": [], "B": []}

async def start(label):
    async def h(request):
        hits[label].append(request.method + " " + request.path_qs)
        return web.Response(status=204)
    app = web.Application()
    app.router.add_route("*", "/{p:.*}", h)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]

class FakeWS:
    async def send_json(self, d):
        pass
    async def send_bytes(self, b):
        pass

async def main():
    ra, pa = await start("A")
    rb, pb = await start("B")
    plugin = MediaMTXPlugin()
    await plugin.initialize()
    base = f"http://127.0.0.1:{pa}"
    try:
        for res in (f"http://127.0.0.1:{pb}/x", "http://169.254.169.254/latest", f"http://localhost:{pb}/x",
                    f"http://127.0.0.1:{pa}@127.0.0.1:{pb}/x", f"//127.0.0.1:{pb}/x", f"{base}\\\\@127.0.0.1:{pb}/x"):
            await plugin._handle_signaling(FakeWS(), {"type": "ice", "candidate": "c", "resource": res},
                                           base, [], 3, 1)
        await plugin._handle_signaling(FakeWS(), {"type": "ice", "candidate": "c", "resource": "/cam/whep/abc"},
                                       base, [], 3, 1)
        await plugin._handle_signaling(FakeWS(), {"type": "ice", "candidate": "c", "resource": base + "/cam/whep/def"},
                                       base, [], 3, 1)
    finally:
        await plugin.shutdown()
        await ra.cleanup()
        await rb.cleanup()
    # vpn_tunnel: user connections (marked) may only use socks mode
    vpn = VPNTunnelPlugin()
    started = []
    async def fake_tun(*a, **k):
        started.append("tun")
    vpn._handle_tun_tunnel = fake_tun
    await vpn.handle_websocket(FakeWS(), ServiceTarget(
        id="t", name="t", plugin="vpn_tunnel", host="", port=0, config={"mode": "tun", "_ssrf_safe": True}), 1)
    out = {"hits": hits, "vpn_user_tun_started": bool(started),
           "admin_enum": VPNTunnelPlugin.info.config_schema["properties"]["mode"]["enum"]}
    print("OUT=" + json.dumps(out))

asyncio.run(main())
"""


async def ws_result(s, url):
    """Open a WebSocket, return (messages, close code)."""
    msgs = []
    async with s.ws_connect(url, ssl=False) as ws:
        while True:
            m = await ws.receive(timeout=15)
            if m.type == 1:     # TEXT
                msgs.append(m.data)
            else:
                break
        return msgs, ws.close_code


async def run(ctx):
    rc, out = await ctx.run_py(CREATE_USER)
    ctx.ok("hosts: create non-admin test user", rc == 0, out.strip()[-200:])
    if rc != 0:
        return

    async with ctx.http() as s:
        resp = await ctx.login(s, USER, PASSWORD)
        ctx.ok("hosts: non-admin login", resp.status == 200, f"status {resp.status}")
        if resp.status != 200:
            return

        # Positive control first: proves the refusals below are about the
        # host and not a disabled feature or a malformed request.
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "pub", "type": "tcp_tunnel", "host": GOOD_HOST, "port": 22}) as r:
            body = await r.json()
            good_id = body.get("id")
            ctx.ok("hosts: create with public address accepted",
                   r.status in (200, 201) and bool(good_id), f"{r.status} {body}")

        for host in BAD_HOSTS:
            async with s.post(f"{ctx.base_url}/api/connections", json={
                "name": f"bad-{host}", "type": "tcp_tunnel", "host": host, "port": 22}) as r:
                body = await r.json()
                ctx.ok(f"hosts: create refused for {host}",
                       r.status == 403 and body.get("error") == "Host not allowed"
                       and "127." not in json.dumps(body), f"{r.status} {body}")

        # A user-set URL in the config is checked as well.
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "bad-url", "type": "http", "host": GOOD_HOST, "port": 80,
            "config": {"target_url": "http://2130706433:8890/"}}) as r:
            body = await r.json()
            ctx.ok("hosts: create refused for internal target_url in config",
                   r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")

        if good_id:
            for host in ("2130706433", "localhost."):
                async with s.put(f"{ctx.base_url}/api/connections/{good_id}",
                                 json={"host": host}) as r:
                    body = await r.json()
                    ctx.ok(f"hosts: update refused for {host}",
                           r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")
            async with s.put(f"{ctx.base_url}/api/connections/{good_id}",
                             json={"host": "93.184.216.35"}) as r:
                ctx.ok("hosts: update to another public address accepted", r.status == 200, str(r.status))

        # VOD storage: save and test are refused for internal hosts.
        vod = {"host": "2130706433", "port": 22, "username": "u", "remote_path": "/v",
               "auth_method": "password", "password": "x"}
        async with s.post(f"{ctx.base_url}/api/vods/storage", json=vod) as r:
            body = await r.json()
            ctx.ok("hosts: VOD storage save refused for internal host",
                   r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/vods/storage/test", json=vod) as r:
            body = await r.json()
            ctx.ok("hosts: VOD storage test refused for internal host",
                   body.get("success") is False and body.get("error") == "Host not allowed", f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/vods/storage", json={**vod, "host": GOOD_HOST}) as r:
            body = await r.json()
            ctx.ok("hosts: VOD storage save accepted for public address",
                   r.status == 200, f"{r.status} {body}")

        # ------------------------------------------------------------------
        # Connect time: rows that reached the database without the save-time
        # checks must still be refused when used.
        # ------------------------------------------------------------------
        rc, out = await ctx.run_py(INSERT_ROWS)
        line = next((l for l in out.splitlines() if l.startswith("ROWS=")), "")
        ctx.ok("hosts: insert internal-host rows directly", rc == 0 and bool(line), out.strip()[-200:])
        if not line:
            return
        ids = json.loads(line[len("ROWS="):])

        for name in ("ssh_dot", "tcp_num", "tcp_hex", "stream_nourl", "stream_internal"):
            try:
                msgs, code = await ws_result(s, ctx.base_url.replace("https", "wss") + f"/ws/user-connection/{ids[name]}")
            except Exception as e:
                msgs, code = [f"exception {e!r}"], None
            ctx.ok(f"hosts: websocket refused with 4003 for {name}",
                   code == 4003 and any("Host not allowed" in m for m in msgs), f"{code} {msgs}")

        async with s.get(f"{ctx.base_url}/api/sftp/{ids['ssh_dot']}/list") as r:
            body = await r.json()
            ctx.ok("hosts: sftp browser refused for internal host",
                   r.status == 502 and body.get("error") == "Host not allowed", f"{r.status} {body}")

        async with s.get(f"{ctx.base_url}/proxy/{ids['http_loop']}/", allow_redirects=False) as r:
            ctx.ok("hosts: /proxy refused for internal host", r.status == 403, str(r.status))
        async with s.get(f"{ctx.base_url}/proxy/{ids['http_internal_url']}/", allow_redirects=False) as r:
            ctx.ok("hosts: /proxy refused for internal target_url", r.status == 403, str(r.status))
        for target in ("https://127.0.0.1:8464/health", "http://2130706433:8464/health",
                       "https://localhost.:8464/health"):
            # (browser mode is isolated since 1.24.1: the entry redirects to the capability address, which is refused)
            async with s.get(f"{ctx.base_url}/proxy/{ids['http_browser']}/{target}") as r:
                ctx.ok(f"hosts: /proxy browser-mode refused for {target}", r.status == 403, str(r.status))

        # A placeholder host with a public target_url is not checked (and not
        # refused): only the dialled URL counts. The dial itself may fail.
        async with s.get(f"{ctx.base_url}/proxy/{ids['http_placeholder']}/", allow_redirects=False) as r:
            ctx.ok("hosts: /proxy checks only target_url when it overrides host",
                   r.status != 403, str(r.status))

        # Media stream connections need their URLs when saved.
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-nourl", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"protocol": "rtsp"}}) as r:
            body = await r.json()
            ctx.ok("hosts: stream connection without URLs refused at create",
                   r.status == 400 and "api_url" in json.dumps(body), f"{r.status} {body}")
        # The HLS URL is optional; the other two are still required.
        pub_api, pub_rtc = f"http://{GOOD_HOST}:9997", f"http://{GOOD_HOST}:8889"
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-nohls", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"api_url": pub_api, "webrtc_url": pub_rtc}}) as r:
            body = await r.json()
            nohls_id = body.get("id")
            ctx.ok("hosts: stream connection without hls_url accepted at create",
                   r.status in (200, 201) and bool(nohls_id), f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-emptyhls", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"api_url": pub_api, "webrtc_url": pub_rtc, "hls_url": ""}}) as r:
            ctx.ok("hosts: stream connection with an empty hls_url accepted at create",
                   r.status in (200, 201), str(r.status))
        for missing in ("api_url", "webrtc_url"):
            cfg = {"api_url": pub_api, "webrtc_url": pub_rtc}
            del cfg[missing]
            async with s.post(f"{ctx.base_url}/api/connections", json={
                "name": f"cam-no-{missing}", "type": "stream", "host": GOOD_HOST, "port": 554,
                "config": cfg}) as r:
                body = await r.json()
                ctx.ok(f"hosts: stream connection without {missing} still refused",
                       r.status == 400 and missing in json.dumps(body), f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-badhls", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"api_url": pub_api, "webrtc_url": pub_rtc, "hls_url": "http://2130706433:8888"}}) as r:
            body = await r.json()
            ctx.ok("hosts: a present internal hls_url is still refused at create",
                   r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")
        if nohls_id:
            async with s.put(f"{ctx.base_url}/api/connections/{nohls_id}", json={"name": "cam-nohls2"}) as r:
                ctx.ok("hosts: stream connection without hls_url can be renamed", r.status == 200, str(r.status))
            async with s.put(f"{ctx.base_url}/api/connections/{nohls_id}", json={
                "config": {"hls_url": "http://2130706433:8888"}}) as r:
                ctx.ok("hosts: an internal hls_url added by update is refused", r.status == 403, str(r.status))
            try:
                msgs, code = await ws_result(
                    s, ctx.base_url.replace("https", "wss") + f"/ws/user-connection/{nohls_id}")
            except Exception as e:
                msgs, code = [f"exception {e!r}"], None
            ctx.ok("hosts: websocket for a stream without hls_url is not refused by the host policy",
                   code != 4003 and not any("Host not allowed" in m for m in msgs), f"{code} {msgs}")
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-url", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"api_url": f"http://{GOOD_HOST}:9997", "webrtc_url": f"http://{GOOD_HOST}:8889",
                       "hls_url": f"http://{GOOD_HOST}:8888"}}) as r:
            body = await r.json()
            ctx.ok("hosts: stream connection with public URLs accepted",
                   r.status in (200, 201), f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-internal", "type": "stream", "host": GOOD_HOST, "port": 554,
            "config": {"api_url": "http://2130706433:9997", "webrtc_url": f"http://{GOOD_HOST}:8889",
                       "hls_url": f"http://{GOOD_HOST}:8888"}}) as r:
            body = await r.json()
            ctx.ok("hosts: stream connection with internal api_url refused at create",
                   r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")

        # The dashboard form for 'stream' sends the three URLs; create and edit work.
        form_cfg = {"protocol": "rtsp", "path": "/live", "api_url": f"http://{GOOD_HOST}:9997",
                    "webrtc_url": f"http://{GOOD_HOST}:8889", "hls_url": f"http://{GOOD_HOST}:8888"}
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "cam-form", "type": "stream", "host": GOOD_HOST, "port": 554, "config": form_cfg}) as r:
            body = await r.json()
            cam_id = body.get("id")
            ctx.ok("hosts: stream connection created with the dashboard form body",
                   r.status in (200, 201) and bool(cam_id), f"{r.status} {body}")
        if cam_id:
            async with s.put(f"{ctx.base_url}/api/connections/{cam_id}", json={
                "name": "cam-form2", "type": "stream", "host": GOOD_HOST, "port": 554,
                "config": {**form_cfg, "path": "/live2"}}) as r:
                body = await r.json()
                ctx.ok("hosts: stream connection edited with the dashboard form body",
                       r.status == 200, f"{r.status} {body}")
            async with s.put(f"{ctx.base_url}/api/connections/{cam_id}", json={"name": "cam-form3"}) as r:
                ctx.ok("hosts: stream connection renamed without resending the config",
                       r.status == 200, str(r.status))
            async with s.put(f"{ctx.base_url}/api/connections/{cam_id}", json={
                "config": {"hls_url": "http://2130706433:8888"}}) as r:
                body = await r.json()
                ctx.ok("hosts: stream connection edit to an internal URL refused",
                       r.status == 403 and body.get("error") == "Host not allowed", f"{r.status} {body}")
        async with s.get(f"{ctx.base_url}/static/js/user-connections.js") as r:
            js = await r.text()
            ctx.ok("hosts: dashboard script reads and fills the stream URL fields",
                   r.status == 200 and js.count("connection-stream-api-url") >= 2
                   and js.count("connection-stream-hls-url") >= 2, str(r.status))
            head = js.split("async function submitConnection", 1)[-1]
            ctx.ok("hosts: stream URL check runs before the submit button is disabled",
                   "required for a media stream" in head and head.index("required for a media stream")
                   < head.index("Portal.setButtonLoading(submitBtn, true)"), "order")
            ctx.ok("hosts: loopback server URL defaults are placeholders in the user form",
                   "urlHintOnly" in js and "input.placeholder = String(prop.default)" in js, "placeholder")
            ctx.ok("hosts: media server URL fields in the user form are marked required",
                   "if (key === 'api_url' || key === 'webrtc_url') isRequired = true;" in js
                   and "if (key === 'hls_url') isRequired = false;" in js
                   and js.index("if (key === 'hls_url') isRequired = false;") < js.index("label.textContent"),
                   "required")
        async with s.get(f"{ctx.base_url}/") as r:
            ctx.ok("hosts: index loads the current dashboard script version",
                   "user-connections.js?v=63" in await r.text(), str(r.status))

        # Non-string name or host is a 400 (never a 500), on create and update.
        for field in ("name", "host"):
            for label, val in (("number", 5), ("list", ["x"]), ("null", None), ("dict", {})):
                body = {"name": "nm-check", "type": "tcp_tunnel", "host": GOOD_HOST, "port": 22}
                body[field] = val
                async with s.post(f"{ctx.base_url}/api/connections", json=body) as r:
                    ctx.ok(f"hosts: create with {label} {field} is a 400", r.status == 400, str(r.status))
                if good_id:
                    async with s.put(f"{ctx.base_url}/api/connections/{good_id}", json={field: val}) as r:
                        ctx.ok(f"hosts: update with {label} {field} is a 400", r.status == 400, str(r.status))

        # Type matching is the same on create and update: surrounding space and case are ignored.
        async with s.post(f"{ctx.base_url}/api/connections", json={
            "name": "case-create", "type": "  TCP_Tunnel ", "host": GOOD_HOST, "port": 22}) as r:
            body = await r.json()
            case_id = body.get("id")
            ctx.ok("hosts: create accepts a type in other case with spaces",
                   r.status in (200, 201) and body.get("type") == "tcp_tunnel", f"{r.status} {body}")
        if case_id:
            async with s.put(f"{ctx.base_url}/api/connections/{case_id}", json={"type": " HTTP "}) as r:
                ctx.ok("hosts: update accepts a type in other case with spaces", r.status == 200, str(r.status))
            async with s.get(f"{ctx.base_url}/api/connections/{case_id}") as r:
                body = await r.json()
                ctx.ok("hosts: update stores the normalised type", body.get("type") == "http", str(body)[:200])

        # A non-string or unknown type is a 400 before any other check.
        for label, typ in (("list", ["x"]), ("dict", {}), ("number", 5), ("unknown", "nope")):
            async with s.post(f"{ctx.base_url}/api/connections", json={
                "name": f"type-{label}", "type": typ, "host": GOOD_HOST, "port": 22}) as r:
                ctx.ok(f"hosts: create with {label} type is a 400", r.status == 400, str(r.status))
            if good_id:
                async with s.put(f"{ctx.base_url}/api/connections/{good_id}", json={"type": typ}) as r:
                    ctx.ok(f"hosts: update with {label} type is a 400", r.status == 400, str(r.status))
                async with s.put(f"{ctx.base_url}/api/connections/{good_id}",
                                 json={"type": typ, "config": {}}) as r:
                    ctx.ok(f"hosts: update with {label} type and config is a 400", r.status == 400, str(r.status))

        # User VPN bridge connections: only socks mode can be saved.
        vpn_base = {"type": "vpn_tunnel", "host": "bridge.example", "port": 1}
        for mode in ("tun", "tap", "TUN", "Socks", "", None, 5):
            async with s.post(f"{ctx.base_url}/api/connections", json={
                **vpn_base, "name": f"vpn-{mode!r}", "config": {"mode": mode}}) as r:
                body = await r.json()
                ctx.ok(f"hosts: user vpn_tunnel create refused for mode {mode!r}",
                       r.status == 400 and "SOCKS" in json.dumps(body), f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/connections", json={
            **vpn_base, "name": "vpn-ok", "config": {"mode": "socks"}}) as r:
            body = await r.json()
            vpn_ok_id = body.get("id")
            ctx.ok("hosts: user vpn_tunnel create accepted for socks mode",
                   r.status in (200, 201) and bool(vpn_ok_id), f"{r.status} {body}")
        async with s.post(f"{ctx.base_url}/api/connections", json={**vpn_base, "name": "vpn-default"}) as r:
            ctx.ok("hosts: user vpn_tunnel create accepted without a mode", r.status in (200, 201), str(r.status))
        if vpn_ok_id:
            for mode in ("tun", "tap"):
                async with s.put(f"{ctx.base_url}/api/connections/{vpn_ok_id}", json={"config": {"mode": mode}}) as r:
                    ctx.ok(f"hosts: user vpn_tunnel update refused for mode {mode}", r.status == 400, str(r.status))
            async with s.put(f"{ctx.base_url}/api/connections/{vpn_ok_id}", json={"name": "vpn-ok2"}) as r:
                ctx.ok("hosts: user vpn_tunnel rename still works", r.status == 200, str(r.status))
        # Changing the type of a connection that carries a tun mode is refused too.
        async with s.put(f"{ctx.base_url}/api/connections/{good_id}", json={
            "type": "vpn_tunnel", "config": {"mode": "tun"}}) as r:
            ctx.ok("hosts: update to vpn_tunnel with tun mode refused", r.status == 400, str(r.status))
        async with s.get(f"{ctx.base_url}/api/connections/types") as r:
            body = await r.json()
            mode_enum = body.get("types", {}).get("vpn_tunnel", {}).get("config_schema", {}) \
                .get("properties", {}).get("mode", {}).get("enum")
            ctx.ok("hosts: user form schema offers only socks for vpn_tunnel", mode_enum == ["socks"], str(mode_enum))

        # Connect-time marker for user VPN bridge connections.
        rc, out = await ctx.run_py(INSERT_VPN_ROWS)
        line = next((l for l in out.splitlines() if l.startswith("VPN=")), "")
        vpn_ids = json.loads(line[4:]) if line else {}
        if vpn_ids:
            for name in ("vpn_tun", "vpn_socks"):
                msgs = []
                try:
                    async with s.ws_connect(
                            ctx.base_url.replace("https", "wss") + f"/ws/user-connection/{vpn_ids[name]}",
                            ssl=False) as ws:
                        await ws.send_bytes(b"\x00")
                        for _ in range(3):
                            m = await ws.receive(timeout=5)
                            if m.type in (1, 2):
                                msgs.append(m.data if isinstance(m.data, bytes) else m.data.encode())
                            else:
                                break
                except Exception as e:
                    msgs.append(repr(e).encode())
                refused = any(b"Tunnel mode not allowed" in m for m in msgs)
                if name == "vpn_tun":
                    ctx.ok("hosts: user vpn_tunnel in tun mode refused", refused, str(msgs)[:200])
                else:
                    ctx.ok("hosts: user vpn_tunnel in socks mode still starts",
                           not refused and any(b"connected" in m for m in msgs), str(msgs)[:200])
        else:
            ctx.ok("hosts: insert vpn rows", False, out.strip()[-200:])

    # Relay destinations are checked again right before ffmpeg is started.
    rc, out = await ctx.run_py(RELAY_CHECK)
    line = next((l for l in out.splitlines() if l.startswith("OUT=")), "")
    ctx.ok("hosts: relay re-check ran", rc == 0 and bool(line), out.strip()[-300:])
    if line:
        res = json.loads(line[len("OUT="):])
        ctx.ok("hosts: relay re-check refuses a name that now resolves internally",
               res["rebound_rtmp"] == "blocked" and res["rebound_rtmps"] == "blocked", str(res))
        ctx.ok("hosts: relay re-check refuses an internal literal", res["literal"] == "blocked", str(res))
        opts, url = res["public_rtmp"]
        ctx.ok("hosts: relay rtmp dials the checked address, keeps the name in tcUrl",
               url == "rtmp://u:pw@93.184.216.34:1936/app/sub/KEY"
               and opts == ["-rtmp_tcurl", "rtmp://public.example:1936/app/sub"], str(res))
        opts, url = res["public_rtmps"]
        ctx.ok("hosts: relay rtmps keeps the name for TLS",
               url == "rtmps://public.example/app/KEY" and opts == [], str(res))

    # Proxmox and HTTP proxy clients for user connections use the policy connector.
    rc, out = await ctx.run_py(PLUGIN_CLIENT_CHECK)
    line = next((l for l in out.splitlines() if l.startswith("OUT=")), "")
    ctx.ok("hosts: plugin client check ran", rc == 0 and bool(line), out.strip()[-300:])
    if line:
        res = json.loads(line[len("OUT="):])
        ctx.ok("hosts: proxmox user connection uses the policy connector",
               res["proxmox_user"] and res["handler_keys"], str(res))
        ctx.ok("hosts: proxmox admin service keeps the plain connector", res["proxmox_admin_plain"], str(res))
        ctx.ok("hosts: http proxy user connection uses the policy connector", res["http_user"], str(res))
        ctx.ok("hosts: http proxy admin service keeps the plain connector", res["http_admin_plain"], str(res))

    # MediaMTX ICE: only the configured origin is dialled, for every caller.
    rc, out = await ctx.run_py(ICE_CHECK)
    line = next((l for l in out.splitlines() if l.startswith("OUT=")), "")
    ctx.ok("hosts: mediamtx ICE check ran", rc == 0 and bool(line), out.strip()[-300:])
    if line:
        res = json.loads(line[len("OUT="):])
        ctx.ok("hosts: ICE resource off the webrtc_url origin is never dialled",
               res["hits"]["B"] == [], str(res))
        ctx.ok("hosts: ICE resource on the webrtc_url origin is dialled",
               res["hits"]["A"] == ["PATCH /cam/whep/abc", "PATCH /cam/whep/def"], str(res))
        ctx.ok("hosts: admin plugin schema still lists tun and tap",
               res["admin_enum"] == ["tun", "tap", "socks"], str(res))
        ctx.ok("hosts: tun mode is not started for a user vpn_tunnel",
               res["vpn_user_tun_started"] is False, str(res))
