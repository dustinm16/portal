"""An in-flight proxied response and the proxy WebSocket relay, opened through a share, end when
the share is revoked and when it expires.

This goes through the real /proxy/{uuid} handler (_proxy_connection_authed) against a local
upstream that holds the response and the socket open, with the real database, the real share
routes and the real sweeper. Removing the _track_shared_access call in either branch of the
handler makes the matching checks fail. Only the outbound host policy is replaced (it refuses a
loopback upstream).

Run: venv/bin/python tests/test_grant_proxy_paths.py
"""

import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
import grant_expiry  # noqa: E402

T0 = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
clock = {"now": T0}
grant_expiry.set_clock(lambda: clock["now"])
upstream_events = []
CLOSED_CODES = (server.GRANT_ENDED_CLOSE_CODE, 1006)


async def held_download(request):
    """Sends the first bytes, then holds the response open for 30 s."""
    resp = web.StreamResponse(headers={"Content-Type": "application/octet-stream"})
    await resp.prepare(request)
    await resp.write(b"first")
    upstream_events.append("download-open")
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:
        upstream_events.append("download-dropped")
        raise
    return resp


async def held_socket(request):
    """A WebSocket upstream that says hi and then holds the socket open."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_str("hi")
    upstream_events.append("ws-open")
    async for _ in ws:
        pass
    upstream_events.append("ws-closed")
    return ws


async def read_until_ended(resp, wait=4.0):
    """True if the proxied body ended (cleanly or with an error) within `wait` seconds."""
    try:
        await asyncio.wait_for(resp.content.read(), wait)
        return True
    except asyncio.TimeoutError:
        return False
    except (aiohttp.ClientError, ConnectionError):
        return True


async def main():
    up = web.Application()
    up.router.add_get("/download", held_download)
    up.router.add_get("/ws", held_socket)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()

    env = await h.boot()
    db, owner, bob = env.db, env.sessions["owner"], env.sessions["bob"]
    # Test-only: the real outbound policy refuses a loopback upstream.
    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    uuid, cid = await h.connection(env, "owner", name="web", ctype="http", host="127.0.0.1", port=upstream.port)
    share_url = f"{env.base}/api/connections/{uuid}/shares"
    ws_base = env.base.replace("http", "ws")

    async def share(duration="7d"):
        async with owner.post(share_url, json={"usernames": ["bob"], "expires_in": duration}) as r:
            assert r.status == 200, r.status

    async def wait_event(name, wait=3.0):
        end = time.monotonic() + wait
        while name not in upstream_events and time.monotonic() < end:
            await asyncio.sleep(0.05)
        return name in upstream_events

    # ---- sanity: the share works through the proxy ---------------------------------------------------
    await share()
    async with bob.get(f"{env.base}/proxy/{uuid}/download") as r:
        check("the grantee reaches the upstream through the share", r.status == 200 and await r.content.readexactly(5) == b"first")
    check("(the upstream saw the request)", await wait_event("download-open"))
    upstream_events.clear()

    # ---- revoke: held download -----------------------------------------------------------------------
    await share()
    resp = await bob.get(f"{env.base}/proxy/{uuid}/download")
    await resp.content.readexactly(5)
    check("a held response is in flight", await wait_event("download-open"))
    check("it is registered as a dependent of the share",
          any(k[:2] == ("conn", cid) and len(v) for k, v in server._grant_dependents.items()))
    async with owner.delete(f"{share_url}/{env.uid['bob']}") as r:
        check("the owner revokes the share", r.status == 200)
    check("the in-flight proxied response ends on revoke", await read_until_ended(resp))
    resp.close()
    check("the portal dropped its upstream request too", await wait_event("download-dropped"))
    upstream_events.clear()

    # ---- revoke: WebSocket relay ------------------------------------------------------------------------
    await share()
    ws = await bob.ws_connect(f"{ws_base}/proxy/{uuid}/ws")
    check("the relay delivers the upstream's first frame", (await asyncio.wait_for(ws.receive(), 3)).data == "hi")
    async with owner.delete(f"{share_url}/{env.uid['bob']}") as r:
        check("the owner revokes the share again", r.status == 200)
    cc = await h.close_code(ws)
    # The relay's own reader sees the close first, so the client may see the connection drop (1006)
    # rather than the 4010 frame; what is proved is that the relay ends.
    check("the proxy WebSocket relay is closed on revoke", cc in CLOSED_CODES, str(cc))
    check("the upstream socket was closed with it", await wait_event("ws-closed"))
    upstream_events.clear()

    # ---- expiry: held download -------------------------------------------------------------------------
    clock["now"] = T0
    await share("1h")
    resp = await bob.get(f"{env.base}/proxy/{uuid}/download")
    await resp.content.readexactly(5)
    check("a held response is in flight (expiry case)", await wait_event("download-open"))
    clock["now"] = T0 + timedelta(hours=1, seconds=1)
    check("the sweeper deletes the expired share", await server.sweep_expired_grants_once() == 1)
    check("the in-flight proxied response ends on expiry", await read_until_ended(resp))
    resp.close()
    upstream_events.clear()

    # ---- expiry: WebSocket relay ------------------------------------------------------------------------
    clock["now"] = T0
    await share("1h")
    ws = await bob.ws_connect(f"{ws_base}/proxy/{uuid}/ws")
    check("the relay delivers the first frame (expiry case)", (await asyncio.wait_for(ws.receive(), 3)).data == "hi")
    clock["now"] = T0 + timedelta(hours=1, seconds=1)
    check("the sweeper deletes the expired share (relay case)", await server.sweep_expired_grants_once() == 1)
    cc = await h.close_code(ws)
    check("the proxy WebSocket relay is closed on expiry", cc in CLOSED_CODES, str(cc))

    # ---- after the end, nothing new gets through -----------------------------------------------------------
    async with bob.get(f"{env.base}/proxy/{uuid}/download") as r:
        check("a new proxied request after the end is refused", r.status == 404, str(r.status))

    grant_expiry.set_clock(None)
    await h.shutdown(env)
    await upstream.close()


asyncio.run(main())
h.finish("test_grant_proxy_paths")
