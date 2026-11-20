"""Closing what a grantee holds open through a share is concurrent and bounded.

A grantee whose sockets are dead made the owner's revoke (and the sweeper) wait about 10 s per
socket, one after the other. close_grant_dependents now closes them together and waits at most
GRANT_CLOSE_WAIT_SECONDS in all.

Run: venv/bin/python tests/test_grant_close.py
"""

import asyncio
import time

from aiohttp import web

import grant_harness as h
from grant_harness import check, server


class StuckSocket(web.WebSocketResponse):
    """A WebSocket whose peer is gone: the close handshake takes `stall` seconds to give up."""

    def __init__(self, stall):
        super().__init__()
        self.stall = stall
        self.close_codes = []

    async def close(self, *, code=1000, message=b"", **kw):
        self.close_codes.append(code)
        await asyncio.sleep(self.stall)
        return True


async def main():
    env = await h.boot()
    uuid, cid = await h.connection(env, "owner")
    bob = env.uid["bob"]

    # ---- the function itself: five dead sockets, 3 s each (15 s one after the other) -------------
    sockets = [StuckSocket(3.0) for _ in range(5)]
    for s in sockets:
        server._register_grant_dependent("conn", cid, bob, s)
    t0 = time.monotonic()
    n = await server.close_grant_dependents("conn", cid, bob)
    took = time.monotonic() - t0
    check("five dead sockets are all asked to close with the access-ended code",
          n == 5 and all(s.close_codes == [server.GRANT_ENDED_CLOSE_CODE] for s in sockets), str(n))
    check("... and the call returns within the bound, not after 5 x 3 s", took < server.GRANT_CLOSE_WAIT_SECONDS + 1.0, f"{took:.1f}s")
    check("the registry no longer holds them", not any(k[1] == cid for k in server._grant_dependents))

    # ---- through the real revoke route -------------------------------------------------------------
    r = await env.sessions["owner"].post(f"{env.base}/api/connections/{uuid}/shares", json={"usernames": ["bob"], "expires_in": "7d"})
    check("share for the route case", r.status == 200)
    stuck = [StuckSocket(3.0) for _ in range(4)]
    for s in stuck:
        server._register_grant_dependent("conn", cid, bob, s)
    live_ws, _ = await h.open_ws(env.sessions["bob"], env.base, uuid)
    t0 = time.monotonic()
    r = await env.sessions["owner"].delete(f"{env.base}/api/connections/{uuid}/shares/{bob}")
    took = time.monotonic() - t0
    check("the owner's revoke answers 200", r.status == 200, str(r.status))
    check("... within about 2 s although four sockets are dead", took < 3.0, f"{took:.1f}s")
    check("a live socket is still closed with 4010", await h.close_code(live_ws) == server.GRANT_ENDED_CLOSE_CODE)

    # ---- the sweeper ----------------------------------------------------------------------------------
    import grant_expiry
    from datetime import datetime, timedelta, timezone
    t0_clock = datetime(2030, 1, 1, tzinfo=timezone.utc)
    clock = {"now": t0_clock}
    grant_expiry.set_clock(lambda: clock["now"])
    await env.db.add_connection_share(cid, bob, env.uid["owner"], "1h")
    stuck = [StuckSocket(3.0) for _ in range(4)]
    for s in stuck:
        server._register_grant_dependent("conn", cid, bob, s)
    clock["now"] = t0_clock + timedelta(hours=2)
    t0 = time.monotonic()
    n = await server.sweep_expired_grants_once()
    took = time.monotonic() - t0
    check("the sweeper removed the share", n == 1, str(n))
    check("... and was not held by the four dead sockets", took < 3.0, f"{took:.1f}s")
    check("... each of them was told to close", all(s.close_codes == [server.GRANT_ENDED_CLOSE_CODE] for s in stuck))
    grant_expiry.set_clock(None)

    await asyncio.sleep(3.2)        # let the background closes finish before the loop ends
    await h.shutdown(env)


asyncio.run(main())
h.finish("test_grant_close")
