"""A browser-mode connection's stored auth_header and extra_headers go only to the connection's own site (1.24.1).

Through the real /proxy/{uuid} handler against two local upstreams that answer with the headers they received.
The connection browses any site (browser_mode) and holds an auth_header and an extra header. They must reach the
connection's own origin (by the bare path, by ~/ and by its full address), and must not reach another host or port
the page is on, nor the same host on the other scheme or its default port (the ~http / ~https address, which would
send an https connection's secret in clear). Only the outbound host policy is replaced (it refuses loopback).
Run: venv/bin/python tests/test_proxy_browser_secrets.py   (60 second deadline)
"""

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

SECRET = "Bearer owner-secret-token"
EXTRA = "extra-secret-value"
CAP = re.compile(r"/~pc1\.[A-Za-z0-9_.-]+")


async def echo(request):
    return web.json_response({"auth": request.headers.get("Authorization"), "x": request.headers.get("X-Owner-Extra")})


async def main():
    up = web.Application()
    up.router.add_get("/echo", echo)
    own, other = TestServer(up, host="127.0.0.1"), TestServer(web.Application(), host="127.0.0.1")
    other.app.router.add_get("/echo", echo)
    await own.start_server()
    await other.start_server()
    env = await h.boot()
    owner, bob = env.sessions["owner"], env.sessions["bob"]

    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)

    cfg = {"browser_mode": True, "auth_header": SECRET, "extra_headers": {"X-Owner-Extra": EXTRA}}
    buuid = await env.db.create_user_connection(env.uid["owner"], "web b", "http", "127.0.0.1", own.port, json.dumps(cfg))
    async with owner.post(f"{env.base}/api/connections/{buuid}/shares", json={"usernames": ["bob"], "expires_in": "7d"}) as r:
        check("the owner shares the browser-mode connection", r.status == 200, str(r.status))
    async with bob.post(f"{env.base}/api/connections/{buuid}/notice") as r:
        assert r.status == 200, r.status

    sent = []
    real = server._proxy_request_headers

    def spy(*a, **kw):
        out = real(*a, **kw)
        sent.append((a[3], dict(out)))              # (the proxy prefix, what goes upstream)
        return out
    server._proxy_request_headers = spy

    async def get(sess, path):
        """The entry redirect to the address with the credential, then the page at that address."""
        async with sess.get(f"{env.base}/proxy/{buuid}/{path}", allow_redirects=False) as r0:
            entry = r0.headers.get("Location", "")
            assert r0.status == 302 and "/~pc1." in entry, (r0.status, entry)
        sent.clear()
        async with sess.get(env.base + entry, allow_redirects=False) as r:
            body = await r.text()
        try:
            return r.status, json.loads(body)
        except ValueError:
            return r.status, None

    def carried():
        """Whether the last dial was sent the stored header and the extra header."""
        hdrs = sent[-1][1] if sent else {}
        return hdrs.get("Authorization") == SECRET, hdrs.get("X-Owner-Extra") == EXTRA

    own_full = f"http://127.0.0.1:{own.port}/echo"
    for sess, path, label in ((owner, "echo", "the owner by a bare path"), (owner, own_full, "the owner by the full address of the own site"),
                              (bob, "~/echo", "a grantee through ~/"), (bob, "echo", "a grantee by a bare path"),
                              (bob, own_full, "a grantee by the full address of the own site")):
        st, data = await get(sess, path)
        check(f"the stored headers reach the connection's own site: {label}",
              st == 200 and data == {"auth": SECRET, "x": EXTRA} and carried() == (True, True), f"{st} {data}")

    other_full = f"http://127.0.0.1:{other.port}/echo"
    for sess, path, label in ((owner, other_full, "the owner, another port of the same host"),
                              (bob, other_full, "a grantee, another port of the same host"),
                              (owner, f"http://localhost:{own.port}/echo", "the owner, another name for the same machine"),
                              (bob, f"http://localhost:{own.port}/echo", "a grantee, another name for the same machine")):
        st, data = await get(sess, path)
        check(f"no stored header goes to another site: {label}",
              st == 200 and data == {"auth": None, "x": None} and carried() == (False, False), f"{st} {data} {sent[-1:]}")

    # the same host on the other scheme or its default port: the alias dials port 80 (nothing listens there: 502 is the answer)
    for alias in ("~http", "~https"):
        st, data = await get(bob, f"{alias}/echo")
        check(f"{alias} sends no stored header (an https secret must not leave in clear)",
              bool(sent) and carried() == (False, False), f"{st} {sent[-1:]}")

    server._proxy_request_headers = real
    # the function itself: the old call shape still sends them, the keyword withholds them
    from aiohttp.test_utils import make_mocked_request
    Req = lambda: make_mocked_request("GET", "/")
    h1 = real(Req(), cfg, "x", "/p", True)
    h2 = real(Req(), cfg, "x", "/p", True, send_secrets=False)
    check("_proxy_request_headers sends the stored headers by default and not with send_secrets=False",
          h1.get("Authorization") == SECRET and h1.get("X-Owner-Extra") == EXTRA
          and "Authorization" not in h2 and "X-Owner-Extra" not in h2, f"{dict(h1)} {dict(h2)}")

    await h.shutdown(env)
    await own.close()
    await other.close()


asyncio.run(asyncio.wait_for(main(), 60))
h.finish("test_proxy_browser_secrets")
