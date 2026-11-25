"""The link preview resolves the host name without blocking the event loop.

A slow resolver (monkeypatched socket.getaddrinfo) must not stop the loop from running other
work, a lookup that takes longer than the limit answers 400, and a name that resolves to a
private address still answers 403.

Run: venv/bin/python tests/test_link_preview_dns.py
"""

import asyncio
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402
outbound_guard.install()
import server  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402


class _Tok:
    user_id = 1


async def _fake_auth(request):
    return _Tok()


def _call(url):
    req = make_mocked_request("GET", "/api/chat/link-preview?url=" + url)
    return server.http_link_preview(req)


def _with(resolver, body):
    async def go():
        saved = (socket.getaddrinfo, server.authenticate_request, getattr(server, "_LINK_PREVIEW_DNS_TIMEOUT", 5.0))
        socket.getaddrinfo = resolver
        server.authenticate_request = _fake_auth
        try:
            await body()
        finally:
            socket.getaddrinfo, server.authenticate_request, server._LINK_PREVIEW_DNS_TIMEOUT = saved
    asyncio.run(asyncio.wait_for(go(), 30))


def _answer(public=True):
    ip = "93.184.216.34" if public else "10.1.2.3"
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_the_loop_keeps_ticking_during_a_slow_lookup():
    def slow(host, *a, **k):
        time.sleep(1.0)
        return _answer(False)          # private: the request ends with a 403 once the lookup returns

    async def body():
        ticks = []

        async def ticker():
            while True:
                ticks.append(time.monotonic())
                await asyncio.sleep(0.05)
        t = asyncio.ensure_future(ticker())
        await asyncio.sleep(0.2)
        before = len(ticks)
        resp = await _call("http://slow.example/page")
        t.cancel()
        assert resp.status == 403, resp.status
        gaps = [b - a for a, b in zip(ticks, ticks[1:])]
        assert len(ticks) - before >= 10, (before, len(ticks))
        assert max(gaps) < 0.5, f"the event loop stalled for {max(gaps):.2f} s"
    _with(slow, body)


def test_a_lookup_over_the_limit_answers_400():
    def slow(host, *a, **k):
        time.sleep(1.5)
        return _answer(True)

    async def body():
        server._LINK_PREVIEW_DNS_TIMEOUT = 0.3
        t0 = time.monotonic()
        resp = await _call("http://slower.example/page")
        assert resp.status == 400, resp.status
        assert time.monotonic() - t0 < 1.2
    _with(slow, body)


def test_a_private_address_still_answers_403():
    async def body():
        resp = await _call("http://internal.example/page")
        assert resp.status == 403, resp.status
    _with(lambda host, *a, **k: _answer(False), body)


def test_an_unknown_name_still_answers_400():
    def nope(host, *a, **k):
        raise socket.gaierror(-2, "Name or service not known")

    async def body():
        resp = await _call("http://nowhere.example/page")
        assert resp.status == 400, resp.status
    _with(nope, body)


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except BaseException as e:
                bad += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if bad else 0)
