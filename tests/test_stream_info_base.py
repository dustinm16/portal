"""GET /api/stream/{key}/info builds the playback addresses from the portal's configured public
address, never from the Host header of the request.

The access decision is replaced by a stub (it has its own tests in test_stream_access.py);
the handler runs on a mocked request. Nothing is dialled.

Run: venv/bin/python tests/test_stream_info_base.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import server  # noqa: E402
from config import Config  # noqa: E402

failures = []
DEADLINE = 60


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


STREAM = {"public_key": "pub_abcdefabcdefabcdefabcdef", "name": "n", "is_live": 1, "is_public": True,
          "allow_unauthenticated": 0}


async def info(host):
    async def fake_validate(stream_key, request=None):
        return dict(STREAM), None
    server._validate_stream_access = fake_validate
    req = make_mocked_request("GET", "/api/stream/pub_abc/info", headers={"Host": host},
                              match_info={"stream_key": "pub_abc"})
    resp = await server.http_stream_info(req)
    return json.loads(resp.body)


async def main():
    saved = (server._validate_stream_access, Config.PUBLIC_BASE_URL, Config.HOSTNAME)
    try:
        Config.PUBLIC_BASE_URL = ""
        Config.HOSTNAME = "portal.example.org"
        body = await info("evil.example.net")
        check("a forged Host header does not reach the addresses (hostname setting)",
              body["playback"]["hls"] == "https://portal.example.org/api/stream/abcdefabcdefabcdefabcdef/hls/index.m3u8"
              and body["playback"]["webrtc_whep"].startswith("https://portal.example.org/")
              and "evil" not in json.dumps(body), json.dumps(body))
        Config.PUBLIC_BASE_URL = "https://live.example.org:8443"
        body = await info("192.168.1.5:8080")
        check("the configured public address is used, port included",
              body["playback"]["hls"].startswith("https://live.example.org:8443/api/stream/abcdefabcdefabcdefabcdef/")
              and body["playback"]["webrtc_whep"].startswith("https://live.example.org:8443/"), json.dumps(body))
        check("the key shown has no pub_ prefix", body["public_key"] == "abcdefabcdefabcdefabcdef", json.dumps(body))
        Config.PUBLIC_BASE_URL = ""
        Config.HOSTNAME = ""
        body = await info("evil.example.net")
        check("with no usable public address the Host header is still not trusted",
              "evil" not in json.dumps(body) and body["playback"]["hls"].startswith("/api/stream/"), json.dumps(body))
    finally:
        server._validate_stream_access, Config.PUBLIC_BASE_URL, Config.HOSTNAME = saved
    print()
    print("FAILED: " + ", ".join(failures) if failures else "all checks passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        _rc = asyncio.run(asyncio.wait_for(main(), DEADLINE))
    except BaseException as exc:
        print(f"FAIL: test aborted with {type(exc).__name__}: {exc}", flush=True)
        os._exit(1)
    outbound_guard.report("test_stream_info_base")
    sys.exit(_rc)
