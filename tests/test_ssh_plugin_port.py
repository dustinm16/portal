"""The ssh plugin dials the same port the host-key accept dialog pins (1.24.2).

The plugin used config.get("port", target.port or 22) as it was stored; the accept dialog coerces the port
(text becomes a number, junk or out of range falls back to the service port or 22). A config port of "2222" now
dials 2222, "abc" or 99999 dials the service port or 22, in the terminal and in the health check, and always the
port server._service_ssh_target names. Fakes: the dial itself (connect_verified, asyncio.open_connection) is
replaced and records the host and port it was given; no network is used.

Run: venv/bin/python tests/test_ssh_plugin_port.py   (60 second deadline)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import WSMsgType  # noqa: E402

import server  # noqa: E402
import plugins.ssh as ssh_mod  # noqa: E402
from plugins.base import ServiceTarget  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send_json(self, data):
        self.sent.append(data)

    async def receive(self):
        return SimpleNamespace(type=WSMsgType.TEXT, data=json.dumps({"type": "auth", "username": "u", "password": "p"}))


CASES = [
    # (config port, service port, expected)
    ("2222", 22, 2222),
    (2222, 22, 2222),
    (" 2200 ", 22, 2200),
    ("abc", 2200, 2200),
    ("abc", None, 22),
    (99999, 2200, 2200),
    (99999, None, 22),
    (0, 2200, 2200),
    (None, 2200, 2200),
    (True, 2200, 2200),
    ("", None, 22),
    (None, "2300", 2300),
    ("junk", "junk", 22),
]


async def dial_port(plugin, target):
    seen = {}

    async def fake_connect(hosts, opts, **kw):
        seen["port"] = opts.get("port")
        seen["host"] = hosts[0]
        raise RuntimeError("stop here")
    real = ssh_mod.connect_verified
    ssh_mod.connect_verified = fake_connect
    try:
        await plugin.handle_websocket(FakeWS(), target, 1)
    finally:
        ssh_mod.connect_verified = real
    return seen


async def health_port(plugin, target):
    seen = {}

    async def fake_open(host, port):
        seen["port"] = port
        raise OSError("refused")
    real = asyncio.open_connection
    asyncio.open_connection = fake_open
    try:
        await plugin.health_check(target)
    finally:
        asyncio.open_connection = real
    return seen.get("port")


async def main():
    plugin = ssh_mod.SSHPlugin()
    check("asyncssh is available for the plugin", ssh_mod.HAS_ASYNCSSH)
    for cfg_port, svc_port, want in CASES:
        config = {"host": "93.184.216.34", "username": "u", "auth_method": "password"}
        if cfg_port is not None:
            config["port"] = cfg_port
        target = ServiceTarget(id=1, name="s", plugin="ssh", host="93.184.216.34", port=svc_port, config=config)
        label = f"config port {cfg_port!r}, service port {svc_port!r}"
        pinned = server._service_ssh_target({"host": "93.184.216.34", "port": svc_port, "config": config})[1]
        got = await dial_port(plugin, target)
        check(f"terminal dials {want} for {label}", got.get("port") == want, str(got))
        check(f"... which is the port the accept dialog pins", got.get("port") == pinned, f"{got} {pinned}")
        hp = await health_port(plugin, target)
        check(f"health check dials {want} for {label}", hp == want, str(hp))


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except BaseException as exc:      # a crash or the deadline prints FAIL and ends
    print(f"FAIL: the test stopped early ({exc!r})", flush=True)
    os._exit(1)
if failures:
    print(f"\ntest_ssh_plugin_port: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_ssh_plugin_port: all checks passed")
