"""Shared guard for the webhook and alert tests: an aiohttp connection to any address that is
not loopback is refused before a socket is opened, and the attempt is recorded in `refused`.

Fixtures use public-looking URLs (a documentation host, discord.com, hooks.slack.com) because
the URL validation needs them; with this guard installed none of them can be dialled for real.

Use at the top of a test, after the path setup:

    import outbound_guard
    outbound_guard.install()
"""

import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aiohappyeyeballs  # noqa: E402

refused = []
_real_start_connection = aiohappyeyeballs.start_connection
_installed = False


def _loopback(ip):
    try:
        return ipaddress.ip_address(str(ip).split("%")[0]).is_loopback
    except ValueError:
        return False


async def _guarded_start_connection(addr_infos, *args, **kwargs):
    targets = [ai[4][0] for ai in addr_infos]
    bad = [t for t in targets if not _loopback(t)]
    if bad:
        refused.append(bad[0])
        raise OSError(f"test guard: refusing to dial non-loopback address {bad[0]}")
    return await _real_start_connection(addr_infos, *args, **kwargs)


def install():
    """Patch the dial point of every aiohttp TCP connector in this process (idempotent)."""
    global _installed
    if not _installed:
        aiohappyeyeballs.start_connection = _guarded_start_connection
        _installed = True
    return refused


def report(name):
    """Print what the guard refused, so a test run shows which fixtures tried to leave."""
    print(f"{name}: outbound guard refused {len(refused)} non-loopback dial(s)" + (f": {sorted(set(refused))}" if refused else ""))
