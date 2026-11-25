"""Measuring a session's chunk lengths: one running probe per member, the global cap stays.

The listing, the cache and the probe job are replaced by fakes (no SFTP, no ffprobe); the job waits on an
event so a probe stays "running" for as long as the test needs.

Run: venv/bin/python tests/test_vod_probe_owner.py
"""
import asyncio
import json
import os
import signal
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402

DEADLINE = 60
STORAGE = {"host": "h", "username": "u", "port": 22, "remote_path": "/v"}
A, B = 11, 12


class FakeCache:
    def get_duration(self, *a):
        return None

    def save_durations(self):
        pass


async def _listing(user_id, storage, folder):
    return [(1, "chunk_001.mkv", 10, 100), (2, "chunk_002.mkv", 10, 100)]


async def _asking(env, user, folder):
    resp = await server._vod_session_playlist(user, STORAGE, folder)
    body = {}
    try:
        body = json.loads(resp.text)
    except Exception:  # noqa: BLE001
        pass
    return resp.status, body


async def _scenario(max_probes=4):
    release = asyncio.Event()
    started = []

    async def job(probe, storage, todo):
        started.append((probe["owner"], probe["folder"]))
        try:
            await release.wait()
        finally:
            probe["finished"] = server.monotonic()
            probe["state"] = "ready"

    server._vod_session_probes.clear()
    patches = [mock.patch.object(server, "_vod_session_listing", _listing),
               mock.patch.object(server, "_vod_play_cache", FakeCache()),
               mock.patch.object(server, "_vod_session_is_live", lambda s, f: False),
               mock.patch.object(server, "_vod_session_probe_job", job),
               mock.patch.object(server, "VOD_SESSION_PROBE_MAX", max_probes)]
    for p in patches:
        p.start()
    try:
        out = {}
        out["a1"] = (await _asking(None, A, "Show/one"))[0]
        await asyncio.sleep(0.05)
        out["a1_again"] = (await _asking(None, A, "Show/one"))[0]
        out["a2"] = (await _asking(None, A, "Show/two"))[0]
        out["b1"] = (await _asking(None, B, "Show/one"))[0]
        await asyncio.sleep(0.05)
        out["started"] = list(started)
        release.set()
        await asyncio.sleep(0.05)
        out["a2_after"] = (await _asking(None, A, "Show/two"))[0]
        await asyncio.sleep(0.05)
        return out
    finally:
        release.set()
        for t in list(server._vod_play_tasks):
            t.cancel()
        await asyncio.sleep(0)
        for p in patches:
            p.stop()
        server._vod_session_probes.clear()


def test_a_member_measures_one_session_at_a_time_and_another_member_is_not_held_up():
    out = asyncio.run(asyncio.wait_for(_scenario(), 30))
    assert out["a1"] == 202, out
    assert out["a1_again"] == 202, out          # the same session: the running probe is reported
    assert out["a2"] == 503, out                # a second session of the same member waits
    assert out["b1"] == 202, out
    assert out["started"] == [(A, "Show/one"), (B, "Show/one")], out
    assert out["a2_after"] == 202, out          # once the first probe is done, the second one starts


def test_the_global_cap_still_holds():
    async def go():
        out = await _scenario(max_probes=1)
        return out
    out = asyncio.run(asyncio.wait_for(go(), 30))
    assert out["a1"] == 202 and out["b1"] == 503, out
    assert out["started"] == [(A, "Show/one")], out


def _deadline(signum, frame):
    print("FAIL: test_vod_probe_owner timed out", flush=True)
    os._exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE * 2)
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except BaseException as e:  # noqa: BLE001
                failed += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e!r}")
    sys.exit(1 if failed else 0)
