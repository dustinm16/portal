"""A stale hidden part file is removed in a later pass even when the local backlog is gone by then.

The sweep removes .live_*.part and .sweep_*.part files older than 24 hours from a remote session folder, but
only while it lists that folder, which it does only while a local staging folder still waits for it. After a
crash the part file is young during that delivery and nothing lists the folder again. The sweep therefore
remembers the folders it delivered into (a setting) and looks at them once more after a day. Real asyncssh
SFTP server on loopback, temporary directories only; the clock of the server module is moved forward.

Run: venv/bin/python tests/test_vod_part_revisit.py
"""
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Patched, Remote, SweepDb, REMOTE, run, server, session  # noqa: E402
from config import Config  # noqa: E402

DEADLINE = 90
DAY = 24 * 3600
PART = ".live_chunk_003_aaaa1111.part"
OTHER_PART = ".sweep_004_bbbb2222.part"


class KeepDb(SweepDb):
    """SweepDb whose settings can be written, like the real one."""

    async def set_setting(self, key, value):
        self.settings[key] = value


def _later(days):
    real = time.time
    return mock.patch.object(server, "time", lambda: real() + days * DAY)


def _scenario(extra=None, host="127.0.0.1", stage_mode=False, live_dir=None, days=2):
    """Pass 1 delivers a chunk beside a young part file; pass 2 runs `days` days later with no backlog."""
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodrevisit_") as t:
            async with Remote(t) as remote:
                remote.put(f"{REMOTE}/chunk_000.mkv", b"old")
                remote.put(f"{REMOTE}/{PART}", b"x")                  # young: written a moment ago
                db = KeepDb(remote, host=host)
                session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"new-chunk"})
                with Patched(t, remote, db):
                    await asyncio.wait_for(server.recover_vod_staging(), 60)
                    first = remote.listing(REMOTE)
                    saved = db.settings.get(server.VOD_PART_REVISIT_KEY)
                    if extra:
                        extra(remote)
                    server._vod_sweep_claims.clear()           # a restart: no memory is kept, the setting stays
                    live = {live_dir: {"session_dir": os.path.join(t, "stage", "9_live"),
                                       "remote_session_dir": live_dir}} if live_dir else {}
                    with _later(days), mock.patch.object(Config, "STAGE_MODE", stage_mode), \
                            mock.patch.dict(server.active_recordings, {9: live[live_dir]} if live else {}):
                        await asyncio.wait_for(server.recover_vod_staging(), 60)
                    return first, remote.listing(REMOTE), saved, db.settings.get(server.VOD_PART_REVISIT_KEY)
    return run(asyncio.wait_for(go(), DEADLINE))


def test_a_part_file_that_was_young_during_the_delivery_is_removed_in_a_later_pass():
    first, second, saved, after = _scenario()
    assert PART in first and "chunk_001.mkv" in first, first          # kept while young, chunk delivered
    entries = json.loads(saved)
    assert len(entries) == 1 and entries[0]["d"] == REMOTE and entries[0]["u"] == 7, entries
    assert PART not in second, f"the part file stays on the member's storage: {second}"
    assert "chunk_001.mkv" in second and "chunk_000.mkv" in second, second     # nothing else was touched
    assert json.loads(after) == [], "a clean folder is dropped from the list"


def test_nothing_is_removed_before_a_day_has_passed():
    first, second, _saved, after = _scenario(days=0.5)
    assert PART in second, second
    assert len(json.loads(after)) == 1, "the entry waits for the day to pass"


def test_a_folder_a_recording_uses_is_left_alone_and_stays_listed():
    _first, second, _saved, after = _scenario(live_dir=REMOTE)
    assert PART in second, second
    assert len(json.loads(after)) == 1, after


def test_a_stage_instance_with_a_real_storage_removes_nothing():
    _first, second, _saved, _after = _scenario(host="storage.example.org", stage_mode=True)
    assert PART in second, second


def test_a_part_that_is_still_young_at_the_revisit_is_asked_again_a_day_later():
    def fresh(remote):
        remote.put(f"{REMOTE}/{OTHER_PART}", b"y")                   # written just before the second pass
        when = time.time() + 1.5 * DAY                               # (the test clock runs 1 day ahead)
        os.utime(remote.path(f"{REMOTE}/{OTHER_PART}"), (when, when))
    _first, second, _saved, after = _scenario(extra=fresh, days=1.001)
    assert PART not in second and OTHER_PART in second, second
    entries = json.loads(after)
    assert len(entries) == 1 and entries[0]["at"] > entries[0]["first"] + DAY * 0.9, entries


def test_a_storage_that_cannot_be_reached_is_asked_again_a_day_later_not_at_every_pass():
    async def down(user_id):
        return None, None, "Connection failed"
    patcher = mock.patch.object(server, "_connect_vod_sftp", down)
    try:
        _first, second, _saved, after = _scenario(extra=lambda remote: patcher.start(), days=2)
    finally:
        patcher.stop()
    assert PART in second, "nothing can be removed while the storage is down"
    entries = json.loads(after)
    assert len(entries) == 1 and entries[0]["at"] > entries[0]["first"] + DAY * 1.5, entries


if __name__ == "__main__":
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
