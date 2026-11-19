"""A backup whose extra copy failed sends backup.failed (the local archive is there, the extra
copy is not), not backup.ok. Fake archive creation and delivery; nothing is written or sent.

Run: venv/bin/python tests/test_backup_extra_alert.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402
import backup_manager as bm  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def run_with(info):
    sent = []

    async def fire(event, payload):
        sent.append((event, payload))
        return 1

    async def fake_cfg():
        return {"keep": 7, "extra_dir": "/mnt/extra"}

    async def fake_version():
        return "1.0.0"

    async def fake_record(*a, **k):
        return None

    alerts.reset_state()
    alerts.bind(fire=fire)
    saved = (bm.load_config, bm.um._get_portal_version, bm.create_archive, bm._record)
    bm.load_config, bm.um._get_portal_version, bm._record = fake_cfg, fake_version, fake_record
    bm.create_archive = lambda *a, **k: info
    try:
        await bm.run_now("manual")
        for _ in range(5):
            await asyncio.sleep(0)
        while alerts._tasks:
            await asyncio.gather(*list(alerts._tasks), return_exceptions=True)
    finally:
        bm.load_config, bm.um._get_portal_version, bm.create_archive, bm._record = saved
        alerts.unbind()
    return sent


async def main():
    sent = await run_with({"name": "portal-1.tar", "pruned": [], "extra_error": "disk full"})
    check("a failed extra copy sends backup.failed only", [e for e, _ in sent] == ["backup.failed"], str(sent))
    summary = sent[0][1]["summary"] if sent else ""
    check("the summary says the local archive was written and the extra copy failed",
          "local" in summary and "written" in summary and "extra copy failed" in summary, summary)
    sent = await run_with({"name": "portal-2.tar", "pruned": [], "extra_error": None})
    check("a backup with no extra problem still sends backup.ok", [e for e, _ in sent] == ["backup.ok"], str(sent))


asyncio.run(main())
if failures:
    print(f"\ntest_backup_extra_alert: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_backup_extra_alert: all checks passed")
