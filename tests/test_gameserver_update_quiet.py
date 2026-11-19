"""A game server stopped by the portal for an update is quiet to the health alerts."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gameservers as gs_mod  # noqa: E402
import services  # noqa: E402


class Svc:
    _expected_stop = False


class Mgr:
    def __init__(self):
        self._stopped_on_purpose = set()
        self.svc = Svc()

    async def get_service(self, sid):
        return self.svc


async def main():
    saved = services.service_manager
    mgr = Mgr()
    services.service_manager = mgr
    try:
        await gs_mod._mark_expected_stop({"service_id": 7, "unit_name": "x"})
    finally:
        services.service_manager = saved
    assert mgr.svc._expected_stop is True, "crash detection is told"
    assert 7 in mgr._stopped_on_purpose, "health alerts are told"
    src = Path(gs_mod.__file__).read_text()
    i = src.index('jobs.log(job, "restarting service")')
    assert "_stopped_on_purpose" in src[i:i + 500] and "discard" in src[i:i + 500], \
        "the mark is cleared before the restart so a failed restart alerts"
    print("test_gameserver_update_quiet: all checks passed")


asyncio.run(main())
