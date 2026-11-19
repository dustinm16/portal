"""A game server stopped by the portal itself for a SteamCMD update is not a crash.

The update path stops the unit with a direct systemctl call. The fake systemctl used here
leaves the unit in the "failed" state after the stop (a server that exits non-zero on SIGTERM),
and the service handler is polled while SteamCMD "runs", as the health monitor does. Without the
mark the poll raises gameserver.crashed; with it nothing is sent, and a real crash afterwards
(the unit running again, then failing) still is. Nothing touches the host: systemctl and
SteamCMD are fakes.

Run: venv/bin/python tests/test_gameserver_update_stop.py
"""

import asyncio
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import gameservers  # noqa: E402
import jobs  # noqa: E402
import services  # noqa: E402
from services.gameserver import GameServerService  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


FAKE_SYSTEMCTL = """#!/bin/sh
# fake systemctl: state in $FAKE_STATE, calls appended to $FAKE_STATE.calls
echo "$*" >> "$FAKE_STATE.calls"
case "$1" in
  is-active) cat "$FAKE_STATE"; exit 0 ;;
  stop) echo failed > "$FAKE_STATE" ;;
  start) echo active > "$FAKE_STATE" ;;
esac
exit 0
"""


class FakeDb:
    def __init__(self, gs):
        self.gs = gs
        self.updates = []

    async def game_server_get(self, gs_id):
        return dict(self.gs)

    async def game_server_update(self, gs_id, **kw):
        self.updates.append(kw)


class Handler(GameServerService):
    def __init__(self, state_file):
        self.id, self.name, self.display_name = 7, "pal", "Pal"
        self.config = {"unit": "portal-gs-pal"}
        self._expected_stop = False
        self.status = "running"
        self._db = None
        self._main_pid = None
        self.emitted = []
        self._on_event = lambda e, d: self.emitted.append((e, d))
        self.state_file = state_file

    async def _show(self):
        state = Path(self.state_file).read_text().strip()
        return {"active_state": state, "sub_state": "running" if state == "active" else state,
                "main_pid": 100 if state == "active" else 0}


class FakeManager:
    def __init__(self, handler):
        self.handler = handler

    async def get_service(self, sid):
        return self.handler if sid == 7 else None


async def scenario(gs_mod):
    """Run one update of a running game server through gs_mod._update_job; return the handler
    and the systemctl calls made."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        bindir = tmp / "bin"
        bindir.mkdir()
        fake = bindir / "systemctl"
        fake.write_text(FAKE_SYSTEMCTL)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        state = tmp / "state"
        state.write_text("active\n")
        os.environ["FAKE_STATE"] = str(state)
        install = tmp / "srv"
        install.mkdir()
        (install / "run.sh").write_text("#!/bin/sh\n")
        gs = {"id": 3, "steam_app_id": 4242, "install_dir": str(install), "unit_name": "portal-gs-pal",
              "steam_login": "anonymous", "start_cmd": "./run.sh", "runtime": "native", "service_id": 7}
        handler = Handler(str(state))
        saved = (gs_mod._sudo, gs_mod._latest_build, gs_mod._run, gs_mod._steam_update_cmd, services.service_manager)

        def fake_sudo(*args):
            return [str(fake), *args[1:]] if args and args[0] == "systemctl" else ["true"]

        async def fake_latest(app_id, login):
            return "999"

        async def fake_run(job, args, timeout=3600, cwd=None):
            # The health monitor polls while SteamCMD runs.
            await handler.sync_status()
            return 0

        gs_mod._sudo, gs_mod._latest_build, gs_mod._run = fake_sudo, fake_latest, fake_run
        gs_mod._steam_update_cmd = lambda *a, **k: ["true"]
        services.service_manager = FakeManager(handler)
        try:
            await handler.sync_status()          # baseline: running
            job = {"id": "t", "log": [], "status": "running"}
            await gs_mod._update_job(FakeDb(gs), 3, job)
            calls = Path(str(state) + ".calls").read_text().splitlines()
            await handler.sync_status()          # the restarted unit is running again
            after_update = list(handler.emitted)
            state.write_text("failed\n")        # a real crash later on
            await handler.sync_status()
            return handler, calls, after_update, job
        finally:
            gs_mod._sudo, gs_mod._latest_build, gs_mod._run, gs_mod._steam_update_cmd, services.service_manager = saved


async def main():
    handler, calls, emitted, job = await scenario(gameservers)
    check("the update stopped and restarted the unit through systemctl",
          any(c.startswith("stop ") for c in calls) and any(c.startswith("start ") for c in calls), str(calls))
    check("the unit was seen 'failed' while stopped and no crash was announced", emitted == [], str(emitted))
    check("the requested-stop flag is cleared once the unit runs again", handler._expected_stop is False)
    check("a real crash after the update is still announced",
          [e for e, _ in handler.emitted] == ["gameserver.crashed"], str(handler.emitted))


if __name__ == "__main__":
    asyncio.run(main())
    if failures:
        print(f"\ntest_gameserver_update_stop: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print("\ntest_gameserver_update_stop: all checks passed")
