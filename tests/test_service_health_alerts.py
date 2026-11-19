"""ServiceManager health transitions: down after three failed checks, up after two good
ones, nothing for a flapping service, a disabled or healthy one, or the first healthy check;
a game server's unexpected exit versus a requested stop. Fake services, no host access.

Run: venv/bin/python tests/test_service_health_alerts.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402
import services as svc  # noqa: E402
from services.gameserver import GameServerService  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeDb:
    async def update_service_health_status(self, *a):
        pass

    async def get_setting(self, k):
        return None


class Fake:
    """Just what the health pass touches."""

    def __init__(self, sid, status="running", healthy=True, enabled=True):
        self.id, self.name, self.display_name = sid, f"svc{sid}", f"Svc {sid}"
        self.status, self.healthy, self.enabled = status, healthy, enabled
        self.process = None

    async def health_check(self):
        return self.healthy

    start_ok = True

    async def start(self):
        if not self.start_ok:
            return False, "boom"
        self.status = "running"
        return True, ""

    async def stop(self):
        self.status = "stopped"
        return True, ""

    restart_ok = True

    async def restart(self):
        if not self.restart_ok:
            self.status = "stopped"
            return False, "boom"
        self.status = "running"
        return True, ""

    def validate_config(self, config):
        return True, ""


async def main():
    events = []
    mgr = svc.ServiceManager(FakeDb(), on_event=lambda e, d: events.append((e, d)))
    s = Fake(1)
    mgr._services[1] = s

    async def passes(n):
        for _ in range(n):
            await mgr._check_services_once()

    await passes(5)
    check("a healthy service sends nothing", events == [])
    s.status = "stopped"
    await passes(2)
    check("two failed checks send nothing", events == [])
    await passes(1)
    check("the third failed check sends one 'down'",
          [(e, d["state"]) for e, d in events] == [("service.health_changed", "down")], str(events))
    await passes(10)
    check("a long outage sends no second alert", len(events) == 1)
    s.status, s.healthy = "running", True
    await passes(1)
    check("one good check is not yet recovery", len(events) == 1)
    s.status = "stopped"
    await passes(1)
    s.status = "running"
    await passes(1)
    check("a flap during recovery sends nothing", len(events) == 1)
    await passes(1)
    check("two good checks in a row send one 'up'",
          [d["state"] for _, d in events] == ["down", "up"], str(events))
    await passes(5)
    check("and nothing more", len(events) == 2)

    # flapping service never reaches three in a row
    events.clear()
    f = Fake(2)
    mgr._services[2] = f
    for i in range(12):
        f.status = "running" if i % 2 else "stopped"
        await mgr._check_services_once()
    check("a service that flaps every check sends nothing", [e for e in events if e[1]["id"] == 2] == [])

    # running but unhealthy counts, and a disabled service does not
    events.clear()
    u = Fake(3, healthy=False)
    d = Fake(4, status="stopped", enabled=False)
    mgr._services[3], mgr._services[4] = u, d
    del mgr._services[1], mgr._services[2]
    await passes(3)
    check("a running but unhealthy service goes down", [x[1]["id"] for x in events] == [3], str(events))
    check("a disabled stopped service is ignored", all(x[1]["id"] != 4 for x in events))
    d.enabled = True
    await passes(2)
    check("enabling it starts the count from zero", all(x[1]["id"] != 4 for x in events))
    await passes(1)
    check("then it goes down after three checks", any(x[1]["id"] == 4 for x in events))
    u.enabled = False
    await passes(1)
    check("disabling a down service forgets its state", 3 not in mgr._health_state)
    mgr._services.pop(4)

    # a service stopped on purpose through the portal is not failing
    events.clear()
    p = Fake(8)
    mgr._services[8] = p
    await passes(2)
    ok, _ = await mgr.stop_service(8)
    check("stop_service stops the fake", ok and p.status == "stopped")
    await passes(10)
    check("a service stopped through the portal sends no down alert", [x for x in events if x[1]["id"] == 8] == [], str(events))
    check("and keeps no failure count", 8 not in mgr._health_state)
    p.start_ok = False
    await mgr.start_service(8)
    await passes(2)
    check("a failed start after that counts from zero", [x for x in events if x[1]["id"] == 8] == [])
    await passes(1)
    check("and the third failed check alerts", [x[1]["state"] for x in events if x[1]["id"] == 8] == ["down"], str(events))
    p.start_ok = True
    await mgr.start_service(8)
    await passes(2)
    check("a good start recovers", [x[1]["state"] for x in events if x[1]["id"] == 8] == ["down", "up"], str(events))
    events.clear()
    await mgr.stop_service(8)
    await passes(1)
    await mgr.start_service(8)
    p.status = "stopped"
    await passes(3)
    check("stopped on purpose, started, then dying alerts again",
          [x[1]["state"] for x in events if x[1]["id"] == 8] == ["down"], str(events))
    mgr._services.pop(8)

    # a restart of the portal: enabled and already stopped at the first check is the baseline
    events.clear()
    m3 = svc.ServiceManager(FakeDb(), on_event=lambda e, d: events.append((e, d)))
    q = Fake(9, status="stopped")
    r = Fake(10)
    m3._services[9], m3._services[10] = q, r
    for _ in range(8):
        await m3._check_services_once()
    check("a service already stopped at the first check sends nothing", events == [], str(events))
    r.status = "stopped"
    for _ in range(3):
        await m3._check_services_once()
    check("a service seen running that then stops alerts", [x[1]["id"] for x in events] == [10], str(events))
    q.status = "running"
    await m3._check_services_once()
    q.status = "stopped"
    for _ in range(3):
        await m3._check_services_once()
    check("the baseline service alerts once it was seen running and then stops",
          sorted(x[1]["id"] for x in events) == [9, 10], str(events))
    events.clear()
    n = Fake(11, status="stopped")
    m3._services[11] = n
    for _ in range(3):
        await m3._check_services_once()
    check("a service added after startup that is stopped does count", [x[1]["id"] for x in events] == [11], str(events))
    events.clear()
    m4 = svc.ServiceManager(FakeDb(), on_event=lambda e, d: events.append((e, d)))
    z = Fake(12, status="stopped")
    m4._services[12] = z
    await m4._check_services_once()
    z.start_ok = False
    await m4.start_service(12)
    for _ in range(3):
        await m4._check_services_once()
    check("a start that fails on a baseline service alerts", [x[1]["id"] for x in events] == [12], str(events))

    # initialize() auto-starts every enabled service before the first health pass: one whose
    # start failed is an outage from that pass on, one that was never started (stage mode) is not
    from config import Config

    class InitDb(FakeDb):
        async def get_services_by_type(self, t):
            return [{"id": 20, "name": "ok", "plugin": "fake-init", "enabled": 1},
                    {"id": 21, "name": "bad", "plugin": "fake-init", "enabled": 1}]

    class InitFake(Fake):
        def __init__(self, data):
            super().__init__(data["id"], status="stopped", enabled=bool(data["enabled"]))
            self.start_ok = data["id"] != 21

    svc._service_types["fake-init"] = InitFake
    real_stage = Config.STAGE_MODE
    try:
        for stage in (False, True):
            events.clear()
            Config.STAGE_MODE = stage
            mi = svc.ServiceManager(InitDb(), on_event=lambda e, d: events.append((e, d)))
            await mi.initialize()
            mi._shutdown = True
            mi._health_task.cancel()
            await asyncio.gather(mi._health_task, return_exceptions=True)
            for _ in range(3):
                await mi._check_services_once()
            if stage:
                check("stage mode: services never started are baseline-quiet, no alert", events == [], str(events))
            else:
                check("an auto-start that failed alerts after the usual three checks, a good one does not",
                      [x[1]["id"] for x in events] == [21], str(events))
    finally:
        Config.STAGE_MODE = real_stage
        svc._service_types.pop("fake-init", None)

    # a broken hook is swallowed
    bad = svc.ServiceManager(FakeDb(), on_event=lambda e, d: 1 / 0)
    bad._services[5] = Fake(5, status="stopped")
    for _ in range(4):
        await bad._check_services_once()
    check("an on_event hook that raises does not stop the monitor", True)
    check("no hook: still fine", await svc.ServiceManager(FakeDb())._check_services_once() is None)

    # alerts mapping: down then up are both sent; a repeat inside the transition is not
    sent = []

    async def fire(ev, payload):
        sent.append((ev, payload))

    alerts.reset_state()
    alerts.bind(fire=fire)
    m2 = svc.ServiceManager(FakeDb(), on_event=alerts.service_event)
    t = Fake(6)
    m2._services[6] = t
    await m2._check_services_once()
    t.status = "stopped"
    for _ in range(3):
        await m2._check_services_once()
    t.status = "running"
    for _ in range(2):
        await m2._check_services_once()
    for _ in range(5):
        await asyncio.sleep(0)
    while alerts._tasks:
        await asyncio.gather(*list(alerts._tasks))
    check("through the alert helper: one down alert and one up alert",
          [p["summary"] for _, p in sent] == ["Service 'Svc 6' is down", "Service 'Svc 6' is back up"], str(sent))
    alerts.unbind()

    # game server crash versus requested stop
    class GS(GameServerService):
        def __init__(self):
            self.id, self.name, self.display_name, self.config = 7, "pal", "Pal", {"unit": "portal-gs-pal"}
            self._expected_stop = False
            self.status = "running"
            self._db = None
            self._main_pid = None
            self.emitted = []
            self._on_event = lambda e, d: self.emitted.append((e, d))

        async def _show(self):
            return self.info

    g = GS()
    g.info = {"active_state": "failed"}
    await g.sync_status()
    check("a running unit that ends 'failed' is a crash",
          [e for e, _ in g.emitted] == ["gameserver.crashed"], str(g.emitted))
    g2 = GS()
    g2._expected_stop = True
    g2.info = {"active_state": "failed"}
    await g2.sync_status()
    check("a failed end after a requested stop is not a crash", g2.emitted == [])
    g3 = GS()
    g3.info = {"active_state": "inactive"}
    await g3.sync_status()
    check("a clean stop is not a crash", g3.emitted == [])
    g4 = GS()
    g4.status = "stopped"
    g4.info = {"active_state": "failed"}
    await g4.sync_status()
    check("failed seen at the first look (was not running) is not a crash", g4.emitted == [])
    g5 = GS()
    g5._expected_stop = True
    g5.info = {"active_state": "active"}
    g5.status = "stopped"
    await g5.sync_status()
    check("running again clears the requested-stop flag", g5._expected_stop is False)

    # --- the generated unit restarts itself, so a crash is seen in the restart count
    gs_src = (Path(__file__).resolve().parent.parent / "gameservers.py").read_text()
    check("the unit the portal writes restarts after a failure (the premise of the restart-count rule)",
          "Restart=on-failure" in gs_src and "RestartSec=10" in gs_src)

    async def polls(g, sequence):
        for info in sequence:
            g.info = info
            await g.sync_status()

    def up(n, pid=100):
        return {"active_state": "active", "sub_state": "running", "main_pid": pid, "n_restarts": n}

    g = GS()
    await polls(g, [up(0), up(0), up(1, pid=200)])
    check("running, running, then running again with one more automatic restart is a crash",
          [e for e, _ in g.emitted] == ["gameserver.crashed"], str(g.emitted))
    check("the crash names the game server", g.emitted and g.emitted[0][1].get("unit") == "portal-gs-pal")
    await polls(g, [up(1, pid=200), up(1, pid=200)])
    check("polls with an unchanged count add nothing", len(g.emitted) == 1, str(g.emitted))
    await polls(g, [up(2, pid=300)])
    check("a second crash is seen too (the alert helper's cooldown spaces them)", len(g.emitted) == 2)

    g = GS()
    await polls(g, [up(0), {"active_state": "activating", "sub_state": "start", "main_pid": 0, "n_restarts": 1}])
    check("a poll inside the restart (activating, mapped to stopped) with a higher count is a crash",
          [e for e, _ in g.emitted] == ["gameserver.crashed"], str(g.emitted))

    g = GS()
    await polls(g, [up(5), up(5)])
    check("the first poll only sets the baseline: old restarts are not news", g.emitted == [])

    g = GS()
    await polls(g, [up(3), up(0), up(0)])
    check("a count that fell (the unit was started by hand) is not a crash", g.emitted == [])
    await polls(g, [up(1)])
    check("and the next restart after that is", len(g.emitted) == 1)

    g = GS()
    await polls(g, [up(0)])
    g._expected_stop = True
    await polls(g, [up(1)])
    check("a count that grew while a stop or restart asked for through the portal is pending is not a crash",
          g.emitted == [])

    g = GS()
    await polls(g, [{"active_state": "active", "main_pid": 1}, {"active_state": "active", "main_pid": 2}])
    check("systemd that does not report the count: a new main pid alone is not a crash", g.emitted == [])

    # both rules firing in one poll still send one alert, through the real helper
    delivered = []

    async def fire(ev, payload):
        delivered.append(ev)

    alerts.reset_state()
    alerts.bind(fire=fire)
    g = GS()
    g._on_event = alerts.service_event
    g._n_restarts = 1
    g.info = {"active_state": "failed", "n_restarts": 2}
    await g.sync_status()
    for _ in range(5):
        await asyncio.sleep(0)
    while alerts._tasks:
        await asyncio.gather(*list(alerts._tasks))
    check("the failed rule and the count rule in one poll send one alert in all",
          delivered.count("gameserver.crashed") == 1, str(delivered))
    alerts.unbind()

    # the property list reaches systemd and the count is read back
    import subprocess
    import system_monitor
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        out = "ActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=42\nNRestarts=3\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    real_run = system_monitor.subprocess.run
    system_monitor.subprocess.run = fake_run
    try:
        info = system_monitor.get_service_status("portal-gs-pal")
    finally:
        system_monitor.subprocess.run = real_run
    check("systemctl show is asked for NRestarts", any("NRestarts" in " ".join(c) for c in seen), str(seen))
    check("the restart count is returned as a number", info and info.get("n_restarts") == 3, str(info))

    def fake_run_old(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="ActiveState=active\nLoadState=loaded\nMainPID=1\n", stderr="")

    system_monitor.subprocess.run = fake_run_old
    try:
        info = system_monitor.get_service_status("portal-gs-pal")
    finally:
        system_monitor.subprocess.run = real_run
    check("a missing count is None, not 0", info and info.get("n_restarts") is None, str(info))


asyncio.run(main())
if failures:
    print(f"\ntest_service_health_alerts: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_service_health_alerts: all checks passed")
