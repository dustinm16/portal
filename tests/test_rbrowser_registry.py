"""Server-side browser: the registry (design 3, 6.4, 8.2, 13). Fake launcher, fake clock, fake counters, no unit started.

Run: venv/bin/python -B tests/test_rbrowser_registry.py

* create: 20 concurrent creates by one member start one unit; 5 members and 2 seats give 2 units and 3 busy answers; a failing launcher
  leaves no placeholder; other token -> elsewhere, takeover -> replaced; a session ended while it starts leaves no unit
* the seat stays taken while a unit may still run (UnitLeftRunning), retried on the tick
* tick: idle, detached, lifetime; the activity throttle; traffic budgets (rate and volume, both ways, 80 % flag); exit status 3, closed,
  crash; the ingress filter check with the session's own pin; the tmp quota; the sweeper's allow-list (helper, probe and test units are
  never stopped); sweep_tmp is given every ident that is live (placeholders, units being stopped, units left)
* revocation with a spared predicate; end is idempotent
* startup does nothing when disabled or unavailable; prepare_host's pin reaches the launcher; prune_stale keeps the pins in use; a failed
  prepare means unavailable and no start; prepare and unprepare never overlap; shutdown passes units_left
* preflight: cache hit runs no probe, key change runs one, create during a run gives 503, a failed check makes availability false
"""

import asyncio
import fnmatch
import json
import os
import re
import shutil
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rbrowser  # noqa: E402
import rbrowser_launch as RL  # noqa: E402
from rbrowser import FakeLauncher, LaunchError, Refused, Registry, UnitLeftRunning  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


async def nosleep(s=0):
    await asyncio.sleep(0)


class TLauncher(FakeLauncher):
    """FakeLauncher with the knobs the registry tests need."""

    def __init__(self, base, **kw):
        super().__init__(base, **kw)
        self.counters = {}
        self.status = {}          # unit -> ExecMainStatus
        self.extra = {}           # extra entries show() reports (units the registry must not touch)
        self.stop_calls = []
        self.fail_stop = set()
        self.fail_start = None
        self.start_gate = None
        self.start_calls = 0
        self.show_calls = []
        self.sweep_args = []
        self.filter_calls = []
        self.unstopped = set()
        self.gone = set()         # units reported inactive although the fake still serves them
        self.stop_gate = None     # an Event that every stop waits for (after it is recorded)
        self.stop_gates = {}      # unit -> Event: only that unit's stop waits
        self.filter_raise = False
        self.failed = {}          # unit -> ExecMainStatus: units that exited in error and stay loaded as `failed` (no --collect)
        self.failed_code = {}     # unit -> ExecMainCode (1 exited, 2 killed, 3 dumped); a unit not listed here exited (1)
        self.reset_calls = []
        self.reset_raises = False

    def exit_in_error(self, unit, status, code="1"):
        """The unit's supervisor ends with `status` and, as without --collect, the unit stays loaded as failed until reset.
        `code` is ExecMainCode: 1 exited (status is the exit code), 2 killed (status is the signal number), 3 dumped."""
        self.failed_code[unit] = str(code)
        srv = self.servers.pop(unit, None)
        self.specs.pop(unit, None)
        if srv is not None:
            asyncio.ensure_future(srv.stop())
        self.failed[unit] = str(status)

    def _check_unit(self, unit):
        """As SystemdLauncher._check_unit: a launcher refuses every name that is not of its own prefix (LaunchError)."""
        if not isinstance(unit, str) or not re.fullmatch(re.escape(self.unit_prefix) + r"[0-9a-f]{12}\.service", unit):
            raise LaunchError("not a unit name of this launcher")

    async def reset_failed(self, unit):
        self._check_unit(unit)
        self.reset_calls.append(unit)
        if self.reset_raises:
            raise RuntimeError("reset-failed failed")
        self.failed.pop(unit, None)

    async def start(self, spec):
        self.start_calls += 1
        if self.start_gate is not None:
            await self.start_gate.wait()
        if self.fail_start == "left":
            raise UnitLeftRunning(f"{self.unit_prefix}{spec.ident}.service")
        if self.fail_start is not None:
            raise self.fail_start
        return await super().start(spec)

    async def stop(self, unit):
        self._check_unit(unit)
        self.stop_calls.append(unit)
        if self.stop_gate is not None:
            await self.stop_gate.wait()
        if unit in self.stop_gates:
            await self.stop_gates[unit].wait()
        if unit in self.fail_stop:
            self.unstopped.add(unit)
            raise UnitLeftRunning(unit)
        self.unstopped.discard(unit)
        await super().stop(unit)

    async def show(self, units):
        for u in units:
            if u != f"{self.unit_prefix}*.service":
                self._check_unit(u)
        self.show_calls.append(list(units))
        out = await super().show(units)
        for u, d in out.items():
            ci, co = self.counters.get(u, (0, 0))
            d["IPIngressBytes"], d["IPEgressBytes"] = str(ci), str(co)
            if u in self.status:
                d["ExecMainStatus"] = self.status[u]
                d["ExecMainCode"] = "1"
            if u in self.gone:
                d["ActiveState"] = "inactive"
        for u, st in self.failed.items():
            if any(fnmatch.fnmatchcase(u, x) if "*" in x else x == u for x in units):
                out[u] = {"Id": u, "ActiveState": "failed", "ExecMainStatus": st, "ExecMainCode": self.failed_code.get(u, "1"),
                          "MainPID": "0", "ControlGroup": "",
                          "IPIngressBytes": "0", "IPEgressBytes": "0"}
        for u, d in self.extra.items():
            out[u] = dict(d, Id=u)
        return out

    def filter_attached(self, cgroup, pin=None):
        self.filter_calls.append((cgroup, pin))
        if self.filter_raise:
            raise RuntimeError("filter query failed")
        return super().filter_attached(cgroup, pin)

    def sweep_tmp(self, live):
        self.sweep_args.append(set(live))
        return []


class FakeL:
    """rbrowser_launch with the host-touching functions replaced; everything else is the real module."""

    def __init__(self, ok=True, pin="/sys/fs/bpf/portal-rb-ingress-0123456789abcdef", slice_ok=True, available=True):
        self.ok, self.pin, self.slice_ok, self.available = ok, pin, slice_ok, available
        self.prepare_calls = []
        self.unprepare_calls = []
        self.active = 0
        self.max_active = 0
        self.delay = 0.0
        self.on_unprepare = None
        self.fail_pin = ""       # the pin a failed prepare_host has already loaded (it fails after the filter, like a tmpfs that cannot be mounted)

    def __getattr__(self, name):
        return getattr(RL, name)

    def availability(self, stage_mode=False, **kw):
        return {"available": self.available, "missing": [], "reasons": [] if self.available else ["xvfb missing"], "chromium_version": "156",
                "chromium_age_days": 3, "kernel_upload_limit": True, "paths": {"chromium": "/usr/bin/chromium"}}

    async def prepare_host(self, cfg, **kw):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.prepare_calls.append(kw)
        await asyncio.sleep(self.delay)
        self.active -= 1
        if not self.ok:
            return {"ok": False, "reasons": ["ingress filter: not loadable"], "ingress_pin": self.fail_pin, "slice_ok": False, "upload_rule": False}
        return {"ok": True, "reasons": [], "ingress_pin": self.pin, "slice_ok": self.slice_ok, "upload_rule": True, "upload_reason": ""}

    async def unprepare_host(self, **kw):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.unprepare_calls.append(kw)
        if self.on_unprepare is not None:
            self.on_unprepare()
        await asyncio.sleep(self.delay)
        self.active -= 1
        return {}


class FakeBpf:
    PIN_BASE = "/sys/fs/bpf/portal-rb-ingress"

    def __init__(self):
        self.pruned = []

    def prune_stale(self, base, keep=()):
        self.pruned.append((base, sorted(keep)))
        return []


FACTS = {"resolvers": ["10.0.0.2"], "ifaces": [], "gateways": ["10.0.0.1"], "gateways_scoped": ["10.0.0.1"]}
CFG = {"rbrowser_enabled": True, "rbrowser_max_sessions": 2, "rbrowser_idle_minutes": 15, "rbrowser_memory_mb": 2048,
       "rbrowser_cpu_percent": 150, "rbrowser_clipboard": "both", "rbrowser_upload_kbps": 4000, "portal_port": 443}


def fake_launcher_kw(calls=None):
    """launcher_kw for a Registry: the SystemdLauncher it builds itself (the probe launcher, the start-up sweep) gets a fake run and which, so
    no test reaches the host's systemctl. Every call is appended to `calls` when it is given."""
    log = calls if calls is not None else []

    async def run(argv, timeout):
        log.append(list(argv))
        return types.SimpleNamespace(rc=0, out="", err="")

    return dict(run=run, which=lambda n: "/usr/bin/" + n, read_text=lambda p: "")


class Rig:
    def __init__(self, tmp, **over):
        self.tmp = tmp
        self.clock = Clock()
        self.launcher = TLauncher(os.path.join(tmp, "run"))
        self.L = FakeL()
        self.bpf = FakeBpf()
        self.scan_listeners = False
        self.scan_error = None
        self.procs = "1234\n"      # what the unit's cgroup.procs holds; an Exception instance is raised instead
        self.probe_runs = 0
        self.probe_result = {"ok": True, "checks": [{"name": "egress", "ok": True, "detail": "ok"}]}
        self.probe_gate = None
        self.versions = {"chromium": "156", "systemd": 252}

        async def probe_runner(spec):
            self.probe_runs += 1
            if self.probe_gate is not None:
                await self.probe_gate.wait()
            return self.probe_result

        self.host_calls = []         # every systemctl-style call a real SystemdLauncher built by the registry would have made
        kw = dict(launcher=self.launcher, launch_mod=self.L, launcher_kw=fake_launcher_kw(self.host_calls), bpf=self.bpf, clock=self.clock, sleep=nosleep, host_facts=lambda: FACTS,
                  ncpu=4, mem_total=15 * 1024 ** 3, cgroup_root=os.path.join(tmp, "cg"), tmp_dir=os.path.join(tmp, "tmp"),
                  cache_path=os.path.join(tmp, "pf.json"), probe_runner=probe_runner, versions=lambda: dict(self.versions),
                  listener_scan=self._scan, read_file=self.read_file)
        kw.update(over)
        os.makedirs(os.path.join(tmp, "tmp"), exist_ok=True)
        self.reg = Registry(**kw)
        self.reg.ready = True
        self.reg._preflight = {"ok": True, "checks": []}
        self.reg.pin = "/sys/fs/bpf/portal-rb-ingress-0123456789abcdef"
        self.reg._pf_key = self.reg.preflight_key(CFG)      # the result above was made with these settings (the full key is compared on every tick)

    def _scan(self, pids):
        if self.scan_error is not None:
            raise self.scan_error
        return self.scan_listeners

    def read_file(self, path):
        if path.endswith("/cgroup.procs"):
            if isinstance(self.procs, Exception):
                raise self.procs
            return self.procs
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    async def make(self, user=1, token="t1", cfg=None, **kw):
        return await self.reg.create(user, token, kw.get("w", 1280), kw.get("h", 720), cfg or CFG, kw.get("takeover", False), theme=kw.get("theme"))


async def case(fn):
    tmp = tempfile.mkdtemp(prefix="rbtest-reg-")
    rig = Rig(tmp)
    try:
        await fn(rig)
    finally:
        for s in list(rig.launcher.servers):
            try:
                await rig.launcher.stop(s)
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- create

async def t_concurrent_same_member(r):
    res = await asyncio.gather(*[r.make(user=7, token="a") for _ in range(20)], return_exceptions=True)
    sessions = [x for x in res if isinstance(x, rbrowser.Session)]
    check("20 concurrent creates by one member: one unit", len(r.launcher.servers) == 1 and r.launcher.start_calls == 1,
          f"{len(r.launcher.servers)} units, {r.launcher.start_calls} starts")
    check("20 concurrent creates: every caller got the same running session",
          len(sessions) == 20 and len({id(s) for s in sessions}) == 1 and sessions[0].state == "running", str([type(x) for x in res][:3]))
    s = sessions[0]
    check("session fields: unit name, ident, started in epoch seconds, clipboard value, pin",
          s.unit == f"portal-rb-{s.ident}.service" and len(s.ident) == 12 and s.started == r.clock() and s.clipboard == "both" and s.ingress_pin.startswith("/sys/fs/bpf/portal-rb"))
    check("get, for_user and all find it", rbrowser.Registry.get(r.reg, s.sid) is s and r.reg.for_user(7) is s and r.reg.all() == [s])
    again = await r.make(user=7, token="a")
    check("a later create with the same token returns the same session", again is s and r.launcher.start_calls == 1)


async def t_five_members_two_seats(r):
    res = await asyncio.gather(*[r.make(user=i, token=f"t{i}") for i in range(5)], return_exceptions=True)
    ok = [x for x in res if isinstance(x, rbrowser.Session)]
    busy = [x for x in res if isinstance(x, Refused) and x.status == 409 and x.body.get("busy") is True]
    check("5 members, 2 seats: exactly 2 units and 3 busy answers", len(ok) == 2 and len(busy) == 3 and len(r.launcher.servers) == 2,
          f"{len(ok)} ok, {len(busy)} busy")
    b = busy[0].body
    check("busy body: free_in_minutes is a multiple of 5 and nothing else", set(b) == {"busy", "free_in_minutes"} and b["free_in_minutes"] % 5 == 0 and b["free_in_minutes"] >= 5, str(b))
    # seat accounting includes placeholders: a slow start still counts
    r.launcher.start_gate = asyncio.Event()
    for s in list(r.reg.all()):
        await r.reg.end(s, "closed")
    t1 = asyncio.ensure_future(r.make(user=11, token="x"))
    t2 = asyncio.ensure_future(r.make(user=12, token="x"))
    await asyncio.sleep(0.05)
    t3 = asyncio.ensure_future(r.make(user=13, token="x"))
    await asyncio.sleep(0.05)
    check("starting placeholders count against the seats", t3.done() and isinstance(t3.exception(), Refused) and t3.exception().body.get("busy"))
    r.launcher.start_gate.set()
    await asyncio.gather(t1, t2)


async def t_failing_launcher(r):
    r.launcher.fail_start = LaunchError("boom")
    try:
        await r.make(user=3)
        got = None
    except Refused as e:
        got = e
    check("a failing launcher answers 503 without retry_after", got is not None and got.status == 503 and "retry_after" not in got.body)
    check("a failing launcher leaves no placeholder", r.reg.all() == [] and r.reg.for_user(3) is None and r.reg._seats_taken() == 0 and not r.reg._x)
    check("the unit is stopped after a failed start", any(u.startswith("portal-rb-") for u in r.launcher.stop_calls))
    r.launcher.fail_start = None
    s = await r.make(user=3)
    check("a later create works", s.state == "running")
    c = r.reg.counters()
    check("counters: started 1, start_failed 1, ended[start_failed] 1", c["started"] == 1 and c["start_failed"] == 1 and c["ended"].get("start_failed") == 1, str(c))
    check("counters: theme_fallbacks is 0 for a launcher without the count and follows the launcher's own count", c["theme_fallbacks"] == 0
          and (setattr(r.launcher, "theme_fallbacks", 3) or r.reg.counters()["theme_fallbacks"] == 3))


async def t_failed_start_unit_left(r):
    r.launcher.fail_start = "left"
    try:
        await r.make(user=3)
    except Refused:
        pass
    check("a start that left a unit keeps the unit on the left list and the seat taken", len(r.reg.left_units()) == 1 and r.reg._seats_taken() == 1 and r.reg.all() == [])


async def t_elsewhere_and_takeover(r):
    a = await r.make(user=5, token="old")
    try:
        await r.make(user=5, token="new")
        got = None
    except Refused as e:
        got = e
    check("another sign-in gets 409 elsewhere", got is not None and got.status == 409 and got.body == {"elsewhere": True})
    b = await r.make(user=5, token="new", takeover=True)
    check("takeover ends the old session with reason replaced and starts a new one", a.state == "ended" and a.end_reason == "replaced" and b.state == "running" and b is not a)
    check("the old unit is gone", a.unit not in r.launcher.servers and b.unit in r.launcher.servers and r.reg.for_user(5) is b)
    # takeover with one seat left over: the old unit's seat is released before the new one is counted
    c = await r.make(user=6, token="z")
    check("takeover did not use a second seat", len(r.reg.all()) == 2 and c.state == "running")


async def t_end_while_starting(r):
    r.launcher.start_gate = asyncio.Event()
    t = asyncio.ensure_future(r.make(user=9))
    await asyncio.sleep(0.05)
    s = r.reg.for_user(9)
    check("placeholder is visible while starting", s is not None and s.state == "starting")
    e = asyncio.ensure_future(r.reg.end(s, "admin_end"))
    await asyncio.sleep(0.05)
    check("a session ended while it starts keeps its seat until the unit is confirmed gone", r.reg._seats_taken() == 1)
    r.launcher.start_gate.set()
    got = None
    try:
        await t
    except Refused as ex:
        got = ex
    await e
    check("create answers 503 and the unit that came up is stopped", got is not None and got.status == 503 and not r.launcher.servers and s.end_reason == "admin_end", str(got))
    check("nothing left behind", r.reg._seats_taken() == 0 and r.reg.all() == [] and not r.reg._x)


# ---------------------------------------------------------------- end, revocation, activity

async def t_end_idempotent(r):
    s = await r.make(user=1)
    await asyncio.gather(r.reg.end(s, "closed"), r.reg.end(s, "closed"), r.reg.end(s, "idle"))
    check("end is idempotent: one stop, the first reason wins", r.launcher.stop_calls.count(s.unit) == 1 and s.end_reason == "closed" and s.state == "ended")
    await r.reg.end(s, "closed")
    check("a third end later is harmless", r.launcher.stop_calls.count(s.unit) == 1)
    check("unknown reason becomes crash", (await _ended_with(r, "no-such-reason")) == "crash")


async def _ended_with(r, reason):
    s = await r.make(user=2, token="q")
    await r.reg.end(s, reason)
    return s.end_reason


async def t_revocation(r):
    a = await r.make(user=1, token="keep")
    b = await r.make(user=2, token="drop")
    await r.reg.on_revocation(1, lambda tok: tok == "keep")
    await r.reg.on_revocation(2, lambda tok: tok == "keep")
    check("revocation: the spared session lives, the other ends at once as signed_out", a.state == "running" and b.state == "ended" and b.end_reason == "signed_out")
    await r.reg.on_revocation(1, lambda tok: False)
    check("a predicate that says no ends it", a.end_reason == "signed_out")
    await r.reg.on_revocation(99, lambda tok: False)
    check("unknown user is harmless", True)


async def t_activity_here_throttle(r):
    s = await r.make(user=1)
    r.clock.advance(100)
    check("here is accepted", rbrowser.Registry.note_activity(r.reg, s, here=True) is True and s.last_activity == r.clock())
    r.clock.advance(5)
    check("a second here within 10 s is ignored", r.reg.note_activity(s, here=True) is False and s.last_activity == r.clock() - 5)
    r.clock.advance(6)
    check("here after 10 s counts again", r.reg.note_activity(s, here=True) is True)
    r.clock.advance(1)
    check("key and pointer activity always counts", r.reg.note_activity(s) is True and s.last_activity == r.clock())
    d = r.reg.deadlines(s, CFG)
    check("deadlines are epoch seconds", d["idle_deadline"] == s.last_activity + 15 * 60 and d["max_deadline"] == s.started + 240 * 60)
    check("activity_state: active, then idle after 2 minutes", r.reg.activity_state(s) == "active" and (r.clock.advance(121) or r.reg.activity_state(s)) == "idle")


# ---------------------------------------------------------------- tick

async def tick(r, advance=0):
    r.clock.advance(advance)
    res = await r.reg.tick(CFG)
    await asyncio.sleep(0.05)       # stops that the tick spawned (unknown units, units left) run now
    return res


async def t_idle_detach_lifetime(r):
    s = await r.make(user=1)
    r.reg.mark_attached(s, object())
    res = await tick(r, 15 * 60 - 1)
    check("not idle just before the limit", res == [] and s.state == "running")
    res = await tick(r, 2)
    check("idle: ended with reason idle", res == [(s, "idle")] and s.end_reason == "idle" and s.marker is None)
    # detached
    s = await r.make(user=1, token="b")
    v = object()
    r.reg.mark_attached(s, v)
    r.reg.mark_detached(s, object())      # a stale viewer's late close changes nothing
    check("mark_detached ignores a replaced viewer", s.viewer is v and s.detached_since is None)
    r.reg.mark_detached(s, v)
    r.reg.note_activity(s)
    res = await tick(r, 299)
    check("detached for 299 s: still there", res == [] and s.state == "running")
    res = await tick(r, 2)
    check("detached for 300 s: ended with reason detached", res == [(s, "detached")])
    # a session that was never attached starts counting at its start
    s = await r.make(user=1, token="c")
    res = await tick(r, 301)
    check("never attached: detached after 300 s", res == [(s, "detached")])
    # lifetime
    s = await r.make(user=1, token="d")
    r.reg.mark_attached(s, object())
    for _ in range(40):
        r.reg.note_activity(s)
        await tick(r, 479)
        if s.state == "ended":
            break
    check("lifetime: ended with reason max_lifetime after 240 minutes", s.end_reason == "max_lifetime" and s.started + 240 * 60 <= r.clock(), s.end_reason)


async def t_one_show_per_tick(r):
    await r.make(user=1)
    await r.make(user=2, token="z")
    r.launcher.show_calls.clear()
    await tick(r, 1)
    check("one launcher.show call per tick, with the glob of the prefix", r.launcher.show_calls == [["portal-rb-*.service"]], str(r.launcher.show_calls))


async def t_exit_status(r):
    a = await r.make(user=1)
    r.launcher.status[a.unit] = "3"
    r.launcher.gone.add(a.unit)
    res = await tick(r, 1)
    check("exit status 3: crash with marker display_mismatch", res == [(a, "crash")] and a.marker == "display_mismatch")
    b = await r.make(user=2, token="b")
    r.launcher.gone.add(b.unit)
    res = await tick(r, 1)
    check("inactive with status 0: closed_in_browser", res == [(b, "closed_in_browser")] and b.marker is None)
    c = await r.make(user=3, token="c")
    r.launcher.gone.add(c.unit)
    r.launcher.status[c.unit] = "4"
    res = await tick(r, 1)
    check("inactive with another status: crash without marker", res == [(c, "crash")] and c.marker is None)
    d = await r.make(user=4, token="d")
    srv = r.launcher.servers.pop(d.unit)      # the unit vanished (collected): asked by name, shown inactive
    await tick(r, 1)
    check("a unit that vanished ends its session", d.state == "ended")
    r.launcher.servers[d.unit] = srv


async def t_marker_events(r):
    s = await r.make(user=1)
    r.launcher.filter_ok = False
    await tick(r, 1)
    r.launcher.filter_ok = True
    ev = [e for e in r.reg.take_events() if e["kind"] == "marker"]
    check("a marker ending queues one event with event name, detail, user and sid prefix and nothing else of the session",
          len(ev) == 1 and ev[0] == {"kind": "marker", "marker": "ingress_filter_lost", "detail": "ingress_filter_lost", "event": "rbrowser_listener_found",
                                     "user_id": 1, "sid_prefix": s.sid[:6]}, str(ev))
    check("take_events drains", r.reg.take_events() == [])
    s2 = await r.make(user=2, token="b")
    r.launcher.counters[s2.unit] = (0, 600 * 1024 * 1024)
    await tick(r, 1)
    ev = [e for e in r.reg.take_events() if e["kind"] == "marker"]
    check("a traffic ending carries the budget as its detail", len(ev) == 1 and ev[0]["event"] == "rbrowser_traffic_limit" and ev[0]["detail"] == "upload_volume", str(ev))
    s3 = await r.make(user=3, token="c")
    await r.reg.end(s3, "closed")
    check("an ending without a marker queues no marker event", [e for e in r.reg.take_events() if e["kind"] == "marker"] == [])


async def t_ingress_filter(r):
    s = await r.make(user=1)
    await tick(r, 1)
    check("filter_attached is called with the unit's cgroup and the session's own pin", r.launcher.filter_calls[-1] == (s.expect_cgroup, s.ingress_pin) and s.ingress_pin)
    r.reg.pin = "/sys/fs/bpf/portal-rb-ingress-ffffffffffffffff"      # a later prepare names a newer program
    await tick(r, 1)
    check("a re-prepare does not change the pin that is checked", r.launcher.filter_calls[-1][1] == s.ingress_pin and s.ingress_pin.endswith("0123456789abcdef"))
    r.launcher.filter_ok = False
    res = await tick(r, 1)
    check("a detached filter ends the session as crash with marker ingress_filter_lost", res == [(s, "crash")] and s.marker == "ingress_filter_lost")
    r.launcher.filter_ok = True


async def t_traffic(r):
    kbps = 4000
    s = await r.make(user=1)
    r.reg.mark_attached(s, object())
    u = s.unit
    # upload: 2 * 4000 kbps = 1,000,000 bytes/s over 30 s
    r.launcher.counters[u] = (0, 0)
    await tick(r, 0)
    ok_bytes = 0
    for i in range(7):
        r.reg.note_activity(s)
        ok_bytes += 5 * 900_000
        r.launcher.counters[u] = (0, ok_bytes)
        res = await tick(r, 5)
    check("upload just under twice the setting for 30 s: no end", s.state == "running" and res == [])
    t = 0
    while s.state == "running" and t < 12:
        r.reg.note_activity(s)
        ok_bytes += 5 * 1_300_000
        r.launcher.counters[u] = (0, ok_bytes)
        res = await tick(r, 5)
        t += 1
    check("upload above twice the setting averaged over 30 s: traffic_limit, upload_rate",
          s.end_reason == "traffic_limit" and s.marker == "traffic_limit" and s.marker_detail == "upload_rate", f"{s.end_reason} {s.marker} {s.marker_detail}")
    # upload volume
    s = await r.make(user=1, token="b")
    r.launcher.counters[s.unit] = (0, 512 * 1024 * 1024 + 1)
    res = await tick(r, 1)
    check("upload volume above 512 MB: upload_volume", res == [(s, "traffic_limit")] and s.marker_detail == "upload_volume")
    # download rate: 40 Mbit/s = 5,000,000 B/s averaged over 60 s
    s = await r.make(user=1, token="c")
    base = 0
    r.launcher.counters[s.unit] = (0, 0)
    await tick(r, 0)
    for i in range(12):
        r.reg.note_activity(s)
        base += 5 * 4_000_000
        r.launcher.counters[s.unit] = (base, 0)
        res = await tick(r, 5)
    check("download at 32 Mbit/s for 60 s: no end", s.state == "running")
    while s.state == "running" and base < 5_000_000_000:
        r.reg.note_activity(s)
        base += 5 * 6_000_000
        r.launcher.counters[s.unit] = (base, 0)
        res = await tick(r, 5)
    check("download above 40 Mbit/s averaged over 60 s: download_rate", s.marker_detail == "download_rate" and s.end_reason == "traffic_limit", s.marker_detail)
    # download volume and warning flag
    s = await r.make(user=1, token="d")
    r.launcher.counters[s.unit] = (int(8 * 1024 ** 3 * 0.79), 0)
    await tick(r, 1)
    check("no warning below 80 % of the download volume", s.net_warning is False and s.state == "running")
    r.launcher.counters[s.unit] = (int(8 * 1024 ** 3 * 0.81), 0)
    await tick(r, 1)
    check("warning flag at 80 % of the volume", s.net_warning is True and s.state == "running")
    r.launcher.counters[s.unit] = (8 * 1024 ** 3 + 1, 0)
    res = await tick(r, 1)
    check("download volume above 8 GB: download_volume", res == [(s, "traffic_limit")] and s.marker_detail == "download_volume")
    check("the byte counters are on the session", s.net_in == 8 * 1024 ** 3 + 1)
    # setting 0 still has a bound
    check("upload_kbps: 0 means the default, below 500 means 500", rbrowser.upload_kbps({"rbrowser_upload_kbps": 0}) == 4000 and rbrowser.upload_kbps({"rbrowser_upload_kbps": 100}) == 500)
    u = await r.reg.usage(s)
    check("usage returns the four keys", set(u) == {"memory_mb", "cpu_seconds", "net_in", "net_out"} and u["net_in"] == s.net_in)


async def t_tmp_quota_and_sweep(r):
    s = await r.make(user=1)
    d = os.path.join(r.tmp, "tmp", s.ident)
    os.makedirs(d)
    for i in range(100):
        open(os.path.join(d, f"f{i}"), "w").close()
    res = await tick(r, 1)
    check("a small tmp directory is fine", res == [])
    for i in range(100, 1501):
        open(os.path.join(d, f"f{i}"), "w").close()
    res = await tick(r, 1)
    check("more than 1500 entries: crash with marker tmp_quota", res == [(s, "crash")] and s.marker == "tmp_quota")
    s2 = await r.make(user=2, token="b")
    d2 = os.path.join(r.tmp, "tmp", s2.ident)
    os.makedirs(d2)
    with open(os.path.join(d2, "big"), "wb") as f:
        f.truncate(12 * 1024 * 1024 + 1)
    res = await tick(r, 1)
    check("more than 12 MiB: tmp_quota", res == [(s2, "crash")] and s2.marker == "tmp_quota")
    s3 = await r.make(user=3, token="c")
    d3 = os.path.join(r.tmp, "tmp", s3.ident)
    os.makedirs(d3)
    with open(os.path.join(d3, "fine"), "wb") as f:
        f.truncate(11 * 1024 * 1024)
    os.symlink("/", os.path.join(d3, "link"))
    res = await tick(r, 1)
    check("11 MiB and a symlink (not followed): fine", res == [] and s3.state == "running")
    live_last = r.launcher.sweep_args[-1]
    check("sweep_tmp is given the running session's ident", s3.ident in live_last)


async def t_sweep_tmp_live_set(r):
    r.launcher.start_gate = asyncio.Event()
    t = asyncio.ensure_future(r.make(user=1))
    await asyncio.sleep(0.05)
    ph = r.reg.for_user(1)
    await tick(r, 1)
    check("a unit that is still starting keeps its tmp directory (ident is live)", ph.ident in r.launcher.sweep_args[-1])
    r.launcher.start_gate.set()
    s = await t
    r.launcher.fail_stop.add(s.unit)
    await r.reg.end(s, "closed")
    await tick(r, 1)
    check("a unit that could not be stopped keeps its tmp directory", s.ident in r.launcher.sweep_args[-1])
    r.launcher.fail_stop.clear()
    await tick(r, 1)           # the retry runs beside the tick
    await tick(r, 1)
    check("after the stop is confirmed the ident is no longer live", s.ident not in r.launcher.sweep_args[-1])
    # the running probe unit shares the tmp area
    r.reg._probe_units["portal-rbprobe-bbbbbbbbbbbb.service"] = "bbbbbbbbbbbb"
    await tick(r, 1)
    check("the probe unit's ident is live", "bbbbbbbbbbbb" in r.launcher.sweep_args[-1])


async def t_sweeper_allow_list(r):
    s = await r.make(user=1)
    # an unknown session-pattern unit that runs
    unk = types.SimpleNamespace()
    await FakeLauncher.start(r.launcher, rbrowser.LaunchSpec(ident="aaaaaaaaaaaa", width=1, height=1, clipboard="off", home_url="", chromium="", memory_mb=1, cpu_percent=1))
    for name in ("portal-rbprobe-cccccccccccc.service", "portal-rbtest-dddddddddddd.service", "portal-rbhost-eeeeeeeeeeee.service",
                 "portal-rbtest-host-ffffffffffff.service", "portal-rb-notahexvalue.service", "portal-rbhost-abc.service", "portal-rb-0123456789abcdef.service"):
        r.launcher.extra[name] = {"ActiveState": "active", "MainPID": "1", "ExecMainStatus": "0"}
    r.launcher.stop_calls.clear()
    await tick(r, 1)
    check("an unknown session-pattern unit is stopped", r.launcher.stop_calls == ["portal-rb-aaaaaaaaaaaa.service"], str(r.launcher.stop_calls))
    check("probe, test, helper and malformed names are never stopped", not any(u in r.launcher.stop_calls for u in r.launcher.extra))
    check("the known session was left alone", s.state == "running")
    ev = r.reg.take_events()
    check("an event is queued for the stopped unit (no name in it)", [e["kind"] for e in ev] == ["unknown_unit_stopped"] and "unit" not in ev[0])
    # the same with the test prefix: portal-rbtest-<12hex> is a session unit of that registry, the helper and probe names are not
    r2 = Registry(launcher_kw=fake_launcher_kw(), prefix="portal-rbtest-", launcher=r.launcher, launch_mod=r.L, clock=r.clock, sleep=nosleep, ncpu=4, mem_total=15 * 1024 ** 3,
                  tmp_dir=os.path.join(r.tmp, "tmp"))
    r.launcher.stop_calls.clear()
    r.launcher.extra = {"portal-rbtest-host-ffffffffffff.service": {"ActiveState": "active", "MainPID": "1"},
                        "portal-rbprobe-cccccccccccc.service": {"ActiveState": "active", "MainPID": "1"},
                        "portal-rbhost-eeeeeeeeeeee.service": {"ActiveState": "active", "MainPID": "1"}}
    r2.launcher_given = True
    await r2._sweep_unknown(dict(r.launcher.extra))      # (a portal-rb- launcher refuses a portal-rbtest- pattern, so the listing is built here)
    check("with the test prefix the helper units portal-rbtest-host-* are not session units", r.launcher.stop_calls == [], str(r.launcher.stop_calls))


async def t_unit_left_running(r):
    a = await r.make(user=1)
    b = await r.make(user=2, token="b")
    r.launcher.fail_stop.add(a.unit)
    await r.reg.end(a, "closed")
    check("a stop that cannot be confirmed: the session is ended, the unit is on the left list", a.state == "ended" and r.reg.left_units() == [a.unit])
    try:
        await r.make(user=3, token="c")
        got = None
    except Refused as e:
        got = e
    check("the seat stays occupied while the old unit may run", got is not None and got.body.get("busy") is True)
    ev = r.reg.take_events()
    check("an event reports the unit left running", any(e["kind"] == "unit_left_running" and e.get("unit") == a.unit for e in ev))
    await tick(r, 1)
    check("the tick retries it and it stays reported", r.launcher.stop_calls.count(a.unit) >= 2 and r.reg.left_units() == [a.unit] and r.reg.counters()["left"] == 1)
    r.launcher.fail_stop.clear()
    await tick(r, 1)
    check("once confirmed it leaves the list and the seat is free", r.reg.left_units() == [] and r.reg._seats_taken() == 1)
    c = await r.make(user=3, token="c")
    check("a create works again", c.state == "running")
    # the launcher's own unstopped set is adopted
    r.launcher.unstopped.add("portal-rb-123456789abc.service")
    r.launcher.fail_stop.add("portal-rb-123456789abc.service")
    await tick(r, 1)
    check("units in launcher.unstopped are retried and reported", r.reg.left_units() == ["portal-rb-123456789abc.service"])
    del b


async def t_listener(r):
    s = await r.make(user=1)
    cg = os.path.join(r.tmp, "cg") + s.expect_cgroup
    os.makedirs(cg)
    with open(os.path.join(cg, "cgroup.procs"), "w") as f:
        f.write("1234\n")
    r.scan_listeners = True
    for i in range(5):
        res = await tick(r, 1)
        if res:
            break
    check("the listener check runs only on every 6th tick", res == [] and s.state == "running")
    res = await tick(r, 1)
    check("a listener found by the tick: crash with marker listener_found", res == [(s, "crash")] and s.marker == "listener_found")
    # at create: refused, unit stopped, event with the marker and the member
    r.scan_listeners = True
    try:
        await r.make(user=2, token="b")
        got = None
    except Refused as e:
        got = e
    # the cgroup file of the new unit does not exist: no pids, so no finding at create for the fake's cgroup (same string): it does exist
    check("a listener found at create refuses the start and stops the unit", got is not None and got.status == 503 and not r.launcher.servers)
    ev = r.reg.take_events()
    check("the create-time finding is queued as an event with marker and user", any(e["kind"] == "marker" and e["marker"] == "listener_found" and e["user_id"] == 2 and e["event"] == "rbrowser_listener_found" for e in ev))


# ---------------------------------------------------------------- startup, prepare, shutdown

async def t_startup_nothing(r):
    reg = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3, launcher=r.launcher)
    await reg.startup({"rbrowser_enabled": False})
    check("startup with the feature off calls nothing", r.L.prepare_calls == [] and r.bpf.pruned == [] and r.launcher.show_calls == [] and not reg.ready)
    r.L.available = False
    await reg.startup({"rbrowser_enabled": True})
    check("startup when unavailable calls nothing (no show, no prepare)", r.L.prepare_calls == [] and r.launcher.show_calls == [] and not reg.ready and reg.unavailable_reasons)
    r.L.available = True


async def t_startup_prepare(r):
    # orphan from an earlier run, and a probe unit that must not be touched
    await FakeLauncher.start(r.launcher, rbrowser.LaunchSpec(ident="aaaaaaaaaaaa", width=1, height=1, clipboard="off", home_url="", chromium="", memory_mb=1, cpu_percent=1))
    r.launcher.extra["portal-rbprobe-cccccccccccc.service"] = {"ActiveState": "active", "MainPID": "1"}
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4,
                   mem_total=15 * 1024 ** 3, cache_path=os.path.join(r.tmp, "pf2.json"), probe_runner=_ok_probe, versions=lambda: {"v": 1},
                   tmp_dir=os.path.join(r.tmp, "tmp"), prepare_kw={"bpf_base": "/sys/fs/bpf/portal-rb-ingress"}, read_file=r.read_file,
                   listener_scan=lambda pids: False)
    await reg.startup(dict(CFG, rbrowser_enabled=True))
    check("startup swept the orphan, never the probe unit", "portal-rb-aaaaaaaaaaaa.service" in r.launcher.stop_calls and "portal-rbprobe-cccccccccccc.service" not in r.launcher.stop_calls)
    check("prepare_host ran once with the policy and the probe targets", len(r.L.prepare_calls) == 1 and "policy" in r.L.prepare_calls[0] and r.L.prepare_calls[0]["probe_targets_doc"])
    check("the pin from prepare_host reaches the launcher", r.launcher.ingress_pin == r.L.pin and reg.pin == r.L.pin and reg.ready)
    check("prune_stale ran after the successful prepare with the current pin in keep", r.bpf.pruned == [("/sys/fs/bpf/portal-rb-ingress", [r.L.pin])], str(r.bpf.pruned))
    await asyncio.wait_for(asyncio.shield(reg._pf_task), 5)
    check("a background preflight was scheduled", reg._preflight is not None and reg._preflight["ok"])
    s = await reg.create(1, "t", 1280, 720, CFG)
    check("a session can start after startup", s.state == "running" and s.ingress_pin == r.L.pin)
    # prune keeps the pins of running sessions (here: a session that names an older pin)
    s.ingress_pin = "/sys/fs/bpf/portal-rb-ingress-1111111111111111"
    r.bpf.pruned.clear()
    r.L.pin = "/sys/fs/bpf/portal-rb-ingress-2222222222222222"
    await reg.host_prepare(CFG)
    check("a re-prepare keeps the pin of the running unit and names the new one",
          r.bpf.pruned and r.bpf.pruned[-1][1] == sorted([s.ingress_pin, r.L.pin]) and r.launcher.ingress_pin == r.L.pin, str(r.bpf.pruned))
    await reg.shutdown()
    check("shutdown stops the unit and unprepares with units_left 0 and the pin", s.state == "ended" and s.end_reason == "portal_stop"
          and r.L.unprepare_calls and r.L.unprepare_calls[-1]["units_left"] == 0 and r.L.unprepare_calls[-1]["bpf_pin"] == r.L.pin, str(r.L.unprepare_calls))
    check("after shutdown no session can start", not reg.ready)


async def _ok_probe(spec):
    return {"ok": True, "checks": [{"name": "egress", "ok": True, "detail": "ok"}]}


async def t_failed_prepare(r):
    r.L.ok = False
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3)
    await reg.startup(CFG)
    av = reg.availability()
    check("a failed prepare_host: unavailable with its reason", not reg.ready and av["available"] is False and any("ingress filter" in x for x in av["reasons"]), str(av["reasons"]))
    check("no pruning after a failed prepare", r.bpf.pruned == [])
    try:
        await reg.create(1, "t", 1280, 720, CFG)
        got = None
    except Refused as e:
        got = e
    check("create refuses to start", got is not None and got.status == 503 and r.launcher.start_calls == 0)
    check("no preflight scheduled", reg._pf_task is None)
    r.L.ok = True


async def t_failed_prepare_cleanup(r):
    """A prepare that fails after the filter was pinned: no launcher exists (production makes it only after a good prepare), yet
    shutdown must still unprepare the host with that pin (pin, static tree and tmpfs areas would stay until reboot)."""
    pin = "/sys/fs/bpf/portal-rb-ingress-feedfacefeedface"
    r.L.ok, r.L.fail_pin = False, pin
    reg = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3)
    await reg.startup(CFG)
    check("setup: prepare failed with a pin, no launcher, nothing ready", not reg.ready and reg._launcher is None and reg.prep is not None and reg.pin == "")
    await reg.shutdown()
    check("shutdown after a failed prepare unprepares once, with the pin the prepare had loaded",
          len(r.L.unprepare_calls) == 1 and r.L.unprepare_calls[0]["bpf_pin"] == pin and r.L.unprepare_calls[0]["units_left"] == 0, str(r.L.unprepare_calls))
    check("and the host is marked unprepared", reg.prep is None and not reg.ready)
    await reg.shutdown()
    check("a second shutdown does not unprepare again", len(r.L.unprepare_calls) == 1)
    # a failure before any pin exists still undoes the mounts and the firewall, but names no pin
    r.L.unprepare_calls.clear()
    r.L.fail_pin = ""
    reg2 = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3)
    await reg2.startup(CFG)
    await reg2.shutdown()
    check("a prepare that failed before any pin: unprepare runs with bpf_pin ''", len(r.L.unprepare_calls) == 1 and r.L.unprepare_calls[0]["bpf_pin"] == "", str(r.L.unprepare_calls))
    r.L.ok, r.L.fail_pin = True, ""
    # a registry that never prepared anything (feature off) calls nothing
    r.L.unprepare_calls.clear()
    reg3 = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3)
    await reg3.shutdown()
    check("shutdown of a registry that prepared nothing does not unprepare", r.L.unprepare_calls == [])


async def t_prepare_serialised(r):
    r.L.delay = 0.02
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                   probe_runner=_ok_probe, cache_path=os.path.join(r.tmp, "pf3.json"), versions=lambda: {})
    await reg.host_prepare(CFG)
    await asyncio.gather(reg.host_prepare(CFG), reg.shutdown(), reg.host_prepare(CFG))
    check("prepare and unprepare never overlap", r.L.max_active == 1, str(r.L.max_active))


async def t_slice_penalty(r):
    r.L.slice_ok = False
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3)
    await reg.host_prepare(CFG)
    check("a slice that could not be set halves the seats", reg.seats(CFG)["max"] == 1)
    r.L.slice_ok = True


async def t_shutdown_left(r):
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                   probe_runner=_ok_probe, cache_path=os.path.join(r.tmp, "pf4.json"), versions=lambda: {}, read_file=r.read_file,
                   listener_scan=lambda pids: False)
    await reg.host_prepare(CFG)
    reg._preflight = {"ok": True, "checks": []}
    reg._pf_key = reg.preflight_key(CFG)
    s = await reg.create(1, "t", 1280, 720, CFG)
    r.launcher.fail_stop.add(s.unit)
    await reg.shutdown()
    check("a unit that cannot be stopped at shutdown is passed as units_left", r.L.unprepare_calls[-1]["units_left"] == 1, str(r.L.unprepare_calls[-1]))


# ---------------------------------------------------------------- preflight

async def t_preflight(r):
    reg = r.reg
    reg._preflight = None
    res = await reg.preflight()
    check("first preflight runs the probe once", r.probe_runs == 1 and res["ok"] and set(res) == {"ok", "checks"})
    check("the cache file was written (0600)", os.path.exists(os.path.join(r.tmp, "pf.json")) and (os.stat(os.path.join(r.tmp, "pf.json")).st_mode & 0o777) == 0o600)
    reg._preflight = None
    res = await reg.preflight()
    check("cache hit: the probe does not run again", r.probe_runs == 1 and res["ok"])
    res = await reg.preflight(force=True)
    check("force runs the probe", r.probe_runs == 2)
    r.versions["chromium"] = "157"
    await reg.preflight()
    check("a key change runs the probe", r.probe_runs == 3)
    # create during a run
    r.probe_gate = asyncio.Event()
    t = asyncio.ensure_future(reg.preflight(force=True))
    await asyncio.sleep(0.05)
    check("checking() is true while the probe runs", reg.checking() is True and reg.availability()["checking"] is True)
    try:
        await r.make(user=1)
        got = None
    except Refused as e:
        got = e
    check("create while the preflight runs: 503 with retry_after 10", got is not None and got.status == 503 and got.body == {"retry_after": 10}, str(got and got.body))
    t2 = asyncio.ensure_future(reg.preflight())
    await asyncio.sleep(0.02)
    r.probe_gate.set()
    a, b = await asyncio.gather(t, t2)
    check("two calls during one run share it", r.probe_runs == 4 and a is b)
    check("create works after the run", (await r.make(user=1)).state == "running")
    # a failed check
    r.probe_result = {"ok": False, "checks": [{"name": "egress", "ok": True, "detail": "ok"}, {"name": "bind", "ok": False, "detail": "x"}]}
    res = await reg.preflight(force=True)
    check("a failed check makes the result not ok", res["ok"] is False)
    reg.L.available = True
    av = reg.availability()
    check("availability()['available'] is false with the failing check named", av["available"] is False and any("bind" in x for x in av["reasons"]), str(av["reasons"]))
    ev = reg.take_events()
    check("preflight_failed event carries the check names", any(e["kind"] == "preflight_failed" and e["checks"] == ["bind"] for e in ev))
    try:
        await r.make(user=2, token="z")
        got = None
    except Refused as e:
        got = e
    check("create is refused while the last preflight failed", got is not None and got.status == 503)
    cache = json.load(open(os.path.join(r.tmp, "pf.json")))
    check("a failed result is not cached", cache["result"]["ok"] is True)
    # parse_probe_output
    good = json.dumps({"ok": True, "checks": [{"name": "a", "ok": True, "detail": "d"}]})
    check("parse_probe_output: last JSON line wins", rbrowser.parse_probe_output("noise\n" + good + "\n")["ok"] is True)
    check("parse_probe_output: nothing printed is a failed run", rbrowser.parse_probe_output("") ["ok"] is False and rbrowser.parse_probe_output("not json")["checks"][0]["name"] == "run")
    mixed = json.dumps({"ok": True, "checks": [{"name": "a", "ok": True, "detail": "d"}, {"name": "b", "ok": False, "detail": "d"}]})
    check("parse_probe_output: one failed check fails the run even when the probe says ok", rbrowser.parse_probe_output(mixed)["ok"] is False)


# ---------------------------------------------------------------- the rest of the contract

async def t_no_start_before_preflight(r):
    r.reg._preflight = None
    try:
        await r.make(user=1)
        got = None
    except Refused as e:
        got = e
    check("no start before a preflight has passed", got is not None and got.status == 503 and r.launcher.start_calls == 0)
    r.reg.ready = False
    res = await r.reg.preflight()
    check("preflight on an unprepared host is a failed run that starts no probe and queues no event", res["ok"] is False and r.probe_runs == 0 and r.reg.take_events() == [])


async def t_misc(r):
    check("end reasons are the closed list of design 3", set(rbrowser.END_REASONS) == {"closed", "closed_in_browser", "idle", "detached", "max_lifetime", "traffic_limit",
          "replaced", "signed_out", "admin_end", "crash", "portal_stop", "start_failed", "settings_changed"})
    seven = {"rbrowser_preflight_failed", "rbrowser_listener_found", "rbrowser_socket_mismatch", "rbrowser_display_mismatch", "rbrowser_protocol_violation",
             "rbrowser_traffic_limit", "rbrowser_settings_changed"}
    check("every marker maps to one of the seven event names", set(rbrowser.EVENT_OF) == set(rbrowser.MARKERS) and set(rbrowser.EVENT_OF.values()) <= seven, str(rbrowser.EVENT_OF))
    check("event_detail: the budget for traffic_limit, the marker name for the rest", rbrowser.event_detail("traffic_limit", "upload_rate") == "upload_rate"
          and rbrowser.event_detail("tmp_quota") == "tmp_quota" and rbrowser.event_detail("traffic_limit", "x") == "traffic_limit" and rbrowser.event_detail(None) == "")
    check("boot_id is stable within a registry and differs between registries", r.reg.boot_id() == r.reg.boot_id() and r.reg.boot_id() != Registry().boot_id())
    check("seats(cfg) is {max, cpu_percent}", set(r.reg.seats(CFG)) == {"max", "cpu_percent"} and r.reg.seats(CFG)["max"] == 2)
    check("clipboard setting to unit value", [rbrowser.clipboard_unit_value(x) for x in ("both", "in", "to_browser", "off", "x", None)] == ["both", "to_browser", "to_browser", "off", "off", "off"])
    check("snap_size follows the unit (560..1920, 480..1200, 16)", rbrowser.snap_size(100, 100) == (560, 480) and rbrowser.snap_size(5000, 5000) == (1920, 1200) and rbrowser.snap_size(1000, 700) == (992, 688))
    try:
        await r.make(user=1, w="x")
        got = None
    except Refused as e:
        got = e
    check("a size that is not a number is 400", got is not None and got.status == 400)
    check("find_prefix needs six characters and one match", r.reg.find_prefix("abc") is None)
    s = await r.make(user=1, token="fp")
    check("find_prefix finds a session by its sid prefix", r.reg.find_prefix(s.sid[:8]) is s)
    check("stage selection: fake only with stage mode", rbrowser.select_launcher_kind(True, {"PORTAL_RBROWSER_FAKE": "1"}) == "fake"
          and rbrowser.select_launcher_kind(False, {"PORTAL_RBROWSER_FAKE": "1"}) == "real" and rbrowser.select_launcher_kind(True, {}) == "real")
    src = Path(rbrowser.__file__).read_text()
    imports = [l.split()[1].split(".")[0] for l in src.splitlines() if l.startswith(("import ", "from ")) and not l.startswith("from __future__")]
    check("the module imports nothing of the portal at the top level", not ({"server", "config", "rbrowser_launch", "rbrowser_policy", "rbrowser_bpf", "psutil", "aiohttp"} & set(imports)), str(imports))


async def t_stage_fake_startup(r):
    reg = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                   environ={"PORTAL_RBROWSER_FAKE": "1"})
    await reg.startup(dict(CFG, stage_mode=True, stage_dir=os.path.join(r.tmp, "stage")))
    check("stage mode with the variable: the fake launcher, no host preparation", reg.ready and isinstance(reg.launcher, FakeLauncher) and r.L.prepare_calls == [] and reg.availability()["available"])
    s = await reg.create(1, "t", 1280, 720, CFG)
    check("a fake session starts through the same code", s.state == "running" and s.expect_cgroup == rbrowser.FAKE_CGROUP)
    reg._x[s.sid].last_listener = 0
    rd, wr = await reg.open_stream(s)
    wr.close()
    check("and attaches through open_stream with the listener check in place (stage reader and scan, no host cgroup)", s.state == "running")
    await reg.shutdown()
    reg2 = Registry(launcher_kw=fake_launcher_kw(), launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3, environ={"PORTAL_RBROWSER_FAKE": "1"})
    r.L.available = False
    await reg2.startup(dict(CFG, stage_mode=False))
    check("the variable without stage mode selects the real path (and here it is unavailable)", not reg2.stage_fake and not reg2.ready and r.L.prepare_calls == [])
    r.L.available = True


# ---------------------------------------------------------------- fix pass 1

async def _bounded(coro, secs=2.0):
    """The result of `coro`, or the string 'HUNG' when it does not finish (a regression is a FAIL, not a 60 s case time-out)."""
    t = asyncio.ensure_future(coro)
    done, _ = await asyncio.wait([t], timeout=secs)
    if not done:
        t.cancel()
        return "HUNG"
    try:
        return t.result()
    except BaseException as e:      # noqa: BLE001
        return e


async def _end_while_parked(r, where):
    """create() parked at `where` (start | sockets | listeners); the session is ended by another member's takeover while it is parked."""
    gate, entered = asyncio.Event(), asyncio.Event()
    if where == "start":
        r.launcher.start_gate = gate
    elif where == "sockets":
        async def parked(sess):
            entered.set()
            await gate.wait()
        r.reg._wait_sockets = parked
    else:
        async def parked(sess, ext):
            entered.set()
            await gate.wait()
            return "clean"
        r.reg._listener_check = parked
    t = asyncio.ensure_future(r.make(user=9))
    await asyncio.sleep(0.05)
    if where != "start":
        await asyncio.wait_for(entered.wait(), 2)
    s = r.reg.for_user(9)
    e = asyncio.ensure_future(r.reg.end(s, "replaced"))
    await asyncio.sleep(0.05)
    gate.set()
    got = await _bounded(t)
    ended = await _bounded(e)
    ok = (isinstance(got, Refused) and got.status == 503 and got.body == {"error": "ended"}) or (where == "start" and isinstance(got, Refused))
    check(f"parked at {where}: create raised and no session was returned", ok, repr(got))
    check(f"parked at {where}: end() returned", ended is None, repr(ended))
    check(f"parked at {where}: the session is ended with its own reason", s.state == "ended" and s.end_reason == "replaced")
    check(f"parked at {where}: _stopping drained, unit stopped, no seat, no leftovers",
          not r.reg._stopping and s.unit not in r.launcher.servers and r.reg._seats_taken() == 0 and not r.reg._x and not r.reg._sessions and not r.reg._left,
          f"stopping {list(r.reg._stopping)} servers {list(r.launcher.servers)} x {len(r.reg._x)}")


async def t_end_while_parked_start(r):
    await _end_while_parked(r, "start")


async def t_end_while_parked_sockets(r):
    await _end_while_parked(r, "sockets")


async def t_end_while_parked_listeners(r):
    await _end_while_parked(r, "listeners")
    # and the member can start again (the seat did not leak)
    del r.reg._listener_check
    s = await r.make(user=9, token="again")
    check("after that the member can start a session", s.state == "running")


async def t_takeover_while_listener_check_parked(r):
    """The member's other sign-in sends takeover while the first create is in its listener check: the second create must not hang."""
    gate, entered = asyncio.Event(), asyncio.Event()
    real = r.reg._listener_check
    state = {"n": 0}

    async def parked(sess, ext):
        state["n"] += 1
        if state["n"] == 1:
            entered.set()
            await gate.wait()
        return await real(sess, ext)
    r.reg._listener_check = parked
    t1 = asyncio.ensure_future(r.make(user=4, token="old"))
    await asyncio.wait_for(entered.wait(), 2)
    t2 = asyncio.ensure_future(r.make(user=4, token="new", takeover=True))
    await asyncio.sleep(0.05)
    gate.set()
    a, b = await _bounded(t1), await _bounded(t2)
    check("takeover during the first create's listener check: the first create is refused, the second one returns a running session",
          isinstance(a, Refused) and isinstance(b, rbrowser.Session) and b.state == "running" and r.reg.for_user(4) is b, f"{a!r} {b!r}")
    check("only the new unit runs", list(r.launcher.servers) == [b.unit] and r.reg._seats_taken() == 1)


async def t_tick_isolation(r):
    a = await r.make(user=1)
    b = await r.make(user=2, token="b")
    r.reg.mark_attached(a, object())
    r.reg.mark_attached(b, object())
    orig = r.reg._judge

    async def judge(s, *args):
        if s is a:
            raise RuntimeError("boom")
        return await orig(s, *args)
    r.reg._judge = judge
    before = len(r.launcher.sweep_args)
    res = await _bounded(tick(r, 16 * 60))
    check("an error in one session's checks does not stop the tick for the other one", res == [(b, "idle")] and b.state == "ended", repr(res))
    check("the tmp sweep still runs", len(r.launcher.sweep_args) == before + 1)
    check("the session whose checks failed is skipped, not ended, on the first and second tick", a.state == "running")
    await tick(r, 0)
    check("still running after the second failing tick", a.state == "running")
    res = await tick(r, 0)
    check("the same failure on three ticks in a row fails closed: ended as crash", res == [(a, "crash")] and a.state == "ended" and a.marker is None)
    check("the errors are counted", r.reg.counters()["check_errors"] == 3)
    await tick(r, 0)
    check("the unit of the failed session was stopped", a.unit not in r.launcher.servers and r.reg._seats_taken() == 0)


async def t_tick_listener_scan_raises(r):
    """The reproduced scenario: two sessions past their idle deadline, cgroup.procs readable, the scan raises on the 6th tick."""
    a = await r.make(user=1)
    b = await r.make(user=2, token="b")
    r.scan_error = RuntimeError("psutil broke")
    res = []
    for i in range(6):
        res = await _bounded(tick(r, 1))
        if res == "HUNG" or isinstance(res, BaseException):
            break
    check("a listener scan that raises does not raise out of tick()", isinstance(res, list), repr(res))
    check("both sessions end as crash without a marker (cannot tell is not clean)", {s.sid for s, _ in res} == {a.sid, b.sid}
          and all(reason == "crash" for _s, reason in res) and a.marker is None and b.marker is None, repr(res))
    check("the tmp sweep ran on that tick", len(r.launcher.sweep_args) >= 6)
    check("counted as unverified", r.reg.counters()["listener_unverified"] == 2)


async def t_tick_concurrent_end(r):
    s = await r.make(user=1)
    orig = r.reg._judge

    async def judge(sess, *args):
        v = await orig(sess, *args)
        await r.reg.end(sess, "admin_end")          # another request ends it while the tick is judging
        return ("idle", None, "")
    r.reg._judge = judge
    res = await tick(r, 1)
    check("a session ended during its own check keeps its real reason and is not returned by the tick", res == [] and s.end_reason == "admin_end", repr(res))


async def t_start_failed_cancelled_during_stop(r):
    r.launcher.start_gate = asyncio.Event()
    t = asyncio.ensure_future(r.make(user=9))
    await asyncio.sleep(0.05)
    s = r.reg.for_user(9)
    e = asyncio.ensure_future(r.reg.end(s, "signed_out"))
    await asyncio.sleep(0.05)
    r.launcher.stop_gate = asyncio.Event()
    r.launcher.start_gate.set()                      # start returns, the registry sees `cancelled` and starts the stop, which is gated
    await asyncio.sleep(0.1)
    t.cancel()                                       # the request task is cancelled during that stop
    await asyncio.sleep(0.05)
    ended = await _bounded(e)
    check("end() returns although the create task was cancelled during the stop", ended is None, repr(ended))
    check("the _x entry is gone (its ident is no longer held live by a stale entry)", s.sid not in r.reg._x and not r.reg._x)
    check("the unit that could not be confirmed is on the left list and keeps its seat", r.reg.left_units() == [s.unit] and r.reg._seats_taken() == 1)
    r.launcher.stop_gate.set()
    await tick(r, 1)
    check("the tick stops it and frees the seat", r.reg.left_units() == [] and r.reg._seats_taken() == 0 and not r.launcher.servers)


async def t_tick_does_not_wait_for_a_stop(r):
    a = await r.make(user=1)
    b = await r.make(user=2, token="b")
    r.reg.mark_attached(a, object())
    r.reg.mark_attached(b, object())
    r.launcher.stop_gates[a.unit] = asyncio.Event()
    r.clock.advance(16 * 60)
    res = await _bounded(r.reg.tick(CFG), 1.0)
    check("a stop that does not confirm does not hold up the tick", isinstance(res, list) and {s.sid for s, _ in res} == {a.sid, b.sid}, repr(res))
    await asyncio.sleep(0.05)
    check("the other session's unit is stopped meanwhile", b.unit not in r.launcher.servers)
    check("the stuck session's seat stays taken", a.unit in r.reg._stopping and r.reg._seats_taken() == 1 and a.state == "ended")
    w = asyncio.ensure_future(r.reg.end(a, "closed"))          # a later end() of the same session waits for the same stop
    await asyncio.sleep(0.05)
    check("end() on it waits, it does not start a second stop", not w.done() and r.launcher.stop_calls.count(a.unit) == 1)
    r.launcher.stop_gates[a.unit].set()
    await _bounded(w)
    check("after the stop the seat is free", r.reg._seats_taken() == 0 and a.unit not in r.launcher.servers and a.end_reason == "idle")


async def t_unverifiable_listener_check(r):
    s = await r.make(user=1)
    check("setup: the unit is checked at start (cgroup.procs read)", s.state == "running")
    # tick
    r.procs = OSError("gone")
    res = []
    for _ in range(6):
        res = await tick(r, 1)
        if res:
            break
    check("cgroup.procs unreadable on a running session: crash, not clean", res == [(s, "crash")] and s.marker is None)
    # empty
    r.procs = "\n"
    s2 = None
    try:
        await r.make(user=2, token="b")
    except Refused as e:
        s2 = e
    check("an empty cgroup.procs at start refuses the start and stops the unit", s2 is not None and s2.status == 503 and not r.launcher.servers and r.reg._seats_taken() == 0, repr(s2))
    # a bad cgroup path in the session
    r.procs = "1234\n"
    s3 = await r.make(user=3, token="c")
    s3.expect_cgroup = "/a/../b"
    r.reg._x[s3.sid].last_listener = 0
    got = None
    try:
        await r.reg.open_stream(s3)
    except rbrowser.StreamRefused as e:
        got = e
    check("open_stream: a listener check that cannot be made ends the session (crash) and refuses", got is not None and got.ended is True and got.marker is None and s3.end_reason == "crash", repr(got))
    # the psutil scan itself: a pid that does not exist is 'could not look', not 'clean'
    raised = False
    try:
        Registry()._psutil_scan([2 ** 22 + 12345])
    except LookupError:
        raised = True
    check("the psutil scan raises when no process of the unit could be looked at", raised)
    check("and finds no listener in a process that has none", Registry()._psutil_scan([os.getpid()]) is False)
    # AccessDenied on one pid among clean ones is 'cannot tell', not 'clean'
    import psutil

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid

        def net_connections(self, kind="inet"):
            if self.pid == 111:
                raise psutil.AccessDenied(pid=111)
            return []
    orig_proc = psutil.Process
    psutil.Process = FakeProc
    try:
        raised = None
        try:
            Registry()._psutil_scan([222, 111, 333])
        except psutil.AccessDenied as e:
            raised = e
        check("the psutil scan raises when one pid of the unit is denied and the others are clean", raised is not None)
        ok_scan = Registry()._psutil_scan([222, 333])
        check("the same fake without the denied pid is clean (the fake itself is sound)", ok_scan is False)
        reg2 = Registry(read_file=lambda path: "111\n222\n", cgroup_root=os.path.join(r.tmp, "cg"))
        from rbrowser import Session
        sess = Session(sid="s", unit="u", user_id=1, token_id="t", state="running", runtime_dir="", expect_uid=-1, expect_cgroup="/a/b", width=1, height=1,
                       started=0, last_activity=0, detached_since=0, ident="0" * 12, ingress_pin="")
        verdict = await reg2._listener_check(sess, rbrowser._Ext("0" * 12, "", "u"))
        check("_listener_check with the real scan: a denied pid makes the verdict unknown, not clean", verdict == "unknown", verdict)
    finally:
        psutil.Process = orig_proc


async def t_filter_attached_raises(r):
    s = await r.make(user=1)
    r.launcher.filter_raise = True
    res = await tick(r, 1)
    check("filter_attached raising fails closed: crash with marker ingress_filter_lost", res == [(s, "crash")] and s.marker == "ingress_filter_lost")
    ev = [e for e in r.reg.take_events() if e["kind"] == "marker"]
    check("and the event is queued", len(ev) == 1 and ev[0]["marker"] == "ingress_filter_lost")
    r.launcher.filter_raise = False


async def t_shutdown_with_probe(r):
    """shutdown() while the probe unit runs: the probe is stopped before the host is unprepared and counted if it is not."""
    async def journal(argv, timeout):
        return types.SimpleNamespace(rc=0, out="")

    def make_reg():
        pl = TLauncher(os.path.join(r.tmp, "probe"), unit_prefix="portal-rbprobe-")
        reg = Registry(launcher_kw=fake_launcher_kw(), launcher=r.launcher, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, ncpu=4,
                       mem_total=15 * 1024 ** 3, cache_path=os.path.join(r.tmp, "pf5.json"), versions=lambda: {}, run=journal,
                       read_file=r.read_file, listener_scan=lambda pids: False, cgroup_root=os.path.join(r.tmp, "cg"))
        reg.ready, reg.pin, reg.prep, reg.cfg, reg._probe_launcher = True, r.reg.pin, {"ok": True, "reasons": []}, CFG, pl
        return reg, pl
    reg, pl = make_reg()
    snap = {}
    r.L.on_unprepare = lambda: snap.update(stops=list(pl.stop_calls), servers=list(pl.servers), probes=dict(reg._probe_units))
    t = asyncio.ensure_future(reg.preflight(force=True))
    await asyncio.sleep(0.1)
    check("setup: the probe unit is running", len(reg._probe_units) == 1 and len(pl.servers) == 1)
    await reg.shutdown()
    r.L.on_unprepare = None
    t_res = await _bounded(t, 1)
    del t_res
    check("the probe unit was stopped before the host was unprepared", len(snap.get("stops", [])) == 1 and snap.get("servers") == [] and snap.get("probes") == {}, str(snap))
    check("units_left is 0 once the probe unit is gone", r.L.unprepare_calls[-1]["units_left"] == 0, str(r.L.unprepare_calls[-1]))
    # a probe stop that does not confirm in time is counted
    reg, pl = make_reg()
    pl.stop_gate = asyncio.Event()
    old = rbrowser.SHUTDOWN_STOP_S
    rbrowser.SHUTDOWN_STOP_S = 0.2
    try:
        t = asyncio.ensure_future(reg.preflight(force=True))
        await asyncio.sleep(0.1)
        await reg.shutdown()
    finally:
        rbrowser.SHUTDOWN_STOP_S = old
    check("a probe unit that is not confirmed gone is counted in units_left", r.L.unprepare_calls[-1]["units_left"] >= 1, str(r.L.unprepare_calls[-1]))
    pl.stop_gate.set()
    await _bounded(t, 1)
    await asyncio.sleep(0.05)


async def t_preflight_invalidation(r):
    reg = r.reg
    reg._preflight = None
    await reg.preflight()
    check("setup: one probe run, its key is kept", r.probe_runs == 1 and reg._pf_key is not None)
    # host_prepare names a new pin: the result was made under another one
    r.L.pin = "/sys/fs/bpf/portal-rb-ingress-aaaaaaaaaaaaaaaa"
    r.probe_gate = asyncio.Event()          # the scheduled run waits here: host_prepare's later awaits cannot let it finish first
    await reg.host_prepare(CFG)
    check("host_prepare with a new pin drops the last result and schedules a run", reg._preflight is None or reg.checking(), repr(reg._preflight))
    got = None
    try:
        await r.make(user=1)
    except Refused as e:
        got = e
    check("create is refused until the probe has passed under the new pin", got is not None and got.status == 503 and got.body in ({"retry_after": 10}, {"error": "unavailable"}), repr(got))
    r.probe_gate.set()
    r.probe_gate = None
    await _bounded(reg._pf_task)
    check("the scheduled run ran and passed", r.probe_runs == 2 and reg._preflight is not None and reg._preflight["ok"])
    check("a re-prepare with the same pin and settings keeps the result", (await reg.host_prepare(CFG)) and r.probe_runs == 2 and reg._preflight is not None)
    # a setting that enters the key, changed through a normal call
    await reg.tick(dict(CFG, rbrowser_extra_deny=["10.99.0.0/16"]))
    await _bounded(reg._pf_task)
    check("a changed deny list runs the probe again", r.probe_runs == 3 and reg._preflight["ok"])
    # a change while a run is in flight: the answer of that run is not kept
    r.probe_gate = asyncio.Event()
    t = asyncio.ensure_future(reg.preflight(force=True))
    await asyncio.sleep(0.05)
    await reg.tick(dict(CFG, rbrowser_extra_deny=["10.98.0.0/16"]))
    r.probe_gate.set()
    await _bounded(t)
    check("a settings change during a run makes it run again", r.probe_runs == 5 and reg._preflight is not None and reg._preflight["ok"], str(r.probe_runs))
    # the key covers the probe targets and the unit sources
    k0 = reg.preflight_key(CFG)
    reg._targets_doc = {"x": 1}
    k1 = reg.preflight_key(CFG)
    reg._unit_src_digest = lambda: "other"
    k2 = reg.preflight_key(CFG)
    check("the key changes with the probe targets document and with the unit sources", len({k0, k1, k2}) == 3)
    check("the unit source digest is a sha256 over the real files", len(Registry()._unit_src_digest()) == 64)


async def t_preflight_drift(r):
    reg = r.reg
    runs = r.probe_runs
    # a setting that is in the key, whatever KEY_SETTINGS holds: found by comparing the whole key
    saved = rbrowser.KEY_SETTINGS
    rbrowser.KEY_SETTINGS = ()
    try:
        await reg.tick(CFG)
        check("setup: the same settings and host facts leave the result alone", r.probe_runs == runs and reg._preflight is not None and not reg.checking())
        r.probe_gate = asyncio.Event()
        await reg.tick(dict(CFG, rbrowser_clipboard="off"))
        check("a clipboard change drops the result and schedules a run (nothing in KEY_SETTINGS names it)", reg._preflight is None and reg.checking(), repr(reg._preflight))
        got = None
        try:
            await r.make(user=1, cfg=dict(CFG, rbrowser_clipboard="off"))
        except Refused as e:
            got = e
        check("create is refused while that run is held", got is not None and got.status == 503 and not r.launcher.servers, repr(got))
        r.probe_gate.set()
        r.probe_gate = None
        await _bounded(reg._pf_task)
        check("the run ran once and passed under the new key", r.probe_runs == runs + 1 and reg._preflight is not None and reg._preflight["ok"]
              and reg._pf_key == reg.preflight_key(dict(CFG, rbrowser_clipboard="off")))
        s = await r.make(user=1, cfg=dict(CFG, rbrowser_clipboard="off"))
        check("and create starts a session again", s.state == "running")
        await reg.end(s, "closed")
        # the Chromium version moves (an apt upgrade while the portal runs)
        r.probe_runs_before = r.probe_runs
        r.versions["chromium"] = "157"
        r.probe_gate = asyncio.Event()
        got = None
        try:
            await r.make(user=2, token="b", cfg=dict(CFG, rbrowser_clipboard="off"))
        except Refused as e:
            got = e
        check("create itself notices a new Chromium version and refuses until the probe passed", got is not None and got.status == 503 and reg._preflight is None
              and not r.launcher.servers, repr(got))
        r.probe_gate.set()
        r.probe_gate = None
        await _bounded(reg._pf_task)
        check("the probe ran again for the new binary", r.probe_runs == r.probe_runs_before + 1 and reg._preflight["ok"])
        # a failed probe under the new key keeps create refused
        r.versions["chromium"] = "158"
        r.probe_result = {"ok": False, "checks": [{"name": "file_scheme", "ok": False, "detail": "x"}]}
        await reg.tick(dict(CFG, rbrowser_clipboard="off"))
        await _bounded(reg._pf_task)
        got = None
        try:
            await r.make(user=3, token="c", cfg=dict(CFG, rbrowser_clipboard="off"))
        except Refused as e:
            got = e
        check("a binary that fails the probe starts no session", got is not None and got.status == 503 and not reg.availability()["available"], repr(got))
        r.probe_result = {"ok": True, "checks": [{"name": "egress", "ok": True, "detail": "ok"}]}
        # a key that cannot be computed leaves the result alone and runs nothing on every tick
        await reg.tick(dict(CFG, rbrowser_clipboard="off"))
        await _bounded(reg._pf_task)
        runs = r.probe_runs
        orig = reg.preflight_key

        def broken(cfg):
            raise RuntimeError("no key")
        reg.preflight_key = broken
        for _ in range(4):
            await reg.tick(dict(CFG, rbrowser_clipboard="off"))
        reg.preflight_key = orig
        check("a key that cannot be computed starts no probe on a tick", r.probe_runs == runs and reg._preflight is not None, f"{r.probe_runs} {runs}")
    finally:
        rbrowser.KEY_SETTINGS = saved
        r.probe_gate = None
    # KEY_SETTINGS itself now names the three settings of the unit's property list that were missing
    check("KEY_SETTINGS names the clipboard, the extra hidden paths and the portal unit", {"rbrowser_clipboard", "hidden_extra", "portal_unit"} <= set(saved))


async def t_failed_unit_reset(r):
    l = r.launcher
    # exit status 3 of a unit that stays loaded as failed (no --collect): the marker fires, the unit is reset
    a = await r.make(user=1)
    l.exit_in_error(a.unit, 3)
    res = await tick(r, 1)
    ev = [e for e in r.reg.take_events() if e["kind"] == "marker"]
    check("a failed unit with status 3 ends as crash with display_mismatch and queues the event",
          res == [(a, "crash")] and a.marker == "display_mismatch" and len(ev) == 1 and ev[0]["marker"] == "display_mismatch", str(ev))
    check("the failed unit was reset after it was read, and is not listed on the next tick", l.reset_calls.count(a.unit) >= 1 and a.unit not in l.failed)
    b = await r.make(user=2, token="b")
    l.exit_in_error(b.unit, 4)
    res = await tick(r, 1)
    check("a failed unit with another status ends as crash without a marker and is reset", res == [(b, "crash")] and b.marker is None and b.unit in l.reset_calls and b.unit not in l.failed)
    # a session ended for another reason while its unit sits failed: the confirmed stop resets it
    c = await r.make(user=3, token="c")
    l.exit_in_error(c.unit, 4)
    await r.reg.end(c, "closed")
    check("ending a session whose unit is failed resets the unit", c.unit in l.reset_calls and c.unit not in l.failed)
    # a failed unit with a session-pattern name that nobody knows: not stopped, but reset (it must not pile up)
    ghost = f"{rbrowser.UNIT_PREFIX}0123456789ab.service"
    l.failed[ghost] = "1"
    before = r.reg.counters()["unknown_stopped"]
    await tick(r, 1)
    check("an unknown failed unit is reset, not stopped, not counted", ghost in l.reset_calls and ghost not in l.failed and ghost not in l.stop_calls
          and r.reg.counters()["unknown_stopped"] == before)
    # after a restart: sweep_orphans, and a failed probe unit
    ghost2 = f"{rbrowser.UNIT_PREFIX}ba9876543210.service"
    pghost = f"{rbrowser.PROBE_PREFIX}0a0a0a0a0a0a.service"
    l.failed[ghost2] = "3"
    pl = TLauncher(os.path.join(r.tmp, "probe2"), unit_prefix=rbrowser.PROBE_PREFIX)
    pl.failed[pghost] = "1"
    r.reg._probe_launcher = pl
    bad = await r.reg.sweep_orphans()
    check("sweep_orphans after a restart resets a failed session unit (session launcher) and a failed probe unit (probe launcher)",
          bad == [] and ghost2 not in l.failed and pghost not in pl.failed and ghost2 in l.reset_calls and pghost in pl.reset_calls
          and pghost not in l.reset_calls, str(l.failed))
    r.reg._probe_launcher = None
    # a reset that fails, and a launcher without reset_failed, change nothing about the verdict
    d = await r.make(user=4, token="d")
    l.reset_raises = True
    l.exit_in_error(d.unit, 3)
    res = await tick(r, 1)
    check("a reset-failed that raises does not change the verdict", res == [(d, "crash")] and d.marker == "display_mismatch")
    l.reset_raises = False
    l.failed.clear()
    e = await r.make(user=5, token="e")
    l.reset_failed = None
    l.exit_in_error(e.unit, 3)
    res = await tick(r, 1)
    check("a launcher without reset_failed is used as before", res == [(e, "crash")] and e.marker == "display_mismatch")
    del l.reset_failed
    # a unit that exited cleanly is unloaded: asked by name, inactive with status 0, closed in the browser
    f = await r.make(user=6, token="f")
    l.gone.add(f.unit)
    res = await tick(r, 1)
    check("a unit that is gone (clean exit, collected by systemd) is closed_in_browser", res == [(f, "closed_in_browser")] and f.marker is None, str(res))


async def t_preflight_gate_in_lock(r):
    """T5: the preflight gate is evaluated inside the registry lock on every pass of create, takeover included."""
    reg, l = r.reg, r.launcher
    # the reviewer's scenario: a takeover waits for the old unit's stop, the key drifts meanwhile, the stop is released
    a = await r.make(user=1, token="old")
    l.stop_gates[a.unit] = asyncio.Event()
    starts = l.start_calls
    t = asyncio.ensure_future(r.make(user=1, token="new", takeover=True))
    await asyncio.sleep(0.05)
    check("setup: the takeover is parked on the old unit's stop and started nothing", not t.done() and a.unit in l.stop_calls and l.start_calls == starts and a.state == "ended")
    r.versions["chromium"] = "157"                     # a host-side change; no setting changed, nothing calls remember in between
    r.probe_gate = asyncio.Event()                     # the run the drift schedules is held, so its result cannot pass in time
    runs = r.probe_runs
    l.stop_gates[a.unit].set()
    got = None
    try:
        await asyncio.wait_for(t, 5)
    except Refused as e:
        got = e
    check("released: the takeover is refused 503 (the second pass saw the drifted key)", got is not None and got.status == 503, repr(got))
    check("and no unit was started and no seat is held", l.start_calls == starts and not l.servers and reg._seats_taken() == 0 and reg.for_user(1) is None, f"{l.start_calls} {starts}")
    check("the drift dropped the result and scheduled one run", reg._preflight is None and reg.checking())
    r.probe_gate.set()
    r.probe_gate = None
    await _bounded(reg._pf_task)
    check("one run for the new binary, then create works again", r.probe_runs == runs + 1 and (await r.make(user=1, token="new")).state == "running")
    for x in list(reg.all()):
        await reg.end(x, "closed")
    # an uncomputable key refuses create and starts no probe (and no unit), however often it is asked
    runs = r.probe_runs
    orig = reg.preflight_key

    def broken(cfg):
        raise RuntimeError("no key")
    reg.preflight_key = broken
    outs = []
    for _ in range(4):
        try:
            await r.make(user=2, token="b")
            outs.append(None)
        except Refused as e:
            outs.append(e)
    reg.preflight_key = orig
    check("an uncomputable key: create refuses 503 every time", all(e is not None and e.status == 503 for e in outs), repr(outs))
    check("an uncomputable key: no probe, no unit, the result is kept", r.probe_runs == runs and not l.servers and reg._preflight is not None and not reg.checking())
    check("the key back: create works", (await r.make(user=2, token="b")).state == "running")
    # a takeover whose gate fails on its FIRST pass does not end the old session
    old = reg.for_user(2)
    r.versions["chromium"] = "158"
    r.probe_gate = asyncio.Event()
    got = None
    try:
        await r.make(user=2, token="c", takeover=True)
    except Refused as e:
        got = e
    check("a takeover refused by the gate leaves the old session running", got is not None and got.status == 503 and old.state == "running" and l.servers)
    r.probe_gate.set()
    r.probe_gate = None
    await _bounded(reg._pf_task)


async def t_exit_code_of_status_3(r):
    """T7/F4: status 3 is display_mismatch only for ExecMainCode 1 (exited); SIGQUIT (killed, 2) and a core dump (3) are a plain crash."""
    l = r.launcher
    a = await r.make(user=1)
    l.exit_in_error(a.unit, 3, code=2)
    res = await tick(r, 1)
    check("status 3 with code 2 (killed by SIGQUIT) is a crash without a marker", res == [(a, "crash")] and a.marker is None and not r.reg.take_events(), str(a.marker))
    b = await r.make(user=2, token="b")
    l.exit_in_error(b.unit, 3, code=3)
    res = await tick(r, 1)
    check("status 3 with code 3 (dumped) is a crash without a marker", res == [(b, "crash")] and b.marker is None)
    c = await r.make(user=3, token="c")
    l.exit_in_error(c.unit, 3, code=1)
    res = await tick(r, 1)
    check("status 3 with code 1 (exited) is display_mismatch", res == [(c, "crash")] and c.marker == "display_mismatch")
    d = await r.make(user=4, token="d")
    l.exit_in_error(d.unit, 3)
    del l.failed_code[d.unit]
    l.failed_code.pop(d.unit, None)
    orig = l.show

    async def no_code(units):
        out = await orig(units)
        for v in out.values():
            v.pop("ExecMainCode", None)
        return out
    l.show = no_code
    res = await tick(r, 1)
    del l.show
    check("status 3 without any ExecMainCode is not read as display_mismatch", res == [(d, "crash")] and d.marker is None)
    check("every one of them was reset by the stop that ended the session, none by the judge", all(u in l.reset_calls for u in (a.unit, b.unit, c.unit)) and not l.failed)
    # the judge itself does not reset: a launcher whose stop does not reset leaves the unit failed
    e = await r.make(user=5, token="e")
    l.exit_in_error(e.unit, 4)
    l.reset_calls.clear()
    seen = []
    orig_stop = l.stop

    async def stop_no_reset(unit):
        seen.append(list(l.reset_calls))
        return await orig_stop(unit)
    l.stop = stop_no_reset
    await tick(r, 1)
    del l.stop
    check("the reset comes after the stop, not before it", seen and seen[0] == [] and e.unit in l.reset_calls, str(seen))


async def t_probe_sweep_fullmatch(r):
    l = r.launcher
    pl = TLauncher(os.path.join(r.tmp, "probe3"), unit_prefix=rbrowser.PROBE_PREFIX)
    reg = Registry(launcher_kw=fake_launcher_kw(), launcher=l, launch_mod=r.L, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, prefix=rbrowser.UNIT_PREFIX,
                   probe_prefix=rbrowser.PROBE_PREFIX, cache_path=os.path.join(r.tmp, "pf2.json"), tmp_dir=os.path.join(r.tmp, "tmp"))
    reg._probe_launcher = pl
    good = f"{rbrowser.PROBE_PREFIX}0a0a0a0a0a0a.service"
    odd1 = f"{rbrowser.PROBE_PREFIX}0a0a0a0a0a0a-x.service"
    odd2 = f"{rbrowser.PROBE_PREFIX}zz.service"
    odd3 = f"{rbrowser.PROBE_PREFIX}0a0a0a0a0a0a0a.service"
    for u in (good, odd1, odd2, odd3):
        pl.extra[u] = {"ActiveState": "failed"}      # show() reports them all; only the exact pattern may be reset
    pl.failed[good] = "1"
    await reg.sweep_orphans()
    check("the probe sweep resets a failed probe unit of the exact pattern and nothing else with the prefix",
          good in pl.reset_calls and not ({odd1, odd2, odd3} & set(pl.reset_calls)), str(pl.reset_calls))


async def t_probe_sweep_real_launchers(r):
    """The sweep with two real SystemdLauncher objects (one per prefix) and a fake `run`: a failed probe unit gets its reset-failed, through the
    probe launcher, before host_prepare has made one (start-up) and after it; nothing of the session pattern is touched."""
    good = f"{rbrowser.PROBE_PREFIX}0a0a0a0a0a0a.service"
    other = f"{rbrowser.PROBE_PREFIX}0b0b0b0b0b0b.service"       # not failed: left alone
    sess = f"{rbrowser.UNIT_PREFIX}0c0c0c0c0c0c.service"          # a session-pattern unit nobody knows: stopped, as before
    for pre_made in (False, True):
        calls = []

        async def run(argv, timeout, _calls=calls):
            _calls.append(list(argv))
            if "show" in argv:
                pats = [a for a in argv if a.endswith(".service")]
                out = ""
                if any(a.startswith(rbrowser.PROBE_PREFIX) for a in pats):
                    out = (f"Id={good}\nActiveState=failed\nExecMainStatus=1\nExecMainCode=1\nMainPID=0\nControlGroup=\n\n"
                           f"Id={other}\nActiveState=inactive\nExecMainStatus=0\nExecMainCode=0\nMainPID=0\nControlGroup=\n")
                elif any(a.startswith(rbrowser.UNIT_PREFIX) for a in pats):
                    out = f"Id={sess}\nActiveState=inactive\nExecMainStatus=0\nExecMainCode=0\nMainPID=0\nControlGroup=\n"
                return types.SimpleNamespace(rc=0, out=out, err="")
            return types.SimpleNamespace(rc=0, out="", err="")

        kw = dict(run=run, which=lambda n: "/usr/bin/" + n, read_text=lambda p: "", bpf=r.bpf,
              theme_dir=os.path.join(r.tmp, "theme"), static_dir=os.path.join(r.tmp, "static"))
        slau = RL.SystemdLauncher(unit_prefix=rbrowser.UNIT_PREFIX, **kw)
        plau = RL.SystemdLauncher(unit_prefix=rbrowser.PROBE_PREFIX, script="probe.py", nice=19, **kw)
        reg = Registry(launcher=slau, launch_mod=RL, bpf=r.bpf, clock=r.clock, sleep=nosleep, host_facts=lambda: FACTS, prefix=rbrowser.UNIT_PREFIX,
                       probe_prefix=rbrowser.PROBE_PREFIX, cache_path=os.path.join(r.tmp, "pf6.json"), tmp_dir=os.path.join(r.tmp, "tmp"),
                       launcher_kw=kw)
        if pre_made:
            reg._probe_launcher = plau
        bad = await reg.sweep_orphans()
        resets = [a for a in calls if "reset-failed" in a]
        tag = "after host_prepare" if pre_made else "at start-up (no probe launcher yet)"
        check(f"real launchers, {tag}: reset-failed is issued for the failed probe unit and for no other",
              bad == [] and [a[-1] for a in resets if a[-1].startswith(rbrowser.PROBE_PREFIX)] == [good]
              and not [a for a in resets if a[-1] == other], str(calls))
        check(f"real launchers, {tag}: only the session unit is stopped (a probe unit is reset, never stopped)",
              [a[-1] for a in calls if "stop" in a] == [sess], str(calls))


async def t_tmp_walk_by_descriptor(r):
    root = os.path.join(r.tmp, "walk")
    os.makedirs(os.path.join(root, "a", "b"))
    for i in range(3):
        with open(os.path.join(root, "a", "b", f"f{i}"), "wb") as f:
            f.write(b"x" * 100)
    b, n, over = rbrowser.bounded_walk(root)
    check("walk by descriptor counts files and directories", n == 5 and b >= 300 and over is False, f"{b} {n} {over}")
    check("a missing directory is (0, 0, False)", rbrowser.bounded_walk(os.path.join(root, "nope")) == (0, 0, False))
    os.symlink(os.path.join(root, "a"), os.path.join(r.tmp, "top-link"))
    check("a symbolic link in place of the area's directory is over", rbrowser.bounded_walk(os.path.join(r.tmp, "top-link"))[2] is True)
    # the race: a subdirectory is swapped for a symbolic link between the listing and the descent
    other = os.path.join(r.tmp, "elsewhere")
    os.makedirs(other)
    for i in range(10):
        with open(os.path.join(other, f"o{i}"), "wb") as f:
            f.write(b"y" * 1000)
    sub = os.path.join(root, "sub")
    os.makedirs(sub)

    def swap(fd, name):
        if name == "sub":
            shutil.rmtree(sub)
            os.symlink(other, sub)
    b, n, over = rbrowser.bounded_walk(root, _race_hook=swap)
    check("a directory swapped for a link during the walk is not followed and counts as over", over is True and b < 5000, f"{b} {n} {over}")
    # a directory swapped for another directory (a different inode): the listed one is not the one opened
    root2 = os.path.join(r.tmp, "walk2")
    os.makedirs(os.path.join(root2, "sub"))
    with open(os.path.join(root2, "sub", "f"), "wb") as f:
        f.write(b"z")
    calls = []

    def swap_dir(fd, name):
        if name == "sub" and not calls:
            calls.append(1)
            os.rename(os.path.join(root2, "sub"), os.path.join(root2, "sub-old"))    # rename, not rmtree: the old inode stays in use
            os.mkdir(os.path.join(root2, "sub"))
    b, n, over = rbrowser.bounded_walk(root2, _race_hook=swap_dir)
    check("a directory swapped for another directory during the walk counts as over", calls == [1] and over is True, f"{b} {n} {over}")
    check("the same tree without the swap is not over", rbrowser.bounded_walk(os.path.join(r.tmp, "walk2", "sub-old"))[2] is False)
    # (the device comparison needs a second mount; the unit cannot make one and the test must not)
    # depth
    deep = os.path.join(r.tmp, "deep")
    p = deep
    for i in range(rbrowser.WALK_DEPTH + 3):
        p = os.path.join(p, "d")
    os.makedirs(p)
    check("a tree deeper than the limit is over", rbrowser.bounded_walk(deep)[2] is True)
    check("the real walk is still what the registry's quota check uses", Registry()._tmp_scan is rbrowser.bounded_walk)


async def t_live_round2_guard(r):
    import importlib.util
    sp = importlib.util.spec_from_file_location("rb_live_for_guard", ROOT / "tests" / "test_rbrowser_live.py")
    live = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(live)
    pre = ("portal-rb-", "portal-rbprobe-")
    clean = "portal-rbtest-aaaaaaaaaaaa.service loaded active running x\n"
    check("round 2 guard: a clean host and an empty tmp area pass", live.round2_refusal("", [], pre) == [] and live.round2_refusal(clean, [], pre) == [])
    check("round 2 guard: a loaded unit of the real feature refuses", len(live.round2_refusal("portal-rb-0123456789ab.service loaded active running x", [], pre)) == 1)
    check("round 2 guard: a loaded probe unit refuses", len(live.round2_refusal("portal-rbprobe-0123456789ab.service loaded", [], pre)) == 1)
    check("round 2 guard: a unit tmp directory refuses (the sweep would remove it)", len(live.round2_refusal("", ["0123456789ab"], pre)) == 1 and live.round2_refusal("", ["lost+found", "x"], pre) == [])
    check("round 2 guard: a listing that failed refuses", len(live.round2_refusal(None, None, pre)) == 2)


# ---------------------------------------------------------------- 1.26.0: the member's portal theme

async def t_theme(r):
    import dataclasses
    import inspect
    import logging
    records = []

    class _H(logging.Handler):
        def emit(self, rec):
            records.append(rec.getMessage())
    h = _H()
    lg = logging.getLogger()
    old_level = lg.level
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    try:
        key0 = r.reg.preflight_key(CFG)
        plain = await r.make(user=1, token="a")
        sp = r.launcher.specs[plain.unit]
        check("theme: a create without a theme starts a spec without one", (sp.theme_color, sp.theme_mode) == (None, None))
        await r.reg.end(plain, "user")
        s2 = await r.make(user=2, token="b", theme=("#1A1A2E", "dark"))
        sp = r.launcher.specs[s2.unit]
        check("theme: a valid pair reaches the launcher's spec validated (lower case)", (sp.theme_color, sp.theme_mode) == ("#1a1a2e", "dark") and s2.state == "running")
        await r.reg.end(s2, "user")
        s3 = await r.make(user=3, token="c", theme=["#f0e6d2", "light"])
        sp = r.launcher.specs[s3.unit]
        check("theme: a list of two works as well", (sp.theme_color, sp.theme_mode) == ("#f0e6d2", "light"))
        await r.reg.end(s3, "user")
        n = 4
        for label, bad in (("a bad colour", ("red", "dark")), ("a bad mode", ("#1a1a2e", "auto")), ("both bad", ("#12", "x")), ("None values", (None, None)),
                           ("a string", "dark"), ("one value", ("#1a1a2e",)), ("three values", ("#1a1a2e", "dark", "x")), ("a dict", {"color": "#1a1a2e"}),
                           ("a number", 5), ("long text", ("#" + "a" * 100000, "dark" * 1000)),
                           # exactly 7 characters: only the pattern rejects these, not the length test
                           ("seven not-hex", ("#gggggg", "dark")), ("seven with a quote", ('#12"45}', "dark")), ("seven with a newline", ("#16213\n", "dark")),
                           ("seven with a NUL", ("#1621\x00e", "dark")), ("seven with a unicode digit", ("#16213\u0663", "dark"))):
            sx = await r.make(user=n, token=f"t{n}", theme=bad)
            sp = r.launcher.specs[sx.unit]
            want = {("red", "dark"): (None, "dark"), ("#1a1a2e", "auto"): ("#1a1a2e", None)}.get(bad if isinstance(bad, tuple) else None, (None, None))
            if isinstance(bad, tuple) and len(bad) == 2 and isinstance(bad[0], str) and len(bad[0]) == 7 and bad[1] == "dark":
                want = (None, "dark")
            check(f"theme: {label} never fails the start; each value is judged alone, the bad one is the neutral default",
                  sx.state == "running" and (sp.theme_color, sp.theme_mode) == want, str((sp.theme_color, sp.theme_mode)))
            await r.reg.end(sx, "user")
            n += 1
        check("theme: the Session keeps exactly the two validated values and nothing else of the theme",
              [f.name for f in dataclasses.fields(rbrowser.Session) if "theme" in f.name or "color" in f.name] == ["theme_color", "theme_mode"])
        check("theme: the Session of a themed create holds the validated pair, a neutral one holds None",
              (s2.theme_color, s2.theme_mode) == ("#1a1a2e", "dark") and (plain.theme_color, plain.theme_mode) == (None, None)
              and (s3.theme_color, s3.theme_mode) == ("#f0e6d2", "light"))
        check("theme: the preflight key does not depend on the theme or on sessions that have one", r.reg.preflight_key(CFG) == key0)
        spec_probe = r.reg.spec("0" * 12, 1280, 720, CFG)
        args = RL.build_unit_args(spec_probe, rbrowser.PROBE_PREFIX, "probe.py", 19, ingress_pin=r.reg.pin)
        check("theme: the probe's spec and arguments carry no theme", (spec_probe.theme_color, spec_probe.theme_mode) == (None, None)
              and not any("portal-theme" in a or "RB_THEME" in a for a in args))
        # a second create with another theme replaces the session: the new unit has the new theme (fixed per session, not per member)
        s2 = await r.make(user=2, token="first", theme=("#1a1a2e", "dark"))
        s5 = await r.make(user=2, token="other", theme=("#f0e6d2", "light"), takeover=True)
        sp = r.launcher.specs[s5.unit]
        check("theme: a takeover starts the new session with the theme of that create", s5 is not s2 and (sp.theme_color, sp.theme_mode) == ("#f0e6d2", "light"))
        again = await r.make(user=2, token="other", theme=("#000000", "dark"))
        check("theme: a repeated create of the running session returns it unchanged (the theme is fixed for its life)",
              again is s5 and (r.launcher.specs[s5.unit].theme_color) == "#f0e6d2")
        check("theme: rbrowser.create accepts theme=", "theme" in inspect.signature(rbrowser.create).parameters
              and inspect.signature(rbrowser.create).parameters["theme"].default is None
              and "theme" in inspect.signature(Registry.create).parameters)
        check("theme: no event and no log line carries the colour", "1a1a2e" not in str(r.reg.take_events()).lower() and not any("1a1a2e" in m.lower() or "f0e6d2" in m.lower() for m in records))
    finally:
        lg.removeHandler(h)
        lg.setLevel(old_level)
    # the real validator is used even when the policy module is replaced
    class _NoPolicy:
        pass
    r.reg._P_mod = _NoPolicy()
    check("theme: the registry validates with the real function whatever policy module was injected", r.reg._theme(("#ABCDEF", "dark")) == ("#abcdef", "dark") and r.reg._theme(("#ABCDEF", "Dark")) == ("#abcdef", None)
          and r.reg._theme("x") == (None, None))


CASES = [t_concurrent_same_member, t_five_members_two_seats, t_failing_launcher, t_failed_start_unit_left, t_elsewhere_and_takeover, t_end_while_starting,
         t_end_idempotent, t_revocation, t_activity_here_throttle, t_idle_detach_lifetime, t_one_show_per_tick, t_exit_status, t_marker_events, t_ingress_filter,
         t_traffic, t_tmp_quota_and_sweep, t_sweep_tmp_live_set, t_sweeper_allow_list, t_unit_left_running, t_listener, t_startup_nothing,
         t_startup_prepare, t_failed_prepare, t_failed_prepare_cleanup, t_prepare_serialised, t_slice_penalty, t_shutdown_left, t_preflight, t_no_start_before_preflight, t_misc, t_stage_fake_startup,
         t_end_while_parked_start, t_end_while_parked_sockets, t_end_while_parked_listeners, t_takeover_while_listener_check_parked, t_tick_isolation,
         t_tick_listener_scan_raises, t_tick_concurrent_end, t_start_failed_cancelled_during_stop, t_tick_does_not_wait_for_a_stop,
         t_unverifiable_listener_check, t_filter_attached_raises, t_shutdown_with_probe, t_preflight_invalidation, t_preflight_drift, t_failed_unit_reset, t_preflight_gate_in_lock, t_exit_code_of_status_3, t_probe_sweep_fullmatch, t_probe_sweep_real_launchers, t_tmp_walk_by_descriptor, t_live_round2_guard, t_theme]


async def main():
    for fn in CASES:
        print(f"# {fn.__name__}", flush=True)
        try:
            await asyncio.wait_for(case(fn), 60)
        except Exception as e:
            import traceback
            traceback.print_exc()
            check(fn.__name__ + " ran to the end", False, f"{e.__class__.__name__}: {e}")


asyncio.run(main())
print(f"\n{len(failures)} failure(s)" if failures else "\nall passed")
sys.exit(1 if failures else 0)
