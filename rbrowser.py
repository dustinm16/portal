"""Server-side web browser ("rbrowser"): the registry, the stream checks, the sweeper and the preflight.

This file is the CONTRACT of design section 9 and, since lane A2, its implementation: the Session dataclass, the
Launcher protocol, LaunchSpec / LaunchResult, the exceptions, a working FakeLauncher and one `Registry` that the module
functions delegate to. Deviation from the section 9 sketch: Launcher.start, stop and show are coroutines, because every
subprocess of the real launcher goes through asyncio.create_subprocess_exec.

The module imports nothing from server.py, nothing outside the standard library at import time, and it must
import on a host without systemd, aiohttp or psutil (rbrowser_launch, rbrowser_policy, rbrowser_bpf and psutil are
imported inside functions).

Never logged, stored or returned: a URL, a page title, a key code, a pointer position, clipboard text.
"""

from __future__ import annotations

import asyncio
import builtins
import collections
import fnmatch
import hashlib
import importlib.util
import inspect
import json
import logging
import os
import re
import secrets
import shutil
import socket
import stat as _stat
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from aiohttp import web

# Unit-name prefixes. The sweeper acts only on the first form (design section 3).
UNIT_PREFIX = "portal-rb-"
PROBE_PREFIX = "portal-rbprobe-"
TEST_PREFIX = "portal-rbtest-"

# What FakeLauncher reports as the peer's cgroup (and what its cgroup_of() returns for every pid).
FAKE_CGROUP = "/fake.slice/portal-rb-fake.service"


class Refused(Exception):
    """create() could not proceed: an HTTP status and a JSON-able body for the caller to send."""

    def __init__(self, status: int, body: dict):
        super().__init__(f"refused {status}")
        self.status = status
        self.body = body


class LaunchError(Exception):
    """A launcher could not start, express or verify a unit. The text never contains a URL."""


class UnitLeftRunning(LaunchError):
    """stop() could not confirm that a unit is gone (the stop failed or timed out, a SIGKILL did not end it, or systemd did
    not answer). `unit` is the unit's name: the caller keeps it on its list (and the sweeper keeps looking at it) instead of
    treating the session as ended. start() raises this, in place of its original error, when it could not take back a unit
    it had asked systemd to start."""

    def __init__(self, unit: str, why: str = "the unit may still be running"):
        super().__init__(why)
        self.unit = unit


@dataclass
class Session:
    sid: str
    unit: str
    user_id: int
    token_id: str
    state: str                    # "starting" (placeholder under the lock) | "running" | "ended"
    runtime_dir: str              # /run/portal-rb/s-<hex12>, or the stage directory for a fake
    expect_uid: int               # peer uid the bridge requires (dynamic uid; never 0 for a real unit)
    expect_cgroup: str            # peer cgroup the bridge requires
    width: int
    height: int
    started: float = 0.0
    last_activity: float = 0.0
    detached_since: float | None = None
    viewer: "web.WebSocketResponse | None" = None
    bytes_out: int = 0            # stream bytes
    bytes_in: int = 0
    net_in: int = 0               # the browser's internet bytes (kernel counters)
    net_out: int = 0
    # ---- added by lane A2 (all defaulted; the section 9 fields above are unchanged)
    ident: str = ""               # the 12 hex characters of the unit name (the tmp directory of the unit has this name)
    ingress_pin: str = ""         # the BPF pin the unit names; passed to filter_attached and to prune_stale(keep=)
    clipboard: str = "off"        # the unit's RB_CLIPBOARD value: both | to_browser | off (fixed when the unit started)
    net_warning: bool = False     # traffic at 80 % of a volume cap (section 6.4)
    end_reason: str | None = None  # one of END_REASONS once state is "ended"
    marker: str | None = None     # one of MARKERS (a security finding) or None; set together with end_reason
    marker_detail: str = ""       # traffic_limit: upload_rate | upload_volume | download_rate | download_volume
    ended_at: float | None = None
    # ---- 1.26.0: the member's portal theme, validated by rbrowser_policy.normalise_theme and fixed for the life of the session; None = neutral
    theme_color: str | None = None   # "#rrggbb" (lower case)
    theme_mode: str | None = None    # "dark" | "light"


@dataclass
class LaunchSpec:
    """Everything a launcher needs to start one unit. Built by create(), consumed by Launcher.start()."""
    ident: str                    # 12 lowercase hex characters: the random part of the unit name
    width: int
    height: int
    clipboard: str                # both | to_browser | off: only "both" lets the unit answer the `clip` request (the VNC clipboard is always off)
    home_url: str
    chromium: str                 # absolute path of the browser binary
    memory_mb: int
    cpu_percent: int
    deny: list = field(default_factory=list)          # CIDR strings, rbrowser_policy.deny_list()
    hidden_extra: list = field(default_factory=list)  # install directory and every storage root
    portal_unit: str = ""         # unit the portal runs in ("portal.service"), "" when it is not in one
    theme_color: str | None = None   # "#rrggbb" (lower case) or None: the member's portal theme colour (1.26.0); None = the neutral default
    theme_mode: str | None = None    # "dark" | "light" or None; both are validated again by the launcher and the supervisor


@dataclass
class LaunchResult:
    unit: str                     # full unit name, with the .service suffix
    runtime_dir: str
    expect_uid: int
    expect_cgroup: str
    main_pid: int = 0
    ingress_pin: str = ""          # the BPF pin the unit names (D1); the registry keeps it for prune_stale(keep=...) while the unit runs


class Launcher(Protocol):
    async def start(self, spec: LaunchSpec) -> LaunchResult: ...
    async def stop(self, unit: str) -> None: ...
    async def show(self, units: list) -> dict: ...   # {unit: {"ActiveState": "...", ...}} strings as systemctl prints them
    def cgroup_of(self, pid: int) -> str: ...        # the path after "0::" in /proc/<pid>/cgroup
    def filter_attached(self, cgroup: str, pin=None) -> bool: ...   # D1: the ingress BPF filter is attached to the unit's
    # cgroup (LaunchResult.expect_cgroup). Never raises; False ends the session (the registry calls it on every tick).
    def sweep_tmp(self, live_idents) -> list: ...   # D6: remove the /tmp directories of units that are not live; names removed
    async def reset_failed(self, unit: str) -> None: ...   # T1: systemctl reset-failed; best effort, no error for a unit that is not loaded
    # (session units have no --collect: a unit that ended in error stays loaded as `failed` until it is reset). Only awaitables.


# ---------------------------------------------------------------- the fake launcher (stage mode and tests)

def _load_fake_rfb():
    """tests/fixtures/fake_rfb.py loaded by path, so nothing imports the tests directory as a package."""
    path = Path(__file__).resolve().parent / "tests" / "fixtures" / "fake_rfb.py"
    spec = importlib.util.spec_from_file_location("rbrowser_fake_rfb", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeLauncher:
    """Starts a fake RFB server (vnc.sock) and a fake control socket (ctl.sock) in `base_dir/s-<ident>`.

    expect_uid is this process's own uid and expect_cgroup is FAKE_CGROUP, the string cgroup_of() returns
    for every pid; so the bridge's peer check passes for it without any branch on the session kind.
    """

    def __init__(self, base_dir, unit_prefix: str = UNIT_PREFIX):
        self.base_dir = str(base_dir)
        self.unit_prefix = unit_prefix
        self.servers: dict = {}       # unit -> FakeRfb (tests read .records, call .send_cut_text, set .stall)
        self.specs: dict = {}

    async def start(self, spec: LaunchSpec) -> LaunchResult:
        unit = f"{self.unit_prefix}{spec.ident}.service"
        rt = os.path.join(self.base_dir, f"s-{spec.ident}")
        os.makedirs(rt, mode=0o700, exist_ok=True)
        mod = _load_fake_rfb()
        srv = mod.FakeRfb(os.path.join(rt, "vnc.sock"), ctl_path=os.path.join(rt, "ctl.sock"))
        await srv.start()
        self.servers[unit] = srv
        self.specs[unit] = spec
        return LaunchResult(unit=unit, runtime_dir=rt, expect_uid=os.getuid(),
                            expect_cgroup=FAKE_CGROUP, main_pid=os.getpid())

    async def stop(self, unit: str) -> None:
        srv = self.servers.pop(unit, None)
        self.specs.pop(unit, None)
        if srv is None:
            return
        await srv.stop()
        shutil.rmtree(os.path.dirname(srv.path), ignore_errors=True)

    async def show(self, units: list) -> dict:
        out = {}
        names = []
        for u in units:       # a pattern such as "portal-rb-*.service" lists the matching units, as systemctl does
            names += sorted(n for n in self.servers if fnmatch.fnmatchcase(n, u)) if "*" in u else [u]
        for u in names:
            on = u in self.servers
            out[u] = {"Id": u, "ActiveState": "active" if on else "inactive",
                      "ExecMainStatus": "0", "ExecMainCode": "0", "MainPID": str(os.getpid()) if on else "0",
                      "ControlGroup": FAKE_CGROUP, "IPIngressBytes": "0", "IPEgressBytes": "0"}
        return out

    def cgroup_of(self, pid: int) -> str:
        return FAKE_CGROUP

    filter_ok = True              # a test sets False to make the registry see a detached filter

    def filter_attached(self, cgroup: str, pin=None) -> bool:
        return bool(self.filter_ok)

    def sweep_tmp(self, live_idents) -> list:
        return []

    async def reset_failed(self, unit: str) -> None:
        """T1: nothing stays loaded in the fake (stop() forgets the unit), so there is nothing to reset; never raises."""
        return None




# ---------------------------------------------------------------- constants and closed lists (lane B maps on these)

log = logging.getLogger("rbrowser")

# End reasons: the closed list of design section 3. Audit details and the page's 4013 close reason are one of these.
END_REASONS = ("closed", "closed_in_browser", "idle", "detached", "max_lifetime", "traffic_limit", "replaced", "signed_out",
               "admin_end", "crash", "portal_stop", "start_failed", "settings_changed")

# Markers: a security finding that ended (or refused) a session. Session.marker holds one of these, or None. EVENT_OF names the
# security event (one of the seven of design 5.5) that lane B records for it; the detail to record with it is event_detail().
# ingress_filter_lost and tmp_quota have no event of their own: they ride on rbrowser_listener_found (the filter IS the listener
# control, D1; cap-exempt, not aggregated) and rbrowser_traffic_limit (a member-caused budget, aggregated per member). The lead may
# rename these two; lane B reads only EVENT_OF.
MARKERS = ("socket_mismatch", "listener_found", "display_mismatch", "traffic_limit", "ingress_filter_lost", "tmp_quota",
           "preflight_failed")
EVENT_OF = {"socket_mismatch": "rbrowser_socket_mismatch", "listener_found": "rbrowser_listener_found",
            "display_mismatch": "rbrowser_display_mismatch", "traffic_limit": "rbrowser_traffic_limit",
            "preflight_failed": "rbrowser_preflight_failed", "ingress_filter_lost": "rbrowser_listener_found",
            "tmp_quota": "rbrowser_traffic_limit"}
TRAFFIC_DETAILS = ("upload_rate", "upload_volume", "download_rate", "download_volume")

# Constants of the design (code, not settings)
DETACH_S = 300
LIFETIME_S = 240 * 60
START_WAIT_S = 10.0
START_STEP_S = 0.1
START_BOUND_S = 40.0           # the whole of launcher.start(): the launcher bounds itself, this is the last resort
TICK_S = 5
LISTENER_EVERY = 6             # every 6th tick
LISTENER_RECHECK_S = 30.0      # open_stream re-checks when the last check is older
HERE_THROTTLE_S = 10.0
IDLE_VISIBLE_S = 120.0         # activity_state(): "idle" = no activity for 2 minutes
SHUTDOWN_STOP_S = 5.0
RESET_FAILED_S = 10.0         # one best-effort reset-failed of a unit the registry has read
CONNECT_S = 2.0
CTL_REPLY_S = 2.0              # resize
CLIP_REPLY_S = 5.0             # clip: the unit itself waits up to 2 s for xsel and its send time-out is 5 s (A1 contract)
TYPE_REPLY_S = 65.0            # type: the unit stops after 55 s of typing; its answer comes a moment later
TYPE_MAX_CHARS = 5000          # type: the page's own limit
CLIP_LINE_MAX = 2 * 1024 * 1024
CLIP_TEXT_MAX = 262144
STREAM_LIMIT = 1 << 20
CHECK_ERRORS_END = 3           # a session whose checks raise on three ticks in a row ends as crash (fail closed)
UNKNOWN_TICKS_END = 3          # a unit that systemctl cannot show three ticks in a row ends its session
PREFLIGHT_RETRY_S = 10
PREFLIGHT_BOUND_S = 60.0
PREFLIGHT_UNIT_WAIT_S = 50.0
PROBE_JSON_MAX = 200000
MIN_H = 480
SNAP = 16
MAX_H = 1200

# 6.4 traffic budgets
UP_VOLUME = 512 * 1024 * 1024
DOWN_VOLUME = 8 * 1024 ** 3
DOWN_RATE_BPS = 40_000_000 // 8          # 40 Mbit/s averaged over 60 s
UP_WINDOW_S = 30
DOWN_WINDOW_S = 60
UP_RATE_FACTOR = 2
WARN_FRACTION = 0.8
UPLOAD_KBPS_DEFAULT = 4000
UPLOAD_KBPS_MIN = 500
UPLOAD_KBPS_MAX = 50000

# Settings that enter the preflight key (a change makes the last result invalid): the portal's own port and version, the policy and
# deny list inputs, and the limits that the unit's property list carries
KEY_SETTINGS = ("portal_port", "portal_version", "rbrowser_home_url", "rbrowser_extra_deny", "rbrowser_memory_mb", "rbrowser_max_sessions",
                "rbrowser_cpu_percent", "rbrowser_clipboard", "hidden_extra", "portal_unit")
# This list is only the quick trigger (it also bumps the generation of a run that is in flight). The full key, including what no setting
# names (host facts, the Chromium version and mtime, the systemd version, the unit sources), is compared on every create and every tick.

# R1 (decisions round 2): per-session share of the one 32 MiB tmp area
TMP_QUOTA_BYTES = 12 * 1024 * 1024
TMP_QUOTA_ENTRIES = 1500

# Directory entries a sweeper must never stop (R8 and design 3). The session pattern is built from the prefix in use.
HELPER_PREFIXES = ("portal-rbhost-", TEST_PREFIX + "host-")
_HEX12 = re.compile(r"[0-9a-f]{12}")


class StreamRefused(Exception):
    """open_stream (or a control call) refused. `reason` is one of connect_failed, socket_mismatch, listener_found,
    not_running. `marker` is the Session marker when the refusal is a security finding (socket_mismatch, listener_found),
    else None. `ended` is True when the registry ended the session because of it (reason crash). The text holds no path."""

    def __init__(self, reason: str, marker: str | None = None, ended: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.marker = marker
        self.ended = ended


# ---------------------------------------------------------------- small helpers

def _cfg(cfg, key, default=None):
    if cfg is None:
        return default
    try:
        v = cfg.get(key, default) if hasattr(cfg, "get") else getattr(cfg, key, default)
    except Exception:
        return default
    return default if v is None else v


def _cfg_int(cfg, key, default, lo, hi):
    try:
        v = int(_cfg(cfg, key, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def _truthy(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def clipboard_unit_value(setting) -> str:
    """The setting rbrowser_clipboard (both | in or to_browser | off) as the unit's RB_CLIPBOARD value."""
    s = str(setting or "").strip().lower()
    if s == "both":
        return "both"
    if s in ("in", "to_browser"):
        return "to_browser"
    return "off"


def upload_kbps(cfg) -> int:
    """The upload rate that the 30 s budget is measured against. The setting 0 means 'no kernel rule'; the portal's own
    budget is always on (design 6.4 layer 2), so 0 stands for the default and a value below 500 for 500."""
    try:
        v = int(_cfg(cfg, "rbrowser_upload_kbps", UPLOAD_KBPS_DEFAULT))
    except (TypeError, ValueError):
        v = UPLOAD_KBPS_DEFAULT
    if v <= 0:
        return UPLOAD_KBPS_DEFAULT
    return max(UPLOAD_KBPS_MIN, min(UPLOAD_KBPS_MAX, v))


def snap_size(width, height) -> tuple:
    """The unit's own clamp (560..1920 x 480..1200, multiples of 16, rounded down), so the registry holds what the screen is."""
    w = max(560, min(1920, int(width)))
    h = max(MIN_H, min(MAX_H, int(height)))
    return w - w % SNAP, h - h % SNAP


def select_launcher_kind(stage_mode, environ=None) -> str:
    """'fake' only when stage mode is on AND PORTAL_RBROWSER_FAKE=1 (design 3 'Stage mode'); otherwise 'real'. A parameter,
    not an import of config, so the module imports on a bare host."""
    env = os.environ if environ is None else environ
    return "fake" if stage_mode and str(env.get("PORTAL_RBROWSER_FAKE", "")) == "1" else "real"


WALK_DEPTH = 40


def bounded_walk(path: str, max_entries: int = TMP_QUOTA_ENTRIES, max_bytes: int = TMP_QUOTA_BYTES, max_visits: int = 6000,
                 _race_hook=None) -> tuple:
    """(bytes, entries, over) for the directory `path`: files and directories below it, symbolic links counted and never
    followed, stops as soon as a cap is passed or `max_visits` entries were looked at. A missing directory is (0, 0, False).

    The walk goes by file descriptor: every directory is opened with O_NOFOLLOW|O_DIRECTORY relative to its parent's descriptor and
    must be on the device of `path` and be the directory that was listed, so a unit that swaps a directory for a symbolic link (or
    a mount) while the walk runs cannot send root to another place. Such a swap, an unreadable directory and a tree deeper than
    WALK_DEPTH count as over (not small). `_race_hook(parent_fd, name)` is for the test: it runs right before a subdirectory is opened."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    total = entries = visits = 0
    over = False
    try:
        top = os.open(path, flags)
    except FileNotFoundError:
        return 0, 0, False
    except OSError:
        return 0, 0, True                  # a symbolic link or a file in place of the directory, or unreadable: not small
    try:
        dev = os.fstat(top).st_dev

        def walk(fd, depth):
            nonlocal total, entries, visits
            if depth > WALK_DEPTH:
                return True
            subs = []
            with os.scandir(fd) as it:
                for e in it:
                    visits += 1
                    entries += 1
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += max(st.st_size, getattr(st, "st_blocks", 0) * 512) if _stat.S_ISREG(st.st_mode) else 0
                    if _stat.S_ISDIR(st.st_mode):
                        subs.append((e.name, st))
                    if entries > max_entries or total > max_bytes or visits > max_visits:
                        return True
            for name, st in subs:
                if _race_hook is not None:
                    _race_hook(fd, name)
                try:
                    child = os.open(name, flags, dir_fd=fd)
                except FileNotFoundError:
                    continue               # removed meanwhile
                except OSError:
                    return True            # was a directory a moment ago: replaced by a link (or unreadable)
                try:
                    cst = os.fstat(child)
                    if cst.st_dev != dev or (cst.st_ino, cst.st_dev) != (st.st_ino, st.st_dev):
                        return True        # another mount, or not the directory that was listed
                    if walk(child, depth + 1):
                        return True
                finally:
                    os.close(child)
            return False

        try:
            over = walk(top, 0)
        except Exception:
            over = True
    finally:
        os.close(top)
    return total, entries, over


def parse_probe_output(text: str) -> dict:
    """The last JSON line of the probe unit's journal -> {"ok", "checks": [{"name","ok","detail"}]}. Anything else (no line, a
    line that is not the probe's object, no check) is a failed run. Details are cut to 300 characters."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if not line.startswith("{") or len(line) > PROBE_JSON_MAX:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or not isinstance(obj.get("checks"), list):
            continue
        checks = []
        for c in obj["checks"]:
            if isinstance(c, dict) and isinstance(c.get("name"), str):
                checks.append({"name": c["name"][:60], "ok": c.get("ok") is True, "detail": str(c.get("detail", ""))[:300]})
        if checks:
            return {"ok": builtins.all(c["ok"] for c in checks) and obj.get("ok") is True, "checks": checks}
    return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the probe unit printed no result"}]}


def event_detail(marker, marker_detail: str = "") -> str:
    """The detail to record with the security event of a marker: the marker's own name, except traffic_limit, whose detail is the
    budget (upload_rate, upload_volume, download_rate, download_volume). Never any text from a page."""
    if marker == "traffic_limit":
        return marker_detail if marker_detail in TRAFFIC_DETAILS else "traffic_limit"
    return marker if marker in MARKERS else ""


def _clean_path(p) -> bool:
    return isinstance(p, str) and p.startswith("/") and ".." not in p.split("/") and "\0" not in p


# ---------------------------------------------------------------- per-session bookkeeping that is not part of Session

class _Ext:
    """What the registry keeps next to a Session (never shown, never logged)."""

    def __init__(self, ident: str, pin: str, unit: str):
        self.ident = ident
        self.pin = pin
        self.unit = unit
        self.evt = asyncio.Event()          # set when a placeholder became running or was ended
        self.done = asyncio.Event()         # set when end() has finished (the stop is confirmed or the unit is on the left list)
        self.cancelled = False              # the session was ended while its start was in flight
        self.samples: collections.deque = collections.deque()
        self.clip_lock = asyncio.Lock()
        self.type_lock = asyncio.Lock()
        self.last_listener = 0.0
        self.unknown = 0
        self.last_here = -1e18
        self.errors = 0                     # consecutive ticks on which this session's checks raised


class Registry:
    """The one registry. Every dependency that touches the host is injectable, so tests start nothing.

    launcher           an object with the Launcher protocol (tests); None = built at startup()
    launch_mod         the module with prepare_host, unprepare_host, availability, seats, SystemdLauncher ... (default rbrowser_launch)
    policy_mod, bpf    rbrowser_policy / rbrowser_bpf (defaults imported lazily)
    clock              wall clock (epoch seconds; Session.started and the deadlines are epoch seconds)
    sleep              asyncio.sleep
    prefix, probe_prefix   unit prefixes (round 2 of the live test passes portal-rbtest- for both)
    cgroup_root        where the cgroup files are read (memory.current, cpu.stat, cgroup.procs)
    read_file          callable(path) -> text, raises OSError
    listener_scan      callable(pids) -> bool, True when a listener exists (default: psutil)
    tmp_scan           callable(path) -> (bytes, entries, over)
    host_facts         callable() -> {"resolvers","ifaces","gateways","gateways_scoped"}
    versions           callable() -> dict of the preflight key parts that are not settings
    run                async callable(argv, timeout) -> Ran (journalctl for the probe)
    probe_runner       async callable(spec) -> dict, replaces the whole probe unit run (tests)
    prepare_kw, unprepare_kw, launcher_kw   extra keyword arguments for prepare_host, unprepare_host and SystemdLauncher
    """

    def __init__(self, *, launcher=None, launch_mod=None, policy_mod=None, bpf=None, clock=time.time, sleep=asyncio.sleep,
                 prefix: str = UNIT_PREFIX, probe_prefix: str = PROBE_PREFIX, cgroup_root: str = "/sys/fs/cgroup", read_file=None,
                 listener_scan=None, tmp_scan=None, host_facts=None, versions=None, run=None, probe_runner=None,
                 cache_path: str | None = None, tmp_dir: str | None = None, ncpu: int | None = None, mem_total: int | None = None,
                 prepare_kw: dict | None = None, unprepare_kw: dict | None = None, launcher_kw: dict | None = None,
                 environ=None):
        self._launcher = launcher
        self._launcher_given = launcher is not None
        self._L_mod = launch_mod
        self._P_mod = policy_mod
        self._bpf_mod = bpf
        self.clock = clock
        self.sleep = sleep
        self.prefix = prefix
        self.probe_prefix = probe_prefix
        self.cgroup_root = cgroup_root
        self._read_file = read_file or self._default_read
        self._read_file_given = read_file is not None
        self._listener_scan = listener_scan or self._psutil_scan
        self._scan_given = listener_scan is not None
        self._tmp_scan = tmp_scan or bounded_walk
        self._facts_fn = host_facts
        self._versions_fn = versions
        self._run = run
        self._probe_runner = probe_runner
        self._cache_path = cache_path
        self._tmp_dir = tmp_dir
        self.ncpu = ncpu
        self.mem_total = mem_total
        self.prepare_kw = dict(prepare_kw or {})
        self.unprepare_kw = dict(unprepare_kw or {})
        self.launcher_kw = dict(launcher_kw or {})
        self.environ = environ
        self.lock = asyncio.Lock()                 # create / takeover / seat count (design 3)
        self._host_lock = asyncio.Lock()           # prepare and unprepare are one at a time (R4)
        self._sessions: dict = {}                  # sid -> Session (starting and running)
        self._by_user: dict = {}                   # user_id -> Session
        self._x: dict = {}                         # sid -> _Ext
        self._stopping: dict = {}                  # unit -> (ident, pin, launcher): a stop is in flight (the seat stays taken)
        self._left: dict = {}                      # unit -> {"ident","pin","launcher","since"}: a stop could not be confirmed
        self._probe_units: dict = {}               # unit -> ident of the probe unit that runs now (shares the tmp area)
        self._bg: set = set()
        self._boot_id = secrets.token_hex(8)
        self._ticks = 0
        self._events: collections.deque = collections.deque(maxlen=200)
        self._counters = {"started": 0, "start_failed": 0, "busy": 0, "ended": {}, "markers": {}, "unknown_stopped": 0,
                          "tmp_swept": 0, "ticks": 0, "listener_unverified": 0, "check_errors": 0}
        # host state
        self.enabled = False
        self.stage_fake = False
        self.ready = False                         # prepared (or fake) and a launcher exists
        self.unavailable_reasons: list = []
        self.prep: dict | None = None
        self.pin = ""
        self.seat_penalty = False
        self.cfg = None
        self.fake_dir: str | None = None
        self._probe_launcher = None
        self._pf_task: asyncio.Task | None = None
        self._preflight: dict | None = None
        self._pf_key: str | None = None            # the preflight key the current _preflight result was made with
        self._pf_gen = 0                           # bumped when a setting that enters the key changed: a run in flight is for old settings
        self._targets_doc = None                   # the probe targets document of the last prepare_host (part of the key)
        self._key_inputs_seen = None
        self._unit_src_cache: tuple = (None, "")
        self._facts_cache = (0.0, None)

    # ------------------------------------------------------------ lazy modules and defaults

    @property
    def L(self):
        if self._L_mod is None:
            import rbrowser_launch
            self._L_mod = rbrowser_launch
        return self._L_mod

    @property
    def P(self):
        if self._P_mod is None:
            import rbrowser_policy
            self._P_mod = rbrowser_policy
        return self._P_mod

    @property
    def bpf(self):
        if self._bpf_mod is None:
            import rbrowser_bpf
            self._bpf_mod = rbrowser_bpf
        return self._bpf_mod

    @staticmethod
    def _default_read(path: str) -> str:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def _psutil_scan(self, pids) -> bool:
        import psutil
        looked = 0
        for pid in pids:
            try:
                conns = psutil.Process(pid).net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue                    # the process ended between the two reads: a renderer comes and goes
            looked += 1
            for c in conns:
                port = c.laddr.port if c.laddr else 0
                if c.type == socket.SOCK_STREAM and c.status == "LISTEN":
                    return True
                if c.type == socket.SOCK_DGRAM and 0 < port < 32768:
                    return True
        if not looked:
            raise LookupError("no process of the unit could be looked at")      # AccessDenied raises by itself: cannot tell
        return False

    @property
    def launcher(self):
        return self._launcher

    def _spawn(self, coro):
        t = asyncio.ensure_future(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)
        return t

    def _event(self, kind: str, **kw):
        self._events.append(dict(kind=kind, **kw))

    def _count_end(self, reason: str, marker):
        e = self._counters["ended"]
        e[reason] = e.get(reason, 0) + 1
        if marker:
            m = self._counters["markers"]
            m[marker] = m.get(marker, 0) + 1

    def remember(self, cfg):
        if cfg is None:
            return
        self.cfg = cfg
        inputs = tuple(json.dumps(_cfg(cfg, k, None), sort_keys=True, default=str) for k in KEY_SETTINGS)
        seen, self._key_inputs_seen = self._key_inputs_seen, inputs
        if seen is not None and inputs != seen:
            self._recheck_preflight(cfg)
        else:
            self._recheck_preflight(cfg, drift=True)     # anything else that enters the key (host facts, the Chromium version): the full key

    def _recheck_preflight(self, cfg, drift: bool = False) -> None:
        """A setting that enters the preflight key changed (or host_prepare ran): a result made with another key is not valid for the
        new one. It is dropped (create refuses until a run passes) and a run is scheduled.

        `drift` is the comparison made on every create and tick: the whole key against the one the result was made with. Nothing to do
        when there is no result (a run in flight judges its own key when it ends, and the next call compares it), and a key that cannot
        be computed leaves the result alone, so a broken key cannot start a probe unit on every tick."""
        if self.stage_fake or not self.ready:
            return
        running = self._pf_task is not None and not self._pf_task.done()
        if self._preflight is None and not running:
            return                          # nothing was ever judged: startup() or preflight() makes the first run
        if drift and self._preflight is None:
            return
        if self._preflight is not None:
            try:
                key = self.preflight_key(cfg)
            except Exception:
                key = None
            if drift and key is None:
                return
            if key is not None and key == self._pf_key:
                return
        self._pf_gen += 1                   # a run in flight was started under the old settings: its answer is not kept
        self._preflight = None
        self._schedule_preflight(False)

    def _schedule_preflight(self, force: bool) -> None:
        if self._pf_task is not None and not self._pf_task.done():
            return                          # a run is in progress (it notices the generation change and runs again)
        try:
            self._pf_task = self._spawn(self._preflight_main(force))
        except RuntimeError:                # no event loop: the next preflight() call runs it
            pass

    def _unit_re(self):
        return re.compile(re.escape(self.prefix) + r"[0-9a-f]{12}\.service")

    def _probe_re(self):
        return re.compile(re.escape(self.probe_prefix) + r"[0-9a-f]{12}\.service")

    def _unit_name(self, ident: str) -> str:
        return f"{self.prefix}{ident}.service"

    # ------------------------------------------------------------ host facts, policy, spec

    def host_facts(self) -> dict:
        t, v = self._facts_cache
        if v is not None and self.clock() - t < 60:
            return v
        if self._facts_fn:
            v = self._facts_fn()
        else:
            P, L = self.P, self.L
            res = []
            for f in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
                res += P.parse_resolv_conf(L._read(f))
            route = L._read("/proc/net/route")
            gws = P.parse_proc_net_route(route) + P.parse_proc_net_ipv6_route(L._read("/proc/net/ipv6_route"))
            scoped = P.parse_proc_net_route(route) + P.parse_proc_net_ipv6_route_scoped(L._read("/proc/net/ipv6_route"))
            try:
                import psutil
                ifaces = P.iface_from_psutil(psutil.net_if_addrs())
            except Exception:
                ifaces = []
            v = {"resolvers": list(dict.fromkeys(res)), "gateways": list(dict.fromkeys(gws)),
                 "gateways_scoped": list(dict.fromkeys(scoped)), "ifaces": ifaces}
        self._facts_cache = (self.clock(), v)
        return v

    def _extra_deny(self, cfg) -> list:
        try:
            return list(self.P.validate_extra_deny(_cfg(cfg, "rbrowser_extra_deny", [])))
        except Exception:
            return []

    def deny(self, cfg) -> list:
        f = self.host_facts()
        return self.P.deny_list(f["resolvers"], f["ifaces"], f["gateways"], self._extra_deny(cfg))

    def home_url(self, cfg) -> str:
        try:
            return self.P.validate_home_url(_cfg(cfg, "rbrowser_home_url", self.P.DEFAULT_HOME_URL))
        except Exception:
            return self.P.DEFAULT_HOME_URL

    def policy(self, cfg) -> dict:
        f = self.host_facts()
        return self.P.build_policy(self.home_url(cfg), self.P.literal_hosts(f["resolvers"], f["ifaces"], f["gateways"]))

    def hidden_extra(self, cfg) -> list:
        extra = [str(p) for p in (_cfg(cfg, "hidden_extra", []) or []) if isinstance(p, str)]
        here = os.path.dirname(os.path.abspath(__file__))
        return list(dict.fromkeys([here] + extra))

    def _ncpu(self) -> int:
        return self.ncpu or os.cpu_count() or 1

    def _mem_total(self) -> int:
        if self.mem_total is not None:
            return self.mem_total
        return self.L.parse_meminfo(self.L._read("/proc/meminfo"))

    def seats(self, cfg=None) -> dict:
        cfg = cfg if cfg is not None else self.cfg
        s = dict(self.L.seats(cfg, self._ncpu(), self._mem_total()))
        if self.seat_penalty and s["max"] > 1:       # the slice could not be configured (G8): halve the seats
            s["max"] = max(1, s["max"] // 2)
        return s

    def spec(self, ident: str, width: int, height: int, cfg, theme: tuple = (None, None)) -> LaunchSpec:
        chromium = ""
        try:
            chromium = (self.L.availability(stage_mode=False).get("paths") or {}).get("chromium", "")
        except Exception:
            chromium = ""
        return LaunchSpec(ident=ident, width=width, height=height, clipboard=clipboard_unit_value(_cfg(cfg, "rbrowser_clipboard", "both")),
                          home_url=self.home_url(cfg), chromium=chromium or "", memory_mb=_cfg_int(cfg, "rbrowser_memory_mb", 2048, 1024, 4096),
                          cpu_percent=self.seats(cfg)["cpu_percent"], deny=self.deny(cfg), hidden_extra=self.hidden_extra(cfg),
                          portal_unit=str(_cfg(cfg, "portal_unit", "") or ""), theme_color=theme[0], theme_mode=theme[1])

    # ------------------------------------------------------------ availability

    def availability(self, cfg=None) -> dict:
        """`cfg` is used only while the registry has none of its own (the feature was never started in this process), so
        that stage mode is honoured by the admin card before the first switch-on."""
        if self.stage_fake:
            return {"available": True, "missing": [], "reasons": [], "chromium_version": "", "chromium_age_days": None,
                    "kernel_upload_limit": False, "paths": {"chromium": ""}, "checking": False}
        stage = _truthy(_cfg(self.cfg if self.cfg is not None else cfg, "stage_mode", False))
        av = dict(self.L.availability(stage_mode=stage))
        av["reasons"] = list(av.get("reasons", []))
        av["missing"] = list(av.get("missing", []))
        if self.prep is not None:
            av["kernel_upload_limit"] = bool(self.prep.get("upload_rule"))
            if self.prep.get("upload_reason"):
                av["upload_reason"] = self.prep["upload_reason"]
            if not self.prep.get("ok"):
                av["available"] = False
                av["reasons"] += [str(r) for r in self.prep.get("reasons", [])] or ["the host could not be prepared"]
        elif self.enabled and av.get("available"):
            av["available"] = False         # enabled, but startup() has not prepared the host (yet)
            av["reasons"] += self.unavailable_reasons or ["the host is not prepared"]
        pf = self._preflight
        if pf is not None and not pf.get("ok"):
            av["available"] = False
            bad = [c["name"] for c in pf.get("checks", []) if not c.get("ok")]
            av["reasons"].append("preflight failed: " + ", ".join(bad or ["run"]))
        av["checking"] = self.checking()
        return av

    def checking(self) -> bool:
        return self._pf_task is not None and not self._pf_task.done()

    def last_preflight(self) -> dict | None:
        return self._preflight

    # ------------------------------------------------------------ lookups

    def get(self, sid):
        s = self._sessions.get(sid)
        return s if s is not None and s.state != "ended" else None

    def for_user(self, user_id):
        s = self._by_user.get(user_id)
        return s if s is not None and s.state != "ended" else None

    def all(self) -> list:
        return [s for s in self._sessions.values() if s.state != "ended"]

    def find_prefix(self, prefix: str):
        """The session whose sid starts with `prefix` (at least 6 characters, exactly one match), else None."""
        if not isinstance(prefix, str) or len(prefix) < 6:
            return None
        hits = [s for s in self.all() if s.sid.startswith(prefix)]
        return hits[0] if len(hits) == 1 else None

    def boot_id(self) -> str:
        return self._boot_id

    def take_events(self) -> list:
        """The registry's events, drained (lane B calls this on every tick, also with no session). The ONLY place a security event is taken
        from; the tick results and StreamRefused serve closes and audit and must not raise the event a second time.
          {"kind": "marker", "marker": <MARKERS>, "detail": str, "event": <secevents name>, "user_id": int, "sid_prefix": str}
          {"kind": "preflight_failed", "event": "rbrowser_preflight_failed", "checks": [names of the failed checks]}
          {"kind": "unknown_unit_stopped"}   {"kind": "unit_left_running", "unit": <portal-rb-... name>}
        No text from a page ever appears."""
        out = list(self._events)
        self._events.clear()
        return out

    def counters(self) -> dict:
        c = dict(self._counters)
        c["ended"] = dict(c["ended"])
        c["markers"] = dict(c["markers"])
        c.update(sessions=len(self.all()), stopping=len(self._stopping), left=len(self._left), ticks=self._ticks,
                 theme_fallbacks=int(getattr(self._launcher, "theme_fallbacks", 0) or 0))
        return c

    def left_units(self) -> list:
        """Units whose stop could not be confirmed (they hold a seat, are retried every tick and keep their BPF pin)."""
        return sorted(self._left)

    def deadlines(self, session: Session, cfg=None) -> dict:
        """{"idle_deadline", "max_deadline"} as epoch seconds (what the page reads)."""
        cfg = cfg if cfg is not None else self.cfg
        idle = _cfg_int(cfg, "rbrowser_idle_minutes", 15, 5, 120) * 60
        return {"idle_deadline": session.last_activity + idle, "max_deadline": session.started + LIFETIME_S}

    def activity_state(self, session: Session) -> str:
        """'active' or 'idle' (no activity for 2 minutes): all the admin list may show."""
        return "idle" if self.clock() - session.last_activity >= IDLE_VISIBLE_S else "active"

    def mark_attached(self, session: Session, viewer) -> None:
        session.viewer = viewer
        session.detached_since = None

    def mark_detached(self, session: Session, viewer=None) -> None:
        """The viewer is gone (only when it is still the session's viewer, so a replaced socket's late close does nothing)."""
        if viewer is not None and session.viewer is not viewer:
            return
        session.viewer = None
        if session.detached_since is None:
            session.detached_since = self.clock()

    def note_activity(self, session: Session, here: bool = False) -> bool:
        """An RFB message of type 4 or 5 (here=False), or the control frame {"op":"here"} (here=True: accepted at most once
        per 10 s). Returns whether it counted."""
        if session.state != "running":
            return False
        now = self.clock()
        if here:
            ext = self._x.get(session.sid)
            if ext is not None:
                if now - ext.last_here < HERE_THROTTLE_S:
                    return False
                ext.last_here = now
        session.last_activity = now
        return True

    # ------------------------------------------------------------ stopping units (a seat is free only when the unit is gone)

    async def _stop_unit(self, unit: str, ident: str, pin: str, launcher=None) -> bool:
        """Stop `unit` through its launcher and CONFIRM it. True: gone. False: the unit may still run; it is then on
        self._left (the seat stays taken, the sweeper retries it, its pin stays in prune_stale's keep list)."""
        launcher = launcher or self._launcher
        self._stopping[unit] = (ident, pin, launcher)
        try:
            await launcher.stop(unit)
        except asyncio.CancelledError:
            self._left[unit] = {"ident": ident, "pin": pin, "launcher": launcher, "since": self.clock()}
            self._stopping.pop(unit, None)
            raise
        except BaseException as e:           # UnitLeftRunning, and anything else: unknown is not stopped
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            if unit not in self._left:
                self._left[unit] = {"ident": ident, "pin": pin, "launcher": launcher, "since": self.clock()}
                self._event("unit_left_running", unit=unit)
            self._stopping.pop(unit, None)
            return False
        self._stopping.pop(unit, None)
        self._left.pop(unit, None)
        await self._reset_failed(launcher, unit)      # a unit that ended in error stays loaded as `failed` until it is reset
        return True

    async def _reset_failed(self, launcher, unit: str) -> None:
        """Best-effort `reset-failed` of a unit the registry has read (or stopped). Never raises (cancellation excepted), bounded by
        RESET_FAILED_S; a launcher without reset_failed is left alone."""
        fn = getattr(launcher, "reset_failed", None)
        if fn is None:
            return
        try:
            res = fn(unit)
            if inspect.isawaitable(res):
                await asyncio.wait_for(res, RESET_FAILED_S)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _seats_taken(self) -> int:
        return len(self._sessions) + len(self._stopping) + len(self._left)

    def _live_idents(self) -> set:
        live = {x.ident for x in self._x.values()}
        live |= {v[0] for v in self._stopping.values()} | {v["ident"] for v in self._left.values()} | set(self._probe_units.values())
        return {i for i in live if i}

    def _known_units(self) -> set:
        known = {s.unit for s in self._sessions.values()} | set(self._stopping) | set(self._left) | set(self._probe_units)
        return known

    # ------------------------------------------------------------ create

    def _free_in_minutes(self, cfg) -> int:
        idle = _cfg_int(cfg, "rbrowser_idle_minutes", 15, 5, 120) * 60
        now = self.clock()
        waits = [max(0.0, s.last_activity + idle - now) for s in self._sessions.values() if s.state == "running"]
        if not waits:
            return 5
        n = int(-(-min(waits) // 60))
        return max(5, -(-n // 5) * 5)

    def _preflight_gate(self, cfg, compare: bool = True) -> None:
        """T5: Refused 503 unless a preflight that passed under the CURRENT key is in place. Synchronous (no await), so inside the
        registry lock it is evaluated and acted on without a gap. A key that cannot be computed refuses and starts no probe; a key
        that differs from the one of the result drops the result and schedules one run (the next calls see the run in progress)."""
        if compare and not self.stage_fake and self.ready and self._preflight is not None and not self.checking():
            try:
                key = self.preflight_key(cfg)
            except Exception:
                raise Refused(503, {"error": "unavailable"}) from None
            if key != self._pf_key:
                self._pf_gen += 1
                self._preflight = None
                self._schedule_preflight(False)
        if self.checking():
            raise Refused(503, {"retry_after": PREFLIGHT_RETRY_S})
        if not self.ready or self._launcher is None:
            raise Refused(503, {"error": "unavailable"})
        if self._preflight is None or not self._preflight.get("ok"):      # no start before a preflight has passed
            raise Refused(503, {"error": "unavailable"})

    def _theme(self, theme) -> tuple:
        """The member's theme as a validated (colour or None, mode or None) pair. Anything that is not a pair of valid values is
        the neutral default; it never fails a start."""
        try:
            import rbrowser_policy       # the pure validator itself, never an injected stand-in: a theme is never trusted unchecked
            color, mode = theme
            return rbrowser_policy.normalise_theme(color, mode)
        except Exception:
            return (None, None)

    async def create(self, user_id, token_id, width, height, cfg, takeover=False, theme=None) -> Session:
        """`theme` is None or (colour, mode) as the page sent them; the registry validates them again (rbrowser_policy.normalise_theme)
        and hands the validated pair to the launcher for this session only. It is not part of the preflight key."""
        self.remember(cfg)
        theme = self._theme(theme)
        self._preflight_gate(cfg, compare=False)          # the early answer; the one that counts is made again under the lock
        try:
            w, h = snap_size(width, height)
        except (TypeError, ValueError, OverflowError):
            raise Refused(400, {"error": "size"}) from None
        for _attempt in range(3):
            wait_for = takeover_old = None
            async with self.lock:
                old = self._by_user.get(user_id)
                if old is not None and old.state in ("starting", "running"):
                    if old.token_id == token_id:
                        if old.state == "running":
                            return old
                        wait_for = old
                    elif not takeover:
                        raise Refused(409, {"elsewhere": True})
                    else:
                        takeover_old = old
                if wait_for is None:
                    # T5: the gate is evaluated on EVERY pass, takeover included, right before anything is started or ended: a
                    # takeover that waited for the old unit's stop (outside the lock) meets a drifted key here, not at its start.
                    self._preflight_gate(cfg)
                if wait_for is None and takeover_old is None:
                    if self._seats_taken() >= self.seats(cfg)["max"]:
                        self._counters["busy"] += 1
                        raise Refused(409, {"busy": True, "free_in_minutes": self._free_in_minutes(cfg)})
                    ident = secrets.token_hex(6)       # made under the lock: the sweeper must see the unit's tmp directory as live
                    now = self.clock()
                    sess = Session(sid=secrets.token_urlsafe(16), unit=self._unit_name(ident), user_id=user_id, token_id=token_id,
                                   state="starting", runtime_dir="", expect_uid=-1, expect_cgroup="", width=w, height=h, started=now,
                                   last_activity=now, detached_since=now, ident=ident, ingress_pin=self.pin,
                                   clipboard=clipboard_unit_value(_cfg(cfg, "rbrowser_clipboard", "both")),
                                   theme_color=theme[0], theme_mode=theme[1])
                    ext = _Ext(ident, self.pin, sess.unit)
                    self._sessions[sess.sid] = sess
                    self._by_user[user_id] = sess
                    self._x[sess.sid] = ext
            if wait_for is not None:                   # a second create by the same member awaits the same placeholder
                ext = self._x.get(wait_for.sid)
                if ext is not None:
                    await ext.evt.wait()
                if wait_for.state == "running":
                    return wait_for
                raise Refused(503, {"error": "start_failed"})
            if takeover_old is not None:               # ended (and its unit confirmed gone) outside the lock, then try again
                await self.end(takeover_old, "replaced")
                continue
            return await self._start(sess, ext, cfg)
        raise Refused(409, {"busy": True, "free_in_minutes": self._free_in_minutes(cfg)})

    async def _start(self, sess: Session, ext: _Ext, cfg) -> Session:
        launcher = self._launcher
        res = None
        try:
            spec = self.spec(sess.ident, sess.width, sess.height, cfg, (sess.theme_color, sess.theme_mode))
            res = await asyncio.wait_for(launcher.start(spec), START_BOUND_S)
            if ext.cancelled:
                raise Refused(503, {"error": "ended"})
            sess.runtime_dir, sess.expect_uid, sess.expect_cgroup = res.runtime_dir, res.expect_uid, res.expect_cgroup
            if getattr(res, "ingress_pin", ""):
                sess.ingress_pin = res.ingress_pin
                ext.pin = res.ingress_pin
            await self._wait_sockets(sess)
            if ext.cancelled:
                raise Refused(503, {"error": "ended"})
            verdict = await self._listener_check(sess, ext)
            if verdict == "found":
                sess.marker = "listener_found"
                self._event("marker", marker="listener_found", detail="listener_found", event=EVENT_OF["listener_found"],
                            user_id=sess.user_id, sid_prefix=sess.sid[:6])
                raise Refused(503, {"error": "start_failed"})
            if verdict != "clean":          # cannot tell: a unit that cannot be checked does not start
                raise Refused(503, {"error": "start_failed"})
            # The session may have been ended while the listener check was parked in a thread. This is the LAST statement of the
            # try: no await sits between it and `state = "running"` below, and a raise here reaches _start_failed (which sets ext.done).
            if ext.cancelled:
                raise Refused(503, {"error": "ended"})
        except BaseException as e:
            await self._start_failed(sess, ext, e)
            if isinstance(e, Refused):
                raise
            if isinstance(e, asyncio.CancelledError):
                raise
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            raise Refused(503, {"error": "start_failed"}) from None
        now = self.clock()
        sess.state = "running"
        sess.started = sess.last_activity = now
        sess.detached_since = now
        self._counters["started"] += 1
        ext.evt.set()
        return sess

    async def _start_failed(self, sess: Session, ext: _Ext, exc: BaseException):
        """A placeholder that did not become a session: drop it, stop its unit (confirmed), wake the waiters."""
        unit = sess.unit
        was_ended = sess.state == "ended"
        if not was_ended:
            sess.state = "ended"
            sess.end_reason = "start_failed"
            sess.ended_at = self.clock()
            self._counters["start_failed"] += 1
            self._count_end("start_failed", sess.marker)
            self._stopping[unit] = (ext.ident, ext.pin, self._launcher)       # hold the seat until the unit is confirmed gone
            self._sessions.pop(sess.sid, None)
            if self._by_user.get(sess.user_id) is sess:
                self._by_user.pop(sess.user_id, None)
        ext.evt.set()
        try:
            already_left = unit in self._left or (isinstance(exc, UnitLeftRunning) and exc.unit == unit)
            if isinstance(exc, UnitLeftRunning) and unit not in self._left:
                self._left[unit] = {"ident": ext.ident, "pin": ext.pin, "launcher": self._launcher, "since": self.clock()}
                self._event("unit_left_running", unit=unit)
            if already_left:
                self._stopping.pop(unit, None)
            elif isinstance(exc, asyncio.CancelledError):
                # the request task was cancelled: the stop must not be lost with it
                self._spawn(self._stop_unit(unit, ext.ident, ext.pin))
            else:
                await self._stop_unit(unit, ext.ident, ext.pin)      # a cancel in here puts the unit on _left (see _stop_unit)
        finally:
            self._x.pop(sess.sid, None)          # always: end() waits on done, and a stale _x entry keeps the tmp directory "live"
            ext.done.set()

    async def _wait_sockets(self, sess: Session):
        n = int(START_WAIT_S / START_STEP_S)
        for _ in range(n):
            ok = True
            for name in ("vnc.sock", "ctl.sock"):
                try:
                    if not _stat.S_ISSOCK(os.lstat(os.path.join(sess.runtime_dir, name)).st_mode):
                        ok = False
                except OSError:
                    ok = False
            if ok:
                return
            await self.sleep(START_STEP_S)
        raise LaunchError("the unit's sockets did not appear in time")

    # ------------------------------------------------------------ ending

    async def end(self, session: Session, reason: str, marker: str | None = None, detail: str = "") -> None:
        """Idempotent. `marker` is one of MARKERS (a security finding) and `detail` its sub-kind (traffic_limit)."""
        await self._end(session, reason, marker, detail, stop_inline=True)

    async def _end(self, session: Session, reason: str, marker, detail: str, *, stop_inline: bool) -> None:
        ext = self._x.get(session.sid)
        if session.state == "ended":
            if ext is not None and stop_inline:
                await ext.done.wait()
            return
        if reason not in END_REASONS:
            reason = "crash"
        if marker not in MARKERS:
            marker = None
        was = session.state
        session.state = "ended"
        session.end_reason = reason
        session.marker = marker
        session.marker_detail = detail if (marker == "traffic_limit" and detail in TRAFFIC_DETAILS) else ""
        session.ended_at = self.clock()
        self._count_end(reason, marker)
        if marker:
            self._event("marker", marker=marker, detail=event_detail(marker, session.marker_detail), event=EVENT_OF[marker],
                        user_id=session.user_id, sid_prefix=session.sid[:6])
        self._sessions.pop(session.sid, None)
        if self._by_user.get(session.user_id) is session:
            self._by_user.pop(session.user_id, None)
        viewer = session.viewer
        session.viewer = None
        if ext is None:
            return
        ext.cancelled = True
        # the seat stays taken until the unit is confirmed gone
        self._stopping[session.unit] = (ext.ident, ext.pin, self._launcher)
        ext.evt.set()
        if viewer is not None:
            if stop_inline:
                try:
                    await self._close_viewer(viewer, reason)
                except asyncio.CancelledError:
                    # the caller was aborted (a viewer replaced by a newer window) before the unit was stopped: nobody else would
                    # stop it or finish the books, and the seat would stay taken. The stop goes on in the registry's own task.
                    self._spawn(self._finish_stop(session))
                    raise
            else:
                self._spawn(self._close_viewer(viewer, reason))        # the tick must not wait for a slow socket
        if was == "starting":
            # _start() sees `cancelled` after launcher.start() returns, stops the unit and finishes the books
            if stop_inline:
                await ext.done.wait()
            return
        if stop_inline:
            await self._finish_stop(session)

    @staticmethod
    async def _close_viewer(viewer, reason: str):
        try:
            await asyncio.wait_for(viewer.close(code=4013, message=reason.encode()), 2.0)
        except Exception:
            pass

    async def _finish_stop(self, session: Session):
        ext = self._x.get(session.sid)
        if ext is None:
            return
        try:
            await self._stop_unit(session.unit, ext.ident, ext.pin)
        finally:
            self._x.pop(session.sid, None)
            ext.done.set()
        log.info("rbrowser session ended: user %s sid %s unit %s reason %s marker %s seconds %d stream_in %d stream_out %d net_in %d net_out %d",
                 session.user_id, session.sid[:6], session.unit, session.end_reason, session.marker or "-",
                 int((session.ended_at or 0) - session.started), session.bytes_in, session.bytes_out, session.net_in, session.net_out)

    async def on_revocation(self, user_id, spared) -> None:
        """The member's sign-in (or all of them) ended: every session whose token is not spared ends at once (signed_out)."""
        s = self._by_user.get(user_id)
        if s is None:
            return
        try:
            keep = bool(spared(s.token_id))
        except Exception:
            keep = False
        if not keep:
            await self.end(s, "signed_out")

    # ------------------------------------------------------------ peer-verified connections

    async def _connect_checked(self, session: Session, sock_name: str, *, end_on_connect_failure: bool, limit: int = STREAM_LIMIT):
        """Connect to a socket of the unit's runtime directory and check who is on the other end (design 5.3). The path is
        built here; lstat must say socket (not a symbolic link); the peer's uid and cgroup must be the session's."""
        if session.state != "running":
            raise StreamRefused("not_running")
        path = os.path.join(session.runtime_dir, sock_name)
        try:
            st = os.lstat(path)
        except OSError:
            await self._connect_failed(session, end_on_connect_failure)
            raise StreamRefused("connect_failed", ended=end_on_connect_failure) from None
        if not _stat.S_ISSOCK(st.st_mode):
            await self._mismatch(session)
            raise StreamRefused("socket_mismatch", "socket_mismatch", True)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(path, limit=limit), CONNECT_S)
        except (OSError, asyncio.TimeoutError):
            await self._connect_failed(session, end_on_connect_failure)
            raise StreamRefused("connect_failed", ended=end_on_connect_failure) from None
        ok = False
        try:
            sock = writer.get_extra_info("socket")
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", creds)
            ok = uid == session.expect_uid and bool(session.expect_cgroup) and self._launcher.cgroup_of(pid) == session.expect_cgroup
        except Exception:
            ok = False           # unknown is a mismatch
        if not ok:
            try:
                writer.close()
            except Exception:
                pass
            await self._mismatch(session)
            raise StreamRefused("socket_mismatch", "socket_mismatch", True)
        return reader, writer

    async def _connect_failed(self, session: Session, end_it: bool):
        if end_it:
            await self.end(session, "crash")       # a dead x11vnc must not hold a seat until the idle timeout

    async def _mismatch(self, session: Session):
        await self.end(session, "crash", "socket_mismatch")

    async def open_stream(self, session: Session):
        """(StreamReader, StreamWriter) for the unit's VNC socket, peer-verified (design 5.3). Raises StreamRefused."""
        ext = self._x.get(session.sid)
        if ext is not None and session.state == "running" and self.clock() - ext.last_listener > LISTENER_RECHECK_S:
            verdict = await self._listener_check(session, ext)
            if verdict == "found":
                await self.end(session, "crash", "listener_found")
                raise StreamRefused("listener_found", "listener_found", True)
            if verdict != "clean":              # cannot tell: the session ends (no marker: nothing was found)
                await self.end(session, "crash")
                raise StreamRefused("connect_failed", ended=True)
        return await self._connect_checked(session, "vnc.sock", end_on_connect_failure=True)

    async def _listener_check(self, session: Session, ext: _Ext) -> str:
        """The unit's pids (cgroup.procs): any TCP socket in LISTEN or UDP bound below 32768 is a finding. 'found', 'clean' or
        'unknown'. A running unit always has pids, so an unreadable or empty cgroup.procs, a bad cgroup path and a scan that fails are
        'unknown', never 'clean': the caller ends the session (or refuses the start)."""
        ext.last_listener = self.clock()
        cg = session.expect_cgroup
        verdict = "unknown"
        if _clean_path(cg):
            try:
                text = await asyncio.to_thread(self._read_file, f"{self.cgroup_root}{os.path.normpath(cg)}/cgroup.procs")
                pids = [int(x) for x in text.split() if x.isdigit()]
            except (OSError, ValueError):
                pids = []
            if pids:
                try:
                    verdict = "found" if await asyncio.to_thread(self._listener_scan, pids) else "clean"
                except Exception:
                    verdict = "unknown"
        if verdict == "unknown":
            self._counters["listener_unverified"] += 1
            log.warning("rbrowser listener check could not be made: user %s sid %s", session.user_id, session.sid[:6])
        return verdict

    # ------------------------------------------------------------ control socket: resize and clip (never log what they carry)

    async def _ctl(self, session: Session, request: dict, reply_s: float, limit: int):
        """One request line to ctl.sock, one reply line back. Returns the parsed object or None (any failure)."""
        reader, writer = await self._connect_checked(session, "ctl.sock", end_on_connect_failure=False, limit=CLIP_LINE_MAX + 4096)
        try:
            writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            await asyncio.wait_for(writer.drain(), CONNECT_S)
            try:
                line = await asyncio.wait_for(reader.readline(), reply_s)
            except (ValueError, asyncio.LimitOverrunError):
                return None
            if not line.endswith(b"\n") or len(line) > limit:
                return None
            try:
                obj = json.loads(line)
            except ValueError:
                return None
            return obj if isinstance(obj, dict) else None
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def resize(self, session: Session, width: int, height: int) -> bool:
        try:
            w, h = snap_size(width, height)
        except (TypeError, ValueError, OverflowError):
            return False
        try:
            obj = await self._ctl(session, {"op": "resize", "w": w, "h": h}, CTL_REPLY_S, 4096)
        except StreamRefused:
            return False
        if obj is not None and obj.get("ok") is True:
            session.width, session.height = w, h
            return True
        return False

    async def clip(self, session: Session) -> dict:
        """The unit's CLIPBOARD selection as {"ok": bool, "text": str, "truncated": bool, "why": str}. ok False is a refusal or
        a failure and is never an empty clipboard (that is ok True with text ""). why (only when ok is False): refused (the
        unit's clipboard setting is not both), busy (another clip is running for the session), unreachable, reply. The text
        is page-controlled: untrusted, never logged, never stored here."""
        bad = {"ok": False, "text": "", "truncated": False}
        if session.state != "running" or session.clipboard != "both":
            return dict(bad, why="refused")
        ext = self._x.get(session.sid)
        if ext is None:
            return dict(bad, why="unreachable")
        if ext.clip_lock.locked():
            return dict(bad, why="busy")
        async with ext.clip_lock:
            try:
                obj = await self._ctl(session, {"op": "clip"}, CLIP_REPLY_S, CLIP_LINE_MAX)
            except StreamRefused:
                return dict(bad, why="unreachable")
        if obj is None:
            return dict(bad, why="reply")
        if obj.get("ok") is not True:
            return dict(bad, why="failed" if obj.get("ok") is False else "reply")
        text, trunc = obj.get("text"), obj.get("truncated")
        if not isinstance(text, str) or not isinstance(trunc, bool):
            return dict(bad, why="reply")
        try:
            if len(text.encode("utf-8")) > CLIP_TEXT_MAX:
                return dict(bad, why="reply")
        except UnicodeEncodeError:
            return dict(bad, why="reply")
        return {"ok": True, "text": text, "truncated": trunc}

    async def type_text(self, session: Session, text: str) -> dict:
        """Types `text` in the unit through its own X connection (ctl.sock `type`). Returns {"ok", "typed", "skipped", "complete",
        "fallback", "why", "warn", "map_changes"}: typed is how many characters the unit typed; fallback is True only when nothing was typed and nothing
        can have been (an older unit that does not know the request, no typing keys, the unit not reachable), so the page may send the
        same text as key events; with typed above 0 or an unknown outcome it never is (the text would be typed twice). why: refused, busy,
        unsupported, unavailable, unreachable, reply, or the unit's own (budget, stopping, failed). The text is page-controlled:
        untrusted, never logged, never stored here."""
        bad = {"ok": False, "typed": 0, "skipped": 0, "complete": False, "fallback": False, "warn": "", "map_changes": 0}
        if not isinstance(text, str) or len(text) > TYPE_MAX_CHARS:
            return dict(bad, why="refused")
        if session.state != "running" or session.clipboard == "off":
            return dict(bad, why="refused")
        ext = self._x.get(session.sid)
        if ext is None:
            return dict(bad, why="unreachable", fallback=True)
        if ext.type_lock.locked():
            return dict(bad, why="busy")
        async with ext.type_lock:
            try:
                obj = await self._ctl(session, {"op": "type", "text": text}, TYPE_REPLY_S, 4096)
            except StreamRefused:
                return dict(bad, why="unreachable", fallback=True)
        if obj is None:
            return dict(bad, why="reply")
        typed, skipped, complete = obj.get("typed"), obj.get("skipped"), obj.get("complete")
        if (isinstance(typed, bool) or not isinstance(typed, int) or isinstance(skipped, bool) or not isinstance(skipped, int)
                or not isinstance(complete, bool) or not 0 <= typed <= TYPE_MAX_CHARS or not 0 <= skipped <= TYPE_MAX_CHARS):
            # an older unit answers an unknown request with {"ok": false} and nothing else: nothing was typed
            return dict(bad, why="unsupported", fallback=obj.get("ok") is False and "typed" not in obj)
        why = obj.get("why")
        why = why if isinstance(why, str) and len(why) <= 20 else ""
        warn = obj.get("warn")
        warn = warn if isinstance(warn, str) and len(warn) <= 20 else ""
        mc = obj.get("map_changes")
        out = {"ok": obj.get("ok") is True and complete, "typed": typed, "skipped": skipped, "complete": complete, "fallback": False,
               "why": why, "warn": warn, "map_changes": mc if isinstance(mc, int) and not isinstance(mc, bool) and 0 <= mc <= 100000 else 0}
        if not out["ok"] and typed == 0 and why in ("unavailable", "refused"):
            out["fallback"] = why == "unavailable"
        return out

    # ------------------------------------------------------------ usage

    async def usage(self, session: Session) -> dict:
        """{"memory_mb", "cpu_seconds", "net_in", "net_out"}: memory and CPU from the unit's cgroup files, the net counters (bytes)
        from the last tick."""
        mem = cpu = 0.0
        cg = session.expect_cgroup
        if _clean_path(cg):
            base = f"{self.cgroup_root}{os.path.normpath(cg)}"
            try:
                mem = int((await asyncio.to_thread(self._read_file, base + "/memory.current")).strip()) / (1024 * 1024)
            except (OSError, ValueError):
                mem = 0.0
            try:
                for line in (await asyncio.to_thread(self._read_file, base + "/cpu.stat")).splitlines():
                    k, _, v = line.partition(" ")
                    if k == "usage_usec":
                        cpu = int(v) / 1e6
            except (OSError, ValueError):
                cpu = 0.0
        return {"memory_mb": round(mem, 1), "cpu_seconds": round(cpu, 1), "net_in": session.net_in, "net_out": session.net_out}

    # ------------------------------------------------------------ the sweeper

    @staticmethod
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    def _window_base(self, samples, now, window):
        base = None
        for smp in samples:
            if smp[0] <= now - window:
                base = smp
            else:
                break
        return base

    def _traffic_verdict(self, session: Session, ext: _Ext, cfg, now: float):
        """Design 6.4 layer 2. Returns a detail from TRAFFIC_DETAILS or None; sets session.net_warning."""
        samples = ext.samples
        samples.append((now, session.net_in, session.net_out))
        while len(samples) > 2 and samples[1][0] <= now - (DOWN_WINDOW_S + 2 * TICK_S + 30):
            samples.popleft()
        session.net_warning = session.net_in >= WARN_FRACTION * DOWN_VOLUME or session.net_out >= WARN_FRACTION * UP_VOLUME
        if session.net_out > UP_VOLUME:
            return "upload_volume"
        if session.net_in > DOWN_VOLUME:
            return "download_volume"
        up_limit = UP_RATE_FACTOR * upload_kbps(cfg) * 125          # bytes per second
        b = self._window_base(samples, now, UP_WINDOW_S)
        if b is not None and now > b[0] and max(0, session.net_out - b[2]) / (now - b[0]) > up_limit:
            return "upload_rate"
        b = self._window_base(samples, now, DOWN_WINDOW_S)
        if b is not None and now > b[0] and max(0, session.net_in - b[1]) / (now - b[0]) > DOWN_RATE_BPS:
            return "download_rate"
        return None

    async def tick(self, cfg) -> list:
        """One sweeper step (design 3). Returns [(Session, reason)] for the sessions it ended; Session.marker and
        marker_detail say why, for the security event. One launcher.show() call in the normal case. A returned session is ended
        (state, end_reason, marker are final) but its unit is stopped beside the tick: its seat stays taken until the stop confirms
        (end() on it waits for that). An error in one session's checks never stops the others or the tmp sweep; the same error on
        three ticks in a row ends that session as crash."""
        self.remember(cfg)
        self._ticks += 1
        ended: list = []
        launcher = self._launcher
        if launcher is None:
            return ended
        now = self.clock()
        sessions = [s for s in list(self._sessions.values()) if s.state == "running"]
        # 1. one show() for every unit of the prefix
        info = None
        try:
            info = await launcher.show([f"{self.prefix}*.service"])
        except Exception:
            info = None
        info = info if isinstance(info, dict) else None
        try:
            if info is not None:
                await self._sweep_unknown(info)
            await self._retry_left(launcher)
        except Exception:
            self._counters["check_errors"] += 1          # a bad entry in the unit list must not stop the checks below
        # 2. per running session. An error in one session's checks never reaches the others, nor the tmp sweep below.
        for s in sessions:
            if s.state != "running":
                continue
            ext = self._x.get(s.sid)
            if ext is None:
                continue
            verdict = None
            try:
                verdict = await self._judge(s, ext, info, cfg, now, launcher)
                ext.errors = 0
            except Exception as e:
                self._counters["check_errors"] += 1
                log.warning("rbrowser check failed: user %s sid %s %s", s.user_id, s.sid[:6], e.__class__.__name__)
                ext.errors += 1
                if ext.errors >= CHECK_ERRORS_END:       # skipped for two ticks; the same failure three ticks in a row is not 'fine'
                    verdict = ("crash", None, "")
            if verdict is None or s.state != "running":   # ended meanwhile (admin, sign-out): its own reason stands
                continue
            reason, marker, detail = verdict
            try:
                await self._end(s, reason, marker, detail, stop_inline=False)     # the stop is confirmed beside the tick (below)
            except Exception:
                self._counters["check_errors"] += 1
            if s.state == "ended" and s.end_reason == reason:
                ended.append((s, reason))
                self._spawn(self._finish_stop(s))
        # 3. tmp directories of units that are gone (and of nobody's), after the quota walk above
        try:
            self._counters["tmp_swept"] += len(launcher.sweep_tmp(self._live_idents()) or [])
        except Exception:
            pass
        return ended

    async def _judge(self, s: Session, ext: _Ext, info, cfg, now: float, launcher):
        """(reason, marker, detail) when the session must end, else None. Findings first, deadlines last."""
        props = None
        if info is not None:
            props = info.get(s.unit)
            if props is None:
                try:
                    props = (await launcher.show([s.unit])).get(s.unit)      # absent from the list: ask by name
                except Exception:
                    props = None
        if props is None:
            if info is not None:
                ext.unknown += 1
                if ext.unknown >= UNKNOWN_TICKS_END:
                    return "crash", None, ""
            # systemctl could not be asked this tick: unknown is not gone; the checks below still run
        else:
            ext.unknown = 0
            state = str(props.get("ActiveState", ""))
            if state not in ("active", "activating", "reloading", "deactivating"):
                status = str(props.get("ExecMainStatus", ""))
                # exit status 3 is display_mismatch only when ExecMainCode says "exited" (1): a unit killed by SIGQUIT has status 3 too
                # (code 2, killed) and a core dump is code 3. The failed unit is reset by the stop that ends the session (T5).
                if status == "3" and str(props.get("ExecMainCode", "")) == "1":
                    return "crash", "display_mismatch", ""
                if state == "inactive" and status == "0":
                    return "closed_in_browser", None, ""
                return "crash", None, ""
            n_in, n_out = self._int(props.get("IPIngressBytes")), self._int(props.get("IPEgressBytes"))
            if n_in is not None and n_out is not None:
                s.net_in, s.net_out = n_in, n_out
        # D1: the ingress filter must still be attached (with the pin this unit names)
        try:
            attached = bool(launcher.filter_attached(s.expect_cgroup, pin=s.ingress_pin or None))
        except Exception:
            attached = False
        if not attached:
            return "crash", "ingress_filter_lost", ""
        # R1: the unit's share of the tmp area
        tmp = self._tmp_dir or self._default_tmp()
        if tmp and _HEX12.fullmatch(s.ident or ""):
            try:
                _b, _n, over = await asyncio.to_thread(self._tmp_scan, os.path.join(tmp, s.ident))
            except Exception:
                over = False
            if over:
                return "crash", "tmp_quota", ""
        # 5.3: the listener check, every 6th tick
        if self._ticks % LISTENER_EVERY == 0:
            verdict = await self._listener_check(s, ext)
            if verdict == "found":
                return "crash", "listener_found", ""
            if verdict != "clean":
                return "crash", None, ""
        # 6.4
        detail = self._traffic_verdict(s, ext, cfg, now) if props is not None else None
        if detail:
            return "traffic_limit", "traffic_limit", detail
        # deadlines
        if s.viewer is not None:
            s.detached_since = None
        elif s.detached_since is None:
            s.detached_since = now
        if now - s.started >= LIFETIME_S:
            return "max_lifetime", None, ""
        if s.viewer is None and s.detached_since is not None and now - s.detached_since >= DETACH_S:
            return "detached", None, ""
        idle = _cfg_int(cfg, "rbrowser_idle_minutes", 15, 5, 120) * 60
        if now - s.last_activity >= idle:
            return "idle", None, ""
        return None

    def _default_tmp(self):
        try:
            return self.L.RUN_TMP
        except Exception:
            return None

    async def _sweep_unknown(self, info: dict):
        """A unit with a session-pattern name that the registry does not know is stopped. Helper, probe and test units never
        match the pattern (it is built from the prefix with exactly 12 hex digits), and units of the probe now running are known."""
        pat = self._unit_re()
        known = self._known_units()
        for unit in list(info):
            if isinstance(unit, str) and pat.fullmatch(unit) and unit not in known:
                ident = unit[len(self.prefix):-len(".service")]
                if info[unit].get("ActiveState") in ("inactive", "failed"):
                    if info[unit].get("ActiveState") == "failed":
                        self._spawn(self._reset_failed(self._launcher, unit))      # loaded but dead: nothing runs, nothing to stop, but it must not pile up (beside the tick)
                    continue
                self._counters["unknown_stopped"] += 1
                self._event("unknown_unit_stopped")
                self._spawn(self._stop_unit(unit, ident, ""))      # a stop that will not confirm takes about a minute: not inline in the tick

    async def _retry_left(self, launcher):
        """Units whose stop was not confirmed (ours, and the launcher's own `unstopped` set) are tried again."""
        for unit in list(getattr(launcher, "unstopped", ()) or ()):
            if unit not in self._left and unit not in self._stopping and unit not in self._known_units() and self._unit_re().fullmatch(unit):
                self._left[unit] = {"ident": unit[len(self.prefix):-len(".service")], "pin": "", "launcher": launcher, "since": self.clock()}
        for unit in list(self._left):
            if unit in self._stopping:
                continue
            v = self._left.get(unit)
            if v is not None:
                self._spawn(self._stop_unit(unit, v["ident"], v["pin"], v["launcher"]))

    # ------------------------------------------------------------ host preparation, start-up, shutdown

    def make_launcher(self, prefix: str, script: str, nice: int, pin):
        kw = dict(self.launcher_kw)
        return self.L.SystemdLauncher(unit_prefix=prefix, script=script, nice=nice, ingress_pin=pin or None, **kw)

    async def sweep_orphans(self) -> list:
        """Stop every unit of the session pattern (a portal restart leaves none that it knows). Returns the units not confirmed gone."""
        launcher = self._launcher or self.make_launcher(self.prefix, "session.py", 5, None)
        try:
            info = await launcher.show([f"{self.prefix}*.service"])
        except Exception:
            info = {}
        pat = self._unit_re()
        bad = []
        for unit in sorted(info or {}):
            if pat.fullmatch(unit) and unit not in self._known_units():
                if not await self._stop_unit(unit, unit[len(self.prefix):-len(".service")], "", launcher):
                    bad.append(unit)
        if self.probe_prefix != self.prefix:      # a probe unit that failed before a restart is still loaded (no --collect)
            # A launcher refuses every name that is not of its own prefix (show and reset_failed raise LaunchError), so the probe part
            # goes through a probe-prefixed launcher. At start-up (before host_prepare) there is none yet: one is built, as host_prepare would.
            plau = self._probe_launcher or self.make_launcher(self.probe_prefix, "probe.py", 19, None)
            try:
                pinfo = await plau.show([f"{self.probe_prefix}*.service"])
            except Exception:
                pinfo = {}
            for unit, props in sorted((pinfo or {}).items()):
                if (isinstance(unit, str) and self._probe_re().fullmatch(unit) and unit not in self._known_units()
                        and isinstance(props, dict) and props.get("ActiveState") == "failed"):
                    await self._reset_failed(plau, unit)
        return bad

    async def host_prepare(self, cfg) -> dict:
        """prepare_host (idempotent) and, only on success, the launchers and the pruning of stale pins. Serialised with unprepare."""
        self.remember(cfg)
        async with self._host_lock:
            kw = dict(self.prepare_kw)
            if self.ncpu:
                kw.setdefault("ncpu", self.ncpu)
            if self.mem_total is not None:
                kw.setdefault("mem_total", self.mem_total)
            facts = self.host_facts()
            targets = self.L.probe_targets(_cfg_int(cfg, "portal_port", 443, 1, 65535), [a for a, _ in facts["ifaces"]],
                                           facts["gateways_scoped"], facts["resolvers"], self.hidden_extra(cfg))
            self._targets_doc = targets
            res = await self.L.prepare_host(cfg, policy=self.policy(cfg), probe_targets_doc=targets, **kw)
            self.prep = res
            if not res.get("ok") or not res.get("ingress_pin"):
                self.ready = False
                self.unavailable_reasons = [str(r) for r in res.get("reasons", [])] or ["the host could not be prepared"]
                return res
            pin = res["ingress_pin"]
            self.pin = pin
            self.seat_penalty = not res.get("slice_ok", True)
            if self._launcher is None:
                self._launcher = self.make_launcher(self.prefix, "session.py", 5, pin)
            if self._probe_launcher is None:
                self._probe_launcher = self.make_launcher(self.probe_prefix, "probe.py", 19, pin)
            for lau in (self._launcher, self._probe_launcher):
                try:
                    lau.ingress_pin = pin          # a re-prepare may name a new pin; running sessions keep their own (Session.ingress_pin)
                except Exception:
                    pass
            self.ready = True
            self.unavailable_reasons = []
            self._recheck_preflight(cfg)        # a new pin, policy or deny list has never passed the probe
            await self._prune_pins()
            return res

    async def _prune_pins(self):
        """prune_stale(base, keep=pins of running units, units being stopped and units left, plus the current one), only when
        every pin in use is known (a unit left over from an earlier run names a pin that nobody here knows)."""
        keep = {s.ingress_pin for s in self._sessions.values()} | {v[1] for v in self._stopping.values()} | {v["pin"] for v in self._left.values()}
        if any(not p for p in keep) and (self._sessions or self._stopping or self._left):
            return
        keep = {p for p in keep if p} | ({self.pin} if self.pin else set())
        if self._left_unknown_pin():
            return
        base = self.prepare_kw.get("bpf_base") or self.bpf.PIN_BASE
        try:
            await asyncio.to_thread(self.bpf.prune_stale, base, sorted(keep))
        except Exception:
            pass

    def _left_unknown_pin(self) -> bool:
        return builtins.any(not v["pin"] for v in self._left.values())

    async def startup(self, cfg) -> None:
        """Nothing at all unless the feature is enabled and available (no file, no mount, no systemctl call)."""
        self.remember(cfg)
        self.enabled = _truthy(_cfg(cfg, "rbrowser_enabled", False))
        if not self.enabled:
            return
        stage = _truthy(_cfg(cfg, "stage_mode", False))
        if select_launcher_kind(stage, self.environ) == "fake":
            import tempfile
            self.stage_fake = True
            self.fake_dir = str(_cfg(cfg, "stage_dir", "") or tempfile.mkdtemp(prefix="rbrowser-stage-"))
            if self._launcher is None:
                self._launcher = FakeLauncher(self.fake_dir, unit_prefix=self.prefix)
            self._stage_listener_wiring()
            self.ready = True
            self._preflight = {"ok": True, "checks": []}
            return
        av = self.L.availability(stage_mode=stage)
        if not av.get("available"):
            self.unavailable_reasons = list(av.get("reasons", [])) or ["not available"]
            return
        bad = await self.sweep_orphans()
        if bad:
            self._event("unit_left_running", unit=bad[0])
        res = await self.host_prepare(cfg)
        if not res.get("ok") or not self.ready:
            return
        self._schedule_preflight(False)

    def _stage_listener_wiring(self) -> None:
        """Stage mode has no cgroup and the portal itself listens: the cgroup.procs of the stage launcher's cgroup names this process and
        the scan finds nothing, unless the caller injected its own reader or scan. The listener check itself is the same code."""
        want = os.path.normpath(f"{self.cgroup_root}{FAKE_CGROUP}/cgroup.procs")
        if not self._read_file_given:
            orig = self._read_file
            self._read_file = lambda path: f"{os.getpid()}\n" if os.path.normpath(path) == want else orig(path)
        if not self._scan_given:
            self._listener_scan = lambda pids: False

    async def shutdown(self) -> None:
        """Every unit is stopped (concurrently, bounded 5 s), then the host is unprepared (the slice and the pin stay while a unit
        is not confirmed gone)."""
        launcher = self._launcher
        pf = self._pf_task
        if pf is not None and not pf.done():
            pf.cancel()
            await asyncio.wait([pf], timeout=SHUTDOWN_STOP_S)      # the probe unit's stop (its finally) must be under way before the host is unprepared
        # No launcher does not mean nothing was prepared: the launchers are made only after a successful prepare, but a prepare that
        # failed half way (pin loaded, then the tmpfs or the state directory failed) has left the pin, the static tree and the mounts.
        if launcher is None and self.prep is None:
            return
        tasks = [asyncio.ensure_future(self.end(s, "portal_stop")) for s in list(self._sessions.values())]
        if tasks:
            await asyncio.wait(tasks, timeout=SHUTDOWN_STOP_S)
        for unit in list(self._left):
            v = self._left[unit]
            tasks.append(asyncio.ensure_future(self._stop_unit(unit, v["ident"], v["pin"], v["launcher"])))
        tasks += [t for t in list(self._bg) if t is not asyncio.current_task() and t is not pf]     # stops the tick spawned
        pending = [t for t in tasks if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=SHUTDOWN_STOP_S)
        left = len(self._left) + len(self._stopping) + len(self._sessions) + len(self._probe_units)
        was_fake = self.stage_fake
        self.ready = False
        if was_fake or self.prep is None:
            self._probe_units.clear()
            return
        async with self._host_lock:
            kw = dict(self.unprepare_kw)
            kw.setdefault("bpf_pin", self.pin or (self.prep or {}).get("ingress_pin") or "")
            try:
                await self.L.unprepare_host(units_left=left, **kw)
            except Exception:
                pass
            self.prep = None

    # ------------------------------------------------------------ preflight (design 8.2)

    def _cache_file(self) -> str:
        if self._cache_path:
            return self._cache_path
        return os.path.join(self.L.STATE_DIR, "preflight.json")

    def _versions(self) -> dict:
        if self._versions_fn:
            return dict(self._versions_fn())
        av = {}
        try:
            av = self.L.availability(stage_mode=False)
        except Exception:
            pass
        mtime = None
        try:
            mtime = os.stat((av.get("paths") or {}).get("chromium", "")).st_mtime
        except OSError:
            pass
        sysd = None
        try:
            sysd = self.L._systemd_version_from_files()
        except Exception:
            pass
        return {"chromium": av.get("chromium_version", ""), "chromium_mtime": mtime, "systemd": sysd, "kernel": os.uname().release}

    def _unit_src_digest(self) -> str:
        """sha256 over the files of rbrowser_unit/*.py (the probe and the supervisor): a portal upgrade that changes them changes the key."""
        d = Path(__file__).resolve().parent / "rbrowser_unit"
        try:
            files = sorted(d.glob("*.py"))
            sig = tuple((f.name, f.stat().st_mtime_ns, f.stat().st_size) for f in files)
            if sig == self._unit_src_cache[0]:
                return self._unit_src_cache[1]
            h = hashlib.sha256()
            for f in files:
                h.update(f.name.encode() + b"\0" + f.read_bytes() + b"\0")
            self._unit_src_cache = (sig, h.hexdigest())
            return self._unit_src_cache[1]
        except OSError:
            return "unreadable"

    def preflight_key(self, cfg) -> str:
        """Hash of (Chromium version and mtime, systemd version, kernel release, portal version, policy JSON, the unit property
        list without per-session values, the deny list)."""
        parts = {"versions": self._versions(), "portal": str(_cfg(cfg, "portal_version", "")), "policy": self.policy(cfg),
                 "deny": self.deny(cfg), "pin": self.pin, "targets": self._targets_doc, "unit_src": self._unit_src_digest()}
        try:
            args = self.L.build_unit_args(self.spec("0" * 12, 1280, 720, cfg), self.probe_prefix, "probe.py", 19, ingress_pin=self.pin)
            parts["props"] = [a for a in args if not a.startswith("--unit=")]
            parts["props"] = [re.sub(r"[0-9a-f]{12}", "<id>", a) for a in parts["props"]]
        except Exception as e:
            parts["props"] = f"error {e.__class__.__name__}"
        return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()

    def _read_cache(self, key: str):
        try:
            with open(self._cache_file(), "r", encoding="utf-8") as f:
                doc = json.load(f)
            res = doc.get("result")
            if doc.get("key") == key and isinstance(res, dict) and res.get("ok") is True and isinstance(res.get("checks"), list):
                return res
        except (OSError, ValueError, AttributeError):
            pass
        return None

    def _write_cache(self, key: str, result: dict):
        path = self._cache_file()
        try:
            tmp = f"{path}.{secrets.token_hex(4)}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"key": key, "result": result, "at": self.clock()}, f)
            os.replace(tmp, path)
        except OSError:
            pass

    async def preflight(self, force: bool = False) -> dict:
        """{"ok": bool, "checks": [{"name","ok","detail"}]}. A run in progress is awaited, not started twice. Without `force` a cache
        file with the same key answers without running the probe. A failed check makes availability() False and queues the event
        {"kind": "preflight_failed", "checks": [names]}."""
        if self._pf_task is not None and not self._pf_task.done():
            return await asyncio.shield(self._pf_task)
        if not self.ready and not self.stage_fake:
            return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the host is not prepared"}]}
        self._schedule_preflight(force)
        if self._pf_task is None:
            return await self._preflight_main(force)
        return await asyncio.shield(self._pf_task)

    async def _preflight_main(self, force: bool) -> dict:
        res = {}
        for _ in range(3):
            gen = self._pf_gen
            res = await self._preflight_once(force)
            if gen == self._pf_gen:
                return res
            self._preflight = None          # a setting changed while it ran: the answer is for the old settings, run again
        self._preflight = res = {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the settings kept changing during the probe"}]}
        return res

    async def _preflight_once(self, force: bool) -> dict:
        if self.stage_fake:
            self._preflight = {"ok": True, "checks": []}
            return self._preflight
        key = None
        try:
            key = self.preflight_key(self.cfg)
            if not force:
                hit = self._read_cache(key)
                if hit is not None:
                    self._preflight, self._pf_key = hit, key
                    return hit
        except Exception:
            key = None
        try:
            result = await asyncio.wait_for(self._run_probe(), PREFLIGHT_BOUND_S + 30)
        except asyncio.CancelledError:
            raise
        except Exception:
            result = {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the probe could not be run"}]}
        self._preflight, self._pf_key = result, key
        if result.get("ok") and key:
            self._write_cache(key, result)
        if not result.get("ok"):
            self._event("preflight_failed", event=EVENT_OF["preflight_failed"], checks=[c["name"] for c in result.get("checks", []) if not c.get("ok")])
        return result

    async def _run_probe(self) -> dict:
        ident = secrets.token_hex(6)
        spec = self.spec(ident, 1280, 720, self.cfg)
        if self._probe_runner is not None:
            return await self._probe_runner(spec)
        launcher = self._probe_launcher
        if launcher is None:
            return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the host is not prepared"}]}
        unit = f"{self.probe_prefix}{ident}.service"
        self._probe_units[unit] = ident
        text = ""
        try:
            res = await launcher.start(spec)
            unit = res.unit
            deadline = self.clock() + PREFLIGHT_UNIT_WAIT_S
            while self.clock() < deadline:
                st = (await launcher.show([unit])).get(unit, {})
                if st.get("ActiveState") in ("inactive", "failed") or not st:
                    break
                await self.sleep(0.5)
            text = await self._journal(unit)
        except UnitLeftRunning as e:
            self._left[e.unit] = {"ident": ident, "pin": self.pin, "launcher": launcher, "since": self.clock()}
            return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the probe unit could not be stopped"}]}
        except LaunchError:
            return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the probe unit could not be started"}]}
        finally:
            await self._stop_unit(unit, ident, self.pin, launcher)
            self._probe_units.pop(f"{self.probe_prefix}{ident}.service", None)
            self._probe_units.pop(unit, None)
        return parse_probe_output(text)

    async def _journal(self, unit: str) -> str:
        run = self._run or self.L.default_run
        tool = self.L.find_tool("journalctl") or "journalctl"
        r = await run([tool, "-u", unit, "-o", "cat", "--no-pager", "-n", "200"], 10.0)
        return r.out if getattr(r, "rc", 1) == 0 else ""


# ---------------------------------------------------------------- the module functions (the contract of design section 9)

_REG: Registry | None = None


def registry() -> Registry:
    global _REG
    if _REG is None:
        _REG = Registry()
    return _REG


def configure(**kw) -> Registry:
    """Replace the module's registry with one built from `kw` (tests; the live test's round 2 passes the test prefix)."""
    global _REG
    _REG = Registry(**kw)
    return _REG


def reset() -> None:
    global _REG
    _REG = None


def availability(cfg=None) -> dict:
    """{"available","missing","reasons","chromium_version","chromium_age_days","kernel_upload_limit", "checking", ...}"""
    return registry().availability(cfg)


async def preflight(force: bool = False) -> dict:
    """{"ok": bool, "checks": [{"name","ok","detail"}]}"""
    return await registry().preflight(force)


async def create(user_id: int, token_id: str, width: int, height: int, cfg, takeover: bool = False, theme=None) -> Session:
    """Raises Refused(status, body_dict). Serialised by Registry.lock. `theme`: None or (colour "#rrggbb", mode "dark"|"light") as
    the page sent them; validated again, invalid values mean the neutral default."""
    return await registry().create(user_id, token_id, width, height, cfg, takeover, theme=theme)


def get(sid: str) -> Session | None:
    return registry().get(sid)


def for_user(user_id: int) -> Session | None:
    return registry().for_user(user_id)


def all() -> list:  # noqa: A001 - the name is the contract
    return registry().all()


async def open_stream(session: Session):
    """(StreamReader, StreamWriter), peer-verified (design 5.3). No branch on the kind of session. Raises StreamRefused."""
    return await registry().open_stream(session)


async def resize(session: Session, width: int, height: int) -> bool:
    return await registry().resize(session, width, height)


async def clip(session: Session) -> dict:
    """{"ok": bool, "text": str, "truncated": bool[, "why": str]}: ok False is never an empty clipboard."""
    return await registry().clip(session)


async def type_text(session: Session, text: str) -> dict:
    """{"ok", "typed", "skipped", "complete", "fallback", "why"}: the text typed in the unit (see Registry.type_text)."""
    return await registry().type_text(session, text)


async def end(session: Session, reason: str, marker: str | None = None, detail: str = "") -> None:
    """Idempotent."""
    await registry().end(session, reason, marker, detail)


async def usage(session: Session) -> dict:
    """{"memory_mb": n, "cpu_seconds": n, "net_in": n, "net_out": n}"""
    return await registry().usage(session)


def note_activity(session: Session, here: bool = False) -> bool:
    """Called for an RFB message of type 4 or 5, or (here=True, throttled to one per 10 s) the control frame {"op":"here"}."""
    return registry().note_activity(session, here)


def mark_attached(session: Session, viewer) -> None:
    registry().mark_attached(session, viewer)


def mark_detached(session: Session, viewer=None) -> None:
    registry().mark_detached(session, viewer)


def deadlines(session: Session, cfg=None) -> dict:
    return registry().deadlines(session, cfg)


def activity_state(session: Session) -> str:
    return registry().activity_state(session)


def find_prefix(prefix: str):
    return registry().find_prefix(prefix)


def boot_id() -> str:
    return registry().boot_id()


def seats(cfg) -> dict:
    """{"max": n, "cpu_percent": n}: the effective values of design 4.3."""
    return registry().seats(cfg)


def checking() -> bool:
    return registry().checking()


def last_preflight() -> dict | None:
    return registry().last_preflight()


def take_events() -> list:
    return registry().take_events()


def counters() -> dict:
    return registry().counters()


def left_units() -> list:
    return registry().left_units()


async def tick(cfg) -> list:
    """Sweeper step. Returns [(Session, reason)] for the sessions it ended (their units are stopped beside the tick; seats are held until then)."""
    return await registry().tick(cfg)


async def on_revocation(user_id: int, spared) -> None:
    """spared: callable(token_id) -> bool, the caller's own predicate."""
    await registry().on_revocation(user_id, spared)


async def host_prepare(cfg) -> dict:
    """prepare_host again (settings that enter it changed): idempotent, serialised with shutdown."""
    return await registry().host_prepare(cfg)


async def startup(cfg) -> None:
    """Does nothing unless the feature is enabled and available."""
    await registry().startup(cfg)


async def shutdown() -> None:
    await registry().shutdown()
