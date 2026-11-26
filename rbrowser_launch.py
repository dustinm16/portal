"""Host side of the server-side browser: availability, the unit's launch command, host preparation, seat
arithmetic and the systemd launcher (design sections 4 and 8.2).

Nothing here starts at import time. Every subprocess goes through an injected `run(argv, timeout)` coroutine
(default: asyncio.create_subprocess_exec with an argument list, stdin /dev/null, a timeout, no shell), so the
tests see the command lists and no test starts a unit, mounts or runs iptables. The lead runs the live gates.

Imports `rbrowser` for the shared dataclasses (LaunchSpec, LaunchResult, LaunchError); `rbrowser` never
imports this module at import time.
"""

from __future__ import annotations

import asyncio
import glob
import ipaddress
import logging
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import rbrowser
import rbrowser_bpf
import rbrowser_policy
from rbrowser import LaunchError, LaunchResult, LaunchSpec, UnitLeftRunning

log = logging.getLogger("portal")

# ---- constants decided by the live gates (round 1 may change them; lane A2 applies the changes)
MIN_W = 560                        # G20 and D5: smallest window width (Chromium's own minimum is 500)
CAPTURE_MAX = (1920, 1200)         # Xvfb screen and largest window; G22 may lower it
STREAM_KBPS = 8000                 # the token-bucket cap of the unit-to-client stream; G22

# ---- names that must match across the lanes
UNIT_PREFIX = rbrowser.UNIT_PREFIX
PROBE_PREFIX = rbrowser.PROBE_PREFIX
TEST_PREFIX = rbrowser.TEST_PREFIX
SLICE = "system-portalrb.slice"
SLICE_CGROUP = "system.slice/system-portalrb.slice"
RUN_DIR = "/run/portal-rb"
WORK_DIR = "/run/work"             # the unit's capped scratch tmpfs; equals rbrowser_unit/session.py WORK_DIR (a test pins it)
STATIC_DIR = "/run/portal-rb-static"
STATE_DIR = "/run/portal-rb-state"
# The member's portal theme (1.26.0): one root-owned file per session in THEME_DIR (inside the root-only state directory, so a unit
# never sees the directory), bound read-only over the placeholder of the same name that write_static_tree() puts into the static
# managed-policy directory. The static tree stays the single source of every security policy; this file holds BrowserThemeColor only.
THEME_DIR = f"{STATE_DIR}/theme"
THEME_FILE = rbrowser_policy.THEME_FILE_NAME
THEME_DEST = f"/etc/chromium/policies/managed/{THEME_FILE}"
CHAIN = "PORTAL-RB"
SESSION_LIFETIME_MIN = 240
RUNTIME_MAX_SEC = SESSION_LIFETIME_MIN * 60 + 60
TMPFS_OPTIONS = "size=8m,nr_inodes=2048,mode=0755,nosuid,nodev,noexec"
RUN_TMP = "/run/portal-rb-tmp"      # D6: the capped tmpfs that every unit gets as its /tmp and /var/tmp (one directory per unit)
TMP_MB = 32
# mode=0700: systemd binds the per-unit directories as root, so a unit needs no access to the area itself, and no other account of
# the host can list the random names, plant a file in a unit's /tmp or fill the area. The 32 MiB and 4096 inodes are ONE cap for
# the whole host (one tmpfs for every unit), not a cap per unit: one session can fill it and every new session then fails to
# start (Xvfb's xkbcomp cannot write its keymap). A per-unit tmpfs (design G2b fallback) is the way to a real per-unit cap.
TMP_OPTIONS = f"size={TMP_MB}m,nr_inodes=4096,mode=0700,nosuid,nodev,noexec"
# The portal runs in its own mount namespace (PrivateTmp=true; /run is a SLAVE of the host's): a mount made by the portal process
# is invisible to systemd (PID 1), which resolves RuntimeDirectory= and BindPaths= in the host's namespace. So the two tmpfs are
# mounted and unmounted by a short oneshot unit (systemd-run --wait: PID 1 starts it in the host's namespace, and the mount
# then propagates down to the portal's slave namespace), and every "is it mounted" question is asked of PID 1's mount table.
HOST_MOUNTINFO = "/proc/1/mountinfo"
HELPER_PREFIX = "portal-rbhost-"      # the helper units (one per mount or umount); the live test passes portal-rbtest-host-
HELPER_PREFIXES = (HELPER_PREFIX, rbrowser.TEST_PREFIX + "host-")
HELPER_TIMEOUT = 30.0
RESET_FAILED_TIMEOUT = 8.0         # the time limit of one `systemctl reset-failed` (below the registry's own 10 s bound, so default_run ends systemctl first)
TOOL_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
START_WAIT_STEPS = 100             # x 0.1 s = the 10 s start budget of section 3
START_WAIT_STEP_S = 0.1
SYSTEMD_MIN = 249                  # SocketBindDeny (kept in the property list); IPIngressFilterPath needs 243
GLOB_SHOW = "*"                    # show(["<prefix>*.service"]) is the sweeper's one call

PACKAGE_OF = {
    "chromium": "chromium", "chromium-browser": "chromium-browser", "Xvfb": "xvfb", "x11vnc": "x11vnc",
    "xauth": "xauth", "xrandr": "x11-xserver-utils", "python3": "python3",
    "xsel": "xsel", "iptables": "iptables", "ip6tables": "iptables",
}

# Hidden-path list of 4.2: fixed entries, then (from the caller) the install directory and every storage
# root, then the program launchers.
HIDDEN_FIXED = ("/srv", "/opt", "/boot", "/var/log", "/var/backups", "/var/spool", "/var/mail", "/etc/ssh",
                "/etc/searxng", "/etc/sudoers.d")
HIDDEN_LAUNCHERS = ("/usr/bin/xdg-open", "/usr/bin/xdg-email", "/usr/bin/xdg-mime", "/usr/bin/xdg-settings",
                    "/usr/bin/mimeopen", "/usr/bin/run-mailcap", "/usr/bin/gio", "/usr/bin/gvfs-open",
                    "/usr/bin/kde-open", "/usr/bin/kde-open5", "/usr/bin/exo-open", "/usr/bin/sensible-browser",
                    "/usr/bin/lynx", "/usr/bin/xclip")      # xsel is not hidden: the supervisor reads the clipboard with it (D4)

_UNIT_RE = r"[0-9a-f]{12}\.service"
_HEX12 = re.compile(r"[0-9a-f]{12}")
_SAFE_PATH_CHARS = re.compile(r"[A-Za-z0-9._/+@-]+")
_UNIT_NAME_OK = re.compile(r"[A-Za-z0-9:_.@-]+\.service")


# ---------------------------------------------------------------- running things

@dataclass
class Ran:
    rc: int
    out: str = ""
    err: str = ""


async def default_run(argv, timeout: float = 10.0) -> Ran:
    """create_subprocess_exec with an argument list: no shell, stdin /dev/null, bounded in time."""
    env = {"PATH": ":".join(TOOL_DIRS), "LANG": "C", "LC_ALL": "C"}
    try:
        p = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=env)
    except OSError as e:
        return Ran(127, "", f"cannot run {os.path.basename(str(argv[0]))}: {e.__class__.__name__}")
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            p.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(p.wait(), 2)
        except Exception:
            pass
        return Ran(124, "", "timeout")
    except BaseException:
        # a cancellation (or anything else) while the child runs: the child is killed and reaped BEFORE the cancellation goes on. A
        # systemd-run that outlived start() could still queue its unit after the clean-up stop had seen the unit inactive.
        try:
            p.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.shield(asyncio.wait_for(p.wait(), 2))
        except BaseException:
            pass
        raise
    return Ran(p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))


def find_tool(name: str, dirs=TOOL_DIRS, env_path=None, is_exec=None) -> str:
    """Absolute path of an executable, searching PATH and then the system directories (iptables lives in
    /usr/sbin, which an unprivileged PATH lacks). '' when not found."""
    if is_exec is None:
        def is_exec(p):
            return os.path.isfile(p) and os.access(p, os.X_OK)
    if env_path is None:
        env_path = os.environ.get("PATH", "")
    seen = []
    for d in [x for x in env_path.split(":") if x.startswith("/")] + list(dirs):
        if d not in seen:
            seen.append(d)
            c = os.path.join(d, name)
            if is_exec(c):
                return c
    return ""


# ---------------------------------------------------------------- 4.2 the launch command

def quote_property_path(path: str) -> str:
    """A path as one InaccessiblePaths= item (design 4.2): plain when every character is in
    [A-Za-z0-9._/+@-]; otherwise wrapped in double quotes with backslash and double quote escaped (systemd
    strips the quotes; the quote has to wrap the whole item, so the '-' prefix is inside). Raises LaunchError
    for a path it cannot express: not a string, not absolute, not normalised, '/', a control character
    (NUL and newline included), a percent sign (specifier), or not encodable as UTF-8."""
    if not isinstance(path, str) or not path.startswith("/") or path == "/":
        raise LaunchError("a hidden path must be an absolute path other than /")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError as e:
        raise LaunchError("a hidden path is not valid UTF-8") from e
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise LaunchError("a hidden path has a control character")
    if "%" in path:
        raise LaunchError("a hidden path has a percent sign")
    if "//" in path or path.endswith("/") or any(seg in (".", "..") for seg in path.split("/")[1:]):
        raise LaunchError("a hidden path is not normalised")
    item = "-" + path
    if _SAFE_PATH_CHARS.fullmatch(path):
        return item
    return '"' + item.replace("\\", "\\\\").replace('"', '\\"') + '"'


def hidden_paths(extra=()) -> list:
    """The hidden-path list: fixed, then the caller's (install directory, storage roots), then launchers.
    Order kept, duplicates removed. Entries are not validated here; build_unit_args() does it."""
    out = []
    for p in list(HIDDEN_FIXED) + list(extra or ()) + list(HIDDEN_LAUNCHERS):
        if p not in out:
            out.append(p)
    return out


def _need(cond, text):
    if not cond:
        raise LaunchError(text)


def _check_spec(spec: LaunchSpec):
    _need(isinstance(spec.ident, str) and _HEX12.fullmatch(spec.ident), "unit id must be 12 lowercase hex characters")
    for v in (spec.width, spec.height, spec.memory_mb, spec.cpu_percent):
        _need(isinstance(v, int) and not isinstance(v, bool), "numbers in the launch spec must be integers")
    _need(1 <= spec.width <= CAPTURE_MAX[0] and 1 <= spec.height <= CAPTURE_MAX[1], "window size out of range")
    _need(spec.clipboard in ("both", "to_browser", "off"), "bad clipboard mode")
    _need(256 <= spec.memory_mb <= 65536, "memory out of range")
    _need(10 <= spec.cpu_percent <= 1600, "cpu out of range")
    _need(isinstance(spec.chromium, str) and spec.chromium.startswith("/") and "\n" not in spec.chromium
          and "\0" not in spec.chromium and not spec.chromium.startswith("/snap/"), "bad browser path")
    _need(isinstance(spec.portal_unit, str) and (spec.portal_unit == "" or _UNIT_NAME_OK.fullmatch(spec.portal_unit)),
          "bad portal unit name")
    _need(isinstance(spec.deny, (list, tuple)) and len(spec.deny) > 0, "the deny list must not be empty")
    for c in spec.deny:
        _need(isinstance(c, str), "bad deny entry")
        try:
            ipaddress.ip_network(c, strict=True)
        except ValueError as e:
            raise LaunchError("bad deny entry") from e
    try:
        rbrowser_policy.validate_home_url(spec.home_url)
    except ValueError as e:
        raise LaunchError("bad home URL") from e


_PIN_CHARS = re.compile(r"[A-Za-z0-9._/-]+")
PIN_PREFIX = rbrowser_bpf.PIN_DIR + "/portal-rb"


def check_ingress_pin(pin) -> str:
    """The pin path IPIngressFilterPath= is given (D1): a plain absolute path under /sys/fs/bpf/portal-rb, nothing that
    needs quoting. Raises LaunchError otherwise (None and '' included), so a unit without the filter cannot be built."""
    if (not isinstance(pin, str) or not pin.startswith(PIN_PREFIX) or not _PIN_CHARS.fullmatch(pin)
            or "//" in pin or any(seg in (".", "..") for seg in pin.split("/")[1:])):
        raise LaunchError("the ingress filter pin is missing or not a portal-rb pin under /sys/fs/bpf")
    return pin


def check_theme_file(path, ident, script) -> str:
    """The per-session theme file BindReadOnlyPaths= is given: a plain absolute path that ends in <ident>.json, for a session only (the
    preflight probe has no theme). Raises LaunchError otherwise."""
    if (script != "session.py" or not isinstance(path, str) or not path.startswith("/") or not _SAFE_PATH_CHARS.fullmatch(path)
            or "//" in path or any(seg in (".", "..") for seg in path.split("/")[1:]) or path.rsplit("/", 1)[-1] != f"{ident}.json"):
        raise LaunchError("bad theme file")
    return path


def build_unit_args(spec: LaunchSpec, unit_prefix: str = UNIT_PREFIX, script: str = "session.py", nice: int = 5, *,
                    ingress_pin: str, theme_file: str | None = None) -> list:
    """The systemd-run arguments of design 4.2, as an argument list (without the program name): one element per
    argument, no shell, no literal quotes except in a quoted InaccessiblePaths item. Raises LaunchError on
    anything it cannot express, which makes create() fail closed.

    `unit_prefix` is portal-rb- for a session, portal-rbprobe- for the preflight, portal-rbtest- for the live
    test. The probe uses script='probe.py' and nice=19 and otherwise the same properties. `ingress_pin` is the path
    prepare_host() returns as "ingress_pin"; it has no default, so no unit can be built without the filter.

    Theme (1.26.0): `theme_file` is the per-session root-owned policy file (SystemdLauncher.make_theme); when given, it is bound read-only
    over the placeholder next to the main policy file. spec.theme_mode, when "dark" or "light", becomes RB_THEME_MODE. Without them the
    arguments are exactly those of a host without a theme (the preflight probe never has either)."""
    _check_spec(spec)
    check_ingress_pin(ingress_pin)
    _color, theme_mode = rbrowser_policy.normalise_theme(spec.theme_color, spec.theme_mode)
    if theme_file is not None:
        check_theme_file(theme_file, spec.ident, script)
    # No --collect (T1): a unit that ends in error stays loaded as `failed` until somebody resets it, so the registry can still read its
    # ExecMainStatus and ExecMainCode afterwards (a status of 3 is the supervisor's display mismatch). SystemdLauncher.stop() and
    # reset_failed() are what removes it. host_run's helper units keep --collect: nobody reads their exit status after the wait.
    _need(unit_prefix in (UNIT_PREFIX, PROBE_PREFIX, TEST_PREFIX), "unknown unit prefix")
    _need(script in ("session.py", "probe.py"), "unknown script")
    _need(isinstance(nice, int) and 0 <= nice <= 19, "bad nice value")
    w, h = spec.width, spec.height
    mem = spec.memory_mb
    a = [
        f"--unit={unit_prefix}{spec.ident}", "--quiet", "--no-block",
        f"--slice={SLICE}",
        "--description=Open Relay Portal browser session",
    ]

    def p(assignment):
        a.extend(["-p", assignment])

    p("Type=exec")
    p("DynamicUser=yes")
    p(f"RuntimeDirectory=portal-rb/s-{spec.ident}")
    p("RuntimeDirectoryMode=0700")
    p("PrivateIPC=yes")
    p("PrivateDevices=yes")
    p("ProtectSystem=strict")
    p("ProtectHome=yes")
    p("ProtectProc=invisible")
    p("NoNewPrivileges=yes")
    p("ProtectKernelTunables=yes")
    p("ProtectKernelModules=yes")
    p("ProtectKernelLogs=yes")
    p("ProtectControlGroups=yes")
    p("ProtectClock=yes")
    p("ProtectHostname=yes")
    p("RestrictSUIDSGID=yes")
    p("LockPersonality=yes")
    p("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK")
    p("CapabilityBoundingSet=CAP_NET_BIND_SERVICE")
    p("AmbientCapabilities=")
    p("UMask=0077")
    # Everything a page can make Chromium write (profile, caches, TMPDIR, HOME) lives on this capped tmpfs; /tmp and
    # /var/tmp are the capped tmpfs directory bound below (D6).
    p(f"TemporaryFileSystem={WORK_DIR}:rw,nosuid,nodev,size=768m,mode=1777")
    p("TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,size=64m,mode=1777")
    p("TemporaryFileSystem=/run:ro,nosuid,nodev,noexec,size=64k,mode=0755")
    p(f"BindPaths={RUN_DIR}/s-{spec.ident}")
    # D6 (measured on systemd 252, live): DynamicUser=yes forces PrivateTmp=yes, which keeps /tmp and /var/tmp on the root disk
    # without a cap, and a TemporaryFileSystem= of those paths is dropped. A BindPaths= over them DOES take effect, so both are
    # a directory of the capped tmpfs RUN_TMP (the launcher creates it, mode 1777, before the start and removes it after the
    # stop). ReadOnlyPaths= and InaccessiblePaths= also work but Xvfb needs a writable /tmp (xkbcomp writes the keymap there).
    p(f"BindPaths={RUN_TMP}/{spec.ident}:/tmp")
    p(f"BindPaths={RUN_TMP}/{spec.ident}:/var/tmp")
    p(f"BindReadOnlyPaths={STATIC_DIR}/bin:/mnt")
    # the probe's headless Chromium cannot run under DeveloperToolsAvailability=2 (see rbrowser_policy.probe_policy)
    p(f"BindReadOnlyPaths={STATIC_DIR}/{'chromium-probe' if script == 'probe.py' else 'chromium'}:/etc/chromium")
    if theme_file is not None:
        # after the /etc/chromium bind: systemd mounts parents first. The "-" makes a source that is gone when the namespace is built
        # (a sweep, a crash) a bind that is skipped, so the placeholder "{}" shows and the session runs without the colour.
        p(f"BindReadOnlyPaths=-{theme_file}:{THEME_DEST}")
    p(f"BindReadOnlyPaths={STATIC_DIR}/chromium.d:/etc/chromium.d")
    for path in hidden_paths(spec.hidden_extra):
        p("InaccessiblePaths=" + quote_property_path(path))
    p(f"MemoryHigh={mem * 3 // 4}M")
    p(f"MemoryMax={mem}M")
    p("MemorySwapMax=0")
    p(f"CPUQuota={spec.cpu_percent}%")
    p("IOWeight=50")
    p(f"Nice={nice}")
    p("TasksMax=512")
    p("LimitNOFILE=4096")
    p("LimitCORE=0")
    p("OOMPolicy=continue")
    p("TimeoutStopSec=5")
    p("KillMode=control-group")
    p("SendSIGKILL=yes")
    p(f"RuntimeMaxSec={RUNTIME_MAX_SEC}")
    # SocketBindDeny=any is accepted but NOT enforced by this systemd build (-BPF_FRAMEWORK); it stays for builds that
    # enforce it and nothing depends on it. The listener control is the ingress filter (rbrowser_bpf), which systemd
    # attaches next to its own IPAddressDeny program; the launcher verifies it after the start.
    p("SocketBindDeny=any")
    p(f"IPIngressFilterPath={ingress_pin}")
    p("IPAccounting=yes")
    p("IPAddressDeny=" + " ".join(spec.deny))
    p("StandardInput=null")
    p("StandardOutput=journal")
    p("StandardError=journal")
    if spec.portal_unit:
        p(f"BindsTo={spec.portal_unit}")
        p(f"After={spec.portal_unit}")
    a.extend(["-E", f"RB_GEOMETRY={w}x{h}"])
    a.extend(["-E", f"RB_CLIPBOARD={spec.clipboard}"])
    a.extend(["-E", f"RB_HOME={spec.home_url}"])
    a.extend(["-E", f"RB_CHROMIUM={spec.chromium}"])
    if theme_mode and script == "session.py":
        a.extend(["-E", f"RB_THEME_MODE={theme_mode}"])
    a.extend(["/usr/bin/python3", "-I", "-S", f"/mnt/{script}"])
    return a


# ---------------------------------------------------------------- 4.3 seats and slice

def _cfg_int(cfg, key, default, lo, hi):
    try:
        v = cfg.get(key, default) if hasattr(cfg, "get") else getattr(cfg, key, default)
        v = int(v)
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


CPU_FLOOR = 50   # percent: the smallest value of the setting; also what a 1-CPU host gets


def seats(cfg, ncpu: int, mem_total: int) -> dict:
    """Effective values of design 4.3. mem_total is in BYTES (psutil.virtual_memory().total).

    seats = min(rbrowser_max_sessions, max(1, floor(MemTotal/3 / rbrowser_memory_mb)))
    cpu   = min(rbrowser_cpu_percent, (ncpu - 1.5) * 100 / seats), never below 50 (a host with 1.5 CPUs or
            fewer would otherwise give zero or a negative quota; the floor keeps one small seat)."""
    max_sessions = _cfg_int(cfg, "rbrowser_max_sessions", 2, 1, 8)
    mem_mb = _cfg_int(cfg, "rbrowser_memory_mb", 2048, 1024, 4096)
    cpu_pct = _cfg_int(cfg, "rbrowser_cpu_percent", 150, 50, 400)
    total_mb = max(0, int(mem_total)) // (1024 * 1024)
    n = min(max_sessions, max(1, (total_mb // 3) // mem_mb))
    budget = int((float(ncpu) - 1.5) * 100)
    cpu = max(CPU_FLOOR, min(cpu_pct, budget // n))
    return {"max": n, "cpu_percent": cpu}


def slice_properties(cfg, ncpu: int, mem_total: int) -> list:
    """`systemctl set-property --runtime system-portalrb.slice ...` assignments (design 4.3): the slice total
    is seats * cpu capped at (ncpu - 1.5) cores, seats * memory + 256M, seats * 512 tasks, CPUWeight 50."""
    s = seats(cfg, ncpu, mem_total)
    mem_mb = _cfg_int(cfg, "rbrowser_memory_mb", 2048, 1024, 4096)
    quota = max(CPU_FLOOR, min(s["max"] * s["cpu_percent"], int((float(ncpu) - 1.5) * 100)))
    return ["CPUWeight=50", f"CPUQuota={quota}%", f"MemoryMax={s['max'] * mem_mb + 256}M", f"TasksMax={s['max'] * 512}"]


# ---------------------------------------------------------------- 6.4 the firewall chain: the upload limit only
#
# The chain PORTAL-RB is reached from OUTPUT through a cgroup match on the slice (xt_cgroup, cgroup v2 path). Since D1 it
# holds ONE rule, the hashlimit rule of the upload limit (rbrowser_upload_kbps 500 or more); the listener control is
# the ingress BPF filter of rbrowser_bpf (an iptables rule cannot see the SYN-ACK of a request socket). So the chain
# is optional: without iptables, ip6tables or with the setting at 0 there is no limiter and nothing else changes.
# The jump is inserted LAST, at position 1 of OUTPUT, so the chain is complete when it becomes active.

FIREWALL_TOOLS = ("iptables", "ip6tables")
JUMP_DELETE_MAX = 5                # a stale or doubled jump is removed at most this many times


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def upload_rule_args(kbps: int) -> dict:
    """The rule arguments of design 6.4 (without the program and without -w / -C / -A / -I):
    {"limit": [...], "jump": [...]}. The setting is kilobits per second: rate = ceil(kbps / 8) kb/s
    and burst = ceil(kbps / 4) kb, rounded up so the limit is never below the setting (500 kbps -> 63kb/s, 125kb).
    Raises ValueError outside 500..50000 (below that there is no chain at all)."""
    if isinstance(kbps, bool) or not isinstance(kbps, int) or not (500 <= kbps <= 50000):
        raise ValueError("upload kbps must be 500 to 50000")
    return {
        "limit": ["-m", "hashlimit", "--hashlimit-name", "portalrb",
                  "--hashlimit-above", f"{_ceil_div(kbps, 8)}kb/s",
                  "--hashlimit-burst", f"{_ceil_div(kbps, 4)}kb", "-j", "DROP"],
        "jump": ["-m", "cgroup", "--path", SLICE_CGROUP, "-j", CHAIN],
    }


def firewall_commands(tool: str, kbps: int) -> dict:
    """Every command (argument lists) for one of iptables / ip6tables; kbps must be valid for upload_rule_args.
    {"chain_exists", "new_chain", "flush", "check_limit", "add_limit", "check_jump", "delete_jump", "insert_jump"}.
    `-w 2` waits for the xtables lock."""
    r = upload_rule_args(kbps)
    limit, jump = r["limit"], r["jump"]
    w = [tool, "-w", "2"]
    return {
        "chain_exists": w + ["-S", CHAIN],
        "new_chain": w + ["-N", CHAIN],
        "flush": w + ["-F", CHAIN],
        "check_limit": w + ["-C", CHAIN] + limit,
        "add_limit": w + ["-A", CHAIN] + limit,
        "check_jump": w + ["-C", "OUTPUT"] + jump,
        "delete_jump": w + ["-D", "OUTPUT"] + jump,
        "insert_jump": w + ["-I", "OUTPUT", "1"] + jump,
    }


def firewall_removal(tool: str) -> dict:
    """Commands that take the chain away: `-C` then `-D` for the jump (repeated while it is found), flush, delete."""
    w = [tool, "-w", "2"]
    jump = ["-m", "cgroup", "--path", SLICE_CGROUP, "-j", CHAIN]
    return {"check_jump": w + ["-C", "OUTPUT"] + jump, "delete_jump": w + ["-D", "OUTPUT"] + jump,
            "flush": w + ["-F", CHAIN], "delete_chain": w + ["-X", CHAIN]}


async def install_firewall(run, which, kbps: int) -> tuple:
    """(True, "") or (False, reason). Idempotent and verified, for iptables and ip6tables; both must succeed, else
    whatever was installed is removed again. kbps is 500..50000 (the caller does not call this for a limiter that is off).

    Per tool: create the chain when `-S` says it is missing; take away every jump to the chain that is already in
    OUTPUT (a `-C` on the jump says nothing about a rule that is stale: the match holds the cgroup that existed when
    the rule was inserted, and a slice that was stopped and started again is a new cgroup under the same path, so a
    jump that is merely present is never trusted); flush the chain; add the limit rule; insert the jump at position 1
    of OUTPUT; verify the limit rule and the jump with `-C`. While the jump is out the slice has no limiter, so this
    runs before any session unit exists."""
    tools = {}
    for name in FIREWALL_TOOLS:
        tool = which(name)
        if not tool:
            return False, f"{name} not found"
        tools[name] = tool
    try:
        cmds = {name: firewall_commands(tool, kbps) for name, tool in tools.items()}
    except ValueError:
        return False, "bad upload setting"

    async def fail(name, what):
        await remove_firewall(run, which)
        return False, f"{name}: {what}"

    for name, c in cmds.items():
        if (await run(c["chain_exists"])).rc != 0 and (await run(c["new_chain"])).rc != 0:
            return await fail(name, "the chain could not be created")
        for _ in range(JUMP_DELETE_MAX):
            if (await run(c["check_jump"])).rc != 0:
                break
            if (await run(c["delete_jump"])).rc != 0:
                return await fail(name, "an old jump could not be removed")
        else:
            if (await run(c["check_jump"])).rc == 0:
                return await fail(name, "too many old jumps")
        if (await run(c["flush"])).rc != 0:
            return await fail(name, "the chain could not be flushed")
        if (await run(c["add_limit"])).rc != 0:
            return await fail(name, "the limit rule could not be added")
        if (await run(c["insert_jump"])).rc != 0:
            return await fail(name, "the cgroup jump could not be inserted")
        for key, what in (("check_limit", "the limit rule"), ("check_jump", "the cgroup jump")):
            if (await run(c[key])).rc != 0:
                return await fail(name, f"{what} could not be verified")
    return True, ""


async def remove_firewall(run, which) -> None:
    for name in FIREWALL_TOOLS:
        tool = which(name)
        if not tool:
            continue
        c = firewall_removal(tool)
        for _ in range(JUMP_DELETE_MAX):
            if (await run(c["check_jump"])).rc != 0:
                break
            if (await run(c["delete_jump"])).rc != 0:
                break
        await run(c["flush"])
        await run(c["delete_chain"])


# ---------------------------------------------------------------- 8.2 the probe's targets file

PROBE_TARGETS_NAME = "probe-targets.json"     # inside STATIC_DIR/bin, so /mnt/probe-targets.json in the unit
PROBE_FIXED_TARGETS = (
    ("127.0.0.1", "PORT"), ("::1", "PORT"), ("0.0.0.0", "PORT"), ("::ffff:127.0.0.1", "PORT"),
    ("::ffff:a9fe:a9fe", 80), ("169.254.169.254", 80), ("168.63.129.16", 80), ("168.63.129.16", 32526),
)
PROBE_EXPECT = {"work_mb": 768, "shm_mb": 64, "run_kb": 64, "runtime_mb": 8, "tmp_mb": TMP_MB}


def probe_targets(portal_port: int, iface_addrs, gateways, resolvers, hidden_extra=()) -> dict:
    """The JSON document probe.py reads (design 8.2 check 1 and 4): the fixed destinations on the portal's port,
    every interface address, gateway and resolver on port 53 and the portal's port, the hidden-path list, the
    expected sizes. Addresses are plain IP literals. An IPv6 link-local address is kept only when it carries its
    zone (fe80::1%eth0, as rbrowser_policy.parse_proc_net_ipv6_route_scoped gives a gateway): connecting to one
    needs the scope, and the usual IPv6 default gateway IS link-local, so leaving it out would leave "every
    gateway" untested. Without a zone it is left out; for any other address the zone is dropped.
    Raises ValueError on a bad port, address or zone."""
    if isinstance(portal_port, bool) or not isinstance(portal_port, int) or not (1 <= portal_port <= 65535):
        raise ValueError("bad portal port")
    out, seen = [], set()

    def add(host, port):
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append({"host": host, "port": port})

    for host, port in PROBE_FIXED_TARGETS:
        add(host, portal_port if port == "PORT" else port)
    for addr in list(iface_addrs or []) + list(gateways or []) + list(resolvers or []):
        text, _, zone = str(addr).partition("%")
        a = ipaddress.ip_address(text)
        host = str(a)
        if a.version == 6 and a.is_link_local:
            if not zone:
                continue
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,15}", zone):
                raise ValueError("bad zone id")
            host = f"{host}%{zone}"
        add(host, 53)
        add(host, portal_port)
    return {"version": 1, "tcp_denied": out, "hidden_paths": hidden_paths(hidden_extra), "expect": dict(PROBE_EXPECT)}


# ---------------------------------------------------------------- 4.1 host preparation

@dataclass
class HostPaths:
    static: str = STATIC_DIR
    run_dir: str = RUN_DIR
    state: str = STATE_DIR
    tmp_dir: str = RUN_TMP


MASTER_PREFERENCES = (
    '{"distribution": {"import_bookmarks": false, "import_history": false, "import_home_page": false, '
    '"import_search_engine": false, "make_chrome_default": false, "make_chrome_default_for_user": false, '
    '"skip_first_run_ui": true, "suppress_first_run_default_browser_prompt": true, "show_welcome_page": false}}\n')
CHROMIUM_D_README = "# Debian's default flag files are replaced by this directory on purpose: no extra flags.\n"


def _mkdir(path: str, mode: int):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)


def _write_atomic(path: str, data: bytes, mode: int = 0o644):
    tmp = f"{path}.new{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_static_tree(paths: HostPaths, policy: dict, source_dir=None) -> None:
    """Design 4.1 item 1: root-owned (the caller is root), directories 0755, files 0644. Each file is replaced
    atomically, so a running Chromium never reads half a policy. Raises LaunchError when a script is missing."""
    src = Path(source_dir) if source_dir else Path(__file__).resolve().parent / "rbrowser_unit"
    scripts = {}
    for name in ("session.py", "probe.py"):
        f = src / name
        if not f.is_file():
            raise LaunchError(f"{name} is missing from the unit directory")
        scripts[name] = f.read_bytes()
    s = paths.static
    for d in (s, f"{s}/bin", f"{s}/chromium", f"{s}/chromium/policies", f"{s}/chromium/policies/managed",
              f"{s}/chromium/policies/recommended", f"{s}/chromium.d", f"{s}/chromium-probe", f"{s}/chromium-probe/policies",
              f"{s}/chromium-probe/policies/managed", f"{s}/chromium-probe/policies/recommended"):
        _mkdir(d, 0o755)
    for name, data in scripts.items():
        _write_atomic(f"{s}/bin/{name}", data)
    _write_atomic(f"{s}/chromium/policies/managed/portal.json", rbrowser_policy.policy_text(policy).encode())
    # The placeholder a session's theme file is bound over (build_unit_args): an empty policy document, so a session without a theme
    # reads nothing from it. Only the session tree has it; the probe tree never does.
    _write_atomic(f"{s}/chromium/policies/managed/{THEME_FILE}", rbrowser_policy.THEME_PLACEHOLDER_TEXT.encode())
    _write_atomic(f"{s}/chromium/master_preferences", MASTER_PREFERENCES.encode())
    _write_atomic(f"{s}/chromium-probe/policies/managed/portal.json", rbrowser_policy.policy_text(rbrowser_policy.probe_policy(policy)).encode())
    _write_atomic(f"{s}/chromium-probe/master_preferences", MASTER_PREFERENCES.encode())
    _write_atomic(f"{s}/chromium.d/README", CHROMIUM_D_README.encode())


def write_probe_targets(paths: HostPaths, targets: dict) -> None:
    """Write the probe's targets file into the static tree (root-owned, 0644, replaced atomically)."""
    import json
    d = f"{paths.static}/bin"
    _mkdir(d, 0o755)
    _write_atomic(f"{d}/{PROBE_TARGETS_NAME}", (json.dumps(targets, indent=1, sort_keys=True) + "\n").encode())


def write_policy(paths: HostPaths, policy: dict) -> None:
    """Replace only the managed policy file (a new home URL or a new set of literal hosts)."""
    for sub, doc in (("chromium", policy), ("chromium-probe", rbrowser_policy.probe_policy(policy))):
        d = f"{paths.static}/{sub}/policies/managed"
        _mkdir(d, 0o755)
        _write_atomic(f"{d}/portal.json", rbrowser_policy.policy_text(doc).encode())


def parse_mountinfo(text: str) -> dict:
    """{mount point: filesystem type} from a mountinfo text."""
    out = {}
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        f = left.split()
        if not sep or len(f) < 5:
            continue
        mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[4])
        out[mp] = right.split()[0] if right.split() else ""
    return out


def parse_mountinfo_dev(text: str) -> dict:
    """{mount point: (filesystem type, "major:minor")} from a mountinfo text; the device is field 3 (the mount's superblock device,
    the same number os.stat(path).st_dev has for a file of that mount). A later line for the same mount point wins (the top mount)."""
    out = {}
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        f = left.split()
        if not sep or len(f) < 5:
            continue
        mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[4])
        out[mp] = (right.split()[0] if right.split() else "", f[2])
    return out


def dev_of(path: str) -> str:
    """"major:minor" of the file system that holds `path` as THIS process sees it ('' when it cannot be read)."""
    try:
        d = os.stat(path).st_dev
    except OSError:
        return ""
    return f"{os.major(d)}:{os.minor(d)}"


def read_host_mountinfo() -> str | None:
    """PID 1's mount table (the host's namespace; the portal's own table is a different one). None when it cannot
    be read or is empty: the callers fail closed, an unreadable table is not an empty one (a tmpfs would be mounted on top of a
    tmpfs again)."""
    try:
        with open(HOST_MOUNTINFO, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    return text or None


def host_mount_problem(path: str, table: dict, want_dev_of=dev_of) -> str:
    """'' when `path` is a tmpfs of the HOST's mount table and the directory this process sees there is that very tmpfs (device
    numbers agree), else a short reason. The device check catches a mount that did not propagate into this namespace, a stale private
    mount of an earlier run, and a plain directory hidden under the host's mount."""
    ent = table.get(path)
    if ent is None:
        return "not mounted in the host's namespace"
    if ent[0] != "tmpfs":
        return f"something other than a tmpfs is mounted there ({ent[0] or '?'})"
    mine = want_dev_of(path)
    if not mine or mine != ent[1]:
        return "the directory this process sees is not the host's tmpfs (the mount did not reach this namespace)"
    return ""


async def host_run(run, which, argv: list, *, prefix: str = HELPER_PREFIX, timeout: float = HELPER_TIMEOUT) -> "Ran":
    """Run `argv` (absolute path first) in the HOST's mount namespace: a transient oneshot unit that PID 1 starts, waited for.
    The unit has no namespace properties, so it sees what PID 1 sees; its mounts are the host's and propagate to the portal's
    slave namespace. systemd-run --wait answers with the command's exit status. TimeoutStartSec= bounds a command that hangs
    (a oneshot unit is `activating` while it runs); RuntimeMaxSec= is kept as the second bound.

    When the client side times out (rc 124: systemd-run was killed, the unit may still be queued or running) the unit is stopped
    BY NAME and the stop is confirmed with `systemctl show`; the answer stays rc 124 and `err` says whether the unit is gone.
    When the caller cancels the await, the unit is stopped and confirmed the same way before CancelledError goes on (so the lock
    of prepare_host and unprepare_host is not released while the helper still runs)."""
    _need(prefix in HELPER_PREFIXES, "unknown helper unit prefix")
    sysrun = which("systemd-run")
    if not sysrun:
        return Ran(127, "", "systemd-run not found")
    unit = f"{prefix}{secrets.token_hex(6)}.service"
    secs = int(timeout)
    try:
        r = await run([sysrun, f"--unit={unit}", "--wait", "--collect", "--quiet", "--description=Open Relay Portal host mount helper",
                       "-p", "Type=oneshot", "-p", f"TimeoutStartSec={secs}", "-p", f"RuntimeMaxSec={secs}", "--"] + list(argv), timeout)
    except asyncio.CancelledError:
        # The caller gave up (asyncio.wait_for, a cancelled task): systemd-run is gone but PID 1 may still run the helper. Stop it by
        # name BEFORE the caller's lock is released, and finish that even when the cancel is repeated; then let the cancel go on.
        gone, _ = await _stop_helper_held(run, which, unit)
        if not gone:
            log.warning("rbrowser: host helper unit %s could not be confirmed stopped after a cancel", unit)     # the unit name only
        raise
    if r.rc == 124:
        gone, cancelled = await _stop_helper_held(run, which, unit)      # the same stopper as the cancel path: a cancel now does not cut it short
        if cancelled:
            if not gone:
                log.warning("rbrowser: host helper unit %s could not be confirmed stopped after a cancel", unit)
            raise asyncio.CancelledError()
        return Ran(124, r.out, "timeout" + ("; the helper unit was stopped" if gone else "; the helper unit could not be confirmed stopped"))
    return r


async def _stop_helper_held(run, which, unit: str):
    """_stop_helper as a task of its own, awaited through shield(): a cancellation of the caller (a repeated one too) does not
    abandon the stop half way. -> (the unit is confirmed stopped, a cancellation arrived meanwhile). Never raises."""
    stopper = asyncio.ensure_future(_stop_helper(run, which, unit))
    cancelled = False
    while not stopper.done():
        try:
            await asyncio.shield(stopper)
        except asyncio.CancelledError:
            if stopper.cancelled():
                break          # the stop task itself was cancelled (the loop is shutting down): nothing more to wait for
            cancelled = True
        except Exception:
            break
    gone = False
    if stopper.done() and not stopper.cancelled() and stopper.exception() is None:
        gone = bool(stopper.result())
    return gone, cancelled


async def _stop_helper(run, which, unit: str) -> bool:
    """Stop a helper unit by name and confirm it (`show` says inactive or failed; a unit that does not exist is inactive).
    A second try uses SIGKILL. False when it is still there or systemd does not answer."""
    systemctl = which("systemctl") or "systemctl"
    for kill in (False, True):
        try:
            if kill:
                await run([systemctl, "kill", "-s", "SIGKILL", unit], 10.0)
            await run([systemctl, "stop", unit], 15.0)
            r = await run([systemctl, "show", "-p", "ActiveState", unit], 10.0)
        except Exception:
            return False
        state = ""
        for line in r.out.splitlines():
            if line.startswith("ActiveState="):
                state = line.partition("=")[2].strip()
        if r.rc == 0 and state in ("inactive", "failed"):
            return True
    return False


# One lock for prepare_host and unprepare_host: a mount, a slice change or a pin removal of one must not interleave with the other.
_HOST_LOCK = asyncio.Lock()


def parse_meminfo(text: str) -> int:
    """MemTotal in bytes."""
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    raise ValueError("no MemTotal")


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


async def _prepare_host(cfg, *, policy: dict, run=default_run, ncpu=None, mem_total=None, paths: HostPaths | None = None,
                       mountinfo=None, source_dir=None, which=find_tool, probe_targets_doc: dict | None = None,
                       bpf=rbrowser_bpf, bpf_base: str | None = None, helper_prefix: str = HELPER_PREFIX, want_dev_of=dev_of) -> dict:
    """Idempotent, root. The ingress filter (loaded and pinned), static tree, 8 MiB tmpfs, state directory, slice
    properties, the upload limiter's firewall chain.

    The two tmpfs are mounted in the HOST's mount namespace (host_run: a oneshot unit started by PID 1) and the "already
    mounted" question is asked of PID 1's mount table (/proc/1/mountinfo), because the portal itself runs in a private mount
    namespace and systemd resolves RuntimeDirectory= and BindPaths= in the host's. `mountinfo` is a text, or a callable that
    returns one (read again after each mount to prove that the mount is the host's and is visible here: device numbers agree);
    a text is used as it is and is not read again. An unreadable host mount table makes the host not ok.

    Returns {"ok", "reasons", "slice_ok", "slice_started", "ingress_filter", "ingress_pin", "firewall", "firewall_reason",
    "upload_rule", "upload_reason", "seats"}. ok is False when the ingress filter could not be loaded and pinned (the
    listener control of D1: nothing is changed then), or the static tree, the tmpfs or the state directory failed: the
    feature stays unavailable. `ingress_pin` is the path every unit names in IPIngressFilterPath= (build_unit_args);
    the pin must outlive every unit that names it, so nothing here removes one (unprepare_host does, with no unit
    left; pruning old pins with prune_stale(keep=<pins of running units>) is the registry's job). A failed slice is not
    fatal (G8: `slice_ok` False tells the caller to halve the seats). The firewall chain holds the upload limit only
    and is OPTIONAL: without iptables / ip6tables, with rbrowser_upload_kbps 0 (or below 500) or when installing it
    fails, `ok` stays True, `upload_rule` is False and `upload_reason` says why.

    Call it again after the slice has been stopped and started: the jump holds the cgroup of the slice as it was when
    the rule was inserted, and install_firewall replaces it."""
    paths = paths or HostPaths()
    ncpu = ncpu or os.cpu_count() or 1
    if mem_total is None:
        mem_total = parse_meminfo(_read("/proc/meminfo"))
    res = {"ok": True, "reasons": [], "slice_ok": False, "slice_started": False, "ingress_filter": False, "ingress_pin": "",
           "firewall": False, "firewall_reason": "", "upload_rule": False, "upload_reason": "", "seats": seats(cfg, ncpu, mem_total)}
    # the listener control first: nothing is changed on a host that cannot hold it
    base = bpf_base or bpf.PIN_BASE
    avail_ok, why = bpf.available(os.path.dirname(base) or rbrowser_bpf.PIN_DIR)
    if not avail_ok:
        res["ok"] = False
        res["reasons"].append(f"ingress filter: {why}")
        return res
    try:
        pinned = bpf.load_and_pin(base)
        res["ingress_pin"] = check_ingress_pin(pinned["path"])
        res["ingress_filter"] = True
    except (rbrowser_bpf.BpfError, LaunchError, OSError, KeyError) as e:
        res["ok"] = False
        res["reasons"].append(f"ingress filter: {str(e).splitlines()[0][:200] if str(e) else e.__class__.__name__}")
        return res
    try:
        write_static_tree(paths, policy, source_dir)
        if probe_targets_doc is not None:
            write_probe_targets(paths, probe_targets_doc)
    except (LaunchError, OSError) as e:
        res["ok"] = False
        res["reasons"].append(f"static tree: {e}")
        return res
    # the session socket area (8 MiB) and the units' /tmp area (D6, 32 MiB): a tmpfs of their own each
    def table():
        t = mountinfo() if callable(mountinfo) else (mountinfo if mountinfo is not None else read_host_mountinfo())
        return None if t is None else parse_mountinfo_dev(t)
    mounts = table()
    if mounts is None:
        res["ok"] = False
        res["reasons"].append(f"the host's mount table ({HOST_MOUNTINFO}) could not be read")
        return res
    for what, path, options, label in (("session area", paths.run_dir, TMPFS_OPTIONS, "portal-rb"),
                                       ("tmp area", paths.tmp_dir, TMP_OPTIONS, "portal-rb-tmp")):
        try:
            _mkdir(path, 0o755)
        except OSError as e:
            res["ok"] = False
            res["reasons"].append(f"mount point: {e}")
            return res
        if path in mounts and mounts[path][0] != "tmpfs":
            res["ok"] = False
            res["reasons"].append(f"something other than a tmpfs is mounted on the {what}")
            return res
        if path == paths.tmp_dir and path in mounts:
            try:
                os.chmod(path, 0o700)       # a mount of an earlier run may still be 0755
            except OSError:
                pass
        if path not in mounts:
            mount = which("mount")
            r = await host_run(run, which, [mount, "-t", "tmpfs", "-o", options, label, path], prefix=helper_prefix) if mount else Ran(127)
            if r.rc != 0:
                res["ok"] = False
                res["reasons"].append(f"the {what} tmpfs could not be mounted")
                return res
        if callable(mountinfo) or mountinfo is None:
            # the mount (new or old) must be the host's AND be what this process sees at the path
            after = table()
            why = "the host's mount table could not be read again" if after is None else host_mount_problem(path, after, want_dev_of)
            if why:
                res["ok"] = False
                res["reasons"].append(f"the {what} tmpfs: {why}")
                return res
            mounts = after
    try:
        _mkdir(paths.state, 0o700)
    except OSError as e:
        res["ok"] = False
        res["reasons"].append(f"state directory: {e}")
        return res
    systemctl = which("systemctl")
    props = slice_properties(cfg, ncpu, mem_total)
    r = await run([systemctl, "set-property", "--runtime", SLICE] + props) if systemctl else Ran(127)
    res["slice_ok"] = r.rc == 0
    if not res["slice_ok"]:
        res["reasons"].append("slice properties could not be set")
    # The firewall's cgroup match names the slice's cgroup directory, and the kernel looks it up when the rule
    # is inserted: `set-property --runtime` does not start the slice, so on a fresh boot there may be no such
    # directory yet. Start the slice first (an empty slice is harmless); unprepare_host stops it again.
    if systemctl:
        res["slice_started"] = (await run([systemctl, "start", SLICE])).rc == 0
        if not res["slice_started"]:
            res["reasons"].append("the slice could not be started")
    kbps = _cfg_int(cfg, "rbrowser_upload_kbps", 4000, 0, 50000)
    missing = [n for n in FIREWALL_TOOLS if not which(n)]
    if kbps == 0:
        res["upload_reason"] = "off by setting"
    elif kbps < 500:
        res["upload_reason"] = "setting below 500"
    elif missing:
        res["upload_reason"] = f"{missing[0]} not found"
    if res["upload_reason"]:
        # no limiter: a chain left by an earlier run would still limit, so it is taken away (when the tools are there)
        if not missing:
            await remove_firewall(run, which)
        return res
    ok, why = await install_firewall(run, which, kbps)
    res["firewall"], res["firewall_reason"] = ok, why
    if ok:
        res["upload_rule"] = True
    else:
        res["upload_reason"] = why
        res["reasons"].append(f"upload limit: {why}")
    return res


async def prepare_host(*args, **kw) -> dict:
    async with _HOST_LOCK:
        return await _prepare_host(*args, **kw)


prepare_host.__doc__ = _prepare_host.__doc__


# What prepare_host's `systemctl set-property --runtime` leaves behind: drop-ins in this directory (slice_properties
# names the properties; a test keeps the two in step). unprepare_host removes exactly those and nothing else.
SLICE_DROPIN_DIR = "/run/systemd/system.control/system-portalrb.slice.d"
SLICE_PROPERTY_NAMES = ("CPUWeight", "CPUQuota", "MemoryMax", "TasksMax")


def is_own_dropin(text: str) -> bool:
    """True when a drop-in file holds nothing but assignments of the properties prepare_host sets (and comments, blank
    lines and the [Slice] header): one that also holds anything else belongs to somebody else and is left alone."""
    n = 0
    for line in (text or "").splitlines():
        t = line.strip()
        if not t or t[0] in "#;" or t == "[Slice]":
            continue
        key, sep, _ = t.partition("=")
        if not sep or key.strip() not in SLICE_PROPERTY_NAMES:
            return False
        n += 1
    return n > 0


def remove_slice_dropins(dropin_dir: str = SLICE_DROPIN_DIR) -> list:
    """Delete the runtime drop-ins that prepare_host wrote (see is_own_dropin), then the directory if it is empty.
    Never follows a link. Returns the file names removed. `systemctl revert` is not used: it would also delete an
    operator's drop-ins and unit file and unmask the unit."""
    removed = []
    try:
        names = sorted(os.listdir(dropin_dir))
    except OSError:
        return removed
    for n in names:
        f = os.path.join(dropin_dir, n)
        if not n.endswith(".conf") or os.path.islink(f) or not os.path.isfile(f):
            continue
        if is_own_dropin(_read(f)):
            try:
                os.unlink(f)
                removed.append(n)
            except OSError:
                pass
    try:
        os.rmdir(dropin_dir)
    except OSError:
        pass
    return removed


def slice_children(cgroup_root: str = None) -> list | None:
    """Names of the child cgroups of the portal-rb slice (one per unit, any prefix: portal-rb-, portal-rbprobe-, portal-rbtest-),
    read from the cgroup file system and not from anybody's count. [] when the slice has no cgroup directory (it is not started
    or already stopped); None when it cannot be read (fail closed: unknown is not empty)."""
    root = CGROUP_ROOT if cgroup_root is None else cgroup_root
    d = os.path.join(root, SLICE_CGROUP)
    try:
        names = os.listdir(d)
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError:
        return None
    out = []
    for n in names:
        try:
            if os.path.isdir(os.path.join(d, n)) and not os.path.islink(os.path.join(d, n)):
                out.append(n)
        except OSError:
            return None
    return sorted(out)


async def _unprepare_host(*, run=default_run, paths: HostPaths | None = None, mountinfo=None, units_left: int = 0,
                         which=find_tool, dropin_dir: str = SLICE_DROPIN_DIR, bpf=rbrowser_bpf, bpf_pin: str | None = None,
                         cgroup_root: str | None = None, helper_prefix: str = HELPER_PREFIX) -> dict:
    """Undo what prepare_host did (the unmount runs in the host's namespace like the mount did, and the mount table is PID 1's): the firewall chain, the slice's runtime properties, the slice itself, the tmpfs and the
    ingress filter's pin (`bpf_pin`: the "ingress_pin" prepare_host returned; None = the pin of the current program; '' = do
    not touch any pin, for a caller that never created one). All of it stays while a session unit is left (units_left > 0): the
    pin above all, because a pin that is gone when systemd re-applies a running unit's BPF firewall silently detaches the
    filter (rbrowser_bpf docstring).

    The pin does not rest on the caller's count: it goes LAST, and only when the slice was stopped (`systemctl stop` rc 0) and
    its cgroup has no child directory any more (slice_children, read from `cgroup_root`). Otherwise it stays and
    `pin_kept` is True. `slice_children` is returned for the caller's log.

    The slice properties are undone by removing the drop-ins that prepare_host wrote and a `daemon-reload`, not by
    `systemctl revert` (which would also delete an operator's drop-ins and unmask the unit)."""
    paths = paths or HostPaths()
    res = {"unmounted": False, "kept": False, "firewall_removed": False, "dropins_removed": [], "daemon_reloaded": False,
           "slice_stopped": False, "pin_removed": False, "pin_kept": False, "slice_children": None, "mounts_unreadable": False}
    if units_left > 0:
        res["pin_kept"] = True
    else:
        await remove_firewall(run, which)
        res["firewall_removed"] = True
        systemctl = which("systemctl")
        res["dropins_removed"] = remove_slice_dropins(dropin_dir)
        if systemctl:
            if res["dropins_removed"]:
                res["daemon_reloaded"] = (await run([systemctl, "daemon-reload"])).rc == 0
            # prepare_host started the slice; with no unit left in it nothing is lost by stopping it
            res["slice_stopped"] = (await run([systemctl, "stop", SLICE])).rc == 0
        # the pin last: only a stopped slice with no unit cgroup in it (a unit that the caller did not count would lose its
        # filter at the next re-apply of its BPF firewall)
        res["slice_children"] = slice_children(cgroup_root)
        if bpf_pin == "":
            pass
        elif res["slice_stopped"] and res["slice_children"] == []:
            try:
                res["pin_removed"] = bool(bpf.unpin(bpf_pin or bpf.pin_path()))
            except (rbrowser_bpf.BpfError, OSError):
                pass
        else:
            res["pin_kept"] = True
    text = mountinfo() if callable(mountinfo) else (mountinfo if mountinfo is not None else read_host_mountinfo())
    if text is None:
        res["mounts_unreadable"] = True      # nothing is unmounted on a guess
        return res
    mounts = parse_mountinfo(text)
    if paths.run_dir in mounts or paths.tmp_dir in mounts:
        if units_left > 0 or res["slice_children"] != []:
            res["kept"] = True      # a unit that is still there has these directories bound
        else:
            umount = which("umount")
            done = []
            for path in (paths.run_dir, paths.tmp_dir):
                if path in mounts and umount:
                    done.append((await host_run(run, which, [umount, path], prefix=helper_prefix)).rc == 0)
            res["unmounted"] = bool(done) and all(done)
    return res


async def unprepare_host(*args, **kw) -> dict:
    async with _HOST_LOCK:
        return await _unprepare_host(*args, **kw)


unprepare_host.__doc__ = _unprepare_host.__doc__


# ---------------------------------------------------------------- 8.2 availability

@dataclass
class HostProbe:
    """Everything availability() reads from the host, replaceable by tests. Nothing here starts a process."""
    euid: object = os.geteuid
    exists: object = os.path.exists
    which: object = find_tool
    read: object = _read
    realpath: object = os.path.realpath
    mtime: object = lambda p: os.stat(p).st_mtime
    now: object = time.time
    systemd_version: object = None      # callable() -> int | None; default reads libsystemd-shared-NNN.so
    bpf_available: object = None        # callable() -> (bool, reason); default rbrowser_bpf.available
    chromium_version: object = None     # callable(binary_name) -> str; default reads the dpkg status file
    read_head: object = None            # callable(path) -> bytes; default reads 2048 bytes


def _systemd_version_from_files():
    best = None
    for pat in ("/usr/lib/systemd/libsystemd-shared-*.so", "/lib/systemd/libsystemd-shared-*.so",
                "/usr/lib/*/systemd/libsystemd-shared-*.so", "/lib/*/systemd/libsystemd-shared-*.so"):
        for f in glob.glob(pat):
            m = re.search(r"libsystemd-shared-(\d+)", f)
            if m:
                v = int(m.group(1))
                best = v if best is None else max(best, v)
    return best


def _dpkg_version(name: str) -> str:
    text = _read("/var/lib/dpkg/status")
    for para in text.split("\n\n"):
        if para.startswith(f"Package: {name}\n"):
            for line in para.splitlines():
                if line.startswith("Version:"):
                    v = line.split(":", 1)[1].strip()
                    v = v.split(":", 1)[-1] if re.match(r"\d+:", v) else v
                    return v.split("-", 1)[0]
    return ""


def _read_head(path):
    try:
        with open(path, "rb") as f:
            return f.read(2048)
    except OSError:
        return b""


_AVAIL_CACHE = {"at": 0.0, "value": None}


def availability(*, stage_mode: bool = False, probe: HostProbe | None = None, use_cache: bool = True) -> dict:
    """Design 8.2. Cheap, starts nothing: file reads and PATH lookups only, cached 60 s (not when a probe is
    injected). `stage_mode` is passed in by the caller (Config.STAGE_MODE).

    -> {"available", "missing", "reasons", "chromium_version", "chromium_age_days", "kernel_upload_limit",
        "paths": {"chromium": ...}}

    Unknown values: a systemd version that cannot be read makes the feature unavailable (reason given); an
    unknown Chromium version is '' and age None and does not block (the preflight decides)."""
    own = probe is None
    if (own and use_cache and _AVAIL_CACHE["value"] is not None and _AVAIL_CACHE.get("stage") == bool(stage_mode)
            and time.time() - _AVAIL_CACHE["at"] < 60):
        return _AVAIL_CACHE["value"]
    pr = probe or HostProbe()
    v = _availability(stage_mode, pr)
    if own and use_cache:
        _AVAIL_CACHE.update(at=time.time(), value=v, stage=bool(stage_mode))
    return v


def _availability(stage_mode: bool, pr: HostProbe) -> dict:
    out = {"available": False, "missing": [], "reasons": [], "chromium_version": "", "chromium_age_days": None,
           "kernel_upload_limit": False, "paths": {"chromium": ""}}
    if stage_mode:
        out["reasons"].append("stage mode: no browser unit is ever started")
        return out
    if pr.euid() != 0:
        out["reasons"].append("the portal does not run as root")
        return out
    reasons, missing = out["reasons"], out["missing"]
    if not pr.exists("/run/systemd/system"):
        reasons.append("systemd is not the init system")
    for tool in ("systemd-run", "systemctl", "mount"):
        if not pr.which(tool):
            missing.append(tool)
            reasons.append(f"{tool} not found")
    sv = (pr.systemd_version or _systemd_version_from_files)()
    if sv is None:
        reasons.append("the systemd version could not be read")
    elif sv < SYSTEMD_MIN:
        reasons.append(f"systemd {sv} is older than {SYSTEMD_MIN} (SocketBindDeny)")
    if not pr.exists("/sys/fs/cgroup/cgroup.controllers"):
        reasons.append("cgroup v2 is not mounted")
    # the listener control (D1): the ingress filter has to be loadable and pinnable here
    try:
        bpf_ok, bpf_why = (pr.bpf_available or rbrowser_bpf.available)()
    except Exception as e:      # a check that cannot run is a refusal
        bpf_ok, bpf_why = False, e.__class__.__name__
    if not bpf_ok:
        reasons.append(f"ingress filter: {bpf_why}")
    # binaries
    chromium = ""
    for name in ("chromium", "chromium-browser"):
        c = pr.which(name)
        if c:
            chromium = c
            out["paths"]["chromium"] = c
            chromium_name = name
            break
    head_fn = pr.read_head or _read_head
    if not chromium:
        missing.append("chromium")
        reasons.append("Chromium not found")
    else:
        real = pr.realpath(chromium)
        if chromium.startswith("/snap/") or real.startswith("/snap/") or b"/snap/" in head_fn(real)[:2048]:
            missing.append("chromium")
            reasons.append("Chromium is a snap package: its sandbox does not work in the unit")
            out["paths"]["chromium"] = ""
        else:
            try:
                out["chromium_age_days"] = max(0, int((pr.now() - pr.mtime(real)) // 86400))
            except OSError:
                pass
            out["chromium_version"] = (pr.chromium_version or _dpkg_version)(chromium_name)
    for tool in ("Xvfb", "x11vnc", "xauth", "xrandr", "xsel"):
        if not pr.which(tool):
            missing.append(tool)
            reasons.append(f"{tool} not found")
    if not pr.exists("/usr/bin/python3"):
        missing.append("python3")
        reasons.append("/usr/bin/python3 not found")
    # unprivileged user namespaces: Chromium's own sandbox needs them, --no-sandbox is never used
    try:
        maxns = int((pr.read("/proc/sys/user/max_user_namespaces") or "0").strip() or "0")
    except ValueError:
        maxns = 0
    if maxns <= 0:
        reasons.append("user namespaces are disabled (max_user_namespaces)")
    clone = pr.read("/proc/sys/kernel/unprivileged_userns_clone")
    if pr.exists("/proc/sys/kernel/unprivileged_userns_clone") and clone.strip() != "1":
        reasons.append("unprivileged user namespaces are disabled (unprivileged_userns_clone)")
    # iptables and ip6tables only give the upload limiter (optional since D1); the key stays for the admin card
    out["kernel_upload_limit"] = bool(pr.which("iptables") and pr.which("ip6tables"))
    out["available"] = not reasons
    return out


def apt_line(missing) -> str:
    """The apt-get line for the admin card."""
    pk = []
    for m in missing:
        p = PACKAGE_OF.get(m)
        if p and p not in pk:
            pk.append(p)
    return ("apt-get install -y --no-install-recommends " + " ".join(pk)) if pk else ""


# ---------------------------------------------------------------- parsing what systemctl and /proc print

def parse_show(text: str) -> dict:
    """`systemctl show` output (blocks of Key=Value separated by blank lines) -> {Id: {Key: value}}."""
    out = {}
    for block in re.split(r"\n\s*\n", text.strip("\n")):
        d = {}
        for line in block.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                d[k] = v
        if "Id" in d:
            out[d["Id"]] = d
    return out


def parse_proc_cgroup(text: str) -> str:
    """The path of the cgroup v2 line ('0::/system.slice/...'): equal to systemctl's ControlGroup property."""
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def parse_status_uid(text: str):
    """Effective uid from /proc/<pid>/status ('Uid:\\treal\\teffective\\tsaved\\tfs'), or None."""
    for line in text.splitlines():
        if line.startswith("Uid:"):
            f = line.split()
            if len(f) >= 3 and f[2].isdigit():
                return int(f[2])
    return None


# ---------------------------------------------------------------- the launcher

CGROUP_ROOT = "/sys/fs/cgroup"


def ingress_attached(cgroup: str, pin: str, *, bpf=rbrowser_bpf, root: str = CGROUP_ROOT) -> bool:
    """True when the program behind `pin` is attached to the ingress hook of the unit's cgroup (`cgroup` as systemd
    reports it, '/system.slice/system-portalrb.slice/portal-rb-<id>.service'). Fail closed: an empty or odd path, a
    missing pin, a vanished cgroup and every error of bpf(2) answer False. This is the check for the launcher after the
    start and for the registry tick (lane A2): a pin that was removed under a running unit detaches the filter at the
    next re-apply of the unit's BPF firewall, and `attached` is what notices."""
    try:
        if (not isinstance(cgroup, str) or not cgroup.startswith("/") or ".." in cgroup.split("/")
                or "\0" in cgroup or not pin):
            return False
        return bool(bpf.attached(root + os.path.normpath(cgroup), check_ingress_pin(pin)))
    except Exception:
        return False

class SystemdLauncher:
    """Starts one transient unit per session with systemd-run. `unit_prefix` is portal-rb- (sessions),
    portal-rbprobe- (preflight) or portal-rbtest- (live test); stop() and show() refuse any other name."""

    def __init__(self, unit_prefix: str = UNIT_PREFIX, *, run=default_run, read_text=_read, sleep=asyncio.sleep,
                 script: str = "session.py", nice: int = 5, run_dir: str = RUN_DIR, which=find_tool,
                 ingress_pin: str | None = None, bpf=rbrowser_bpf, cgroup_root: str = CGROUP_ROOT, tmp_dir: str = RUN_TMP,
                 mountinfo=None, want_dev_of=dev_of, theme_dir: str = THEME_DIR, static_dir: str = STATIC_DIR):
        _need(unit_prefix in (UNIT_PREFIX, PROBE_PREFIX, TEST_PREFIX), "unknown unit prefix")
        self.unit_prefix = unit_prefix
        self.theme_dir = theme_dir          # the per-session theme files (root-only; never visible in a unit)
        self.static_dir = static_dir        # where the placeholder the theme file is bound over is looked for
        self._run = run
        self._read = read_text
        self._sleep = sleep
        self.script = script
        self.nice = nice
        self.run_dir = run_dir
        self._which = which
        self.tmp_dir = tmp_dir
        # a callable returning the text of the HOST's mount table (PID 1's, not this process's: the portal has a private mount namespace)
        self._mountinfo = mountinfo or (lambda: _read(HOST_MOUNTINFO))
        self._dev_of = want_dev_of
        self.ingress_pin = ingress_pin      # prepare_host()'s "ingress_pin"; start() refuses to run without it
        self._bpf = bpf
        self._cgroup_root = cgroup_root
        self._unit_re = re.compile(re.escape(unit_prefix) + _UNIT_RE)
        self._glob = f"{unit_prefix}{GLOB_SHOW}.service"
        self.unstopped: set = set()        # units whose stop() could not be confirmed; the registry and the sweeper keep them on their list
        self._cleanups: set = set()        # the clean-up stop tasks of start() that are still running

    def _check_unit(self, unit):
        if not isinstance(unit, str) or not self._unit_re.fullmatch(unit):
            raise LaunchError("not a unit name of this launcher")

    async def start(self, spec: LaunchSpec) -> LaunchResult:
        # The theme is cosmetic: a host whose static tree has no placeholder yet (prepare_host has not run since the upgrade) or a theme
        # file that cannot be written starts the session without it, never fails it.
        color, mode = rbrowser_policy.normalise_theme(spec.theme_color, spec.theme_mode)
        want_theme = bool(color) and self.script == "session.py" and os.path.isfile(self._placeholder())
        args = build_unit_args(spec, self.unit_prefix, self.script, self.nice, ingress_pin=self.ingress_pin,
                               theme_file=self._theme_path(spec.ident) if want_theme else None)
        sysrun = self._which("systemd-run")
        if not sysrun:
            raise LaunchError("systemd-run not found")
        unit = f"{self.unit_prefix}{spec.ident}.service"
        self.make_tmp(spec.ident)
        try:
            themed = want_theme
            if want_theme:
                try:
                    self.make_theme(spec.ident, color, mode)
                except (OSError, LaunchError):
                    themed = False
                    args = build_unit_args(spec, self.unit_prefix, self.script, self.nice, ingress_pin=self.ingress_pin)
            # Inside the try, like everything after it: a systemd-run that timed out (rc 124) or was cancelled may have queued the
            # start job (--no-block) all the same, so every way out of here takes the unit back (stopping a unit that does not
            # exist is harmless and is confirmed by show()).
            try:
                pid, cgroup = await self._spawn(sysrun, args, unit)
            except LaunchError:
                if not themed:
                    raise
                # The theme is cosmetic, so a unit that did not come up WITH the theme bind (systemd refusing the file bind, a mount
                # point it cannot make) is taken back and started once more without it, never a failed start for the member.
                left, cancelled = await self._take_back(unit)
                if cancelled:
                    raise asyncio.CancelledError()
                if left is not None:
                    raise left
                self.remove_theme(spec.ident)
                themed = False
                args = build_unit_args(spec, self.unit_prefix, self.script, self.nice, ingress_pin=self.ingress_pin)
                pid, cgroup = await self._spawn(sysrun, args, unit)
            uid = parse_status_uid(self._read(f"/proc/{pid}/status"))
            if uid is None:
                raise LaunchError("the unit's user id could not be read")
            if uid == 0:
                raise LaunchError("the unit runs as root")
            # systemd attaches the filter before it forks the first process, so it is there when the unit is `active`
            if not self.filter_attached(cgroup):
                raise LaunchError("the ingress filter is not attached to the unit")
        except BaseException as first:
            left, cancelled = await self._take_back(unit)
            if cancelled and not isinstance(first, asyncio.CancelledError):
                raise asyncio.CancelledError() from first      # a cancellation that came while the stop ran is not swallowed
            if left is not None and not isinstance(first, asyncio.CancelledError):
                raise left from first      # the caller learns that the unit may be running (it is also in self.unstopped)
            raise
        return LaunchResult(unit=unit, runtime_dir=f"{self.run_dir}/s-{spec.ident}", expect_uid=uid,
                            expect_cgroup=cgroup, main_pid=pid, ingress_pin=self.ingress_pin)

    async def _spawn(self, sysrun: str, args: list, unit: str):
        """systemd-run, then wait until the unit is `active`: (main pid, cgroup). Raises LaunchError."""
        r = await self._run([sysrun] + args, 10.0)
        if r.rc != 0:
            raise LaunchError(f"systemd-run failed ({r.rc})")
        return await self._wait_main(unit)

    async def _take_back(self, unit: str):
        """The clean-up stop of a failed or cancelled start(), run as a task of its own and awaited through shield(): a second
        cancellation cannot abandon it half way (the task goes on in the background; `self._cleanups` holds it). Returns the
        (UnitLeftRunning or None, whether a cancellation arrived meanwhile)."""
        task = asyncio.ensure_future(self._stop_quietly(unit))
        self._cleanups.add(task)
        task.add_done_callback(self._cleanups.discard)
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True    # cancelled again: the stop is not abandoned, the cancellation is passed on afterwards
            except Exception:
                break
        return (task.result() if not task.cancelled() else UnitLeftRunning(unit)), cancelled

    async def _stop_quietly(self, unit: str):
        try:
            await self.stop(unit)
            return None
        except UnitLeftRunning as e:
            return e
        except Exception:
            return UnitLeftRunning(unit)

    def make_tmp(self, ident: str) -> None:
        """The unit's /tmp and /var/tmp (D6): a directory of the capped tmpfs, mode 1777 (the unit's user is not known yet). The
        area itself is 0700 (see TMP_OPTIONS) and must be a tmpfs mount: anything else is refused."""
        if not _HEX12.fullmatch(ident):
            raise LaunchError("unit id must be 12 lowercase hex characters")
        # Without the tmpfs under it a unit's /tmp would silently be a directory of the host's /run, with no size cap at all; and
        # systemd (PID 1) sees the HOST's mounts only: a tmpfs that exists in this process's private namespace alone does not count.
        # So both areas must be tmpfs mounts of PID 1's table, and the directory seen here must be that very tmpfs (same device).
        table = parse_mountinfo_dev(self._mountinfo())
        for what, path in (("tmp area", self.tmp_dir), ("session area", self.run_dir)):
            why = host_mount_problem(path, table, self._dev_of)
            if why:
                raise LaunchError(f"the unit {what} is not the host's tmpfs ({why}); the host is not prepared")
        try:
            if os.stat(self.tmp_dir).st_mode & 0o077:
                os.chmod(self.tmp_dir, 0o700)
        except OSError as e:
            raise LaunchError(f"the unit's tmp area could not be checked ({e.__class__.__name__})") from None
        d = f"{self.tmp_dir}/{ident}"
        try:
            os.mkdir(d, 0o700)
            os.chmod(d, 0o1777)
        except FileExistsError:
            if os.path.islink(d) or not os.path.isdir(d):
                raise LaunchError("the unit's tmp directory is not a directory") from None
            os.chmod(d, 0o1777)
        except OSError as e:
            raise LaunchError(f"the unit's tmp directory could not be made ({e.__class__.__name__})") from None

    def _placeholder(self) -> str:
        return f"{self.static_dir}/chromium/policies/managed/{THEME_FILE}"

    def _theme_path(self, ident: str) -> str:
        return f"{self.theme_dir}/{ident}.json"

    def make_theme(self, ident: str, color, mode) -> str | None:
        """The session's theme policy file: root-owned (the portal runs as root), mode 0444, written atomically into the root-only theme
        directory BEFORE systemd-run, with the document rbrowser_policy.theme_policy() builds from the two validated values. Returns its
        path, or None when there is nothing to write (no valid colour). Raises LaunchError or OSError."""
        if not _HEX12.fullmatch(ident):
            raise LaunchError("unit id must be 12 lowercase hex characters")
        doc = rbrowser_policy.theme_policy(color, mode)
        if not doc:
            return None
        if os.path.islink(self.theme_dir) or (os.path.exists(self.theme_dir) and not os.path.isdir(self.theme_dir)):
            raise LaunchError("the theme directory is not a directory")
        os.makedirs(self.theme_dir, mode=0o700, exist_ok=True)
        os.chmod(self.theme_dir, 0o700)
        # A check of its own, not the validator that built the document: whatever theme_policy() returned, the file holds exactly the
        # one theme key and a plain #rrggbb value, or nothing is written.
        if (not isinstance(doc, dict) or list(doc) != ["BrowserThemeColor"] or not isinstance(doc["BrowserThemeColor"], str)
                or not re.fullmatch(r"#[0-9a-f]{6}", doc["BrowserThemeColor"], re.ASCII)):
            raise LaunchError("the theme document is not exactly the theme colour")
        path = self._theme_path(ident)
        _write_atomic(path, rbrowser_policy.policy_text(doc).encode(), 0o444)
        return path

    def remove_theme(self, ident: str) -> None:
        """Remove the session's theme file (never follows a link)."""
        if isinstance(ident, str) and _HEX12.fullmatch(ident):
            try:
                os.unlink(self._theme_path(ident))
            except OSError:
                pass

    def remove_tmp(self, ident: str) -> None:
        """Remove the unit's tmp directory (never follows a link; the directory is removed with whatever the unit left)."""
        if isinstance(ident, str) and _HEX12.fullmatch(ident):
            d = f"{self.tmp_dir}/{ident}"
            if os.path.isdir(d) and not os.path.islink(d):
                shutil.rmtree(d, ignore_errors=True)

    def sweep_tmp(self, live_idents) -> list:
        """Remove every tmp directory that no unit in `live_idents` owns (the registry's sweeper, lane A2: a unit that ended
        by itself leaves its directory on the 32 MiB tmpfs). Returns the names removed."""
        keep = set(live_idents)
        gone = []
        try:
            names = sorted(os.listdir(self.tmp_dir))
        except OSError:
            names = []
        for n in names:
            if _HEX12.fullmatch(n) and n not in keep:
                self.remove_tmp(n)
                gone.append(n)
        # the same sweep covers the per-session theme files (a unit that ended by itself, a crash between make_theme and the start)
        try:
            files = sorted(os.listdir(self.theme_dir))
        except OSError:
            files = []
        for f in files:
            m = re.fullmatch(r"([0-9a-f]{12})\.json", f)
            if m and m.group(1) not in keep:
                self.remove_theme(m.group(1))
                if m.group(1) not in gone:
                    gone.append(m.group(1))
        return gone

    def filter_attached(self, cgroup: str, pin: str | None = None) -> bool:
        """True when the ingress filter is attached to the cgroup (`expect_cgroup` of the LaunchResult, the path systemd
        reports). The registry calls this for every running session on its tick; a False ends the session. Never raises."""
        return ingress_attached(cgroup, pin or self.ingress_pin, bpf=self._bpf, root=self._cgroup_root)

    async def _wait_main(self, unit):
        """Wait until the unit is `active`. With Type=exec the unit stays `activating` while the child still
        runs as root setting up its namespaces; only `active` means execve happened, so the uid read after it
        is the dynamic uid. With --no-block the first poll may still see `inactive` (job queued): that is
        terminal only after `activating` or `active` has been seen; `failed` is terminal at once."""
        seen_started = False
        for _ in range(START_WAIT_STEPS):
            props = (await self.show([unit])).get(unit, {})
            state = props.get("ActiveState", "")
            if state == "failed":
                await self.reset_failed(unit)      # seen once: it must not stay loaded (the stop of the clean-up resets it again, harmlessly)
                raise LaunchError("the unit failed while starting")
            if state in ("activating", "active", "deactivating"):
                seen_started = True
            elif state == "inactive" and seen_started:
                raise LaunchError("the unit ended while starting")
            try:
                pid = int(props.get("MainPID", "0"))
            except ValueError:
                pid = 0
            cg = props.get("ControlGroup", "")
            if state == "active" and pid > 0 and cg:
                return pid, cg
            await self._sleep(START_WAIT_STEP_S)
        raise LaunchError("the unit did not start in time")

    async def stop(self, unit: str) -> None:
        """Stop the unit and CONFIRM it: `systemctl stop`, then ActiveState read back through show(). When the unit is still
        there (the stop failed or timed out) it is killed with SIGKILL and stopped once more. Raises UnitLeftRunning when it
        still cannot be shown as inactive or failed, or when systemd does not answer (unknown is not stopped); the unit is then
        in `self.unstopped` and its tmp directory stays (the unit still has it mounted). The unit is put on `self.unstopped`
        BEFORE the first systemctl call and taken off only when it is confirmed gone, so a stop() that is cancelled part way
        leaves the unit on the list. A unit that does not exist is
        inactive, so stopping one returns normally."""
        self._check_unit(unit)
        systemctl = self._which("systemctl") or "systemctl"
        # The unit is on the list from here until the show says it is gone: a stop() that is cancelled or timed out by its caller
        # part way (the four systemctl calls and two shows can take over a minute) must not drop the unit on the floor.
        self.unstopped.add(unit)
        await self._run([systemctl, "stop", unit], 15.0)
        if not await self._is_gone(unit):
            await self._run([systemctl, "kill", "-s", "SIGKILL", unit], 10.0)
            await self._run([systemctl, "stop", unit], 15.0)
            if not await self._is_gone(unit):
                raise UnitLeftRunning(unit)
        self.unstopped.discard(unit)
        self.remove_tmp(unit[len(self.unit_prefix):-len(".service")])
        self.remove_theme(unit[len(self.unit_prefix):-len(".service")])
        # without --collect a unit that ended in error (a SIGKILL, an exit status) stays loaded as `failed`: it is reset here, after the
        # stop is confirmed, so that nothing piles up whichever path led to the stop
        await self.reset_failed(unit)

    async def reset_failed(self, unit: str) -> None:
        """`systemctl reset-failed <unit>` (T1): a unit that ended in error stays loaded as `failed` until then (no --collect). Best effort:
        the answer is ignored (a unit that is not loaded answers with an error, which is fine), its own time limit, nothing raised
        except LaunchError for a name that is not a unit of this launcher and a cancellation."""
        self._check_unit(unit)
        try:
            await self._run([self._which("systemctl") or "systemctl", "reset-failed", unit], RESET_FAILED_TIMEOUT)
        except Exception:
            pass

    async def _is_gone(self, unit: str) -> bool:
        props = (await self.show([unit])).get(unit)
        return bool(props) and props.get("ActiveState") in ("inactive", "failed")

    async def show(self, units: list) -> dict:
        for u in units:
            if u != self._glob:
                self._check_unit(u)
        if not units:
            return {}
        argv = [self._which("systemctl") or "systemctl", "show", "-p", "Id", "-p", "ActiveState", "-p", "ExecMainStatus",
                "-p", "ExecMainCode", "-p", "MainPID", "-p", "ControlGroup", "-p", "IPIngressBytes", "-p", "IPEgressBytes"] + list(units)
        r = await self._run(argv, 10.0)
        return parse_show(r.out) if r.rc == 0 else {}

    def cgroup_of(self, pid: int) -> str:
        return parse_proc_cgroup(self._read(f"/proc/{int(pid)}/cgroup"))
