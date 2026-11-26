"""Live sandbox test of the server-side browser: real systemd units, real Xvfb, x11vnc and Chromium (design 13).

NOT part of the ordinary suite. It starts units, mounts a tmpfs, changes a slice and installs an iptables
rule, so it refuses to run unless asked twice (the variable AND root). The lead runs it, off peak, and saves the
output with the release:

    sudo RBROWSER_LIVE=1 /home/dustin/scripts/portal/venv/bin/python tests/test_rbrowser_live.py --round 1

Optional environment (each unlocks a gate that cannot be measured without it):
    RBROWSER_PUBLIC_IP=<the host's public address>     G24 (hairpin)
    RBROWSER_UPLOAD_SINK=<host:port>                    G19 (a public TCP sink that accepts and discards)
    RBROWSER_EXTRA_DENY=<cidr,cidr>                     added to the deny list
    RBROWSER_STORAGE_ROOTS=<path:path>                  added to the hidden-path list
    RBROWSER_LIVE_OUT=<directory>                       screenshots and notes (default /root/rbrowser-live-<time>)
    CHROMIUM=<path>                                     the browser Playwright drives (default /usr/bin/chromium)

    --only G02,G06,G11                                  run just these gates (the host is prepared and cleaned up as always; the probe
                                                        runs only when one of G00, G02, G02b, G06, G18 is chosen)

Round 1 (after lane A1): the unit gates G1 to G11 (G01b: a listener in a unit with the ingress filter cannot be reached, the control without it can) and G18, the policy gates G13 to G16, input G17 and G21,
the phone width G20, the measured performance G22, the CPU test G8, the upload limit G19, the hairpin G24, the
egress table of 6.1 (printed as G00) and the 20 resizes (G23). Round 2 is filled by lane A2.
1.26.0 adds G25 (a HARD gate for this release: a FAIL blocks it; it covers systemd's own handling of the optional file bind
`BindReadOnlyPaths=-<theme file>:/etc/chromium/policies/managed/portal-theme.json` inside the read-only /etc/chromium bind,
and it needs a host whose rbrowser state is not prepared, see the refusal below): the remote Chromium follows the member's portal theme (tab strip colour, prefers-color-scheme, the security
policy still applies, the per-session theme file is root-owned, read-only in the unit and gone after the stop).

Output: one line per gate, `Gnn PASS|FAIL|FALLBACK detail`. A gate that needs a person to look at a picture
prints FAIL with "manual:" and the path of the picture: nothing is called PASS that was not measured.

Run it inside tmux, or as `sudo systemd-run --wait --pty ...`, never straight over an SSH session that may drop:
the process also handles SIGHUP like SIGTERM (so it cleans up), but the units below carry their own time limit
(RuntimeMaxSec=120 for the CPU burner, the G03 dummy and the G19 control) as a second line of defence.

It refuses to start when the host already holds state of the feature that it did not create: the static tree
(STATIC_DIR of rbrowser_launch), a mount on its session area (RUN_DIR), the PORTAL-RB chain in iptables or ip6tables, a drop-in or an
active unit for system-portalrb.slice. It works on those shared paths and would overwrite what is there, so it only
runs on a host where the feature has never been prepared, or after the lead has torn that state down. What it
creates it removes, and nothing else.

Safety: every unit it starts has the prefix portal-rbtest- (SystemdLauncher(unit_prefix=TEST_PREFIX) is the only
launcher used). It does not read or change the portal's own unit, the media services, the database or the
settings. Everything is removed in `finally`: units, the iptables chain, the slice's runtime properties, and
the static tree, state directory and tmpfs only if this run created them.
"""

import contextlib
import errno
import glob
import ipaddress
import json
import os
import re
import secrets
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_LINES = []


FAILING = ("FAIL", "INCONCLUSIVE")      # INCONCLUSIVE counts as a failure for the release (T2): a measurement that proved nothing is not a pass


def say(gid, status, detail=""):
    line = f"{gid} {status} {str(detail).replace(chr(10), ' ')[:1800]}".rstrip()
    OUT_LINES.append((gid, status))
    print(line, flush=True)


def same_mount_namespace(read_link=os.readlink):
    """True only when this process is in PID 1's mount namespace (/proc/self/ns/mnt and /proc/1/ns/mnt are the same link text).
    The test mounts, unmounts and reads the HOST's tables; from a private namespace (a sudo inside a PrivateTmp unit, a container,
    an unshare) its view of /run and /tmp is not the host's. Unreadable is not the same: False. Pure apart from `read_link`."""
    try:
        mine, init = read_link("/proc/self/ns/mnt"), read_link("/proc/1/ns/mnt")
    except OSError:
        return False
    return bool(mine) and mine == init


def refuse_unless_asked():
    """Before any other import: no import below may run unless every guard passes."""
    if os.environ.get("RBROWSER_LIVE") != "1":
        print("skip: set RBROWSER_LIVE=1 and run as root to run the live sandbox test (it starts real systemd units)")
        sys.exit(0)
    if os.geteuid() != 0:
        print("refused: RBROWSER_LIVE=1 is set but this is not root (run it with sudo)")
        sys.exit(2)
    if not same_mount_namespace():
        print("refused: this process is not in PID 1's mount namespace (/proc/self/ns/mnt differs from /proc/1/ns/mnt, or cannot be read); "
              "run it from a shell of the host, not from a unit with a private mount namespace")
        sys.exit(2)
    if "--round" not in sys.argv or sys.argv[sys.argv.index("--round") + 1:][:1] not in (["1"], ["2"]):
        print("refused: give --round 1 or --round 2")
        sys.exit(2)


if __name__ == "__main__":
    refuse_unless_asked()

import asyncio  # noqa: E402
import ast  # noqa: E402
import collections  # noqa: E402
import importlib.util  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import statistics  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402

sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------- constants of the test
QUALITY_CANDIDATES = {"Low": (2, 6), "Balanced": (5, 3), "Sharp": (8, 2)}   # (qualityLevel, compressionLevel)
DEFAULT_LEVEL = "Balanced"
HOME_URL = "https://duckduckgo.com/"
WIDTHS_G20 = (320, 400, 480, 560, 640)
MEASURE_S = 8.0
WARMUP_S = 3.0
BARS = {"text_fps": 10, "news_fps": 6, "video_fps": 5, "x11vnc_cores": 0.5, "throttled_pct": 20, "latency_ms": 150}
TYPE_CHUNK, TYPE_INTERVAL_MS = 40, 30
G17_TEXT = "\u00e9 \u00df \u20ac \u201cq\u201d \u041f\u0440\u0438\u0432\u0435\u0442 \U0001f600"
HARD_GATES = ("G01", "G01b", "G02", "G02b", "G02c", "G09b", "G10", "G18", "G25")    # ids are the design's G1, G2, G2b, ... with two digits
CLIENT_ARGS = ["--no-sandbox"]    # only this test's local browser, as root, on loopback; never the unit's browser


def offline_args():
    """The OFFLINE_CHROMIUM_ARGS list of tools/make_screenshots.py, read as text (importing it needs aiohttp's
    stage helpers)."""
    tree = ast.parse((ROOT / "tools" / "make_screenshots.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "OFFLINE_CHROMIUM_ARGS" for t in node.targets):
            return list(ast.literal_eval(node.value))
    return []


# ---------------------------------------------------------------- pure helpers (checked by a scratch run, not by the suite)

_WIN = re.compile(r'^(\s+)(0x[0-9a-f]+) (?:"(.*)"|\(has no name\)): \((?:("[^"]*"|\(has no name\)) ("[^"]*"))?\)\s+(\d+)x(\d+)\+(-?\d+)\+(-?\d+)')


def parse_xwininfo(text):
    """`xwininfo -root -tree` -> top-level windows [{id, title, cls, w, h, x, y}]: the children of the root."""
    out = []
    for line in text.splitlines():
        m = _WIN.match(line)
        if m and len(m.group(1)) == 5:
            out.append({"id": m.group(2), "title": m.group(3) or "", "cls": (m.group(5) or "").strip('"'), "w": int(m.group(6)),
                        "h": int(m.group(7)), "x": int(m.group(8)), "y": int(m.group(9))})
    return out


def parse_stats(text):
    """`xwininfo -id W` -> geometry, override-redirect flag and map state."""
    def num(key):
        m = re.search(rf"^\s*{key}:\s*(-?\d+)", text, re.M)
        return int(m.group(1)) if m else None
    return {"x": num("Absolute upper-left X"), "y": num("Absolute upper-left Y"), "w": num("Width"), "h": num("Height"),
            "or": bool(re.search(r"Override Redirect State:\s*yes", text)), "viewable": "IsViewable" in text}


def parse_min_width(text):
    """`xprop WM_NORMAL_HINTS` -> the minimum width the program asks for, or None."""
    m = re.search(r"program specified minimum size:\s*(\d+) by (\d+)", text or "")
    return int(m.group(1)) if m else None


def chromium_windows(wins, min_size=120):
    return [w for w in wins if w["cls"].lower() == "chromium" and w["w"] >= min_size and w["h"] >= min_size]


def rects_overlap(a, b):
    return a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]


def keysym_for(ch):
    cp = ord(ch)
    if ch == "\n":
        return 0xFF0D
    if ch == "\t":
        return 0xFF09
    return cp if (0x20 <= cp <= 0x7E or 0xA0 <= cp <= 0xFF) else 0x01000000 + cp


def percentile(values, p):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


def page_url(body, title):
    """A data: page for the remote browser: typed into the address bar, so '%' and '#' are percent-encoded."""
    html = f"<meta charset=utf-8><title>{title}</title>{body}"
    return "data:text/html," + html.replace("%", "%25").replace("#", "%23")


def parse_cpu_stat(text):
    d = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if v.strip().isdigit():
            d[k] = int(v)
    return d


# Everything that `systemctl revert system-portalrb.slice` deletes (man systemctl: the set-property drop-ins, the
# foo.d/ directories below /etc/systemd/system and /run/systemd/system, a unit file there, and a mask, which is a
# symlink to /dev/null at the unit file's place). If any of it exists the host is not ours to revert.
SLICE_DROPIN_DIRS = ("/run/systemd/system.control/system-portalrb.slice.d", "/etc/systemd/system.control/system-portalrb.slice.d",
                     "/etc/systemd/system/system-portalrb.slice.d", "/run/systemd/system/system-portalrb.slice.d")
SLICE_UNIT_FILES = ("/etc/systemd/system/system-portalrb.slice", "/run/systemd/system/system-portalrb.slice")
SLICE_CGROUP = "/sys/fs/cgroup/system.slice/system-portalrb.slice"
QUOTE_DIR = '/var/lib/rbtest hidden "q"'     # a hidden path that needs the quoting rule: a space and a double quote
QUOTE_FILE = "marker.txt"


def chain_state(rc, out, err):
    """The answer of `<tool> -w 2 -S PORTAL-RB` -> True (the chain exists), False (it does not), None (cannot tell:
    a lock time-out, a resource error, any other failure). Only the tool's own 'No chain/target/match by that name'
    with exit status 1 means absent. Pure."""
    if rc == 0:
        return True
    text = (out + err).lower()
    if rc == 1 and "no chain/target/match by that name" in text:
        return False
    # iptables-nft 1.8.9 (Debian 12) answers a chain that does not exist with "chain `X' in table `filter' is
    # incompatible, use 'nft' tool." A chain that really is incompatible is then treated as absent here, and
    # install_firewall fails closed on its -N.
    if rc == 1 and "is incompatible, use 'nft' tool" in text:
        return False
    return None


PRODUCTION_PIN_GLOB = "/sys/fs/bpf/portal-rb" + "-ingress-*"     # the feature's own pin (PIN_BASE of rbrowser_bpf, split so that no session-unit prefix is spelled here); the test's pins are portal-rblive-*


def preexisting_state(*, static_exists, run_mounted, chains, dropins, slice_active, slice_masked=False, quote_exists=False, production_pins=()):
    """The reasons (a list of text) why this test must not run: state of the feature that it did not create. Pure.
    chains: {"iptables": True|False|None, "ip6tables": ...} - the PORTAL-RB chain exists / does not / could not be
    told (None refuses); dropins: the paths of the slice's drop-ins and unit file that exist (anything `systemctl
    revert` would delete); quote_exists: QUOTE_DIR exists (even as a symlink). [] means the host is clean."""
    why = []
    if static_exists:
        why.append("the static tree (STATIC_DIR) exists")
    if run_mounted:
        why.append("something is mounted on the session area (RUN_DIR)")
    for tool in sorted(chains):
        if chains[tool] is None:
            why.append(f"{tool} could not tell whether the PORTAL-RB chain exists (lock time-out or error)")
        elif chains[tool]:
            why.append(f"the PORTAL-RB chain exists in {tool}")
    for d in dropins:
        why.append(f"{d} exists (state of system-portalrb.slice that the clean-up's revert would delete)")
    if slice_masked:
        why.append("system-portalrb.slice is masked (the clean-up's revert would unmask it)")
    if slice_active:
        why.append("system-portalrb.slice is active")
    if quote_exists:
        why.append(f"{QUOTE_DIR} exists (the test would fill it and delete it)")
    for pin in production_pins:
        why.append(f"{pin} exists (the feature's own ingress-filter pin; the test must not touch it)")
    return why


def slice_stop_offenders(units_out, cgroup_dirs, unit_prefix, test_prefix):
    """The units a stop of system-portalrb.slice (or the host tear-down) must not be allowed to kill: a production
    session unit or a preflight probe unit (<prefix><12 hex>.service, for each prefix in unit_prefix: one prefix or a
    tuple of them) in the `systemctl list-units --all` text, and EVERY child directory of the slice's cgroup that does
    not start with the test prefix, whatever its suffix (a .scope, a .service, a bare name: anything that systemd or
    somebody else put in the slice). cgroup_dirs are directory names only (see cgroup_child_dirs); [] means every
    member is this run's. Pure."""
    prefixes = (unit_prefix,) if isinstance(unit_prefix, str) else tuple(unit_prefix)
    alts = "|".join(re.escape(x) for x in prefixes)
    found = set(re.findall(r"(?:" + alts + r")[0-9a-f]{12}\.service", units_out or ""))
    found |= {n for n in cgroup_dirs if not n.startswith(test_prefix)}
    return sorted(found)


def clean_up_may_unpin(unprepare_result, unconfirmed, children, unsettled=False):
    """Whether the clean-up may remove the run's own ingress-filter pin ITSELF after the host part. Pure.
    unprepare_result: what unprepare_host returned, or None when it did not run (or raised); it removes the pin only for a slice
    that was stopped and has no child cgroup, and says pin_removed / pin_kept: when it ran its answer is the last word, so the
    clean-up never unpins on top of it. unconfirmed: test units that were not confirmed gone (a unit still running in the slice
    without the pin would run without the filter after the next re-apply). children: the slice's child cgroups read again NOW
    (slice_children: [] = none, None = unreadable). Any unconfirmed unit, or anything but [] here, keeps the pin.
    unsettled: something may still be running (a coroutine that was cancelled and has not ended, an unprepare_host that did not
    return): the pin is kept whatever else is true."""
    if unconfirmed or unsettled:
        return False
    if unprepare_result is not None:
        return False
    return children == []


def kept_line_due(pin_exists, already_said):
    """Whether the clean-up must still print the KEPT line for the run's pin: the pin exists after everything and no KEPT line was
    printed for it yet. Pure."""
    return bool(pin_exists) and not already_said


def cgroup_child_dirs(path, scandir=os.scandir):
    """The names of the child DIRECTORIES of a cgroup directory (cgroup.procs and the other interface files are not
    members). A symlink is not followed and is not a directory. Raises OSError like os.scandir."""
    with scandir(path) as it:
        return sorted(e.name for e in it if e.is_dir(follow_symlinks=False))


def listener_findings(conns):
    """conns: [(pid, protocol 'tcp'|'udp', status text, local port)] of the unit's processes. -> the ones that count:
    any TCP socket in LISTEN, any UDP socket bound below 32768 (design 5.3 item 4). Pure."""
    return [(pid, proto, port) for pid, proto, status, port in conns
            if (proto == "tcp" and status == "LISTEN") or (proto == "udp" and 0 < port < 32768)]


# ---- G01b: a listener inside the slice must not complete a handshake (design 5.3 item 4, 6.4)

LISTEN_HOLD_S = 40
LISTEN_SNIPPET = r'''
import errno, json, secrets, socket, time
KEEP, res = [], {"ports": {}, "errors": {}, "outbound": None}
def rec(name, fam, bind=None, proto=0):
    s = None
    try:
        s = socket.socket(fam, socket.SOCK_STREAM, proto)
        if bind is not None:
            s.bind(bind)
        s.listen(1024)       # nobody ever accepts: a small backlog would drop later SYNs of the control, and the control must stay connectable
        res["ports"][name] = s.getsockname()[1]
        KEEP.append(s)
    except OSError as e:
        res["errors"][name] = errno.errorcode.get(e.errno, str(e.errno))
        if s is not None:
            s.close()
rec("tcp4_autobind", socket.AF_INET)
rec("tcp6_autobind", socket.AF_INET6)
rec("tcp4_bind0", socket.AF_INET, ("0.0.0.0", 0))
rec("tcp6_bind0", socket.AF_INET6, ("::", 0))
# MPTCP (IPPROTO_MPTCP = 262; RestrictAddressFamilies allows it): the SYN of a plain TCP client reaches it as protocol 6, and the
# listener's sockets live in the unit's cgroup. A host without MPTCP gives an error here and the gate skips the name.
rec("tcp4_mptcp_autobind", socket.AF_INET, None, 262)
rec("tcp6_mptcp_autobind", socket.AF_INET6, None, 262)
for name, fam, host in (("tcp4_bind_fixed", socket.AF_INET, "0.0.0.0"), ("tcp6_bind_fixed", socket.AF_INET6, "::")):
    for _ in range(8):
        res["errors"].pop(name, None)
        res["ports"].pop(name, None)
        rec(name, fam, (host, 20000 + secrets.randbelow(10000)))
        if res["errors"].get(name) != "EADDRINUSE":
            break
try:
    c = socket.create_connection(("1.1.1.1", 443), 5)
    res["outbound"] = "connected"
    c.close()
except socket.timeout:
    res["outbound"] = "timeout"
except OSError as e:
    res["outbound"] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(res), flush=True)
time.sleep(%d)
''' % LISTEN_HOLD_S


def host_addresses(if_addrs):
    """psutil.net_if_addrs() (or anything shaped like it: {iface: [object with .family and .address]}) -> {address: {"v6":
    bool, "loopback": bool}} for every IPv4 and IPv6 address of the host, loopback included. A link-local IPv6 address
    gets its interface as the zone (fe80::1%eth0), as connect() needs it. Pure."""
    out = {}
    for iface, items in sorted(if_addrs.items()):
        for it in items:
            if it.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            text, _, zone = str(it.address).partition("%")
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                continue
            addr = str(ip)
            if ip.version == 6 and ip.is_link_local:
                addr += "%" + (zone or iface)
            out.setdefault(addr, {"v6": ip.version == 6, "loopback": ip.is_loopback})
    return out


def pair_tested(addr_is_v6, listener, bindv6only=False):
    """Whether a listener ('tcp4_...' or 'tcp6_...') can be reached through an address at all: an IPv6 address never
    reaches an IPv4 socket, and an IPv4 address reaches an IPv6 wildcard socket only on a dual-stack host. Pure."""
    if addr_is_v6:
        return not listener.startswith("tcp4")
    return listener.startswith("tcp4") or not bindv6only


def connect_outcome(addr, port, timeout=3.0):
    """Try one TCP connect from this process: 'connected', 'timeout', an errno name (ECONNREFUSED ...) or
    'unaddressable'. The address is numeric (a zone is allowed)."""
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    try:
        sa = socket.getaddrinfo(addr, port, fam, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0][4]
        sock = socket.socket(fam, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return "unaddressable"
    try:
        sock.settimeout(timeout)
        sock.connect(sa)
        return "connected"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        sock.close()


def judge_g01b(addrs, session, filter_only, control, attached=None):
    """The verdict of G01b (D1). addrs: {address: {"v6", "loopback"}}. Each unit: {"reported": bool, "ports": {name: port},
    "errors": {name: errno name}, "outbound": str or None, "outcomes": {(address, name): outcome}}.

    session      the unit exactly as a browser session (SocketBindDeny, IPAddressDeny, the ingress filter), in the slice
    filter_only  the same without SocketBindDeny and IPAddressDeny, in the slice: only the ingress filter can stop it
    control      the same as filter_only but WITHOUT the ingress filter, in the slice: the positive control
    attached     {"session": bool, "filter-only": bool, "control": bool}: whether rbrowser_bpf.attached() sees the filter on
                 each unit's cgroup (optional); it must be True for the first two and False for the control

    No judgement on binds (SocketBindDeny is not enforced on this systemd build): every listener that comes up is tried.
    The control proves the method: a (address, listener) pair counts only if the control's listener of that name
    connects through that address. For every such pair the units with the filter must show a time-out (the SYN is
    dropped, nothing answers); a connection, a refusal or anything else fails. -> (ok, detail). Pure."""
    problems = []
    if not control.get("reported"):
        problems.append("the control unit did not report its listeners")
    cports = control.get("ports", {})
    autos = [n for n in cports if n.endswith("autobind")]
    if not autos:
        problems.append("no listener without bind came up in the control unit: nothing proves the method")
    proven = {k for k, v in control.get("outcomes", {}).items() if v == "connected"}
    if not any(addrs[a]["loopback"] for a, n in proven if n in autos and a in addrs):
        problems.append("the control's listener cannot be reached on loopback")
    if not any(not addrs[a]["loopback"] for a, n in proven if n in autos and a in addrs):
        problems.append("the control's listener cannot be reached on any non-loopback address")
    skipped = sorted(f"{a}/{n}" for (a, n), v in control.get("outcomes", {}).items() if v != "connected")
    if attached is not None:
        for label, want in (("session", True), ("filter-only", True), ("control", False)):
            if attached.get(label) is not want:
                problems.append(f"{label}: the ingress filter is {'not attached' if want else 'attached'} (the unit is not what the gate needs)")

    def judge_unit(label, u, must_listen):
        if not u.get("reported"):
            problems.append(f"the {label} unit did not report its listeners")
            return 0
        timed_out = 0
        for name in sorted(cports):
            if name not in u.get("ports", {}):
                err = u.get("errors", {}).get(name)
                if must_listen:
                    problems.append(f"{label}: the {name} listener did not come up ({err}), so the filter was not exercised")
                elif err in ("EPERM", "EACCES"):
                    continue      # a build that enforces SocketBindDeny refused the bind outright: nothing listens, nothing to reach
                else:
                    problems.append(f"{label}: {name} is neither listening nor refused by the kernel ({err})")
                continue
            for (a, n) in sorted(proven):
                if n != name:
                    continue
                got = u.get("outcomes", {}).get((a, n))
                if got != "timeout":
                    problems.append(f"{label}: {name} through {a} -> {got or 'not tried'} (expected a time-out)")
                else:
                    timed_out += 1
        return timed_out

    t1 = judge_unit("session", session, False)
    t2 = judge_unit("filter-only", filter_only, True)
    if session.get("outbound") != "connected":
        problems.append(f"an outbound connection from the session unit to 1.1.1.1:443 did not work ({session.get('outbound')})")
    detail = (f"every connection to a listener in the units with the ingress filter timed out ({t1} through the session unit, {t2} with only the filter), "
              f"the same listeners without the filter connected ({len(proven)} pairs: positive control), "
              f"outbound to 1.1.1.1:443 from the session unit: {session.get('outbound')}"
              + (f"; not provable and so not judged: {', '.join(skipped[:6])}" if skipped else ""))
    if problems:
        return False, "; ".join(problems[:8])
    return True, detail


@contextlib.contextmanager
def time_limit(seconds):
    """Raises TimeoutError in the main thread after `seconds` (SIGALRM). A call of the synchronous Playwright API
    cannot be given a time-out of its own at close time; this bounds it. Only usable in the main thread: elsewhere it
    does nothing."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def fire(*_a):
        raise TimeoutError(f"no answer in {seconds} s")
    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def bounded_call(fn, seconds):
    """fn() with a time limit. -> True when it finished, False when it did not (or failed): never raises."""
    try:
        with time_limit(seconds):
            fn()
        return True
    except BaseException:
        return False


# ================================================================ the test's machinery (needs root)

class Loop:
    """One asyncio loop in a thread: the launcher and the bridge live there, so Playwright's synchronous API
    can run in the main thread."""

    UNWIND_S = 75.0      # a launcher's clean-up stop (four systemctl calls and two shows) can take over a minute

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.stuck = 0          # coroutines that were cancelled and had NOT ended when run() gave up waiting for them (clean-up keeps the pin)

    def run(self, coro, timeout=120, unwind=None):
        """Run a coroutine on the loop and wait for its result. On ANY exception, a time-out and a SystemExit or
        KeyboardInterrupt from a signal handler included, the coroutine is cancelled and run() WAITS (at most `unwind`, default
        UNWIND_S) until it has really ended (a launcher that was starting a unit stops it in its own clean-up) before the exception
        goes on. A coroutine that has not ended by then is counted in self.stuck: the clean-up decisions (removing the pin) must
        not be taken while something may still be running on the loop."""
        unwind = self.UNWIND_S if unwind is None else unwind
        done = threading.Event()

        async def _spawn():
            t = asyncio.ensure_future(coro)
            t.add_done_callback(lambda _t: done.set())
            return t
        task = asyncio.run_coroutine_threadsafe(_spawn(), self.loop).result(10)
        try:
            if not done.wait(timeout):
                raise TimeoutError(f"the coroutine did not finish in {timeout} s")
            return task.result()
        except BaseException:
            self.loop.call_soon_threadsafe(task.cancel)
            if not done.wait(unwind):
                self.stuck += 1
            raise

    def cancel_pending(self, timeout=5.0):
        """Cancel every task still on the loop and wait (at most `timeout`) for them to end. -> how many were
        cancelled, or -1 when the loop could not be asked. A task that has not ended when the time is up (or when the loop could not be
        asked) is counted in self.stuck: the clean-up keeps the pin then."""
        async def _all():
            me = asyncio.current_task()
            tasks = [t for t in asyncio.all_tasks() if t is not me]
            for t in tasks:
                t.cancel()
            pending = set()
            if tasks:
                _, pending = await asyncio.wait(tasks, timeout=timeout)
            return len(tasks), len(pending)
        try:
            n, left = asyncio.run_coroutine_threadsafe(_all(), self.loop).result(timeout + 2)
            self.stuck += left
            return n
        except BaseException:
            self.stuck += 1
            return -1

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def sh(argv, timeout=30, check=False):
    """A command as an argument list; never a shell."""
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{os.path.basename(argv[0])} failed ({p.returncode}): {p.stderr.decode('utf-8', 'replace')[:200]}")
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


# What the portal does at start, run the way the portal runs: in a unit of its own with PrivateTmp=yes (its mount namespace is a
# private copy whose /run is a SLAVE of the host's, so a mount made in it never reaches systemd). The request arrives on stdin as
# JSON, the answer leaves on stdout as one JSON line. Names of files and paths only; nothing of a page or a user.
PRIVATE_NS_SCRIPT = r"""
import asyncio, json, os, sys
req = json.load(sys.stdin)
sys.path.insert(0, req["root"])
import rbrowser_launch as L
async def go():
    out = {"ns": os.readlink("/proc/self/ns/mnt")}
    kw = dict(helper_prefix=req["helper_prefix"])
    if req["op"] == "prepare":
        res = await L.prepare_host(req["cfg"], policy=req["policy"], paths=L.HostPaths(**req["paths"]), source_dir=None,
                                   probe_targets_doc=req["probe"], bpf_base=req["bpf_base"], **kw)
        out["result"] = res
        mine = L.parse_mountinfo_dev(open("/proc/self/mountinfo").read())
        out["private_sees"] = {p: list(mine.get(p, ())) for p in (req["paths"]["run_dir"], req["paths"]["tmp_dir"])}
        out["private_dev"] = {p: L.dev_of(p) for p in (req["paths"]["run_dir"], req["paths"]["tmp_dir"])}
        if res.get("ok"):
            ln = L.SystemdLauncher(unit_prefix=req["test_prefix"], ingress_pin=res.get("ingress_pin") or None,
                                   tmp_dir=req["paths"]["tmp_dir"], run_dir=req["paths"]["run_dir"])
            try:
                ln.make_tmp(req["ident"])
                out["make_tmp"] = "ok"
            except Exception as e:
                out["make_tmp"] = e.__class__.__name__ + ": " + str(e)[:200]
    elif req["op"] == "stat":
        out["exists"] = {p: os.path.exists(p) for p in req["paths_to_stat"]}
    else:
        out["result"] = await L.unprepare_host(units_left=0, paths=L.HostPaths(**req["paths"]), bpf_pin=req["bpf_pin"], **kw)
    print(json.dumps(out), flush=True)
asyncio.run(go())
"""

# The control: the way prepare_host mounted before fix pass 2 (a plain mount in the unit's own namespace) against the helper unit.
PRIVATE_CONTROL_SCRIPT = r"""
import asyncio, json, os, subprocess, sys
req = json.load(sys.stdin)
sys.path.insert(0, req["root"])
import rbrowser_launch as L
async def go():
    out = {"ns": os.readlink("/proc/self/ns/mnt")}
    r = subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "size=1m", "rbtest-ctl", req["direct"]], capture_output=True)
    out["direct_rc"] = r.returncode
    out["direct_seen_here"] = req["direct"] in L.parse_mountinfo(open("/proc/self/mountinfo").read())
    h = await L.host_run(L.default_run, L.find_tool, ["/usr/bin/mount", "-t", "tmpfs", "-o", "size=1m", "rbtest-ctl", req["helper"]], prefix=req["helper_prefix"])
    out["helper_rc"] = h.rc
    out["helper_seen_here"] = req["helper"] in L.parse_mountinfo(open("/proc/self/mountinfo").read())
    print(json.dumps(out), flush=True)
asyncio.run(go())
"""


class Rig:
    """Everything the gates share: the launcher, the host description, the artifacts directory, a record of what
    this run created so that `finally` removes exactly that."""

    def __init__(self):
        self.tmp = None
        self.loop = None
        try:
            self._setup()
        except BaseException:
            # a failure (or a signal) in the set-up must not leave the scratch directory or the loop thread behind
            if self.tmp is not None:
                shutil.rmtree(self.tmp, ignore_errors=True)
            if self.loop is not None:
                try:
                    self.loop.close()
                except Exception:
                    pass
            raise

    def _setup(self):
        import rbrowser
        import rbrowser_launch as L
        import rbrowser_policy as P
        self.rbrowser, self.L, self.P = rbrowser, L, P
        self.TP = rbrowser.TEST_PREFIX
        self.loop = Loop()
        self.launcher = L.SystemdLauncher(unit_prefix=self.TP)    # gets its pin in prepare()
        self.pin = ""                   # the ingress filter's pin prepare_host returned (the test's own base, removed at the end)
        self.bpf_base = f"/sys/fs/bpf/portal-rblive-{secrets.token_hex(3)}"
        self.out = Path(os.environ.get("RBROWSER_LIVE_OUT") or f"/root/rbrowser-live-{time.strftime('%Y%m%d-%H%M%S')}")
        self.out.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="rbrowser-live-"))
        self.units = []                 # every unit name this run started
        self.prep = None                # what the first prepare_host (inside a PrivateTmp unit) reported about its namespace
        self.private_stuck = set()      # private units (PrivateTmp prepare/unprepare) that timed out and are NOT confirmed gone
        self.unconfirmed = set()        # test units whose stop could not be confirmed (stop_unit); the clean-up then keeps the pin
        self.sessions = []
        self.created = {}               # what this run created, for the cleanup
        self.bridges = []
        self.pw = None
        self.browser = None
        self.cleanups = []
        self.sess_mod = self._load("rbrowser_unit/session.py", "rb_sess_live")
        self.paths = L.HostPaths()
        self.cfg = {"rbrowser_max_sessions": 2, "rbrowser_memory_mb": 2048, "rbrowser_cpu_percent": 150,
                    "rbrowser_upload_kbps": 4000}
        self.ncpu = os.cpu_count() or 1
        self.mem_total = L.parse_meminfo(L._read("/proc/meminfo"))
        self.avail = L.availability(stage_mode=False, use_cache=False)
        self.chromium = self.avail["paths"]["chromium"]
        self.host = self.describe_host()
        self.deny = P.deny_list(self.host["resolvers"], self.host["ifaces"], self.host["gateways"], self.host["extra"])
        self.literals = P.literal_hosts(self.host["resolvers"], self.host["ifaces"], self.host["gateways"])
        self.policy = P.build_policy(HOME_URL, self.literals)
        self.hidden_extra = [str(ROOT)] + [p for p in os.environ.get("RBROWSER_STORAGE_ROOTS", "").split(":") if p]
        self.portal_port = 443

    @staticmethod
    def _load(rel, name):
        spec = importlib.util.spec_from_file_location(name, ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def describe_host(self):
        import psutil
        P = self.P
        res = []
        for f in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            res += P.parse_resolv_conf(self.L._read(f))
        gws = P.parse_proc_net_route(self.L._read("/proc/net/route")) + P.parse_proc_net_ipv6_route(self.L._read("/proc/net/ipv6_route"))
        # the same gateways, an IPv6 link-local one with its device as the zone (fe80::1%eth0): only the probe needs it
        gws_scoped = P.parse_proc_net_route(self.L._read("/proc/net/route")) + P.parse_proc_net_ipv6_route_scoped(self.L._read("/proc/net/ipv6_route"))
        extra = [c for c in os.environ.get("RBROWSER_EXTRA_DENY", "").split(",") if c.strip()]
        return {"resolvers": list(dict.fromkeys(res)), "gateways": list(dict.fromkeys(gws)), "gateways_scoped": list(dict.fromkeys(gws_scoped)),
                "ifaces": P.iface_from_psutil(psutil.net_if_addrs()), "extra": extra}

    # ---- units
    def ident(self):
        return secrets.token_hex(6)

    def spec(self, ident=None, **over):
        d = dict(ident=ident or self.ident(), width=1280, height=720, clipboard="both", home_url=HOME_URL,
                 chromium=self.chromium, memory_mb=2048, cpu_percent=125, deny=self.deny, hidden_extra=self.hidden_extra,
                 portal_unit="")
        d.update(over)
        return self.rbrowser.LaunchSpec(**d)

    def own(self, unit):
        assert unit.startswith(self.TP) and unit.endswith(".service") and re.fullmatch(r"[A-Za-z0-9._-]+", unit), unit
        return unit

    def systemctl(self, *args, timeout=30):
        return sh(["/usr/bin/systemctl", *args], timeout)

    def unit_state(self, unit):
        rc, out, _ = self.systemctl("show", "-p", "ActiveState", "-p", "ExecMainStatus", "-p", "MainPID", "-p", "ControlGroup", self.own(unit))
        return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)

    def stop_unit(self, unit, seconds=20):
        """Stop a test unit and CONFIRM it (ActiveState inactive or failed): `systemctl stop`, then a SIGKILL and a second stop when it
        is still there. Returns True when it is gone; a unit that is not is remembered in `self.unconfirmed` (the clean-up keeps the
        ingress filter's pin for it) and False is returned. Never raises."""
        try:
            self.own(unit)
            self.systemctl("stop", unit, timeout=40)
            if self.confirmed_gone(unit, seconds):
                self.unconfirmed.discard(unit)
                self.systemctl("reset-failed", unit, timeout=15)      # no --collect on the session units: a failed one stays loaded
                return True
            self.systemctl("kill", "-s", "SIGKILL", unit, timeout=15)
            self.systemctl("stop", unit, timeout=40)
            if self.confirmed_gone(unit, seconds):
                self.unconfirmed.discard(unit)
                self.systemctl("reset-failed", unit, timeout=15)
                return True
        except Exception:
            pass
        self.unconfirmed.add(unit)
        return False

    def confirmed_gone(self, unit, seconds=20):
        """True only when systemd ANSWERED that the unit is inactive or failed (an unreadable answer is not gone: fail closed)."""
        end = time.time() + seconds
        while True:
            rc, out, _ = self.systemctl("show", "-p", "ActiveState", "--value", self.own(unit), timeout=15)
            if rc == 0 and out.strip() in ("inactive", "failed"):
                return True
            if time.time() >= end:
                return False
            time.sleep(0.5)

    def wait_gone(self, unit, seconds=60):
        end = time.time() + seconds
        while time.time() < end:
            if self.unit_state(unit).get("ActiveState", "inactive") in ("inactive", "failed", ""):
                return True
            time.sleep(0.5)
        return False

    def journal(self, unit):
        sh(["/usr/bin/journalctl", "--sync"], 20)
        return sh(["/usr/bin/journalctl", "-u", self.own(unit), "-o", "cat", "--no-pager"], 30)[1]

    def start_session(self, **over):
        spec = self.spec(**over)
        try:
            res = self.loop.run(self.launcher.start(spec), 60)
        except Exception:
            # a start that fails leaves no journal behind once the unit is gone: keep it for the report (fixed words only)
            unit = f"{self.TP}{spec.ident}.service"
            try:
                self.save(f"start-failure-{spec.ident}.journal.txt", self.journal(unit))
            except Exception:
                pass
            raise
        self.units.append(res.unit)
        return Session(self, spec, res)

    def custom_args(self, spec, command, mutate=None, wait=False, script="session.py", theme_file=None):
        args = self.L.build_unit_args(spec, self.TP, script, 5, ingress_pin=self.pin, theme_file=theme_file)
        assert args[-4:] == ["/usr/bin/python3", "-I", "-S", f"/mnt/{script}"]
        args = args[:-4]
        if mutate:
            args = mutate(list(args))
        if wait:
            args = [a for a in args if a not in ("--no-block", "--quiet")] + ["--wait"]
        return args + list(command)

    def run_unit(self, command, mutate=None, wait=True, spec=None, timeout=120, script="session.py", theme_file=None):
        """systemd-run of an arbitrary command with the session's properties. -> (systemd-run rc, stderr, unit)"""
        spec = spec or self.spec()
        unit = f"{self.TP}{spec.ident}.service"
        self.launcher.make_tmp(spec.ident)        # D6: the unit's /tmp is a directory of the capped tmpfs; the launcher makes it for a session
        argv = [self.L.find_tool("systemd-run")] + self.custom_args(spec, command, mutate, wait, script, theme_file)
        self.units.append(unit)
        rc, out, err = sh(argv, timeout)
        return rc, err, unit

    def snippet(self, code, mutate=None, timeout=120):
        """A python snippet inside a unit; returns (accepted, last JSON line printed or None, stderr). It runs with the
        probe's policy tree (script='probe.py' binds chromium-probe): headless Chromium hangs under
        DeveloperToolsAvailability=2, and the snippets that load pages use it."""
        rc, err, unit = self.run_unit(["/usr/bin/python3", "-I", "-S", "-c", code], mutate=mutate, timeout=timeout, script="probe.py")
        text = self.journal(unit)
        self.wait_gone(unit, 20)
        last = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    last = json.loads(line)
                except ValueError:
                    pass
        return rc == 0 or last is not None, last, err

    def run_probe(self):
        spec = self.spec()
        launcher = self.L.SystemdLauncher(unit_prefix=self.TP, script="probe.py", nice=19, ingress_pin=self.pin)
        res = self.loop.run(launcher.start(spec), 60)
        self.units.append(res.unit)
        self.wait_gone(res.unit, 80)
        text = self.journal(res.unit)
        for line in reversed(text.splitlines()):
            if line.startswith("{"):
                return json.loads(line)
        return {"ok": False, "checks": [{"name": "run", "ok": False, "detail": "the probe printed nothing: " + text[-200:]}]}

    def probe_check(self, probe, name):
        for c in probe.get("checks", []):
            if c["name"] == name:
                return c
        return {"name": name, "ok": False, "detail": "missing from the probe's answer"}

    def save(self, name, data):
        p = self.out / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return str(p)

    # ---- host
    def host_facts(self):
        """What the host holds already, for preexisting_state(). Read-only commands only."""
        L = self.L
        chains = {}
        for name in ("iptables", "ip6tables"):
            tool = L.find_tool(name)
            # a tool that is not installed has no chain; any failure other than "no such chain" is an unknown, not an absence
            chains[name] = chain_state(*sh([tool, "-w", "2", "-S", L.CHAIN])) if tool else False
        active = self.systemctl("is-active", L.SLICE)[1].strip() in ("active", "activating", "reloading")
        masked = self.systemctl("show", "-p", "LoadState", "--value", L.SLICE)[1].strip() == "masked"
        return dict(static_exists=os.path.exists(L.STATIC_DIR), run_mounted=bool({L.RUN_DIR, L.RUN_TMP} & set(L.parse_mountinfo(L._read(L.HOST_MOUNTINFO)))),
                    chains=chains, dropins=[d for d in SLICE_DROPIN_DIRS + SLICE_UNIT_FILES if os.path.lexists(d)], slice_active=active,
                    slice_masked=masked, quote_exists=os.path.lexists(QUOTE_DIR), production_pins=sorted(glob.glob(PRODUCTION_PIN_GLOB)))

    def slice_offenders(self):
        """Units that stopping the slice would kill although this run did not start them (see slice_stop_offenders):
        a session or probe unit of the real feature, and any child directory of the slice's cgroup that is not a
        test unit. Asked again before every slice stop: a unit may have been started by the portal since the start of
        the run. A listing that fails counts as an offender (fail closed)."""
        U = self.rbrowser
        rc, out, _ = self.systemctl("list-units", "--all", "--plain", "--no-legend", f"{U.UNIT_PREFIX}*", f"{U.PROBE_PREFIX}*")
        if rc != 0:
            return ["(the unit list could not be read)"]
        members = []
        try:
            members = cgroup_child_dirs(SLICE_CGROUP)
        except FileNotFoundError:
            pass
        except OSError:
            return ["(the slice's cgroup could not be read)"]
        return slice_stop_offenders(out, members, (U.UNIT_PREFIX, U.PROBE_PREFIX), self.TP)

    def make_quote_dir(self):
        """A directory whose name needs the quoting rule of InaccessiblePaths=, with a file in it and mode 0755, so
        that an unhidden unit can read it and a hidden one cannot. Added to the hidden-path list."""
        os.mkdir(QUOTE_DIR, 0o755)              # FileExistsError if anything (a symlink too) is there: never reuse a path
        self.created["quote_dir"] = True        # from here on the directory is this run's
        dfd = os.open(QUOTE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(dfd, 0o755)               # the umask may have narrowed it
            ffd = os.open(QUOTE_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
            try:
                os.fchmod(ffd, 0o644)           # root's umask must not hide the file from the dynamic user (G06)
                os.write(ffd, b"rbtest\n")
            finally:
                os.close(ffd)
        finally:
            os.close(dfd)
        self.hidden_extra.append(QUOTE_DIR)

    def unit_listeners(self, pids):
        """[(pid, 'tcp'|'udp', status, port)] over the given pids, from psutil (the portal's own listener check)."""
        import psutil
        out = []
        for pid in pids:
            try:
                for c in psutil.Process(pid).net_connections(kind="inet"):
                    proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                    out.append((pid, proto, c.status, c.laddr.port if c.laddr else 0))
            except (psutil.Error, OSError):
                continue
        return out

    @property
    def helper_prefix(self):
        return self.TP + "host-"

    def private_unit(self, script, request, seconds=150):
        """Run `script` (python source) as root in a transient unit that has PrivateTmp=yes, the way the portal runs. The request goes in as
        JSON on stdin, the last stdout line is the JSON answer. The unit is named portal-rbtest-prep-<hex>; it is waited for and
        collected. Returns (answer dict or None, error text)."""
        unit = f"{self.TP}prep-{secrets.token_hex(6)}.service"
        self.own(unit)
        argv = ["/usr/bin/systemd-run", f"--unit={unit}", "--wait", "--collect", "--pipe", "--quiet", "-p", "PrivateTmp=yes", "-p", "Type=exec",
                sys.executable, "-B", "-c", script]
        try:
            r = subprocess.run(argv, input=json.dumps(dict(request, root=str(ROOT), helper_prefix=self.helper_prefix,
                                                           test_prefix=self.TP)).encode(), capture_output=True, timeout=seconds)
        except subprocess.TimeoutExpired:
            # subprocess.run killed the systemd-run client only; the unit itself is stopped by name and CONFIRMED gone (stop_unit; a
            # unit that stays is in self.unconfirmed and in self.private_stuck, and the caller must not run its fallback next to it)
            if not self.stop_unit(unit):
                self.private_stuck.add(unit)
                return None, f"the unit {unit} did not finish in {seconds} s and is NOT confirmed gone"
            return None, f"the unit {unit} did not finish in {seconds} s (stopped and confirmed gone)"
        lines = [l for l in r.stdout.decode(errors="replace").splitlines() if l.startswith("{")]
        if r.returncode != 0 or not lines:
            return None, f"rc {r.returncode}: {(r.stderr or r.stdout).decode(errors='replace')[-300:]}"
        try:
            return json.loads(lines[-1]), ""
        except ValueError:
            return None, "the answer was not JSON"

    def prepare(self, source_dir=None):
        """prepare_host as the portal calls it: inside a PrivateTmp unit (see PRIVATE_NS_SCRIPT). `self.prep` keeps the evidence of the first call."""
        import dataclasses
        probe = self.L.probe_targets(self.portal_port, [a for a, _ in self.host["ifaces"]], self.host["gateways_scoped"], self.host["resolvers"], self.hidden_extra)
        if not hasattr(self, "prep_ident"):
            self.prep_ident = self.ident()
        ans, err = self.private_unit(PRIVATE_NS_SCRIPT, dict(op="prepare", cfg=self.cfg, policy=self.policy, paths=dataclasses.asdict(self.paths), probe=probe,
                                                             bpf_base=self.bpf_base, ident=self.prep_ident))
        if ans is None:
            return {"ok": False, "reasons": [f"prepare_host in a PrivateTmp unit failed: {err}"]}
        if self.prep is None:
            self.prep = ans
        res = ans["result"]
        if res.get("ingress_pin"):
            self.pin = res["ingress_pin"]
            self.launcher.ingress_pin = self.pin
        return res


class Session:
    def __init__(self, rig, spec, res):
        self.rig, self.spec, self.res = rig, spec, res
        self.unit, self.rt = res.unit, res.runtime_dir
        self.bridge = None
        self.display = None
        rig.sessions.append(self)

    def wait_sockets(self, seconds=15):
        end = time.time() + seconds
        while time.time() < end:
            if os.path.exists(f"{self.rt}/vnc.sock") and os.path.exists(f"{self.rt}/ctl.sock"):
                return True
            time.sleep(0.2)
        return False

    def ctl(self, req, timeout=4):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(timeout)
        try:
            s.connect(f"{self.rt}/ctl.sock")
            s.sendall(json.dumps(req).encode() + b"\n")
            return json.loads(s.makefile().readline())
        finally:
            s.close()

    def pids(self):
        try:
            return [int(x) for x in Path(f"/sys/fs/cgroup{self.res.expect_cgroup}/cgroup.procs").read_text().split()]
        except OSError:
            return []

    def cmdline(self, pid):
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            return ""

    def exe(self, pid):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return ""

    def find(self, name):
        return [p for p in self.pids() if os.path.basename(self.cmdline(p).split(" ")[0]) == name]

    def find_display(self):
        S = self.rig.sess_mod
        xv = self.find("Xvfb")
        if not xv:
            return None
        links = [os.readlink(f"/proc/{xv[0]}/fd/{n}") for n in os.listdir(f"/proc/{xv[0]}/fd")]
        owned = S.socket_inodes(links)
        for inode, flags, path in S.parse_proc_net_unix(Path("/proc/net/unix").read_text()):
            m = re.fullmatch(r"@/tmp/\.X11-unix/X(\d+)", path)
            if m and flags & S.UNIX_LISTEN_FLAG and inode in owned:
                self.display = int(m.group(1))
                return self.display
        return None

    def xenv(self):
        d = self.display if self.display is not None else self.find_display()
        if d is None:
            raise RuntimeError("the unit's display was not found")
        return {**os.environ, "DISPLAY": f":{d}", "XAUTHORITY": f"{self.rt}/xauth", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

    def x(self, argv, timeout=10):
        p = subprocess.run(argv, env=self.xenv(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    def windows(self):
        rc, out = self.x(["/usr/bin/xwininfo", "-root", "-tree"])
        return chromium_windows(parse_xwininfo(out)) if rc == 0 else []

    def main_window(self):
        w = self.windows()
        return max(w, key=lambda x: x["w"] * x["h"]) if w else None

    def title(self):
        w = self.main_window()
        if not w:
            return ""
        rc, out = self.x(["/usr/bin/xprop", "-id", w["id"], "_NET_WM_NAME"])
        m = re.search(r'= "(.*)"', out, re.S)
        t = m.group(1) if m else w["title"]
        return t[:-len(" - Chromium")] if t.endswith(" - Chromium") else t

    def wait_title(self, needle, seconds=12):
        end = time.time() + seconds
        t = ""
        while time.time() < end:
            t = self.title()
            if needle in t:
                return True, t
            time.sleep(0.4)
        return False, t

    def screen(self):
        rc, out = self.x(["/usr/bin/xwininfo", "-root"])
        st = parse_stats(out)
        return (st["w"], st["h"]) if rc == 0 else None

    def top_info(self, min_size=20):
        """Every top-level window of at least min_size with its override-redirect flag, map state, transient-for and window type."""
        rc, out = self.x(["/usr/bin/xwininfo", "-root", "-tree"])
        res = []
        for w in parse_xwininfo(out) if rc == 0 else []:
            if w["w"] < min_size or w["h"] < min_size:
                continue
            rc2, o2 = self.x(["/usr/bin/xwininfo", "-id", w["id"], "-stats"])
            st = parse_stats(o2)
            if rc2 != 0 or not st["viewable"]:
                continue
            rc3, o3 = self.x(["/usr/bin/xprop", "-id", w["id"], "WM_TRANSIENT_FOR", "_NET_WM_WINDOW_TYPE"])
            res.append({**w, "or": st["or"], "transient": "window id #" in o3,
                        "type": (re.search(r"_NET_WM_WINDOW_TYPE\(ATOM\) = (.*)", o3) or [None, "-"])[1].replace("_NET_WM_WINDOW_TYPE_", "").strip()})
        return res

    def window_props(self, wid, full=False):
        """Class, role, state and type of one window, from xprop (never a window name, title or icon). full=True lists every property
        except the names and icons."""
        if full:
            rc, out = self.x(["/usr/bin/xprop", "-id", wid])
            skip = ("WM_NAME", "_NET_WM_NAME", "WM_ICON_NAME", "_NET_WM_ICON_NAME", "_NET_WM_ICON", "_NET_WM_VISIBLE_NAME")
            lines, drop = [], False
            for l in out.splitlines():
                if l and not l[0].isspace():
                    drop = l.split("(")[0].split(":")[0].split("=")[0].strip() in skip
                if not drop:
                    lines.append(l.strip())
            return " | ".join(lines)[:1500]
        rc, out = self.x(["/usr/bin/xprop", "-id", wid, "WM_CLASS", "WM_WINDOW_ROLE", "_NET_WM_STATE", "_NET_WM_WINDOW_TYPE", "WM_TRANSIENT_FOR", "WM_HINTS"])
        keep = [l.strip() for l in out.splitlines() if l.split("(")[0].split("=")[0].strip() in ("WM_CLASS", "WM_WINDOW_ROLE", "_NET_WM_STATE", "_NET_WM_WINDOW_TYPE", "WM_TRANSIENT_FOR", "WM_HINTS")]
        return " | ".join(keep)[:400]

    def min_width_hint(self):
        w = self.main_window()
        if not w:
            return None
        rc, out = self.x(["/usr/bin/xprop", "-id", w["id"], "WM_NORMAL_HINTS"])
        return parse_min_width(out)

    def wait_main_window(self, size, seconds=5.0):
        """Poll until the biggest Chromium window is at 0,0 and `size` big. -> (reached, window)"""
        end = time.time() + seconds
        w = None
        while time.time() < end:
            w = self.main_window()
            if w and (w["x"], w["y"], w["w"], w["h"]) == (0, 0, size[0], size[1]):
                return True, w
            time.sleep(0.25)
        return False, w

    def selection(self, which):
        rc, out = self.x(["/usr/bin/xsel", f"--{which}", "-o"], 5)
        return out

    def set_selection(self, which, text):
        p = subprocess.Popen(["/usr/bin/xsel", f"--{which}", "-i"], env=self.xenv(), stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        p.stdin.write(text.encode())
        p.stdin.close()
        self.rig.cleanups.append(lambda: p.poll() is None and p.kill())

    def cpu_stat(self):
        try:
            return parse_cpu_stat(Path(f"/sys/fs/cgroup{self.res.expect_cgroup}/cpu.stat").read_text())
        except OSError:
            return {}

    def proc_ticks(self, pids):
        total = 0
        for p in pids:
            try:
                f = Path(f"/proc/{p}/stat").read_text().rsplit(")", 1)[1].split()
                total += int(f[11]) + int(f[12])
            except (OSError, IndexError, ValueError):
                pass
        return total

    def show(self):
        return self.rig.unit_state(self.unit)

    def stop(self):
        if self.bridge:
            self.bridge.close()
            self.bridge = None
        self.rig.loop.run(self.rig.launcher.stop(self.unit), 40)

    def open_page(self, kbps=None, clipboard=False, viewport=None):
        self.bridge = Bridge(self.rig, f"{self.rt}/vnc.sock", clipboard=clipboard, kbps=kbps)
        return NoVnc(self.rig, self.bridge, viewport or (self.spec.width + 20, self.spec.height + 20))


# ================================================================ the test bridge: WebSocket to unix socket, through ClientFilter

class Bridge:
    """A 40-line bridge on a loopback port. Client bytes go through ClientFilter; server bytes go to the client
    through an optional token bucket. It serves static/vendor/novnc and a page that drives it."""

    def __init__(self, rig, sock_path, clipboard=True, kbps=None):
        self.rig, self.sock_path, self.clipboard, self.kbps = rig, sock_path, clipboard, kbps
        self.stats = {"to_client": 0, "to_unit": 0, "types": collections.Counter(), "violations": []}
        self.stall = False
        self.needle = None            # bytes to look for in what the unit sends (a boolean is kept, never the bytes)
        self.stats["saw"] = False
        self._tail = b""
        self.runner = None
        self.port = None
        rig.loop.run(self._start(), 20)

    async def _start(self):
        from aiohttp import web
        app = web.Application()
        app.router.add_get("/", self._index)
        app.router.add_get("/ws", self._ws)
        app.router.add_static("/novnc/", str(ROOT / "static" / "vendor" / "novnc"))
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def _index(self, request):
        from aiohttp import web
        return web.Response(text=PAGE_HTML, content_type="text/html")

    async def _ws(self, request):
        from aiohttp import web
        import rbrowser_rfb
        ws = web.WebSocketResponse(max_msg_size=1 << 20, protocols=("binary",))
        await ws.prepare(request)
        reader, writer = await asyncio.open_unix_connection(self.sock_path)
        flt = rbrowser_rfb.ClientFilter(self.clipboard)
        bucket = {"t": time.monotonic(), "tokens": (self.kbps or 0) * 125.0}

        async def up():
            async for msg in ws:
                if msg.type != web.WSMsgType.BINARY:
                    continue
                try:
                    fwd, types = flt.feed(msg.data)
                except rbrowser_rfb.Violation as e:
                    self.stats["violations"].append(e.reason)
                    await ws.close(code=4013, message=b"protocol")
                    return
                self.stats["types"].update(types)
                if fwd:
                    self.stats["to_unit"] += len(fwd)
                    writer.write(fwd)
                    await writer.drain()

        async def down():
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                if self.kbps:
                    now = time.monotonic()
                    cap = self.kbps * 125.0
                    bucket["tokens"] = min(cap, bucket["tokens"] + (now - bucket["t"]) * cap)
                    bucket["t"] = now
                    bucket["tokens"] -= len(chunk)
                    if bucket["tokens"] < 0:
                        await asyncio.sleep(-bucket["tokens"] / cap)
                self.stats["to_client"] += len(chunk)
                if self.needle and not self.stats["saw"]:
                    self.stats["saw"] = self.needle in self._tail + chunk
                    self._tail = (self._tail + chunk)[-len(self.needle):]
                await ws.send_bytes(chunk)

        tasks = [asyncio.ensure_future(up()), asyncio.ensure_future(down())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            writer.close()
            if not ws.closed:
                await ws.close()
        return ws

    def snapshot(self):
        return {"to_client": self.stats["to_client"], "to_unit": self.stats["to_unit"], "t3": self.stats["types"][3],
                "t4": self.stats["types"][4], "t5": self.stats["types"][5], "t": time.monotonic()}

    def close(self):
        try:
            self.rig.loop.run(self.runner.cleanup(), 10)
        except Exception:
            pass


PAGE_HTML = """<!doctype html><meta charset=utf-8><title>rb live</title>
<body style="margin:0;background:#222"><div id="screen" style="width:100vw;height:100vh"></div>
<script type="module">
import RFB from '/novnc/core/rfb.js';
const wsurl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
window.__clip = []; window.__events = [];
const rfb = new RFB(document.getElementById('screen'), wsurl, {credentials: {password: ''}});
rfb.scaleViewport = false; rfb.resizeSession = false; rfb.clipViewport = false;
rfb.addEventListener('connect', () => { window.__events.push('connect'); window.__connected = true; });
rfb.addEventListener('disconnect', e => { window.__events.push('disconnect'); window.__connected = false; window.__detail = e.detail; });
rfb.addEventListener('clipboard', e => window.__clip.push(e.detail.text));
window.rfb = rfb;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const keysym = ch => { const cp = ch.codePointAt(0); if (ch === '\\n') return 0xFF0D; if (ch === '\\t') return 0xFF09;
  return (cp >= 0x20 && cp <= 0x7E) || (cp >= 0xA0 && cp <= 0xFF) ? cp : 0x01000000 + cp; };
window.typeText = async (text, chunk, interval) => { let n = 0;
  for (const ch of text) { rfb.sendKey(keysym(ch), null); if (++n % chunk === 0) await sleep(interval); } return n; };
window.chord = (mods, key) => { for (const m of mods) rfb.sendKey(m, null, true); rfb.sendKey(key, null); for (const m of mods.slice().reverse()) rfb.sendKey(m, null, false); };
window.setQuality = (q, c) => { rfb.qualityLevel = q; rfb.compressionLevel = c; };
window.regionHash = (x, y, w, h) => { const c = document.querySelector('canvas'); const d = c.getContext('2d').getImageData(x, y, w, h).data;
  let s = 0; for (let i = 0; i < d.length; i += 4) s = (s * 31 + d[i] + d[i + 1] * 3 + d[i + 2] * 7) >>> 0; return s; };
window.collectBase = async (x, y, w, h, ms) => { const s = new Set(); const t0 = performance.now();
  while (performance.now() - t0 < ms) { s.add(window.regionHash(x, y, w, h)); await sleep(30); } window.__base = s; return s.size; };
window.latencyTrial = async (x, y, w, h, sym, timeoutMs) => { const t0 = performance.now();
  rfb.sendKey(sym, null);
  while (performance.now() - t0 < timeoutMs) { await new Promise(r => requestAnimationFrame(r)); if (!window.__base.has(window.regionHash(x, y, w, h))) return performance.now() - t0; }
  return null; };
</script></body>"""


class NoVnc:
    """Playwright Chromium on the bridge's page."""

    def __init__(self, rig, bridge, viewport):
        from playwright.sync_api import sync_playwright
        self.rig, self.bridge = rig, bridge
        if rig.pw is None:
            rig.pw = sync_playwright().start()
            rig.browser = rig.pw.chromium.launch(executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"), headless=True,
                                                 args=CLIENT_ARGS + offline_args())
        self.ctx = rig.browser.new_context(viewport={"width": viewport[0], "height": viewport[1]})
        self.page = self.ctx.new_page()
        self.page.goto(f"http://127.0.0.1:{bridge.port}/")
        self.page.wait_for_function("window.__connected === true", timeout=20000)
        self.page.wait_for_selector("canvas", timeout=10000)

    def js(self, expr, arg=None):
        return self.page.evaluate(expr, arg) if arg is not None else self.page.evaluate(expr)

    def type_text(self, text, chunk=TYPE_CHUNK, interval=TYPE_INTERVAL_MS):
        return self.page.evaluate("([t,c,i]) => window.typeText(t,c,i)", [text, chunk, interval])

    def chord(self, mods, key):
        self.page.evaluate("([m,k]) => window.chord(m,k)", [mods, key])

    def nav(self, url):
        """Ctrl+L, the address, Return, in the remote browser."""
        self.chord([0xFFE3], 0x6C)
        time.sleep(0.4)
        self.type_text(url)
        time.sleep(0.2)
        self.page.evaluate("() => rfb.sendKey(0xFF0D, null)")

    def key(self, key, code, text=None, modifiers=0, vk=0):
        """One key as a real keyboard layout would send it, through the DevTools Input domain: Playwright's keyboard.press only
        knows the US layout's key names and raises "Unknown key" for e-acute or the euro sign. `key` is event.key, `code` the
        physical key, `text` what the key types (None for a key that types nothing)."""
        if getattr(self, "_cdp", None) is None:
            self._cdp = self.ctx.new_cdp_session(self.page)
        base = {"key": key, "code": code, "modifiers": modifiers, "windowsVirtualKeyCode": vk or (ord(key.upper()) if len(key) == 1 and ord(key) < 128 else 0)}
        self._cdp.send("Input.dispatchKeyEvent", dict(base, type="rawKeyDown" if text is None else "keyDown", **({"text": text, "unmodifiedText": text} if text is not None else {})))
        self._cdp.send("Input.dispatchKeyEvent", dict(base, type="keyUp"))

    def click(self, x, y, button="left"):
        box = self.page.locator("canvas").bounding_box()
        self.page.mouse.click(box["x"] + x, box["y"] + y, button=button)

    def triple_click(self, x, y):
        """A real triple click (a user selection: Chromium takes PRIMARY with it, which a script's select() does not)."""
        box = self.page.locator("canvas").bounding_box()
        self.page.mouse.click(box["x"] + x, box["y"] + y, click_count=3)

    def hover(self, x, y):
        box = self.page.locator("canvas").bounding_box()
        self.page.mouse.move(box["x"] + x, box["y"] + y)

    def shot(self, name):
        return self.rig.save(name, self.page.screenshot(type="png"))

    def close(self):
        try:
            self.ctx.close()
        except Exception:
            pass


# ================================================================ the gates

GATES = []


def gate(gid, title):
    def deco(fn):
        GATES.append((gid, title, fn))
        return fn
    return deco


NET_SNIPPET = r'''
import importlib.util, json, os
def load(n):
    s = importlib.util.spec_from_file_location(n, "/mnt/" + n + ".py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
S = load("session"); P = load("probe")
os.makedirs(S.HOME_DIR, exist_ok=True)
os.makedirs(S.TMP_DIR, exist_ok=True)
out = {"bind": P.check_bind()}
rc, dom = P._dump_dom(S, os.environ["RB_CHROMIUM"], "n", "https://example.com/")
out["rc"] = rc
out["example"] = rc == 0 and "Example Domain" in dom
rc2, dom2 = P._dump_dom(S, os.environ["RB_CHROMIUM"], "m", "http://127.0.0.1/")
out["loopback_blocked"] = "ERR_BLOCKED_BY_ADMINISTRATOR" in dom2
print(json.dumps(out))
'''

SOCKETS_SNIPPET = r'''
import errno, json, socket
res = {}
for p in ["/run/dbus/system_bus_socket", "/run/systemd/notify", "/run/systemd/journal/socket", "/run/avahi-daemon/socket",
          "/run/systemd/resolve/io.systemd.Resolve", "/var/run/dbus/system_bus_socket"]:
    s = socket.socket(socket.AF_UNIX); s.settimeout(2)
    try:
        s.connect(p); res[p] = "CONNECTED"
    except OSError as e:
        res[p] = errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()
print(json.dumps(res))
'''


def connect_snippet(host, port):
    return ("import json, socket, errno\n"
            f"s = socket.socket(socket.AF_INET); s.settimeout(3)\n"
            "try:\n"
            f"    s.connect(({host!r}, {int(port)})); r = 'connected'\n"
            "except socket.timeout:\n    r = 'timeout'\n"
            "except OSError as e:\n    r = errno.errorcode.get(e.errno, str(e.errno))\n"
            "print(json.dumps({'result': r}))\n")


@gate("G00", "egress table of 6.1")
def g_egress(rig, ctx):
    chk = rig.probe_check(ctx["probe"], "egress")
    return ("PASS" if chk["ok"] else "FAIL"), chk["detail"]


@gate("G01", "an https page loads in the session's properties (QUIC off, DoH), no x11vnc listener; binds are reported, not judged")
def g1(rig, ctx):
    """Hard gate, part 1 (D1: re-baselined). SocketBindDeny=any is accepted but NOT enforced by this systemd build, so what
    bind() and listen() do in the unit (fixed ports, port 0, listen without bind) is only REPORTED here (the probe's bind
    check) and never judged. The control for a listener that comes up is the ingress BPF filter, proven from outside the
    unit by G01b. What this gate decides: the session's properties (filter included) let an https page load, and the
    session unit that is running has no TCP listener and no UDP socket bound below 32768 (x11vnc and Xvfb use sockets
    in the runtime directory only)."""
    ok, res, err = rig.snippet(NET_SNIPPET)
    if not ok or res is None:
        return "FAIL", f"the unit with the session's properties did not start or print: {err[:150]}"
    bind = res["bind"]
    sess = ctx.get("session")
    if sess is None or not sess.pids():
        owned = "not checked: no running session unit to look at (so this gate cannot pass)"
        listeners_ok = False
    else:
        found = listener_findings(rig.unit_listeners(sess.pids()))
        x11 = sess.find("x11vnc")
        owned = (f"x11vnc pids {x11}, listeners in the unit: {found or 'none'}")
        listeners_ok = bool(x11) and not found
    report = f"{bind['detail']}; ports {bind.get('listen_ports')}"
    if res["example"] and listeners_ok:
        return "PASS", f"an https page loaded with QUIC off and DoH; {owned}; {report}"
    return "FAIL", f"page loaded: {res.get('example')}; {owned}; {report}"


@gate("G01b", "listeners in a session unit are unreachable from the host (ingress filter), the control without the filter is reachable, outbound works")
def g1b(rig, ctx):
    """Hard gate, part 2 (D1). Three units in the slice each open listeners (socket(); listen() with no bind on tcp4 and tcp6,
    a bind to port 0 and listen, and a bind to a fixed port) and hold them for LISTEN_HOLD_S seconds:

      session      exactly as a browser session
      filter-only  the same without SocketBindDeny and IPAddressDeny. IPAddressDeny lists this host's own addresses, so a
                   connect from the host would be dropped by it whether or not the filter works; only this unit shows that
                   the INGRESS FILTER is what stops the connection
      control      the same as filter-only but WITHOUT IPIngressFilterPath, also in the slice: the positive control, so the
                   filter is the only difference; its listeners are reachable from here

    rbrowser_bpf.attached() must see the filter on the first two cgroups and must not see it on the control. From the HOST
    (this process, outside every unit) every listener is then tried on every address of the host, loopback included, with a
    3 s limit. PASS only when the control connects on loopback and on a non-loopback address and every pair the control
    reached times out in the two units with the filter, and an outbound connection from the session unit to 1.1.1.1:443
    (the DoH endpoint) works with the filter in place."""
    if not rig.pin:
        return "FAIL", "prepare_host returned no ingress pin: nothing stops a listener in the slice"
    import psutil
    addrs = host_addresses(psutil.net_if_addrs())
    L = rig.L
    short = f"RuntimeMaxSec={L.RUNTIME_MAX_SEC}"

    def lifetime(args):
        return _drop_prop(args, short) + ["-p", "RuntimeMaxSec=120"]

    def filter_only(args):
        return _drop_prop(_drop_prop(lifetime(args), "SocketBindDeny=any"), "IPAddressDeny=" + " ".join(rig.deny))

    def control(args):
        return _drop_prop(filter_only(args), "IPIngressFilterPath=" + rig.pin)
    units = {}
    try:
        for label, mutate in (("session", lifetime), ("filter-only", filter_only), ("control", control)):
            rc, err, unit = rig.run_unit(["/usr/bin/python3", "-I", "-S", "-c", LISTEN_SNIPPET], mutate=mutate, wait=False)
            if rc != 0:
                return "FAIL", f"the {label} unit was not accepted: {err[:150]}"
            units[label] = unit
        reports = {}
        end = time.time() + 25
        while time.time() < end and len(reports) < len(units):
            for label, unit in units.items():
                if label in reports:
                    continue
                for line in rig.journal(unit).splitlines():
                    if line.startswith("{"):
                        try:
                            reports[label] = json.loads(line)
                        except ValueError:
                            pass
            time.sleep(0.5)
        att = {label: L.ingress_attached(rig.unit_state(unit).get("ControlGroup", ""), rig.pin) for label, unit in units.items()}
        try:
            bindv6only = Path("/proc/sys/net/ipv6/bindv6only").read_text().strip() == "1"
        except OSError:
            bindv6only = False
        data = {}
        jobs = []
        for label in units:
            rep = reports.get(label)
            data[label] = {"reported": rep is not None, "ports": (rep or {}).get("ports", {}), "errors": (rep or {}).get("errors", {}),
                           "outbound": (rep or {}).get("outbound"), "outcomes": {}}
            for name, port in data[label]["ports"].items():
                for addr, info in addrs.items():
                    if pair_tested(info["v6"], name, bindv6only):
                        jobs.append((label, addr, name, port))
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=32) as pool:
            futs = [(j, pool.submit(connect_outcome, j[1], j[3], 3.0)) for j in jobs]
            for (label, addr, name, _port), f in futs:
                data[label]["outcomes"][(addr, name)] = f.result()
        ok, detail = judge_g01b(addrs, data["session"], data["filter-only"], data["control"], att)
        extra = (f" [attached: {att}; addresses tried: {', '.join(sorted(addrs))}; listeners per unit: "
                 + "; ".join(f"{k}: {sorted(v['ports'])}" for k, v in data.items()) + "]")
        return ("PASS" if ok else "FAIL"), f"attached {att}; " + detail + extra
    finally:
        for unit in units.values():
            try:
                rig.stop_unit(unit)
            except Exception:
                pass


@gate("G02", "TemporaryFileSystem, Xvfb, Chromium, caps")
def g2(rig, ctx):
    p = ctx["probe"]
    parts = {n: rig.probe_check(p, n) for n in ("mounts", "display_proof", "chromium_policy")}
    bad = {n: c["detail"] for n, c in parts.items() if not c["ok"]}
    return ("PASS", "tmpfs caps as expected, Xvfb and headless Chromium run") if not bad else ("FAIL", str(bad))


@gate("G02b", "RuntimeDirectory on the 8 MiB tmpfs")
def g2b(rig, ctx):
    s = ctx["session"]
    st = os.stat(s.rt)
    sv = os.statvfs(s.rt)
    size = sv.f_blocks * sv.f_frsize
    mode_ok = (st.st_mode & 0o777) == 0o700 and st.st_uid == s.res.expect_uid
    probe_ok = rig.probe_check(ctx["probe"], "mounts")["ok"]
    s.stop()
    gone = not os.path.exists(s.rt)
    ctx["session"] = None
    if size == 8 << 20 and mode_ok and gone and probe_ok:
        return "PASS", "8 MiB tmpfs, mode 0700 owned by the dynamic uid, removed at stop"
    return "FAIL", f"size {size}, mode/uid ok {mode_ok}, removed {gone}, probe mounts {probe_ok}"


@gate("G02c", "prepare_host from a PrivateTmp unit: the tmpfs reach PID 1 and the caps hold in a session")
def g2c(rig, ctx):
    L = rig.L
    prep = rig.prep
    if not prep:
        return "FAIL", "prepare_host did not run inside a PrivateTmp unit"
    bad, facts = [], []
    host_ns = os.readlink("/proc/1/ns/mnt")
    if prep["ns"] == host_ns:
        bad.append("the prepare unit had no mount namespace of its own: this run does not reproduce the portal")
    table = L.parse_mountinfo_dev(L._read(L.HOST_MOUNTINFO))
    for path, cap in ((L.RUN_DIR, 8 << 20), (L.RUN_TMP, 32 << 20)):
        why = L.host_mount_problem(path, table)
        sv = os.statvfs(path)
        size = sv.f_blocks * sv.f_frsize
        sees = prep["private_sees"].get(path) or []
        if why:
            bad.append(f"{path} in PID 1's table: {why}")
        if size != cap:
            bad.append(f"{path} is {size} bytes, not {cap}")
        if not sees or sees[0] != "tmpfs" or path not in table or sees[1] != table[path][1] or prep["private_dev"].get(path) != sees[1]:
            bad.append(f"{path}: the prepare unit's own view {sees} differs from PID 1's {table.get(path)}")
        facts.append(f"{path} {table.get(path)} {size >> 20} MiB, seen from the prepare unit as {sees}")
    if prep.get("make_tmp") != "ok":
        bad.append(f"make_tmp inside the PrivateTmp unit: {prep.get('make_tmp')}")
    # a session whose /tmp directory the PrivateTmp unit made: the caps as the unit's own view shows them
    s = rig.start_session(ident=rig.prep_ident)
    try:
        s.wait_sockets()
        pid = s.res.main_pid
        for d in ("/tmp", "/var/tmp"):
            sv = os.statvfs(f"/proc/{pid}/root{d}")
            size = sv.f_blocks * sv.f_frsize
            facts.append(f"session {d} {size >> 20} MiB")
            if size != 32 << 20:
                bad.append(f"the session's {d} is {size} bytes, not {32 << 20}")
        sv = os.statvfs(s.rt)
        if sv.f_blocks * sv.f_frsize != 8 << 20:
            bad.append(f"the session's runtime directory is {sv.f_blocks * sv.f_frsize} bytes, not {8 << 20}")
        # the portal (the PrivateTmp unit) must SEE the sockets that PID 1 made under the host's /run/portal-rb
        ans, err = rig.private_unit(PRIVATE_NS_SCRIPT, dict(op="stat", paths_to_stat=[s.rt + "/vnc.sock", s.rt + "/ctl.sock"], paths={}), 60)
        seen = (ans or {}).get("exists") or {}
        if not ans or not all(seen.values()):
            bad.append(f"the PrivateTmp unit does not see the session's sockets ({err or seen})")
        facts.append(f"sockets seen from the PrivateTmp unit: {sorted(seen.values())}")
    finally:
        s.stop()
    # prepare_host again from a PrivateTmp unit (what the portal does after a slice restart): the mounts are there, no second one is made
    again = rig.prepare()
    n_before = len([l for l in L._read(L.HOST_MOUNTINFO).splitlines() if f" {L.RUN_DIR} " in l or f" {L.RUN_TMP} " in l])
    if not again.get("ok") or n_before != 2:
        bad.append(f"prepare_host again from the PrivateTmp unit: ok {again.get('ok')} {again.get('reasons')}, {n_before} mount lines for the two areas (want 2)")
    facts.append(f"prepare again ok {again.get('ok')}, {n_before} mounts")
    # the control: the old way (a plain mount in the unit's own namespace) against the helper unit, on scratch directories
    tag = secrets.token_hex(3)
    direct, helper = f"/run/portal-rbtest-ctl-{tag}-a", f"/run/portal-rbtest-ctl-{tag}-b"
    for d in (direct, helper):
        os.mkdir(d, 0o700)
    rig.cleanups.append(lambda: [sh(["/usr/bin/umount", helper], 15), [os.rmdir(d) for d in (direct, helper) if os.path.isdir(d)]])
    ans, err = rig.private_unit(PRIVATE_CONTROL_SCRIPT, dict(direct=direct, helper=helper), 90)
    if not ans:
        bad.append(f"the control unit failed: {err}")
    else:
        t2 = L.parse_mountinfo_dev(L._read(L.HOST_MOUNTINFO))
        control_ok = ans["direct_rc"] == 0 and ans["direct_seen_here"] and direct not in t2
        helper_ok = ans["helper_rc"] == 0 and helper in t2 and t2[helper][0] == "tmpfs" and ans["helper_seen_here"]
        facts.append(f"control: a plain mount in the PrivateTmp unit is {'invisible to PID 1' if control_ok else 'NOT as expected (' + str(ans) + ')'}; "
                     f"the helper unit's mount is {'in PID 1 table and in the unit' if helper_ok else 'NOT as expected'}")
        if not control_ok:
            bad.append("the control did not show the premise (a plain mount in the PrivateTmp unit staying invisible to PID 1)")
        if not helper_ok:
            bad.append("a mount made through the helper unit did not reach PID 1 and the PrivateTmp unit")
    return ("PASS" if not bad else "FAIL"), "; ".join(facts) + ("" if not bad else " || " + "; ".join(bad))


@gate("G04", "RestrictAddressFamilies with and without AF_NETLINK")
def g4(rig, ctx):
    full = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
    no_nl = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"

    def works(mutate=None):
        ok, res, _ = rig.snippet(NET_SNIPPET, mutate=mutate)
        return bool(ok and res and res["example"])
    with_nl = works()
    without_nl = works(lambda a: [no_nl if x == full else x for x in a])
    if with_nl:
        return "PASS", f"an https page loads with AF_NETLINK in the list; with the list lacking AF_NETLINK it {'also loads' if without_nl else 'does not load (AF_NETLINK is needed)'}"
    if without_nl:
        return "FALLBACK", "the page does not load with AF_NETLINK but does without it: take AF_NETLINK out of the list"
    if works(lambda a: _drop_prop(a, full)):
        return "FALLBACK", "the page loads only without the property: drop RestrictAddressFamilies"
    return "FAIL", "the page does not load with the list, without AF_NETLINK or without the property (check the network from the unit first)"


@gate("G05", "RestrictSUIDSGID, LockPersonality, ProtectKernelLogs, LimitCORE, UMask, Nice, IOWeight, IPAccounting")
def g5(rig, ctx):
    rc, err, unit = rig.run_unit(["/bin/sleep", "20"], wait=False)
    st = {}
    end = time.time() + 15
    while time.time() < end:
        st = rig.unit_state(unit)
        if st.get("ActiveState") == "active":
            break
        time.sleep(0.3)
    show = rig.systemctl("show", "-p", "IPAccounting", "-p", "LockPersonality", "-p", "RestrictSUIDSGID", "-p", "ProtectKernelLogs",
                         "-p", "LimitCORE", "-p", "UMask", "-p", "Nice", "-p", "IOWeight", unit)[1]
    rig.stop_unit(unit)
    if rc == 0 and st.get("ActiveState") == "active":
        want = ("IPAccounting=yes", "LockPersonality=yes", "RestrictSUIDSGID=yes", "ProtectKernelLogs=yes")
        missing = [w for w in want if w not in show]
        return ("PASS", "the unit starts with all of them; systemctl show reports them") if not missing else ("FAIL", f"started, but not reported: {missing}")
    props = ("RestrictSUIDSGID=yes", "LockPersonality=yes", "ProtectKernelLogs=yes", "LimitCORE=0", "UMask=0077", "Nice=5", "IOWeight=50", "IPAccounting=yes")
    culprit = []
    for prop in props:
        rc2, _, u2 = rig.run_unit(["/bin/sleep", "3"], mutate=lambda a, prop=prop: _drop_prop(a, prop), wait=True)
        if rc2 == 0:
            culprit.append(prop)
    if culprit == ["IPAccounting=yes"]:
        return "FAIL", "IPAccounting breaks the start: without it section 6.4 has no data, the feature is unavailable"
    return ("FALLBACK", f"drop: {culprit}") if culprit else ("FAIL", f"the unit did not start and no single property is the cause: {err[:150]}")


def _drop_prop(args, prop):
    out, i = [], 0
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args) and args[i + 1] == prop:
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out


@gate("G06", "hidden-path list: Chromium starts, fonts and TLS roots load")
def g6(rig, ctx):
    hp = rig.probe_check(ctx["probe"], "hidden_paths")
    cp = rig.probe_check(ctx["probe"], "chromium_policy")
    ok, res, _ = rig.snippet(NET_SNIPPET)
    page = bool(ok and res and res["example"])
    # The hidden list holds a path with a space and a double quote (QUOTE_DIR), which only the quoting rule can
    # express: the probe says it is hidden (it holds a file and has mode 0755 on the host), and a unit that does NOT
    # list it must still be able to read the file, so "hidden" is not just "missing".
    code = ("import json\ntry:\n    t = open(" + repr(QUOTE_DIR + "/" + QUOTE_FILE) + ").read().strip()\nexcept OSError as e:\n    t = 'ERR ' + str(e.errno)\n"
            "print(json.dumps({'text': t}))\n")
    others = [x for x in rig.hidden_extra if x != QUOTE_DIR]
    rc, err_c, unit_c = rig.run_unit(["/usr/bin/python3", "-I", "-S", "-c", code], spec=rig.spec(hidden_extra=others), timeout=60)
    ctl = None
    for line in rig.journal(unit_c).splitlines():
        if line.startswith("{"):
            ctl = json.loads(line)
    rig.wait_gone(unit_c, 20)
    quote_ok = os.path.isdir(QUOTE_DIR) and QUOTE_DIR in rig.hidden_extra and bool(ctl) and ctl.get("text") == "rbtest"
    if hp["ok"] and cp["ok"] and page and quote_ok:
        return "PASS", (f"{hp['detail']} (including a path with a space and a double quote); the same directory is readable from a unit that does not hide it; "
                        "Chromium renders and loads an https page (TLS roots); links needing xdg-open are checked under G13")
    return "FAIL", f"hidden paths: {hp['detail']}; chromium: {cp['detail']}; https page: {page}; quoted path hidden by the probe and readable without the entry: {quote_ok} ({ctl})"


@gate("G07", "empty /etc/chromium.d: no Debian default flags")
def g7(rig, ctx):
    s = ctx["session"] or rig.start_session()
    ctx["session"] = s
    s.wait_sockets()
    time.sleep(4)
    cmds = [s.cmdline(p) for p in s.pids()]
    main = [c for c in cmds if c.split(" ")[0].endswith(("chromium", "chrome")) and "--type=" not in c]
    bad = [f for c in main for f in ("--enable-remote-extensions", "--load-extension=", "--enable-gpu-rasterization") if f in c]
    s.stop()
    ctx["session"] = None
    if not main:
        return "FAIL", "no browser process found in the unit"
    return ("PASS", "the wrapper starts with no Debian default flags") if not bad else ("FALLBACK", f"flags present {sorted(set(bad))}: exec /usr/lib/chromium/chromium directly")


@gate("G03", "BindsTo accepted, a stopped dummy takes the session unit down")
def g3(rig, ctx):
    dummy = f"{rig.TP}{rig.ident()}.service"
    rig.units.append(dummy)
    rc, _, err = sh([rig.L.find_tool("systemd-run"), f"--unit={dummy[:-8]}", "--collect", "--quiet", "--no-block", "-p", "RuntimeMaxSec=120", "/bin/sleep", "300"], 20)
    if rc != 0:
        return "FAIL", f"the dummy unit did not start: {err[:150]}"
    time.sleep(1)
    rc, err, unit = rig.run_unit(["/bin/sleep", "300"], spec=rig.spec(portal_unit=dummy), wait=False)
    time.sleep(2)
    st = rig.unit_state(unit).get("ActiveState")
    accepted = rc == 0 and st in ("active", "activating")
    rig.stop_unit(dummy)
    gone = rig.wait_gone(unit, 15)
    if not accepted:
        return "FALLBACK", f"BindsTo/After is refused on a transient unit ({err[:100]}): rely on shutdown() and the start-up sweep"
    rig.stop_unit(unit)
    return ("PASS", "BindsTo accepted; stopping the dummy stopped the unit") if gone else ("FALLBACK", "BindsTo accepted but the unit did not follow: rely on shutdown() and the start-up sweep")


@gate("G08", "slice properties and CPU weight under load")
def g8(rig, ctx):
    show = rig.systemctl("show", "-p", "CPUWeight", "-p", "CPUQuotaPerSecUSec", "-p", "MemoryMax", "-p", "TasksMax", rig.L.SLICE)[1]
    want = rig.L.slice_properties(rig.cfg, rig.ncpu, rig.mem_total)
    mem = [w for w in want if w.startswith("MemoryMax=")][0]
    mem_bytes = int(mem.split("=")[1][:-1]) << 20
    reported = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
    shown_ok = reported.get("CPUWeight") == "50" and reported.get("MemoryMax") == str(mem_bytes) and reported.get("TasksMax") == str(rig.cfg["rbrowser_max_sessions"] * 512)
    if not shown_ok:
        return "FALLBACK", f"slice properties not reported as set ({reported}): the card says no CPU priority below live video and seats are halved"
    burner = f"{rig.TP}{rig.ident()}.service"
    s = rig.start_session(cpu_percent=rig.L.seats(rig.cfg, rig.ncpu, rig.mem_total)["cpu_percent"])
    s.wait_sockets()
    try:
        nv = s.open_page()
        nv.nav(page_url(PAGES["video"], "vid"))
        s.wait_title("vid")
        # The burner starts only now, so that session start and page load do not eat into its life. It is an ordinary
        # transient unit in system.slice with RuntimeMaxSec=120 (the window below is 30 s), so it ends by itself even if
        # this process is killed. No CPUQuota on purpose: a cap below the host's core count would leave a core idle and
        # the gate would no longer measure what the slice's CPUWeight=50 does against competing load.
        rig.units.append(burner)
        sh([rig.L.find_tool("systemd-run"), f"--unit={burner[:-8]}", "--collect", "--quiet", "--no-block", "-p", "RuntimeMaxSec=120",
            "/usr/bin/python3", "-I", "-S", "-c",
            "import os, time\nfor _ in range(4):\n    if os.fork() == 0:\n        while True: pass\ntime.sleep(3600)\n"], 20)
        for _ in range(40):
            if rig.unit_state(burner).get("ControlGroup"):
                break
            time.sleep(0.25)
        time.sleep(1)
        burn_cg = Path(f"/sys/fs/cgroup{rig.unit_state(burner)['ControlGroup']}/cpu.stat")
        slice_cg = Path(f"/sys/fs/cgroup/{rig.L.SLICE_CGROUP}/cpu.stat")
        a1, b1 = parse_cpu_stat(slice_cg.read_text())["usage_usec"], parse_cpu_stat(burn_cg.read_text())["usage_usec"]
        time.sleep(30)
        a2, b2 = parse_cpu_stat(slice_cg.read_text())["usage_usec"], parse_cpu_stat(burn_cg.read_text())["usage_usec"]
        nv.close()
    finally:
        s.stop()
        rig.stop_unit(burner)
    da, db = a2 - a1, b2 - b1
    share = da / max(1, da + db)
    return ("PASS" if share < 1 / 3 else "FAIL"), f"over 30 s the browser slice used {share:.0%} of the cpu with a 4-thread burner beside it (bar: below 33%); slice {da / 1e6:.1f} s, burner {db / 1e6:.1f} s"


PAGE_INFO_CLICKS = [("lock icon", (138, 63))]
POPUP_BAND_H = 90      # the address bar and tab strip: nothing of a page may cover the top 90 px


def js_codepoints(text):
    """A JavaScript expression that builds `text` from code points: the page's address is typed through VNC, which is unreliable for
    characters above U+FFFF, so no such character appears in an address."""
    return "String.fromCodePoint(" + ",".join(str(ord(c)) for c in text) + ")"


def describe_windows(infos):
    return ", ".join(f"{w['w']}x{w['h']}+{w['x']}+{w['y']}{' OR' if w['or'] else ''}{' transient' if w['transient'] else ''} type={w['type']}" for w in infos) or "none"


@gate("G09", "popups and second windows that the window manager manages are full-screen with Chromium's own toolbar; override-redirect windows (select lists, menus, tooltips) are a residual risk that is measured and reported, not judged")
def g9(rig, ctx):
    notes, failed = [], []
    s = rig.start_session(width=1280, height=720)
    s.wait_sockets()
    try:
        nv = s.open_page()
        body = ("<body style=margin:0><button style=width:1000px;height:500px onclick=\"var p=window.open('about:blank','p','left=0,top=0,width=420,height=240');"
                "setTimeout(()=>{p.moveTo(600,400);p.resizeTo(300,200)},600);window.open('about:blank','q','left=700,top=300,width=300,height=200')\">open</button>")
        nv.nav(page_url(body, "popup1"))
        ok, t = s.wait_title("popup1")
        screen = s.screen()
        before = {w["id"] for w in s.top_info()}
        nv.click(500, 300)
        time.sleep(3.0)
        after = s.top_info()
        new = [w for w in after if w["id"] not in before]
        shot1 = nv.shot("g09-popup.png")
        # a second browser window of its own (Ctrl+N)
        nv.chord([0xFFE3], 0x6E)
        time.sleep(3.0)
        after2 = s.top_info()
        new2 = [w for w in after2 if w["id"] not in before and w["id"] not in {x["id"] for x in new}]
        shot2 = nv.shot("g09-second-window.png")
        nv.close()
    finally:
        s.stop()
    if not ok:
        return "FAIL", f"the test page did not load (title {t!r})"
    managed = [w for w in after2 if not w["or"]]
    full = lambda w: (w["x"], w["y"], w["w"], w["h"]) == (0, 0, screen[0], screen[1])
    if not new:
        failed.append(f"no popup window appeared after the click ({describe_windows(after)})")
    if not new2:
        failed.append(f"no second window appeared after Ctrl+N ({describe_windows(after2)})")
    notes.append(f"screen {screen[0]}x{screen[1]}; new after window.open (moveTo and resizeTo asked 600,400 300x200 and the features 0,0 420x240): {describe_windows(new)}; new after Ctrl+N: {describe_windows(new2)}")
    bad = [w for w in managed if not full(w)]
    if bad:
        failed.append(f"windows that are not the full screen at 0,0: {describe_windows(bad)}")
    covered = [w for w in managed if w["y"] > 0 or w["x"] > 0]
    if covered:
        failed.append(f"a window does not start at 0,0: {describe_windows(covered)}")
    notes.append(f"pictures {shot1}, {shot2}: every popup is a full-screen window with Chromium's own toolbar")
    # override-redirect windows: what a menu, a select list and a tooltip can do (a person looks at them: nothing places them but Chromium)
    orw = []
    for (w, h) in ((1280, 720), (560, 480)):
        s2 = rig.start_session(width=w, height=h)
        s2.wait_sockets()
        try:
            nv = s2.open_page(viewport=(w + 20, h + 20))
            body = ("<body style=margin:0><div title='a tooltip' style=position:absolute;left:0;top:0;width:100%;height:40%;background:#ccc>hover</div>"
                    "<select id=s style=position:absolute;bottom:10px;left:10px;width:200px;height:60px>"
                    + "".join(f"<option>option {i}</option>" for i in range(40)) + "</select>"
                    "<input list=dl id=i style=position:absolute;bottom:10px;left:300px;width:200px;height:40px><datalist id=dl>"
                    + "".join(f"<option value='suggestion {i}'>" for i in range(40)) + "</datalist>")
            nv.nav(page_url(body, "orwin"))
            s2.wait_title("orwin")
            time.sleep(1)
            # the select sits in the lower part of the screen: its list opens upward or downward, Chromium decides
            base = {x["id"] for x in s2.top_info()}
            found = {}
            for label, act in (("context menu", lambda: nv.click(w // 2, h - 40, button="right")),
                               ("select list", lambda: nv.click(60, h - 40)),
                               ("datalist popup", lambda: (nv.click(400, h - 30), time.sleep(0.4), nv.chord([], 0xFF54))),
                               ("tooltip", lambda: (nv.hover(w // 2, 200), time.sleep(0.3), nv.hover(w // 2 + 2, 202), time.sleep(1.5)))):
                act()
                time.sleep(2.0)
                cur = [x for x in s2.top_info() if x["id"] not in base]
                found[label] = cur
                nv.chord([], 0xFF1B)
                time.sleep(0.6)
            nv.close()
        finally:
            s2.stop()
        for label, ws in found.items():
            if not ws:
                orw.append(f"{w}x{h} {label}: no separate window seen")
            for x in ws:
                reach = "REACHES the top %d px" % POPUP_BAND_H if x["y"] < POPUP_BAND_H else "stays below the top %d px" % POPUP_BAND_H
                orw.append(f"{w}x{h} {label}: {x['w']}x{x['h']}+{x['x']}+{x['y']} override-redirect {x['or']}, {reach}")
    notes.append("override-redirect windows (nothing here places them but Chromium, on a user action; a window manager is never asked about them): " + "; ".join(orw))
    notes.append("not tested: autofill popups (an ephemeral profile has nothing to fill in)")
    if failed:
        return "FAIL", "; ".join(failed + notes)
    reaching = [x for x in orw if "REACHES" in x]
    if reaching:
        # R2 (decision of round 2): an accepted limit, not a failure. The select list and the datalist popup are override-redirect
        # windows that Chromium sizes and places, a page does not and the window manager cannot; MIN_H stays 480.
        return "RESIDUAL", ("accepted limit (R2), not a FAIL: at small screen heights an override-redirect list (the option text is chosen by the page, "
                            "Chromium places the window) reaches the toolbar band, so the address bar of the remote browser is not a security indicator "
                            "at very small window sizes: " + "; ".join(reaching) + "; " + "; ".join(notes))
    return "PASS", "; ".join(notes)


def root_windows(s):
    """EVERY child of the root with a size of at least 8x8, mapped or not (top_info drops windows that are not viewable: a window that the
    window manager refused is not viewable, and would look as if Chromium never created it)."""
    rc, out = s.x(["/usr/bin/xwininfo", "-root", "-tree"])
    return [w for w in (parse_xwininfo(out) if rc == 0 else []) if w["w"] >= 8 and w["h"] >= 8]


def all_window_ids(s):
    """The ids of every window of the display at any depth (root children and their descendants)."""
    rc, out = s.x(["/usr/bin/xwininfo", "-root", "-tree"])
    return {m.group(2) for m in map(_WIN.match, out.splitlines() if rc == 0 else []) if m}


def deep_windows(s):
    """Descendants of the root's children (depth > 1) of at least 8x8: [(id, w, h, x, y)]."""
    rc, out = s.x(["/usr/bin/xwininfo", "-root", "-tree"])
    res = []
    for line in out.splitlines() if rc == 0 else []:
        m = _WIN.match(line)
        if m and len(m.group(1)) > 5 and int(m.group(6)) >= 8 and int(m.group(7)) >= 8:
            res.append((m.group(2), int(m.group(6)), int(m.group(7)), int(m.group(8)), int(m.group(9))))
    return res


def parse_xprop_window(text):
    """xprop of one window -> {class, role, state, type, transient (hex id or None)}. A property that is not there is None / []. Names
    are never asked for."""
    def val(key):
        m = re.search(rf"^{key}\([A-Z_]+\)\s*=\s*(.*)$", text, re.M)
        return m.group(1).strip() if m else None
    tr = re.search(r"^WM_TRANSIENT_FOR\(WINDOW\):\s*window id # (0x[0-9a-f]+)", text, re.M)
    names = lambda v: [x.strip().replace("_NET_WM_STATE_", "").replace("_NET_WM_WINDOW_TYPE_", "") for x in v.split(",")] if v else []
    return {"class": [x.strip().strip('"') for x in (val("WM_CLASS") or "").split(",") if x.strip()], "role": (val("WM_WINDOW_ROLE") or "").strip('"') or None,
            "state": names(val("_NET_WM_STATE")), "type": names(val("_NET_WM_WINDOW_TYPE")), "transient": tr.group(1) if tr else None}


def measure_new(s, known_ids, trigger):
    """The root children that are not in `known_ids`, each with override-redirect, map state, geometry, WM_CLASS, role, state, type,
    WM_TRANSIENT_FOR (and whether that is the main browser window) and what the window manager's rule (wm_may_show) says about it. No names."""
    cands = [w for w in root_windows(s) if w["id"] in known_ids and w["cls"].lower() == "chromium" and w["w"] >= 120 and w["h"] >= 120]
    main = max(cands, key=lambda w: w["w"] * w["h"]) if cands else None
    main_id = int(main["id"], 16) if main else None
    rows = []
    for wid, depth in [(w["id"], 1) for w in root_windows(s) if w["id"] not in known_ids] + [(d[0], 2) for d in deep_windows(s) if d[0] not in known_ids]:
        rc, o = s.x(["/usr/bin/xwininfo", "-id", wid, "-stats"])
        st = parse_stats(o)
        rc2, o2 = s.x(["/usr/bin/xprop", "-id", wid, "WM_CLASS", "WM_WINDOW_ROLE", "_NET_WM_STATE", "_NET_WM_WINDOW_TYPE", "WM_TRANSIENT_FOR"])
        pr = parse_xprop_window(o2)
        shown = pr["role"] in ("browser", "pop-up") and "ABOVE" not in pr["state"]
        rows.append({"trigger": trigger + ("" if depth == 1 else " (a child of another window, not a top-level)"), "id": wid, "depth": depth, "or": st["or"], "viewable": st["viewable"],
                     "geom": f"{st['w']}x{st['h']}+{st['x']}+{st['y']}", **pr,
                     "transient_main": pr["transient"] is not None and main_id is not None and int(pr["transient"], 16) == main_id,
                     "refused_by_rule": depth == 1 and (not st["or"]) and not shown})
    return rows


def describe_rows(rows):
    return " || ".join(f"[{r['trigger']}] OR={r['or']} viewable={r['viewable']} {r['geom']} class={'/'.join(r['class']) or '-'} role={r['role'] or '-'} "
                       f"type={','.join(r['type']) or '-'} state={','.join(r['state']) or '-'} transient={'main' if r['transient_main'] else (r['transient'] or '-')} "
                       f"refused_by_the_current_rule={r['refused_by_rule']}" for r in rows) or "no new window"


def no_fit_transient(text):
    """session.py whose window manager does not fit a window that has WM_TRANSIENT_FOR: it keeps the geometry Chromium created it with (measurement only)."""
    old = "            if name == \"fit\":\n                x11.XMoveResizeWindow(dpy, win, 0, 0, w, ht)\n"
    new = "            if name == \"fit\":\n                if self._property(win, b\"WM_TRANSIENT_FOR\") is None:\n                    x11.XMoveResizeWindow(dpy, win, 0, 0, w, ht)\n"
    if old not in text:
        raise RuntimeError("the window manager's fit is not where the test expects it")
    return text.replace(old, new, 1)


PERM_BODY = ("<meta charset=utf-8><title>perm</title><body style=margin:0>"
             "<button style=display:block;width:100%;height:150px onclick=\"navigator.geolocation.getCurrentPosition(p=>document.title='geo:ok',e=>document.title='geo:'+e.code)\">geo</button>"
             "<button style=display:block;width:100%;height:150px onclick=\"Notification.requestPermission().then(r=>document.title='notif:'+r)\">notif</button>"
             "<button style=display:block;width:100%;height:150px onclick=\"navigator.clipboard.readText().then(t=>document.title='clip:ok',e=>document.title='clip:'+e.name)\">clip</button>")


def measure_permissions(rig, tag, policy_keys=()):
    """A secure (file:) page asks for geolocation, notifications and clipboard-read, one click each; the windows that appear are measured.
    The page is a file of the unit's own /tmp, so URLBlocklist is lifted (like try_pip_in_secure_context)."""
    rows, notes = [], []
    with policy_without(rig, "URLBlocklist", *policy_keys):
        s = rig.start_session(width=1280, height=720)
        s.wait_sockets()
        try:
            page = Path(rig.paths.tmp_dir) / s.spec.ident / "perm.html"
            page.write_text(PERM_BODY)
            os.chmod(page, 0o644)
            nv = s.open_page()
            time.sleep(3)
            nv.nav("file:///tmp/perm.html")
            s.wait_title("perm")
            for label, y in (("geolocation", 160), ("notifications", 300), ("clipboard read", 440)):
                known = all_window_ids(s)
                nv.click(300, y)
                time.sleep(2.5)
                got = measure_new(s, known, f"{tag} {label}")
                rows += got
                notes.append(f"{label}: page says {s.title()[:20]!r}, {len(got)} new window(s), picture {nv.shot(f'g09b-{tag}-{label.split()[0]}.png')}")
                nv.chord([], 0xFF1B)
                time.sleep(0.8)
            nv.close()
        finally:
            s.stop()
    return rows, notes


def g09b_verdict(control, rule):
    """T2, the hard part of G09b: document Picture-in-Picture under the window manager's real rule. `control` is the try_pip_in_secure_context
    result with the window manager showing every window (the Chromium switch removed), `rule` the one with the real rule (only the switch
    removed); None = the page could not be built. -> (status, text).
    FAIL: the control shows a new viewable window and the rule run shows one too (the page got a window the window manager should refuse).
    INCONCLUSIVE: the control shows none (nothing proves that the rule run had a window to refuse; counts as a FAIL for the release), or the
    rule run did not run. PASS: the control shows a window and the rule run none. Re-run on every Chromium update (the rule depends on how
    Chromium builds this window)."""
    if control is None or not new_windows(control):
        return "INCONCLUSIVE", ("the control (window manager shows every window, Chromium switch removed) shows no new viewable window, so the "
                                "refusal of document Picture-in-Picture is unproven: " + (control or {}).get("res", "not built"))
    if rule is None:
        return "INCONCLUSIVE", "the run under the window manager's real rule could not be built, the control shows " + describe_windows(new_windows(control))
    shown = new_windows(rule)
    if shown:
        return "FAIL", f"document Picture-in-Picture shows a new viewable window under the window manager's real rule: {describe_windows(shown)} (control: {describe_windows(new_windows(control))})"
    return "PASS", f"document Picture-in-Picture: the control shows {describe_windows(new_windows(control))}, the run under the real rule shows no new viewable window"


@gate("G09b", "HARD for R3/T2: document Picture-in-Picture stays unmapped under the window manager's rule (re-run on every Chromium update); also MEASURES every window Chromium creates for its own UI (omnibox, page info, permission prompts) and the controls (video Picture-in-Picture, the file dialog)")
def g09b(rig, ctx):
    rows, notes = [], []
    with wm_shows_everything(rig, no_fit_transient):
        s = rig.start_session(width=1280, height=720)
        s.wait_sockets()
        try:
            nv = s.open_page()
            time.sleep(3)
            base = all_window_ids(s)
            nv.chord([0xFFE3], 0x6C)
            time.sleep(0.5)
            nv.type_text("examp")
            time.sleep(2.5)
            rows += measure_new(s, base, "omnibox typing")
            notes.append("omnibox picture " + nv.shot("g09b-omnibox.png"))
            nv.type_text("le.com")
            nv.page.evaluate("() => rfb.sendKey(0xFF0D, null)")
            ok, t = s.wait_title("Example Domain", 20)
            time.sleep(2)
            notes.append(f"example.com loaded: {ok}; picture {nv.shot('g09b-example.png')}")
            known = all_window_ids(s)
            for label, (px, py) in PAGE_INFO_CLICKS:
                nv.click(px, py)
                time.sleep(2)
                got = measure_new(s, known, f"page info click {px},{py}")
                rows += got
                notes.append(f"{label}: {len(got)} new window(s), picture {nv.shot(f'g09b-pageinfo-{px}.png')}")
                nv.chord([], 0xFF1B)
                time.sleep(0.8)
            nv.close()
        finally:
            s.stop()
        # the smallest screen the feature allows (MIN_H 480): a bubble that is taller than the browser window cannot be drawn inside it
        s3 = rig.start_session(width=560, height=480)
        s3.wait_sockets()
        try:
            nv = s3.open_page(viewport=(580, 500))
            time.sleep(3)
            nv.nav("https://example.com/")
            ok, t = s3.wait_title("Example Domain", 20)
            time.sleep(2)
            known = all_window_ids(s3)
            nv.click(138, 63)
            time.sleep(2)
            got = measure_new(s3, known, "560x480 page info click")
            rows += got
            notes.append(f"560x480 page info: example.com loaded {ok}, {len(got)} new window(s), picture {nv.shot('g09b-small-pageinfo.png')}")
            nv.chord([], 0xFF1B)
            time.sleep(0.8)
            known = all_window_ids(s3)
            nv.chord([0xFFE3], 0x6C)
            time.sleep(0.4)
            nv.type_text("examp")
            time.sleep(2)
            got = measure_new(s3, known, "560x480 omnibox typing")
            rows += got
            notes.append(f"560x480 omnibox: {len(got)} new window(s), picture {nv.shot('g09b-small-omnibox.png')}")
            nv.close()
        finally:
            s3.stop()
        r1, n1 = measure_permissions(rig, "shipped")
        r2, n2 = measure_permissions(rig, "control", ("DefaultGeolocationSetting", "DefaultNotificationsSetting"))
        rows += r1 + r2
        notes += n1 + n2
        with policy_without(rig, "AllowFileSelectionDialogs"):
            try_file_dialog(rig, "measure", rows)
        pip = try_pip_in_secure_context(rig, "measure-doc", patch=lambda t: no_fit_transient(show_every_window(drop_doc_pip_switch(t))), shot_name="g09b-docpip")
        vpip = try_pip_in_secure_context(rig, "measure-video", body=VIDEO_PIP_BODY, title="vpip", patch=lambda t: no_fit_transient(show_every_window(t)), shot_name="g09b-videopip")
        # the same document PiP with the window manager's real refusal (only the Chromium switch removed): is the window mapped?
        rule = try_pip_in_secure_context(rig, "measure-doc-rule", patch=drop_doc_pip_switch, shot_name="g09b-docpip")
        notes.append("document PiP with the Chromium switch removed and the window manager's real rule: "
                     + ("not built" if rule is None else f"new viewable windows {describe_windows(new_windows(rule))}; picture {rule['shot']}"))
        for lab, r in (("document PiP", pip), ("video PiP", vpip), ("document PiP (window manager's real rule)", rule)):
            notes.append(f"{lab}: {(r or {}).get('res', 'not built')}; new windows' role, state, type, transient-for: " + " ;; ".join((r or {}).get("new_short", []))
                         + "; all properties: " + " ;; ".join((r or {}).get("new_props", [])))
    rig.save("g09b-notes.txt", "\n".join(notes) + "\n")
    out = rig.save("g09b-rows.json", json.dumps(rows, indent=1))
    return g09b_result(pip, rule, rows, notes, out)


def g09b_result(pip, rule, rows, notes, out):
    """The end of G09b: the gate's status IS the verdict's status (a test calls this with a control window and a rule window and expects FAIL)."""
    status, verdict = g09b_verdict(pip, rule)
    return status, f"{verdict} || rows saved to {out}; " + describe_rows(rows) + " || NOTES: " + "; ".join(notes)


@gate("G10", "display ownership with a squatted name")
def g10(rig, ctx):
    squat = []
    stop = threading.Event()
    hits = {"n": 0}
    for n in range(0, 4):
        sk = socket.socket(socket.AF_UNIX)
        sk.bind("\0/tmp/.X11-unix/X" + str(n))
        sk.listen(4)
        sk.settimeout(0.5)
        squat.append(sk)

    def serve():
        while not stop.is_set():
            for sk in squat:
                try:
                    c, _ = sk.accept()
                    hits["n"] += 1
                    c.close()
                except OSError:
                    pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        s = rig.start_session()
        ok = s.wait_sockets(20)
        time.sleep(2)
        disp = s.find_display()
        pong = None
        try:
            pong = s.ctl({"op": "ping"})
        except OSError:
            pass
        state = s.show()
        s.stop()
    finally:
        stop.set()
        th.join(3)
        for sk in squat:
            sk.close()
    if hits["n"]:
        return "FAIL", f"a client of the session connected to the squatted name {hits['n']} time(s)"
    if ok and pong == {"ok": True} and disp is not None and disp > 3:
        return "PASS", f"the session runs on display :{disp}; the squatter of :0 to :3 saw no connection"
    return "FAIL", f"sockets {ok}, ping {pong}, display {disp}, state {state}"


@gate("G11", "after a resize the Chromium window has the new screen size (xrandr and the window manager)")
def g11(rig, ctx):
    S = rig.sess_mod
    s = rig.start_session()
    s.wait_sockets()
    rows, failed = [], []
    try:
        time.sleep(3)
        for ask in ((560, 480), (1920, 1200), (1001, 701), (300, 200), (1280, 720)):
            want = S.clamp_geometry(*ask)
            t0 = time.time()
            reply = s.ctl({"op": "resize", "w": ask[0], "h": ask[1]})
            took = time.time() - t0
            scr = s.screen()
            reached, win = s.wait_main_window(want, 5.0)
            shown = "none" if not win else "%dx%d+%d+%d" % (win["w"], win["h"], win["x"], win["y"])
            rows.append(f"{ask[0]}x{ask[1]} -> screen {scr}, window {shown}, reply {reply.get('ok')} in {took:.2f} s")
            if reply != {"ok": True} or scr != want or not reached or took > 2.0:
                failed.append(f"{ask[0]}x{ask[1]} (expected {want[0]}x{want[1]})")
        cmds = [s.cmdline(p) for p in s.pids() if "chrom" in s.cmdline(p)]
        debug = [c for c in cmds if "--remote-debugging" in c]
        log = rig.journal(s.unit)
        wm_lines = [l for l in log.splitlines() if "window manager:" in l]
    finally:
        s.stop()
    detail = "; ".join(rows) + f"; Chromium processes {len(cmds)}, with a debugging flag {len(debug)}; window manager log lines {len(wm_lines)}"
    if debug:
        failed.append("Chromium has a debugging flag")
    if failed:
        return "FAIL", "did not follow: " + ", ".join(failed) + "; " + detail
    return "PASS", detail


FS_PIP_BODY = ("<body style=margin:0><button style=width:100%;height:300px onclick=\"var r=['secure:'+window.isSecureContext];"
               "document.documentElement.requestFullscreen().then(()=>r.push('fs:ok'),e=>r.push('fs:'+e.name));"
               "if(window.documentPictureInPicture){documentPictureInPicture.requestWindow({width:300,height:200}).then(w=>r.push('pip:opened'),e=>r.push('pip:'+e.name))}else{r.push('pip:absent')}"
               "setTimeout(()=>{document.title='res:'+r.join(',')},1500)\">go</button>")
F11_BODY = "<body style=margin:0><script>setInterval(()=>{document.title='h:'+innerHeight+':'+(document.fullscreenElement?1:0)},200)</script>"


def try_fullscreen_pip(rig, tag="full"):
    """A click (a user gesture) asks for requestFullscreen and documentPictureInPicture.requestWindow; F11 is pressed on another page.
    -> {"res": the page's own answer, "windows_before", "windows_after": top-level windows, "f11": (inner height before, after), "shots"}"""
    s = rig.start_session(width=1280, height=720)
    s.wait_sockets()
    out = {}
    try:
        nv = s.open_page()
        time.sleep(3)
        # F11 first (the control must be able to change the page's height), then F11 again to leave it, then the gesture page
        nv.nav(page_url(F11_BODY, "f11"))
        time.sleep(1.5)
        h0 = s.title()
        nv.chord([], 0xFFC8)
        time.sleep(2.5)
        h1 = s.title()
        out["f11"] = (h0, h1)
        out["shot_f11"] = nv.shot(f"g13-f11-{tag}.png")
        nv.chord([], 0xFFC8)
        time.sleep(2.0)
        nv.nav(page_url(FS_PIP_BODY, "fspip"))
        s.wait_title("fspip")
        out["windows_before"] = s.top_info()
        nv.click(300, 150)
        ok, t = s.wait_title("res:", 6)
        time.sleep(1.5)
        out["res"] = t if ok else f"no answer (title {t[:40]!r})"
        out["windows_after"] = s.top_info()
        out["shot_gesture"] = nv.shot(f"g13-fullscreen-pip-{tag}.png")
        nv.close()
    finally:
        s.stop()
    return out


PIP_FILE_BODY = ("<meta charset=utf-8><title>pipfile</title><body style=margin:0><button style=width:100%;height:300px onclick=\"var r=['secure:'+window.isSecureContext];"
                 "if(window.documentPictureInPicture){documentPictureInPicture.requestWindow({width:300,height:200}).then(w=>{r.push('pip:opened');"
                 "w.document.body.textContent='x'},e=>r.push('pip:'+e.name))}else{r.push('pip:absent')}"
                 "setTimeout(()=>{document.title='res:'+r.join(',')},1500)\">go</button>")


def drop_doc_pip_switch(text):
    """session.py without the Chromium switch that turns document Picture-in-Picture off, so a document PiP window can open at all (a measurement:
    the window manager's own answer to such a window is what G09b records). Raises when the switch is not where the test expects it."""
    out, n = re.subn(r'"--disable-features=DocumentPictureInPictureAPI", ?', "", text)
    if n == 0:
        raise RuntimeError("the document Picture-in-Picture switch is not where the test expects it")
    return out


def try_pip_in_secure_context(rig, tag, chromium_flag_removed=False, body=None, title="pipfile", patch=None, shot_name="g13-pip-file"):
    """documentPictureInPicture needs a secure context, which a data: page is not. A file: page is one, but the policy blocks file:, so this
    runs in a session whose policy tree lacks URLBlocklist (a property of the browser, not of the policy). The page is a file in the unit's own
    /tmp directory, written from the host. With chromium_flag_removed the session.py of the unit has the PiP feature switch patched out.
    -> {"res", "windows_before", "windows_after", "shot"}"""
    L = rig.L
    patched = None
    body = body or PIP_FILE_BODY
    if chromium_flag_removed or patch:
        src = rig.tmp / "patched-pip"
        src.mkdir(exist_ok=True)
        text = (ROOT / "rbrowser_unit" / "session.py").read_text()
        if patch:
            patched = patch(text)
            n = 1 if patched is not None and patched != text else 0
        else:
            # the control without the feature switch: the window manager also maps every window, or its refusal (G13b) would hide the PiP window
            patched, n = re.subn(r'"--disable-features=DocumentPictureInPictureAPI", ?', "", text)
            patched = show_every_window(patched)
        if n == 0:
            return None
        (src / "session.py").write_text(patched)
        shutil.copy(ROOT / "rbrowser_unit" / "probe.py", src / "probe.py")
        L.write_static_tree(rig.paths, rig.policy, src)
    out = {}
    try:
        with policy_without(rig, "URLBlocklist"):
            s = rig.start_session(width=1280, height=720)
            s.wait_sockets()
            try:
                page = Path(rig.paths.tmp_dir) / s.spec.ident / "pip.html"
                page.write_text(body)
                os.chmod(page, 0o644)
                nv = s.open_page()
                time.sleep(3)
                nv.nav("file:///tmp/pip.html")
                ok, _ = s.wait_title(title)
                out["windows_before"] = s.top_info()
                nv.click(300, 150)
                ok2, t = s.wait_title("res:", 6)
                time.sleep(1.5)
                out["res"] = t if ok2 else f"no answer (page loaded {ok}, title {t[:40]!r})"
                out["windows_after"] = s.top_info()
                out["new_props"] = [s.window_props(w["id"], full=True) for w in out["windows_after"] if w["id"] not in {x["id"] for x in out["windows_before"]}]
                out["new_short"] = [s.window_props(w["id"]) for w in out["windows_after"] if w["id"] not in {x["id"] for x in out["windows_before"]}]
                out["old_props"] = [s.window_props(w["id"], full=True) for w in out["windows_before"]]
                out["shot"] = nv.shot(f"{shot_name}-{tag}.png")
                nv.close()
            finally:
                s.stop()
    finally:
        if patched is not None:
            L.write_static_tree(rig.paths, rig.policy, ROOT / "rbrowser_unit")
    return out


@gate("G13", "policy, extended")
def g13(rig, ctx):
    s = rig.start_session()
    s.wait_sockets()
    try:
        nv = s.open_page()
        time.sleep(3)
        nv.nav("chrome://policy")
        time.sleep(4)
        shot_pol = nv.shot("g13-chrome-policy.png")
        # links to other programs start no process
        body = "<body style=margin:0><a href=mailto:a@b.example style=display:block;height:300px;background:red>m</a><a href=foo:bar style=display:block;height:300px;background:blue>f</a>"
        nv.nav(page_url(body, "links"))
        ok, t = s.wait_title("links")
        before = set(s.pids())
        nv.click(300, 200)
        time.sleep(1.5)
        nv.click(300, 450)
        time.sleep(2.5)
        new = [p for p in set(s.pids()) - before]
        foreign = [(p, s.exe(p)) for p in new if not s.exe(p).startswith(("/usr/lib/chromium", "/usr/bin/python"))]
        shot_links = nv.shot("g13-links.png")
        nv.close()
    finally:
        s.stop()
    ok2, res, _ = rig.snippet(NET_SNIPPET)
    block = bool(res and res.get("loopback_blocked"))
    if not ok:
        return "FAIL", f"the link test page did not load; picture {shot_links}"
    if foreign:
        return "FAIL", f"a click started a foreign process: {foreign[:3]}; picture {shot_links}"
    if not block:
        return "FAIL", "http://127.0.0.1/ did not show the policy block page"
    # requestFullscreen, F11 and document Picture-in-Picture (a normal window that holds page content; the window manager puts every such
    # window at the full screen, so a page could fill the screen under a drawn toolbar). The control is the policy tree without FullscreenAllowed.
    fp = try_fullscreen_pip(rig)
    with policy_without(rig, "FullscreenAllowed"):
        fp_c = try_fullscreen_pip(rig, "control")
    fs_ok, fs_ok_c = "fs:ok" in fp["res"], "fs:ok" in fp_c["res"]
    pip_opened = "pip:opened" in fp["res"] or len(fp["windows_after"]) > len(fp["windows_before"])
    # document Picture-in-Picture in a secure context: the session as it is, and a control without the PiP feature switch
    pf = try_pip_in_secure_context(rig, "session")
    pf_c = try_pip_in_secure_context(rig, "control", True)
    def pip_state(r):
        return "not run" if r is None else f"{r['res']}; new windows {describe_windows([w for w in r['windows_after'] if w['id'] not in {x['id'] for x in r['windows_before']}]) or 'none'}"
    pip_text = f"document PiP from a file: page (secure context): session: {pip_state(pf)}; control without the feature switch: {pip_state(pf_c)}"
    pf_opened = bool(pf) and ("pip:opened" in pf["res"] or len(pf["windows_after"]) > len(pf["windows_before"]))
    pf_c_opened = bool(pf_c) and ("pip:opened" in pf_c["res"] or len(pf_c["windows_after"]) > len(pf_c["windows_before"]))
    f11_changed = fp["f11"][0] != fp["f11"][1]
    f11_changed_c = fp_c["f11"][0] != fp_c["f11"][1]
    summary = (f"requestFullscreen under the full policy: {fp['res']}; control without FullscreenAllowed: {fp_c['res']}; windows before {len(fp['windows_before'])}, after {len(fp['windows_after'])} "
               f"({describe_windows([w for w in fp['windows_after'] if w['id'] not in {x['id'] for x in fp['windows_before']}])}); F11 title {fp['f11'][0]!r} -> {fp['f11'][1]!r} (control {fp_c['f11'][0]!r} -> {fp_c['f11'][1]!r}); "
               f"pictures {fp['shot_gesture']}, {fp['shot_f11']}")
    if fs_ok:
        return "FAIL", "requestFullscreen SUCCEEDED under the full policy; " + summary
    if f11_changed:
        return "FAIL", "F11 changed the page's height under the full policy; " + summary
    if pip_opened or pf_opened:
        return "FAIL", "a document Picture-in-Picture window opened in the session (the window manager makes every such window full-screen); " + pip_text + "; " + summary
    if pf is not None and "secure:true" not in pf["res"]:
        return "FAIL", "manual: the file: test page was not a secure context, so document PiP is unproven; " + pip_text + "; " + summary
    if pf_c is not None and not pf_c_opened and "pip:absent" not in pf["res"]:
        return "FAIL", "manual: the control without the feature switch did not open a PiP window either, so the refusal is unproven; " + pip_text + "; " + summary
    if not fs_ok_c:
        return "FAIL", "manual: the control (policy tree without FullscreenAllowed) did not enter fullscreen either, so the refusal is unproven; " + summary
    f11_note = "F11 changed nothing, and does change the page's height under the control (positive control)" if f11_changed_c else "F11 changed nothing under the full policy, but ALSO nothing under the control, so F11 is UNPROVEN"
    pip_note = "documentPictureInPicture: " + pip_text
    return "FAIL", (f"manual: automated parts passed (127.0.0.1 shows the block page, mailto: and foo: clicks started no foreign process, requestFullscreen refused with a positive control, {f11_note}, {pip_note} and no new window appeared); look at chrome://policy {shot_pol} (every entry OK) and {shot_links} (no Open xdg-open prompt); {summary}")


# HTMLVideoElement.requestPictureInPicture() is a different API from documentPictureInPicture: a canvas stream in a <video>, one user gesture.
VIDEO_PIP_BODY = ("<meta charset=utf-8><title>vpip</title><body style=margin:0><button style=width:100%;height:300px onclick=\"var r=['secure:'+window.isSecureContext,"
                  "'enabled:'+('pictureInPictureEnabled' in document?document.pictureInPictureEnabled:'absent')];"
                  "var c=document.createElement('canvas');c.width=640;c.height=360;var x=c.getContext('2d');x.fillStyle='#c00';x.fillRect(0,0,640,360);"
                  "setInterval(()=>{x.fillStyle='#'+(Math.random()*0xffffff|0).toString(16).padStart(6,'0');x.fillRect(0,0,640,360)},100);"
                  "var v=document.createElement('video');v.muted=true;v.srcObject=c.captureStream(10);document.body.appendChild(v);"
                  "v.play().then(()=>v.requestPictureInPicture()).then(w=>r.push('pip:opened:'+w.width+'x'+w.height),e=>r.push('pip:'+e.name))"
                  ".finally(()=>setTimeout(()=>{document.title='res:'+r.join(',')},1500))\">go</button>")


def new_windows(r):
    """The top-level windows that appeared between the two lists of a try_pip_in_secure_context result."""
    before = {x["id"] for x in r["windows_before"]}
    return [w for w in r["windows_after"] if w["id"] not in before]


def show_every_window(text):
    """session.py with the window manager's refusal switched off (the control of G13b): wm_may_show always says yes."""
    return text.replace("    return role in WM_SHOWN_ROLES and above is False", "    return True")


@gate("G13b", "video Picture-in-Picture cannot give a page a full-screen surface: the window manager never maps a window that is not a browser window")
def g13b(rig, ctx):
    """HTMLVideoElement.requestPictureInPicture() with a canvas.captureStream() video after one click. Measured before the fix: the window opened
    (type NORMAL, no WM_CLASS, no WM_WINDOW_ROLE, ABOVE and STICKY) and the window manager made it the full screen: a page-painted surface with
    no toolbar. No --disable-features / --disable-blink-features name stops it on this Chromium (tried PictureInPicture, PictureInPictureAPI,
    PictureInPictureV2: the window still opened), so the window manager refuses to map it. The control is the same page in a session whose
    window manager maps every window."""
    r = try_pip_in_secure_context(rig, "session", body=VIDEO_PIP_BODY, title="vpip", shot_name="g13b-video-pip")
    c = try_pip_in_secure_context(rig, "control", body=VIDEO_PIP_BODY, title="vpip", shot_name="g13b-video-pip", patch=show_every_window)
    if r is None or c is None:
        return "FAIL", "manual: the session or the control could not be built"
    nw, nc = new_windows(r), new_windows(c)
    text = (f"session: {r['res']}; new viewable windows {describe_windows(nw)}; control (window manager maps everything): {c['res']}; new viewable windows "
            f"{describe_windows(nc)}; pictures {r['shot']}, {c['shot']}")
    if nw:
        return "FAIL", "a video Picture-in-Picture window is on the screen; " + text
    if "pip:opened" not in r["res"]:
        return "FAIL", "manual: the page's requestPictureInPicture did not open in the session, so the refusal is unproven; " + text
    if not nc:
        return "FAIL", "manual: the control did not show a Picture-in-Picture window either, so the refusal is unproven; " + text
    full = [w for w in nc if (w["x"], w["y"], w["w"], w["h"]) == (0, 0, 1280, 720)]
    return "PASS", ("no window appears in the session although the page's requestPictureInPicture succeeded; the control, without the refusal, shows it "
                    f"{'at the full screen (the hole)' if full else 'at ' + describe_windows(nc)}; " + text)


@gate("G14", "a new tab opens the home URL")
def g14(rig, ctx):
    s = rig.start_session()
    s.wait_sockets()
    try:
        nv = s.open_page()
        time.sleep(4)
        nv.chord([0xFFE3], 0x74)
        time.sleep(4)
        t = s.title()
        shot = nv.shot("g14-newtab.png")
        nv.close()
    finally:
        s.stop()
    if "duckduckgo" in t.lower():
        return "PASS", f"the new tab's window title names the home page; picture {shot}"
    return "FAIL", f"manual: window title {t[:60]!r} does not say DuckDuckGo (offline test host?); picture {shot}"


@contextlib.contextmanager
def policy_without(rig, *keys):
    """The managed policy of the sessions without `keys`, for a positive control; the full policy is written back afterwards."""
    L = rig.L
    path = f"{rig.paths.static}/chromium/policies/managed/portal.json"
    pol = {k: v for k, v in rig.policy.items() if k not in keys}
    L._write_atomic(path, L.rbrowser_policy.policy_text(pol).encode())
    try:
        yield
    finally:
        L._write_atomic(path, L.rbrowser_policy.policy_text(rig.policy).encode())


@contextlib.contextmanager
def wm_shows_everything(rig, patch=None):
    """Sessions started inside the block have a window manager that maps every window (the refusal of non-browser windows is off), for a gate
    that must see whether Chromium OPENED a window at all (a file dialog): with the refusal on, 'no window' would also mean 'refused'. The
    unit directory's own session.py is written back afterwards."""
    L = rig.L
    src = rig.tmp / "patched-wm"
    src.mkdir(exist_ok=True)
    text = (ROOT / "rbrowser_unit" / "session.py").read_text()
    patched = show_every_window(text)
    if patched == text:
        raise RuntimeError("the window manager's refusal is not where the test expects it")
    if patch is not None:
        patched = patch(patched)
    (src / "session.py").write_text(patched)
    shutil.copy(ROOT / "rbrowser_unit" / "probe.py", src / "probe.py")
    L.write_static_tree(rig.paths, rig.policy, src)
    try:
        yield
    finally:
        L.write_static_tree(rig.paths, rig.policy, ROOT / "rbrowser_unit")


def download_files(s):
    """Files a download left in the unit (the work area of its mount namespace), seen from the host."""
    pid = (s.find("python3") or [s.res.main_pid])[0]
    root = f"/proc/{pid}/root/run/work"
    found = []
    for dp, dns, fns in os.walk(root):
        if dp.count("/") - root.count("/") > 5:
            dns[:] = []
        found += [os.path.join(dp, n)[len(root):] for n in fns if n == "probe.txt" or n.endswith(".crdownload")]
    return found


def try_download(rig, tag="full"):
    s = rig.start_session()
    s.wait_sockets()
    try:
        nv = s.open_page()
        time.sleep(3)
        body = "<body style=margin:0><a download=probe.txt href=data:text/plain;base64,SGVsbG8= style=display:block;height:600px;background:orange>dl</a>"
        nv.nav(page_url(body, "dl"))
        ok, t = s.wait_title("dl")
        nv.click(300, 300)
        time.sleep(4)
        found = download_files(s)
        shot = nv.shot(f"g15-download-{tag}.png")
        nv.close()
    finally:
        s.stop()
    return ok, found, shot


@gate("G15", "a real download is blocked")
def g15(rig, ctx):
    ok, found, shot = try_download(rig)
    with policy_without(rig, "DownloadRestrictions"):
        ok_c, found_c, shot_c = try_download(rig, "control")
    if not ok or not ok_c:
        return "FAIL", f"the test page did not load; pictures {shot}, {shot_c}"
    if not found_c:
        return "FAIL", f"manual: the positive control (the policy tree without DownloadRestrictions) saved no file either, so the click's landing is unproven; pictures {shot}, {shot_c}"
    if found:
        return "FAIL", f"a download left files in the unit under the full policy: {found[:4]}; picture {shot}"
    return "PASS", f"the same click saves {len(found_c)} file(s) under the policy tree without DownloadRestrictions and none under the full policy; pictures {shot}, {shot_c}"


def try_file_dialog(rig, tag="full", rows=None):
    s = rig.start_session()
    s.wait_sockets()
    try:
        nv = s.open_page()
        time.sleep(3)
        nv.nav(page_url("<body style=margin:0><input type=file style=width:100%;height:600px>", "fileinput"))
        s.wait_title("fileinput")
        before = {w["id"] for w in s.top_info()}
        known = all_window_ids(s)
        nv.click(300, 200)
        time.sleep(3)
        new = [w for w in s.top_info() if w["id"] not in before]
        if rows is not None:
            rows += measure_new(s, set(known), "file dialog")
        shot = nv.shot(f"g16-file-input-{tag}.png")
        nv.close()
    finally:
        s.stop()
    return new, shot


@gate("G16", "no file dialog")
def g16(rig, ctx):
    # both runs with a window manager that maps everything: the question is whether Chromium OPENS a dialog; the window manager's refusal of a
    # window that is not a browser window (which a file dialog is) would otherwise make 'no window' mean 'refused' as well
    with wm_shows_everything(rig):
        new, shot = try_file_dialog(rig)
        with policy_without(rig, "AllowFileSelectionDialogs"):
            new_c, shot_c = try_file_dialog(rig, "control")
    if not new_c:
        return "FAIL", f"manual: no window appeared under the full policy ({len(new)} new) and none under the control either (a dialog drawn inside the page or no dialog at all): look at {shot} and {shot_c}"
    if new:
        return "FAIL", f"a new window appeared after a click on a file input under the full policy ({describe_windows(new)}); picture {shot}"
    return "PASS", f"the same click opens {describe_windows(new_c)} under the policy tree without AllowFileSelectionDialogs and no window under the full policy; pictures {shot}, {shot_c}"


def type_check(s, nv, text, expect_len=None):
    """Type `text` into the test textarea of the remote browser and read it back from the window title."""
    page = page_url("<body style=margin:0><textarea autofocus style=width:100%;height:100%;font-size:40px oninput=\"document.title='v:'+this.value.length+':'+this.value.slice(-24)\"></textarea>", "ta")
    nv.nav(page)
    s.wait_title("ta")
    time.sleep(1)
    nv.click(200, 200)
    t0 = time.time()
    nv.type_text(text)
    time.sleep(1.5)
    return s.title(), time.time() - t0


def control_session_exchange(rig):
    """The positive control of the clipboard check: the same session with the no-clipboard flags patched out of x11vnc's argument
    list (a second x11vnc on the display of a running session cannot be used: the X server refuses a second one with BadAccess).
    -> (text reached the member, text reached the browser) through it"""
    src = rig.tmp / "patched-clip"
    src.mkdir(exist_ok=True)
    text = (ROOT / "rbrowser_unit" / "session.py").read_text()
    patched, n = re.subn(r"^NO_CLIPBOARD_FLAGS = \(.*?\)$", "NO_CLIPBOARD_FLAGS = ()", text, flags=re.M)
    assert n == 1
    (src / "session.py").write_text(patched)
    shutil.copy(ROOT / "rbrowser_unit" / "probe.py", src / "probe.py")
    rig.L.write_static_tree(rig.paths, rig.policy, src)
    try:
        c = rig.start_session()
        c.wait_sockets()
        try:
            time.sleep(3)
            return exchange(rig, c, f"{c.rt}/vnc.sock", "ctrl")
        finally:
            c.stop()
    finally:
        rig.L.write_static_tree(rig.paths, rig.policy, ROOT / "rbrowser_unit")


def selection_owners(s):
    """(PRIMARY owner, CLIPBOARD owner) window ids of the session's display, 0 for none. Read with libX11 in this process: a change of
    the owner is the proof that x11vnc took a selection (reading the text back with xsel did not work against x11vnc's selections)."""
    import ctypes
    x = ctypes.CDLL("libX11.so.6")
    vp, ul = ctypes.c_void_p, ctypes.c_ulong
    x.XOpenDisplay.restype, x.XOpenDisplay.argtypes = vp, [ctypes.c_char_p]
    x.XInternAtom.restype, x.XInternAtom.argtypes = ul, [vp, ctypes.c_char_p, ctypes.c_int]
    x.XGetSelectionOwner.restype, x.XGetSelectionOwner.argtypes = ul, [vp, ul]
    x.XCloseDisplay.argtypes = [vp]
    old = os.environ.get("XAUTHORITY")
    os.environ["XAUTHORITY"] = f"{s.rt}/xauth"
    d = s.display if s.display is not None else s.find_display()
    dpy = x.XOpenDisplay(f":{d}".encode())
    try:
        if not dpy:
            raise RuntimeError("the display could not be opened to read the selection owners")
        return tuple(int(x.XGetSelectionOwner(dpy, x.XInternAtom(dpy, n, 0))) for n in (b"PRIMARY", b"CLIPBOARD"))
    finally:
        if dpy:
            x.XCloseDisplay(dpy)
        if old is None:
            os.environ.pop("XAUTHORITY", None)
        else:
            os.environ["XAUTHORITY"] = old


def exchange(rig, s, sock, tag):
    """Both directions through a bridge that lets everything pass (so only x11vnc decides): -> (text of a copy in the browser reached
    the member, text sent by the member took a selection)"""
    nv = NoVnc(rig, Bridge(rig, sock, clipboard=True), (s.spec.width + 20, s.spec.height + 20))
    try:
        time.sleep(3)
        # browser -> member: copy in the page with Ctrl+C (Chromium owns the selection, with every target)
        nv.nav(copy_page(f"'{tag}-copied-in-the-browser'", "ex"))
        s.wait_title("ex")
        time.sleep(1)
        nv.click(300, 300)
        time.sleep(0.5)
        nv.bridge.needle = f"{tag}-copied".encode()
        nv.chord([0xFFE3], 0x63)
        time.sleep(4)
        # two observations of "x11vnc sent the text": noVNC's clipboard event, and the tag in the raw bytes of the stream (a ServerCutText is not compressed)
        how = []

        def seen():
            return any(tag in c for c in nv.js("() => window.__clip.slice()")) or nv.bridge.stats["saw"]
        if seen():
            how.append("ctrl-c (CLIPBOARD)")
        # variant B: a real triple click in the textarea (a user selection: PRIMARY), the stream is watched again
        nv.bridge.stats["saw"] = False
        nv.js("() => { window.__clip.length = 0 }")
        nv.triple_click(300, 20)
        time.sleep(4)
        if seen():
            how.append("mouse selection (PRIMARY)")
        # variant C: a program in the unit's display owns PRIMARY (xsel -i -p, which stays as the owner), the page is not involved
        nv.bridge.stats["saw"] = False
        nv.js("() => { window.__clip.length = 0 }")
        owner = subprocess.Popen(["/usr/bin/xsel", "-i", "-p"], env=s.xenv(), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            owner.stdin.write(f"{tag}-copied-by-a-program".encode())
            owner.stdin.close()
            time.sleep(4)
            if seen():
                how.append("a program owning PRIMARY (xsel -i -p)")
        finally:
            try:
                owner.kill()
                owner.wait(3)
            except Exception:
                pass
        to_member = bool(how)
        # member -> browser: a ClientCutText that no filter holds back; does x11vnc take a selection?
        before = selection_owners(s)
        nv.js("([m]) => rfb.clipboardPasteFrom(m)", [f"{tag}-to-the-browser"])
        time.sleep(3)
        after = selection_owners(s)
        to_browser = after != before
    finally:
        nv.close()
    return to_member, to_browser, how


def copy_page(expr, title):
    return page_url(f"<body style=margin:0><textarea id=t style=width:100%;height:100%;font-size:20px></textarea><script>t.value={expr};t.onclick=()=>t.select()</script>", title)


@gate("G17", "typed text still arrives; the VNC clipboard is dead both ways; the op clip returns what the browser copied")
def g17(rig, ctx):
    notes, failed = [], []
    s = rig.start_session()
    s.wait_sockets()
    try:
        nv = s.open_page()
        time.sleep(3)
        # 1. the address bar: type a data page whose title is the text
        url = "data:text/html,<meta charset=utf-8><title>" + G17_TEXT + "</title>"
        nv.nav(url)
        time.sleep(2)
        rc, out = s.x(["/usr/bin/xprop", "-id", s.main_window()["id"], "_NET_WM_NAME"])
        got = (re.search(r'= "(.*)"', out, re.S) or [None, ""])[1]
        if G17_TEXT in got:
            notes.append("address bar ok")
        else:
            failed.append(f"address bar: {got[:50]!r}")
        # 2. a textarea, then 5000 characters
        t, _ = type_check(s, nv, G17_TEXT)
        units = len(G17_TEXT.encode("utf-16-le")) // 2
        tail = G17_TEXT.encode("utf-16-le")[-48:].decode("utf-16-le", "surrogatepass")
        if t == f"v:{units}:{tail}":
            notes.append("textarea ok (non-Latin text and an emoji typed)")
        else:
            failed.append(f"textarea: {t[:60]!r}")
        big = ("abcdefghij" * 500)
        t, secs = type_check(s, nv, big)
        if "v:5000:" in t:
            notes.append(f"5000 characters in {secs:.1f} s")
        else:
            failed.append(f"5000 characters: {t[:40]!r}")
        nv.close()
        # 3. the VNC clipboard is dead both ways, against a control session whose x11vnc lacks the flags
        sess_dir = exchange(rig, s, f"{s.rt}/vnc.sock", "sess")
        if sess_dir[:2] != (False, False):
            failed.append(f"VNC clipboard NOT dead: to member {sess_dir[0]} ({', '.join(sess_dir[2])}), to browser {sess_dir[1]}")
        # 4. the op clip: text copied in the page with Ctrl+C
        nv = s.open_page()
        time.sleep(2)
        empty = s.ctl({"op": "clip"})
        notes.append(f"clip before any copy: ok {empty.get('ok')}, {len(empty.get('text', ''))} characters")
        short = "é ß € “q” Привет 日本語 \U0001f600"
        for label, expr, want_text, want_cut in (
                ("short text with non-Latin letters and an emoji", js_codepoints(short), short, False),
                ("300000 bytes, an emoji across the 262144 limit", "'a'.repeat(262142)+String.fromCodePoint(128512)+'b'.repeat(40000)", "a" * 262142, True),
                ("exactly 262144 bytes", "'a'.repeat(262144)", "a" * 262144, False)):
            nv.nav(copy_page(expr, "cp"))
            s.wait_title("cp")
            time.sleep(1.5 if len(want_text) < 1000 else 3)
            nv.click(300, 300)
            time.sleep(0.5)
            nv.chord([0xFFE3], 0x63)
            time.sleep(1.0)
            t0 = time.time()
            r = s.ctl({"op": "clip"}, timeout=6)
            took = time.time() - t0
            good = r.get("ok") is True and r.get("text") == want_text and r.get("truncated") is want_cut and took < 2.0
            (notes if good else failed).append(f"clip {label}: {'ok' if good else 'WRONG'} (ok {r.get('ok')}, {len((r.get('text') or '').encode())} bytes, truncated {r.get('truncated')}, {took:.2f} s)")
        nv.close()
    finally:
        s.stop()
    ctl_dir = control_session_exchange(rig)
    if not ctl_dir[1]:
        failed.append(f"VNC clipboard: the control (no flags) did not even take the member's text {ctl_dir}: the method cannot see a clipboard")
    elif not ctl_dir[0]:
        failed.append("manual: VNC clipboard member to browser is dead (the owner of PRIMARY and CLIPBOARD does not change through the session's x11vnc; it does through the same x11vnc without the flags: positive control). "
                      "Browser to member: no text reached the member through the session's x11vnc, but none reached it through the control without the flags either (Ctrl+C, a real mouse selection and a program owning PRIMARY were tried; "
                      "noVNC's clipboard event and the raw stream were watched), so this direction has NO positive control and is unproven: it depends on lane B's bridge dropping ServerCutText (D4, second barrier)")
    else:
        notes.append("VNC clipboard dead both ways through the session's x11vnc; both directions work through the same x11vnc without the flags "
                     f"(positive control; the browser-to-member text reached the member through: {', '.join(ctl_dir[2])})")
    # 5. the setting gates the op
    for mode in ("to_browser", "off"):
        s = rig.start_session(clipboard=mode)
        s.wait_sockets()
        try:
            r = s.ctl({"op": "clip"})
        finally:
            s.stop()
        (notes if r.get("ok") is False and r.get("text") == "" else failed).append(f"clip with the setting {mode}: ok {r.get('ok')}")
    if failed:
        return "FAIL", "; ".join(failed + notes)
    return "PASS", "; ".join(notes)


@gate("G18", "no host socket reachable, /run is private")
def g18(rig, ctx):
    chk = rig.probe_check(ctx["probe"], "unix_sockets")
    mnt = rig.probe_check(ctx["probe"], "mounts")
    ok, res, err = rig.snippet(SOCKETS_SNIPPET)
    if not ok or res is None:
        return "FAIL", f"the socket snippet did not run: {err[:150]}"
    bad = {p: r for p, r in res.items() if r != "ENOENT"}
    cp = rig.probe_check(ctx["probe"], "chromium_policy")
    if chk["ok"] and mnt["ok"] and not bad and cp["ok"]:
        return "PASS", f"every named socket gives ENOENT; {chk['detail']}; Chromium starts without a bus; the probe's output reached the journal"
    return "FAIL", f"sockets not ENOENT: {bad}; walk: {chk['detail']}; mounts: {mnt['detail']}; chromium: {cp['detail']}"


@gate("G19", "kernel upload limit")
def g19(rig, ctx):
    host = ctx["host"]
    if not host["upload_rule"]:
        return "FALLBACK", f"the rule is not available ({host['upload_reason']}): section 6.4 layer 2 is the control"
    L = rig.L
    # case 1: the rule was inserted by prepare_host while NO unit was running in the slice (prepare runs before the
    # first session). prepare_host starts the slice first; the jump rule must be in OUTPUT of both tools.
    chains = {}
    for name in ("iptables", "ip6tables"):
        rc, out, _ = sh([L.find_tool(name), "-w", "2", "-S", "OUTPUT"])
        rc2, out2, _ = sh([L.find_tool(name), "-w", "2", "-S", L.CHAIN])
        chains[name] = rc == 0 and L.CHAIN in out and "cgroup" in out and rc2 == 0 and "hashlimit" in out2
    res_text = f"rule inserted with no unit running, on both tools: {chains}; slice started by prepare_host: {host.get('slice_started')}"
    if not all(chains.values()):
        return "FAIL", res_text
    sink = os.environ.get("RBROWSER_UPLOAD_SINK", "")
    if not sink or ":" not in sink:
        return "FAIL", res_text + "; the rate was not measured: set RBROWSER_UPLOAD_SINK=host:port (a public TCP discard sink)"
    shost, sport = sink.rsplit(":", 1)
    code = ("import socket, time, json\n"
            f"s = socket.create_connection(({shost!r}, {int(sport)}), 5)\n"
            "buf = b'x' * 65536; t = time.time(); n = 0\n"
            "while time.time() - t < 15:\n    s.sendall(buf); n += len(buf)\n"
            "print(json.dumps({'bytes': n, 'secs': time.time() - t}))\n")

    def inside():
        ok, res, err = rig.snippet(code, timeout=60)
        return ok and res, err

    def rate(r):
        return r["bytes"] / r["secs"] * 8 / 1000
    want = rig.cfg["rbrowser_upload_kbps"]
    in1, err = inside()
    # a process outside the slice, same sink: an ordinary transient unit in system.slice, bounded to 120 s
    ctrl = f"{rig.TP}{rig.ident()}.service"
    rig.units.append(ctrl)
    sh([L.find_tool("systemd-run"), f"--unit={ctrl[:-8]}", "--collect", "--wait", "--quiet", "-p", "RuntimeMaxSec=120", "-p", "StandardOutput=journal",
        "/usr/bin/python3", "-I", "-S", "-c", code], 60)
    outside = None
    for line in rig.journal(ctrl).splitlines():
        if line.startswith("{"):
            outside = json.loads(line)
    if not in1 or not outside:
        return "FAIL", res_text + f"; the sink could not be reached from the unit ({err[:100]}); inside {in1}, outside {outside}"
    rate_in, rate_out = rate(in1), rate(outside)
    near = 0.6 * want <= rate_in <= 1.4 * want
    # case 2: the slice emptied and refilled. All test units are gone; stop the slice itself (its cgroup is removed),
    # start it again, and measure from a new unit: an inserted xt_cgroup rule that went stale would stop matching here.
    # This is information (the jump holds the cgroup it was inserted for), not a verdict: case 3 puts it right.
    for u in [u for u in rig.units if u.startswith(rig.TP)]:
        rig.stop_unit(u)
    others = rig.slice_offenders()
    if others:
        return "FAIL", res_text + f"; refused to stop the slice: {', '.join(others)} is not a unit of this test and would be killed"
    rig.systemctl("stop", L.SLICE, timeout=40)
    rig.systemctl("start", L.SLICE, timeout=40)
    in2, err2 = inside()
    if not in2:
        return "FAIL", res_text + f"; after the slice was stopped and started again the sink could not be reached ({err2[:100]})"
    rate_in2 = rate(in2)
    near2 = 0.6 * want <= rate_in2 <= 1.4 * want
    # case 3: prepare_host again (what the portal must do after any slice restart): install_firewall takes the old
    # jump away and inserts a new one for the new cgroup. Every later gate runs on this repaired state.
    host2 = rig.prepare()
    ctx["host"] = host2
    if not host2["ok"] or not host2["firewall"]:
        return "FAIL", res_text + f"; prepare_host again after the slice restart failed: {host2['reasons']}"
    in3, err3 = inside()
    if not in3:
        return "FAIL", res_text + f"; after prepare_host again the sink could not be reached ({err3[:100]})"
    rate_in3 = rate(in3)
    near3 = 0.6 * want <= rate_in3 <= 1.4 * want
    detail = (res_text + f"; inside the slice {rate_in:.0f} kbit/s (setting {want}), outside it {rate_out:.0f} kbit/s; "
              f"after the slice was stopped and started again {rate_in2:.0f} kbit/s ({'still limited' if near2 else 'NOT limited: the old jump went stale, as feared'}); "
              f"after prepare_host again {rate_in3:.0f} kbit/s")
    return ("PASS" if near and rate_out > 2 * rate_in and near3 else "FAIL"), detail


@gate("G20", "minimum window width")
def g20(rig, ctx):
    src = rig.tmp / "patched"
    src.mkdir()
    text = (ROOT / "rbrowser_unit" / "session.py").read_text()
    assert re.search(r"^MIN_W = \d+$", text, re.M)
    (src / "session.py").write_text(re.sub(r"^MIN_W = \d+$", "MIN_W = 320", text, flags=re.M))
    shutil.copy(ROOT / "rbrowser_unit" / "probe.py", src / "probe.py")
    rig.L.write_static_tree(rig.paths, rig.policy, src)
    results = {}
    try:
        for w in WIDTHS_G20:
            s = rig.start_session(width=w, height=800)
            s.wait_sockets()
            try:
                time.sleep(5)
                win = s.main_window()
                hint = s.min_width_hint()
                scr = s.screen()
                nv = s.open_page(viewport=(w + 20, 820))
                shot = nv.shot(f"g20-width-{w}.png")
                nv.close()
            finally:
                s.stop()
            results[w] = (win["w"] if win else None, hint, scr, shot)
    finally:
        rig.L.write_static_tree(rig.paths, rig.policy, ROOT / "rbrowser_unit")
    hints = {r[1] for r in results.values() if r[1]}
    detail = ("window width by requested width (screen width, Chromium's own minimum width from WM_NORMAL_HINTS): "
              + ", ".join(f"{w}->{r[0]} (screen {r[2] and r[2][0]}, minimum {r[1]})" for w, r in results.items()) + f"; pictures in {rig.out}")
    if not hints:
        return "FAIL", "manual: Chromium's minimum width could not be read from WM_NORMAL_HINTS; " + detail
    need = max(hints)
    at_min = results.get(rig.L.MIN_W)
    if at_min is None or at_min[0] != rig.L.MIN_W:
        return "FAIL", f"the window is {at_min and at_min[0]} wide at the requested width MIN_W {rig.L.MIN_W}; " + detail
    if rig.L.MIN_W < need:
        return "FAIL", f"MIN_W {rig.L.MIN_W} is below Chromium's own minimum width {need}: the window would be clipped; " + detail
    narrow = [w for w, r in results.items() if r[2] and r[2][0] < need]
    return "PASS", f"MIN_W {rig.L.MIN_W} >= Chromium's own minimum {need}, and the window is exactly the screen wide at MIN_W (below the minimum, at {narrow}, the window is smaller than Chromium asks: clipped, hence the floor); " + detail


@gate("G23", "20 resizes leave one xrandr mode and the window follows")
def g23(rig, ctx):
    S = rig.sess_mod
    s = rig.start_session()
    s.wait_sockets()
    try:
        time.sleep(3)
        sizes = [(560 + 16 * (i % 12) * 5, 480 + 16 * (i % 9) * 4) for i in range(20)]
        oks = [s.ctl({"op": "resize", "w": w, "h": h}).get("ok") for w, h in sizes]
        want = S.clamp_geometry(*sizes[-1])
        reached, cur = s.wait_main_window(want, 5.0)
        rc, out = s.x(["/usr/bin/xrandr", "-q"] if os.path.exists("/usr/bin/xrandr") else ["/usr/bin/xdpyinfo"])
        modes = re.findall(r"^\s+(rb\d+x\d+)\b", out, re.M)
    finally:
        s.stop()
    if all(oks) and len(modes) == 1 and reached:
        return "PASS", f"20 resizes answered ok; one rb mode is left ({modes[0]}); the main window is {cur['w']}x{cur['h']}+{cur['x']}+{cur['y']}, the last size asked"
    return "FAIL", f"answers {oks.count(True)}/20 ok; rb modes left: {modes}; window {cur and (cur['w'], cur['h'], cur['x'], cur['y'])} wanted {want}"


PAGES = {
    "text": ("<body style=margin:0;font:16px/1.4 serif><script>for(let i=0;i<500;i++){let p=document.createElement('p');"
             "p.textContent='Line '+i+' lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore';"
             "document.body.append(p)}let y=0;setInterval(()=>{y=(y+30)%(document.body.scrollHeight-700);scrollTo(0,y)},40)</script>"),
    "news": ("<body style=margin:0><script>for(let i=0;i<160;i++){let d=document.createElement('div');"
             "d.style.cssText='height:'+(120+i%7*20)+'px;margin:8px;font:'+(14+i%5*4)+'px sans-serif;background:linear-gradient(90deg,hsl('+(i*23%360)+',70%,60%),hsl('+(i*53%360)+',60%,40%))';"
             "d.textContent='Headline '+i+' and some more words to fill the card with text';document.body.append(d)}"
             "let y=0;setInterval(()=>{y=(y+50)%(document.body.scrollHeight-700);scrollTo(0,y)},50)</script>"),
    "video": ("<body style=margin:0><canvas id=c width=1280 height=720></canvas><script>let c=document.getElementById('c').getContext('2d');"
              "function f(){for(let i=0;i<260;i++){c.fillStyle='hsl('+(Math.random()*360)+',80%,'+(30+Math.random()*40)+'%)';"
              "c.fillRect(Math.random()*1200,Math.random()*640,80,80)}requestAnimationFrame(f)}f()</script>"),
}


def measure(s, nv, seconds):
    """Counters for `seconds`: bridge bytes and type-3 requests, cgroup CPU, x11vnc CPU, throttling."""
    vnc = s.find("x11vnc")
    b0, c0, v0, t0 = nv.bridge.snapshot(), s.cpu_stat(), s.proc_ticks(vnc), time.monotonic()
    time.sleep(seconds)
    b1, c1, v1, t1 = nv.bridge.snapshot(), s.cpu_stat(), s.proc_ticks(vnc), time.monotonic()
    dt = t1 - t0
    hz = os.sysconf("SC_CLK_TCK")
    periods = max(1, c1.get("nr_periods", 0) - c0.get("nr_periods", 0))
    return {"kBps": (b1["to_client"] - b0["to_client"]) / 1000 / dt, "fps": (b1["t3"] - b0["t3"]) / dt,
            "cores": (c1.get("usage_usec", 0) - c0.get("usage_usec", 0)) / 1e6 / dt, "x11vnc_cores": (v1 - v0) / hz / dt,
            "throttled_pct": 100 * (c1.get("nr_throttled", 0) - c0.get("nr_throttled", 0)) / periods}


@gate("G22", "bandwidth, frame rate, CPU and latency at three quality levels")
def g22(rig, ctx):
    s = rig.start_session()
    s.wait_sockets()
    table, misses, latency = {}, [], []
    try:
        nv = s.open_page(kbps=rig.L.STREAM_KBPS)
        time.sleep(3)
        for page in ("text", "news", "video"):
            nv.nav(page_url(PAGES[page], page[:3]))
            s.wait_title(page[:3])
            time.sleep(WARMUP_S)
            for level, (q, c) in QUALITY_CANDIDATES.items():
                nv.js("([q,c]) => window.setQuality(q,c)", [q, c])
                time.sleep(1.5)
                m = measure(s, nv, MEASURE_S)
                table[(page, level)] = m
                print(f"     G22 data {page:5s} {level:8s} {m['kBps']:7.0f} KB/s {m['fps']:5.1f} fps cpu {m['cores']:.2f} cores x11vnc {m['x11vnc_cores']:.2f} throttled {m['throttled_pct']:.0f}%", flush=True)
        # key to pixel: a typed character in the address bar
        nv.js("([q,c]) => window.setQuality(q,c)", list(QUALITY_CANDIDATES[DEFAULT_LEVEL]))
        nv.nav(page_url("<body>idle", "idle"))
        s.wait_title("idle")
        nv.chord([0xFFE3], 0x6C)
        time.sleep(1)
        for i in range(12):
            nv.js("() => window.collectBase(100, 45, 600, 40, 1000)")
            ms = nv.js("() => window.latencyTrial(100, 45, 600, 40, 0x61, 1500)")
            if ms is not None:
                latency.append(ms)
            nv.js("() => rfb.sendKey(0xFF08, null)")
            time.sleep(0.4)
        nv.shot("g22-final.png")
        nv.close()
    finally:
        s.stop()
    d = {p: table[(p, DEFAULT_LEVEL)] for p in ("text", "news", "video")}
    if d["text"]["fps"] < BARS["text_fps"]:
        misses.append(f"text scroll {d['text']['fps']:.1f} fps < {BARS['text_fps']}")
    if d["news"]["fps"] < BARS["news_fps"]:
        misses.append(f"news scroll {d['news']['fps']:.1f} fps < {BARS['news_fps']}")
    if d["video"]["fps"] < BARS["video_fps"]:
        misses.append(f"video {d['video']['fps']:.1f} fps < {BARS['video_fps']}")
    worst_vnc = max(m["x11vnc_cores"] for m in d.values())
    worst_thr = max(m["throttled_pct"] for m in d.values())
    if worst_vnc > BARS["x11vnc_cores"]:
        misses.append(f"x11vnc {worst_vnc:.2f} cores > {BARS['x11vnc_cores']}")
    if worst_thr >= BARS["throttled_pct"]:
        misses.append(f"throttled {worst_thr:.0f}% >= {BARS['throttled_pct']}")
    med = statistics.median(latency) if latency else None
    if med is None or med > BARS["latency_ms"]:
        misses.append(f"key-to-pixel median {med} ms > {BARS['latency_ms']} ({len(latency)} trials)")
    rig.save("g22-table.json", json.dumps({f"{p}/{l}": m for (p, l), m in table.items()} | {"latency_ms": latency}, indent=1))
    detail = (f"at {DEFAULT_LEVEL} with the {rig.L.STREAM_KBPS} kbit/s cap: text {d['text']['fps']:.1f} fps, news {d['news']['fps']:.1f}, video (synthetic canvas, not a decoded video) {d['video']['fps']:.1f}; "
              f"x11vnc {worst_vnc:.2f} cores; throttled {worst_thr:.0f}%; key-to-pixel median {med and round(med)} ms p95 {percentile(latency, 95) and round(percentile(latency, 95))}; table in {rig.out}/g22-table.json")
    return ("PASS", detail) if not misses else ("FALLBACK", "bars missed (change a constant, does not block): " + "; ".join(misses) + "; " + detail)


@gate("G21", "keyboard layouts through real noVNC")
def g21(rig, ctx):
    s = rig.start_session()
    s.wait_sockets()
    res = {}
    try:
        nv = s.open_page()
        time.sleep(3)
        nv.nav(page_url("<body style=margin:0><textarea autofocus style=width:100%;height:100%;font-size:40px oninput=\"document.title='k:'+this.value\"></textarea>", "kb"))
        s.wait_title("kb")
        time.sleep(1)
        nv.click(200, 200)
        # (name, wanted text, action): the physical keys of a French, a German, a German-with-AltGr and a US layout
        cases = [("e-acute", "\u00e9", lambda: nv.key("\u00e9", "Digit2", "\u00e9")), ("sharp s", "\u00df", lambda: nv.key("\u00df", "Minus", "\u00df")),
                 ("euro", "\u20ac", lambda: nv.key("\u20ac", "KeyE", "\u20ac", modifiers=0)),
                 ("AltGr at-sign", "@", lambda: (nv.key("AltGraph", "AltRight", None, vk=225), nv.key("@", "KeyQ", "@", modifiers=0), nv.key("AltGraph", "AltRight", None, vk=225)))]
        for name, want, act in cases:
            nv.js("() => { document.title = 'kb'; }") if False else None
            before = s.title()
            act()
            time.sleep(1.2)
            after = s.title()
            res[name] = after.startswith("k:") and after[len("k:"):].endswith(want) and after != before
        before = s.title()
        nv.key("Dead", "Quote", None, vk=222)
        nv.key("e", "KeyE", "e")
        time.sleep(1.2)
        dead = s.title()
        nv.close()
    finally:
        s.stop()
    bad = [n for n, ok in res.items() if not ok]
    note = f"dead key sequence produced {dead[-12:]!r} (Playwright cannot compose a dead key; list it as a limit if it is not the accented letter)"
    if bad:
        return "FAIL", f"not arriving: {bad}; {note}"
    return "PASS", f"e-acute, sharp s, euro and AltGr @ arrived; {note}"


@gate("G24", "hairpin to the public address")
def g24(rig, ctx):
    ip = os.environ.get("RBROWSER_PUBLIC_IP", "")
    if not ip:
        return "FAIL", "not measured: set RBROWSER_PUBLIC_IP to the host's public address"
    ok, res, err = rig.snippet(connect_snippet(ip, 443))
    if not ok or not res:
        return "FAIL", f"the connect snippet did not run: {err[:100]}"
    r = res["result"]
    if r in ("connected", "ECONNREFUSED"):
        return "FALLBACK", f"the unit reaches {ip}:443 ({r}): put that address into rbrowser_extra_deny and into the README's set-up steps"
    return "PASS", f"{ip}:443 is not reachable from the unit ({r})"


# ---- G25 (1.26.0): the remote Chromium matches the member's portal theme

# Two real portal themes: the default dark one and Nord Light (the value of --bg-secondary, which .rb-toolbar uses).
G25_DARK = ("#16213e", "dark")
G25_LIGHT = ("#e5e9f0", "light")
G25_NEUTRAL_STRIP = (211, 227, 253)       # the tab strip of Chromium 156 without any theme, measured under Xvfb with no window manager: only a
#                                           reference for the detail line, the verdict does not rest on it (an inactive frame is another shade)
G25_TOLERANCE = 24                        # per channel: BrowserThemeColor is a seed and Chromium derives the frame from it. Measured on 156 for all
#                                           28 portal themes: 24 dark ones come out exactly, nord 18 off, the four light ones 0 to 22 off (the
#                                           frame of a light seed is pulled darker/warmer); #ff0000 or #fdf6e3 (no portal theme) come out far off
G25_PCS_PAGE = "data:text/html,<title>t</title><script>document.title='PCS='+matchMedia('(prefers-color-scheme:dark)').matches</script>"


def g25_strip(nv, s):
    """The tab strip colour: three points of the canvas (the stream is shown 1:1) at y=10 to the right of the tabs; the median per channel."""
    pts = [nv.js("([x, y]) => { const d = document.querySelector('canvas').getContext('2d').getImageData(x, y, 1, 1).data; return [d[0], d[1], d[2]]; }", [x, 10])
           for x in (500, 700, 900)]
    return tuple(sorted(p[i] for p in pts)[1] for i in range(3))


def g25_near(px, want, tol=G25_TOLERANCE):
    return all(abs(a - b) <= tol for a, b in zip(px, want))


def g25_hex(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


def g25_session(rig, color, mode, tag):
    """A session with this theme: (strip pixel, the title after the prefers-color-scheme page, the unit's own files) and the pictures."""
    s = rig.start_session(theme_color=color, theme_mode=mode)
    ident = s.spec.ident
    out = {"ident": ident, "file_before_stop": os.path.isfile(f"{rig.L.THEME_DIR}/{ident}.json") if color else None}
    try:
        s.wait_sockets()
        time.sleep(6)
        nv = s.open_page()
        try:
            out["strip"] = g25_strip(nv, s)
            out["shot_home"] = nv.shot(f"g25-{tag}-home.png")
            nv.nav(G25_PCS_PAGE)
            ok, title = s.wait_title("PCS=", 15)
            out["pcs_title"] = title
            out["shot_pcs"] = nv.shot(f"g25-{tag}-pcs.png")
            out["pcs_strip"] = g25_strip(nv, s)
            # the security policy still applies: a file: URL is not in URLAllowlist, so URLBlocklist "*" must stop it (a loaded text file would
            # make the window title its file name)
            nv.nav("file:///etc/hostname")
            time.sleep(3)
            out["blocked_title"] = s.title()
            out["shot_blocked"] = nv.shot(f"g25-{tag}-blocked.png")
        finally:
            nv.close()
    finally:
        s.stop()
    out["file_after_stop"] = os.path.exists(f"{rig.L.THEME_DIR}/{ident}.json")
    return out


G25_UNIT_SNIPPET = r"""
import json, os, stat
d = "/etc/chromium/policies/managed"
res = {"files": sorted(os.listdir(d))}
st = os.stat(d + "/portal-theme.json")
res["owner"] = st.st_uid; res["mode"] = stat.S_IMODE(st.st_mode)
try:
    open(d + "/portal-theme.json", "a").write("x"); res["theme_writable"] = True
except OSError as e:
    res["theme_writable"] = False; res["theme_errno"] = e.errno
try:
    open(d + "/portal.json", "a").write("x"); res["main_writable"] = True
except OSError as e:
    res["main_writable"] = False
try:
    open(d + "/other.json", "w").write("{}"); res["dir_writable"] = True
except OSError as e:
    res["dir_writable"] = False
res["theme"] = json.load(open(d + "/portal-theme.json"))
main = json.load(open(d + "/portal.json"))
res["main_keys"] = len(main); res["url_block_first"] = main.get("URLBlocklist", [None])[0]
res["main_has_theme_key"] = "BrowserThemeColor" in main
print(json.dumps(res))
"""


@gate("G25", "the remote Chromium follows the portal theme")
def g25(rig, ctx):
    L = rig.L
    notes = []
    # (1) the unit's view: the theme file is root-owned, read-only, next to an intact main policy file
    ident = rig.ident()
    spec = rig.spec(ident=ident, theme_color=G25_DARK[0], theme_mode=G25_DARK[1])
    path = rig.launcher.make_theme(ident, *G25_DARK)
    unit_res = None
    try:
        # the production argument list itself (build_unit_args with theme_file), not a bind added by hand
        rc, err, unit = rig.run_unit(["/usr/bin/python3", "-I", "-S", "-c", G25_UNIT_SNIPPET], spec=spec, script="session.py", theme_file=path)
        text = rig.journal(unit)
        rig.wait_gone(unit, 20)
        for line in text.splitlines():
            if line.strip().startswith("{"):
                try:
                    unit_res = json.loads(line)
                except ValueError:
                    pass
    finally:
        rig.launcher.remove_theme(ident)
        rig.launcher.remove_tmp(ident)
    if not unit_res:
        return "FAIL", f"the in-unit check did not print its answer: {err[:120]}"
    bad = []
    if unit_res["files"] != ["portal-theme.json", "portal.json"]:
        bad.append(f"managed directory holds {unit_res['files']}")
    if unit_res["owner"] != 0 or unit_res["mode"] != 0o444:
        bad.append(f"theme file owner {unit_res['owner']} mode {oct(unit_res['mode'])}")
    if unit_res["theme_writable"] or unit_res["main_writable"] or unit_res["dir_writable"]:
        bad.append("something under /etc/chromium is writable in the unit")
    if unit_res["theme"] != {"BrowserThemeColor": G25_DARK[0]}:
        bad.append(f"theme file holds {unit_res['theme']}")
    if unit_res["url_block_first"] != "*" or unit_res["main_has_theme_key"] or unit_res["main_keys"] < 50:
        bad.append("the main policy file is not the security policy")
    if bad:
        return "FAIL", "; ".join(bad)
    notes.append("in the unit the theme file is root-owned 0444 and read-only, the main policy intact")
    # (2) three real sessions
    dark = g25_session(rig, *G25_DARK, "dark")
    light = g25_session(rig, *G25_LIGHT, "light")
    plain = g25_session(rig, None, None, "neutral")
    # positive control for the blocked check: with the block lists lifted, the same file: URL LOADS and the window is titled with the file name
    with policy_without(rig, "URLBlocklist", "URLAllowlist"):
        control = g25_session(rig, *G25_DARK, "control")
    fails = []
    if control["blocked_title"] != "hostname":
        return "FAIL", (f"manual: the control session (block lists lifted) shows the title {control['blocked_title']!r} for file:///etc/hostname, not 'hostname', so "
                        f"the blocked check cannot tell loaded from blocked; pictures g25-*-blocked.png in {rig.out}")
    if not dark["file_before_stop"] or dark["file_after_stop"] or light["file_after_stop"]:
        fails.append(f"theme file before stop {dark['file_before_stop']}, left after stop {dark['file_after_stop']}/{light['file_after_stop']}")
    if os.path.isdir(L.THEME_DIR) and os.listdir(L.THEME_DIR):
        fails.append(f"files left in the theme directory: {os.listdir(L.THEME_DIR)}")
    if not g25_near(dark["strip"], g25_hex(G25_DARK[0])):
        fails.append(f"dark: tab strip {dark['strip']}, asked {g25_hex(G25_DARK[0])} (+-{G25_TOLERANCE})")
    if not g25_near(light["strip"], g25_hex(G25_LIGHT[0])):
        fails.append(f"light: tab strip {light['strip']}, asked {g25_hex(G25_LIGHT[0])} (+-{G25_TOLERANCE})")
    dist = lambda a, b: max(abs(x - y) for x, y in zip(a, b))
    if dist(plain["strip"], dark["strip"]) <= 60 or dist(plain["strip"], g25_hex(G25_DARK[0])) <= G25_TOLERANCE:
        fails.append(f"neutral: tab strip {plain['strip']} is not clearly different from the dark theme's {dark['strip']}")
    if dist(light["strip"], g25_hex(G25_LIGHT[0])) >= dist(plain["strip"], g25_hex(G25_LIGHT[0])):
        fails.append(f"light: tab strip {light['strip']} is not closer to the asked colour than the neutral {plain['strip']} is")
    for name, r_, want in (("dark", dark, "PCS=true"), ("light", light, "PCS=false"), ("neutral", plain, "PCS=false")):
        if want not in r_["pcs_title"]:
            fails.append(f"{name}: prefers-color-scheme page title {r_['pcs_title']!r}, wanted {want!r}")
    for name, r_ in (("dark", dark), ("light", light), ("neutral", plain)):
        if r_["blocked_title"] == control["blocked_title"] or not r_["blocked_title"]:
            fails.append(f"{name}: file:///etc/hostname was not blocked (window title {r_['blocked_title']!r}, the same as the control that loads it)")
    if dark["blocked_title"] != plain["blocked_title"] or light["blocked_title"] != plain["blocked_title"]:
        fails.append(f"the blocked page looks different with a theme: {dark['blocked_title']!r} / {light['blocked_title']!r} / {plain['blocked_title']!r}")
    detail = (f"tab strip dark {dark['strip']} (asked {G25_DARK[0]}), light {light['strip']} (asked {G25_LIGHT[0]}), neutral {plain['strip']}; "
              f"prefers-color-scheme titles {dark['pcs_title']!r} / {light['pcs_title']!r} / {plain['pcs_title']!r}; blocked-page title {plain['blocked_title']!r} in all three (the control without block lists: {control['blocked_title']!r}); "
              + "; ".join(notes) + f"; pictures g25-*-home/pcs/blocked.png in {rig.out}")
    if fails:
        return "FAIL", "; ".join(fails) + " | " + detail
    return "PASS", detail


# ================================================================ the run

PROBE_GATES = ("G00", "G02", "G02b", "G02c", "G06", "G18")


def only_gates(argv=None):
    """The gate ids of `--only G02,G06`, or None when every gate runs."""
    argv = sys.argv if argv is None else argv
    if "--only" not in argv:
        return None
    rest = argv[argv.index("--only") + 1:][:1]
    return {g.strip() for g in rest[0].split(",") if g.strip()} if rest else set()


def main():
    import rbrowser_launch as L
    rig = None
    ctx = {}
    only = only_gates()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(130))
    signal.signal(signal.SIGHUP, lambda *a: sys.exit(129))    # a dropped SSH session still runs the clean-up
    try:
        rig = Rig()                                           # inside the try: a signal during its set-up is handled too
        # refuse to run next to real sessions or probes of the feature: the same fail-closed check the clean-up uses (a
        # unit list that cannot be read, a slice cgroup that cannot be read, a session or probe unit, a foreign member)
        others = rig.slice_offenders()
        if others:
            say("G00", "FAIL", f"refused: {', '.join(others)} is not a unit of this test; this test works on the shared host paths and would disturb it")
            return 1
        if not rig.avail["available"]:
            say("G00", "FAIL", f"the feature is not available on this host: {rig.avail['reasons']}")
            return 1
        # refuse before anything is written: this test works on the shared host paths and must not revert, overwrite
        # or flush state of the feature that it did not create
        why = preexisting_state(**rig.host_facts())
        if why:
            say("G00", "FAIL", "refused: the host already holds state of the feature (" + "; ".join(why) + "); tear it down first, this test would overwrite it")
            return 1
        mounts_before = L.parse_mountinfo(L._read(L.HOST_MOUNTINFO))
        # the guard above proved that the static tree, the mount, both chains and the slice's drop-ins do not exist, so
        # everything prepare_host makes of those is this run's, and the clean-up removes exactly that
        rig.created.update({"static": not os.path.exists(L.STATIC_DIR), "state": not os.path.exists(L.STATE_DIR), "run": not os.path.exists(L.RUN_DIR) and not os.path.exists(L.RUN_TMP),
                            "mounted": L.RUN_DIR not in mounts_before and L.RUN_TMP not in mounts_before, "chain": True, "slice": True, "slice_started": True})
        rig.make_quote_dir()
        print(f"# artifacts in {rig.out}; units use the prefix {rig.TP}; chromium {rig.chromium}", flush=True)
        host = rig.prepare()
        ctx["host"] = host
        if not host["ok"]:
            say("G00", "FAIL", f"prepare_host failed: {host['reasons']}")
            return 1
        print(f"# host prepared: ingress filter {host['ingress_filter']} (pin {host['ingress_pin']}), slice ok {host['slice_ok']}, firewall chain {host['firewall']} ({host['firewall_reason'] or 'ok'}), upload rule {host['upload_rule']} ({host['upload_reason'] or 'ok'}), seats {host['seats']}", flush=True)
        if only is None or only & set(PROBE_GATES):
            probe = rig.run_probe()
        else:
            probe = {"ok": True, "checks": []}
        ctx["probe"] = probe
        rig.save("probe.json", json.dumps(probe, indent=1))
        for c in probe["checks"]:
            print(f"     probe {c['name']:16s} {'ok  ' if c['ok'] else 'FAIL'} {c['detail']}", flush=True)
        ctx["session"] = None
        if only is None or only & {"G01", "G02b"}:      # G01 looks at the first session's units, G02b ends it
            try:
                ctx["session"] = rig.start_session()
                ctx["session"].wait_sockets()
                ctx["session_ok"] = True
            except Exception as e:
                ctx["session"] = None
                ctx["session_ok"] = False
                print(f"# the first session did not start: {e.__class__.__name__}: {e}", flush=True)
        for gid, title, fn in GATES:
            if only is not None and gid not in only:
                continue
            if gid == "G02b" and ctx.get("session") is None:
                ctx["session"] = rig.start_session()
                ctx["session"].wait_sockets()
            try:
                status, detail = fn(rig, ctx)
            except SystemExit:
                raise
            except Exception as e:
                status, detail = "FAIL", f"the gate raised {e.__class__.__name__}: {str(e)[:200]}"
            say(gid, status, f"[{title}] {detail}")
    finally:
        if rig is not None:
            cleanup(rig)
    fails = [g for g, s in OUT_LINES if s in FAILING]
    hard = [g for g in fails if g in HARD_GATES]
    print(f"# summary: {len(OUT_LINES)} gates, {len(fails)} FAIL or INCONCLUSIVE ({', '.join(fails) or 'none'}); hard gate failures: {', '.join(hard) or 'none'}", flush=True)
    print("# RESIDUAL lines are accepted limits (R2), not failures; FAIL lines that say manual: are for a person to judge from the saved pictures", flush=True)
    return 1 if hard else 0


def cleanup(rig):
    """Remove everything this run made: only units with the test prefix, only what `created` says."""
    L = rig.L
    # a second signal (SIGHUP, then SIGTERM or a second Ctrl-C) must not abort the clean-up half way: `except Exception`
    # below does not catch the SystemExit that the handlers raise
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    # First of all: whatever the loop still runs (a launcher that was starting a unit when a signal came) is cancelled
    # and awaited for a bounded time, so that it cannot start a unit after the listing below
    try:
        rig.loop.cancel_pending(5.0)
    except Exception:
        pass
    for fn in rig.cleanups:
        try:
            fn()
        except Exception:
            pass
    for s in list(rig.sessions):
        try:
            if s.bridge:
                s.bridge.close()
        except Exception:
            pass
    # Playwright's synchronous close can hang on a dead browser: each call gets 15 s, then it is given up
    if rig.browser:
        bounded_call(rig.browser.close, 15)
    if rig.pw:
        bounded_call(rig.pw.stop, 15)
    try:
        rc, out, _ = rig.systemctl("list-units", "--all", "--plain", "--no-legend", f"{rig.TP}*")
        names = set(re.findall(re.escape(rig.TP) + r"(?:prep-|host-)?[0-9a-f]{12}\.service", out)) | set(u for u in rig.units if u.startswith(rig.TP))
        for u in names:
            rig.stop_unit(u)             # confirms (and resets a failed unit), never raises; a unit that stays goes to rig.unconfirmed
    except Exception:
        pass
    # a unit that the launcher could not confirm gone (UnitLeftRunning, a stop cancelled part way) counts too
    try:
        rig.unconfirmed |= {u for u in rig.launcher.unstopped if u.startswith(rig.TP)}
    except Exception:
        pass
    try:
        for u in rig.units:                      # this run's units only: the tmpfs is shared with the feature, a unit that is not ours keeps its directory
            if u not in rig.unconfirmed:
                rig.launcher.remove_tmp(u[len(rig.TP):-len(".service")])
    except Exception:
        pass
    # A session unit of the real feature that started during this run lives in the slice and uses the host paths:
    # tearing the host down would kill it. Then the host part of the clean-up is skipped and said so. The check is made again
    # right before each stop of the slice (a unit of the portal may have started since): a window of a few milliseconds between
    # that check and systemd's stop remains, systemd has no stop that refuses a slice with a foreign member.
    def check_offenders():
        try:
            return rig.slice_offenders()
        except Exception as e:
            return [f"(the check failed: {e.__class__.__name__})"]

    offenders = check_offenders()
    if offenders:
        try:
            print(f"# clean-up: the host part is LEFT IN PLACE (firewall chain, slice properties and state, tmpfs, static tree) because "
                  f"{', '.join(offenders)} is not a unit of this run; remove it by hand when that unit is gone", flush=True)
        except Exception:      # a closed pipe (the SSH session is gone) must not stop the clean-up
            pass
    try:
        rig.loop.run(L.remove_firewall(L.default_run, L.find_tool), 60) if rig.created.get("chain") and not offenders else None
    except BaseException:
        pass
    try:
        if rig.created.get("slice") and not offenders:
            rig.systemctl("revert", L.SLICE)
        if rig.created.get("slice_started") and not offenders:
            offenders = check_offenders()        # again, right before the stop
            if not offenders:
                rig.systemctl("stop", L.SLICE)
    except Exception:
        pass
    try:
        if rig.created.get("quote_dir"):
            shutil.rmtree(QUOTE_DIR, ignore_errors=True)
    except Exception:
        pass
    unprep = None
    unsettled = False
    try:
        if not offenders:
            if rig.created.get("mounted"):
                offenders = check_offenders()    # again: unprepare_host stops the slice a second time
            if rig.created.get("mounted") and not offenders:
                # bpf_pin='' when no pin of this run exists: unprepare_host then touches no pin at all (its default would be the
                # feature's own pin, which this test must never remove). It removes the pin only for a slice that is stopped and
                # holds no unit cgroup, and reports pin_removed / pin_kept: that answer is the last word on the pin.
                # run the way the portal would run it, inside a PrivateTmp unit (the umount goes through a helper unit of the host's
                # namespace); when that unit cannot run, in this shell (the host's namespace) with the same helper
                # a test unit that is not confirmed gone (rig.unconfirmed, which includes the launcher's unstopped units) keeps the pin: bpf_pin ''
                # tells unprepare_host to touch no pin at all
                pin_arg = "" if (rig.unconfirmed or rig.loop.stuck) else (rig.pin or "")
                ans, _err = rig.private_unit(PRIVATE_NS_SCRIPT, dict(op="unprepare", paths={"static": L.STATIC_DIR, "run_dir": L.RUN_DIR, "state": L.STATE_DIR, "tmp_dir": L.RUN_TMP},
                                                                     bpf_pin=pin_arg), 90)
                if ans:
                    unprep = ans["result"]
                elif rig.private_stuck:
                    # the private unit that was to run unprepare_host is not confirmed gone: a second unprepare_host beside it could
                    # race with it, so the fallback does not run; the pin is reported KEPT below
                    print(f"# clean-up: the private unit {sorted(rig.private_stuck)[0]} is not confirmed gone; the fallback unprepare_host is NOT run", flush=True)
                    pin_arg = ""
                else:
                    try:
                        unprep = rig.loop.run(L.unprepare_host(units_left=0, bpf_pin=pin_arg, helper_prefix=rig.helper_prefix), 60)
                    except BaseException:
                        unprep = None
                        unsettled = True        # unprepare_host did not return (it may have run half way, or still run): the pin is kept
            if rig.created.get("static"):
                shutil.rmtree(L.STATIC_DIR, ignore_errors=True)
            if rig.created.get("state"):
                shutil.rmtree(L.STATE_DIR, ignore_errors=True)
            for d in (L.RUN_DIR, L.RUN_TMP):
                if rig.created.get("run") and os.path.isdir(d) and not os.path.ismount(d):
                    os.rmdir(d)
    except BaseException:
        pass
    # the test's own pin (a base of its own, never the feature's): unprepare_host decided about it when it ran. Only when it did not
    # run is the pin removed here, and then only with no test unit left unconfirmed and the slice's cgroup empty when read again now.
    kept_said = False
    try:
        if rig.pin:
            if unprep is not None and unprep.get("pin_kept"):
                kept_said = True
                print(f"# clean-up: the test's ingress-filter pin {rig.pin} is KEPT ({'slice children ' + str(unprep.get('slice_children'))}); "
                      f"remove it by hand when no unit is left in the slice", flush=True)
            elif unprep is None and not offenders and clean_up_may_unpin(None, rig.unconfirmed, L.slice_children(), unsettled or rig.loop.stuck > 0):
                import rbrowser_bpf
                rbrowser_bpf.unpin(rig.pin)
            elif unprep is None or rig.unconfirmed:     # also the case of unprepare_host with bpf_pin '' for an unconfirmed unit
                kept_said = True
                print(f"# clean-up: the test's ingress-filter pin {rig.pin} is KEPT (units not confirmed gone: "
                      f"{sorted(rig.unconfirmed) or 'none'}; unprepare_host did not return or a cancelled coroutine had not ended: {unsettled or rig.loop.stuck > 0}); remove it by hand when no unit is left in the slice", flush=True)
    except BaseException:
        pass
    # the last word: a pin that still exists is said to be KEPT, whatever path led here (a pin the paths above did not mention, e.g. an
    # unprepare_host that ran without removing it, or an unpin that failed)
    try:
        if rig.pin and kept_line_due(os.path.lexists(rig.pin), kept_said):
            print(f"# clean-up: the test's ingress-filter pin {rig.pin} is KEPT (it still exists after the clean-up); "
                  f"remove it by hand when no unit is left in the slice", flush=True)
    except BaseException:
        pass
    shutil.rmtree(rig.tmp, ignore_errors=True)
    try:
        rig.loop.close()
    except Exception:
        pass


# ====================================================================== ROUND 2 (lane A2): the same host, through the real Registry
# Written, not run. `--round 2` starts the host through rbrowser.Registry.startup (prepare_host, the BPF pin, the preflight probe), then
# drives create, attach, the peer check, the tick and shutdown with the test prefix (portal-rbtest-) for sessions AND the probe unit.
# Gate ids are R01..R12. Nothing here names a session unit or a probe unit of the real feature.
# Run it only on a host where the portal's feature has no session and holds no state: round 2 shares RUN_TMP and the host preparation with
# the real feature (the registry's tmp sweep removes every unit directory it does not know), so main_round2 refuses (G00, round2_refusal)
# while a unit of the feature is loaded or a unit tmp directory exists, on top of the round-1 checks (mounts, chain, slice, pins).

def round2_refusal(units_out, tmp_entries, unit_prefixes):
    """The reasons (a list of text) why round 2 must not run on this host. Pure. Round 2 drives the real prepare_host and unprepare_host
    and the registry's tmp sweep, which removes every 12-hex directory of RUN_TMP that is not one of its own units' (and its shutdown
    unprepares the host): on a host where the portal's feature has sessions, that would wipe their /tmp directories.
    units_out: the text of `systemctl list-units --all` for the feature's prefixes, or None when it could not be read; tmp_entries:
    the names in RUN_TMP, or None when they could not be listed (a missing directory is []); unit_prefixes: the prefixes of the
    feature's own session and probe units. Any loaded unit of those prefixes, any directory of a unit in RUN_TMP, or a listing that
    failed, refuses."""
    why = []
    if units_out is None:
        why.append("the unit list could not be read")
    else:
        alts = "|".join(re.escape(x) for x in unit_prefixes)
        loaded = sorted(set(re.findall(r"(?:" + alts + r")[0-9a-f]{12}\.service", units_out)))
        if loaded:
            why.append(f"{len(loaded)} unit(s) of the feature are loaded ({', '.join(loaded[:3])}): their tmp directories and host state are not this test's")
    if tmp_entries is None:
        why.append("the tmp area could not be listed")
    else:
        stray = [n for n in tmp_entries if re.fullmatch(r"[0-9a-f]{12}", n)]
        if stray:
            why.append(f"{len(stray)} unit tmp directory(ies) exist in the tmp area; the registry's tmp sweep would remove them")
    return why


def round2_units(rig):
    rc, out, _ = rig.systemctl("list-units", "--all", "--plain", "--no-legend", f"{rig.TP}*")
    return sorted(set(re.findall(re.escape(rig.TP) + r"[0-9a-f]{12}\.service", out)))


def round2_body(rig):
    import rbrowser as U
    import rbrowser_launch as L
    TP = rig.TP
    off = {"s": 0.0}
    cfg = dict(rig.cfg, rbrowser_enabled=True, rbrowser_idle_minutes=15, rbrowser_clipboard="both", rbrowser_home_url=HOME_URL,
               hidden_extra=rig.hidden_extra, portal_port=rig.portal_port, portal_unit="")

    def run(coro, seconds=120):
        return rig.loop.run(coro, seconds)

    async def build():
        return U.Registry(launch_mod=L, prefix=TP, probe_prefix=TP, clock=lambda: time.time() + off["s"],
                          prepare_kw={"helper_prefix": rig.helper_prefix, "bpf_base": rig.bpf_base},
                          unprepare_kw={"helper_prefix": rig.helper_prefix}, tmp_dir=L.RUN_TMP,
                          cache_path=str(rig.tmp / "preflight.json"))

    reg = run(build(), 10)

    def make(user, token="tok"):
        s = run(reg.create(user, token, 1280, 720, cfg), 90)
        rig.units.append(s.unit)
        return s

    def end_all(reason="closed"):
        for s in list(reg.all()):
            run(reg.end(s, reason), 90)

    # ---- R01 start-up through the registry, then the preflight
    run(reg.startup(cfg), 300)
    rig.pin = reg.pin
    rig.prep = reg.prep
    av = reg.availability()
    if not reg.ready:
        say("R01", "FAIL", f"startup did not prepare the host: {reg.unavailable_reasons or av['reasons']}")
        return
    pf = run(reg.preflight(), 120)
    for c in pf["checks"]:
        print(f"     probe {c['name']:16s} {'ok  ' if c['ok'] else 'FAIL'} {c['detail']}", flush=True)
    rig.save("round2-probe.json", json.dumps(pf, indent=1))
    av = reg.availability()
    say("R01", "PASS" if pf["ok"] and av["available"] else "FAIL",
        f"[startup and preflight through the registry] ready {reg.ready}, pin {reg.pin}, seats {reg.seats(cfg)}, available {av['available']}, probe ok {pf['ok']} ({len(pf['checks'])} checks)")

    # ---- R12 negative control: the preflight fails when the policy directory bind is removed, and recovers
    orig = reg._probe_launcher._run
    drop = f"BindReadOnlyPaths={L.STATIC_DIR}/chromium-probe:/etc/chromium"

    async def mutated(argv, timeout=10.0):
        if argv and os.path.basename(argv[0]) == "systemd-run":
            argv = [argv[0]] + _drop_prop(list(argv[1:]), drop)
        return await orig(argv, timeout)
    reg._probe_launcher._run = mutated
    try:
        bad = run(reg.preflight(force=True), 150)
        av_bad = reg.availability()
    finally:
        reg._probe_launcher._run = orig
    good = run(reg.preflight(force=True), 150)
    failed = [c["name"] for c in bad["checks"] if not c["ok"]]
    ev = [e for e in reg.take_events() if e["kind"] == "preflight_failed"]
    say("R12", "PASS" if (not bad["ok"] and "chromium_policy" in failed and av_bad["available"] is False and ev and good["ok"]) else "FAIL",
        f"[negative control: no policy bind] failed checks {failed}, available while failed {av_bad['available']}, event {bool(ev)}, recovered {good['ok']}")

    # ---- R02 create, attach through open_stream, control calls
    s = make(1)
    rd, wr = run(reg.open_stream(s), 20)
    greeting = run(rd.readexactly(12), 10)
    wr.close()
    resized = run(reg.resize(s, 1000, 700), 20)
    clip = run(reg.clip(s), 20)
    unit_state = rig.unit_state(s.unit).get("ActiveState")
    say("R02", "PASS" if (greeting.startswith(b"RFB 003") and resized and clip["ok"] is True and unit_state == "active" and s.expect_uid not in (0, os.getuid())
                          and s.runtime_dir.startswith(L.RUN_DIR)) else "FAIL",
        f"[create and attach] greeting {greeting!r}, resize {resized}, clip ok {clip['ok']} (text length {len(clip['text'])}), unit {unit_state}, uid {s.expect_uid}")
    end_all()

    # ---- R03 concurrent creates by one member, then more members than seats
    async def many(users, token):
        return await asyncio.gather(*[reg.create(u, token, 1280, 720, cfg) for u in users], return_exceptions=True)
    res = run(many([10] * 8, "m"), 120)
    got = [x for x in res if isinstance(x, U.Session)]
    for x in got:
        rig.units.append(x.unit)
    one = len({x.sid for x in got}) == 1 and len(round2_units(rig)) == 1
    end_all()
    seats = reg.seats(cfg)["max"]
    res = run(many([21, 22, 23, 24], "m"), 180)
    got = [x for x in res if isinstance(x, U.Session)]
    busy = [x for x in res if isinstance(x, U.Refused) and x.body.get("busy")]
    for x in got:
        rig.units.append(x.unit)
    units = round2_units(rig)
    say("R03", "PASS" if one and len(got) == seats and len(busy) == 4 - seats and len(units) == seats else "FAIL",
        f"[concurrent creates] 8 creates by one member: one unit {one}; 4 members, {seats} seats: {len(got)} sessions, {len(busy)} busy answers, {len(units)} units")
    end_all()

    # ---- R04 the peer check against a planted symbolic link and a wrong uid, on a real socket
    s = make(2)
    plant = rig.tmp / "plant"
    plant.mkdir()
    os.symlink(os.path.join(s.runtime_dir, "vnc.sock"), plant / "vnc.sock")

    def clone(**over):
        c = U.Session(sid="r2clone" + secrets.token_hex(4), unit=f"{TP}{secrets.token_hex(6)}.service", user_id=99, token_id="x", state="running",
                      runtime_dir=str(plant), expect_uid=s.expect_uid, expect_cgroup=s.expect_cgroup, width=1, height=1, ident=secrets.token_hex(6))
        for k, v in over.items():
            setattr(c, k, v)
        reg._sessions[c.sid] = c
        reg._x[c.sid] = U._Ext(c.ident, "", c.unit)
        reg._x[c.sid].last_listener = reg.clock()      # the listener check (which has its own gate, R05) is not what this gate measures: the clone's cgroup is made up
        return c

    async def attempt(c):
        try:
            await reg.open_stream(c)
            return None
        except U.StreamRefused as e:
            return e
    link = clone()
    e1 = run(attempt(link), 30)
    wrong = clone(runtime_dir=s.runtime_dir, expect_uid=s.expect_uid + 1)
    e2 = run(attempt(wrong), 30)
    wrongcg = clone(runtime_dir=s.runtime_dir, expect_cgroup="/system.slice/not-this.service")
    e3 = run(attempt(wrongcg), 30)
    say("R04", "PASS" if all(e is not None and e.marker == "socket_mismatch" for e in (e1, e2, e3)) and s.state == "running" else "FAIL",
        f"[peer check] symbolic link: {e1 and e1.reason}, wrong uid: {e2 and e2.reason}, wrong cgroup: {e3 and e3.reason}; the real session still running: {s.state == 'running'}")

    # ---- R05 the listener check: a planted listener is found (positive control), the unit has none
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        found = reg._psutil_scan([os.getpid()])
    finally:
        srv.close()
    clean = reg._psutil_scan([os.getpid()])
    live = run(reg._listener_check(s, reg._x[s.sid]), 30)
    say("R05", "PASS" if found and not clean and live == "clean" else "FAIL", f"[listener check] planted listener found {found}, none after close {not clean}, verdict for the unit {live}")

    # ---- R06 the ingress filter check of the tick, with a negative control
    attached = reg.launcher.filter_attached(s.expect_cgroup, pin=s.ingress_pin)
    bogus = reg.launcher.filter_attached(s.expect_cgroup, pin="/sys/fs/bpf/portal-rblive-nonexistent-0000000000000000")
    ended = run(reg.tick(cfg), 60)
    say("R06", "PASS" if attached and not bogus and ended == [] else "FAIL", f"[ingress filter on the tick] attached {attached}, a pin that does not exist {bogus}, ended by the tick {len(ended)}")
    end_all()

    # ---- R07 traffic budget on real kernel counters (volume cap lowered to one byte; the rate arithmetic is unit-tested)
    s = make(3)
    saved = U.UP_VOLUME
    U.UP_VOLUME = 1
    try:
        ended = []
        t0 = time.time()
        while time.time() - t0 < 60 and not ended:
            time.sleep(5)
            ended = run(reg.tick(cfg), 60)
    finally:
        U.UP_VOLUME = saved
    say("R07", "PASS" if ended and s.end_reason == "traffic_limit" and s.marker_detail == "upload_volume" else "FAIL",
        f"[traffic budget] ended {bool(ended)} reason {s.end_reason} marker {s.marker}/{s.marker_detail}, counters in {s.net_in} out {s.net_out}")
    end_all()

    # ---- R08 idle end (the clock is moved 16 minutes forward)
    s = make(4)
    reg.mark_attached(s, object())
    off["s"] = 16 * 60
    try:
        ended = run(reg.tick(cfg), 60)
    finally:
        off["s"] = 0.0
    say("R08", "PASS" if ended == [(s, "idle")] else "FAIL", f"[idle end] {[(x.end_reason) for x, _ in ended]}")
    end_all()

    # ---- R09 stop timing, and nothing left of the unit
    s = make(5)
    ident = s.ident
    t0 = time.time()
    run(reg.end(s, "closed"), 90)
    took = time.time() - t0
    state = rig.unit_state(s.unit).get("ActiveState")
    load = rig.systemctl("show", "-p", "LoadState", s.unit)[1].strip()
    left = [p for p in (f"{L.RUN_DIR}/s-{ident}", f"{L.RUN_TMP}/{ident}") if os.path.lexists(p)]
    # no --collect any more: the confirmed stop resets the unit, so it must not stay loaded (not even as failed)
    say("R09", "PASS" if took < 20 and state in ("inactive", None) and load == "LoadState=not-found" and not left else "FAIL",
        f"[stop] took {took:.1f} s, unit {state}, {load}, left behind {left}")

    # ---- R10 the tmp quota on the real tmpfs
    s = make(6)
    d = f"{L.RUN_TMP}/{s.ident}"
    with open(f"{d}/filler", "wb") as f:
        f.write(b"x" * (13 * 1024 * 1024))
    ended = run(reg.tick(cfg), 60)
    say("R10", "PASS" if ended == [(s, "crash")] and s.marker == "tmp_quota" else "FAIL", f"[tmp quota] ended {[(x.end_reason, x.marker) for x, _ in ended]}")
    end_all()

    # ---- R13 a unit that exits with status 3 (the supervisor's display mismatch) ends its session with the marker (F4)
    # A stand-in unit with a registry-style name exits 3 after two seconds. It is started WITHOUT --collect, as the real units must be: with
    # --collect systemd unloads a unit that exits, `systemctl show <name>` then answers LoadState=not-found ActiveState=inactive
    # ExecMainStatus=0, and the session would end as closed_in_browser with no marker. rbrowser_launch drops --collect from build_unit_args
    # and SystemdLauncher.stop() resets the unit after the confirmed stop that ends the session, so the unit is not-found afterwards.
    ident = secrets.token_hex(6)
    unit = f"{TP}{ident}.service"
    rig.units.append(unit)
    rc, _o, err = sh([L.find_tool("systemd-run"), f"--unit={TP}{ident}", "--quiet", "--no-block", "-p", "Type=exec", "-p", "RuntimeMaxSec=120",
                      "/bin/sh", "-c", "sleep 2; exit 3"], 20)
    sess = U.Session(sid=secrets.token_urlsafe(16), unit=unit, user_id=13, token_id="r13", state="running", runtime_dir="", expect_uid=-1,
                     expect_cgroup="", width=1280, height=720, started=time.time(), last_activity=time.time(), detached_since=time.time(),
                     ident=ident, ingress_pin=reg.pin)
    reg._sessions[sess.sid] = sess
    reg._by_user[13] = sess
    reg._x[sess.sid] = U._Ext(ident, reg.pin, unit)
    time.sleep(4)
    seen = rig.systemctl("show", "-p", "LoadState", "-p", "ActiveState", "-p", "ExecMainStatus", "-p", "ExecMainCode", unit)[1].split()
    ended = run(reg.tick(cfg), 60)
    ev = [e for e in reg.take_events() if e["kind"] == "marker" and e.get("marker") == "display_mismatch"]
    # tick() ends the session and leaves the stop to a task beside it: wait (bounded) until the unit is unloaded by the stop's reset-failed
    after = ""
    for _ in range(40):
        after = rig.systemctl("show", "-p", "LoadState", unit)[1].strip()
        if after == "LoadState=not-found":
            break
        time.sleep(0.5)
    no_collect = not any("--collect" in a for a in L.build_unit_args(reg.spec("0" * 12, 1280, 720, cfg), TP, "session.py", 5, ingress_pin=reg.pin))
    ok = rc == 0 and ended == [(sess, "crash")] and sess.marker == "display_mismatch" and len(ev) == 1 and after == "LoadState=not-found" and no_collect
    say("R13", "PASS" if ok else "FAIL",
        f"[exit status 3] stand-in unit before the tick {seen}, ended {[(x.end_reason, x.marker) for x, _ in ended]}, display_mismatch events {len(ev)}, "
        f"after the stop {after}, the real units carry no --collect {no_collect}" + (f", systemd-run rc {rc} {err[:80]}" if rc else ""))
    rig.systemctl("reset-failed", unit)        # the stand-in must not stay loaded as failed (R11 lists units with --all); nothing to do when it was reset
    end_all()

    # ---- R13b the same status 3 reached by a signal (SIGQUIT: ExecMainCode 2, killed) is a crash WITHOUT the marker
    ident = secrets.token_hex(6)
    unit = f"{TP}{ident}.service"
    rig.units.append(unit)
    rc, _o, err = sh([L.find_tool("systemd-run"), f"--unit={TP}{ident}", "--quiet", "--no-block", "-p", "Type=exec", "-p", "RuntimeMaxSec=120",
                      "-p", "LimitCORE=0", "/bin/sleep", "300"], 20)
    time.sleep(1)
    rig.systemctl("kill", "-s", "QUIT", "--kill-whom=main", unit)
    sess = U.Session(sid=secrets.token_urlsafe(16), unit=unit, user_id=14, token_id="r13b", state="running", runtime_dir="", expect_uid=-1,
                     expect_cgroup="", width=1280, height=720, started=time.time(), last_activity=time.time(), detached_since=time.time(),
                     ident=ident, ingress_pin=reg.pin)
    reg._sessions[sess.sid] = sess
    reg._by_user[14] = sess
    reg._x[sess.sid] = U._Ext(ident, reg.pin, unit)
    time.sleep(4)
    seen = rig.systemctl("show", "-p", "LoadState", "-p", "ActiveState", "-p", "ExecMainStatus", "-p", "ExecMainCode", unit)[1].split()
    ended = run(reg.tick(cfg), 60)
    ev = [e for e in reg.take_events() if e["kind"] == "marker"]
    after = ""
    for _ in range(40):
        after = rig.systemctl("show", "-p", "LoadState", unit)[1].strip()
        if after == "LoadState=not-found":
            break
        time.sleep(0.5)
    ok = rc == 0 and "ExecMainStatus=3" in seen and "ExecMainCode=1" not in seen and any(c in seen for c in ("ExecMainCode=2", "ExecMainCode=3")) and ended == [(sess, "crash")] and sess.marker is None and not ev and after == "LoadState=not-found"
    say("R13b", "PASS" if ok else "FAIL",
        f"[status 3 by a signal] stand-in unit before the tick {seen}, ended {[(x.end_reason, x.marker) for x, _ in ended]}, marker events {len(ev)}, after the stop {after}"
        + (f", systemd-run rc {rc} {err[:80]}" if rc else ""))
    rig.systemctl("reset-failed", unit)
    end_all()

    # ---- R11 shutdown leaves nothing behind
    s = make(7)
    run(reg.shutdown(), 120)
    units = round2_units(rig)
    mounts = L.parse_mountinfo(L._read(L.HOST_MOUNTINFO))
    chains = []
    for name in ("iptables", "ip6tables"):
        tool = L.find_tool(name)
        if tool:
            rc, out, _ = sh([tool, "-w", "2", "-S"])
            if L.CHAIN in out:
                chains.append(name)
    passwd = [l for l in L._read("/etc/passwd").splitlines() if "portal-rb" in l]
    entries = os.listdir(L.RUN_DIR) if os.path.isdir(L.RUN_DIR) else []
    pin_left = os.path.exists(reg.pin) if reg.pin else False
    ok = s.end_reason == "portal_stop" and not units and L.RUN_DIR not in mounts and L.RUN_TMP not in mounts and not chains and not passwd and not entries
    say("R11", "PASS" if ok else "FAIL", f"[shutdown] ended as {s.end_reason}, units {units}, mounted {[m for m in (L.RUN_DIR, L.RUN_TMP) if m in mounts]}, chains {chains}, "
        f"passwd lines {len(passwd)}, entries under {L.RUN_DIR} {entries}, pin {'KEPT' if pin_left else 'removed'}")


def main_round2():
    import rbrowser_launch as L
    rig = None
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(130))
    signal.signal(signal.SIGHUP, lambda *a: sys.exit(129))
    try:
        rig = Rig()
        others = rig.slice_offenders()
        if others:
            say("G00", "FAIL", f"refused: {', '.join(others)} is not a unit of this test")
            return 1
        if not rig.avail["available"]:
            say("G00", "FAIL", f"the feature is not available on this host: {rig.avail['reasons']}")
            return 1
        why = preexisting_state(**rig.host_facts())
        if why:
            say("G00", "FAIL", "refused: the host already holds state of the feature (" + "; ".join(why) + "); tear it down first")
            return 1
        rc, units_out, _ = rig.systemctl("list-units", "--all", "--plain", "--no-legend", f"{rig.rbrowser.UNIT_PREFIX}*", f"{rig.rbrowser.PROBE_PREFIX}*")
        try:
            tmp_entries = sorted(os.listdir(L.RUN_TMP))
        except FileNotFoundError:
            tmp_entries = []
        except OSError:
            tmp_entries = None
        why = round2_refusal(units_out if rc == 0 else None, tmp_entries, (rig.rbrowser.UNIT_PREFIX, rig.rbrowser.PROBE_PREFIX))
        if why:
            say("G00", "FAIL", "refused: round 2 shares the host's tmp area and host preparation with the real feature (" + "; ".join(why) + ")")
            return 1
        mounts_before = L.parse_mountinfo(L._read(L.HOST_MOUNTINFO))
        rig.created.update({"static": not os.path.exists(L.STATIC_DIR), "state": not os.path.exists(L.STATE_DIR), "run": not os.path.exists(L.RUN_DIR) and not os.path.exists(L.RUN_TMP),
                            "mounted": L.RUN_DIR not in mounts_before and L.RUN_TMP not in mounts_before, "chain": True, "slice": True, "slice_started": True})
        rig.make_quote_dir()
        print(f"# round 2: artifacts in {rig.out}; units use the prefix {rig.TP} for sessions and for the probe", flush=True)
        try:
            round2_body(rig)
        except SystemExit:
            raise
        except Exception as e:
            say("R00", "FAIL", f"the round raised {e.__class__.__name__}: {str(e)[:300]}")
    finally:
        if rig is not None:
            cleanup(rig)
    fails = [g for g, st in OUT_LINES if st in FAILING]
    print(f"# summary: {len(OUT_LINES)} gates, {len(fails)} FAIL or INCONCLUSIVE ({', '.join(fails) or 'none'})", flush=True)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main_round2() if sys.argv[sys.argv.index("--round") + 1:][:1] == ["2"] else main())
