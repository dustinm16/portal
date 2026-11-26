"""Server-side browser: the unit's launch command, seat arithmetic, host preparation, availability and the
systemd launcher, with injected fakes (design 4.1, 4.2, 4.3, 6.4, 8.2, 13). Starts nothing, needs no root.

Run: venv/bin/python tests/test_rbrowser_unit_args.py

* the argument list of 4.2: every property pinned in order, one InaccessiblePaths per path, the launcher list,
  quoting of a path with a space or a quote, an inexpressible path raises, the "must never emit" list, no
  user id in the name or description, no shell, the probe and test prefixes
* seats and slice arithmetic of 4.3 for (4 CPU, 15 GB), (2 CPU, 4 GB), (16 CPU, 64 GB) and a 1-CPU host
* the firewall chain of 6.4 (SYN-ACK rule first, optional hashlimit rule, jump last): exact iptables and ip6tables command
  lists and their rounding, a stateful fake iptables for order, idempotence, stale jumps and failure clean-up
* prepare_host / unprepare_host with a fake run and a temporary directory: command lists, idempotence, failures,
  the slice drop-ins removed without `systemctl revert`
* availability() with a fake host: every reason of 8.2
* SystemdLauncher with a fake run: start flow, uid 0 refused, name checks, /proc and systemctl fixtures

* the supervisor's argument lists (x11vnc, Xvfb, Chromium flags, clipboard settings) at the end; its behaviour
  is in tests/test_rbrowser_supervisor.py
"""

import fnmatch
import asyncio
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rbrowser  # noqa: E402
import rbrowser_launch as L  # noqa: E402
import rbrowser_policy  # noqa: E402
from rbrowser import LaunchError, LaunchSpec  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc:
        return True
    except Exception as e:
        print("   unexpected", type(e).__name__, e)
        return False
    return False


def spec(**kw):
    d = dict(ident="0123456789ab", width=1280, height=720, clipboard="both", home_url="https://duckduckgo.com/",
             chromium="/usr/bin/chromium", memory_mb=2048, cpu_percent=125,
             deny=rbrowser_policy.deny_list(["168.63.129.16"], [("172.16.0.5", 24)], ["172.16.0.1"], []),
             hidden_extra=["/home/portal/scripts/portal", "/mnt/gamedata"], portal_unit="")
    d.update(kw)
    return LaunchSpec(**d)


PIN = "/sys/fs/bpf/portal-rb-ingress-0123456789abcdef"


def BA(*a, **k):
    """build_unit_args with the pin that prepare_host would have returned."""
    k.setdefault("ingress_pin", PIN)
    return L.build_unit_args(*a, **k)


def props(args):
    out = []
    for i, a in enumerate(args):
        if a == "-p":
            out.append(args[i + 1])
    return out


# ---------------------------------------------------------------- 4.2 the argument list
S = spec()
args = BA(S)
check("the list starts with the unit, quiet, no-block, slice, description (T1: no --collect, a failed unit stays readable until it is reset)",
      args[:5] == ["--unit=portal-rb-0123456789ab", "--quiet", "--no-block",
                   "--slice=system-portalrb.slice", "--description=Open Relay Portal browser session"] and "--collect" not in args, str(args[:6]))
check("T1: --collect is absent for the probe and the live test's prefix too",
      all("--collect" not in BA(spec(), pfx) for pfx in (L.PROBE_PREFIX, L.TEST_PREFIX)))
check("every element is a plain string and none holds a newline", all(isinstance(a, str) and "\n" not in a for a in args))
check("the command is python3 -I -S /mnt/session.py and ends the list",
      args[-4:] == ["/usr/bin/python3", "-I", "-S", "/mnt/session.py"])
P = props(args)
hidden_n = len(L.hidden_paths(S.hidden_extra))
PINNED = [
    "Type=exec", "DynamicUser=yes", "RuntimeDirectory=portal-rb/s-0123456789ab", "RuntimeDirectoryMode=0700",
    "PrivateIPC=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectProc=invisible",
    "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
    "AmbientCapabilities=", "UMask=0077",
    "TemporaryFileSystem=/run/work:rw,nosuid,nodev,size=768m,mode=1777",
    "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,size=64m,mode=1777",
    "TemporaryFileSystem=/run:ro,nosuid,nodev,noexec,size=64k,mode=0755",
    "BindPaths=/run/portal-rb/s-0123456789ab",
    "BindPaths=/run/portal-rb-tmp/0123456789ab:/tmp",
    "BindPaths=/run/portal-rb-tmp/0123456789ab:/var/tmp",
    "BindReadOnlyPaths=/run/portal-rb-static/bin:/mnt",
    "BindReadOnlyPaths=/run/portal-rb-static/chromium:/etc/chromium",
    "BindReadOnlyPaths=/run/portal-rb-static/chromium.d:/etc/chromium.d",
]
TAIL = [
    "MemoryHigh=1536M", "MemoryMax=2048M", "MemorySwapMax=0", "CPUQuota=125%", "IOWeight=50", "Nice=5",
    "TasksMax=512", "LimitNOFILE=4096", "LimitCORE=0", "OOMPolicy=continue", "TimeoutStopSec=5",
    "KillMode=control-group", "SendSIGKILL=yes", "RuntimeMaxSec=14460", "SocketBindDeny=any", "IPIngressFilterPath=" + PIN, "IPAccounting=yes",
    "IPAddressDeny=" + " ".join(S.deny), "StandardInput=null", "StandardOutput=journal", "StandardError=journal",
]
check("the properties before the hidden-path list are exactly those of 4.2, in order",
      P[:len(PINNED)] == PINNED, str([x for x in P[:len(PINNED)] if x not in PINNED]))
check("the properties after the hidden-path list are exactly those of 4.2, in order",
      P[len(PINNED) + hidden_n:] == TAIL, str(P[len(PINNED) + hidden_n:]))
check("nothing sits between them but InaccessiblePaths",
      all(p.startswith("InaccessiblePaths=") for p in P[len(PINNED):len(PINNED) + hidden_n]))
check("every -p is followed by exactly one assignment and the option never stands alone",
      args.count("-p") == len(P) and all("=" in p for p in P))
env = [args[i + 1] for i, a in enumerate(args) if a == "-E"]
check("environment: geometry, clipboard, home, chromium (no window manager variable, no display)",
      env == ["RB_GEOMETRY=1280x720", "RB_CLIPBOARD=both", "RB_HOME=https://duckduckgo.com/", "RB_CHROMIUM=/usr/bin/chromium"], str(env))
for needle in ("SocketBindDeny=any", "IPAccounting=yes", "TemporaryFileSystem=/run:ro,nosuid,nodev,noexec,size=64k,mode=0755",
               "BindPaths=/run/portal-rb/s-0123456789ab", "DynamicUser=yes", "OOMPolicy=continue"):
    check(f"property present: {needle}", needle in P)
check("slice name is system-portalrb.slice", "--slice=system-portalrb.slice" in args)
check("the runtime directory is on the portal tmpfs (portal-rb/s-<hex>)", "RuntimeDirectory=portal-rb/s-0123456789ab" in P)
check("IPAddressDeny is one element, space separated, from the deny list",
      sum(p.startswith("IPAddressDeny=") for p in P) == 1 and "10.0.0.0/8" in [p for p in P if p.startswith("IPAddressDeny=")][0].split("=", 1)[1].split())
check("the default CapabilityBoundingSet is the one harmless capability", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in P)

# hidden paths
ip = [p[len("InaccessiblePaths="):] for p in P if p.startswith("InaccessiblePaths=")]
check("one InaccessiblePaths per path, each with the - prefix", len(ip) == hidden_n and all(x.startswith("-/") for x in ip))
FIXED = "/srv /opt /boot /var/log /var/backups /var/spool /var/mail /etc/ssh /etc/searxng /etc/sudoers.d".split()
LAUNCH = ("/usr/bin/xdg-open /usr/bin/xdg-email /usr/bin/xdg-mime /usr/bin/xdg-settings /usr/bin/mimeopen /usr/bin/run-mailcap "
          "/usr/bin/gio /usr/bin/gvfs-open /usr/bin/kde-open /usr/bin/kde-open5 /usr/bin/exo-open /usr/bin/sensible-browser "
          "/usr/bin/lynx /usr/bin/xclip").split()
check("the fixed list of 4.2 is complete", all("-" + f in ip for f in FIXED), str([f for f in FIXED if "-" + f not in ip]))
check("the program-launcher list of 4.2 is complete (14 entries; xsel is not hidden, the supervisor reads the clipboard with it)",
      len(LAUNCH) == 14 and all("-" + f in ip for f in LAUNCH) and "-/usr/bin/xsel" not in ip)
check("the install directory and the storage roots are included", "-/home/portal/scripts/portal" in ip and "-/mnt/gamedata" in ip)
check("order: fixed, then the caller's, then the launchers", ip == ["-" + x for x in FIXED + S.hidden_extra + LAUNCH])
check("hidden_paths removes duplicates and keeps order", L.hidden_paths(["/srv", "/x", "/x"]).count("/srv") == 1 and L.hidden_paths(["/x", "/x"]).count("/x") == 1)
check("a path with a space is double-quoted with the prefix inside", L.quote_property_path("/mnt/my disk") == '"-/mnt/my disk"')
check("a quote and a backslash are escaped", L.quote_property_path('/mnt/a"b\\c') == '"-/mnt/a\\"b\\\\c"')
check("safe characters stay unquoted", L.quote_property_path("/mnt/a.b_c+d@e-f/g") == "-/mnt/a.b_c+d@e-f/g")
check("a colon, an equals sign and a non-ASCII letter are quoted", all(L.quote_property_path(p).startswith('"') for p in ("/mnt/a:b", "/mnt/a=b", "/mnt/\u00e9")))
a2 = BA(spec(hidden_extra=["/mnt/my disk"]))
check("a storage root with a space comes out as one quoted element", 'InaccessiblePaths="-/mnt/my disk"' in props(a2))
for bad in ("relative/path", "", "/", "/a\nb", "/a\x00b", "/a%b", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\tb", "/a\x7fb", "/\ud800", None, 5):
    check(f"an inexpressible path raises: {bad!r}", raises(LaunchError, BA, spec(hidden_extra=[bad])))

# the must-never-emit list
blob = "\n".join(args)
for banned in ("RestrictNamespaces", "ProcSubset", "SystemCallFilter", "PrivateNetwork", "PrivateTmp", "PrivateUsers",
               "--no-sandbox", "-shared", "-nolisten local", "RB_DISPLAY", "CPUWeight", "StateDirectory", "bash", "/bin/sh"):
    check(f"never emitted: {banned}", banned not in blob)
check("never emitted: an element that is exactly -c, sh or bash", not ({"-c", "sh", "bash"} & set(args)))
check("the unit name and description carry no user id and no name",
      args[0] == "--unit=portal-rb-0123456789ab" and "user" not in args[5].lower().replace("browser session", ""))
check("no wm, no portal unit: neither RB_WM nor BindsTo", "BindsTo" not in blob and "RB_WM" not in blob)
a3 = BA(spec(portal_unit="portal.service"))
P3 = props(a3)
check("the window manager is built in: no RB_WM, no spec field, no REQUIRE_WM, no matchbox", "RB_WM" not in " ".join(a3) and not hasattr(L, "REQUIRE_WM")
      and "wm" not in LaunchSpec.__dataclass_fields__ and "matchbox" not in (ROOT / "rbrowser_launch.py").read_text())
check("when the portal runs in a unit: BindsTo and After, and only then", "BindsTo=portal.service" in P3 and "After=portal.service" in P3)
check("a bad portal unit name raises", raises(LaunchError, BA, spec(portal_unit="portal.service; rm")))
# prefixes
ap = BA(spec(), L.PROBE_PREFIX, "probe.py", 19)
check("probe: unit prefix portal-rbprobe-, probe.py, Nice=19, all other properties equal",
      ap[0] == "--unit=portal-rbprobe-0123456789ab" and ap[-1] == "/mnt/probe.py" and "Nice=19" in props(ap)
      and [p for p in props(ap) if not p.startswith("Nice=") and "/etc/chromium" not in p] == [p for p in P if not p.startswith("Nice=") and "/etc/chromium" not in p])
check("probe: /etc/chromium is bound from chromium-probe (the policy without DeveloperToolsAvailability), a session from chromium",
      "BindReadOnlyPaths=/run/portal-rb-static/chromium-probe:/etc/chromium" in props(ap) and "BindReadOnlyPaths=/run/portal-rb-static/chromium:/etc/chromium" in P
      and "BindReadOnlyPaths=/run/portal-rb-static/chromium:/etc/chromium" not in props(ap))
at = BA(spec(), L.TEST_PREFIX)
check("live test: unit prefix portal-rbtest-", at[0] == "--unit=portal-rbtest-0123456789ab")
check("an unknown prefix or script raises", raises(LaunchError, BA, spec(), "portal-rb2-")
      and raises(LaunchError, BA, spec(), L.UNIT_PREFIX, "other.py"))
# validation
for name, kw in (("bad ident", dict(ident="XYZ")), ("ident of 11", dict(ident="0123456789a")), ("upper-case ident", dict(ident="0123456789AB")),
                 ("clipboard", dict(clipboard="all")), ("empty deny", dict(deny=[])), ("bad deny", dict(deny=["10.0.0.0/8; x"])),
                 ("deny with host bits", dict(deny=["10.0.0.1/8"])), ("http home", dict(home_url="http://example.org/")),
                 ("snap chromium", dict(chromium="/snap/bin/chromium")), ("relative chromium", dict(chromium="chromium")),
                 ("width", dict(width=1921)), ("height 0", dict(height=0)), ("memory", dict(memory_mb=10)), ("cpu", dict(cpu_percent=5000)),
                 ("float width", dict(width=800.5))):
    check(f"spec refused: {name}", raises(LaunchError, BA, spec(**kw)))
check("clipboard values both, to_browser and off pass the builder and reach RB_CLIPBOARD",
      all(f"RB_CLIPBOARD={c}" in BA(spec(clipboard=c)) for c in ("both", "to_browser", "off")))

# ---------------------------------------------------------------- 4.3 seats
GIB = 1024 ** 3
CFG = {"rbrowser_max_sessions": 2, "rbrowser_memory_mb": 2048, "rbrowser_cpu_percent": 150}
check("seats (4 CPU, 15 GB) = 2 seats, 125 %", L.seats(CFG, 4, 15 * GIB) == {"max": 2, "cpu_percent": 125}, str(L.seats(CFG, 4, 15 * GIB)))
check("seats (2 CPU, 4 GB) = 1 seat, 50 %", L.seats(CFG, 2, 4 * GIB) == {"max": 1, "cpu_percent": 50}, str(L.seats(CFG, 2, 4 * GIB)))
check("seats (16 CPU, 64 GB) = 2 seats, 150 %", L.seats(CFG, 16, 64 * GIB) == {"max": 2, "cpu_percent": 150}, str(L.seats(CFG, 16, 64 * GIB)))
c8 = dict(CFG, rbrowser_max_sessions=8)
check("seats (16 CPU, 64 GB, max 8) = 8 seats by memory (10) capped by the setting, 150 %", L.seats(c8, 16, 64 * GIB) == {"max": 8, "cpu_percent": 150})
check("seats (4 CPU, 15 GB, max 8) = 2 by memory", L.seats(c8, 4, 15 * GIB)["max"] == 2)
check("seats on a 1-CPU host: a floor of 50 %, never zero or negative", L.seats(CFG, 1, 8 * GIB)["cpu_percent"] == 50 and L.seats(CFG, 1.5, 8 * GIB)["cpu_percent"] == 50)
check("memory below one seat still gives 1 seat", L.seats(CFG, 8, 1 * GIB)["max"] == 1)
check("settings are clamped to their ranges", L.seats({"rbrowser_max_sessions": 99, "rbrowser_memory_mb": 1, "rbrowser_cpu_percent": 9999}, 64, 256 * GIB)
      == {"max": 8, "cpu_percent": 400})
check("settings that are not numbers fall back to the defaults", L.seats({"rbrowser_max_sessions": "x"}, 4, 15 * GIB) == {"max": 2, "cpu_percent": 125})
check("seats takes an object as well as a mapping",
      L.seats(type("C", (), {"rbrowser_max_sessions": 1, "rbrowser_memory_mb": 2048, "rbrowser_cpu_percent": 100})(), 4, 15 * GIB) == {"max": 1, "cpu_percent": 100})
check("slice properties on this host: 250 % quota, 4352M, 1024 tasks, weight 50",
      L.slice_properties(CFG, 4, 15 * GIB) == ["CPUWeight=50", "CPUQuota=250%", "MemoryMax=4352M", "TasksMax=1024"], str(L.slice_properties(CFG, 4, 15 * GIB)))
check("slice quota is capped at (ncpu - 1.5) cores", L.slice_properties(c8, 4, 64 * GIB)[1] == "CPUQuota=250%")
check("constants", L.MIN_W == 560 and L.CAPTURE_MAX == (1920, 1200) and L.STREAM_KBPS == 8000)

# ---------------------------------------------------------------- 6.4 iptables command lists
r = L.upload_rule_args(4000)
check("limit arguments: 4000 kbps -> 500kb/s, burst 1000kb",
      r["limit"] == ["-m", "hashlimit", "--hashlimit-name", "portalrb", "--hashlimit-above", "500kb/s", "--hashlimit-burst", "1000kb", "-j", "DROP"], str(r))
check("jump arguments: the cgroup v2 path of the slice",
      r["jump"] == ["-m", "cgroup", "--path", "system.slice/system-portalrb.slice", "-j", "PORTAL-RB"])
check("D1: no SYN-ACK rule anywhere (the listener control is the ingress filter)",
      "synack" not in r and not hasattr(L, "SYNACK_RULE") and set(r) == {"limit", "jump"})
check("rounding: 500 kbps -> 63kb/s and 125kb (rounded up); 501 -> 63kb/s, 126kb",
      "63kb/s" in L.upload_rule_args(500)["limit"] and "125kb" in L.upload_rule_args(500)["limit"]
      and "63kb/s" in L.upload_rule_args(501)["limit"] and "126kb" in L.upload_rule_args(501)["limit"])
check("limits outside 500..50000 raise", all(raises(ValueError, L.upload_rule_args, v) for v in (0, 499, 50001, -1, 4000.5, True)))
IPT = "/usr/sbin/iptables"
c = L.firewall_commands(IPT, 4000)
_w = [IPT, "-w", "2"]
_LIM = ["-m", "hashlimit", "--hashlimit-name", "portalrb", "--hashlimit-above", "500kb/s", "--hashlimit-burst", "1000kb", "-j", "DROP"]
_JMP = ["-m", "cgroup", "--path", "system.slice/system-portalrb.slice", "-j", "PORTAL-RB"]
check("firewall commands: every command list, exactly (-w 2 first; -S/-N/-F for the chain; the limit rule; jump at position 1)",
      c == {"chain_exists": _w + ["-S", "PORTAL-RB"], "new_chain": _w + ["-N", "PORTAL-RB"], "flush": _w + ["-F", "PORTAL-RB"],
            "check_limit": _w + ["-C", "PORTAL-RB"] + _LIM, "add_limit": _w + ["-A", "PORTAL-RB"] + _LIM,
            "check_jump": _w + ["-C", "OUTPUT"] + _JMP, "delete_jump": _w + ["-D", "OUTPUT"] + _JMP,
            "insert_jump": _w + ["-I", "OUTPUT", "1"] + _JMP}, str(c))
c6 = L.firewall_commands("/usr/sbin/ip6tables", 4000)
check("firewall commands: ip6tables gets the same lists under its own path",
      all(v[0] == "/usr/sbin/ip6tables" for v in c6.values()) and {k: v[1:] for k, v in c6.items()} == {k: v[1:] for k, v in c.items()})
check("firewall commands: 0, a setting between 1 and 499, above 50000 or a bool raises (with no limiter there is no chain)",
      all(raises(ValueError, L.firewall_commands, IPT, v) for v in (0, 1, 499, 50001, -1, True)))
rm = L.firewall_removal("/usr/sbin/ip6tables")
check("removal list: -C and -D of the jump, then -F and -X of the chain",
      rm["delete_jump"][3:5] == ["-D", "OUTPUT"] and rm["flush"][3:] == ["-F", "PORTAL-RB"] and rm["delete_chain"][3:] == ["-X", "PORTAL-RB"])
check("the old upload-only names are gone", not hasattr(L, "install_upload_rule") and not hasattr(L, "upload_rule_commands") and hasattr(L, "install_firewall"))


# ---------------------------------------------------------------- fakes
class FakeTables:
    """A stateful iptables / ip6tables: for each tool its chains (lists of rules, a rule is the tuple of arguments
    after the chain name) with OUTPUT always there. Understands -S -N -F -X -A -I -C -D as the real tools answer them."""

    def __init__(self, output=None, chains=None):
        self.t = {n: {"OUTPUT": list(output or []), **{k: list(v) for k, v in (chains or {}).items()}} for n in ("iptables", "ip6tables")}

    def handle(self, argv):
        tool = os.path.basename(argv[0])
        a = argv[3:] if argv[1:3] == ["-w", "2"] else argv[1:]
        chains = self.t[tool]
        op, chain = a[0], a[1]
        if op == "-S":
            return 0 if chain in chains else 1
        if op == "-N":
            if chain in chains:
                return 1
            chains[chain] = []
            return 0
        if chain not in chains:
            return 1
        if op == "-F":
            chains[chain] = []
            return 0
        if op == "-X":
            if chains[chain] or chain == "OUTPUT" or any(r[-1] == chain for rs in chains.values() for r in rs):
                return 1
            del chains[chain]
            return 0
        if op == "-A":
            chains[chain].append(tuple(a[2:]))
            return 0
        if op == "-I":
            chains[chain].insert(int(a[2]) - 1, tuple(a[3:]))
            return 0
        if op == "-C":
            return 0 if tuple(a[2:]) in chains[chain] else 1
        if op == "-D":
            r = tuple(a[2:])
            if r in chains[chain]:
                chains[chain].remove(r)
                return 0
            return 1
        return 2


class FakeRun:
    """Records every argv; `rules` maps a predicate on the command text to a return code (checked first, no state
    change); `tables` is a FakeTables that answers the iptables and ip6tables commands."""

    def __init__(self, rules=None, out=None, tables=None):
        self.calls = []
        self.rules = rules or []
        self.out = out or {}
        self.tables = tables

    async def __call__(self, argv, timeout=10.0):
        self.calls.append(list(argv))
        text = " ".join(argv)
        for pred, rc in self.rules:
            if pred(text):
                return L.Ran(rc, self.out.get(text, ""), "")
        if self.tables is not None and os.path.basename(argv[0]) in ("iptables", "ip6tables"):
            return L.Ran(self.tables.handle(argv), "", "")
        return L.Ran(0, self.out.get(text, ""), "")

    def texts(self):
        return [" ".join(c) for c in self.calls]


def inner(text):
    """The command of a host_run wrapper (after ` -- `); any other text unchanged."""
    return text.split(" -- ", 1)[1] if " --wait " in text and " -- " in text else text


def which_all(name):
    return {"iptables": "/usr/sbin/iptables", "ip6tables": "/usr/sbin/ip6tables"}.get(name, "/usr/bin/" + name)


POLICY = rbrowser_policy.build_policy("https://duckduckgo.com/", ["8.8.8.8"])
CFGH = dict(CFG, rbrowser_upload_kbps=4000)
LIM_T, JMP_T = tuple(_LIM), tuple(_JMP)


class FakeBpf:
    """What prepare_host, unprepare_host and the launcher ask of rbrowser_bpf, with nothing loaded. `attached_map` maps a
    cgroup path (with the cgroup root in front) to True; anything else is False; `fail_with` makes attached() raise."""
    PIN_BASE = "/sys/fs/bpf/portal-rb-ingress"

    def __init__(self, avail=(True, ""), load_error=None, attach=True, fail_with=None):
        self.avail, self.load_error, self.attach, self.fail_with = avail, load_error, attach, fail_with
        self.loaded, self.unpinned, self.asked = [], [], []

    def available(self, pin_dir="/sys/fs/bpf"):
        return self.avail

    def load_and_pin(self, base=PIN_BASE):
        if self.load_error:
            raise L.rbrowser_bpf.BpfError(self.load_error)
        self.loaded.append(base)
        return {"path": base + "-0123456789abcdef", "id": 7, "tag": "00", "created": True}

    def pin_path(self, base=PIN_BASE, prog=None):
        return base + "-0123456789abcdef"

    def unpin(self, path):
        self.unpinned.append(path)
        return True

    def attached(self, cgroup_path, pin=None):
        self.asked.append((cgroup_path, pin))
        if self.fail_with:
            raise L.rbrowser_bpf.BpfError(self.fail_with)
        return self.attach


async def PH(*a, **k):
    """prepare_host with a fake bpf unless the test gives one."""
    k.setdefault("bpf", FakeBpf())
    return await L.prepare_host(*a, **k)


TMPD = tempfile.mkdtemp(prefix="rbtest-tmpd-")
import atexit as _atexit, shutil as _shutil  # noqa: E402
_atexit.register(_shutil.rmtree, TMPD, ignore_errors=True)


THEMED = tempfile.mkdtemp(prefix="rbtest-theme-")
STATICD = tempfile.mkdtemp(prefix="rbtest-static-")
_atexit.register(_shutil.rmtree, THEMED, ignore_errors=True)
_atexit.register(_shutil.rmtree, STATICD, ignore_errors=True)


EMPTY_CG = tempfile.mkdtemp(prefix="rbtest-cg-")      # an empty cgroup root: the slice has no directory, so no unit
_atexit.register(_shutil.rmtree, EMPTY_CG, ignore_errors=True)


def UNP(**k):
    """unprepare_host with a cgroup root of its own unless the test gives one: no test reads this host's /sys/fs/cgroup."""
    k.setdefault("cgroup_root", EMPTY_CG)
    return L.unprepare_host(**k)


def LN(*a, **k):
    """SystemdLauncher with the pin, a fake bpf and a scratch tmp area unless the test gives them."""
    k.setdefault("ingress_pin", PIN)
    k.setdefault("tmp_dir", TMPD)
    k.setdefault("bpf", FakeBpf())
    k.setdefault("theme_dir", THEMED)     # never the host's /run/portal-rb-state/theme: sweep_tmp and stop remove files there
    k.setdefault("static_dir", STATICD)
    # PID 1's table: both areas are tmpfs mounts there (devices 0:41 and 0:40) and this "process" sees the same devices
    k.setdefault("mountinfo", lambda _t=k["tmp_dir"], _r=k.get("run_dir", L.RUN_DIR): (
        f"41 30 0:40 / {_t} rw,nosuid,nodev,noexec - tmpfs portal-rb-tmp rw,size=32768k,mode=700\n42 30 0:41 / {_r} rw,nosuid,nodev,noexec - tmpfs portal-rb rw,size=8192k\n"))
    k.setdefault("want_dev_of", lambda p, _t=k["tmp_dir"]: "0:40" if p == _t else "0:41")
    return L.SystemdLauncher(*a, **k)


def unit_src(td):
    d = Path(td) / "unit"
    d.mkdir()
    (d / "session.py").write_text("# session\n")
    (d / "probe.py").write_text("# probe\n")
    return d


def tool_texts(texts, tool):
    return [x.replace(f"/usr/sbin/{tool} -w 2 ", "") for x in texts if x.startswith(f"/usr/sbin/{tool} ")]


async def host_tests():
    with tempfile.TemporaryDirectory() as td:
        paths = L.HostPaths(static=f"{td}/static", run_dir=f"{td}/run", state=f"{td}/state", tmp_dir=f"{td}/tmp")
        src = unit_src(td)
        mi = f"1 2 0:5 / {td}/run rw - tmpfs portal-rb rw\n1 2 0:6 / {td}/tmp rw - tmpfs portal-rb-tmp rw\n"
        ft = FakeTables()
        run = FakeRun(tables=ft)
        res = await PH(CFGH, policy=POLICY, run=run, ncpu=4, mem_total=15 * GIB, paths=paths,
                                   mountinfo="", source_dir=src, which=which_all)
        check("prepare_host: ok with every step done, the ingress filter and the limiter included", res["ok"] and res["slice_ok"] and res["firewall"] and res["upload_rule"]
              and res["firewall_reason"] == "" and res["upload_reason"] == "" and res["ingress_filter"] and res["ingress_pin"] == PIN, str(res))
        t = run.texts()
        mount = [inner(x) for x in t if " -t tmpfs " in x]
        check("prepare_host: mounts the 8 MiB session tmpfs and the 32 MiB /tmp tmpfs (D6) once each, with their options",
              mount == [f"/usr/bin/mount -t tmpfs -o size=8m,nr_inodes=2048,mode=0755,nosuid,nodev,noexec portal-rb {td}/run",
                        f"/usr/bin/mount -t tmpfs -o size=32m,nr_inodes=4096,mode=0700,nosuid,nodev,noexec portal-rb-tmp {td}/tmp"], str(mount))
        # fix pass 2 (F1): the portal has a private mount namespace; a mount made by its own process never reaches systemd
        wrapped = [x for x in t if " -t tmpfs " in x]
        check("prepare_host: each mount runs in the HOST's namespace through a oneshot unit (systemd-run --wait, portal-rbhost-<12 hex>, no namespace properties), never directly",
              len(wrapped) == 2 and all(re.fullmatch(r"/usr/bin/systemd-run --unit=portal-rbhost-[0-9a-f]{12}\.service --wait --collect --quiet "
                                                      r"--description=\S.* -p Type=oneshot -p TimeoutStartSec=30 -p RuntimeMaxSec=30 -- /usr/bin/mount -t tmpfs .*", x) for x in wrapped)
              and not any(c[0].endswith("/mount") or c[0].endswith("/umount") for c in run.calls)
              and not any(a.startswith(("-pPrivate", "-pProtect", "-pReadWrite", "-pTemporary", "-pBind", "-pMount")) for c in run.calls for a in c)
              and not any(c[i] == "-p" and c[i + 1].split("=")[0] not in ("Type", "TimeoutStartSec", "RuntimeMaxSec") for c in run.calls if "systemd-run" in c[0] for i in range(len(c) - 1)), str(wrapped))
        check("prepare_host: the two helper units have different names", len({x.split("--unit=")[1].split()[0] for x in wrapped}) == 2)
        check("prepare_host: the mount point exists before mount and is 0755", os.path.isdir(f"{td}/run") and stat.S_IMODE(os.stat(f"{td}/run").st_mode) == 0o755)
        check("prepare_host: sets the slice properties with --runtime",
              "/usr/bin/systemctl set-property --runtime system-portalrb.slice CPUWeight=50 CPUQuota=250% MemoryMax=4352M TasksMax=1024" in t, str(t))
        i_set = next(i for i, x in enumerate(t) if "set-property" in x)
        i_start = [i for i, x in enumerate(t) if x == "/usr/bin/systemctl start system-portalrb.slice"]
        i_rule = [i for i, x in enumerate(t) if x.startswith("/usr/sbin/iptables") or x.startswith("/usr/sbin/ip6tables")]
        check("prepare_host: the slice is started after its properties are set and BEFORE the first iptables command (the cgroup match needs the directory)",
              len(i_start) == 1 and i_set < i_start[0] < min(i_rule) and res["slice_started"], str(t))
        check("prepare_host: state directory is 0700", stat.S_IMODE(os.stat(f"{td}/state").st_mode) == 0o700)
        check("prepare_host: static tree layout and modes",
              all(os.path.exists(f"{td}/static/{p}") for p in ("bin/session.py", "bin/probe.py", "chromium/policies/managed/portal.json",
                                                              "chromium/policies/recommended", "chromium/master_preferences", "chromium.d/README"))
              and stat.S_IMODE(os.stat(f"{td}/static/bin/session.py").st_mode) == 0o644
              and stat.S_IMODE(os.stat(f"{td}/static/chromium").st_mode) == 0o755
              and os.listdir(f"{td}/static/chromium/policies/recommended") == [])
        import json as _j
        check("prepare_host: portal.json is the policy that was passed", _j.load(open(f"{td}/static/chromium/policies/managed/portal.json")) == POLICY)
        _pp = _j.load(open(f"{td}/static/chromium-probe/policies/managed/portal.json"))
        check("prepare_host: the probe tree holds the policy without DeveloperToolsAvailability and nothing else changed",
              "DeveloperToolsAvailability" not in _pp and POLICY.get("DeveloperToolsAvailability") == 2 and _pp == {k: v for k, v in POLICY.items() if k != "DeveloperToolsAvailability"}
              and os.listdir(f"{td}/static/chromium-probe/policies/recommended") == [] and "distribution" in _j.load(open(f"{td}/static/chromium-probe/master_preferences")))
        check("prepare_host: master_preferences is JSON with the distribution block", "distribution" in _j.load(open(f"{td}/static/chromium/master_preferences")))
        check("prepare_host: the scripts are copies of the unit directory", open(f"{td}/static/bin/probe.py").read() == "# probe\n")
        want_fresh = [
            "-S PORTAL-RB", "-N PORTAL-RB", "-C OUTPUT " + " ".join(_JMP), "-F PORTAL-RB",
            "-A PORTAL-RB " + " ".join(_LIM), "-I OUTPUT 1 " + " ".join(_JMP), "-C PORTAL-RB " + " ".join(_LIM), "-C OUTPUT " + " ".join(_JMP)]
        for tool in ("iptables", "ip6tables"):
            check(f"prepare_host: {tool} exact command list on a fresh host (chain, stale-jump check, flush, limit rule, jump at 1, verify both)",
                  tool_texts(t, tool) == want_fresh, str(tool_texts(t, tool)))
            check(f"prepare_host: {tool} ends with the limit rule alone in the chain and one jump at position 1",
                  ft.t[tool]["PORTAL-RB"] == [LIM_T] and ft.t[tool]["OUTPUT"] == [JMP_T], str(ft.t[tool]))
        check("prepare_host: every iptables command comes before every ip6tables command (one tool is finished before the next)",
              max(i for i, x in enumerate(t) if x.startswith("/usr/sbin/iptables ")) < min(i for i, x in enumerate(t) if x.startswith("/usr/sbin/ip6tables ")))
        check("prepare_host: every command is an argument list of strings", all(isinstance(c, list) and all(isinstance(a, str) for a in c) for c in run.calls))
        check("prepare_host: iptables always uses -w 2 and the absolute path", all(x.startswith(("/usr/sbin/iptables -w 2 ", "/usr/sbin/ip6tables -w 2 ")) for x in t if "tables" in x))
        # idempotent: second run with the mount and the rules already there
        run2 = FakeRun(tables=ft)
        res2 = await PH(CFGH, policy=POLICY, run=run2, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        t2 = run2.texts()
        check("prepare_host again: ok, no second mount", res2["ok"] and res2["firewall"] and not any(" -t tmpfs " in x for x in t2))
        check("prepare_host again: the chain is not created again, the old jump is deleted and put back (never trusted by a -C alone)",
              all("-N PORTAL-RB" not in x for x in t2)
              and all(tool_texts(t2, tl)[:5] == ["-S PORTAL-RB", "-C OUTPUT " + " ".join(_JMP), "-D OUTPUT " + " ".join(_JMP), "-C OUTPUT " + " ".join(_JMP), "-F PORTAL-RB"]
                      for tl in ("iptables", "ip6tables")), str([tool_texts(t2, tl)[:6] for tl in ("iptables", "ip6tables")]))
        check("prepare_host again: the state is the same as after the first run (one jump, two rules, in order)",
              all(ft.t[tl]["PORTAL-RB"] == [LIM_T] and ft.t[tl]["OUTPUT"] == [JMP_T] for tl in ("iptables", "ip6tables")))
        # a stale and doubled jump, and somebody else's rule at the top of OUTPUT: ours goes back to position 1, theirs stay
        foreign = ("-p", "tcp", "--dport", "22", "-j", "ACCEPT")
        ft3 = FakeTables(output=[foreign, JMP_T, JMP_T], chains={"PORTAL-RB": [("-j", "RETURN")]})
        run3 = FakeRun(tables=ft3)
        res3 = await PH(CFGH, policy=POLICY, run=run3, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("prepare_host: a doubled jump and a leftover chain: one jump at position 1, the foreign rule kept after it, the chain rebuilt",
              res3["ok"] and all(ft3.t[tl]["OUTPUT"] == [JMP_T, foreign] and ft3.t[tl]["PORTAL-RB"] == [LIM_T] for tl in ("iptables", "ip6tables")),
              str(ft3.t))
        # no limiter (setting 0 or below 500): no chain at all, a chain of an earlier run is taken away, ok all the same
        for kb, why in ((0, "setting"), (300, "below 500")):
            ft4 = FakeTables(output=[JMP_T], chains={"PORTAL-RB": [LIM_T]})
            run4 = FakeRun(tables=ft4)
            res4 = await PH(dict(CFGH, rbrowser_upload_kbps=kb), policy=POLICY, run=run4, ncpu=4, mem_total=15 * GIB,
                            paths=paths, mountinfo=mi, source_dir=src, which=which_all)
            check(f"upload_kbps {kb}: ok, no firewall, no upload rule and the reason says so", res4["ok"] and not res4["firewall"] and not res4["upload_rule"] and why in res4["upload_reason"], str(res4))
            check(f"upload_kbps {kb}: no hashlimit command, a chain left by an earlier run is removed on both tools (no SYN-ACK rule exists any more)",
                  not any("hashlimit" in x or "--tcp-flags" in x for x in run4.texts())
                  and all(ft4.t[tl]["OUTPUT"] == [] and "PORTAL-RB" not in ft4.t[tl] for tl in ("iptables", "ip6tables")), str(ft4.t))
        # failures of the host steps
        run5 = FakeRun(tables=FakeTables(), rules=[(lambda t: " -t tmpfs " in t, 32)])
        res5 = await PH(CFGH, policy=POLICY, run=run5, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo="", source_dir=src, which=which_all)
        check("a failed mount makes the host not ok and stops before the slice and the firewall", not res5["ok"] and not any("set-property" in x or "tables" in x for x in run5.texts()))
        res5b = await PH(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, paths=paths,
                                     mountinfo=f"1 2 0:5 / {td}/run rw - ext4 /dev/x rw\n", source_dir=src, which=which_all)
        check("something other than a tmpfs on the mount point: not ok", not res5b["ok"])
        run6 = FakeRun(tables=FakeTables(), rules=[(lambda t: "set-property" in t, 1)])
        res6 = await PH(CFGH, policy=POLICY, run=run6, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("a failed slice is not fatal and is reported (the caller halves the seats)", res6["ok"] and not res6["slice_ok"] and res6["reasons"])
        run6b = FakeRun(tables=FakeTables(), rules=[(lambda t: " start " in t, 1)])
        res6b = await PH(CFGH, policy=POLICY, run=run6b, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("a slice that cannot be started is reported; the firewall is still tried", res6b["slice_ok"] and not res6b["slice_started"] and any("started" in r for r in res6b["reasons"])
              and res6b["firewall"])
        run6c = FakeRun(tables=FakeTables(), rules=[(lambda t: " start " in t, 1), (lambda t: " -I OUTPUT " in t, 1)])
        res6c = await PH(CFGH, policy=POLICY, run=run6c, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("a slice that cannot be started and a jump the kernel refuses (no cgroup directory): the limiter is off, the host is still ok, both reasons given",
              res6c["ok"] and not res6c["upload_rule"] and not res6c["firewall"] and any("started" in r for r in res6c["reasons"]) and any("upload limit" in r for r in res6c["reasons"]))
        # firewall failures: not ok, the reason names the step, and what was installed is removed again
        cases = [
            ("the chain cannot be created", lambda t: "-N PORTAL-RB" in t, "chain could not be created"),
            ("an old jump cannot be deleted", lambda t: " -D OUTPUT " in t, None),
            ("the chain cannot be flushed", lambda t: " -F PORTAL-RB" in t, "could not be flushed"),
            ("the limit rule cannot be added", lambda t: "-A PORTAL-RB -m hashlimit" in t, "limit rule could not be added"),
            ("the jump cannot be inserted", lambda t: " -I OUTPUT 1 " in t, "jump could not be inserted"),
        ]
        for name, pred, frag in cases:
            for tool in ("iptables", "ip6tables"):
                ftf = FakeTables(output=[JMP_T] if "old jump" in name else [])
                rf = FakeRun(tables=ftf, rules=[(lambda t, pred=pred, tool=tool: t.startswith(f"/usr/sbin/{tool} ") and pred(t), 1)])
                resf = await PH(CFGH, policy=POLICY, run=rf, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
                left = {tl: (ftf.t[tl]["OUTPUT"], "PORTAL-RB" in ftf.t[tl]) for tl in ftf.t}
                clean = (all(left[tl] == ([], False) for tl in left) if "old jump" not in name and "flushed" not in name
                         else all(left[tl][0] == [] for tl in left) if "flushed" in name else True)
                check(f"firewall failure on {tool}: {name}: host still ok, firewall False, no upload rule, a reason, and no chain or jump is left"
                      + (" (the jump that was there stays: it could not be deleted)" if "old jump" in name else ""),
                      (resf["ok"] and not resf["firewall"] and resf["firewall_reason"].startswith(tool) and any("upload limit" in r for r in resf["reasons"])
                       and (frag is None or frag in resf["firewall_reason"]) and not resf["upload_rule"] and clean), f"{resf} {left}")
        # verification failures: the insert succeeded, the -C afterwards does not
        for name, frag in (("the limit rule", "-C PORTAL-RB -m hashlimit"),):
            ftv = FakeTables()
            rv = FakeRun(tables=ftv, rules=[(lambda t, frag=frag: t.startswith("/usr/sbin/ip6tables ") and frag in t, 1)])
            resv = await PH(CFGH, policy=POLICY, run=rv, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
            check(f"firewall verification: {name} that does not pass -C turns the limiter off (host still ok) and the chain is taken away on both tools",
                  resv["ok"] and not resv["upload_rule"] and "could not be verified" in resv["firewall_reason"] and resv["firewall_reason"].startswith("ip6tables")
                  and all(ftv.t[tl]["OUTPUT"] == [] and "PORTAL-RB" not in ftv.t[tl] for tl in ftv.t), f"{resv} {ftv.t}")
        ftj = FakeTables()
        calls = {"jump_c": 0}

        async def jump_never_verifies(argv, timeout=10.0):
            text = " ".join(argv)
            if " -C OUTPUT " in text and argv[0].endswith("ip6tables"):
                calls["jump_c"] += 1
                if calls["jump_c"] == 2:          # the first -C finds no stale jump, the second is the verification
                    return L.Ran(1, "", "")
            return await FakeRun(tables=ftj)(argv, timeout)
        resj = await PH(CFGH, policy=POLICY, run=jump_never_verifies, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("firewall verification: a jump that does not pass the final -C turns the limiter off, the host is still ok", resj["ok"] and not resj["upload_rule"] and "cgroup jump could not be verified" in resj["firewall_reason"], str(resj))
        # a jump that can never be deleted does not loop for ever
        runb = FakeRun(rules=[(lambda t: " -C OUTPUT " in t, 0), (lambda t: " -D OUTPUT " in t, 0)])
        resb = await PH(CFGH, policy=POLICY, run=runb, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("a jump that is always there: the -D loop is bounded (5 tries, then the clean-up's 5) and the limiter is off", resb["ok"] and not resb["upload_rule"] and "too many" in resb["firewall_reason"]
              and L.JUMP_DELETE_MAX <= sum(1 for x in runb.texts() if x.startswith("/usr/sbin/iptables") and " -D OUTPUT " in x) <= 2 * L.JUMP_DELETE_MAX, str(resb["firewall_reason"]))
        # iptables and ip6tables are optional (D1): without either, no limiter, no firewall command, everything else is done
        for gone in ("iptables", "ip6tables"):
            tdir = Path(td) / f"nt-{gone}"
            runm = FakeRun(tables=FakeTables())
            resm = await PH(CFGH, policy=POLICY, run=runm, ncpu=4, mem_total=15 * GIB,
                            paths=L.HostPaths(static=f"{tdir}/static", run_dir=f"{tdir}/run", state=f"{tdir}/state", tmp_dir=f"{tdir}/tmp"), mountinfo="", source_dir=src,
                            which=lambda n, gone=gone: "" if n == gone else which_all(n))
            check(f"no {gone}: the host is still ok, no limiter, the reason names it, no firewall command ran, the static tree is written",
                  resm["ok"] and not resm["firewall"] and not resm["upload_rule"] and gone in resm["upload_reason"]
                  and not any(x.startswith(("/usr/sbin/iptables", "/usr/sbin/ip6tables")) for x in runm.texts()) and (tdir / "static" / "bin" / "session.py").exists(), str(resm))
        # the ingress filter (D1): loaded and pinned first, a failure changes nothing and makes the host not ok
        fb = FakeBpf()
        tdir = Path(td) / "bpf-ok"
        resi = await L.prepare_host(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, bpf=fb, bpf_base="/sys/fs/bpf/portal-rb-x",
                                    paths=L.HostPaths(static=f"{tdir}/static", run_dir=f"{tdir}/run", state=f"{tdir}/state", tmp_dir=f"{tdir}/tmp"), mountinfo="", source_dir=src, which=which_all)
        check("prepare_host: loads and pins the filter once and returns the pin path (the base can be given)",
              resi["ok"] and fb.loaded == ["/sys/fs/bpf/portal-rb-x"] and resi["ingress_pin"] == "/sys/fs/bpf/portal-rb-x-0123456789abcdef" and resi["ingress_filter"], str(resi))
        for label, fbad in (("cannot be loaded", FakeBpf(load_error="BPF_PROG_LOAD failed: EPERM\nverifier log:\nsecret detail")),
                            ("is not available here", FakeBpf(avail=(False, "needs root")))):
            tdir = Path(td) / ("bpf-bad-" + label.split()[1])
            runi = FakeRun(tables=FakeTables())
            resb2 = await L.prepare_host(CFGH, policy=POLICY, run=runi, ncpu=4, mem_total=15 * GIB, bpf=fbad,
                                         paths=L.HostPaths(static=f"{tdir}/static", run_dir=f"{tdir}/run", state=f"{tdir}/state", tmp_dir=f"{tdir}/tmp"), mountinfo="", source_dir=src, which=which_all)
            check(f"prepare_host: a filter that {label}: host not ok, no pin, one reason, nothing changed (no command, nothing written)",
                  not resb2["ok"] and not resb2["ingress_filter"] and resb2["ingress_pin"] == "" and len(resb2["reasons"]) == 1
                  and resb2["reasons"][0].startswith("ingress filter: ") and "secret detail" not in resb2["reasons"][0]
                  and runi.calls == [] and not tdir.exists(), str(resb2))
        fbp = FakeBpf()
        fbp.load_and_pin = lambda base=FakeBpf.PIN_BASE: {"path": "/tmp/evil"}
        resp = await L.prepare_host(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, bpf=fbp,
                                    paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        check("prepare_host: a pin path outside /sys/fs/bpf/portal-rb is refused", not resp["ok"] and resp["ingress_pin"] == "")
        res9 = await PH(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo="",
                                    source_dir=Path(td) / "nowhere", which=which_all)
        check("a missing unit script: not ok, reason names static tree", not res9["ok"] and "static tree" in res9["reasons"][0])
        # write_policy replaces only the policy
        L.write_policy(paths, rbrowser_policy.build_policy("https://example.org/", []))
        check("write_policy replaces the managed policy file",
              _j.load(open(f"{td}/static/chromium/policies/managed/portal.json"))["HomepageLocation"] == "https://example.org/"
              and _j.load(open(f"{td}/static/chromium-probe/policies/managed/portal.json"))["HomepageLocation"] == "https://example.org/"
              and "DeveloperToolsAvailability" not in _j.load(open(f"{td}/static/chromium-probe/policies/managed/portal.json")))
        # ---- unprepare
        d_ok = Path(td) / "dropins"
        d_ok.mkdir()
        own = {"50-CPUWeight.conf": "# created via set-property\n[Slice]\nCPUWeight=50\n", "50-CPUQuota.conf": "[Slice]\nCPUQuota=250%\n",
               "50-MemoryMax.conf": "[Slice]\nMemoryMax=4352M\n", "50-TasksMax.conf": "[Slice]\nTasksMax=1024\n"}
        theirs = {"90-operator.conf": "[Slice]\nCPUQuota=10%\nMemoryHigh=1G\n", "91-other.conf": "[Slice]\nIOWeight=10\n", "notes.txt": "CPUQuota=1%\n",
                  "92-empty.conf": "# nothing\n"}
        for n, body in {**own, **theirs}.items():
            (d_ok / n).write_text(body)
        (d_ok / "50-link.conf").symlink_to(d_ok / "50-CPUQuota.conf")
        ftu = FakeTables()
        await PH(CFGH, policy=POLICY, run=FakeRun(tables=ftu), ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=mi, source_dir=src, which=which_all)
        ru = FakeRun(tables=ftu)
        res_u = await UNP(run=ru, paths=paths, mountinfo=mi, units_left=0, which=which_all, dropin_dir=str(d_ok))
        tu = ru.texts()
        check("unprepare: removes the chain on both tools (jump, flush, delete) and unmounts when no unit is left",
              res_u["unmounted"] and f"/usr/bin/umount {td}/run" in [inner(x) for x in tu] and f"/usr/bin/umount {td}/tmp" in [inner(x) for x in tu]
              and sum(1 for x in tu if "umount" in x and "--wait" in x and "--unit=portal-rbhost-" in x) == 2 and res_u["firewall_removed"]
              and all(f"/usr/sbin/{t} -w 2 -X PORTAL-RB" in tu for t in ("iptables", "ip6tables"))
              and all(ftu.t[tl]["OUTPUT"] == [] and "PORTAL-RB" not in ftu.t[tl] for tl in ftu.t), str(tu))
        check("unprepare: NEVER runs `systemctl revert` (it would delete an operator's drop-ins and unmask the unit)", not any(" revert" in x for x in tu))
        check("unprepare: removes exactly the drop-ins prepare_host writes, leaves an operator's file, a file with other properties, a non-.conf file, an empty one and a link",
              sorted(res_u["dropins_removed"]) == sorted(own) and sorted(os.listdir(d_ok)) == sorted(list(theirs) + ["50-link.conf"]), str(sorted(os.listdir(d_ok))))
        check("unprepare: daemon-reload through the runner after the drop-ins are gone, then the slice is stopped",
              res_u["daemon_reloaded"] and res_u["slice_stopped"] and tu.index("/usr/bin/systemctl daemon-reload") < tu.index("/usr/bin/systemctl stop system-portalrb.slice"), str(tu))
        d_own = Path(td) / "dropins2"
        d_own.mkdir()
        for n, body in own.items():
            (d_own / n).write_text(body)
        ru_b = FakeRun(tables=FakeTables())
        res_b = await UNP(run=ru_b, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(d_own))
        check("unprepare: when only its own drop-ins are there the directory goes too", not d_own.exists() and sorted(res_b["dropins_removed"]) == sorted(own))
        ru_c = FakeRun(tables=FakeTables())
        res_c = await UNP(run=ru_c, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(Path(td) / "no-such-dir"))
        check("unprepare: no drop-in directory: no daemon-reload, the slice is still stopped", not res_c["daemon_reloaded"] and res_c["dropins_removed"] == []
              and not any("daemon-reload" in x for x in ru_c.texts()) and res_c["slice_stopped"])
        ru_d = FakeRun(tables=FakeTables(), rules=[(lambda t: "daemon-reload" in t, 1)])
        d_f = Path(td) / "dropins3"
        d_f.mkdir()
        (d_f / "50-CPUQuota.conf").write_text(own["50-CPUQuota.conf"])
        res_d = await UNP(run=ru_d, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(d_f))
        check("unprepare: a failed daemon-reload is reported and the slice is stopped all the same", res_d["dropins_removed"] and not res_d["daemon_reloaded"] and res_d["slice_stopped"])
        ru2 = FakeRun(tables=FakeTables())
        d_keep = Path(td) / "dropins4"
        d_keep.mkdir()
        (d_keep / "50-CPUQuota.conf").write_text(own["50-CPUQuota.conf"])
        res_u2 = await UNP(run=ru2, paths=paths, mountinfo=mi, units_left=1, which=which_all, dropin_dir=str(d_keep))
        check("unprepare: with a session unit left nothing at all is undone: tmpfs, chain, drop-ins, slice stay and no command runs",
              res_u2["kept"] and ru2.calls == [] and (d_keep / "50-CPUQuota.conf").exists() and not res_u2["firewall_removed"] and not res_u2["slice_stopped"], str(ru2.texts()))
        ru3 = FakeRun(tables=FakeTables())
        await UNP(run=ru3, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(Path(td) / "none"))
        check("unprepare: nothing mounted, nothing unmounted", not any("umount" in x for x in ru3.texts()))
        fbu = FakeBpf()
        await UNP(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(Path(td) / "none"), bpf=fbu, bpf_pin=PIN)
        check("unprepare: with no unit left the pin that prepare_host returned is removed", fbu.unpinned == [PIN])
        fbu2 = FakeBpf()
        res_k = await UNP(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo=mi, units_left=1, which=which_all, dropin_dir=str(Path(td) / "none"), bpf=fbu2, bpf_pin=PIN)
        check("unprepare: with a unit left the pin is NEVER removed (a pin gone under a running unit detaches the filter at the next re-apply)",
              fbu2.unpinned == [] and res_k["pin_kept"] and not res_k["pin_removed"])
        fbu3 = FakeBpf()
        await UNP(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(Path(td) / "none"), bpf=fbu3)
        check("unprepare: without a pin given the pin of the current program is the one removed", fbu3.unpinned == [FakeBpf().pin_path()])
        fbu4 = FakeBpf()
        fbu4.unpin = lambda path: (_ for _ in ()).throw(L.rbrowser_bpf.BpfError("nope"))
        res_e = await UNP(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=str(Path(td) / "none"), bpf=fbu4)
        check("unprepare: a pin that cannot be removed does not stop the rest", res_e["slice_stopped"] and not res_e["pin_removed"])
        ru4 = FakeRun()  # -C always succeeds: the removal loop must stop
        await UNP(run=ru4, paths=paths, mountinfo="", which=which_all, dropin_dir=str(Path(td) / "none"))
        check("unprepare: the -D loop is bounded", sum(1 for x in ru4.texts() if " -D OUTPUT " in x) <= 10)
        # the pin does not rest on the caller's count (fix pass 1)
        none_dir = str(Path(td) / "none")
        cg_busy = Path(td) / "cg-busy"
        (cg_busy / "system.slice" / "system-portalrb.slice" / "portal-rbprobe-0123456789ab.service").mkdir(parents=True)
        (cg_busy / "system.slice" / "system-portalrb.slice" / "cgroup.procs").write_text("")
        fb_a, ru_a = FakeBpf(), FakeRun(tables=FakeTables())
        res_a = await L.unprepare_host(run=ru_a, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_a, bpf_pin=PIN, cgroup_root=str(cg_busy))
        check("unprepare: units_left 0 with a unit cgroup (a probe unit the caller did not count) in the slice: the pin STAYS, pin_kept, the rest is still undone",
              fb_a.unpinned == [] and res_a["pin_kept"] and not res_a["pin_removed"] and res_a["slice_children"] == ["portal-rbprobe-0123456789ab.service"]
              and res_a["firewall_removed"] and res_a["slice_stopped"], str(res_a))
        fb_m = FakeBpf()
        res_m = await L.unprepare_host(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo=mi, units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_m, bpf_pin=PIN, cgroup_root=str(cg_busy))
        check("unprepare: ... and the tmpfs areas that such a unit has bound are not unmounted", res_m["kept"] and not res_m["unmounted"])
        fb_b = FakeBpf()
        ru_b2 = FakeRun(tables=FakeTables(), rules=[(lambda t: t.endswith("stop system-portalrb.slice"), 1)])
        res_b2 = await L.unprepare_host(run=ru_b2, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_b, bpf_pin=PIN, cgroup_root=EMPTY_CG)
        check("unprepare: a slice stop that failed keeps the pin even when no cgroup is seen", fb_b.unpinned == [] and res_b2["pin_kept"] and not res_b2["slice_stopped"], str(res_b2))
        fb_c = FakeBpf()
        res_c2 = await L.unprepare_host(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=lambda n: "" if n == "systemctl" else which_all(n),
                                        dropin_dir=none_dir, bpf=fb_c, bpf_pin=PIN, cgroup_root=EMPTY_CG)
        check("unprepare: with no systemctl the slice cannot be shown stopped: the pin stays", fb_c.unpinned == [] and res_c2["pin_kept"])
        fb_d = FakeBpf()
        res_d2 = await L.unprepare_host(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_d, bpf_pin=PIN,
                                        cgroup_root=str(Path(td) / "cg-file-not-a-dir"))
        check("unprepare: a missing cgroup root counts as an empty slice", fb_d.unpinned == [PIN] and res_d2["pin_removed"] and res_d2["slice_children"] == [])
        cg_bad = Path(td) / "cg-unreadable"
        (cg_bad / "system.slice").mkdir(parents=True)
        (cg_bad / "system.slice" / "system-portalrb.slice").mkdir()
        os.chmod(cg_bad / "system.slice" / "system-portalrb.slice", 0)
        fb_e = FakeBpf()
        try:
            res_e2 = await L.unprepare_host(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_e, bpf_pin=PIN, cgroup_root=str(cg_bad))
            unreadable_ok = os.geteuid() == 0 or (fb_e.unpinned == [] and res_e2["pin_kept"] and res_e2["slice_children"] is None)
        finally:
            os.chmod(cg_bad / "system.slice" / "system-portalrb.slice", 0o700)
        check("unprepare: a slice directory that cannot be read is unknown, not empty: the pin stays (fail closed)", unreadable_ok)
        fb_f = FakeBpf()
        res_f = await L.unprepare_host(run=FakeRun(tables=FakeTables()), paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_f, bpf_pin="", cgroup_root=EMPTY_CG)
        check("unprepare: bpf_pin='' means no pin is touched (not the default pin), the rest is undone", fb_f.unpinned == [] and not res_f["pin_removed"] and res_f["slice_stopped"])
        fb_g, ru_g = FakeBpf(), FakeRun(tables=FakeTables())
        fb_g.unpin = lambda path, _u=fb_g.unpinned, _r=ru_g: (_u.append((path, len(_r.texts()))), True)[1]
        await L.unprepare_host(run=ru_g, paths=paths, mountinfo="", units_left=0, which=which_all, dropin_dir=none_dir, bpf=fb_g, bpf_pin=PIN, cgroup_root=EMPTY_CG)
        check("unprepare: the pin is removed after the slice stop, the last command", fb_g.unpinned and fb_g.unpinned[0][1] == len(ru_g.texts()) and ru_g.texts()[-1].endswith("stop system-portalrb.slice"), str(ru_g.texts()[-3:]))
        check("slice_children: lists only directories, never a link; [] without the slice",
              L.slice_children(str(cg_busy)) == ["portal-rbprobe-0123456789ab.service"] and L.slice_children(EMPTY_CG) == [])
        import inspect as _insp
        _usrc = _insp.getsource(L.unprepare_host) + _insp.getsource(L.remove_slice_dropins)
        check("unprepare: the source never names the revert verb as an argument", '"revert"' not in _usrc and "'revert'" not in _usrc)


asyncio.run(host_tests())
check("the property names unprepare matches are exactly the ones slice_properties sets",
      [x.split("=")[0] for x in L.slice_properties(CFG, 4, 15 * GIB)] == list(L.SLICE_PROPERTY_NAMES))
check("is_own_dropin: assignments of our properties, comments, blank lines and [Slice] only",
      L.is_own_dropin("# c\n\n[Slice]\nCPUQuota=250%\n") and not L.is_own_dropin("") and not L.is_own_dropin("[Slice]\n")
      and not L.is_own_dropin("[Slice]\nCPUQuota=1%\nIOWeight=5\n") and not L.is_own_dropin("[Service]\nCPUQuota=1%\n") and not L.is_own_dropin("CPUQuotaX=1\n"))
check("parse_mountinfo: mount point and type, octal escapes decoded",
      L.parse_mountinfo("36 35 0:30 / /run/portal\\040rb rw,nosuid - tmpfs portal-rb rw,size=8192k\n") == {"/run/portal rb": "tmpfs"})
check("parse_meminfo: MemTotal in bytes", L.parse_meminfo("MemTotal:       15728640 kB\nMemFree: 1 kB\n") == 15728640 * 1024)


# ---------------------------------------------------------------- 8.2 availability
def probe(**over):
    files = {"/proc/sys/user/max_user_namespaces": "63778\n", "/proc/sys/kernel/unprivileged_userns_clone": "1\n"}
    exists = {"/run/systemd/system", "/sys/fs/cgroup/cgroup.controllers", "/usr/bin/python3", "/proc/sys/kernel/unprivileged_userns_clone"}
    tools = {"systemd-run", "systemctl", "mount", "chromium", "Xvfb", "x11vnc", "xauth", "xrandr", "xsel", "iptables", "ip6tables"}
    kw = dict(euid=lambda: 0, exists=lambda p: p in exists, which=lambda n: "/usr/bin/" + n if n in tools else "",
              read=lambda p: files.get(p, ""), realpath=lambda p: "/usr/lib/chromium/chromium", mtime=lambda p: 1_000_000.0,
              now=lambda: 1_000_000.0 + 86400 * 10 + 5, systemd_version=lambda: 252, chromium_version=lambda n: "156.0.8078.108",
              read_head=lambda p: b"\x7fELF", bpf_available=lambda: (True, ""))
    ctl = over.pop("_ctl", None)
    if ctl:
        ctl(files, exists, tools)
    kw.update(over)
    return L.HostProbe(**kw)


ok = L.availability(probe=probe())
check("availability: a complete host is available", ok["available"] and not ok["missing"] and not ok["reasons"], str(ok))
check("availability: version, age in days, upload limit and paths",
      ok["chromium_version"] == "156.0.8078.108" and ok["chromium_age_days"] == 10 and ok["kernel_upload_limit"]
      and ok["paths"]["chromium"] == "/usr/bin/chromium")
check("availability: shape has exactly the documented keys",
      set(ok) == {"available", "missing", "reasons", "chromium_version", "chromium_age_days", "kernel_upload_limit", "paths"})
_c1 = L.availability(stage_mode=False)
_c2 = L.availability(stage_mode=True)
check("availability cache is keyed on stage_mode (file reads only)", "stage" in _c2["reasons"][0] and _c2 is not _c1 and L.availability(stage_mode=True) is _c2)
a = L.availability(stage_mode=True, probe=probe())
check("availability: stage mode is never available", not a["available"] and "stage" in a["reasons"][0])
a = L.availability(probe=probe(euid=lambda: 1000))
check("availability: not root: that is the only reason and there is no package line", not a["available"] and a["reasons"] == ["the portal does not run as root"] and a["missing"] == [])
a = L.availability(probe=probe(_ctl=lambda f, e, t: t.discard("Xvfb")))
check("availability: Xvfb missing is named", not a["available"] and "Xvfb" in a["missing"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: (t.discard("chromium"))))
check("availability: no chromium", not a["available"] and "chromium" in a["missing"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: (t.discard("chromium"), t.add("chromium-browser"))))
check("availability: chromium-browser is the second choice", a["available"] and a["paths"]["chromium"] == "/usr/bin/chromium-browser")
a = L.availability(probe=probe(which=lambda n: "/snap/bin/chromium" if n == "chromium" else "/usr/bin/" + n))
check("availability: a /snap/ path is refused", not a["available"] and "snap" in " ".join(a["reasons"]) and a["paths"]["chromium"] == "")
a = L.availability(probe=probe(realpath=lambda p: "/snap/chromium/current/chrome"))
check("availability: a link that resolves into /snap/ is refused", not a["available"])
a = L.availability(probe=probe(read_head=lambda p: b"#!/bin/sh\nexec /snap/bin/chromium\n"))
check("availability: the Debian/Ubuntu snap stub script is refused", not a["available"])
a = L.availability(probe=probe(systemd_version=lambda: 248))
check("availability: systemd 248 is too old", not a["available"] and "248" in " ".join(a["reasons"]))
a = L.availability(probe=probe(systemd_version=lambda: 249))
check("availability: systemd 249 is enough", a["available"])
a = L.availability(probe=probe(systemd_version=lambda: None))
check("availability: an unreadable systemd version makes it unavailable, with the reason", not a["available"] and "could not be read" in " ".join(a["reasons"]))
a = L.availability(probe=probe(chromium_version=lambda n: ""))
check("availability: an unknown Chromium version does not block", a["available"] and a["chromium_version"] == "")
a = L.availability(probe=probe(_ctl=lambda f, e, t: e.discard("/sys/fs/cgroup/cgroup.controllers")))
check("availability: no cgroup v2", not a["available"] and "cgroup" in " ".join(a["reasons"]))
a = L.availability(probe=probe(_ctl=lambda f, e, t: e.discard("/run/systemd/system")))
check("availability: not systemd", not a["available"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: f.update({"/proc/sys/user/max_user_namespaces": "0\n"})))
check("availability: max_user_namespaces 0", not a["available"] and "namespaces" in " ".join(a["reasons"]))
a = L.availability(probe=probe(_ctl=lambda f, e, t: f.update({"/proc/sys/kernel/unprivileged_userns_clone": "0\n"})))
check("availability: unprivileged_userns_clone 0 (where the file exists)", not a["available"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: e.discard("/proc/sys/kernel/unprivileged_userns_clone")))
check("availability: a missing unprivileged_userns_clone file is fine", a["available"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: t.discard("iptables")))
check("availability (D1): no iptables does NOT make the feature unavailable; only the upload limit key says so",
      a["available"] and a["missing"] == [] and not a["reasons"] and not a["kernel_upload_limit"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: (t.discard("ip6tables"), t.discard("iptables"))))
check("availability (D1): neither firewall tool: still available, no upload limit", a["available"] and not a["kernel_upload_limit"] and a["missing"] == [])
check("availability (D1): the packages of the two tools are still known to the apt line", L.apt_line(["iptables", "ip6tables"]).count("iptables") == 1)
a = L.availability(probe=probe(bpf_available=lambda: (False, "the bpf file system is not mounted")))
check("availability (D1): the ingress filter check is part of it: unavailable, with its reason, no missing package",
      not a["available"] and a["reasons"] == ["ingress filter: the bpf file system is not mounted"] and a["missing"] == [])
def _boom():
    raise OSError("x")
a = L.availability(probe=probe(bpf_available=_boom))
check("availability (D1): a bpf check that raises is a refusal", not a["available"] and a["reasons"] == ["ingress filter: OSError"])
a = L.availability(probe=probe(euid=lambda: 1000, bpf_available=lambda: (False, "needs root")))
check("availability: not root still answers with that one reason first and returns", a["reasons"] == ["the portal does not run as root"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: e.discard("/usr/bin/python3")))
check("availability: no python3", not a["available"] and "python3" in a["missing"])
a = L.availability(probe=probe(_ctl=lambda f, e, t: (t.discard("systemd-run"), t.discard("mount"))))
check("availability: systemd-run and mount are required", not a["available"] and {"systemd-run", "mount"} <= set(a["missing"]))
a = L.availability(probe=probe(_ctl=lambda f, e, t: t.discard("xsel")))
check("availability: xsel is required (the clip request needs it), no window manager package is", not a["available"] and "xsel" in a["missing"]
      and "xsel" in L.PACKAGE_OF and "matchbox-window-manager" not in L.PACKAGE_OF and ok["available"] and "wm" not in ok["paths"])
check("apt_line names the packages and omits unknown ones",
      L.apt_line(["Xvfb", "xrandr", "xrandr", "systemctl"]) == "apt-get install -y --no-install-recommends xvfb x11-xserver-utils" and L.apt_line(["systemctl"]) == "")
_lsrc = (ROOT / "rbrowser_launch.py").read_text()
check("availability() starts no process: the module has no blocking subprocess call",
      not re.search(r"import subprocess|subprocess\.(run|Popen|call|check_output|check_call)|os\.popen|os\.system", _lsrc))
v = L._systemd_version_from_files()
check("systemd version reader returns an int or None on this host", v is None or isinstance(v, int))

# ---------------------------------------------------------------- parsers
SHOW = """Id=portal-rb-0123456789ab.service
ActiveState=active
ExecMainStatus=0
MainPID=4242
ControlGroup=/system.slice/system-portalrb.slice/portal-rb-0123456789ab.service
IPIngressBytes=100
IPEgressBytes=200

Id=portal-rb-aaaaaaaaaaaa.service
ActiveState=inactive
MainPID=0
"""
ps = L.parse_show(SHOW)
check("parse_show: blocks keyed by Id", set(ps) == {"portal-rb-0123456789ab.service", "portal-rb-aaaaaaaaaaaa.service"}
      and ps["portal-rb-0123456789ab.service"]["MainPID"] == "4242" and ps["portal-rb-aaaaaaaaaaaa.service"]["ActiveState"] == "inactive")
check("parse_show: empty and junk text", L.parse_show("") == {} and L.parse_show("nonsense") == {})
CG = "0::/system.slice/system-portalrb.slice/portal-rb-0123456789ab.service\n"
check("parse_proc_cgroup: the path after 0:: equals ControlGroup",
      L.parse_proc_cgroup(CG) == ps["portal-rb-0123456789ab.service"]["ControlGroup"])
check("parse_proc_cgroup: hybrid and empty input", L.parse_proc_cgroup("12:cpu:/x\n0::/a/b\n") == "/a/b" and L.parse_proc_cgroup("12:cpu:/x\n") == "" and L.parse_proc_cgroup("") == "")
check("parse_status_uid: the effective uid", L.parse_status_uid("Name:\tpython3\nUid:\t64748\t64748\t64748\t64748\nGid:\t1\n") == 64748
      and L.parse_status_uid("Uid:\t1\t0\t0\t0\n") == 0 and L.parse_status_uid("junk") is None)


# ---------------------------------------------------------------- the launcher
class Host:
    """A fake systemd: show answers MainPID 0 for a few polls, then the pid; /proc files in a dict."""

    def __init__(self, polls_before=3, uid=64748, state="active", script=None):
        self.script = script           # [(ActiveState, MainPID)] one entry per show poll, the last repeats
        self.uid_reads = []
        self.calls = []
        self.polls = 0
        self.polls_before = polls_before
        self.proc = {"/proc/4242/status": f"Name:\tpython3\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n", "/proc/4242/cgroup": CG}
        self.state = state
        self.sleeps = []
        self.sysrun_rc = 0
        self.stopped = False           # a `systemctl stop` that worked ended the unit
        self.stop_rc = 0               # 124 = the stop timed out (the unit is not ended by it)
        self.stop_works = True         # False: the unit stays active through every stop
        self.kill_helps = True         # a SIGKILL makes the next stop work
        self.killed = False
        self.show_rc = 0               # != 0: systemctl show answers nothing
        self.sysrun_exc = None         # an exception the systemd-run call raises (a cancellation)

    async def run(self, argv, timeout=10.0):
        self.calls.append((list(argv), timeout))
        base = os.path.basename(argv[0])
        if base == "systemd-run":
            if self.sysrun_exc is not None:
                raise self.sysrun_exc
            return L.Ran(self.sysrun_rc)
        if base == "systemctl" and argv[1] == "stop":
            if self.stop_rc == 124 and not self.killed:
                return L.Ran(124, "", "timeout")
            if self.stop_works or (self.killed and self.kill_helps):
                self.stopped = True
            return L.Ran(self.stop_rc if not self.stopped else 0)
        if base == "systemctl" and argv[1] == "kill":
            self.killed = True
            return L.Ran(0)
        if base == "systemctl" and argv[1] == "show":
            if self.show_rc:
                return L.Ran(self.show_rc)
            if self.stopped:
                return L.Ran(0, f"Id={argv[-1]}\nActiveState=inactive\nMainPID=0\nControlGroup=\n")
            self.polls += 1
            unit = argv[-1]
            if self.script:
                st, pid = self.script[min(self.polls, len(self.script)) - 1]
                self.last_state = st
            else:
                st = self.state
                pid = 4242 if self.polls > self.polls_before else 0
                self.last_state = st
            return L.Ran(0, f"Id={unit}\nActiveState={st}\nMainPID={pid}\nControlGroup={CG[3:-1] if pid else ''}\n")
        return L.Ran(0)

    async def sleep(self, s):
        self.sleeps.append(s)

    def reader(self, p):
        if p == "/proc/4242/status":
            self.uid_reads.append(getattr(self, "last_state", ""))
            if self.script and getattr(self, "last_state", "") != "active":
                return "Uid:\t0\t0\t0\t0\n"      # still root while the unit is activating
        return self.proc.get(p, "")


async def launcher_tests():
    h = Host()
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    res = await ln.start(spec())
    sysrun = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"]
    check("start: one systemd-run call, argument list, the program first, the builder's list after",
          len(sysrun) == 1 and sysrun[0][0] == "/usr/bin/systemd-run" and sysrun[0][1:] == BA(spec()), str(sysrun[0][:3]))
    check("start: no shell anywhere", all(os.path.basename(c[0]) not in ("sh", "bash", "dash") and "-c" not in c[:2] for c, _ in h.calls))
    check("start: waits (injected sleep) until MainPID is set, three empty polls first", h.polls == 4 and h.sleeps == [0.1] * 3, f"{h.polls} {h.sleeps}")
    check("start: result has the .service name, runtime dir, dynamic uid, cgroup equal to ControlGroup, pid",
          res.unit == "portal-rb-0123456789ab.service" and res.runtime_dir == "/run/portal-rb/s-0123456789ab" and res.expect_uid == 64748
          and res.expect_cgroup == "/system.slice/system-portalrb.slice/portal-rb-0123456789ab.service" and res.main_pid == 4242)
    check("start: expect_cgroup equals what cgroup_of(pid) reads from /proc", ln.cgroup_of(4242) == res.expect_cgroup)
    check("start: the systemd-run call has a timeout of 10 s", all(t == 10.0 for c, t in h.calls if os.path.basename(c[0]) == "systemd-run"))
    # the ingress filter (D1): checked right after the start against the unit's cgroup, fail closed
    fb_ok = ln._bpf
    check("start: the filter is looked up once, in the unit's cgroup under /sys/fs/cgroup, with the pin the launcher was given",
          fb_ok.asked == [("/sys/fs/cgroup" + res.expect_cgroup, PIN)], str(fb_ok.asked))
    check("start: the LaunchResult carries the pin (the registry keeps it for prune_stale)", res.ingress_pin == PIN and rbrowser.FakeLauncher.sweep_tmp(None, []) == [])
    check("start: the pin reaches the unit as IPIngressFilterPath", f"IPIngressFilterPath={PIN}" in props(sysrun[0]))
    for label, fbx in (("is not attached", FakeBpf(attach=False)), ("check raises", FakeBpf(fail_with="BPF_PROG_QUERY: EPERM"))):
        hx = Host()
        lnx2 = LN(run=hx.run, read_text=hx.reader, sleep=hx.sleep, which=which_all, bpf=fbx)
        check(f"start: the filter {label}: LaunchError and the unit is stopped", await _raises_async(LaunchError, lnx2.start(spec()))
              and any(c[1:3] == ["stop", "portal-rb-0123456789ab.service"] for c, _ in hx.calls) and len(fbx.asked) == 1)
    h0b = Host(uid=0)
    fb0 = FakeBpf()
    await _raises_async(LaunchError, LN(run=h0b.run, read_text=h0b.reader, sleep=h0b.sleep, which=which_all, bpf=fb0).start(spec()))
    check("start: a root unit is refused before the filter is asked", fb0.asked == [])
    for pin_bad in (None, "", "/tmp/portal-rb-x", "/sys/fs/bpf/other", "/sys/fs/bpf/portal-rb/../x", "/sys/fs/bpf/portal-rb x", "/sys/fs/bpf/portal-rb\nx"):
        hq = Host()
        lq = L.SystemdLauncher(run=hq.run, read_text=hq.reader, sleep=hq.sleep, which=which_all, ingress_pin=pin_bad, bpf=FakeBpf(), theme_dir=THEMED, static_dir=STATICD)
        check(f"start without a usable pin ({pin_bad!r}): LaunchError and no systemd-run call at all",
              await _raises_async(LaunchError, lq.start(spec())) and not any(os.path.basename(c[0]) == "systemd-run" for c, _ in hq.calls))
    check("build_unit_args has no default pin: a unit without the filter cannot be built",
          raises(TypeError, L.build_unit_args, spec()) and raises(LaunchError, L.build_unit_args, spec(), ingress_pin="")
          and raises(LaunchError, L.build_unit_args, spec(), ingress_pin=None))
    check("build_unit_args: the pin is one -p property, after SocketBindDeny and before IPAddressDeny, on every prefix and script",
          all(props(L.build_unit_args(spec(), pre, scr, 5, ingress_pin=PIN)).index(f"IPIngressFilterPath={PIN}")
              == props(L.build_unit_args(spec(), pre, scr, 5, ingress_pin=PIN)).index("SocketBindDeny=any") + 1
              for pre, scr in ((L.UNIT_PREFIX, "session.py"), (L.PROBE_PREFIX, "probe.py"), (L.TEST_PREFIX, "session.py"))))
    # filter_attached (the registry's per-session re-check) never raises and is False for anything odd
    cg = res.expect_cgroup
    fbq = FakeBpf()
    lq2 = LN(bpf=fbq)
    check("filter_attached: True when the filter is attached, asked with the full cgroup path and the launcher's pin", lq2.filter_attached(cg) is True and fbq.asked == [("/sys/fs/cgroup" + cg, PIN)])
    check("filter_attached: another pin can be given", LN(bpf=fbq).filter_attached(cg, PIN + "x") is True and fbq.asked[-1][1] == PIN + "x")
    check("filter_attached: False when it is not attached", LN(bpf=FakeBpf(attach=False)).filter_attached(cg) is False)
    check("filter_attached: False (not an exception) when bpf(2) fails", LN(bpf=FakeBpf(fail_with="x")).filter_attached(cg) is False)
    fbn = FakeBpf()
    check("filter_attached: False without asking bpf for an empty, relative, dotted or NUL path",
          all(L.ingress_attached(c, PIN, bpf=fbn) is False for c in ("", "system.slice/x", "/a/../b", "/a\0b", None, 5)) and fbn.asked == [])
    check("filter_attached: False for a missing or bad pin without asking bpf", all(L.ingress_attached(cg, p, bpf=fbn) is False for p in (None, "", "/etc/passwd")) and fbn.asked == [])
    check("ingress_attached: the module function and the method agree", L.ingress_attached(cg, PIN, bpf=FakeBpf()) is True)
    # D6: the unit's /tmp and /var/tmp are a directory of the capped tmpfs, made before the start, removed after the stop
    d_tmp = f"{TMPD}/0123456789ab"
    ht = Host()
    ln = LN(run=ht.run, read_text=ht.reader, sleep=ht.sleep, which=which_all)
    res = await ln.start(spec())
    check("start: the unit's tmp directory exists, is 1777 and is a real directory", os.path.isdir(d_tmp) and not os.path.islink(d_tmp) and stat.S_IMODE(os.stat(d_tmp).st_mode) == 0o1777)
    open(f"{d_tmp}/left-by-the-unit", "w").write("x")
    os.mkdir(f"{d_tmp}/sub")
    os.symlink("/etc", f"{d_tmp}/link-to-etc")
    await ln.stop(res.unit)
    check("stop: the tmp directory is removed with what the unit left in it, a link inside is not followed", not os.path.exists(d_tmp) and os.path.isdir("/etc"))
    os.mkdir(f"{TMPD}/aaaaaaaaaaaa"); os.mkdir(f"{TMPD}/bbbbbbbbbbbb"); os.mkdir(f"{TMPD}/not-an-id")
    check("sweep_tmp: removes the directories of units that are not live, keeps live ones and names that are no unit id",
          ln.sweep_tmp(["aaaaaaaaaaaa"]) == ["bbbbbbbbbbbb"] and os.path.isdir(f"{TMPD}/aaaaaaaaaaaa") and os.path.isdir(f"{TMPD}/not-an-id")
          and not os.path.exists(f"{TMPD}/bbbbbbbbbbbb"))
    check("remove_tmp refuses anything that is not a 12 hex id (no traversal)", (ln.remove_tmp("../x"), ln.remove_tmp("aaaaaaaaaaaa/.."), True)[2] and os.path.isdir(f"{TMPD}/aaaaaaaaaaaa"))
    hnf = Host()
    lnnf = LN(run=hnf.run, read_text=hnf.reader, sleep=hnf.sleep, which=which_all, tmp_dir=f"{TMPD}/no/such/area")
    check("start: a tmp area that does not exist (not prepared) is a LaunchError and no unit is started",
          await _raises_async(LaunchError, lnnf.start(spec())) and not any(os.path.basename(c[0]) == "systemd-run" for c, _ in hnf.calls))
    for label, mi_txt in (("not mounted at all", ""), ("a directory of another file system", f"41 30 0:40 / {TMPD} rw - ext4 /dev/sda1 rw\n"),
                          ("a tmpfs elsewhere", f"41 30 0:40 / {TMPD}x rw - tmpfs t rw\n")):
        hnm = Host()
        lnm = LN(run=hnm.run, read_text=hnm.reader, sleep=hnm.sleep, which=which_all, mountinfo=lambda _t=mi_txt: _t)
        check(f"start: a tmp area that is {label}: LaunchError, no unit started, no directory made",
              await _raises_async(LaunchError, lnm.start(spec())) and not any(os.path.basename(c[0]) == "systemd-run" for c, _ in hnm.calls)
              and not os.path.exists(f"{TMPD}/0123456789ab"))
    os.chmod(TMPD, 0o755)
    LN(run=ht.run, read_text=ht.reader, sleep=ht.sleep, which=which_all).make_tmp("0123456789ab")
    check("make_tmp: an area left 0755 by an earlier mount is put back to 0700", stat.S_IMODE(os.stat(TMPD).st_mode) == 0o700)
    LN(run=ht.run, read_text=ht.reader, sleep=ht.sleep, which=which_all).remove_tmp("0123456789ab")
    check("the tmp area is mounted 0700 and the unit's directories are not, and the cap is written down as per host",
          "mode=0700" in L.TMP_OPTIONS and "mode=0755" not in L.TMP_OPTIONS and "ONE cap for" in (ROOT / "rbrowser_launch.py").read_text())
    hr0 = Host()
    hr0.sysrun_rc = 1
    await _raises_async(LaunchError, LN(run=hr0.run, read_text=hr0.reader, sleep=hr0.sleep, which=which_all).start(spec()))
    check("start: a systemd-run that fails leaves no tmp directory behind", not os.path.exists(d_tmp))
    h0 = Host(uid=0)
    ln0 = LN(run=h0.run, read_text=h0.reader, sleep=h0.sleep, which=which_all)
    check("start: a unit whose main process is uid 0 is refused", await _raises_async(LaunchError, ln0.start(spec())))
    check("start: ... and the unit is stopped", any(c[1:3] == ["stop", "portal-rb-0123456789ab.service"] for c, _ in h0.calls))
    # never starts
    hn = Host(polls_before=10 ** 6)
    lnn = LN(run=hn.run, read_text=hn.reader, sleep=hn.sleep, which=which_all)
    check("start: gives up after the 10 s budget and stops the unit", await _raises_async(LaunchError, lnn.start(spec())) and len(hn.sleeps) == 100
          and any(c[1] == "stop" for c, _ in hn.calls))
    hs = Host(script=[("inactive", 0), ("activating", 4242), ("activating", 4242), ("active", 4242)])
    lns = LN(run=hs.run, read_text=hs.reader, sleep=hs.sleep, which=which_all)
    rs = await lns.start(spec())
    check("start: an early 'inactive' (job still queued) is not terminal; the uid is read only once the unit is active",
          rs.expect_uid == 64748 and hs.uid_reads == ["active"] and hs.polls == 4, f"{rs} {hs.uid_reads} {hs.polls}")
    ha = Host(script=[("activating", 4242)])
    lna = LN(run=ha.run, read_text=ha.reader, sleep=ha.sleep, which=which_all)
    check("start: a unit that stays 'activating' (root) until the budget ends raises and is stopped, uid never read",
          await _raises_async(LaunchError, lna.start(spec())) and ha.uid_reads == [] and len(ha.sleeps) == 100
          and any(c[1] == "stop" for c, _ in ha.calls))
    hi = Host(script=[("inactive", 0)])
    lni = LN(run=hi.run, read_text=hi.reader, sleep=hi.sleep, which=which_all)
    check("start: 'inactive' for the whole budget raises after 100 polls", await _raises_async(LaunchError, lni.start(spec())) and len(hi.sleeps) == 100)
    hd = Host(script=[("activating", 4242), ("inactive", 0)])
    lnd = LN(run=hd.run, read_text=hd.reader, sleep=hd.sleep, which=which_all)
    check("start: 'inactive' after 'activating' is terminal at once", await _raises_async(LaunchError, lnd.start(spec())) and len(hd.sleeps) == 1)
    hf = Host(state="failed")
    lnf = LN(run=hf.run, read_text=hf.reader, sleep=hf.sleep, which=which_all)
    check("start: a unit that failed while starting raises at once", await _raises_async(LaunchError, lnf.start(spec())) and hf.sleeps == [])
    hr = Host()
    hr.sysrun_rc = 1
    lnr = LN(run=hr.run, read_text=hr.reader, sleep=hr.sleep, which=which_all)
    err = None
    try:
        await lnr.start(spec())
    except LaunchError as e:
        err = str(e)
    check("start: a failing systemd-run raises without echoing the command (no URL in the message)", err and "duckduckgo" not in err and "http" not in err, str(err))
    lnx = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=lambda n: "")
    check("start: systemd-run not found raises", await _raises_async(LaunchError, lnx.start(spec())))
    # prefixes
    hp = Host()
    lp = LN(L.PROBE_PREFIX, run=hp.run, read_text=hp.reader, sleep=hp.sleep, script="probe.py", nice=19, which=which_all)
    rp = await lp.start(spec())
    sp = [c for c, _ in hp.calls if os.path.basename(c[0]) == "systemd-run"][0]
    check("probe launcher: unit portal-rbprobe-<hex>.service, probe.py, Nice=19",
          rp.unit == "portal-rbprobe-0123456789ab.service" and "--unit=portal-rbprobe-0123456789ab" in sp and sp[-1] == "/mnt/probe.py" and "Nice=19" in sp)
    check("an unknown launcher prefix raises", raises(LaunchError, L.SystemdLauncher, "portal-rb2-"))
    # name checks on stop and show
    h2 = Host()
    l2 = LN(run=h2.run, read_text=h2.reader, sleep=h2.sleep, which=which_all)
    for bad in ("portal.service", "portal-rb-0123456789ab", "portal-rbprobe-0123456789ab.service", "portal-rbtest-0123456789ab.service",
                "portal-rb-0123456789AB.service", "portal-rb-0123456789a.service", "portal-rb-0123456789abc.service",
                "portal-rb-*.service", "x portal-rb-0123456789ab.service", "portal-rb-0123456789ab.service\n", "ffmpeg", "", None, "mediamtx.service"):
        check(f"stop refuses {bad!r}", await _raises_async(LaunchError, l2.stop(bad)))
        check(f"show refuses {bad!r}" if bad != "portal-rb-*.service" else "show allows the launcher's own glob",
              (await _raises_async(LaunchError, l2.show([bad]))) == (bad != "portal-rb-*.service"))
    check("no systemctl call was made for a refused name", not any(c[1] in ("stop",) for c, _ in h2.calls))
    await l2.stop("portal-rb-0123456789ab.service")
    stop_calls = [x for x in h2.calls if x[0][1:2] == ["stop"]]
    check("stop: systemctl stop <unit>, an argument list with a timeout, then ActiveState is read back",
          stop_calls[-1][0][1:] == ["stop", "portal-rb-0123456789ab.service"] and stop_calls[-1][1] > 5 and h2.calls[-2][0][1] == "show"
          and h2.calls[-1][0][1] == "reset-failed")
    await l2.show(["portal-rb-0123456789ab.service", "portal-rb-aaaaaaaaaaaa.service"])
    sc = h2.calls[-1][0]
    check("show: one systemctl show call naming the properties of 8.2 and 6.4 and both units",
          sc[1] == "show" and {"-p"} <= set(sc) and all(p in sc for p in ("Id", "ActiveState", "ExecMainStatus", "ExecMainCode", "MainPID", "ControlGroup", "IPIngressBytes", "IPEgressBytes"))
          and sc[-2:] == ["portal-rb-0123456789ab.service", "portal-rb-aaaaaaaaaaaa.service"])
    await l2.show(["portal-rb-*.service"])
    check("show: the sweeper's glob is passed through", h2.calls[-1][0][-1] == "portal-rb-*.service")
    check("show of nothing is empty and runs nothing", await l2.show([]) == {})
    lt = LN(L.TEST_PREFIX, run=h2.run, read_text=h2.reader, sleep=h2.sleep, which=which_all)
    check("the test launcher refuses a session-pattern unit and the session launcher refuses a test unit",
          await _raises_async(LaunchError, lt.stop("portal-rb-0123456789ab.service")) and await _raises_async(LaunchError, l2.stop("portal-rbtest-0123456789ab.service")))
    check("Launcher protocol methods exist on SystemdLauncher and FakeLauncher",
          all(hasattr(c, m) for c in (L.SystemdLauncher, rbrowser.FakeLauncher) for m in ("start", "stop", "show", "cgroup_of")))
    check("start, stop and show are coroutines", all(asyncio.iscoroutinefunction(getattr(L.SystemdLauncher, m)) for m in ("start", "stop", "show")))


async def _raises_async(exc, coro):
    try:
        await coro
    except exc:
        return True
    except Exception as e:
        print("   unexpected", type(e).__name__, e)
        return False
    return False


asyncio.run(launcher_tests())


# ---------------------------------------------------------------- stop() is confirmed, a failed start takes its unit back (fix pass 1)
async def stop_safety_tests():
    UNIT = "portal-rb-0123456789ab.service"

    def calls_of(h, verb):
        return [c for c, _ in h.calls if c[1:2] == [verb]]
    # a stop that works: stop, then show, no kill
    h = Host()
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    ln.make_tmp("0123456789ab")
    await ln.stop(UNIT)
    check("stop: a stop that worked is confirmed by one show, no kill, the tmp directory goes",
          [c[1] for c, _ in h.calls] == ["stop", "show", "reset-failed"] and not os.path.exists(f"{TMPD}/0123456789ab") and UNIT not in ln.unstopped)
    # rc 124 (the stop timed out): SIGKILL, a second stop, then it is confirmed
    h = Host()
    h.stop_rc = 124
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    ln.make_tmp("0123456789ab")
    await ln.stop(UNIT)
    seq = [c[1] for c, _ in h.calls]
    check("stop: systemctl stop that times out (rc 124): the unit is shown, killed with SIGKILL, stopped again and shown gone",
          seq == ["stop", "show", "kill", "stop", "show", "reset-failed"] and calls_of(h, "kill")[0][2:] == ["-s", "SIGKILL", UNIT]
          and not os.path.exists(f"{TMPD}/0123456789ab"), str(seq))
    # the unit is still active after the kill and the second stop: a distinct error, the unit is remembered, its tmp directory stays
    h = Host()
    h.stop_works = False
    h.kill_helps = False
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    ln.make_tmp("0123456789ab")
    err = None
    try:
        await ln.stop(UNIT)
    except UnitLeftRunning as e:
        err = e
    check("stop: a unit still active after the kill and a second stop raises UnitLeftRunning (a LaunchError) naming the unit",
          err is not None and err.unit == UNIT and isinstance(err, LaunchError) and UNIT in ln.unstopped and "http" not in str(err))
    check("stop: ... and its tmp directory is not removed (the unit still has it mounted)", os.path.isdir(f"{TMPD}/0123456789ab"))
    h.stop_works = True
    await ln.stop(UNIT)
    check("stop: a later stop that works takes the unit off the unstopped list", UNIT not in ln.unstopped and not os.path.exists(f"{TMPD}/0123456789ab"))
    # T1: reset_failed
    check("T1: SystemdLauncher has an awaitable reset_failed", asyncio.iscoroutinefunction(L.SystemdLauncher.reset_failed))
    h = Host()
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    await ln.reset_failed(UNIT)
    rf = [(c, t) for c, t in h.calls if c[1:2] == ["reset-failed"]]
    check("T1: reset_failed runs `systemctl reset-failed <unit>` as an argument list with its own time limit",
          len(rf) == 1 and rf[0][0] == ["/usr/bin/systemctl", "reset-failed", UNIT] and rf[0][1] == L.RESET_FAILED_TIMEOUT, str(rf))

    class HNoUnit(Host):
        async def run(self, argv, timeout=10.0):
            if argv[1:2] == ["reset-failed"]:
                self.calls.append((list(argv), timeout))
                return L.Ran(5, "", "Unit not loaded.")
            return await super().run(argv, timeout)
    hn = HNoUnit()
    ln = LN(run=hn.run, read_text=hn.reader, sleep=hn.sleep, which=which_all)
    check("T1: reset_failed of a unit that is not loaded (an error answer) raises nothing", await ln.reset_failed(UNIT) is None)

    class HBoom(Host):
        async def run(self, argv, timeout=10.0):
            if argv[1:2] == ["reset-failed"]:
                raise OSError("no systemctl")
            return await super().run(argv, timeout)
    hb = HBoom()
    ln = LN(run=hb.run, read_text=hb.reader, sleep=hb.sleep, which=which_all)
    check("T1: reset_failed swallows an exception of the runner", await ln.reset_failed(UNIT) is None)

    class HHang(Host):
        async def run(self, argv, timeout=10.0):
            if argv[1:2] == ["reset-failed"]:
                await asyncio.sleep(30)
            return await super().run(argv, timeout)
    hg = HHang()
    ln = LN(run=hg.run, read_text=hg.reader, sleep=hg.sleep, which=which_all)
    tk = asyncio.ensure_future(ln.reset_failed(UNIT))
    await asyncio.sleep(0.02)
    tk.cancel()
    check("T1: a cancellation is not swallowed by reset_failed", (await asyncio.gather(tk, return_exceptions=True))[0].__class__ is asyncio.CancelledError)
    check("T1: reset_failed refuses a name that is not a unit of this launcher, and runs nothing for it",
          await _raises_async(LaunchError, ln.reset_failed("portal-rbtest-0123456789ab.service"))
          and await _raises_async(LaunchError, ln.reset_failed("sshd.service")) and await _raises_async(LaunchError, ln.reset_failed("portal-rb-*.service")))
    # T1: the start path resets a unit it saw `failed`; show() itself never resets (the registry reads a failed unit's exit status)
    h = Host(script=[("activating", 0), ("failed", 0)])
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    check("T1: start: a unit seen `failed` raises LaunchError and is reset-failed",
          await _raises_async(LaunchError, ln.start(spec())) and any(c[1:3] == ["reset-failed", UNIT] for c, _ in h.calls), str([c[1:] for c, _ in h.calls]))
    h = Host()
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    await ln.show([UNIT])
    check("T1: show() never resets", not any(c[1:2] == ["reset-failed"] for c, _ in h.calls))
    # systemd does not answer: unknown is not stopped
    h = Host()
    h.show_rc = 1
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    check("stop: when `systemctl show` gives no answer the unit counts as still running (fail closed)", await _raises_async(UnitLeftRunning, ln.stop(UNIT)))
    # a unit in 'deactivating' is not gone
    class HDeact(Host):
        async def run(self, argv, timeout=10.0):
            r = await super().run(argv, timeout)
            if argv[1] == "show":
                r.out = f"Id={argv[-1]}\nActiveState=deactivating\nMainPID=1\n"
            return r
    hd = HDeact()
    check("stop: 'deactivating' is not gone", await _raises_async(UnitLeftRunning, LN(run=hd.run, read_text=hd.reader, sleep=hd.sleep, which=which_all).stop(UNIT)))
    # start(): the filter is not attached and the stop times out: the caller gets UnitLeftRunning, not the plain error
    h = Host()
    h.stop_works = False
    h.kill_helps = False
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all, bpf=FakeBpf(attach=False))
    check("start: the filter is not attached and the unit cannot be stopped: UnitLeftRunning (the registry must keep the name), unit in .unstopped",
          await _raises_async(UnitLeftRunning, ln.start(spec())) and UNIT in ln.unstopped)
    # start(): systemd-run timed out (rc 124) after the job was queued: the unit is stopped all the same, the tmp directory goes
    h = Host()
    h.sysrun_rc = 124
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    ok = await _raises_async(LaunchError, ln.start(spec()))
    check("start: systemd-run rc 124 raises LaunchError and still stops the unit (it may have been queued), shown gone, tmp directory removed",
          ok and len(calls_of(h, "stop")) == 1 and calls_of(h, "stop")[0][2] == UNIT and not os.path.exists(f"{TMPD}/0123456789ab"))
    # start(): cancelled while systemd-run runs: the unit is stopped, the cancellation goes through
    h = Host()
    h.sysrun_exc = asyncio.CancelledError()
    ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all)
    cancelled = False
    try:
        await ln.start(spec())
    except asyncio.CancelledError:
        cancelled = True
    check("start: a cancellation during systemd-run still stops the unit, and is re-raised as a cancellation", cancelled and len(calls_of(h, "stop")) == 1)
    # start(): a second cancellation during the clean-up stop does not abandon the stop
    class HSlow(Host):
        def __init__(self):
            super().__init__()
            self.gate = asyncio.Event()
        async def run(self, argv, timeout=10.0):
            if argv[1:2] == ["stop"]:
                self.calls.append((list(argv), timeout))
                await self.gate.wait()
                self.stopped = True
                return L.Ran(0)
            return await super().run(argv, timeout)
    hs = HSlow()
    hs.sysrun_rc = 1
    ln = LN(run=hs.run, read_text=hs.reader, sleep=hs.sleep, which=which_all)
    task = asyncio.ensure_future(ln.start(spec()))
    await asyncio.sleep(0.05)               # the clean-up stop is now waiting on the gate
    task.cancel()
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.sleep(0.05)
    still_waiting = not task.done()
    hs.gate.set()
    for _ in range(50):
        if task.done():
            break
        await asyncio.sleep(0.02)
    check("start: cancelled again while the clean-up stop runs: the stop is awaited to its end (show read afterwards), then the cancellation is raised",
          still_waiting and task.done() and task.cancelled() and [c[1] for c, _ in hs.calls if c[0].endswith("systemctl")][-3:] == ["stop", "show", "reset-failed"]
          and not ln._cleanups, str([c[1] for c, _ in hs.calls]))
    # fix pass 2: a stop() cancelled part way leaves the unit on `unstopped` (the unit is added before the first systemctl call)
    class HCut(Host):
        """Blocks forever in the systemctl call whose verb is `cut_at` (the n-th time it is made), so that a caller can cancel there."""
        def __init__(self, cut_at, nth=1):
            super().__init__()
            self.cut_at, self.nth, self.seen = cut_at, nth, 0
            self.stop_works = False      # the first stop does not end the unit, so the kill and the second stop follow
            self.kill_helps = True
            self.reached = asyncio.Event()
        async def run(self, argv, timeout=10.0):
            if argv[1:2] == [self.cut_at]:
                self.seen += 1
                if self.seen == self.nth:
                    self.calls.append((list(argv), timeout))
                    self.reached.set()
                    await asyncio.Event().wait()
            return await super().run(argv, timeout)
    for what, verb, nth in (("the first systemctl stop", "stop", 1), ("the kill", "kill", 1), ("the second systemctl stop", "stop", 2)):
        hc = HCut(verb, nth)
        ln = LN(run=hc.run, read_text=hc.reader, sleep=hc.sleep, which=which_all)
        ln.make_tmp("0123456789ab")
        t = asyncio.ensure_future(ln.stop(UNIT))
        await asyncio.wait_for(hc.reached.wait(), 5)
        listed_while_running = UNIT in ln.unstopped
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
        check(f"stop: cancelled during {what}: the unit is in .unstopped (and was while the call ran) and its tmp directory stays",
              listed_while_running and UNIT in ln.unstopped and os.path.isdir(f"{TMPD}/0123456789ab") and t.cancelled())
        hc.cut_at = "none"
        hc.stop_works = True
        await ln.stop(UNIT)
        check(f"stop: ... a later stop that confirms the unit gone takes it off the list (after a cancel during {what})",
              UNIT not in ln.unstopped and not os.path.exists(f"{TMPD}/0123456789ab"))
    # a caller's wait_for (the portal's bounded shutdown stop) is the same thing
    hc = HCut("kill")
    ln = LN(run=hc.run, read_text=hc.reader, sleep=hc.sleep, which=which_all)
    try:
        await asyncio.wait_for(ln.stop(UNIT), 0.3)
    except asyncio.TimeoutError:
        pass
    check("stop: a wait_for that times out in the kill step leaves the unit in .unstopped", UNIT in ln.unstopped)
    # the source: nothing between the tmp directory and the try
    import inspect as _i
    ssrc = _i.getsource(L.SystemdLauncher.start)
    check("start: systemd-run runs inside the try that takes the unit back", ssrc.index("try:") < ssrc.index("await self._run([sysrun]") < ssrc.index("_take_back"))


from rbrowser import UnitLeftRunning  # noqa: E402
asyncio.run(stop_safety_tests())

# ---------------------------------------------------------------- fix pass 2 (F1): the host's mount namespace
async def _raises_here(exc, coro):
    try:
        await coro
    except exc:
        return True
    return False


async def namespace_tests():
    with tempfile.TemporaryDirectory() as td:
        paths = L.HostPaths(static=f"{td}/static", run_dir=f"{td}/run", state=f"{td}/state", tmp_dir=f"{td}/tmp")
        src = unit_src(td)
        MI_RUN = f"42 30 0:41 / {td}/run rw - tmpfs portal-rb rw\n"
        MI_TMP = f"41 30 0:40 / {td}/tmp rw - tmpfs portal-rb-tmp rw\n"
        dev = {f"{td}/run": "0:41", f"{td}/tmp": "0:40"}
        # the host table is read from PID 1's file, never from this process's: the source says so
        lsrc = (ROOT / "rbrowser_launch.py").read_text()
        check("F1: no code reads /proc/self/mountinfo (the portal's own, private table); PID 1's is the one", "/proc/self/mountinfo" not in lsrc
              and L.HOST_MOUNTINFO == "/proc/1/mountinfo")
        # a table that is read live: empty before the mount, the host's entries after it (the mount reached PID 1 and this process)
        state = {"mounted": 0}

        def live_table():
            return "" + (MI_RUN if state["mounted"] >= 1 else "") + (MI_TMP if state["mounted"] >= 2 else "")

        class RunMounts(FakeRun):
            async def __call__(self, argv, timeout=10.0):
                r = await super().__call__(argv, timeout)
                if " -t tmpfs " in " ".join(argv) and r.rc == 0:
                    state["mounted"] += 1
                return r
        r1 = RunMounts(tables=FakeTables())
        res = await PH(CFGH, policy=POLICY, run=r1, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=live_table, source_dir=src, which=which_all, want_dev_of=dev.get)
        check("F1: a mount that is visible in PID 1's table after the helper ran, with the same device here: ok", res["ok"], str(res["reasons"]))
        # the helper reports success but PID 1's table does not show the mount (it went to a private namespace): not ok, nothing else done
        r2 = FakeRun(tables=FakeTables())
        res = await PH(CFGH, policy=POLICY, run=r2, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=lambda: "", source_dir=src, which=which_all, want_dev_of=dev.get)
        check("F1: the helper says ok but the host's table has no such mount: not ok, with a reason, and the slice and the firewall are not touched",
              not res["ok"] and any("not mounted in the host's namespace" in x for x in res["reasons"]) and not any("set-property" in x or "tables" in x for x in r2.texts()), str(res["reasons"]))
        # the mount is in the host's table but this process sees another directory there (a stale private mount, or no propagation)
        r3 = FakeRun(tables=FakeTables())
        res = await PH(CFGH, policy=POLICY, run=r3, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=lambda: MI_RUN + MI_TMP, source_dir=src, which=which_all,
                       want_dev_of=lambda p: "0:99")
        check("F1: a directory here whose device is not the host's tmpfs is refused (no mount is made over an existing one)",
              not res["ok"] and any("did not reach this namespace" in x for x in res["reasons"]) and not any(" -t tmpfs " in x for x in r3.texts()), str(res["reasons"]))
        # PID 1's table cannot be read: not ok, no mount (an empty answer must not be taken for 'nothing mounted')
        r4 = FakeRun(tables=FakeTables())
        res = await PH(CFGH, policy=POLICY, run=r4, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo=lambda: None, source_dir=src, which=which_all)
        check("F1: an unreadable host mount table makes the host not ok and mounts nothing", not res["ok"] and any("mount table" in x for x in res["reasons"])
              and not any(" -t tmpfs " in x for x in r4.texts()), str(res["reasons"]))
        # something other than a tmpfs in the host's table
        res = await PH(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, paths=paths,
                       mountinfo=lambda: f"1 2 0:5 / {td}/run rw - ext4 /dev/x rw\n", source_dir=src, which=which_all)
        check("F1: a non-tmpfs in the host's table is refused", not res["ok"])
        # the helper fails: not ok
        res = await PH(CFGH, policy=POLICY, run=FakeRun(rules=[(lambda t: "--wait" in t and " -t tmpfs " in t, 1)], tables=FakeTables()), ncpu=4,
                       mem_total=15 * GIB, paths=paths, mountinfo=lambda: "", source_dir=src, which=which_all)
        check("F1: a helper unit that fails (rc 1) makes the host not ok", not res["ok"] and any("could not be mounted" in x for x in res["reasons"]))
        # no systemd-run: no mount
        res = await PH(CFGH, policy=POLICY, run=FakeRun(tables=FakeTables()), ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo="", source_dir=src,
                       which=lambda n: "" if n == "systemd-run" else which_all(n))
        check("F1: without systemd-run there is no helper and no mount", not res["ok"])
        # the helper prefix is a closed list (the live test passes its own)
        check("F1: host_run takes the production prefix and the live test's, nothing else",
              await _raises_here(LaunchError, L.host_run(FakeRun(), which_all, ["/bin/true"], prefix="portal-rb-"))
              and (await L.host_run(FakeRun(), which_all, ["/bin/true"], prefix="portal-rbtest-host-")).rc == 0)
        fr = FakeRun()
        await L.host_run(fr, which_all, ["/usr/bin/umount", "/x"], prefix="portal-rbtest-host-")
        check("F1: with the test prefix the helper unit is portal-rbtest-host-<hex>", re.search(r"--unit=portal-rbtest-host-[0-9a-f]{12}\.service", fr.texts()[0]) is not None)
        # R4: a client time-out stops the helper unit by name and confirms it; one lock serialises prepare_host and unprepare_host
        class ToRun(FakeRun):
            def __init__(self, state="inactive", **kw):
                super().__init__(**kw)
                self.state = state

            async def __call__(self, argv, timeout=10.0):
                self.calls.append(list(argv))
                t = " ".join(argv)
                if "--wait" in t:
                    return L.Ran(124, "", "timeout")
                if " show " in t:
                    return L.Ran(0, f"ActiveState={self.state}\n", "")
                return L.Ran(0, "", "")
        tr = ToRun()
        r = await L.host_run(tr, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-")
        uname = re.search(r"--unit=(portal-rbtest-host-[0-9a-f]{12}\.service)", tr.texts()[0]).group(1)
        check("R4: the helper unit carries TimeoutStartSec=<timeout> next to RuntimeMaxSec", "-p TimeoutStartSec=30 -p RuntimeMaxSec=30" in tr.texts()[0])
        check("R4: after a client time-out the helper unit is stopped BY NAME and its state is read back; the answer stays rc 124 and says it was stopped",
              r.rc == 124 and f"/usr/bin/systemctl stop {uname}" in tr.texts() and f"/usr/bin/systemctl show -p ActiveState {uname}" in tr.texts()
              and tr.texts().index(f"/usr/bin/systemctl stop {uname}") < tr.texts().index(f"/usr/bin/systemctl show -p ActiveState {uname}")
              and "stopped" in r.err and "could not" not in r.err and not any("kill" in x for x in tr.texts()), str(tr.texts()))
        tr = ToRun(state="active")
        r = await L.host_run(tr, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-")
        check("R4: a helper unit that stays active after the stop gets SIGKILL and, still active, is reported as not confirmed",
              r.rc == 124 and any(" kill -s SIGKILL portal-rbtest-host-" in x for x in tr.texts()) and "could not be confirmed" in r.err, str(tr.texts()))
        tr = ToRun()
        r = await L.host_run(tr, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-")
        fr = FakeRun()
        r2 = await L.host_run(fr, which_all, ["/bin/true"], prefix="portal-rbtest-host-")
        check("R4: with no time-out nothing is stopped by name", r2.rc == 0 and not any(" stop " in x for x in fr.texts()))
        # R4: the caller cancels host_run (asyncio.wait_for, a cancelled task) while systemd-run waits: the unit is stopped and confirmed
        # BY NAME before CancelledError goes on, and the lock is still held until then (a second cancel does not cut the stop short)
        class CancelRun(FakeRun):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.waiting = asyncio.Event()
                self.log = []

            async def __call__(self, argv, timeout=10.0):
                self.calls.append(list(argv))
                t = " ".join(argv)
                if "--wait" in t:
                    self.waiting.set()
                    await asyncio.sleep(3600)
                if " stop " in t:
                    self.log.append("stop-begin")
                    await asyncio.sleep(0.05)
                    self.log.append("stop-end")
                if " show " in t:
                    return L.Ran(0, "ActiveState=inactive\n", "")
                return L.Ran(0, "", "")
        cr = CancelRun()

        async def locked_host_run():
            async with L._HOST_LOCK:
                return await L.host_run(cr, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-")

        async def later_unprepare():
            async with L._HOST_LOCK:
                cr.log.append("lock-taken-by-next")
        t1 = asyncio.ensure_future(locked_host_run())
        await cr.waiting.wait()
        t2 = asyncio.ensure_future(later_unprepare())
        await asyncio.sleep(0)
        t1.cancel()
        await asyncio.sleep(0.01)
        t1.cancel()
        res1 = (await asyncio.gather(t1, return_exceptions=True))[0]
        await t2
        cname = re.search(r"--unit=(portal-rbtest-host-[0-9a-f]{12}\.service)", cr.texts()[0]).group(1)
        check("R4: a cancelled host_run stops its helper unit BY NAME, reads the state back, and CancelledError propagates",
              isinstance(res1, asyncio.CancelledError) and f"/usr/bin/systemctl stop {cname}" in cr.texts()
              and f"/usr/bin/systemctl show -p ActiveState {cname}" in cr.texts()
              and cr.texts().index(f"/usr/bin/systemctl stop {cname}") < cr.texts().index(f"/usr/bin/systemctl show -p ActiveState {cname}"), str(cr.texts()))
        check("R4: after a cancel (even a repeated one) the lock is released only when the stop has ended, so the next caller cannot run first",
              cr.log == ["stop-begin", "stop-end", "lock-taken-by-next"], str(cr.log))
        # T3: the rc-124 path stops the helper through the same uncancellable stopper: a cancel that arrives while it runs does not cut it
        # short, the lock stays held until the stop ended, and the cancellation goes on afterwards
        class R124(FakeRun):
            def __init__(self, state="inactive", **kw):
                super().__init__(**kw)
                self.log = []
                self.state = state
                self.stopping = asyncio.Event()

            async def __call__(self, argv, timeout=10.0):
                self.calls.append(list(argv))
                t = " ".join(argv)
                if "--wait" in t:
                    return L.Ran(124, "", "timeout")
                if " stop " in t:
                    self.log.append("stop-begin")
                    self.stopping.set()
                    await asyncio.sleep(0.05)
                    self.log.append("stop-end")
                if " show " in t:
                    return L.Ran(0, f"ActiveState={self.state}\n", "")
                return L.Ran(0, "", "")
        r4 = R124()

        async def locked_host_run124():
            async with L._HOST_LOCK:
                return await L.host_run(r4, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-")

        async def later_unprepare124():
            async with L._HOST_LOCK:
                r4.log.append("lock-taken-by-next")
        u1 = asyncio.ensure_future(locked_host_run124())
        await r4.stopping.wait()
        u2 = asyncio.ensure_future(later_unprepare124())
        await asyncio.sleep(0)
        u1.cancel()
        await asyncio.sleep(0.01)
        u1.cancel()
        res124 = (await asyncio.gather(u1, return_exceptions=True))[0]
        await u2
        uname124 = re.search(r"--unit=(portal-rbtest-host-[0-9a-f]{12}\.service)", r4.texts()[0]).group(1)
        check("T3: a cancel (even a repeated one) during the rc-124 stop does not cut it short: the stop is confirmed, then the cancellation goes on",
              isinstance(res124, asyncio.CancelledError) and f"/usr/bin/systemctl show -p ActiveState {uname124}" in r4.texts(), str(r4.texts()))
        check("T3: the lock of the rc-124 path is released only when the stop has ended",
              r4.log == ["stop-begin", "stop-end", "lock-taken-by-next"], str(r4.log))
        # T3: an unconfirmed stop on the cancel path is logged with the unit name and nothing else
        import logging as _lg
        recs = []

        class Grab(_lg.Handler):
            def emit(self, record):
                recs.append(record)
        gh = Grab(level=_lg.DEBUG)
        plog = _lg.getLogger("portal")
        plog.addHandler(gh)
        try:
            cu = CancelRun()
            _orig_call = CancelRun.__call__

            async def stuck_call(self, argv, timeout=10.0):
                if " show " in " ".join(argv):
                    self.calls.append(list(argv))
                    return L.Ran(0, "ActiveState=active\n", "")
                return await _orig_call(self, argv, timeout)
            cu.__class__ = type("StuckCancelRun", (CancelRun,), {"__call__": stuck_call})
            v1 = asyncio.ensure_future(L.host_run(cu, which_all, ["/usr/bin/mount", "SECRET-ARGUMENT"], prefix="portal-rbtest-host-"))
            await cu.waiting.wait()
            v1.cancel()
            resv = (await asyncio.gather(v1, return_exceptions=True))[0]
            uname_c = re.search(r"--unit=(portal-rbtest-host-[0-9a-f]{12}\.service)", cu.texts()[0]).group(1)
            msgs = [r.getMessage() for r in recs]
            check("T3: an unconfirmed stop on the cancel path is logged once, with the unit name; the cancellation still goes on",
                  isinstance(resv, asyncio.CancelledError) and len(msgs) == 1 and uname_c in msgs[0] and recs[0].levelno >= _lg.WARNING, str(msgs))
            check("T3: the log line holds no command, argument or path", all("SECRET-ARGUMENT" not in m and "/usr/bin/mount" not in m and "mount" not in m.replace("host helper", "") for m in msgs), str(msgs))
            recs.clear()
            ok_run = CancelRun()
            v2 = asyncio.ensure_future(L.host_run(ok_run, which_all, ["/usr/bin/mount", "x"], prefix="portal-rbtest-host-"))
            await ok_run.waiting.wait()
            v2.cancel()
            await asyncio.gather(v2, return_exceptions=True)
            check("T3: a confirmed stop on the cancel path logs nothing", not recs, str([r.getMessage() for r in recs]))
        finally:
            plog.removeHandler(gh)
        order = []

        async def slow_run(argv, timeout=10.0):
            t = " ".join(argv)
            if " -t tmpfs " in t or "umount" in t:
                order.append("in")
                await asyncio.sleep(0.05)
                order.append("out")
            return L.Ran(0, "", "")
        a = asyncio.ensure_future(PH(CFGH, policy=POLICY, run=slow_run, ncpu=4, mem_total=15 * GIB, paths=paths, mountinfo="", source_dir=src, which=which_all))
        b = asyncio.ensure_future(UNP(run=slow_run, paths=paths, mountinfo=lambda: MI_RUN + MI_TMP, units_left=0, which=which_all, dropin_dir=f"{td}/none"))
        await asyncio.gather(a, b, return_exceptions=True)
        check("R4: prepare_host and unprepare_host never interleave (one module-level lock): every helper call ends before the next begins",
              order[:2] == ["in", "out"] and all(order[i] == ("in" if i % 2 == 0 else "out") for i in range(len(order))) and len(order) >= 4
              and isinstance(L._HOST_LOCK, asyncio.Lock) and not L._HOST_LOCK.locked(), str(order))
        # unprepare: unmounts through the helper, in PID 1's table; an unreadable table unmounts nothing
        mi = MI_RUN + MI_TMP
        ru = FakeRun(tables=FakeTables())
        out = await UNP(run=ru, paths=paths, mountinfo=lambda: mi, units_left=0, which=which_all, dropin_dir=f"{td}/none", helper_prefix="portal-rbtest-host-")
        check("F1: unprepare_host unmounts both areas through helper units of the given prefix and never calls umount directly",
              out["unmounted"] and sum(1 for x in ru.texts() if "--unit=portal-rbtest-host-" in x and inner(x).startswith("/usr/bin/umount ")) == 2
              and not any(c[0].endswith("/umount") for c in ru.calls))
        ru2 = FakeRun(tables=FakeTables())
        out = await UNP(run=ru2, paths=paths, mountinfo=lambda: None, units_left=0, which=which_all, dropin_dir=f"{td}/none")
        check("F1: unprepare_host with an unreadable host mount table unmounts nothing and says so",
              out["mounts_unreadable"] and not out["unmounted"] and not any("umount" in x for x in ru2.texts()))
    # make_tmp: both areas are checked against PID 1's table and the device seen here
    with tempfile.TemporaryDirectory() as td2:
        tmpd = f"{td2}/tmp"
        os.mkdir(tmpd, 0o700)
        full = f"41 30 0:40 / {tmpd} rw - tmpfs portal-rb-tmp rw\n42 30 0:41 / /run/portal-rb rw - tmpfs portal-rb rw\n"
        h = Host()
        good = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all, tmp_dir=tmpd, mountinfo=lambda: full, want_dev_of=lambda p: "0:40" if p == tmpd else "0:41")
        good.make_tmp("0123456789ab")
        check("F1: make_tmp passes when both areas are the host's tmpfs and the devices agree", os.path.isdir(f"{tmpd}/0123456789ab"))
        for label, kw in (("the tmp area is in this process's namespace only (not in PID 1's table)", dict(mountinfo=lambda: full.splitlines()[1] + "\n")),
                          ("the session area is missing from PID 1's table", dict(mountinfo=lambda: full.splitlines()[0] + "\n")),
                          ("the device here is not the host's tmpfs (a private or stale mount)", dict(want_dev_of=lambda p: "0:77")),
                          ("PID 1's table is unreadable", dict(mountinfo=lambda: ""))):
            ln = LN(run=h.run, read_text=h.reader, sleep=h.sleep, which=which_all, tmp_dir=tmpd, **{**dict(mountinfo=lambda: full, want_dev_of=lambda p: "0:40" if p == tmpd else "0:41"), **kw})
            check(f"F1: make_tmp refuses to start a unit when {label}", raises(LaunchError, ln.make_tmp, "0123456789cd"))
            check(f"F1: ... and creates no directory ({label})", not os.path.exists(f"{tmpd}/0123456789cd"))
    # parse_mountinfo_dev
    check("F1: parse_mountinfo_dev: type and device per mount point, the last line for a point wins, octal escapes decoded",
          L.parse_mountinfo_dev("1 2 0:5 / /a rw - tmpfs t rw\n3 2 0:6 / /a rw - tmpfs t rw\n4 2 0:7 / /b\\040c rw - ext4 /dev/x rw\n")
          == {"/a": ("tmpfs", "0:6"), "/b c": ("ext4", "0:7")})
    d0 = L.dev_of(os.getcwd())
    check("F1: dev_of is major:minor of this process's view of a path ('' when unreadable)", re.fullmatch(r"\d+:\d+", d0) is not None and L.dev_of("/no/such/dir") == "")


asyncio.run(namespace_tests())

# default_run: argument list, no shell (a harmless command)
async def real_run():
    r = await L.default_run(["/bin/echo", "a b; c"], 5)
    check("default_run: an argument list is not shell-parsed, stdout captured", r.rc == 0 and r.out == "a b; c\n", str(r))
    r = await L.default_run(["/nonexistent/tool"], 5)
    check("default_run: a missing program is rc 127, no exception", r.rc == 127)
    r = await L.default_run(["/bin/sleep", "5"], 0.3)
    check("default_run: a timeout kills the process and returns rc 124", r.rc == 124)
    r = await L.default_run(["/bin/cat"], 3)
    check("default_run: stdin is /dev/null (cat ends at once)", r.rc == 0 and r.out == "")
    pidf = Path(TMPD) / "child.pid"
    task = asyncio.ensure_future(L.default_run(["/bin/sh", "-c", f"echo $$ > {pidf}; exec /bin/sleep 30"], 60))
    for _ in range(100):
        if pidf.exists() and pidf.read_text().strip():
            break
        await asyncio.sleep(0.05)
    child = int(pidf.read_text().strip())
    task.cancel()
    try:
        await task
        cancelled = False
    except asyncio.CancelledError:
        cancelled = True
    try:
        os.kill(child, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    check("default_run: a cancellation kills and reaps the child before it goes on (a systemd-run must not outlive a cancelled start)", cancelled and not alive)


asyncio.run(real_run())
src = (ROOT / "rbrowser_launch.py").read_text()
check("source: create_subprocess_exec only, no shell, no os.system, no subprocess module",
      "create_subprocess_exec" in src and "shell=True" not in src and "os.system" not in src and "import subprocess" not in src
      and "create_subprocess_shell" not in src)
check("source: no systemd-run, mount or iptables call outside a command list builder (no literal run of them at import)",
      "systemd-run" in src and not any(l.startswith(("asyncio.run", "run(")) for l in src.splitlines()))
check("source: nothing from server.py or config.py is imported", not any(l.startswith(("import server", "from server", "import config", "from config")) for l in src.splitlines()))
check("rbrowser.py does not import rbrowser_launch at import time", not any(l.startswith(("import rbrowser_launch", "from rbrowser_launch")) for l in (ROOT / "rbrowser.py").read_text().splitlines()))

# ---------------------------------------------------------------- the probe's targets file, slice revert
_t = L.probe_targets(8443, ["10.0.0.5", "2001:db8::5", "fe80::1", "2001:db8::6%eth0"], ["10.0.0.1"], ["168.63.129.16", "10.0.0.1"], hidden_extra=["/home/portal/x"])
_hp = {(d["host"], d["port"]) for d in _t["tcp_denied"]}
check("probe targets: the fixed destinations on the portal's port",
      all((h, 8443) in _hp for h in ("127.0.0.1", "::1", "0.0.0.0", "::ffff:127.0.0.1")) and ("169.254.169.254", 80) in _hp
      and ("::ffff:a9fe:a9fe", 80) in _hp and ("168.63.129.16", 80) in _hp and ("168.63.129.16", 32526) in _hp)
check("probe targets: every interface address, gateway and resolver on port 53 and the portal's port",
      all((h, p_) in _hp for h in ("10.0.0.5", "2001:db8::5", "10.0.0.1", "168.63.129.16") for p_ in (53, 8443)))
check("probe targets: a link-local IPv6 address without a zone is left out, global ones lose any zone, nothing appears twice",
      not any(h.startswith("fe80") for h, _ in _hp) and not any("%" in h for h, _ in _hp) and len(_hp) == len(_t["tcp_denied"]))
_t6 = L.probe_targets(8443, ["fe80::5"], ["fe80::1%eth0", "2001:db8::1%eth1"], [])
_hp6 = {(x["host"], x["port"]) for x in _t6["tcp_denied"]}
check("probe targets: a link-local gateway WITH its zone is probed on port 53 and the portal's port, with the scope kept",
      ("fe80::1%eth0", 53) in _hp6 and ("fe80::1%eth0", 8443) in _hp6 and ("2001:db8::1", 53) in _hp6 and not any(h == "fe80::5" for h, _ in _hp6), str(_hp6))
check("probe targets: a bad zone raises", raises(ValueError, L.probe_targets, 8443, [], ["fe80::1%a b"], []) and raises(ValueError, L.probe_targets, 8443, [], ["fe80::1%" + "x" * 16], []))
check("probe targets: the hidden-path list includes the caller's paths and the launchers, and the expected sizes",
      "/home/portal/x" in _t["hidden_paths"] and "/usr/bin/xdg-open" in _t["hidden_paths"] and "/srv" in _t["hidden_paths"]
      and _t["expect"] == {"work_mb": 768, "shm_mb": 64, "run_kb": 64, "runtime_mb": 8, "tmp_mb": 32} and _t["version"] == 1)
import importlib.util as _ilu
_ps = _ilu.spec_from_file_location("rb_probe_for_tmp", ROOT / "rbrowser_unit" / "probe.py")
_pm = _ilu.module_from_spec(_ps)
_ps.loader.exec_module(_pm)
check("D6: the probe expects the launcher's /tmp size (32 MiB, the tmpfs options say so) and checks both paths against it",
      _pm.DEFAULT_EXPECT == L.PROBE_EXPECT and L.TMP_MB == 32 and f"size={L.TMP_MB}m" in L.TMP_OPTIONS and "noexec" in L.TMP_OPTIONS
      and '("/tmp", exp["tmp_mb"] << 20), ("/var/tmp", exp["tmp_mb"] << 20)' in (ROOT / "rbrowser_unit" / "probe.py").read_text())
check("probe targets: a bad port or address raises", raises(ValueError, L.probe_targets, 0, [], [], []) and raises(ValueError, L.probe_targets, 80, ["nope"], [], [])
      and raises(ValueError, L.probe_targets, True, [], [], []))
check("the launcher's work directory is the supervisor's", L.WORK_DIR == "/run/work" and "TemporaryFileSystem=/run/work:rw,nosuid,nodev,size=768m,mode=1777" in props(BA(spec())))
check("probe targets: the expected sizes equal the unit's TemporaryFileSystem sizes",
      all(x in " ".join(BA(spec())) for x in ("/run/work:rw,nosuid,nodev,size=768m", "/dev/shm:rw,nosuid,nodev,size=64m", "/run:ro,nosuid,nodev,noexec,size=64k"))
      and "size=8m" in L.TMPFS_OPTIONS)


async def targets_and_revert():
    import json as _j2
    with tempfile.TemporaryDirectory() as td:
        pth = L.HostPaths(static=f"{td}/static", run_dir=f"{td}/run", state=f"{td}/state", tmp_dir=f"{td}/tmp")
        src = unit_src(td)
        mi = f"1 2 0:5 / {td}/run rw - tmpfs portal-rb rw\n1 2 0:6 / {td}/tmp rw - tmpfs portal-rb-tmp rw\n"
        ftt = FakeTables()
        res = await PH(CFGH, policy=POLICY, run=FakeRun(tables=ftt), ncpu=4, mem_total=15 * GIB, paths=pth,
                                   mountinfo=mi, source_dir=src, which=which_all, probe_targets_doc=_t)
        f = Path(td) / "static" / "bin" / "probe-targets.json"
        st = os.stat(f)
        check("prepare_host writes the probe's targets next to the scripts (mode 0644), readable as JSON",
              res["ok"] and _j2.load(open(f)) == _t and stat.S_IMODE(st.st_mode) == 0o644)
        res2 = await PH(CFGH, policy=POLICY, run=FakeRun(tables=ftt), ncpu=4, mem_total=15 * GIB, paths=pth,
                                    mountinfo=mi, source_dir=src, which=which_all)
        check("prepare_host without a targets document leaves the file as it was", res2["ok"] and _j2.load(open(f)) == _t)
        r1 = FakeRun(tables=ftt)
        out = await UNP(run=r1, paths=pth, mountinfo="", units_left=0, which=which_all, dropin_dir=f"{td}/nodropins")
        check("unprepare no longer reverts the slice: no revert command, only its own drop-ins are removed",
              not any("revert" in x for x in r1.texts()) and "slice_reverted" not in out and out["slice_stopped"])
        r2 = FakeRun(tables=ftt)
        out = await UNP(run=r2, paths=pth, mountinfo="", units_left=1, which=which_all, dropin_dir=f"{td}/nodropins")
        check("unprepare keeps everything while a unit is left", r2.calls == [] and not out["slice_stopped"] and not out["firewall_removed"])


asyncio.run(targets_and_revert())

# ---------------------------------------------------------------- the supervisor (rbrowser_unit/session.py)
import importlib.util as _ilu  # noqa: E402

_sp = _ilu.spec_from_file_location("rb_session_args", ROOT / "rbrowser_unit" / "session.py")
SESS = _ilu.module_from_spec(_sp)
_sp.loader.exec_module(SESS)
_vnc = " ".join(SESS.x11vnc_argv("/usr/bin/x11vnc", 3, "/a/xauth", "/a/vnc.sock"))
check("supervisor: the x11vnc line has -rfbport 0, -rfbportv6 -1, -noipv6, -unixsock, -safer, -nocmds and no -shared",
      all(x in _vnc for x in ("-rfbport 0", "-rfbportv6 -1", "-noipv6", "-no6 ", "-unixsock /a/vnc.sock", "-safer", "-nocmds")) and "-shared" not in _vnc)
check("supervisor: the Xvfb line has -displayfd and no -nolisten local",
      "-displayfd" in SESS.xvfb_argv("/usr/bin/Xvfb", 5, "/a/xauth") and "local" not in SESS.xvfb_argv("/usr/bin/Xvfb", 5, "/a/xauth"))
check("supervisor: x11vnc never exchanges a selection, whatever the setting (D4)",
      all(f in SESS.x11vnc_argv("x", 1, "a", "s") for f in ("-nosel", "-noprimary", "-nosetprimary", "-noclipboard", "-nosetclipboard")))
_chrome = SESS.chromium_argv("/usr/bin/chromium", 1280, 720, "https://duckduckgo.com/")
check("supervisor: the Chromium flags hold the offline set and --no-proxy-server and never --no-sandbox",
      "--no-proxy-server" in _chrome and "--disable-background-networking" in _chrome and "--no-sandbox" not in _chrome and not any(a.startswith("--remote-debugging") for a in _chrome))
_sess_src = (ROOT / "rbrowser_unit" / "session.py").read_text()
import ast as _ast  # noqa: E402

_sess_tree = _ast.parse(_sess_src)
_doc_ids = set()
for _n in _ast.walk(_sess_tree):
    if isinstance(_n, (_ast.Module, _ast.FunctionDef, _ast.ClassDef)) and _n.body and isinstance(_n.body[0], _ast.Expr) \
            and isinstance(_n.body[0].value, _ast.Constant):
        _doc_ids.add(id(_n.body[0].value))
_consts = [_n.value for _n in _ast.walk(_sess_tree) if isinstance(_n, _ast.Constant) and isinstance(_n.value, str) and id(_n) not in _doc_ids]
check("supervisor: no -nolisten local, no RB_DISPLAY, no --no-sandbox, no -shared among the strings of its code",
      not any(c in ("-shared", "--no-sandbox", "local") or "RB_DISPLAY" in c or "-nolisten local" in c for c in _consts))
check("supervisor: every RB_ variable it reads is one that the unit's command line sets",
      set(re.findall(r'"(RB_[A-Z]+)"', _sess_src)) == {"RB_GEOMETRY", "RB_CLIPBOARD", "RB_HOME", "RB_CHROMIUM"}
      and all(f"RB_{k}=" in " ".join(BA(spec())) for k in ("GEOMETRY", "CLIPBOARD", "HOME", "CHROMIUM")))
check("supervisor: the unit command runs /mnt/session.py with python3 -I -S",
      BA(spec())[-4:] == ["/usr/bin/python3", "-I", "-S", "/mnt/session.py"])

# ---------------------------------------------------------------- the live test file (never run here)
import subprocess as _sp  # noqa: E402

_live_src = (ROOT / "tests" / "test_rbrowser_live.py").read_text()
_live_tree = _ast.parse(_live_src)
check("live test: never names the portal's own unit or a session unit by prefix",
      "portal.service" not in _live_src and "portal-rb-" not in _live_src and "UNIT_PREFIX" in _live_src)
check("live test: the only launcher it builds takes the test prefix",
      all("unit_prefix=self.TP" in m or "unit_prefix=TEST_PREFIX" in m or 'unit_prefix=req["test_prefix"]' in m for m in re.findall(r"SystemdLauncher\([^)]*\)", _live_src)) and "SystemdLauncher(" in _live_src)
_top_imports = {n.names[0].name.split(".")[0] if isinstance(n, _ast.Import) else (n.module or "").split(".")[0]
                for n in _live_tree.body if isinstance(n, (_ast.Import, _ast.ImportFrom))}
check("live test: at module level it imports only the standard library (the guards run before any portal module)",
      _top_imports <= set(sys.stdlib_module_names), str(_top_imports - set(sys.stdlib_module_names)))
check("live test: the guard function comes before the first import that is not at the top",
      _live_src.index("refuse_unless_asked()") < _live_src.index("import asyncio") and "def refuse_unless_asked" in _live_src)
check("live test: every gate of the round 1 table is present",
      set(re.findall(r'@gate\("(G\d\d\w*)"', _live_src)) == {"G00", "G01", "G01b", "G02", "G02b", "G02c", "G03", "G04", "G05", "G06", "G07", "G08", "G09", "G09b", "G10", "G11",
                                                              "G13", "G13b", "G14", "G15", "G16", "G17", "G18", "G19", "G20", "G21", "G22", "G23", "G24", "G25"})
check("live test: G25 (1.26.0) is a round 1 gate, written for the theme file and the pictures, and is not a hard gate",
      "G25" in re.findall(r'@gate\("(G\d\d\w*)"', _live_src) and "G25" not in _live_src.split("HARD_GATES = (")[1].split(")")[0]
      and "make_theme" in _live_src and "theme_color=" in _live_src and "prefers-color-scheme" in _live_src and "file:///etc/hostname" in _live_src)
check("live test: it removes everything in finally and handles SIGTERM", "finally:\n        if rig is not None:\n            cleanup(rig)" in _live_src and "signal.SIGTERM" in _live_src)
# ---- the live test's guards and bounds (pure parts imported under another name: its guards only run as __main__)
_ls = _ilu.spec_from_file_location("rb_live_imported", ROOT / "tests" / "test_rbrowser_live.py")
LIVE = _ilu.module_from_spec(_ls)
_ls.loader.exec_module(LIVE)
_clean = dict(static_exists=False, run_mounted=False, chains={"iptables": False, "ip6tables": False}, dropins=[], slice_active=False)
check("live guard: a clean host has no reason to refuse", LIVE.preexisting_state(**_clean) == [])
for _name, _over in (("the static tree", {"static_exists": True}), ("a mount on the session area", {"run_mounted": True}),
                     ("the iptables chain", {"chains": {"iptables": True, "ip6tables": False}}),
                     ("the ip6tables chain alone", {"chains": {"iptables": False, "ip6tables": True}}),
                     ("a runtime drop-in of the slice", {"dropins": ["/run/systemd/system.control/system-portalrb.slice.d"]}),
                     ("an active slice", {"slice_active": True})):
    _w = LIVE.preexisting_state(**{**_clean, **_over})
    check(f"live guard: {_name} makes the test refuse, with one reason that names it", len(_w) == 1, str(_w))
check("live guard: every fact at once gives every reason", len(LIVE.preexisting_state(static_exists=True, run_mounted=True, chains={"iptables": True, "ip6tables": True},
                                                                                  dropins=list(LIVE.SLICE_DROPIN_DIRS + LIVE.SLICE_UNIT_FILES), slice_active=True,
                                                                                  slice_masked=True, quote_exists=True)) == 2 + 2 + 6 + 1 + 1 + 1)
check("live guard: the feature's own pin on the host makes the test refuse; the test's own base cannot match that glob",
      len(LIVE.preexisting_state(**{**_clean, "production_pins": ["/sys/fs/bpf/portal-rb-ingress-0123456789abcdef"]})) == 1
      and fnmatch.fnmatch("/sys/fs/bpf/portal-rb-ingress-0123456789abcdef", LIVE.PRODUCTION_PIN_GLOB)
      and not fnmatch.fnmatch("/sys/fs/bpf/portal-rblive-ab12cd-0123456789abcdef", LIVE.PRODUCTION_PIN_GLOB)
      and "production_pins=sorted(glob.glob(PRODUCTION_PIN_GLOB))" in _live_src)
check("live clean-up: unprepare_host gets the test's own pin or '' (never None, whose default is the feature's pin)",
      'pin_arg = "" if (rig.unconfirmed or rig.loop.stuck) else (rig.pin or "")' in _live_src and "bpf_pin=rig.pin or None" not in _live_src and "bpf_pin=None" not in _live_src)
check("live G01b: the listener set holds an MPTCP listener on both families (protocol 262), named so that pair_tested and the judge treat it like a tcp one",
      "rec(\"tcp4_mptcp_autobind\", socket.AF_INET, None, 262)" in LIVE.LISTEN_SNIPPET and "rec(\"tcp6_mptcp_autobind\", socket.AF_INET6, None, 262)" in LIVE.LISTEN_SNIPPET
      and LIVE.pair_tested(False, "tcp4_mptcp_autobind") and not LIVE.pair_tested(True, "tcp4_mptcp_autobind") and LIVE.pair_tested(True, "tcp6_mptcp_autobind"))
_adr = {"127.0.0.1": {"v6": False, "loopback": True}, "10.0.0.5": {"v6": False, "loopback": False}}
_ctl = {"reported": True, "ports": {"tcp4_autobind": 1, "tcp4_mptcp_autobind": 2}, "errors": {}, "outbound": "connected",
        "outcomes": {(a, n): "connected" for a in _adr for n in ("tcp4_autobind", "tcp4_mptcp_autobind")}}
def _unit(mptcp_outcome):
    return {"reported": True, "ports": {"tcp4_autobind": 1, "tcp4_mptcp_autobind": 2}, "errors": {}, "outbound": "connected",
            "outcomes": {(a, n): ("timeout" if n == "tcp4_autobind" else mptcp_outcome) for a in _adr for n in ("tcp4_autobind", "tcp4_mptcp_autobind")}}
check("live G01b judge: an MPTCP listener that a host connect reaches in a unit with the filter fails the gate, one that times out passes",
      not LIVE.judge_g01b(_adr, _unit("connected"), _unit("connected"), _ctl, {"session": True, "filter-only": True, "control": False})[0]
      and LIVE.judge_g01b(_adr, _unit("timeout"), _unit("timeout"), _ctl, {"session": True, "filter-only": True, "control": False})[0])
# everything `systemctl revert` deletes is in the guard: the persistent and runtime foo.d directories, the unit file (and a mask is a symlink there)
check("live guard: the guard lists the /etc and /run drop-in directories and unit file of the slice, besides the .control ones",
      {"/etc/systemd/system/system-portalrb.slice.d", "/run/systemd/system/system-portalrb.slice.d", "/run/systemd/system.control/system-portalrb.slice.d",
       "/etc/systemd/system.control/system-portalrb.slice.d"} <= set(LIVE.SLICE_DROPIN_DIRS)
      and {"/etc/systemd/system/system-portalrb.slice", "/run/systemd/system/system-portalrb.slice"} <= set(LIVE.SLICE_UNIT_FILES))
check("live guard: a masked slice, an existing quote directory and a chain that cannot be told each make the test refuse",
      len(LIVE.preexisting_state(**{**_clean, "slice_masked": True})) == 1 and len(LIVE.preexisting_state(**{**_clean, "quote_exists": True})) == 1
      and len(LIVE.preexisting_state(**{**_clean, "chains": {"iptables": None, "ip6tables": False}})) == 1)
check("live guard: host_facts looks with lexists (a symlink, a mask or a dangling one counts) and asks for the slice's LoadState",
      "for d in SLICE_DROPIN_DIRS + SLICE_UNIT_FILES if os.path.lexists(d)" in _live_src and "LoadState" in _live_src and "os.path.lexists(QUOTE_DIR)" in _live_src)
# the iptables answer: only "no such chain" with status 1 is an absence
CS = LIVE.chain_state
check("live guard: chain_state: 0 is a chain, status 1 with 'No chain/target/match by that name' is none",
      CS(0, "-N PORTAL-RB\n", "") is True and CS(1, "", "iptables: No chain/target/match by that name.\n") is False)
check("live guard: chain_state: a lock time-out, a resource error or an unknown failure cannot tell (None), also status 1 with another text",
      CS(4, "", "Another app is currently holding the xtables lock") is None and CS(2, "", "bad") is None and CS(3, "", "") is None
      and CS(1, "", "Another app is currently holding the xtables lock. Stopped waiting after 2s.") is None)
check("live guard: chain_state: the iptables-nft 1.8.9 answer for a missing chain ('is incompatible, use nft tool') is an absence",
      CS(1, "", "iptables v1.8.9 (nf_tables): chain `PORTAL-RB' in table `filter' is incompatible, use 'nft' tool.\n") is False)
# the units a slice stop may not kill
SO = LIVE.slice_stop_offenders
check("live clean-up: a production session unit or a probe unit in the unit list is an offender; the test's own units are not",
      SO("portal-rb-0123456789ab.service loaded active running x\n", [], "portal-rb-", "portal-rbtest-") == ["portal-rb-0123456789ab.service"]
      and SO("portal-rbprobe-0123456789ab.service loaded active running x\n", [], ("portal-rb-", "portal-rbprobe-"), "portal-rbtest-") == ["portal-rbprobe-0123456789ab.service"]
      and SO("portal-rbprobe-0123456789ab.service loaded active running x\n", [], "portal-rb-", "portal-rbtest-") == []
      and SO("portal-rbtest-aabbccddeeff.service loaded active running\n", [], ("portal-rb-", "portal-rbprobe-"), "portal-rbtest-") == [])
check("live clean-up: every child directory of the slice that does not start with the test prefix is an offender, whatever its suffix (a .scope, a bare name, a .mount)",
      SO("", ["portal-rbtest-aabbccddeeff.service", "other.service", "x.scope", "bare", "y.mount", "portal-rb-0123456789ab.service"], "portal-rb-", "portal-rbtest-")
      == ["bare", "other.service", "portal-rb-0123456789ab.service", "x.scope", "y.mount"]
      and SO("", ["portal-rbtest-aabbccddeeff.service"], "portal-rb-", "portal-rbtest-") == [] and SO("", [], "portal-rb-", "portal-rbtest-") == [])
with tempfile.TemporaryDirectory() as _cg:
    for _n in ("cgroup.procs", "cpu.stat", "memory.max"):
        (Path(_cg) / _n).write_text("x")
    for _d in ("portal-rbtest-aabbccddeeff.service", "x.scope", "bare"):
        (Path(_cg) / _d).mkdir()
    (Path(_cg) / "linked").symlink_to(Path(_cg) / "bare")
    check("live clean-up: cgroup_child_dirs lists directories only (interface files and a link are not members)",
          LIVE.cgroup_child_dirs(_cg) == ["bare", "portal-rbtest-aabbccddeeff.service", "x.scope"], str(LIVE.cgroup_child_dirs(_cg)))
    check("live clean-up: a slice with an x.scope in it is an offender through the real listing",
          LIVE.slice_stop_offenders("", LIVE.cgroup_child_dirs(_cg), "portal-rb-", "portal-rbtest-") == ["bare", "x.scope"])
check("live clean-up: Rig.slice_offenders reads directories (not os.listdir), lists both the session and the probe prefix and fails closed",
      "cgroup_child_dirs(SLICE_CGROUP)" in _live_src and "os.listdir(SLICE_CGROUP)" not in _live_src and "U.PROBE_PREFIX" in _live_src and "(the slice's cgroup could not be read)" in _live_src)
check("live clean-up: a failed unit listing counts as an offender (fails closed)", "the unit list could not be read" in _live_src)
_main_src = _live_src[_live_src.index("def main():"):_live_src.index("def cleanup(rig):")]
check("live guard: main() checks the host before it prepares it, and returns without preparing",
      _main_src.index("preexisting_state(") < _main_src.index("rig.prepare()") and _main_src.index("preexisting_state(") < _main_src.index('rig.created.update')
      and "return 1" in _main_src[_main_src.index("preexisting_state("):_main_src.index("rig.created.update")])
_clean_src = _live_src[_live_src.index("def cleanup(rig):"):]
# fix pass 2 (F1): the live test runs prepare_host the way the portal runs it
for _nm in ("PRIVATE_NS_SCRIPT", "PRIVATE_CONTROL_SCRIPT"):
    try:
        compile(getattr(LIVE, _nm), _nm, "exec")
        _ok = True
    except SyntaxError:
        _ok = False
    check(f"live test: {_nm} is valid python", _ok)
check("live test: Rig.prepare runs prepare_host in a unit with PrivateTmp=yes, named with the test prefix, and passes the test's helper prefix",
      '"PrivateTmp=yes"' in _live_src and 'unit = f"{self.TP}prep-' in _live_src and "helper_prefix=self.helper_prefix" in _live_src
      and 'return self.TP + "host-"' in _live_src and "PRIVATE_NS_SCRIPT" in _live_src[_live_src.index("def prepare(self"):_live_src.index("class Session")])
check("live test: G02c is a hard gate that holds a control (a plain mount in a PrivateTmp unit) and the helper mount, and reads PID 1's table",
      "G02c" in LIVE.HARD_GATES and "G02c" in LIVE.PROBE_GATES and "PRIVATE_CONTROL_SCRIPT" in _live_src[_live_src.index('@gate("G02c"'):_live_src.index('@gate("G04"')]
      and "HOST_MOUNTINFO" in _live_src[_live_src.index('@gate("G02c"'):_live_src.index('@gate("G04"')] and "/proc/self/mountinfo" in _live_src.split("PRIVATE_NS_SCRIPT = ")[1].split('"""')[1])
check("live test: the guard facts and mounts_before read PID 1's mount table, the clean-up's unprepare runs in a PrivateTmp unit",
      _live_src.count("L.HOST_MOUNTINFO") >= 3 and 'op="unprepare"' in _clean_src)
# R5: the live test's guards and clean-up lines
_links = {"/proc/self/ns/mnt": "mnt:[4026531841]", "/proc/1/ns/mnt": "mnt:[4026531841]"}
def _rl(path):
    if path not in _links:
        raise FileNotFoundError(path)
    return _links[path]
check("R5: the live guard accepts only PID 1's mount namespace", LIVE.same_mount_namespace(_rl) is True
      and LIVE.same_mount_namespace(lambda p: "mnt:[4026531841]" if p == "/proc/1/ns/mnt" else "mnt:[4026532999]") is False
      and LIVE.same_mount_namespace(lambda p: (_ for _ in ()).throw(PermissionError(p))) is False
      and LIVE.same_mount_namespace(lambda p: "") is False)
_rg = _live_src[_live_src.index("def refuse_unless_asked"):_live_src.index('if __name__ == "__main__":')]
check("R5: refuse_unless_asked calls the namespace guard and exits 2 before any import of the portal's modules", "same_mount_namespace()" in _rg and "sys.exit(2)" in _rg)
check("R5: the KEPT line is due for a pin that exists and was not mentioned, never for a gone pin or one already said",
      LIVE.kept_line_due(True, False) and not LIVE.kept_line_due(True, True) and not LIVE.kept_line_due(False, False))
check("R5: the clean-up prints the last-word KEPT line for an existing pin and the fallback unprepare_host waits for a private unit that is not confirmed gone",
      "kept_line_due(os.path.lexists(rig.pin), kept_said)" in _live_src and "rig.private_stuck" in _live_src and "self.stop_unit(unit)" in _live_src
      and _live_src.index("self.stop_unit(unit)") < _live_src.index("is NOT confirmed gone"))
_g9 = _live_src[_live_src.index('@gate("G09"'):_live_src.index('def g09b_verdict')]
check("R2: G09 reports the override-redirect select list as RESIDUAL (an accepted limit), not as a FAIL",
      'return "RESIDUAL"' in _g9 and "manual: RESIDUAL RISK" not in _g9 and _g9.count('return "FAIL"') == 2 and "R2" in _g9)
_xp = LIVE.parse_xprop_window('WM_CLASS(STRING) = "chromium", "Chromium"\nWM_WINDOW_ROLE(STRING) = "GtkFileChooserDialog"\n_NET_WM_STATE(ATOM) = _NET_WM_STATE_MODAL\n'
                              '_NET_WM_WINDOW_TYPE(ATOM) = _NET_WM_WINDOW_TYPE_DIALOG\nWM_TRANSIENT_FOR(WINDOW): window id # 0xe00002\n')
_xp0 = LIVE.parse_xprop_window("WM_CLASS:  not found.\nWM_WINDOW_ROLE:  not found.\n_NET_WM_STATE:  not found.\n_NET_WM_WINDOW_TYPE:  not found.\nWM_TRANSIENT_FOR:  not found.\n")
check("R3 measurement: the xprop parser reads class, role, state, type and transient-for, and an absent property as None or empty",
      _xp == {"class": ["chromium", "Chromium"], "role": "GtkFileChooserDialog", "state": ["MODAL"], "type": ["DIALOG"], "transient": "0xe00002"}
      and _xp0 == {"class": [], "role": None, "state": [], "type": [], "transient": None})
_sess_text = (ROOT / "rbrowser_unit" / "session.py").read_text()
check("R3 measurement: the measurement patches apply to the unit's session.py (the refusal and the fit are where the test expects them)",
      LIVE.show_every_window(_sess_text) != _sess_text and LIVE.no_fit_transient(_sess_text) != _sess_text and "WM_TRANSIENT_FOR" in LIVE.no_fit_transient(_sess_text))
check("R7: --only G01 starts the first session too (G01 has nothing to judge without a running session unit)", 'only & {"G01", "G02b"}' in _live_src)
# fix pass 2 (F4): the pin and the unconfirmed units
_may = LIVE.clean_up_may_unpin
check("live clean-up: the pin is removed by the clean-up itself only when unprepare_host did not run, no unit is unconfirmed and the slice is empty NOW",
      _may(None, set(), []) is True and _may(None, set(), None) is False and _may(None, set(), ["portal-rbtest-aabbccddeeff.service"]) is False)
check("live clean-up: a test unit that is not confirmed gone keeps the pin, whatever else is true",
      _may(None, {"portal-rbtest-aabbccddeeff.service"}, []) is False and _may({"pin_removed": False, "pin_kept": True}, {"x"}, []) is False)
check("live clean-up: when unprepare_host ran its answer (pin_removed or pin_kept) is the last word: no second unpin",
      _may({"pin_removed": True, "pin_kept": False}, set(), []) is False and _may({"pin_removed": False, "pin_kept": True}, set(), []) is False)
check("live clean-up: stop_unit confirms through systemctl show and kills once; the launcher's unstopped units are counted",
      "def confirmed_gone" in _live_src and '"kill", "-s", "SIGKILL"' in _clean_src + _live_src[_live_src.index("def stop_unit"):_live_src.index("def confirmed_gone")]
      and "rig.launcher.unstopped" in _clean_src and "rig.unconfirmed" in _clean_src)
check("live clean-up: the slice is checked for foreign units again right before each stop of it (revert/stop and unprepare_host)",
      _clean_src.count("check_offenders()") >= 4 and _clean_src.index('rig.systemctl("stop", L.SLICE)') > _clean_src.index("again, right before the stop")
      and _clean_src.index("unprepare_host(") > _clean_src.index("again: unprepare_host stops the slice"))
check("live clean-up: unprepare_host gets bpf_pin '' (no pin touched) while a test unit is unconfirmed, in the PrivateTmp unit and in the fallback",
      'pin_arg = "" if (rig.unconfirmed or rig.loop.stuck) else (rig.pin or "")' in _clean_src and _clean_src.count("bpf_pin=pin_arg") == 2 and 'bpf_pin=rig.pin or ""' not in _clean_src)
check("live test: G16 runs both of its sessions with the window manager's refusal off (a refused dialog must not count as a dialog that did not open)",
      "wm_shows_everything(rig)" in _live_src[_live_src.index('@gate("G16"'):_live_src.index("def type_check")] and "@contextlib.contextmanager\ndef wm_shows_everything" in _live_src)
check("live test: the document-PiP control also switches the window manager's refusal off",
      "show_every_window(patched)" in _live_src and "def show_every_window" in _live_src)
_g09b = _live_src[_live_src.index('@gate("G09b"'):_live_src.index('@gate("G10"')]
_ns = {"re": re}
exec(_live_src[_live_src.index("def drop_doc_pip_switch"):_live_src.index("def try_pip_in_secure_context")], _ns)
_sess = (Path(__file__).resolve().parent.parent / "rbrowser_unit" / "session.py").read_text()
_sw = '"--disable-features=DocumentPictureInPictureAPI"'
check("live test: G09b's document PiP control removes the Chromium switch that turns document PiP off (so a document PiP window can be measured)",
      "drop_doc_pip_switch(t)" in _g09b and '"measure-doc"' in _g09b and _sw in _sess
      and _sw not in _ns["drop_doc_pip_switch"](_sess) and _ns["drop_doc_pip_switch"](_sess).count("--disable-features") == _sess.count("--disable-features") - 1)
check("live test: G09b also runs the document PiP with only the Chromium switch removed (the window manager's real rule) and saves its notes",
      "measure-doc-rule" in _g09b and "patch=drop_doc_pip_switch" in _g09b and 'rig.save("g09b-notes.txt"' in _g09b)
check("live test: G09b lists the role, state, type and transient-for of the new PiP windows", 'new_short' in _live_src and "role, state, type, transient-for" in _g09b)
check("live clean-up: there is no unconditional unpin after the host part any more",
      "rbrowser_bpf.unpin(rig.pin)" in _clean_src and _clean_src.index("rbrowser_bpf.unpin(rig.pin)") > _clean_src.index("clean_up_may_unpin("))
check("live clean-up: the slice is reverted and stopped only when this run made those changes",
      re.search(r'if rig\.created\.get\("slice"\) and not offenders:\s+rig\.systemctl\("revert"', _clean_src) is not None
      and re.search(r'if rig\.created\.get\("slice_started"\) and not offenders:\s+offenders = check_offenders\(\)[^\n]*\n\s+if not offenders:\s+rig\.systemctl\("stop"', _clean_src) is not None
      and _clean_src.count('"revert"') == 1)
check("live clean-up: the upload rule, the tmpfs, the static and state trees and the scratch directory go only when `created` says so",
      all(k in _clean_src for k in ('created.get("chain")', 'created.get("mounted")', 'created.get("static")', 'created.get("state")', 'created.get("quote_dir")')))
_g19 = _live_src[_live_src.index('@gate("G19"'):_live_src.index('@gate("G20"')]
check("live test: G19 asks for foreign slice members before it stops the slice",
      _g19.index("slice_offenders()") < _g19.index('rig.systemctl("stop", L.SLICE')
      and _clean_src.index("slice_offenders()") < _clean_src.index('"revert"') < _clean_src.index('"stop"') and _clean_src.index("slice_offenders()") < _clean_src.index("unprepare_host("))
check("live clean-up: with an offender the upload rule, the slice, the tmpfs and the trees are left alone",
      _clean_src.count("not offenders") >= 4)
_sig_ign = _clean_src[:_clean_src.index("for fn in rig.cleanups")]
check("live clean-up: SIGTERM, SIGINT and SIGHUP are ignored before the first clean-up step",
      all(f"signal.{n}" in _sig_ign for n in ("SIGTERM", "SIGINT", "SIGHUP")) and "signal.SIG_IGN" in _sig_ign)
check("live test: Rig() is built inside the try (signal-safe) and its set-up removes its scratch directory on failure",
      _main_src.index("try:") < _main_src.index("rig = Rig()") and "if rig is not None:" in _live_src
      and "shutil.rmtree(self.tmp" in _live_src[_live_src.index("def __init__(self):\n        self.tmp = None"):_live_src.index("def _setup")])
_mq = _live_src[_live_src.index("def make_quote_dir"):_live_src.index("def unit_listeners")]
check("live test: the quote directory is created with mkdir (never reused), the file with O_EXCL|O_NOFOLLOW and mode 0644; no makedirs, no chmod by path",
      "os.mkdir(QUOTE_DIR" in _mq and "O_EXCL" in _mq and "O_NOFOLLOW" in _mq and "fchmod(ffd, 0o644)" in _mq and "makedirs" not in _mq and "os.chmod" not in _mq
      and _mq.index("os.mkdir(QUOTE_DIR") < _mq.index('created["quote_dir"] = True'))
check("live test: SIGHUP is handled like SIGTERM and SIGINT", "signal.SIGHUP" in _main_src and "tmux" in _live_src)
check("live test: the CPU burner, the G03 dummy, the G19 control unit, the G01b listener units and the R13 and R13b stand-in units each carry RuntimeMaxSec=120", _live_src.count('"RuntimeMaxSec=120"') == 6, str(_live_src.count('"RuntimeMaxSec=120"')))
_g8 = _live_src[_live_src.index("def g8("):_live_src.index('@gate("G09"')]
check("live test: the burner starts only after the session page has loaded, and has no quota that would leave a core idle",
      _g8.index("s.wait_title") < _g8.index('"RuntimeMaxSec=120"') and '"CPUQuota=' not in _g8)
check("live test: the hidden-path scratch directory needs the quoting rule and is expressed as one quoted, escaped item",
      LIVE.QUOTE_DIR in L.hidden_paths([LIVE.QUOTE_DIR]) and L.quote_property_path(LIVE.QUOTE_DIR) == '"-/var/lib/rbtest hidden \\"q\\""'
      and any(L.quote_property_path(LIVE.QUOTE_DIR) in a for a in BA(spec(hidden_extra=[LIVE.QUOTE_DIR]))), L.quote_property_path(LIVE.QUOTE_DIR))
check("live test: listener findings count a TCP LISTEN and a UDP bind below 32768, not an established socket or a high UDP port",
      LIVE.listener_findings([(1, "tcp", "LISTEN", 5900), (2, "tcp", "ESTABLISHED", 5900), (3, "udp", "NONE", 5353), (4, "udp", "NONE", 40000), (5, "udp", "NONE", 0)])
      == [(1, "tcp", 5900), (3, "udp", 5353)])
_g1 = _live_src[_live_src.index("def g1("):_live_src.index('@gate("G02"')]
check("live test: G01 looks at the listeners of the running session (x11vnc) and cannot pass without a session", "unit_listeners(" in _g1 and "listeners_ok = False" in _g1 and "x11vnc" in _g1)
check("live test: G19 covers the rule with no unit running, the slice stopped and started again, and prepare_host again after that (the later gates run on the repaired rule)",
      "no unit running" in _live_src and "stopped and started again" in _live_src and "host2 = rig.prepare()" in _g19
      and _g19.index("stopped and started again") < _g19.index("host2 = rig.prepare()") and 'ctx["host"] = host2' in _g19 and "near3" in _g19.split("return (")[-1])
check("live test: the gateways it hands the probe keep an IPv6 link-local zone", 'self.host["gateways_scoped"]' in _live_src)
# ---- the live test's loop, clean-up and G01b helpers
import socket as _so  # noqa: E402
import threading as _th  # noqa: E402
import time as _tm  # noqa: E402
import signal as _sg  # noqa: E402
import types as _ty  # noqa: E402


async def _slow(flag):
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:
        flag.append("cancelled")
        raise


_lp = LIVE.Loop()
_flag = []
try:
    _lp.run(_slow(_flag), timeout=0.3)
    _raised = None
except BaseException as e:      # noqa: BLE001
    _raised = e
check("live loop: a time-out cancels the coroutine (it sees CancelledError) before the exception goes on",
      isinstance(_raised, TimeoutError) and _flag == ["cancelled"], f"{_raised!r} {_flag}")
_flag2 = []
_old_alrm = _sg.signal(_sg.SIGALRM, lambda *a: (_ for _ in ()).throw(SystemExit(7)))
_sg.setitimer(_sg.ITIMER_REAL, 0.3)
try:
    _lp.run(_slow(_flag2), timeout=20)
    _raised2 = None
except BaseException as e:      # noqa: BLE001
    _raised2 = e
finally:
    _sg.setitimer(_sg.ITIMER_REAL, 0)
    _sg.signal(_sg.SIGALRM, _old_alrm)
check("live loop: a SystemExit from a signal handler (not an Exception) also cancels the coroutine and is re-raised",
      isinstance(_raised2, SystemExit) and _flag2 == ["cancelled"], f"{_raised2!r} {_flag2}")
_flag3 = []
asyncio.run_coroutine_threadsafe(_slow(_flag3), _lp.loop)
_tm.sleep(0.2)
_n = _lp.cancel_pending(3.0)
check("live loop: cancel_pending cancels and awaits every task that is still on the loop", _n == 1 and _flag3 == ["cancelled"], f"{_n} {_flag3}")
check("live loop: afterwards nothing is pending and the loop still answers", _lp.cancel_pending(1.0) == 0 and _lp.run(asyncio.sleep(0, "x"), 2) == "x")
_lp.close()
# review note 2: Loop.run waits until the cancelled coroutine has REALLY unwound before the exception goes on (the old 0.3 s sleep did not)
async def _slow_unwind(flag, secs=1.0):
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:
        await asyncio.sleep(secs)          # a launcher's clean-up stop that takes a while
        flag.append("unwound")
        raise


_lp = LIVE.Loop()
_fl = []
try:
    _lp.run(_slow_unwind(_fl, 1.0), timeout=0.1, unwind=10)
    _r = None
except BaseException as e:      # noqa: BLE001
    _r = e
check("live loop: run() does not raise before a cancelled coroutine that needs a second to unwind has unwound", isinstance(_r, TimeoutError) and _fl == ["unwound"] and _lp.stuck == 0, f"{_r!r} {_fl} {_lp.stuck}")
_fl2 = []
try:
    _lp.run(_slow_unwind(_fl2, 5.0), timeout=0.1, unwind=0.3)
    _r = None
except BaseException as e:      # noqa: BLE001
    _r = e
check("live loop: a coroutine that has not unwound within the bound is counted in .stuck (the clean-up keeps the pin)", isinstance(_r, TimeoutError) and _fl2 == [] and _lp.stuck == 1, f"{_r!r} {_fl2} {_lp.stuck}")
async def _boom():
    raise ValueError("own")


try:
    _lp.run(_boom(), 3)
    _own = None
except BaseException as e:      # noqa: BLE001
    _own = e
check("live loop: run() still returns a result and re-raises the coroutine's own exception", _lp.run(asyncio.sleep(0, "v"), 2) == "v" and isinstance(_own, ValueError))
_lp.cancel_pending(8.0)
_lp.close()
_lp = LIVE.Loop()
asyncio.run_coroutine_threadsafe(_slow_unwind([], 5.0), _lp.loop)
_tm.sleep(0.2)
_n = _lp.cancel_pending(0.3)
check("live loop: cancel_pending counts a task that has not ended within its time in .stuck (the clean-up keeps the pin)", _n == 1 and _lp.stuck == 1, f"{_n} {_lp.stuck}")
_lp.cancel_pending(8.0)
_lp.close()
check("live clean-up: a Loop that has a coroutine stuck, or an unprepare_host that did not return, keeps the pin (never unpins)",
      LIVE.clean_up_may_unpin(None, set(), [], False) is True and LIVE.clean_up_may_unpin(None, set(), [], True) is False
      and "unsettled = True" in _clean_src and "rig.loop.stuck" in _clean_src and "unsettled or rig.loop.stuck > 0" in _clean_src)
# T2: G09b is a hard gate; INCONCLUSIVE counts as a failure
def _pipres(n_new):
    return {"res": "res:secure:true,pip:opened", "windows_before": [{"id": "0x1"}],
            "windows_after": [{"id": "0x1"}] + [{"id": f"0x{i + 2}", "w": 300, "h": 200, "x": 0, "y": 0, "or": False, "transient": False, "type": "NORMAL"} for i in range(n_new)]}
_v = LIVE.g09b_verdict
check("T2: G09b is a hard gate and INCONCLUSIVE counts as a failure", "G09b" in LIVE.HARD_GATES and "INCONCLUSIVE" in LIVE.FAILING and "FAIL" in LIVE.FAILING and "PASS" not in LIVE.FAILING)
check("T2: G09b FAIL when the rule run shows a new viewable window while the control shows one", _v(_pipres(1), _pipres(1))[0] == "FAIL")
check("T2: G09b INCONCLUSIVE when the control shows none (whatever the rule run shows)",
      _v(_pipres(0), _pipres(0))[0] == "INCONCLUSIVE" and _v(_pipres(0), _pipres(1))[0] == "INCONCLUSIVE" and _v(None, _pipres(0))[0] == "INCONCLUSIVE")
check("T2: G09b PASS when the control shows a window and the rule run none; INCONCLUSIVE when the rule run could not be built",
      _v(_pipres(1), _pipres(0))[0] == "PASS" and _v(_pipres(2), None)[0] == "INCONCLUSIVE")
_g09b_src = _live_src[_live_src.index('@gate("G09b"'):_live_src.index('@gate("G10"')]
_g09b_res_src = _live_src[_live_src.index("def g09b_result("):_live_src.index('@gate("G10"')]
_gs, _gt = LIVE.g09b_result(_pipres(1), _pipres(1), [], [], "x.json")
_ps, _pt = LIVE.g09b_result(_pipres(1), _pipres(0), [], [], "x.json")
_is, _it = LIVE.g09b_result(_pipres(0), _pipres(0), [], [], "x.json")
check("T2: the G09b gate returns the verdict's status (a control window and a rule window: FAIL; control only: PASS; no control: INCONCLUSIVE)",
      (_gs, _ps, _is) == ("FAIL", "PASS", "INCONCLUSIVE") and "return g09b_result(pip, rule, rows, notes, out)" in _g09b_src
      and "status, verdict = g09b_verdict(pip, rule)" in _g09b_res_src and "return status, " in _g09b_res_src and '"PASS"' not in _g09b_res_src,
      f"{_gs} {_ps} {_is}")
check("T2: the G09b gate answers with the verdict (no INFO any more) and says it is re-run on every Chromium update",
      "g09b_verdict(pip, rule)" in _g09b_src and '"INFO"' not in _g09b_src and "re-run on every Chromium update" in _g09b_src and "FAILING" in _live_src[_live_src.index("# summary"):][:300] + _live_src[_live_src.index("def main"):])
check("live clean-up: a failed test unit is reset after the stop (the session units have no --collect)",
      'self.systemctl("reset-failed", unit, timeout=15)' in _live_src and _live_src.count('self.systemctl("reset-failed", unit, timeout=15)') == 2)
check("live clean-up: cancel_pending runs before the test units are listed again, and it is the first step after the signals are ignored",
      _clean_src.index("cancel_pending(") < _clean_src.index("rig.cleanups") and _clean_src.index("cancel_pending(") < _clean_src.index('"list-units"')
      and _clean_src.index("signal.SIG_IGN") < _clean_src.index("cancel_pending("))
check("live clean-up: the warning print about a left-in-place host is inside a try/except (a closed pipe must not stop the clean-up)",
      re.search(r"if offenders:\s+try:\s+print\(f\"# clean-up: the host part is LEFT IN PLACE", _clean_src) is not None
      and "except Exception:      # a closed pipe" in _clean_src)
check("live clean-up: the Playwright browser and driver are closed under a time limit",
      "bounded_call(rig.browser.close" in _clean_src and "bounded_call(rig.pw.stop" in _clean_src)
check("live clean-up: it removes the firewall chain through remove_firewall (the old upload-only function is gone)",
      "L.remove_firewall(" in _clean_src and "remove_upload_rule" not in _live_src)
check("live bounded_call: a call that finishes is True, one that hangs is given up after the limit, one that raises is False, never an exception",
      LIVE.bounded_call(lambda: None, 2) is True and LIVE.bounded_call(lambda: 1 / 0, 2) is False
      and (lambda t0: (LIVE.bounded_call(lambda: _tm.sleep(10), 0.4) is False) and _tm.time() - t0 < 3)(_tm.time()))
check("live bounded_call: the alarm is disarmed afterwards", _sg.getitimer(_sg.ITIMER_REAL)[0] == 0.0)
check("live main: the first refusal uses the fail-closed offender check (slice_offenders), which also covers probe units, not a regex of one prefix",
      "rig.slice_offenders()" in _main_src[:_main_src.index("preexisting_state(")] and "UNIT_PREFIX) + r" not in _main_src)
check("live main: G01b is a HARD gate and runs right after G01", "G01b" in LIVE.HARD_GATES and _live_src.index('@gate("G01b"') > _live_src.index('@gate("G01"') and _live_src.index('@gate("G01b"') < _live_src.index('@gate("G02"'))

_lo = {"127.0.0.1": {"v6": False, "loopback": True}, "::1": {"v6": True, "loopback": True}}
_ad = {**_lo, "10.1.2.3": {"v6": False, "loopback": False}, "2001:db8::5": {"v6": True, "loopback": False}}
_Item = _ty.SimpleNamespace
_ha = LIVE.host_addresses({"lo": [_Item(family=_so.AF_INET, address="127.0.0.1"), _Item(family=_so.AF_INET6, address="::1"), _Item(family=_so.AF_PACKET, address="00:00")],
                           "eth0": [_Item(family=_so.AF_INET, address="10.1.2.3"), _Item(family=_so.AF_INET6, address="fe80::1"),
                                    _Item(family=_so.AF_INET6, address="fe80::2%eth0"), _Item(family=_so.AF_INET6, address="2001:db8::5")]})
check("G01b helpers: host_addresses keeps every IPv4 and IPv6 address incl. loopback, gives link-local the zone, skips other families",
      set(_ha) == {"127.0.0.1", "::1", "10.1.2.3", "fe80::1%eth0", "fe80::2%eth0", "2001:db8::5"} and _ha["::1"]["loopback"] and not _ha["10.1.2.3"]["loopback"] and _ha["fe80::1%eth0"]["v6"], str(_ha))
check("G01b helpers: pair_tested: v6 address never reaches a tcp4 socket; v4 reaches a tcp6 wildcard socket only when dual-stack",
      LIVE.pair_tested(True, "tcp6_autobind") and not LIVE.pair_tested(True, "tcp4_autobind") and LIVE.pair_tested(False, "tcp4_autobind")
      and LIVE.pair_tested(False, "tcp6_autobind") and not LIVE.pair_tested(False, "tcp6_autobind", bindv6only=True))
_srv = _so.socket()
_srv.bind(("127.0.0.1", 0))
_srv.listen(1)
_port = _srv.getsockname()[1]
_srv.close()
_srv = _so.socket()
_srv.bind(("127.0.0.1", 0))
_srv.listen(1)
check("G01b helpers: connect_outcome: a listener connects, a closed port is ECONNREFUSED, a name is unaddressable",
      LIVE.connect_outcome("127.0.0.1", _srv.getsockname()[1], 1.0) == "connected" and LIVE.connect_outcome("127.0.0.1", _port, 1.0) == "ECONNREFUSED"
      and LIVE.connect_outcome("localhost", 80, 1.0) == "unaddressable")
_srv.close()


def _unit(ports=None, errors=None, outbound="connected", outcomes=None, reported=True):
    return {"reported": reported, "ports": ports or {}, "errors": errors or {}, "outbound": outbound, "outcomes": outcomes or {}}


_names = ("tcp4_autobind", "tcp6_autobind", "tcp4_bind0", "tcp6_bind0", "tcp4_bind_fixed", "tcp6_bind_fixed")
_pairs = [(a, n) for a in _ad for n in _names if LIVE.pair_tested(_ad[a]["v6"], n)]
_ports = {n: 30000 + i for i, n in enumerate(_names)}
_ctl = _unit(_ports, outcomes={k: "connected" for k in _pairs})
_rule = _unit(_ports, outcomes={k: "timeout" for k in _pairs})
_sess = _unit({n: p for n, p in _ports.items() if not n.endswith("bind_fixed")}, {n: "EPERM" for n in _names if n.endswith("bind_fixed")},
              outcomes={k: "timeout" for k in _pairs if not k[1].endswith("bind_fixed")})
# ---- the helpers of the window-manager and clipboard gates (D2, D3, D4)
_pw = LIVE.parse_xwininfo('     0x400004 (has no name): ()  1x1+0+0  +0+0\n     0x500001 (has no name): ()  200x300+10+20  +10+20\n     0x400002 "t - Chromium": ("chromium (/tmp/x)" "Chromium")  800x600+0+0  +0+0\n        0x400003 (has no name): ()  5x5+0+0  +0+0\n')
check("live: xwininfo -tree lists top-level windows that have no class (menus), not their children",
      [(w["id"], w["cls"], w["w"], w["h"]) for w in _pw] == [("0x400004", "", 1, 1), ("0x500001", "", 200, 300), ("0x400002", "Chromium", 800, 600)])
check("live: xwininfo -stats is parsed (geometry, override-redirect, map state)",
      LIVE.parse_stats("  Absolute upper-left X:  0\n  Absolute upper-left Y:  -5\n  Width: 1280\n  Height: 720\n  Map State: IsViewable\n  Override Redirect State: no\n")
      == {"x": 0, "y": -5, "w": 1280, "h": 720, "or": False, "viewable": True}
      and LIVE.parse_stats("  Width: 90\n  Height: 20\n  Map State: IsUnMapped\n  Override Redirect State: yes\n")["or"] is True
      and LIVE.parse_stats("  Map State: IsUnMapped\n")["viewable"] is False and LIVE.parse_stats("")["w"] is None)
check("live: Chromium's minimum width is read from WM_NORMAL_HINTS",
      LIVE.parse_min_width("WM_NORMAL_HINTS(WM_SIZE_HINTS):\n\t\tprogram specified minimum size: 500 by 160\n") == 500 and LIVE.parse_min_width("") is None and LIVE.parse_min_width(None) is None)
check("live: js_codepoints builds a text from ASCII only (no character above U+FFFF in a typed address)",
      LIVE.js_codepoints("a\u00e9\U0001F600") == "String.fromCodePoint(97,233,128512)" and LIVE.js_codepoints("a\u00e9\U0001F600").isascii())
_wi = LIVE.describe_windows([{"w": 1280, "h": 720, "x": 0, "y": 0, "or": False, "transient": True, "type": "DIALOG"}])
check("live: describe_windows names size, position, transient and type", _wi == "1280x720+0+0 transient type=DIALOG" and LIVE.describe_windows([]) == "none")
check("live: the window gates compare the Chromium window to the screen, G11 sizes include the minimum, the maximum and a size that snaps",
      all(x in _live_src for x in ("(560, 480), (1920, 1200), (1001, 701), (300, 200)", "wait_main_window", "--remote-debugging", "WM_NORMAL_HINTS", "policy_without(rig, \"DownloadRestrictions\")",
                                   "policy_without(rig, \"AllowFileSelectionDialogs\")", "NO_CLIPBOARD_FLAGS = ()", "selection_owners")))
check("live: the clipboard gates never print or save the copied text (booleans and byte counts only)",
      "print(" not in _live_src[_live_src.index('@gate("G17"'):_live_src.index('@gate("G18"')] and "save(" not in _live_src[_live_src.index('@gate("G17"'):_live_src.index('@gate("G18"')])

_j = LIVE.judge_g01b
check("G01b verdict: control connects everywhere, both units with the filter time out everywhere, outbound works, fixed bind refused: PASS", _j(_ad, _sess, _rule, _ctl)[0] is True, _j(_ad, _sess, _rule, _ctl)[1])
check("G01b verdict: a listener in the slice that CONNECTS fails (the rule does not work)",
      _j(_ad, _sess, _unit(_ports, outcomes={**{k: "timeout" for k in _pairs}, ("10.1.2.3", "tcp4_autobind"): "connected"}), _ctl)[0] is False)
check("G01b verdict: the session unit connecting fails too", _j(_ad, _unit(_sess["ports"], _sess["errors"], outcomes={**_sess["outcomes"], ("127.0.0.1", "tcp4_autobind"): "connected"}), _rule, _ctl)[0] is False)
check("G01b verdict: a refused connection is not a pass (no listener there: nothing proven)",
      _j(_ad, _sess, _unit(_ports, outcomes={**{k: "timeout" for k in _pairs}, ("::1", "tcp6_autobind"): "ECONNREFUSED"}), _ctl)[0] is False)
check("G01b verdict: no positive control (the control's listener cannot be reached) fails", _j(_ad, _sess, _rule, _unit(_ports, outcomes={k: "timeout" for k in _pairs}))[0] is False)
check("G01b verdict: a control that does not report fails", _j(_ad, _sess, _rule, _unit(reported=False))[0] is False)
check("G01b verdict: a control reached only on loopback, or only on a non-loopback address, fails",
      _j(_ad, _sess, _rule, _unit(_ports, outcomes={k: ("connected" if _ad[k[0]]["loopback"] else "timeout") for k in _pairs}))[0] is False
      and _j(_ad, _sess, _rule, _unit(_ports, outcomes={k: ("connected" if not _ad[k[0]]["loopback"] else "timeout") for k in _pairs}))[0] is False)
check("G01b verdict: the filter-only unit must really listen (else the filter was not exercised)",
      _j(_ad, _sess, _unit({"tcp4_autobind": 1}, {"tcp6_autobind": "EAFNOSUPPORT"}, outcomes={}), _ctl)[0] is False)
check("G01b verdict: a failed outbound connection from the session unit fails", _j(_ad, _unit(_sess["ports"], _sess["errors"], "timeout", _sess["outcomes"]), _rule, _ctl)[0] is False)
check("G01b verdict (D1): a fixed-port bind that works in the session unit is NOT judged: its listener only has to time out",
      _j(_ad, _unit(_ports, outcomes={k: "timeout" for k in _pairs}), _rule, _ctl)[0] is True
      and _j(_ad, _unit(_ports, outcomes={**{k: "timeout" for k in _pairs}, ("127.0.0.1", "tcp4_bind_fixed"): "connected"}), _rule, _ctl)[0] is False)
_att_ok = {"session": True, "filter-only": True, "control": False}
check("G01b verdict: the filter must be attached to the session and filter-only units and not to the control",
      _j(_ad, _sess, _rule, _ctl, _att_ok)[0] is True and _j(_ad, _sess, _rule, _ctl, {**_att_ok, "session": False})[0] is False
      and _j(_ad, _sess, _rule, _ctl, {**_att_ok, "filter-only": False})[0] is False and _j(_ad, _sess, _rule, _ctl, {**_att_ok, "control": True})[0] is False
      and _j(_ad, _sess, _rule, _ctl, {"session": True})[0] is False)
check("G01b verdict: an address the control cannot reach is not judged (and is named), the rest still counts",
      (lambda r: r[0] is True and "10.1.2.3/tcp4_autobind" in r[1])(_j(_ad, _sess, _rule, _unit(_ports, outcomes={**{k: "connected" for k in _pairs}, ("10.1.2.3", "tcp4_autobind"): "EHOSTUNREACH"}))))
_ref = {"tcp6_autobind": "EPERM", "tcp4_bind0": "EPERM", "tcp6_bind0": "EPERM", "tcp4_bind_fixed": "EPERM", "tcp6_bind_fixed": "EPERM"}
check("G01b verdict: listen() refused outright by the kernel in the session unit (EPERM) is fine; another error is not",
      _j(_ad, _unit({"tcp4_autobind": 1}, _ref, outcomes={k: "timeout" for k in _pairs if k[1] == "tcp4_autobind"}), _rule, _ctl)[0] is True
      and _j(_ad, _unit({"tcp4_autobind": 1}, {**_ref, "tcp6_autobind": "EINVAL"}, outcomes={}), _rule, _ctl)[0] is False)
check("G01b verdict: a port-0 listener that connects in the slice fails like any other",
      _j(_ad, _sess, _unit(_ports, outcomes={**{k: "timeout" for k in _pairs}, ("127.0.0.1", "tcp4_bind0"): "connected"}), _ctl)[0] is False)
_g1b = _live_src[_live_src.index('@gate("G01b"'):_live_src.index('@gate("G02"')]
check("G01b: three units in the slice (the control only without the filter), connects come from this process with 3 s, the filter is verified on every cgroup",
      '"SocketBindDeny=any"' in _g1b and '"IPAddressDeny=" + " ".join(rig.deny)' in _g1b and '"IPIngressFilterPath=" + rig.pin' in _g1b and '"--slice=system.slice"' not in _g1b
      and "connect_outcome, j[1], j[3], 3.0" in _g1b and "L.ingress_attached(" in _g1b and "judge_g01b(addrs, data[\"session\"], data[\"filter-only\"], data[\"control\"], att)" in _g1b
      and _g1b.count("rig.run_unit(") == 1 and "wait=False" in _g1b and "rig.stop_unit(unit)" in _g1b and "host.get(\"firewall\")" not in _g1b and "SYN-ACK" not in _g1b)
_g1 = _live_src[_live_src.index('@gate("G01",'):_live_src.index('@gate("G01b"')]
check("G01 (D1): no judgement on binds (the bind detail is only reported), no SocketBindDeny fallback pair, no SYN-ACK",
      'bind["ok"]' not in _g1 and "SocketBindDeny=tcp" not in _g1 and "FALLBACK" not in _g1 and "not judged" in _g1 and "SYN-ACK" not in _g1)
_cl_src = _live_src[_live_src.index("def cleanup(rig):"):]
check("live clean-up removes only the tmp directories of this run's own units (the tmpfs is shared with the feature)",
      "sweep_tmp" not in _cl_src and "rig.launcher.remove_tmp(" in _cl_src and "for u in rig.units" in _cl_src)
check("the live test hands the pin to build_unit_args, the probe launcher and the host clean-up and removes its own pin",
      "ingress_pin=self.pin" in _live_src and "bpf_base=self.bpf_base" in _live_src and "bpf_pin=pin_arg" in _live_src and "rbrowser_bpf.unpin(rig.pin)" in _live_src
      and 'bpf_base = f"/sys/fs/bpf/portal-rblive-' in _live_src)
check("G01b: the listener script makes socket(); listen() with no bind and a bind to port 0 on tcp4 and tcp6, one normal bind, a backlog of 1024, and an outbound connect",
      "listen(1024)" in LIVE.LISTEN_SNIPPET and "listen(5)" not in LIVE.LISTEN_SNIPPET
      and "rec(\"tcp4_bind0\", socket.AF_INET, (\"0.0.0.0\", 0))" in LIVE.LISTEN_SNIPPET and "rec(\"tcp6_bind0\", socket.AF_INET6, (\"::\", 0))" in LIVE.LISTEN_SNIPPET
      and "rec(\"tcp4_autobind\", socket.AF_INET)" in LIVE.LISTEN_SNIPPET and "rec(\"tcp6_autobind\", socket.AF_INET6)" in LIVE.LISTEN_SNIPPET and "tcp4_bind_fixed" in LIVE.LISTEN_SNIPPET
      and "create_connection((\"1.1.1.1\", 443)" in LIVE.LISTEN_SNIPPET and f"time.sleep({LIVE.LISTEN_HOLD_S})" in LIVE.LISTEN_SNIPPET and LIVE.LISTEN_HOLD_S < 120)
_ns = {}
import contextlib as _cl, io as _io  # noqa: E402
with _cl.redirect_stdout(_io.StringIO()):
  exec(compile(LIVE.LISTEN_SNIPPET.replace("time.sleep(%d)" % LIVE.LISTEN_HOLD_S, "pass").replace('("1.1.1.1", 443)', '("127.0.0.1", 9)'), "listen-snippet", "exec"), _ns)
check("G01b: the listener script runs as written on this host (its one outbound target swapped for a closed loopback port) and reports ports for its listeners",
      _ns["res"]["ports"].get("tcp4_autobind", 0) > 0 and _ns["res"]["ports"].get("tcp4_bind_fixed", 0) >= 20000 and set(_ns["res"]) == {"ports", "errors", "outbound"}, str(_ns.get("res")))
for _s_ in _ns.get("KEEP", []):
    _s_.close()

_env = {k: v for k, v in os.environ.items() if k != "RBROWSER_LIVE"}
_r = _sp.run([sys.executable, "-B", str(ROOT / "tests" / "test_rbrowser_live.py")], env=_env, capture_output=True, text=True, timeout=30)
check("live test: without the variable it prints skip: and exits 0, starting nothing", _r.returncode == 0 and _r.stdout.startswith("skip:"), _r.stdout + _r.stderr)
if os.geteuid() != 0:
    _r = _sp.run([sys.executable, "-B", str(ROOT / "tests" / "test_rbrowser_live.py"), "--round", "1"], env={**_env, "RBROWSER_LIVE": "1"},
                 capture_output=True, text=True, timeout=30)
    check("live test: with the variable but not as root it refuses (exit 2) and starts nothing", _r.returncode == 2 and _r.stdout.startswith("refused:"), _r.stdout)


# ---------------------------------------------------------------- 1.26.0: the member's portal theme
import json as _json  # noqa: E402

THEME_FILE_PATH = f"{THEMED}/0123456789ab.json"
THEME_DEST = "/etc/chromium/policies/managed/portal-theme.json"
TS = spec(theme_color="#1A1A2E", theme_mode="dark")
base_args = BA(spec())
check("theme: a spec without a theme gives exactly the arguments of a host without one (no bind, no RB_THEME_MODE)",
      BA(spec(theme_color=None, theme_mode=None)) == base_args and not any("portal-theme" in a or "RB_THEME_MODE" in a for a in base_args))
check("theme: the colour in the spec alone changes nothing in the arguments (the launcher decides on the file)", BA(spec(theme_color="#1a1a2e")) == base_args)
themed = BA(TS, theme_file=THEME_FILE_PATH)
bind = f"BindReadOnlyPaths={THEME_FILE_PATH}:{THEME_DEST}"
pt = props(themed)
check("theme: the file is bound read-only over the placeholder, once, after the /etc/chromium bind and before /etc/chromium.d",
      pt.count(bind) == 1 and pt.index(bind) == pt.index("BindReadOnlyPaths=/run/portal-rb-static/chromium:/etc/chromium") + 1
      and pt.index(bind) + 1 == pt.index("BindReadOnlyPaths=/run/portal-rb-static/chromium.d:/etc/chromium.d"))
check("theme: the mode is one -E RB_THEME_MODE=dark before the program; nothing else is added",
      "RB_THEME_MODE=dark" in themed and themed[themed.index("RB_THEME_MODE=dark") - 1] == "-E" and themed[-4:] == base_args[-4:]
      and len(themed) == len(base_args) + 4)
stripped = list(themed)
i = stripped.index(bind); del stripped[i - 1:i + 1]
j = stripped.index("RB_THEME_MODE=dark"); del stripped[j - 1:j + 1]
check("theme: without those two additions the list is the no-theme list", stripped == base_args)
check("theme: a light mode is passed too, a bad mode or colour never is",
      "RB_THEME_MODE=light" in BA(spec(theme_mode="light")) and all(not any("RB_THEME_MODE" in a for a in BA(spec(theme_mode=m)))
                                                               for m in ("evil", "", "DARK 1", "dark\n", None, 5, ["dark"])))
check("theme: the mode is lower-cased by the validator, so only the two words can reach the environment",
      "RB_THEME_MODE=dark" in BA(spec(theme_mode="DARK")) and not any(a.startswith("RB_THEME_MODE=") and a not in ("RB_THEME_MODE=dark", "RB_THEME_MODE=light")
                                                                    for m in ("dark;rm", "light ", "x") for a in BA(spec(theme_mode=m))))
for label, bad in (("relative", "run/x/0123456789ab.json"), ("another id", f"{THEMED}/aaaaaaaaaaaa.json"), ("a colon", f"{THEMED}:x/0123456789ab.json"),
                   ("dotdot", f"{THEMED}/../0123456789ab.json"), ("a space", f"{THEMED} x/0123456789ab.json"), ("a newline", f"{THEMED}/0123456789ab.json\n"),
                   ("no .json", f"{THEMED}/0123456789ab"), ("empty", ""), ("a number", 5), ("a double slash", f"{THEMED}//0123456789ab.json")):
    check(f"theme: a theme file path that is {label} is refused", raises(LaunchError, BA, TS, theme_file=bad))
check("theme: the preflight probe never gets a theme (no file allowed, no mode passed)",
      raises(LaunchError, BA, TS, L.PROBE_PREFIX, "probe.py", 19, theme_file=THEME_FILE_PATH)
      and BA(TS, L.PROBE_PREFIX, "probe.py", 19) == BA(spec(), L.PROBE_PREFIX, "probe.py", 19))
check("theme: the placeholder file name is the policy module's file name and the destination sits in the managed directory",
      L.THEME_FILE == rbrowser_policy.THEME_FILE_NAME and L.THEME_DEST == THEME_DEST)

# the static tree: a placeholder in the session tree only; the main policy file is the one source of the security policy
_pt = tempfile.mkdtemp(prefix="rbtest-static-tree-")
_atexit.register(_shutil.rmtree, _pt, ignore_errors=True)
_hp = L.HostPaths(static=f"{_pt}/static", run_dir=f"{_pt}/run", state=f"{_pt}/state", tmp_dir=f"{_pt}/tmp")
L.write_static_tree(_hp, POLICY)
_ph = f"{_pt}/static/chromium/policies/managed/portal-theme.json"
check("static tree: the session tree has the empty placeholder, the probe tree has none, the main policy is unchanged",
      _json.load(open(_ph)) == {} and not os.path.exists(f"{_pt}/static/chromium-probe/policies/managed/portal-theme.json")
      and _json.load(open(f"{_pt}/static/chromium/policies/managed/portal.json")) == POLICY
      and sorted(os.listdir(f"{_pt}/static/chromium/policies/managed")) == ["portal-theme.json", "portal.json"])
L.write_policy(_hp, POLICY)
check("static tree: write_policy leaves the placeholder alone", _json.load(open(_ph)) == {})
check("static tree: the placeholder is root-owned like the rest (written by the same code, 0644)", stat.S_IMODE(os.stat(_ph).st_mode) == 0o644)


async def theme_launcher_tests():
    sd = tempfile.mkdtemp(prefix="rbtest-theme-static-")
    td = tempfile.mkdtemp(prefix="rbtest-theme-dir-")
    _atexit.register(_shutil.rmtree, sd, ignore_errors=True)
    _atexit.register(_shutil.rmtree, td, ignore_errors=True)
    tpath = f"{td}/0123456789ab.json"

    def mk(h, seen=None, **kw):
        async def run(argv, timeout=10.0):
            if seen is not None and os.path.basename(argv[0]) == "systemd-run":
                seen["file_at_start"] = os.path.isfile(tpath)
                if seen["file_at_start"]:
                    seen["st"] = os.stat(tpath)
                    seen["text"] = open(tpath).read()
                seen["dir_mode"] = stat.S_IMODE(os.stat(td).st_mode) if os.path.isdir(td) else None
            return await h.run(argv, timeout)
        kw.setdefault("theme_dir", td)
        kw.setdefault("static_dir", sd)
        return LN(run=run, read_text=h.reader, sleep=h.sleep, which=which_all, **kw)

    # no placeholder yet (prepare_host has not run since the upgrade): the session starts, without the colour
    h = Host(); seen = {}
    ln = mk(h, seen)
    res = await ln.start(TS)
    call = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"][0]
    check("theme launcher: no placeholder in the static tree: the session starts without a theme file and without the bind, the mode still goes",
          res.unit.endswith("0123456789ab.service") and not seen["file_at_start"] and not os.path.exists(tpath)
          and call[1:] == BA(spec(theme_color="#1a1a2e", theme_mode="dark")) and "RB_THEME_MODE=dark" in call and not any("portal-theme" in a for a in call))
    await ln.stop(res.unit)

    L.write_static_tree(L.HostPaths(static=sd, run_dir=f"{sd}/r", state=f"{sd}/s", tmp_dir=f"{sd}/t"), POLICY)
    h = Host(); seen = {}
    ln = mk(h, seen)
    res = await ln.start(TS)
    call = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"][0]
    check("theme launcher: the file exists BEFORE systemd-run, with exactly the colour key, lower case, in a root-only directory",
          seen["file_at_start"] and _json.loads(seen["text"]) == {"BrowserThemeColor": "#1a1a2e"} and set(_json.loads(seen["text"])) == set(rbrowser_policy.THEME_POLICY_KEYS)
          and seen["dir_mode"] == 0o700, str(seen))
    check("theme launcher: the file is owned by the portal's own user (root in production), mode 0444, a plain file",
          seen["st"].st_uid == os.getuid() and stat.S_IMODE(seen["st"].st_mode) == 0o444 and stat.S_ISREG(seen["st"].st_mode))
    check("theme launcher: systemd-run gets the bind of that very file and RB_THEME_MODE",
          call[1:] == BA(TS, theme_file=tpath) and f"BindReadOnlyPaths={tpath}:{THEME_DEST}" in props(call))
    check("theme launcher: nothing else of the spec's theme reaches the call (no colour text outside the file path)", not any("1a1a2e" in a.lower() for a in call))
    await ln.stop(res.unit)
    check("theme launcher: stop removes the file with the unit's other per-ident files", not os.path.exists(tpath) and not os.path.exists(f"{TMPD}/0123456789ab"))

    # a failed start takes the file back
    for label, kw in (("systemd-run fails", dict(sysrun_rc=1)), ("the unit runs as root", dict(uid=0))):
        h = Host(); h.sysrun_rc = kw.get("sysrun_rc", 0)
        h2 = Host(uid=kw["uid"]) if "uid" in kw else h
        lnf = mk(h2)
        check(f"theme launcher: {label}: LaunchError, and no theme file is left", await _raises_async(LaunchError, lnf.start(TS)) and not os.path.exists(tpath))
    # a cancelled systemd-run takes it back too
    h = Host(); h.sysrun_exc = asyncio.CancelledError()
    lnc = mk(h)
    try:
        await lnc.start(TS)
        cancelled = False
    except asyncio.CancelledError:
        cancelled = True
    check("theme launcher: a cancelled start leaves no theme file", cancelled and not os.path.exists(tpath))

    # the sweep covers the theme files: stale ones go, live ones and foreign names stay
    for n in ("aaaaaaaaaaaa", "bbbbbbbbbbbb"):
        open(f"{td}/{n}.json", "w").write("{}")
    open(f"{td}/not-an-id.json", "w").write("x")
    os.symlink("/etc/passwd", f"{td}/cccccccccccc.json")
    got = ln.sweep_tmp(["aaaaaaaaaaaa"])
    check("theme launcher: sweep_tmp removes stale theme files too, keeps a live unit's and names that are no unit id; a link is unlinked, not followed",
          sorted(got) == ["bbbbbbbbbbbb", "cccccccccccc"] and os.path.exists(f"{td}/aaaaaaaaaaaa.json") and os.path.exists(f"{td}/not-an-id.json")
          and not os.path.lexists(f"{td}/bbbbbbbbbbbb.json") and not os.path.lexists(f"{td}/cccccccccccc.json") and os.path.exists("/etc/passwd"), str(got))
    ln.remove_theme("../x"); ln.remove_theme("aaaaaaaaaaaa/..")
    check("theme launcher: remove_theme refuses anything that is not a 12 hex id", os.path.exists(f"{td}/aaaaaaaaaaaa.json"))
    for n in os.listdir(td):
        os.unlink(f"{td}/{n}")
    check("theme launcher: a missing theme directory sweeps to nothing", LN(theme_dir=f"{td}/none", tmp_dir=f"{sd}/no-tmp").sweep_tmp([]) == [])

    # nothing to write or nowhere to write: the session starts without the theme (it is cosmetic)
    for label, sp in (("an invalid colour", spec(theme_color="red", theme_mode="dark")), ("no colour", spec(theme_color=None, theme_mode="light")),
                      ("only a bad mode", spec(theme_color=None, theme_mode="evil"))):
        h = Host(); seen = {}
        lnx = mk(h, seen)
        r2 = await lnx.start(sp)
        call = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"][0]
        check(f"theme launcher: {label}: no file, no bind, the call is the plain one (plus the valid mode, if any)",
              not seen["file_at_start"] and not any("portal-theme" in a for a in call) and call[1:] == BA(sp))
        await lnx.stop(r2.unit)
    blocker = f"{td}/blocked"
    open(blocker, "w").write("x")
    h = Host()
    lnb = mk(h, theme_dir=blocker)
    r3 = await lnb.start(TS)
    call = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"][0]
    check("theme launcher: a theme directory that cannot be made does not fail the start; the session runs without the colour",
          r3.unit.endswith("0123456789ab.service") and not any("portal-theme" in a for a in call) and call[1:] == BA(TS))
    await lnb.stop(r3.unit)
    # the probe launcher never writes a theme
    h = Host(); seen = {}
    lnp = mk(h, seen, unit_prefix=L.PROBE_PREFIX, script="probe.py", nice=19)
    r4 = await lnp.start(TS)
    call = [c for c, _ in h.calls if os.path.basename(c[0]) == "systemd-run"][0]
    check("theme launcher: the probe launcher writes no theme file and its call has neither bind nor mode",
          not seen["file_at_start"] and call[1:] == BA(spec(), L.PROBE_PREFIX, "probe.py", 19))
    await lnp.stop(r4.unit)
    check("theme launcher: no per-session file survives any of the above", os.listdir(td) == ["blocked"] or sorted(os.listdir(td)) == ["blocked"])


asyncio.run(theme_launcher_tests())

if failures:
    print(f"\ntest_rbrowser_unit_args: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_rbrowser_unit_args: all checks passed")
