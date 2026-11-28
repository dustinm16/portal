"""The preflight probe (design section 8.2): runs inside a `portal-rbprobe-<hex>` unit that has exactly the
session's properties (plus Nice=19) and checks, from the inside, that the containment holds.

    /usr/bin/python3 -I -S /mnt/probe.py

Standard library only. Targets (addresses, ports, the hidden-path list, the expected mount sizes) come from
/mnt/probe-targets.json, which the portal writes into the static tree. One JSON object on stdout, one line:

    {"ok": bool, "checks": [{"name": ..., "ok": bool, "detail": "..."}], "abstract_connectable": n,
     "listen_ports": {"tcp4_autobind": port or null, ...}}      (the bind check is report-only, see check_bind)

The eight checks run concurrently, every connect has a 2 s limit, and the whole run ends before 40 s: a check
that has not finished at 36 s is reported as failed. No request to a third party is made. Nothing here prints
a URL of a page (the only URLs are the fixed test pages: a data: page and file:///etc/hostname).

Exit status: 0 when every check passed, 1 otherwise.
"""

import concurrent.futures
import errno
import importlib.util
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time

TARGETS_PATH = "/mnt/probe-targets.json"
CONNECT_S = 2.0
TOTAL_S = 36.0
CHROMIUM_RUN_S = 10.0      # one headless run takes 0.6 to 4 s here, also with the probe's other checks running
CHROMIUM_ATTEMPTS = 2      # about one headless launch in 200 never ends (see _dump_dom): a run that hit the limit is repeated once
SANDBOX_POLL_S = 12.0
SANDBOX_SETTLE_S = 1.5     # a renderer is judged when no further renderer has appeared for this long
WALK_ROOTS = ("/run", "/var/run", "/tmp", "/var/lib")
WALK_DEPTH = 4
# /tmp is the unit's own PrivateTmp directory, and the probe's own Xvfb (check_display_proof, running at the same time)
# puts its socket in /tmp/.X11-unix: that one is not a host socket.
OWN_SOCKET_DIRS = ("/tmp/.X11-unix",)
WALK_MAX_CONNECTS = 300
ABSTRACT_MAX = 200
BLOCK_MARKER = "ERR_BLOCKED_BY_ADMINISTRATOR"
DEFAULT_EXPECT = {"work_mb": 768, "shm_mb": 64, "run_kb": 64, "runtime_mb": 8, "tmp_mb": 32}

# connect() outcomes that mean "the packet never got anywhere" (a dropped packet is a time-out) ...
BLOCKED_ERRNOS = {errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
                  errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.ETIMEDOUT}
# ... and the ones that mean the other end answered, so the filter did not work.
REACHED_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET}


# ================================================================ pure helpers

def classify_connect(outcome):
    """outcome: 0 (connected), 'timeout', or an errno number. -> 'blocked' | 'reachable' | 'inconclusive'.
    A refused or reset connection is NOT a pass: it means the packet arrived (IPAddressDeny drops, it does not
    refuse)."""
    if outcome == 0:
        return "reachable"
    if outcome == "timeout":
        return "blocked"
    if outcome in REACHED_ERRNOS:
        return "reachable"
    if outcome in BLOCKED_ERRNOS:
        return "blocked"
    return "inconclusive"


def classify_bind(outcome):
    """outcome: 0 (bound), or an errno. EPERM/EACCES (above port 1023) is the SocketBindDeny rule; EADDRINUSE
    says nothing."""
    if outcome == 0:
        return "bound"
    if outcome in (errno.EPERM, errno.EACCES):
        return "blocked"
    if outcome == errno.EADDRINUSE:
        return "busy"
    return "inconclusive"


def path_blocked(path, lstat=os.lstat, listdir=os.listdir, opener=None):
    """True when `path` cannot be used from inside the unit: it does not exist, or access is refused (an
    InaccessiblePaths= entry is an empty mode-000 node mounted over the path, so lstat() itself may work).
    Returns (blocked, why)."""
    opener = opener or (lambda p: open(p, "rb").close())
    try:
        st = lstat(path)
    except OSError as e:
        return (e.errno in (errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTDIR), errno.errorcode.get(e.errno, "error"))
    if stat.S_ISDIR(st.st_mode):
        try:
            names = listdir(path)
        except OSError as e:
            return (e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT), errno.errorcode.get(e.errno, "error"))
        return (not names and stat.S_IMODE(st.st_mode) == 0, "listable")
    try:
        opener(path)
    except OSError as e:
        return (e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT), errno.errorcode.get(e.errno, "error"))
    return (False, "opens")


def size_matches(total_bytes, expected_bytes, tolerance=0.01):
    return expected_bytes > 0 and abs(total_bytes - expected_bytes) <= expected_bytes * tolerance


def parse_userns(link):
    m = re.fullmatch(r"user:\[(\d+)\]", link or "")
    return int(m.group(1)) if m else None


def parse_pidns(link):
    m = re.fullmatch(r"pid:\[(\d+)\]", link or "")
    return int(m.group(1)) if m else None


# Chromium rewrites its argv, so the whole command line of a child can sit in ONE string: the type is read with a regex
# from the joined text, never from an argument list. Flags that switch off a layer of Chromium's own sandbox (spelled
# without the dashes here, so that this file never holds the literal flag).
FORBIDDEN_FLAG_NAMES = ("no-sandbox", "disable-setuid-sandbox", "disable-seccomp-filter-sandbox", "disable-namespace-sandbox")
_TYPE_RE = re.compile(r"(?:^|\s)--type=([A-Za-z0-9_-]+)")
_SUBTYPE_RE = re.compile(r"(?:^|\s)--utility-sub-type=([A-Za-z0-9_.-]+)")


def classify_cmdline(raw):
    """The raw bytes (or text) of /proc/<pid>/cmdline -> (type, utility sub-type or None). The browser process has no
    --type= and is 'browser'. NULs are turned into spaces first: both the one-string form and the argument list work."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    text = text.replace("\0", " ")
    m = _TYPE_RE.search(text)
    sub = _SUBTYPE_RE.search(text)
    return (m.group(1) if m else "browser"), (sub.group(1) if sub else None)


def forbidden_flags(raw):
    """Names (without dashes) of the sandbox-disabling flags a command line holds, in the order of FORBIDDEN_FLAG_NAMES."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    text = text.replace("\0", " ")
    return [n for n in FORBIDDEN_FLAG_NAMES if re.search(r"(?:^|\s)--" + re.escape(n) + r"(?=$|[\s=])", text)]


def status_number(text, field):
    """'Seccomp:\t2' in the text of /proc/<pid>/status -> 2, or None."""
    m = re.search(r"^" + re.escape(field) + r":\s*(\d+)\s*$", text or "", re.M)
    return int(m.group(1)) if m else None


def sample_process(pid):
    """What the probe sees of one process: {pid, type, sub, user, pidns, seccomp, nnp, flags} or None when it is gone. The
    command line is read LAST: a process that exits in between has an empty one and is skipped, not judged. A value
    that cannot be read is None (under ProtectProc the probe may not see a process's namespaces)."""
    def link(name):
        try:
            return os.readlink(f"/proc/{pid}/ns/{name}")
        except OSError:
            return None
    user, pidns = link("user"), link("pid")
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            status = f.read()
    except OSError:
        status = ""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read()
    except OSError:
        return None
    if not cmd.strip(b"\0"):
        return None
    ptype, sub = classify_cmdline(cmd)
    return {"pid": pid, "type": ptype, "sub": sub, "user": parse_userns(user), "pidns": parse_pidns(pidns),
            "seccomp": status_number(status, "Seccomp"), "nnp": status_number(status, "NoNewPrivs"), "flags": forbidden_flags(cmd)}


def merge_sample(old, new):
    """One process seen twice: the later sighting, unless it lost the user namespace that the earlier one could read
    (the process died between two reads). A namespace that was never readable stays unreadable."""
    if old is None or new is None:
        return new or old
    if new["user"] is None and old["user"] is not None:
        return old
    return new


def renderer_problems(r, main_user, main_pid_ns):
    """Why one renderer does not prove Chromium's own sandbox (a list of short texts; empty = it does)."""
    out = []
    if r["user"] is None:
        out.append("user namespace unreadable (under ProtectProc the probe may not see it: unproven)")
    elif main_user is not None and r["user"] == main_user:
        out.append("in the browser's user namespace")
    if r["pidns"] is None:
        out.append("pid namespace unreadable")
    elif main_pid_ns is not None and r["pidns"] == main_pid_ns:
        out.append("in the browser's pid namespace")
    if r["seccomp"] != 2:
        out.append(f"Seccomp {r['seccomp']}")
    if r["nnp"] != 1:
        out.append(f"NoNewPrivs {r['nnp']}")
    if r["flags"]:
        out.append("flag " + ", ".join("--" + n for n in r["flags"]))
    return out


def _short_sub(sub):
    return (sub or "?").rsplit(".", 1)[-1]


def sandbox_verdict(browser, procs):
    """The decision of check 8, pure. `browser` and `procs` are sample_process() results: the headless browser and every
    process below it that was seen. -> (ok, detail). PASS only when at least one renderer was seen, EVERY renderer has a
    readable user namespace and a pid namespace that both differ from the browser's, Seccomp 2 and NoNewPrivs 1 and none of the
    sandbox-disabling flags, and the browser (and every other process seen) has none of them either. The unit's own
    system call filter gives EVERY process Seccomp 2 and NoNewPrivs 1, so those two are necessary, not the proof: the
    namespace difference is the proof of Chromium's own namespace sandbox. The detail names counts and verdicts only."""
    procs = list(procs)
    if browser is None:
        return False, "the browser process could not be read (it ended or is not visible): no sandbox state proven"
    renderers = [p for p in procs if p["type"] == "renderer"]
    counts = {}
    for p in procs:
        key = p["type"] if p["type"] != "utility" else "utility"
        counts[key] = counts.get(key, 0) + 1
    subs = {}
    for p in procs:
        if p["type"] == "utility":
            subs[_short_sub(p["sub"])] = subs.get(_short_sub(p["sub"]), 0) + 1
    others = [f"{n} {t}" for t, n in sorted(counts.items()) if t != "renderer"]
    if subs:
        others = [o + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(subs.items())) + ")" if o.endswith(" utility") else "") for o in others]
    seen = f"seen: {len(renderers)} renderer, " + (", ".join(others) if others else "no other process")
    problems = []
    if browser["flags"]:
        problems.append("the browser's command line holds " + ", ".join("--" + n for n in browser["flags"]))
    helpers_flagged = [p for p in procs if p["type"] != "renderer" and p["flags"]]
    if helpers_flagged:
        problems.append(f"{len(helpers_flagged)} helper processes hold " + ", ".join("--" + n for n in sorted({n for p in helpers_flagged for n in p["flags"]})))
    if browser["user"] is None or browser["pidns"] is None:
        problems.append("the browser's own namespaces are unreadable")
    if not renderers:
        problems.append("no renderer process was observed")
    groups = {}
    for r in renderers:                       # renderers with the same findings are one line: the detail is short
        why = tuple(renderer_problems(r, browser["user"], browser["pidns"]))
        if why:
            groups[why] = groups.get(why, 0) + 1
    for why, n in groups.items():
        problems.append(f"{n} of {len(renderers)} renderers: " + ", ".join(why))
    if problems:
        return False, "; ".join(problems) + f". {seen}"      # reasons first: result() cuts at 300 characters, a cut drops counts, not reasons
    return True, (f"every one of {len(renderers)} renderers runs in its own user and pid namespace with Seccomp 2 and NoNewPrivs 1, "
                  f"no sandbox-disabling flag on the browser or a renderer. {seen}")


def data_url(marker):
    """A page whose text exists only if its script ran: the marker is assembled, never written out."""
    a, b = marker[:6], marker[6:]
    return ("data:text/html,%3Cbody%3E%3Cscript%3Edocument.body.textContent%3D%5B%27" + a + "%27%2C%27" + b +
            "%27%5D.join%28%27%27%29%3C%2Fscript%3E")


def result(name, ok, detail):
    return {"name": name, "ok": bool(ok), "detail": str(detail)[:300]}


def summarize(checks, abstract_connectable=0):
    """{"ok", "checks", "abstract_connectable", "listen_ports"}: listen_ports is the bind check's report of the ports a
    listener got ({} when that check did not run); it never decides `ok`."""
    ports = {}
    for c in checks:
        if c.get("name") == "bind" and isinstance(c.get("listen_ports"), dict):
            ports = c["listen_ports"]
    return {"ok": bool(checks) and all(c["ok"] for c in checks), "checks": checks, "abstract_connectable": abstract_connectable,
            "listen_ports": ports}


def read_targets(path=TARGETS_PATH):
    with open(path, "r", encoding="utf-8") as f:
        t = json.load(f)
    if not isinstance(t, dict) or t.get("version") != 1:
        raise ValueError("unknown targets file")
    return t


# ================================================================ the checks

def _sockaddr(host, port):
    """-> (family, address) for a connect. The host MUST be a numeric address (AI_NUMERICHOST, IPv4 and IPv6): a name
    raises socket.gaierror and is never looked up, so the probe makes no DNS request. An IPv6 literal with a zone
    ('fe80::1%eth0') goes through getaddrinfo as well: a plain (host, port) tuple leaves sin6_scope_id at 0 and
    connect() then answers EINVAL for a link-local gateway, which would never be probed."""
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    return fam, socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0][4]


def _connect(host, port, timeout=CONNECT_S):
    try:
        fam, addr = _sockaddr(host, port)
    except (OSError, UnicodeError) as e:       # an address the resolver refuses (unknown zone): not a verdict on the rule
        return getattr(e, "errno", None) or errno.EINVAL
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(addr)
        return 0
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return e.errno
    finally:
        s.close()


def check_egress(targets, pool):
    items = [(t["host"], int(t["port"])) for t in targets.get("tcp_denied", [])]
    if not items:
        return result("egress", False, "no targets were given")
    futs = {pool.submit(_connect, h, p): (h, p) for h, p in items}
    bad = []
    for f in concurrent.futures.as_completed(futs):
        verdict = classify_connect(f.result())
        if verdict != "blocked":
            bad.append(f"{futs[f][0]}:{futs[f][1]} {verdict}")
    return result("egress", not bad, f"{len(items)} destinations blocked" if not bad else "not blocked: " + ", ".join(sorted(bad)[:6]))


def classify_listen(outcome):
    """outcome: 0 (the socket is listening), or an errno. EPERM/EACCES is a listener that was refused outright;
    a listener that came up is only REPORTED (see check_bind): the control for it is the ingress BPF filter, not this
    check."""
    if outcome == 0:
        return "listening"
    if outcome in (errno.EPERM, errno.EACCES):
        return "blocked"
    return "inconclusive"


def _listen_attempt(factory, fam, bind_first):
    """-> (errno or 0, port or None). bind_first: bind to port 0 of the wildcard address and listen; otherwise
    listen() on a socket that was never bound (the kernel picks the address and the port). The socket is closed
    at once; nothing ever accepts on it."""
    s = None
    try:
        s = factory(fam, socket.SOCK_STREAM)     # may raise (no IPv6 on the host): reported, not a crash
        if bind_first:
            s.bind(("::" if fam == socket.AF_INET6 else "0.0.0.0", 0))
        s.listen(1)
        try:
            port = s.getsockname()[1]
        except OSError:
            port = None
        return 0, port
    except OSError as e:
        return e.errno, None
    finally:
        if s is not None:
            s.close()


def check_bind(sock_factory=socket.socket):
    """REPORT-ONLY (D1): says what bind() and listen() do in this unit and never fails. SocketBindDeny=any is accepted by
    this systemd build (-BPF_FRAMEWORK) and not enforced, so no verdict on a bind can be a gate. The listener control is
    the ingress BPF filter that systemd attaches to the unit (rbrowser_launch verifies it after the start and the
    registry on every tick; the live test G01b proves it from outside); this check only keeps the numbers.

    Fixed ports: a TCP and a UDP bind on ports of 20000 to 29999, tcp4, udp4, tcp6, udp6: each is reported as blocked
    (EPERM/EACCES: a build that enforces SocketBindDeny), bound or inconclusive. Port 0 and listen() without bind:
    tcp4 and tcp6, each way; `listen_ports` gives the port the kernel chose (None when listen() was refused), so a
    caller outside the unit can try to connect. The sockets are closed at once here; the live test keeps its own open."""
    notes = []
    for label, kind, host in (("tcp4", socket.SOCK_STREAM, "0.0.0.0"), ("udp4", socket.SOCK_DGRAM, "0.0.0.0"),
                              ("tcp6", socket.SOCK_STREAM, "::"), ("udp6", socket.SOCK_DGRAM, "::")):
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        verdict = None
        for _ in range(5):
            port = 20000 + secrets.randbelow(10000)
            s = None
            try:
                s = sock_factory(fam, kind)
                s.bind((host, port))
                out = 0
            except OSError as e:
                out = e.errno
            finally:
                if s is not None:
                    s.close()
            verdict = classify_bind(out)
            if verdict != "busy":
                break
        notes.append(f"{label} {verdict}")
    listen_ports = {}
    for label, fam in (("tcp4", socket.AF_INET), ("tcp6", socket.AF_INET6)):
        for key, how, bind_first in (("bind0", "bind to port 0 and listen", True), ("autobind", "listen without bind", False)):
            out, port = _listen_attempt(sock_factory, fam, bind_first)
            verdict = classify_listen(out)
            listen_ports[f"{label}_{key}"] = port if verdict == "listening" else None
            notes.append(f"{label} {how} {verdict}" + (f" (port {port})" if verdict == "listening" and port else ""))
    r = result("bind", True, "reported, not judged: " + ", ".join(notes))
    r["listen_ports"] = listen_ports
    return r


def _try_connect_unix(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(CONNECT_S)
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def _walk_sockets(roots, depth, skip_prefix, skip_dirs=()):
    """Every unix socket under `roots`. `skip_dirs` are directories whose subtree is not looked at."""
    found = []
    for root in roots:
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count("/") - base_depth >= depth:
                dirnames[:] = []
            if skip_prefix and (dirpath + "/").startswith(skip_prefix + "/"):
                dirnames[:] = []
                continue
            if any((dirpath + "/").startswith(d.rstrip("/") + "/") for d in skip_dirs):
                dirnames[:] = []
                continue
            for n in filenames + dirnames:
                p = os.path.join(dirpath, n)
                try:
                    if stat.S_ISSOCK(os.lstat(p).st_mode):
                        found.append(p)
                except OSError:
                    pass
    return found


def _abstract_names(text):
    names = []
    for line in (text or "").splitlines()[1:]:
        f = line.split(None, 7)
        if len(f) == 8 and f[7].startswith("@"):
            names.append(f[7])
    return sorted(set(names))[:ABSTRACT_MAX]


def check_unix_sockets(pool, runtime_dir, proc_unix="/proc/net/unix"):
    """Returns (check, abstract_connectable)."""
    # positive control: this machinery can connect to a socket that is there
    ctl_path = os.path.join(runtime_dir, "probe-control.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if os.path.lexists(ctl_path):
            os.unlink(ctl_path)
        srv.bind(ctl_path)
        srv.listen(1)
        control = _try_connect_unix(ctl_path)
    except OSError:
        control = False
    finally:
        srv.close()
        try:
            os.unlink(ctl_path)
        except OSError:
            pass
    if not control:
        return result("unix_sockets", False, "positive control failed: the probe cannot connect to a socket of its own"), 0
    bus = _try_connect_unix("/run/dbus/system_bus_socket")
    paths = _walk_sockets(WALK_ROOTS, WALK_DEPTH, runtime_dir.rstrip("/"), OWN_SOCKET_DIRS)[:WALK_MAX_CONNECTS]
    futs = {pool.submit(_try_connect_unix, p): p for p in paths}
    open_paths = sorted(p for f, p in futs.items() if f.result())
    try:
        with open(proc_unix, "r", encoding="utf-8", errors="replace") as fh:
            abstract = _abstract_names(fh.read())
    except OSError:
        abstract = []
    afuts = []
    for name in abstract:
        afuts.append(pool.submit(_try_connect_unix, "\0" + name[1:]))
    n_abstract = sum(1 for f in afuts if f.result())
    ok = not bus and not open_paths
    detail = f"{len(paths)} sockets tried, {len(open_paths)} connectable"
    if bus:
        detail += ", the system bus connects"
    if open_paths:
        detail += ": " + ", ".join(open_paths[:4])
    return result("unix_sockets", ok, detail + f"; abstract connectable (informational): {n_abstract}"), n_abstract


def check_hidden_paths(targets):
    paths = targets.get("hidden_paths", [])
    if not paths:
        return result("hidden_paths", False, "no hidden-path list was given")
    open_ = [p for p in paths if not path_blocked(p)[0]]
    try:
        home = os.listdir("/home")
    except OSError:
        home = []
    ok = not open_ and not home
    return result("hidden_paths", ok, f"{len(paths)} paths hidden" if ok else
                  ("usable: " + ", ".join(open_[:5]) if open_ else "/home is listable"))


def _mount_total(path):
    sv = os.statvfs(path)
    return sv.f_blocks * sv.f_frsize


def _fstype(mountinfo, path):
    best, kind = "", ""
    for line in (mountinfo or "").splitlines():
        left, sep, right = line.partition(" - ")
        f = left.split()
        if sep and len(f) >= 5:
            mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[4])
            if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
                best, kind = mp, right.split()[0]
    return kind


def _mount_root(mountinfo, path):
    """The `root` field (the directory of the source file system that is mounted) of the mount that holds `path`."""
    best, root = "", ""
    for line in (mountinfo or "").splitlines():
        left, sep, _right = line.partition(" - ")
        f = left.split()
        if sep and len(f) >= 5:
            mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[4])
            if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
                best, root = mp, f[3]
    return root


def check_mounts(targets, runtime_dir, work_dir="/run/work"):
    exp = dict(DEFAULT_EXPECT)
    exp.update(targets.get("expect", {}))
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as fh:
            mi = fh.read()
    except OSError:
        mi = ""
    problems = []
    want = ((work_dir, exp["work_mb"] << 20), ("/dev/shm", exp["shm_mb"] << 20), ("/run", exp["run_kb"] << 10),
            (runtime_dir, exp["runtime_mb"] << 20), ("/tmp", exp["tmp_mb"] << 20), ("/var/tmp", exp["tmp_mb"] << 20))
    for path, size in want:
        try:
            total = _mount_total(path)
        except OSError:
            problems.append(f"{path} unreadable")
            continue
        if not size_matches(total, size):
            problems.append(f"{path} is {total >> 10} KiB, expected {size >> 10}")
        if _fstype(mi, path) != "tmpfs":
            problems.append(f"{path} is not a tmpfs")
    # D6: DynamicUser=yes forces PrivateTmp=yes (root disk, no cap) and ignores TemporaryFileSystem= for /tmp and /var/tmp; the
    # launcher binds a directory of its capped tmpfs over both. The size check above proves the file system (a tmpfs of tmp_mb), NOT
    # a cap per unit: that tmpfs is shared by every unit (the cap is per host, see TMP_OPTIONS in rbrowser_launch)
    try:
        run_entries = sorted(os.listdir("/run"))
        if run_entries != sorted(["portal-rb", os.path.basename(work_dir.rstrip("/")), "systemd"]):
            problems.append("/run holds " + ",".join(run_entries[:6]))
        # systemd's own mount-propagation point: one empty directory, no socket can be in it
        incoming = os.listdir("/run/systemd")
        if incoming != ["incoming"]:
            problems.append("/run/systemd holds " + ",".join(incoming[:5]))
        try:
            if os.listdir("/run/systemd/incoming"):
                problems.append("/run/systemd/incoming is not empty")
        except PermissionError:
            pass          # root-only directory: the unit's user cannot enter it, which is as good as empty
        under = sorted(os.listdir("/run/portal-rb"))
        if under != [os.path.basename(runtime_dir.rstrip("/"))]:
            problems.append("/run/portal-rb holds " + ",".join(under[:5]))
    except OSError:
        problems.append("/run cannot be listed")
    try:
        fd = os.open("/run/probe-write-test", os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        os.unlink("/run/probe-write-test")
        problems.append("/run is writable")
    except OSError:
        pass
    return result("mounts", not problems, "work area, shm, run, the runtime directory, /tmp and /var/tmp (the capped tmpfs) as expected" if not problems else "; ".join(problems[:5]))


def check_display_proof(S, runtime_dir, tag):
    """The first two steps of the supervisor: Xvfb with -displayfd and the ownership proof."""
    xauth = os.path.join(runtime_dir, f"probe-{tag}.xauth")
    binary = S.find_binary("Xvfb")
    if not binary:
        return result("display_proof", False, "Xvfb not found")
    fd = os.open(xauth, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(S.xauth_entry(secrets.token_hex(16)))
    proc = None
    try:
        proc, display = S.start_xvfb(binary, xauth, S.child_env(xauth=xauth))
        S.prove_display(proc.pid, display)
        return result("display_proof", True, "Xvfb chose its own display and holds its abstract name")
    except S.SupervisorError as e:
        return result("display_proof", False, str(e))
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        try:
            os.unlink(xauth)
        except OSError:
            pass


def _headless_flags(S, tag):
    # --disable-logging is dropped: the only place headless Chromium names why a page did not load is its log line
    # "Page load failed: net::ERR_BLOCKED_BY_ADMINISTRATOR" (a failed load prints no DOM at all, so stdout cannot tell a
    # policy block from any other failure). _dump_dom keeps that error code and throws the rest of the log away.
    drop = ("--user-data-dir", "--window-position", "--password-store", "--disable-logging")
    flags = [f for f in S.CHROMIUM_FLAGS if not f.startswith(drop)]
    return ["--headless=new", f"--user-data-dir={S.WORK_DIR}/probe-{tag}", "--enable-logging=stderr", "--log-level=0", *flags]


LOAD_FAILED = re.compile(r"Page load failed: net::(ERR_[A-Z0-9_]+)")


def _read_until_exit(p, seconds, limit=1 << 20):
    """(stdout bytes, stderr bytes, timed_out) of a child with both streams piped. Reads until the MAIN process has
    exited, not until the pipes close: Chromium's helper processes (the crash handler, a zygote) can outlive it by
    seconds holding the pipe's write end open, and communicate() then waits for them until the time limit (seen
    intermittently on the live host, round 1)."""
    import selectors
    out, err = bytearray(), bytearray()
    sel = selectors.DefaultSelector()
    for f, buf in ((p.stdout, out), (p.stderr, err)):
        os.set_blocking(f.fileno(), False)
        sel.register(f, selectors.EVENT_READ, buf)
    end = time.monotonic() + seconds
    timed_out = False
    exited_at = None
    try:
        while True:
            now = time.monotonic()
            if now >= end:
                timed_out = p.poll() is None
                break
            if p.poll() is not None:
                exited_at = exited_at or now
                if now - exited_at > 0.3:          # the output the main process wrote is in the pipes by now
                    break
            for key, _ in sel.select(0.1):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                if len(key.data) < limit:
                    key.data.extend(chunk)
            if not sel.get_map() and p.poll() is not None:
                break
    finally:
        sel.close()
        for f in (p.stdout, p.stderr):
            try:
                f.close()
            except OSError:
                pass
    return bytes(out), bytes(err), timed_out


def _dump_dom(S, chromium, tag, url):
    """chromium --dump-dom URL -> (return code, output). Own process group, time limit, one repeat after a time-out.
    Of stderr only the error code of a failed page load is kept: it is appended to the output as
    `[load failed: net::ERR_...]`. The process group is killed afterwards, so nothing of the browser is left behind.

    The repeat: on the live host about one headless launch in 200 never ends. The browser process spins at 100 % CPU
    with its zygote, GPU and utility processes asleep, after the log lines "Failed to send GetTerminationStatus message
    to zygote" and "Socket closed prematurely" (a Chromium 156 fault, not of the policy or the unit: it also happens
    with the plain flag set)."""
    timed_out, out, err, p = True, b"", b"", None
    for attempt in range(CHROMIUM_ATTEMPTS):
        p = subprocess.Popen([chromium, *_headless_flags(S, f"{tag}{attempt}"), "--dump-dom", url], env=S.child_env(),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err, timed_out = _read_until_exit(p, CHROMIUM_RUN_S)
        finally:
            _kill_group(p)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if not timed_out:
            break
    text = out.decode("utf-8", "replace")
    if timed_out:
        return 124, text
    m = LOAD_FAILED.search(err.decode("utf-8", "replace"))
    if m:
        text += f"\n[load failed: net::{m.group(1)}]"
    return p.returncode, text


def _kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        p.kill()
    except OSError:
        pass


def check_chromium_policy(S, chromium, pool):
    """Positive controls (design 8.2 check 7): a data: page with a marker must render, and file:///etc/hostname
    must fail to load with the policy's error (net::ERR_BLOCKED_BY_ADMINISTRATOR), not be answered by the file."""
    marker = "rbp" + secrets.token_hex(6)
    f1 = pool.submit(_dump_dom, S, chromium, "a", data_url(marker))
    f2 = pool.submit(_dump_dom, S, chromium, "b", "file:///etc/hostname")
    rc1, out1 = f1.result()
    rc2, out2 = f2.result()
    try:
        with open("/etc/hostname", "r", encoding="utf-8", errors="replace") as fh:
            host = fh.read().strip()
    except OSError:
        host = ""
    probs = []
    if rc1 != 0:
        probs.append(f"the data page: exit {rc1}")
    elif marker not in out1:
        probs.append("the data page did not render its marker")
    if rc2 != 0:
        probs.append(f"the file page: exit {rc2}")
    elif BLOCK_MARKER not in out2:
        probs.append("the file page did not fail with ERR_BLOCKED_BY_ADMINISTRATOR")
    elif host and len(host) > 3 and host in out2:
        probs.append("the file page shows the host name")
    return result("chromium_policy", not probs, "the page rendered and file: was blocked by policy" if not probs else "; ".join(probs))


def _children_of(pid):
    out = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for n in names:
        if n.isdigit():
            try:
                with open(f"/proc/{n}/stat", "rb") as f:
                    data = f.read()
                ppid_pgrp = data[data.rindex(b")") + 2:].split()
                out.append((int(n), int(ppid_pgrp[1])))
            except (OSError, ValueError, IndexError):
                continue
    return out


def _descendants(root):
    pairs = _children_of(root)
    kids = {}
    for pid, ppid in pairs:
        kids.setdefault(ppid, []).append(pid)
    seen, todo = [], list(kids.get(root, []))
    while todo:
        p = todo.pop()
        if p not in seen:
            seen.append(p)
            todo.extend(kids.get(p, []))
    return seen


def check_sandbox_state(S, chromium, pool):
    """Design 8.2 check 8: Chromium's own sandbox is on for every renderer. A headless Chromium loads a data: page (it
    certainly creates a renderer); the check polls /proc up to SANDBOX_POLL_S for the renderers, until no new one has
    appeared for SANDBOX_SETTLE_S, and passes only when sandbox_verdict does. Chromium's own sandbox page is not used: headless
    Chromium 156 prints nothing for any chrome: page (net::ERR_ABORTED), measured."""
    p = subprocess.Popen([chromium, *_headless_flags(S, "s"), data_url("rbp" + secrets.token_hex(6))], env=S.child_env(),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    browser, seen = None, {}
    try:
        end = time.monotonic() + SANDBOX_POLL_S
        last_new = None
        while time.monotonic() < end:
            time.sleep(0.25)
            now = time.monotonic()
            b = sample_process(p.pid)         # the wrapper script execs the browser: the pid stays, its command line changes
            if b is not None:
                browser = b
            before = sum(1 for s in seen.values() if s["type"] == "renderer")
            for pid in _descendants(p.pid):
                s = sample_process(pid)
                if s is not None:
                    seen[pid] = merge_sample(seen.get(pid), s)
            n = sum(1 for s in seen.values() if s["type"] == "renderer")
            if n and (n != before or last_new is None):
                last_new = now
            if n and now - last_new >= SANDBOX_SETTLE_S:
                break
    finally:
        _kill_group(p)
        p.wait()
    ok, detail = sandbox_verdict(browser, list(seen.values()))
    return result("sandbox_state", ok, detail)


# ================================================================ main

def load_session():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("rb_session", os.path.join(here, "session.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_all(targets, environ):
    S = load_session()
    runtime_dir = environ.get("RUNTIME_DIRECTORY", "").rstrip("/")
    chromium = environ.get("RB_CHROMIUM", "")
    if not runtime_dir.startswith("/") or not chromium.startswith("/"):
        return summarize([result("setup", False, "the unit did not pass RUNTIME_DIRECTORY and RB_CHROMIUM")])
    for d in (S.HOME_DIR, S.TMP_DIR):
        os.makedirs(d, mode=0o700, exist_ok=True)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=48)
    outer = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    tag = secrets.token_hex(3)
    jobs = {
        "egress": lambda: check_egress(targets, pool),
        "bind": check_bind,
        "unix_sockets": lambda: check_unix_sockets(pool, runtime_dir),
        "hidden_paths": lambda: check_hidden_paths(targets),
        "mounts": lambda: check_mounts(targets, runtime_dir),
        "display_proof": lambda: check_display_proof(S, runtime_dir, tag),
        "chromium_policy": lambda: check_chromium_policy(S, chromium, pool),
        "sandbox_state": lambda: check_sandbox_state(S, chromium, pool),
    }
    futs = {outer.submit(fn): name for name, fn in jobs.items()}
    done, pending = concurrent.futures.wait(futs, timeout=TOTAL_S)
    checks, abstract = {}, 0
    for f in done:
        name = futs[f]
        try:
            r = f.result()
        except Exception as e:   # a crashing check is a failed check
            r = result(name, False, f"the check failed to run ({e.__class__.__name__})")
        if isinstance(r, tuple):
            r, abstract = r
        checks[name] = r
    for f in pending:
        checks[futs[f]] = result(futs[f], False, f"not finished in {int(TOTAL_S)} s")
    ordered = [checks[n] for n in jobs]
    return summarize(ordered, abstract)


def main(environ=None, path=TARGETS_PATH):
    environ = os.environ if environ is None else environ
    try:
        targets = read_targets(path)
    except (OSError, ValueError):
        out = summarize([result("setup", False, "the targets file is missing or unreadable")])
    else:
        out = run_all(targets, environ)
    sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    os._exit(code)    # leave no worker thread or child behind
