"""Live proof of the ingress BPF program of rbrowser_bpf with real systemd units (systemd 252, kernel 6.1).

NOT part of the ordinary suite. It loads a BPF program, pins it under /sys/fs/bpf/portal-rb-livetest-<hex> and
starts transient units, so it refuses to run unless asked twice (the variable AND root):

    sudo RBROWSER_LIVE=1 /home/dustin/scripts/portal/venv/bin/python -B tests/test_rbrowser_bpf_live.py

Every unit is named portal-rbtest-bpf-<hex> (plain system.slice, DynamicUser=yes, RuntimeMaxSec=90, --collect).
It does not touch portal.service, system-portalrb.slice, iptables, /run/portal-rb*, or any other unit. Units and
the test pin are removed in `finally`. Output: one line per check, `Bnn PASS|FAIL|INFO detail`.

Checks
 B01  filter unit: every listener (fixed port, port 0, listen without bind; tcp4, tcp6, dual stack) is in LISTEN
      state on the host
 B02  filter unit: a host connect to every listener on every host address (loopback, eth0, link-local) fails
 B03  control unit (no IPIngressFilterPath), same listeners: every connect succeeds and is accepted (the method)
 B04  inside a filter unit: DNS over UDP, an https page and a 5 MB download work
 B05  control for B06: a unit with the filter but no deny list connects to the host's own addresses
 B06  filter plus the feature's IPAddressDeny list: connects to the host's own addresses (proved reachable by B05)
      and to the other denied ranges all fail, public https and download still work, and both our program and
      systemd's own are attached at ingress. Only the host-owned targets have a control; the other ranges are
      "did not connect", not proof of denial.
 B07  filter plus a deny list WITHOUT loopback and the host's own range: the host still cannot connect; the same
      deny list without the filter is connectable (so the filter, not the deny list, blocks)
 B08  systemctl show reports IPIngressFilterPath
 B09  attached(): True for the filter units, False for the control units (also when systemd's own program is there)
 B10  a missing pin: what systemd does (the unit must fail to start) and attached() is False
 B11  INFO (a measurement, not a check): SocketBindDeny=any, whether a fixed bind is refused
 B12  systemd re-applies the unit's BPF firewall (set-property) with the pin present: our program stays attached
      and the unit stays closed
 B13  INFO (a measurement): the same with the pin REMOVED: the filter is detached silently (the finding)
 B14  prune_stale() removes only stale pins of its base and keeps the current one and the `keep` list
 B15  clean-up: no unit, no pin, no drop-in, no listener left
"""

import concurrent.futures
import errno
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def refuse_unless_asked():
    if os.environ.get("RBROWSER_LIVE") != "1":
        print("skip: set RBROWSER_LIVE=1 and run as root to run the live BPF test (it starts real systemd units)")
        sys.exit(0)
    if os.geteuid() != 0:
        print("refused: RBROWSER_LIVE=1 is set but this is not root (run it with sudo)")
        sys.exit(2)


if __name__ == "__main__":
    refuse_unless_asked()

sys.path.insert(0, str(ROOT))
import rbrowser_bpf as B  # noqa: E402
import rbrowser_policy as P  # noqa: E402

TAG = secrets.token_hex(3)
PREFIX = "portal-rbtest-bpf-"
PIN_BASE = f"/sys/fs/bpf/portal-rb-livetest-{TAG}"
UNITS = []
USED_PORTS = set()
HOLD = []
RESULTS = []


def say(bid, status, detail=""):
    RESULTS.append((bid, status))
    print(f"{bid} {status} {str(detail).replace(chr(10), ' ')[:600]}".rstrip(), flush=True)


def sh(args, timeout=60):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def unit_name(label):
    n = f"{PREFIX}{TAG}-{label}"
    assert n.startswith(PREFIX)
    return n


def start_unit(label, code, props=()):
    """systemd-run a python snippet as a transient unit; returns (name, returncode, output)."""
    name = unit_name(label)
    UNITS.append(name)
    cmd = ["systemd-run", "--unit", name, "--collect", "-p", "DynamicUser=yes", "-p", "RuntimeMaxSec=90"]
    for p in props:
        cmd += ["-p", p]
    cmd += ["/usr/bin/python3", "-I", "-c", code]
    rc, out = sh(cmd)
    return name, rc, out


def journal(name):
    return sh(["journalctl", "-u", name + ".service", "--no-pager", "-o", "cat"])[1]


def wait_for(name, marker, seconds=45):
    end = time.time() + seconds
    while time.time() < end:
        text = journal(name)
        if marker in text:
            return text
        time.sleep(0.5)
    return journal(name)


def cgroup_of(name):
    return "/sys/fs/cgroup" + sh(["systemctl", "show", "-p", "ControlGroup", "--value", name + ".service"])[1]


def stop_unit(name):
    sh(["systemctl", "stop", name + ".service"])
    sh(["systemctl", "reset-failed", name + ".service"])


# ---------------------------------------------------------------- the code that runs inside the units

LISTENER = r'''
import select, socket, sys, time
def say(*a):
    print(*a, flush=True)
BASE = %(base)d
socks = {}
def mk(name, fams, fam, v6only=None, bind=None):
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        if v6only is not None:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
        if bind is not None:
            s.bind(bind)
        s.listen(128)
        socks[name] = s
        say("PORT", name, fams, s.getsockname()[1])
    except OSError as e:
        say("LISTENFAIL", name, fams, e.errno, e)
A, A6 = socket.AF_INET, socket.AF_INET6
mk("fixed4", "4", A, bind=("0.0.0.0", BASE))
mk("fixed6", "6", A6, 1, ("::", BASE + 1))
mk("fixed6dual", "46", A6, 0, ("::", BASE + 2))
mk("zero4", "4", A, bind=("0.0.0.0", 0))
mk("zero6", "6", A6, 1, ("::", 0))
mk("auto4", "4", A)
mk("auto6dual", "46", A6)
mk("auto6only", "6", A6, 1)
try:
    c = socket.create_connection(("example.com", 443), timeout=10)
    c.close()
    say("OUTBOUND ok")
except OSError as e:
    say("OUTBOUND err", e)
say("READY")
end = time.time() + 80
while time.time() < end:
    r, _, _ = select.select(list(socks.values()), [], [], 1)
    for s in r:
        try:
            c, _a = s.accept()
            c.close()
            say("ACCEPT", [k for k, v in socks.items() if v is s][0])
        except OSError:
            pass
'''

CLIENT = r'''
import errno, socket, ssl, struct, time, urllib.request
def say(*a):
    print(*a, flush=True)
MODE = %(mode)r
DENY_TARGETS = %(deny)r

def dns_raw(name, server="1.1.1.1"):
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (server, 53))
    d, _ = s.recvfrom(1024)
    flags, an = struct.unpack("!2xHxxH", d[:8])[0], struct.unpack("!H", d[6:8])[0]
    i = 12
    while d[i]:
        i += d[i] + 1
    i += 5
    ips = []
    for _ in range(an):
        if d[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while d[i]:
                i += d[i] + 1
            i += 1
        t, c, ttl, l = struct.unpack("!HHIH", d[i:i + 10])
        i += 10
        if t == 1 and l == 4:
            ips.append(".".join(str(b) for b in d[i:i + 4]))
        i += l
    return flags & 15, ips

def fetch(host, path, ip):
    s = socket.create_connection((ip, 443), timeout=20)
    s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    s.settimeout(30)
    s.sendall(("GET %%s HTTP/1.0\r\nHost: %%s\r\nUser-Agent: rbtest\r\n\r\n" %% (path, host)).encode())
    n, head = 0, b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        if b"\r\n\r\n" not in head:
            head += b
            if b"\r\n\r\n" in head:
                n += len(head.split(b"\r\n\r\n", 1)[1])
        else:
            n += len(b)
    return head.split(b"\r\n", 1)[0].decode(), n

def t(name, fn):
    try:
        say("T", name, "OK", fn())
    except Exception as e:
        say("T", name, "ERR", type(e).__name__, getattr(e, "errno", None), e)

if MODE == "c":
    t("dns_stub", lambda: socket.getaddrinfo("example.com", 443)[0][4][0])
    t("dns_udp", lambda: dns_raw("example.com"))
    t("https_urllib", lambda: b"Example Domain" in urllib.request.urlopen(urllib.request.Request("https://example.com", headers={"User-Agent": "rbtest/1.0"}), timeout=20).read())
    def dl():
        t0 = time.time()
        rq = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=5000000", headers={"User-Agent": "rbtest/1.0"})
        data = urllib.request.urlopen(rq, timeout=60).read()
        return len(data), round(time.time() - t0, 2)
    t("download_urllib", dl)
else:
    if MODE == "d":
        t("dns_udp", lambda: dns_raw("example.com"))
        t("https_ip", lambda: fetch("example.com", "/", dns_raw("example.com")[1][0]))
        t("download_ip", lambda: fetch("speed.cloudflare.com", "/__down?bytes=5000000", dns_raw("speed.cloudflare.com")[1][0]))
    import concurrent.futures
    def one(tg):
        host, port, scope = tg
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((host, port, 0, scope) if fam == socket.AF_INET6 else (host, port))
            r = "CONNECTED"
        except socket.timeout:
            r = "TIMEOUT"
        except OSError as e:
            r = errno.errorcode.get(e.errno, str(e.errno))
        s.close()
        return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for tg, r in zip(DENY_TARGETS, ex.map(one, DENY_TARGETS)):
            say("T", "deny:%%s:%%s" %% (tg[0], tg[1]), "OK", r)
say("DONE")
time.sleep(75)
'''

DENY_HOSTS = ["127.0.0.1", "10.0.0.1", "172.16.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1",
              "fe80::1", "64:ff9b::a00:1"]


# ---------------------------------------------------------------- host side helpers

def host_addresses():
    """[(family, address, scope_id)] of every address on every interface, loopback included."""
    out = []
    for line in sh(["ip", "-o", "addr"])[1].splitlines():
        f = line.split()
        if len(f) < 4 or f[2] not in ("inet", "inet6"):
            continue
        dev, addr = f[1], f[3].split("/")[0]
        if f[2] == "inet":
            out.append((4, addr, 0))
        else:
            out.append((6, addr, socket.if_nametoindex(dev) if addr.lower().startswith("fe80") else 0))
    return out


def listening_ports():
    ports = set()
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(fn).read().splitlines()[1:]:
                f = line.split()
                if f[3] == "0A":
                    ports.add(int(f[1].split(":")[1], 16))
        except OSError:
            pass
    return ports


def pick_base():
    busy = listening_ports()
    for _ in range(200):
        b = 42000 + secrets.randbelow(5000)
        if not ({b, b + 1, b + 2} & busy):
            return b
    raise RuntimeError("no free port range")


def parse_listeners(text):
    ports, fails = {}, []
    for line in text.splitlines():
        f = line.split()
        if f[:1] == ["PORT"] and len(f) == 4:
            ports[f[1]] = (f[2], int(f[3]))
            USED_PORTS.add(int(f[3]))
        elif f[:1] == ["LISTENFAIL"]:
            fails.append(line)
    return ports, fails


def attempt(fam, addr, scope, port, seconds=3.0):
    s = socket.socket(socket.AF_INET if fam == 4 else socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(seconds)
    try:
        s.connect((addr, port) if fam == 4 else (addr, port, 0, scope))
        return "connected"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()


def probe_all(ports, addrs):
    jobs = []
    for name, (fams, port) in ports.items():
        for fam, addr, scope in addrs:
            if str(fam) in fams:
                jobs.append((name, addr, port, fam, scope))
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        res = list(ex.map(lambda j: (j, attempt(j[3], j[1], j[4], j[2])), jobs))
    return res


def listener_unit(label, props):
    base = pick_base()
    name, rc, out = start_unit(label, LISTENER % {"base": base}, props)
    if rc != 0:
        return name, None, f"systemd-run failed: {out}", {}, []
    text = wait_for(name, "READY")
    ports, fails = parse_listeners(text)
    return name, text, "", ports, fails


def local_targets(addrs, p4, p6):
    """Host-owned addresses with the ports of the temporary host listeners (they connect unless something denies)."""
    return [(a, p4 if fam == 4 else p6, scope) for fam, a, scope in addrs]


def other_targets():
    return [(h, 80, 0) for h in DENY_HOSTS if h not in ("127.0.0.1", "172.16.0.5", "::1", "fe80::1")]


def host_listener(fam):
    s = socket.socket(socket.AF_INET if fam == 4 else socket.AF_INET6, socket.SOCK_STREAM)
    if fam == 6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("0.0.0.0", 0) if fam == 4 else ("::", 0))
    s.listen(64)
    USED_PORTS.add(s.getsockname()[1])
    return s


def feature_deny_list(addrs):
    """The deny list the feature builds (rbrowser_policy.deny_list) from this host's real inputs."""
    resolvers = P.parse_resolv_conf(open("/etc/resolv.conf").read())
    ifaces = []
    for line in sh(["ip", "-o", "addr"])[1].splitlines():
        f = line.split()
        if len(f) >= 4 and f[2] in ("inet", "inet6"):
            ifaces.append(f[3])
    gws = P.parse_proc_net_route(open("/proc/net/route").read())
    return P.deny_list(resolvers, ifaces, gws, [])


def okk(t, k):
    return t.get(k, ("missing", ""))[0] == "OK"


def results_of(text):
    """{test: (status, rest)} from the 'T name OK|ERR ...' lines of a client unit."""
    out = {}
    for line in text.splitlines():
        f = line.split(None, 3)
        if f[:1] == ["T"] and len(f) >= 3:
            out[f[1]] = (f[2], f[3] if len(f) > 3 else "")
    return out


# ---------------------------------------------------------------- the checks

def main():
    rc, load = sh(["uptime"])
    print("host:", load, flush=True)
    ok, why = B.available()
    if not ok:
        say("B00", "FAIL", why)
        return
    res = B.load_and_pin(PIN_BASE)
    pin = res["path"]
    say("B00", "PASS", f"program of {len(B.program()) // 8} instructions loaded and pinned at {pin} (id {res['id']}, tag {res['tag']}), "
        f"mode {oct(os.stat(pin).st_mode & 0o777)} uid {os.stat(pin).st_uid}")
    filt = f"IPIngressFilterPath={pin}"
    addrs = host_addresses()
    print("host addresses: " + " ".join(f"{a}{'%' + str(s) if s else ''}" for _, a, s in addrs), flush=True)
    nonloop = [a for a in addrs if not (a[1].startswith("127.") or a[1] == "::1")]
    if not nonloop:
        say("B00", "FAIL", "no non-loopback address on this host")

    # ---- (a) the filtered unit with listeners, nothing else
    fu, text, err, fports, ffails = listener_unit("filt", [filt])
    if text is None:
        say("B01", "FAIL", err)
        return
    host_listening = listening_ports()
    missing = [n for n, (_, p) in fports.items() if p not in host_listening]
    outbound = [l for l in text.splitlines() if l.startswith("OUTBOUND")]
    say("B01", "PASS" if len(fports) == 8 and not missing and not ffails and outbound == ["OUTBOUND ok"] else "FAIL",
        f"{len(fports)}/8 listeners {sorted(fports)} all in LISTEN state on the host (missing {missing}, fails {ffails}); "
        f"ports {sorted(p for _, p in fports.values())}; unit's own outbound connect: {outbound}")
    res_a = probe_all(fports, addrs)
    okc = [(j[0], j[1], r) for j, r in res_a if r == "connected"]
    kinds = {}
    for _j, r in res_a:
        kinds[r] = kinds.get(r, 0) + 1
    accepted = [l for l in journal(fu).splitlines() if l.startswith("ACCEPT")]
    say("B02", "PASS" if res_a and not okc and not accepted else "FAIL",
        f"{len(res_a)} connect attempts (loopback, eth0, link-local; 3 s limit): outcomes {kinds}; connected {okc[:3]}; "
        f"accept events in the unit: {len(accepted)}")

    # ---- (b) the control unit
    cu, ctext, err, cports, cfails = listener_unit("ctl", [])
    if ctext is None:
        say("B03", "FAIL", err)
    else:
        res_b = probe_all(cports, addrs)
        bad = [(j[0], j[1], r) for j, r in res_b if r != "connected"]
        time.sleep(0.5)
        acc = {l.split()[1] for l in journal(cu).splitlines() if l.startswith("ACCEPT")}
        never = sorted(set(cports) - acc)
        say("B03", "PASS" if res_b and not bad and not never and len(cports) == 8 else "FAIL",
            f"{len(res_b)} connect attempts to the unit WITHOUT the property: failed {bad[:4]}; listeners that accepted "
            f"{sorted(acc)}; never accepted {never}")

    # ---- (c) outbound inside a filtered unit
    cl, rc, out = start_unit("client", CLIENT % {"mode": "c", "deny": []}, [filt])
    t = results_of(wait_for(cl, "DONE", 80)) if rc == 0 else {}
    say("B04", "PASS" if all(okk(t, k) for k in ("dns_stub", "dns_udp", "https_urllib", "download_urllib")) and
        "True" in t.get("https_urllib", ("", ""))[1] and int(t["download_urllib"][1].strip("() ").split(",")[0] or 0) >= 5000000 else "FAIL",
        f"inside a unit with the filter: {t or out}")

    # ---- (d) the feature's deny list plus the filter. Targets: the host's own addresses with the port of a
    # temporary host listener (connectable unless denied; a control unit proves it) and the other denied ranges.
    h4, h6 = host_listener(4), host_listener(6)
    HOLD.extend([h4, h6])
    loc = local_targets(addrs, h4.getsockname()[1], h6.getsockname()[1])
    others = other_targets()
    kc, rc, out = start_unit("dctl", CLIENT % {"mode": "k", "deny": loc}, [filt])
    tk = results_of(wait_for(kc, "DONE", 60)) if rc == 0 else {}
    notconn_k = {k: v for k, v in tk.items() if v != ("OK", "CONNECTED")}
    say("B05", "PASS" if len(tk) == len(loc) and not notconn_k else "FAIL",
        f"control (filter, no deny list): outbound connects to the host's own addresses {len(tk)}/{len(loc)} connected "
        f"(proves the targets are reachable unless denied); not connected {notconn_k}")
    deny = feature_deny_list(addrs)
    dl, rc, out = start_unit("deny", CLIENT % {"mode": "d", "deny": loc + others}, [filt, "IPAddressDeny=" + " ".join(deny)])
    t = results_of(wait_for(dl, "DONE", 80)) if rc == 0 else {}
    denied = {k[5:]: v for k, v in t.items() if k.startswith("deny:")}
    wrong = {k: v for k, v in denied.items() if v[1] == "CONNECTED"}
    cg = cgroup_of(dl)
    ids = B.ingress_program_ids(cg) if rc == 0 else []
    att = B.attached(cg, pin) if rc == 0 else False
    dl_ok = okk(t, "https_ip") and okk(t, "download_ip") and okk(t, "dns_udp") and t["download_ip"][1].rstrip(")").rsplit(" ", 1)[-1] == "5000000"
    kinds = sorted({v[1] for v in denied.values()})
    say("B06", "PASS" if len(denied) == len(loc) + len(others) and not wrong and dl_ok and len(ids) >= 2 and att else "FAIL",
        f"deny list of {len(deny)} entries + filter: {len(denied)}/{len(loc) + len(others)} denied-range connects, none connected "
        f"(outcomes {kinds}; connected: {wrong}); public https/download/dns still work: "
        f"{[t.get(k) for k in ('https_ip', 'download_ip', 'dns_udp')]}; ingress program ids at the unit {ids}, ours attached {att}")
    stop_unit(dl)
    stop_unit(kc)

    # ---- (d2/d3) deny list without loopback/host range: the filter blocks, the control does not
    base_deny = [c for c in list(P.FIXED_V4) + list(P.FIXED_V6) + list(P.CLOUD)
                 if c not in ("127.0.0.0/8", "172.16.0.0/12", "::1/128", "::/96", "fc00::/7", "fe80::/10")]
    dprops = ["IPAddressDeny=" + " ".join(base_deny), "SocketBindDeny=any"]
    f2, t2, err, p2, fl2 = listener_unit("denyfilt", [filt] + dprops)
    if t2 is None:
        say("B07", "FAIL", err)
    else:
        r2 = probe_all(p2, addrs)
        c2, tc2, err, pc2, fc2 = listener_unit("denyctl", dprops)
        r3 = probe_all(pc2, addrs) if tc2 else []
        conn2 = [(j[0], j[1]) for j, r in r2 if r == "connected"]
        notconn3 = [(j[0], j[1], r) for j, r in r3 if r != "connected"]
        say("B07", "PASS" if r2 and r3 and not conn2 and not notconn3 and len(p2) == 8 and len(pc2) == 8 else "FAIL",
            f"deny list ({len(base_deny)} entries) + SocketBindDeny=any: with the filter {len(r2)} attempts, connected {conn2[:3]}; "
            f"without the filter {len(r3)} attempts, not connected {notconn3[:3]}; listeners {len(p2)}/{len(pc2)}")
        fixed = {n: v for n, v in p2.items() if n.startswith("fixed")}
        say("B11", "INFO", f"SocketBindDeny=any in the unit: fixed-port binds succeeded {sorted(fixed)} and listeners failed {fl2}: "
            + ("NOT enforced" if len(fixed) == 3 else "enforced for some") + "; systemctl --version: "
            + ("-BPF_FRAMEWORK" if "-BPF_FRAMEWORK" in sh(["systemctl", "--version"])[1] else "+BPF_FRAMEWORK"))

    # ---- (e) systemctl show
    shown = sh(["systemctl", "show", "-p", "IPIngressFilterPath", "--value", fu + ".service"])[1]
    shown_c = sh(["systemctl", "show", "-p", "IPIngressFilterPath", "--value", cu + ".service"])[1]
    say("B08", "PASS" if shown == pin and shown_c == "" else "FAIL", f"filter unit: {shown!r}; control unit: {shown_c!r}")

    # ---- attached()
    a_f = B.attached(cgroup_of(fu), pin)
    a_c = B.attached(cgroup_of(cu), pin)
    a_cd = B.attached(cgroup_of(c2), pin) if tc2 else None
    ids_cd = B.ingress_program_ids(cgroup_of(c2)) if tc2 else []
    say("B09", "PASS" if a_f is True and a_c is False and a_cd is False and ids_cd else "FAIL",
        f"attached(): filter unit {a_f}, control unit {a_c}, control unit with IPAddressDeny {a_cd} (it has systemd's own "
        f"ingress program ids {ids_cd}, so a count would be wrong); filter unit ids {B.ingress_program_ids(cgroup_of(fu))}")

    # ---- (f) a missing pin
    missing_pin = f"/sys/fs/bpf/portal-rb-livetest-{TAG}-absent"
    mu, rc, out = start_unit("nopin", "import time\nprint('RAN', flush=True)\ntime.sleep(60)", [f"IPIngressFilterPath={missing_pin}"])
    time.sleep(1)
    st = sh(["systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "Result", mu + ".service"])[1].replace("\n", " ")
    jr = sh(["journalctl", "_PID=1", "--no-pager", "-o", "cat", "-n", "400"])[1]
    lines = [l for l in jr.splitlines() if mu in l and ("bpf" in l.lower() or "resources" in l or "Failed" in l)]
    ran = "RAN" in journal(mu)
    att = B.attached(cgroup_of(mu), pin)
    say("B10", "PASS" if rc != 0 and not ran and not att else "FAIL",
        f"systemd-run exit {rc} ({out.splitlines()[0] if out else ''!r}); {st}; the process ran: {ran}; attached(): {att}; "
        f"journal: {lines[:3]}")

    # ---- B12/B13: systemd re-applies the BPF firewall of a running unit (set-property); the pin is needed again
    res2 = B.load_and_pin(PIN_BASE + "-pr")
    pin2 = res2["path"]
    ru, rtext, err, rports, rfails = listener_unit("reapply", [f"IPIngressFilterPath={pin2}"])
    if rtext is None:
        say("B12", "FAIL", err)
        return
    cg = cgroup_of(ru)
    steps = []

    def state(label):
        ids = B.ingress_program_ids(cg)
        res = probe_all(rports, addrs)
        conn = [(j[0], j[1]) for j, r in res if r == "connected"]
        steps.append(f"{label}: ids {ids} ours {res2['id'] in ids} connects {len(res)} connected {len(conn)}")
        return res2["id"] in ids and not conn

    s0 = state("running")
    rc1, o1 = sh(["systemctl", "set-property", "--runtime", ru + ".service", "IPAccounting=no"])
    s1 = state(f"pin present, after set-property IPAccounting=no (rc {rc1} {o1[:60]!r})")
    rc2, o2 = sh(["systemctl", "set-property", "--runtime", ru + ".service", "IPAddressDeny=10.77.0.0/16"])
    s2 = state(f"pin present, after set-property IPAddressDeny=10.77.0.0/16 (rc {rc2} {o2[:60]!r})")
    say("B12", "PASS" if s0 and s1 and s2 else "FAIL", "; ".join(steps) + f"; attached() {B.attached(cg, pin2)}")
    steps.clear()
    B.unpin(pin2)
    s3 = state("pin removed, nothing re-applied yet")
    rc3, o3 = sh(["systemctl", "set-property", "--runtime", ru + ".service", "IPAddressDeny=10.78.0.0/16"])
    s4 = state(f"pin removed, after set-property IPAddressDeny=10.78.0.0/16 (rc {rc3} {o3[:60]!r})")
    jl = [l.split("]: ", 1)[-1] for l in sh(["journalctl", "_PID=1", "--no-pager", "-o", "cat", "-n", "300"])[1].splitlines()
          if ru in l and "bpf" in l.lower()]
    dropins = sorted(__import__("glob").glob(f"/run/systemd/system.control/{ru}.service.d*"))
    say("B13", "INFO", "FINDING (a measurement): " + ("the filter SURVIVED a re-apply without its pin" if s3 and s4 else
        "a pin removed while the unit runs does not matter until systemd re-applies the unit's BPF firewall, then the "
        "filter is detached silently and the unit keeps running OPEN" if s3 and not s4 else "unexpected") + "; "
        + "; ".join(steps) + f"; journal {jl[-1:]}; runtime drop-ins {dropins}")
    stop_unit(ru)
    sh(["systemctl", "revert", ru + ".service"])

    # ---- B14: prune_stale keeps the current pin and the ones in `keep`, removes the other hashes of the same base
    pbase = PIN_BASE + "-pp"
    r3 = B.load_and_pin(pbase)
    fd = B._obj_path_op(B.BPF_OBJ_GET, r3["path"])
    fakes = [f"{pbase}-{h}" for h in ("a" * 16, "b" * 16)]
    try:
        for f in fakes:
            B._obj_path_op(B.BPF_OBJ_PIN, f, fd)
    finally:
        os.close(fd)
    other = f"{pbase}x-{'c' * 16}"
    removed = B.prune_stale(pbase, keep=[fakes[1]])
    left = sorted(n for n in os.listdir("/sys/fs/bpf") if n.startswith(os.path.basename(pbase)))
    say("B14", "PASS" if removed == [fakes[0]] and os.path.exists(r3["path"]) and os.path.exists(fakes[1]) else "FAIL",
        f"prune_stale removed {[os.path.basename(x) for x in removed]}, kept current + keep: {left}")

def clean():
    for h in HOLD:
        h.close()
    for n in UNITS:
        stop_unit(n)
    left = sh(["systemctl", "list-units", "--all", "--no-legend", PREFIX + "*"])[1]
    pins = [p for p in (os.listdir("/sys/fs/bpf") if os.path.isdir("/sys/fs/bpf") else []) if p.startswith("portal-rb-livetest-" + TAG)]
    for p in pins:
        try:
            B.unpin("/sys/fs/bpf/" + p)
        except (OSError, B.BpfError):
            pass
    time.sleep(1)
    pins = [p for p in (os.listdir("/sys/fs/bpf")) if p.startswith("portal-rb-livetest-" + TAG)]
    stray = sorted(USED_PORTS & listening_ports())
    dropins = sorted(__import__("glob").glob(f"/run/systemd/system.control/{PREFIX}{TAG}*"))
    for d in dropins:        # only drop-ins of our own transient units
        sh(["rm", "-rf", "--", d])
    left = sh(["systemctl", "list-units", "--all", "--no-legend", PREFIX + "*"])[1]
    say("B15", "PASS" if not left and not pins and not stray and not dropins else "FAIL",
        f"units left {left!r}, test pins left {pins}, runtime drop-ins that had to be removed {dropins}, listeners left on the used ports {stray}")


if __name__ == "__main__":
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))
    try:
        main()
    except BaseException as e:   # report, then clean up
        say("B99", "FAIL", f"{type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        clean()
    sys.exit(1 if any(s == "FAIL" for _, s in RESULTS) else 0)
