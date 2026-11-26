"""Server-side browser: a cgroup-skb INGRESS BPF program that makes inbound TCP connections to a unit impossible.

Why: SocketBindDeny=any is accepted by systemd 252 on this build (systemctl --version shows -BPF_FRAMEWORK, the
libbpf-skeleton path that implements it) but NOT enforced, and an iptables OUTPUT rule cannot see the SYN-ACK of
a request socket. So a process in a browser unit could open a TCP listener that is reachable from outside. This
module builds our own program, loads it with bpf(2), pins it in bpffs and lets systemd attach it to the unit:

    systemd-run ... -p IPIngressFilterPath=<pin path> ...      (man systemd.resource-control, since v243)

systemd attaches it next to its own IPAddressDeny= program (both with BPF_F_ALLOW_MULTI); for the ingress hook
the packet is delivered only when every attached program returns 1.

What the program does (the verdict is 1 = pass, 0 = drop). It runs in the receive path of a socket of the cgroup
(sk_filter_trim_cap), so it judges only packets that are about to be delivered to a socket of that unit.
skb->data is the IP header there (the kernel pushes it back to the network header before the program runs).

    * IPv4: header (20 bytes) must be present, else drop. Protocol UDP (17) and ICMP (1): pass. TCP (6): drop
      every fragment (MF set or fragment offset != 0; IP reassembly runs before socket delivery, so the hook never
      sees one and the rule costs nothing), read the header length from the IHL nibble (below 5 words: drop),
      and drop when the TCP flags byte (offset IHL*4 + 13) has SYN set and ACK clear; a packet too short to hold
      that byte is dropped. Every other protocol (SCTP, DCCP, IPIP, GRE, ...): drop (fail closed; SCTP is a
      connection-oriented transport that the kernel would load on demand, ordinary browsing needs only TCP, UDP and
      ICMP). This is stricter than "pass everything else".
    * IPv6: the 40 byte header must be present, else drop. Next header at the fixed offset 6: UDP (17) and ICMPv6
      (58): pass. TCP (6): the flags byte at 40 + 13 decides as for IPv4. Anything else, i.e. every extension header
      (hop-by-hop, routing, fragment, destination options) and every other protocol: drop (fail closed). Ordinary
      browsing sends none of these to a socket: reassembly is done before delivery and hosts do not put extension
      headers on TCP segments; the multicast listener reports that carry hop-by-hop are not delivered to a unit's
      sockets. This is the choice the work order allowed; it was not measured to break browsing (live test B13..B15).
    * Version nibble other than 4 and 6, and an empty packet: drop.

"SYN set and ACK clear" is exactly the first segment of a connection attempt (and of a TCP simultaneous open, so
the unit cannot accept a connection without listen() either). A listener never sees a SYN, so no handshake
completes, the kernel sends no RST and the remote side times out. Outbound connections are unaffected: they
only receive SYN-ACK (SYN and ACK both set), ACKs, data, FIN and RST.

Not covered: UDP (a UDP server in the unit still receives datagrams, because UDP has no handshake and the hook
cannot tell a reply from an unsolicited datagram), anything a process does through connections it opens outward
(a reverse tunnel), abstract AF_UNIX sockets (shared with the host namespace; not a network path).

Kernel interface (constants checked against /usr/include/linux/bpf.h of the 6.1 headers, x86_64 __NR_bpf = 321):
BPF_PROG_TYPE_CGROUP_SKB = 8, BPF_CGROUP_INET_INGRESS = 0, struct __sk_buff data at offset 76 and data_end at
80; union bpf_attr layouts for BPF_PROG_LOAD, BPF_OBJ_PIN/GET, BPF_PROG_QUERY, BPF_OBJ_GET_INFO_BY_FD and
struct bpf_prog_info (type, id, tag). Direct packet access with data_end bounds checks only (no helper call, so
the licence string does not matter; "GPL" is passed anyway).

The pin: /sys/fs/bpf/<base>-<sha256 of the program bytes, 16 hex>. BPF_OBJ_PIN is atomic and fails with EEXIST,
so a changed program gets a new name and a unit started later names the new path. The file is 0600 root (checked).

A PIN MUST OUTLIVE EVERY UNIT THAT NAMES IT (measured on systemd 252, live test B12/B13). systemd opens the pin when the
unit starts (a missing pin fails the start: "bpf-firewall: Loading of ingress BPF program ... failed", result
'resources'), and opens it AGAIN every time it re-applies the unit's BPF firewall (set-property on the unit,
a property change on the slice, ...). When the pin is gone at that moment systemd logs the same line, detaches our
program and keeps the unit RUNNING WITHOUT the filter (the unit is open again). So nothing here removes a pin that a
running unit may still name: load_and_pin() does not prune, prune_stale() takes the pins that are still in use, and
the launcher should check attached() again while a session runs, not only at its start.
Everything here is standard library; importing needs no privilege, loading needs CAP_BPF + CAP_NET_ADMIN or root.
"""

import ctypes
import ctypes.util
import errno
import hashlib
import os
import platform
import struct
import sys

__all__ = ["BpfError", "program", "listing", "tag", "available", "load_and_pin", "prune_stale", "unpin", "pin_path", "attached",
           "ingress_program_ids",
           "PIN_DIR", "PIN_BASE", "PinResult"]

PIN_DIR = "/sys/fs/bpf"
PIN_BASE = PIN_DIR + "/portal-rb-ingress"
PROG_NAME = b"portal_rb_in"            # [A-Za-z0-9_.] only (a hyphen is EINVAL), at most 15 bytes
VERIFIER_LOG_SIZE = 1 << 20

# ---- bpf(2)
_NR_BPF = {"x86_64": 321, "aarch64": 280, "riscv64": 280, "armv7l": 386, "ppc64le": 361, "s390x": 351}
BPF_PROG_LOAD, BPF_OBJ_PIN, BPF_OBJ_GET = 5, 6, 7
BPF_PROG_GET_FD_BY_ID, BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_QUERY = 13, 15, 16
BPF_PROG_TYPE_CGROUP_SKB = 8
BPF_CGROUP_INET_INGRESS = 0
BPF_F_QUERY_EFFECTIVE = 1
SK_BUFF_DATA, SK_BUFF_DATA_END = 76, 80

# ---- eBPF instruction set (the subset used)
BPF_LD_X = 0x61          # ldx (BPF_LDX | BPF_MEM | BPF_W)
BPF_LDXB = 0x71          # BPF_LDX | BPF_MEM | BPF_B
BPF_LDXW = 0x61
MOV_X, MOV_K = 0xbf, 0xb7                   # BPF_ALU64 | BPF_MOV
ADD_X, ADD_K = 0x0f, 0x07
AND_K = 0x57
OR_X = 0x4f
LSH_K, RSH_K = 0x67, 0x77
JA = 0x05
JEQ_K, JNE_K, JGT_X, JLT_K, JNE_X = 0x15, 0x55, 0x2d, 0xa5, 0x5d
EXIT = 0x95

R0, R1, R2, R3, R4, R5, R6, R7, R8 = range(9)


class BpfError(Exception):
    pass


# ---------------------------------------------------------------- the program

class _Asm:
    """A tiny assembler: instructions with symbolic jump targets; each carries its comment for listing()."""

    def __init__(self):
        self.items = []          # (label or None, code, dst, src, off, imm, target label or None, text)
        self.pending = None

    def label(self, name):
        self.pending = name

    def emit(self, code, dst=0, src=0, off=0, imm=0, to=None, text=""):
        self.items.append((self.pending, code, dst, src, off, imm, to, text))
        self.pending = None

    def build(self):
        where = {it[0]: i for i, it in enumerate(self.items) if it[0]}
        out = bytearray()
        lines = []
        for i, (lab, code, dst, src, off, imm, to, text) in enumerate(self.items):
            if to is not None:
                off = where[to] - (i + 1)
            out += struct.pack("<BBhi", code, (src << 4) | dst, off, imm)
            lines.append((i, lab, text))
        return bytes(out), lines


def _assemble():
    a = _Asm()
    e = a.emit

    def ptr_check(n, why):
        # r4 = data + n ; if r4 > data_end goto DROP : the n bytes [data, data+n) are inside the packet
        e(MOV_X, R4, R2, text="r4 = r2")
        e(ADD_K, R4, imm=n, text=f"r4 += {n}")
        e(JGT_X, R4, R3, to="DROP", text=f"if r4 > r3 goto DROP    ; {why}")

    # -- context: data and data_end (32 bit loads from struct __sk_buff)
    e(LDXW, R2, R1, SK_BUFF_DATA, text=f"r2 = *(u32 *)(r1 + {SK_BUFF_DATA})    ; r2 = skb->data (the IP header)")
    e(LDXW, R3, R1, SK_BUFF_DATA_END, text=f"r3 = *(u32 *)(r1 + {SK_BUFF_DATA_END})    ; r3 = skb->data_end")
    ptr_check(1, "an empty packet has no version nibble")
    e(LDXB, R5, R2, 0, text="r5 = *(u8 *)(r2 + 0)    ; version and IHL")
    e(RSH_K, R5, imm=4, text="r5 >>= 4    ; version")
    e(JEQ_K, R5, imm=4, to="V4", text="if r5 == 4 goto V4")
    e(JNE_K, R5, imm=6, to="DROP", text="if r5 != 6 goto DROP    ; neither IPv4 nor IPv6")

    # -- IPv6
    ptr_check(40, "the fixed IPv6 header")
    e(LDXB, R5, R2, 6, text="r5 = *(u8 *)(r2 + 6)    ; next header")
    e(JEQ_K, R5, imm=6, to="V6TCP", text="if r5 == 6 goto V6TCP")
    e(JEQ_K, R5, imm=17, to="PASS", text="if r5 == 17 goto PASS    ; UDP")
    e(JEQ_K, R5, imm=58, to="PASS", text="if r5 == 58 goto PASS    ; ICMPv6")
    e(JA, to="DROP", text="goto DROP    ; extension header or other protocol: fail closed")
    a.label("V6TCP")
    ptr_check(54, "the flags byte of the TCP header (40 + 13) must be present")
    e(LDXB, R5, R2, 53, text="r5 = *(u8 *)(r2 + 53)    ; TCP flags")
    e(AND_K, R5, imm=0x12, text="r5 &= 0x12    ; SYN | ACK")
    e(JEQ_K, R5, imm=0x02, to="DROP", text="if r5 == 0x02 goto DROP    ; SYN without ACK: a connection attempt")
    e(JA, to="PASS", text="goto PASS")

    # -- IPv4
    a.label("V4")
    ptr_check(20, "the fixed IPv4 header")
    e(LDXB, R5, R2, 9, text="r5 = *(u8 *)(r2 + 9)    ; protocol")
    e(JEQ_K, R5, imm=6, to="V4TCP", text="if r5 == 6 goto V4TCP")
    e(JEQ_K, R5, imm=17, to="PASS", text="if r5 == 17 goto PASS    ; UDP")
    e(JEQ_K, R5, imm=1, to="PASS", text="if r5 == 1 goto PASS    ; ICMP")
    e(JA, to="DROP", text="goto DROP    ; any other protocol: fail closed")
    a.label("V4TCP")
    e(LDXB, R5, R2, 6, text="r5 = *(u8 *)(r2 + 6)    ; flags (reserved, DF, MF) and fragment offset, high byte")
    e(AND_K, R5, imm=0x3f, text="r5 &= 0x3f    ; MF and the high 5 bits of the offset (DF and the reserved bit ignored)")
    e(LDXB, R6, R2, 7, text="r6 = *(u8 *)(r2 + 7)    ; fragment offset, low byte")
    e(OR_X, R5, R6, text="r5 |= r6")
    e(JNE_K, R5, imm=0, to="DROP", text="if r5 != 0 goto DROP    ; a TCP fragment: cannot be judged, drop")
    e(LDXB, R6, R2, 0, text="r6 = *(u8 *)(r2 + 0)")
    e(AND_K, R6, imm=0x0f, text="r6 &= 0x0f    ; IHL in 32 bit words (0..15)")
    e(LSH_K, R6, imm=2, text="r6 <<= 2    ; header length in bytes (0..60)")
    e(JLT_K, R6, imm=20, to="DROP", text="if r6 < 20 goto DROP    ; IHL below 5 is not a valid header")
    e(MOV_X, R7, R2, text="r7 = r2")
    e(ADD_X, R7, R6, text="r7 += r6    ; r7 = the TCP header (a bounded variable offset: 20..60)")
    e(MOV_X, R8, R7, text="r8 = r7")
    e(ADD_K, R8, imm=14, text="r8 += 14")
    e(JGT_X, R8, R3, to="DROP", text="if r8 > r3 goto DROP    ; the TCP flags byte (offset 13) must be present")
    e(LDXB, R5, R7, 13, text="r5 = *(u8 *)(r7 + 13)    ; TCP flags")
    e(AND_K, R5, imm=0x12, text="r5 &= 0x12    ; SYN | ACK")
    e(JEQ_K, R5, imm=0x02, to="DROP", text="if r5 == 0x02 goto DROP    ; SYN without ACK: a connection attempt")

    a.label("PASS")
    e(MOV_K, R0, imm=1, text="r0 = 1    ; pass")
    e(EXIT, text="exit")
    a.label("DROP")
    e(MOV_K, R0, imm=0, text="r0 = 0    ; drop")
    e(EXIT, text="exit")
    return a.build()


LDXB = BPF_LDXB
LDXW = BPF_LDXW
_PROGRAM, _LINES = _assemble()


def program() -> bytes:
    """The eBPF instructions (struct bpf_insn, little endian, 8 bytes each)."""
    return _PROGRAM


def listing() -> str:
    """The program, one instruction per line: index, label, the instruction and what it is for."""
    return "\n".join(f"{i:3d}  {(lab + ':') if lab else '':8s} {text}" for i, lab, text in _LINES)


def tag(prog: bytes = None) -> bytes:
    """The 8 byte tag the kernel shows for the program (the first 8 bytes of SHA-1 over the instructions)."""
    return hashlib.sha1(prog if prog is not None else _PROGRAM).digest()[:8]


def pin_path(base: str = PIN_BASE, prog: bytes = None) -> str:
    """The pin path for the program: base + '-' + 16 hex digits of the SHA-256 of its bytes."""
    return f"{base}-{hashlib.sha256(prog if prog is not None else _PROGRAM).hexdigest()[:16]}"


# ---------------------------------------------------------------- bpf(2)

_libc = None


def _bpf(cmd: int, attr: bytearray) -> int:
    """Raw bpf(2). Returns the result (an fd for most commands) or raises OSError."""
    global _libc
    nr = _NR_BPF.get(platform.machine())
    if nr is None:
        raise BpfError(f"unknown bpf syscall number for {platform.machine()}")
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    buf = (ctypes.c_char * len(attr)).from_buffer(attr)
    ret = _libc.syscall(ctypes.c_long(nr), ctypes.c_int(cmd), buf, ctypes.c_uint(len(attr)))
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return ret


def _addr(buf) -> int:
    return ctypes.addressof(buf)


def _prog_load(prog: bytes, log_level: int):
    """BPF_PROG_LOAD. Returns (fd, log text). Raises OSError with .log set on failure."""
    insns = ctypes.create_string_buffer(prog, len(prog))
    lic = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(VERIFIER_LOG_SIZE if log_level else 1)
    attr = bytearray(128)
    struct.pack_into("<II", attr, 0, BPF_PROG_TYPE_CGROUP_SKB, len(prog) // 8)
    struct.pack_into("<QQ", attr, 8, _addr(insns), _addr(lic))
    struct.pack_into("<IIQ", attr, 24, log_level, len(log) if log_level else 0, _addr(log) if log_level else 0)
    attr[48:48 + len(PROG_NAME)] = PROG_NAME
    struct.pack_into("<I", attr, 68, BPF_CGROUP_INET_INGRESS)           # expected_attach_type
    try:
        fd = _bpf(BPF_PROG_LOAD, attr)
    except OSError as e:
        e.log = log.value.decode("latin-1") if log_level else ""
        raise
    return fd, (log.value.decode("latin-1") if log_level else "")


def _obj_path_op(cmd: int, path: str, fd: int = 0) -> int:
    p = ctypes.create_string_buffer(os.fsencode(path))
    attr = bytearray(16)
    struct.pack_into("<QII", attr, 0, _addr(p), fd, 0)
    return _bpf(cmd, attr)


def _prog_info(fd: int) -> dict:
    info = ctypes.create_string_buffer(256)
    attr = bytearray(16)
    struct.pack_into("<IIQ", attr, 0, fd, len(info), _addr(info))
    _bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    raw = info.raw
    ptype, pid = struct.unpack_from("<II", raw, 0)
    return {"type": ptype, "id": pid, "tag": bytes(raw[8:16]), "name": raw[64:80].split(b"\0")[0].decode("latin-1")}


def _read_mounts() -> str:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _bpffs_mounted(directory: str = PIN_DIR) -> bool:
    for line in _read_mounts().splitlines():
        left, sep, right = line.partition(" - ")
        f = left.split()
        if sep and len(f) > 4 and f[4] == directory and right.split()[:1] == ["bpf"]:
            return True
    return False


def _capabilities() -> int:
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def available(pin_dir: str = PIN_DIR):
    """(True, "") when the program can be loaded and pinned here, else (False, the reason). Checks only: reads
    /proc, loads nothing, mounts nothing (the bpf file system is a host decision; the reason says it is missing)."""
    if not sys.platform.startswith("linux"):
        return False, "not Linux"
    if sys.byteorder != "little":
        return False, "the instruction encoding is little endian only"
    if platform.machine() not in _NR_BPF:
        return False, f"no bpf syscall number known for {platform.machine()}"
    if not _bpffs_mounted(pin_dir):
        return False, f"{pin_dir} is not a mounted bpf file system (mount -t bpf bpf {pin_dir}); it is not mounted here"
    caps = _capabilities()
    sys_admin, net_admin, cap_bpf = 1 << 21, 1 << 12, 1 << 39
    if not (caps & sys_admin or (caps & cap_bpf and caps & net_admin)):
        return False, "needs root (CAP_SYS_ADMIN, or CAP_BPF with CAP_NET_ADMIN) to load a cgroup BPF program"
    return True, ""


class PinResult(dict):
    """path (the pin to give IPIngressFilterPath=), id (kernel program id), tag (hex), created (False when the
    pin already held this program)."""

    __getattr__ = dict.__getitem__


def _check_pin_name(path: str):
    if not os.path.abspath(path).startswith(PIN_DIR + "/portal-rb") or ".." in path.split("/"):
        raise BpfError(f"refusing a pin outside {PIN_DIR}/portal-rb*: {path!r}")


def load_and_pin(base: str = PIN_BASE) -> PinResult:
    """Load the program and pin it at pin_path(base). Idempotent: when the pin exists and holds this program
    (checked by tag and type) nothing is loaded. The pin is created 0600 root. A different program with the same
    base lives under another name, so replacing never leaves a window without a pin. Old pins are NOT removed
    here (a running unit needs its pin for as long as it runs, see the module docstring): call prune_stale().
    Returns a PinResult; raises BpfError, with the verifier log when the verifier refuses."""
    ok, why = available(os.path.dirname(base) or PIN_DIR)
    if not ok:
        raise BpfError(why)
    _check_pin_name(base)
    prog = program()
    path = pin_path(base, prog)
    created = False
    try:
        fd = _obj_path_op(BPF_OBJ_GET, path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise BpfError(f"BPF_OBJ_GET {path}: {e}") from e
        fd = None
    if fd is not None:
        try:
            info = _prog_info(fd)
        finally:
            os.close(fd)
        if info["type"] != BPF_PROG_TYPE_CGROUP_SKB or info["tag"] != tag(prog):
            raise BpfError(f"{path} exists but does not hold this program ({info})")
    else:
        try:
            fd, _log = _prog_load(prog, 0)
        except OSError as first:
            try:                                  # again with the verifier log, to say why
                fd, _log = _prog_load(prog, 1)
            except OSError as e:
                raise BpfError(f"BPF_PROG_LOAD failed: {e} (first try: {first})\nverifier log:\n{getattr(e, 'log', '')}") from e
        try:
            _obj_path_op(BPF_OBJ_PIN, path, fd)      # the kernel makes it 0600 minus umask; checked and fixed below
            created = True
            info = _prog_info(fd)
        except OSError as e:
            raise BpfError(f"BPF_OBJ_PIN {path}: {e}") from e
        finally:
            os.close(fd)
    st = os.stat(path)
    if st.st_uid != 0 or (st.st_mode & 0o777) != 0o600:
        os.chmod(path, 0o600)
        st = os.stat(path)
        if st.st_uid != 0 or (st.st_mode & 0o777) != 0o600:
            raise BpfError(f"{path} is {oct(st.st_mode & 0o777)} uid {st.st_uid}, not 0600 root")
    return PinResult(path=path, id=info["id"], tag=info["tag"].hex(), created=created)


def prune_stale(base: str = PIN_BASE, keep=()) -> list:
    """Remove the pins of `base` (name = base + '-' + 16 hex digits) other than the current one and the paths in
    `keep`. The caller MUST put in `keep` every pin that a running unit names (see the module docstring): removing
    one lets the next re-apply of that unit's BPF firewall detach the filter silently. Returns the removed paths."""
    _check_pin_name(base)
    cur = pin_path(base)
    keep = {os.path.abspath(k) for k in keep} | {cur}
    d, b = os.path.split(base)
    removed = []
    for name in sorted(os.listdir(d)):
        full = os.path.join(d, name)
        suffix = name[len(b) + 1:]
        if (name.startswith(b + "-") and len(suffix) == 16 and all(c in "0123456789abcdef" for c in suffix)
                and full not in keep):
            try:
                os.unlink(full)
                removed.append(full)
            except OSError:
                pass
    return removed


def unpin(path: str) -> bool:
    """Remove a pin created here (only paths under /sys/fs/bpf/portal-rb*). True when a file was removed."""
    _check_pin_name(path)
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def ingress_program_ids(cgroup_path: str) -> list:
    """The ids of the programs attached to the cgroup's own ingress hook (BPF_PROG_QUERY, not the effective
    set of the parents). Raises FileNotFoundError when the cgroup does not exist, BpfError on other errors."""
    cfd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        n = 64
        ids = (ctypes.c_uint32 * n)()
        attr = bytearray(48)
        struct.pack_into("<IIIIQI", attr, 0, cfd, BPF_CGROUP_INET_INGRESS, 0, 0, _addr(ids), n)
        try:
            _bpf(BPF_PROG_QUERY, attr)
        except OSError as e:
            raise BpfError(f"BPF_PROG_QUERY {cgroup_path}: {e}") from e
        cnt = struct.unpack_from("<I", attr, 24)[0]
        return list(ids)[:min(cnt, n)]
    finally:
        os.close(cfd)


def attached(cgroup_path: str, pin: str = None) -> bool:
    """True when THIS program is attached to the cgroup's ingress hook. The id of the program behind the pin
    (default: pin_path() of program()) is looked up and compared with the ids that BPF_PROG_QUERY returns for the
    cgroup; counting programs would prove nothing, because IPAddressDeny= attaches systemd's own program too.
    False when the pin is missing, the cgroup is gone or nothing matches; raises BpfError on other errors.
    The launcher calls it right after the unit started (systemd attaches before it forks the first process)."""
    pin = pin or pin_path()
    try:
        pfd = _obj_path_op(BPF_OBJ_GET, pin)
    except FileNotFoundError:
        return False
    except OSError as e:
        raise BpfError(f"BPF_OBJ_GET {pin}: {e}") from e
    try:
        want = _prog_info(pfd)["id"]
    finally:
        os.close(pfd)
    try:
        return want in ingress_program_ids(cgroup_path)
    except FileNotFoundError:
        return False


if __name__ == "__main__":
    print(listing())
    print("tag", tag().hex(), "pin", pin_path(), "available", available())
