"""Server-side browser: the ingress BPF program of rbrowser_bpf, tested without root and without the kernel.

Run: venv/bin/python -B tests/test_rbrowser_bpf.py

A small interpreter for exactly the instruction subset the program uses runs it over crafted packets:

* it raises on any read outside [data, data_end) (the verifier's job in the kernel), on any read of a register
  that was never written, on any context read other than data and data_end, and on an unknown opcode
* IPv4 SYN / SYN-ACK / ACK / RST / FIN / data with IHL 5 and 15, a fragment, UDP, ICMP, another protocol
* IPv6 SYN / SYN-ACK / ACK / UDP / ICMPv6 / hop-by-hop / fragment header / other protocol
* every truncation 0..60 bytes of several packets: no out-of-bounds read, and the verdict equals an independent
  reference model of the documented policy
* structure: jump targets in range, last instruction exit, instruction count, no backward jump (loops)
* a deliberately broken copy (the bounds check removed) must make the interpreter report an out-of-bounds read,
  so the truncation tests prove something
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rbrowser_bpf as B  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# ---------------------------------------------------------------- the interpreter

class OutOfBounds(Exception):
    pass


class BadProgram(Exception):
    pass


CTX = 0x1000
PKT = 0x100000


def decode(prog):
    out = []
    for i in range(0, len(prog), 8):
        code, regs, off, imm = struct.unpack_from("<BBhi", prog, i)
        out.append((code, regs & 0xf, regs >> 4, off, imm))
    return out


def run(prog, packet, max_steps=1000):
    """Execute; returns r0. Raises OutOfBounds / BadProgram."""
    insns = decode(prog)
    reg = [None] * 11
    reg[1] = CTX
    pc = 0
    steps = 0
    M = (1 << 64) - 1

    def get(r):
        if reg[r] is None:
            raise BadProgram(f"read of unset r{r} at {pc}")
        return reg[r]

    while True:
        steps += 1
        if steps > max_steps or not 0 <= pc < len(insns):
            raise BadProgram(f"runaway or fell off at {pc}")
        code, dst, src, off, imm = insns[pc]
        nxt = pc + 1
        if code == 0x61 or code == 0x71:                         # ldx u32 / u8
            size = 4 if code == 0x61 else 1
            addr = (get(src) + off) & M
            if CTX <= addr < CTX + 256:
                if code != 0x61 or addr - CTX not in (B.SK_BUFF_DATA, B.SK_BUFF_DATA_END):
                    raise BadProgram(f"context read at {addr - CTX} size {size}")
                reg[dst] = PKT if addr - CTX == B.SK_BUFF_DATA else PKT + len(packet)
            else:
                if addr < PKT or addr + size > PKT + len(packet):
                    raise OutOfBounds(f"read {size} at packet offset {addr - PKT}, length {len(packet)}, pc {pc}")
                reg[dst] = packet[addr - PKT]
        elif code == 0xbf:
            reg[dst] = get(src)
        elif code == 0xb7:
            reg[dst] = imm & M
        elif code == 0x0f:
            reg[dst] = (get(dst) + get(src)) & M
        elif code == 0x07:
            reg[dst] = (get(dst) + imm) & M
        elif code == 0x57:
            reg[dst] = get(dst) & (imm & M)
        elif code == 0x4f:
            reg[dst] = get(dst) | get(src)
        elif code == 0x67:
            reg[dst] = (get(dst) << imm) & M
        elif code == 0x77:
            reg[dst] = get(dst) >> imm
        elif code == 0x05:
            nxt = pc + 1 + off
        elif code in (0x15, 0x55, 0xa5, 0x2d, 0x5d):
            a = get(dst)
            b = get(src) if code in (0x2d, 0x5d) else imm & M
            taken = {0x15: a == b, 0x55: a != b, 0xa5: a < b, 0x2d: a > b, 0x5d: a != b}[code]
            if taken:
                nxt = pc + 1 + off
        elif code == 0x95:
            return get(0)
        else:
            raise BadProgram(f"opcode {code:#x} at {pc}")
        pc = nxt


# ---------------------------------------------------------------- packets

SYN, ACK, RST, FIN, PSH = 0x02, 0x10, 0x04, 0x01, 0x08


def tcp(flags, payload=b""):
    return struct.pack("!HHIIBBHHH", 40000, 443, 1, 2, 5 << 4, flags, 1000, 0, 0) + payload


def ipv4(proto, body, ihl=5, frag=0, ver=4):
    opts = b"\x01" * ((ihl - 5) * 4)                       # NOP options
    hdr = struct.pack("!BBHHHBBH4s4s", (ver << 4) | ihl, 0, 20 + len(opts) + len(body), 1, frag, 64, proto, 0,
                      bytes([10, 1, 1, 1]), bytes([10, 1, 1, 2]))
    return hdr + opts + body


def ipv6(nh, body, ver=6):
    return struct.pack("!IHBB16s16s", (ver << 28), len(body), nh, 64, b"\x20\x01" + b"\0" * 14, b"\x20\x01" + b"\0" * 13 + b"\x02") + body


UDP = struct.pack("!HHHH", 53, 40000, 12, 0) + b"abcd"
ICMP = struct.pack("!BBHI", 8, 0, 0, 0) + b"abcd"

PROG = B.program()


def verdict(pkt, prog=PROG):
    return run(prog, pkt)


def reference(pkt):
    """The documented policy, written independently of the instruction list. 1 pass, 0 drop."""
    if len(pkt) < 1:
        return 0
    ver = pkt[0] >> 4
    if ver == 6:
        if len(pkt) < 40:
            return 0
        nh = pkt[6]
        if nh in (17, 58):
            return 1
        if nh != 6:
            return 0
        if len(pkt) < 54:
            return 0
        return 0 if pkt[53] & 0x12 == 0x02 else 1
    if ver == 4:
        if len(pkt) < 20:
            return 0
        proto = pkt[9]
        if proto in (17, 1):
            return 1
        if proto != 6:
            return 0
        if ((pkt[6] & 0x3f) << 8 | pkt[7]) != 0:
            return 0
        ihl = (pkt[0] & 15) * 4
        if ihl < 20 or len(pkt) < ihl + 14:
            return 0
        return 0 if pkt[ihl + 13] & 0x12 == 0x02 else 1
    return 0


# ---------------------------------------------------------------- structure

insns = decode(PROG)
check("the program is whole instructions", len(PROG) % 8 == 0 and len(insns) == len(PROG) // 8)
check("instruction count is 53 and below the 4096 limit", len(insns) == 53, len(insns))
check("last instruction is exit", insns[-1][0] == 0x95)
bad = []
for i, (code, dst, src, off, imm) in enumerate(insns):
    if code in (0x05, 0x15, 0x55, 0xa5, 0x2d, 0x5d):
        t = i + 1 + off
        if not (0 <= t < len(insns)):
            bad.append((i, "target out of range"))
        elif t <= i:
            bad.append((i, "backward jump"))
check("every jump target is in range and forward (no loop)", not bad, bad)
check("both verdict blocks end in exit", insns[-4][0] == 0xb7 and insns[-4][4] == 1 and insns[-2][4] == 0)
check("only the opcodes of the interpreter are used", {i[0] for i in insns} <= {0x61, 0x71, 0xbf, 0xb7, 0x0f, 0x07, 0x57, 0x4f, 0x67, 0x77, 0x05, 0x15, 0x55, 0xa5, 0x2d, 0x95})
check("registers are 0..8 (r10 untouched, no stack)", all(i[1] <= 8 and i[2] <= 8 for i in insns))
check("no call instruction (no helper, no licence need)", all(i[0] != 0x85 for i in insns))
check("listing has one line per instruction", len(B.listing().splitlines()) == len(insns))
check("tag is 8 bytes", len(B.tag()) == 8)
p = B.pin_path()
check("pin path carries a hash of the bytes and lives under /sys/fs/bpf/portal-rb",
      p.startswith("/sys/fs/bpf/portal-rb") and len(p.rsplit("-", 1)[1]) == 16 and p == B.pin_path())
check("a changed program gets another pin name", B.pin_path(prog=PROG + PROG[:8]) != p)
try:
    B.unpin("/sys/fs/bpf/other")
    refused = False
except B.BpfError:
    refused = True
check("unpin refuses a path outside /sys/fs/bpf/portal-rb", refused)
try:
    B.unpin("/sys/fs/bpf/portal-rb/../x")
    refused = False
except B.BpfError:
    refused = True
check("unpin refuses a dotdot path", refused)
ok, why = B.available()
check("available() returns (bool, str) without raising", isinstance(ok, bool) and isinstance(why, str) and (ok or why))

# the mount check: a bpf file system at /sys/fs/bpf is required; the code never mounts it
MI_OK = "35 25 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:12 - bpf bpf rw,mode=700\n"
MI_NONE = "25 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw\n"
MI_ELSEWHERE = "35 25 0:30 / /mnt/bpf rw,relatime shared:12 - bpf bpf rw\n"
MI_WRONGFS = "35 25 0:30 / /sys/fs/bpf rw,relatime shared:12 - tmpfs tmpfs rw\n"
saved = B._read_mounts
try:
    B._read_mounts = lambda: MI_OK
    check("mount check: bpf mounted at /sys/fs/bpf is recognised", B._bpffs_mounted())
    for label, text in (("no bpf mount", MI_NONE), ("bpf mounted elsewhere", MI_ELSEWHERE), ("another fs at /sys/fs/bpf", MI_WRONGFS)):
        B._read_mounts = lambda text=text: text
        ok, why = B.available()
        check(f"available() is False with a reason when there is {label}", ok is False and "not a mounted bpf file system" in why, why)
        try:
            B.load_and_pin()
            raised = False
        except B.BpfError as e:
            raised = "not a mounted bpf file system" in str(e)
        check(f"load_and_pin() raises BpfError (and mounts nothing) with {label}", raised)
finally:
    B._read_mounts = saved

# ---------------------------------------------------------------- packets: verdicts

CASES = [
    # name, packet, expected verdict
    ("IPv4 SYN is dropped", ipv4(6, tcp(SYN)), 0),
    ("IPv4 SYN-ACK passes", ipv4(6, tcp(SYN | ACK)), 1),
    ("IPv4 ACK passes", ipv4(6, tcp(ACK)), 1),
    ("IPv4 RST passes", ipv4(6, tcp(RST)), 1),
    ("IPv4 RST-ACK passes", ipv4(6, tcp(RST | ACK)), 1),
    ("IPv4 FIN-ACK passes", ipv4(6, tcp(FIN | ACK)), 1),
    ("IPv4 data (PSH-ACK) passes", ipv4(6, tcp(PSH | ACK, b"x" * 100)), 1),
    ("IPv4 no flags (null scan) passes", ipv4(6, tcp(0)), 1),
    ("IPv4 SYN with URG/ECE/CWR but no ACK is dropped", ipv4(6, tcp(SYN | 0x20 | 0xC0)), 0),
    ("IPv4 SYN-FIN is dropped", ipv4(6, tcp(SYN | FIN)), 0),
    ("IPv4 SYN with payload is dropped", ipv4(6, tcp(SYN, b"data")), 0),
    ("IPv4 IHL 15 SYN is dropped", ipv4(6, tcp(SYN), ihl=15), 0),
    ("IPv4 IHL 15 SYN-ACK passes", ipv4(6, tcp(SYN | ACK), ihl=15), 1),
    ("IPv4 IHL 15 ACK passes", ipv4(6, tcp(ACK), ihl=15), 1),
    ("IPv4 IHL 6 SYN is dropped", ipv4(6, tcp(SYN), ihl=6), 0),
    ("IPv4 IHL 4 (invalid) is dropped", ipv4(6, tcp(ACK))[:0] + bytes([0x44]) + ipv4(6, tcp(ACK))[1:], 0),
    ("IPv4 TCP with MF set (first fragment) is dropped", ipv4(6, tcp(ACK), frag=0x2000), 0),
    ("IPv4 TCP non-first fragment is dropped", ipv4(6, tcp(ACK), frag=0x0010), 0),
    ("IPv4 TCP fragment offset in the low byte only is dropped", ipv4(6, tcp(ACK), frag=0x0001), 0),
    ("IPv4 TCP with only DF set passes (ACK)", ipv4(6, tcp(ACK), frag=0x4000), 1),
    ("IPv4 TCP SYN with DF set is dropped", ipv4(6, tcp(SYN), frag=0x4000), 0),
    ("IPv4 UDP passes", ipv4(17, UDP), 1),
    ("IPv4 UDP fragment passes (UDP is not judged)", ipv4(17, UDP, frag=0x0010), 1),
    ("IPv4 ICMP passes", ipv4(1, ICMP), 1),
    ("IPv4 SCTP (132) is dropped", ipv4(132, b"\0" * 20), 0),
    ("IPv4 IPIP (4) is dropped", ipv4(4, b"\0" * 20), 0),
    ("IPv6 SYN is dropped", ipv6(6, tcp(SYN)), 0),
    ("IPv6 SYN-ACK passes", ipv6(6, tcp(SYN | ACK)), 1),
    ("IPv6 ACK passes", ipv6(6, tcp(ACK)), 1),
    ("IPv6 RST passes", ipv6(6, tcp(RST)), 1),
    ("IPv6 FIN-ACK passes", ipv6(6, tcp(FIN | ACK)), 1),
    ("IPv6 data passes", ipv6(6, tcp(PSH | ACK, b"y" * 100)), 1),
    ("IPv6 UDP passes", ipv6(17, UDP), 1),
    ("IPv6 ICMPv6 passes", ipv6(58, b"\x87\0\0\0" + b"\0" * 20), 1),
    ("IPv6 hop-by-hop header before TCP is dropped (fail closed)", ipv6(0, b"\x06\0\x01\x04\0\0\0\0" + tcp(ACK)), 0),
    ("IPv6 hop-by-hop header before ICMPv6 is dropped (fail closed)", ipv6(0, b"\x3a\0\x01\x04\0\0\0\0" + b"\0" * 8), 0),
    ("IPv6 fragment header is dropped", ipv6(44, b"\x06\0\0\0\0\0\0\1" + tcp(ACK)), 0),
    ("IPv6 destination options is dropped", ipv6(60, b"\x06\0\x01\x04\0\0\0\0" + tcp(ACK)), 0),
    ("IPv6 SCTP is dropped", ipv6(132, b"\0" * 20), 0),
    ("version 0 is dropped", bytes([0x05]) + b"\0" * 59, 0),
    ("version 5 is dropped", bytes([0x55]) + b"\0" * 59, 0),
    ("version 15 is dropped", bytes([0xf5]) + b"\0" * 59, 0),
    ("an empty packet is dropped", b"", 0),
]
for name, pkt, want in CASES:
    try:
        got = verdict(pkt)
    except (OutOfBounds, BadProgram) as e:
        check(name, False, f"interpreter: {e}")
        continue
    check(name, got == want, f"verdict {got}, want {want}")
    check(name + " (reference model agrees)", reference(pkt) == want, f"reference {reference(pkt)}")

# ---------------------------------------------------------------- truncation 0..60

BASES = {
    "IPv4 SYN IHL5": ipv4(6, tcp(SYN)),
    "IPv4 ACK IHL5": ipv4(6, tcp(ACK)),
    "IPv4 SYN IHL15": ipv4(6, tcp(SYN), ihl=15),
    "IPv4 ACK IHL15": ipv4(6, tcp(ACK), ihl=15),
    "IPv4 SYN-ACK IHL15": ipv4(6, tcp(SYN | ACK), ihl=15),
    "IPv4 UDP": ipv4(17, UDP),
    "IPv4 ICMP": ipv4(1, ICMP),
    "IPv6 SYN": ipv6(6, tcp(SYN)),
    "IPv6 ACK": ipv6(6, tcp(ACK)),
    "IPv6 UDP": ipv6(17, UDP),
    "IPv6 ICMPv6": ipv6(58, b"\x87\0\0\0" + b"\0" * 20),
    "IPv6 hop-by-hop": ipv6(0, b"\x06\0\x01\x04\0\0\0\0" + tcp(ACK)),
}
for name, base in BASES.items():
    bad = []
    for n in range(0, 61):
        pkt = base[:n]
        try:
            got = verdict(pkt)
        except OutOfBounds as e:
            bad.append((n, str(e)))
            continue
        except BadProgram as e:
            bad.append((n, str(e)))
            continue
        if got not in (0, 1) or got != reference(pkt):
            bad.append((n, f"verdict {got}, reference {reference(pkt)}"))
    check(f"truncated {name}: every length 0..60 is in bounds, defined and equal to the reference", not bad, bad[:3])

# a truncated SYN can never pass
bad = [(n, name) for name in ("IPv4 SYN IHL5", "IPv4 SYN IHL15", "IPv6 SYN") for n in range(0, 61)
       if verdict(BASES[name][:n]) == 1]
check("no prefix of a SYN passes", not bad, bad[:3])
check("the full SYN packets are dropped", all(verdict(BASES[k]) == 0 for k in ("IPv4 SYN IHL5", "IPv4 SYN IHL15", "IPv6 SYN")))

# ---------------------------------------------------------------- the interpreter itself catches a missing bounds check

broken = bytearray(PROG)
# instruction 45 is the bounds check of the TCP flags byte (if r8 > r3 goto DROP): turn it into a jump of 0
code, regs, off, imm = struct.unpack_from("<BBhi", broken, 45 * 8)
assert code == 0x2d and off > 0, (code, off)
struct.pack_into("<BBhi", broken, 45 * 8, 0x05, 0, 0, 0)
try:
    verdict(BASES["IPv4 SYN IHL15"][:40], bytes(broken))
    caught = False
except OutOfBounds:
    caught = True
check("meta: with the TCP bounds check removed the interpreter reports an out-of-bounds read", caught)

broken = bytearray(PROG)
struct.pack_into("<BBhi", broken, 19 * 8, 0x05, 0, 0, 0)       # the IPv6 TCP flags bounds check
try:
    verdict(BASES["IPv6 SYN"][:45], bytes(broken))
    caught = False
except OutOfBounds:
    caught = True
check("meta: with the IPv6 TCP bounds check removed the interpreter reports an out-of-bounds read", caught)

# a program that reads an unset register is refused by the interpreter
try:
    run(struct.pack("<BBhi", 0xbf, 0x20, 0, 0) + struct.pack("<BBhi", 0x95, 0, 0, 0), b"")
    caught = False
except BadProgram:
    caught = True
check("meta: reading an unset register is reported", caught)

print()
if failures:
    print(f"{len(failures)} FAILED:")
    for f in failures:
        print("  ", f)
    sys.exit(1)
print("all checks passed")
