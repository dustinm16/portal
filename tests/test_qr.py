"""The QR encoder of the two-factor dialog (static/js/qr.js, 1.24.1): byte mode, level M, versions 1 to 10.

No QR library is installed and none is added, so the symbol is judged three ways:
  1. Published values: the Reed-Solomon codewords of the "HELLO WORLD" examples (1-M and 1-Q), the 15-bit format
     strings of level M (BCH code plus the 0x5412 mask) and the 18-bit version information of versions 7 to 10.
  2. A small reference decoder written here from the standard's layout and not sharing code with the encoder: it
     finds the format information in both of its places, removes the mask, reads the zigzag, puts the blocks back in
     order, checks that every block is a Reed-Solomon codeword (all syndromes zero, own GF(256) arithmetic), and reads
     the byte segment back. Run over strings of every capacity boundary of versions 1 to 10 (exactly full, and one
     byte more which must move to the next version), UTF-8 text and an otpauth address.
  3. Structure: finder, timing and dark modules, and a string longer than version 10 holds is refused.
What it does not prove: that a phone camera reads it (no scanner is available here); the layout of the format bits is
checked against the standard's description from memory by two routes, not against a scanner.
Run: venv/bin/python tests/test_qr.py   (needs node; 60 second deadline)
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({str(detail)[:300]})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


NODE = shutil.which("node")
CAPACITY = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213]     # bytes of byte mode at level M, versions 1..10


def run(ask):
    out = subprocess.run([NODE, str(ROOT / "tests" / "qr_dump.js"), str(ROOT / "static" / "js" / "qr.js"), json.dumps(ask)],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[-500:])
    return json.loads(out.stdout)


# ---- reference decoder ------------------------------------------------------------------------------------------
EXP, LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    EXP[_i], LOG[_x] = _x, _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gmul(a, b):
    return EXP[LOG[a] + LOG[b]] if a and b else 0


def bch(value, poly, check_bits):
    """value followed by the remainder of value * x^check_bits divided by the generator polynomial."""
    rem = value << check_bits
    top = poly.bit_length() - 1
    for shift in range(rem.bit_length() - 1, top - 1, -1):
        if rem >> shift & 1:
            rem ^= poly << (shift - top)
    return (value << check_bits) | rem


# Level M: (error correction codewords per block, [(blocks, data codewords)...]), the standard's table
M_TABLE = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
           6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
           10: (26, [(4, 43), (1, 44)])}
ALIGN = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
FORMAT_M = [bch(mask, 0x537, 10) ^ 0x5412 for mask in range(8)]       # level bits 00, then the mask number


def total_codewords(version):
    """The number of codewords a symbol holds, from the count of modules left after the function patterns."""
    raw = (16 * version + 128) * version + 64
    if version >= 2:
        n = version // 7 + 2
        raw -= (25 * n - 10) * n - 55
        if version >= 7:
            raw -= 36
    return raw // 8


def reserved(version):
    size = 4 * version + 17
    res = [[False] * size for _ in range(size)]

    def box(r0, c0, r1, c1):
        for r in range(max(r0, 0), min(r1, size - 1) + 1):
            for c in range(max(c0, 0), min(c1, size - 1) + 1):
                res[r][c] = True
    box(0, 0, 8, 8); box(0, size - 8, 8, size - 1); box(size - 8, 0, size - 1, 8)        # finders, separators, format
    box(6, 0, 6, size - 1); box(0, 6, size - 1, 6)                                       # timing
    if version >= 7:
        box(0, size - 11, 5, size - 9); box(size - 11, 0, size - 9, 5)                   # version information
    pos = ALIGN.get(version, [])
    for i, a in enumerate(pos):
        for j, b in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                continue
            box(a - 2, b - 2, a + 2, b + 2)
    return res


def decode(rows):
    """The text a symbol holds, or raises AssertionError saying what is wrong with it."""
    m = [[c == "1" for c in row] for row in rows]
    size = len(m)
    version = (size - 17) // 4
    assert size == 4 * version + 17 and 1 <= version <= 10, f"size {size}"
    # format information, both copies, most significant bit first
    copy1 = [(8, c) for c in (0, 1, 2, 3, 4, 5, 7, 8)] + [(r, 8) for r in (7, 5, 4, 3, 2, 1, 0)]
    copy2 = [(r, 8) for r in range(size - 1, size - 8, -1)] + [(8, c) for c in range(size - 8, size)]
    v1 = int("".join("1" if m[r][c] else "0" for r, c in copy1), 2)
    v2 = int("".join("1" if m[r][c] else "0" for r, c in copy2), 2)
    assert v1 == v2, f"the two copies of the format information differ: {v1:015b} {v2:015b}"
    assert v1 in FORMAT_M, f"format information {v1:015b} is not a level M code"
    mask = FORMAT_M.index(v1)
    assert m[size - 8][8], "the dark module is missing"
    if version >= 7:
        want = bch(version, 0x1F25, 12)
        got_a = sum((m[i // 3][size - 11 + i % 3] << i) for i in range(18))
        got_b = sum((m[size - 11 + i % 3][i // 3] << i) for i in range(18))
        assert got_a == got_b == want, f"version information {got_a:018b} {got_b:018b} want {want:018b}"
    res = reserved(version)
    fn = [
        lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0, lambda r, c: (r + c) % 3 == 0,
        lambda r, c: (r // 2 + c // 3) % 2 == 0, lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
        lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0, lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0][mask]
    bits = []
    col, going_up = size - 1, True
    while col > 0:
        if col == 6:
            col -= 1
        for r in (range(size - 1, -1, -1) if going_up else range(size)):
            for c in (col, col - 1):
                if not res[r][c]:
                    bits.append(m[r][c] ^ fn(r, c))
        going_up = not going_up
        col -= 2
    n = total_codewords(version)
    assert len(bits) >= n * 8 and not any(bits[n * 8:]), f"{len(bits)} data bits for {n} codewords, remainder bits must be light"
    cw = [int("".join("1" if b else "0" for b in bits[i * 8:i * 8 + 8]), 2) for i in range(n)]
    ec_len, groups = M_TABLE[version]
    lens = [d for count, d in groups for _ in range(count)]
    assert sum(lens) + ec_len * len(lens) == n, "table does not add up to the symbol's codewords"
    data_total = sum(lens)
    blocks = [[] for _ in lens]
    pos = 0
    for i in range(max(lens)):
        for b, dl in enumerate(lens):
            if i < dl:
                blocks[b].append(cw[pos]); pos += 1
    ecs = [[] for _ in lens]
    for i in range(ec_len):
        for b in range(len(lens)):
            ecs[b].append(cw[pos]); pos += 1
    for b in range(len(lens)):
        word = blocks[b] + ecs[b]
        for root in range(ec_len):                  # the generator's roots are alpha^0 .. alpha^(ec_len - 1)
            acc = 0
            for coef in word:
                acc = gmul(acc, EXP[root]) ^ coef
            assert acc == 0, f"block {b}: syndrome {root} is not zero"
    data = [x for blk in blocks for x in blk]
    assert len(data) == data_total
    stream = "".join(f"{x:08b}" for x in data)
    assert stream[:4] == "0100", f"mode {stream[:4]} is not byte mode"
    cbits = 8 if version <= 9 else 16
    count = int(stream[4:4 + cbits], 2)
    body = stream[4 + cbits:4 + cbits + 8 * count]
    text = bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8))
    rest = stream[4 + cbits + 8 * count:]
    assert rest[:4] == "0000" or len(rest) < 4, "no terminator"
    pad_start = ((4 + cbits + 8 * count + min(4, len(rest)) + 7) // 8)
    pads = data[pad_start:]
    assert all(p == (0xEC if i % 2 == 0 else 0x11) for i, p in enumerate(pads)), "bad pad bytes"
    return text.decode("utf-8"), version


if not NODE:
    check("node is available", False, "install node to run the encoder checks")
else:
    # ---- 1. published values
    got = run({"rs": [[[32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17], 10],
                      [[32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236], 13]],
               "format": list(range(8)), "version": [7, 8, 9, 10]})
    check("Reed-Solomon: the published HELLO WORLD 1-M codewords", got["rs"][0] == [196, 35, 39, 119, 235, 215, 231, 226, 93, 23], got["rs"][0])
    check("Reed-Solomon: the published HELLO WORLD 1-Q codewords", got["rs"][1] == [168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16], got["rs"][1])
    published_format = ["101010000010010", "101000100100101", "101111001111100", "101101101001011",
                        "100010111111001", "100000011001110", "100111110010111", "100101010100000"]
    check("format information: the published level M strings for the eight masks",
          [f"{v:015b}" for v in got["format"]] == published_format, [f"{v:015b}" for v in got["format"]])
    check("format information: the same values from the reference's own BCH division", got["format"] == FORMAT_M)
    check("version information of versions 7 to 10 as published",
          [f"{v:018b}" for v in got["version"]] == ["000111110010010100", "001000010110111100", "001001101010011001", "001010010011010011"],
          [f"{v:018b}" for v in got["version"]])
    check("the table of blocks adds up to the number of codewords each version holds (from the module count)",
          all(M_TABLE[v][0] * sum(c for c, _ in M_TABLE[v][1]) + sum(c * d for c, d in M_TABLE[v][1]) == total_codewords(v) for v in M_TABLE)
          and [total_codewords(v) for v in range(1, 11)] == [26, 44, 70, 100, 134, 172, 196, 242, 292, 346])
    check("byte capacity per version agrees with the data codewords (mode and count field first)",
          all((sum(c * d for c, d in M_TABLE[v][1]) * 8 - 4 - (8 if v <= 9 else 16)) // 8 == CAPACITY[v - 1] for v in M_TABLE))

    # ---- 2. the reference decoder over every boundary
    texts = ["A", "Hello", "otpauth://totp/Portal:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Portal",
             "café über €", "\x00\x01\x7f"]
    for v, cap in enumerate(CAPACITY, 1):
        texts += [("x7Q" * 100)[:cap], ("k9" * 200)[:cap + 1] if cap < 213 else ("k9" * 200)[:cap]]
    answers = run({"encode": texts})["encode"]
    for text, qr in zip(texts, answers):
        label = f"{len(text.encode('utf-8'))} bytes"
        if qr is None:
            check(f"encodes {label}", False, "refused")
            continue
        try:
            back, version = decode(qr["rows"])
            ok, detail = back == text, f"decoded {back[:40]!r} version {version}"
        except AssertionError as e:
            ok, detail, version = False, str(e), qr["version"]
        smallest = next(i for i, c in enumerate(CAPACITY, 1) if len(text.encode("utf-8")) <= c)
        check(f"a decoder reads {label} back, version {qr['version']} (the smallest that holds it is {smallest})",
              ok and qr["version"] == smallest and version == smallest, detail)
    check("text longer than version 10 holds (214 bytes) is refused, not truncated", run({"encode": ["z" * 214]})["encode"] == [None])
    check("the empty string still makes a symbol", run({"encode": [""]})["encode"][0] is not None)

    # ---- 3. structure of one symbol and the drawing
    qr = run({"encode": ["Hello"]})["encode"][0]
    rows = qr["rows"]
    n = qr["size"]
    finder = ["1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"]
    check("the three finder patterns sit in three corners and not the fourth",
          all(rows[r][c:c + 7] == finder[r - r0] for r0, c in ((0, 0), (0, n - 7), (n - 7, 0)) for r in range(r0, r0 + 7))
          and rows[n - 7][n - 7:] != "1111111"[: 7])
    check("the timing patterns alternate between the finders",
          all(rows[6][c] == ("1" if c % 2 == 0 else "0") and rows[c][6] == ("1" if c % 2 == 0 else "0") for c in range(8, n - 8)))
    long_text = "otpauth://totp/Portal:alice?secret=JBSWY3DPEHPK3PXP&issuer=Portal"
    drawn = run({"encode": [], "draw": long_text, "pixels": 200})["draw"]
    q2 = run({"encode": [long_text]})["encode"][0]
    cells = q2["size"] + 8
    rects = [c for c in drawn["calls"] if c[0] == "rect"]
    check("draw: it succeeds, the canvas is square and a whole number of pixels per module", drawn["ok"] and drawn["width"] == drawn["height"]
          and drawn["width"] % cells == 0 and drawn["width"] <= 200, str(drawn["width"]))
    check("draw: white first over the whole canvas (a dark page theme must not show through), then black",
          drawn["calls"][0] == ["style", "#ffffff"] and drawn["calls"][1][1:] == [0, 0, drawn["width"], drawn["width"]]
          and ["style", "#000000"] in drawn["calls"])
    scale = drawn["width"] // cells
    dark = sum(row.count("1") for row in q2["rows"])
    check("draw: one filled square per dark module, inside a four-module quiet zone",
          len(rects) == dark + 1 and all(r[1] >= 4 * scale and r[2] >= 4 * scale and r[1] + scale <= (cells - 4) * scale
                                         and r[2] + scale <= (cells - 4) * scale for r in rects[1:]), f"{len(rects)} {dark}")
    refused = run({"encode": [], "draw": "z" * 300})["draw"]
    check("draw: text that does not fit draws nothing and answers false (the dialog then shows only the key)",
          refused["ok"] is False and refused["calls"] == [])

# ---- the dialog
index = (ROOT / "static" / "index.html").read_text()
admin_js = (ROOT / "static" / "js" / "admin.js").read_text()
qr_tag, admin_tag = '<script src="/static/js/qr.js?v=1"></script>', '/static/js/admin.js?v='
check("index.html loads qr.js (versioned) before admin.js, which opens the two-factor dialog",
      qr_tag in index and index.index(qr_tag) < index.index(admin_tag))
setup = admin_js[admin_js.index("// Generate QR code"):admin_js.index("// Reset and show setup modal")]
check("the dialog draws the otpauth address with PortalQR and, when that is refused, hides the picture and keeps the key",
      "PortalQR.draw(canvas, data.uri" in setup and "2fa-qr-container" in setup and "2fa-secret-display" in admin_js[:admin_js.index("// Generate QR code")][-400:]
      and "QRCode" not in setup.replace("PortalQR", ""))
if NODE:
    def dialog(uri):
        out = subprocess.run([NODE, str(ROOT / "tests" / "qr_dialog_harness.js"), str(ROOT / "static" / "js" / "qr.js"),
                              str(ROOT / "static" / "js" / "admin.js"), uri], capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout) if out.returncode == 0 else {"error": out.stderr[-300:]}
    shown = dialog("otpauth://totp/Portal:alice?secret=JBSWY3DPEHPK3PXP&issuer=Portal")
    check("the two-factor dialog shows the picture for a normal address: box visible, canvas drawn, the intro says to scan it",
          shown.get("box") == "inline-block" and shown.get("canvasWidth", 0) > 100 and "Scan this QR code" in shown.get("intro", ""), shown)
    hidden = dialog("otpauth://totp/" + "x" * 300)
    check("for an address too long for version 10 it hides the picture and says to enter the key",
          hidden.get("box") == "none" and "entering the key below" in hidden.get("intro", ""), hidden)
check("the code uses no CDN or other script", "cdn" not in (ROOT / "static" / "js" / "qr.js").read_text().lower()
      and "innerHTML" not in (ROOT / "static" / "js" / "qr.js").read_text())

if failed:
    print(f"\ntest_qr: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_qr: all checks passed")
