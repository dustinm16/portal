"""Client-to-server RFB message filter for the server-side browser (design section 5.4).

The bridge never lets raw bytes from the member's browser reach x11vnc: every byte goes through a
ClientFilter first. The filter is a state machine over the byte stream (RFB message boundaries are not
WebSocket frame boundaries). It is pure: no I/O, no clock, no logging, and it never keeps anything of a
message beyond the bytes it still has to complete.

    f = ClientFilter()                  # the VNC clipboard is off in both directions (decision D4)
    forward, types = f.feed(chunk)     # forward: whole messages to send on; types: message types completed
                                       # in this call (handshake bytes are not listed)

Handshake: 12 bytes protocol version (3.3, 3.7 or 3.8), for 3.7 and 3.8 one security-type byte that must be
1 (None), one ClientInit byte. Then only six message types: 0 SetPixelFormat (20 bytes), 2 SetEncodings
(4 + 4n, n <= 64, rewritten to the allow-list), 3 FramebufferUpdateRequest (10), 4 KeyEvent (8),
5 PointerEvent (6), 6 ClientCutText (8 + len, 0 <= len <= 262144, only with clipboard=True, which the bridge never
passes: since D4 text goes to the browser as typed key events only, so a ClientCutText is a Violation).

Anything else raises Violation. After a violation the filter stays dead: every later feed() raises too.
"""

from __future__ import annotations

import struct

VERSIONS = (b"RFB 003.003\n", b"RFB 003.007\n", b"RFB 003.008\n")

MAX_ENCODINGS = 64
MAX_CUT_TEXT = 262144
# The largest message the filter ever has to hold: ClientCutText header (8) plus the longest text.
MAX_BUFFER = MAX_CUT_TEXT + 8  # 262152

# Encodings the server may be told about. Everything else (extended clipboard, fence, continuous updates,
# QEMU extensions, ...) is removed, so the server never enables an extension that would make the client send
# a message type this filter refuses.
ALLOWED_ENCODINGS = frozenset(
    {0, 1, 5, 6, 7, 16}                 # Raw, CopyRect, Hextile, zlib, Tight, ZRLE
    | set(range(-32, -22))              # JPEG quality levels -23 .. -32
    | set(range(-256, -246))            # compression levels -247 .. -256
    | {-223, -224, -239, -307, -308}    # DesktopSize, LastRect, Cursor, DesktopName, ExtendedDesktopSize
)

# message type -> total length when it is fixed
_FIXED = {0: 20, 3: 10, 4: 8, 5: 6}

_ST_VERSION = 0
_ST_SECURITY = 1
_ST_INIT = 2
_ST_NORMAL = 3
_ST_DEAD = 4


class Violation(Exception):
    """The member's byte stream broke the rules. `reason` is a short fixed word, never message content."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def rewrite_encodings(encodings):
    """Intersect with the allow-list, keeping the client's order and dropping repeats."""
    out = []
    seen = set()
    for e in encodings:
        if e in ALLOWED_ENCODINGS and e not in seen:
            seen.add(e)
            out.append(e)
    return out


class ClientFilter:
    """The member's byte stream, checked message by message. `hold`, when given, is a function that says whether the session is being typed
    into by the supervisor's `type` request (Session.typing): while it says yes, every KeyEvent with its down flag set is dropped, whole (8
    bytes, nothing else shifts), and key-ups, pointer events and every other message pass. What this guarantees: no key-down of the member that
    reaches this filter while a request runs gets to x11vnc. What it does not: a key-down that passed before the mark was set, nor one that was
    sent by another route (there is none), and x11vnc may still release a key it already holds."""

    def __init__(self, clipboard: bool = False, hold=None):
        self.clipboard = bool(clipboard)
        self.hold = hold
        self.dropped = 0                # key-downs held back (a count, never content)
        self._buf = bytearray()
        self._state = _ST_VERSION
        self._v33 = False

    def _fail(self, reason: str):
        self._state = _ST_DEAD
        self._buf = bytearray()
        raise Violation(reason)

    def feed(self, data: bytes):
        if self._state == _ST_DEAD:
            raise Violation("closed")
        self._buf += data
        out = bytearray()
        types = []
        buf = self._buf
        pos = 0
        n = len(buf)
        while pos < n:
            st = self._state
            if st == _ST_VERSION:
                if n - pos < 12:
                    break
                ver = bytes(buf[pos:pos + 12])
                if ver not in VERSIONS:
                    self._fail("version")
                self._v33 = ver == VERSIONS[0]
                out += ver
                pos += 12
                self._state = _ST_INIT if self._v33 else _ST_SECURITY
            elif st == _ST_SECURITY:
                if buf[pos] != 1:
                    self._fail("security")
                out.append(1)
                pos += 1
                self._state = _ST_INIT
            elif st == _ST_INIT:
                out.append(buf[pos])
                pos += 1
                self._state = _ST_NORMAL
            else:
                t = buf[pos]
                avail = n - pos
                if t in _FIXED:
                    need = _FIXED[t]
                    if avail < need:
                        break
                    if t == 4 and buf[pos + 1] and self.hold is not None and self.hold():
                        self.dropped += 1                       # a key-down while a text is typed: held back, the whole message
                    else:
                        out += buf[pos:pos + need]
                    pos += need
                    types.append(t)
                elif t == 2:
                    if avail < 4:
                        break
                    count = struct.unpack_from(">H", buf, pos + 2)[0]
                    if count > MAX_ENCODINGS:
                        self._fail("encodings")
                    need = 4 + 4 * count
                    if avail < need:
                        break
                    encs = struct.unpack_from(">%di" % count, buf, pos + 4) if count else ()
                    keep = rewrite_encodings(encs)
                    out += struct.pack(">BBH", 2, 0, len(keep))
                    if keep:
                        out += struct.pack(">%di" % len(keep), *keep)
                    pos += need
                    types.append(2)
                elif t == 6:
                    if not self.clipboard:
                        self._fail("clipboard")
                    if avail < 8:
                        break
                    length = struct.unpack_from(">i", buf, pos + 4)[0]
                    if length < 0 or length > MAX_CUT_TEXT:
                        self._fail("length")
                    need = 8 + length
                    if avail < need:
                        break
                    out += buf[pos:pos + need]
                    pos += need
                    types.append(6)
                else:
                    self._fail("type")
        # The bound applies to what is left unconsumed, not to the size of one chunk.
        del buf[:pos]
        if len(buf) > MAX_BUFFER:
            self._fail("buffer")
        return bytes(out), types
