"""The supervisor that runs inside one browser unit (design section 4.5).

Standard library only: the unit runs it as `/usr/bin/python3 -I -S /mnt/session.py`, so nothing from the
portal's checkout or its virtual environment exists there. Importing this file starts nothing; main() runs
only when the file is executed as a script. Every decision that can be taken from plain text or numbers is a
pure function (the tests in tests/test_rbrowser_supervisor.py use them with fixture text, there is no X
server in a test).

The steps:
    1. environment, the X authority file with a fresh cookie
    2. Xvfb on a display it picks itself (-displayfd), then the ownership proof against /proc/net/unix
    3. xrandr: a mode for RB_GEOMETRY; every later resize removes the previous mode
    4. x11vnc on a unix socket only, with the selection exchange switched off in both directions (decision D4)
    5. the built-in window manager (decision D2): every top-level window is the size of the screen at 0,0
    6. Chromium (no debugging pipe, no debugging port: nothing reads its tabs)
    7. ctl.sock with four operations: ping, resize, clip and type
    8. a one second loop over all children, the control socket and the window manager's X events

Exit codes: 0 when Chromium ended by itself with status 0, 3 when the display proof failed, 4 otherwise.

This process never prints, stores or forwards a URL, a page title or page content. RB_HOME goes into
Chromium's command line and nowhere else. The one thing it reads out of the browser is the CLIPBOARD selection,
on the request "clip" of the control socket, and that text goes into the reply and nowhere else (never the
journal, never a file).
"""

import collections
import ctypes
import json
import os
import re
import secrets
import select
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

# ---- constants that must equal rbrowser_launch.MIN_W and CAPTURE_MAX (a test pins it): this file runs from
# /mnt with -I -S and cannot import the portal's modules.
MIN_W = 560
MIN_H = 480
MAX_W = 1920
MAX_H = 1200
SNAP = 16

EXIT_OK = 0
EXIT_DISPLAY = 3
EXIT_OTHER = 4

CTL_MAX = 4096                 # bytes of one control request
CTL_READ_S = 2.0               # how long a client may take to send its line
DISPLAYFD_WAIT_S = 5.0
LOOP_S = 1.0
CHROMIUM_TERM_WAIT_S = 2.0
RESIZE_BUDGET_S = 1.5
XRANDR_WAIT_S = 2.0
OPEN_TRIES = 10               # XOpenDisplay attempts of the mode holder, OPEN_PAUSE_S apart
OPEN_PAUSE_S = 0.3
CLIP_MAX = 262144             # bytes of the CLIPBOARD text a `clip` request returns; more is cut and flagged
CLIP_WAIT_S = 2.0             # time limit of one `clip` request
CTL_REPLY_S = 5.0             # how long a client may take to read a reply (a clip answer is up to about 1 MB)
# `type` (1.26.3): text typed by this process through XTEST. Measured on the rig (5000 mixed characters incl. CJK and emoji per run, 4 CPUs,
# also with 8 busy loops): with no wait between a key's new binding and its press thousands of characters were wrong, 2 ms gave 1 wrong
# in 5000 under load, 5 ms none in 40000, 10 ms none. Chromium handles the change of the map on its own time, so the press must not come too
# soon after it. A wait before a key is rebound again made it worse, not better (14 wrong in 5000 under load against none without it):
# a busy Chromium works through the map change and the key in the order they were sent, an idle one starts on the key while it still reads the map.
TYPE_MAX_CHARS = 5000         # characters of one `type` request (the page's own limit)
CTL_TYPE_MAX = 70000          # bytes of a `type` request line: 5000 characters, an emoji as two \uXXXX escapes, about 60 KB
TYPE_BUDGET_S = 55.0          # time limit of one `type` request (5000 different characters take 50 s); what is not typed by then is reported as not typed
SCRATCH_COUNT = 8             # keys this process owns for typing; never empty, so x11vnc never takes one
SCRATCH_SYM = 0xFFFFFF        # VoidSymbol: what a scratch key holds when it is not in use
TYPE_MAP_WAIT_S = 0.010       # between a key's new binding and its press (Chromium reads the map on the change)
TYPE_SETTLE_S = 0.080         # a scratch key is not rebound, and goes back to the placeholder, sooner than this after its last press (Chromium reads a key later than it is sent)
TYPE_MOD_STRIKES = 2          # a held Control, Alt, Super or AltGr key is found down more than this many times in one request (a key held or auto-repeating, not tapped): the run stops
LOCK_MASK = 2                 # the Lock bit of the pointer state mask (Caps Lock)
KEYSYM_CAPS_LOCK = 0xFFE5
TYPE_PUMP_S = 0.05            # the window manager is served at least this often while typing
KEYSYM_RETURN = 0xFF0D
KEYSYM_TAB = 0xFF09
BIN_DIRS = ("/usr/bin", "/bin")
PATH_VALUE = "/usr/bin:/bin"
# Everything a page can make Chromium write lives on the unit's own size-capped tmpfs (TemporaryFileSystem=/run/work in
# rbrowser_launch). /tmp and /var/tmp cannot be used for this: DynamicUser=yes forces PrivateTmp=yes, and systemd 252
# applies that private directory (on the root disk) over a TemporaryFileSystem= of the same path [live round 1, G02].
WORK_DIR = "/run/work"
HOME_DIR = f"{WORK_DIR}/home"
PROFILE_DIR = f"{WORK_DIR}/profile"
TMP_DIR = f"{WORK_DIR}/tmp"
SCREEN = f"{MAX_W}x{MAX_H}x24"
HOME_URL_MAX = 300
THEME_MODES = ("dark", "light")                  # RB_THEME_MODE (the member's portal theme, 1.26.0)
THEME_DARK_FLAG = "--force-dark-mode"
CLIPBOARD_MODES = ("both", "to_browser", "off")   # RB_CLIPBOARD: only "both" lets the `clip` request answer
# x11vnc with the selection exchange off in both directions (decision D4). -nosel alone is "no exchange at all"; the
# other four are named as well so that a build that reads one of them differently still has nothing to exchange.
# -input KMB leaves out C, which refuses clipboard input from a viewer.
NO_CLIPBOARD_FLAGS = ("-nosel", "-noprimary", "-nosetprimary", "-noclipboard", "-nosetclipboard", "-input", "KMB")
UNIX_LISTEN_FLAG = 0x10000     # /proc/net/unix Flags column: __SO_ACCEPTCON
X_ABSTRACT_PREFIX = "@/tmp/.X11-unix/X"
XAUTH_PROTOCOL = b"MIT-MAGIC-COOKIE-1"
XAUTH_FAMILY_WILD = 0xFFFF

# The offline set of tools/make_screenshots.py (OFFLINE_CHROMIUM_ARGS) is part of this list, including
# --no-proxy-server; the policy also pins ProxyMode=direct.
CHROMIUM_FLAGS = (
    f"--user-data-dir={PROFILE_DIR}", "--no-first-run", "--no-default-browser-check",
    "--window-position=0,0", "--password-store=basic", "--disable-gpu", "--disable-dev-shm-usage",
    "--mute-audio", "--disk-cache-size=134217728", "--media-cache-size=67108864", "--no-proxy-server",
    "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
    "--disable-field-trial-config", "--disable-domain-reliability", "--no-pings", "--disable-breakpad",
    "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update", "--disable-logging",
    # Document Picture-in-Picture (documentPictureInPicture.requestWindow, needs a user gesture) opens an ordinary window that holds page
    # content; the built-in window manager puts every such window at the full screen, so a page could draw a toolbar in it. Measured live
    # (G13, Chromium 156): without this switch the window opens at 0,0 full screen. No policy turns the API off. The feature name is in the
    # installed binary (`grep -a DocumentPictureInPictureAPI /usr/lib/chromium/chromium`), and G13's control session without it proves it works.
    "--disable-features=DocumentPictureInPictureAPI",
)


class SupervisorError(Exception):
    """Something the supervisor cannot go on without. The text never contains a URL."""


class DisplayMismatch(SupervisorError):
    """The display proof failed: the abstract X name is not held by our own Xvfb."""


class CtlError(Exception):
    """A control request that is not allowed. `reason` is a short fixed word."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ================================================================ pure helpers

def snap(value, step=SNAP):
    """Round down to a multiple of `step`."""
    return value - (value % step)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def clamp_geometry(w, h):
    """(w, h) clamped to MIN_W..MAX_W x MIN_H..MAX_H and snapped down to multiples of 16."""
    if not _is_int(w) or not _is_int(h):
        raise ValueError("geometry must be integers")
    w = snap(min(max(w, MIN_W), MAX_W))
    h = snap(min(max(h, MIN_H), MAX_H))
    return max(w, MIN_W), max(h, MIN_H)


def parse_geometry(text):
    """'1280x720' -> clamped (w, h). Raises ValueError on anything else."""
    m = re.fullmatch(r"([0-9]{1,5})x([0-9]{1,5})", text or "")
    if not m:
        raise ValueError("RB_GEOMETRY must be WxH")
    return clamp_geometry(int(m.group(1)), int(m.group(2)))


def valid_home(url):
    """RB_HOME ends up on Chromium's command line: it must be an https URL, so it can never be read as a flag."""
    return (isinstance(url, str) and url.startswith("https://") and len(url) <= HOME_URL_MAX
            and all(0x20 < ord(c) < 0x7F for c in url))


def valid_clipboard(mode):
    return mode in CLIPBOARD_MODES


def xvfb_argv(binary, fd, xauth):
    """Xvfb picks its own display (-displayfd), keeps both unix listeners (no -nolisten local) and no TCP."""
    return [binary, "-displayfd", str(fd), "-screen", "0", SCREEN, "-nolisten", "tcp", "-auth", xauth,
            "+extension", "RANDR", "-dpi", "96"]


def x11vnc_argv(binary, display, xauth, sock):
    """Unix socket only: -rfbport 0, -rfbportv6 -1, -noipv6, -no6 (this host's x11vnc is built with the -6 listening
    mode ON by default and its help says "you MUST supply the -no6 option" to disable it). -safer = -novncconnect -noremote and no -gui;
    -nocmds = no external commands. No -shared. The selection exchange is off both ways (NO_CLIPBOARD_FLAGS): text
    reaches the browser only as typed key events, and leaves it only through the control socket's `clip`."""
    return ([binary, "-display", f":{display}", "-auth", xauth, "-unixsock", sock, "-rfbport", "0",
             "-rfbportv6", "-1", "-noipv6", "-no6", "-nopw", "-forever", "-noxdamage", "-xrandr", "-norc", "-nobell",
             "-safer", "-nocmds", "-q", *NO_CLIPBOARD_FLAGS])


def valid_theme_mode(mode):
    """RB_THEME_MODE: exactly "dark" or "light". Anything else is not an error: the member just gets the neutral default."""
    return mode if mode in THEME_MODES else None


def chromium_argv(binary, w, h, home, theme_mode=None):
    """`theme_mode` "dark" adds --force-dark-mode (measured on Chromium 156 under Xvfb: it makes the browser's own UI dark and the pages'
    prefers-color-scheme report dark, and recolours no page content; the colour policy BrowserColorScheme did neither). "light" and None add
    nothing: light is what Chromium does without a desktop. The switch is a constant here; no part of the mode reaches the command line."""
    extra = [THEME_DARK_FLAG] if valid_theme_mode(theme_mode) == "dark" else []
    return [binary, *CHROMIUM_FLAGS, *extra, f"--window-size={w},{h}", home]


def child_env(display=None, xauth=None):
    """The environment of every child, built from nothing: no proxy variable, nothing of the unit's own."""
    env = {"PATH": PATH_VALUE, "HOME": HOME_DIR, "TMPDIR": TMP_DIR, "LANG": "C.UTF-8"}
    if xauth:
        env["XAUTHORITY"] = xauth
    if display is not None:
        env["DISPLAY"] = f":{display}"
    return env


def xauth_entry(cookie_hex):
    """One wildcard entry (any address, any display) of an X authority file in its binary format, so the
    server accepts the cookie on whichever display it picks."""
    data = bytes.fromhex(cookie_hex)
    out = struct.pack(">H", XAUTH_FAMILY_WILD)
    out += struct.pack(">H", 0) + struct.pack(">H", 0)          # address, display number: empty = any
    out += struct.pack(">H", len(XAUTH_PROTOCOL)) + XAUTH_PROTOCOL
    out += struct.pack(">H", len(data)) + data
    return out


def parse_displayfd(data):
    """What Xvfb writes to the -displayfd pipe: the number and a newline."""
    m = re.fullmatch(rb"([0-9]{1,5})\n?", data or b"")
    if not m:
        raise ValueError("unexpected displayfd output")
    return int(m.group(1))


# ---- the display ownership proof (design 4.5 step 2)

def parse_proc_net_unix(text):
    """/proc/net/unix -> [(inode, flags, path)] for the lines that have a path. Fields: Num RefCount
    Protocol Flags Type St Inode Path."""
    out = []
    for line in (text or "").splitlines()[1:]:
        f = line.split(None, 7)
        if len(f) < 8:
            continue
        try:
            flags = int(f[3], 16)
            inode = int(f[6])
        except ValueError:
            continue
        out.append((inode, flags, f[7].strip()))
    return out


def socket_inodes(links):
    """Inode numbers from readlink() results of /proc/<pid>/fd entries ('socket:[1234]')."""
    out = set()
    for link in links:
        m = re.fullmatch(r"socket:\[([0-9]+)\]", link or "")
        if m:
            out.add(int(m.group(1)))
    return out


def display_decision(entries, display, owned_inodes):
    """'owned' when the abstract name of X<display> has a listening socket and every one of them belongs to
    our Xvfb; 'squatted' when any listener of that name is held by someone else; 'missing' when there is
    none. The name is matched exactly (X1 is not X10)."""
    name = f"{X_ABSTRACT_PREFIX}{display}"
    listeners = [inode for inode, flags, path in entries if path == name and flags & UNIX_LISTEN_FLAG]
    if not listeners:
        return "missing"
    return "owned" if all(i in owned_inodes for i in listeners) else "squatted"


# ---- modes for xrandr

def modeline(w, h):
    """A reduced-blanking style modeline for a virtual screen: (name, clock MHz string, timings, flags). Xvfb
    does not drive a monitor, the numbers only have to be consistent."""
    hs, he, ht = w + 48, w + 80, w + 160
    vs, ve, vt = h + 3, h + 9, h + 28
    clock = round(ht * vt * 60 / 1e6 * 4) / 4
    return f"rb{w}x{h}", f"{clock:.2f}", [w, hs, he, ht, h, vs, ve, vt], ["+hsync", "-vsync"]


def parse_xrandr_query(text):
    """`xrandr -q` -> (output name, current mode name, [mode names]) for the first connected output, or
    (None, None, [])."""
    out_name, current, modes = None, None, []
    inside = False
    for line in (text or "").splitlines():
        if not line.startswith((" ", "\t")):
            m = re.match(r"(\S+) connected", line)
            if m and out_name is None:
                out_name, inside = m.group(1), True
            else:
                inside = False
            continue
        if inside:
            f = line.split()
            if f:
                modes.append(f[0])
                if any("*" in x for x in f[1:]):
                    current = f[0]
    return out_name, current, modes


def mode_args(w, h):
    """(name, dot clock in Hz, [hdisp, hsyncstart, hsyncend, htotal, vdisp, vsyncstart, vsyncend, vtotal], RandR
    flags) of the mode for WxH, the numbers of modeline() in the form the X request takes."""
    name, clock, t, _flags = modeline(w, h)
    return name, int(round(float(clock) * 1e6)), list(t), RR_HSYNC_POSITIVE | RR_VSYNC_NEGATIVE


def resize_commands(binary, output, current, created, w, h):
    """The xrandr command lists (argument lists) that switch to WxH and then remove the modes this program
    made before. The mode itself is made and added to the output by ModeHolder (a mode lives only as long as the
    X connection that made it, so xrandr --newmode in a process of its own cannot be used). A mode in use cannot
    be removed, so the switch comes first. Returns (name, main, cleanup)."""
    name = modeline(w, h)[0]
    main = [[binary, "--output", output, "--mode", name]]
    cleanup = []
    for old in created:
        if old != name:
            cleanup.append([binary, "--delmode", output, old])
            cleanup.append([binary, "--rmmode", old])
    return name, main, cleanup


RR_HSYNC_POSITIVE = 0x1
RR_VSYNC_NEGATIVE = 0x8


# ---- the keyboard map (1.26.1)
#
# Typed text, from the page's own paths and from a member's keyboard through noVNC, arrives as key events whose keysym is the
# character's (Latin-1 as it is, above it noVNC's keysymdef lookup: the legacy keysym where X11 has one, else 0x01000000 + code point). A keysym that is not in the X server's keyboard map is added by x11vnc on a key without
# symbols, and x11vnc takes those back only when it exits: this host's Xvfb has 18 such keys, so the 19th different
# character a session ever typed (Cyrillic needs 66) was dropped, silently, for the rest of the session [rig
# measurement, 1.26.1]. The map is therefore prepared before x11vnc and Chromium start: letters with both cases and the
# usual signs go onto keys, two keysyms on one key (lower case, then Shift), and keys that carry only media and
# launcher symbols (XF86...; the unit has no audio and no desktop) are used for it as well. Browser navigation keys are kept.
KEYMAP_RESERVE = 15            # keys that stay free after the table; SCRATCH_COUNT (8) of them become the supervisor's typing keys, 7 stay empty for x11vnc's own additions (1.26.3: 15, was 16: the em dash did not fit)
XF86_FIRST = 0x1008FF00
XF86_LAST = 0x1008FFFF
KEYMAP_KEEP = frozenset({0x1008FF18, 0x1008FF1B, 0x1008FF26, 0x1008FF27, 0x1008FF28, 0x1008FF29, 0x1008FF30, 0x1008FF38, 0x1008FF73})
#                        HomePage, Search, Back, Forward, Stop, Refresh, Favorites, OpenURL, Reload


# The keysym noVNC sends for a code point above Latin-1, for the code points of keymap_codepoint_units(): the legacy keysym where
# X11 has one (Cyrillic, Polish, euro, typographic punctuation) and 0x01000000 + code point otherwise. The supervisor cannot import
# JavaScript, so these are data, generated by tools/keymap_table.py from static/vendor/novnc/core/input/keysymdef.js; a test reads
# that file and fails if a value here differs, so an updated noVNC cannot drift away from this table unseen.
KEYMAP_KEYSYMS = {
    0x0104: 0x01A1,
    0x0105: 0x01B1,
    0x0106: 0x01C6,
    0x0107: 0x01E6,
    0x0118: 0x01CA,
    0x0119: 0x01EA,
    0x0141: 0x01A3,
    0x0142: 0x01B3,
    0x0143: 0x01D1,
    0x0144: 0x01F1,
    0x015A: 0x01A6,
    0x015B: 0x01B6,
    0x0178: 0x13BE,
    0x0179: 0x01AC,
    0x017A: 0x01BC,
    0x017B: 0x01AF,
    0x017C: 0x01BF,
    0x0401: 0x06B3,
    0x0404: 0x06B4,
    0x0406: 0x06B6,
    0x0407: 0x06B7,
    0x040E: 0x06BE,
    0x0410: 0x06E1,
    0x0411: 0x06E2,
    0x0412: 0x06F7,
    0x0413: 0x06E7,
    0x0414: 0x06E4,
    0x0415: 0x06E5,
    0x0416: 0x06F6,
    0x0417: 0x06FA,
    0x0418: 0x06E9,
    0x0419: 0x06EA,
    0x041A: 0x06EB,
    0x041B: 0x06EC,
    0x041C: 0x06ED,
    0x041D: 0x06EE,
    0x041E: 0x06EF,
    0x041F: 0x06F0,
    0x0420: 0x06F2,
    0x0421: 0x06F3,
    0x0422: 0x06F4,
    0x0423: 0x06F5,
    0x0424: 0x06E6,
    0x0425: 0x06E8,
    0x0426: 0x06E3,
    0x0427: 0x06FE,
    0x0428: 0x06FB,
    0x0429: 0x06FD,
    0x042A: 0x06FF,
    0x042B: 0x06F9,
    0x042C: 0x06F8,
    0x042D: 0x06FC,
    0x042E: 0x06E0,
    0x042F: 0x06F1,
    0x0430: 0x06C1,
    0x0431: 0x06C2,
    0x0432: 0x06D7,
    0x0433: 0x06C7,
    0x0434: 0x06C4,
    0x0435: 0x06C5,
    0x0436: 0x06D6,
    0x0437: 0x06DA,
    0x0438: 0x06C9,
    0x0439: 0x06CA,
    0x043A: 0x06CB,
    0x043B: 0x06CC,
    0x043C: 0x06CD,
    0x043D: 0x06CE,
    0x043E: 0x06CF,
    0x043F: 0x06D0,
    0x0440: 0x06D2,
    0x0441: 0x06D3,
    0x0442: 0x06D4,
    0x0443: 0x06D5,
    0x0444: 0x06C6,
    0x0445: 0x06C8,
    0x0446: 0x06C3,
    0x0447: 0x06DE,
    0x0448: 0x06DB,
    0x0449: 0x06DD,
    0x044A: 0x06DF,
    0x044B: 0x06D9,
    0x044C: 0x06D8,
    0x044D: 0x06DC,
    0x044E: 0x06C0,
    0x044F: 0x06D1,
    0x0451: 0x06A3,
    0x0454: 0x06A4,
    0x0456: 0x06A6,
    0x0457: 0x06A7,
    0x045E: 0x06AE,
    0x0490: 0x06BD,
    0x0491: 0x06AD,
    0x2013: 0x0AAA,
    0x2014: 0x0AA9,
    0x2018: 0x0AD0,
    0x2019: 0x0AD1,
    0x201C: 0x0AD2,
    0x201D: 0x0AD3,
    0x201E: 0x0AFE,
    0x2026: 0x0AAE,
    0x20AC: 0x20AC,
}


def keymap_keysym(cp):
    """The keysym that noVNC (core/input/keysymdef.js lookup) and static/js/rbrowser.js keysymFor both send for a code point."""
    return cp if cp <= 0xFF else KEYMAP_KEYSYMS[cp]


def keymap_codepoint_units():
    """The characters worth a key of their own, most useful first, as code points: a tuple (lower, upper) for a letter with both
    cases, a tuple (sign,) for anything else: Latin-1, the euro sign and typographic punctuation, Cyrillic, Polish."""
    units, seen = [], set()
    seen_pairs = set()

    def add_letters(cps):
        for cp in cps:
            ch = chr(cp)
            lo, up = ch.lower(), ch.upper()
            if len(lo) == len(up) == 1 and lo != up and up.lower() == lo:
                for c in (lo, up):
                    seen.add(ord(c))
                if ord(lo) not in seen_pairs:
                    seen_pairs.add(ord(lo))
                    units.append((ord(lo), ord(up)))
            elif cp not in seen:
                seen.add(cp)
                units.append((cp,))

    add_letters([c for c in range(0xE0, 0x100) if c != 0xF7])             # Latin-1 letters with their capitals
    add_letters([0xDF, 0xA1, 0xA3, 0xA7, 0xA9, 0xAB, 0xB0, 0xB1, 0xB5, 0xBB, 0xBF, 0xD7, 0xF7])
    add_letters([0x20AC, 0x201C, 0x201D, 0x2018, 0x2019, 0x201E, 0x2026, 0x2013, 0x2014])   # euro, quotes, ellipsis, dashes
    add_letters(list(range(0x430, 0x450)) + [0x451, 0x456, 0x457, 0x454, 0x491, 0x45E])    # Cyrillic (Russian, Ukrainian, Belarusian)
    add_letters([0x105, 0x107, 0x119, 0x142, 0x144, 0x15B, 0x17A, 0x17C])                  # Polish
    return units


def keymap_units():
    """keymap_codepoint_units() as keysyms."""
    return [tuple(keymap_keysym(cp) for cp in u) for u in keymap_codepoint_units()]


def plan_keymap(rows, min_keycode, reserve=KEYMAP_RESERVE, units=None):
    """The keyboard changes to make. `rows` is the server's map, one tuple of keysyms per key from `min_keycode` on (0 =
    NoSymbol). Returns {keycode: row} for the keys to write. Keys that carry nothing but media and launcher symbols come first, then free keys;
    `reserve` free keys are left over (a few unused media keys are emptied when there are fewer); units whose keysym is in the map already are skipped. The first key
    (min_keycode) is never used. Pure: no X."""
    units = keymap_units() if units is None else units
    if not rows:
        return {}
    width = len(rows[0])
    present = {k for row in rows for k in row[:2] if k}      # on the first two levels of a key: a character on a higher level needs a key of its own to be typed without a map change
    free, spare = [], []
    for i, row in enumerate(rows):
        kc = min_keycode + i
        if kc == min_keycode:
            continue
        syms = [k for k in row if k]
        if not syms:
            free.append(kc)
        elif all(XF86_FIRST <= k <= XF86_LAST and k not in KEYMAP_KEEP for k in syms):
            spare.append(kc)
    keys = spare + free           # the keys that stay unused are free ones: x11vnc can only add keysyms on those
    usable = max(0, len(keys) - max(0, reserve))
    want = []
    singles = []
    for u in units:
        if any(k in present for k in u):
            continue
        if len(u) == 2:
            want.append(u)
        else:
            singles.append(u[0])
            if len(singles) == 2:
                want.append((singles[0], singles[1]))
                singles = []
    if singles:
        want.append((singles[0], singles[0]))
    out = {}
    for kc, (lo, up) in zip(keys[:usable], want):
        out[kc] = tuple((lo, up)[j % 2] for j in range(width))
    # the keys x11vnc can use must be free ones: when too few are, empty some of the media keys that are not used
    unused_spare = [kc for kc in spare if kc not in out]
    for kc in unused_spare[:max(0, reserve - len(free))]:
        out[kc] = (0,) * width
    return out


class _XMode(ctypes.Structure):
    """XRRModeInfo of <X11/extensions/Xrandr.h>."""
    _fields_ = [("id", ctypes.c_ulong), ("width", ctypes.c_uint), ("height", ctypes.c_uint), ("dotClock", ctypes.c_ulong),
                ("hSyncStart", ctypes.c_uint), ("hSyncEnd", ctypes.c_uint), ("hTotal", ctypes.c_uint), ("hSkew", ctypes.c_uint),
                ("vSyncStart", ctypes.c_uint), ("vSyncEnd", ctypes.c_uint), ("vTotal", ctypes.c_uint),
                ("name", ctypes.c_char_p), ("nameLength", ctypes.c_uint), ("modeFlags", ctypes.c_ulong)]


class _XResources(ctypes.Structure):
    """XRRScreenResources."""
    _fields_ = [("timestamp", ctypes.c_ulong), ("configTimestamp", ctypes.c_ulong), ("ncrtc", ctypes.c_int),
                ("crtcs", ctypes.POINTER(ctypes.c_ulong)), ("noutput", ctypes.c_int), ("outputs", ctypes.POINTER(ctypes.c_ulong)),
                ("nmode", ctypes.c_int), ("modes", ctypes.POINTER(_XMode))]


class _XOutputInfo(ctypes.Structure):
    """The first fields of XRROutputInfo; only the name is read."""
    _fields_ = [("timestamp", ctypes.c_ulong), ("crtc", ctypes.c_ulong), ("name", ctypes.c_char_p), ("nameLen", ctypes.c_int)]


class _XErrorEvent(ctypes.Structure):
    """XErrorEvent of <X11/Xlib.h>."""
    _fields_ = [("type", ctypes.c_int), ("display", ctypes.c_void_p), ("resourceid", ctypes.c_ulong),
                ("serial", ctypes.c_ulong), ("error_code", ctypes.c_ubyte), ("request_code", ctypes.c_ubyte),
                ("minor_code", ctypes.c_ubyte)]


class _XModMap(ctypes.Structure):
    """XModifierKeymap of <X11/Xlib.h>."""
    _fields_ = [("max", ctypes.c_int), ("map", ctypes.POINTER(ctypes.c_ubyte))]


BAD_ACCESS = 10
_KEEP = []          # the C callbacks must stay referenced for the life of the process (a collected one is a crash)


class ModeHolder:
    """The one X connection that makes the RandR modes and keeps them alive.

    On this host's Xvfb (xserver 21.1.7) a mode is destroyed when the client that made it disconnects, and the
    screen falls back to 1920x1200 with it (live round 1: `xrandr --newmode` and `xrandr --addmode` in two
    processes cannot work, a mode is "not found" by the second). So the supervisor keeps this connection open for
    the whole session. It only makes a mode and adds it to the output;
    switching to it and removing old ones stay xrandr commands (those work from any client). Standard library
    only: ctypes with libX11 and libXrandr, which the xrandr program itself needs.

    The window manager (WindowManager) runs on this same connection. Xlib's error handler and its I/O error handler are
    process-wide, so there is one of each, here: an X error is recorded with the serial of the request that caused it
    (`errors_since(serial)` tells which errors belong to which caller), and a lost connection ends the supervisor in
    an orderly way through `on_lost`."""

    def __init__(self, display, xauth, output, cdll=ctypes.CDLL, on_lost=None, sleep=time.sleep):
        self.errors = 0
        self.recent = collections.deque(maxlen=64)       # (serial, error code) of the last X errors
        self.on_lost = on_lost
        self.dpy = None
        try:
            self.x11 = cdll("libX11.so.6")
            self.xr = cdll("libXrandr.so.2")
        except OSError:
            raise SupervisorError("libX11 or libXrandr is missing") from None
        x11, xr = self.x11, self.xr
        self.scratch, self.typer, self.width = [], None, 0
        try:
            self.xtst = cdll("libXtst.so.6")           # typing text (`type`); without it only that request is unavailable
            self.xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
        except (OSError, AttributeError):
            self.xtst = None
        vp, ul = ctypes.c_void_p, ctypes.c_ulong
        x11.XOpenDisplay.restype, x11.XOpenDisplay.argtypes = vp, [ctypes.c_char_p]
        x11.XDefaultRootWindow.restype, x11.XDefaultRootWindow.argtypes = ul, [vp]
        x11.XCloseDisplay.argtypes = [vp]
        x11.XSync.argtypes = [vp, ctypes.c_int]
        x11.XQueryKeymap.argtypes = [vp, ctypes.POINTER(ctypes.c_char * 32)]
        x11.XGrabServer.argtypes = [vp]
        x11.XUngrabServer.argtypes = [vp]
        x11.XFlush.argtypes = [vp]
        x11.XQueryPointer.argtypes = [vp, ul, ctypes.POINTER(ul), ctypes.POINTER(ul), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                                      ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_uint)]
        x11.XSetErrorHandler.argtypes = [vp]
        x11.XSetIOErrorHandler.argtypes = [vp]
        x11.XNextRequest.restype, x11.XNextRequest.argtypes = ul, [vp]
        xr.XRRGetScreenResources.restype, xr.XRRGetScreenResources.argtypes = ctypes.POINTER(_XResources), [vp, ul]
        xr.XRRFreeScreenResources.argtypes = [ctypes.POINTER(_XResources)]
        xr.XRRGetOutputInfo.restype = ctypes.POINTER(_XOutputInfo)
        xr.XRRGetOutputInfo.argtypes = [vp, ctypes.POINTER(_XResources), ul]
        xr.XRRFreeOutputInfo.argtypes = [ctypes.POINTER(_XOutputInfo)]
        xr.XRRCreateMode.restype, xr.XRRCreateMode.argtypes = ul, [vp, ul, ctypes.POINTER(_XMode)]
        xr.XRRAddOutputMode.argtypes = [vp, ul, ul]
        # An X error would end the whole process through Xlib's default handler: count it instead.
        self._handler = ctypes.CFUNCTYPE(ctypes.c_int, vp, ctypes.POINTER(_XErrorEvent))(self._on_error)
        self._io_handler = ctypes.CFUNCTYPE(ctypes.c_int, vp)(self._on_io_error)
        _KEEP.extend([self._handler, self._io_handler])
        x11.XSetErrorHandler(ctypes.cast(self._handler, vp))
        x11.XSetIOErrorHandler(ctypes.cast(self._io_handler, vp))
        os.environ["XAUTHORITY"] = xauth          # libX11 reads the authority file from the environment
        # Opening can fail once in a while right after Xvfb reported its display (seen live: one start in about twenty
        # ended here with nothing else wrong): a few more tries, then the start fails.
        for attempt in range(OPEN_TRIES):
            self.dpy = x11.XOpenDisplay(f":{display}".encode())
            if self.dpy:
                if attempt:
                    log(f"the X connection opened at try {attempt + 1}")
                break
            sleep(OPEN_PAUSE_S)
        if not self.dpy:
            raise SupervisorError("the X connection for modes could not be opened")
        self.root = x11.XDefaultRootWindow(self.dpy)
        self.output = self._find_output(output)
        if not self.output:
            self.close()
            raise SupervisorError("the output was not found")

    def _on_error(self, _dpy, event):
        self.errors += 1
        try:
            self.recent.append((int(event.contents.serial), int(event.contents.error_code)))
        except Exception:
            self.recent.append((0, 0))
        return 0

    def _on_io_error(self, _dpy):
        """The X connection is gone (Xvfb died). Xlib calls exit() when this returns, which would leave the other
        children running: end them, then leave with the status of "a child ended" (4)."""
        try:
            if self.on_lost:
                self.on_lost()
        finally:
            os._exit(EXIT_OTHER)

    def errors_since(self, serial, code=None):
        """How many recorded X errors belong to requests with a serial of `serial` or later (and have error code
        `code` when given). Call XSync first so that every error of those requests has arrived."""
        return sum(1 for s, c in self.recent if s >= serial and (code is None or c == code))

    def _find_output(self, name):
        res = self.xr.XRRGetScreenResources(self.dpy, self.root)
        if not res:
            return 0
        found = 0
        try:
            for i in range(res.contents.noutput):
                oid = res.contents.outputs[i]
                info = self.xr.XRRGetOutputInfo(self.dpy, res, oid)
                if info:
                    try:
                        if info.contents.name == name.encode():
                            found = oid
                    finally:
                        self.xr.XRRFreeOutputInfo(info)
                if found:
                    break
        finally:
            self.xr.XRRFreeScreenResources(res)
        return found

    def create(self, w, h):
        """Make the mode for WxH and add it to the output. True when the server accepted both."""
        name, clock_hz, t, flags = mode_args(w, h)
        m = _XMode()
        m.width, m.height, m.dotClock = w, h, clock_hz
        m.hSyncStart, m.hSyncEnd, m.hTotal = t[1], t[2], t[3]
        m.vSyncStart, m.vSyncEnd, m.vTotal = t[5], t[6], t[7]
        m.name, m.nameLength, m.modeFlags = name.encode(), len(name), flags
        self.x11.XSync(self.dpy, 0)                # errors of earlier requests (the window manager's) have arrived by now
        first = self.x11.XNextRequest(self.dpy)
        mode_id = self.xr.XRRCreateMode(self.dpy, self.root, ctypes.byref(m))
        self.x11.XSync(self.dpy, 0)
        if not mode_id or self.errors_since(first):
            return False
        self.xr.XRRAddOutputMode(self.dpy, self.output, mode_id)
        self.x11.XSync(self.dpy, 0)
        return not self.errors_since(first)

    def prefill_keymap(self):
        """Prepare the keyboard map (see plan_keymap). Returns the number of keys written; 0 when there was nothing to do or the
        server refused (the session then works as before, with x11vnc adding keysyms on the fly)."""
        x11, dpy = self.x11, self.dpy
        vp, ci = ctypes.c_void_p, ctypes.c_int
        x11.XDisplayKeycodes.argtypes = [vp, ctypes.POINTER(ci), ctypes.POINTER(ci)]
        x11.XGetKeyboardMapping.restype = ctypes.POINTER(ctypes.c_ulong)
        x11.XGetKeyboardMapping.argtypes = [vp, ctypes.c_ubyte, ci, ctypes.POINTER(ci)]
        x11.XChangeKeyboardMapping.argtypes = [vp, ci, ci, ctypes.POINTER(ctypes.c_ulong), ci]
        x11.XFree.argtypes = [vp]
        lo, hi, width = ci(), ci(), ci()
        x11.XDisplayKeycodes(dpy, ctypes.byref(lo), ctypes.byref(hi))
        count = hi.value - lo.value + 1
        if count <= 0:
            return 0
        table = x11.XGetKeyboardMapping(dpy, lo.value, count, ctypes.byref(width))
        if not table or width.value <= 0:
            return 0
        try:
            w = width.value
            rows = [tuple(int(table[i * w + j]) for j in range(w)) for i in range(count)]
        finally:
            x11.XFree(table)
        if self.xtst is not None and not self._xtest_present():
            self.xtst = None                       # no XTEST extension: nothing can be typed from here, the portal sends key events instead
        plan = plan_keymap(rows, lo.value)
        scratch = plan_scratch(rows, lo.value, plan) if self.xtst is not None else []
        if not plan and not scratch:
            return 0
        x11.XSync(dpy, 0)
        first = x11.XNextRequest(dpy)
        for kc, row in sorted(plan.items()):
            arr = (ctypes.c_ulong * w)(*row)
            x11.XChangeKeyboardMapping(dpy, kc, w, arr, 1)
        for kc in scratch:                       # never empty from here on: x11vnc adds keysyms only to empty keys
            x11.XChangeKeyboardMapping(dpy, kc, w, (ctypes.c_ulong * w)(*([SCRATCH_SYM] * w)), 1)
        x11.XSync(dpy, 0)
        if self.errors_since(first):
            log("the keyboard map was not prepared")
            return 0
        if scratch:
            self.scratch, self.width = scratch, w
            final = apply_plan(rows, lo.value, plan)
            shift, held, shifts, lock = modifier_keycodes(self._modifier_map(), final, lo.value)
            self.typer = ScratchTyper(x11, self.xtst, dpy, scratch, w, index=build_key_index(final, lo.value, exclude=set(scratch)), shift=shift, held=held,
                                      shifts=shifts, lock=lock, root=getattr(self, "root", 0))
        return len(plan)

    def _xtest_present(self):
        """True when the X server has the XTEST extension (XTestQueryExtension)."""
        try:
            ci = ctypes.c_int
            self.xtst.XTestQueryExtension.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ci)] * 4
            a, b, c, d = ci(), ci(), ci(), ci()
            return bool(self.xtst.XTestQueryExtension(self.dpy, ctypes.byref(a), ctypes.byref(b), ctypes.byref(c), ctypes.byref(d)))
        except Exception:
            return False

    def _modifier_map(self):
        """The 8 lists of keycodes of the server's modifier map (XGetModifierMapping), or [] when it cannot be read."""
        try:
            x11 = self.x11
            x11.XGetModifierMapping.restype = ctypes.POINTER(_XModMap)
            x11.XGetModifierMapping.argtypes = [ctypes.c_void_p]
            x11.XFreeModifiermap.argtypes = [ctypes.POINTER(_XModMap)]
            m = x11.XGetModifierMapping(self.dpy)
            if not m:
                return []
            try:
                per = m.contents.max
                return parse_modifier_map(per, [m.contents.map[i] for i in range(8 * per)])
            finally:
                x11.XFreeModifiermap(m)
        except Exception:
            return []

    def _own_error(self, first, end):
        """True when an X error was recorded for a request with a serial in [first, end)."""
        return any(first <= serial < end for serial, _code in list(self.recent))

    def type_text(self, text, budget_s=TYPE_BUDGET_S, pump=lambda: None, stopping=lambda: False):
        """Types `text` (see ScratchTyper). Returns {"ok", "typed", "skipped", "complete", "map_changes"[, "why"][, "warn"]}: why is "unavailable"
        when the keys or XTEST are not there (nothing was typed), else the reason the run stopped early (budget, stopping, failed, modifier,
        capslock); warn ("modifier", "capslock") says that a held key or Caps Lock was in the way of a run that went through, so the text is to be
        checked; map_changes is the number of keyboard map changes the request made. Errors of the window manager on this connection do not stop a
        run. Never raises, never holds the text."""
        res = {"ok": False, "typed": 0, "skipped": 0, "complete": False, "map_changes": 0}
        typer = self.typer
        if typer is None or not self.dpy:
            return dict(res, why="unavailable")
        typer.begin()                                        # also when something raises before the first press: the counts are this request's
        try:
            keys, skipped = type_keysyms(text)
            res["skipped"] = skipped
            self.x11.XSync(self.dpy, 0)
            typed, why = typer.type(keys, budget_s, pump, stopping, error_in=self._own_error)
            res["complete"] = res["ok"] = not why
            if why:
                res["why"] = why
        except Exception:
            res["why"] = "failed"
            log("typing failed")
        finally:
            try:
                typer.release()
            except Exception:
                log("typing keys not restored")
            try:
                typer.finish()
            except Exception:
                log("caps lock not restored")
            res["typed"] = typer.typed                       # what was actually pressed, also after an exception
            res["map_changes"] = typer.map_changes
            if typer.warn and "why" not in res:
                res["warn"] = typer.warn
        return res

    def close(self):
        if self.dpy:
            try:
                self.x11.XCloseDisplay(self.dpy)
            except Exception:
                pass
            self.dpy = None


# ---- the window manager (decision D2)
#
# A page can ask Chromium for a popup of a size and place of its own choosing (window.open with features, moveTo,
# resizeTo). With nothing to answer the X server's configure requests, such a window would sit wherever the page said,
# over the address bar, and could imitate it. This minimal window manager takes the requests: every top-level window
# that is not override-redirect is put at 0,0 at the size of the screen, mapped, raised and given the input focus, so a
# popup becomes a full-screen window with Chromium's own window UI. Override-redirect windows (menus, tooltips, select
# lists) are not managed and cannot be: X does not give them to a window manager.

WM_MAX_WINDOWS = 64
WM_PUMP_BUDGET_S = 0.2          # one pump serves events for at most this long, then the loop looks at the control socket and the children
EV_DESTROY_NOTIFY = 17
EV_UNMAP_NOTIFY = 18
EV_MAP_REQUEST = 20
EV_REPARENT_NOTIFY = 21
EV_CONFIGURE_NOTIFY = 22
EV_CONFIGURE_REQUEST = 23
MASK_STRUCTURE_NOTIFY = 1 << 17
MASK_SUBSTRUCTURE_NOTIFY = 1 << 19
MASK_SUBSTRUCTURE_REDIRECT = 1 << 20
REVERT_TO_POINTER_ROOT = 1


class WmState:
    """The decisions of the window manager, with no X in them: which windows are managed and in which order, and the
    list of actions each event calls for. An action is (name, window) with name one of fit (move and resize to the
    screen, border 0), notify (tell the client its geometry, as ICCCM wants for a request that changed nothing), map,
    raise, focus."""

    def __init__(self, w, h):
        self.w, self.h = int(w), int(h)
        self.stack = []                      # managed windows, bottom first; the last one is the top window

    def geometry(self):
        return 0, 0, self.w, self.h

    def _top_actions(self):
        if not self.stack:
            return []
        top = self.stack[-1]
        return [("fit", top), ("raise", top), ("focus", top)]

    def map_request(self, win, show=True):
        """A client wants a window shown: manage it, make it the top window. With show=False (wm_may_show said no) the window is NOT
        mapped, not fitted, not raised and not focused: it stays invisible and is not managed, and nothing else changes."""
        if not show:
            if win in self.stack:
                self.stack.remove(win)
            return []
        if win in self.stack:
            self.stack.remove(win)
        self.stack.append(win)
        del self.stack[:-WM_MAX_WINDOWS]
        return [("fit", win), ("notify", win), ("map", win), ("raise", win), ("focus", win)]

    def configure_request(self, win):
        """Whatever geometry, border or stacking a client asks for, it gets the screen. Stacking requests are
        ignored: only a map and the end of the top window change the order."""
        return [("fit", win), ("notify", win)]

    def gone(self, win):
        """A managed window was unmapped, destroyed or reparented away: when it was the top window, the next one is
        raised and focused. Windows that are not managed give nothing."""
        if win not in self.stack:
            return []
        was_top = self.stack[-1] == win
        self.stack.remove(win)
        return self._top_actions() if was_top else []

    def resize(self, w, h):
        """The screen has a new size: every managed window follows."""
        w, h = int(w), int(h)
        if (w, h) == (self.w, self.h):
            return []
        self.w, self.h = w, h
        out = []
        for win in self.stack:
            out += [("fit", win), ("notify", win)]
        return out


# A top-level window is shown only when it is a Chromium BROWSER window: one that has the window role Chromium gives its browser
# windows ("browser", and "pop-up" for a window.open popup) and is not marked always-on-top. Anything else is a window that holds
# page-chosen pixels and no toolbar of Chromium's own: video Picture-in-Picture (G13b measured it: no role, no class, ABOVE and STICKY
# state, forced to the full screen by this window manager it was a canvas the page painted, with no address bar). It is never mapped.
# Round 2 R3, measured live (live test gate G09b): Chromium's own bubbles (page info from the lock icon, omnibox suggestions, the geolocation and
# clipboard permission prompts) are drawn INSIDE the browser window, also at 560x480: they create no top-level window, so no window is lost by
# this refusal. The one window of Chromium's own that is not a browser window and is a top-level, the GTK file dialog (class Chromium,
# transient for the browser window, type DIALOG, state MODAL, not ABOVE), would pass the "transient, not ABOVE, not NORMAL" rule of R3 and
# must stay refused (G16): the rule cannot separate it, so it is not implemented.
WM_ROLE_ATOM = b"WM_WINDOW_ROLE"
WM_STATE_ATOM = b"_NET_WM_STATE"
WM_ABOVE_ATOM = b"_NET_WM_STATE_ABOVE"
WM_SHOWN_ROLES = frozenset({"browser", "pop-up"})
PROP_FAILED = object()      # WindowManager._property: the read failed (not the same as a property that is absent)


def wm_may_show(role, above):
    """True when a window with this WM_WINDOW_ROLE (None or '' when it has none or it could not be read) and this always-on-top flag
    (True also when the state could not be read: unknown is refused) may be mapped. Pure."""
    return role in WM_SHOWN_ROLES and above is False


def wm_dispatch(state, kind, win, new_parent_is_root=False, show=True):
    """Event kind -> actions. kind is one of map_request, configure_request, destroy, unmap, reparent."""
    if kind == "map_request":
        return state.map_request(win, show)
    if kind == "configure_request":
        return state.configure_request(win)
    if kind in ("destroy", "unmap"):
        return state.gone(win)
    if kind == "reparent":
        return [] if new_parent_is_root else state.gone(win)
    return []


class _XEvent(ctypes.Union):
    """XEvent: a union of 24 longs (192 bytes on a 64-bit host)."""
    _fields_ = [("type", ctypes.c_int), ("pad", ctypes.c_long * 24)]


class _XSubEvent(ctypes.Structure):
    """The common start of MapRequest, ConfigureRequest, ConfigureNotify, UnmapNotify, DestroyNotify and
    ReparentNotify: `parent` is the event window (the root, for what the window manager sees), `window` the window
    the event is about (offset 40, not 32), `extra` is the new parent of a ReparentNotify."""
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("parent", ctypes.c_ulong), ("window", ctypes.c_ulong),
                ("extra", ctypes.c_ulong)]


class _XConfigureEvent(ctypes.Structure):
    """XConfigureEvent, the notification a client gets (here sent by hand)."""
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("event", ctypes.c_ulong), ("window", ctypes.c_ulong),
                ("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("above", ctypes.c_ulong), ("override_redirect", ctypes.c_int)]


class _XConfigureRequest(ctypes.Structure):
    """XConfigureRequestEvent (only its layout is checked by a test)."""
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("parent", ctypes.c_ulong), ("window", ctypes.c_ulong),
                ("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("above", ctypes.c_ulong), ("detail", ctypes.c_int),
                ("value_mask", ctypes.c_ulong)]


class WindowManager:
    """The window manager on the ModeHolder's X connection. Nothing in here ends the supervisor: an X error is only
    counted (and recorded by the holder), an exception is logged by its class name, and the next event is served.
    Starting is the one thing that can fail, and then the session must not start (another window manager is running,
    or the redirect could not be set): a popup that nobody holds in place is the thing this exists to prevent."""

    def __init__(self, holder):
        self.h = holder
        x11 = holder.x11
        vp, ul = ctypes.c_void_p, ctypes.c_ulong
        x11.XSelectInput.argtypes = [vp, ul, ctypes.c_long]
        x11.XPending.restype, x11.XPending.argtypes = ctypes.c_int, [vp]
        x11.XNextEvent.argtypes = [vp, ctypes.POINTER(_XEvent)]
        x11.XMoveResizeWindow.argtypes = [vp, ul, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint]
        x11.XSetWindowBorderWidth.argtypes = [vp, ul, ctypes.c_uint]
        x11.XMapWindow.argtypes = [vp, ul]
        x11.XRaiseWindow.argtypes = [vp, ul]
        x11.XSetInputFocus.argtypes = [vp, ul, ctypes.c_int, ul]
        x11.XSendEvent.restype = ctypes.c_int
        x11.XSendEvent.argtypes = [vp, ul, ctypes.c_int, ctypes.c_long, ctypes.POINTER(_XEvent)]
        x11.XGetGeometry.restype = ctypes.c_int
        x11.XGetGeometry.argtypes = [vp, ul, ctypes.POINTER(ul), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                                     ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                     ctypes.POINTER(ctypes.c_uint)]
        x11.XConnectionNumber.restype, x11.XConnectionNumber.argtypes = ctypes.c_int, [vp]
        x11.XFlush.argtypes = [vp]
        x11.XInternAtom.restype, x11.XInternAtom.argtypes = ul, [vp, ctypes.c_char_p, ctypes.c_int]
        x11.XGetWindowProperty.restype = ctypes.c_int
        x11.XGetWindowProperty.argtypes = [vp, ul, ul, ctypes.c_long, ctypes.c_long, ctypes.c_int, ul, ctypes.POINTER(ul), ctypes.POINTER(ctypes.c_int),
                                           ctypes.POINTER(ul), ctypes.POINTER(ul), ctypes.POINTER(ctypes.c_void_p)]
        x11.XFree.argtypes = [vp]
        size = self._root_size()
        if size is None:
            raise SupervisorError("the screen size could not be read")
        self.state = WmState(*size)
        self.fd = x11.XConnectionNumber(holder.dpy)
        x11.XSync(holder.dpy, 0)
        first = x11.XNextRequest(holder.dpy)
        x11.XSelectInput(holder.dpy, holder.root, MASK_SUBSTRUCTURE_REDIRECT | MASK_SUBSTRUCTURE_NOTIFY | MASK_STRUCTURE_NOTIFY)
        x11.XSync(holder.dpy, 0)
        if holder.errors_since(first, BAD_ACCESS):
            raise SupervisorError("another window manager is running")

    def _atom(self, name):
        return int(self.h.x11.XInternAtom(self.h.dpy, name, 0))

    def _property(self, win, name):
        """A property of `win`: None when it is ABSENT (the call worked and the window has no such property); (format, items as bytes)
        when it is there; PROP_FAILED when the read failed (the call returned an error, e.g. the window is gone, the format or type
        is unreadable, or there is more of it than was read: bytes_after > 0). A failed read is never the same as an absent one."""
        x11, dpy = self.h.x11, self.h.dpy
        atype, fmt = ctypes.c_ulong(), ctypes.c_int()
        nitems, after = ctypes.c_ulong(), ctypes.c_ulong()
        data = ctypes.c_void_p()
        rc = x11.XGetWindowProperty(dpy, win, self._atom(name), 0, 64, 0, 0, ctypes.byref(atype), ctypes.byref(fmt), ctypes.byref(nitems),
                                    ctypes.byref(after), ctypes.byref(data))
        try:
            if rc != 0:
                return PROP_FAILED
            if atype.value == 0 and not data.value:
                return None if after.value == 0 else PROP_FAILED
            width = {8: 1, 16: 2, 32: ctypes.sizeof(ctypes.c_long)}.get(fmt.value, 0)
            if width == 0 or atype.value == 0 or not data.value or after.value > 0:
                return PROP_FAILED
            return fmt.value, ctypes.string_at(data.value, int(nitems.value) * width)
        finally:
            if data.value:
                x11.XFree(data)

    def may_show(self, win):
        """wm_may_show for a real window: its role and its always-on-top state, read now. Never raises. A read that fails (or is
        incomplete) refuses; a property that is absent is not a failure (no _NET_WM_STATE: not marked always-on-top)."""
        try:
            role = self._property(win, WM_ROLE_ATOM)
            state = self._property(win, WM_STATE_ATOM)
            if role is PROP_FAILED or state is PROP_FAILED:
                return False
            role = role[1].decode("latin-1") if role and role[0] == 8 else None
            if state is None:
                above = False                       # no _NET_WM_STATE at all: not marked always-on-top
            elif state[0] != 32:
                above = True                        # unreadable: refused
            else:
                width = ctypes.sizeof(ctypes.c_long)
                atoms = {int.from_bytes(state[1][i:i + width], sys.byteorder) for i in range(0, len(state[1]), width)}
                above = self._atom(WM_ABOVE_ATOM) in atoms
            return wm_may_show(role, above)
        except Exception as e:
            log(f"window manager: window check failed ({e.__class__.__name__})")
            return False

    def _root_size(self):
        x11, h = self.h.x11, self.h
        root_r, x, y = ctypes.c_ulong(), ctypes.c_int(), ctypes.c_int()
        w, ht, bw, depth = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
        ok = x11.XGetGeometry(h.dpy, h.root, ctypes.byref(root_r), ctypes.byref(x), ctypes.byref(y), ctypes.byref(w),
                              ctypes.byref(ht), ctypes.byref(bw), ctypes.byref(depth))
        if not ok or w.value < 1 or ht.value < 1:
            return None
        return int(w.value), int(ht.value)

    def _run(self, actions):
        x11, dpy = self.h.x11, self.h.dpy
        _x, _y, w, ht = self.state.geometry()
        for name, win in actions:
            if name == "fit":
                x11.XMoveResizeWindow(dpy, win, 0, 0, w, ht)
                x11.XSetWindowBorderWidth(dpy, win, 0)
            elif name == "notify":
                ev = _XEvent()
                ce = ctypes.cast(ctypes.byref(ev), ctypes.POINTER(_XConfigureEvent)).contents
                ce.type, ce.event, ce.window = EV_CONFIGURE_NOTIFY, win, win
                ce.x, ce.y, ce.width, ce.height, ce.border_width, ce.above, ce.override_redirect = 0, 0, w, ht, 0, 0, 0
                x11.XSendEvent(dpy, win, 0, MASK_STRUCTURE_NOTIFY, ctypes.byref(ev))
            elif name == "map":
                x11.XMapWindow(dpy, win)
            elif name == "raise":
                x11.XRaiseWindow(dpy, win)
            elif name == "focus":
                x11.XSetInputFocus(dpy, win, REVERT_TO_POINTER_ROOT, 0)
        if actions:
            x11.XSync(dpy, 0)          # errors (a window that vanished meanwhile) arrive here, not in a mode request

    def refresh(self):
        """Read the screen size and move every managed window to it. Called after a resize and every second."""
        try:
            size = self._root_size()
            if size is not None:
                self._run(self.state.resize(*size))
            return True
        except Exception as e:
            log(f"window manager: refresh failed ({e.__class__.__name__})")
            return False

    def _event(self, ev):
        t = ev.type
        sub = ctypes.cast(ctypes.byref(ev), ctypes.POINTER(_XSubEvent)).contents
        root = self.h.root
        if t == EV_CONFIGURE_NOTIFY:
            if sub.window == root:
                self.refresh()
            return
        if t in (EV_MAP_REQUEST, EV_CONFIGURE_REQUEST):
            if sub.parent != root:
                return
            kind = "map_request" if t == EV_MAP_REQUEST else "configure_request"
            self._run(wm_dispatch(self.state, kind, sub.window, show=self.may_show(sub.window) if t == EV_MAP_REQUEST else True))
        elif t == EV_DESTROY_NOTIFY and sub.parent == root:
            self._run(wm_dispatch(self.state, "destroy", sub.window))
        elif t == EV_UNMAP_NOTIFY and sub.parent == root:
            self._run(wm_dispatch(self.state, "unmap", sub.window))
        elif t == EV_REPARENT_NOTIFY and sub.parent == root:
            self._run(wm_dispatch(self.state, "reparent", sub.window, new_parent_is_root=sub.extra == root))

    def pending(self):
        """True when Xlib already holds events that select() on the X connection cannot announce. Never raises (False on error)."""
        try:
            return bool(self.h.x11.XPending(self.h.dpy))
        except Exception:
            return False

    def pump(self, budget_s=WM_PUMP_BUDGET_S, clock=time.monotonic):
        """Serve the events that are waiting, also those Xlib read while another request waited for its answer, until none is
        left or `budget_s` is used up (a time budget, not a count: a page that fires resizeTo/moveTo in a loop builds a backlog
        that a fixed count drained at only a few hundred a second). Returns how many were served. Never raises."""
        x11, dpy = self.h.x11, self.h.dpy
        served = 0
        end = clock() + budget_s
        try:
            while x11.XPending(dpy):
                ev = _XEvent()
                x11.XNextEvent(dpy, ctypes.byref(ev))
                served += 1
                try:
                    self._event(ev)
                except Exception as e:
                    log(f"window manager: event failed ({e.__class__.__name__})")
                if clock() >= end:
                    break
            x11.XFlush(dpy)
        except Exception as e:
            log(f"window manager: pump failed ({e.__class__.__name__})")
        return served


# ---- control socket

def parse_ctl_request(data):
    """One request line -> ('ping',), ('clip',), ('resize', w, h) or ('type', text). Raises CtlError. At most CTL_MAX bytes
    (CTL_TYPE_MAX for `type`), one JSON object, only the four operations that exist."""
    if not isinstance(data, (bytes, bytearray)):
        raise CtlError("type")
    if len(data) > CTL_TYPE_MAX:
        raise CtlError("size")
    line = bytes(data).split(b"\n", 1)[0]
    try:
        req = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CtlError("json") from None
    if not isinstance(req, dict):
        raise CtlError("shape")
    op = req.get("op")
    if op == "type":
        text = req.get("text")
        if not isinstance(text, str) or len(text) > TYPE_MAX_CHARS:
            raise CtlError("text")
        return ("type", text)
    if len(data) > CTL_MAX:
        raise CtlError("size")
    if op == "ping":
        return ("ping",)
    if op == "clip":
        return ("clip",)
    if op == "resize":
        w, h = req.get("w"), req.get("h")
        if not _is_int(w) or not _is_int(h) or not (1 <= w <= 100000) or not (1 <= h <= 100000):
            raise CtlError("geometry")
        return ("resize", w, h)
    raise CtlError("op")


def ctl_reply(ok):
    return (json.dumps({"ok": bool(ok)}) + "\n").encode()


def type_keysyms(text):
    """(keysyms, skipped) for the text of a `type` request, by the filter the page applies (static/js/rbrowser.js keysymsForText): a line
    break (CR, LF or CR LF) is Return, a tab is Tab, printable ASCII and Latin-1 are their own keysym, every other code point that is not
    a surrogate or a control character is 0x01000000 + code point, anything else is skipped and counted."""
    keys, skipped = [], 0
    chars = list(text)
    i = 0
    while i < len(chars):
        cp = ord(chars[i])
        i += 1
        if cp == 13:
            if i < len(chars) and chars[i] == "\n":
                i += 1
            keys.append(KEYSYM_RETURN)
        elif cp == 10:
            keys.append(KEYSYM_RETURN)
        elif cp == 9:
            keys.append(KEYSYM_TAB)
        elif 0x20 <= cp <= 0x7E or 0xA0 <= cp <= 0xFF:
            keys.append(cp)
        elif 0xFF < cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF:
            keys.append(0x01000000 | cp)
        else:
            skipped += 1
    return keys, skipped


def type_reply(res):
    """The answer line of `type`: {"ok", "typed", "skipped", "complete"[, "why"]}. Never the text."""
    out = {"ok": bool(res.get("ok")), "typed": int(res.get("typed", 0)), "skipped": int(res.get("skipped", 0)),
           "complete": bool(res.get("complete")), "map_changes": int(res.get("map_changes", 0))}
    if res.get("why"):
        out["why"] = str(res["why"])[:20]
    if res.get("warn"):
        out["warn"] = str(res["warn"])[:20]
    return (json.dumps(out) + "\n").encode()


def plan_scratch(rows, min_keycode, plan, n=SCRATCH_COUNT):
    """The keys to own for typing: `n` keys that are empty (in `rows`, or emptied by `plan`) and that `plan` does not fill, never the first
    key, the highest ones. Fewer when fewer are free. Pure: no X."""
    free = []
    for i, row in enumerate(rows):
        kc = min_keycode + i
        if kc == min_keycode:
            continue
        written = plan.get(kc)
        if (written is None and not any(row)) or (written is not None and not any(written)):
            free.append(kc)
    return sorted(free)[-n:] if n > 0 else []


def apply_plan(rows, min_keycode, plan):
    """`rows` with the keys of `plan` replaced, as the map reads after prefill_keymap wrote it. Pure."""
    return [tuple(plan[min_keycode + i]) if (min_keycode + i) in plan else tuple(r) for i, r in enumerate(rows)]


def build_key_index(rows, min_keycode, exclude=()):
    """{keysym: (keycode, level)} of the keys that exist on the map: level 0 is the first column, level 1 the second (Shift). A keysym on
    both levels, or on several keys, takes level 0 and then the lowest keycode. The first key, the keys in `exclude` (the typing keys)
    and the placeholder keysym are never in it. Built once after the prefill; the map is never read again for it. Pure."""
    best = {}
    for i, row in enumerate(rows):
        kc = min_keycode + i
        if kc == min_keycode or kc in exclude:
            continue
        for level in (0, 1):
            sym = row[level] if level < len(row) else 0
            if not sym or sym == SCRATCH_SYM:
                continue
            cand = (level, kc)
            if sym not in best or cand < best[sym]:
                best[sym] = cand
    return {sym: (kc, level) for sym, (level, kc) in best.items()}


def keysym_candidates(sym):
    """The keysyms a character may sit on the map as: its own and, above Latin-1, the legacy one the prefilled table uses (the one noVNC sends)."""
    if sym >= 0x01000000:
        legacy = KEYMAP_KEYSYMS.get(sym & 0xFFFFFF)
        return [sym, legacy] if legacy else [sym]
    return [sym]


def parse_modifier_map(per_mod, codes):
    """The 8 lists of keycodes (Shift, Lock, Control, Mod1 to Mod5) of an XModifierKeymap: `per_mod` keycodes each, 0 = unused. Pure."""
    codes = list(codes)
    return [[c for c in codes[m * per_mod:(m + 1) * per_mod] if c] for m in range(8)] if per_mod > 0 else [[] for _ in range(8)]


_MOD_FALLBACK = {"shift": (0xFFE1, 0xFFE2), "held": (0xFFE3, 0xFFE4, 0xFFE7, 0xFFE8, 0xFFE9, 0xFFEA, 0xFFEB, 0xFFEC, 0xFFED, 0xFFEE, 0xFE03, 0xFF7E), "lock": (0xFFE5,)}


def modifier_keycodes(modmap, rows, min_keycode):
    """(shift_keycode or 0, [held keycodes], [every Shift keycode], caps_lock_keycode or 0). Shift from the modifier map (the first key of Shift,
    and all of them for the release before a level-0 character), the held ones from Control, Mod1 (Alt), Mod4 (Super) and Mod5 (AltGr, Mode_switch)
    (their being down turns typed characters into shortcuts); Num Lock (Mod2) is not one (no key the typer uses is a keypad key). The Caps Lock
    key from the Lock list. Without a modifier map the keys are found by their keysyms in `rows`. Pure."""
    mm = modmap if modmap and len(modmap) == 8 and any(modmap) else None
    by_sym = {}
    for i, row in enumerate(rows):
        if row and row[0]:
            by_sym.setdefault(row[0], min_keycode + i)
    if mm:
        shifts = sorted(set(mm[0]))
        held = sorted({c for m in (2, 3, 6, 7) for c in mm[m]})
        lock = mm[1][0] if mm[1] else 0
    else:
        shifts = sorted({by_sym[k] for k in _MOD_FALLBACK["shift"] if k in by_sym})
        held = sorted({by_sym[k] for k in _MOD_FALLBACK["held"] if k in by_sym})
        lock = next((by_sym[k] for k in _MOD_FALLBACK["lock"] if k in by_sym), 0)
    shift = (mm[0][0] if mm and mm[0] else (shifts[0] if shifts else 0))
    return shift, held, shifts, lock


def keys_down(keymap, keycodes):
    """Which of `keycodes` are down in the 32 bytes XQueryKeymap returned (bit keycode % 8 of byte keycode // 8). Pure."""
    return [kc for kc in keycodes if kc // 8 < len(keymap) and keymap[kc // 8] >> (kc % 8) & 1]


class ScratchTyper:
    """Types keysyms through XTEST. A keysym that is on the keyboard map (`index`, from build_key_index) is typed with its own key and
    Shift for the second level: Shift down, key down, key up, Shift up; the map is not touched. Only a keysym that is on no key uses a
    scratch key, which only this object binds: bound, synced, TYPE_MAP_WAIT_S passes, down and up; one a scratch key holds already needs no
    binding; the least recently used key is rebound, and not sooner than TYPE_SETTLE_S after its last press. Idle scratch keys hold
    SCRATCH_SYM and are never empty: x11vnc takes only empty ones.

    What a member does on the picture meanwhile. The first line of defence is the portal's relay, which does not pass the member's key-downs on to
    x11vnc while a `type` request runs (rbrowser_rfb.ClientFilter, Session.typing). This object is the second line, for a key-down that was already past
    the relay when the request began, and for state the member left behind: before every press the key state is read (a held Control, Alt, Super or
    AltGr key found down is counted and reported as `warn` "modifier", and a run in which it is found more than TYPE_MOD_STRIKES times stops with
    why "modifier"); the press is sent as a key-up for every such key and, for a character on the first level, every Shift key, then the key down and
    up, inside XGrabServer. XGrabServer does NOT keep x11vnc out: x11vnc injects its events with XTestGrabControl, which lets them take effect inside
    another client's grab (measured: 5 of 5), so the grab only orders this object's own requests, and a key-down of the member that gets through
    the relay can still land between the key-ups and the press. Caps Lock is read from the pointer state before every character and once after the
    last, switched off with a tap on its key when it is on (reported as `warn` "capslock" when that happens after the first character or is seen after
    the last; at the start of a request it is not a warning, the text is right) and put back at the end; when it cannot be switched off the run stops
    before the first character with why "capslock". The member's Shift is released by a character on the first level and not given back."""

    def __init__(self, x11, xtst, dpy, scratch, width, clock=time.monotonic, sleep=time.sleep, index=None, shift=0, held=(), shifts=(), lock=0, root=0):
        self.x11, self.xtst, self.dpy, self.width = x11, xtst, dpy, width
        self.clock, self.sleep = clock, sleep
        self.order = list(scratch)                      # least recently used first
        self.bound = {kc: SCRATCH_SYM for kc in scratch}
        self.last = {kc: float("-inf") for kc in scratch}
        self.index, self.shift, self.held = dict(index or {}), shift, list(held)
        self.shifts, self.lock, self.root = list(shifts), lock, root
        self.map_changes = 0                            # XChangeKeyboardMapping calls made (a run of characters on the map makes none)
        self.strikes = 0                                # sightings of a held modifier in the current request
        self.warn = ""                                  # "modifier" or "capslock": something was in the way during the current request
        self.caps_fixed = False                         # Caps Lock was on and was switched off by this request
        self.typed = 0                                  # characters whose key-down was sent in the current request (what was actually pressed)
        self.pressed = set()                            # keycodes this object has sent a key-down for and not yet a key-up
        self.ranges = []                                # request serials [first, end) of the typer's own requests since the last error check

    def begin(self):
        """Start of a request: the counters of the last one are gone."""
        self.strikes, self.warn, self.caps_fixed = 0, "", False
        self.typed = 0
        self.pressed = set()
        self.map_changes = 0
        self.ranges = []

    def _mark(self, first):
        try:
            self.ranges.append((int(first), int(self.x11.XNextRequest(self.dpy))))
        except Exception:
            pass

    def _own_error(self, error_in):
        ranges, self.ranges = self.ranges, []
        return any(error_in(a, b) for a, b in ranges)

    def _bind(self, kc, sym):
        arr = (ctypes.c_ulong * self.width)(*([sym] * self.width))
        first = self.x11.XNextRequest(self.dpy)
        self.x11.XChangeKeyboardMapping(self.dpy, kc, self.width, arr, 1)
        self.map_changes += 1
        self.x11.XSync(self.dpy, 0)
        self._mark(first)
        self.bound[kc] = sym

    def _caps_on(self):
        mask = ctypes.c_uint()
        root, child = ctypes.c_ulong(), ctypes.c_ulong()
        a, b, c, d = ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
        self.x11.XQueryPointer(self.dpy, self.root, ctypes.byref(root), ctypes.byref(child), ctypes.byref(a), ctypes.byref(b), ctypes.byref(c), ctypes.byref(d), ctypes.byref(mask))
        return bool(mask.value & LOCK_MASK)

    def _tap_caps(self):
        self.xtst.XTestFakeKeyEvent(self.dpy, self.lock, 1, 0)
        self.xtst.XTestFakeKeyEvent(self.dpy, self.lock, 0, 0)
        self.x11.XSync(self.dpy, 0)

    def _fix_caps(self):
        """False when Caps Lock is on and cannot be switched off. Nothing is done when its key or the pointer state is not known."""
        if not self.lock:
            return True
        if not self._caps_on():
            return True
        self._tap_caps()
        if self._caps_on():
            return False
        self.caps_fixed = True
        return True

    def start(self):
        """Before the first character: Caps Lock off. The reason when it cannot be, else ""."""
        self.begin()
        if not self._fix_caps():
            return "capslock"
        self.warn = ""                                  # on at the start is the member's state, not something in the way of this text
        return ""

    def finish(self):
        """After the last character: Caps Lock back on when this request switched it off."""
        if self.caps_fixed and self.lock:
            try:
                if not self._caps_on():
                    self._tap_caps()
            finally:
                self.caps_fixed = False

    def _guard(self):
        """Before a press, outside the grab: count the Control, Alt, Super and AltGr keys found down (the run stops when that happens more than
        TYPE_MOD_STRIKES times in a request: a key that is held or auto-repeating, not tapped), and switch Caps Lock off when it is on.
        Returns "" or why the run must stop (modifier, capslock). What it finds is reported as `warn`."""
        if self.held:
            buf = (ctypes.c_char * 32)()
            self.x11.XQueryKeymap(self.dpy, buf)
            if keys_down(bytes(buf.raw), self.held):
                self.strikes += 1
                self.warn = "modifier"
                if self.strikes > TYPE_MOD_STRIKES:
                    return "modifier"
        if self.lock and self._caps_on():
            if not self._fix_caps():
                self.warn = "capslock"
                return "capslock"
            self.warn = self.warn or "capslock"
        return ""

    def _send(self, kc, level):
        """One key, with Shift held around it for level 1: after a key-up for EVERY Control, Alt, Super and AltGr key and, for a character on the
        first level, every Shift key (whether the key state shows it down or not: a key-down that is queued is not in the state yet, and the key-ups
        come after it in the queue), the key goes down and up, all inside XGrabServer (which orders this object's requests; it does not keep x11vnc out,
        see the class). Every key this object pressed is released in the `finally`, whatever happens, and `typed` counts a character when its
        key-down was sent. Measured on the rig: key-ups chosen from a state read inside the grab were worse. (ok, why)."""
        why = self._guard()
        if why:
            return False, why
        first = self.x11.XNextRequest(self.dpy)
        x = self.xtst.XTestFakeKeyEvent
        self.x11.XGrabServer(self.dpy)
        try:
            for k in self.held + (self.shifts if not level else []):
                x(self.dpy, k, 0, 0)
            ok = True
            if level:
                self.pressed.add(self.shift)
                ok = bool(x(self.dpy, self.shift, 1, 0))
            self.pressed.add(kc)
            down = bool(x(self.dpy, kc, 1, 0))
            if down:
                self.typed += 1
            ok = down and ok
            ok = bool(x(self.dpy, kc, 0, 0)) and ok
            self.pressed.discard(kc)
            if level:
                ok = bool(x(self.dpy, self.shift, 0, 0)) and ok
                self.pressed.discard(self.shift)
        finally:
            try:
                for k in list(self.pressed):                 # an exception between a key-down and its key-up leaves nothing pressed
                    x(self.dpy, k, 0, 0)
            finally:
                self.pressed.clear()
                self.x11.XUngrabServer(self.dpy)
                self.x11.XFlush(self.dpy)                   # the grab must not outlast the press (a wait for a binding comes next)
        self._mark(first)
        return ok, "" if ok else "failed"

    def type(self, keysyms, budget_s=TYPE_BUDGET_S, pump=lambda: None, stopping=lambda: False, error_in=lambda a, b: False):
        """(typed, why): how many keysyms were typed and why it stopped early ("" = all typed; budget, stopping, failed, modifier, capslock).
        `warn` says what was in the way of a run that went through. `error_in(first, end)` tells whether an X error belongs to a request with a
        serial in [first, end): only errors of this object's own requests stop a run, never those of the window manager on the same connection."""
        why0 = self.start()
        if why0:
            return 0, why0
        deadline = self.clock() + budget_s
        next_pump = self.clock()
        for sym in keysyms:
            now = self.clock()
            if now >= deadline:
                return self.typed, "budget"
            if stopping():
                return self.typed, "stopping"
            if now >= next_pump:
                pump()
                next_pump = self.clock() + TYPE_PUMP_S
            own = next((self.index[c] for c in keysym_candidates(sym) if c in self.index), None)
            if own is not None and own[1] and not self.shift:
                own = None
            if own is not None:
                ok, why = self._send(*own)
                if not ok:
                    return self.typed, why
            else:
                kc = next((k for k in self.order if self.bound[k] == sym), None)
                if kc is None:
                    kc = self.order[0]
                    if self.bound[kc] != SCRATCH_SYM:
                        wait = self.last[kc] + TYPE_SETTLE_S - self.clock()
                        if wait > 0:
                            self.sleep(wait)
                    self._bind(kc, sym)
                    if self._own_error(error_in):
                        return self.typed, "failed"
                    self.sleep(TYPE_MAP_WAIT_S)
                self.order.remove(kc)
                self.order.append(kc)
                ok, why = self._send(kc, 0)                 # after the wait for the binding, and nothing between its check and its press
                self.last[kc] = self.clock()
                if not ok:
                    return self.typed, why
            if self.ranges and len(self.ranges) >= 64:
                self.x11.XSync(self.dpy, 0)
                if self._own_error(error_in):
                    return self.typed, "failed"
        self.x11.XSync(self.dpy, 0)
        if self.lock and self._caps_on():                   # one read after the last press: a toggle before the last character is flagged
            self.warn = self.warn or "capslock"
        if self._own_error(error_in):
            return self.typed, "failed"
        return self.typed, ""

    def release(self):
        """Every scratch key back to SCRATCH_SYM (after the last press has been read), so no character stays where x11vnc could find it."""
        for kc in self.order:
            if self.bound[kc] != SCRATCH_SYM:
                wait = self.last[kc] + TYPE_SETTLE_S - self.clock()
                if wait > 0:
                    self.sleep(wait)
                self._bind(kc, SCRATCH_SYM)


def clip_cut(data, limit=CLIP_MAX):
    """(text, truncated) from the raw bytes of a selection: at most `limit` bytes, cut back to a character boundary
    (never in the middle of a UTF-8 sequence), invalid bytes shown as U+FFFD. `truncated` is True when anything was
    cut off. `data` may hold a few bytes more than `limit` so that the boundary can be told."""
    data = bytes(data)
    truncated = len(data) > limit
    if truncated:
        i = limit
        while i > 0 and data[i] & 0xC0 == 0x80:      # data[i] continues a character that starts before the cut
            i -= 1
        data = data[:i]
    return data.decode("utf-8", "replace"), truncated


def clip_reply(ok, text="", truncated=False):
    """{"ok": bool, "text": str, "truncated": bool} on one line, UTF-8 and not ASCII-escaped (an emoji stays four
    bytes). On a failure the text is empty."""
    if not ok:
        text, truncated = "", False
    return (json.dumps({"ok": bool(ok), "text": text, "truncated": bool(truncated)}, ensure_ascii=False) + "\n").encode("utf-8")


# ---- exit and shutdown decisions

def exit_code(display_ok, first_gone, returncode, terminated):
    """3 when the display proof failed; 0 when Chromium ended by itself with status 0; 4 otherwise (any other
    child, any other status, a stop request)."""
    if not display_ok:
        return EXIT_DISPLAY
    if not terminated and first_gone == "chromium" and returncode == 0:
        return EXIT_OK
    return EXIT_OTHER


def find_binary(name, dirs=BIN_DIRS, exists=None):
    exists = exists or (lambda p: os.path.isfile(p) and os.access(p, os.X_OK))
    for d in dirs:
        p = f"{d}/{name}"
        if exists(p):
            return p
    return None


def read_config(environ, exists=os.path.isdir):
    """The unit's settings from its environment (set by systemd-run -E). Raises SupervisorError."""
    try:
        geometry = parse_geometry(environ.get("RB_GEOMETRY", ""))
    except ValueError:
        raise SupervisorError("bad geometry") from None
    clipboard = environ.get("RB_CLIPBOARD", "")
    if not valid_clipboard(clipboard):
        raise SupervisorError("bad clipboard mode")
    home = environ.get("RB_HOME", "")
    if not valid_home(home):
        raise SupervisorError("bad home page")
    chromium = environ.get("RB_CHROMIUM", "")
    if not chromium.startswith("/") or "\n" in chromium or "\0" in chromium:
        raise SupervisorError("bad browser path")
    rt = environ.get("RUNTIME_DIRECTORY", "")
    if not rt.startswith("/") or ":" in rt or not exists(rt):
        raise SupervisorError("no runtime directory")
    return {"geometry": geometry, "clipboard": clipboard, "home": home, "chromium": chromium,
            "runtime_dir": rt.rstrip("/"), "theme_mode": valid_theme_mode(environ.get("RB_THEME_MODE"))}


# ================================================================ the side-effect half

def log(msg):
    """To the journal (standard error). Fixed words and numbers only: never a URL, a title, a key or a path
    that came from a page."""
    try:
        sys.stderr.write(f"rb-supervisor: {msg}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _devnull_run(argv, env, timeout, stdin_bytes=None):
    """Run a helper to completion with a time limit, output discarded. Returns the return code (124 on a
    timeout)."""
    try:
        p = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    except OSError:
        return 127
    try:
        p.communicate(stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        return 124
    return p.returncode


def _capture_run(argv, env, timeout):
    try:
        p = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, close_fds=True)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout.decode("utf-8", "replace")


def spawn(argv, env, **kw):
    """A child with no stdin and no output (Xvfb, x11vnc and Chromium log things a page chose)."""
    return subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True, **kw)


class Xrandr:
    """Keeps the screen at the requested size and the mode list short: only the mode in use and the initial
    one exist after any number of resizes. `holder` (a ModeHolder) makes the modes; None only in a test."""

    def __init__(self, binary, env, output, current, holder=None):
        self.binary, self.env, self.output, self.current, self.holder = binary, env, output, current, holder
        self.created = []

    def set_size(self, w, h, deadline):
        name, main, cleanup = resize_commands(self.binary, self.output, self.current, self.created, w, h)
        if name == self.current:
            return True
        if self.holder is not None and not self.holder.create(w, h):
            return False
        for i, argv in enumerate(main):
            left = max(0.2, min(XRANDR_WAIT_S, deadline - time.monotonic()))
            if _devnull_run(argv, self.env, left) != 0:
                # take back what was made, ignore failures
                _devnull_run([self.binary, "--delmode", self.output, name], self.env, 1.0)
                _devnull_run([self.binary, "--rmmode", name], self.env, 1.0)
                return False
        for argv in cleanup:
            _devnull_run(argv, self.env, max(0.2, min(XRANDR_WAIT_S, deadline - time.monotonic())))
        self.created = [name]
        self.current = name
        return True


def handle_ctl(conn, state, now=time.monotonic):
    """Serve one control connection: read one line (<= 4 KB, 2 s), answer one line. ping and resize answer
    {"ok": bool}; clip answers {"ok", "text", "truncated"}; type answers {"ok", "typed", "skipped", "complete"[, "why"]}. `state` holds
    "xrandr", "wm", "clip" (a function returning (ok, text, truncated)), "clipboard" (the RB_CLIPBOARD value) and "type" (a function
    taking the text and returning type_text's dict; refused when the clipboard setting is off). Never raises."""
    try:
        conn.settimeout(0.5)
        end = now() + CTL_READ_S
        data = b""
        while b"\n" not in data and len(data) <= CTL_TYPE_MAX and now() < end:
            try:
                chunk = conn.recv(CTL_TYPE_MAX + 1 - len(data))
            except (socket.timeout, BlockingIOError):
                continue
            if not chunk:
                break
            data += chunk
        try:
            req = parse_ctl_request(data)
        except CtlError:
            conn.sendall(ctl_reply(False))
            return
        if req[0] == "ping":
            conn.sendall(ctl_reply(True))
            return
        if req[0] == "clip":
            # Only when the setting lets text out of the browser; the portal checks it as well (403 otherwise).
            ok, text, truncated = state["clip"]() if state.get("clipboard") == "both" else (False, "", False)
            conn.settimeout(CTL_REPLY_S)
            conn.sendall(clip_reply(ok, text, truncated))
            return
        if req[0] == "type":
            if state.get("clipboard") == "off" or not state.get("type"):
                res = {"ok": False, "why": "refused" if state.get("clipboard") == "off" else "unavailable"}
            else:
                res = state["type"](req[1])
            conn.settimeout(CTL_REPLY_S)
            conn.sendall(type_reply(res))
            return
        w, h = clamp_geometry(req[1], req[2])
        deadline = time.monotonic() + RESIZE_BUDGET_S
        ok = state["xrandr"].set_size(w, h, deadline)
        if ok:
            state["wm"].refresh()                 # the windows are at the new size before the answer
        conn.sendall(ctl_reply(ok))
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def watch(children, wait_events, should_stop):
    """The one second loop. `children` is [(name, process)] with poll(); `wait_events()` blocks for at most one
    second and serves the control socket. Returns (name, returncode) of the first child that is gone, or
    (None, None) when a stop was asked for."""
    while True:
        wait_events()
        if should_stop():
            return None, None
        for name, p in children:
            rc = p.poll()
            if rc is not None:
                return name, rc


def stop_children(children, sleep=time.sleep, clock=time.monotonic):
    """SIGTERM Chromium (2 s), then SIGKILL everything left: x11vnc ignored SIGTERM for 50 to 90 s in the
    prototype."""
    for name, p in children:
        if name == "chromium" and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass
    end = clock() + CHROMIUM_TERM_WAIT_S
    while clock() < end and any(n == "chromium" and p.poll() is None for n, p in children):
        sleep(0.05)
    for name, p in children:
        if p.poll() is None:
            try:
                p.kill()
            except OSError:
                pass
    for name, p in children:
        try:
            p.wait(timeout=2)
        except Exception:
            pass


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def prove_display(xvfb_pid, display):
    """Step 2: the abstract name of our display must be bound by our own Xvfb. Raises DisplayMismatch."""
    try:
        links = [os.readlink(f"/proc/{xvfb_pid}/fd/{n}") for n in os.listdir(f"/proc/{xvfb_pid}/fd")]
    except OSError:
        raise DisplayMismatch("cannot read the Xvfb file descriptors") from None
    verdict = display_decision(parse_proc_net_unix(_read_text("/proc/net/unix")), display, socket_inodes(links))
    if verdict != "owned":
        raise DisplayMismatch(f"display proof: {verdict}")


def start_xvfb(binary, xauth, env):
    """Xvfb on a display of its own choosing. Returns (process, display number)."""
    r, w = os.pipe()
    try:
        p = subprocess.Popen(xvfb_argv(binary, w, xauth), env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(w,))
    except OSError:
        os.close(r)
        os.close(w)
        raise SupervisorError("Xvfb did not start") from None
    os.close(w)
    try:
        data = b""
        end = time.monotonic() + DISPLAYFD_WAIT_S
        while b"\n" not in data:
            left = end - time.monotonic()
            if left <= 0 or not select.select([r], [], [], left)[0]:
                break
            chunk = os.read(r, 64)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(r)
    try:
        return p, parse_displayfd(data)
    except ValueError:
        p.kill()
        p.wait()
        raise SupervisorError("Xvfb gave no display number") from None


def read_clipboard(binary, env, limit=CLIP_MAX, wait=CLIP_WAIT_S, popen=subprocess.Popen, clock=time.monotonic):
    """The CLIPBOARD selection as text: (ok, text, truncated). `xsel -o -b` asks the owner (Chromium, after a copy in
    a page) and handles the incremental transfer of a long text. Reads at most limit + 4 bytes and waits at most `wait`
    seconds; a time-out, a failing program or no program is (False, "", False). The text is never logged."""
    try:
        p = popen([binary, "-o", "-b"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                  stderr=subprocess.DEVNULL, close_fds=True)
    except OSError:
        return False, "", False
    data = b""
    done = False
    end = clock() + wait
    try:
        while len(data) < limit + 4:
            left = end - clock()
            if left <= 0:
                break
            if not select.select([p.stdout], [], [], left)[0]:
                break
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                done = True
                break
            data += chunk
        else:
            done = True                     # more than the limit is here: the rest is not needed
    except OSError:
        done = False
    finally:
        try:
            p.kill()
        except OSError:
            pass
        try:
            p.wait(timeout=1)
        except Exception:
            pass
        try:
            p.stdout.close()
        except OSError:
            pass
    if not done:
        return False, "", False
    text, truncated = clip_cut(data, limit)
    return True, text, truncated


def start_chromium(argv, env):
    """Chromium on the display, with no output and no debugging channel."""
    try:
        return spawn(argv, env)
    except OSError:
        raise SupervisorError("Chromium did not start") from None


def make_ctl_socket(path):
    if os.path.lexists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(4)
    s.setblocking(False)
    return s


def run(cfg):
    """Steps 1 to 8. Returns the exit code."""
    stop = {"flag": False}

    def on_signal(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    os.umask(0o077)
    rt = cfg["runtime_dir"]
    xauth = f"{rt}/xauth"
    children = []
    holders = []
    ctl = None
    display_ok = True
    first_gone, rc = None, None
    try:
        # 1. environment and the authority file with a fresh cookie
        for d in (HOME_DIR, TMP_DIR, PROFILE_DIR):
            os.makedirs(d, mode=0o700, exist_ok=True)
        cookie = secrets.token_hex(16)
        fd = os.open(xauth, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(xauth_entry(cookie))
        bins = {n: find_binary(n) for n in ("Xvfb", "x11vnc", "xauth", "xrandr", "xsel")}
        if not all(bins.values()):
            raise SupervisorError("a required program is missing")
        # 2. Xvfb, then the proof that its abstract name is its own
        xvfb, display = start_xvfb(bins["Xvfb"], xauth, child_env(xauth=xauth))
        children.append(("xvfb", xvfb))
        try:
            prove_display(xvfb.pid, display)
        except DisplayMismatch:
            display_ok = False
            raise
        env = child_env(display, xauth)
        if _devnull_run([bins["xauth"], "-f", xauth, "source", "-"], env, 5.0,
                        stdin_bytes=f"add :{display} . {cookie}\n".encode()) != 0:
            raise SupervisorError("xauth failed")
        # 3. the size
        w, h = cfg["geometry"]
        code, text = _capture_run([bins["xrandr"], "-q"], env, 5.0)
        output, current, _modes = parse_xrandr_query(text)
        if code != 0 or not output:
            raise SupervisorError("xrandr gave no output name")
        holder = ModeHolder(display, xauth, output, on_lost=lambda: stop_children(children))
        holders.append(holder)
        xr = Xrandr(bins["xrandr"], env, output, current, holder)
        if not xr.set_size(w, h, time.monotonic() + 5.0):
            raise SupervisorError("the screen size could not be set")
        # 3b. the keyboard map, before x11vnc and Chromium look at it (1.26.1). Never fatal: without it x11vnc adds keysyms itself.
        try:
            holder.prefill_keymap()
        except Exception:
            log("the keyboard map was not prepared")
        # 4. x11vnc
        vnc = spawn(x11vnc_argv(bins["x11vnc"], display, xauth, f"{rt}/vnc.sock"), env)
        children.append(("x11vnc", vnc))
        # 5. the window manager: before Chromium maps its first window. Failing to become the window manager ends the session.
        wm = WindowManager(holder)
        # 6. Chromium
        chromium = start_chromium(chromium_argv(cfg["chromium"], w, h, cfg["home"], cfg.get("theme_mode")), env)
        children.append(("chromium", chromium))
        # 7. the control socket
        ctl = make_ctl_socket(f"{rt}/ctl.sock")
        sel = selectors.DefaultSelector()
        sel.register(ctl, selectors.EVENT_READ, "ctl")
        sel.register(wm.fd, selectors.EVENT_READ, "wm")
        state = {"xrandr": xr, "wm": wm, "clipboard": cfg["clipboard"],
                 "clip": lambda: read_clipboard(bins["xsel"], env),
                 "type": lambda text: holder.type_text(text, TYPE_BUDGET_S, pump=wm.pump, stopping=lambda: stop["flag"])}
        log("session started")

        def wait_events():
            # events Xlib already holds do not wake select(): with some pending, do not sleep (the backlog would drain at one
            # pump per second); the control socket is still served on this pass
            for key, _ in sel.select(0 if wm.pending() else LOOP_S):
                if key.data == "ctl":
                    try:
                        conn, _addr = ctl.accept()
                    except (BlockingIOError, OSError):
                        continue
                    handle_ctl(conn, state)
            # events Xlib already holds do not wake select(): serve them on every pass, and re-read the screen size
            wm.pump()
            wm.refresh()

        # 8. the loop over every child
        first_gone, rc = watch(children, wait_events, lambda: stop["flag"])
    except DisplayMismatch:
        log("display proof failed")
    except SupervisorError as e:
        log(f"setup failed: {e}")
        first_gone, rc = "setup", 1
    except Exception as e:   # never leave the unit half started
        log(f"setup failed: {e.__class__.__name__}")
        first_gone, rc = "setup", 1
    finally:
        stop_children(children)
        for h in holders:
            h.close()
        if ctl is not None:
            try:
                ctl.close()
            except OSError:
                pass
            try:
                os.unlink(f"{rt}/ctl.sock")
            except OSError:
                pass
    code = exit_code(display_ok, first_gone, rc, stop["flag"])
    log(f"exit {code} (gone: {first_gone or 'none'}, status: {rc})")
    return code


def main(environ=None):
    environ = os.environ if environ is None else environ
    try:
        cfg = read_config(environ)
    except SupervisorError as e:
        log(f"refused: {e}")
        return EXIT_OTHER
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main())
