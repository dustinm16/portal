"""Voice connection-quality bars and the lost-audio hint (1.20.0).

Static checks on static/js/voice.js, chat.html and watch.html, then the real
voice.js runs under Node (tests/voicequality_harness.js) against fake peer
connections with scripted getStats(), a controllable clock, setInterval and
page visibility. Node is needed for the second half; without it that part is
reported as skipped.

Usage: venv/bin/python tests/test_voicequality.py [path to voice.js]
(the optional path runs the same checks against another copy of the script)
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
VOICE_JS = Path(sys.argv[1]) if len(sys.argv) > 1 else STATIC / "js" / "voice.js"
SRC = VOICE_JS.read_text()
CHAT = (STATIC / "chat.html").read_text()
WATCH = (STATIC / "watch.html").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


def between(a, b):
    """The source between two markers, or "" when the code is not there."""
    return SRC.split(a)[1].split(b)[0] if a in SRC and b in SRC.split(a)[1] else ""


# ---- static ---------------------------------------------------------------------
check("both pages carry the bar styles", all(".vq-bar" in p and ".vq-noaudio .vq-hint" in p for p in (CHAT, WATCH)))
check("the bar slot has a fixed width (no layout shift)", all(re.search(r"\.vq \{[^}]*width: 2rem", p) for p in (CHAT, WATCH)))
check("the slot is built from DOM nodes, never from markup", "innerHTML" not in SRC and "insertAdjacentHTML" not in SRC)
check("the loop and its page-visibility pause exist",
      "QUALITY_POLL_MS = 4000" in SRC and "QUALITY_NOAUDIO_MS = 6000" in SRC and "visibilitychange" in SRC)
check("_cleanup stops the loop", "_qualityClear();" in between("function _cleanup", "function toggleMute"))
check("only getStats numbers and candidate types are read: no address, ip or port",
      not re.search(r"\.(address|ip|port|relatedAddress|relatedPort|usernameFragment)\b", between("function readQualityStats", "function scoreQuality")))
check("nothing from the quality code is sent to the server",
      not re.search(r"_ws\.send[^;]*(_quality|lossPct|rttMs|path)", SRC))
check("the hint code never restarts, closes or renegotiates",
      not re.search(r"restartIce|\.close\(\)|createOffer|_createAndOffer",
                    between("function _qualityPoll", "function _qualityStart")))
_css = [p.split("connection quality bars")[-1].split("</style>")[0] for p in (CHAT, WATCH)]
check("no inline handler and no non-ASCII character (emoji) in the new CSS",
      all("onclick" not in c and c.isascii() for c in _css))
check("no non-ASCII character in the new voice.js code",
      between("Connection quality (1.20.0)", "// WebRTC peer management").isascii())

# ---- dynamic ----------------------------------------------------------------------
node = shutil.which("node")
if not node:
    print("ok   (static only; node not found, dynamic checks skipped)")
    sys.exit(1 if failed else 0)

res = subprocess.run([node, str(Path(__file__).with_name("voicequality_harness.js")), str(VOICE_JS)],
                     capture_output=True, text=True, timeout=120)
rows = [json.loads(l[7:]) for l in res.stdout.splitlines() if l.startswith("RESULT ")]
check("the harness ran", res.returncode == 0 and len(rows) > 0, res.stderr[-400:])
for r in rows:
    check(r["name"], r["ok"], r["detail"])
check("enough dynamic checks ran", len(rows) >= 70, len(rows))

print(f"{len(rows)} dynamic checks, {len(failed)} failure(s)")
sys.exit(1 if failed else 0)
