"""Per-user voice volume and local mute.

Static checks on static/js/voice.js, chat.html and watch.html, then the real
voice.js runs under Node (tests/voicevol_harness.js) against a fake
AudioContext with gain nodes, fake audio elements, a small DOM, a fake
RTCPeerConnection and a fake localStorage. Node is needed for the second half;
without it that part is reported as skipped.

Usage: venv/bin/python tests/test_voicevol.py [path to voice.js]
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


# ---- static ---------------------------------------------------------------------
for page in STATIC.glob("*.html"):
    text = page.read_text()
    if "js/voice.js" in text:
        check(f"{page.name} loads voice.js v10", "js/voice.js?v=10" in text and "voice.js?v=9" not in text)
check("chat.html and watch.html both load voice.js",
      "js/voice.js?v=10" in CHAT and "js/voice.js?v=10" in WATCH)
check("the popover is built from DOM nodes and text, never from markup", "innerHTML" not in SRC and "insertAdjacentHTML" not in SRC)
check("localStorage is only touched inside try blocks",
      all("try {" in SRC[max(0, m.start() - 400):m.start()] for m in re.finditer(r"localStorage\.(?:get|set|remove)Item", SRC)))
check("volume preferences are never part of a message to the server",
      not re.search(r"JSON\.stringify\(\{[^}]*(vol|local)", SRC.replace("voice_prefs", "")))
check("a single _applyGain writes element mute and volume",
      len(re.findall(r"el\.muted = (?!true)", SRC)) == 1 and len(re.findall(r"\.volume = ", SRC)) == 1)
check("deafen goes through _applyAllGains", "_applyAllGains();" in SRC.split("function toggleDeafen")[1].split("function setMode")[0])
check("the page markup carries the popover hooks without inline handlers",
      'data-voice-uid="${Number(u.user_id)}"' in CHAT and "attachUserMenu" in CHAT and "attachUserMenu" in WATCH)
check("a masked anonymous sidebar entry never gets a voice id",
      "user.user_id != null" in CHAT and "anon_ref" not in re.search(r"const volAttrs.*?: '';", CHAT, re.S).group(0))

# ---- dynamic ----------------------------------------------------------------------
node = shutil.which("node")
if not node:
    print("ok   (static only; node not found, dynamic checks skipped)")
    sys.exit(1 if failed else 0)

res = subprocess.run([node, str(Path(__file__).with_name("voicevol_harness.js")), str(VOICE_JS)],
                     capture_output=True, text=True, timeout=120)
rows = [json.loads(l[7:]) for l in res.stdout.splitlines() if l.startswith("RESULT ")]
check("the harness ran", res.returncode == 0 and len(rows) > 0, res.stderr[-400:])
for r in rows:
    check(r["name"], r["ok"], r["detail"])
check("enough dynamic checks ran", len(rows) >= 90, len(rows))

print(f"{len(rows)} dynamic checks, {len(failed)} failure(s)")
sys.exit(1 if failed else 0)
