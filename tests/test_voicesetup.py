"""Voice setup panel: device picker, VAD gate, level meter, loopback test,
output device and PTT release delay.

Static checks on static/js/voice.js, chat.html and watch.html, then the real
voice.js runs under Node (tests/voicesetup_harness.js) against fake
microphones, tracks, senders, AudioContexts, timers and localStorage. Node is
needed for the second half; without it that part is reported as skipped.
Nothing here touches the server: the settings never leave the browser.

Usage: venv/bin/python tests/test_voicesetup.py [path to voice.js]
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
check("chat.html and watch.html load voice.js v16",
      "js/voice.js?v=16" in CHAT and "js/voice.js?v=16" in WATCH)
check("track.enabled is written in one place only (the gate)",
      len(re.findall(r"\.enabled = ", SRC)) == 3,   # the gate, a clone's flag, the replacement track
      str(re.findall(r".*\.enabled = .*", SRC)))
check("the gate function is the only writer of enabled on the sent tracks",
      re.search(r"function _applyTxGate\(\) \{[^}]*t\.enabled = on", SRC, re.S) is not None)
check("the VAD and the meter read a clone, never the track that is gated",
      "track.clone()" in SRC and "_cloneStream(track)" in SRC and "_cloneStream(live)" in SRC)
check("the microphone is opened with an exact device id and a fallback",
      "deviceId = { exact: deviceId }" in SRC and "OverconstrainedError" in SRC)
check("the sent microphone sender is recorded, not searched for", "_micSenders.set(userId, sender)" in SRC and "getSenders" not in SRC)
def between(text, start, end):
    """The text from `start` up to `end`, or "" when the script does not have it."""
    return text.split(start)[1].split(end)[0] if start in text else ""


swap_src = between(SRC, "async function _swapMic", "function setInputDevice")
check("a switch uses replaceTrack and never rebuilds peer connections",
      "replaceTrack(fresh)" in swap_src and "_createAndOffer" not in swap_src)
check("the output picker is detected on AudioContext when Web Audio plays", "C.prototype.setSinkId" in SRC)
check("nothing is built from markup in voice.js", "innerHTML" not in SRC and "insertAdjacentHTML" not in SRC)
check("localStorage is only touched inside try blocks",
      all("try {" in SRC[max(0, m.start() - 400):m.start()] for m in re.finditer(r"localStorage\.(?:get|set|remove)Item", SRC)))
sends = re.findall(r"JSON\.stringify\(\{[^}]*\}\)", SRC)
check("no message to the server mentions a device, threshold, delay or loopback",
      not any(re.search(r"device|threshold|delay|loopback|sink", s, re.I) for s in sends), str(sends))
check("no network call besides the ICE server fetch", len(re.findall(r"\bfetch\(", SRC)) == 1)
# the page
panel = CHAT.split('id="voice-settings-modal"')[1].split("</body>")[0]
for needle, what in (("voice-meter", "the level meter"), ("voice-meter-line", "the threshold line"),
                     ("ptt-delay-slider", "the PTT delay slider"), ('id="voice-input-device"', "the input picker"),
                     ('id="voice-output-device"', "the output picker"), ('id="voice-loopback"', "the loopback box")):
    check(f"the settings window has {what}", needle in panel)
check("the output picker starts hidden", re.search(r'id="voice-output-settings"[^>]*display:\s*none', panel) is not None)
open_src = between(CHAT, "function openVoiceSettings", "function closeVoiceSettings")
check("the one-time threshold notice has its place in the window, outside the VAD block (hidden in PTT mode)",
      'id="voice-gate-notice"' in panel
      and panel.index('id="voice-gate-notice"') < panel.index('id="vad-settings"'))
check("opening the window takes the notice and shows it as text",
      "VoiceChat.takeGateNotice()" in open_src and "gateEl.textContent = gateNotice" in open_src and "innerHTML" not in open_src)
check("the loopback test warns about headphones", "headphones" in panel.lower())
check("the loopback box is not checked by default", "checked" not in re.search(r'<input[^>]*id="voice-loopback"[^>]*>', panel).group(0))
check("the input picker is wired", "handleVoiceInputChange" in CHAT and "VoiceChat.setInputDevice" in CHAT)
check("one close path stops the meter, and Escape, the backdrop and the button use it",
      "VoiceChat.stopMeter()" in between(CHAT, "function closeVoiceSettings", "function ")
      and "closeVoiceSettings();" in CHAT and "if(event.target===this)closeVoiceSettings()" in CHAT
      and 'onclick="closeVoiceSettings()"' in CHAT)
check("device names are put into the page as text, not markup",
      "opt.textContent = d.label" in CHAT and "innerHTML = '<option" not in CHAT)
check("the watch page has no settings window (the choices apply to its next join)", "voice-settings-modal" not in WATCH)

# ---- dynamic ----------------------------------------------------------------------
node = shutil.which("node")
if not node:
    print("ok   (static only; node not found, dynamic checks skipped)")
    sys.exit(1 if failed else 0)

res = subprocess.run([node, str(Path(__file__).with_name("voicesetup_harness.js")), str(VOICE_JS)],
                     capture_output=True, text=True, timeout=120)
rows = [json.loads(l[7:]) for l in res.stdout.splitlines() if l.startswith("RESULT ")]
check("the harness ran", res.returncode == 0 and len(rows) > 0, res.stderr[-400:])
for r in rows:
    check(r["name"], r["ok"], r["detail"])
check("enough dynamic checks ran", len(rows) >= 120, len(rows))

print(f"{len(rows)} dynamic checks, {len(failed)} failure(s)")
sys.exit(1 if failed else 0)
