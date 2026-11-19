"""Chat page fixes of the 1.14.0 review: styles, the voice meter note, history state
on a closed socket, the lost-channel state, and the search highlight.

Markup and wiring checks on chat.html, then the voice meter and lost-channel
functions run under Node (tests/chat_page_fixes_harness.js) against a small fake
page. The socket close handler and the look of the chips are checked as text
only: a browser is needed to see them.

Run: venv/bin/python tests/test_chat_page_fixes.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
CHAT = (STATIC / "chat.html").read_text()
PORTAL_CSS = (STATIC / "css" / "portal.css").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


def rule(selector):
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CHAT)
    return m.group(1) if m else ""


vs = rule(".voice-settings-content")
check("the voice settings box scrolls inside the window", "max-height: 90vh" in vs and "overflow-y: auto" in vs, vs)

for sel in (".search-chip", ".search-results-note"):
    body = rule(sel)
    used = set(re.findall(r"var\((--[a-z-]+)", body))
    undefined = [v for v in used if ("%s:" % v) not in PORTAL_CSS]
    check(f"{sel} uses only variables portal.css defines", not undefined, undefined)
    check(f"{sel} has a fallback on every variable", all(re.search(r"var\(%s," % v, body) for v in used if v not in
          ("--text-muted", "--text-primary")), body)
chip = rule(".search-chip")
check("a chip has a border and a background", "border: 1px solid var(" in chip and "background: var(" in chip, chip)

close = CHAT[CHAT.index("ws.onclose = (event)"):CHAT.index("ws.onerror")]
check("a closed socket resets the history request state and keeps the buffer",
      "HistoryView.pending = null;" in close and "HistoryView.loading = false;" in close
      and "HistoryView.buffer" not in close)

check("a Channel not found frame in a channel view shows the lost-channel state",
      "data.message === 'Channel not found' && currentView === 'channel'" in CHAT and "showChannelUnavailable();" in CHAT)
check("sending is refused while the channel is lost",
      "if (channelUnavailable && currentView === 'channel') return;" in CHAT)

if shutil.which("node"):
    proc = subprocess.run(["node", str(ROOT / "tests" / "chat_page_fixes_harness.js"), str(STATIC / "chat.html")],
                          capture_output=True, text=True, timeout=60)
    rows = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    check("the harness ran", proc.returncode == 0 and len(rows) >= 5, proc.stderr[-300:])
    for r in rows:
        check(r["name"], r["ok"], r["detail"])
else:
    print("skip the Node checks: node is not installed")

if failed:
    print(f"\ntest_chat_page_fixes: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_chat_page_fixes: all checks passed")
