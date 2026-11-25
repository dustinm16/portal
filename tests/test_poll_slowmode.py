"""Watch and chat page polish of 1.24.2: a poll card keeps the member's own choice across a broadcast, the slow
mode select returns to the last confirmed value when the server refuses a change, the live-now strip is capped
and follows stream_status, and the viewer-chat header buttons wrap on a narrow screen.

The poll and slow mode functions run under Node (tests/poll_slowmode_harness.js) against a small fake page; the
strip and the header are checked as text. There is no browser here: how the card, the strip and the header look
is not proven.

Run: venv/bin/python tests/test_poll_slowmode.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402

outbound_guard.install()
WATCH = (ROOT / "static" / "watch.html").read_text()
CHAT = (ROOT / "static" / "chat.html").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


if not shutil.which("node"):
    check("node is installed", False, "node not found")
else:
    try:
        out = subprocess.run(["node", str(ROOT / "tests" / "poll_slowmode_harness.js"),
                              str(ROOT / "static" / "watch.html"), str(ROOT / "static" / "chat.html")],
                             capture_output=True, text=True, timeout=60)
        rows = [json.loads(l[7:]) for l in out.stdout.splitlines() if l.startswith("RESULT ")]
        check("the harness ran", len(rows) >= 10, out.stderr[-300:] + out.stdout[-300:])
        for r in rows:
            check(r["name"], r["ok"], r["detail"])
    except subprocess.TimeoutExpired:
        check("the harness finished in time", False, "timeout")

# 93: the live-now strip
m = re.search(r"\.live-now-strip\s*\{([^}]*)\}", CHAT)
strip = m.group(1) if m else ""
check("the live-now strip has a height cap and scrolls", "max-height: 5rem" in strip and "overflow-y: auto" in strip, strip)
m = re.search(r"case 'stream_status':(.*?)break;", CHAT, re.S)
check("a stream_status frame refreshes the live-now strip", bool(m) and "refreshLiveNow()" in m.group(1), m.group(1) if m else "")

# 110: the viewer-chat header buttons
m = re.search(r'<div class="viewer-chat-header">.*?<div style="([^"]*)">\s*<button class="chat-popout-btn"', WATCH, re.S)
check("the viewer-chat header buttons wrap on a narrow screen", bool(m) and "flex-wrap:wrap" in m.group(1), m.group(1) if m else "no header")

if outbound_guard.refused:
    check("nothing dialled out", False, str(outbound_guard.refused))
if failed:
    print(f"\ntest_poll_slowmode: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_poll_slowmode: all checks passed")
