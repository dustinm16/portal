"""Stream schedule client (static/js/stream-schedule.js): countdown, Interested toggle, Upcoming strip, the owner's
editor and the calendar link block.

The script runs under Node together with the real portal.js, as two classic scripts in one global scope that share only
the global object (tests/schedule_client_harness.js), against a small fake DOM and a scripted fetch. Source checks: no
innerHTML, no inline handlers, no emoji-like characters, every page that uses it loads it at its version. No browser:
how the countdown looks and the layout of the strip are not proven here.

Run: venv/bin/python tests/test_schedule_client.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
JS = (STATIC / "js" / "stream-schedule.js").read_text(encoding="utf-8")
failed = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ("" if ok else f"  ({detail})"), flush=True)
    if not ok:
        failed.append(name)


check("the script never assigns innerHTML or outerHTML, and never evals",
      not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|eval\(|new Function", JS))
check("no inline handler is made", "onclick" not in JS.lower() and "setAttribute('on" not in JS)
check("no emoji or emoji-like symbol characters", all(ord(ch) < 0x2190 or ch in "\u2013\u2014\u2018\u2019\u201c\u201d" for ch in JS),
      str({ch for ch in JS if ord(ch) >= 0x2190}))
for page, mark in (("watch.html", "stream-schedule.js?v=5"), ("streams.html", "stream-schedule.js?v=5"), ("index.html", "stream-schedule.js?v=5")):
    check(f"{page} loads stream-schedule.js at v5", mark in (STATIC / page).read_text(encoding="utf-8"))
check("the Streams page has the Upcoming strip element and the user settings the calendar link element",
      'id="schedule-upcoming"' in (STATIC / "streams.html").read_text() and 'id="calendar-feed-settings"' in (STATIC / "index.html").read_text())
check("the offline page draws once and mounts the countdown for the next occurrence",
      'data-offline="1"' in (STATIC / "watch.html").read_text() and "StreamSchedule.mountWatch(" in (STATIC / "watch.html").read_text())
_watch = (STATIC / "watch.html").read_text(encoding="utf-8")
_guard = _watch[_watch.index("function showOfflineMessage()"):]
_guard = _guard[:_guard.index("document.getElementById('video-container').innerHTML")]
check("the offline page is drawn once but the live indicator, the viewer count and the picture-in-picture button are settled on every call",
      "return;" in _guard and "live-indicator" in _guard and "viewer-count" in _guard and "updatePipButton()" in _guard, _guard)
_docs = (STATIC / "api-docs.html").read_text(encoding="utf-8")
_mine = _docs[_docs.index("/api/streams/schedule/upcoming</span>") - 400:_docs.index("/api/streams/live</span>") - 300]
check("the new endpoint blocks of the API page carry no inline onclick (they use data-endpoint-toggle)",
      "onclick" not in _mine and _mine.count("data-endpoint-toggle") == 5, str(_mine.count("data-endpoint-toggle")))
_streams_js = (STATIC / "js" / "streams.js").read_text()
check("the stream settings mount the owner's editor", "StreamSchedule.mountOwner(" in _streams_js)
_mount = _streams_js[_streams_js.index("StreamSchedule.mountOwner("):]
_mount = _mount[:_mount.index("loadUserStreams();")]
check("the stream settings pass a done callback that sets the name field and the heading and reloads the list",
      "(name) =>" in _mount and "'stream-name-input'" in _mount and ".value = name" in _mount
      and "'stream-details-title'" in _mount and ".textContent = name" in _mount, _mount)

node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "schedule_client_harness.js"), str(STATIC / "js" / "portal.js"),
                          str(STATIC / "js" / "stream-schedule.js")], capture_output=True, text=True, timeout=60)
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-600:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])
    for js in ("stream-schedule.js", "streams.js"):
        r = subprocess.run([node, "--check", str(STATIC / "js" / js)], capture_output=True, text=True, timeout=30)
        check(f"node --check {js}", r.returncode == 0, r.stderr[-300:])

if failed:
    print(f"\ntest_schedule_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_schedule_client: all checks passed")
