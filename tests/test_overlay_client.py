"""Chat overlay clients: the overlay page script (static/js/overlay.js) and the stream settings block
(static/js/stream-overlay-settings.js).

The scripts run under Node as separate classic scripts in one global scope (tests/overlay_client_harness.js) against a
small fake DOM, a fake WebSocket and a scripted fetch. Source checks: no innerHTML, no inline handlers, no emoji-like
characters, every page that uses them loads them at their version. No browser: how the overlay looks and that OBS
shows it are not proven here.

Run: venv/bin/python tests/test_overlay_client.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
failed = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ("" if ok else f"  ({detail})"), flush=True)
    if not ok:
        failed.append(name)


for js_name in ("overlay.js", "stream-overlay-settings.js"):
    JS = (STATIC / "js" / js_name).read_text(encoding="utf-8")
    check(f"{js_name} never assigns innerHTML or outerHTML, and never evals",
          not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|eval\(|new Function", JS))
    check(f"{js_name} makes no inline handler", "onclick" not in JS.lower() and "setAttribute('on" not in JS)
    check(f"{js_name} has no emoji or emoji-like symbol characters", all(ord(ch) < 0x2190 or ch in "–—‘’“”" for ch in JS),
          str({ch for ch in JS if ord(ch) >= 0x2190}))
css = (STATIC / "css" / "overlay.css").read_text(encoding="utf-8")
check("overlay.css is transparent and has no external url", "transparent" in css and "url(" not in css and "@import" not in css)
html = (STATIC / "overlay.html").read_text(encoding="utf-8")
check("overlay.html loads its own script (v2) and style (v1) and nothing else",
      "/static/js/overlay.js?v=2" in html and "/static/css/overlay.css?v=1" in html and html.count("<script") == 1 and html.count("<link") == 1)
index = (STATIC / "index.html").read_text(encoding="utf-8")
check("the dashboard loads the settings block before streams.js, at v2", index.index("stream-overlay-settings.js?v=2") < index.index("streams.js?v=53"))
streams_js = (STATIC / "js" / "streams.js").read_text(encoding="utf-8")
check("the stream settings have the mount point and mount the block", 'id="stream-overlay-mount"' in streams_js and "StreamOverlaySettings.mount(" in streams_js)

node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "overlay_client_harness.js"), str(STATIC / "js" / "overlay.js"),
                          str(STATIC / "js" / "stream-overlay-settings.js"), str(STATIC / "js" / "portal.js")],
                         capture_output=True, text=True, timeout=60)
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-600:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])
    for js in ("overlay.js", "stream-overlay-settings.js", "streams.js"):
        r = subprocess.run([node, "--check", str(STATIC / "js" / js)], capture_output=True, text=True, timeout=30)
        check(f"node --check {js}", r.returncode == 0, r.stderr[-300:])

if failed:
    print(f"\ntest_overlay_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_overlay_client: all checks passed")
