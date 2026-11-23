"""The announcement banner script (static/js/announce.js): the safe subset of markup built with DOM nodes,
links to http and https only, dismissal by id and last change, where the banner goes in a page, and the
wiring (portal.js loads it, the sign-in page loads it with the public list only).

The code runs under Node (tests/announce_harness.js) against a small fake document that throws if
innerHTML is assigned. No browser: how a banner looks, and the layout of the full-height pages with the
banner floating over them, are not proven here.

Run: venv/bin/python tests/test_announce_client.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
JS = (STATIC / "js" / "announce.js").read_text()
PORTAL = (STATIC / "js" / "portal.js").read_text()
LOGIN = (STATIC / "login.html").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("the script never assigns innerHTML, outerHTML or insertAdjacentHTML, and never evals",
      not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|eval\(|new Function", JS))
check("every link made passes through safeUrl (a protocol of http: or https: only)",
      "u.protocol !== 'http:' && u.protocol !== 'https:'" in JS and JS.count("safeUrl(") >= 3)
check("links get rel noopener noreferrer", "'noopener noreferrer'" in JS)
check("no inline handlers are made", "onclick" not in JS.lower() and "setAttribute('on" not in JS)
check("portal.js loads announce.js with a version, from the member list, and never inside a frame",
      "/static/js/announce.js?v=2" in PORTAL and "data-url', '/api/announcements'" in PORTAL and "window.self !== window.top" in PORTAL)
check("the sign-in page loads it with the public list only",
      'src="/static/js/announce.js?v=2" data-url="/api/announcements/public"' in LOGIN and LOGIN.count("announce.js") == 1)
check("no page loads it with a different version",
      not [p.name for p in STATIC.glob("*.html") if re.search(r"announce\.js\?v=(?!2\b)", p.read_text())])

node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "announce_harness.js"), str(STATIC / "js" / "announce.js")],
                         capture_output=True, text=True, timeout=60)
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, out.stderr[-500:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_announce_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_announce_client: all checks passed")
