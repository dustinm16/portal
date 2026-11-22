"""The status dot on dashboard cards (static/js/conn-health.js, css/conn-health.css): wiring and
markup checks, then the tooltip words, the 60 second poll that pauses on a hidden tab, painting and
removal of dots, and an unexpected status run under Node against a fake DOM
(tests/conn_health_harness.js). Also the admin setting card.

No browser, no phone: how the dot looks next to the badge at phone width, the colours in each of the
28 themes and the real tooltip are not proven here.

Run: venv/bin/python tests/test_conn_health_client.py
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
INDEX = (STATIC / "index.html").read_text()
ADMIN = (STATIC / "admin.html").read_text()
JS = (STATIC / "js" / "conn-health.js").read_text()
ORG = (STATIC / "js" / "conn-organise.js").read_text()
CSS = (STATIC / "css" / "conn-health.css").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("index.html loads conn-health.js before conn-organise.js",
      0 < INDEX.find("conn-health.js?v=1") < INDEX.find("conn-organise.js?v="))
check("index.html loads the dot stylesheet", 'css/conn-health.css?v=1"' in INDEX)
check("conn-organise.js asks for a dot when it draws a card", "root.ConnHealth" in ORG and "ConnHealth.dot(conn.id)" in ORG)
check("conn-health.js polls the status route every 60 seconds and only while the tab is visible",
      "/api/connections/status" in JS and "POLL_MS = 60000" in JS and "visibilityState" in JS and "visibilitychange" in JS)
check("conn-health.js has no inline handler, no innerHTML and no eval",
      "innerHTML" not in JS and "eval(" not in JS and not re.search(r"\bon(click|change|input|submit)\s*=", JS))
check("the dot's words are set as attributes", "setAttribute('title'" in JS and "setAttribute('aria-label'" in JS)
check("the stylesheet has up, down and unknown",
      all(c in CSS for c in (".conn-health-up", ".conn-health-down", ".conn-health-unknown")))
check("the admin page has the setting card and no inline handler for it",
      'id="connhealth-body"' in ADMIN and "data-connhealth-action" in ADMIN and "/api/admin/connection-health" in ADMIN
      and "onclick=\"saveConnHealth" not in ADMIN)

node = shutil.which("node")
if node:
    res = subprocess.run([node, str(ROOT / "tests" / "conn_health_harness.js")], capture_output=True, text=True, timeout=60)
    for ln in res.stdout.splitlines():
        if ln.startswith(("ok:", "FAIL:")):
            check("conn_health_harness: " + ln.split(":", 1)[1].strip(), ln.startswith("ok:"))
    check("conn_health_harness.js exits 0", res.returncode == 0, res.stderr[-300:])
else:
    check("node is installed", False, "the dot logic could not be run")

if failed:
    print(f"\ntest_conn_health_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_conn_health_client: all checks passed")
