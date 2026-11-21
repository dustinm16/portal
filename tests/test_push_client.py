"""The push client: the "Phone notifications" block, the install hint, the places push stays off, the
logout that names this browser's device, and the markup and wiring around it.

push.js runs under Node (tests/push_client_harness.js) against fakes: no browser, no real service
worker, no real permission prompt, no phone. How the block looks, whether a browser shows the
permission prompt, and whether an installed iOS app receives a push are not proven here.

Run: venv/bin/python tests/test_push_client.py
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
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


INDEX = (STATIC / "index.html").read_text()
CHAT = (STATIC / "chat.html").read_text()
ADMIN = (STATIC / "admin.html").read_text()
ADMIN_JS = (STATIC / "js" / "admin.js").read_text()
PUSH = (STATIC / "js" / "push.js").read_text()

check("the user settings carry the Phone notifications block", 'id="push-settings"' in INDEX and "Phone notifications" in INDEX)
check("opening the settings draws the block", "PortalPush.mountSettings(document.getElementById('push-settings'))" in ADMIN_JS)
check("index and chat name the manifest and a theme colour", all(
    'rel="manifest" href="/manifest.webmanifest"' in p and 'name="theme-color"' in p for p in (INDEX, CHAT)))
check("no proxied or third-party page gets the manifest", all(
    "manifest.webmanifest" not in (STATIC / n).read_text() for n in ("browser.html", "terminal.html", "vnc.html", "login.html")))
for page in ("index", "chat", "admin", "streams", "files", "about", "guides", "api-docs"):
    text = (STATIC / f"{page}.html").read_text()
    check(f"{page}.html loads push.js (so a sign-out there names this browser's device)",
          re.search(r'src="/static/js/push\.js\?v=3"', text) is not None)
for page in sorted(STATIC.glob("*.html")):
    text = page.read_text()
    if 'href="/logout"' in text:
        check(f"{page.name} has a logout link, so it loads push.js (a sign-out there must close this browser's device)",
              "/static/js/push.js?v=3" in text)
check("the /search/ pages load push.js too (their navbar has a logout link)",
      "/static/js/push.js?v=3" in (ROOT / "server.py").read_text().split("_SEARXNG_HEAD_INJECT = (")[1].split(")")[0])
check("the chat page opens a /chat?dm= link once the socket's first frame has arrived (the server checks participation)",
      "pendingDmLink" in CHAT and "openDmConversation(linked)" in CHAT)
check("the admin card has the switch, the test button, a device count and the allow-list, and shows only on a 200",
      all(t in ADMIN for t in ("push-admin-enabled", "sendPushTest()", "push-admin-count", "push-admin-hosts"))
      and "if (!resp.ok) { card.style.display = 'none'; return; }" in ADMIN)
check("the admin card never asks for an endpoint", "endpoint" not in ADMIN[ADMIN.index('id="push-admin-card"'):ADMIN.index("Certificate Management Card")])

node = shutil.which("node")
if not node:
    check("node is installed", False, "node not found")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "push_client_harness.js"), str(STATIC / "js" / "push.js")],
                         capture_output=True, text=True, timeout=60)
    rows = [json.loads(l[7:]) for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", len(rows) >= 15, out.stderr[-300:] + out.stdout[-300:])
    for r in rows:
        check("push.js: " + r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_push_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_push_client: all checks passed")
