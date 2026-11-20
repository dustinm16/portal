"""The share and grant dialogs carry the duration picker (30 days preselected, the server's
seven values), send the chosen key and never a timestamp, lists show the time left, and the
terminal does not offer to reconnect after "access ended" (close code 4010).

Run: venv/bin/python tests/test_grant_expiry_ui.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import grant_expiry  # noqa: E402

STATIC = ROOT / "static"
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


index = (STATIC / "index.html").read_text()
admin = (STATIC / "admin.html").read_text()
ucjs = (STATIC / "js" / "user-connections.js").read_text()
dash = (STATIC / "js" / "dashboard.js").read_text()
term = (STATIC / "js" / "terminal.js").read_text()

for label, html, sel_id in (("share dialog", index, "share-duration"), ("grant dialog", admin, "grant-duration")):
    m = re.search(rf'<select id="{sel_id}">(.*?)</select>', html, re.S)
    opts = re.findall(r'<option value="([^"]+)"( selected)?>', m.group(1)) if m else []
    check(f"{label} has a duration picker with exactly the server's values",
          [o[0] for o in opts] == list(grant_expiry.DURATIONS), str(opts))
    check(f"{label} preselects 30 days (the UI default)", [o[0] for o in opts if o[1]] == [grant_expiry.UI_DEFAULT], str(opts))

check("the share dialog sends the chosen duration, not a timestamp",
      "expires_in" in ucjs and "expires_at:" not in ucjs and "JSON.stringify({ usernames, expires_in })" in ucjs)
check("the grant dialog sends the chosen duration, not a timestamp",
      "expires_in: document.getElementById('grant-duration').value" in admin and "expires_at:" not in admin)
check("a shared card shows the time left (both dashboards)",
      "formatGrantRemaining(conn.share_expires_in)" in ucjs and "formatGrantRemaining(conn.share_expires_in)" in dash)
check("the share list shows grantor, creation and time left", "describeGrant(s)" in ucjs)
check("both dialogs have an all-grants view",
      "/api/me/shares" in ucjs and "/api/admin/grants" in admin and "describeGrantLine(g)" in admin)
check("terminal.js ends quietly on 4010 without offering a reconnect",
      re.search(r"event\.code === 4010\s*\)\s*\{[^}]*return;", term, re.S) is not None)

node = shutil.which("node")
if node:
    def fn_src(text):
        m = re.search(r"function formatGrantRemaining\(sec\) \{.*?\n\s*\}\n", text, re.S)
        return m.group(0) if m else ""
    for label, text in (("user-connections.js", ucjs), ("admin.html", admin)):
        src = fn_src(text)
        script = src + "\nconsole.log(JSON.stringify([null, 0, -5, 59, 60, 3600, 3660, 86400 + 3600, 2 * 86400, 30 * 86400].map(formatGrantRemaining)));"
        out = subprocess.run([node, "-e", script], capture_output=True, text=True)
        got = json.loads(out.stdout) if out.returncode == 0 else out.stderr
        want = ["never expires", "expired", "expired", "1 min left", "1 min left", "1 h 0 min left",
                "1 h 1 min left", "1 day 1 h left", "2 days left", "30 days left"]
        check(f"formatGrantRemaining in {label}", got == want, str(got))
else:
    print("skip: node is not installed, formatGrantRemaining was not run")

if failures:
    print(f"\ntest_grant_expiry_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_grant_expiry_ui: all checks passed")
