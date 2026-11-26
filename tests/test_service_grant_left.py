"""A service card shows the time left on the viewer's grant when /api/me carries an end time for it.

static/js/dashboard.js serviceGrantLeft(user, serviceId) gives the words user-connections.js
formatGrantRemaining gives a shared connection's card ("12 days left"); it gives nothing for an administrator,
a grant that never ends, a service with no grant entry or an answer without granted_service_expiry. The card
carries an empty span that is filled with textContent, never with markup. Both functions run under Node.

Run: venv/bin/python tests/test_service_grant_left.py   (60 second deadline)
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


dash = (STATIC / "js" / "dashboard.js").read_text()
ucjs = (STATIC / "js" / "user-connections.js").read_text()
index = (STATIC / "index.html").read_text()


def fn(text, name):
    m = re.search(rf"function {name}\(.*?\n\}}\n", text, re.S)
    return m.group(0) if m else ""


left_src, fmt_src = fn(dash, "serviceGrantLeft"), fn(ucjs, "formatGrantRemaining")
check("both functions were found", bool(left_src) and bool(fmt_src))
check("the card has the span, and it is filled with textContent",
      'class="service-grant-left"' in dash and "el.textContent = serviceGrantLeft(currentUser, el.dataset.grantLeft)" in dash)
card = dash.split("function createServiceCard")[1].split("\n}\n")[0] if "function createServiceCard" in dash else ""
span = re.search(r'<span class="service-grant-left"[^>]*>', card)
check("the span has no inline handler and holds no text of its own",
      span is not None and "onclick" not in span.group(0) and "</span>" in card[span.end():span.end() + 8])
check("index.html loads dashboard.js version 62 (61 added this card; 62 added the Web Browser card)", 'dashboard.js?v=62"' in index)

node = shutil.which("node")
if node and left_src and fmt_src:
    script = f"""
const Portal = {{ isAdmin: (u) => !!(u && u.is_admin) }};
{fmt_src}
{left_src}
const exp = {{ "7": 30 * 86400, "8": null, "9": 3600 + 120, "10": 0 }};
const member = {{ is_admin: false, granted_service_expiry: exp }};
const out = [
  serviceGrantLeft(member, 7), serviceGrantLeft(member, "7"), serviceGrantLeft(member, 8), serviceGrantLeft(member, 9),
  serviceGrantLeft(member, 10), serviceGrantLeft(member, 99),
  serviceGrantLeft({{ is_admin: false }}, 7), serviceGrantLeft({{ is_admin: true, granted_service_expiry: exp }}, 7),
  serviceGrantLeft(null, 7),
];
console.log(JSON.stringify(out));
"""
    try:
        res = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
        got = json.loads(res.stdout) if res.returncode == 0 else res.stderr
    except subprocess.TimeoutExpired:
        got = "node timed out"
    want = ["30 days left", "30 days left", "", "1 h 2 min left", "expired", "", "", "", ""]
    check("serviceGrantLeft answers as the connection cards do, and nothing when there is no end time", got == want, str(got))
else:
    check("node is installed (the harness needs it)", False, "node missing")

if failures:
    print(f"\ntest_service_grant_left: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_service_grant_left: all checks passed")
