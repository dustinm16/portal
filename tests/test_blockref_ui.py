"""The administrator's reference lookup: the field in Admin > System > Network and static/js/block-ref-admin.js.

Source checks (ids, no inline handler, no innerHTML, the version everywhere) and the script itself under Node
against a fake document. No browser: how the field looks and a real fetch are not proven here.

Run: venv/bin/python tests/test_blockref_ui.py
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


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


admin = (STATIC / "admin.html").read_text()
js = (STATIC / "js" / "block-ref-admin.js").read_text()
check("admin.html has the field, the button and the result area",
      all(f'id="{i}"' in admin for i in ("block-ref-input", "block-ref-go", "block-ref-result")))
check("the field sits in the Blocked IPs section (after the list, before the Files tab)",
      admin.index('id="blocked-ips-body"') < admin.index('id="block-ref-input"') < admin.index('id="tab-files"'))
check("the new markup has no inline handler",
      not re.search(r'on(click|change|keydown)=', admin[admin.index('id="block-ref-input"') - 200: admin.index('id="block-ref-result"') + 100]))
check("the script is loaded once with version 1", admin.count("/static/js/block-ref-admin.js?v=1") == 1
      and not [p.name for p in STATIC.glob("*.html") if re.search(r"block-ref-admin\.js\?v=(?!1\b)", p.read_text())])
check("the script never assigns innerHTML or outerHTML and uses no inline handler attribute",
      not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|\.onclick\s*=|setAttribute\('on", js))
check("the unblock goes through the existing route with the reference", "'/api/admin/blocked-ips/'" in js and "'?ref='" in js)

node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "block_ref_harness.js"), str(STATIC / "js" / "block-ref-admin.js")],
                         capture_output=True, text=True, timeout=60)
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, out.stderr[-500:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_blockref_ui: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_blockref_ui: all checks passed")
