"""portal.js must publish Portal on the global object. It declares `const Portal`, which makes no window
property, so a script that reads window.Portal (block-ref-admin.js, voice.js, chat-retention.js) found nothing:
the Reference lookup always answered "The lookup failed." and toasts never showed.

The client check loads portal.js and then block-ref-admin.js as two classic scripts in one global scope
(Node vm), sharing only the global object, and follows the lookup to Portal.fetch. The older block-ref harness
passes Portal in itself and so could not see this. No browser.

Run: venv/bin/python tests/test_portal_global.py
"""

import json
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


node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "portal_global_harness.js"),
                          str(STATIC / "js" / "portal.js"), str(STATIC / "js" / "block-ref-admin.js")],
                         capture_output=True, text=True, timeout=60)
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-500:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_portal_global: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_portal_global: all checks passed")
