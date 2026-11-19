"""The Cloudflare ranges panel of static/admin.html, run under Node against small fakes (a fake document,
fake Portal.fetch and confirm): the pending list box, its escaping, the approve and dismiss calls, and the
text that says why a saved list is ignored. The fakes are not a browser: layout and real events are not covered.

Run:  venv/bin/python tests/test_cf_panel.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
node = shutil.which("node")
if not node:
    print("ok   (node not found, panel checks skipped)")
    sys.exit(0)

proc = subprocess.run([node, str(ROOT / "tests" / "cf_panel_harness.js"), str(ROOT / "static" / "admin.html")], capture_output=True, text=True, timeout=60)
failures = []
seen = 0
for line in proc.stdout.splitlines():
    if not line.startswith("RESULT "):
        continue
    r = json.loads(line[7:])
    seen += 1
    print(("ok:   " if r["ok"] else "FAIL: ") + r["name"] + (f"  ({r['detail']})" if not r["ok"] and r["detail"] else ""))
    if not r["ok"]:
        failures.append(r["name"])
if proc.returncode != 0 or seen < 10:
    print("FAIL: the harness ran", proc.stderr[-500:], proc.stdout[-500:])
    failures.append("harness")
print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
