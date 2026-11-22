"""The VOD guard and playback cache fields of the retention form in static/admin.html, run under Node against
small fakes (a fake document, Portal.fetch and toast): whole-number fields refuse decimals, negatives, empty
and non-numbers with a message next to the field and send nothing; the gigabyte fields accept fractions; after
a save the form is drawn again from the configuration the server returned. Not a browser: layout is not covered.

Run:  venv/bin/python tests/test_admin_vod_fields.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
node = shutil.which("node")
if not node:
    print("FAIL: node is not installed (needed to run the admin page harness)")
    sys.exit(1)

proc = subprocess.run([node, str(ROOT / "tests" / "admin_vod_fields_harness.js"), str(ROOT / "static" / "admin.html")],
                      capture_output=True, text=True, timeout=60)
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
