"""The blocked-words field of the automod rule form in static/admin.html, run under Node against a small fake
document: one entry per line, so a regex such as a{1,3} is saved and read back unchanged; text with no line
break in a rule that is not a regex rule is still a comma-separated list; the stored words are shown one per
line. Not a browser: layout is not covered.

Run:  venv/bin/python tests/test_automod_words_form.py
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

try:
    proc = subprocess.run([node, str(ROOT / "tests" / "automod_words_harness.js"), str(ROOT / "static" / "admin.html")],
                          capture_output=True, text=True, timeout=60)
except subprocess.TimeoutExpired:
    print("FAIL: the harness did not finish in 60 seconds")
    sys.exit(1)
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
if proc.returncode != 0 or seen < 14:
    print("FAIL: the harness ran", proc.stderr[-500:], proc.stdout[-500:])
    failures.append("harness")
print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
