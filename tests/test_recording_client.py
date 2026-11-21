"""The Recordings player and list (static/js/recordings-admin.js) under Node, against a small fake DOM,
a fake fetch and a fake xterm (tests/recordings_client_harness.js): a load that is cancelled by closing the
modal or by Play on another row draws nothing, sizes are clamped to 500 x 200, Download saves a blob and
reports a failure, Escape closes the modal, and the last page is left when its last row was deleted.
No browser: how the modal looks and how a real download behaves is not proven.

Run: venv/bin/python tests/test_recording_client.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


JS = ROOT / "static" / "js" / "recordings-admin.js"
if shutil.which("node") is None:
    check("node is installed (needed to run the client harness)", False)
else:
    syn = subprocess.run(["node", "--check", str(JS)], capture_output=True, text=True, timeout=60)
    check("recordings-admin.js passes a syntax check", syn.returncode == 0, syn.stderr[:300])
    proc = subprocess.run(["node", str(ROOT / "tests" / "recordings_client_harness.js"), str(JS)],
                          capture_output=True, text=True, timeout=60)
    got = [json.loads(l[7:]) for l in proc.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran and reported checks", len(got) >= 25, proc.stdout[-300:] + proc.stderr[-300:])
    for r in got:
        check(r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_recording_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_recording_client: all checks passed")
