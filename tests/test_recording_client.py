"""The Recordings player and list (static/js/recordings-admin.js) under Node, against a small fake DOM,
a fake fetch and a fake xterm (tests/recordings_client_harness.js): a load that is cancelled by closing the
modal or by Play on another row draws nothing, sizes are clamped to 500 x 200, Download saves a blob and
reports a failure, Escape closes the modal, and the last page is left when its last row was deleted.
Each of the three stale checks in play() (after loadXterm, after the fetch, after the text) is also
proven on its own: a copy of the script with just that one check deleted must fail the case for that await.
No browser: how the modal looks and how a real download behaves is not proven.

Run: venv/bin/python tests/test_recording_client.py
"""

import json
import shutil
import subprocess
import sys
import tempfile
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

# Delete each of the three "if (token !== loadToken) return;" lines of play() in turn, in a temporary copy,
# and run the harness on it: the case for that await (and only a stale-after-... case) must fail.
CHECK_LINE = "            if (token !== loadToken) return;\n"
CASES = ["stale-after-xterm", "stale-after-fetch", "stale-after-text"]
if shutil.which("node") is not None:
    src = JS.read_text()
    check("play() has the three stale checks the mutation cases delete", src.count(CHECK_LINE) == 3, str(src.count(CHECK_LINE)))
    if src.count(CHECK_LINE) == 3:
        for n, case in enumerate(CASES):
            parts = src.split(CHECK_LINE)
            out = parts[0]
            for i in range(1, 4):
                out += (CHECK_LINE if i - 1 != n else "") + parts[i]
            with tempfile.TemporaryDirectory() as d:
                copy = Path(d) / "recordings-admin.js"
                copy.write_text(out)
                proc = subprocess.run(["node", str(ROOT / "tests" / "recordings_client_harness.js"), str(copy)],
                                      capture_output=True, text=True, timeout=60)
            got = [json.loads(l[7:]) for l in proc.stdout.splitlines() if l.startswith("RESULT ")]
            bad = [r["name"] for r in got if not r["ok"]]
            check(f"without its own check, the {case} case fails",
                  any(b.startswith(case) for b in bad), "; ".join(bad) or proc.stderr[-200:])

if failed:
    print(f"\ntest_recording_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_recording_client: all checks passed")
