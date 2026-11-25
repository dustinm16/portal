"""The watch page while it is open: a stream that goes offline and live again, a ban placed while the page is
open, a stream that is gone.

watch.html's poll function runs under Node (tests/watch_page_harness.js) against a small fake page and a fake
fetch. There is no browser here: the real player, the real timers and the look of the page are not proven.

Run: venv/bin/python tests/test_watch_page.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import outbound_guard  # noqa: E402

outbound_guard.install()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


if not shutil.which("node"):
    check("node is installed", False, "node not found")
else:
    try:
        out = subprocess.run(["node", str(ROOT / "tests" / "watch_page_harness.js"), str(ROOT / "static" / "watch.html")],
                             capture_output=True, text=True, timeout=60)
        rows = [json.loads(l[7:]) for l in out.stdout.splitlines() if l.startswith("RESULT ")]
        check("the harness ran", len(rows) >= 8, out.stderr[-300:] + out.stdout[-300:])
        for r in rows:
            check("watch.html: " + r["name"], r["ok"], r["detail"])
    except subprocess.TimeoutExpired:
        check("the harness finished in time", False, "timeout")

if outbound_guard.refused:
    check("nothing dialled out", False, str(outbound_guard.refused))
if failed:
    print(f"\ntest_watch_page: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_watch_page: all checks passed")
