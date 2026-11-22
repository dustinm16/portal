"""The command palette (Ctrl+K, static/js/portal.js) opens a connection in the open mode the member
saved for it (prefs.open_mode of the list API) instead of the default one. The palette code runs
under Node with stubs (tests/palette_open_mode_harness.js); no browser, so how the new window is
treated by a popup blocker is not proven here.

Run: venv/bin/python tests/test_palette_open_mode.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL = (ROOT / "static" / "js" / "portal.js").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("the palette passes the saved open mode to connectTo", "connectTo(item.id, item.openMode || 'default')" in PORTAL
      and "openMode: this._openModeOf(c)" in PORTAL)
check("connectTo takes the open mode as its second argument",
      "async function connectTo(connectionId, openMode)" in (ROOT / "static" / "js" / "user-connections.js").read_text())
node = shutil.which("node")
if node:
    res = subprocess.run([node, str(ROOT / "tests" / "palette_open_mode_harness.js")], capture_output=True, text=True, timeout=60)
    for ln in res.stdout.splitlines():
        print(ln)
        if ln.startswith("FAIL"):
            failed.append(ln)
    check("palette_open_mode_harness.js exits 0", res.returncode == 0, res.stderr[-300:])
else:
    check("node is installed", False, "the palette could not be run")

if failed:
    print(f"\ntest_palette_open_mode: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_palette_open_mode: all checks passed")
