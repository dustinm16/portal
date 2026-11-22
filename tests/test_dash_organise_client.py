"""The dashboard organiser client (static/js/conn-organise.js): markup and wiring checks, then
the matching, grouping, recents and key rules run under Node (tests/conn_organise_harness.js), and
the drawing, filtering, folder collapse, pin, open mode and dialog run against a small fake DOM
(tests/conn_organise_dom_harness.js).

No browser, no phone: how it looks at phone width, focus movement and what window.open does
with each open mode are not proven here.

Run: venv/bin/python tests/test_dash_organise_client.py
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
INDEX = (STATIC / "index.html").read_text()
JS = (STATIC / "js" / "conn-organise.js").read_text()
DASH = (STATIC / "js" / "dashboard.js").read_text()
UC = (STATIC / "js" / "user-connections.js").read_text()
CSS = (STATIC / "css" / "portal.css").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


for ident in ("conn-filter", "conn-filter-clear", "conn-tag-chips", "conn-recent", "conn-recent-grid",
              "conn-organise-modal", "conn-organise-form", "conn-organise-folder", "conn-organise-tags",
              "conn-organise-cancel", "conn-organise-backdrop", "inline-connections-grid", "svc-filter"):
    check(f"index.html has #{ident}", f'id="{ident}"' in INDEX)
check("index.html loads conn-organise.js before dashboard.js",
      INDEX.find("conn-organise.js?v=") != -1 and INDEX.find("conn-organise.js?v=") < INDEX.find("dashboard.js?v="))
check("the dialog is a labelled modal dialog", 'role="dialog"' in INDEX and 'aria-modal="true"' in INDEX and "aria-labelledby=\"conn-organise-title\"" in INDEX)
block = INDEX[INDEX.index('id="conn-organiser"'):INDEX.index('id="inline-connections-grid"')]
dialog = INDEX[INDEX.index('id="conn-organise-modal"'):INDEX.index("<!-- Share Connection Modal -->")]
check("the new markup has no inline handler", "onclick" not in block and "onclick" not in dialog and "onsubmit" not in dialog)
check("conn-organise.js has no inline handler and no inline attribute handlers",
      not re.search(r"\bon(click|change|input|submit|keydown)\s*=", JS) and "setAttribute('on" not in JS)
inner = [ln.strip() for ln in JS.splitlines() if "innerHTML" in ln and not ln.strip().startswith(("//", "*"))]
check("innerHTML is used only for the file's own icons", all("svg" in ln or "getConnectionIcon" in ln for ln in inner), str(inner))
check("names, hosts, folders and tags are set with textContent", "el('h4')" in JS and "createTextNode(conn.name" in JS and "el('span', 'connection-host'" in JS)
check("dashboard.js hands the list to the organiser", "ConnOrganiser.show(" in DASH and "togglePin(${" not in DASH.split("async function loadInlineConnections")[1])
check("the services filter is re-applied after the cards are drawn", "ConnOrganiser.applyServiceFilter()" in DASH)
check("connectTo takes the open mode and uses it for every window it opens",
      "async function connectTo(connectionId, openMode)" in UC and UC.count("_openConnectionTarget(") >= 4 and "window.open(`" not in UC.split("async function connectTo")[1].split("\n}\n")[0])
check("collapsed folders are kept in this browser, per user", "localStorage" in JS and "portal.dash.folders." in JS)
check("Enter in the filter opens the first match; Escape clears", "orderedMatches(state.conns" in JS and "e.key === 'Enter'" in JS and "e.key === 'Escape'" in JS)
check("folder heads are buttons with aria-expanded", "'aria-expanded'" in JS and "conn-folder-head" in JS)
check("an author display rule cannot defeat the hidden attribute on the new controls",
      ".conn-filter-row [hidden]" in CSS and "display: none !important" in CSS.split("Dashboard organising")[1][:400])
check("the services filter reads only the name and plugin", "'.service-name'" in JS and "'.service-plugin'" in JS)
check("the phone layout has a rule", "@media (max-width: 600px)" in CSS.split("Dashboard organising")[1])
check("server text is never put in a selector unescaped", "CSS.escape" in JS)

node = shutil.which("node")
if node:
    for harness in ("conn_organise_harness.js", "conn_organise_dom_harness.js"):
        res = subprocess.run([node, str(ROOT / "tests" / harness)], capture_output=True, text=True, timeout=60)
        for ln in res.stdout.splitlines():
            print(ln)
            if ln.startswith("FAIL"):
                failed.append(ln)
        check(f"{harness} exits 0", res.returncode == 0, res.stderr[-300:])
else:
    check("node is installed", False, "the matching rules could not be run")

if failed:
    print(f"\ntest_dash_organise_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_dash_organise_client: all checks passed")
