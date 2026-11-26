"""Every script and stylesheet the pages load carries a ?v= version, and a file
has one version everywhere it is referenced (the HTML pages and the copy in
server.py's SearXNG head injection). Cloudflare caches /static/* by URL, so a
file referenced under two versions means one page serves stale code.

Run: venv/bin/python tests/test_static_versions.py
"""

import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = re.compile(r"""(?:src|href)=["'](?:/static/|/)?((?:js|css)/[A-Za-z0-9_./-]+\.(?:js|css))(?:\?v=([A-Za-z0-9]+))?["']""")
INJECT = re.compile(r"""/static/((?:js|css)/[A-Za-z0-9_./-]+\.(?:js|css))\?v=([A-Za-z0-9]+)""")

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


versions = collections.defaultdict(lambda: collections.defaultdict(set))
unversioned = []
for page in sorted((ROOT / "static").glob("*.html")):
    text = page.read_text(encoding="utf-8")
    for m in REF.finditer(text):
        path, ver = m.group(1), m.group(2)
        if ver is None:
            unversioned.append(f"{page.name}: {path}")
        else:
            versions[path][ver].add(page.name)
for m in INJECT.finditer((ROOT / "server.py").read_text(encoding="utf-8")):
    versions[m.group(1)][m.group(2)].add("server.py")

check("the pages reference scripts and stylesheets", len(versions) > 20, str(len(versions)))
check("every script and stylesheet tag has a version", not unversioned, str(unversioned))
for path, found in sorted(versions.items()):
    check(f"{path} has one version everywhere", len(found) == 1,
          "; ".join(f"v{v}: {sorted(p)}" for v, p in sorted(found.items())))
    check(f"{path} exists", (ROOT / "static" / path).is_file())

# The Web Browser files (release 1.25.0): each is loaded by exactly the pages that should load it.
check("rbrowser-admin.js is loaded by admin.html only", sorted(versions["js/rbrowser-admin.js"].get("1", set())) == ["admin.html"], str(dict(versions["js/rbrowser-admin.js"])))
check("rbrowser.js and rbrowser.css are loaded by rbrowser.html only",
      all(sorted(p for v in versions[f].values() for p in v) == ["rbrowser.html"] for f in ("js/rbrowser.js", "css/rbrowser.css")))
check("dashboard.js is loaded by index.html at the version the dashboard card shipped with",
      dict(versions["js/dashboard.js"]) == {"62": {"index.html"}}, str(dict(versions["js/dashboard.js"])))

if failures:
    print(f"\ntest_static_versions: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_static_versions: all checks passed")
