"""Static check on static/admin.html: the text shown when the local Chart.js file does not load names
the file, not a CDN.

Run: venv/bin/python tests/test_admin_page_text.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "static" / "admin.html").read_text()
failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


# ---- E41: the chart fallback text -------------------------------------------------------------------
msg = re.search(r"Charts unavailable[^<]*", html)
check("the chart fallback names the local file", bool(msg) and "/static/vendor/chart.js/chart.umd.js" in msg.group(0), msg.group(0) if msg else "")
check("the chart fallback no longer talks about a CDN", "from CDN" not in html and "failed to load from CDN" not in html)

if failures:
    print(f"\ntest_admin_page_text: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_admin_page_text: all checks passed")
