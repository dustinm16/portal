"""Static checks on static/admin.html: the Webhooks section and the retention error lines take their
status colours from the theme variables (every theme gets --accent-red, --accent-green and
--accent-yellow from the :root block of static/css/portal.css, and a theme may override them).

Run: venv/bin/python tests/test_admin_status_colours.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "static" / "admin.html").read_text()
css = (ROOT / "static" / "css" / "portal.css").read_text()
failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
FALLBACK = re.compile(r"var\(--[a-z-]+,\s*#[0-9a-fA-F]{3,8}\)")


def bare_hex(text):
    """Hex colours left once every var(--name, #hex) fallback is taken out."""
    return HEX.findall(FALLBACK.sub("", text))


# ---- 86: status colours of the Webhooks section and of the retention error lines ---------------
m = re.search(r"// System webhooks \(superadmin only\).*?// Initialize\n", html, re.S)
wh = m.group(0) if m else ""
check("webhook section script found", len(wh) > 2000)
check("the webhook section has no hard-coded colour, only var() with a fallback", not bare_hex(wh), str(bare_hex(wh)))
errs = re.findall(r'<div id="ret-vod-[a-z-]+-err"[^>]*>', html)
check("the four retention error lines are found", len(errs) == 4, str(len(errs)))
check("the retention error lines have no hard-coded colour", not any(bare_hex(e) for e in errs), str(errs))
used = set(re.findall(r"var\((--accent-(?:red|green|yellow))", wh + "".join(errs)))
check("the variables used are red, green and yellow", used == {"--accent-red", "--accent-green", "--accent-yellow"}, str(used))
root = re.search(r"^:root\s*\{(.*?)^\}", css, re.S | re.M)
root_body = root.group(1) if root else ""
check("every one of them is defined in the :root block, so all themes have it",
      all(re.search(re.escape(v) + r"\s*:", root_body) for v in used), str(used))
check("no theme block removes one of them (a value of 'unset' or 'initial')",
      not re.search(r"--accent-(red|green|yellow)\s*:\s*(unset|initial|inherit)", css))

if failures:
    print(f"\ntest_admin_status_colours: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_admin_status_colours: all checks passed")
