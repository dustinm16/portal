"""Admin > Settings > Shared web connections (static/js/proxy-trust-admin.js, 1.24.1): the list of members' shared web
connections with Trust and Remove trust, each asking first on its own row, guarded while the request is in flight, built
with textContent. Driven in Node against a fake DOM and a fake Portal.fetch (tests/proxy_trust_admin_harness.js), plus
static checks of admin.html. No browser: layout is not covered. Run: venv/bin/python tests/test_proxy_trust_admin.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    try:
        out = subprocess.run([node, str(ROOT / "tests" / "proxy_trust_admin_harness.js"), str(ROOT / "static" / "js" / "proxy-trust-admin.js")],
                             capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as e:
        out = subprocess.CompletedProcess(e.cmd, 1, "", "the harness did not finish within 60 seconds")
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-600:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

admin = (ROOT / "static" / "admin.html").read_text()
card = admin[admin.index('id="proxy-trust-card"'):admin.index("Certificate Management Card")]
check("admin.html has the card, hidden until the list loads, with no inline handler", 'style="display:none;"' in card and "onclick" not in card)
check("admin.html loads the script with a version", '/static/js/proxy-trust-admin.js?v=1"' in admin)
route = (ROOT / "server.py").read_text()
check("the screen only uses the two existing superadmin routes",
      "/api/admin/proxy-trust-connections" in (ROOT / "static" / "js" / "proxy-trust-admin.js").read_text()
      and "/proxy-trust'" in (ROOT / "static" / "js" / "proxy-trust-admin.js").read_text()
      and 'add_get("/api/admin/proxy-trust-connections"' in route)

if failed:
    print(f"\ntest_proxy_trust_admin: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_proxy_trust_admin: all checks passed")
