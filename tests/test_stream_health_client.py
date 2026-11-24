"""Client checks of the stream health panel (static/js/stream-health.js) and the administrator's live list
(static/js/live-ops-admin.js): both load as separate classic scripts after the real portal.js in one Node vm
context, driven against a fake DOM and a fake fetch. Also static checks of the pages that load them.
No browser: layout, real timers, real SVG rendering and a real server are not covered.

Run: venv/bin/python tests/test_stream_health_client.py
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
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
        out = subprocess.run([node, str(ROOT / "tests" / "stream_health_client_harness.js"), str(STATIC / "js" / "portal.js"),
                              str(STATIC / "js" / "stream-health.js"), str(STATIC / "js" / "live-ops-admin.js")],
                             capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired as e:
        out = subprocess.CompletedProcess(e.cmd, 1, "", "the harness did not finish within 90 seconds")
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-600:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

watch = (STATIC / "watch.html").read_text(encoding="utf-8")
admin = (STATIC / "admin.html").read_text(encoding="utf-8")
check("watch.html loads stream-health.js after portal.js", "/static/js/stream-health.js?v=3" in watch
      and watch.index("/static/js/portal.js") < watch.index("/static/js/stream-health.js"))
check("the health button is hidden until the page decides", 'id="health-btn" style="display: none;"' in watch
      and "Number(streamData.user_id) === Number(currentUser.id)" in watch and "Portal.isAdmin(currentUser)" in watch)
check("admin.html has the Live streams tab and loads live-ops-admin.js", 'id="tab-btn-livestreams"' in admin
      and 'id="tab-livestreams"' in admin and "/static/js/live-ops-admin.js?v=3" in admin)
check("the question row wraps inside the table: a scoped rule gives its cell normal white-space",
      re.search(r"#live-ops-body \.live-ops-confirm-row\s*>\s*td\s*\{[^}]*white-space:\s*normal", admin) is not None)
for name in ("stream-health.js", "live-ops-admin.js"):
    src = (STATIC / "js" / name).read_text(encoding="utf-8")
    check(f"{name} has no innerHTML, no inline handler and no emoji", "innerHTML" not in src and "onclick" not in src.lower()
          and not re.search(r"[\U0001F000-\U0001FFFF☀-➿←-⇿]", src))
settings = (STATIC / "js" / "streams.js").read_text(encoding="utf-8")
check("the stream settings link to the health panel", "#health" in settings and "stream-health-link" in settings)

if failed:
    print(f"\ntest_stream_health_client: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_stream_health_client: all checks passed")
