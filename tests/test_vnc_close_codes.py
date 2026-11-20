"""Close code 4010 means two things: plugins/vnc.py uses it for "this host speaks RDP" and the
server uses it (GRANT_ENDED_CLOSE_CODE) when a share ends. vnc.html must tell them apart by the
close reason, so a grantee whose share ended is not told that the host speaks RDP.

Run: venv/bin/python tests/test_vnc_close_codes.py
The page function is also run under node when it is installed.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import server  # noqa: E402
from plugins import vnc  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


page = (ROOT / "static" / "vnc.html").read_text()
src = (ROOT / "server.py").read_text()

check("the two uses really share the code", server.GRANT_ENDED_CLOSE_CODE == vnc.CLOSE_RDP_HOST == 4010)
check("every grant-ended close in server.py says 'access ended'",
      len(re.findall(r"code=GRANT_ENDED_CLOSE_CODE, message=b\"access ended\"", src)) == src.count("code=GRANT_ENDED_CLOSE_CODE"))
check("the RDP refusal reason is not 'access ended'", b"access ended" not in vnc.CLOSE_REASONS[vnc.CLOSE_RDP_HOST].lower())
check("vnc.html picks the message by code and reason", "refusalFor(ev.code, ev.reason)" in page)
check("vnc.html has no automatic reconnect", "setTimeout(connect" not in page and "setInterval(connect" not in page)

node = shutil.which("node")
if node:
    m = re.search(r"const REFUSALS = \{.*?\n        function refusalFor\(code, reason\) \{.*?\n        \}\n", page, re.S)
    check("the page's refusal table and function are found", m is not None)
    if m:
        script = m.group(0) + """
const out = [
  refusalFor(4010, 'access ended'), refusalFor(4010, 'Access ended '),
  refusalFor(4010, 'This host speaks RDP, not VNC'), refusalFor(4010, ''), refusalFor(4010, undefined),
  refusalFor(4011, 'This host does not speak VNC'), refusalFor(4011, 'access ended'), refusalFor(1000, ''),
].map(i => i ? i.title : null);
console.log(JSON.stringify(out));
"""
        r = subprocess.run([node, "-e", script], capture_output=True, text=True)
        got = json.loads(r.stdout) if r.returncode == 0 else r.stderr
        want = ["Access ended", "Access ended", "This host speaks RDP, not VNC", "This host speaks RDP, not VNC",
                "This host speaks RDP, not VNC", "This host does not speak VNC", "This host does not speak VNC", None]
        check("4010 with 'access ended' is the access-ended message, any other 4010 stays the RDP refusal", got == want, str(got))
else:
    print("skip: node is not installed, the page function was not run")

if failures:
    print(f"\ntest_vnc_close_codes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_vnc_close_codes: all checks passed")
