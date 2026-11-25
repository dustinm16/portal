"""The chat page seeds the Mentions-only badge from the channel list after a reload
(unread_mentions per channel, see tests/test_unread_mentions.py for the server side).

loadChannels runs under Node (tests/unread_mentions_harness.js) against a fake fetch. No browser:
how the badge looks is not proven here.

Run: venv/bin/python tests/test_unread_mentions_client.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


if shutil.which("node"):
    proc = subprocess.run(["node", str(ROOT / "tests" / "unread_mentions_harness.js"), str(STATIC / "chat.html"),
                           str(STATIC / "js" / "chat-notify.js")], capture_output=True, text=True, timeout=60)
    rows = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    check("the harness ran", proc.returncode == 0 and len(rows) >= 7, (proc.stdout + proc.stderr)[-500:])
    for r in rows:
        check(r["name"], r["ok"], r["detail"])
else:
    print("skip the Node checks: node is not installed")

if failed:
    print(f"\ntest_unread_mentions_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_unread_mentions_client: all checks passed")
