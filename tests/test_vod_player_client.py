"""The VOD player (static/js/vod-player.js) under Node against a small fake DOM, a fake Portal.fetch and a
fake hls.js (tests/vod_player_harness.js): whole-session mode loads the playlist, then hls.js with a long
segment timeout and many retries, natively on Safari; the resume position is per session; a 415 (from the
playlist or a segment), a 409, a fatal error after three restarts, no hls.js and a native error all fall back
to chunk by chunk; the default stays the single chunk. No browser: real hls.js, real playback, seeking and
the layout are not proven.

Run: venv/bin/python tests/test_vod_player_client.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


JS = ROOT / "static" / "js" / "vod-player.js"
if shutil.which("node") is None:
    check("node is installed (needed to run the client harness)", False)
else:
    syn = subprocess.run(["node", "--check", str(JS)], capture_output=True, text=True, timeout=60)
    check("vod-player.js passes a syntax check", syn.returncode == 0, syn.stderr[:300])
    proc = subprocess.run(["node", str(ROOT / "tests" / "vod_player_harness.js"), str(JS)],
                          capture_output=True, text=True, timeout=60)
    got = [json.loads(l[7:]) for l in proc.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran and reported checks", len(got) >= 20, proc.stdout[-300:] + proc.stderr[-300:])
    for r in got:
        check(r["name"], r["ok"], r["detail"])

html = (ROOT / "static" / "vod-player.html").read_text()
check("the page loads the same hls.js file and host as the live page",
      "https://cdn.jsdelivr.net/npm/hls.js@1.5.17" in html and "https://cdn.jsdelivr.net/npm/hls.js@1.5.17" in (ROOT / "static" / "live.html").read_text())
check("hls.js is loaded before the player script", html.index("hls.js@1.5.17") < html.index("/static/js/vod-player.js?v="))
check("the player page has no inline handler", "onclick" not in html.split("<nav")[0] + html.split("</nav>")[1])

if failed:
    print(f"\ntest_vod_player_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_vod_player_client: all checks passed")
