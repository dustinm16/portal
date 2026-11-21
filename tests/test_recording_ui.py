"""The recording banner and the Recordings tab, checked on the page sources (no browser).

Run: venv/bin/python tests/test_recording_ui.py

The banner is shown only from the server's connected frame, hidden on every new connection and
on close; the tab and the modal use no inline handlers; the player takes no input; the page
policy is not loosened and the WebAssembly player is not vendored.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


term_js = (ROOT / "static/js/terminal.js").read_text()
term_html = (ROOT / "static/terminal.html").read_text()
admin_js = (ROOT / "static/js/recordings-admin.js").read_text()
admin_html = (ROOT / "static/admin.html").read_text()
server_py = (ROOT / "server.py").read_text()

check("terminal.html has a hidden 'This session is recorded' banner",
      re.search(r'<div id="recording-banner"[^>]*role="status"[^>]*hidden>This session is recorded</div>', term_html) is not None)
check("the banner is shown only when the connected frame says recording is true",
      re.search(r"case 'connected':.*?if \(data\.recording === true\) \{\s*setRecordingBanner\(true\)", term_js, re.S) is not None)
check("the banner is hidden at every connect and on close",
      re.search(r"function connect\(\) \{\s*updateStatus\('connecting', 'Connecting\.\.\.'\);\s*setRecordingBanner\(false\)", term_js)
      and re.search(r"ws\.onclose = \(event\) => \{\s*updateStatus\('disconnected', 'Disconnected'\);\s*setRecordingBanner\(false\)", term_js))
check("terminal.html loads terminal.js v7", "terminal.js?v=7" in term_html)

check("the tab button, its content and the modal exist in admin.html",
      all(x in admin_html for x in ('id="tab-btn-recordings"', 'id="tab-recordings"', 'id="rec-modal"',
                                    "/static/js/recordings-admin.js?v=1")))
section = admin_html.split('<!-- Recordings Tab', 1)[1].split('<!-- Webhooks Tab', 1)[0]
check("the new tab markup has no inline handlers", not re.search(r"\son[a-z]+\s*=", section), "")
check("the new tab button has no inline handler", 'id="tab-btn-recordings" data-recordings-tab style="display:none;">' in admin_html)
check("the audit filter lists the three recording actions",
      all(f'value="{a}"' in admin_html for a in ("recording_play", "recording_download", "recording_delete")))
check("the player script builds rows with textContent, never innerHTML", "innerHTML" not in admin_js)
check("the player attaches no input handler and turns stdin off",
      "onData" not in admin_js and "disableStdin: true" in admin_js)
check("rows carry data attributes and one delegated listener", "dataset.action" in admin_js and "closest('button[data-action]')" in admin_js)
check("delete asks first", "confirm(" in admin_js)

csp = re.search(r'"script-src ([^"]*)"', server_py).group(1)
check("the page policy still has no wasm-unsafe-eval or unsafe-eval", "wasm-unsafe-eval" not in csp and "unsafe-eval" not in csp, csp)
check("no asciinema-player is vendored", not list((ROOT / "static").rglob("*asciinema*")))

_api = (ROOT / "static/api-docs.html").read_text()
_api_sec = _api.split("<!-- Session Recordings -->", 1)[1].split("<!-- Security Events -->", 1)[0]
check("the API reference's recordings section has no inline handlers", not re.search(r"\son[a-z]+\s*=", _api_sec))
check("its headers are bound by one listener", "data-endpoint-toggle" in _api_sec and "[data-endpoint-toggle]" in _api)
import collections  # noqa: E402
_defs = collections.Counter(re.findall(r"^(?:async )?def (\w+)", server_py, re.M))
check("no function of server.py is defined twice (a later def silently replaces an earlier one)",
      [n for n, k in _defs.items() if k > 1] == [], str([n for n, k in _defs.items() if k > 1]))

if failures:
    print(f"\ntest_recording_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_recording_ui: all checks passed")
