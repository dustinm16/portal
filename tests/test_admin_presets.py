"""The admin service presets of static/js/admin.js (1.24.2, item 30).

A preset that uses the vnc plugin speaks the VNC protocol, whose port is 5900 (the user connection form says
the same). The 'rdp-server' preset ("Desktop (VNC protocol)") had 3389, the port of Microsoft's RDP.

Run: venv/bin/python tests/test_admin_presets.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def presets(text):
    start = text.index("const SERVICE_PRESETS = {")
    end = text.index("\n};", start)
    body = text[start:end]
    heads = list(re.finditer(r"^    '([^']+)': \{", body, re.M))
    out = {}
    for i, m in enumerate(heads):
        chunk = body[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(body)]
        plugin = re.search(r"^\s+plugin: '([^']+)'", chunk, re.M)
        port = re.search(r"^\s+port: (\d+)", chunk, re.M)
        out[m.group(1)] = (plugin.group(1) if plugin else None, int(port.group(1)) if port else None)
    return out


found = presets((ROOT / "static/js/admin.js").read_text())
check("the preset list was read", len(found) > 8 and "vnc-server" in found, str(len(found)))
vnc = {k: v for k, v in found.items() if v[0] == "vnc"}
check("there are vnc presets, including the desktop one", {"vnc-server", "rdp-server"} <= set(vnc), str(sorted(vnc)))
for key, (_plugin, port) in sorted(vnc.items()):
    check(f"the {key} preset uses the VNC port 5900", port == 5900, str(port))

if failures:
    print(f"\ntest_admin_presets: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_admin_presets: all checks passed")
