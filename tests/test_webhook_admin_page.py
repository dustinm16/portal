"""Admin > Webhooks section of static/admin.html: the tab exists and is hidden until the
superadmin probe answers, every dynamic value is escaped, destinations and credentials
of non-generic hooks are never written into the page, and the page script still parses
under Node (skipped without Node).

Run: venv/bin/python tests/test_webhook_admin_page.py
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "static" / "admin.html").read_text()
failures = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


m = re.search(r"// System webhooks \(superadmin only\).*?// Initialize\n", html, re.S)
js = m.group(0) if m else ""
check("webhook section script found", len(js) > 2000)
check("tab button is hidden until probed",
      'id="tab-btn-webhooks" style="display:none;"' in html and "probeWebhooksTab" in html
      and "document.getElementById('tab-btn-webhooks').style.display = ''" in js)
check("tab content and loader wired into showTab",
      'id="tab-webhooks"' in html and "case 'webhooks': loadSystemWebhooks(); break;" in html)
check("only admin routes are used (system hooks have their own)", "'/api/webhooks" not in js and "`/api/webhooks" not in js and "/api/admin/webhooks" in js)
tpl_values = re.findall(r"\$\{([^}]*)\}", js)
raw = [v for v in tpl_values if not (v.startswith("escapeHtml(") or v.startswith("Number(") or "?" in v or v in
                                     ("inputCss", "evBoxes", "id", "checked", "isEdit ? 'Edit' : 'New'", "isEdit ? 'Save' : 'Create'")
                                     or v.startswith(("whState", "WH_", "status", "fails", "flags", "last", "reason", "dest")))]
check("every interpolated value is escaped, numeric or built from escaped parts", not raw, str(raw))
check("a non-generic destination is shown only as the masked host",
      "w.url_host" in js and "(path hidden)" in js and "w.format === 'generic' ? (w.url || '')" in js)
check("the stored token is never put back into a field", "format_config" in js and "has_format_secret" in js
      and "q('wh-token').value = " not in js)
check("a new hook starts with no events selected, not '*'",
      "url: '', events: [], enabled: 1" in js and "events: ['*']" not in js)
check("the form says '*' leaves out the presence events in third-party formats",
      "user.connected or user.disconnected" in js)
check("a plain sentence under the format select warns what a generic hook receives",
      re.search(r'id="wh-format".*?</select>\s*<div[^>]*>A generic hook receives full event payloads, including the text of messages in private channels, so point it only at a receiver you control\.</div>', js, re.S) is not None)
check("no inline onclick for data in the section", "onclick" not in js)
check("no emoji", not re.search("[\U0001F000-\U0001FFFF☀-➿]", js))
node = shutil.which("node")
if node:
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write("\n".join(scripts))
    r = subprocess.run([node, "--check", f.name], capture_output=True, text=True)
    check("page script parses under node", r.returncode == 0, r.stderr[-300:])
else:
    print("skip: node not available")
sys.exit(1 if failures else 0)
