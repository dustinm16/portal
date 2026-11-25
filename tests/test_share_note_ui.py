"""The share dialog's note on how a web connection is shown to the people it is shared with (1.24.1).

proxy_origin.decide gives "trusted" (no sandbox) to a web connection owned by an administrator that is not
in browser mode, and "isolated" to the rest. The dialog must not tell an administrator that such a
connection runs in a sandbox. showShareConnectionModal runs under node with a fake document (no browser).

Run: venv/bin/python tests/test_share_note_ui.py
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
index = (ROOT / "static" / "index.html").read_text()
js = (ROOT / "static" / "js" / "user-connections.js").read_text()
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


check("index.html has both notes", 'id="share-web-isolation-note"' in index and 'id="share-web-trusted-note"' in index)
m = re.search(r"async function showShareConnectionModal\(.*?\n}\n", js, re.S)
check("showShareConnectionModal is present", m is not None)
if m:
    script = """
const els = {};
const mk = () => ({ style: {}, value: '', textContent: '' });
for (const id of ['share-conn-uuid', 'share-conn-name', 'share-duration', 'share-stored-password-warning',
                  'share-web-isolation-note', 'share-web-trusted-note', 'share-connection-modal']) els[id] = mk();
global.document = { getElementById: (id) => els[id] || null };
global.showModal = () => {};
global.initUserPicker = () => ({ reset: () => {} });
global.loadConnectionShares = async () => {};
global.Portal = { isAdmin: (u) => !!u && (u.is_admin || u.role === 'superadmin' || u.role === 'admin') };
let _sharePicker = null, _shareExisting = new Set();
""" + m.group(0) + """
async function run(user, conn) {
  global.currentUser = user;
  global.userConnections = conn ? [conn] : [];
  els['share-web-isolation-note'].style.display = '';
  els['share-web-trusted-note'].style.display = '';
  await showShareConnectionModal('c1', 'x');
  return { isolated: els['share-web-isolation-note'].style.display, trusted: els['share-web-trusted-note'].style.display };
}
(async () => {
  const out = {};
  out.memberWeb = await run({ role: 'user' }, { id: 'c1', name: 'x', config: {} });
  out.memberBrowser = await run({ role: 'user' }, { id: 'c1', name: 'x', config: { browser_mode: true } });
  out.adminWeb = await run({ role: 'admin' }, { id: 'c1', name: 'x', config: {} });
  out.superWeb = await run({ role: 'superadmin' }, { id: 'c1', name: 'x', config: {} });
  out.adminBrowser = await run({ role: 'admin' }, { id: 'c1', name: 'x', config: { browser_mode: true } });
  out.adminFlag = await run({ role: 'user', is_admin: true }, { id: 'c1', name: 'x', config: {} });
  console.log(JSON.stringify(out));
})();
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        try:
            r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
        except subprocess.TimeoutExpired:
            r = None
    got = json.loads(r.stdout) if r is not None and r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), (r.stderr[-300:] if r is not None else "timeout"))
    sandboxed = {"isolated": "block", "trusted": "none"}
    trusted = {"isolated": "none", "trusted": "block"}
    check("a member sharing a web connection sees the sandbox note only", got.get("memberWeb") == sandboxed, str(got.get("memberWeb")))
    check("anybody sharing a connection in browser mode sees the sandbox note only (it is isolated whoever owns it)",
          got.get("memberBrowser") == sandboxed and got.get("adminBrowser") == sandboxed, str(got))
    check("an administrator sharing a web connection not in browser mode sees the trusted note, not the sandbox claim",
          got.get("adminWeb") == trusted and got.get("superWeb") == trusted and got.get("adminFlag") == trusted, str(got))

if failures:
    print(f"\ntest_share_note_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_share_note_ui: all checks passed")
