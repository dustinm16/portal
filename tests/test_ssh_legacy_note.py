"""An older SSH row with a stored password and no credential_mode says so in its edit form (1.24.2, item 123).

Such a row shows "Prompt each time" on (the terminal does ask), which hid that a password is stored (the file
browser may use it). The form now shows a note under the switch for exactly that row, and for no other.

Run: venv/bin/python tests/test_ssh_legacy_note.py
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


note = re.search(r'<[a-z]+ [^>]*id="connection-ssh-legacy-note"[^>]*>', index)
check("index.html has the note, hidden to begin with", note is not None and "display: none" in note.group(0), str(note))
check("the note sits inside the prompt switch's group",
      re.search(r'id="connection-ssh-prompt-group".*?id="connection-ssh-legacy-note"', index, re.S) is not None
      and index.index('id="connection-ssh-legacy-note"') < index.index('id="connection-ssh-stored-group"'))

m = re.search(r"async function editConnection\(.*?\n}\n", js, re.S)
check("editConnection is present", m is not None)
if m:
    script = """
const els = new Proxy({}, { get(t, id) {
  if (!(id in t)) t[id] = { value: '', checked: false, placeholder: '', textContent: '', dataset: {}, style: {}, classList: { add() {}, remove() {} } };
  return t[id];
} });
global.document = { getElementById: (id) => els[id], querySelector: () => null, querySelectorAll: () => [] };
let conns = {};
global.Portal = { fetch: async (url) => ({ ok: true, json: async () => conns[url.split('/').pop()] }), toast() {} };
global.connectionTypeSchemas = { x: 1 };
global.onConnectionTypeChange = () => {};
global.onSSHAuthChange = () => {};
global.populateDynamicConfigFields = () => {};
global.showModal = () => {};
global.fillConnectionMaintenance = () => {};
""" + m.group(0) + """
const base = { name: 'a', type: 'ssh', host: 'h', port: 22 };
conns.legacy = { ...base, id: 'legacy', config: { username: 'u', auth_method: 'password', has_stored_password: true } };
conns.stored = { ...base, id: 'stored', config: { username: 'u', auth_method: 'password', has_stored_password: true, credential_mode: 'stored' } };
conns.prompt = { ...base, id: 'prompt', config: { username: 'u', auth_method: 'password', credential_mode: 'prompt' } };
conns.plain = { ...base, id: 'plain', config: { username: 'u', auth_method: 'password' } };
conns.db = { id: 'db', name: 'b', type: 'database', host: 'h', port: 3306, config: { db_type: 'mysql' } };
(async () => {
  const note = els['connection-ssh-legacy-note'];
  const out = {};
  for (const id of ['legacy', 'stored', 'legacy', 'prompt', 'legacy', 'plain', 'legacy', 'db']) {
    await editConnection(id);
    out[id] = out[id] || [];
    out[id].push({ shown: note.style.display, text: note.textContent });
  }
  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran editConnection", bool(got), r.stderr[-300:])
    legacy = got.get("legacy") or [{}]
    check("a mode-less row with a stored password shows the note, every time it is opened",
          all(x.get("shown") == "block" for x in legacy) and "password is stored" in legacy[0].get("text", ""), str(legacy))
    for other in ("stored", "prompt", "plain", "db"):
        check(f"a {other} row does not show it (and opening it after a legacy row hides it again)",
              all(x.get("shown") == "none" for x in got.get(other, [{}])), str(got.get(other)))
    check("the note says the terminal still asks", "still asks" in legacy[0].get("text", ""), str(legacy[0]))

if failures:
    print(f"\ntest_ssh_legacy_note: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_ssh_legacy_note: all checks passed")
