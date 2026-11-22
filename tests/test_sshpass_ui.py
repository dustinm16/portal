"""The SSH connection form and the share dialog for a stored password (source checks, and the
credential collection function run under node with a fake document; no browser).

Run: venv/bin/python tests/test_sshpass_ui.py
"""

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


for ident in ("connection-ssh-stored-password", "connection-ssh-prompt", "share-stored-password-warning"):
    check(f"index.html has #{ident}", f'id="{ident}"' in index)
check("the prompt switch is on by default", re.search(r'id="connection-ssh-prompt"[^>]*\bchecked\b', index) is not None)
check("the form says the grantee gets a shell without knowing the password",
      index.count("without knowing the password") >= 2)
check("the stored password input is a password field the browser does not fill",
      re.search(r'<input type="password" id="connection-ssh-stored-password" autocomplete="new-password"', index) is not None)
check("the script version in index.html was bumped", "user-connections.js?v=57" in index)
check("the edit form records the switch state it opened with and passes it on",
      "pwField.dataset.initialPrompt = " in js and "collectSSHCredential(type, isEdit, pwFieldNow.dataset.hadStored === '1', initialPrompt)" in js)
check("the edit form reads has_stored_password and never puts a value in the field", "config.has_stored_password" in js and "pwField.value = '';" in js)
check("the share dialog warns for any connection that holds a password and does not prompt", "share-stored-password-warning" in js and "credential_mode !== 'prompt'" in js)

# Run collectSSHCredential with a fake document.
m = re.search(r"function collectSSHCredential\(.*?\n}\n", js, re.S)
check("collectSSHCredential is present", m is not None)
if m:
    script = """
const els = {};
const toasts = [];
global.document = { getElementById: (id) => els[id] };
global.Portal = { toast: (m, t) => toasts.push([m, t]) };
""" + m.group(0) + """
function setup(auth, prompt, pw) {
  els['connection-ssh-auth'] = { value: auth };
  els['connection-ssh-prompt'] = { checked: prompt };
  els['connection-ssh-stored-password'] = { value: pw };
}
const out = {};
setup('password', true, 'typed');   out.prompt = collectSSHCredential('ssh', false, false);
setup('password', false, 'typed');  out.stored = collectSSHCredential('ssh', false, false);
setup('password', false, '');       out.missing = collectSSHCredential('ssh', false, false);
setup('password', false, '');       out.keep = collectSSHCredential('ssh', true, true);
setup('key', false, 'typed');       out.key = collectSSHCredential('ssh', false, false);
setup('password', true, '');        out.sftpEmpty = collectSSHCredential('sftp', false, false);
setup('password', true, 'typed');   out.sftp = collectSSHCredential('sftp', false, false);
// edit form: initialPrompt is the switch as the form opened it
setup('password', true, '');        out.renameOlder = collectSSHCredential('ssh', true, true, true);
setup('password', true, 'typed');   out.renameTyped = collectSSHCredential('ssh', true, true, true);
setup('password', false, '');       out.renameStored = collectSSHCredential('ssh', true, true, false);
setup('password', false, 'new');    out.replaceStored = collectSSHCredential('ssh', true, true, false);
setup('password', true, 'typed');   out.hiddenTyped = collectSSHCredential('ssh', true, false, true);
setup('password', true, '');        out.turnedOn = collectSSHCredential('ssh', true, true, false);
setup('password', false, '');       out.turnedOff = collectSSHCredential('ssh', true, true, true);
setup('password', true, 'typed');   out.addNew = collectSSHCredential('ssh', false, false, undefined);
out.toasts = toasts.length;
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    import json
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), r.stderr[-300:])
    check("Prompt each time sends the mode prompt and no password", got.get("prompt") == {"credential_mode": "prompt"})
    check("a typed password sends mode stored and the password", got.get("stored") == {"credential_mode": "stored", "password": "typed"})
    check("stored with nothing typed on a new connection is refused with a message",
          got.get("missing") is None and got.get("toasts") == 1)
    check("stored with nothing typed on an edit of a stored connection keeps the password",
          got.get("keep") == {"credential_mode": "stored"})
    check("an edit that leaves the switch alone sends no credential_mode (a rename of an older row keeps its password)",
          got.get("renameOlder") == {} and got.get("renameStored") == {} and got.get("renameTyped") == {}
          and got.get("replaceStored") == {"password": "new"})
    check("a password left in the hidden field with the switch on is never sent",
          got.get("renameTyped") == {} and got.get("hiddenTyped") == {})
    check("turning the switch on clears the stored-password field",
          "if (!isSftp && prompt.checked)" in js and "connection-ssh-stored-password').value = ''" in js)
    check("an edit that turns the switch on sends prompt, off sends stored",
          got.get("turnedOn") == {"credential_mode": "prompt"} and got.get("turnedOff") == {"credential_mode": "stored"})
    check("a new connection is unchanged by this", got.get("addNew") == {"credential_mode": "prompt"})
    check("key authentication sends prompt (the server drops any stored password)", got.get("key") == {"credential_mode": "prompt"})
    check("an SFTP connection sends the password only when one was typed",
          got.get("sftpEmpty") == {} and got.get("sftp") == {"credential_mode": "stored", "password": "typed"})

# editConnection resets the SSH credential state for every row type, so an SSH row opened before
# cannot leave its mode, "had a password" flag or typed password behind for the next row.
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
conns.ssh = { id: 'ssh', name: 'a', type: 'ssh', host: 'h', port: 22,
              config: { username: 'u', auth_method: 'password', has_stored_password: true, credential_mode: 'stored' } };
conns.db = { id: 'db', name: 'b', type: 'database', host: 'h', port: 3306, config: { db_type: 'mysql' } };
conns.old = { id: 'old', name: 'c', type: 'ssh', host: 'h', port: 22, config: { username: 'u', auth_method: 'password', has_stored_password: true } };
(async () => {
  const pw = els['connection-ssh-stored-password'], sw = els['connection-ssh-prompt'];
  const out = {};
  await editConnection('ssh');
  out.ssh = { had: pw.dataset.hadStored, initial: pw.dataset.initialPrompt, prompt: sw.checked, ph: pw.placeholder };
  pw.value = 'typed-by-hand';
  await editConnection('db');
  out.db = { had: pw.dataset.hadStored, initial: pw.dataset.initialPrompt === undefined ? 'undefined' : pw.dataset.initialPrompt,
             prompt: sw.checked, ph: pw.placeholder, value: pw.value };
  await editConnection('old');
  out.old = { had: pw.dataset.hadStored, initial: pw.dataset.initialPrompt, prompt: sw.checked };
  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    import json
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran editConnection", bool(got), r.stderr[-300:])
    check("a stored SSH row opens with the switch off and its state recorded",
          got.get("ssh", {}).get("had") == "1" and got["ssh"].get("initial") == "0" and got["ssh"].get("prompt") is False, str(got.get("ssh")))
    check("opening a non-SSH row after it leaves no SSH credential state behind",
          got.get("db") == {"had": "", "initial": "undefined", "prompt": True, "ph": "", "value": ""}, str(got.get("db")))
    check("a mode-less older SSH row opens with the switch on", got.get("old", {}).get("initial") == "1" and got["old"].get("prompt") is True, str(got.get("old")))

if failures:
    print(f"\ntest_sshpass_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_sshpass_ui: all checks passed")
