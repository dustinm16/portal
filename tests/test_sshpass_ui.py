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
check("the script version in index.html was bumped", "user-connections.js?v=49" in index)
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
    check("key authentication sends prompt (the server drops any stored password)", got.get("key") == {"credential_mode": "prompt"})
    check("an SFTP connection sends the password only when one was typed",
          got.get("sftpEmpty") == {} and got.get("sftp") == {"credential_mode": "stored", "password": "typed"})

if failures:
    print(f"\ntest_sshpass_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_sshpass_ui: all checks passed")
