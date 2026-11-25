"""A stored password of an SFTP connection can be removed from the form (1.24.2, item 122).

The SFTP form sent no credential_mode unless a password was typed, so only the API could clear a stored
SFTP password. The form now has a "Remove stored password" box (SFTP only, only where a password is stored)
that sends credential_mode "prompt"; the server clears the password for that, as for ssh.

Checked here: the page has the box, collectSSHCredential run under node with a fake document, the box is
shown by onSSHAuthChange only for SFTP with a stored password, and the API clears an SFTP password for
credential_mode prompt.

Run: venv/bin/python tests/test_sftp_clear_password.py   (60 second deadline)
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
index = (ROOT / "static" / "index.html").read_text()
js = (ROOT / "static" / "js" / "user-connections.js").read_text()

check("index.html has the checkbox", re.search(r'<input type="checkbox" id="connection-sftp-clear-password"[^>]*>', index) is not None)
check("the checkbox has no inline handler", "onclick" not in (re.search(r'<input type="checkbox" id="connection-sftp-clear-password"[^>]*>', index) or [""])[0])
check("the box sits in the form group the script shows and hides", 'id="connection-sftp-clear-group"' in index)

m = re.search(r"function collectSSHCredential\(.*?\n}\n", js, re.S)
check("collectSSHCredential is present", m is not None)
if m:
    script = """
const els = {};
global.document = { getElementById: (id) => els[id] };
global.Portal = { toast() {} };
""" + m.group(0) + """
function setup(auth, pw, clear) {
  els['connection-ssh-auth'] = { value: auth };
  els['connection-ssh-prompt'] = { checked: true };
  els['connection-ssh-stored-password'] = { value: pw };
  if (clear === undefined) delete els['connection-sftp-clear-password'];
  else els['connection-sftp-clear-password'] = { checked: clear };
}
const out = {};
setup('password', '', true);        out.boxChecked = collectSSHCredential('sftp', true, true);
setup('password', 'typed', true);   out.boxAndTyped = collectSSHCredential('sftp', true, true);
setup('password', '', false);       out.boxOff = collectSSHCredential('sftp', true, true);
setup('password', 'typed', false);  out.typed = collectSSHCredential('sftp', true, true);
setup('password', '', undefined);   out.noBox = collectSSHCredential('sftp', true, true);
setup('password', '', true);        out.sshIgnoresBox = collectSSHCredential('ssh', false, false);
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), r.stderr[-300:])
    check("an SFTP form with the box checked sends credential_mode prompt", got.get("boxChecked") == {"credential_mode": "prompt"}, str(got.get("boxChecked")))
    check("the box wins over a password typed in the same form", got.get("boxAndTyped") == {"credential_mode": "prompt"}, str(got.get("boxAndTyped")))
    check("with the box off an SFTP form behaves as before", got.get("boxOff") == {} and got.get("noBox") == {}
          and got.get("typed") == {"credential_mode": "stored", "password": "typed"}, str(got))
    check("an ssh form is not changed by the box", got.get("sshIgnoresBox") == {"credential_mode": "prompt"})

m = re.search(r"function onSSHAuthChange\(.*?\n}\n", js, re.S)
check("onSSHAuthChange is present", m is not None)
if m:
    script = """
const els = new Proxy({}, { get(t, id) {
  if (!(id in t)) t[id] = { value: '', checked: false, dataset: {}, style: {} };
  return t[id];
} });
global.document = { getElementById: (id) => els[id] };
global.connectionRecordingAllowed = () => false;
""" + m.group(0) + """
function shown(type, auth, had) {
  els['connection-type'].value = type;
  els['connection-ssh-auth'].value = auth;
  els['connection-ssh-stored-password'].dataset.hadStored = had;
  onSSHAuthChange();
  return els['connection-sftp-clear-group'].style.display;
}
console.log(JSON.stringify({
  sftpStored: shown('sftp', 'password', '1'), sftpNone: shown('sftp', 'password', ''),
  sftpKey: shown('sftp', 'key', '1'), sshStored: shown('ssh', 'password', '1') }));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran onSSHAuthChange", bool(got), r.stderr[-300:])
    check("the box is shown for SFTP with a stored password only",
          got.get("sftpStored") == "block" and got.get("sftpNone") == "none" and got.get("sftpKey") == "none" and got.get("sshStored") == "none", str(got))

check("opening the form for a new or an edited connection resets the box",
      len(re.findall(r"\b(?:sftpClearBox|clearReset)\.checked = false", js)) == 2)


async def main():
    env = await h.boot()
    db, owner = env.db, env.sessions["owner"]
    cfg = {"username": "u", "auth_method": "password", "password": "stored-secret", "credential_mode": "stored"}
    uuid = await db.create_user_connection(env.uid["owner"], "files", "sftp", "93.184.216.34", 22, json.dumps(cfg))
    async with owner.put(f"{env.base}/api/connections/{uuid}", json={"config": {"credential_mode": "prompt"}}) as r:
        status, body = r.status, await r.json()
    stored = (await db.get_user_connection_by_uuid(uuid, env.uid["owner"]))["config"]
    check("credential_mode prompt on an SFTP connection clears the password and says so",
          status == 200 and "password" not in stored and stored.get("credential_mode") == "prompt" and body.get("stored_password_cleared") is True,
          f"{status} {stored} {body}")
    await h.shutdown(env)


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except BaseException as exc:
    print(f"FAIL: the test stopped early ({exc!r})", flush=True)
    os._exit(1)
h.finish("test_sftp_clear_password")
