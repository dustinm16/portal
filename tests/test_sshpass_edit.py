"""Editing an older ssh connection that holds a password and has no credential_mode.

The server reports stored_password_cleared whenever it removes a stored password, also when the
owner asked for it (Prompt each time, or an empty password); a rename that sends no
credential_mode keeps the password. (The form's part, not sending credential_mode unless the
switch was changed, is checked in tests/test_sshpass_ui.py.)

Run: venv/bin/python tests/test_sshpass_edit.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

SSH_PW = "old-stored-secret"


async def main():
    env = await h.boot()
    db, owner = env.db, env.sessions["owner"]

    async def new_row(name, config):
        uuid = await db.create_user_connection(env.uid["owner"], name, "ssh", "93.184.216.34", 22, json.dumps(config))
        return uuid

    async def stored(uuid):
        return (await db.get_user_connection_by_uuid(uuid, env.uid["owner"]))["config"]

    async def put(uuid, body):
        async with owner.put(f"{env.base}/api/connections/{uuid}", json=body) as r:
            return r.status, await r.json()

    old = {"username": "u", "auth_method": "password", "password": SSH_PW}      # no credential_mode: an older row

    u = await new_row("older", old)
    st, body = await put(u, {"name": "older-renamed", "config": {"username": "u", "auth_method": "password"}})
    c = await stored(u)
    check("a rename that sends no credential_mode keeps the password of an older row",
          st == 200 and c.get("password") == SSH_PW and "credential_mode" not in c and "stored_password_cleared" not in body,
          f"{st} {c} {body}")

    st, body = await put(u, {"config": {"credential_mode": "prompt"}})
    c = await stored(u)
    check("choosing Prompt each time removes the password and the answer says so",
          st == 200 and "password" not in c and c.get("credential_mode") == "prompt" and body.get("stored_password_cleared") is True,
          f"{st} {c} {body}")

    st, body = await put(u, {"config": {"credential_mode": "prompt"}})
    check("Prompt each time on a row with no password says nothing was cleared", st == 200 and "stored_password_cleared" not in body, str(body))

    u2 = await new_row("older2", dict(old, credential_mode="stored"))
    st, body = await put(u2, {"config": {"password": ""}})
    c = await stored(u2)
    check("an explicit empty password removes it and the answer says so",
          st == 200 and "password" not in c and body.get("stored_password_cleared") is True, f"{st} {c} {body}")

    u3 = await new_row("older3", dict(old, credential_mode="stored"))
    st, body = await put(u3, {"config": {"password": "new-secret"}})
    c = await stored(u3)
    check("replacing the password is not a removal", st == 200 and c.get("password") == "new-secret" and "stored_password_cleared" not in body, f"{c} {body}")

    u4 = await new_row("older4", dict(old, credential_mode="stored"))
    st, body = await put(u4, {"config": {"username": "other"}})
    check("a changed username still reports the clear", body.get("stored_password_cleared") is True, str(body))

    await h.shutdown(env)


asyncio.run(main())
h.finish("test_sshpass_edit")
