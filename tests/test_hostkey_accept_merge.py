"""Accepting a host key merges only the pin keys into the connection's current config.

An edit made while the accept prompt was open (mode set to prompt, a cleared password, a new
username) used to be overwritten by the accept, which wrote back the config it had read before,
so the old password came back. Run: venv/bin/python tests/test_hostkey_accept_merge.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import hostkeys  # noqa: E402

FP = "SHA256:" + "A" * 43
OLD_PW = "old-stored-secret"


async def main():
    env = await h.boot()
    db, owner = env.db, env.sessions["owner"]
    uid = env.uid["owner"]
    cfg = {"username": "u", "auth_method": "password", "password": OLD_PW, "credential_mode": "stored",
           "host_key_refused": "SHA256:" + "B" * 43, "shell": "/bin/bash"}
    uuid = await db.create_user_connection(uid, "pin", "ssh", "93.184.216.34", 22, json.dumps(cfg))
    cid = (await db.get_user_connection_by_uuid(uuid, uid))["id"]

    async def stored():
        return (await db.get_user_connection_by_uuid(uuid, uid))["config"]

    # The accept token and the prompt bookkeeping are not what is tested here.
    async def fake_read(request):
        return {}, FP, None

    real_read, real_prompt = server._read_accept_request, server._check_accepted_prompt
    server._read_accept_request = fake_read

    # ---- an edit lands between the handler's read and its write ---------------------------------------
    async def edit_between():
        await db.update_user_connection(cid, uid, config={"username": "renamed", "auth_method": "password",
                                                           "credential_mode": "prompt", "shell": "/bin/zsh"})

    # The concurrent edit lands right after the handler read the connection and before it writes the
    # pin: the read is wrapped so that the edit follows it (the handler keeps the stale read).
    real_get = db.get_user_connection_by_uuid
    armed = {"on": True}

    async def get_then_edit(*a, **k):
        row = await real_get(*a, **k)
        if armed["on"]:
            armed["on"] = False
            await edit_between()
        return row
    server._check_accepted_prompt = lambda *a, **k: None
    db.get_user_connection_by_uuid = get_then_edit
    async with owner.post(f"{env.base}/api/connections/{uuid}/host-key/accept", json={}) as r:
        status = r.status
    db.get_user_connection_by_uuid = real_get
    c = await stored()
    check("the accept answers 200", status == 200, str(status))
    check("the pin is stored", c.get(hostkeys.FINGERPRINT_KEY) == FP, str(c))
    check("the refused marker is gone", hostkeys.REFUSED_KEY not in c, str(c))
    check("the concurrent edit survived: mode prompt, new username, new shell",
          c.get("credential_mode") == "prompt" and c.get("username") == "renamed" and c.get("shell") == "/bin/zsh", str(c))
    check("the password the edit removed did not come back", "password" not in c, str(c))

    # ---- an edit between the merge's own read and write: compare and set retries ---------------------------
    await db.update_user_connection(cid, uid, config=dict(cfg))
    orig_execute = db.conn.execute
    state = {"armed": True, "updates": 0}

    def execute(sql, params=()):
        if state["armed"] and sql.lstrip().startswith("UPDATE user_connections SET config = ?"):
            state["armed"] = False

            async def run():
                await edit_between()            # somebody writes after the merge read the row
                state["updates"] += 1
                return await orig_execute(sql, params)
            return run()
        return orig_execute(sql, params)
    db.conn.execute = execute
    try:
        ok = await db.merge_user_connection_host_key(cid, uid, FP, "93.184.216.34", 22,
                                                     hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY)
    finally:
        db.conn.execute = orig_execute
    c = await stored()
    check("a write between the merge's read and its update is not overwritten: the merge retries on the new config",
          ok and c.get(hostkeys.FINGERPRINT_KEY) == FP and c.get("credential_mode") == "prompt"
          and "password" not in c and c.get("username") == "renamed", f"{ok} {c}")

    # ---- the target moved: nothing is written ----------------------------------------------------------------
    await db.update_user_connection(cid, uid, config=dict(cfg), host="93.184.216.99")
    ok = await db.merge_user_connection_host_key(cid, uid, FP, "93.184.216.34", 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY)
    c = await stored()
    check("a host change refuses the accept and writes nothing", not ok and hostkeys.FINGERPRINT_KEY not in c and c.get("password") == OLD_PW, str(c))
    ok = await db.merge_user_connection_host_key(999999, uid, FP, "x", 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY)
    check("a connection that is gone is refused", not ok)
    ok = await db.merge_user_connection_host_key(cid, env.uid["bob"], FP, "93.184.216.99", 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY)
    check("another user's connection is refused", not ok)

    server._read_accept_request, server._check_accepted_prompt = real_read, real_prompt
    await h.shutdown(env)


asyncio.run(main())
h.finish("test_hostkey_accept_merge")
