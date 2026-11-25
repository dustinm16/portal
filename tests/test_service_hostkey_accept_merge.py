"""Accepting the host key of an SSH service merges only the pin keys into the service's current config (1.24.2).

The accept route used to read the whole service config, add the fingerprint and write it all back, so a config
edit made while the prompt was open (another key changed, a key removed) was overwritten. Now the pin keys are
merged into the config as it is stored when the write happens (compare and set, retried when somebody wrote in
between), still only while the service points at the host and port the prompt showed.

Run: venv/bin/python tests/test_service_hostkey_accept_merge.py   (90 second deadline)
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import hostkeys  # noqa: E402

FP = "SHA256:" + "A" * 43
HOST = "93.184.216.34"


async def main():
    env = await h.boot()
    db, adm = env.db, env.sessions["adm"]
    cfg = {"username": "svc", "shell": "/bin/bash", "keepalive": 30, hostkeys.REFUSED_KEY: {"fingerprint": "SHA256:" + "B" * 43}}
    sid = await db.create_service("ssh box", "/ssh-box", plugin="ssh", host=HOST, port=22, config=dict(cfg))

    async def stored():
        return (await db.get_service_by_id(sid))["config"]

    async def fake_read(request):
        return {}, FP, None
    real_read, real_prompt = server._read_accept_request, server._check_accepted_prompt
    server._read_accept_request = fake_read
    server._check_accepted_prompt = lambda *a, **k: None

    # an edit lands right after the handler read the service and before it writes the pin
    real_get = db.get_service_by_id
    armed = {"on": True}

    async def get_then_edit(service_id):
        row = await real_get(service_id)
        if armed["on"]:
            armed["on"] = False
            await db.update_service_config_if_target(
                service_id, {"username": "renamed", "shell": "/bin/zsh", "newkey": "x", hostkeys.REFUSED_KEY: {"fingerprint": "SHA256:" + "B" * 43}},
                HOST, 22)
        return row
    db.get_service_by_id = get_then_edit
    async with adm.post(f"{env.base}/api/services/{sid}/host-key/accept", json={}) as r:
        status, body = r.status, await r.json()
    db.get_service_by_id = real_get
    c = await stored()
    check("the accept answers 200", status == 200 and body.get("fingerprint") == FP, f"{status} {body}")
    check("the pin is stored and the refused marker gone", c.get(hostkeys.FINGERPRINT_KEY) == FP and hostkeys.REFUSED_KEY not in c, str(c))
    check("the concurrent edit survived: new username, shell and key",
          c.get("username") == "renamed" and c.get("shell") == "/bin/zsh" and c.get("newkey") == "x", str(c))
    check("a key the edit removed did not come back", "keepalive" not in c, str(c))

    # an edit between the merge's own read and its write: compare and set retries on the new config
    await db.update_service_config_if_target(sid, dict(cfg), HOST, 22)
    orig_execute = db.conn.execute
    state = {"armed": True}

    def execute(sql, params=()):
        if state["armed"] and sql.lstrip().startswith("UPDATE services SET config = ?"):
            state["armed"] = False

            async def run():
                await db.update_service_config_if_target(sid, {"username": "late", "extra": 1}, HOST, 22)
                return await orig_execute(sql, params)
            return run()
        return orig_execute(sql, params)
    db.conn.execute = execute
    try:
        ok = await db.merge_service_host_key(sid, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 22))
    finally:
        db.conn.execute = orig_execute
    c = await stored()
    check("a write between the merge's read and its update is not overwritten",
          ok and c.get(hostkeys.FINGERPRINT_KEY) == FP and c.get("username") == "late" and c.get("extra") == 1, f"{ok} {c}")

    # a moved target, a missing service and a service of another plugin are refused and nothing is written
    await db.update_service_config_if_target(sid, dict(cfg), HOST, 22)
    ok = await db.merge_service_host_key(sid, FP, "93.184.216.99", 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, ("93.184.216.99", 22))
    check("a different host is refused and nothing is written", not ok and hostkeys.FINGERPRINT_KEY not in await stored())
    ok = await db.merge_service_host_key(sid, FP, HOST, 2222, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 2222))
    check("a different port is refused", not ok)
    ok = await db.merge_service_host_key(999999, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 22))
    check("a service that is gone is refused", not ok)
    other = await db.create_service("web", "/web", plugin="http", host=HOST, port=22, config={"a": 1})
    ok = await db.merge_service_host_key(other, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 22))
    check("a service of another plugin is refused and unchanged", not ok and (await real_get(other))["config"] == {"a": 1})
    # the ssh plugin dials config host/port over the columns: a config whose target moved while the prompt was open
    await db.update_service_config_if_target(sid, {**cfg, "host": "10.0.0.1"}, HOST, 22)
    await db.update_service_config_if_target(sid, {**cfg, "host": "10.0.0.2"}, HOST, 22)
    ok = await db.merge_service_host_key(sid, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, ("10.0.0.1", 22))
    check("a config host that changed since the prompt is refused and nothing is written",
          not ok and hostkeys.FINGERPRINT_KEY not in await stored(), str(await stored()))
    await db.update_service_config_if_target(sid, {**cfg, "port": "2200"}, HOST, 22)
    ok = await db.merge_service_host_key(sid, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 22))
    check("a config port that changed since the prompt is refused", not ok and hostkeys.FINGERPRINT_KEY not in await stored())
    await db.update_service_config_if_target(sid, {**cfg, "host": "10.0.0.1"}, HOST, 22)
    ok = await db.merge_service_host_key(sid, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, ("10.0.0.1", 22))
    check("a config host override that is still the prompt's target is pinned", ok and (await stored()).get(hostkeys.FINGERPRINT_KEY) == FP)
    await db.update_service_config_if_target(sid, dict(cfg), HOST, 22)
    ok = await db.merge_service_host_key(sid, FP, HOST, 22, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY, (HOST, 22))
    check("the plain accept still works", ok and (await stored()).get(hostkeys.FINGERPRINT_KEY) == FP)

    server._read_accept_request, server._check_accepted_prompt = real_read, real_prompt
    await h.shutdown(env)


try:
    asyncio.run(asyncio.wait_for(main(), 90))
except BaseException as exc:      # a crash or the deadline prints FAIL and ends, it does not hang on the open server
    print(f"FAIL: the test stopped early ({exc!r})", flush=True)
    os._exit(1)
h.finish("test_service_hostkey_accept_merge")
