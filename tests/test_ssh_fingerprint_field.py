"""The ssh plugin's form lists a host-key fingerprint field an admin can pre-fill (1.24.2, item 21).

The accept route and the API could already pin a key; the admin service form had no field for it. The schema now
lists host_key_fingerprint (a public fingerprint, not a secret), and an admin service save with a value that is not
a fingerprint is refused with 400 instead of being dropped silently.

Run: venv/bin/python tests/test_ssh_fingerprint_field.py   (60 second deadline)
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import connection_secrets as cs  # noqa: E402
import hostkeys  # noqa: E402
import plugins  # noqa: E402

FP = "SHA256:" + "A" * 43
HOST = "93.184.216.34"


async def main():
    plugins.load_builtin_plugins()
    props = plugins.get_all_plugins()["ssh"].info.config_schema["properties"]
    prop = props.get("host_key_fingerprint")
    check("the ssh schema lists host_key_fingerprint as a string", isinstance(prop, dict) and prop.get("type") == "string", str(prop))
    check("it is not write-only and not a listed secret",
          bool(prop) and prop.get("writeOnly") is not True and "host_key_fingerprint" not in cs.SECRET_KEYS)
    check("it is the key the host-key code reads", hostkeys.FINGERPRINT_KEY == "host_key_fingerprint")

    env = await h.boot()
    db, adm = env.db, env.sessions["adm"]

    async def post(body):
        async with adm.post(f"{env.base}/api/services", json=body) as r:
            return r.status, await r.json()

    async def put(sid, body):
        async with adm.put(f"{env.base}/api/services/{sid}", json=body) as r:
            return r.status, await r.json()

    base = {"name": "ssh box", "path": "/ssh-box", "plugin": "ssh", "host": HOST, "port": 22}
    st, _ = await post({**base, "config": {"username": "u", "host_key_fingerprint": "not-a-fingerprint"}})
    check("creating with a malformed fingerprint is refused", st == 400, str(st))
    check("nothing was created", not [s for s in await db.get_all_services() if s["path"] == "/ssh-box"])

    st, body = await post({**base, "config": {"username": "u", "host_key_fingerprint": "sha256:" + "A" * 43 + "="}})
    check("creating with a valid fingerprint works", st in (200, 201), f"{st} {body}")
    sid = (await db.get_service_by_path("/ssh-box"))["id"] if hasattr(db, "get_service_by_path") else None
    if sid is None:
        sid = [s for s in await db.get_all_services() if s["path"] == "/ssh-box"][0]["id"]
    check("the pin is stored in canonical form", (await db.get_service_by_id(sid))["config"].get("host_key_fingerprint") == FP)

    st, _ = await put(sid, {"config": {"username": "u", "host_key_fingerprint": "SHA256:short"}})
    check("saving a malformed fingerprint is refused", st == 400, str(st))
    check("the stored pin is unchanged", (await db.get_service_by_id(sid))["config"].get("host_key_fingerprint") == FP)

    st, _ = await put(sid, {"config": {"username": "v", "host_key_fingerprint": FP}})
    check("saving the same fingerprint again works", st == 200 and (await db.get_service_by_id(sid))["config"].get("username") == "v", str(st))
    st, _ = await put(sid, {"config": {"username": "v"}})
    check("saving without the field keeps the pin", st == 200 and (await db.get_service_by_id(sid))["config"].get("host_key_fingerprint") == FP, str(st))

    # the edit form sends the stored pin back with every save: moving the service must still drop the old host's pin
    st, _ = await put(sid, {"host": "93.184.216.35", "config": {"username": "v", "host_key_fingerprint": FP}})
    check("moving the host with the stored pin sent back drops the pin",
          st == 200 and "host_key_fingerprint" not in (await db.get_service_by_id(sid))["config"], str((await db.get_service_by_id(sid))["config"]))
    await db.update_service_config_if_target(sid, {"username": "v", "host_key_fingerprint": FP}, "93.184.216.35", 22)
    st, _ = await put(sid, {"config": {"username": "v", "host": "93.184.216.36", "host_key_fingerprint": FP}})
    check("moving the host through the config with the stored pin sent back drops the pin",
          st == 200 and "host_key_fingerprint" not in (await db.get_service_by_id(sid))["config"])
    other = "SHA256:" + "B" * 43
    st, _ = await put(sid, {"host": "93.184.216.37", "config": {"username": "v", "host_key_fingerprint": other}})
    check("moving the host with a different fingerprint typed in pins that one",
          st == 200 and (await db.get_service_by_id(sid))["config"].get("host_key_fingerprint") == other)

    await h.shutdown(env)


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except BaseException as exc:
    print(f"FAIL: the test stopped early ({exc!r})", flush=True)
    os._exit(1)
h.finish("test_ssh_fingerprint_field")
