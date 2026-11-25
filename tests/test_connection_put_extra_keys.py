"""PUT /api/connections/{id} ignores keys that are not connection fields (1.24.2).

A body with user_id (or conn_id, id, uuid, any unknown key) used to reach the database writer as a keyword that
collided with its own arguments and ended in a 500. Now the keys that are not fields of the table are ignored, not
refused, so a client that reads a connection and writes it back keeps working; the fields in the body are saved.
A body of only such keys changes no field and answers like any body that names no field (200).

Run: venv/bin/python tests/test_connection_put_extra_keys.py   (90 second deadline)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402


async def main():
    env = await h.boot(names=("owner", "bob"), superadmin=())
    base, db = env.base, env.db
    bob = env.sessions["bob"]
    uuid, cid = await h.connection(env, "bob", name="box")

    async def put(body):
        async with bob.put(base + f"/api/connections/{uuid}", json=body) as r:
            return r.status, await r.json()

    async def row():
        return await (await db.conn.execute("SELECT * FROM user_connections WHERE id = ?", (cid,))).fetchone()

    st, body = await put({"user_id": 1, "name": "renamed"})
    check("a body with user_id and a name answers 200", st == 200, f"{st} {body}")
    r = await row()
    check("... the name was saved", r["name"] == "renamed", r["name"])
    check("... and the owner did not change", r["user_id"] == env.uid["bob"], str(r["user_id"]))

    st, body = await put({"conn_id": 99, "id": 5, "uuid": "x", "unknown": 1, "name": "again", "port": 2222})
    r = await row()
    check("conn_id, id, uuid and unknown keys are ignored, the fields saved", st == 200 and r["name"] == "again"
          and r["port"] == 2222 and r["uuid"] == uuid and r["id"] == cid, f"{st} {body}")

    st, body = await put({"user_id": 1})
    check("a body of only user_id answers 200 like a body naming no field", st == 200, f"{st} {body}")
    st2, _ = await put({"unknown": 1})
    check("... as a body of an unknown key does", st2 == st, str(st2))
    r = await row()
    check("... and the fields are as they were", r["name"] == "again" and r["port"] == 2222 and r["user_id"] == env.uid["bob"])
    await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), 90))
h.finish("test_connection_put_extra_keys")
