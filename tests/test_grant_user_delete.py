"""Deleting an account ends what is open through its shares.

The owner's deletion cascades the shares away; before this, a grantee's open terminal and
the SSH connections and proxied calls opened through those shares kept running. A deleted
grantee's own SSH connections through a share end too.

Run: venv/bin/python tests/test_grant_user_delete.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402


class FakeSsh:
    closed = 0

    def close(self):
        self.closed += 1


async def main():
    env = await h.boot()
    adm = env.sessions["adm"]
    uid = env.uid
    uuid, cid = await h.connection(env, "owner")
    uuid2, cid2 = await h.connection(env, "owner", name="second")
    keep_uuid, keep_cid = await h.connection(env, "carol", name="carols")
    for u in (uuid, uuid2):
        async with env.sessions["owner"].post(f"{env.base}/api/connections/{u}/shares",
                                              json={"usernames": ["bob", "carol"], "expires_in": "30d"}) as r:
            check("share for the delete case", r.status == 200)
    async with env.sessions["carol"].post(f"{env.base}/api/connections/{keep_uuid}/shares",
                                          json={"usernames": ["bob"], "expires_in": "30d"}) as r:
        check("an unrelated share (carol to bob)", r.status == 200)

    ws_bob, first = await h.open_ws(env.sessions["bob"], env.base, uuid)
    check("bob opens the owner's shared terminal", "ready" in first.data)
    ws_bob_keep, _ = await h.open_ws(env.sessions["bob"], env.base, keep_uuid)
    ws_carol, _ = await h.open_ws(env.sessions["carol"], env.base, uuid2)
    ssh_carol, ssh_keep = FakeSsh(), FakeSsh()
    server._register_grant_dependent("conn", cid2, uid["carol"], ssh_carol)
    server._register_grant_dependent("conn", keep_cid, uid["bob"], ssh_keep)

    async with adm.delete(f"{env.base}/api/users/{uid['owner']}") as r:
        check("the superadmin deletes the owner", r.status == 200, str(r.status))
    check("the owner's connections and shares are gone",
          await env.db.list_owned_connection_ids(uid["owner"]) == []
          and (await (await env.db.conn.execute("SELECT COUNT(*) c FROM connection_shares WHERE connection_id IN (?, ?)", (cid, cid2))).fetchone())["c"] == 0)
    check("bob's terminal on the owner's connection is closed with 4010",
          await h.close_code(ws_bob) == server.GRANT_ENDED_CLOSE_CODE)
    check("carol's terminal on the owner's second connection is closed with 4010",
          await h.close_code(ws_carol) == server.GRANT_ENDED_CLOSE_CODE)
    check("the SSH connection carol held through the owner's share is closed", ssh_carol.closed == 1, str(ssh_carol.closed))
    check("a share of somebody else's connection is not touched",
          await h.close_code(ws_bob_keep, 0.5) is None and ssh_keep.closed == 0)

    # ---- the deleted account as a grantee --------------------------------------------------------------
    ssh_bob = FakeSsh()
    server._register_grant_dependent("conn", keep_cid, uid["bob"], ssh_bob)   # opened through carol's share
    async with adm.delete(f"{env.base}/api/users/{uid['bob']}") as r:
        check("the superadmin deletes bob", r.status == 200, str(r.status))
    check("what bob held open through a share is closed with his account", ssh_bob.closed == 1 and ssh_keep.closed == 1,
          f"{ssh_bob.closed} {ssh_keep.closed}")
    check("no dependent of bob is left in the registry", not [k for k in server._grant_dependents if k[2] == uid["bob"]])
    check("his terminal socket is closed", await h.close_code(ws_bob_keep) in (4001, server.GRANT_ENDED_CLOSE_CODE))

    await h.shutdown(env)


asyncio.run(main())
h.finish("test_grant_user_delete")
