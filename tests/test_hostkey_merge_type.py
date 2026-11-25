"""merge_user_connection_host_key only pins a key on an ssh or sftp connection (the types the accept route allows).

Run: venv/bin/python tests/test_hostkey_merge_type.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402
import hostkeys  # noqa: E402
import sftp_browser  # noqa: E402

DEADLINE = 90
FP = "SHA256:" + "A" * 43


async def main():
    env = await h.boot()
    db = env.db
    uid = env.uid["owner"]
    check("the SQL type list is the route's list", set(sftp_browser.SFTP_ELIGIBLE_TYPES) == {"ssh", "sftp"})
    try:
        async def merge(typ, port=22):
            cfg = {"username": "u", "host_key_refused": "SHA256:" + "B" * 43}
            u = await db.create_user_connection(uid, f"hk-{typ}", typ, "93.184.216.34", port, json.dumps(cfg))
            row = await db.get_user_connection_by_uuid(u, uid)
            ok = await db.merge_user_connection_host_key(
                row["id"], uid, FP, "93.184.216.34", port, hostkeys.FINGERPRINT_KEY, hostkeys.REFUSED_KEY)
            return ok, (await db.get_user_connection_by_uuid(u, uid))["config"]

        ok, c = await merge("vnc", 5900)
        check("a vnc connection is refused", ok is False, str(ok))
        check("a vnc connection is left as it was",
              hostkeys.FINGERPRINT_KEY not in c and hostkeys.REFUSED_KEY in c, str(c))
        ok, c = await merge("rdp", 3389)
        check("an rdp connection is refused and unchanged", ok is False and hostkeys.FINGERPRINT_KEY not in c, f"{ok} {c}")
        for typ in ("ssh", "sftp"):
            ok, c = await merge(typ)
            check(f"a {typ} connection is pinned", ok is True and c.get(hostkeys.FINGERPRINT_KEY) == FP
                  and hostkeys.REFUSED_KEY not in c, f"{ok} {c}")
    finally:
        await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), DEADLINE))
h.finish("test_hostkey_merge_type")
