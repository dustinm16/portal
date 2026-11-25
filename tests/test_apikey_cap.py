"""A member can hold at most 50 live API keys (1.24.2).

Live means not revoked and not expired. The 51st creation answers 400; revoking (or letting one expire) allows
a new one; a member who is already above the cap keeps every key, only creation is refused. Real app on a
loopback test server (tests/grant_harness.py); the keys below the cap are inserted directly with a fake hash.

Run: venv/bin/python tests/test_apikey_cap.py   (90 second deadline)
"""

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

CAP = 50


async def main():
    env = await h.boot(names=("owner", "bob", "carol"), superadmin=("owner",))
    base, db = env.base, env.db
    bob = env.sessions["bob"]
    uid = env.uid["bob"]
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    ids = []
    for i in range(CAP - 2):
        ids.append(await db.create_api_key(user_id=uid, name=f"k{i}", key_hash="x", key_prefix="portal_aa"))
    # one revoked and one expired key do not count
    dead = await db.create_api_key(user_id=uid, name="dead", key_hash="x", key_prefix="portal_aa")
    await db.revoke_api_key(dead, uid)
    await db.create_api_key(user_id=uid, name="old", key_hash="x", key_prefix="portal_aa", expires_at=past)

    async def live_count():
        now = datetime.now(timezone.utc).isoformat()
        return len([k for k in await db.get_user_api_keys(uid)
                    if not k["revoked"] and (not k["expires_at"] or k["expires_at"] >= now)])

    async def create(name, session=bob):
        async with session.post(base + "/api/api-keys", json={"name": name}) as r:
            return r.status, await r.json()

    st, body = await create("n49")
    check("with 48 live keys (and a revoked and an expired one) the 49th is created", st == 201, f"{st} {body}")
    st, body = await create("n50")
    check("... and the 50th", st == 201, f"{st} {body}")
    key50 = body.get("id")
    st, body = await create("n51")
    check("the 51st answers 400 and says why", st == 400 and "50" in body.get("error", ""), f"{st} {body}")
    check("... and nothing was stored: still exactly 50 live keys", await live_count() == CAP, str(await live_count()))
    names = {k["name"] for k in await db.get_user_api_keys(uid)}
    check("... the refused key is not in the list", "n51" not in names)
    st, body = await create("carol-key", env.sessions["carol"])
    check("another member's cap is separate", st == 201, f"{st} {body}")
    st, _ = await create("n51b")
    check("still 400 on a second try", st == 400)
    async with bob.post(base + f"/api/api-keys/{key50}/revoke") as r:
        await r.read()
        check("revoking one key answers 200", r.status == 200, str(r.status))
    st, body = await create("n51c")
    check("... and then a new key can be created", st == 201, f"{st} {body}")
    st, body = await create("n52")
    check("... and the cap holds again", st == 400, f"{st} {body}")

    # an existing member above the cap keeps every key
    for i in range(3):
        await db.create_api_key(user_id=uid, name=f"over{i}", key_hash="x", key_prefix="portal_bb")
    before = await live_count()
    st, _ = await create("n53")
    after = await live_count()
    check("above the cap: creation is refused and no key is removed", st == 400 and before == after and before > CAP, f"{st} {before} {after}")
    await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), 90))
h.finish("test_apikey_cap")
