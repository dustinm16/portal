"""GET /api/me tells a service grantee when each grant ends (1.24.2, item 134, server side).

granted_services keeps its shape ({service id: [actions]}); the new granted_service_expiry carries
{service id: seconds left, or null for a grant that never ends} for the same services.

Run: venv/bin/python tests/test_granted_service_expiry.py   (60 second deadline)
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402


async def main():
    env = await h.boot()
    db, bob = env.db, env.sessions["bob"]
    timed = await db.create_service("timed", "/timed", plugin="mediamtx", service_type="managed")
    forever = await db.create_service("forever", "/forever", plugin="mediamtx", service_type="managed")
    other = await db.create_service("other", "/other", plugin="mediamtx", service_type="managed")
    await db.add_service_grant(timed, env.uid["bob"], ["control"], env.uid["adm"], "1h")
    await db.add_service_grant(forever, env.uid["bob"], ["logs", "files"], env.uid["adm"], "never")

    async def me(session):
        async with session.get(f"{env.base}/api/me") as r:
            return r.status, await r.json()

    st, body = await me(bob)
    check("/api/me answers 200", st == 200, str(st))
    check("granted_services keeps its shape",
          body.get("granted_services") == {str(timed): ["control"], str(forever): ["files", "logs"]} or
          {k: sorted(v) for k, v in body.get("granted_services", {}).items()} == {str(timed): ["control"], str(forever): ["files", "logs"]},
          str(body.get("granted_services")))
    exp = body.get("granted_service_expiry")
    check("the expiry map names exactly the granted services", isinstance(exp, dict) and set(exp) == {str(timed), str(forever)}, str(exp))
    check("a grant of one hour carries about 3600 seconds", isinstance(exp, dict) and isinstance(exp.get(str(timed)), int)
          and 3500 <= exp[str(timed)] <= 3600, str(exp))
    check("a grant that never ends carries null", isinstance(exp, dict) and str(forever) in exp and exp[str(forever)] is None, str(exp))

    st, body = await me(env.sessions["carol"])
    check("a member with no grants gets empty maps", body.get("granted_services") == {} and body.get("granted_service_expiry") == {}, str(body.get("granted_service_expiry")))
    st, body = await me(env.sessions["adm"])
    check("an administrator gets empty maps (no grant is needed)", body.get("granted_services") == {} and body.get("granted_service_expiry") == {})

    await db.conn.execute("UPDATE service_grants SET expires_at = '2000-01-01 00:00:00' WHERE service_id = ?", (timed,))
    await db.conn.commit()
    st, body = await me(bob)
    check("a grant whose time has passed is in neither map", set(body.get("granted_services", {})) == {str(forever)}
          and set(body.get("granted_service_expiry", {})) == {str(forever)}, str(body.get("granted_service_expiry")))
    await h.shutdown(env)


try:
    asyncio.run(asyncio.wait_for(main(), 60))
except BaseException as exc:
    print(f"FAIL: the test stopped early ({exc!r})", flush=True)
    os._exit(1)
h.finish("test_granted_service_expiry")
