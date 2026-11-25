"""The sign-out routes have a per-account throttle (1.24.2).

DELETE /api/me/sessions/{id}, POST /api/me/sessions/revoke-others and POST /api/users/{id}/sessions/revoke
share one allowance of 30 calls a minute per signed-in account (the acting account for the admin route). The
31st answers 429 with a reference ID and Retry-After, through the shared limiter and _limited; it blocks
nothing and another account is not affected. A normal sign-out of one session still works.

Run: venv/bin/python tests/test_session_revoke_limit.py   (90 second deadline)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aiohttp  # noqa: E402
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

LIMIT = 30


async def main():
    env = await h.boot(names=("owner", "bob", "carol"), superadmin=("owner",))
    base = env.base
    bob, owner, carol = env.sessions["bob"], env.sessions["owner"], env.sessions["carol"]

    # a second session of bob, listed under its public id
    async with aiohttp.ClientSession() as anon:
        async with anon.post(base + "/api/token", json={"username": "bob", "password": h.PW}) as r:
            tok = (await r.json())["token"]
    async with bob.get(base + "/api/me/sessions") as r:
        listing = await r.json()
    rows = listing.get("sessions", listing) if isinstance(listing, dict) else listing
    other = next((x for x in rows if not x.get("current")), None)
    check("bob has a second session to sign out", other is not None, str(listing)[:200])

    async with bob.delete(base + f"/api/me/sessions/{other['id']}") as r:
        await r.read()
        check("a normal sign-out of one session still works", r.status == 200, str(r.status))
    async with aiohttp.ClientSession() as anon:
        async with anon.get(base + "/api/me", headers={"Authorization": f"Bearer {tok}"}) as r:
            check("... and that session is gone", r.status == 401, str(r.status))

    statuses = []
    for _ in range(LIMIT - 1):
        async with bob.post(base + "/api/me/sessions/revoke-others", json={}) as r:
            await r.read()
            statuses.append(r.status)
    check("29 more sign-out calls (30 in all) are answered normally", statuses == [200] * (LIMIT - 1), str(set(statuses)))
    async with bob.post(base + "/api/me/sessions/revoke-others", json={}) as r:
        body = await r.json()
        check("the 31st answers 429 with a reference ID and Retry-After",
              r.status == 429 and "ref" in body and r.headers.get("Retry-After"), f"{r.status} {body} {dict(r.headers)}")
    async with bob.delete(base + "/api/me/sessions/does-not-exist") as r:
        await r.read()
        check("the allowance is shared by the single-session route", r.status == 429, str(r.status))
    async with bob.get(base + "/api/me") as r:
        check("a 429 blocks nothing: bob is still signed in", r.status == 200, str(r.status))
    async with carol.post(base + "/api/me/sessions/revoke-others", json={}) as r:
        await r.read()
        check("another account is not limited by bob's calls", r.status == 200, str(r.status))

    owner_id = env.uid["owner"]
    statuses = []
    for _ in range(LIMIT):
        async with owner.post(base + f"/api/users/{owner_id}/sessions/revoke", json={}) as r:
            await r.read()
            statuses.append(r.status)
    check("the admin route answers its first 30 calls", statuses == [200] * LIMIT, str(set(statuses)))
    async with owner.post(base + f"/api/users/{env.uid['carol']}/sessions/revoke", json={}) as r:
        body = await r.json()
        check("the 31st admin call answers 429 (keyed by the acting admin, not the target)",
              r.status == 429 and "ref" in body, f"{r.status} {body}")
    async with owner.get(base + "/api/me") as r:
        check("the admin is still signed in", r.status == 200, str(r.status))
    await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), 90))
h.finish("test_session_revoke_limit")
