"""A token shown by GET /api/tokens can be revoked by what the list shows (1.24.2).

The list keeps its truncated "token_id" field and gains "session_id" (the same opaque public id the sessions
page uses). POST /api/token/revoke takes the full token id as before, or that public id; the public id only
reaches the caller's own tokens (another member's, or an administrator reaching for a member's, answers 404).

Run: venv/bin/python tests/test_token_list_revoke.py   (90 second deadline)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aiohttp  # noqa: E402
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402
from session_devices import public_session_id  # noqa: E402


async def make_token(base, name):
    async with aiohttp.ClientSession() as anon:
        async with anon.post(base + "/api/token", json={"username": name, "password": h.PW}) as r:
            body = await r.json()
            assert r.status == 200, body
            return body["token"], body["token_id"]


async def listing(base, jwt):
    async with aiohttp.ClientSession() as anon:
        async with anon.get(base + "/api/tokens", headers={"Authorization": "Bearer " + jwt}) as r:
            return r.status, await r.json()


async def revoke(base, jwt, ident, api_key=False):
    headers = {"X-API-Key": jwt} if api_key else {"Authorization": "Bearer " + jwt}
    async with aiohttp.ClientSession() as anon:
        async with anon.post(base + "/api/token/revoke", json={"token_id": ident}, headers=headers) as r:
            return r.status, await r.json()


async def main():
    env = await h.boot(names=("owner", "bob", "carol"), superadmin=("owner",))
    base, db = env.base, env.db

    jwt, tid = await make_token(base, "bob")
    jwt2, tid2 = await make_token(base, "bob")
    jwt3, tid3 = await make_token(base, "bob")
    st, body = await listing(base, jwt)
    rows = {r["session_id"]: r for r in body.get("tokens", []) if "session_id" in r}
    check("the list carries session_id for every token", st == 200 and len(rows) == len(body.get("tokens", [])) >= 3, f"{st} {body}")
    check("... equal to the public id of the token", public_session_id(tid2) in rows)
    shown = rows.get(public_session_id(tid2), {})
    check("... and keeps the truncated token_id field as it was", shown.get("token_id") == tid2[:8] + "...", str(shown))

    st, body = await revoke(base, jwt, shown.get("session_id", "none"))
    check("revoking by the shown session_id answers 200", st == 200 and body.get("status") == "revoked", f"{st} {body}")
    check("... and the token is gone", await db.get_token(tid2) is None)
    check("... while the other tokens stay", await db.get_token(tid) is not None and await db.get_token(tid3) is not None)
    st, body = await revoke(base, jwt, public_session_id(tid2))
    check("a second try answers 404", st == 404, f"{st} {body}")

    st, body = await revoke(base, jwt, tid3)
    check("the full token id still works", st == 200 and await db.get_token(tid3) is None, f"{st} {body}")
    st, body = await revoke(base, jwt, "0123456789abcdef")
    check("an unknown id answers 404", st == 404, f"{st} {body}")

    # another member's public id is not reachable, by a member or by an administrator
    cjwt, ctid = await make_token(base, "carol")
    st, body = await revoke(base, jwt, public_session_id(ctid))
    check("a member cannot revoke another member's token by its public id", st == 404 and await db.get_token(ctid) is not None, f"{st} {body}")
    ojwt, _ = await make_token(base, "owner")
    st, body = await revoke(base, ojwt, public_session_id(ctid))
    check("an administrator cannot reach a member's token by its public id either", st == 404 and await db.get_token(ctid) is not None, f"{st} {body}")
    st, body = await revoke(base, ojwt, ctid)
    check("... while the full id keeps working for an administrator", st == 200 and await db.get_token(ctid) is None, f"{st} {body}")

    # a scoped credential cannot end the owner's browser sessions by their public id (it could not before)
    async def make_key(bearer, scopes=None):
        body = {"name": "k" + str(len(scopes or ())) + bearer[-4:]}
        if scopes is not None:
            body["scopes"] = scopes
        async with aiohttp.ClientSession() as anon:
            async with anon.post(base + "/api/api-keys", json=body, headers={"Authorization": "Bearer " + bearer}) as r:
                out = await r.json()
                assert r.status == 201, out
                return out["key"]

    bjwt, btid = await make_token(base, "bob")
    member_key = await make_key(bjwt)
    st, body = await revoke(base, member_key, public_session_id(btid), api_key=True)
    check("a member's default API key cannot revoke a browser session by its public id", st == 404 and await db.get_token(btid) is not None, f"{st} {body}")
    ojwt2, otid = await make_token(base, "owner")
    admin_key = await make_key(ojwt2, ["services:read"])
    st, body = await revoke(base, admin_key, public_session_id(otid), api_key=True)
    check("an administrator's services:read key cannot either", st == 404 and await db.get_token(otid) is not None, f"{st} {body}")
    st, body = await revoke(base, bjwt, public_session_id(btid))
    check("... while the browser session itself still can", st == 200 and await db.get_token(btid) is None, f"{st} {body}")
    await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), 90))
h.finish("test_token_list_revoke")
