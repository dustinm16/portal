"""A busy Argon2 check on one API key does not hide the other keys with the same prefix (1.24.2).

Two live keys can share the 12-bit prefix. authenticate_api_key checks each candidate; when the check of one
is refused as busy (ApiKeyCheckBusy, 503) the others are still tried, and 503 is answered only when no
candidate verified and at least one was busy. The Argon2 check is a fake keyed by key id; no timing involved.

Run: venv/bin/python tests/test_apikey_busy.py   (30 second deadline)
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


KEY = "portal_ab" + "c" * 40
PFX = KEY[:10]


class FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.touched = []

    async def get_api_keys_by_prefix(self, prefix):
        return list(self.rows)

    async def update_api_key_last_used(self, key_id, ip=None):
        self.touched.append(key_id)


def rec(i, user=10):
    return {"id": i, "user_id": user + i, "key_hash": f"hash-{i}", "key_prefix": PFX, "scopes": "*",
            "revoked": 0, "expires_at": None, "allowed_cidrs": None}


async def main():
    real_db, real_verify = server.db, server._verify_api_key_offloop
    server._verified_api_keys.clear()
    calls = []

    def fake(busy_ids, valid_id):
        async def verify(key_id, api_key, stored_hash):
            calls.append(key_id)
            if key_id in busy_ids:
                raise server.ApiKeyCheckBusy()
            return key_id == valid_id
        return verify

    try:
        # newest first, as the database returns them: id 2 is checked first
        server.db = FakeDB([rec(2), rec(1)])

        server._verify_api_key_offloop = fake({2}, 1)
        calls.clear()
        out = await server.authenticate_api_key(KEY, "198.51.100.7")
        check("first candidate busy, second valid: the second authenticates",
              out is not None and out.token_id == "apikey-1" and calls == [2, 1], f"{out} {calls}")
        server._verified_api_keys.clear()

        server._verify_api_key_offloop = fake({2, 1}, None)
        try:
            await server.authenticate_api_key(KEY, "198.51.100.7")
            check("every candidate busy: 503 (ApiKeyCheckBusy)", False, "answered without raising")
        except server.ApiKeyCheckBusy as e:
            check("every candidate busy: 503 (ApiKeyCheckBusy)", e.status == 503 and "Retry-After" in e.headers)

        server._verify_api_key_offloop = fake({2}, None)
        try:
            out = await server.authenticate_api_key(KEY, "198.51.100.7")
            check("one busy, the other checked and wrong: 503, since the busy one might have been the key", False, str(out))
        except server.ApiKeyCheckBusy:
            check("one busy, the other checked and wrong: 503, since the busy one might have been the key", True)

        server._verify_api_key_offloop = fake(set(), None)
        out = await server.authenticate_api_key(KEY, "198.51.100.7")
        check("none busy, none valid: still None (a wrong key is not a 503)", out is None, str(out))

        server._verify_api_key_offloop = fake(set(), 2)
        calls.clear()
        out = await server.authenticate_api_key(KEY, "198.51.100.7")
        check("first candidate valid: authenticates without checking the second",
              out is not None and out.token_id == "apikey-2" and calls == [2], f"{out} {calls}")
    finally:
        server.db, server._verify_api_key_offloop = real_db, real_verify
        server._verified_api_keys.clear()


asyncio.run(asyncio.wait_for(main(), 30))
if failures:
    print(f"\ntest_apikey_busy: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_apikey_busy: all checks passed")
