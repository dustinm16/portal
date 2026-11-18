"""Revoking one session, or an API key, ends what was opened with that
credential (sockets, in-flight proxied calls) and nothing else.

Run: venv/bin/python tests/test_revocation.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiohttp import web  # noqa: E402

import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeWs:
    def __init__(self):
        self.closed = False
        self.code = None

    async def close(self, code=1000, message=b""):
        self.closed = True
        self.code = code


class FakeTransport:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True


class FakeRequest:
    def __init__(self, data=None, match=None):
        self._data = data
        self.match_info = match or {}
        self.transport = FakeTransport()

    async def json(self):
        return self._data


class Caller:
    def __init__(self, user_id, token_id="caller-session", scopes=("admin",)):
        self.user_id = user_id
        self.token_id = token_id
        self.scopes = list(scopes)

    def has_scope(self, scope):
        return scope in self.scopes or "*" in self.scopes


OWNER, ADMIN = 31, 32


def opened(user_id, token_id):
    """A socket and a proxied call opened with token_id."""
    ws = FakeWs()
    call = server._ProxyHttpCall(FakeRequest())
    server._register_user_ws(user_id, ws, token_id)
    server._register_user_proxy_call(user_id, call, token_id)
    return ws, call


def reset():
    server._user_websockets.clear()
    server._user_proxy_calls.clear()


async def run():
    state = {"caller": None, "tokens": {}, "revoked": [], "key_ok": True}

    async def fake_auth(request):
        return state["caller"]

    async def fake_role(token):
        return "admin" if token.user_id == ADMIN else "user"

    async def fake_get_token(token_id):
        return state["tokens"].get(token_id)

    async def fake_get_user(user_id):
        return {"id": user_id, "username": f"u{user_id}", "role": "user"}

    async def fake_revoke(token_id, user_id=None):
        t = state["tokens"].get(token_id)
        if not t or (user_id is not None and t["user_id"] != user_id):
            return False
        state["revoked"].append(token_id)
        return True

    async def fake_audit(*a, **k):
        return None

    async def fake_revoke_key(key_id, user_id):
        return state["key_ok"]

    saved = (server.authenticate_request, server.get_user_role_from_token, server.db.get_token,
             server.db.get_user_by_id, server.revoke_token, server.audit_log,
             server.db.revoke_api_key, server.db.delete_api_key)
    server.authenticate_request = fake_auth
    server.get_user_role_from_token = fake_role
    server.db.get_token = fake_get_token
    server.db.get_user_by_id = fake_get_user
    server.revoke_token = fake_revoke
    server.audit_log = fake_audit
    server.db.revoke_api_key = fake_revoke_key
    server.db.delete_api_key = fake_revoke_key
    try:
        # --- a member signs out one of their sessions
        reset()
        state["tokens"] = {"sess-1": {"user_id": OWNER}, "sess-2": {"user_id": OWNER}}
        state["caller"] = Caller(OWNER, "sess-2", scopes=("services:read", "access:*"))
        ws1, call1 = opened(OWNER, "sess-1")
        ws2, call2 = opened(OWNER, "sess-2")
        wsk, callk = opened(OWNER, "apikey-7")
        r = await server.http_revoke_token(FakeRequest({"token_id": "sess-1"}))
        check("revoke token: the answer is 'revoked'", json.loads(r.body)["status"] == "revoked")
        check("revoke token: the socket of that session is closed (code 4001) and its proxied call aborted",
              ws1.closed and ws1.code == 4001 and call1.aborted and call1.request.transport.aborted)
        check("revoke token: the member's other session and an API key keep their socket and call",
              not ws2.closed and not call2.aborted and not wsk.closed and not callk.aborted)

        # --- an admin revokes another member's session
        reset()
        state["tokens"] = {"sess-1": {"user_id": OWNER}, "sess-2": {"user_id": OWNER}}
        state["caller"] = Caller(ADMIN, "admin-sess")
        ws1, call1 = opened(OWNER, "sess-1")
        ws2, call2 = opened(OWNER, "sess-2")
        wsa, calla = opened(ADMIN, "sess-1")        # the admin's own, same token id text: other user
        r = await server.http_revoke_token(FakeRequest({"token_id": "sess-1"}))
        check("admin revokes a member's session: that session's socket and call end",
              ws1.closed and call1.aborted)
        check("admin revokes a member's session: the member's other session and the admin's own are untouched",
              not ws2.closed and not call2.aborted and not wsa.closed and not calla.aborted)

        # --- a token that was not revoked closes nothing
        reset()
        state["caller"] = Caller(OWNER, "sess-2", scopes=("services:read", "access:*"))
        ws1, call1 = opened(OWNER, "sess-1")
        r = await server.http_revoke_token(FakeRequest({"token_id": "nope"}))
        check("revoke token: an unknown token answers 404 and closes nothing",
              r.status == 404 and not ws1.closed and not call1.aborted)

        # --- API keys
        for label, handler in (("revoke", server.http_revoke_api_key), ("delete", server.http_delete_api_key)):
            reset()
            state["key_ok"] = True
            state["caller"] = Caller(OWNER, "sess-2")
            wk, ck = opened(OWNER, "apikey-7")
            wother, cother = opened(OWNER, "apikey-70")
            ws2, call2 = opened(OWNER, "sess-2")
            await handler(FakeRequest(match={"id": "7"}))
            check(f"API key {label}: sockets and calls opened with that key end",
                  wk.closed and ck.aborted)
            check(f"API key {label}: another key (apikey-70) and the member's session are untouched",
                  not wother.closed and not cother.aborted and not ws2.closed and not call2.aborted)
            reset()
            state["key_ok"] = False
            wk, ck = opened(OWNER, "apikey-7")
            r = await handler(FakeRequest(match={"id": "7"}))
            check(f"API key {label}: a key that does not exist (404) closes nothing",
                  r.status == 404 and not wk.closed and not ck.aborted)
    finally:
        (server.authenticate_request, server.get_user_role_from_token, server.db.get_token,
         server.db.get_user_by_id, server.revoke_token, server.audit_log,
         server.db.revoke_api_key, server.db.delete_api_key) = saved
        reset()


asyncio.run(run())
if failures:
    print(f"test_revocation: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("test_revocation: all checks passed")
