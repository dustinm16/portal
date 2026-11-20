"""A socket whose credential is revoked while it is still connecting is closed
with code 4001, on every handler that registers sockets for revocation.

Run: venv/bin/python tests/test_ws_revoked_during_upgrade.py

A real aiohttp server runs the handlers against a temporary database. The
revocation is made to land in the window the handlers await in, after
authentication and before the socket is registered; without the re-check after
registration the client would stay connected.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import server  # noqa: E402
from auth import TokenPayload  # noqa: E402
from database import Database  # noqa: E402


async def scenario(path, handler, revoke_during_upgrade):
    """Returns (close_code or None, messages seen) for a client that connects to path."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "t.db"))
        await d.connect()
        uid = await d.create_user("wsuser1", "x")
        state = {"revoked": False}
        real_prepare = web.WebSocketResponse.prepare

        async def prepare(self, request):
            result = await real_prepare(self, request)
            if revoke_during_upgrade and not state["revoked"]:
                # the logout lands here: the upgrade is done, the socket is not registered yet
                state["revoked"] = True
                await server.close_user_websockets(uid, only_token_id="sess-1")
            return result

        async def is_token_valid(token_id):
            return not state["revoked"]

        async def auth(request):
            return TokenPayload({"sub": str(uid), "jti": "sess-1", "scopes": ["*"], "iat": 0})

        saved = (server.db, server.authenticate_request, server.check_rate_limit)
        d.is_token_valid = is_token_valid
        server.db, server.authenticate_request = d, auth
        web.WebSocketResponse.prepare = prepare
        server.check_rate_limit = lambda ip: True
        app = web.Application()
        app.router.add_get(path, handler)
        srv = TestServer(app)
        await srv.start_server()
        seen = []
        code = None
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.ws_connect(srv.make_url(path)) as ws:
                    try:
                        while True:
                            msg = await asyncio.wait_for(ws.receive(), 3)
                            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                                code = ws.close_code
                                break
                            seen.append(msg.data)
                            if len(seen) >= 1 and not revoke_during_upgrade:
                                break
                    except asyncio.TimeoutError:
                        pass
            # the registry must not keep the socket
            await asyncio.sleep(0.1)
            leftover = dict(server._user_websockets.get(uid, {}))
        finally:
            await srv.close()
            server.db, server.authenticate_request, server.check_rate_limit = saved
            web.WebSocketResponse.prepare = real_prepare
            await d.close()
        return code, seen, leftover


def test_chat_socket_opened_during_a_revocation_is_closed_with_4001():
    code, seen, leftover = asyncio.run(scenario("/ws/chat", server.handle_chat_websocket, True))
    assert code == 4001, (code, seen)
    assert not leftover


def test_generic_socket_opened_during_a_revocation_is_closed_with_4001():
    code, seen, leftover = asyncio.run(scenario("/ws", server.websocket_handler, True))
    assert code == 4001, (code, seen)
    assert not leftover


def test_sockets_of_a_valid_session_are_kept():
    code, seen, _ = asyncio.run(scenario("/ws/chat", server.handle_chat_websocket, False))
    assert code is None and seen, "a valid session must get its chat socket"
    code, seen, _ = asyncio.run(scenario("/ws", server.websocket_handler, False))
    assert code is None and seen


def test_credential_check_covers_sessions_keys_and_accounts():
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = server.db
            server.db = d
            try:
                uid = await d.create_user("wsuser2", "x")

                def tok(jti, user=uid):
                    return TokenPayload({"sub": str(user), "jti": jti, "scopes": ["*"], "iat": 0})
                assert await server._credential_still_valid(tok("streamkey-1")) is True
                assert await server._credential_still_valid(tok("streamkey-1", user=9999)) is False
                assert await server._credential_still_valid(tok("no-such-session")) is False
                assert await server._credential_still_valid(tok("apikey-12345")) is False
                saved_valid = d.is_token_valid

                async def valid(token_id):
                    return True
                d.is_token_valid = valid
                assert await server._credential_still_valid(tok("sess-x")) is True
                d.is_token_valid = saved_valid
            finally:
                server.db = saved
                await d.close()
    asyncio.run(go())


def test_every_register_site_re_checks_the_credential():
    src = (ROOT / "server.py").read_text()
    import re
    sites = [m.start() for m in re.finditer(r"^\s+_register_user_ws\(", src, re.M)]
    assert len(sites) == 3, "a new handler registers sockets: add the re-check, or this test"

    def rest_of_function(i):
        # from the register call to the end of the enclosing top-level function, so lines added
        # between the two do not move the check out of reach
        m = re.search(r"^(?:async def |def |class |@)", src[i:], re.M)
        return src[i:i + m.start()] if m else src[i:]

    # the proxy relay too: the call registry (call.aborted) is not a substitute, it does not
    # see a revocation that landed before the call was registered
    unchecked = [src[:i].count("\n") + 1 for i in sites if "_credential_still_valid(token)" not in rest_of_function(i)]
    assert not unchecked, f"register sites without a credential re-check, at server.py lines {unchecked}"
    proxy = [i for i in sites if "_unregister_user_proxy_call(" in rest_of_function(i)]
    assert len(proxy) == 1
    body = rest_of_function(proxy[0])
    credential = body.index("_credential_still_valid(token)")
    assert "4001" in body[credential:credential + 250]
    # and the re-check comes before the relay opens its upstream connection
    assert credential < body.index("ws_connect(")


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                traceback.print_exc()
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
