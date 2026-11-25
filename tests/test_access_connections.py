"""Connection writes need the user's whole authority.

/api/connections create, update, delete, pin, prefs, connect, share and unshare start with
_connection_user_auth: an administrator's key limited to one service or to read access gets 403; a
browser session, an all-scope token or key, and a member's default key (services:read,access:* on a
non-administrator, equal to that member's session) pass. A source guard walks the registered routes.

Run: venv/bin/python tests/test_access_connections.py
"""

import asyncio
import inspect
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# Routes under /api/connections that need no gate here, with the reason
EXEMPT = {
    ("GET", "/api/connections/types"): "static list of types",
    ("GET", "/api/connections"): "read: the caller's own list",
    ("GET", "/api/connections/status"): "read",
    ("GET", "/api/connections/{id}"): "read",
    ("GET", "/api/connections/{id}/shares"): "read",
    ("POST", "/api/connections/{id}/host-key/accept"): "has its own full-scope check and a signed accept token",
}

app = server.create_app()
routes = []
for r in app.router.routes():
    info = r.resource.get_info() if r.resource else {}
    path = info.get("formatter") or info.get("path") or ""
    if path.startswith("/api/connections") and r.method != "HEAD":
        routes.append((r.method, path, r.handler))
check("the guard found the connection routes", len(routes) >= 12, str(len(routes)))
gated = []
for method, path, handler in routes:
    src = inspect.getsource(handler)
    if (method, path) in EXEMPT:
        continue
    gated.append((method, path, handler))
    check(f"{method} {path} starts with _connection_user_auth",
          "_connection_user_auth(" in src and "await authenticate_request(request)" not in src, handler.__name__)
check("every route that is not exempt is a write, a connect or a share route",
      all(m != "GET" or p.endswith("/connect") for m, p, _h in gated), str([(m, p) for m, p, _h in gated if m == "GET"]))
check("the accept route is still gated by its full-scope check",
      "has_full_user_scope(" in inspect.getsource(server.http_accept_connection_host_key))


def tok(scopes, jti):
    return server.TokenPayload({"jti": jti, "sub": "5", "scopes": scopes})


ROLE = {"v": "admin"}


async def fake_user(uid):
    return {"id": uid, "role": ROLE["v"], "is_admin": ROLE["v"] in ("admin", "superadmin")}


async def run_one(handler, method, path, token):
    async def fake_auth(request):
        return token
    real = (server.authenticate_request, server.db)
    server.authenticate_request = fake_auth
    server.db = SimpleNamespace(get_user_by_id=fake_user)
    try:
        req = make_mocked_request(method, path, match_info={"id": "abc", "grantee": "7"})
        try:
            return (await asyncio.wait_for(handler(req), 10)).status
        except Exception:
            return "past-gate"           # got beyond the credential check and failed on the fake database
    finally:
        server.authenticate_request, server.db = real


class FakeWS:
    """Records what a /ws handler sends and the code it closes with."""

    def __init__(self):
        self.closed_with = None
        self.sent = []
        self.closed = False

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self, code=1000, message=b""):
        self.closed_with, self.closed = code, True


async def run_ws(coro_factory, token, found):
    """Close code of a socket handler. found: what the fake database answers for a connection
    lookup (None: no such connection, so a credential that passes the gate ends in 4004)."""
    async def fake_lookup(*a, **k):
        return found

    async def no_service(*a, **k):
        return None
    real = (server.db, server.get_service_for_path)
    server.db = SimpleNamespace(get_user_by_id=fake_user, get_accessible_connection=fake_lookup,
                                get_user_connection=fake_lookup, get_service_by_id=no_service)
    server.get_service_for_path = no_service
    ws = FakeWS()
    try:
        await asyncio.wait_for(coro_factory(ws, token), 10)
    except Exception as e:
        return f"error {type(e).__name__}"
    finally:
        server.db, server.get_service_for_path = real
    return ws.closed_with


async def run_sftp(handler, method, path, token):
    async def fake_auth(request):
        return token

    async def no_connection(*a, **k):
        return None
    real = (server.authenticate_request, server.db)
    server.authenticate_request = fake_auth
    server.db = SimpleNamespace(get_user_by_id=fake_user, get_accessible_connection=no_connection)
    try:
        req = make_mocked_request(method, path, match_info={"conn_id": "abc"})
        try:
            return (await asyncio.wait_for(handler(req), 10)).status
        except Exception as e:
            return f"error {type(e).__name__}"
    finally:
        server.authenticate_request, server.db = real


async def run_proxy(handler, method, path, token, upgrade=False):
    """Status of the /proxy handler for one credential. The fake database finds no connection, so a
    credential that passes the gate ends in 404 and nothing is dialled; a refused one is 403."""
    async def fake_auth(request):
        return token

    async def no_connection(*a, **k):
        return None
    real = (server.authenticate_request, server.db)
    server.authenticate_request = fake_auth
    server.db = SimpleNamespace(get_user_by_id=fake_user, get_accessible_connection=no_connection)
    try:
        headers = {"Upgrade": "websocket", "Connection": "Upgrade"} if upgrade else {}
        req = make_mocked_request(method, path, headers=headers, match_info={"conn_id": "abc", "path": ""})
        try:
            return (await asyncio.wait_for(handler(req), 10)).status
        except Exception as e:
            return f"error {type(e).__name__}"
    finally:
        server.authenticate_request, server.db = real


async def main():
    cases = [
        ("admin key limited to one service", ["relay:media"], "apikey-1", "admin", False),
        ("admin key limited to services:read", ["services:read"], "apikey-2", "admin", False),
        ("admin key with only the two member scopes", ["services:read", "access:*"], "apikey-3", "admin", False),
        ("admin key with admin scope only", ["admin"], "apikey-4", "admin", False),
        ("member key with one scope", ["services:read"], "apikey-5", "user", False),
        ("stream key", ["*"], "streamkey-1", "admin", False),
        ("admin all-scope key", ["*"], "apikey-6", "admin", True),
        ("admin browser session", ["*"], "sess1", "admin", True),
        ("member browser session", ["services:read", "access:*"], "sess2", "user", True),
        ("member default key", ["services:read", "access:*"], "apikey-7", "user", True),
        ("moderator default key", ["services:read", "access:*"], "apikey-8", "moderator", True),
    ]
    for label, scopes, jti, role, passes in cases:
        ROLE["v"] = role
        statuses = {}
        for method, path, handler in gated:
            statuses[(method, path)] = await run_one(handler, method, path.replace("{id}", "abc").replace("{grantee}", "7"),
                                                     tok(scopes, jti))
        if passes:
            check(f"{label}: passes the gate on every route", all(v != 403 for v in statuses.values()), str(statuses))
        else:
            check(f"{label}: 403 on every route", all(v == 403 for v in statuses.values()), str(statuses))

        # The routes that USE a connection's stored credentials take the same rule.
        sftp = [(r.method, (r.resource.get_info().get("formatter") or ""), r.handler) for r in app.router.routes()
                if r.resource and (r.resource.get_info().get("formatter") or "").startswith("/api/sftp/{conn_id}/")
                and r.method != "HEAD"]
        if label == cases[0][0]:
            check("the guard found the eight SFTP routes", len(sftp) == 8, str(len(sftp)))
        sftp_status = {}
        for method, path, handler in sftp:
            sftp_status[(method, path)] = await run_sftp(handler, method, path.replace("{conn_id}", "abc"),
                                                         tok(scopes, jti))
        if passes:
            check(f"{label}: passes the gate on every SFTP route (404 from the empty database)",
                  all(v != 403 for v in sftp_status.values()), str(sftp_status))
        else:
            check(f"{label}: 403 on every SFTP route", all(v == 403 for v in sftp_status.values()), str(sftp_status))

        # The reverse proxy sends the connection's stored auth_header and extra_headers upstream.
        proxy = [(r.method, (r.resource.get_info().get("formatter") or ""), r.handler) for r in app.router.routes()
                 if r.resource and (r.resource.get_info().get("formatter") or "").startswith("/proxy/{conn_id}")
                 and r.method != "HEAD"]
        if label == cases[0][0]:
            check("the guard found the two /proxy routes", sorted(p for _m, p, _h in proxy) ==
                  ["/proxy/{conn_id}", "/proxy/{conn_id}/{path}"], str([(m, p) for m, p, _h in proxy]))
        proxy_status = {}
        for method, path, handler in proxy:
            for upgrade in (False, True):
                proxy_status[(method, path, upgrade)] = await run_proxy(
                    handler, "GET", path.replace("{conn_id}", "abc").replace("{path}", ""), tok(scopes, jti), upgrade)
        if passes:
            check(f"{label}: passes the gate on every /proxy route (404 from the empty database)",
                  all(v == 404 for v in proxy_status.values()), str(proxy_status))
        else:
            check(f"{label}: 403 on every /proxy route, a WebSocket upgrade too",
                  all(v == 403 for v in proxy_status.values()), str(proxy_status))

        # The sockets: direct, and through the /ws/terminal/{uuid} redirect to a user connection.
        row = {"id": 1, "uuid": "abc", "user_id": 5, "name": "c", "type": "ssh", "host": "h", "port": 22, "config": {}}
        direct = await run_ws(lambda ws, t: server.handle_user_connection_ws(ws, "/ws/user-connection/abc", t, "127.0.0.1"),
                              tok(scopes, jti), None)
        relay = await run_ws(lambda ws, t: server.handle_relay_ws(ws, "/ws/terminal/abc", t, "127.0.0.1"),
                             tok(scopes, jti), row)
        if passes:
            check(f"{label}: the connection socket passes the gate (4004 from the empty database)", direct == 4004, str(direct))
        else:
            check(f"{label}: the connection socket is refused with 4003", direct == 4003, str(direct))
            check(f"{label}: the /ws/terminal redirect to a connection is refused with 4003", relay == 4003, str(relay))


try:
    asyncio.run(asyncio.wait_for(main(), 120))
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
