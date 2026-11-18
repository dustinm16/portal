"""Host-key accept routes need a credential with full user scope.

Stream keys and narrowly scoped API keys or tokens get 403 on the connection,
service and VOD accept routes, and are never handed an accept token in the 409
host-key body.

Run: venv/bin/python tests/test_host_key_scope.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import hostkeys  # noqa: E402
import server  # noqa: E402
from auth import TokenPayload  # noqa: E402


def tok(scopes, jti="web", uid=5):
    return TokenPayload({"sub": str(uid), "scopes": scopes, "jti": jti})


FULL_USER = ["services:read", "access:*"]
SCOPED = {
    "stream key": tok(["stream", "stream:read", "stream:write"], "streamkey-3"),
    "narrow api key": tok(["services:read"], "apikey-4"),
    "admin-only api key": tok(["admin"], "apikey-4"),
    "non-admin api key": tok(FULL_USER, "apikey-4"),
    "token limited to services:read": tok(["services:read"], "abc"),
    "token limited to admin": tok(["admin"], "abc"),
    "empty scopes": tok([], "abc"),
}
FULL = {
    "admin browser session": tok(["*"], "s1"),
    "user browser session": tok(FULL_USER, "s2"),
    "all-scope api key": tok(["*"], "apikey-9"),
}


def test_truth_table():
    for label, t in SCOPED.items():
        assert not server.has_full_user_scope(t), label
    for label, t in FULL.items():
        assert server.has_full_user_scope(t), label
    assert not server.has_full_user_scope(None)
    # a stream key never counts, whatever scopes it was given
    assert not server.has_full_user_scope(tok(["*"], "streamkey-1"))


def _call(handler, token, path, match):
    async def fake_auth(request):
        return token

    async def none(*a, **k):
        return None

    real = (server.authenticate_request, server.db)
    server.authenticate_request = fake_auth
    server.db = SimpleNamespace(get_user_connection_by_uuid=none, get_service_by_id=none, get_vod_storage=none)
    try:
        req = make_mocked_request("POST", path, match_info=match)
        return asyncio.run(handler(req))
    finally:
        server.authenticate_request, server.db = real


def test_accept_routes_refuse_scoped_credentials():
    routes = [
        (server.http_accept_connection_host_key, "/api/connections/abc/host-key/accept", {"id": "abc"}),
        (server.http_accept_service_host_key, "/api/services/1/host-key/accept", {"id": "1"}),
        (server.http_accept_vod_host_key, "/api/vods/storage/host-key/accept", {}),
    ]
    for handler, path, match in routes:
        for label, t in SCOPED.items():
            if handler is server.http_accept_service_host_key and not (t.has_scope("admin") or t.has_scope("*")):
                continue   # refused earlier, as an admin-only route
            r = _call(handler, t, path, match)
            assert r.status == 403, (handler.__name__, label, r.status)
        for label, t in FULL.items():
            if handler is server.http_accept_service_host_key and not t.has_scope("*"):
                continue   # a non-admin session: the admin-only rule applies
            r = _call(handler, t, path, match)
            assert r.status != 403, (handler.__name__, label, r.status)  # gets as far as the lookup (404)


def _refused_409(token, owner_id=5):
    async def get_accessible(conn_uuid, user_id):
        return {"id": 11, "type": "ssh", "user_id": owner_id, "host": "h.example", "port": 22, "config": {}}

    async def connect(connection):
        raise hostkeys.HostKeyRefused(hostkeys.STATE_UNPINNED, "SHA256:" + "A" * 43)

    real = (server.db, server.sftp_browser.connect_sftp)
    server.db = SimpleNamespace(get_accessible_connection=get_accessible)
    server.sftp_browser.connect_sftp = connect
    try:
        req = make_mocked_request("GET", "/api/sftp/abc/list", match_info={"conn_id": "abc"})
        _, _, resp = asyncio.run(server._get_sftp_connection(req, token))
        return resp.status, json.loads(resp.text)
    finally:
        server.db, server.sftp_browser.connect_sftp = real


def test_409_body_has_no_accept_token_for_scoped_callers():
    for label, t in SCOPED.items():
        status, body = _refused_409(t)
        assert status == 409, label
        assert body["can_accept"] is False and "accept_token" not in body and "accept_url" not in body, (label, body)
    for label, t in FULL.items():
        status, body = _refused_409(t)
        assert status == 409 and body["can_accept"] is True and body.get("accept_token") and body.get("accept_url"), label


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok   {name}")
    print("test_host_key_scope: ok")


main()
