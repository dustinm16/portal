"""PUT /api/admin/push: a bearer client that sends the allow-list back unchanged (a script that
reads the settings and writes them back with one field changed) is not refused; a changed list
still needs the superadmin's browser login session.

Temporary database, a route table of its own, fake sign-in; nothing is dialled.

Run: venv/bin/python tests/test_push_admin_put_unchanged.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import auth as auth_mod  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

failures = []
DEADLINE = 90


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Tok:
    def __init__(self, user_id, token_id):
        self.user_id, self.token_id, self.scopes = user_id, token_id, ["*", "admin"]

    def has_scope(self, scope):
        return True


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    if not uid:
        return None
    return Tok(int(uid), request.headers.get("X-Test-Tid") or f"t{uid}")


async def main():
    tmp = tempfile.TemporaryDirectory()
    db = Database(str(Path(tmp.name) / "t.db"))
    await db.connect()
    saved = (server.db, server.authenticate_request, auth_mod.db, server._push_pusher)
    server.db = auth_mod.db = db
    server.authenticate_request = fake_auth
    server._push_pusher = None
    srv = None
    http = None
    try:
        uid = await db.create_user("root", server.hash_password("old-password-1"))
        await db.set_user_role(uid, "superadmin")
        await db.create_token(uid, f"t{uid}", ["*"], name="web_session")
        app = web.Application()
        app.router.add_get("/api/admin/push", server.http_admin_push_get)
        app.router.add_put("/api/admin/push", server.http_admin_push_put)
        srv = TestServer(app)
        await srv.start_server()
        http = aiohttp.ClientSession()
        cookie, tid = await auth_mod.create_access_token(uid, ["*"], name="web_session")
        sess = {"Cookie": f"{Config.SESSION_COOKIE_NAME}={cookie}", "X-Test-Tid": tid}

        async def call(method, headers=None, **kw):
            h = {"X-Test-User": str(uid), **(headers or {})}
            async with http.request(method, str(srv.make_url("/api/admin/push")), headers=h, allow_redirects=False, **kw) as r:
                try:
                    body = await r.json(content_type=None)
                except Exception:
                    body = None
                return r.status, body

        # an allow-list is set by the browser session first
        s, b = await call("PUT", sess, json={"allowed_hosts": ["push.example.org", "*.push.example.net"]})
        check("the browser session sets the allow-list", s == 200 and b.get("allowed_hosts") == ["push.example.org", "*.push.example.net"], str((s, b)))

        # a bearer script reads the settings and writes them back with only enabled changed
        s, state = await call("GET")
        s2, b2 = await call("PUT", json={"enabled": False, "allowed_hosts": state["allowed_hosts"], "subject": state["subject"]})
        check("a bearer PUT with the allow-list unchanged is accepted", s2 == 200 and b2.get("enabled") is False, str((s2, b2)))
        check("the allow-list is as it was", b2.get("allowed_hosts") == state["allowed_hosts"], str(b2))

        # the same list in another spelling is the same parsed list
        s, b = await call("PUT", json={"allowed_hosts": "Push.Example.org., *.push.example.net push.example.org"})
        check("the same hosts written differently compare equal after parsing", s == 200, str((s, b)))

        # a changed list still needs the session
        for label, new in (("a host added", ["push.example.org", "*.push.example.net", "more.example.org"]),
                           ("a host removed", ["push.example.org"]), ("the list emptied", [])):
            s, b = await call("PUT", json={"allowed_hosts": new})
            check(f"a bearer PUT with {label} is refused (403)", s == 403, str((s, b)))
        s, st = await call("GET")
        check("the refused calls changed nothing", st["allowed_hosts"] == ["push.example.org", "*.push.example.net"], str(st))
        s, b = await call("PUT", sess, json={"allowed_hosts": ["push.example.org"]})
        check("the browser session may change it", s == 200 and b.get("allowed_hosts") == ["push.example.org"], str((s, b)))
    finally:
        if http is not None:
            await http.close()
        if srv is not None:
            await srv.close()
        server.db, server.authenticate_request, auth_mod.db, server._push_pusher = saved
        await db.close()
        tmp.cleanup()
    print()
    print("FAILED: " + ", ".join(failures) if failures else "all checks passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        _rc = asyncio.run(asyncio.wait_for(main(), DEADLINE))
    except BaseException as exc:
        print(f"FAIL: test aborted with {type(exc).__name__}: {exc}", flush=True)
        os._exit(1)
    outbound_guard.report("test_push_admin_put_unchanged")
    sys.exit(_rc)
