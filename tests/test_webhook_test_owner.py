"""POST /api/webhooks/{id}/test applies the delivery's owner rule.

Delivery sends nothing for a user hook whose owner is not an administrator now. The test route checked the
caller (a superadmin may test another member's hook) but not the hook's owner, so an old hook of a demoted
administrator could still be made to deliver by anyone who may cross. Now it answers 400 and sends nothing.
Nothing leaves this machine: _deliver_webhook is replaced by a recorder.

Run: venv/bin/python tests/test_webhook_test_owner.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402

failures = []
DEADLINE = 60


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def main():
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    secevents.log.bind(db)
    ids = {}
    for name, role in (("sa", "superadmin"), ("adm", "admin")):
        u = await create_user(name, "Pass-12345-xyz!", is_admin=True)
        await db.set_user_role(u["id"], role)
        ids[name] = u["id"]
    sent = []

    async def recorder(webhook, event, payload, attempt=1, **kw):
        sent.append(webhook["id"])
        return {"sent": True, "status": 200, "success": True, "error": None}
    server._deliver_webhook = recorder

    async def auth(request):
        return server.TokenPayload({"jti": "t1", "sub": str(ids["sa"]), "scopes": ["*"]})
    server.authenticate_request = auth

    hook = await db.create_webhook(ids["adm"], "h", "outgoing", url="https://hooks.example.test/h", events=["stream.live"])

    async def test_it():
        req = make_mocked_request("POST", f"/api/webhooks/{hook['id']}/test", match_info={"id": str(hook["id"])})
        r = await server.http_test_webhook(req)
        return r.status, r.body.decode()

    st, body = await test_it()
    check("the owner is an administrator: the test is delivered", st == 200 and sent == [hook["id"]], f"{st} {body} {sent}")
    sent.clear()
    await db.set_user_role(ids["adm"], "user")          # demoted; the hook is still enabled in the table
    check("the hook is still enabled (the case under test)", bool((await db.get_webhook(hook["id"]))["enabled"]))
    st, body = await test_it()
    check("the owner is demoted: the test is refused and nothing is sent", st == 400 and sent == [] and "administrator" in body, f"{st} {body} {sent}")
    await db.set_user_role(ids["adm"], "admin")
    sent.clear()
    st, body = await test_it()
    check("the owner is an administrator again: delivered", st == 200 and sent == [hook["id"]], f"{st} {body}")
    await db.conn.close()


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check("finished within the deadline", False, f"{DEADLINE} s")
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
