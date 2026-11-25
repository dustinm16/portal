"""A hook belongs to an administrator: when its owner stops being one, it is switched off (kept, with the
reason) and delivery refuses it whatever its stored state, also when the role was changed outside the portal
process (the command line) or the owner row is gone. System hooks (no owner) are not affected.

Nothing is sent: _deliver_webhook is replaced by a recorder. Run: venv/bin/python tests/test_access_hooks.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402

failures = []
DEADLINE = 90


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def main():
    tmp = tempfile.mkdtemp()
    db = server.db
    db.db_path = str(Path(tmp) / "t.db")
    await db.connect()
    secevents.log.bind(db)
    ids = {}
    for name, role in (("sa", "superadmin"), ("adm", "admin"), ("adm2", "admin"), ("mem", "user")):
        u = await create_user(name, "Pass-12345-xyz!", is_admin=role in ("admin", "superadmin"))
        await db.set_user_role(u["id"], role)
        ids[name] = u["id"]

    sent = []

    async def recorder(webhook, event, payload, attempt=1, **kw):
        sent.append(webhook["id"])
        return {"sent": True, "status": 200, "success": True, "error": None}
    server._deliver_webhook = recorder

    def mk(owner, name="h"):
        return db.create_webhook(ids[owner], name, "outgoing", url="https://hooks.example.test/" + name,
                                 events=["message.created", "stream.live"])
    h_adm = await mk("adm", "adm")
    h_adm2 = await mk("adm2", "adm2")
    h_sys = await db.create_webhook(None, "sys", "outgoing", url="https://hooks.example.test/sys",
                                    events=["stream.live"], kind="system")
    meta = {"stream_public": True}

    async def fire():
        sent.clear()
        n = await server.fire_webhook_event("stream.live", {"stream_id": 1}, meta=meta)
        await asyncio.sleep(0.05)
        return n, sorted(sent)

    n, got = await fire()
    check("an administrator's hook and the system hook receive the event",
          got == sorted([h_adm["id"], h_adm2["id"], h_sys["id"]]), str(got))

    # Fail closed: the role changed without anything touching the hook (the command line runs in another
    # process; a code path that forgets). The stored hook is still enabled.
    await db.set_user_role(ids["adm"], "user")
    row = await db.get_webhook(h_adm["id"])
    check("the hook is still enabled in the table (nothing disabled it yet)", bool(row["enabled"]))
    n, got = await fire()
    check("a demoted owner's enabled hook receives nothing", h_adm["id"] not in got and h_adm2["id"] in got, str(got))
    check("the system hook is unaffected", h_sys["id"] in got, str(got))
    w = await db.get_webhook_for_delivery(h_adm["id"])
    check("the retry path (current stored hook) refuses it", await server._webhook_current_for_event(
        h_adm["id"], "stream.live", meta) is None and w["owner_may_send"] is False)
    check("an administrator's hook passes the retry check", await server._webhook_current_for_event(
        h_adm2["id"], "stream.live", meta) is not None)

    # Owner row gone
    await db.conn.execute("PRAGMA foreign_keys = OFF")
    await db.conn.execute("UPDATE webhooks SET user_id = 99999 WHERE id = ?", (h_adm2["id"],))
    await db.conn.commit()
    n, got = await fire()
    check("a hook whose owner row is gone receives nothing", h_adm2["id"] not in got, str(got))
    await db.conn.execute("UPDATE webhooks SET user_id = ? WHERE id = ?", (ids["adm2"], h_adm2["id"]))
    await db.conn.execute("PRAGMA foreign_keys = ON")
    await db.conn.commit()

    # The admin route: demotion disables the hooks, keeps them, says why
    async def fake_auth(request):
        return server.TokenPayload({"jti": "s1", "sub": str(ids["sa"]), "scopes": ["*"]})
    server.authenticate_request = fake_auth

    async def role_call(uid, role):
        req = make_mocked_request("PUT", f"/api/users/{uid}/role", match_info={"id": str(uid)})

        async def _json():
            return {"role": role}
        req.json = _json
        return await server.http_update_user_role(req)

    inc = await db.create_webhook(ids["adm2"], "inc", "incoming", channel_id=1)
    check("setup: two hooks of the second administrator", bool((await db.get_webhook(h_adm2["id"]))["enabled"]))
    r = await role_call(ids["adm2"], "moderator")
    check("the role route answers 200", r.status == 200, str(r.status))
    for label, wid in (("outgoing", h_adm2["id"]), ("incoming", inc["id"])):
        row = await db.get_webhook(wid)
        check(f"demotion switched the {label} hook off and kept it",
              row is not None and not row["enabled"] and (row.get("last_failure_reason") or "").startswith("The owner is no longer"),
              str(row))
    check("the system hook is still enabled", bool((await db.get_webhook(h_sys["id"]))["enabled"]))
    # a promotion does not switch anything off
    h_new = await mk("sa", "sa")
    await role_call(ids["mem"], "admin")
    check("a promotion leaves other hooks alone", bool((await db.get_webhook(h_new["id"]))["enabled"]))

    # The demoted owner cannot switch it back on; the incoming URL no longer posts
    async def owner_auth(request):
        return server.TokenPayload({"jti": "s2", "sub": str(ids["adm2"]), "scopes": ["services:read", "access:*"]})
    server.authenticate_request = owner_auth
    req = make_mocked_request("PUT", f"/api/webhooks/{h_adm2['id']}", match_info={"id": str(h_adm2["id"])})

    async def _en():
        return {"enabled": True}
    req.json = _en
    r = await server.http_update_webhook(req)
    check("the demoted owner cannot enable the hook again", r.status == 409
          and not (await db.get_webhook(h_adm2["id"]))["enabled"], str(r.status))
    got_row = await db.get_webhook_by_token(await db.get_webhook_token(inc["id"]))
    check("an incoming hook of a demoted owner is not enabled", not got_row["enabled"])

    # the start-up pass: an old demotion that nobody cleaned
    await db.set_user_role(ids["sa"], "user")
    await db.conn.execute("UPDATE webhooks SET enabled = 1 WHERE id = ?", (h_new["id"],))
    await db.conn.commit()
    n1 = await db.disable_webhooks_of_non_admins()
    n2 = await db.disable_webhooks_of_non_admins()
    check("the start-up pass switches off a leftover hook once and is idempotent", n1 >= 1 and n2 == 0, f"{n1} {n2}")
    check("the start-up pass spares the system hook", bool((await db.get_webhook(h_sys["id"]))["enabled"]))

    # The command line
    await db.set_user_role(ids["sa"], "admin")
    h_cli = await mk("sa", "cli")
    await server.set_admin_cli("sa", remove=True)
    import sqlite3      # the command closed the connection it opened: read the file directly
    row = sqlite3.connect(db.db_path).execute("SELECT enabled FROM webhooks WHERE id = ?", (h_cli["id"],)).fetchone()
    check("the command line's demotion also switches the hook off", row is not None and row[0] == 0, str(row))

    # A retry of a stream event is judged on the stream as it is now, system hooks of a third-party format
    # included; a generic system hook is not asked.
    await db.connect()          # the command line's demotion closed the connection
    sid = await db.create_user_stream(ids["sa"], "show", "live_" + "a" * 24, public_key="pub_" + "a" * 24, is_public=True)
    h_dc = await db.create_webhook(None, "dc", "outgoing", url="https://hooks.example.test/dc",
                                   events=["stream.live", "stream.offline"], kind="system", fmt="discord")
    h_gen = await db.create_webhook(None, "gen", "outgoing", url="https://hooks.example.test/gen",
                                    events=["stream.live", "stream.offline"], kind="system")
    dc = await db.get_webhook_for_delivery(h_dc["id"])
    gen = await db.get_webhook_for_delivery(h_gen["id"])
    check("setup: a system hook in the discord format and a generic one",
          dc["kind"] == "system" and dc["format"] == "discord" and gen["kind"] == "system" and gen["format"] == "generic")
    payload = {"stream_id": sid}
    pub = {"stream_public": True}
    check("a retry for a public stream goes to the third-party system hook",
          await server._webhook_resend_allowed(dc, "stream.live", pub, payload))
    await db.update_user_stream(sid, is_public=False)
    check("a retry after the stream turned private is refused for the third-party system hook",
          not await server._webhook_resend_allowed(dc, "stream.live", pub, payload))
    check("the same retry still goes to the generic system hook",
          await server._webhook_resend_allowed(gen, "stream.live", pub, payload))
    await db.conn.execute("DELETE FROM user_streams WHERE id = ?", (sid,))
    await db.conn.commit()
    check("a retry for a deleted stream is refused for the third-party system hook",
          not await server._webhook_resend_allowed(dc, "stream.offline", pub, payload))
    check("... and still goes to the generic system hook",
          await server._webhook_resend_allowed(gen, "stream.offline", pub, payload))
    check("a third-party system hook still gets events that are not stream events",
          await server._stream_event_still_public(dc, "message.created", {}))


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check("finished within the deadline", False, f"{DEADLINE} s")
except Exception as e:  # a regression prints FAIL instead of a traceback only
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
