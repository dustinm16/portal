"""Starting, stopping and restarting a service through the portal leaves an audit entry (actor,
service id and name, action), for a managed service and for one bound to a systemd unit. A
failed action leaves none. A fake service manager and a fake systemctl: nothing touches the host.

Run: venv/bin/python tests/test_service_control_audit.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class FakeManager:
    def __init__(self):
        self.ok = True

    async def start_service(self, sid):
        return (True, "") if self.ok else (False, "boom")

    stop_service = restart_service = start_service

    async def get_service_status(self, sid):
        return {"id": sid, "status": "running"}


async def main():
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    db = server.db
    u = await create_user("adm", "Adm-pass-12345!", is_admin=True)
    await db.set_user_role(u["id"], "admin")
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()

    mid = await db.create_service("mgd", "/mgd", plugin="mediamtx", service_type="managed")
    sid = await db.create_service("sysd", "/sysd", service_type="proxy", systemd_unit="fake-unit")
    mgr = FakeManager()
    server._service_manager = mgr
    calls = []
    server.system_monitor.control_service = lambda unit, action: (calls.append((unit, action)) or (True, "ok"))
    server.system_monitor.get_service_status = lambda unit: {"sub_state": "running", "main_pid": 1}

    async def entries():
        out = [e for e in await db.get_audit_log(limit=100) if (e["action"] or "").startswith("service.")]
        for e in out:
            if isinstance(e["details"], str):
                e["details"] = json.loads(e["details"])
        return out

    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        async with s.post(base + "/login", json={"username": "adm", "password": "Adm-pass-12345!"}) as r:
            assert r.status == 200
        for action in ("start", "stop", "restart"):
            async with s.post(base + f"/api/services/{mid}/{action}") as r:
                check(f"managed {action} answers 200", r.status == 200, str(r.status))
            es = [e for e in await entries() if e["action"] == f"service.{action}" and e["target_id"] == mid]
            check(f"managed {action} is audited with actor, service and action",
                  len(es) == 1 and es[0]["actor_username"] == "adm" and es[0]["target_name"] == "mgd"
                  and (es[0]["details"] or {}).get("action") == action
                  and (es[0]["details"] or {}).get("service_id") == mid, str(es))
        for action in ("start", "stop", "restart"):
            async with s.post(base + f"/api/services/{sid}/{action}") as r:
                check(f"systemd-bound {action} answers 200", r.status == 200, str(r.status))
            es = [e for e in await entries() if e["action"] == f"service.{action}" and e["target_id"] == sid]
            check(f"systemd-bound {action} is audited", len(es) == 1 and es[0]["target_name"] == "sysd", str(es))
        # The admin panel's own buttons use a second set of routes; they must leave the same record.
        for action in ("start", "stop", "restart"):
            before = len([e for e in await entries() if e["action"] == f"service.{action}" and e["target_id"] == mid])
            async with s.post(base + f"/api/managed-services/{mid}/{action}") as r:
                check(f"panel route {action} answers 200", r.status == 200, str(r.status))
            es = [e for e in await entries() if e["action"] == f"service.{action}" and e["target_id"] == mid]
            check(f"panel route {action} is audited", len(es) == before + 1 and es[0]["actor_username"] == "adm", str(es))
        n = len(await entries())
        mgr.ok = False
        async with s.post(base + f"/api/services/{mid}/stop") as r:
            check("a failed stop answers 400", r.status == 400, str(r.status))
        check("a failed action leaves no audit entry", len(await entries()) == n)

    await srv.close()
    await db.conn.close()


asyncio.run(main())
if failures:
    print(f"\ntest_service_control_audit: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_service_control_audit: all checks passed")
