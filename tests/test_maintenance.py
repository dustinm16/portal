"""Maintenance of one service or one connection: every entry point answers a member with 503, the
friendly page and a Retry-After, an administrator passes, someone without access gets what they
always got, and an end time that has passed stops applying with no clean-up.

The real app on a loopback test server with a temporary database (tests/grant_harness.py); the
HTTP proxy goes to a local upstream (only the outbound host policy is replaced) and the terminal
plugin is a fake that holds the socket open, so no SSH target is involved. The route list check
at the end fails when a route that reaches a service or a connection has no maintenance check.

Run: venv/bin/python tests/test_maintenance.py
"""

import asyncio
import inspect
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
import maintenance  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------------------------
# The rules, with a fixed clock
# ---------------------------------------------------------------------------------------------

def rules():
    now = datetime(2030, 3, 4, 12, 0, 0, tzinfo=timezone.utc)
    later = now + timedelta(hours=8)
    row = {"maintenance": 1, "maintenance_until": iso(later), "maintenance_message": "disk swap"}
    check("rules: a flagged row with an end time ahead is in maintenance",
          maintenance.state(row, now) == {"until": later, "message": "disk swap"})
    check("rules: the same row after its end time is not (no clean-up needed)",
          maintenance.state(row, later + timedelta(seconds=1)) is None)
    check("rules: an open-ended row stays in maintenance",
          maintenance.state({"maintenance": 1, "maintenance_until": None}, now + timedelta(days=900)) is not None)
    check("rules: a row without the flag is not, whatever its end time",
          maintenance.state({"maintenance": 0, "maintenance_until": iso(later)}, now) is None)
    check("rules: an unreadable stored end time ends the maintenance",
          maintenance.state({"maintenance": 1, "maintenance_until": "garbage"}, now) is None)
    for extreme in ("0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"):
        def _raises(f):
            try:
                f()
                return False
            except ValueError:
                return True
        check(f"rules: {extreme} is unreadable (None), refused as a ValueError, and ends a stored maintenance",
              maintenance.parse_stored(extreme) is None and _raises(lambda: maintenance.parse_until(extreme, now))
              and _raises(lambda: maintenance.parse_update({"maintenance": True, "maintenance_until": extreme}, now))
              and maintenance.state({"maintenance": 1, "maintenance_until": extreme}, now) is None)
    check("rules: Retry-After is the time left, capped",
          maintenance.retry_after(now + timedelta(seconds=40), now) == 41
          and maintenance.retry_after(later, now) == maintenance.RETRY_AFTER_CAP
          and maintenance.retry_after(None, now) == maintenance.RETRY_AFTER_CAP)
    today = datetime(2030, 3, 4, 20, 0, tzinfo=timezone.utc)
    check("rules: the text names the time (today) or the date and time",
          maintenance.describe_until(today, now) == "Down for maintenance until 20:00 UTC"
          and maintenance.describe_until(today + timedelta(days=1), now) == "Down for maintenance until 2030-03-05 20:00 UTC"
          and maintenance.describe_until(None, now) == "Down for maintenance")
    for bad in ("tomorrow", 5, iso(now - timedelta(minutes=1)), iso(now + timedelta(days=400))):
        try:
            maintenance.parse_until(bad, now)
            ok = False
        except ValueError:
            ok = True
        check(f"rules: end time {bad!r} is refused", ok)
    check("rules: no offset counts as UTC and the stored form is normalised",
          maintenance.parse_until("2030-03-04T20:00", now) == "2030-03-04T20:00:00Z"
          and maintenance.parse_until("2030-03-04T22:00:00+02:00", now) == "2030-03-04T20:00:00Z"
          and maintenance.parse_until(None, now) is None and maintenance.parse_until("", now) is None)
    check("rules: turning it off clears the end time and the message",
          maintenance.parse_update({"maintenance": False, "maintenance_message": "x"}, now)
          == {"maintenance": 0, "maintenance_until": None, "maintenance_message": None})
    check("rules: turning it on without an end time is open-ended (an old end time does not linger)",
          maintenance.parse_update({"maintenance": True}, now)["maintenance_until"] is None)
    try:
        maintenance.parse_update({"maintenance_message": "x" * 201}, now)
        ok = False
    except ValueError:
        ok = True
    check("rules: a message over the limit is refused", ok)
    check("rules: control characters and line breaks leave the message",
          maintenance.clean_message("a\r\nb\x00c‮d") == "a b c d")


# ---------------------------------------------------------------------------------------------

async def main():
    rules()

    async def ok_page(request):
        return web.Response(text="upstream-ok")

    async def held_socket(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str("hi")
        async for _ in ws:
            pass
        return ws

    up = web.Application()
    up.router.add_get("/ws", held_socket)
    up.router.add_get("/{p:.*}", ok_page)
    upstream = TestServer(up, host="127.0.0.1")
    await upstream.start_server()

    env = await h.boot()
    db = env.db
    adm, bob, carol = env.sessions["adm"], env.sessions["bob"], env.sessions["carol"]

    async def no_resolve(host, port=0):
        return []
    server.resolve_checked_host = no_resolve
    server.resolve_checked_host_cached = no_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)
    ws_base = env.base.replace("http", "ws")

    web_uuid, web_id = await h.connection(env, "adm", name="web", ctype="http", host="127.0.0.1", port=upstream.port)
    box_uuid, box_id = await h.connection(env, "adm", name="box")
    for uuid in (web_uuid, box_uuid):
        async with adm.post(f"{env.base}/api/connections/{uuid}/shares", json={"usernames": ["bob"]}) as r:
            assert r.status == 200, r.status
        async with bob.post(f"{env.base}/api/connections/{uuid}/notice") as r:     # the first-open notice (1.24.1)
            assert r.status == 200, r.status

    async def text(resp):
        return resp.status, await resp.text()

    # ---- before: everything works, and what carol (no access) sees is recorded --------------------
    async with bob.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        check("before: a grantee reaches the upstream through /proxy", await text(r) == (200, "upstream-ok"))
    carol_before = {}
    async def carol_answers():
        out = {}
        async with carol.get(f"{env.base}/proxy/{web_uuid}/x") as r:
            out["proxy"] = (r.status, await r.text(), r.headers.get("Retry-After"))
        async with carol.get(f"{env.base}/browser?connection={web_uuid}") as r:
            out["browser"] = (r.status, await r.text())
        async with carol.get(f"{env.base}/terminal/connect?connection={box_uuid}") as r:
            out["terminal"] = (r.status, await r.text())
        async with carol.get(f"{env.base}/api/connections/{box_uuid}/connect") as r:
            out["connect"] = (r.status, await r.text())
        async with carol.get(f"{env.base}/api/sftp/{box_uuid}/list?path=/") as r:
            out["sftp"] = (r.status, await r.text())
        ws = await carol.ws_connect(f"{ws_base}/ws/user-connection/{box_uuid}")
        out["ws"] = (await h.close_code(ws), )
        return out
    carol_before = await carol_answers()
    check("before: carol is told the connection does not exist (404 on every route)",
          carol_before["proxy"][0] == 404 and carol_before["browser"][0] == 404
          and carol_before["terminal"][0] == 404 and carol_before["connect"][0] == 404
          and carol_before["sftp"][0] == 404 and carol_before["ws"] == (4004,), str(carol_before))

    # ---- who may set it -------------------------------------------------------------------------------
    soon = datetime.now(timezone.utc) + timedelta(hours=2)
    body = {"maintenance": True, "maintenance_until": iso(soon), "maintenance_message": "<b>swap</b> & <script>x</script>"}
    mine = await db.create_user_connection(env.uid["bob"], "mine", "ssh", "93.184.216.34", 22, "{}")
    EDITABLE = ("name", "type", "host", "port", "config", "icon", "portal_access", "api_access") + maintenance.FIELDS

    def sendable(row):
        """What a form sends back after a GET: the editable fields of what it read, maintenance ones included."""
        return {k: v for k, v in row.items() if k in EDITABLE}

    async def stored_maint(conn_uuid):
        row = await db.get_user_connection_by_uuid(conn_uuid, env.uid["bob"])
        return row.get("maintenance"), row.get("maintenance_until"), row.get("maintenance_message")
    async with bob.put(f"{env.base}/api/connections/{mine}", json=dict(body, name="mine1")) as r:
        check("a member's maintenance fields are ignored, not an error (200, like the recording flag)", r.status == 200, str(r.status))
    check("... and nothing was stored", await stored_maint(mine) in ((0, None, None), (None, None, None)), str(await stored_maint(mine)))
    async with bob.put(f"{env.base}/api/connections/{mine}", json={"name": "mine2"}) as r:
        check("(a plain edit by a member still works)", r.status == 200, str(r.status))
    for junk in ({"maintenance": "yes"}, {"maintenance_until": "0001-01-01T00:00:00+05:00"},
                 {"maintenance": True, "maintenance_until": iso(datetime.now(timezone.utc) - timedelta(hours=1))}):
        async with bob.put(f"{env.base}/api/connections/{mine}", json=dict(junk, name="mine3")) as r:
            check(f"a member sending {sorted(junk)}: ignored, 200, nothing validated or stored",
                  r.status == 200 and await stored_maint(mine) in ((0, None, None), (None, None, None)), str(r.status))
    async with bob.get(f"{env.base}/api/connections/{mine}") as r:
        read_back = await r.json()
    async with bob.put(f"{env.base}/api/connections/{mine}", json=dict(sendable(read_back), name="mine4")) as r:
        check("a member's read followed by a write of the same object works (200)", r.status == 200, f"{r.status} {await r.text()}")
    async with bob.post(f"{env.base}/api/connections", json={"name": "fresh", "type": "ssh", "host": "93.184.216.34",
                                                             "port": 22, "config": {}, **body}) as r:
        created_j = await r.json()
        check("a member's create with maintenance fields: created, fields ignored", r.status == 201, f"{r.status} {created_j}")
    fresh = await db.get_user_connection_by_uuid(created_j.get("id"), env.uid["bob"]) if r.status == 201 else {}
    check("... the new connection is not in maintenance", not fresh.get("maintenance") and not fresh.get("maintenance_until"), str(fresh))
    async with adm.put(f"{env.base}/api/connections/{web_uuid}", json={"maintenance": "yes"}) as r:
        check("an administrator's non-boolean flag is refused with 400", r.status == 400, str(r.status))
    for extreme in ("0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"):
        async with adm.put(f"{env.base}/api/connections/{web_uuid}", json={"maintenance": True, "maintenance_until": extreme}) as r:
            check(f"an administrator's {extreme} is refused with 400, not 500", r.status == 400, str(r.status))
    async with adm.put(f"{env.base}/api/connections/{web_uuid}",
                       json={"maintenance": True, "maintenance_until": iso(datetime.now(timezone.utc) - timedelta(hours=1))}) as r:
        check("an end time in the past is refused", r.status == 400, str(r.status))
    async with adm.put(f"{env.base}/api/connections/{web_uuid}", json=body) as r:
        check("an administrator sets maintenance on a connection (200)", r.status == 200, str(r.status))
    async with adm.put(f"{env.base}/api/connections/{box_uuid}", json=body) as r:
        check("... and on the SSH connection", r.status == 200, str(r.status))
    async with adm.get(f"{env.base}/api/connections/{web_uuid}") as r:
        got = await r.json()
        check("the connection API shows the flag, end time, message and that it is active",
              got.get("maintenance") is True and got.get("maintenance_active") is True
              and got.get("maintenance_until") == iso(soon) and got.get("maintenance_message") == body["maintenance_message"],
              str({k: v for k, v in got.items() if k.startswith("maint")}))
    rows = await db.get_audit_log(limit=20, action="connection.maintenance")
    check("the change is in the audit log (who, which, was, now)",
          len(rows) == 2 and "web" in {r["target_name"] for r in rows} and "maintenance_message" in str(rows[0]["details"]))

    # ---- a member in maintenance, every entry point -----------------------------------------------------
    def friendly(status, page, retry, label):
        check(f"{label}: 503 with Retry-After (time left, at most {maintenance.RETRY_AFTER_CAP})",
              status == 503 and retry is not None and 1 <= int(retry) <= maintenance.RETRY_AFTER_CAP, f"{status} {retry}")
        check(f"{label}: the page says Down for maintenance until <time> and the message is escaped",
              "Down for maintenance until" in page and f"{soon:%H:%M}" in page
              and "&lt;b&gt;swap&lt;/b&gt;" in page and "<b>swap" not in page and "<script>x" not in page, page[:300])

    async with bob.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        friendly(r.status, await r.text(), r.headers.get("Retry-After"), "/proxy")
        check("/proxy: no-store and a request ID on the answer",
              r.headers.get("Cache-Control") == "no-store" and len(r.headers.get("X-Request-ID", "")) == 8)
    async with bob.post(f"{env.base}/proxy/{web_uuid}/x", data=b"abc") as r:
        check("/proxy: a POST is refused too", r.status == 503)
    async with bob.get(f"{env.base}/proxy/{web_uuid}/x", headers={"Accept": "application/json"}) as r:
        j = await r.json()
        check("/proxy: JSON for an API-style request names the end time and the message",
              r.status == 503 and j.get("maintenance") is True and j.get("until") == iso(soon)
              and j.get("message") == body["maintenance_message"] and "Down for maintenance" in j.get("error", ""), str(j))
    async with bob.get(f"{env.base}/browser?connection={web_uuid}") as r:
        friendly(r.status, await r.text(), r.headers.get("Retry-After"), "/browser")
    async with bob.get(f"{env.base}/terminal/connect?connection={box_uuid}") as r:
        friendly(r.status, await r.text(), r.headers.get("Retry-After"), "/terminal page")
    for page in ("vnc", "media", "spice", "proxmox", "github"):
        async with bob.get(f"{env.base}/{page}/connect?connection={box_uuid}") as r:
            check(f"/{page} page: 503", r.status == 503, str(r.status))
    async with bob.get(f"{env.base}/api/connections/{box_uuid}/connect") as r:
        j = await r.json()
        check("/api/connections/{id}/connect: 503 JSON", r.status == 503 and j.get("maintenance") is True, str(j))
    async with bob.get(f"{env.base}/api/sftp/{box_uuid}/list?path=/") as r:
        check("/api/sftp/{id}/list: 503 JSON", r.status == 503 and (await r.json()).get("maintenance") is True)
    for path, label in ((f"/ws/user-connection/{box_uuid}", "/ws/user-connection"),
                        (f"/ws/terminal/{box_uuid}", "/ws/terminal (a connection id)"),
                        (f"/proxy/{web_uuid}/ws", "/proxy WebSocket")):
        try:
            ws = await bob.ws_connect(ws_base + path)
            await ws.close()
            check(f"{label}: refused before the upgrade", False, "the upgrade succeeded")
        except aiohttp.WSServerHandshakeError as e:
            check(f"{label}: refused before the upgrade (handshake answer 503 with Retry-After)",
                  e.status == 503 and e.headers.get("Retry-After") is not None, str(e.status))

    # ---- an administrator passes ----------------------------------------------------------------------
    async with adm.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        check("an administrator reaches /proxy during maintenance", await text(r) == (200, "upstream-ok"))
    async with adm.get(f"{env.base}/terminal/connect?connection={box_uuid}") as r:
        check("... and the terminal page", r.status == 200)
    ws, msg = await h.open_ws(adm, env.base, box_uuid)
    check("... and the terminal socket (the redirect from /ws/terminal/<connection id>)",
          msg.type == aiohttp.WSMsgType.TEXT and "ready" in msg.data, str(msg))
    await ws.close()
    wsx = await adm.ws_connect(f"{ws_base}/proxy/{web_uuid}/ws")
    check("... and the /proxy WebSocket relay", (await asyncio.wait_for(wsx.receive(), 3)).data == "hi")
    await wsx.close()

    # ---- someone without access: exactly what they got before ----------------------------------------------
    carol_during = await carol_answers()
    check("carol (no access) gets byte for byte the answers she got before, on every route",
          carol_during == carol_before, f"{carol_before} != {carol_during}")
    async with carol.get(f"{env.base}/proxy/zzzzzzzzzzzz/x") as r:
        nothing = (r.status, await r.text())
    check("... which is also what a connection that does not exist gives", nothing[0] == carol_during["proxy"][0]
          and nothing[1] == carol_during["proxy"][1])

    # ---- expiry needs no clean-up ----------------------------------------------------------------------------
    await db.conn.execute("UPDATE user_connections SET maintenance_until = ? WHERE id = ?",
                          (iso(datetime.now(timezone.utc) - timedelta(seconds=5)), web_id))
    await db.conn.commit()
    async with bob.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        check("an end time that has passed stops applying with no job running", await text(r) == (200, "upstream-ok"))
    async with adm.get(f"{env.base}/api/connections/{web_uuid}") as r:
        got = await r.json()
        check("(the API still shows the stored flag, and that it is no longer active)",
              got.get("maintenance") is True and got.get("maintenance_active") is False)
    async with adm.get(f"{env.base}/api/connections/{web_uuid}") as r:
        expired_row = await r.json()
    async with adm.put(f"{env.base}/api/connections/{web_uuid}", json=dict(sendable(expired_row), name="web")) as r:
        check("an administrator sending back an unchanged, expired end time (a read then a write) is accepted (200)",
              r.status == 200, f"{r.status} {await r.text()}")
    async with adm.get(f"{env.base}/api/connections/{web_uuid}") as r:
        again = await r.json()
    check("... and the stored end time is the one it was",
          again.get("maintenance_until") == expired_row.get("maintenance_until") and again.get("maintenance") is True)
    async with adm.put(f"{env.base}/api/connections/{web_uuid}",
                       json={"maintenance": True, "maintenance_until": iso(datetime.now(timezone.utc) - timedelta(hours=2))}) as r:
        check("a different end time in the past is still refused (400)", r.status == 400, str(r.status))
    # open-ended
    async with adm.put(f"{env.base}/api/connections/{web_uuid}", json={"maintenance": True, "maintenance_message": "back soon"}) as r:
        check("open-ended maintenance is set", r.status == 200)
    async with bob.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        page = await r.text()
        check("open-ended: 503, Retry-After at the cap, no end time named",
              r.status == 503 and r.headers.get("Retry-After") == str(maintenance.RETRY_AFTER_CAP)
              and "Down for maintenance" in page and "Down for maintenance until" not in page
              and "back soon" in page, f"{r.status} {r.headers.get('Retry-After')} {page[page.find('<h1>'):][:400]}")
    async with adm.put(f"{env.base}/api/connections/{web_uuid}", json={"maintenance": False}) as r:
        check("the administrator ends it", r.status == 200)
    async with bob.get(f"{env.base}/proxy/{web_uuid}/x") as r:
        check("afterwards the member reaches the upstream again", await text(r) == (200, "upstream-ok"))
    async with adm.get(f"{env.base}/api/connections/{web_uuid}") as r:
        got = await r.json()
        check("turning it off cleared the end time and the message",
              got.get("maintenance") is False and got.get("maintenance_until") is None and got.get("maintenance_message") is None)

    # ---- an administrator can clear maintenance on any connection (setting stays with the owner) ----------------
    await db.conn.execute("UPDATE user_connections SET maintenance = 1, maintenance_until = NULL, "
                          "maintenance_message = 'stuck since a demotion' WHERE uuid = ?", (mine,))
    await db.conn.commit()
    clear_url = f"{env.base}/api/admin/connections/{mine}/maintenance/clear"
    list_url = f"{env.base}/api/admin/connections/maintenance"
    async with bob.get(list_url) as r:
        check("a member cannot list connections in maintenance (403)", r.status == 403, str(r.status))
    async with bob.post(clear_url) as r:
        check("the owner, a member now, cannot clear it through the admin route (403)", r.status == 403, str(r.status))
    async with bob.put(f"{env.base}/api/connections/{mine}", json={"maintenance": False, "name": "mine5"}) as r:
        pass
    check("... nor by an edit (the fields are ignored): it is still set",
          (await stored_maint(mine))[0] == 1, str(await stored_maint(mine)))
    async with adm.get(list_url) as r:
        lst = await r.json()
    mine_rows = [c for c in lst.get("connections", []) if c["id"] == mine]
    check("an administrator lists it with its owner and message, no host, port or config",
          r.status == 200 and len(mine_rows) == 1 and mine_rows[0]["owner"] == "bob" and mine_rows[0]["maintenance_active"] is True
          and mine_rows[0]["maintenance_message"] == "stuck since a demotion"
          and not ({"host", "port", "config"} & set(mine_rows[0])) and "93.184.216.34" not in json.dumps(lst), str(lst))
    async with env.sessions["carol"].post(clear_url) as r:
        check("another member cannot clear it either (403)", r.status == 403)
    async with adm.post(f"{env.base}/api/admin/connections/zzzz-no-such/maintenance/clear") as r:
        check("an unknown connection id is 404", r.status == 404, str(r.status))
    async with adm.post(clear_url) as r:
        check("any administrator clears it on a connection they do not own (200)", r.status == 200, f"{r.status} {await r.text()}")
    check("... the three fields are cleared", await stored_maint(mine) in ((0, None, None), (None, None, None)), str(await stored_maint(mine)))
    rows = await db.get_audit_log(limit=20, action="connection.maintenance_clear")
    check("... and it is audited with who, which connection, what it was and its owner",
          len(rows) == 1 and rows[0]["target_name"] and "stuck since a demotion" in str(rows[0]["details"])
          and "bob" in str(rows[0]["details"]), str(rows))
    async with adm.post(clear_url) as r:
        check("clearing again is harmless (200) and writes no second audit entry",
              r.status == 200 and len(await db.get_audit_log(limit=20, action="connection.maintenance_clear")) == 1)
    async with env.sessions["bob"].delete(f"{env.base}/api/connections/{mine}") as r:
        pass

    # ---- a service ---------------------------------------------------------------------------------------------
    svc_id = await db.create_service("relay1", "/ws/relay1", plugin="ssh", host="93.184.216.34", port=22)
    locked_id = await db.create_service("relay2", "/ws/relay2", plugin="ssh", host="93.184.216.34", port=22,
                                        required_scopes=["nobody-has-this"])
    async def svc_answers(sess):
        out = {}
        async with sess.get(f"{env.base}/terminal/{svc_id}") as r:
            out["page"] = r.status
        async with sess.get(f"{env.base}/terminal/{locked_id}") as r:
            out["locked_page"] = (r.status, await r.text())
        try:
            ws = await sess.ws_connect(f"{ws_base}/ws/terminal/{locked_id}")
            out["locked_ws"] = (await h.close_code(ws),)
        except aiohttp.WSServerHandshakeError as e:
            out["locked_ws"] = ("handshake", e.status)
        return out
    svc_before = await svc_answers(bob)
    check("before: a service page opens, a service the member lacks the scope for is refused",
          svc_before["page"] == 200 and svc_before["locked_page"][0] == 403, str(svc_before))
    async with adm.put(f"{env.base}/api/services/{svc_id}", json=body) as r:
        check("an administrator sets maintenance on a service (PUT /api/services/{id})", r.status == 200
              and (await r.json()).get("maintenance_active") is True)
    async with adm.put(f"{env.base}/api/services/{locked_id}", json=body) as r:
        check("... and on the service the member has no scope for", r.status == 200)
    async with bob.put(f"{env.base}/api/services/{svc_id}", json={"maintenance": False}) as r:
        check("a member cannot touch a service (403)", r.status == 403)
    async with bob.get(f"{env.base}/terminal/{svc_id}") as r:
        friendly(r.status, await r.text(), r.headers.get("Retry-After"), "service terminal page")
    try:
        await bob.ws_connect(f"{ws_base}/ws/terminal/{svc_id}")
        check("service WebSocket /ws/terminal/<id>: refused before the upgrade", False)
    except aiohttp.WSServerHandshakeError as e:
        check("service WebSocket /ws/terminal/<id>: refused before the upgrade (503)", e.status == 503, str(e.status))
    try:
        await bob.ws_connect(f"{ws_base}/ws/relay1")
        check("service WebSocket by path /ws/relay1: refused before the upgrade", False)
    except aiohttp.WSServerHandshakeError as e:
        check("service WebSocket by path /ws/relay1: refused before the upgrade (503)", e.status == 503, str(e.status))
    check("a service the member has no access to answers as before, maintenance or not",
          await svc_answers(bob) == {**svc_before, "page": 503}, str(await svc_answers(bob)))
    ws, msg = await h.open_ws(adm, env.base, str(svc_id))
    check("an administrator opens the service socket during maintenance", msg.type == aiohttp.WSMsgType.TEXT)
    await ws.close()
    async with adm.get(f"{env.base}/api/services") as r:
        listing = {s["name"]: s for s in (await r.json())["services"]}
        check("the service list shows the state", listing["relay1"]["maintenance_active"] is True)
    async with adm.put(f"{env.base}/api/services/{svc_id}", json={"maintenance": False}) as r:
        check("maintenance of a service ends by PUT", r.status == 200)
    async with bob.get(f"{env.base}/terminal/{svc_id}") as r:
        check("... and the member opens it again", r.status == 200)
    rows = await db.get_audit_log(limit=20, action="service.maintenance")
    check("service changes are audited", len(rows) == 3, str(len(rows)))

    # ---- search (the managed service row named searxng) -----------------------------------------------
    sx = await db.create_service("searxng", "/search", plugin="searxng", service_type="managed", host="127.0.0.1", port=8890)
    async with bob.get(f"{env.base}/search/", headers={"Accept": "text/html"}) as r:
        page = await r.text()
        check("search before: the usual page for a search service that is not running",
              r.status == 503 and "down for maintenance" not in page.lower())
    async with adm.put(f"{env.base}/api/services/{sx}", json={"maintenance": True, "maintenance_message": "reindex"}) as r:
        check("an administrator puts the search service in maintenance", r.status == 200)
    async with bob.get(f"{env.base}/search/?q=x", headers={"Accept": "text/html"}) as r:
        page = await r.text()
        check("/search: 503 with the maintenance page and the message",
              r.status == 503 and "Down for maintenance" in page and "reindex" in page and r.headers.get("Retry-After"))
    async with bob.get(f"{env.base}/search/?q=x&format=json") as r:
        check("/search: JSON for format=json", r.status == 503 and (await r.json()).get("maintenance") is True)
    async with adm.get(f"{env.base}/search/", headers={"Accept": "text/html"}) as r:
        check("/search: an administrator gets the usual answer (here: search not running)",
              "Down for maintenance" not in await r.text())

    # ---- every route that reaches a service or a connection has the check ---------------------------------
    routes_check(server.create_app())

    await h.shutdown(env)
    await upstream.close()


# Routes that look up a connection or a service for a member and are NOT entry points to it. Each
# has a reason; a route that is in neither this list nor the checked set fails the test.
EXEMPT = {
    # management of the record itself (the owner or an administrator edits it, nothing is dialled)
    "http_get_service": "reads the record", "http_update_service": "edits the record",
    "http_get_user_connection": "reads the record", "http_update_user_connection": "edits the record",
    "http_service_health": "a status probe a monitor may need during maintenance",
    "http_accept_service_host_key": "admin pins a key", "http_accept_connection_host_key": "owner pins a key",
    "http_remove_connection_share": "a grantee leaves a share",
    "http_shared_app_page": "the first-open notice names the connection and the sharer; it serves no upstream content and dials nothing",
    "http_accept_share_notice": "records the recipient's choice; nothing is dialled",
    "http_vuln_scan_service": "admin scan",
    "http_start_service": "admin control", "http_stop_service": "admin control", "http_restart_service": "admin control",
    "http_start_managed_service": "admin or grantee controls a process, nothing is proxied",
    "http_stop_managed_service": "same", "http_restart_managed_service": "same",
    "http_get_service_logs": "log reading", "http_add_service_grant": "grants",
    "http_add_connection_shares": "sharing", "http_list_connection_shares": "sharing",
    "http_create_user_connection": "looks up the record it just created to set the flag",
    "http_delete_user_connection": "deletes the record", "http_toggle_connection_pin": "a pin on the dashboard",
    "handle_overlay_websocket": "the chat overlay reads one stream's chat for an OBS browser source, nothing is proxied or dialled",
    "http_set_connection_prefs": "a member files a connection on the dashboard, nothing is dialled",
    # the Web Browser on the server (rbrowser): starting a session and the page carry the check (CHECKED below)
    "http_rbrowser_status": "reads a few flags; the dashboard card needs it during maintenance",
    "http_rbrowser_get_session": "reads the member's own existing session; nothing is started",
    "http_rbrowser_delete_session": "a member ends their own session; maintenance must not keep one open",
    "http_rbrowser_resize": "acts on the member's own running session; the attach (websocket_handler) carries the check",
    "http_rbrowser_clipboard": "reads the clipboard of the member's own running session; the attach carries the check",
}
# The routes that carry the check, by handler name.
CHECKED = {
    "http_proxy_connection": "/proxy", "http_browser_page": "/browser", "http_searxng_proxy": "/search",
    "websocket_handler": "/ws", "http_terminal_page": "/terminal", "http_vnc_page": "/vnc",
    "http_media_page": "/media", "http_spice_page": "/spice", "http_proxmox_page": "/proxmox",
    "http_github_page": "/github", "http_connect_user_connection": "/api/connections/{id}/connect",
    "http_rbrowser_page": "/rbrowser", "http_rbrowser_create_session": "/api/rbrowser/session",
}
LOOKUPS = re.compile(r"get_accessible_connection\(|get_service_by_id\(|get_service_for_path\(|get_user_connection\(|"
                     r"_get_sftp_connection\(|get_user_connection_by_uuid\(")
# URL prefixes that mean "a way to use a service or a connection".
PREFIXES = ("/proxy", "/search", "/browser", "/ws", "/terminal", "/vnc", "/media", "/spice", "/proxmox", "/github",
            "/api/sftp/", "/rbrowser", "/api/rbrowser/")


def routes_check(app):
    seen = {}
    for route in app.router.routes():
        info = route.resource.get_info() if route.resource else {}
        path = info.get("path") or info.get("formatter") or ""
        seen.setdefault(route.handler.__name__, set()).add(path)
    # 1. every route under an entry-point prefix is a checked handler (or the chat socket)
    odd = []
    for name, paths in seen.items():
        for path in paths:
            if path.startswith(PREFIXES) and not path.startswith("/api/sftp/vod/") \
                    and name not in CHECKED and name not in EXEMPT:
                src = inspect.getsource(getattr(server, name))
                if "_maintenance_block(" in src or "_get_sftp_connection(" in src or name in ("handle_chat_websocket",):
                    continue
                odd.append((name, path))
    check("routes: every route under /proxy /search /browser /ws /terminal /vnc /media /spice /proxmox /github /api/sftp "
          "has a maintenance check", not odd, str(odd))
    # 2. the checked handlers really call it
    for name in CHECKED:
        src = inspect.getsource(getattr(server, "_proxy_connection_authed" if name == "http_proxy_connection" else name))
        check(f"routes: {name} carries the check",
              "_maintenance_block(" in src or "_ws_maintenance_refusal(" in src, name)
    # 3. any other handler that looks up a connection or a service for a member must carry the check or be exempt
    missing = []
    for name in seen:
        fn = getattr(server, name, None)
        if fn is None or not inspect.iscoroutinefunction(fn):
            continue
        src = inspect.getsource(fn)
        if LOOKUPS.search(src) and not ("_maintenance_block(" in src or "_ws_maintenance_refusal(" in src) \
                and name not in EXEMPT and name not in CHECKED:
            if re.fullmatch(r"http_sftp_(list|read|download|upload|write|mkdir|rename|delete)", name) \
                    and "_get_sftp_connection(" in src:
                continue  # these go through _get_sftp_connection, which has the check
            missing.append(name)
    check("routes: no other handler reaches a connection or service without the check or a stated reason",
          not missing, str(sorted(missing)))
    src = inspect.getsource(server._get_sftp_connection)
    check("routes: the SFTP helper carries the check", "_maintenance_block(" in src)
    for name in ("handle_user_connection_ws", "handle_relay_ws"):
        check(f"routes: {name} keeps its own check after the access check",
              "_ws_refuse_in_maintenance(" in inspect.getsource(getattr(server, name)))
    # 4. the global flag is looked at only by the three HTTP entry points
    users = [n for n in dir(server) if callable(getattr(server, n)) and not n.startswith("__")
             and n not in ("_maintenance_block",)]
    glob = []
    for n in users:
        try:
            src = inspect.getsource(getattr(server, n))
        except (TypeError, OSError):
            continue
        if "use_global=True" in src and n != "_maintenance_block":
            glob.append(n)
    check("routes: only /proxy, /browser, /search and the Web Browser page and start ask for the global flag",
          sorted(glob) == ["_proxy_connection_authed", "http_browser_page", "http_rbrowser_create_session", "http_rbrowser_page",
                           "http_searxng_proxy"], str(sorted(glob)))


def braces_in_names():
    """A name with braces is stored text, not a format template: the 503 page and JSON carry it
    as it is."""
    from aiohttp.test_utils import make_mocked_request
    import html
    until = datetime.now(timezone.utc) + timedelta(hours=2)
    st = {"until": until, "message": ""}
    for name in ("Prod {primary}", "{", "a{0}b", "{name.__class__.__mro__}", "}x{"):
        for path, hdr in (("/proxy/x/", {}), ("/api/x", {"Accept": "application/json"})):
            try:
                resp = server._maintenance_answer(make_mocked_request("GET", path, headers=hdr), name, st)
                ok = resp.status == 503
                body = resp.text if resp.text else ""
                if path == "/api/x":
                    ok = ok and '"maintenance": true' in body
                else:
                    ok = ok and f"<h1>{html.escape(name)} is down for maintenance</h1>" in body \
                        and f"<title>{html.escape(name)} is down for maintenance</title>" in body
            except Exception as e:  # the old code raised KeyError, ValueError or IndexError
                ok = False
                body = f"{type(e).__name__}: {e}"
            check(f"braces: name {name!r} answers 503 with the name as written ({path})", ok, body[:200])


braces_in_names()
asyncio.run(main())
h.finish("test_maintenance")
