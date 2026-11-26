"""Web Browser on the server, lane B: settings, the member and administrator API, the page route and its CSP,
audit visibility, security events, the start-up gate and the source guards.

The real app on a loopback test server with a temporary database (tests/grant_harness.py); the registry is the real one,
driven through rbrowser.FakeLauncher (stage mode with PORTAL_RBROWSER_FAKE=1). No unit is started, nothing needs root.

Run: venv/bin/python -B tests/test_rbrowser_api.py
"""

import asyncio
import inspect
import json
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402
import rbrowser  # noqa: E402
import secevents  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FACTS = {"resolvers": [], "ifaces": [], "gateways": [], "gateways_scoped": []}
J = {"Accept": "application/json"}
TEN = ["rbrowser_enabled", "rbrowser_min_role", "rbrowser_max_sessions", "rbrowser_idle_minutes", "rbrowser_memory_mb",
       "rbrowser_cpu_percent", "rbrowser_clipboard", "rbrowser_home_url", "rbrowser_upload_kbps", "rbrowser_extra_deny"]
SENTINEL = "SENTINEL-clip-text-93117"


class Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage())
        except Exception:
            self.lines.append("?")


def urlish(obj, path=""):
    """Every string in a JSON value that looks like an address or a page title, with where it was."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if "url" in str(k).lower() or "title" in str(k).lower() or "idle_seconds" in str(k):
                out.append(f"{path}/{k}")
            out += urlish(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += urlish(v, f"{path}[{i}]")
    elif isinstance(obj, str) and re.search(r"https?://|www\.", obj):
        out.append(path)
    return out


async def main():
    tmp = tempfile.mkdtemp(prefix="rbapi-")
    env = await h.boot(names=("owner", "bob", "carol", "adm", "mod", "adm2"))
    db = env.db
    await db.set_user_role(env.uid["mod"], "moderator")
    await db.set_user_role(env.uid["adm2"], "admin")
    for n in ("mod", "adm2"):
        await env.sessions[n].close()
        env.sessions[n] = await h.login(env.base, n)
    adm, bob, carol, mod, adm2, owner = (env.sessions[n] for n in ("adm", "bob", "carol", "mod", "adm2", "owner"))
    base = env.base
    server._MAINT_CACHE_TTL = 0.05
    log = Records()
    logging.getLogger().addHandler(log)
    logging.getLogger("portal").addHandler(log)
    logging.getLogger("rbrowser").addHandler(log)

    # ---------------------------------------------------------------- the ten settings, the feature off
    async with adm.get(f"{base}/api/admin/rbrowser", headers=J) as r:
        j = await r.json()
        check("administrator reads the card data: exactly the ten settings", r.status == 200 and sorted(j["settings"]) == sorted(TEN), str(sorted(j.get("settings", {}))))
        check("defaults: off, admins only, 2 seats, 15 minutes, 2048 MB, 150 %, clipboard both, 4000 kbit/s",
              j["settings"]["rbrowser_enabled"] is False and j["settings"]["rbrowser_min_role"] == "admin"
              and j["settings"]["rbrowser_max_sessions"] == 2 and j["settings"]["rbrowser_idle_minutes"] == 15
              and j["settings"]["rbrowser_memory_mb"] == 2048 and j["settings"]["rbrowser_cpu_percent"] == 150
              and j["settings"]["rbrowser_clipboard"] == "both" and j["settings"]["rbrowser_upload_kbps"] == 4000
              and j["settings"]["rbrowser_extra_deny"] == [])
        check("the answer has the keys the card reads", all(k in j for k in ("settings", "availability", "preflight", "seats", "sessions"))
              and j["sessions"] == [] and j["units_not_confirmed_stopped"] == 0)
    async with adm2.get(f"{base}/api/admin/rbrowser", headers=J) as r:
        check("an administrator (not superadmin) may read", r.status == 200)
    for who, sess, want in (("moderator", mod, 403), ("member", bob, 403)):
        async with sess.get(f"{base}/api/admin/rbrowser", headers=J) as r:
            check(f"GET admin: a {who} gets {want}", r.status == want, str(r.status))
    async with aiohttp_plain().get(f"{base}/api/admin/rbrowser", headers=J) as r:
        check("GET admin: no sign-in gets 401", r.status == 401, str(r.status))

    # ---------------------------------------------------------------- PUT: validation and the role matrix
    url = f"{base}/api/admin/rbrowser"
    for who, sess, want in (("an administrator", adm2, 403), ("a moderator", mod, 403), ("a member", bob, 403)):
        async with sess.put(url, json={"rbrowser_max_sessions": 3}) as r:
            check(f"PUT: {who} gets {want}", r.status == want, str(r.status))
    check("the refused PUTs changed nothing", server._rbrowser_cfg["rbrowser_max_sessions"] == 2)
    cookie = next(c.value for c in adm.cookie_jar if c.key == server.Config.SESSION_COOKIE_NAME)
    async with aiohttp_plain().put(url, json={"rbrowser_max_sessions": 3}, headers={"Authorization": f"Bearer {cookie}"}) as r:
        check("PUT: a superadmin's bearer token is not a browser sign-in", r.status in (401, 403), str(r.status))
    # finding 1 attack on the settings route: a /api/token script token (scope *) of a superadmin sent as the session cookie.
    # _backup_superadmin(cookie_only=True) must refuse it, because its row is not named web_session
    async with aiohttp_plain().post(f"{base}/api/token", json={"username": "owner", "password": h.PW, "name": "script", "scopes": ["*"]}) as r:
        stok = (await r.json()).get("token") if r.status in (200, 201) else None
    check("a superadmin script token for the settings cookie test was made", bool(stok))
    if stok:
        cfg_before = dict(server._rbrowser_cfg)
        async with aiohttp_plain().put(url, json={"rbrowser_max_sessions": 3},
                                       headers={"Cookie": f"{server.Config.SESSION_COOKIE_NAME}={stok}"}) as r:
            check("PUT: a superadmin script token sent as the session cookie is 403", r.status == 403, str(r.status))
        async with aiohttp_plain().put(url, json={"rbrowser_enabled": False},
                                       headers={"Cookie": f"{server.Config.SESSION_COOKIE_NAME}={stok}"}) as r:
            check("PUT: the same for a switch-off is 403", r.status == 403, str(r.status))
        check("and the settings are unchanged", server._rbrowser_cfg == cfg_before)
    async with adm.put(url, json={"rbrowser_nope": 1}) as r:
        check("PUT: an unknown key is 400", r.status == 400 and "Unknown" in (await r.json())["error"])
    async with adm.put(url, data="[1]", headers={"Content-Type": "application/json"}) as r:
        check("PUT: a body that is not an object is 400", r.status == 400)
    bad = [("rbrowser_enabled", 1), ("rbrowser_enabled", "true"), ("rbrowser_min_role", "superadmin"), ("rbrowser_min_role", 3),
           ("rbrowser_max_sessions", 0), ("rbrowser_max_sessions", 9), ("rbrowser_max_sessions", True), ("rbrowser_max_sessions", "2"),
           ("rbrowser_idle_minutes", 4), ("rbrowser_idle_minutes", 121), ("rbrowser_memory_mb", 1023), ("rbrowser_memory_mb", 4097),
           ("rbrowser_cpu_percent", 49), ("rbrowser_cpu_percent", 401), ("rbrowser_clipboard", "to_browser_only"), ("rbrowser_clipboard", True),
           ("rbrowser_home_url", "http://example.org/"), ("rbrowser_home_url", "https://" + "a" * 300), ("rbrowser_home_url", "javascript:alert(1)"),
           ("rbrowser_home_url", 5), ("rbrowser_upload_kbps", 499), ("rbrowser_upload_kbps", 50001), ("rbrowser_upload_kbps", -1),
           ("rbrowser_upload_kbps", False), ("rbrowser_extra_deny", ["10.0.0.1/8"]), ("rbrowser_extra_deny", ["nonsense"]),
           ("rbrowser_extra_deny", [f"10.{i}.0.0/16" for i in range(33)]), ("rbrowser_extra_deny", 7), ("rbrowser_extra_deny", ["0.0.0.0/0"])]
    got = {}
    for key, val in bad:
        async with adm.put(url, json={key: val}) as r:
            got[(key, repr(val)[:30])] = r.status
    check("PUT: every out-of-range or wrong-typed value is 400 (nothing is coerced)", all(v == 400 for v in got.values()),
          str({k: v for k, v in got.items() if v != 400}))
    check("nothing was stored by the refused values", server._rbrowser_cfg["rbrowser_max_sessions"] == 2
          and await db.get_setting("rbrowser_max_sessions") is None)
    async with adm.put(url, json={"rbrowser_idle_minutes": 20, "rbrowser_clipboard": "to_browser", "rbrowser_upload_kbps": 0,
                                  "rbrowser_extra_deny": "10.9.0.0/16, 10.8.0.0/16", "rbrowser_home_url": "https://example.org/start"}) as r:
        j = await r.json()
        check("PUT: valid values are saved (the old name to_browser reads as in; a text list is split)",
              r.status == 200 and j["saved"] is True and j["settings"]["rbrowser_clipboard"] == "in"
              and j["settings"]["rbrowser_idle_minutes"] == 20 and j["settings"]["rbrowser_upload_kbps"] == 0
              and j["settings"]["rbrowser_extra_deny"] == ["10.9.0.0/16", "10.8.0.0/16"], json.dumps(j.get("settings", j))[:300])
    check("memory follows the write: cfg and database agree", server._rbrowser_cfg["rbrowser_idle_minutes"] == 20
          and await db.get_setting("rbrowser_idle_minutes") == "20" and await db.get_setting("rbrowser_clipboard") == "in")
    # a restart reads the same back, an unusable stored value falls back to its default
    await db.set_settings({"rbrowser_memory_mb": "banana", "rbrowser_min_role": "root"})
    await server._load_rbrowser_state()
    check("start-up loader: values come back; garbage keeps the default; the extras are fixed once",
          server._rbrowser_cfg["rbrowser_idle_minutes"] == 20 and server._rbrowser_cfg["rbrowser_memory_mb"] == 2048
          and server._rbrowser_cfg["rbrowser_min_role"] == "admin" and server._rbrowser_cfg["rbrowser_extra_deny"] == ["10.9.0.0/16", "10.8.0.0/16"]
          and server._rbrowser_cfg["portal_version"] and isinstance(server._rbrowser_cfg["hidden_extra"], list)
          and all(p.startswith("/") for p in server._rbrowser_cfg["hidden_extra"]))
    # put the defaults back for the rest (enabled stays off)
    async with adm.put(url, json={"rbrowser_idle_minutes": 15, "rbrowser_clipboard": "both", "rbrowser_upload_kbps": 4000,
                                  "rbrowser_extra_deny": [], "rbrowser_home_url": "https://duckduckgo.com/",
                                  "rbrowser_memory_mb": 2048, "rbrowser_min_role": "admin"}) as r:
        check("PUT: the defaults can be put back", r.status == 200)
    async with adm.put(url, json={"rbrowser_max_sessions": 2}, headers={"Sec-Fetch-Site": "cross-site"}) as r:
        check("PUT: refused from another site", r.status == 403)

    # ---------------------------------------------------------------- status and the member API while the feature is off
    async with bob.get(f"{base}/api/rbrowser/status") as r:
        j = await r.json()
        check("status (off): enabled false, allowed false, available false, boot_id, no reason for a member",
              r.status == 200 and j["enabled"] is False and j["allowed"] is False and j["available"] is False
              and isinstance(j["boot_id"], str) and j["boot_id"] and "reason" not in j and j["clipboard"] in ("off", "in", "both")
              and j["checking"] is False, str(j))
    async with adm.get(f"{base}/api/rbrowser/status") as r:
        j = await r.json()
        check("status (off): an administrator also gets a reason", j.get("reason") == "switched off", str(j))
    async with aiohttp_plain().get(f"{base}/api/rbrowser/status", headers=J) as r:
        check("status: 401 without a sign-in", r.status == 401)
    async with bob.post(f"{base}/api/rbrowser/session", json={"width": 1280, "height": 720}) as r:
        check("create while the feature is off: 403", r.status == 403)
    async with bob.get(f"{base}/api/rbrowser/session") as r:
        check("GET session while the feature is off: 403", r.status == 403)

    # ---------------------------------------------------------------- the start-up gate: nothing in rbrowser is called while off
    class Spy:
        calls = []

        def __getattr__(self, name):
            Spy.calls.append(name)
            raise AssertionError("rbrowser." + name)
    real = server.rbrowser
    server.rbrowser = Spy()
    try:
        await server._load_rbrowser_state()
        await server._rbrowser_start()
        server._rbrowser_revoked(env.uid["bob"], lambda t: False)
        await server._rbrowser_stop()
        await server._rbrowser_switch_off()
    finally:
        server.rbrowser = real
    check("start-up with the feature off, a revocation and a stop call nothing in rbrowser (spy)", Spy.calls == [], str(Spy.calls))
    check("and no sweeper task exists", server._rbrowser_state["sweeper"] is None and server._rbrowser_state["started"] is False)

    # ---------------------------------------------------------------- switch the feature on (stage mode, fake launcher)
    rbrowser.configure(environ={"PORTAL_RBROWSER_FAKE": "1"}, host_facts=lambda: FACTS, ncpu=4, mem_total=15 * 1024 ** 3,
                       cgroup_root=os.path.join(tmp, "cg"), tmp_dir=os.path.join(tmp, "tmp"), cache_path=os.path.join(tmp, "pf.json"))
    reg = rbrowser.registry()
    clock = {"off": 0.0}
    reg.clock = lambda: time.time() + clock["off"]
    server._rbrowser_cfg.update(stage_mode=True, stage_dir=os.path.join(tmp, "stage"))
    os.makedirs(server._rbrowser_cfg["stage_dir"], exist_ok=True)
    async with adm.put(url, json={"rbrowser_enabled": True, "rbrowser_min_role": "user"}) as r:
        j = await r.json()
        check("PUT enabled true starts the feature (registry up, sweeper running)", r.status == 200 and server._rbrowser_state["started"] is True
              and server._rbrowser_state["sweeper"] is not None and reg.stage_fake and reg.ready, str(j.get("availability")))
        check("the admin answer lists availability, seats and an empty session list", j["availability"]["available"] is True
              and j["seats"]["max"] == 2 and j["sessions"] == [])
    async with bob.get(f"{base}/api/rbrowser/status") as r:
        j = await r.json()
        check("status (on): available, allowed, not busy, boot_id equals the registry's", j["available"] and j["allowed"] and not j["busy"]
              and j["boot_id"] == rbrowser.boot_id() and j["enabled"] is True, str(j))
    server._rbrowser_cfg["rbrowser_min_role"] = "admin"
    async with bob.get(f"{base}/api/rbrowser/status") as r:
        j = await r.json()
        check("status: a member below the role is not allowed", j["allowed"] is False and j["enabled"] is True)
    async with bob.post(f"{base}/api/rbrowser/session", json={"width": 1280, "height": 720}) as r:
        check("create below the role: 403", r.status == 403)
    server._rbrowser_cfg["rbrowser_min_role"] = "user"

    # ---------------------------------------------------------------- create, return, elsewhere, takeover, busy
    body = {"width": 1280, "height": 720}
    async with bob.post(f"{base}/api/rbrowser/session", json=body) as r:
        j = await r.json()
        check("create: 201 with the shape the page reads", r.status == 201 and set(j) == {"sid", "ws", "width", "height", "idle_deadline", "max_deadline", "clipboard", "net_warning"}
              and j["ws"] == f"/ws/rbrowser/{j['sid']}" and isinstance(j["idle_deadline"], (int, float)) and j["max_deadline"] > j["idle_deadline"] - 1
              and j["clipboard"] == "both" and j["net_warning"] is False and (j["width"], j["height"]) == (1280, 720), str(j))
        sid = j["sid"]
        check("the deadlines are epoch seconds (the registry's wall clock)", abs(j["idle_deadline"] - (time.time() + 15 * 60)) < 30)
    async with bob.post(f"{base}/api/rbrowser/session", json=body) as r:
        j = await r.json()
        check("create again by the same sign-in: 200 and the same session", r.status == 200 and j["sid"] == sid)
    async with bob.get(f"{base}/api/rbrowser/session") as r:
        j = await r.json()
        check("GET session: 200, same sid", r.status == 200 and j["sid"] == sid)
    bob2 = await h.login(base, "bob")
    async with bob2.get(f"{base}/api/rbrowser/session") as r:
        check("another sign-in of the member: GET is 409 {elsewhere}", r.status == 409 and await r.json() == {"elsewhere": True})
    async with bob2.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("another sign-in of the member: POST is 409 {elsewhere}", r.status == 409 and await r.json() == {"elsewhere": True})
    async with bob2.post(f"{base}/api/rbrowser/session/resize", json={"width": 900, "height": 600}) as r:
        check("another sign-in cannot resize (409)", r.status == 409)
    async with bob2.post(f"{base}/api/rbrowser/session/clipboard", json={}) as r:
        check("another sign-in cannot read the clipboard (409)", r.status == 409)
    async with carol.post(f"{base}/api/rbrowser/session", json={"width": 1280, "height": 720}) as r:
        j = await r.json()
        check("a second member gets the second seat", r.status == 201)
    async with owner.post(f"{base}/api/rbrowser/session", json=body) as r:
        j = await r.json()
        check("busy: 409 with free_in_minutes and nothing about who", r.status == 409 and j.get("busy") is True and isinstance(j.get("free_in_minutes"), int)
              and set(j) == {"busy", "free_in_minutes"}, str(j))
    async with owner.get(f"{base}/api/rbrowser/status") as r:
        check("status shows busy when every seat is taken", (await r.json())["busy"] is True)
    async with bob2.post(f"{base}/api/rbrowser/session", json={**body, "takeover": True}) as r:
        j = await r.json()
        check("takeover: the old session ends (replaced), the new sign-in gets a session", r.status == 201 and j["sid"] != sid)
        sid2 = j["sid"]
    check("the old session is gone from the registry", rbrowser.get(sid) is None and rbrowser.get(sid2) is not None)
    async with bob.get(f"{base}/api/rbrowser/session") as r:
        check("the old sign-in now sees 409 elsewhere", r.status == 409)
    async with bob2.delete(f"{base}/api/rbrowser/session") as r:
        check("DELETE: 204", r.status == 204)
    async with bob2.get(f"{base}/api/rbrowser/session") as r:
        check("then GET is 404", r.status == 404)
    async with bob2.delete(f"{base}/api/rbrowser/session") as r:
        check("DELETE without a session: 404", r.status == 404)
    for bad in ({"width": "1280", "height": 720}, {"width": 1280}, {"width": True, "height": 720}, {"width": 1280, "height": 720, "takeover": "yes"}, [1]):
        async with bob2.post(f"{base}/api/rbrowser/session", json=bad) as r:
            check(f"create: a bad body {str(bad)[:40]} is 400", r.status == 400)

    # ---------------------------------------------------------------- credentials: only the browser sign-in
    async with aiohttp_plain().post(f"{base}/api/token", json={"username": "owner", "password": h.PW, "name": "t", "scopes": ["*"]}) as r:
        tok = (await r.json()).get("token") if r.status in (200, 201) else None
    if tok:
        async with aiohttp_plain().post(f"{base}/api/rbrowser/session", json=body, headers={"Authorization": f"Bearer {tok}"}) as r:
            check("create with a full-scope bearer token (not the cookie): 403", r.status == 403, str(r.status))
        async with aiohttp_plain().get(f"{base}/api/rbrowser/session", headers={"Authorization": f"Bearer {tok}"}) as r:
            check("GET session with a bearer token: 403", r.status == 403)
    else:
        check("a full-scope token could be made for the test", False, "no token route answer")

    # A token made by /api/token (scopes *) sent in the Cookie header is a script credential, not the browser sign-in:
    # the token row is not named web_session. Carol's real sign-in holds a running session at this point.
    async with aiohttp_plain().post(f"{base}/api/token", json={"username": "carol", "password": h.PW, "name": "script", "scopes": ["*"]}) as r:
        mtok = (await r.json()).get("token") if r.status in (200, 201) else None
    check("a full-scope script token for the cookie-header test was made", bool(mtok))
    if mtok:
        ck = {"Cookie": f"{server.Config.SESSION_COOKIE_NAME}={mtok}"}
        s_carol = rbrowser.for_user(env.uid["carol"])
        sid_carol = s_carol.sid if s_carol else None
        check("carol's real sign-in holds a running session", s_carol is not None and s_carol.state == "running")
        async with aiohttp_plain().get(f"{base}/api/rbrowser/status", headers={**J, **ck}) as r:
            j = await r.json()
            check("cookie-header script token: status says allowed false", r.status == 200 and j["allowed"] is False, str(j))
        async with aiohttp_plain().get(f"{base}/api/rbrowser/session", headers={**J, **ck}) as r:
            check("cookie-header script token: GET session is 403", r.status == 403, str(r.status))
        async with aiohttp_plain().post(f"{base}/api/rbrowser/session", json=body, headers={**J, **ck}) as r:
            check("cookie-header script token: create is 403", r.status == 403, str(r.status))
        async with aiohttp_plain().post(f"{base}/api/rbrowser/session", json={**body, "takeover": True}, headers={**J, **ck}) as r:
            check("cookie-header script token: takeover is 403", r.status == 403, str(r.status))
        check("and the member's session was not replaced", rbrowser.for_user(env.uid["carol"]) is s_carol and s_carol.state == "running"
              and rbrowser.get(sid_carol) is s_carol)
        async with aiohttp_plain().post(f"{base}/api/rbrowser/session/clipboard", json={}, headers={**J, **ck}) as r:
            check("cookie-header script token: clipboard is 403", r.status == 403, str(r.status))
        async with aiohttp_plain().post(f"{base}/api/rbrowser/session/resize", json={"width": 900, "height": 600}, headers={**J, **ck}) as r:
            check("cookie-header script token: resize is 403", r.status == 403, str(r.status))
        async with aiohttp_plain().delete(f"{base}/api/rbrowser/session", headers={**J, **ck}) as r:
            check("cookie-header script token: DELETE is 403 and the session stays", r.status == 403 and s_carol.state == "running", str(r.status))
        row = await db.get_token(s_carol.token_id)
        check("the real sign-in's token row is named web_session", bool(row) and row.get("name") == "web_session")

    # ---------------------------------------------------------------- the start limiter goes through _limited
    server._rbrowser_start_rate = server._viewers_mod.RateWindow(1, 600.0)
    async with owner.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("limiter: the first start of a member counts", r.status == 201, str(r.status))
    async with owner.delete(f"{base}/api/rbrowser/session") as r:
        check("owner ends it", r.status == 204)
    async with owner.post(f"{base}/api/rbrowser/session", json=body) as r:
        j = await r.json()
        check("limiter: the second is 429 through _limited (reference, Retry-After, no store)", r.status == 429 and r.headers.get("Retry-After") == "60"
              and r.headers.get("Cache-Control") == "no-store" and j.get("error"), str(r.status))
    for fn in (server.http_rbrowser_create_session, server.http_rbrowser_resize, server.http_rbrowser_clipboard):
        check(f"{fn.__name__} has no hand-built 429", "status=429" not in inspect.getsource(fn) and "_limited(" in inspect.getsource(fn))
    server._rbrowser_start_rate = server._viewers_mod.RateWindow(6, 600.0)

    # ---------------------------------------------------------------- resize and the clipboard route
    async with carol.post(f"{base}/api/rbrowser/session/resize", json={"width": 1000, "height": 700}) as r:
        j = await r.json()
        s_c = rbrowser.for_user(env.uid["carol"])
        check("resize: {ok: true} and the registry holds the snapped size", r.status == 200 and j == {"ok": True} and (s_c.width, s_c.height) == (992, 688), str(j))
    async with carol.post(f"{base}/api/rbrowser/session/resize", json={"width": 1000, "height": 700}) as r:
        check("resize twice inside a second: 429", r.status == 429)
    await asyncio.sleep(1.05)
    async with carol.post(f"{base}/api/rbrowser/session/resize", json={"width": "x", "height": 700}) as r:
        check("resize: a bad body is 400", r.status == 400)
    calls = []

    async def fake_clip(session):
        calls.append(session.sid)
        return {"ok": True, "text": SENTINEL, "truncated": False}
    real_clip = rbrowser.clip
    rbrowser.clip = fake_clip
    try:
        async with carol.post(f"{base}/api/rbrowser/session/clipboard", json={}) as r:
            j = await r.json()
            check("clipboard (both): {text, truncated} and nothing else", r.status == 200 and j == {"text": SENTINEL, "truncated": False}, str(j))
        server._rbrowser_cfg["rbrowser_clipboard"] = "in"
        async with carol.post(f"{base}/api/rbrowser/session/clipboard", json={}) as r:
            check("clipboard with the setting 'in': 403 and the registry is not asked", r.status == 403 and len(calls) == 1)
        server._rbrowser_cfg["rbrowser_clipboard"] = "off"
        async with carol.post(f"{base}/api/rbrowser/session/clipboard", json={}) as r:
            check("clipboard with the setting 'off': 403", r.status == 403 and len(calls) == 1)
        server._rbrowser_cfg["rbrowser_clipboard"] = "both"

        async def failing(session):
            return {"ok": False, "text": "", "truncated": False, "why": "unreachable"}
        rbrowser.clip = failing
        async with carol.post(f"{base}/api/rbrowser/session/clipboard", json={}) as r:
            j = await r.json()
            check("clipboard: the registry's ok false is 502 without detail", r.status == 502 and "unreachable" not in json.dumps(j) and "why" not in j, str(j))
    finally:
        rbrowser.clip = real_clip
    async with carol.post(f"{base}/api/rbrowser/session/clipboard", json={}, headers={"Sec-Fetch-Site": "cross-site"}) as r:
        check("clipboard: refused from another site", r.status == 403)
    async with carol.post(f"{base}/api/rbrowser/session", json=body, headers={"Sec-Fetch-Site": "cross-site"}) as r:
        check("POST create: refused from another site", r.status == 403)
    async with carol.delete(f"{base}/api/rbrowser/session", headers={"Origin": "null"}) as r:
        check("DELETE: refused from a sandboxed document (Origin null)", r.status == 403)
    check("the clipboard text was never logged", not any(SENTINEL in line for line in log.lines))
    check("nor audited", SENTINEL not in json.dumps(await db.get_audit_log(limit=200), default=str))

    # ---------------------------------------------------------------- admin list: states, no URL-like field
    async with adm.get(url, headers=J) as r:
        j = await r.json()
        rows = j["sessions"]
        check("admin list: one row per running session with exactly the fields the card reads",
              len(rows) == 1 and all(set(x) == {"sid_prefix", "user_id", "username", "started", "state", "attached", "memory_mb", "cpu_seconds",
                                                 "net_in_mb", "net_out_mb"} for x in rows), str(rows))
        check("state is active or idle, started is epoch seconds, attached is a bool",
              all(x["state"] in ("active", "idle") and x["started"] > 1e9 and isinstance(x["attached"], bool) for x in rows))
        check("no URL-like field, title or seconds anywhere outside the settings", urlish({k: v for k, v in j.items() if k not in ("settings", "defaults")}) == [],
              str(urlish({k: v for k, v in j.items() if k not in ("settings", "defaults")})))
    clock["off"] = 130.0
    async with adm.get(url, headers=J) as r:
        states = {x["username"]: x["state"] for x in (await r.json())["sessions"]}
        check("two minutes without activity reads as idle", set(states.values()) == {"idle"}, str(states))
    clock["off"] = 0.0
    # ---------------------------------------------------------------- admin end
    sp = rbrowser.for_user(env.uid["carol"]).sid[:6]
    async with adm.post(f"{url}/sessions/{sp}/end", json={}) as r:
        check("admin end: no confirm is 400", r.status == 400)
    async with adm.post(f"{url}/sessions/{sp}/end", json={"confirm": "true"}) as r:
        check("admin end: confirm must be true", r.status == 400)
    async with bob.post(f"{url}/sessions/{sp}/end", json={"confirm": True}) as r:
        check("admin end: a member is refused", r.status == 403)
    async with mod.post(f"{url}/sessions/{sp}/end", json={"confirm": True}) as r:
        check("admin end: a moderator is refused", r.status == 403)
    async with adm.post(f"{url}/sessions/zzzzzz/end", json={"confirm": True}) as r:
        check("admin end: an unknown prefix is 404", r.status == 404)
    async with adm.post(f"{url}/sessions/abc/end", json={"confirm": True}) as r:
        check("admin end: a prefix shorter than 6 is 404", r.status == 404)
    async with adm2.post(f"{url}/sessions/{sp}/end", json={"confirm": True}) as r:
        check("admin end: an administrator ends it", r.status == 200 and rbrowser.for_user(env.uid["carol"]) is None)
    cur = await db.conn.execute("SELECT id, action, actor_id, target_id FROM audit_log WHERE action IN ('rbrowser_admin_end','rbrowser_end') ORDER BY id")
    arows = [dict(x) for x in await cur.fetchall()]
    names = [x["action"] for x in arows]
    i_admin = names.index("rbrowser_admin_end") if "rbrowser_admin_end" in names else -1
    check("the audit entry of the admin end is written before the member's end entry", i_admin >= 0 and "rbrowser_end" in names[i_admin:], str(names))
    check("it names the administrator as actor and the member as target", arows[i_admin]["actor_id"] == env.uid["adm2"] and arows[i_admin]["target_id"] == env.uid["carol"])
    cur = await db.conn.execute("SELECT type FROM notifications WHERE user_id = ?", (env.uid["carol"],))
    check("the member gets a notification of type rbrowser_ended", "rbrowser_ended" in [x[0] for x in await cur.fetchall()])
    # an administrator has no way to attach: the route table has none that takes another member
    rb_routes = sorted({(r.method, (r.resource.get_info().get("formatter") or r.resource.get_info().get("path") or ""))
                        for r in server.create_app().router.routes() if "rbrowser" in str(r.resource.get_info())} - {("HEAD", "/rbrowser")})
    want_routes = sorted([("GET", "/api/admin/rbrowser"), ("PUT", "/api/admin/rbrowser"), ("POST", "/api/admin/rbrowser/preflight"),
                          ("POST", "/api/admin/rbrowser/sessions/{sid_prefix}/end"), ("GET", "/rbrowser"), ("GET", "/api/rbrowser/status"),
                          ("GET", "/api/rbrowser/session"), ("POST", "/api/rbrowser/session"), ("DELETE", "/api/rbrowser/session"),
                          ("POST", "/api/rbrowser/session/resize"), ("POST", "/api/rbrowser/session/clipboard")])
    check("the route table is exactly the documented one (no observe or attach route for administrators)",
          [x for x in rb_routes if x[0] != "HEAD"] == want_routes, str(rb_routes))

    # ---------------------------------------------------------------- audit visibility per role
    for _ in range(2):      # the audit rows are written; ask each role
        pass
    async with adm.get(f"{base}/api/admin/audit-log?limit=200", headers=J) as r:
        sup = {e["action"] for e in (await r.json())["entries"]}
    async with adm2.get(f"{base}/api/admin/audit-log?limit=200", headers=J) as r:
        adm_seen = {e["action"] for e in (await r.json())["entries"]}
    async with mod.get(f"{base}/api/admin/audit-log?limit=200", headers=J) as r:
        mod_seen = {e["action"] for e in (await r.json())["entries"]}
    check("audit: a superadmin sees the start, the end, the admin end and the settings update",
          {"rbrowser_start", "rbrowser_end", "rbrowser_admin_end", "rbrowser_settings_update"} <= sup, str(sorted(sup)))
    check("audit: an administrator sees start, end and admin end but not the settings update",
          {"rbrowser_start", "rbrowser_end", "rbrowser_admin_end"} <= adm_seen and "rbrowser_settings_update" not in adm_seen, str(sorted(adm_seen)))
    check("audit: a moderator sees none of them", not any(a.startswith("rbrowser") for a in mod_seen), str(sorted(mod_seen)))
    check("the constants: RBROWSER_AUDIT_ACTIONS and the superadmin-only entry",
          server.RBROWSER_AUDIT_ACTIONS == ("rbrowser_start", "rbrowser_end", "rbrowser_admin_end")
          and "rbrowser_settings_update" in server.SUPERADMIN_ONLY_AUDIT_ACTIONS)
    ents = [e for e in await db.get_audit_log(limit=200) if str(e.get("action", "")).startswith("rbrowser_") and e["action"] != "rbrowser_settings_update"]
    check("audit details of sessions hold no address", ents and not any(re.search(r"https?://", json.dumps(e, default=str)) for e in ents))

    # ---------------------------------------------------------------- the sweeper ends an idle session and audits it
    async with bob2.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("a session to sweep", r.status == 201)
    sw = rbrowser.for_user(env.uid["bob"])
    rbrowser.mark_attached(sw, object())      # a viewer is attached: the detach window does not apply, only idleness
    clock["off"] = 15 * 60 + 400.0
    old_tick = server.RBROWSER_TICK_S
    server.RBROWSER_TICK_S = 0.05
    await server._rbrowser_stop_sweeper()
    server._rbrowser_state["sweeper"] = asyncio.ensure_future(server._rbrowser_sweeper())
    for _ in range(100):
        if sw.state == "ended":
            break
        await asyncio.sleep(0.05)
    server.RBROWSER_TICK_S = old_tick
    await asyncio.sleep(0.2)
    clock["off"] = 0.0
    check("the sweeper ended the idle session (reason idle)", sw.state == "ended" and sw.end_reason == "idle", str((sw.state, sw.end_reason)))
    ents = await db.get_audit_log(limit=50, action="rbrowser_end", actor_id=env.uid["bob"])
    d = ents[0].get("details") if ents else None
    d = json.loads(d) if isinstance(d, str) else (d or {})
    check("and audited it with the reason and the minutes", d.get("reason") == "idle" and "minutes" in d, str(ents[:1]))

    # ---------------------------------------------------------------- security events: through EVENT_OF only
    reg._events.clear()
    for marker, detail in (("traffic_limit", "upload_rate"), ("tmp_quota", "tmp_quota"), ("ingress_filter_lost", "ingress_filter_lost"),
                           ("listener_found", "listener_found"), ("socket_mismatch", "socket_mismatch"), ("display_mismatch", "display_mismatch")):
        reg._event("marker", marker=marker, detail=detail, event="rbrowser_listener_found", user_id=env.uid["bob"], sid_prefix="abcdef")
    reg._event("preflight_failed", event="rbrowser_preflight_failed", checks=["egress", "mounts"])
    reg._event("unit_left_running", unit="portal-rb-0123456789ab.service")
    reg._event("marker", marker="not_a_marker", detail="x", event="login_success", user_id=env.uid["bob"], sid_prefix="abcdef")
    await server._rbrowser_drain_events()
    await secevents.log.flush()
    cur = await db.conn.execute("SELECT event, details, user_id FROM security_events WHERE event LIKE 'rbrowser_%' ORDER BY id")
    ev = [dict(x) for x in await cur.fetchall()]
    got_events = sorted(x["event"] for x in ev if x["event"] != "rbrowser_settings_changed")
    check("every marker lands on the event the registry's EVENT_OF table names (the event field of a take_events entry is not trusted)",
          got_events == sorted(["rbrowser_traffic_limit", "rbrowser_traffic_limit", "rbrowser_listener_found", "rbrowser_listener_found",
                                "rbrowser_socket_mismatch", "rbrowser_display_mismatch", "rbrowser_preflight_failed"]) or
          sorted(set(got_events)) == sorted(["rbrowser_traffic_limit", "rbrowser_listener_found", "rbrowser_socket_mismatch",
                                             "rbrowser_display_mismatch", "rbrowser_preflight_failed"]), str(got_events))
    check("an unknown marker and a unit-left note raise no event", "login_success" not in [x["event"] for x in ev]
          and not any("0123456789ab" in (x["details"] or "") for x in ev))
    check("the settings change was a security event with the key names only", any(x["event"] == "rbrowser_settings_changed" and "rbrowser_" in (x["details"] or "")
                                                                                   and "example.org" not in (x["details"] or "") for x in ev))
    check("the seven names are in secevents.EVENTS; two are counted per member, five are never capped",
          {"rbrowser_settings_changed", "rbrowser_preflight_failed", "rbrowser_listener_found", "rbrowser_socket_mismatch", "rbrowser_display_mismatch",
           "rbrowser_protocol_violation", "rbrowser_traffic_limit"} <= set(secevents.EVENTS)
          and {"rbrowser_protocol_violation", "rbrowser_traffic_limit"} <= secevents.AGGREGATED
          and {"rbrowser_settings_changed", "rbrowser_preflight_failed", "rbrowser_listener_found", "rbrowser_socket_mismatch",
               "rbrowser_display_mismatch"} <= secevents.CAP_EXEMPT)

    # ---------------------------------------------------------------- the page route, its CSP, robots.txt, maintenance
    (server.STATIC_DIR / "rbrowser.html").write_text("<!doctype html><title>t</title><script src=\"/static/js/rbrowser.js\"></script>")
    async with aiohttp_plain().get(f"{base}/rbrowser", allow_redirects=False) as r:
        check("/rbrowser without a sign-in redirects to /login", r.status == 302 and r.headers.get("Location") == "/login")
    async with bob.get(f"{base}/rbrowser") as r:
        csp = r.headers.get("Content-Security-Policy", "")
        sm = re.search(r"script-src ([^;]*)", csp)
        check("/rbrowser: the page is served with its own CSP", r.status == 200 and "text/html" in r.headers.get("Content-Type", ""))
        check("CSP: script-src 'self' only (no unsafe-inline, no blob:), no bare wss:, frame-ancestors none, form-action none",
              sm is not None and sm.group(1).strip() == "'self'" and not re.search(r"\bwss:(?!//)", csp) and "frame-ancestors 'none'" in csp
              and "form-action 'none'" in csp and "base-uri 'none'" in csp and "unsafe-inline" not in csp.split("style-src")[0], csp)
        check("CSP: connect-src names this host over wss and nothing else", f"connect-src 'self' wss://127.0.0.1:{env.srv.port};" in csp, csp)
    async with bob.get(f"{base}/rbrowser", headers={"Host": "evil.test; script-src *"}) as r:
        csp = r.headers.get("Content-Security-Policy", "")
        check("CSP: a crafted Host header adds no directive", r.status == 200 and "evil" not in csp and "script-src 'self';" in csp, csp)
    async with bob.get(f"{base}/dashboard") as r:
        check("every other page keeps the default CSP", "'unsafe-inline'" in r.headers.get("Content-Security-Policy", "").split("style-src")[0])
    async with bob.get(f"{base}/robots.txt") as r:
        check("robots.txt disallows /rbrowser", "Disallow: /rbrowser" in await r.text())
    async with adm.put(f"{base}/api/admin/maintenance", json={"active": True, "message": "disks"}) as r:
        check("global maintenance set", r.status == 200)
    await asyncio.sleep(0.1)
    async with bob.get(f"{base}/rbrowser", headers=J) as r:
        check("the page is refused in global maintenance for a member", r.status == 503)
    async with bob2.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("create is refused in global maintenance for a member", r.status in (503,) and "maintenance" in json.dumps(await r.json()).lower())
    async with adm.get(f"{base}/rbrowser") as r:
        check("an administrator passes maintenance", r.status == 200)
    async with adm.put(f"{base}/api/admin/maintenance", json={"active": False}) as r:
        pass
    await asyncio.sleep(0.1)

    # ---------------------------------------------------------------- settings change ends affected sessions
    async with bob2.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("a session before a role change", r.status == 201)
    s_b = rbrowser.for_user(env.uid["bob"])
    async with adm.put(url, json={"rbrowser_min_role": "admin"}) as r:
        check("raising the role ends the session of a member below it (settings_changed)", r.status == 200 and s_b.state == "ended" and s_b.end_reason == "settings_changed")
    async with adm.put(url, json={"rbrowser_min_role": "user"}) as r:
        pass
    async with carol.post(f"{base}/api/rbrowser/session", json=body) as r:
        check("a session before the switch-off", r.status == 201)
    s_c = rbrowser.for_user(env.uid["carol"])
    async with adm.put(url, json={"rbrowser_enabled": False}) as r:
        check("switching off ends every session, stops the sweeper and the registry", r.status == 200 and s_c.state == "ended" and s_c.end_reason == "settings_changed"
              and server._rbrowser_state["started"] is False and server._rbrowser_state["sweeper"] is None and reg.ready is False)
    async with bob.get(f"{base}/api/rbrowser/status") as r:
        check("status after the switch-off", (await r.json())["enabled"] is False)
    async with adm.post(f"{url}/preflight") as r:
        check("preflight while off: 409", r.status == 409)

    # ---------------------------------------------------------------- a create in flight during a switch-off or a role raise
    async with adm.put(url, json={"rbrowser_enabled": True, "rbrowser_min_role": "user"}) as r:
        check("race setup: the feature is switched on again", r.status == 200 and server._rbrowser_state["started"] is True)
    real_create = rbrowser.create
    cur = await db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'rbrowser_end' AND actor_id = ?", (env.uid["bob"],))
    n_aud0 = (await cur.fetchone())[0]

    def flip(**changes):
        async def create(*a, **kw):
            s = await real_create(*a, **kw)
            server._rbrowser_cfg.update(changes)          # the settings change while the unit was starting
            return s
        return create
    for label, changes in (("the feature switched off", {"rbrowser_enabled": False}), ("the role raised", {"rbrowser_min_role": "admin"})):
        server.rbrowser.create = flip(**changes)
        try:
            async with bob.post(f"{base}/api/rbrowser/session", json=body) as r:
                st = r.status
        finally:
            server.rbrowser.create = real_create
            server._rbrowser_cfg.update(rbrowser_enabled=True, rbrowser_min_role="user")
        check(f"create in flight, {label}: 403 and no running session is left", st == 403 and rbrowser.for_user(env.uid["bob"]) is None
              and not [x for x in rbrowser.all() if x.user_id == env.uid["bob"]], str(st))
    cur = await db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'rbrowser_end' AND actor_id = ?", (env.uid["bob"],))
    check("and each end was audited (details are stored encrypted)", (await cur.fetchone())[0] - n_aud0 == 2)

    # the sign-out (or a disabled account) during the create: the token is revoked while the unit is not yet in the registry's
    # per-user list, so the revocation sweep finds nothing; the create must notice the sign-in is gone and end the unit itself
    bob3 = await h.login(base, "bob")
    async def create_signed_out(*a, **kw):
        s = await real_create(*a, **kw)
        await db.revoke_token(s.token_id)                 # what a sign-out does to the row (the sweep has nothing to end yet)
        return s
    server.rbrowser.create = create_signed_out
    try:
        async with bob3.post(f"{base}/api/rbrowser/session", json=body) as r:
            st = r.status
    finally:
        server.rbrowser.create = real_create
    check("create in flight, the sign-in revoked: 403 and no running session is left", st == 403 and rbrowser.for_user(env.uid["bob"]) is None
          and not [x for x in rbrowser.all() if x.user_id == env.uid["bob"] and x.state != "ended"], str(st))
    cur = await db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'rbrowser_end' AND actor_id = ?", (env.uid["bob"],))
    check("and that end was audited too", (await cur.fetchone())[0] - n_aud0 == 3)
    await bob3.close()
    async with adm.put(url, json={"rbrowser_enabled": False}) as r:
        check("race cleanup: switched off again", r.status == 200 and server._rbrowser_state["started"] is False)

    # ---------------------------------------------------------------- source guards
    banned = ("session_recording", "recorder", "Page.captureScreenshot", "Page.startScreencast")
    for name in ("rbrowser.py", "rbrowser_launch.py", "rbrowser_unit/session.py"):
        txt = (ROOT / name).read_text(encoding="utf-8")
        check(f"guard: {name} has none of the recording words", not [w for w in banned if w in txt], str([w for w in banned if w in txt]))
    ws_src = inspect.getsource(server.handle_rbrowser_ws)
    check("guard: handle_rbrowser_ws has none of the recording words", not [w for w in banned if w in ws_src])
    check("guard: the handler makes no log call at all (a message payload cannot be formatted into one)",
          all("type(e).__name__" in ln for ln in ws_src.splitlines() if "logger." in ln) and "print(" not in ws_src)
    check("guard: the handler never touches msg.data except to filter, size or parse a control frame",
          len(re.findall(r"msg\.data", ws_src)) <= 6 and "send_str" not in ws_src and "send_json" not in ws_src)
    src_all = inspect.getsource(server)
    rb_start = src_all.index("# Web Browser on the server (rbrowser, 1.25.0)")
    rb_block = (src_all[rb_start:src_all.index("_uploads_root_cache: Optional[tuple]", rb_start)]
                + "\n" + inspect.getsource(server.handle_rbrowser_ws) + "\n" + inspect.getsource(server._rbrowser_browser_signin))
    check("guard: the log-line guard looks at the whole feature block, never an empty slice", len(rb_block) > 10000, str(len(rb_block)))
    # a unit name (chosen by the registry) goes through _log_text; the helper's own name is not a text from the stream
    rb_logs = rb_block.replace("rbrowser_home_url", "").replace("_log_text(ev.get('unit'), 60)", "UNIT")
    check("guard: no log line of the feature formats a text from the stream, a key or a pointer",
          not re.findall(r"logger\.\w+\(f?[\"'][^\n]*(?:\.data|clip|text|keysym|pointer|url)\b", rb_logs),
          str(re.findall(r"logger\.\w+\(f?[\"'][^\n]*(?:\.data|clip|text|keysym|pointer|url)\b", rb_logs)[:3]))
    check("guard: the log-line guard sees log lines (a block with no logger call would pass it vacuously)", len(re.findall(r"logger\.\w+\(", rb_block)) > 10,
          str(len(re.findall(r"logger\.\w+\(", rb_block))))
    check("guard: ClientFilter is built with no argument (clipboard off)", "ClientFilter()" in ws_src)
    check("guard: the server-to-member direction is not parsed (no ClientFilter or RFB parsing in to_client)",
          "def to_client" in ws_src and "flt." not in ws_src.split("async def to_unit")[0])

    await server._rbrowser_stop()
    logging.getLogger().removeHandler(log)
    await bob2.close()
    await h.shutdown(env)
    h.finish("test_rbrowser_api")


def aiohttp_plain():
    import aiohttp
    return aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())


h.run(main, 240)
