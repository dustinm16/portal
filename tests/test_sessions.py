"""Sessions page: schema migration, the once-a-minute last-used write, the
User-Agent parser, and the routes that list and sign out sessions.

Run: venv/bin/python tests/test_sessions.py
"""

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory()
os.environ["JWT_SECRET"] = "x" * 64
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "sessions-test.db")

import auth  # noqa: E402
import server  # noqa: E402
import secevents  # noqa: E402
import session_devices as sd  # noqa: E402
from database import db, Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1")
IPHONE_CHROME = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
                 "(KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1")
ANDROID_CHROME = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")
WIN_EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0")
LINUX_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
MAC_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.4 Safari/605.1.15")
WIN_OPERA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0")
LINUX_CHROME = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def test_parser():
    cases = [
        (IPHONE, "Safari on iOS"), (IPHONE_CHROME, "Chrome on iOS"),
        (ANDROID_CHROME, "Chrome on Android"), (WIN_EDGE, "Edge on Windows"),
        (LINUX_FIREFOX, "Firefox on Linux"), (MAC_SAFARI, "Safari on macOS"),
        (WIN_OPERA, "Opera on Windows"), (LINUX_CHROME, "Chrome on Linux"),
        ("curl/8.5.0", "curl"), (None, "Unknown device"), ("", "Unknown device"),
        ("something odd", "Unknown device"),
    ]
    for ua, want in cases:
        got = sd.parse_user_agent(ua)["label"]
        check(f"parser: {str(ua)[:40]!r} -> {want}", got == want, got)
    check("parser: a very long agent is cut to 200 characters",
          len(sd.clean_user_agent("A" * 500)) == 200)
    check("parser: control characters are removed from a stored agent",
          sd.clean_user_agent("Mozilla\r\n\x00/5.0\x1b[31m") == "Mozilla/5.0[31m")
    check("parser: an empty or non-text agent is stored as nothing",
          sd.clean_user_agent("  ") is None and sd.clean_user_agent(None) is None
          and sd.clean_user_agent(123) is None)
    pid = sd.public_session_id("abc")
    check("public id: 16 hex characters, stable, not the token id",
          len(pid) == 16 and pid == sd.public_session_id("abc") and "abc" not in pid
          and sd.matches_public_id("abc", pid) and not sd.matches_public_id("abd", pid)
          and not sd.matches_public_id("abc", None))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Caller:
    def __init__(self, user_id, token_id, scopes=("services:read", "access:*")):
        self.user_id = user_id
        self.token_id = token_id
        self.scopes = list(scopes)

    def has_scope(self, scope):
        return scope in self.scopes or "*" in self.scopes


class FakeWs:
    def __init__(self):
        self.closed = False
        self.code = None

    async def close(self, code=1000, message=b""):
        self.closed = True
        self.code = code


class FakeRequest:
    def __init__(self, match=None):
        self.match_info = match or {}
        self.headers = {}


JWTS = {}


async def make_user(name, role="user"):
    u = await auth.create_user(name, "pw-" + name + "-12345", is_admin=role in ("admin", "superadmin"))
    if role != "user":
        await db.set_user_role(u["id"], role)
    return u["id"]


async def make_session(user_id, ip, ua, name="web_session", scopes=None):
    scopes = scopes or ["services:read", "access:*"]
    jwt_token, token_id = await auth.create_access_token(
        user_id=user_id, scopes=scopes, name=name, expires_in_hours=24, ip=ip, user_agent=ua)
    JWTS[token_id] = jwt_token
    return jwt_token, token_id


async def token_row(token_id):
    cur = await db.conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def sec_rows(event="session_revoked"):
    cur = await db.conn.execute("SELECT * FROM security_events WHERE event = ? ORDER BY id", (event,))
    return [dict(r) for r in await cur.fetchall()]


async def test_schema():
    path = Path(_TMP.name) / "old.db"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        token_id TEXT UNIQUE NOT NULL, name TEXT, scopes TEXT NOT NULL, expires_at TEXT,
        revoked INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT)""")
    con.execute("INSERT INTO tokens (user_id, token_id, name, scopes) VALUES (1, 'old', 'web_session', '*')")
    con.commit()
    con.close()
    d = Database(str(path))
    await d.connect()
    cols = [r[1] for r in await (await d.conn.execute("PRAGMA table_info(tokens)")).fetchall()]
    check("migration: ip, user_agent and last_ip are added to an existing tokens table",
          {"ip", "user_agent", "last_ip"} <= set(cols), str(cols))
    old = dict(await (await d.conn.execute("SELECT * FROM tokens WHERE token_id='old'")).fetchone())
    check("migration: a session from before the upgrade keeps its row, with empty ip and agent",
          old["ip"] is None and old["user_agent"] is None and old["last_ip"] is None)
    before = [tuple(r) for r in await (await d.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")).fetchall()]
    await d._run_migrations()
    await d.close()
    d2 = Database(str(path))
    await d2.connect()
    after = [tuple(r) for r in await (await d2.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")).fetchall()]
    await d2.close()
    check("migration: running it again changes nothing in the schema", before == after)
    view = server._session_view(old | {"token_id": "old"}, "other")
    check("old row is shown as an unknown device without an address",
          view["device"] == "Unknown device" and view["ip"] is None and view["last_ip"] is None)


async def test_throttle(uid):
    clock = Clock()
    saved_clock = auth._touch_clock
    auth._touch_clock = clock
    auth._last_touch.clear()
    writes = []
    real = db.update_token_last_used

    async def counting(token_id, last_ip=None):
        writes.append((token_id, last_ip))
        await real(token_id, last_ip)

    db.update_token_last_used = counting
    try:
        jwt_token, token_id = await make_session(uid, "198.51.100.1", LINUX_FIREFOX)
        row = await token_row(token_id)
        check("login stores ip, last_ip and the agent",
              row["ip"] == "198.51.100.1" and row["last_ip"] == "198.51.100.1" and row["user_agent"] == LINUX_FIREFOX)
        for _ in range(200):
            await auth.validate_token(jwt_token, "198.51.100.1")
        check("throttle: 200 requests inside one minute write last_used once", len(writes) == 1, str(len(writes)))
        row = await token_row(token_id)
        check("throttle: the first request set last_used_at", row["last_used_at"] is not None)
        clock.now += 30
        await auth.validate_token(jwt_token, "203.0.113.9")
        check("throttle: a request from a new address inside the minute does not write", len(writes) == 1)
        clock.now += 31
        await auth.validate_token(jwt_token, "203.0.113.9")
        row = await token_row(token_id)
        check("throttle: after a minute the next request writes and records the new last_ip",
              len(writes) == 2 and row["last_ip"] == "203.0.113.9" and row["ip"] == "198.51.100.1")
        await auth.validate_token(jwt_token)
        check("throttle: a call without an address does not erase last_ip",
              (await token_row(token_id))["last_ip"] == "203.0.113.9")
        # Several tokens are throttled independently.
        jwt2, tid2 = await make_session(uid, "198.51.100.2", MAC_SAFARI)
        await auth.validate_token(jwt2, "198.51.100.2")
        check("throttle: a second token has its own minute", len(writes) == 3)
        # Revoked tokens are refused and forgotten.
        await db.revoke_token(tid2)
        try:
            await auth.validate_token(jwt2, "198.51.100.2")
            refused = False
        except auth.AuthError:
            refused = True
        check("throttle: a revoked token is refused and not in the table",
              refused and tid2 not in auth._last_touch)
        # The table does not grow without bound.
        auth._last_touch.clear()
        for i in range(auth._TOUCH_SWEEP_SIZE + 10):
            auth._touch_due(f"t{i}")
        clock.now += 61
        auth._touch_due("fresh")
        check("throttle: stale entries are swept when the table is large", len(auth._last_touch) <= 2,
              str(len(auth._last_touch)))
    finally:
        db.update_token_last_used = real
        auth._touch_clock = saved_clock
        auth._last_touch.clear()


def body(resp):
    return json.loads(resp.body)


async def test_routes():
    alice = await make_user("sess_alice")
    bob = await make_user("sess_bob")
    admin = await make_user("sess_admin", "admin")
    admin2 = await make_user("sess_admin2", "admin")
    root = await make_user("sess_root", "superadmin")

    _, phone = await make_session(alice, "198.51.100.7", IPHONE)
    _, laptop = await make_session(alice, "198.51.100.8", LINUX_FIREFOX)
    _, tokn = await make_session(alice, "198.51.100.9", "curl/8.5.0", name="ci-script")
    _, bob_sess = await make_session(bob, "198.51.100.10", MAC_SAFARI)
    state = {"caller": Caller(alice, laptop)}

    async def fake_auth(request):
        return state["caller"]

    saved_auth = server.authenticate_request
    server.authenticate_request = fake_auth
    try:
        # list
        r = await server.http_list_my_sessions(FakeRequest())
        data = body(r)["sessions"]
        raw = r.body.decode()
        check("list: the caller sees only their own sessions (3 rows)", r.status == 200 and len(data) == 3, str(len(data)))
        check("list: exactly one row is marked current, and it is the laptop",
              [s["device"] for s in data if s["current"]] == ["Firefox on Linux"])
        check("list: the phone row is parsed and shows its address",
              any(s["device"] == "Safari on iOS" and s["ip"] == "198.51.100.7" and s["kind"] == "browser" for s in data))
        check("list: a token made through the API is marked and named",
              any(s["kind"] == "token" and s["name"] == "ci-script" for s in data))
        check("list: no token id, only 16-character public ids",
              all(t not in raw for t in (phone, laptop, tokn, bob_sess)) and all(len(s["id"]) == 16 for s in data))
        check("list: another member's session is not listed", "198.51.100.10" not in raw)
        check("list: timestamps are ISO UTC with a Z",
              all((s["created_at"] or "").endswith("Z") for s in data))
        phone_id = sd.public_session_id(phone)
        bob_id = sd.public_session_id(bob_sess)

        # credentials that are not full are refused
        for label, cred in (("stream key", Caller(alice, "streamkey-4", ("streams:*",))),
                            ("scoped API key", Caller(alice, "apikey-9", ("services:read",))),
                            ("API key with only services:read and access:*", Caller(alice, "apikey-9"))):
            state["caller"] = cred
            codes = [(await h(FakeRequest(match={"id": phone_id}))).status for h in
                     (server.http_list_my_sessions, server.http_revoke_my_session,
                      server.http_revoke_my_other_sessions)]
            check(f"{label}: list, revoke and revoke-others all answer 403", codes == [403, 403, 403], str(codes))
        state["caller"] = Caller(alice, laptop)
        row = await token_row(phone)
        check("a refused credential changed nothing", row["revoked"] == 0)
        state["caller"] = Caller(alice, "apikey-9", ("*",))
        r = await server.http_list_my_sessions(FakeRequest())
        check("an all-scope API key may list sessions, none is current",
              r.status == 200 and not any(s["current"] for s in body(r)["sessions"]))
        state["caller"] = Caller(alice, laptop)

        # revoke one
        r = await server.http_revoke_my_session(FakeRequest(match={"id": sd.public_session_id(laptop)}))
        check("revoke one: the current session is refused with a hint to log out",
              r.status == 400 and "Log out" in body(r)["error"] and (await token_row(laptop))["revoked"] == 0)
        for bad in (bob_id, "0" * 16, "", "x"):
            r = await server.http_revoke_my_session(FakeRequest(match={"id": bad}))
            check(f"revoke one: id {bad[:6]!r} (not mine / unknown) answers 404", r.status == 404)
        check("revoke one: another member's session is untouched", (await token_row(bob_sess))["revoked"] == 0)

        server._user_websockets.clear()
        server._user_proxy_calls.clear()
        ws_phone, ws_laptop, ws_tok, ws_key, ws_stream, ws_bob = (FakeWs() for _ in range(6))
        server._register_user_ws(alice, ws_phone, phone)
        server._register_user_ws(alice, ws_laptop, laptop)
        server._register_user_ws(alice, ws_tok, tokn)
        server._register_user_ws(alice, ws_key, "apikey-9")
        server._register_user_ws(alice, ws_stream, "streamkey-4")
        server._register_user_ws(bob, ws_bob, bob_sess)

        r = await server.http_revoke_my_session(FakeRequest(match={"id": phone_id}))
        check("revoke one: the phone session is revoked and its socket closed with 4001",
              r.status == 200 and (await token_row(phone))["revoked"] == 1 and ws_phone.closed and ws_phone.code == 4001)
        check("revoke one: the laptop, the token, the key and another member keep their sockets",
              not any(w.closed for w in (ws_laptop, ws_tok, ws_key, ws_stream, ws_bob)))
        try:
            await auth.validate_token(JWTS[phone])
            still = True
        except auth.AuthError:
            still = False
        check("revoke one: the phone's next request is refused", still is False)
        ev = await sec_rows()
        d = json.loads(ev[-1]["details"]) if ev else {}
        check("revoke one: recorded as a security event with the user, result own and the session",
              len(ev) == 1 and ev[0]["user_id"] == alice and ev[0]["result"] == "own"
              and d.get("own") is True and d.get("token_id") == phone[:8] and phone not in (ev[0]["details"] or ""),
              str(ev))

        # revoke others
        _, phone2 = await make_session(alice, "198.51.100.11", ANDROID_CHROME)
        ws_phone2 = FakeWs()
        server._register_user_ws(alice, ws_phone2, phone2)
        r = await server.http_revoke_my_other_sessions(FakeRequest())
        out = body(r)
        check("revoke others: the other browser session and the token are revoked, the laptop is not",
              r.status == 200 and out["revoked"] == 2 and (await token_row(phone2))["revoked"] == 1
              and (await token_row(tokn))["revoked"] == 1 and (await token_row(laptop))["revoked"] == 0, str(out))
        check("revoke others: their sockets close, the laptop's, an API key's and a stream key's stay",
              ws_phone2.closed and ws_tok.closed and not ws_laptop.closed and not ws_key.closed
              and not ws_stream.closed)
        check("revoke others: another member's session is untouched",
              (await token_row(bob_sess))["revoked"] == 0 and not ws_bob.closed)
        ev = [e for e in await sec_rows() if e["result"] == "others"]
        d = json.loads(ev[0]["details"]) if ev else {}
        check("revoke others: one security event carries the number of sessions ended",
              len(ev) == 1 and ev[0]["user_id"] == alice and d.get("sessions_revoked") == 2, str(ev))
        r = await server.http_list_my_sessions(FakeRequest())
        data = body(r)["sessions"]
        check("list after revoke-others: only the laptop remains, current", len(data) == 1 and data[0]["current"])

        # admin sign out everywhere
        _, a1 = await make_session(admin, "203.0.113.1", MAC_SAFARI, scopes=["*"])
        _, a2 = await make_session(admin, "203.0.113.2", IPHONE, scopes=["*"])
        state["caller"] = Caller(admin, a1, ("*",))
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(admin)}))
        check("admin everywhere on themselves keeps the current session and signs out the rest",
              r.status == 200 and body(r)["kept_current_session"] is True
              and (await token_row(a1))["revoked"] == 0 and (await token_row(a2))["revoked"] == 1)

        _, l2 = await make_session(alice, "198.51.100.12", LINUX_CHROME)
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(alice)}))
        check("admin everywhere on a member signs out all of their sessions",
              r.status == 200 and body(r)["revoked"] == 2 and (await token_row(laptop))["revoked"] == 1
              and (await token_row(l2))["revoked"] == 1 and ws_laptop.closed)
        check("admin everywhere: the admin's own session is untouched", (await token_row(a1))["revoked"] == 0)
        ev = [e for e in await sec_rows() if e["result"] == "admin_all"]
        d = json.loads(ev[-1]["details"]) if ev else {}
        check("admin everywhere: a security event names the admin as actor and the member as target",
              len(ev) == 2 and ev[1]["user_id"] == admin and d.get("target_user_id") == alice
              and d.get("target_username") == "sess_alice" and d.get("sessions_revoked") == 2
              and d.get("kept_current_session") is False, str(ev))
        check("admin everywhere on themselves is recorded too, keeping the current session",
              json.loads(ev[0]["details"]).get("kept_current_session") is True
              and json.loads(ev[0]["details"]).get("target_user_id") == admin)
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(bob)}))
        cur = await db.conn.execute(
            "SELECT actor_id, target_id, details FROM audit_log WHERE action = 'sessions_revoke' AND target_id = ?", (bob,))
        rows = [dict(x) for x in await cur.fetchall()]
        check("admin everywhere on another member is audited with actor and target",
              r.status == 200 and len(rows) == 1 and rows[0]["actor_id"] == admin, str(rows))

        # who may use it
        _, r1 = await make_session(root, "203.0.113.5", MAC_SAFARI, scopes=["*"])
        state["caller"] = Caller(admin, a1, ("*",))
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(root)}))
        check("a plain admin cannot sign a superadmin out", r.status == 403 and (await token_row(r1))["revoked"] == 0)
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(admin2)}))
        check("a plain admin cannot sign another admin out", r.status == 403)
        state["caller"] = Caller(root, r1, ("*",))
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(admin2)}))
        check("a superadmin can sign an admin out", r.status == 200)
        _, bob2 = await make_session(bob, "198.51.100.20", MAC_SAFARI)
        state["caller"] = Caller(alice, "any", ("services:read", "access:*"))
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(bob)}))
        check("a member cannot use the admin route", r.status == 403 and (await token_row(bob2))["revoked"] == 0)
        state["caller"] = Caller(admin, "apikey-3", ("admin",))
        r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": str(bob)}))
        check("an admin-only scoped key is refused", r.status == 403)
        state["caller"] = Caller(admin, a1, ("*",))
        for bad, want in (("abc", 400), ("999999", 404)):
            r = await server.http_admin_revoke_user_sessions(FakeRequest(match={"id": bad}))
            check(f"admin everywhere: id {bad!r} answers {want}", r.status == want, str(r.status))
        state["caller"] = None
        r = await server.http_list_my_sessions(FakeRequest())
        check("no credential: 401", r.status == 401)
    finally:
        server.authenticate_request = saved_auth
        server._user_websockets.clear()
        server._user_proxy_calls.clear()


async def main():
    test_parser()
    await test_schema()
    await db.connect()
    secevents.log.bind(db)
    try:
        uid = await make_user("sess_throttle")
        await test_throttle(uid)
        await test_routes()
    finally:
        await db.close()


asyncio.run(main())
_TMP.cleanup()
if failures:
    print(f"test_sessions: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("test_sessions: all checks passed")
