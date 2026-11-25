"""API key least privilege: address binding, the scope registry, the 90 day default
expiry, last-used address, the stale flag and the security events.

Run: venv/bin/python tests/test_apikeys.py
"""

import asyncio
import ipaddress
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory()
os.environ["JWT_SECRET"] = "x" * 64
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "apikeys-test.db")

from multidict import CIMultiDict  # noqa: E402

import apikey_policy as ap  # noqa: E402
import auth  # noqa: E402
import server  # noqa: E402
import secevents  # noqa: E402
from database import db, Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def raises(fn, *a):
    try:
        fn(*a)
    except ap.PolicyError:
        return True
    return False


class FakeTransport:
    def __init__(self, ip):
        self.ip = ip

    def get_extra_info(self, name):
        return (self.ip, 4000) if name == "peername" else None


class FakeRequest:
    def __init__(self, peer="198.51.100.7", headers=None, body=None, match=None):
        self.headers = CIMultiDict(headers or {})
        self.query = {}
        self.cookies = {}
        self.match_info = match or {}
        self.path = "/api/test"
        self.transport = FakeTransport(peer)
        self._body = body
        self._store = {}

    async def json(self):
        if self._body is None:
            raise json.JSONDecodeError("empty", "", 0)
        return self._body

    def __setitem__(self, k, v):
        self._store[k] = v

    def __getitem__(self, k):
        return self._store[k]

    def get(self, k, d=None):
        return self._store.get(k, d)


def body_of(resp):
    return json.loads(resp.body)


def test_policy():
    n = ap.normalise_cidrs
    check("cidr: none and empty mean not bound", n(None) is None and n([]) is None and n("") is None)
    check("cidr: a bare address becomes /32 and /128", n("203.0.113.5") == ["203.0.113.5/32"]
          and n(["2001:db8::1"]) == ["2001:db8::1/128"])
    check("cidr: host bits are cleared, text and list forms agree, duplicates collapse",
          n("203.0.113.9/24, 203.0.113.0/24") == ["203.0.113.0/24"]
          and n(["10.0.0.0/8", "2001:DB8::/32"]) == ["10.0.0.0/8", "2001:db8::/32"])
    check("cidr: a /0 is refused", raises(n, "0.0.0.0/0") and raises(n, ["::/0"]))
    check("cidr: 'any' alone means not bound, mixed with others is refused",
          n("any") is None and raises(n, "any,10.0.0.0/8"))
    check("cidr: garbage, empty entries, non-text and ipv4-mapped forms are refused",
          raises(n, "nope") and raises(n, ["10.0.0.1", ""]) and raises(n, [5]) and raises(n, "::ffff:10.0.0.1")
          and raises(n, {"a": 1}))
    check("cidr: ten distinct entries pass, eleven are refused",
          len(n([f"10.0.{i}.0/24" for i in range(10)])) == 10 and raises(n, [f"10.0.{i}.0/24" for i in range(11)]))
    check("cidr: ten entries written twice are still ten",
          len(n([f"10.0.{i}.0/24" for i in range(10)] * 2)) == 10)
    c = ["203.0.113.0/24", "2001:db8::/32"]
    check("match: inside, outside, ipv6, ipv4-mapped, missing and garbage",
          ap.client_in_cidrs("203.0.113.77", c) and not ap.client_in_cidrs("203.0.114.1", c)
          and ap.client_in_cidrs("2001:db8::5", c) and ap.client_in_cidrs("::ffff:203.0.113.5", c)
          and not ap.client_in_cidrs(None, c) and not ap.client_in_cidrs("unknown", c)
          and ap.client_in_cidrs(None, []))

    s = ap.normalise_scopes
    check("scopes: text, list and default; '*' swallows the rest",
          s("services:read, access:*") == ["services:read", "access:*"] and s(["admin"]) == ["admin"]
          and s(None) == ["*"] and s("admin,*") == ["*"])
    check("scopes: an unknown scope is refused", raises(s, "frobnicate") and raises(s, "admin,relay:read")
          and raises(s, "Bad Scope!") and raises(s, [1]) and raises(s, {"a": 1}))
    check("scopes: a scope a service requires is accepted, with a wildcard that covers it",
          s("relay:read", extra_known=["relay:read"]) == ["relay:read"]
          and s("relay:*", extra_known=["relay:read"]) == ["relay:*"] and raises(s, "relay:*"))
    check("scopes: a service scope is kept exactly as stored (case, slash), a wildcard over it too",
          s("Relay:Media", extra_known=["Relay:Media"]) == ["Relay:Media"]
          and s(["files/read"], extra_known=["files/read"]) == ["files/read"]
          and s("Relay:*", extra_known=["Relay:Media"]) == ["Relay:*"]
          and raises(s, "relay:media", ["Relay:Media"]) and raises(s, "Relay:Media")
          and raises(s, "x" * 129, ["x" * 129]) and raises(s, ["a\x00b"], ["a\x00b"]))
    check("scopes: an explicitly empty value is refused, only a missing or null one is the default",
          raises(s, []) and raises(s, "") and raises(s, "  , ") and s(None) == ["*"])
    check("cidr: an address with a zone id is refused", raises(n, "fe80::1%eth0") and raises(n, ["fe80::/64%eth0"]))
    many = [f"svc{i}" for i in range(25)]
    check("scopes: more than 20 are refused", raises(lambda: s(many, extra_known=many)))

    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    e = ap.resolve_expiry
    at, days = e({}, now)
    check("expiry: absent is 90 days", days == 90 and at == (now + timedelta(days=90)).isoformat())
    check("expiry: 'never' and 0 mean no expiry", e({"expires_days": "never"}, now) == (None, None)
          and e({"expires_days": 0}, now) == (None, None))
    check("expiry: a number of days, as number or text", e({"expires_days": 30}, now)[1] == 30
          and e({"expires_days": "7"}, now)[1] == 7)
    check("expiry: the older expires_in_days spelling is read", e({"expires_in_days": 14}, now)[1] == 14)
    check("expiry: negative, huge, unreadable and boolean values are refused",
          raises(e, {"expires_days": -1}) and raises(e, {"expires_days": 99999}) and raises(e, {"expires_days": "soon"})
          and raises(e, {"expires_days": True}) and raises(e, {"expires_days": 1.5}) and raises(e, {"expires_days": []}))

    old = (now - timedelta(days=91)).strftime("%Y-%m-%d %H:%M:%S")
    new = (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
    check("stale: used 91 days ago is stale, used 10 days ago is not",
          ap.is_stale({"last_used_at": old, "created_at": old}, now)
          and not ap.is_stale({"last_used_at": new, "created_at": old}, now))
    check("stale: never used counts from creation; revoked and expired keys are not flagged",
          ap.is_stale({"last_used_at": None, "created_at": old}, now)
          and not ap.is_stale({"last_used_at": None, "created_at": new}, now)
          and not ap.is_stale({"last_used_at": old, "created_at": old, "revoked": 1}, now)
          and not ap.is_stale({"last_used_at": old, "created_at": old, "expires_at": "2026-01-01T00:00:00+00:00"}, now))
    check("warning: only a '*' key with no expiry",
          ap.no_expiry_warning(["*"], None) and not ap.no_expiry_warning(["*"], "x")
          and not ap.no_expiry_warning(["admin"], None))


async def test_migration():
    path = Path(_TMP.name) / "old.db"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL, key_hash TEXT NOT NULL, key_prefix TEXT NOT NULL, scopes TEXT DEFAULT '*',
        expires_at TEXT, last_used_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, revoked INTEGER DEFAULT 0)""")
    con.execute("INSERT INTO api_keys (user_id, name, key_hash, key_prefix) VALUES (1, 'old', 'h', 'portal_abc')")
    con.commit()
    con.close()
    d = Database(str(path))
    await d.connect()
    cols = {r[1] for r in await (await d.conn.execute("PRAGMA table_info(api_keys)")).fetchall()}
    check("migration: the three columns are added to an existing api_keys table",
          {"allowed_cidrs", "created_ip", "last_used_ip"} <= cols, str(cols))
    row = dict(await (await d.conn.execute("SELECT * FROM api_keys WHERE name='old'")).fetchone())
    check("migration: an existing key keeps its row and is not bound",
          row["allowed_cidrs"] is None and row["created_ip"] is None and row["last_used_ip"] is None
          and row["expires_at"] is None and row["scopes"] == "*")
    before = [tuple(r) for r in await (await d.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")).fetchall()]
    await d._run_migrations()
    after = [tuple(r) for r in await (await d.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")).fetchall()]
    await d.close()
    check("migration: running it again changes nothing", before == after)


async def make_user(name, role="user"):
    u = await auth.create_user(name, "pw-" + name + "-12345", is_admin=role in ("admin", "superadmin"))
    if role != "user":
        await db.set_user_role(u["id"], role)
    return u["id"]


async def bearer(uid, scopes):
    jwt_token, _ = await auth.create_access_token(user_id=uid, scopes=scopes, name="t", expires_in_hours=1)
    return {"Authorization": f"Bearer {jwt_token}"}


async def create(headers, body, peer="198.51.100.7"):
    r = await server.http_create_api_key(FakeRequest(peer=peer, headers=headers, body=body))
    return r.status, body_of(r)


async def events(event):
    await secevents.log.flush()
    cur = await db.conn.execute("SELECT * FROM security_events WHERE event = ? ORDER BY id", (event,))
    return [dict(r) for r in await cur.fetchall()]


async def test_auth_and_routes():
    admin = await make_user("ak_admin", "admin")
    member = await make_user("ak_member")
    ah = await bearer(admin, ["*"])
    mh = await bearer(member, ["services:read", "access:*"])

    # --- creation -----------------------------------------------------------
    st, d = await create(ah, {"name": "default"})
    exp = datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None
    check("create: a new key expires in 90 days by default",
          st == 201 and exp is not None and 89.9 < (exp - datetime.now(timezone.utc)).total_seconds() / 86400 < 90.1
          and d["expires_days"] == 90, str(d))
    check("create: a '*' key with an expiry carries no warning", "expiry_warning" not in d)
    st, d = await create(ah, {"name": "forever", "expires_days": "never"})
    check("create: 'never' is an explicit choice, with a warning for a '*' key",
          st == 201 and d["expires_at"] is None and "expiry_warning" in d and d["scopes"] == "*", str(d))
    st, d = await create(ah, {"name": "forever-admin", "scopes": "admin", "expires_days": "never"})
    check("create: a narrow key with no expiry carries no warning", st == 201 and "expiry_warning" not in d)
    st, d = await create(ah, {"name": "bad-scope", "scopes": "frobnicate"})
    check("create: an unknown scope is a 400", st == 400 and "scope" in d["error"].lower(), str(d))
    st, d = await create(ah, {"name": "bad-scope2", "scopes": ["admin", "nope:read"]})
    check("create: one unknown scope in a list is a 400", st == 400)
    st, d = await create(mh, {"name": "member-bad", "scopes": "frobnicate"})
    check("create: a member's unknown scope is a 400 too", st == 400)
    st, d = await create(mh, {"name": "member-admin", "scopes": "admin"})
    check("create: a member asking for admin still gets the limited scopes",
          st == 201 and d["scopes"] == "services:read,access:*", str(d))
    st, d = await create(ah, {"name": "bad-cidr", "allowed_cidrs": ["203.0.113.0/24", "nonsense"]})
    check("create: a bad network is a 400", st == 400)
    st, d = await create(ah, {"name": "zero-cidr", "allowed_cidrs": "0.0.0.0/0"})
    check("create: /0 is a 400", st == 400)
    st, d = await create(ah, {"name": "bad-days", "expires_days": "soon"})
    check("create: an unreadable expiry is a 400 (it used to mean never)", st == 400)
    await db.conn.execute("INSERT INTO services (name, path, required_scopes) VALUES ('svcx', '/svcx', 'relay:read')")
    await db.conn.commit()
    st, d = await create(ah, {"name": "svc-key", "scopes": ["relay:read"]})
    check("create: a scope a service requires is accepted", st == 201 and d["scopes"] == "relay:read", str(d))

    # --- the binding, through the proxy rule ---------------------------------
    st, d = await create(ah, {"name": "bound", "scopes": "services:read", "allowed_cidrs": "203.0.113.0/24"},
                         peer="198.51.100.7")
    key, key_id = d["key"], d["id"]
    check("create: the response lists the binding and where the key was made",
          st == 201 and d["allowed_cidrs"] == ["203.0.113.0/24"] and d["created_ip"] == "198.51.100.7", str(d))
    created = [e for e in await events("api_key_created") if json.loads(e["details"]).get("key_id") == key_id]
    check("create: the security event records the binding",
          len(created) == 1 and json.loads(created[0]["details"])["allowed_cidrs"] == "203.0.113.0/24")

    calls = []
    real_verify = server._verify_api_key_offloop

    async def counting(*a):
        calls.append(a[0])
        return await real_verify(*a)

    server._verify_api_key_offloop = counting
    try:
        out = await server.authenticate_api_key(key, "198.51.100.9")
        check("bound key: used from outside the range is refused", out is None)
        check("bound key: the refusal costs no Argon2 verification", calls == [], str(calls))
        out = await server.authenticate_api_key(key, None)
        check("bound key: no address at all is refused (fails closed)", out is None)
        out = await server.authenticate_api_key(key, "203.0.113.77")
        check("bound key: works from inside the range", out is not None and out.token_id == f"apikey-{key_id}")
        check("bound key: the inside call verified once", len(calls) == 1)
        out = await server.authenticate_api_key(key, "198.51.100.9")
        check("bound key: after a verified call from inside (cache warm) outside is still refused",
              out is None and len(calls) == 1)
        out = await server.authenticate_api_key(key[:-1] + ("0" if key[-1] != "0" else "1"), "203.0.113.77")
        check("bound key: a wrong key from inside is a plain refusal", out is None)
    finally:
        server._verify_api_key_offloop = real_verify
    denied = [e for e in await events("api_key_ip_denied") if json.loads(e["details"]).get("key_id") == key_id]
    check("bound key: the refusal is a security event with the real reason, address and key id, no secret",
          len(denied) >= 1 and all(e["result"] == "address_not_allowed" for e in denied)
          and denied[0]["ip"] == "198.51.100.9" and key not in json.dumps(denied), str(denied))
    check("bound key: a flood of refusals is aggregated, not one row each",
          "api_key_ip_denied" in secevents.AGGREGATED)

    # Same generic answer through the real request path, with the proxy rule
    saved_nets, saved_cache = server._trusted_proxy_networks, dict(server._trusted_peer_cache)
    server._trusted_proxy_networks = [ipaddress.ip_network("10.9.0.0/16")]
    server._trusted_peer_cache.clear()
    try:
        hdr = {"Authorization": f"Api-Key {key}", "Accept": "application/json"}
        r = await server.http_list_api_keys(FakeRequest(peer="10.9.0.1", headers={**hdr, "CF-Connecting-IP": "198.51.100.50"}))
        wrong = await server.http_list_api_keys(FakeRequest(peer="10.9.0.1", headers={
            "Authorization": "Api-Key portal_" + "0" * 64, "Accept": "application/json", "CF-Connecting-IP": "198.51.100.50"}))
        check("request path: from another address the answer is the generic 401, same body as a wrong key",
              r.status == 401 and wrong.status == 401 and r.body == wrong.body, f"{r.status} {wrong.status}")
        r = await server.http_list_api_keys(FakeRequest(peer="10.9.0.1", headers={**hdr, "CF-Connecting-IP": "203.0.113.50"}))
        check("request path: from inside the range (through a trusted proxy) it works", r.status == 200, str(r.status))
        r = await server.http_list_api_keys(FakeRequest(peer="198.51.100.7", headers={**hdr, "CF-Connecting-IP": "203.0.113.50"}))
        check("request path: a spoofed CF-Connecting-IP from an untrusted peer does not get in", r.status == 401, str(r.status))
        r = await server.http_list_api_keys(FakeRequest(peer="203.0.113.50", headers=hdr))
        check("request path: a direct client inside the range works", r.status == 200)
    finally:
        server._trusted_proxy_networks = saved_nets
        server._trusted_peer_cache.clear()
        server._trusted_peer_cache.update(saved_cache)

    # --- an unbound key is unchanged -----------------------------------------
    st, d = await create(ah, {"name": "open", "scopes": "services:read"})
    out = await server.authenticate_api_key(d["key"], "192.0.2.1")
    out2 = await server.authenticate_api_key(d["key"], None)
    check("unbound key: works from any address and without one", out is not None and out2 is not None)

    # --- last used address, throttled ----------------------------------------
    clock = [1000.0]
    saved_clock = auth._touch_clock
    auth._touch_clock = lambda: clock[0]
    auth._last_touch.clear()
    writes = []
    real_touch = db.update_api_key_last_used

    async def counting_touch(kid, ip=None):
        writes.append((kid, ip))
        await real_touch(kid, ip)

    db.update_api_key_last_used = counting_touch
    try:
        st, d = await create(ah, {"name": "touch", "scopes": "services:read"})
        for _ in range(50):
            await server.authenticate_api_key(d["key"], "192.0.2.10")
        check("last used: 50 requests inside a minute write once", len(writes) == 1, str(writes))
        clock[0] += 61
        await server.authenticate_api_key(d["key"], "192.0.2.11")
        check("last used: the next minute writes again", len(writes) == 2)
        rows = {k["name"]: k for k in await db.get_user_api_keys(admin)}
        check("last used: the address and the time are stored",
              rows["touch"]["last_used_ip"] == "192.0.2.11" and rows["touch"]["last_used_at"] is not None, str(rows["touch"]))
        check("last used: the creation address is stored", rows["touch"]["created_ip"] == "198.51.100.7")
    finally:
        db.update_api_key_last_used = real_touch
        auth._touch_clock = saved_clock
        auth._last_touch.clear()

    # --- listing -------------------------------------------------------------
    r = await server.http_list_api_keys(FakeRequest(headers=ah))
    data = body_of(r)
    by = {k["name"]: k for k in data["api_keys"]}
    check("list: the owner sees created address, last-used time and address, and the binding as a list",
          by["touch"]["created_ip"] == "198.51.100.7" and by["touch"]["last_used_ip"] == "192.0.2.11"
          and by["touch"]["last_used_at"] and by["bound"]["allowed_cidrs"] == ["203.0.113.0/24"]
          and by["open"]["allowed_cidrs"] == [], str(by["touch"]))
    check("list: no hash is returned", all("key_hash" not in k for k in data["api_keys"]))
    check("list: an administrator sees the stale flag, fresh keys are not stale",
          all("stale" in k for k in data["api_keys"]) and not by["touch"]["stale"] and data["stale_after_days"] == 90)
    old = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S")
    await db.conn.execute("UPDATE api_keys SET created_at = ?, last_used_at = ? WHERE id = ?", (old, old, by["open"]["id"]))
    await db.conn.commit()
    data = body_of(await server.http_list_api_keys(FakeRequest(headers=ah)))
    by = {k["name"]: k for k in data["api_keys"]}
    check("list: a key unused for 100 days is flagged stale for the administrator", by["open"]["stale"] is True)
    mdata = body_of(await server.http_list_api_keys(FakeRequest(headers=mh)))
    check("list: an ordinary member gets no stale flag but does get the addresses",
          mdata["api_keys"] and all("stale" not in k for k in mdata["api_keys"])
          and all("created_ip" in k and "last_used_ip" in k for k in mdata["api_keys"]))

    # --- scope picker route --------------------------------------------------
    sc = body_of(await server.http_api_key_scopes(FakeRequest(headers=ah)))
    names = [x["scope"] for x in sc["scopes"]]
    check("scope route: the registry, the service scope and the defaults for an administrator",
          {"*", "admin", "services:read", "access:*", "relay:read"} <= set(names) and sc["can_choose"]
          and sc["default_expiry_days"] == 90)
    sc = body_of(await server.http_api_key_scopes(FakeRequest(headers=mh)))
    check("scope route: a member cannot choose and is not shown service scopes",
          not sc["can_choose"] and "relay:read" not in [x["scope"] for x in sc["scopes"]]
          and sc["limited_scopes"] == ["services:read", "access:*"])
    r = await server.http_api_key_scopes(FakeRequest(headers={}))
    check("scope route: needs a sign-in", r.status in (401, 302, 403), str(r.status))

    # --- revoke is an event ---------------------------------------------------
    r = await server.http_revoke_api_key(FakeRequest(headers=ah, match={"id": str(key_id)}))
    check("revoke: works and is a security event", r.status == 200
          and any(json.loads(e["details"]).get("key_id") == key_id for e in await events("api_key_revoked")))
    out = await server.authenticate_api_key(key, "203.0.113.77")
    check("revoke: a revoked bound key no longer works from inside", out is None)


async def test_fix_b1():
    admin = await make_user("b1_admin", "admin")
    member = await make_user("b1_member")
    ah = await bearer(admin, ["*"])
    mh = await bearer(member, ["services:read", "access:*"])

    # 1. service scopes are stored and honoured exactly
    await db.conn.execute("INSERT INTO services (name, path, required_scopes) VALUES ('b1svc', '/b1svc', 'Relay:Media, files/read, svc:lower')")
    await db.conn.commit()
    check("scope names: read back exactly as stored", {"Relay:Media", "files/read"} <= set(await db.get_service_scope_names()))
    st, d = await create(ah, {"name": "b1-case", "scopes": ["Relay:Media", "files/read"]})
    check("create: a service scope with capitals or a slash is accepted and stored exactly",
          st == 201 and d["scopes"] == "Relay:Media,files/read", str(d))
    out = await server.authenticate_api_key(d["key"], "198.51.100.7")
    service = {"required_scopes": ["Relay:Media"]}
    check("key: the stored scope opens the service that requires it",
          out is not None and server.check_service_authorization(service, out)
          and not server.check_service_authorization({"required_scopes": ["relay:media"]}, out))

    # 2. a member's answer does not depend on which service scopes exist
    st1, d1 = await create(mh, {"name": "b1-m1", "scopes": "svc:lower"})
    st2, d2 = await create(mh, {"name": "b1-m2", "scopes": "svc:made"})
    check("create: a member gets the same answer for a real and a made-up service scope",
          st1 == st2 == 400 and d1["error"].replace("svc:lower", "") == d2["error"].replace("svc:made", ""), f"{d1} {d2}")
    names_calls = []
    real_names = db.get_service_scope_names

    async def spy():
        names_calls.append(1)
        return await real_names()

    db.get_service_scope_names = spy
    try:
        await create(mh, {"name": "b1-m3", "scopes": "services:read"})
        member_calls = len(names_calls)
        await create(ah, {"name": "b1-a3", "scopes": "services:read"})
    finally:
        db.get_service_scope_names = real_names
    check("create: service scope names are read only for a caller who may choose scopes",
          member_calls == 0 and len(names_calls) == 1, str(names_calls))

    # 4. empty scopes
    for i, v in enumerate(([], "", " ")):
        st, d = await create(ah, {"name": f"b1-empty{i}", "scopes": v})
        check(f"create: an administrator's empty scopes {v!r} is a 400", st == 400, str(d))
    st, d = await create(ah, {"name": "b1-missing"})
    check("create: a missing scopes field is still the default", st == 201 and d["scopes"] == "*", str(d))

    # 5. zone id, and the stale text
    st, d = await create(ah, {"name": "b1-zone", "allowed_cidrs": "fe80::1%eth0"})
    check("create: an allowed address with a zone id is a 400", st == 400, str(d))
    adata = body_of(await server.http_list_api_keys(FakeRequest(headers=ah)))
    mdata = body_of(await server.http_list_api_keys(FakeRequest(headers=mh)))
    check("list: stale_after_days is present for an administrator and absent for a member",
          adata.get("stale_after_days") == 90 and "stale_after_days" not in mdata)
    doc = (ROOT / "docs" / "API.md").read_text(encoding="utf-8")
    check("docs: the text says both stale fields are absent for anybody else", "For anybody else both are absent." in doc)

    # 3. the denial event is counted per key
    u1 = await make_user("b1_u1")
    u2 = await make_user("b1_u2")
    keys = []
    for uid, nm in ((u1, "b1-bound1"), (u2, "b1-bound2")):
        hdr = await bearer(uid, ["services:read", "access:*"])
        st, k = await create(hdr, {"name": nm, "allowed_cidrs": "203.0.113.0/24"})
        keys.append((uid, k))
    for uid, k in keys:
        await server.authenticate_api_key(k["key"], "198.51.100.77")
    rows = [e for e in await events("api_key_ip_denied") if e["ip"] == "198.51.100.77"]
    check("denial: two members' keys refused from one address are two rows, each under its own user",
          sorted(r["user_id"] for r in rows) == sorted([u1, u2])
          and {json.loads(r["details"])["key_id"] for r in rows} == {k["id"] for _, k in keys}, str(rows))
    lg = secevents.SecurityEventLog()
    for i in range(9):
        lg.note("api_key_ip_denied", ip="203.0.113.250", user_id=100 + i, result="address_not_allowed",
                details={"key_id": 500 + i, "key_prefix": "portal_abc"}, now=1_800_000_000)
    for i in range(9):
        lg.note("api_key_ip_denied", ip="203.0.113.250", user_id=100 + i, result="address_not_allowed",
                details={"key_id": 500 + i, "key_prefix": "portal_abc"}, now=1_800_000_001)
    ents = list(lg._agg.values())
    keyed = [e for e in ents if e["user_id"] is not None]
    folded = [e for e in ents if e["user_id"] is None]
    check("denial: rows per address and minute are capped, the rest folded into one row without user and key",
          len(keyed) == secevents.KEY_ROWS_PER_ADDRESS and len(folded) == 1
          and folded[0]["details"] is None and folded[0]["count"] == 2 * (9 - secevents.KEY_ROWS_PER_ADDRESS)
          and all(e["count"] == 2 for e in keyed), str([(e["user_id"], e["count"]) for e in ents]))

    # 6. two live keys that share a prefix both work
    import secrets
    pfx = "portal_f0f"
    made = []
    for uid, nm in ((u1, "b1-share1"), (u2, "b1-share2")):
        full = pfx + secrets.token_hex(31)[:61]
        full = full[:71]
        kid = await db.create_api_key(user_id=uid, name=nm, key_hash=auth.hash_password(full), key_prefix=pfx[:10],
                                      scopes="services:read", expires_at=None)
        made.append((uid, kid, full))
    check("prefix: the lookup returns every live key with the prefix",
          [r["id"] for r in await db.get_api_keys_by_prefix(pfx[:10])] == [m[1] for m in reversed(made)])
    ok = True
    for uid, kid, full in made:
        out = await server.authenticate_api_key(full, "198.51.100.7")
        ok = ok and out is not None and out.token_id == f"apikey-{kid}" and out.user_id == uid
    check("prefix: both keys sharing a prefix authenticate, each as its own key", ok)
    out = await server.authenticate_api_key(made[0][2][:-1] + ("0" if made[0][2][-1] != "0" else "1"), "198.51.100.7")
    check("prefix: a wrong key with the shared prefix is the generic refusal", out is None)
    check("prefix: the verified-key cache holds one entry per key and neither vouches for the other",
          not server._api_key_cached_ok(made[0][1], made[1][2], (await db.get_api_keys_by_prefix(pfx[:10]))[-1]["key_hash"]))
    cred_a = await server._has_valid_credential(FakeRequest(headers={"X-API-Key": made[1][2]}))
    cred_b = await server._has_valid_credential(FakeRequest(headers={"X-API-Key": made[0][2]}))
    cred_x = await server._has_valid_credential(FakeRequest(headers={"X-API-Key": made[0][2][:-1] + "z"}))
    check("prefix: the proxy limit's credential test sees both verified keys and not a forged one",
          cred_a and cred_b and not cred_x)

    # 6b. expired keys on a prefix cannot hide a newer live key: the filter is in SQL, before the limit
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    pfx2 = "portal_e0e"
    past = (_dt.now(_tz.utc) - _td(days=1)).isoformat()
    future = (_dt.now(_tz.utc) + _td(days=30)).isoformat()
    for i in range(db.API_KEY_PREFIX_CANDIDATES):
        await db.create_api_key(user_id=u1, name=f"b1-exp{i}", key_hash=auth.hash_password("x" + str(i)), key_prefix=pfx2[:10],
                                scopes="services:read", expires_at=past)
    live_full = (pfx2 + secrets.token_hex(31)[:61])[:71]
    live_id = await db.create_api_key(user_id=u1, name="b1-live", key_hash=auth.hash_password(live_full), key_prefix=pfx2[:10],
                                      scopes="services:read", expires_at=future)
    older_live = await db.create_api_key(user_id=u2, name="b1-live-old", key_hash=auth.hash_password("y"), key_prefix=pfx2[:10],
                                         scopes="services:read", expires_at=None)
    rows = await db.get_api_keys_by_prefix(pfx2[:10])
    check("prefix: four expired keys do not hide the live ones; none of the expired come back",
          [r["id"] for r in rows] == [older_live, live_id],
          str([r["id"] for r in rows]))
    check("prefix: live keys come newest first", [r["id"] for r in rows] == sorted([r["id"] for r in rows], reverse=True))
    out = await server.authenticate_api_key(live_full, "198.51.100.7")
    check("prefix: the live key behind four expired ones authenticates",
          out is not None and out.token_id == f"apikey-{live_id}", str(out))
    cred = await server._has_valid_credential(FakeRequest(headers={"X-API-Key": live_full}))
    check("prefix: the proxy limit's credential test agrees (the live key behind four expired ones is valid)", cred)
    # a key whose time passes between the two calls is judged by the same clock in both places
    just_past = (_dt.now(_tz.utc) - _td(seconds=2)).isoformat()
    await db.conn.execute("UPDATE api_keys SET expires_at = ? WHERE id = ?", (just_past, live_id))
    await db.conn.commit()
    check("prefix: a key that has just expired is gone from the lookup and from the viable list",
          live_id not in [r["id"] for r in await db.get_api_keys_by_prefix(pfx2[:10])]
          and server._api_key_viable_candidates([{"id": live_id, "expires_at": just_past}], "198.51.100.7")[0] == [])
    await db.revoke_api_key(made[0][1], made[0][0])
    out0 = await server.authenticate_api_key(made[0][2], "198.51.100.7")
    out1 = await server.authenticate_api_key(made[1][2], "198.51.100.7")
    check("prefix: revoking one leaves the other working", out0 is None and out1 is not None)
    # the bound one is refused from outside but the other key with the prefix still works
    bound_full = "portal_f1f" + "a" * 61
    bk = await db.create_api_key(user_id=u1, name="b1-sb", key_hash=auth.hash_password(bound_full), key_prefix="portal_f1f",
                                 scopes="services:read", allowed_cidrs="203.0.113.0/24")
    free_full = "portal_f1f" + "b" * 61
    fk = await db.create_api_key(user_id=u2, name="b1-sf", key_hash=auth.hash_password(free_full), key_prefix="portal_f1f",
                                 scopes="services:read")
    outf = await server.authenticate_api_key(free_full, "198.51.100.8")
    outb = await server.authenticate_api_key(bound_full, "198.51.100.8")
    outb_in = await server.authenticate_api_key(bound_full, "203.0.113.8")
    check("prefix: a bound key and an unbound one sharing a prefix each behave by their own binding",
          outf is not None and outf.token_id == f"apikey-{fk}" and outb is None
          and outb_in is not None and outb_in.token_id == f"apikey-{bk}")
    rows = [e for e in await events("api_key_ip_denied") if e["ip"] == "198.51.100.8"]
    check("prefix: the denial is logged for the bound key only when nobody else accepted the request",
          [json.loads(r["details"])["key_id"] for r in rows] == [bk], str(rows))


async def test_playback_cache_and_minting():
    import secrets
    owner = await make_user("pc_owner", "user")
    adm = await make_user("pc_admin", "admin")
    ah = await bearer(adm, ["*"])
    st, k = await create(ah, {"name": "bound", "allowed_cidrs": "203.0.113.0/24", "expires_days": 30})
    check("playback setup: a bound admin key", st == 201 and k["allowed_cidrs"] == ["203.0.113.0/24"], str(k))
    live = "live_" + secrets.token_hex(16)
    await db.create_user_stream(owner, "pc private", live, is_public=False)
    kh = {"X-API-Key": k["key"]}
    server._playback_auth_cache.clear()
    s, _ = await server._stream_read_access(FakeRequest(peer="198.51.100.9", headers=kh), live)
    check("playback: a bound key is refused from outside on a cold cache", s is None)
    server._playback_auth_cache.clear()
    s, _ = await server._stream_read_access(FakeRequest(peer="203.0.113.5", headers=kh), live)
    check("playback: the same key is allowed from inside", s is not None)
    s, _ = await server._stream_read_access(FakeRequest(peer="198.51.100.9", headers=kh), live)
    check("playback: a decision made inside is not reused for a caller outside", s is None)
    server._playback_auth_cache.clear()
    s, _ = await server._stream_read_access(FakeRequest(peer="198.51.100.9", headers=kh), live)
    s2, _ = await server._stream_read_access(FakeRequest(peer="203.0.113.5", headers=kh), live)
    check("playback: a refusal from outside is not reused for the owner inside", s is None and s2 is not None)

    # A key cannot mint keys: only a sign-in can.
    for who, role, scopes in (("pc_adm2", "admin", ["*"]), ("pc_mem", "user", ["services:read", "access:*"])):
        uid = await make_user(who, role)
        hdr = await bearer(uid, scopes)
        st, bk = await create(hdr, {"name": "bound", "allowed_cidrs": "203.0.113.0/24", "expires_days": 30})
        before = len(body_of(await server.http_list_api_keys(FakeRequest(headers=hdr)))["api_keys"])
        r = await server.http_create_api_key(FakeRequest(peer="203.0.113.5", headers={"X-API-Key": bk["key"]},
                     body={"name": "escape", "expires_days": "never", "scopes": "*"}))
        after = len(body_of(await server.http_list_api_keys(FakeRequest(headers=hdr)))["api_keys"])
        check(f"mint ({role}): a bound key inside its range cannot create a key", r.status == 403 and after == before,
              f"{r.status} {before} {after}")
        st, ok = await create(hdr, {"name": "still", "expires_days": 30})
        check(f"mint ({role}): a sign-in still creates keys", st == 201, str(st))


def test_window_source():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "static" / "js" / "user-connections.js").read_text(encoding="utf-8")
    check("window: the free-text scope box is gone, a picker, an address box and a 90 day default are in",
          'id="api-key-scopes"' not in html and 'id="api-key-scope-picker"' in html and 'id="api-key-cidrs"' in html
          and '<option value="90" selected>' in html and '<option value="never">' in html)
    check("window: the script reads the registry, sends expires_days and allowed_cidrs, and not the ignored old name",
          "/api/api-keys/scopes" in js and "expires_days:" in js and "allowed_cidrs:" in js and "expires_in_days" not in js)
    check("window: the list shows both addresses, the binding and the stale badge, escaped",
          "key.created_ip" in js and "key.last_used_ip" in js and "key.allowed_cidrs" in js and "key.stale" in js
          and "escapeHtml(key.last_used_ip)" in js and "escapeHtml(key.scopes" in js)
    check("window: a full-access key with no expiry is warned about in the form and after creation",
          "api-key-create-warning" in html and "new-api-key-warning" in html and "expiry_warning" in js)


async def main():
    test_policy()
    test_window_source()
    await test_migration()
    await db.connect()
    secevents.log.bind(db)
    try:
        await test_auth_and_routes()
        await test_fix_b1()
        await test_playback_cache_and_minting()
    finally:
        await db.close()


asyncio.run(main())
_TMP.cleanup()
if failures:
    print(f"test_apikeys: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("test_apikeys: all checks passed")
