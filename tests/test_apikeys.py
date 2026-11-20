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
        await test_playback_cache_and_minting()
    finally:
        await db.close()


asyncio.run(main())
_TMP.cleanup()
if failures:
    print(f"test_apikeys: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("test_apikeys: all checks passed")
