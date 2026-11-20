"""Tight per-address limit for logged-out hits on /proxy, /search and /browser.

Covers: the path rule (exact prefixes only); the token bucket (30 allowed, then 429 with
Retry-After, refill, a refused hit takes nothing); a logged-out client and a client with a bogus,
forged or revoked credential limited the same; a valid session, Bearer token, ?token= and verified
API key never counted (300 asset hits); an unverified API key counted and never hashed; /login,
/api, /admin, /health and static files never limited and login still working from a limited address;
exempt addresses; the off switch and the saved settings; a bounded table; no ban, no probe strike
and no alert feed from limiting; the security headers on the 429.

Run:  venv/bin/python tests/test_proxy_limit.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)

_TMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "server.db")
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ["NEVER_BAN_CIDRS"] = ""

import jwt  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from multidict import CIMultiDict  # noqa: E402

import auth as auth_module  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
from auth import hash_password  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


A = "45.9.9.9"
B = "8.8.8.8"
C = "9.9.9.9"
PASSWORD = "Right-Pass-1!"


class _Transport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, name, default=None):
        return (self.peer, 4242) if name == "peername" else default


def req(peer, path="/proxy/x", headers=None, method="GET"):
    return make_mocked_request(method, path, headers=CIMultiDict(headers or {}), transport=_Transport(peer))


class Counter:
    """The handler behind the middleware: counts how often it was reached."""

    def __init__(self):
        self.n = 0

    async def __call__(self, request):
        self.n += 1
        return web.Response(status=404, text="no such connection")


async def hit(peer, path="/proxy/x", headers=None, handler=None):
    handler = handler or Counter()
    resp = await server.proxy_limit_middleware(req(peer, path, headers), handler)
    return resp


async def hits(peer, n, path="/proxy/x", headers=None):
    got = []
    h = Counter()
    for _ in range(n):
        got.append((await hit(peer, path, headers, h)).status)
    return got, h.n


def fresh():
    server._proxy_buckets.clear()
    server._proxy_limit_cfg.clear()
    server._proxy_limit_cfg.update(server.PROXY_LIMIT_DEFAULTS)


def first_429(got):
    return got.index(429) + 1 if 429 in got else None


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------

check("defaults: on, 30 a minute", server.PROXY_LIMIT_DEFAULTS == {"enabled": True, "per_minute": 30})
paths_in = ["/proxy/abc", "/proxy/abc/x/y.js", "/search", "/search/", "/search/?q=1", "/browser", "/browser/x"]
paths_out = ["/login", "/api/search/status", "/api/me", "/admin", "/health", "/static/portal.js", "/searchfoo",
             "/browserx", "/proxy", "/proxyfoo/x", "/", "/dashboard", "/ws/chat"]
check("path rule: /proxy/, /search and /browser only", all(server._is_proxy_limit_path(p) for p in paths_in)
      and not any(server._is_proxy_limit_path(p) for p in paths_out),
      str([p for p in paths_in if not server._is_proxy_limit_path(p)] + [p for p in paths_out if server._is_proxy_limit_path(p)]))

server._proxy_buckets.clear()
t = 1000.0
res = [server._proxy_bucket_take("k", 30, t) for _ in range(30)]
check("bucket: 30 hits at one instant are all allowed", set(res) == {0.0})
wait = server._proxy_bucket_take("k", 30, t)
check("bucket: the 31st is refused with a wait of about two seconds", 1.9 < wait <= 2.0, str(wait))
check("bucket: a refused hit takes nothing (still about two seconds)",
      1.9 < server._proxy_bucket_take("k", 30, t) <= 2.0)
check("bucket: after the wait one hit is allowed, the next is not",
      server._proxy_bucket_take("k", 30, t + 2.01) == 0.0 and server._proxy_bucket_take("k", 30, t + 2.01) > 0)
check("bucket: a minute of quiet refills to the full 30",
      all(server._proxy_bucket_take("k", 30, t + 200) == 0.0 for _ in range(30))
      and server._proxy_bucket_take("k", 30, t + 200) > 0)
check("bucket key: an IPv6 address is kept as its /64, IPv4-mapped folds to IPv4",
      server._proxy_bucket_key("2001:db8:1:2:aaaa::1") == server._proxy_bucket_key("2001:DB8:1:2:bbbb::9")
      and server._proxy_bucket_key("2001:db8:1:3::1") != server._proxy_bucket_key("2001:db8:1:2::1")
      and server._proxy_bucket_key("::ffff:45.9.9.9") == "45.9.9.9")

# Bounded table: expired buckets go first, then the oldest
server._proxy_buckets.clear()
small = server._PROXY_LIMIT_TABLE_MAX
server._PROXY_LIMIT_TABLE_MAX = 5
try:
    now = 5000.0
    for i in range(5):
        server._proxy_bucket_take(f"old{i}", 30, now)           # 29 tokens: full again after 2 s
    server._proxy_bucket_take("busy", 30, now)
    for _ in range(29):
        server._proxy_bucket_take("busy", 30, now)              # drained, not expired
    check("table: bounded at its capacity while filling", len(server._proxy_buckets) <= 5)
    server._proxy_bucket_take("new1", 30, now + 10)
    check("table: a full table drops expired buckets first and keeps the drained one",
          "busy" in server._proxy_buckets and "new1" in server._proxy_buckets
          and not any(k.startswith("old") for k in server._proxy_buckets), str(list(server._proxy_buckets)))
    server._proxy_buckets.clear()
    for i in range(5):
        for _ in range(30):
            server._proxy_bucket_take(f"d{i}", 30, now)         # all drained: none expired
    server._proxy_bucket_take("fresh", 30, now)
    check("table: when none has expired the least recently used goes and the size stays bounded",
          len(server._proxy_buckets) == 5 and "d0" not in server._proxy_buckets and "fresh" in server._proxy_buckets,
          str(list(server._proxy_buckets)))
    # a flood of distinct addresses never grows it
    for i in range(500):
        server._proxy_bucket_take(f"flood{i}", 30, now + 1)
    check("table: 500 more distinct addresses leave it at its capacity", len(server._proxy_buckets) == 5)
finally:
    server._PROXY_LIMIT_TABLE_MAX = small
    server._proxy_buckets.clear()


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "pl.db"))
        await d.connect()
        saved = (server.db, server.monotonic, server.security_event_nowait)
        saved_auth_db = auth_module.db
        noted = []
        try:
            server.db = auth_module.db = d
            secevents.log.bind(d)
            server.security_event_nowait = lambda event, **kw: noted.append((event, kw))
            alice = await d.create_user("alice_pl", hash_password(PASSWORD))
            fresh()
            await server._load_proxy_limit_state()
            check("settings: a fresh database loads the defaults (on, 30)",
                  server._proxy_limit_cfg == {"enabled": True, "per_minute": 30})

            # ---- a logged-out client
            got, reached = await hits(A, 40)
            check("logged out: 40 hits on /proxy/x give 429 from the 31st on, the handler is reached 30 times",
                  first_429(got) == 31 and set(got[30:]) == {429} and reached == 30, str(got))
            resp = await hit(A)
            check("logged out: the 429 carries Retry-After and a JSON error",
                  resp.status == 429 and int(resp.headers["Retry-After"]) >= 1 and b"error" in resp.body,
                  str(resp.headers))
            check("logged out: another address is not affected", (await hit(B)).status == 404)
            check("logged out: each limited hit is counted as an aggregated rate_limited event",
                  any(e == "rate_limited" and kw.get("ip") == A and kw["details"]["scope"] == "logged_out_proxy"
                      for e, kw in noted))
            for path in ("/search", "/search/?q=x&format=json", "/browser?connection=x", "/browser/y"):
                fresh()
                got, _ = await hits(A, 40, path)
                check(f"logged out: {path} is limited too", first_429(got) == 31, str(got))
            fresh()
            got, _ = await hits(A, 35, "/proxy/x/y.js?v=1")
            check("logged out: a deep /proxy path and a query string are limited", first_429(got) == 31, str(got))

            # ---- bogus credentials are still logged out
            forged = jwt.encode({"sub": "1", "jti": "nope", "scopes": ["*"]}, "another-secret", algorithm=Config.JWT_ALGORITHM)
            sname = Config.SESSION_COOKIE_NAME
            bogus = {
                "garbage cookie": {"Cookie": f"{sname}=bogus"},
                "forged cookie": {"Cookie": f"{sname}={forged}"},
                "empty cookie": {"Cookie": f"{sname}="},
                "bogus Bearer": {"Authorization": "Bearer nonsense"},
                "bogus ?token path": None,
                "bogus API key": {"X-API-Key": "portal_" + "0" * 64},
                "stream key": {"X-Stream-Key": "live_abc"},
            }
            for name, hdr in bogus.items():
                fresh()
                path = "/proxy/x?token=bogus" if hdr is None else "/proxy/x"
                got, reached = await hits(A, 40, path, hdr or {})
                check(f"{name}: limited the same, the 31st gets 429", first_429(got) == 31 and reached == 30, str(got))
            sig_ok_no_row = jwt.encode({"sub": str(alice), "jti": "no-such-row", "scopes": ["*"]},
                                       Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
            fresh()
            got, _ = await hits(A, 40, headers={"Cookie": f"{sname}={sig_ok_no_row}"})
            check("a correctly signed token with no live row is limited", first_429(got) == 31, str(got))

            # ---- a valid session is never counted
            fresh()
            jwt_tok, tid = await auth_module.create_access_token(
                user_id=alice, scopes=["services:read", "access:*"], name="web_session",
                expires_in_hours=24, ip=A, user_agent="UA")
            cookie = {"Cookie": f"{sname}={jwt_tok}"}
            got, reached = await hits(A, 300, "/proxy/x/asset.js", cookie)
            check("valid session: 300 asset hits through /proxy are never limited", set(got) == {404} and reached == 300,
                  str(set(got)))
            got, _ = await hits(A, 100, "/search/", cookie)
            got2, _ = await hits(A, 100, "/browser?connection=x", cookie)
            check("valid session: /search and /browser are not limited either", set(got) == {404} and set(got2) == {404})
            check("valid session: nothing was taken from the address's bucket", server._proxy_bucket_key(A) not in server._proxy_buckets)
            got, _ = await hits(A, 40)
            check("the same address logged out is still limited at 31", first_429(got) == 31, str(got))
            check("valid session: unaffected while that address's bucket is empty", (await hit(A, headers=cookie)).status == 404)
            check("valid Bearer token is never limited", (await hits(A, 50, headers={"Authorization": f"Bearer {jwt_tok}"}))[0] == [404] * 50)
            check("valid ?token= is never limited", (await hits(A, 50, f"/proxy/x?token={jwt_tok}"))[0] == [404] * 50)
            await d.revoke_token(tid)
            fresh()
            got, _ = await hits(A, 40, headers=cookie)
            check("a revoked session cookie is limited like no cookie", first_429(got) == 31, str(got))

            # ---- API keys: verified ones pass, unverified ones are counted and never hashed
            full, key_hash, prefix = auth_module.generate_api_key()
            key_id = await d.create_api_key(alice, "k", key_hash, prefix)
            hashed = []

            async def no_argon(*a, **k):
                hashed.append(a)
                return False
            real_verify = server._verify_api_key_offloop
            server._verify_api_key_offloop = no_argon
            try:
                fresh()
                server._verified_api_keys.clear()
                got, _ = await hits(A, 40, headers={"X-API-Key": full})
                check("API key not yet verified: counted as logged out, limited at 31", first_429(got) == 31, str(got))
                check("API key not yet verified: the middleware never ran the hash", hashed == [])
                server._api_key_remember(key_id, full, key_hash)
                fresh()
                got, _ = await hits(A, 100, headers={"X-API-Key": full})
                check("API key already verified: never limited, still no hash run", set(got) == {404} and hashed == [])
                await d.conn.execute("UPDATE api_keys SET allowed_cidrs = '10.1.2.3/32' WHERE id = ?", (key_id,))
                await d.conn.commit()
                fresh()
                got, _ = await hits(A, 40, headers={"X-API-Key": full})
                check("API key verified but bound to other networks: limited", first_429(got) == 31, str(got))
                await d.conn.execute("UPDATE api_keys SET allowed_cidrs = NULL, revoked = 1 WHERE id = ?", (key_id,))
                await d.conn.commit()
                fresh()
                got, _ = await hits(A, 40, headers={"X-API-Key": full})
                check("API key revoked: limited", first_429(got) == 31, str(got))
            finally:
                server._verify_api_key_offloop = real_verify
                server._verified_api_keys.clear()

            # ---- outside the three prefixes: never limited
            fresh()
            for p in ("/login", "/api/me", "/api/search/status", "/admin", "/health", "/static/portal.js", "/searchfoo", "/browserx"):
                got, reached = await hits(A, 120, p)
                check(f"{p} is never limited", set(got) == {404} and reached == 120, str(set(got)))

            # ---- login still works from a limited address
            fresh()
            await hits(A, 40)
            check("setup: the address is limited", (await hit(A)).status == 429)
            sys.path.insert(0, str(Path(SRC) / "tests"))

            class _LoginReq:
                def __init__(self, peer):
                    self._inner = req(peer, "/login", method="POST")
                    self.content_type = "application/json"

                async def json(self):
                    return {"username": "alice_pl", "password": PASSWORD}

                def __getattr__(self, n):
                    return getattr(self._inner, n)
            server.rate_limits.clear()
            lr = await server.http_login_submit(_LoginReq(A))
            check("login from a limited address succeeds", lr.status == 200, str(lr.status))
            new_cookie = lr.cookies.get(sname)
            check("login: the response sets a session cookie", new_cookie is not None)
            if new_cookie is not None:
                check("login: the new session passes /proxy at once although the bucket is empty",
                      (await hit(A, headers={"Cookie": f"{sname}={new_cookie.value}"})).status == 404)

            # ---- exempt addresses
            fresh()
            local = [set((await hits(p, 60))[0]) for p in ("127.0.0.1", "10.1.2.3", "192.168.5.5", "::1", "fe80::1")]
            check("exempt: loopback, private and link-local are never limited", all(x == {404} for x in local), str(local))
            server._never_ban_admin_nets = server.ipguard.validate_cidr_list(["8.8.8.0/24"])
            try:
                check("exempt: an address on the never-ban list is never limited", set((await hits(B, 60))[0]) == {404})
                check("exempt: another address is limited", first_429((await hits(C, 40))[0]) == 31)
            finally:
                server._never_ban_admin_nets = []
            fresh()
            check("trusted proxy peer: the client address behind it is the one limited",
                  first_429((await hits("173.245.48.5", 40, headers={"CF-Connecting-IP": C}))[0]) == 31
                  and (await hit("173.245.48.5", headers={"CF-Connecting-IP": B})).status == 404)

            # ---- the off switch and the saved settings
            fresh()
            server._proxy_limit_cfg["enabled"] = False
            got, reached = await hits(A, 100)
            check("switched off: nothing is limited", set(got) == {404} and reached == 100)
            await d.set_setting("proxy_limit_enabled", "0")
            await server._load_proxy_limit_state()
            check("saved off: loaded as off after a restart", server._proxy_limit_cfg["enabled"] is False
                  and set((await hits(A, 50))[0]) == {404})
            await d.set_setting("proxy_limit_enabled", "1")
            await d.set_setting("proxy_limit_per_minute", "10")
            await server._load_proxy_limit_state()
            got, _ = await hits(A, 20)
            check("saved rate 10: the 11th hit is refused", server._proxy_limit_cfg["per_minute"] == 10 and first_429(got) == 11, str(got))
            await d.set_setting("proxy_limit_per_minute", "100000")
            await server._load_proxy_limit_state()
            check("an out-of-range saved rate keeps the default 30", server._proxy_limit_cfg["per_minute"] == 30)
            await d.set_setting("proxy_limit_per_minute", "abc")
            await server._load_proxy_limit_state()
            check("an unusable saved rate keeps the default 30", server._proxy_limit_cfg["per_minute"] == 30)
            await d.set_setting("proxy_limit_enabled", "1")
            await d.set_setting("proxy_limit_per_minute", "30")

            mws = list(server.create_app().middlewares)
            check("the app runs the limit inside the ban and security-headers middleware",
                  mws.index(server.security_headers_middleware) < mws.index(server.proxy_limit_middleware), str(mws))

            # ---- the settings route
            class _JsonReq:
                def __init__(self, body):
                    self._inner = req("45.9.9.9", "/api/admin/proxy-limit", method="PUT")
                    self._body = body

                async def json(self):
                    return self._body

                def __getattr__(self, n):
                    return getattr(self._inner, n)

            async def fake_super(request):
                return {"id": alice, "username": "alice_pl"}, None

            async def fake_admin(request):
                return object(), None
            saved_super, saved_admin = server._backup_superadmin, server._admin_only
            server._backup_superadmin, server._admin_only = fake_super, fake_admin
            try:
                fresh()
                for bad in ({"enabled": "yes"}, {"per_minute": 1}, {"per_minute": 9999}, {"per_minute": "30"},
                            {"per_minute": True}, {"per_minute": 12.5}, {"bogus": 1}):
                    r = await server.http_put_proxy_limit(_JsonReq(bad))
                    check(f"settings route: refuses {bad}", r.status == 400, str(r.body))
                r = await server.http_put_proxy_limit(_JsonReq([]))
                check("settings route: refuses a non-object body", r.status == 400)
                check("settings route: a refused change leaves everything as it was",
                      server._proxy_limit_cfg == server.PROXY_LIMIT_DEFAULTS)
                await hits(B, 5)
                check("setup: a bucket exists", len(server._proxy_buckets) == 1)
                r = await server.http_put_proxy_limit(_JsonReq({"per_minute": 12}))
                body = __import__("json").loads(r.body)
                check("settings route: a valid change is applied, returned and clears the buckets",
                      r.status == 200 and body["per_minute"] == 12 and body["enabled"] is True and body["saved"] is True
                      and not server._proxy_buckets, str(body))
                check("settings route: the new rate is in force at once", first_429((await hits(A, 20))[0]) == 13)
                fresh()
                await server._load_proxy_limit_state()
                check("settings route: the change is saved and loaded again at start",
                      server._proxy_limit_cfg == {"enabled": True, "per_minute": 12}, str(server._proxy_limit_cfg))
                r = await server.http_put_proxy_limit(_JsonReq({"enabled": False}))
                check("settings route: the switch turns it off at once", r.status == 200
                      and set((await hits(A, 60))[0]) == {404})
                cur = await d.conn.execute("SELECT * FROM security_events WHERE event = 'proxy_limit_changed'")
                evs = [dict(x) for x in await cur.fetchall()]
                check("settings route: each change is a security event and an audit entry",
                      len(evs) == 2 and all(e["user_id"] == alice and e["category"] == "security" for e in evs)
                      and bool(await d.get_audit_log(action="proxy_limit.update")), str(evs))
                g = await server.http_get_proxy_limit(_JsonReq({}))
                gb = __import__("json").loads(g.body)
                check("settings route: GET shows the values, defaults and limits",
                      gb["defaults"]["per_minute"] == 30 and gb["limits"]["per_minute"] == {"min": 5, "max": 600}
                      and gb["enabled"] is False and "your_ip" in gb, str(gb))
            finally:
                server._backup_superadmin, server._admin_only = saved_super, saved_admin
                await d.delete_setting("proxy_limit_enabled")
                await d.delete_setting("proxy_limit_per_minute")
                fresh()

            # ---- no ban, no probe strike, headers on the 429, over the real middleware order
            fresh()
            server._blocked_ips.clear()
            server._probe_strikes.clear()
            server._probe_blocks.clear()
            old_strikes = Config.PROBE_BLOCK_STRIKES
            Config.PROBE_BLOCK_STRIKES = 3
            try:
                inner = Counter()

                async def chain(r):
                    return await server.proxy_limit_middleware(r, inner)
                statuses = []
                last = None
                for _ in range(140):
                    last = await server.security_headers_middleware(req(A, "/proxy/.env"), chain)
                    statuses.append(last.status)
                check("100 limited hits: 429s, no probe strike, no block, no stored ban row",
                      statuses.count(429) == 110 and not server._probe_strikes and not server._probe_blocks
                      and not server._is_ip_blocked(A) and not server._is_probe_blocked(A)
                      and not [r for r in await (await d.conn.execute("SELECT * FROM blocked_ips")).fetchall()],
                      f"{statuses.count(429)} {server._probe_strikes}")
                check("the 429 passes the security headers", last.status == 429
                      and "Strict-Transport-Security" in last.headers and last.headers.get("X-Frame-Options") == "SAMEORIGIN")
            finally:
                Config.PROBE_BLOCK_STRIKES = old_strikes
        finally:
            server.db, server.monotonic, server.security_event_nowait = saved
            auth_module.db = saved_auth_db
            await d.close()


asyncio.run(main())

if failures:
    print(f"\n{len(failures)} FAILED: {failures}")
    sys.exit(1)
print("\nall passed")
