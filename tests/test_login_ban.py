"""Failed-login address throttling and persisted, escalating, always-temporary automatic bans.

Covers: the per-address counter fed by password, 2FA and POST /api/token failures; the ban it
writes (kind 'login', expires_at, security event); survival across a restart and expiry on time;
doubling on a repeat offence within 7 days and the 24 hour cap; the never-ban exemptions (loopback,
trusted proxy, never-ban lists); the household exemption (a successful sign-in from the same
address for the same user within 30 days); off by default; scanner-probe bans stored the same way;
the settings route; the admin list; the command-line unblock; the migration and that release 1.17.0
still starts on the migrated database.

Run:  venv/bin/python tests/test_login_ban.py
"""

import asyncio
import contextlib
import io
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)

_TMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "server.db")
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ["NEVER_BAN_CIDRS"] = ""

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from multidict import CIMultiDict  # noqa: E402

import auth as auth_module  # noqa: E402
import ban_cli  # noqa: E402
import ipguard  # noqa: E402
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


GLOBAL_A = "1.2.3.4"
GLOBAL_B = "45.9.9.9"
GLOBAL_C = "8.8.8.8"
GLOBAL_D = "9.9.9.9"
CF_PEER = "173.245.48.5"
PASSWORD = "Right-Pass-1!"


class _Transport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, name, default=None):
        return (self.peer, 4242) if name == "peername" else default


class _Req:
    """A mocked request that carries a JSON body."""

    def __init__(self, peer, body, headers=None, path="/login"):
        self._inner = make_mocked_request("POST", path, headers=CIMultiDict(headers or {}),
                                          transport=_Transport(peer))
        self._body = body
        self.content_type = "application/json"

    async def json(self):
        return self._body

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _JsonRequest(_Req):
    def __init__(self, body):
        super().__init__("203.0.113.5", body)


async def attempt(ip, username, password, via="web", headers=None, totp=None):
    body = {"username": username, "password": password}
    if totp is not None:
        body["totp_code"] = totp
    req = _Req(ip, body, headers=headers)
    fn = server.http_login_submit if via == "web" else server.http_create_token
    resp = await fn(req)
    return resp.status


async def flood(ip, username, n, via="web", password="wrong", headers=None):
    got = []
    for _ in range(n):
        server.rate_limits.clear()
        got.append(await attempt(ip, username, password, via=via, headers=headers))
    return got


async def rows(d, ip=None):
    cur = await d.conn.execute("SELECT * FROM blocked_ips" + (" WHERE ip_address = ?" if ip else ""),
                               (ip,) if ip else ())
    return [dict(r) for r in await cur.fetchall()]


async def events(d, name="ip_blocked"):
    cur = await d.conn.execute("SELECT * FROM security_events WHERE event = ? ORDER BY id", (name,))
    out = []
    for r in await cur.fetchall():
        r = dict(r)
        r["details"] = json.loads(r["details"]) if r.get("details") else {}
        out.append(r)
    return out


def reset_state():
    server._blocked_ips.clear()
    server._login_fails.clear()
    server._login_known_cache.clear()
    server._login_ban_pending.clear()
    server._probe_strikes.clear()
    server._probe_blocks.clear()
    server.rate_limits.clear()
    server._totp_pair_state.clear()
    server._totp_user_state.clear()


def past(seconds=60):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------

check("login banning is off by default with the conservative defaults",
      server.LOGIN_BAN_DEFAULTS == {"enabled": False, "max_failures": 20, "find_minutes": 10, "base_minutes": 15})
check("duration: 15 min, doubled each repeat",
      [server._ban_seconds(900, n) for n in (1, 2, 3, 4)] == [900, 1800, 3600, 7200])
check("duration: capped at 24 hours however many repeats",
      server._ban_seconds(900, 8) == 86400 and server._ban_seconds(900, 500) == 86400
      and server._ban_seconds(1, 10 ** 6) <= 86400)
check("duration: the base itself is kept when it is longer than the cap",
      server._ban_seconds(2 * 86400, 1) == 2 * 86400 and server._ban_seconds(2 * 86400, 5) == 2 * 86400)


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "lb.db")
        d = Database(path)
        await d.connect()
        saved = (server.db, Config.PROBE_BLOCK_STRIKES, Config.PROBE_BLOCK_SECONDS)
        saved_auth_db = auth_module.db
        try:
            server.db = auth_module.db = d
            secevents.log.bind(d)
            alice = await d.create_user("alice_lb", hash_password(PASSWORD))
            await d.create_user("bob_lb", hash_password(PASSWORD))
            reset_state()
            await server._load_login_ban_state()
            check("settings: a fresh database loads the defaults (off)",
                  server._login_ban_cfg == server.LOGIN_BAN_DEFAULTS)

            # ---- off: the counter exists, nothing is banned
            got = await flood(GLOBAL_A, "alice_lb", 30)
            canon = ipguard.canonical_ip(GLOBAL_A)
            check("off: 30 wrong passwords are all refused with 401, no ban, no row",
                  set(got) == {401} and not await rows(d) and not server._is_ip_blocked(GLOBAL_A), str(got))
            check("off: the counter still counts", len(server._login_fails.get(canon, ())) >= 20,
                  str(len(server._login_fails.get(canon, ()))))

            # ---- on, small time scale so a ban can expire inside the test
            reset_state()
            server._login_ban_cfg.update({"enabled": True, "max_failures": 20, "find_minutes": 10,
                                          "base_minutes": 0.05})     # 3 seconds
            got = await flood(GLOBAL_A, "alice_lb", 19)
            check("on: 19 wrong passwords do not ban", not server._is_ip_blocked(GLOBAL_A) and not await rows(d), str(got))
            await flood(GLOBAL_A, "alice_lb", 1)
            r = await rows(d, GLOBAL_A)
            check("on: the 20th wrong password writes a temporary 'login' ban",
                  len(r) == 1 and r[0]["kind"] == "login" and r[0]["source"] == "auto" and r[0]["expires_at"]
                  and server._is_ip_blocked(GLOBAL_A), str(r))
            ev = await events(d)
            check("on: the ban is a security event with kind, expiry, offence and duration",
                  len(ev) == 1 and ev[0]["details"].get("kind") == "login" and ev[0]["details"].get("offences") == 1
                  and ev[0]["details"].get("seconds") == 3 and ev[0]["details"].get("expires_at") == r[0]["expires_at"]
                  and ev[0]["ip"] == GLOBAL_A, str(ev))
            # the middleware refuses the address now
            async def ok_handler(request):
                return web.Response(text="fine")
            mw = await server.security_headers_middleware(
                make_mocked_request("GET", "/", transport=_Transport(GLOBAL_A)), ok_handler)
            check("on: the middleware answers the banned address 403", mw.status == 403)

            # ---- restart
            await d.close()
            d = Database(path)
            await d.connect()
            server.db = auth_module.db = d
            secevents.log.bind(d)
            server._blocked_ips.clear()
            server._blocked_ips.update(await d.get_active_blocked_ips())
            check("restart: the ban is loaded again from the database", server._is_ip_blocked(GLOBAL_A))

            # ---- expiry on time
            time.sleep(3.5)
            check("expiry: after its time the ban is ignored at once", not server._is_ip_blocked(GLOBAL_A))
            check("expiry: an expired row is not loaded", GLOBAL_A not in await d.get_active_blocked_ips())
            check("expiry: the sweep deletes the expired row", await d.sweep_auto_bans() == 1 and not await rows(d))
            mw = await server.security_headers_middleware(
                make_mocked_request("GET", "/", transport=_Transport(GLOBAL_A)), ok_handler)
            check("expiry: the address is served again", mw.status == 200)

            # ---- second offence doubles
            server._login_fails.clear()
            await flood(GLOBAL_A, "alice_lb", 20)
            ev = await events(d)
            check("repeat: a second offence within 7 days doubles the duration",
                  len(ev) == 2 and ev[1]["details"].get("offences") == 2 and ev[1]["details"].get("seconds") == 6,
                  str([e["details"] for e in ev]))
            await d.conn.execute("UPDATE blocked_ips SET expires_at = ?", (past(),))
            await d.conn.commit()
            server._blocked_ips.clear()
            await flood(GLOBAL_A, "alice_lb", 20)
            ev = await events(d)
            check("repeat: a third offence doubles again",
                  len(ev) == 3 and ev[2]["details"].get("seconds") == 12 and ev[2]["details"].get("offences") == 3,
                  str([e["details"] for e in ev]))
            await d.conn.execute("UPDATE ip_ban_history SET last_ban_at = datetime('now', '-8 days')")
            await d.conn.execute("UPDATE blocked_ips SET expires_at = ?", (past(),))
            await d.conn.commit()
            server._blocked_ips.clear()
            await flood(GLOBAL_A, "alice_lb", 20)
            ev = await events(d)
            check("repeat: an offence after more than 7 days starts again at the base",
                  ev[-1]["details"].get("offences") == 1 and ev[-1]["details"].get("seconds") == 3,
                  str([e["details"] for e in ev]))
            check("no ban is ever permanent", all(r["expires_at"] for r in await rows(d)))
            await d.conn.execute("UPDATE ip_ban_history SET last_ban_at = datetime('now', '-8 days')")
            await d.conn.commit()
            await d.sweep_auto_bans()
            cur = await d.conn.execute("SELECT COUNT(*) AS n FROM ip_ban_history")
            check("sweep: escalation history older than 7 days is dropped", (await cur.fetchone())["n"] == 0)
            await d.conn.execute("DELETE FROM login_addresses")
            await d.conn.execute("INSERT INTO login_addresses VALUES (999, '1.1.1.1', datetime('now', '-31 days'))")
            await d.conn.execute("INSERT INTO login_addresses VALUES (999, '2.2.2.2', datetime('now', '-1 days'))")
            await d.conn.commit()
            await d.sweep_auto_bans()
            cur = await d.conn.execute("SELECT ip_address FROM login_addresses WHERE user_id = 999")
            check("sweep: sign-in addresses older than 30 days go even for an account that never signs in again",
                  [r["ip_address"] for r in await cur.fetchall()] == ["2.2.2.2"])

            # ---- exempt addresses
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("DELETE FROM ip_ban_history")
            await d.conn.commit()
            await flood("127.0.0.1", "alice_lb", 25)
            check("exempt: 127.0.0.1 is never banned", not await rows(d) and not server._login_fails)
            await flood("::1", "alice_lb", 25)
            check("exempt: ::1 is never banned", not await rows(d))
            await flood(CF_PEER, "alice_lb", 25)
            check("exempt: a trusted proxy peer (Cloudflare range, no client header) is never banned", not await rows(d))
            await flood("127.0.0.1", "alice_lb", 25, headers={"CF-Connecting-IP": GLOBAL_B})
            check("control: loopback carrying a Cloudflare client header IS counted against that client when loopback is "
                  "a trusted proxy (otherwise the peer is exempt)",
                  bool(await rows(d, GLOBAL_B)) == bool(server._is_trusted_proxy("127.0.0.1")))
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            reset_state()
            server._never_ban_env_nets = ipguard.parse_env_cidrs("8.8.8.0/24")[0]
            await flood(GLOBAL_C, "alice_lb", 25)
            check("exempt: an address in NEVER_BAN_CIDRS is never banned", not await rows(d))
            server._never_ban_env_nets = []
            server._never_ban_admin_nets = ipguard.validate_cidr_list(["9.9.9.0/24"])
            await flood(GLOBAL_D, "alice_lb", 25)
            check("exempt: an address on the admin never-ban list is never banned", not await rows(d))
            server._never_ban_admin_nets = []
            reset_state()
            await flood(GLOBAL_C, "alice_lb", 20)
            check("control: the same address is banned once it is no longer exempt", bool(await rows(d, GLOBAL_C)))
            exempt = await server._auto_block_ip("127.0.0.1", "x", 60, kind="login")
            check("the helper itself refuses an exempt address", exempt == "loopback"
                  and not await rows(d, "127.0.0.1"))

            # ---- 2FA failures and POST /api/token failures count
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            await flood(GLOBAL_B, "alice_lb", 5, via="token")
            check("POST /api/token: wrong passwords are counted",
                  len(server._login_fails.get(GLOBAL_B, ())) == 5)
            await flood(GLOBAL_B, "no_such_user", 3)
            check("an unknown account is counted too", len(server._login_fails.get(GLOBAL_B, ())) == 8)
            user = await d.get_user_by_id(await d.get_user_by_username("bob_lb") and (await d.get_user_by_username("bob_lb"))["id"])
            for _ in range(3):
                res, _ = await server.verify_second_factor(user, "000000", GLOBAL_B)
            check("a wrong 2FA code is counted", res == "invalid" and len(server._login_fails.get(GLOBAL_B, ())) == 11,
                  str(len(server._login_fails.get(GLOBAL_B, ()))))
            await flood(GLOBAL_B, "alice_lb", 9, via="token")
            check("password, token and 2FA failures add up to a ban", bool(await rows(d, GLOBAL_B)))

            # ---- household exemption
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            st = await attempt(GLOBAL_C, "alice_lb", PASSWORD)
            check("household: a correct sign-in succeeds and the address is remembered for that user",
                  st == 200 and await d.has_recent_login_from(alice, GLOBAL_C), str(st))
            await flood(GLOBAL_C, "alice_lb", 40)
            check("household: typos against the same user from a known address never ban",
                  not await rows(d, GLOBAL_C) and not server._login_fails.get(GLOBAL_C))
            await flood(GLOBAL_C, "bob_lb", 20)
            check("household: failures against another account from that address never ban either",
                  not await rows(d, GLOBAL_C) and not server._is_ip_blocked(GLOBAL_C) and not server._login_fails.get(GLOBAL_C))
            await flood(GLOBAL_C, "no_such_name_lb", 40)
            check("household: failures against an unknown name from that address never ban either",
                  not await rows(d, GLOBAL_C) and not server._is_ip_blocked(GLOBAL_C) and not server._login_fails.get(GLOBAL_C))
            server._login_known_cache.clear()
            await d.conn.execute("DELETE FROM tokens WHERE user_id = ?", (alice,))
            await d.conn.commit()
            await flood(GLOBAL_C, "bob_lb", 40, via="token")
            check("household: still no ban once the session tokens and the cache are gone",
                  not await rows(d, GLOBAL_C) and not server._is_ip_blocked(GLOBAL_C))
            await d.conn.execute("UPDATE login_addresses SET last_login_at = datetime('now', '-31 days') WHERE ip_address = ?", (GLOBAL_C,))
            await d.conn.commit()
            server._login_known_cache.clear()
            await flood(GLOBAL_C, "bob_lb", 20)
            check("household: with no sign-in from the address in 30 days the same failures do ban",
                  bool(await rows(d, GLOBAL_C)))
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            await flood(GLOBAL_D, "alice_lb", 20)
            check("household: another address is not exempt", bool(await rows(d, GLOBAL_D)))
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("UPDATE login_addresses SET last_login_at = datetime('now', '-31 days')")
            await d.conn.execute("DELETE FROM tokens")
            await d.conn.commit()
            await flood(GLOBAL_C, "alice_lb", 20)
            check("household: a sign-in older than 30 days no longer exempts", bool(await rows(d, GLOBAL_C)))
            check("household: unknown accounts have no exemption",
                  not await d.has_recent_login_from(0, GLOBAL_C))
            # a session that began before login_addresses existed still counts (tokens fallback)
            await d.conn.execute("DELETE FROM login_addresses")
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            await d.create_token(alice, "tok-old", ["*"], ip=GLOBAL_B)
            reset_state()
            await flood(GLOBAL_B, "alice_lb", 25)
            check("household: a live session's address counts as a sign-in", not await rows(d, GLOBAL_B))

            # ---- scanner probes are stored the same way
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("DELETE FROM ip_ban_history")
            await d.conn.commit()
            Config.PROBE_BLOCK_STRIKES = 3
            Config.PROBE_BLOCK_SECONDS = 60

            async def nf(request):
                return web.Response(status=404, text="no")

            async def probe(peer, n=5):
                got = []
                for _ in range(n):
                    resp = await server.security_headers_middleware(
                        make_mocked_request("GET", "/.env", transport=_Transport(peer)), nf)
                    got.append(resp.status)
                await asyncio.sleep(0.3)
                return got

            got = await probe(GLOBAL_A)
            r = await rows(d, GLOBAL_A)
            check("probe: a scanner ban is stored as kind 'probe' with an expiry",
                  403 in got and len(r) == 1 and r[0]["kind"] == "probe" and r[0]["source"] == "auto" and r[0]["expires_at"],
                  f"{got} {r}")
            check("probe: the stored ban replaces the in-memory one", not server._probe_blocks)
            ev = await events(d)
            check("probe: the stored ban is a security event", any(e["details"].get("kind") == "probe" for e in ev))
            await d.conn.execute("UPDATE blocked_ips SET expires_at = ?", (past(),))
            await d.conn.commit()
            server._blocked_ips.clear()
            server._probe_strikes.clear()
            await probe(GLOBAL_A)
            ev = [e for e in await events(d) if e["details"].get("kind") == "probe"]
            check("probe: a repeat doubles the duration, like a login ban",
                  len(ev) == 2 and ev[1]["details"]["seconds"] == 120 and ev[1]["details"]["offences"] == 2,
                  str([e["details"] for e in ev]))
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            reset_state()
            await probe("127.0.0.1")
            check("probe: an exempt peer is never stored", not await rows(d))
            Config.PROBE_BLOCK_STRIKES = 0
            reset_state()
            await probe(GLOBAL_B)
            check("probe: with the existing toggle off (default) nothing is blocked or stored",
                  not await rows(d) and not server._probe_blocks)

            # ---- settings route
            class _Reqs(_Req):
                pass

            async def fake_super(request):
                return {"id": alice, "username": "alice_lb"}, None
            saved_super, saved_admin = server._backup_superadmin, server._admin_only

            async def fake_admin(request):
                return object(), None
            server._backup_superadmin, server._admin_only = fake_super, fake_admin
            try:
                server._login_ban_cfg.clear()
                server._login_ban_cfg.update(server.LOGIN_BAN_DEFAULTS)
                for bad in ({"enabled": "yes"}, {"max_failures": 1}, {"max_failures": 5000}, {"max_failures": "20"},
                            {"max_failures": True}, {"find_minutes": 0}, {"base_minutes": 99999}, {"bogus": 1}):
                    r = await server.http_put_login_ban(_JsonRequest(bad))
                    check(f"settings: refuses {bad}", r.status == 400, str(r.body))
                r = await server.http_put_login_ban(_JsonRequest([]))
                check("settings: refuses a non-object body", r.status == 400)
                check("settings: a refused change leaves everything as it was",
                      server._login_ban_cfg == server.LOGIN_BAN_DEFAULTS)
                r = await server.http_put_login_ban(_JsonRequest({"enabled": True, "max_failures": 30, "base_minutes": 10}))
                body = json.loads(r.body)
                check("settings: a valid change is applied and returned",
                      r.status == 200 and body["enabled"] is True and body["max_failures"] == 30
                      and body["base_minutes"] == 10 and body["find_minutes"] == 10, str(body))
                server._login_ban_cfg.clear()
                server._login_ban_cfg.update(server.LOGIN_BAN_DEFAULTS)
                await server._load_login_ban_state()
                check("settings: the change is saved and loaded again at start",
                      server._login_ban_cfg == {"enabled": True, "max_failures": 30, "find_minutes": 10, "base_minutes": 10},
                      str(server._login_ban_cfg))
                ev = await events(d, "login_ban_changed")
                check("settings: the change is a security event and an audit entry",
                      len(ev) == 1 and ev[0]["user_id"] == alice and ev[0]["category"] == "security"
                      and bool(await d.get_audit_log(action="login_ban.update")), str(ev))
                g = await server.http_get_login_ban(_JsonRequest({}))
                check("settings: GET shows the values, defaults and limits",
                      json.loads(g.body)["defaults"]["max_failures"] == 20 and "limits" in json.loads(g.body))
            finally:
                server._backup_superadmin, server._admin_only = saved_super, saved_admin
                server._login_ban_cfg.clear()
                server._login_ban_cfg.update(server.LOGIN_BAN_DEFAULTS)
                await d.delete_setting("login_ban_enabled")

            # ---- admin list, never-ban save, admin unblock
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("DELETE FROM ip_ban_history")
            await d.conn.commit()
            await d.block_ip("203.0.113.77", reason="by hand", expires_at=None)
            e1, x1 = await server._escalating_ban(GLOBAL_B, "login", 900, "test"), None
            lst = await d.list_blocked_ips()
            kinds = {r["ip_address"]: r["kind"] for r in lst}
            exp = {r["ip_address"]: r["expires_at"] for r in lst}
            check("admin list: shows each block's kind and expiry",
                  kinds.get(GLOBAL_B) == "login" and exp.get(GLOBAL_B) and kinds.get("203.0.113.77") == "manual"
                  and exp.get("203.0.113.77") is None, str(lst))

            class _Admin:
                user_id = alice

                def has_scope(self, s):
                    return True
            saved_auth = server.authenticate_request

            async def fake_auth(request):
                return _Admin()
            server.authenticate_request = fake_auth
            try:
                r = await server.http_list_blocked_ips(_JsonRequest({}))
                check("admin list route: the banned address is listed with kind and expiry",
                      any(b["ip_address"] == GLOBAL_B and b["kind"] == "login" and b["expires_at"]
                          for b in json.loads(r.body)["blocked_ips"]))
            finally:
                server.authenticate_request = saved_auth

            server._never_ban_admin_nets = []
            saved_super = server._backup_superadmin
            server._backup_superadmin = fake_super
            try:
                r = await server.http_put_never_ban(_JsonRequest({"entries": ["45.9.9.0/24"]}))
                check("never-ban save: a stored automatic ban on a covered address is removed",
                      r.status == 200 and not await rows(d, GLOBAL_B) and not server._is_ip_blocked(GLOBAL_B)
                      and await rows(d, "203.0.113.77"), str(r.body))
            finally:
                server._backup_superadmin = saved_super
                server._never_ban_admin_nets = []
                await d.delete_setting(server.NEVER_BAN_SETTING)

            await server._escalating_ban(GLOBAL_A, "login", 900, "test")
            server._login_fails[GLOBAL_A] = server.deque([1.0])
            saved_auth = server.authenticate_request
            server.authenticate_request = fake_auth

            class _Un(_Req):
                match_info = {"ip": GLOBAL_A}
            try:
                r = await server.http_unblock_ip(_Un("203.0.113.5", {}))
                cur = await d.conn.execute("SELECT COUNT(*) AS n FROM ip_ban_history WHERE ip_address = ?", (GLOBAL_A,))
                check("admin unblock: lifts the ban, the cache entry, the count and the escalation history",
                      r.status == 200 and not await rows(d, GLOBAL_A) and not server._is_ip_blocked(GLOBAL_A)
                      and GLOBAL_A not in server._login_fails and (await cur.fetchone())["n"] == 0, str(r.body))
            finally:
                server.authenticate_request = saved_auth

            # ---- command-line unblock
            await server._escalating_ban(GLOBAL_A, "login", 900, "test")
            await server._escalating_ban(GLOBAL_B, "probe", 900, "test")
            await d.close()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ban_cli.unblock(GLOBAL_A, path)
            out = buf.getvalue()
            d = Database(path)
            await d.connect()
            server.db = auth_module.db = d
            cur = await d.conn.execute("SELECT COUNT(*) AS n FROM ip_ban_history WHERE ip_address = ?", (GLOBAL_A,))
            check("CLI unblock: removes the stored login ban and its history, names its kind",
                  rc == 0 and not await rows(d, GLOBAL_A) and (await cur.fetchone())["n"] == 0 and "login" in out, out)
            check("CLI unblock: other addresses keep their ban", bool(await rows(d, GLOBAL_B)))
            check("CLI unblock: the removal is recorded as an event from the command line",
                  any(e["details"].get("kind") == "cli" for e in await events(d, "ip_unblocked")))
            await d.close()
            with contextlib.redirect_stdout(io.StringIO()):
                ban_cli.clear_bans(path)
            d = Database(path)
            await d.connect()
            server.db = auth_module.db = d
            cur = await d.conn.execute("SELECT COUNT(*) AS n FROM ip_ban_history")
            check("CLI clear-bans: removes every block and every escalation record",
                  not await rows(d) and (await cur.fetchone())["n"] == 0)

            # ---- fix pass: an offence is recorded only when a row was written
            secevents.log.bind(d)
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("DELETE FROM ip_ban_history")
            await d.conn.commit()

            async def history(ip):
                cur = await d.conn.execute("SELECT * FROM ip_ban_history WHERE ip_address = ?", (ip,))
                return [dict(r) for r in await cur.fetchall()]
            await d.block_ip(GLOBAL_C, reason="by hand", expires_at=None)
            got = await server._escalating_ban(GLOBAL_C, "login", 900, "test")
            check("offence: a manual block that is kept writes nothing and records no offence",
                  got is None and not await history(GLOBAL_C) and (await rows(d, GLOBAL_C))[0]["source"] == "manual",
                  str(await history(GLOBAL_C)))
            await d.block_ip(GLOBAL_D, reason="long", expires_at="2999-01-01 00:00:00", source="auto", kind="login")
            got = await server._escalating_ban(GLOBAL_D, "login", 900, "test")
            check("offence: a longer automatic block that is kept records no offence",
                  got is None and not await history(GLOBAL_D), str(await history(GLOBAL_D)))
            got = await server._escalating_ban(GLOBAL_A, "login", 900, "test")
            check("offence: a block that is written records exactly one offence",
                  got and [h["offences"] for h in await history(GLOBAL_A)] == [1], str(await history(GLOBAL_A)))

            # ---- fix pass: the recorded sign-in address alone carries the household exemption
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.commit()
            HOME = "5.6.7.8"
            server._login_ban_cfg.update({"enabled": True, "max_failures": 20, "find_minutes": 10, "base_minutes": 15})
            try:
                check("household: a real sign-in from the address succeeds",
                      await attempt(HOME, "alice_lb", PASSWORD) == 200)
                cur = await d.conn.execute("SELECT COUNT(*) AS n FROM login_addresses WHERE user_id = ? AND ip_address = ?",
                                           (alice, HOME))
                check("household: the sign-in address was recorded", (await cur.fetchone())["n"] == 1)
                await d.conn.execute("DELETE FROM tokens WHERE user_id = ?", (alice,))
                await d.conn.commit()
                server._login_known_cache.clear()
                got = await flood(HOME, "alice_lb", 40)
                check("household: 40 wrong passwords after the session tokens and the cache are gone: no ban",
                      set(got) == {401} and not await rows(d, HOME) and not server._is_ip_blocked(HOME)
                      and not server._login_fails.get(HOME), str(got))
            finally:
                server._login_ban_cfg.clear()
                server._login_ban_cfg.update(server.LOGIN_BAN_DEFAULTS)

            # ---- fix pass: a wrong password costs the same lookups for a known and an unknown name
            reset_state()
            calls = {}
            real = {n: getattr(d, n) for n in ("get_user_by_username", "has_recent_login_from_anyone")}

            def counting(name):
                async def wrapper(*a, **kw):
                    calls[name] = calls.get(name, 0) + 1
                    return await real[name](*a, **kw)
                return wrapper
            for n in real:
                setattr(d, n, counting(n))
            try:
                OUT = "6.7.8.9"
                await flood(OUT, "alice_lb", 1)
                known = dict(calls)
                calls.clear()
                server._login_known_cache.clear()
                await flood(OUT, "no_such_name_lb", 1)
                unknown = dict(calls)
            finally:
                for n in real:
                    delattr(d, n)
            check("timing: a known and an unknown name run the same database lookups before the 401",
                  known == unknown and known.get("has_recent_login_from_anyone") == 1 and known.get("get_user_by_username") == 2,
                  f"known {known} unknown {unknown}")
            check("timing: the dummy lookup leaves the known-address cache alone", not server._login_known_cache)

            # ---- fix pass: a ban on an address that is exempt now is not enforced and is dropped
            reset_state()
            await d.conn.execute("DELETE FROM blocked_ips")
            await d.conn.execute("DELETE FROM ip_ban_history")
            await d.conn.commit()

            async def ok_handler2(request):
                return web.Response(text="fine")

            async def status_for(ip):
                return (await server.security_headers_middleware(
                    make_mocked_request("GET", "/", transport=_Transport(ip)), ok_handler2)).status
            server._auto_blocked_ips.clear()
            check("exempt: setup, an automatic ban is written and enforced",
                  await server._escalating_ban(GLOBAL_B, "login", 900, "test") and await status_for(GLOBAL_B) == 403)
            await d.block_ip("45.9.9.10", reason="by hand", expires_at=None)
            server._blocked_ips["45.9.9.10"] = None
            server._probe_blocks[GLOBAL_B] = server.monotonic() + 100
            server._never_ban_admin_nets = ipguard.validate_cidr_list(["45.9.9.0/24"])
            try:
                check("exempt: the address is exempt now, its stored automatic ban and probe block are not enforced",
                      await status_for(GLOBAL_B) == 200)
                check("exempt: a manual block on an exempt address is still enforced", await status_for("45.9.9.10") == 403)
                # a restart: blocks are loaded before the exemption state, then filtered
                server._blocked_ips.clear()
                server._blocked_ips.update(await d.get_active_blocked_ips())
                server._auto_blocked_ips.clear()
                check("exempt: after a restart load the stale ban would still be there",
                      server._is_ip_blocked(GLOBAL_B))
                n = await server._drop_exempt_auto_bans()
                check("exempt: the startup filter deletes the automatic row and leaves the manual one",
                      n == 1 and not await rows(d, GLOBAL_B) and bool(await rows(d, "45.9.9.10"))
                      and not server._is_ip_blocked(GLOBAL_B) and server._is_ip_blocked("45.9.9.10"))
            finally:
                server._never_ban_admin_nets = []
                server._probe_blocks.clear()
            # a Cloudflare range refresh that newly covers a banned address
            await d.block_ip(GLOBAL_A, reason="x", expires_at="2999-01-01 00:00:00", source="auto", kind="login")
            server._blocked_ips[GLOBAL_A] = "2999-01-01 00:00:00"
            server._auto_blocked_ips.add(GLOBAL_A)
            before_nets, before_src = list(server._cf_networks), server._cf_source
            server._apply_cloudflare_networks(before_nets + [ipaddress.ip_network("1.2.3.0/24")], "fetched", "t")
            try:
                await asyncio.gather(*list(server._bg_tasks))
                check("exempt: a Cloudflare range refresh drops the ban it now covers",
                      not await rows(d, GLOBAL_A) and not server._is_ip_blocked(GLOBAL_A)
                      and GLOBAL_A not in server._auto_blocked_ips)
            finally:
                server._apply_cloudflare_networks(before_nets, before_src)
                await asyncio.gather(*list(server._bg_tasks))
            src = Path(server.__file__).read_text()
            i_cf = src.index("await _load_cloudflare_state()\n        # Exemption state")
            check("exempt: startup drops them after the never-ban list and Cloudflare state are loaded",
                  src.index("await _load_never_ban_state()") < i_cf < src.index("await _drop_exempt_auto_bans()", i_cf))
        finally:
            server.db, Config.PROBE_BLOCK_STRIKES, Config.PROBE_BLOCK_SECONDS = saved
            auth_module.db = saved_auth_db
            reset_state()
            secevents.log.bind(None)
            await d.close()


asyncio.run(main())


# ---------------------------------------------------------------------------
# Migration, and release 1.17.0 on the migrated database
# ---------------------------------------------------------------------------

async def migration_cases():
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        old_tree = scratch / "v1.17.0"
        old_tree.mkdir()
        repo = subprocess.run(["git", "-C", SRC, "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        arch = subprocess.run(f"git -C {repo.stdout.strip()} archive v1.17.0 | tar -x -C {old_tree}",
                              shell=True, capture_output=True, text=True)
        have_old = arch.returncode == 0 and (old_tree / "database.py").exists()
        py = sys.executable
        path = str(scratch / "m.db")
        env = {**os.environ, "DATABASE_PATH": path, "JWT_SECRET": "x" * 64}
        old_script = (
            "import asyncio, sys\n"
            "from database import Database\n"
            "async def main():\n"
            "    d = Database(sys.argv[1]); await d.connect()\n"
            "    mode = sys.argv[2]\n"
            "    if mode == 'seed':\n"
            "        await d.block_ip('203.0.113.9', reason='old manual')\n"
            "    else:\n"
            "        blocks = await d.get_active_blocked_ips()\n"
            "        await d.block_ip('198.51.100.5', reason='old-code block after migration')\n"
            "        await d.block_ip('1.2.3.4', reason='old auto', expires_at='2999-01-01 00:00:00', source='auto')\n"
            "        print('BLOCKS=' + ','.join(sorted(blocks)))\n"
            "    await d.close()\n"
            "asyncio.run(main())\n")
        if have_old:
            r = subprocess.run([py, "-c", old_script, path, "seed"], cwd=old_tree, capture_output=True,
                               text=True, env=env)
            check("1.17.0 creates a database to migrate", r.returncode == 0, r.stderr[-300:])
        else:
            print("skip: the v1.17.0 tag is not available, the older-release checks are skipped")

        d = Database(path)
        await d.connect()
        cols = {r["name"] for r in await (await d.conn.execute("PRAGMA table_info(blocked_ips)")).fetchall()}
        check("migration: blocked_ips gains kind", "kind" in cols)
        names = {r["name"] for r in await (await d.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")).fetchall()}
        check("migration: the history and sign-in address tables exist", {"ip_ban_history", "login_addresses"} <= names)
        if have_old:
            lst = await d.list_blocked_ips()
            check("migration: an old manual row keeps its meaning and is listed as manual",
                  any(r["ip_address"] == "203.0.113.9" and r["kind"] == "manual" and r["source"] == "manual" for r in lst))
        await d.close()
        d = Database(path)
        await d.connect()
        check("migration: a second start is a no-op", True)
        await d.block_ip("1.2.3.4", reason="x", expires_at="2999-01-01 00:00:00", source="auto", kind="login")
        await d.close()

        if have_old:
            r = subprocess.run([py, "-c", old_script, path, "check"], cwd=old_tree, capture_output=True,
                               text=True, env=env)
            check("1.17.0 starts on the migrated database and reads and writes blocks",
                  r.returncode == 0 and "1.2.3.4" in r.stdout and "203.0.113.9" in r.stdout, r.stderr[-400:] + r.stdout)
            d = Database(path)
            await d.connect()
            check("the new code still reads rows 1.17.0 wrote", "198.51.100.5" in await d.get_active_blocked_ips())
            await d.close()


asyncio.run(migration_cases())

print()
if failures:
    print(f"{len(failures)} FAILED:")
    for f in failures:
        print("  - " + f)
    sys.exit(1)
print("all passed")
