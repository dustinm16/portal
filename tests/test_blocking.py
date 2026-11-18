"""Lockout-safe blocking: the never-ban helper, its list validation, the block_ip
conflict rule, the unblock / clear-bans command line and the proxy-trust self-check.

Run:  venv/bin/python tests/test_blocking.py
      PORTAL_SRC=/path/to/other/tree venv/bin/python tests/test_blocking.py   (test another tree)
"""

import asyncio
import ipaddress
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)

_TMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "server.db")   # every Database() below gets its own explicit path
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ["NEVER_BAN_CIDRS"] = ""

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from multidict import CIMultiDict  # noqa: E402

import ipguard  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# A truly global address (the documentation ranges count as private in Python 3.11).
GLOBAL_A = "1.2.3.4"
GLOBAL_B = "45.9.9.9"
CF_PEER = "173.245.48.5"

# ---------------------------------------------------------------------------
# List validation
# ---------------------------------------------------------------------------

def refused(entries):
    try:
        ipguard.validate_cidr_list(entries)
    except ipguard.ListError as e:
        return str(e)
    return None


check("never-ban: plain addresses and networks are accepted",
      refused(["203.0.113.7", "198.51.100.0/24", "2001:db8::/32", "10.0.0.0/8", "2001::/16"]) is None)
check("never-ban: bare IP becomes /32", str(ipguard.validate_cidr_list(["203.0.113.7"])[0]) == "203.0.113.7/32")
check("never-ban: duplicates are collapsed", len(ipguard.validate_cidr_list(["1.2.3.4", "1.2.3.4/32"])) == 1)
for bad in ["0.0.0.0/0", "::/0", "1.0.0.0/7", "128.0.0.0/1", "2000::/15", "2001::/8", "::ffff:0:0/96",
            "::ffff:1.2.3.4", "::/16", "203.0.113.7/24", "203.0.113.7/33", "1.2.3.4/255.255.255.0",
            "not-an-ip", "", " ", "1.2.3", "1.2.3.4/", "1.2.3.4/-1", "1.2.3.4\n5.6.7.8", "1.2.3.4 5.6.7.8", "999.1.1.1",
            "fe80::1%eth0", "1.2.3.4/8x", 123, None, ["1.2.3.4"], "x" * 200]:
    check(f"never-ban: refuses {bad!r}", refused([bad]) is not None)
check("never-ban: /8 and /16 are the narrowest-allowed floor", refused(["10.0.0.0/8", "2001::/16"]) is None)
check("never-ban: 100 entries are accepted", refused([f"10.0.{i}.0/24" for i in range(100)]) is None)
check("never-ban: 101 entries are refused", refused([f"10.0.{i}.0/24" for i in range(101)]) is not None)
check("never-ban: a non-list is refused", refused("1.2.3.4") is not None and refused(None) is not None)
nets, warns = ipguard.parse_env_cidrs("1.2.3.4, 45.9.9.0/24 0.0.0.0/0 junk ::/0")
check("env list: good entries kept, broad and bad ones skipped with a warning",
      [str(n) for n in nets] == ["1.2.3.4/32", "45.9.9.0/24"] and len(warns) == 3, f"{nets} {warns}")

# ---------------------------------------------------------------------------
# The exemption helper
# ---------------------------------------------------------------------------

check("helper: loopback is exempt", server._never_ban_reason("127.0.0.1") == "loopback")
check("helper: IPv6 loopback is exempt", server._never_ban_reason("::1") == "loopback")
check("helper: IPv4-mapped loopback is exempt", server._never_ban_reason("::ffff:127.0.0.1") == "loopback")
check("helper: a private address is exempt", server._never_ban_reason("192.168.1.9") == "private network")
check("helper: a Cloudflare address is exempt", server._never_ban_reason(CF_PEER) == "trusted proxy or Cloudflare")
check("helper: an invalid address is exempt", server._never_ban_reason("garbage") is not None)
check("helper: an ordinary public address is not exempt", server._never_ban_reason(GLOBAL_A) is None)

server._never_ban_env_nets = ipguard.parse_env_cidrs("45.9.9.0/24")[0]
check("helper: NEVER_BAN_CIDRS exempts without any database",
      server._never_ban_reason("45.9.9.77") == "NEVER_BAN_CIDRS" and server._never_ban_reason(GLOBAL_A) is None)
server._never_ban_env_nets = []
check("helper: removing the env entry removes the exemption", server._never_ban_reason("45.9.9.77") is None)

server._never_ban_admin_nets = ipguard.validate_cidr_list(["45.9.9.0/24"])
check("helper: the admin list exempts", server._never_ban_reason("45.9.9.77") == "never-ban list")
check("helper: an address outside the admin list is not exempt", server._never_ban_reason(GLOBAL_A) is None)
check("helper: a candidate list can be tried without saving it",
      server._never_ban_reason(GLOBAL_A, admin_nets=ipguard.validate_cidr_list(["1.2.3.0/24"])) == "never-ban list")
server._never_ban_admin_nets = []

own = sorted(a for a in server._host_addresses() if not ipaddress.ip_address(a).is_private
             and not ipaddress.ip_address(a).is_loopback and not ipaddress.ip_address(a).is_link_local)
if own:
    check("helper: this host's own public address is exempt",
          server._never_ban_reason(own[0]) == "this host's own address", own[0])
else:
    print("skip: this host has no public interface address to test the own-address rule with")
server._host_addr_cache = (server.monotonic(), frozenset({GLOBAL_B}))
check("helper: an interface address is exempt", server._never_ban_reason(GLOBAL_B) == "this host's own address")
server._host_addr_cache = (0.0, frozenset())

eff = {g["source"]: g for g in server._never_ban_effective()}
check("effective list names every source",
      set(eff) == {"loopback", "private", "host", "cloudflare", "trusted_proxies", "env", "admin"}, str(sorted(eff)))
check("effective list shows the Cloudflare ranges", "173.245.48.0/20" in eff["cloudflare"]["entries"])

# ---------------------------------------------------------------------------
# Scanner blocking never fires for exempt peers (the one automatic block that exists today)
# ---------------------------------------------------------------------------

Config.PROBE_BLOCK_STRIKES = 3
Config.PROBE_BLOCK_SECONDS = 60


class _Transport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, name, default=None):
        return (self.peer, 4242) if name == "peername" else default


def _make(peer, path="/.env", headers=None):
    return make_mocked_request("GET", path, headers=CIMultiDict(headers or {}), transport=_Transport(peer))


async def _handler(request):
    return web.Response(status=404, text="no")


async def probe(peer, headers=None, n=6):
    statuses = []
    for _ in range(n):
        resp = await server.security_headers_middleware(_make(peer, headers=headers), _handler)
        statuses.append(resp.status)
    return statuses


def reset_probe():
    server._probe_strikes.clear()
    server._probe_blocks.clear()


async def probe_cases():
    reset_probe()
    got = await probe(GLOBAL_A)
    check("probe control: a public scanner IS blocked after the strike limit",
          got[:3] == [404, 404, 404] and got[3] == 403 and bool(server._probe_blocks), str(got))

    reset_probe()
    got = await probe("127.0.0.1")
    check("probe: a loopback peer never creates a block", 403 not in got and not server._probe_blocks, str(got))

    reset_probe()
    got = await probe("127.0.0.1", headers={"CF-Connecting-IP": GLOBAL_A, "CF-Ray": "abc-LHR"})
    check("probe: a loopback peer carrying Cloudflare headers (trust misconfigured) never creates a block",
          403 not in got and not server._probe_blocks, str(got))

    reset_probe()
    got = await probe(CF_PEER)
    check("probe: a Cloudflare peer without a client header never creates a block",
          403 not in got and not server._probe_blocks, str(got))

    reset_probe()
    got = await probe(CF_PEER, headers={"CF-Connecting-IP": GLOBAL_A})
    check("probe: a scanner reached THROUGH Cloudflare is still blockable (its own address counts)",
          403 in got and GLOBAL_A in server._probe_blocks, str(got))

    reset_probe()
    server._never_ban_env_nets = ipguard.parse_env_cidrs("45.9.9.0/24")[0]
    got = await probe("45.9.9.9")
    check("probe: an address in NEVER_BAN_CIDRS never creates a block", 403 not in got and not server._probe_blocks, str(got))
    server._never_ban_env_nets = []
    reset_probe()
    got = await probe("45.9.9.9")
    check("probe control: the same address IS blocked without the env entry", 403 in got, str(got))

    reset_probe()
    server._never_ban_admin_nets = ipguard.validate_cidr_list(["45.9.9.9"])
    got = await probe("45.9.9.9")
    check("probe: an address on the admin never-ban list never creates a block",
          403 not in got and not server._probe_blocks, str(got))
    server._never_ban_admin_nets = []

    reset_probe()
    server._probe_blocks["45.9.9.9"] = server.monotonic() + 60
    server._probe_strikes["45.9.9.9"] = (2, server.monotonic())
    server._probe_blocks["8.8.8.8"] = server.monotonic() + 60
    dropped = server._forget_probe_state(ipguard.validate_cidr_list(["45.9.9.0/24"]))
    check("saving the list drops existing scanner state for covered addresses only",
          dropped == 2 and "45.9.9.9" not in server._probe_blocks and "8.8.8.8" in server._probe_blocks)
    reset_probe()


asyncio.run(probe_cases())

# ---------------------------------------------------------------------------
# Database: the block_ip conflict rule and the migration
# ---------------------------------------------------------------------------

def fmt(delta_s):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).strftime("%Y-%m-%d %H:%M:%S")


async def row(d, ip):
    cur = await d.conn.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip,))
    r = await cur.fetchone()
    return dict(r) if r else None


async def db_cases():
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "t.db"))
        await d.connect()
        try:
            uid = await d.create_user("blk_admin", "x")
            ip = GLOBAL_A

            # automatic never overwrites or shortens a manual block
            await d.block_ip(ip, "manual perm", uid, None)
            r0 = await row(d, ip)
            check("manual block is stored with source manual", r0["source"] == "manual" and r0["blocked_by"] == uid)
            wrote = await d.block_ip(ip, "auto", None, fmt(3600), source="auto")
            r1 = await row(d, ip)
            check("auto does not shorten a permanent manual block",
                  not wrote and r1["expires_at"] is None and r1["source"] == "manual" and r1["reason"] == "manual perm"
                  and r1["blocked_by"] == uid, str(r1))
            wrote = await d.block_ip(ip, "auto perm", None, None, source="auto")
            r1 = await row(d, ip)
            check("auto does not overwrite a permanent manual block with a permanent auto one",
                  not wrote and r1["source"] == "manual" and r1["reason"] == "manual perm", str(r1))

            # manual timed, auto longer: still untouched
            ip2 = GLOBAL_B
            await d.block_ip(ip2, "m", uid, fmt(60))
            wrote = await d.block_ip(ip2, "a", None, fmt(86400), source="auto")
            r = await row(d, ip2)
            check("auto does not extend or take over a live timed manual block",
                  not wrote and r["source"] == "manual" and r["reason"] == "m", str(r))

            # a manual block whose admin was deleted (blocked_by NULL) is still manual
            await d.conn.execute("UPDATE blocked_ips SET blocked_by = NULL WHERE ip_address = ?", (ip,))
            await d.conn.commit()
            wrote = await d.block_ip(ip, "auto", None, fmt(60), source="auto")
            r = await row(d, ip)
            check("a manual block with no admin id left is still protected", not wrote and r["source"] == "manual", str(r))

            # automatic rows
            ip3 = "8.8.4.4"
            check("auto block creates a row", await d.block_ip(ip3, "a1", None, fmt(600), source="auto")
                  and (await row(d, ip3))["source"] == "auto")
            before = (await row(d, ip3))["expires_at"]
            wrote = await d.block_ip(ip3, "shorter", None, fmt(60), source="auto")
            check("auto never shortens an auto block", not wrote and (await row(d, ip3))["expires_at"] == before)
            wrote = await d.block_ip(ip3, "longer", None, fmt(7200), source="auto")
            r = await row(d, ip3)
            check("auto extends an auto block", wrote and r["expires_at"] > before and r["reason"] == "longer", str(r))
            wrote = await d.block_ip(ip3, "forever", None, None, source="auto")
            check("auto may make an auto block permanent", wrote and (await row(d, ip3))["expires_at"] is None)
            wrote = await d.block_ip(ip3, "timed again", None, fmt(60), source="auto")
            check("auto never turns a permanent auto block into a timed one",
                  not wrote and (await row(d, ip3))["expires_at"] is None)

            # an expired row of either kind may be replaced by an automatic block
            ip4 = "9.9.9.9"
            await d.block_ip(ip4, "old manual", uid, fmt(-60))
            wrote = await d.block_ip(ip4, "fresh", None, fmt(300), source="auto")
            r = await row(d, ip4)
            check("auto replaces an EXPIRED manual block (it no longer blocks anything)",
                  wrote and r["source"] == "auto" and r["expires_at"] > fmt(0), str(r))

            # a manual block replaces anything (the admin's own choice)
            wrote = await d.block_ip(ip3, "admin says", uid, fmt(30))
            r = await row(d, ip3)
            check("a manual block still overwrites an auto block",
                  wrote and r["source"] == "manual" and r["blocked_by"] == uid and r["reason"] == "admin says", str(r))
            try:
                await d.block_ip(ip3, source="bogus")
                check("an unknown source is refused", False)
            except ValueError:
                check("an unknown source is refused", True)

            # the server-level entry point: exempt addresses are never written
            server.db = d
            server._blocked_ips.clear()
            res = await server._auto_block_ip("127.0.0.1", "x", 60)
            check("_auto_block_ip refuses a loopback address and writes nothing",
                  res == "loopback" and await row(d, "127.0.0.1") is None)
            res = await server._auto_block_ip(CF_PEER, "x", 60)
            check("_auto_block_ip refuses a Cloudflare address", res and await row(d, CF_PEER) is None)
            server._never_ban_env_nets = ipguard.parse_env_cidrs("45.9.9.0/24")[0]
            res = await server._auto_block_ip("45.9.9.50", "x", 60)
            check("_auto_block_ip refuses a NEVER_BAN_CIDRS address", res == "NEVER_BAN_CIDRS" and await row(d, "45.9.9.50") is None)
            server._never_ban_env_nets = []
            res = await server._auto_block_ip("45.9.9.50", "probing", 60)
            r = await row(d, "45.9.9.50")
            check("_auto_block_ip blocks an ordinary address and updates the in-process cache",
                  res is None and r and r["source"] == "auto" and "45.9.9.50" in server._blocked_ips, str(r))
            res = await server._auto_block_ip(ip, "x", 60)
            check("_auto_block_ip leaves a manual permanent block alone",
                  res is None and (await row(d, ip))["source"] == "manual" and server._blocked_ips.get(ip) is None)
        finally:
            await d.close()

    # migration: a database from before the column gets it, rows become manual, and a second start changes nothing
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "old.db")
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE blocked_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL UNIQUE, "
                  "reason TEXT, blocked_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT DEFAULT NULL)")
        c.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES ('5.6.7.8', 'legacy')")
        c.commit()
        c.close()
        d = Database(path)
        await d.connect()
        r = await row(d, "5.6.7.8")
        check("migration: an existing block becomes source manual", r and r["source"] == "manual", str(r))
        await d.close()

        def schema():
            c = sqlite3.connect(path)
            try:
                return c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
            finally:
                c.close()
        s1 = schema()
        d = Database(path)
        await d.connect()
        await d.close()
        check("migration: a second start leaves the schema unchanged", schema() == s1)


asyncio.run(db_cases())


class _JsonRequest:
    """Just enough of a request for the never-ban handler."""
    transport = None

    def __init__(self, body):
        self._body = body
        self.headers = {}

    async def json(self):
        return self._body


async def never_ban_audit_cases():
    import json as _json
    import secevents
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "nb.db"))
        await d.connect()
        saved = (server.db, server._backup_superadmin, server._never_ban_admin_nets)
        try:
            uid = await d.create_user("nb_root", "x")
            server.db = d
            secevents.log.bind(d)

            async def fake_superadmin(request):
                return {"id": uid, "username": "nb_root"}, None
            server._backup_superadmin = fake_superadmin
            server._never_ban_admin_nets = []
            r = await server.http_put_never_ban(_JsonRequest({"entries": ["203.0.113.0/24", "198.51.100.7", "45.9.9.0/24"]}))
            r2 = await server.http_put_never_ban(_JsonRequest({"entries": ["45.9.9.0/24", "192.0.2.0/24"]}))
            audit = [e for e in await d.get_audit_log(action="never_ban.update")]
            detail = {e["id"]: _json.loads(e["details"]) for e in audit}
            first = detail[min(detail)] if detail else {}
            check("never-ban update: the audit entry holds the saved entries, not only their number",
                  r.status == 200 and first.get("entries") == ["203.0.113.0/24", "198.51.100.7/32", "45.9.9.0/24"]
                  and first.get("count") == 3, str(first))
            cur = await d.conn.execute("SELECT * FROM security_events WHERE event = 'never_ban_changed' ORDER BY id")
            ev = [dict(x) for x in await cur.fetchall()]
            second = _json.loads(ev[1]["details"]) if len(ev) == 2 else {}
            check("never-ban update: each change is a security event with the actor and counts",
                  r2.status == 200 and len(ev) == 2 and ev[0]["user_id"] == uid and ev[0]["category"] == "security"
                  and second == {"entries": 2, "added": 1, "removed": 2, "scanner_blocks_cleared": 0}, str(ev))
            check("never-ban update: the event does not carry the entries",
                  "203.0.113" not in (ev[0]["details"] or ""))
        finally:
            server.db, server._backup_superadmin, server._never_ban_admin_nets = saved
            await d.close()


asyncio.run(never_ban_audit_cases())

# ---------------------------------------------------------------------------
# CLI: unblock and clear-bans
# ---------------------------------------------------------------------------

import ban_cli  # noqa: E402
import contextlib  # noqa: E402
import io  # noqa: E402


def run_cli(fn, *a):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        try:
            rc = fn(*a)
        except SystemExit as e:
            rc = e.code
    return rc, buf.getvalue() + err.getvalue()


def schema_of(path):
    c = sqlite3.connect(path)
    try:
        return c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
    finally:
        c.close()


async def make_db(path):
    d = Database(path)
    await d.connect()
    await d.close()


with tempfile.TemporaryDirectory() as tmp:
    path = str(Path(tmp) / "cli.db")
    asyncio.run(make_db(path))
    c = sqlite3.connect(path)
    c.executemany("INSERT INTO blocked_ips (ip_address, reason, expires_at, source) VALUES (?,?,?,?)", [
        ("203.0.113.9", "manual thing", None, "manual"),
        ("2001:DB8:0:0::1", "typed in upper case", None, "manual"),
        ("1.2.3.4", "scanner", "2999-01-01 00:00:00", "auto"),
        ("5.5.5.5", "other", None, "manual"),
    ])
    c.commit()
    c.close()
    before = schema_of(path)
    rc, out = run_cli(ban_cli.unblock, "203.0.113.9", path)
    c = sqlite3.connect(path)
    left = [r[0] for r in c.execute("SELECT ip_address FROM blocked_ips ORDER BY id")]
    c.close()
    check("unblock removes the named block and prints what it removed",
          rc == 0 and "203.0.113.9" in out and "manual thing" in out and "203.0.113.9" not in left and len(left) == 3, out)
    rc, out = run_cli(ban_cli.unblock, "2001:db8::1", path)
    c = sqlite3.connect(path)
    left = [r[0] for r in c.execute("SELECT ip_address FROM blocked_ips ORDER BY id")]
    c.close()
    check("unblock matches IPv6 canonically (stored in a different spelling)",
          rc == 0 and "2001:db8::1" in out and "2001:DB8:0:0::1" not in left, out)
    rc, out = run_cli(ban_cli.unblock, "::ffff:1.2.3.4", path)
    check("unblock folds an IPv4-mapped address", rc == 0 and "1.2.3.4" in out and "auto" in out, out)
    rc, out = run_cli(ban_cli.unblock, "9.9.9.9", path)
    check("unblock of an address with no block says so and exits 1", rc == 1 and "No database block" in out, out)
    rc, out = run_cli(ban_cli.unblock, "not-an-ip", path)
    check("unblock of a non-address exits 2", rc == 2, out)
    check("the CLI does not change the schema", schema_of(path) == before)

    def cli_events():
        c = sqlite3.connect(path)
        try:
            return c.execute("SELECT event, category, ip, result, details, count FROM security_events ORDER BY id").fetchall()
        finally:
            c.close()
    evs = cli_events()
    check("unblock records one ip_unblocked security event per command, source cli",
          len(evs) == 3 and all(e[0] == "ip_unblocked" and e[1] == "security" and e[2] == "cli" and e[5] == 1 for e in evs)
          and '"target_ip":"203.0.113.9"' in evs[0][4] and '"kind":"cli"' in evs[0][4], str(evs))
    rc, out = run_cli(ban_cli.unblock, "9.9.9.9", path)
    check("an unblock that found nothing records nothing", rc == 1 and len(cli_events()) == 3)
    rc, out = run_cli(ban_cli.clear_bans, path)
    c = sqlite3.connect(path)
    n = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    c.close()
    check("clear-bans removes everything and lists it", rc == 0 and n == 0 and "5.5.5.5" in out, out)
    evs = cli_events()
    check("clear-bans records one event with the number removed",
          len(evs) == 4 and '"scope":"all"' in evs[-1][4] and '"removed":1' in evs[-1][4] and "5.5.5.5" in evs[-1][4], str(evs[-1:]))
    rc, out = run_cli(ban_cli.clear_bans, path)
    check("clear-bans on an empty list is a no-op", rc == 0 and "no blocks" in out and len(cli_events()) == 4, out)
    check("the CLI writes the same columns the server does",
          ban_cli._EVENT_COLUMNS == Database._SEC_COLS)

    missing = str(Path(tmp) / "nope.db")
    rc, out = run_cli(ban_cli.unblock, "1.2.3.4", missing)
    check("a missing database is an error and is not created", rc not in (0, 1, 2, None) and not Path(missing).exists(), f"{rc} {out}")

    # an old database without the source column and without ever having been migrated
    old = str(Path(tmp) / "old.db")
    c = sqlite3.connect(old)
    c.execute("CREATE TABLE blocked_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL UNIQUE, "
              "reason TEXT, blocked_by INTEGER, created_at TEXT, expires_at TEXT)")
    c.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES ('7.7.7.7', 'legacy')")
    c.commit()
    c.close()
    sch = schema_of(old)
    rc, out = run_cli(ban_cli.unblock, "7.7.7.7", old)
    check("works on a database from before the source column and does not migrate it",
          rc == 0 and "7.7.7.7" in out and schema_of(old) == sch, out)

    # a database that has no blocked_ips table at all
    bare = str(Path(tmp) / "bare.db")
    sqlite3.connect(bare).close()
    rc, out = run_cli(ban_cli.clear_bans, bare)
    check("a database with no block table is a no-op", rc == 0 and schema_of(bare) == [], out)

    # through the real entry point, with the server not running. A .env next to the code (a staged copy
    # has one) overrides DATABASE_PATH in the child, so this part only runs from a tree without one.
    path2 = str(Path(tmp) / "entry.db")
    asyncio.run(make_db(path2))
    c = sqlite3.connect(path2)
    c.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES ('127.0.0.1', 'locked out')")
    c.commit()
    c.close()
    if (Path(SRC) / ".env").exists():
        print("skip: the entry-point test needs a tree without a .env (the staged smoke check covers it)")
    else:
        env = dict(os.environ, DATABASE_PATH=path2, JWT_SECRET="x" * 64)
        sch2 = schema_of(path2)
        res = subprocess.run([sys.executable, "server.py", "unblock", "127.0.0.1"], cwd=SRC, env=env,
                             capture_output=True, text=True, timeout=120)
        c = sqlite3.connect(path2)
        n = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        c.close()
        check("server.py unblock <ip> works through the real entry point",
              res.returncode == 0 and n == 0 and "locked out" in res.stdout and schema_of(path2) == sch2,
              res.stdout + res.stderr)
        res = subprocess.run([sys.executable, "server.py", "clear-bans"], cwd=SRC, env=env,
                             capture_output=True, text=True, timeout=120)
        check("server.py clear-bans works through the real entry point", res.returncode == 0, res.stdout + res.stderr)

# NEVER_BAN_CIDRS through the real environment path: parsed at import, no database connected
if (Path(SRC) / ".env").exists():
    print("skip: the NEVER_BAN_CIDRS import test needs a tree without a .env")
else:
    code = (
        "import server\n"
        "print('R1=' + str(server._never_ban_reason('45.9.9.9')))\n"
        "print('R2=' + str(server._never_ban_reason('1.2.3.4')))\n"
        "print('N=' + str(len(server._never_ban_env_nets)))\n"
    )
    env = dict(os.environ, NEVER_BAN_CIDRS="45.9.9.0/24,0.0.0.0/0", JWT_SECRET="x" * 64)
    res = subprocess.run([sys.executable, "-c", code], cwd=SRC, env=env, capture_output=True, text=True, timeout=120)
    out = res.stdout + res.stderr
    check("NEVER_BAN_CIDRS from the environment exempts with no database connected",
          "R1=NEVER_BAN_CIDRS" in out and "R2=None" in out and "N=1" in out, out[-300:])
    check("NEVER_BAN_CIDRS: an over-broad entry is skipped with a warning at start",
          out.count("ignored NEVER_BAN_CIDRS entry") == 1 and "0.0.0.0/0" in out, out[-300:])

# ---------------------------------------------------------------------------
# Proxy-trust self-check
# ---------------------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


cap = _Capture()
logging.getLogger("portal").addHandler(cap)


def reset_peers():
    server._peer_marks.clear()
    server._peer_suspect_count = 0
    server._peer_trust_warned = False
    cap.records.clear()


def feed(peer, n, headers):
    for _ in range(n):
        server._note_request_peer(_make(peer, "/health", headers=headers))


CF_HEADERS = {"CF-Connecting-IP": GLOBAL_A, "CF-Ray": "abc-LHR"}
trusted_before = server._is_trusted_proxy("127.0.0.1")

reset_peers()
feed("127.0.0.1", 20, CF_HEADERS)
check("self-check: too few requests do not trip it", not server._proxy_trust_status()["suspect"])
feed("127.0.0.1", 20, CF_HEADERS)
st = server._proxy_trust_status()
check("self-check: mostly loopback requests with Cloudflare headers trip it", st["suspect"] and st["peers"] == ["127.0.0.1"], str(st))
check("self-check: the warning is logged once", sum("not a trusted proxy" in m for m in cap.records) == 1, str(cap.records))
feed("127.0.0.1", 10, CF_HEADERS)
check("self-check: it is not logged again while it stays tripped", sum("not a trusted proxy" in m for m in cap.records) == 1)
check("self-check: it never changes trust", server._is_trusted_proxy("127.0.0.1") == trusted_before == False)

reset_peers()
feed("127.0.0.1", 60, {})
feed("127.0.0.1", 40, CF_HEADERS)
check("self-check: a minority of such requests does not trip it", not server._proxy_trust_status()["suspect"])

reset_peers()
feed("10.1.2.3", 60, {"CF-Ray": "abc-LHR"})
check("self-check: a private peer carrying CF-Ray trips it too", server._proxy_trust_status()["suspect"])

reset_peers()
feed(GLOBAL_B, 60, CF_HEADERS)
check("self-check: a public untrusted peer is not this problem (it is a spoof attempt, not a proxy)",
      not server._proxy_trust_status()["suspect"])

reset_peers()
feed(CF_PEER, 60, CF_HEADERS)
check("self-check: a trusted Cloudflare peer does not trip it", not server._proxy_trust_status()["suspect"])

reset_peers()
saved = list(server._trusted_proxy_networks)
server._trusted_proxy_networks[:] = saved + [ipaddress.ip_network("127.0.0.1/32")]
server._trusted_peer_cache.clear()
feed("127.0.0.1", 60, CF_HEADERS)
check("self-check: a correctly trusted loopback proxy does not trip it", not server._proxy_trust_status()["suspect"])
server._trusted_proxy_networks[:] = saved
server._trusted_peer_cache.clear()

reset_peers()
feed("127.0.0.1", 60, CF_HEADERS)
check("self-check: recovery clears the state", server._proxy_trust_status()["suspect"])
feed("127.0.0.1", 100, {})
check("self-check: ...and it clears once ordinary requests dominate again",
      not server._proxy_trust_status()["suspect"] and server._peer_trust_warned is False)
reset_peers()

# Hysteresis: traffic hovering around half must not log the warning on every crossing
reset_peers()
for _ in range(100):
    feed("127.0.0.1", 3, CF_HEADERS)
    feed("127.0.0.1", 3, {})
n_warn = sum("not a trusted proxy" in m for m in cap.records)
check("self-check: traffic hovering around half logs the warning once, not on every crossing", n_warn == 1, f"{n_warn} warnings")
reset_peers()
feed("127.0.0.1", 40, CF_HEADERS)
feed("127.0.0.1", 60, {})          # share falls to 40 percent: no longer tripped, but not clearly below
check("self-check: a share between a quarter and a half stays armed-off (no re-warn)",
      not server._proxy_trust_status()["suspect"] and server._peer_trust_warned is True)
feed("127.0.0.1", 100, {})
check("self-check: it re-arms once the share is clearly low", server._peer_trust_warned is False)
reset_peers()


# ---------------------------------------------------------------------------
# Canonical addresses in manual blocks, the TRUSTED_PROXIES breadth warning,
# printable CLI output, the proxy-trust caution
# ---------------------------------------------------------------------------

class _Admin:
    user_id = 1
    scopes = ["*"]

    def has_scope(self, scope):
        return True


class _BlockRequest:
    def __init__(self, peer, body=None, match=None):
        self.transport = _Transport(peer)
        self.headers = CIMultiDict({})
        self.match_info = match or {}
        self._body = body

    async def json(self):
        return self._body


async def canonical_cases():
    import json as _json
    import secevents
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(str(Path(tmp) / "canon.db"))
        await d.connect()
        saved = (server.db, server.authenticate_request)
        try:
            await d.create_user("canon_admin", "x")
            server.db = d
            secevents.log.bind(d)

            async def fake_auth(request):
                return _Admin()
            server.authenticate_request = fake_auth
            server._blocked_ips.clear()

            r = await server.http_block_ip(_BlockRequest("203.0.113.5", {"ip_address": "2001:DB8::1", "reason": "x"}))
            check("manual block: an upper-case IPv6 address is stored in canonical form",
                  r.status == 201 and _json.loads(r.body)["ip_address"] == "2001:db8::1"
                  and await row(d, "2001:db8::1") and await row(d, "2001:DB8::1") is None, str(r.body))
            check("manual block: the middleware cache matches either spelling and a mapped IPv4",
                  server._is_ip_blocked("2001:db8::1") and server._is_ip_blocked("2001:DB8:0::1")
                  and not server._is_ip_blocked("2001:db8::2"))
            r = await server.http_block_ip(_BlockRequest("203.0.113.5", {"ip_address": "2001:db8::1", "reason": "again"}))
            cur = await d.conn.execute("SELECT COUNT(*) AS n FROM blocked_ips WHERE ip_address LIKE '2001:%'")
            check("manual block: the other spelling is the same block, not a second row",
                  r.status == 201 and (await cur.fetchone())["n"] == 1)
            r = await server.http_block_ip(_BlockRequest("203.0.113.5", {"ip_address": "::ffff:5.6.7.8"}))
            check("manual block: an IPv4-mapped address is stored as IPv4",
                  r.status == 201 and await row(d, "5.6.7.8") is not None and server._is_ip_blocked("5.6.7.8"))
            r = await server.http_block_ip(_BlockRequest("203.0.113.5", {"ip_address": "not-an-ip"}))
            check("manual block: a non-address is still refused", r.status == 400)
            r = await server.http_block_ip(_BlockRequest("2001:db8::5", {"ip_address": "2001:DB8::5"}))
            check("manual block: the own-address guard compares canonical forms",
                  r.status == 400 and await row(d, "2001:db8::5") is None, str(r.body))

            r = await server.http_unblock_ip(_BlockRequest("203.0.113.5", match={"ip": "2001:DB8::1"}))
            check("unblock: the other spelling removes the block and the cache entry",
                  r.status == 200 and await row(d, "2001:db8::1") is None and not server._is_ip_blocked("2001:db8::1"),
                  str(r.body))
            r = await server.http_unblock_ip(_BlockRequest("203.0.113.5", match={"ip": "::ffff:5.6.7.8"}))
            check("unblock: an IPv4-mapped spelling removes the IPv4 block", r.status == 200 and await row(d, "5.6.7.8") is None)

            # a row typed before this release (non-canonical) is still matched and removed
            await d.conn.execute("INSERT INTO blocked_ips (ip_address, reason, source) VALUES ('2001:DB8::77', 'old', 'manual')")
            await d.conn.commit()
            check("loading blocks: a non-canonical stored row is keyed canonically",
                  "2001:db8::77" in await d.get_active_blocked_ips())
            r = await server.http_unblock_ip(_BlockRequest("203.0.113.5", match={"ip": "2001:db8::77"}))
            check("unblock: a not-yet-migrated row is removed by its canonical spelling",
                  r.status == 200 and await row(d, "2001:DB8::77") is None)
        finally:
            server.db, server.authenticate_request = saved
            server._blocked_ips.clear()
            secevents.log.bind(None)
            await d.close()

    # migration: existing rows are rewritten, duplicates merged, junk left alone, a second start is a no-op
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "mig.db")
        d = Database(path)
        await d.connect()
        await d.close()
        c = sqlite3.connect(path)
        c.executemany("INSERT INTO blocked_ips (ip_address, reason, expires_at, source) VALUES (?,?,?,?)", [
            ("2001:DB8::1", "typed upper", "2999-01-01 00:00:00", "auto"),
            ("2001:db8::1", "typed lower", "2030-01-01 00:00:00", "manual"),
            ("2001:0db8:0:0:0:0:0:9", "long form", None, "manual"),
            ("::ffff:9.9.9.9", "mapped", "2040-01-01 00:00:00", "manual"),
            ("9.9.9.9", "plain", "2035-01-01 00:00:00", "auto"),
            ("not an address", "junk", None, "manual"),
            ("8.8.8.8", "already canonical", None, "manual"),
        ])
        c.commit()
        c.close()

        def rows_now():
            c = sqlite3.connect(path)
            try:
                return c.execute("SELECT ip_address, reason, expires_at, source FROM blocked_ips ORDER BY ip_address").fetchall()
            finally:
                c.close()
        d = Database(path)
        await d.connect()
        await d.close()
        got = {r[0]: r for r in rows_now()}
        check("migration: addresses are rewritten to canonical form",
              set(got) == {"2001:db8::1", "2001:db8::9", "9.9.9.9", "not an address", "8.8.8.8"}, str(sorted(got)))
        check("migration: duplicates keep the manual row and the longest expiry",
              got["2001:db8::1"][1] == "typed lower" and got["2001:db8::1"][2] == "2999-01-01 00:00:00"
              and got["2001:db8::1"][3] == "manual", str(got["2001:db8::1"]))
        check("migration: a mapped duplicate merges into the IPv4 row, the manual one wins",
              got["9.9.9.9"][1] == "mapped" and got["9.9.9.9"][2] == "2040-01-01 00:00:00", str(got["9.9.9.9"]))
        check("migration: a junk row and a permanent block are left as they were",
              got["not an address"][1] == "junk" and got["2001:db8::9"][2] is None)
        before = rows_now()
        d = Database(path)
        await d.connect()
        await d.close()
        check("migration: a second start changes nothing", rows_now() == before)


asyncio.run(canonical_cases())

check("breadth: networks broader than /8 and /16 are found, /8 and /16 themselves are not",
      [str(n) for n in ipguard.broad_networks(ipaddress.ip_network(x) for x in
       ("10.0.0.0/8", "10.0.0.0/7", "0.0.0.0/0", "2001::/16", "2000::/15", "::/0", "127.0.0.1/32"))]
      == ["10.0.0.0/7", "0.0.0.0/0", "2000::/15", "::/0"])
saved_extra, saved_host = list(server._extra_trusted_networks), Config.HOST
try:
    server._extra_trusted_networks[:] = [ipaddress.ip_network(x) for x in ("96.0.0.0/7", "2000::/3", "127.0.0.1/32", "10.0.0.0/8")]
    Config.HOST = "0.0.0.0"
    cap.records.clear()
    server._log_proxy_trust_at_startup()
    broad = [m for m in cap.records if "TRUSTED_PROXIES contains" in m]
    check("startup: a TRUSTED_PROXIES network broader than /8 or /16 is warned about, whatever HOST is",
          len(broad) == 2 and "96.0.0.0/7" in broad[0] and "2000::/3" in broad[1]
          and "spoof" not in broad[0].lower() and "forwarding headers" in broad[0], str(broad))
    server._extra_trusted_networks[:] = [ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("10.0.0.0/8")]
    cap.records.clear()
    server._log_proxy_trust_at_startup()
    check("startup: narrow entries give no breadth warning", not [m for m in cap.records if "TRUSTED_PROXIES contains" in m])
finally:
    server._extra_trusted_networks[:] = saved_extra
    Config.HOST = saved_host
    cap.records.clear()

reset_peers()
feed("127.0.0.1", 40, CF_HEADERS)
note = server._proxy_trust_status()["message"] or ""
check("the proxy-trust note tells the admin to verify the peer before trusting it",
      "really is your own proxy" in note and "TRUSTED_PROXIES" in note, note)
check("the logged warning carries the same caution",
      any("really is your own proxy" in m for m in cap.records), str(cap.records))
reset_peers()

with tempfile.TemporaryDirectory() as tmp:
    path = str(Path(tmp) / "print.db")
    asyncio.run(make_db(path))
    c = sqlite3.connect(path)
    c.execute("INSERT INTO blocked_ips (ip_address, reason, source) VALUES ('6.6.6.6', ?, 'manual')",
              ("evil\x1b[31m red\nsecond line\x07\u2028end",))
    c.commit()
    c.close()
    rc, out = run_cli(ban_cli.clear_bans, path)
    line = next((ln for ln in out.splitlines() if "6.6.6.6" in ln), "")
    check("CLI output: control characters in a stored reason are not printed",
          rc == 0 and "\x1b" not in out and "\x07" not in out and "\u2028" not in out
          and "evil[31m redsecond lineend" in line, repr(out))

print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
