"""Security event log: what is recorded, how floods are bounded, who can read it,
and that no secret ever reaches a row.

Run: venv/bin/python tests/test_secevents.py
"""

import asyncio
import csv
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
import pyotp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user, generate_backup_codes, generate_totp_secret  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


PW = {"sa": "Sa-pass-12345!", "adm": "Adm-pass-12345!", "u1": "U1-pass-12345!",
      "tfa": "Tfa-pass-12345!", "victim": "Victim-pass-12345!"}
NEW_PW = "Brand-new-pass-777!"
WRONG_CODE = "918273"
UA = "secevents-test-agent/1.0"


async def rows(where="1=1", params=()):
    cur = await server.db.conn.execute(f"SELECT * FROM security_events WHERE {where} ORDER BY id", params)
    return [dict(r) for r in await cur.fetchall()]


async def agg_total(event, result=None):
    where, params = "event = ?", [event]
    if result:
        where += " AND result = ?"
        params.append(result)
    return sum(r["count"] for r in await rows(where, params))


async def wait_for(pred, timeout=5.0):
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if await pred():
            return True
        await asyncio.sleep(0.05)
    return False


def unit_tests():
    # clean_text / clean_details
    check("username truncated to 64 and control chars stripped",
          secevents.clean_text("a\x00b\nc\x1b" + "x" * 100, 64) == "abc" + "x" * 61)
    d = json.loads(secevents.clean_details({
        "ok": "v", "password": "p", "totp_code": "1", "token": "t", "invite_code": "c",
        "api_key": "k", "nested": {"a": 1}, "n": 5, "key_id": 3}))
    check("secret-looking detail keys are dropped", set(d) == {"ok", "nested", "n", "key_id"}, str(d))
    check("long detail values are cut", len(json.loads(secevents.clean_details({"a": "z" * 900}))["a"]) == 200)
    check("bidi overrides, isolates and zero-width characters are removed",
          secevents.clean_text("\u202enimda\u200b\u2066x\u2069\ufeff\u200f\u202a", 64) == "nimdax")
    # clean_text bounds the input before the regex pass
    seen = []

    class _SpyRe:
        def __init__(self, real):
            self.real = real

        def sub(self, repl, text):
            seen.append(len(text))
            return self.real.sub(repl, text)

    real_re = secevents._CONTROL_RE
    secevents._CONTROL_RE = _SpyRe(real_re)
    try:
        out = secevents.clean_text("a\x00" * 2_000_000, 64)
        small = secevents.clean_text("abc\x00d", 64)
    finally:
        secevents._CONTROL_RE = real_re
    check("clean_text scans only a few times the limit, not a multi-megabyte value",
          seen and seen[0] <= 64 * 8 and out == "a" * 64 and small == "abcd", str(seen))
    # the ip filter
    f = secevents.ip_filter_values
    check("a full IPv6 address also matches its /64 row, in canonical form",
          f("2001:DB8:1:2:aaaa::9") == ["2001:DB8:1:2:aaaa::9", "2001:db8:1:2:aaaa::9", "2001:db8:1:2::/64"], str(f("2001:DB8:1:2:aaaa::9")))
    check("a typed /64 matches the stored /64 text",
          "2001:db8:1:2::/64" in f("2001:DB8:1:2::/64") and "2001:db8:1:2::/64" in f("2001:db8:1:2:5::1/64"))
    check("IPv4 and non-addresses match as typed",
          f("203.0.113.9") == ["203.0.113.9"] and f("unknown") == ["unknown"] and f("*") == ["*"])
    # csv
    check("csv formula prefixes get an apostrophe",
          [secevents.csv_cell(c) for c in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "plain", 5, None)]
          == ["'=1+1", "'+1", "'-1", "'@SUM(A1)", "'\tx", "plain", 5, ""])
    # since/until parsing
    check("date bounds", secevents.parse_bound("2026-01-02") == "2026-01-02 00:00:00"
          and secevents.parse_bound("2026-01-02", end=True) == "2026-01-02 23:59:59"
          and secevents.parse_bound("2026-01-02T03:04:05Z") == "2026-01-02 03:04:05"
          and secevents.parse_bound("2026-01-02T03:04:05+02:00") == "2026-01-02 01:04:05")
    try:
        secevents.parse_bound("yesterday")
        check("bad bound raises", False)
    except ValueError:
        check("bad bound raises", True)

    # the aggregate buffer
    buf = secevents.SecurityEventLog()
    for i in range(500):
        buf.note("login_failed", ip="203.0.113.7", user_agent="ua", username=f"user{i}",
                 result="unknown_user", now=1_000_000.0 + i * 0.01)
    check("500 events from one ip in one minute are one buffered row",
          len(buf._agg) == 1 and next(iter(buf._agg.values()))["count"] == 500, str(len(buf._agg)))
    for i in range(secevents.BUFFER_MAX_KEYS + 3000):
        buf.note("login_failed", ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", now=2_000_000.0)
    check("flood from many addresses stays bounded in memory",
          len(buf._agg) <= secevents.BUFFER_MAX_KEYS + 2, str(len(buf._agg)))
    check("overflow bucket counts what did not fit",
          buf.pending() == 500 + secevents.BUFFER_MAX_KEYS + 3000)
    check("an IPv6 address is counted under its /64, IPv4 and mapped IPv4 as they are",
          secevents.aggregate_ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd") == "2001:db8:1:2::/64"
          and secevents.aggregate_ip("2001:db8:1:2::1") == "2001:db8:1:2::/64"
          and secevents.aggregate_ip("::ffff:203.0.113.9") == "203.0.113.9"
          and secevents.aggregate_ip("203.0.113.9") == "203.0.113.9"
          and secevents.aggregate_ip("unknown") == "unknown")
    v6 = secevents.SecurityEventLog()
    for i in range(300):
        v6.note("login_failed", ip=f"2001:db8:5:6::{i:x}", result="unknown_user", now=3_000_000.0)
    check("rotating addresses inside one /64 are one buffered row",
          len(v6._agg) == 1 and v6.pending() == 300, str(len(v6._agg)))
    buf.note("login_failed", ip=None, user_agent=object(), username=12345, details=object())
    check("note never raises on odd input", True)

    # public helpers never raise without a database
    secevents.SecurityEventLog().note("rate_limited")
    asyncio.run(secevents.SecurityEventLog().write("logout"))
    check("write without a database does not raise", True)


class _CountingDB:
    """Stands in for the database: keeps what the upsert would keep, per agg_key."""

    def __init__(self):
        self.rows = {}

    async def upsert_security_events(self, rows):
        for r in rows:
            self.rows[r["agg_key"]] = self.rows.get(r["agg_key"], 0) + r["count"]


async def rows_per_minute_unit():
    """The row cap holds across flushes: a flush must not hand the next one a fresh budget."""
    db = _CountingDB()
    buf = secevents.SecurityEventLog(db)
    cap = getattr(secevents, "MINUTE_MAX_KEYS", secevents.BUFFER_MAX_KEYS)
    minute = 1_800_000_000.0
    sent = 0
    for rnd in range(12):
        for i in range(secevents.BUFFER_MAX_KEYS + 500):
            sent += 1
            buf.note("login_failed", ip=f"10.{(sent >> 16) & 255}.{(sent >> 8) & 255}.{sent & 255}",
                     result="unknown_user", now=minute + rnd * 4)
        await buf.flush()
    check("distinct sources over many flushes in one minute stay within the row cap",
          len(db.rows) <= cap + 1, f"{len(db.rows)} rows for {sent} events")
    check("nothing is lost: every event is in a row or the overflow bucket",
          sum(db.rows.values()) == sent, f"{sum(db.rows.values())} of {sent}")
    check("overflow rows are in the shared bucket", any(k.startswith("*|") for k in db.rows))
    # a source already written this minute still adds to its own row after the cap is spent
    first = next(k for k in db.rows if not k.startswith("*|"))
    ip = first.split("|")[0]
    before = db.rows[first]
    buf.note("login_failed", ip=ip, result="unknown_user", now=minute + 50)
    await buf.flush()
    check("a known source keeps its own row after the cap is spent",
          db.rows[first] == before + 1 and len(db.rows) <= cap + 1)
    # the next minute has its own budget, and old minutes are forgotten
    buf.note("login_failed", ip="198.51.100.4", result="unknown_user", now=minute + 61)
    await buf.flush()
    check("the next minute gets its own row for a new source",
          any(k.startswith("198.51.100.4|") for k in db.rows))
    for m in range(1, 10):
        buf.note("login_failed", ip="198.51.100.5", now=minute + 60 * (m + 2))
    check("only a few recent minutes keep a key set",
          len(buf._minute_keys) <= secevents.MINUTES_TRACKED, str(len(buf._minute_keys)))
    # the same flood from one /64 is one row
    db2 = _CountingDB()
    b2 = secevents.SecurityEventLog(db2)
    for rnd in range(12):
        for i in range(2500):
            b2.note("login_failed", ip=f"2001:db8::{rnd * 2500 + i:x}", result="unknown_user", now=minute)
        await b2.flush()
    check("a rotating IPv6 /64 over many flushes is one row", len(db2.rows) == 1
          and sum(db2.rows.values()) == 30000, str(db2.rows))


class _ImmediateDB(_CountingDB):
    def __init__(self):
        super().__init__()
        self.inserted = []

    async def insert_security_event(self, row):
        self.inserted.append(row)


async def immediate_cap_unit():
    """Immediate events: at most 30 rows per (user id or address, event) and minute; the rest is aggregated."""
    db = _ImmediateDB()
    buf = secevents.SecurityEventLog(db)
    clock = {"t": 1_900_000_020.0}          # 20 s into a minute: a loop of 100 stays inside it
    real_clock = secevents._clock
    secevents._clock = lambda: clock["t"]
    try:
        check("the cap is 30 per minute", secevents.IMMEDIATE_PER_MINUTE == 30)
        for i in range(100):
            await buf.write("login_success", ip="198.51.100.20", user_id=7, username="loop_user",
                            result="web", details={"via": "web"})
        for i in range(100):
            await buf.write("session_revoked", ip="198.51.100.20", user_id=7, username="loop_user", result="own")
        await buf.flush()
        logins = [r for r in db.inserted if r["event"] == "login_success"]
        revokes = [r for r in db.inserted if r["event"] == "session_revoked"]
        check("a loop of 100 sign-ins writes 30 immediate rows", len(logins) == 30, str(len(logins)))
        check("a loop of 100 session revocations writes 30 immediate rows", len(revokes) == 30, str(len(revokes)))
        agg = {k: v for k, v in db.rows.items()}
        login_agg = [(k, v) for k, v in agg.items() if "|login_success|" in k]
        check("the other 70 sign-ins are one counted row for the minute",
              len(login_agg) == 1 and login_agg[0][1] == 70, str(login_agg))
        revoke_agg = [(k, v) for k, v in agg.items() if "|session_revoked|" in k]
        check("the other 70 revocations are one counted row for the minute",
              len(revoke_agg) == 1 and revoke_agg[0][1] == 70, str(revoke_agg))
        check("every event is accounted for (written or counted)",
              len(logins) + sum(v for k, v in login_agg) == 100 and len(revokes) + sum(v for k, v in revoke_agg) == 100)
        # two accounts behind one address, both over the cap: counted apart, never under the other's id
        for _ in range(100):
            await buf.write("login_success", ip="198.51.100.30", user_id=21, result="web")
            await buf.write("login_success", ip="198.51.100.30", user_id=22, result="web")
        await buf.flush()
        k21 = [(k, v) for k, v in db.rows.items() if k.startswith("198.51.100.30|login_success|") and k.endswith("|u21")]
        k22 = [(k, v) for k, v in db.rows.items() if k.startswith("198.51.100.30|login_success|") and k.endswith("|u22")]
        check("two accounts behind one address over the cap get one counted row each (70 each)",
              len(k21) == 1 and k21[0][1] == 70 and len(k22) == 1 and k22[0][1] == 70, str(db.rows))
        # another user, another event, another address are separate budgets
        for _ in range(5):
            await buf.write("login_success", ip="198.51.100.20", user_id=8, username="other", result="web")
            await buf.write("password_changed", ip="198.51.100.20", user_id=7, username="loop_user")
            await buf.write("login_success", ip="198.51.100.21", user_id=None, username=None, result="web")
        got = lambda e, u: len([r for r in db.inserted if r["event"] == e and r["user_id"] == u])  # noqa: E731
        check("another user has their own budget", got("login_success", 8) == 5)
        check("another event of the same user has its own budget", got("password_changed", 7) == 5)
        check("without a user id the address is the key", len([r for r in db.inserted
              if r["ip"] == "198.51.100.21"]) == 5)
        # the next minute starts again
        clock["t"] += 60
        for _ in range(40):
            await buf.write("login_success", ip="198.51.100.20", user_id=7, username="loop_user", result="web")
        check("the next minute has a fresh budget of 30", len([r for r in db.inserted
              if r["event"] == "login_success" and r["user_id"] == 7]) == 60)
        # a flood of distinct keys cannot grow the memory of the counter without bound
        for i in range(secevents.IMMEDIATE_MAX_KEYS + 50):
            await buf.write("login_success", ip="203.0.113.1", user_id=100000 + i, result="web")
        check("the per-minute counter is bounded",
              len(buf._immediate_counts) <= secevents.IMMEDIATE_MAX_KEYS)
    finally:
        secevents._clock = real_clock


async def exempt_events_unit():
    """Admin and configuration events keep every row: no per-minute cap, no overflow bucket."""
    db = _ImmediateDB()
    buf = secevents.SecurityEventLog(db)
    clock = {"t": 1_900_000_020.0}
    real_clock = secevents._clock
    secevents._clock = lambda: clock["t"]
    try:
        exempt = ["role_changed", "user_deleted", "password_reset", "never_ban_changed", "login_ban_changed", "proxy_limit_changed",
                  "cf_ranges_refreshed", "cf_ranges_reset", "cf_refresh_toggled", "cf_ranges_approved", "cf_ranges_dismissed",
                  "security_retention_changed", "security_events_pruned", "security_log_export",
                  "webhook_allow_private", "push_key_reset", "maintenance_changed",
                  "rbrowser_settings_changed", "rbrowser_preflight_failed", "rbrowser_listener_found",
                  "rbrowser_socket_mismatch", "rbrowser_display_mismatch"]
        cap_exempt = set(getattr(secevents, "CAP_EXEMPT", ()))
        check("every cf_* event of the table is on the exempt list",
              {e for e in secevents.EVENTS if e.startswith("cf_")} <= cap_exempt)
        check("every exempt name is a real event", set(exempt) <= set(secevents.EVENTS)
              and cap_exempt == set(exempt)
              and set(getattr(secevents, "CAP_EXEMPT_WITH_USER", ())) == {"ip_blocked", "ip_unblocked"})
        check("sign-ins and sign-outs are not exempt", not ({"login_success", "logout", "session_revoked",
              "api_key_created", "password_changed", "invite_created"} & cap_exempt))
        for ev in exempt:
            for i in range(secevents.IMMEDIATE_PER_MINUTE + 15):
                await buf.write(ev, ip="198.51.100.40", user_id=9, username="staff", result="x",
                                details={"target_user_id": i})
        for ev in ("ip_blocked", "ip_unblocked"):
            for i in range(secevents.IMMEDIATE_PER_MINUTE + 15):
                await buf.write(ev, ip="198.51.100.40", user_id=9, username="staff", details={"target_ip": f"203.0.113.{i}"})
        await buf.flush()
        for ev in exempt + ["ip_blocked", "ip_unblocked"]:
            got = [r for r in db.inserted if r["event"] == ev]
            check(f"{ev}: all {secevents.IMMEDIATE_PER_MINUTE + 15} rows are written with their details",
                  len(got) == secevents.IMMEDIATE_PER_MINUTE + 15 and all(r["details"] for r in got), str(len(got)))
        check("none of them went into the aggregate buffer", not db.rows, str(db.rows))
        # without a user id an ip_blocked is not an administrator's action: it is capped like any event
        before = len([r for r in db.inserted if r["event"] == "ip_blocked"])
        for i in range(60):
            await buf.write("ip_blocked", ip="198.51.100.41", details={"target_ip": "203.0.113.9"})
        await buf.flush()
        check("ip_blocked without a user id stays under the cap",
              len([r for r in db.inserted if r["event"] == "ip_blocked"]) - before == secevents.IMMEDIATE_PER_MINUTE)
        # exempt events never use up the budget of a capped event of the same user
        for i in range(secevents.IMMEDIATE_PER_MINUTE):
            await buf.write("logout", ip="198.51.100.40", user_id=9)
        check("the budget of a capped event is not spent by exempt ones",
              len([r for r in db.inserted if r["event"] == "logout"]) == secevents.IMMEDIATE_PER_MINUTE)
        # a flood of distinct keys does not turn exempt events into counted ones
        for i in range(secevents.IMMEDIATE_MAX_KEYS + 50):
            await buf.write("login_success", ip="203.0.113.1", user_id=200000 + i, result="web")
        before = len([r for r in db.inserted if r["event"] == "role_changed"])
        await buf.write("role_changed", ip="203.0.113.1", user_id=7, details={"target_user_id": 1})
        check("an exempt event is still written when the per-minute key table is full",
              len([r for r in db.inserted if r["event"] == "role_changed"]) == before + 1)
    finally:
        secevents._clock = real_clock


async def overflow_keeps_user_unit():
    """An over-cap row that has a user id is never folded into the bucket without an actor."""
    db = _ImmediateDB()
    buf = secevents.SecurityEventLog(db)
    clock = {"t": 1_900_000_020.0}
    real_clock = secevents._clock
    secevents._clock = lambda: clock["t"]
    try:
        for i in range(secevents.MINUTE_MAX_KEYS + 20):      # spend the minute's distinct rows
            buf.note("login_failed", ip=f"10.{i >> 8}.{i & 255}.1", result="bad_password", now=clock["t"])
        check("(setup) the minute's row budget is spent",
              len(buf._minute_keys[secevents.now_ts(clock["t"])[:16]]) >= secevents.MINUTE_MAX_KEYS)
        for _ in range(secevents.IMMEDIATE_PER_MINUTE + 10):
            await buf.write("login_success", ip="198.51.100.50", user_id=31, username="member_a", result="web")
            await buf.write("login_success", ip="198.51.100.51", user_id=32, username="member_b", result="web")
        await buf.flush()
        mine = [(k, v) for k, v in db.rows.items() if "|login_success|" in k]
        check("over-cap rows of two accounts are kept apart, not in one bucket without an actor",
              sorted(k.rsplit("|", 1)[-1] for k, _ in mine) == ["u31", "u32"] and all(v == 10 for _, v in mine), str(mine))
        buf.note("login_success", ip="198.51.100.52", user_id=33, username="member_c", result="web", now=clock["t"])
        entry = [e for k, e in buf._agg.items() if k[1] == "login_success" and k[-1] == "u33"]
        check("the folded row keeps the account (user id and name) and drops the address, agent and details",
              len(entry) == 1 and entry[0]["user_id"] == 33 and entry[0]["username_tried"] == "member_c"
              and entry[0]["ip"] == secevents.OVERFLOW_IP and entry[0]["details"] is None, str(entry))
        buf.note("login_failed", ip="203.0.113.77", result="bad_password", now=clock["t"])
        entry = [e for k, e in buf._agg.items() if k[0] == secevents.OVERFLOW_IP and k[1] == "login_failed"]
        check("an actor-less flood still shares the one overflow bucket",
              len(entry) == 1 and entry[0]["user_id"] is None, str(entry))
    finally:
        secevents._clock = real_clock


async def probe_and_rate_unit():
    secevents.log._agg.clear()
    saved = (Config.PROBE_BLOCK_STRIKES, Config.RATE_LIMIT_REQUESTS)
    try:
        Config.PROBE_BLOCK_STRIKES = 3
        server._probe_strikes.clear()
        server._probe_blocks.clear()
        for _ in range(3):
            server._record_probe("127.0.0.1", "/.env", "scanner/1")
        check("loopback probe makes no block and no event", not secevents.log._agg)
        for _ in range(3):
            server._record_probe("8.8.8.23", "/.env", "scanner/1")
        pend = [e for e in secevents.log._agg.values() if e["event"] == "probe_block"]
        check("automatic probe block is recorded once, with ip and agent",
              len(pend) == 1 and pend[0]["ip"] == "8.8.8.23" and pend[0]["user_agent"] == "scanner/1"
              and pend[0]["count"] == 1 and pend[0]["category"] == "security", str(pend))
        server._probe_blocks.pop("8.8.8.23", None)

        Config.RATE_LIMIT_REQUESTS = 3
        server.rate_limits.clear()
        results = [server.check_rate_limit("198.51.100.99") for _ in range(10)]
        trips = [e for e in secevents.log._agg.values() if e["event"] == "rate_limited"]
        check("rate-limit trips are aggregated into one row",
              results.count(False) == 7 and len(trips) == 1 and trips[0]["count"] == 7, str(trips))
    finally:
        Config.PROBE_BLOCK_STRIKES, Config.RATE_LIMIT_REQUESTS = saved
        server.rate_limits.clear()
        server._probe_strikes.clear()
        server._probe_blocks.clear()
        secevents.log._agg.clear()


async def filter_and_upsert_db_tests():
    db = server.db
    base_rows = {"category": "auth", "count": 1, "user_id": None, "username_tried": None,
                 "user_agent": None, "result": None, "details": None}
    ts = "2026-01-01 00:00:00"
    await db.insert_security_event({**base_rows, "ts": ts, "event": "login_failed",
                                    "ip": "2001:db8:aa:bb::/64", "agg_key": "2001:db8:aa:bb::/64|login_failed||x"})
    await db.insert_security_event({**base_rows, "ts": ts, "event": "login_success",
                                    "ip": "2001:db8:aa:bb::9", "agg_key": None})
    await db.insert_security_event({**base_rows, "ts": ts, "event": "login_success",
                                    "ip": "2001:db8:aa:cc::9", "agg_key": None})
    full = await db.get_security_events(ip="2001:DB8:AA:BB::9", limit=50)
    check("ip filter: a full IPv6 address finds its immediate row and its aggregated /64 row",
          sorted(e["event"] for e in full) == ["login_failed", "login_success"], str(full))
    typed = await db.get_security_events(ip="2001:db8:aa:bb::/64", limit=50)
    check("ip filter: a typed /64 finds the aggregated row",
          [e["event"] for e in typed] == ["login_failed"], str(typed))
    other = await db.get_security_events(ip="2001:db8:aa:cc::9", limit=50)
    check("ip filter: an address in another /64 does not match the first",
          [e["ip"] for e in other] == ["2001:db8:aa:cc::9"], str(other))
    check("ip filter: the count agrees with the list",
          await db.count_security_events(ip="2001:db8:aa:bb::9") == 2)

    # an upsert that fails partway leaves nothing behind and does not double counts
    key = lambda n: f"203.0.113.{n}|login_failed|bad|2026-01-01 00:00"
    def agg(n):
        return {**base_rows, "ts": ts, "event": "login_failed", "ip": f"203.0.113.{n}",
                "result": "bad", "count": 1, "agg_key": key(n)}
    good = [agg(1), agg(2), agg(3)]
    broken = [dict(good[0]), {**good[1], "ts": None}, dict(good[2])]
    try:
        await db.upsert_security_events(broken)
        failed = False
    except Exception:
        failed = True
    await db.conn.commit()          # an unrelated commit, as another request would do
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM security_events WHERE ip LIKE '203.0.113.%'")
    left = (await cur.fetchone())["n"]
    check("upsert: a failure partway applies none of the batch, even after an unrelated commit",
          failed and left == 0, f"failed={failed} left={left}")
    buf = secevents.SecurityEventLog(db)
    for n in (1, 2, 3):
        buf.note("login_failed", ip=f"203.0.113.{n}", result="bad", now=1_767_225_600.0)
    real_up = db.upsert_security_events
    calls = []

    async def flaky(rows):
        calls.append(len(rows))
        if len(calls) == 1:
            rows = [dict(rows[0]), {**rows[1], "ts": None}] + [dict(r) for r in rows[2:]]
        await real_up(rows)

    db.upsert_security_events = flaky
    try:
        first = await buf.flush()
        await db.conn.commit()
        second = await buf.flush()
    finally:
        db.upsert_security_events = real_up
    cur = await db.conn.execute(
        "SELECT ip, count FROM security_events WHERE ip LIKE '203.0.113.%' ORDER BY ip")
    got = [tuple(r) for r in await cur.fetchall()]
    check("upsert: a failed flush is re-queued and each source is counted once",
          first == 0 and second == 3 and got == [("203.0.113.1", 1), ("203.0.113.2", 1), ("203.0.113.3", 1)],
          f"{first} {second} {got}")
    await db.conn.execute("DELETE FROM security_events WHERE ip LIKE '203.0.113.%' OR ip LIKE '2001:db8:aa:%'")
    await db.conn.commit()


def unused_import_unit():
    import ast
    tree = ast.parse(Path(secevents.__file__).read_text())
    imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.value.id for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    check("secevents.py has no unused import (timedelta was one)", "timedelta" not in imported and not (imported - used),
          str(sorted(imported - used)))


async def main_async(tmp):
    unused_import_unit()
    await rows_per_minute_unit()
    await immediate_cap_unit()
    for unit in (exempt_events_unit, overflow_keeps_user_unit):
        try:
            await unit()
        except Exception as e:
            check(f"{unit.__name__} ran to the end", False, f"{type(e).__name__}: {e}")
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    # the schema is unchanged by a second connect
    cur = await server.db.conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name")
    before = [tuple(r) for r in await cur.fetchall()]
    await server.db._run_migrations()
    cur = await server.db.conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name")
    check("migration is idempotent", before == [tuple(r) for r in await cur.fetchall()])
    check("table has no foreign key to users",
          not [r for r in await (await server.db.conn.execute("PRAGMA foreign_key_list(security_events)")).fetchall()])
    check("retention default is 180 and settable",
          (await server.db.get_retention_config())["retention_security_events_days"] == "180")
    await server.db.set_retention_config({"retention_security_events_days": 0})
    check("retention 0 is accepted", (await server.db.get_retention_config())["retention_security_events_days"] == "0")
    await server.db.set_retention_config({"retention_security_events_days": 180})

    await probe_and_rate_unit()
    await filter_and_upsert_db_tests()

    ids = {}
    for name, role in (("sa", "superadmin"), ("adm", "admin"), ("u1", None), ("tfa", None), ("victim", None)):
        u = await create_user(name, PW[name], is_admin=role in ("admin", "superadmin"))
        if role:
            await server.db.set_user_role(u["id"], role)
        ids[name] = u["id"]
    totp_secret = generate_totp_secret()
    backups = generate_backup_codes(3)
    await server.db.set_user_totp_secret(ids["tfa"], totp_secret)
    await server.db.enable_user_totp(ids["tfa"], backups)

    secrets_used = list(PW.values()) + [NEW_PW, WRONG_CODE, totp_secret] + backups

    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False       # the test server speaks plain http
    server.rate_limits.clear()

    def client():
        return aiohttp.ClientSession(headers={"User-Agent": UA},
                                     cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def login(sess, name, pw=None, **extra):
        async with sess.post(base + "/login", json={"username": name, "password": pw or PW[name], **extra}) as r:
            return r.status, await r.json(content_type=None)

    async with client() as sa, client() as adm, client() as u1, client() as anon:
        # wrong password, unknown user
        long_name = "ghost\x00\n" + "g" * 100
        st, _ = await login(anon, long_name, "whatever-pass")
        check("unknown user login is refused", st == 401)
        st, _ = await login(anon, "u1", "not-the-password")
        check("wrong password login is refused", st == 401)
        await secevents.log.flush()
        unk = await rows("event = 'login_failed' AND result = 'unknown_user'")
        bad = await rows("event = 'login_failed' AND result = 'bad_password'")
        check("unknown-user failure row has ip, agent, truncated username, category auth",
              len(unk) == 1 and unk[0]["ip"] == "127.0.0.1" and unk[0]["user_agent"] == UA
              and unk[0]["username_tried"] == secevents.UNKNOWN_ACCOUNT and unk[0]["category"] == "auth"
              and unk[0]["user_id"] is None, str(unk))
        check("the typed text of an unknown account is stored nowhere in the row",
              "ghost" not in json.dumps(unk), str(unk))
        check("bad-password failure row names the account only by what was typed",
              len(bad) == 1 and bad[0]["username_tried"] == "u1", str(bad))

        # flood: 500 attempts from one address
        calls = {"upsert": 0, "insert": 0}
        real_up, real_ins = server.db.upsert_security_events, server.db.insert_security_event

        async def count_up(rs):
            calls["upsert"] += 1
            return await real_up(rs)

        async def count_ins(r):
            calls["insert"] += 1
            return await real_ins(r)
        server.db.upsert_security_events, server.db.insert_security_event = count_up, count_ins
        for i in range(500):
            async with anon.post(base + "/login", json={"username": f"nobody{i}", "password": "x"}) as r:
                await r.read()
        await secevents.log.flush()
        server.db.upsert_security_events, server.db.insert_security_event = real_up, real_ins
        flood = await rows("event = 'login_failed' AND result = 'unknown_user'")
        check("500-attempt flood adds at most 2 rows (minute boundary) and one transaction",
              len(flood) - len(unk) <= 2 and calls["insert"] == 0 and calls["upsert"] <= 1,
              f"rows {len(flood)} calls {calls}")
        check("flood count is kept", sum(r["count"] for r in flood) == 501, str(sum(r["count"] for r in flood)))
        check("none of the 500 typed unknown names was stored",
              not await rows("username_tried LIKE 'nobody%'"), "")

        # the warning log lines: the name only for an existing account
        import logging
        records = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        grab = Grab()
        server.logger.addHandler(grab)
        pasted = "Pasted-Password-9x"
        try:
            await login(anon, pasted, "x")                    # web login, unknown account
            async with anon.post(base + "/api/token", json={"username": pasted + "T", "password": "x"}) as r:
                await r.read()                                # token route, unknown account
            await login(anon, "u1", "wrong-pass-again")        # web login, existing account
            async with anon.post(base + "/api/token", json={"username": "u1", "password": "wrong-pass-again"}) as r:
                await r.read()
        finally:
            server.logger.removeHandler(grab)
        text = "\n".join(records)
        check("log: an unknown account is named 'an unknown account' on both login routes",
              text.count("Failed web login for an unknown account") == 1
              and text.count("Failed login attempt for an unknown account") == 1, text[-400:])
        check("log: the typed text of an unknown account is not logged", pasted not in text, text[-400:])
        check("log: an existing account is still named",
              "Failed web login for 'u1'" in text and "Failed login attempt for 'u1'" in text, text[-400:])
        await secevents.log.flush()
        check("the pasted text is not in any row either", not await rows("username_tried LIKE ?", ("%" + pasted + "%",)))
        check("_existing_username: an existing account is kept, an unknown one is replaced, a non-string too",
              await server._existing_username("u1") == "u1"
              and await server._existing_username("no-such-user") == secevents.UNKNOWN_ACCOUNT
              and await server._existing_username(12345) == secevents.UNKNOWN_ACCOUNT
              and await server._existing_username(None) == secevents.UNKNOWN_ACCOUNT)

        # flood where the rate limit trips as well: only aggregate rows grow
        Config.RATE_LIMIT_REQUESTS = 50
        server.rate_limits.clear()
        before_rows = len(await rows())
        for i in range(120):
            async with anon.post(base + "/login", json={"username": f"zed{i}", "password": "x"}) as r:
                await r.read()
        await secevents.log.flush()
        grown = len(await rows()) - before_rows
        check("rate-limited flood is aggregated too", grown <= 4 and await agg_total("rate_limited") == 70,
              f"grown {grown} rate_limited {await agg_total('rate_limited')}")
        Config.RATE_LIMIT_REQUESTS = 100000
        server.rate_limits.clear()

        # periodic flusher writes without a manual flush
        secevents.FLUSH_INTERVAL = 0.2
        secevents.log.start()
        await login(anon, "flusher-check", "x")

        async def flushed():
            return bool(await rows("username_tried = 'flusher-check'")) or \
                bool(await rows("event = 'login_failed' AND count > 1"))
        check("background flusher writes the buffer", await wait_for(flushed))
        await secevents.log.shutdown()

        # successful logins: written at once
        st, _ = await login(sa, "sa")
        check("superadmin logs in", st == 200)
        st, _ = await login(adm, "adm")
        st, _ = await login(u1, "u1")
        succ = await rows("event = 'login_success' AND username_tried = 'sa'")
        check("login success is written without waiting for a flush",
              len(succ) == 1 and succ[0]["user_agent"] == UA and succ[0]["user_id"] == ids["sa"]
              and succ[0]["category"] == "auth" and "web" in succ[0]["details"], str(succ))

        # 2FA: required, failed, passed, backup
        async with client() as t1:
            st, body = await login(t1, "tfa")
            check("2FA is requested", st == 200 and body.get("status") == "2fa_required")
            actual = pyotp.TOTP(totp_secret).now()
            secrets_used.append(actual)
            wrong = WRONG_CODE if WRONG_CODE != actual else "123123"
            secrets_used.append(wrong)
            st, _ = await login(t1, "tfa", totp_code=wrong)
            check("wrong 2FA code is refused", st == 401)
            good = pyotp.TOTP(totp_secret).now()
            secrets_used.append(good)
            st, _ = await login(t1, "tfa", totp_code=good)
            check("correct 2FA code is accepted", st == 200)
        async with client() as t2:
            st, _ = await login(t2, "tfa", totp_code=backups[0])
            check("backup code is accepted", st == 200)
        await secevents.log.flush()
        for ev, res in (("2fa_required", None), ("2fa_failed", "bad_code"), ("2fa_passed", "totp"),
                        ("backup_code_used", None)):
            got = await rows("event = ? AND user_id = ?", (ev, ids["tfa"]))
            check(f"{ev} recorded with ip and agent",
                  bool(got) and got[0]["ip"] == "127.0.0.1" and got[0]["user_agent"] == UA
                  and (res is None or got[0]["result"] == res), str(got))
        async with client() as t3:
            await t3.post(base + "/api/token", json={"username": "tfa", "password": PW["tfa"]})
            tcode = pyotp.TOTP(totp_secret).now()
            secrets_used.append(tcode)
            async with t3.post(base + "/api/token", json={"username": "tfa", "password": PW["tfa"],
                                                           "totp_code": tcode}) as r:
                tok = (await r.json())["token"]
            secrets_used.append(tok)
        tok_login = await rows("event = 'login_success' AND details LIKE '%\"via\":\"token\"%' AND user_id = ?", (ids["tfa"],))
        check("token endpoint login recorded", len(tok_login) == 1, str(tok_login))

        # API keys
        async with u1.post(base + "/api/api-keys", json={"name": "k1"}) as r:
            kd = await r.json()
        secrets_used.append(kd["key"])
        kid = kd["id"]
        async with u1.post(base + "/api/api-keys", json={"name": "k2"}) as r:
            kd2 = await r.json()
        secrets_used.append(kd2["key"])
        async with u1.post(base + f"/api/api-keys/{kid}/revoke") as r:
            check("api key revoke", r.status == 200)
        async with u1.delete(base + f"/api/api-keys/{kd2['id']}") as r:
            check("api key delete", r.status == 200)
        for ev in ("api_key_created", "api_key_revoked", "api_key_deleted"):
            got = await rows("event = ? AND user_id = ?", (ev, ids["u1"]))
            check(f"{ev} recorded with ip and agent",
                  bool(got) and got[0]["ip"] == "127.0.0.1" and got[0]["user_agent"] == UA, str(got))

        # password change: wrong current, then right
        async with u1.post(base + "/api/me/password",
                           json={"current_password": "nope-nope-nope", "new_password": NEW_PW}) as r:
            check("wrong current password refused", r.status == 401)
        async with u1.post(base + "/api/me/password",
                           json={"current_password": PW["u1"], "new_password": NEW_PW}) as r:
            check("password change works", r.status == 200)
        await secevents.log.flush()
        check("password_changed and password_change_failed recorded",
              len(await rows("event = 'password_changed' AND user_id = ?", (ids["u1"],))) == 1
              and await agg_total("password_change_failed") == 1)

        # 2FA enable / disable through the API
        async with client() as u2:
            await login(u2, "victim")
            async with u2.post(base + "/api/user/2fa/setup") as r:
                sec = (await r.json())["secret"]
            secrets_used.append(sec)
            vcode = pyotp.TOTP(sec).now()
            secrets_used.append(vcode)
            async with u2.post(base + "/api/user/2fa/verify", json={"code": vcode}) as r:
                bc = (await r.json())["backup_codes"]
            secrets_used.extend(bc)
            async with u2.post(base + "/api/user/2fa/disable", json={"password": "bad-bad-bad"}) as r:
                pass
            async with u2.post(base + "/api/user/2fa/disable", json={"password": PW["victim"]}) as r:
                check("2FA disable works", r.status == 200)
        await secevents.log.flush()
        check("2fa_enabled, 2fa_disabled and 2fa_disable_failed recorded",
              len(await rows("event = '2fa_enabled' AND user_id = ?", (ids["victim"],))) == 1
              and len(await rows("event = '2fa_disabled' AND user_id = ?", (ids["victim"],))) == 1
              and await agg_total("2fa_disable_failed") == 1)

        # admin actions
        async with sa.post(base + "/api/admin/invite-codes", json={"type": "single_use"}) as r:
            inv = await r.json()
        secrets_used.append(inv["code"])
        async with client() as reg:
            async with reg.post(base + "/api/register", json={
                    "username": "newbie", "password": "Newbie-pass-1234!", "invite_code": "bad-bad-code"}) as r:
                check("bad invite refused", r.status == 403)
            async with reg.post(base + "/api/register", json={
                    "username": "newbie", "password": "Newbie-pass-1234!", "invite_code": inv["code"]}) as r:
                check("registration works", r.status == 201, str(r.status))
        secrets_used.append("Newbie-pass-1234!")
        async with sa.delete(base + f"/api/admin/invite-codes/{inv['id']}") as r:
            pass
        async with sa.post(base + "/api/users", json={"username": "madeby", "password": "Madeby-pass-123!"}) as r:
            made = await r.json()
        secrets_used.append("Madeby-pass-123!")
        async with sa.put(base + f"/api/users/{made['id']}/role", json={"role": "moderator"}) as r:
            check("role change works", r.status == 200)
        async with sa.post(base + f"/api/users/{made['id']}/reset-password", json={"new_password": "Reset-pass-12345!"}) as r:
            check("admin reset works", r.status == 200)
        secrets_used.append("Reset-pass-12345!")
        async with sa.post(base + "/api/admin/blocked-ips", json={"ip_address": "203.0.113.200", "reason": "t"}) as r:
            check("manual block works", r.status == 201)
        async with sa.delete(base + "/api/admin/blocked-ips/203.0.113.200") as r:
            check("manual unblock works", r.status == 200)
        async with sa.delete(base + f"/api/users/{made['id']}") as r:
            check("user delete works", r.status == 200)
        audits = await server.db.get_audit_log(action="user_delete")
        check("deleting a user is an audit log entry with the actor, the target and the role, like a role change",
              len(audits) == 1 and audits[0]["actor_id"] == ids["sa"] and audits[0]["target_id"] == made["id"]
              and audits[0]["target_name"] == "madeby" and audits[0]["target_type"] == "user"
              and "moderator" in json.dumps(audits[0].get("details")), str(audits))
        audits = await server.db.get_audit_log(action="role_change")
        check("(control) the role change is audited the same way", len(audits) == 1 and audits[0]["target_name"] == "madeby")

        # changes that weaken the log are events themselves
        async with sa.put(base + "/api/admin/retention", json={"retention_chat_days": 7}) as r:
            await r.read()
        check("an unrelated retention save is not an event",
              not await rows("event = 'security_retention_changed'"))
        async with sa.put(base + "/api/admin/retention", json={"retention_security_events_days": 30}) as r:
            check("retention save works", r.status == 200, str(r.status))
        async with sa.put(base + "/api/admin/retention", json={"retention_security_events_days": 30}) as r:
            await r.read()
        got = await rows("event = 'security_retention_changed'")
        check("shortening the security log retention is an event with the old and new value and the actor",
              len(got) == 1 and json.loads(got[0]["details"]) == {"old_days": "180", "new_days": "30"}
              and got[0]["user_id"] == ids["sa"] and got[0]["category"] == "security", str(got))
        await server.db.conn.execute(
            "INSERT INTO security_events (ts, event, category, ip, count) VALUES ('2001-01-01 00:00:00', 'logout', 'auth', '203.0.113.77', 1)")
        await server.db.conn.execute(
            "INSERT INTO security_events (ts, event, category, ip, count) VALUES ('2001-01-02 00:00:00', 'logout', 'auth', '203.0.113.78', 1)")
        await server.db.conn.commit()
        async with sa.post(base + "/api/admin/retention/run") as r:
            ran = await r.json()
            check("run cleanup works", r.status == 200 and ran["deleted"].get("security_events") == 2, str(ran))
        got = await rows("event = 'security_events_pruned'")
        check("a manual cleanup that pruned security events records the count",
              len(got) == 1 and json.loads(got[0]["details"]) == {"deleted": 2, "days": 30, "via": "run_cleanup_now"}
              and got[0]["user_id"] == ids["sa"], str(got))
        async with sa.post(base + "/api/admin/retention/run") as r:
            await r.read()
        check("a manual cleanup that pruned nothing records nothing",
              len(await rows("event = 'security_events_pruned'")) == 1)
        async with sa.put(base + "/api/admin/retention", json={"retention_security_events_days": 180}) as r:
            await r.read()
        async with sa.put(base + "/api/admin/cf-ranges", json={"enabled": False}) as r:
            check("turning the Cloudflare refresh off works", r.status == 200, str(r.status))
        async with sa.put(base + "/api/admin/cf-ranges", json={"enabled": False}) as r:
            await r.read()
        async with sa.put(base + "/api/admin/cf-ranges", json={"enabled": True}) as r:
            await r.read()
        got = await rows("event = 'cf_refresh_toggled'")
        check("turning the Cloudflare refresh off and on are events (a save that changes nothing is not)",
              [json.loads(g["details"]) for g in got] == [{"was": True, "enabled": False}, {"was": False, "enabled": True}]
              and all(g["user_id"] == ids["sa"] for g in got), str(got))
        await secevents.log.flush()
        for ev in ("invite_created", "invite_deactivated", "user_created", "role_changed",
                   "password_reset", "ip_blocked", "ip_unblocked", "user_deleted"):
            got = await rows("event = ? AND user_id = ?", (ev, ids["sa"]))
            if ev == "user_created":
                got = [g for g in await rows("event = 'user_created'")]
            check(f"{ev} recorded", bool(got) and got[0]["ip"] == "127.0.0.1", str(got))
        check("failed registration is aggregated", await agg_total("register_failed", "invalid_invite") == 1)
        reg_rows = await rows("event = 'register_failed'")
        check("a failed registration for a name that is not an account stores the fixed text",
              len(reg_rows) == 1 and reg_rows[0]["username_tried"] == secevents.UNKNOWN_ACCOUNT, str(reg_rows))
        deleted_rows = await rows("event = 'role_changed'")
        check("rows are kept after the target account is deleted",
              len(deleted_rows) == 1 and json.loads(deleted_rows[0]["details"])["target_username"] == "madeby")

        # sessions: revoke one, logout
        async with u1.get(base + "/api/tokens") as r:
            toks = (await r.json())["tokens"]
        async with client() as extra:
            await login(extra, "victim")
            async with extra.post(base + "/logout", allow_redirects=False) as r:
                check("logout (POST) answers", r.status == 200)
        await secevents.log.flush()
        check("logout recorded", len(await rows("event = 'logout' AND user_id = ?", (ids["victim"],))) == 1)
        async with sa.get(base + "/api/tokens") as r:
            pass
        async with client() as rv:
            await login(rv, "victim")
            tid = (await server.db.get_user_tokens(ids["victim"]))[0]["token_id"]
            async with rv.post(base + "/api/token/revoke", json={"token_id": tid}) as r:
                check("own session revoke works", r.status == 200)
        check("session_revoked recorded with a token prefix only",
              any(json.loads(r["details"]).get("token_id") == tid[:8] and tid not in (r["details"] or "")
                  for r in await rows("event = 'session_revoked'")))
        del toks

        # host-key accept needs an SSH connection; covered by the staged check

        # reading and exporting: superadmin only
        for label, sess in (("admin", adm), ("user", u1), ("anonymous", anon)):
            async with sess.get(base + "/api/admin/security-events") as r:
                check(f"{label} cannot read the log", r.status in (401, 403), str(r.status))
            async with sess.get(base + "/api/admin/security-events/export") as r:
                check(f"{label} cannot export the log", r.status in (401, 403), str(r.status))
        async with sa.get(base + "/api/admin/security-events?category=auth&limit=5") as r:
            data = await r.json()
            check("superadmin reads the log, auth chip filters by category",
                  r.status == 200 and data["total"] > 0 and all(e["category"] == "auth" for e in data["events"]))
        async with sa.get(base + "/api/admin/security-events?limit=200") as r:
            data = await r.json()
            cats = {e["category"] for e in data["events"]}
            check("no category filter shows auth and security rows", cats == {"auth", "security"}, str(cats))
        async with sa.get(base + "/api/admin/security-events?event=api_key_created&ip=127.0.0.1") as r:
            data = await r.json()
            check("event and ip filters", data["total"] >= 2 and all(e["event"] == "api_key_created" for e in data["events"]))
        async with sa.get(base + "/api/admin/security-events?since=nonsense") as r:
            check("bad since is a 400", r.status == 400)
        async with sa.get(base + "/api/admin/security-events?category=zzz") as r:
            check("bad category is a 400", r.status == 400)
        n_exports = len(await rows("event = 'security_log_export'"))
        # rows whose text starts with a formula character (a failed login keeps only the
        # first name of a minute, so these go in as separate immediate events)
        for nm in ("=cmd|' /C calc'!A0", "@SUM(1+1)", "-2+3", "+1+1"):
            await server.security_event("logout", ip="127.0.0.1", username=nm, user_agent="=HYPERLINK(\"x\")")
        async with sa.get(base + "/api/admin/security-events/export?format=csv&event=logout") as r:
            text = await r.text()
            check("csv export headers", r.status == 200 and "attachment" in r.headers["Content-Disposition"]
                  and r.headers["X-Export-Truncated"] == "false")
        parsed = list(csv.reader(io.StringIO(text)))
        check("csv has the header and rows", parsed[0] == list(secevents.CSV_COLUMNS) and len(parsed) >= 5, str(len(parsed)))
        names = [row[5] for row in parsed[1:]]
        check("csv neutralises formula cells",
              all(n in names for n in ("'=cmd|' /C calc'!A0", "'@SUM(1+1)", "'-2+3", "'+1+1"))
              and not any(n[:1] in "=@+-" for n in names if n), str(names))
        check("csv neutralises a formula user agent",
              [row[7] for row in parsed[1:] if row[5] == "'+1+1"] == ["'=HYPERLINK(\"x\")"])
        async with sa.get(base + "/api/admin/security-events/export?format=json&category=security") as r:
            exported = json.loads(await r.text())
            check("json export returns the filtered rows",
                  exported["count"] == len(exported["events"]) and exported["events"]
                  and all(e["category"] == "security" for e in exported["events"]) and not exported["truncated"])
        async with sa.get(base + "/api/admin/security-events/export?format=json&since=2999-01-01") as r:
            check("range filter applies to the export", json.loads(await r.text())["events"] == [])
        async with sa.get(base + "/api/admin/security-events/export?format=xml") as r:
            check("unknown export format is a 400", r.status == 400)
        check("each export is recorded once, listing is not",
              len(await rows("event = 'security_log_export'")) == n_exports + 3,
              str(len(await rows("event = 'security_log_export'")) - n_exports))
        exp = (await rows("event = 'security_log_export'"))[-1]
        check("export event names the superadmin and the ip",
              exp["user_id"] == ids["sa"] and exp["ip"] == "127.0.0.1")
        n_now = len(await rows("event = 'security_log_export'"))
        async with sa.head(base + "/api/admin/security-events/export?format=csv") as r:
            head_status = r.status
        check("export answers only GET: a HEAD is refused and records no export event",
              head_status == 405 and len(await rows("event = 'security_log_export'")) == n_now, str(head_status))

        # export cap
        saved_cap, saved_page = secevents.EXPORT_MAX_ROWS, secevents.EXPORT_PAGE
        secevents.EXPORT_MAX_ROWS, secevents.EXPORT_PAGE = 7, 3
        async with sa.get(base + "/api/admin/security-events/export?format=json") as r:
            exported = json.loads(await r.text())
            check("export is capped and says so",
                  len(exported["events"]) == 7 and exported["truncated"] and r.headers["X-Export-Truncated"] == "true")
            ids_seen = [e["id"] for e in exported["events"]]
            check("export pages are newest first without gaps or repeats",
                  ids_seen == sorted(set(ids_seen), reverse=True))
        secevents.EXPORT_MAX_ROWS, secevents.EXPORT_PAGE = saved_cap, saved_page

        # secrets: none of what the test used appears in any column of any row
        await secevents.log.flush()
        blob = "\n".join(json.dumps(r) for r in await rows())
        leaked = [s for s in secrets_used if s and s in blob]
        check("no password, code, token, API key or invite code in any row", not leaked, str(leaked))
        check("secret list is non-trivial", len(secrets_used) >= 20, str(len(secrets_used)))

        # a database error never blocks a login
        async def boom(*a, **k):
            raise RuntimeError("disk full")
        real_ins = server.db.insert_security_event
        server.db.insert_security_event = boom
        async with client() as ok:
            st, _ = await login(ok, "sa")
        server.db.insert_security_event = real_ins
        check("login succeeds while event writes fail", st == 200)
        real_up = server.db.upsert_security_events
        server.db.upsert_security_events = boom
        secevents.log.note("login_failed", ip="192.0.2.1")
        await secevents.log.flush()
        check("failed flush keeps the counts for the next try", secevents.log.pending() == 1)
        server.db.upsert_security_events = real_up
        await secevents.log.flush()
        check("counts are written once the database recovers", secevents.log.pending() == 0
              and await agg_total("login_failed") > 0)

        # a stalled write does not hold the caller
        async def slow(*a, **k):
            await asyncio.sleep(10)
        server.db.insert_security_event = slow
        saved_to = secevents.IMMEDIATE_TIMEOUT
        secevents.IMMEDIATE_TIMEOUT = 0.2
        t0 = asyncio.get_event_loop().time()
        await server.security_event("logout", ip="127.0.0.1")
        check("a stalled write releases the caller", asyncio.get_event_loop().time() - t0 < 2)
        secevents.IMMEDIATE_TIMEOUT = saved_to
        server.db.insert_security_event = real_ins

        # rows survive account deletion; retention prunes by age only
        victim_rows = len(await rows("user_id = ?", (ids["victim"],)))
        await server.db.delete_user(ids["victim"])
        check("deleting an account keeps its rows",
              victim_rows > 0 and len(await rows("user_id = ?", (ids["victim"],))) == victim_rows)
        await server.db.insert_security_event({
            "ts": "2000-01-01 00:00:00", "event": "logout", "category": "auth", "ip": "1.1.1.1",
            "count": 1, "agg_key": None})
        removed = await server.db.cleanup_old_security_events(days=180)
        check("retention removes only old rows",
              removed == 1 and len(await rows("ip = '1.1.1.1'")) == 0 and len(await rows()) > 10)

    await srv.close()
    await server.db.close()


def main():
    unit_tests()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            asyncio.run(main_async(tmp))
        except BaseException:
            os._exit(1)      # a failed run must not hang on the open database thread
    print(f"\n{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
