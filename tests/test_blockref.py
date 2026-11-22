"""Reference IDs on block (403) and rate-limit (429) answers, and the administrator lookup.

Covers: the ID format and that it is random; one ID and one row for 10,000 requests from a blocked
address; a bounded number of rows for a flood of distinct addresses (new IDs a minute, overflow ID,
row cap, age cap); the same block page for a manual permanent block, a manual timed block, a sign-in
ban and a scanner block (no reason, address, rule or expiry in it, no Retry-After, no script); JSON with
`ref` for API clients; a rate-limited client's ID finds the limiter event; the lookup (administrators
only, a member and a signed-out client refused before the ID is read, one 404 for unknown, malformed and
expired IDs, rate limited); the unblock from the lookup uses the existing route and is audited; a source
guard on every 429 in server.py; the migration is idempotent.

Run:  venv/bin/python tests/test_blockref.py
"""

import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ["NEVER_BAN_CIDRS"] = ""

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, make_mocked_request  # noqa: E402
from multidict import CIMultiDict  # noqa: E402

import blockref  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class _Transport:
    def __init__(self, peer):
        self.peer = peer

    def get_extra_info(self, name, default=None):
        return (self.peer, 4242) if name == "peername" else default


def req(peer, path="/dashboard", headers=None, method="GET"):
    return make_mocked_request(method, path, headers=CIMultiDict(headers or {}), transport=_Transport(peer))


async def ok_handler(request):
    return web.Response(text="fine")


async def through(peer, path="/dashboard", headers=None):
    return await server.security_headers_middleware(req(peer, path, headers), ok_handler)


async def rows(where="1=1", params=()):
    cur = await server.db.conn.execute(f"SELECT * FROM block_refs WHERE {where} ORDER BY id", params)
    return [dict(r) for r in await cur.fetchall()]


def strip_ref(text):
    return re.sub(r"[A-Z2-9]{4}-[A-Z2-9]{4}", "XXXX-XXXX", text)


PW = {"sa": "Sa-pass-12345!", "member": "Member-pass-123!"}
HTML = {"Accept": "text/html,application/xhtml+xml"}
REASON = "secret-reason-text-9431"


def pure_unit():
    refs = {blockref.new_ref() for _ in range(2000)}
    check("IDs are 8 characters from the reading alphabet", all(len(r) == 8 and set(r) <= set(blockref.ALPHABET) for r in refs))
    check("IDs are random (2000 draws, no repeat)", len(refs) == 2000)
    check("the alphabet has no 0, O, 1 or I", not set("0O1I") & set(blockref.ALPHABET))
    check("display and normalize round-trip, case, spaces and hyphen ignored",
          blockref.normalize(blockref.display("ABCD2345")) == "ABCD2345" and blockref.normalize(" abcd-2345 ") == "ABCD2345")
    check("normalize refuses what cannot be an ID",
          all(blockref.normalize(x) is None for x in ("", "ABC", "ABCD-234O", "A" * 9, None, 5, "ABCD2345; DROP", "ABCD\n2345x")))
    src = (Path(SRC) / "blockref.py").read_text()
    check("the ID comes from the secrets module and nothing derives from an address or account",
          "secrets.choice" in src and "hashlib" not in src and "hash(" not in src)
    check("the retention constant in database.py equals the one in blockref.py",
          server.db.__class__.BLOCK_REF_DAYS == blockref.MAX_AGE_DAYS)
    check("bounds as stated in the notes", (blockref.REUSE_SECONDS, blockref.NEW_PER_MINUTE, blockref.MAX_ROWS,
                                             blockref.MAX_AGE_DAYS, blockref.LOOKUP_PER_MINUTE) == (3600, 60, 5000, 7, 20))


async def bounds_unit():
    ip = "203.0.113.50"
    await server.db.block_ip(ip, reason=REASON, blocked_by=None, expires_at=None)
    server._blocked_ips[ip] = None
    server._refs.reset()
    answers = []
    for i in range(10000):
        r = await through(ip, "/api/me" if i % 2 else "/dashboard", HTML if i % 3 == 0 else None)
        answers.append(r)
    check("10,000 requests from a blocked address are all 403", {a.status for a in answers} == {403})
    got = await rows("subject = ?", (ip,))
    check("10,000 requests from one blocked address are one row", len(got) == 1, str(len(got)))
    texts = {strip_ref(a.text) for a in answers if a.content_type == "text/html"}
    jrefs = {json.loads(a.text)["ref"] for a in answers if a.content_type == "application/json"}
    prefs = {re.search(r"[A-Z2-9]{4}-[A-Z2-9]{4}", a.text).group(0) for a in answers if a.content_type == "text/html"}
    check("they all show the same ID, in the page and in the JSON", len(jrefs) == 1 and jrefs == prefs, f"{jrefs} {prefs}")
    check("the stored row is that ID, kind block, with the stored reason and kind",
          got and blockref.display(got[0]["ref"]) in jrefs and got[0]["kind"] == "block"
          and got[0]["limiter"] == "ip_block" and got[0]["source"] == "manual" and got[0]["reason"] == REASON, str(got))
    await server.db.touch_block_ref(got[0]["ref"], 10000)

    # a flood of distinct sources: bounded rows, still an ID every time
    server._refs.reset()
    before = await server.db.count_block_refs()
    seen = set()
    for i in range(3000):
        a = f"198.51.{i // 250}.{i % 250 + 1}"
        r = await server._limited(req(a, "/api/x"), "login", "Rate limit exceeded", subject=a)
        seen.add(json.loads(r.text)["ref"])
    added = await server.db.count_block_refs() - before
    check("3000 distinct limited addresses add at most the per-minute budget plus one overflow row",
          added <= blockref.NEW_PER_MINUTE + 2, str(added))
    over = await rows("kind = 'overflow'")
    check("the overflow ID is one shared row that says why", len(over) <= 2 and all("more than" in (o["reason"] or "") and o["subject"] is None for o in over), str(over))
    check("every one of the 3000 answers carries an ID", all(re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", s) for s in seen) and len(seen) <= 63, str(len(seen)))

    # concurrent requests from one client during the first write: one ID, and it is the stored one
    server._refs.reset()
    cip = "203.0.113.55"
    await server.db.block_ip(cip, reason=REASON, blocked_by=None, expires_at=None)
    server._blocked_ips[cip] = None

    async def slow_loader():
        await asyncio.sleep(0.02)
        return "manual", REASON
    issuer = blockref.RefIssuer(server.db)
    got = await asyncio.gather(*[issuer.issue("block", "ip_block", cip, loader=slow_loader) for _ in range(10)])
    check("10 concurrent first requests from one client get one ID", len(set(got)) == 1 and got[0], str(got))
    check("and that ID is the stored row", await server.db.get_block_ref(got[0], blockref.MAX_AGE_DAYS) is not None)
    cip = "203.0.113.56"
    await server.db.block_ip(cip, reason=REASON, blocked_by=None, expires_at=None)
    server._blocked_ips[cip] = None
    server._refs.reset()
    results = await asyncio.gather(*[through(cip, "/api/me") for _ in range(10)])
    shown = {json.loads(r.text)["ref"] for r in results}
    stored = [blockref.display(r["ref"]) for r in await rows("subject = ?", (cip,))]
    check("10 concurrent blocked requests through the middleware show the stored ID, one row",
          len(shown) == 1 and stored == list(shown), f"{shown} {stored}")
    server._blocked_ips.pop(cip, None)
    # the overflow ID is stored too, also for concurrent first requests
    small = blockref.NEW_PER_MINUTE
    blockref.NEW_PER_MINUTE = 0
    try:
        issuer = blockref.RefIssuer(server.db)
        got = await asyncio.gather(*[issuer.issue("limit", "login", f"192.0.2.{i}", loader=slow_loader) for i in range(10)])
        check("concurrent first requests past the budget share one overflow ID that is stored",
              len(set(got)) == 1 and got[0] and (await server.db.get_block_ref(got[0], blockref.MAX_AGE_DAYS) or {}).get("kind") == "overflow", str(got))
    finally:
        blockref.NEW_PER_MINUTE = small
    lru = blockref.RefIssuer(server.db)
    small_cache = blockref.CACHE_MAX
    blockref.CACHE_MAX = 3
    try:
        ids = [await lru.issue("limit", "x", f"198.18.0.{i}") for i in range(3)]
        await lru.issue("limit", "x", "198.18.0.0")         # touched: now the most recently used
        await lru.issue("limit", "x", "198.18.0.9")         # evicts the least recently used (.1)
        check("the in-memory map drops the least recently used entry", lru.cached(("limit", "x", "198.18.0.0", None)) == ids[0]
              and lru.cached(("limit", "x", "198.18.0.1", None)) is None)
    finally:
        blockref.CACHE_MAX = small_cache

    # clock: the same client keeps its ID for the period, then gets a new one
    now = [1000.0]
    issuer = blockref.RefIssuer(server.db, clock=lambda: now[0])
    a = await issuer.issue("limit", "login", "192.0.2.1")
    b = await issuer.issue("limit", "login", "192.0.2.1")
    now[0] += blockref.REUSE_SECONDS - 1
    c = await issuer.issue("limit", "login", "192.0.2.1")
    now[0] += 2
    d = await issuer.issue("limit", "login", "192.0.2.1")
    check("one ID for the period, a new one after it", a == b == c and d and d != a)
    e = await issuer.issue("limit", "register", "192.0.2.1")
    f = await issuer.issue("limit", "login", "192.0.2.1", user_id=7)
    check("another limiter or another account gets its own ID", e not in (a, d) and f not in (a, d, e))
    # a failing database never breaks the answer
    class Broken:
        async def insert_block_ref(self, *a, **k):
            raise RuntimeError("disk full")
        async def prune_block_refs(self, *a):
            raise RuntimeError("x")
    check("a failed write gives no ID and no exception",
          await blockref.RefIssuer(Broken()).issue("limit", "login", "192.0.2.9") is None)

    # row cap and age cap
    for i in range(60):
        await server.db.insert_block_ref(f"CAP{i:05d}", "limit", "t", None, f"cap{i}", None, None, 25)
    check("the table never holds more than the row cap", await server.db.count_block_refs() <= 25)
    await server.db.conn.execute(
        "INSERT INTO block_refs (ref, kind, limiter, subject, hits, created_at, last_seen) "
        "VALUES ('OLDREF22', 'limit', 'login', 'old', 1, datetime('now', '-8 days'), datetime('now', '-8 days'))")
    await server.db.conn.commit()
    check("a row older than the age cap is not returned even before the sweep removed it",
          await server.db.get_block_ref("OLDREF22", blockref.MAX_AGE_DAYS) is None
          and len(await rows("ref = 'OLDREF22'")) == 1)
    await server.db.sweep_auto_bans()
    check("the sweep removes it", not await rows("ref = 'OLDREF22'"))
    server._blocked_ips.pop(ip, None)


async def pages_unit():
    peers = {"manual permanent": ("203.0.113.61", None), "manual timed": ("203.0.113.62", "2099-01-01 00:00:00")}
    for peer, exp in peers.values():
        await server.db.block_ip(peer, reason=REASON, blocked_by=None, expires_at=exp)
        server._blocked_ips[peer] = exp
    await server.db.block_ip("45.9.9.63", reason="failed sign-ins", expires_at="2099-01-01 00:00:00", source="auto", kind="login")
    server._blocked_ips["45.9.9.63"] = "2099-01-01 00:00:00"
    server._auto_blocked_ips.add("45.9.9.63")
    server._probe_blocks["45.9.9.64"] = server.monotonic() + 600
    server._refs.reset()
    out = {}
    for name, peer in (("manual permanent", "203.0.113.61"), ("manual timed", "203.0.113.62"),
                       ("sign-in ban", "45.9.9.63"), ("scanner block", "45.9.9.64")):
        r = await through(peer, "/proxy/abc/x", HTML)
        out[name] = r
    check("each kind of block answers 403", {r.status for r in out.values()} == {403})
    bodies = {strip_ref(r.text) for r in out.values()}
    check("the page is byte-identical for all four kinds once the ID is removed", len(bodies) == 1, str(len(bodies)))
    heads = {tuple(sorted((k, strip_ref(v)) for k, v in r.headers.items() if k.lower() not in ("content-length",))) for r in out.values()}
    check("the headers are identical too", len(heads) == 1, str(heads))
    page = next(iter(out.values())).text
    low = page.lower()
    check("the page names no reason, address, rule, expiry or duration",
          not any(x in low for x in (REASON, "203.0.113", "45.9.9", "failed sign-in", "scanner", "probe", "permanent", "expire", "until", "minutes", "hours", "login", "rule")), page)
    check("the page says what to do in one sentence", "Give this reference to an administrator." in page)
    check("no Retry-After on a 403, no script, no link", "Retry-After" not in next(iter(out.values())).headers
          and "<script" not in low and "<a " not in low)
    refs = {re.search(r"[A-Z2-9]{4}-[A-Z2-9]{4}", r.text).group(0) for r in out.values()}
    check("each blocked address has its own ID", len(refs) == 4)
    j = await through("203.0.113.61", "/api/me", {"Accept": "application/json"})
    body = json.loads(j.text)
    check("an API client gets JSON with the old error text and a ref, nothing else",
          j.status == 403 and set(body) == {"error", "ref"} and body["error"] == "Access denied", str(body))
    j2 = await through("203.0.113.61", "/api/me", {"Accept": "text/html"})
    check("an /api path gets JSON even when the Accept asks for HTML", j2.content_type == "application/json")
    j3 = await through("203.0.113.61", "/dashboard", {"Accept": "*/*"})
    check("a plain client (Accept */*) keeps getting JSON", j3.content_type == "application/json")
    for ip in ("203.0.113.61", "203.0.113.62", "45.9.9.63"):
        server._blocked_ips.pop(ip, None)
        server._auto_blocked_ips.discard(ip)
    server._probe_blocks.pop("45.9.9.64", None)
    r = await through("203.0.113.61")
    check("(control) an address that is not blocked is let through untouched", r.status == 200 and r.text == "fine")

    # rate limiter pages and JSON
    server._refs.reset()
    server._proxy_buckets.clear()
    last = None
    for _ in range(40):
        last = await server.proxy_limit_middleware(req("45.9.9.9", "/proxy/x", HTML), ok_handler)
    check("the logged-out proxy limit's 429 page shows an ID and the one sentence",
          last.status == 429 and "Give this reference to an administrator." in last.text
          and re.search(r"[A-Z2-9]{4}-[A-Z2-9]{4}", last.text) and last.headers.get("Retry-After"), str(last.status))
    check("the 429 page does not say the address or the limit", "45.9.9.9" not in last.text and "30" not in re.sub(r"[A-Z2-9]{4}-[A-Z2-9]{4}", "", last.text.split("</style>")[1]))
    server._proxy_buckets.clear()
    for _ in range(40):
        last = await server.proxy_limit_middleware(req("45.9.9.9", "/proxy/x"), ok_handler)
    jb = json.loads(last.text)
    check("an API-style 429 keeps its text and adds ref", last.status == 429 and jb["error"] == "Too many requests, retry shortly" and "ref" in jb)
    got = await rows("ref = ?", (blockref.normalize(jb["ref"]),))
    check("the ref finds the limiter event", got and got[0]["kind"] == "limit" and got[0]["limiter"] == "logged_out_proxy"
          and got[0]["subject"] == "45.9.9.9", str(got))
    server._proxy_buckets.clear()


def source_guard_unit():
    text = (Path(SRC) / "server.py").read_text()
    found = [(i + 1, l.strip()) for i, l in enumerate(text.splitlines())
             if re.search(r"status\s*=\s*429|Response\(429|json_response\([^)]*429", l) and "response_status" not in l]
    check("no 429 is built by hand in server.py (every one goes through _limited; the lookup's own limit too)",
          not found, str(found))
    check("no handler calls check_rate_limit without answering through _limited",
          len(re.findall(r"if not check_rate_limit\(client_ip\):\n\s+(?:logger\.warning\([^\n]*\)\n\s+)?return await _limited", text))
          == len(re.findall(r"if not check_rate_limit\(", text)))
    mid = text.split("async def security_headers_middleware")[1].split("HSTS")[0]
    check("the block answer goes through _blocked_answer", '"Access denied"}, status=403)' not in mid and "_blocked_answer" in mid)


async def e2e_unit():
    ids = {}
    for name, role in (("sa", "superadmin"), ("member", None)):
        u = await create_user(name, PW[name], is_admin=bool(role))
        if role:
            await server.db.set_user_role(u["id"], role)
        ids[name] = u["id"]
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()

    def client():
        return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def login(sess, name):
        async with sess.post(base + "/login", json={"username": name, "password": PW[name]}) as r:
            return r.status

    target = "203.0.113.90"
    async with client() as sa, client() as mem, client() as anon:
        check("administrator signs in", await login(sa, "sa") == 200)
        check("member signs in", await login(mem, "member") == 200)
        async with sa.post(base + "/api/admin/blocked-ips", json={"ip_address": target, "reason": REASON}) as r:
            check("manual block made", r.status == 201)
        server._refs.reset()
        blocked = await through(target, "/proxy/abc/", HTML)
        ref = re.search(r"[A-Z2-9]{4}-[A-Z2-9]{4}", blocked.text).group(0)

        async with sa.get(base + f"/api/admin/blocks/ref/{ref}") as r:
            data = await r.json()
            check("the administrator finds the block by its ID", r.status == 200 and data["kind"] == "block"
                  and data["address"] == target and data["reason"] == REASON and data["active"] is True
                  and data["can_unblock"] is True and data["block"]["ip_address"] == target and data["ref"] == ref, str(data))
        async with sa.get(base + f"/api/admin/blocks/ref/{ref.lower().replace('-', ' ')}") as r:
            check("the ID is accepted in lower case and with a space", r.status == 200)
        async with mem.get(base + f"/api/admin/blocks/ref/{ref}", headers={"Accept": "application/json"}) as r:
            body = await r.text()
            check("a member cannot use the lookup (403, no event in the answer)", r.status == 403 and target not in body and REASON not in body, f"{r.status} {body}")
        async with anon.get(base + f"/api/admin/blocks/ref/{ref}", headers={"Accept": "application/json"}) as r:
            check("a signed-out client gets 401", r.status == 401)
        async with mem.get(base + "/api/admin/blocks/ref/ZZZZ-ZZZZ", headers={"Accept": "application/json"}) as r:
            check("a member gets the same 403 for an unknown ID (the ID is never read)", r.status == 403)
        outs = []
        for odd in ("ZZZZ-ZZZZ", "nonsense", "ABCD-234O", "A" * 60):
            async with sa.get(base + f"/api/admin/blocks/ref/{odd}") as r:
                outs.append((r.status, await r.read(), r.headers.get("Content-Type")))
        check("an unknown, malformed or oversized ID gets one 404 with one body", len({o for o in outs}) == 1 and outs[0][0] == 404, str(outs))
        await server.db.conn.execute(
            "INSERT INTO block_refs (ref, kind, limiter, subject, hits, created_at, last_seen) "
            "VALUES ('EXPIRED2', 'block', 'ip_block', '203.0.113.91', 1, datetime('now', '-9 days'), datetime('now', '-9 days'))")
        await server.db.conn.commit()
        async with sa.get(base + "/api/admin/blocks/ref/EXPIRED2") as r:
            check("an expired ID gets the same 404 and body", (r.status, await r.read(), r.headers.get("Content-Type")) == outs[0])

        # unblock from the lookup uses the existing route and is audited
        async with sa.delete(base + f"/api/admin/blocked-ips/{data['address']}?ref={ref}") as r:
            check("the one-click unblock is the existing route", r.status == 200, str(r.status))
        await secevents.log.flush()
        cur = await server.db.conn.execute("SELECT * FROM security_events WHERE event = 'ip_unblocked' ORDER BY id DESC LIMIT 1")
        ev = dict(await cur.fetchone())
        check("the unblock is a security event with the administrator and the reference",
              ev["user_id"] == ids["sa"] and json.loads(ev["details"]).get("ref") == blockref.normalize(ref)
              and json.loads(ev["details"]).get("target_ip") == target, str(ev))
        cur = await server.db.conn.execute(
            "SELECT * FROM activity_log WHERE user_id = ? AND action = 'ip_unblock' ORDER BY id DESC LIMIT 1", (ids["sa"],))
        act = await cur.fetchone()
        check("the unblock is an activity entry with the address and the reference",
              act is not None and target in act["detail"] and ref in act["detail"], str(dict(act) if act else None))
        async with sa.get(base + f"/api/admin/blocks/ref/{ref}") as r:
            d2 = await r.json()
            check("the lookup now shows the block as no longer active", r.status == 200 and d2["active"] is False and d2["can_unblock"] is False, str(d2))
        r = await through(target)
        check("the unblocked address is let through", r.status == 200)
        async with sa.delete(base + f"/api/admin/blocked-ips/{target}?ref=not-an-id") as r:
            check("(control) a malformed ref in the query changes nothing about the answer", r.status == 404)

        # a rate-limited sign-in: the ID finds the limiter event
        Config.RATE_LIMIT_REQUESTS = 3
        server.rate_limits.clear()
        server._refs.reset()
        stat = []
        async with client() as lim:
            for _ in range(5):
                async with lim.post(base + "/login", json={"username": "nobody", "password": "x" * 12},
                                    headers={"Accept": "application/json"}) as r:
                    stat.append((r.status, await r.json(content_type=None)))
        last = stat[-1]
        check("a rate-limited sign-in is 429 with its old text and a ref",
              last[0] == 429 and last[1]["error"] == "Rate limit exceeded" and "ref" in last[1], str(stat))
        Config.RATE_LIMIT_REQUESTS = 100000
        server.rate_limits.clear()
        async with sa.get(base + f"/api/admin/blocks/ref/{last[1]['ref']}") as r:
            d3 = await r.json()
            check("the ID finds the limiter event: limiter login, address, not unblockable",
                  r.status == 200 and d3["kind"] == "limit" and d3["limiter"] == "login" and d3["address"] == "127.0.0.1"
                  and d3["can_unblock"] is False and d3["active"] is None, str(d3))
        # the lookup is rate limited
        codes = []
        for _ in range(blockref.LOOKUP_PER_MINUTE + 3):
            async with sa.get(base + "/api/admin/blocks/ref/ZZZZ-ZZZZ") as r:
                codes.append(r.status)
        check("the lookup is rate limited per administrator", 429 in codes and codes[-1] == 429, str(codes))
        server._ref_lookup_times.clear()
    await srv.close()


async def migration_unit():
    cur = await server.db.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")
    before = [tuple(r) for r in await cur.fetchall()]
    await server.db._run_migrations()
    cur = await server.db.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")
    check("the migration is idempotent", before == [tuple(r) for r in await cur.fetchall()])
    cur = await server.db.conn.execute("PRAGMA foreign_key_list(block_refs)")
    check("block_refs has no foreign key (rows outlive accounts) and a unique ID", not await cur.fetchall()
          and any("UNIQUE" in (s or "") for _, s in before if _ == "block_refs"))
    src = (Path(SRC) / "database.py").read_text()
    m = re.search(r'CREATE TABLE IF NOT EXISTS block_refs.*?\)""",', src, re.S)
    check("the new table is created with IF NOT EXISTS only, no data move", bool(m) and "INSERT" not in m.group(0))


async def main_async(tmp):
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    secevents.log.bind(server.db)
    for unit in (bounds_unit, pages_unit, migration_unit, e2e_unit):
        try:
            await unit()
        except Exception as e:
            import traceback
            traceback.print_exc()
            check(f"{unit.__name__} ran to the end", False, f"{type(e).__name__}: {e}")
    await server.db.close()


def main():
    pure_unit()
    source_guard_unit()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            asyncio.run(main_async(tmp))
        except BaseException:
            os._exit(1)
    print(f"\n{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
