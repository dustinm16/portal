"""Second factor on POST /api/token and the shared wrong-code throttle."""

import json
import time

SETUP = r'''
import asyncio, json, sys
import pyotp
from database import db
from auth import create_user, generate_totp_secret, generate_backup_codes

async def main():
    await db.connect()
    out = {}
    for name, twofa in (("t_plain", False), ("t_2fa", True), ("t_thr", True), ("t_other", True), ("t_blank", True), ("t_audit", True), ("t_audit2", True)):
        user = await create_user(name, "Pw-" + name + "-12345!", is_admin=False)
        rec = {"id": user["id"], "password": "Pw-" + name + "-12345!"}
        if twofa:
            secret = generate_totp_secret()
            await db.set_user_totp_secret(user["id"], secret)
            backup = generate_backup_codes(3)
            await db.enable_user_totp(user["id"], backup)
            rec["secret"] = secret
            rec["backup"] = backup
        out[name] = rec
    await db.conn.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

LIMITER = r'''
import json
import server
from server import _totp_begin_attempt, _totp_end_attempt

res = {}
uid = 987001
t = 1000.0
# 5 wrong codes from A are allowed, the 6th trips the pair cooldown.
res["a_five_allowed"] = all(_totp_begin_attempt(uid, "10.0.0.1", t + i)[0] for i in range(5))
ok, retry, _ = _totp_begin_attempt(uid, "10.0.0.1", t + 6)
res["a_sixth_blocked"] = (not ok) and 290 <= retry <= 301
# A different IP for the same user is unaffected while A cools down.
ok_b, _, tok = _totp_begin_attempt(uid, "10.0.0.2", t + 7)
res["b_allowed_during_a_cooldown"] = ok_b
_totp_end_attempt(uid, "10.0.0.2", tok)
# Another user from the same IP is unaffected.
res["other_user_allowed"] = _totp_begin_attempt(987002, "10.0.0.1", t + 8)[0]
# A is allowed again after the cooldown.
res["a_allowed_after_cooldown"] = _totp_begin_attempt(uid, "10.0.0.1", t + 400)[0]
# Per-user ceiling across IPs: 20 wrong codes in 15 minutes block every address.
uid2 = 987003
n = 0
for i in range(40):
    ip = "10.1.%d.%d" % (i // 4, i % 4)
    for j in range(4):
        if _totp_begin_attempt(uid2, ip, 5000.0 + i * 5 + j)[0]:
            n += 1
        if n >= 20:
            break
    if n >= 20:
        break
res["user_ceiling_reached"] = n == 20
ok, retry, _ = _totp_begin_attempt(uid2, "10.9.9.9", 5000.0 + 300)
res["user_ceiling_blocks_new_ip"] = not ok and retry > 0
# Sustained rotation: one attempt a second for an hour, a new address every 5
# attempts. The per-user ceiling must hold at 20 per 15 minutes (80 per hour),
# not restart with every cooldown.
uid3 = 987004
allowed = 0
for i in range(3600):
    ip = "10.3.%d.%d" % ((i // 5) // 250, (i // 5) % 250)
    if _totp_begin_attempt(uid3, ip, 20000.0 + i)[0]:
        allowed += 1
res["user_hourly_bound"] = allowed <= 80
res["user_hourly_count"] = allowed
# A per-user trip must end exactly when Retry-After says, and must not re-arm
# for a correct code arriving from a fresh address at that moment.
uid4 = 987005
for i in range(20):
    _totp_begin_attempt(uid4, "10.4.0.%d" % (i // 5), 40000.0 + i)
ok, retry, _ = _totp_begin_attempt(uid4, "10.4.9.9", 40020.0)
res["user_trip_blocked"] = (not ok) and retry > 0
ok_early, _, _ = _totp_begin_attempt(uid4, "10.4.9.8", 40020.0 + retry - 5)
res["user_trip_blocks_until_retry_after"] = not ok_early
ok_at, _, tok = _totp_begin_attempt(uid4, "10.4.9.7", 40020.0 + retry)
res["user_trip_accepts_at_retry_after"] = ok_at
if ok_at:
    _totp_end_attempt(uid4, "10.4.9.7", tok)
    res["user_trip_no_rearm"] = _totp_begin_attempt(uid4, "10.4.9.6", 40020.0 + retry + 1)[0]
else:
    res["user_trip_no_rearm"] = False
# Table stays bounded.
for i in range(server._TOTP_TABLE_MAX + 500):
    _totp_begin_attempt(1_000_000 + i, "10.2.0.1", 9000.0)
res["bounded"] = len(server._totp_pair_state) <= server._TOTP_TABLE_MAX and len(server._totp_user_state) <= server._TOTP_TABLE_MAX
# Eviction must not remove entries that are still in cooldown.
saved_max = server._TOTP_TABLE_MAX
server._TOTP_TABLE_MAX = 50
server._totp_pair_state.clear()
server._totp_user_state.clear()
T = 100000.0
# 10 oldest pairs go into cooldown (6 attempts each), then 40 pairs with one attempt.
for u in range(10):
    for k in range(6):
        _totp_begin_attempt(2_000_000 + u, "10.5.0.1", T + k)
for u in range(40):
    _totp_begin_attempt(2_000_100 + u, "10.5.0.1", T + 10)
# 30 more new pairs force 30 evictions; none may be a cooldown entry.
for u in range(30):
    _totp_begin_attempt(2_000_200 + u, "10.5.0.1", T + 20)
res["evict_table_capped"] = len(server._totp_pair_state) <= 50
cool = [server._totp_pair_state.get((2_000_000 + u, "10.5.0.1")) for u in range(10)]
res["evict_keeps_cooldowns"] = all(e is not None and e["until"] > T + 20 for e in cool)
ok, retry, _ = _totp_begin_attempt(2_000_000, "10.5.0.1", T + 30)
res["evict_cooldown_still_blocks"] = (not ok) and retry > 0
# Table full of cooldowns only: a new pair is refused, nothing is evicted.
server._totp_pair_state.clear()
server._totp_user_state.clear()
for u in range(50):
    for k in range(6):
        _totp_begin_attempt(2_001_000 + u, "10.6.0.1", T + k)
before = list(server._totp_pair_state.keys())
ok, retry, tok = _totp_begin_attempt(2_002_000, "10.6.0.1", T + 40)
res["full_cooldowns_refuse_new"] = (not ok) and tok is None and 0 < retry <= 301
res["full_cooldowns_no_eviction"] = list(server._totp_pair_state.keys()) == before
# The refusal ends once a cooldown has expired.
ok, _, _ = _totp_begin_attempt(2_002_000, "10.6.0.1", T + 400)
res["full_cooldowns_recover"] = ok
server._TOTP_TABLE_MAX = saved_max
print("RESULT " + json.dumps(res))
'''

AUDIT = r'''
import asyncio, json, sys
from database import db
import server
from server import verify_second_factor

async def main():
    await db.connect()
    user = await db.get_user_by_id(__UID__)
    res = {}
    results = []
    for i in range(__N__):
        r, _ = await verify_second_factor(user, "000000", "10.7.%d.1" % (i // 5))
        results.append(r)
    res["results"] = results
    rows = await db.get_recent_activity(limit=50, user_id=user["id"])
    res["entries"] = [r for r in rows if r.get("action") == "2fa_throttled"]
    await db.conn.close()
    print("RESULT " + json.dumps(res))

asyncio.run(main())
'''


def _parse(output):
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    raise RuntimeError("no RESULT line in: " + output[-500:])


def _wrong_code(secret):
    """A 6-digit code that is not valid in the accepted time window."""
    import pyotp
    totp = pyotp.TOTP(secret)
    now = time.time()
    valid = {totp.at(now + d) for d in (-60, -30, 0, 30, 60)}
    for n in range(100000, 100100):
        if str(n) not in valid:
            return str(n)


async def run(ctx):
    import pyotp

    rc, out = await ctx.run_py(SETUP)
    if rc != 0:
        ctx.ok("totp: create test users", False, out[-400:])
        return
    users = _parse(out)
    ctx.ok("totp: create test users", True)

    url = ctx.base_url + "/api/token"

    async def post(session, name, **extra):
        body = {"username": name, "password": users[name]["password"]}
        body.update(extra)
        async with session.post(url, json=body) as resp:
            try:
                data = await resp.json()
            except Exception:
                data = {}
            return resp.status, data, resp.headers

    async with ctx.http() as s:
        # User without 2FA: password only still gets a token.
        st, data, _ = await post(s, "t_plain")
        ctx.ok("totp: user without 2FA gets a token with password only",
               st == 200 and bool(data.get("token")), "status=%s" % st)

        # 2FA user, password only: refused, with a hint that a code is needed.
        st, data, _ = await post(s, "t_2fa")
        ctx.ok("totp: password only is refused for a 2FA user",
               st == 401 and not data.get("token") and data.get("totp_required") is True,
               "status=%s body=%s" % (st, data))

        # Valid code: token that works on /api/me.
        code = pyotp.TOTP(users["t_2fa"]["secret"]).now()
        st, data, _ = await post(s, "t_2fa", totp_code=code)
        token = data.get("token")
        ctx.ok("totp: password + valid code returns a token", st == 200 and bool(token), "status=%s" % st)
        if token:
            async with s.get(ctx.base_url + "/api/me", headers={"Authorization": "Bearer " + token}) as resp:
                me = await resp.json() if resp.status == 200 else {}
                ctx.ok("totp: issued token works on /api/me",
                       resp.status == 200 and "t_2fa" in json.dumps(me), "status=%s" % resp.status)

        # Backup code works once.
        backup = users["t_2fa"]["backup"][0]
        st1, d1, _ = await post(s, "t_2fa", totp_code=backup)
        st2, d2, _ = await post(s, "t_2fa", totp_code=backup)
        ctx.ok("totp: backup code is accepted exactly once",
               st1 == 200 and bool(d1.get("token")) and st2 == 401 and not d2.get("token"),
               "first=%s second=%s" % (st1, st2))

        # Wrong password + any code: the same generic 401 as a wrong password.
        async with s.post(url, json={"username": "t_2fa", "password": "wrong-password",
                                     "totp_code": pyotp.TOTP(users["t_2fa"]["secret"]).now()}) as r1:
            b1 = await r1.json()
            s1 = r1.status
        async with s.post(url, json={"username": "no_such_user_x", "password": "wrong-password"}) as r2:
            b2 = await r2.json()
            s2 = r2.status
        ctx.ok("totp: wrong password + code gives the generic 401",
               s1 == 401 and s2 == 401 and b1 == b2 and "totp_required" not in b1,
               "%s %s vs %s %s" % (s1, b1, s2, b2))

        # Wrong codes: five answered 401, the sixth is throttled with Retry-After.
        bad = _wrong_code(users["t_thr"]["secret"])
        statuses = []
        last_headers = None
        for _ in range(6):
            st, data, headers = await post(s, "t_thr", totp_code=bad)
            statuses.append(st)
            last_headers = headers
        retry = last_headers.get("Retry-After") if last_headers else None
        ctx.ok("totp: six wrong codes produce 429 with Retry-After",
               statuses == [401] * 5 + [429] and bool(retry) and retry.isdigit() and int(retry) > 0,
               "statuses=%s retry-after=%s" % (statuses, retry))

        # Throttle is shared with the web login 2FA step, even for a correct code.
        code = pyotp.TOTP(users["t_thr"]["secret"]).now()
        resp = await ctx.login(s, "t_thr", users["t_thr"]["password"], totp_code=code)
        try:
            web_body = await resp.json()
        except Exception:
            web_body = {}
        web_retry = resp.headers.get("Retry-After")
        ctx.ok("totp: web login shares the cooldown",
               resp.status == 429 and "Too many incorrect codes" in str(web_body.get("error", ""))
               and bool(web_retry) and web_retry.isdigit(),
               "status=%s body=%s retry-after=%s" % (resp.status, web_body, web_retry))

        # A blank code is "missing" on both endpoints and is never counted as a wrong attempt.
        blank_status = []
        for _ in range(7):
            resp = await ctx.login(s, "t_blank", users["t_blank"]["password"], totp_code="   ")
            try:
                blank_body = await resp.json()
            except Exception:
                blank_body = {}
            blank_status.append((resp.status, blank_body.get("status")))
        st, data, _ = await post(s, "t_blank", totp_code="   ")
        ctx.ok("totp: blank code is treated as missing on both endpoints",
               blank_status == [(200, "2fa_required")] * 7 and st == 401 and data.get("totp_required") is True,
               "login=%s token=%s %s" % (blank_status[-1], st, data))
        code = pyotp.TOTP(users["t_blank"]["secret"]).now()
        st, data, _ = await post(s, "t_blank", totp_code=code)
        ctx.ok("totp: blank codes did not count toward the throttle",
               st == 200 and bool(data.get("token")), "status=%s" % st)

        # Cooldown is per user: another 2FA user and a non-2FA user are unaffected.
        code = pyotp.TOTP(users["t_other"]["secret"]).now()
        st, data, _ = await post(s, "t_other", totp_code=code)
        ctx.ok("totp: another user is not affected by the cooldown", st == 200 and bool(data.get("token")), "status=%s" % st)
        st, data, _ = await post(s, "t_plain")
        ctx.ok("totp: user without 2FA is never throttled", st == 200 and bool(data.get("token")), "status=%s" % st)

        # Password login for the throttled user is still a plain 401 for a wrong password (no 429 leak).
        async with s.post(url, json={"username": "t_thr", "password": "wrong-password",
                                     "totp_code": bad}) as resp:
            ctx.ok("totp: wrong password is not answered with the throttle",
                   resp.status == 401, "status=%s" % resp.status)

    # The in-app API docs page carries the same throttle description as docs/API.md.
    async with ctx.http() as s:
        async with s.get(ctx.base_url + "/api-docs") as resp:
            page = await resp.text() if resp.status == 200 else ""
    ctx.ok("totp: api-docs page describes the cooldown and the activity entry",
           "Correct codes are also refused during a cooldown" in page
           and "activity feed" in page and "20 wrong codes in 15 minutes" in page,
           "page_len=%s" % len(page))

    # Limiter behaviour for several addresses and the per-user ceiling.
    rc, out = await ctx.run_py(LIMITER)
    if rc != 0:
        ctx.ok("totp: limiter checks", False, out[-400:])
        return
    res = _parse(out)
    for key, label in (
        ("a_five_allowed", "five attempts from one address are allowed"),
        ("a_sixth_blocked", "sixth attempt from that address starts a cooldown"),
        ("b_allowed_during_a_cooldown", "another address of the same user is allowed during the cooldown"),
        ("other_user_allowed", "another user from the same address is allowed"),
        ("a_allowed_after_cooldown", "address is allowed again after the cooldown"),
        ("user_ceiling_reached", "per-user ceiling is 20 attempts across addresses"),
        ("user_ceiling_blocks_new_ip", "per-user ceiling blocks a new address"),
        ("user_hourly_bound", "per-user ceiling holds over an hour of rotating addresses (at most 80 attempts)"),
        ("user_trip_blocked", "per-user trip refuses with a Retry-After"),
        ("user_trip_blocks_until_retry_after", "per-user trip refuses until Retry-After has elapsed"),
        ("user_trip_accepts_at_retry_after", "a code from a fresh address is accepted at exactly Retry-After"),
        ("user_trip_no_rearm", "the per-user cooldown does not re-arm after Retry-After"),
        ("bounded", "state tables stay bounded"),
        ("evict_table_capped", "a full table stays at its cap"),
        ("evict_keeps_cooldowns", "eviction keeps entries that are in cooldown"),
        ("evict_cooldown_still_blocks", "an entry kept through eviction still refuses"),
        ("full_cooldowns_refuse_new", "a table full of cooldowns refuses a new key"),
        ("full_cooldowns_no_eviction", "a refused new key evicts nothing"),
        ("full_cooldowns_recover", "a new key is accepted again once a cooldown ends"),
    ):
        ctx.ok("totp: limiter: " + label, bool(res.get(key)),
               "allowed=%s" % res.get("user_hourly_count") if key == "user_hourly_bound" else "")

    # A per-user trip leaves exactly one activity entry for the account.
    # 23 wrong codes from 5 addresses: 20 are answered "invalid", the rest are refused.
    rc, out = await ctx.run_py(AUDIT.replace("__UID__", str(users["t_audit"]["id"])).replace("__N__", "23"))
    if rc != 0:
        ctx.ok("totp: per-user trip activity log", False, out[-400:])
        return
    audit = _parse(out)
    results = audit.get("results", [])
    entries = audit.get("entries", [])
    ctx.ok("totp: per-user trip writes one activity entry for the account",
           results.count("invalid") == 20 and results.count("throttled") == 3 and len(entries) == 1,
           "invalid=%s throttled=%s entries=%s" % (results.count("invalid"), results.count("throttled"), len(entries)))
    ctx.ok("totp: the activity entry names the account and carries no code",
           bool(entries) and entries[0].get("user_id") == users["t_audit"]["id"]
           and "000000" not in json.dumps(entries[0]),
           json.dumps(entries[:1]))

    # Exactly 20 wrong codes and nothing more: the request that spends the last
    # of the budget is recorded, with the address it came from, before any
    # other request trips the limit.
    rc, out = await ctx.run_py(AUDIT.replace("__UID__", str(users["t_audit2"]["id"])).replace("__N__", "20"))
    if rc != 0:
        ctx.ok("totp: per-user budget spent without a trip is logged", False, out[-400:])
        return
    audit = _parse(out)
    results = audit.get("results", [])
    entries = audit.get("entries", [])
    ctx.ok("totp: twenty wrong codes and no more write one activity entry",
           results.count("invalid") == 20 and len(entries) == 1,
           "invalid=%s entries=%s" % (results.count("invalid"), len(entries)))
    ctx.ok("totp: that entry carries the address that spent the last attempt",
           bool(entries) and entries[0].get("ip_address") == "10.7.3.1",
           json.dumps(entries[:1]))
