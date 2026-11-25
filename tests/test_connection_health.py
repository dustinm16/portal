"""Connection health checks (connection_health.py), opt-in and SSRF safe.

Proves, with a temporary database, loopback listeners and a fake probe where a real one is not the
point: the target of each connection type is what a real attempt dials; a probe goes through the host
policy (a name that resolves to 127.0.0.1, a private, link-local or CGNAT address is never dialled
and reads "unknown"); a redirect is not followed; no cookie or credential is sent; a 5xx and a closed
port are failures; hysteresis (down after 3 failures, up after 2 successes, unknown to up silent);
only transitions are stored and pruned; one alert per transition, none for a never-up connection,
none for the third-party text with a name or host; with the feature off no probe is made; only pinned
or recently opened connections of somebody who still has access are probed; the cap, the dedupe and
the in-flight guard; a probe that raises changes nothing and the loop goes on; the task stops at
shutdown; a staged instance probes nothing but the loopback ports its harness names; and the route
GET /api/connections/status (not swallowed by /{id}) shows owner and grantee the same shape and no
host, address or error text.

Run: venv/bin/python tests/test_connection_health.py
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402
import outbound_guard  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
import alerts  # noqa: E402
import connection_health as ch  # noqa: E402
import host_check  # noqa: E402
import server  # noqa: E402

TYPES = server.CONNECTION_TYPES


def conn(ctype="ssh", host="example.org", port=22, config=None, cid=1):
    return {"id": cid, "type": ctype, "host": host, "port": port, "config": config or {}, "name": f"c{cid}"}


def unit_checks():
    t = ch.target_of(conn("ssh", "box.example", 2222), TYPES)
    check("ssh: a TCP target on the connection's own host and port", t and (t.kind, t.host, t.port) == ("tcp", "box.example", 2222))
    t = ch.target_of(conn("ssh", "box.example", None), TYPES)
    check("ssh: no port means the type's default (22)", t and t.port == 22)
    check("vnc, rdp (vnc plugin), tcp_tunnel, secure_tunnel and a database type are TCP",
          all(ch.target_of(conn(x, "h.example", 5000), TYPES).kind == "tcp" for x in ("vnc", "rdp", "tcp_tunnel", "secure_tunnel", "redis")))
    check("not probed: vpn_tunnel, github, mediamtx, spice, proxmox",
          all(ch.target_of(conn(x, "h.example", 5000), TYPES) is None for x in ("vpn_tunnel", "github", "mediamtx", "spice", "proxmox")))
    check("no host, or an unusable port, is not probed",
          ch.target_of(conn("ssh", "", 22), TYPES) is None and ch.target_of(conn("ssh", "h.example", 99999), TYPES) is None)
    t = ch.target_of(conn("http", "web.example", 8080), TYPES)
    check("http: origin of host and port, path /, plain http", t and t.url == "http://web.example:8080/" and t.scheme == "http", str(t))
    t = ch.target_of(conn("https", "web.example", 443), TYPES)
    check("https type: https, default port left out of the URL", t and t.url == "https://web.example/", str(t))
    t = ch.target_of(conn("http", "web.example", 443), TYPES)
    check("port 443 on a plain http type is https (the proxy's rule)", t and t.scheme == "https")
    check("the scheme rule is the proxy's own helper", ch.proxy_scheme("portainer", 9443) == "https" and ch.proxy_scheme("http", 80) == "http")
    t = ch.target_of(conn("http", "ignored.example", 80, {"target_url": "https://user:pw@app.example:9000/deep/path?q=1#f"}), TYPES)
    check("http: target_url is probed instead of the host, origin only: no user info, path or query",
          t and t.url == "https://app.example:9000/" and t.host == "app.example" and t.port == 9000, str(t))
    check("http: a target_url that is not http(s) is not probed",
          ch.target_of(conn("http", "x.example", 80, {"target_url": "ftp://x.example/"}), TYPES) is None)
    check("http: browser_mode has no fixed target and is not probed",
          ch.target_of(conn("http", "duckduckgo.com", 443, {"browser_mode": True}), TYPES) is None)
    check("http: verify_ssl follows the connection", ch.target_of(conn("https", "w.example", 443, {"verify_ssl": True}), TYPES).verify_ssl is True
          and ch.target_of(conn("https", "w.example", 443), TYPES).verify_ssl is False)
    check("a host that would break out of the URL is not probed",
          ch.target_of(conn("http", "evil.example/@127.0.0.1", 80), TYPES) is None)
    a, b = ch.target_of(conn("ssh", "Box.Example", 22), TYPES), ch.target_of(conn("ssh", "box.example", 22), TYPES)
    check("two connections to one target share a key", a.key == b.key)
    check("clamp_interval: default for junk, range kept", ch.clamp_interval("x") == 60 and ch.clamp_interval(30) == 60
          and ch.clamp_interval(120) == 120 and ch.clamp_interval(5000) == 60)
    check("stage ports parse", ch.parse_ports("9001, 9002,x,0,70000") == frozenset({9001, 9002}))

    # hysteresis
    st = ch.HealthState()
    K = ("tcp", "", "h", 1, False)
    ok, bad = ch.Result("ok", 5), ch.Result("fail")
    seq = []

    def step(r, t):
        tr = st.apply(1, K, r, float(t), "2030-01-01T00:00:%02dZ" % t)
        seq.append((st.entries[1].status, tr.alert if tr else None))
        return tr

    step(ok, 1)
    check("one success is not enough to be up", seq[-1] == ("unknown", None))
    tr = step(ok, 2)
    check("up after 2 successes in a row, and silent (never down before)", seq[-1] == ("up", None) and tr.new == "up")
    step(bad, 3), step(bad, 4)
    check("two failures do not make it down", seq[-1] == ("up", None))
    step(ok, 5)
    step(bad, 6), step(bad, 7)
    check("a success in between resets the failure count", seq[-1] == ("up", None))
    tr = step(bad, 8)
    check("down after 3 failures in a row, one alert", seq[-1] == ("down", "down") and tr.since.endswith("08Z"))
    step(bad, 9)
    check("more failures change nothing", seq[-1] == ("down", None))
    step(ok, 10)
    check("one success does not bring it up", seq[-1] == ("down", None))
    step(bad, 11), step(ok, 12)
    tr = step(ok, 13)
    check("up after 2 successes in a row, one alert", seq[-1] == ("up", "up"))
    check("view: up shows latency and since; unknown shows neither",
          st.view(1, 14.0, 300)["status"] == "up" and st.view(1, 14.0, 300)["latency_ms"] == 5
          and st.view(1, 9999.0, 300) == {"status": "unknown", "latency_ms": None, "since": None})
    # never up: down does not alert
    st2 = ch.HealthState()
    r = [st2.apply(2, K, bad, float(i), "t") for i in range(3)]
    check("a connection that was never up goes down without an alert", r[2].new == "down" and r[2].alert is None)
    # refused: unknown, no alert, counters reset
    st3 = ch.HealthState()
    st3.apply(3, K, ok, 1.0, "t"), st3.apply(3, K, ok, 2.0, "t")
    tr = st3.apply(3, K, ch.Result("refused"), 3.0, "t")
    check("a refused target turns an up connection to unknown, not down, no alert", tr.new == "unknown" and tr.alert is None)
    st3.apply(3, K, bad, 4.0, "t"), st3.apply(3, K, bad, 5.0, "t")
    check("a refusal reset the failure count", st3.entries[3].status == "unknown")
    tr = st3.apply(3, K, bad, 6.0, "t")
    check("up, refused, then three failures is down with an alert (it was up before)", tr.new == "down" and tr.alert == "down")
    # an error changes nothing
    st4 = ch.HealthState()
    st4.apply(4, K, ok, 1.0, "t"), st4.apply(4, K, ok, 2.0, "t")
    st4.apply(4, K, bad, 3.0, "t")
    st4.apply(4, K, ch.Result("error"), 4.0, "t")
    check("an error result changes neither status nor counters", st4.entries[4].status == "up" and st4.entries[4].fails == 1)
    # target changed
    tr = st4.apply(4, ("tcp", "", "other", 1, False), ok, 5.0, "t")
    check("a connection that now points elsewhere starts again from unknown", tr.new == "unknown" and st4.entries[4].known is None)


class Upstream:
    """A loopback HTTP listener that records what it was asked."""

    def __init__(self, status=200, headers=None, body=b"ok", head_status=None, delay=0):
        self.status, self.headers, self.body, self.head_status, self.delay = status, headers or {}, body, head_status, delay
        self.seen = []

    async def handler(self, request):
        self.seen.append((request.method, dict(request.headers)))
        if self.delay:
            await asyncio.sleep(self.delay)
        status = self.head_status if (request.method == "HEAD" and self.head_status) else self.status
        return web.Response(status=status, headers=self.headers, body=self.body if request.method != "HEAD" else None)

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self.handler)
        self.srv = TestServer(app, host="127.0.0.1")
        await self.srv.start_server()
        self.port = self.srv.port
        return self

    async def stop(self):
        await self.srv.close()


class Tcp:
    def __init__(self):
        self.accepted = 0

    async def start(self):
        async def on(r, w):
            self.accepted += 1
            w.close()
        self.server = await asyncio.start_server(on, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def probe_checks():
    http_t = lambda port, **kw: ch.Target("http", "127.0.0.1", port, "http", False, f"http://127.0.0.1:{port}/")
    tcp_t = lambda host, port: ch.Target("tcp", host, port)

    # ---- production rule: nothing loopback or private is dialled ----------------------------------
    tcp, up = await Tcp().start(), await Upstream().start()
    real_resolve = host_check._resolve

    async def to_loopback(host, port):
        return ["127.0.0.1"]

    host_check._resolve = to_loopback
    try:
        r = await ch.probe_target(tcp_t("looks-public.example", tcp.port))
        check("production: a name that resolves to 127.0.0.1 is refused (unknown), not down", r.kind == "refused", str(r))
        await asyncio.sleep(0.05)
        check("production: the loopback listener was never dialled", tcp.accepted == 0, str(tcp.accepted))
        t = ch.Target("http", "looks-public.example", up.port, "http", False, f"http://looks-public.example:{up.port}/")
        r = await ch.probe_target(t)
        check("production: the same for an http target; the upstream saw no request", r.kind == "refused" and not up.seen, f"{r} {up.seen}")
    finally:
        host_check._resolve = real_resolve
    for host in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.1.5", "169.254.169.254", "100.64.0.1", "::1", "0.0.0.0", "2130706433"):
        r = await ch.probe_target(tcp_t(host, tcp.port))
        check(f"production: {host} is refused by the policy", r.kind == "refused", str(r))
    for hostname, addr in (("a.example", "10.0.0.7"), ("b.example", "169.254.169.254"), ("c.example", "100.64.3.3")):
        async def fake(host, port, _a=addr):
            return [_a]
        host_check._resolve = fake
        try:
            r = await ch.probe_target(tcp_t(hostname, 80))
        finally:
            host_check._resolve = real_resolve
        check(f"production: a name resolving to {addr} is refused", r.kind == "refused", str(r))
    check("production: nothing local was dialled by any of them", tcp.accepted == 0 and not outbound_guard.refused, f"{tcp.accepted} {outbound_guard.refused}")

    async def mixed(host, port):
        return ["93.184.216.34", "127.0.0.1"]
    host_check._resolve = mixed
    try:
        r = await ch.probe_target(tcp_t("mixed.example", tcp.port))
    finally:
        host_check._resolve = real_resolve
    check("production: one refused address among the answers refuses the name", r.kind == "refused", str(r))

    async def unresolvable(host, port):
        raise OSError("no such name")
    host_check._resolve = unresolvable
    try:
        r = await ch.probe_target(tcp_t("nxdomain.example", 80))
    finally:
        host_check._resolve = real_resolve
    check("a name that does not resolve is a failure, like a real attempt's 'Connection failed'", r.kind == "fail", str(r))

    # ---- the stage allowance (LAN policy) works and still refuses metadata ---------------------------
    r = await ch.probe_target(tcp_t("127.0.0.1", tcp.port), lan=True)
    check("tcp probe: an open port is ok with a latency", r.kind == "ok" and isinstance(r.latency_ms, int), str(r))
    check("tcp probe: connected, sent nothing", tcp.accepted == 1)
    r = await ch.probe_target(tcp_t("169.254.169.254", 80), lan=True)
    check("the LAN policy still refuses the metadata address", r.kind == "refused", str(r))
    await tcp.stop()
    r = await ch.probe_target(tcp_t("127.0.0.1", tcp.port), lan=True)
    check("tcp probe: a closed port is a failure", r.kind == "fail", str(r))

    # ---- http ---------------------------------------------------------------------------------------
    r = await ch.probe_target(http_t(up.port), lan=True)
    method, hdrs = up.seen[0]
    check("http probe: HEAD of / answered 200 is ok, class 2xx", r.kind == "ok" and r.status_class == "2xx" and method == "HEAD", f"{r} {up.seen}")
    low = {k.lower() for k in hdrs}
    check("http probe: no cookie, authorization or other credential is sent",
          not ({"cookie", "authorization", "proxy-authorization", "x-api-key"} & low), str(sorted(low)))
    check("http probe: only a plain identifying user agent", hdrs.get("User-Agent") == "OpenRelayPortal-health", str(hdrs))
    await up.stop()

    other = await Upstream().start()
    redir = await Upstream(status=302, headers={"Location": f"http://127.0.0.1:{other.port}/internal"}).start()
    r = await ch.probe_target(http_t(redir.port), lan=True)
    check("http probe: a redirect is not followed (3xx counts as an answer)", r.kind == "ok" and r.status_class == "3xx", str(r))
    check("http probe: the redirect target never saw a request", not other.seen, str(other.seen))
    await redir.stop()
    meta = await Upstream(status=301, headers={"Location": "http://169.254.169.254/latest/meta-data/"}).start()
    r = await ch.probe_target(http_t(meta.port), lan=True)
    check("http probe: a redirect to a metadata address is not followed either", r.kind == "ok" and r.status_class == "3xx" and len(meta.seen) == 1, str(r))
    await meta.stop()
    await other.stop()

    boom = await Upstream(status=503).start()
    r = await ch.probe_target(http_t(boom.port), lan=True)
    check("http probe: 5xx is a failure", r.kind == "fail" and r.status_class == "5xx", str(r))
    await boom.stop()
    nf = await Upstream(status=404).start()
    r = await ch.probe_target(http_t(nf.port), lan=True)
    check("http probe: 404 is an answer (up)", r.kind == "ok" and r.status_class == "4xx", str(r))
    await nf.stop()
    big = await Upstream(status=200, head_status=405, body=b"x" * 500000).start()
    r = await ch.probe_target(http_t(big.port), lan=True)
    check("http probe: GET after a 405 to HEAD", r.kind == "ok" and [m for m, _ in big.seen] == ["HEAD", "GET"], f"{r} {big.seen}")
    await big.stop()
    slow = await Upstream(delay=3).start()
    old = ch.PROBE_TIMEOUT
    ch.PROBE_TIMEOUT = 0.5
    try:
        t0 = asyncio.get_running_loop().time()
        r = await ch.probe_target(http_t(slow.port), lan=True)
        took = asyncio.get_running_loop().time() - t0
    finally:
        ch.PROBE_TIMEOUT = old
    check("http probe: a slow upstream is a failure at the timeout", r.kind == "fail" and took < 2, f"{r} {took}")
    await slow.stop()
    r = await ch.probe_target(http_t(up.port), lan=True)
    check("http probe: a closed port is a failure", r.kind == "fail", str(r))

    # the pinned resolver answers only with the checked addresses
    res = ch._PinnedResolver({"a.example": ["93.184.216.34"]})
    got = await res.resolve("a.example", 80)
    check("pinned resolver: only the checked address", [e["host"] for e in got] == ["93.184.216.34"])
    try:
        await res.resolve("other.example", 80)
        check("pinned resolver: any other name is refused", False)
    except OSError:
        check("pinned resolver: any other name is refused", True)


class Fire:
    def __init__(self):
        self.sent = []

    async def __call__(self, event, payload):
        self.sent.append((event, payload))
        return 1


async def settle():
    for _ in range(6):
        await asyncio.sleep(0)
    while alerts._tasks:
        await asyncio.gather(*list(alerts._tasks), return_exceptions=True)


async def db_checks(env):
    db = env.db
    uid = env.uid
    now = datetime.now(timezone.utc)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    async def mk(owner, name, ctype="ssh", host="93.184.216.34", port=22, cfg="{}"):
        u = await db.create_user_connection(env.uid[owner], name, ctype, host, port, cfg)
        cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
        return u, cid

    pinned_u, pinned = await mk("owner", "pinned")
    recent_u, recent = await mk("owner", "recent")
    old_u, old = await mk("owner", "old")
    plain_u, plain = await mk("owner", "plain")
    shared_u, shared = await mk("owner", "shared-open")
    gone_u, gone = await mk("owner", "share-gone")
    legacy_u, legacy = await mk("owner", "legacy-pin")
    unpinned_u, unpinned = await mk("owner", "unpinned")
    await db.set_connection_prefs(uid["owner"], pinned, {"pinned": True}, owner=True)
    await db.note_connection_opened(uid["owner"], recent)
    await db.note_connection_opened(uid["owner"], old)
    await db.conn.execute("UPDATE connection_user_prefs SET last_opened_at = ? WHERE connection_id = ?",
                          (iso(now - timedelta(days=8)), old))
    await db.conn.execute("UPDATE user_connections SET is_pinned = 1 WHERE id IN (?, ?)", (legacy, unpinned))
    await db.set_connection_prefs(uid["owner"], unpinned, {"pinned": False}, owner=True)
    await db.add_connection_share(shared, uid["bob"], uid["owner"], "30d")
    await db.note_connection_opened(uid["bob"], shared)
    await db.add_connection_share(gone, uid["bob"], uid["owner"], "30d")
    await db.note_connection_opened(uid["bob"], gone)
    await db.conn.execute("UPDATE connection_shares SET expires_at = '2000-01-01T00:00:00Z' WHERE connection_id = ?", (gone,))
    await db.conn.commit()
    async def cands(limit):
        return await db.get_health_candidate_rows([c for c, _o in await db.list_health_candidate_refs(iso(now - timedelta(days=7)), limit)])

    rows = await cands(100)
    names = {r["name"] for r in rows if r["name"] in
             {"pinned", "recent", "old", "plain", "shared-open", "share-gone", "legacy-pin", "unpinned"}}
    check("candidates: pinned, opened this week, opened by a grantee with a live share, owner's older pin",
          {"pinned", "recent", "shared-open", "legacy-pin"} <= names, str(names))
    check("candidates: not an old open, a never-opened one, a share that ended, a pin the member turned off",
          not ({"old", "plain", "share-gone", "unpinned"} & names), str(names))
    check("candidates: each connection once", len(rows) == len({r["id"] for r in rows}))
    await db.remove_connection_share(shared, uid["bob"])
    rows = await cands(100)
    check("candidates: a revoked share no longer keeps the connection in (nobody with access opened it)",
          "shared-open" not in {r["name"] for r in rows})
    check("candidates: the limit holds", len(await cands(1)) == 1)

    # ---- the monitor ---------------------------------------------------------------------------------
    for k in (ch.SETTING_ENABLED, ch.SETTING_INTERVAL):
        await db.set_setting(k, "")
    for cid in (recent, old, plain, shared, gone, legacy, unpinned):
        await db.conn.execute("DELETE FROM connection_user_prefs WHERE connection_id = ?", (cid,))
    await db.conn.execute("UPDATE user_connections SET is_pinned = 0")
    await db.conn.commit()
    calls = []
    verdict = {"v": "ok"}

    async def fake_probe(target, *, lan=False):
        calls.append((target.key, lan))
        v = verdict["v"]
        if v == "raise":
            raise RuntimeError("boom")
        return ch.Result(v, 7 if v == "ok" else None)

    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    clock = {"t": 1000.0}
    alerts._clock = lambda: clock["t"]
    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=fake_probe, clock=lambda: clock["t"])
    n = await mon.run_round()
    check("feature off (the default): no probe at all", n == 0 and not calls)
    check("feature off: the status of every connection is the empty map", await mon.statuses_for(uid["owner"]) == {})

    await db.set_setting(ch.SETTING_ENABLED, "1")
    # one pinned connection, a twin on the same target, and one on another target
    twin_u, twin = await mk("owner", "twin", host="93.184.216.34", port=22)
    await db.set_connection_prefs(uid["owner"], twin, {"pinned": True}, owner=True)
    web_u, web_id = await mk("owner", "webby", "http", "web.example", 8080)
    await db.set_connection_prefs(uid["owner"], web_id, {"pinned": True}, owner=True)
    vpn_u, vpn = await mk("owner", "vpn", "vpn_tunnel", "93.184.216.34", 1080)
    await db.set_connection_prefs(uid["owner"], vpn, {"pinned": True}, owner=True)
    n = await mon.run_round()
    keys = [k for k, _ in calls]
    check("on: pinned connections are probed; twins on one target share one probe; an unprobeable type is not dialled",
          n == 2 and len(keys) == 2 and len(set(keys)) == 2, f"{n} {keys}")
    check("on: nothing in production mode uses the LAN policy", all(not lan for _, lan in calls))
    await mon.run_round()
    st = await mon.statuses_for(uid["owner"])
    check("two successes: up, with latency and since", st[pinned_u]["status"] == "up" and st[pinned_u]["latency_ms"] == 7 and st[pinned_u]["since"], str(st[pinned_u]))
    check("the unprobeable and the unfiled are unknown with nothing else",
          st[vpn_u] == {"status": "unknown", "latency_ms": None, "since": None} and st[plain_u]["status"] == "unknown")
    check("every status has exactly the three fields", all(set(v) == {"status", "latency_ms", "since"} for v in st.values()))
    rows = await (await db.conn.execute("SELECT status FROM connection_health_log WHERE connection_id = ?", (pinned,))).fetchall()
    check("the change to up is stored once", [r["status"] for r in rows] == ["up"], str([r["status"] for r in rows]))
    await settle()
    check("coming up from unknown sent no alert", not fire.sent, str(fire.sent))

    verdict["v"] = "fail"
    for _ in range(2):
        await mon.run_round()
    await settle()
    check("two failures: still up, nothing sent", (await mon.statuses_for(uid["owner"]))[pinned_u]["status"] == "up" and not fire.sent)
    await mon.run_round()
    await settle()
    st = await mon.statuses_for(uid["owner"])
    check("third failure: down since a time, no latency", st[pinned_u]["status"] == "down" and st[pinned_u]["since"] and st[pinned_u]["latency_ms"] is None, str(st[pinned_u]))
    down = [p for e, p in fire.sent if e == "service.health_changed"]
    pay = [p for p in down if "'pinned'" in p["summary"]]
    check("exactly one alert for the connection that went down, naming it", len(pay) == 1 and "is down" in pay[0]["summary"], str(down))
    flat = json.dumps(down)
    check("no alert carries a host, an address or a port", "93.184.216.34" not in flat and "web.example" not in flat and "8080" not in flat, flat[:300])
    check("the third-party text has no name and no detail", all(p["third_party"]["summary"] == "A member's connection is down" and not p["third_party"]["details"] for p in down))
    sent_before = len(fire.sent)
    for _ in range(3):
        await mon.run_round()
    await settle()
    check("staying down sends nothing more", len(fire.sent) == sent_before)
    rows = await (await db.conn.execute("SELECT status FROM connection_health_log WHERE connection_id = ? ORDER BY id", (pinned,))).fetchall()
    check("the log holds the transitions only (up, down)", [r["status"] for r in rows] == ["up", "down"], str([r["status"] for r in rows]))

    verdict["v"] = "ok"
    clock["t"] += ch.ALERT_PERIOD + 1        # the per-connection alert period has passed
    await mon.run_round()
    await settle()
    check("one success after down: still down", (await mon.statuses_for(uid["owner"]))[pinned_u]["status"] == "down")
    await mon.run_round()
    await settle()
    back = [p for e, p in fire.sent if "back up" in p["summary"] and "pinned" in p["summary"]]
    check("two successes: up again, one 'back up' alert", (await mon.statuses_for(uid["owner"]))[pinned_u]["status"] == "up" and len(back) == 1, str(fire.sent[-2:]))

    # restart: the stored state is read back, no alert for staying down
    verdict["v"] = "fail"
    for _ in range(3):
        await mon.run_round()
    await settle()
    n_alerts = len(fire.sent)
    mon2 = ch.Monitor(db, TYPES, emit=alerts.emit, probe=fake_probe, clock=lambda: clock["t"])
    st0 = await mon2.statuses_for(uid["owner"])
    check("after a restart nothing is shown before the first probe (unknown)", st0[pinned_u]["status"] == "unknown")
    await mon2.run_round()
    await settle()
    st1 = await mon2.statuses_for(uid["owner"])
    check("after a restart the stored 'down since' is kept and one failure does not alert again",
          st1[pinned_u]["status"] == "down" and st1[pinned_u]["since"] and len(fire.sent) == n_alerts, str(st1[pinned_u]))

    # a probe that raises changes nothing, the round goes on
    verdict["v"] = "raise"
    try:
        n = await mon2.run_round()
        check("a probe that raises: the round finishes, status unchanged", (await mon2.statuses_for(uid["owner"]))[pinned_u]["status"] == "down", str(n))
    except Exception as e:
        check("a probe that raises: the round finishes", False, repr(e))

    # the cap, the in-flight guard, least recently probed first
    verdict["v"] = "ok"
    old_cap = ch.PROBE_ROUND_CAP
    ch.PROBE_ROUND_CAP = 2
    for i in range(4):
        u, c = await mk("owner", f"cap{i}", host=f"cap{i}.example")
        await db.set_connection_prefs(uid["owner"], c, {"pinned": True}, owner=True)
    mon3 = ch.Monitor(db, TYPES, emit=alerts.emit, probe=fake_probe, clock=lambda: clock["t"])
    seen = []
    for _ in range(4):
        calls.clear()
        clock["t"] += 60
        n = await mon3.run_round()
        seen.append((n, [k[2] for k, _ in calls]))
    ch.PROBE_ROUND_CAP = old_cap
    check("the cap is a hard limit on probes per round", all(n == 2 for n, _ in seen), str(seen))
    allhosts = {h_ for _, hs in seen for h_ in hs}
    check("the cap rotates (every target gets probed over a few rounds)", {f"cap{i}.example" for i in range(4)} <= allhosts, str(seen))

    peak = {"now": 0, "max": 0}

    async def counting(target, *, lan=False):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        await asyncio.sleep(0.02)
        peak["now"] -= 1
        return ch.Result("ok", 1)

    mon4 = ch.Monitor(db, TYPES, emit=alerts.emit, probe=counting, clock=lambda: clock["t"])
    await mon4.run_round()
    check("at most 5 probes at once", 0 < peak["max"] <= 5, str(peak))
    inflight_seen = []

    async def recording(target, *, lan=False):
        inflight_seen.append(target.host)
        return ch.Result("ok", 1)

    mon7 = ch.Monitor(db, TYPES, emit=alerts.emit, probe=recording, clock=lambda: clock["t"])
    mon7._inflight.add(ch.target_of({"type": "ssh", "host": "cap0.example", "port": 22, "config": {}}, TYPES).key)
    await mon7.run_round()
    check("a target that is already being probed is not probed a second time at once",
          "cap0.example" not in inflight_seen and "cap1.example" in inflight_seen, str(inflight_seen))

    # the feature goes off again: no probe, state dropped
    await db.set_setting(ch.SETTING_ENABLED, "0")
    calls.clear()
    n = await mon.run_round()
    check("switched off again: no probe, no state", n == 0 and not calls and not mon.state.entries)

    # prune: old rows go, the latest row of a connection stays
    await db.conn.execute("INSERT INTO connection_health_log (connection_id, status, since) VALUES (?, 'up', '2020-01-01T00:00:00Z')", (plain,))
    await db.conn.execute("INSERT INTO connection_health_log (connection_id, status, since) VALUES (?, 'down', '2020-02-01T00:00:00Z')", (plain,))
    await db.conn.execute("INSERT INTO connection_health_log (connection_id, status, since) VALUES (?, 'up', '2020-03-01T00:00:00Z')", (old,))
    await db.conn.commit()
    n = await db.prune_health_log(14)
    left = await (await db.conn.execute("SELECT connection_id, status FROM connection_health_log WHERE connection_id IN (?, ?) ORDER BY id", (plain, old))).fetchall()
    check("prune: old rows go but the latest row of each connection stays", n >= 1 and [(r["connection_id"], r["status"]) for r in left] == [(plain, "down"), (old, "up")], str([tuple(r) for r in left]))
    await db.conn.execute("DELETE FROM user_connections WHERE id = ?", (plain,))
    await db.conn.commit()
    check("deleting a connection deletes its log rows",
          not await (await db.conn.execute("SELECT 1 FROM connection_health_log WHERE connection_id = ?", (plain,))).fetchone())

    # the task stops at shutdown
    await db.set_setting(ch.SETTING_ENABLED, "1")
    verdict["v"] = "ok"
    mon5 = ch.Monitor(db, TYPES, emit=alerts.emit, probe=fake_probe)
    mon5.rng = type("R", (), {"uniform": staticmethod(lambda a, b: 0.01)})()
    mon5.start()
    check("the task is one task", mon5._task is not None and not mon5._task.done())
    first = mon5._task
    mon5.start()
    check("starting twice keeps the one task", mon5._task is first)
    await asyncio.sleep(0.2)
    await mon5.stop()
    check("stop() ends the task cleanly", first.done() and mon5._task is None)

    # a round that raises does not end the loop
    class Broken(ch.Monitor):
        rounds_seen = 0

        async def run_round(self):
            Broken.rounds_seen += 1
            raise RuntimeError("db gone")
    mon6 = Broken(db, TYPES)
    mon6.rng = type("R", (), {"uniform": staticmethod(lambda a, b: 0.01)})()
    mon6.interval = 0
    mon6._round_seconds = lambda _i: 0.01
    mon6.start()
    await asyncio.sleep(0.25)
    alive = not mon6._task.done()
    await mon6.stop()
    check("a failing round is logged and the loop keeps running", alive and Broken.rounds_seen >= 2, str(Broken.rounds_seen))
    await db.set_setting(ch.SETTING_ENABLED, "0")



# ---------------------------------------------------------------------------------------------------
# Fix pass C: fairness, bounded log and state, own alert bucket, maintenance, dialled address, seeding
# ---------------------------------------------------------------------------------------------------

class LogCatcher:
    def __init__(self):
        import logging
        self.records = []
        outer = self

        class H(logging.Handler):
            def emit(self, record):
                outer.records.append(record.getMessage())
        self.handler = H(level=logging.DEBUG)
        self.logger = logging.getLogger("portal")

    def __enter__(self):
        self.logger.addHandler(self.handler)
        return self

    def __exit__(self, *a):
        self.logger.removeHandler(self.handler)

    def health(self):
        return [m for m in self.records if m.startswith("[Health]")]


async def dial_checks():
    """The probe dials the address that was checked, never the name a second time."""
    import itertools
    real_resolve, real_open = host_check._resolve, asyncio.open_connection
    asked = []

    async def flipping(host, port):
        asked.append(host)
        return ["93.184.216.34"] if len(asked) == 1 else ["127.0.0.1"]

    dialled = []

    async def fake_open(host, port, **kw):
        dialled.append(host)
        raise ConnectionRefusedError()

    host_check._resolve = flipping
    asyncio.open_connection = fake_open
    try:
        r = await ch.probe_target(ch.Target("tcp", "flip.example", 8022))
    finally:
        host_check._resolve, asyncio.open_connection = real_resolve, real_open
    check("tcp probe: dials the checked address, not the name (a second lookup would have said 127.0.0.1)",
          dialled == ["93.184.216.34"] and len(asked) == 1 and r.kind == "fail", f"{dialled} {asked} {r}")

    up = await Upstream().start()
    asked.clear()
    outbound_guard.refused.clear()
    host_check._resolve = flipping
    try:
        t = ch.Target("http", "flip.example", up.port, "http", False, f"http://flip.example:{up.port}/")
        r = await ch.probe_target(t)
    finally:
        host_check._resolve = real_resolve
    check("http probe: dials the checked address, not the name: the loopback upstream saw nothing",
          not up.seen and len(asked) == 1 and r.kind == "fail", f"{up.seen} {asked} {r}")
    check("http probe: the connection attempt went to the checked public address (stopped by the test guard)",
          outbound_guard.refused[:1] == ["93.184.216.34"], str(outbound_guard.refused))
    outbound_guard.refused.clear()
    await up.stop()

    # a refused name: the refusal is raised as before, but this probe writes no warning of its own
    async def to_loopback(host, port):
        return ["127.0.0.1"]
    host_check._resolve = to_loopback
    try:
        with LogCatcher() as lc:
            r = await ch.probe_target(ch.Target("tcp", "sneaky.example", 80))
            quiet_msgs = [m for m in lc.records if "Outbound host check" in m]
        try:
            await host_check.resolve_checked_host("sneaky.example", 80)
            raised = False
        except host_check.HostBlockedError:
            raised = True
        with LogCatcher() as lc2:
            try:
                await host_check.resolve_checked_host("sneaky.example", 80)
            except host_check.HostBlockedError:
                pass
            loud = [m for m in lc2.records if "Outbound host check" in m]
    finally:
        host_check._resolve = real_resolve
    check("a refused name is still refused by the probe, without a warning per attempt", r.kind == "refused" and not quiet_msgs, f"{r} {quiet_msgs}")
    check("the host policy itself is untouched: it still raises and still warns outside a probe", raised and len(loud) == 1, f"{raised} {loud}")


def alert_and_state_units():
    # seeding: a stale stored "down" is not "known" after a restart; a fresh one is
    now_dt = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    st = ch.HealthState()
    st.seed({1: ("down", iso(now_dt - timedelta(hours=3)), "down", iso(now_dt - timedelta(hours=3))),
             2: ("down", iso(now_dt - timedelta(minutes=2)), "down", iso(now_dt - timedelta(minutes=2))),
             3: ("unknown", iso(now_dt - timedelta(minutes=1)), "down", iso(now_dt - timedelta(hours=5))),
             4: ("up", iso(now_dt - timedelta(days=9)), "up", iso(now_dt - timedelta(days=9)))}, now_dt)
    check("seed: an old stored down is not known, a recent one is, a down behind a recent unknown is judged by its own time, an old up stays known",
          [st.entries[i].known for i in (1, 2, 3, 4)] == [None, "down", None, "up"], str([st.entries[i].known for i in (1, 2, 3, 4)]))
    check("seed: the status itself is kept for the view", st.entries[1].status == "down")

    # maintenance: an alert is owed, sent afterwards when still true, cancelled by the opposite
    K = ("tcp", "", "h", 1, False)
    ok, bad = ch.Result("ok", 5), ch.Result("fail")
    s2 = ch.HealthState()
    for i in range(2):
        s2.apply(1, K, ok, float(i), "t")
    trs = [s2.apply(1, K, bad, 10.0 + i, "t", quiet=True) for i in range(3)]
    check("maintenance: the down is a transition but sends no alert", trs[2].new == "down" and trs[2].alert is None and s2.entries[1].owed == "down")
    tr = s2.apply(1, K, bad, 20.0, "t2")
    check("after maintenance, a status still down sends the owed alert once, not stored again",
          tr is not None and tr.alert == "down" and tr.store is False and s2.apply(1, K, bad, 21.0, "t3") is None)
    s3 = ch.HealthState()
    for i in range(2):
        s3.apply(1, K, ok, float(i), "t")
    for i in range(3):
        s3.apply(1, K, bad, 10.0 + i, "t", quiet=True)
    for i in range(2):
        s3.apply(1, K, ok, 20.0 + i, "t", quiet=True)
    check("maintenance: down then up inside it cancel (no orphan 'back up' afterwards)",
          s3.entries[1].owed is None and s3.apply(1, K, ok, 30.0, "t") is None)


async def fix_c_checks(env):
    db = env.db
    uid = env.uid
    await db.conn.execute("DELETE FROM user_connections")
    await db.conn.execute("DELETE FROM connection_health_log")
    await db.conn.commit()
    await db.set_setting(ch.SETTING_ENABLED, "1")
    clock = {"t": 5000.0}
    old_notice = (alerts.NOTICE_DELAY, alerts.NOTICE_INTERVAL)
    alerts.NOTICE_DELAY = alerts.NOTICE_INTERVAL = 0.01      # the "held back" notice must not wait in real time
    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    alerts._clock = lambda: clock["t"]

    async def mk(owner, name, host, ctype="ssh", port=22, pin=True):
        u = await db.create_user_connection(uid[owner], name, ctype, host, port, "{}")
        cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
        if pin:
            await db.set_connection_prefs(uid[owner], cid, {"pinned": True}, owner=True)
        return u, cid

    async def wipe():
        await db.conn.execute("DELETE FROM user_connections")
        await db.conn.execute("DELETE FROM connection_health_log")
        await db.conn.commit()

    # ---- 1. fairness ------------------------------------------------------------------------------
    calls = []

    async def ok_probe(target, *, lan=False):
        calls.append(target.host)
        return ch.Result("ok", 3)

    for i in range(25):
        await mk("owner", f"o{i}", f"o{i:02d}.example")
    await mk("bob", "b0", "bob0.example")
    await mk("carol", "c0", "o00.example")           # the same target as the first of owner's
    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=ok_probe, clock=lambda: clock["t"])
    n = await mon.run_round()
    owner_hosts = [h_ for h_ in calls if h_.startswith("o")]
    check("fairness: one member's 25 pinned targets get at most PER_OWNER_PROBES probes in a round",
          len(owner_hosts) == ch.PER_OWNER_PROBES, str(calls))
    check("fairness: another member's single connection is probed in the same round", "bob0.example" in calls, str(calls))
    check("fairness: a target two members share is probed once", calls.count("o00.example") == 1)
    for _ in range(2):
        clock["t"] += 60
        await mon.run_round()
    check("fairness: the owner's excess is probed in later rounds, least recently probed first (all 25 within three rounds)",
          {f"o{i:02d}.example" for i in range(25)} <= set(calls), str(len(set(calls))))
    since_iso = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    kept = await db.list_health_candidate_refs(since_iso, 3)
    check("fairness: when the safety limit on the candidate list bites, every owner's first connection is kept first",
          {o for _c, o in kept} >= {uid["owner"], uid["bob"], uid["carol"]}, str(kept))
    # the cap of the round and the cap on decoded rows are shared out in turn too
    old_round, old_limit = ch.PROBE_ROUND_CAP, ch.CANDIDATE_LIMIT
    ch.PROBE_ROUND_CAP = 4
    calls.clear()
    mon_b = ch.Monitor(db, TYPES, emit=alerts.emit, probe=ok_probe, clock=lambda: clock["t"])
    try:
        await mon_b.run_round()
    finally:
        ch.PROBE_ROUND_CAP = old_round
    check("fairness: with a small round cap every member still has a turn", {"bob0.example"} & set(calls) and len(calls) == 4, str(calls))
    ch.CANDIDATE_LIMIT = 3
    calls.clear()
    mon_c = ch.Monitor(db, TYPES, emit=alerts.emit, probe=ok_probe, clock=lambda: clock["t"])
    try:
        await mon_c.run_round()
    finally:
        ch.CANDIDATE_LIMIT = old_limit
    check("fairness: with a small cap on decoded rows every member is still looked at", "bob0.example" in calls and len(calls) <= 3, str(calls))

    # ---- 2. bounded log and state -------------------------------------------------------------------
    await wipe()
    u, cid = await mk("owner", "flappy", "flap.example")
    phase = {"i": 0}

    async def flap_probe(target, *, lan=False):
        phase["i"] += 1
        return ch.Result("ok", 1) if (phase["i"] - 1) % 5 < 2 else ch.Result("fail")

    sent = []
    day = {"d": datetime(2030, 3, 1, 12, 0, 0, tzinfo=timezone.utc)}
    old_store = ch.STORE_PER_DAY
    ch.STORE_PER_DAY = 4
    mon = ch.Monitor(db, TYPES, emit=lambda *a, **k: sent.append(k), probe=flap_probe, clock=lambda: clock["t"], wall=lambda: day["d"])
    try:
        for _ in range(30):                       # six cycles of two ups and three downs: twelve changes
            clock["t"] += 60
            await mon.run_round()
        rows = await (await db.conn.execute("SELECT status FROM connection_health_log WHERE connection_id = ?", (cid,))).fetchall()
        check("bounded: at most STORE_PER_DAY transitions of one connection are stored in a day", len(rows) == 4, str(len(rows)))
        check("bounded: and no alert after them either (of the four stored changes the first, to up, never alerts)", len(sent) == 3, str(len(sent)))
        view = mon.state.view(cid, clock["t"], 1e9)
        check("bounded: the status keeps changing in memory and is shown", view["status"] in ("up", "down") and mon.state.entries[cid].since, str(view))
        day["d"] += timedelta(days=1)
        for _ in range(10):
            clock["t"] += 60
            await mon.run_round()
        rows2 = await (await db.conn.execute("SELECT status FROM connection_health_log WHERE connection_id = ?", (cid,))).fetchall()
        check("bounded: the next day stores again (up to the cap)", 4 < len(rows2) <= 8, str(len(rows2)))
    finally:
        ch.STORE_PER_DAY = old_store

    await wipe()
    ids = []
    for i in range(3):
        _, c = await mk("owner", f"cap{i}", f"cap{i}.example", pin=False)
        ids.append(c)
    for j in range(60):
        await db.conn.execute("INSERT INTO connection_health_log (connection_id, status, since) VALUES (?, ?, ?)",
                              (ids[j % 3], "up" if j % 2 else "down", "2030-01-01T00:00:%02dZ" % (j % 60)))
    await db.conn.commit()
    latest = {r["connection_id"]: r["id"] for r in await (await db.conn.execute(
        "SELECT connection_id, MAX(id) AS id FROM connection_health_log GROUP BY connection_id")).fetchall()}
    n = await db.prune_health_log(100000, 20)
    left = [r["id"] for r in await (await db.conn.execute("SELECT id FROM connection_health_log ORDER BY id")).fetchall()]
    check("bounded: the global row cap deletes the oldest rows first and keeps each connection's latest",
          n == 40 and len(left) == 20 and set(latest.values()) <= set(left) and left == sorted(left)
          and min(left) > 30, f"{n} {left}")

    # refused target: one warning when it starts, one when it ends
    await wipe()
    await mk("owner", "sneaky", "sneaky.example")
    verdict = {"v": "refused"}
    probed = []

    async def refusing(target, *, lan=False):
        probed.append(clock["t"])
        return ch.Result(verdict["v"])

    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=refusing, clock=lambda: clock["t"])
    with LogCatcher() as lc:
        for _ in range(8):
            clock["t"] += 60
            await mon.run_round()
        starts = list(lc.health())
        check("refused: eight rounds log one warning, not eight, and probe once inside the backoff",
              len(starts) == 1 and "refuses" in starts[0] and len(probed) == 1, f"{starts} {probed}")
        clock["t"] += ch.REFUSED_BACKOFF + 1
        await mon.run_round()
        check("refused: tried again after the backoff, still one warning", len(probed) == 2 and len(lc.health()) == 1, f"{probed} {lc.health()}")
        verdict["v"] = "ok"
        clock["t"] += ch.REFUSED_BACKOFF_MAX + 1
        await mon.run_round()
        check("refused: one more warning when it ends, none after", len(lc.health()) == 2 and "no longer refused" in lc.health()[1], str(lc.health()))
        for _ in range(3):
            clock["t"] += 60
            await mon.run_round()
        check("refused: nothing further", len(lc.health()) == 2)
    check("refused: the remembered targets are bounded", len(mon._refused) <= ch.REFUSED_MAX)

    # ---- 3. alert bucket and period -----------------------------------------------------------------
    await wipe()
    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    alerts._clock = lambda: clock["t"]
    cids = []
    for i in range(6):
        _, c = await mk("owner", f"alert{i}", f"alert{i}.example")
        cids.append(c)
    verdict2 = {"v": "ok"}

    async def probe2(target, *, lan=False):
        return ch.Result(verdict2["v"], 2 if verdict2["v"] == "ok" else None)

    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=probe2, clock=lambda: clock["t"])
    for _ in range(2):
        clock["t"] += 1
        await mon.run_round()
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 1
        await mon.run_round()
    await settle()
    downs = [p for e, p in fire.sent if e == "service.health_changed" and "is down" in p["summary"]]
    check("alerts: six connections going down use only the health bucket's own cap", len(downs) == alerts.SUB_CAPS[alerts.HEALTH_BUCKET], str(len(downs)))
    check("alerts: a moderation alert is still admitted (the member bucket is untouched)",
          alerts.emit("moderation.action", key=("t", 1), summary="x") is True)
    check("alerts: the health bucket is its own, not the member bucket", alerts.HEALTH_BUCKET != alerts.MEMBER_BUCKET and alerts.HEALTH_BUCKET in alerts.SUB_CAPS)
    check("alerts: the caps still leave the room the rest of the portal was promised",
          sum(alerts.SUB_CAPS.values()) <= alerts.CAP_ALERTS - alerts.MEMBER_RESERVE)

    await wipe()
    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    alerts._clock = lambda: clock["t"]
    _, one = await mk("owner", "once", "once.example")
    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=probe2, clock=lambda: clock["t"])
    seq = ["ok"] * 2 + ["fail"] * 3 + ["ok"] * 2 + ["fail"] * 3
    for v in seq:
        verdict2["v"] = v
        clock["t"] += 5
        await mon.run_round()
    await settle()
    mine = [p["summary"] for e, p in fire.sent if e == "service.health_changed"]
    check("alerts: a connection that goes down, up and down again within the period sends one alert", len(mine) == 1 and "is down" in mine[0], str(mine))
    clock["t"] += ch.ALERT_PERIOD
    for v in ["ok"] * 2:
        verdict2["v"] = v
        await mon.run_round()
    await settle()
    check("alerts: after the period the next change is announced",
          len([p for e, p in fire.sent if e == "service.health_changed"]) == 2, str(fire.sent[-1:]))

    # ---- 4. maintenance ---------------------------------------------------------------------------
    await wipe()
    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    alerts._clock = lambda: clock["t"]
    mu, mc = await mk("owner", "serviced", "svc.example")
    await db.add_connection_share(mc, uid["bob"], uid["owner"], "30d")
    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=probe2, clock=lambda: clock["t"])
    verdict2["v"] = "ok"
    for _ in range(2):
        clock["t"] += 5
        await mon.run_round()
    await db.conn.execute("UPDATE user_connections SET maintenance = 1, maintenance_until = NULL, maintenance_message = 'secret plan' WHERE id = ?", (mc,))
    await db.conn.commit()
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 5
        await mon.run_round()
    await settle()
    check("maintenance: the connection goes down without an alert while maintenance lasts", mon.state.entries[mc].status == "down" and not fire.sent, str(fire.sent))
    for who in ("owner", "bob"):
        v = (await mon.statuses_for(uid[who]))[mu]
        check(f"maintenance: the dot reads 'maintenance' for {who} and carries nothing else",
              v == {"status": "maintenance", "latency_ms": None, "since": None}, str(v))
    check("maintenance: a member with no access sees nothing of it", await mon.statuses_for(uid["carol"]) == {})
    check("maintenance: the message is not in the answer", "secret plan" not in json.dumps(await mon.statuses_for(uid["bob"])))
    await db.conn.execute("UPDATE user_connections SET maintenance = 0 WHERE id = ?", (mc,))
    await db.conn.commit()
    clock["t"] += 5
    await mon.run_round()
    await settle()
    after = [p["summary"] for e, p in fire.sent]
    check("maintenance: once it ends, a connection that is still down sends the one owed alert",
          len(after) == 1 and "is down" in after[0], str(after))
    check("maintenance: the dot shows the real status again", (await mon.statuses_for(uid["owner"]))[mu]["status"] == "down")
    clock["t"] += 5
    await mon.run_round()
    await settle()
    check("maintenance: and not a second time", len(fire.sent) == 1)
    # an end time that has passed means no maintenance
    await db.conn.execute("UPDATE user_connections SET maintenance = 1, maintenance_until = '2000-01-01T00:00:00Z' WHERE id = ?", (mc,))
    await db.conn.commit()
    check("maintenance: an end time in the past is no maintenance", (await mon.statuses_for(uid["owner"]))[mu]["status"] == "down")

    # ---- 4b. the global maintenance flag reads as maintenance for proxy-type connections ------------------
    await wipe()
    alerts.reset_state()
    fire = Fire()
    alerts.bind(fire=fire, notify=None, get_setting=None, set_setting=None)
    alerts.bind_record(None)
    alerts._clock = lambda: clock["t"]
    web_u, web_c = await mk("owner", "webapp", "web.example", ctype="http", port=80)
    ssh_u, ssh_c = await mk("owner", "shellbox", "shell.example")
    gflag = {"flag": None}

    async def read_flag():
        return gflag["flag"]

    mon = ch.Monitor(db, TYPES, emit=alerts.emit, probe=probe2, clock=lambda: clock["t"], global_maintenance=read_flag)
    verdict2["v"] = "ok"
    for _ in range(2):
        clock["t"] += 5
        await mon.run_round()
    st = await mon.statuses_for(uid["owner"])
    check("global maintenance off: both dots show the real status", st[web_u]["status"] == "up" and st[ssh_u]["status"] == "up", str(st))
    gflag["flag"] = {"message": "secret plan", "until": None, "set_by": "adm", "set_at": None}
    st = await mon.statuses_for(uid["owner"])
    check("global maintenance: the proxy-type dot reads 'maintenance' and carries nothing else",
          st[web_u] == {"status": "maintenance", "latency_ms": None, "since": None}, str(st[web_u]))
    check("global maintenance: a connection the proxy does not serve keeps its status", st[ssh_u]["status"] == "up", str(st[ssh_u]))
    check("global maintenance: the message is not in the answer", "secret plan" not in json.dumps(st))
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 5
        await mon.run_round()
    await settle()
    downs = [p["summary"] for e, p in fire.sent]
    check("global maintenance: the proxy-type connection goes down without an alert, the other one alerts once",
          len(downs) == 1 and "webapp" not in downs[0] and mon.state.entries[web_c].status == "down" and mon.state.entries[ssh_c].status == "down", str(downs))
    gflag["flag"] = {"message": "", "until": "2000-01-01T00:00:00Z", "set_by": "adm", "set_at": None}
    check("global maintenance: an end time in the past is no maintenance", (await mon.statuses_for(uid["owner"]))[web_u]["status"] == "down")
    gflag["flag"] = None
    clock["t"] += 5
    await mon.run_round()
    await settle()
    check("global maintenance: once it ends the owed alert is sent",
          len([1 for e, p in fire.sent if "webapp" in p["summary"]]) == 1, str(fire.sent))

    # ---- 5c. a stale stored down does not announce 'back up' -----------------------------------------
    await wipe()
    ru, rc = await mk("owner", "restarted", "restart.example")
    got = []
    emit_rec = lambda *a, **k: got.append(k.get("summary"))
    mon = ch.Monitor(db, TYPES, emit=emit_rec, probe=probe2, clock=lambda: clock["t"])
    verdict2["v"] = "ok"
    for _ in range(2):
        clock["t"] += 5
        await mon.run_round()
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 5
        await mon.run_round()
    check("restart setup: one 'down' alert", len(got) == 1 and "is down" in got[0], str(got))
    iso_ago = lambda **kw: (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")
    await db.conn.execute("UPDATE connection_health_log SET since = ? WHERE connection_id = ? AND status = 'down'", (iso_ago(hours=3), rc))
    await db.conn.commit()
    got.clear()
    fresh = ch.Monitor(db, TYPES, emit=emit_rec, probe=probe2, clock=lambda: clock["t"])
    verdict2["v"] = "ok"
    for _ in range(3):
        clock["t"] += 5
        await fresh.run_round()
    check("restart: a connection stored as down three hours ago comes back up without a 'back up' alert",
          fresh.state.entries[rc].status == "up" and not got, str(got))
    # switching the feature off and on
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 5
        await fresh.run_round()
    check("off/on setup: down again, announced", len(got) == 1 and "is down" in got[0], str(got))
    await db.conn.execute("UPDATE connection_health_log SET since = ? WHERE connection_id = ? AND status = 'down'", (iso_ago(hours=2), rc))
    await db.conn.commit()
    await db.set_setting(ch.SETTING_ENABLED, "0")
    await fresh.run_round()
    await db.set_setting(ch.SETTING_ENABLED, "1")
    got.clear()
    verdict2["v"] = "ok"
    for _ in range(3):
        clock["t"] += 5
        await fresh.run_round()
    check("off then on: an old stored down does not announce 'back up'", fresh.state.entries[rc].status == "up" and not got, str(got))
    # and a recent one still does (the control: the rule is the age, not a silenced recovery)
    verdict2["v"] = "fail"
    for _ in range(3):
        clock["t"] += 5
        await fresh.run_round()
    got.clear()
    await db.conn.execute("UPDATE connection_health_log SET since = ? WHERE connection_id = ? AND status = 'down'", (iso_ago(minutes=2), rc))
    await db.conn.commit()
    await db.set_setting(ch.SETTING_ENABLED, "0")
    await fresh.run_round()
    await db.set_setting(ch.SETTING_ENABLED, "1")
    verdict2["v"] = "ok"
    for _ in range(3):
        clock["t"] += 5
        await fresh.run_round()
    check("control: a down stored two minutes ago does announce 'back up' after a restart", len(got) == 1 and "back up" in got[0], str(got))
    await db.set_setting(ch.SETTING_ENABLED, "0")
    alerts._clock = __import__("time").monotonic
    alerts.NOTICE_DELAY, alerts.NOTICE_INTERVAL = old_notice


async def stage_checks(env):
    db = env.db
    uid = env.uid
    up = await Upstream().start()
    tcp = await Tcp().start()
    calls = []

    async def fake_probe(target, *, lan=False):
        calls.append((target.host, target.port, lan))
        return ch.Result("ok", 1)

    async def mk(name, ctype, host, port):
        u = await db.create_user_connection(uid["owner"], name, ctype, host, port, "{}")
        cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (u,))).fetchone())["id"]
        await db.set_connection_prefs(uid["owner"], cid, {"pinned": True}, owner=True)
        return u

    await db.conn.execute("DELETE FROM user_connections")
    await db.conn.commit()
    local = await mk("stage-local", "ssh", "127.0.0.1", tcp.port)
    other_port = await mk("stage-other-port", "ssh", "127.0.0.1", tcp.port + 1)
    realish = await mk("stage-real", "ssh", "93.184.216.34", 22)
    named = await mk("stage-named", "ssh", "localhost", tcp.port)
    await db.set_setting(ch.SETTING_ENABLED, "1")
    await db.set_setting(ch.SETTING_STAGE_PORTS, str(tcp.port))
    m = ch.Monitor(db, TYPES, stage_mode=True, emit=alerts.emit, probe=fake_probe)
    n = await m.run_round()
    check("staged: only the loopback target on the harness's port is probed, under the LAN policy",
          calls == [("127.0.0.1", tcp.port, True)] and n == 1, str(calls))
    st = await m.statuses_for(uid["owner"])
    check("staged: every other connection stays unknown and was never dialled",
          st[other_port]["status"] == "unknown" and st[realish]["status"] == "unknown" and st[named]["status"] == "unknown")
    # the same database setting in a production process is ignored
    calls.clear()
    p = ch.Monitor(db, TYPES, stage_mode=False, emit=alerts.emit, probe=fake_probe)
    await p.run_round()
    check("production ignores the stage setting: the LAN policy is never asked for", all(not lan for _, _, lan in calls), str(calls))
    # a real probe of the staged loopback target, end to end
    calls.clear()
    real = ch.Monitor(db, TYPES, stage_mode=True, emit=alerts.emit)
    await real.run_round()
    await real.run_round()
    st = await real.statuses_for(uid["owner"])
    check("staged, real probe: the local listener is up after two rounds", st[local]["status"] == "up" and st[local]["latency_ms"] is not None, str(st[local]))
    await tcp.stop()
    for _ in range(3):
        await real.run_round()
    st = await real.statuses_for(uid["owner"])
    check("staged, real probe: stopping the listener turns it down after three rounds", st[local]["status"] == "down" and st[local]["since"], str(st[local]))
    await up.stop()
    await db.set_setting(ch.SETTING_ENABLED, "0")


async def api_checks(env):
    base = env.base
    owner, bob, carol, adm = (env.sessions[n] for n in ("owner", "bob", "carol", "adm"))
    db = env.db
    await db.conn.execute("DELETE FROM user_connections")
    await db.conn.commit()
    uuid, cid = await h.connection(env, "owner", name="Palworld", ctype="ssh", host="secret-host.example", port=2222)
    async with owner.post(f"{base}/api/connections/{uuid}/shares", json={"usernames": ["bob"], "expires_in": "30d"}) as r:
        assert r.status == 200
    await db.set_connection_prefs(env.uid["owner"], cid, {"pinned": True}, owner=True)

    async def get(s, path="/api/connections/status"):
        async with s.get(base + path) as r:
            return r.status, await r.text()

    st, body = await get(owner)
    check("the status route is not swallowed by /api/connections/{id} (200, not 'Connection not found')",
          st == 200 and "not found" not in body.lower(), f"{st} {body}")
    check("feature off: an empty map", json.loads(body) == {}, body)
    async with owner.get(f"{base}/api/connections/{uuid}") as r:
        check("a real connection id still works", r.status == 200)
    async with aiohttp.ClientSession() as anon:
        async with anon.get(base + "/api/connections/status", allow_redirects=False) as r:
            check("signed out: refused", r.status in (401, 302, 403), str(r.status))

    # settings: only a superadmin changes it
    async with owner.put(f"{base}/api/admin/connection-health", json={"enabled": True}) as r:
        check("a member cannot switch it on", r.status in (401, 403), str(r.status))
    for bad in ({"enabled": "yes"}, {"interval": 10}, {"interval": 100000}, {"interval": 61.5}, {"interval": True}, {"x": 1}, {}):
        async with adm.put(f"{base}/api/admin/connection-health", json=bad) as r:
            check(f"settings refuse {bad}", r.status == 400, str(r.status))
    async with adm.get(f"{base}/api/admin/connection-health") as r:
        d = await r.json()
        check("settings: off by default, interval 60", r.status == 200 and d["enabled"] is False and d["interval"] == 60, str(d))
    async with adm.put(f"{base}/api/admin/connection-health", json={"enabled": True, "interval": 120}) as r:
        d = await r.json()
        check("a superadmin switches it on with an interval", r.status == 200 and d["enabled"] is True and d["interval"] == 120, str(d))
    audit = await (await db.conn.execute("SELECT action FROM audit_log WHERE action = 'connection_health.update'")).fetchall()
    check("the change is audited", len(audit) == 1, str(len(audit)))

    # status for owner, grantee, stranger
    mon = server._health_monitor
    mon.probe = None
    results = {"v": "ok"}

    async def fake_probe(target, *, lan=False):
        return ch.Result(results["v"], 4 if results["v"] == "ok" else None)

    mon.probe = fake_probe
    await mon.run_round()
    await mon.run_round()
    so, bo = (await get(owner))[1], (await get(bob))[1]
    jo, jb = json.loads(so), json.loads(bo)
    check("owner and grantee see the same shape and values", jo == jb and set(jo) == {uuid}, f"{so} {bo}")
    check("the entry is exactly status, latency_ms, since", set(jo[uuid]) == {"status", "latency_ms", "since"} and jo[uuid]["status"] == "up", so)
    check("a stranger sees nothing of it", json.loads((await get(carol))[1]) == {})
    results["v"] = "fail"
    for _ in range(3):
        await mon.run_round()
    jb = json.loads((await get(bob))[1])
    text = json.dumps(jb)
    check("the grantee sees down since a time, no latency", jb[uuid]["status"] == "down" and jb[uuid]["since"] and jb[uuid]["latency_ms"] is None, text)
    check("the grantee's answer holds no host, address, port or error text",
          not any(x in text for x in ("secret-host", "2222", "error", "refused", "timeout", "Palworld")), text)
    # 5b. a share that was revoked or has ended shows the grantee nothing of the connection
    async with bob.get(base + "/api/connections/status") as r:
        check("no-store", "no-store" in r.headers.get("Cache-Control", ""))
    await db.remove_connection_share(cid, env.uid["bob"])
    check("a revoked share: the grantee's map no longer holds the connection", uuid not in json.loads((await get(bob))[1]))
    check("a revoked share: the owner still sees it", uuid in json.loads((await get(owner))[1]))
    await db.add_connection_share(cid, env.uid["bob"], env.uid["owner"], "30d")
    check("a live share shows it again", uuid in json.loads((await get(bob))[1]))
    await db.conn.execute("UPDATE connection_shares SET expires_at = '2000-01-01T00:00:00Z' WHERE connection_id = ?", (cid,))
    await db.conn.commit()
    check("an expired share: the grantee's map no longer holds the connection", uuid not in json.loads((await get(bob))[1]))
    async with adm.put(f"{base}/api/admin/connection-health", json={"enabled": False}) as r:
        check("switched off again", r.status == 200)
    check("off again: the empty map at once", json.loads((await get(owner))[1]) == {})
    await mon.run_round()
    check("off again: the monitor drops its state", not mon.state.entries)


async def main():
    unit_checks()
    outbound_guard.refused.clear()
    await probe_checks()
    await dial_checks()
    alert_and_state_units()
    env = await h.boot()
    try:
        await db_checks(env)
        await fix_c_checks(env)
        await stage_checks(env)
        await api_checks(env)
    finally:
        await h.shutdown(env)
    h.finish("test_connection_health")


asyncio.run(main())
