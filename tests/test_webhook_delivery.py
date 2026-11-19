"""Outgoing webhook delivery in every format against a receiver on 127.0.0.1:
HMAC kept for generic, minimal ntfy/Gotify/Discord/Slack messages, credentials only
in headers, no redirects, Retry-After handling that never counts toward auto-disable,
destination policy, and the private-channel and private-stream exclusions.

Nothing leaves this machine: the receiver is a local aiohttp server and the hooks that
reach it carry allow_private.

Run: venv/bin/python tests/test_webhook_delivery.py
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import server  # noqa: E402
import webhook_formats as wf  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


received = []          # (path, headers dict, body bytes)
script = []            # statuses for the receiver to answer with, in order
redirect_hits = []


async def receiver(request):
    body = await request.read()
    received.append((request.path_qs, dict(request.headers), body))
    if request.path == "/redirect":
        raise web.HTTPFound("/landed")
    if request.path == "/landed":
        redirect_hits.append(1)
        return web.Response(status=200)
    if script:
        item = script.pop(0)
        status, headers = item if isinstance(item, tuple) else (item, {})
        return web.Response(status=status, headers=headers, text="receiver says no")
    return web.Response(status=204)


def unit_tests():
    # --- cleaning
    c = wf.clean_text
    check("@everyone and @here lose their @", c("hi @everyone and @here!", 100) == "hi everyone and here!")
    check("user, role and channel mentions removed", c("a <@123> b <@!9> c <@&55> d <#7> e", 100) == "a  b  c  d  e")
    check("nested mention forms cannot rebuild a mention", "<@" not in c("<<@1>@2>@3>", 100) and "@everyone" not in c("@@everyone", 100))
    check("slack special mentions removed", "<!" not in c("<!channel> <!here> <!subteam^S1>", 100))
    check("control and zero-width characters removed", c("a\x00b​c\x1bd", 100) == "abcd")
    check("long text is cut with an ellipsis", c("x" * 500, 200) == "x" * 197 + "...")
    check("@ alone survives", c("mail me @ home", 100) == "mail me @ home")
    # --- retry-after
    p = wf.parse_retry_after
    check("Retry-After seconds, cap, negative, junk, missing",
          p("7") == 7 and p("999999") == 600 and p("-5") == 0 and p("soon") == wf.RETRY_AFTER_DEFAULT
          and p(None) == wf.RETRY_AFTER_DEFAULT and p("nan") == wf.RETRY_AFTER_DEFAULT and p("inf") == 600)
    from datetime import datetime, timezone
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    check("Retry-After HTTP date", p("Thu, 01 Jan 2026 12:00:30 GMT", now) == 30)
    # --- masking
    check("mask_url keeps scheme and host only",
          wf.mask_url("https://discord.com/api/webhooks/1/TOKEN?x=1") == {"url_set": True, "url_host": "https://discord.com"}
          and wf.mask_url(None) == {"url_set": False, "url_host": None})
    # --- formats
    d = {"message": "secret chat text", "username": "alice", "channel": "general", "message_id": 5,
         "user_id": 9, "email": "a@b.c", "ip": "1.2.3.4", "token": "tok", "public_key": "pub_abc"}
    for fmt in ("ntfy", "gotify", "discord", "slack"):
        r = wf.format_payload(fmt, "message.created", d, meta={"channel_id": 1}, portal_name="P")
        blob = r.body.decode() + json.dumps(r.headers)
        check(f"{fmt}: default message carries none of the payload fields",
              not any(x in blob for x in ("secret chat text", "alice", "a@b.c", "1.2.3.4", "tok", "pub_abc", "user_id")), blob[:200])
        check(f"{fmt}: no HMAC header", "X-Portal-Signature" not in r.headers)
    r = wf.format_payload("discord", "stream.live", {"stream_name": "S", "public_key": "pub_abc", "owner_username": "bob"},
                          include_details=True, portal_name="P")
    check("details are an allow-list: a pub_ key never leaves", "pub_abc" not in r.body.decode() and "bob" in r.body.decode())
    r = wf.format_payload("discord", "message.created",
                          {"message": "x" * 400 + " @everyone <@5>", "username": "alice", "channel": "general"},
                          meta={"anonymous": True}, include_details=True, portal_name="P")
    emb = json.loads(r.body)
    check("discord: details show Anonymous, never the name, text cut to 200",
          "Anonymous" in emb["embeds"][0]["description"] and "alice" not in r.body.decode()
          and ("x" * 197 + "...") in emb["embeds"][0]["description"] and "x" * 198 not in emb["embeds"][0]["description"])
    r = wf.format_payload("discord", "message.created",
                          {"message": "click [here](http://evil.example/x) **bold** `code` ||spoiler|| > q", "username": "al", "channel": "a_b"},
                          include_details=True, portal_name="P")
    desc = json.loads(r.body)["embeds"][0]["description"]
    check("discord: link and formatting syntax in the text is made literal",
          "\\[here\\]\\(http://evil.example/x\\)" in desc and "[here](" not in desc and "**bold**" not in desc
          and "\\*\\*bold\\*\\*" in desc and "\\|\\|spoiler\\|\\|" in desc and "a\\_b" in desc, desc)
    check("discord: allowed_mentions parse is empty", emb["allowed_mentions"] == {"parse": []})
    r = wf.format_payload("slack", "message.created", {"message": "<!channel> & <@U1>", "channel": "g"},
                          include_details=True, portal_name="P")
    txt = json.loads(r.body)["text"]
    check("slack: nothing angle-bracketed survives", "<" not in txt.replace("*", "") or "&lt;" in txt and "<!" not in txt, txt)
    r = wf.format_payload("ntfy", "webhook.test", {}, portal_name="Café \r\nX-Evil: 1",
                          secret_config={"token": "tk_abc"})
    check("ntfy: header values are ASCII with no CR or LF",
          all(("\r" not in v and "\n" not in v and v.isascii()) for v in r.headers.values()), str(r.headers))
    check("ntfy: bearer, title, priority", r.headers["Authorization"] == "Bearer tk_abc" and "Title" in r.headers
          and r.headers["Priority"] == "3")
    r = wf.format_payload("ntfy", "webhook.test", {}, secret_config={"username": "u", "password": "p"})
    check("ntfy: basic auth", r.headers["Authorization"].startswith("Basic "))
    r = wf.format_payload("gotify", "webhook.test", {}, secret_config={"token": "GT"})
    check("gotify: token in X-Gotify-Key, path /message, not in body",
          r.headers["X-Gotify-Key"] == "GT" and r.path_suffix == "/message" and b"GT" not in r.body)
    r = wf.format_payload("generic", "user.joined", {"a": 1}, secret="s3cret")
    sig = hmac.new(b"s3cret", r.body, hashlib.sha256).hexdigest()
    check("generic: unchanged signed body", r.headers["X-Portal-Signature"] == "sha256=" + sig
          and set(json.loads(r.body)) == {"event", "timestamp", "data"})


async def hook(db, fmt, url, *, events=("*",), cfg=None, details=False, private=True, kind="user", uid=None):
    h = await db.create_webhook(uid, f"t-{fmt}", "outgoing", url=url, events=list(events), fmt=fmt,
                                format_config=cfg, include_details=details, allow_private=private,
                                kind=kind)
    return await db.get_webhook_for_delivery(h["id"])


async def main():
    unit_tests()
    tmp = tempfile.mkdtemp()
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    db = server.db
    await db.conn.execute("INSERT INTO users (username, password_hash) VALUES ('owner', 'x')")
    await db.conn.commit()
    uid = (await (await db.conn.execute("SELECT id FROM users WHERE username='owner'")).fetchone())["id"]
    Config.TOTP_ISSUER = "Test Portal"

    # The receiver below listens in this very process, which the real discovery of
    # "the portal's own sockets" would (rightly) refuse. Delivery tests pin the portal
    # to Config.PORT; the discovery itself is tested on its own further down.
    real_endpoints = server._own_endpoints
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", receiver)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    slept = []

    async def fake_sleep(secs):
        slept.append(secs)
    server._webhook_sleep = fake_sleep

    # ---- generic: signed, policy applies
    g = await hook(db, "generic", base + "/g", private=True, uid=uid)
    res = await server._deliver_webhook(g, "user.joined", {"user_id": 1, "username": "zed"}, single=True)
    path, hdrs, body = received[-1]
    check("generic delivery arrives and is signed",
          res["success"] and hdrs["X-Portal-Signature"] == "sha256=" + hmac.new(g["secret"].encode(), body, hashlib.sha256).hexdigest()
          and json.loads(body)["data"]["username"] == "zed")
    n = len(received)
    g2 = await hook(db, "generic", base + "/g", private=False, uid=uid)
    res = await server._deliver_webhook(g2, "user.joined", {}, single=True)
    check("a hook without allow_private cannot reach loopback", not res["sent"] and len(received) == n and not res["success"], str(res))

    # ---- ntfy
    nt = await hook(db, "ntfy", base + "/topic-SECRETTOPIC", cfg={"token": "tk_SECRET"}, uid=uid)
    res = await server._deliver_webhook(nt, "webhook.test", {"triggered_by": "me"}, single=True)
    path, hdrs, body = received[-1]
    check("ntfy test: status reported, title, priority, bearer, topic path",
          res["status"] == 204 and res["success"] and path == "/topic-SECRETTOPIC" and hdrs["Priority"] == "3"
          and "Title" in hdrs and hdrs["Authorization"] == "Bearer tk_SECRET" and "X-Portal-Signature" not in hdrs, str((res, hdrs)))
    # redirect not followed
    rd = await hook(db, "ntfy", base + "/redirect", uid=uid)
    res = await server._deliver_webhook(rd, "webhook.test", {}, single=True)
    check("non-generic redirects are not followed", res["status"] == 302 and not redirect_hits and not res["success"], str(res))
    gr = await hook(db, "generic", base + "/redirect", uid=uid)
    res = await server._deliver_webhook(gr, "webhook.test", {}, single=True)
    check("a generic allow_private hook does not follow a redirect (it could bounce to the LAN)",
          res["status"] == 302 and not redirect_hits, str(res))
    check("a plain generic hook is still built to follow redirects (unchanged)",
          wf.format_payload("generic", "user.joined", {}, secret="s").follow_redirects is True)

    # ---- gotify
    gt = await hook(db, "gotify", base + "/gotify/", cfg={"token": "GOTIFYTOKEN"}, uid=uid)
    res = await server._deliver_webhook(gt, "user.joined", {"username": "zed"}, single=True)
    path, hdrs, body = received[-1]
    check("gotify: /message, token header only, minimal body",
          path == "/gotify/message" and hdrs["X-Gotify-Key"] == "GOTIFYTOKEN" and b"GOTIFYTOKEN" not in body
          and b"zed" not in body and "GOTIFYTOKEN" not in path, str((path, body)))

    # ---- discord / slack
    dc = await hook(db, "discord", base + "/api/webhooks/1/DISCORDTOKEN", events=["message.created"], uid=uid)
    res = await server._deliver_webhook(dc, "message.created", {"message": "hello world", "username": "alice", "channel": "general"},
                                        meta={"channel_id": 1}, single=True)
    path, hdrs, body = received[-1]
    emb = json.loads(body)
    check("discord embed posted, no message text or author by default",
          res["success"] and emb["embeds"][0]["title"] and "hello world" not in body.decode() and "alice" not in body.decode()
          and emb["allowed_mentions"] == {"parse": []})
    sl = await hook(db, "slack", base + "/services/T/B/SLACKTOKEN", uid=uid, details=True)
    res = await server._deliver_webhook(sl, "message.created", {"message": "<!channel> hi", "username": "al", "channel": "g"},
                                        meta={"channel_id": 1}, single=True)
    body = received[-1][2].decode()
    check("slack text posted with the mention removed", res["success"] and "<!channel>" not in body and "channel>" not in body, body)

    # ---- logs and failure reasons hold no destination or credential
    cur = await db.conn.execute("SELECT * FROM webhook_logs WHERE webhook_id IN (?, ?, ?, ?)", (nt["id"], gt["id"], dc["id"], sl["id"]))
    logs = [dict(r) for r in await cur.fetchall()]
    dump = json.dumps(logs, default=str)
    check("non-generic delivery logs keep no payload and no body", all(l["request_payload"] is None for l in logs) and logs)
    check("no credential in raw log rows", not any(t in dump for t in ("tk_SECRET", "GOTIFYTOKEN", "DISCORDTOKEN", "SLACKTOKEN", "SECRETTOPIC")))

    # ---- 429
    del slept[:]
    rl = await hook(db, "discord", base + "/rl", uid=uid)
    script[:] = [(429, {"Retry-After": "3"}), 204]
    res = await server._deliver_webhook(rl, "user.joined", {})
    check("a 429 waits for Retry-After and then succeeds", res["success"] and slept == [3], str((res, slept)))
    del slept[:]
    script[:] = [(429, {"Retry-After": "99999"}), 204]
    await server._deliver_webhook(rl, "user.joined", {})
    check("Retry-After is capped at 10 minutes", slept == [600], str(slept))
    del slept[:]
    script[:] = [(429, {"Retry-After": "1"})] * 10
    res = await server._deliver_webhook(rl, "user.joined", {})
    w = await db.get_webhook(rl["id"])
    check("at most 3 waits, then dropped; failure count stays 0 and the hook stays enabled",
          len(slept) == 3 and res["status"] == 429 and w["consecutive_failures"] == 0 and w["enabled"] == 1, str((slept, w)))
    # a 429 followed by a 500 is an ordinary failure: counted, and the backoff retries run
    async def sleep_and_unpause(secs):
        slept.append(secs)
        server._webhook_paused_until.clear()    # the real sleep lets the Retry-After pause pass
    server._webhook_sleep = sleep_and_unpause
    for fmt_name in ("generic", "discord"):
        mixed = await hook(db, fmt_name, base + "/mixed-" + fmt_name, uid=uid)
        del slept[:]
        n = len(received)
        script[:] = [(429, {"Retry-After": "1"}), 500, 500, 500, 500]
        res = await server._deliver_webhook(mixed, "user.joined", {})
        w = await db.get_webhook(mixed["id"])
        check(f"{fmt_name}: a 429 then 500s is counted and retried with the backoff delays",
              slept == [1, 10, 60, 300] and w["consecutive_failures"] == 4 and n + 5 == len(received) and res["status"] == 500,
              str((slept, w["consecutive_failures"], res)))
        server._webhook_paused_until.clear()
    # the cap of 3 Retry-After waits covers the whole delivery, backoff retries included
    server._webhook_sleep = sleep_and_unpause
    cap = await hook(db, "discord", base + "/cap", uid=uid)
    del slept[:]
    script[:] = [(429, {"Retry-After": "2"}), 500, (429, {"Retry-After": "2"}), (429, {"Retry-After": "2"}),
                 (429, {"Retry-After": "2"}), (429, {"Retry-After": "2"}), 500, 500, 500]
    await server._deliver_webhook(cap, "user.joined", {})
    check("Retry-After waits are capped at 3 across the backoff retries too", slept.count(2) == 3, str(slept))
    server._webhook_paused_until.clear()
    # deleting a hook forgets its Retry-After pause
    server._webhook_paused_until[cap["id"]] = server.monotonic() + 100
    server._webhook_rate_limits[cap["id"]] = [1.0]
    class _Req:
        match_info = {"id": str(cap["id"])}
    _real_auth, _real_get_user = server.authenticate_request, db.get_user_by_id
    async def _fake_auth(request):
        class T: user_id = uid
        return T()
    async def _fake_user(i):
        return {"id": uid, "is_admin": True, "role": "admin", "username": "owner"}
    server.authenticate_request, db.get_user_by_id = _fake_auth, _fake_user
    try:
        await server.http_delete_webhook(_Req())
    finally:
        server.authenticate_request, db.get_user_by_id = _real_auth, _real_get_user
    check("deleting a user hook clears its Retry-After pause", cap["id"] not in server._webhook_paused_until)
    server._webhook_sleep = fake_sleep
    # a receiver still in its wait is not hit by new deliveries
    server._webhook_paused_until[rl["id"]] = server.monotonic() + 100
    n = len(received)
    res = await server._deliver_webhook(rl, "user.joined", {})
    check("deliveries to a paused receiver are dropped, not queued", len(received) == n and not res["sent"])
    server._webhook_paused_until.clear()
    script[:] = []
    # Test route behaviour: single reports a 429 at once
    del slept[:]
    script[:] = [(429, {"Retry-After": "5"})]
    res = await server._deliver_webhook(rl, "webhook.test", {}, single=True)
    check("single attempt reports 429 without waiting", res["status"] == 429 and not slept)
    # other failures keep counting; auto-disable at 10
    fl = await hook(db, "generic", base + "/fail", uid=uid)
    for _ in range(10):
        script[:] = [500]
        await server._deliver_webhook(fl, "webhook.test", {}, single=True)
    w = await db.get_webhook(fl["id"])
    check("ten 500s still auto-disable", w["enabled"] == 0 and w["consecutive_failures"] == 10, str(w))
    # failure text of a non-generic hook has no URL
    bad = await hook(db, "ntfy", "http://127.0.0.1:1/SECRETPATH-xyz", uid=uid)
    res = await server._deliver_webhook(bad, "webhook.test", {}, single=True)
    w = await db.get_webhook(bad["id"])
    check("failure text of a non-generic hook names no URL",
          "SECRETPATH" not in json.dumps(res) and "SECRETPATH" not in (w["last_failure_reason"] or ""), str(res))

    # ---- the portal's own port is refused even with allow_private
    own = await hook(db, "ntfy", f"http://127.0.0.1:{Config.PORT}/x", uid=uid)
    res = await server._deliver_webhook(own, "webhook.test", {}, single=True)
    check("allow_private still refuses the portal's own port", not res["sent"], str(res))
    check("validate refuses own port, link-local and metadata under allow_private",
          await server._validate_webhook_url(f"http://127.0.0.1:{Config.PORT}/", True) == "URL points at the portal itself"
          and await server._validate_webhook_url("http://169.254.169.254/", True)
          and await server._validate_webhook_url("http://[fe80::1]/", True)
          and await server._validate_webhook_url("http://127.0.0.1:9/", True) is None
          and await server._validate_webhook_url("http://127.0.0.1:9/", False))

    # ---- the blocking socket lookup (psutil, host names) runs off the event loop
    import threading
    main_thread = threading.get_ident()
    seen_threads = []
    stub_eps = server._own_endpoints
    server._own_endpoints = lambda: (seen_threads.append(threading.get_ident()), stub_eps())[1]
    await server._validate_webhook_url("http://127.0.0.1:9/", True)
    thr = await hook(db, "ntfy", base + "/thr", uid=uid)
    await server._deliver_webhook(thr, "webhook.test", {}, single=True)
    server._own_endpoints = stub_eps
    check("the own-endpoint lookup runs in a worker thread for validation and delivery",
          len(seen_threads) >= 2 and all(t != main_thread for t in seen_threads), str(seen_threads))

    # ---- delivery asks for the private-only connector exactly for plain http under allow_private
    real_connector = server._SSRFSafeConnector
    kw_seen = []

    def spy_connector(**kw):
        kw_seen.append(kw.get("private_only"))
        return real_connector(**kw)
    server._SSRFSafeConnector = spy_connector
    try:
        ph = await hook(db, "ntfy", base + "/spy", uid=uid)                    # http, allow_private
        await server._deliver_webhook(ph, "webhook.test", {}, single=True)
        gh = await hook(db, "generic", base + "/spy", uid=uid, private=True)   # also http, allow_private
        await server._deliver_webhook(gh, "webhook.test", {}, single=True)
    finally:
        server._SSRFSafeConnector = real_connector
    check("delivery asks for the private-only connector for http under allow_private", kw_seen == [True, True], str(kw_seen))

    # ---- a non-generic hook narrowed to allow_private off (saving it is never refused) is not
    # delivered over plain http: the default connector would accept a public address
    before = len(received)
    connectors_made = []

    def counting_connector(**kw):
        connectors_made.append(kw)
        return real_connector(**kw)
    server._SSRFSafeConnector = counting_connector
    try:
        for nfmt in ("ntfy", "gotify", "discord", "slack"):
            nh = await hook(db, nfmt, base + "/narrowed", uid=uid, private=False, cfg={"token": "tok"} if nfmt in ("ntfy", "gotify") else None)
            nres = await server._deliver_webhook(nh, "webhook.test", {}, single=True)
            check(f"{nfmt}: plain http without allow_private is refused at delivery",
                  not nres["sent"] and not nres["success"] and "https" in (nres["error"] or ""), str(nres))
    finally:
        server._SSRFSafeConnector = real_connector
    check("a narrowed non-generic http hook opens no connection and reaches no receiver",
          len(received) == before and not connectors_made, f"{len(received) - before} {connectors_made}")

    # ---- plain http under allow_private only reaches private or loopback addresses
    # (address literals only: nothing is resolved or dialled here; the connector itself
    # is exercised in test_webhook_host_policy.py)
    check("validate: allow_private + http to a public address is refused, https passes",
          await server._validate_webhook_url("http://93.184.216.34/x", True)
          and await server._validate_webhook_url("https://93.184.216.34/x", True) is None
          and await server._validate_webhook_url("http://192.168.1.5/x", True) is None
          and await server._validate_webhook_url("http://0.1.2.3/x", True))

    # ---- discovery of the portal's own listening sockets (real psutil path)
    import socket as _socket
    server._own_endpoints = real_endpoints
    server._own_endpoints_cache = (0.0, frozenset(), frozenset())
    ls = _socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    lw = _socket.socket()
    lw.bind(("0.0.0.0", 0))
    lw.listen(1)
    pl, pw = ls.getsockname()[1], lw.getsockname()[1]
    check("a socket bound to one address blocks exactly that address and port",
          server._own_endpoint_blocked("127.0.0.1", pl) and not server._own_endpoint_blocked("127.0.0.1", pl + 1)
          and not server._own_endpoint_blocked("10.9.9.9", pl))
    check("a wildcard socket blocks every loopback address on its port, not other hosts",
          server._own_endpoint_blocked("127.0.0.1", pw) and server._own_endpoint_blocked("127.0.0.2", pw)
          and server._own_endpoint_blocked("::ffff:127.0.0.1", pw) and not server._own_endpoint_blocked("203.0.113.5", pw))
    ls.close()
    lw.close()
    server._own_endpoints = lambda: (frozenset({("0.0.0.0", Config.PORT)}), frozenset())

    # ---- stage mode only reaches the sink
    Config.STAGE_MODE = True
    try:
        n = len(received)
        res = await server._deliver_webhook(nt, "webhook.test", {}, single=True)
        check("stage mode sends nothing without a sink", len(received) == n and not res["sent"])
        await db.set_setting("stage_webhook_sink_port", str(srv.port))
        res = await server._deliver_webhook(nt, "webhook.test", {}, single=True)
        check("stage mode reaches the 127.0.0.1 sink port", res["success"] and len(received) == n + 1)
        nonlocal_hook = dict(nt, allow_private=False)
        res = await server._deliver_webhook(nonlocal_hook, "webhook.test", {}, single=True)
        check("stage mode needs allow_private even for the sink", not res["sent"])
        other = dict(nt, url="http://127.0.0.1:%d/x" % (srv.port + 1))
        res = await server._deliver_webhook(other, "webhook.test", {}, single=True)
        check("stage mode refuses any other port", not res["sent"])
    finally:
        Config.STAGE_MODE = False

    # ---- dispatch: channels and streams
    await db.conn.execute("INSERT INTO chat_channels (name, visibility) VALUES ('pubch', 'public')")
    await db.conn.execute("INSERT INTO chat_channels (name, visibility) VALUES ('privch', 'private')")
    await db.conn.commit()
    pub = (await (await db.conn.execute("SELECT id FROM chat_channels WHERE name='pubch'")).fetchone())["id"]
    priv = (await (await db.conn.execute("SELECT id FROM chat_channels WHERE name='privch'")).fetchone())["id"]
    check("public channel may be seen by a third party", await server._third_party_may_see("message.created", {"channel_id": pub}))
    check("private channel never", not await server._third_party_may_see("message.created", {"channel_id": priv}))
    check("missing channel id fails closed", not await server._third_party_may_see("message.created", {})
          and not await server._third_party_may_see("message.deleted", {"channel_id": 99999}))
    real = db.get_stream_by_chat_channel

    async def hidden(_cid):
        return {"id": 1, "user_id": 5, "is_public": 0, "chat_channel_default": 0, "chat_channel_all_public": 0,
                "chat_channel_owner_ids": [5]}
    db.get_stream_by_chat_channel = hidden
    check("chat of a non-public stream never", not await server._third_party_may_see("message.created", {"channel_id": pub}))
    db.get_stream_by_chat_channel = real
    check("stream events only for public streams",
          await server._third_party_may_see("stream.live", {"stream_public": True})
          and not await server._third_party_may_see("stream.live", {"stream_public": False})
          and not await server._third_party_may_see("stream.offline", None))

    # end to end through fire_webhook_event
    for t in list(await db.get_all_webhooks()):
        await db.update_webhook(t["id"], enabled=0)
    star = await hook(db, "ntfy", base + "/star", events=["*"], uid=uid)
    named = await hook(db, "ntfy", base + "/named", events=["message.created"], uid=uid, details=True)
    gen = await hook(db, "generic", base + "/gen", events=["*"], uid=uid)
    del received[:]

    async def fire(event, payload, meta):
        await server.fire_webhook_event(event, payload, meta=meta)
        await asyncio.sleep(0.4)

    await fire("message.created", {"message": "hi", "username": "alice", "channel": "pubch"}, {"channel_id": priv})
    paths = [r[0] for r in received]
    check("private channel: only the generic hook gets message.created (unchanged), no ntfy hook",
          paths == ["/gen"], str(paths))
    del received[:]
    await fire("message.created", {"message": "hi there", "username": "Anonymous", "channel": "pubch"},
               {"channel_id": pub, "anonymous": True})
    paths = sorted(r[0] for r in received)
    check("public channel: '*' ntfy hook skips message.created, the named one gets it",
          paths == ["/gen", "/named"], str(paths))
    named_body = [r for r in received if r[0] == "/named"][0][2].decode()
    check("named hook with details: Anonymous and text, no author id",
          "Anonymous" in named_body and "hi there" in named_body and "user_id" not in named_body, named_body)
    del received[:]
    await fire("webhook.test", {}, None)
    check("webhook.test is never dispatched to user hooks", not received)
    await fire("user.joined", {"user_id": 3, "username": "zed"}, None)
    star_body = [r for r in received if r[0] == "/star"][0][2].decode()
    check("minimal user.joined: no username by default", "zed" not in star_body, star_body)
    # ---- presence events: explicit in a non-generic format, never for an appear-offline member
    pres = await hook(db, "ntfy", base + "/pres", events=["user.connected", "user.disconnected"], uid=uid)
    for ev in ("user.connected", "user.disconnected"):
        del received[:]
        await fire(ev, {"user_id": uid, "username": "owner"}, {"user_id": uid})
        paths = sorted(r[0] for r in received)
        check(f"{ev}: named ntfy hook and generic '*' get it, the ntfy '*' hook does not",
              paths == ["/gen", "/pres"], str(paths))
    await db.conn.execute("UPDATE users SET status_preference = 'offline' WHERE id = ?", (uid,))
    await db.conn.commit()
    for ev in ("user.connected", "user.disconnected"):
        del received[:]
        await fire(ev, {"user_id": uid, "username": "owner"}, {"user_id": uid})
        paths = sorted(r[0] for r in received)
        check(f"{ev}: an appear-offline member is not announced to a non-generic hook (generic unchanged)",
              paths == ["/gen"], str(paths))
    del received[:]
    await fire("user.connected", {"user_id": uid, "username": "owner"}, None)
    check("presence event without a member id fails closed for non-generic", [r[0] for r in received] == ["/gen"],
          str([r[0] for r in received]))
    await db.conn.execute("UPDATE users SET status_preference = NULL WHERE id = ?", (uid,))
    await db.conn.commit()
    await db.update_webhook(pres["id"], enabled=0)
    # a user hook row listing a future/unknown event gets nothing: user hooks use an allow-list
    fut = await hook(db, "generic", base + "/future", events=["ops.future", "*"], uid=uid)
    del received[:]
    await fire("ops.future", {"x": 1}, None)
    check("an event outside the user allow-list reaches no user hook, not even through '*'",
          "/future" not in [r[0] for r in received], str([r[0] for r in received]))
    await db.update_webhook(fut["id"], enabled=0)
    del received[:]

    # ---- a retry applies the dispatch rules again
    rt = await hook(db, "generic", base + "/retry", events=["message.created"], uid=uid)
    del received[:]

    async def flip_then_sleep(secs):
        # while the delivery waits, the owner switches the hook to Discord
        await db.update_webhook(rt["id"], format="discord")
    server._webhook_sleep = flip_then_sleep
    script[:] = [500]
    await server._deliver_webhook(rt, "message.created",
                                  {"message": "private words", "username": "al", "channel": "privch"},
                                  meta={"channel_id": priv})
    server._webhook_sleep = fake_sleep
    check("a retry does not send a private channel's event to a hook that became non-generic",
          [r[0] for r in received] == ["/retry"], str([r[0] for r in received]))
    await db.update_webhook(rt["id"], format="generic", events=["message.created"])
    del received[:]

    async def unsub_then_sleep(secs):
        await db.update_webhook(rt["id"], events=["user.joined"])
    server._webhook_sleep = unsub_then_sleep
    script[:] = [500]
    await server._deliver_webhook(await db.get_webhook_for_delivery(rt["id"]), "message.created",
                                  {"message": "x", "channel": "pubch"}, meta={"channel_id": pub})
    server._webhook_sleep = fake_sleep
    check("a retry is dropped when the hook no longer subscribes to the event",
          [r[0] for r in received] == ["/retry"], str([r[0] for r in received]))
    await db.update_webhook(rt["id"], enabled=0)

    # ---- a Retry-After wait re-applies the rules before every resend
    async def rl_case(fmt, change, *, event="message.created", meta=None, url_path="/rl2", details=False):
        """Receiver always answers 429 Retry-After. `change` runs during the first wait.
        Returns the paths the receiver saw and the result."""
        h = await hook(db, fmt, base + url_path, events=[event], uid=uid, details=details)
        server._webhook_paused_until.clear()
        del received[:]
        state = {"n": 0}

        async def sleeper(secs):
            state["n"] += 1
            if state["n"] == 1:
                await change(h)
        server._webhook_sleep = sleeper
        script[:] = [(429, {"Retry-After": "1"})] * 10
        res = await server._deliver_webhook(h, event, {"message": "x", "channel": "pubch"}, meta=meta or {"channel_id": pub})
        server._webhook_sleep = fake_sleep
        script[:] = []
        return h, [r[0] for r in received], res

    async def noop(h):
        pass
    h, seen, res = await rl_case("discord", noop)
    check("control: an unchanged hook is resent up to 3 more times after a 429", len(seen) == 4, str(seen))
    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], enabled=0))
    check("a hook switched off during the wait gets no resend", len(seen) == 1, str(seen))
    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], url=base + "/rotated"))
    check("a hook re-aimed during the wait does not hit the old URL again and not the new one",
          [x for x in seen] == ["/rl2"], str(seen))
    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], format="slack"))
    check("a format change during the wait stops the resend", len(seen) == 1, str(seen))
    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], events=["user.joined"]))
    check("an unsubscribed hook gets no resend", len(seen) == 1, str(seen))
    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], format_config={"token": "NEW"}))
    check("rotated credentials stop the resend of the request built with the old ones", len(seen) == 1, str(seen))

    h, seen, res = await rl_case("discord", lambda h: db.update_webhook(h["id"], include_details=0), details=True)
    check("details switched off during the wait: the built body with the message text is not resent",
          len(seen) == 1, str(seen))

    async def make_private(h):
        await db.conn.execute("UPDATE chat_channels SET visibility = 'private' WHERE id = ?", (pub,))
        await db.conn.commit()
    h, seen, res = await rl_case("discord", make_private)
    await db.conn.execute("UPDATE chat_channels SET visibility = 'public' WHERE id = ?", (pub,))
    await db.conn.commit()
    check("a channel made private during the wait gets no resend to a third-party format",
          len(seen) == 1, str(seen))

    async def drop(h):
        await db.conn.execute("DELETE FROM webhooks WHERE id = ?", (h["id"],))
        await db.conn.commit()
    h, seen, res = await rl_case("discord", drop)
    cur = await db.conn.execute("SELECT COUNT(*) AS n FROM webhook_logs WHERE webhook_id = ?", (h["id"],))
    check("a deleted hook gets no resend and no log row is written for it",
          len(seen) == 1 and (await cur.fetchone())["n"] == 0 and res["error"] == "webhook changed while waiting",
          str((seen, res)))
    server._webhook_paused_until.clear()

    await srv.close()
    await db.conn.close()


asyncio.run(main())
if failures:
    print(f"{len(failures)} failed")
sys.exit(1 if failures else 0)
