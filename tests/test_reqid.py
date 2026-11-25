"""Request ID and unreachable-upstream page checks.

Part 1: the ID, the log filter and the text and JSON formats (real logger.setup_logging
into a temporary directory). Part 2: the real middleware, response hook, HTTP proxy and
SearXNG proxy handlers behind the real security middleware, with a local echo upstream, a
port nobody listens on, and a fake login. Part 3: the wiring in create_app.

User connections may not target loopback (the outbound host policy), so this test replaces
the policy connector and the resolve checks with plain ones, as tests/test_proxyfix.py does.

Run:  venv/bin/python tests/test_reqid.py        (takes a few seconds)
"""

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, make_mocked_request  # noqa: E402

import logger as portal_logger  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


TMP = Path(tempfile.mkdtemp(prefix="reqid_test_"))
LOGDIR = TMP / "logs"
ALPHABET = set(portal_logger.REQUEST_ID_ALPHABET)

# ---------------------------------------------------------------------------
# Part 1: the ID and the log format
# ---------------------------------------------------------------------------

ids = {portal_logger.new_request_id() for _ in range(2000)}
check("ids: 8 characters from the safe alphabet",
      all(len(i) == 8 and set(i) <= ALPHABET for i in ids), str(list(ids)[:3]))
check("ids: random (2000 draws, no repeats worth worrying about)", len(ids) > 1990, str(len(ids)))
check("ids: the alphabet has no quote, space, bracket, percent or control character",
      portal_logger.REQUEST_ID_ALPHABET.isalnum() and portal_logger.REQUEST_ID_ALPHABET.isascii())

saved_settings = dict(portal_logger.LOG_SETTINGS)
saved_paths = (portal_logger.LOG_DIR, portal_logger.LOG_FILE, portal_logger.AUDIT_FILE)
root = logging.getLogger()
saved_handlers = list(root.handlers)
saved_level = root.level


def log_lines(structured):
    portal_logger.setup_logging(level="INFO", log_dir=LOGDIR, console_enabled=False, file_enabled=True,
                                structured=structured)
    lg = logging.getLogger("portal")
    tok = portal_logger.set_request_id("abcd2345")
    try:
        lg.error("inside the request password=hunter2 end")
    finally:
        portal_logger.reset_request_id(tok)
    lg.error("outside any request")
    for h in logging.getLogger().handlers:
        h.flush()
    return (LOGDIR / "portal.log").read_text(encoding="utf-8").splitlines()


try:
    lines = log_lines(False)
    inside = [x for x in lines if "inside the request" in x][0]
    outside = [x for x in lines if "outside any request" in x][0]
    check("text log: a line from inside a request carries the ID once, after the logger name, level token intact",
          re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[ERROR\] portal: \[req=abcd2345\] inside the request", inside)
          and inside.count("abcd2345") == 1, inside)
    check("text log: redaction still works on a line that has the ID",
          "hunter2" not in inside and "password=[REDACTED]" in inside and "[req=abcd2345]" in inside, inside)
    check("text log: a line outside a request is exactly the old format",
          re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[ERROR\] portal: outside any request$", outside), outside)
    (LOGDIR / "portal.log").unlink()
    lines = log_lines(True)
    rec_in = json.loads([x for x in lines if "inside the request" in x][0])
    rec_out = json.loads([x for x in lines if "outside any request" in x][0])
    check("json log: request_id field inside a request, none outside",
          rec_in.get("request_id") == "abcd2345" and "request_id" not in rec_out, str((rec_in, rec_out)))
finally:
    for h in list(root.handlers):
        h.close()
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    portal_logger.LOG_SETTINGS.clear()
    portal_logger.LOG_SETTINGS.update(saved_settings)
    portal_logger.LOG_DIR, portal_logger.LOG_FILE, portal_logger.AUDIT_FILE = saved_paths

# ---------------------------------------------------------------------------
# Part 2: the handlers behind the real middleware
# ---------------------------------------------------------------------------

CONNECTION = {}
SEARX = {"available": True, "port": 0}
FORGED = ["EVIL-ID-1 [ERROR] portal: forged line", "<script>alert(1)</script>", "%0aINJECTED%0d", "a" * 300]
MARK = "QWERTYZ9"          # a marker used for the raw-socket injection attempt


async def fake_auth(request):
    class T:
        user_id = 1
        token_id = "t"
    return T()


async def fake_get_connection(conn_id, user_id):
    return dict(CONNECTION)


async def fake_usage(*a, **k):
    return None


async def fake_resolve(host, port=0):
    return []


async def fake_user(user_id):
    return {"id": user_id}


async def fake_token_valid(token_id):
    return True


async def fake_sx_status():
    return SEARX["available"], SEARX["port"]


async def echo_headers(request):
    return web.json_response({k.lower(): v for k, v in request.headers.items()})


async def slow_search(request):
    await asyncio.sleep(5)
    return web.Response(text="late")


async def sets_request_id(request):
    return web.Response(text="body", headers={"X-Request-ID": "UPSTREAM-ID"})


async def streams_request_id(request):
    resp = web.StreamResponse(headers={"X-Request-ID": "UPSTREAM-ID"})
    await resp.prepare(request)
    await resp.write(b"x" * 200000)
    await resp.write_eof()
    return resp


async def a_page(request):
    log = logging.getLogger("portal")
    log.warning("handler line one")
    await asyncio.sleep(0)
    log.warning("handler line two")
    return web.Response(text="page")


SPAWNED = []


async def spawns_task(request):
    async def later():
        logging.getLogger("portal").warning("spawned inside")
        await asyncio.sleep(0.3)
        logging.getLogger("portal").warning("spawned after the response")
        SPAWNED.append(1)
    SPAWNED.append(asyncio.ensure_future(later()))
    await asyncio.sleep(0.05)       # the task's first line is written while the request is still handled
    return web.Response(text="spawned")


async def redirects(request):
    raise web.HTTPFound("/somewhere")


async def socket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.send_str("hello")
    await ws.close()
    return ws


async def captured(request):
    return web.json_response({"rid": request.get("request_id"), "ctx": portal_logger.current_request_id()})


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def main():
    up_app = web.Application()
    up_app.router.add_get("/echo", echo_headers)
    up_app.router.add_get("/search/echo", echo_headers)
    up_app.router.add_get("/search/slow", slow_search)
    up_app.router.add_get("/setid", sets_request_id)
    up_app.router.add_get("/streamid", streams_request_id)
    upstream = TestServer(up_app, host="127.0.0.1")
    await upstream.start_server()

    app = web.Application(middlewares=[server.request_id_middleware, server.security_headers_middleware])
    server.register_request_ids(app)
    app.router.add_route("*", "/proxy/{conn_id}", server.http_proxy_connection)
    app.router.add_route("*", "/proxy/{conn_id}/{path:.*}", server.http_proxy_connection)
    app.router.add_route("*", "/search/{path:.*}", server.http_searxng_proxy)
    app.router.add_get("/page", a_page)
    app.router.add_get("/redir", redirects)
    app.router.add_get("/spawn", spawns_task)
    app.router.add_get("/ws", socket_handler)
    app.router.add_get("/captured", captured)
    portal = TestServer(app, host="127.0.0.1")
    await portal.start_server()
    base = f"http://127.0.0.1:{portal.port}"

    saved = (server.authenticate_request, server.db.get_accessible_connection,
             server.db.record_connection_usage, server.resolve_checked_host,
             server.resolve_checked_host_cached, server._SSRFSafeConnector, server._searxng_status,
             server.db.get_user_by_id, server.db.is_token_valid)
    server.authenticate_request = fake_auth
    server.db.get_accessible_connection = fake_get_connection
    server.db.record_connection_usage = fake_usage
    saved_note = server.db.note_connection_opened
    server.db.note_connection_opened = fake_usage  # the last-opened write needs a database too
    server.resolve_checked_host = fake_resolve
    server.resolve_checked_host_cached = fake_resolve
    server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)
    server._searxng_status = fake_sx_status
    server.db.get_user_by_id = fake_user
    server.db.is_token_valid = fake_token_valid
    old_host = Config.HOSTNAME
    Config.HOSTNAME = "127.0.0.1"

    # the real log setup, into the temporary directory
    (LOGDIR / "portal.log").unlink(missing_ok=True)
    portal_logger.setup_logging(level="INFO", log_dir=LOGDIR, console_enabled=False, file_enabled=True,
                                structured=False)

    def log_text():
        for h in logging.getLogger().handlers:
            h.flush()
        return (LOGDIR / "portal.log").read_text(encoding="utf-8")

    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c:
            # --- the ID on ordinary responses
            async with c.get(f"{base}/captured") as r:
                body = await r.json()
                rid = r.headers.get("X-Request-ID")
            check("middleware: an ID of 8 safe characters in the header, on the request and in the context",
                  rid and len(rid) == 8 and set(rid) <= ALPHABET and body["rid"] == rid and body["ctx"] == rid,
                  f"{rid} {body}")
            async with c.get(f"{base}/captured") as r:
                await r.read()
                check("middleware: a new ID for each request", r.headers.get("X-Request-ID") != rid)
            async with c.get(f"{base}/nothing-here") as r:
                await r.read()
                check("response hook: the 404 has the header", r.status == 404 and len(r.headers.get("X-Request-ID", "")) == 8,
                      f"{r.status} {dict(r.headers)}")
            async with c.get(f"{base}/redir", allow_redirects=False) as r:
                check("response hook: the redirect has the header", r.status == 302 and len(r.headers.get("X-Request-ID", "")) == 8)
            async with c.get(f"{base}/page") as r:
                page_rid = r.headers.get("X-Request-ID")
                await r.read()
            text = log_text()
            one = [x for x in text.splitlines() if "handler line one" in x]
            two = [x for x in text.splitlines() if "handler line two" in x]
            check("log: both lines a handler wrote (across an await) carry that request's ID",
                  len(one) == 1 and len(two) == 1 and f"[req={page_rid}]" in one[0] and f"[req={page_rid}]" in two[0],
                  str((one, two, page_rid)))
            logging.getLogger("portal").warning("after the request")
            tail = [x for x in log_text().splitlines() if "after the request" in x][0]
            check("log: a line written after the request has no ID", "[req=" not in tail, tail)
            async with c.get(f"{base}/page") as r1:
                id1 = r1.headers["X-Request-ID"]
                await r1.read()
            check("log: requests do not share an ID", id1 != page_rid)

            # --- a task the request started does not keep the ID once the request is over
            async with c.get(f"{base}/spawn") as r:
                spawn_rid = r.headers["X-Request-ID"]
                await r.read()
            await asyncio.wait_for(SPAWNED[0], 5)
            text = log_text()
            inside_l = [x for x in text.splitlines() if "spawned inside" in x]
            after_l = [x for x in text.splitlines() if "spawned after the response" in x]
            check("log: a background task's line is tagged while the request runs and untagged after it ended",
                  len(inside_l) == 1 and f"[req={spawn_rid}]" in inside_l[0] and len(after_l) == 1
                  and "[req=" not in after_l[0], str((inside_l, after_l)))

            # --- WebSocket: no header on the handshake or after it
            async with c.ws_connect(f"{base}/ws") as ws:
                hdrs = dict(ws._response.headers)
                msg = await ws.receive()
            check("websocket: the upgrade carries no X-Request-ID and the socket works",
                  "X-Request-ID" not in hdrs and msg.data == "hello", str(hdrs))

            # --- an inbound ID is never trusted, echoed or logged
            for forged in FORGED:
                async with c.get(f"{base}/page", headers={"X-Request-ID": forged}) as r:
                    got = r.headers.get("X-Request-ID")
                    await r.read()
                check(f"inbound: {forged[:24]!r} is not echoed, the ID is ours", got != forged and len(got) == 8, str(got))
            for hname in ("X-Correlation-ID", "Request-Id", "X-Amzn-Trace-Id"):
                async with c.get(f"{base}/page", headers={hname: "FORGED-CORR-1"}) as r:
                    await r.read()
                    check(f"inbound: {hname} is not copied to a response header",
                          "FORGED-CORR-1" not in json.dumps(dict(r.headers)))
            # a raw request with a bare line feed inside the value (a log-injection attempt)
            reader, writer = await asyncio.open_connection("127.0.0.1", portal.port)
            writer.write(("GET /page HTTP/1.1\r\nHost: x\r\nX-Request-ID: " + MARK + "\nINJECTED [ERROR] forged\r\n\r\n").encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), 5)
            writer.close()
            await asyncio.sleep(0.2)
            text = log_text()
            check("inbound: a header value with a bare line feed never reaches the log",
                  MARK not in text and "INJECTED" not in text and "malformed request" in text,
                  text[-300:])
            check("inbound: nor the answer (aiohttp's 400 for the refused bytes is fixed text)",
                  MARK.encode() not in raw and b"INJECTED" not in raw and raw.startswith(b"HTTP/1.")
                  and b" 400 " in raw.split(b"\r\n")[0] and raw.rstrip().endswith(b"Bad Request"),
                  raw[:300].decode("latin-1"))
            check("inbound: that malformed request carries no X-Request-ID header of ours",
                  b"X-Request-ID:" not in raw.split(b"\r\n\r\n")[0])
            for forged in FORGED[:2]:
                check(f"inbound: {forged[:24]!r} is not in the log", forged not in text and "forged line" not in text)

            # --- proxied responses: ours replaces the upstream's
            CONNECTION.clear()
            CONNECTION.update({"id": 5, "type": "http", "host": "127.0.0.1", "port": upstream.port,
                               "name": "Echo", "config": {}})
            for path in ("setid", "streamid"):
                async with c.get(f"{base}/proxy/xyz/{path}", headers={"X-Request-ID": "FORGED-IN"}) as r:
                    await r.read()
                    vals = r.headers.getall("X-Request-ID", [])
                check(f"proxy: {path}: the response has exactly our ID, not the upstream's or the client's",
                      r.status == 200 and len(vals) == 1 and len(vals[0]) == 8 and vals[0] not in ("UPSTREAM-ID", "FORGED-IN"),
                      f"{r.status} {vals}")
            # SearXNG: the client's ID is not passed on
            SEARX.update(available=True, port=upstream.port)
            async with c.get(f"{base}/search/echo", headers={"X-Request-ID": "FORGED-IN", "X-Correlation-ID": "FORGED-IN"}) as r:
                seen = await r.json()
            check("searxng: no request ID header is forwarded to the search service",
                  not any(k in seen for k in ("x-request-id", "x-correlation-id", "request-id")), str(seen))

            # a forward_headers pattern never passes a client's request ID to the connection's own service
            for pats in (["*"], ["x-*"], ["x-request-id", "x-correlation-id", "request-id", "x-user-id"]):
                CONNECTION.update({"config": {"forward_headers": pats}})
                async with c.get(f"{base}/proxy/xyz/echo", headers={
                        "X-Request-ID": "FORGED-IN", "X-Correlation-ID": "FORGED-IN", "Request-Id": "FORGED-IN",
                        "X-User-Id": "kept"}) as r:
                    seen = await r.json()
                check(f"proxy: forward_headers {pats[0]!r}: the client's request ID headers are not copied, others are",
                      r.status == 200 and not any(k in seen for k in ("x-request-id", "x-correlation-id", "request-id"))
                      and "FORGED-IN" not in json.dumps(seen) and seen.get("x-user-id") == "kept", str(seen))
            CONNECTION.update({"config": {}})

            # --- the page for a service that is down
            dead = free_port()
            CONNECTION.update({"port": dead, "name": 'My <b>App</b> & "co"'})
            async with c.get(f"{base}/proxy/xyz/some/path", headers={"Accept": "text/html"}) as r:
                page = await r.text()
                header_id = r.headers.get("X-Request-ID")
                status = r.status
                retry = r.headers.get("Retry-After")
                csp = r.headers.get("Content-Security-Policy", "")
                cache = r.headers.get("Cache-Control")
            m = re.search(r'id="upstream-error-id">([^<]*)<', page)
            page_id = m.group(1) if m else None
            check("down upstream: 502 page with the ID in the header and in the page, the same ID",
                  status == 502 and page_id == header_id and len(page_id or "") == 8, f"{status} {page_id} {header_id}")
            check("down upstream: the service name is escaped",
                  "My &lt;b&gt;App&lt;/b&gt; &amp; &quot;co&quot;" in page and "<b>App" not in page, page[:400])
            check("down upstream: no host, address, port or exception text in the page",
                  "127.0.0.1" not in page and str(dead) not in page and "localhost" not in page
                  and "ClientConnector" not in page and "Connect call failed" not in page and "Cannot connect" not in page,
                  page)
            check("down upstream: the dashboard link has no target (the embedded frame cannot navigate the top window)",
                  "_top" not in page and 'id="upstream-error-home"' in page and "target=" not in page)
            check("down upstream: a retry countdown from a static script, no inline script, no inline handler",
                  'data-retry="15"' in page and '<script src="/static/js/upstream-error.js?v=2"></script>' in page
                  and page.count("<script") == 1 and "onclick" not in page and "javascript:" not in page)
            check("down upstream: Retry-After and no-store, and the portal CSP is the one the middleware adds, unchanged",
                  retry == "15" and cache == "no-store" and "script-src 'self' 'unsafe-inline' blob:" in csp and "jsdelivr" not in csp
                  and "default-src 'self'" in csp, f"{retry} {cache} {csp}")
            text = log_text()
            err = [x for x in text.splitlines() if f"[req={header_id}]" in x and "Upstream error 502" in x]
            check("down upstream: the ID finds exactly one error line, with the service and the real reason",
                  len(err) == 1 and "My <b>App</b>" in err[0] and "ClientConnectorError" in err[0] and str(dead) in err[0],
                  str(err))
            check("down upstream: the ID appears on no other line than that one",
                  len([x for x in text.splitlines() if header_id in x]) == 1)
            async with c.post(f"{base}/proxy/xyz/some/path", data=b"x") as r:
                page = await r.text()
            check("down upstream: a POST page does not reload by itself", 'data-auto="0"' in page, page[:300])
            for hdrs in ({"Accept": "application/json"}, {"X-Requested-With": "XMLHttpRequest"},
                         {"Accept": "application/json, text/plain, */*"}):
                async with c.get(f"{base}/proxy/xyz/x", headers=hdrs) as r:
                    data = await r.json()
                    check(f"down upstream: {list(hdrs)[0]} gets JSON with request_id",
                          r.status == 502 and data.get("request_id") == r.headers.get("X-Request-ID")
                          and data.get("retry_after") == 15 and "127.0.0.1" not in json.dumps(data)
                          and r.content_type == "application/json", str(data))
            async with c.get(f"{base}/proxy/xyz/x", headers={"Accept": "text/html,application/json;q=0.9"}) as r:
                await r.read()
                check("down upstream: a browser Accept that also lists JSON still gets the page", r.content_type == "text/html")

            # --- SearXNG not running: 503 page and JSON
            SEARX.update(available=False)
            async with c.get(f"{base}/search/", headers={"Accept": "text/html"}) as r:
                page = await r.text()
                sid = r.headers.get("X-Request-ID")
            check("searxng off: 503 page with the name, the ID and Retry-After",
                  r.status == 503 and ">Search is not available" in page and f">{sid}<" in page
                  and r.headers.get("Retry-After") == "30", f"{r.status} {page[:300]}")
            check("searxng off: no ERROR line per request (a state, not a failure)",
                  not [x for x in log_text().splitlines() if f"[req={sid}]" in x and "[ERROR]" in x])
            info_lines = [x for x in log_text().splitlines() if "[INFO]" in x and "not enabled or not running" in x]
            check("searxng off: one INFO line for the first request", len(info_lines) == 1, str(info_lines))
            for _ in range(3):
                async with c.get(f"{base}/search/", headers={"Accept": "text/html"}) as r:
                    await r.read()
            info_lines = [x for x in log_text().splitlines() if "not enabled or not running" in x]
            check("searxng off: three more requests within 10 minutes add no line", len(info_lines) == 1, str(info_lines))
            server._searxng_unavailable_logged_at -= 601
            async with c.get(f"{base}/search/", headers={"Accept": "text/html"}) as r:
                await r.read()
            info_lines = [x for x in log_text().splitlines() if "not enabled or not running" in x]
            check("searxng off: after 10 minutes the next request logs again", len(info_lines) == 2, str(info_lines))
            async with c.get(f"{base}/search/?format=json") as r:
                data = await r.json()
            check("searxng off: format=json keeps its JSON error and gains request_id",
                  r.status == 503 and data["error"] == "Search is not enabled on this portal"
                  and data["request_id"] == r.headers["X-Request-ID"], str(data))

            # --- SearXNG up but hung: 504 through the same page
            SEARX.update(available=True, port=upstream.port)
            old_to = server._SEARXNG_PROXY_TIMEOUT
            server._SEARXNG_PROXY_TIMEOUT = 0.3
            try:
                async with c.get(f"{base}/search/slow", headers={"Accept": "text/html"}) as r:
                    page = await r.text()
                    sid = r.headers.get("X-Request-ID")
                async with c.get(f"{base}/search/slow?format=json") as r:
                    jdata = await r.json()
                    jstatus = r.status
            finally:
                server._SEARXNG_PROXY_TIMEOUT = old_to
            terr = [x for x in log_text().splitlines() if f"[req={sid}]" in x and "Upstream error 504" in x]
            check("searxng hung: 504 page with the ID, no port, one log line",
                  r.status == 504 and f">{sid}<" in page and str(upstream.port) not in page and len(terr) == 1,
                  f"{r.status} {terr}")
            check("searxng hung: format=json answers 504 JSON with request_id",
                  jstatus == 504 and jdata.get("request_id") and "error" in jdata, str(jdata))

            # --- SearXNG up but its socket closed
            SEARX.update(available=True, port=dead)
            async with c.get(f"{base}/search/?q=x", headers={"Accept": "text/html"}) as r:
                page = await r.text()
                sid = r.headers.get("X-Request-ID")
            err = [x for x in log_text().splitlines() if f"[req={sid}]" in x and "Upstream error 502" in x]
            check("searxng down: 502 page with the ID, no port, one log line with the reason",
                  r.status == 502 and f">{sid}<" in page and str(dead) not in page and len(err) == 1
                  and "ClientConnectorError" in err[0], f"{r.status} {err}")

        # --- the helper alone
        def helper(path="/x", headers=None, status=502, **kw):
            req = make_mocked_request("GET", path, headers=headers or {})
            req["request_id"] = "zzzz2222"
            return server._upstream_error_page(req, kw.pop("name", "Svc"), status, 15, **kw)
        r = helper("/api/streams/1/hls/x")
        check("helper: a path under /api answers JSON", r.content_type == "application/json"
              and json.loads(r.body)["request_id"] == "zzzz2222")
        r = helper(status=504)
        check("helper: 504 page says timed out", r.status == 504 and b"timed out" in r.body)
        r = helper(name="x\r\ny\x00z" + "q" * 200)
        check("helper: control characters in a name are dropped and the name is cut",
              b"\r" not in r.body and b"\x00" not in r.body and b"x y z" in r.body and b"q" * 81 not in r.body)
    finally:
        (server.authenticate_request, server.db.get_accessible_connection,
         server.db.record_connection_usage, server.resolve_checked_host,
         server.resolve_checked_host_cached, server._SSRFSafeConnector, server._searxng_status,
         server.db.get_user_by_id, server.db.is_token_valid) = saved
        server.db.note_connection_opened = saved_note
        Config.HOSTNAME = old_host
        for h in list(root.handlers):
            h.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        await portal.close()
        await upstream.close()


try:
    asyncio.run(asyncio.wait_for(main(), 60))

    # -----------------------------------------------------------------------
    # Part 3: wiring
    # -----------------------------------------------------------------------
    real_app = server.create_app()
    check("create_app: the request ID middleware is the first (outermost) one",
          real_app.middlewares[0] is server.request_id_middleware, str(real_app.middlewares))
    check("create_app: the response hook is registered", server._stamp_request_id in real_app.on_response_prepare)
    # every call of the helper sits in a function that has the request in scope, and the list of entry points
    import ast
    tree = ast.parse((Path(__file__).resolve().parent.parent / "server.py").read_text(encoding="utf-8"))
    callers, no_request = set(), []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "_upstream_error_page"):
                    callers.add(fn.name)
                    if "request" not in [a.arg for a in fn.args.args]:
                        no_request.append(fn.name)
    callers.discard("_upstream_error_page")
    check("source guard: every _upstream_error_page call is in a function that has `request`", not no_request, str(no_request))
    check("source guard: the entry points that answer through the helper are the ones documented",
          callers == {"_maintenance_answer", "_proxy_connection_authed", "_searxng_unavailable_response", "http_searxng_proxy",
                      "http_stream_hls_proxy", "http_stream_webrtc_whep", "http_stream_webrtc_whip",
                      "http_stream_webrtc_session"},
          str(sorted(callers)))
    src = (Path(__file__).resolve().parent.parent / "static" / "js" / "upstream-error.js").read_text(encoding="utf-8")
    check("static script: reloads, no eval, no innerHTML", "location.reload" in src and "eval(" not in src and "innerHTML" not in src)
finally:
    shutil.rmtree(TMP, ignore_errors=True)

if failures:
    print(f"\ntest_reqid: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_reqid: all checks passed")
