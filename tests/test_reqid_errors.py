"""An unhandled exception in a handler: the 500 and the journal line carry the same request ID.

The console handler is switched on (the journal reads stdout), so the line a member's ID is looked up
in is the one the test reads. Removing `console_handler.addFilter(request_id_filter)` in logger.py must
fail the "handler line" check; removing the catch in server.request_id_middleware must fail the
"error line" checks (aiohttp then logs the traceback after the ID is gone).

Run:  venv/bin/python tests/test_reqid_errors.py
"""

import asyncio
import io
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import logger as portal_logger  # noqa: E402
import server  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""),
          file=sys.__stdout__, flush=True)
    if not passed:
        failures.append(name)


TMP = Path(tempfile.mkdtemp(prefix="reqid_err_test_"))
SECRET_TEXT = "backend-detail-9f3"


async def page(request):
    logging.getLogger("portal").warning("handler line before the failure")
    await asyncio.sleep(0)
    return web.Response(text="page")


async def boom(request):
    logging.getLogger("portal").warning("handler line before the failure")
    raise RuntimeError(SECRET_TEXT)


async def missing(request):
    raise web.HTTPNotFound()


async def moved(request):
    raise web.HTTPFound("/elsewhere")


async def slow(request):
    raise asyncio.TimeoutError()


async def main():
    app = web.Application(middlewares=[server.request_id_middleware])
    server.register_request_ids(app)
    app.router.add_get("/page", page)
    app.router.add_get("/boom", boom)
    app.router.add_get("/missing", missing)
    app.router.add_get("/moved", moved)
    app.router.add_get("/slow", slow)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"

    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    saved_settings = dict(portal_logger.LOG_SETTINGS)
    saved_paths = (portal_logger.LOG_DIR, portal_logger.LOG_FILE, portal_logger.AUDIT_FILE)
    saved_stdout = sys.stdout
    sys.stdout = captured = io.StringIO()      # the console handler binds stdout when it is made
    try:
        portal_logger.setup_logging(level="INFO", log_dir=TMP, console_enabled=True, file_enabled=False,
                                    structured=False)

        def out():
            return captured.getvalue()

        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as c:
            async with c.get(f"{base}/page") as r:
                await r.read()
                page_rid = r.headers["X-Request-ID"]
            check("console: a line a handler wrote carries the ID (the console filter)",
                  f"[req={page_rid}] handler line before the failure" in out(), out()[-300:])

            async with c.get(f"{base}/boom", headers={"Accept": "text/plain"}) as r:
                body = await r.text()
                rid = r.headers.get("X-Request-ID")
                status, ctype = r.status, r.content_type
            check("500: the status, the plain body and the ID header are as before",
                  status == 500 and ctype == "text/plain" and rid and len(rid) == 8
                  and body.startswith("500 Internal Server Error") and SECRET_TEXT not in body, f"{status} {body!r}")
            text = out()
            err = [x for x in text.splitlines() if "Error handling request" in x]
            check("error line: exactly one, and it carries the ID the response gave",
                  len(err) == 1 and f"[req={rid}]" in err[0], str(err))
            check("error line: the traceback and the exception text follow it",
                  "Traceback (most recent call last)" in text and f"RuntimeError: {SECRET_TEXT}" in text)
            check("error line: the handler's own line has the same ID",
                  f"[req={rid}] handler line before the failure" in text)

            async with c.get(f"{base}/boom", headers={"Accept": "text/html"}) as r:
                html = await r.text()
                check("500: a browser still gets aiohttp's HTML page",
                      r.status == 500 and r.content_type == "text/html" and "<h1>500 Internal Server Error</h1>" in html
                      and SECRET_TEXT not in html and len(r.headers.get("X-Request-ID", "")) == 8)
            async with c.get(f"{base}/boom") as r:
                await r.read()
                check("500: a failure does not poison the next request on the connection",
                      r.status == 500 and r.headers["X-Request-ID"] != rid)

            before = out()
            async with c.get(f"{base}/missing") as r:
                await r.read()
                check("HTTPException: a 404 passes through untouched", r.status == 404 and len(r.headers.get("X-Request-ID", "")) == 8)
            async with c.get(f"{base}/moved", allow_redirects=False) as r:
                check("HTTPException: a redirect passes through untouched",
                      r.status == 302 and r.headers["Location"] == "/elsewhere")
            check("HTTPException: no error line", "Error handling request" not in out()[len(before):])
            async with c.get(f"{base}/slow") as r:
                await r.read()
                tid = r.headers.get("X-Request-ID")
                check("timeout: still aiohttp's 504, not turned into a 500", r.status == 504, str(r.status))
            terr = [x for x in out()[len(before):].splitlines() if "Error handling request" in x]
            check("timeout: aiohttp's one line now carries the ID", len(terr) == 1 and f"[req={tid}]" in terr[0], str(terr))

        # cancellation is never swallowed, and the ID context is cleared afterwards
        async def cancelled(request):
            raise asyncio.CancelledError()

        from aiohttp.test_utils import make_mocked_request
        raised = None
        try:
            await server.request_id_middleware(make_mocked_request("GET", "/x"), cancelled)
        except BaseException as e:
            raised = e
        check("cancellation: CancelledError propagates", isinstance(raised, asyncio.CancelledError), repr(raised))
        check("cancellation: the request ID is cleared after the request", portal_logger.current_request_id() is None)
    finally:
        sys.stdout = saved_stdout
        for h in list(root.handlers):
            h.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        portal_logger.LOG_SETTINGS.clear()
        portal_logger.LOG_SETTINGS.update(saved_settings)
        portal_logger.LOG_DIR, portal_logger.LOG_FILE, portal_logger.AUDIT_FILE = saved_paths
        await srv.close()


try:
    asyncio.run(asyncio.wait_for(main(), 30))
finally:
    shutil.rmtree(TMP, ignore_errors=True)

if failures:
    print(f"\ntest_reqid_errors: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_reqid_errors: all checks passed")
