"""What stop() ends: the viewer sync task, the grant sweeper and the mod-level pushes are cancelled
and awaited before the database closes; five expired grants close their dependents at the same time
(about one wait, not five); a stop followed by a start needs no manual reset of the shutdown flag; a
disconnect event that arrives while the server stops starts no grace task.

The real stop() against a temporary database; start() is not run (it starts the media services), the
tasks it would create are created the way start() creates them and handed over under the names
start() stores them under. Nothing is dialled.

Run: venv/bin/python tests/test_shutdown_tasks.py
"""

import asyncio
import io
import logging
import sys

from retention_harness import (check, finish, run, server)  # noqa: E402

DEADLINE = 60


def run_with_deadline(body):
    async def guarded(env):
        try:
            await asyncio.wait_for(body(env), DEADLINE)
        except asyncio.TimeoutError:
            check(body.__name__ + " finished within its deadline", False, f"{DEADLINE} s")
    run(guarded)


class Capture:
    def __enter__(self):
        self.buf = io.StringIO()
        self.handler = logging.StreamHandler(self.buf)
        self.handler.setLevel(logging.WARNING)
        server.logger.addHandler(self.handler)
        return self

    def __exit__(self, *exc):
        server.logger.removeHandler(self.handler)

    @property
    def text(self):
        return self.buf.getvalue()


def test_stop_cancels_the_viewer_sync_and_the_mod_level_pushes():
    async def body(env):
        srv = server.PortalServer()
        srv._viewer_task = asyncio.create_task(srv._viewer_sync_task())
        gate = asyncio.Event()
        push = asyncio.create_task(gate.wait())
        server._mod_level_tasks.add(push)
        push.add_done_callback(server._mod_level_tasks.discard)
        await asyncio.sleep(0)
        viewer = srv._viewer_task
        with Capture() as cap:
            await srv.stop()
        check("the viewer sync task is ended by stop()", viewer.done(), "still pending")
        check("a mod-level push in flight is ended by stop()", push.done(), "still pending")
        check("the mod-level set is empty afterwards", not server._mod_level_tasks, str(server._mod_level_tasks))
        check("nothing was logged as a problem", not cap.text, cap.text)
        src = __import__("inspect").getsource(server.PortalServer.start)
        check("start() keeps the viewer sync task on the server", "self._viewer_task = asyncio.create_task(self._viewer_sync_task())" in src)
    run_with_deadline(body)

def test_stop_cancels_the_grant_sweeper():
    async def body(env):
        srv = server.PortalServer()
        srv._grant_sweep_task = asyncio.create_task(srv._grant_expiry_task())
        await asyncio.sleep(0)
        sweeper = srv._grant_sweep_task
        with Capture() as cap:
            await srv.stop()
        check("the grant sweeper is ended by stop()", sweeper.done(), "still pending")
        check("nothing was logged as a problem", not cap.text, cap.text)
        src = __import__("inspect").getsource(server.PortalServer.start)
        check("start() keeps the grant sweeper on the server", "self._grant_sweep_task = asyncio.create_task(self._grant_expiry_task())" in src)
    run_with_deadline(body)


def test_five_expired_grants_close_together():
    """Each close may take up to GRANT_CLOSE_WAIT_SECONDS; five of them in a row held the sweep for five waits."""
    async def body(env):
        rows = [{"kind": "conn", "resource_id": 100 + i, "grantee_id": 7, "grantee_username": "g",
                 "granted_by": 1, "granted_by_username": "owner", "expires_at": "2026-01-01T00:00:00+00:00",
                 "resource_name": f"c{i}"} for i in range(5)]
        closed = []
        wait = 0.5

        async def sweep():
            return rows

        async def noop(*a, **k):
            return None

        async def slow_close(kind, resource_id, user_id=None):
            await asyncio.sleep(wait)
            closed.append(resource_id)
            return 0
        saved = (env.db.sweep_expired_grants, env.db.cleanup_orphan_connection_prefs, server.audit_log,
                 server.close_grant_dependents)
        env.db.sweep_expired_grants, env.db.cleanup_orphan_connection_prefs = sweep, noop
        server.audit_log, server.close_grant_dependents = noop, slow_close
        try:
            started = asyncio.get_running_loop().time()
            n = await server.sweep_expired_grants_once()
            took = asyncio.get_running_loop().time() - started
        finally:
            (env.db.sweep_expired_grants, env.db.cleanup_orphan_connection_prefs, server.audit_log,
             server.close_grant_dependents) = saved
        check("the sweep reports five rows", n == 5, str(n))
        check("all five were closed", sorted(closed) == [100, 101, 102, 103, 104], str(closed))
        check("the five closes ran together: about one wait, not five", took < wait * 2.5, f"{took:.2f} s")
    run_with_deadline(body)

def test_a_start_after_a_stop_clears_the_shutdown_flag():
    """The flag stop() sets is a module global; a server started again in the same process (a test, a staged
    instance) must accept overlay sockets again without the caller resetting it by hand."""
    async def body(env):
        await server.PortalServer().stop()
        check("stop() sets the flag", server._shutting_down is True)
        saved = server.Config.validate_or_warn
        server.Config.validate_or_warn = lambda: True       # start() ends here (SystemExit): its first lines are what is tried
        try:
            try:
                await server.PortalServer().start()
            except SystemExit:
                pass
        finally:
            server.Config.validate_or_warn = saved
        check("start() clears the flag", server._shutting_down is False)
    run_with_deadline(body)

def test_a_disconnect_event_while_stopping_starts_no_grace_task():
    """MediaMTX stops before the runner is cleaned up, so a late disconnect hook can arrive while the server
    stops; a grace task started then would never be awaited (the start-up reset repairs the state)."""
    async def body(env):
        import aiohttp
        from aiohttp import web
        from aiohttp.test_utils import TestServer
        uid = await env.user("owner")
        key = "live_" + "c" * 24
        sid = await env.db.create_user_stream(uid, "s-c", key, public_key="pub_" + "c" * 24, is_public=True)
        app = web.Application()
        app.router.add_post("/api/stream/event", server.http_stream_event)
        srv = TestServer(app)
        await srv.start_server()
        server._disconnect_grace_tasks.clear()
        try:
            async with aiohttp.ClientSession() as http:
                async def disconnect():
                    async with http.post(srv.make_url("/api/stream/event"), json={"event": "disconnect", "path": key}) as r:
                        return r.status
                server._shutting_down = True
                try:
                    st = await disconnect()
                    check("(control) the hook is answered while stopping", st == 200, str(st))
                    check("no grace task was started while the server stops", not server._disconnect_grace_tasks,
                          str(server._disconnect_grace_tasks))
                finally:
                    server._shutting_down = False
                st = await disconnect()
                check("(control) the same event outside a shutdown starts the grace task",
                      st == 200 and sid in server._disconnect_grace_tasks, str(server._disconnect_grace_tasks))
        finally:
            for t in list(server._disconnect_grace_tasks.values()):
                t.cancel()
            await asyncio.gather(*server._disconnect_grace_tasks.values(), return_exceptions=True)
            server._disconnect_grace_tasks.clear()
            await srv.close()
    run_with_deadline(body)


for name, fn in list(globals().items()):
    if name.startswith("test_") and callable(fn):
        fn()
finish("test_shutdown_tasks")
