"""A reaction made while the reactor chats anonymously stays anonymous (1.24.1).

chat_reactions.anonymous is set when the row is inserted (from the reactor's chat_anonymous setting at that
moment). History, search, threads and pins (_enrich_channel_messages -> _mask_reactor_ids) and the live
reaction_update frame (also when the reaction is taken back) hide the reactor on that flag for everybody but
the reactor and staff, after the member has switched anonymous off. The migration marks the existing rows of
members who are anonymous at that moment, once. The anonymous handle changes when anonymous mode is switched
on again.

Real chat websocket handler and HTTP routes on a loopback test server with a temporary database
(helpers of tests/test_chat_history.py). Every test has a 60 second deadline.

Run: venv/bin/python tests/test_anonymous_reactions.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_chat_history as H  # noqa: E402
from test_chat_history import server  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402


class Env(H.Env):
    """The environment of test_chat_history plus the route that switches anonymous mode."""

    async def __aenter__(self):
        await super().__aenter__()
        await self.srv.close()
        await self.http.close()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_get("/api/chat/channels/{id}/messages", server.http_get_channel_messages)
        app.router.add_get("/api/chat/thread/{id}", server.http_get_chat_thread)
        app.router.add_get("/api/chat/search", server.http_search_messages)
        app.router.add_put("/api/me/anonymous", server.http_update_chat_anonymous)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self


def run(body):
    async def go():
        async with Env() as env:
            await asyncio.wait_for(body(env), 60)
    asyncio.run(go())


async def world(d):
    ids = {}
    for name in ("alice", "bob", "carol", "mod"):
        ids[name] = await d.create_user(name, "x")
    await d.set_user_role(ids["mod"], "moderator")
    cid = await d.create_chat_channel("react1", created_by=ids["bob"])
    mid = await d.create_chat_message(cid, ids["bob"], "bob", "hello")
    return ids, cid, mid


def reactors(history, mid, emoji="+1"):
    for m in history["messages"]:
        if m["id"] == mid:
            for r in m["reactions"]:
                if r["emoji"] == emoji:
                    return r
    raise AssertionError("no such reaction in the history")


def test_row_flag_is_set_at_insert_and_reported_on_removal():
    async def body(env):
        d = env.db
        ids, cid, mid = await world(d)
        await d.set_chat_anonymous(ids["alice"], True)
        assert await d.toggle_reaction_state(mid, ids["alice"], "+1") == (True, 1, True)
        assert await d.toggle_reaction_state(mid, ids["bob"], "+1") == (True, 2, False)
        await d.set_chat_anonymous(ids["alice"], False)
        # taking it back reports the flag the row had, not the setting of today
        assert await d.toggle_reaction_state(mid, ids["alice"], "+1") == (False, 1, True)
        assert await d.toggle_reaction_state(mid, ids["alice"], "+1") == (True, 2, False), "made again while named"
        bulk = (await d.get_bulk_reactions([mid]))[mid][0]
        assert bulk["user_ids"] == [ids["bob"], ids["alice"]] and bulk["anonymous_user_ids"] == [], bulk
    run(body)


def test_history_does_not_name_a_reactor_who_switched_anonymous_off():
    async def body(env):
        d = env.db
        ids, cid, mid = await world(d)
        await d.set_chat_anonymous(ids["alice"], True)
        await d.toggle_reaction(mid, ids["alice"], "+1")
        await d.toggle_reaction(mid, ids["carol"], "+1")
        await d.set_chat_anonymous(ids["alice"], False)
        for viewer, expect in ((ids["bob"], [ids["carol"]]), (ids["carol"], [ids["carol"]]),
                               (ids["alice"], [ids["alice"], ids["carol"]]),
                               (ids["mod"], [ids["alice"], ids["carol"]])):
            status, data, _ = await env.get(viewer, cid)
            r = reactors(data, mid)
            assert status == 200 and r["count"] == 2, (viewer, r)
            assert sorted(r["user_ids"]) == sorted(expect), (viewer, r)
            assert "anonymous_user_ids" not in r, "the internal list is never sent"
        # the join history and the paged history go through the same helper
        bob = await env.ws(ids["bob"])
        hist = await bob.join(cid)
        r = reactors(hist, mid)
        assert r["user_ids"] == [ids["carol"]] and r["count"] == 2 and "anonymous_user_ids" not in r, r
        await bob.close()
        # search, thread and pins show the same
        status, data = await env.search(ids["bob"], "hello")
        hits = data.get("results") or data.get("messages") or []
        assert hits, data      # (a search hit carries no reactions at all)
        for m in hits:
            for rr in m.get("reactions", []):
                assert ids["alice"] not in rr["user_ids"] and "anonymous_user_ids" not in rr, rr
        status, data, _ = await env.thread(ids["bob"], mid)
        for m in data["thread"]:
            for rr in m.get("reactions", []):
                assert ids["alice"] not in rr["user_ids"] and "anonymous_user_ids" not in rr, rr
    run(body)


def test_live_frames_after_anonymous_was_switched_off():
    async def body(env):
        d = env.db
        ids, cid, mid = await world(d)
        await d.set_chat_anonymous(ids["alice"], True)
        alice, bob, mod = await env.ws(ids["alice"]), await env.ws(ids["bob"]), await env.ws(ids["mod"])
        for s in (alice, bob, mod):
            await s.join(cid)
        await alice.send(type="react", message_id=mid, emoji="+1")
        for s, who in ((bob, None), (alice, ids["alice"]), (mod, ids["alice"])):
            f = await s.until("reaction_update")
            assert f["added"] is True and f["user_id"] == who, (who, f)
        await d.set_chat_anonymous(ids["alice"], False)
        server.chat_user_state.get(ids["alice"], {}).update(anonymous=False)
        await alice.send(type="react", message_id=mid, emoji="+1")      # takes it back, now named
        for s, who in ((bob, None), (alice, ids["alice"]), (mod, ids["alice"])):
            f = await s.until("reaction_update")
            assert f["added"] is False and f["user_id"] == who, ("removal", who, f)
        # a reaction made while named is named
        await alice.send(type="react", message_id=mid, emoji="+1")
        f = await bob.until("reaction_update")
        assert f["added"] is True and f["user_id"] == ids["alice"], f
        for s in (alice, bob, mod):
            await s.close()
    run(body)


def test_migration_marks_existing_rows_once():
    async def body(env):
        d = env.db
        ids, cid, mid = await world(d)
        await d.toggle_reaction(mid, ids["alice"], "+1")     # named when made
        await d.toggle_reaction(mid, ids["carol"], "+1")
        await d.conn.execute("UPDATE chat_reactions SET anonymous = 0")      # as on a 1.24.0 database
        await d.conn.execute("DELETE FROM settings WHERE key = 'reaction_anonymous_marked'")
        await d.set_chat_anonymous(ids["alice"], True)
        await d.conn.commit()
        await d._migrate_reaction_anonymous()
        rows = await (await d.conn.execute("SELECT user_id, anonymous FROM chat_reactions")).fetchall()
        assert {r["user_id"]: r["anonymous"] for r in rows} == {ids["alice"]: 1, ids["carol"]: 0}
        # a second run (the next start) marks nobody who became anonymous since
        await d.set_chat_anonymous(ids["carol"], True)
        await d._migrate_reaction_anonymous()
        rows = await (await d.conn.execute("SELECT user_id, anonymous FROM chat_reactions")).fetchall()
        assert {r["user_id"]: r["anonymous"] for r in rows} == {ids["alice"]: 1, ids["carol"]: 0}
        # the column is added by the migration list on a database that has none (idempotent)
        await d._run_migrations()
    run(body)


def test_handle_changes_when_anonymous_is_switched_on_again():
    async def body(env):
        d = env.db
        ids, cid, mid = await world(d)

        async def put(user, value):
            async with env.http.put(env.url("/api/me/anonymous"), json={"anonymous": value},
                                    headers={"X-Test-User": str(user)}) as r:
                assert r.status == 200, r.status

        first = server._anon_ref("react1", ids["alice"])
        assert server._anon_ref("react1", ids["alice"]) == first and server._anon_ref("react1", ids["bob"]) != first
        await put(ids["alice"], True)
        second = server._anon_ref("react1", ids["alice"])
        assert second != first, "a new anonymous period has a new handle"
        await put(ids["alice"], True)          # already on: the same period
        assert server._anon_ref("react1", ids["alice"]) == second
        await put(ids["alice"], False)
        await put(ids["alice"], True)
        assert server._anon_ref("react1", ids["alice"]) not in (first, second)
    run(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except BaseException as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
