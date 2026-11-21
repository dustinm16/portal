"""@here and @everyone.

Runs the real chat websocket handler in-process against a temporary database (only the
authentication lookup is replaced), with real sockets.

* a moderator's "@everyone dinner at 7" in a private channel puts one notification row on every
  member, once, even when the text also names a member; the rows are written by ONE bulk insert
* a regular member's @everyone where the channel flag is off notifies nobody and gets no notice
* with the flag on a regular member may; a second one within 60 s is not carried out (the message
  is posted, the sender gets a notice, no rows); admins are not limited; the slot returns later
* @here reaches only members with an open chat socket who do not appear offline
* level none and an active timed mute get nothing, level mentions still does
* an anonymous sender's mass mention is dropped and does not use up the slot
* code spans are plain text; the cap is applied and the sender told
* who may set the flag (staff anywhere, the owner of a stream chat, not a stream mod, not a
  private channel's moderator row), channel_info carries the flag and what the member may do
* a non-public stream chat's @everyone reaches only those who may read it
* automod: a mass mention weighs 5 against mention_spam
* the migration is idempotent

Run: venv/bin/python tests/test_mass_mentions.py
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_chat_access_loss as base  # noqa: E402
import test_notify_levels as nl  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402


def run(body):
    async def go():
        async with nl.Env() as env:
            clock = [1000.0]
            env.clock = clock
            saved = (server._mass_clock, server.MASS_MENTION_CAP, server._mass_mention_last.copy())
            server._mass_clock = lambda: clock[0]
            server._mass_mention_last.clear()
            server._automod_cache_time = -1e9
            server.chat_user_state.clear()          # a socket left open by a test would keep its flags
            server._chat_state_refs.clear()
            try:
                await body(env)
            finally:
                server._mass_clock, server.MASS_MENTION_CAP = saved[0], saved[1]
                server._mass_mention_last.clear()
                server._automod_rules_cache = []
                server._automod_cache_time = -1e9
    asyncio.run(go())


async def rows(d, channel_id):
    """user_id -> number of mention notifications for that channel."""
    cur = await d.conn.execute("SELECT user_id, data FROM notifications WHERE type = 'mention'")
    out = {}
    import json
    for r in await cur.fetchall():
        if json.loads(r["data"] or "{}").get("channel_id") == channel_id:
            out[r["user_id"]] = out.get(r["user_id"], 0) + 1
    return out


async def post(sock, text, settle=0.4):
    mark = sock.mark()
    await sock.send(type="message", message=text)
    await sock.wait(lambda e: e.get("type") == "message" and e.get("message") == text, mark)
    await asyncio.sleep(settle)
    return mark


def notices(sock, mark, code=None):
    return [e for e in sock.events[mark:] if e.get("type") == "notice" and (code is None or e.get("code") == code)]


async def private(d, ids, members=("alice", "bob", "carol")):
    return await base.private_channel(d, ids, members)


# ---------------------------------------------------------------------------

def test_a_moderators_everyone_reaches_every_member_of_a_private_channel_once():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await private(d, ids)
        calls = []
        real_bulk = d.create_notifications_bulk
        singles = []
        real_single = d.create_notification

        async def bulk(rows_):
            calls.append(len(rows_))
            return await real_bulk(rows_)

        async def single(*a, **k):
            singles.append(a)
            return await real_single(*a, **k)
        d.create_notifications_bulk, d.create_notification = bulk, single
        mod = await env.sock(ids["alice"])
        await mod.join(cid)
        bob = await env.sock(ids["bob"])      # in the room, sees it live and is still notified
        await bob.join(cid)
        mark = await post(mod, "@everyone dinner at 7 @bob")
        got = await rows(d, cid)
        assert got == {ids["bob"]: 1, ids["carol"]: 1}, got      # exactly once each, not the sender,
        # not the admin or the viewer who are not members
        # bob has the room open, so a direct @bob skips him: he is reached by the mass mention, and
        # both members are written by ONE bulk insert
        assert calls == [2] and not singles, (calls, singles)
        pushed = [e for e in bob.events if e.get("type") == "notification"]
        assert len(pushed) == 1 and pushed[0]["notification"]["data"]["channel_id"] == cid, pushed
        assert not notices(mod, mark)
        # carol is named directly as well and is not in the room: still ONE bulk insert and one
        # row each, carol's with the personal title
        env.clock[0] += 61
        del calls[:]
        await post(mod, "@everyone and @carol, again")
        got = await rows(d, cid)
        assert got == {ids["bob"]: 2, ids["carol"]: 2}, got
        assert calls == [2] and not singles, (calls, singles)
        # newest by id (created_at has a resolution of one second)
        titles = {u: max(await d.get_notifications(ids[u], limit=100), key=lambda n: n["id"])["title"]
                  for u in ("bob", "carol")}
        assert "mentioned you" in titles["carol"] and "everyone" in titles["bob"], titles
        # no mass token (or a refused one): the named member is notified as before, one by one
        del calls[:]
        await post(mod, "just @carol, hello")
        assert calls == [] and [a[0] for a in singles] == [ids["carol"]], (calls, singles)

        # chat timeouts: a timed-out moderator's message is refused before it posts, so nothing is
        # written; a recipient under a timeout can still read, so is still notified
        await d.create_chat_timeout(ids["alice"], ids["boss"], "timeout", cid, "test", 600)
        env.clock[0] += 61
        del calls[:]
        mark = mod.mark()
        await mod.send(type="message", message="@everyone while timed out")
        assert await mod.wait(lambda e: e.get("error_code") == "timeout", mark)
        await asyncio.sleep(0.3)
        assert calls == [] and (await rows(d, cid)) == {ids["bob"]: 2, ids["carol"]: 3}
    run(body)


def test_a_regular_member_without_the_flag_notifies_nobody():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await private(d, ids)
        bob = await env.sock(ids["bob"])
        await bob.join(cid)
        mark = await post(bob, "@everyone look at this")
        assert await rows(d, cid) == {}
        assert not notices(bob, mark)                   # the text is ordinary text: no notice either
        mark = await post(bob, "@here too")
        assert await rows(d, cid) == {} and not notices(bob, mark)
        assert server._mass_mention_last == {}          # no slot used
    run(body)


def test_with_the_flag_on_a_member_may_and_a_second_within_60_seconds_is_limited():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await private(d, ids)
        boss = await env.sock(ids["boss"])
        await boss.join(cid)
        mark = boss.mark()
        await boss.send(type="set_mass_mentions", allowed=True)
        assert await boss.wait(lambda e: e.get("type") == "mass_mentions_changed" and e["allowed"] is True, mark)
        bob = await env.sock(ids["bob"])
        await bob.join(cid)
        await post(bob, "@everyone first")
        assert await rows(d, cid) == {ids["alice"]: 1, ids["carol"]: 1}
        env.clock[0] += 30
        mark = await post(bob, "@everyone second")
        got = notices(bob, mark, "mass_mention_limited")
        assert len(got) == 1 and 0 < got[0]["retry_after"] <= 31, got
        assert await rows(d, cid) == {ids["alice"]: 1, ids["carol"]: 1}     # unchanged
        cur = await d.conn.execute("SELECT COUNT(*) AS n FROM chat_messages WHERE channel_id = ?", (cid,))
        assert (await cur.fetchone())["n"] == 2                              # the message is posted
        env.clock[0] += 31
        await post(bob, "@everyone third")
        assert await rows(d, cid) == {ids["alice"]: 2, ids["carol"]: 2}
        # an admin is not limited
        await boss.join(cid)
        await post(boss, "@everyone a")
        mark = await post(boss, "@everyone b")
        assert not notices(boss, mark)
        assert (await rows(d, cid))[ids["carol"]] == 4
    run(body)


def test_here_reaches_only_online_members_who_do_not_appear_offline():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await nl.general(d)
        lobby = await nl.pub_channel(d, ids)
        users = {n: ids[n] for n in ("bob", "carol", "viewer", "owner")}
        await d.set_user_status(ids["viewer"], "offline", None, update_preference=True)   # appears offline
        sender = await env.sock(ids["alice"])
        await sender.join(lobby)
        online = await env.sock(ids["bob"])
        await online.join(gen)                      # connected, in another room
        hidden = await env.sock(ids["viewer"])
        await hidden.join(gen)
        await d.set_user_status(ids["viewer"], "offline", None, update_preference=True)
        await post(sender, "@here standup now")
        got = await rows(d, lobby)
        assert got == {ids["bob"]: 1}, got          # carol and owner are offline, viewer hides
        await d.conn.execute("DELETE FROM notifications")
        await d.conn.commit()
        env.clock[0] += 100
        await post(sender, "@everyone all hands")
        got = await rows(d, lobby)
        assert ids["carol"] in got and ids["viewer"] in got and ids["bob"] in got, got
        assert ids["alice"] not in got and set(got.values()) == {1}
    run(body)


def test_levels_and_mutes_are_respected():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        lobby = await nl.pub_channel(d, ids)
        await d.set_notify_pref(ids["bob"], lobby, "none", 0)
        await d.set_notify_pref(ids["carol"], lobby, "mentions", 0)
        await d.set_notify_pref(ids["owner"], lobby, "all", int(env.now[0]) + 3600)       # muted for an hour
        await d.set_notify_pref(ids["viewer"], lobby, "all", int(env.now[0]) - 10)        # mute ended
        sender = await env.sock(ids["alice"])
        await sender.join(lobby)
        await post(sender, "@everyone news")
        got = await rows(d, lobby)
        assert ids["bob"] not in got and ids["owner"] not in got, got
        assert got.get(ids["carol"]) == 1 and got.get(ids["viewer"]) == 1, got
    run(body)


def test_an_anonymous_senders_mass_mention_is_dropped_and_uses_no_slot():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await private(d, ids)
        await d.conn.execute("UPDATE users SET chat_anonymous = 1 WHERE id = ?", (ids["alice"],))
        await d.conn.commit()
        mod = await env.sock(ids["alice"])
        await mod.join(cid)
        mark = await post(mod, "@everyone secret")
        assert await rows(d, cid) == {}, await rows(d, cid)
        assert not notices(mod, mark), mod.events[mark:]
        assert server._mass_mention_last == {}
        for n in ("bob", "carol"):
            s = await env.sock(ids[n])
            await s.join(cid)
            assert not any(e.get("type") == "notification" for e in s.events)
    run(body)


def test_code_spans_are_plain_text_and_the_cap_is_applied():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid = await private(d, ids, members=("alice", "bob", "carol", "owner", "viewer"))
        mod = await env.sock(ids["alice"])
        await mod.join(cid)
        await post(mod, "use `@everyone` for that")
        await post(mod, "```\n@here\n```")
        assert await rows(d, cid) == {}
        assert server._mass_mention_last == {}
        server.MASS_MENTION_CAP = 2
        env.clock[0] += 61
        mark = await post(mod, "@everyone cap")
        got = await rows(d, cid)
        assert len(got) == 2 and set(got.values()) == {1}, got
        assert len(notices(mod, mark, "mass_mention_capped")) == 1
    run(body)


def test_a_mass_mention_of_a_non_public_stream_chat_reaches_only_who_may_read_it():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid, sid = await base.stream_chat(d, ids, public=False)
        owner = await env.sock(ids["owner"])
        await owner.join(cid)
        await post(owner, "@everyone going live")
        got = await rows(d, cid)
        assert ids["bob"] not in got and ids["carol"] not in got and ids["viewer"] not in got, got
        assert got == {ids["boss"]: 1}, got          # the admin reads it; the owner is the sender
    run(body)


def test_who_may_set_the_flag_and_what_channel_info_says():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        cid, sid = await base.stream_chat(d, ids, public=True)
        await d.add_channel_member(cid, ids["bob"], role="moderator", added_by=ids["owner"])   # a stream mod
        pcid = await private(d, ids)
        await d.add_channel_member(pcid, ids["carol"], role="moderator", added_by=ids["boss"])  # row only

        async def try_set(user, channel, allowed):
            s = await env.sock(ids[user])
            await s.join(channel)
            info = next(e for e in s.events if e.get("type") == "channel_info")
            mark = s.mark()
            await s.send(type="set_mass_mentions", allowed=allowed)
            await asyncio.sleep(0.3)
            ch = await d.get_chat_channel(channel)
            await s.close()
            return info, bool(ch["allow_mass_mentions"]), [e for e in s.events[mark:] if e.get("type") == "error"]

        info, now, errs = await try_set("viewer", cid, True)
        assert not now and errs and info["can_mass_mention"] is False and info["allow_mass_mentions"] is False
        info, now, errs = await try_set("bob", cid, True)                 # stream mod: refused
        assert not now and errs and info["can_mass_mention"] is True      # may USE it as a mod, not set it
        info, now, errs = await try_set("carol", pcid, True)              # private channel moderator row
        assert not now and errs and info["can_mass_mention"] is False
        info, now, errs = await try_set("owner", cid, "yes")              # not a boolean
        assert not now and errs
        info, now, errs = await try_set("owner", cid, True)               # the stream's owner
        assert now and not errs and info["can_mass_mention"] is True
        info, now, errs = await try_set("viewer", cid, False)             # still refused
        assert now
        info, now, errs = await try_set("viewer", cid, True)
        assert now
        # a viewer now sees the flag and may use it
        s = await env.sock(ids["viewer"])
        await s.join(cid)
        info = next(e for e in s.events if e.get("type") == "channel_info")
        assert info["allow_mass_mentions"] is True and info["can_mass_mention"] is True
        info, now, errs = await try_set("alice", pcid, True)              # staff
        assert now and not errs
        info, now, errs = await try_set("boss", pcid, False)
        assert not now and not errs
        entries = [e for e in await d.get_audit_log(limit=200) if e["action"] == "mass_mentions_set"]
        assert len(entries) == 3, entries      # the three accepted changes; refusals are not logged
    run(body)


def test_automod_weighs_a_mass_mention_five_times():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.create_automod_rule("mention_spam", "spam", {"max_mentions": 5}, "warn", ids["boss"])
        cid = await private(d, ids)
        mod = await env.sock(ids["alice"])
        await mod.join(cid)
        mark = mod.mark()
        await mod.send(type="message", message="@everyone @bob")
        assert await mod.wait(lambda e: e.get("error_code") == "automod", mark), mod.events[mark:]
        assert await rows(d, cid) == {}
        mark = await post(mod, "@everyone alone")
        assert not any(e.get("error_code") == "automod" for e in mod.events[mark:])
        assert await rows(d, cid) == {ids["bob"]: 1, ids["carol"]: 1}
        mark = mod.mark()
        await mod.send(type="message", message="@a @b @c @d @e @f")           # six, as before
        assert await mod.wait(lambda e: e.get("error_code") == "automod", mark)
    run(body)


def test_automod_weighs_a_mass_mention_only_where_the_sender_may_use_it():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        await d.create_automod_rule("mention_spam", "spam", {"max_mentions": 5}, "warn", ids["boss"])
        lobby = await nl.pub_channel(d, ids)
        carol = await env.sock(ids["carol"])
        await carol.join(lobby)
        # a member who may not mass-mention here: plain text, two mentions, not blocked
        mark = await post(carol, "@everyone @bob")
        assert not any(e.get("error_code") == "automod" for e in carol.events[mark:]), carol.events[mark:]
        assert await rows(d, lobby) == {ids["bob"]: 1}, "only the named member is notified"
        assert server._check_mention_spam("@everyone @x", {"max_mentions": 5}, mass_allowed=False) is False
        # the channel's switch lets every member use it: weight 5 applies again
        boss = await env.sock(ids["boss"])
        await boss.join(lobby)
        await boss.send(type="set_mass_mentions", allowed=True)
        assert await boss.wait(lambda e: e.get("type") == "mass_mentions_changed")
        mark = carol.mark()
        await carol.send(type="message", message="@everyone @bob")
        assert await carol.wait(lambda e: e.get("error_code") == "automod", mark), carol.events[mark:]
    run(body)


def test_here_and_everyone_are_reserved_names_and_an_old_account_with_one_is_not_mentioned():
    async def body(env):
        d = env.db
        ids = await base.users(d)
        # the routes refuse the names in any case; the nickname route and the account routes
        st, b = await env.call("PUT", ids["bob"], "/api/me/nickname", json={"nickname": "Everyone"})
        assert st == 400 and "reserved" in b["error"], (st, b)
        st, b = await env.call("PUT", ids["bob"], "/api/me/nickname", json={"nickname": " here "})
        assert st == 400, (st, b)
        st, b = await env.call("PUT", ids["bob"], "/api/me/nickname", json={"nickname": "hero"})
        assert st == 200, (st, b)
        real_scope = base.Tok.has_scope
        base.Tok.has_scope = lambda self, scope: True      # the stand-in credential has no admin scope
        try:
            st, b = await env.call("POST", ids["boss"], "/api/users", json={"username": "Everyone", "password": "longenough1"})
        finally:
            base.Tok.has_scope = real_scope
        assert st == 400 and "reserved" in b["error"], (st, b)
        try:
            from auth import create_user
            await create_user("HERE", "longenough1")
            raise AssertionError("auth.create_user accepted a reserved name")
        except ValueError:
            pass
        # accounts made before the names were reserved: the text does nothing special for them
        old_here = await d.create_user("here", "x")
        old_all = await d.create_user("Wide", "x")
        await d.conn.execute("UPDATE users SET nickname = 'everyone' WHERE id = ?", (old_all,))
        await d.conn.commit()
        got = await server._parse_mentions("@here @Everyone and @bob")
        assert got == {ids["bob"]}, got
    run(body)


def test_a_closed_sender_socket_does_not_drop_the_named_members_notifications():
    class DeadSocket:
        closed = True

        async def send_json(self, payload):
            raise ConnectionResetError("closed")

    async def body(env):
        d = env.db
        ids = await base.users(d)
        gen = await nl.general(d)
        channel = await d.get_chat_channel(gen)
        # alice is a moderator (may mass-mention, is rate limited); her slot is already used
        server._mass_mention_last[ids["alice"]] = server._mass_clock()
        await server._notify_mentions(DeadSocket(), channel, ids["alice"], "moderator", "alice",
                                      "@everyone look @bob", 1)
        assert (await rows(d, gen)).get(ids["bob"]) == 1, await rows(d, gen)
    run(body)


def test_detection_rules():
    k = server._mass_mention_kind
    assert k("@everyone dinner at 7") == "everyone" and k("hi @here.") == "here"
    assert k("@Here and @EVERYONE") == "everyone"
    assert k("mail me@here.com") is None and k("@heretic") is None and k("@everyone-else") is None
    assert k("`@here`") is None and k("a @@everyone") is None and k("") is None
    assert server._check_mention_spam("@everyone", {"max_mentions": 4})
    assert not server._check_mention_spam("@everyone", {"max_mentions": 5})
    assert server._check_mention_spam("@everyone @x", {"max_mentions": 5})


def test_the_migration_is_idempotent():
    async def body(env):
        d = env.db
        path = str(Path(env.tmp.name) / "t.db")
        ids = await base.users(d)
        cid = await private(d, ids)
        await d.set_allow_mass_mentions(cid, True)
        await d.close()
        d2 = Database(path)
        await d2.connect()                      # every migration runs again
        assert (await d2.get_chat_channel(cid))["allow_mass_mentions"] == 1
        cur = await d2.conn.execute("PRAGMA table_info(chat_channels)")
        assert [r["name"] for r in await cur.fetchall()].count("allow_mass_mentions") == 1
        await d2.close()
        d.close = lambda: asyncio.sleep(0)
    run(body)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
