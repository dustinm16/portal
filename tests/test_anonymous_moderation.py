"""A moderation action on an anonymous post answers the same for a stream owner or stream mod whoever wrote it (1.24.1).

Decision: the action is allowed on every anonymous post of the actor's own stream chat, as the range prune already
treats them (anonymous posts are rankless for everybody but an administrator), so no refusal tells the actor the
rank of the hidden author. Staff roles are given the author's identity and keep the rank rules; an action on a
named member keeps them for everybody. Covers delete, timeout by message id, ban by message id and lifting a ban
made from an anonymous post.

Real chat websocket handler on a loopback test server with a temporary database (helpers of tests/test_chat_history.py).
Every test has a 90 second deadline.

Run: venv/bin/python tests/test_anonymous_moderation.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import outbound_guard  # noqa: E402

outbound_guard.install()

import test_chat_history as H  # noqa: E402
from test_chat_history import Env, server  # noqa: E402
import aiohttp  # noqa: E402


def run(body):
    async def go():
        async with Env() as env:
            await asyncio.wait_for(body(env), 90)
    asyncio.run(go())


AUTHORS = ("member", "othermod", "streamer", "admin_author", "moderator_author")


async def world(d):
    ids = {}
    for name in ("streamer", "mod1", "member", "othermod", "admin_author", "moderator_author", "gmod", "gadmin"):
        ids[name] = await d.create_user(name, "x")
    await d.set_user_role(ids["admin_author"], "admin")
    await d.set_user_role(ids["moderator_author"], "moderator")
    await d.set_user_role(ids["gmod"], "moderator")
    await d.set_user_role(ids["gadmin"], "admin")
    cid = await d.create_chat_channel("modchat", created_by=ids["streamer"])
    sid = await d.create_user_stream(ids["streamer"], "s1", "live_" + "a" * 24, public_key="pub_" + "b" * 24, is_public=1)
    await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, sid))
    await d.conn.commit()
    for name in ("mod1", "othermod"):
        assert await d.add_channel_moderator_capped(cid, ids[name], ids["streamer"], 20)
    return ids, cid, sid


async def post(d, cid, ids, who, anonymous, text):
    return await d.create_chat_message(cid, ids[who], who, text, anonymous=anonymous)


async def drain(sock, quiet=0.5):
    out = []
    while True:
        try:
            out.append(await sock.until("message_deleted", "user_timed_out", "user_banned", "error", "ban_added",
                                        "stream_ban_added", "user_unbanned", "ban_removed", timeout=quiet))
        except (asyncio.TimeoutError, AssertionError):
            return out


def shape(frames, drop=("message_id", "ban_id", "id", "target_ban_id")):
    return json.dumps([{k: v for k, v in f.items() if k not in drop} for f in frames], sort_keys=True)


async def act(sock, payload):
    await sock.send(**payload)
    return await drain(sock)


def test_stream_mod_gets_one_answer_for_every_author_of_an_anonymous_post():
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        for action in ("delete", "timeout", "ban"):
            answers, effects = {}, {}
            for who in AUTHORS:
                mid = await post(d, cid, ids, who, True, f"anon {action} {who}")
                if action == "delete":
                    frames = await act(mod, {"type": "delete", "message_id": mid})
                    effects[who] = await d.get_chat_message(mid) is None
                elif action == "timeout":
                    frames = await act(mod, {"type": "timeout_user", "message_id": mid, "duration": 60, "reason": "r"})
                    effects[who] = bool(await d.is_user_timed_out(ids[who], cid))
                else:
                    frames = await act(mod, {"type": "ban", "message_id": mid, "reason": "r"})
                    effects[who] = bool(await d.is_user_banned_from_stream(sid, ids[who]))
                answers[who] = shape(frames)
                assert frames and not any(f["type"] == "error" for f in frames), (action, who, frames)
                assert all(f.get("user_id") is None for f in frames if "user_id" in f), (action, who, frames)
            assert len(set(answers.values())) == 1, (action, answers)
            assert all(effects.values()), (action, effects)
        await mod.close()
    run(body)


def test_named_posts_keep_the_rank_rules():
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        for who in AUTHORS:
            mid = await post(d, cid, ids, who, False, f"named {who}")
            frames = await act(mod, {"type": "delete", "message_id": mid})
            gone = await d.get_chat_message(mid) is None
            # a stream mod deletes an ordinary member's named post only
            assert gone == (who == "member"), (who, gone, frames)
            mid = await post(d, cid, ids, who, False, f"named t {who}")
            frames = await act(mod, {"type": "timeout_user", "message_id": mid, "duration": 60})
            assert bool(await d.is_user_timed_out(ids[who], cid)) == (who == "member"), (who, frames)
            if who != "member":
                assert [f.get("message") for f in frames] == ["Not allowed"], (who, frames)
        # nobody acts on themselves: an own anonymous post cannot be banned through the ban path
        mid = await post(d, cid, ids, "mod1", True, "mine")
        frames = await act(mod, {"type": "ban", "message_id": mid})
        assert [f.get("message") for f in frames] == ["Not allowed"] and not await d.is_user_banned_from_stream(sid, ids["mod1"])
        await mod.close()
    run(body)


def test_staff_roles_keep_the_rank_rules_on_anonymous_posts():
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        gmod = await env.ws(ids["gmod"])        # global moderator: is given the author's identity
        await gmod.join(cid)
        res = {}
        for who in ("member", "admin_author", "moderator_author"):
            mid = await post(d, cid, ids, who, True, f"anon staff {who}")
            frames = await act(gmod, {"type": "delete", "message_id": mid})
            res[who] = await d.get_chat_message(mid) is None
        assert res == {"member": True, "admin_author": False, "moderator_author": False}, res
        await gmod.close()
        gadmin = await env.ws(ids["gadmin"])
        await gadmin.join(cid)
        for who in ("member", "admin_author", "moderator_author"):
            mid = await post(d, cid, ids, who, True, f"anon admin {who}")
            await act(gadmin, {"type": "delete", "message_id": mid})
            res[who] = await d.get_chat_message(mid) is None
        assert res["member"] and res["moderator_author"] and not res["admin_author"], res
        await gadmin.close()
    run(body)


def test_lifting_a_ban_made_from_an_anonymous_post_does_not_depend_on_the_author():
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        answers = {}
        for who in ("member", "streamer", "admin_author"):
            ban_id = await d.create_stream_ban(sid, ids[who], ids["streamer"], "r", anonymous=True,
                                               message_id=await post(d, cid, ids, who, True, f"ban {who}"))
            frames = await act(mod, {"type": "unban", "ban_id": ban_id})
            answers[who] = shape(frames)
            assert await d.get_stream_ban(sid, ban_id) is None, (who, frames)
        assert len(set(answers.values())) == 1, answers
        await mod.close()
    run(body)


async def collect(sock, quiet=0.6):
    """Every frame that arrives until the socket has been quiet for `quiet` seconds."""
    out = []
    while True:
        try:
            msg = await asyncio.wait_for(sock.ws.receive(), quiet)
        except asyncio.TimeoutError:
            return out
        if msg.type != aiohttp.WSMsgType.TEXT:
            return out
        out.append(json.loads(msg.data))


def test_a_ban_made_from_an_anonymous_post_never_applies_to_the_owner_or_an_administrator():
    """1.24.1: the rankless rule lets a stream mod ban the author of any anonymous post, so the chat read gate must
    keep the stream owner and administrators (the playback gate already does) out of the ban's reach."""
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        owner = await env.ws(ids["streamer"])
        await owner.join(cid)
        admin = await env.ws(ids["admin_author"])
        await admin.join(cid)
        for who in ("streamer", "admin_author", "member"):
            mid = await post(d, cid, ids, who, True, f"ban me {who}")
            frames = await act(mod, {"type": "ban", "message_id": mid, "reason": "r"})
            assert frames and not any(f["type"] == "error" for f in frames), (who, frames)
        assert await d.is_user_banned_from_stream(sid, ids["member"])
        channel = await d.get_chat_channel(cid)
        assert bool(await server._can_read_channel(channel, ids["streamer"], "user")), "the owner still reads"
        assert bool(await server._can_read_channel(channel, ids["admin_author"], "admin")), "an administrator still reads"
        refused = await server._can_read_channel(channel, ids["member"], "user")
        assert not refused and refused.reason == "banned", "an ordinary banned member is still refused"
        # the owner and the administrator were not put out of the room and can still speak in it
        for who, sock in (("streamer", owner), ("admin_author", admin)):
            await sock.send(type="message", message=f"still here {who}")
            got = await sock.until("message", "error")
            assert got["type"] == "message", (who, got)
            await sock.close()
        # and a fresh join works for both
        for who in ("streamer", "admin_author"):
            sock = await env.ws(ids[who])
            first = await sock.join(cid)
            assert first["type"] == "history", (who, first)
            await sock.close()
        late = await env.ws(ids["member"])
        refused_join = await late.join(cid)
        assert refused_join["type"] == "error" and "banned" in refused_join["message"], refused_join
        await late.close()
        await mod.close()
    run(body)


def test_a_timeout_made_from_an_anonymous_post_never_binds_the_owner_or_an_administrator():
    """1.24.1: the rankless rule lets a stream mod time out the author of any anonymous post, the owner and an
    administrator included. The owner has no route to lift it (30 days at most), so it does not bind them, as a ban
    made the same way does not. An ordinary member stays timed out, and a timeout placed by a staff role binds
    everybody it can be placed on."""
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        socks = {}

        async def say(sock, text):
            await collect(sock, 0.3)
            await sock.send(type="message", message=text)
            return await collect(sock, 0.6)
        for who in ("streamer", "admin_author", "member"):
            socks[who] = await env.ws(ids[who])
            await socks[who].join(cid)
            mid = await post(d, cid, ids, who, True, f"time me out {who}")
            frames = await act(mod, {"type": "timeout_user", "message_id": mid, "duration": 2592000, "reason": "r"})
            assert frames and not any(f["type"] == "error" for f in frames), (who, frames)
            assert await d.is_user_timed_out(ids[who], cid), (who, "the row is still recorded")
        for who in ("streamer", "admin_author"):
            sent = await say(socks[who], f"still here {who}")
            assert not any(f["type"] == "error" for f in sent) and any(f["type"] == "message" for f in sent), (who, sent)
        sent = await say(socks["member"], "should be refused")
        assert any(f.get("error_code") == "timeout" for f in sent), sent
        # a timeout a global moderator (staff) places on the owner still binds the owner
        gmod = await env.ws(ids["gmod"])
        await gmod.join(cid)
        await d.conn.execute("DELETE FROM chat_timeouts")
        await d.conn.commit()
        frames = await act(gmod, {"type": "timeout_user", "target_user_id": ids["streamer"], "duration": 60, "reason": "r"})
        assert frames and not any(f["type"] == "error" for f in frames), frames
        sent = await say(socks["streamer"], "staff timed me out")
        assert any(f.get("error_code") == "timeout" for f in sent), sent
        for sock in (*socks.values(), gmod, mod):
            await sock.close()
    run(body)


def test_a_ban_made_from_an_anonymous_post_does_not_name_the_author_to_the_moderator():
    """1.24.1: the author stays in the room under their name and is put out by the ban; the room is told that
    somebody left, but the stream mod's socket must not receive a frame that names them."""
    async def body(env):
        d = env.db
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        results = {}
        for who in ("member", "othermod"):
            author = await env.ws(ids[who])
            await author.join(cid)
            await collect(mod, 0.3)         # the frames that announced the join
            mid = await post(d, cid, ids, who, True, f"anon {who}")
            await mod.send(type="ban", message_id=mid, reason="r")
            frames = await collect(mod)
            assert any(f["type"] == "ban_success" for f in frames), (who, frames)
            text = json.dumps(frames)
            assert who not in text, (who, frames)
            assert not any(f.get("user_id") == ids[who] for f in frames), (who, frames)
            assert await d.is_user_banned_from_stream(sid, ids[who])
            results[who] = frames
            await author.close()
        await mod.close()
    run(body)


def test_a_timeout_made_from_an_anonymous_post_ends_nobody_s_call_whoever_wrote_it():
    """1.24.1: a timeout placed through an anonymous post gives the observers of the call and the room nothing that
    names or singles out the author: no voice_user_left with their id, no users list, whoever they are (an ordinary
    member in the call under their name, the owner, an administrator, another stream mod, a global moderator). The penalty is read at their next join."""
    async def body(env):
        d = env.db
        server.voice_state.clear()          # module state: an earlier test's calls and penalty denies are not this world's
        server._voice_penalty_denies.clear()
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        await mod.send(type="voice_join")
        await mod.until("voice_state")
        outcomes = {}
        for who in ("member", "streamer", "admin_author", "othermod", "moderator_author"):
            author = await env.ws(ids[who])
            await author.join(cid)
            await author.send(type="voice_join")
            await author.until("voice_state")
            await collect(mod, 0.4)
            await collect(author, 0.2)
            mid = await post(d, cid, ids, who, True, f"anon call {who}")
            await mod.send(type="timeout_user", message_id=mid, duration=60, reason="r")
            frames = await collect(mod, 0.8)
            assert any(f["type"] == "user_timed_out" for f in frames), (who, frames)
            assert await d.is_user_timed_out(ids[who], cid), who
            seen = [f["type"] for f in frames]
            assert "voice_user_left" not in seen and "users" not in seen, (who, frames)
            assert not any(f.get("user_id") == ids[who] and f["type"] != "user_timed_out" for f in frames), (who, frames)
            assert who not in json.dumps(frames), (who, frames)
            own = await collect(author, 0.3)
            assert not any(f["type"] in ("voice_denied", "voice_user_left") for f in own), (who, own)
            assert ids[who] in server.voice_state.get("modchat", {}), (who, "still in the call")
            if who == "member":
                # the consequence is applied at the next join attempt
                await author.send(type="voice_leave")
                await collect(author, 0.3)
                await author.send(type="voice_join")
                denied = await author.until("voice_denied", "voice_state")
                assert denied["type"] == "voice_denied" and denied.get("code") == "timed_out", denied
            outcomes[who] = seen
            await author.close()
            await collect(mod, 0.4)
            await d.conn.execute("DELETE FROM chat_timeouts")
            await d.conn.commit()
        await mod.close()
        # nobody is told apart: every author, the other stream mod and the global moderator included, gets the
        # same frames
        assert set(outcomes) == {"member", "streamer", "admin_author", "othermod", "moderator_author"}, outcomes
        assert len({tuple(v) for v in outcomes.values()}) == 1, outcomes
    run(body)


def test_a_timeout_made_from_a_named_post_still_ends_the_call():
    """The change above is only for a post that was anonymous: a timeout by a named message still removes the author
    from the call and tells the room."""
    async def body(env):
        d = env.db
        server.voice_state.clear()          # module state: an earlier test's calls and penalty denies are not this world's
        server._voice_penalty_denies.clear()
        ids, cid, sid = await world(d)
        mod = await env.ws(ids["mod1"])
        await mod.join(cid)
        await mod.send(type="voice_join")
        await mod.until("voice_state")
        author = await env.ws(ids["member"])
        await author.join(cid)
        await author.send(type="voice_join")
        await author.until("voice_state")
        await collect(mod, 0.4)
        mid = await post(d, cid, ids, "member", False, "named")
        await mod.send(type="timeout_user", message_id=mid, duration=60, reason="r")
        frames = await collect(mod, 0.8)
        assert any(f["type"] == "voice_user_left" and f.get("user_id") == ids["member"] for f in frames), frames
        await author.close()
        await mod.close()
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
