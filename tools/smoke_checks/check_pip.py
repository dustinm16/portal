"""Pop-out stream chat: a second chat socket of the same user.

The pop-out window (/watch/<id>?chat=only) loads the stream and joins the chat the
same way as the normal watch page, so it is a second websocket of the same user in
the same room. This module proves, over real sockets on the staged instance:

- the pop-out page goes through the same access path as the normal page (same
  status, redirect and body for anonymous visitors, the owner and an outsider; a
  private stream is still 404 for the outsider);
- a second socket does not produce a second join announcement or a second entry
  in the users list, and its messages reach the main tab and other members;
- closing either socket announces a leave only when the last one goes, and a
  voice call joined on the main socket survives closing the pop-out;
- anonymous masking is the same on both sockets, including when the member
  switches anonymous mode on or off over HTTP while two sockets (or one socket
  after a pop-out was opened and closed) are connected; a banned user is
  refused on both.

Absence of an announcement is proved without sleeps: the server sends the users
list to the room right after the (skipped) join or leave announcement, so once a
fresh users list arrives with no announcement before it, none was sent.
"""
import asyncio
import json
from contextlib import AsyncExitStack

PW = "pip-smoke-pass-1234"
ANON_NAME = "pipanon"

SETUP = '''
import asyncio, json
from database import db
from auth import hash_password
import server

async def main():
    await db.connect()
    try:
        await body()
    finally:
        await db.close()

async def body():
    out = {}
    for name in ("pipowner", "pipalice", "pipbob", "pipvoice", "pipanon", "pipban", "pipout", "pipmask", "pipmaskb"):
        u = await db.get_user_by_username(name)
        out[name] = u["id"] if u else await db.create_user(name, hash_password(%(pw)r))
    await db.set_chat_anonymous(out["pipanon"], True)
    for label, public in (("pub", True), ("priv", False)):
        sk, pk = server.generate_stream_key(), server.generate_public_key()
        sid = await db.create_user_stream(user_id=out["pipowner"], name="pip " + label, stream_key=sk,
                                          public_key=pk, is_public=public)
        cid = await db.create_chat_channel(name="stream-pip-%%s-%%d" %% (label, sid), created_by=out["pipowner"])
        await db.update_user_stream(sid, chat_channel_id=cid)
        out[label] = {"id": sid, "public_key": pk, "channel": cid}
    await db.create_stream_ban(out["pub"]["id"], out["pipban"], out["pipowner"], "smoke")
    print("RESULT " + json.dumps(out))

asyncio.run(main())
''' % {"pw": PW}


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


class Client:
    """One chat websocket with its collected events."""

    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                if msg.type == 1:
                    self.events.append(json.loads(msg.data))
        except Exception:
            pass

    def mark(self):
        return len(self.events)

    async def wait(self, pred, start=0, timeout=10.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.05)
        return None

    def count(self, etype, start=0, **kw):
        return sum(1 for e in self.events[start:]
                   if e.get("type") == etype and all(e.get(k) == v for k, v in kw.items()))

    async def close(self):
        try:
            await self.ws.close()
        except Exception:
            pass
        self.task.cancel()


def _check(ctx, name, passed, detail=""):
    """Record a result; the evidence is only attached when the check fails."""
    ctx.ok(name, bool(passed), "" if passed else str(detail))


def _is(etype):
    return lambda e: e.get("type") == etype


async def _page(sess, base, path):
    async with sess.get(base + path, allow_redirects=False) as r:
        return r.status, r.headers.get("Location"), await r.text()


async def _page_parity(ctx, st):
    base = ctx.base_url
    async with ctx.http() as anon, ctx.http() as owner, ctx.http() as outsider:
        for s, name in ((owner, "pipowner"), (outsider, "pipout")):
            r = await ctx.login(s, name, PW)
            if r.status != 200:
                _check(ctx, "pip: login " + name, False, f"status {r.status}")
                return
        for who, sess in (("anonymous", anon), ("owner", owner), ("outsider", outsider)):
            for label in ("pub", "priv"):
                sid = st[label]["id"]
                plain = await _page(sess, base, f"/watch/{sid}")
                popped = await _page(sess, base, f"/watch/{sid}?chat=only")
                _check(ctx, f"pip: /watch/<id>?chat=only matches the normal page for {who} on the {label} stream",
                       plain == popped, f"{plain[:2]} vs {popped[:2]}")
        status, loc, _ = await _page(anon, base, f"/watch/{st['pub']['id']}?chat=only")
        _check(ctx, "pip: anonymous visitor of the pop-out page is sent to /login",
               status == 302 and (loc or "").startswith("/login"), f"{status} {loc}")
        status, _, body = await _page(owner, base, f"/watch/{st['pub']['id']}?chat=only")
        _check(ctx, "pip: pop-out page is the watch page with the chat-only switch",
               status == 200 and "chat-only" in body and "get('chat') === 'only'" in body, f"status {status}")
        live_status, _, live_body = await _page(anon, base, "/live")
        for label, code, page in (("watch", status, body), ("live", live_status, live_body)):
            _check(ctx, f"pip: {label} page keeps the PiP button reachable with native HLS and refreshes it on loadedmetadata",
                   code == 200 and "native-hls" in page and "'loadedmetadata'" in page
                   and "player-control-group pip-group" in page, f"status {code}")
        # the data the page loads before it joins the chat: same API, same refusal
        async with outsider.get(f"{base}/api/streams/{st['priv']['id']}") as r:
            _check(ctx, "pip: outsider still gets 404 for a private stream the pop-out would load",
                   r.status == 404, f"status {r.status}")
        async with outsider.get(f"{base}/api/streams/{st['pub']['id']}") as r:
            body = await r.json()
            _check(ctx, "pip: outsider loads the public stream and sees its public key only",
                   r.status == 200 and body["stream"].get("public_key") == st["pub"]["public_key"]
                   and "stream_key" not in body["stream"], f"status {r.status}")
        async with owner.get(f"{base}/api/streams/{st['priv']['id']}") as r:
            _check(ctx, "pip: owner loads the private stream", r.status == 200, f"status {r.status}")


async def _open(ctx, stack, name):
    sess = await stack.enter_async_context(ctx.http())
    r = await ctx.login(sess, name, PW)
    return sess if r.status == 200 else None


async def _connect(ctx, stack, sess, key, wait_users=True):
    ws = await stack.enter_async_context(sess.ws_connect(f"{ctx.base_url}/ws/chat"))
    cl = Client(ws)
    stack.callback(cl.task.cancel)
    await ws.send_json({"type": "join", "stream_key": key})
    if wait_users:
        await cl.wait(_is("users"))
    return cl


def _entries_for(event, **kw):
    return [u for u in (event or {}).get("users", []) if all(u.get(k) == v for k, v in kw.items())]


async def _presence(ctx, st, key):
    async with AsyncExitStack() as stack:
        s_bob = await _open(ctx, stack, "pipbob")
        s_alice = await _open(ctx, stack, "pipalice")
        if s_bob is None or s_alice is None:
            _check(ctx, "pip: presence users can log in", False, "login failed")
            return
        bob = await _connect(ctx, stack, s_bob, key)
        m = bob.mark()
        a1 = await _connect(ctx, stack, s_alice, key)
        await bob.wait(lambda e: e.get("type") == "users" and _entries_for(e, username="pipalice"), start=m)
        _check(ctx, "pip: first socket of a member is announced once",
               bob.count("user_joined", m, username="pipalice") == 1, json.dumps(bob.events[m:])[:300])

        # second socket (pop-out) joins
        m_b, m_a = bob.mark(), a1.mark()
        a2 = await _connect(ctx, stack, s_alice, key)
        got = await bob.wait(_is("users"), start=m_b)
        _check(ctx, "pip: second socket joins and sees history and the users list",
               a2.count("history") == 1 and a2.count("users") >= 1 and got is not None,
               "no users list reached the observer")
        _check(ctx, "pip: second socket sends no second join announcement to other members",
               bob.count("user_joined", m_b) == 0, json.dumps(bob.events[m_b:])[:300])
        _check(ctx, "pip: second socket sends no join announcement to the main tab either",
               a1.count("user_joined", m_a) == 0, json.dumps(a1.events[m_a:])[:300])
        own = next((e for e in reversed(a2.events) if e.get("type") == "users"), None)
        _check(ctx, "pip: users list has one entry for the member, for the observer and for the pop-out",
               len(_entries_for(got, username="pipalice")) == 1 and len(_entries_for(own, username="pipalice")) == 1,
               json.dumps([got, own])[:300])

        # a message from the pop-out reaches the main tab and other members
        text = "from the popout"
        m_b, m_a = bob.mark(), a1.mark()
        await a2.ws.send_json({"type": "message", "message": text})
        r_bob = await bob.wait(lambda e: e.get("type") == "message" and e.get("message") == text, start=m_b)
        r_a1 = await a1.wait(lambda e: e.get("type") == "message" and e.get("message") == text, start=m_a)
        _check(ctx, "pip: a message sent from the pop-out reaches other members and the main tab",
               r_bob is not None and r_a1 is not None and r_bob.get("username") == "pipalice",
               "bob=%s main=%s" % (r_bob is not None, r_a1 is not None))

        # closing the pop-out while the main tab is connected: no leave
        m_b = bob.mark()
        await a2.close()
        got = await bob.wait(_is("users"), start=m_b)
        _check(ctx, "pip: closing the pop-out announces no leave while the main tab is connected",
               got is not None and bob.count("user_left", m_b) == 0, json.dumps(bob.events[m_b:])[:300])
        _check(ctx, "pip: the member is still listed after the pop-out closed",
               len(_entries_for(got, username="pipalice")) == 1, json.dumps(got)[:300])

        # last socket gone: exactly one leave
        m_b = bob.mark()
        await a1.close()
        await bob.wait(_is("user_left"), start=m_b)
        await bob.wait(_is("users"), start=m_b)
        _check(ctx, "pip: closing the last socket announces exactly one leave",
               bob.count("user_left", m_b, username="pipalice") == 1, json.dumps(bob.events[m_b:])[:300])

        # the other order: main tab closes first, pop-out stays
        a1 = await _connect(ctx, stack, s_alice, key)
        a2 = await _connect(ctx, stack, s_alice, key)
        m_b = bob.mark()
        await a1.close()
        got = await bob.wait(_is("users"), start=m_b)
        _check(ctx, "pip: closing the main tab first announces no leave while the pop-out stays",
               got is not None and bob.count("user_left", m_b) == 0, json.dumps(bob.events[m_b:])[:300])
        m_b = bob.mark()
        await a2.close()
        await bob.wait(_is("user_left"), start=m_b)
        _check(ctx, "pip: the pop-out closing last announces the leave",
               bob.count("user_left", m_b, username="pipalice") == 1, json.dumps(bob.events[m_b:])[:300])
        await bob.close()


async def _voice(ctx, st, key):
    async with AsyncExitStack() as stack:
        s_bob = await _open(ctx, stack, "pipbob")
        s_v = await _open(ctx, stack, "pipvoice")
        if s_bob is None or s_v is None:
            _check(ctx, "pip: voice users can log in", False, "login failed")
            return
        bob = await _connect(ctx, stack, s_bob, key)
        await bob.ws.send_json({"type": "voice_join"})
        await bob.wait(_is("voice_state"))
        v1 = await _connect(ctx, stack, s_v, key)
        m = bob.mark()
        await v1.ws.send_json({"type": "voice_join"})
        joined = await bob.wait(_is("voice_user_joined"), start=m)
        _check(ctx, "pip: voice joined on the main socket is seen by another voice member", joined is not None)
        v2 = await _connect(ctx, stack, s_v, key)
        m = bob.mark()
        await v2.close()
        got = await bob.wait(_is("users"), start=m)
        _check(ctx, "pip: closing the pop-out does not end the voice call of the main tab",
               got is not None and bob.count("voice_user_left", m) == 0, json.dumps(bob.events[m:])[:300])
        _check(ctx, "pip: the member is still listed as in voice after the pop-out closed",
               any(u.get("in_voice") for u in _entries_for(got, username="pipvoice")), json.dumps(got)[:300])
        m = bob.mark()
        await v1.close()
        left = await bob.wait(_is("voice_user_reconnecting"), start=m)
        _check(ctx, "pip: closing the socket that holds the voice call puts it on hold", left is not None)
        await bob.close()


async def _anonymous(ctx, st, key, anon_id):
    async with AsyncExitStack() as stack:
        s_bob = await _open(ctx, stack, "pipbob")
        s_anon = await _open(ctx, stack, ANON_NAME)
        if s_bob is None or s_anon is None:
            _check(ctx, "pip: anonymous users can log in", False, "login failed")
            return
        bob = await _connect(ctx, stack, s_bob, key)
        m = bob.mark()
        n1 = await _connect(ctx, stack, s_anon, key)
        await bob.wait(lambda e: e.get("type") == "users" and _entries_for(e, anonymous=True), start=m)
        m2 = bob.mark()
        n2 = await _connect(ctx, stack, s_anon, key)
        got = await bob.wait(_is("users"), start=m2)
        _check(ctx, "pip: an anonymous member's second socket adds no announcement and no second entry",
               got is not None and bob.count("user_joined", m2) == 0 and len(_entries_for(got, anonymous=True)) == 1,
               json.dumps(bob.events[m2:])[:300])
        text = "anon from the popout"
        m3 = bob.mark()
        await n2.ws.send_json({"type": "message", "message": text})
        msg = await bob.wait(lambda e: e.get("type") == "message" and e.get("message") == text, start=m3)
        await n1.wait(lambda e: e.get("type") == "message" and e.get("message") == text)
        blob = json.dumps(bob.events[m:])
        _check(ctx, "pip: anonymous masking is the same for messages from the pop-out",
               msg is not None and msg.get("username") == "Anonymous" and msg.get("user_id") is None
               and ANON_NAME not in blob and f'"user_id": {anon_id}' not in blob, blob[:400])
        m4 = bob.mark()
        await n2.close()
        await bob.wait(_is("users"), start=m4)
        _check(ctx, "pip: closing an anonymous member's pop-out announces no leave",
               bob.count("user_left", m4) == 0, json.dumps(bob.events[m4:])[:300])
        await bob.close()


async def _toggle(sess, base, value):
    async with sess.put(f"{base}/api/me/anonymous", json={"anonymous": value}) as r:
        return r.status


async def _say(ctx, bob, sender, text):
    """Send from one socket; return the copy another member receives."""
    m = bob.mark()
    await sender.ws.send_json({"type": "message", "message": text})
    return await bob.wait(lambda e: e.get("type") == "message" and e.get("message") == text, start=m)


async def _mask_toggle(ctx, st, key, ids):
    """Anonymous mode switched over HTTP while a member holds several sockets.

    The HTTP handler updates one shared per-user state; every socket of the member
    must follow it, not only the newest one.
    """
    async with AsyncExitStack() as stack:
        s_bob = await _open(ctx, stack, "pipbob")
        s_a = await _open(ctx, stack, "pipmask")
        s_b = await _open(ctx, stack, "pipmaskb")
        if s_bob is None or s_a is None or s_b is None:
            _check(ctx, "pip: masking users can log in", False, "login failed")
            return
        bob = await _connect(ctx, stack, s_bob, key)

        # A: main tab and pop-out both open, then anonymous mode is switched on
        main = await _connect(ctx, stack, s_a, key)
        pop = await _connect(ctx, stack, s_a, key)
        m_on = bob.mark()
        status = await _toggle(s_a, ctx.base_url, True)
        _check(ctx, "pip: anonymous mode can be switched on with two sockets open", status == 200, f"status {status}")
        for label, cl in (("main tab", main), ("pop-out", pop)):
            text = f"masked from the {label}"
            got = await _say(ctx, bob, cl, text)
            _check(ctx, f"pip: a message from the {label} is masked after anonymous mode was switched on",
                   got is not None and got.get("username") == "Anonymous" and got.get("user_id") is None
                   and got.get("anonymous") is True, json.dumps(got)[:300])
        blob = json.dumps(bob.events[m_on:])
        _check(ctx, "pip: the real name and id of a member with two sockets never reach other members after the switch",
               "pipmask\"" not in blob and f'"user_id": {ids["pipmask"]}' not in blob, blob[:400])
        # closing the newer socket must not leave the older one on stale state
        await pop.close()
        got = await _say(ctx, bob, main, "masked after the pop-out closed")
        _check(ctx, "pip: the main tab stays masked after the pop-out closed",
               got is not None and got.get("username") == "Anonymous" and got.get("user_id") is None,
               json.dumps(got)[:300])
        # and back off again: both sockets show the real name
        pop = await _connect(ctx, stack, s_a, key)
        status = await _toggle(s_a, ctx.base_url, False)
        _check(ctx, "pip: anonymous mode can be switched off with two sockets open", status == 200, f"status {status}")
        for label, cl in (("main tab", main), ("pop-out", pop)):
            got = await _say(ctx, bob, cl, f"visible from the {label}")
            _check(ctx, f"pip: a message from the {label} shows the real name after anonymous mode was switched off",
                   got is not None and got.get("username") == "pipmask" and got.get("anonymous") is False,
                   json.dumps(got)[:300])
        await main.close()
        await pop.close()

        # B: pop-out opened and closed first, then anonymous mode switched on
        main = await _connect(ctx, stack, s_b, key)
        pop = await _connect(ctx, stack, s_b, key)
        await pop.close()
        status = await _toggle(s_b, ctx.base_url, True)
        _check(ctx, "pip: anonymous mode can be switched on after a pop-out was opened and closed",
               status == 200, f"status {status}")
        got = await _say(ctx, bob, main, "masked, popout already gone")
        _check(ctx, "pip: the main tab is masked when the pop-out was opened and closed before the switch",
               got is not None and got.get("username") == "Anonymous" and got.get("user_id") is None
               and got.get("anonymous") is True, json.dumps(got)[:300])
        await _toggle(s_b, ctx.base_url, False)
        await main.close()
        await bob.close()


async def _banned(ctx, st, key):
    async with AsyncExitStack() as stack:
        s_bob = await _open(ctx, stack, "pipbob")
        s_ban = await _open(ctx, stack, "pipban")
        if s_bob is None or s_ban is None:
            _check(ctx, "pip: ban users can log in", False, "login failed")
            return
        bob = await _connect(ctx, stack, s_bob, key)
        m = bob.mark()
        for label in ("main socket", "pop-out socket"):
            cl = await _connect(ctx, stack, s_ban, key, wait_users=False)
            err = await cl.wait(lambda e: e.get("type") == "error" and "banned" in (e.get("message") or ""))
            _check(ctx, f"pip: a banned user is refused on the {label}",
                   err is not None and cl.count("history") == 0 and cl.count("channel_info") == 0,
                   json.dumps(cl.events)[:300])
            text = "banned try " + label
            await cl.ws.send_json({"type": "message", "message": text})
            await asyncio.sleep(0.3)
            await cl.close()
        _check(ctx, "pip: a banned user's messages and presence never reach the room",
               bob.count("user_joined", m, username="pipban") == 0
               and not any(e.get("type") == "message" and "banned try" in (e.get("message") or "")
                           for e in bob.events[m:]), json.dumps(bob.events[m:])[:300])
        await bob.close()


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    st = _result(out)
    _check(ctx, "pip: staged users and streams created", rc == 0 and st is not None, out[-300:] if st is None else "")
    if st is None:
        return
    key = st["pub"]["public_key"]
    await _page_parity(ctx, st)
    await _presence(ctx, st, key)
    await _voice(ctx, st, key)
    await _anonymous(ctx, st, key, st["pipanon"])
    await _mask_toggle(ctx, st, key, st)
    await _banned(ctx, st, key)
