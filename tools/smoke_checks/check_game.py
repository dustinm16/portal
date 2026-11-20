"""Live title and game on a running instance.

Over HTTP and the chat websocket against the staged server (real logins; the MediaMTX publish
hook is posted from loopback): the owner sets a game at create, goes live and changes the game and
the title, and a member in the stream's chat room receives a stream_info frame and sees the new
values in the stream detail, the public listing and the live-now list; a game that was switched away
from is still offered to its owner and is not offered to anybody else; a stream made private with a
new title and game sends nothing with them to the member's socket, and its game is not offered to
the member, while the owner still gets the frame and the suggestion; a game over 60 characters is
refused.

Users, streams and games carry random suffixes and every assertion is about those rows, so the
module also holds on a stage started from a copy of a production database. It needs no admin
password.

Not proven here (needs the real thing): a browser repainting the watch page and the cards from the
frame, the datalist in a real browser, a real MediaMTX and OBS.
"""
import asyncio
import json
import secrets
import time

PW = "Game-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "m1", "m2"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


class Reader:
    """A chat socket with a background reader that keeps every frame."""

    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.ensure_future(self._pump())

    async def _pump(self):
        try:
            async for msg in self.ws:
                try:
                    self.events.append(json.loads(msg.data))
                except Exception:
                    pass
        except Exception:
            pass

    async def wait(self, pred, start=0, timeout=6.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.1)
        return None


async def run(ctx):
    pre = "gm" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    if rc != 0 or _result(out) is None:
        ctx.ok("game: setup", False, out[-500:])
        return
    base = ctx.base_url
    streams = []

    def ok(name, passed, detail=""):
        ctx.ok("game: " + name, bool(passed), "" if passed else detail)

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def games(sess):
        st, b = await call(sess, "GET", "/api/streams/games")
        return st, (b or {}).get("games") or []

    async with ctx.http() as owner, ctx.http() as m1, ctx.http() as hk:
        try:
            for name, sess in (("owner", owner), ("m1", m1)):
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return
            g1, g2, g3 = pre + " Alpha", pre + " Beta", pre + " Secret"
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "s", "is_public": True, "game": g1})
            if st != 201:
                ok("the stream is created with a game", False, f"{st} {b}")
                return
            made = b["stream"]
            sid = made["id"]
            streams.append(sid)
            ok("a game is set at create", made.get("game") == g1, str(made.get("game")))
            st, b = await call(owner, "POST", "/api/streams", json={"name": pre + "long", "game": "x" * 61})
            ok("a game over 60 characters is refused", st == 400, f"{st} {b}")
            if st == 201:
                streams.append(b["stream"]["id"])
            s = await hk.post(base + "/api/stream/auth", json={
                "action": "publish", "path": "live/" + made["stream_key"],
                "password": made["stream_key"], "ip": "127.0.0.1"})
            async with s:
                ok("the stream goes live", s.status == 200, str(s.status))
            st, b = await call(m1, "GET", f"/api/streams/{sid}")
            chan = (b or {}).get("stream", {}).get("chat_channel_id")
            ok("a member sees the game and the chat channel of the public stream",
               st == 200 and b["stream"].get("game") == g1 and chan, f"{st} {b}")
            if not chan:
                return

            ws = await m1.ws_connect(f"{base}/ws/chat", max_msg_size=0)
            sock = Reader(ws)
            try:
                await sock.ws.send_json({"type": "join", "channel_id": chan})
                joined = await sock.wait(lambda e: e.get("type") in ("history", "error"))
                ok("the member joins the stream's chat", joined and joined["type"] == "history", str(joined))
                owner_ws = await owner.ws_connect(f"{base}/ws/chat", max_msg_size=0)
                osock = Reader(owner_ws)
                await osock.ws.send_json({"type": "join", "channel_id": chan})
                await osock.wait(lambda e: e.get("type") in ("history", "error"))

                # ---- change the game mid-stream
                mark = len(sock.events)
                st, b = await call(owner, "PUT", f"/api/streams/{sid}", json={"game": g2})
                ok("the owner changes the game", st == 200 and b["stream"]["game"] == g2, f"{st} {b}")
                got = await sock.wait(lambda e: e.get("type") == "stream_info", mark)
                ok("the member's socket gets a stream_info frame with the stream id, name and game",
                   got and got.get("stream_id") == sid and got.get("game") == g2 and got.get("name") == pre + "s",
                   str(got))
                st, b = await call(m1, "GET", "/api/streams/public")
                row = [x for x in (b or {}).get("streams", []) if x["id"] == sid]
                ok("the public listing carries the new game", row and row[0].get("game") == g2, str(row))
                st, b = await call(m1, "GET", "/api/streams/live")
                row = [x for x in (b or {}).get("streams", []) if x["id"] == sid]
                ok("the live-now list carries the new game", row and row[0].get("game") == g2, str(row))

                # ---- the title
                mark = len(sock.events)
                st, b = await call(owner, "PUT", f"/api/streams/{sid}", json={"name": pre + "s2"})
                got = await sock.wait(lambda e: e.get("type") == "stream_info", mark)
                ok("a new title is sent too", st == 200 and got and got.get("name") == pre + "s2"
                   and got.get("game") == g2, f"{st} {got}")

                # ---- suggestions
                st, mine = await games(owner)
                ok("the owner's earlier game and the current one are offered",
                   st == 200 and g1 in mine and g2 in mine and mine.index(g2) < mine.index(g1), str(mine[:8]))
                st, theirs = await games(m1)
                ok("a member is offered the public stream's current game but not its earlier one",
                   st == 200 and g2 in theirs and g1 not in theirs, str(theirs[:8]))

                # ---- private: a new title and game reach only the owner
                mark, omark = len(sock.events), len(osock.events)
                st, b = await call(owner, "PUT", f"/api/streams/{sid}",
                                   json={"is_public": False, "name": pre + "hidden", "game": g3})
                ok("the owner makes it private with a new title and game", st == 200, f"{st} {b}")
                got = await osock.wait(lambda e: e.get("type") == "stream_info" and e.get("game") == g3, omark)
                ok("the owner's socket still gets the frame", got is not None, str(osock.events[omark:]))
                await asyncio.sleep(1.0)
                leaked = [e for e in sock.events[mark:] if pre + "hidden" in json.dumps(e) or g3 in json.dumps(e)]
                ok("the member's socket gets nothing with the new title or game", not leaked, str(leaked))
                st, _ = await call(m1, "GET", f"/api/streams/{sid}")
                ok("the member cannot read the stream any more", st == 404, str(st))
                st, theirs = await games(m1)
                ok("a member is not offered a private stream's game", st == 200 and g3 not in theirs and g2 not in theirs,
                   str(theirs[:8]))
                st, mine = await games(owner)
                ok("the owner is", st == 200 and g3 in mine, str(mine[:8]))
                st, b = await call(m1, "GET", "/api/streams/live")
                ok("and the live list leaves the stream out", all(x["id"] != sid for x in (b or {}).get("streams", [])),
                   str(b)[:200])
            finally:
                for r in (sock, locals().get("osock")):
                    if r:
                        r.task.cancel()
                        await r.ws.close()
        finally:
            for x in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{x}")
                except Exception:
                    pass
