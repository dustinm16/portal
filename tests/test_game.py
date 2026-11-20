"""Live title and game field on streams.

* game: at most 60 characters, control characters stripped, a lone surrogate or a non-string
  refused, empty means none; settable at create and update; in the allow-listed columns
* a live stream whose name or game changes sends a `stream_info` frame (stream id, name,
  game) to the sockets that may read the room AND may watch the stream; a private stream's
  new title or game reaches nobody but its owner and administrators, also when the stream
  is bound to a channel that is never hidden (the default channel)
* GET /api/streams/games: the caller's earlier games, then the game of streams that are
  public now; never a private stream's game or another member's history; bounded to 50
* go-live: the game is in the stream.live payload, the {game} placeholder, the card (also
  when history rebuilds it), the notification and the live-now list
* the pages render it with textContent / escapeHtml

Run: venv/bin/python tests/test_game.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import server  # noqa: E402
from database import Database  # noqa: E402
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
from test_chat_access_loss import Env, fake_auth, fake_valid, stream_chat, users  # noqa: E402
from test_golive import World, with_world  # noqa: E402

NEW_NAME = "Brand New Title"


server._STREAM_INFO_MIN_GAP = 0.05      # the existing frame tests change one stream many times


class GameEnv(Env):
    """The chat test environment with the stream routes this file needs as well."""

    async def __aenter__(self):
        from pathlib import Path
        from database import Database
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth),
                            ("_credential_still_valid", fake_valid)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server.chat_rooms.clear()
        server.voice_state.clear()
        app = web.Application()
        app.router.add_get("/ws/chat", server.handle_chat_websocket)
        app.router.add_post("/api/streams", server.http_create_user_stream)
        app.router.add_get("/api/streams/games", server.http_stream_games)
        app.router.add_get("/api/streams/{id}", server.http_get_user_stream)
        app.router.add_put("/api/streams/{id}", server.http_update_user_stream)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def call(self, method, user_id, path, **kw):
        async with self.http.request(method, self.url(path), headers={"X-Test-User": str(user_id)}, **kw) as r:
            return r.status, (await r.json() if r.content_type == "application/json" else await r.text())


def run(body):
    async def go():
        async with GameEnv() as env:
            await body(env)
    asyncio.run(go())


async def set_live(d, sid, live=True):
    await d.set_stream_live(sid, live)


def frames(sock, start=0):
    return [e for e in sock.events[start:] if e.get("type") == "stream_info"]


# ---------------------------------------------------------------------------
# validation and storage

def test_game_is_validated_like_the_other_stream_text_fields():
    ok = server._validate_stream_fields
    assert ok({"game": "Chess"}) == ({"game": "Chess"}, None)
    assert ok({"game": "  Chess  "})[0] == {"game": "Chess"}
    assert ok({"game": "a\x00b\x1bc‮d"})[0] == {"game": "abcd"}          # controls, bidi override
    assert ok({"game": "a\tb\nc"})[0] == {"game": "a b c"}
    assert ok({"game": ""})[0] == {"game": None} and ok({"game": None})[0] == {"game": None}
    assert ok({"game": "x" * 60})[1] is None
    assert "60" in ok({"game": "x" * 61})[1]
    assert ok({"game": "x" * 5000})[1] is not None                              # refused before stripping
    assert ok({"game": "a\ud800b"})[1] is not None                              # lone surrogate
    for bad in (5, ["a"], {"a": 1}, True):
        assert ok({"game": bad})[1] is not None, bad
    assert "game" in server._STREAM_CLIENT_FIELDS
    assert "game" in Database.PUBLIC_STREAM_COLUMNS


def test_game_is_set_at_create_and_update_and_shown_to_members():
    async def body(env):
        d = env.db
        ids = await users(d)
        st, b = await env.call("POST", ids["owner"], "/api/streams",
                               json={"name": "g1", "game": "Doom", "is_public": True})
        assert st == 201 and b["stream"]["game"] == "Doom", b
        sid = b["stream"]["id"]
        st, b = await env.call("POST", ids["owner"], "/api/streams", json={"name": "g2", "game": "x" * 61})
        assert st == 400, b
        st, b = await env.call("PUT", ids["viewer"], f"/api/streams/{sid}", json={"game": "Hacked"})
        assert st == 404 and (await d.get_user_stream(sid))["game"] == "Doom"
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": "Quake\x07"})
        assert st == 200 and b["stream"]["game"] == "Quake", b
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": 7})
        assert st == 400
        # a member sees it on the detail route and in the public listing
        st, b = await env.call("GET", ids["viewer"], f"/api/streams/{sid}")
        assert st == 200 and b["stream"]["game"] == "Quake", b
        assert [s["game"] for s in await d.get_public_streams() if s["id"] == sid] == ["Quake"]
        # a private stream: its game is not in the detail route for a member
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": False})
        assert st == 200
        st, b = await env.call("GET", ids["viewer"], f"/api/streams/{sid}")
        assert st == 404 and "Quake" not in json.dumps(b)
        assert await d.get_public_streams() == []
        # clearing it
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": ""})
        assert st == 200 and b["stream"]["game"] is None
    run(body)


# ---------------------------------------------------------------------------
# the live frame

def test_a_live_streams_name_and_game_change_reaches_the_room():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        owner, viewer, boss = await env.sock(ids["owner"]), await env.sock(ids["viewer"]), await env.sock(ids["boss"])
        for s in (owner, viewer, boss):
            await s.join(cid)
        # offline: nothing is sent (the pages read it when they next load)
        mark = {s: s.mark() for s in (owner, viewer, boss)}
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": "Offline Game"})
        assert st == 200
        await asyncio.sleep(0.2)
        assert not any(frames(s, mark[s]) for s in mark)
        await set_live(d, sid)
        mark = {s: s.mark() for s in (owner, viewer, boss)}
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": "Chess"})
        assert st == 200
        got = await viewer.wait(lambda e: e.get("type") == "stream_info", mark[viewer])
        assert got == {"type": "stream_info", "stream_id": sid, "name": "s1", "game": "Chess"}, got
        for s in (owner, boss):
            assert await s.wait(lambda e: e.get("type") == "stream_info", mark[s])
        # a rename alone, and the game cleared, are changes too
        m = viewer.mark()
        await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": NEW_NAME})
        got = await viewer.wait(lambda e: e.get("type") == "stream_info", m)
        assert got["name"] == NEW_NAME and got["game"] == "Chess", got
        m = viewer.mark()
        await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": ""})
        got = await viewer.wait(lambda e: e.get("type") == "stream_info", m)
        assert got["game"] is None, got
        # no change (same values, clearing an empty game, another field): no frame
        m = viewer.mark()
        for payload in ({"name": NEW_NAME}, {"game": ""}, {"game": None}, {"description": "hello"}):
            st, _ = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json=payload)
            assert st == 200
        await asyncio.sleep(0.3)
        assert frames(viewer, m) == []
    run(body)


def test_a_private_streams_new_title_and_game_reach_only_its_owner_and_admins():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        await set_live(d, sid)
        owner, viewer, boss = await env.sock(ids["owner"]), await env.sock(ids["viewer"]), await env.sock(ids["boss"])
        for s in (owner, viewer, boss):
            await s.join(cid)
        mark = {s: s.mark() for s in (owner, viewer, boss)}
        # one request: private and renamed and a new game
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}",
                               json={"is_public": False, "name": "Secret Title", "game": "Secret Game"})
        assert st == 200, b
        for s in (owner, boss):
            got = await s.wait(lambda e: e.get("type") == "stream_info", mark[s])
            assert got and got["name"] == "Secret Title" and got["game"] == "Secret Game", got
        await asyncio.sleep(0.3)
        assert "Secret" not in json.dumps(viewer.events[mark[viewer]:]), viewer.events[mark[viewer]:]
        # and a later change of the private stream
        m = viewer.mark()
        await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": "Still Secret"})
        assert await boss.wait(lambda e: e.get("type") == "stream_info" and e["game"] == "Still Secret", mark[boss])
        await asyncio.sleep(0.2)
        assert "Secret" not in json.dumps(viewer.events[m:])
    run(body)


def test_a_private_stream_bound_to_the_default_channel_leaks_nothing_to_its_members():
    async def body(env):
        d = env.db
        ids = await users(d)
        _cid, sid = await stream_chat(d, ids, public=False)
        general = await d.get_chat_channel_by_name("general")
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (general["id"], sid))
        await d.conn.commit()
        await set_live(d, sid)
        owner, viewer, boss = await env.sock(ids["owner"]), await env.sock(ids["viewer"]), await env.sock(ids["boss"])
        for s in (owner, viewer, boss):
            await s.join(general["id"])
        mark = {s: s.mark() for s in (owner, viewer, boss)}
        st, b = await env.call("PUT", ids["owner"], f"/api/streams/{sid}",
                               json={"name": "Hidden Title", "game": "Hidden Game"})
        assert st == 200, b
        for s in (owner, boss):
            assert await s.wait(lambda e: e.get("type") == "stream_info", mark[s]), "owner and admin are told"
        await asyncio.sleep(0.3)
        assert "Hidden" not in json.dumps(viewer.events[mark[viewer]:]), viewer.events[mark[viewer]:]
    run(body)


def test_a_member_banned_from_the_stream_chat_gets_no_frame():
    async def body(env):
        d = env.db
        ids = await users(d)
        cid, sid = await stream_chat(d, ids, public=True)
        await set_live(d, sid)
        viewer, other = await env.sock(ids["viewer"]), await env.sock(ids["carol"])
        for s in (viewer, other):
            await s.join(cid)
        assert await d.create_stream_ban(sid, ids["viewer"], ids["owner"], "r")
        m, mo = viewer.mark(), other.mark()
        await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"game": "Banned Test"})
        assert await other.wait(lambda e: e.get("type") == "stream_info", mo)
        await asyncio.sleep(0.2)
        assert frames(viewer, m) == []
    run(body)


# ---------------------------------------------------------------------------
# suggestions

def test_the_games_route_lists_earlier_games_and_public_ones_but_never_a_private_one():
    async def body(env):
        d = env.db
        ids = await users(d)

        async def make(user, name, game, public):
            st, b = await env.call("POST", ids[user], "/api/streams",
                                   json={"name": name, "game": game, "is_public": public})
            assert st == 201, b
            return b["stream"]["id"]

        mine = await make("owner", "mine", "Alpha Game", False)
        await make("alice", "pubs", "Public Game", True)
        hidden = await make("alice", "privs", "Alice Private Game", False)
        went_private = await make("bob", "was", "Was Public Game", True)
        await env.call("PUT", ids["bob"], f"/api/streams/{went_private}", json={"is_public": False})
        # earlier game: switch away from Alpha, it must still be suggested to its owner
        await env.call("PUT", ids["owner"], f"/api/streams/{mine}", json={"game": "Beta Game"})
        st, b = await env.call("GET", ids["owner"], "/api/streams/games")
        assert st == 200, b
        games = b["games"]
        assert games[:2] == ["Beta Game", "Alpha Game"], games            # own first, newest first
        assert "Public Game" in games
        assert "Alice Private Game" not in games and "Was Public Game" not in games, games
        # nobody else's history: alice does not see Alpha/Beta (owner's stream is private)
        st, b = await env.call("GET", ids["alice"], "/api/streams/games")
        assert "Alpha Game" not in b["games"] and "Beta Game" not in b["games"], b
        assert "Alice Private Game" in b["games"] and "Public Game" in b["games"]
        # bob sees his own earlier game though his stream is private now, and not alice's private one
        st, b = await env.call("GET", ids["bob"], "/api/streams/games")
        assert "Was Public Game" in b["games"] and "Alice Private Game" not in b["games"], b
        # an admin gets no more than a member: another member's private game is not offered
        st, b = await env.call("GET", ids["boss"], "/api/streams/games")
        assert "Alice Private Game" not in b["games"] and "Alpha Game" not in b["games"], b
        assert hidden
        # no credential: refused
        async with env.http.get(env.url("/api/streams/games")) as r:
            assert r.status == 401
    run(body)


def test_the_games_list_is_bounded_and_deduplicated_without_regard_to_case():
    async def body(env):
        d = env.db
        ids = await users(d)
        for i in range(70):
            await d.create_user_stream(ids["alice"], f"p{i}", f"live_{i:024d}", public_key=f"pub_{i:024d}",
                                       is_public=True, game=f"Game {i:03d}")
        await d.create_user_stream(ids["alice"], "dupe", "live_" + "d" * 24, public_key="pub_" + "d" * 24,
                                   is_public=True, game="game 001")
        st, b = await env.call("GET", ids["viewer"], "/api/streams/games")
        assert st == 200 and len(b["games"]) == 50, len(b["games"])
        assert len({g.casefold() for g in b["games"]}) == 50
        # the caller's own come first, so a rehearsal with many public games still shows them
        await d.create_user_stream(ids["viewer"], "mine", "live_" + "m" * 24, public_key="pub_" + "m" * 24,
                                   is_public=False, game="ZZZ Mine")
        st, b = await env.call("GET", ids["viewer"], "/api/streams/games")
        assert b["games"][0] == "ZZZ Mine" and len(b["games"]) == 50
    run(body)


def test_the_game_suggestions_are_deduplicated_and_limited_in_sql():
    """200 public streams with one game in varied case (and a non-ASCII pair) read back one row
    per game and never more than the limit: the database does the work, not Python."""
    async def body(env):
        d = env.db
        ids = await users(d)
        for i in range(200):
            variant = "".join(c.upper() if (i >> n) & 1 else c for n, c in enumerate("same game"))
            await d.create_user_stream(ids["alice"], f"v{i}", f"live_{i:024d}", public_key=f"pub_{i:024d}",
                                       is_public=True, game=variant)
        for i in range(70):
            await d.create_user_stream(ids["alice"], f"u{i}", f"live_u{i:023d}", public_key=f"pub_u{i:023d}",
                                       is_public=True, game=f"Other {i:03d}")
        await d.create_user_stream(ids["viewer"], "de1", "live_" + "e" * 24, public_key="pub_" + "e" * 24,
                                   is_public=False, game="Strasse \u00c4rger")
        await d.create_user_stream(ids["viewer"], "de2", "live_" + "f" * 24, public_key="pub_" + "f" * 24,
                                   is_public=False, game="STRASSE \u00e4RGER")
        fetched = []
        real_conn = d._connection

        class Cur:
            def __init__(self, cur):
                self.cur = cur

            async def fetchall(self):
                rows = await self.cur.fetchall()
                fetched.append(len(rows))
                return rows

        class Spy:
            def __getattr__(self, name):
                return getattr(real_conn, name)

            async def execute(self, *a, **k):
                return Cur(await real_conn.execute(*a, **k))
        d._connection = Spy()
        try:
            games = await d.get_game_suggestions(ids["viewer"])
        finally:
            d._connection = real_conn
        assert fetched and max(fetched) <= d.GAME_SUGGESTIONS_MAX, fetched
        assert len(games) == d.GAME_SUGGESTIONS_MAX
        assert len({g.casefold() for g in games}) == len(games)
        assert sum(1 for g in games if g.casefold() == "same game") <= 1
        # the caller's own pair differs only by non-ASCII case: one entry, and it comes first
        assert sum(1 for g in games if g.casefold() == "strasse \u00e4rger") == 1
    run(body)


class FakeWs:
    """A room member's socket on the server side: records frames, optionally never finishes a send."""

    def __init__(self, hang=False):
        self.hang, self.frames, self.closed = hang, [], False

    async def send_json(self, frame):
        if self.hang:
            await asyncio.sleep(60)
        self.frames.append(frame)


async def fake_room(env, ids, hangers=0):
    cid, sid = await stream_chat(env.db, ids, public=True)
    await set_live(env.db, sid)
    name = (await env.db.get_chat_channel(cid))["name"]
    good = FakeWs()
    room = {(good, ids["viewer"], "viewer", "user")}
    for i in range(hangers):
        room.add((FakeWs(hang=True), ids["viewer"], "viewer", "user"))
    server.chat_rooms[name] = room
    return cid, sid, name, good


def test_stream_info_sends_run_together_and_a_hanging_socket_costs_only_its_own_wait():
    async def body(env):
        ids = await users(env.db)
        cid, sid, name, good = await fake_room(env, ids, hangers=4)
        stream = await env.db.get_user_stream(sid)
        t0 = asyncio.get_running_loop().time()
        sent = await server._broadcast_stream_info(stream)
        took = asyncio.get_running_loop().time() - t0
        assert sent == 1 and len(good.frames) == 1
        assert took < 3.0, f"sequential sends: {took:.1f}s"       # one 2 s wait, not four
    run(body)


def test_the_owners_put_does_not_wait_for_the_sockets_and_rapid_changes_merge():
    async def body(env):
        ids = await users(env.db)
        old_gap = server._STREAM_INFO_MIN_GAP
        server._STREAM_INFO_MIN_GAP = 0.5
        try:
            cid, sid, name, good = await fake_room(env, ids, hangers=3)
            t0 = asyncio.get_running_loop().time()
            for n in ("First", "Second", "Third", "Fourth"):
                st, _ = await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": n})
                assert st == 200
            assert asyncio.get_running_loop().time() - t0 < 1.5, "the PUTs waited for a hanging socket"
            await asyncio.sleep(3.2)        # the first send waits 2 s for the hanging sockets
            names = [f["name"] for f in good.frames]
            assert 1 <= len(names) <= 2, names                      # at most one per gap
            assert names[-1] == "Fourth", names                    # the last value wins
            # a later change after the gap is sent again
            await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "Fifth"})
            await asyncio.sleep(3.2)
            assert [f["name"] for f in good.frames][-1] == "Fifth"
        finally:
            server._STREAM_INFO_MIN_GAP = old_gap
            await server._cancel_stream_info_tasks()
    run(body)


def test_a_change_followed_by_making_the_stream_private_sends_nothing_to_members():
    async def body(env):
        ids = await users(env.db)
        old_gap = server._STREAM_INFO_MIN_GAP
        server._STREAM_INFO_MIN_GAP = 0.5
        try:
            cid, sid, name, good = await fake_room(env, ids)
            await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "Seen"})
            await asyncio.sleep(0.15)
            info = lambda: [f for f in good.frames if f.get("type") == "stream_info"]
            n_before = len(info())
            await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"name": "Hidden"})
            await env.call("PUT", ids["owner"], f"/api/streams/{sid}", json={"is_public": False})
            await asyncio.sleep(1.2)
            assert len(info()) == n_before, good.frames             # judged from the stream as it is at send time
            assert all(f["name"] != "Hidden" for f in info())
        finally:
            server._STREAM_INFO_MIN_GAP = old_gap
            await server._cancel_stream_info_tasks()
    run(body)


def test_the_create_stream_window_has_a_game_field_that_is_sent():
    import re
    import subprocess
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "static" / "js" / "streams.js").read_text(encoding="utf-8")
    modal = html[html.index('id="create-stream-modal"'):]
    modal = modal[:modal.index("</form>")]
    assert re.search(r'<input[^>]*id="stream-game"[^>]*maxlength="60"', modal)
    # its own suggestion list: the settings form's list id is rendered by the details view
    assert 'list="create-stream-game-list"' in modal and 'id="create-stream-game-list"' in modal
    create = js[js.index("async function createStream("):]
    create = create[:create.index("\n}\n")]
    assert "getElementById('stream-game')" in create
    assert re.search(r"postJSON\('/api/streams', \{[^}]*\bgame\b", create)
    show = js[js.index("function showCreateStreamModal("):]
    assert "loadGameSuggestions('create-stream-game-list')" in show[:show.index("\n}\n")]
    assert "async function loadGameSuggestions(listId" in js
    if subprocess.run(["which", "node"], capture_output=True).returncode == 0:
        r = subprocess.run(["node", "--check", str(ROOT / "static" / "js" / "streams.js")], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    async def body(env):
        ids = await users(env.db)
        # what the window sends when the field is left empty or filled, to the real create route
        st, b = await env.call("POST", ids["owner"], "/api/streams", json={"name": "c1", "description": "", "game": "", "is_public": False})
        assert st == 201 and b["stream"]["game"] is None, b
        st, b = await env.call("POST", ids["owner"], "/api/streams", json={"name": "c2", "description": "", "game": "Tetris", "is_public": False})
        assert st == 201 and b["stream"]["game"] == "Tetris", b
    run(body)


def test_the_games_route_starts_with_the_stream_user_auth():
    src = (ROOT / "server.py").read_text()
    start = src.index("async def http_stream_games(")
    chunk = src[start:src.index("\nasync def ", start + 10)]
    assert "_stream_user_auth(request)" in chunk
    # registered ahead of /api/streams/{id}, which would otherwise take "games"
    assert src.index('"/api/streams/games"') < src.index('"/api/streams/{id}", http_get_user_stream')


# ---------------------------------------------------------------------------
# go-live

def test_the_template_has_a_game_placeholder_and_old_calls_still_work():
    r = server._render_golive_message
    assert r("{streamer} plays {game}: {title} {url}", "Ann", "Night", "https://x/y", "Chess") == \
        "Ann plays Chess: Night https://x/y"
    assert r("{game}!", "Ann", "T", "u") == "!"                               # no game: empty
    assert r(None, "Ann", "T", "u", "Chess") == "T just went live"
    assert r("{game}", "a", "b", "c", "{url}") == "{url}"                      # not substituted again
    p = server._golive_payload({"id": 4, "name": "T", "game": "Chess", "owner_username": "ann"})
    assert p["game"] == "Chess"
    assert server._golive_payload({"id": 4, "name": "T", "owner_username": "ann"})["game"] == ""


@with_world
async def test_the_game_is_in_the_live_payload_the_card_the_notification_and_the_live_list(w):
    cid = await w.db.create_chat_channel("strm", created_by=w.ids["owner"])
    await w.db.conn.execute("UPDATE user_streams SET chat_channel_id = ?, game = ?, golive_message = ? WHERE id = ?",
                            (cid, "Chess", "{streamer} plays {game}", w.sid["pub"]))
    await w.db.conn.commit()
    assert await w.publish() == 200
    ev = w.live_events("sys")
    assert len(ev) == 1 and ev[0]["payload"]["game"] == "Chess", ev
    assert ev[0]["payload"]["message"] == "The Owner plays Chess"
    # the notification
    notes = await w.notes("m1")
    assert len(notes) == 1
    data = notes[0]["data"]
    data = json.loads(data) if isinstance(data, str) else data
    assert data["game"] == "Chess", data
    # the card, as stored and as history rebuilds it
    msgs = [m for m in await w.db.get_chat_messages(cid, limit=50) if m["message_type"] == "stream_card"]
    assert len(msgs) == 1
    rebuilt = await server._enrich_channel_messages(msgs, w.ids["m1"], "user", cid)
    assert rebuilt[0]["card"]["game"] == "Chess", rebuilt[0]["card"]
    raw = await (await w.db.conn.execute("SELECT game FROM stream_cards")).fetchone()
    assert raw["game"] and "Chess" not in raw["game"], "stored encrypted"
    # the live list
    class Req:
        pass
    live = await w.db.get_live_streams()
    assert [s["game"] for s in live if s["id"] == w.sid["pub"]] == ["Chess"]


@with_world
async def test_a_stream_without_a_game_announces_as_before(w):
    assert await w.publish() == 200
    ev = w.live_events("sys")
    assert ev[0]["payload"]["game"] == "" and ev[0]["payload"]["message"] == "Show pub just went live"
    data = (await w.notes("m1"))[0]["data"]
    data = json.loads(data) if isinstance(data, str) else data
    assert "game" not in data


# ---------------------------------------------------------------------------
# the pages

def test_the_pages_render_the_game_as_text_and_react_to_the_frame():
    watch = (ROOT / "static" / "watch.html").read_text()
    assert "stream_info" in watch and "viewer-game" in watch
    assert "gameEl.textContent = game" in watch and "viewer-game').innerHTML" not in watch
    chat = (ROOT / "static" / "chat.html").read_text()
    assert "card.game" in chat and "st.game" in chat
    assert "innerHTML = " not in chat[chat.index("function renderLiveNow"):chat.index("function updateStreamStatus")]
    js = (ROOT / "static" / "js" / "streams.js").read_text()
    assert "stream-game-list" in js and "/api/streams/games" in js
    assert js.count("escapeHtml(stream.game)") >= 2
    cards = (ROOT / "static" / "streams.html").read_text()
    assert "escapeHtml(stream.game)" in cards


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
