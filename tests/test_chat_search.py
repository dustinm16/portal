"""Message search: operators, in-context results, access and anonymity, the index
flags and the one-time backfill.

The parser and the flag rules are tested on their own. The rest runs the real
GET /api/chat/search and GET /api/chat/channels/{id}/messages handlers in-process
(only the authentication lookup is replaced) against a temporary database, and
calls the real backfill.

Run: venv/bin/python tests/test_chat_search.py
"""

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import chat_search  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402
from chat_search import SearchQueryError, parse_search_query  # noqa: E402

SERVER_SRC = (ROOT / "server.py").read_text(encoding="utf-8")

ANON_NAME = "anonreal_zq"
ANON_NICK = "NickZQ"
ANON_AVATAR = "AVATARZQ"
LAST_MONTH = "2026-10-12T09:30:00+00:00"


class Tok:
    def __init__(self, user_id):
        self.user_id = user_id
        self.token_id = "t%d" % user_id


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    return Tok(int(uid)) if uid else None


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {}

    async def __aenter__(self):
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        await self.db.connect()
        for name, value in (("db", self.db), ("authenticate_request", fake_auth)):
            self.saved[name] = getattr(server, name)
            setattr(server, name, value)
        server._search_rate_limits.clear()
        server._history_hits.clear()
        app = web.Application()
        app.router.add_get("/api/chat/search", server.http_search_messages)
        app.router.add_post("/api/chat/search/rebuild", server.http_rebuild_search_index)
        app.router.add_get("/api/chat/channels/{id}/messages", server.http_get_channel_messages)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        await self.http.close()
        await self.srv.close()
        for name, value in self.saved.items():
            setattr(server, name, value)
        await self.db.close()
        self.tmp.cleanup()

    async def search(self, user_id, **params):
        server._search_rate_limits.clear()
        async with self.http.get(str(self.srv.make_url("/api/chat/search")), params=params,
                                 headers={"X-Test-User": str(user_id)}) as r:
            return r.status, await r.json()

    async def history(self, user_id, channel_id, **params):
        async with self.http.get(str(self.srv.make_url(f"/api/chat/channels/{channel_id}/messages")),
                                 params=params, headers={"X-Test-User": str(user_id)}) as r:
            return r.status, await r.json()


def run(body):
    async def go():
        async with Env() as env:
            await body(env)
    asyncio.run(go())


def ids_of(body):
    return [r["id"] for r in body["results"]]


async def seed(d):
    """Users, a public and a private channel and messages of every kind."""
    u = {}
    for name in ("mom", "alice", "bob", "mod", "boss", ANON_NAME, "outsider", "member", "ghost"):
        u[name] = await d.create_user(name, "x")
    await d.set_user_role(u["mod"], "moderator")
    await d.set_user_role(u["boss"], "admin")
    await d.set_user_nickname(u["alice"], "Ally")
    await d.set_user_nickname(u[ANON_NAME], ANON_NICK)
    await d.set_avatar(u[ANON_NAME], {"color": "#112233", "emoji": ANON_AVATAR, "initials": "ZQ"})
    await d.set_chat_anonymous(u[ANON_NAME], True)
    gen = (await d.get_chat_channel_by_name("general"))["id"]      # created with the database
    rnd = (await d.get_chat_channel_by_name("random"))["id"]
    priv = await d.create_chat_channel("secret", created_by=u["alice"])
    await d.update_chat_channel(priv, visibility="private")
    await d.add_channel_member(priv, u["member"])
    await d.add_channel_member(priv, u["alice"])
    m = {}
    m["mom_photo"] = await d.create_chat_message(gen, u["mom"], "mom", "", image_url="/static/uploads/a.png")
    m["mom_text"] = await d.create_chat_message(gen, u["mom"], "mom", "dinner at six")
    m["mom_link"] = await d.create_chat_message(gen, u["mom"], "mom", "recipe https://example.com/pie please")
    m["alice_file"] = await d.create_chat_message(gen, u["alice"], "alice", "", attachment_url="/static/uploads/b.pdf",
                                                  attachment_name="b.pdf", attachment_size=10, attachment_type="application/pdf")
    m["alice_imgatt"] = await d.create_chat_message(gen, u["alice"], "alice", "cat", attachment_url="/static/uploads/c.png",
                                                    attachment_name="c.png", attachment_size=10, attachment_type="image/png")
    m["bob_text"] = await d.create_chat_message(gen, u["bob"], "bob", "dinner was good")
    m["anon_text"] = await d.create_chat_message(gen, u[ANON_NAME], ANON_NAME, "dinner secret words https://anon.example/x",
                                                 anonymous=True)
    m["anon_file"] = await d.create_chat_message(gen, u[ANON_NAME], ANON_NAME, "", anonymous=True,
                                                 attachment_url="/static/uploads/d.zip", attachment_name="d.zip",
                                                 attachment_size=1, attachment_type="application/zip")
    m["alice_anon"] = await d.create_chat_message(gen, u["alice"], "alice", "dinner alice anonymously", anonymous=True)
    m["rnd"] = await d.create_chat_message(rnd, u["bob"], "bob", "dinner in random")
    m["priv"] = await d.create_chat_message(priv, u["alice"], "alice", "dinner in the secret room https://p.example")
    await d.pin_message(m["bob_text"], u["boss"])
    await d.pin_message(m["anon_text"], u["boss"])
    # a month ago: the post and its index row
    for key in ("mom_photo",):
        await d.conn.execute("UPDATE chat_messages SET created_at = ? WHERE id = ?", (LAST_MONTH, m[key]))
        await d.conn.execute("UPDATE chat_fts_map SET created_at = ? WHERE message_id = ?", (LAST_MONTH, m[key]))
    await d.conn.commit()
    return u, {"gen": gen, "rnd": rnd, "priv": priv}, m


# ---------------------------------------------------------------------------
# parser and flags

def test_word_search_in_all_scope_pages_without_repeats_or_gaps():
    """Page 2 of a word search in the merged scope continues where page 1 ended. Short old posts rank best
    and long newer ones rank worse; both sources (channels and DMs) are read to offset + limit rows in the
    same order as the merge, so every match is reached exactly once, newest first."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        pad = "filler words here " * 20
        for i in range(6):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"pearword {i}")
        conv = await d.create_dm_conversation(u["mom"], [u["alice"]])
        for i in range(3):
            await d.create_dm_message(conv["id"], u["mom"], "mom", f"pearword dm {i}")
        for i in range(6):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"pearword {pad}{i}")
        for i in range(3):
            await d.create_dm_message(conv["id"], u["mom"], "mom", f"pearword {pad}dm {i}")
        expected = None
        for scope in ("all", "channels", "dms"):
            seen, offset = [], 0
            while True:
                st, b = await env.search(u["alice"], q="pearword", scope=scope, limit=4, offset=offset)
                assert st == 200
                seen += [(r["source"], r["id"]) for r in b["results"]]
                offset += len(b["results"])
                if not b["has_more"]:
                    break
                assert offset < 100, "has_more never turned false"
            want = {"all": 18, "channels": 12, "dms": 6}[scope]
            assert len(seen) == want and len(set(seen)) == want, (scope, len(seen), len(set(seen)))
            if scope == "all":
                expected = seen
        st, whole = await env.search(u["alice"], q="pearword", scope="all", limit=50)
        assert [(r["source"], r["id"]) for r in whole["results"]] == expected, "pages must add up to the one big page"
        stamps = [(r["created_at"] or "").replace(" ", "T") for r in whole["results"]]
        assert stamps == sorted(stamps, reverse=True)
    run(body)


def test_parser_operators_and_words():
    p = parse_search_query('from:mom has:image dinner "two words" -from:bob in:#General -in:random is:pinned '
                           'before:2026-11-01 after:2026-10-01')
    assert p.from_users == ["mom"] and p.not_from_users == ["bob"]
    assert p.in_channels == ["general"] and p.not_in_channels == ["random"]
    assert p.has == ["image"] and p.pinned and p.before == "2026-11-01" and p.after == "2026-10-01"
    assert p.phrases == [["dinner"], ["two", "words"]] and p.words == ["dinner", "two", "words"]
    assert p.fts_expr == '"dinner" "two words"' and not p.operator_only
    q = parse_search_query("HAS:Link FROM:Mom")
    assert q.has == ["link"] and q.from_users == ["Mom"] and q.operator_only and q.has_operators


def test_parser_refusals():
    bad = ["has:video", "has:", "is:open", "color:red", "-has:link", "-before:2026-01-01", "before:yesterday",
           "before:2026-13-40", "after:2026-1-1", "before:2026-01-01 before:2026-02-01", "from:", "in:#",
           "x:" + "y" * 70] + [" ".join("from:a%d" % i for i in range(11))]
    for q in bad:
        try:
            parse_search_query(q)
        except SearchQueryError as e:
            assert str(e), q
        else:
            raise AssertionError("not refused: " + q)
    for q in ("has:video", "color:red"):
        try:
            parse_search_query(q)
        except SearchQueryError as e:
            assert "has: value" in str(e) or "Unknown search operator" in str(e)


def test_parser_keeps_times_and_addresses_as_text():
    for q, words in (("meet at 12:30", ["meet", "at", "12", "30"]),
                     ("see https://example.com/a?b=1", ["see", "https", "//example.com/a?b=1"]),
                     ("Note: milk", ["Note", "milk"]), ('"color:red"', ["color", "red"])):
        p = parse_search_query(q)
        assert not p.has_operators, q
        assert p.words == [w for w in words if w], (q, p.words)
    assert parse_search_query('"from:mom"').from_users == []
    assert parse_search_query("--").phrases == [] and not parse_search_query("--").has_operators
    # FTS characters never reach the expression
    assert '*' not in parse_search_query('a* (b) ^c d:').fts_expr


def test_legacy_parameters_use_the_same_checks():
    p = parse_search_query("dinner", from_="mom", has="IMAGE", before="2026-11-01")
    assert p.from_users == ["mom"] and p.has == ["image"] and p.before == "2026-11-01"
    for kw in ({"has": "bogus"}, {"before": "nope"}):
        try:
            parse_search_query("dinner", **kw)
        except SearchQueryError:
            continue
        raise AssertionError(kw)


def test_message_flags():
    f = chat_search.message_flags
    assert f("hi", None, None, None) == (0, 0, 0)
    assert f("see https://x.y/z", None, None, None) == (0, 0, 1)
    assert f("", "/u/a.png", None, None) == (1, 0, 0)
    assert f("", None, "/u/a.pdf", "application/pdf") == (0, 1, 0)
    assert f("", None, "/u/a.png", "image/png") == (1, 0, 0), "an image attachment is an image, not a file"
    assert f("www.example.com", None, None, None) == (0, 0, 0), "only http(s) addresses are links, as in the chat page"


# ---------------------------------------------------------------------------
# index

def test_migration_adds_flag_columns_and_runs_again():
    async def body(env):
        await env.db.close()
        await env.db.connect()
        for table in ("chat_fts_map", "dm_fts_map"):
            cur = await env.db.conn.execute(f"PRAGMA table_info({table})")
            cols = {r["name"] for r in await cur.fetchall()}
            assert {"has_link", "has_file", "has_image"} <= cols, table
    run(body)


def test_new_messages_are_indexed_with_flags_including_attachment_only():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        cur = await d.conn.execute("SELECT message_id, has_image, has_file, has_link FROM chat_fts_map")
        rows = {r["message_id"]: (r["has_image"], r["has_file"], r["has_link"]) for r in await cur.fetchall()}
        assert rows[m["mom_photo"]] == (1, 0, 0), "image-only post is indexed"
        assert rows[m["alice_file"]] == (0, 1, 0), "file-only post is indexed"
        assert rows[m["alice_imgatt"]] == (1, 0, 0)
        assert rows[m["mom_link"]] == (0, 0, 1)
        assert rows[m["mom_text"]] == (0, 0, 0)
        # an edit keeps the attachment flags (it used to lose them) and recomputes the link flag
        await d.update_search_index(m["alice_imgatt"], "cat https://c.example", "channel")
        cur = await d.conn.execute("SELECT has_image, has_file, has_link FROM chat_fts_map WHERE message_id = ?",
                                   (m["alice_imgatt"],))
        assert tuple((await cur.fetchone())) == (1, 0, 1)
        await d.update_search_index(m["alice_file"], "", "channel")
        cur = await d.conn.execute("SELECT has_file FROM chat_fts_map WHERE message_id = ?", (m["alice_file"],))
        assert (await cur.fetchone())["has_file"] == 1, "a file post edited to no text stays indexed"
        # empty FTS rows never match a word
        res = await d.search_messages("zzzz", u["boss"], user_role="superadmin")
        assert res["total"] == 0
    run(body)


def test_rebuild_fills_flags_and_marks_backfill_done():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        counts = await d.rebuild_search_index()
        assert counts["channel"] == 11
        cur = await d.conn.execute("SELECT has_file, has_link FROM chat_fts_map WHERE message_id = ?", (m["mom_link"],))
        r = await cur.fetchone()
        assert (r["has_file"], r["has_link"]) == (0, 1)
        assert await d.search_backfill_complete()
    run(body)


def test_backfill_fills_old_rows_resumes_and_is_guarded():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        # the plaintext of the "" posts is encrypted "", so mark them as legacy gaps by id
        for key in ("mom_photo", "alice_file", "anon_file"):
            await d.conn.execute("DELETE FROM chat_fts_map WHERE message_id = ?", (m[key],))
        await d.conn.execute("UPDATE chat_fts_map SET has_link = 0, has_file = 0, has_image = 0")
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        status, body_ = await env.search(u["boss"], q="has:link")
        assert status == 200 and body_["results"] == [] and body_["index_complete"] is False

        # stop after the first batch: a crash in the middle
        sleeps = []
        real_sleep = asyncio.sleep

        async def stopper(delay, *a, **k):
            sleeps.append(delay)
            if len(sleeps) == 2:
                raise RuntimeError("stop")
            await real_sleep(0)
        import database
        database.asyncio.sleep, saved = stopper, database.asyncio.sleep
        try:
            try:
                await d.backfill_search_flags(batch_size=3, pause=0.5)
            except RuntimeError:
                pass
        finally:
            database.asyncio.sleep = saved
        assert sleeps and sleeps[0] == 0.5, "yields between batches"
        position = int(await d.get_setting("search_backfill_channel_last_id"))
        assert 0 < position < max(m.values()), position
        assert not await d.search_backfill_complete()

        # the second run resumes after the stored position and finishes
        stats = await d.backfill_search_flags(batch_size=3, pause=0)
        assert 0 < stats["channel"] < len(m), stats      # only the rows after the stored position
        assert await d.search_backfill_complete()
        status, body_ = await env.search(u["boss"], q="has:link")
        assert set(ids_of(body_)) == {m["mom_link"], m["anon_text"], m["priv"]}, body_
        assert body_["index_complete"] is True
        status, body_ = await env.search(u["boss"], q="has:file")
        assert set(ids_of(body_)) == {m["alice_file"], m["anon_file"]}
        status, body_ = await env.search(u["boss"], q="has:image")
        assert set(ids_of(body_)) == {m["mom_photo"], m["alice_imgatt"]}
        # a text message that has no index row is not indexed by the backfill (only rebuild does that)
        await d.conn.execute("DELETE FROM chat_fts_map WHERE message_id IN (?, ?)", (m["mom_text"], m["alice_file"]))
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        await d.backfill_search_flags(pause=0)
        cur = await d.conn.execute("SELECT message_id FROM chat_fts_map WHERE message_id IN (?, ?)", (m["mom_text"], m["alice_file"]))
        assert [r["message_id"] for r in await cur.fetchall()] == [m["alice_file"]], "text gap stays, attachment-only is back"
        # guarded by the flag: a done backfill does no work
        rows = (await (await d.conn.execute("SELECT COUNT(*) FROM chat_fts_map")).fetchone())[0]
        assert await d.backfill_search_flags() == {"skipped": "done"}
        assert (await (await d.conn.execute("SELECT COUNT(*) FROM chat_fts_map")).fetchone())[0] == rows
        # running it twice from the start gives the same index (no duplicates)
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        await d.backfill_search_flags(pause=0)
        assert (await (await d.conn.execute("SELECT COUNT(*) FROM chat_fts_map")).fetchone())[0] == rows
    run(body)


def test_backfill_is_started_after_startup_and_not_in_stage_mode():
    start = SERVER_SRC[SERVER_SRC.index("    async def start(self)"):]
    i = start.index("_search_backfill_runner()")
    assert "if not Config.STAGE_MODE:" in start[max(0, i - 200):i]
    runner = SERVER_SRC[SERVER_SRC.index("async def _search_backfill_runner"):SERVER_SRC.index("    async def start(self)")]
    assert "asyncio.sleep(" in runner and "backfill_search_flags()" in runner
    handler = SERVER_SRC[SERVER_SRC.index("async def http_search_messages"):SERVER_SRC.index("async def http_rebuild_search_index")]
    assert "backfill_search_flags" not in handler, "never on a request path"


# ---------------------------------------------------------------------------
# the route

def test_done_when_lines():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        # from:mom has:image returns the image-only post from last month ...
        st, b = await env.search(u["member"], q="from:mom has:image")
        assert st == 200 and ids_of(b) == [m["mom_photo"]], b
        hit = b["results"][0]
        assert hit["source"] == "channel" and hit["source_id"] == ch["gen"] and hit["created_at"] == LAST_MONTH
        assert hit["has_image"] == 1 and hit["image_url"] == "/static/uploads/a.png"
        # ... and the history route (what the click calls) opens it in context
        st, page = await env.history(u["member"], hit["source_id"], around_id=hit["id"])
        assert st == 200 and page["found"] and hit["id"] in [x["id"] for x in page["messages"]]
        # in:general before:... returns only accessible channels
        st, b = await env.search(u["outsider"], q="in:general before:2026-12-01")
        assert st == 200 and set(ids_of(b)) >= {m["mom_photo"], m["mom_text"]}
        assert all(r["source_id"] == ch["gen"] for r in b["results"])
        st, b = await env.search(u["outsider"], q="in:secret")
        assert st == 200 and b["results"] == [] and b["total"] == 0
        st2, b2 = await env.search(u["outsider"], q="in:nosuchroom")
        assert st == st2 and {**b, "query": 0, "terms": 0} == {**b2, "query": 0, "terms": 0}, \
            "a private channel looks like one that does not exist"
        st, b = await env.search(u["member"], q="in:secret")
        assert ids_of(b) == [m["priv"]], "a member reads it"
        st, b = await env.search(u["boss"], q="in:secret")
        assert ids_of(b) == [m["priv"]], "an admin reads every channel"
        st, b = await env.search(u["mod"], q="in:secret")
        assert b["results"] == [], "a moderator does not read private channels they are not in"
        st, b = await env.search(u["outsider"], q="before:2026-11-01")
        assert ids_of(b) == [m["mom_photo"]] and b["operator_only"] is True
        st, b = await env.search(u["outsider"], q="after:2026-11-01 has:image")
        assert ids_of(b) == [m["alice_imgatt"]]
        # an unknown has: value is a 400 with a message
        for q in ("has:video", "color:red", "before:soon"):
            st, b = await env.search(u["member"], q=q)
            assert st == 400 and b["error"], q
        st, b = await env.search(u["member"], q="dinner", has="bogus")
        assert st == 400
    run(body)


def test_operators_filter_and_sort():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        st, b = await env.search(u["member"], q="has:link in:general")
        assert set(ids_of(b)) == {m["anon_text"], m["mom_link"]}
        assert ids_of(b) == sorted(ids_of(b), reverse=True), "operator-only results are newest first"
        st, b = await env.search(u["member"], q="is:pinned")
        assert set(ids_of(b)) == {m["bob_text"], m["anon_text"]}
        st, b = await env.search(u["member"], q="dinner -in:random -in:general")
        assert ids_of(b) == [m["priv"]]
        st, b = await env.search(u["member"], q="dinner in:random")
        assert ids_of(b) == [m["rnd"]] and b["operator_only"] is False and b["terms"] == ["dinner"]
        st, b = await env.search(u["member"], q='from:Ally "alice anonymously"')
        assert b["results"] == [], "nickname matches only her own non-anonymous posts"
        st, b = await env.search(u["member"], q="from:ally has:image")
        assert ids_of(b) == [m["alice_imgatt"]], "from: takes a nickname, any case"
        st, b = await env.search(u["member"], q="dinner -from:mom")
        assert m["mom_text"] not in ids_of(b) and m["bob_text"] in ids_of(b)
        # a URL and a time are plain text
        st, b = await env.search(u["member"], q="https://example.com/pie")
        assert st == 200
        st, b = await env.search(u["member"], q="recipe", **{"from": "mom"})
        assert ids_of(b) == [m["mom_link"]], "the older from= parameter still works"
        # scope and DMs: in: and is:pinned skip DMs, has: reaches them
        conv = await d.create_dm_conversation(u["mom"], [u["alice"]])
        dm_file = await d.create_dm_message(conv["id"], u["mom"], "mom", "", attachment_url="/static/uploads/e.pdf",
                                            attachment_name="e.pdf", attachment_size=3, attachment_type="application/pdf")
        st, b = await env.search(u["alice"], q="has:file")
        assert ("dm", dm_file) in [(r["source"], r["id"]) for r in b["results"]]
        dm = [r for r in b["results"] if r["source"] == "dm"][0]
        assert dm["has_file"] == 1 and dm["attachment_name"] == "e.pdf"
        st, b = await env.search(u["bob"], q="has:file")
        assert dm_file not in ids_of(b), "someone outside the conversation never sees it"
        st, b = await env.search(u["alice"], q="has:file in:general")
        assert all(r["source"] == "channel" for r in b["results"])
        st, b = await env.search(u["alice"], q="has:file is:pinned")
        assert b["results"] == []
        st, b = await env.search(u["alice"], q="has:file", scope="dms")
        assert ids_of(b) == [dm_file]
    run(body)


def test_operator_only_cap_and_has_more():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for i in range(230):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"see https://e.example/{i}")
        st, b = await env.search(u["member"], q="has:link in:random", limit=50, offset=0)
        assert len(b["results"]) == 50 and b["total"] == 200 and b["capped"] is True and b["has_more"] is True
        st, b = await env.search(u["member"], q="has:link in:random", limit=50, offset=150)
        assert len(b["results"]) == 50 and b["has_more"] is False and b["capped"] is True, "the last page of 200 has no next page"
        st, b = await env.search(u["member"], q="has:link in:random", limit=50, offset=200)
        assert b["results"] == [] and b["total"] == 200
        st, b = await env.search(u["member"], q="has:link in:random from:bob is:pinned", limit=50)
        assert b["results"] == [] and b["capped"] is False and b["has_more"] is False
        st, b = await env.search(u["member"], q="has:link in:general", limit=50)
        assert b["capped"] is False and b["has_more"] is False and b["total"] == 2
        # a word query keeps its exact count
        st, b = await env.search(u["member"], q="dinner", limit=2)
        assert len(b["results"]) == 2 and b["total"] == 6 and b["has_more"] is True and b["capped"] is False
    run(body)


def test_capped_query_pages_to_the_end_and_stops():
    """has_more is false from the last listed result on (offset plus limit never goes past 200), also when
    the channel and DM sources together count more than the cap; paging with the default size reaches all 200."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for i in range(230):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"see https://e.example/{i}")
        conv = await d.create_dm_conversation(u["mom"], [u["alice"]])
        for i in range(210):
            await d.create_dm_message(conv["id"], u["mom"], "mom", f"dm https://d.example/{i}")
        for scope, q in (("channels", "has:link in:random"), ("all", "has:link")):
            seen, offset, pages = [], 0, 0
            while True:
                st, b = await env.search(u["alice"], q=q, scope=scope, limit=25, offset=offset)
                pages += 1
                assert st == 200 and b["capped"] is True and b["total"] == 200
                seen += ids_of(b)
                offset += len(b["results"])
                if not b["has_more"]:
                    break
                assert pages < 20, "has_more never turned false"
            assert len(seen) == 200 and len(set(seen)) == 200 and pages == 8, (scope, len(seen), pages)
            st, b = await env.search(u["alice"], q=q, scope=scope, limit=25, offset=175)
            assert len(b["results"]) == 25 and b["has_more"] is False, (scope, b["has_more"])
            st, b = await env.search(u["alice"], q=q, scope=scope, limit=25, offset=150)
            assert b["has_more"] is True
            for off in (200, 1000):
                st, b = await env.search(u["alice"], q=q, scope=scope, limit=25, offset=off)
                assert b["results"] == [] and b["has_more"] is False and b["total"] == 200 and b["capped"] is True, (scope, off)
    run(body)


def test_capped_query_never_fetches_past_the_cap():
    """An offset past the cap lists nothing, so no source is asked for rows (only for its count)."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for i in range(230):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"see https://e.example/{i}")
        calls = []
        real = d._search_index

        async def spy(source, parsed, **kw):
            calls.append((source, kw["limit"], kw["offset"]))
            return await real(source, parsed, **kw)
        d._search_index = spy
        try:
            for scope in ("all", "channels", "dms"):
                calls.clear()
                st, b = await env.search(u["member"], q="has:link", scope=scope, limit=25, offset=server.SEARCH_OFFSET_MAX)
                assert b["results"] == [] and b["has_more"] is False, scope
                assert calls and all(lim <= 0 for _s, lim, _o in calls), (scope, calls)
            calls.clear()
            st, b = await env.search(u["member"], q="has:link", scope="all", limit=25, offset=190)
            assert len(b["results"]) == 10 and all(lim <= 200 for _s, lim, _o in calls), calls
        finally:
            d._search_index = real
    run(body)


def test_offset_past_the_limit_is_refused_not_swallowed():
    """An offset beyond SEARCH_OFFSET_MAX (2000; including one past the SQLite integer range) answers 400 and never
    reaches the database; before, the driver failed inside _search_index and the route answered an empty 200."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        calls = []
        real = d._search_index

        async def spy(source, parsed, **kw):
            calls.append(source)
            return await real(source, parsed, **kw)
        d._search_index = spy
        try:
            for q in ("dinner", "has:link"):
                for off in (2001, 1_000_001, 2**63, 10**19, 10**40):
                    calls.clear()
                    st, b = await env.search(u["member"], q=q, offset=off)
                    assert st == 400 and "offset" in b["error"] and "results" not in b, (q, off, st, b)
                    assert not calls, (q, off, calls)
            st, b = await env.search(u["member"], q="has:link", offset=2000)
            assert st == 200 and b["results"] == [], (st, b)
            st, b = await env.search(u["member"], q="has:link", offset=-5)
            assert st == 200, (st, b)
        finally:
            d._search_index = real
    run(body)


def test_has_more_is_false_when_the_next_page_would_be_refused():
    """A client that follows has_more must never be sent past SEARCH_OFFSET_MAX: a page that ends beyond the cap
    says has_more false, although more matches exist, and the last page the cap allows is still served."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for i in range(12):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"capword number{i}")
        real_max = server.SEARCH_OFFSET_MAX
        server.SEARCH_OFFSET_MAX = 4
        try:
            for scope in ("all", "channels"):
                seen, offset, last = [], 0, None
                for _ in range(10):
                    st, last = await env.search(u["member"], q="capword", scope=scope, limit=4, offset=offset)
                    assert st == 200, (scope, offset, st, last)
                    seen += ids_of(last)
                    offset += len(last["results"])
                    if not last["has_more"]:
                        break
                # offsets 0 and 4 are served; the page at 4 ends at 8, past the cap of 4, so it is the last
                assert offset == 8 and len(seen) == 8 and len(set(seen)) == 8, (scope, offset, seen)
                assert last["has_more"] is False and last["total"] == 12, (scope, last)
                # a page that ends exactly at the cap still points at the page the cap allows
                st, b = await env.search(u["member"], q="capword", scope=scope, limit=2, offset=2)
                assert st == 200 and b["has_more"] is True, (scope, b)
                st, b = await env.search(u["member"], q="capword", scope=scope, limit=4, offset=8)
                assert st == 400 and "offset" in b["error"], (scope, st, b)
                # a page with nothing past it keeps its own answer
                st, b = await env.search(u["member"], q="capword", scope=scope, limit=4, offset=0)
                assert st == 200 and b["has_more"] is True, (scope, b)
        finally:
            server.SEARCH_OFFSET_MAX = real_max
    run(body)


def test_anonymous_authors_are_never_revealed_by_any_operator():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        anon_ids = {m["anon_text"], m["anon_file"], m["alice_anon"]}
        secrets = [ANON_NAME, ANON_NICK, ANON_AVATAR]
        viewer = u["member"]

        async def get(q, who=viewer, **kw):
            st, b = await env.search(who, q=q, **kw)
            assert st == 200, (q, b)
            return b

        # a positive author filter never matches an anonymous post, for the real author either
        for who in (ANON_NAME, ANON_NICK, "alice", "Ally"):
            b = await get(f"from:{who} in:general")
            assert not (set(ids_of(b)) & anon_ids), who
            assert b["total"] == len(b["results"])
        b = await get(f"from:{ANON_NAME}")
        assert b["results"] == [] and b["total"] == 0
        # counts: an author with only anonymous posts looks like an account that never posted
        ghost = await get("from:nobodyatall has:file in:general")
        mine = await get(f"from:{ANON_NAME} has:file in:general")
        strip = lambda b: {k: v for k, v in b.items() if k not in ("query", "terms")}
        assert strip(ghost) == strip(mine) and mine["total"] == 0
        # the author's own other posts stay findable, anonymous ones do not
        b = await get("from:alice dinner in:general")
        assert ids_of(b) == []
        b = await get("from:alice in:general has:file")
        assert ids_of(b) == [m["alice_file"]]
        # negation never removes an anonymous post for a member, whoever is named
        a = await get(f"-from:{ANON_NAME} in:general")
        g = await get("-from:nobodyatall in:general")
        assert ids_of(a) == ids_of(g) and a["total"] == g["total"], "indistinguishable from a name nobody has"
        assert anon_ids <= set(ids_of(a))
        a2 = await get("-from:alice in:general")
        assert m["alice_anon"] in ids_of(a2) and m["alice_file"] not in ids_of(a2)
        # nothing in any response names the author
        for q in (f"from:{ANON_NAME}", "-from:alice in:general", "dinner", "has:file", "is:pinned", "has:link"):
            got = await get(q)
            blob = json.dumps({k: v for k, v in got.items() if k not in ("query", "terms")})   # the echo of what was typed
            for s in secrets:
                assert s not in blob, (q, s)
            for r in (await get(q))["results"]:
                if r["id"] in anon_ids:
                    assert r["username"] == "Anonymous" and r["display_name"] == "Anonymous"
                    assert r["user_id"] is None and r["role"] is None and r["nickname"] is None
                    assert r["avatar"] == {} and r["anonymous"] is True
        # staff may match: moderators and admins already receive the author id
        for who in (u["mod"], u["boss"]):
            b = await get(f"from:{ANON_NAME}", who=who)
            assert set(ids_of(b)) == {m["anon_text"], m["anon_file"]}
            for r in b["results"]:
                assert r["user_id"] == u[ANON_NAME] and r["username"] == "Anonymous"
            b = await get("-from:alice in:general", who=who)
            assert m["alice_anon"] not in ids_of(b), "staff see who wrote it"
        # the author gets own id back but no match through from:
        b = await get("dinner secret", who=u[ANON_NAME])
        own = [r for r in b["results"] if r["id"] == m["anon_text"]][0]
        assert own["user_id"] == u[ANON_NAME]
        b = await get(f"from:{ANON_NAME}", who=u[ANON_NAME])
        assert b["results"] == []
    run(body)


def test_results_match_what_history_sends_for_the_same_viewer():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for viewer in (u["member"], u["mod"], u["boss"], u[ANON_NAME]):
            st, hist = await env.history(viewer, ch["gen"], limit=100)
            by_id = {x["id"]: x for x in hist["messages"]}
            st, found = await env.search(viewer, q="in:general before:2100-01-01", limit=50)
            assert len(found["results"]) == len(by_id)
            for r in found["results"]:
                h = by_id[r["id"]]
                for key in ("user_id", "role", "nickname", "avatar", "anonymous", "message"):
                    assert r[key] == h[key], (viewer, r["id"], key, r[key], h[key])
                assert r["display_name"] == h["username"]
    run(body)


def test_stream_ban_and_removed_member_are_not_searched():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        room = await d.create_chat_channel("streamroom", created_by=u["alice"])
        sm = await d.create_chat_message(room, u["alice"], "alice", "dinner on stream")
        sid = await d.create_user_stream(u["alice"], "s", "live_" + "h" * 24, public_key="pub_" + "i" * 24,
                                         is_public=True)     # a stream chat that is not public is closed to other members
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (room, sid))
        await d.conn.commit()
        st, b = await env.search(u["bob"], q="in:streamroom")
        assert ids_of(b) == [sm]
        await d.create_stream_ban(sid, u["bob"], u["alice"], "x")
        st, b = await env.search(u["bob"], q="in:streamroom")
        assert b["results"] == [] and b["total"] == 0
        st, b = await env.search(u["bob"], q="dinner")
        assert sm not in ids_of(b)
        st, b = await env.search(u["boss"], q="in:streamroom")
        assert ids_of(b) == [sm], "an admin who is not banned reads it"
        await d.create_stream_ban(sid, u["boss"], u["alice"], "x")
        st, b = await env.search(u["boss"], q="in:streamroom")
        assert ids_of(b) == [sm], "a stream ban never applies to an administrator (1.24.1), here as for history"
        await d.remove_channel_member(ch["priv"], u["member"])
        st, b = await env.search(u["member"], q="in:secret")
        assert b["results"] == []
    run(body)


def test_rate_limit_stays_ten_a_minute():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        server._search_rate_limits.clear()
        hdr = {"X-Test-User": str(u["member"])}
        codes = []
        for _ in range(11):
            async with env.http.get(str(env.srv.make_url("/api/chat/search")), params={"q": "has:link"}, headers=hdr) as r:
                codes.append(r.status)
        assert codes == [200] * 10 + [429], codes
        server._search_rate_limits.clear()
        # a refused query does not use the budget
        for _ in range(12):
            async with env.http.get(str(env.srv.make_url("/api/chat/search")), params={"q": "has:nope"}, headers=hdr) as r:
                assert r.status == 400
        async with env.http.get(str(env.srv.make_url("/api/chat/search")), params={"q": "has:link"}, headers=hdr) as r:
            assert r.status == 200
    run(body)


def test_unauthenticated_and_short_queries():
    async def body(env):
        async with env.http.get(str(env.srv.make_url("/api/chat/search")), params={"q": "has:link"}) as r:
            assert r.status in (401, 403, 302)
        st, b = await env.search(1, q="x")
        assert st == 400
        st, b = await env.search(1, q="a" * 201)
        assert st == 400
    run(body)


def test_ids_are_range_checked_like_history():
    """channel_id and conversation_id must be 1..HISTORY_ID_MAX; anything else answers 400 and never reaches
    the database (0 used to mean "no filter", and a huge value failed inside the driver)."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        calls = []
        real = d._search_index

        async def spy(source, parsed, **kw):
            calls.append(source)
            return await real(source, parsed, **kw)
        d._search_index = spy
        try:
            for name in ("channel_id", "conversation_id"):
                for bad in ("0", "-1", str(server.HISTORY_ID_MAX + 1), str(10 ** 40), "abc", ""):
                    calls.clear()
                    st, b = await env.search(u["member"], q="dinner", **{name: bad})
                    assert st == 400 and "results" not in b, (name, bad, st, b)
                    assert not calls, (name, bad, calls)
                scope = "dms" if name == "conversation_id" else "channels"
                st, b = await env.search(u["member"], q="dinner", scope=scope, **{name: str(server.HISTORY_ID_MAX)})
                assert st == 200 and b["results"] == [], (name, st, b)
            st, b = await env.search(u["alice"], q="dinner", channel_id=str(ch["gen"]))
            assert st == 200 and b["results"], (st, b)
            # a refused request does not count against the 10 a minute
            server._search_rate_limits.clear()
            hdr = {"X-Test-User": str(u["member"])}
            url = str(env.srv.make_url("/api/chat/search"))
            for _ in range(12):
                async with env.http.get(url, params={"q": "dinner", "channel_id": "0"}, headers=hdr) as r:
                    assert r.status == 400
                async with env.http.get(url, params={"q": "dinner", "offset": "2001"}, headers=hdr) as r:
                    assert r.status == 400
            async with env.http.get(url, params={"q": "dinner"}, headers=hdr) as r:
                assert r.status == 200, r.status
        finally:
            d._search_index = real
    run(body)


def test_dms_scope_does_no_per_channel_work():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        conv = await d.create_dm_conversation(u["mom"], [u["alice"]])
        await d.create_dm_message(conv["id"], u["mom"], "mom", "pearword in a dm")
        seen = []
        real_read, real_acc = server._can_read_channel, d.get_accessible_channels

        async def spy_read(*a, **k):
            seen.append("read")
            return await real_read(*a, **k)

        async def spy_acc(*a, **k):
            seen.append("accessible")
            return await real_acc(*a, **k)
        server._can_read_channel, d.get_accessible_channels = spy_read, spy_acc
        try:
            st, b = await env.search(u["alice"], q="pearword", scope="dms")
            assert st == 200 and len(b["results"]) == 1 and b["results"][0]["source"] == "dm", (st, b)
            assert seen == [], seen
            st, b = await env.search(u["alice"], q="dinner", scope="all")
            assert st == 200 and b["results"] and "read" in seen and "accessible" in seen, seen
        finally:
            server._can_read_channel, d.get_accessible_channels = real_read, real_acc
    run(body)


def test_finish_lists_a_message_once():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        conv = await d.create_dm_conversation(u["mom"], [u["alice"]])
        await d.create_dm_message(conv["id"], u["mom"], "mom", "dinner in a dm")
        found = await d.search_messages("dinner", u["alice"], user_role="user", scope="all",
                                        channel_ids={ch["gen"]})
        once = await server._finish_search_results(list(found["results"]), u["alice"], "user")
        assert len(once) >= 3 and len({(r["source"], r["id"]) for r in once}) == len(once)
        twice = await server._finish_search_results(list(found["results"]) + list(found["results"]), u["alice"], "user")
        assert [(r["source"], r["id"]) for r in twice] == [(r["source"], r["id"]) for r in once], "a repeated hit is listed once"
    run(body)


def test_rebuild_takes_the_backfill_lock():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        # a rebuild waits while the backfill (or anything else) holds the lock
        async with d._search_backfill_lock:
            task = asyncio.create_task(d.rebuild_search_index())
            for _ in range(20):
                await asyncio.sleep(0.01)
            assert not task.done(), "rebuild must not run while the backfill lock is held"
        counts = await asyncio.wait_for(task, 20)
        assert counts["channel"] == 11 and await d.search_backfill_complete()
        # a backfill that starts during a rebuild does nothing; the rebuild finishes the index itself
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        started = asyncio.Event()
        release = asyncio.Event()
        real = d._rebuild_search_index_locked

        async def slow():
            started.set()
            await release.wait()
            return await real()
        d._rebuild_search_index_locked = slow
        try:
            task = asyncio.create_task(d.rebuild_search_index())
            await started.wait()
            assert await d.backfill_search_flags(pause=0) == {"skipped": "running"}
            release.set()
            await task
        finally:
            d._rebuild_search_index_locked = real
        assert await d.search_backfill_complete()
        rows = (await (await d.conn.execute("SELECT COUNT(*), COUNT(DISTINCT message_id) FROM chat_fts_map")).fetchone())
        assert rows[0] == rows[1] == 11, tuple(rows)
    run(body)


def test_backfill_batch_survives_rollbacks_elsewhere():
    """Another coroutine rolling back the shared connection while the backfill runs must not discard
    flag updates of a batch whose position was stored: each batch is one uninterrupted step."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        for i in range(30):
            await d.create_chat_message(ch["rnd"], u["bob"], "bob", f"see https://r.example/{i}")
        want = (await (await d.conn.execute("SELECT COUNT(*) FROM chat_fts_map WHERE has_link = 1")).fetchone())[0]
        assert want >= 33
        await d.conn.execute("UPDATE chat_fts_map SET has_link = 0, has_file = 0, has_image = 0")
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        stop = False

        async def roller():
            while not stop:
                await d.conn.rollback()
                await asyncio.sleep(0)
        task = asyncio.create_task(roller())
        try:
            await d.backfill_search_flags(batch_size=2, pause=0)
        finally:
            stop = True
            await task
        got = (await (await d.conn.execute("SELECT COUNT(*) FROM chat_fts_map WHERE has_link = 1")).fetchone())[0]
        assert got == want, (got, want)
        # (the final "done" mark is a plain set_setting, which a rollback in between can still undo; a
        # restart then only repeats a pass that has nothing left to do)
        assert int(await d.get_setting("search_backfill_channel_last_id")) == max(m.values()) + 30
    run(body)


def test_backfill_does_not_overwrite_an_edit_made_after_its_read():
    """The message is edited right when the backfill is about to write the flags of the text it read earlier
    (the hook fires at the backfill's UPDATE of that row when the backfill awaits between its read and its
    write; a backfill that reads and writes in one step gives the hook no such moment). The row must end
    with the flags of the edited text, and the progress marker must have moved on."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        target = await d.create_chat_message(ch["rnd"], u["bob"], "bob", "plain words without an address")
        await d.conn.execute("UPDATE chat_fts_map SET has_link = 0, has_file = 0, has_image = 0")
        await d.conn.execute("DELETE FROM settings WHERE key LIKE 'search_backfill%'")
        await d.conn.commit()
        conn = d.conn
        real = conn.execute
        fired = []

        async def hooked(sql, params=None):
            if (not fired and sql.startswith("UPDATE chat_fts_map SET has_image")
                    and params is not None and params[-1] == target):
                fired.append(True)
                conn.execute = real          # the edit's own statements go straight through
                try:
                    assert await d.edit_chat_message(target, u["bob"], "now with https://e.example/x an address")
                finally:
                    conn.execute = hooked
            return await real(sql, params) if params is not None else await real(sql)
        conn.execute = hooked
        try:
            await d.backfill_search_flags(batch_size=5, pause=0)
        finally:
            conn.execute = real
        if not fired:
            # one-step backfill: it never awaits between read and write; edit afterwards, the index must follow
            assert await d.edit_chat_message(target, u["bob"], "now with https://e.example/x an address")
        row = await (await d.conn.execute("SELECT has_link FROM chat_fts_map WHERE message_id = ?", (target,))).fetchone()
        assert row is not None and row["has_link"] == 1, dict(row) if row else None
        assert int(await d.get_setting("search_backfill_channel_last_id")) >= target
    run(body)


def test_non_public_stream_chat_is_not_searchable_for_other_members():
    """The chat of a stream that is not public is closed to everyone but its owner and admins (the rule inside
    _can_read_channel); search goes through that check, so another member gets no hits, and the answer matches
    the one for a channel that does not exist."""
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        room = await d.create_chat_channel("streamroom2", created_by=u["alice"])
        word = "zebrafinch"
        msg = await d.create_chat_message(room, u["alice"], "alice", f"{word} on the closed stream")
        sid = await d.create_user_stream(u["alice"], "s2", "live_" + "j" * 24, public_key="pub_" + "k" * 24,
                                         is_public=False)
        await d.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (room, sid))
        await d.conn.commit()
        missing_id = room + 1000

        def shape(b):
            return {k: b[k] for k in ("results", "total", "has_more", "capped")}
        for query in (dict(q=word), dict(q="in:streamroom2"), dict(q=word, channel_id=str(room))):
            st, b = await env.search(u["member"], **query)
            assert st == 200 and b["results"] == [] and b["total"] == 0, (query, b)
        # same answer as for a channel that does not exist (by name and by id)
        st, closed = await env.search(u["member"], q="in:streamroom2")
        st2, ghost = await env.search(u["member"], q="in:nosuchroomzz")
        assert shape(closed) == shape(ghost)
        st, closed = await env.search(u["member"], q=word, channel_id=str(room))
        st2, ghost = await env.search(u["member"], q=word, channel_id=str(missing_id))
        assert shape(closed) == shape(ghost)
        # the totals of a search over everything do not move with the closed chat's messages
        st, before = await env.search(u["member"], q=word)
        assert msg not in ids_of(before)
        # the owner and an admin do find it
        for who in ("alice", "boss"):
            st, b = await env.search(u[who], q=word)
            assert ids_of(b) == [msg], (who, b)
        # once the stream is public the same member finds it
        await d.update_user_stream(sid, is_public=True)
        st, b = await env.search(u["member"], q=word)
        assert ids_of(b) == [msg], b
        await d.update_user_stream(sid, is_public=False)
        st, b = await env.search(u["member"], q=word)
        assert b["results"] == [] and b["total"] == 0
    run(body)


def test_one_masking_path_and_no_fail_open():
    handler = SERVER_SRC[SERVER_SRC.index("async def _search_readable_channels"):SERVER_SRC.index("async def http_rebuild_search_index")]
    assert "_can_read_channel(" in handler and "_enrich_channel_messages(" in handler
    assert "_mask_anonymous_author" not in handler, "masking is reused through the history enrichment"
    db_src = (ROOT / "database.py").read_text(encoding="utf-8")
    seg = db_src[db_src.index("    async def search_messages("):db_src.index("    # -- Backfill of the operator flags")]
    assert "accessible_channel_ids = None" not in seg and "Fall back to unfiltered" not in seg


def test_backfill_relies_on_aiosqlite_attributes_that_exist():
    """The backfill runs one batch as a single job on the connection's thread through two private
    aiosqlite attributes (Connection._execute and Connection._conn). Both must exist on the pinned
    aiosqlite (requirements.txt); a version bump that renames them fails here, not in production."""
    async def body(env):
        conn = env.db.conn
        assert callable(getattr(conn, "_execute", None)), "aiosqlite.Connection._execute is gone"
        raw = getattr(conn, "_conn", None)
        assert isinstance(raw, sqlite3.Connection), "aiosqlite.Connection._conn is no longer the sqlite3 connection"
        assert env.db._connection._conn is raw
    run(body)


def test_rebuild_route_answers_409_while_the_backfill_runs():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        root = await d.create_user("rootadmin", "x")
        await d.set_user_role(root, "superadmin")

        async def rebuild(uid):
            async with env.http.post(str(env.srv.make_url("/api/chat/search/rebuild")),
                                     headers={"X-Test-User": str(uid)}) as r:
                return r.status, await r.json()
        async with d._search_backfill_lock:      # a backfill (or another rebuild) is running
            st, b = await asyncio.wait_for(rebuild(root), 3)
            assert st == 409 and "being built" in b["error"], (st, b)
            st, b = await asyncio.wait_for(rebuild(u["boss"]), 3)
            assert st == 403, (st, b)        # still superadmin only, checked first
        st, b = await asyncio.wait_for(rebuild(root), 30)
        assert st == 200 and b["rebuilt"] is True and b["indexed"]["channel"] == 11, (st, b)
    run(body)


def test_search_fails_closed_when_the_readable_channels_cannot_be_looked_up():
    async def body(env):
        d = env.db
        u, ch, m = await seed(d)
        st, ok = await env.search(u["member"], q="dinner")
        assert st == 200 and ok["total"] > 0, ok
        # the check on one channel raises: no search at all, never one without the filter
        real = server._can_read_channel

        async def broken(*a, **k):
            raise RuntimeError("lookup failed")
        server._can_read_channel = broken
        try:
            for who in ("member", "boss"):
                st, b = await env.search(u[who], q="dinner")
                assert st == 503 and "results" not in b and "unavailable" in b["error"], (st, b)
        finally:
            server._can_read_channel = real
        # the lookup of the accessible channels raises
        real_acc = d.get_accessible_channels

        async def broken_acc(*a, **k):
            raise RuntimeError("lookup failed")
        d.get_accessible_channels = broken_acc
        try:
            st, b = await env.search(u["member"], q="dinner")
            assert st == 503 and "results" not in b, (st, b)
            # a search with no read check of its own (channel_ids not given) searches no channel
            res = await d.search_messages("dinner", u["boss"], user_role="superadmin", scope="channels")
            assert res["results"] == [] and res["total"] == 0, res
            res = await d.search_messages("dinner", u["boss"], user_role="superadmin", scope="all")
            assert all(r["source"] != "channel" for r in res["results"]), res
        finally:
            d.get_accessible_channels = real_acc
        # (control) the same call with the lookup working finds the channel messages
        res = await d.search_messages("dinner", u["boss"], user_role="superadmin", scope="channels")
        assert res["total"] > 0, res
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
