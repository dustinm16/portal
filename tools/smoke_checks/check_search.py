"""Message search on a running instance: operators, in-context results, access,
anonymity, the index flags and the one-time backfill.

Users, channels and messages are created in the stage database with ctx.run_py
(registration is rate limited); everything is read back through the real
endpoints. Names carry a random suffix and every search is limited to the
check's own channels with in:<name>, so the check also holds on a stage started
from a copy of the production database (no counts of shared tables, no reliance
on which messages are the newest). The backfill step moves the stored position
to just below the check's own first message, so on a production copy it only
touches the check's rows. Nothing here needs the admin password.

Search is limited to 10 requests a minute per user, so the searches are spread
over several users.

Not covered (needs a browser, see the final report): the look of the suggestion
chips and the highlight in the chat after a click on a result.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone

PW = "Search-check-pw-1"

SETUP = r'''
import asyncio, json
from datetime import datetime, timedelta, timezone
from database import db
from auth import hash_password

P = json.loads(%(params)r)

async def main():
    await db.connect()
    try:
        out = {"users": {}}
        pw = hash_password(P["pw"])
        for name in P["names"]:
            u = await db.get_user_by_username(P["pre"] + name)
            out["users"][name] = u["id"] if u else await db.create_user(P["pre"] + name, pw)
        ids = out["users"]
        await db.set_user_role(ids["mod"], "moderator")
        await db.set_user_nickname(ids["mom"], P["pre"] + "Mommy")
        await db.set_user_nickname(ids["anon"], P["pre"] + "Shadow")
        await db.set_avatar(ids["anon"], {"color": "#112233", "emoji": P["pre"] + "AV", "initials": "ZQ"})
        await db.set_chat_anonymous(ids["anon"], True)

        main_ch = await db.create_chat_channel(P["pre"] + "-main", created_by=ids["mom"])
        priv = await db.create_chat_channel(P["pre"] + "-priv", created_by=ids["mom"])
        await db.update_chat_channel(priv, visibility="private")
        await db.add_channel_member(priv, ids["member"])
        await db.add_channel_member(priv, ids["mom"])
        word = P["pre"] + "dinner"
        old = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        m = {}
        m["photo"] = await db.create_chat_message(main_ch, ids["mom"], P["pre"] + "mom", "", image_url="/static/uploads/%%s.png" %% P["pre"])
        m["text"] = await db.create_chat_message(main_ch, ids["mom"], P["pre"] + "mom", word + " at six")
        m["link"] = await db.create_chat_message(main_ch, ids["mom"], P["pre"] + "mom", word + " recipe https://example.com/pie")
        m["file"] = await db.create_chat_message(main_ch, ids["alice"], P["pre"] + "alice", "", attachment_url="/static/uploads/%%s.pdf" %% P["pre"],
                                                  attachment_name="menu.pdf", attachment_size=10, attachment_type="application/pdf")
        m["imgatt"] = await db.create_chat_message(main_ch, ids["alice"], P["pre"] + "alice", word + " cat", attachment_url="/static/uploads/%%s.jpg" %% P["pre"],
                                                    attachment_name="cat.jpg", attachment_size=10, attachment_type="image/jpeg")
        m["anon_text"] = await db.create_chat_message(main_ch, ids["anon"], P["pre"] + "anon", word + " secret https://anon.example/x", anonymous=True)
        m["anon_file"] = await db.create_chat_message(main_ch, ids["anon"], P["pre"] + "anon", "", anonymous=True,
                                                       attachment_url="/static/uploads/%%s.zip" %% P["pre"], attachment_name="a.zip",
                                                       attachment_size=1, attachment_type="application/zip")
        m["alice_anon"] = await db.create_chat_message(main_ch, ids["alice"], P["pre"] + "alice", word + " alice anonymously", anonymous=True)
        m["priv"] = await db.create_chat_message(priv, ids["mom"], P["pre"] + "mom", word + " in the secret room https://p.example")
        await db.pin_message(m["text"], ids["mod"])
        await db.conn.execute("UPDATE chat_messages SET created_at = ? WHERE id = ?", (old, m["photo"]))
        await db.conn.execute("UPDATE chat_fts_map SET created_at = ? WHERE message_id = ?", (old, m["photo"]))
        await db.conn.commit()
        # more link posts than an operator-only query lists (200)
        bulk = await db.create_chat_channel(P["pre"] + "-bulk", created_by=ids["mom"])
        for i in range(P["bulk_posts"]):
            await db.create_chat_message(bulk, ids["mom"], P["pre"] + "mom", "pie https://bulk.example/%%d" %% i)
        # a word search in the merged scope: short posts rank best, long newer ones worse
        pg = await db.create_chat_channel(P["pre"] + "-page", created_by=ids["mom"])
        pword = P["pre"] + "pearword"
        for i in range(6):
            await db.create_chat_message(pg, ids["mom"], P["pre"] + "mom", "%%s %%d" %% (pword, i))
        for i in range(6):
            await db.create_chat_message(pg, ids["mom"], P["pre"] + "mom", "%%s %%s%%d" %% (pword, "filler words here " * 20, i))
        # more word matches than the offset cap allows paging through (2000 + one page of 25)
        deep = await db.create_chat_channel(P["pre"] + "-deep", created_by=ids["mom"])
        dword = P["pre"] + "deepword"
        for i in range(P["deep_posts"]):
            await db.create_chat_message(deep, ids["mom"], P["pre"] + "mom", "%%s %%d" %% (dword, i))
        out["main"], out["priv"], out["m"], out["word"], out["bulk"] = main_ch, priv, m, word, bulk
        out["pword"] = pword
        out["dword"] = dword
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''

# Puts the check's own index rows back into the state before this release and
# points the backfill at them (nothing below the first of them is read), or
# runs the backfill and reports its state.
LEGACY = r'''
import asyncio, json
from database import db

P = json.loads(%(params)r)

async def main():
    await db.connect()
    try:
        out = {}
        ids = P["ids"]
        ph = ",".join("?" * len(ids))
        if P["act"] == "legacy":
            await db.conn.execute(f"UPDATE chat_fts_map SET has_link = 0, has_file = 0, has_image = 0 WHERE message_id IN ({ph})", ids)
            gph = ",".join("?" * len(P["gaps"]))
            await db.conn.execute(f"DELETE FROM chat_fts_map WHERE message_id IN ({gph})", P["gaps"])
            await db.conn.execute("DELETE FROM settings WHERE key = 'search_backfill_done'")
            cur = await db.conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM dm_messages")
            dm_max = (await cur.fetchone())["m"]
            await db.set_setting("search_backfill_channel_last_id", str(min(ids) - 1))
            await db.set_setting("search_backfill_dm_last_id", str(dm_max))
            await db.conn.commit()
        elif P["act"] == "backfill":
            out["stats"] = await db.backfill_search_flags(batch_size=P.get("batch", 200), pause=0)
            out["again"] = await db.backfill_search_flags()
            out["done"] = await db.search_backfill_complete()
        elif P["act"] == "state":
            cur = await db.conn.execute(f"SELECT message_id, has_image, has_file, has_link FROM chat_fts_map WHERE message_id IN ({ph})", ids)
            out["rows"] = {str(r["message_id"]): [r["has_image"], r["has_file"], r["has_link"]] for r in await cur.fetchall()}
            for t in ("chat_fts_map", "dm_fts_map"):
                cur = await db.conn.execute(f"PRAGMA table_info({t})")
                out[t] = [r["name"] for r in await cur.fetchall()]
            out["last_id"] = await db.get_setting("search_backfill_channel_last_id")
        print("RESULT " + json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
'''


def _result(output):
    for line in output.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


async def run(ctx):
    rnd = secrets.token_hex(3)
    pre = "se" + rnd
    names = ("mom", "alice", "anon", "member", "outsider", "mod", "v1", "v2", "v3", "limit", "pager", "paging", "deep")
    params = {"pw": PW, "names": names, "pre": pre, "bulk_posts": 205, "deep_posts": 2030}
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps(params)}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("search: setup", False, out[-500:])
        return
    ids, m, main_ch, word = data["users"], data["m"], data["main"], data["word"]
    inmain = f"in:{pre}-main"
    secrets_ = [pre + "anon", pre + "Shadow", pre + "AV"]
    own = list(m.values())

    async def act(act, **kw):
        rc2, out2 = await ctx.run_py(LEGACY % {"params": json.dumps({"act": act, **kw})}, timeout=170)
        return _result(out2) if rc2 == 0 else None

    # the stage never starts the backfill by itself
    ctx.ok("search: a staged instance does not start the backfill on its own",
           "Search index backfill" not in ctx.server_log())

    sessions = {}
    try:
        for n in ("member", "outsider", "mod", "anon", "v1", "v2", "v3", "limit", "pager", "paging", "deep"):
            s = ctx.http()
            await s.__aenter__()
            sessions[n] = s
            resp = await ctx.login(s, pre + n, PW)
            if resp.status != 200:
                ctx.ok("search: users can log in", False, f"{n}: {resp.status}")
                return

        async def search(who, q, **extra):
            async with sessions[who].get(f"{ctx.base_url}/api/chat/search", params={"q": q, **extra}) as r:
                try:
                    body = await r.json()
                except Exception:
                    body = None
                return r.status, body

        def ids_of(body):
            return [r["id"] for r in (body or {}).get("results", [])]

        # ---- migration and flags written for new messages --------------------------
        st = await act("state", ids=own)
        ctx.ok("search: the index map has the link and file columns",
               bool(st) and "has_link" in st["chat_fts_map"] and "has_file" in st["chat_fts_map"]
               and "has_link" in st["dm_fts_map"] and "has_file" in st["dm_fts_map"])
        rows = (st or {}).get("rows", {})
        ctx.ok("search: attachment-only posts are indexed when written, with their flags",
               rows.get(str(m["photo"])) == [1, 0, 0] and rows.get(str(m["file"])) == [0, 1, 0]
               and rows.get(str(m["imgatt"])) == [1, 0, 0] and rows.get(str(m["link"])) == [0, 0, 1], str(rows))

        # ---- the index before the backfill: old rows have no link or file flags ------
        legacy = await act("legacy", ids=own, gaps=[m["photo"], m["file"], m["anon_file"]])
        ctx.ok("search: the check's own index rows are put back into their old state", legacy is not None)
        st = await act("state", ids=own)
        ctx.ok("search: ... without link or file flags and without the attachment-only rows",
               bool(st) and set(st["rows"]) == {str(i) for i in own} - {str(m["photo"]), str(m["file"]), str(m["anon_file"])}
               and all(v == [0, 0, 0] for v in st["rows"].values()), str(st)[:300])
        code, body = await search("v1", f"has:link {inmain}")
        ctx.ok("search: before the backfill has:link finds nothing of the old rows and says the index is unfinished",
               code == 200 and body["results"] == [] and body["index_complete"] is False, str(body)[:200])
        a = await act("backfill", ids=own, batch=3)
        ctx.ok("search: the backfill finishes in small batches, sets its flag and does no work a second time",
               bool(a) and a["done"] is True and a["again"] == {"skipped": "done"}
               and a["stats"]["channel"] >= len(own), str(a))
        st = await act("state", ids=own)
        rows = (st or {}).get("rows", {})
        ctx.ok("search: the backfill restores the flags and adds the missing rows",
               rows.get(str(m["photo"])) == [1, 0, 0] and rows.get(str(m["file"])) == [0, 1, 0]
               and rows.get(str(m["anon_file"])) == [0, 1, 0] and rows.get(str(m["link"])) == [0, 0, 1]
               and rows.get(str(m["imgatt"])) == [1, 0, 0] and rows.get(str(m["text"])) == [0, 0, 0], str(rows))
        ctx.ok("search: the stored position moved to the last row", bool(st) and int(st["last_id"]) >= max(own))

        # ---- Done-when lines --------------------------------------------------------
        code, body = await search("member", f"from:{pre}mom has:image {inmain}")
        ctx.ok("search: from:<name> has:image returns the image-only post from last month",
               code == 200 and ids_of(body) == [m["photo"]], str(body)[:300])
        hit = (body["results"] or [{}])[0]
        ctx.ok("search: the hit carries what a click needs (channel and message id) and the date",
               hit.get("source") == "channel" and hit.get("source_id") == main_ch and hit.get("has_image") == 1
               and str(hit.get("created_at", ""))[:10] == (datetime.now(timezone.utc) - timedelta(days=35)).strftime("%Y-%m-%d"))
        async with sessions["member"].get(f"{ctx.base_url}/api/chat/channels/{main_ch}/messages",
                                          params={"around_id": m["photo"], "limit": 20}) as r:
            page = await r.json()
        ctx.ok("search: the history route opens that message in context",
               r.status == 200 and page["found"] and m["photo"] in [x["id"] for x in page["messages"]])
        code, nick = await search("v1", f"from:{(pre + 'Mommy').lower()} has:image {inmain}")
        ctx.ok("search: from: also takes the nickname, in any case", code == 200 and ids_of(nick) == [m["photo"]])

        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d")
        code, body = await search("member", f"{inmain} before:{yesterday}")
        ctx.ok("search: in:<channel> before:<date> returns only that channel's older post",
               code == 200 and ids_of(body) == [m["photo"]] and body["operator_only"] is True, str(body)[:200])
        code, body = await search("member", f"{inmain} before:{tomorrow}")
        ctx.ok("search: an operator-only query lists everything of the channel, newest first, not capped",
               code == 200 and ids_of(body) == sorted(ids_of(body), reverse=True)
               and set(ids_of(body)) == set(m[k] for k in ("photo", "text", "link", "file", "imgatt", "anon_text", "anon_file", "alice_anon"))
               and body["capped"] is False and body["has_more"] is False, str(body)[:300])

        code, body = await search("outsider", f"in:{pre}-priv")
        code2, none = await search("outsider", f"in:{pre}-nosuchchannel")
        strip = lambda b: {k: v for k, v in (b or {}).items() if k not in ("query", "terms")}
        ctx.ok("search: a private channel a member does not belong to looks like one that does not exist",
               code == 200 and body["results"] == [] and body["total"] == 0 and strip(body) == strip(none), str(body)[:200])
        code, body = await search("member", f"in:{pre}-priv")
        ctx.ok("search: a member of the private channel finds its post", code == 200 and ids_of(body) == [m["priv"]])
        code, body = await search("mod", f"in:{pre}-priv")
        ctx.ok("search: a moderator who is not a member does not", code == 200 and body["results"] == [])
        code, body = await search("outsider", f"{word}")
        ctx.ok("search: a word search by an outsider never includes the private channel",
               code == 200 and m["priv"] not in ids_of(body) and m["text"] in ids_of(body))

        code, body = await search("v1", f"has:link {inmain}")
        ctx.ok("search: has:link returns the old posts after the backfill",
               code == 200 and set(ids_of(body)) == {m["link"], m["anon_text"]} and body["index_complete"] is True, str(body)[:200])
        code, body = await search("v1", f"has:file {inmain}")
        ctx.ok("search: has:file returns file-only posts, not image attachments",
               set(ids_of(body)) == {m["file"], m["anon_file"]})
        code, body = await search("v1", f"has:image {inmain}")
        ctx.ok("search: has:image returns image posts and image attachments", set(ids_of(body)) == {m["photo"], m["imgatt"]})
        code, body = await search("v1", f"is:pinned {inmain}")
        ctx.ok("search: is:pinned returns the pinned post", ids_of(body) == [m["text"]])
        code, body = await search("v1", f"{word} {inmain} -from:{pre}mom")
        ctx.ok("search: a word with -from: leaves out that author", m["text"] not in ids_of(body) and m["imgatt"] in ids_of(body))

        # ---- refusals ---------------------------------------------------------------
        for q, label in ((f"has:video {inmain}", "an unknown has: value"), ("colour:red", "an unknown operator"),
                         ("before:soon", "a bad date"), ("has:link before:2026-02-30", "an impossible date"),
                         ("-has:link", "a negated has:")):
            code, body = await search("v2", q)
            ctx.ok(f"search: {label} is a 400 with a message", code == 400 and bool((body or {}).get("error")), f"{code} {body}")
        code, body = await search("v2", "has:link", **{"from": "x", "has": "bogus"})
        ctx.ok("search: the older has= parameter is checked too", code == 400)
        code, body = await search("v2", f"see https://example.com/{pre} {inmain}")
        ctx.ok("search: an address in the query is searched as text, not refused", code == 200)

        # ---- anonymity --------------------------------------------------------------
        anon_ids = {m["anon_text"], m["anon_file"], m["alice_anon"]}
        code, by_name = await search("v3", f"from:{pre}anon {inmain}")
        code2, by_nick = await search("v3", f"from:{pre}Shadow {inmain}")
        code3, ghost = await search("v3", f"from:{pre}nobodyatall {inmain}")
        ctx.ok("search: from:<anonymous author> matches nothing for a member, by name or nickname, same as an unknown name",
               code == code2 == code3 == 200 and by_name["results"] == [] and by_nick["results"] == []
               and by_name["total"] == by_nick["total"] == ghost["total"] == 0, str(by_name)[:200])
        code, alice_from = await search("v3", f"from:{pre}alice {inmain}")
        ctx.ok("search: an author's anonymous posts are not found through from:<their name>",
               set(ids_of(alice_from)) == {m["file"], m["imgatt"]} and m["alice_anon"] not in ids_of(alice_from), str(ids_of(alice_from)))
        code, a_neg = await search("v3", f"-from:{pre}anon {inmain}")
        code, g_neg = await search("v3", f"-from:{pre}nobodyatall {inmain}")
        ctx.ok("search: -from:<anonymous author> is indistinguishable from -from:<unknown name>",
               ids_of(a_neg) == ids_of(g_neg) and a_neg["total"] == g_neg["total"] and anon_ids <= set(ids_of(a_neg)))
        ctx.ok("search: no response names an anonymous author, their nickname or avatar",
               not any(s in json.dumps({k: v for k, v in b.items() if k not in ("query", "terms")})
                       for b in (a_neg, g_neg, by_name, alice_from) for s in secrets_))
        masked = [r for r in a_neg["results"] if r["id"] in anon_ids]
        ctx.ok("search: anonymous hits show Anonymous with no id, role, nickname or avatar",
               len(masked) == 3 and all(r["username"] == "Anonymous" and r["display_name"] == "Anonymous"
                                        and r["user_id"] is None and r["role"] is None and r["nickname"] is None
                                        and r["avatar"] == {} for r in masked))
        code, staff = await search("mod", f"from:{pre}anon {inmain}")
        ctx.ok("search: a moderator, who already receives the author id, may match an anonymous author",
               set(ids_of(staff)) == {m["anon_text"], m["anon_file"]}
               and all(r["user_id"] == ids["anon"] and r["username"] == "Anonymous" for r in staff["results"]))
        code, own_view = await search("anon", f"from:{pre}anon {inmain}")
        ctx.ok("search: the author searching for themselves gets no match through from: either",
               code == 200 and own_view["results"] == [])

        # ---- an operator-only query past the cap can be paged to its end ------------
        inbulk = f"in:{pre}-bulk"
        seen, offset, pages, last = [], 0, 0, None
        while pages < 12:
            code, last = await search("pager", f"has:link {inbulk}", offset=offset)
            pages += 1
            if code != 200:
                break
            seen += ids_of(last)
            offset += len(last["results"])
            if not last["has_more"]:
                break
        ctx.ok("search: a capped query (205 matches) pages with the default size to 200 results and then has_more is false",
               code == 200 and len(seen) == 200 and len(set(seen)) == 200 and pages == 8 and last["capped"] is True
               and last["total"] == 200 and last["has_more"] is False and seen == sorted(seen, reverse=True),
               f"{code} pages={pages} seen={len(seen)} {str(last)[:200]}")
        code, past = await search("pager", f"has:link {inbulk}", offset=2000)
        ctx.ok("search: the largest allowed offset (2000) past the cap answers an empty page, no more pages, still capped",
               code == 200 and past["results"] == [] and past["has_more"] is False and past["capped"] is True and past["total"] == 200,
               str(past)[:200])

        code, deep = await search("paging", f"has:link {inbulk}", offset=2001)   # own user: the pager is at its 10 searches
        ctx.ok("search: an offset above 2000 is refused with 400 and says so",
               code == 400 and "2000" in str(deep.get("error", "")) and "results" not in deep, f"{code} {str(deep)[:200]}")
        for name, bad in (("channel_id", 0), ("channel_id", -3), ("channel_id", 2 ** 63), ("conversation_id", 0),
                          ("conversation_id", 10 ** 30)):
            code, rb = await search("paging", f"has:link {inbulk}", **{name: bad})
            ctx.ok(f"search: {name}={bad} is out of range and answers 400, like the history routes",
                   code == 400 and "results" not in (rb or {}), f"{code} {str(rb)[:200]}")
        code, huge = await search("pager", f"has:link {inbulk}", offset=10 ** 19)
        ctx.ok("search: an offset past the integer range is refused with 400, not answered as an empty page",
               code == 400 and "offset" in str(huge.get("error", "")) and "results" not in huge, f"{code} {str(huge)[:200]}")

        # ---- a word search in the merged scope pages without repeats or gaps -------
        inpage = f"{data['pword']} in:{pre}-page"
        pages_seen = []
        for off in (0, 5, 10):
            code, pb = await search("paging", inpage, scope="all", limit=5, offset=off)
            pages_seen.append(ids_of(pb) if code == 200 else None)
        flat = [i for p in pages_seen if p for i in p]
        ctx.ok("search: pages of a word search in the all scope add up to every match once, newest first",
               [len(p or []) for p in pages_seen] == [5, 5, 2] and len(set(flat)) == 12 and flat == sorted(flat, reverse=True),
               str(pages_seen))

        # ---- has_more never invites a page the offset cap refuses -------------------
        indeep = f"{data['dword']} in:{pre}-deep"
        code, edge = await search("deep", indeep, scope="channels", limit=25, offset=1975)
        ctx.ok("search: the page that ends at the offset cap (2000) of a 2030-match word search still has more",
               code == 200 and len(edge["results"]) == 25 and edge["total"] == 2030 and edge["has_more"] is True,
               f"{code} {str(edge)[:200]}")
        code, over = await search("deep", indeep, scope="channels", limit=25, offset=2000)
        ctx.ok("search: the page that ends past the cap says has_more false although matches remain, so Load more goes away",
               code == 200 and len(over["results"]) == 25 and over["total"] == 2030 and over["has_more"] is False,
               f"{code} {str(over)[:200]}")
        code, refused = await search("deep", indeep, scope="channels", limit=25, offset=2025)
        ctx.ok("search: the page after it is refused with 400, which has_more false no longer invites",
               code == 400 and "2000" in str(refused.get("error", "")), f"{code} {str(refused)[:200]}")

        # ---- rate limit stays at 10 a minute ----------------------------------------
        codes = []
        for _ in range(11):
            c, _b = await search("limit", f"has:link {inmain}")
            codes.append(c)
        ctx.ok("search: the 11th search in a minute is rate limited", codes == [200] * 10 + [429], str(codes))

        # ---- the page ships the client ----------------------------------------------
        async with sessions["member"].get(f"{ctx.base_url}/chat") as r:
            text = await r.text()
            ctx.ok("search: the chat page has the suggestion chips and sends the query as typed",
                   r.status == 200 and "search-chips" in text and "SEARCH-CLIENT-BEGIN" in text and "parseSearchFilters" not in text)
    finally:
        for s in sessions.values():
            await s.__aexit__(None, None, None)
