"""Small privacy leaks (1.24.1): the SQL driver's logger never prints parameters, custom thumbnails of a non-public
stream are served to those who may watch it only (private, no-store), the owner's health dot does not show a
grantee's filing, and the go-live activity row is written from the stream as it is when it is written.

Real app on a loopback test server (tests/grant_harness.py) and temporary databases. Run: venv/bin/python tests/test_privacy_leaks.py
"""

import asyncio
import io
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402

import connection_health  # noqa: E402
import logger as portal_logger  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


async def driver_log_check(db):
    secret = "sf_hash_" + "ab12" * 16
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    saved = (root.level, logging.getLogger("aiosqlite").level)
    portal_logger.setup_logging()
    root.addHandler(handler)
    try:
        root.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        await db.conn.execute("SELECT ? AS x", (secret,))
        await db.conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('probe', ?)", (secret,))
        await db.conn.commit()
        check("DEBUG on the root logger: the SQL driver's logger prints no parameter value", secret not in stream.getvalue(),
              stream.getvalue()[:200])
        portal_logger.set_log_level("DEBUG")
        await db.conn.execute("SELECT ? AS x", (secret,))
        check("set_log_level(DEBUG) does not switch the driver's output on", secret not in stream.getvalue())
        check("the driver's logger has its own level above DEBUG", logging.getLogger("aiosqlite").level >= logging.INFO)
    finally:
        root.removeHandler(handler)
        root.setLevel(saved[0])
        portal_logger.set_log_level("INFO")


async def main():
    env = await h.boot(names=("owner", "bob", "carol", "adm"))
    db = env.db
    u = env.uid
    await driver_log_check(db)

    # ---- custom thumbnails ---------------------------------------------------------------------------------------
    upload = h.STATIC_DIR / "uploads" / "thumbnails"
    upload.mkdir(parents=True, exist_ok=True)
    files = []
    try:
        async def stream_with_thumb(name, public):
            sid = await db.create_user_stream(u["owner"], name, "live_" + name * 12, public_key="pub_" + name * 12, is_public=public)
            fn = f"t241{name}{public}.jpg"
            (upload / fn).write_bytes(b"\xff\xd8\xff\xd9")
            files.append(upload / fn)
            await db.update_user_stream(sid, user_id=u["owner"], thumbnail_url=f"/static/uploads/thumbnails/{fn}")
            return sid, f"/static/uploads/thumbnails/{fn}"

        pub, pub_url = await stream_with_thumb("pub", 1)
        prv, prv_url = await stream_with_thumb("prv", 0)
        orphan = upload / "t241orphan.jpg"
        orphan.write_bytes(b"\xff\xd8\xff\xd9")
        files.append(orphan)

        async def get(who, url):
            async with env.sessions[who].get(env.base + url, allow_redirects=False) as r:
                return r.status, dict(r.headers)

        for who in ("owner", "adm"):
            st, hd = await get(who, prv_url)
            check(f"{who} gets the private stream's thumbnail, private and not stored",
                  st == 200 and hd.get("Cache-Control") == "private, no-store", f"{st} {hd.get('Cache-Control')}")
        st, hd = await get("bob", prv_url)
        check("a member who may not watch the stream gets 404 for its thumbnail", st == 404, str(st))
        async def raw_get(who, path):
            # yarl would fold a "." segment away before sending, so the request is made with the path as written
            async with env.sessions[who].get(__import__("yarl").URL(env.base + path, encoded=True), allow_redirects=False) as r:
                return r.status, dict(r.headers)

        fn_prv = prv_url.rsplit("/", 1)[1]
        for odd in ("/static/uploads/%2e/thumbnails/", "/static/uploads/./thumbnails/", "/static/uploads/%2e//thumbnails/",
                    "/static/uploads/thumbnails/%2e/", "/static/uploads/thumbnails//", "/static/uploads/.//thumbnails/"):
            for who in ("bob", "owner"):
                st, hd = await raw_get(who, odd + fn_prv)
                check(f"{who}: the private thumbnail by the spelling {odd!r} is not served",
                      st in (400, 404) and "image" not in hd.get("Content-Type", ""), f"{st} {hd.get('Cache-Control')}")
        st, hd = await raw_get("bob", "/static/uploads/thumbnails%2F" + fn_prv)
        check("bob: the %2F spelling is still gated like the plain path", st == 404, str(st))
        st, hd = await raw_get("owner", "/static/uploads/thumbnails%2F" + fn_prv)
        check("owner: the %2F spelling is the plain path and carries the private header",
              st == 200 and hd.get("Cache-Control") == "private, no-store", f"{st} {hd.get('Cache-Control')}")
        # The same file through the plain static route: spellings the uploads route does not match ("%2F" in the
        # directory part, "." and ".." segments before "uploads") must not serve anything under static/uploads.
        chat_dir = h.STATIC_DIR / "uploads" / "chat"
        chat_dir.mkdir(parents=True, exist_ok=True)
        active = chat_dir / "t241active.html"
        active.write_bytes(b"<script>1</script>")
        files.append(active)
        import aiohttp as _aiohttp
        import yarl as _yarl

        async def anon_get(path):
            async with _aiohttp.ClientSession() as anon:
                async with anon.get(_yarl.URL(env.base + path, encoded=True), allow_redirects=False) as r:
                    return r.status, dict(r.headers), await r.read()

        for target, label in ((prv_url.replace("/static/uploads/", ""), "a private thumbnail"),
                              ("chat/t241active.html", "an uploaded html file"),
                              (pub_url.replace("/static/uploads/", ""), "a public thumbnail")):
            sub, name = target.split("/", 1)
            for spelling in (f"/static/uploads%2F{sub}/{name}", f"/static/./uploads/{sub}/{name}",
                             f"/static/%2e/uploads/{sub}/{name}", f"/static/x/../uploads/{sub}/{name}",
                             f"/static/x/%2e%2e/uploads/{sub}/{name}", f"/static/uploads/../uploads/{sub}/{name}"):
                for who in ("bob", "anon"):
                    if who == "anon":
                        st, hd, body = await anon_get(spelling)
                    else:
                        st, hd = await raw_get(who, spelling)
                        body = b""
                    check(f"{who}: {label} by the static-route spelling {spelling!r} is not served",
                          st != 200 and "image" not in hd.get("Content-Type", "") and "html" not in hd.get("Content-Type", "")
                          and body != b"<script>1</script>", f"{st} {hd.get('Content-Type')}")
        # The guard works out the uploads root once, not on every static request.
        import pathlib as _pathlib
        real_resolve, uploads_dir, resolved_uploads = _pathlib.Path.resolve, h.STATIC_DIR / "uploads", []

        def counting_resolve(self, *a, **kw):
            if self == uploads_dir:
                resolved_uploads.append(str(self))
            return real_resolve(self, *a, **kw)
        _pathlib.Path.resolve = counting_resolve
        try:
            for _ in range(3):
                await raw_get("bob", "/static/css/portal.css")
        finally:
            _pathlib.Path.resolve = real_resolve
        check("three static requests resolve the uploads directory at most once between them (not once each)",
              len(resolved_uploads) <= 1, str(resolved_uploads))
        for who in ("bob", "owner"):
            st, hd = await raw_get(who, "/static/css/portal.css")
            check(f"{who}: an ordinary static file is still served", st == 200 and "css" in hd.get("Content-Type", ""),
                  f"{st} {hd.get('Content-Type')}")
        st, hd, body = await anon_get("/static/css/portal.css")
        check("logged out: an ordinary static file is still served", st == 200, str(st))
        st, hd = await get("bob", pub_url)
        check("a public stream's thumbnail is answered for the signed-in member only: Cache-Control private, not no-store",
              st == 200 and hd.get("Cache-Control") == "private", f"{st} {hd.get('Cache-Control')}")
        chat_png = chat_dir / "t241cache.png"
        chat_png.write_bytes(b"\x89PNG\r\n\x1a\n")
        files.append(chat_png)
        st, hd = await get("bob", "/static/uploads/chat/t241cache.png")
        check("a chat attachment is answered with Cache-Control private (no shared cache stores it)",
              st == 200 and hd.get("Cache-Control") == "private", f"{st} {hd.get('Cache-Control')}")
        st, hd = await get("bob", "/static/uploads/chat/t241active.html")
        check("a chat file offered as a download carries Cache-Control private too",
              st == 200 and hd.get("Cache-Control") == "private" and "attachment" in hd.get("Content-Disposition", ""),
              f"{st} {hd.get('Cache-Control')}")
        st, hd = await get("bob", "/static/uploads/thumbnails/t241orphan.jpg")
        check("a thumbnail no stream names is not served", st == 404, str(st))
        async with env.srv.make_url("/") and __import__("aiohttp").ClientSession() as anon:
            async with anon.get(env.base + prv_url, allow_redirects=False) as r:
                check("nobody logged in gets 401 as before", r.status == 401, str(r.status))
        await db.update_user_stream(prv, user_id=u["owner"], is_public=1)
        st, hd = await get("bob", prv_url)
        check("once the stream is public again the thumbnail is open to members", st == 200, str(st))
        await db.update_user_stream(prv, user_id=u["owner"], is_public=0)
        await db.create_stream_ban(prv, u["carol"], u["owner"], "r")
        st, hd = await get("carol", prv_url)
        check("a banned member gets 404", st == 404, str(st))
    finally:
        for f in files:
            f.unlink(missing_ok=True)

    # ---- the owner's health dot -------------------------------------------------------------------------------------
    await db.set_setting(connection_health.SETTING_ENABLED, "1")
    uuid = await db.create_user_connection(u["owner"], "web", "http_proxy", "93.184.216.34", 80, "{}")
    cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
    await db.conn.execute("INSERT INTO connection_shares (connection_id, grantee_user_id, granted_by) VALUES (?, ?, ?)",
                          (cid, u["bob"], u["owner"]))
    await db.conn.commit()
    await db.set_connection_prefs(u["bob"], cid, {"pinned": True}, owner=False)
    mon = connection_health.Monitor(db, {"http_proxy": {"plugin": "http_proxy", "default_port": 80}}, emit=lambda *a, **k: None,
                                    probe=None)
    now = mon.clock()
    mon.state.entries[cid] = type("E", (), {})()
    e = mon.state.entries[cid]
    e.status, e.checked, e.latency_ms, e.since = "up", now, 5, "2026-01-01T00:00:00+00:00"
    own = (await mon.statuses_for(u["owner"]))[uuid]
    grantee = (await mon.statuses_for(u["bob"]))[uuid]
    check("a grantee's pin does not give the owner a dot", own["status"] == "unknown", str(own))
    check("the grantee who pinned it sees the status", grantee["status"] == "up", str(grantee))
    await db.set_connection_prefs(u["owner"], cid, {"pinned": True}, owner=True)
    check("the owner's own pin gives the owner the status", (await mon.statuses_for(u["owner"]))[uuid]["status"] == "up")
    await db.set_connection_prefs(u["owner"], cid, {"pinned": False}, owner=True)
    check("without the owner's pin it is unknown again", (await mon.statuses_for(u["owner"]))[uuid]["status"] == "unknown")
    await db.conn.execute("UPDATE connection_user_prefs SET last_opened_at = ? WHERE user_id = ? AND connection_id = ?",
                          ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), u["owner"], cid))
    await db.conn.commit()
    check("the owner's own recent use gives the status", (await mon.statuses_for(u["owner"]))[uuid]["status"] == "up")

    # ---- the go-live activity row is written from the stream as it is now ---------------------------------------------
    sid = await db.create_user_stream(u["owner"], "before", "live_" + "q" * 24, public_key="pub_" + "q" * 24, is_public=1)
    real_set_live = db.set_stream_live

    async def flip(stream_id, is_live, session_stats=None):
        ok = await real_set_live(stream_id, is_live, session_stats=session_stats)
        await db.update_user_stream(stream_id, user_id=u["owner"], name="after", is_public=0)
        return ok
    db.set_stream_live = flip
    server._announce_go_live = lambda *a, **k: asyncio.sleep(0)
    try:
        await server._mark_stream_live(await db.get_user_stream(sid), "127.0.0.1")
    finally:
        db.set_stream_live = real_set_live
    cur = await db.conn.execute("SELECT action, detail FROM activity_log WHERE detail LIKE '%went live%' ORDER BY id DESC LIMIT 1")
    row = await cur.fetchone()
    check("the go-live row is private and carries the present name", row is not None and row["action"] == "stream_live_private"
          and "after" in row["detail"] and "before" not in row["detail"], str(dict(row) if row else None))

    await h.shutdown(env)
    h.finish("test_privacy_leaks")


async def guarded():
    try:
        await asyncio.wait_for(main(), 100)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        import os
        os._exit(1)


asyncio.run(guarded())
