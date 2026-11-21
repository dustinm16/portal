"""Chat upload files: removed with their messages, kept while another row names them,
and the orphan sweeper (report only by default).

Real endpoints are used where they exist: POST /api/chat/upload, the chat WebSocket
(send and delete a message) and POST /api/admin/retention/run. Old rows and files
that would take weeks to appear are planted in-process (ctx.run_py), with
created_at written the way the server writes it (isoformat) and file ages set with
utime. The default, report-only sweeper is proven first; deletion is then switched
on through the database setting, as the operator would, to prove the removal.

Not provable here (see the final report): the browser rendering of a deleted
image, and what the chat page shows to a member after the file disappears.
"""
import asyncio
import json
import os
from pathlib import Path

import aiohttp

PW = "uploads-admin-pass-1234"

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\xc9\xfe\x92\xef\x00\x00\x00\x00IEND\xaeB`\x82")

HEAD = '''
import asyncio, json, os, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from database import db, encrypt_message
P = json.loads(%r)
out = {}

async def main():
    global out
    await db.connect()
'''
TAIL = '''
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def snippet(body, **params):
    indented = "\n".join("    " + line if line.strip() else line for line in body.strip("\n").splitlines())
    return HEAD % json.dumps(params) + indented + "\n" + TAIL


SETUP = '''
from auth import create_user
u = await create_user("up_admin", P["pw"], is_admin=True)
await db.set_user_role(u["id"], "superadmin")
o = await create_user("up_other", P["pw"])
ch = await db.create_chat_channel("up-room", created_by=u["id"])
conv = await db.create_dm_conversation(u["id"], [o["id"]])
await db.set_setting("retention_chat_days", "7")
await db.set_setting("retention_dm_days", "30")
out = {"uid": u["id"], "ch": ch, "conv": conv["id"], "dir": str(db.chat_upload_dir)}
'''

# Rows and files for the retention run and the sweeper.
PLANT = '''
up = Path(db.chat_upload_dir)
now = time.time()
uid, ch, conv = P["uid"], P["ch"], P["conv"]
outside = Path(os.getcwd()) / "smoke_uploads_outside.txt"
outside.write_text("must survive")

def mk(age_h=0, size=100, ext=".png"):
    name = os.urandom(16).hex() + ext
    (up / name).write_bytes(b"x" * size)
    if age_h:
        t = now - age_h * 3600
        os.utime(up / name, (t, t))
    return name

def link(age_h=0):
    name = os.urandom(16).hex() + ".png"
    os.symlink(outside, up / name)
    if age_h:
        t = now - age_h * 3600
        os.utime(up / name, (t, t), follow_symlinks=False)
    return name

def iso(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

URL = "/static/uploads/chat/"

async def chat(days, text="planted", image=None, att=None, pinned=0):
    cur = await db.conn.execute(
        "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url, attachment_url, is_pinned) "
        "VALUES (?, ?, 'up_admin', ?, ?, ?, ?, ?)",
        (ch, uid, encrypt_message(text), iso(days), image, att, pinned))
    await db.conn.commit()
    return cur.lastrowid

async def dm(days, image=None, att=None):
    cur = await db.conn.execute(
        "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at, image_url, attachment_url) "
        "VALUES (?, ?, 'up_admin', ?, ?, ?, ?)",
        (conv, uid, encrypt_message("planted dm"), iso(days), image, att))
    await db.conn.commit()
    return cur.lastrowid

f_old, f_att = mk(size=100), mk(size=40, ext=".pdf")
f_pin, f_shared, f_dm, f_dm_kept = mk(), mk(), mk(size=60), mk()
f_link = link()
o_young, o_old = mk(age_h=1), mk(age_h=48, size=77)
o_text, o_dm_col, o_link, o_odd = mk(age_h=48), mk(age_h=48), link(age_h=48), "notes.txt"
(up / o_odd).write_text("hand placed")
t = now - 48 * 3600
os.utime(up / o_odd, (t, t))
o_dir = os.urandom(16).hex()
(up / o_dir).mkdir()
os.utime(up / o_dir, (t, t))

out["rows"] = {
    "old": await chat(40, image=URL + f_old),
    "old_att": await chat(40, att=URL + f_att),
    "pinned": await chat(40, image=URL + f_pin, pinned=1),
    "shared_old": await chat(40, image=URL + f_shared),
    "shared_new": await chat(0, att=URL + f_shared),
    "link": await chat(40, image=URL + f_link),
    "crafted": await chat(40, image=URL + "../smoke_uploads_outside.txt"),
    "pasted": await chat(0, text="see https://portal.example" + URL + o_text + " here"),
    "dm_old": await dm(90, image=URL + f_dm),
    "dm_shared_old": await dm(90, att=URL + f_dm_kept),
    "dm_keeps_orphan": await dm(0, image=URL + o_dm_col),
}
cur = await db.conn.execute("INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
                            "VALUES (?, ?, 'up_admin', ?, ?, ?)", (ch, uid, encrypt_message("keeps dm file"), iso(0), URL + f_dm_kept))
await db.conn.commit()
out["files"] = {"old": f_old, "att": f_att, "pin": f_pin, "shared": f_shared, "dm": f_dm, "dm_kept": f_dm_kept,
                "link": f_link, "young": o_young, "orphan": o_old, "text": o_text, "dm_col": o_dm_col,
                "orphan_link": o_link, "odd": o_odd, "dir": o_dir}
out["outside"] = str(outside)
'''

# Old messages whose files a surviving row names only in its (encrypted) text.
PLANT_TEXT = '''
up = Path(db.chat_upload_dir)
uid, ch, conv = P["uid"], P["ch"], P["conv"]
URL = "/static/uploads/chat/"

def iso(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def mk(size):
    name = os.urandom(16).hex() + ".png"
    (up / name).write_bytes(b"x" * size)
    return name

async def chat(days, text, image=None, pinned=0):
    cur = await db.conn.execute(
        "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url, is_pinned) "
        "VALUES (?, ?, 'up_admin', ?, ?, ?, ?)", (ch, uid, encrypt_message(text), iso(days), image, pinned))
    await db.conn.commit()
    return cur.lastrowid

async def dm(days, text):
    cur = await db.conn.execute(
        "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) "
        "VALUES (?, ?, 'up_admin', ?, ?)", (conv, uid, encrypt_message(text), iso(days)))
    await db.conn.commit()
    return cur.lastrowid

x_dm, y_pin, z_plain = mk(11), mk(13), mk(17)
out["rows"] = {
    "x_old": await chat(40, "old with image", image=URL + x_dm),
    "x_dm": await dm(10, "look at " + URL + x_dm),
    "y_old": await chat(40, "old with image", image=URL + y_pin),
    "y_pin": await chat(40, "pinned, links " + URL + y_pin, pinned=1),
    "z_old": await chat(40, "old with image", image=URL + z_plain),
}
out["files"] = {"x": x_dm, "y": y_pin, "z": z_plain}
'''

# An old message whose file nothing else names, an unreadable DM row, orphans named
# only in other free-text fields, and one plain orphan.
PLANT_SKIP = '''
up = Path(db.chat_upload_dir)
uid, ch, conv = P["uid"], P["ch"], P["conv"]
URL = "/static/uploads/chat/"
now = time.time()

def mk(age_h=0, size=10):
    name = os.urandom(16).hex() + ".png"
    (up / name).write_bytes(b"x" * size)
    if age_h:
        t = now - age_h * 3600
        os.utime(up / name, (t, t))
    return name

f_msg = mk(48, 21)
f_status, f_topic, f_poll, f_stream = mk(48), mk(48), mk(48), mk(48)
f_plain = mk(48, 33)
old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
await db.conn.execute(
    "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
    "VALUES (?, ?, 'up_admin', ?, ?, ?)", (ch, uid, encrypt_message("old"), old, URL + f_msg))
cur = await db.conn.execute(
    "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) VALUES (?, ?, 'up_admin', ?, ?)",
    (conv, uid, "gAAAAAB" + "A" * 80, datetime.now(timezone.utc).isoformat()))
bad = cur.lastrowid
await db.conn.execute("UPDATE users SET status_message = ? WHERE id = ?", ("see " + URL + f_status, uid))
await db.conn.execute("UPDATE chat_channels SET topic = ? WHERE id = ?", ("topic " + URL + f_topic, ch))
await db.conn.execute(
    "INSERT INTO chat_polls (channel_id, user_id, question, options) VALUES (?, ?, ?, ?)",
    (ch, uid, encrypt_message("poll " + URL + f_poll), encrypt_message('["a", "b"]')))
await db.conn.execute(
    "INSERT INTO user_streams (user_id, name, stream_key, description) VALUES (?, 'up-stream', 'up-key', ?)",
    (uid, "about " + URL + f_stream))
await db.set_setting("chat_orphan_sweep_delete", "true")
await db.conn.commit()
out = {"bad": bad, "msg": f_msg, "status": f_status, "topic": f_topic, "poll": f_poll, "stream": f_stream,
       "plain": f_plain}
'''

STATE = '''
out = {}
for t in ("chat_messages", "dm_messages"):
    cur = await db.conn.execute("SELECT id FROM " + t)
    out[t] = [r["id"] for r in await cur.fetchall()]
cur = await db.conn.execute("SELECT value FROM settings WHERE key = 'chat_orphan_sweep_delete'")
r = await cur.fetchone()
out["flag"] = r["value"] if r else None
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def _chat_errors(body):
    """The cleanup errors that concern chat messages, DMs and their files. Other parts of
    the run (metrics, recordings, service logs...) work on whatever a production copy holds
    and are not what this module checks."""
    return [e for e in (body.get("errors") or []) if str(e).startswith(("chat", "dm"))]


async def _ws_join(sess, ctx, channel_id):
    ws = await sess.ws_connect(ctx.base_url.replace("https", "wss") + "/ws/chat")
    await ws.send_json({"type": "join", "channel_id": channel_id})
    async with asyncio.timeout(15):
        while True:
            m = await ws.receive_json()
            if m.get("type") == "channel_info":
                return ws


async def _send(ws, text, **extra):
    await ws.send_json({"type": "message", "message": text, **extra})
    async with asyncio.timeout(15):
        while True:
            m = await ws.receive_json()
            if m.get("type") == "message" and m.get("message") == text:
                return m["id"]
            if m.get("type") == "error":
                return None


async def _delete(ws, message_id):
    await ws.send_json({"type": "delete", "message_id": message_id})
    async with asyncio.timeout(15):
        while True:
            m = await ws.receive_json()
            if m.get("type") == "message_deleted" and m.get("message_id") == message_id:
                return True


async def _upload(sess, ctx, ctype="image/png", name="a.png", data=PNG):
    form = aiohttp.FormData()
    form.add_field("image", data, filename=name, content_type=ctype)
    r = await sess.post(ctx.base_url + "/api/chat/upload", data=form)
    body = await r.json(content_type=None)
    return r.status, body


async def run(ctx):
    rc, out = await ctx.run_py(snippet(SETUP, pw=PW))
    ids = _result(out)
    ctx.ok("uploads: test users, channel and DM conversation created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    up = Path(ids["dir"])

    async with ctx.http() as sess:
        resp = await ctx.login(sess, "up_admin", PW)
        if resp.status != 200:
            ctx.ok("uploads: test admin can log in", False, f"status {resp.status}")
            return

        # --- Real upload, real WebSocket send and delete of single messages
        st1, b1 = await _upload(sess, ctx)
        st2, b2 = await _upload(sess, ctx)
        st3, b3 = await _upload(sess, ctx, "application/pdf", "doc.pdf", b"%PDF-1.4 smoke")
        ok_up = st1 == st2 == st3 == 200 and all(b.get("url", "").startswith("/static/uploads/chat/") for b in (b1, b2, b3))
        ctx.ok("uploads: three files uploaded through POST /api/chat/upload", ok_up, f"{st1} {st2} {st3}")
        if not ok_up:
            return
        shared, solo, doc = (Path(b["url"]).name for b in (b1, b2, b3))
        ctx.ok("uploads: the files are in the chat upload folder", all((up / n).is_file() for n in (shared, solo, doc)))

        ws = await _ws_join(sess, ctx, ids["ch"])
        try:
            m1 = await _send(ws, "smoke shared one", image_url=b1["url"])
            m2 = await _send(ws, "smoke shared two", attachment_url=b1["url"], attachment_name="a.png",
                             attachment_type="image/png")
            m3 = await _send(ws, "smoke solo", image_url=b2["url"])
            m4 = await _send(ws, "smoke doc", attachment_url=b3["url"], attachment_name="doc.pdf",
                             attachment_type="application/pdf")
            ctx.ok("uploads: four messages with files sent over the chat socket", all((m1, m2, m3, m4)),
                   str((m1, m2, m3, m4)))
            await _delete(ws, m1)
            ctx.ok("uploads: deleting one of two messages that name a file keeps the file", (up / shared).is_file())
            await _delete(ws, m3)
            ctx.ok("uploads: deleting the only message that names a file removes the file", not (up / solo).exists())
            await _delete(ws, m4)
            ctx.ok("uploads: deleting a message with an attachment removes the attachment file", not (up / doc).exists())
            await _delete(ws, m2)
            ctx.ok("uploads: the file goes with the last message that names it", not (up / shared).exists())
        finally:
            await ws.close()

        # --- Retention run on planted data
        rc, out = await ctx.run_py(snippet(PLANT, **ids))
        planted = _result(out)
        ctx.ok("uploads: old rows, shared files, links and orphans planted", rc == 0 and bool(planted), out[-400:])
        if not planted:
            return
        f, rows = planted["files"], planted["rows"]
        outside = Path(planted["outside"])

        r = await sess.get(ctx.base_url + "/api/admin/retention")
        cfg = await r.json()
        ctx.ok("uploads: the sweeper switch is not part of the retention settings",
               "chat_orphan_sweep_delete" not in cfg, str(sorted(cfg))[:200])
        r = await sess.put(ctx.base_url + "/api/admin/retention", json={"chat_orphan_sweep_delete": "true"})
        await r.read()
        rc, out = await ctx.run_py(snippet(STATE))
        ctx.ok("uploads: the retention API cannot switch orphan deletion on", (_result(out) or {}).get("flag") is None,
               out[-200:])

        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        d = body.get("deleted", {})
        sweep = d.get("chat_orphan_sweep", {})
        # On a production copy the run also removes that copy's own old rows, so the counts
        # are "at least" what this check planted; its own rows and files are asserted below.
        ctx.ok("uploads: the manual cleanup run succeeds without chat or DM errors",
               r.status == 200 and not _chat_errors(body), str(body)[:300])
        ctx.ok("uploads: the run reports at least the chat messages removed (old ones only, pinned and shared-with-newer kept)",
               (d.get("chat_messages") or 0) >= 5 and (d.get("dm_messages") or 0) >= 2, str(d)[:300])
        ctx.ok("uploads: the run reports at least the files and bytes removed with the messages",
               (d.get("chat_files") or 0) >= 3 and (d.get("chat_file_bytes") or 0) >= 200, str(d)[:300])
        rc, out = await ctx.run_py(snippet(STATE))
        state = _result(out) or {}
        ctx.ok("uploads: an old message loses its row and its image file",
               not (up / f["old"]).exists() and rows["old"] not in state.get("chat_messages", []))
        ctx.ok("uploads: an old message with an attachment loses its attachment file", not (up / f["att"]).exists())
        ctx.ok("uploads: a pinned message keeps its row and its file",
               rows["pinned"] in state.get("chat_messages", []) and (up / f["pin"]).is_file())
        ctx.ok("uploads: a file named by an old and a newer message survives deleting the old one",
               rows["shared_old"] not in state.get("chat_messages", []) and rows["shared_new"] in state.get("chat_messages", [])
               and (up / f["shared"]).is_file())
        ctx.ok("uploads: an old DM loses its file, a DM file also named by a chat message stays",
               not (up / f["dm"]).exists() and (up / f["dm_kept"]).is_file()
               and rows["dm_old"] not in state.get("dm_messages", []))
        ctx.ok("uploads: a row naming a symlink, and one with a ../ URL, delete nothing outside the folder",
               os.path.islink(up / f["link"]) and outside.read_text() == "must survive"
               and rows["link"] not in state.get("chat_messages", []) and rows["crafted"] not in state.get("chat_messages", []))

        ctx.ok("uploads: the sweep in the default mode only reports", sweep.get("report_only") is True
               and sweep.get("deleted") == 0, str(sweep)[:300])
        ctx.ok("uploads: the report finds exactly the old unreferenced file, with its size",
               sweep.get("orphans") == 1 and sweep.get("names") == [f["orphan"]] and sweep.get("bytes") == 77, str(sweep)[:300])
        ctx.ok("uploads: report-only mode leaves the old orphan on disk", (up / f["orphan"]).is_file())
        ctx.ok("uploads: an unreferenced file younger than 24 hours is not even reported", (up / f["young"]).is_file()
               and f["young"] not in sweep.get("names", []))
        ctx.ok("uploads: files named only in a message text or a DM column are not orphans",
               (up / f["text"]).is_file() and (up / f["dm_col"]).is_file())
        ctx.ok("uploads: links, folders and foreign names in the folder are never touched",
               os.path.islink(up / f["orphan_link"]) and (up / f["odd"]).is_file() and (up / f["dir"]).is_dir()
               and outside.read_text() == "must survive")

        # --- Deletion switched on (as an operator would, in the database)
        await ctx.run_py(snippet('await db.set_setting("chat_orphan_sweep_delete", "true")'))
        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        sweep = body.get("deleted", {}).get("chat_orphan_sweep", {})
        ctx.ok("uploads: with deletion on, the old orphan is removed and counted",
               r.status == 200 and sweep.get("report_only") is False and sweep.get("deleted") == 1
               and sweep.get("deleted_bytes") == 77 and not (up / f["orphan"]).exists(), str(sweep)[:300])
        ctx.ok("uploads: with deletion on, everything else is still there",
               all(os.path.lexists(up / f[k]) for k in ("young", "text", "dm_col", "orphan_link", "odd", "dir", "pin", "shared", "dm_kept"))
               and outside.read_text() == "must survive")
        await ctx.run_py(snippet('await db.delete_setting("chat_orphan_sweep_delete")'))

        # --- Files that a surviving row names only in its text
        rc, out = await ctx.run_py(snippet(PLANT_TEXT, **ids))
        pt = _result(out)
        ctx.ok("uploads: old messages whose files are linked in surviving message text planted", rc == 0 and bool(pt),
               out[-400:])
        if not pt:
            return
        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        d = body.get("deleted", {})
        rc, out = await ctx.run_py(snippet(STATE))
        state = _result(out) or {}
        tf, tr = pt["files"], pt["rows"]
        ctx.ok("uploads: the cleanup run deletes the old rows that name those files",
               r.status == 200 and not _chat_errors(body) and all(
                   tr[k] not in state.get("chat_messages", []) for k in ("x_old", "y_old", "z_old")), str(body)[:300])
        ctx.ok("uploads: a file linked in the text of a surviving DM is kept",
               (up / tf["x"]).is_file() and tr["x_dm"] in state.get("dm_messages", []))
        ctx.ok("uploads: a file linked in the text of a pinned message is kept",
               (up / tf["y"]).is_file() and tr["y_pin"] in state.get("chat_messages", []))
        ctx.ok("uploads: a file nothing names any more is still removed (the two files that are still named stay)",
               not (up / tf["z"]).exists() and (d.get("chat_files") or 0) >= 1 and (d.get("chat_file_bytes") or 0) >= 17
               and (up / tf["x"]).is_file() and (up / tf["y"]).is_file(), str(d)[:300])

        # --- Member text that looks like an unreadable message must not switch cleanup off
        ws = await _ws_join(sess, ctx, ids["ch"])
        try:
            looks = [await _send(ws, t) for t in ("gAAAAAB hi", "[Message could not be decrypted]", "hello")]
        finally:
            await ws.close()
        ctx.ok("uploads: three ordinary messages whose text looks unreadable were posted over the chat socket",
               all(looks), str(looks))
        rc, out = await ctx.run_py(snippet('''
up = Path(db.chat_upload_dir)
name = os.urandom(16).hex() + ".png"
(up / name).write_bytes(b"x" * 31)
t = time.time() - 48 * 3600
os.utime(up / name, (t, t))
await db.set_setting("chat_orphan_sweep_delete", "true")
out = {"name": name}
'''))
        lk = _result(out)
        ctx.ok("uploads: an old orphan planted and deletion switched on", rc == 0 and bool(lk), out[-300:])
        if not lk:
            return
        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        sweep = body.get("deleted", {}).get("chat_orphan_sweep", {})
        ctx.ok("uploads: those messages do not make the sweep skip, and the old orphan is removed",
               r.status == 200 and not sweep.get("skipped") and lk["name"] in (sweep.get("names") or [])
               and not (up / lk["name"]).exists(), str(sweep)[:300])
        await ctx.run_py(snippet('await db.delete_setting("chat_orphan_sweep_delete")'))

        # --- A skipped cleanup is reported, never silent
        rc, out = await ctx.run_py(snippet(PLANT_SKIP, **ids))
        ps = _result(out)
        ctx.ok("uploads: an old message, an unreadable DM row and files named in other text fields planted",
               rc == 0 and bool(ps), out[-400:])
        if not ps:
            return
        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        d = body.get("deleted", {})
        sweep = d.get("chat_orphan_sweep", {})
        ctx.ok("uploads: with an unreadable message the run says no chat upload file was removed, and why",
               r.status == 200 and bool(d.get("chat_files_skipped")) and d.get("chat_files") == 0
               and (up / ps["msg"]).is_file(), str(d)[:300])
        ctx.ok("uploads: with an unreadable message the sweep says it was skipped, and removes nothing",
               bool(sweep.get("skipped")) and sweep.get("deleted") == 0 and (up / ps["plain"]).is_file(), str(sweep)[:300])
        await ctx.run_py(snippet('await db.conn.execute("DELETE FROM dm_messages WHERE id = ?", (P["bad"],))\n'
                                 'await db.conn.commit()', bad=ps["bad"]))
        r = await sess.post(ctx.base_url + "/api/admin/retention/run")
        body = await r.json()
        d = body.get("deleted", {})
        sweep = d.get("chat_orphan_sweep", {})
        ctx.ok("uploads: once the unreadable row is gone the sweep runs, with no skip reasons",
               r.status == 200 and not d.get("chat_files_skipped") and not sweep.get("skipped"), str(d)[:300])
        ctx.ok("uploads: files named in a status message, channel topic, poll or stream description are kept",
               all((up / ps[k]).is_file() for k in ("status", "topic", "poll", "stream")))
        ctx.ok("uploads: the old orphan nothing names, and the file of the deleted message, are removed",
               not (up / ps["plain"]).exists() and not (up / ps["msg"]).exists()
               and sweep.get("deleted", 0) + d.get("chat_files", 0) >= 2 and sweep.get("deleted", 0) >= 1,
               str(d)[:300])
        r = await sess.get(ctx.base_url + "/admin")
        page = await r.text()
        ctx.ok("uploads: the admin page shows both skip reasons in the cleanup summary",
               r.status == 200 and "d.chat_files_skipped" in page and "sweep.skipped" in page)
        await ctx.run_py(snippet('await db.delete_setting("chat_orphan_sweep_delete")'))
