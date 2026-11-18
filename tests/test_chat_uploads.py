"""Chat upload files: deleted with their messages (retention, clear, single delete),
kept while any surviving row still refers to them, and the orphan sweeper.

Run: venv/bin/python tests/test_chat_uploads.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""

import asyncio
import json
import logging
import os
import sqlite3
import sys
import tempfile
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database  # noqa: E402
import chat_uploads  # noqa: E402

URL = "/static/uploads/chat/"


def run_with_db(body):
    """Run body(db, upload_dir, tmp) with the upload directory inside a temp tree."""
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            d = Database(str(tmp / "t.db"))
            await d.connect()
            up = tmp / "static" / "uploads" / "chat"
            up.mkdir(parents=True)
            d.chat_upload_dir = str(up)
            try:
                await body(d, up, tmp)
            finally:
                await d.close()
    asyncio.run(go())


_n = [0]


def new_name(ext=".png"):
    _n[0] += 1
    return f"{_n[0]:032x}{ext}"


def make_file(up, name=None, size=10, age_hours=0):
    name = name or new_name()
    p = up / name
    p.write_bytes(b"x" * size)
    if age_hours:
        t = time.time() - age_hours * 3600
        os.utime(p, (t, t))
    return name


async def setup_ids(d):
    uid = await d.create_user("up_user", "x")
    ch = await d.create_chat_channel("up-room", created_by=uid)
    conv = await d.create_dm_conversation(uid, [await d.create_user("up_other", "x")])
    return uid, ch, conv["id"]


async def age_rows(d, table, days):
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    await d.conn.execute(f"UPDATE {table} SET created_at = ?", (old,))
    await d.conn.commit()


async def msg(d, ch, uid, name=None, text="hi", att=False, image=True):
    kw = {}
    if name:
        if image:
            kw["image_url"] = URL + name
        if att:
            kw["attachment_url"] = URL + name
    return await d.create_chat_message(ch, uid, "up_user", text, **kw)


async def ids(d, table):
    cur = await d.conn.execute(f"SELECT id FROM {table}")
    return {r["id"] for r in await cur.fetchall()}


def exists(up, name):
    return os.path.lexists(up / name)


def raw(d, sql, params=()):
    """A write by another connection, as another process or thread would make it."""
    conn = sqlite3.connect(d.db_path, timeout=10)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def insert_chat_row(d, ch, uid, text="late", image_url=None):
    from database import encrypt_message
    raw(d, "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
           "VALUES (?, ?, 'u', ?, ?, ?)",
        (ch, uid, encrypt_message(text), datetime.now(timezone.utc).isoformat(), image_url))


async def with_write_after_scan(d, write, coro_or_none=None, func=None):
    """Run the awaitable `coro_or_none` (already created) so that `write()` happens
    in the worker thread right after the text scan returned: the window the final
    check has to cover."""
    real = chat_uploads.scan_text_sync

    def scan_then_write(*a, **kw):
        result = real(*a, **kw)
        write()
        return result

    chat_uploads.scan_text_sync = scan_then_write
    try:
        return await coro_or_none
    finally:
        chat_uploads.scan_text_sync = real


# ---------------------------------------------------------------------------
# Rows deleted: files go with them, after the commit
# ---------------------------------------------------------------------------

def test_retention_removes_old_message_row_and_file():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        old_img, old_att, keep = make_file(up, size=7), make_file(up, size=5), make_file(up)
        await msg(d, ch, uid, old_img)
        await msg(d, ch, uid, old_att, att=True, image=False)
        await age_rows(d, "chat_messages", 30)
        fresh = await msg(d, ch, uid, keep)
        stats = {}
        n = await d.cleanup_old_chat_messages(days=7, stats=stats)
        assert n == 2, n
        assert not exists(up, old_img) and not exists(up, old_att)
        assert exists(up, keep) and fresh in await ids(d, "chat_messages")
        assert stats == {"files": 2, "bytes": 12}, stats
    run_with_db(body)


def test_retention_keeps_pinned_message_and_its_file():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        mid = await msg(d, ch, uid, name)
        await d.pin_message(mid, uid)
        await age_rows(d, "chat_messages", 30)
        assert await d.cleanup_old_chat_messages(days=7, stats={}) == 0
        assert exists(up, name) and mid in await ids(d, "chat_messages")
    run_with_db(body)


def test_file_shared_by_two_messages_survives_deleting_one():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        old = await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        await msg(d, ch, uid, name)          # a fresh message re-uses the same upload
        stats = {}
        assert await d.cleanup_old_chat_messages(days=7, stats=stats) == 1
        assert old not in await ids(d, "chat_messages")
        assert exists(up, name) and stats["files"] == 0 and stats["bytes"] == 0, stats
    run_with_db(body)


def test_file_shared_between_channel_and_dm_survives():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        await d.create_dm_message(conv, uid, "up_user", "hi", attachment_url=URL + name)
        await d.cleanup_old_chat_messages(days=7, stats={})
        assert exists(up, name)
        # the other direction: the DM expires, the channel message survives
        name2 = make_file(up)
        await d.create_dm_message(conv, uid, "up_user", "old", image_url=URL + name2)
        await age_rows(d, "dm_messages", 90)
        await msg(d, ch, uid, name2, att=True, image=False)
        await d.cleanup_old_dm_messages(days=30, stats={})
        assert exists(up, name2)
    run_with_db(body)


def test_dm_retention_removes_file():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        a, b = make_file(up, size=3), make_file(up, size=4)
        await d.create_dm_message(conv, uid, "up_user", "x", image_url=URL + a)
        await d.create_dm_message(conv, uid, "up_user", "y", attachment_url=URL + b)
        await age_rows(d, "dm_messages", 90)
        stats = {}
        assert await d.cleanup_old_dm_messages(days=30, stats=stats) == 2
        assert not exists(up, a) and not exists(up, b)
        assert stats == {"files": 2, "bytes": 7}, stats
    run_with_db(body)


def test_clear_channel_removes_files_in_batches():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        other = await d.create_chat_channel("up-other", created_by=uid)
        names = [make_file(up, size=1) for _ in range(1100)]
        for i, name in enumerate(names):
            await d.conn.execute(
                "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
                "VALUES (?, ?, 'u', 'x', ?, ?)", (ch, uid, "2026-01-01T00:00:00+00:00", URL + name))
        kept = make_file(up)
        await d.conn.commit()
        await msg(d, other, uid, kept)
        stats = {}
        assert await d.clear_channel_messages(ch, stats=stats) == 1100
        assert not any(exists(up, n) for n in names)
        assert exists(up, kept)
        assert stats == {"files": 1100, "bytes": 1100}, stats
    run_with_db(body)


def test_clear_channel_keeps_file_used_in_another_channel():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        other = await d.create_chat_channel("up-other", created_by=uid)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await msg(d, other, uid, name)
        assert await d.clear_channel_messages(ch) == 1
        assert exists(up, name)
    run_with_db(body)


def test_single_delete_keeps_shared_file_and_removes_sole_file():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        shared, solo = make_file(up), make_file(up)
        m1 = await msg(d, ch, uid, shared)
        m2 = await msg(d, ch, uid, shared)
        m3 = await msg(d, ch, uid, solo)
        assert await d.delete_chat_message(m1)
        assert exists(up, shared)
        assert await d.delete_chat_message(m3, user_id=uid)
        assert not exists(up, solo)
        assert not await d.delete_chat_message(m3)       # already gone
        assert await d.delete_chat_message(m2)
        assert not exists(up, shared)                    # last reference gone
        dm_shared = make_file(up)
        d1 = await d.create_dm_message(conv, uid, "up_user", "a", image_url=URL + dm_shared)
        d2 = await d.create_dm_message(conv, uid, "up_user", "b", attachment_url=URL + dm_shared)
        assert await d.delete_dm_message(d1)
        assert exists(up, dm_shared)
        assert await d.delete_dm_message(d2, user_id=uid)
        assert not exists(up, dm_shared)
    run_with_db(body)


def test_single_delete_by_wrong_owner_keeps_row_and_file():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        mid = await msg(d, ch, uid, name)
        assert not await d.delete_chat_message(mid, user_id=uid + 99)
        assert exists(up, name) and mid in await ids(d, "chat_messages")
    run_with_db(body)


def test_files_are_unlinked_only_after_the_commit():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        mid = await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        seen = {}
        real = chat_uploads.unlink_names

        def spy(dir_path, names, older_than=None):
            # a separate connection only sees committed data
            con = sqlite3.connect(str(tmp / "t.db"))
            seen["rows"] = con.execute("SELECT COUNT(*) FROM chat_messages WHERE id = ?", (mid,)).fetchone()[0]
            con.close()
            seen["file_still_there"] = exists(up, name)
            return real(dir_path, names, older_than=older_than)

        chat_uploads.unlink_names = spy
        try:
            await d.cleanup_old_chat_messages(days=7, stats={})
        finally:
            chat_uploads.unlink_names = real
        assert seen == {"rows": 0, "file_still_there": True}, seen
        assert not exists(up, name)
    run_with_db(body)


# ---------------------------------------------------------------------------
# Containment: only plain generated names, never symlinks, never outside
# ---------------------------------------------------------------------------

def test_crafted_urls_symlinks_and_odd_names_are_never_touched():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        outside = tmp / "outside.txt"
        outside.write_text("must survive")
        link = new_name()
        os.symlink(outside, up / link)                 # a link with a generated-looking name
        odd = "notes.txt"                              # not a generated name
        (up / odd).write_text("hand placed")
        sub = up / ("d" * 32)
        sub.mkdir()
        (sub / "inner.png").write_text("inner")
        (tmp / "static" / "uploads" / "sibling.png").write_text("sibling")
        urls = [URL + link, URL + odd, URL + sub.name, URL + "../sibling.png",
                "/static/uploads/chat/../../uploads/sibling.png", "/static/uploads/emotes/x.png",
                "https://elsewhere.example/" + new_name(), URL, URL + "a/b.png"]
        for u in urls:
            await d.conn.execute(
                "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
                "VALUES (?, ?, 'u', 'x', '2026-01-01T00:00:00+00:00', ?)", (ch, uid, u))
        await d.conn.commit()
        stats = {}
        assert await d.cleanup_old_chat_messages(days=7, stats=stats) == len(urls)
        assert os.path.islink(up / link) and outside.read_text() == "must survive"
        assert (up / odd).exists() and (sub / "inner.png").exists()
        assert (tmp / "static" / "uploads" / "sibling.png").exists()
        assert stats == {"files": 0, "bytes": 0}, stats
    run_with_db(body)


def test_upload_directory_that_is_a_symlink_is_left_alone():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        real = tmp / "elsewhere"
        real.mkdir()
        name = make_file(real, new_name())
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        link = tmp / "linked_chat"
        os.symlink(real, link)
        d.chat_upload_dir = str(link)
        stats = {}
        assert await d.cleanup_old_chat_messages(days=7, stats=stats) == 1     # the row still goes
        assert (real / name).exists() and stats == {"files": 0, "bytes": 0}
        make_file(real, new_name(), age_hours=100)
        rep = await d.sweep_orphan_chat_uploads(delete=True)
        assert rep.get("skipped") and len(list(real.iterdir())) == 2, rep
    run_with_db(body)


# ---------------------------------------------------------------------------
# Orphan sweeper
# ---------------------------------------------------------------------------

def test_sweeper_grace_period_and_report_only_default():
    async def body(d, up, tmp):
        young = make_file(up, age_hours=23)
        old = make_file(up, size=9, age_hours=25)
        rep = await d.sweep_orphan_chat_uploads()       # default: report only
        assert rep["report_only"] is True and rep["orphans"] == 1 and rep["bytes"] == 9, rep
        assert rep["names"] == [old] and rep["deleted"] == 0, rep
        assert exists(up, young) and exists(up, old)
        await d.set_setting("chat_orphan_sweep_delete", "false")
        rep = await d.sweep_orphan_chat_uploads()
        assert exists(up, old) and rep["deleted"] == 0
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await d.sweep_orphan_chat_uploads()
        assert rep["report_only"] is False and rep["deleted"] == 1 and rep["deleted_bytes"] == 9, rep
        assert exists(up, young) and not exists(up, old)
    run_with_db(body)


def test_sweeper_never_deletes_without_grace_even_when_asked():
    async def body(d, up, tmp):
        fresh = make_file(up)
        rep = await d.sweep_orphan_chat_uploads(delete=True)
        assert exists(up, fresh) and rep["orphans"] == 0, rep
        # no argument can shorten the grace
        try:
            await d.sweep_orphan_chat_uploads(delete=True, grace_seconds=0)
        except TypeError:
            pass
        else:
            raise AssertionError("grace_seconds must not be a parameter")
        assert exists(up, fresh)
    run_with_db(body)


def test_sweeper_keeps_referenced_files_in_every_place_a_url_can_live():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        by_chat_img = make_file(up, age_hours=48)
        by_chat_att = make_file(up, age_hours=48)
        by_dm_img = make_file(up, age_hours=48)
        by_dm_att = make_file(up, age_hours=48)
        by_pinned = make_file(up, age_hours=48)
        by_text = make_file(up, age_hours=48)
        by_text_dot = make_file(up, age_hours=48)
        by_preview = make_file(up, age_hours=48)
        orphan = make_file(up, age_hours=48)
        await msg(d, ch, uid, by_chat_img)
        await msg(d, ch, uid, by_chat_att, att=True, image=False)
        await d.create_dm_message(conv, uid, "up_user", "x", image_url=URL + by_dm_img)
        await d.create_dm_message(conv, uid, "up_user", "x", attachment_url=URL + by_dm_att)
        pin = await msg(d, ch, uid, by_pinned)
        await d.pin_message(pin, uid)
        await age_rows(d, "chat_messages", 400)
        # a URL only in the (encrypted) text, one with a sentence dot after it, one in a reply preview
        await d.create_chat_message(ch, uid, "u", f"look https://portal.example{URL}{by_text} nice")
        await d.create_dm_message(conv, uid, "u", f"see {URL}{by_text_dot[:-4]}.png.")
        await d.create_chat_message(ch, uid, "u", "re", reply_preview_text=f"was {URL}{by_preview}")
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await d.sweep_orphan_chat_uploads()
        assert rep["orphans"] == 1 and rep["names"] == [orphan], rep
        for n in (by_chat_img, by_chat_att, by_dm_img, by_dm_att, by_pinned, by_text, by_text_dot, by_preview):
            assert exists(up, n), n
        assert not exists(up, orphan)
    run_with_db(body)


def test_sweeper_does_nothing_when_a_message_cannot_be_decrypted():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up, age_hours=48)
        await d.conn.execute(
            "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at) "
            "VALUES (?, ?, 'u', ?, '2026-01-01T00:00:00+00:00')", (ch, uid, "gAAAAAB" + "A" * 80))
        await d.conn.commit()
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await d.sweep_orphan_chat_uploads()
        assert rep.get("skipped") and rep["deleted"] == 0 and exists(up, name), rep
    run_with_db(body)


def test_member_text_that_looks_unreadable_does_not_switch_cleanup_off():
    texts = ("hello", "gAAAAAB hi", "[Message could not be decrypted]")

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        await d.set_setting("chat_orphan_sweep_delete", "true")
        for text in texts:
            await msg(d, ch, uid, text=text)
            await d.conn.execute(
                "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) "
                "VALUES (?, ?, 'u', ?, ?)",
                (conv, uid, encrypt_text(text), datetime.now(timezone.utc).isoformat()))
        await d.conn.commit()
        orphan = make_file(up, age_hours=48)
        rep = await d.sweep_orphan_chat_uploads()
        assert not rep.get("skipped") and rep["orphans"] == 1 and rep["deleted"] == 1, (texts, rep)
        assert not exists(up, orphan)
        # the purge path decides the same way
        name = make_file(up)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        stats = {}
        await d.cleanup_old_chat_messages(days=7, stats=stats)
        assert not exists(up, name) and stats["files"] == 1, stats
    run_with_db(body)


def encrypt_text(text):
    from database import encrypt_message
    return encrypt_message(text)


def test_unreadable_stored_value_is_still_detected_by_the_stored_value():
    from database import decrypt_message_strict, MessageDecryptError
    broken = "gAAAAAB" + "A" * 80
    try:
        decrypt_message_strict(broken)
    except MessageDecryptError:
        pass
    else:
        raise AssertionError("an unreadable token must raise")
    assert decrypt_message_strict("plain") == "plain"
    assert decrypt_message_strict(encrypt_text("[Message could not be decrypted]")) == \
        "[Message could not be decrypted]"


def test_sweeper_ignores_links_directories_and_foreign_names():
    async def body(d, up, tmp):
        outside = tmp / "outside.bin"
        outside.write_text("keep")
        link = new_name()
        os.symlink(outside, up / link)
        t = time.time() - 100 * 3600
        os.utime(up / link, (t, t), follow_symlinks=False)
        sub = up / ("e" * 32)
        sub.mkdir()
        os.utime(sub, (t, t))
        (up / ".hidden").write_text("h")
        (up / "readme.txt").write_text("r")
        (up / ("A" * 32 + ".png")).write_text("upper")
        for n in (".hidden", "readme.txt", "A" * 32 + ".png"):
            os.utime(up / n, (t, t))
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await d.sweep_orphan_chat_uploads()
        assert rep["orphans"] == 0 and rep["deleted"] == 0, rep
        assert os.path.islink(up / link) and outside.read_text() == "keep"
        assert sub.is_dir() and (up / ".hidden").exists() and (up / "readme.txt").exists()
    run_with_db(body)


def test_sweeper_report_lists_at_most_20_names_and_is_logged():
    async def body(d, up, tmp):
        for _ in range(25):
            make_file(up, size=2, age_hours=30)
        records = []

        class H(logging.Handler):
            def emit(self, r):
                records.append(r.getMessage())

        lg = logging.getLogger("portal.database")
        h = H()
        lg.addHandler(h)
        old_level = lg.level
        lg.setLevel(logging.INFO)
        try:
            rep = await d.sweep_orphan_chat_uploads()
        finally:
            lg.removeHandler(h)
            lg.setLevel(old_level)
        assert rep["orphans"] == 25 and rep["bytes"] == 50 and len(rep["names"]) == 20, rep
        text = "\n".join(records)
        assert "25" in text and "50" in text and rep["names"][0] in text, text
        assert rep["names"][-1] in text and "report only" in text.lower(), text
    run_with_db(body)


def test_sweeper_rechecks_references_just_before_unlinking():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up, age_hours=48)
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await with_write_after_scan(d, lambda: insert_chat_row(d, ch, uid, image_url=URL + name),
                                          d.sweep_orphan_chat_uploads())
        assert exists(up, name) and rep["deleted"] == 0 and rep["orphans"] == 0, rep
    run_with_db(body)


# ---------------------------------------------------------------------------
# Rows deleted while a surviving row names the file only in its (encrypted) text
# ---------------------------------------------------------------------------

def test_retention_keeps_file_linked_in_text_of_a_surviving_dm():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        await d.create_dm_message(conv, uid, "up_user", "look: " + URL + name)
        await age_rows(d, "dm_messages", 10)             # inside the 30 day DM retention
        stats = {}
        assert await d.cleanup_old_chat_messages(days=7, stats=stats) == 1
        assert exists(up, name) and stats["files"] == 0 and stats["bytes"] == 0, stats
    run_with_db(body)


def test_retention_keeps_file_linked_in_text_of_a_pinned_message():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        await msg(d, ch, uid, name)
        pinned = await msg(d, ch, uid, None, text="pinned link " + URL + name)
        await d.pin_message(pinned, uid)
        await age_rows(d, "chat_messages", 30)
        assert await d.cleanup_old_chat_messages(days=7, stats={}) == 1
        assert exists(up, name) and pinned in await ids(d, "chat_messages")
    run_with_db(body)


def test_file_linked_in_a_reply_preview_survives():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        await d.create_chat_message(ch, uid, "u", "re", reply_preview_text="was " + URL + name)
        assert await d.cleanup_old_chat_messages(days=7, stats={}) == 1
        assert exists(up, name)
    run_with_db(body)


def test_clear_channel_keeps_file_linked_in_text_of_another_channel():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        other = await d.create_chat_channel("up-other", created_by=uid)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await msg(d, other, uid, None, text="same file " + URL + name)
        assert await d.clear_channel_messages(ch) == 1
        assert exists(up, name)
    run_with_db(body)


def test_single_delete_keeps_file_linked_in_text_of_another_message():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name, dm_name = make_file(up), make_file(up)
        m1 = await msg(d, ch, uid, name)
        keeper = await msg(d, ch, uid, None, text="link " + URL + name)
        assert await d.delete_chat_message(m1)
        assert exists(up, name)
        assert exists(up, name) and keeper in await ids(d, "chat_messages")
        d1 = await d.create_dm_message(conv, uid, "up_user", "a", image_url=URL + dm_name)
        d2 = await d.create_dm_message(conv, uid, "up_user", "see " + URL + dm_name)
        assert await d.delete_dm_message(d1)
        assert exists(up, dm_name)
        assert exists(up, dm_name) and d2 in await ids(d, "dm_messages")
    run_with_db(body)


def test_purge_removes_nothing_when_a_message_cannot_be_decrypted():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        await d.conn.execute(
            "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) "
            "VALUES (?, ?, 'u', ?, ?)", (conv, uid, "gAAAAAB" + "A" * 80, datetime.now(timezone.utc).isoformat()))
        await d.conn.commit()
        stats = {}
        assert await d.cleanup_old_chat_messages(days=7, stats=stats) == 1     # the row is still deleted
        assert exists(up, name) and stats["files"] == 0 and stats["bytes"] == 0, stats
        assert "decrypt" in stats.get("skipped", ""), stats      # the admin is told why nothing was removed
    run_with_db(body)


def test_purge_reads_message_text_once_not_once_per_batch():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        names = [make_file(up, size=1) for _ in range(1100)]      # three batches of 500
        for name in names:
            await d.conn.execute(
                "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at, image_url) "
                "VALUES (?, ?, 'u', 'x', ?, ?)", (ch, uid, "2026-01-01T00:00:00+00:00", URL + name))
        await d.conn.commit()
        calls = []
        real = chat_uploads.scan_text_sync

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        chat_uploads.scan_text_sync = spy
        try:
            stats = {}
            assert await d.cleanup_old_chat_messages(days=7, stats=stats) == 1100
        finally:
            chat_uploads.scan_text_sync = real
        assert len(calls) == 1, calls
        assert stats == {"files": 1100, "bytes": 1100}, stats
        assert not any(exists(up, n) for n in names)
    run_with_db(body)


# ---------------------------------------------------------------------------
# Skipped cleanups are reported, not silent
# ---------------------------------------------------------------------------

def test_sweep_and_purge_report_why_nothing_was_removed():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up)
        old = make_file(up, age_hours=48)
        await msg(d, ch, uid, name)
        await age_rows(d, "chat_messages", 30)
        raw(d, "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) "
               "VALUES (?, ?, 'u', ?, ?)", (conv, uid, "gAAAAAB" + "A" * 80, datetime.now(timezone.utc).isoformat()))
        await d.set_setting("chat_orphan_sweep_delete", "true")
        rep = await d.sweep_orphan_chat_uploads()
        assert "decrypt" in rep.get("skipped", "") and exists(up, old), rep
        stats = {}
        await d.cleanup_old_chat_messages(days=7, stats=stats)
        assert "decrypt" in stats.get("skipped", "") and exists(up, name), stats
    run_with_db(body)


def test_skip_reason_reaches_the_manual_cleanup_response_and_the_admin_page():
    server_src = (Path(__file__).resolve().parent.parent / "server.py").read_text()
    admin_src = (Path(__file__).resolve().parent.parent / "static" / "admin.html").read_text()
    assert 'results["chat_files_skipped"]' in server_src
    assert "d.chat_files_skipped" in admin_src and "sweep.skipped" in admin_src


# ---------------------------------------------------------------------------
# The full-text scan runs in a worker thread; the legacy key is derived once
# ---------------------------------------------------------------------------

def test_text_scan_runs_off_the_event_loop():
    import threading
    import database

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        for i in range(5):
            await msg(d, ch, uid, text=f"m{i}")
        old = make_file(up, age_hours=48)
        main_thread = threading.get_ident()
        seen, ticks = set(), []

        def slow_decrypt(value):
            seen.add(threading.get_ident())
            time.sleep(0.05)
            return real(value)

        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(0.01)

        real = database.decrypt_message_strict
        database.decrypt_message_strict = slow_decrypt
        t = asyncio.create_task(ticker())
        try:
            rep = await d.sweep_orphan_chat_uploads(delete=False)
        finally:
            database.decrypt_message_strict = real
            t.cancel()
        assert rep["orphans"] == 1 and rep["names"] == [old], rep
        assert seen and main_thread not in seen, seen
        assert len(ticks) > 10, f"the event loop was blocked ({len(ticks)} ticks)"
    run_with_db(body)


def test_legacy_chat_key_is_derived_once_per_process():
    import database
    calls = []
    real_cls = database.PBKDF2HMAC

    class Counting:
        def __init__(self, *a, **kw):
            self.inner = real_cls(*a, **kw)

        def derive(self, secret):
            calls.append(1)
            return self.inner.derive(secret)

    database._legacy_chat_key_cache = None
    database.PBKDF2HMAC = Counting
    try:
        first = database._get_legacy_chat_key()
        for _ in range(20):
            assert database._get_legacy_chat_key() == first
    finally:
        database.PBKDF2HMAC = real_cls
    assert len(calls) == 1, calls


def test_legacy_encrypted_rows_decrypt_and_are_searched():
    import database
    from cryptography.fernet import Fernet

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up, age_hours=48)
        legacy = Fernet(database._get_legacy_chat_key()).encrypt(f"see {URL}{name}".encode()).decode()
        raw(d, "INSERT INTO chat_messages (channel_id, user_id, username, message, created_at) VALUES (?, ?, 'u', ?, ?)",
            (ch, uid, legacy, datetime.now(timezone.utc).isoformat()))
        rep = await d.sweep_orphan_chat_uploads(delete=True)
        assert rep["orphans"] == 0 and exists(up, name), rep
    run_with_db(body)


# ---------------------------------------------------------------------------
# Other free-text fields that can carry an upload URL
# ---------------------------------------------------------------------------

def _plant_raw(d, kind, ch, uid, text):
    from database import encrypt_message
    if kind == "poll_question":
        raw(d, "INSERT INTO chat_polls (channel_id, user_id, question, options) VALUES (?, ?, ?, ?)",
            (ch, uid, encrypt_message(text), encrypt_message('["a", "b"]')))
    elif kind == "poll_option":
        import json
        raw(d, "INSERT INTO chat_polls (channel_id, user_id, question, options) VALUES (?, ?, ?, ?)",
            (ch, uid, encrypt_message("q"), encrypt_message(json.dumps(["a", text]))))
    elif kind == "status":
        raw(d, "UPDATE users SET status_message = ? WHERE id = ?", (text, uid))
    elif kind == "topic":
        raw(d, "UPDATE chat_channels SET topic = ? WHERE id = ?", (text, ch))
    elif kind == "channel_description":
        raw(d, "UPDATE chat_channels SET description = ? WHERE id = ?", (text, ch))
    elif kind == "stream_name":
        raw(d, "INSERT INTO user_streams (user_id, name, stream_key) VALUES (?, ?, 'k1')", (uid, text))
    elif kind == "stream_description":
        raw(d, "INSERT INTO user_streams (user_id, name, stream_key, description) VALUES (?, 'n', 'k2', ?)", (uid, text))
    else:
        raise AssertionError(kind)


async def plant_field(d, kind, ch, uid, text):
    """Store `text` in the field the way the application does, then check that the
    stored value is what the reference check reads (plain text for the plain
    columns, so the SQL search can see it)."""
    col = None
    if kind == "poll_question":
        await d.create_poll(ch, uid, text, ["a", "b"])
    elif kind == "poll_option":
        await d.create_poll(ch, uid, "q", ["a", text])
    elif kind == "status":
        await d.set_user_status(uid, "online", text)
        col = ("users", "status_message", "id", uid)
    elif kind == "topic":
        await d.update_chat_channel(ch, topic=text)
        col = ("chat_channels", "topic", "id", ch)
    elif kind == "channel_description":
        await d.update_chat_channel(ch, description=text)
        col = ("chat_channels", "description", "id", ch)
    elif kind == "stream_name":
        sid = await d.create_user_stream(uid, text, "key-name")
        col = ("user_streams", "name", "id", sid)
    elif kind == "stream_description":
        sid = await d.create_user_stream(uid, "n", "key-desc", description=text)
        col = ("user_streams", "description", "id", sid)
    else:
        raise AssertionError(kind)
    if col:
        cur = await d.conn.execute(f"SELECT {col[1]} FROM {col[0]} WHERE {col[2]} = ?", (col[3],))
        assert (await cur.fetchone())[0] == text, f"{kind} is not stored as plain text"


FIELDS = ("poll_question", "poll_option", "status", "topic", "channel_description", "stream_name",
          "stream_description")


def test_sweeper_keeps_files_named_in_every_other_free_text_field():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        names = {k: make_file(up, age_hours=48) for k in FIELDS}
        orphan = make_file(up, age_hours=48)
        for kind, name in names.items():
            await plant_field(d, kind, ch, uid, f"look {URL}{name}.")
        rep = await d.sweep_orphan_chat_uploads(delete=True)
        assert rep["orphans"] == 1 and rep["names"] == [orphan], rep
        assert all(exists(up, n) for n in names.values()) and not exists(up, orphan)
    run_with_db(body)


def test_message_purge_keeps_files_named_in_every_other_free_text_field():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        names = {k: make_file(up) for k in FIELDS}
        for kind, name in names.items():
            await msg(d, ch, uid, name)
            await plant_field(d, kind, ch, uid, f"look {URL}{name}.")
        gone = make_file(up)
        await msg(d, ch, uid, gone)
        await age_rows(d, "chat_messages", 30)
        stats = {}
        await d.cleanup_old_chat_messages(days=7, stats=stats)
        assert all(exists(up, n) for n in names.values()), stats
        assert not exists(up, gone) and stats["files"] == 1, stats
    run_with_db(body)


def test_an_unreadable_poll_stops_the_sweep_like_an_unreadable_message():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        old = make_file(up, age_hours=48)
        raw(d, "INSERT INTO chat_polls (channel_id, user_id, question, options) VALUES (?, ?, ?, ?)",
            (ch, uid, "gAAAAAB" + "A" * 80, "gAAAAAB" + "B" * 80))
        rep = await d.sweep_orphan_chat_uploads(delete=True)
        assert rep.get("skipped") and exists(up, old), rep
    run_with_db(body)


# ---------------------------------------------------------------------------
# A row written after the scan keeps the file (the scan/unlink race)
# ---------------------------------------------------------------------------

def test_edit_after_the_scan_that_pastes_the_link_keeps_the_file_for_sweep_and_purge():
    from database import encrypt_message

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        # sweep: a row that existed when the scan ran is edited to name the file afterwards
        old = make_file(up, age_hours=48)
        await msg(d, ch, uid, text="plain")
        dm_id = await d.create_dm_message(conv, uid, "u", "plain dm")
        now = datetime.now(timezone.utc).isoformat()

        def edit_rows():
            raw(d, "UPDATE chat_messages SET message = ?, edited_at = ?", (encrypt_message(f"now {URL}{old}"), now))

        rep = await with_write_after_scan(d, edit_rows, d.sweep_orphan_chat_uploads(delete=True))
        assert exists(up, old) and rep["orphans"] == 0, rep

        # purge: the same in a DM row
        gone = make_file(up)
        await msg(d, ch, uid, gone)
        raw(d, "UPDATE chat_messages SET message = 'plain', edited_at = NULL")
        await age_rows(d, "chat_messages", 30)

        def edit_dm():
            raw(d, "UPDATE dm_messages SET message = ?, edited_at = ? WHERE id = ?",
                (encrypt_message(f"now {URL}{gone}"), now, dm_id))

        stats = {}
        await with_write_after_scan(d, edit_dm, d.cleanup_old_chat_messages(days=7, stats=stats))
        assert exists(up, gone) and stats["files"] == 0, stats
    run_with_db(body)


def test_new_rows_written_after_the_scan_keep_the_file():
    from database import encrypt_message

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        writers = {
            "chat text": lambda n: insert_chat_row(d, ch, uid, text=f"see {URL}{n}"),
            "chat column": lambda n: insert_chat_row(d, ch, uid, image_url=URL + n),
            "dm text": lambda n: raw(d, "INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at) "
                                        "VALUES (?, ?, 'u', ?, ?)",
                                     (conv, uid, encrypt_message(f"see {URL}{n}"), datetime.now(timezone.utc).isoformat())),
            "poll": lambda n: _plant_raw(d, "poll_question", ch, uid, f"see {URL}{n}"),
            "status": lambda n: _plant_raw(d, "status", ch, uid, f"see {URL}{n}"),
        }
        for label, write in writers.items():
            name = make_file(up, age_hours=48)
            rep = await with_write_after_scan(d, lambda: write(name), d.sweep_orphan_chat_uploads(delete=True))
            assert exists(up, name) and rep["deleted"] == 0, (label, rep)
    run_with_db(body)


def test_the_unlink_happens_while_the_write_lock_is_held():
    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        name = make_file(up, age_hours=48)
        outcome = {}
        real = chat_uploads.unlink_names

        def probe(*a, **kw):
            conn = sqlite3.connect(d.db_path, timeout=0)
            try:
                conn.execute("INSERT INTO settings (key, value) VALUES ('probe', '1')")
                conn.commit()
                outcome["write"] = "allowed"
            except sqlite3.OperationalError as e:
                outcome["write"] = str(e)
            finally:
                conn.close()
            return real(*a, **kw)

        chat_uploads.unlink_names = probe
        try:
            rep = await d.sweep_orphan_chat_uploads(delete=True)
        finally:
            chat_uploads.unlink_names = real
        assert rep["deleted"] == 1 and "locked" in outcome["write"], (rep, outcome)
        # and the lock is released afterwards
        raw(d, "INSERT OR REPLACE INTO settings (key, value) VALUES ('probe', '2')")
    run_with_db(body)


def test_missing_upload_folder_is_not_reported_as_a_skipped_sweep():
    async def body(d, up, tmp):
        up.rmdir()                      # nothing was ever uploaded
        rep = await d.sweep_orphan_chat_uploads()
        assert not rep.get("skipped") and rep["scanned"] == 0 and rep["orphans"] == 0, rep
    run_with_db(body)


def test_single_message_delete_reads_text_off_the_event_loop():
    import threading
    import database

    async def body(d, up, tmp):
        uid, ch, conv = await setup_ids(d)
        await msg(d, ch, uid, text="another")
        name = make_file(up)
        mid = await msg(d, ch, uid, name)
        seen, ticks = set(), []
        real = database.decrypt_message_strict

        def slow_decrypt(value):
            seen.add(threading.get_ident())
            time.sleep(0.05)
            return real(value)

        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(0.01)

        database.decrypt_message_strict = slow_decrypt
        t = asyncio.create_task(ticker())
        try:
            assert await d.delete_chat_message(mid)
        finally:
            database.decrypt_message_strict = real
            t.cancel()
        assert not exists(up, name)
        assert seen and threading.get_ident() not in seen, seen
        assert len(ticks) > 5, f"the event loop was blocked ({len(ticks)} ticks)"
    run_with_db(body)


def test_clear_channel_answer_names_why_files_were_skipped():
    import server

    class Req:
        match_info = {"id": "7"}

    async def go(skipped):
        async def auth(request):
            return types.SimpleNamespace(user_id=1)

        async def get_user(uid):
            return {"id": 1, "username": "root", "role": "superadmin"}

        async def get_channel(cid):
            return {"id": cid, "name": "nowhere-room"}

        async def clear(cid, stats=None):
            if skipped:
                stats["skipped"] = skipped
            return 4

        async def audit(*a, **k):
            return None

        saved = (server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel,
                 server.db.clear_channel_messages, server.audit_log)
        server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel = auth, get_user, get_channel
        server.db.clear_channel_messages, server.audit_log = clear, audit
        try:
            r = await server.http_clear_chat_channel(Req())
            return json.loads(r.body)
        finally:
            (server.authenticate_request, server.db.get_user_by_id, server.db.get_chat_channel,
             server.db.clear_channel_messages, server.audit_log) = saved

    reason = "a message could not be decrypted, so its upload links are unknown"
    body = asyncio.run(go(reason))
    assert body == {"success": True, "deleted_count": 4, "chat_files_skipped": reason}, body
    body = asyncio.run(go(None))
    assert body == {"success": True, "deleted_count": 4}, body


def test_dead_helper_is_gone():
    assert not hasattr(chat_uploads, "all_column_references")


def test_reference_extraction_in_text():
    f = chat_uploads.stems_in
    a, b = "a" * 32, "b" * 32
    assert f(f"x {URL}{a}.png y") == {a}
    assert f(f"{URL}{a}.png.") == {a}
    assert f(f"https://h{URL}{a} and {URL}{b}.pdf") == {a, b}
    assert f(f"{URL}{a.upper()}.png") == {a}
    assert f("no urls here") == set() and f(None) == set()
    assert f("/static/uploads/emotes/" + a) == set()


if __name__ == "__main__":
    tests = sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f))
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {e!r}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
