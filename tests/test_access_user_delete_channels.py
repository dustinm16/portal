"""Deleting an account deletes the chat channel of each of its streams (the way deleting a stream does), so no
public channel is left holding the history of a private stream; and channels already left behind are made
private and listed by a start-up pass that deletes nothing.

Run: venv/bin/python tests/test_access_user_delete_channels.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

from aiohttp.test_utils import make_mocked_request  # noqa: E402

import secevents  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


async def main():
    db = server.db
    db.db_path = str(Path(tempfile.mkdtemp()) / "t.db")
    await db.connect()
    secevents.log.bind(db)
    ids = {}
    for name, role in (("sa", "superadmin"), ("gone", "user"), ("stays", "user")):
        u = await create_user(name, "Pass-12345-xyz!", is_admin=role == "superadmin")
        await db.set_user_role(u["id"], role)
        ids[name] = u["id"]

    async def stream_with_channel(owner, uname, label, public):
        sid = await db.create_user_stream(ids[owner], label, "live_" + label * 8, public_key="pub_" + label * 8, is_public=public)
        cid = await db.create_chat_channel(f"stream-{uname}-{sid}", f"Chat for {label} by {uname}", ids[owner])
        await db.update_user_stream(sid, chat_channel_id=cid)
        await db.create_chat_message(cid, ids[owner], uname, "private history of a private stream")
        return sid, cid
    s1, c1 = await stream_with_channel("gone", "gone", "p", False)
    s2, c2 = await stream_with_channel("gone", "gone", "q", True)
    s3, c3 = await stream_with_channel("stays", "stays", "r", False)
    shared = await db.create_chat_channel("lounge", "everybody", ids["sa"])
    await db.update_user_stream(s2, chat_channel_id=c2)

    async def fake_auth(request):
        return server.TokenPayload({"jti": "s1", "sub": str(ids["sa"]), "scopes": ["*"]})
    server.authenticate_request = fake_auth
    req = make_mocked_request("DELETE", f"/api/users/{ids['gone']}", match_info={"id": str(ids["gone"])})
    resp = await server.http_delete_user(req)
    check("the account was deleted", resp.status == 200, str(resp.status))
    for label, cid in (("private", c1), ("public", c2)):
        check(f"the chat channel of its {label} stream is gone, with its messages", await db.get_chat_channel(cid) is None)
    check("another member's stream channel is untouched", await db.get_chat_channel(c3) is not None)
    check("a channel that was never a stream's is untouched", await db.get_chat_channel(shared) is not None)
    check("the default channel is untouched", await db.get_chat_channel(1) is not None)

    # leftovers from the old behaviour: the signature of a stream channel whose stream and creator are gone
    async def raw_channel(name, desc, created_by, vis="public"):
        cur = await db.conn.execute(
            "INSERT INTO chat_channels (name, description, created_by, visibility) VALUES (?, ?, ?, ?)", (name, desc, created_by, vis))
        await db.conn.commit()
        return cur.lastrowid
    left = await raw_channel("stream-olduser-901", "Chat for Show by olduser", None)
    left_private = await raw_channel("stream-olduser-902", "Chat for Show by olduser", None, "private")
    mimic_alive = await raw_channel("stream-olduser-903", "Chat for Show by olduser", ids["stays"])      # creator still exists
    wrong_user = await raw_channel("stream-olduser-904", "Chat for Show by somebody", None)
    plain = await raw_channel("stream-notes-x", "Chat for Show by notes", None)
    real_stream_id = s3
    live_one = await raw_channel(f"stream-zed-{real_stream_id}", "Chat for r by zed", None)             # its stream exists
    await db._migrate_orphaned_stream_channels()
    vis = {}
    for label, cid in (("left", left), ("left_private", left_private), ("mimic_alive", mimic_alive), ("wrong_user", wrong_user),
                       ("plain", plain), ("live_one", live_one)):
        vis[label] = (await db.get_chat_channel(cid))["visibility"]
    check("a leftover stream channel is made private and kept", vis["left"] == "private" and await db.get_chat_channel(left) is not None, str(vis))
    check("channels that do not carry the whole signature stay as they were",
          vis["mimic_alive"] == "public" and vis["wrong_user"] == "public" and vis["plain"] == "public" and vis["live_one"] == "public", str(vis))
    listed = json.loads(await db.get_setting("orphaned_stream_channels"))
    check("the leftovers are listed for administrators", sorted(x["id"] for x in listed) == sorted([left, left_private]), str(listed))
    await db._migrate_orphaned_stream_channels()
    listed2 = json.loads(await db.get_setting("orphaned_stream_channels"))
    check("a second run changes nothing", listed2 == listed)
    # An administrator who deliberately made a handled channel public again does not see it reverted at the next start
    await db.conn.execute("UPDATE chat_channels SET visibility = 'public' WHERE id = ?", (left,))
    await db.conn.commit()
    await db._migrate_orphaned_stream_channels()
    check("a channel an administrator made public again stays public at the next start",
          (await db.get_chat_channel(left))["visibility"] == "public", str((await db.get_chat_channel(left))["visibility"]))
    listed3 = json.loads(await db.get_setting("orphaned_stream_channels"))
    check("the list for administrators still names it (the list is not wiped by the skipped pass)",
          sorted(x["id"] for x in listed3) == sorted([left, left_private]), str(listed3))
    handled = json.loads(await db.get_setting("orphaned_stream_channels_handled"))
    check("the handled channels are recorded by id and name", {(x["id"], x["name"]) for x in handled} == {(left, "stream-olduser-901"), (left_private, "stream-olduser-902")}, str(handled))
    # a leftover that appears later is still handled once
    later = await raw_channel("stream-olduser-905", "Chat for Show by olduser", None)
    await db._migrate_orphaned_stream_channels()
    check("a new leftover is made private by the next pass", (await db.get_chat_channel(later))["visibility"] == "private")
    check("and the earlier one is still left alone", (await db.get_chat_channel(left))["visibility"] == "public")
    # an id reused under another name is not mistaken for a handled one
    await db.conn.execute("DELETE FROM chat_channels WHERE id = ?", (left_private,))
    await db.conn.execute("INSERT INTO chat_channels (id, name, description, created_by, visibility) VALUES (?, 'stream-olduser-906', 'Chat for Show by olduser', NULL, 'public')", (left_private,))
    await db.conn.commit()
    await db._migrate_orphaned_stream_channels()
    check("a reused id under a new name is handled as new", (await db.get_chat_channel(left_private))["visibility"] == "private")
    # no message is deleted by the pass
    cur = await db.conn.execute("SELECT COUNT(*) FROM chat_messages WHERE channel_id = ?", (c3,))
    check("the pass deletes no history", (await cur.fetchone())[0] == 1)


try:
    asyncio.run(asyncio.wait_for(main(), 90))
except Exception as e:
    import traceback
    traceback.print_exc()
    check("ran without an exception", False, repr(e))
print("FAILED: " + ", ".join(failures) if failures else "all passed")
sys.stdout.flush()
os._exit(1 if failures else 0)
