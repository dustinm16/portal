"""The clean-up (at every start) of a stored "recording" flag on the connections of accounts that are not
administrators: a member could store it on 1.19.0 where it did nothing, and a later promotion would
silently have started recording. It runs at every start, so a flag stored after a rollback to 1.19.0
(the settings marker already exists) is removed after the next upgrade as well.

Run: venv/bin/python tests/test_recording_flag_migration.py

Scratch database only. A row is changed only when its owner is not an administrator and its
config holds the key; the format (encrypted or plain) is kept; an undecodable row is skipped and its
id is logged; the migration writes its settings marker (old code reads it) but does not depend on it.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database, decrypt_config, encrypt_config  # noqa: E402

failures = []
FLAG = "recording_member_flags_cleared"


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def stored(d, cid):
    cur = await d.conn.execute("SELECT config FROM user_connections WHERE id = ?", (cid,))
    return (await cur.fetchone())["config"]


async def add(d, uid, name, config_text):
    """A row with the config text stored exactly as given."""
    uuid = await d.create_user_connection(uid, name, "ssh", "93.184.216.34", 22, "{}")
    cur = await d.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))
    cid = (await cur.fetchone())["id"]
    await d.conn.execute("UPDATE user_connections SET config = ? WHERE id = ?", (config_text, cid))
    await d.conn.commit()
    return cid


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "t.db")
        d = Database(path)
        await d.connect()
        member = await d.create_user("member", "x")
        admin = await d.create_user("admin", "x")
        sup = await d.create_user("sup", "x")
        legacy = await d.create_user("legacy", "x")
        await d.set_user_role(admin, "admin")
        await d.set_user_role(sup, "superadmin")
        await d.conn.execute("UPDATE users SET role = NULL, is_admin = 1 WHERE id = ?", (legacy,))
        await d.conn.commit()

        flagged = {"username": "u", "recording": True, "password": "keep-me"}
        plain_flagged = json.dumps(flagged)
        no_key = encrypt_config(json.dumps({"username": "u", "host_key_fingerprint": "SHA256:abc"}))
        ids = {
            "member_enc": await add(d, member, "m-enc", encrypt_config(json.dumps(flagged))),
            "member_plain": await add(d, member, "m-plain", plain_flagged),
            "member_false": await add(d, member, "m-false", encrypt_config(json.dumps({"recording": False}))),
            "member_nokey": await add(d, member, "m-nokey", no_key),
            "member_empty": await add(d, member, "m-empty", "{}"),
            "admin": await add(d, admin, "a", encrypt_config(json.dumps(flagged))),
            "sup": await add(d, sup, "s", encrypt_config(json.dumps(flagged))),
            "legacy": await add(d, legacy, "l", encrypt_config(json.dumps(flagged))),
            "garbage": await add(d, member, "garbage", "enc:not-a-fernet-token"),
        }
        before_nokey = await stored(d, ids["member_nokey"])
        before_garbage = await stored(d, ids["garbage"])
        # the database as 1.19.0 left it: the migration has not run
        await d.conn.execute("DELETE FROM settings WHERE key = ?", (FLAG,))
        await d.conn.commit()
        await d.close()

        cap = Capture()
        logging.getLogger("portal.database").addHandler(cap)
        logging.getLogger("portal.database").setLevel(logging.DEBUG)
        d = Database(path)
        await d.connect()
        try:
            check("the start went through with an undecodable row in the table", True)
            m_enc = json.loads(decrypt_config(await stored(d, ids["member_enc"])))
            check("a member's encrypted config loses the key and keeps everything else",
                  "recording" not in m_enc and m_enc == {"username": "u", "password": "keep-me"}, str(m_enc))
            check("a member's encrypted config is still stored encrypted",
                  (await stored(d, ids["member_enc"])).startswith("enc:"))
            m_plain = json.loads(decrypt_config(await stored(d, ids["member_plain"])))   # the start encrypts plain rows first
            check("a member's plain-JSON config loses the key as well",
                  "recording" not in m_plain and m_plain.get("password") == "keep-me", str(m_plain))
            check("a member's flag set to false is removed as well",
                  "recording" not in json.loads(decrypt_config(await stored(d, ids["member_false"]))))
            for who in ("admin", "sup", "legacy"):
                kept = json.loads(decrypt_config(await stored(d, ids[who])))
                check(f"the flag of an {who} account's connection stays", kept.get("recording") is True, str(kept))
            check("a member's row without the key is byte for byte unchanged",
                  await stored(d, ids["member_nokey"]) == before_nokey)
            check("an empty config is unchanged", await stored(d, ids["member_empty"]) == "{}")
            check("an undecodable row is left as it was", await stored(d, ids["garbage"]) == before_garbage)
            check("the undecodable row's id is logged",
                  any(str(ids["garbage"]) in line and "recording" in line.lower() for line in cap.lines), str(cap.lines))
            cur = await d.conn.execute("SELECT value FROM settings WHERE key = ?", (FLAG,))
            row = await cur.fetchone()
            check("the migration records that it ran", row is not None and row["value"] == "1")

            # a flag stored after the marker exists (a rollback to 1.19.0 and back) is removed at the next start
            again = await add(d, member, "again", encrypt_config(json.dumps({"recording": True})))
        finally:
            await d.close()
            logging.getLogger("portal.database").removeHandler(cap)
        d = Database(path)
        await d.connect()
        left = json.loads(decrypt_config(await stored(d, again)))
        check("a second start removes a flag stored after the marker exists", "recording" not in left, str(left))
        cur = await d.conn.execute("SELECT value FROM settings WHERE key = ?", (FLAG,))
        row = await cur.fetchone()
        check("the settings marker is still written", row is not None and row["value"] == "1")
        cur = await d.conn.execute("SELECT config FROM user_connections WHERE id = ?", (ids["admin"],))
        check("an administrator's flag still stays at the second start",
              json.loads(decrypt_config((await cur.fetchone())["config"])).get("recording") is True)
        await d.close()


try:
    asyncio.run(asyncio.wait_for(main(), 90))
except asyncio.TimeoutError:
    check("the test finished within its deadline", False)
if failures:
    print(f"\ntest_recording_flag_migration: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_recording_flag_migration: all checks passed")
