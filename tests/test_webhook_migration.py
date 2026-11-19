"""Webhook channels schema: an old-shape webhooks table is rebuilt with a nullable
owner and the new columns, rows, ids and logs unchanged, repeatable; and the
redaction rules of the database layer (no secret, no destination URL of a
non-generic hook, ever).

Run: venv/bin/python tests/test_webhook_migration.py
"""

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import outbound_guard  # noqa: E402

outbound_guard.install()  # a fixture URL that is not loopback can never be dialled
os.environ.setdefault("JWT_SECRET", "x" * 64)

from database import Database, encrypt_config  # noqa: E402
import webhook_formats  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


OLD_SHAPE = """
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL DEFAULT 'x');
CREATE TABLE webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'outgoing', url TEXT, secret TEXT NOT NULL, token TEXT UNIQUE,
    events TEXT NOT NULL DEFAULT '[]', channel_id INTEGER, enabled INTEGER DEFAULT 1,
    consecutive_failures INTEGER DEFAULT 0, last_delivery_at TEXT, last_failure_at TEXT,
    last_failure_reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE webhook_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, webhook_id INTEGER NOT NULL, event TEXT NOT NULL,
    request_payload TEXT, response_status INTEGER, response_body TEXT, success INTEGER DEFAULT 0,
    attempt INTEGER DEFAULT 1, duration_ms INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE);
"""


async def main():
    tmp = tempfile.mkdtemp()
    path = str(Path(tmp) / "old.db")
    raw = sqlite3.connect(path)
    raw.executescript(OLD_SHAPE)
    raw.execute("INSERT INTO users (id, username) VALUES (7, 'owner')")
    secret_enc = encrypt_config("hmac-secret-old")
    url_enc = encrypt_config("https://old.example/hook")
    raw.execute("INSERT INTO webhooks (id, user_id, name, url, secret, events, enabled, consecutive_failures) "
                "VALUES (41, 7, 'old hook', ?, ?, '[\"*\"]', 1, 3)", (url_enc, secret_enc))
    raw.execute("INSERT INTO webhooks (id, user_id, name, type, secret, token) "
                "VALUES (42, 7, 'in', 'incoming', ?, 'tok123')", (secret_enc,))
    raw.execute("INSERT INTO webhook_logs (webhook_id, event, success) VALUES (41, 'user.joined', 1)")
    raw.execute("INSERT INTO webhook_logs (webhook_id, event, success) VALUES (41, 'user.joined', 0)")
    raw.commit()
    raw.close()

    db = Database(path)
    await db.connect()
    cur = await db.conn.execute("PRAGMA table_info(webhooks)")
    info = {r["name"]: r for r in await cur.fetchall()}
    check("user_id is nullable after the rebuild", info["user_id"]["notnull"] == 0)
    check("new columns exist with defaults",
          {"kind", "format", "format_config", "include_details", "allow_private", "created_by"} <= set(info)
          and info["kind"]["dflt_value"] == "'user'" and info["format"]["dflt_value"] == "'generic'")
    cur = await db.conn.execute("SELECT * FROM webhooks ORDER BY id")
    rows = [dict(r) for r in await cur.fetchall()]
    check("both rows kept with their ids", [r["id"] for r in rows] == [41, 42])
    old = rows[0]
    check("old hook: every old column unchanged",
          old["name"] == "old hook" and old["url"] == url_enc and old["secret"] == secret_enc
          and old["consecutive_failures"] == 3 and old["enabled"] == 1 and old["user_id"] == 7)
    check("old hook behaves as before: generic, user, no details, no private",
          (old["kind"], old["format"], old["include_details"], old["allow_private"]) == ("user", "generic", 0, 0))
    check("incoming token kept", rows[1]["token"] == "tok123" and rows[1]["type"] == "incoming")
    cur = await db.conn.execute("SELECT COUNT(*) FROM webhook_logs WHERE webhook_id = 41")
    check("delivery logs survived the rebuild", (await cur.fetchone())[0] == 2)
    cur = await db.conn.execute("PRAGMA foreign_key_check")
    check("foreign key check is clean", not await cur.fetchall())
    cur = await db.conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='webhooks'")
    names = {r["name"] for r in await cur.fetchall()}
    check("indexes recreated", {"idx_webhooks_user", "idx_webhooks_type_enabled", "idx_webhooks_token"} <= names, str(names))

    # delete the owner: the user hook goes, a system hook stays
    sysh = await db.create_webhook(None, "ops", "outgoing", url="https://hooks.example/x", events=["*"],
                                   kind="system", fmt="ntfy", created_by=7)
    check("system hook has no owner", sysh["user_id"] is None and sysh["kind"] == "system")
    await db.conn.execute("DELETE FROM users WHERE id = 7")
    await db.conn.commit()
    check("deleting the creating user leaves the system hook", await db.get_webhook(sysh["id"]) is not None)
    check("deleting the owner removes their user hooks", await db.get_webhook(41) is None)
    await db.conn.close()

    # second connect: nothing changes
    db2 = Database(path)
    await db2.connect()
    check("rebuild is repeatable", await db2.get_webhook(sysh["id"]) is not None)
    await db2.conn.close()

    # ----- redaction and storage -----
    db3 = Database(str(Path(tmp) / "fresh.db"))
    await db3.connect()
    await db3.conn.execute("INSERT INTO users (username, password_hash) VALUES ('u1', 'x')")
    await db3.conn.commit()
    uid = (await (await db3.conn.execute("SELECT id FROM users WHERE username='u1'")).fetchone())["id"]
    discord = "https://discord.com/api/webhooks/123456/SECRET-DISCORD-TOKEN"
    gen = await db3.create_webhook(uid, "gen", "outgoing", url="https://gen.example/hook?k=abc",
                                   events=["user.joined"])
    check("generic create shows url and the secret once", gen["url"] == "https://gen.example/hook?k=abc" and len(gen["secret"]) == 64)
    dc = await db3.create_webhook(uid, "dc", "outgoing", url=discord, events=["user.joined"], fmt="discord")
    check("discord create does not return the URL or a secret",
          dc["url"] is None and "secret" not in dc and dc["url_host"] == "https://discord.com"
          and "SECRET-DISCORD-TOKEN" not in json.dumps(dc), str(dc))
    gt = await db3.create_webhook(uid, "gt", "outgoing", url="http://192.168.1.5:8080", events=["*"], fmt="gotify",
                                  format_config={"token": "GOTIFY-APP-TOKEN"}, allow_private=True, include_details=True)
    check("gotify create: token set flag, no token", gt["has_format_secret"] is True
          and "GOTIFY-APP-TOKEN" not in json.dumps(gt) and gt["allow_private"] is True and gt["include_details"] is True)
    outs = [json.dumps(x) for x in (await db3.get_webhooks_for_user(uid), await db3.get_all_webhooks(),
                                    await db3.get_webhook(gt["id"]), await db3.get_webhook(dc["id"]))]
    check("no read path returns a token or a Discord path",
          not any(t in o for o in outs for t in ("GOTIFY-APP-TOKEN", "SECRET-DISCORD-TOKEN", "123456")))
    rawdb = sqlite3.connect(str(Path(tmp) / "fresh.db"))
    dump = "\n".join(str(r) for r in rawdb.execute("SELECT url, secret, format_config FROM webhooks"))
    check("raw database holds none of them in the clear",
          not any(t in dump for t in ("GOTIFY-APP-TOKEN", "SECRET-DISCORD-TOKEN", "192.168.1.5", "discord.com")), dump[:200])
    rawdb.close()
    full = await db3.get_webhook_for_delivery(gt["id"])
    check("delivery read decrypts url and credentials",
          full["url"] == "http://192.168.1.5:8080" and full["format_config"] == {"token": "GOTIFY-APP-TOKEN"})
    await db3.update_webhook(gt["id"], name="renamed")
    check("a rename keeps the stored token", (await db3.get_webhook_for_delivery(gt["id"]))["format_config"]["token"] == "GOTIFY-APP-TOKEN")

    # only the generic format keeps an HMAC secret (a version without formats skips a hook with none)
    rawdb = sqlite3.connect(str(Path(tmp) / "fresh.db"))
    sec = dict(rawdb.execute("SELECT id, secret FROM webhooks").fetchall())
    check("a non-generic hook is stored with an empty secret, a generic one with a secret",
          sec[dc["id"]] == "" and sec[gt["id"]] == "" and sec[gen["id"]] != "")
    check("a non-generic hook shows no secret flag", (await db3.get_webhook(dc["id"]))["has_secret"] is False)
    await db3.update_webhook(dc["id"], format="generic", url="https://gen.example/other")
    sec = dict(rawdb.execute("SELECT id, secret FROM webhooks").fetchall())
    check("a switch to generic generates a secret", sec[dc["id"]] != "" and (await db3.get_webhook(dc["id"]))["has_secret"] is True)
    first = (await db3.get_webhook_for_delivery(dc["id"]))["secret"]
    await db3.update_webhook(dc["id"], format="generic", name="again")
    check("generic to generic keeps the secret", (await db3.get_webhook_for_delivery(dc["id"]))["secret"] == first)
    await db3.update_webhook(dc["id"], format="slack", url="https://hooks.slack.com/services/T/B/X")
    sec = dict(rawdb.execute("SELECT id, secret FROM webhooks").fetchall())
    check("a switch away from generic drops the secret", sec[dc["id"]] == "")
    await db3.update_webhook(dc["id"], name="plain rename")
    sec = dict(rawdb.execute("SELECT id, secret FROM webhooks").fetchall())
    check("a rename leaves the secret state alone", sec[dc["id"]] == "")
    rawdb.close()

    # dispatch rules: "*" and system-only
    subs = await db3.get_enabled_outgoing_webhooks_for_event("message.created")
    ids = {w["id"] for w in subs}
    check("'*' on a non-generic hook does not cover message.created", gt["id"] not in ids and gen["id"] not in ids)
    # a hook that does not receive the event is never decrypted
    import database as _dbmod
    real_decrypt = _dbmod.decrypt_config
    decrypted = []
    _dbmod.decrypt_config = lambda v: (decrypted.append(v), real_decrypt(v))[1]
    try:
        subs = await db3.get_enabled_outgoing_webhooks_for_event("stream.offline")
    finally:
        _dbmod.decrypt_config = real_decrypt
    cur = await db3.conn.execute("SELECT COUNT(*) FROM webhooks WHERE type='outgoing' AND enabled=1")
    n_enabled = (await cur.fetchone())[0]
    check("dispatch decrypts only the hooks that receive the event",
          len(subs) < n_enabled and len(decrypted) <= 3 * len(subs),
          str((len(subs), n_enabled, len(decrypted))))
    decrypted.clear()
    _dbmod.decrypt_config = lambda v: (decrypted.append(v), real_decrypt(v))[1]
    try:
        none = await db3.get_enabled_outgoing_webhooks_for_event("no.such.event")
    finally:
        _dbmod.decrypt_config = real_decrypt
    check("an event nobody receives decrypts nothing", none == [] and decrypted == [], str(len(decrypted)))
    sysh2 = await db3.create_webhook(None, "s", "outgoing", url="https://x.example", events=["*"], kind="system", fmt="ntfy")
    subs = {w["id"] for w in await db3.get_enabled_outgoing_webhooks_for_event("webhook.test")}
    check("webhook.test reaches only system hooks", subs == {sysh2["id"]}, str(subs))
    check("user list leaves system hooks out", all(w["kind"] == "user" for w in await db3.get_all_webhooks()))
    check("system list has only system hooks", [w["id"] for w in await db3.get_system_webhooks()] == [sysh2["id"]])
    await db3.conn.close()

    # pure helpers
    es = webhook_formats.event_subscribed
    check("event_subscribed rules",
          es(["*"], "stream.live") and not es(["*"], "webhook.test")
          and es(["*"], "webhook.test", kind="system") and not es(["*"], "message.created", fmt="ntfy")
          and es(["message.created"], "message.created", fmt="ntfy") and es(["*"], "message.created"))
    check("presence events need an explicit subscription in a non-generic format, '*' still covers generic",
          not es(["*"], "user.connected", fmt="slack") and not es(["*"], "user.disconnected", fmt="discord")
          and es(["user.connected"], "user.connected", fmt="gotify") and es(["*"], "user.connected")
          and es(["*"], "user.joined", fmt="ntfy"))
    check("a user hook gets only allow-listed events; a future event is system-only",
          not es(["ops.future"], "ops.future") and not es(["*"], "ops.future")
          and es(["ops.future"], "ops.future", kind="system") and es(["*"], "ops.future", kind="system")
          and webhook_formats.USER_EVENTS >= {"stream.live", "user.joined"}
          and "webhook.test" not in webhook_formats.USER_EVENTS)


asyncio.run(main())
outbound_guard.report("test_webhook_migration")
sys.exit(1 if failures else 0)
