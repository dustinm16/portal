"""An automod trigger is written to the audit log.

The entry used to name actor id 0, which the foreign key on audit_log.actor_id rejects, so
nothing was ever stored. It is now filed under the member the rule acted on, with the actor
name AutoMod and an automatic flag in the details.

Run: venv/bin/python tests/test_automod_audit.py
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402
outbound_guard.install()
import server  # noqa: E402
from database import Database  # noqa: E402


class _Catch(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_a_triggered_rule_is_audited_under_the_member():
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time)
            server.db = d
            server._automod_regex = server.automod.RegexRunner()
            catch = _Catch()
            server.logger.addHandler(catch)
            try:
                uid = await d.create_user("author", "x")
                cid = await d.create_chat_channel("room", created_by=uid)
                await d.create_automod_rule("word_filter", "no-foo", {"words": ["foo"], "match_mode": "contains"},
                                            "delete", uid)
                server._automod_cache_time = -1e9
                hit = await server.check_automod("a foo here", uid, cid, "room")
                assert hit and hit["rule_name"] == "no-foo", hit
                assert not [m for m in catch.lines if "[AuditLog] Failed" in m], catch.lines
                rows = await d.get_audit_log(limit=20, action="automod_trigger")
                assert len(rows) == 1, rows
                r = rows[0]
                assert r["actor_id"] == uid and r["actor_username"] == "AutoMod", r
                assert r["target_id"] == uid and r["target_type"] == "user", r
                assert r["channel_id"] == cid and r["channel_name"] == "room", r
                details = r["details"]
                for _ in range(2):
                    if isinstance(details, str):
                        details = json.loads(details)
                assert details.get("automatic") is True and details.get("rule") == "no-foo", details
            finally:
                server.logger.removeHandler(catch)
                await server._automod_regex.close()
                server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time = saved
                await d.close()
    asyncio.run(asyncio.wait_for(go(), 30))


if __name__ == "__main__":
    try:
        test_a_triggered_rule_is_audited_under_the_member()
    except BaseException as e:
        print(f"FAIL test_a_triggered_rule_is_audited_under_the_member: {type(e).__name__}: {e}")
        sys.exit(1)
    print("ok   test_a_triggered_rule_is_audited_under_the_member")
