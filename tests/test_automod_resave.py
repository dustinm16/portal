"""An old regex rule with more than 100 patterns can be saved again unchanged.

validate_automod_config refused more than REGEX_MAX_PATTERNS patterns on every save, so the admin page
could not save an unrelated edit of a rule stored before the cap. The update route now hands the stored
config to the validator: a save whose pattern list equals the stored list (regex mode both times) is
accepted, a list that grew or changed is held to the cap. New rules keep the cap.

Run: venv/bin/python tests/test_automod_resave.py
"""

import asyncio
import json
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
import automod  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402

BIG = [f"word{i}" for i in range(101)]


def cfg(words, mode="regex"):
    return {"words": list(words), "match_mode": mode}


class Req:
    def __init__(self, rule_id, body):
        self.match_info = {"id": str(rule_id)}
        self._body = body
        self.headers = {}

    async def json(self):
        return self._body


def test_validator_accepts_an_unchanged_oversized_list_only():
    v = automod.validate_automod_config
    assert v("word_filter", cfg(BIG)), "the cap must hold without a stored config"
    assert v("word_filter", cfg(BIG), cfg(BIG)) is None
    assert v("word_filter", cfg(BIG + ["extra"]), cfg(BIG))
    assert v("word_filter", cfg(BIG[:-1] + ["other"]), cfg(BIG))
    assert v("word_filter", cfg(BIG), cfg(BIG, "contains"))
    assert v("word_filter", cfg(BIG), None)
    # an unchanged list is still checked pattern by pattern
    assert v("word_filter", cfg(BIG[:-1] + ["(a+)+$"]), cfg(BIG[:-1] + ["(a+)+$"]))


def test_update_route_resaves_an_old_oversized_rule_but_not_a_grown_one():
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (server.db, server.authenticate_request, server._automod_cache_time)
            server.db = d
            try:
                uid = await d.create_user("boss", "x")
                await d.set_user_role(uid, "admin")

                async def auth(request):
                    return type("T", (), {"user_id": uid, "has_scope": lambda self, s: True})()
                server.authenticate_request = auth
                # stored directly, as a rule saved before the cap existed would be
                rid = await d.create_automod_rule("word_filter", "old", cfg(BIG), "delete", uid)

                async def put(body):
                    resp = await server.http_update_automod_rule(Req(rid, body))
                    return resp.status, json.loads(resp.body)

                st, b = await put({"type": "word_filter", "name": "renamed", "config": cfg(BIG)})
                assert st == 200, (st, b)
                st, b = await put({"name": "only a name"})
                assert st == 200, (st, b)
                st, b = await put({"type": "word_filter", "config": cfg(BIG + ["one more"])})
                assert st == 400, (st, b)
                st, b = await put({"config": cfg(BIG[:-1] + ["swapped"])})
                assert st == 400, (st, b)
                rules = await d.get_automod_rules()
                stored = json.loads(rules[0]["config"])["words"]
                assert stored == BIG and rules[0]["name"] == "only a name", rules
                # a smaller list is saved, and then the cap applies to it again
                st, b = await put({"config": cfg(BIG[:100])})
                assert st == 200, (st, b)
                st, b = await put({"config": cfg(BIG)})
                assert st == 400, (st, b)
            finally:
                server.db, server.authenticate_request, server._automod_cache_time = saved
                await d.close()
    asyncio.run(asyncio.wait_for(go(), 60))


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except BaseException as e:
                bad += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if bad else 0)
