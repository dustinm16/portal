"""Automod: config validation, bounded regex evaluation, and edit handling.

Run: venv/bin/python tests/test_automod.py

Nothing outside a temporary directory is touched. The worker process used for
regex evaluation is started from sys.executable and is killed when a test ends.
"""

import asyncio
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import automod  # noqa: E402
from database import Database  # noqa: E402


def test_nested_quantifiers_are_refused():
    for p in (r"(a+)+$", r"(a*)*", r"(\w+\s?)+", r"(?:a+){2,}", r"(x+x+)+y", r"((a+)b)+", r"(a+)*?"):
        assert automod.regex_problem(p), f"{p} was accepted"


def test_ordinary_patterns_are_accepted():
    for p in (r"(ab)+", r"a+b+", r"colou?r", r"[(a+)+]x", r"\(a+\)+", r"(foo|bar)+",
              r"(?:ab){2,}c+", r"(a+)?b", r"(a{1,3})+", r"\bfree\s+money\b", r"https?://\S+\.ru"):
        assert automod.regex_problem(p) is None, f"{p}: {automod.regex_problem(p)}"


def test_open_ended_repeats_count_as_unbounded():
    # Python reads {,} as {0,} and {n,} as unbounded, so a group repeated with either is nested.
    for p in (r"(a{,})+$", r"(a{,})*", r"(a{2,})+", r"(a{1,})+$", r"(a+){,}$", r"(a+){3,}", r"(a{,}b)*",
              r"(?:a{,}){2,}", r"(a{,})+?", r"(\w{,}\s?)+"):
        assert automod.regex_problem(p), f"{p} was accepted"
    # bounded forms and text that only looks like a quantifier stay accepted
    for p in (r"(a{,3})+", r"(a{2,5})+", r"(a{3})+", r"a{,}b", r"(ab){,3}", r"(a{})+", r"(a{ ,})+", r"(a+){2}"):
        assert automod.regex_problem(p) is None, f"{p}: {automod.regex_problem(p)}"
    assert automod.validate_automod_config("word_filter", {"words": [r"(a{,})+$"], "match_mode": "regex"})


def test_unenforced_reason_names_the_skipped_patterns():
    r = automod.unenforced_reason
    cfg = {"words": [r"(a+)+$", "fine", r"(b*)*"], "match_mode": "regex"}
    reason = r("word_filter", cfg)
    assert reason and "(a+)+$" in reason and "nested quantifier" in reason and "2 patterns" in reason, reason
    one = r("word_filter", {"words": ["(", "ok"], "match_mode": "regex"})
    assert one and "does not compile" in one and one.startswith("pattern is skipped"), one
    long_ = r("word_filter", {"words": ["(" + "a" * 100], "match_mode": "regex"})
    assert long_ and "..." in long_ and len(long_) < 200, long_
    # nothing to report for rules that are enforced as written
    assert r("word_filter", {"words": ["fine"], "match_mode": "regex"}) is None
    assert r("word_filter", {"words": [r"(a+)+$", "("], "match_mode": "contains"}) is None
    assert r("word_filter", {"words": [r"(a+)+$"]}) is None
    assert r("link_filter", {"block_list": ["x.com"]}) is None
    assert r("word_filter", None) is None
    assert r("word_filter", {"words": "abc", "match_mode": "regex"}) is None


def test_length_compile_and_type_limits():
    assert automod.regex_problem("a" * 500) is None
    assert "longer" in automod.regex_problem("a" * 501)
    assert "compile" in automod.regex_problem("(")
    assert automod.regex_problem("")
    assert automod.regex_problem(5)


def test_validate_config_rules():
    v = automod.validate_automod_config
    assert v("word_filter", {"words": ["x"], "match_mode": "regex"}) is None
    assert v("word_filter", {"words": ["(a+)+$"], "match_mode": "regex"})
    assert v("word_filter", {"words": ["a" * 501], "match_mode": "regex"})
    assert v("word_filter", {"words": ["x"] * 101, "match_mode": "regex"})
    assert v("word_filter", {"words": "abc"})
    assert v("word_filter", {"words": [1]})
    assert v("word_filter", {"words": ["x"], "match_mode": "nope"})
    assert v("word_filter", [])
    # patterns that are only words in the other modes are not compiled
    assert v("word_filter", {"words": ["(a+)+$", "("], "match_mode": "contains"}) is None
    assert v("link_filter", {"block_list": ["x.com"]}) is None
    assert v("spam_filter", {"max_messages": 5}) is None


def test_runner_matches_and_truncates():
    async def go():
        r = automod.RegexRunner()
        try:
            assert await r.search(r"fr+ee", "so FRRREE today")
            assert not await r.search(r"fr+ee", "nothing here")
            assert await r.search("needle", "x" * 1990 + "needle")      # inside the first 2000
            assert not await r.search("needle", "x" * 2000 + "needle")   # cut off
        finally:
            await r.close()
    asyncio.run(go())


def test_slow_pattern_is_stopped_loop_keeps_running_and_the_check_fails_closed():
    async def go():
        r = automod.RegexRunner(budget=0.25)
        gaps = []

        async def ticker():
            last = time.monotonic()
            while True:
                await asyncio.sleep(0.02)
                now = time.monotonic()
                gaps.append(now - last)
                last = now
        t = asyncio.create_task(ticker())

        async def overrun(pattern, text):
            try:
                await r.search(pattern, text)
            except automod.RegexCheckError as e:
                assert e.timed_out and e.pattern == pattern
                return True
            return False
        try:
            await asyncio.sleep(0.1)
            t0 = time.monotonic()
            # not accepted by the validator, but a rule saved before validation could hold it
            assert await overrun(r"(a+)+$", "a" * 40 + "b"), "an overrun must raise, not read as no match"
            took = time.monotonic() - t0
            assert took < 1.5, f"slow pattern held the caller for {took:.2f}s"
            assert max(gaps) < 0.2, f"event loop stalled for {max(gaps):.2f}s"
            assert r.restarts == 1
            # the pattern is NOT skipped afterwards: the next message is checked, and fails closed again
            assert await overrun(r"(a+)+$", "a" * 40 + "b")
            assert r.restarts == 2
            assert r.timeouts_in_last_hour(r"(a+)+$") == 2
            assert r.timeouts_in_last_hour("abc") == 0
            # the worker was replaced and still answers other patterns
            assert await r.search("abc", "xxABCxx")
            # a polynomial pattern that passes the validator is stopped the same way
            poly = r"a*a*a*a*a*a*b"
            assert automod.regex_problem(poly) is None
            assert await overrun(poly, "a" * 1999)
            assert max(gaps) < 0.2, f"event loop stalled for {max(gaps):.2f}s"
        finally:
            t.cancel()
            await r.close()
    asyncio.run(go())


def test_timeout_counter_expires_and_is_bounded():
    r = automod.RegexRunner()
    now = time.monotonic()
    r._timeouts["old"] = automod.deque([now - automod.SLOW_PATTERN_WINDOW_SECONDS - 5, now - 10])
    assert r.timeouts_in_last_hour("old") == 1
    for i in range(automod._MAX_TRACKED_PATTERNS + 50):
        r._note_timeout(f"p{i}")
    assert len(r._timeouts) <= automod._MAX_TRACKED_PATTERNS
    for _ in range(automod._MAX_TIMEOUTS_PER_PATTERN + 10):
        r._note_timeout("busy")
    assert r.timeouts_in_last_hour("busy") == automod._MAX_TIMEOUTS_PER_PATTERN


def test_slow_pattern_count_for_a_rule():
    r = automod.RegexRunner()
    r._note_timeout("a*a*b")
    r._note_timeout("a*a*b")
    r._note_timeout("other")
    cfg = {"words": ["a*a*b", "fine", "other"], "match_mode": "regex"}
    assert automod.slow_pattern_timeouts(r, "word_filter", cfg) == 3
    assert automod.slow_pattern_timeouts(r, "word_filter", {"words": ["a*a*b"], "match_mode": "contains"}) == 0
    assert automod.slow_pattern_timeouts(r, "link_filter", cfg) == 0
    assert automod.slow_pattern_timeouts(r, "word_filter", None) == 0


def test_runner_recovers_when_worker_dies():
    async def go():
        r = automod.RegexRunner()
        try:
            assert await r.search("a", "a")
            r._proc.kill()
            await r._proc.wait()
            assert await r.search("b", "abc")
        finally:
            await r.close()
    asyncio.run(go())


def _cancel_after_request_written(r, pattern, text):
    """Start r.search and return (task, event); event is set once the request is in the worker's pipe."""
    sent = asyncio.Event()

    async def go():
        if r._proc is None or r._proc.returncode is not None:
            await r._start()
        reader = r._proc.stdout
        orig = reader.readline

        async def readline():
            sent.set()          # the request was written and drained before the reply is read
            return await orig()
        reader.readline = readline
        return await r.search(pattern, text)
    return asyncio.ensure_future(go()), sent


def test_cancelled_search_does_not_leak_its_reply_to_the_next_search():
    async def go():
        r = automod.RegexRunner()
        try:
            assert await r.search("warm", "warm")
            task, sent = _cancel_after_request_written(r, "badword", "a badword here")
            await asyncio.wait_for(sent.wait(), 5)
            task.cancel()
            try:
                await task
                raise AssertionError("cancelled search returned")
            except asyncio.CancelledError:
                pass
            assert r._proc is None, "worker with an unread reply was kept"
            # must not see the earlier pattern's answer
            assert await r.search("zzz", "hello") is False
            assert await r.search("hel+o", "hello") is True
        finally:
            await r.close()
    asyncio.run(go())


def test_cancelled_slow_search_does_not_time_out_the_next_pattern():
    async def go():
        r = automod.RegexRunner(budget=0.5)
        try:
            assert await r.search("warm", "warm")
            poly = r"a*a*a*a*a*a*b"
            task, sent = _cancel_after_request_written(r, poly, "a" * 1999)
            await asyncio.wait_for(sent.wait(), 5)
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            assert await r.search("zzz", "hello") is False
            assert await r.search("hello", "say hello") is True
            assert r.restarts == 0, "trivial pattern was timed out behind the cancelled one"
            assert r.timeouts_in_last_hour("zzz") == 0
            assert r.timeouts_in_last_hour(poly) == 0   # a cancelled search is not a budget overrun
        finally:
            await r.close()
    asyncio.run(go())


def test_stale_unsafe_rule_is_skipped_at_run_time():
    import server

    async def go():
        server._automod_regex = automod.RegexRunner(budget=0.25)
        try:
            cfg = {"words": [r"(a+)+$", "fre+"], "match_mode": "regex"}
            t0 = time.monotonic()
            assert await server._check_word_filter("a" * 40 + "b", cfg) is False
            assert time.monotonic() - t0 < 0.1, "unsafe stored pattern reached the worker"
            assert await server._check_word_filter("freee", cfg) is True
        finally:
            await server._automod_regex.close()
    asyncio.run(go())


def test_check_automod_raises_when_a_pattern_overruns_and_apply_automod_rejects_without_penalty():
    import server

    class Ws:
        def __init__(self):
            self.sent = []

        async def send_json(self, payload):
            self.sent.append(payload)

    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time,
                     server.broadcast_to_channel)
            server.db = d
            server._automod_regex = automod.RegexRunner(budget=0.25)
            told = []

            async def fake_broadcast(*a, **k):
                told.append(a)
            server.broadcast_to_channel = fake_broadcast
            try:
                uid = await d.create_user("author3", "x")
                cid = await d.create_chat_channel("room3", created_by=uid)
                channel = await d.get_chat_channel_by_name("room3")
                poly = "a*a*a*a*a*a*!"
                assert automod.regex_problem(poly) is None
                await d.create_automod_rule("word_filter", "slow", {"words": [poly], "match_mode": "regex"},
                                            "timeout", uid, action_duration=60)
                server._automod_cache_time = 0
                for edit_of in (None, {"id": 9, "message": "old text"}):
                    ws = Ws()
                    t0 = time.monotonic()
                    blocked = await server.apply_automod(ws, "a" * 1999, user_id=uid, user_role="user",
                                                         channel=channel, channel_name="room3",
                                                         username="author3", my_state={}, edit_of=edit_of)
                    assert time.monotonic() - t0 < 1.5
                    assert blocked is True, "a message that could not be checked must be rejected"
                    err = ws.sent[0]
                    assert err["error_code"] == "automod_unchecked" and "could not be checked" in err["message"]
                    assert "shorten or rephrase" in err["message"]
                    if edit_of:
                        assert ws.sent[1] == {"type": "edit_rejected", "message_id": 9, "message": "old text"}
                    else:
                        assert len(ws.sent) == 1
                assert told == [], "nobody else may be told"
                assert not await d.is_user_timed_out(uid, cid), "no penalty for a check that could not finish"
                cur = await d.conn.execute("SELECT COUNT(*) AS n FROM automod_actions")
                assert (await cur.fetchone())["n"] == 0
                # not skipped for the next message: still rejected, and counted
                assert await server.apply_automod(Ws(), "a" * 1999, user_id=uid, user_role="user", channel=channel,
                                                  channel_name="room3", username="author3", my_state={}) is True
                assert server._automod_regex.timeouts_in_last_hour(poly) == 3
                # a short message the rule can finish on is checked normally
                assert await server.apply_automod(Ws(), "hello", user_id=uid, user_role="user", channel=channel,
                                                  channel_name="room3", username="author3", my_state={}) is False
            finally:
                await server._automod_regex.close()
                (server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time,
                 server.broadcast_to_channel) = saved
                await d.close()
    asyncio.run(go())


def test_admin_list_reports_slow_pattern_timeouts():
    import server
    cfg = json.dumps({"words": ["a*a*b"], "match_mode": "regex"})
    rows = [{"id": 1, "type": "word_filter", "name": "slow", "config": cfg, "enabled": 1},
            {"id": 2, "type": "link_filter", "name": "links", "config": "{}", "enabled": 1}]

    async def go():
        async def auth(request):
            return type("T", (), {"user_id": 1, "has_scope": lambda self, s: True})()

        async def get_rules(enabled_only=False):
            return [dict(r) for r in rows]

        saved = (server.authenticate_request, server.db.get_automod_rules, server._automod_regex)
        server.authenticate_request, server.db.get_automod_rules = auth, get_rules
        server._automod_regex = automod.RegexRunner()
        server._automod_regex._note_timeout("a*a*b")
        server._automod_regex._note_timeout("a*a*b")
        try:
            resp = await server.http_get_automod_rules(object())
            return {r["id"]: r["slow_pattern_timeouts"] for r in json.loads(resp.body)["rules"]}
        finally:
            server.authenticate_request, server.db.get_automod_rules, server._automod_regex = saved

    assert asyncio.run(go()) == {1: 2, 2: 0}
    admin = (ROOT / "static" / "admin.html").read_text()
    assert "slow pattern, " in admin and "skipped for 60" not in admin


def test_rate_limit_runs_before_automod_in_the_send_and_edit_paths():
    src = (ROOT / "server.py").read_text()
    edit = src[src.index('elif msg_type == "edit_message":'):src.index('elif msg_type == "pin_message":')]
    assert edit.index("_chat_member_blocked(") < edit.index("apply_automod(")
    send_at = src.index('elif msg_type == "message":')
    send = src[send_at:src.index("elif msg_type ==", send_at + 10)]
    assert send.index("_chat_member_blocked(") < send.index("apply_automod(")
    helper = src[src.index("async def _chat_member_blocked"):src.index("async def _dm_participant_blocked")]
    assert "msg_times" in helper and "rate_limit" in helper


def test_spam_filter_rules_are_reported_as_not_enforced():
    r = automod.unenforced_reason("spam_filter", {"max_messages": 5})
    assert r and "never applied" in r
    assert automod.unenforced_reason("link_filter", {}) is None
    import server

    rows = [{"id": 1, "type": "spam_filter", "name": "spam", "config": "{}", "enabled": 1},
            {"id": 2, "type": "spam_filter", "name": "spam off", "config": "{}", "enabled": 0}]

    async def go():
        async def auth(request):
            return type("T", (), {"user_id": 1, "has_scope": lambda self, s: True})()

        async def get_rules(enabled_only=False):
            return [dict(x) for x in rows]

        saved = (server.authenticate_request, server.db.get_automod_rules)
        server.authenticate_request, server.db.get_automod_rules = auth, get_rules
        try:
            resp = await server.http_get_automod_rules(object())
            return {x["id"]: x["not_enforced_reason"] for x in json.loads(resp.body)["rules"]}
        finally:
            server.authenticate_request, server.db.get_automod_rules = saved
    reasons = asyncio.run(go())
    assert reasons[1] and reasons[2] is None, reasons


def test_admin_form_keeps_a_stored_spam_filter_config_and_states_the_comma_rule():
    import shutil
    import subprocess
    admin = (ROOT / "static" / "admin.html").read_text()
    assert "patterns are separated by commas, so a pattern cannot contain a comma" in admin
    if not shutil.which("node"):
        return
    start = admin.index("function getAutomodConfig() {")
    fn = admin[start:admin.index("async function submitAutomodRule", start)]
    script = fn + r"""
const fields = {};
global.document = { getElementById: id => (id === 'am-type' ? { value: global.__type } : null) };
global.window = {};
const out = {};
window._amEditType = 'spam_filter'; window._amEditConfig = { max_messages: 5, window_seconds: 10 };
global.__type = 'spam_filter';
out.kept = getAutomodConfig();
window._amEditType = null; window._amEditConfig = { words: ['x'] };
out.created = getAutomodConfig();
window._amEditType = 'word_filter'; window._amEditConfig = { words: ['x'] };
out.switched = getAutomodConfig();
console.log(JSON.stringify(out));
"""
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got["kept"] == {"max_messages": 5, "window_seconds": 10}, got
    assert got["created"] == {} and got["switched"] == {}, got


def test_patterns_ending_in_a_group_close_are_handled():
    # The quantifier scan used to read one character past the end of the pattern.
    for p in (r"(\d+)", r"(foo|bar)", r"colou?r(s)", r"(?:ab)", r"a(b(c))", r"(a)(b)"):
        assert automod.regex_problem(p) is None, f"{p}: {automod.regex_problem(p)}"
        assert automod.nested_quantifier(p) is False
    # a group close at the very end still counts as unrepeated, so a nested one is still found
    assert automod.regex_problem(r"((a+)+)")
    assert automod._unbounded_quantifier("(a)", 3) is None
    v = automod.validate_automod_config
    assert v("word_filter", {"words": ["(foo|bar)", r"(\d+)"], "match_mode": "regex"}) is None


def test_stored_rule_ending_in_a_group_close_is_checked_without_raising():
    import server

    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            saved = (server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time)
            server.db = d
            server._automod_regex = automod.RegexRunner()
            try:
                uid = await d.create_user("author2", "x")
                cid = await d.create_chat_channel("room2", created_by=uid)
                # stored directly, as a rule saved before validation existed would be
                await d.create_automod_rule("word_filter", "stored", {"words": ["(foo|bar)"], "match_mode": "regex"},
                                            "delete", uid)
                server._automod_cache_time = 0     # force a reload from the database
                hit = await server.check_automod("a BAR here", uid, cid, "room2")
                assert hit and hit["rule_name"] == "stored", hit
                assert await server.check_automod("nothing to see", uid, cid, "room2") is None
            finally:
                await server._automod_regex.close()
                server.db, server._automod_regex, server._automod_rules_cache, server._automod_cache_time = saved
                await d.close()
    asyncio.run(go())


def test_editable_window_and_owner():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    fresh = {"user_id": 1, "created_at": (now - timedelta(seconds=10)).isoformat()}
    old = {"user_id": 1, "created_at": (now - timedelta(seconds=301)).isoformat()}
    assert Database.chat_message_editable(fresh, 1)
    assert not Database.chat_message_editable(fresh, 2)
    assert not Database.chat_message_editable(old, 1)
    assert not Database.chat_message_editable(None, 1)


def test_edit_and_send_paths_share_apply_automod():
    src = (ROOT / "server.py").read_text()
    assert len(re.findall(r"await check_automod\(", src)) == 1, "check_automod must be called only from apply_automod"
    assert len(re.findall(r"await apply_automod\(", src)) == 2
    edit = src[src.index('elif msg_type == "edit_message":'):src.index('elif msg_type == "pin_message":')]
    assert "apply_automod(" in edit
    # the check comes before the store
    assert edit.index("apply_automod(") < edit.index("db.edit_chat_message(")
    # and the cheap refusals (not the author, window over) come before the check
    assert edit.index("chat_message_editable(") < edit.index("apply_automod(")


def test_spam_filter_type_is_kept():
    import server
    assert "spam_filter" in server._AUTOMOD_RULE_TYPES
    admin = (ROOT / "static" / "admin.html").read_text()
    assert "Spam Filter (not enforced)" in admin


def test_rejected_edit_keeps_old_text_in_database():
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            d = Database(str(Path(tmp) / "t.db"))
            await d.connect()
            try:
                uid = await d.create_user("author1", "x")
                cid = await d.create_chat_channel("room1", created_by=uid)
                mid = await d.create_chat_message(cid, uid, "author1", "hello there")
                msg = await d.get_chat_message(mid)
                assert d.chat_message_editable(msg, uid)
                # A blocked edit never reaches edit_chat_message; an allowed one does
                assert (await d.edit_chat_message(mid, uid, "hello again"))["message"] == "hello again"
                assert (await d.edit_chat_message(mid, uid + 1, "stolen")) is None
                assert (await d.get_chat_message(mid))["message"] == "hello again"
            finally:
                await d.close()
    asyncio.run(go())


def test_list_flags_only_enabled_rules_as_not_enforced():
    import server
    bad = json.dumps({"words": ["(a+)+$"], "match_mode": "regex"})
    good = json.dumps({"words": ["fine"], "match_mode": "regex"})
    rows = [
        {"id": 1, "type": "word_filter", "name": "enabled bad", "config": bad, "enabled": 1},
        {"id": 2, "type": "word_filter", "name": "disabled bad", "config": bad, "enabled": 0},
        {"id": 3, "type": "word_filter", "name": "enabled good", "config": good, "enabled": 1},
    ]

    async def go():
        async def auth(request):
            return type("T", (), {"user_id": 1, "has_scope": lambda self, s: True})()

        async def get_rules(enabled_only=False):
            return [dict(r) for r in rows]

        saved = (server.authenticate_request, server.db.get_automod_rules)
        server.authenticate_request, server.db.get_automod_rules = auth, get_rules
        try:
            resp = await server.http_get_automod_rules(object())
            return {r["id"]: r["not_enforced_reason"] for r in json.loads(resp.body)["rules"]}
        finally:
            server.authenticate_request, server.db.get_automod_rules = saved

    reasons = asyncio.run(go())
    assert reasons[1] and "nested quantifier" in reasons[1], reasons
    assert reasons[2] is None, reasons
    assert reasons[3] is None, reasons


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
