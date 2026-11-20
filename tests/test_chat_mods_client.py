"""Stream chat controls on the watch page and in the stream settings window (static checks).

There is no browser here: this reads static/watch.html and static/js/streams.js and checks that the
frames the server sends are handled, that user-controlled text only reaches the page as text, that
the owner-and-mod rules the page uses to hide buttons match the server's (the server still decides),
that the inline script parses, and that no new UI text contains an emoji.

Run: venv/bin/python tests/test_chat_mods_client.py
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WATCH = (ROOT / "static" / "watch.html").read_text()
STREAMS = (ROOT / "static" / "js" / "streams.js").read_text()


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def inline_script():
    scripts = re.findall(r"<script>(.*?)</script>", WATCH, re.S)
    check(scripts, "no inline script")
    return max(scripts, key=len)


def test_every_new_frame_is_handled():
    for frame in ("pinned_messages", "message_pinned", "message_unpinned", "poll_created", "poll_updated",
                  "poll_closed", "mod_level", "slowmode_changed", "user_timed_out", "channel_info"):
        check(f"case '{frame}'" in WATCH, frame)
    for sent in ("set_slowmode", "timeout_user", "pin_message", "unpin_message", "create_poll", "vote_poll",
                 "close_poll"):
        check(f"type: '{sent}'" in WATCH, sent)


def test_menu_items_and_banner_exist_in_the_page_and_the_popout_uses_the_same_page():
    for ident in ("ctx-pin-btn", "ctx-timeout-btn", "watch-pinned", "slowmode-select", "poll-btn"):
        check(f'id="{ident}"' in WATCH, ident)
    check("chat === 'only'" in WATCH or "chat') === 'only'" in WATCH, "pop-out mode")


def test_cards_and_polls_and_badges_are_built_from_text():
    for fn in ("buildStreamCard", "buildPollElement", "renderPinned"):
        body = re.search(r"function %s\(.*?\n        }\n" % fn, WATCH, re.S)
        check(body, fn)
        check("innerHTML" not in body.group(0), fn + " must not use innerHTML")
    check("msg.message_type === 'stream_card'" in WATCH, "go-live cards are rendered as cards")
    check("Number(card.stream_id)" in WATCH, "the card link comes from the numeric id")
    check("stream-owner" in WATCH and "stream-mod" in WATCH, "badges")
    check("escapeHtml(msg.role)" in WATCH, "the role badge is escaped")


def test_the_ban_is_labelled_as_signed_in_viewing_and_a_banned_viewer_is_told():
    low = WATCH.lower()
    check("while signed in" in low and "signed-in viewing" in low, "label")
    check("why.banned" in WATCH and "You are banned from this stream" in WATCH, "explanation")


def test_streams_settings_has_the_mod_list():
    for needle in ("Chat Moderators", "stream-mods-list", "/mods", "loadStreamMods", "bindStreamModSearch"):
        check(needle in STREAMS, needle)
    body = re.search(r"async function loadStreamMods\(.*?\n}\n", STREAMS, re.S).group(0)
    check("innerHTML" not in body, "mod names are text nodes")


def test_no_emoji_in_the_new_ui_text():
    block = WATCH[WATCH.index("stream chat controls"):WATCH.index("function appendSystemMessage")]
    check(not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", block), "emoji in the new block")


def run_node(code):
    out = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=30)
    check(out.returncode == 0, out.stderr or out.stdout)
    return out.stdout


def test_inline_script_parses_and_the_hide_rules_match_the_server():
    if not shutil.which("node"):
        print("skip: node not installed")
        return
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "inline.js"
        p.write_text(inline_script())
        out = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
        check(out.returncode == 0, out.stderr)
    fn = re.search(r"function authorOutranks\(msg\) \{.*?\n        }\n", WATCH, re.S).group(0)
    code = fn + """
    var streamData = {user_id: 1};
    function t(level, msg) { modLevel = level; return authorOutranks(msg); }
    var modLevel;
    var res = {
      modOnOwner: t('mod', {user_id: 1, stream_role: 'owner', role: 'user'}),
      modOnMod: t('mod', {user_id: 5, stream_role: 'mod', role: 'user'}),
      modOnAdmin: t('mod', {user_id: 6, role: 'admin'}),
      modOnPlain: t('mod', {user_id: 7, role: 'user'}),
      ownerOnMod: t('owner', {user_id: 5, stream_role: 'mod', role: 'user'}),
      ownerOnAdmin: t('owner', {user_id: 6, role: 'admin'}),
      ownerOnPlain: t('owner', {user_id: 7, role: 'user'}),
      staffOnAny: t('staff', {user_id: 6, role: 'admin'}),
    };
    console.log(JSON.stringify(res));
    """
    got = json.loads(run_node(code))
    check(got == {"modOnOwner": True, "modOnMod": True, "modOnAdmin": True, "modOnPlain": False,
                  "ownerOnMod": False, "ownerOnAdmin": True, "ownerOnPlain": False, "staffOnAny": False}, got)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print("FAIL", name, type(e).__name__, e)
                failed += 1
    sys.exit(1 if failed else 0)
