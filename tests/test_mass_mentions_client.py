"""@here and @everyone on the chat page and the watch page.

Static checks plus the page's own functions run under Node against fakes (no browser): the
autocomplete offers @here and @everyone only when the member may use them (a moderator level or
the channel's switch), the switch button is shown to staff and a stream owner only, the frames
(channel_info, mod_level, mass_mentions_changed, notice) are handled and the toggle sends the
right frame. What a real keyboard, phone or screen does is not proven.

Run: venv/bin/python tests/test_mass_mentions_client.py
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHAT = (ROOT / "static" / "chat.html").read_text()
WATCH = (ROOT / "static" / "watch.html").read_text()


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def function_source(src, name):
    m = re.search(r"\n\s*(async )?function %s\(" % re.escape(name), src)
    check(m, "function " + name)
    i = src.index("{", m.end())
    depth = 0
    for j in range(i, len(src)):
        depth += src[j] == "{"
        depth -= src[j] == "}"
        if depth == 0:
            return src[m.start():j + 1]
    raise AssertionError("unbalanced " + name)


def run_node(code):
    out = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=30)
    check(out.returncode == 0, out.stderr)
    return out.stdout


def test_frames_and_controls_exist():
    for frame in ("case 'mass_mentions_changed':", "case 'notice':", "case 'mod_level':"):
        check(frame in CHAT, "chat.html " + frame)
    for frame in ("case 'mass_mentions_changed':", "case 'notice':"):
        check(frame in WATCH, "watch.html " + frame)
    check('id="mass-mention-btn"' in CHAT and 'id="mass-mention-btn"' in WATCH, "buttons")
    check("type: 'set_mass_mentions'" in WATCH and "type: 'set_mass_mentions'" in CHAT.replace('"', "'")
          or "'set_mass_mentions'" in CHAT, "frame sent")


def test_no_emoji_in_the_new_text():
    for src in (CHAT, WATCH):
        for line in src.splitlines():
            if "mass" in line.lower() or "@everyone" in line:
                check(not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", line), line)


def test_the_page_scripts_still_parse():
    if not shutil.which("node"):
        print("skip: node not installed")
        return
    for name, src in (("chat", CHAT), ("watch", WATCH)):
        scripts = re.findall(r"<script>(.*?)</script>", src, re.S)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(max(scripts, key=len))
        out = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
        check(out.returncode == 0, name + ": " + out.stderr)


def harness(extra):
    funcs = "\n".join(function_source(CHAT, n) for n in (
        "canMassMention", "renderMassMentionButton", "toggleMassMentions", "handleMentionAutocomplete",
        "showMentionDropdown", "hideMentionDropdown"))
    return """
const els = {};
function el(id) { return els[id] || (els[id] = {id, style: {}, classList: {add(){}, remove(){}}, textContent: '', innerHTML: ''}); }
const document = { getElementById: el };
let channelModLevel = 'none', channelMassFlag = false, currentView = 'channel';
let mentionDropdownVisible = false, mentionSelectedIndex = 0, mentionMatches = [], mentionStartPos = 0;
let onlineUsers = new Map([[1, {username: 'eve', nickname: null, avatar: {}}], [2, {username: 'hereward', nickname: null, avatar: {}}]]);
let knownChatNames = new Set(['everett']);
const sent = []; let ws = {readyState: 1, send: (m) => sent.push(JSON.parse(m))};
const WebSocket = {OPEN: 1};
function escapeHtml(t) { return String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';'); }
""" + funcs + "\n" + extra


def names_for(level, flag, text):
    code = harness("""
channelModLevel = %s; channelMassFlag = %s;
handleMentionAutocomplete({value: %s, selectionStart: %d});
console.log(JSON.stringify(mentionMatches.map(m => m.name)));
""" % (json.dumps(level), json.dumps(flag), json.dumps(text), len(text)))
    return json.loads(run_node(code))


def test_autocomplete_offers_the_specials_only_when_allowed():
    if not shutil.which("node"):
        print("skip: node not installed")
        return
    plain = names_for("none", False, "hi @")
    check("everyone" not in plain and "here" not in plain, plain)
    check(names_for("none", False, "@ev") == ["eve", "everett"], "prefix, not allowed")
    for level, flag in (("staff", False), ("owner", False), ("mod", False), ("none", True)):
        got = names_for(level, flag, "hi @")
        check(got[:2] == ["everyone", "here"], (level, flag, got))
    check(names_for("none", True, "@ev")[:1] == ["everyone"], "filtered by prefix")
    check("here" not in names_for("none", True, "@ev"), "here does not match ev")
    check(names_for("none", True, "@he")[0] == "here", "here first for he")


def test_a_view_change_forgets_the_last_room_s_mass_mention_rights():
    """channelModLevel and channelMassFlag belong to the room that sent them: a DM or another room must not
    inherit them (a DM would still offer @everyone)."""
    if not shutil.which("node"):
        print("skip: node not installed")
        return
    funcs = "\n".join(function_source(CHAT, n) for n in ("canMassMention", "switchChannel", "renderDmView"))
    check("function resetMassMentionState" in CHAT, "the reset helper exists")
    funcs += "\n" + function_source(CHAT, "resetMassMentionState") + "\n" + function_source(CHAT, "renderMassMentionButton")
    code = """
const els = {};
function el(id) { return els[id] || (els[id] = {id, style: {}, classList: {add(){}, remove(){}, toggle(){}}, textContent: '', innerHTML: '', dataset: {}}); }
const document = { getElementById: el, querySelectorAll: () => [] };
const window = {};
let channelModLevel = 'none', channelMassFlag = false;
let currentChannel = 'general', currentView = 'channel', currentDmConversationId = null, _lastReadMessageId = 0, pendingJoin = null;
const unreadMentions = new Map(), currentUser = {id: 1};
let ws = {readyState: 1, send() {}}; const WebSocket = {OPEN: 1};
function resetHistoryState() {} function renderDmList() {} function renderHistory() {}
""" + funcs + """
const out = {};
channelModLevel = 'staff'; channelMassFlag = true; out.before = canMassMention();
renderDmView({id: 3, type: 'direct', participants: [{user_id: 1}, {user_id: 2, username: 'bob'}]}, []);
out.dm = canMassMention(); out.dmState = [channelModLevel, channelMassFlag, el('mass-mention-btn').style.display];
channelModLevel = 'owner'; channelMassFlag = true;
switchChannel('other');
out.channel = canMassMention(); out.chState = [channelModLevel, channelMassFlag];
// a frame of the room arrives while a DM is open: the DM still does not offer them
currentView = 'dm'; channelModLevel = 'staff'; channelMassFlag = true; out.late = canMassMention();
console.log(JSON.stringify(out));
"""
    got = json.loads(run_node(code))
    check(got["before"] is True, got)
    check(got["dm"] is False and got["dmState"] == ["none", False, "none"], got)
    check(got["channel"] is False and got["chState"] == ["none", False], got)
    check(got["late"] is False, got)


def test_the_switch_button_and_the_toggle():
    if not shutil.which("node"):
        print("skip: node not installed")
        return
    code = harness("""
const out = {};
for (const level of ['none', 'mod', 'owner', 'staff']) {
  channelModLevel = level; channelMassFlag = false; renderMassMentionButton();
  out[level] = [el('mass-mention-btn').style.display, el('mass-mention-btn').textContent];
}
channelModLevel = 'staff'; channelMassFlag = true; renderMassMentionButton();
out.on = el('mass-mention-btn').textContent;
toggleMassMentions();
out.sent = sent;
console.log(JSON.stringify(out));
""")
    got = json.loads(run_node(code))
    check(got["none"][0] == "none" and got["mod"][0] == "none", "hidden for none and stream mods")
    check(got["owner"][0] == "" and got["staff"][0] == "", "shown for owner and staff")
    check(got["on"] == "@everyone: on", got["on"])
    check(got["sent"] == [{"type": "set_mass_mentions", "allowed": False}], got["sent"])


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
