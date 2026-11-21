"""The chat page's retention window, prune window and notice (static/js/chat-retention.js).

Markup and wiring checks on chat.html, then the script runs under Node
(tests/retention_client_harness.js) against a small fake DOM and a fake fetch. No browser: what
the windows look like and how they behave on a phone is not proven.

Run: venv/bin/python tests/test_chat_retention_client.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
CHAT = (STATIC / "chat.html").read_text()
JS = (STATIC / "js" / "chat-retention.js").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("chat.html loads chat-retention.js with a version", re.search(r'src="/static/js/chat-retention\.js\?v=\d+"', CHAT) is not None)
check("the page handles messages_pruned by removing every id",
      "case 'messages_pruned':" in CHAT and "(data.ids || []).forEach(removeDeletedMessage)" in CHAT)
check("the channel_info frame and the mod_level frame reach the script",
      "ChatRetention.onChannelInfo(data, currentUser)" in CHAT and "ChatRetention.onModLevel(channelModLevel, currentUser)" in CHAT)
_WATCH = (STATIC / "watch.html").read_text()
check("the watch page's stream chat drops pruned messages too",
      "case 'messages_pruned':" in _WATCH and "(data.ids || []).forEach(" in _WATCH)
check("a DM hides the controls", "ChatRetention.onChannelInfo(null)" in CHAT)
check("an attachment whose file was removed is marked in the message", "data.file_removed" in CHAT and "file-removed-note" in CHAT)
check("the script has no inline handler and no innerHTML", not re.search(r"\bon(click|change|input|submit)\s*=", JS) and "innerHTML" not in JS)
check("the script sends credentials and uses the retention and prune routes",
      "credentials: 'include'" in JS and "/retention'" in JS and "/prune'" in JS)
_STREAMS = (STATIC / "js" / "streams.js").read_text()
check("the Streams page's small chat handles messages_pruned with the list of ids",
      "data.type === 'messages_pruned'" in _STREAMS and "removeStreamChatMessages(data.ids)" in _STREAMS)
check("the script has no emoji", not re.search("[\U0001F000-\U0001FFFF☀-➿]", JS))

if shutil.which("node") is None:
    check("node is installed (needed to run the client harness)", False)
else:
    syn = subprocess.run(["node", "--check", str(STATIC / "js" / "chat-retention.js")], capture_output=True, text=True, timeout=60)
    check("chat-retention.js passes a syntax check", syn.returncode == 0, syn.stderr[:300])
    proc = subprocess.run(["node", str(ROOT / "tests" / "retention_client_harness.js"),
                           str(STATIC / "js" / "chat-retention.js")], capture_output=True, text=True, timeout=60)
    got = [json.loads(l[7:]) for l in proc.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran and reported checks", len(got) >= 25, proc.stdout[-300:] + proc.stderr[-300:])
    for r in got:
        check(r["name"], r["ok"], r["detail"])

if shutil.which("node") is not None:
    m = re.search(r"function removeStreamChatMessages\(ids\) \{.*?\n\}\n", _STREAMS, re.S)
    check("streams.js has the pruned-message remover to run", m is not None)
    if m:
        harness = """
class El { constructor(id){ this.dataset = {messageId: String(id)}; this.gone = false; } remove(){ this.gone = true; } }
const els = [1, 2, 3, 40].map(i => new El(i));
global.document = { querySelectorAll: sel => (sel === '#stream-chat-messages .chat-message' ? els : []) };
""" + m.group(0) + """
removeStreamChatMessages([2, '40', 99]);
const a = els.map(e => e.gone);
removeStreamChatMessages(null); removeStreamChatMessages('1'); removeStreamChatMessages({});
console.log(JSON.stringify([a, els.map(e => e.gone)]));
"""
        proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=60)
        try:
            first, after = json.loads(proc.stdout.strip())
        except Exception:
            first = after = None
        check("the listed ids leave the small chat, the others stay, a non-list is ignored",
              first == [False, True, False, True] and after == first, proc.stdout + proc.stderr[-300:])

if failed:
    print(f"\ntest_chat_retention_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_chat_retention_client: all checks passed")
