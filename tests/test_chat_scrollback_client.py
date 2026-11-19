"""The chat page's scrollback client: markup and wiring checks on chat.html and
portal.js, then the scrollback code of chat.html runs under Node
(tests/chat_scrollback_harness.js) against a small fake page: older pages above
the first row without duplicates, the read tracker never seeing fetched rows,
the row cap, windows around a message, the live buffer and Jump to present.
Node is needed for the second half; without it that part is reported as skipped.

What a browser must still show (scroll position while images load, the highlight,
the button's look) is listed in the release notes, not here.

Run: venv/bin/python tests/test_chat_scrollback_client.py
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
PORTAL = (STATIC / "js" / "portal.js").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("reply previews jump instead of opening the thread (thread stays on Shift-click)",
      'data-reply-id=' in CHAT and 'onclick="openThread(' not in CHAT and "e.shiftKey" in CHAT)
check("no inline onclick carries message data for reply previews", "scrollToMessage(${" not in CHAT.replace(
    'onclick="scrollToMessage(${m.id})"', ""))
check("the deleted-reply selector follows the new attribute",
      '.message-reply-preview[data-reply-id=' in CHAT and 'onclick*="scrollToMessage' not in CHAT)
check("the page handles the three scrollback replies",
      all(f"case '{t}':" in CHAT for t in ("history_older", "history_around", "history_error")))
check("fetched rows skip the read observer", "!(opts && opts.fetched)) observeMessageForRead" in CHAT)
BLOCK = CHAT[CHAT.index("const HISTORY_TOP_PX"):CHAT.index("window.chatJumpToMessage")]
check("older pages and windows never call markAsRead; only the newest page after Jump to present does",
      BLOCK.count("markAsRead(") == 1 and "markAsRead(last)" in BLOCK
      and "if (p.kind === 'latest' && !HistoryView.detached) markNewestPageRead(data.messages);" in BLOCK)
check("a send in the channel view jumps to the present when detached, after the message went out",
      "ws.send(JSON.stringify(payload));\n            jumpToPresentAfterSend();" in CHAT
      and CHAT.count("jumpToPresentAfterSend()") == 2)
check("edit, reaction and poll updates are applied to the live buffer first",
      "function handleMessageEdited(data) {\n            bufferApplyEdit(data);" in CHAT
      and "function handleReactionUpdate(data) {\n            bufferApplyReaction(data);" in CHAT
      and "function updatePollDisplay(poll) {\n            bufferApplyPoll(poll);" in CHAT
      and "HistoryView.buffer = HistoryView.buffer.filter(m => m.id !== messageId);" in CHAT)
check("live messages go through the buffering function", "appendLiveMessage(data);" in CHAT)
check("a new poll goes through the live buffer too", "case 'poll_created':\n                    appendLivePoll(data);" in CHAT)
check("search results jump to the message", "jumpToChannelMessage(sourceId, messageId)" in CHAT)
check("the page reads a message link (?channel_id=&message_id=)", "jp.get('channel_id')" in CHAT and "jp.get('message_id')" in CHAT)
check("notifications with a channel message open it in context",
      "chatJumpToMessage" in PORTAL and "data.channel_id && data.message_id" in PORTAL)
check("the pop-out chat page is unchanged by scrollback", "history_page" not in (STATIC / "watch.html").read_text())

# ---- documentation ---------------------------------------------------------------
README = (ROOT / "README.md").read_text()
m = re.search(r"### Upgrade notes for 1\.14\.0\n(.*?)(?=\n## |\n### )", README, re.S)
check("README has an 'Upgrade notes for 1.14.0' section after the 1.13.0 notes",
      m is not None and README.index("### Upgrade notes for 1.14.0") > README.index("### Upgrade notes for 1.13.0"))
notes = (m.group(1) if m else "").lower()
for name, needles in (("the retention is global, not per channel", ("retention_chat_days", "not a per-channel")),
                      ("the new message and route", ("history_page", "/api/chat/channels/{id}/messages")),
                      ("the limits", ("50", "100", "30 requests per minute")),
                      ("404 for an unreadable channel", ("404",)),
                      ("anonymous posts stay anonymous", ("anonymous",)),
                      ("the index", ("idx_chat_messages_channel_id_id", "second start changes nothing")),
                      ("portal.js v45", ("?v=45",))):
    check("README states: " + name, all(n.lower() in notes for n in needles), str(needles))
api = (ROOT / "docs" / "API.md").read_text()
html = (STATIC / "api-docs.html").read_text()
for label, text in (("docs/API.md", api), ("api-docs.html", html)):
    check(f"{label} documents the route and the WebSocket message",
          "/api/chat/channels/" in text and "messages" in text and "history_page" in text and "history_older" in text
          and "history_around" in text and "history_error" in text and "rate_limited" in text)

if shutil.which("node"):
    proc = subprocess.run(["node", str(ROOT / "tests" / "chat_scrollback_harness.js"), str(STATIC / "chat.html")],
                          capture_output=True, text=True, timeout=60)
    rows = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    check("the harness ran", proc.returncode == 0 and len(rows) >= 20, proc.stderr[-300:])
    for r in rows:
        check(r["name"], r["ok"], r["detail"])
else:
    print("skip the Node checks: node is not installed")

if failed:
    print(f"\ntest_chat_scrollback_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_chat_scrollback_client: all checks passed")
