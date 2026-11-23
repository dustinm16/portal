"""The chat page's notification client: level and mute, badges for channels not joined,
the bell menu, the sound with quiet hours and the one-tab lock, the move of the old star,
and the desktop alert that names the channel of the message frame.

Markup and wiring checks on chat.html, chat-notify.js and portal.js, then the code runs under
Node (tests/chat_notify_harness.js) against fakes. No browser, no audio device, no real
notification here: what a speaker or a desktop notification does is not proven.

Run: venv/bin/python tests/test_chat_notify_client.py
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
JS = (STATIC / "js" / "chat-notify.js").read_text()
PORTAL = (STATIC / "js" / "portal.js").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("chat.html loads chat-notify.js with a version", re.search(r'src="/static/js/chat-notify\.js\?v=\d+"', CHAT) is not None)
check("the localStorage star is gone from the page", "_subscribedChannels" not in CHAT and "_saveNotifSubscriptions" not in CHAT
      and "localStorage.setItem('portal_notif_channels'" not in CHAT)
check("the star is moved once", "ChatNotify.migrateStars(localStorage" in CHAT and "_starsMigrated" in CHAT)
check("a message frame is judged by its own channel, not currentChannel for the alert",
      "const frameChannel = data.channel || currentChannel;" in CHAT and "_sendChannelDesktopNotification" not in CHAT)
check("a channel_activity frame is handled", "case 'channel_activity':" in CHAT and "onChannelActivity(data)" in CHAT)
check("the channel list is rebuilt on reconnect and on window focus",
      "if (reconnectAttempts > 0) reconcileChannels();" in CHAT
      and "window.addEventListener('focus', reconcileChannels)" in CHAT
      and "document.addEventListener('visibilitychange'" in CHAT and "unreadCounts = new Map();" in CHAT)
check("the bell menu offers All, Mentions, Nothing and mute 1, 8, 24 hours",
      all(t in CHAT for t in ("All messages", "Mentions only", "'Nothing'", "Mute for 1 hour", "Mute for 8 hours", "Mute for 24 hours")))
check("the stream follow bell is kept", "toggleStreamFollow(channelName, e)" in CHAT and "/api/me/follows" in CHAT)
_bell = next((ln for ln in CHAT.splitlines() if "const bellBtn = " in ln), "")
check("the bell button carries data attributes and no inline handler",
      bool(_bell) and "onclick" not in _bell and 'data-bell-channel-id="${Number(ch.id)}"' in _bell and "data-bell-kind=" in _bell, _bell[:120])
_touch = re.search(r"@media \(hover: none\)\s*\{([^}]*\.ch-notif-bell[^}]*)\}", CHAT)
check("on a touch screen (hover: none) the bell is visible at reduced opacity with a target of at least 32 px",
      bool(_touch) and re.search(r"opacity:\s*0\.[3-9]", _touch.group(1)) and re.search(r"min-width:\s*(3[2-9]|[4-9]\d)px", _touch.group(1))
      and re.search(r"min-height:\s*(3[2-9]|[4-9]\d)px", _touch.group(1)), str(_touch and _touch.group(1)))
check("the bells are bound with addEventListener after each render",
      "bindChannelBells(list);" in CHAT and "btn.addEventListener('click'" in CHAT and "btn.dataset.bellChannelId" in CHAT)
check("the PUT goes to the notify route", "/notify`" in CHAT and "method: 'PUT'" in CHAT)
check("no external fetch for the sound", "new Audio(" not in CHAT and "new Audio(" not in JS)
check("portal.js gives each desktop notification its own tag and opens the channel on click",
      "_desktopTag(notification)" in PORTAL and "data.channel_id && data.message_id" in PORTAL
      and "tag: notification.type ||" not in PORTAL)
for page in sorted(STATIC.glob("*.html")):
    if "/static/js/portal.js" in page.read_text():
        if "portal.js?v=52" not in page.read_text():
            check("portal.js v52 in " + page.name, False)
check("portal.js is v51 everywhere it is loaded", not [f for f in failed if f.startswith("portal.js v52")])

if shutil.which("node"):
    proc = subprocess.run(["node", str(ROOT / "tests" / "chat_notify_harness.js"), str(STATIC / "chat.html"),
                           str(STATIC / "js" / "chat-notify.js")], capture_output=True, text=True, timeout=60)
    rows = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    check("the harness ran", len(rows) > 20, (proc.stdout + proc.stderr)[-500:])
    for r in rows:
        check(r["name"], r["ok"], r["detail"])
else:
    print("skip node harness: node is not installed")

if failed:
    print(f"\ntest_chat_notify_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_chat_notify_client: all checks passed")
