"""The chat page's saved-message client: the marker, the Save and Remind entries of the message menu,
the Saved view, the reminder dialog, and the way a reminder notification opens it.

Markup and wiring checks on chat.html, chat-saved.js and portal.js, then the scripts run under Node
(tests/chat_saved_harness.js) as separate classic scripts sharing only the global object, against a small
fake DOM, twice: once in a zone that crosses a clock change (Europe/Berlin) and once in New York.
No browser, no phone, no calendar and no real notification here: how it looks and feels is not proven.

Run: venv/bin/python tests/test_saved_client.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
CHAT = (STATIC / "chat.html").read_text()
JS = (STATIC / "js" / "chat-saved.js").read_text()
CODE = re.sub(r"/\*.*?\*/", "", JS, flags=re.S)           # the code without its comments
PORTAL = (STATIC / "js" / "portal.js").read_text()
failed = []
SYMBOLS = re.compile("[" + chr(0x2190) + "-" + chr(0x21FF) + chr(0x2300) + "-" + chr(0x27BF) + chr(0x2B00) + "-" + chr(0x2BFF) + chr(0x1F000) + "-" + chr(0x1FFFF) + "]")


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("chat.html loads chat-saved.js with a version, after portal.js",
      re.search(r'src="/static/js/chat-saved\.js\?v=\d+"', CHAT) is not None
      and CHAT.index("/static/js/portal.js") < CHAT.index("/static/js/chat-saved.js"))
_items = {i: next((ln for ln in CHAT.splitlines() if f'id="{i}"' in ln), "") for i in ("saved-menu-item", "remind-menu-item", "saved-open-btn")}
check("the menu has Save message and Remind me entries and the header a Saved button",
      "Save message" in _items["saved-menu-item"] and "Remind me" in _items["remind-menu-item"] and _items["saved-open-btn"] != "")
check("the new markup carries no inline handler", all("onclick" not in v for v in _items.values()), str(_items))
check("the menu entries are menu items and the button is a real button",
      'role="menuitem"' in _items["saved-menu-item"] and 'type="button"' in _items["saved-open-btn"])
check("the page starts the module and prepares the menu for the clicked message",
      "ChatSaved.init({" in CHAT and "ChatSaved.prepareMenu(contextMenuMessageId)" in CHAT
      and "jumpToMessage: (channelId, messageId) => jumpToChannelMessage(channelId, messageId)" in CHAT)
check("/chat?saved=1 opens the Saved view once and is removed from the address", "sp.has('saved')" in CHAT and "ChatSaved.open()" in CHAT)
check("portal.js opens the Saved view for a reminder that has no message, in the bell list and the desktop alert",
      PORTAL.count("data.saved") >= 2 and PORTAL.count("window.ChatSaved.open()") >= 2 and PORTAL.count("/chat?saved=1") >= 2)
check("the module never builds markup from text and keeps nothing in browser storage",
      "innerHTML" not in CODE and "insertAdjacentHTML" not in CODE and "onclick" not in CODE and "localStorage" not in CODE
      and "sessionStorage" not in CODE)
check("the module sends no WebSocket frame and opens none", "WebSocket" not in CODE and ".send(" not in CODE)
check("no emoji or symbol characters in the module or the new markup",
      not SYMBOLS.search(JS)
      and not any(SYMBOLS.search(v) for v in _items.values()))
_css = CHAT[CHAT.index("/* Saved messages: the member's own marker"):CHAT.index("/* Message highlight animation for scroll-to */")]
check("the Saved view fills the screen and its buttons reach 44 px on a phone",
      "@media (max-width: 640px), (hover: none)" in _css and re.search(r"min-height:\s*44px", _css) is not None
      and "width: 100%" in _css)
check("a focused message and the menu items show a focus ring", "message:focus-visible" in _css and "context-menu-item:focus-visible" in _css)

node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    for tz in ("Europe/Berlin", "America/New_York"):
        out = subprocess.run([node, str(ROOT / "tests" / "chat_saved_harness.js"), str(STATIC / "js" / "chat-saved.js"),
                              str(STATIC / "js" / "portal.js")], capture_output=True, text=True, timeout=120,
                             env={**os.environ, "TZ": tz})
        lines = [json.loads(ln[7:]) for ln in out.stdout.splitlines() if ln.startswith("RESULT ")]
        check(f"the harness ran in {tz}", len(lines) >= 40 and out.returncode == 0, (out.stderr or out.stdout)[-500:])
        for r in lines:
            check(f"[{tz}] {r['name']}", r["ok"], r["detail"])

if failed:
    print(f"\ntest_saved_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_saved_client: all checks passed")
