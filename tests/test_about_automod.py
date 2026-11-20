"""The Auto-Moderation section of the about page describes what automod really does.

Real behaviour (server.apply_automod): every triggered rule refuses the message or edit and
tells its author in a private error; only the timeout and mute actions also penalise the
member (staff are exempt), and the room sees an AutoMod notice. 'warn' and 'delete' behave the
same. The page used to say Delete is silent and Warn is a separate message.

Run: venv/bin/python tests/test_about_automod.py
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import server  # noqa: E402


def section() -> str:
    html = (ROOT / "static" / "about.html").read_text(encoding="utf-8")
    start = html.index("<h3>Automod Actions</h3>")
    return html[start:html.index("<!-- File Manager -->", start)]


def test_the_actions_text_matches_the_code():
    text = re.sub(r"<[^>]+>", " ", section()).lower()
    for action in server._AUTOMOD_ACTIONS:
        assert action in text, f"the about page does not mention the {action} action"
    assert "silently" not in text, "Delete is not silent: the author is told"
    assert "private error" in text and "not sent" in text
    # the two penalties are described as what they add to the block
    assert "timed out" in text and "muted" in text and "5 minutes" in text


if __name__ == "__main__":
    test_the_actions_text_matches_the_code()
    print("ok   test_the_actions_text_matches_the_code")
