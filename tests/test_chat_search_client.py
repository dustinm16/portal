"""The chat page's search client: markup and wiring checks on chat.html, then the
search block (suggestion chips, result rendering, the result click) runs under
Node (tests/chat_search_harness.js) against a small fake page. Without Node that
part is reported as skipped.

What a browser must still show (the look of the chips, the highlight after a
click on a result) is listed in the release notes, not here.

Run: venv/bin/python tests/test_chat_search_client.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
CHAT = (STATIC / "chat.html").read_text()
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failed.append(name)


check("the page no longer parses operators itself", "parseSearchFilters" not in CHAT and "filters.in_channel" not in CHAT)
check("the page sends the query as typed", "searchUrl(searchState.q" in CHAT and "q=${encodeURIComponent(q)}" in CHAT)
check("result clicks use the jump-to-message path", "jumpToChannelMessage(sourceId, messageId)" in CHAT)
check("results carry ids in data attributes", 'data-source-id="${Number(r.source_id)}"' in CHAT and "navigateToSearchResult('${" not in CHAT)
check("chips use only loaded state", "channelsList" in CHAT[CHAT.index("function searchKnownNames"):CHAT.index("function renderSearchChips")]
      and "fetch(" not in CHAT[CHAT.index("function searchSuggestions"):CHAT.index("function renderSearchChips")])

check("the Load more click goes through loadMoreSearch, which guards a second click",
      "loadMoreSearch(moreBtn)" in CHAT and "fetchSearchPage(true); return;" not in CHAT
      and "if (searchMoreBusy) return;" in CHAT[CHAT.index("async function loadMoreSearch"):CHAT.index("function searchResultHtml")])

# ---- documentation ---------------------------------------------------------------
README = (ROOT / "README.md").read_text()
notes = README[README.index("### Upgrade notes for 1.14.0"):]
for needle in ("from:name", "has:link", "is:pinned", "400", "search_backfill_done", "search_backfill_channel_last_id",
               "batches of 200", "has_link", "chat_fts_map", "Anonymous posts", "staged instance", "10 per minute"):
    check("README upgrade notes mention: " + needle, needle in notes)
for label, text in (("docs/API.md", (ROOT / "docs" / "API.md").read_text()),
                    ("api-docs.html", (STATIC / "api-docs.html").read_text())):
    check(f"{label} documents the operators, the new fields and the backfill flag",
          all(n in text for n in ("has:link", "is:pinned", "before:", "capped", "index_complete", "display_name", "has_more")),
          label)

if shutil.which("node"):
    proc = subprocess.run(["node", str(ROOT / "tests" / "chat_search_harness.js"), str(STATIC / "chat.html")],
                          capture_output=True, text=True, timeout=60)
    rows = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    check("the harness ran", proc.returncode == 0 and len(rows) >= 20, proc.stderr[-300:])
    for r in rows:
        check(r["name"], r["ok"], r["detail"])
else:
    print("skip the Node checks: node is not installed")

if failed:
    print(f"\ntest_chat_search_client: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_chat_search_client: all checks passed")
