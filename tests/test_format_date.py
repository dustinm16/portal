"""formatDate shows a date the same whether the server wrote it as a database timestamp
("2026-11-20 10:00:00", UTC with no zone) or as isoformat() with a zone ("...+00:00", "...Z").

The API key window's Expires column and the "Expires:" line of a new key got a dash for every
key with an expiry because the helper appended a Z to a string that already had a zone.

Run: venv/bin/python tests/test_format_date.py
Needs node; skipped without it.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def function_source(text, name):
    """The text of `function name(...) { ... }`, found by matching braces."""
    m = re.search(r"function " + name + r"\(", text)
    if not m:
        return ""
    i = text.index("{", m.start())
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():j + 1]
    return ""


CASES = [
    "2026-11-20 10:00:00",
    "2026-11-20T10:00:00",
    "2026-11-20T10:00:00Z",
    "2026-11-20T10:00:00+00:00",
    "2026-11-20T10:00:00.123456+00:00",
    "2026-11-20T12:00:00+02:00",
    "2026-11-20T05:00:00-05:00",
    "2026-11-20 09:00:00",
]

node = shutil.which("node")
if not node:
    print("skip: node is not installed, formatDate was not run")
    sys.exit(0)

for label in ("admin.js", "user-connections.js", "ssh-keys.js"):
    src = function_source((ROOT / "static" / "js" / label).read_text(), "formatDate")
    check(f"{label} defines formatDate", bool(src))
    script = src + "\nconsole.log(JSON.stringify(%s.map(formatDate)));" % json.dumps(CASES)
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, env={**os.environ, "TZ": "UTC"})
    got = json.loads(out.stdout) if out.returncode == 0 else out.stderr
    if not isinstance(got, list):
        check(f"{label} formatDate runs", False, str(got))
        continue
    ten_utc = got[0]
    check(f"{label}: a database timestamp is a real date", ten_utc not in ("", "—") and "Invalid" not in ten_utc, ten_utc)
    check(f"{label}: Z, +00:00 and fractional seconds give the same as the timestamp",
          got[1] == got[2] == got[3] == got[4] == got[0], str(got[:5]))
    check(f"{label}: an offset is converted to UTC, not ignored", got[5] == got[0] and got[6] == got[0], str(got[5:7]))
    check(f"{label}: a different time stays different", got[7] != got[0], str(got[7]))

if failures:
    print(f"\ntest_format_date: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_format_date: all checks passed")
