"""Every pattern= attribute of the sign-in page compiles under the v flag, which is how browsers compile it.

Run: venv/bin/python tests/test_login_patterns.py

An unescaped trailing '-' in a character class is a syntax error under the v flag: the browser logs a console
error and drops the check. The pattern is compiled with node the way the browser does, ^(?:pattern)$ with the
v flag, and must accept the same names as before. Skipped with a note when node is missing. When the installed
node is too old to know the v flag (before node 20), the same rule is checked on the text: inside a character class
a '-' must be written \\- unless it sits between two characters as a range.

Failing on the old code: [a-zA-Z0-9_-]+ did not compile.
"""

import html
import json
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


node = shutil.which("node")
if not node:
    print("SKIP: node is not installed, the patterns were not compiled")
    sys.exit(0)

text = (ROOT / "static" / "login.html").read_text(encoding="utf-8")
patterns = [html.unescape(m.group(1)) for m in re.finditer(r"""\bpattern="([^"]*)\"""", text)]
check("login.html has pattern attributes", len(patterns) >= 2, str(len(patterns)))
# The server decides what a valid sign-in name is (older accounts may hold a dot or an at sign), so the
# browser must not block the sign-in field on a pattern of its own.
_signin = re.search(r'<input[^>]*id="login-username"[^>]*>', text, re.S)
check("the sign-in name field has no pattern of its own", bool(_signin) and "pattern=" not in _signin.group(0))

NAMES_OK = ["abc", "A_b-c", "user_name-1", "a-b", "-ab", "ab-", "x" * 30]
NAMES_BAD = ["ab", "a b", "a.b", "x" * 31, "a/b", ""]

V_FLAG = subprocess.run([node, "-e", "try { new RegExp('a', 'v'); } catch (e) { process.exit(3); }"],
                        capture_output=True, text=True, timeout=30).returncode == 0
if not V_FLAG:
    print("note: this node does not know the v flag; checking character classes on the text instead")


def classes_ok(p):
    """True when every '-' inside a [...] class is escaped or is a range between two characters."""
    i = 0
    while i < len(p):
        if p[i] == "\\":
            i += 2
            continue
        if p[i] == "[":
            j = i + 1
            body = []
            while j < len(p) and p[j] != "]":
                if p[j] == "\\":
                    body.append(p[j:j + 2])
                    j += 2
                else:
                    body.append(p[j])
                    j += 1
            for k, ch in enumerate(body):
                if ch == "-" and (k == 0 or k == len(body) - 1):
                    return False
            i = j
        i += 1
    return True


for p in patterns:
    if not V_FLAG:
        check(f"pattern {p!r} has no unescaped '-' at the edge of a class", classes_ok(p))
        try:
            re.compile("^(?:" + p.replace("\\-", "-") + ")$")
        except re.error as e:
            check(f"pattern {p!r} still compiles", False, str(e))
        continue
    script = (
        "const p = process.argv[1]; let re;"
        "try { re = new RegExp('^(?:' + p + ')$', 'v'); } catch (e) { console.log(JSON.stringify({error: String(e)})); process.exit(0); }"
        "console.log(JSON.stringify({ok: process.argv.slice(2).map(s => re.test(s))}));"
    )
    try:
        out = subprocess.run([node, "-e", script, p] + NAMES_OK + NAMES_BAD, capture_output=True, text=True, timeout=30)
        res = json.loads(out.stdout.strip() or "{}")
    except Exception as e:  # noqa: BLE001
        check(f"pattern {p!r} compiles under the v flag", False, str(e))
        continue
    check(f"pattern {p!r} compiles under the v flag", "ok" in res, res.get("error", ""))
    if p.startswith("[a-zA-Z0-9_") and "ok" in res:
        got = res["ok"]
        if "{3,30}" in p:
            want = [True, True, True, True, True, True, True] + [False] * len(NAMES_BAD)
        else:
            # the sign-in field has no length bound in the pattern; the length is the field's own limits
            want = [True] * len(NAMES_OK) + [False, False, False, True, False, False]
            want[len(NAMES_OK) + 0] = got[len(NAMES_OK) + 0]  # "ab": any length is allowed by + alone
            got = got[:len(NAMES_OK)] + [got[len(NAMES_OK) + 1], got[len(NAMES_OK) + 2], got[len(NAMES_OK) + 4]]
            want = [True] * len(NAMES_OK) + [False, False, False]
        check(f"pattern {p!r} accepts the same names", got == want, str(got))

if failures:
    print(f"\n{len(failures)} FAILED")
    sys.exit(1)
print("\nall passed")
