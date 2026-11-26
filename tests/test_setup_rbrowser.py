"""The optional setup step for the Web Browser on the server (setup.py, release 1.25.0).

The step only offers and explains: default No, nothing is run without a yes, nothing is written, the feature
stays off. Its table of binaries and packages is pinned against rbrowser_launch (what availability() looks for and
PACKAGE_OF, read as source text so nothing here imports the heavy module) and the privacy sentences against the
page. No package is installed and no command runs: which, the prompt and subprocess.run are replaced.

Usage: venv/bin/python tests/test_setup_rbrowser.py
"""

import contextlib
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import setup  # noqa: E402

failed = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ("" if ok else f"  ({str(detail)[:300]})"), flush=True)
    if not ok:
        failed.append(name)


class Run:
    """setup._setup_rbrowser() with a fake PATH, a scripted answer and a recording subprocess.run."""

    def __init__(self, present, answer=False, apt=True, rc=0):
        self.calls, self.prompts, self.out = [], [], ""
        have = set(present) | ({"apt-get"} if apt else set())
        saved = (setup.shutil.which, setup._prompt_yes_no, setup.subprocess.run)
        setup.shutil.which = lambda n, *a, **k: f"/usr/bin/{n}" if n in have else None

        def ask(prompt, default_yes=True):
            self.prompts.append((prompt, default_yes))
            return answer
        setup._prompt_yes_no = ask

        def fake_run(cmd, *a, **k):
            self.calls.append(list(cmd))
            return type("R", (), {"returncode": rc, "stdout": "", "stderr": "boom"})()
        setup.subprocess.run = fake_run
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                setup._setup_rbrowser()
        finally:
            setup.shutil.which, setup._prompt_yes_no, setup.subprocess.run = saved
        self.out = buf.getvalue()


ALL = {"chromium", "Xvfb", "x11vnc", "xauth", "xrandr", "xsel", "iptables", "ip6tables"}

# 1. nothing missing: no offer, no command
r = Run(ALL)
check("everything installed: no question and no command", not r.prompts and not r.calls and "Nothing to do" in r.out, r.out)

# 2. missing: asks with default No, and No runs nothing
r = Run({"Xvfb", "x11vnc", "xauth"}, answer=False)
check("missing packages are listed", "chromium x11-xserver-utils xsel" in r.out, r.out)
check("the question defaults to No", len(r.prompts) == 1 and r.prompts[0][1] is False, r.prompts)
check("No runs nothing and says how to do it later", not r.calls and "Skipped" in r.out, r.out)

# 3. Yes: exactly one apt-get call, only the missing packages, no recommends, never a shell
r = Run({"Xvfb", "x11vnc", "xauth"}, answer=True)
cmd = r.calls[0] if r.calls else []
check("Yes runs one command", len(r.calls) == 1, r.calls)
tail = cmd[cmd.index("apt-get"):] if "apt-get" in cmd else []
check("it is apt-get install -y --no-install-recommends with the missing packages only",
      tail == ["apt-get", "install", "-y", "--no-install-recommends", "chromium", "x11-xserver-utils", "xsel"], cmd)
check("noninteractive, and sudo only when not root", "DEBIAN_FRONTEND=noninteractive" in cmd and (cmd[0] == "sudo") == (setup.os.geteuid() != 0), cmd)
check("after the install it says the feature is still off", "still off" in r.out, r.out)

# 4. a failed install leaves setup going and the feature off
r = Run(set(), answer=True, rc=100)
check("a failed apt-get is reported and does not raise", "apt-get failed" in r.out and "stays off" in r.out, r.out)

# 5. no apt: the package line is printed, nothing is asked or run
r = Run({"Xvfb"}, answer=True, apt=False)
check("no apt: no question, no command, the package line printed", not r.prompts and not r.calls and "apt-get install -y --no-install-recommends chromium" in r.out, r.out)

# 6. chromium-browser counts as chromium; iptables is optional and never a package to install here
r = Run((ALL - {"chromium", "iptables", "ip6tables"}) | {"chromium-browser"})
check("chromium-browser satisfies the chromium need", not r.calls and "Nothing to do" in r.out, r.out)
check("missing iptables is mentioned as optional, and is not in the install line", "Optional: iptables" in r.out)
r = Run(ALL - {"iptables", "ip6tables", "xsel"}, answer=True)
check("optional iptables is not installed with the required packages", r.calls and r.calls[0][-1] == "xsel" and "iptables" not in r.calls[0], r.calls)

# 7. the text: explains, states the privacy sentences, never switches on, no window-manager package
r = Run({"Xvfb"}, answer=False)
html = (ROOT / "static" / "rbrowser.html").read_text()
m = re.search(r'<p id="rb-privacy">(.*?)</p>', html, re.S)
page = m.group(1).replace("&#39;", "'").replace("&apos;", "'") if m else ""
check("the privacy sentences printed are the first two of the page's statement", bool(page) and page.startswith(setup.RBROWSER_PRIVACY), page[:140])
check("it says the feature stays off until an administrator switches it on", "OFF until a superadmin switches it on" in r.out)
check("no window manager package is mentioned", "matchbox" not in r.out.lower() and "matchbox" not in "".join(p for _, p in setup.RBROWSER_BINARIES))
src = (ROOT / "setup.py").read_text()
body = src[src.index("def _setup_rbrowser"):src.index("def _setup_venv_and_deps")]
check("the step writes no .env key and touches no database", "_write_env" not in body and "sqlite" not in body.lower() and "open(" not in body)
check("the step is in the wizard, after fail2ban and before the admin user",
      src.index("_setup_fail2ban()\n") < src.index("_setup_rbrowser()\n") < src.index("_setup_admin_user(venv_python)\n"))

# 8. the table agrees with what the launcher looks for
launch = (ROOT / "rbrowser_launch.py").read_text()
m = re.search(r'for tool in \(("Xvfb"[^)]*)\):', launch)
tools = re.findall(r'"([^"]+)"', m.group(1)) if m else []
table = {n for names, _ in setup.RBROWSER_BINARIES for n in names}
check("every binary availability() looks for is in the setup table", bool(tools) and set(tools) <= table, tools)
check("the table names chromium and chromium-browser as availability() does", {"chromium", "chromium-browser"} <= table and '("chromium", "chromium-browser")' in launch)
pk = dict(re.findall(r'"([^"]+)": "([^"]+)"', launch[launch.index("PACKAGE_OF = {"):launch.index("}", launch.index("PACKAGE_OF = {"))]))
bad = [(n, p) for names, p in setup.RBROWSER_BINARIES for n in names if pk.get(n) != p and not (n == "chromium-browser" and p == "chromium")]
check("every package in the setup table is the one rbrowser_launch.PACKAGE_OF names", not bad, bad)
check("python3 and the sandbox needs that setup cannot install are left to the check in Admin", "sandbox check in Admin decides" in r.out)

if failed:
    print(f"\ntest_setup_rbrowser: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_setup_rbrowser: all checks passed")
