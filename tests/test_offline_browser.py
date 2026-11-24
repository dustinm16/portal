"""No smoke check or tool of the project lets a browser phone home.

A headless Chromium contacts its maker's hosts within seconds of starting (component updates, account and model
services, dictionaries). A smoke check dials nothing outside this machine, so none of them starts a browser: the page
scripts run against a fake DOM under Node instead (tests/test_overlay_client.py and its neighbours). The screenshot
tool is not a test but must not phone home either: it starts Chromium with background networking, component updates,
sync, default apps and field trials switched off and with a resolver rule that leaves only the demo host and
loopback resolvable (this was checked once in a net log of a real Chromium 156; a test cannot repeat that without a
browser, so this one reads the source).

Run: venv/bin/python tests/test_offline_browser.py
"""

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ("" if ok else f"  ({detail})"), flush=True)
    if not ok:
        failed.append(name)


BROWSER_WORDS = re.compile(r"chromium|chrome|remote-debugging|headless|playwright|selenium|webdriver", re.I)
for path in sorted((ROOT / "tools" / "smoke_checks").glob("*.py")) + [ROOT / "tools" / "stage_smoke.py"]:
    if not path.exists():
        continue
    code = [l for l in path.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#")]
    body = "\n".join(code)
    # words in a docstring that say no browser is started are fine; a launch is not
    launches = re.findall(r"(?:create_subprocess_exec|Popen|subprocess\.run|sync_playwright|which)\([^)]*(?:chrom|headless)", body, re.I)
    check(f"{path.name} starts no browser", not launches and "--remote-debugging" not in body and "--headless" not in body,
          str(launches)[:200])

src = (ROOT / "tools" / "make_screenshots.py").read_text(encoding="utf-8")
tree = ast.parse(src)
flags = None
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "OFFLINE_CHROMIUM_ARGS":
        flags = ast.literal_eval(node.value)
check("make_screenshots.py has the OFFLINE_CHROMIUM_ARGS list", isinstance(flags, list))
for need in ("--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
             "--disable-field-trial-config", "--no-first-run", "--no-proxy-server"):
    check(f"the screenshot browser gets {need}", flags is not None and need in flags)
rule = re.search(r'def offline_host_rules\(\).*?return f"([^"]+)"', src, re.S)
rule = rule.group(1) if rule else ""
check("the resolver rule maps the demo host, keeps loopback and makes every other name not found, in that order",
      0 <= rule.find("MAP {DEMO_HOST} 127.0.0.1") < rule.find("EXCLUDE 127.0.0.1") < rule.find("MAP * ~NOTFOUND"), rule)
launch = src[src.index("playwright.chromium.launch("):]
launch = launch[:launch.index("self.contexts")]
check("the launch uses both the rule and the flags, and the old demo-host-only rule is gone",
      "offline_host_rules()" in launch and "*OFFLINE_CHROMIUM_ARGS" in launch and "MAP {DEMO_HOST} 127.0.0.1\"" not in launch, launch)
check("the launch is not a persistent profile (Playwright's throwaway profile is used)",
      "launch_persistent_context" not in src and "user_data_dir" not in src)

if failed:
    print(f"\ntest_offline_browser: {len(failed)} FAILED")
    sys.exit(1)
print("\ntest_offline_browser: all checks passed")
