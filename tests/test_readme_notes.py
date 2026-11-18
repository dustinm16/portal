"""The README's upgrade notes for 1.13.0 state what an operator must know
before upgrading, and no bullet is repeated.

Run: venv/bin/python tests/test_readme_notes.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
text = (ROOT / "README.md").read_text(encoding="utf-8")
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


m = re.search(r"### Upgrade notes for 1\.13\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.13.0' section", m is not None)
section = m.group(1) if m else ""
bullets = [b.strip() for b in re.findall(r"^- (.*)$", section, re.M)]
check("the section is a list of bullets", len(bullets) >= 10, str(len(bullets)))
check("no bullet is repeated (same first 80 characters)",
      len({b[:80] for b in bullets}) == len(bullets))
low = section.lower()


def says(name, *needles):
    check(f"states: {name}", all(n.lower() in low for n in needles), str(needles))


says("the security event log exists", "security event log", "security_events")
says("it stores IP addresses and user agents", "ip address and user agent")
says("retention defaults to 180 days and how to change it", "180 days", "retention_security_events_days")
says("only a superadmin reads it", "only a superadmin can read the log")
says("sessions store IP and user agent", "sessions now store the ip address and user agent")
says("the Cloudflare refresh is the only scheduled outbound request this release adds (two named older exceptions)",
     "only scheduled outbound request", "game servers", "portal-update.timer")
says("what the refresh fetches", "https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
says("the refresh sends no portal data", "sends no portal data")
says("how to turn the refresh off", "cf_ranges_refresh", "turn it off")
says("scanner blocking is still off by default", "scanner blocking", "still off by default", "PROBE_BLOCK_STRIKES")
says("NEVER_BAN_CIDRS", "NEVER_BAN_CIDRS")
says("the unblock and clear-bans commands", "server.py unblock", "server.py clear-bans")
says("canonical block addresses", "canonical address form")
says("the caution before trusting a proxy", "really is your own proxy")
check("it does not claim the sessions values are shown to nobody else", "nobody else" not in low)
check("the scanner-blocking default is stated once as off, never as on",
      low.count("still off by default") == 1 and "scanner blocking is on" not in low)

if failures:
    print(f"\ntest_readme_notes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_readme_notes: all checks passed")
