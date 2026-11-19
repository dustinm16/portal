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
     "only scheduled outbound request this release adds", "game servers", "portal-update.timer")
check("the old claim that the refresh is the only request the portal makes by itself is gone",
      "the portal makes by itself" not in low)
says("what the refresh fetches", "https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
says("the refresh sends no portal data", "sends no portal data")
says("how to turn the refresh off", "cf_ranges_refresh", "turn it off")
says("scanner blocking is still off by default", "scanner blocking", "still off by default", "PROBE_BLOCK_STRIKES")
says("NEVER_BAN_CIDRS", "NEVER_BAN_CIDRS")
says("the unblock and clear-bans commands", "server.py unblock", "server.py clear-bans")
says("canonical block addresses", "canonical address form")
says("the caution before trusting a proxy", "really is your own proxy")
env_example = (ROOT / "." / ".env.example").read_text(encoding="utf-8")
check(".env.example has a commented NEVER_BAN_CIDRS example in a documentation range",
      re.search(r"^# NEVER_BAN_CIDRS=(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d+/\d+\s*$", env_example, re.M) is not None)
check("it does not claim the sessions values are shown to nobody else", "nobody else" not in low)
check("the scanner-blocking default is stated once as off, never as on",
      low.count("still off by default") == 1 and "scanner blocking is on" not in low)

# --- 1.15.0 notes: notification channels --------------------------------------
m15 = re.search(r"### Upgrade notes for 1\.15\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.15.0' section after the 1.14.0 one",
      m15 is not None and text.index("### Upgrade notes for 1.15.0") > text.index("### Upgrade notes for 1.14.0"))
sec15 = m15.group(1) if m15 else ""
b15 = [b.strip() for b in re.findall(r"^- (.*)$", sec15, re.M)]
check("1.15.0 notes are bullets and none is repeated", len(b15) >= 10 and len({b[:80] for b in b15}) == len(b15), str(len(b15)))
low15 = sec15.lower()


def says15(name, *needles):
    check(f"1.15.0 states: {name}", all(n.lower() in low15 for n in needles), str(needles))


says15("the formats and that generic stays signed", "ntfy", "gotify", "discord", "slack", "hmac-sha256")
says15("what leaves the machine by default", "title", "one-line summary", "include_details", "200 characters")
says15("message.created is opt-in and never private", "message.created", "`*` does not include it", "private channel")
says15("credentials are write-only", "never returned again", "encrypted")
says15("429 handling", "retry-after", "10 minutes", "3 waits", "never counts")
says15("allow_private rules", "allow_private", "superadmin using a browser login session", "link-local", "listening ports", "webhook_allow_private")
says15("system webhooks and the admin section", "system webhook", "admin > webhooks", "system-only", "webhook.test")
says15("the test button reports a status", "status code")
says15("the database change", "six columns", "rebuilt once", "user_id")
says15("no static version moved", "no `?v=` number moved")
says15("stage mode sink", "stage_webhook_sink_port")
says15("alert events exist and nothing is subscribed by default", "alert events", "nothing is subscribed", "`*` never includes an alert")
says15("alert payload rules", "include_details", "anonymous", "an anonymous member")
says15("alert storm bounds", "30 per 10 minutes", "alerts.suppressed", "three consecutive failed health checks", "14, 7 and 1 days")
says15("alert sub-caps and the notice", "smaller cap of its own", "at most one per 10 minutes", "which limit held them back")
says15("certificate check and update check outbound rules", "heuristic", "no new scheduled outbound request")
says15("rollback", "rollback")
rb = next((b for b in b15 if b.startswith("Rollback")), "").lower()
check("1.15.0 rollback does not claim a non-generic hook cannot be signed", "cannot be signed" not in rb and "looks like a generic" not in rb)
check("1.15.0 rollback says 1.14.0 skips hooks without a secret and shows the destination URL",
      "no signing secret" in rb and "skips" in rb and "full destination url" in rb and "credential" in rb, rb[:120])

if failures:
    print(f"\ntest_readme_notes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_readme_notes: all checks passed")
