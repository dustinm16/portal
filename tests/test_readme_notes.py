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
says15("staff-subject sign-in bursts are capped", "at most 5 of the 10 reserved slots", "25 of the 30 slots")
says15("alert sub-caps and the notice", "smaller cap of its own", "at most one per 10 minutes", "which limit held them back")
says15("certificate check and update check outbound rules", "heuristic", "no new scheduled outbound request")
says15("rollback", "rollback")
rb = next((b for b in b15 if b.startswith("Rollback")), "").lower()
check("1.15.0 rollback does not claim a non-generic hook cannot be signed", "cannot be signed" not in rb and "looks like a generic" not in rb)
check("1.15.0 rollback says 1.14.0 skips hooks without a secret and shows the destination URL",
      "no signing secret" in rb and "skips" in rb and "full destination url" in rb and "credential" in rb, rb[:120])

# --- 1.16.0 notes: stream access --------------------------------------------------
m16 = re.search(r"### Upgrade notes for 1\.16\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.16.0' section after the 1.15.0 one",
      m16 is not None and text.index("### Upgrade notes for 1.16.0") > text.index("### Upgrade notes for 1.15.0"))
sec16 = m16.group(1) if m16 else ""
b16 = [b.strip() for b in re.findall(r"^- (.*)$", sec16, re.M)]
check("1.16.0 notes are bullets and none is repeated", len(b16) >= 8 and len({b[:80] for b in b16}) == len(b16), str(len(b16)))
low16 = sec16.lower()


def says16(name, *needles):
    check(f"1.16.0 states: {name}", all(n.lower() in low16 for n in needles), str(needles))


says16("the one rule and who is let in", "one rule", "owner", "administrators", "moderator is not an administrator", "allow_unauthenticated", "current")
says16("every refusal is a 404 with one body", "`404`", "same body", "never `401` or `403`", "rotated")
says16("the links that stop working, all of them", "links that stop working", "private", "without the open link",
       "other websites", "`live_` key", "scoped")
says16("what keeps working", "open link on", "vlc", "access-control-allow-origin: *")
says16("CORS and caching of everything else", "no wildcard cors", "cache-control: private")
says16("cache time and invalidation", "5 seconds", "signed out", "rotated")
says16("internal consumers", "relays", "recorder", "thumbnail capture", "loopback", "authhttpexclude")
says16("webrtc media is outside the rule", "webrtc media", "keeps flowing")
says16("the query token is not passed on", "?token=", "no longer passed on")
says16("the database columns and the one static version that moved", "three columns", "golive_message", "`?v=43`", "golive_audience", "stream_follow", "stream_cards")
says16("the go-live cooldown", "one announcement per 10 minutes", "stored in the database", "stream state lock", "`stream.offline`")
says16("the go-live message", "200 characters", "`{streamer}`, `{title}` and `{url}`", "`{0.__class__}`", "literal text")
says16("the payload change, no keys, where the URL comes from", "`public_key` is removed", "`public_key`", "`url`", "public_base_url", "host header")
says16("who is told, and private streams reach system hooks only", "who is told", "administrators", "only to system hooks", "members who may watch")
# the note must match the renderer: braces around a placeholder stay, the placeholder inside is filled
check("1.16.0 does not say {{title}} is shown exactly as typed",
      not re.search(r"\{\{title\}\}`?,? is shown exactly as typed", sec16) and "`{0}` and `{{title}}`" not in sec16)
says16("braces around a placeholder stay and the placeholder inside is filled", "braces around a placeholder stay",
       "`{{title}}`", "filled in")

says16("follows: who may follow, one 404, the cap", "following and go-live announcements", "`put /api/streams/{id}/follow`", "same `404`", "200 follows")
says16("who follows whom is private: a count for the owner, no list for anyone", "private", "number of followers", "never a name", "no route that returns one")
says16("a stream made private loses its follows and they do not come back", "making a stream private removes every follow", "does not bring old follows back")
says16("the audience: new streams follow, old streams stay on everyone", "golive_audience", "new stream defaults to followers", "exist before the upgrade stay on everyone")
says16("the hook answers at once and the cooldown still holds", "answers at once", "background task", "batches of 100", "10-minute cooldown")
says16("cards: stream_card, fallback text, no key or thumbnail, retention, not for a stream that is not public", "stream_card", "plain-text fallback", "no key and no thumbnail", "chat retention removes them", "not public")
says16("the announce channel: public streams only, checked again, deleted when private", "announce channel", "stream_announce_channel_id", "every member", "again at every go-live", "deleted from the announce channel")
says16("the old localStorage gate is replaced", "localstorage", "follow again")
says16("the live-now strip", "live now", "/api/streams/live")
check("1.16.0 does not still say a public stream notifies everybody except the owner as before",
      "for a public stream everybody except the owner, as before" not in sec16)

check("1.16.0 does not still say a WHIP publish announces nothing",
      "does not announce a go-live" not in sec16 and "whip" in low16 and "same background announcement" in low16)
says16("the fixes made after review", "fixes made after review", "activity feed", "plain playlist or segment file name",
       "lone surrogate", "announce channel setting is validated", "`public_base_url`")
says16("rollback", "rollback", "1.15.0")
says16("what was not tested", "not tested", "vlc", "cloudflare")

# --- 1.17.0 notes: viewer counts ----------------------------------------------------
m17 = re.search(r"### Upgrade notes for 1\.17\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.17.0' section after the 1.16.0 one",
      m17 is not None and text.index("### Upgrade notes for 1.17.0") > text.index("### Upgrade notes for 1.16.0"))
sec17 = m17.group(1) if m17 else ""
low17 = sec17.lower()


def says17(name, *needles):
    check(f"1.17.0 states: {name}", all(n.lower() in low17 for n in needles), str(needles))


says17("the portal keeps the count and the old figure was wrong", "kept by the portal", "recorder", "`rtmp_` token")
says17("what counts and the heartbeat", "playlist", "whep", "/api/stream/{key}/viewer", "same `404`", "`429`")
says17("identity", "by account", "x-viewer-id", "salted hash")
says17("bounds and timing", "5000", "5 anonymous", "15 seconds", "20 seconds", "only when it changes")
says17("privacy", "in memory only", "no address", "only a number")
says17("peak and unique", "last_peak_viewers", "last_unique_viewers", "nullable", "restart")
says17("rollback", "rollback", "1.16.0")
says17("what was not tested", "not tested", "hls.js", "safari", "mediamtx")

# --- README: the live streaming section and the pictures of it ----------------------
ls = re.search(r"### Live Streaming\n(.*?)\n### ", text, re.S)
lstext = (ls.group(1) if ls else "").lower()
check("Live Streaming describes read access, follows, audience, message, cards, announce channel and the strip",
      all(n in lstext for n in ("private means private", "follow", "who is told", "go-live message", "card",
                                "announce channel", "live now")), lstext[:80])
check("Live Streaming no longer says private streams send no go-live notification",
      "private streams send no go-live notification" not in lstext)
shots = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
for pic in ("streams", "streams-settings", "chat-golive"):
    check(f"README shows docs/screenshots/{pic}.png and the file exists",
          f"docs/screenshots/{pic}.png" in text and (shots / f"{pic}.png").is_file())
mk = (Path(__file__).resolve().parent.parent / "tools" / "make_screenshots.py").read_text()
check("make_screenshots takes the stream pictures", all(f'@shot("{n}")' in mk for n in ("streams", "streams-settings", "chat-golive")))

if failures:
    print(f"\ntest_readme_notes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_readme_notes: all checks passed")
