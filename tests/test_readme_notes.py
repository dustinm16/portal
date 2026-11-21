"""The README's upgrade notes for 1.13.0 state what an operator must know
before upgrading, and no bullet is repeated.

Run: venv/bin/python tests/test_readme_notes.py
"""

import os
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

says17("game field", "live title and game", "60 characters", "`game`", "`stream_info`", "`{game}`", "/api/streams/games")
says17("game privacy", "judged per socket", "owner and administrators", "never contributes its game")
says17("game not tested", "datalist", "40 viewers behind one address")

says17("chat controls: the helper and its order", "`chat_mod_level(channel, user)`", "looked up on every call", "stream mod", "real stream chat",
       "stream b", "no longer read", "does not let them watch")
says17("chat controls: who acts on whom", "never on the owner, another mod or global staff", "never on staff", "role order",
       "same text", "`message_id`", "global moderator can now ban", "only the owner, its mods and staff can start a poll")
says17("chat controls: a timeout does not replace a penalty above the actor", "replaces the member's earlier penalty", "site-wide penalty", "automod penalty", "earlier penalty stays")
says17("chat controls: the mods routes", "/api/streams/{id}/mods", "same `404`", "at most 20", "not banned", "`409`", "/api/chat/channels/{id}/members")
says17("chat controls: audit", "audit entry", "actor", "target", "channel", "were not audited before")
says17("chat controls: slow mode", "`set_slowmode`", "0, 5, 15 or 30", "`slowmode_changed`", "http guard", "`mod_level`", "`stream_role`")
says17("chat controls: watch page", "pop-out", "pinned", "poll", "badge", "go-live cards", "plain text")
says17("chat controls: playback ban", "`_stream_read_allowed`", "same `404`", "cleared at every ban and unban", "`403` with `{\"banned\": true}`",
       "never confirms a private stream", "never banned from viewing", "open-link stream can still be watched signed out", "already flowing")
says17("chat controls: not tested", "no browser", "real hls playlist", "temporary database")
says17("chat controls: lifting a stream ban", "lifting a stream ban", "administrator or a superadmin", "by ban id", "`pinned_by_username`",
       "can lift a ban on staff")

# one coherent section: one statement of each fact, and what the three lanes said agrees
bullets17 = [b.strip() for b in re.findall(r"^- (.*)$", sec17, re.M)]
check("1.17.0: no bullet is repeated (same first 80 characters)", len({b[:80] for b in bullets17}) == len(bullets17))
check("1.17.0: no bullet is a left-over per-lane 'Not tested (...)', 'Fixes after review' or 'Database and static files'",
      not any(re.match(r"\*\*(Not tested \(|Fixes after review|Database and static files)", b) for b in bullets17))
sv = re.findall(r"`streams\.js`[^.]*?version (\d+)|`streams\.js` (?:is|moved to) (?:now )?(?:version |`\?v=)(\d+)", sec17)
index_html = (Path(__file__).resolve().parent.parent / "static" / "index.html").read_text()
real_v = re.search(r"streams\.js\?v=(\d+)", index_html).group(1)
stated = {a or b for a, b in sv}
check("1.17.0: exactly one streams.js version is stated and it is the one index.html loads",
      stated == {real_v}, f"stated {stated}, index.html {real_v}")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)
import server as _server  # noqa: E402
check("1.17.0: the heartbeat limit stated is the one in the code",
      f"{_server._VIEWER_BEAT_LIMIT} requests per minute" in sec17 and f"{_server._VIEWER_REFUSED_LIMIT} refusals per minute" in sec17)
says17("external RTMPS and RTSP readers are no longer counted", "rtmps or rtsp port", "no longer counted")
says17("an external WHEP player must send the heartbeat", "external whep player", "heartbeat route", "`patch`")

# --- README: the live streaming section and the pictures of it ----------------------
ls = re.search(r"### Live Streaming\n(.*?)\n### ", text, re.S)
lstext = (ls.group(1) if ls else "").lower()
check("Live Streaming describes read access, follows, audience, message, cards, announce channel and the strip",
      all(n in lstext for n in ("private means private", "follow", "who is told", "go-live message", "card",
                                "announce channel", "live now")), lstext[:80])
check("Live Streaming no longer says private streams send no go-live notification",
      "private streams send no go-live notification" not in lstext)
shots = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
for pic in ("streams", "streams-settings", "chat-golive", "watch-chat"):
    check(f"README shows docs/screenshots/{pic}.png and the file exists",
          f"docs/screenshots/{pic}.png" in text and (shots / f"{pic}.png").is_file())
mk = (Path(__file__).resolve().parent.parent / "tools" / "make_screenshots.py").read_text()
check("make_screenshots takes the stream pictures", all(f'@shot("{n}")' in mk for n in ("streams", "streams-settings", "chat-golive", "watch-chat")))

# --- 1.17.0: the feature sections and the other docs say what the code does ------------------
ms = re.search(r"### Moderation and Anonymous Posting\n(.*?)\n### ", text, re.S)
mstext = (ms.group(1) if ms else "").lower()
check("Live Streaming describes the portal-side count, last session figures, game field, live updates, mods and the playback ban",
      all(n in lstext for n in ("viewer count", "last session", "game", "stream mod", "pin a message", "slow mode", "poll", "badge", "banned")),
      lstext[:80])
check("Live Streaming says direct RTMPS and RTSP readers are not counted", "rtmps" in lstext and "not counted" in lstext)
check("Moderation describes stream mods and keeps stream slow mode apart from the channel one",
      all(n in mstext for n in ("stream mod", "time out", "5, 15 or 30 seconds", "5, 10 or 30 seconds")), mstext[:80])
api_html = (ROOT / "static" / "api-docs.html").read_text(encoding="utf-8")
check("api-docs.html states the heartbeat limit of the code, not an old one",
      f"{_server._VIEWER_BEAT_LIMIT} per minute" in api_html and "120 per minute" not in api_html
      and f"{_server._VIEWER_REFUSED_LIMIT} refused" in api_html)
about = (ROOT / "static" / "about.html").read_text(encoding="utf-8")
check("about.html does not say the viewer count is polled every 10 seconds", "polled every 10 seconds" not in about)
check("about.html says the owner and stream mods can pin in a stream chat", "stream mod" in about.lower())
api_md = (ROOT / "docs" / "API.md").read_text(encoding="utf-8")
check("docs/API.md does not say that only stream owners ban", "Stream owners can ban users from their stream's chat." not in api_md)

# --- 1.18.0 notes: expiring shares and grants -----------------------------------------
import apikey_policy as _apikey_policy  # noqa: E402

# --- 1.18.0 notes: API key least privilege --------------------------------------------
m18 = re.search(r"### Upgrade notes for 1\.18\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.18.0' section after the 1.17.0 one",
      m18 is not None and text.index("### Upgrade notes for 1.18.0") > text.index("### Upgrade notes for 1.17.0"))
sec18 = m18.group(1) if m18 else ""
low18 = sec18.lower()


def says18(name, *needles):
    check(f"1.18.0 states: {name}", all(n.lower() in low18 for n in needles), str(needles))


says18("the durations, the UI default and the API default", "`1h`", "`8h`", "`1d`", "`7d`", "`30d`", "`90d`", "`never`",
       "30 days preselected", "left out the api still means `never`", "`expires_at`", "`400`")
says18("where it is enforced and that the clock decides, not the sweeper", "one predicate", "not at the sweeper", "no end time")
says18("the sweeper", "every 60 seconds", "`connection.share_expired`", "`service.grant_expired`", "`4010`", "up to 60 seconds")
says18("revoke closes sessions", "revoking a share", "leaving a shared connection", "deleting a connection")
says18("views", "`get /api/me/shares`", "`get /api/admin/grants`")
says18("what is not there", "no read-only", "no reminder", "no guest link")
says18("database", "`connection_shares.expires_at`", "`service_grants.expires_at`", "nullable", "1.17.0's own database code")
says18("rollback makes unswept rows permanent", "rollback", "1.17.0", "permanent again")
says18("what was not tested", "not tested", "ssh", "browser", "cloudflare")
check("1.18.0: the sweeper interval and the close code stated are the ones in the code",
      "every 60 seconds" in low18 and f"`{_server.GRANT_ENDED_CLOSE_CODE}`" in sec18 and _server._GRANT_SWEEP_SECONDS == 60)
check("1.18.0: the user-connections and dashboard versions stated are the ones the pages load (terminal.js moved on in 1.20.0)",
      re.search(r"user-connections\.js\?v=55", (ROOT / "static" / "index.html").read_text())
      and "`user-connections.js` is now version 55" in sec18
      and re.search(r"dashboard\.js\?v=59", (ROOT / "static" / "index.html").read_text()) and "`dashboard.js` 59" in sec18
      and "`terminal.js` 6" in sec18)
check("1.18.0: the admin.js and portal.css versions stated are the ones the 1.18.0 pages loaded (admin.js moved on in 1.19.0)",
      re.search(r"js/admin\.js\?v=39", (ROOT / "static" / "index.html").read_text()) and "`admin.js` 38" in sec18
      and re.search(r"css/portal\.css\?v=55", (ROOT / "static" / "index.html").read_text()) and "`portal.css` 55" in sec18)
check("README feature section says a share can expire", "the card shows the time left" in text and "All grants on the portal" in text)
check("docs/API.md documents expires_in, the 400 case and both new routes",
      all(n in (ROOT / "docs" / "API.md").read_text(encoding="utf-8") for n in ("expires_in", "GET /api/me/shares", "/api/admin/grants", "connection.share_expired", "service.grant_expired")))
check("api-docs.html documents expires_in and both new routes",
      all(n in (ROOT / "static" / "api-docs.html").read_text(encoding="utf-8") for n in ("expires_in", "/api/me/shares", "/api/admin/grants", "4010")))

# --- 1.18.0 notes: stored SSH password -----------------------------------------------
says18("the stored password fields and modes", "store password", "prompt each time", "`credential_mode`", "`prompt`", "`stored`",
       "existing connections are not changed", "no migration")
says18("the password is write-only and the API change", "write-only", "`has_stored_password`", "`has_password` is no longer sent",
       "breaking for api clients", "`stored_password_cleared`", "without knowing the password")
says18("host keys", "unpinned or changed host key", "skips the host key check", "`400`", "behaviour change")
says18("revoke closes the terminal and sftp", "revoking a share", "local test ssh server")
says18("rollback", "rolling back", "ignores it")
says18("what was not tested for the stored password", "not tested", "no ssh key storage", "asyncssh's own")
check("README says in Sharing Access that a share of a stored password gives a shell without the password",
      "without knowing the password" in text[text.index("### Sharing Access"):text.index("### File Management")])
check("docs/API.md and api-docs.html document the stored password",
      all(n in (ROOT / "docs" / "API.md").read_text(encoding="utf-8") for n in ("has_stored_password", "credential_mode", "stored_password_cleared"))
      and all(n in (ROOT / "static" / "api-docs.html").read_text(encoding="utf-8") for n in ("has_stored_password", "credential_mode", "stored_password_cleared")))
says18("API keys: binding", "allowed_cidrs", "at most 10", "`/0`", "`\"any\"`", "generic `401`", "api_key_ip_denied")
says18("API keys: proxy trust must be clean first", "proxy-trust self-check is clean", "trusted_proxies", "/api/admin/proxy-trust")
says18("API keys: scope registry and the 400", "apikey_policy.py", "/api/api-keys/scopes", "`400`", "required_scopes")
says18("API keys: default expiry and what breaks", "90 days", "\"never\"", "breaking", "expires_in_days")
says18("API keys: last used and stale", "last_used_ip", "created_ip", "once a minute", "stale")
says18("API keys: migration, existing keys and rollback", "allowed_cidrs", "existing keys are unchanged", "works from any address again after a rollback")
says18("API keys: what is not tested", "not tested", "browser", "cloudflare")
check("1.18.0: the key defaults stated are the ones in the code",
      f"{_apikey_policy.DEFAULT_EXPIRY_DAYS} days" in sec18 and f"at most {_apikey_policy.MAX_CIDRS}" in sec18
      and f"from 1 to {_apikey_policy.MAX_EXPIRY_DAYS}" in sec18 and f"{_apikey_policy.STALE_DAYS} days" in sec18)
api_md18 = (ROOT / "docs" / "API.md").read_text(encoding="utf-8")
api_html18 = (ROOT / "static" / "api-docs.html").read_text(encoding="utf-8")
check("docs/API.md and api-docs.html describe the binding, the default expiry, the scope route and the stale flag",
      all(n in api_md18 for n in ("allowed_cidrs", "last_used_ip", "GET /api/api-keys/scopes", "expires in 90 days", "stale"))
      and all(n in api_html18 for n in ("allowed_cidrs", "last_used_ip", "/api/api-keys/scopes", "Omitted: 90 days", "stale")))
says18("API keys: only a sign-in creates keys, playback cache keyed on the address", "apikey-", "`403`", "only a sign-in creates keys", "caller's address")
check("docs/API.md and api-docs.html say an API key cannot create keys",
      "A key cannot create keys" in api_md18 and "API key gets 403" in api_html18)
check("docs/API.md no longer says an omitted expiry never expires", "omit (or `0`) for a key that never expires" not in api_md18)
# --- 1.18.0 notes: sign-in blocking ---------------------------------------------------

says18("sign-in blocking: off by default, the counter, no lockout", "sign-in blocking (off by default)",
       "nothing is blocked until you turn it on", "no per-account lockout", "/api/admin/login-ban")
says18("sign-in blocking: doubling, cap, never permanent", "doubles", "24 hours", "never permanent", "7 days")
says18("sign-in blocking: exemptions", "never-ban helper", "`never_ban_cidrs`", "30 days", "any account signed in from")
says18("sign-in blocking: stored bans, events, unblock", "`kind` `login`", "survives a restart", "ip_blocked", "clear-bans")
says18("scanner blocking: stored and escalating, still off", "`probe_block_strikes` is still 0", "kind `probe`", "no longer says")
says18("sign-in blocking: migration and rollback", "blocked_ips.kind", "ip_ban_history", "login_addresses", "1.17.0 starts on the migrated database")
says18("sign-in blocking: what is not tested", "not tested", "browser", "cloudflare", "rotating ipv6")
_d = _server.LOGIN_BAN_DEFAULTS
check("1.18.0: the sign-in blocking defaults stated are the ones in the code",
      _d["enabled"] is False and f"{_d['max_failures']} failures within {_d['find_minutes']} minutes" in sec18
      and f"blocked for {_d['base_minutes']} minutes" in sec18 and "15 minutes, 30, 60, up to 24 hours" in sec18
      and _server.AUTO_BAN_CAP_SECONDS == 24 * 3600)
check("docs/API.md and api-docs.html describe the sign-in blocking settings route and the kinds",
      all(n in api_md18 for n in ("GET /api/admin/login-ban", "PUT /api/admin/login-ban", "`login_ban_changed`", "`probe`"))
      and all(n in api_html18 for n in ("/api/admin/login-ban", "login_ban_changed", "<code>probe</code>")))
check("docs no longer say an automatic block is held in memory only",
      "Nothing in 1.13.0 writes an automatic block" not in api_md18 and "Nothing in 1.13.0 writes an automatic block" not in api_html18)
# --- 1.18.0 notes: logged-out limit on /proxy, /search and /browser ---------------------

says18("logged-out limit: on by default, paths, 429, valid credential decides",
       "logged-out limit on /proxy, /search and /browser (on by default)", "30 requests a minute", "`429`", "`retry-after`",
       "bogus, forged, empty or revoked", "300 assets", "no argon2")
says18("logged-out limit: api keys, never-limited paths, ipv6", "api keys:", "verified", "`/login`, `/api`, `/admin`, `/health`", "/64")
says18("logged-out limit: exemptions, table, event, setting, breaking change",
       "never-ban helper", "bounded at 10000", "`rate_limited`", "`logged_out_proxy`", "/api/admin/proxy-limit",
       "`proxy_limit.update`", "`proxy_limit_changed`", "changed behaviour", "shared address", "feeds no ban")
says18("logged-out limit: migration and rollback", "no migration", "`proxy_limit_enabled`", "`proxy_limit_per_minute`", "1.17.0 ignores the rows")
says18("logged-out limit: what is not tested", "not tested", "browser", "cloudflare", "real client address")
_pl = _server.PROXY_LIMIT_DEFAULTS
check("1.18.0: the logged-out limit defaults stated are the ones in the code",
      _pl == {"enabled": True, "per_minute": 30} and "30 requests a minute" in sec18
      and "5 to 600 requests a minute" in sec18 and _server.PROXY_LIMIT_LIMITS == {"per_minute": (5, 600)}
      and "bounded at 10000" in sec18 and _server._PROXY_LIMIT_TABLE_MAX == 10000)
check("docs/API.md and api-docs.html describe the logged-out limit route",
      all(n in api_md18 for n in ("GET /api/admin/proxy-limit", "PUT /api/admin/proxy-limit", "`proxy_limit_changed`", "`429`", "`Retry-After`"))
      and all(n in api_html18 for n in ("/api/admin/proxy-limit", "proxy_limit_changed", "<code>429</code>", "Retry-After")))
about18 = (ROOT / "static" / "about.html").read_text(encoding="utf-8")
check("about.html no longer lists scopes the code does not check", "<code>chat</code> &mdash; Send and receive chat messages" not in about18)


# --- 1.18.0 notes: one coherent section, not five lanes pasted together -------------------
b18 = [b.strip() for b in re.findall(r"^- (.*)$", sec18, re.M)]
lead18 = [re.match(r"\*\*([^*]+)\*\*", b).group(1) if re.match(r"\*\*([^*]+)\*\*", b) else "" for b in b18]
check("1.18.0: no bullet is repeated (same first 80 characters)", len({b[:80] for b in b18}) == len(b18))
for lead in ("Database.", "Static files.", "Rollback.", "Not tested."):
    check(f"1.18.0: exactly one '{lead}' bullet", lead18.count(lead) == 1, str(lead18.count(lead)))
check("1.18.0: no left-over per-lane Database, Static files, Rollback or Not tested bullet",
      not [x for x in lead18 if re.match(r"(Database|Static files|Rollback|Rolling back|Not tested)\b", x)
           and x not in ("Database.", "Static files.", "Rollback.", "Not tested.")], str(lead18))
check("1.18.0: the section has no blank line inside its list", "\n\n- " not in sec18.strip("\n"))
check("1.18.0: no contradiction about static files (one says only admin.html changed, one that nothing did)",
      "is the only static file that changed" not in sec18 and "No static file changed" not in sec18)
check("1.18.0: the logged-out limit answer is described with its Cache-Control header, not as having none",
      "carries no cache header" not in sec18 and "`Cache-Control: no-store`" in sec18)
import secevents as _secevents  # noqa: E402
check("1.18.0: the key-refused-by-address event is counted per key, with the cap per address",
      "per source and minute, because" not in sec18 and "per key" in sec18
      and f"at most {_secevents.KEY_ROWS_PER_ADDRESS} distinct keys" in sec18)
check("1.18.0: scopes are kept as written and an empty list is refused; only administrators name service scopes",
      "exactly as written" in sec18 and "empty list" in low18 and "only administrators" in low18 and "zone id" in low18)
check("1.18.0: two keys sharing a prefix both work (every candidate, at most 4)", "two live keys can share one" in low18 and "at most 4" in low18)
check("1.18.0: an automatic ban on an address that became exempt is dropped and never enforced",
      "never enforced at request time" in low18 and "exempt now" in low18)
check("1.18.0: an offence is counted only when a ban row was written", "only when a ban row was written" in low18)
check("1.18.0: deleting an account and the 2 second wait are stated", "deleting a user account" in low18 and "2 seconds" in low18)

# --- 1.18.0 pictures --------------------------------------------------------------------
for pic in ("share-expiry", "api-keys", "admin-signin-limits"):
    check(f"README shows docs/screenshots/{pic}.png and the file exists",
          f"docs/screenshots/{pic}.png" in text and (shots / f"{pic}.png").is_file())
check("make_screenshots takes the 1.18.0 pictures", all(f'@shot("{n}")' in mk for n in ("share-expiry", "api-keys", "admin-signin-limits")))

# --- 1.19.0 notes: notification levels --------------------------------------------------
m19 = re.search(r"### Upgrade notes for 1\.19\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.19.0' section after the 1.18.0 one",
      m19 is not None and text.index("### Upgrade notes for 1.19.0") > text.index("### Upgrade notes for 1.18.0"))
low19 = (m19.group(1) if m19 else "").lower()
for name, needles in (("the table and the routes", ("channel_notify_prefs", "/api/chat/channels/{id}/notify")),
                      ("the levels and the mute lengths", ("mentions only", "nothing", "1, 8 or 24 hours")),
                      ("stream chats and the level menu", ("api-only", "follows the stream")),
                      ("a mention still notifies while muted but not at level nothing", ("still notifies", "unless the level is nothing")),
                      ("the signal holds the channel id only and never reaches a non-reader", ("channel_activity", "nothing else", "same read check")),
                      ("the memory cache and the verdict memory", ("60 seconds", "forgotten whenever access is lost")),
                      ("the sound is local, with quiet hours and one tab", ("webaudio", "localstorage", "only one plays")),
                      ("the star migration", ("portal_notif_channels", "level all")),
                      ("the alert bug", ("wrong channel", "own tag")),
                      ("the static versions", ("chat-notify.js", "version 46")),
                      ("rollback", ("1.18.0", "ignores the table")),
                      ("what is not tested", ("not tested", "no browser", "phone", "push service", "cloudflare"))):
    check(f"1.19.0 states: {name}", all(n in low19 for n in needles), str(needles))

# --- 1.19.0 notes: @here and @everyone ---------------------------------------------------
for name, needles in (("the switch, the frame and who sets it", ("allow_mass_mentions", "set_mass_mentions", "stream mod", "mass_mentions_changed")),
                      ("who may use it", ("chat_mod_level", "global staff")),
                      ("the limit and its notice", ("60 seconds", "mass_mention_limited", "uses no slot")),
                      ("the recipients", ("@everyone** notifies every member who may read", "appear offline", "mentions only still gets it")),
                      ("the cap and the single transaction", ("500 members", "one transaction", "one row per member")),
                      ("anonymous senders", ("anonymous sender", "dropped")),
                      ("automod weight", ("mention_spam", "counts as 5", "staff are not exempt", "`max_mentions`", "cannot be chosen as a username or a nickname")),
                      ("code spans and no groups", ("code span", "no named groups")),
                      ("the column and the rollback", ("chat_channels.allow_mass_mentions", "1.18.0 ignores `allow_mass_mentions`")),
                      ("what is not proven", ("check_massmention", "real push service", "thousands of members"))):
    check(f"1.19.0 states: @here/@everyone {name}", all(n in low19 for n in needles), str(needles))
_defaults = (ROOT / "server.py").read_text()
check("1.19.0: the cap and the cooldown stated are the ones in the code",
      "MASS_MENTION_CAP = 500" in _defaults and "MASS_MENTION_COOLDOWN = 60.0" in _defaults and "MASS_MENTION_WEIGHT = 5" in _defaults)

# --- 1.19.0 notes: web push foundation --------------------------------------------------
for name, needles in (("what exists", ("web push foundation", "user settings > phone notifications", "webpush.py", "push_subscriptions", "no new dependency")),
                      ("the device routes and who may use them", ("/api/push/subscriptions", "/api/push/unsubscribe", "/api/push/config", "api keys (even with the all-scope)", "10 devices")),
                      ("the session lifecycle", ("session that registered it", "log out", "password change", "deleting an account", "sign out other sessions", "only expires")),
                      ("the allow-list and the outbound rules", ("fcm.googleapis.com", "*.push.apple.com", "*.notify.windows.com", "port 443", "no redirects", "4096 bytes", "never logged")),
                      ("the key storage and the flag", ("encrypted in the settings table", "push_enabled", "push_vapid_subject")),
                      ("the sender", ("send_push", "30 pushes per user per minute", "429", "retry-after", "build_payload")),
                      ("the worker, scope and policy", ("no fetch handler", "service-worker-allowed: /push-sw/", "worker-src 'none'", "/manifest.webmanifest")),
                      ("the migration and the rollback", ("create table if not exists", "1.18.0 starts on the migrated database")),
                      ("the static files", ("`push.js` is new", "`portal.js` is now version 46", "`admin.js` is now version 39")),
                      ("what is not proven", ("not tested", "no browser", "real push service", "cloudflare", "rfc 8291 appendix vector"))):
    check(f"1.19.0 states: web push {name}", all(n in low19 for n in needles), str(needles))
check("docs/API.md and api-docs.html describe the push routes",
      all(x in (ROOT / "docs" / "API.md").read_text() for x in ("/api/push/subscriptions", "/api/admin/push/test", "/sw.js"))
      and all(x in (ROOT / "static" / "api-docs.html").read_text() for x in ("/api/push/subscriptions", "/api/admin/push", "/sw.js")))
check("the limits stated for web push are the ones in the code",
      "MAX_DEVICES_PER_USER = 10" in (ROOT / "webpush.py").read_text() and "USER_RATE_LIMIT = 30" in (ROOT / "webpush.py").read_text()
      and "SEND_CONCURRENCY = 8" in (ROOT / "webpush.py").read_text() and "PRUNE_AFTER_FAILURES = 8" in (ROOT / "webpush.py").read_text()
      and "_PUSH_SUBSCRIBE_LIMIT = 10 " in _defaults)

# --- 1.19.0 notes: web push delivery ------------------------------------------------------
for name, needles in (("when a push is sent", ("when a push is sent", "no open chat socket", "@here never pushes", "followers only", "may watch the stream at the moment of the push")),
                      ("no text, no names", ("no message text, no sender or author name and no stream title", "anonymous sender", "new direct message", "you were mentioned in #channel", "<streamer> is live")),
                      ("the tap url and the collapse", ("/chat?dm=<conversation>", "/chat?channel_id=<id>&message_id=<id>", "/watch/<stream>", "`topic` header", "opaque keyed hash")),
                      ("the per-kind switches", ("push_prefs", "/api/push/prefs", "streams you follow going live")),
                      ("the settings screens", ("send test push to my devices", "install hint", "ios 16.4", "never as markup", "embedded browser")),
                      ("sign-out and backups", ("post /logout", "never in the url", "encryption_salt", "same public key")),
                      ("what is not proven", ("push delivery", "not proven at all", "installed ios or android app", "delivery latency"))):
    check(f"1.19.0 states: web push delivery {name}", all(n in low19 for n in needles), str(needles))
check("the README names the same tag, topic and kinds as the code",
      '"golive"' in _defaults and 'PUSH_KINDS = ("dm", "mention", "golive")' in (ROOT / "database.py").read_text()
      and "def _push_topic" in _defaults)
check("docs/API.md and api-docs.html describe the prefs route and POST /logout",
      all(x in (ROOT / "docs" / "API.md").read_text() for x in ("/api/push/prefs", "POST /logout"))
      and all(x in (ROOT / "static" / "api-docs.html").read_text() for x in ("/api/push/prefs", "/logout")))

# --- 1.19.0: one coherent section, the administrator statement, What You Get ----------------
sec19 = m19.group(1) if m19 else ""
for lead in ("**Database.**", "**Static files.**", "**Rollback.**", "**Not tested.**"):
    check(f"1.19.0 has exactly one bullet '{lead}'", len(re.findall(r"^- " + re.escape(lead), sec19, re.M)) == 1)
check("1.19.0 keeps no leftovers of the lane and fix-pass assembly",
      all(x not in low19 for x in ("fix pass", "not tested (web push)", "unchanged (version 46)")))
for name, needles in (("push services are contacted only for members who enabled it", ("google, mozilla, apple or microsoft", "only for members who", "enabled notifications")),
                      ("what those servers can see", ("that a notification was sent to a device and when", "its size", "encrypted", "no message text")),
                      ("how to switch it off", ("admin > settings", "push notifications enabled", "push_enabled")),
                      ("iOS needs the home screen", ("ios", "home screen", "16.4")),
                      ("the portal's own address is visible to the push service", ("vapid", "push_vapid_subject"))):
    check(f"1.19.0 tells administrators: {name}", all(n in low19 for n in needles), str(needles))
get = text.split("## What You Get", 1)[1].split("\n## ", 1)[0]
check("What You Get has a 'Phone Notifications' part", "### Phone Notifications" in get)
check("the chat part of What You Get describes levels, mute, badges and mass mentions",
      all(x in get.split("### Direct Messages")[0] for x in ("bell", "mute", "@everyone", "@here", "badge")))
check("the old 'enable desktop alerts' star sentence is gone from the chat part",
      "Enable desktop alerts to get browser notifications" not in text)
_pages = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "static").glob("*.html")}
for js, ver in (("portal.js", 46), ("push.js", 4), ("admin.js", 39), ("chat-notify.js", 1)):
    loaded = {m for t_ in _pages.values() for m in re.findall(rf"/static/js/{re.escape(js)}\?v=(\d+)", t_)}
    check(f"1.19.0 states {js} as version {ver} and the pages load exactly that",
          loaded == {str(ver)} and re.search(rf"`{re.escape(js)}`[^.]*?version {ver}", sec19) is not None, str(loaded))
check("the README names the three pictures and they exist",
      all(f"docs/screenshots/{n}.png" in text and (ROOT / "docs" / "screenshots" / f"{n}.png").is_file()
          for n in ("chat-notify-menu", "phone-notifications", "admin-push")))
_mk = (ROOT / "tools" / "make_screenshots.py").read_text()
check("make_screenshots takes the 1.19.0 pictures", all(f'@shot("{n}")' in _mk for n in ("chat-notify-menu", "phone-notifications", "admin-push")))
check("api-docs.html and docs/API.md both describe the rebind call",
      "rebind" in (ROOT / "docs" / "API.md").read_text() and "rebind" in _pages["api-docs.html"])

# --- 1.20.0 notes: recordings -------------------------------------------------------------
m20 = re.search(r"### Upgrade notes for 1\.20\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.20.0' section directly before the 1.19.0 one",
      m20 is not None and text.index("### Upgrade notes for 1.20.0") < text.index("### Upgrade notes for 1.19.0")
      and text.index("### Upgrade notes for 1.20.0") > text.index("### Upgrade notes for 1.18.0"))
low20 = (m20.group(1) if m20 else "").lower()
for name, needles in (("recording is off unless the flag is a real boolean true", ("off", '"recording": true', "real boolean")),
                      ("output only, never keystrokes, and what the remote echoes is recorded", ("output only", "keystrokes are never recorded", "echo")),
                      ("0600 files, the cap and retention", ("0600", "50 mb", "retention_recordings_days")),
                      ("a shared connection records the person at the keyboard", ("shared", "at the keyboard")),
                      ("the banner comes from the server before any output", ("this session is recorded", "connected", "before any output")),
                      ("only administrators, 404 for everyone else, 403 for API keys", ("administrators", "404", "every api key gets 403")),
                      ("the routes and the audit actions", ("/api/recordings", "/cast", "recording_play", "recording_download", "recording_delete")),
                      ("the refused rows", ("symlink", "outside the folder", "refused")),
                      ("why asciinema-player is not used", ("asciinema-player", "webassembly", "wasm-unsafe-eval")),
                      ("the table rebuild and what deleting a connection does", ("rebuilt", "service_id", "deleting a connection")),
                      ("the static versions", ("terminal.js", "version 7", "recordings-admin.js", "version 1")),
                      ("rollback", ("1.19.0", "migrated database")),
                      ("what is not tested", ("not tested", "no browser", "no microphone", "cloudflare", "real ssh server"))):
    check(f"1.20.0 states: {name}", all(n in low20 for n in needles), str(needles))
_pages20 = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "static").glob("*.html")}
for js, ver in (("terminal.js", 7), ("recordings-admin.js", 1)):
    loaded = {m for t_ in _pages20.values() for m in re.findall(rf"/static/js/{re.escape(js)}\?v=(\d+)", t_)}
    check(f"1.20.0 states {js} as version {ver} and the pages load exactly that", loaded == {str(ver)}, str(loaded))
check("api-docs.html and docs/API.md both describe the recordings routes",
      all("/api/recordings" in t_ and "recording_play" in t_ for t_ in ((ROOT / "docs" / "API.md").read_text(), _pages20["api-docs.html"])))
# --- 1.20.0 notes: voice moderation and the room cap -----------------------------------
m20 = re.search(r"### Upgrade notes for 1\.20\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.20.0' section directly before the 1.19.0 one",
      m20 is not None and text.index("### Upgrade notes for 1.20.0") < text.index("### Upgrade notes for 1.19.0"))
low20 = (m20.group(1) if m20 else "").lower()
for name, needles in (("who is refused at join", ("timed out or muted", "locked room", "60 seconds", "resume")),
                      ("the cap, its range and who sets it", ("voice_room_cap", "2 to 25", "default 8", "superadmin", "does not remove anyone")),
                      ("the behaviour change", ("behaviour change", "ninth")),
                      ("the frames and the rule", ("voice_kick", "voice_server_mute", "voice_lock_room", "chat_mod_level", "equal or higher")),
                      ("server mute is advisory and a kick is enforced against normal clients", ("advisory", "modified client")),
                      ("the lock and the block are in memory", ("in memory", "restart")),
                      ("signalling is re-checked", ("dropped unless the sender is currently in that room",)),
                      ("a penalty ends the call", ("timeout or mute", "removes the member from that channel's voice room")),
                      ("the static version", ("voice.js", "version 15")),
                      ("rollback", ("1.19.0", "ignores the setting")),
                      ("what is not tested", ("not tested", "no browser", "microphone", "cloudflare"))):
    check(f"1.20.0 states: {name}", all(n in low20 for n in needles), str(needles))
check("1.20.0: the cap range and the default stated are the ones in the code",
      all(re.search(p_, (ROOT / "server.py").read_text()) for p_ in (
          r"VOICE_CAP_DEFAULT, VOICE_CAP_MIN, VOICE_CAP_MAX = 8, 2, 25", r"VOICE_KICK_BLOCK = 60\.0")))
_vj = {m for p_ in ("chat.html", "watch.html") for m in re.findall(r"/static/js/voice\.js\?v=(\d+)", (ROOT / "static" / p_).read_text())}
check("1.20.0 states voice.js as version 15 and chat.html and watch.html load exactly that", _vj == {"15"}, str(_vj))

# --- 1.20.0 notes: voice connection quality ---------------------------------------------
_vq_js = (ROOT / "static" / "js" / "voice.js").read_text()
for name, needles in (("what is shown", ("voice connection quality", "1 to 4 small bars", "every 4 seconds", "in place", "direct", "relayed")),
                      ("how it is scored", ("packetsreceived", "currentroundtriptime", "last interval", "never the lifetime totals", "worst one", "scoreQuality".lower())),
                      ("the thresholds", ("2 percent loss, 150 ms round trip and 30 ms jitter", "5 percent, 300 ms and 60 ms", "10 percent, 500 ms and 120 ms")),
                      ("the firefox fallback and privacy", ("nominated pair", "unknown", "no address, candidate ip or port")),
                      ("the hint", ("not advanced for 6 seconds", "self-muted nor server muted", "never closes, restarts or renegotiates")),
                      ("the lifecycle", ("pauses while the page is hidden", "stops when you leave")),
                      ("no server change and no breaking change", ("nothing new is sent to the server", "docs/api.md", "**breaking changes.** none")),
                      ("what is not tested", ("not tested (connection quality)", "no browser", "real `getstats` shapes"))):
    check(f"1.20.0 quality states: {name}", all(n in low20 for n in needles), str(needles))
check("1.20.0 quality: the thresholds stated are the ones in the code",
      all(s_ in _vq_js for s_ in ("QUALITY_POLL_MS = 4000", "QUALITY_NOAUDIO_MS = 6000", "QUALITY_LOSS_PCT = [2, 5, 10]",
                                  "QUALITY_RTT_MS = [150, 300, 500]", "QUALITY_JITTER_MS = [30, 60, 120]")))
# --- 1.20.0 notes: per-channel retention and prune ---------------------------------------
m20r = re.search(r"### Upgrade notes for 1\.20\.0\n(.*?)(?=\n## |\n### )", text, re.S)
check("README has an 'Upgrade notes for 1.20.0' section before the 1.19.0 one",
      m20r is not None and text.index("### Upgrade notes for 1.20.0") < text.index("### Upgrade notes for 1.19.0"))
low20r = (m20r.group(1) if m20r else "").lower()
for name, needles in (
        ("administrators only set it, moderators cannot", ("administrators only", "moderator", "cannot change")),
        ("the cap setting and its range", ("retention_chat_max_days", "3650", "1 to 3650")),
        ("empty means follow the global setting and nothing changes until set", ("follow the global setting", "nothing changes until an administrator")),
        ("a channel with a value is no longer touched by the global retention", ("no longer touched",)),
        ("file retention keeps the message and never exceeds it", ("file retention", "(file removed)", "can never be longer than the message retention")),
        ("pinned messages are kept", ("pinned messages are kept",)),
        ("shortening needs confirm and is audited", ("confirm", "would remove", "channel_retention_change")),
        ("the next-cleanup notice and its limits", ("next cleanup about", "not known until the cleanup task has started")),
        ("prune: who may, dry run, expected count, margin", ("chat_mod_level", "dry run", "expected", "max(2, 2 percent)")),
        ("prune: background batches, frame, one audit entry, one at a time", ("batches of 200", "messages_pruned", "chat_prune", "one prune per channel")),
        ("prune: unreadable and no-level callers get the 404 of a missing channel", ("404",)),
        ("prune: rank rules of a single delete, own posts, user filter counts 0", ("rank", "lower role", "counts and removes 0")),
        ("prune: anonymous ids of a user-filtered prune go to staff and the author only", ("not told which ids", "staff and the author", "next load")),
        ("prune status counts go to staff and the starter only", ("`removed`, `total` and `files`", "stream owner or stream mod gets `running` and `status` only")),
        ("anonymous posts are not revealed", ("anonymous", "never matches an anonymous message", "neither the frames nor the audit entry")),
        ("DMs and stream chats are not covered", ("direct messages", "stream's own chat")),
        ("the rollback consequence", ("rolling back", "retention_chat_days")),
        ("a Not tested paragraph", ("**not tested.**", "no browser", "not proven"))):
    check(f"1.20.0 states: retention {name}", all(n in low20r for n in needles), str(needles))
_pages20 = {p_.name: p_.read_text(encoding="utf-8") for p_ in (ROOT / "static").glob("*.html")}
_loaded20 = {m_ for t_ in _pages20.values() for m_ in re.findall(r"/static/js/chat-retention\.js\?v=(\d+)", t_)}
check("1.20.0 states chat-retention.js as version 1 and the pages load exactly that",
      _loaded20 == {"1"} and re.search(r"`chat-retention\.js` version 1", m20r.group(1) if m20r else "") is not None, str(_loaded20))
_srv20 = (ROOT / "server.py").read_text(encoding="utf-8")
check("the margin and the batch size stated are the ones in the code",
      "return max(2, int(expected) // 50)" in _srv20 and "PRUNE_BATCH = 200" in _srv20)
check("the new audit actions are in the admin filter and the API reference",
      all(a in _pages20["admin.html"] and a in _pages20["api-docs.html"] for a in ("channel_retention_change", "chat_prune")))
check("docs/API.md and api-docs.html both describe the retention route, the prune route and the frame",
      all(x in (ROOT / "docs" / "API.md").read_text() and x in _pages20["api-docs.html"]
          for x in ("/retention", "/prune", "messages_pruned")))
check("the 1.20.0 retention notes carry no emoji", not re.search("[\U0001F000-\U0001FFFF\u2600-\u27BF]", m20r.group(1) if m20r else ""))

if failures:
    print(f"\ntest_readme_notes: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_readme_notes: all checks passed")
