"""Outgoing webhook formats and the event-class split.

Pure functions, no database and no network. `server._deliver_webhook` calls
`format_payload` once per delivery; everything a third-party service sees in a
non-generic format is decided here:

* generic: the original signed JSON body, unchanged (HMAC-SHA256 header).
* ntfy, gotify, discord, slack: a minimal message built from a fixed catalogue
  per event: a title, a one-line summary and the portal name. Nothing is copied
  from the event payload unless the hook has include_details, and then only the
  fields on that event's allow-list (never the raw payload, which can carry
  keys). Message text is cut to 200 characters. Mentions are neutralised.

Per-format secrets (a Gotify application token, an ntfy bearer token or basic
login) arrive in `secret_config` and go into request headers only. They are
never part of a returned description of the request.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets as _secrets
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone

FORMATS = ("generic", "ntfy", "gotify", "discord", "slack")

# The one allow-list of events a user hook may subscribe to or receive. Anything not
# listed here (webhook.test, every ops or security event added later) is system-only:
# a new event is closed to user hooks until it is added to this set on purpose.
USER_EVENTS = frozenset({
    "message.created", "message.deleted", "stream.live", "stream.offline",
    "user.joined", "user.connected", "user.disconnected",
})

# Events a system hook may also receive. Listed for the admin form; the rule that
# keeps them from user hooks is the allow-list above, not this set.
SYSTEM_ONLY_EVENTS = frozenset({"webhook.test"})

# Presence events: never sent in a non-generic format for a member whose status
# preference is appear-offline (the dispatcher checks this, see server).
PRESENCE_EVENTS = frozenset({"user.connected", "user.disconnected"})

# Only delivered to a non-generic hook that lists them by name, never through "*".
NON_GENERIC_EXPLICIT_ONLY = frozenset({"message.created"}) | PRESENCE_EVENTS

# Events about chat messages: a non-generic hook only gets them for a channel an
# ordinary member can read (the dispatcher checks this, see server.fire_webhook_event).
CHAT_EVENTS = frozenset({"message.created", "message.deleted"})
STREAM_EVENTS = frozenset({"stream.live", "stream.offline"})

MESSAGE_TEXT_LIMIT = 200

# Service limits (characters unless stated).
DISCORD_TITLE_LIMIT = 250          # embed title: 256
DISCORD_DESCRIPTION_LIMIT = 3900   # embed description: 4096
DISCORD_FOOTER_LIMIT = 200         # embed footer: 2048
SLACK_TEXT_LIMIT = 3000            # a section block's text: 3000
NTFY_MESSAGE_BYTES = 3900          # ntfy message body: 4096 bytes
NTFY_TITLE_LIMIT = 120

MAX_SLEEP_REASON = 120


def event_subscribed(events, event: str, *, kind: str = "user", fmt: str = "generic") -> bool:
    """Whether a hook (its event list, kind and format) receives `event`.

    Enforced at dispatch as well as at subscribe time, so a row written by an
    older version or by hand cannot widen what a hook receives.
    """
    if kind != "system" and event not in USER_EVENTS:
        return False
    if not isinstance(events, (list, tuple, set, frozenset)):
        return False
    if event in events:
        return True
    if "*" in events:
        return not (fmt != "generic" and event in NON_GENERIC_EXPLICIT_ONLY)
    return False


# ---------------------------------------------------------------------------
# Text cleaning
# ---------------------------------------------------------------------------

_MENTION_ANGLE = re.compile(r"<[@#!&][^<>]*>")
_MENTION_WORD = re.compile(r"@(?=(?:everyone|here|channel)\b)", re.I)


def clean_text(text, limit: int, *, mentions: bool = True) -> str:
    """Printable single-purpose text: control and invisible format characters
    removed, @everyone / @here / @channel and <@id> style mentions neutralised
    (repeated until nothing is left to remove, so nested forms cannot rebuild
    one), cut to `limit` characters with an ellipsis."""
    if text is None:
        return ""
    s = str(text)
    s = "".join(c for c in s if c in "\n" or (unicodedata.category(c)[0] != "C"))
    if mentions:
        while True:
            t = _MENTION_ANGLE.sub("", s)
            t = _MENTION_WORD.sub("", t)
            if t == s:
                break
            s = t
    s = s.strip()
    if len(s) > limit:
        s = s[: max(limit - 3, 0)].rstrip() + "..."
    return s


def _one_line(text, limit: int) -> str:
    return clean_text(" ".join(str(text or "").split()), limit)


def _ascii_header(text: str, limit: int = 200) -> str:
    """A value that is safe in an HTTP header: printable ASCII only, no CR or LF."""
    s = "".join(c if 32 <= ord(c) < 127 else "?" for c in str(text or ""))
    return s.strip()[:limit]


def _slack_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_DISCORD_MD = re.compile(r"([\\*_~`|>#\[\]()<])")


def _discord_escape(s: str) -> str:
    """Text for a Discord embed with its markdown syntax made literal: a backslash before
    every character that starts formatting or a link, so `[text](url)` shows as typed
    and cannot render as a link."""
    return _DISCORD_MD.sub(r"\\\1", s)


def _utf8_cut(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s
    return b[: max_bytes - 3].decode("utf-8", "ignore") + "..."


# ---------------------------------------------------------------------------
# The event catalogue: what each event says by default and with details
# ---------------------------------------------------------------------------

@dataclass
class Message:
    title: str
    summary: str
    details: list = field(default_factory=list)   # [(label, value)], include_details only
    priority: int = 3                              # 1 (min) to 5 (urgent)
    tag: str = "bell"                              # ntfy tag name
    color: int = 0x5865F2


def _channel_label(data: dict) -> str:
    ch = _one_line(data.get("channel"), 60)
    return f"#{ch}" if ch else "a channel"


def build_message(event: str, data: dict, meta: dict, *, include_details: bool,
                  portal_name: str) -> Message:
    """The message for one event. Reads only fields named here."""
    data = data if isinstance(data, dict) else {}
    meta = meta if isinstance(meta, dict) else {}
    portal = _one_line(portal_name, 60) or "Portal"
    d = bool(include_details)

    if event == "message.created":
        m = Message("New chat message", f"A message was posted in {_channel_label(data)}",
                    priority=2, tag="speech_balloon", color=0x3498DB)
        if d:
            author = "Anonymous" if meta.get("anonymous") else _one_line(data.get("username"), 60)
            m.details.append(("From", author or "Anonymous"))
            text = clean_text(data.get("message"), MESSAGE_TEXT_LIMIT)
            if text:
                m.details.append(("Message", text))
        return m
    if event == "message.deleted":
        return Message("Chat message deleted", f"A message was deleted in {_channel_label(data)}",
                       priority=1, tag="wastebasket", color=0x95A5A6)
    if event == "stream.live":
        m = Message("Stream went live", "A public stream went live", priority=3,
                    tag="red_circle", color=0xE74C3C)
        if d:
            _add(m, "Stream", data.get("stream_name"))
            _add(m, "Streamer", data.get("owner_username"))
        return m
    if event == "stream.offline":
        m = Message("Stream ended", "A public stream went offline", priority=2,
                    tag="black_circle", color=0x95A5A6)
        if d:
            _add(m, "Stream", data.get("stream_name"))
            _add(m, "Streamer", data.get("owner_username"))
        return m
    if event == "user.joined":
        m = Message("New member", "A new member registered", priority=3,
                    tag="wave", color=0x2ECC71)
        if d:
            _add(m, "Member", data.get("username"))
        return m
    if event in ("user.connected", "user.disconnected"):
        up = event == "user.connected"
        m = Message("Member connected" if up else "Member disconnected",
                    "A member came online" if up else "A member went offline", priority=1,
                    tag="green_circle" if up else "white_circle",
                    color=0x2ECC71 if up else 0x95A5A6)
        if d:
            _add(m, "Member", data.get("username"))
        return m
    if event == "webhook.test":
        return Message("Test notification", f"This is a test message from {portal}",
                       priority=3, tag="white_check_mark", color=0x2ECC71)
    # An event with no catalogue entry (ops events added later must add one):
    # say only that it happened.
    return Message("Portal event", "An event happened", priority=3, tag="bell")


def _add(m: Message, label: str, value) -> None:
    v = _one_line(value, 120)
    if v:
        m.details.append((label, v))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

@dataclass
class Request:
    """What to send. `path_suffix` is appended to the hook URL's path."""
    body: bytes
    headers: dict
    path_suffix: str = ""
    follow_redirects: bool = False


def _detail_lines(m: Message) -> list:
    return [f"{k}: {v}" for k, v in m.details]


def format_payload(fmt: str, event: str, data: dict, *, meta: dict | None = None,
                   include_details: bool = False, portal_name: str = "Portal",
                   secret: str | None = None, secret_config: dict | None = None,
                   delivery_id: str | None = None) -> Request:
    """Build the request for one delivery.

    generic needs `secret` (HMAC) and keeps its original body and headers.
    The other formats need no secret; `secret_config` carries their credentials.
    """
    if fmt == "generic":
        body_json = json.dumps({
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }, default=str)
        signature = hmac.new((secret or "").encode(), body_json.encode(), hashlib.sha256).hexdigest()
        return Request(
            body=body_json.encode(),
            headers={
                "Content-Type": "application/json",
                "X-Portal-Signature": f"sha256={signature}",
                "X-Portal-Event": event,
                "X-Portal-Delivery": delivery_id or _secrets.token_hex(16),
                "User-Agent": "OpenRelayPortal-Webhook/1.0",
            },
            follow_redirects=True,
        )

    cfg = secret_config if isinstance(secret_config, dict) else {}
    m = build_message(event, data, meta or {}, include_details=include_details,
                      portal_name=portal_name)
    portal = _one_line(portal_name, 60) or "Portal"
    base_headers = {"User-Agent": "OpenRelayPortal-Webhook/1.0"}

    if fmt == "ntfy":
        lines = [m.summary] + _detail_lines(m)
        text = _utf8_cut("\n".join(lines), NTFY_MESSAGE_BYTES)
        headers = dict(base_headers)
        headers["Content-Type"] = "text/plain; charset=utf-8"
        headers["Title"] = _ascii_header(f"{portal}: {m.title}", NTFY_TITLE_LIMIT)
        headers["Priority"] = str(max(1, min(5, int(m.priority))))
        headers["Tags"] = _ascii_header(m.tag, 60)
        tok = cfg.get("token")
        if tok:
            headers["Authorization"] = "Bearer " + _ascii_header(tok, 500)
        elif cfg.get("username") and cfg.get("password") is not None:
            raw = f"{cfg['username']}:{cfg['password']}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return Request(body=text.encode("utf-8"), headers=headers)

    if fmt == "gotify":
        lines = [m.summary] + _detail_lines(m)
        body = json.dumps({
            "title": clean_text(f"{portal}: {m.title}", NTFY_TITLE_LIMIT),
            "message": clean_text("\n".join(lines), 3900),
            "priority": {1: 1, 2: 2, 3: 5, 4: 7, 5: 9}.get(int(m.priority), 5),
            "extras": {"client::display": {"contentType": "text/plain"}},
        })
        headers = dict(base_headers)
        headers["Content-Type"] = "application/json"
        tok = cfg.get("token")
        if tok:
            headers["X-Gotify-Key"] = _ascii_header(tok, 500)
        return Request(body=body.encode("utf-8"), headers=headers, path_suffix="/message")

    if fmt == "discord":
        desc_lines = [_discord_escape(x) for x in [m.summary] + _detail_lines(m)]
        body = json.dumps({
            "username": clean_text(portal, 80) or "Portal",
            "allowed_mentions": {"parse": []},
            "embeds": [{
                "title": clean_text(m.title, DISCORD_TITLE_LIMIT),
                "description": clean_text("\n".join(desc_lines), DISCORD_DESCRIPTION_LIMIT),
                "color": int(m.color),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": clean_text(portal, DISCORD_FOOTER_LIMIT)},
            }],
        })
        headers = dict(base_headers)
        headers["Content-Type"] = "application/json"
        return Request(body=body.encode("utf-8"), headers=headers)

    if fmt == "slack":
        lines = [f"*{_slack_escape(clean_text(m.title, 200))}*",
                 _slack_escape(clean_text(m.summary, 400))]
        lines += [_slack_escape(clean_text(x, 400)) for x in _detail_lines(m)]
        lines.append("_" + _slack_escape(clean_text(portal, 80)) + "_")
        text = "\n".join(lines)
        if len(text) > SLACK_TEXT_LIMIT:
            text = text[: SLACK_TEXT_LIMIT - 3] + "..."
        body = json.dumps({"text": text})
        headers = dict(base_headers)
        headers["Content-Type"] = "application/json"
        return Request(body=body.encode("utf-8"), headers=headers)

    raise ValueError("unknown webhook format")


# ---------------------------------------------------------------------------
# Retry-After
# ---------------------------------------------------------------------------

RETRY_AFTER_CAP = 600.0
RETRY_AFTER_DEFAULT = 5.0


def parse_retry_after(value, now: datetime | None = None) -> float:
    """Seconds to wait from a Retry-After header (delta seconds or HTTP date),
    never negative and never more than RETRY_AFTER_CAP; a missing or
    unreadable value gives a short default."""
    if value is None:
        return RETRY_AFTER_DEFAULT
    text = str(value).strip()
    try:
        secs = float(text)
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            when = parsedate_to_datetime(text)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            secs = (when - (now or datetime.now(timezone.utc))).total_seconds()
        except (TypeError, ValueError, IndexError, OverflowError):
            return RETRY_AFTER_DEFAULT
    if secs != secs:        # NaN
        return RETRY_AFTER_DEFAULT
    return max(0.0, min(secs, RETRY_AFTER_CAP))


# ---------------------------------------------------------------------------
# Masked display of a stored destination
# ---------------------------------------------------------------------------

def mask_url(url: str | None) -> dict:
    """What an API may say about a destination URL of a non-generic hook:
    that one is set, and its scheme and host. Never the path (a Discord or
    Slack webhook path, an ntfy topic) or the query."""
    from urllib.parse import urlsplit
    if not url:
        return {"url_set": False, "url_host": None}
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        host, port = "", ""
    scheme = parts.scheme if host else ""
    return {"url_set": True, "url_host": f"{scheme}://{host}{port}" if host else None}
