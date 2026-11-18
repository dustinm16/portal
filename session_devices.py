"""Small local helpers for the sessions page: clean a User-Agent header for
storage and turn it into a short "Browser on OS" label.

No library, no network. The parser only needs to be good enough to tell a
member which of their devices is which; anything it does not recognise is
shown as "Unknown".
"""

import hashlib
import hmac
import re
from typing import Optional

USER_AGENT_MAX = 200

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Order matters: a browser built on another one names both (Edge and Opera
# contain "Chrome", Chrome and every iOS browser contain "Safari").
_BROWSERS = (
    ("Edge", re.compile(r"\b(?:Edg|EdgA|EdgiOS|Edge)/")),
    ("Opera", re.compile(r"\b(?:OPR|OPT|Opera)/")),
    ("Samsung Internet", re.compile(r"SamsungBrowser/")),
    ("Firefox", re.compile(r"\b(?:Firefox|FxiOS)/")),
    ("Brave", re.compile(r"\bBrave/")),
    ("Vivaldi", re.compile(r"\bVivaldi/")),
    ("Chrome", re.compile(r"\b(?:Chrome|CriOS|Chromium)/")),
    ("Safari", re.compile(r"\bSafari/")),
)

# iPhone and iPad user agents contain "like Mac OS X"; Android contains "Linux";
# ChromeOS contains "X11; CrOS".
_SYSTEMS = (
    ("iOS", re.compile(r"iPhone|iPad|iPod")),
    ("Android", re.compile(r"Android")),
    ("ChromeOS", re.compile(r"\bCrOS\b")),
    ("Windows", re.compile(r"Windows")),
    ("macOS", re.compile(r"Macintosh|Mac OS X")),
    ("Linux", re.compile(r"Linux|X11")),
)

# Clients that are not browsers (scripts that made a token through the API).
_TOOLS = (
    ("curl", re.compile(r"^curl/", re.I)),
    ("Python", re.compile(r"^(?:python-requests|python-urllib|aiohttp|Python)", re.I)),
    ("Wget", re.compile(r"^Wget/", re.I)),
    ("PowerShell", re.compile(r"PowerShell", re.I)),
    ("Go", re.compile(r"^Go-http-client/", re.I)),
)


def clean_user_agent(value) -> Optional[str]:
    """User-Agent value as stored: control characters dropped, at most 200
    characters, None when nothing is left."""
    if not isinstance(value, str):
        return None
    value = _CONTROL.sub("", value).strip()[:USER_AGENT_MAX]
    return value or None


def parse_user_agent(user_agent: Optional[str]) -> dict:
    """Return {"browser", "os", "label"} for a stored User-Agent.

    A missing or unrecognised part is "Unknown"; the label is "Browser on OS",
    or just "Unknown device" when neither part is known.
    """
    ua = user_agent or ""
    browser = "Unknown"
    system = "Unknown"
    for name, pattern in _TOOLS:
        if pattern.search(ua):
            browser = name
            break
    else:
        for name, pattern in _BROWSERS:
            if pattern.search(ua):
                browser = name
                break
    for name, pattern in _SYSTEMS:
        if pattern.search(ua):
            system = name
            break
    if browser == "Unknown" and system == "Unknown":
        label = "Unknown device"
    elif system == "Unknown":
        label = browser
    elif browser == "Unknown":
        label = system
    else:
        label = f"{browser} on {system}"
    return {"browser": browser, "os": system, "label": label}


def public_session_id(token_id: str) -> str:
    """Opaque id shown to the client in place of the token id (a truncated
    SHA-256, which cannot be turned back into the token id)."""
    return hashlib.sha256(str(token_id).encode("utf-8")).hexdigest()[:16]


def matches_public_id(token_id: str, public_id) -> bool:
    return (isinstance(public_id, str)
            and hmac.compare_digest(public_session_id(token_id), public_id))
