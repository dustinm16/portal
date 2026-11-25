"""Who may run script as the viewer: the decisions behind the /proxy origin rules (release 1.24.1).

Everything here is pure (no database, no request objects) so tests can drive it directly; server.py
does the lookups and wires the results into the proxy handler, the middleware and the pages.

Four parts:

* trust: `decide` says whether a proxied page runs unsandboxed on the portal origin ("trusted") or
  in an opaque origin ("isolated").
* capability: a signed path segment that authenticates the requests of an isolated page. Requests
  from an opaque origin carry no cookie of any kind (measured in Chromium, SameSite=None included),
  so the credential rides in the URL, scoped to one connection and one viewer session.
* fetch metadata: `cross_site_refusal` judges a state-changing request that carries the session
  cookie by Sec-Fetch-Site, Origin and Referer.
* cookies: names an upstream may never set.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
from typing import Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# The policy that makes an isolated document run in an opaque origin: no allow-same-origin, so its
# script cannot read portal pages, use the viewer's cookies or storage, or reach the parent frame.
ISOLATED_SANDBOX = "sandbox allow-scripts allow-forms allow-popups allow-downloads allow-modals"

CAP_MARK = "~"                    # every capability starts with this (an application's own path may too)
CAP_PREFIX = "~pc1."              # ... and with this exactly, which is what makes it a capability
CAP_VERSION = "1"
CAP_TTL_SECONDS = 6 * 3600        # re-minted at every entry; cannot be renewed from inside the page
CAP_MAX_LEN = 600
# The minted shape: prefix, a base64url body, a dot and a MAC of 18 bytes (24 base64url characters, no padding).
# Anything else that starts with "~" (an Apache userdir path such as /~alice/) is an ordinary path.
_CAP_SHAPE = re.compile(r"~pc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{24}")


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------

def is_admin_role(role, is_admin=False) -> bool:
    return bool(is_admin) or role in ("admin", "superadmin")


def target_fingerprint(connection: dict, config: dict) -> str:
    """What a "trusted" mark or an accepted share is bound to: the connection type, host, port and
    scheme, and the target URL (which replaces host when it is set), and, when set, the config port, the
    Host header and the path rewrite rules. A change of any of them makes the stored fingerprint stop matching."""
    parts = [
        str(connection.get("type") or ""),
        str(connection.get("host") or "").lower(),
        str(connection.get("port") or ""),
        str((config or {}).get("target_url") or "").lower(),
        "browser" if (config or {}).get("browser_mode") else "single",
    ]
    # (1.24.2) The port in the config, the Host entry of extra_headers and the path rewrite rules also decide what
    # a request reaches. They are added only when at least one is set, so a connection that uses none of them keeps
    # the value stored before this change and its mark and accepted notice keep matching.
    cfg = config or {}
    cfg_port = str(cfg.get("port") or "")
    extra = cfg.get("extra_headers")
    host_header = ""
    if isinstance(extra, dict):
        for k, v in extra.items():
            if str(k).strip().lower() == "host":
                host_header = str(v or "").strip().lower()   # the last one wins, as in the request headers
    rules = cfg.get("path_rewrite_rules") or []
    if cfg_port or host_header or rules:
        try:
            rules_text = json.dumps(rules, sort_keys=True)
        except (TypeError, ValueError):
            rules_text = repr(rules)
        parts += [cfg_port, host_header, hashlib.sha256(rules_text.encode("utf-8")).hexdigest()]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def decide(*, viewer_id: int, owner_id: int, owner_is_admin: bool, browser_mode: bool,
           marked_trusted: bool) -> str:
    """"trusted" or "isolated" for one viewer of one connection.

    Trusted: the connection is not in browser mode and (its owner is an administrator, or the viewer
    is its owner, or a superadmin marked it trusted for this target). Everything else, and every
    page shown through browser mode whoever owns it, is isolated."""
    if browser_mode:
        return "isolated"
    if owner_is_admin or viewer_id == owner_id or marked_trusted:
        return "trusted"
    return "isolated"


# ---------------------------------------------------------------------------
# Capability in the path
# ---------------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key(secret: str) -> bytes:
    return hashlib.sha256(b"portal-proxy-capability-v" + CAP_VERSION.encode() + b"|" + secret.encode("utf-8")).digest()


def _seal_key(secret: str) -> bytes:
    """AES-256 key for the capability body: its own domain string, so it differs from the MAC key."""
    return hashlib.sha256(b"portal-proxy-capability-seal-v" + CAP_VERSION.encode() + b"|" + secret.encode("utf-8")).digest()


def mint(secret: str, *, user_id: int, token_id: str, conn_uuid: str,
         now: Optional[float] = None, ttl: int = CAP_TTL_SECONDS) -> str:
    """The path segment (without a slash) for one viewer session and one connection.

    Not bound to the client address (release 1.24.1): a member's address changes in the middle of a page (mobile
    network, IPv4 and IPv6 on different connections) and a bound capability then failed inside an open page. The
    address does not stop script in the isolated page (it reads its own address and already reaches everything the
    capability reaches, from the viewer's own address). What is given up: a copy of the address used from elsewhere
    until CAP_TTL_SECONDS or the end of the session. It is limited to one connection and ends with the session
    (logout, revoke, password change)."""
    exp = int((time.time() if now is None else now) + ttl)
    plain = json.dumps([int(user_id), str(token_id), str(conn_uuid), exp], separators=(",", ":")).encode("utf-8")
    # The body is encrypted (release 1.24.2): the page that reads its own address learns no member id, session id
    # or connection from it. 12 random nonce bytes in front of the ciphertext and its GCM tag.
    nonce = os.urandom(12)
    body = _b64(nonce + AESGCM(_seal_key(secret)).encrypt(nonce, plain, None))
    mac = _b64(hmac.new(_key(secret), body.encode("ascii"), hashlib.sha256).digest()[:18])
    return f"{CAP_PREFIX}{body}.{mac}"


def is_capability(segment: str) -> bool:
    """True when a path segment has the exact shape mint() makes (whether it verifies is verify()'s question).
    A well-formed one that does not verify is refused; any other segment is the application's own path."""
    return bool(segment) and _CAP_SHAPE.fullmatch(segment) is not None


def split_path(path: str):
    """(capability segment or None, the path without it) for the {path} part of /proxy/{id}/{path}."""
    seg, _, rest = path.partition("/")
    if is_capability(seg):
        return seg, rest
    return None, path


def verify(secret: str, segment: str, *, conn_uuid: str, now: Optional[float] = None) -> Optional[dict]:
    """The payload {user_id, token_id} of a good capability for this connection, else None.
    Signature, decryption, expiry and connection are checked here; that the session is still live and the
    viewer still has access is the caller's job (it needs the database)."""
    if not segment or len(segment) > CAP_MAX_LEN or not is_capability(segment):
        return None
    body, dot, mac = segment[len(CAP_PREFIX):].partition(".")
    if not dot or not body or not mac:
        return None
    want = _b64(hmac.new(_key(secret), body.encode("ascii", "replace"), hashlib.sha256).digest()[:18])
    if not hmac.compare_digest(want, mac):
        return None
    try:
        raw = _unb64(body)
        if len(raw) < 12 + 16:
            return None
        # A body in the readable 1.24.1 shape does not decrypt and is refused like an expired capability.
        plain = AESGCM(_seal_key(secret)).decrypt(raw[:12], raw[12:], None)
        user_id, token_id, conn, exp = json.loads(plain)
        user_id = int(user_id)
    except (ValueError, TypeError, InvalidTag):
        return None
    if conn != conn_uuid:
        return None
    if exp < (time.time() if now is None else now):
        return None
    return {"user_id": user_id, "token_id": str(token_id), "expires": exp}


def strip_capability(url_path: str) -> str:
    """A path as shown to a person: /proxy/<id>/~cap/rest becomes /proxy/<id>/rest."""
    parts = url_path.split("/", 4)
    if len(parts) >= 4 and parts[1] == "proxy" and is_capability(parts[3]):
        return "/".join(parts[:3] + parts[4:5])
    return url_path


# ---------------------------------------------------------------------------
# Fetch metadata for cookie-authenticated state changes
# ---------------------------------------------------------------------------

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Pages whose script is not the portal's own: a request they make is not the member's doing.
UNTRUSTED_PAGE_PREFIXES = ("/proxy", "/browser", "/search")
# Portal scripts injected into the SearXNG pages (push.js: sign-out and device announce) call these
# from a /search page, so a Referer under /search alone is accepted for exactly these.
SEARCH_PAGE_EXEMPT = ("/logout", "/api/push/")


def _host_of(value: str) -> str:
    try:
        return (urlsplit(value).netloc or "").lower()
    except ValueError:
        return ""


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def cross_site_refusal(method: str, path: str, headers, own_hosts, *, websocket: bool = False) -> Optional[str]:
    """Why a request that carries the session cookie must be refused, or None.

    Applies to POST, PUT, PATCH and DELETE and to a WebSocket upgrade. `headers` is a case-insensitive
    mapping; `own_hosts` the lower-case host[:port] names this portal answers to.
    Refused: Sec-Fetch-Site cross-site; an Origin of "null" (a sandboxed document) unless the browser says
    the request is same-origin (a form posted from a page that sends no referrer carries Origin null; a
    sandboxed document is never same-origin); with no fetch metadata, or with Sec-Fetch-Site same-site (a
    sibling subdomain), an Origin that is not one of our hosts;
    a Referer under /proxy, /browser or /search.
    A browser that sends nothing at all (a script, curl, OBS) is not affected here."""
    if not websocket and method.upper() in SAFE_METHODS:
        return None
    site = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if site == "cross-site":
        return "cross-site request"
    origin = (headers.get("Origin") or "").strip()
    if origin.lower() == "null" and site != "same-origin":
        return "opaque origin"
    if origin and not site and _host_of(origin) not in own_hosts:
        return "foreign origin"
    if origin and site == "same-site" and _host_of(origin) not in own_hosts:
        # A page on a sibling subdomain of the portal's domain is same-site, not same-origin.
        return "same-site foreign origin"
    referer = (headers.get("Referer") or "").strip()
    if referer:
        try:
            parts = urlsplit(referer)
        except ValueError:
            return "unreadable referer"
        ref_host = (parts.netloc or "").lower()
        if ref_host and ref_host not in own_hosts:
            return "foreign referer" if not site else None
        ref_path = parts.path or "/"
        for prefix in UNTRUSTED_PAGE_PREFIXES:
            if _under(ref_path, prefix):
                if prefix == "/search" and any(path == e or path.startswith(e) for e in SEARCH_PAGE_EXEMPT):
                    return None
                return "request from a proxied page"
    return None


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

def forbidden_cookie_name(name: str, session_cookie_name: str, value: Optional[str] = None) -> bool:
    """True for a cookie name an upstream may never set: the portal's session cookie, in any letter
    case (a browser treats names as case sensitive, a server that folds case must not be tricked).
    The portal sets no other cookie. Other names, __Secure- ones included, are an application's own.

    `value` is what follows the first "=" of the pair. A pair with an empty name whose value holds a second
    "=" and whose part before it, with surrounding white space removed, is the session cookie name in any
    letter case ("=portal_session=x", "=portal_session =x", "=portal_session<TAB>=x") is read back by servers
    as "portal_session=x", so it is refused too."""
    clean = (name or "").strip().lower()
    if clean == session_cookie_name.lower():
        return True
    if not clean and value is not None:
        head, sep, _ = (value or "").partition("=")
        return bool(sep) and head.strip().lower() == session_cookie_name.lower()
    return False


def clean_cookie_path(path: str) -> str:
    """"" for a Path that is not absolute or contains a dot segment (it is then treated as missing)."""
    if not path.startswith("/"):
        return ""
    if any(seg in ("..", ".") or seg.lower() in ("%2e%2e", "%2e", ".%2e", "%2e.") for seg in path.split("/")):
        return ""
    return path
