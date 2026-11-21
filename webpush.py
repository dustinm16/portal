"""Web Push foundation: VAPID (RFC 8292), message encryption (RFC 8291, aes128gcm),
endpoint policy and the sender.

Nothing here decides WHEN a push goes out. `send_push(user_id, payload)` is the one
entry point other code calls; `build_payload()` is the one way to make a payload.

Privacy rules this module keeps by construction:
  * A payload is a type, a short generic title, a short generic body and a same-origin
    relative URL. It never carries a message text or an author. A channel name or a
    streamer's name appears only when the caller (the triggers in server.py) has checked that
    the recipient may read that channel or the stream is public.
  * A subscription endpoint is a capability (whoever holds it can push to that device),
    so it is never logged and never returned by a list route in full.
  * The endpoint is attacker-chosen input and the server POSTs to it. `validate_endpoint`
    accepts only https on port 443 to a host on the allow-list of real push services,
    and the connection goes through the project's outbound guard (host_check), which
    refuses private, loopback, link-local and metadata addresses at connect time. No
    redirects, short timeouts, bounded response read.

The VAPID private key is generated on first use and stored encrypted (database.encrypt_config)
in the settings table, so it is inside every database backup. If it cannot be stored
encrypted, or an existing one cannot be decrypted, push stays off: a new key is never
generated over an old one (that would silently end every subscription).

The only way to reach a plain-http loopback endpoint is `allow_test_sink(port)` (tests) or,
on a staged instance (PORTAL_STAGE_MODE), the setting `stage_push_sink_port`. A staged
instance sends nothing anywhere else. server.py never calls `allow_test_sink`.
"""

import asyncio
import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from time import monotonic
from urllib.parse import urlsplit

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import host_check
import webhook_formats
from config import Config

logger = logging.getLogger("portal")

# --------------------------------------------------------------------------- limits
MAX_DEVICES_PER_USER = 10
MAX_ENDPOINT_LEN = 700
MAX_PAYLOAD_BYTES = 2048          # plaintext, well under the 4096 octet limit of push services
RECORD_SIZE = 4096
SEND_CONCURRENCY = 8              # global: pushes in flight at once
USER_RATE_LIMIT = 30              # per user per window, over all devices
USER_RATE_WINDOW = 60.0
CONNECT_TIMEOUT = 5.0
TOTAL_TIMEOUT = 10.0
RESPONSE_READ_LIMIT = 4096
PRUNE_AFTER_FAILURES = 8          # consecutive failures that are not 404/410/429
DEFAULT_TTL = 3600
MAX_TTL = 86400
URGENCIES = ("very-low", "low", "normal", "high")
VAPID_EXP_SECONDS = 12 * 3600

# Real push services. An entry "*.x.y" matches any host below x.y (not x.y itself).
DEFAULT_ALLOWED_HOSTS = (
    "fcm.googleapis.com",
    "updates.push.services.mozilla.com",
    "*.push.apple.com",
    "*.notify.windows.com",
)

SETTING_ENABLED = "push_enabled"
SETTING_EXTRA_HOSTS = "push_allowed_hosts_extra"
SETTING_SUBJECT = "push_vapid_subject"
SETTING_PRIVATE = "push_vapid_private"
SETTING_PUBLIC = "push_vapid_public"
SETTING_STAGE_SINK = "stage_push_sink_port"

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_.]{0,31}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f​-‏ -‮⁠-⁯﻿]")


class PushError(ValueError):
    """A refused subscription, host list or payload. The text is safe to show the caller."""


# --------------------------------------------------------------------------- base64url
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text or len(text) > 2048:
        raise PushError("Invalid base64 value")
    t = text.strip().replace("+", "-").replace("/", "_").rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", t):
        raise PushError("Invalid base64 value")
    try:
        return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except Exception:
        raise PushError("Invalid base64 value") from None


# --------------------------------------------------------------------------- RFC 8291
def public_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def load_public_point(raw: bytes) -> ec.EllipticCurvePublicKey:
    """A 65 octet uncompressed P-256 point that is really on the curve."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 65 or raw[0] != 4:
        raise PushError("Invalid p256dh key")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(raw))
    except Exception:
        raise PushError("Invalid p256dh key") from None


def validate_keys(p256dh: str, auth: str) -> tuple[bytes, bytes]:
    """(ua_public, auth_secret) from the base64url strings a browser gives; refuses junk."""
    ua_public = b64u_decode(p256dh)
    load_public_point(ua_public)
    auth_secret = b64u_decode(auth)
    if len(auth_secret) != 16:
        raise PushError("Invalid auth secret")
    return ua_public, auth_secret


def encrypt_aes128gcm(plaintext: bytes, ua_public: bytes, auth_secret: bytes, *,
                      as_private: ec.EllipticCurvePrivateKey | None = None,
                      salt: bytes | None = None, record_size: int = RECORD_SIZE) -> bytes:
    """RFC 8291 section 3 with RFC 8188 framing: one record, delimiter 0x02, no extra padding.

    Returns the whole request body: salt, record size, key id length and key id (the
    sender's public key), then the ciphertext. as_private and salt are injectable only so
    that the RFC's test vector can be reproduced; leave them out in real use."""
    if len(plaintext) > record_size - 17:
        raise PushError("Payload too large")
    ua_key = load_public_point(ua_public)
    if len(auth_secret) != 16:
        raise PushError("Invalid auth secret")
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    salt = salt if salt is not None else os.urandom(16)
    if len(salt) != 16:
        raise PushError("Invalid salt")
    as_public = public_bytes(as_private)
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    key_info = b"WebPush: info\x00" + ua_public + as_public
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret, info=key_info).derive(ecdh_secret)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
               info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt,
                 info=b"Content-Encoding: nonce\x00").derive(ikm)
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + record_size.to_bytes(4, "big") + bytes([len(as_public)]) + as_public
    return header + ciphertext


# --------------------------------------------------------------------------- VAPID
@dataclass
class VapidKeys:
    private: ec.EllipticCurvePrivateKey
    public: bytes                      # 65 octets, uncompressed

    @property
    def public_b64(self) -> str:
        return b64u(self.public)


def vapid_from_secret(d_b64: str) -> VapidKeys:
    d = int.from_bytes(b64u_decode(d_b64), "big")
    key = ec.derive_private_key(d, ec.SECP256R1())
    return VapidKeys(key, public_bytes(key))


def vapid_jwt(keys: VapidKeys, audience: str, subject: str, *, now: float | None = None,
              lifetime: int = VAPID_EXP_SECONDS) -> str:
    """ES256 JWT of RFC 8292: aud is the push service origin, exp at most 24 hours ahead."""
    now = time.time() if now is None else now
    lifetime = min(int(lifetime), 24 * 3600)
    header = {"typ": "JWT", "alg": "ES256"}
    claims = {"aud": audience, "exp": int(now) + lifetime, "sub": subject}
    signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode())
                     + "." + b64u(json.dumps(claims, separators=(",", ":")).encode()))
    der = keys.private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def vapid_authorization(keys: VapidKeys, audience: str, subject: str, *, now: float | None = None) -> str:
    return f"vapid t={vapid_jwt(keys, audience, subject, now=now)}, k={keys.public_b64}"


_vapid_lock: asyncio.Lock | None = None


async def get_vapid(db) -> VapidKeys | None:
    """The server's VAPID key pair; generated on first use. None when push must stay off
    (the key could not be stored encrypted, or the stored one cannot be decrypted)."""
    global _vapid_lock
    import database as dbmod
    if _vapid_lock is None:
        _vapid_lock = asyncio.Lock()
    async with _vapid_lock:
        stored = await db.get_setting(SETTING_PRIVATE)
        if stored:
            if not stored.startswith("enc:"):
                logger.error("Web push: stored VAPID key is not encrypted; push stays off")
                return None
            try:
                data = json.loads(dbmod.decrypt_config(stored))
                keys = vapid_from_secret(data["d"])
            except Exception:
                logger.error("Web push: stored VAPID key cannot be read; push stays off "
                             "(a new key is never generated over an old one)")
                return None
            return keys
        key = ec.generate_private_key(ec.SECP256R1())
        d = b64u(key.private_numbers().private_value.to_bytes(32, "big"))
        sealed = dbmod.encrypt_config(json.dumps({"d": d}))
        if not sealed.startswith("enc:"):
            logger.error("Web push: the VAPID key could not be encrypted; push stays off")
            return None
        await db.set_settings({SETTING_PRIVATE: sealed, SETTING_PUBLIC: b64u(public_bytes(key))})
        return VapidKeys(key, public_bytes(key))


def default_subject() -> str:
    """The VAPID `sub`: the portal's own https address, never a person's address."""
    base = (getattr(Config, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if not base.lower().startswith("https://"):
        base = "https://" + (Config.HOSTNAME or "localhost")
    return base


# --------------------------------------------------------------------------- endpoint policy
_test_sink_port: int | None = None


def allow_test_sink(port: int | None) -> None:
    """Tests only: let exactly http://127.0.0.1:<port> be a push endpoint (None switches it off)."""
    global _test_sink_port
    _test_sink_port = int(port) if port else None


def parse_extra_hosts(text) -> list[str]:
    """The superadmin extension of the allow-list: host names or `*.suffix` entries, no IPs,
    no single-label names, no localhost. Raises PushError."""
    if text is None or text == "":
        return []
    if isinstance(text, str):
        items = [p for p in re.split(r"[\s,]+", text.strip()) if p]
    elif isinstance(text, (list, tuple)):
        items = [str(p).strip() for p in text if str(p).strip()]
    else:
        raise PushError("Allowed hosts must be a list of host names")
    out: list[str] = []
    for item in items:
        h = item.lower().rstrip(".")
        wild = h.startswith("*.")
        base = h[2:] if wild else h
        labels = base.split(".")
        if (len(labels) < 2 or not all(_HOST_LABEL.match(x) for x in labels)
                or host_check._normalise_ip(base) is not None
                or host_check.is_blocked_host(base) or labels[-1].isdigit()
                or labels[-1] in ("localhost", "local", "internal", "lan", "home", "corp", "arpa")
                or (wild and len(labels) < 3)):
            raise PushError(f"Not an acceptable push service host: {item[:60]}")
        if h not in out:
            out.append(h)
    if len(out) > 20:
        raise PushError("At most 20 extra hosts")
    return out


def host_allowed(host: str, extra=()) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h or host_check._normalise_ip(h) is not None:
        return False
    labels = h.split(".")
    if not all(_HOST_LABEL.match(x) for x in labels):
        return False
    for entry in list(DEFAULT_ALLOWED_HOSTS) + list(extra or ()):
        if entry.startswith("*."):
            if h.endswith("." + entry[2:]):
                return True
        elif h == entry:
            return True
    return False


def validate_endpoint(endpoint, extra_hosts=(), sink_port: int | None = None) -> str:
    """The endpoint to store, or PushError. https, port 443, no userinfo, no fragment,
    host on the allow-list (default list plus `extra_hosts`). `sink_port` (from the test
    hook or a staged instance) additionally allows plain http to 127.0.0.1 on that port."""
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > MAX_ENDPOINT_LEN:
        raise PushError("Invalid push endpoint")
    if _CTRL_RE.search(endpoint) or endpoint != endpoint.strip() or " " in endpoint or "\\" in endpoint:
        raise PushError("Invalid push endpoint")
    try:
        parts = urlsplit(endpoint)
        port = parts.port
        host = parts.hostname or ""
    except ValueError:
        raise PushError("Invalid push endpoint") from None
    if parts.username is not None or parts.password is not None or parts.fragment or "@" in parts.netloc:
        raise PushError("Invalid push endpoint")
    if sink_port and parts.scheme == "http" and host == "127.0.0.1" and port == sink_port:
        return endpoint
    if parts.scheme != "https" or not host:
        raise PushError("Push endpoint must be https")
    if port not in (None, 443):
        raise PushError("Push endpoint port not allowed")
    if not host_allowed(host, extra_hosts):
        raise PushError("Push service not allowed")
    return endpoint


async def check_resolves_public(endpoint: str, sink_port: int | None = None) -> None:
    """Refuse an endpoint whose host resolves to a private, loopback, link-local or metadata
    address. Raises PushError with a generic text (the address is never shown)."""
    parts = urlsplit(endpoint)
    if sink_port and parts.scheme == "http" and parts.hostname == "127.0.0.1" and parts.port == sink_port:
        return
    try:
        await host_check.resolve_checked_host(parts.hostname or "", 443)
    except host_check.HostCheckError:
        raise PushError("Push endpoint host is not allowed") from None


def endpoint_label(endpoint: str) -> str:
    """Host only: the part of an endpoint that is safe to log or show."""
    try:
        return urlsplit(endpoint).hostname or "?"
    except ValueError:
        return "?"


# --------------------------------------------------------------------------- payloads
def safe_relative_url(url) -> str:
    """A same-origin relative path or PushError: starts with one slash, no scheme, no
    protocol-relative form, no backslash, no control character."""
    if (not isinstance(url, str) or not url.startswith("/") or url.startswith("//")
            or "\\" in url or _CTRL_RE.search(url) or len(url) > 300):
        raise PushError("A push URL must be a relative path")
    return url


def _clean(text, limit: int) -> str:
    t = _CTRL_RE.sub("", str(text or "")).strip()
    return t[:limit]


def build_payload(kind: str, title: str, body: str = "", url: str = "/", tag: str | None = None) -> dict:
    """The one way to make a push payload. Callers pass GENERIC text (for example
    "New message" with no channel name, text or author) and a relative URL."""
    if not isinstance(kind, str) or not _KIND_RE.match(kind):
        raise PushError("Invalid push type")
    title = _clean(title, 80)
    if not title:
        raise PushError("A push needs a title")
    payload = {"type": kind, "title": title, "body": _clean(body, 160), "url": safe_relative_url(url)}
    if tag:
        payload["tag"] = _clean(tag, 40)
    if len(json.dumps(payload, separators=(",", ":")).encode()) > MAX_PAYLOAD_BYTES:
        raise PushError("Payload too large")
    return payload


def make_test_payload() -> dict:
    return build_payload("test", "Test notification", "Push is working on this device.", "/")


# --------------------------------------------------------------------------- sender
class Pusher:
    """Sends payloads to a user's devices. One instance per server process."""

    def __init__(self, db, *, clock=monotonic):
        self.db = db
        self._clock = clock
        self._sem: asyncio.Semaphore | None = None
        self._rates: dict[int, list[float]] = {}
        self._paused: dict[int, float] = {}      # subscription id -> clock time it may be used again
        self.tasks: set[asyncio.Task] = set()

    # -- settings
    async def enabled(self) -> bool:
        return (await self.db.get_setting(SETTING_ENABLED) or "1").strip() != "0"

    async def extra_hosts(self) -> list[str]:
        try:
            return parse_extra_hosts(await self.db.get_setting(SETTING_EXTRA_HOSTS))
        except PushError:
            return []

    async def sink_port(self) -> int | None:
        if _test_sink_port:
            return _test_sink_port
        if Config.STAGE_MODE:
            try:
                return int(await self.db.get_setting(SETTING_STAGE_SINK) or 0) or None
            except ValueError:
                return None
        return None

    async def subject(self) -> str:
        return (await self.db.get_setting(SETTING_SUBJECT) or "").strip() or default_subject()

    # -- scheduling
    def send_push(self, user_id: int, payload: dict, *, ttl: int = DEFAULT_TTL,
                  urgency: str = "normal", topic: str | None = None) -> "asyncio.Task | None":
        """Fire and forget: schedule delivery to every device of the user and return the task
        (callers normally ignore it). Never raises; nothing is sent to a user with no device."""
        try:
            task = asyncio.get_running_loop().create_task(
                self.deliver(user_id, payload, ttl=ttl, urgency=urgency, topic=topic))
        except RuntimeError:
            return None
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def cancel_all(self) -> None:
        for t in list(self.tasks):
            t.cancel()

    def _rate_ok(self, user_id: int) -> bool:
        now = self._clock()
        recent = [t for t in self._rates.get(user_id, []) if t > now - USER_RATE_WINDOW]
        if len(recent) >= USER_RATE_LIMIT:
            self._rates[user_id] = recent
            return False
        recent.append(now)
        self._rates[user_id] = recent
        if len(self._rates) > 5000:
            self._rates = {u: v for u, v in self._rates.items() if v and v[-1] > now - USER_RATE_WINDOW}
        return True

    async def deliver(self, user_id: int, payload: dict, *, ttl: int = DEFAULT_TTL,
                      urgency: str = "normal", topic: str | None = None) -> list[dict]:
        """Deliver to every live device of the user; one result dict per device
        ({"id", "status", "outcome"}). Used directly by the superadmin test route."""
        try:
            if not await self.enabled():
                return []
            subs = await self.db.push_subscriptions_for_send(user_id)
            if not subs:
                return []
            if not self._rate_ok(user_id):
                return [{"id": s["id"], "status": None, "outcome": "rate_limited"} for s in subs]
            keys = await get_vapid(self.db)
            if keys is None:
                return [{"id": s["id"], "status": None, "outcome": "unavailable"} for s in subs]
            body = json.dumps(payload, separators=(",", ":")).encode()
            if len(body) > MAX_PAYLOAD_BYTES:
                return []
            results = await asyncio.gather(
                *(self._send_one(s, body, keys, ttl, urgency, topic) for s in subs),
                return_exceptions=True)
            out = []
            for s, r in zip(subs, results):
                if isinstance(r, BaseException):
                    logger.warning(f"Web push: send to device {s['id']} failed: {type(r).__name__}")
                    r = {"id": s["id"], "status": None, "outcome": "error"}
                out.append(r)
            return out
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"Web push: delivery for user {user_id} failed: {type(e).__name__}")
            return []

    async def _send_one(self, sub: dict, body: bytes, keys: VapidKeys, ttl: int,
                        urgency: str, topic: str | None) -> dict:
        sid = sub["id"]
        res = {"id": sid, "status": None, "outcome": "failed"}
        if self._clock() < self._paused.get(sid, 0.0):
            res["outcome"] = "paused"
            return res
        sink = await self.sink_port()
        if Config.STAGE_MODE and not sink:
            res["outcome"] = "staged"          # a staged instance sends nothing outside the host
            return res
        endpoint = sub["endpoint"]
        try:
            validate_endpoint(endpoint, await self.extra_hosts(), sink)
            message = encrypt_aes128gcm(body, b64u_decode(sub["p256dh"]), b64u_decode(sub["auth"]))
        except PushError:
            res["outcome"] = "refused"         # no longer allowed (list shrank) or keys unusable
            await self.db.push_record_failure(sid, PRUNE_AFTER_FAILURES)
            return res
        parts = urlsplit(endpoint)
        audience = f"{parts.scheme}://{parts.netloc}"
        headers = {
            "Authorization": vapid_authorization(keys, audience, await self.subject()),
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(max(0, min(int(ttl), MAX_TTL))),
            "Urgency": urgency if urgency in URGENCIES else "normal",
        }
        if topic and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", topic):
            headers["Topic"] = topic
        if self._sem is None:
            self._sem = asyncio.Semaphore(SEND_CONCURRENCY)
        status = None
        retry_after = None
        try:
            async with self._sem:
                is_sink = bool(sink) and parts.scheme == "http"
                connector = aiohttp.TCPConnector() if is_sink else host_check._SSRFSafeConnector()
                timeout = aiohttp.ClientTimeout(total=TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.post(endpoint, data=message, headers=headers,
                                            allow_redirects=False) as resp:
                        status = resp.status
                        retry_after = resp.headers.get("Retry-After")
                        await resp.content.read(RESPONSE_READ_LIMIT)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.info(f"Web push: device {sid} ({endpoint_label(endpoint)}) not reached: {type(e).__name__}")
            await self.db.push_record_failure(sid, PRUNE_AFTER_FAILURES)
            res["outcome"] = "error"
            return res
        res["status"] = status
        if 200 <= status < 300:
            await self.db.push_record_success(sid)
            res["outcome"] = "sent"
        elif status in (404, 410):
            await self.db.delete_push_subscription_by_id(sid)
            self._paused.pop(sid, None)
            res["outcome"] = "gone"
        elif status == 429:
            wait = webhook_formats.parse_retry_after(retry_after)
            self._paused[sid] = self._clock() + wait
            res["outcome"] = "slow_down"       # not counted as a failure
        else:
            pruned = await self.db.push_record_failure(sid, PRUNE_AFTER_FAILURES)
            res["outcome"] = "pruned" if pruned else "failed"
        return res
