"""Authentication module for Open Relay Portal."""

import asyncio
import secrets
import time
import hashlib
import logging
import jwt
import pyotp
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from config import Config
from database import db
from session_devices import clean_user_agent


ph = PasswordHasher()
logger = logging.getLogger("portal.auth")

# Invite code storage
INVITE_CODE_FILE = Path(__file__).parent / ".invite_code"
_current_invite_code: Optional[str] = None
_invite_code_date: Optional[str] = None


class AuthError(Exception):
    """Authentication error."""
    pass


class TokenPayload:
    """Decoded JWT token payload."""

    def __init__(self, data: dict):
        self.token_id: str = data.get("jti", "")
        self.user_id: int = int(data.get("sub", 0))  # Convert from string
        self.scopes: list[str] = data.get("scopes", [])
        self.issued_at: datetime = datetime.fromtimestamp(
            data.get("iat", 0), tz=timezone.utc
        )
        self.expires_at: Optional[datetime] = (
            datetime.fromtimestamp(data["exp"], tz=timezone.utc)
            if "exp" in data
            else None
        )

    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope."""
        if "*" in self.scopes:
            return True
        if scope in self.scopes:
            return True
        # Check wildcard patterns (e.g., "relay:*" matches "relay:service1")
        scope_parts = scope.split(":")
        for s in self.scopes:
            s_parts = s.split(":")
            if len(s_parts) == len(scope_parts):
                match = True
                for sp, tp in zip(s_parts, scope_parts):
                    if sp != "*" and sp != tp:
                        match = False
                        break
                if match:
                    return True
        return False

    def has_any_scope(self, scopes: list[str]) -> bool:
        """Check if token has any of the specified scopes."""
        return any(self.has_scope(s) for s in scopes)

    def has_all_scopes(self, scopes: list[str]) -> bool:
        """Check if token has all specified scopes."""
        return all(self.has_scope(s) for s in scopes)


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


# Argon2 takes tens of milliseconds of CPU; run on the event loop it stalls every other request, so the
# handlers use these wrappers. At most PASSWORD_HASH_WORKERS hashes run at once (the rest wait their turn).
PASSWORD_HASH_WORKERS = 4
_password_hash_sem: Optional[tuple] = None      # (event loop, semaphore); made when first used on a loop


def _password_hash_semaphore() -> asyncio.Semaphore:
    global _password_hash_sem
    loop = asyncio.get_running_loop()
    if _password_hash_sem is None or _password_hash_sem[0] is not loop:
        _password_hash_sem = (loop, asyncio.Semaphore(PASSWORD_HASH_WORKERS))
    return _password_hash_sem[1]


async def hash_password_async(password: str) -> str:
    """hash_password in a worker thread, at most PASSWORD_HASH_WORKERS at once."""
    async with _password_hash_semaphore():
        return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str) -> bool:
    """verify_password in a worker thread, at most PASSWORD_HASH_WORKERS at once."""
    async with _password_hash_semaphore():
        return await asyncio.to_thread(verify_password, password, password_hash)


# A fixed hash that a login for an unknown account is checked against, so the answer takes
# as long as one for a real account and the time does not tell the two apart.
_DUMMY_PASSWORD_HASH = ph.hash("no-such-account-placeholder")


def generate_token_id() -> str:
    """Generate a unique token ID."""
    return secrets.token_urlsafe(32)


def create_jwt(
    user_id: int,
    token_id: str,
    scopes: list[str],
    expires_in_hours: int = None
) -> str:
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    expires_hours = expires_in_hours or Config.TOKEN_EXPIRY_HOURS

    payload = {
        "jti": token_id,
        "sub": str(user_id),  # PyJWT requires string subject
        "scopes": scopes,
        "iat": int(now.timestamp()),
    }

    if expires_hours > 0:
        payload["exp"] = int((now + timedelta(hours=expires_hours)).timestamp())

    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)


def decode_jwt(token: str) -> TokenPayload:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET,
            algorithms=[Config.JWT_ALGORITHM]
        )
        return TokenPayload(payload)
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")


async def authenticate_user_reason(username: str, password: str) -> tuple[Optional[dict], Optional[str]]:
    """Authenticate; returns (user, None) or (None, "unknown_user" | "bad_password")."""
    user = await db.get_user_by_username(username)
    if not user:
        try:
            await verify_password_async(password, _DUMMY_PASSWORD_HASH)     # same work as for a real account
        except Exception:
            pass
        return None, "unknown_user"
    if not await verify_password_async(password, user["password_hash"]):
        return None, "bad_password"
    return user, None


async def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate a user by username and password."""
    user, _ = await authenticate_user_reason(username, password)
    return user


# @here and @everyone are the mass mentions of the chat; no account may carry either as its
# username or nickname (an @name of that kind could never reach the member, and it would
# look like a mass mention)
RESERVED_MENTION_NAMES = frozenset({"here", "everyone"})


def is_reserved_mention_name(name) -> bool:
    return isinstance(name, str) and name.strip().casefold() in RESERVED_MENTION_NAMES


async def create_user(
    username: str,
    password: str,
    is_admin: bool = False,
    registration_ip: str = None
) -> dict:
    """Create a new user."""
    if is_reserved_mention_name(username):
        raise ValueError("That username is reserved")
    password_hash = await hash_password_async(password)
    user_id = await db.create_user(username, password_hash, is_admin, registration_ip=registration_ip)
    return await db.get_user_by_id(user_id)


async def create_access_token(
    user_id: int,
    scopes: list[str],
    name: str = None,
    expires_in_hours: int = None,
    ip: str = None,
    user_agent: str = None
) -> tuple[str, str]:
    """Create a new access token for a user.

    ip and user_agent (the caller's address and User-Agent header) are kept on
    the token row for the sessions page.

    Returns:
        Tuple of (jwt_token, token_id)
    """
    token_id = generate_token_id()
    expires_hours = expires_in_hours or Config.TOKEN_EXPIRY_HOURS

    expires_at = None
    if expires_hours > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

    await db.create_token(
        user_id=user_id,
        token_id=token_id,
        scopes=scopes,
        name=name,
        expires_at=expires_at,
        ip=ip,
        user_agent=clean_user_agent(user_agent)
    )

    jwt_token = create_jwt(user_id, token_id, scopes, expires_hours)
    return jwt_token, token_id


# last_used_at / last_ip are written at most once per TOUCH_INTERVAL seconds
# per credential (a token, or "apikey-<id>" for an API key): every
# authenticated request passes through validate_token or the API key check, and
# a write plus commit on each of them would load the single SQLite writer.
TOUCH_INTERVAL = 60
_TOUCH_SWEEP_SIZE = 2048
_last_touch: dict[str, float] = {}


def _touch_clock() -> float:
    return time.monotonic()


def touch_due(token_id: str) -> bool:
    """True (and the time is noted) when this credential's last_used write is due."""
    now = _touch_clock()
    last = _last_touch.get(token_id)
    if last is not None and 0 <= now - last < TOUCH_INTERVAL:
        return False
    if len(_last_touch) >= _TOUCH_SWEEP_SIZE:
        # Forget tokens not seen for a while (revoked, expired, logged out);
        # one that is still in use is simply written again at its next request.
        for key in [k for k, t in _last_touch.items() if now - t >= TOUCH_INTERVAL]:
            _last_touch.pop(key, None)
    _last_touch[token_id] = now
    return True


async def validate_token(token: str, client_ip: str = None) -> TokenPayload:
    """Validate a JWT token and check database status.

    client_ip, when given, is stored as the token's last_ip with the
    last-used time. Raises AuthError if token is invalid or revoked.
    """
    payload = decode_jwt(token)

    # Check if token is still valid in database (not revoked)
    if not await db.is_token_valid(payload.token_id):
        _last_touch.pop(payload.token_id, None)
        raise AuthError("Token has been revoked or expired")

    # Update last used timestamp (throttled, see TOUCH_INTERVAL)
    if touch_due(payload.token_id):
        await db.update_token_last_used(payload.token_id, client_ip)

    return payload


async def revoke_token(token_id: str, user_id: int = None) -> bool:
    """Revoke a token by its ID, optionally only if owned by user_id."""
    return await db.revoke_token(token_id, user_id)


def extract_token_from_request(
    headers: dict = None,
    query_params: dict = None
) -> Optional[str]:
    """Extract JWT token from request headers or query parameters.

    Checks:
    1. Authorization: Bearer <token> header
    2. ?token=<token> query parameter
    """
    # Check Authorization header
    if headers:
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

    # Check query parameter
    if query_params and "token" in query_params:
        return query_params["token"]

    return None


# =============================================================================
# Invite Code System
# =============================================================================

def _generate_invite_code() -> str:
    """Generate a new invite code.

    Format: PORTAL-XXXX-XXXX-XXXX (where X is alphanumeric)
    """
    # Generate 12 random characters
    chars = secrets.token_hex(6).upper()  # 12 hex characters
    return f"PORTAL-{chars[:4]}-{chars[4:8]}-{chars[8:12]}"


def get_daily_invite_code() -> str:
    """Get or generate the daily invite code.

    The invite code rotates at midnight UTC each day.
    Codes are logged to stdout (visible via journalctl) and stored in a file.
    """
    global _current_invite_code, _invite_code_date

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Check if we need to generate a new code
    if _invite_code_date != today or _current_invite_code is None:
        # Try to read existing code from file
        if INVITE_CODE_FILE.exists():
            try:
                content = INVITE_CODE_FILE.read_text().strip()
                lines = content.split("\n")
                if len(lines) >= 2:
                    stored_date = lines[0].strip()
                    stored_code = lines[1].strip()
                    if stored_date == today:
                        _invite_code_date = stored_date
                        _current_invite_code = stored_code
                        return _current_invite_code
            except Exception as e:
                logger.warning(f"Failed to read invite code file: {e}")

        # Generate new code
        _current_invite_code = _generate_invite_code()
        _invite_code_date = today

        # Store to file
        try:
            INVITE_CODE_FILE.write_text(f"{today}\n{_current_invite_code}\n")
            INVITE_CODE_FILE.chmod(0o600)  # Owner-only (code is also logged to journalctl)
        except Exception as e:
            logger.error(f"Failed to write invite code file: {e}")

        log_message = f"INVITE_CODE_GENERATED date={today} code={_current_invite_code}"
        logger.info(log_message)

    return _current_invite_code


async def validate_invite_code(code: str, db=None) -> tuple:
    """Validate an invite code against DB codes or legacy daily code.

    Args:
        code: The invite code to validate
        db: Database instance for DB-backed code lookup

    Returns:
        Tuple of (is_valid: bool, code_id: int or None)
    """
    if not code:
        return (False, None)

    code = code.strip().upper()

    # Check DB first if available
    if db:
        row = await db.get_active_invite_code_by_code(code)
        if row:
            return (True, row["id"])

    # Fall back to legacy file-based daily code (constant-time comparison)
    import hmac
    current_code = get_daily_invite_code()
    if hmac.compare_digest(code.encode(), current_code.upper().encode()):
        return (True, None)

    return (False, None)


def get_invite_code_info() -> dict:
    """Get information about the current invite code (for admin display).

    Returns:
        Dict with date and masked code hint
    """
    code = get_daily_invite_code()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Create a masked hint (show first and last part)
    parts = code.split("-")
    masked = f"{parts[0]}-{parts[1][:2]}**-****-**{parts[3][2:]}"

    return {
        "date": today,
        "hint": masked,
        "expires_at": f"{today}T23:59:59Z"
    }


def log_invite_code_usage(username: str, success: bool, client_ip: str) -> None:
    """Log invite code usage attempt.

    Args:
        username: Username attempting registration (logged only when success is true)
        success: Whether the code was valid
        client_ip: Client IP address
    """
    status = "SUCCESS" if success else "FAILED"
    # A refused attempt never logs the typed name (people paste passwords into the name box).
    who = username if success else "an unknown account"
    log_message = f"INVITE_CODE_USAGE user={who} status={status} ip={client_ip}"
    print(f"[PORTAL] {log_message}")
    logger.info(log_message)


# =============================================================================
# Two-Factor Authentication (TOTP)
# =============================================================================

def generate_totp_secret() -> str:
    """Generate a new random TOTP secret.

    Returns:
        Base32-encoded secret string for TOTP
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = None) -> str:
    """Get TOTP provisioning URI for QR code generation.

    Args:
        secret: Base32-encoded TOTP secret
        username: User's account name
        issuer: Application name (defaults to Config.TOTP_ISSUER)

    Returns:
        otpauth:// URI for QR code
    """
    if issuer is None:
        issuer = getattr(Config, 'TOTP_ISSUER', 'Open Relay Portal')
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret.

    Args:
        secret: Base32-encoded TOTP secret
        code: 6-digit TOTP code from authenticator app

    Returns:
        True if code is valid (within 1 time window drift)
    """
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        # Allow 1 window drift (30 seconds before/after)
        return totp.verify(code.strip(), valid_window=1)
    except Exception as e:
        logger.warning(f"TOTP verification error: {e}")
        return False


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate one-time backup codes for 2FA recovery.

    Args:
        count: Number of backup codes to generate (default 10)

    Returns:
        List of uppercase hex backup codes (8 characters each)
    """
    return [secrets.token_hex(4).upper() for _ in range(count)]


# =============================================================================
# API Key Management
# =============================================================================

def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key for programmatic access.

    Returns:
        Tuple of (full_key, key_hash, key_prefix)
        - full_key: The complete API key to show user once (portal_XXXXXXXX...)
        - key_hash: Argon2 hash of the key for storage
        - key_prefix: First 8 chars for identification (portal_XX)
    """
    # Generate 32 random bytes = 64 hex characters
    key_body = secrets.token_hex(32)
    full_key = f"portal_{key_body}"
    key_prefix = full_key[:10]  # "portal_XX" prefix for lookup

    # Hash the full key for secure storage
    key_hash = hash_password(full_key)

    return full_key, key_hash, key_prefix


def verify_api_key(full_key: str, stored_hash: str) -> bool:
    """Verify an API key against its stored hash.

    Args:
        full_key: The full API key provided by user
        stored_hash: The Argon2 hash stored in database

    Returns:
        True if key is valid
    """
    return verify_password(full_key, stored_hash)


def parse_api_key(key: str) -> Optional[str]:
    """Parse and validate API key format.

    Args:
        key: The API key to parse

    Returns:
        The key prefix for database lookup, or None if invalid format
    """
    if not key or not key.startswith("portal_") or len(key) < 10:
        return None
    return key[:10]
