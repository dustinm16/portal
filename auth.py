"""Authentication module for Open Relay Portal."""

import secrets
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


async def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate a user by username and password."""
    user = await db.get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


async def create_user(
    username: str,
    password: str,
    is_admin: bool = False,
    registration_ip: str = None
) -> dict:
    """Create a new user."""
    password_hash = hash_password(password)
    user_id = await db.create_user(username, password_hash, is_admin, registration_ip=registration_ip)
    return await db.get_user_by_id(user_id)


async def create_access_token(
    user_id: int,
    scopes: list[str],
    name: str = None,
    expires_in_hours: int = None
) -> tuple[str, str]:
    """Create a new access token for a user.

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
        expires_at=expires_at
    )

    jwt_token = create_jwt(user_id, token_id, scopes, expires_hours)
    return jwt_token, token_id


async def validate_token(token: str) -> TokenPayload:
    """Validate a JWT token and check database status.

    Raises AuthError if token is invalid or revoked.
    """
    payload = decode_jwt(token)

    # Check if token is still valid in database (not revoked)
    if not await db.is_token_valid(payload.token_id):
        raise AuthError("Token has been revoked or expired")

    # Update last used timestamp
    await db.update_token_last_used(payload.token_id)

    return payload


async def revoke_token(token_id: str) -> bool:
    """Revoke a token by its ID."""
    return await db.revoke_token(token_id)


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
            INVITE_CODE_FILE.chmod(0o644)  # Readable by all (code is logged anyway)
        except Exception as e:
            logger.error(f"Failed to write invite code file: {e}")

        # Log to stdout (journalctl visible)
        # Use print with specific format for easy grepping
        log_message = f"INVITE_CODE_GENERATED date={today} code={_current_invite_code}"
        print(f"[PORTAL] {log_message}")
        logger.info(log_message)

    return _current_invite_code


def validate_invite_code(code: str) -> bool:
    """Validate an invite code against the current daily code.

    Args:
        code: The invite code to validate

    Returns:
        True if code matches today's invite code, False otherwise
    """
    if not code:
        return False

    current_code = get_daily_invite_code()
    # Case-insensitive comparison
    return code.strip().upper() == current_code.upper()


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
        username: Username attempting registration
        success: Whether the code was valid
        client_ip: Client IP address
    """
    status = "SUCCESS" if success else "FAILED"
    log_message = f"INVITE_CODE_USAGE user={username} status={status} ip={client_ip}"
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
