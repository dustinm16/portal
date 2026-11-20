"""Database layer for Open Relay Portal using SQLite."""

import asyncio
import json
import logging
import secrets as _secrets

import aiosqlite
import sqlite3
import base64
import hashlib
import ipaddress
import os
import stat
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from config import Config
import recording_paths
import chat_uploads
import secevents
import ipguard
import chat_search
import webhook_formats
import grant_expiry

logger = logging.getLogger("portal.database")

# Terminal recording files end in this extension (see plugins/terminal.py).
RECORDING_FILE_EXTENSION = ".cast"

# Message encryption using Fernet-like scheme with AES
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    import logging as _logging
    _logging.getLogger(__name__).critical(
        "cryptography library not available — ALL DATA WILL BE STORED UNENCRYPTED"
    )


# --- Machine-bound encryption salt ---
# The encryption salt is unique per installation: derived from /etc/machine-id
# (hardware-bound) + a random component. Even with the same JWT_SECRET, a
# different machine produces different encryption keys. The salt file is
# auto-generated on first run and must NOT be committed to version control.

_ENCRYPTION_SALT_FILE = Path(__file__).parent / ".encryption_salt"
_encryption_salt_cache: bytes | None = None


def _get_machine_id() -> bytes:
    """Read /etc/machine-id for hardware binding."""
    try:
        return Path("/etc/machine-id").read_text().strip().encode()
    except (FileNotFoundError, PermissionError):
        return b"no-machine-id"


def _get_encryption_salt() -> bytes:
    """Get machine-bound encryption salt. Auto-generated on first run."""
    global _encryption_salt_cache
    if _encryption_salt_cache is not None:
        return _encryption_salt_cache

    if _ENCRYPTION_SALT_FILE.exists():
        _encryption_salt_cache = _ENCRYPTION_SALT_FILE.read_bytes()
        return _encryption_salt_cache

    # Salt file missing — could be fresh install or accidental deletion
    logger.warning(
        "Encryption salt file not found — generating new salt. "
        "If this is not a fresh install, previously encrypted data will be unreadable!"
    )
    return _generate_encryption_salt()


def _generate_encryption_salt() -> bytes:
    """Generate and persist a new machine-bound encryption salt."""
    global _encryption_salt_cache
    machine_id = _get_machine_id()
    random_component = _secrets.token_bytes(32)
    salt = hashlib.sha256(machine_id + random_component).digest()
    _ENCRYPTION_SALT_FILE.write_bytes(salt)
    os.chmod(str(_ENCRYPTION_SALT_FILE), 0o600)
    _encryption_salt_cache = salt
    return salt


# --- Key derivation caches (avoid repeated PBKDF2 computations) ---
_chat_key_cache: bytes | None = None
_config_key_cache: bytes | None = None
_legacy_chat_key_cache: tuple | None = None    # (JWT_SECRET it was derived from, key)

# --- Legacy key functions (hardcoded salts, pre-machine-binding) ---

def _get_legacy_chat_key() -> bytes:
    """Legacy chat encryption key using hardcoded salt. Derived once per process
    (and per JWT_SECRET): PBKDF2 at 100k iterations is far too slow to repeat for
    every legacy row."""
    global _legacy_chat_key_cache
    if not Config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required for encryption")
    cached = _legacy_chat_key_cache
    if cached is not None and cached[0] == Config.JWT_SECRET:
        return cached[1]
    secret = Config.JWT_SECRET.encode()
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=b"portal-chat-salt", iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
    else:
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    _legacy_chat_key_cache = (Config.JWT_SECRET, key)
    return key


def _get_legacy_config_key() -> bytes:
    """Legacy config encryption key using hardcoded salt."""
    if not Config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required for encryption")
    secret = Config.JWT_SECRET.encode()
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=b"portal-config-salt", iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


# --- Current key derivation (machine-bound) ---

def get_chat_encryption_key() -> bytes:
    """Derive chat encryption key from JWT_SECRET + machine-bound salt."""
    global _chat_key_cache
    if _chat_key_cache is not None:
        return _chat_key_cache
    if not Config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required for encryption")
    secret = Config.JWT_SECRET.encode()
    machine_salt = _get_encryption_salt()
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=machine_salt + b"chat",
            iterations=100000,
        )
        _chat_key_cache = base64.urlsafe_b64encode(kdf.derive(secret))
        return _chat_key_cache
    _chat_key_cache = base64.urlsafe_b64encode(hashlib.sha256(secret + machine_salt).digest())
    return _chat_key_cache


def get_config_encryption_key() -> bytes:
    """Derive config encryption key from JWT_SECRET + machine-bound salt."""
    global _config_key_cache
    if _config_key_cache is not None:
        return _config_key_cache
    if not Config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required for encryption")
    secret = Config.JWT_SECRET.encode()
    machine_salt = _get_encryption_salt()
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=machine_salt + b"config",
            iterations=100000,
        )
        _config_key_cache = base64.urlsafe_b64encode(kdf.derive(secret))
        return _config_key_cache
    _config_key_cache = base64.urlsafe_b64encode(hashlib.sha256(secret + machine_salt).digest())
    return _config_key_cache


def encrypt_message(plaintext: str) -> str:
    """Encrypt a chat message. Raises on failure to prevent plaintext storage."""
    if not CRYPTO_AVAILABLE or not plaintext:
        return plaintext
    f = Fernet(get_chat_encryption_key())
    return f.encrypt(plaintext.encode()).decode()


class SearchIndexBusy(Exception):
    """The search index is being backfilled or rebuilt and the caller would not wait."""


class MessageDecryptError(Exception):
    """A stored chat message looks encrypted but neither key opens it."""


def decrypt_message_strict(ciphertext: str) -> str:
    """Like decrypt_message, but raises MessageDecryptError instead of returning
    the placeholder, so a caller can tell an unreadable row from a message whose
    text happens to be the placeholder."""
    if not CRYPTO_AVAILABLE or not ciphertext:
        return ciphertext
    # Fernet tokens always start with gAAAAAB — if it doesn't, it's plaintext
    if not ciphertext.startswith("gAAAAAB"):
        return ciphertext
    try:
        f = Fernet(get_chat_encryption_key())
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        # Try legacy key (pre-machine-binding)
        try:
            f = Fernet(_get_legacy_chat_key())
            return f.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            raise MessageDecryptError(type(e).__name__) from None


def decrypt_message(ciphertext: str) -> str:
    """Decrypt a chat message. Falls back to legacy key for pre-migration data.

    Plaintext (pre-encryption era data) is detected by checking for the Fernet
    token prefix and returned as-is to avoid false "decryption failed" errors.
    """
    try:
        return decrypt_message_strict(ciphertext)
    except MessageDecryptError as e:
        logger.warning(f"Message decryption failed (both keys): {e}")
        return "[Message could not be decrypted]"


# --- Connection config encryption (separate key from chat) ---

def encrypt_config(config_json: str) -> str:
    """Encrypt a connection config JSON string.

    Encrypted values are prefixed with 'enc:' to distinguish from legacy plaintext.
    """
    if not CRYPTO_AVAILABLE or not config_json or config_json == "{}":
        return config_json
    try:
        f = Fernet(get_config_encryption_key())
        return "enc:" + f.encrypt(config_json.encode()).decode()
    except Exception as e:
        logger.warning(f"Config encryption failed, storing plaintext: {e}")
        return config_json


def decrypt_config(data: str) -> str:
    """Decrypt a connection config string. Falls back to legacy key for pre-migration data."""
    if not data or not data.startswith("enc:"):
        return data  # Not encrypted (legacy or empty)
    try:
        f = Fernet(get_config_encryption_key())
        return f.decrypt(data[4:].encode()).decode()
    except Exception:
        # Try legacy key (pre-machine-binding)
        try:
            f = Fernet(_get_legacy_config_key())
            return f.decrypt(data[4:].encode()).decode()
        except Exception as e:
            logger.warning(f"Config decryption failed (both keys): {type(e).__name__}")
            return "{}"


def hash_stream_key(key: str) -> str:
    """SHA-256 hex digest of a stream key for indexed lookups."""
    return hashlib.sha256(key.encode()).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_id TEXT UNIQUE NOT NULL,
    name TEXT,
    scopes TEXT NOT NULL,
    expires_at TEXT,
    revoked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    icon TEXT DEFAULT 'folder',
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    plugin TEXT NOT NULL DEFAULT 'tcp_tunnel',
    path TEXT UNIQUE NOT NULL,
    host TEXT,
    port INTEGER,
    config TEXT DEFAULT '{}',
    required_scopes TEXT DEFAULT '',
    icon TEXT DEFAULT 'server',
    category_id INTEGER,
    enabled INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    client_ip TEXT,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ended_at TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ed25519',
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tokens_token_id ON tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_services_path ON services(path);
CREATE INDEX IF NOT EXISTS idx_services_plugin ON services(plugin);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_service_id ON sessions(service_id);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_id ON ssh_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
"""

# Migration for existing databases
MIGRATIONS = [
    # Add plugin column if not exists
    "ALTER TABLE services ADD COLUMN plugin TEXT DEFAULT 'tcp_tunnel'",
    "ALTER TABLE services ADD COLUMN host TEXT",
    "ALTER TABLE services ADD COLUMN port INTEGER",
    "ALTER TABLE services ADD COLUMN config TEXT DEFAULT '{}'",
    "ALTER TABLE services ADD COLUMN icon TEXT DEFAULT 'server'",
    "ALTER TABLE services ADD COLUMN category_id INTEGER",
    "ALTER TABLE services ADD COLUMN sort_order INTEGER DEFAULT 0",
    # Two-Factor Authentication columns
    "ALTER TABLE users ADD COLUMN totp_secret TEXT",
    "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN backup_codes TEXT",
    # Session recordings table
    """CREATE TABLE IF NOT EXISTS recordings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        service_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'asciicast',
        size INTEGER DEFAULT 0,
        duration REAL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_recordings_user_id ON recordings(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_recordings_service_id ON recordings(service_id)",
    # Settings table for persistent configuration
    """CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    # API keys for programmatic access
    """CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        scopes TEXT DEFAULT '*',
        expires_at TEXT,
        last_used_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, name)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix)",
    # User connections (personal services/connections)
    """CREATE TABLE IF NOT EXISTS user_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER,
        config TEXT DEFAULT '{}',
        ssh_key_id INTEGER,
        icon TEXT DEFAULT 'link',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id) ON DELETE SET NULL,
        UNIQUE(user_id, name)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_user_connections_user_id ON user_connections(user_id)",
    # Chat/Forum tables
    """CREATE TABLE IF NOT EXISTS chat_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        topic TEXT,
        is_default INTEGER DEFAULT 0,
        created_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )""",
    """CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        message_type TEXT DEFAULT 'message',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_channel_id ON chat_messages(channel_id)",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at)",
    # Scrollback pages read (channel_id, id) ranges
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_channel_id_id ON chat_messages(channel_id, id)",
    # Insert default channels
    "INSERT OR IGNORE INTO chat_channels (name, description, is_default) VALUES ('general', 'General discussion', 1)",
    "INSERT OR IGNORE INTO chat_channels (name, description) VALUES ('random', 'Off-topic chat')",
    "INSERT OR IGNORE INTO chat_channels (name, description) VALUES ('help', 'Help and support')",
    # User status for chat presence
    "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'online'",
    "ALTER TABLE users ADD COLUMN status_message TEXT",
    "ALTER TABLE users ADD COLUMN nickname TEXT",
    # User roles for permission system (superadmin, admin, moderator, user)
    "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
    # Migrate existing is_admin to role system
    "UPDATE users SET role = 'superadmin' WHERE is_admin = 1 AND role = 'user'",
    # Hidden username for anonymous chat
    "ALTER TABLE users ADD COLUMN chat_anonymous INTEGER DEFAULT 0",
    # Avatar customization (JSON: {"color": "#hex", "emoji": "🙂", "initials": "AB"})
    "ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN registration_ip TEXT",
    # Managed services - actual server processes Portal runs
    """CREATE TABLE IF NOT EXISTS managed_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        display_name TEXT,
        description TEXT,
        enabled INTEGER DEFAULT 0,
        status TEXT DEFAULT 'stopped',
        pid INTEGER,
        config TEXT DEFAULT '{}',
        port INTEGER,
        ports TEXT DEFAULT '[]',
        binary_path TEXT,
        config_path TEXT,
        working_dir TEXT,
        last_health_check TEXT,
        health_status TEXT DEFAULT 'unknown',
        restart_count INTEGER DEFAULT 0,
        last_started_at TEXT,
        last_stopped_at TEXT,
        error_message TEXT,
        icon TEXT DEFAULT 'server',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_managed_services_type ON managed_services(type)",
    "CREATE INDEX IF NOT EXISTS idx_managed_services_status ON managed_services(status)",
    # Service logs
    """CREATE TABLE IF NOT EXISTS service_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        level TEXT DEFAULT 'info',
        message TEXT NOT NULL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_service_logs_service ON service_logs(service_id)",
    "CREATE INDEX IF NOT EXISTS idx_service_logs_timestamp ON service_logs(timestamp)",
    # User streams - for OBS/RTMP streaming
    """CREATE TABLE IF NOT EXISTS user_streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        stream_key TEXT NOT NULL UNIQUE,
        description TEXT,
        is_public INTEGER DEFAULT 0,
        is_live INTEGER DEFAULT 0,
        viewer_count INTEGER DEFAULT 0,
        chat_channel_id INTEGER,
        thumbnail_url TEXT,
        started_at TEXT,
        ended_at TEXT,
        total_views INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (chat_channel_id) REFERENCES chat_channels(id) ON DELETE SET NULL,
        UNIQUE(user_id, name)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_user_streams_user ON user_streams(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_streams_stream_key ON user_streams(stream_key)",
    "CREATE INDEX IF NOT EXISTS idx_user_streams_public ON user_streams(is_public, is_live)",
    # One row per streamer: when their last broad go-live announcement (the "everyone" audience, or
    # a card in the shared announce channel) was made. Not tied to a stream, so deleting and
    # recreating a stream does not reset it; it goes with the account.
    """CREATE TABLE IF NOT EXISTS golive_owner_cooldown (
        user_id INTEGER PRIMARY KEY,
        announced_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    # Unified services - add process management fields to services table
    "ALTER TABLE services ADD COLUMN service_type TEXT DEFAULT 'proxy'",
    "ALTER TABLE services ADD COLUMN display_name TEXT",
    "ALTER TABLE services ADD COLUMN description TEXT",
    "ALTER TABLE services ADD COLUMN status TEXT DEFAULT 'stopped'",
    "ALTER TABLE services ADD COLUMN pid INTEGER",
    "ALTER TABLE services ADD COLUMN binary_path TEXT",
    "ALTER TABLE services ADD COLUMN config_path TEXT",
    "ALTER TABLE services ADD COLUMN working_dir TEXT",
    "ALTER TABLE services ADD COLUMN ports TEXT DEFAULT '[]'",
    "ALTER TABLE services ADD COLUMN last_health_check TEXT",
    "ALTER TABLE services ADD COLUMN health_status TEXT DEFAULT 'unknown'",
    "ALTER TABLE services ADD COLUMN restart_count INTEGER DEFAULT 0",
    "ALTER TABLE services ADD COLUMN last_started_at TEXT",
    "ALTER TABLE services ADD COLUMN last_stopped_at TEXT",
    "ALTER TABLE services ADD COLUMN error_message TEXT",
    "CREATE INDEX IF NOT EXISTS idx_services_service_type ON services(service_type)",
    "CREATE INDEX IF NOT EXISTS idx_services_status ON services(status)",
    # Migrate managed_services data to unified services table
    """INSERT OR IGNORE INTO services (name, plugin, path, host, port, config, icon, enabled,
        service_type, display_name, description, status, pid, binary_path, config_path,
        working_dir, ports, last_health_check, health_status, restart_count,
        last_started_at, last_stopped_at, error_message)
    SELECT name, type, '/managed/' || name, '127.0.0.1', port, config, icon, enabled,
        'managed', display_name, description, status, pid, binary_path, config_path,
        working_dir, ports, last_health_check, health_status, restart_count,
        last_started_at, last_stopped_at, error_message
    FROM managed_services""",
    # Connection access control fields
    "ALTER TABLE user_connections ADD COLUMN portal_access INTEGER DEFAULT 1",
    "ALTER TABLE user_connections ADD COLUMN api_access INTEGER DEFAULT 0",
    # Stream bans - allow stream owners to ban users from their stream chat
    """CREATE TABLE IF NOT EXISTS stream_bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        banned_by INTEGER NOT NULL,
        reason TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        anonymous INTEGER NOT NULL DEFAULT 0,
        message_id INTEGER,
        banned_by_anonymous INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE CASCADE
    )""",
    # Whether the member who banned had anonymous chat on at that moment (the ban list masks
    # the banner from this, never from his current setting). Older rows count as named.
    "ALTER TABLE stream_bans ADD COLUMN banned_by_anonymous INTEGER NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_stream_bans_stream ON stream_bans(stream_id)",
    "CREATE INDEX IF NOT EXISTS idx_stream_bans_user ON stream_bans(user_id)",
    # Public key for read-only stream access (separate from private stream_key)
    "ALTER TABLE user_streams ADD COLUMN public_key TEXT",
    "CREATE INDEX IF NOT EXISTS idx_user_streams_public_key ON user_streams(public_key)",
    # Allow unauthenticated public access to stream video
    "ALTER TABLE user_streams ADD COLUMN allow_unauthenticated INTEGER DEFAULT 0",
    # VOD storage - per-user SFTP configuration for remote VOD files
    # Store anonymous flag per chat message so history preserves anonymity
    "ALTER TABLE chat_messages ADD COLUMN anonymous INTEGER DEFAULT 0",
    # Reply-to support for chat message threading
    "ALTER TABLE chat_messages ADD COLUMN reply_to INTEGER",
    # Image URL for chat message image embeds
    "ALTER TABLE chat_messages ADD COLUMN image_url TEXT",
    """CREATE TABLE IF NOT EXISTS vod_storage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        name TEXT NOT NULL DEFAULT 'My VOD Storage',
        host TEXT NOT NULL,
        port INTEGER DEFAULT 22,
        username TEXT NOT NULL,
        auth_method TEXT NOT NULL DEFAULT 'password',
        remote_path TEXT NOT NULL DEFAULT '/home/user/vods',
        config TEXT DEFAULT '{}',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    # Activity log for dashboard feed
    """CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        detail TEXT,
        ip_address TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_activity_log_user ON activity_log(user_id)",
    # The relabel of a private stream's activity rows (start-up pass and stream edits) selects by owner and action
    "CREATE INDEX IF NOT EXISTS idx_activity_log_user_action ON activity_log(user_id, action)",
    "CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log(created_at DESC)",
    # Store reply preview inline so it persists when the original message is deleted
    "ALTER TABLE chat_messages ADD COLUMN reply_preview_username TEXT",
    "ALTER TABLE chat_messages ADD COLUMN reply_preview_text TEXT",
    # Stream key encryption - hash columns for lookups
    "ALTER TABLE user_streams ADD COLUMN stream_key_hash TEXT",
    "ALTER TABLE user_streams ADD COLUMN public_key_hash TEXT",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_streams_stream_key_hash ON user_streams(stream_key_hash)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_streams_public_key_hash ON user_streams(public_key_hash)",
    # Connection usage tracking and pinning
    "ALTER TABLE user_connections ADD COLUMN last_used_at TEXT",
    "ALTER TABLE user_connections ADD COLUMN use_count INTEGER DEFAULT 0",
    "ALTER TABLE user_connections ADD COLUMN is_pinned INTEGER DEFAULT 0",
    # Notifications system
    """CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        data TEXT DEFAULT '{}',
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at DESC)",
    # RTMP plain ingress - per-stream toggle
    "ALTER TABLE user_streams ADD COLUMN rtmp_enabled INTEGER DEFAULT 0",
    # Go-live announcement: the owner's message template, and when the stream was last
    # announced (epoch seconds; kept across restarts, it is the go-live cooldown)
    "ALTER TABLE user_streams ADD COLUMN golive_message TEXT",
    "ALTER TABLE user_streams ADD COLUMN golive_announced_at INTEGER",
    # Who a go-live is announced to: 'followers' or 'everyone' (every member who may watch).
    # Rows that exist now keep today's behaviour ('everyone') through this default; a stream
    # created from now on is inserted with 'followers'.
    "ALTER TABLE user_streams ADD COLUMN golive_audience TEXT DEFAULT 'everyone'",
    # Peak and unique viewers of the last live session, written when the stream goes offline
    # (NULL: no session recorded yet, e.g. rows from before this was kept)
    "ALTER TABLE user_streams ADD COLUMN last_peak_viewers INTEGER",
    "ALTER TABLE user_streams ADD COLUMN last_unique_viewers INTEGER",
    # Follows: a member follows a stream to hear when it goes live. Private to the member.
    """CREATE TABLE IF NOT EXISTS stream_follow (
        user_id INTEGER NOT NULL,
        stream_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, stream_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_stream_follow_stream ON stream_follow(stream_id)",
    # The go-live card posted into a chat channel: which message, for which stream, and what
    # it shows. The message text is the plain-text fallback; this row lets history rebuild
    # the card and lets the card be removed when the stream becomes private or is deleted.
    """CREATE TABLE IF NOT EXISTS stream_cards (
        message_id INTEGER PRIMARY KEY,
        stream_id INTEGER NOT NULL,
        channel_id INTEGER NOT NULL,
        streamer TEXT NOT NULL,
        title TEXT NOT NULL,
        FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE CASCADE,
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_stream_cards_stream ON stream_cards(stream_id)",
    # The game a stream shows next to its title (at most 60 characters), what a go-live card
    # shows of it (encrypted like the card's title), and the games an owner used before, kept
    # for the settings form's suggestions.
    "ALTER TABLE user_streams ADD COLUMN game TEXT",
    "ALTER TABLE stream_cards ADD COLUMN game TEXT",
    """CREATE TABLE IF NOT EXISTS stream_game_history (
        user_id INTEGER NOT NULL,
        game TEXT NOT NULL COLLATE NOCASE,
        used_at TEXT NOT NULL,
        PRIMARY KEY (user_id, game),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    # RTMP temporary publish tokens
    """CREATE TABLE IF NOT EXISTS rtmp_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        stream_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        used_at TEXT,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_rtmp_tokens_hash ON rtmp_tokens(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_rtmp_tokens_stream ON rtmp_tokens(stream_id)",
    # Chat reactions
    """CREATE TABLE IF NOT EXISTS chat_reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        emoji TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(message_id, user_id, emoji)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_reactions_message ON chat_reactions(message_id)",
    # Message editing
    "ALTER TABLE chat_messages ADD COLUMN edited_at TEXT",
    # Pinned messages
    "ALTER TABLE chat_messages ADD COLUMN is_pinned INTEGER DEFAULT 0",
    "ALTER TABLE chat_messages ADD COLUMN pinned_by INTEGER",
    "ALTER TABLE chat_messages ADD COLUMN pinned_at TEXT",
    # Unread tracking
    """CREATE TABLE IF NOT EXISTS channel_read_positions (
        user_id INTEGER NOT NULL,
        channel_id INTEGER NOT NULL,
        last_read_message_id INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, channel_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE
    )""",
    # --- Direct Messages ---
    # DM conversations (1:1 or group)
    """CREATE TABLE IF NOT EXISTS dm_conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL DEFAULT '1on1',
        name TEXT,
        created_by INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )""",
    # DM participants
    """CREATE TABLE IF NOT EXISTS dm_participants (
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
        left_at TEXT,
        muted INTEGER DEFAULT 0,
        PRIMARY KEY (conversation_id, user_id),
        FOREIGN KEY (conversation_id) REFERENCES dm_conversations(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_dm_participants_user ON dm_participants(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_dm_participants_conv ON dm_participants(conversation_id)",
    # DM messages (encrypted at rest like chat_messages)
    """CREATE TABLE IF NOT EXISTS dm_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        message_type TEXT DEFAULT 'message',
        reply_to INTEGER,
        image_url TEXT,
        reply_preview_username TEXT,
        reply_preview_text TEXT,
        edited_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES dm_conversations(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_dm_messages_conv ON dm_messages(conversation_id)",
    "CREATE INDEX IF NOT EXISTS idx_dm_messages_created ON dm_messages(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_dm_messages_user ON dm_messages(user_id)",
    # DM reactions
    """CREATE TABLE IF NOT EXISTS dm_reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        emoji TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (message_id) REFERENCES dm_messages(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(message_id, user_id, emoji)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_dm_reactions_message ON dm_reactions(message_id)",
    # DM read positions
    """CREATE TABLE IF NOT EXISTS dm_read_positions (
        user_id INTEGER NOT NULL,
        conversation_id INTEGER NOT NULL,
        last_read_message_id INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, conversation_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (conversation_id) REFERENCES dm_conversations(id) ON DELETE CASCADE
    )""",
    # --- Full-Text Search (FTS5) ---
    # Contentless FTS5 indexes for channel and DM messages
    "CREATE VIRTUAL TABLE IF NOT EXISTS chat_messages_fts USING fts5(message, content='', tokenize='porter unicode61')",
    "CREATE VIRTUAL TABLE IF NOT EXISTS dm_messages_fts USING fts5(message, content='', tokenize='porter unicode61')",
    # FTS mapping tables (link FTS rowid to message metadata for filtering)
    """CREATE TABLE IF NOT EXISTS chat_fts_map (
        rowid INTEGER PRIMARY KEY,
        message_id INTEGER NOT NULL UNIQUE,
        channel_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        has_image INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_fts_map_msg ON chat_fts_map(message_id)",
    "CREATE INDEX IF NOT EXISTS idx_chat_fts_map_channel ON chat_fts_map(channel_id)",
    """CREATE TABLE IF NOT EXISTS dm_fts_map (
        rowid INTEGER PRIMARY KEY,
        message_id INTEGER NOT NULL UNIQUE,
        conversation_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        has_image INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_dm_fts_map_msg ON dm_fts_map(message_id)",
    "CREATE INDEX IF NOT EXISTS idx_dm_fts_map_conv ON dm_fts_map(conversation_id)",
    # Invite codes system
    """CREATE TABLE IF NOT EXISTS invite_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL DEFAULT 'daily',
        label TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT,
        max_uses INTEGER,
        use_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1
    )""",
    "CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code)",
    "CREATE INDEX IF NOT EXISTS idx_invite_codes_active ON invite_codes(is_active)",
    "ALTER TABLE users ADD COLUMN invite_code_id INTEGER REFERENCES invite_codes(id)",
    # Chat features: slowmode, channel categories, timeouts, file attachments
    "ALTER TABLE chat_channels ADD COLUMN slowmode_seconds INTEGER DEFAULT 0",
    "ALTER TABLE chat_channels ADD COLUMN category TEXT",
    """CREATE TABLE IF NOT EXISTS chat_timeouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        channel_id INTEGER,
        moderator_id INTEGER NOT NULL,
        type TEXT NOT NULL DEFAULT 'timeout',
        reason TEXT,
        expires_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY (moderator_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_timeouts_user ON chat_timeouts(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_chat_timeouts_channel ON chat_timeouts(channel_id)",
    "ALTER TABLE chat_messages ADD COLUMN attachment_url TEXT",
    "ALTER TABLE chat_messages ADD COLUMN attachment_name TEXT",
    "ALTER TABLE chat_messages ADD COLUMN attachment_size INTEGER",
    "ALTER TABLE chat_messages ADD COLUMN attachment_type TEXT",
    "ALTER TABLE dm_messages ADD COLUMN attachment_url TEXT",
    "ALTER TABLE dm_messages ADD COLUMN attachment_name TEXT",
    "ALTER TABLE dm_messages ADD COLUMN attachment_size INTEGER",
    "ALTER TABLE dm_messages ADD COLUMN attachment_type TEXT",
    # User blocking
    """CREATE TABLE IF NOT EXISTS user_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        blocked_user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (blocked_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, blocked_user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_user_blocks_user ON user_blocks(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_blocks_blocked ON user_blocks(blocked_user_id)",
    # Polls
    """CREATE TABLE IF NOT EXISTS chat_polls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        message_id INTEGER,
        user_id INTEGER NOT NULL,
        question TEXT NOT NULL,
        options TEXT NOT NULL,
        allow_multiple INTEGER DEFAULT 0,
        anonymous_votes INTEGER DEFAULT 0,
        expires_at TEXT,
        is_closed INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_polls_channel ON chat_polls(channel_id)",
    "CREATE INDEX IF NOT EXISTS idx_chat_polls_message ON chat_polls(message_id)",
    """CREATE TABLE IF NOT EXISTS chat_poll_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        option_index INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES chat_polls(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(poll_id, user_id, option_index)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_chat_poll_votes_poll ON chat_poll_votes(poll_id)",
    # Audit log
    """CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        actor_id INTEGER NOT NULL,
        actor_username TEXT NOT NULL,
        target_id INTEGER,
        target_type TEXT,
        target_name TEXT,
        details TEXT,
        channel_id INTEGER,
        channel_name TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)",
    # Auto-moderation
    """CREATE TABLE IF NOT EXISTS automod_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        config TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER DEFAULT 1,
        action TEXT NOT NULL DEFAULT 'delete',
        action_duration INTEGER,
        created_by INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS automod_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        channel_id INTEGER,
        message_text TEXT,
        action_taken TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (rule_id) REFERENCES automod_rules(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_automod_actions_rule ON automod_actions(rule_id)",
    # Per-channel permissions
    "ALTER TABLE chat_channels ADD COLUMN visibility TEXT DEFAULT 'public'",
    "ALTER TABLE chat_channels ADD COLUMN mode TEXT DEFAULT 'open'",
    """CREATE TABLE IF NOT EXISTS channel_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        added_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL,
        UNIQUE(channel_id, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members(channel_id)",
    "CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members(user_id)",
    # RTMP token IP binding and reconnect grace
    "ALTER TABLE rtmp_tokens ADD COLUMN bound_ip TEXT",
    "ALTER TABLE rtmp_tokens ADD COLUMN last_active_at TEXT",
    # Opaque connection IDs - UUID column for external-facing URLs
    "ALTER TABLE user_connections ADD COLUMN uuid TEXT",
    # Performance indexes for common queries
    "CREATE INDEX IF NOT EXISTS idx_chat_timeouts_user_expires ON chat_timeouts(user_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_chat_channels_visibility ON chat_channels(visibility)",
    "CREATE INDEX IF NOT EXISTS idx_dm_participants_user_left ON dm_participants(user_id, left_at)",
    "CREATE INDEX IF NOT EXISTS idx_automod_rules_enabled ON automod_rules(enabled)",
    # Custom emotes
    """CREATE TABLE IF NOT EXISTS custom_emotes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        filename TEXT NOT NULL,
        category TEXT DEFAULT 'General',
        uploaded_by INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_custom_emotes_name ON custom_emotes(name)",
    # Stream relay destinations (multi-platform relay)
    """CREATE TABLE IF NOT EXISTS stream_relay_destinations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER NOT NULL,
        platform TEXT NOT NULL DEFAULT 'custom',
        name TEXT NOT NULL,
        rtmp_url TEXT NOT NULL,
        stream_key TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_relay_dest_stream ON stream_relay_destinations(stream_id)",
    "CREATE INDEX IF NOT EXISTS idx_relay_dest_enabled ON stream_relay_destinations(stream_id, enabled)",
    # User presence: last seen tracking
    "ALTER TABLE users ADD COLUMN last_seen_at TEXT",
    # Webhooks (outgoing + incoming)
    """CREATE TABLE IF NOT EXISTS webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'outgoing',
        url TEXT,
        secret TEXT NOT NULL,
        token TEXT UNIQUE,
        events TEXT NOT NULL DEFAULT '[]',
        channel_id INTEGER,
        enabled INTEGER DEFAULT 1,
        consecutive_failures INTEGER DEFAULT 0,
        last_delivery_at TEXT,
        last_failure_at TEXT,
        last_failure_reason TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE SET NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_webhooks_type_enabled ON webhooks(type, enabled)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_token ON webhooks(token)",
    # Webhook delivery logs
    """CREATE TABLE IF NOT EXISTS webhook_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        webhook_id INTEGER NOT NULL,
        event TEXT NOT NULL,
        request_payload TEXT,
        response_status INTEGER,
        response_body TEXT,
        success INTEGER DEFAULT 0,
        attempt INTEGER DEFAULT 1,
        duration_ms INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_webhook_logs_webhook ON webhook_logs(webhook_id)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_logs_created ON webhook_logs(created_at)",
    # Notification channels (v1.15.0). Defaults leave every existing hook as it was.
    "ALTER TABLE webhooks ADD COLUMN kind TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE webhooks ADD COLUMN format TEXT NOT NULL DEFAULT 'generic'",
    "ALTER TABLE webhooks ADD COLUMN format_config TEXT",
    "ALTER TABLE webhooks ADD COLUMN include_details INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE webhooks ADD COLUMN allow_private INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE webhooks ADD COLUMN created_by INTEGER",
    # Status persistence: track user's explicit offline preference
    "ALTER TABLE users ADD COLUMN status_preference TEXT",
    # Relay error tracking: persist last ffmpeg failure for operator visibility
    "ALTER TABLE stream_relay_destinations ADD COLUMN last_error TEXT DEFAULT NULL",
    "ALTER TABLE stream_relay_destinations ADD COLUMN last_error_at TEXT DEFAULT NULL",
    # Bind any service (proxy or managed) to a systemd unit for lifecycle control
    "ALTER TABLE services ADD COLUMN systemd_unit TEXT DEFAULT NULL",
    # App-wide IP blocking
    """CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        reason TEXT,
        blocked_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT DEFAULT NULL,
        FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)",
    # Who made the block: 'manual' (an admin) or 'auto' (the server). Existing rows are manual.
    "ALTER TABLE blocked_ips ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'",
    # What an automatic block was for: 'login' (failed sign-ins) or 'probe' (scanner paths).
    # NULL on manual rows and on rows written before 1.18.0. Older code ignores the column.
    "ALTER TABLE blocked_ips ADD COLUMN kind TEXT DEFAULT NULL",
    # Escalation history of automatic bans, so a repeat offence within 7 days lasts longer.
    # Kept apart from blocked_ips because the sweep and the unblock commands delete those rows.
    """CREATE TABLE IF NOT EXISTS ip_ban_history (
        ip_address TEXT NOT NULL,
        kind TEXT NOT NULL,
        offences INTEGER NOT NULL DEFAULT 1,
        last_ban_at TEXT NOT NULL,
        PRIMARY KEY (ip_address, kind)
    )""",
    # Addresses a user has signed in from, written at each successful sign-in. tokens rows are
    # deleted when a session ends, so they cannot answer "has this user signed in from here lately".
    """CREATE TABLE IF NOT EXISTS login_addresses (
        user_id INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        last_login_at TEXT NOT NULL,
        PRIMARY KEY (user_id, ip_address)
    )""",
    # Device-wide metrics: one JSON blob row per category per sample tick
    # (category in 'process' | 'port' | 'ip'). Written by device_metrics.py.
    """CREATE TABLE IF NOT EXISTS device_metric_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        category TEXT NOT NULL,
        entries_json TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_device_metrics_cat_ts ON device_metric_samples(category, ts)",
    # Shared access: let a connection owner grant other users use of a
    # connection, and an admin grant a user control/logs on one managed service.
    """CREATE TABLE IF NOT EXISTS connection_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        connection_id INTEGER NOT NULL,
        grantee_user_id INTEGER NOT NULL,
        granted_by INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (connection_id) REFERENCES user_connections(id) ON DELETE CASCADE,
        FOREIGN KEY (grantee_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(connection_id, grantee_user_id)
    )""",
    """CREATE TABLE IF NOT EXISTS service_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        grantee_user_id INTEGER NOT NULL,
        actions TEXT NOT NULL DEFAULT 'control',
        granted_by INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (grantee_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(service_id, grantee_user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_conn_shares_grantee ON connection_shares(grantee_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_conn_shares_conn ON connection_shares(connection_id)",
    "CREATE INDEX IF NOT EXISTS idx_service_grants_grantee ON service_grants(grantee_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_service_grants_service ON service_grants(service_id)",
    # Game servers (SteamCMD). game_catalog = curated + admin-added game
    # definitions; game_servers = deployed instances, each backed by a
    # services row (plugin='gameserver') for lifecycle + grants.
    """CREATE TABLE IF NOT EXISTS game_catalog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        steam_app_id INTEGER NOT NULL,
        steam_login TEXT DEFAULT 'anonymous',
        start_cmd TEXT NOT NULL,
        start_args TEXT DEFAULT '',
        stop_signal TEXT DEFAULT 'SIGTERM',
        config_paths TEXT DEFAULT '[]',
        backup_paths TEXT DEFAULT '[]',
        config_root TEXT,
        game_port INTEGER,
        icon TEXT DEFAULT 'game',
        notes TEXT,
        builtin INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS game_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        catalog_key TEXT,
        steam_app_id INTEGER NOT NULL,
        steam_login TEXT DEFAULT 'anonymous',
        install_dir TEXT NOT NULL,
        unit_name TEXT NOT NULL,
        start_cmd TEXT NOT NULL,
        start_args TEXT DEFAULT '',
        stop_signal TEXT DEFAULT 'SIGTERM',
        config_paths TEXT DEFAULT '[]',
        backup_paths TEXT DEFAULT '[]',
        config_root TEXT,
        service_id INTEGER,
        state TEXT DEFAULT 'installing',
        install_job TEXT,
        installed_build TEXT,
        latest_build TEXT,
        build_checked_at TEXT,
        created_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_game_servers_service ON game_servers(service_id)",
    # v1.10.1 — save/world backup globs, separate from the editable config globs;
    # config_root for games that keep config/saves outside the install tree
    "ALTER TABLE game_catalog ADD COLUMN backup_paths TEXT DEFAULT '[]'",
    "ALTER TABLE game_servers ADD COLUMN backup_paths TEXT DEFAULT '[]'",
    "ALTER TABLE game_catalog ADD COLUMN config_root TEXT",
    "ALTER TABLE game_servers ADD COLUMN config_root TEXT",
    # How the server binary is run: 'native', or 'wine' for Windows-only servers
    "ALTER TABLE game_catalog ADD COLUMN runtime TEXT DEFAULT 'native'",
    "ALTER TABLE game_servers ADD COLUMN runtime TEXT DEFAULT 'native'",
    # Admin-managed game-data storage locations (disks/mounts a new game
    # server can be deployed onto). Seeded from PORTAL_GAMEDATA_ROOT at boot
    # if empty -- see gameservers.ensure_default_storage_root().
    """CREATE TABLE IF NOT EXISTS game_storage_roots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL UNIQUE,
        label TEXT,
        is_default INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_game_storage_roots_default ON game_storage_roots(is_default)",
    # v1.13.0 -- security event log (see secevents.py). No foreign key to users:
    # rows outlive the account. ts is 'YYYY-MM-DD HH:MM:SS' UTC. agg_key is set
    # only on aggregated rows ("ip|event|result|minute") so a flood is one row
    # per source per minute; immediate rows leave it NULL (NULLs never collide).
    """CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event TEXT NOT NULL,
        category TEXT NOT NULL,
        user_id INTEGER,
        username_tried TEXT,
        ip TEXT,
        user_agent TEXT,
        result TEXT,
        details TEXT,
        count INTEGER NOT NULL DEFAULT 1,
        agg_key TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts)",
    "CREATE INDEX IF NOT EXISTS idx_security_events_event ON security_events(event, ts)",
    "CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip, ts)",
    "CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id, ts)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_agg ON security_events(agg_key)",
    # Sessions page: where and with what a login was made, and where it was last used
    "ALTER TABLE tokens ADD COLUMN ip TEXT",
    "ALTER TABLE tokens ADD COLUMN user_agent TEXT",
    "ALTER TABLE tokens ADD COLUMN last_ip TEXT",
    # API keys: address binding (comma-separated networks, NULL = not bound), where the key was
    # made and where it was last used
    "ALTER TABLE api_keys ADD COLUMN allowed_cidrs TEXT",
    "ALTER TABLE api_keys ADD COLUMN created_ip TEXT",
    "ALTER TABLE api_keys ADD COLUMN last_used_ip TEXT",
    # Search operators: link and file flags next to has_image (filled for old rows by the backfill)
    "ALTER TABLE chat_fts_map ADD COLUMN has_link INTEGER DEFAULT 0",
    "ALTER TABLE chat_fts_map ADD COLUMN has_file INTEGER DEFAULT 0",
    "ALTER TABLE dm_fts_map ADD COLUMN has_link INTEGER DEFAULT 0",
    "ALTER TABLE dm_fts_map ADD COLUMN has_file INTEGER DEFAULT 0",
    # Expiring shares and grants: NULL = never (every row that exists today). A nullable
    # column with no default is a schema-only change, cheap on a large database.
    "ALTER TABLE connection_shares ADD COLUMN expires_at TEXT",
    "ALTER TABLE service_grants ADD COLUMN expires_at TEXT",
    "CREATE INDEX IF NOT EXISTS idx_conn_shares_expires ON connection_shares(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_service_grants_expires ON service_grants(expires_at)",
]

# Role hierarchy - higher index = more permissions
ROLE_HIERARCHY = ['user', 'moderator', 'admin', 'superadmin']

def get_role_level(role: str) -> int:
    """Get numeric level for a role (higher = more permissions)."""
    try:
        return ROLE_HIERARCHY.index(role)
    except ValueError:
        return 0

def can_manage_role(actor_role: str, target_role: str) -> bool:
    """Check if actor can manage users with target role.

    Superadmins can manage other superadmins.
    Other roles can only manage users with lower roles.
    """
    actor_level = get_role_level(actor_role)
    target_level = get_role_level(target_role)
    # Superadmins can manage anyone including other superadmins
    if actor_role == "superadmin":
        return True
    # Others must be higher level to manage
    return actor_level > target_level

def can_assign_role(actor_role: str, new_role: str) -> bool:
    """Check if actor can assign a specific role.

    Superadmins can assign any role including superadmin.
    Other roles can only assign roles below their level.
    """
    actor_level = get_role_level(actor_role)
    new_level = get_role_level(new_role)
    # Superadmins can assign any role
    if actor_role == "superadmin":
        return True
    # Others can only assign roles below their level
    return actor_level > new_level

def get_manageable_roles(actor_role: str) -> list[str]:
    """Get list of roles that actor can assign to others."""
    actor_level = get_role_level(actor_role)
    # Superadmins can assign any role
    if actor_role == "superadmin":
        return ROLE_HIERARCHY.copy()
    return [r for r in ROLE_HIERARCHY if get_role_level(r) < actor_level]


def _casefold_or_none(value):
    return value.casefold() if isinstance(value, str) else value


class Database:
    """Async database operations for Open Relay Portal."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DATABASE_PATH
        self._connection: Optional[aiosqlite.Connection] = None
        # Terminal recordings whose session is still running (ids and file
        # names), kept by the recorder; retention must not touch these.
        self.live_recording_ids: set[int] = set()
        # Held while the search index backfill runs (see backfill_search_flags).
        self._search_backfill_lock = asyncio.Lock()
        self.live_recording_files: set[str] = set()
        # Folder holding chat uploads (a test points this at a temporary folder).
        self.chat_upload_dir: str = str(chat_uploads.DEFAULT_DIR)

    async def connect(self) -> None:
        """Initialize database connection and schema."""
        # Ensure parent directory exists (SQLite won't create directories)
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        # Unicode case folding for queries that group names without regard to case (SQLite's
        # own lower() and NOCASE fold ASCII only)
        await self._connection.create_function("casefold", 1, _casefold_or_none, deterministic=True)
        # Restrict DB file permissions even if umask is permissive
        os.chmod(self.db_path, 0o600)
        await self._connection.execute("PRAGMA journal_mode = WAL")
        await self._connection.execute("PRAGMA busy_timeout = 5000")
        # Cap the WAL file: without a limit it stays at its high-water mark
        # (a VACUUM writes the whole database through it) forever.
        await self._connection.execute("PRAGMA journal_size_limit = 67108864")
        await self._connection.execute("PRAGMA foreign_keys = ON")
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()
        await self._run_migrations()

    async def _run_migrations(self) -> None:
        """Run database migrations for schema updates."""
        for migration in MIGRATIONS:
            try:
                await self._connection.execute(migration)
                await self._connection.commit()
            except Exception as e:
                err_msg = str(e).lower()
                if "already exists" not in err_msg and "duplicate column" not in err_msg:
                    logger.warning(f"Migration skipped (non-duplicate error): {e}")
                # Column/table/index already exists — expected on re-run

        # Fix service_logs FK to reference services instead of managed_services
        await self._migrate_service_logs_fk()

        # System webhooks have no owner: webhooks.user_id becomes nullable
        await self._migrate_webhooks_owner_nullable()

        # Allow several bans per user and stream (one named, any number
        # recorded from anonymous posts)
        await self._migrate_stream_bans_anonymous()

        # Generate public keys for any streams that don't have one
        await self._populate_stream_public_keys()

        # Encrypt any plaintext configs (one-time migration)
        await self._migrate_encrypt_configs()

        # Encrypt any plaintext stream keys (one-time migration)
        await self._migrate_encrypt_stream_keys()

        # Re-encrypt all data with machine-bound keys (one-time migration)
        await self._migrate_encryption_to_machine_key()

        # Encrypt any remaining plaintext chat data (polls, automod, reply previews)
        await self._migrate_encrypt_plaintext_chat_data()

        # Encrypt notifications, automod rules, and audit log details
        await self._migrate_encrypt_extended_data()

        # One-time: rotate playback keys of private streams, scrub go-live notifications
        await self._migrate_private_stream_keys()
        await self._relabel_private_stream_activity_at_start()

        # Generate UUIDs for any connections that don't have one
        await self._populate_connection_uuids()

        # Seed default connections for existing users who don't have one
        await self._seed_default_connections()

        # Encrypt plaintext TOTP secrets and hash plaintext backup codes
        await self._migrate_totp_and_backup_codes()

        # Blocks are kept in canonical address form
        await self._migrate_blocked_ips_canonical()

    async def _migrate_blocked_ips_canonical(self) -> None:
        """Rewrite blocked_ips rows to the canonical address form (idempotent).

        Rows typed as '2001:DB8::1' or '::ffff:1.2.3.4' become '2001:db8::1' and
        '1.2.3.4'. When several rows are one address, one is kept (a manual block
        over an automatic one, then the one that lasts longest) and given the
        longest expiry of the group, so the merge never blocks for less time
        than before. Rows that are not an address are left alone.
        """
        try:
            cursor = await self._connection.execute(
                "SELECT id, ip_address, expires_at, source FROM blocked_ips ORDER BY id")
            rows = [dict(r) for r in await cursor.fetchall()]
        except Exception as e:
            logger.warning(f"Block list normalisation skipped: {e}")
            return
        groups: dict[str, list[dict]] = {}
        for r in rows:
            canon = ipguard.canonical_ip(r["ip_address"])
            if canon is not None:
                groups.setdefault(canon, []).append(r)
        changed = False
        for canon, grp in groups.items():
            if len(grp) == 1 and grp[0]["ip_address"] == canon:
                continue

            def strength(r):
                return (r["source"] == "manual", r["expires_at"] is None, r["expires_at"] or "")

            keep = max(grp, key=strength)
            expires = None if any(r["expires_at"] is None for r in grp) else max(r["expires_at"] for r in grp)
            for r in grp:
                if r["id"] != keep["id"]:
                    await self._connection.execute("DELETE FROM blocked_ips WHERE id = ?", (r["id"],))
            await self._connection.execute(
                "UPDATE blocked_ips SET ip_address = ?, expires_at = ? WHERE id = ?",
                (canon, expires, keep["id"]))
            changed = True
        if changed:
            await self._connection.commit()
            logger.info("Block list: addresses rewritten to their canonical form")

    async def _seed_default_connections(self) -> None:
        """One-time: add default Web Browser connection and enable browser_mode on existing ones."""
        try:
            # Check if this migration already ran
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = 'default_connections_seeded'"
            )
            row = await cursor.fetchone()
            if row:
                return  # Already done

            browser_config = encrypt_config('{}')

            # Create for users who don't have one
            cursor = await self._connection.execute(
                """SELECT u.id FROM users u
                   WHERE u.id NOT IN (
                       SELECT DISTINCT user_id FROM user_connections
                       WHERE name = 'Web Browser' AND type = 'http_proxy' AND host = 'duckduckgo.com'
                   )"""
            )
            rows = await cursor.fetchall()
            for row in rows:
                uuid_val = _secrets.token_urlsafe(12)
                await self._connection.execute(
                    """INSERT INTO user_connections
                       (user_id, name, type, host, port, config, icon, portal_access, api_access, uuid)
                       VALUES (?, 'Web Browser', 'http_proxy', 'duckduckgo.com', 443, ?, 'globe', 1, 0, ?)""",
                    (row["id"], browser_config, uuid_val)
                )

            # Update existing Web Browser connections to have browser_mode config
            await self._connection.execute(
                """UPDATE user_connections SET config = ?
                   WHERE name = 'Web Browser' AND type = 'http_proxy' AND host = 'duckduckgo.com'""",
                (browser_config,)
            )

            # Mark as done so it doesn't re-run
            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('default_connections_seeded', '1')"
            )
            await self._connection.commit()
        except Exception:
            pass  # Table may not exist yet on first run

    async def _migrate_totp_and_backup_codes(self) -> None:
        """One-time: encrypt plaintext TOTP secrets and hash plaintext backup codes.

        TOTP secrets are encrypted with Fernet (encrypt_message).
        Backup codes are hashed with SHA-256.
        Uses a settings flag to avoid re-running.
        """
        try:
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = 'totp_backup_codes_migrated'"
            )
            row = await cursor.fetchone()
            if row:
                return  # Already done
        except Exception:
            return  # settings table may not exist yet

        total_totp = 0
        total_backup = 0

        try:
            # Migrate TOTP secrets: encrypt any that are plaintext
            # Fernet tokens are base64url and 120+ chars; plaintext TOTP secrets are
            # base32 strings typically 16-32 chars. Use length as the discriminator.
            cursor = await self._connection.execute(
                "SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ''"
            )
            rows = await cursor.fetchall()
            for row in rows:
                secret = row["totp_secret"]
                if len(secret) < 100:
                    # Likely plaintext base32 — encrypt it
                    encrypted = encrypt_message(secret)
                    await self._connection.execute(
                        "UPDATE users SET totp_secret = ? WHERE id = ?",
                        (encrypted, row["id"])
                    )
                    total_totp += 1

            # Migrate backup codes: hash any that are plaintext
            # Plaintext codes are 8-char uppercase hex (e.g. "A1B2C3D4")
            # SHA-256 hashes are 64-char lowercase hex
            cursor = await self._connection.execute(
                "SELECT id, backup_codes FROM users WHERE backup_codes IS NOT NULL AND backup_codes != ''"
            )
            rows = await cursor.fetchall()
            for row in rows:
                codes_str = row["backup_codes"]
                codes = codes_str.split(",")
                # Check if first code looks like plaintext (8 chars) vs hash (64 chars)
                if codes and len(codes[0]) < 64:
                    hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
                    await self._connection.execute(
                        "UPDATE users SET backup_codes = ? WHERE id = ?",
                        (",".join(hashed_codes), row["id"])
                    )
                    total_backup += 1

            # Mark migration complete
            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('totp_backup_codes_migrated', '1')"
            )
            await self._connection.commit()

            if total_totp or total_backup:
                logger.info(
                    f"TOTP/backup migration: encrypted {total_totp} TOTP secret(s), "
                    f"hashed {total_backup} backup code set(s)"
                )
        except Exception as e:
            err_lower = str(e).lower()
            if "no such table" not in err_lower:
                logger.warning(f"TOTP/backup code migration error: {e}")

    async def _migrate_service_logs_fk(self) -> None:
        """Fix service_logs FK: managed_services(id) -> services(id)."""
        try:
            # Check if the FK still points to managed_services
            cursor = await self._connection.execute("PRAGMA foreign_key_list(service_logs)")
            rows = await cursor.fetchall()
            needs_fix = any(row["table"] == "managed_services" for row in rows)
            if not needs_fix:
                return
            # Must disable FK checks to recreate table
            await self._connection.execute("PRAGMA foreign_keys = OFF")
            await self._connection.execute("""
                CREATE TABLE IF NOT EXISTS service_logs_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id INTEGER NOT NULL,
                    level TEXT DEFAULT 'info',
                    message TEXT NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
                )
            """)
            await self._connection.execute(
                "INSERT INTO service_logs_new SELECT * FROM service_logs"
            )
            await self._connection.execute("DROP TABLE service_logs")
            await self._connection.execute(
                "ALTER TABLE service_logs_new RENAME TO service_logs"
            )
            await self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_service_logs_service ON service_logs(service_id)"
            )
            await self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_service_logs_timestamp ON service_logs(timestamp)"
            )
            await self._connection.commit()
            await self._connection.execute("PRAGMA foreign_keys = ON")
        except Exception:
            await self._connection.execute("PRAGMA foreign_keys = ON")

    _WEBHOOK_COLUMNS = (
        "id, user_id, name, type, url, secret, token, events, channel_id, enabled, "
        "consecutive_failures, last_delivery_at, last_failure_at, last_failure_reason, "
        "created_at, updated_at, kind, format, format_config, include_details, "
        "allow_private, created_by")

    async def _migrate_webhooks_owner_nullable(self) -> None:
        """Rebuild webhooks with a nullable user_id (a system webhook has no owner).

        Ids, tokens and every column are copied as they are, so webhook_logs
        rows still point at their webhook. Foreign keys are off for the
        rebuild (a DROP with them on would cascade into webhook_logs). Does
        nothing when user_id is already nullable, so it is safe to repeat.
        """
        conn = self._connection
        try:
            cursor = await conn.execute("PRAGMA table_info(webhooks)")
            info = {row["name"]: row for row in await cursor.fetchall()}
            if not info or "user_id" not in info or not info["user_id"]["notnull"]:
                return
            if not {"kind", "format", "format_config", "include_details", "allow_private",
                    "created_by"} <= set(info):
                logger.warning("webhooks rebuild skipped: new columns are missing")
                return
            await conn.commit()
            await conn.execute("PRAGMA foreign_keys = OFF")
            try:
                await conn.execute("BEGIN")
                await conn.execute("DROP TABLE IF EXISTS webhooks_new")
                await conn.execute("""
                    CREATE TABLE webhooks_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL DEFAULT 'outgoing',
                        url TEXT,
                        secret TEXT NOT NULL,
                        token TEXT UNIQUE,
                        events TEXT NOT NULL DEFAULT '[]',
                        channel_id INTEGER,
                        enabled INTEGER DEFAULT 1,
                        consecutive_failures INTEGER DEFAULT 0,
                        last_delivery_at TEXT,
                        last_failure_at TEXT,
                        last_failure_reason TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        kind TEXT NOT NULL DEFAULT 'user',
                        format TEXT NOT NULL DEFAULT 'generic',
                        format_config TEXT,
                        include_details INTEGER NOT NULL DEFAULT 0,
                        allow_private INTEGER NOT NULL DEFAULT 0,
                        created_by INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE SET NULL
                    )""")
                await conn.execute(
                    f"INSERT INTO webhooks_new ({self._WEBHOOK_COLUMNS}) "
                    f"SELECT {self._WEBHOOK_COLUMNS} FROM webhooks ORDER BY id")
                await conn.execute("DROP TABLE webhooks")
                await conn.execute("ALTER TABLE webhooks_new RENAME TO webhooks")
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id)")
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_webhooks_type_enabled ON webhooks(type, enabled)")
                await conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_token ON webhooks(token)")
                await conn.commit()
            except Exception:
                try:
                    await conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                await conn.execute("PRAGMA foreign_keys = ON")
        except Exception as e:
            logger.warning(f"webhooks migration failed: {e}")

    async def _migrate_stream_bans_anonymous(self) -> None:
        """Rebuild stream_bans without UNIQUE(stream_id, user_id).

        A ban made from an anonymous post is recorded with anonymous = 1 and
        the id of that message. It lives next to a named ban of the same user
        so that nothing the stream owner can do (banning or unbanning by
        account id) shows whether a masked ban exists for that account. Only
        one named ban per user and stream remains unique, through a partial
        index. Safe to run repeatedly.
        """
        conn = self._connection
        try:
            cursor = await conn.execute("PRAGMA index_list(stream_bans)")
            old_constraint = any(row["origin"] == "u" for row in await cursor.fetchall())
            cursor = await conn.execute("PRAGMA table_info(stream_bans)")
            cols = {row["name"] for row in await cursor.fetchall()}
            if old_constraint or not {"anonymous", "message_id"} <= cols:
                await conn.execute("PRAGMA foreign_keys = OFF")
                try:
                    await conn.execute("DROP TABLE IF EXISTS stream_bans_new")
                    await conn.execute("""
                        CREATE TABLE stream_bans_new (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            stream_id INTEGER NOT NULL,
                            user_id INTEGER NOT NULL,
                            banned_by INTEGER NOT NULL,
                            reason TEXT,
                            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                            anonymous INTEGER NOT NULL DEFAULT 0,
                            message_id INTEGER,
                            banned_by_anonymous INTEGER NOT NULL DEFAULT 0,
                            FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE CASCADE
                        )
                    """)
                    anon_sql = "COALESCE(anonymous, 0)" if "anonymous" in cols else "0"
                    msg_sql = "message_id" if "message_id" in cols else "NULL"
                    by_anon_sql = ("COALESCE(banned_by_anonymous, 0)"
                                   if "banned_by_anonymous" in cols else "0")
                    await conn.execute(
                        "INSERT INTO stream_bans_new "
                        "(id, stream_id, user_id, banned_by, reason, created_at, anonymous, message_id, "
                        "banned_by_anonymous) "
                        "SELECT id, stream_id, user_id, banned_by, reason, created_at, "
                        + anon_sql + ", " + msg_sql + ", " + by_anon_sql + " FROM stream_bans ORDER BY id"
                    )
                    await conn.execute("DROP TABLE stream_bans")
                    await conn.execute("ALTER TABLE stream_bans_new RENAME TO stream_bans")
                    await conn.commit()
                finally:
                    await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_stream_bans_stream ON stream_bans(stream_id)")
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_stream_bans_user ON stream_bans(user_id)")
            await conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_stream_bans_named "
                "ON stream_bans(stream_id, user_id) WHERE anonymous = 0")
            await conn.commit()
        except Exception as e:
            logger.warning(f"stream_bans migration failed: {e}")
            try:
                await conn.rollback()
            except Exception:
                pass

    async def _populate_stream_public_keys(self) -> None:
        """Generate public keys for streams that don't have one."""
        import secrets
        cursor = await self._connection.execute(
            "SELECT id FROM user_streams WHERE public_key IS NULL OR public_key = ''"
        )
        rows = await cursor.fetchall()
        for row in rows:
            public_key = f"pub_{secrets.token_urlsafe(16)}"
            pk_hash = hash_stream_key(public_key)
            pk_encrypted = encrypt_config(public_key) if CRYPTO_AVAILABLE else public_key
            await self._connection.execute(
                "UPDATE user_streams SET public_key = ?, public_key_hash = ? WHERE id = ?",
                (pk_encrypted, pk_hash, row["id"])
            )
        if rows:
            await self._connection.commit()

    async def _populate_connection_uuids(self) -> None:
        """Generate UUIDs for any connections that don't have one (migration)."""
        try:
            cursor = await self._connection.execute(
                "SELECT id FROM user_connections WHERE uuid IS NULL"
            )
            rows = await cursor.fetchall()
            for row in rows:
                uuid_val = _secrets.token_urlsafe(12)
                await self._connection.execute(
                    "UPDATE user_connections SET uuid = ? WHERE id = ?",
                    (uuid_val, row["id"])
                )
            if rows:
                await self._connection.commit()
            # Create unique index (idempotent)
            await self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_connections_uuid ON user_connections(uuid)"
            )
            await self._connection.commit()
        except Exception:
            pass  # Column may not exist yet on first run

    async def _migrate_encrypt_configs(self) -> None:
        """Encrypt any plaintext config fields (one-time migration).

        Migrates user_connections, services, and vod_storage tables.
        Encrypted values are prefixed with 'enc:' — already-encrypted rows are skipped.
        """
        if not CRYPTO_AVAILABLE:
            return

        tables = ["user_connections", "services", "vod_storage"]
        total = 0
        for table in tables:
            try:
                cursor = await self._connection.execute(
                    f"SELECT id, config FROM {table} WHERE config IS NOT NULL AND config != '{{}}' AND config NOT LIKE 'enc:%'"
                )
                rows = await cursor.fetchall()
                for row in rows:
                    config_str = row["config"]
                    if config_str:
                        encrypted = encrypt_config(config_str)
                        await self._connection.execute(
                            f"UPDATE {table} SET config = ? WHERE id = ?",
                            (encrypted, row["id"])
                        )
                        total += 1
            except Exception as e:
                err_lower = str(e).lower()
                if "no such table" not in err_lower:
                    logger.debug(f"Config encryption migration skipped for {table}: {e}")
        if total:
            await self._connection.commit()
            import logging
            logging.getLogger("portal.database").info(
                f"Encrypted {total} plaintext config(s) across {', '.join(tables)}"
            )

    async def _migrate_encrypt_stream_keys(self) -> None:
        """Encrypt plaintext stream keys and populate hash columns (one-time migration).

        For each row where stream_key does NOT start with 'enc:':
        1. Compute SHA-256 hash of the plaintext key -> store in stream_key_hash
        2. Fernet-encrypt the plaintext key -> overwrite stream_key with 'enc:...'
        Same process for public_key / public_key_hash.
        """
        if not CRYPTO_AVAILABLE:
            return

        try:
            cursor = await self._connection.execute(
                "SELECT id, stream_key, public_key FROM user_streams "
                "WHERE stream_key IS NOT NULL AND stream_key != '' AND stream_key NOT LIKE 'enc:%'"
            )
            rows = await cursor.fetchall()
        except Exception as e:
            if "no such table" not in str(e).lower():
                logger.debug(f"Stream key migration skipped: {e}")
            return

        total = 0
        for row in rows:
            stream_key = row["stream_key"]
            public_key = row["public_key"]

            sk_hash = hash_stream_key(stream_key)
            sk_encrypted = encrypt_config(stream_key)

            pk_hash = hash_stream_key(public_key) if public_key else None
            pk_encrypted = encrypt_config(public_key) if public_key else None

            await self._connection.execute(
                "UPDATE user_streams SET stream_key = ?, stream_key_hash = ?, "
                "public_key = ?, public_key_hash = ? WHERE id = ?",
                (sk_encrypted, sk_hash, pk_encrypted, pk_hash, row["id"])
            )
            total += 1

        if total:
            await self._connection.commit()
            import logging
            logging.getLogger("portal.database").info(
                f"Encrypted {total} plaintext stream key(s)"
            )

    async def _migrate_encryption_to_machine_key(self) -> None:
        """Re-encrypt all data with machine-bound keys (one-time migration).

        Detects data encrypted with the old hardcoded-salt keys and re-encrypts
        it with the new machine-bound keys. Uses a DB setting to track completion.
        """
        if not CRYPTO_AVAILABLE:
            return

        import logging
        log = logging.getLogger("portal.database")

        # Check if already migrated
        try:
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = 'encryption_key_version'"
            )
            row = await cursor.fetchone()
            if row and row["value"] == "2":
                return  # Already migrated
        except Exception:
            pass  # Settings table might not exist yet

        # Ensure machine salt file exists
        _get_encryption_salt()

        old_config_key = _get_legacy_config_key()
        new_config_key = get_config_encryption_key()
        old_chat_key = _get_legacy_chat_key()
        new_chat_key = get_chat_encryption_key()

        # Skip if keys are identical (shouldn't happen, but safety check)
        if old_config_key == new_config_key:
            try:
                await self._connection.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('encryption_key_version', '2')"
                )
                await self._connection.commit()
            except Exception:
                pass
            return

        total = 0
        failed = 0

        # 1. Re-encrypt config fields (user_connections, services, vod_storage)
        for table in ["user_connections", "services", "vod_storage"]:
            try:
                cursor = await self._connection.execute(
                    f"SELECT id, config FROM {table} WHERE config LIKE 'enc:%'"
                )
                rows = await cursor.fetchall()
                for row in rows:
                    try:
                        old_f = Fernet(old_config_key)
                        plaintext = old_f.decrypt(row["config"][4:].encode()).decode()
                        new_f = Fernet(new_config_key)
                        new_encrypted = "enc:" + new_f.encrypt(plaintext.encode()).decode()
                        await self._connection.execute(
                            f"UPDATE {table} SET config = ? WHERE id = ?",
                            (new_encrypted, row["id"])
                        )
                        total += 1
                    except Exception as e:
                        failed += 1
                        logger.debug(f"Re-encryption failed for {table} id={row['id']}: {type(e).__name__}")
            except Exception as e:
                if "no such table" not in str(e).lower():
                    logger.debug(f"Re-encryption skipped for {table}: {e}")

        # 2. Re-encrypt stream keys
        try:
            cursor = await self._connection.execute(
                "SELECT id, stream_key, public_key FROM user_streams "
                "WHERE stream_key LIKE 'enc:%'"
            )
            rows = await cursor.fetchall()
            for row in rows:
                try:
                    old_f = Fernet(old_config_key)
                    new_f = Fernet(new_config_key)
                    updates = {}
                    if row["stream_key"] and row["stream_key"].startswith("enc:"):
                        sk_plain = old_f.decrypt(row["stream_key"][4:].encode()).decode()
                        updates["stream_key"] = "enc:" + new_f.encrypt(sk_plain.encode()).decode()
                    if row["public_key"] and row["public_key"].startswith("enc:"):
                        pk_plain = old_f.decrypt(row["public_key"][4:].encode()).decode()
                        updates["public_key"] = "enc:" + new_f.encrypt(pk_plain.encode()).decode()
                    if updates:
                        set_clause = ", ".join(f"{k} = ?" for k in updates)
                        await self._connection.execute(
                            f"UPDATE user_streams SET {set_clause} WHERE id = ?",
                            (*updates.values(), row["id"])
                        )
                        total += 1
                except Exception as e:
                    failed += 1
                    logger.debug(f"Stream key re-encryption failed for id={row['id']}: {type(e).__name__}")
        except Exception as e:
            if "no such table" not in str(e).lower():
                logger.debug(f"Stream key re-encryption skipped: {e}")

        # 3. Re-encrypt chat messages (content + reply_preview)
        chat_total = 0
        chat_failed = 0
        try:
            old_f = Fernet(old_chat_key)
            new_f = Fernet(new_chat_key)
            cursor = await self._connection.execute(
                "SELECT id, message, reply_preview_text FROM chat_messages"
            )
            rows = await cursor.fetchall()
            for row in rows:
                try:
                    updates = {}
                    if row["message"]:
                        try:
                            plaintext = old_f.decrypt(row["message"].encode()).decode()
                            updates["message"] = new_f.encrypt(plaintext.encode()).decode()
                        except Exception:
                            pass  # Might be unencrypted legacy
                    if row.get("reply_preview_text"):
                        try:
                            plaintext = old_f.decrypt(row["reply_preview_text"].encode()).decode()
                            updates["reply_preview_text"] = new_f.encrypt(plaintext.encode()).decode()
                        except Exception:
                            pass
                    if updates:
                        set_clause = ", ".join(f"{k} = ?" for k in updates)
                        await self._connection.execute(
                            f"UPDATE chat_messages SET {set_clause} WHERE id = ?",
                            (*updates.values(), row["id"])
                        )
                        chat_total += 1
                except Exception as e:
                    chat_failed += 1
                    logger.debug(f"Chat message re-encryption failed for id={row['id']}: {type(e).__name__}")
        except Exception as e:
            if "no such table" not in str(e).lower():
                logger.debug(f"Chat message re-encryption skipped: {e}")

        # 4. Re-encrypt DM messages
        dm_total = 0
        dm_failed = 0
        try:
            old_f = Fernet(old_chat_key)
            new_f = Fernet(new_chat_key)
            cursor = await self._connection.execute(
                "SELECT id, message, reply_preview_text FROM dm_messages WHERE message IS NOT NULL"
            )
            rows = await cursor.fetchall()
            for row in rows:
                try:
                    updates = {}
                    if row["message"]:
                        try:
                            plaintext = old_f.decrypt(row["message"].encode()).decode()
                            updates["message"] = new_f.encrypt(plaintext.encode()).decode()
                        except Exception:
                            pass  # Might be unencrypted legacy
                    if row.get("reply_preview_text"):
                        try:
                            plaintext = old_f.decrypt(row["reply_preview_text"].encode()).decode()
                            updates["reply_preview_text"] = new_f.encrypt(plaintext.encode()).decode()
                        except Exception:
                            pass
                    if updates:
                        set_clause = ", ".join(f"{k} = ?" for k in updates)
                        await self._connection.execute(
                            f"UPDATE dm_messages SET {set_clause} WHERE id = ?",
                            (*updates.values(), row["id"])
                        )
                        dm_total += 1
                except Exception as e:
                    dm_failed += 1
                    logger.debug(f"DM re-encryption failed for id={row['id']}: {type(e).__name__}")
        except Exception as e:
            if "no such table" not in str(e).lower():
                logger.debug(f"DM re-encryption skipped: {e}")

        if total or chat_total or dm_total:
            await self._connection.commit()
            log.info(
                f"Migrated encryption to machine-bound keys: "
                f"{total} config(s), {chat_total} chat message(s), {dm_total} DM(s)"
            )

        total_failed = failed + chat_failed + dm_failed
        if total_failed:
            log.warning(
                f"Encryption migration completed with {total_failed} failed row(s): "
                f"{failed} config(s), {chat_failed} chat message(s), {dm_failed} DM(s)"
            )

        # Mark migration complete (even with failures, to avoid infinite retries)
        try:
            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('encryption_key_version', '2')"
            )
            await self._connection.commit()
        except Exception:
            pass

    async def _migrate_encrypt_plaintext_chat_data(self) -> None:
        """Encrypt any remaining plaintext chat data (polls, automod, reply previews).

        Detects plaintext by checking for absence of Fernet token prefix (gAAAAAB).
        Uses a settings flag to avoid re-running.
        """
        if not CRYPTO_AVAILABLE:
            return
        import logging
        log = logging.getLogger("portal.database")

        try:
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = 'plaintext_chat_migrated'"
            )
            row = await cursor.fetchone()
            if row and row["value"] == "1":
                return
        except Exception:
            pass

        total = 0

        # 1. Encrypt plaintext reply_preview_text in chat_messages
        try:
            cursor = await self._connection.execute(
                "SELECT id, reply_preview_text FROM chat_messages WHERE reply_preview_text IS NOT NULL AND reply_preview_text != ''"
            )
            for row in await cursor.fetchall():
                val = row["reply_preview_text"]
                if not val.startswith("gAAAAAB"):
                    encrypted = encrypt_message(val)
                    await self._connection.execute(
                        "UPDATE chat_messages SET reply_preview_text = ? WHERE id = ?",
                        (encrypted, row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Reply preview encryption skipped: {e}")

        # 2. Encrypt plaintext poll questions and options
        try:
            cursor = await self._connection.execute(
                "SELECT id, question, options FROM chat_polls"
            )
            for row in await cursor.fetchall():
                updates = {}
                if row["question"] and not row["question"].startswith("gAAAAAB"):
                    updates["question"] = encrypt_message(row["question"])
                if row["options"] and not row["options"].startswith("gAAAAAB"):
                    updates["options"] = encrypt_message(row["options"])
                if updates:
                    sets = ", ".join(f"{k} = ?" for k in updates)
                    await self._connection.execute(
                        f"UPDATE chat_polls SET {sets} WHERE id = ?",
                        (*updates.values(), row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Poll encryption skipped: {e}")

        # 3. Encrypt plaintext automod action message_text
        try:
            cursor = await self._connection.execute(
                "SELECT id, message_text FROM automod_actions WHERE message_text IS NOT NULL AND message_text != ''"
            )
            for row in await cursor.fetchall():
                val = row["message_text"]
                if not val.startswith("gAAAAAB"):
                    encrypted = encrypt_message(val)
                    await self._connection.execute(
                        "UPDATE automod_actions SET message_text = ? WHERE id = ?",
                        (encrypted, row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Automod encryption skipped: {e}")

        if total:
            await self._connection.commit()
            log.info(f"Encrypted {total} plaintext chat data row(s) (polls, automod, reply previews)")

        try:
            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('plaintext_chat_migrated', '1')"
            )
            await self._connection.commit()
        except Exception:
            pass

    async def relabel_private_stream_activity(self, user_id: int, names, commit: bool = True) -> int:
        """Turn the stored 'stream_live' / 'stream_offline' activity rows of one owner that name
        one of these streams into 'stream_live_private' / 'stream_offline_private', which no
        other member is shown. The rows carry no stream id, only the name in their text
        ("Stream 'x' went live"), so the match is by owner and exact text; it uses the
        (user_id, action) index, so it reads only that owner's rows of those two actions. Idempotent."""
        total = 0
        for name in {n for n in names if n}:
            for verb in ("live", "offline"):
                cursor = await self.conn.execute(
                    "UPDATE activity_log SET action = ? WHERE user_id = ? AND action = ? AND detail = ?",
                    (f"stream_{verb}_private", user_id, f"stream_{verb}", f"Stream '{name}' went {verb}"))
                total += cursor.rowcount or 0
        if commit and total:
            await self.conn.commit()
        return total

    async def _relabel_private_stream_activity_at_start(self) -> None:
        """Every start: relabel the stored activity rows of every stream that is not public (a
        stream made private while rows from its public time were stored, or a rename that
        brought them back through the read-time name match). Cheap: one indexed pass per
        non-public stream; nothing to do once the rows are relabelled."""
        import logging
        try:
            cursor = await self._connection.execute(
                "SELECT user_id, name FROM user_streams WHERE COALESCE(is_public, 0) = 0")
            total = 0
            for row in await cursor.fetchall():
                total += await self.relabel_private_stream_activity(row["user_id"], [row["name"]], commit=False)
            await self._connection.commit()
            if total:
                logging.getLogger("portal.database").info(
                    "Relabelled %d stored activity row(s) of non-public streams", total)
        except Exception as e:
            logging.getLogger("portal.database").warning("Relabelling private stream activity failed: %s", e)

    async def _migrate_private_stream_keys(self) -> None:
        """Rotate the playback key of every private stream and strip the key from
        stored go-live notifications. Runs once (settings flag); safe on an empty DB."""
        import logging
        import secrets
        log = logging.getLogger("portal.database")
        flag = "private_stream_keys_rotated_v1"
        try:
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = ?", (flag,)
            )
            row = await cursor.fetchone()
            if row and row["value"] == "1":
                return
        except Exception:
            return

        try:
            rotated = 0
            cursor = await self._connection.execute(
                "SELECT id FROM user_streams WHERE is_public = 0 OR is_public IS NULL"
            )
            for row in await cursor.fetchall():
                new_key = f"pub_{secrets.token_urlsafe(16)}"
                pk_encrypted = encrypt_config(new_key) if CRYPTO_AVAILABLE else new_key
                await self._connection.execute(
                    "UPDATE user_streams SET public_key = ?, public_key_hash = ?, updated_at = ? WHERE id = ?",
                    (pk_encrypted, hash_stream_key(new_key),
                     datetime.now(timezone.utc).isoformat(), row["id"])
                )
                rotated += 1

            scrubbed = 0
            cursor = await self._connection.execute(
                "SELECT id, data FROM notifications WHERE type = 'stream_live' AND data LIKE '%public_key%'"
            )
            for row in await cursor.fetchall():
                try:
                    payload = json.loads(row["data"])
                except (TypeError, ValueError):
                    continue
                if isinstance(payload, dict) and "public_key" in payload:
                    payload.pop("public_key", None)
                    await self._connection.execute(
                        "UPDATE notifications SET data = ? WHERE id = ?",
                        (json.dumps(payload), row["id"])
                    )
                    scrubbed += 1

            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, '1')", (flag,)
            )
            await self._connection.commit()
            if rotated or scrubbed:
                log.info(f"Rotated {rotated} private stream playback key(s), "
                         f"scrubbed {scrubbed} go-live notification(s)")
        except Exception as e:
            await self._connection.rollback()
            log.warning(f"Private stream key rotation failed (will retry next start): {e}")

    async def _migrate_encrypt_extended_data(self) -> None:
        """Encrypt plaintext notifications, automod rules config, and audit log details."""
        if not CRYPTO_AVAILABLE:
            return
        import logging
        log = logging.getLogger("portal.database")
        try:
            cursor = await self._connection.execute(
                "SELECT value FROM settings WHERE key = 'extended_encryption_migrated'"
            )
            row = await cursor.fetchone()
            if row and row["value"] == "1":
                return
        except Exception:
            pass

        total = 0

        # 1. Encrypt notification title and message
        try:
            cursor = await self._connection.execute(
                "SELECT id, title, message FROM notifications"
            )
            for row in await cursor.fetchall():
                updates = {}
                if row["title"] and not row["title"].startswith("gAAAAAB"):
                    updates["title"] = encrypt_message(row["title"])
                if row["message"] and not row["message"].startswith("gAAAAAB"):
                    updates["message"] = encrypt_message(row["message"])
                if updates:
                    sets = ", ".join(f"{k} = ?" for k in updates)
                    await self._connection.execute(
                        f"UPDATE notifications SET {sets} WHERE id = ?",
                        (*updates.values(), row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Notification encryption skipped: {e}")

        # 2. Encrypt automod_rules config
        try:
            cursor = await self._connection.execute(
                "SELECT id, config FROM automod_rules WHERE config IS NOT NULL AND config != ''"
            )
            for row in await cursor.fetchall():
                val = row["config"]
                if not val.startswith("gAAAAAB"):
                    encrypted = encrypt_message(val)
                    await self._connection.execute(
                        "UPDATE automod_rules SET config = ? WHERE id = ?",
                        (encrypted, row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Automod rules encryption skipped: {e}")

        # 3. Encrypt audit_log details
        try:
            cursor = await self._connection.execute(
                "SELECT id, details FROM audit_log WHERE details IS NOT NULL AND details != ''"
            )
            for row in await cursor.fetchall():
                val = row["details"]
                if not val.startswith("gAAAAAB"):
                    encrypted = encrypt_message(val)
                    await self._connection.execute(
                        "UPDATE audit_log SET details = ? WHERE id = ?",
                        (encrypted, row["id"])
                    )
                    total += 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                log.debug(f"Audit log encryption skipped: {e}")

        if total:
            await self._connection.commit()
            log.info(f"Encrypted {total} plaintext row(s) (notifications, automod rules, audit log)")

        try:
            await self._connection.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('extended_encryption_migrated', '1')"
            )
            await self._connection.commit()
        except Exception:
            pass

    @staticmethod
    def _decrypt_stream_keys(stream: dict) -> dict:
        """Decrypt stream_key and public_key fields in a stream dict, if encrypted."""
        if stream.get("stream_key") and stream["stream_key"].startswith("enc:"):
            stream["stream_key"] = decrypt_config(stream["stream_key"])
        if stream.get("public_key") and stream["public_key"].startswith("enc:"):
            stream["public_key"] = decrypt_config(stream["public_key"])
        return stream

    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if not self._connection:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._connection

    # User operations
    async def create_user(self, username: str, password_hash: str, is_admin: bool = False,
                          registration_ip: str = None) -> int:
        """Create a new user and return their ID."""
        cursor = await self.conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, registration_ip) VALUES (?, ?, ?, ?)",
            (username, password_hash, int(is_admin), registration_ip)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username."""
        cursor = await self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        user = dict(row)
        if user.get("totp_secret"):
            user["totp_secret"] = decrypt_message(user["totp_secret"])
        return user

    async def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Get user by ID."""
        cursor = await self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        user = dict(row)
        if user.get("totp_secret"):
            user["totp_secret"] = decrypt_message(user["totp_secret"])
        return user

    async def update_password_hash(self, user_id: int, password_hash: str) -> bool:
        """Update a user's password hash."""
        cursor = await self.conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (password_hash, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_user(self, user_id: int) -> bool:
        """Delete a user and all associated data (tokens, connections, streams, etc.).

        Explicitly deletes from all user-related tables. Uses try/except per-table
        in case migrations haven't created certain tables yet.
        """
        # Collect FTS rowids for cleanup before deleting map entries
        fts_cleanup = []
        for fts_table, map_table in [
            ("chat_messages_fts", "chat_fts_map"),
            ("dm_messages_fts", "dm_fts_map"),
        ]:
            try:
                cursor = await self.conn.execute(
                    f"SELECT rowid FROM {map_table} WHERE user_id = ?", (user_id,)
                )
                rows = await cursor.fetchall()
                for row in rows:
                    fts_cleanup.append((fts_table, row[0]))
            except Exception:
                pass

        # Delete FTS virtual table entries by rowid
        for fts_table, rowid in fts_cleanup:
            try:
                await self.conn.execute(
                    f"INSERT INTO {fts_table}({fts_table}, rowid, message) VALUES ('delete', ?, '')",
                    (rowid,)
                )
            except Exception:
                pass

        # Delete from all user-related tables. Each wrapped in try/except
        # in case a table doesn't exist yet (migrations may not have run).
        delete_statements = [
            # FTS map tables (after FTS cleanup above)
            ("chat_fts_map", "DELETE FROM chat_fts_map WHERE user_id = ?"),
            ("dm_fts_map", "DELETE FROM dm_fts_map WHERE user_id = ?"),
            # Chat reactions
            ("chat_reactions", "DELETE FROM chat_reactions WHERE user_id = ?"),
            ("dm_reactions", "DELETE FROM dm_reactions WHERE user_id = ?"),
            # Read positions
            ("channel_read_positions", "DELETE FROM channel_read_positions WHERE user_id = ?"),
            ("dm_read_positions", "DELETE FROM dm_read_positions WHERE user_id = ?"),
            # Poll votes (before polls, since polls may cascade)
            ("chat_poll_votes", "DELETE FROM chat_poll_votes WHERE user_id = ?"),
            # Polls created by user
            ("chat_polls", "DELETE FROM chat_polls WHERE user_id = ?"),
            # Chat timeouts (as target or moderator)
            ("chat_timeouts (target)", "DELETE FROM chat_timeouts WHERE user_id = ?"),
            ("chat_timeouts (moderator)", "DELETE FROM chat_timeouts WHERE moderator_id = ?"),
            # User blocks (as blocker or blocked)
            ("user_blocks (blocker)", "DELETE FROM user_blocks WHERE user_id = ?"),
            ("user_blocks (blocked)", "DELETE FROM user_blocks WHERE blocked_user_id = ?"),
            # Channel memberships
            ("channel_members", "DELETE FROM channel_members WHERE user_id = ?"),
            # Audit log entries by this user
            ("audit_log", "DELETE FROM audit_log WHERE actor_id = ?"),
            # Automod actions targeting this user
            ("automod_actions", "DELETE FROM automod_actions WHERE user_id = ?"),
            # Chat messages
            ("chat_messages", "DELETE FROM chat_messages WHERE user_id = ?"),
            # DM messages
            ("dm_messages", "DELETE FROM dm_messages WHERE user_id = ?"),
            # DM participants
            ("dm_participants", "DELETE FROM dm_participants WHERE user_id = ?"),
            # DM conversations created by user (only orphaned ones with no other participants)
            ("dm_conversations", "DELETE FROM dm_conversations WHERE created_by = ? AND id NOT IN (SELECT conversation_id FROM dm_participants)"),
            # Stream bans (as banned user)
            ("stream_bans", "DELETE FROM stream_bans WHERE user_id = ?"),
            # Stream follows
            ("stream_follow", "DELETE FROM stream_follow WHERE user_id = ?"),
            # Recordings
            ("recordings", "DELETE FROM recordings WHERE user_id = ?"),
            # SSH keys
            ("ssh_keys", "DELETE FROM ssh_keys WHERE user_id = ?"),
            # Tokens (no FK cascade)
            ("tokens", "DELETE FROM tokens WHERE user_id = ?"),
            ("login_addresses", "DELETE FROM login_addresses WHERE user_id = ?"),
            # API keys
            ("api_keys", "DELETE FROM api_keys WHERE user_id = ?"),
            # User connections
            ("user_connections", "DELETE FROM user_connections WHERE user_id = ?"),
            # User streams (cascade handles related stream data)
            ("user_streams", "DELETE FROM user_streams WHERE user_id = ?"),
            # Notifications
            ("notifications", "DELETE FROM notifications WHERE user_id = ?"),
            # Activity log
            ("activity_log", "DELETE FROM activity_log WHERE user_id = ?"),
            # VOD storage config
            ("vod_storage", "DELETE FROM vod_storage WHERE user_id = ?"),
        ]

        for table_name, sql in delete_statements:
            try:
                await self.conn.execute(sql, (user_id,))
            except Exception:
                pass  # Table may not exist if migration hasn't run

        # Delete the user
        cursor = await self.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await self.conn.commit()
        return cursor.rowcount > 0

    # Two-Factor Authentication operations
    async def set_user_totp_secret(self, user_id: int, secret: str) -> None:
        """Store TOTP secret for user (before enabling 2FA). Encrypted at rest."""
        encrypted_secret = encrypt_message(secret)
        await self.conn.execute(
            "UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?",
            (encrypted_secret, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()

    async def enable_user_totp(self, user_id: int, backup_codes: list[str]) -> None:
        """Enable TOTP for user and store backup codes (SHA-256 hashed)."""
        hashed_codes = [hashlib.sha256(code.encode()).hexdigest() for code in backup_codes]
        codes_str = ",".join(hashed_codes)
        await self.conn.execute(
            "UPDATE users SET totp_enabled = 1, backup_codes = ?, updated_at = ? WHERE id = ?",
            (codes_str, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()

    async def disable_user_totp(self, user_id: int) -> None:
        """Disable TOTP for user and clear secrets."""
        await self.conn.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL, backup_codes = NULL, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()

    async def use_backup_code(self, user_id: int, code: str) -> bool:
        """Use a backup code, removing it from available codes. Returns True if valid.

        Backup codes are stored as SHA-256 hashes. The input code is hashed before
        comparison. Uses constant-time comparison to prevent timing attacks and atomic
        read-modify-write to prevent race conditions with concurrent requests.
        """
        import hmac
        user = await self.get_user_by_id(user_id)
        if not user or not user.get("backup_codes"):
            return False
        codes = user["backup_codes"].split(",")
        code_hash = hashlib.sha256(code.upper().strip().encode()).hexdigest()
        # Constant-time scan: check all codes to prevent timing leaks
        match_idx = -1
        for i, stored_code in enumerate(codes):
            if hmac.compare_digest(code_hash.encode(), stored_code.encode()):
                match_idx = i
        if match_idx < 0:
            return False
        codes.pop(match_idx)
        # Atomic update: only succeed if backup_codes hasn't changed since we read it
        cursor = await self.conn.execute(
            "UPDATE users SET backup_codes = ?, updated_at = ? WHERE id = ? AND backup_codes = ?",
            (",".join(codes), datetime.now(timezone.utc).isoformat(), user_id, user["backup_codes"])
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # User status and profile operations
    async def get_user_status(self, user_id: int) -> Optional[dict]:
        """Get user status info."""
        cursor = await self.conn.execute(
            "SELECT id, username, nickname, status, status_message, status_preference FROM users WHERE id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def set_user_status(self, user_id: int, status: str, status_message: str = None,
                              update_preference: bool = False) -> bool:
        """Set user status (online, away, busy, dnd, offline).

        update_preference=True: also record the user's explicit choice in status_preference.
        When status is 'offline', status_preference is set to 'offline' (skip auto-online on reconnect).
        When status is anything else, status_preference is cleared (allow auto-online).
        """
        valid_statuses = ('online', 'away', 'busy', 'dnd', 'offline')
        if status not in valid_statuses:
            return False
        if update_preference:
            pref = 'offline' if status == 'offline' else None
            cursor = await self.conn.execute(
                "UPDATE users SET status = ?, status_message = ?, status_preference = ?, updated_at = ? WHERE id = ?",
                (status, status_message, pref, datetime.now(timezone.utc).isoformat(), user_id)
            )
        else:
            cursor = await self.conn.execute(
                "UPDATE users SET status = ?, status_message = ?, updated_at = ? WHERE id = ?",
                (status, status_message, datetime.now(timezone.utc).isoformat(), user_id)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def set_user_nickname(self, user_id: int, nickname: str) -> bool:
        """Set user nickname for chat display."""
        # Allow empty/null to clear nickname
        cursor = await self.conn.execute(
            "UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?",
            (nickname if nickname else None, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_users_status(self, user_ids: list[int]) -> list[dict]:
        """Get status for multiple users."""
        if not user_ids:
            return []
        placeholders = ",".join("?" * len(user_ids))
        cursor = await self.conn.execute(
            f"SELECT id, username, nickname, status, status_message, last_seen_at, role, chat_anonymous, avatar FROM users WHERE id IN ({placeholders})",
            user_ids
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def set_chat_anonymous(self, user_id: int, anonymous: bool) -> bool:
        """Set whether user hides their username in chat."""
        cursor = await self.conn.execute(
            "UPDATE users SET chat_anonymous = ?, updated_at = ? WHERE id = ?",
            (1 if anonymous else 0, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def set_avatar(self, user_id: int, avatar: dict) -> bool:
        """Set user avatar settings (color, emoji, initials)."""
        import json
        cursor = await self.conn.execute(
            "UPDATE users SET avatar = ?, updated_at = ? WHERE id = ?",
            (json.dumps(avatar), datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # User role operations
    async def get_user_role(self, user_id: int) -> Optional[str]:
        """Get user's role."""
        cursor = await self.conn.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        if row:
            # Handle legacy is_admin users that haven't been migrated
            role = row["role"]
            return role if role else "user"
        return None

    async def set_user_role(self, user_id: int, role: str) -> bool:
        """Set user's role."""
        if role not in ROLE_HIERARCHY:
            return False
        # Also update is_admin for backward compatibility
        is_admin = 1 if role in ('admin', 'superadmin') else 0
        cursor = await self.conn.execute(
            "UPDATE users SET role = ?, is_admin = ?, updated_at = ? WHERE id = ?",
            (role, is_admin, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_all_users(self) -> list[dict]:
        """Get all users with their roles."""
        cursor = await self.conn.execute(
            "SELECT id, username, role, is_admin, created_at, status FROM users ORDER BY id"
        )
        rows = await cursor.fetchall()
        users = []
        for row in rows:
            user = dict(row)
            # Ensure role is set (handle legacy data)
            if not user.get("role"):
                user["role"] = "admin" if user.get("is_admin") else "user"
            users.append(user)
        return users

    async def reset_user_password(self, user_id: int, new_password_hash: str) -> bool:
        """Reset a user's password (admin action)."""
        cursor = await self.conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (new_password_hash, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Token operations
    async def create_token(
        self,
        user_id: int,
        token_id: str,
        scopes: list[str],
        name: str = None,
        expires_at: datetime = None,
        ip: str = None,
        user_agent: str = None
    ) -> int:
        """Create a new token record and return its ID.

        ip and user_agent record where the login was made (the sessions page);
        last_ip starts out as the same address.
        """
        cursor = await self.conn.execute(
            """INSERT INTO tokens (user_id, token_id, name, scopes, expires_at,
                                   ip, user_agent, last_ip)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                token_id,
                name,
                ",".join(scopes),
                expires_at.isoformat() if expires_at else None,
                ip,
                user_agent,
                ip
            )
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_token(self, token_id: str) -> Optional[dict]:
        """Get token by token_id."""
        cursor = await self.conn.execute(
            "SELECT * FROM tokens WHERE token_id = ? AND revoked = 0",
            (token_id,)
        )
        row = await cursor.fetchone()
        if row:
            token = dict(row)
            token["scopes"] = token["scopes"].split(",") if token["scopes"] else []
            return token
        return None

    async def get_user_tokens(self, user_id: int) -> list[dict]:
        """Get all tokens for a user."""
        cursor = await self.conn.execute(
            "SELECT * FROM tokens WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        rows = await cursor.fetchall()
        tokens = []
        for row in rows:
            token = dict(row)
            token["scopes"] = token["scopes"].split(",") if token["scopes"] else []
            tokens.append(token)
        return tokens

    async def revoke_token(self, token_id: str, user_id: int = None) -> bool:
        """Revoke a token by token_id.

        When user_id is given, only a token owned by that user is revoked
        (a token belonging to someone else behaves as if it did not exist).
        """
        if user_id is None:
            cursor = await self.conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE token_id = ?",
                (token_id,)
            )
        else:
            cursor = await self.conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE token_id = ? AND user_id = ?",
                (token_id, user_id)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def revoke_user_tokens(self, user_id: int, except_token_id: str = None) -> int:
        """Revoke every live token (API tokens and browser sessions) of a user.

        except_token_id keeps one token, normally the caller's own session.
        Returns the number of tokens revoked.
        """
        if except_token_id:
            cursor = await self.conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0 AND token_id != ?",
                (user_id, except_token_id)
            )
        else:
            cursor = await self.conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                (user_id,)
            )
        await self.conn.commit()
        return cursor.rowcount

    async def revoke_user_api_keys(self, user_id: int, except_token_id: str = None) -> int:
        """Revoke every live API key of a user. Returns the number revoked.

        except_token_id is the caller's credential id; when it is an API key
        ("apikey-<id>") that key is kept.
        """
        sql = "UPDATE api_keys SET revoked = 1 WHERE user_id = ? AND revoked = 0"
        params = [user_id]
        if except_token_id and except_token_id.startswith("apikey-"):
            try:
                params.append(int(except_token_id[7:]))
                sql += " AND id != ?"
            except ValueError:
                pass
        cursor = await self.conn.execute(sql, params)
        await self.conn.commit()
        return cursor.rowcount

    async def update_token_last_used(self, token_id: str, last_ip: str = None) -> None:
        """Update the last_used_at timestamp (and, when known, last_ip) for a token."""
        if last_ip:
            await self.conn.execute(
                "UPDATE tokens SET last_used_at = ?, last_ip = ? WHERE token_id = ?",
                (datetime.now(timezone.utc).isoformat(), last_ip, token_id)
            )
        else:
            await self.conn.execute(
                "UPDATE tokens SET last_used_at = ? WHERE token_id = ?",
                (datetime.now(timezone.utc).isoformat(), token_id)
            )
        await self.conn.commit()

    async def get_user_live_tokens(self, user_id: int) -> list[dict]:
        """Tokens of a user that can still be used (not revoked, not expired),
        newest first. Includes browser sessions and tokens made through
        POST /api/token."""
        cursor = await self.conn.execute(
            "SELECT * FROM tokens WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC, id DESC",
            (user_id,)
        )
        now = datetime.now(timezone.utc)
        live = []
        for row in await cursor.fetchall():
            token = dict(row)
            exp = token.get("expires_at")
            if exp:
                try:
                    when = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    if when < now:
                        continue
                except ValueError:
                    pass
            live.append(token)
        return live

    async def is_token_valid(self, token_id: str) -> bool:
        """Check if a token is valid (exists, not revoked, not expired)."""
        token = await self.get_token(token_id)
        if not token:
            return False
        if token["revoked"]:
            return False
        if token["expires_at"]:
            expires = datetime.fromisoformat(token["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < datetime.now(timezone.utc):
                return False
        return True

    # Service operations
    async def create_service(
        self,
        name: str,
        path: str,
        internal_url: str = None,
        required_scopes: list[str] = None,
        plugin: str = "tcp_tunnel",
        host: str = None,
        port: int = None,
        config: dict = None,
        icon: str = "server",
        category_id: int = None,
        # Unified services - process management fields
        service_type: str = "proxy",
        display_name: str = None,
        description: str = None,
        binary_path: str = None,
        working_dir: str = None,
        ports: list = None,
        systemd_unit: str = None,
        enabled: bool = True
    ) -> int:
        """Create a new service and return its ID.

        Args:
            service_type: 'proxy' for external backends, 'managed' for Portal-run processes
            display_name: Human-readable name (defaults to name)
            description: Service description
            binary_path: Path to executable (for managed services)
            working_dir: Working directory (for managed services)
            ports: Additional ports list (for managed services)
            systemd_unit: Optional systemd unit name (without .service) to bind for
                start/stop/restart control via systemctl — lets a proxy-type service
                (e.g. a game server or file share behind the reverse proxy) be
                controlled from the Services panel instead of requiring SSH.
            enabled: Whether the service is enabled (auto-starts on Portal boot for
                managed services). The column defaults to 1, so this must be passed
                through explicitly for a service to be created disabled.
        """
        import json
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO services (name, plugin, path, host, port, config, required_scopes,
               icon, category_id, service_type, display_name, description, binary_path,
               working_dir, ports, systemd_unit, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name,
                plugin,
                path,
                host,
                port,
                encrypt_config(json.dumps(config or {})),
                ",".join(required_scopes or []),
                icon,
                category_id,
                service_type,
                display_name or name,
                description,
                binary_path,
                working_dir,
                json.dumps(ports or []),
                systemd_unit,
                1 if enabled else 0,
                now,
                now
            )
        )
        await self.conn.commit()
        return cursor.lastrowid

    def _parse_service(self, row) -> dict:
        """Parse a service row from the database."""
        import json
        service = dict(row)
        service["required_scopes"] = (
            service["required_scopes"].split(",")
            if service.get("required_scopes")
            else []
        )
        # Parse JSON config (decrypt if encrypted)
        config_str = service.get("config", "{}")
        try:
            service["config"] = json.loads(decrypt_config(config_str)) if config_str else {}
        except (json.JSONDecodeError, Exception):
            service["config"] = {}
        # Parse JSON ports array (for managed services)
        ports_str = service.get("ports", "[]")
        try:
            service["ports"] = json.loads(ports_str) if ports_str else []
        except json.JSONDecodeError:
            service["ports"] = []
        # Ensure service_type has a default
        if not service.get("service_type"):
            service["service_type"] = "proxy"
        return service

    async def get_service_by_path(self, path: str) -> Optional[dict]:
        """Get service by path."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE path = ? AND enabled = 1",
            (path,)
        )
        row = await cursor.fetchone()
        return self._parse_service(row) if row else None

    async def get_service_by_id(self, service_id: int) -> Optional[dict]:
        """Get service by ID."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE id = ?",
            (service_id,)
        )
        row = await cursor.fetchone()
        return self._parse_service(row) if row else None

    async def get_all_services(self) -> list[dict]:
        """Get all enabled services."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE enabled = 1 ORDER BY sort_order, name"
        )
        rows = await cursor.fetchall()
        return [self._parse_service(row) for row in rows]

    async def get_services_by_category(self, category_id: int) -> list[dict]:
        """Get all services in a category."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE category_id = ? AND enabled = 1 ORDER BY sort_order, name",
            (category_id,)
        )
        rows = await cursor.fetchall()
        return [self._parse_service(row) for row in rows]

    async def get_services_by_plugin(self, plugin: str) -> list[dict]:
        """Get all services using a specific plugin."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE plugin = ? AND enabled = 1 ORDER BY name",
            (plugin,)
        )
        rows = await cursor.fetchall()
        return [self._parse_service(row) for row in rows]

    async def update_service(
        self,
        service_id: int,
        name: str = None,
        path: str = None,
        required_scopes: list[str] = None,
        enabled: bool = None
    ) -> bool:
        """Update a service. Returns True if updated."""
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if path is not None:
            updates.append("path = ?")
            params.append(path)
        if required_scopes is not None:
            updates.append("required_scopes = ?")
            params.append(",".join(required_scopes))
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(int(enabled))

        if not updates:
            return False

        updates.append("updated_at = ?")
        params.append(datetime.now(timezone.utc).isoformat())
        params.append(service_id)

        cursor = await self.conn.execute(
            f"UPDATE services SET {', '.join(updates)} WHERE id = ?",
            params
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_service(self, service_id: int) -> bool:
        """Delete a service by ID (also cleans up associated logs)."""
        # Clean up service_logs (FK references managed_services, not services)
        await self.conn.execute(
            "DELETE FROM service_logs WHERE service_id = ?", (service_id,)
        )
        cursor = await self.conn.execute(
            "DELETE FROM services WHERE id = ?", (service_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Unified services - process management methods

    async def get_services_by_type(self, service_type: str) -> list[dict]:
        """Get all services of a specific type (proxy or managed)."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE service_type = ? ORDER BY sort_order, name",
            (service_type,)
        )
        rows = await cursor.fetchall()
        return [self._parse_service(row) for row in rows]

    async def get_enabled_services_by_type(self, service_type: str) -> list[dict]:
        """Get enabled services of a specific type."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE service_type = ? AND enabled = 1 ORDER BY sort_order, name",
            (service_type,)
        )
        rows = await cursor.fetchall()
        return [self._parse_service(row) for row in rows]

    async def get_service_by_plugin_type(self, plugin: str) -> Optional[dict]:
        """Get first managed service using a specific plugin."""
        cursor = await self.conn.execute(
            "SELECT * FROM services WHERE plugin = ? AND service_type = 'managed' LIMIT 1",
            (plugin,)
        )
        row = await cursor.fetchone()
        return self._parse_service(row) if row else None

    async def update_service_process_status(
        self,
        service_id: int,
        status: str,
        pid: int = None,
        error_message: str = None
    ) -> bool:
        """Update service process status and optional PID/error."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        updates = ["status = ?", "updated_at = ?"]
        params = [status, now]

        if status == 'running':
            updates.extend(["last_started_at = ?", "error_message = ?", "pid = ?"])
            params.extend([now, None, pid])
        elif status == 'stopped':
            updates.extend(["last_stopped_at = ?", "pid = ?"])
            params.extend([now, None])
        elif status == 'error':
            updates.extend(["error_message = ?", "pid = ?"])
            params.extend([error_message, None])
        else:
            updates.append("pid = ?")
            params.append(pid)

        params.append(service_id)
        cursor = await self.conn.execute(
            f"UPDATE services SET {', '.join(updates)} WHERE id = ?",
            params
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_service_health_status(
        self,
        service_id: int,
        health_status: str
    ) -> bool:
        """Update service health status."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """UPDATE services
               SET health_status = ?, last_health_check = ?, updated_at = ?
               WHERE id = ?""",
            (health_status, now, now, service_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def increment_service_restart(self, service_id: int) -> bool:
        """Increment the restart count for a service."""
        cursor = await self.conn.execute(
            """UPDATE services
               SET restart_count = restart_count + 1, updated_at = ?
               WHERE id = ?""",
            (datetime.now(timezone.utc).isoformat(), service_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_service_full(self, service_id: int, **updates) -> bool:
        """Update any service fields (unified method)."""
        import json
        allowed_fields = {
            "name", "path", "host", "port", "plugin", "icon", "description",
            "display_name",
            "config", "ports", "required_scopes", "category_id", "internal_url",
            "service_type", "enabled", "command", "working_dir", "env_vars",
            "auto_start", "health_check_url", "status", "pid", "health_status",
            "error_message", "restart_count", "last_started_at", "last_stopped_at",
            "last_health_check", "systemd_unit",
        }
        updates = {k: v for k, v in updates.items() if k in allowed_fields}
        if not updates:
            return False

        # Handle JSON fields (encrypt config at rest)
        if 'config' in updates and isinstance(updates['config'], dict):
            updates['config'] = encrypt_config(json.dumps(updates['config']))
        if 'ports' in updates and isinstance(updates['ports'], list):
            updates['ports'] = json.dumps(updates['ports'])
        if 'required_scopes' in updates and isinstance(updates['required_scopes'], list):
            updates['required_scopes'] = ','.join(updates['required_scopes'])

        updates['updated_at'] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [service_id]

        cursor = await self.conn.execute(
            f"UPDATE services SET {set_clause} WHERE id = ?",
            values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_service_config_if_target(
        self, service_id: int, config: dict, host: Optional[str], port: Optional[int]
    ) -> bool:
        """Replace a service's (encrypted) config, only if its host and port
        columns are still `host` and `port` (an edit made meanwhile wins)."""
        import json
        cursor = await self.conn.execute(
            "UPDATE services SET config = ?, updated_at = ? "
            "WHERE id = ? AND COALESCE(host, '') = ? AND COALESCE(port, 0) = ?",
            (encrypt_config(json.dumps(config)), datetime.now(timezone.utc).isoformat(),
             service_id, host or "", port or 0)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Category operations
    async def create_category(self, name: str, icon: str = "folder", sort_order: int = 0) -> int:
        """Create a new category and return its ID."""
        cursor = await self.conn.execute(
            "INSERT INTO categories (name, icon, sort_order) VALUES (?, ?, ?)",
            (name, icon, sort_order)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_all_categories(self) -> list[dict]:
        """Get all categories."""
        cursor = await self.conn.execute(
            "SELECT * FROM categories ORDER BY sort_order, name"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def delete_category(self, category_id: int) -> bool:
        """Delete a category by ID."""
        cursor = await self.conn.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Session tracking
    async def create_session(
        self,
        user_id: int,
        service_id: int,
        client_ip: str = None
    ) -> int:
        """Record a new session and return its ID."""
        cursor = await self.conn.execute(
            "INSERT INTO sessions (user_id, service_id, client_ip) VALUES (?, ?, ?)",
            (user_id, service_id, client_ip)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def end_session(
        self,
        session_id: int,
        bytes_sent: int = 0,
        bytes_received: int = 0
    ) -> None:
        """Mark a session as ended."""
        await self.conn.execute(
            """UPDATE sessions
               SET ended_at = ?, bytes_sent = ?, bytes_received = ?
               WHERE id = ?""",
            (datetime.now(timezone.utc).isoformat(), bytes_sent, bytes_received, session_id)
        )
        await self.conn.commit()

    async def get_active_sessions(self) -> list[dict]:
        """Get all active (non-ended) sessions."""
        cursor = await self.conn.execute(
            """SELECT s.*, u.username, svc.name as service_name
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               JOIN services svc ON s.service_id = svc.id
               WHERE s.ended_at IS NULL
               ORDER BY s.started_at DESC"""
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_user_sessions(self, user_id: int, limit: int = 50) -> list[dict]:
        """Get recent sessions for a user."""
        cursor = await self.conn.execute(
            """SELECT s.*, svc.name as service_name
               FROM sessions s
               JOIN services svc ON s.service_id = svc.id
               WHERE s.user_id = ?
               ORDER BY s.started_at DESC
               LIMIT ?""",
            (user_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # Recording operations
    async def create_recording(
        self,
        user_id: int,
        service_id: int,
        filename: str,
        format: str = "asciicast",
        size: int = 0,
        duration: float = 0
    ) -> int:
        """Create a new recording record and return its ID."""
        cursor = await self.conn.execute(
            """INSERT INTO recordings (user_id, service_id, filename, format, size, duration)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, service_id, filename, format, size, duration)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_recording(self, recording_id: int, size: int, duration: float) -> None:
        """Update recording size and duration after completion."""
        await self.conn.execute(
            "UPDATE recordings SET size = ?, duration = ? WHERE id = ?",
            (size, duration, recording_id)
        )
        await self.conn.commit()

    async def get_recording(self, recording_id: int) -> Optional[dict]:
        """Get recording by ID with user and service names."""
        cursor = await self.conn.execute(
            """SELECT r.*, u.username, s.name as service_name
               FROM recordings r
               JOIN users u ON r.user_id = u.id
               JOIN services s ON r.service_id = s.id
               WHERE r.id = ?""",
            (recording_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_all_recordings(self, limit: int = 100) -> list[dict]:
        """Get all recordings (admin) with user and service names."""
        cursor = await self.conn.execute(
            """SELECT r.*, u.username, s.name as service_name
               FROM recordings r
               JOIN users u ON r.user_id = u.id
               JOIN services s ON r.service_id = s.id
               ORDER BY r.created_at DESC
               LIMIT ?""",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def cleanup_old_recordings(self, days: int, recordings_dir: Optional[str] = None) -> int:
        """Remove recordings older than `days`: the file first, then the row.

        Only a plain file name inside the recordings directory is ever
        unlinked; a row whose filename points anywhere else is left alone and
        logged. A row is kept when its file cannot be removed, so the next
        run retries. A recording whose session is still running is skipped.
        Returns the number of rows removed.
        """
        if days <= 0:
            return 0
        directory = os.path.realpath(recordings_dir or Config.RECORDINGS_DIR)
        cursor = await self.conn.execute(
            "SELECT id, filename FROM recordings WHERE created_at < datetime('now', ?)",
            (f"-{int(days)} days",)
        )
        rows = await cursor.fetchall()
        dir_fd = None
        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            pass  # no directory yet: nothing on disk to remove, rows can still go
        removed = 0
        try:
            for row in rows:
                if row["id"] in self.live_recording_ids:
                    continue  # the session is still running and writing to it
                name = row["filename"]
                if (not isinstance(name, str) or not name or name in (".", "..")
                        or "/" in name or "\\" in name or "\x00" in name):
                    logger.warning(f"Retention: recording {row['id']} has an unsafe filename, left in place")
                    continue
                if dir_fd is not None:
                    try:
                        os.unlink(name, dir_fd=dir_fd)  # a symlink is removed itself, never followed
                    except FileNotFoundError:
                        pass
                    except OSError as e:
                        logger.warning(f"Retention: could not remove recording file {name}: {e}")
                        continue
                await self.conn.execute("DELETE FROM recordings WHERE id = ?", (row["id"],))
                removed += 1
            await self.conn.commit()
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
        return removed

    async def cleanup_orphan_recordings(self, recordings_dir: Optional[str] = None,
                                        min_age_seconds: int = 3600) -> int:
        """Remove recording files that no row refers to (left behind when a user
        or service was deleted). Only regular files with the recording extension
        directly inside the recordings directory are considered; symlinks and
        subdirectories are never followed, files of a running session and files
        younger than `min_age_seconds` are left alone. Returns the number removed.
        """
        if recording_paths.check(recordings_dir or Config.RECORDINGS_DIR):
            return 0  # refused folder: not swept (the reason is logged once)
        directory = os.path.realpath(recordings_dir or Config.RECORDINGS_DIR)
        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return 0
        removed = 0
        try:
            cursor = await self.conn.execute("SELECT filename FROM recordings")
            referenced = {r["filename"] for r in await cursor.fetchall()}
            cutoff = time.time() - min_age_seconds
            with os.scandir(dir_fd) as entries:
                candidates = [e.name for e in entries if e.name.endswith(RECORDING_FILE_EXTENSION)]
            for name in candidates:
                if name in referenced or name in self.live_recording_files:
                    continue
                try:
                    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or st.st_mtime > cutoff:
                        continue
                    os.unlink(name, dir_fd=dir_fd)
                    removed += 1
                except FileNotFoundError:
                    continue
                except OSError as e:
                    logger.warning(f"Retention: could not remove orphan recording file {name}: {e}")
        finally:
            os.close(dir_fd)
        return removed

    async def delete_recording(self, recording_id: int) -> bool:
        """Delete a recording record by ID."""
        cursor = await self.conn.execute(
            "DELETE FROM recordings WHERE id = ?",
            (recording_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Settings operations (for persistent configuration)
    async def get_setting(self, key: str) -> Optional[str]:
        """Get a setting value by key."""
        cursor = await self.conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (key,)
        )
        row = await cursor.fetchone()
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        """Set a setting value (insert or update)."""
        await self.conn.execute(
            """INSERT INTO settings (key, value, updated_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(key) DO UPDATE SET
               value = excluded.value,
               updated_at = CURRENT_TIMESTAMP""",
            (key, value)
        )
        await self.conn.commit()

    async def set_settings(self, values: dict) -> None:
        """Set several settings in one transaction: all of them are saved or none.

        One executemany call runs on the connection's worker thread without yielding to the
        event loop, so no other coroutine's commit can land between the rows."""
        try:
            await self.conn.executemany(
                """INSERT INTO settings (key, value, updated_at)
                   VALUES (?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = CURRENT_TIMESTAMP""",
                list(values.items()))
            await self.conn.commit()
        except BaseException:
            await self.conn.rollback()
            raise

    async def delete_setting(self, key: str) -> bool:
        """Delete a setting by key."""
        cursor = await self.conn.execute(
            "DELETE FROM settings WHERE key = ?",
            (key,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_all_settings(self) -> dict[str, str]:
        """Get all settings as a dictionary."""
        cursor = await self.conn.execute("SELECT key, value FROM settings")
        rows = await cursor.fetchall()
        return {row["key"]: row["value"] for row in rows}

    # API Key operations
    async def create_api_key(
        self,
        user_id: int,
        name: str,
        key_hash: str,
        key_prefix: str,
        scopes: str = "*",
        expires_at: Optional[str] = None,
        allowed_cidrs: Optional[str] = None,
        created_ip: Optional[str] = None
    ) -> int:
        """Create a new API key and return its ID.

        allowed_cidrs is the comma-separated, already validated list of networks the
        key may be used from (None: not bound); created_ip is the address it was made from.
        """
        cursor = await self.conn.execute(
            """INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, expires_at,
                                     allowed_cidrs, created_ip)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, key_hash, key_prefix, scopes, expires_at, allowed_cidrs, created_ip)
        )
        await self.conn.commit()
        return cursor.lastrowid

    API_KEY_PREFIX_CANDIDATES = 4

    async def get_api_keys_by_prefix(self, prefix: str) -> list[dict]:
        """Every live (not revoked) API key with this prefix, oldest first, at most
        API_KEY_PREFIX_CANDIDATES. The prefix is 12 bits, so two keys can share one."""
        cursor = await self.conn.execute(
            """SELECT ak.*, u.username
               FROM api_keys ak
               JOIN users u ON ak.user_id = u.id
               WHERE ak.key_prefix = ? AND ak.revoked = 0
               ORDER BY ak.id
               LIMIT ?""",
            (prefix, self.API_KEY_PREFIX_CANDIDATES)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_api_key_by_prefix(self, prefix: str) -> Optional[dict]:
        """The first live key with this prefix (see get_api_keys_by_prefix for all of them)."""
        rows = await self.get_api_keys_by_prefix(prefix)
        return rows[0] if rows else None

    async def get_user_api_keys(self, user_id: int) -> list[dict]:
        """Get all API keys for a user (excluding hash for security)."""
        cursor = await self.conn.execute(
            """SELECT id, name, key_prefix, scopes, expires_at, last_used_at, created_at, revoked,
                      allowed_cidrs, created_ip, last_used_ip
               FROM api_keys
               WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_api_key_last_used(self, key_id: int, ip: Optional[str] = None) -> None:
        """Update last_used_at (and, when known, last_used_ip) for an API key."""
        if ip:
            await self.conn.execute(
                "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ? WHERE id = ?",
                (ip, key_id)
            )
        else:
            await self.conn.execute(
                "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
                (key_id,)
            )
        await self.conn.commit()

    async def get_service_scope_names(self) -> list[str]:
        """Every scope some service requires (an administrator makes these up per service)."""
        cursor = await self.conn.execute(
            "SELECT required_scopes FROM services WHERE required_scopes IS NOT NULL AND required_scopes != ''")
        names: set[str] = set()
        for row in await cursor.fetchall():
            for part in str(row[0]).split(","):
                part = part.strip()
                if part:
                    names.add(part)
        return sorted(names)

    async def revoke_api_key(self, key_id: int, user_id: int) -> bool:
        """Revoke an API key (user must own it)."""
        cursor = await self.conn.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
            (key_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_api_key(self, key_id: int, user_id: int) -> bool:
        """Delete an API key (user must own it)."""
        cursor = await self.conn.execute(
            "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
            (key_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # User Connection operations
    async def create_user_connection(
        self,
        user_id: int,
        name: str,
        conn_type: str,
        host: str,
        port: Optional[int] = None,
        config: str = "{}",
        ssh_key_id: Optional[int] = None,
        icon: str = "link",
        portal_access: int = 1,
        api_access: int = 0
    ) -> str:
        """Create a new user connection and return its UUID."""
        uuid_val = _secrets.token_urlsafe(12)
        encrypted_config = encrypt_config(config) if config else "{}"
        cursor = await self.conn.execute(
            """INSERT INTO user_connections
               (user_id, name, type, host, port, config, ssh_key_id, icon, portal_access, api_access, uuid)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, conn_type, host, port, encrypted_config, ssh_key_id, icon, portal_access, api_access, uuid_val)
        )
        await self.conn.commit()
        return uuid_val

    async def get_user_connection(self, conn_id: int, user_id: int) -> Optional[dict]:
        """Get a user connection by ID (must be owned by user)."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.id = ? AND uc.user_id = ?""",
            (conn_id, user_id)
        )
        row = await cursor.fetchone()
        if row:
            conn = dict(row)
            import json
            try:
                raw_config = conn.get("config", "{}")
                conn["config"] = json.loads(decrypt_config(raw_config))
            except (json.JSONDecodeError, Exception):
                conn["config"] = {}
            return conn
        return None

    async def get_user_connection_by_uuid(self, uuid: str, user_id: int) -> Optional[dict]:
        """Get a user connection by UUID (must be owned by user)."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.uuid = ? AND uc.user_id = ?""",
            (uuid, user_id)
        )
        row = await cursor.fetchone()
        if row:
            conn = dict(row)
            import json
            try:
                raw_config = conn.get("config", "{}")
                conn["config"] = json.loads(decrypt_config(raw_config))
            except (json.JSONDecodeError, Exception):
                conn["config"] = {}
            return conn
        return None

    def _decode_conn_rows(self, rows) -> list[dict]:
        import json
        out = []
        for row in rows:
            conn = dict(row)
            try:
                conn["config"] = json.loads(decrypt_config(conn.get("config", "{}")))
            except (json.JSONDecodeError, Exception):
                conn["config"] = {}
            out.append(conn)
        return out

    def _decode_shared_rows(self, rows) -> list[dict]:
        """Decode rows of connections shared with a user; they carry the share's expiry
        as share_expires_at (ISO, Z) and share_expires_in (seconds left), both None for a
        share that never expires."""
        out = self._decode_conn_rows(rows)
        for conn in out:
            info = grant_expiry.describe(conn.pop("share_expires_raw", None))
            conn["share_expires_at"] = info["expires_at"]
            conn["share_expires_in"] = info["expires_in"]
        return out

    async def list_owned_connection_ids(self, user_id: int) -> list[int]:
        """Ids of the connections a user owns (no config read, nothing decrypted)."""
        cursor = await self.conn.execute(
            "SELECT id FROM user_connections WHERE user_id = ?", (user_id,))
        return [r["id"] for r in await cursor.fetchall()]

    async def get_user_connections(self, user_id: int) -> list[dict]:
        """Get all connections for a user — owned (pinned first) then shared-with."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.user_id = ?
               ORDER BY uc.is_pinned DESC, uc.last_used_at DESC NULLS LAST, uc.name""",
            (user_id,)
        )
        connections = self._decode_conn_rows(await cursor.fetchall())

        cursor = await self.conn.execute(
            f"""SELECT uc.*, NULL as ssh_key_name, NULL as ssh_key_fingerprint,
                      1 as shared, owner.username as owner_username,
                      cs.expires_at as share_expires_raw
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users owner ON owner.id = uc.user_id
               WHERE cs.grantee_user_id = ? AND {grant_expiry.live_sql('cs')}
               ORDER BY uc.name""",
            (user_id, grant_expiry.live_param())
        )
        connections.extend(self._decode_shared_rows(await cursor.fetchall()))
        return connections

    async def update_user_connection(
        self,
        conn_id: int,
        user_id: int,
        **kwargs
    ) -> bool:
        """Update a user connection (must be owned by user)."""
        allowed_fields = {"name", "type", "host", "port", "config", "ssh_key_id", "icon", "portal_access", "api_access"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False

        # Convert config dict to JSON and encrypt
        if "config" in updates:
            import json
            config_val = updates["config"]
            if isinstance(config_val, dict):
                config_val = json.dumps(config_val)
            updates["config"] = encrypt_config(config_val)

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [conn_id, user_id]

        cursor = await self.conn.execute(
            f"""UPDATE user_connections
               SET {set_clause}, updated_at = CURRENT_TIMESTAMP
               WHERE id = ? AND user_id = ?""",
            values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_user_connection_config_if_target(
        self, conn_id: int, user_id: int, config: dict, host: str, port: Optional[int]
    ) -> bool:
        """Replace a connection's (encrypted) config, only if it still points at
        `host`:`port` (a missing port means 22), so an edit of the target made
        meanwhile wins over a stale host-key accept."""
        import json
        cursor = await self.conn.execute(
            "UPDATE user_connections SET config = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND user_id = ? AND host = ? AND COALESCE(NULLIF(port, 0), 22) = ?",
            (encrypt_config(json.dumps(config)), conn_id, user_id, host, port or 22)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def merge_user_connection_host_key(
        self, conn_id: int, user_id: int, fingerprint: str, host: str, port: Optional[int],
        pin_key: str, refused_key: str,
    ) -> bool:
        """Pin a host key on a connection by changing only the pin keys of its CURRENT config.

        The accept route used to write back the whole config it had read earlier, so an edit
        made while the prompt was open (the mode set to prompt, a new username, a cleared
        password) was overwritten and the old values came back. Here the row is read again,
        the pin keys are merged into what is stored now, and the write only lands if the
        config is still the text that was read (compare and set; retried when somebody wrote
        in between). False when the connection no longer points at `host`:`port` (a missing
        port means 22) or is gone, or when its config cannot be read (nothing is written)."""
        import json
        for _ in range(8):
            cursor = await self.conn.execute(
                "SELECT config, host, port FROM user_connections WHERE id = ? AND user_id = ?",
                (conn_id, user_id))
            row = await cursor.fetchone()
            if not row or row["host"] != host or (row["port"] or 22) != (port or 22):
                return False
            stored = row["config"]
            plain = decrypt_config(stored) if stored else "{}"
            if stored and stored.startswith("enc:") and plain == "{}":
                return False        # decryption failed: never write a pin over a config we cannot read
            try:
                cfg = json.loads(plain) if plain else {}
            except json.JSONDecodeError:
                return False
            if not isinstance(cfg, dict):
                return False
            cfg[pin_key] = fingerprint
            cfg.pop(refused_key, None)
            cursor = await self.conn.execute(
                "UPDATE user_connections SET config = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ? AND user_id = ? AND host = ? AND COALESCE(NULLIF(port, 0), 22) = ? "
                "AND config IS ?",
                (encrypt_config(json.dumps(cfg)), conn_id, user_id, host, port or 22, stored))
            await self.conn.commit()
            if cursor.rowcount > 0:
                return True
        return False

    async def delete_user_connection(self, conn_id: int, user_id: int) -> bool:
        """Delete a user connection (must be owned by user)."""
        cursor = await self.conn.execute(
            "DELETE FROM user_connections WHERE id = ? AND user_id = ?",
            (conn_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def record_connection_usage(self, conn_id: int, user_id: int) -> bool:
        """Record that a connection was used (increment count and set timestamp)."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """UPDATE user_connections SET use_count = use_count + 1, last_used_at = ?
               WHERE id = ? AND user_id = ?""",
            (now, conn_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def toggle_connection_pin(self, conn_id: int, user_id: int) -> Optional[bool]:
        """Toggle pin status for a connection. Returns new pin state or None if not found."""
        cursor = await self.conn.execute(
            "SELECT is_pinned FROM user_connections WHERE id = ? AND user_id = ?",
            (conn_id, user_id)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        new_state = 0 if row["is_pinned"] else 1
        await self.conn.execute(
            "UPDATE user_connections SET is_pinned = ? WHERE id = ? AND user_id = ?",
            (new_state, conn_id, user_id)
        )
        await self.conn.commit()
        return bool(new_state)

    async def get_user_connections_by_type(self, user_id: int, conn_type: str) -> list[dict]:
        """Get all connections of a specific type — owned then shared-with."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.user_id = ? AND uc.type = ?
               ORDER BY uc.name""",
            (user_id, conn_type)
        )
        connections = self._decode_conn_rows(await cursor.fetchall())

        cursor = await self.conn.execute(
            f"""SELECT uc.*, NULL as ssh_key_name, NULL as ssh_key_fingerprint,
                      1 as shared, owner.username as owner_username,
                      cs.expires_at as share_expires_raw
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users owner ON owner.id = uc.user_id
               WHERE cs.grantee_user_id = ? AND uc.type = ? AND {grant_expiry.live_sql('cs')}
               ORDER BY uc.name""",
            (user_id, conn_type, grant_expiry.live_param())
        )
        connections.extend(self._decode_shared_rows(await cursor.fetchall()))
        return connections

    # ------------------------------------------------------------------
    # Shared access — connection_shares + service_grants
    # ------------------------------------------------------------------
    async def get_accessible_connection(self, uuid: str, user_id: int) -> Optional[dict]:
        """Connection by UUID if the user owns it OR it's shared with them.

        Owner hits return exactly what get_user_connection_by_uuid does; shared
        hits carry shared=True + owner_username and no ssh key join.
        """
        owned = await self.get_user_connection_by_uuid(uuid, user_id)
        if owned:
            return owned
        cursor = await self.conn.execute(
            f"""SELECT uc.*, 1 as shared, owner.username as owner_username,
                      cs.expires_at as share_expires_raw
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users owner ON owner.id = uc.user_id
               WHERE uc.uuid = ? AND cs.grantee_user_id = ? AND {grant_expiry.live_sql('cs')}""",
            (uuid, user_id, grant_expiry.live_param()),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._decode_shared_rows([row])[0]

    async def list_connection_shares(self, connection_id: int) -> list[dict]:
        """Live shares of one connection (an expired one the sweeper has not deleted yet is not listed)."""
        cursor = await self.conn.execute(
            f"""SELECT cs.grantee_user_id as user_id, u.username, cs.created_at,
                      cs.expires_at as expires_raw, g.username as granted_by_username
               FROM connection_shares cs JOIN users u ON u.id = cs.grantee_user_id
               LEFT JOIN users g ON g.id = cs.granted_by
               WHERE cs.connection_id = ? AND {grant_expiry.live_sql('cs')}
               ORDER BY u.username""",
            (connection_id, grant_expiry.live_param()),
        )
        return [self._with_expiry(r) for r in await cursor.fetchall()]

    @staticmethod
    def _with_expiry(row) -> dict:
        d = dict(row)
        d.update(grant_expiry.describe(d.pop("expires_raw", None)))
        return d

    async def list_shares_by_owner(self, owner_id: int) -> list[dict]:
        """Every live share of every connection a user owns (the owner's "all shares" view)."""
        cursor = await self.conn.execute(
            f"""SELECT uc.uuid as connection_id, uc.name as connection_name, uc.type as connection_type,
                      cs.grantee_user_id as user_id, u.username, cs.created_at,
                      cs.expires_at as expires_raw, g.username as granted_by_username
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users u ON u.id = cs.grantee_user_id
               LEFT JOIN users g ON g.id = cs.granted_by
               WHERE uc.user_id = ? AND {grant_expiry.live_sql('cs')}
               ORDER BY uc.name, u.username""",
            (owner_id, grant_expiry.live_param()),
        )
        return [self._with_expiry(r) for r in await cursor.fetchall()]

    async def list_all_grants(self) -> dict:
        """Every live service grant and connection share on the portal (the admin view)."""
        live = grant_expiry.live_param()
        cursor = await self.conn.execute(
            f"""SELECT sg.service_id, s.name as service_name, sg.grantee_user_id as user_id,
                      u.username, sg.actions, sg.created_at,
                      sg.expires_at as expires_raw, g.username as granted_by_username
               FROM service_grants sg
               JOIN users u ON u.id = sg.grantee_user_id
               LEFT JOIN services s ON s.id = sg.service_id
               LEFT JOIN users g ON g.id = sg.granted_by
               WHERE {grant_expiry.live_sql('sg')}
               ORDER BY s.name, u.username""",
            (live,),
        )
        grants = []
        for r in await cursor.fetchall():
            d = self._with_expiry(r)
            d["actions"] = [a.strip() for a in (d["actions"] or "").split(",") if a.strip()]
            grants.append(d)
        cursor = await self.conn.execute(
            f"""SELECT uc.uuid as connection_id, uc.name as connection_name, uc.type as connection_type,
                      owner.username as owner_username,
                      cs.grantee_user_id as user_id, u.username, cs.created_at,
                      cs.expires_at as expires_raw, g.username as granted_by_username
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users owner ON owner.id = uc.user_id
               JOIN users u ON u.id = cs.grantee_user_id
               LEFT JOIN users g ON g.id = cs.granted_by
               WHERE {grant_expiry.live_sql('cs')}
               ORDER BY owner.username, uc.name, u.username""",
            (live,),
        )
        shares = [self._with_expiry(r) for r in await cursor.fetchall()]
        return {"service_grants": grants, "connection_shares": shares}

    async def add_connection_share(self, connection_id: int, grantee_id: int, owner_id: int,
                                   duration: Optional[str] = grant_expiry.API_DEFAULT) -> bool:
        """Share a connection; sharing again with the same user replaces the expiry. A
        duration of None keeps the end time of a live share and gives a new one (or an
        expired one the sweeper has not deleted yet) the API default, never."""
        expires_at = grant_expiry.expires_at_for(duration)
        try:
            await self.conn.execute(
                """INSERT INTO connection_shares
                   (connection_id, grantee_user_id, granted_by, expires_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(connection_id, grantee_user_id)
                   DO UPDATE SET expires_at = CASE
                       WHEN ? AND (connection_shares.expires_at IS NULL OR connection_shares.expires_at > ?)
                       THEN connection_shares.expires_at ELSE excluded.expires_at END""",
                (connection_id, grantee_id, owner_id, expires_at,
                 1 if duration is None else 0, grant_expiry.live_param()),
            )
            await self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"add_connection_share failed: {e}")
            return False

    async def remove_connection_share(self, connection_id: int, grantee_id: int) -> bool:
        cursor = await self.conn.execute(
            "DELETE FROM connection_shares WHERE connection_id = ? AND grantee_user_id = ?",
            (connection_id, grantee_id),
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def user_service_grant(self, user_id: int, service_id: int) -> Optional[set]:
        """Set of granted actions ({'control','logs','files'}) for user on service, or None
        (also None when the grant has expired)."""
        cursor = await self.conn.execute(
            f"""SELECT sg.actions FROM service_grants sg
                WHERE sg.grantee_user_id = ? AND sg.service_id = ? AND {grant_expiry.live_sql('sg')}""",
            (user_id, service_id, grant_expiry.live_param()),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {a.strip() for a in (row["actions"] or "").split(",") if a.strip()}

    async def get_user_granted_service_ids(self, user_id: int) -> dict:
        """{service_id: ['control','logs'], ...} for every live grant this user holds."""
        cursor = await self.conn.execute(
            f"""SELECT sg.service_id, sg.actions FROM service_grants sg
                WHERE sg.grantee_user_id = ? AND {grant_expiry.live_sql('sg')}""",
            (user_id, grant_expiry.live_param()),
        )
        out = {}
        for row in await cursor.fetchall():
            out[row["service_id"]] = [a.strip() for a in (row["actions"] or "").split(",") if a.strip()]
        return out

    async def list_service_grants(self, service_id: int) -> list[dict]:
        """Live grants on one service (an expired one the sweeper has not deleted yet is not listed)."""
        cursor = await self.conn.execute(
            f"""SELECT sg.grantee_user_id as user_id, u.username, sg.actions, sg.created_at,
                      sg.expires_at as expires_raw, g.username as granted_by_username
               FROM service_grants sg JOIN users u ON u.id = sg.grantee_user_id
               LEFT JOIN users g ON g.id = sg.granted_by
               WHERE sg.service_id = ? AND {grant_expiry.live_sql('sg')}
               ORDER BY u.username""",
            (service_id, grant_expiry.live_param()),
        )
        out = []
        for r in await cursor.fetchall():
            d = self._with_expiry(r)
            d["actions"] = [a.strip() for a in (d["actions"] or "").split(",") if a.strip()]
            out.append(d)
        return out

    async def add_service_grant(self, service_id: int, grantee_id: int, actions: list, granted_by: int,
                                duration: Optional[str] = grant_expiry.API_DEFAULT) -> bool:
        """Grant a service; granting again replaces the actions and the expiry. A duration
        of None keeps the end time of a live grant (the actions are still replaced) and
        gives a new one, or an expired one not yet swept, the API default, never."""
        clean = ",".join(sorted({a for a in actions if a in ("control", "logs", "files")})) or "control"
        expires_at = grant_expiry.expires_at_for(duration)
        try:
            await self.conn.execute(
                """INSERT INTO service_grants (service_id, grantee_user_id, actions, granted_by, expires_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(service_id, grantee_user_id)
                   DO UPDATE SET actions = excluded.actions, expires_at = CASE
                       WHEN ? AND (service_grants.expires_at IS NULL OR service_grants.expires_at > ?)
                       THEN service_grants.expires_at ELSE excluded.expires_at END""",
                (service_id, grantee_id, clean, granted_by, expires_at,
                 1 if duration is None else 0, grant_expiry.live_param()),
            )
            await self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"add_service_grant failed: {e}")
            return False

    async def remove_service_grant(self, service_id: int, grantee_id: int) -> bool:
        cursor = await self.conn.execute(
            "DELETE FROM service_grants WHERE service_id = ? AND grantee_user_id = ?",
            (service_id, grantee_id),
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def sweep_expired_grants(self) -> list[dict]:
        """Delete every share and grant whose time has passed; returns one dict per row
        actually deleted (kind 'conn' or 'svc'), for the audit entry and for closing what
        depended on it. A row renewed between the read and the delete is left alone. Access
        was refused by the predicate long before this runs; this only cleans up."""
        now = grant_expiry.live_param()
        out = []
        cursor = await self.conn.execute(
            """SELECT cs.id, cs.connection_id, cs.grantee_user_id, cs.granted_by, cs.expires_at,
                      uc.name as connection_name, uc.uuid as connection_uuid,
                      u.username as grantee_username, g.username as granted_by_username
               FROM connection_shares cs
               JOIN user_connections uc ON uc.id = cs.connection_id
               JOIN users u ON u.id = cs.grantee_user_id
               LEFT JOIN users g ON g.id = cs.granted_by
               WHERE cs.expires_at IS NOT NULL AND cs.expires_at <= ?""", (now,))
        for r in await cursor.fetchall():
            d = await self.conn.execute(
                "DELETE FROM connection_shares WHERE id = ? AND expires_at IS NOT NULL AND expires_at <= ?",
                (r["id"], now))
            if d.rowcount > 0:
                out.append({"kind": "conn", "resource_id": r["connection_id"],
                            "resource_name": r["connection_name"], "resource_uuid": r["connection_uuid"],
                            "grantee_id": r["grantee_user_id"], "grantee_username": r["grantee_username"],
                            "granted_by": r["granted_by"], "granted_by_username": r["granted_by_username"],
                            "expires_at": r["expires_at"]})
        cursor = await self.conn.execute(
            """SELECT sg.id, sg.service_id, sg.grantee_user_id, sg.granted_by, sg.expires_at, sg.actions,
                      s.name as service_name, u.username as grantee_username,
                      g.username as granted_by_username
               FROM service_grants sg
               JOIN users u ON u.id = sg.grantee_user_id
               LEFT JOIN services s ON s.id = sg.service_id
               LEFT JOIN users g ON g.id = sg.granted_by
               WHERE sg.expires_at IS NOT NULL AND sg.expires_at <= ?""", (now,))
        for r in await cursor.fetchall():
            d = await self.conn.execute(
                "DELETE FROM service_grants WHERE id = ? AND expires_at IS NOT NULL AND expires_at <= ?",
                (r["id"], now))
            if d.rowcount > 0:
                out.append({"kind": "svc", "resource_id": r["service_id"],
                            "resource_name": r["service_name"], "actions": r["actions"],
                            "grantee_id": r["grantee_user_id"], "grantee_username": r["grantee_username"],
                            "granted_by": r["granted_by"], "granted_by_username": r["granted_by_username"],
                            "expires_at": r["expires_at"]})
        await self.conn.commit()
        return out

    async def find_usernames(self, prefix: str, limit: int = 10) -> list[dict]:
        """Case-insensitive username prefix search for the share/grant picker."""
        prefix = (prefix or "").strip().replace("%", "").replace("_", "")
        if not prefix:
            return []
        cursor = await self.conn.execute(
            "SELECT id, username FROM users WHERE username LIKE ? ORDER BY username LIMIT ?",
            (prefix + "%", min(max(limit, 1), 25)),
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ------------------------------------------------------------------
    # Game servers (SteamCMD) — see gameservers.py
    # ------------------------------------------------------------------
    async def game_catalog_list(self) -> list[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM game_catalog ORDER BY builtin DESC, name")
        return [dict(r) for r in await cur.fetchall()]

    async def game_catalog_get(self, key: str) -> Optional[dict]:
        cur = await self.conn.execute("SELECT * FROM game_catalog WHERE key = ?", (key,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def game_catalog_upsert(self, data: dict, builtin: bool = False) -> int:
        import json
        cp = data.get("config_paths", [])
        bp = data.get("backup_paths", [])
        row = {
            "key": data["key"], "name": data["name"],
            "steam_app_id": int(data["steam_app_id"]),
            "steam_login": data.get("steam_login") or "anonymous",
            "start_cmd": data["start_cmd"], "start_args": data.get("start_args", ""),
            "stop_signal": data.get("stop_signal") or "SIGTERM",
            "config_paths": cp if isinstance(cp, str) else json.dumps(cp),
            "backup_paths": bp if isinstance(bp, str) else json.dumps(bp),
            "config_root": data.get("config_root") or None,
            "game_port": data.get("game_port"),
            "runtime": data.get("runtime") or "native",
            "icon": data.get("icon") or "game", "notes": data.get("notes"),
            "builtin": 1 if builtin else 0,
        }
        cols = ", ".join(row.keys())
        ph = ", ".join("?" * len(row))
        upd = ", ".join(f"{k}=excluded.{k}" for k in row if k not in ("key", "builtin"))
        cur = await self.conn.execute(
            f"""INSERT INTO game_catalog ({cols}, updated_at) VALUES ({ph}, CURRENT_TIMESTAMP)
               ON CONFLICT(key) DO UPDATE SET {upd}, updated_at=CURRENT_TIMESTAMP""",
            tuple(row.values()),
        )
        await self.conn.commit()
        return cur.lastrowid

    async def game_catalog_seed(self, entries: list[dict]) -> None:
        """Keep the curated built-in catalog in sync with the code.

        Upserts every built-in entry (so catalog definition changes ship on
        restart) but only touches rows that are still marked ``builtin`` —
        admin-added or admin-overridden entries are left alone.
        """
        for e in entries:
            cur = await self.conn.execute(
                "SELECT builtin FROM game_catalog WHERE key = ?", (e["key"],))
            existing = await cur.fetchone()
            if existing is None or existing[0] == 1:
                await self.game_catalog_upsert(e, builtin=True)

    async def game_catalog_delete(self, key: str) -> bool:
        cur = await self.conn.execute(
            "DELETE FROM game_catalog WHERE key = ? AND builtin = 0", (key,))
        await self.conn.commit()
        return cur.rowcount > 0

    async def game_server_list(self) -> list[dict]:
        cur = await self.conn.execute("SELECT * FROM game_servers ORDER BY name")
        return [dict(r) for r in await cur.fetchall()]

    async def game_server_get(self, gs_id: int) -> Optional[dict]:
        cur = await self.conn.execute("SELECT * FROM game_servers WHERE id = ?", (gs_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def game_server_by_name(self, name: str) -> Optional[dict]:
        cur = await self.conn.execute("SELECT * FROM game_servers WHERE name = ?", (name,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def game_server_by_service_id(self, service_id: int) -> Optional[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM game_servers WHERE service_id = ?", (service_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def game_server_create(self, data: dict) -> int:
        import json
        cp = data.get("config_paths", [])
        bp = data.get("backup_paths", [])
        row = {
            "name": data["name"], "catalog_key": data.get("catalog_key"),
            "steam_app_id": int(data["steam_app_id"]),
            "steam_login": data.get("steam_login") or "anonymous",
            "install_dir": data["install_dir"], "unit_name": data["unit_name"],
            "start_cmd": data["start_cmd"], "start_args": data.get("start_args", ""),
            "stop_signal": data.get("stop_signal") or "SIGTERM",
            "config_paths": cp if isinstance(cp, str) else json.dumps(cp),
            "backup_paths": bp if isinstance(bp, str) else json.dumps(bp),
            "config_root": data.get("config_root") or None,
            "runtime": data.get("runtime") or "native",
            "state": data.get("state", "installing"),
            "created_by": data.get("created_by"),
        }
        cols = ", ".join(row.keys())
        ph = ", ".join("?" * len(row))
        cur = await self.conn.execute(
            f"INSERT INTO game_servers ({cols}) VALUES ({ph})", tuple(row.values()))
        await self.conn.commit()
        return cur.lastrowid

    async def game_server_update(self, gs_id: int, **fields) -> bool:
        allowed = {"service_id", "state", "install_job", "installed_build",
                   "latest_build", "build_checked_at", "start_args", "start_cmd",
                   "stop_signal", "config_paths", "backup_paths", "config_root",
                   "runtime"}
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return False
        sets = ", ".join(f"{k} = ?" for k in fields)
        cur = await self.conn.execute(
            f"UPDATE game_servers SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (*fields.values(), gs_id),
        )
        await self.conn.commit()
        return cur.rowcount > 0

    async def game_server_delete(self, gs_id: int) -> bool:
        cur = await self.conn.execute("DELETE FROM game_servers WHERE id = ?", (gs_id,))
        await self.conn.commit()
        return cur.rowcount > 0

    # Game-server storage roots (admin-managed deploy locations)
    async def game_storage_root_list(self) -> list[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM game_storage_roots ORDER BY is_default DESC, path")
        return [dict(r) for r in await cur.fetchall()]

    async def game_storage_root_get(self, root_id: int) -> Optional[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM game_storage_roots WHERE id = ?", (root_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def game_storage_root_add(self, path: str, label: str = None,
                                     is_default: bool = False) -> int:
        if is_default:
            await self.conn.execute("UPDATE game_storage_roots SET is_default = 0")
        cur = await self.conn.execute(
            "INSERT INTO game_storage_roots (path, label, is_default) VALUES (?, ?, ?)",
            (path, label, 1 if is_default else 0),
        )
        await self.conn.commit()
        return cur.lastrowid

    async def game_storage_root_set_default(self, root_id: int) -> bool:
        cur = await self.conn.execute(
            "SELECT id FROM game_storage_roots WHERE id = ?", (root_id,))
        if not await cur.fetchone():
            return False
        await self.conn.execute("UPDATE game_storage_roots SET is_default = 0")
        await self.conn.execute(
            "UPDATE game_storage_roots SET is_default = 1 WHERE id = ?", (root_id,))
        await self.conn.commit()
        return True

    async def game_storage_root_delete(self, root_id: int) -> bool:
        cur = await self.conn.execute(
            "DELETE FROM game_storage_roots WHERE id = ?", (root_id,))
        await self.conn.commit()
        return cur.rowcount > 0

    # User streams operations
    async def create_user_stream(
        self,
        user_id: int,
        name: str,
        stream_key: str,
        public_key: str = None,
        description: str = None,
        is_public: bool = False,
        golive_audience: str = "followers",
        golive_message: str = None,
        game: str = None
    ) -> int:
        """Create a new user stream.

        Args:
            user_id: Owner's user ID
            name: Stream name
            stream_key: Private key for publishing (OBS/RTMP)
            public_key: Public key for viewing (HLS/WebRTC)
            description: Stream description
            is_public: Whether stream is publicly visible
            golive_audience: 'followers' (the default for a new stream) or 'everyone'
            golive_message: the owner's go-live message template (already validated), or None
            game: the game shown next to the title (already validated), or None
        """
        if golive_audience not in ("followers", "everyone"):
            golive_audience = "followers"
        sk_hash = hash_stream_key(stream_key)
        sk_encrypted = encrypt_config(stream_key) if CRYPTO_AVAILABLE else stream_key
        pk_hash = hash_stream_key(public_key) if public_key else None
        pk_encrypted = encrypt_config(public_key) if (public_key and CRYPTO_AVAILABLE) else public_key

        cursor = await self.conn.execute(
            """INSERT INTO user_streams (user_id, name, stream_key, stream_key_hash,
               public_key, public_key_hash, description, is_public, created_at, golive_audience,
               golive_message, game)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, sk_encrypted, sk_hash, pk_encrypted, pk_hash,
             description, 1 if is_public else 0,
             datetime.now(timezone.utc).isoformat(), golive_audience, golive_message or None,
             game or None)
        )
        await self.conn.commit()
        if game:
            await self.remember_stream_game(user_id, game)
        return cursor.lastrowid

    async def get_user_streams(self, user_id: int) -> list[dict]:
        """Get all streams for a user."""
        cursor = await self.conn.execute(
            """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname, c.name as chat_channel_name
               FROM user_streams us
               LEFT JOIN users u ON us.user_id = u.id
               LEFT JOIN chat_channels c ON us.chat_channel_id = c.id
               WHERE us.user_id = ?
               ORDER BY us.created_at DESC""",
            (user_id,)
        )
        rows = await cursor.fetchall()
        return [self._decrypt_stream_keys(dict(row)) for row in rows]

    async def get_user_stream(self, stream_id: int) -> Optional[dict]:
        """Get a specific stream by ID."""
        cursor = await self.conn.execute(
            """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname, c.name as chat_channel_name
               FROM user_streams us
               LEFT JOIN users u ON us.user_id = u.id
               LEFT JOIN chat_channels c ON us.chat_channel_id = c.id
               WHERE us.id = ?""",
            (stream_id,)
        )
        row = await cursor.fetchone()
        return self._decrypt_stream_keys(dict(row)) if row else None

    async def get_stream_by_key(self, stream_key: str) -> Optional[dict]:
        """Get a stream by its private stream key (for publishing authentication)."""
        sk_hash = hash_stream_key(stream_key)
        cursor = await self.conn.execute(
            """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
               FROM user_streams us
               LEFT JOIN users u ON us.user_id = u.id
               WHERE us.stream_key_hash = ?""",
            (sk_hash,)
        )
        row = await cursor.fetchone()
        if not row:
            # Fallback for un-migrated rows (stream_key_hash is NULL)
            cursor = await self.conn.execute(
                """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
                   FROM user_streams us
                   LEFT JOIN users u ON us.user_id = u.id
                   WHERE us.stream_key = ? AND us.stream_key_hash IS NULL""",
                (stream_key,)
            )
            row = await cursor.fetchone()
            if row:
                logger.warning("Stream key lookup used plaintext fallback — un-migrated stream key detected (stream_id=%s)", row["id"])
        return self._decrypt_stream_keys(dict(row)) if row else None

    async def get_stream_by_public_key(self, public_key: str) -> Optional[dict]:
        """Get a stream by its public key (for viewing access)."""
        pk_hash = hash_stream_key(public_key)
        cursor = await self.conn.execute(
            """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
               FROM user_streams us
               LEFT JOIN users u ON us.user_id = u.id
               WHERE us.public_key_hash = ?""",
            (pk_hash,)
        )
        row = await cursor.fetchone()
        if not row:
            # Fallback for un-migrated rows (public_key_hash is NULL)
            cursor = await self.conn.execute(
                """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
                   FROM user_streams us
                   LEFT JOIN users u ON us.user_id = u.id
                   WHERE us.public_key = ? AND us.public_key_hash IS NULL""",
                (public_key,)
            )
            row = await cursor.fetchone()
            if row:
                logger.warning("Public key lookup used plaintext fallback — un-migrated stream key detected (stream_id=%s)", row["id"])
        return self._decrypt_stream_keys(dict(row)) if row else None

    # The only user_streams columns a listing for other members or for logged-out visitors
    # may carry. An allow-list on purpose: a column added later (the go-live message and
    # audience, key hashes, rtmp state) is private until it is added here.
    PUBLIC_STREAM_COLUMNS = ("id", "user_id", "name", "description", "is_public", "is_live",
                             "viewer_count", "chat_channel_id", "thumbnail_url", "started_at",
                             "total_views", "created_at", "public_key", "allow_unauthenticated", "game")

    @classmethod
    def _public_stream_select(cls) -> str:
        return ", ".join(f"us.{c}" for c in cls.PUBLIC_STREAM_COLUMNS)

    async def get_public_streams(self, live_only: bool = False) -> list[dict]:
        """Get all public streams, optionally only live ones. Only PUBLIC_STREAM_COLUMNS
        (plus owner names and the chat channel name) are returned."""
        query = f"""SELECT {self._public_stream_select()}, u.username as owner_username, u.nickname as owner_nickname, c.name as chat_channel_name
                   FROM user_streams us
                   LEFT JOIN users u ON us.user_id = u.id
                   LEFT JOIN chat_channels c ON us.chat_channel_id = c.id
                   WHERE us.is_public = 1"""
        if live_only:
            query += " AND us.is_live = 1"
        query += " ORDER BY (CASE us.is_live WHEN 1 THEN 0 WHEN 2 THEN 1 ELSE 2 END), us.viewer_count DESC, us.created_at DESC"

        cursor = await self.conn.execute(query)
        rows = await cursor.fetchall()
        return [self._decrypt_stream_keys(dict(row)) for row in rows]

    async def get_open_streams(self) -> list[dict]:
        """Get streams that allow unauthenticated public access (PUBLIC_STREAM_COLUMNS only)."""
        query = f"""SELECT {self._public_stream_select()}, u.username as owner_username, u.nickname as owner_nickname
                   FROM user_streams us
                   LEFT JOIN users u ON us.user_id = u.id
                   WHERE us.is_public = 1 AND us.allow_unauthenticated = 1
                   ORDER BY (CASE us.is_live WHEN 1 THEN 0 WHEN 2 THEN 1 ELSE 2 END), us.viewer_count DESC, us.created_at DESC"""
        cursor = await self.conn.execute(query)
        rows = await cursor.fetchall()
        streams = [self._decrypt_stream_keys(dict(row)) for row in rows]
        for s in streams:
            s.pop("stream_key", None)
            s.pop("stream_key_hash", None)
            s.pop("public_key_hash", None)
        return streams

    async def update_user_stream(self, stream_id: int, user_id: int = None, **kwargs) -> bool:
        """Update a user stream. If user_id is provided, verify ownership."""
        allowed_fields = {"name", "description", "is_public", "is_live", "viewer_count",
                         "chat_channel_id", "thumbnail_url", "started_at", "ended_at",
                         "allow_unauthenticated", "rtmp_enabled", "golive_message",
                         "golive_audience", "game"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not updates:
            return False

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [stream_id]

        query = f"UPDATE user_streams SET {set_clause} WHERE id = ?"
        if user_id is not None:
            query += " AND user_id = ?"
            values.append(user_id)

        cursor = await self.conn.execute(query, values)
        await self.conn.commit()
        changed = cursor.rowcount > 0
        if changed and kwargs.get("game"):
            owner = user_id
            if owner is None:
                row = await (await self.conn.execute(
                    "SELECT user_id FROM user_streams WHERE id = ?", (stream_id,))).fetchone()
                owner = row["user_id"] if row else None
            if owner is not None:
                await self.remember_stream_game(owner, kwargs["game"])
        return changed

    # Games an owner used before, for the settings form's suggestions. Per owner, at most
    # GAME_HISTORY_PER_USER (the least recently used go first).
    GAME_HISTORY_PER_USER = 100
    GAME_SUGGESTIONS_MAX = 50

    async def remember_stream_game(self, user_id: int, game: str) -> None:
        """Note that this owner used this game now (case-insensitive: the newest spelling wins)."""
        now = datetime.now(timezone.utc).isoformat()
        await self.conn.execute("DELETE FROM stream_game_history WHERE user_id = ? AND game = ?",
                                (user_id, game))
        await self.conn.execute(
            "INSERT INTO stream_game_history (user_id, game, used_at) VALUES (?, ?, ?)",
            (user_id, game, now))
        await self.conn.execute(
            """DELETE FROM stream_game_history WHERE user_id = ? AND game NOT IN (
                   SELECT game FROM stream_game_history WHERE user_id = ?
                   ORDER BY used_at DESC, rowid DESC LIMIT ?)""",
            (user_id, user_id, self.GAME_HISTORY_PER_USER))
        await self.conn.commit()

    async def get_game_suggestions(self, user_id: int) -> list[str]:
        """Distinct games for the settings form: first the ones this member used before (their
        history and their own streams' current games, most recent first), then the current game
        of streams that are public now. Never the game of another member's stream that is not
        public, and never another member's history: a stream that was public once and is
        private now shows nothing. At most GAME_SUGGESTIONS_MAX."""
        # One row per game (case folded), the best one by own-before-public then newest, and the
        # LIMIT, all in SQL: a community with thousands of streams reads at most the answer.
        cursor = await self.conn.execute(
            """WITH cand(game, prio, at) AS (
                   SELECT game, 0, COALESCE(used_at, '') FROM stream_game_history
                    WHERE user_id = ? AND game IS NOT NULL AND game != ''
                   UNION ALL
                   SELECT game, 0, COALESCE(updated_at, created_at, '') FROM user_streams
                    WHERE user_id = ? AND game IS NOT NULL AND game != ''
                   UNION ALL
                   SELECT game, 1, COALESCE(updated_at, created_at, '') FROM user_streams
                    WHERE is_public = 1 AND game IS NOT NULL AND game != ''),
               ranked AS (
                   SELECT game, prio, at,
                          ROW_NUMBER() OVER (PARTITION BY casefold(game)
                                             ORDER BY prio, at DESC, game) AS n
                   FROM cand)
               SELECT game FROM ranked WHERE n = 1 ORDER BY prio, at DESC, game LIMIT ?""",
            (user_id, user_id, self.GAME_SUGGESTIONS_MAX))
        return [r["game"] for r in await cursor.fetchall()]

    async def claim_golive(self, stream_id: int, now: int, cooldown: int) -> bool:
        """Take the right to announce a go-live: True for exactly one caller per cooldown.

        One conditional UPDATE, so the check and the set are a single step that two
        concurrent publishes (a retried media hook, a quick encoder restart) cannot
        both win. The time is stored, so a restart of the portal does not reset it.
        A stored time in the future (the clock was stepped back) is no announcement
        that happened yet, so it never blocks: it is claimable and is overwritten.
        """
        cursor = await self.conn.execute(
            """UPDATE user_streams SET golive_announced_at = ?
               WHERE id = ? AND (golive_announced_at IS NULL OR golive_announced_at <= ?
                                 OR golive_announced_at > ?)""",
            (int(now), stream_id, int(now) - int(cooldown), int(now))
        )
        await self.conn.commit()
        return cursor.rowcount == 1

    async def claim_golive_owner(self, user_id: int, now: int, cooldown: int) -> bool:
        """Take the owner's broad-announcement slot: True for exactly one caller per cooldown
        per streamer, whatever stream it is for. One upsert that only overwrites a time that is
        old enough (or in the future: the clock was stepped back), so concurrent announcements
        cannot both win and a restart does not reset it."""
        cursor = await self.conn.execute(
            """INSERT INTO golive_owner_cooldown (user_id, announced_at) VALUES (?, ?)
               ON CONFLICT(user_id) DO UPDATE SET announced_at = excluded.announced_at
               WHERE golive_owner_cooldown.announced_at <= ? OR golive_owner_cooldown.announced_at > ?""",
            (user_id, int(now), int(now) - int(cooldown), int(now)))
        await self.conn.commit()
        return cursor.rowcount == 1

    # ------------------------------------------------------------------
    # Follows. Who follows whom is private: nothing here returns the follower
    # ids of a stream to a route. get_follower_audience is for the go-live
    # fan-out only; the owner sees count_followers, never names.
    # ------------------------------------------------------------------

    FOLLOW_LIMIT_PER_USER = 200

    async def follow_stream(self, user_id: int, stream_id: int) -> str:
        """Follow a stream. Returns 'followed', 'already' or 'limit'."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM stream_follow WHERE user_id = ? AND stream_id = ?", (user_id, stream_id))
        if await cursor.fetchone():
            return "already"
        cursor = await self.conn.execute(
            "SELECT COUNT(*) AS n FROM stream_follow WHERE user_id = ?", (user_id,))
        if (await cursor.fetchone())["n"] >= self.FOLLOW_LIMIT_PER_USER:
            return "limit"
        await self.conn.execute(
            "INSERT OR IGNORE INTO stream_follow (user_id, stream_id) VALUES (?, ?)", (user_id, stream_id))
        await self.conn.commit()
        return "followed"

    async def unfollow_stream(self, user_id: int, stream_id: int) -> bool:
        cursor = await self.conn.execute(
            "DELETE FROM stream_follow WHERE user_id = ? AND stream_id = ?", (user_id, stream_id))
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_followed_stream_ids(self, user_id: int) -> list[int]:
        """The streams this member follows (their own list only)."""
        cursor = await self.conn.execute(
            "SELECT stream_id FROM stream_follow WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        return [r["stream_id"] for r in await cursor.fetchall()]

    async def count_followers(self, stream_id: int) -> int:
        cursor = await self.conn.execute(
            "SELECT COUNT(*) AS n FROM stream_follow WHERE stream_id = ?", (stream_id,))
        return (await cursor.fetchone())["n"]

    async def count_followers_for_streams(self, stream_ids: list[int]) -> dict:
        """Follower counts for several streams (the owner's own list)."""
        if not stream_ids:
            return {}
        marks = ",".join("?" * len(stream_ids))
        cursor = await self.conn.execute(
            f"SELECT stream_id, COUNT(*) AS n FROM stream_follow WHERE stream_id IN ({marks}) GROUP BY stream_id",
            list(stream_ids))
        return {r["stream_id"]: r["n"] for r in await cursor.fetchall()}

    async def remove_stream_follows(self, stream_id: int) -> int:
        """Remove every follow of a stream (it became private)."""
        cursor = await self.conn.execute("DELETE FROM stream_follow WHERE stream_id = ?", (stream_id,))
        await self.conn.commit()
        return cursor.rowcount

    async def get_follower_audience(self, stream_id: int) -> list[dict]:
        """Id and role of each follower, for the go-live fan-out only."""
        cursor = await self.conn.execute(
            """SELECT u.id, u.role, u.is_admin FROM stream_follow f
               JOIN users u ON u.id = f.user_id WHERE f.stream_id = ? ORDER BY u.id""", (stream_id,))
        return [dict(r) for r in await cursor.fetchall()]

    async def get_live_streams(self) -> list[dict]:
        """Streams that are live now, with the streamer's names and no key at all."""
        cursor = await self.conn.execute(
            """SELECT us.id, us.user_id, us.name, us.game, us.is_public, us.is_live, us.viewer_count,
                      us.started_at, u.username AS owner_username, u.nickname AS owner_nickname
               FROM user_streams us LEFT JOIN users u ON us.user_id = u.id
               WHERE us.is_live = 1 ORDER BY us.started_at DESC, us.id DESC""")
        return [dict(r) for r in await cursor.fetchall()]

    # ------------------------------------------------------------------
    # Go-live cards and notification batches
    # ------------------------------------------------------------------

    async def add_stream_card(self, message_id: int, stream_id: int, channel_id: int,
                              streamer: str, title: str, game: str = None) -> None:
        """Store what a card shows. The streamer and the title are encrypted at rest like
        the message text: a renamed stream's old title must not stay readable here."""
        await self.conn.execute(
            "INSERT INTO stream_cards (message_id, stream_id, channel_id, streamer, title, game) VALUES (?, ?, ?, ?, ?, ?)",
            (message_id, stream_id, channel_id, encrypt_message(streamer), encrypt_message(title),
             encrypt_message(game) if game else None))
        await self.conn.commit()

    async def scrub_reply_previews(self, message_id: int) -> int:
        """Forget the preview text stored with replies to a message that is about to be removed."""
        cursor = await self.conn.execute(
            """UPDATE chat_messages SET reply_preview_text = NULL, reply_preview_username = NULL
               WHERE reply_to = ?""", (message_id,))
        await self.conn.commit()
        return cursor.rowcount

    async def get_stream_cards(self, message_ids) -> dict:
        """The card data of the given messages, by message id."""
        ids = list(message_ids)
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        cursor = await self.conn.execute(
            f"SELECT message_id, stream_id, channel_id, streamer, title, game FROM stream_cards WHERE message_id IN ({marks})",
            ids)
        out = {}
        for r in await cursor.fetchall():
            row = dict(r)
            row["streamer"] = decrypt_message(row["streamer"])
            row["title"] = decrypt_message(row["title"])
            row["game"] = decrypt_message(row["game"]) if row.get("game") else None
            out[row["message_id"]] = row
        return out

    async def get_cards_of_stream(self, stream_id: int) -> list[dict]:
        cursor = await self.conn.execute(
            "SELECT message_id, stream_id, channel_id FROM stream_cards WHERE stream_id = ?", (stream_id,))
        return [dict(r) for r in await cursor.fetchall()]

    async def create_notifications_bulk(self, rows: list) -> list[tuple[int, int]]:
        """Insert several notifications in one transaction (one commit).

        `rows` is a list of (user_id, type, title, message, data). Returns
        [(user_id, notification_id)] in the same order."""
        out = []
        try:
            for user_id, type_, title, message, data in rows:
                cursor = await self.conn.execute(
                    """INSERT INTO notifications (user_id, type, title, message, data)
                       VALUES (?, ?, ?, ?, ?)""",
                    (user_id, type_, encrypt_message(title) if title else title,
                     encrypt_message(message) if message else message, json.dumps(data or {})))
                out.append((user_id, cursor.lastrowid))
            await self.conn.commit()
        except Exception:
            await self.conn.rollback()
            raise
        return out

    async def reset_all_streams_offline(self) -> int:
        """Reset all streams to offline. Called on server startup."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "UPDATE user_streams SET is_live = 0, viewer_count = 0, updated_at = ? WHERE is_live != 0",
            (now,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def set_stream_live(self, stream_id: int, is_live: bool, session_stats=None) -> bool:
        """Set stream live status and update timestamps. Going offline may carry
        session_stats=(peak, unique) viewers of the session that ended; None leaves the
        stored figures as they are."""
        now = datetime.now(timezone.utc).isoformat()
        if is_live:
            cursor = await self.conn.execute(
                """UPDATE user_streams
                   SET is_live = 1, started_at = ?, updated_at = ?
                   WHERE id = ?""",
                (now, now, stream_id)
            )
        else:
            cursor = await self.conn.execute(
                """UPDATE user_streams
                   SET is_live = 0, ended_at = ?, viewer_count = 0, updated_at = ?,
                       total_views = total_views + viewer_count,
                       last_peak_viewers = COALESCE(?, last_peak_viewers),
                       last_unique_viewers = COALESCE(?, last_unique_viewers)
                   WHERE id = ?""",
                (now, now, session_stats[0] if session_stats else None,
                 session_stats[1] if session_stats else None, stream_id)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def set_live_viewer_count(self, stream_id: int, count: int) -> bool:
        """Write the viewer count of a stream that is live now (a late write cannot bring a
        count back to a stream that has just gone offline)."""
        cursor = await self.conn.execute(
            "UPDATE user_streams SET viewer_count = ? WHERE id = ? AND is_live = 1",
            (int(count), stream_id))
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_viewer_count(self, stream_id: int, count: int) -> None:
        """Update viewer count for a live stream."""
        await self.conn.execute(
            "UPDATE user_streams SET viewer_count = ? WHERE id = ?",
            (count, stream_id)
        )
        await self.conn.commit()

    async def set_stream_encoding(self, stream_id: int) -> bool:
        """Set stream to encoding state (is_live=2). VOD chunks still being finalized."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """UPDATE user_streams
               SET is_live = 2, viewer_count = 0, updated_at = ?
               WHERE id = ?""",
            (now, stream_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def increment_stream_viewers(self, stream_id: int, delta: int = 1) -> bool:
        """Increment or decrement viewer count."""
        if delta >= 0:
            cursor = await self.conn.execute(
                "UPDATE user_streams SET viewer_count = viewer_count + ? WHERE id = ?",
                (delta, stream_id)
            )
        else:
            cursor = await self.conn.execute(
                "UPDATE user_streams SET viewer_count = MAX(0, viewer_count + ?) WHERE id = ?",
                (delta, stream_id)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_user_stream(self, stream_id: int, user_id: int = None) -> bool:
        """Delete a user stream. If user_id is provided, verify ownership."""
        query = "DELETE FROM user_streams WHERE id = ?"
        params = [stream_id]

        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        cursor = await self.conn.execute(query, params)
        await self.conn.commit()
        return cursor.rowcount > 0

    async def regenerate_stream_key(self, stream_id: int, new_key: str, user_id: int = None) -> bool:
        """Regenerate a stream key."""
        sk_hash = hash_stream_key(new_key)
        sk_encrypted = encrypt_config(new_key) if CRYPTO_AVAILABLE else new_key

        query = "UPDATE user_streams SET stream_key = ?, stream_key_hash = ?, updated_at = ? WHERE id = ?"
        params = [sk_encrypted, sk_hash, datetime.now(timezone.utc).isoformat(), stream_id]

        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        cursor = await self.conn.execute(query, params)
        await self.conn.commit()
        return cursor.rowcount > 0

    async def regenerate_public_key(self, stream_id: int, new_key: str, user_id: int = None) -> bool:
        """Replace a stream's public (playback) key. The old key stops resolving at once."""
        pk_hash = hash_stream_key(new_key)
        pk_encrypted = encrypt_config(new_key) if CRYPTO_AVAILABLE else new_key

        query = "UPDATE user_streams SET public_key = ?, public_key_hash = ?, updated_at = ? WHERE id = ?"
        params = [pk_encrypted, pk_hash, datetime.now(timezone.utc).isoformat(), stream_id]

        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        cursor = await self.conn.execute(query, params)
        await self.conn.commit()
        return cursor.rowcount > 0

    # RTMP Token operations
    async def create_rtmp_token(self, stream_id: int, user_id: int, token_hash: str, expires_at: str) -> int:
        """Create a temporary RTMP publish token."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO rtmp_tokens (token_hash, stream_id, user_id, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (token_hash, stream_id, user_id, now, expires_at)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_rtmp_token(self, token_hash: str) -> Optional[dict]:
        """Get an RTMP token by hash, joined with stream data."""
        cursor = await self.conn.execute(
            """SELECT rt.*, us.stream_key, us.stream_key_hash, us.rtmp_enabled,
                      us.user_id as stream_user_id, us.name as stream_name,
                      us.is_public, us.is_live, us.chat_channel_id,
                      us.allow_unauthenticated, us.viewer_count,
                      us.started_at, us.ended_at, us.thumbnail_url,
                      u.username as owner_username, u.nickname as owner_nickname
               FROM rtmp_tokens rt
               JOIN user_streams us ON rt.stream_id = us.id
               LEFT JOIN users u ON us.user_id = u.id
               WHERE rt.token_hash = ?""",
            (token_hash,)
        )
        row = await cursor.fetchone()
        if row:
            result = dict(row)
            # Decrypt stream key for downstream use (VOD recording needs it)
            if result.get("stream_key"):
                result["stream_key"] = decrypt_config(result["stream_key"])
            return result
        return None

    async def mark_rtmp_token_used(self, token_id: int, ip: str) -> bool:
        """Mark an RTMP token as used and bind to the connecting IP."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "UPDATE rtmp_tokens SET used = 1, used_at = ?, bound_ip = ?, last_active_at = ? WHERE id = ?",
            (now, ip, now, token_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def refresh_rtmp_token_activity(self, token_id: int) -> bool:
        """Update last_active_at for rolling reconnect grace window."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "UPDATE rtmp_tokens SET last_active_at = ? WHERE id = ?",
            (now, token_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def revoke_rtmp_tokens_for_stream(self, stream_id: int) -> int:
        """Revoke all active tokens for a stream."""
        cursor = await self.conn.execute(
            "UPDATE rtmp_tokens SET revoked = 1 WHERE stream_id = ? AND revoked = 0",
            (stream_id,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def cleanup_expired_rtmp_tokens(self) -> int:
        """Delete tokens that are no longer usable.

        - Unused tokens: delete if expired more than 1 hour ago
        - Used tokens: delete if last activity more than 1 hour ago
        - Revoked tokens: always delete
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cursor = await self.conn.execute(
            """DELETE FROM rtmp_tokens WHERE
               revoked = 1 OR
               (used = 0 AND expires_at < ?) OR
               (used = 1 AND (last_active_at < ? OR (last_active_at IS NULL AND used_at < ?)))""",
            (cutoff, cutoff, cutoff)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def get_active_rtmp_tokens(self, stream_id: int) -> list[dict]:
        """Get active (usable) tokens for a stream."""
        now = datetime.now(timezone.utc).isoformat()
        from config import Config
        grace_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=Config.RTMP_TOKEN_GRACE_SECONDS)).isoformat()
        cursor = await self.conn.execute(
            """SELECT id, created_at, expires_at, used, used_at, bound_ip, last_active_at
               FROM rtmp_tokens
               WHERE stream_id = ? AND revoked = 0
               AND (
                   (used = 0 AND expires_at > ?) OR
                   (used = 1 AND (last_active_at > ? OR (last_active_at IS NULL AND used_at > ?)))
               )
               ORDER BY created_at DESC""",
            (stream_id, now, grace_cutoff, grace_cutoff)
        )
        return [dict(row) for row in await cursor.fetchall()]

    # Stream Ban operations (moderation)
    async def create_stream_ban(
        self,
        stream_id: int,
        user_id: int,
        banned_by: int,
        reason: str = None,
        anonymous: bool = False,
        message_id: int = None,
        banned_by_anonymous: bool = False
    ) -> int:
        """Ban a user from a stream's chat. Returns ban ID or 0 if failed.

        A named ban is unique per user and stream. A ban made from an anonymous
        post (anonymous=True) is recorded as its own row, once per message, and
        is never rejected because the user is already banned, so the outcome
        does not depend on whose post it was.
        """
        try:
            if anonymous and message_id is not None:
                cursor = await self.conn.execute(
                    "SELECT id FROM stream_bans WHERE stream_id = ? AND anonymous = 1 AND message_id = ?",
                    (stream_id, message_id)
                )
                row = await cursor.fetchone()
                if row:
                    return row["id"]
            cursor = await self.conn.execute(
                """INSERT INTO stream_bans (stream_id, user_id, banned_by, reason, anonymous, message_id,
                                             banned_by_anonymous)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (stream_id, user_id, banned_by, reason, 1 if anonymous else 0,
                 message_id if anonymous else None, 1 if banned_by_anonymous else 0)
            )
            await self.conn.commit()
            return cursor.lastrowid
        except Exception:
            return 0

    async def remove_stream_ban(self, stream_id: int, user_id: int,
                                include_anonymous: bool = False) -> bool:
        """Remove a user's named ban from a stream. Bans recorded from
        anonymous posts are removed as well only when include_anonymous is set
        (callers entitled to know who the author is)."""
        cursor = await self.conn.execute(
            "DELETE FROM stream_bans WHERE stream_id = ? AND user_id = ? AND (anonymous = 0 OR ?)",
            (stream_id, user_id, 1 if include_anonymous else 0)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_stream_ban(self, stream_id: int, ban_id: int) -> Optional[dict]:
        """One ban of this stream by its ban id (id, user_id, anonymous) or None."""
        cursor = await self.conn.execute(
            "SELECT id, user_id, anonymous FROM stream_bans WHERE id = ? AND stream_id = ?",
            (ban_id, stream_id))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_banned_stream_ids(self, user_id: int) -> set:
        """The ids of the streams this member is banned from."""
        cursor = await self.conn.execute(
            "SELECT DISTINCT stream_id FROM stream_bans WHERE user_id = ?", (user_id,))
        return {r[0] for r in await cursor.fetchall()}

    async def get_banned_user_ids(self, stream_id: int) -> set:
        """The ids of the members banned from this stream."""
        cursor = await self.conn.execute(
            "SELECT DISTINCT user_id FROM stream_bans WHERE stream_id = ?", (stream_id,))
        return {r[0] for r in await cursor.fetchall()}

    async def remove_stream_ban_by_id(self, stream_id: int, ban_id: int) -> Optional[dict]:
        """Remove one ban of this stream by its ban id. Returns the removed row
        (so the caller can tell whether it was an anonymous one) or None."""
        cursor = await self.conn.execute(
            "SELECT id, user_id, anonymous FROM stream_bans WHERE id = ? AND stream_id = ?",
            (ban_id, stream_id)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        await self.conn.execute(
            "DELETE FROM stream_bans WHERE id = ? AND stream_id = ?", (ban_id, stream_id))
        await self.conn.commit()
        return dict(row)

    async def is_user_banned_from_stream(self, stream_id: int, user_id: int) -> bool:
        """Check if a user is banned from a stream."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM stream_bans WHERE stream_id = ? AND user_id = ?",
            (stream_id, user_id)
        )
        return await cursor.fetchone() is not None

    async def get_stream_bans(self, stream_id: int) -> list[dict]:
        """Get all bans for a stream. Rows made from anonymous posts carry
        anonymous = 1; callers must mask them for viewers not entitled to the
        author's identity."""
        cursor = await self.conn.execute(
            """SELECT sb.id, sb.stream_id, sb.user_id, sb.banned_by, sb.reason, sb.created_at,
                      sb.anonymous,
                      u.username as banned_username, ub.username as banned_by_username,
                      sb.banned_by_anonymous, ub.role as banned_by_role
               FROM stream_bans sb
               JOIN users u ON sb.user_id = u.id
               JOIN users ub ON sb.banned_by = ub.id
               WHERE sb.stream_id = ?
               ORDER BY sb.created_at DESC, sb.id DESC""",
            (stream_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_stream_by_chat_channel(self, channel_id: int) -> Optional[dict]:
        """Get a stream by its chat channel ID."""
        cursor = await self.conn.execute(
            """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
               FROM user_streams us
               JOIN users u ON us.user_id = u.id
               WHERE us.chat_channel_id = ?
               ORDER BY us.id""",
            (channel_id,)
        )
        rows = await cursor.fetchall()
        if not rows:
            return None
        stream = self._decrypt_stream_keys(dict(rows[0]))
        # A default channel, or one several streams point at, is not the chat of
        # this stream (see _stream_chat_hidden)
        cursor = await self.conn.execute(
            "SELECT is_default FROM chat_channels WHERE id = ?", (channel_id,))
        ch = await cursor.fetchone()
        is_default = bool(ch and ch["is_default"])
        stream["chat_channel_shared"] = len(rows) > 1 or is_default
        stream["chat_channel_default"] = is_default
        # Every stream bound to the channel: who may read it when several are
        stream["chat_channel_owner_ids"] = sorted({r["user_id"] for r in rows})
        stream["chat_channel_all_public"] = all(bool(r["is_public"]) for r in rows)
        return stream

    async def count_streams_for_chat_channel(self, channel_id: int) -> int:
        """How many streams use this chat channel."""
        cursor = await self.conn.execute(
            "SELECT COUNT(*) FROM user_streams WHERE chat_channel_id = ?", (channel_id,))
        row = await cursor.fetchone()
        return row[0] if row else 0

    # Chat timeout/mute operations
    async def create_chat_timeout(self, user_id: int, moderator_id: int,
                                   type: str = 'timeout', channel_id: int = None,
                                   reason: str = None, duration_seconds: int = None) -> int:
        """Create a timeout or mute. duration_seconds=None means indefinite (mute)."""
        expires_at = None
        if duration_seconds:
            expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)).isoformat()
        # Remove any existing timeout/mute for this user+channel first
        if channel_id:
            await self.conn.execute(
                "DELETE FROM chat_timeouts WHERE user_id = ? AND (channel_id = ? OR channel_id IS NULL)",
                (user_id, channel_id)
            )
        else:
            await self.conn.execute(
                "DELETE FROM chat_timeouts WHERE user_id = ?", (user_id,)
            )
        cursor = await self.conn.execute(
            """INSERT INTO chat_timeouts (user_id, channel_id, moderator_id, type, reason, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, channel_id, moderator_id, type, reason, expires_at)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def remove_chat_timeout(self, user_id: int, channel_id: int = None) -> bool:
        """Remove active timeouts/mutes for a user."""
        if channel_id:
            cursor = await self.conn.execute(
                "DELETE FROM chat_timeouts WHERE user_id = ? AND (channel_id = ? OR channel_id IS NULL)",
                (user_id, channel_id)
            )
        else:
            cursor = await self.conn.execute(
                "DELETE FROM chat_timeouts WHERE user_id = ?", (user_id,)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def is_user_timed_out(self, user_id: int, channel_id: int = None) -> Optional[dict]:
        """Check if user has an active timeout/mute. Returns record or None."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """SELECT * FROM chat_timeouts
               WHERE user_id = ? AND (channel_id IS NULL OR channel_id = ?)
               AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, channel_id, now)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_chat_timeouts(self, channel_id: int = None) -> list[dict]:
        """Get all active timeouts/mutes."""
        now = datetime.now(timezone.utc).isoformat()
        if channel_id:
            cursor = await self.conn.execute(
                """SELECT t.*, u.username as target_username, m.username as moderator_username
                   FROM chat_timeouts t
                   JOIN users u ON t.user_id = u.id
                   JOIN users m ON t.moderator_id = m.id
                   WHERE (t.channel_id = ? OR t.channel_id IS NULL)
                   AND (t.expires_at IS NULL OR t.expires_at > ?)
                   ORDER BY t.created_at DESC""",
                (channel_id, now)
            )
        else:
            cursor = await self.conn.execute(
                """SELECT t.*, u.username as target_username, m.username as moderator_username
                   FROM chat_timeouts t
                   JOIN users u ON t.user_id = u.id
                   JOIN users m ON t.moderator_id = m.id
                   WHERE t.expires_at IS NULL OR t.expires_at > ?
                   ORDER BY t.created_at DESC""",
                (now,)
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def cleanup_expired_timeouts(self) -> int:
        """Delete expired timeouts. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM chat_timeouts WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def get_user_by_nickname(self, nickname: str) -> Optional[dict]:
        """Get a user by nickname (case-insensitive). Returns only safe fields."""
        cursor = await self.conn.execute(
            "SELECT id, username, nickname, role, is_admin FROM users WHERE LOWER(nickname) = LOWER(?)",
            (nickname,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # =============================================
    # User blocking operations
    # =============================================

    async def block_user(self, user_id: int, blocked_user_id: int) -> bool:
        """Block a user."""
        try:
            await self.conn.execute(
                "INSERT OR IGNORE INTO user_blocks (user_id, blocked_user_id) VALUES (?, ?)",
                (user_id, blocked_user_id)
            )
            await self.conn.commit()
            return True
        except Exception:
            return False

    async def unblock_user(self, user_id: int, blocked_user_id: int) -> bool:
        """Unblock a user."""
        cursor = await self.conn.execute(
            "DELETE FROM user_blocks WHERE user_id = ? AND blocked_user_id = ?",
            (user_id, blocked_user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_blocked_users(self, user_id: int) -> list[int]:
        """Get list of user IDs blocked by this user."""
        cursor = await self.conn.execute(
            "SELECT blocked_user_id FROM user_blocks WHERE user_id = ?", (user_id,)
        )
        return [row["blocked_user_id"] for row in await cursor.fetchall()]

    async def is_blocked_bidirectional(self, user_id: int, target_user_id: int) -> bool:
        """Check if either user has blocked the other."""
        cursor = await self.conn.execute(
            """SELECT 1 FROM user_blocks
               WHERE (user_id = ? AND blocked_user_id = ?)
               OR (user_id = ? AND blocked_user_id = ?)""",
            (user_id, target_user_id, target_user_id, user_id)
        )
        return (await cursor.fetchone()) is not None

    # =============================================
    # Poll operations
    # =============================================

    async def create_poll(self, channel_id: int, user_id: int, question: str,
                          options: list, allow_multiple: bool = False,
                          anonymous_votes: bool = False, expires_minutes: int = None,
                          message_id: int = None) -> int:
        """Create a poll."""
        expires_at = None
        if expires_minutes:
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)).isoformat()
        encrypted_question = encrypt_message(question)
        encrypted_options = encrypt_message(json.dumps(options))
        cursor = await self.conn.execute(
            """INSERT INTO chat_polls (channel_id, message_id, user_id, question, options,
               allow_multiple, anonymous_votes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (channel_id, message_id, user_id, encrypted_question, encrypted_options,
             1 if allow_multiple else 0, 1 if anonymous_votes else 0, expires_at)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_poll(self, poll_id: int) -> Optional[dict]:
        """Get a poll with vote counts."""
        cursor = await self.conn.execute("SELECT * FROM chat_polls WHERE id = ?", (poll_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        poll = dict(row)
        poll["question"] = decrypt_message(poll["question"])
        decrypted_options = decrypt_message(poll["options"])
        poll["options_list"] = json.loads(decrypted_options)
        # Get vote counts per option
        cursor = await self.conn.execute(
            """SELECT option_index, COUNT(*) as count, GROUP_CONCAT(user_id) as voter_ids
               FROM chat_poll_votes WHERE poll_id = ? GROUP BY option_index""",
            (poll_id,)
        )
        vote_rows = await cursor.fetchall()
        vote_map = {}
        for vr in vote_rows:
            vote_map[vr["option_index"]] = {
                "count": vr["count"],
                "voter_ids": [int(x) for x in vr["voter_ids"].split(",")] if vr["voter_ids"] else []
            }
        total = sum(v["count"] for v in vote_map.values())
        options_data = []
        for i, text in enumerate(poll["options_list"]):
            v = vote_map.get(i, {"count": 0, "voter_ids": []})
            opt = {"text": text, "index": i, "count": v["count"]}
            if not poll["anonymous_votes"]:
                opt["voter_ids"] = v["voter_ids"]
            options_data.append(opt)
        poll["options_data"] = options_data
        poll["total_votes"] = total
        # Check expiry
        if poll["expires_at"]:
            exp = poll["expires_at"]
            if not exp.endswith("Z") and "+" not in exp:
                exp += "+00:00"
            try:
                if datetime.fromisoformat(exp) < datetime.now(timezone.utc):
                    poll["is_closed"] = 1
            except Exception:
                pass
        return poll

    async def vote_poll(self, poll_id: int, user_id: int, option_index: int) -> bool:
        """Vote on a poll. Returns True if vote was recorded."""
        poll = await self.get_poll(poll_id)
        if not poll or poll["is_closed"]:
            return False
        if option_index < 0 or option_index >= len(poll["options_list"]):
            return False
        try:
            if not poll["allow_multiple"]:
                # Single vote: atomic delete + insert in same transaction
                await self.conn.execute(
                    "DELETE FROM chat_poll_votes WHERE poll_id = ? AND user_id = ?",
                    (poll_id, user_id)
                )
            await self.conn.execute(
                "INSERT OR IGNORE INTO chat_poll_votes (poll_id, user_id, option_index) VALUES (?, ?, ?)",
                (poll_id, user_id, option_index)
            )
            await self.conn.commit()
            return True
        except Exception:
            await self.conn.rollback()
            return False

    async def unvote_poll(self, poll_id: int, user_id: int, option_index: int) -> bool:
        """Remove a vote from a poll."""
        cursor = await self.conn.execute(
            "DELETE FROM chat_poll_votes WHERE poll_id = ? AND user_id = ? AND option_index = ?",
            (poll_id, user_id, option_index)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def close_poll(self, poll_id: int) -> bool:
        """Close a poll."""
        cursor = await self.conn.execute(
            "UPDATE chat_polls SET is_closed = 1 WHERE id = ?", (poll_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_poll_by_message(self, message_id: int) -> Optional[dict]:
        """Get a poll by its associated message ID."""
        cursor = await self.conn.execute(
            "SELECT id FROM chat_polls WHERE message_id = ?", (message_id,)
        )
        row = await cursor.fetchone()
        if row:
            return await self.get_poll(row["id"])
        return None

    async def get_polls_by_message_ids(self, message_ids: list[int]) -> dict[int, dict]:
        """Get polls for multiple message IDs. Returns {message_id: poll_dict}."""
        if not message_ids:
            return {}
        placeholders = ",".join("?" * len(message_ids))
        cursor = await self.conn.execute(
            f"SELECT id, message_id FROM chat_polls WHERE message_id IN ({placeholders})",
            message_ids
        )
        rows = await cursor.fetchall()
        result = {}
        for row in rows:
            poll = await self.get_poll(row["id"])
            if poll:
                result[row["message_id"]] = poll
        return result

    # =============================================
    # Audit log operations
    # =============================================

    async def create_audit_entry(self, action: str, actor_id: int, actor_username: str,
                                  target_id: int = None, target_type: str = None,
                                  target_name: str = None, details: dict = None,
                                  channel_id: int = None, channel_name: str = None) -> int:
        """Create an audit log entry."""
        details_str = json.dumps(details) if details else None
        enc_details = encrypt_message(details_str) if details_str else None
        cursor = await self.conn.execute(
            """INSERT INTO audit_log (action, actor_id, actor_username, target_id, target_type,
               target_name, details, channel_id, channel_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (action, actor_id, actor_username, target_id, target_type, target_name,
             enc_details, channel_id, channel_name)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_audit_log(self, limit: int = 50, offset: int = 0,
                             action: str = None, actor_id: int = None,
                             channel_id: int = None, since: str = None,
                             exclude_actions: tuple = ()) -> list[dict]:
        """Get audit log entries with optional filters; exclude_actions leaves those actions out."""
        conditions = []
        params = []
        if action:
            conditions.append("action = ?")
            params.append(action)
        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if channel_id:
            conditions.append("channel_id = ?")
            params.append(channel_id)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)
        if exclude_actions:
            conditions.append("action NOT IN (" + ",".join("?" * len(exclude_actions)) + ")")
            params.extend(exclude_actions)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        cursor = await self.conn.execute(
            f"SELECT * FROM audit_log{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params
        )
        entries = []
        for row in await cursor.fetchall():
            e = dict(row)
            if e.get("details"):
                e["details"] = decrypt_message(e["details"])
            entries.append(e)
        return entries

    async def get_audit_log_count(self, action: str = None, actor_id: int = None,
                                   channel_id: int = None, since: str = None,
                                   exclude_actions: tuple = ()) -> int:
        """Get total count of audit log entries with filters."""
        conditions = []
        params = []
        if action:
            conditions.append("action = ?")
            params.append(action)
        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if channel_id:
            conditions.append("channel_id = ?")
            params.append(channel_id)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)
        if exclude_actions:
            conditions.append("action NOT IN (" + ",".join("?" * len(exclude_actions)) + ")")
            params.extend(exclude_actions)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        cursor = await self.conn.execute(f"SELECT COUNT(*) as cnt FROM audit_log{where}", params)
        row = await cursor.fetchone()
        return row["cnt"] if row else 0

    async def cleanup_old_audit_log(self, days: int = 90) -> int:
        """Delete audit log entries older than N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM audit_log WHERE created_at < ?", (cutoff,)
        )
        await self.conn.commit()
        return cursor.rowcount

    # =============================================
    # Security events (see secevents.py)
    # =============================================

    _SEC_COLS = ("ts", "event", "category", "user_id", "username_tried", "ip",
                 "user_agent", "result", "details", "count", "agg_key")

    async def insert_security_event(self, row: dict) -> int:
        """Write one security event now."""
        cursor = await self.conn.execute(
            f"INSERT INTO security_events ({', '.join(self._SEC_COLS)}) "
            f"VALUES ({', '.join('?' for _ in self._SEC_COLS)})",
            tuple(row.get(c) for c in self._SEC_COLS),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def upsert_security_events(self, rows: list[dict]) -> None:
        """Write aggregated rows; a repeated agg_key adds to its count.

        One INSERT ... SELECT statement, so SQLite applies it all or not at all.
        Row by row (executemany) a failure partway would leave the earlier rows
        in the shared connection's open transaction, for the next unrelated
        commit to write, while the caller re-queues the whole batch and counts
        them twice. A rollback is no answer either: the connection is shared
        with other callers' uncommitted work.
        """
        if not rows:
            return
        cols = self._SEC_COLS
        payload = json.dumps([{c: r.get(c) for c in cols} for r in rows])
        selected = ", ".join(f"json_extract(value, '$.{c}')" for c in cols)
        await self.conn.execute(
            f"INSERT INTO security_events ({', '.join(cols)}) "
            f"SELECT {selected} FROM json_each(?) WHERE true "
            "ON CONFLICT(agg_key) DO UPDATE SET count = count + excluded.count",
            (payload,),
        )
        await self.conn.commit()

    @staticmethod
    def _security_where(category=None, event=None, ip=None, user_id=None, username=None,
                        since=None, until=None, before_id=None):
        conds, params = [], []
        if category:
            conds.append("category = ?"); params.append(category)
        if event:
            conds.append("event = ?"); params.append(event)
        if ip:
            ips = secevents.ip_filter_values(ip)
            conds.append(f"ip IN ({', '.join('?' for _ in ips)})"); params.extend(ips)
        if user_id:
            conds.append("user_id = ?"); params.append(user_id)
        if username:
            conds.append("username_tried = ?"); params.append(username)
        if since:
            conds.append("ts >= ?"); params.append(since)
        if until:
            conds.append("ts <= ?"); params.append(until)
        if before_id:
            conds.append("id < ?"); params.append(before_id)
        return (" WHERE " + " AND ".join(conds)) if conds else "", params

    async def get_security_events(self, limit: int = 50, offset: int = 0, **filters) -> list[dict]:
        where, params = self._security_where(**filters)
        cursor = await self.conn.execute(
            f"SELECT * FROM security_events{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset])
        return [dict(r) for r in await cursor.fetchall()]

    async def count_security_events(self, **filters) -> int:
        where, params = self._security_where(**filters)
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) AS cnt FROM security_events{where}", params)
        row = await cursor.fetchone()
        return row["cnt"] if row else 0

    async def cleanup_old_security_events(self, days: int = 180) -> int:
        """Delete security events older than N days (same timestamp format as ts)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        cursor = await self.conn.execute("DELETE FROM security_events WHERE ts < ?", (cutoff,))
        await self.conn.commit()
        return cursor.rowcount

    # =============================================
    # Auto-moderation operations
    # =============================================

    async def get_automod_rules(self, enabled_only: bool = False) -> list[dict]:
        """Get auto-moderation rules."""
        if enabled_only:
            cursor = await self.conn.execute("SELECT * FROM automod_rules WHERE enabled = 1 ORDER BY id")
        else:
            cursor = await self.conn.execute("SELECT * FROM automod_rules ORDER BY id")
        rules = []
        for row in await cursor.fetchall():
            r = dict(row)
            if r.get("config"):
                r["config"] = decrypt_message(r["config"])
            rules.append(r)
        return rules

    async def create_automod_rule(self, type: str, name: str, config: dict,
                                   action: str, created_by: int,
                                   action_duration: int = None) -> int:
        """Create an auto-moderation rule."""
        enc_config = encrypt_message(json.dumps(config))
        cursor = await self.conn.execute(
            """INSERT INTO automod_rules (type, name, config, action, action_duration, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (type, name, enc_config, action, action_duration, created_by)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_automod_rule(self, rule_id: int, **kwargs) -> bool:
        """Update an auto-moderation rule."""
        allowed = {"name", "config", "enabled", "action", "action_duration", "type"}
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                if k == "config" and isinstance(v, dict):
                    updates[k] = encrypt_message(json.dumps(v))
                else:
                    updates[k] = v
        if not updates:
            return False
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [rule_id]
        cursor = await self.conn.execute(
            f"UPDATE automod_rules SET {set_clause} WHERE id = ?", values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_automod_rule(self, rule_id: int) -> bool:
        """Delete an auto-moderation rule."""
        cursor = await self.conn.execute("DELETE FROM automod_rules WHERE id = ?", (rule_id,))
        await self.conn.commit()
        return cursor.rowcount > 0

    async def create_automod_action(self, rule_id: int, user_id: int,
                                     channel_id: int, message_text: str,
                                     action_taken: str) -> int:
        """Log an auto-moderation action."""
        truncated = message_text[:500] if message_text else None
        encrypted_text = encrypt_message(truncated) if truncated else None
        cursor = await self.conn.execute(
            """INSERT INTO automod_actions (rule_id, user_id, channel_id, message_text, action_taken)
               VALUES (?, ?, ?, ?, ?)""",
            (rule_id, user_id, channel_id, encrypted_text, action_taken)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_automod_actions(self, limit: int = 50, offset: int = 0,
                                   rule_id: int = None, user_id: int = None) -> list[dict]:
        """Get auto-moderation action log."""
        conditions = []
        params = []
        if rule_id:
            conditions.append("a.rule_id = ?")
            params.append(rule_id)
        if user_id:
            conditions.append("a.user_id = ?")
            params.append(user_id)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        cursor = await self.conn.execute(
            f"""SELECT a.*, r.name as rule_name, r.type as rule_type, u.username
                FROM automod_actions a
                LEFT JOIN automod_rules r ON a.rule_id = r.id
                LEFT JOIN users u ON a.user_id = u.id
                {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?""",
            params
        )
        rows = []
        for row in await cursor.fetchall():
            d = dict(row)
            if d.get("message_text"):
                d["message_text"] = decrypt_message(d["message_text"])
            rows.append(d)
        return rows

    async def cleanup_old_automod_actions(self, days: int = 30) -> int:
        """Delete automod actions older than N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute("DELETE FROM automod_actions WHERE created_at < ?", (cutoff,))
        await self.conn.commit()
        return cursor.rowcount

    # =============================================
    # Per-channel permission operations
    # =============================================

    async def add_channel_member(self, channel_id: int, user_id: int,
                                  role: str = "member", added_by: int = None) -> bool:
        """Add a member to a channel."""
        try:
            await self.conn.execute(
                "INSERT OR REPLACE INTO channel_members (channel_id, user_id, role, added_by) VALUES (?, ?, ?, ?)",
                (channel_id, user_id, role, added_by)
            )
            await self.conn.commit()
            return True
        except Exception:
            return False

    async def add_channel_moderator_capped(self, channel_id: int, user_id: int,
                                           added_by: int, cap: int) -> bool:
        """Make a member a 'moderator' of a channel unless it already has `cap` of them.
        One statement counts and inserts, so concurrent requests cannot pass the cap
        together. False: the cap is reached (or the insert failed)."""
        try:
            cursor = await self.conn.execute(
                """INSERT OR REPLACE INTO channel_members (channel_id, user_id, role, added_by)
                   SELECT ?, ?, 'moderator', ?
                   WHERE (SELECT COUNT(*) FROM channel_members
                          WHERE channel_id = ? AND role = 'moderator' AND user_id != ?) < ?""",
                (channel_id, user_id, added_by, channel_id, user_id, cap))
            await self.conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    async def remove_channel_member(self, channel_id: int, user_id: int) -> bool:
        """Remove a member from a channel."""
        cursor = await self.conn.execute(
            "DELETE FROM channel_members WHERE channel_id = ? AND user_id = ?",
            (channel_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_channel_members(self, channel_id: int) -> list[dict]:
        """Get all members of a channel."""
        cursor = await self.conn.execute(
            """SELECT cm.*, u.username, u.nickname
               FROM channel_members cm
               JOIN users u ON cm.user_id = u.id
               WHERE cm.channel_id = ?
               ORDER BY cm.role DESC, u.username""",
            (channel_id,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_channel_moderator_ids(self, channel_id: int) -> list:
        """The user ids with a 'moderator' row in this channel (a stream chat's mods)."""
        cursor = await self.conn.execute(
            "SELECT user_id FROM channel_members WHERE channel_id = ? AND role = 'moderator' ORDER BY id",
            (channel_id,))
        return [r[0] for r in await cursor.fetchall()]

    async def is_channel_member(self, channel_id: int, user_id: int) -> bool:
        """Check if a user is a member of a channel."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM channel_members WHERE channel_id = ? AND user_id = ?",
            (channel_id, user_id)
        )
        return (await cursor.fetchone()) is not None

    async def get_channel_member_role(self, channel_id: int, user_id: int) -> Optional[str]:
        """Get a user's role in a channel."""
        cursor = await self.conn.execute(
            "SELECT role FROM channel_members WHERE channel_id = ? AND user_id = ?",
            (channel_id, user_id)
        )
        row = await cursor.fetchone()
        return row["role"] if row else None

    async def get_accessible_channels(self, user_id: int, user_role: str) -> list[dict]:
        """Get channels visible to a user (public + private where member)."""
        if user_role in ("admin", "superadmin"):
            return await self.get_chat_channels()
        cursor = await self.conn.execute(
            """SELECT c.*, u.username as created_by_username
               FROM chat_channels c
               LEFT JOIN users u ON c.created_by = u.id
               WHERE c.visibility = 'public' OR c.visibility IS NULL
               OR c.id IN (SELECT channel_id FROM channel_members WHERE user_id = ?)
               ORDER BY c.is_default DESC, c.name""",
            (user_id,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def can_send_in_channel(self, channel_id: int, user_id: int, user_role: str) -> bool:
        """Check if user can send messages in a channel."""
        if user_role in ("admin", "superadmin", "moderator"):
            return True
        cursor = await self.conn.execute("SELECT * FROM chat_channels WHERE id = ?", (channel_id,))
        row = await cursor.fetchone()
        if not row:
            return False
        channel = dict(row)
        if channel.get("visibility") == "private":
            if not await self.is_channel_member(channel_id, user_id):
                return False
        if channel.get("mode") == "readonly":
            member_role = await self.get_channel_member_role(channel_id, user_id)
            if member_role != "moderator":
                return False
        return True

    # VOD Storage operations
    async def get_vod_storage(self, user_id: int) -> Optional[dict]:
        """Get VOD storage config for a user."""
        cursor = await self.conn.execute(
            "SELECT * FROM vod_storage WHERE user_id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        if row:
            storage = dict(row)
            raw_config = storage.get("config", "{}")
            try:
                storage["config"] = json.loads(decrypt_config(raw_config)) if raw_config else {}
            except (json.JSONDecodeError, Exception):
                storage["config"] = {}
            return storage
        return None

    async def save_vod_storage(self, user_id: int, **kwargs) -> int:
        """Create or update VOD storage config (upsert)."""
        # Encrypt config if present
        if "config" in kwargs:
            config_val = kwargs["config"]
            if isinstance(config_val, dict):
                import json as _json
                config_val = _json.dumps(config_val)
            kwargs["config"] = encrypt_config(config_val)

        now = datetime.now(timezone.utc).isoformat()

        fields = {
            "user_id": user_id,
            "name": kwargs.get("name", "My VOD Storage"),
            "host": kwargs["host"],
            "port": kwargs.get("port", 22),
            "username": kwargs["username"],
            "auth_method": kwargs.get("auth_method", "password"),
            "remote_path": kwargs.get("remote_path", "/home/user/vods"),
            "config": kwargs.get("config", "{}"),
            "created_at": now,
            "updated_at": now,
        }
        columns = ", ".join(fields.keys())
        placeholders = ", ".join("?" for _ in fields)
        # Atomic upsert — avoids TOCTOU race between check and insert
        update_cols = ["name", "host", "port", "username", "auth_method",
                       "remote_path", "config", "updated_at"]
        conflict_update = ", ".join(f"{c} = excluded.{c}" for c in update_cols)
        cursor = await self.conn.execute(
            f"INSERT INTO vod_storage ({columns}) VALUES ({placeholders}) "
            f"ON CONFLICT(user_id) DO UPDATE SET {conflict_update}",
            list(fields.values())
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_vod_storage_config(self, user_id: int, config: dict,
                                        host: str, port: Optional[int]) -> bool:
        """Replace the (encrypted) config of a VOD storage row, only if it still
        points at `host`:`port` (so a concurrent edit of the target wins)."""
        import json as _json
        cursor = await self.conn.execute(
            "UPDATE vod_storage SET config = ?, updated_at = ? "
            "WHERE user_id = ? AND host = ? AND COALESCE(port, 22) = ?",
            (encrypt_config(_json.dumps(config)), datetime.now(timezone.utc).isoformat(),
             user_id, host, port or 22)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_vod_storage(self, user_id: int) -> bool:
        """Delete VOD storage config for a user."""
        cursor = await self.conn.execute(
            "DELETE FROM vod_storage WHERE user_id = ?",
            (user_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Chat/Forum operations
    async def get_chat_channels(self) -> list[dict]:
        """Get all chat channels."""
        cursor = await self.conn.execute(
            """SELECT c.*, u.username as created_by_username
               FROM chat_channels c
               LEFT JOIN users u ON c.created_by = u.id
               ORDER BY c.is_default DESC, c.name"""
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_chat_channel(self, channel_id: int) -> Optional[dict]:
        """Get a specific chat channel."""
        cursor = await self.conn.execute(
            "SELECT * FROM chat_channels WHERE id = ?", (channel_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_chat_channel_by_name(self, name: str) -> Optional[dict]:
        """Get a chat channel by name."""
        cursor = await self.conn.execute(
            "SELECT * FROM chat_channels WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def create_chat_channel(self, name: str, description: str = None, created_by: int = None, category: str = None) -> int:
        """Create a new chat channel."""
        cursor = await self.conn.execute(
            "INSERT INTO chat_channels (name, description, created_by, category) VALUES (?, ?, ?, ?)",
            (name, description, created_by, category)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_chat_channel(self, channel_id: int, **kwargs) -> bool:
        """Update a chat channel."""
        allowed_fields = {"name", "description", "topic", "category", "slowmode_seconds", "visibility", "mode"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [channel_id]

        cursor = await self.conn.execute(
            f"UPDATE chat_channels SET {set_clause} WHERE id = ?",
            values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_chat_channel(self, channel_id: int) -> bool:
        """Delete a chat channel (cannot delete default channels)."""
        cursor = await self.conn.execute(
            "DELETE FROM chat_channels WHERE id = ? AND is_default = 0",
            (channel_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def create_chat_message(
        self,
        channel_id: int,
        user_id: int,
        username: str,
        message: str,
        message_type: str = "message",
        anonymous: bool = False,
        reply_to: int = None,
        image_url: str = None,
        reply_preview_username: str = None,
        reply_preview_text: str = None,
        attachment_url: str = None,
        attachment_name: str = None,
        attachment_size: int = None,
        attachment_type: str = None
    ) -> int:
        """Create a new chat message (encrypted)."""
        plaintext = message
        encrypted_message = encrypt_message(message)
        encrypted_preview = encrypt_message(reply_preview_text) if reply_preview_text else None
        # Explicitly store UTC timestamp with timezone info
        created_at = datetime.now(timezone.utc).isoformat()
        flags = chat_search.message_flags(plaintext, image_url, attachment_url, attachment_type)
        cursor = await self.conn.execute(
            """INSERT INTO chat_messages (channel_id, user_id, username, message, message_type, created_at, anonymous, reply_to, image_url, reply_preview_username, reply_preview_text, attachment_url, attachment_name, attachment_size, attachment_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (channel_id, user_id, username, encrypted_message, message_type, created_at, int(anonymous), reply_to, image_url, reply_preview_username, encrypted_preview, attachment_url, attachment_name, attachment_size, attachment_type)
        )
        msg_id = cursor.lastrowid
        await self.conn.commit()
        # Index for full-text search
        await self.index_message_for_search(
            msg_id, plaintext, "channel", channel_id, user_id, username,
            flags[0], created_at, has_file=flags[1], has_link=flags[2]
        )
        return msg_id

    @staticmethod
    def _decrypt_chat_row(row) -> dict:
        """One chat_messages row as a dict with the message and the stored
        reply preview text decrypted."""
        msg = dict(row)
        msg["message"] = decrypt_message(msg.get("message", ""))
        if msg.get("reply_preview_text"):
            msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
        return msg

    async def get_chat_messages(
        self,
        channel_id: int,
        limit: int = 100,
        before_id: int = None
    ) -> list[dict]:
        """Get chat messages for a channel (decrypted)."""
        if before_id:
            cursor = await self.conn.execute(
                """SELECT * FROM chat_messages
                   WHERE channel_id = ? AND id < ?
                   ORDER BY id DESC LIMIT ?""",
                (channel_id, before_id, limit)
            )
        else:
            cursor = await self.conn.execute(
                """SELECT * FROM chat_messages
                   WHERE channel_id = ?
                   ORDER BY id DESC LIMIT ?""",
                (channel_id, limit)
            )
        rows = await cursor.fetchall()
        # Decrypt messages and return in chronological order
        return [self._decrypt_chat_row(row) for row in reversed(rows)]

    async def get_chat_messages_page(self, channel_id: int, limit: int,
                                     before_id: int = None) -> tuple[list[dict], bool]:
        """The newest `limit` messages of a channel, or the newest `limit`
        older than before_id, oldest first, and whether still older ones exist."""
        rows = await self.get_chat_messages(channel_id, limit=limit + 1, before_id=before_id)
        if len(rows) > limit:
            return rows[1:], True
        return rows, False

    async def get_chat_messages_around(self, channel_id: int, around_id: int,
                                       limit: int) -> Optional[tuple[list[dict], bool, bool]]:
        """A window of about `limit` messages of one channel centred on
        around_id, oldest first, as (messages, has_older, has_newer). None when
        around_id is not a message of this channel (another channel, deleted,
        or removed by retention)."""
        cursor = await self.conn.execute(
            "SELECT * FROM chat_messages WHERE id = ? AND channel_id = ?",
            (around_id, channel_id)
        )
        target = await cursor.fetchone()
        if target is None:
            return None
        before_n = limit // 2
        after_n = max(limit - 1 - before_n, 0)
        cursor = await self.conn.execute(
            """SELECT * FROM chat_messages WHERE channel_id = ? AND id < ?
               ORDER BY id DESC LIMIT ?""",
            (channel_id, around_id, before_n + 1)
        )
        older = list(await cursor.fetchall())
        cursor = await self.conn.execute(
            """SELECT * FROM chat_messages WHERE channel_id = ? AND id > ?
               ORDER BY id ASC LIMIT ?""",
            (channel_id, around_id, after_n + 1)
        )
        newer = list(await cursor.fetchall())
        has_older = len(older) > before_n
        has_newer = len(newer) > after_n
        rows = list(reversed(older[:before_n])) + [target] + newer[:after_n]
        return [self._decrypt_chat_row(r) for r in rows], has_older, has_newer

    async def get_chat_messages_by_ids(self, message_ids, channel_id: int) -> list[dict]:
        """Messages of one channel by id in a single query (decrypted). Ids
        that belong to another channel, or no longer exist, are not returned."""
        ids = list({int(i) for i in message_ids})
        if not ids:
            return []
        out = []
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            placeholders = ",".join("?" * len(chunk))
            cursor = await self.conn.execute(
                f"SELECT * FROM chat_messages WHERE channel_id = ? AND id IN ({placeholders})",
                [channel_id] + chunk
            )
            out.extend(self._decrypt_chat_row(r) for r in await cursor.fetchall())
        return out

    async def get_chat_message(self, message_id: int) -> Optional[dict]:
        """Get a single chat message by ID (decrypted)."""
        cursor = await self.conn.execute(
            "SELECT * FROM chat_messages WHERE id = ?", (message_id,)
        )
        row = await cursor.fetchone()
        return self._decrypt_chat_row(row) if row else None

    async def delete_chat_message(self, message_id: int, user_id: int = None) -> bool:
        """Delete a chat message (optionally verify ownership)."""
        return await self._delete_one_message("chat_messages", "channel", message_id, user_id)

    async def cleanup_old_chat_messages(self, days: int = 7, stats: dict = None) -> int:
        """Delete chat messages older than specified days (pinned ones stay), and
        their upload files unless another row still refers to them. Returns the
        count of messages deleted; `stats`, when given, receives the files and
        bytes removed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return await self._purge_messages(
            "chat_messages", "channel", "chat_reactions",
            "created_at < ? AND is_pinned = 0", (cutoff,), stats)

    async def clear_channel_messages(self, channel_id: int, stats: dict = None) -> int:
        """Delete all messages in a channel (pinned ones too) and their upload
        files unless another row still refers to them. Returns count deleted."""
        return await self._purge_messages(
            "chat_messages", "channel", "chat_reactions",
            "channel_id = ?", (channel_id,), stats)

    # -------------------------------------------------------------------------
    # Chat upload files: removed with the rows that refer to them
    # -------------------------------------------------------------------------

    @staticmethod
    def _new_file_stats(stats: Optional[dict]) -> dict:
        stats = stats if stats is not None else {}
        stats.setdefault("files", 0)
        stats.setdefault("bytes", 0)
        return stats

    @staticmethod
    def _upload_names(rows, names: Optional[set] = None) -> set:
        """Add the upload file names that (image_url, attachment_url) pairs name."""
        names = names if names is not None else set()
        for row in rows:
            for url in (row[0], row[1]):
                name = chat_uploads.name_from_url(url)
                if name:
                    names.add(name)
        return names

    async def _remove_unreferenced_uploads(self, names, stats: dict) -> None:
        """Unlink the named upload files of already-deleted rows, except those any
        surviving row still names (see chat_uploads for where). Call only after
        the deletion was committed. The text of all messages is read in a worker
        thread; the last check and the unlinks then happen together under the
        database write lock (chat_uploads.finalize_sync). If any message cannot be
        decrypted, or the check cannot complete, nothing is removed and
        stats["skipped"] says why."""
        if not names:
            return
        try:
            stems = {chat_uploads.stem_of(n) for n in names}
            used = await asyncio.to_thread(chat_uploads.references_sync, self.db_path, stems)
            left = [n for n in sorted(names) if chat_uploads.stem_of(n) not in used]
            if not left:
                return
            scan = await asyncio.to_thread(chat_uploads.scan_text_sync, self.db_path, decrypt_message_strict)
            left = [n for n in left if chat_uploads.stem_of(n) not in scan.stems]
            if not left:
                return
            _, files, size = await asyncio.to_thread(
                chat_uploads.finalize_sync, self.db_path, self.chat_upload_dir, left,
                decrypt_message_strict, scan, True)
        except chat_uploads.Undecryptable as e:
            logger.warning(f"Chat upload cleanup skipped: a message could not be decrypted ({e})")
            stats.setdefault("skipped", "a message could not be decrypted, so its upload links are unknown")
            return
        except Exception as e:
            logger.warning(f"Chat upload cleanup skipped: {type(e).__name__}: {e}")
            stats.setdefault("skipped", f"{type(e).__name__}: {e}")
            return
        stats["files"] += files
        stats["bytes"] += size

    async def _purge_messages(self, table: str, source: str, reaction_table: str,
                              where: str, params: tuple, stats: Optional[dict]) -> int:
        """Delete the rows of `table` matching `where` in batches of 500, each
        batch in one transaction. After the last commit, the upload files of the
        deleted rows that no surviving row refers to are removed (one reference
        check for the whole purge, so the text of the surviving rows is decrypted
        once, not once per batch)."""
        stats = self._new_file_stats(stats)
        total = 0
        last_id = 0
        names: set = set()
        while True:
            cursor = await self.conn.execute(
                f"SELECT id, image_url, attachment_url FROM {table} "
                f"WHERE ({where}) AND id > ? ORDER BY id LIMIT 500", (*params, last_id))
            rows = await cursor.fetchall()
            if not rows:
                break
            batch = [r["id"] for r in rows]
            last_id = batch[-1]
            for msg_id in batch:
                try:
                    await self.remove_message_from_search(msg_id, source)
                except Exception:
                    pass
            placeholders = ",".join("?" * len(batch))
            await self.conn.execute(
                f"DELETE FROM {reaction_table} WHERE message_id IN ({placeholders})", batch)
            await self.conn.execute(
                f"DELETE FROM {table} WHERE id IN ({placeholders})", batch)
            await self.conn.commit()
            total += len(batch)
            self._upload_names([(r["image_url"], r["attachment_url"]) for r in rows], names)
        await self._remove_unreferenced_uploads(names, stats)
        return total

    async def _delete_one_message(self, table: str, source: str, message_id: int,
                                  user_id: Optional[int]) -> bool:
        """Delete one message row (optionally only if `user_id` owns it) and, after
        the commit, its upload files unless another row still refers to them."""
        file_cursor = await self.conn.execute(
            f"SELECT image_url, attachment_url FROM {table} WHERE id = ?", (message_id,))
        file_row = await file_cursor.fetchone()
        if user_id:
            cursor = await self.conn.execute(
                f"DELETE FROM {table} WHERE id = ? AND user_id = ?", (message_id, user_id))
        else:
            cursor = await self.conn.execute(f"DELETE FROM {table} WHERE id = ?", (message_id,))
        await self.conn.commit()
        if cursor.rowcount <= 0:
            return False
        await self.remove_message_from_search(message_id, source)
        if file_row:
            await self._remove_unreferenced_uploads(
                self._upload_names([(file_row["image_url"], file_row["attachment_url"])]),
                self._new_file_stats(None))
        return True

    async def sweep_orphan_chat_uploads(self, delete: Optional[bool] = None) -> dict:
        """Find chat upload files that no row refers to.

        Looks only at generated-name regular files directly inside the chat
        upload folder that are older than the 24 hour grace (the grace cannot be
        changed by a caller). A file counts as referenced if any row names it
        where chat_uploads says (URL columns, status messages, channel topics and
        descriptions, stream names and descriptions, and the decrypted text of
        messages, replies and polls, read in a worker thread). If any message
        cannot be decrypted, or the check cannot complete, nothing is reported as
        orphaned and report["skipped"] says why. Unless deletion is
        switched on (`delete`, or the setting chat_orphan_sweep_delete = "true")
        this only reports. Returns the report dict."""
        if delete is None:
            delete = (await self.get_setting("chat_orphan_sweep_delete")) == "true"
        report = {"report_only": not delete, "scanned": 0, "orphans": 0, "bytes": 0,
                  "names": [], "deleted": 0, "deleted_bytes": 0}
        found = chat_uploads.scan_candidates(self.chat_upload_dir, chat_uploads.cutoff())
        if found is None and not os.path.lexists(self.chat_upload_dir):
            found = ([], 0)        # nothing was ever uploaded: not a problem, nothing to sweep
        if found is None:
            report["skipped"] = "upload folder missing or not a plain folder"
            logger.warning("[Retention] Orphan chat upload sweep skipped: upload folder missing or a link")
            return report
        candidates, report["scanned"] = found
        sizes = dict(candidates)
        try:
            if candidates:
                used = await asyncio.to_thread(
                    chat_uploads.references_sync, self.db_path, {chat_uploads.stem_of(n) for n, _ in candidates})
                candidates = [(n, sz) for n, sz in candidates if chat_uploads.stem_of(n) not in used]
            if candidates:
                scan = await asyncio.to_thread(chat_uploads.scan_text_sync, self.db_path, decrypt_message_strict)
                candidates = [(n, sz) for n, sz in candidates if chat_uploads.stem_of(n) not in scan.stems]
            if candidates:
                # The last check, covering rows written since the scan, and (when
                # deletion is on) the unlinks, together under the write lock.
                free, files, size = await asyncio.to_thread(
                    chat_uploads.finalize_sync, self.db_path, self.chat_upload_dir, [n for n, _ in candidates],
                    decrypt_message_strict, scan, bool(delete), chat_uploads.cutoff())
                candidates = [(n, sizes[n]) for n in free]
                report["deleted"], report["deleted_bytes"] = files, size
        except chat_uploads.Undecryptable as e:
            report["skipped"] = "a message could not be decrypted, so its links are unknown"
            logger.warning(f"[Retention] Orphan chat upload sweep skipped: {report['skipped']} ({e})")
            return report
        except Exception as e:
            report["skipped"] = f"the reference check could not complete ({type(e).__name__}: {e})"
            logger.warning(f"[Retention] Orphan chat upload sweep skipped: {report['skipped']}")
            return report
        report["orphans"] = len(candidates)
        report["bytes"] = sum(sz for _, sz in candidates)
        report["names"] = [n for n, _ in candidates[:20]]
        if report["orphans"]:
            verb = f"removed {report['deleted']} ({report['deleted_bytes']} bytes)" if delete else "report only, nothing deleted"
            logger.info(
                f"[Retention] Orphan chat uploads: {report['orphans']} file(s), {report['bytes']} bytes "
                f"({verb}); first {len(report['names'])}: {', '.join(report['names'])}")
        else:
            logger.info(f"[Retention] Orphan chat uploads: none ({report['scanned']} file(s) checked, "
                        f"{'report only' if not delete else 'deletion on'})")
        return report

    # =========================================================================
    # Chat Reactions
    # =========================================================================

    async def toggle_reaction(self, message_id: int, user_id: int, emoji: str) -> tuple[bool, int]:
        """Toggle a reaction on a message. Returns (added, new_count)."""
        # Try to insert; if exists, delete instead
        try:
            await self.conn.execute(
                "INSERT INTO chat_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)",
                (message_id, user_id, emoji)
            )
            await self.conn.commit()
            added = True
        except Exception:
            # Already exists — remove it
            await self.conn.execute(
                "DELETE FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                (message_id, user_id, emoji)
            )
            await self.conn.commit()
            added = False
        # Get new count for this emoji on this message
        cursor = await self.conn.execute(
            "SELECT COUNT(*) FROM chat_reactions WHERE message_id = ? AND emoji = ?",
            (message_id, emoji)
        )
        row = await cursor.fetchone()
        count = row[0] if row else 0
        return added, count

    async def get_bulk_reactions(self, message_ids: list[int]) -> dict[int, list[dict]]:
        """Get reactions for multiple messages, grouped by message and emoji."""
        if not message_ids:
            return {}
        placeholders = ",".join("?" * len(message_ids))
        cursor = await self.conn.execute(
            f"SELECT message_id, emoji, user_id FROM chat_reactions WHERE message_id IN ({placeholders}) ORDER BY created_at",
            message_ids
        )
        rows = await cursor.fetchall()
        # Group by message_id -> emoji -> user_ids
        result: dict[int, dict[str, list[int]]] = {}
        for row in rows:
            mid = row["message_id"]
            emoji = row["emoji"]
            uid = row["user_id"]
            if mid not in result:
                result[mid] = {}
            if emoji not in result[mid]:
                result[mid][emoji] = []
            result[mid][emoji].append(uid)
        # Convert to list format
        output = {}
        for mid, emojis in result.items():
            output[mid] = [
                {"emoji": emoji, "count": len(uids), "user_ids": uids}
                for emoji, uids in emojis.items()
            ]
        return output

    # =========================================================================
    # Custom Emotes
    # =========================================================================

    async def get_all_custom_emotes(self) -> list[dict]:
        """Get all custom emotes ordered by category then name."""
        cursor = await self.conn.execute(
            "SELECT id, name, filename, category, uploaded_by, created_at "
            "FROM custom_emotes ORDER BY category, name"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_custom_emote_by_name(self, name: str) -> Optional[dict]:
        """Get a single emote by shortcode name."""
        cursor = await self.conn.execute(
            "SELECT id, name, filename, category, uploaded_by, created_at "
            "FROM custom_emotes WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def create_custom_emote(self, name: str, filename: str, category: str, uploaded_by: int) -> dict:
        """Create a new custom emote."""
        cursor = await self.conn.execute(
            "INSERT INTO custom_emotes (name, filename, category, uploaded_by) VALUES (?, ?, ?, ?)",
            (name, filename, category, uploaded_by)
        )
        await self.conn.commit()
        return {"id": cursor.lastrowid, "name": name, "filename": filename,
                "category": category, "uploaded_by": uploaded_by}

    async def update_custom_emote(self, emote_id: int, name: str = None, category: str = None) -> bool:
        """Update emote name and/or category."""
        fields, values = [], []
        if name is not None:
            fields.append("name = ?")
            values.append(name)
        if category is not None:
            fields.append("category = ?")
            values.append(category)
        if not fields:
            return False
        values.append(emote_id)
        cursor = await self.conn.execute(
            f"UPDATE custom_emotes SET {', '.join(fields)} WHERE id = ?", values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_custom_emote(self, emote_id: int) -> Optional[str]:
        """Delete emote by ID. Returns filename for disk cleanup, or None."""
        cursor = await self.conn.execute(
            "SELECT filename FROM custom_emotes WHERE id = ?", (emote_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        await self.conn.execute("DELETE FROM custom_emotes WHERE id = ?", (emote_id,))
        await self.conn.commit()
        return row["filename"]

    # =========================================================================
    # Stream Relay Destinations
    # =========================================================================

    async def create_relay_destination(self, stream_id: int, platform: str, name: str,
                                       rtmp_url: str, stream_key: str) -> dict:
        """Create a relay destination. rtmp_url and stream_key are encrypted at rest."""
        enc_url = encrypt_config(rtmp_url)
        enc_key = encrypt_config(stream_key)
        cursor = await self.conn.execute(
            """INSERT INTO stream_relay_destinations (stream_id, platform, name, rtmp_url, stream_key)
               VALUES (?, ?, ?, ?, ?)""",
            (stream_id, platform, name, enc_url, enc_key)
        )
        await self.conn.commit()
        return {"id": cursor.lastrowid, "stream_id": stream_id, "platform": platform,
                "name": name, "rtmp_url": rtmp_url, "has_stream_key": True, "enabled": 1}

    async def get_relay_destinations(self, stream_id: int) -> list[dict]:
        """Get all relay destinations for a stream (decrypted, key redacted)."""
        cursor = await self.conn.execute(
            """SELECT id, stream_id, platform, name, rtmp_url, stream_key, enabled,
                      last_error, last_error_at, created_at, updated_at
               FROM stream_relay_destinations WHERE stream_id = ? ORDER BY created_at""",
            (stream_id,)
        )
        results = []
        for row in await cursor.fetchall():
            d = dict(row)
            d["rtmp_url"] = decrypt_config(d["rtmp_url"])
            d["has_stream_key"] = bool(d.get("stream_key"))
            del d["stream_key"]
            # Decrypt last_error if present (may contain partial credential data)
            if d.get("last_error"):
                d["last_error"] = decrypt_config(d["last_error"])
            results.append(d)
        return results

    async def update_relay_last_error(self, relay_id: int, error: Optional[str]) -> None:
        """Persist the sanitized last ffmpeg error for a relay destination."""
        from datetime import datetime, timezone as _tz
        enc_error = encrypt_config(error) if error else None
        now = datetime.now(_tz.utc).isoformat()
        await self.conn.execute(
            """UPDATE stream_relay_destinations
               SET last_error = ?, last_error_at = ?, updated_at = ?
               WHERE id = ?""",
            (enc_error, now if enc_error else None, now, relay_id)
        )
        await self.conn.commit()

    async def get_relay_destination(self, relay_id: int) -> Optional[dict]:
        """Get a single relay destination by ID (decrypted, including stream_key)."""
        cursor = await self.conn.execute(
            """SELECT id, stream_id, platform, name, rtmp_url, stream_key, enabled,
                      created_at, updated_at
               FROM stream_relay_destinations WHERE id = ?""",
            (relay_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["rtmp_url"] = decrypt_config(d["rtmp_url"])
        d["stream_key"] = decrypt_config(d["stream_key"])
        return d

    async def get_enabled_relay_destinations(self, stream_id: int) -> list[dict]:
        """Get enabled relay destinations for a stream (decrypted, including stream_key)."""
        cursor = await self.conn.execute(
            """SELECT id, stream_id, platform, name, rtmp_url, stream_key, enabled,
                      created_at, updated_at
               FROM stream_relay_destinations WHERE stream_id = ? AND enabled = 1
               ORDER BY created_at""",
            (stream_id,)
        )
        results = []
        for row in await cursor.fetchall():
            d = dict(row)
            d["rtmp_url"] = decrypt_config(d["rtmp_url"])
            d["stream_key"] = decrypt_config(d["stream_key"])
            results.append(d)
        return results

    async def update_relay_destination(self, relay_id: int, **kwargs) -> bool:
        """Update a relay destination. Encrypts rtmp_url and stream_key if provided."""
        allowed = {"platform", "name", "rtmp_url", "stream_key", "enabled"}
        fields, values = [], []
        for key, val in kwargs.items():
            if key not in allowed or val is None:
                continue
            if key in ("rtmp_url", "stream_key"):
                val = encrypt_config(val)
            fields.append(f"{key} = ?")
            values.append(val)
        if not fields:
            return False
        fields.append("updated_at = CURRENT_TIMESTAMP")
        values.append(relay_id)
        cursor = await self.conn.execute(
            f"UPDATE stream_relay_destinations SET {', '.join(fields)} WHERE id = ?", values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_relay_destination(self, relay_id: int) -> bool:
        """Delete a relay destination by ID."""
        cursor = await self.conn.execute(
            "DELETE FROM stream_relay_destinations WHERE id = ?", (relay_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # =========================================================================
    # Message Editing
    # =========================================================================

    @staticmethod
    def chat_message_editable(msg: Optional[dict], user_id: int, max_age_seconds: int = 300) -> bool:
        """True if msg is the user's own and still inside the edit window."""
        if not msg or msg["user_id"] != user_id:
            return False
        if msg.get("message_type") == "stream_card":
            return False        # a go-live card is a system post: its author may not reword it
        created = datetime.fromisoformat(msg["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).total_seconds() <= max_age_seconds

    async def edit_chat_message(self, message_id: int, user_id: int, new_message: str, max_age_seconds: int = 300) -> Optional[dict]:
        """Edit a chat message within time window. Returns updated message or None."""
        msg = await self.get_chat_message(message_id)
        if not self.chat_message_editable(msg, user_id, max_age_seconds):
            return None
        now = datetime.now(timezone.utc)
        encrypted = encrypt_message(new_message)
        edited_at = now.isoformat()
        await self.conn.execute(
            "UPDATE chat_messages SET message = ?, edited_at = ? WHERE id = ? AND user_id = ?",
            (encrypted, edited_at, message_id, user_id)
        )
        await self.conn.commit()
        # Update FTS index
        await self.update_search_index(message_id, new_message, "channel")
        msg["message"] = new_message
        msg["edited_at"] = edited_at
        return msg

    # =========================================================================
    # Pinned Messages
    # =========================================================================

    async def pin_message(self, message_id: int, pinned_by: int) -> bool:
        """Pin a chat message."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "UPDATE chat_messages SET is_pinned = 1, pinned_by = ?, pinned_at = ? WHERE id = ?",
            (pinned_by, now, message_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def unpin_message(self, message_id: int) -> bool:
        """Unpin a chat message."""
        cursor = await self.conn.execute(
            "UPDATE chat_messages SET is_pinned = 0, pinned_by = NULL, pinned_at = NULL WHERE id = ?",
            (message_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_pinned_messages(self, channel_id: int) -> list[dict]:
        """Get all pinned messages in a channel."""
        cursor = await self.conn.execute(
            """SELECT cm.*, u.nickname as author_nickname, u.role as author_role,
                      p.username as pinned_by_username
               FROM chat_messages cm
               LEFT JOIN users u ON cm.user_id = u.id
               LEFT JOIN users p ON cm.pinned_by = p.id
               WHERE cm.channel_id = ? AND cm.is_pinned = 1
               ORDER BY cm.pinned_at DESC""",
            (channel_id,)
        )
        rows = await cursor.fetchall()
        messages = []
        for row in rows:
            msg = dict(row)
            msg["message"] = decrypt_message(msg.get("message", ""))
            if msg.get("reply_preview_text"):
                msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
            messages.append(msg)
        return messages

    # =========================================================================
    # Unread Tracking
    # =========================================================================

    async def update_read_position(self, user_id: int, channel_id: int, message_id: int) -> None:
        """Update the last read message position for a user in a channel."""
        await self.conn.execute(
            """INSERT INTO channel_read_positions (user_id, channel_id, last_read_message_id, updated_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(user_id, channel_id) DO UPDATE
               SET last_read_message_id = MAX(last_read_message_id, excluded.last_read_message_id),
                   updated_at = CURRENT_TIMESTAMP""",
            (user_id, channel_id, message_id)
        )
        await self.conn.commit()

    async def get_unread_counts(self, user_id: int) -> dict[int, int]:
        """Get unread message counts per channel for a user.

        Only counts channels the user can access (public + private where member).
        """
        cursor = await self.conn.execute(
            """SELECT c.id, COUNT(m.id) as unread
               FROM chat_channels c
               LEFT JOIN channel_read_positions rp ON rp.channel_id = c.id AND rp.user_id = ?
               INNER JOIN chat_messages m ON m.channel_id = c.id AND m.id > COALESCE(rp.last_read_message_id, 0)
               WHERE c.visibility = 'public' OR c.visibility IS NULL
                  OR c.id IN (SELECT channel_id FROM channel_members WHERE user_id = ?)
               GROUP BY c.id
               HAVING unread > 0""",
            (user_id, user_id)
        )
        rows = await cursor.fetchall()
        return {row["id"]: row["unread"] for row in rows}

    # =========================================================================
    # Reply Chain (Threads)
    # =========================================================================

    async def get_reply_chain(self, message_id: int, max_depth: int = 20) -> list[dict]:
        """Get the full reply chain for a message (walking reply_to backwards)."""
        chain = []
        current_id = message_id
        seen = set()
        while current_id and len(chain) < max_depth and current_id not in seen:
            seen.add(current_id)
            msg = await self.get_chat_message(current_id)
            if not msg:
                break
            chain.append(msg)
            current_id = msg.get("reply_to")
        chain.reverse()
        return chain

    # =========================================================================
    # Managed Services
    # =========================================================================

    async def create_managed_service(
        self,
        name: str,
        service_type: str,
        display_name: str = None,
        description: str = None,
        config: dict = None,
        port: int = None,
        binary_path: str = None,
        icon: str = "server"
    ) -> int:
        """Create a new managed service."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO managed_services
               (name, type, display_name, description, config, port, binary_path, icon, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, service_type, display_name or name, description,
             json.dumps(config or {}), port, binary_path, icon, now, now)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_managed_service(self, service_id: int) -> Optional[dict]:
        """Get a managed service by ID."""
        cursor = await self.conn.execute(
            "SELECT * FROM managed_services WHERE id = ?",
            (service_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_managed_service_by_name(self, name: str) -> Optional[dict]:
        """Get a managed service by name."""
        cursor = await self.conn.execute(
            "SELECT * FROM managed_services WHERE name = ?",
            (name,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_managed_service_by_type(self, service_type: str) -> Optional[dict]:
        """Get first managed service of a given type."""
        cursor = await self.conn.execute(
            "SELECT * FROM managed_services WHERE type = ? LIMIT 1",
            (service_type,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_all_managed_services(self) -> list[dict]:
        """Get all managed services."""
        cursor = await self.conn.execute(
            "SELECT * FROM managed_services ORDER BY name"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_enabled_managed_services(self) -> list[dict]:
        """Get all enabled managed services."""
        cursor = await self.conn.execute(
            "SELECT * FROM managed_services WHERE enabled = 1 ORDER BY name"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_managed_service(self, service_id: int, **updates) -> bool:
        """Update a managed service."""
        import json
        allowed_fields = {
            "name", "description", "command", "working_dir", "env_vars",
            "config", "ports", "enabled", "auto_start", "health_check_url",
            "icon", "category_id",
        }
        updates = {k: v for k, v in updates.items() if k in allowed_fields}
        if not updates:
            return False

        # Handle JSON fields (encrypt config at rest)
        if 'config' in updates and isinstance(updates['config'], dict):
            updates['config'] = encrypt_config(json.dumps(updates['config']))
        if 'ports' in updates and isinstance(updates['ports'], list):
            updates['ports'] = json.dumps(updates['ports'])

        updates['updated_at'] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [service_id]

        cursor = await self.conn.execute(
            f"UPDATE managed_services SET {set_clause} WHERE id = ?",
            values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_service_status(
        self,
        service_id: int,
        status: str,
        pid: int = None,
        error_message: str = None
    ) -> bool:
        """Update service status and optional PID/error."""
        now = datetime.now(timezone.utc).isoformat()
        updates = {
            'status': status,
            'pid': pid,
            'updated_at': now
        }

        if status == 'running':
            updates['last_started_at'] = now
            updates['error_message'] = None
        elif status == 'stopped':
            updates['last_stopped_at'] = now
            updates['pid'] = None
        elif status == 'error':
            updates['error_message'] = error_message
            updates['pid'] = None

        return await self.update_managed_service(service_id, **updates)

    async def update_service_health(
        self,
        service_id: int,
        health_status: str
    ) -> bool:
        """Update service health status."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """UPDATE managed_services
               SET health_status = ?, last_health_check = ?, updated_at = ?
               WHERE id = ?""",
            (health_status, now, now, service_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def increment_service_restart_count(self, service_id: int) -> bool:
        """Increment the restart count for a service."""
        cursor = await self.conn.execute(
            """UPDATE managed_services
               SET restart_count = restart_count + 1, updated_at = ?
               WHERE id = ?""",
            (datetime.now(timezone.utc).isoformat(), service_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_managed_service(self, service_id: int) -> bool:
        """Delete a managed service."""
        cursor = await self.conn.execute(
            "DELETE FROM managed_services WHERE id = ?",
            (service_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Service logs

    async def add_service_log(
        self,
        service_id: int,
        message: str,
        level: str = "info"
    ) -> int:
        """Add a log entry for a service."""
        cursor = await self.conn.execute(
            """INSERT INTO service_logs (service_id, level, message, timestamp)
               VALUES (?, ?, ?, ?)""",
            (service_id, level, message, datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_service_logs(
        self,
        service_id: int,
        limit: int = 100,
        level: str = None
    ) -> list[dict]:
        """Get logs for a service."""
        if level:
            cursor = await self.conn.execute(
                """SELECT * FROM service_logs
                   WHERE service_id = ? AND level = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (service_id, level, limit)
            )
        else:
            cursor = await self.conn.execute(
                """SELECT * FROM service_logs
                   WHERE service_id = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (service_id, limit)
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def clear_service_logs(self, service_id: int, keep_recent: int = 1000) -> int:
        """Clear old logs for a service, keeping the most recent entries."""
        # Get the ID threshold
        cursor = await self.conn.execute(
            """SELECT id FROM service_logs
               WHERE service_id = ?
               ORDER BY id DESC LIMIT 1 OFFSET ?""",
            (service_id, keep_recent)
        )
        row = await cursor.fetchone()
        if not row:
            return 0

        threshold_id = row[0]
        cursor = await self.conn.execute(
            "DELETE FROM service_logs WHERE service_id = ? AND id <= ?",
            (service_id, threshold_id)
        )
        await self.conn.commit()
        return cursor.rowcount

    # Activity log operations
    async def log_activity(self, user_id: int, username: str, action: str,
                           detail: str = None, ip_address: str = None) -> None:
        """Log a user activity event. Deduplicates within 5 minutes and auto-prunes to 50 entries."""
        # Skip if identical event (same user + action + detail) happened within 5 minutes
        cursor = await self.conn.execute(
            """SELECT id FROM activity_log
               WHERE user_id = ? AND action = ? AND detail = ?
               AND created_at > datetime('now', '-5 minutes')
               LIMIT 1""",
            (user_id, action, detail)
        )
        if await cursor.fetchone():
            return
        await self.conn.execute(
            """INSERT INTO activity_log (user_id, username, action, detail, ip_address)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, username, action, detail, ip_address)
        )
        # Prune old entries beyond 50
        await self.conn.execute(
            """DELETE FROM activity_log WHERE id NOT IN (
                SELECT id FROM activity_log ORDER BY created_at DESC LIMIT 50
            )"""
        )
        await self.conn.commit()

    # IP blocking (app-wide, enforced in the security middleware)

    async def block_ip(self, ip_address: str, reason: str = None,
                        blocked_by: int = None, expires_at: str = None,
                        source: str = "manual", kind: str = None) -> bool:
        """Block an IP address. Returns True when a row was written.

        A manual block (an admin's own action) overwrites an existing row for
        the same IP, as before. An automatic block (source='auto') is
        cautious: it never overwrites or shortens a manual block, never
        shortens an automatic one and never turns a permanent block into a
        timed one. It only replaces a row whose own expiry has passed, or
        extends an automatic timed block. It returns False when it left the
        existing row as it was.

        `kind` says what an automatic block was for ('login' or 'probe'); a
        manual block always clears it.
        """
        if source not in ("manual", "auto"):
            raise ValueError("source must be 'manual' or 'auto'")
        if kind not in (None, "login", "probe"):
            raise ValueError("kind must be 'login' or 'probe'")
        ip_address = ipguard.canonical_ip(ip_address) or ip_address
        if source == "manual":
            cursor = await self.conn.execute(
                """INSERT INTO blocked_ips (ip_address, reason, blocked_by, expires_at, source)
                   VALUES (?, ?, ?, ?, 'manual')
                   ON CONFLICT(ip_address) DO UPDATE SET
                       reason = excluded.reason,
                       blocked_by = excluded.blocked_by,
                       created_at = CURRENT_TIMESTAMP,
                       expires_at = excluded.expires_at,
                       source = 'manual',
                       kind = NULL""",
                (ip_address, reason, blocked_by, expires_at)
            )
        else:
            cursor = await self.conn.execute(
                """INSERT INTO blocked_ips (ip_address, reason, blocked_by, expires_at, source, kind)
                   VALUES (?, ?, NULL, ?, 'auto', ?)
                   ON CONFLICT(ip_address) DO UPDATE SET
                       reason = excluded.reason,
                       blocked_by = NULL,
                       created_at = CURRENT_TIMESTAMP,
                       expires_at = excluded.expires_at,
                       source = 'auto',
                       kind = excluded.kind
                   WHERE (blocked_ips.expires_at IS NOT NULL
                          AND blocked_ips.expires_at <= datetime('now'))
                      OR (blocked_ips.source = 'auto'
                          AND blocked_ips.expires_at IS NOT NULL
                          AND (excluded.expires_at IS NULL
                               OR excluded.expires_at > blocked_ips.expires_at))""",
                (ip_address, reason, expires_at, kind)
            )
        await self.conn.commit()
        return cursor.rowcount > 0

    # Escalating automatic bans (failed sign-ins and scanner probes)

    BAN_REPEAT_DAYS = 7

    async def record_ban_offence(self, ip_address: str, kind: str) -> int:
        """Count one more automatic ban of this address for this kind and return the
        number of offences within the last BAN_REPEAT_DAYS days, this one included (1 for
        a first offence). The count restarts at 1 when the last offence is older."""
        ip_address = ipguard.canonical_ip(ip_address) or ip_address
        cursor = await self.conn.execute(
            "SELECT offences, last_ban_at FROM ip_ban_history WHERE ip_address = ? AND kind = ?",
            (ip_address, kind))
        row = await cursor.fetchone()
        cursor = await self.conn.execute(
            "SELECT datetime('now'), datetime('now', ?)", (f"-{self.BAN_REPEAT_DAYS} days",))
        now, cutoff = await cursor.fetchone()
        if row and row["last_ban_at"] > cutoff:
            offences = int(row["offences"]) + 1
        else:
            offences = 1
        await self.conn.execute(
            """INSERT INTO ip_ban_history (ip_address, kind, offences, last_ban_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(ip_address, kind) DO UPDATE SET
                   offences = excluded.offences, last_ban_at = excluded.last_ban_at""",
            (ip_address, kind, offences, now))
        await self.conn.commit()
        return offences

    async def forget_ban_history(self, ip_address: str) -> None:
        """Drop the escalation history of an address (an administrator lifted its ban)."""
        ip_address = ipguard.canonical_ip(ip_address) or ip_address
        await self.conn.execute("DELETE FROM ip_ban_history WHERE ip_address = ?", (ip_address,))
        await self.conn.commit()

    async def sweep_auto_bans(self) -> int:
        """Delete expired automatic ban rows, escalation history older than BAN_REPEAT_DAYS and
        sign-in addresses older than LOGIN_ADDRESS_DAYS. Manual rows are never touched.
        Returns the number of block rows deleted."""
        cursor = await self.conn.execute(
            """DELETE FROM blocked_ips
               WHERE source = 'auto' AND kind IN ('login', 'probe')
                 AND expires_at IS NOT NULL AND expires_at <= datetime('now')""")
        removed = cursor.rowcount
        await self.conn.execute(
            "DELETE FROM ip_ban_history WHERE last_ban_at <= datetime('now', ?)",
            (f"-{self.BAN_REPEAT_DAYS} days",))
        # Sign-in addresses older than the household window: an account that never signs in
        # again would otherwise keep its rows.
        await self.conn.execute(
            "DELETE FROM login_addresses WHERE last_login_at < datetime('now', ?)",
            (f"-{self.LOGIN_ADDRESS_DAYS} days",))
        await self.conn.commit()
        return removed

    async def remove_auto_bans_in(self, nets) -> list:
        """Delete automatic (login and probe) block rows for addresses inside `nets` and
        return their canonical addresses (for the in-memory cache)."""
        cursor = await self.conn.execute(
            "SELECT id, ip_address FROM blocked_ips WHERE source = 'auto' AND kind IN ('login', 'probe')")
        hit = []
        for r in await cursor.fetchall():
            canon = ipguard.canonical_ip(r["ip_address"])
            try:
                addr = ipaddress.ip_address(canon) if canon else None
            except ValueError:
                addr = None
            if addr is not None and ipguard.addr_in_networks(addr, nets):
                hit.append((r["id"], canon))
        if hit:
            await self.conn.executemany("DELETE FROM blocked_ips WHERE id = ?", [(i,) for i, _ in hit])
            await self.conn.commit()
        return [c for _, c in hit]

    # Addresses a user signed in from

    LOGIN_ADDRESS_DAYS = 30
    LOGIN_ADDRESS_MAX_PER_USER = 50

    async def record_login_address(self, user_id: int, ip_address: str) -> None:
        """Note a successful sign-in from this address (kept per user, newest 50)."""
        canon = ipguard.canonical_ip(ip_address)
        if canon is None or not user_id:
            return
        await self.conn.execute(
            """INSERT INTO login_addresses (user_id, ip_address, last_login_at)
               VALUES (?, ?, datetime('now'))
               ON CONFLICT(user_id, ip_address) DO UPDATE SET last_login_at = excluded.last_login_at""",
            (user_id, canon))
        await self.conn.execute(
            """DELETE FROM login_addresses WHERE user_id = ? AND ip_address NOT IN (
                   SELECT ip_address FROM login_addresses WHERE user_id = ?
                   ORDER BY last_login_at DESC LIMIT ?)""",
            (user_id, user_id, self.LOGIN_ADDRESS_MAX_PER_USER))
        await self.conn.execute(
            "DELETE FROM login_addresses WHERE user_id = ? AND last_login_at < datetime('now', ?)",
            (user_id, f"-{self.LOGIN_ADDRESS_DAYS} days"))
        await self.conn.commit()

    async def has_recent_login_from(self, user_id: int, ip_address: str) -> bool:
        """True when this user signed in from this address within LOGIN_ADDRESS_DAYS days.

        Reads login_addresses and, for sessions that began before that table existed, the
        creation address of the user's tokens."""
        canon = ipguard.canonical_ip(ip_address)
        if canon is None or not user_id:
            return False
        window = f"-{self.LOGIN_ADDRESS_DAYS} days"
        cursor = await self.conn.execute(
            """SELECT 1 FROM login_addresses
               WHERE user_id = ? AND ip_address = ? AND last_login_at >= datetime('now', ?)""",
            (user_id, canon, window))
        if await cursor.fetchone():
            return True
        cursor = await self.conn.execute(
            "SELECT ip FROM tokens WHERE user_id = ? AND created_at >= datetime('now', ?) AND ip IS NOT NULL",
            (user_id, window))
        return any(ipguard.canonical_ip(r["ip"]) == canon for r in await cursor.fetchall())

    async def unblock_ip(self, ip_address: str) -> bool:
        """Remove an IP block. The address is matched in its canonical form
        (a row written before addresses were canonicalised is matched as typed)."""
        canon = ipguard.canonical_ip(ip_address) or ip_address
        cursor = await self.conn.execute("SELECT id, ip_address FROM blocked_ips")
        ids = [(r["id"],) for r in await cursor.fetchall()
               if (ipguard.canonical_ip(r["ip_address"]) or r["ip_address"]) == canon
               or r["ip_address"] == ip_address]
        if ids:
            await self.conn.executemany("DELETE FROM blocked_ips WHERE id = ?", ids)
        await self.conn.commit()
        return bool(ids)

    async def list_blocked_ips(self) -> list[dict]:
        """List all blocked IPs (including expired ones — caller filters)."""
        cursor = await self.conn.execute(
            """SELECT b.id, b.ip_address, b.reason, b.blocked_by, b.created_at, b.expires_at, b.source,
                      COALESCE(b.kind, CASE WHEN b.source = 'manual' THEN 'manual' ELSE 'auto' END) AS kind,
                      u.username AS blocked_by_username
               FROM blocked_ips b
               LEFT JOIN users u ON u.id = b.blocked_by
               ORDER BY b.created_at DESC"""
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_active_blocked_ips(self) -> dict[str, Optional[str]]:
        """Get a {ip: expires_at} map of currently-active blocks (expired ones excluded).

        Loaded once at startup and kept in sync in-process on block/unblock —
        this is what the request-path middleware check runs against, so it
        never touches the database per-request.
        """
        cursor = await self.conn.execute(
            """SELECT ip_address, expires_at FROM blocked_ips
               WHERE expires_at IS NULL OR expires_at > datetime('now')"""
        )
        rows = await cursor.fetchall()
        blocks: dict[str, Optional[str]] = {}
        for row in rows:
            key = ipguard.canonical_ip(row["ip_address"]) or row["ip_address"]
            # Two spellings of one address (not merged yet): the longer block wins.
            if key in blocks and blocks[key] is None:
                continue
            if key not in blocks or row["expires_at"] is None or row["expires_at"] > (blocks[key] or ""):
                blocks[key] = row["expires_at"]
        return blocks

    # Activity types visible to all authenticated users (community events)
    PUBLIC_ACTIVITY_TYPES = {"stream_live", "stream_offline", "register"}

    async def get_recent_activity(self, limit: int = 20, offset: int = 0,
                                   user_id: int = None) -> list[dict]:
        """Get recent activity entries.

        Admins (user_id=None): see everything.
        Regular users: see their own activity + public community events.
        """
        if user_id:
            placeholders = ",".join("?" for _ in self.PUBLIC_ACTIVITY_TYPES)
            # Another member's stream_live / stream_offline row is left out while that owner has
            # a non-public stream of that name (the row carries no stream id, only the name in
            # its text). Decided at read time, so rows stored before the fix and streams made
            # private later are covered too; a public stream sharing the name goes with it.
            cursor = await self.conn.execute(
                f"""SELECT * FROM activity_log
                    WHERE (user_id = ? OR (action IN ({placeholders})
                       AND NOT (action IN ('stream_live', 'stream_offline') AND EXISTS (
                            SELECT 1 FROM user_streams us
                            WHERE us.user_id = activity_log.user_id
                              AND COALESCE(us.is_public, 0) = 0
                              AND instr(activity_log.detail, 'Stream ''' || us.name || ''' went ') = 1))))
                    ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (user_id, *self.PUBLIC_ACTIVITY_TYPES, limit, offset)
            )
        else:
            cursor = await self.conn.execute(
                "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # Notification operations

    async def create_notification(self, user_id: int, type: str, title: str,
                                   message: str = "", data: dict = None) -> int:
        """Create a notification for a user. Returns notification ID."""
        enc_title = encrypt_message(title) if title else title
        enc_message = encrypt_message(message) if message else message
        cursor = await self.conn.execute(
            """INSERT INTO notifications (user_id, type, title, message, data)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, type, enc_title, enc_message, json.dumps(data or {}))
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_notifications(self, user_id: int, unread_only: bool = False,
                                 limit: int = 50, offset: int = 0) -> list[dict]:
        """Get notifications for a user."""
        query = "SELECT * FROM notifications WHERE user_id = ?"
        params = [user_id]
        if unread_only:
            query += " AND is_read = 0"
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self.conn.execute(query, params)
        notifications = []
        for row in await cursor.fetchall():
            n = dict(row)
            if n.get("title"):
                n["title"] = decrypt_message(n["title"])
            if n.get("message"):
                n["message"] = decrypt_message(n["message"])
            notifications.append(n)
        return notifications

    async def get_unread_notification_count(self, user_id: int) -> int:
        """Get count of unread notifications."""
        cursor = await self.conn.execute(
            "SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0",
            (user_id,)
        )
        row = await cursor.fetchone()
        return row["count"] if row else 0

    async def mark_notification_read(self, notification_id: int, user_id: int) -> bool:
        """Mark a single notification as read."""
        cursor = await self.conn.execute(
            "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
            (notification_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def mark_all_notifications_read(self, user_id: int) -> int:
        """Mark all notifications as read for a user. Returns count updated."""
        cursor = await self.conn.execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0",
            (user_id,)
        )
        await self.conn.commit()
        return cursor.rowcount

    # =========================================================================
    # Direct Messages — Conversations
    # =========================================================================

    async def find_dm_conversation(self, user_id_a: int, user_id_b: int) -> Optional[dict]:
        """Find an existing 1:1 DM conversation between two users."""
        if user_id_a == user_id_b:
            return None  # Self-DM not supported
        cursor = await self.conn.execute(
            """SELECT dc.* FROM dm_conversations dc
               JOIN dm_participants dp1 ON dp1.conversation_id = dc.id AND dp1.user_id = ? AND dp1.left_at IS NULL
               JOIN dm_participants dp2 ON dp2.conversation_id = dc.id AND dp2.user_id = ? AND dp2.left_at IS NULL
               WHERE dc.type = '1on1'
               LIMIT 1""",
            (user_id_a, user_id_b)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def create_dm_conversation(
        self, creator_id: int, participant_ids: list[int],
        name: str = None, conv_type: str = "1on1"
    ) -> dict:
        """Create a DM conversation. For 1:1, returns existing if found."""
        if conv_type == "1on1" and len(participant_ids) == 1:
            existing = await self.find_dm_conversation(creator_id, participant_ids[0])
            if existing:
                existing["participants"] = await self._get_dm_participants(existing["id"])
                return existing
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "INSERT INTO dm_conversations (type, name, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (conv_type, name, creator_id, now, now)
        )
        conv_id = cursor.lastrowid
        all_ids = set(participant_ids) | {creator_id}
        for uid in all_ids:
            await self.conn.execute(
                "INSERT INTO dm_participants (conversation_id, user_id, joined_at) VALUES (?, ?, ?)",
                (conv_id, uid, now)
            )
        await self.conn.commit()
        conv = {"id": conv_id, "type": conv_type, "name": name, "created_by": creator_id,
                "created_at": now, "updated_at": now}
        conv["participants"] = await self._get_dm_participants(conv_id)
        return conv

    async def _get_dm_participants(self, conversation_id: int) -> list[dict]:
        """Get active participants with user info."""
        cursor = await self.conn.execute(
            """SELECT dp.user_id, dp.joined_at, dp.muted, u.username, u.nickname,
                      u.avatar, u.role, u.status, u.status_message
               FROM dm_participants dp
               JOIN users u ON u.id = dp.user_id
               WHERE dp.conversation_id = ? AND dp.left_at IS NULL""",
            (conversation_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_dm_participant_ids(self, conversation_id: int) -> list[int]:
        """Get active participant user IDs for a conversation."""
        cursor = await self.conn.execute(
            "SELECT user_id FROM dm_participants WHERE conversation_id = ? AND left_at IS NULL",
            (conversation_id,)
        )
        rows = await cursor.fetchall()
        return [r["user_id"] for r in rows]

    async def get_dm_conversations(self, user_id: int, limit: int = 50, offset: int = 0) -> list[dict]:
        """Get all DM conversations for a user with last message and unread counts."""
        cursor = await self.conn.execute(
            """SELECT dc.*, dm_last.id as last_msg_id, dm_last.message as last_msg,
                      dm_last.username as last_msg_user, dm_last.created_at as last_msg_at
               FROM dm_conversations dc
               JOIN dm_participants dp ON dp.conversation_id = dc.id AND dp.user_id = ? AND dp.left_at IS NULL
               LEFT JOIN dm_messages dm_last ON dm_last.id = (
                   SELECT MAX(id) FROM dm_messages WHERE conversation_id = dc.id
               )
               ORDER BY dc.updated_at DESC
               LIMIT ? OFFSET ?""",
            (user_id, limit, offset)
        )
        rows = await cursor.fetchall()
        unread = await self.get_dm_unread_counts(user_id)
        conv_ids = [row["id"] for row in rows]
        # Batch fetch all participants for returned conversations (avoids N+1)
        participants_map: dict[int, list[dict]] = {cid: [] for cid in conv_ids}
        if conv_ids:
            placeholders = ",".join("?" * len(conv_ids))
            pcursor = await self.conn.execute(
                f"""SELECT dp.conversation_id, dp.user_id, dp.joined_at, dp.muted,
                           u.username, u.nickname, u.avatar, u.role, u.status, u.status_message
                    FROM dm_participants dp
                    JOIN users u ON u.id = dp.user_id
                    WHERE dp.conversation_id IN ({placeholders}) AND dp.left_at IS NULL""",
                conv_ids
            )
            for prow in await pcursor.fetchall():
                participants_map[prow["conversation_id"]].append(dict(prow))
        convs = []
        for row in rows:
            conv = dict(row)
            conv["participants"] = participants_map.get(conv["id"], [])
            if conv.get("last_msg"):
                conv["last_msg"] = decrypt_message(conv["last_msg"])
                if len(conv["last_msg"]) > 100:
                    conv["last_msg"] = conv["last_msg"][:100] + "..."
            conv["unread_count"] = unread.get(conv["id"], 0)
            convs.append(conv)
        return convs

    async def get_dm_conversation(self, conversation_id: int) -> Optional[dict]:
        """Get a single DM conversation with participants."""
        cursor = await self.conn.execute(
            "SELECT * FROM dm_conversations WHERE id = ?", (conversation_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        conv = dict(row)
        conv["participants"] = await self._get_dm_participants(conversation_id)
        return conv

    async def is_dm_participant(self, conversation_id: int, user_id: int) -> bool:
        """Check if a user is an active participant in a DM conversation."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM dm_participants WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
            (conversation_id, user_id)
        )
        return await cursor.fetchone() is not None

    async def leave_dm_conversation(self, conversation_id: int, user_id: int) -> bool:
        """Leave a group DM (sets left_at timestamp)."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """UPDATE dm_participants SET left_at = ?
               WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL""",
            (now, conversation_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_dm_mute(self, conversation_id: int, user_id: int, muted: bool) -> bool:
        """Toggle mute for a DM conversation participant."""
        cursor = await self.conn.execute(
            "UPDATE dm_participants SET muted = ? WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL",
            (int(muted), conversation_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def add_dm_participants(self, conversation_id: int, user_ids: list[int]) -> list[int]:
        """Add participants to a group DM. Max 10 enforced. Returns added user IDs."""
        current = await self.get_dm_participant_ids(conversation_id)
        if len(current) + len(user_ids) > 10:
            return []
        now = datetime.now(timezone.utc).isoformat()
        added = []
        for uid in user_ids:
            if uid not in current:
                try:
                    await self.conn.execute(
                        """INSERT INTO dm_participants (conversation_id, user_id, joined_at)
                           VALUES (?, ?, ?)
                           ON CONFLICT(conversation_id, user_id)
                           DO UPDATE SET left_at = NULL, joined_at = excluded.joined_at""",
                        (conversation_id, uid, now)
                    )
                    added.append(uid)
                except Exception:
                    pass
        if added:
            await self.conn.commit()
        return added

    # =========================================================================
    # Direct Messages — Messages
    # =========================================================================

    async def create_dm_message(
        self, conversation_id: int, user_id: int, username: str, message: str,
        reply_to: int = None, image_url: str = None,
        reply_preview_username: str = None, reply_preview_text: str = None,
        attachment_url: str = None, attachment_name: str = None,
        attachment_size: int = None, attachment_type: str = None
    ) -> int:
        """Create a new DM message (encrypted). Returns message_id."""
        plaintext = message
        encrypted_message = encrypt_message(message)
        encrypted_preview = encrypt_message(reply_preview_text) if reply_preview_text else None
        created_at = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO dm_messages (conversation_id, user_id, username, message, created_at,
                                        reply_to, image_url, reply_preview_username, reply_preview_text,
                                        attachment_url, attachment_name, attachment_size, attachment_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (conversation_id, user_id, username, encrypted_message, created_at,
             reply_to, image_url, reply_preview_username, encrypted_preview,
             attachment_url, attachment_name, attachment_size, attachment_type)
        )
        msg_id = cursor.lastrowid
        await self.conn.execute(
            "UPDATE dm_conversations SET updated_at = ? WHERE id = ?",
            (created_at, conversation_id)
        )
        await self.conn.commit()
        # Index for full-text search
        flags = chat_search.message_flags(plaintext, image_url, attachment_url, attachment_type)
        await self.index_message_for_search(
            msg_id, plaintext, "dm", conversation_id, user_id, username,
            flags[0], created_at, has_file=flags[1], has_link=flags[2]
        )
        return msg_id

    async def get_dm_messages(self, conversation_id: int, limit: int = 100, before_id: int = None) -> list[dict]:
        """Get DM messages for a conversation (decrypted)."""
        if before_id:
            cursor = await self.conn.execute(
                """SELECT * FROM dm_messages WHERE conversation_id = ? AND id < ?
                   ORDER BY id DESC LIMIT ?""",
                (conversation_id, before_id, limit)
            )
        else:
            cursor = await self.conn.execute(
                """SELECT * FROM dm_messages WHERE conversation_id = ?
                   ORDER BY id DESC LIMIT ?""",
                (conversation_id, limit)
            )
        rows = await cursor.fetchall()
        messages = []
        for row in reversed(rows):
            msg = dict(row)
            msg["message"] = decrypt_message(msg.get("message", ""))
            if msg.get("reply_preview_text"):
                msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
            messages.append(msg)
        return messages

    async def get_dm_message(self, message_id: int) -> Optional[dict]:
        """Get a single DM message by ID (decrypted)."""
        cursor = await self.conn.execute(
            "SELECT * FROM dm_messages WHERE id = ?", (message_id,)
        )
        row = await cursor.fetchone()
        if row:
            msg = dict(row)
            msg["message"] = decrypt_message(msg.get("message", ""))
            if msg.get("reply_preview_text"):
                msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
            return msg
        return None

    async def edit_dm_message(self, message_id: int, user_id: int, new_message: str, max_age_seconds: int = 300) -> Optional[dict]:
        """Edit a DM message within time window. Returns updated message or None."""
        msg = await self.get_dm_message(message_id)
        if not msg or msg["user_id"] != user_id:
            return None
        created = datetime.fromisoformat(msg["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if (now - created).total_seconds() > max_age_seconds:
            return None
        encrypted = encrypt_message(new_message)
        edited_at = now.isoformat()
        await self.conn.execute(
            "UPDATE dm_messages SET message = ?, edited_at = ? WHERE id = ? AND user_id = ?",
            (encrypted, edited_at, message_id, user_id)
        )
        await self.conn.commit()
        # Update FTS index
        await self.update_search_index(message_id, new_message, "dm")
        msg["message"] = new_message
        msg["edited_at"] = edited_at
        return msg

    async def delete_dm_message(self, message_id: int, user_id: int = None) -> bool:
        """Delete a DM message (optionally verify ownership)."""
        return await self._delete_one_message("dm_messages", "dm", message_id, user_id)

    # =========================================================================
    # Direct Messages — Reactions
    # =========================================================================

    async def toggle_dm_reaction(self, message_id: int, user_id: int, emoji: str) -> tuple[bool, int]:
        """Toggle a reaction on a DM message. Returns (added, new_count)."""
        try:
            await self.conn.execute(
                "INSERT INTO dm_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)",
                (message_id, user_id, emoji)
            )
            await self.conn.commit()
            added = True
        except Exception:
            await self.conn.execute(
                "DELETE FROM dm_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                (message_id, user_id, emoji)
            )
            await self.conn.commit()
            added = False
        cursor = await self.conn.execute(
            "SELECT COUNT(*) FROM dm_reactions WHERE message_id = ? AND emoji = ?",
            (message_id, emoji)
        )
        row = await cursor.fetchone()
        count = row[0] if row else 0
        return added, count

    async def get_bulk_dm_reactions(self, message_ids: list[int]) -> dict[int, list[dict]]:
        """Get reactions for multiple DM messages, grouped by message and emoji."""
        if not message_ids:
            return {}
        placeholders = ",".join("?" * len(message_ids))
        cursor = await self.conn.execute(
            f"SELECT message_id, emoji, user_id FROM dm_reactions WHERE message_id IN ({placeholders}) ORDER BY created_at",
            message_ids
        )
        rows = await cursor.fetchall()
        result: dict[int, dict[str, list[int]]] = {}
        for row in rows:
            mid = row["message_id"]
            emoji = row["emoji"]
            uid = row["user_id"]
            if mid not in result:
                result[mid] = {}
            if emoji not in result[mid]:
                result[mid][emoji] = []
            result[mid][emoji].append(uid)
        output = {}
        for mid, emojis in result.items():
            output[mid] = [
                {"emoji": emoji, "count": len(uids), "user_ids": uids}
                for emoji, uids in emojis.items()
            ]
        return output

    # =========================================================================
    # Direct Messages — Read Tracking
    # =========================================================================

    async def update_dm_read_position(self, user_id: int, conversation_id: int, message_id: int) -> None:
        """Update the last read message position for a user in a DM conversation."""
        await self.conn.execute(
            """INSERT INTO dm_read_positions (user_id, conversation_id, last_read_message_id, updated_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(user_id, conversation_id) DO UPDATE
               SET last_read_message_id = MAX(last_read_message_id, excluded.last_read_message_id),
                   updated_at = CURRENT_TIMESTAMP""",
            (user_id, conversation_id, message_id)
        )
        await self.conn.commit()

    async def get_dm_unread_counts(self, user_id: int) -> dict[int, int]:
        """Get unread DM message counts per conversation for a user."""
        cursor = await self.conn.execute(
            """SELECT dc.id, COUNT(dm.id) as unread
               FROM dm_conversations dc
               JOIN dm_participants dp ON dp.conversation_id = dc.id AND dp.user_id = ? AND dp.left_at IS NULL
               LEFT JOIN dm_read_positions rp ON rp.conversation_id = dc.id AND rp.user_id = ?
               INNER JOIN dm_messages dm ON dm.conversation_id = dc.id AND dm.id > COALESCE(rp.last_read_message_id, 0) AND dm.user_id != ?
               GROUP BY dc.id
               HAVING unread > 0""",
            (user_id, user_id, user_id)
        )
        rows = await cursor.fetchall()
        return {row["id"]: row["unread"] for row in rows}

    # =========================================================================
    # Full-Text Search (FTS5)
    # =========================================================================

    # (source) -> (fts table, map table, id column, message table)
    _SEARCH_TABLES = {
        "channel": ("chat_messages_fts", "chat_fts_map", "channel_id", "chat_messages"),
        "dm": ("dm_messages_fts", "dm_fts_map", "conversation_id", "dm_messages"),
    }
    SEARCH_BACKFILL_DONE = "search_backfill_done"

    async def _write_search_row(
        self, message_id: int, plaintext: str, source: str, source_id: int,
        user_id: int, username: str, has_image: int, created_at: str,
        has_file: int = 0, has_link: int = 0
    ) -> None:
        """Insert one search index row (FTS row and map row) without committing.
        An attachment-only message gets an empty FTS row: it matches no word,
        but it owns the rowid the map row needs and the operators find it."""
        fts_table, map_table, id_col, _ = self._SEARCH_TABLES[source]
        cursor = await self.conn.execute(
            f"INSERT INTO {fts_table}(message) VALUES (?)", (plaintext or "",)
        )
        await self.conn.execute(
            f"""INSERT INTO {map_table} (rowid, message_id, {id_col}, user_id, username,
                                         has_image, has_file, has_link, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cursor.lastrowid, message_id, source_id, user_id, username,
             has_image, has_file, has_link, created_at)
        )

    async def index_message_for_search(
        self, message_id: int, plaintext: str, source: str, source_id: int,
        user_id: int, username: str, has_image: int, created_at: str,
        has_file: int = 0, has_link: int = 0
    ) -> None:
        """Index a message for full-text search. source='channel' or 'dm'.
        A message with no text is indexed when it has an image or a file."""
        if not (plaintext and plaintext.strip()) and not (has_image or has_file):
            return
        try:
            await self._write_search_row(
                message_id, plaintext, source, source_id, user_id, username,
                has_image, created_at, has_file, has_link)
            await self.conn.commit()
        except Exception:
            pass

    async def remove_message_from_search(self, message_id: int, source: str) -> None:
        """Remove a message from the search index.

        For contentless FTS5 tables (content=''), the 'delete' command requires
        the original indexed content. Since we only store encrypted text in the
        message tables, we delete the map entry instead. Orphaned FTS rows are
        harmless — they never appear in results because _search_index JOINs
        through the map table and the message table.
        Periodic rebuild_search_index() cleans up orphans.
        """
        try:
            if source == "channel":
                map_table = "chat_fts_map"
            else:
                map_table = "dm_fts_map"
            await self.conn.execute(
                f"DELETE FROM {map_table} WHERE message_id = ?", (message_id,)
            )
            await self.conn.commit()
        except Exception:
            pass

    async def update_search_index(self, message_id: int, new_plaintext: str, source: str) -> None:
        """Update the search index for an edited message. The flags are worked
        out again from the stored row (its attachments do not change on edit)."""
        await self.remove_message_from_search(message_id, source)
        try:
            _, _, id_col, msg_table = self._SEARCH_TABLES[source]
            cursor = await self.conn.execute(
                f"""SELECT {id_col} AS source_id, user_id, username, image_url, attachment_url,
                           attachment_type, created_at FROM {msg_table} WHERE id = ?""",
                (message_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return
            has_image, has_file, has_link = chat_search.message_flags(
                new_plaintext, row["image_url"], row["attachment_url"], row["attachment_type"])
            if not (new_plaintext and new_plaintext.strip()) and not (has_image or has_file):
                return
            await self._write_search_row(
                message_id, new_plaintext, source, row["source_id"], row["user_id"],
                row["username"], has_image, row["created_at"], has_file, has_link)
            await self.conn.commit()
        except Exception:
            pass

    async def search_messages(
        self, query: str, user_id: int, scope: str = "all",
        channel_id: int = None, conversation_id: int = None,
        from_user: str = None, has_image: bool = None,
        before: str = None, after: str = None,
        limit: int = 25, offset: int = 0,
        user_role: str = "user", *,
        parsed: "chat_search.ParsedSearch" = None,
        channel_ids=None, include_anonymous_authors: bool = False
    ) -> dict:
        """Search messages across channels and/or DMs.

        Returns {results, total, has_more, capped}. `parsed` is the parsed query
        (chat_search.parse_search_query); without it `query` is parsed here
        together with the older from_user / has_image / before / after
        arguments, and a bad query raises chat_search.SearchQueryError.

        `channel_ids` is the set of channels the caller may read; the server
        passes the answer of its read check. Without it the channels visible to
        `user_role` are used (no stream-ban check), which is for callers that
        have no read check of their own. A channel that is not in the set is
        never searched: the set is part of the WHERE clause, so counts and
        has_more can not reveal anything outside it.

        Channel hits carry ids and flags only (no author, no text): the server
        builds the visible message from the row for the viewer, with the same
        masking as history. A positive author filter skips anonymous posts
        unless `include_anonymous_authors` (staff); a negated one never removes
        them for anyone else, so neither can be used to tell who wrote one.
        An operator-only query (no words) is ordered newest first and returns
        at most chat_search.OPERATOR_ONLY_CAP results in total.
        """
        empty = {"results": [], "total": 0, "has_more": False, "capped": False}
        if parsed is None:
            parsed = chat_search.parse_search_query(
                query, from_=from_user, has="image" if has_image else None,
                before=before, after=after)
        if not parsed.phrases and not parsed.has_operators:
            return empty
        op_only = parsed.operator_only
        cap = chat_search.OPERATOR_ONLY_CAP
        if op_only:
            limit = max(0, min(limit, cap - offset))

        search_channels = scope in ("all", "channels")
        search_dms = scope in ("all", "dms") and not parsed.in_channels and not parsed.pinned
        # Nothing to list (an operator-only query past its cap): only the counts
        # are needed, so no rows are fetched however large the offset is.
        fetch = (offset + limit if scope == "all" else limit) if limit > 0 else 0
        fetch_offset = 0 if scope == "all" else offset

        ch_hits, ch_total, dm_hits, dm_total = [], 0, [], 0
        if search_channels:
            if channel_ids is not None:
                accessible = set(channel_ids)
            else:
                # No read check from the caller: the channels visible to the role.
                # If even that lookup fails the search fails closed: no channel is
                # searched, never all of them.
                try:
                    accessible = {c["id"] for c in await self.get_accessible_channels(user_id, user_role)}
                except Exception as e:
                    logger.error(f"Search: the accessible channels could not be looked up, "
                                 f"no channel is searched: {e}")
                    accessible = set()
            if parsed.in_channels or parsed.not_in_channels:
                wanted, unwanted = set(parsed.in_channels), set(parsed.not_in_channels)
                cur = await self.conn.execute("SELECT id, name FROM chat_channels")
                names = {r["id"]: (r["name"] or "").lower() for r in await cur.fetchall()}
                accessible = {cid for cid in accessible
                              if (not wanted or names.get(cid) in wanted) and names.get(cid) not in unwanted}
            ch_hits, ch_total = await self._search_index(
                "channel", parsed, channel_ids=accessible, channel_id=channel_id,
                include_anonymous_authors=include_anonymous_authors,
                limit=fetch, offset=fetch_offset, count_cap=cap if op_only else None,
                newest_first=scope == "all")
        if search_dms:
            dm_hits, dm_total = await self._search_index(
                "dm", parsed, conversation_id=conversation_id, dm_user_id=user_id,
                limit=fetch, offset=fetch_offset, count_cap=cap if op_only else None,
                newest_first=scope == "all")

        raw_total = ch_total + dm_total
        results = ch_hits + dm_hits
        results.sort(key=lambda r: ((r.get("created_at") or "").replace(" ", "T"), r["id"]), reverse=True)
        if scope == "all":
            results = results[offset:offset + limit]
        await self._name_search_hits(results, user_id)
        capped = bool(op_only and raw_total > cap)
        # Each source counts up to cap + 1, so the sum can be past the cap; an
        # operator-only query never lists more than cap results in total.
        listed_total = min(raw_total, cap) if op_only else raw_total
        return {
            "results": results,
            "total": listed_total,
            "has_more": listed_total > offset + len(results),
            "capped": capped,
        }

    async def _search_index(
        self, source: str, parsed: "chat_search.ParsedSearch", *,
        channel_ids=None, channel_id: int = None, conversation_id: int = None,
        dm_user_id: int = None, include_anonymous_authors: bool = False,
        limit: int = 25, offset: int = 0, count_cap: int = None,
        newest_first: bool = False
    ) -> tuple[list[dict], int]:
        """Run one search against the channel or the DM index. Returns
        (hits, count); count stops at count_cap + 1 when a cap is given.

        `newest_first` orders a word search by date, the way search_messages
        merges the channel and DM lists, instead of by relevance. The merged
        scope reads the first offset + limit rows of each source and slices the
        merge, so both must use the same order or a later page is not the
        continuation of the earlier one."""
        fts_table, map_table, id_col, msg_table = self._SEARCH_TABLES[source]
        conds: list = []
        params: list = []
        if parsed.phrases:
            from_sql = (f"FROM {fts_table} JOIN {map_table} m ON m.rowid = {fts_table}.rowid "
                        f"JOIN {msg_table} cm ON cm.id = m.message_id")
            conds.append(f"{fts_table} MATCH ?")
            params.append(parsed.fts_expr)
            order = ("ORDER BY REPLACE(m.created_at, ' ', 'T') DESC, m.message_id DESC"
                     if newest_first else "ORDER BY rank, m.message_id DESC")
        else:
            from_sql = f"FROM {map_table} m JOIN {msg_table} cm ON cm.id = m.message_id"
            order = "ORDER BY m.message_id DESC"

        if source == "channel":
            if not channel_ids:
                return [], 0
            # integers only, so the list can be written into the statement
            conds.append("cm.channel_id IN (%s)" % ",".join(str(int(c)) for c in channel_ids))
            if channel_id:
                conds.append("cm.channel_id = ?")
                params.append(int(channel_id))
            if parsed.pinned:
                conds.append("COALESCE(cm.is_pinned, 0) = 1")
        else:
            if parsed.pinned:
                return [], 0
            conds.append("cm.conversation_id IN (SELECT conversation_id FROM dm_participants "
                         "WHERE user_id = ? AND left_at IS NULL)")
            params.append(dm_user_id)
            if conversation_id:
                conds.append("cm.conversation_id = ?")
                params.append(int(conversation_id))

        # Anonymous channel posts never match an author for someone who may not
        # see who wrote them; DM messages have no anonymous flag.
        hide_anon = " AND COALESCE(cm.anonymous, 0) = 0" if (
            source == "channel" and not include_anonymous_authors) else ""

        def author_in(names):
            ph = ",".join("?" * len(names))
            params.extend(list(names) * 2)
            return ("cm.user_id IN (SELECT id FROM users WHERE username COLLATE NOCASE IN (%s) "
                    "OR nickname COLLATE NOCASE IN (%s))" % (ph, ph))
        if parsed.from_users:
            conds.append("(" + author_in(parsed.from_users) + hide_anon + ")")
        if parsed.not_from_users:
            conds.append("NOT (" + author_in(parsed.not_from_users) + hide_anon + ")")
        for flag in parsed.has:
            conds.append({"image": "m.has_image = 1", "file": "m.has_file = 1", "link": "m.has_link = 1"}[flag])
        if parsed.before:
            conds.append("m.created_at < ?")
            params.append(parsed.before)
        if parsed.after:
            conds.append("m.created_at >= ?")
            params.append(parsed.after)

        where = " AND ".join(conds)
        try:
            if count_cap:
                cursor = await self.conn.execute(
                    f"SELECT COUNT(*) FROM (SELECT 1 {from_sql} WHERE {where} LIMIT {int(count_cap) + 1})", params)
            else:
                cursor = await self.conn.execute(f"SELECT COUNT(*) {from_sql} WHERE {where}", params)
            row = await cursor.fetchone()
            total = row[0] if row else 0
            if total == 0 or limit <= 0:
                return [], total
            pinned_col = ", COALESCE(cm.is_pinned, 0) AS is_pinned" if source == "channel" else ""
            cursor = await self.conn.execute(
                f"""SELECT m.message_id AS id, cm.{id_col} AS source_id, m.created_at,
                           m.has_image, m.has_file, m.has_link{pinned_col}
                    {from_sql} WHERE {where} {order} LIMIT ? OFFSET ?""",
                params + [limit, offset])
            hits = [dict(r) for r in await cursor.fetchall()]
        except Exception as e:
            logger.warning(f"Search failed: {e}")
            return [], 0
        for h in hits:
            h["source"] = source
            h["has_image"], h["has_file"], h["has_link"] = (
                1 if h["has_image"] else 0, 1 if h["has_file"] else 0, 1 if h["has_link"] else 0)
            if source == "channel":
                h["is_pinned"] = 1 if h["is_pinned"] else 0
        return hits, total

    async def _name_search_hits(self, hits: list[dict], user_id: int) -> None:
        """Add source_name to the hits and, for DM hits, the message itself
        (a DM has no anonymous authors, so its fields are as stored)."""
        ch_ids = list({h["source_id"] for h in hits if h["source"] == "channel"})
        ch_names = {}
        if ch_ids:
            ph = ",".join("?" * len(ch_ids))
            cur = await self.conn.execute(f"SELECT id, name FROM chat_channels WHERE id IN ({ph})", ch_ids)
            ch_names = {r["id"]: r["name"] for r in await cur.fetchall()}
        for h in hits:
            if h["source"] == "channel":
                h["source_name"] = f"#{ch_names.get(h['source_id'], 'unknown')}"

        dm_hits = [h for h in hits if h["source"] == "dm"]
        if not dm_hits:
            return
        dm_conv_ids = list({h["source_id"] for h in dm_hits})
        ph = ",".join("?" * len(dm_conv_ids))
        cur = await self.conn.execute(f"SELECT id, name FROM dm_conversations WHERE id IN ({ph})", dm_conv_ids)
        dm_conv_map = {r["id"]: r["name"] for r in await cur.fetchall()}
        pcur = await self.conn.execute(
            f"""SELECT dp.conversation_id, dp.user_id, u.username, u.nickname
                FROM dm_participants dp JOIN users u ON u.id = dp.user_id
                WHERE dp.conversation_id IN ({ph}) AND dp.left_at IS NULL""",
            dm_conv_ids)
        dm_parts: dict[int, list[dict]] = {cid: [] for cid in dm_conv_ids}
        for prow in await pcur.fetchall():
            dm_parts[prow["conversation_id"]].append(dict(prow))
        msg_ids = [h["id"] for h in dm_hits]
        ph2 = ",".join("?" * len(msg_ids))
        mcur = await self.conn.execute(
            f"""SELECT id, user_id, username, message, image_url, attachment_url, attachment_name,
                       attachment_type, attachment_size FROM dm_messages WHERE id IN ({ph2})""", msg_ids)
        msgs = {r["id"]: r for r in await mcur.fetchall()}
        for h in dm_hits:
            cid = h["source_id"]
            name = dm_conv_map.get(cid)
            if not name:
                others = [p["nickname"] or p["username"] for p in dm_parts.get(cid, []) if p["user_id"] != user_id]
                name = ", ".join(others) or "DM"
            h["source_name"] = name
            row = msgs.get(h["id"])
            if row:
                h["message"] = decrypt_message(row["message"])
                h["user_id"], h["username"], h["display_name"] = row["user_id"], row["username"], row["username"]
                for k in ("image_url", "attachment_url", "attachment_name", "attachment_type", "attachment_size"):
                    h[k] = row[k]
            else:
                h["message"] = ""

    # -- Backfill of the operator flags and of attachment-only messages ----------

    async def search_backfill_complete(self) -> bool:
        return await self.get_setting(self.SEARCH_BACKFILL_DONE) == "1"

    async def backfill_search_flags(self, batch_size: int = 200, pause: float = 0.05,
                                    log_interval: float = 60.0) -> dict:
        """One-time pass over every stored message that fills has_image, has_file
        and has_link in the search index and adds the index rows that are missing for
        attachment-only messages, which were never indexed (an empty row: no
        words are stored; messages with text but no row are left to
        rebuild_search_index).

        Meant to run as a background task, never on a request path: it decrypts
        each message, so it works in batches of `batch_size` rows, commits and
        stores its position in settings after every batch, and sleeps `pause`
        seconds between batches so the event loop stays free. It can be stopped
        at any time and resumes from the stored position (`search_backfill_channel_last_id`,
        `search_backfill_dm_last_id`); once both tables are done the setting
        `search_backfill_done` is '1' and later calls return at once. Progress is
        logged at most once per `log_interval` seconds. A second call while one
        runs returns without doing anything."""
        if await self.search_backfill_complete():
            return {"skipped": "done"}
        if self._search_backfill_lock.locked():
            return {"skipped": "running"}
        async with self._search_backfill_lock:
            stats = {"channel": 0, "dm": 0, "indexed": 0}
            started = last_log = time.monotonic()
            logger.info("Search index backfill started")
            for source in ("channel", "dm"):
                key = f"search_backfill_{source}_last_id"
                last_id = int(await self.get_setting(key) or 0)
                while True:
                    done = await self._backfill_batch(source, key, last_id, batch_size)
                    if done is None:
                        break
                    last_id, rows_done, added = done
                    stats[source] += rows_done
                    stats["indexed"] += added
                    now = time.monotonic()
                    if now - last_log >= log_interval:
                        last_log = now
                        logger.info(f"Search index backfill: {stats['channel']} channel and "
                                    f"{stats['dm']} DM messages done ({int(now - started)} s)")
                    await asyncio.sleep(pause)
            await self.set_setting(self.SEARCH_BACKFILL_DONE, "1")
            logger.info(f"Search index backfill finished: {stats['channel']} channel and "
                        f"{stats['dm']} DM messages, {stats['indexed']} added to the index")
            return stats

    async def _backfill_batch(self, source: str, key: str, last_id: int, batch_size: int):
        """One batch of the backfill as a single uninterrupted step on the
        connection: the rows are read, their flags worked out from what was just
        read, the index rows updated, the position stored under `key` and
        everything committed, all in one job on the connection's own thread.
        No other coroutine can run in between, so a rollback or an edit elsewhere
        can neither discard the updates of a batch whose position was stored, nor
        be overwritten with flags of the text from before the edit.
        Returns (last id, rows seen, rows added to the index), or None when no row
        is left after `last_id`."""
        return await self.conn._execute(
            self._backfill_batch_sync, source, key, last_id, batch_size)

    def _backfill_batch_sync(self, source: str, key: str, last_id: int, batch_size: int):
        """The body of _backfill_batch. Runs on the connection's thread with the
        sqlite3 connection itself; nothing in it awaits."""
        raw = self._connection._conn
        fts_table, map_table, id_col, msg_table = self._SEARCH_TABLES[source]
        rows = raw.execute(
            f"""SELECT id, {id_col} AS source_id, user_id, username, message, image_url,
                       attachment_url, attachment_type, created_at
                FROM {msg_table} WHERE id > ? ORDER BY id LIMIT ?""",
            (last_id, batch_size)).fetchall()
        if not rows:
            return None
        added = 0
        # a savepoint, so a failure undoes only this batch, not what was pending
        # on the shared connection before it. The commit at the end is the
        # connection's own, though: it also commits whatever else is pending there.
        raw.execute("SAVEPOINT search_backfill")
        try:
            for row in rows:
                try:
                    plaintext = decrypt_message(row["message"]) if row["message"] else ""
                    has_image, has_file, has_link = chat_search.message_flags(
                        plaintext, row["image_url"], row["attachment_url"], row["attachment_type"])
                    cursor = raw.execute(
                        f"UPDATE {map_table} SET has_image = ?, has_file = ?, has_link = ? WHERE message_id = ?",
                        (has_image, has_file, has_link, row["id"]))
                    if cursor.rowcount > 0:
                        continue
                    # Only attachment-only messages are added: a message with text and no
                    # row is left to rebuild_search_index, so the backfill stores no new words.
                    if (plaintext and plaintext.strip()) or not (has_image or has_file):
                        continue
                    fts = raw.execute(f"INSERT INTO {fts_table}(message) VALUES ('')")
                    raw.execute(
                        f"""INSERT INTO {map_table} (rowid, message_id, {id_col}, user_id, username,
                                                     has_image, has_file, has_link, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (fts.lastrowid, row["id"], row["source_id"], row["user_id"], row["username"],
                         has_image, has_file, has_link, row["created_at"]))
                    added += 1
                except Exception as e:
                    logger.debug(f"Search backfill skipped {source} message {row['id']}: {e}")
            new_last = rows[-1]["id"]
            raw.execute(
                """INSERT INTO settings (key, value, updated_at)
                   VALUES (?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = CURRENT_TIMESTAMP""",
                (key, str(new_last)))
            raw.execute("RELEASE search_backfill")
        except BaseException:
            try:
                raw.execute("ROLLBACK TO search_backfill")
                raw.execute("RELEASE search_backfill")
            except sqlite3.Error:
                pass    # the database already ended the transaction; the original error is the one to report
            raise
        raw.commit()
        return new_last, len(rows), added

    async def rebuild_search_index(self, wait: bool = True) -> dict:
        """Rebuild all FTS indexes from encrypted messages. Returns counts.

        Holds the backfill's lock for the whole rebuild, so the two never
        interleave (a backfill that is running finishes its batch loop first;
        one that starts meanwhile finds the lock taken and returns). With
        wait=False a held lock raises SearchIndexBusy at once instead of
        waiting for the backfill (which can take minutes) to finish."""
        if not wait and self._search_backfill_lock.locked():
            raise SearchIndexBusy("the search index is being built")
        async with self._search_backfill_lock:
            return await self._rebuild_search_index_locked()

    async def _rebuild_search_index_locked(self) -> dict:
        counts = {"channel": 0, "dm": 0}
        # Clear existing FTS data
        try:
            await self.conn.execute("DELETE FROM chat_fts_map")
            await self.conn.execute("DELETE FROM dm_fts_map")
            # Rebuild contentless FTS by dropping and recreating
            await self.conn.execute("DROP TABLE IF EXISTS chat_messages_fts")
            await self.conn.execute("DROP TABLE IF EXISTS dm_messages_fts")
            await self.conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS chat_messages_fts USING fts5(message, content='', tokenize='porter unicode61')"
            )
            await self.conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS dm_messages_fts USING fts5(message, content='', tokenize='porter unicode61')"
            )
            await self.conn.commit()
        except Exception:
            pass

        # Reindex messages in batches; flags come from the stored rows, so a
        # rebuilt index needs no backfill
        batch_size = 500
        for source in ("channel", "dm"):
            _, _, id_col, msg_table = self._SEARCH_TABLES[source]
            last_id = 0
            while True:
                cursor = await self.conn.execute(
                    f"""SELECT id, {id_col} AS source_id, user_id, username, message, image_url,
                               attachment_url, attachment_type, created_at
                        FROM {msg_table} WHERE id > ? ORDER BY id LIMIT ?""",
                    (last_id, batch_size)
                )
                rows = await cursor.fetchall()
                if not rows:
                    break
                for row in rows:
                    row = dict(row)
                    plaintext = decrypt_message(row["message"])
                    has_image, has_file, has_link = chat_search.message_flags(
                        plaintext, row["image_url"], row["attachment_url"], row["attachment_type"])
                    if (plaintext and plaintext.strip()) or has_image or has_file:
                        await self.index_message_for_search(
                            row["id"], plaintext, source, row["source_id"],
                            row["user_id"], row["username"], has_image, row["created_at"],
                            has_file=has_file, has_link=has_link
                        )
                        counts[source] += 1
                    last_id = row["id"]
                last_id = rows[-1]["id"]
                await asyncio.sleep(0)
        await self.set_setting(self.SEARCH_BACKFILL_DONE, "1")
        return counts

    # =========================================================================
    # Data Retention / Cleanup
    # =========================================================================

    _RETENTION_DEFAULTS = {
        "retention_chat_days": "7",
        "retention_dm_days": "30",
        "retention_notifications_days": "30",
        "retention_activity_max": "500",
        "retention_service_logs_max": "1000",
        "retention_device_metrics_days": "14",
        "retention_recordings_days": "30",
        "retention_security_events_days": "180",
        "cleanup_interval_hours": "6",
        "auto_vacuum": "true",
    }

    async def get_retention_config(self) -> dict[str, str]:
        """Get all retention settings with defaults for missing keys."""
        config = dict(self._RETENTION_DEFAULTS)
        for key in self._RETENTION_DEFAULTS:
            val = await self.get_setting(key)
            if val is not None:
                config[key] = val
        return config

    async def set_retention_config(self, config: dict) -> None:
        """Validate and save retention settings."""
        valid_keys = set(self._RETENTION_DEFAULTS.keys())
        for key, value in config.items():
            if key not in valid_keys:
                continue
            # Validate numeric fields
            if key == "auto_vacuum":
                value = "true" if value in ("true", True, "1") else "false"
            else:
                try:
                    int_val = int(value)
                    if int_val < 0:
                        continue
                    # Enforce reasonable upper bounds
                    max_vals = {
                        "retention_chat_days": 3650, "retention_dm_days": 3650,
                        "retention_notifications_days": 3650,
                        "retention_activity_max": 100000, "retention_service_logs_max": 100000,
                        "retention_device_metrics_days": 365,
                        "retention_recordings_days": 3650,
                        "retention_security_events_days": 3650,
                        "cleanup_interval_hours": 168,  # max 1 week
                    }
                    if key in max_vals and int_val > max_vals[key]:
                        int_val = max_vals[key]
                    value = str(int_val)
                except (ValueError, TypeError):
                    continue
            await self.set_setting(key, value)

    async def cleanup_old_dm_messages(self, days: int = 30, stats: dict = None) -> int:
        """Delete DM messages older than specified days, and their upload files
        unless another row still refers to them. Returns count deleted; `stats`,
        when given, receives the files and bytes removed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return await self._purge_messages(
            "dm_messages", "dm", "dm_reactions", "created_at < ?", (cutoff,), stats)

    async def add_device_metric_sample(self, category: str, entries_json: str, ts: str = None) -> None:
        """Persist one device-wide metric sample row (see device_metrics.py)."""
        ts = ts or datetime.now(timezone.utc).isoformat()
        await self.conn.execute(
            "INSERT INTO device_metric_samples (ts, category, entries_json) VALUES (?, ?, ?)",
            (ts, category, entries_json),
        )
        await self.conn.commit()

    async def get_device_metric_samples(
        self, category: str, since_iso: str, max_rows: int = 2000
    ) -> list[dict]:
        """Return {ts, entries_json} rows for a category since `since_iso`, oldest first.

        For windows with more than `max_rows` samples the result is strided
        (every Nth sample, counting back from the newest) so the newest sample
        is always included and memory stays bounded regardless of window size.
        """
        cur = await self.conn.execute(
            "SELECT COUNT(*) AS c FROM device_metric_samples WHERE category = ? AND ts >= ?",
            (category, since_iso),
        )
        total = (await cur.fetchone())["c"]

        if total <= max_rows:
            cur = await self.conn.execute(
                """SELECT ts, entries_json FROM device_metric_samples
                   WHERE category = ? AND ts >= ? ORDER BY ts ASC""",
                (category, since_iso),
            )
            return [dict(row) for row in await cur.fetchall()]

        stride = (total + max_rows - 1) // max_rows
        cur = await self.conn.execute(
            """SELECT ts, entries_json FROM (
                 SELECT ts, entries_json, ROW_NUMBER() OVER (ORDER BY ts DESC) AS rn
                 FROM device_metric_samples WHERE category = ? AND ts >= ?
               ) WHERE (rn - 1) % ? = 0 ORDER BY ts ASC""",
            (category, since_iso, stride),
        )
        return [dict(row) for row in await cur.fetchall()]

    async def cleanup_device_metrics(self, days: int = 14) -> int:
        """Delete device metric samples older than `days`. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM device_metric_samples WHERE ts < ?", (cutoff,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def cleanup_old_notifications(self, days: int = 30) -> int:
        """Delete notifications older than specified days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM notifications WHERE created_at < ?", (cutoff,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def cleanup_expired_tokens(self) -> int:
        """Delete expired or revoked tokens. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM tokens WHERE (expires_at IS NOT NULL AND expires_at < ?) OR revoked = 1",
            (now,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def cleanup_expired_api_keys(self) -> int:
        """Delete expired or revoked API keys. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM api_keys WHERE (expires_at IS NOT NULL AND expires_at < ?) OR revoked = 1",
            (now,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def cleanup_old_activity_log(self, keep: int = 500) -> int:
        """Trim activity log to keep only the most recent N entries. Returns count deleted."""
        cursor = await self.conn.execute(
            "SELECT id FROM activity_log ORDER BY id DESC LIMIT 1 OFFSET ?",
            (keep,)
        )
        row = await cursor.fetchone()
        if not row:
            return 0
        threshold_id = row[0]
        cursor = await self.conn.execute(
            "DELETE FROM activity_log WHERE id <= ?", (threshold_id,)
        )
        await self.conn.commit()
        return cursor.rowcount

    # =========================================================================
    # Invite Codes
    # =========================================================================

    async def create_invite_code(self, code: str, code_type: str, created_by: int,
                                  label: Optional[str] = None, expires_at: Optional[str] = None,
                                  max_uses: Optional[int] = None) -> int:
        """Create a new invite code. Returns the code ID."""
        cursor = await self.conn.execute(
            """INSERT INTO invite_codes (code, type, created_by, label, expires_at, max_uses)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (code, code_type, created_by, label, expires_at, max_uses)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_invite_codes(self, include_inactive: bool = False) -> list[dict]:
        """Get all invite codes with creator username."""
        query = """SELECT ic.*, u.username as created_by_username
                   FROM invite_codes ic
                   LEFT JOIN users u ON ic.created_by = u.id"""
        if not include_inactive:
            query += " WHERE ic.is_active = 1"
        query += " ORDER BY ic.created_at DESC"
        cursor = await self.conn.execute(query)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_active_invite_code_by_code(self, code: str) -> Optional[dict]:
        """Get an active, non-expired invite code with available uses."""
        cursor = await self.conn.execute(
            """SELECT * FROM invite_codes
               WHERE code = ? AND is_active = 1
               AND (expires_at IS NULL OR expires_at > datetime('now'))
               AND (max_uses IS NULL OR use_count < max_uses)""",
            (code,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def increment_invite_code_usage(self, code_id: int) -> bool:
        """Atomically increment use count for an invite code.

        Returns True if the code was valid and incremented, False if
        the code was already exhausted (TOCTOU-safe for single-use codes).
        """
        cursor = await self.conn.execute(
            """UPDATE invite_codes SET use_count = use_count + 1
               WHERE id = ? AND is_active = 1
               AND (max_uses IS NULL OR use_count < max_uses)""",
            (code_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def deactivate_invite_code(self, code_id: int) -> None:
        """Deactivate an invite code."""
        await self.conn.execute(
            "UPDATE invite_codes SET is_active = 0 WHERE id = ?",
            (code_id,)
        )
        await self.conn.commit()

    async def cleanup_old_invite_codes(self, days: int = 30) -> int:
        """Delete revoked/inactive invite codes older than N days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM invite_codes WHERE is_active = 0 AND created_at < ?",
            (cutoff,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def get_invite_code_registrations(self, code_id: int) -> list[dict]:
        """Get users who registered with a specific invite code."""
        cursor = await self.conn.execute(
            """SELECT id, username, role, created_at
               FROM users WHERE invite_code_id = ?
               ORDER BY created_at DESC""",
            (code_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def set_user_invite_code(self, user_id: int, code_id: int) -> None:
        """Set the invite code used for registration."""
        await self.conn.execute(
            "UPDATE users SET invite_code_id = ? WHERE id = ?",
            (code_id, user_id)
        )
        await self.conn.commit()

    async def ensure_daily_invite_code(self, admin_user_id: int) -> str:
        """Ensure today's daily invite code exists in DB. Returns the code string."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_start = f"{today} 00:00:00"
        today_end = f"{today} 23:59:59"

        # Check for existing daily code created today
        cursor = await self.conn.execute(
            """SELECT * FROM invite_codes
               WHERE type = 'daily' AND is_active = 1
               AND created_at >= ? AND created_at <= ?""",
            (today_start, today_end)
        )
        existing = await cursor.fetchone()
        if existing:
            return existing["code"]

        # Deactivate previous daily codes
        await self.conn.execute(
            "UPDATE invite_codes SET is_active = 0 WHERE type = 'daily' AND is_active = 1"
        )

        # Generate new daily code
        import secrets
        chars = secrets.token_hex(6).upper()
        code = f"PORTAL-{chars[:4]}-{chars[4:8]}-{chars[8:12]}"

        await self.conn.execute(
            """INSERT INTO invite_codes (code, type, created_by, expires_at, max_uses)
               VALUES (?, 'daily', ?, ?, NULL)""",
            (code, admin_user_id, today_end)
        )
        await self.conn.commit()
        return code

    async def vacuum_database(self, force: bool = False) -> bool:
        """Reclaim disk space. Returns True if a VACUUM actually ran.

        VACUUM rewrites the entire database (through the WAL), so it is only
        worth doing when a meaningful share of the file is free pages: at
        least 10% of the database or 64 MB. `force` skips that check. The WAL
        is checkpointed and truncated either way.
        """
        async def _pragma(name: str) -> int:
            cursor = await self.conn.execute(f"PRAGMA {name}")
            row = await cursor.fetchone()
            return int(row[0]) if row else 0

        free_pages = await _pragma("freelist_count")
        page_count = await _pragma("page_count")
        page_size = await _pragma("page_size")
        worthwhile = free_pages > 0 and (
            free_pages * 10 >= page_count or free_pages * page_size >= 64 * 1024 * 1024
        )
        vacuumed = False
        if force or worthwhile:
            await self.conn.commit()
            await self.conn.execute("VACUUM")
            vacuumed = True
        cursor = await self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await cursor.fetchall()
        return vacuumed

    async def get_all_service_ids(self) -> list[int]:
        """Get all service IDs for bulk cleanup."""
        cursor = await self.conn.execute("SELECT id FROM services")
        rows = await cursor.fetchall()
        return [row["id"] for row in rows]

    # =========================================================================
    # User presence
    # =========================================================================

    async def update_last_seen(self, user_id: int) -> None:
        """Update last_seen_at timestamp for a user."""
        await self.conn.execute(
            "UPDATE users SET last_seen_at = datetime('now') WHERE id = ?",
            (user_id,)
        )
        await self.conn.commit()

    # =========================================================================
    # Webhooks
    # =========================================================================

    @staticmethod
    def _webhook_secret_config(raw) -> dict:
        """Decrypt the per-format credentials column to a dict (empty when unset)."""
        if not raw:
            return {}
        try:
            val = json.loads(decrypt_config(raw))
        except (ValueError, TypeError):
            return {}
        return val if isinstance(val, dict) else {}

    @classmethod
    def _webhook_public(cls, row) -> dict:
        """A webhook row as an API may show it. Never carries the HMAC secret, the URL
        token of an incoming hook or the per-format credentials; for a non-generic format never the URL either
        (a Discord or Slack webhook URL, an ntfy topic, a Gotify server are
        credentials), only whether one is set and its scheme and host."""
        d = dict(row)
        url = decrypt_config(d["url"]) if d.get("url") else None
        d["has_secret"] = bool(d.get("secret"))
        d.pop("secret", None)
        # The URL token of an incoming hook is a credential (anyone holding it can post into the
        # channel): not part of a public row. The creation response carries it once; a read route
        # adds it for the hook's owner only (get_webhook_token).
        d["has_token"] = bool(d.get("token"))
        d.pop("token", None)
        d["events"] = json.loads(d["events"]) if d.get("events") else []
        if d.get("last_failure_reason"):
            d["last_failure_reason"] = decrypt_config(d["last_failure_reason"])
        fc = cls._webhook_secret_config(d.pop("format_config", None))
        d["has_format_secret"] = any(fc.get(k) for k in ("token", "password"))
        d["format"] = d.get("format") or "generic"
        d["kind"] = d.get("kind") or "user"
        d["include_details"] = bool(d.get("include_details"))
        d["allow_private"] = bool(d.get("allow_private"))
        if d["format"] == "generic":
            d["url"] = url
        else:
            d["url"] = None
            d.update(webhook_formats.mask_url(url))
        return d

    async def create_webhook(self, user_id, name: str, webhook_type: str,
                             url: str = None, events: list[str] = None,
                             channel_id: int = None, *, kind: str = "user",
                             fmt: str = "generic", format_config: dict = None,
                             include_details: bool = False, allow_private: bool = False,
                             created_by: int = None) -> dict:
        """Create a webhook. Secret/token auto-generated, encrypted at rest.

        A system webhook (kind 'system') has no owner (user_id None) and is
        managed by superadmins only. The HMAC secret is generated for every
        hook of the generic format and for incoming hooks. A hook of another
        format is stored with an empty secret, so that a version which does not
        know formats (1.14.0 after a code-only rollback) skips it instead of
        signing and sending to it; a switch to generic generates one then
        (update_webhook).
        """
        import secrets as _s
        signed = webhook_type != "outgoing" or fmt == "generic"
        secret = _s.token_hex(32) if signed else ""
        token = _s.token_urlsafe(32) if webhook_type == "incoming" else None
        enc_secret = encrypt_config(secret) if secret else ""
        enc_url = encrypt_config(url) if url else None
        events_json = json.dumps(events or [])
        enc_fc = encrypt_config(json.dumps(format_config)) if format_config else None
        cursor = await self.conn.execute(
            """INSERT INTO webhooks (user_id, name, type, url, secret, token, events, channel_id,
                                     kind, format, format_config, include_details, allow_private,
                                     created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, webhook_type, enc_url, enc_secret, token, events_json, channel_id,
             kind, fmt, enc_fc, int(bool(include_details)), int(bool(allow_private)), created_by)
        )
        await self.conn.commit()
        out = await self.get_webhook(cursor.lastrowid)
        if token:
            out["token"] = token
        if fmt == "generic":
            out["secret"] = secret
        return out

    async def get_webhook(self, webhook_id: int) -> Optional[dict]:
        """Get webhook by ID, redacted (see _webhook_public)."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        return self._webhook_public(row) if row else None

    async def get_webhook_token(self, webhook_id: int) -> Optional[str]:
        """The URL token of an incoming hook (None for any other). For the owner's own read only."""
        cursor = await self.conn.execute("SELECT token FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        return (row[0] or None) if row else None

    async def get_webhook_for_delivery(self, webhook_id: int) -> Optional[dict]:
        """Full webhook for the delivery engine: decrypted url, HMAC secret and
        per-format credentials (`format_config` as a dict). Never sent to an API."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._webhook_full(row)

    @classmethod
    def _webhook_full(cls, row) -> dict:
        d = dict(row)
        d["url"] = decrypt_config(d["url"]) if d.get("url") else None
        d["secret"] = decrypt_config(d["secret"]) if d.get("secret") else None
        d["events"] = json.loads(d["events"]) if d.get("events") else []
        d["format_config"] = cls._webhook_secret_config(d.get("format_config"))
        d["format"] = d.get("format") or "generic"
        d["kind"] = d.get("kind") or "user"
        return d

    async def get_webhook_by_token(self, token: str) -> Optional[dict]:
        """Get incoming webhook by URL token. Decrypts url and secret."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE token = ?", (token,))
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["url"] = decrypt_config(d["url"]) if d["url"] else None
        d["secret"] = decrypt_config(d["secret"]) if d["secret"] else None
        d["events"] = json.loads(d["events"]) if d["events"] else []
        return d

    async def get_webhooks_for_user(self, user_id: int) -> list[dict]:
        """Get all (user) webhooks of a user, redacted."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE user_id = ? AND kind = 'user' ORDER BY created_at DESC",
            (user_id,))
        return [self._webhook_public(row) for row in await cursor.fetchall()]

    async def get_all_webhooks(self) -> list[dict]:
        """Admin: get all user webhooks with their owner (system webhooks have
        their own list, see get_system_webhooks), redacted."""
        cursor = await self.conn.execute(
            """SELECT w.*, u.username as owner_username
               FROM webhooks w LEFT JOIN users u ON w.user_id = u.id
               WHERE w.kind = 'user'
               ORDER BY w.created_at DESC""")
        return [self._webhook_public(row) for row in await cursor.fetchall()]

    async def get_system_webhooks(self) -> list[dict]:
        """System webhooks (no owner), redacted."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE kind = 'system' ORDER BY id")
        return [self._webhook_public(row) for row in await cursor.fetchall()]

    async def count_system_webhooks(self) -> int:
        cursor = await self.conn.execute("SELECT COUNT(*) FROM webhooks WHERE kind = 'system'")
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_enabled_outgoing_webhooks_for_event(self, event: str) -> list[dict]:
        """Get enabled outgoing webhooks that receive `event` (the event-class
        rules in webhook_formats.event_subscribed apply). Full rows, for delivery."""
        cursor = await self.conn.execute(
            "SELECT * FROM webhooks WHERE type = 'outgoing' AND enabled = 1")
        results = []
        for row in await cursor.fetchall():
            # Decide on the plain columns first: url, secret and format_config are
            # decrypted only for a hook that receives this event.
            try:
                events = json.loads(row["events"]) if row["events"] else []
            except ValueError:
                continue
            if not webhook_formats.event_subscribed(
                    events, event, kind=row["kind"] or "user", fmt=row["format"] or "generic"):
                continue
            results.append(self._webhook_full(row))
        return results

    async def update_webhook(self, webhook_id: int, **kwargs) -> bool:
        """Update webhook fields. Encrypts url and the per-format credentials."""
        allowed = {"name", "url", "events", "channel_id", "enabled", "format",
                   "format_config", "include_details", "allow_private"}
        fields, values = [], []
        for key, val in kwargs.items():
            if key not in allowed:
                continue
            if key == "url" and val is not None:
                val = encrypt_config(val)
            elif key == "events" and isinstance(val, list):
                val = json.dumps(val)
            elif key == "format_config":
                val = encrypt_config(json.dumps(val)) if val else None
            elif key in ("include_details", "allow_private"):
                val = int(bool(val))
            fields.append(f"{key} = ?")
            values.append(val)
        if not fields:
            return False
        if kwargs.get("format"):
            # Only the generic format is signed. Any other format keeps no
            # secret (a version without formats would otherwise sign and send
            # to it); a switch to generic gets a fresh one.
            if kwargs["format"] == "generic":
                cur = await self.conn.execute(
                    "SELECT secret FROM webhooks WHERE id = ? AND type = 'outgoing'", (webhook_id,))
                row = await cur.fetchone()
                if row is not None and not row[0]:
                    import secrets as _s
                    fields.append("secret = ?")
                    values.append(encrypt_config(_s.token_hex(32)))
            else:
                fields.append("secret = ?")
                values.append("")
        fields.append("updated_at = CURRENT_TIMESTAMP")
        values.append(webhook_id)
        cursor = await self.conn.execute(
            f"UPDATE webhooks SET {', '.join(fields)} WHERE id = ?", values)
        await self.conn.commit()
        return cursor.rowcount > 0

    async def delete_webhook(self, webhook_id: int) -> bool:
        """Delete a webhook (cascades to logs)."""
        cursor = await self.conn.execute(
            "DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        await self.conn.commit()
        return cursor.rowcount > 0

    async def increment_webhook_failures(self, webhook_id: int, reason: str) -> int:
        """Increment failure counter. Returns new count."""
        await self.conn.execute(
            """UPDATE webhooks SET consecutive_failures = consecutive_failures + 1,
               last_failure_at = datetime('now'), last_failure_reason = ?
               WHERE id = ?""", (encrypt_config(reason[:500]), webhook_id))
        await self.conn.commit()
        cursor = await self.conn.execute(
            "SELECT consecutive_failures FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def reset_webhook_failures(self, webhook_id: int) -> None:
        """Reset failure counter on successful delivery."""
        await self.conn.execute(
            """UPDATE webhooks SET consecutive_failures = 0,
               last_delivery_at = datetime('now') WHERE id = ?""", (webhook_id,))
        await self.conn.commit()

    async def disable_webhook(self, webhook_id: int) -> None:
        """Disable a webhook (e.g. after too many failures)."""
        await self.conn.execute(
            "UPDATE webhooks SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (webhook_id,))
        await self.conn.commit()

    async def regenerate_webhook_secret(self, webhook_id: int) -> Optional[str]:
        """Regenerate HMAC signing secret. Returns new secret (plaintext, shown once)."""
        import secrets as _s
        new_secret = _s.token_hex(32)
        enc_secret = encrypt_config(new_secret)
        cursor = await self.conn.execute(
            "UPDATE webhooks SET secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (enc_secret, webhook_id))
        await self.conn.commit()
        return new_secret if cursor.rowcount > 0 else None

    async def create_webhook_log(self, webhook_id: int, event: str,
                                  request_payload: str, response_status: int = None,
                                  response_body: str = None, success: bool = False,
                                  attempt: int = 1, duration_ms: int = 0) -> int:
        """Create delivery log entry. Payloads encrypted at rest."""
        enc_req = encrypt_config(request_payload) if request_payload else None
        enc_resp = encrypt_config(response_body) if response_body else None
        cursor = await self.conn.execute(
            """INSERT INTO webhook_logs (webhook_id, event, request_payload, response_status,
               response_body, success, attempt, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (webhook_id, event, enc_req, response_status, enc_resp, int(success), attempt, duration_ms))
        await self.conn.commit()
        return cursor.lastrowid

    async def get_webhook_logs(self, webhook_id: int, limit: int = 50,
                                offset: int = 0) -> list[dict]:
        """Get delivery logs (decrypted payloads)."""
        cursor = await self.conn.execute(
            """SELECT * FROM webhook_logs WHERE webhook_id = ?
               ORDER BY id DESC LIMIT ? OFFSET ?""",
            (webhook_id, limit, offset))
        results = []
        for row in await cursor.fetchall():
            d = dict(row)
            d["request_payload"] = decrypt_config(d["request_payload"]) if d["request_payload"] else None
            d["response_body"] = decrypt_config(d["response_body"]) if d["response_body"] else None
            d["success"] = bool(d["success"])
            results.append(d)
        return results

    async def cleanup_old_webhook_logs(self, max_age_days: int = 7) -> int:
        """Delete webhook logs older than max_age_days."""
        cursor = await self.conn.execute(
            "DELETE FROM webhook_logs WHERE created_at < datetime('now', ?)",
            (f"-{max_age_days} days",))
        await self.conn.commit()
        return cursor.rowcount


# Global database instance
db = Database()
