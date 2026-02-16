"""Database layer for Open Relay Portal using SQLite."""

import json
import logging
import secrets as _secrets

import aiosqlite
import base64
import hashlib
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from config import Config

logger = logging.getLogger("portal.database")

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

# --- Legacy key functions (hardcoded salts, pre-machine-binding) ---

def _get_legacy_chat_key() -> bytes:
    """Legacy chat encryption key using hardcoded salt."""
    if not Config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is required for encryption")
    secret = Config.JWT_SECRET.encode()
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=b"portal-chat-salt", iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


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
    """Encrypt a chat message."""
    if not CRYPTO_AVAILABLE or not plaintext:
        return plaintext
    try:
        f = Fernet(get_chat_encryption_key())
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"Message encryption failed, storing plaintext: {e}")
        return plaintext


def decrypt_message(ciphertext: str) -> str:
    """Decrypt a chat message. Falls back to legacy key for pre-migration data."""
    if not CRYPTO_AVAILABLE or not ciphertext:
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
            logger.warning(f"Message decryption failed (both keys): {type(e).__name__}")
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
        logger.debug(f"Config encryption failed, storing plaintext: {e}")
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
        FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(stream_id, user_id)
    )""",
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
    # Discord parity: slowmode, channel categories, timeouts, file attachments
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


class Database:
    """Async database operations for Open Relay Portal."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DATABASE_PATH
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Initialize database connection and schema."""
        # Ensure parent directory exists (SQLite won't create directories)
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        # Restrict DB file permissions even if umask is permissive
        os.chmod(self.db_path, 0o600)
        await self._connection.execute("PRAGMA journal_mode = WAL")
        await self._connection.execute("PRAGMA busy_timeout = 5000")
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

        # Generate public keys for any streams that don't have one
        await self._populate_stream_public_keys()

        # Encrypt any plaintext configs (one-time migration)
        await self._migrate_encrypt_configs()

        # Encrypt any plaintext stream keys (one-time migration)
        await self._migrate_encrypt_stream_keys()

        # Re-encrypt all data with machine-bound keys (one-time migration)
        await self._migrate_encryption_to_machine_key()

        # Generate UUIDs for any connections that don't have one
        await self._populate_connection_uuids()

        # Seed default connections for existing users who don't have one
        await self._seed_default_connections()

        # Encrypt plaintext TOTP secrets and hash plaintext backup codes
        await self._migrate_totp_and_backup_codes()

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

            browser_config = encrypt_config('{"browser_mode": true}')

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
            # Recordings
            ("recordings", "DELETE FROM recordings WHERE user_id = ?"),
            # SSH keys
            ("ssh_keys", "DELETE FROM ssh_keys WHERE user_id = ?"),
            # Tokens (no FK cascade)
            ("tokens", "DELETE FROM tokens WHERE user_id = ?"),
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
            "SELECT id, username, nickname, status, status_message FROM users WHERE id = ?",
            (user_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def set_user_status(self, user_id: int, status: str, status_message: str = None) -> bool:
        """Set user status (online, away, busy, dnd, offline)."""
        valid_statuses = ('online', 'away', 'busy', 'dnd', 'offline')
        if status not in valid_statuses:
            return False
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
            f"SELECT id, username, nickname, status, status_message, role, chat_anonymous, avatar FROM users WHERE id IN ({placeholders})",
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
        expires_at: datetime = None
    ) -> int:
        """Create a new token record and return its ID."""
        cursor = await self.conn.execute(
            """INSERT INTO tokens (user_id, token_id, name, scopes, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                user_id,
                token_id,
                name,
                ",".join(scopes),
                expires_at.isoformat() if expires_at else None
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

    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by token_id."""
        cursor = await self.conn.execute(
            "UPDATE tokens SET revoked = 1 WHERE token_id = ?",
            (token_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def update_token_last_used(self, token_id: str) -> None:
        """Update the last_used_at timestamp for a token."""
        await self.conn.execute(
            "UPDATE tokens SET last_used_at = ? WHERE token_id = ?",
            (datetime.now(timezone.utc).isoformat(), token_id)
        )
        await self.conn.commit()

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
        ports: list = None
    ) -> int:
        """Create a new service and return its ID.

        Args:
            service_type: 'proxy' for external backends, 'managed' for Portal-run processes
            display_name: Human-readable name (defaults to name)
            description: Service description
            binary_path: Path to executable (for managed services)
            working_dir: Working directory (for managed services)
            ports: Additional ports list (for managed services)
        """
        import json
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO services (name, plugin, path, host, port, config, required_scopes,
               icon, category_id, service_type, display_name, description, binary_path,
               working_dir, ports, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            "config", "ports", "required_scopes", "category_id", "internal_url",
            "service_type", "enabled", "command", "working_dir", "env_vars",
            "auto_start", "health_check_url", "status", "pid", "health_status",
            "error_message", "restart_count", "last_started_at", "last_stopped_at",
            "last_health_check",
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
        expires_at: Optional[str] = None
    ) -> int:
        """Create a new API key and return its ID."""
        cursor = await self.conn.execute(
            """INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, name, key_hash, key_prefix, scopes, expires_at)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_api_key_by_prefix(self, prefix: str) -> Optional[dict]:
        """Get API key by prefix for authentication."""
        cursor = await self.conn.execute(
            """SELECT ak.*, u.username
               FROM api_keys ak
               JOIN users u ON ak.user_id = u.id
               WHERE ak.key_prefix = ? AND ak.revoked = 0""",
            (prefix,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_user_api_keys(self, user_id: int) -> list[dict]:
        """Get all API keys for a user (excluding hash for security)."""
        cursor = await self.conn.execute(
            """SELECT id, name, key_prefix, scopes, expires_at, last_used_at, created_at, revoked
               FROM api_keys
               WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_api_key_last_used(self, key_id: int) -> None:
        """Update last_used_at timestamp for an API key."""
        await self.conn.execute(
            "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (key_id,)
        )
        await self.conn.commit()

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

    async def get_user_connections(self, user_id: int) -> list[dict]:
        """Get all connections for a user (pinned first, then by last used)."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.user_id = ?
               ORDER BY uc.is_pinned DESC, uc.last_used_at DESC NULLS LAST, uc.name""",
            (user_id,)
        )
        rows = await cursor.fetchall()
        import json
        connections = []
        for row in rows:
            conn = dict(row)
            try:
                raw_config = conn.get("config", "{}")
                conn["config"] = json.loads(decrypt_config(raw_config))
            except (json.JSONDecodeError, Exception):
                conn["config"] = {}
            connections.append(conn)
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
        """Get all connections of a specific type for a user."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.user_id = ? AND uc.type = ?
               ORDER BY uc.name""",
            (user_id, conn_type)
        )
        rows = await cursor.fetchall()
        import json
        connections = []
        for row in rows:
            conn = dict(row)
            try:
                raw_config = conn.get("config", "{}")
                conn["config"] = json.loads(decrypt_config(raw_config))
            except (json.JSONDecodeError, Exception):
                conn["config"] = {}
            connections.append(conn)
        return connections

    # User streams operations
    async def create_user_stream(
        self,
        user_id: int,
        name: str,
        stream_key: str,
        public_key: str = None,
        description: str = None,
        is_public: bool = False
    ) -> int:
        """Create a new user stream.

        Args:
            user_id: Owner's user ID
            name: Stream name
            stream_key: Private key for publishing (OBS/RTMP)
            public_key: Public key for viewing (HLS/WebRTC)
            description: Stream description
            is_public: Whether stream is publicly visible
        """
        sk_hash = hash_stream_key(stream_key)
        sk_encrypted = encrypt_config(stream_key) if CRYPTO_AVAILABLE else stream_key
        pk_hash = hash_stream_key(public_key) if public_key else None
        pk_encrypted = encrypt_config(public_key) if (public_key and CRYPTO_AVAILABLE) else public_key

        cursor = await self.conn.execute(
            """INSERT INTO user_streams (user_id, name, stream_key, stream_key_hash,
               public_key, public_key_hash, description, is_public, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, sk_encrypted, sk_hash, pk_encrypted, pk_hash,
             description, 1 if is_public else 0,
             datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()
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

    async def get_public_streams(self, live_only: bool = False) -> list[dict]:
        """Get all public streams, optionally only live ones."""
        query = """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname, c.name as chat_channel_name
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
        """Get streams that allow unauthenticated public access."""
        query = """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
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
                         "allow_unauthenticated", "rtmp_enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not updates:
            return False

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [stream_id]

        query = f"UPDATE user_streams SET {set_clause} WHERE id = ?"
        if user_id:
            query += " AND user_id = ?"
            values.append(user_id)

        cursor = await self.conn.execute(query, values)
        await self.conn.commit()
        return cursor.rowcount > 0

    async def reset_all_streams_offline(self) -> int:
        """Reset all streams to offline. Called on server startup."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            "UPDATE user_streams SET is_live = 0, viewer_count = 0, updated_at = ? WHERE is_live != 0",
            (now,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def set_stream_live(self, stream_id: int, is_live: bool) -> bool:
        """Set stream live status and update timestamps."""
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
                       total_views = total_views + viewer_count
                   WHERE id = ?""",
                (now, now, stream_id)
            )
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

        if user_id:
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

        if user_id:
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
        reason: str = None
    ) -> int:
        """Ban a user from a stream's chat. Returns ban ID or 0 if failed."""
        try:
            cursor = await self.conn.execute(
                """INSERT INTO stream_bans (stream_id, user_id, banned_by, reason)
                   VALUES (?, ?, ?, ?)""",
                (stream_id, user_id, banned_by, reason)
            )
            await self.conn.commit()
            return cursor.lastrowid
        except Exception:
            return 0

    async def remove_stream_ban(self, stream_id: int, user_id: int) -> bool:
        """Remove a ban from a stream."""
        cursor = await self.conn.execute(
            "DELETE FROM stream_bans WHERE stream_id = ? AND user_id = ?",
            (stream_id, user_id)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def is_user_banned_from_stream(self, stream_id: int, user_id: int) -> bool:
        """Check if a user is banned from a stream."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM stream_bans WHERE stream_id = ? AND user_id = ?",
            (stream_id, user_id)
        )
        return await cursor.fetchone() is not None

    async def get_stream_bans(self, stream_id: int) -> list[dict]:
        """Get all bans for a stream."""
        cursor = await self.conn.execute(
            """SELECT sb.*, u.username as banned_username, ub.username as banned_by_username
               FROM stream_bans sb
               JOIN users u ON sb.user_id = u.id
               JOIN users ub ON sb.banned_by = ub.id
               WHERE sb.stream_id = ?
               ORDER BY sb.created_at DESC""",
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
               WHERE us.chat_channel_id = ?""",
            (channel_id,)
        )
        row = await cursor.fetchone()
        return self._decrypt_stream_keys(dict(row)) if row else None

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
        """Get a user by nickname (case-insensitive)."""
        cursor = await self.conn.execute(
            "SELECT * FROM users WHERE LOWER(nickname) = LOWER(?)", (nickname,)
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
        cursor = await self.conn.execute(
            """INSERT INTO audit_log (action, actor_id, actor_username, target_id, target_type,
               target_name, details, channel_id, channel_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (action, actor_id, actor_username, target_id, target_type, target_name,
             json.dumps(details) if details else None, channel_id, channel_name)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_audit_log(self, limit: int = 50, offset: int = 0,
                             action: str = None, actor_id: int = None,
                             channel_id: int = None, since: str = None) -> list[dict]:
        """Get audit log entries with optional filters."""
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
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        cursor = await self.conn.execute(
            f"SELECT * FROM audit_log{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_audit_log_count(self, action: str = None, actor_id: int = None,
                                   channel_id: int = None, since: str = None) -> int:
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
    # Auto-moderation operations
    # =============================================

    async def get_automod_rules(self, enabled_only: bool = False) -> list[dict]:
        """Get auto-moderation rules."""
        if enabled_only:
            cursor = await self.conn.execute("SELECT * FROM automod_rules WHERE enabled = 1 ORDER BY id")
        else:
            cursor = await self.conn.execute("SELECT * FROM automod_rules ORDER BY id")
        return [dict(row) for row in await cursor.fetchall()]

    async def create_automod_rule(self, type: str, name: str, config: dict,
                                   action: str, created_by: int,
                                   action_duration: int = None) -> int:
        """Create an auto-moderation rule."""
        cursor = await self.conn.execute(
            """INSERT INTO automod_rules (type, name, config, action, action_duration, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (type, name, json.dumps(config), action, action_duration, created_by)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_automod_rule(self, rule_id: int, **kwargs) -> bool:
        """Update an auto-moderation rule."""
        allowed = {"name", "config", "enabled", "action", "action_duration", "type"}
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                updates[k] = json.dumps(v) if k == "config" and isinstance(v, dict) else v
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
        has_attachment = 1 if (image_url or attachment_url) else 0
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
            has_attachment, created_at
        )
        return msg_id

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
        messages = []
        for row in reversed(rows):
            msg = dict(row)
            msg["message"] = decrypt_message(msg.get("message", ""))
            if msg.get("reply_preview_text"):
                msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
            messages.append(msg)
        return messages

    async def get_chat_message(self, message_id: int) -> Optional[dict]:
        """Get a single chat message by ID (decrypted)."""
        cursor = await self.conn.execute(
            "SELECT * FROM chat_messages WHERE id = ?", (message_id,)
        )
        row = await cursor.fetchone()
        if row:
            msg = dict(row)
            msg["message"] = decrypt_message(msg.get("message", ""))
            if msg.get("reply_preview_text"):
                msg["reply_preview_text"] = decrypt_message(msg["reply_preview_text"])
            return msg
        return None

    async def delete_chat_message(self, message_id: int, user_id: int = None) -> bool:
        """Delete a chat message (optionally verify ownership)."""
        # Fetch file URLs before deleting so we can clean up uploaded files
        file_cursor = await self.conn.execute(
            "SELECT image_url, attachment_url FROM chat_messages WHERE id = ?",
            (message_id,)
        )
        file_row = await file_cursor.fetchone()

        if user_id:
            cursor = await self.conn.execute(
                "DELETE FROM chat_messages WHERE id = ? AND user_id = ?",
                (message_id, user_id)
            )
        else:
            cursor = await self.conn.execute(
                "DELETE FROM chat_messages WHERE id = ?",
                (message_id,)
            )
        await self.conn.commit()
        if cursor.rowcount > 0:
            await self.remove_message_from_search(message_id, "channel")
            # Clean up uploaded files from disk
            if file_row:
                for field in ('image_url', 'attachment_url'):
                    url = file_row[field]
                    if url and url.startswith('/static/uploads/chat/'):
                        file_path = Path(__file__).parent / url.lstrip('/')
                        try:
                            if file_path.exists():
                                file_path.unlink()
                        except OSError:
                            pass
            return True
        return False

    async def cleanup_old_chat_messages(self, days: int = 7) -> int:
        """Delete chat messages older than specified days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        total_deleted = 0
        batch_size = 500
        while True:
            cursor = await self.conn.execute(
                "SELECT id FROM chat_messages WHERE created_at < ? LIMIT ?",
                (cutoff, batch_size)
            )
            batch = [row["id"] for row in await cursor.fetchall()]
            if not batch:
                break
            for msg_id in batch:
                try:
                    await self.remove_message_from_search(msg_id, "channel")
                except Exception:
                    pass
            placeholders = ",".join("?" * len(batch))
            await self.conn.execute(
                f"DELETE FROM chat_reactions WHERE message_id IN ({placeholders})", batch
            )
            await self.conn.execute(
                f"DELETE FROM chat_messages WHERE id IN ({placeholders})", batch
            )
            await self.conn.commit()
            total_deleted += len(batch)
        return total_deleted

    async def clear_channel_messages(self, channel_id: int) -> int:
        """Delete all messages in a channel. Returns count deleted."""
        # Get IDs for FTS and reaction cleanup
        cursor = await self.conn.execute(
            "SELECT id FROM chat_messages WHERE channel_id = ?", (channel_id,)
        )
        msg_ids = [row["id"] for row in await cursor.fetchall()]
        if msg_ids:
            for msg_id in msg_ids:
                try:
                    await self.remove_message_from_search(msg_id, "channel")
                except Exception:
                    pass
            placeholders = ",".join("?" * len(msg_ids))
            await self.conn.execute(
                f"DELETE FROM chat_reactions WHERE message_id IN ({placeholders})", msg_ids
            )
        cursor = await self.conn.execute(
            "DELETE FROM chat_messages WHERE channel_id = ?",
            (channel_id,)
        )
        await self.conn.commit()
        return cursor.rowcount

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
    # Message Editing
    # =========================================================================

    async def edit_chat_message(self, message_id: int, user_id: int, new_message: str, max_age_seconds: int = 300) -> Optional[dict]:
        """Edit a chat message within time window. Returns updated message or None."""
        msg = await self.get_chat_message(message_id)
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
        """Get unread message counts per channel for a user."""
        cursor = await self.conn.execute(
            """SELECT c.id, COUNT(m.id) as unread
               FROM chat_channels c
               LEFT JOIN channel_read_positions rp ON rp.channel_id = c.id AND rp.user_id = ?
               INNER JOIN chat_messages m ON m.channel_id = c.id AND m.id > COALESCE(rp.last_read_message_id, 0)
               GROUP BY c.id
               HAVING unread > 0""",
            (user_id,)
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
            cursor = await self.conn.execute(
                f"""SELECT * FROM activity_log
                    WHERE user_id = ? OR action IN ({placeholders})
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
        cursor = await self.conn.execute(
            """INSERT INTO notifications (user_id, type, title, message, data)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, type, title, message, json.dumps(data or {}))
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
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

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
        await self.index_message_for_search(
            msg_id, plaintext, "dm", conversation_id, user_id, username,
            1 if image_url else 0, created_at
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
        # Fetch file URLs before deleting so we can clean up uploaded files
        file_cursor = await self.conn.execute(
            "SELECT image_url, attachment_url FROM dm_messages WHERE id = ?",
            (message_id,)
        )
        file_row = await file_cursor.fetchone()

        if user_id:
            cursor = await self.conn.execute(
                "DELETE FROM dm_messages WHERE id = ? AND user_id = ?",
                (message_id, user_id)
            )
        else:
            cursor = await self.conn.execute(
                "DELETE FROM dm_messages WHERE id = ?", (message_id,)
            )
        await self.conn.commit()
        if cursor.rowcount > 0:
            await self.remove_message_from_search(message_id, "dm")
            # Clean up uploaded files from disk
            if file_row:
                for field in ('image_url', 'attachment_url'):
                    url = file_row[field] if file_row[field] else None
                    if url and url.startswith('/static/uploads/chat/'):
                        file_path = Path(__file__).parent / url.lstrip('/')
                        try:
                            if file_path.exists():
                                file_path.unlink()
                        except OSError:
                            pass
            return True
        return False

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

    async def index_message_for_search(
        self, message_id: int, plaintext: str, source: str, source_id: int,
        user_id: int, username: str, has_image: int, created_at: str
    ) -> None:
        """Index a message for full-text search. source='channel' or 'dm'."""
        if not plaintext or not plaintext.strip():
            return
        try:
            if source == "channel":
                fts_table, map_table = "chat_messages_fts", "chat_fts_map"
                id_col = "channel_id"
            else:
                fts_table, map_table = "dm_messages_fts", "dm_fts_map"
                id_col = "conversation_id"
            cursor = await self.conn.execute(
                f"INSERT INTO {fts_table}(message) VALUES (?)", (plaintext,)
            )
            fts_rowid = cursor.lastrowid
            await self.conn.execute(
                f"""INSERT INTO {map_table} (rowid, message_id, {id_col}, user_id, username, has_image, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (fts_rowid, message_id, source_id, user_id, username, has_image, created_at)
            )
            await self.conn.commit()
        except Exception:
            pass

    async def remove_message_from_search(self, message_id: int, source: str) -> None:
        """Remove a message from the search index.

        For contentless FTS5 tables (content=''), the 'delete' command requires
        the original indexed content. Since we only store encrypted text in the
        message tables, we delete the map entry instead. Orphaned FTS rows are
        harmless — they never appear in results because _search_fts JOINs through
        the map table, and any message_id misses are filtered by the msg_row check.
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
        """Update the FTS index for an edited message."""
        await self.remove_message_from_search(message_id, source)
        if not new_plaintext or not new_plaintext.strip():
            return
        try:
            if source == "channel":
                fts_table, map_table = "chat_messages_fts", "chat_fts_map"
                # Fetch channel_id from original message
                cursor = await self.conn.execute(
                    "SELECT channel_id, user_id, username, image_url, created_at FROM chat_messages WHERE id = ?",
                    (message_id,)
                )
            else:
                fts_table, map_table = "dm_messages_fts", "dm_fts_map"
                cursor = await self.conn.execute(
                    "SELECT conversation_id, user_id, username, image_url, created_at FROM dm_messages WHERE id = ?",
                    (message_id,)
                )
            row = await cursor.fetchone()
            if not row:
                return
            row = dict(row)
            source_id = row.get("channel_id") or row.get("conversation_id")
            id_col = "channel_id" if source == "channel" else "conversation_id"
            cur = await self.conn.execute(
                f"INSERT INTO {fts_table}(message) VALUES (?)", (new_plaintext,)
            )
            fts_rowid = cur.lastrowid
            await self.conn.execute(
                f"""INSERT INTO {map_table} (rowid, message_id, {id_col}, user_id, username, has_image, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (fts_rowid, message_id, source_id, row["user_id"], row["username"],
                 1 if row.get("image_url") else 0, row["created_at"])
            )
            await self.conn.commit()
        except Exception:
            pass

    async def search_messages(
        self, query: str, user_id: int, scope: str = "all",
        channel_id: int = None, conversation_id: int = None,
        from_user: str = None, has_image: bool = None,
        before: str = None, after: str = None,
        limit: int = 25, offset: int = 0,
        user_role: str = "user"
    ) -> dict:
        """Search messages across channels and/or DMs. Returns {results, total}."""
        results = []
        total = 0
        fts_query = query.strip()
        if not fts_query:
            return {"results": [], "total": 0}
        # Escape FTS5 special chars to prevent syntax errors
        safe_query = ""
        for ch in fts_query:
            if ch in '"*():-^':
                safe_query += " "
            else:
                safe_query += ch
        # Split into words and rejoin for FTS prefix matching
        words = safe_query.split()
        if not words:
            return {"results": [], "total": 0}
        fts_expr = " ".join(f'"{w}"' for w in words if w)

        # Build set of accessible channel IDs to filter private channels
        accessible_channel_ids = None
        if scope in ("all", "channels") and user_role not in ("admin", "superadmin"):
            try:
                accessible = await self.get_accessible_channels(user_id, user_role)
                accessible_channel_ids = {ch["id"] for ch in accessible}
            except Exception:
                accessible_channel_ids = None  # Fall back to unfiltered on error

        # Search channel messages
        if scope in ("all", "channels"):
            ch_results, ch_total = await self._search_fts(
                "chat_messages_fts", "chat_fts_map", "chat_messages", "channel_id",
                fts_expr, channel_id=channel_id, from_user=from_user,
                has_image=has_image, before=before, after=after,
                limit=offset + limit if scope == "all" else limit,
                offset=offset if scope == "channels" else 0,
                accessible_channel_ids=accessible_channel_ids
            )
            # Batch fetch channel names (avoids N+1)
            ch_ids = list({r.get("source_id") for r in ch_results if r.get("source_id")})
            ch_names = {}
            if ch_ids:
                ph = ",".join("?" * len(ch_ids))
                cur = await self.conn.execute(f"SELECT id, name FROM chat_channels WHERE id IN ({ph})", ch_ids)
                ch_names = {row["id"]: row["name"] for row in await cur.fetchall()}
            for r in ch_results:
                r["source"] = "channel"
                r["source_name"] = f"#{ch_names.get(r.get('source_id'), 'unknown')}"
            results.extend(ch_results)
            total += ch_total

        # Search DM messages (only user's own conversations)
        if scope in ("all", "dms"):
            dm_results, dm_total = await self._search_fts(
                "dm_messages_fts", "dm_fts_map", "dm_messages", "conversation_id",
                fts_expr, conversation_id=conversation_id, from_user=from_user,
                has_image=has_image, before=before, after=after,
                limit=offset + limit if scope == "all" else limit,
                offset=offset if scope == "dms" else 0,
                dm_user_id=user_id
            )
            # Batch fetch DM conversation info (avoids N+1)
            dm_conv_ids = list({r.get("source_id") for r in dm_results if r.get("source_id")})
            dm_conv_map = {}
            if dm_conv_ids:
                ph = ",".join("?" * len(dm_conv_ids))
                cur = await self.conn.execute(f"SELECT id, name FROM dm_conversations WHERE id IN ({ph})", dm_conv_ids)
                dm_conv_map = {row["id"]: row["name"] for row in await cur.fetchall()}
                # Batch fetch participants for DM conversations
                pcur = await self.conn.execute(
                    f"""SELECT dp.conversation_id, u.username, u.nickname
                        FROM dm_participants dp JOIN users u ON u.id = dp.user_id
                        WHERE dp.conversation_id IN ({ph}) AND dp.left_at IS NULL""",
                    dm_conv_ids
                )
                dm_parts: dict[int, list[dict]] = {cid: [] for cid in dm_conv_ids}
                for prow in await pcur.fetchall():
                    dm_parts[prow["conversation_id"]].append(dict(prow))
            for r in dm_results:
                r["source"] = "dm"
                cid = r.get("source_id")
                conv_name = dm_conv_map.get(cid)
                if conv_name:
                    r["source_name"] = conv_name
                elif cid in dm_parts:
                    others = [p["nickname"] or p["username"] for p in dm_parts[cid] if p.get("user_id") != user_id]
                    r["source_name"] = ", ".join(others) or "DM"
                else:
                    r["source_name"] = "DM"
            results.extend(dm_results)
            total += dm_total

        # Sort combined results by date descending, apply limit
        results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        if scope == "all":
            results = results[offset:offset + limit]
        return {"results": results, "total": total}

    async def _search_fts(
        self, fts_table: str, map_table: str, msg_table: str, id_col: str,
        fts_expr: str, channel_id: int = None, conversation_id: int = None,
        from_user: str = None, has_image: bool = None,
        before: str = None, after: str = None,
        limit: int = 25, offset: int = 0, dm_user_id: int = None,
        accessible_channel_ids: set = None
    ) -> tuple[list[dict], int]:
        """Run FTS5 search against a specific table pair. Returns (results, total)."""
        try:
            conditions = [f"{fts_table} MATCH ?"]
            params = [fts_expr]

            if channel_id:
                conditions.append(f"m.{id_col} = ?")
                params.append(channel_id)
            if conversation_id:
                conditions.append(f"m.{id_col} = ?")
                params.append(conversation_id)
            if from_user:
                conditions.append("m.username = ?")
                params.append(from_user)
            if has_image:
                conditions.append("m.has_image = 1")
            if before:
                conditions.append("m.created_at < ?")
                params.append(before)
            if after:
                conditions.append("m.created_at > ?")
                params.append(after)
            # DM security: only search user's conversations
            if dm_user_id:
                conditions.append(
                    f"m.{id_col} IN (SELECT conversation_id FROM dm_participants WHERE user_id = ? AND left_at IS NULL)"
                )
                params.append(dm_user_id)
            # Channel access security: only search channels the user can access
            if accessible_channel_ids is not None:
                if not accessible_channel_ids:
                    return [], 0  # User has no accessible channels
                ph = ",".join("?" * len(accessible_channel_ids))
                conditions.append(f"m.{id_col} IN ({ph})")
                params.extend(accessible_channel_ids)

            where = " AND ".join(conditions)

            # Get total count
            count_sql = f"""SELECT COUNT(*) FROM {fts_table}
                           JOIN {map_table} m ON m.rowid = {fts_table}.rowid
                           WHERE {where}"""
            cursor = await self.conn.execute(count_sql, params)
            row = await cursor.fetchone()
            total = row[0] if row else 0

            if total == 0:
                return [], 0

            # Get results
            search_sql = f"""SELECT m.message_id, m.{id_col} as source_id, m.user_id, m.username,
                                    m.has_image, m.created_at, rank
                             FROM {fts_table}
                             JOIN {map_table} m ON m.rowid = {fts_table}.rowid
                             WHERE {where}
                             ORDER BY rank
                             LIMIT ? OFFSET ?"""
            params_with_pag = params + [limit, offset]
            cursor = await self.conn.execute(search_sql, params_with_pag)
            rows = await cursor.fetchall()

            # Batch fetch message content (avoids N+1)
            msg_ids = [row["message_id"] for row in rows]
            msg_map = {}
            if msg_ids:
                ph = ",".join("?" * len(msg_ids))
                msg_cursor = await self.conn.execute(
                    f"SELECT id, message, image_url FROM {msg_table} WHERE id IN ({ph})", msg_ids
                )
                for mrow in await msg_cursor.fetchall():
                    msg_map[mrow["id"]] = mrow

            results = []
            for row in rows:
                row = dict(row)
                msg_row = msg_map.get(row["message_id"])
                if msg_row:
                    row["message"] = decrypt_message(msg_row["message"])
                    row["has_image"] = 1 if msg_row["image_url"] else 0
                else:
                    row["message"] = ""
                row["id"] = row.pop("message_id")
                results.append(row)
            return results, total
        except Exception:
            return [], 0

    async def rebuild_search_index(self) -> dict:
        """Rebuild all FTS indexes from encrypted messages. Returns counts."""
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

        # Reindex channel messages in batches
        batch_size = 500
        last_id = 0
        while True:
            cursor = await self.conn.execute(
                "SELECT id, channel_id, user_id, username, message, image_url, created_at FROM chat_messages WHERE id > ? ORDER BY id LIMIT ?",
                (last_id, batch_size)
            )
            rows = await cursor.fetchall()
            if not rows:
                break
            for row in rows:
                row = dict(row)
                plaintext = decrypt_message(row["message"])
                if plaintext and plaintext.strip():
                    await self.index_message_for_search(
                        row["id"], plaintext, "channel", row["channel_id"],
                        row["user_id"], row["username"],
                        1 if row.get("image_url") else 0, row["created_at"]
                    )
                    counts["channel"] += 1
                last_id = row["id"]

        # Reindex DM messages in batches
        last_id = 0
        while True:
            cursor = await self.conn.execute(
                "SELECT id, conversation_id, user_id, username, message, image_url, created_at FROM dm_messages WHERE id > ? ORDER BY id LIMIT ?",
                (last_id, batch_size)
            )
            rows = await cursor.fetchall()
            if not rows:
                break
            for row in rows:
                row = dict(row)
                plaintext = decrypt_message(row["message"])
                if plaintext and plaintext.strip():
                    await self.index_message_for_search(
                        row["id"], plaintext, "dm", row["conversation_id"],
                        row["user_id"], row["username"],
                        1 if row.get("image_url") else 0, row["created_at"]
                    )
                    counts["dm"] += 1
                last_id = row["id"]

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
                        "cleanup_interval_hours": 168,  # max 1 week
                    }
                    if key in max_vals and int_val > max_vals[key]:
                        int_val = max_vals[key]
                    value = str(int_val)
                except (ValueError, TypeError):
                    continue
            await self.set_setting(key, value)

    async def cleanup_old_dm_messages(self, days: int = 30) -> int:
        """Delete DM messages older than specified days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        total_deleted = 0
        batch_size = 500
        while True:
            cursor = await self.conn.execute(
                "SELECT id FROM dm_messages WHERE created_at < ? LIMIT ?",
                (cutoff, batch_size)
            )
            batch = [row["id"] for row in await cursor.fetchall()]
            if not batch:
                break
            for msg_id in batch:
                try:
                    await self.remove_message_from_search(msg_id, "dm")
                except Exception:
                    pass
            placeholders = ",".join("?" * len(batch))
            await self.conn.execute(
                f"DELETE FROM dm_reactions WHERE message_id IN ({placeholders})", batch
            )
            await self.conn.execute(
                f"DELETE FROM dm_messages WHERE id IN ({placeholders})", batch
            )
            await self.conn.commit()
            total_deleted += len(batch)
        return total_deleted

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

    async def vacuum_database(self) -> None:
        """Run VACUUM to reclaim disk space."""
        await self.conn.execute("VACUUM")

    async def get_all_service_ids(self) -> list[int]:
        """Get all service IDs for bulk cleanup."""
        cursor = await self.conn.execute("SELECT id FROM services")
        rows = await cursor.fetchall()
        return [row["id"] for row in rows]


# Global database instance
db = Database()
