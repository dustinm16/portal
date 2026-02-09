"""Database layer for Open Relay Portal using SQLite."""

import json

import aiosqlite
import base64
import hashlib
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from config import Config

# Message encryption using Fernet-like scheme with AES
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def get_chat_encryption_key() -> bytes:
    """Generate encryption key from JWT_SECRET."""
    secret = Config.JWT_SECRET.encode() if Config.JWT_SECRET else b"default-secret"
    # Use PBKDF2 to derive a Fernet-compatible key
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"portal-chat-salt",
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
        return key
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_message(plaintext: str) -> str:
    """Encrypt a chat message."""
    if not CRYPTO_AVAILABLE or not plaintext:
        return plaintext
    try:
        f = Fernet(get_chat_encryption_key())
        return f.encrypt(plaintext.encode()).decode()
    except Exception:
        return plaintext


def decrypt_message(ciphertext: str) -> str:
    """Decrypt a chat message."""
    if not CRYPTO_AVAILABLE or not ciphertext:
        return ciphertext
    try:
        f = Fernet(get_chat_encryption_key())
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        # Return as-is if decryption fails (might be unencrypted legacy message)
        return ciphertext


# --- Connection config encryption (separate key from chat) ---

def get_config_encryption_key() -> bytes:
    """Generate encryption key for connection configs (separate from chat key)."""
    secret = Config.JWT_SECRET.encode() if Config.JWT_SECRET else b"default-secret"
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"portal-config-salt",
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
        return key
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def encrypt_config(config_json: str) -> str:
    """Encrypt a connection config JSON string.

    Encrypted values are prefixed with 'enc:' to distinguish from legacy plaintext.
    """
    if not CRYPTO_AVAILABLE or not config_json or config_json == "{}":
        return config_json
    try:
        f = Fernet(get_config_encryption_key())
        return "enc:" + f.encrypt(config_json.encode()).decode()
    except Exception:
        return config_json


def decrypt_config(data: str) -> str:
    """Decrypt a connection config string.

    Handles both encrypted ('enc:' prefixed) and legacy plaintext values.
    """
    if not data or not data.startswith("enc:"):
        return data  # Not encrypted (legacy or empty)
    try:
        f = Fernet(get_config_encryption_key())
        return f.decrypt(data[4:].encode()).decode()
    except Exception:
        return "{}"  # Decryption failed


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
        FOREIGN KEY (service_id) REFERENCES managed_services(id) ON DELETE CASCADE
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
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()
        await self._run_migrations()

    async def _run_migrations(self) -> None:
        """Run database migrations for schema updates."""
        for migration in MIGRATIONS:
            try:
                await self._connection.execute(migration)
                await self._connection.commit()
            except Exception:
                # Column likely already exists
                pass

        # Generate public keys for any streams that don't have one
        await self._populate_stream_public_keys()

        # Encrypt any plaintext configs (one-time migration)
        await self._migrate_encrypt_configs()

        # Encrypt any plaintext stream keys (one-time migration)
        await self._migrate_encrypt_stream_keys()

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
            except Exception:
                pass  # Table might not exist yet
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
        except Exception:
            return  # Table might not exist yet

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
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Get user by ID."""
        cursor = await self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # Two-Factor Authentication operations
    async def set_user_totp_secret(self, user_id: int, secret: str) -> None:
        """Store TOTP secret for user (before enabling 2FA)."""
        await self.conn.execute(
            "UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?",
            (secret, datetime.now(timezone.utc).isoformat(), user_id)
        )
        await self.conn.commit()

    async def enable_user_totp(self, user_id: int, backup_codes: list[str]) -> None:
        """Enable TOTP for user and store backup codes."""
        codes_str = ",".join(backup_codes)
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
        """Use a backup code, removing it from available codes. Returns True if valid."""
        user = await self.get_user_by_id(user_id)
        if not user or not user.get("backup_codes"):
            return False
        codes = user["backup_codes"].split(",")
        code_upper = code.upper().strip()
        if code_upper in codes:
            codes.remove(code_upper)
            await self.conn.execute(
                "UPDATE users SET backup_codes = ?, updated_at = ? WHERE id = ?",
                (",".join(codes), datetime.now(timezone.utc).isoformat(), user_id)
            )
            await self.conn.commit()
            return True
        return False

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
        internal_url: str = None,
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
        if internal_url is not None:
            updates.append("internal_url = ?")
            params.append(internal_url)
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
    ) -> int:
        """Create a new user connection and return its ID."""
        encrypted_config = encrypt_config(config) if config else "{}"
        cursor = await self.conn.execute(
            """INSERT INTO user_connections
               (user_id, name, type, host, port, config, ssh_key_id, icon, portal_access, api_access)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, conn_type, host, port, encrypted_config, ssh_key_id, icon, portal_access, api_access)
        )
        await self.conn.commit()
        return cursor.lastrowid

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
        query += " ORDER BY us.is_live DESC, us.viewer_count DESC, us.created_at DESC"

        cursor = await self.conn.execute(query)
        rows = await cursor.fetchall()
        return [self._decrypt_stream_keys(dict(row)) for row in rows]

    async def get_open_streams(self) -> list[dict]:
        """Get streams that allow unauthenticated public access."""
        query = """SELECT us.*, u.username as owner_username, u.nickname as owner_nickname
                   FROM user_streams us
                   LEFT JOIN users u ON us.user_id = u.id
                   WHERE us.is_public = 1 AND us.allow_unauthenticated = 1
                   ORDER BY us.is_live DESC, us.viewer_count DESC, us.created_at DESC"""
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
                         "allow_unauthenticated"}
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
            "UPDATE user_streams SET is_live = 0, viewer_count = 0, updated_at = ? WHERE is_live = 1",
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
            storage["config"] = decrypt_config(raw_config)
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

        existing = await self.get_vod_storage(user_id)
        now = datetime.now(timezone.utc).isoformat()

        if existing:
            allowed = {"name", "host", "port", "username", "auth_method",
                       "remote_path", "config"}
            updates = {k: v for k, v in kwargs.items() if k in allowed}
            updates["updated_at"] = now
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [user_id]
            await self.conn.execute(
                f"UPDATE vod_storage SET {set_clause} WHERE user_id = ?",
                values
            )
            await self.conn.commit()
            return existing["id"]
        else:
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
            cursor = await self.conn.execute(
                f"INSERT INTO vod_storage ({columns}) VALUES ({placeholders})",
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

    async def create_chat_channel(self, name: str, description: str = None, created_by: int = None) -> int:
        """Create a new chat channel."""
        cursor = await self.conn.execute(
            "INSERT INTO chat_channels (name, description, created_by) VALUES (?, ?, ?)",
            (name, description, created_by)
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_chat_channel(self, channel_id: int, **kwargs) -> bool:
        """Update a chat channel."""
        allowed_fields = {"name", "description", "topic"}
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
        reply_preview_text: str = None
    ) -> int:
        """Create a new chat message (encrypted)."""
        encrypted_message = encrypt_message(message)
        # Explicitly store UTC timestamp with timezone info
        created_at = datetime.now(timezone.utc).isoformat()
        cursor = await self.conn.execute(
            """INSERT INTO chat_messages (channel_id, user_id, username, message, message_type, created_at, anonymous, reply_to, image_url, reply_preview_username, reply_preview_text)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (channel_id, user_id, username, encrypted_message, message_type, created_at, int(anonymous), reply_to, image_url, reply_preview_username, reply_preview_text)
        )
        await self.conn.commit()
        return cursor.lastrowid

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
            return msg
        return None

    async def delete_chat_message(self, message_id: int, user_id: int = None) -> bool:
        """Delete a chat message (optionally verify ownership)."""
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
        return cursor.rowcount > 0

    async def cleanup_old_chat_messages(self, days: int = 7) -> int:
        """Delete chat messages older than specified days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cursor = await self.conn.execute(
            "DELETE FROM chat_messages WHERE created_at < ?",
            (cutoff,)
        )
        await self.conn.commit()
        return cursor.rowcount

    async def clear_channel_messages(self, channel_id: int) -> int:
        """Delete all messages in a channel. Returns count deleted."""
        cursor = await self.conn.execute(
            "DELETE FROM chat_messages WHERE channel_id = ?",
            (channel_id,)
        )
        await self.conn.commit()
        return cursor.rowcount

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

    async def get_recent_activity(self, limit: int = 20, offset: int = 0,
                                   user_id: int = None) -> list[dict]:
        """Get recent activity entries. If user_id is specified, filter to that user only."""
        if user_id:
            cursor = await self.conn.execute(
                """SELECT * FROM activity_log WHERE user_id = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (user_id, limit, offset)
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


# Global database instance
db = Database()
