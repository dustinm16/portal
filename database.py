"""Database layer for Portal Gateway using SQLite."""

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
]


class Database:
    """Async database operations for Portal Gateway."""

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
    async def create_user(self, username: str, password_hash: str, is_admin: bool = False) -> int:
        """Create a new user and return their ID."""
        cursor = await self.conn.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, password_hash, int(is_admin))
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
        category_id: int = None
    ) -> int:
        """Create a new service and return its ID."""
        import json
        cursor = await self.conn.execute(
            """INSERT INTO services (name, plugin, path, host, port, config, required_scopes, icon, category_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name,
                plugin,
                path,
                host,
                port,
                json.dumps(config or {}),
                ",".join(required_scopes or []),
                icon,
                category_id
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
        # Parse JSON config
        config_str = service.get("config", "{}")
        try:
            service["config"] = json.loads(config_str) if config_str else {}
        except json.JSONDecodeError:
            service["config"] = {}
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
        """Delete a service by ID."""
        cursor = await self.conn.execute(
            "DELETE FROM services WHERE id = ?", (service_id,)
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
        icon: str = "link"
    ) -> int:
        """Create a new user connection and return its ID."""
        cursor = await self.conn.execute(
            """INSERT INTO user_connections
               (user_id, name, type, host, port, config, ssh_key_id, icon)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, conn_type, host, port, config, ssh_key_id, icon)
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
                conn["config"] = json.loads(conn.get("config", "{}"))
            except json.JSONDecodeError:
                conn["config"] = {}
            return conn
        return None

    async def get_user_connections(self, user_id: int) -> list[dict]:
        """Get all connections for a user."""
        cursor = await self.conn.execute(
            """SELECT uc.*, sk.name as ssh_key_name, sk.fingerprint as ssh_key_fingerprint
               FROM user_connections uc
               LEFT JOIN ssh_keys sk ON uc.ssh_key_id = sk.id
               WHERE uc.user_id = ?
               ORDER BY uc.name""",
            (user_id,)
        )
        rows = await cursor.fetchall()
        import json
        connections = []
        for row in rows:
            conn = dict(row)
            try:
                conn["config"] = json.loads(conn.get("config", "{}"))
            except json.JSONDecodeError:
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
        allowed_fields = {"name", "type", "host", "port", "config", "ssh_key_id", "icon"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False

        # Convert config dict to JSON if needed
        if "config" in updates and isinstance(updates["config"], dict):
            import json
            updates["config"] = json.dumps(updates["config"])

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
                conn["config"] = json.loads(conn.get("config", "{}"))
            except json.JSONDecodeError:
                conn["config"] = {}
            connections.append(conn)
        return connections

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
        message_type: str = "message"
    ) -> int:
        """Create a new chat message (encrypted)."""
        encrypted_message = encrypt_message(message)
        cursor = await self.conn.execute(
            """INSERT INTO chat_messages (channel_id, user_id, username, message, message_type)
               VALUES (?, ?, ?, ?, ?)""",
            (channel_id, user_id, username, encrypted_message, message_type)
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


# Global database instance
db = Database()
