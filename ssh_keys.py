"""Open Relay Portal - SSH Key Management.

Security Design:
    - Private keys are NEVER stored in the database
    - Private keys are generated in-memory and returned to the user ONCE
    - Only public keys and fingerprints are persisted
    - Users must save their private key immediately as it cannot be recovered
    - Even if the database is compromised, no private keys can be stolen

Supported key types:
    - ed25519: Recommended, modern elliptic curve algorithm (default)
    - rsa: RSA 4096-bit keys for legacy compatibility
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend

from database import db

logger = logging.getLogger("portal.ssh_keys")

# SSH keys directory
SSH_KEYS_DIR = Path(__file__).parent / "ssh_keys"


def ensure_keys_dir():
    """Ensure SSH keys directory exists with proper permissions."""
    SSH_KEYS_DIR.mkdir(mode=0o700, exist_ok=True)


def generate_key_pair(
    key_type: str = "ed25519",
    key_size: int = 4096,
    comment: str = ""
) -> tuple[str, str]:
    """
    Generate an SSH key pair.

    Returns:
        Tuple of (private_key_pem, public_key_openssh)
    """
    if key_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "rsa":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    # Serialize private key (PEM format, no password)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Serialize public key (OpenSSH format)
    public_key = private_key.public_key()
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')

    # Add comment if provided
    if comment:
        public_openssh = f"{public_openssh} {comment}"

    return private_pem, public_openssh


async def create_user_key(
    user_id: int,
    key_name: str,
    key_type: str = "ed25519"
) -> dict:
    """
    Generate and store a new SSH key pair for a user.

    Returns:
        Dict with key info including private key (only returned once)
    """
    ensure_keys_dir()

    # Get user info for comment
    user = await db.get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found")

    comment = f"{user['username']}@portal-{key_name}"

    # Generate key pair
    private_pem, public_openssh = generate_key_pair(key_type, comment=comment)

    # Get fingerprint
    fingerprint = get_key_fingerprint(public_openssh)

    # Store in database
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = await db.conn.execute(
        """INSERT INTO ssh_keys (user_id, name, key_type, public_key, fingerprint, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, key_name, key_type, public_openssh, fingerprint, created_at)
    )
    await db.conn.commit()
    key_id = cursor.lastrowid

    logger.info(f"SSH key '{key_name}' created for user {user['username']} (fingerprint: {fingerprint})")

    return {
        "id": key_id,
        "name": key_name,
        "key_type": key_type,
        "fingerprint": fingerprint,
        "public_key": public_openssh,
        "private_key": private_pem,  # Only returned on creation
        "created_at": created_at
    }


def get_key_fingerprint(public_key: str) -> str:
    """Get SHA256 fingerprint of a public key."""
    import base64
    import hashlib

    # Parse the public key
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid public key format")

    key_data = base64.b64decode(parts[1])
    fingerprint = hashlib.sha256(key_data).digest()
    return "SHA256:" + base64.b64encode(fingerprint).decode('utf-8').rstrip('=')


async def get_user_keys(user_id: int) -> list[dict]:
    """Get all SSH keys for a user."""
    async with db.conn.execute(
        """SELECT id, name, key_type, public_key, fingerprint, created_at, last_used_at
           FROM ssh_keys WHERE user_id = ? ORDER BY created_at DESC""",
        (user_id,)
    ) as cursor:
        rows = await cursor.fetchall()

    return [
        {
            "id": row["id"],
            "name": row["name"],
            "key_type": row["key_type"],
            "public_key": row["public_key"],
            "fingerprint": row["fingerprint"],
            "created_at": row["created_at"],
            "last_used_at": row["last_used_at"]
        }
        for row in rows
    ]


async def get_key_by_id(key_id: int) -> Optional[dict]:
    """Get a specific SSH key by ID."""
    async with db.conn.execute(
        """SELECT id, user_id, name, key_type, public_key, fingerprint, created_at, last_used_at
           FROM ssh_keys WHERE id = ?""",
        (key_id,)
    ) as cursor:
        row = await cursor.fetchone()

    if not row:
        return None

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "key_type": row["key_type"],
        "public_key": row["public_key"],
        "fingerprint": row["fingerprint"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"]
    }


async def delete_user_key(key_id: int, user_id: int) -> bool:
    """Delete an SSH key (user can only delete their own keys)."""
    cursor = await db.conn.execute(
        "DELETE FROM ssh_keys WHERE id = ? AND user_id = ?",
        (key_id, user_id)
    )
    await db.conn.commit()
    deleted = cursor.rowcount > 0

    if deleted:
        logger.info(f"SSH key {key_id} deleted by user {user_id}")

    return deleted


async def admin_delete_key(key_id: int) -> bool:
    """Admin delete any SSH key."""
    key = await get_key_by_id(key_id)
    if not key:
        return False

    cursor = await db.conn.execute(
        "DELETE FROM ssh_keys WHERE id = ?",
        (key_id,)
    )
    await db.conn.commit()

    logger.info(f"SSH key {key_id} (user {key['user_id']}) deleted by admin")
    return cursor.rowcount > 0


async def get_all_keys() -> list[dict]:
    """Get all SSH keys (admin only)."""
    async with db.conn.execute(
        """SELECT k.id, k.user_id, k.name, k.key_type, k.public_key, k.fingerprint,
                  k.created_at, k.last_used_at, u.username
           FROM ssh_keys k
           JOIN users u ON k.user_id = u.id
           ORDER BY k.created_at DESC"""
    ) as cursor:
        rows = await cursor.fetchall()

    return [
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "name": row["name"],
            "key_type": row["key_type"],
            "public_key": row["public_key"],
            "fingerprint": row["fingerprint"],
            "created_at": row["created_at"],
            "last_used_at": row["last_used_at"]
        }
        for row in rows
    ]


async def get_authorized_keys(user_id: int) -> str:
    """Get all public keys for a user in authorized_keys format."""
    keys = await get_user_keys(user_id)
    return "\n".join(key["public_key"] for key in keys)


async def update_key_last_used(key_id: int) -> None:
    """Update last_used_at timestamp for a key."""
    await db.conn.execute(
        "UPDATE ssh_keys SET last_used_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), key_id)
    )
    await db.conn.commit()
