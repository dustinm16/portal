"""SFTP browser module for Open Relay Portal.

Provides remote file browsing via user's existing SSH/SFTP connections.
Per-user access enforced by API handlers (connection ownership check).
"""

import asyncio
import json
import logging
from typing import Optional

import asyncssh

logger = logging.getLogger("portal")

# Connection types eligible for SFTP browsing
SFTP_ELIGIBLE_TYPES = {"ssh", "sftp"}


async def connect_sftp(connection: dict) -> tuple[Optional[asyncssh.SSHClientConnection], Optional[asyncssh.SFTPClient], Optional[str]]:
    """Establish SFTP session from a user_connection record.

    Args:
        connection: User connection dict from database (with decrypted config)

    Returns:
        (conn, sftp_client, None) on success or (None, None, error_msg) on failure
    """
    config = connection.get("config", {})
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            config = {}

    connect_opts = {
        "host": connection["host"],
        "port": connection.get("port") or 22,
        "username": config.get("username", ""),
        "known_hosts": None,
    }

    # Auth method
    private_key = config.get("private_key")
    password = config.get("password")

    if private_key:
        try:
            connect_opts["client_keys"] = [asyncssh.import_private_key(private_key)]
        except asyncssh.KeyImportError:
            return None, None, "Invalid private key format"
    elif password:
        connect_opts["password"] = password
    else:
        return None, None, "No credentials configured (need password or private key)"

    try:
        conn = await asyncio.wait_for(asyncssh.connect(**connect_opts), timeout=10)
        sftp = await conn.start_sftp_client()
        return conn, sftp, None
    except asyncio.TimeoutError:
        return None, None, "Connection timed out"
    except asyncssh.PermissionDenied:
        return None, None, "Authentication failed"
    except asyncssh.Error as e:
        return None, None, f"SSH error: {e}"
    except OSError as e:
        return None, None, f"Connection error: {e}"


async def list_remote_directory(sftp: asyncssh.SFTPClient, path: str) -> list[dict]:
    """List remote directory contents.

    Returns entries sorted: directories first, then files, alphabetically.
    """
    try:
        entries = []
        for item in await sftp.readdir(path):
            name = item.filename
            if name in (".", ".."):
                continue

            attrs = item.attrs
            is_dir = attrs.type == asyncssh.FILEXFER_TYPE_DIRECTORY if attrs.type is not None else False

            entries.append({
                "name": name,
                "type": "directory" if is_dir else "file",
                "size": attrs.size or 0,
                "permissions": _format_permissions(attrs.permissions) if attrs.permissions is not None else "",
                "modified": attrs.mtime or 0,
            })

        entries.sort(key=lambda e: (0 if e["type"] == "directory" else 1, e["name"].lower()))
        return entries
    except asyncssh.SFTPNoSuchFile:
        raise ValueError("Directory not found")
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        raise ValueError(f"SFTP error: {e}")


async def read_remote_file(sftp: asyncssh.SFTPClient, path: str, max_size: int = 5 * 1024 * 1024) -> bytes:
    """Read remote file content for inline editing.

    Args:
        sftp: SFTP client
        path: Remote file path
        max_size: Maximum file size (default 5MB)
    """
    try:
        attrs = await sftp.stat(path)
        if attrs.size and attrs.size > max_size:
            raise ValueError(f"File too large ({attrs.size} bytes, max {max_size})")

        async with sftp.open(path, "rb") as f:
            return await f.read(max_size)
    except asyncssh.SFTPNoSuchFile:
        raise ValueError("File not found")
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        raise ValueError(f"SFTP error: {e}")


async def write_remote_file(sftp: asyncssh.SFTPClient, path: str, content: bytes) -> None:
    """Write content to a remote file."""
    try:
        async with sftp.open(path, "wb") as f:
            await f.write(content)
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        raise ValueError(f"SFTP error: {e}")


async def create_remote_directory(sftp: asyncssh.SFTPClient, path: str) -> None:
    """Create a remote directory."""
    try:
        await sftp.mkdir(path)
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        if "already exists" in str(e).lower():
            raise ValueError("Directory already exists")
        raise ValueError(f"SFTP error: {e}")


async def delete_remote_path(sftp: asyncssh.SFTPClient, path: str) -> None:
    """Delete a remote file or empty directory."""
    try:
        attrs = await sftp.stat(path)
        if attrs.type == asyncssh.FILEXFER_TYPE_DIRECTORY:
            await sftp.rmdir(path)
        else:
            await sftp.remove(path)
    except asyncssh.SFTPNoSuchFile:
        raise ValueError("Path not found")
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        if "not empty" in str(e).lower():
            raise ValueError("Directory is not empty")
        raise ValueError(f"SFTP error: {e}")


async def rename_remote_path(sftp: asyncssh.SFTPClient, old_path: str, new_path: str) -> None:
    """Rename/move a remote file or directory."""
    try:
        await sftp.rename(old_path, new_path)
    except asyncssh.SFTPNoSuchFile:
        raise ValueError("Source path not found")
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        raise ValueError(f"SFTP error: {e}")


def _format_permissions(mode: int) -> str:
    """Format Unix permission bits to rwx string."""
    import stat
    return stat.filemode(mode)
