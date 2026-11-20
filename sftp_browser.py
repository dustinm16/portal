"""SFTP browser module for Open Relay Portal.

Provides remote file browsing via user's existing SSH/SFTP connections.
Per-user access enforced by API handlers (connection ownership check).
"""

import asyncio
import json
import logging
from typing import Optional

import asyncssh

import sshpass_rules
from host_check import HostCheckError, resolve_checked_host
from hostkeys import HostKeyRefused, connect_verified, policy_for

logger = logging.getLogger("portal")

# Connection types eligible for SFTP browsing
SFTP_ELIGIBLE_TYPES = {"ssh", "sftp"}


async def connect_sftp(connection: dict, addrs: Optional[list] = None) -> tuple[Optional[asyncssh.SSHClientConnection], Optional[asyncssh.SFTPClient], Optional[str]]:
    """Establish SFTP session from a user_connection record.

    The server's host key is verified against the connection's pin before any
    credential is sent.

    Args:
        connection: User connection dict from database (with decrypted config)
        addrs: already policy-checked addresses to dial; resolved and checked
            here when not given

    Returns:
        (conn, sftp_client, None) on success or (None, None, error_msg) on failure

    Raises:
        HostKeyRefused: the host key is not pinned yet or differs from the pin
            (the caller decides who may accept it)
    """
    config = connection.get("config", {})
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            config = {}

    # Outbound host policy: check what the name resolves to and dial that
    # address, so a later DNS answer cannot differ from the one checked.
    if addrs is None:
        try:
            addrs = await resolve_checked_host(connection["host"], connection.get("port") or 22)
        except HostCheckError:
            logger.warning("SFTP connect refused by outbound host policy")
            return None, None, "Host not allowed"

    connect_opts = {
        "host": addrs[0],   # replaced per attempt by try_each_address below
        "port": connection.get("port") or 22,
        "username": config.get("username", ""),
    }
    pinned, ignore = policy_for(config)

    # Auth method
    private_key = config.get("private_key")
    password = sshpass_rules.sftp_password(config)

    if private_key:
        try:
            connect_opts["client_keys"] = [asyncssh.import_private_key(private_key)]
        except asyncssh.KeyImportError:
            return None, None, "Invalid private key format"
    elif password:
        if ignore:
            # A stored password is never sent to a host whose key is not checked, whatever
            # the mode (a connection without a mode included).
            return None, None, "A stored password is only used with a verified host key"
        connect_opts["password"] = password
    elif sshpass_rules.has_stored_password(config):
        return None, None, "This connection asks for its password each time; the file browser needs a stored password"
    else:
        return None, None, "No credentials configured (need password or private key)"

    try:
        conn, _seen = await connect_verified(
            addrs, connect_opts, pinned=pinned, ignore=ignore, timeout=10)
        sftp = await conn.start_sftp_client()
        return conn, sftp, None
    except HostKeyRefused:
        raise
    except asyncio.TimeoutError:
        return None, None, "Connection timed out"
    except asyncssh.PermissionDenied:
        return None, None, "Authentication failed"
    except asyncssh.Error as e:
        logger.warning(f"SFTP connect SSH error for {connection['host']}: {e}")
        return None, None, "Connection failed"
    except OSError as e:
        logger.warning(f"SFTP connect OS error for {connection['host']}: {e}")
        return None, None, "Connection failed"


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
        logger.error(f"SFTP list directory error for {path}: {e}")
        raise ValueError("SFTP operation failed")


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
        logger.error(f"SFTP read file error for {path}: {e}")
        raise ValueError("SFTP operation failed")


async def write_remote_file(sftp: asyncssh.SFTPClient, path: str, content: bytes) -> None:
    """Write content to a remote file."""
    try:
        async with sftp.open(path, "wb") as f:
            await f.write(content)
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        logger.error(f"SFTP write file error for {path}: {e}")
        raise ValueError("SFTP operation failed")


async def create_remote_directory(sftp: asyncssh.SFTPClient, path: str) -> None:
    """Create a remote directory."""
    try:
        await sftp.mkdir(path)
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        if "already exists" in str(e).lower():
            raise ValueError("Directory already exists")
        logger.error(f"SFTP mkdir error for {path}: {e}")
        raise ValueError("SFTP operation failed")


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
        logger.error(f"SFTP delete error for {path}: {e}")
        raise ValueError("SFTP operation failed")


async def rename_remote_path(sftp: asyncssh.SFTPClient, old_path: str, new_path: str) -> None:
    """Rename/move a remote file or directory."""
    try:
        await sftp.rename(old_path, new_path)
    except asyncssh.SFTPNoSuchFile:
        raise ValueError("Source path not found")
    except asyncssh.SFTPPermissionDenied:
        raise ValueError("Permission denied")
    except asyncssh.SFTPError as e:
        logger.error(f"SFTP rename error for {old_path} -> {new_path}: {e}")
        raise ValueError("SFTP operation failed")


def _format_permissions(mode: int) -> str:
    """Format Unix permission bits to rwx string."""
    import stat
    return stat.filemode(mode)
