"""Local file manager module for Open Relay Portal.

Provides filesystem operations with path traversal protection.
All operations are admin-only (enforced by API handlers in server.py).
"""

import logging
import mimetypes
import os
import shutil
import stat
from pathlib import Path
from pwd import getpwuid
from grp import getgrgid

logger = logging.getLogger("portal")

# Files that should never be served or listed
BLOCKED_FILES = {
    ".env", "admin_credentials.txt", ".claude_test_creds",
    ".git/config", "id_rsa", "id_ed25519",
}


def _validate_path(path: str, root: str) -> Path:
    """Resolve and validate a path is under root and not blocked.

    Args:
        path: The requested path
        root: The allowed root directory

    Returns:
        Resolved Path object

    Raises:
        ValueError: If path traversal detected or path is blocked
    """
    root_path = Path(root).resolve()
    resolved = (root_path / path.lstrip("/")).resolve()

    if not str(resolved).startswith(str(root_path)):
        raise ValueError("Path traversal detected")

    # Check blocked files
    rel = str(resolved.relative_to(root_path))
    name = resolved.name
    if name in BLOCKED_FILES or rel in BLOCKED_FILES:
        raise ValueError("Access to this file is not allowed")

    return resolved


def _file_entry(path: Path) -> dict:
    """Build a file entry dict from a Path."""
    try:
        st = path.lstat()
    except (OSError, PermissionError):
        return {
            "name": path.name,
            "type": "unknown",
            "size": 0,
            "permissions": "",
            "modified": 0,
            "owner": "",
            "group": "",
        }

    if stat.S_ISLNK(st.st_mode):
        ftype = "symlink"
    elif stat.S_ISDIR(st.st_mode):
        ftype = "directory"
    else:
        ftype = "file"

    try:
        owner = getpwuid(st.st_uid).pw_name
    except (KeyError, OverflowError):
        owner = str(st.st_uid)

    try:
        group = getgrgid(st.st_gid).gr_name
    except (KeyError, OverflowError):
        group = str(st.st_gid)

    return {
        "name": path.name,
        "type": ftype,
        "size": st.st_size,
        "permissions": stat.filemode(st.st_mode),
        "modified": st.st_mtime,
        "owner": owner,
        "group": group,
    }


def list_directory(path: str, root: str) -> list[dict]:
    """List directory contents.

    Returns entries sorted: directories first, then files, alphabetically.
    """
    resolved = _validate_path(path, root)

    if not resolved.is_dir():
        raise ValueError("Not a directory")

    entries = []
    try:
        for item in resolved.iterdir():
            # Skip blocked files
            if item.name in BLOCKED_FILES:
                continue
            if item.name.startswith(".env"):
                continue
            entries.append(_file_entry(item))
    except PermissionError:
        raise ValueError("Permission denied")

    # Sort: dirs first, then alphabetical
    entries.sort(key=lambda e: (0 if e["type"] == "directory" else 1, e["name"].lower()))
    return entries


def get_file_info(path: str, root: str) -> dict:
    """Get stat info for a single file/directory."""
    resolved = _validate_path(path, root)

    if not resolved.exists():
        raise FileNotFoundError("File not found")

    entry = _file_entry(resolved)
    entry["path"] = str(resolved)

    # Add MIME type for files
    if entry["type"] == "file":
        mime, _ = mimetypes.guess_type(str(resolved))
        entry["mime_type"] = mime or "application/octet-stream"

    return entry


def read_file(path: str, root: str, max_size: int = 5 * 1024 * 1024) -> bytes:
    """Read file content for inline editing.

    Args:
        path: File path relative to root
        root: Allowed root directory
        max_size: Maximum file size to read (default 5MB)

    Returns:
        File content as bytes

    Raises:
        ValueError: If file too large or not readable
    """
    resolved = _validate_path(path, root)

    if not resolved.is_file():
        raise ValueError("Not a file")

    size = resolved.stat().st_size
    if size > max_size:
        raise ValueError(f"File too large ({size} bytes, max {max_size})")

    try:
        return resolved.read_bytes()
    except PermissionError:
        raise ValueError("Permission denied")


def write_file(path: str, root: str, content: bytes) -> None:
    """Write content to a file."""
    resolved = _validate_path(path, root)

    # Ensure parent directory exists
    resolved.parent.mkdir(parents=True, exist_ok=True)

    try:
        resolved.write_bytes(content)
        logger.info(f"File written: {resolved}")
    except PermissionError:
        raise ValueError("Permission denied")


def create_directory(path: str, root: str) -> None:
    """Create a directory (mkdir -p equivalent)."""
    resolved = _validate_path(path, root)

    try:
        resolved.mkdir(parents=True, exist_ok=True)
        logger.info(f"Directory created: {resolved}")
    except PermissionError:
        raise ValueError("Permission denied")


def delete_path(path: str, root: str, recursive: bool = False) -> None:
    """Delete a file or directory.

    Args:
        path: Path to delete
        root: Allowed root directory
        recursive: If True, recursively delete non-empty directories
    """
    resolved = _validate_path(path, root)

    if not resolved.exists():
        raise FileNotFoundError("Path not found")

    # Don't allow deleting the root itself
    if resolved == Path(root).resolve():
        raise ValueError("Cannot delete the root directory")

    try:
        if resolved.is_dir():
            if recursive:
                shutil.rmtree(str(resolved))
            else:
                resolved.rmdir()  # Only works on empty dirs
        else:
            resolved.unlink()
        logger.info(f"Deleted: {resolved}")
    except OSError as e:
        if "not empty" in str(e).lower() or "directory not empty" in str(e).lower():
            raise ValueError("Directory is not empty. Use recursive=true to delete.")
        raise ValueError(f"Delete failed: {e}")
    except PermissionError:
        raise ValueError("Permission denied")


def rename_path(old_path: str, new_path: str, root: str) -> None:
    """Rename/move a file or directory."""
    old_resolved = _validate_path(old_path, root)
    new_resolved = _validate_path(new_path, root)

    if not old_resolved.exists():
        raise FileNotFoundError("Source not found")

    if new_resolved.exists():
        raise ValueError("Destination already exists")

    try:
        old_resolved.rename(new_resolved)
        logger.info(f"Renamed: {old_resolved} -> {new_resolved}")
    except PermissionError:
        raise ValueError("Permission denied")
    except OSError as e:
        raise ValueError(f"Rename failed: {e}")


def get_mime_type(path: str, root: str) -> str:
    """Detect MIME type for a file."""
    resolved = _validate_path(path, root)
    mime, _ = mimetypes.guess_type(str(resolved))
    return mime or "application/octet-stream"


def is_text_file(path: str, root: str) -> bool:
    """Check if a file is likely a text file."""
    resolved = _validate_path(path, root)
    mime = get_mime_type(path, root)

    if mime.startswith("text/"):
        return True

    text_mimes = {
        "application/json", "application/xml", "application/javascript",
        "application/x-yaml", "application/toml", "application/x-sh",
        "application/x-python", "application/sql",
    }
    if mime in text_mimes:
        return True

    # Check extension
    text_extensions = {
        ".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".fish",
        ".md", ".txt", ".log", ".sql", ".env.example", ".gitignore",
        ".dockerfile", ".service", ".timer", ".csv", ".tsv",
    }
    return resolved.suffix.lower() in text_extensions
