"""Local staging folder for VOD chunks that are waiting to be uploaded.

Pure filesystem helpers with no dependency on the server module, so they can be
tested on their own. The folder holds one sub-directory per recording session;
each session directory holds the ffmpeg chunk files plus a small session.json
that says where the chunks have to go, so a restart can finish the upload.
"""

import errno
import ipaddress
import json
import logging
import os
import pwd
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("portal")

# Refuse to start a new recording session below this much free space (the default of the
# setting vod_min_free_gb; the server reads the setting, this value is only the fallback).
MIN_FREE_BYTES = 1024 * 1024 * 1024
# Defaults of the settings vod_min_free_gb, vod_max_backlog_gb (gigabytes, 0 = check off) and
# vod_orphan_max_age_days (0 = never remove by age).
DEFAULT_MIN_FREE_GB = 1.0
DEFAULT_MAX_BACKLOG_GB = 2.0
DEFAULT_ORPHAN_MAX_AGE_DAYS = 14

# Where older releases kept the staging folder.
LEGACY_DIR = "/tmp/portal_vods"

SIDECAR_NAME = "session.json"

# Written into a staging folder when the portal creates (or adopts) it. A
# non-empty folder without it is somebody else's and is never used.
MARKER_NAME = ".portal_vod_staging"

# Chunks that can never be delivered are removed after this long.
STALE_SECONDS = 14 * 24 * 3600
STALE_DAYS = 14
# A custom staging folder may not be at or below these: a service with
# PrivateTmp gets a fresh, empty one on every restart.
TEMP_ROOTS = ("/tmp", "/var/tmp")
_CHUNK_RE = re.compile(r"^chunk_(\d+)\.mkv$")
_COPY_BLOCK = 1024 * 1024


def _inside(path: str, parent: str) -> bool:
    path = os.path.realpath(path)
    parent = os.path.realpath(parent)
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def dangerous_reason(path: str, project_root: Optional[str] = None, allow_temp: bool = False) -> Optional[str]:
    """Why *path* must never be a staging folder, or None.

    The staging folder gets its mode changed and its empty sub-folders removed,
    so it has to be a folder of its own: not the filesystem root, a mount point
    root, a shared temp folder, anything below /tmp or /var/tmp, a home
    directory or the project folder. *allow_temp* skips the below-/tmp rule; it
    is for the portal's own default location, which the operator chose by
    installing the portal there.
    """
    real = os.path.realpath(path)
    if real == os.sep:
        return "it is the filesystem root"
    try:
        if os.path.ismount(real):
            return "it is the root of a mounted filesystem"
    except OSError:
        pass
    shared = {os.path.realpath(p) for p in ("/tmp", "/var/tmp", tempfile.gettempdir())}
    if real in shared:
        return "it is a shared temporary folder"
    for root in () if allow_temp else TEMP_ROOTS:
        if _inside(real, root):
            return f"it is inside {root}, which a service with PrivateTmp loses on restart"
    homes = set()
    try:
        homes.add(os.path.realpath(os.path.expanduser("~")))
        homes.update(os.path.realpath(e.pw_dir) for e in pwd.getpwall() if e.pw_dir)
    except (KeyError, OSError):
        pass
    if real in homes:
        return "it is a home directory"
    if project_root and real == os.path.realpath(project_root):
        return "it is the portal's project folder"
    return None


def has_marker(path: str) -> bool:
    """True when *path* carries the marker the portal writes into its own staging folder."""
    try:
        st = os.lstat(os.path.join(path, MARKER_NAME))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()


def _write_marker(path: str) -> None:
    try:
        fd = os.open(os.path.join(path, MARKER_NAME), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("Created by the portal for VOD chunks that are waiting to be uploaded.\n")


def ensure_private_dir(path: str, forbidden_roots: tuple = (), project_root: Optional[str] = None,
                       adopt_nonempty: bool = False, allow_temp: bool = False) -> None:
    """Create *path* as a 0700 directory owned by this user, or raise ValueError.

    Refuses a symlink, a non-directory, a directory owned by someone else, any
    location inside one of *forbidden_roots* (for example the folder the static
    route serves), a dangerous location (see dangerous_reason) and an existing
    non-empty folder that the portal did not create (no marker file). An empty
    existing folder is adopted. *adopt_nonempty* also adopts a non-empty one;
    it is for the portal's own default location only, as is *allow_temp* (which
    permits a location below /tmp or /var/tmp). A refused folder is never
    changed in any way.
    """
    path = os.path.abspath(path)
    for root in forbidden_roots:
        if root and _inside(path, str(root)):
            raise ValueError(f"{path} is inside {root}, which the web server serves")
    reason = dangerous_reason(path, project_root, allow_temp)
    if reason:
        raise ValueError(f"{path} cannot be used: {reason}")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        parent = os.path.dirname(path)
        os.makedirs(parent, exist_ok=True)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{path} is a symbolic link")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{path} is not a directory")
    if st.st_uid != os.geteuid():
        raise ValueError(f"{path} is owned by uid {st.st_uid}, expected {os.geteuid()}")
    for root in forbidden_roots:
        if root and _inside(path, str(root)):
            raise ValueError(f"{path} resolves inside {root}, which the web server serves")
    if not has_marker(path) and not adopt_nonempty:
        try:
            nonempty = any(True for _ in os.scandir(path))
        except OSError as e:
            raise ValueError(f"{path} cannot be read: {e}")
        if nonempty:
            raise ValueError(
                f"{path} is not empty and was not created by the portal (no {MARKER_NAME} file)"
            )
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    _write_marker(path)


def free_bytes(path: str) -> int:
    return shutil.disk_usage(path).free


def has_free_space(path: str, min_bytes: int = MIN_FREE_BYTES) -> tuple:
    """Return (enough, free_bytes) for the filesystem holding *path*."""
    free = free_bytes(path)
    return free >= min_bytes, free


def format_size(n: int) -> str:
    return f"{n / (1024 * 1024):.0f} MB" if n < 1024 ** 3 else f"{n / 1024 ** 3:.1f} GB"


# ---------------------------------------------------------------------------
# Session sidecar
# ---------------------------------------------------------------------------

def write_sidecar(session_dir: str, info: dict) -> None:
    """Write session.json (0600, never through a symlink, never over a file)."""
    path = os.path.join(session_dir, SIDECAR_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(info, fh)


def read_sidecar(session_dir: str) -> Optional[dict]:
    """Return the sidecar dict, or None when it is missing or unusable."""
    path = os.path.join(session_dir, SIDECAR_NAME)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("user_id"), int) or not isinstance(data.get("remote_session_dir"), str):
        return None
    if not data["remote_session_dir"]:
        return None
    return data


def list_session_dirs(root: str) -> list:
    """Session directories under *root*: real directories owned by this user."""
    out = []
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return out
    uid = os.geteuid()
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_uid == uid:
                out.append(entry.path)
        except OSError:
            continue
    return out


def chunk_files(session_dir: str) -> list:
    try:
        return sorted(
            e.path for e in os.scandir(session_dir)
            if _CHUNK_RE.match(e.name) and e.is_file(follow_symlinks=False)
        )
    except OSError:
        return []


def next_free_chunk_number(root: str, remote_session_dir: str, current_dir: Optional[str] = None) -> int:
    """One past the highest chunk number still waiting locally for *remote_session_dir*.

    A new session resuming at the remote's highest number would otherwise reuse a
    number that an earlier session left behind unuploaded.
    """
    highest = -1
    for d in list_session_dirs(root):
        if current_dir and os.path.abspath(d) == os.path.abspath(current_dir):
            continue
        meta = read_sidecar(d)
        if not meta or meta["remote_session_dir"] != remote_session_dir:
            continue
        for f in chunk_files(d):
            m = _CHUNK_RE.match(os.path.basename(f))
            if m:
                highest = max(highest, int(m.group(1)))
    return highest + 1


def remove_if_empty(session_dir: str) -> bool:
    """Remove a session directory that holds nothing but its sidecar."""
    try:
        names = os.listdir(session_dir)
    except OSError:
        return False
    if any(n != SIDECAR_NAME for n in names):
        return False
    try:
        if SIDECAR_NAME in names:
            os.unlink(os.path.join(session_dir, SIDECAR_NAME))
        os.rmdir(session_dir)
        return True
    except OSError:
        return False


def newest_mtime(session_dir: str) -> float:
    """Newest modification time among the chunks and the session record (folder time if none)."""
    newest = None
    try:
        for e in os.scandir(session_dir):
            if e.name == SIDECAR_NAME or _CHUNK_RE.match(e.name):
                try:
                    m = e.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                newest = m if newest is None else max(newest, m)
        if newest is None:
            newest = os.lstat(session_dir).st_mtime
    except OSError:
        return time.time()
    return newest


def is_stale(session_dir: str, now: Optional[float] = None, max_age: float = STALE_SECONDS) -> bool:
    return ((now if now is not None else time.time()) - newest_mtime(session_dir)) >= max_age


def remove_stale_session(session_dir: str) -> tuple:
    """Delete the chunk files and the session record of one session, then the folder if it is empty.

    Never recurses and never follows links. Returns (chunks_removed, bytes_removed).
    """
    count = 0
    size = 0
    for c in chunk_files(session_dir):
        try:
            n = os.lstat(c).st_size
            os.unlink(c)
        except OSError:
            continue
        count += 1
        size += n
    try:
        os.unlink(os.path.join(session_dir, SIDECAR_NAME))
    except OSError:
        pass
    try:
        os.rmdir(session_dir)
    except OSError:
        pass
    return count, size


# ---------------------------------------------------------------------------
# Migration from the old /tmp location
# ---------------------------------------------------------------------------

def _copy_tree_nofollow(src: str, dst: str) -> None:
    """Copy regular files and directories only. Symlinks and special files are skipped."""
    os.mkdir(dst, 0o700)
    for entry in os.scandir(src):
        target = os.path.join(dst, entry.name)
        if entry.is_symlink():
            logger.warning("VOD staging migration: skipped symbolic link %s", entry.path)
            continue
        if entry.is_dir(follow_symlinks=False):
            _copy_tree_nofollow(entry.path, target)
        elif entry.is_file(follow_symlinks=False):
            in_fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    while True:
                        block = os.read(in_fd, _COPY_BLOCK)
                        if not block:
                            break
                        view = memoryview(block)
                        while view:
                            view = view[os.write(out_fd, view):]
                    os.fsync(out_fd)
                finally:
                    os.close(out_fd)
            finally:
                os.close(in_fd)
        else:
            logger.warning("VOD staging migration: skipped special file %s", entry.path)


def migrate_legacy(new_dir: str, legacy_dir: str = LEGACY_DIR) -> dict:
    """Move session directories from *legacy_dir* into *new_dir*.

    Each session directory is renamed when both folders share a filesystem and
    copied (then deleted) otherwise. Symbolic links are never followed, an entry
    that already exists in *new_dir* is never overwritten, and a legacy folder
    that is a symlink or belongs to another user is left alone. Returns
    {"moved": [...], "skipped": [(name, reason), ...]}.
    """
    result = {"moved": [], "skipped": []}
    try:
        st = os.lstat(legacy_dir)
    except OSError:
        return result
    if os.path.abspath(legacy_dir) == os.path.abspath(new_dir):
        return result
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        result["skipped"].append((legacy_dir, "not a plain directory"))
        return result
    if st.st_uid != os.geteuid():
        result["skipped"].append((legacy_dir, f"owned by uid {st.st_uid}"))
        return result
    try:
        entries = sorted(os.scandir(legacy_dir), key=lambda e: e.name)
    except OSError as e:
        result["skipped"].append((legacy_dir, str(e)))
        return result
    for entry in entries:
        name = entry.name
        target = os.path.join(new_dir, name)
        try:
            if entry.is_symlink():
                result["skipped"].append((name, "symbolic link"))
                continue
            if not entry.is_dir(follow_symlinks=False):
                result["skipped"].append((name, "not a directory"))
                continue
            if entry.stat(follow_symlinks=False).st_uid != st.st_uid:
                result["skipped"].append((name, "owned by another user"))
                continue
            if os.path.lexists(target):
                result["skipped"].append((name, "already exists in the new folder"))
                continue
            try:
                os.rename(entry.path, target)
            except OSError as e:
                if e.errno != errno.EXDEV:
                    raise
                try:
                    _copy_tree_nofollow(entry.path, target)
                except Exception:
                    shutil.rmtree(target, ignore_errors=True)
                    raise
                shutil.rmtree(entry.path)
            os.chmod(target, 0o700)
            result["moved"].append(name)
        except Exception as e:  # keep going: one bad session must not block the rest
            result["skipped"].append((name, f"{type(e).__name__}: {e}"))
    try:
        os.rmdir(legacy_dir)
    except OSError:
        pass
    return result


# ---------------------------------------------------------------------------
# Recorder output arguments (shared by the recorder and by the tests)
# ---------------------------------------------------------------------------

def segment_args(session_dir: str, start_number: int, segment_seconds: int) -> list:
    """ffmpeg output arguments that cut the input into MKV chunks, without re-encoding.

    The recorder puts its input arguments in front of these; a test puts a local file or a
    generated source there instead, so both write chunks in exactly the same way.
    """
    return [
        "-c", "copy",
        "-f", "segment",
        "-segment_time", str(segment_seconds),
        "-segment_format", "matroska",
        "-segment_start_number", str(start_number),
        "-reset_timestamps", "1",
        os.path.join(session_dir, "chunk_%03d.mkv"),
    ]


# ---------------------------------------------------------------------------
# Disk guard: free space and backlog of the staging folder
# ---------------------------------------------------------------------------

def _chunk_size(path: str) -> int:
    try:
        return os.lstat(path).st_size
    except OSError:
        return 0


def backlog_bytes(session_dir: str, live: bool = False) -> int:
    """Bytes of chunks waiting in one session folder.

    For the folder a recording is writing to (*live*), the newest chunk is the one ffmpeg is
    still filling, so it is left out: only completed chunks that the uploader has not yet
    delivered count as waiting. Every chunk of a finished (orphan) folder counts.
    """
    files = chunk_files(session_dir)
    if live and files:
        files = files[:-1]
    return sum(_chunk_size(f) for f in files)


def total_backlog_bytes(root: str, live_dirs=(), owner_id: Optional[int] = None) -> int:
    """Bytes waiting in all session folders under *root*, or, with *owner_id*, in that owner's folders only.

    A folder belongs to the user named in its session record; a folder without a usable record
    belongs to nobody and is left out of an owner's count (the free-space floor still covers it).
    """
    live = {os.path.abspath(d) for d in live_dirs}
    total = 0
    for d in list_session_dirs(root):
        if owner_id is not None:
            meta = read_sidecar(d)
            if not meta or meta.get("user_id") != owner_id:
                continue
        total += backlog_bytes(d, os.path.abspath(d) in live)
    return total


def guard_verdict(root: str, min_free: int, max_backlog: int, live_dirs=(), own_dir: Optional[str] = None,
                  owner_id: Optional[int] = None):
    """Why a recording must not run (or start), as (code, text), or None when all is well.

    *min_free* and *max_backlog* are bytes, 0 switches that check off. *live_dirs* are the
    session folders of running recordings (their unfinished chunk is not backlog); *own_dir*
    is the recording being checked (None for a recording that has not started). The free-space
    floor is global; the backlog limit is counted for *owner_id* alone (the owner's own waiting
    chunks across their folders), so one member's unreachable storage cannot stop other members'
    recordings. Without *owner_id* every folder counts (a caller that does not know the owner).
    """
    try:
        free = free_bytes(root)
    except OSError:
        free = None
    if min_free and free is not None and free < min_free:
        return ("low_free_space",
                f"only {format_size(free)} free in the VOD staging folder (needs {format_size(min_free)})")
    if max_backlog:
        if own_dir:
            own = backlog_bytes(own_dir, True)
            if own > max_backlog:
                return ("session_backlog",
                        f"{format_size(own)} of this recording is waiting to be uploaded "
                        f"(limit {format_size(max_backlog)})")
        total = total_backlog_bytes(root, live_dirs, owner_id)
        if total > max_backlog:
            whose = "of your recordings" if owner_id is not None else "of recordings"
            return ("total_backlog",
                    f"{format_size(total)} {whose} are waiting to be uploaded "
                    f"(limit {format_size(max_backlog)})")
    return None


def gb_setting(raw, default: float) -> float:
    """A gigabyte setting as a number (0 or more); anything unusable gives *default*."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value != value or value < 0 or value > 10_000_000:
        return default
    return value


def int_setting(raw, default: int, maximum: int = 3650) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return default if value < 0 else min(value, maximum)


# ---------------------------------------------------------------------------
# Remote numbering for the sweep
# ---------------------------------------------------------------------------

_REMOTE_INDEX_RE = re.compile(r"^chunk_(\d+)")


def highest_remote_index(names) -> int:
    """Highest chunk number among the names of one remote folder, or -1.

    Any name that starts with chunk_NNN counts: a finished chunk, a ".part" left by a crash and
    a "_recovered" copy all hold their number. Gaps are never filled.
    """
    highest = -1
    for name in names:
        m = _REMOTE_INDEX_RE.match(str(name))
        if m:
            highest = max(highest, int(m.group(1)))
    return highest


def is_loopback_host(host: str) -> bool:
    """True for the literal name localhost and for an IP literal in the loopback range (IPv4 or IPv6,
    also IPv4-mapped). Anything else, such as a name that merely starts with 127. , is not loopback."""
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback
