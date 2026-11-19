"""Backup archives: a consistent database copy plus the keys needed to read it.

An archive is a tar.gz holding

    manifest.json     portal version, schema marker, sha256 and size of every member
    portal.db         consistent copy made through the SQLite backup API
    .env              JWT secret and settings                  (when present)
    .encryption_salt  salt of the chat/config encryption keys   (when present)
    .invite_code      current invite code                       (when present)

The archive holds the JWT secret and the encryption salt, so it is as
sensitive as root access to the portal. Archives are written 0600 into a 0700
directory (backups/archives/), downloads are superadmin-only, and nothing in
this module ever writes into the live installation: restore_archive() only
unpacks into an empty directory.

Everything that touches the disk here is blocking; call it from a thread
(run_now() and run_scheduled() do) or from the command line.
"""

import asyncio
import hashlib
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import alerts
import update_manager as um
from config import Config

logger = logging.getLogger("portal.backups")

MANIFEST_NAME = "manifest.json"
DB_MEMBER = "portal.db"
# Members besides the database and the manifest, with their location in the project directory.
STATE_FILES = (".env", ".encryption_salt", ".invite_code")
ALLOWED_MEMBERS = (DB_MEMBER,) + STATE_FILES
MANIFEST_FORMAT = 1
MANIFEST_MAX_BYTES = 1 << 20

_NAME_RE = re.compile(r"^portal-backup-(\d{8})-(\d{6})(?:-(\d{1,3}))?\.tar\.gz$")

DEFAULTS = {
    "backup_enabled": "true",
    "backup_interval_hours": "24",
    "backup_keep": "7",
    "backup_extra_dir": "",
}
INTERVAL_MIN, INTERVAL_MAX = 1, 720
# The service runs with PrivateTmp, so anything written under these is invisible to the
# host and removed when the service restarts: not a usable off-disk destination.
PRIVATE_TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
KEEP_MIN, KEEP_MAX = 1, 100
# The maintenance loop wakes every few hours; a backup that is within this
# many seconds of being due counts as due, so a 24 hour schedule does not slip
# to the next wake-up.
DUE_SLACK_SECONDS = 1800
# The due check also runs once this long after the server starts.
STARTUP_CHECK_DELAY_SECONDS = 120

_RUN_LOCK = threading.Lock()

# Leftovers of a run that was killed: its private work directory and its partial archive.
STALE_AGE_SECONDS = 3600
_STALE_WORK_RE = re.compile(r"^\.work-[A-Za-z0-9_]{8}$")
_STALE_PARTIAL_RE = re.compile(r"^\.partial-[A-Za-z0-9_]{8}\.tar\.gz$")


class BackupError(RuntimeError):
    """A backup could not be written or an archive could not be used."""


# ---------------------------------------------------------------------------
# Locations and names
# ---------------------------------------------------------------------------

def archives_dir() -> Path:
    return um.BACKUPS_DIR / "archives"


def _state_path(name: str) -> Path:
    return um.PORTAL_DIR / name


def _name_key(name: str):
    m = _NAME_RE.match(name)
    if not m:
        return None
    return (m.group(1), m.group(2), int(m.group(3) or 0))


def is_archive_name(name: str) -> bool:
    return isinstance(name, str) and _NAME_RE.match(name) is not None


# Names the file manager must never serve or touch: finished archives, the temporary files
# written while one is built or copied, and the database copies written by `backup-db`
# (and the private work directory it builds them in). They hold the same secrets as .env.
_DB_COPY_RE = re.compile(r"^portal-db-.+\.db$")


def is_protected_name(name: str) -> bool:
    """True for a file name that belongs to a backup archive or a database copy."""
    if not isinstance(name, str):
        return False
    return (is_archive_name(name)
            or (name.startswith(".partial-") and name.endswith(".tar.gz"))
            or _DB_COPY_RE.match(name) is not None
            or name.startswith(".portal-backup-"))


def _ensure_archives_dir() -> Path:
    """Create backups/archives/ (0700) and refuse one that is not ours to use."""
    um._ensure_private_dirs(snapshots=False)
    adir = archives_dir()
    try:
        os.mkdir(adir, 0o700)
        os.chmod(adir, 0o700)  # umask-independent
    except FileExistsError:
        pass
    uid = os.geteuid()
    for d in (um.BACKUPS_DIR, adir):
        st = os.lstat(d)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise BackupError(f"{d} is not a plain directory")
        if st.st_uid != uid:
            raise BackupError(f"{d} is owned by another account")
    if os.lstat(adir).st_mode & 0o077:
        os.chmod(adir, 0o700)
    return adir


def resolve_archive(name: str) -> Path:
    """Map an archive file name to its path, or raise.

    The name must match the strict pattern, the entry must be a regular file
    (never a link), and its real path must stay inside the archives directory.
    """
    if not is_archive_name(name):
        raise BackupError("Invalid archive name")
    adir = archives_dir()
    path = adir / name
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise FileNotFoundError(name) from None
    if not stat.S_ISREG(st.st_mode):
        raise BackupError("Invalid archive name")
    real_dir = os.path.realpath(adir)
    real = os.path.realpath(path)
    if os.path.dirname(real) != real_dir:
        raise BackupError("Invalid archive name")
    return Path(real)


def _matching_files(directory: Path) -> list:
    """Archive-named regular files directly inside *directory*, oldest first."""
    found = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for n in names:
        key = _name_key(n)
        if key is None:
            continue
        try:
            st = os.lstat(os.path.join(directory, n))
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            found.append((key, n))
    found.sort()
    return [n for _, n in found]


def prune(directory: Path, keep: int) -> list:
    """Delete the oldest archive-named files in *directory* beyond *keep*. Returns the names removed."""
    names = _matching_files(directory)
    removed = []
    for n in names[: max(0, len(names) - max(1, keep))]:
        try:
            os.unlink(os.path.join(directory, n))
            removed.append(n)
        except OSError as e:
            logger.warning("Could not delete old backup %s: %s", n, e)
    return removed


def remove_stale_work(directory: Path, max_age: float = STALE_AGE_SECONDS, now: Optional[float] = None) -> list:
    """Delete leftovers of an interrupted run from *directory*. Returns the names removed.

    Only names exactly like the ones this module creates (`.work-XXXXXXXX` directories and
    `.partial-XXXXXXXX.tar.gz` files) that are older than *max_age* seconds, owned by this
    account and not symbolic links. Entries are inspected with lstat and a link is never followed.
    """
    now = time.time() if now is None else now
    uid = os.geteuid()
    removed = []
    try:
        names = os.listdir(directory)
    except OSError:
        return removed
    for n in names:
        is_dir = bool(_STALE_WORK_RE.match(n))
        if not is_dir and not _STALE_PARTIAL_RE.match(n):
            continue
        path = os.path.join(directory, n)
        try:
            st = os.lstat(path)
            if st.st_uid != uid or now - st.st_mtime < max_age:
                continue
            if is_dir:
                if not stat.S_ISDIR(st.st_mode):
                    continue
                shutil.rmtree(path)
            else:
                if not stat.S_ISREG(st.st_mode):
                    continue
                os.unlink(path)
            removed.append(n)
        except OSError as e:
            logger.warning("Could not delete stale backup leftover %s: %s", n, e)
    return removed


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def parse_config(values: dict) -> dict:
    """Turn raw setting strings into a typed config, falling back to the defaults."""
    raw = dict(DEFAULTS)
    raw.update({k: v for k, v in (values or {}).items() if k in DEFAULTS and v is not None})

    def _int(key, lo, hi):
        try:
            return min(hi, max(lo, int(raw[key])))
        except (TypeError, ValueError):
            return int(DEFAULTS[key])

    return {
        "enabled": str(raw["backup_enabled"]).lower() in ("true", "1", "yes", "on"),
        "interval_hours": _int("backup_interval_hours", INTERVAL_MIN, INTERVAL_MAX),
        "keep": _int("backup_keep", KEEP_MIN, KEEP_MAX),
        "extra_dir": str(raw["backup_extra_dir"] or "").strip(),
    }


# Directories the portal serves or exposes besides the installation itself. server.py adds
# the ones it owns (for instance the VOD temp directory) with register_served_dir().
_REGISTERED_SERVED_DIRS: list = []


def register_served_dir(path: str, label: str = "a directory the portal serves") -> None:
    """Make check_extra_dir() refuse *path* and everything below it."""
    if path and (path, label) not in _REGISTERED_SERVED_DIRS:
        _REGISTERED_SERVED_DIRS.append((path, label))


def _db_storage_roots() -> list:
    """Game-server storage roots straight from the database file (read-only).

    The in-process cache of gameservers.py is only filled by the running server; the command
    line (backup-archive, update) never loads it.
    """
    roots = []
    try:
        conn = sqlite3.connect(f"file:{Config.DATABASE_PATH}?mode=ro", uri=True, timeout=5)
        try:
            for (p,) in conn.execute("SELECT path FROM game_storage_roots"):
                if p:
                    roots.append(p)
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return roots


def served_dirs() -> list:
    """(label, real path) of every directory the portal serves or exposes, besides the install.

    File-manager root (unless it is the whole filesystem, which would leave no place to put a
    copy), game-server storage and config roots, the recordings directory, and whatever
    server.py registered.
    """
    found = []

    def _add(label, path):
        try:
            if path:
                found.append((label, Path(path).resolve()))
        except (OSError, RuntimeError, ValueError):
            pass

    fm = Path(Config.FILE_MANAGER_ROOT or "/").resolve()
    if fm != Path(fm.anchor):
        _add("the file manager root", fm)
    _add("the recordings directory", Config.RECORDINGS_DIR)
    try:
        import gameservers
        try:
            for p in gameservers._allowed_config_root_bases():
                _add("a game-server storage root", p)
        except Exception:
            # No run-as account configured (staged tests, command line): the storage roots alone.
            for p in gameservers._storage_root_paths():
                _add("a game-server storage root", p)
        if not gameservers._storage_roots_cache:
            for p in _db_storage_roots():
                _add("a game-server storage root", p)
    except Exception as e:
        logger.warning("Could not list the game-server storage roots: %s", e)
    for path, label in _REGISTERED_SERVED_DIRS:
        _add(label, path)
    return found


def check_extra_dir(path: str) -> Path:
    """Validate the optional extra destination directory and return its real path.

    Run when the setting is saved and again before every copy, because the setting may predate a
    rule and a symlink may have been swapped since.
    """
    if not path or len(path) > 400 or any(ord(c) < 32 for c in path):
        raise BackupError("Extra destination is not a valid path")
    p = Path(path)
    if not p.is_absolute():
        raise BackupError("Extra destination must be an absolute path")
    if not p.is_dir():
        raise BackupError(f"Extra destination does not exist or is not a directory: {path}")
    real = p.resolve()
    live = um.PORTAL_DIR.resolve()
    if real == live or live in real.parents:
        raise BackupError(
            "Extra destination cannot be the installation directory or anything inside it: "
            "files there can be served or swept into update snapshots (backups/archives is "
            "already the primary destination)")
    for label, root in served_dirs():
        if real == root or root in real.parents:
            raise BackupError(
                f"Extra destination cannot be inside {label} ({root}): archives hold the "
                "portal's secrets and must not be reachable through the portal")
    if real == archives_dir().resolve():
        raise BackupError("Extra destination must differ from the archives directory")
    for private in PRIVATE_TMP_DIRS:
        roots = {Path(private), Path(private).resolve()}
        if any(real == r or r in real.parents for r in roots):
            raise BackupError(
                f"Extra destination cannot be under {private}: the service runs with "
                "PrivateTmp, so copies written there are invisible to the host and "
                "are deleted when the service restarts")
    try:
        um._require_safe_dest_dir(real)
    except RuntimeError as e:
        raise BackupError(str(e)) from None
    if not os.access(real, os.W_OK | os.X_OK):
        raise BackupError(f"Extra destination is not writable: {path}")
    return real


def keep_lowered(data, current_keep: int) -> bool:
    """True when the update asks for a smaller `keep` than the saved one (older archives
    would be deleted at the next run)."""
    if not isinstance(data, dict) or "keep" not in data:
        return False
    v = data["keep"]
    return not isinstance(v, bool) and isinstance(v, int) and v < current_keep


def extra_dir_changed(data, current_extra_dir: str) -> bool:
    """True when the update names an extra_dir that differs from the saved one."""
    if not isinstance(data, dict) or "extra_dir" not in data:
        return False
    v = data["extra_dir"]
    return not isinstance(v, str) or v.strip() != (current_extra_dir or "")


def validate_config_update(data: dict, current_extra_dir: Optional[str] = None) -> tuple:
    """Validate a settings update. Returns ({setting_key: value_string}, [error, ...]).

    With *current_extra_dir* given, an extra_dir equal to it is left alone and not checked
    again, so an unmounted extra disk does not block editing the other settings (the copy
    still checks it every time).
    """
    out, errors = {}, []
    if not isinstance(data, dict):
        return out, ["Body must be a JSON object"]
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            errors.append("enabled must be true or false")
        else:
            out["backup_enabled"] = "true" if data["enabled"] else "false"
    for field, key, lo, hi in (
        ("interval_hours", "backup_interval_hours", INTERVAL_MIN, INTERVAL_MAX),
        ("keep", "backup_keep", KEEP_MIN, KEEP_MAX),
    ):
        if field in data:
            v = data[field]
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                errors.append(f"{field} must be a whole number from {lo} to {hi}")
            else:
                out[key] = str(v)
    if "extra_dir" in data:
        v = data["extra_dir"]
        if not isinstance(v, str):
            errors.append("extra_dir must be text")
        elif current_extra_dir is not None and v.strip() == current_extra_dir:
            pass
        elif v.strip():
            try:
                check_extra_dir(v.strip())
                out["backup_extra_dir"] = v.strip()
            except BackupError as e:
                errors.append(str(e))
        else:
            out["backup_extra_dir"] = ""
    return out, errors


def read_config_sync(db_path: Optional[str] = None) -> dict:
    """Read the backup settings straight from the database file (read-only).

    Used by the command line, which must not run migrations against a database
    the server may have open.
    """
    db_path = db_path or Config.DATABASE_PATH
    values = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        try:
            marks = ",".join("?" for _ in DEFAULTS)
            for k, v in conn.execute(f"SELECT key, value FROM settings WHERE key IN ({marks})", tuple(DEFAULTS)):
                values[k] = v
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return parse_config(values)


def is_due(last_ok_iso: Optional[str], interval_hours: int, now: Optional[float] = None) -> bool:
    """True when the last successful backup is older than the interval (or there is none)."""
    if not last_ok_iso:
        return True
    try:
        last = datetime.fromisoformat(last_ok_iso)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    now = time.time() if now is None else now
    return now - last.timestamp() >= interval_hours * 3600 - DUE_SLACK_SECONDS


# ---------------------------------------------------------------------------
# Writing an archive
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _schema_info(db_copy: str) -> dict:
    """Marker of what the copied database looks like (for the manifest)."""
    info = {"migrations": None, "schema_sha256": None, "tables": None, "encryption_key_version": None}
    try:
        import database
        info["migrations"] = len(database.MIGRATIONS)
    except Exception:
        pass
    conn = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        info["schema_sha256"] = hashlib.sha256(repr(rows).encode()).hexdigest()[:16]
        info["tables"] = sum(1 for r in rows if r[0] == "table")
        try:
            row = conn.execute("SELECT value FROM settings WHERE key = 'encryption_key_version'").fetchone()
            info["encryption_key_version"] = row[0] if row else None
        except sqlite3.Error:
            pass
    finally:
        conn.close()
    return info


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = 0o600
    ti.mtime = int(time.time())
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    tar.addfile(ti, io.BytesIO(data))


def _publish(tmp: str, directory: Path, stamp: str) -> str:
    """Move *tmp* to its final archive name in *directory* without overwriting. Returns the name."""
    # Start after the highest suffix already used for this second, so a name freed by
    # pruning is never reused (it would sort as the oldest and be pruned at once).
    used = [k[2] for k in map(_name_key, os.listdir(directory)) if k and f"{k[0]}-{k[1]}" == stamp]
    first = max(used) + 1 if used else 0
    for n in range(first, first + 1000):
        name = f"portal-backup-{stamp}" + (f"-{n}" if n else "") + ".tar.gz"
        final = os.path.join(directory, name)
        try:
            os.link(tmp, final)
        except FileExistsError:
            continue
        except OSError:
            # Filesystem without hard links: rename, guarded by an exists check.
            if os.path.lexists(final):
                continue
            os.rename(tmp, final)
            return name
        os.unlink(tmp)
        return name
    raise BackupError("Could not find a free archive name")


def _copy_to_extra(src: Path, name: str, extra_dir: str, keep: int) -> str:
    """Copy a finished archive into the extra destination. Returns the path written."""
    real = check_extra_dir(extra_dir)
    size = os.stat(src).st_size
    try:
        um._require_free_space(real, 2 * size, "twice the archive size")
    except RuntimeError as e:
        raise BackupError(str(e)) from None
    fd, tmp = tempfile.mkstemp(prefix=".partial-", suffix=".tar.gz", dir=str(real))
    try:
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            shutil.copyfileobj(inp, out, 1 << 20)
            out.flush()
            os.fsync(out.fileno())
        final = os.path.join(real, name)
        try:
            os.link(tmp, final)
        except FileExistsError:
            raise BackupError(f"{name} already exists in the extra destination") from None
        except OSError:
            if os.path.lexists(final):
                raise BackupError(f"{name} already exists in the extra destination") from None
            os.rename(tmp, final)
        return final
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        prune(real, keep)


def create_archive(db_path: Optional[str] = None, version: str = "unknown",
                   keep: int = 7, extra_dir: str = "", wait: float = 0) -> dict:
    """Write one backup archive, prune old ones, and copy it to the extra destination.

    Refuses (and logs) when less than twice the database size is free. Raises
    BackupError on any failure; a failed run leaves no partial file behind.
    A failure of the optional extra copy does not fail the backup: it is
    reported in the result as "extra_error". With *wait* seconds given, a backup that is
    already running is waited for that long instead of failing at once.
    """
    if wait and wait > 0:
        if not _RUN_LOCK.acquire(timeout=wait):
            raise BackupError(f"A backup was still running after waiting {int(wait)} seconds")
    elif not _RUN_LOCK.acquire(blocking=False):
        raise BackupError("A backup is already running")
    try:
        return _create_archive_locked(db_path, version, keep, extra_dir)
    except BackupError as e:
        logger.error("Backup failed: %s", e)
        raise
    except Exception as e:
        logger.error("Backup failed: %s", e)
        raise BackupError(str(e) or type(e).__name__) from e
    finally:
        _RUN_LOCK.release()


def _create_archive_locked(db_path, version, keep, extra_dir) -> dict:
    db_path = db_path or Config.DATABASE_PATH
    if not os.path.isfile(db_path):
        raise BackupError(f"Database not found: {db_path}")
    adir = _ensure_archives_dir()
    stale = remove_stale_work(adir)
    if stale:
        logger.info("Removed stale backup leftovers older than an hour: %s", ", ".join(stale))

    db_size = os.stat(db_path).st_size
    try:
        db_size += os.stat(db_path + "-wal").st_size
    except OSError:
        pass
    try:
        um._require_free_space(adir, 2 * db_size, "twice the database size")
    except RuntimeError as e:
        raise BackupError(str(e)) from None

    workdir = tempfile.mkdtemp(prefix=".work-", dir=str(adir))  # mode 0700
    tmp_archive = None
    try:
        db_copy = os.path.join(workdir, DB_MEMBER)
        db_bytes, integrity = um._sqlite_backup(db_path, db_copy)
        if integrity != "ok":
            raise BackupError(f"The database copy failed its integrity check: {integrity}")

        files = {DB_MEMBER: {"sha256": _sha256_file(db_copy), "size": db_bytes}}
        blobs = {}
        missing = []
        for name in STATE_FILES:
            try:
                with open(_state_path(name), "rb") as f:
                    data = f.read()
            except FileNotFoundError:
                missing.append(name)
                continue
            blobs[name] = data
            files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name in (".env", ".encryption_salt"):
            if name in missing:
                logger.warning("Backup archive has no %s: the project directory does not contain one", name)

        now = datetime.now(timezone.utc)
        manifest = {
            "format": MANIFEST_FORMAT,
            "created_at": now.isoformat(timespec="seconds"),
            "portal_version": version or "unknown",
            "database": DB_MEMBER,
            "schema": _schema_info(db_copy),
            "files": files,
        }

        fd, tmp_archive = tempfile.mkstemp(prefix=".partial-", suffix=".tar.gz", dir=str(adir))  # 0600
        with os.fdopen(fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w:gz") as tar:
                _add_bytes(tar, MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True).encode())
                ti = tarfile.TarInfo(DB_MEMBER)
                ti.size = db_bytes
                ti.mode = 0o600
                ti.mtime = int(now.timestamp())
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                with open(db_copy, "rb") as f:
                    tar.addfile(ti, f)
                for name, data in blobs.items():
                    _add_bytes(tar, name, data)
            raw.flush()
            os.fsync(raw.fileno())
        name = _publish(tmp_archive, adir, now.strftime("%Y%m%d-%H%M%S"))
        tmp_archive = None
    finally:
        if tmp_archive:
            try:
                os.unlink(tmp_archive)
            except OSError:
                pass
        shutil.rmtree(workdir, ignore_errors=True)

    final = adir / name
    os.chmod(final, 0o600)
    removed = prune(adir, keep)
    result = {
        "name": name,
        "path": str(final),
        "size": os.stat(final).st_size,
        "created_at": manifest["created_at"],
        "portal_version": manifest["portal_version"],
        "pruned": removed,
        "stale_removed": stale,
        "missing": missing,
        "extra_path": None,
        "extra_error": None,
    }
    if extra_dir:
        try:
            result["extra_path"] = _copy_to_extra(final, name, extra_dir, keep)
        except Exception as e:
            result["extra_error"] = str(e)
            logger.error("Backup %s was written, but copying it to the extra destination failed: %s", name, e)
    logger.info("Backup archive written: %s (%d bytes)", name, result["size"])
    return result


# ---------------------------------------------------------------------------
# Listing and deleting
# ---------------------------------------------------------------------------

def _read_manifest(path) -> dict:
    with tarfile.open(path, "r:gz") as tar:
        first = tar.next()
        if first is None or first.name != MANIFEST_NAME or not first.isreg() or first.size > MANIFEST_MAX_BYTES:
            raise BackupError("archive has no manifest")
        data = json.loads(tar.extractfile(first).read(MANIFEST_MAX_BYTES + 1))
    if not isinstance(data, dict):
        raise BackupError("manifest is not an object")
    return data


def list_archives() -> list:
    """All archives in backups/archives/, newest first, with manifest facts when readable."""
    adir = archives_dir()
    out = []
    for name in reversed(_matching_files(adir)):
        try:
            st = os.lstat(adir / name)
        except OSError:
            continue
        entry = {
            "name": name,
            "size": st.st_size,
            "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
            "portal_version": None,
            "members": None,
            "readable": True,
        }
        try:
            m = _read_manifest(adir / name)
            entry["portal_version"] = m.get("portal_version")
            entry["members"] = sorted((m.get("files") or {}).keys())
            entry["created_at"] = m.get("created_at") or entry["created_at"]
        except Exception:
            entry["readable"] = False
        out.append(entry)
    return out


def delete_archive(name: str) -> None:
    os.unlink(resolve_archive(name))


def latest_archive() -> Optional[str]:
    names = _matching_files(archives_dir())
    return str(archives_dir() / names[-1]) if names else None


# ---------------------------------------------------------------------------
# Restoring into an empty directory
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _load_manifest(tar: tarfile.TarFile) -> dict:
    first = tar.next()
    if first is None or first.name != MANIFEST_NAME or not first.isreg() or first.size > MANIFEST_MAX_BYTES:
        raise BackupError("The archive does not start with a manifest")
    try:
        manifest = json.loads(tar.extractfile(first).read())
    except ValueError:
        raise BackupError("The manifest is not valid JSON") from None
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise BackupError("Unsupported archive format")
    files = manifest.get("files")
    if not isinstance(files, dict) or DB_MEMBER not in files:
        raise BackupError("The manifest does not list the database")
    for name, meta in files.items():
        if name not in ALLOWED_MEMBERS:
            raise BackupError(f"The manifest lists an unexpected file: {name!r}")
        if not (isinstance(meta, dict) and isinstance(meta.get("sha256"), str) and _HEX64.match(meta["sha256"])
                and isinstance(meta.get("size"), int) and meta["size"] >= 0):
            raise BackupError(f"The manifest entry for {name} is malformed")
    return manifest


def _walk_members(tar: tarfile.TarFile, manifest: dict, sink=None) -> None:
    """Verify every member against the manifest; with *sink*, also hand each member's bytes to it.

    sink(name) -> object with write(bytes), called once per member.
    """
    files = manifest["files"]
    seen = set()
    manifest_skipped = False
    for member in tar:
        name = member.name
        if not manifest_skipped:  # the first member is the manifest, already read
            manifest_skipped = True  # iterating a TarFile starts at its first member again
            continue
        if name not in files:
            raise BackupError(f"Unexpected member in the archive: {name!r}")
        if name in seen:
            raise BackupError(f"Duplicate member in the archive: {name!r}")
        if not member.isreg():
            raise BackupError(f"Member is not a regular file: {name!r}")
        seen.add(name)
        expected = files[name]["size"]
        # Refuse before reading a single byte of a member that is not the size the manifest says.
        if member.size != expected:
            raise BackupError(
                f"Size mismatch for {name}: the archive header says {member.size} bytes, "
                f"the manifest says {expected}")
        h = hashlib.sha256()
        total = 0
        out = sink(name) if sink else None
        src = tar.extractfile(member)
        while True:
            # Never ask for more than one byte beyond the expected size.
            chunk = src.read(min(1 << 20, expected - total + 1))
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
            if total > expected:
                raise BackupError(f"{name} holds more data than the manifest says: the archive is damaged or was altered")
            if out:
                out.write(chunk)
        if total != expected or h.hexdigest() != files[name]["sha256"]:
            raise BackupError(f"Checksum mismatch for {name}: the archive is damaged or was altered")
    absent = sorted(set(files) - seen)
    if absent:
        raise BackupError(f"The archive is missing: {', '.join(absent)}")


def _check_target(into: str) -> tuple:
    """Return (path, created) for a target that is empty or does not exist yet."""
    p = Path(into).expanduser().absolute()
    if p.name in ("", "..") or p.parent == p:
        raise BackupError(f"Invalid target directory: {into}")
    target = p.parent.resolve() / p.name
    live = um.PORTAL_DIR.resolve()
    if target == live or live in target.parents:
        raise BackupError("Refusing to restore into the live installation")
    if os.path.lexists(target):
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise BackupError(f"{target} is not a plain directory")
        if os.listdir(target):
            raise BackupError(f"{target} is not empty: restore only unpacks into an empty directory")
        try:
            um._require_safe_dest_dir(target)
        except RuntimeError as e:
            raise BackupError(str(e)) from None
        return target, False
    if not target.parent.is_dir():
        raise BackupError(f"Parent directory does not exist: {target.parent}")
    return target, True


def _env_warnings(env_text: str, target: Path) -> list:
    """Name every path-valued .env setting that points outside the restored directory."""
    warnings = []
    for raw in env_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key in ("DATABASE_PATH", "RECORDINGS_DIR", "SSL_CERT", "SSL_KEY") and value:
            inside = os.path.commonpath([os.path.abspath(value), str(target)]) == str(target) \
                if os.path.isabs(value) else True
            if not inside:
                warnings.append(f"{key}={value} points outside {target}")
        elif key == "PORT" and value:
            warnings.append(f"PORT={value} is the port of the original installation")
    return warnings


def restore_archive(archive: str, into: str) -> dict:
    """Unpack an archive into an empty directory after verifying every checksum.

    Pass one reads the whole archive and checks each member against the
    manifest without writing anything; pass two writes the files (0600) and
    checks them again. If anything fails the target is left empty (and a
    directory this call created is removed). The live installation is never
    read or written.
    """
    src = Path(archive).expanduser()
    if not src.is_file():
        raise BackupError(f"Archive not found: {archive}")
    target, created = _check_target(into)

    with tarfile.open(src, "r:gz") as tar:
        manifest = _load_manifest(tar)
        _walk_members(tar, manifest)

    # Everything is checked and nothing is written yet: make sure the unpacked files fit.
    needed = sum(meta["size"] for meta in manifest["files"].values())
    try:
        um._require_free_space(target.parent if created else target, needed, "the total size of the archive's files")
    except RuntimeError as e:
        raise BackupError(f"Cannot restore into {target}: {e}") from None

    written = []
    handles = {}
    try:
        if created:
            os.mkdir(target, 0o700)
            os.chmod(target, 0o700)

        class _Sink:
            def __init__(self, name):
                fd = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                written.append(target / name)
                self.f = os.fdopen(fd, "wb")

            def write(self, data):
                self.f.write(data)

        def sink(name):
            s = handles.get(name)
            if s is None:
                s = handles[name] = _Sink(name)
            return s

        with tarfile.open(src, "r:gz") as tar:
            _load_manifest(tar)
            _walk_members(tar, manifest, sink)
        for s in handles.values():
            s.f.flush()
            os.fsync(s.f.fileno())
            s.f.close()
        handles.clear()

        conn = sqlite3.connect(f"file:{target / DB_MEMBER}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            conn.close()
        if integrity != "ok":
            raise BackupError(f"The restored database failed its integrity check: {integrity}")
    except BaseException:
        for s in handles.values():
            try:
                s.f.close()
            except OSError:
                pass
        for p in written:
            try:
                os.unlink(p)
            except OSError:
                pass
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                os.unlink(str(target / DB_MEMBER) + suffix)
            except OSError:
                pass
        if created:
            try:
                os.rmdir(target)
            except OSError:
                pass
        raise

    warnings = []
    if ".env" in manifest["files"]:
        warnings = _env_warnings((target / ".env").read_text(errors="replace"), target)
    return {
        "into": str(target),
        "files": sorted(manifest["files"]),
        "portal_version": manifest.get("portal_version"),
        "created_at": manifest.get("created_at"),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Server-side entry points (async)
# ---------------------------------------------------------------------------

_STATUS_KEYS = ("backup_last_run_at", "backup_last_ok_at", "backup_last_status", "backup_last_error", "backup_last_name")


def _db_connected() -> bool:
    """False in command-line runs (server.py update) that never opened the database."""
    from database import db
    return db._connection is not None


async def load_config() -> dict:
    from database import db
    if not _db_connected():
        return await asyncio.to_thread(read_config_sync)
    values = {}
    for key in DEFAULTS:
        values[key] = await db.get_setting(key)
    return parse_config(values)


async def save_config(update: dict) -> dict:
    from database import db
    for key, value in update.items():
        if key in DEFAULTS:
            await db.set_setting(key, value)
    return await load_config()


async def get_status() -> dict:
    from database import db
    if not _db_connected():
        return {}
    return {k: await db.get_setting(k) for k in _STATUS_KEYS}


async def _record(ok: bool, name: str = "", error: str = "") -> None:
    from database import db
    if not _db_connected():
        return  # command-line run: the card's last-result fields are only kept by the server
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        await db.set_setting("backup_last_run_at", now)
        await db.set_setting("backup_last_status", "ok" if ok else "failed")
        await db.set_setting("backup_last_error", error[:500])
        if ok:
            await db.set_setting("backup_last_ok_at", now)
            await db.set_setting("backup_last_name", name)
    except Exception as e:
        logger.error("Could not record the backup result: %s", e)


async def run_now(reason: str = "manual", wait: float = 0) -> dict:
    """Take a backup archive now (in a worker thread) and record the outcome.

    With *wait* seconds given, a backup that is already running is waited for
    that long instead of failing at once.
    """
    cfg = await load_config()
    try:
        version = await um._get_portal_version()
    except Exception:
        version = "unknown"
    try:
        info = await asyncio.to_thread(
            create_archive, None, version, cfg["keep"], cfg["extra_dir"], wait
        )
    except Exception as e:
        await _record(False, error=str(e))
        alerts.emit("backup.failed", key=reason, summary="A backup failed",
                    details={"Reason": reason, "Error": str(e)[:200]})
        raise
    await _record(True, name=info["name"], error=info.get("extra_error") or "")
    if info.get("extra_error"):
        # The local archive exists, but the copy meant to survive the disk did not: not a success.
        alerts.emit("backup.failed", key=f"{reason}:extra",
                    summary="The local backup archive was written, but the extra copy failed",
                    details={"Archive": info["name"], "Reason": reason, "Local archive": "written",
                             "Extra copy": "failed", "Error": str(info["extra_error"])[:200]})
    else:
        alerts.emit("backup.ok", key=reason, summary="A backup finished",
                    details={"Archive": info["name"], "Reason": reason})
    logger.info("Backup (%s) finished: %s%s", reason, info["name"],
                f"; pruned {', '.join(info['pruned'])}" if info.get("pruned") else "")
    return info


async def run_scheduled() -> Optional[dict]:
    """Called from the maintenance loop: take a backup when one is due. Skipped in staged mode."""
    if Config.STAGE_MODE:
        return None
    cfg = await load_config()
    if not cfg["enabled"]:
        return None
    status = await get_status()
    if not is_due(status.get("backup_last_ok_at"), cfg["interval_hours"]):
        return None
    return await run_now("scheduled")


async def run_startup_check(delay: float = STARTUP_CHECK_DELAY_SECONDS) -> Optional[dict]:
    """Run the due check once, shortly after the server started.

    The maintenance loop sleeps its whole interval before it checks anything, so a service that
    restarts more often than that would never take a scheduled backup. Skipped in staged mode.
    Never raises (it runs as a background task).
    """
    if Config.STAGE_MODE:
        return None
    try:
        await asyncio.sleep(delay)
        return await run_scheduled()
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error("Startup backup check failed: %s", e)
        return None
