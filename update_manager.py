"""Update Manager for Open Relay Portal.

Handles checking for updates, creating snapshots, applying updates,
and rolling back to previous versions.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Optional

from config import Config
import recording_paths
import vod_play
import vod_staging

logger = logging.getLogger("portal.updates")

PORTAL_DIR = Path(__file__).parent.resolve()
BACKUPS_DIR = PORTAL_DIR / "backups"
SNAPSHOTS_DIR = BACKUPS_DIR / "snapshots"
HISTORY_FILE = BACKUPS_DIR / "update_history.jsonl"
GITHUB_PORTAL_REPO = "dustinm16/portal"
GITHUB_MEDIAMTX_REPO = "bluenviron/mediamtx"

# Minimal environment for system subprocesses — avoids leaking JWT_SECRET etc. into logs
_APT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "DEBIAN_FRONTEND": "noninteractive",
    "LANG": "C.UTF-8",
}

# Cache: {key: {"data": ..., "ts": float}}
_check_cache: dict = {}
CACHE_TTL = 3600  # 1 hour

# Jobs: {job_id: {id, name, status, log, started_at, finished_at}}
_jobs: dict = {}
MAX_JOBS = 20

# Prevents concurrent update/rollback jobs from running simultaneously
_update_lock: asyncio.Lock = None  # initialized lazily (needs running event loop)


def _get_update_lock() -> asyncio.Lock:
    global _update_lock
    if _update_lock is None:
        _update_lock = asyncio.Lock()
    return _update_lock


# Strict allowlist for portal version strings (semver tags + branch names)
_VERSION_RE = re.compile(r'^v?\d+\.\d+\.\d+[\w.\-]*$')
_BRANCH_ALLOWLIST = {"master", "main"}

# `git describe --tags` output: v1.7.2  or  v1.7.2-3-gabc1234 (3 commits past the tag)
_DESCRIBE_RE = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-f]+)?', re.IGNORECASE)


def _parse_version(v: str):
    """Return ((major, minor, patch), commits_ahead) or (None, 0) if unparseable."""
    if not v:
        return None, 0
    m = _DESCRIBE_RE.match(v.strip())
    if not m:
        return None, 0
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), int(m.group(4) or 0)

# Strict allowlist for pip package names (PEP 508)
_PKG_NAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$')

# Strict allowlist for mediamtx version (digits only)
_MEDIAMTX_VERSION_RE = re.compile(r'^\d+\.\d+\.\d+$')

# Callback registered by server.py to restart portal-managed mediamtx services.
# Signature: async () -> None
_restart_mediamtx_fn: Optional[object] = None


def register_mediamtx_restart(fn) -> None:
    """Register an async callback that stops and restarts all mediamtx services."""
    global _restart_mediamtx_fn
    _restart_mediamtx_fn = fn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_cmd(
    args: list,
    cwd: Optional[str] = None,
    timeout: int = 120,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"Command timed out after {timeout}s"
        return proc.returncode, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")
    except FileNotFoundError as e:
        return -1, "", f"Command not found: {e}"
    except Exception as e:
        return -1, "", str(e)


def _ts() -> str:
    """Return current UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _log(job: dict, msg: str) -> None:
    """Append a timestamped message to a job's log."""
    entry = f"[{_ts()}] {msg}"
    job["log"].append(entry)
    logger.info("job=%s %s", job["id"], msg)


# ---------------------------------------------------------------------------
# Job management
# ---------------------------------------------------------------------------

def get_job(job_id: str) -> Optional[dict]:
    """Get a job by ID."""
    return _jobs.get(job_id)


def list_jobs() -> list[dict]:
    """List all jobs, newest first."""
    return sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)


def start_job(name: str, coro) -> str:
    """Start a background job. Returns job_id."""
    job_id = uuid.uuid4().hex[:12]

    # Cap at MAX_JOBS: remove oldest entries
    if len(_jobs) >= MAX_JOBS:
        completed = [j for j in _jobs.values() if j["status"] != "running"]
        if completed:
            oldest = sorted(completed, key=lambda j: j["started_at"])
            for j in oldest[: len(_jobs) - MAX_JOBS + 1]:
                _jobs.pop(j["id"], None)
        elif len(_jobs) >= MAX_JOBS:
            oldest_all = sorted(_jobs.values(), key=lambda j: j["started_at"])
            _jobs.pop(oldest_all[0]["id"], None)

    job = {
        "id": job_id,
        "name": name,
        "status": "running",
        "log": [],
        "started_at": _ts(),
        "finished_at": None,
    }
    _jobs[job_id] = job

    async def _runner():
        try:
            await coro(job)
            job["status"] = "completed"
        except Exception as e:
            job["status"] = "failed"
            _log(job, f"ERROR: {e}")
            logger.exception("Job %s failed: %s", job_id, e)
        finally:
            job["finished_at"] = _ts()

    asyncio.create_task(_runner())
    return job_id


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

async def _record_history(entry: dict) -> None:
    """Append an entry to the update history JSONL file."""
    try:
        _ensure_private_dirs(snapshots=False)
        line = json.dumps({**entry, "ts": _ts()}) + "\n"
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        logger.warning("Failed to write update history: %s", e)


async def get_history(limit: int = 50) -> list[dict]:
    """Return last N update history entries (newest first)."""
    if not HISTORY_FILE.exists():
        return []
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
        entries = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return list(reversed(entries[-limit:]))
    except Exception as e:
        logger.warning("Failed to read update history: %s", e)
        return []


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def _git_args(args: list) -> list:
    """Prepend git safe.directory config to allow running as root in user-owned repos."""
    assert args and args[0] == "git", f"_git_args expects ['git', ...], got {args!r}"
    return ["git", "-c", f"safe.directory={PORTAL_DIR}"] + args[1:]


async def _get_portal_version() -> str:
    """Get current portal version from git tags."""
    rc, out, _ = await _run_cmd(
        _git_args(["git", "describe", "--tags", "--exact-match", "HEAD"]),
        cwd=str(PORTAL_DIR),
    )
    if rc == 0 and out.strip():
        return out.strip()
    rc, out, _ = await _run_cmd(
        _git_args(["git", "describe", "--tags"]),
        cwd=str(PORTAL_DIR),
    )
    if rc == 0 and out.strip():
        return out.strip()
    rc, out, _ = await _run_cmd(
        _git_args(["git", "rev-parse", "--short", "HEAD"]),
        cwd=str(PORTAL_DIR),
    )
    if rc == 0 and out.strip():
        return out.strip()
    return "unknown"


async def _get_mediamtx_version() -> str:
    """Get currently installed MediaMTX version."""
    for path in ["/usr/local/bin/mediamtx", "mediamtx"]:
        rc, out, err = await _run_cmd([path, "--version"], timeout=10)
        combined = out + err
        m = re.search(r"v?(\d+\.\d+\.\d+)", combined)
        if m:
            return m.group(1)
    # Try via which
    rc, which_out, _ = await _run_cmd(["which", "mediamtx"])
    if rc == 0 and which_out.strip():
        rc, out, err = await _run_cmd([which_out.strip(), "--version"], timeout=10)
        combined = out + err
        m = re.search(r"v?(\d+\.\d+\.\d+)", combined)
        if m:
            return m.group(1)
    return "not installed"


# ---------------------------------------------------------------------------
# Update checks
# ---------------------------------------------------------------------------

async def _check_portal_updates() -> dict:
    """Check for portal updates via GitHub releases API."""
    import aiohttp
    current = await _get_portal_version()
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://api.github.com/repos/{GITHUB_PORTAL_REPO}/releases/latest"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    latest = data.get("tag_name", "unknown")
                    raw_url = data.get("html_url", "")
                    release_url = raw_url if raw_url.startswith("https://github.com/") else ""

                    # Compare by semver, not string equality — otherwise a checkout
                    # that's ahead of the latest release (e.g. "v1.7.2-3-gabc1234")
                    # reads as "!= v1.7.2" and the UI offers a downgrade.
                    cur_v, cur_ahead = _parse_version(current)
                    lat_v, _ = _parse_version(latest)
                    if latest in ("unknown", ""):
                        update_available = False
                        dev_build = False
                    elif cur_v and lat_v:
                        update_available = lat_v > cur_v
                        dev_build = not update_available and (lat_v < cur_v or cur_ahead > 0)
                    else:
                        update_available = latest != current
                        dev_build = False

                    return {
                        "current": current,
                        "latest": latest,
                        "update_available": update_available,
                        "dev_build": dev_build,
                        "release_url": release_url,
                        "release_notes": data.get("body") or "",
                    }
                else:
                    return {"current": current, "latest": "unknown", "update_available": False,
                            "error": f"GitHub API returned {resp.status}"}
    except Exception as e:
        return {"current": current, "latest": "unknown", "update_available": False, "error": str(e)}


async def _check_pip_updates() -> dict:
    """Check for outdated pip packages."""
    rc, out, err = await _run_cmd(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        timeout=60,
    )
    if rc != 0:
        return {"error": f"pip list failed: {err.strip()}", "packages": [], "count": 0}
    try:
        packages = json.loads(out)
        return {
            "packages": [
                {"name": p["name"], "current": p["version"], "latest": p["latest_version"]}
                for p in packages
            ],
            "count": len(packages),
        }
    except (json.JSONDecodeError, KeyError) as e:
        return {"error": f"Failed to parse pip output: {e}", "packages": [], "count": 0}


async def _check_mediamtx_updates() -> dict:
    """Check for MediaMTX updates via GitHub releases API."""
    import aiohttp
    current = await _get_mediamtx_version()
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://api.github.com/repos/{GITHUB_MEDIAMTX_REPO}/releases/latest"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    latest_tag = data.get("tag_name", "unknown")
                    latest = latest_tag.lstrip("v")
                    raw_url = data.get("html_url", "")
                    return {
                        "current": current,
                        "latest": latest,
                        "latest_tag": latest_tag,
                        "update_available": (
                            current not in ("not installed", "unknown")
                            and latest != "unknown"
                            and latest != current
                        ) or current == "not installed",
                        "release_url": raw_url if raw_url.startswith("https://github.com/") else "",
                    }
                else:
                    return {"current": current, "latest": "unknown", "update_available": False,
                            "error": f"GitHub API returned {resp.status}"}
    except Exception as e:
        return {"current": current, "latest": "unknown", "update_available": False, "error": str(e)}


async def _check_system_updates() -> dict:
    """Check for apt upgradable packages."""
    rc, out, err = await _run_cmd(
        ["apt", "list", "--upgradable"],
        env=_APT_ENV,
        timeout=60,
    )
    if rc not in (0, 1):  # apt list returns 0 or 1 on success
        return {"error": f"apt not available or failed: {err.strip()}", "packages": [], "count": 0}
    packages = []
    for line in out.splitlines():
        if "/" not in line or line.startswith("Listing"):
            continue
        # Format: "packagename/suite version arch [upgradable from: old_version]"
        try:
            parts = line.split()
            name_suite = parts[0]
            name = name_suite.split("/")[0]
            available = parts[1] if len(parts) > 1 else "unknown"
            # Extract current from "upgradable from: X"
            m = re.search(r"upgradable from: ([^\]]+)\]", line)
            current = m.group(1).strip() if m else "unknown"
            packages.append({"name": name, "current": current, "available": available})
        except (IndexError, AttributeError):
            continue
    return {"packages": packages, "count": len(packages)}


async def check_all(force: bool = False) -> dict:
    """Run all update checks in parallel. Cache results for 1 hour."""
    cache_key = "check_all"
    now = time()
    if not force and cache_key in _check_cache:
        cached = _check_cache[cache_key]
        if now - cached["ts"] < CACHE_TTL:
            return cached["data"]

    results = await asyncio.gather(
        _check_portal_updates(),
        _check_pip_updates(),
        _check_mediamtx_updates(),
        _check_system_updates(),
        return_exceptions=True,
    )

    portal_res, pip_res, mediamtx_res, system_res = results

    def _safe(r):
        if isinstance(r, Exception):
            return {"error": str(r)}
        return r

    data = {
        "portal": _safe(portal_res),
        "pip": _safe(pip_res),
        "mediamtx": _safe(mediamtx_res),
        "system": _safe(system_res),
        "checked_at": _ts(),
    }
    _check_cache[cache_key] = {"data": data, "ts": now}
    announce_updates(data)
    return data


def announce_updates(data: dict) -> None:
    """Hand a check's answer to the alert events (update.available, once per version).
    Fire and forget; does nothing in the command-line run, where no alerts are bound."""
    try:
        import alerts
        if alerts.bound():
            alerts._spawn(alerts.note_updates(data))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

EXCLUDE_DIRS = {"venv", "__pycache__", ".git", "backups"}
EXCLUDE_SUFFIXES = {".pyc", ".db-shm", ".db-wal"}


def _vod_staging_dirs() -> list:
    """Absolute paths of the VOD staging folder(s): never snapshotted, never removed by a rollback.

    Chunks waiting to upload can be gigabytes and are not restorable. That is the
    default folder under data/ plus the configured one, but a configured folder
    only counts when the portal created it (marker file). Otherwise a
    VOD_TEMP_DIR that the portal refused at start, such as a code folder, would
    be skipped by snapshots and frozen by rollbacks.
    """
    # Real paths throughout: the snapshot walks PORTAL_DIR, which is resolved.
    paths = [os.path.realpath(os.path.join(str(PORTAL_DIR), "data", "vod_tmp"))]
    try:
        configured = os.path.realpath(Config.VOD_TEMP_DIR)
        if configured not in paths and vod_staging.has_marker(configured) \
                and not vod_staging.dangerous_reason(configured, str(PORTAL_DIR)):
            paths.append(configured)
    except (OSError, ValueError):
        pass
    return paths


def _recordings_dirs() -> list:
    """Absolute paths of the terminal recordings folder: never snapshotted, never removed by a rollback.

    Recordings are private session history and can be large; a snapshot is
    readable by whoever reads the backups folder and a rollback would replace
    them with an older copy. That is the default folder in the project plus
    the configured one, but a configured folder only counts when it passes the
    same safety check the portal applies to it at start (recording_paths), so
    a RECORDINGS_DIR that points at a code folder is not frozen against
    rollback.
    """
    paths = [os.path.realpath(os.path.join(str(PORTAL_DIR), "recordings"))]
    try:
        configured = os.path.realpath(Config.RECORDINGS_DIR)
        if configured not in paths and not recording_paths.refusal_reason(configured, str(PORTAL_DIR)):
            paths.append(configured)
    except (OSError, ValueError):
        pass
    return paths


def _uploads_dirs() -> list:
    """Absolute path of static/uploads: never snapshotted, never replaced by a rollback.

    Chat files, avatars, emotes and stream thumbnails that members uploaded are
    live data (the folder is not part of the code and is ignored by git). A
    snapshot copy would be old by the time of a rollback: restoring it would
    delete everything uploaded since and bring back files that were deleted
    on purpose (retention, removed messages).
    """
    return [os.path.realpath(os.path.join(str(PORTAL_DIR), "static", "uploads"))]


def _vod_play_cache_dirs() -> list:
    """The browser playback cache of VOD chunks (up to the cap of vod_play_cache_mb): rebuilt on demand, so
    a snapshot must not copy it, and a rollback empties it (_empty_vod_play_cache_dirs) because 1.20.0 does
    not know the folder and would copy it into every snapshot it takes."""
    paths = [os.path.realpath(os.path.join(str(PORTAL_DIR), "data", "vod_play_cache"))]
    try:
        configured = os.path.realpath(Config.VOD_PLAY_CACHE_DIR)
        if configured not in paths and os.path.exists(os.path.join(configured, ".portal_vod_play_cache")):
            paths.append(configured)
    except (OSError, ValueError):
        pass
    return paths


def _empty_vod_play_cache_dirs(job: dict) -> None:
    """Empty the playback cache folder(s) so that 1.20.0, which does not know the folder and copies it into
    every snapshot it takes, finds it empty. Only what the cache itself writes is removed (the same names
    that vod_play.PlayCache.reconcile treats as its own: <32 hex>.mp4 and .ts, index.json, durations.json (and their .tmp) and the
    job-* folders in work/), and only from a folder that carries the portal's marker file. Anything else in
    the folder (for example a staging session folder a configuration put there) is left and logged. Links
    are removed, never followed. The marker stays so that 1.21.0 accepts the folder again."""
    marker = vod_play.MARKER_NAME
    # the portal writes durations.json a moment after a change, and again at its shutdown: from here on it must
    # not, or the file would be back (1.20.0 copies it into every snapshot) when the restart comes
    vod_play.freeze_durations_writes()
    for folder in _vod_play_cache_dirs():
        try:
            if not stat.S_ISDIR(os.lstat(folder).st_mode) or not stat.S_ISREG(os.lstat(os.path.join(folder, marker)).st_mode):
                continue
            removed = 0
            left = []
            for name in os.listdir(folder):
                if name == marker:
                    continue
                path = os.path.join(folder, name)
                if name == vod_play.WORK_NAME:
                    st = os.lstat(path)
                    if stat.S_ISDIR(st.st_mode):
                        for sub in os.listdir(path):
                            if re.match(r"^job-[0-9a-f]+$", sub):
                                _remove_cache_path(os.path.join(path, sub))
                                removed += 1
                            else:
                                left.append(f"{name}/{sub}")
                        try:
                            os.rmdir(path)      # only when it is empty now
                        except OSError:
                            pass
                        continue
                    left.append(name)
                elif vod_play._ENTRY_RE.match(name) or name in (
                        vod_play.INDEX_NAME, vod_play.INDEX_NAME + ".tmp",
                        vod_play.DURATIONS_NAME, vod_play.DURATIONS_NAME + ".tmp"):
                    _remove_cache_path(path)
                    removed += 1
                else:
                    left.append(name)
            if removed:
                _log(job, f"Emptied the VOD playback cache {folder} (1.20.0 would copy it into every snapshot).")
            if left:
                _log(job, f"WARNING: Left {len(left)} item(s) in the VOD playback cache {folder} that are not "
                          f"cache files ({', '.join(sorted(left)[:5])}); 1.20.0 may copy them into a snapshot.")
        except OSError as e:
            _log(job, f"WARNING: Could not empty the VOD playback cache {folder}: {e}")


def _remove_cache_path(path: str) -> None:
    """Remove one cache file or folder without following links."""
    if stat.S_ISDIR(os.lstat(path).st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _preserved_state_dirs() -> list:
    """Folders of live data that snapshots skip and rollbacks leave alone."""
    return _vod_staging_dirs() + _recordings_dirs() + _uploads_dirs() + _vod_play_cache_dirs()


def _snapshot_size(snap_dir: Path) -> int:
    """Return total size of snapshot directory in bytes."""
    total = 0
    try:
        for f in snap_dir.rglob("*"):
            try:
                if f.is_file():
                    total += f.stat().st_size
            except OSError:
                pass
    except Exception:
        pass
    return total


def _format_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


# Files at the top of the project directory that are never copied verbatim into
# a snapshot: the live database (copied through the SQLite backup API instead),
# its write-ahead-log side files, and the stray manual backup copy.
_SNAPSHOT_DB_SKIP = {"portal.db", "portal.db-wal", "portal.db-shm", "portal.db.backup"}
_SNAPSHOT_DB_NAME = "portal.db"


def _ensure_private_dirs(snapshots: bool = True) -> None:
    """Make sure backups/ (and backups/snapshots/) exist and are private (0700).

    A missing directory is created 0700 regardless of the umask. An existing one
    that is owned by the portal's user and accessible to group or other is
    tightened to 0700. A symlink, or a directory owned by someone else, is left
    alone (the rollback guard refuses to use it).
    """
    uid = os.geteuid()
    for d in ((BACKUPS_DIR, SNAPSHOTS_DIR) if snapshots else (BACKUPS_DIR,)):
        try:
            os.mkdir(d, 0o700)
            os.chmod(d, 0o700)  # umask-independent
            continue
        except FileExistsError:
            pass
        try:
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            continue  # symlink or unreadable: not ours to change
        try:
            st = os.fstat(fd)
            if st.st_uid == uid and st.st_mode & 0o077:
                os.fchmod(fd, 0o700)
        except OSError as e:
            logger.warning("Could not tighten %s: %s", d, e)
        finally:
            os.close(fd)


def _sqlite_backup(src: str, dest: str) -> tuple[int, str]:
    """Write a consistent single-file copy of the SQLite database at *src* to *dest*.

    Uses the online backup API, so everything committed to the write-ahead log
    is included and the portal can keep running. *dest* is created 0600 and
    must not already exist. Returns (size_in_bytes, integrity_check_result).
    Blocking: call from a thread.
    """
    if not os.path.isfile(src):
        raise FileNotFoundError(f"database not found: {src}")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        source = sqlite3.connect(src, timeout=30)
        try:
            target = sqlite3.connect(dest)
            try:
                source.backup(target)
                # The backup keeps the WAL flag in the file header; switch the copy
                # to a rollback journal so it is one self-contained file.
                target.execute("PRAGMA journal_mode=DELETE")
                row = target.execute("PRAGMA integrity_check").fetchone()
                result = str(row[0]) if row else "no result"
            finally:
                target.close()
        finally:
            source.close()
        for suffix in ("-wal", "-shm"):
            try:
                os.unlink(dest + suffix)
            except FileNotFoundError:
                pass
        os.chmod(dest, 0o600)
        return os.stat(dest).st_size, result
    except BaseException:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.unlink(dest + suffix)
            except OSError:
                pass
        raise


def _strip_group_other_write(root: Path, skip_names: set = frozenset()) -> None:
    """Remove group/other write bits from every file and directory under *root*.

    Entries directly under *root* whose name is in *skip_names* are left alone.
    """
    def _fix(path: str) -> None:
        try:
            st = os.lstat(path)
        except OSError:
            return
        if stat.S_ISLNK(st.st_mode):
            return
        if st.st_mode & 0o022:
            os.chmod(path, stat.S_IMODE(st.st_mode) & ~0o022)

    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        if dirpath == str(root) and skip_names:
            dirnames[:] = [n for n in dirnames if n not in skip_names]
            filenames = [n for n in filenames if n not in skip_names]
        for name in filenames:
            _fix(os.path.join(dirpath, name))
        for name in dirnames:
            _fix(os.path.join(dirpath, name))


def _require_safe_dest_dir(directory: Path) -> None:
    """Refuse a destination directory that group or other can write to (unless sticky)."""
    pst = os.stat(directory)
    if pst.st_mode & 0o022 and not pst.st_mode & stat.S_ISVTX:
        raise RuntimeError(
            f"Refusing to write into {directory}: it is writable by group or other "
            f"(mode {stat.S_IMODE(pst.st_mode):04o}) and has no sticky bit. "
            f"Choose a private directory."
        )


def _require_free_space(directory: Path, needed: int, what: str) -> None:
    """Raise when the filesystem holding *directory* has less than *needed* bytes free."""
    free = shutil.disk_usage(str(directory)).free
    if free < needed:
        raise RuntimeError(
            f"Not enough free disk space in {directory}: {free} bytes free, "
            f"need at least {needed} ({what})"
        )


def backup_database(out: Optional[str] = None, db_path: Optional[str] = None) -> tuple[Path, int, str]:
    """Write a consistent copy of the database to a 0600 file and return (path, size, integrity).

    Works while the portal is running. Refuses when less than twice the database
    size (including its write-ahead log) is free on the destination filesystem,
    and when the destination directory is writable by group or other without the
    sticky bit. The copy is built inside a fresh 0700 directory created next to
    the destination (so SQLite's journal files are never created by name in a
    shared directory) and then moved into place without overwriting anything.
    Blocking: call from a thread or from the CLI.
    """
    if db_path is None:
        from config import Config
        db_path = Config.DATABASE_PATH
    if not os.path.isfile(db_path):
        raise RuntimeError(f"Database not found: {db_path}")

    if out:
        # Resolve only the directory: resolving the final component would follow a
        # symlink planted at the destination and bypass every check below.
        p = Path(out).expanduser().absolute()
        if p.name in ("", "..") or p.parent == p:
            raise RuntimeError(f"Invalid destination file name: {out}")
        dest = p.parent.resolve() / p.name
        if not dest.parent.is_dir():
            raise RuntimeError(f"Destination directory does not exist: {dest.parent}")
    else:
        _ensure_private_dirs(snapshots=False)
        dest = BACKUPS_DIR / f"portal-db-{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    if dest.exists() or dest.is_symlink():
        raise RuntimeError(f"Refusing to overwrite existing file: {dest}")

    _require_safe_dest_dir(dest.parent)

    db_size = os.stat(db_path).st_size
    try:
        db_size += os.stat(db_path + "-wal").st_size
    except OSError:
        pass
    _require_free_space(dest.parent, 2 * db_size, "twice the database size")

    try:
        workdir = tempfile.mkdtemp(prefix=".portal-backup-", dir=str(dest.parent))  # mode 0700
    except OSError as e:
        raise RuntimeError(f"Cannot write into {dest.parent}: {e.strerror or e}") from e
    try:
        tmp = os.path.join(workdir, "db")
        size, result = _sqlite_backup(db_path, tmp)
        try:
            os.link(tmp, dest)  # fails if dest appeared meanwhile; never overwrites
        except FileExistsError:
            raise RuntimeError(f"Refusing to overwrite existing file: {dest}") from None
        except OSError:
            # Filesystem without hard links: fall back to a rename guarded by an exists check.
            if dest.exists() or dest.is_symlink():
                raise RuntimeError(f"Refusing to overwrite existing file: {dest}") from None
            os.rename(tmp, dest)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return dest, size, result


async def create_snapshot(reason: str = "manual", db_path: Optional[str] = None) -> dict:
    """Create a directory snapshot of the portal (excluding venv, __pycache__, etc.).

    The snapshot directory is private (0700). The database is not copied as a
    raw file; it is written through the SQLite backup API so the snapshot holds
    one consistent file that includes the write-ahead log.
    """
    _ensure_private_dirs()
    snap_id = f"snap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    snap_dir = SNAPSHOTS_DIR / snap_id
    meta_file = SNAPSHOTS_DIR / f"{snap_id}.json"

    current_version = await _get_portal_version()

    # Stash any dirty git changes
    git_stash_ref = None
    rc, out, err = await _run_cmd(
        _git_args(["git", "stash", "push", "-m", f"portal-snapshot-{snap_id}"]),
        cwd=str(PORTAL_DIR),
    )
    if rc == 0 and "Saved working directory" in out:
        git_stash_ref = f"portal-snapshot-{snap_id}"
        logger.info("Git stash created for snapshot %s", snap_id)

    # Copy files excluding certain dirs/files
    vod_dirs = set(_preserved_state_dirs())

    def _ignore(src, names):
        ignored = set()
        for name in names:
            p = Path(src) / name
            if name in EXCLUDE_DIRS or os.path.abspath(p) in vod_dirs:
                ignored.add(name)
            elif p.is_file() and p.suffix in EXCLUDE_SUFFIXES:
                ignored.add(name)
        return ignored

    created = False
    try:
        # Mode 0700 regardless of umask or of the source directory's mode.
        os.mkdir(snap_dir, 0o700)
        created = True
        os.chmod(snap_dir, 0o700)
        # Copy the children one by one: copytree onto snap_dir itself would
        # finish by copying the project directory's mode onto it.
        top_ignored = _ignore(str(PORTAL_DIR), [c.name for c in PORTAL_DIR.iterdir()])

        def _copy_children():
            for child in PORTAL_DIR.iterdir():
                if child.name in top_ignored or child.name in _SNAPSHOT_DB_SKIP:
                    continue
                dest = snap_dir / child.name
                if child.is_dir():
                    shutil.copytree(str(child), str(dest), ignore=_ignore)
                else:
                    shutil.copy2(str(child), str(dest))

        await asyncio.to_thread(_copy_children)
        await asyncio.to_thread(_strip_group_other_write, snap_dir)
    except Exception as e:
        # Never leave a half-written (and meta-less, so invisible) snapshot behind,
        # but never touch a directory this call did not create (same-second id clash).
        if created:
            await asyncio.to_thread(shutil.rmtree, snap_dir, True)
        raise RuntimeError(f"Failed to copy portal directory: {e}") from e

    db_size = None
    db_integrity = None
    if db_path is None:
        from config import Config
        db_path = Config.DATABASE_PATH
    if os.path.isfile(db_path):
        try:
            db_size, db_integrity = await asyncio.to_thread(
                _sqlite_backup, db_path, str(snap_dir / _SNAPSHOT_DB_NAME)
            )
        except Exception as e:
            await asyncio.to_thread(shutil.rmtree, snap_dir, True)
            raise RuntimeError(f"Failed to back up the database: {e}") from e
        if db_integrity != "ok":
            logger.warning("Snapshot %s: database integrity_check returned %r", snap_id, db_integrity)
    else:
        logger.warning("Snapshot %s: database file not found at %s", snap_id, db_path)

    size = await asyncio.to_thread(_snapshot_size, snap_dir)

    meta = {
        "id": snap_id,
        "reason": reason,
        "version": current_version,
        "created_at": _ts(),
        "size_bytes": size,
        "size_human": _format_size(size),
        "git_stash_ref": git_stash_ref,
        "path": str(snap_dir),
        "db_size_bytes": db_size,
        "db_integrity": db_integrity,
    }
    # Owner-only from the first byte: never readable under a permissive umask.
    fd = os.open(meta_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(json.dumps(meta, indent=2))
    finally:
        if fd >= 0:
            os.close(fd)
    await _record_history({"type": "snapshot_created", "snap_id": snap_id, "reason": reason, "version": current_version})
    return meta


async def list_snapshots() -> list[dict]:
    """List all snapshots, newest first."""
    if not SNAPSHOTS_DIR.exists():
        return []
    snapshots = []
    for meta_file in SNAPSHOTS_DIR.glob("snap_*.json"):
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            snapshots.append(meta)
        except Exception:
            pass
    return sorted(snapshots, key=lambda s: s.get("created_at", ""), reverse=True)


async def delete_snapshot(snap_id: str) -> bool:
    """Delete a snapshot by ID."""
    # Validate snap_id format to prevent path traversal
    if not re.match(r'^snap_\d{8}_\d{6}$', snap_id):
        return False
    meta_file = SNAPSHOTS_DIR / f"{snap_id}.json"
    snap_dir = SNAPSHOTS_DIR / snap_id
    deleted = False
    if meta_file.exists():
        meta_file.unlink()
        deleted = True
    if snap_dir.exists():
        shutil.rmtree(str(snap_dir), ignore_errors=True)
        deleted = True
    if deleted:
        await _record_history({"type": "snapshot_deleted", "snap_id": snap_id})
    return deleted


# ---------------------------------------------------------------------------
# Apply updates
# ---------------------------------------------------------------------------

async def _apply_portal_update(job: dict, version: Optional[str]) -> None:
    """Apply a portal update: snapshot → git fetch → checkout → pip install → restart."""
    _log(job, "Creating pre-update snapshot...")
    try:
        snap = await create_snapshot(reason=f"pre-update to {version or 'latest'}")
        _log(job, f"Snapshot created: {snap['id']}")
    except Exception as e:
        _log(job, f"WARNING: Could not create snapshot: {e}")

    _log(job, "Fetching latest tags from origin...")
    rc, out, err = await _run_cmd(
        _git_args(["git", "fetch", "--tags", "--prune", "origin"]),
        cwd=str(PORTAL_DIR),
        timeout=60,
    )
    if rc != 0:
        raise RuntimeError(f"git fetch failed: {err.strip()}")
    _log(job, "Fetch complete.")

    # Also refresh moved tags — `git fetch --tags` won't clobber an existing tag
    # whose target changed (e.g. after a history rewrite), so force it.
    await _run_cmd(
        _git_args(["git", "fetch", "--tags", "--force", "origin"]),
        cwd=str(PORTAL_DIR), timeout=60,
    )

    target = version or "master"

    # Guard against a downgrade: if the requested tag is already an ancestor of
    # HEAD, checking it out would silently drop unreleased commits. Roll back via
    # the snapshot system instead.
    if version:
        rc_a, _, _ = await _run_cmd(
            _git_args(["git", "merge-base", "--is-ancestor", target, "HEAD"]),
            cwd=str(PORTAL_DIR), timeout=15,
        )
        if rc_a == 0:
            raise RuntimeError(
                f"{target} is already in this checkout's history — refusing to "
                f"downgrade. Use a snapshot rollback instead."
            )

    _log(job, f"Checking out {target}...")
    rc, out, err = await _run_cmd(
        _git_args(["git", "checkout", target]),
        cwd=str(PORTAL_DIR),
        timeout=30,
    )
    if rc != 0:
        raise RuntimeError(f"git checkout {target} failed: {err.strip()}")
    _log(job, f"Checked out {target}.")

    _log(job, "Installing Python dependencies...")
    rc, out, err = await _run_cmd(
        [sys.executable, "-m", "pip", "install", "-r", str(PORTAL_DIR / "requirements.txt")],
        timeout=300,
    )
    if rc != 0:
        raise RuntimeError(f"pip install failed: {err.strip()}")
    _log(job, "Dependencies installed.")

    await _record_history({"type": "update_applied", "component": "portal", "version": target, "job_id": job["id"]})
    _log(job, "Scheduling service restart in 2 seconds...")

    async def _delayed_restart():
        await asyncio.sleep(2)
        await _run_cmd(["systemctl", "restart", "portal"], timeout=10)

    asyncio.create_task(_delayed_restart())
    _log(job, "Portal update complete. Service restarting...")


async def _apply_pip_update(job: dict, packages: Optional[str]) -> None:
    """Update pip packages."""
    if packages:
        pkg_list = [p.strip() for p in packages.split(",") if p.strip()]
        # Validate each name (already checked in start_apply, double-check here)
        for pkg in pkg_list:
            if not _PKG_NAME_RE.match(pkg):
                raise ValueError(f"Invalid package name: {pkg!r}")
    else:
        # Upgrade every package pip reports as outdated (not just requirements.txt entries)
        _log(job, "Checking for outdated packages...")
        rc, out, err = await _run_cmd(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            timeout=60,
        )
        if rc != 0:
            raise RuntimeError(f"pip list --outdated failed: {err.strip()}")
        try:
            outdated = json.loads(out)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse pip outdated list: {e}") from e
        if not outdated:
            _log(job, "All packages are up to date.")
            await _record_history({
                "type": "update_applied",
                "component": "pip",
                "packages": "none (already up to date)",
                "job_id": job["id"],
            })
            return
        pkg_list = [p["name"] for p in outdated]
        _log(job, f"Upgrading {len(pkg_list)} outdated package(s): {', '.join(pkg_list)}")

    args = [sys.executable, "-m", "pip", "install", "--upgrade", "--"] + pkg_list
    rc, out, err = await _run_cmd(args, timeout=300)
    if rc != 0:
        raise RuntimeError(f"pip upgrade failed: {err.strip()}")
    _log(job, "Pip upgrade complete.")
    for line in out.splitlines():
        if line.startswith("Successfully installed"):
            _log(job, line)

    # Regenerate requirements.txt from current installed state
    _log(job, "Regenerating requirements.txt...")
    rc, freeze_out, freeze_err = await _run_cmd(
        [sys.executable, "-m", "pip", "freeze"],
        timeout=30,
    )
    if rc == 0 and freeze_out.strip():
        req_path = PORTAL_DIR / "requirements.txt"
        req_path.write_text(
            "# Portal dependencies — auto-managed, regenerated after each pip upgrade\n"
            "# Run: pip install -r requirements.txt\n"
            + freeze_out,
            encoding="utf-8",
        )
        _log(job, f"requirements.txt updated ({len(freeze_out.splitlines())} packages).")
    else:
        _log(job, f"WARNING: pip freeze failed, requirements.txt not updated: {freeze_err.strip()}")

    await _record_history({
        "type": "update_applied",
        "component": "pip",
        "packages": ", ".join(pkg_list),
        "job_id": job["id"],
    })


async def _apply_mediamtx_update(job: dict, version: Optional[str]) -> None:
    """Download and install a MediaMTX release."""
    import aiohttp

    if not version:
        # Get latest version
        _log(job, "Fetching latest MediaMTX release info...")
        check = await _check_mediamtx_updates()
        if "error" in check:
            raise RuntimeError(f"Could not determine latest MediaMTX version: {check['error']}")
        version = check.get("latest", "")
        if not version:
            raise RuntimeError("Could not determine latest MediaMTX version")

    _log(job, f"Installing MediaMTX v{version}...")
    url = (
        f"https://github.com/bluenviron/mediamtx/releases/download/"
        f"v{version}/mediamtx_v{version}_linux_amd64.tar.gz"
    )
    _log(job, f"Downloading from {url}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball_path = Path(tmpdir) / "mediamtx.tar.gz"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Download failed: HTTP {resp.status}")
                content = await resp.read()
                tarball_path.write_bytes(content)
                _log(job, f"Downloaded {len(content)} bytes.")

        # Extract
        _log(job, "Extracting archive...")
        rc, out, err = await _run_cmd(
            ["tar", "xzf", str(tarball_path), "-C", tmpdir],
            timeout=30,
        )
        if rc != 0:
            raise RuntimeError(f"tar extraction failed: {err.strip()}")

        binary_src = Path(tmpdir) / "mediamtx"
        if not binary_src.exists():
            raise RuntimeError("mediamtx binary not found in archive")

        dest = Path("/usr/local/bin/mediamtx")

        # Stop portal-managed mediamtx before replacing the running binary (avoids ETXTBSY)
        _log(job, "Stopping mediamtx service...")
        await _run_cmd(["pkill", "-TERM", "-f", "mediamtx"], timeout=10)
        await asyncio.sleep(2)  # Give process time to exit

        _log(job, f"Installing binary to {dest}...")
        # Write to a temp file beside the destination, then rename atomically
        tmp_dest = dest.with_suffix(".tmp")
        shutil.copy2(str(binary_src), str(tmp_dest))
        tmp_dest.chmod(0o755)
        tmp_dest.rename(dest)
        _log(job, "Binary installed.")

    # Restart via portal service manager (regenerates config for new version)
    if _restart_mediamtx_fn:
        _log(job, "Restarting mediamtx via portal service manager...")
        try:
            await _restart_mediamtx_fn()
            _log(job, "mediamtx restarted.")
        except Exception as e:
            _log(job, f"WARNING: mediamtx restart failed: {e}")
    else:
        _log(job, "WARNING: No mediamtx restart callback registered; service not restarted.")

    await _record_history({
        "type": "update_applied",
        "component": "mediamtx",
        "version": version,
        "job_id": job["id"],
    })
    _log(job, f"MediaMTX v{version} installation complete.")


async def _apply_system_update(job: dict) -> None:
    """Run apt-get upgrade."""
    _log(job, "Running apt-get update...")
    rc, out, err = await _run_cmd(
        ["apt-get", "update", "-qq"],
        env=_APT_ENV,
        timeout=120,
    )
    if rc != 0:
        raise RuntimeError(f"apt-get update failed: {err.strip()}")
    _log(job, "apt-get update complete. Running apt-get upgrade...")

    rc, out, err = await _run_cmd(
        ["apt-get", "upgrade", "-y", "-qq"],
        env=_APT_ENV,
        timeout=600,
    )
    if rc != 0:
        raise RuntimeError(f"apt-get upgrade failed: {err.strip()}")
    _log(job, "System packages upgraded.")
    if out.strip():
        for line in out.splitlines():
            _log(job, line)

    await _record_history({"type": "update_applied", "component": "system", "job_id": job["id"]})
    _log(job, "System update complete.")


# A backup that is already running (scheduled, or started by hand) is waited for this long.
PRE_UPDATE_BACKUP_WAIT_SECONDS = 600


async def _backup_before_update(job: dict) -> None:
    """Write a backup archive (database plus restore keys) and stop the update if that fails."""
    import backup_manager
    _log(job, "Creating pre-update backup archive...")
    try:
        info = await backup_manager.run_now("pre-update", wait=PRE_UPDATE_BACKUP_WAIT_SECONDS)
    except Exception as e:
        raise RuntimeError(f"Pre-update backup failed, so the update was not started: {e}") from e
    _log(job, f"Backup archive created: {info['name']}")
    if info.get("extra_error"):
        _log(job, f"WARNING: copy to the extra backup destination failed: {info['extra_error']}")


async def _run_apply(job: dict, component: str, version: Optional[str]) -> None:
    """Take a backup archive, then apply the update. Nothing is changed if the backup fails."""
    await _backup_before_update(job)
    if component == "portal":
        await _apply_portal_update(job, version)
    elif component == "pip":
        await _apply_pip_update(job, version)
    elif component == "mediamtx":
        await _apply_mediamtx_update(job, version)
    elif component == "system":
        await _apply_system_update(job)


async def start_apply(component: str, version: Optional[str] = None) -> str:
    """Dispatch an update job for the given component. Returns job_id."""
    if Config.STAGE_MODE:
        raise RuntimeError("Updates are disabled in staged test mode")
    component = component.lower()
    if component not in ("portal", "pip", "mediamtx", "system"):
        raise ValueError(f"Unknown component: {component}")

    # Validate version string to prevent git ref abuse and URL manipulation
    if version:
        if len(version) > 100:
            raise ValueError("version too long (max 100 chars)")
        if component == "portal":
            if version not in _BRANCH_ALLOWLIST and not _VERSION_RE.match(version):
                raise ValueError(f"Invalid portal version: {version!r} (must be semver tag or branch)")
        elif component == "mediamtx":
            v = version.lstrip("v")
            if not _MEDIAMTX_VERSION_RE.match(v):
                raise ValueError(f"Invalid mediamtx version: {version!r} (must be X.Y.Z)")
            version = v  # strip leading 'v' for URL construction
        elif component == "pip":
            # version field is reused as comma-separated package list for pip
            for pkg in version.split(","):
                pkg = pkg.strip()
                if pkg and not _PKG_NAME_RE.match(pkg):
                    raise ValueError(f"Invalid package name: {pkg!r}")

    # Prevent concurrent destructive jobs
    lock = _get_update_lock()
    if lock.locked():
        raise RuntimeError("Another update or rollback job is already running")

    async def _run(job: dict):
        async with lock:
            await _run_apply(job, component, version)

    name = f"Update {component}" + (f" to {version}" if version else "")
    return start_job(name, _run)


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

# Database, .env and other state are never restored from a snapshot.
_ROLLBACK_PRESERVE_DIRS = {"venv", "backups", ".git", "data", "__pycache__"}
_ROLLBACK_PRESERVE_FILES = {".env", "portal.db", "portal.db-shm", "portal.db-wal", "portal.db.backup"}


def _rollback_staging_keep() -> tuple:
    """(preserve_names, keep_paths) for the live-data folders during a rollback.

    The folders are the VOD staging folder and the terminal recordings folder. One
    directly under the project folder is preserved by name like data/. One nested
    deeper (for example "code/vods") goes into keep_paths: the folders above it are
    cleaned and restored around it, and it is left alone.
    """
    names = set()
    keeps = []
    root = os.path.realpath(str(PORTAL_DIR))
    for path in _preserved_state_dirs():
        rel = os.path.relpath(os.path.realpath(path), root)
        parts = Path(rel).parts
        if not parts or parts[0] == os.pardir or os.path.isabs(rel):
            continue  # the project folder itself or outside it: nothing to protect
        if parts[0] in _ROLLBACK_PRESERVE_DIRS:
            continue
        if len(parts) == 1:
            names.add(parts[0])
        else:
            keeps.append(Path(root) / rel)
    return names, keeps


def _keep_ignore(snap_dir: Path, keeps):
    """copytree ignore function that skips the preserved folders when restoring a snapshot."""
    root = Path(os.path.realpath(str(PORTAL_DIR)))
    base = Path(snap_dir)

    def _ignore(src, names):
        try:
            here = root / Path(src).relative_to(base)
        except ValueError:
            return set()
        return {n for n in names if here / n in keeps}
    return _ignore


def _rmtree_except(directory: Path, keeps) -> None:
    """Remove everything under *directory* except the *keeps* paths and the folders leading to them."""
    if isinstance(keeps, Path):
        keeps = [keeps]
    for child in directory.iterdir():
        if child in keeps:
            continue
        if not child.is_symlink() and child.is_dir():
            if any(child in k.parents for k in keeps):
                _rmtree_except(child, keeps)
            else:
                shutil.rmtree(str(child))
        else:
            child.unlink()


def _backup_dirs_problems() -> list:
    """Describe every way backups/ or backups/snapshots/ is not private to the portal user."""
    uid = os.geteuid()
    problems = []
    for d in (BACKUPS_DIR, SNAPSHOTS_DIR):
        try:
            st = os.lstat(d)
        except OSError as e:
            problems.append(f"{d.name}/ ({e.strerror or e})")
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            problems.append(f"{d.name}/ (not a plain directory)")
        elif st.st_uid != uid:
            problems.append(f"{d.name}/ (owned by uid {st.st_uid}, expected {uid})")
        elif st.st_mode & 0o022:
            problems.append(f"{d.name}/ (mode {stat.S_IMODE(st.st_mode):04o} is writable by group or other)")
    return problems


def _check_snapshot_restorable(snap_dir: Path, skip_names: set) -> None:
    """Refuse a snapshot that someone other than the portal's own user could have altered.

    backups/ and backups/snapshots/ must be plain directories owned by the user
    running the portal and not writable by group or other (someone who can write
    there could swap the snapshot after it was verified). Every directory and file
    rollback is about to restore must be owned by that user and must not be
    writable by group or other. Symlinks are judged by owner only (their own mode
    is meaningless on Linux). Raises RuntimeError before anything has been copied
    or removed.
    """
    uid = os.geteuid()
    problems = _backup_dirs_problems()

    def _inspect(path: str) -> None:
        st = os.lstat(path)
        rel = os.path.relpath(path, str(snap_dir)) if path != str(snap_dir) else "."
        if st.st_uid != uid:
            problems.append(f"{rel} (owned by uid {st.st_uid}, expected {uid})")
        elif not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
            problems.append(f"{rel} (mode {stat.S_IMODE(st.st_mode):04o} is writable by group or other)")

    _inspect(str(snap_dir))
    if snap_dir.is_symlink() or not snap_dir.is_dir():
        problems.append(". (not a plain directory)")
    for item in snap_dir.iterdir():
        if item.name in skip_names:
            continue
        _inspect(str(item))
        if item.is_dir() and not item.is_symlink():
            for dirpath, dirnames, filenames in os.walk(str(item), followlinks=False):
                for name in dirnames + filenames:
                    _inspect(os.path.join(dirpath, name))
    if problems:
        shown = "; ".join(problems[:5])
        more = f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""
        raise RuntimeError(
            f"Refusing to roll back: snapshot is not private to the portal user: {shown}{more}. "
            f"Nothing was changed. Inspect the snapshot, then fix its owner and permissions "
            f"(chown to the portal user, chmod -R go-w; chmod 0700 the backups directories) or delete it."
        )


def _adopt_legacy_snapshot(snap_dir: Path, meta: dict, skip_names: set = frozenset()) -> bool:
    """Tighten a snapshot made before snapshots were private, when that is safe.

    Older releases copied the project directory's mode (typically 0775) onto the
    snapshot, so every such snapshot would be refused by _check_snapshot_restorable.
    A snapshot is adopted (group/other write bits stripped, directory set to 0700)
    only if all of the following hold, otherwise nothing is changed and the normal
    check decides:
      - its metadata predates the database-integrity field (made by older code);
      - backups/ and backups/snapshots/ are owned by the portal user and not
        writable by group or other;
      - every entry rollback would restore (names in *skip_names* are not looked
        at and not changed) is owned by the portal user, is not writable by
        other, and is group-writable only when its group is the portal user's
        own primary group.
    Returns True if the snapshot was adopted. Blocking: call from a thread.
    """
    if "db_integrity" in meta:
        return False
    uid, gid = os.geteuid(), os.getegid()
    if _backup_dirs_problems():
        return False
    try:
        if snap_dir.is_symlink() or not snap_dir.is_dir():
            return False
        top = os.lstat(snap_dir)
        if top.st_uid != uid or top.st_mode & 0o002:
            return False
        if top.st_mode & 0o020 and top.st_gid != gid:
            return False
        entries = [e for e in snap_dir.iterdir() if e.name not in skip_names]
        paths = []
        for e in entries:
            paths.append(str(e))
            if e.is_dir() and not e.is_symlink():
                for dirpath, dirnames, filenames in os.walk(str(e), followlinks=False):
                    paths.extend(os.path.join(dirpath, n) for n in dirnames + filenames)
        for path in paths:
            st = os.lstat(path)
            if st.st_uid != uid:
                return False
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mode & 0o002:
                return False
            if st.st_mode & 0o020 and st.st_gid != gid:
                return False
    except OSError:
        return False
    _strip_group_other_write(snap_dir, skip_names)
    os.chmod(snap_dir, 0o700)
    return True


def _log_restore_hint(job: dict) -> None:
    """Say how the database is restored: a rollback never does it."""
    _log(job, "A rollback restores code only. The database, .env and keys are not touched.")
    _log(job, "To recover them from a backup archive, unpack it into an empty directory with:")
    _log(job, "  python server.py restore-archive <archive file> --into <empty directory>")
    try:
        import backup_manager
        latest = backup_manager.latest_archive()
    except Exception:
        latest = None
    if latest:
        _log(job, f"Newest backup archive: {latest}")
    _log(job, "See 'Backups and Rollback' in the README for the remaining steps.")


async def _apply_rollback(job: dict, snap_id: str) -> None:
    """Restore portal files from snapshot and reinstall dependencies."""
    # Validate snap_id
    if not re.match(r'^snap_\d{8}_\d{6}$', snap_id):
        raise ValueError(f"Invalid snapshot ID: {snap_id}")

    meta_file = SNAPSHOTS_DIR / f"{snap_id}.json"
    snap_dir = SNAPSHOTS_DIR / snap_id

    if not meta_file.exists():
        raise RuntimeError(f"Snapshot metadata not found: {snap_id}")
    if not snap_dir.exists():
        raise RuntimeError(f"Snapshot directory not found: {snap_id}")

    staging_names, staging_keeps = _rollback_staging_keep()
    PRESERVE_DIRS = _ROLLBACK_PRESERVE_DIRS | staging_names
    PRESERVE_FILES = _ROLLBACK_PRESERVE_FILES

    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    if await asyncio.to_thread(_adopt_legacy_snapshot, snap_dir, meta, PRESERVE_DIRS | PRESERVE_FILES):
        _log(job, f"Snapshot {snap_id} predates private snapshots; removed group/other write permissions from it.")

    # Verify every file that would be restored before changing anything.
    await asyncio.to_thread(_check_snapshot_restorable, snap_dir, PRESERVE_DIRS | PRESERVE_FILES)

    _log(job, f"Rolling back to snapshot {snap_id} (version: {meta.get('version', 'unknown')})...")
    _log_restore_hint(job)

    # Create a safety snapshot before rollback
    _log(job, "Creating pre-rollback safety snapshot...")
    try:
        safety_snap = await create_snapshot(reason=f"pre-rollback from {snap_id}")
        _log(job, f"Safety snapshot: {safety_snap['id']}")
    except Exception as e:
        _log(job, f"WARNING: Could not create safety snapshot: {e}")

    # Restore files: remove current portal dir contents (excluding venv, backups, .git, data)
    # The safety snapshot above takes a while; re-verify so the snapshot cannot
    # have been swapped or loosened in the meantime.
    await asyncio.to_thread(_check_snapshot_restorable, snap_dir, PRESERVE_DIRS | PRESERVE_FILES)

    _log(job, "Removing current portal files (preserving venv, db, .env, etc.)...")
    for item in PORTAL_DIR.iterdir():
        if item.name in PRESERVE_DIRS or item.name in PRESERVE_FILES:
            continue
        try:
            if not item.is_symlink() and any(item.resolve() in k.parents for k in staging_keeps):
                _rmtree_except(item.resolve(), staging_keeps)
            elif item.is_dir():
                shutil.rmtree(str(item))
            else:
                item.unlink()
        except Exception as e:
            _log(job, f"WARNING: Could not remove {item.name}: {e}")

    _log(job, "Copying snapshot files...")
    for item in snap_dir.iterdir():
        if item.name in PRESERVE_DIRS or item.name in PRESERVE_FILES:
            continue
        dest = PORTAL_DIR / item.name
        try:
            if item.is_symlink():
                # Preserve symlinks as-is (don't follow — prevents symlink escape)
                os.symlink(os.readlink(item), dest)
            elif item.is_dir():
                # dest may still exist when it holds a preserved folder. An older snapshot
                # (taken before static/uploads was left out) may hold one: never copy it back.
                shutil.copytree(str(item), str(dest), symlinks=True, dirs_exist_ok=True,
                                ignore=_keep_ignore(snap_dir, staging_keeps))
            else:
                shutil.copy2(str(item), str(dest))
        except Exception as e:
            _log(job, f"WARNING: Could not copy {item.name}: {e}")

    _log(job, "Reinstalling Python dependencies...")
    rc, out, err = await _run_cmd(
        [sys.executable, "-m", "pip", "install", "-r", str(PORTAL_DIR / "requirements.txt")],
        timeout=300,
    )
    if rc != 0:
        _log(job, f"WARNING: pip install failed: {err.strip()}")
    else:
        _log(job, "Dependencies reinstalled.")

    await asyncio.to_thread(_empty_vod_play_cache_dirs, job)

    await _record_history({
        "type": "rollback",
        "snap_id": snap_id,
        "version": meta.get("version", "unknown"),
        "job_id": job["id"],
    })
    _log(job, "Rollback complete. Scheduling service restart in 2 seconds...")

    async def _delayed_restart():
        await asyncio.sleep(2)
        await _run_cmd(["systemctl", "restart", "portal"], timeout=10)

    asyncio.create_task(_delayed_restart())
    _log(job, "Service restarting...")


async def start_rollback(snap_id: str) -> str:
    """Start a rollback job. Returns job_id."""
    if Config.STAGE_MODE:
        raise RuntimeError("Rollback is disabled in staged test mode")
    lock = _get_update_lock()
    if lock.locked():
        raise RuntimeError("Another update or rollback job is already running")

    async def _run(job: dict):
        async with lock:
            await _apply_rollback(job, snap_id)

    return start_job(f"Rollback to {snap_id}", _run)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

async def _cli_check_updates() -> None:
    """Print update check summary to stdout."""
    print("Checking for updates...")
    data = await check_all(force=True)
    print(f"\nChecked at: {data.get('checked_at', 'unknown')}\n")

    portal = data.get("portal", {})
    print(f"Portal:      {portal.get('current', '?')} → {portal.get('latest', '?')}"
          f"  {'[UPDATE AVAILABLE]' if portal.get('update_available') else '[up to date]'}")
    if portal.get("error"):
        print(f"             Error: {portal['error']}")

    pip = data.get("pip", {})
    pip_count = pip.get("count", 0)
    print(f"Pip:         {pip_count} package(s) outdated"
          f"  {'[UPDATES AVAILABLE]' if pip_count > 0 else '[up to date]'}")
    if pip.get("error"):
        print(f"             Error: {pip['error']}")
    elif pip_count > 0:
        for pkg in pip.get("packages", []):
            print(f"             - {pkg['name']}: {pkg['current']} → {pkg['latest']}")

    mediamtx = data.get("mediamtx", {})
    print(f"MediaMTX:    {mediamtx.get('current', '?')} → {mediamtx.get('latest', '?')}"
          f"  {'[UPDATE AVAILABLE]' if mediamtx.get('update_available') else '[up to date]'}")
    if mediamtx.get("error"):
        print(f"             Error: {mediamtx['error']}")

    system = data.get("system", {})
    sys_count = system.get("count", 0)
    print(f"System:      {sys_count} package(s) upgradable"
          f"  {'[UPDATES AVAILABLE]' if sys_count > 0 else '[up to date]'}")
    if system.get("error"):
        print(f"             Error: {system['error']}")
