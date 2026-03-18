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
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Optional

logger = logging.getLogger("portal.updates")

PORTAL_DIR = Path(__file__).parent.resolve()
BACKUPS_DIR = PORTAL_DIR / "backups"
SNAPSHOTS_DIR = BACKUPS_DIR / "snapshots"
HISTORY_FILE = BACKUPS_DIR / "update_history.jsonl"
GITHUB_PORTAL_REPO = "dustinm16/portal"
GITHUB_MEDIAMTX_REPO = "bluenviron/mediamtx"

# Cache: {key: {"data": ..., "ts": float}}
_check_cache: dict = {}
CACHE_TTL = 3600  # 1 hour

# Jobs: {job_id: {id, name, status, log, started_at, finished_at}}
_jobs: dict = {}
MAX_JOBS = 20


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
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
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
                    return {
                        "current": current,
                        "latest": latest,
                        "update_available": latest != current and latest != "unknown",
                        "release_url": data.get("html_url", ""),
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
                    return {
                        "current": current,
                        "latest": latest,
                        "latest_tag": latest_tag,
                        "update_available": (
                            current not in ("not installed", "unknown")
                            and latest != "unknown"
                            and latest != current
                        ) or current == "not installed",
                        "release_url": data.get("html_url", ""),
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
        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
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
    return data


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

EXCLUDE_DIRS = {"venv", "__pycache__", ".git", "backups"}
EXCLUDE_SUFFIXES = {".pyc", ".db-shm", ".db-wal"}


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


async def create_snapshot(reason: str = "manual") -> dict:
    """Create a directory snapshot of the portal (excluding venv, __pycache__, etc.)."""
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
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
    def _ignore(src, names):
        ignored = set()
        for name in names:
            p = Path(src) / name
            if name in EXCLUDE_DIRS:
                ignored.add(name)
            elif p.is_file() and p.suffix in EXCLUDE_SUFFIXES:
                ignored.add(name)
        return ignored

    try:
        shutil.copytree(str(PORTAL_DIR), str(snap_dir), ignore=_ignore)
    except Exception as e:
        raise RuntimeError(f"Failed to copy portal directory: {e}") from e

    size = _snapshot_size(snap_dir)

    meta = {
        "id": snap_id,
        "reason": reason,
        "version": current_version,
        "created_at": _ts(),
        "size_bytes": size,
        "size_human": _format_size(size),
        "git_stash_ref": git_stash_ref,
        "path": str(snap_dir),
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
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

    target = version or "master"
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

    args = [sys.executable, "-m", "pip", "install", "--upgrade"] + pkg_list
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
        _log(job, f"Installing binary to {dest}...")
        shutil.copy2(str(binary_src), str(dest))
        dest.chmod(0o755)
        _log(job, "Binary installed.")

    # Restart mediamtx if it's running
    _log(job, "Restarting mediamtx service...")
    rc, out, err = await _run_cmd(["systemctl", "restart", "mediamtx"], timeout=15)
    if rc != 0:
        _log(job, f"WARNING: systemctl restart mediamtx: {err.strip()}")
    else:
        _log(job, "mediamtx service restarted.")

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
        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        timeout=120,
    )
    if rc != 0:
        raise RuntimeError(f"apt-get update failed: {err.strip()}")
    _log(job, "apt-get update complete. Running apt-get upgrade...")

    rc, out, err = await _run_cmd(
        ["apt-get", "upgrade", "-y", "-qq"],
        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
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


async def start_apply(component: str, version: Optional[str] = None) -> str:
    """Dispatch an update job for the given component. Returns job_id."""
    component = component.lower()
    if component not in ("portal", "pip", "mediamtx", "system"):
        raise ValueError(f"Unknown component: {component}")

    async def _run(job: dict):
        if component == "portal":
            await _apply_portal_update(job, version)
        elif component == "pip":
            await _apply_pip_update(job, version)
        elif component == "mediamtx":
            await _apply_mediamtx_update(job, version)
        elif component == "system":
            await _apply_system_update(job)

    name = f"Update {component}" + (f" to {version}" if version else "")
    return start_job(name, _run)


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

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

    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    _log(job, f"Rolling back to snapshot {snap_id} (version: {meta.get('version', 'unknown')})...")

    # Create a safety snapshot before rollback
    _log(job, "Creating pre-rollback safety snapshot...")
    try:
        safety_snap = await create_snapshot(reason=f"pre-rollback from {snap_id}")
        _log(job, f"Safety snapshot: {safety_snap['id']}")
    except Exception as e:
        _log(job, f"WARNING: Could not create safety snapshot: {e}")

    # Restore files: remove current portal dir contents (excluding venv, backups, .git, data)
    PRESERVE_DIRS = {"venv", "backups", ".git", "data", "__pycache__"}
    PRESERVE_FILES = {".env", "portal.db", "portal.db-shm", "portal.db-wal", "portal.db.backup"}

    _log(job, "Removing current portal files (preserving venv, db, .env, etc.)...")
    for item in PORTAL_DIR.iterdir():
        if item.name in PRESERVE_DIRS or item.name in PRESERVE_FILES:
            continue
        try:
            if item.is_dir():
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
            if item.is_dir():
                shutil.copytree(str(item), str(dest))
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
    async def _run(job: dict):
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
