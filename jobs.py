"""Lightweight in-memory background jobs with a streaming subprocess runner.

Used for long, chatty operations (SteamCMD installs/updates) where the caller
wants to poll a growing log. Modelled on the job registry in update_manager.py
but independent — game-server jobs live here, portal-update jobs stay there.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("portal.jobs")

_jobs: dict = {}
MAX_JOBS = 40
_MAX_LOG_LINES = 5000


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(job: dict, msg: str) -> None:
    """Append a timestamped line to a job's log (trims to the last N lines)."""
    for line in str(msg).splitlines() or [""]:
        job["log"].append(f"[{_ts()}] {line}" if not line.startswith("[") else line)
    if len(job["log"]) > _MAX_LOG_LINES:
        del job["log"][: len(job["log"]) - _MAX_LOG_LINES]
    logger.info("job=%s %s", job["id"], str(msg).splitlines()[0] if str(msg) else "")


def get_job(job_id: str) -> Optional[dict]:
    return _jobs.get(job_id)


def list_jobs() -> list[dict]:
    return sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)


def _evict() -> None:
    if len(_jobs) < MAX_JOBS:
        return
    done = sorted(
        (j for j in _jobs.values() if j["status"] != "running"),
        key=lambda j: j["started_at"],
    )
    for j in done[: len(_jobs) - MAX_JOBS + 1]:
        _jobs.pop(j["id"], None)


def start_job(name: str, coro, meta: dict = None) -> str:
    """Run `coro(job)` in the background. Returns the job id immediately."""
    _evict()
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "name": name,
        "status": "running",
        "log": [],
        "started_at": _ts(),
        "finished_at": None,
        **(meta or {}),
    }
    _jobs[job_id] = job

    async def _runner():
        try:
            await coro(job)
            if job["status"] == "running":
                job["status"] = "completed"
        except Exception as e:
            job["status"] = "failed"
            log(job, f"ERROR: {e}")
            logger.exception("job %s failed", job_id)
        finally:
            job["finished_at"] = _ts()

    asyncio.create_task(_runner())
    return job_id


async def run_streamed(job: dict, args: list, cwd: str = None, env: dict = None,
                       timeout: int = 3600) -> int:
    """Run a subprocess, streaming stdout+stderr lines into job['log'].

    Returns the exit code (or -1 on spawn failure / timeout).
    """
    log(job, "$ " + " ".join(args))
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, cwd=cwd, env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as e:
        log(job, f"command not found: {e}")
        return -1
    except Exception as e:
        log(job, f"failed to start: {e}")
        return -1

    async def _pump():
        assert proc.stdout is not None
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip()
            if line:
                log(job, line)

    try:
        await asyncio.wait_for(asyncio.gather(_pump(), proc.wait()), timeout=timeout)
    except asyncio.TimeoutError:
        log(job, f"timed out after {timeout}s — killing")
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return -1
    return proc.returncode if proc.returncode is not None else -1
