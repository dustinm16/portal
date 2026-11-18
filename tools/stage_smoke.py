#!/usr/bin/env python3
"""Staged-instance smoke runner.

Builds a throwaway copy of this source tree in a private temp directory,
starts the portal there on 127.0.0.1 (self-signed certificate, its own
database, .env and encryption salt), runs every check module in
tools/smoke_checks/ against it, prints one line per check and exits non-zero
if any check failed. It never touches the production checkout, database,
.env, service or port.

    /path/to/venv/bin/python tools/stage_smoke.py [options]

Run it with the project's interpreter: the same interpreter starts the staged
server and runs the checks.

Check module interface (tools/smoke_checks/check_<name>.py):

    async def run(ctx) -> None

    ctx.base_url, ctx.stage_dir, ctx.admin_user, ctx.admin_password
    ctx.http()                    aiohttp.ClientSession (TLS verify off, unsafe cookie jar)
    await ctx.login(session, username, password, totp_code=None)
    await ctx.run_py(code)        -> (returncode, output), cwd = stage dir
    await ctx.stop_server()       stop the staged server (a check that does so must start it again)
    await ctx.start_server(wait_healthy=True)
                                  start it on the same database; False returns without waiting for /health
    ctx.server_log()              the whole staged server log so far
    ctx.ok(name, passed, detail)  record one result
    ctx.skip(name, reason)        record a check that could not run (not a failure)
"""

import argparse
import asyncio
import hashlib
import importlib.util
import os
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

try:
    import aiohttp
except ImportError:  # pragma: no cover
    sys.exit("aiohttp is not available: run this with the project's virtualenv interpreter")

TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_SOURCE = TOOLS_DIR.parent
CHECKS_DIR = TOOLS_DIR / "smoke_checks"
PYTHON = sys.executable
HEALTH_TIMEOUT = 60          # seconds to wait for /health after a start
MODULE_TIMEOUT = 180         # seconds allowed for one check module

# Files that must never be copied into a stage from a source tree.
_NEVER_COPY = {".env", ".encryption_salt", ".invite_code", "admin_credentials.txt"}
_NEVER_COPY_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal", ".pem", ".key")
_SKIP_DIRS = {".git", "venv", ".venv", "__pycache__", "certs", "logs", "recordings", "data", "backups"}

# Keys the runner always forces in the staged .env.
_FORCED_ENV = (
    "HOST", "PORT", "HOSTNAME", "SSL_CERT", "SSL_KEY", "DATABASE_PATH",
    "RECORDINGS_DIR", "VOD_TEMP_DIR", "PORTAL_STAGE_MODE", "PROBE_BLOCK_STRIKES", "PROBE_BLOCK_SECONDS",
    "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW",
)
# Keys dropped from a copied .env (they enable outgoing calls to third parties).
_DROP_ENV = {"SHODAN_API_KEY", "NVD_API_KEY"}


class RunnerError(Exception):
    """Raised for a setup failure; the message is shown with the log tail."""


class _Terminated(BaseException):
    """Raised by the SIGTERM/SIGHUP handler so the cleanup in main() runs."""

    def __init__(self, signum: int):
        super().__init__(signum)
        self.signum = signum


# ---------------------------------------------------------------------------
# Context handed to check modules
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, stage_dir: Path, port: int, env: dict, admin_user: str, admin_password):
        self.stage_dir = stage_dir
        self.base_url = f"https://127.0.0.1:{port}"
        self.admin_user = admin_user
        self.admin_password = admin_password
        self._env = env
        self.server: "StagedServer | None" = None
        self.results: list[tuple[str, str, str, str]] = []   # (status, module, name, detail)
        self.module = "runner"

    def http(self) -> "aiohttp.ClientSession":
        return aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=30),
        )

    async def login(self, session, username, password, totp_code=None):
        body = {"username": username, "password": password}
        if totp_code:
            body["totp_code"] = totp_code
        resp = await session.post(f"{self.base_url}/login", json=body)
        await resp.read()    # body stays available to resp.json()/resp.text()
        return resp

    async def run_py(self, code: str, timeout: int = 120):
        proc = await asyncio.create_subprocess_exec(
            PYTHON, "-c", code,
            cwd=str(self.stage_dir), env=self._env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return 124, "run_py timed out"
        return proc.returncode, out.decode("utf-8", "replace")

    async def stop_server(self) -> None:
        if self.server is None:
            raise RunnerError("no staged server is attached to this context")
        await asyncio.to_thread(self.server.stop)

    async def start_server(self, wait_healthy: bool = True) -> None:
        if self.server is None:
            raise RunnerError("no staged server is attached to this context")
        await asyncio.to_thread(self.server.start)
        if wait_healthy:
            await asyncio.to_thread(self.server.wait_healthy)

    def server_log(self) -> str:
        if self.server is None:
            return ""
        try:
            return self.server.log_path.read_text(errors="replace")
        except OSError:
            return ""

    def ok(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append(("PASS" if passed else "FAIL", self.module, name, detail))
        self._print(self.results[-1])

    def skip(self, name: str, reason: str = "") -> None:
        self.results.append(("SKIP", self.module, name, reason))
        self._print(self.results[-1])

    @staticmethod
    def _print(row) -> None:
        status, module, name, detail = row
        line = f"{status:<4}  [{module}] {name}"
        if detail:
            line += f"  ({detail})"
        print(line, flush=True)

    @property
    def failed(self) -> list:
        return [r for r in self.results if r[0] == "FAIL"]


# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------

def _source_files(source: Path) -> list[Path]:
    """Relative paths of the source tree's files: tracked plus new unignored
    ones, as they are on disk now, so uncommitted edits are tested."""
    rels: list[str] = []
    try:
        out = subprocess.run(
            ["git", "-C", str(source), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        ).stdout
        rels = [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        for root, dirs, files in os.walk(source):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for f in files:
                rels.append(os.path.relpath(os.path.join(root, f), source))
    keep = []
    for rel in sorted(set(rels)):
        p = Path(rel)
        if p.name in _NEVER_COPY or p.name.endswith(_NEVER_COPY_SUFFIXES):
            continue
        if any(part in _SKIP_DIRS for part in p.parts[:-1]):
            continue
        if not (source / p).exists() and not (source / p).is_symlink():
            continue    # listed by git but deleted in the working tree
        keep.append(p)
    return keep


def stage_tree(source: Path, stage: Path) -> int:
    count = 0
    for rel in _source_files(source):
        src, dst = source / rel, stage / rel
        if src.is_dir() and not src.is_symlink():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst, follow_symlinks=False)
        count += 1
    return count


def make_cert(stage: Path) -> tuple[Path, Path]:
    cert, key = stage / "stage-cert.pem", stage / "stage-key.pem"
    res = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise RunnerError(f"openssl could not create the test certificate: {res.stderr.strip()[-300:]}")
    key.chmod(0o600)
    return cert, key


def write_env(stage: Path, port: int, cert: Path, key: Path, base_env: Path | None) -> list[str]:
    """Write the staged .env. Returns the names of keys dropped from a copied one."""
    import secrets

    forced = {
        "HOST": "127.0.0.1",
        "PORT": str(port),
        "HOSTNAME": "localhost",
        "SSL_CERT": str(cert),
        "SSL_KEY": str(key),
        "DATABASE_PATH": str(stage / "portal.db"),
        "RECORDINGS_DIR": str(stage / "recordings"),
        "VOD_TEMP_DIR": str(stage / "data" / "vod_tmp"),
        "PORTAL_STAGE_MODE": "1",
        # turn on the scanner-probe blocker so a check about it is not vacuous
        "PROBE_BLOCK_STRIKES": "3",
        "PROBE_BLOCK_SECONDS": "60",
        # Every check module talks to the stage from 127.0.0.1, so the per-IP
        # request limit would be shared by all of them. A check of the limit
        # itself must exercise it in-process, not through the staged server.
        "RATE_LIMIT_REQUESTS": "100000",
        "RATE_LIMIT_WINDOW": "60",
    }
    lines: list[str] = []
    dropped: list[str] = []
    if base_env is None:
        forced["JWT_SECRET"] = secrets.token_hex(32)
    else:
        for raw in base_env.read_text().splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k in forced:
                continue
            # Any other absolute path could point the staged server at real
            # files, and some keys enable outgoing calls: drop them.
            if k in _DROP_ENV or v.startswith("/"):
                dropped.append(k)
                continue
            lines.append(f"{k}={v}")
    lines += [f"{k}={v}" for k, v in forced.items()]
    env_path = stage / ".env"
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)
    return dropped


def child_env(stage: Path) -> dict:
    """A clean environment: nothing from the caller's shell can reach the stage."""
    home = stage / "home"
    home.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "HOME": str(home),
        "PORTAL_STAGE_MODE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }


def copy_db_readonly(src: Path, dst: Path) -> None:
    """Copy a database through the SQLite backup API, opening the source read-only."""
    try:
        source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    except sqlite3.Error as e:
        raise RunnerError(f"cannot open {src} read-only: {e}")
    try:
        dest = sqlite3.connect(str(dst))
        try:
            source.backup(dest)
        finally:
            dest.close()
    except sqlite3.Error as e:
        raise RunnerError(f"backup of {src} failed: {e} (point --from-db at a copy if it is in use)")
    finally:
        source.close()
    dst.chmod(0o600)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def schema_fingerprint(db_path: Path) -> tuple[str, str]:
    """(sha256 of the sorted schema, integrity_check result) of a stopped database."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()
    return hashlib.sha256(repr(rows).encode()).hexdigest()[:16], integrity


# ---------------------------------------------------------------------------
# Server process control (plain synchronous code so cleanup survives Ctrl-C)
# ---------------------------------------------------------------------------

class StagedServer:
    def __init__(self, stage: Path, env: dict, port: int, cert: Path):
        self.stage, self.env, self.port, self.cert = stage, env, port, cert
        self.log_path = stage / "server.log"
        self.proc: subprocess.Popen | None = None
        self._log_start = 0

    def port_busy(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(("127.0.0.1", self.port)) == 0

    def start(self) -> None:
        if self.port_busy():
            raise RunnerError(f"127.0.0.1:{self.port} is already in use; refusing to start (use --port)")
        self._log_start = self.log_path.stat().st_size if self.log_path.exists() else 0
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                [PYTHON, "server.py", "serve"], cwd=str(self.stage), env=self.env,
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        finally:
            log.close()

    def wait_healthy(self, timeout: float = HEALTH_TIMEOUT) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        deadline = time.monotonic() + timeout
        url = f"https://127.0.0.1:{self.port}/health"
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RunnerError(f"staged server exited early (code {self.proc.returncode})")
            try:
                with urllib.request.urlopen(url, timeout=2, context=ctx) as r:
                    if r.status == 200:
                        self._check_own_certificate()
                        return
            except RunnerError:
                raise
            except Exception:
                pass
            time.sleep(0.5)
        raise RunnerError(f"staged server did not answer /health within {timeout:.0f}s")

    def _check_own_certificate(self) -> None:
        """The answering server must be ours: another instance on the same
        port would present a different certificate."""
        try:
            served = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("127.0.0.1", self.port)))
        except OSError as e:
            raise RunnerError(f"could not read the server certificate on port {self.port}: {e}")
        if served != ssl.PEM_cert_to_DER_cert(self.cert.read_text()):
            raise RunnerError(f"the server answering on port {self.port} is not the staged one (certificate differs)")

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=10)
        else:
            try:    # reap any stragglers of an already-dead leader's group
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def log_since_start(self) -> str:
        try:
            with open(self.log_path, "rb") as f:
                f.seek(self._log_start)
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def log_tail(self, lines: int = 40) -> str:
        try:
            text = self.log_path.read_text(errors="replace")
        except OSError:
            return "(no server log)"
        return "\n".join(text.splitlines()[-lines:])


_LOG_PROBLEMS = ("Traceback (most recent call last)", "Migration skipped")


def log_problems(text: str) -> list[str]:
    return [line.strip()[:160] for line in text.splitlines() if any(p in line for p in _LOG_PROBLEMS)]


# ---------------------------------------------------------------------------
# Check modules
# ---------------------------------------------------------------------------

def discover_modules(only: str | None) -> list[Path]:
    mods = sorted(CHECKS_DIR.glob("check_*.py"))
    if only:
        want = only if only.startswith("check_") else f"check_{only}"
        mods = [m for m in mods if m.stem == want]
        if not mods:
            raise RunnerError(f"no check module named {only!r} in {CHECKS_DIR}")
    return mods


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(f"smoke_checks.{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def run_checks(ctx: Ctx, modules: list[Path], selftest_fail: bool, selftest_hang: bool = False) -> None:
    for path in modules:
        ctx.module = path.stem.removeprefix("check_")
        before = len(ctx.results)
        try:
            mod = load_module(path)
            await asyncio.wait_for(mod.run(ctx), MODULE_TIMEOUT)
            if len(ctx.results) == before:
                # a module that returns early or never reaches its checks is not a pass
                ctx.ok("module recorded at least one result", False,
                       "run() finished without calling ctx.ok() or ctx.skip()")
        except asyncio.TimeoutError:
            ctx.ok("module finished in time", False, f"timed out after {MODULE_TIMEOUT}s")
        except Exception as e:
            tb = traceback.format_exc().strip().splitlines()
            ctx.ok("module ran without an exception", False, f"{type(e).__name__}: {e} @ {tb[-2].strip() if len(tb) > 1 else ''}")
    if selftest_fail:
        ctx.module = "selftest"
        ctx.ok("deliberate failure (runner self-test)", False, "this check always fails; exit status must be non-zero")
    if selftest_hang:   # lets tools/test_stage_smoke_signals.py signal a live runner
        await asyncio.sleep(3600)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Run smoke checks against a throwaway staged copy of the portal.")
    p.add_argument("--port", type=int, default=8461, help="port to bind on 127.0.0.1 (default 8461)")
    p.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                   help="tree to stage (default: the repository this script lives in; working-tree files)")
    p.add_argument("--keep", action="store_true", help="do not delete the stage directory at the end")
    p.add_argument("--only", metavar="NAME", help="run one check module (e.g. baseline)")
    p.add_argument("--from-db", type=Path, metavar="PATH",
                   help="copy this database (SQLite backup API, opened read-only) instead of starting fresh")
    p.add_argument("--env", type=Path, metavar="PATH", help="with --from-db: matching .env to copy")
    p.add_argument("--salt", type=Path, metavar="PATH", help="with --from-db: matching .encryption_salt to copy")
    p.add_argument("--admin-user", default="admin", help="with --from-db: admin account for login checks")
    p.add_argument("--admin-password", help="with --from-db: password of that account (enables login checks)")
    p.add_argument("--selftest-fail", action="store_true",
                   help="add a deliberately failing check to prove the runner exits non-zero")
    p.add_argument("--selftest-hang", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    if not (1024 <= args.port <= 65535) or args.port == 443:
        p.error("--port must be an unprivileged port (1024-65535)")
    if (args.env or args.salt or args.admin_password) and not args.from_db:
        p.error("--env, --salt and --admin-password only make sense with --from-db")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    source = args.source.resolve()
    prod_files = [f for f in (args.from_db, args.env, args.salt) if f]
    for f in prod_files:
        if not f.is_file():
            print(f"error: {f} is not a file", file=sys.stderr)
            return 2

    stage = Path(tempfile.mkdtemp(prefix="portal-stage-")).resolve()
    stage.chmod(0o700)
    print(f"stage dir: {stage}" + ("  (kept)" if args.keep else ""), flush=True)

    # SIGTERM (timeout, CI cancel, kill) and SIGHUP (closed terminal) must run
    # the same cleanup as Ctrl-C: the staged server lives in its own session
    # and would otherwise survive the runner.
    def _terminate(signum, _frame):
        raise _Terminated(signum)
    for _sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, _terminate)

    rc = 2
    try:
        rc = _run(args, source, stage, prod_files)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        rc = 130
    except _Terminated as e:
        print(f"\nterminated by signal {e.signum}", file=sys.stderr)
        rc = 128 + e.signum
    except RunnerError as e:
        print(f"FAIL  [runner] {e}", file=sys.stderr)
        rc = 2
    except Exception:
        traceback.print_exc()
        rc = 2
    finally:
        # a second signal must not interrupt the cleanup itself
        for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(_sig, signal.SIG_IGN)
        if _STATE["server"] is not None:
            _STATE["server"].stop()
        if args.keep:
            print(f"stage dir kept: {stage}")
        else:
            shutil.rmtree(stage, ignore_errors=True)
    return rc


_STATE: dict = {"server": None}


def _run(args, source: Path, stage: Path, prod_files: list) -> int:
    n = stage_tree(source, stage)
    print(f"staged {n} files from {source}")
    has_switch = "PORTAL_STAGE_MODE" in (stage / "config.py").read_text(errors="replace")
    if not has_switch:
        if args.from_db:
            raise RunnerError(
                "the staged tree has no PORTAL_STAGE_MODE switch (config.py); refusing --from-db because a copy "
                "of real data could start managed services and send webhooks. Stage a tree that has it.")
        print("warning: the staged tree has no PORTAL_STAGE_MODE switch; side effects are not disabled "
              "(acceptable only because the database is fresh)", file=sys.stderr)
    cert, key = make_cert(stage)
    modules = discover_modules(args.only)

    before = {f: sha256(f) for f in prod_files}
    admin_user, admin_password = args.admin_user, args.admin_password
    dropped: list[str] = []

    if args.from_db:
        copy_db_readonly(args.from_db, stage / "portal.db")
        if args.salt:
            shutil.copy2(args.salt, stage / ".encryption_salt")
            (stage / ".encryption_salt").chmod(0o600)
        dropped = write_env(stage, args.port, cert, key, args.env)
        if not args.env:
            print("warning: no --env given; the staged server gets a new JWT secret", file=sys.stderr)
        if not args.salt:
            print("warning: no --salt given; encrypted data in the copy will not decrypt", file=sys.stderr)
        conn = sqlite3.connect(str(stage / "portal.db"))
        try:    # keys that would make the staged server call third parties
            conn.execute("DELETE FROM settings WHERE key IN ('shodan_api_key', 'nvd_api_key')")
            conn.commit()
        except sqlite3.Error:
            pass
        finally:
            conn.close()
        if dropped:
            print(f"dropped from the copied .env: {', '.join(dropped)}")
    else:
        write_env(stage, args.port, cert, key, None)

    env = child_env(stage)
    server = StagedServer(stage, env, args.port, cert)
    _STATE["server"] = server
    ctx = Ctx(stage, args.port, env, admin_user, admin_password)
    ctx.server = server

    try:
        if not args.from_db:
            res = subprocess.run([PYTHON, "server.py", "init"], cwd=str(stage), env=env,
                                 capture_output=True, text=True, timeout=120)
            (stage / "init.log").write_text(res.stdout + res.stderr)
            creds = stage / "admin_credentials.txt"
            if res.returncode != 0 or not creds.exists():
                raise RunnerError(f"'server.py init' failed:\n{(res.stdout + res.stderr)[-800:]}")
            for line in creds.read_text().splitlines():
                if line.startswith("Password:"):
                    ctx.admin_password = line.split(":", 1)[1].strip()
            ctx.admin_user = "admin"

        # First start, stop, second start on the same database: migrations must be idempotent.
        server.start()
        server.wait_healthy()
        first_log = server.log_since_start()
        server.stop()
        fp1 = schema_fingerprint(stage / "portal.db")
        server.start()
        server.wait_healthy()
        second_log = server.log_since_start()
        ctx.module = "runner"
        # the schema after the second start is compared below, once that server is stopped
        ctx.ok("first start is healthy and clean", not log_problems(first_log), "; ".join(log_problems(first_log))[:300])
        ctx.ok("second start on the same database is clean", not log_problems(second_log),
               "; ".join(log_problems(second_log))[:300])

        asyncio.run(run_checks(ctx, modules, args.selftest_fail, args.selftest_hang))

        server.stop()
        ctx.module = "runner"
        fp2 = schema_fingerprint(stage / "portal.db")
        ctx.ok("schema unchanged by the second start", fp1 == fp2 and fp2[1] == "ok",
               f"schema {fp1[0]} -> {fp2[0]}, integrity_check {fp2[1]}")
        if prod_files:
            after = {f: sha256(f) for f in prod_files}
            changed = [str(f) for f in prod_files if before[f] != after[f]]
            ctx.ok("source files untouched (sha256 before/after)", not changed,
                   ", ".join(changed) if changed else f"{len(prod_files)} file(s) compared; a live database may differ legitimately")
    except RunnerError as e:
        print(f"FAIL  [runner] {e}")
        print("---- staged server log (tail) ----")
        print(server.log_tail())
        print("----------------------------------")
        return 2
    finally:
        server.stop()

    failed = ctx.failed
    skipped = [r for r in ctx.results if r[0] == "SKIP"]
    passed = [r for r in ctx.results if r[0] == "PASS"]
    if failed:
        print("\n---- staged server log (tail) ----")
        print(server.log_tail(15))
        print("----------------------------------")
    print(f"\n{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")
    if failed:
        print("failed checks:")
        for _, module, name, detail in failed:
            print(f"  - [{module}] {name}" + (f"  ({detail})" if detail else ""))
        print("(re-run with --keep to keep the stage directory and its full server log)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
