"""Backup archives: routes, permissions, scheduling, update backup, and a restore that starts and decrypts."""

import asyncio
import io
import json
import os
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tarfile
from pathlib import Path

import pyotp

PREFIX = "bk_"

SETUP = r'''
import asyncio, json
import pyotp
from database import db
from auth import create_user, generate_totp_secret, generate_backup_codes

async def main():
    await db.connect()
    out = {}
    user = await create_user("bk_totp", "Pw-bk_totp-12345!", is_admin=False)
    secret = generate_totp_secret()
    await db.set_user_totp_secret(user["id"], secret)
    await db.enable_user_totp(user["id"], generate_backup_codes(3))
    out["secret"] = secret
    out["uid"] = user["id"]
    adm = await create_user("bk_admin", "Pw-bk_admin-12345!", is_admin=True)
    await db.set_user_role(adm["id"], "admin")
    cur = await db.conn.execute("SELECT id FROM chat_channels ORDER BY id LIMIT 1")
    row = await cur.fetchone()
    if row:
        channel = row["id"]
    else:
        cur = await db.conn.execute("INSERT INTO chat_channels (name) VALUES ('bk_general')")
        await db.conn.commit()
        channel = cur.lastrowid
    await db.create_chat_message(channel, user["id"], "bk_totp", "bk-secret-message-7421")
    out["channel"] = channel
    cur = await db.conn.execute("SELECT role FROM users WHERE username = 'admin'")
    out["admin_role"] = (await cur.fetchone())["role"]
    await db.conn.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''

MARKER = r'''
import asyncio
from database import db
from auth import create_user

async def main():
    await db.connect()
    await create_user("bk_marker", "Pw-bk_marker-12345!", is_admin=False)
    await db.conn.close()
    print("RESULT done")

asyncio.run(main())
'''

SCHEDULE = r'''
import asyncio, json, os
from config import Config
from database import db
import backup_manager as bm

async def main():
    await db.connect()
    adir = bm.archives_dir()
    before = set(os.listdir(adir))
    res = {"stage_mode": bool(Config.STAGE_MODE)}
    res["skipped_in_stage"] = (await bm.run_scheduled()) is None
    res["no_file_in_stage"] = set(os.listdir(adir)) == before
    res["startup_skipped_in_stage"] = (await bm.run_startup_check(delay=0)) is None and set(os.listdir(adir)) == before
    Config.STAGE_MODE = False
    await db.set_setting("backup_last_ok_at", "2000-01-01T00:00:00+00:00")
    first = await bm.run_scheduled()
    res["ran_when_due"] = bool(first) and first["name"] not in before
    second = await bm.run_scheduled()
    res["not_due_again"] = second is None
    await db.set_setting("backup_last_ok_at", "2000-01-01T00:00:00+00:00")
    startup = await bm.run_startup_check(delay=0)
    res["startup_ran_when_due"] = bool(startup)
    res["startup_not_repeated"] = (await bm.run_startup_check(delay=0)) is None
    await db.set_setting("backup_enabled", "false")
    await db.set_setting("backup_last_ok_at", "2000-01-01T00:00:00+00:00")
    res["disabled_skips"] = (await bm.run_scheduled()) is None
    await db.set_setting("backup_enabled", "true")
    res["status"] = (await bm.get_status()).get("backup_last_status")
    await db.conn.close()
    print("RESULT " + json.dumps(res))

asyncio.run(main())
'''

UPDATE = r'''
import asyncio, json, os, shutil
from database import db
import update_manager as um
import backup_manager as bm

calls = []

async def fake_run_cmd(cmd, *a, **k):
    calls.append(" ".join(str(c) for c in cmd))
    return 0, "", ""

um._run_cmd = fake_run_cmd

async def main():
    await db.connect()
    adir = bm.archives_dir()
    res = {}
    before = set(os.listdir(adir))
    job = {"id": "smoke", "log": []}
    await um._run_apply(job, "portal", None)
    new = sorted(set(os.listdir(adir)) - before)
    res["fresh_archive"] = len(new) == 1
    res["git_after_backup"] = any(" fetch " in c or "checkout" in c for c in calls)
    res["log_mentions_backup"] = any("Backup archive created" in l for l in job["log"])

    # A failing backup must stop the update before anything else runs.
    calls.clear()
    real = shutil.disk_usage
    class _U:
        free = 1
        total = used = 0
    um.shutil.disk_usage = lambda p: _U()
    try:
        await um._run_apply({"id": "smoke2", "log": []}, "portal", None)
        res["refused"] = False
    except RuntimeError as e:
        res["refused"] = "Pre-update backup failed" in str(e)
    finally:
        um.shutil.disk_usage = real
    # only the read-only version lookup may have run; no fetch, checkout or pip
    res["nothing_ran"] = not any(("fetch" in c or "checkout" in c or "pip" in c) for c in calls)
    await db.conn.close()
    print("RESULT " + json.dumps(res))

asyncio.run(main())
'''

CLI_UPDATE = r'''
# What `server.py update` does: no database connection is opened first.
import asyncio, json, os
import update_manager as um
import backup_manager as bm

calls = []

async def fake_run_cmd(cmd, *a, **k):
    calls.append(" ".join(str(c) for c in cmd))
    return 0, "", ""

um._run_cmd = fake_run_cmd

async def main():
    adir = bm.archives_dir()
    before = set(os.listdir(adir))
    res = {}
    try:
        await um._run_apply({"id": "smoke3", "log": []}, "portal", None)
        res["completed"] = True
    except Exception as e:
        res["completed"] = False
        res["error"] = str(e)[:200]
    res["fresh_archive"] = len(set(os.listdir(adir)) - before) == 1
    print("RESULT " + json.dumps(res))

asyncio.run(main())
'''

WRITES = r'''
# Archives taken while another connection keeps writing the live database.
import json, os, sqlite3, tarfile, tempfile, threading
from config import Config
import backup_manager as bm

stop = threading.Event()
errors = []

def writer():
    c = sqlite3.connect(Config.DATABASE_PATH, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    i = 0
    try:
        while not stop.is_set():
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("bk_churn_%d" % (i % 300), "x" * 300))
            if i % 5 == 0:
                c.execute("DELETE FROM settings WHERE key = ?", ("bk_churn_%d" % ((i * 7) % 300),))
            c.commit()
            i += 1
    except Exception as e:
        errors.append(str(e))
    finally:
        c.close()

t = threading.Thread(target=writer)
t.start()
results = []
try:
    import time
    time.sleep(0.3)
    for _ in range(3):
        info = bm.create_archive(None, "smoke", 20, "")
        with tarfile.open(info["path"], "r:gz") as tar:
            data = tar.extractfile("portal.db").read()
        fd, tmp = tempfile.mkstemp(prefix="bk_snap_")
        os.write(fd, data)
        os.close(fd)
        conn = sqlite3.connect(tmp)
        results.append(conn.execute("PRAGMA integrity_check").fetchone()[0])
        conn.close()
        os.unlink(tmp)
finally:
    stop.set()
    t.join()
c = sqlite3.connect(Config.DATABASE_PATH, timeout=30)
c.execute("DELETE FROM settings WHERE key LIKE 'bk_churn_%'")
c.commit()
c.close()
print("RESULT " + json.dumps({"results": results, "errors": errors}))
'''

DECRYPT = r'''
import asyncio, json
from config import Config
from database import db

async def main():
    await db.connect()
    msgs = await db.get_chat_messages(__CHANNEL__, limit=50)
    user = await db.get_user_by_username("bk_totp")
    print("RESULT " + json.dumps({
        "db_path": Config.DATABASE_PATH,
        "messages": [m.get("message") for m in msgs],
        "totp_secret": user["totp_secret"] if user else None,
    }))
    await db.conn.close()

asyncio.run(main())
'''


def _result(out):
    for line in out.splitlines():
        if line.startswith("RESULT "):
            try:
                return json.loads(line[7:])
            except ValueError:
                return {}
    return {}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


async def _status(session, method, url, **kw):
    async with session.request(method, url, **kw) as r:
        body = await r.read()
        return r.status, body, r.headers


async def _restored_instance(ctx, archive_path, work, seed, marker_name):
    """Restore the archive into an empty directory, run the portal from it, and check it."""
    restored = os.path.join(work, "restored")
    env = dict(ctx._env)
    proc = subprocess.run(
        [sys.executable, "server.py", "restore-archive", archive_path, "--into", restored],
        cwd=str(ctx.stage_dir), env=env, capture_output=True, text=True, timeout=120,
    )
    files = sorted(os.listdir(restored)) if os.path.isdir(restored) else []
    ctx.ok("backups: restore-archive unpacks into a new empty directory",
           proc.returncode == 0 and files == sorted([".encryption_salt", ".env", ".invite_code", "portal.db"]) or
           (proc.returncode == 0 and {"portal.db", ".env", ".encryption_salt"} <= set(files)),
           f"rc={proc.returncode} files={files} {proc.stderr[-200:]}")
    ctx.ok("backups: restore-archive warns about paths that point at the original install",
           "DATABASE_PATH" in proc.stderr and "PORT=" in proc.stderr, proc.stderr[-300:])
    again = subprocess.run(
        [sys.executable, "server.py", "restore-archive", archive_path, "--into", restored],
        cwd=str(ctx.stage_dir), env=env, capture_output=True, text=True, timeout=120,
    )
    ctx.ok("backups: restore-archive refuses a directory that is not empty",
           again.returncode == 1 and "not empty" in again.stderr, f"rc={again.returncode} {again.stderr[-200:]}")
    live_target = os.path.join(str(ctx.stage_dir), "static", "bk_restore_probe")
    inside = subprocess.run(
        [sys.executable, "server.py", "restore-archive", archive_path, "--into", live_target],
        cwd=str(ctx.stage_dir), env=env, capture_output=True, text=True, timeout=120,
    )
    ctx.ok("backups: restore-archive refuses a target inside the live installation and writes nothing",
           inside.returncode == 1 and "live installation" in inside.stderr and not os.path.exists(live_target),
           f"rc={inside.returncode} {inside.stderr[-200:]}")

    # Build a runnable copy: the portal code plus the restored state, with the paths of
    # the original install replaced (the restored .env still names the stage's own files).
    skip = {"backups", "recordings", "home", "server.log", "init.log", "admin_credentials.txt",
            "portal.db", "portal.db-wal", "portal.db-shm", ".env", ".encryption_salt", ".invite_code"}
    for name in os.listdir(ctx.stage_dir):
        if name in skip:
            continue
        src, dst = os.path.join(ctx.stage_dir, name), os.path.join(restored, name)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst)
    port = _free_port()
    env_path = os.path.join(restored, ".env")
    keep = []
    for line in open(env_path).read().splitlines():
        key = line.split("=", 1)[0].strip()
        if key in ("PORT", "DATABASE_PATH", "RECORDINGS_DIR", "SSL_CERT", "SSL_KEY"):
            continue
        keep.append(line)
    keep += [f"PORT={port}", f"DATABASE_PATH={restored}/portal.db", f"RECORDINGS_DIR={restored}/recordings",
             f"SSL_CERT={restored}/stage-cert.pem", f"SSL_KEY={restored}/stage-key.pem"]
    with open(env_path, "w") as f:
        f.write("\n".join(keep) + "\n")
    os.chmod(env_path, 0o600)

    base = f"https://127.0.0.1:{port}"
    log = open(os.path.join(work, "restored.log"), "ab")
    server = subprocess.Popen([sys.executable, "server.py", "serve"], cwd=restored, env=env,
                              stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                              start_new_session=True)
    log.close()
    try:
        healthy = False
        deadline = time.monotonic() + 60
        async with ctx.http() as s:
            while time.monotonic() < deadline and server.poll() is None:
                try:
                    async with s.get(base + "/health") as r:
                        if r.status == 200:
                            healthy = True
                            break
                except Exception:
                    pass
                await asyncio.sleep(0.5)
        ctx.ok("backups: the portal starts from the restored directory", healthy,
               open(os.path.join(work, "restored.log"), errors="replace").read()[-300:] if not healthy else "")
        if not healthy:
            return restored
        ctx_user = "bk_totp"
        pw = "Pw-bk_totp-12345!"
        totp = pyotp.TOTP(seed["secret"])
        async with ctx.http() as s:
            r = await s.post(base + "/login", json={"username": ctx.admin_user, "password": ctx.admin_password})
            await r.read()
            ctx.ok("backups: restored instance: the existing admin can log in", r.status == 200, f"status={r.status}")
        async with ctx.http() as s:
            r = await s.post(base + "/login", json={"username": ctx_user, "password": pw, "totp_code": totp.now()})
            body = await r.json()
            ctx.ok("backups: restored instance: password plus TOTP code logs in (TOTP secret decrypts)",
                   r.status == 200 and body.get("status") == "logged_in", f"status={r.status} body={body}")
        async with ctx.http() as s:
            r = await s.post(base + "/login", json={"username": ctx_user, "password": pw, "totp_code": "000000"})
            await r.read()
            ctx.ok("backups: restored instance: a wrong TOTP code is refused", r.status != 200, f"status={r.status}")
        async with ctx.http() as s:
            r = await s.post(base + "/login", json={"username": marker_name, "password": "Pw-bk_marker-12345!"})
            await r.read()
            ctx.ok("backups: restored instance is the archive, not the live database (a later user is absent)",
                   r.status != 200, f"status={r.status}")
        async with ctx.http() as s:
            r = await s.post(ctx.base_url + "/login", json={"username": marker_name, "password": "Pw-bk_marker-12345!"})
            await r.read()
            ctx.ok("backups: the live stage still has the later user", r.status == 200, f"status={r.status}")
    finally:
        try:
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=15)
        except Exception:
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except Exception:
                pass
    # Decrypt straight from the restored directory (its own .env, salt and database).
    p = await asyncio.create_subprocess_exec(
        sys.executable, "-c", DECRYPT.replace("__CHANNEL__", str(seed["channel"])),
        cwd=restored, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await p.communicate()
    res = _result(out.decode("utf-8", "replace"))
    ctx.ok("backups: restored directory reads its own database", str(res.get("db_path", "")).startswith(restored),
           str(res.get("db_path")))
    ctx.ok("backups: encrypted chat message decrypts with the restored salt and secret",
           "bk-secret-message-7421" in (res.get("messages") or []), str(res.get("messages"))[:200])
    ctx.ok("backups: TOTP secret decrypts from the restored database", res.get("totp_secret") == seed["secret"])
    return restored


def _extra_base(ctx) -> str:
    """A writable directory that the extra-destination rules accept: not under a private temp
    folder, not inside the staged install, not inside the source checkout."""
    private = [os.path.realpath(p) for p in ("/tmp", "/var/tmp", "/dev/shm")]
    banned = private + [os.path.realpath(str(ctx.stage_dir)), os.path.realpath(str(Path(__file__).resolve().parents[2]))]
    candidates = [os.environ.get("XDG_RUNTIME_DIR"), os.path.expanduser("~"), str(Path(__file__).resolve().parents[3])]
    for c in candidates:
        if not c or not os.path.isdir(c) or not os.access(c, os.W_OK | os.X_OK):
            continue
        real = os.path.realpath(c)
        if any(real == b or real.startswith(b.rstrip(os.sep) + os.sep) for b in banned):
            continue
        return real
    raise RuntimeError("no directory outside /tmp, the stage and the checkout is writable for the extra destination checks")


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    seed = _result(out)
    if not seed:
        ctx.ok("backups: seed users and a chat message", False, out.strip()[-300:])
        return
    ctx.ok("backups: the stage admin is a superadmin", seed.get("admin_role") == "superadmin", str(seed.get("admin_role")))

    adir = os.path.join(ctx.stage_dir, "backups", "archives")
    base = ctx.base_url
    work = tempfile.mkdtemp(prefix="bk_work_")
    os.chmod(work, 0o700)
    # Extra destinations cannot live under /tmp, /var/tmp or /dev/shm (PrivateTmp), nor inside the
    # install (the stage directory) or a served root, so the stage's own temp area is no use; take
    # a private scratch folder somewhere else and never one inside the source checkout.
    xwork = tempfile.mkdtemp(prefix="bk_extra_", dir=_extra_base(ctx))
    os.chmod(xwork, 0o700)
    try:
        async with ctx.http() as admin, ctx.http() as other, ctx.http() as anon:
            r = await ctx.login(admin, ctx.admin_user, ctx.admin_password)
            if r.status != 200:
                ctx.ok("backups: superadmin login", False, f"status={r.status}")
                return
            r = await ctx.login(other, "bk_admin", "Pw-bk_admin-12345!")
            ctx.ok("backups: a plain admin can log in for the access checks", r.status == 200, f"status={r.status}")

            # ---- run now, permissions, listing
            st, body, _ = await _status(admin, "GET", base + "/api/admin/backups")
            listing = json.loads(body) if st == 200 else {}
            ctx.ok("backups: superadmin can list (staged mode reported)", st == 200 and listing.get("stage_mode") is True
                   and listing.get("config", {}).get("keep") == 7 and listing["config"]["interval_hours"] == 24,
                   f"status={st} {body[:200]!r}")
            st, body, _ = await _status(admin, "POST", base + "/api/admin/backups/run")
            info = json.loads(body) if st == 201 else {}
            name = info.get("name", "")
            path = os.path.join(adir, name) if name else ""
            ctx.ok("backups: run now works in staged mode and writes an archive", st == 201 and os.path.isfile(path),
                   f"status={st} {body[:200]!r}")
            if not os.path.isfile(path):
                return
            ctx.ok("backups: archive is 0600 and the archives directory 0700",
                   _mode(path) == 0o600 and _mode(adir) == 0o700 and _mode(os.path.dirname(adir)) == 0o700,
                   f"{_mode(path):04o} {_mode(adir):04o}")
            with tarfile.open(path, "r:gz") as tar:
                members = tar.getnames()
            ctx.ok("backups: archive holds manifest, database, .env and salt",
                   members[:2] == ["manifest.json", "portal.db"] and ".env" in members and ".encryption_salt" in members,
                   str(members))
            st, body, _ = await _status(admin, "GET", base + "/api/admin/backups")
            listing = json.loads(body)
            ctx.ok("backups: list shows the archive and a successful last run",
                   name in [a["name"] for a in listing.get("archives", [])] and listing["status"]["backup_last_status"] == "ok",
                   str(listing.get("status")))

            # ---- who may do what
            for label, method, url in (
                ("list", "GET", "/api/admin/backups"),
                ("run", "POST", "/api/admin/backups/run"),
                ("settings", "PUT", "/api/admin/backups/settings"),
                ("download", "GET", f"/api/admin/backups/{name}/download"),
                ("delete", "DELETE", f"/api/admin/backups/{name}"),
            ):
                kw = {"json": {"keep": 3}} if method == "PUT" else {}
                st, _, _ = await _status(other, method, base + url, **kw)
                ctx.ok(f"backups: a plain admin gets 403 on {label}", st == 403, f"status={st}")
                st, _, _ = await _status(anon, method, base + url, headers={"Accept": "application/json"}, **kw)
                ctx.ok(f"backups: no login gets 401 on {label}", st == 401, f"status={st}")
            ctx.ok("backups: the refused calls changed nothing", os.path.isfile(path))

            # ---- the admin file manager must not hand out archives (they hold the secrets)
            probe = os.path.join(work, "fm_probe.txt")
            with open(probe, "w") as f:
                f.write("file manager probe")
            st, body, _ = await _status(other, "GET", base + "/api/files/read", params={"path": probe})
            ctx.ok("backups: control: a plain admin can read an ordinary file through /api/files/read",
                   st == 200 and b"file manager probe" in body, f"status={st}")
            for label, who in (("a plain admin", other), ("the superadmin", admin)):
                for what, url in (("read", "/api/files/read"), ("download", "/api/files/download"),
                                  ("info", "/api/files/info")):
                    st, body, _ = await _status(who, "GET", base + url, params={"path": path})
                    ctx.ok(f"backups: {label} is refused the archive through /api/files ({what})",
                           st == 400 and body[:2] != b"\x1f\x8b" and b"not allowed" in body, f"status={st} {body[:120]!r}")
                st, body, _ = await _status(who, "GET", base + "/api/files/list", params={"path": adir})
                ctx.ok(f"backups: {label} cannot list the archives directory through /api/files",
                       st == 400 and name.encode() not in body, f"status={st} {body[:120]!r}")
            st, body, _ = await _status(other, "GET", base + "/api/files/list", params={"path": os.path.dirname(adir)})
            ctx.ok("backups: the backups directory as a whole cannot be listed through /api/files",
                   st == 400 and b'"archives"' not in body and b'"snapshots"' not in body, f"status={st}")
            st, body, _ = await _status(other, "GET", base + "/api/files/list", params={"path": os.path.dirname(os.path.dirname(adir))})
            ctx.ok("backups: the backups directory is not listed next to the install's files",
                   st == 200 and b'"backups"' not in body and b'"server.py"' in body, f"status={st} {body[:150]!r}")
            st, _, _ = await _status(other, "DELETE", base + "/api/files/delete", params={"path": path})
            ctx.ok("backups: a plain admin cannot delete the archive through /api/files",
                   st == 400 and os.path.isfile(path), f"status={st}")

            # ---- download
            st, body, headers = await _status(admin, "GET", base + f"/api/admin/backups/{name}/download")
            with open(path, "rb") as f:
                disk = f.read()
            ctx.ok("backups: superadmin downloads the archive byte for byte", st == 200 and body == disk, f"status={st}")
            ctx.ok("backups: download is Cache-Control no-store and an attachment",
                   "no-store" in headers.get("Cache-Control", "") and "attachment" in headers.get("Content-Disposition", ""),
                   f"{headers.get('Cache-Control')} / {headers.get('Content-Disposition')}")
            conn = sqlite3.connect(os.path.join(ctx.stage_dir, "portal.db"))
            try:
                rows = conn.execute("SELECT actor_username, target_name FROM audit_log WHERE action = 'backup.download'").fetchall()
                run_rows = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'backup.run'").fetchone()[0]
            finally:
                conn.close()
            ctx.ok("backups: the download and the run are in the audit log",
                   (ctx.admin_user, name) in rows and run_rows >= 1, str(rows))

            # Credentials other than the browser cookie: API key, bearer token, ?token=.
            st, body, _ = await _status(admin, "POST", base + "/api/api-keys", json={"name": "bk-key"})
            api_key = json.loads(body).get("key", "") if st in (200, 201) else ""
            st, body, _ = await _status(anon, "POST", base + "/api/token",
                                        json={"username": ctx.admin_user, "password": ctx.admin_password})
            bearer = json.loads(body).get("token", "") if st == 200 else ""
            ctx.ok("backups: an API key and a bearer token exist for the superadmin", bool(api_key) and bool(bearer),
                   f"key={bool(api_key)} token={bool(bearer)}")
            url = base + f"/api/admin/backups/{name}/download"
            for label, kw in (
                ("an API key", {"headers": {"X-API-Key": api_key}}),
                ("an Api-Key header", {"headers": {"Authorization": "Api-Key " + api_key}}),
                ("a bearer token", {"headers": {"Authorization": "Bearer " + bearer}}),
                ("a ?token= query value", {"params": {"token": bearer}}),
            ):
                async with ctx.http() as fresh:
                    st, body, _ = await _status(fresh, "GET", url, **kw)
                ctx.ok(f"backups: download refuses {label}", st == 401 and body[:2] != b"\x1f\x8b", f"status={st}")
            async with ctx.http() as fresh:
                st, body, _ = await _status(fresh, "GET", base + "/api/admin/backups",
                                            headers={"Authorization": "Bearer " + bearer})
            ctx.ok("backups: other routes still accept the superadmin's bearer token", st == 200, f"status={st}")

            # A credential that belongs to a superadmin but is not itself admin-level.
            st, body, _ = await _status(admin, "POST", base + "/api/api-keys",
                                        json={"name": "bk-narrow", "scopes": "services:read"})
            narrow_key = json.loads(body).get("key", "") if st in (200, 201) else ""
            st, body, _ = await _status(anon, "POST", base + "/api/token",
                                        json={"username": ctx.admin_user, "password": ctx.admin_password,
                                              "scopes": ["services:read"]})
            narrow_jwt = json.loads(body).get("token", "") if st == 200 else ""
            st, body, _ = await _status(admin, "POST", base + "/api/streams", json={"name": "bk-stream"})
            stream_key = ""
            if st == 201:
                try:
                    stream_key = json.loads(body).get("stream", {}).get("stream_key") or ""
                except ValueError:
                    stream_key = ""
            ctx.ok("backups: narrowly scoped credentials of the superadmin exist",
                   bool(narrow_key) and bool(narrow_jwt), f"key={bool(narrow_key)} jwt={bool(narrow_jwt)}")
            if stream_key:
                creds = [("a stream key", {"headers": {"Authorization": "Stream-Key " + stream_key}})]
            else:
                ctx.skip("backups: stream key checks", "no stream key could be read from the stage")
                creds = []
            creds += [
                ("a narrow API key", {"headers": {"X-API-Key": narrow_key}}),
                ("a narrow bearer token", {"headers": {"Authorization": "Bearer " + narrow_jwt}}),
            ]
            before_cfg = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            for label, kw in creds:
                for what, method, url in (
                    ("list", "GET", "/api/admin/backups"),
                    ("run", "POST", "/api/admin/backups/run"),
                    ("settings", "PUT", "/api/admin/backups/settings"),
                ):
                    extra_kw = dict(kw)
                    if method == "PUT":
                        extra_kw["json"] = {"enabled": False, "keep": 1}
                    async with ctx.http() as fresh:
                        st, _, _ = await _status(fresh, method, base + url, **extra_kw)
                    ctx.ok(f"backups: {label} of the superadmin gets 403 on {what}", st == 403, f"status={st}")
            # Delete, like download, needs the browser cookie: no other credential is accepted.
            for label, kw in creds + [
                ("an API key", {"headers": {"X-API-Key": api_key}}),
                ("an Api-Key header", {"headers": {"Authorization": "Api-Key " + api_key}}),
                ("a bearer token", {"headers": {"Authorization": "Bearer " + bearer}}),
                ("a ?token= query value", {"params": {"token": bearer}}),
            ]:
                async with ctx.http() as fresh:
                    st, _, _ = await _status(fresh, "DELETE", base + f"/api/admin/backups/{name}", **kw)
                ctx.ok(f"backups: delete refuses {label} and keeps the archive",
                       st in (401, 403) and os.path.isfile(path), f"status={st}")
            after_cfg = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            ctx.ok("backups: the refused scoped calls changed no setting and removed no archive",
                   before_cfg == after_cfg and os.path.isfile(path), f"{before_cfg} {after_cfg}")
            cookie_name = "portal_session"
            url_dl = base + f"/api/admin/backups/{name}/download"
            async with ctx.http() as fresh:
                st, body, _ = await _status(fresh, "GET", url_dl, headers={"Cookie": f"{cookie_name}={narrow_jwt}"})
            ctx.ok("backups: download refuses an API-minted narrow token sent as the session cookie",
                   st in (401, 403) and body[:2] != b"\x1f\x8b", f"status={st}")
            async with ctx.http() as fresh:
                st, body, _ = await _status(fresh, "GET", url_dl, headers={"Cookie": f"{cookie_name}={bearer}"})
            ctx.ok("backups: download refuses an API-minted full-scope token sent as the session cookie",
                   st in (401, 403) and body[:2] != b"\x1f\x8b", f"status={st}")

            # A token minted through the API cannot borrow the browser-session name.
            async with ctx.http() as fresh:
                st, body, _ = await _status(fresh, "POST", base + "/api/token",
                                            json={"username": ctx.admin_user, "password": ctx.admin_password,
                                                  "name": "web_session", "expires_hours": 8760})
            ctx.ok("backups: the token endpoint refuses the reserved name web_session",
                   st == 400 and b'"token"' not in body, f"status={st}")
            async with ctx.http() as fresh:
                st, body, _ = await _status(fresh, "POST", base + "/api/token",
                                            json={"username": ctx.admin_user, "password": ctx.admin_password,
                                                  "name": " Web_Session "})
            ctx.ok("backups: the reserved name is refused whatever its case and padding",
                   st == 400 and b'"token"' not in body, f"status={st}")

            # ---- names
            for label, raw in (("a parent path", "..%2f..%2f.env"), ("a bare traversal", "..%2F..%2Fportal.db"),
                               ("a wrong pattern", "portal-backup-x.tar.gz"), ("a plain file name", "manifest.json"),
                               ("a suffix after the name", name + ".evil")):
                st, body, _ = await _status(admin, "GET", base + f"/api/admin/backups/{raw}/download")
                ctx.ok(f"backups: download refuses {label}", st in (400, 404) and body[:2] != b"\x1f\x8b", f"status={st}")
            outside = os.path.join(work, "outside.tar.gz")
            with open(outside, "wb") as f:
                f.write(b"\x1f\x8b not an archive of ours")
            link = os.path.join(adir, "portal-backup-20300101-000000.tar.gz")
            os.symlink(outside, link)
            st, body, _ = await _status(admin, "GET", base + "/api/admin/backups/portal-backup-20300101-000000.tar.gz/download")
            ctx.ok("backups: a symlink planted in the archives directory is not served", st == 400 and b"not an archive" not in body,
                   f"status={st}")
            st, _, _ = await _status(admin, "DELETE", base + "/api/admin/backups/portal-backup-20300101-000000.tar.gz")
            ctx.ok("backups: a symlink is not deleted through the API and its target survives",
                   st == 400 and os.path.exists(outside), f"status={st}")
            os.unlink(link)

            # ---- settings
            st, body, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings",
                                        json={"keep": 2, "interval_hours": 12, "enabled": True, "extra_dir": ""})
            ctx.ok("backups: valid settings are saved", st == 200 and json.loads(body)["config"]["keep"] == 2, f"status={st} {body[:200]!r}")
            for label, payload in (("keep 0", {"keep": 0}), ("interval 99999", {"interval_hours": 99999}),
                                   ("a relative extra directory", {"extra_dir": "relative"}),
                                   ("a missing extra directory", {"extra_dir": os.path.join(work, "nope")})):
                st, _, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings", json=payload)
                ctx.ok(f"backups: settings refuse {label}", st == 400, f"status={st}")
            for private in ("/tmp", "/var/tmp"):
                st, body, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"extra_dir": private})
                ctx.ok(f"backups: settings refuse {private} as the extra directory (PrivateTmp)",
                       st == 400 and b"PrivateTmp" in body, f"status={st} {body[:200]!r}")
            shared = os.path.join(xwork, "shared")
            os.mkdir(shared)
            os.chmod(shared, 0o777)
            st, body, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"extra_dir": shared})
            ctx.ok("backups: settings refuse a group/other-writable extra directory", st == 400 and b"writable" in body, f"status={st}")
            install = os.path.realpath(ctx.stage_dir)
            os.makedirs(os.path.join(install, "static"), exist_ok=True)
            link_in = os.path.join(xwork, "link_into_install")
            os.symlink(os.path.join(install, "static"), link_in)
            for label, d in (("the installation directory", install),
                             ("the installation's static directory", os.path.join(install, "static")),
                             ("the recordings directory below the installation", os.path.join(install, "recordings")),
                             ("a symlink that points into the installation", link_in)):
                if not os.path.islink(d):
                    os.makedirs(d, exist_ok=True)
                st, body, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"extra_dir": d})
                ctx.ok(f"backups: settings refuse {label} as the extra directory",
                       st == 400 and b"installation" in body, f"status={st} {body[:200]!r}")
            cfg_now = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            ctx.ok("backups: the refused installation paths were not saved", cfg_now.get("extra_dir") == "", str(cfg_now))
            extra = os.path.join(xwork, "extra")
            os.mkdir(extra, 0o700)
            st, _, _ = await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"extra_dir": extra})
            ctx.ok("backups: a private extra directory is accepted", st == 200, f"status={st}")
            st, body, _ = await _status(admin, "POST", base + "/api/admin/backups/run")
            info2 = json.loads(body) if st == 201 else {}
            copied = os.path.join(extra, info2.get("name", "x"))
            ctx.ok("backups: the finished archive is copied to the extra directory",
                   st == 201 and os.path.isfile(copied) and _mode(copied) == 0o600 and not info2.get("extra_error"),
                   f"status={st} {info2.get('extra_error')}")
            # Only the browser session may move the extra destination; other settings keep working.
            settings_url = base + "/api/admin/backups/settings"
            other_extra = os.path.join(xwork, "extra2")
            os.mkdir(other_extra, 0o700)
            for label, kw in (("a bearer token", {"headers": {"Authorization": "Bearer " + bearer}}),
                              ("an API key", {"headers": {"X-API-Key": api_key}}),
                              ("a ?token= query value", {"params": {"token": bearer}})):
                async with ctx.http() as fresh:
                    st, body, _ = await _status(fresh, "PUT", settings_url, json={"keep": 5, "extra_dir": other_extra}, **kw)
                cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
                ctx.ok(f"backups: {label} cannot change the extra destination",
                       st == 403 and cfg_after["extra_dir"] == extra and cfg_after["keep"] == 2,
                       f"status={st} {cfg_after}")
                async with ctx.http() as fresh:
                    st, body, _ = await _status(fresh, "PUT", settings_url, json={"extra_dir": ""}, **kw)
                cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
                ctx.ok(f"backups: {label} cannot clear the extra destination either",
                       st == 403 and cfg_after["extra_dir"] == extra, f"status={st} {cfg_after}")
            async with ctx.http() as fresh:
                st, _, _ = await _status(fresh, "PUT", settings_url, json={"keep": 3, "extra_dir": extra},
                                         headers={"Authorization": "Bearer " + bearer})
            cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            ctx.ok("backups: a bearer token can still edit settings when extra_dir is left as it is",
                   st == 200 and cfg_after["keep"] == 3 and cfg_after["extra_dir"] == extra, f"status={st} {cfg_after}")
            async with ctx.http() as fresh:
                st, _, _ = await _status(fresh, "PUT", settings_url, json={"interval_hours": 24},
                                         headers={"Authorization": "Bearer " + bearer})
            ctx.ok("backups: a bearer token can edit settings that do not mention extra_dir", st == 200, f"status={st}")
            # Lowering keep deletes older archives at the next run: browser session only.
            for label, kw in (("a bearer token", {"headers": {"Authorization": "Bearer " + bearer}}),
                              ("an API key", {"headers": {"X-API-Key": api_key}}),
                              ("a ?token= query value", {"params": {"token": bearer}})):
                async with ctx.http() as fresh:
                    st, body, _ = await _status(fresh, "PUT", settings_url, json={"keep": 2}, **kw)
                cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
                ctx.ok(f"backups: {label} cannot lower the number of archives kept",
                       st == 403 and cfg_after["keep"] == 3, f"status={st} {cfg_after}")
            st, _, _ = await _status(admin, "PUT", settings_url, json={"keep": 2})
            cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            ctx.ok("backups: the browser session lowers the number of archives kept", st == 200 and cfg_after["keep"] == 2,
                   f"status={st} {cfg_after}")
            st, _, _ = await _status(admin, "PUT", settings_url, json={"extra_dir": other_extra})
            cfg_after = json.loads((await _status(admin, "GET", base + "/api/admin/backups"))[1])["config"]
            ctx.ok("backups: the browser session changes the extra destination",
                   st == 200 and cfg_after["extra_dir"] == other_extra, f"status={st} {cfg_after}")
            # An unmounted extra disk must not block editing the other settings.
            shutil.rmtree(other_extra)
            st, body, _ = await _status(admin, "PUT", settings_url,
                                        json={"enabled": True, "interval_hours": 24, "keep": 2, "extra_dir": other_extra})
            ctx.ok("backups: with the extra destination gone, the other settings can still be saved",
                   st == 200, f"status={st} {body[:200]!r}")
            st, body, _ = await _status(admin, "PUT", settings_url, json={"extra_dir": other_extra + "-new"})
            ctx.ok("backups: a different missing extra destination is still refused", st == 400, f"status={st}")
            st, body, _ = await _status(admin, "POST", base + "/api/admin/backups/run")
            ctx.ok("backups: a backup with the extra destination gone still succeeds and reports the copy error",
                   st == 201 and json.loads(body).get("extra_error"), f"status={st} {body[:200]!r}")
            await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"extra_dir": ""})
            for _ in range(2):
                await _status(admin, "POST", base + "/api/admin/backups/run")
            ctx.ok("backups: only the configured number of archives is kept",
                   len([n for n in os.listdir(adir) if n.startswith("portal-backup-")]) == 2, str(sorted(os.listdir(adir))))

            # The audit entry of a run names the archives it pruned (read back through the API; details are encrypted at rest).
            st, body, _ = await _status(admin, "GET", base + "/api/admin/audit-log", params={"action": "backup.run", "limit": "50"})
            entries = json.loads(body).get("entries", []) if st == 200 else []
            pruned_seen = []
            for e in entries:
                try:
                    pruned_seen += json.loads(e.get("details") or "{}").get("pruned", [])
                except ValueError:
                    pass
            ctx.ok("backups: the run audit entries list the archives that were pruned",
                   st == 200 and any(n.startswith("portal-backup-") for n in pruned_seen), f"status={st} {str(entries)[:300]}")

            # ---- delete
            st, body, _ = await _status(admin, "GET", base + "/api/admin/backups")
            victim = json.loads(body)["archives"][-1]["name"]
            st, _, _ = await _status(admin, "DELETE", base + f"/api/admin/backups/{victim}")
            ctx.ok("backups: superadmin deletes an archive", st == 200 and not os.path.exists(os.path.join(adir, victim)), f"status={st}")
            st, _, _ = await _status(admin, "DELETE", base + f"/api/admin/backups/{victim}")
            ctx.ok("backups: deleting it again is a 404", st == 404, f"status={st}")
            st, _, _ = await _status(admin, "DELETE", base + "/api/admin/backups/..%2f..%2fportal.db")
            ctx.ok("backups: delete refuses a traversal name", st in (400, 404) and os.path.isfile(os.path.join(ctx.stage_dir, "portal.db")), f"status={st}")
            await _status(admin, "PUT", base + "/api/admin/backups/settings", json={"keep": 7, "interval_hours": 24})

        # ---- scheduler (staged mode skips it; with the switch off it runs when due)
        rc, out = await ctx.run_py(SCHEDULE)
        res = _result(out)
        ctx.ok("backups: scheduled job is skipped in staged mode and writes nothing",
               res.get("stage_mode") is True and res.get("skipped_in_stage") and res.get("no_file_in_stage"), out.strip()[-300:])
        ctx.ok("backups: scheduled job runs when due and not again right after", res.get("ran_when_due") and res.get("not_due_again"),
               str(res))
        ctx.ok("backups: the startup check does nothing in staged mode, runs a due backup, and does not repeat it",
               res.get("startup_skipped_in_stage") and res.get("startup_ran_when_due") and res.get("startup_not_repeated"), str(res))
        ctx.ok("backups: scheduled job does nothing when disabled", res.get("disabled_skips") is True and res.get("status") == "ok", str(res))

        # ---- update: a backup first, and no update when the backup fails
        rc, out = await ctx.run_py(UPDATE)
        res = _result(out)
        ctx.ok("backups: an update run leaves a fresh archive and then runs", res.get("fresh_archive") and res.get("git_after_backup")
               and res.get("log_mentions_backup"), out.strip()[-300:])
        ctx.ok("backups: a failed backup stops the update before anything runs", res.get("refused") and res.get("nothing_ran"), str(res))

        rc, out = await ctx.run_py(CLI_UPDATE)
        res = _result(out)
        ctx.ok("backups: an update started from the command line (no database connection) takes its backup first",
               res.get("completed") and res.get("fresh_archive"), out.strip()[-300:])

        rc, out = await ctx.run_py(WRITES)
        res = _result(out)
        ctx.ok("backups: archives taken while the live database is written pass integrity_check",
               res.get("results") == ["ok"] * 3 and not res.get("errors"), out.strip()[-300:])

        # ---- CLI run now, then restore the seeded state
        env = dict(ctx._env)
        before = set(os.listdir(adir))
        cli = subprocess.run([sys.executable, "server.py", "backup-archive"], cwd=str(ctx.stage_dir), env=env,
                             capture_output=True, text=True, timeout=120)
        made = sorted(set(os.listdir(adir)) - before)
        ctx.ok("backups: server.py backup-archive writes an archive and prints its path",
               cli.returncode == 0 and len(made) == 1 and cli.stdout.strip().endswith(made[0]), f"rc={cli.returncode} {cli.stderr[-200:]}")
        if not made:
            return
        archive = os.path.join(adir, made[0])
        # The state that exists now is what the archive holds; this user is created afterwards.
        rc, out = await ctx.run_py(MARKER)
        ctx.ok("backups: a user is created after the archive was taken", "RESULT done" in out, out.strip()[-200:])
        # A member larger than the manifest says is refused by the command line before it is read.
        forged = os.path.join(work, "forged.tar.gz")
        with tarfile.open(archive, "r:gz") as src_tar, tarfile.open(forged, "w:gz") as out_tar:
            for m in src_tar:
                data = src_tar.extractfile(m).read()
                if m.name == ".env":
                    data += b"A" * (4 << 20)
                    m.size = len(data)
                out_tar.addfile(m, io.BytesIO(data))
        forged_into = os.path.join(work, "forged_out")
        proc = subprocess.run([sys.executable, "server.py", "restore-archive", forged, "--into", forged_into],
                              cwd=str(ctx.stage_dir), env=env, capture_output=True, text=True, timeout=120)
        ctx.ok("backups: restore-archive refuses a member whose size differs from the manifest and creates nothing",
               proc.returncode != 0 and "size" in (proc.stdout + proc.stderr).lower() and not os.path.exists(forged_into),
               f"rc={proc.returncode} {(proc.stdout + proc.stderr)[-200:]}")
        await _restored_instance(ctx, archive, work, seed, "bk_marker")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(xwork, ignore_errors=True)
