"""Game server management (SteamCMD) for Open Relay Portal.

Deploys dedicated game servers from a catalog: SteamCMD install → generated
systemd unit → a managed service (plugin 'gameserver') so lifecycle control
and the v1.9 grant system apply. Also a SteamCMD "update" flow and a scoped
config-file editor.

Everything runs as the `dustin` account (portal is root with passwordless
`sudo -u dustin`); game data lives on the /mnt/gamedata disk, matching the
existing hand-rolled setup in ~/steamcmd/.
"""

import asyncio
import glob
import json
import logging
import os
import re
import shutil
from pathlib import Path

import file_manager
import jobs
import services as _services

logger = logging.getLogger("portal.gameservers")

STEAMCMD = os.getenv("PORTAL_STEAMCMD", "/home/dustin/steamcmd/steamcmd.sh")
GAMEDATA_ROOT = os.getenv("PORTAL_GAMEDATA_ROOT", "/mnt/gamedata")
RUN_AS = os.getenv("PORTAL_GAMESERVER_USER", "dustin")
_PORTAL_DIR = Path(__file__).resolve().parent
UNITS_DIR = _PORTAL_DIR / "data" / "gameservers" / "units"
SYSTEMD_DIR = "/etc/systemd/system"

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
_deploy_lock: asyncio.Lock = None


def _lock() -> asyncio.Lock:
    global _deploy_lock
    if _deploy_lock is None:
        _deploy_lock = asyncio.Lock()
    return _deploy_lock


def _sudo_user(*args: str) -> list:
    return ["sudo", "-n", "-u", RUN_AS, "-H", *args]


def _sudo(*args: str) -> list:
    return ["sudo", "-n", *args]


# ---------------------------------------------------------------------------
# Curated catalog
# ---------------------------------------------------------------------------
CATALOG_SEED = [
    {"key": "palworld", "name": "Palworld", "steam_app_id": 2394010,
     "start_cmd": "./PalServer.sh",
     "start_args": "-useperfthreads -NoAsyncLoadingThread -UseMultithreadForDS",
     "game_port": 8211,
     "config_paths": ["Pal/Saved/Config/LinuxServer/PalWorldSettings.ini",
                      "Pal/Saved/Config/LinuxServer/Game.ini"],
     "notes": "UDP 8211. Settings generated after first start."},
    {"key": "zomboid", "name": "Project Zomboid", "steam_app_id": 380870,
     "start_cmd": "./start-server.sh", "start_args": "", "stop_signal": "SIGINT",
     "game_port": 16261,
     "config_paths": ["*.ini", "Server/*.ini", "Server/*.lua"],
     "notes": "SIGINT stop so the world saves. Config under ~/Zomboid/Server after first start."},
    {"key": "valheim", "name": "Valheim", "steam_app_id": 896660,
     "start_cmd": "./valheim_server.x86_64",
     "start_args": "-name Portal -port 2456 -world Dedicated -public 1",
     "game_port": 2456, "config_paths": ["*.txt"],
     "notes": "Set a password with -password on the command line (min 5 chars)."},
    {"key": "7dtd", "name": "7 Days to Die", "steam_app_id": 294420,
     "start_cmd": "./startserver.sh", "start_args": "-configfile=serverconfig.xml",
     "game_port": 26900, "config_paths": ["serverconfig.xml"]},
    {"key": "satisfactory", "name": "Satisfactory", "steam_app_id": 1690800,
     "start_cmd": "./FactoryServer.sh", "start_args": "-unattended",
     "game_port": 7777,
     "config_paths": ["FactoryGame/Saved/Config/LinuxServer/*.ini"]},
    {"key": "rust", "name": "Rust", "steam_app_id": 258550,
     "start_cmd": "./RustDedicated", "start_args": "-batchmode +server.port 28015",
     "game_port": 28015, "config_paths": ["server/*/cfg/*.cfg"]},
    {"key": "vrising", "name": "V Rising", "steam_app_id": 1829350,
     "start_cmd": "./VRisingServer.sh", "start_args": "-persistentDataPath ./save-data",
     "game_port": 9876, "config_paths": ["save-data/Settings/*.json"]},
    {"key": "enshrouded", "name": "Enshrouded", "steam_app_id": 2278520,
     "start_cmd": "./enshrouded_server.sh", "start_args": "", "game_port": 15636,
     "config_paths": ["enshrouded_server.json"]},
    {"key": "ark-asa", "name": "ARK: Survival Ascended", "steam_app_id": 2430930,
     "start_cmd": "./ShooterGame/Binaries/Linux/ArkAscendedServer",
     "start_args": "TheIsland_WP?listen", "game_port": 7777,
     "config_paths": ["ShooterGame/Saved/Config/WindowsServer/*.ini"]},
    {"key": "cs2", "name": "Counter-Strike 2", "steam_app_id": 730,
     "start_cmd": "./game/bin/linuxsteamrt64/cs2",
     "start_args": "-dedicated +map de_dust2", "game_port": 27015,
     "config_paths": ["game/csgo/cfg/*.cfg"]},
    {"key": "gmod", "name": "Garry's Mod", "steam_app_id": 4020,
     "start_cmd": "./srcds_run",
     "start_args": "-game garrysmod +map gm_flatgrass +maxplayers 16",
     "game_port": 27015, "config_paths": ["garrysmod/cfg/*.cfg"]},
    {"key": "squad", "name": "Squad", "steam_app_id": 403240,
     "start_cmd": "./SquadGameServer.sh", "start_args": "", "game_port": 7787,
     "config_paths": ["SquadGame/ServerConfig/*.cfg"]},
    {"key": "insurgency-sandstorm", "name": "Insurgency: Sandstorm",
     "steam_app_id": 581330, "start_cmd": "./InsurgencyServer.sh",
     "start_args": "", "game_port": 27102,
     "config_paths": ["Insurgency/Saved/Config/LinuxServer/*.ini"]},
    {"key": "core-keeper", "name": "Core Keeper", "steam_app_id": 1963720,
     "start_cmd": "./_launch.sh", "start_args": "", "game_port": 7777,
     "config_paths": ["*.json"]},
    {"key": "sons-of-the-forest", "name": "Sons of the Forest",
     "steam_app_id": 2465200, "start_cmd": "./SonsOfTheForestDS.exe",
     "start_args": "-batchmode -nographics -dedicated", "game_port": 8766,
     "config_paths": ["userdata/*.cfg"], "notes": "Runs via Proton/wine layer for some hosts."},
    {"key": "the-forest", "name": "The Forest", "steam_app_id": 556450,
     "start_cmd": "./server.x86_64", "start_args": "-batchmode -nographics",
     "game_port": 27015, "config_paths": ["*.cfg"]},
    {"key": "space-engineers", "name": "Space Engineers", "steam_app_id": 298740,
     "start_cmd": "./SpaceEngineersDedicated", "start_args": "-console",
     "game_port": 27016, "config_paths": ["Saves/*/*.sbc", "*.cfg"]},
    {"key": "dst", "name": "Don't Starve Together", "steam_app_id": 343050,
     "start_cmd": "./dontstarve_dedicated_server_nullrenderer_x64",
     "start_args": "-console -cluster MyDediServer", "game_port": 10999,
     "config_paths": ["*.ini"]},
    {"key": "barotrauma", "name": "Barotrauma", "steam_app_id": 1026340,
     "start_cmd": "./DedicatedServer", "start_args": "", "game_port": 27015,
     "config_paths": ["serversettings.xml", "*.xml"]},
    {"key": "unturned", "name": "Unturned", "steam_app_id": 1110390,
     "start_cmd": "./ServerHelper.sh", "start_args": "+InternetServer/Portal",
     "game_port": 27015, "config_paths": ["Servers/*/Server/*.json"]},
    {"key": "terraria-tshock", "name": "Terraria (TShock)", "steam_app_id": 105600,
     "start_cmd": "./TShock.Server", "start_args": "-autocreate 2 -world world1",
     "game_port": 7777, "config_paths": ["tshock/config.json", "*.json"]},
]


async def seed_catalog(db) -> None:
    await db.game_catalog_seed(CATALOG_SEED)
    logger.info("Game catalog seeded (%d built-in entries)", len(CATALOG_SEED))


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
def _unit_text(name: str, install_dir: str, start_cmd: str, start_args: str,
               stop_signal: str) -> str:
    cmd = start_cmd if not start_args else f"{start_cmd} {start_args}"
    return (
        "[Unit]\n"
        f"Description=Game server ({name}) — managed by Open Relay Portal\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={RUN_AS}\n"
        f"WorkingDirectory={install_dir}\n"
        f"ExecStart=/bin/bash -lc 'exec {cmd}'\n"
        "Restart=on-failure\nRestartSec=10\n"
        f"KillSignal={stop_signal}\nTimeoutStopSec=45\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


async def _run(job, args, timeout=3600, cwd=None):
    return await jobs.run_streamed(job, args, cwd=cwd, timeout=timeout)


def _installed_build(install_dir: str, app_id: int) -> str | None:
    acf = Path(install_dir) / "steamapps" / f"appmanifest_{app_id}.acf"
    try:
        m = re.search(r'"buildid"\s+"(\d+)"', acf.read_text())
        return m.group(1) if m else None
    except OSError:
        return None


async def _latest_build(app_id: int, steam_login: str = "anonymous") -> str | None:
    proc = await asyncio.create_subprocess_exec(
        *_sudo_user(STEAMCMD, "+login", steam_login, "+app_info_update", "1",
                    "+app_info_print", str(app_id), "+quit"),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        return None
    out = out_b.decode("utf-8", "replace")
    # locate the "branches" -> "public" -> "buildid" value
    m = re.search(r'"branches"\s*{.*?"public"\s*{.*?"buildid"\s*"(\d+)"',
                  out, re.S)
    return m.group(1) if m else None


async def deploy(db, *, catalog_key: str | None, custom: dict | None, name: str,
                 install_dir: str | None, start_args: str | None,
                 steam_login: str | None, enable: bool, start: bool,
                 created_by: int) -> dict:
    """Validate + register a game server and kick off the SteamCMD install job.

    Returns {"game_server": <row>, "job_id": <id>}.
    """
    name = (name or "").strip().lower()
    if not _NAME_RE.match(name):
        raise ValueError("name must be 2–32 chars, lowercase letters/digits/hyphens")
    if await db.game_server_by_name(name):
        raise ValueError(f"a game server named '{name}' already exists")

    if catalog_key:
        cat = await db.game_catalog_get(catalog_key)
        if not cat:
            raise ValueError(f"unknown catalog game '{catalog_key}'")
    elif custom:
        cat = {
            "key": None, "name": custom.get("name") or name,
            "steam_app_id": int(custom["steam_app_id"]),
            "steam_login": custom.get("steam_login") or "anonymous",
            "start_cmd": custom["start_cmd"], "start_args": custom.get("start_args", ""),
            "stop_signal": custom.get("stop_signal") or "SIGTERM",
            "config_paths": custom.get("config_paths") or [],
        }
    else:
        raise ValueError("catalog_key or custom game definition required")

    cfg_paths = cat["config_paths"]
    if isinstance(cfg_paths, str):
        try:
            cfg_paths = json.loads(cfg_paths)
        except json.JSONDecodeError:
            cfg_paths = []

    install_dir = install_dir or f"{GAMEDATA_ROOT}/{name}"
    install_dir = os.path.normpath(install_dir)
    if not install_dir.startswith(GAMEDATA_ROOT + "/"):
        raise ValueError(f"install_dir must be under {GAMEDATA_ROOT}")

    unit_name = f"portal-gs-{name}"
    args = start_args if start_args is not None else cat["start_args"]
    slogin = steam_login or cat["steam_login"]
    stop_sig = cat["stop_signal"]

    async with _lock():
        # create dirs
        UNITS_DIR.mkdir(parents=True, exist_ok=True)
        unit_file = UNITS_DIR / f"{unit_name}.service"
        gs_id = None
        try:
            os.makedirs(install_dir, exist_ok=True)
            try:
                shutil.chown(install_dir, RUN_AS, RUN_AS)
            except (LookupError, PermissionError, OSError) as e:
                logger.warning("chown %s failed: %s", install_dir, e)

            unit_file.write_text(_unit_text(name, install_dir, cat["start_cmd"], args, stop_sig))
            rc, _, err = await _run_cmd(_sudo("ln", "-sf", str(unit_file),
                                              f"{SYSTEMD_DIR}/{unit_name}.service"))
            if rc != 0:
                raise RuntimeError(f"failed to install unit: {err}")
            await _run_cmd(_sudo("systemctl", "daemon-reload"))

            gs_id = await db.game_server_create({
                "name": name, "catalog_key": catalog_key,
                "steam_app_id": cat["steam_app_id"], "steam_login": slogin,
                "install_dir": install_dir, "unit_name": unit_name,
                "start_cmd": cat["start_cmd"], "start_args": args,
                "stop_signal": stop_sig,
                "config_paths": json.dumps(cfg_paths),
                "state": "installing", "created_by": created_by,
            })

            svc = await _services.service_manager.create_service(
                name=name, service_type="gameserver",
                display_name=f"{cat['name']} ({name})",
                description=f"Game server · Steam app {cat['steam_app_id']}",
                config={"unit": unit_name, "game_server_id": gs_id},
                enabled=False,
            )
            if not svc:
                raise RuntimeError("could not create the backing managed service")
            await db.game_server_update(gs_id, service_id=svc.id)
        except Exception:
            # Roll back anything created before the failure.
            await _run_cmd(_sudo("rm", "-f", f"{SYSTEMD_DIR}/{unit_name}.service"))
            unit_file.unlink(missing_ok=True)
            await _run_cmd(_sudo("systemctl", "daemon-reload"))
            # create_service inserts the services row before instantiating the
            # handler and swallows a handler error returning None — so an
            # orphan row can survive. Drop any managed service by this name.
            try:
                for row in await db.get_services_by_type("managed"):
                    if row.get("name") == name:
                        await _services.service_manager.delete_service(row["id"])
            except Exception as e:
                logger.warning("orphan service cleanup failed: %s", e)
            if gs_id is not None:
                await db.game_server_delete(gs_id)
            try:
                os.rmdir(install_dir)   # only if we created it and it's empty
            except OSError:
                pass
            raise

    job_id = jobs.start_job(
        f"Install {name}",
        lambda job: _install_job(db, gs_id, install_dir, cat["steam_app_id"],
                                 slogin, enable, start, job),
        meta={"game_server_id": gs_id, "kind": "install"},
    )
    await db.game_server_update(gs_id, install_job=job_id)
    return {"game_server": await db.game_server_get(gs_id), "job_id": job_id}


async def _run_cmd(args, timeout=60):
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        o, e = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "timeout"
    return proc.returncode, o.decode(errors="replace"), e.decode(errors="replace")


async def _install_job(db, gs_id, install_dir, app_id, steam_login, enable, start, job):
    jobs.log(job, f"Installing Steam app {app_id} into {install_dir} (as {RUN_AS})")
    rc = await _run(job, _sudo_user(
        STEAMCMD, "+force_install_dir", install_dir, "+login", steam_login,
        "+app_update", str(app_id), "validate", "+quit"), timeout=7200)
    if rc != 0:
        await db.game_server_update(gs_id, state="error")
        jobs.log(job, f"SteamCMD exited {rc}")
        job["status"] = "failed"
        return

    build = _installed_build(install_dir, app_id)
    await db.game_server_update(gs_id, state="installed", installed_build=build)
    jobs.log(job, f"Installed — build {build or 'unknown'}")

    gs = await db.game_server_get(gs_id)
    svc = (await _services.service_manager.get_service(gs["service_id"])) if gs.get("service_id") else None
    if enable and svc:
        await _services.service_manager.enable_service(gs["service_id"])
        jobs.log(job, "Enabled (auto-start on Portal boot)")
    if start and svc:
        ok, err = await svc.start()
        jobs.log(job, "Started" if ok else f"Start failed: {err}")


# ---------------------------------------------------------------------------
# Update / build check
# ---------------------------------------------------------------------------
async def check_latest_build(db, gs_id: int) -> dict:
    gs = await db.game_server_get(gs_id)
    if not gs:
        raise ValueError("no such game server")
    latest = await _latest_build(gs["steam_app_id"], gs["steam_login"])
    from datetime import datetime, timezone
    await db.game_server_update(
        gs_id, latest_build=latest,
        build_checked_at=datetime.now(timezone.utc).isoformat(),
        installed_build=_installed_build(gs["install_dir"], gs["steam_app_id"]),
    )
    return await db.game_server_get(gs_id)


def update_server(db, gs_id: int) -> str:
    """Start a background update job; returns job_id."""
    return jobs.start_job(
        f"Update game server {gs_id}",
        lambda job: _update_job(db, gs_id, job),
        meta={"game_server_id": gs_id, "kind": "update"},
    )


async def _update_job(db, gs_id, job):
    gs = await db.game_server_get(gs_id)
    if not gs:
        raise ValueError("no such game server")
    app_id, install_dir, unit = gs["steam_app_id"], gs["install_dir"], gs["unit_name"]
    cur = _installed_build(install_dir, app_id)
    latest = await _latest_build(app_id, gs["steam_login"])
    jobs.log(job, f"installed={cur or '?'} latest={latest or '?'}")
    if latest and cur and latest == cur:
        jobs.log(job, "already up to date — nothing to do")
        await db.game_server_update(gs_id, latest_build=latest)
        return

    await db.game_server_update(gs_id, state="updating")
    was_running = False
    rc, out, _ = await _run_cmd(_sudo("systemctl", "is-active", f"{unit}.service"))
    was_running = out.strip() == "active"
    if was_running:
        jobs.log(job, "stopping service for update")
        await _run_cmd(_sudo("systemctl", "stop", f"{unit}.service"), timeout=120)

    rc = await _run(job, _sudo_user(
        STEAMCMD, "+force_install_dir", install_dir, "+login", gs["steam_login"],
        "+app_update", str(app_id), "+quit"), timeout=7200)

    new_build = _installed_build(install_dir, app_id)
    await db.game_server_update(
        gs_id, state="installed" if rc == 0 else "error",
        installed_build=new_build, latest_build=latest)

    if was_running:
        jobs.log(job, "restarting service")
        await _run_cmd(_sudo("systemctl", "start", f"{unit}.service"), timeout=120)
    if rc != 0:
        jobs.log(job, f"SteamCMD exited {rc}")
        job["status"] = "failed"
    else:
        jobs.log(job, f"done — build {new_build or 'unknown'}")


# ---------------------------------------------------------------------------
# Destroy
# ---------------------------------------------------------------------------
async def destroy(db, gs_id: int, delete_files: bool = False) -> None:
    gs = await db.game_server_get(gs_id)
    if not gs:
        raise ValueError("no such game server")
    unit = gs["unit_name"]
    await _run_cmd(_sudo("systemctl", "disable", "--now", f"{unit}.service"), timeout=120)
    await _run_cmd(_sudo("rm", "-f", f"{SYSTEMD_DIR}/{unit}.service"))
    try:
        (UNITS_DIR / f"{unit}.service").unlink(missing_ok=True)
    except OSError:
        pass
    await _run_cmd(_sudo("systemctl", "daemon-reload"))

    if gs.get("service_id"):
        try:
            await _services.service_manager.delete_service(gs["service_id"])
        except Exception as e:
            logger.warning("delete_service failed: %s", e)

    if delete_files and gs["install_dir"].startswith(GAMEDATA_ROOT + "/"):
        await _run_cmd(_sudo_user("rm", "-rf", gs["install_dir"]), timeout=600)

    await db.game_server_delete(gs_id)


# ---------------------------------------------------------------------------
# Config file editor (scoped to the server's install dir + config_paths)
# ---------------------------------------------------------------------------
def _config_globs(gs: dict) -> list:
    cp = gs.get("config_paths") or "[]"
    if isinstance(cp, str):
        try:
            cp = json.loads(cp)
        except json.JSONDecodeError:
            cp = []
    return [p for p in cp if isinstance(p, str) and ".." not in p]


def list_config_files(gs: dict) -> list[dict]:
    root = gs["install_dir"]
    seen, out = set(), []
    for pat in _config_globs(gs):
        for match in glob.glob(os.path.join(root, pat)):
            try:
                rp = file_manager._validate_path(os.path.relpath(match, root), root)
            except ValueError:
                continue
            if not rp.is_file() or str(rp) in seen:
                continue
            seen.add(str(rp))
            st = rp.stat()
            out.append({
                "name": rp.name,
                "path": os.path.relpath(str(rp), root),
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
    out.sort(key=lambda f: f["path"])
    return out


def _resolve_config(gs: dict, rel: str) -> Path:
    root = gs["install_dir"]
    rp = file_manager._validate_path(rel, root)
    allowed = {os.path.realpath(f["path"] if os.path.isabs(f["path"])
                                else os.path.join(root, f["path"]))
               for f in list_config_files(gs)}
    if os.path.realpath(str(rp)) not in allowed:
        raise ValueError("not an editable config file for this server")
    return rp


def read_config(gs: dict, rel: str, max_size: int = 2 * 1024 * 1024) -> str:
    rp = _resolve_config(gs, rel)
    data = rp.read_bytes()
    if len(data) > max_size:
        raise ValueError("file too large to edit")
    return data.decode("utf-8", "replace")


def write_config(gs: dict, rel: str, text: str) -> None:
    rp = _resolve_config(gs, rel)
    rp.write_bytes(text.encode("utf-8"))
    try:
        shutil.chown(str(rp), RUN_AS, RUN_AS)
    except (LookupError, PermissionError, OSError) as e:
        logger.warning("chown %s failed: %s", rp, e)
