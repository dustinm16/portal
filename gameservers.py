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
import shlex
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
     "stop_signal": "SIGINT", "game_port": 8211,
     "config_paths": ["Pal/Saved/Config/LinuxServer/PalWorldSettings.ini",
                      "Pal/Saved/Config/LinuxServer/Game.ini",
                      "Pal/Saved/Config/LinuxServer/Engine.ini",
                      "Pal/Saved/Config/LinuxServer/GameUserSettings.ini"],
     "backup_paths": ["Pal/Saved/SaveGames/**",
                      "Pal/Saved/Config/LinuxServer/*.ini"],
     "notes": "UDP 8211. Settings generated after first start. SIGINT stop so the world saves."},
    {"key": "zomboid", "name": "Project Zomboid", "steam_app_id": 380870,
     "start_cmd": "./start-server.sh", "start_args": "", "stop_signal": "SIGINT",
     "game_port": 16261,
     "config_root": "~/Zomboid",
     "config_paths": ["Server/*.ini", "Server/*.lua"],
     "backup_paths": ["Server/*.ini", "Server/*.lua", "Saves/**", "db/*.db"],
     "notes": "SIGINT stop so the world saves. PZ keeps its config, player DB "
              "(bans/whitelist/safehouses) and saves under ~/Zomboid (the "
              "run-as account's home), not the install dir."},
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
     "config_paths": ["FactoryGame/Saved/Config/LinuxServer/*.ini"],
     "backup_paths": ["FactoryGame/Saved/SaveGames/**"]},
    {"key": "rust", "name": "Rust", "steam_app_id": 258550,
     "start_cmd": "./RustDedicated", "start_args": "-batchmode +server.port 28015",
     "game_port": 28015, "config_paths": ["server/*/cfg/*.cfg"]},
    {"key": "vrising", "name": "V Rising", "steam_app_id": 1829350,
     "start_cmd": "./VRisingServer.sh", "start_args": "-persistentDataPath ./save-data",
     "game_port": 9876, "config_paths": ["save-data/Settings/*.json"],
     "backup_paths": ["save-data/Saves/**"]},
    {"key": "enshrouded", "name": "Enshrouded", "steam_app_id": 2278520,
     "start_cmd": "./enshrouded_server.sh", "start_args": "", "game_port": 15636,
     "config_paths": ["enshrouded_server.json"],
     "backup_paths": ["savegame/**"]},
    {"key": "ark-asa", "name": "ARK: Survival Ascended", "steam_app_id": 2430930,
     "start_cmd": "./ShooterGame/Binaries/Linux/ArkAscendedServer",
     "start_args": "TheIsland_WP?listen", "game_port": 7777,
     "config_paths": ["ShooterGame/Saved/Config/WindowsServer/*.ini"],
     "backup_paths": ["ShooterGame/Saved/SavedArks/**"]},
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

    # --- Valve Source-engine dedicated servers (srcds) ---
    {"key": "tf2", "name": "Team Fortress 2", "steam_app_id": 232250,
     "start_cmd": "./srcds_run",
     "start_args": "-game tf +map cp_dustbowl +maxplayers 24 -port 27015",
     "game_port": 27015, "config_paths": ["tf/cfg/*.cfg"]},
    {"key": "css", "name": "Counter-Strike: Source", "steam_app_id": 232330,
     "start_cmd": "./srcds_run",
     "start_args": "-game cstrike +map de_dust2 +maxplayers 16 -port 27015",
     "game_port": 27015, "config_paths": ["cstrike/cfg/*.cfg"]},
    {"key": "l4d2", "name": "Left 4 Dead 2", "steam_app_id": 222860,
     "start_cmd": "./srcds_run",
     "start_args": "-game left4dead2 +map c1m1_hotel +maxplayers 8 -port 27015",
     "game_port": 27015, "config_paths": ["left4dead2/cfg/*.cfg"]},
    {"key": "dods", "name": "Day of Defeat: Source", "steam_app_id": 232290,
     "start_cmd": "./srcds_run",
     "start_args": "-game dod +map dod_anzio +maxplayers 24 -port 27015",
     "game_port": 27015, "config_paths": ["dod/cfg/*.cfg"]},
    {"key": "hl2dm", "name": "Half-Life 2: Deathmatch", "steam_app_id": 232370,
     "start_cmd": "./srcds_run",
     "start_args": "-game hl2mp +map dm_lockdown +maxplayers 16 -port 27015",
     "game_port": 27015, "config_paths": ["hl2mp/cfg/*.cfg"]},
    {"key": "svencoop", "name": "Sven Co-op", "steam_app_id": 276060,
     "start_cmd": "./svends_run",
     "start_args": "-game svencoop +map svencoop1 +maxplayers 8 -port 27015",
     "game_port": 27015, "config_paths": ["svencoop/cfg/*.cfg", "svencoop_addon/cfg/*.cfg"]},
    {"key": "nmrih", "name": "No More Room in Hell", "steam_app_id": 317670,
     "start_cmd": "./srcds_run",
     "start_args": "-game nmrih +map nmo_broadway +maxplayers 8 -port 27015",
     "game_port": 27015, "config_paths": ["nmrih/cfg/*.cfg"]},
    {"key": "black-mesa", "name": "Black Mesa", "steam_app_id": 346680,
     "start_cmd": "./srcds_run",
     "start_args": "-game bms +map bm_c1a0a +maxplayers 12 -port 27015",
     "game_port": 27015, "config_paths": ["bms/cfg/*.cfg"]},
    {"key": "insurgency2014", "name": "Insurgency (2014)", "steam_app_id": 237410,
     "start_cmd": "./srcds_run",
     "start_args": "-game insurgency +map sinjar +maxplayers 16 -port 27015",
     "game_port": 27015, "config_paths": ["insurgency/cfg/*.cfg"]},

    # --- Survival / sandbox ---
    {"key": "ark-se", "name": "ARK: Survival Evolved", "steam_app_id": 376030,
     "start_cmd": "./ShooterGame/Binaries/Linux/ShooterGameServer",
     "start_args": "TheIsland?listen?SessionName=Portal", "game_port": 7777,
     "config_paths": ["ShooterGame/Saved/Config/LinuxServer/*.ini"],
     "backup_paths": ["ShooterGame/Saved/SavedArks/**"]},
    {"key": "conan-exiles", "name": "Conan Exiles", "steam_app_id": 443030,
     "start_cmd": "./ConanSandboxServer.sh", "start_args": "-log", "game_port": 7777,
     "config_paths": ["ConanSandbox/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "icarus", "name": "Icarus", "steam_app_id": 2089300,
     "start_cmd": "./IcarusServer.sh", "start_args": "-UserDir=./Saved", "game_port": 17777,
     "config_paths": ["Saved/Config/LinuxServer/*.ini", "Saved/*.json"]},
    {"key": "soulmask", "name": "Soulmask", "steam_app_id": 3017300,
     "start_cmd": "./WS/Binaries/Linux/WSServer-Linux-Shipping",
     "start_args": "Level01_Main -server -SteamServerName=Portal", "game_port": 8777,
     "config_paths": ["WS/Saved/Config/LinuxServer/*.ini", "WS/Saved/GameUserSettings.ini"]},
    {"key": "abiotic-factor", "name": "Abiotic Factor", "steam_app_id": 2857200,
     "start_cmd": "./AbioticFactor/Binaries/Win64/AbioticFactorServer-Win64-Shipping.exe",
     "start_args": "-newconsole -useperfthreads", "game_port": 7777,
     "config_paths": ["AbioticFactor/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "myth-of-empires", "name": "Myth of Empires", "steam_app_id": 1954850,
     "start_cmd": "./StartServer.sh", "start_args": "", "game_port": 10086,
     "config_paths": ["EmpiresServer/Saved/Config/*/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "stationeers", "name": "Stationeers", "steam_app_id": 600760,
     "start_cmd": "./rocketstation_DedicatedServer.x86_64",
     "start_args": "-settings StartLocalHost true", "game_port": 27500,
     "config_paths": ["*.xml", "saves/*/*.xml"]},
    {"key": "empyrion", "name": "Empyrion – Galactic Survival", "steam_app_id": 530870,
     "start_cmd": "./EmpyrionDedicated.sh", "start_args": "-dedicated dedicated.yaml",
     "game_port": 30000,
     "config_paths": ["*.yaml", "Content/Configuration/*.yaml", "Content/Configuration/*.ecf"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "starbound", "name": "Starbound", "steam_app_id": 211820,
     "start_cmd": "./linux/starbound_server", "start_args": "", "game_port": 21025,
     "config_paths": ["storage/starbound_server.config"]},
    {"key": "hurtworld", "name": "Hurtworld", "steam_app_id": 405100,
     "start_cmd": "./Hurtworld.x86_64",
     "start_args": "-batchmode -nographics -exec \"host 12871;queryport 12881;servername Portal\"",
     "game_port": 12871, "config_paths": ["*.cfg"]},
    {"key": "colony-survival", "name": "Colony Survival", "steam_app_id": 366090,
     "start_cmd": "./colonyserver.x86_64", "start_args": "+server.world Portal",
     "game_port": 27004, "config_paths": ["gamedata/savegames/*/*.json"]},
    {"key": "necesse", "name": "Necesse", "steam_app_id": 1169370,
     "start_cmd": "./StartServer-nogui.sh", "start_args": "", "game_port": 14159,
     "config_paths": ["cfg/*.cfg"]},

    # --- Shooters / milsim / vehicle ---
    {"key": "arma3", "name": "Arma 3", "steam_app_id": 233780,
     "start_cmd": "./arma3server",
     "start_args": "-name=server -config=server.cfg -port=2302", "game_port": 2302,
     "config_paths": ["*.cfg", "*.Arma3Profile"]},
    {"key": "dayz", "name": "DayZ", "steam_app_id": 223350,
     "start_cmd": "./DayZServer", "start_args": "-config=serverDZ.cfg -port=2302",
     "game_port": 2302, "config_paths": ["serverDZ.cfg", "*.cfg"]},
    {"key": "kf2", "name": "Killing Floor 2", "steam_app_id": 232130,
     "start_cmd": "./Binaries/Linux/KFGameSteamServer.bin.x86_64",
     "start_args": "KF-BioticsLab", "game_port": 7777,
     "config_paths": ["KFGame/Config/*.ini"]},
    {"key": "mordhau", "name": "MORDHAU", "steam_app_id": 629800,
     "start_cmd": "./Mordhau/Binaries/Linux/MordhauServer-Linux-Shipping",
     "start_args": "Mordhau -Port=7777 -QueryPort=27015", "game_port": 7777,
     "config_paths": ["Mordhau/Saved/Config/LinuxServer/*.ini"]},
    {"key": "pavlov-vr", "name": "Pavlov VR", "steam_app_id": 622970,
     "start_cmd": "./PavlovServer.sh", "start_args": "", "game_port": 7777,
     "config_paths": ["Pavlov/Saved/Config/LinuxServer/*.ini"]},
    {"key": "assetto-corsa", "name": "Assetto Corsa", "steam_app_id": 302550,
     "start_cmd": "./acServer", "start_args": "", "game_port": 9600,
     "config_paths": ["cfg/*.ini"]},
    {"key": "astroneer", "name": "Astroneer", "steam_app_id": 728470,
     "start_cmd": "./AstroServer.sh", "start_args": "", "game_port": 8777,
     "config_paths": ["Astro/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},

    # --- More popular multiplayer titles ---
    {"key": "left4dead", "name": "Left 4 Dead", "steam_app_id": 222840,
     "start_cmd": "./srcds_run",
     "start_args": "-game left4dead +map l4d_hospital01_apartment +maxplayers 4 -port 27015",
     "game_port": 27015, "config_paths": ["left4dead/cfg/*.cfg"]},
    {"key": "day-of-infamy", "name": "Day of Infamy", "steam_app_id": 447440,
     "start_cmd": "./srcds_run",
     "start_args": "-game doi +map drepublic_coop +maxplayers 16 -port 27015",
     "game_port": 27015, "config_paths": ["doi/cfg/*.cfg"]},
    {"key": "fistful-of-frags", "name": "Fistful of Frags", "steam_app_id": 295230,
     "start_cmd": "./srcds_run",
     "start_args": "-game fof +map fof_depot +maxplayers 12 -port 27015",
     "game_port": 27015, "config_paths": ["fof/cfg/*.cfg"]},
    {"key": "codename-cure", "name": "Codename CURE", "steam_app_id": 355180,
     "start_cmd": "./srcds_run",
     "start_args": "-game cure +map cbe_frostbite +maxplayers 8 -port 27015",
     "game_port": 27015, "config_paths": ["cure/cfg/*.cfg"]},
    {"key": "zombie-panic-source", "name": "Zombie Panic! Source", "steam_app_id": 17500,
     "start_cmd": "./srcds_run",
     "start_args": "-game zps +map zpo_biotec +maxplayers 24 -port 27015",
     "game_port": 27015, "config_paths": ["zps/cfg/*.cfg"]},
    {"key": "double-action", "name": "Double Action: Boogaloo", "steam_app_id": 317360,
     "start_cmd": "./srcds_run",
     "start_args": "-game dab +map da_rooftops +maxplayers 12 -port 27015",
     "game_port": 27015, "config_paths": ["dab/cfg/*.cfg"]},
    {"key": "hell-let-loose", "name": "Hell Let Loose", "steam_app_id": 686810,
     "start_cmd": "./HLL/Binaries/Win64/HLL-Win64-Shipping.exe",
     "start_args": "", "game_port": 7777,
     "config_paths": ["HLL/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "arma-reforger", "name": "Arma Reforger", "steam_app_id": 1890870,
     "start_cmd": "./ArmaReforgerServer",
     "start_args": "-config ./config.json -maxFPS 60", "game_port": 2001,
     "config_paths": ["*.json"]},
    {"key": "squad44", "name": "Squad 44", "steam_app_id": 736220,
     "start_cmd": "./PostScriptumServer.sh", "start_args": "", "game_port": 7787,
     "config_paths": ["PostScriptum/ServerConfig/*.cfg"]},
    {"key": "operation-harsh-doorstop", "name": "Operation: Harsh Doorstop",
     "steam_app_id": 950900, "start_cmd": "./HarshDoorstopServer.sh",
     "start_args": "", "game_port": 7777,
     "config_paths": ["HarshDoorstop/Saved/Config/LinuxServer/*.ini"]},
    {"key": "natural-selection-2", "name": "Natural Selection 2", "steam_app_id": 4940,
     "start_cmd": "./server_linux64", "start_args": "-name Portal -port 27015",
     "game_port": 27015, "config_paths": ["config/*.json", "*.json"]},
    {"key": "the-isle", "name": "The Isle", "steam_app_id": 412680,
     "start_cmd": "./TheIsleServer.sh", "start_args": "", "game_port": 7777,
     "config_paths": ["TheIsle/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "scp-secret-laboratory", "name": "SCP: Secret Laboratory",
     "steam_app_id": 996560, "start_cmd": "./LocalAdmin", "start_args": "7777",
     "game_port": 7777,
     "config_paths": ["*.txt", ".config/SCP Secret Laboratory/config/**/*.txt"]},
    {"key": "quake-live", "name": "Quake Live", "steam_app_id": 349090,
     "start_cmd": "./qzeroded.x64",
     "start_args": "+set net_strict 1 +set sv_hostname Portal +exec server.cfg",
     "game_port": 27960, "config_paths": ["baseq3/*.cfg"]},
    {"key": "just-cause-2-mp", "name": "Just Cause 2: Multiplayer", "steam_app_id": 259080,
     "start_cmd": "./Jcmp-Server", "start_args": "", "game_port": 7777,
     "config_paths": ["config.lua", "*.lua"]},
    {"key": "teeworlds", "name": "Teeworlds", "steam_app_id": 380840,
     "start_cmd": "./teeworlds_srv", "start_args": "", "game_port": 8303,
     "config_paths": ["*.cfg"]},

    # --- Survival / sandbox / sim (part 2) ---
    {"key": "eco", "name": "Eco", "steam_app_id": 739590,
     "start_cmd": "./EcoServer", "start_args": "", "game_port": 3000,
     "config_paths": ["Configs/*.eco", "Configs/*.json"],
     "backup_paths": ["Storage/**"]},
    {"key": "avorion", "name": "Avorion", "steam_app_id": 565060,
     "start_cmd": "./bin/AvorionServer",
     "start_args": "--galaxy-name Portal --admin Portal", "game_port": 27000,
     "config_paths": ["galaxies/*/server.ini", "*.ini"],
     "backup_paths": ["galaxies/**"]},
    {"key": "factorio", "name": "Factorio", "steam_app_id": 427520,
     "start_cmd": "./bin/x64/factorio",
     "start_args": "--start-server-load-latest --server-settings ./data/server-settings.json",
     "game_port": 34197,
     "config_paths": ["config/config.ini", "data/server-settings.json",
                      "data/server-whitelist.json", "data/server-adminlist.json"],
     "backup_paths": ["saves/**"],
     "notes": "The Steam build can run headless — no separate server download."},
    {"key": "wurm-unlimited", "name": "Wurm Unlimited", "steam_app_id": 402370,
     "start_cmd": "./WurmServerLauncher-linux", "start_args": "", "game_port": 3724,
     "config_paths": ["*.db", "config/**/*.properties"]},
    {"key": "craftopia", "name": "Craftopia", "steam_app_id": 1670950,
     "start_cmd": "./DedicatedServer.x86_64", "start_args": "", "game_port": 25565,
     "config_paths": ["*.json", "DedicatedServer_Data/**/*.json"]},
    {"key": "tower-unite", "name": "Tower Unite", "steam_app_id": 439660,
     "start_cmd": "./TowerServer.sh", "start_args": "", "game_port": 7777,
     "config_paths": ["Tower/Saved/Config/LinuxServer/*.ini"],
     "notes": "Windows-focused server — may need a Proton/wine layer on Linux."},
    {"key": "the-front", "name": "The Front", "steam_app_id": 2699560,
     "start_cmd": "./StartServer.sh", "start_args": "", "game_port": 8888,
     "config_paths": ["ProjectWar/Saved/Config/WindowsServer/*.ini"],
     "notes": "Windows-only server — runs via a Proton/wine layer on Linux."},
    {"key": "ets2", "name": "Euro Truck Simulator 2 (Convoy)", "steam_app_id": 1948160,
     "start_cmd": "./bin/linux_x64/eurotrucks2_server", "start_args": "",
     "game_port": 27015,
     "config_paths": ["server_config.sii", "server_packages.sii"]},
    {"key": "american-truck-sim", "name": "American Truck Simulator (Convoy)",
     "steam_app_id": 2239530, "start_cmd": "./bin/linux_x64/amtrucks_server",
     "start_args": "", "game_port": 27015,
     "config_paths": ["server_config.sii", "server_packages.sii"]},
]


async def seed_catalog(db) -> None:
    await db.game_catalog_seed(CATALOG_SEED)
    logger.info("Game catalog seeded (%d built-in entries)", len(CATALOG_SEED))


def _as_glob_list(v) -> list:
    """Coerce a catalog/row path field (list or JSON string) to a clean list.

    Rejects traversal (``..``), absolute paths and ``~`` — every glob is
    resolved *relative to* the server's config root.
    """
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except json.JSONDecodeError:
            v = []
    return [p for p in (v or []) if isinstance(p, str) and p
            and ".." not in p and not p.startswith(("/", "~"))]


def _run_as_home() -> str:
    """Home directory of the account game servers run as (RUN_AS), not this
    process's — Portal runs as root, the servers run as ``dustin``."""
    import pwd
    try:
        return pwd.getpwnam(RUN_AS).pw_dir
    except KeyError:
        return os.path.expanduser("~" + RUN_AS)


_INSTALL_DIR_RE = re.compile(r"[A-Za-z0-9._/-]+")
_STEAM_LOGIN_RE = re.compile(r"[A-Za-z0-9._@+-]{1,64}")


def _validate_steam_login(v: str) -> str:
    """A Steam account name (or ``anonymous``). Confined so it can't be a
    stray ``+command`` token to steamcmd even though it's already argv-safe."""
    v = (v or "anonymous").strip()
    if not _STEAM_LOGIN_RE.fullmatch(v):
        raise ValueError("steam_login must be a plain account name or 'anonymous'")
    return v


def _validate_install_dir(p: str, *, must_exist: bool = False) -> str:
    """Normalise + confine an install dir to a subdirectory of GAMEDATA_ROOT.

    Rejects control characters, shell/systemd-meaningful characters and paths
    that resolve outside (or exactly onto) the game-data root."""
    raw = (p or "").strip()
    norm = os.path.normpath(raw)
    if not raw or not _INSTALL_DIR_RE.fullmatch(norm):
        raise ValueError("install_dir contains invalid characters")
    root = os.path.realpath(GAMEDATA_ROOT)
    rp = os.path.realpath(norm)
    if rp == root or not rp.startswith(root + os.sep):
        raise ValueError(f"install_dir must be a subdirectory of {GAMEDATA_ROOT}")
    if must_exist and not os.path.isdir(rp):
        raise ValueError(f"{rp} does not exist")
    return rp


def _allowed_config_root_bases() -> list[str]:
    """The only directories a ``config_root`` may resolve under.

    The game-data disk, plus ``<run-as home>/Zomboid`` (Project Zomboid is the
    one built-in that keeps config/saves in the account home). NOT the whole
    home directory — that would put ``~/.ssh``, ``~/.bashrc`` and Portal's own
    source under a `files` grant. Extra roots can be added out-of-band via
    ``PORTAL_GS_EXTRA_CONFIG_ROOTS`` (``:``-separated absolute paths)."""
    bases = [os.path.realpath(GAMEDATA_ROOT),
             os.path.realpath(os.path.join(_run_as_home(), "Zomboid"))]
    for p in os.getenv("PORTAL_GS_EXTRA_CONFIG_ROOTS", "").split(":"):
        p = p.strip()
        if p:
            bases.append(os.path.realpath(p))
    return bases


def _config_root(gs: dict) -> str:
    """Directory that a server's config/backup globs resolve against.

    ``install_dir`` by default; a catalog/row ``config_root`` overrides it for
    games that keep their config outside the install tree (Project Zomboid
    writes to ``~/Zomboid``, for example). ``~`` expands to the *run-as*
    account's home, never this process's. The result is clamped to
    ``_allowed_config_root_bases()`` — an admin cannot point it at ``~/.ssh``
    or Portal's source and hand a non-admin `files` grant on it."""
    cr = (gs.get("config_root") or "").strip()
    if not cr:
        return gs["install_dir"]
    if cr == "~":
        cr = _run_as_home()
    elif cr.startswith("~/"):
        cr = _run_as_home() + cr[1:]
    cr = os.path.realpath(cr)
    for base in _allowed_config_root_bases():
        if cr == base or cr.startswith(base + os.sep):
            return cr
    logger.warning("config_root %r not under an allowed base — falling back to install_dir", cr)
    return gs["install_dir"]


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
_STOP_SIGNALS = {"SIGINT", "SIGTERM", "SIGKILL", "SIGHUP", "SIGQUIT",
                 "SIGUSR1", "SIGUSR2"}
_ARGS_MAX = 4000


def _systemd_quote(a: str) -> str:
    """Quote one ExecStart token for a systemd unit file.

    systemd does its own C-style unquoting of ExecStart, so we double-quote
    every token and escape the characters that are special *to systemd*
    (`"` `\\` `%` `$`). There is no shell in the picture, so shell
    metacharacters need no handling — they reach the process as literal argv."""
    out = (a.replace("\\", "\\\\").replace('"', '\\"')
           .replace("%", "%%").replace("$", "$$"))
    return f'"{out}"'


def _resolve_launch_cmd(install_dir: str, start_cmd: str) -> str:
    """Absolute path to the launch executable, confined to ``install_dir``.

    ``start_cmd`` is a plain relative path (``./PalServer.sh``) — never a shell
    fragment. Existence is *not* checked here (the unit is written before the
    SteamCMD install runs); the file check belongs to `set_launch_options`."""
    sc = (start_cmd or "").strip()
    rel = sc[2:] if sc.startswith("./") else sc
    if not rel or not re.fullmatch(r"[A-Za-z0-9_./+-]+", rel):
        raise ValueError("start command must be a plain relative path "
                         "(letters, digits, . _ / + -) inside the install dir")
    if rel.startswith(("/", "~")) or ".." in rel.split("/"):
        raise ValueError("start command must be a path inside the install dir")
    root = os.path.realpath(install_dir)
    abs_p = os.path.realpath(os.path.join(root, rel))
    if abs_p != root and not abs_p.startswith(root + os.sep):
        raise ValueError("start command resolves outside the install dir")
    return abs_p


def _parse_launch_args(start_args: str) -> list:
    """Split a launch-argument string into argv tokens (shell-style quoting,
    for the operator's convenience) — no shell is ever invoked on them."""
    s = (start_args or "").strip()
    if not s:
        return []
    if len(s) > _ARGS_MAX:
        raise ValueError("start arguments too long")
    if any(ord(c) < 0x20 and c != "\t" for c in s):
        raise ValueError("start arguments contain a control character")
    try:
        return shlex.split(s)
    except ValueError as e:
        raise ValueError(f"could not parse start arguments: {e}")


def _unit_text(name: str, install_dir: str, start_cmd: str, start_args: str,
               stop_signal: str) -> str:
    # Defence in depth: nothing interpolated raw into the unit file may carry a
    # newline or other control char (would inject arbitrary systemd directives).
    for field, val in (("name", name), ("install_dir", install_dir)):
        if any(ord(c) < 0x20 for c in str(val or "")):
            raise ValueError(f"illegal control character in {field}")
    exe = _resolve_launch_cmd(install_dir, start_cmd)
    argv = _parse_launch_args(start_args)
    exec_line = " ".join(_systemd_quote(t) for t in [exe, *argv])
    sig = stop_signal if stop_signal in _STOP_SIGNALS else "SIGTERM"
    return (
        "[Unit]\n"
        f"Description=Game server ({name}) — managed by Open Relay Portal\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={RUN_AS}\n"
        f"WorkingDirectory={install_dir}\n"
        f"ExecStart={exec_line}\n"
        "Restart=on-failure\nRestartSec=10\n"
        f"KillSignal={sig}\nTimeoutStopSec=45\n\n"
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

    cfg_paths = _as_glob_list(cat["config_paths"])
    bak_paths = _as_glob_list(cat.get("backup_paths"))

    install_dir = _validate_install_dir(install_dir or f"{GAMEDATA_ROOT}/{name}")

    unit_name = f"portal-gs-{name}"
    args = start_args if start_args is not None else cat["start_args"]
    slogin = _validate_steam_login(steam_login or cat["steam_login"])
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
                "backup_paths": json.dumps(bak_paths),
                "config_root": cat.get("config_root") or None,
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


async def adopt(db, *, catalog_key: str | None = None, custom: dict | None = None,
                name: str, install_dir: str, display_name: str | None = None,
                start_cmd: str | None = None, start_args: str | None = None,
                steam_login: str | None = None, stop_signal: str | None = None,
                reuse_service_id: int | None = None, enable: bool = False,
                created_by: int | None = None) -> dict:
    """Register an ALREADY-INSTALLED game server as a Portal-managed one.

    No SteamCMD install runs and the install directory is never touched — this
    adopts a hand-rolled server (existing dir + its own systemd unit) onto the
    Portal game-server machinery. Pass ``reuse_service_id`` to convert an
    existing managed-service row in place, keeping its id, grants and encrypted
    config; otherwise a fresh ``gameserver`` service is created.

    The caller is responsible for the actual cut-over (stop the old unit,
    ``systemctl enable --now portal-gs-<name>``).
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

    cfg_paths = _as_glob_list(cat["config_paths"])
    bak_paths = _as_glob_list(cat.get("backup_paths"))

    install_dir = _validate_install_dir(install_dir, must_exist=True)
    app_id = cat["steam_app_id"]
    acf = os.path.join(install_dir, "steamapps", f"appmanifest_{app_id}.acf")
    if not os.path.isfile(acf):
        raise ValueError(
            f"{install_dir} has no Steam manifest for app {app_id} "
            f"({acf}) — wrong directory or catalog game?")

    unit_name = f"portal-gs-{name}"
    s_cmd = start_cmd or cat["start_cmd"]
    args = start_args if start_args is not None else cat["start_args"]
    slogin = _validate_steam_login(steam_login or cat["steam_login"])
    stop_sig = stop_signal or cat["stop_signal"]
    build = _installed_build(install_dir, app_id)

    old_service = None
    if reuse_service_id is not None:
        old_service = await db.get_service_by_id(reuse_service_id)
        if not old_service:
            raise ValueError(f"service {reuse_service_id} not found")

    async with _lock():
        UNITS_DIR.mkdir(parents=True, exist_ok=True)
        unit_file = UNITS_DIR / f"{unit_name}.service"
        gs_id = None
        try:
            unit_file.write_text(_unit_text(name, install_dir, s_cmd, args, stop_sig))
            rc, _, err = await _run_cmd(_sudo("ln", "-sf", str(unit_file),
                                              f"{SYSTEMD_DIR}/{unit_name}.service"))
            if rc != 0:
                raise RuntimeError(f"failed to install unit: {err}")
            await _run_cmd(_sudo("systemctl", "daemon-reload"))

            gs_id = await db.game_server_create({
                "name": name, "catalog_key": catalog_key,
                "steam_app_id": app_id, "steam_login": slogin,
                "install_dir": install_dir, "unit_name": unit_name,
                "start_cmd": s_cmd, "start_args": args, "stop_signal": stop_sig,
                "config_paths": json.dumps(cfg_paths),
                "backup_paths": json.dumps(bak_paths),
                "config_root": cat.get("config_root") or None,
                "state": "installed", "created_by": created_by,
            })
            await db.game_server_update(gs_id, installed_build=build)

            if reuse_service_id is not None:
                await db.update_service_full(
                    reuse_service_id,
                    plugin="gameserver", service_type="managed", icon="game",
                    display_name=(display_name or old_service.get("display_name")
                                  or f"{cat['name']} ({name})"),
                    enabled=enable,
                    config={"unit": unit_name, "game_server_id": gs_id},
                )
                svc_id = reuse_service_id
                # refresh the in-memory handler if the manager is already live
                mgr = _services.service_manager
                if mgr is not None:
                    mgr._services.pop(svc_id, None)
                    try:
                        row = await db.get_service_by_id(svc_id)
                        cls = _services.get_service_class("gameserver")
                        if cls and row:
                            h = cls(row)
                            h._db = db
                            mgr._services[svc_id] = h
                    except Exception as e:
                        logger.warning("handler refresh for service %s failed: %s", svc_id, e)
            else:
                svc = await _services.service_manager.create_service(
                    name=name, service_type="gameserver",
                    display_name=display_name or f"{cat['name']} ({name})",
                    description=f"Game server · Steam app {app_id}",
                    config={"unit": unit_name, "game_server_id": gs_id},
                    enabled=enable,
                )
                if not svc:
                    raise RuntimeError("could not create the backing managed service")
                svc_id = svc.id

            await db.game_server_update(gs_id, service_id=svc_id, state="installed")
        except Exception:
            await _run_cmd(_sudo("rm", "-f", f"{SYSTEMD_DIR}/{unit_name}.service"))
            unit_file.unlink(missing_ok=True)
            await _run_cmd(_sudo("systemctl", "daemon-reload"))
            if reuse_service_id is not None and old_service is not None:
                # put the row back the way we found it
                try:
                    await db.update_service_full(
                        reuse_service_id,
                        plugin=old_service.get("plugin"),
                        service_type=old_service.get("service_type"),
                        display_name=old_service.get("display_name"),
                        enabled=bool(old_service.get("enabled")),
                        config=old_service.get("config") or {},
                    )
                except Exception as e:
                    logger.error("failed to restore service %s: %s", reuse_service_id, e)
            elif gs_id is not None:
                try:
                    for r in await db.get_services_by_type("managed"):
                        if r.get("name") == name and r.get("plugin") == "gameserver":
                            await _services.service_manager.delete_service(r["id"])
                except Exception as e:
                    logger.warning("orphan service cleanup failed: %s", e)
            if gs_id is not None:
                await db.game_server_delete(gs_id)
            raise

    return {"game_server": await db.game_server_get(gs_id)}


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


_BUILD_CHECK_INTERVAL = 6 * 3600     # seconds between automatic checks
_build_check_task = None


def is_update_available(gs: dict) -> bool:
    ib, lb = gs.get("installed_build"), gs.get("latest_build")
    return bool(ib and lb and str(ib) != str(lb))


async def _build_check_loop(db):
    """Refresh installed/latest build for every deployed server on a timer so
    the admin cards can show an up-to-date / update-available badge without
    anyone clicking Check."""
    await asyncio.sleep(90)   # let the box settle after boot
    while True:
        try:
            for gs in await db.game_server_list():
                if gs.get("state") in ("installing", "updating"):
                    continue
                try:
                    await check_latest_build(db, gs["id"])
                except Exception as e:
                    logger.warning("build check for %s failed: %s", gs.get("name"), e)
                await asyncio.sleep(5)
        except Exception:
            logger.exception("game-server build-check loop iteration failed")
        await asyncio.sleep(_BUILD_CHECK_INTERVAL)


def start_build_check_loop(db):
    global _build_check_task
    if _build_check_task is None or _build_check_task.done():
        _build_check_task = asyncio.create_task(_build_check_loop(db))
    return _build_check_task


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
# Launch options — rewrite the unit's ExecStart / KillSignal
# ---------------------------------------------------------------------------
async def set_launch_options(db, gs_id: int, *, start_args=None, stop_signal=None,
                             start_cmd=None, allow_cmd=False) -> dict:
    """Update a deployed server's launch arguments / stop signal (and, for an
    admin, its start command), regenerate the unit file and `daemon-reload`.

    Safe for a `control` grant to drive the args/signal: the unit runs the
    executable directly (no shell), so arguments are literal argv — there is
    no command-injection surface. `start_cmd` changes the binary that runs as
    the game account, so they are gated to admins (`allow_cmd`).

    Does not restart the server; the new ExecStart takes effect on next start.
    Returns ``{game_server, restart_required}``."""
    gs = await db.game_server_get(gs_id)
    if not gs:
        raise ValueError("no such game server")

    new_args = gs.get("start_args") or ""
    if start_args is not None:
        _parse_launch_args(start_args)          # validate (raises ValueError)
        new_args = start_args.strip()

    new_sig = gs.get("stop_signal") or "SIGTERM"
    if stop_signal is not None:
        if stop_signal not in _STOP_SIGNALS:
            raise ValueError(f"stop signal must be one of {sorted(_STOP_SIGNALS)}")
        new_sig = stop_signal

    new_cmd = gs.get("start_cmd")
    if start_cmd is not None and start_cmd != new_cmd:
        if not allow_cmd:
            raise PermissionError("changing the start command requires admin")
        exe = _resolve_launch_cmd(gs["install_dir"], start_cmd)   # confine
        if not os.path.isfile(exe):
            raise ValueError(f"no such file in the install dir: {start_cmd}")
        new_cmd = start_cmd.strip()

    changed = (new_args != (gs.get("start_args") or "")
               or new_sig != (gs.get("stop_signal") or "SIGTERM")
               or new_cmd != gs.get("start_cmd"))

    unit_name = gs["unit_name"]
    unit_file = UNITS_DIR / f"{unit_name}.service"
    old_text = unit_file.read_text() if unit_file.exists() else None
    new_text = _unit_text(gs["name"], gs["install_dir"], new_cmd, new_args, new_sig)

    async with _lock():
        try:
            UNITS_DIR.mkdir(parents=True, exist_ok=True)
            unit_file.write_text(new_text)
            # ensure the /etc symlink still points here (harmless if it does)
            await _run_cmd(_sudo("ln", "-sf", str(unit_file),
                                 f"{SYSTEMD_DIR}/{unit_name}.service"))
            rc, _, err = await _run_cmd(_sudo("systemctl", "daemon-reload"))
            if rc != 0:
                raise RuntimeError(f"daemon-reload failed: {err}")
        except Exception:
            if old_text is not None:
                unit_file.write_text(old_text)
                await _run_cmd(_sudo("systemctl", "daemon-reload"))
            raise
        await db.game_server_update(gs_id, start_args=new_args,
                                    stop_signal=new_sig, start_cmd=new_cmd)

    return {
        "game_server": await db.game_server_get(gs_id),
        "restart_required": bool(changed),
    }


# ---------------------------------------------------------------------------
# Config file editor + backup (scoped to the server's install dir)
# ---------------------------------------------------------------------------
def _config_globs(gs: dict) -> list:
    return _as_glob_list(gs.get("config_paths"))


def _backup_globs(gs: dict) -> list:
    return _as_glob_list(gs.get("backup_paths"))


def _match_files(root: str, globs: list) -> list[dict]:
    """Existing regular files under `root` matching any glob (``**`` supported)."""
    seen, out = set(), []
    for pat in globs:
        for match in glob.glob(os.path.join(root, pat), recursive=True):
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


def list_config_files(gs: dict) -> list[dict]:
    return _match_files(_config_root(gs), _config_globs(gs))


def list_backup_files(gs: dict) -> list[dict]:
    """Everything the backup archive would contain: config + save/world globs."""
    return _match_files(_config_root(gs), _config_globs(gs) + _backup_globs(gs))


# Archive guards — a browser download, not a disk image.
_BACKUP_MAX_TOTAL = 512 * 1024 * 1024
_BACKUP_MAX_FILE = 128 * 1024 * 1024


def make_backup_archive(gs: dict) -> tuple[bytes, str]:
    """tar.gz of the server's config + backup files. Returns (bytes, filename)."""
    import io
    import tarfile
    from datetime import datetime, timezone

    root = _config_root(gs)
    files = list_backup_files(gs)
    if not files:
        raise ValueError("nothing to back up for this server yet")

    total = 0
    buf = io.BytesIO()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    prefix = f"{gs['name']}-{stamp}"
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for f in files:
            if f["size"] > _BACKUP_MAX_FILE:
                continue
            total += f["size"]
            if total > _BACKUP_MAX_TOTAL:
                raise ValueError("backup set exceeds 512 MB — grab it over SFTP instead")
            abs_p = os.path.join(root, f["path"])
            tar.add(abs_p, arcname=os.path.join(prefix, f["path"]))
    return buf.getvalue(), f"{prefix}.tar.gz"


def _resolve_config(gs: dict, rel: str) -> Path:
    root = _config_root(gs)
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


# Never writable through the config editor even if an admin points a
# ``config_paths`` glob at one — editing these and restarting the server
# (a `control` grant) would run attacker code as the game account.
_NO_WRITE_SUFFIXES = {
    ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".php", ".lua5", ".js",
    ".service", ".timer", ".socket", ".path", ".so", ".bin", ".run", ".x86_64",
}


def write_config(gs: dict, rel: str, text: str) -> None:
    rp = _resolve_config(gs, rel)
    if rp.suffix.lower() in _NO_WRITE_SUFFIXES or os.access(str(rp), os.X_OK):
        raise ValueError("this file type can't be edited here")
    rp.write_bytes(text.encode("utf-8"))
    try:
        shutil.chown(str(rp), RUN_AS, RUN_AS)
    except (LookupError, PermissionError, OSError) as e:
        logger.warning("chown %s failed: %s", rp, e)


# ---------------------------------------------------------------------------
# Jailed file browser
#
# The general file-access mechanism for a `files` grant (or an admin): a
# directory browser confined to the server's own tree(s). The ``config_paths``
# globs above are now just the "pinned settings files" shortcut list surfaced
# at the top of the browser — not the access boundary. The boundary is the
# jail: every path is resolved and required to stay under one of the roots,
# symlinks are refused outright (``file_manager._validate_path``), and writes
# are limited to existing files with a config-like extension so a grantee can't
# drop or edit a script that ``systemctl restart`` would then run as `dustin`.
# ---------------------------------------------------------------------------

_BROWSE_MAX_EDIT = 2 * 1024 * 1024          # inline-editable ceiling
_BROWSE_MAX_DOWNLOAD = _BACKUP_MAX_FILE     # single-file download ceiling (128 MB)

# Text config formats only. Executables, shared objects, archives, databases and
# save blobs are browsable/downloadable but never writable through the browser.
_BROWSE_WRITE_SUFFIXES = {
    ".ini", ".cfg", ".conf", ".config", ".json", ".xml", ".yaml", ".yml",
    ".toml", ".txt", ".lua", ".properties", ".props", ".cnf",
    ".settings", ".list", ".ecf",
}


def file_roots(gs: dict) -> list[dict]:
    """The directory roots the browser is allowed to expose for this server.

    Always the install dir; plus ``config_root`` when it resolves somewhere
    else (Project Zomboid's ``~/Zomboid``). Both are re-validated against
    ``_allowed_config_root_bases()`` — the game-data disk plus an explicit
    allowlist — before being handed out, so a bad ``config_root`` can't expose
    the account home or Portal's source through a `files` grant."""
    out, seen = [], set()
    bases = _allowed_config_root_bases()

    def _ok(p: str) -> bool:
        rp = os.path.realpath(p)
        return any(rp == b or rp.startswith(b + os.sep) for b in bases)

    inst = os.path.realpath(gs["install_dir"])
    if _ok(inst) and os.path.isdir(inst):
        out.append({"key": "install", "label": "Server files", "path": inst})
        seen.add(inst)
    cr = os.path.realpath(_config_root(gs))
    if cr not in seen and _ok(cr) and os.path.isdir(cr):
        out.append({"key": "config", "label": "Config & saves", "path": cr})
    return out


def _browse_root(gs: dict, root_key: str) -> str:
    for r in file_roots(gs):
        if r["key"] == root_key:
            return r["path"]
    raise ValueError("unknown file root")


def _jail(root: str, resolved: Path) -> Path:
    rp = os.path.realpath(str(resolved))
    if rp != root and not rp.startswith(root + os.sep):
        raise ValueError("path is outside the permitted directory")
    return resolved


def _browse_writable(resolved: Path) -> bool:
    return resolved.suffix.lower() in _BROWSE_WRITE_SUFFIXES


def browse_dir(gs: dict, root_key: str, rel: str = "") -> dict:
    """One directory level. Symlinks are dropped from the listing."""
    root = _browse_root(gs, root_key)
    rel = (rel or "").strip().strip("/")
    _jail(root, file_manager._validate_path(rel or "/", root))
    entries = file_manager.list_directory(rel or "/", root)
    items = []
    for e in entries:
        if e.get("type") == "symlink":
            continue
        items.append({
            "name": e["name"],
            "type": e["type"],
            "size": e.get("size", 0),
            "mtime": e.get("modified", 0),
            "path": (rel + "/" + e["name"]).lstrip("/") if rel else e["name"],
            "writable": e.get("type") == "file"
            and e["name"].lower().endswith(tuple(_BROWSE_WRITE_SUFFIXES)),
        })
    items.sort(key=lambda i: (i["type"] != "directory", i["name"].lower()))
    return {"root": root_key, "path": rel, "entries": items}


def browse_read(gs: dict, root_key: str, rel: str) -> dict:
    root = _browse_root(gs, root_key)
    resolved = _jail(root, file_manager._validate_path(rel, root))
    if not resolved.is_file():
        raise ValueError("not a file")
    if resolved.stat().st_size > _BROWSE_MAX_EDIT:
        raise ValueError("file is too large to edit here — download it instead")
    data = resolved.read_bytes()
    return {
        "path": rel,
        "content": data.decode("utf-8", "replace"),
        "writable": _browse_writable(resolved),
    }


def browse_write(gs: dict, root_key: str, rel: str, text: str) -> None:
    root = _browse_root(gs, root_key)
    resolved = _jail(root, file_manager._validate_path(rel, root))
    if not resolved.is_file():
        raise ValueError("can only edit files that already exist")
    if not _browse_writable(resolved):
        raise ValueError("this file type can't be edited from the browser")
    if len(text.encode("utf-8")) > _BROWSE_MAX_EDIT:
        raise ValueError("file too large")
    resolved.write_bytes(text.encode("utf-8"))
    try:
        shutil.chown(str(resolved), RUN_AS, RUN_AS)
    except (LookupError, PermissionError, OSError) as e:
        logger.warning("chown %s failed: %s", resolved, e)


def browse_download(gs: dict, root_key: str, rel: str) -> tuple[bytes, str]:
    root = _browse_root(gs, root_key)
    resolved = _jail(root, file_manager._validate_path(rel, root))
    if not resolved.is_file():
        raise ValueError("not a file")
    if resolved.stat().st_size > _BROWSE_MAX_DOWNLOAD:
        raise ValueError("file too large to download here — use the full backup or SFTP")
    return resolved.read_bytes(), resolved.name


# ---------------------------------------------------------------------------
# Keep a deployed server's paths in sync with its (builtin) catalog entry
# ---------------------------------------------------------------------------
async def resync_from_catalog(db, gs_id: int) -> dict:
    """Refresh a deployed server's config/backup globs + config_root from its
    catalog entry. Deploy snapshots these, so a later catalog correction never
    reaches an already-deployed server without this."""
    gs = await db.game_server_get(gs_id)
    if not gs:
        raise ValueError("no such game server")
    key = gs.get("catalog_key")
    if not key:
        raise ValueError("server was deployed from a custom entry — nothing to sync")
    cat = await db.game_catalog_get(key)
    if not cat:
        raise ValueError(f"catalog entry {key!r} no longer exists")
    await db.game_server_update(
        gs_id,
        config_paths=json.dumps(_as_glob_list(cat.get("config_paths"))),
        backup_paths=json.dumps(_as_glob_list(cat.get("backup_paths"))),
        config_root=cat.get("config_root") or None,
    )
    return await db.game_server_get(gs_id)


async def resync_all_from_catalog(db) -> int:
    """Boot-time: re-pull paths for every server that came from a builtin
    catalog entry, so shipped catalog fixes land without a manual script."""
    changed = 0
    try:
        servers = await db.game_server_list()
    except Exception:
        return 0
    for gs in servers:
        key = gs.get("catalog_key")
        if not key:
            continue
        try:
            cat = await db.game_catalog_get(key)
        except Exception:
            continue
        if not cat or not cat.get("builtin"):
            continue
        want = (
            json.dumps(_as_glob_list(cat.get("config_paths"))),
            json.dumps(_as_glob_list(cat.get("backup_paths"))),
            cat.get("config_root") or None,
        )
        have = (
            json.dumps(_as_glob_list(gs.get("config_paths"))),
            json.dumps(_as_glob_list(gs.get("backup_paths"))),
            gs.get("config_root") or None,
        )
        if want != have:
            try:
                await db.game_server_update(
                    gs["id"], config_paths=want[0], backup_paths=want[1],
                    config_root=want[2])
                changed += 1
                logger.info("resynced game server %s paths from catalog %s",
                            gs.get("name"), key)
            except Exception as e:
                logger.warning("resync %s failed: %s", gs.get("name"), e)
    return changed
