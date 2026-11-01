# Windows-only game servers

Some dedicated servers ship no Linux build at all. Portal runs these under
Wine, one prefix per server. This page records how that works and the behaviour
that isn't obvious from the code.

## How it works

Each catalog entry and deployed server has a `runtime` of `native` or `wine`.
A `wine` server differs from a native one in three ways:

- **Unit**: `ExecStart` is `PORTAL_WINE_BIN` (default `/usr/lib/wine/wine64`)
  followed by the absolute path to the `.exe`. There is still no shell in the
  unit, and `start_cmd` is still confined to the install dir.
- **Prefix**: `WINEPREFIX=<install_dir>/.wineprefix`. It is created on first
  start and deleted with the server's files.
- **SteamCMD**: every install and update passes
  `+@sSteamCmdForcePlatformType windows`, through `_steam_update_cmd`.

## What Portal does on its own

- **Detects Windows-only apps at deploy.** If a native install has no launch
  file, Portal reads the app's Steam launch entries. If they list an `.exe` and
  no Linux entry, it reinstalls the Windows depots, moves the server to Wine,
  sets the start command to that `.exe` and uses `SIGINT`. A Linux entry blocks
  this, so a Linux game with a wrong start command fails instead of being
  replaced by its Windows build.
- **Installs Wine when first needed.** A deploy or update runs
  `apt-get install --no-install-recommends wine64` if Wine is missing. It does
  this only for the default `PORTAL_WINE_BIN`, on hosts with `apt-get`. With a
  custom path, or on another distro, the job fails and says so.
- **Fails instead of faking success.** Install and update fail if the launch
  file is missing afterwards, and a failed install is never enabled.
- **Repairs broken installs.** Update re-validates a server whose launch file is
  missing, even when its build id is current.
- **Applies catalog corrections.** At boot, and on `resync-catalog`, a server
  with a missing launch file moves to its built-in catalog entry's runtime and
  start command. A server that can launch is never changed.

Portal does not update game servers automatically. The six-hour job only
compares builds so the admin panel can show an update badge; applying an update
is still a click on **Update**, because it restarts the server.

## Nuances

**SteamCMD's success message proves nothing.** Fetching a Windows-only app on
Linux prints `Success! App fully installed` and exits 0, but only delivers the
Steam redistributables (depot 1006, about 111 MB).

**The platform flag is needed on every SteamCMD call.** Without it, an update
reconciles the install to the Linux depots and can remove the `.exe`. Always go
through `_steam_update_cmd`; never build an `app_update` command by hand.

**Use `SIGINT`, not `SIGTERM`.** Under Wine, Enshrouded ignores `SIGTERM` until
the 45-second stop timeout kills it without saving. With a world loaded,
`SIGINT` saves and exits in about a second. Portal uses `SIGINT` for Wine servers
unless a different signal was chosen explicitly.

**Wine, not Proton.** Proton was tried first on Debian 12 and did not work:

- GE-Proton 11 needs glibc 2.38 (the host has 2.36) or Steam Linux Runtime 4,
  and anonymous SteamCMD refuses that runtime with `No subscription`. Running it
  with the runtime from Valve's public repo was not tried.
- GE-Proton 10 runs, but its Steam bridge is older than the Steamworks version
  Enshrouded uses, so the server exits with `No SteamUtils011`. Disabling the
  bridge or copying Steam DLLs into the prefix does not help.

Plain Wine has no Steam bridge, so the game loads the `steamclient64.dll` it
ships with. Dedicated servers log on to Steam themselves and don't need a
client.

**64-bit only.** Debian's `wine64` can't run 32-bit programs, so Portal reads the
executable's PE header and fails a 32-bit server with a clear error. To run one,
point `PORTAL_WINE_BIN` at a Wine with 32-bit support.

**No .NET.** `mscoree` and `mshtml` are disabled so a new prefix doesn't try to
download Mono and Gecko. Servers built on .NET, such as Space Engineers, are
expected not to run until that changes.

**Launcher executables may not work.** systemd tracks the process it started. A
launcher that starts the real server and exits ends the unit. Steam's launch
entry can be such a launcher, so prefer the real server binary when you know it
(for Unreal Engine games, usually `...-Win64-Shipping.exe`).

**The prefix holds links out of the install dir.** `.wineprefix/dosdevices/z:`
points to `/`, and the folders under `drive_c/users/<account>/` point into the
game account's home. The Files browser hides these links and refuses paths
through them. Backups only include each game's `backup_paths`. A Wine server has
the same file access as a native one running as that account.

**Harmless log lines.** With only `wine64` installed, the first start logs
`failed to open L"C:\windows\syswow64\rundll32.exe"`. Enshrouded also logs an
error about `QueryIoRingCapabilities` on start.

**The first start takes longer.** Wine builds the prefix before the game runs,
which took about 20 seconds here.

## Tested status

| Game | Result |
|------|--------|
| Enshrouded | Runs: connects to Steam, saves, reloads, stops cleanly. Tested without a game client joining. |
| Astroneer | Automatic install and switch to Wine work, but `AstroServer.exe` exited on its own within seconds. Not working yet. |
| Sons of the Forest, The Forest, Abiotic Factor | Set to Wine in the catalog, not tested. |

## Adding a Windows-only game

Set **Runtime** to Wine and the start command to the `.exe`, in the catalog form
or in a server's launch options, then run **Update** if the Windows files aren't
installed yet. Automatic detection covers the common case, but it uses whatever
`.exe` Steam lists, which may be a launcher.
