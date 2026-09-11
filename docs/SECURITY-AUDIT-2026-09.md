# Security audit — releases v1.7.0 → v1.10.3

Date: 2026-09-09. Scope: everything shipped between v1.7.0 and v1.10.3
(shared-access grants, device metrics, managed-service systemd type, the
embedded browser, and the whole SteamCMD game-server subsystem). Focus:
paths that could give an **unauthenticated user, a plain user, or a
grant-holder** remote code execution or a shell on the host.

## Threat model

`portal.service` runs as **root**. A portal **admin** already has a root PTY
on the host on purpose — `GET /ws/terminal/local` (admin-scope-gated) spawns
`/bin/bash` as root, and the admin file manager (`/api/files/*`, also
admin-only) is rooted at `/`. So for this audit **"portal admin" is treated as
root-equivalent by design**, and a finding only matters if it lets someone
*without* admin scope — anonymous, a plain user, or the holder of a
`control` / `logs` / `files` service grant — reach code execution, file
write outside their lane, or host access.

Non-admin attack surface in range:

| Capability | Reaches |
|---|---|
| `control` grant | start/stop/restart/update a specific game server (systemd + SteamCMD); edit its launch args / stop signal |
| `logs` grant | `journalctl` for that unit (read-only) |
| `files` grant | jailed file browser + config editor for that server's tree(s) |
| plain user | own proxy connections / stream relays (SSRF-checked), chat |
| anonymous | login, static assets, OG tags |

## Findings

### FIXED

#### F2 — `config_root` allowed the whole run-as home → `files`-grantee → host (High)

`gameservers._config_root()` clamped a catalog/row `config_root` to
"under `GAMEDATA_ROOT` **or** the run-as account's home". The run-as home
(`/home/dustin`) contains `~/.ssh/authorized_keys` (→ SSH in as the
sudo-capable game account → root), `~/scripts/portal/*.py` (→ overwrite
`server.py` → root on next restart), `~/.bashrc`, etc.

An admin who set `config_root: "~/.ssh"` + `config_paths: ["authorized_keys"]`
on a catalog entry, deployed it, and granted a non-admin `files` on that
server handed that user read+write on those paths. The legacy
`POST /api/game-servers/{id}/config/write` endpoint has only a glob
allowlist (no file-type check), so an extensionless target like
`authorized_keys` went straight through. The write runs as root and
`chown`s the result to the game account.

Requires admin misconfiguration to reach, but the *exploiting* party is a
non-admin `files` grantee, so it crosses a real privilege boundary.

**Fix** (`gameservers.py`):
- `_allowed_config_root_bases()` — `config_root` may now resolve only under
  `GAMEDATA_ROOT` or `<run-as home>/Zomboid` (plus anything in the
  `PORTAL_GS_EXTRA_CONFIG_ROOTS` env var). `~/.ssh`, `~`, `~/scripts`,
  `~/.config`, `/etc` all fall back to `install_dir`.
- Applied in both `_config_root()` and `file_roots()`.
- Defence in depth: `write_config()` now refuses any file with an
  executable/script suffix (`.sh .py .service …`) or the execute bit set,
  independent of the glob allowlist.

The `write_config()` suffix denylist is a speed bump, not the boundary —
it matches on `Path.suffix` so a double extension (`x.sh.bak`) or an
extensionless target slips it, and it only catches the execute bit on a
file that *already exists*. The real containment is the
`_allowed_config_root_bases()` allowlist: with `config_root` unable to
resolve outside `GAMEDATA_ROOT` / `<home>/Zomboid`, there is nothing
security-relevant (`~/.ssh`, `~/scripts`, `/etc`) left to write regardless
of suffix.

Verified: `_config_root()` and `file_roots()` — the two functions the
`/files` and `/config` HTTP handlers call, with no `config_root` logic of
their own on top — resolve a poisoned `config_root` (`~/.ssh`, `~`,
`~/scripts/portal`, `/etc`) to `install_dir` and expose only the `install`
root, logging the rejection. Separately, poisoning `game_servers.config_root`
for a built-in-keyed row directly in the DB is undone on the next restart
by the boot `resync_all_from_catalog()` pass (it re-pulls `config_root`
from the catalog) — a third layer below the allowlist and the write-suffix
denylist.

Project Zomboid (`config_root: "~/Zomboid"`) is unaffected.

#### F1 — `install_dir` reached the systemd unit unescaped → unit-directive injection (Low–Med, admin-only)

`deploy()` / `adopt()` accepted `install_dir` with only
`os.path.normpath` + a `startswith(GAMEDATA_ROOT + "/")` check — neither
rejects newlines. `_unit_text()` interpolated it into `WorkingDirectory=`
raw, so `install_dir = "/mnt/gamedata/real\nExecStartPre=+/bin/sh -c '…'"`
injected an `ExecStartPre` that systemd runs as root when the unit starts.

Only `deploy` is HTTP-reachable and it is **admin-only** (no `adopt`
endpoint exists), so this is not a privilege boundary crossing — an admin
is already root-equivalent. Fixed anyway because it is cheap and prevents
unit-file corruption.

**Fix** (`gameservers.py`): `_validate_install_dir()` — charset
`[A-Za-z0-9._/-]`, must resolve to a strict subdirectory of
`GAMEDATA_ROOT`. `_unit_text()` also rejects any control character in
`name` / `install_dir` as a backstop.

#### F4 / F5 — input hardening on SteamCMD login and launch args (Low)

- `steam_login` was unvalidated before being passed as `steamcmd +login <x>`.
  argv-safe (no shell) and admin-only, so not RCE, but now constrained to
  `[A-Za-z0-9._@+-]{1,64}` so it can't be a stray `+command` token.
- `_parse_launch_args()` rejected only `\n\r\0`; now rejects every control
  character except tab.

### ACCEPTED — admin is root-equivalent by design, no non-admin path

| # | Item | Why it's accepted |
|---|---|---|
| F3 | A `systemd`-type managed service lets an admin `start/stop/enable/disable` **any** existing host unit (`config.unit` is any name matching `^[A-Za-z0-9_\-.@]+$`). | Admin-only. `control`/`disable` of arbitrary units is broad, but an admin already has a root shell. No unit-file *write* — needs a unit already on disk. `mask`/`daemon-reload` are not in `_ALLOWED_ACTIONS`. |
| F6 | `.lua` is writable through the config editor (editing a file already on disk). For a Lua-scripting game server (e.g. Garry's Mod) a `files` grantee could rewrite server-side Lua. | Game-sandbox-dependent, and `.lua` is a legitimate config format (Zomboid `SandboxVars.lua`, Factorio). Documented limitation. A dedicated Lua-scripting game would warrant a per-catalog "no `.lua` write" flag. **Multi-file upload (added after this audit) does not widen this**: `browse_upload` uses `_BROWSE_UPLOAD_SUFFIXES` = `_BROWSE_WRITE_SUFFIXES` minus `.lua` — a `files` grantee can still edit an existing `.lua`, but cannot upload a new one (creating a file that never existed is a bigger step than editing one already there — e.g. dropping something into a GMod autorun path). |
| F7 | Relay `rtmp_url` has no scheme allowlist. | `_validate_relay_url()` already rejects bad chars, requires a hostname (kills `file:` / `concat:` / `pipe:`), and runs a full SSRF check incl. DNS-rebind. Residual is exfil to a *public* host over an odd scheme — low, and pre-dates the window. Adding an `{rtmp, rtmps}` allowlist is a reasonable follow-up. |
| F8 | `redact_service_config()` redacts by keyword (`password`/`secret`/`token`/`key`/`credential`). A non-keyword-named secret would leak to a grantee on the service-detail endpoint. | No current service config has such a field (`gameserver` config is `{unit, game_server_id}`; MediaMTX/SearXNG secrets live in their own files). Worth switching to an explicit per-plugin allowlist if a plugin ever stores an oddly-named secret. |
| — | Admin file manager rooted at `/`; `/ws/terminal/local` root PTY. | Intentional admin capability. |
| — | `http_game_server_job` looks the job up before the grant check → a non-grantee can tell "job id exists" from "doesn't". | Trivial oracle, no data disclosed. |

## Verified clean

- **No shell.** No `shell=True`, `os.system`, `os.popen`, or
  `create_subprocess_shell` anywhere. Every subprocess is
  `create_subprocess_exec(*argv_list)`.
- **No attacker-controlled `env`.** `run_streamed` / `_run_cmd` accept an
  `env=`, but no game-server or non-admin call site passes one
  (`update_manager` passes a constant `_APT_ENV`; `services/base` passes a
  plugin-defined env from admin-set service config).
- **SQL.** All queries are parameterised; the only f-string interpolation
  into SQL is `,`-joined `?` placeholder lists and hard-coded table names.
  Chat FTS search builds its `WHERE` from `?`-placeholder conditions only.
- **No `eval` / `exec` / `pickle` / `yaml.load` on request data.**
- **Grants.** `service_grants.actions` is whitelisted to
  `{control, logs, files}` at the DB layer; only admins can grant; grant
  lookups are parameterised; a non-admin cannot self-escalate.
- **Path traversal.** `file_manager._validate_path` rejects `..` (post-resolve
  `startswith` + `relative_to`) and symlinks (pre- and post-resolve). The
  game-server browser adds a redundant realpath jail check. `_as_glob_list`
  strips `..`, absolute and `~` globs.
- **`_gs_*` endpoint ordering.** Every game-server handler runs
  `_gs_access` / `_gs_config_ctx` before doing work.
- **Unit / service names.** `_validate_service_name` (`^[A-Za-z0-9_\-.@]+$`),
  `_NAME_RE` for game servers (`^[a-z0-9][a-z0-9-]{1,31}$`) — no `/`, no `..`.
- **Device metrics** — pure `psutil`, no subprocess; all three endpoints
  admin-only.
- **Vulnerability scanner** — admin-only; host regex-validated; ports
  `int()`-coerced; nmap `--script=` value is built from a hard-coded
  `scan_type` map, not request input.

## Post-audit capability growth — `files` grant (2026-09-11, not a new audit pass)

Three capabilities were added to the jailed game-server browser after this
audit: multi-file **upload**, **delete**, and **rename**. Each is confined to
the same jail (`file_manager._validate_path` + `_jail`) as the original
read/write/download set and gated the same way (admin or `files` grant), but
each also *narrows* the file-type allowlist rather than reusing
`_BROWSE_WRITE_SUFFIXES` as-is:

- `_BROWSE_UPLOAD_SUFFIXES` = `_BROWSE_WRITE_SUFFIXES` minus `.lua`. Editing
  an existing `.lua` (Zomboid's `SandboxVars.lua`) was already accepted as
  F6 above because nothing new lands on disk. Upload, delete, and rename all
  create/remove/relabel a filesystem entry — a bigger step — so all three
  exclude `.lua`: a `files` grantee still cannot introduce or remove a Lua
  file on a Lua-scripting server (Garry's Mod) even though they can still
  edit one that's already there.
- Delete never touches a directory (no recursive delete) — a `files`
  grantee can only remove single files matching the upload allowlist, never
  `Saves/`, `steamapps/`, or the server binary.
- Rename is same-directory only and requires the new name to keep the exact
  same extension as the old one — it cannot be used to move a file into an
  autorun-relevant path or relabel it under a different extension to dodge
  the write/delete suffix checks (which key off the *current* file's
  extension, not a claimed one).

None of this widens what a `files` grant can reach outside a server's own
directory tree — the jail and the grant check are unchanged — only what it
can do to files already inside it.

**Row rendering (2026-09-11 follow-up):** the three file-browser surfaces
(jailed game-server browser, admin file manager) originally embedded each
row's path/name into an inline `onclick`/`oncontextmenu` HTML attribute via
hand-rolled JS-string escaping (only `'` and sometimes `\`/`\n` were escaped).
Since these attributes are themselves double-quoted, a filename containing a
literal `"` was not escaped for that context and could break out of the
attribute — a `files` grantee (or anyone who can place a file inside the
jail, e.g. via upload before this branch guarded extensions) naming a file
`x" onmouseover="...` could inject an arbitrary attribute/handler into an
admin's or another grantee's DOM on next render. Rows now carry path/name/
type/root as `data-*` attributes (escaped via `FileBrowser.escapeAttr` /
`filesEscapeHtml`, which do escape `"`) read back through `.dataset` by a
single delegated listener per surface, instead of being interpolated into
inline event-handler JS at all — removes the injection class and the need
for any hand-written unescape step.

## Follow-ups (not blocking)

1. Relay `rtmp_url`: add an explicit `{rtmp, rtmps}` scheme allowlist to
   `_validate_relay_url`.
2. `redact_service_config`: move from keyword matching to a per-plugin
   sensitive-field allowlist.
3. Per-catalog `allow_lua_write: false` flag for Lua-scripting game servers.
