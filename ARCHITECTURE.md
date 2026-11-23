# Open Relay Portal - Architecture Documentation

## Overview

Open Relay Portal is a privacy-first, self-hosted streaming and community platform. It also acts as an authenticated gateway for the infrastructure around it, and provides:

1. **Unified Services** - Both proxy routes to external backends AND managed server processes (MediaMTX, TURN, etc.)
2. **User Connections** - Personal authenticated access to external resources (SSH, VNC, Proxmox, etc.)
3. **Community Features** - Chat, user management, and collaboration tools

**Public Endpoint:** `https://portal.example.com`

---

## System Architecture

```
                                 Internet
                                     │
                                     ▼
                           ┌─────────────────┐
                           │   Cloudflare    │
                           └────────┬────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                            Open Relay Portal                                      │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │                          Core Services                                   │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐    │  │
│  │  │   Auth   │  │  Router  │  │ Database │  │   Service Manager    │    │  │
│  │  │  (JWT)   │  │          │  │ (SQLite) │  │  (Process Control)   │    │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                          │
│  ┌────────────────────────────────┬┴┬─────────────────────────────────────┐  │
│  │                                │ │                                      │  │
│  │    MANAGED SERVICES            │ │      REMOTE CONNECTIONS              │  │
│  │    (Portal runs these)         │ │      (Portal proxies to these)       │  │
│  │                                │ │                                      │  │
│  │  ┌──────────────────────┐     │ │     ┌──────────────────────┐        │  │
│  │  │  MediaMTX Relay      │     │ │     │  SSH Tunnels         │        │  │
│  │  │  (RTSP/WebRTC/HLS)   │     │ │     │  (asyncssh)          │        │  │
│  │  └──────────────────────┘     │ │     └──────────────────────┘        │  │
│  │  ┌──────────────────────┐     │ │     ┌──────────────────────┐        │  │
│  │  │  TURN/STUN Server    │     │ │     │  VNC Proxy           │        │  │
│  │  │  (WebRTC relay)      │     │ │     │  (noVNC)             │        │  │
│  │  └──────────────────────┘     │ │     └──────────────────────┘        │  │
│  │  ┌──────────────────────┐     │ │     ┌──────────────────────┐        │  │
│  │  │  Local Terminal      │     │ │     │  Proxmox API         │        │  │
│  │  │  (PTY shell)         │     │ │     │  (VM management)     │        │  │
│  │  └──────────────────────┘     │ │     └──────────────────────┘        │  │
│  │                                │ │     ┌──────────────────────┐        │  │
│  │                                │ │     │  HTTP Proxy          │        │  │
│  │                                │ │     │  (Web UIs)           │        │  │
│  │                                │ │     └──────────────────────┘        │  │
│  └────────────────────────────────┴─┴─────────────────────────────────────┘  │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │                          Web Dashboard                                   │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │Dashboard │  │  Admin   │  │ Terminal │  │  VNC     │  │   Chat   │  │  │
│  │  │          │  │  Panel   │  │ Emulator │  │  Viewer  │  │          │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │  Linux PC   │ │  Proxmox    │ │  TrueNAS    │
            │  (SSH/VNC)  │ │  (API/VNC)  │ │  (API/SSH)  │
            └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Key Concepts

### 1. Unified Services Model

Services are stored in a single `services` table with a `service_type` field:

| Aspect | Proxy Services | Managed Services | User Connections |
|--------|----------------|------------------|------------------|
| **service_type** | `proxy` | `managed` | N/A (separate table) |
| **Definition** | Proxy routing to external backend | Server process Portal runs | Personal remote connections |
| **Lifecycle** | Static configuration | Start/stop/restart by Portal | Static configuration |
| **Examples** | "Proxy /ssh to 192.168.1.10:22" | MediaMTX server, TURN server | "My home server SSH" |
| **Storage** | `services` table | `services` table | `user_connections` table |
| **Ownership** | System-wide (admin only) | System-wide (admin only) | Per-user (private) |
| **Process** | No process (just routing) | Runs on Portal server | No process (just routing) |
| **UI Location** | Dashboard > Services (admin) | Dashboard > Services (admin) | Dashboard > My Connections (Quick Add bar) |
| **API** | `/api/services` | `/api/services` + `/start`, `/stop`, `/restart` | `/api/connections` |

**Unified API:**
- `GET /api/services` - List all services (use `?type=proxy` or `?type=managed` to filter)
- `POST /api/services/{id}/start` - Start a managed service
- `POST /api/services/{id}/stop` - Stop a managed service
- `POST /api/services/{id}/restart` - Restart a managed service
- `GET /api/services/{id}/logs` - Get logs for a managed service

### 2. Authentication Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Methods                    │
├─────────────────────────────────────────────────────────────┤
│  1. Session Cookie    - Web dashboard login                 │
│  2. JWT Bearer Token  - API access                          │
│  3. API Key           - Programmatic access (portal_xxx)    │
│  4. Stream Key        - Publish only (live_xxx), no sign-in │
│  5. WebSocket Auth    - Token in query/header               │
└─────────────────────────────────────────────────────────────┘
```

### 3. Role-Based Permissions

```
Permission Hierarchy:
  superadmin (Level 4) ─┬─ All permissions
                        ├─ Manage all users
                        ├─ Delete users
                        ├─ Manage services
                        └─ System configuration

  admin (Level 3) ──────┬─ Manage moderators/users
                        ├─ Reset passwords
                        └─ View all connections

  moderator (Level 2) ──┬─ View users
                        ├─ Chat moderation
                        └─ Limited user management

  user (Level 1) ───────┬─ Own connections only
                        ├─ Chat participation
                        └─ Profile management
```

### 4. Alerts and notification channels

Two modules, no database access and no network of their own:

- `webhook_formats.py` (pure functions) turns one event into the body and headers of one delivery. `generic` is the original signed JSON (HMAC-SHA256); `ntfy`, `gotify`, `discord` and `slack` get a minimal message (title, one-line summary, portal name) built from a fixed catalogue, with payload fields added only for hooks with `include_details` and only from an allow-list. Format credentials (a Gotify token, an ntfy token or login) go into request headers only.
- `alerts.py` decides whether an ops, security or moderation alert may be sent. `server.py` binds the delivery functions at start (`alerts.bind`); until then every emitter does nothing. Each emitter has a cooldown or a transition rule, and all share a global cap of 30 alerts per 10 minutes. Events that a stranger or an ordinary member can set off also have smaller per-kind caps, the global cap keeps a reserve of 10 slots they can never use, and a notice names what was held back. The counters are in memory.

**System hooks** are outgoing webhooks with `kind = 'system'` and no owner, managed by superadmins only (`/api/admin/webhooks`, Admin > Webhooks). Alert events and `webhook.test` go to system hooks only and are never matched by `*`; user hooks never receive them. Destination URLs and format credentials are stored encrypted and are write-only in the API: they are never returned (a generic hook's URL is the one exception). That is a property of the API, not of the database, which an administrator with terminal access can read.

**allow_private** lets a hook reach loopback and private (LAN) addresses for a self-hosted ntfy or Gotify. Link-local, metadata and this portal's own listening ports stay blocked, a plain-http destination must resolve to a non-public address, and only a superadmin in a browser session can switch it on or change the URL or format of such a hook (security event and audit entry `webhook_allow_private`). Delivery runs through the same checked connector as every outbound request, so a rebinding hostname is refused at connect time.

---

## Directory Structure

```
/opt/portal/
├── server.py              # Main aiohttp server (~14,600 lines)
├── database.py            # SQLite async database layer (~5,730 lines)
├── auth.py                # JWT/API key authentication (~467 lines)
├── config.py              # Environment configuration
├── logger.py              # Logging with rotation
├── ssh_keys.py            # SSH key generation/management
├── shodan_integration.py  # Shodan API for recon
├── traffic_metrics.py     # Connection metrics, time series, Chart.js data
├── vulnerability_scanner.py # CVE/port scanning
├── cert_manager.py        # TLS certificate lifecycle (self-signed, Let's Encrypt, custom)
├── setup.py               # Interactive setup wizard
├── system_monitor.py      # Process, systemd service, and network monitoring
├── file_manager.py        # Local filesystem operations (admin)
├── sftp_browser.py        # Remote SFTP file browsing (per-user)
├── hostkeys.py            # SSH host-key pinning (trust on first use) for terminals, SFTP, VOD storage
│
├── plugins/               # Connection plugins
│   ├── __init__.py        # Plugin registry
│   ├── base.py            # PluginBase, PluginInfo, ServiceTarget
│   ├── terminal.py        # Web PTY terminal
│   ├── ssh.py             # SSH over WebSocket
│   ├── vnc.py             # VNC via noVNC
│   ├── spice.py           # SPICE console
│   ├── proxmox.py         # Proxmox VE API
│   ├── github.py          # GitHub integration
│   ├── mediamtx.py        # MediaMTX streaming
│   ├── tcp_tunnel.py      # Generic TCP tunnel
│   ├── secure_tunnel.py   # Encrypted multiplex tunnel
│   ├── vpn_tunnel.py      # VPN bridge
│   └── http_proxy.py      # HTTP reverse proxy
│
├── services/              # Managed service controllers
│   ├── __init__.py        # ServiceManager, registration system
│   ├── base.py            # ManagedService base class, ServiceInfo
│   └── mediamtx.py        # MediaMTX process manager
│
├── static/                # 20 HTML pages, 9 JS modules, 1 CSS file
│   ├── index.html         # Dashboard
│   ├── login.html         # Login page
│   ├── admin.html         # Admin panel
│   ├── browser.html       # Embedded HTTP browser (navigation, address bar, iframe sandbox)
│   ├── chat.html          # Community chat (mobile sidebar toggle)
│   ├── streams.html       # Community streams
│   ├── live.html          # Public live streams (unauthenticated)
│   ├── watch.html         # Stream viewer (HLS playback, mobile chat popout)
│   ├── terminal.html      # Terminal UI
│   ├── vnc.html           # VNC viewer
│   ├── spice.html         # SPICE viewer
│   ├── proxmox.html       # Proxmox dashboard
│   ├── mediamtx.html      # MediaMTX management
│   ├── github.html        # GitHub browser
│   ├── api-docs.html      # Interactive API documentation
│   ├── about.html         # Feature guide & docs (fully public, all features visible)
│   ├── guides.html        # Connection setup guides (75 types)
│   ├── files.html         # File manager (SFTP, admin local in admin panel)
│   ├── sysmon.html        # Redirects to /admin#system
│   ├── unauthorized.html  # Auth error page
│   ├── css/portal.css     # Shared styles (~3,520 lines, 6 responsive breakpoints)
│   ├── uploads/           # User-uploaded content (gitignored)
│   │   └── chat/          # Chat image uploads
│   └── js/
│       ├── portal.js      # Core utilities: Portal.fetch/fetchJSON/postJSON, Portal.toast (stacking), Portal.isAdmin(), Portal.getRoleLabel(), Portal.setButtonLoading(), Portal.flashButtonSuccess(), NotificationBell (dropdown + desktop alerts), Portal.shortcuts, Portal.commandPalette, Portal.welcomeTour, sessionActivity
│       ├── dashboard.js   # Dashboard logic
│       ├── admin.js       # Admin panel
│       ├── user-connections.js # Connection CRUD, edit, type schemas
│       ├── ssh-keys.js    # SSH key management
│       ├── streams.js     # Stream management
│       ├── vods.js        # VOD file manager
│       ├── terminal-keybar.js # Terminal key bar helpers (pure functions)
│       └── terminal.js    # Terminal WebSocket client and key bar
│
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md    # This file
│   ├── API.md             # API reference
│   └── SERVICES_PLAN.md   # Service implementation plan
│
├── certs/                 # SSL certificates
└── portal.db              # SQLite database
```

---

## Database Schema

### Core Tables

```sql
-- Users with role-based permissions
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user',        -- superadmin, admin, moderator, user
    nickname TEXT,
    status TEXT DEFAULT 'online',
    avatar TEXT DEFAULT '{}',
    chat_anonymous INTEGER DEFAULT 0,
    totp_secret TEXT,
    totp_enabled INTEGER DEFAULT 0,
    registration_ip TEXT,            -- IP at registration (rate limit: 1/IP/24h)
    created_at TEXT,
    updated_at TEXT
);

-- User's remote connections (private)
CREATE TABLE user_connections (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,              -- ssh, vnc, rdp (VNC protocol), proxmox, etc.
    host TEXT NOT NULL,
    port INTEGER,
    config TEXT,                     -- JSON plugin config
    ssh_key_id INTEGER,
    icon TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

-- Managed services (system-wide, admin controlled)
CREATE TABLE managed_services (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,              -- mediamtx, turn, etc.
    display_name TEXT,
    description TEXT,
    enabled INTEGER DEFAULT 0,
    status TEXT DEFAULT 'stopped',   -- running, stopped, error
    pid INTEGER,                     -- Process ID when running
    config TEXT DEFAULT '{}',        -- JSON configuration
    port INTEGER,                    -- Primary listening port
    ports TEXT DEFAULT '[]',         -- Additional ports (JSON array)
    binary_path TEXT,                -- Custom binary path
    config_path TEXT,                -- Config file path
    working_dir TEXT,                -- Working directory
    last_health_check TEXT,
    health_status TEXT DEFAULT 'unknown',
    restart_count INTEGER DEFAULT 0,
    last_started_at TEXT,
    last_stopped_at TEXT,
    error_message TEXT,
    icon TEXT DEFAULT 'server',
    created_at TEXT,
    updated_at TEXT
);

-- Service logs for monitoring
CREATE TABLE service_logs (
    id INTEGER PRIMARY KEY,
    service_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    level TEXT DEFAULT 'info',       -- debug, info, warn, error
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES managed_services(id) ON DELETE CASCADE
);

-- Temporary RTMP publish tokens (single-use, short-lived)
CREATE TABLE rtmp_tokens (
    id INTEGER PRIMARY KEY,
    stream_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,        -- SHA-256 hash of rtmp_ prefixed token
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    used_at TEXT,
    created_at TEXT,
    FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- user_streams table also includes:
--   rtmp_enabled INTEGER DEFAULT 0   -- Per-stream toggle for plain RTMP ingress

-- Multi-platform relay destinations (per-stream)
CREATE TABLE stream_relay_destinations (
    id INTEGER PRIMARY KEY,
    stream_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    platform TEXT NOT NULL,          -- twitch, youtube, kick, portal, custom
    name TEXT NOT NULL,
    rtmp_url TEXT NOT NULL,          -- Encrypted (Fernet, machine-bound PBKDF2)
    stream_key TEXT NOT NULL,        -- Encrypted (Fernet, machine-bound PBKDF2)
    enabled INTEGER DEFAULT 1,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (stream_id) REFERENCES user_streams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- VOD remote storage config (per-user SFTP)
CREATE TABLE vod_storage (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'My VOD Storage',
    host TEXT NOT NULL,
    port INTEGER DEFAULT 22,
    username TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'password',
    remote_path TEXT NOT NULL DEFAULT '/home/user/vods',
    config TEXT DEFAULT '{}',              -- JSON: password or private_key
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API keys for programmatic access
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,        -- portal_XX for lookup
    scopes TEXT DEFAULT '*',
    expires_at TEXT,
    revoked INTEGER DEFAULT 0,
    last_used_at TEXT,
    created_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

-- Chat channels
CREATE TABLE chat_channels (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    topic TEXT,
    is_default INTEGER DEFAULT 0,
    created_at TEXT
);

-- Chat messages (encrypted)
CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    message TEXT NOT NULL,           -- Fernet encrypted
    message_type TEXT DEFAULT 'message',
    created_at TEXT,
    anonymous INTEGER DEFAULT 0,    -- Per-message anonymous flag (preserves anonymity in history)
    reply_to INTEGER,              -- References chat_messages(id) for reply threading
    image_url TEXT,                -- URL to uploaded chat image (/static/uploads/chat/...)
    edited_at TEXT,                -- ISO timestamp if message was edited (5-min window)
    is_pinned INTEGER DEFAULT 0,   -- 1 if pinned by a moderator
    pinned_by INTEGER,             -- User ID who pinned it
    pinned_at TEXT,                -- ISO timestamp of pin
    FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE
);

-- Chat reactions (emoji reactions on messages)
CREATE TABLE chat_reactions (
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    created_at TEXT,
    UNIQUE(message_id, user_id, emoji),
    FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE CASCADE
);

-- Unread tracking per channel per user
CREATE TABLE channel_read_positions (
    user_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    last_read_message_id INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT,
    PRIMARY KEY (user_id, channel_id)
);

-- DM conversations (1:1 or group, max 10 participants)
CREATE TABLE dm_conversations (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL DEFAULT '1on1',  -- '1on1' or 'group'
    name TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT, updated_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE dm_participants (
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at TEXT, left_at TEXT, muted INTEGER DEFAULT 0,
    PRIMARY KEY (conversation_id, user_id)
);

-- DM messages (encrypted at rest, same Fernet scheme as chat_messages)
CREATE TABLE dm_messages (
    id INTEGER PRIMARY KEY,
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    message TEXT NOT NULL,        -- Encrypted via encrypt_message()
    message_type TEXT DEFAULT 'message',
    reply_to INTEGER, image_url TEXT,
    reply_preview_username TEXT, reply_preview_text TEXT,
    edited_at TEXT, created_at TEXT
);

-- FTS5 full-text search (contentless indexes alongside encrypted data)
CREATE VIRTUAL TABLE chat_messages_fts USING fts5(message, content='', tokenize='porter unicode61');
CREATE VIRTUAL TABLE dm_messages_fts USING fts5(message, content='', tokenize='porter unicode61');
```

---

## API Reference

### Authentication & Registration

```
POST /login              - Session login (form)
GET  /logout             - End session
POST /api/register       - Register new account (requires invite code)
POST /api/token          - Create JWT token (2FA accounts also send totp_code)
GET  /api/tokens         - List active tokens
POST /api/token/revoke   - Revoke a token
POST /api/api-keys       - Create API key
GET  /api/api-keys       - List API keys
DELETE /api/api-keys/:id - Delete API key
GET  /api/invite-code    - Get daily invite code (admin)
```

### User Management

```
GET  /api/me                    - Current user info
POST /api/me/password           - Change password
PUT  /api/me/status             - Update chat status
PUT  /api/me/nickname           - Update nickname
PUT  /api/me/avatar             - Update avatar
PUT  /api/me/anonymous          - Toggle anonymous mode
GET  /api/users                 - List users (admin)
POST /api/users                 - Create user (admin)
PUT  /api/users/:id/role        - Change user role (admin)
POST /api/users/:id/reset-password - Reset password (admin)
DELETE /api/users/:id           - Delete user (superadmin)
```

### Two-Factor Authentication

```
GET  /api/user/2fa/status     - Check 2FA status
POST /api/user/2fa/setup      - Generate TOTP secret and URI
POST /api/user/2fa/verify     - Verify code and enable 2FA
POST /api/user/2fa/disable    - Disable 2FA (requires password)
```

### SSH Keys

```
POST /api/ssh-keys              - Generate key pair
GET  /api/ssh-keys              - List keys
GET  /api/ssh-keys/:id          - Get key details
DELETE /api/ssh-keys/:id        - Delete key
GET  /api/ssh-keys/authorized   - Get authorized_keys format
GET  /api/ssh-keys/all          - All keys (admin)
```

### User Connections (Personal)

```
GET  /api/connections           - List user's connections
POST /api/connections           - Create connection
GET  /api/connections/:id       - Get connection details
PUT  /api/connections/:id       - Update connection
DELETE /api/connections/:id     - Delete connection
GET  /api/connections/:id/connect - Get connection info + WS URL
GET  /api/connections/types     - Available connection types
```

### Services (Admin) - Unified API

All services (proxy routes and managed processes) use a single API endpoint.

```
GET  /api/services              - List all services (?type=proxy|managed)
POST /api/services              - Create service
GET  /api/services/:id          - Get service details
PUT  /api/services/:id          - Update service
DELETE /api/services/:id        - Delete service
GET  /api/services/types        - Available managed service types
POST /api/services/:id/start    - Start managed service
POST /api/services/:id/stop     - Stop managed service
POST /api/services/:id/restart  - Restart managed service
GET  /api/services/:id/logs     - Get managed service logs
```

### Streaming

Publishing is available via two methods:
- **RTMPS** (port 1936) - Primary method, encrypted, always available: `rtmps://<STREAM_HOSTNAME>:1936/live`
- **RTMP** (port 1935) - Optional plain RTMP ingress using temporary tokens for security; enabled per-stream via `rtmp_enabled` flag

Playback is proxied through the portal: `https://<HOSTNAME>/api/stream/{key}/hls/...`

```
GET  /api/streams               - List user's streams
POST /api/streams               - Create stream config
GET  /api/streams/:id           - Get stream details
PUT  /api/streams/:id           - Update stream
DELETE /api/streams/:id         - Delete stream
GET  /api/streams/public        - List public streams
GET  /api/streams/open          - List currently live public streams
POST /api/streams/:id/thumbnail - Upload custom thumbnail
DELETE /api/streams/:id/thumbnail - Delete custom thumbnail
POST /api/streams/:id/rtmp-token - Generate temporary RTMP publish token
GET  /api/relay-platforms        - List supported relay platforms (Twitch, YouTube, Kick, etc.)
GET  /api/streams/:id/relays    - List relay destinations (owner only)
POST /api/streams/:id/relays    - Add relay destination (owner only)
PUT  /api/streams/:id/relays/:rid - Update relay destination
DELETE /api/streams/:id/relays/:rid - Delete relay destination
GET  /api/stream/:key/thumbnail - Dynamic stream thumbnail (ffmpeg; one capture per stream, two at once, 503 + Retry-After when busy or no frame can be made)
GET  /api/stream/:key/hls/...   - HLS playback proxy
POST /api/stream/event          - MediaMTX webhook (live/encoding/offline)
```

#### MediaMTX Configuration

The MediaMTX managed service configuration is generated dynamically by Portal. Key streaming settings:

- **RTMPS** (port 1936) - Always enabled with TLS encryption (`rtmpEncryption: strict`)
- **RTMP** (port 1935) - Conditionally enabled based on `rtmp_plain_enabled` config; when enabled, `rtmpEncryption: optional` is set to allow both plain and encrypted connections on the RTMPS port
- **Publish auth** - All publish requests validated via MediaMTX external auth webhook back to Portal
- **Playback** - Read/playback auth handled by Portal's HLS proxy, not MediaMTX
- **RTMP path mapping** - When publishing via `rtmp_` token, MediaMTX creates the path using the token instead of the `live_` key (i.e., `live/rtmp_xxx` not `live/live_xxx`). Portal maintains an internal mapping (`_rtmp_stream_paths`) so HLS proxy, thumbnails, and VOD recording resolve to the correct MediaMTX path.
- **Multi-platform relay** - Streams can be simultaneously relayed to external platforms (Twitch, YouTube, Kick, other Portal instances, or custom RTMP destinations). Relay processes use `ffmpeg -c copy -f flv` per destination. Relays start automatically on publish and stop on disconnect/shutdown. Max 10 relay destinations per stream. Relay credentials (RTMP URL + stream key) are encrypted at rest.

#### Go-live announcement

When the publish hook sees a stream that was not live, the state frame to the stream's chat and the activity entry always go out; the announcement (in-portal notification and the `stream.live` webhook) goes out only if `db.claim_golive` wins. That is one conditional `UPDATE` on `user_streams.golive_announced_at` (epoch seconds, kept across restarts), called under `_stream_state_lock`, with a fixed cooldown of 10 minutes (`_GOLIVE_COOLDOWN_SECONDS`). `_announce_go_live` then reads the stream afresh (the `rtmp_` token branch builds a thin stream dict), builds the payload in `_golive_payload` (streamer, title, watch URL from `_public_base_url`, the message from `_render_golive_message`), notifies the members for whom `_stream_read_allowed` is true (never the owner) and fires `stream.live`. `_stream_event_hook_allowed` keeps the events of a stream that is not public from every hook that is not a system hook; `_third_party_may_see` still keeps them from non-generic hooks. The announcement never carries a stream key, a `pub_` key or an RTMP address.

The claim wins in the hook, under the lock; the rest runs in a background task (`_spawn_go_live`, named `golive-fanout`, held in `_golive_tasks`) so the hook answers at once. `_announce_go_live` fires `stream.live`, then `_post_go_live_cards`, then `_notify_go_live`, each in its own try block. **Audience:** `user_streams.golive_audience` is `followers` (rows of `stream_follow`, read with `db.get_follower_audience`, which only the fan-out calls) or `everyone` (all users); the column default is `everyone` for rows that existed before 1.16.0 and `db.create_user_stream` inserts `followers`. `_notify_go_live` re-reads the stream before every batch of `_GOLIVE_BATCH` (100), keeps only users for whom `_stream_read_allowed` is true at that moment (never the owner), inserts the batch with `db.create_notifications_bulk` (one commit) and pushes to open sockets with `_push_notification_frame`. **Follows** (`stream_follow`, `PUT|DELETE /api/streams/{id}/follow`, `GET /api/me/follows`): the decision is `_stream_read_allowed`, one 404 for unknown and unviewable, a stream key is not a credential, no route returns followers, the owner gets `follower_count`. A visibility change in either direction (`is_public` flipped, in `http_update_user_stream`) clears all of the stream's follows (`db.remove_stream_follows`); an edit that does not change it keeps them. **Cards:** `stream_cards(message_id, stream_id, channel_id, streamer, title)` (streamer and title encrypted like the message) next to a `chat_messages` row of type `stream_card` (the text is the plain fallback, authored by the owner's account and not editable: `chat_message_editable`); `_enrich_channel_messages` attaches `card`. A card goes to the stream's own chat when the stream is public or that chat is closed to ordinary members (`_channel_open_to_members` is `_can_read_channel` for an unrelated member id), and for a public stream also to the setting `stream_announce_channel_id`, re-checked with the same function at every go-live. `_remove_stream_cards` deletes a stream's cards from channels members can read when it turns private (the owner's closed chat keeps its card) and from everywhere when it is deleted, and `_post_go_live_cards` re-reads `is_public` after writing, so a switch to private during the fan-out removes the cards just written.

**Per-owner broadcast cooldown.** Besides the per-stream claim, a second cooldown is stored per owner (`golive_owner_cooldown`, claimed by `db.claim_golive_owner`, same 10 minutes, not tied to a stream, so it survives the stream's deletion and a restart). `_announce_go_live` takes this slot only for a public stream that wants to reach members at large: its audience is `everyone`, or an announce channel is set (so a `followers` stream with an announce channel uses the owner's slot too, because its card goes to the shared channel). While the slot is taken, or when claiming it fails (it fails closed), `broad` is false: `_post_go_live_cards` posts only the card in the stream's own chat and `_notify_go_live` tells only the followers. The webhook and the per-stream claim are unaffected.

**A stream key authorises publishing only.** A stream key (`live_`, sent as `X-Stream-Key` or `Authorization: Stream-Key`) is read from the body or URL of the publish side only: the MediaMTX publish hook, RTMPS, WHIP and the stream event calls. `authenticate_request` takes no stream key on any route and has no `allow_stream_key` switch; a request that offers one and nothing that signs in is answered `403` (`unauthorized_response`, via `_stream_key_refusal`), not `401`. A token whose id still starts with `streamkey-` (none is issued any more) has the role `user` in `get_user_role_from_token` and no full scope in `has_full_user_scope`. The routes under `/api/streams`, `/api/me/follows` and `/api/vods` need a browser session or an all-scope (`*`) token or API key; an ordinary member scripts them with a token from `/api/token`, because their API keys are always scoped.

### Stream Relay

```
GET  /api/relay-platforms              - List supported relay platforms
GET  /api/streams/:id/relays           - List relay destinations (owner)
POST /api/streams/:id/relays           - Add relay destination (owner)
PUT  /api/streams/:id/relays/:rid      - Update relay destination (owner)
DELETE /api/streams/:id/relays/:rid    - Delete relay destination (owner)
```

### Stream Moderation

```
GET  /api/streams/:id/bans      - List banned users
POST /api/streams/:id/ban       - Ban user from stream chat
DELETE /api/streams/:id/ban/:uid - Unban user
```

### VOD Storage (Personal)

VODs are automatically recorded during live broadcasts as 5-minute MKV chunks (lossless remux via ffmpeg segment muxer). Chunks are continuously uploaded to the user's SFTP storage in an organized directory structure: `{StreamName}/{YYYY-MM-DD}/chunk_NNN.mkv`.

**Stream Lifecycle:** When a stream stops broadcasting, it transitions to an **Encoding** state (`is_live=2`) while ffmpeg finishes writing the current chunk and all remaining chunks are uploaded to SFTP. The stream only goes **Offline** (`is_live=0`) after all VOD data has been fully offloaded. This prevents incomplete VODs caused by premature ffmpeg termination.

| State | `is_live` | Description |
|-------|-----------|-------------|
| Live | `1` | Actively broadcasting |
| Encoding | `2` | Broadcast ended, VOD chunks finalizing and uploading |
| Offline | `0` | All VOD data offloaded, stream fully stopped |

```
GET  /api/vods/storage               - Get storage config
POST /api/vods/storage               - Save storage config
DELETE /api/vods/storage              - Remove storage config
POST /api/vods/storage/test          - Test SFTP connection
GET  /api/vods                       - List MKV files (recursive)
GET  /api/vods/download/{filename}   - Download single VOD file
POST /api/vods/download-archive      - Download multiple files as zip
DELETE /api/vods/{filename}          - Delete VOD file
```

### Chat

```
GET  /api/chat/channels              - List channels (with unread counts)
POST /api/chat/channels              - Create channel
PUT  /api/chat/channels/:id          - Update channel
DELETE /api/chat/channels/:id        - Delete channel
POST /api/chat/channels/:id/clear    - Clear history (superadmin)
POST /api/chat/upload                - Upload chat image
GET  /api/chat/link-preview          - Fetch OpenGraph metadata for URL
GET  /api/chat/thread/:id            - Get reply chain for a message
GET  /api/chat/channels/:id/messages - Older messages / a window around a message (before_id, around_id, limit)
WS   /ws/chat                        - Chat WebSocket (text + voice signaling)
```

Chat features: emoji reactions (toggle per-message), message editing (5-min window), pinned messages (mod/admin), unread tracking (per-channel badges), @mention autocomplete, link previews (OpenGraph), thread expansion (reply chain panel).

### Direct Messages

```
GET  /api/dm/conversations              - List DM conversations (with unread counts)
POST /api/dm/conversations              - Create DM (1:1 or group)
GET  /api/dm/conversations/:id          - Get conversation with participants
GET  /api/dm/conversations/:id/messages - Get messages (cursor pagination)
POST /api/dm/conversations/:id/mute     - Toggle mute
POST /api/dm/conversations/:id/leave    - Leave group DM
POST /api/dm/conversations/:id/participants - Add to group DM (max 10)
```

Private 1:1 and group DMs. All messages encrypted at rest (Fernet). Participant-only access enforced on every endpoint. Full feature parity with channel chat: reactions, replies, editing (5-min window), deletion, typing indicators, unread badges. WebSocket message types prefixed `dm_` (dm_message, dm_typing, dm_react, dm_edit, dm_delete, dm_mark_read, dm_history). Offline users receive persistent notifications.

### Message Search

```
GET  /api/chat/search                   - Full-text search (FTS5)
POST /api/chat/search/rebuild           - Rebuild search index (superadmin)
```

FTS5 full-text search across channels and DMs. Contentless index tables store plaintext alongside encrypted message data. The query is parsed on the server (`chat_search.py`): `from:`, `in:` (both negatable), `has:link|file|image`, `is:pinned`, `before:`/`after:` (YYYY-MM-DD), phrases; operator-only queries are newest first and capped at 200. Also scope, channel_id, conversation_id. Channels are searched only if `_can_read_channel` allows, and results are built with `_enrich_channel_messages` (anonymous authors masked as in history). DM results restricted to user's own conversations. Rate limited: 10 searches/min/user. `offset` is capped at 2000 and the ids must be 1..HISTORY_ID_MAX (400 otherwise). The one-time flag backfill runs each batch as one uninterrupted step on the connection and shares a lock with the rebuild.

### Voice Chat

```
GET  /api/voice/ice-servers          - ICE server config (STUN/TURN)
WS   /ws/chat                        - Voice signaling (piggybacks on chat WS)
```

Voice chat uses WebRTC P2P mesh (2-10 users). Server relays signaling only — no audio processing or storage. Audio encrypted via DTLS-SRTP natively. A dropped chat socket keeps the voice seat for 20 s (`voice_user_reconnecting`, then `voice_user_resumed` or `voice_user_left`); see docs/API.md.

### System Info

```
GET  /api/shells                     - Available shells (admin)
GET  /api/plugins                    - Available plugins with schemas
```

### Public Stats

```
GET  /api/stats/public               - Live streams + online user count
```

Online user count is tracked globally via a ref-counted dict (`_online_users`) that increments on WebSocket connect (both service and chat handlers) and decrements on disconnect. Dashboard polls every 10 seconds.

### Traffic Metrics (Admin)

```
GET  /api/metrics                    - Summary metrics (uptime, connections, bandwidth, users)
GET  /api/metrics/services           - Per-service metrics
GET  /api/metrics/active             - Active connections (WebSocket + chat)
GET  /api/metrics/timeseries         - Time-series data (?hours=1-24, per-minute bandwidth deltas)
GET  /api/metrics/top                - Top services and users (?limit=1-50)
```

The admin panel visualizes time-series data with Chart.js: a dual-axis line chart (connections + active users) and a stacked bar chart (bandwidth sent/received per minute). Time range selectors allow 1H/6H/12H/24H views. Data is recorded every 60 seconds by a background task and retained for 24 hours.

### Server Logs (Admin)

```
GET  /api/logs                       - Recent log entries
GET  /api/logs/files                 - List log files
GET  /api/logs/settings              - Get log settings
PUT  /api/logs/settings              - Update log settings
```

### Shodan Integration (Admin)

```
GET  /api/shodan/info                - API key info and credits
POST /api/shodan/api-key             - Set Shodan API key
GET  /api/shodan/lookup/:ip          - Lookup IP
GET  /api/shodan/search              - Search query
```

### Vulnerability Scanner (Admin)

```
GET  /api/vuln/status                - Scanner status (nmap, NVD)
GET  /api/vuln/scan/:host            - Scan host ports
GET  /api/vuln/scan-service/:id      - Scan a service
GET  /api/vuln/cve/:id               - CVE details
GET  /api/vuln/mitigations/:cve      - Mitigation advice
GET  /api/vuln/known-cves            - All known CVEs
GET  /api/vuln/search                - Search CVEs
POST /api/vuln/nvd-api-key           - Set NVD API key
```

### Certificate Management (Admin)

```
GET  /api/certs/info                 - Certificate details (subject, issuer, SANs, expiry)
POST /api/certs/upload               - Upload custom PEM cert+key
POST /api/certs/self-signed          - Generate self-signed certificate
POST /api/certs/letsencrypt          - Request Let's Encrypt certificate
POST /api/certs/apply                - Restart server to apply new certs
```

### Server Settings (Admin)

```
GET  /api/settings/hostname          - Get hostname and port
PUT  /api/settings/hostname          - Update hostname
```

### System Monitor (Admin)

```
GET  /api/sysmon/processes           - List processes (sort, limit)
GET  /api/sysmon/processes/:pid      - Process details
POST /api/sysmon/processes/:pid/kill - Kill process (signal)
GET  /api/sysmon/services            - List systemd services (filter)
GET  /api/sysmon/services/:name      - Service status
GET  /api/sysmon/services/:name/logs - Service journal logs (lines)
POST /api/sysmon/services/:name/control - Control service (action)
GET  /api/sysmon/network             - Network interfaces
GET  /api/sysmon/ports               - Listening ports
```

### File Manager (Admin)

```
GET    /api/files/list               - List directory (?path=)
GET    /api/files/info               - File stat (?path=)
GET    /api/files/read               - Read text file (?path=)
GET    /api/files/download           - Download file (?path=)
POST   /api/files/upload             - Upload file (multipart)
POST   /api/files/write              - Write text file (JSON)
POST   /api/files/mkdir              - Create directory (JSON)
POST   /api/files/rename             - Rename/move (JSON)
DELETE /api/files/delete             - Delete file/directory (?path=)
```

Server file management is also integrated into the Admin Panel as a "Files" tab for quick access without leaving the admin interface.

### Data Retention (Admin)

```
GET  /api/admin/retention            - Get retention config (Admin+)
PUT  /api/admin/retention            - Update retention config (Superadmin)
POST /api/admin/retention/run        - Run cleanup now (Superadmin)
```

Configurable retention policies:
- **retention_chat_days** (default 7) — Channel message retention
- **retention_dm_days** (default 30) — DM message retention
- **retention_notifications_days** (default 30) — Notification retention
- **retention_activity_max** (default 500) — Max activity log entries
- **retention_service_logs_max** (default 1000) — Max service log entries per service
- **Chat upload files**: Deleting a message also deletes its uploaded image or attachment file, after the deletion is committed, unless another row still names the same file: in a message image or attachment column (channel, DM or pinned), in decrypted message or DM text or reply preview, in a decrypted poll question or option, or in a plain-text user status message, channel topic or description, or stream name or description. Reading all that text happens once per cleanup run in a worker thread on a read-only SQLite connection (never on the event loop), not once per batch of 500. The last check and the unlinks then run together in one `BEGIN IMMEDIATE` transaction for exactly the candidate files, re-checking the plain columns and re-reading every row written or edited since the scan, so a row that names a file in the meantime keeps it. If any message cannot be decrypted, or the lock or check cannot complete, no file is removed; the manual cleanup result then carries `chat_files_skipped` (purges) or `chat_orphan_sweep.skipped` and the admin page shows it. Logged webhook payloads are not counted. This applies to retention, DM retention, clearing a channel (including the clear at the end of a stream) and deleting a single message. Files of messages removed some other way (a deleted channel, user or DM conversation) stay on disk and are only reported by the orphan sweep below. A daily orphan sweep looks at `static/uploads/chat` only: plain generated file names, regular files (links and folders are never followed or touched), older than 24 hours, that no row names as above. In 1.12.0 it only reports: the log shows the count, bytes and up to 20 names it would delete, and the manual run returns them as `chat_orphan_sweep`. Deletion is off until the setting `chat_orphan_sweep_delete` is `true`; it is not in the retention API or the admin UI.
- **cleanup_interval_hours** (default 6) — Auto-cleanup interval
- **auto_vacuum** (default true) — VACUUM database after cleanup

Setting any value to `0` disables cleanup for that category. A unified background task runs on the configured interval, cleaning up: old chat messages, DM messages, notifications, activity log entries, expired JWT tokens, expired API keys, and service logs. The `/run` endpoint triggers an immediate cleanup cycle.

### SFTP Browser (Per-User)

```
GET    /api/sftp/:conn_id/list       - List remote directory (?path=)
GET    /api/sftp/:conn_id/read       - Read remote text file (?path=)
GET    /api/sftp/:conn_id/download   - Download remote file (?path=)
POST   /api/sftp/:conn_id/upload     - Upload to remote (multipart)
POST   /api/sftp/:conn_id/write      - Write remote text file (JSON)
POST   /api/sftp/:conn_id/mkdir      - Create remote directory (JSON)
POST   /api/sftp/:conn_id/rename     - Rename/move remote path (JSON)
DELETE /api/sftp/:conn_id/delete     - Delete remote path (?path=)
```

### Notifications

```
GET  /api/notifications          - List notifications (?unread=1 for unread only, &limit=N)
POST /api/notifications/:id/read - Mark single notification as read
POST /api/notifications/read-all - Mark all notifications as read
```

Notifications are created server-side (e.g., stream goes live, DM received while offline) and pushed in real time over the chat WebSocket as `{"type": "notification", "notification": {...}}`. The `NotificationBell` frontend module (in `portal.js`) handles the full lifecycle:

- **Bell icon** injected into the navbar, with a live unread badge (polled every 30s, updated instantly on WS push)
- **Dropdown** shows up to 20 unread notifications; click to mark read and navigate (e.g., opens `/watch/:key` for stream-live events)
- **Desktop alerts** — uses the browser `Notification` API. Users enable via an "Enable alerts" button in the dropdown header. Only fires when the page is hidden/unfocused (toast covers the foreground case). Clicking a desktop notification focuses the tab and navigates to the relevant resource.
- **Toast fallback** — `Portal.toast()` always fires on push, regardless of desktop permission state

### WebSocket Endpoints

```
WS /ws/chat                     - Chat real-time + voice signaling
WS /ws/terminal/local           - Local terminal (admin, ?shell= for shell selection)
WS /ws/terminal/:id             - Terminal session (falls back to user-connection if no service)
WS /ws/vnc/:id                  - VNC connection
WS /ws/spice/:id                - SPICE connection
WS /ws/user-connection/:id      - User connection relay (?shell= override for SSH)
WS /ws/{path}                   - Service relay (catch-all)
```

### Web Pages

```
GET /                    - Redirect to /dashboard
GET /dashboard           - Main dashboard
GET /login               - Login page
GET /admin               - Admin panel (metrics charts, managed services, security)
GET /chat                - Community chat
GET /streams             - Community streams
GET /terminal            - Terminal UI
GET /vnc                 - VNC viewer
GET /spice               - SPICE viewer
GET /proxmox             - Proxmox dashboard
GET /watch/:id           - Stream viewer (HLS, picture-in-picture); ?chat=only = pop-out chat window (no player, same access checks)
GET /api-docs            - Interactive API documentation
GET /about               - About page (feature guide)
GET /files               - File manager (admin local + user SFTP)
GET /sysmon              - System monitor (admin only)
GET /live                - Public live streams (unauthenticated)
```

---

## Plugin System

### Plugin Interface

```python
class PluginBase:
    """Base class for connection plugins."""

    @classmethod
    def get_info(cls) -> PluginInfo:
        """Return plugin metadata."""

    async def handle_websocket(
        self,
        ws: WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle WebSocket connection to target."""

    async def health_check(self, target: ServiceTarget) -> bool:
        """Check if target is reachable."""

    def validate_config(self, config: dict) -> bool:
        """Validate plugin configuration."""
```

### Available Plugins

| Plugin | Description | Default Port |
|--------|-------------|--------------|
| terminal | Web PTY terminal (DA1/DA2/DSR compat) | - |
| ssh | SSH over WebSocket (xterm.js-native DA1/DA2/DSR) | 22 |
| vnc | VNC via noVNC | 5900 |
| spice | SPICE console | 5930 |
| proxmox | Proxmox VE API | 8006 |
| github | GitHub integration | 443 |
| mediamtx | Media streaming | 8554 |
| tcp_tunnel | Generic TCP | - |
| secure_tunnel | Encrypted tunnel | - |
| vpn_tunnel | VPN bridge | - |
| http_proxy | HTTP reverse proxy | 80 |

---

## Security Model

### Request Flow

```
Client Request
     │
     ▼
┌──────────────────┐
│ Security Headers │ ─── HSTS, X-Frame-Options, Server suppression
│   (middleware)    │     Applied to ALL responses (incl. redirects/errors)
└───────┬──────────┘
        │
        ▼
┌────────────────┐
│ Rate Limiting  │ ─── Too many requests? → 429 Too Many Requests
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ Authentication │ ─── No valid token? → 401 Unauthorized
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ Authorization  │ ─── Insufficient role? → 403 Forbidden
└───────┬────────┘
        │
        ▼
┌────────────────┐
│Input Validation│ ─── Invalid params? → 400 Bad Request
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ Localhost Check│ ─── User connection to localhost? → 403 Blocked
└───────┬────────┘
        │
        ▼
    Handler
```

### Security Features

Open Relay Portal is designed with privacy and security as core principles:

1. **Password Security** - Argon2id hashing with secure defaults
2. **JWT Tokens** - Short-lived, scoped access tokens
3. **API Keys** - Prefix-based lookup, hashed storage
4. **2FA Support** - TOTP with encrypted backup codes
5. **Rate Limiting** - Per-IP request throttling, 1 registration per IP per 24 hours
6. **Localhost Blocking** - User connections cannot target localhost
7. **Chat Encryption** - Messages encrypted at rest (Fernet)
8. **Config Encryption** - Connection, service, and VOD configs encrypted at rest (Fernet, `enc:` prefix, separate PBKDF2 key from chat)
9. **Stream Key Encryption** - Stream keys encrypted at rest (Fernet); SHA-256 hashes stored for indexed lookups
10. **API Credential Redaction** - GET endpoints never return passwords/keys; replaced with `has_<field>` flags
11. **HTTPS/WSS Only** - All traffic encrypted via TLS, HSTS with preload
12. **Security Headers** - Applied to all response types (including redirects and errors) via middleware; server version suppressed
13. **Input Validation** - All user-supplied `int()` and `json.loads()` conversions protected with try/except; path params, query params, WebSocket fields, and database configs all guarded
14. **Shell Whitelist** - SSH and terminal shell overrides validated against `ALLOWED_SHELLS` constant
15. **Stream Auth** - Default-deny for unmatched actions; read/playback auth handled by Portal's HLS proxy
16. **No Session Recording** - Privacy-first design, no session logging
17. **WebSocket Security** - All WebSocket connections use WSS (TLS encrypted)
18. **Authenticated Uploads** - Chat images/uploads require authentication (route intercepted before static file serving)
19. **Service Log PII Redaction** - Managed service logs auto-redact IPs, stream keys, passwords, tokens, and secrets
20. **Stream Hash Redaction** - Internal `stream_key_hash` and `public_key_hash` stripped from all API responses (open, public, non-owner individual stream endpoints)
21. **Watch Page Auth Expiry** - Expired sessions redirect to login instead of silently polling with 401s; API calls send `Accept: application/json` for proper error responses
22. **Voice Chat Security** - WebRTC DTLS-SRTP encryption for all audio; `Permissions-Policy: microphone=(self)` restricts mic access to same origin; voice state is ephemeral (in-memory only, no database persistence); multi-tab voice rejection (a voice entry belongs to its socket; a dropped socket is held 20 s and resumed only by the same account with the per-join token; revoked sessions end the call at once); speaking broadcasts rate-limited (1 per 100ms); signaling validates target user presence before forwarding
23. **RTMP Token Security** - Plain RTMP publish uses temporary `rtmp_` prefixed tokens; tokens are SHA-256 hashed in the database; single-use with a configurable grace period for reconnects; per-stream toggle (`rtmp_enabled`) prevents unauthorized plain RTMP usage
24. **Certificate Management** - Admin-only cert operations (upload, generation, Let's Encrypt); private keys never exposed via API; cert/key pair validation before activation; file permissions 0o600 on private keys
25. **File Manager Security** - Path traversal prevention via `Path.resolve()` + root check; blocked files list (`.env`, credentials); symlinks resolved and checked; configurable root directory; upload size limits enforced server-side
26. **SFTP Browser Security** - Per-user connection ownership enforced on every request; only SSH/SFTP connection types eligible; SFTP connections are ephemeral (opened per-request, closed after); no path traversal possible (remote filesystem)
27. **System Monitor Safety** - Process kill refuses PID 1, kernel threads, and portal process; systemd service control limited to start/stop/restart/enable/disable (no mask/daemon-reload); all subprocess calls use list args (no shell=True); service names validated with regex

---

## Frontend Responsiveness

The portal uses a mobile-first enhancement strategy with progressive breakpoints:

| Breakpoint | Target | Key Changes |
|-----------|--------|-------------|
| `pointer: coarse` | Touch devices | 44px min touch targets, 16px form font (prevents iOS zoom), tap highlight |
| `900px` | Tablets | Stream viewer stacks, chat sidebars become overlay panels |
| `768px` | Small tablets | Dashboard stacks, hamburger nav, sidebar below content, modals resize |
| `600px` | Large phones | Form rows stack, grids single-column, VOD metadata hidden |
| `480px` | Phones | Compact cards/modals/navbar, log pre-wrap |
| `360px` | Small phones | Stats single-column, tabs wrap, brand text hidden (icon only) |

Additional mobile features:
- **Chat mobile sidebar**: Channels/Users toggle buttons appear at <900px with overlay dismiss
- **Notification dropdown**: Responsive width `min(320px, calc(100vw - 1rem))`
- **Table scroll**: `.table-responsive` wrapper and `overflow-x: auto` on docs content
- **Z-index stacking**: Modals (10001) > Notification dropdown (10002) > Session banner (10000)

---

## Configuration

### Environment Variables

```bash
# Server
PORTAL_HOST=0.0.0.0
PORTAL_PORT=443
PORTAL_DOMAIN=portal.example.com

# Security
JWT_SECRET=<random-secret>
INVITE_CODE_SEED=<random-seed>

# Database
DATABASE_PATH=/opt/portal/portal.db

# SSL
SSL_CERT=/path/to/cert.pem
SSL_KEY=/path/to/key.pem

# Optional integrations
SHODAN_API_KEY=<key>
NVD_API_KEY=<key>

# Plain RTMP ingress (optional)
RTMP_PLAIN_ENABLED=false          # Enable plain RTMP ingress (default: false)
RTMP_PLAIN_PORT=1935              # Plain RTMP port (default: 1935)
RTMP_TOKEN_EXPIRY_MINUTES=15      # Token expiry time in minutes (default: 15)
RTMP_TOKEN_GRACE_SECONDS=30       # Grace period for reconnects (default: 30)

# Certificate Management
CERT_METHOD=                      # letsencrypt, selfsigned, or custom
CERT_EMAIL=                       # Email for Let's Encrypt renewal notifications

# File Manager
FILE_MANAGER_ROOT=/               # Root directory for admin file browser
FILE_MANAGER_MAX_UPLOAD_MB=100    # Max upload size in MB
```

---

## Deployment

### Setup Wizard

The fastest way to deploy from a fresh clone:

```bash
git clone https://github.com/dustinm16/portal.git
cd portal
sudo python3 server.py setup
```

The wizard runs **before dependencies are installed** (early argv intercept bypasses third-party imports). It handles:
1. Virtual environment creation and `pip install -r requirements.txt`
2. Auto-generates a self-signed TLS certificate on fresh installs (openssl or Python cryptography)
3. Hostname, port, and optional stream hostname configuration
4. JWT secret generation and `.env` file creation
5. Database initialization and admin user creation
6. Systemd service file generation, installation, and startup

On reconfiguration, existing settings are detected and preserved by default. The wizard validates the final configuration (cert files exist, key permissions, JWT secret set) before finishing.

Port 443 requires root — the wizard and `serve` command both need `sudo`. Alternatively, set `PORT=8443` in `.env` to avoid root.

### Let's Encrypt

The setup wizard includes Let's Encrypt with pre-flight checks:
- Verifies `certbot` is installed
- Checks port 80 is available for HTTP-01 challenge
- Validates hostname is a public domain (not localhost/IP)
- Falls back to self-signed if issuance fails

Switch from self-signed to Let's Encrypt at any time by re-running `sudo python3 server.py setup` or via the Admin Panel > Settings > Certificate Management.

### Systemd Service

The setup wizard auto-generates a service file with correct paths. Manual template:

```ini
[Unit]
Description=Open Relay Portal
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/portal
ExecStart=/path/to/portal/venv/bin/python server.py serve
Restart=always
RestartSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Commands

```bash
# Setup wizard (works on fresh clone, no venv needed)
sudo python3 server.py setup

# Initialize admin user (if not using setup wizard)
sudo venv/bin/python server.py init

# Start server directly (port 443 requires root)
sudo venv/bin/python server.py serve

# Systemd service management (after setup installs the service)
sudo systemctl start portal
sudo systemctl stop portal
sudo systemctl restart portal

# View logs
sudo journalctl -u portal -f

# Check status
sudo systemctl status portal
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "page took too long to respond" | TLS cert missing or server not running | `sudo journalctl -u portal -n 50` — check for SSL errors |
| `ModuleNotFoundError: asyncssh` | Running `serve`/`init` without venv | `source venv/bin/activate` first, or use `sudo venv/bin/python server.py serve` |
| `PermissionError: port 443` | Not running as root | `sudo python server.py serve` or set `PORT=8443` in `.env` |
| `unable to open database file` | Database directory doesn't exist | Fixed automatically — `db.connect()` creates parent dirs |
| Browser security warning | Self-signed certificate | Click "Advanced" > "Proceed", or switch to Let's Encrypt |
