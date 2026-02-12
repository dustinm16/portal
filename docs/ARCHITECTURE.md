# Open Relay Portal - Architecture Documentation

## Overview

Open Relay Portal is a secure, authenticated gateway for home infrastructure that provides:

1. **Unified Services** - Both proxy routes to external backends AND managed server processes (MediaMTX, TURN, etc.)
2. **User Connections** - Personal authenticated access to external resources (SSH, VNC, Proxmox, etc.)
3. **Community Features** - Chat, user management, and collaboration tools

**Public Endpoint:** `https://portal.example.com`

### Codebase Statistics

| Category | Files | Lines |
|----------|------:|------:|
| Python (core) | 14 | 21,517 |
| Python (plugins) | 13 | 4,376 |
| Python (services) | 3 | 1,291 |
| **Python Total** | **30** | **27,184** |
| HTML | 19 | 27,457 |
| JavaScript | 9 | 7,231 |
| CSS | 1 | 3,476 |
| **All Code Total** | **59** | **65,348** |

- **217 HTTP routes** (118 GET, 67 POST, 14 PUT, 17 DELETE, 1 PATCH)
- **28 WebSocket message types** (13 chat, 9 DM, 6 voice)
- **75 connection types** across 17 categories
- **28 documented security features**

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
│  │  │  TURN/STUN Server    │     │ │     │  VNC/RDP Proxy       │        │  │
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
│  4. Stream Key        - Publish (live_xxx) / View (pub_xxx) │
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

---

## Directory Structure

```
/opt/portal/
├── server.py              # Main aiohttp server (~11,280 lines, 217 routes)
├── database.py            # SQLite async database layer (~4,255 lines)
├── auth.py                # JWT/API key authentication (~466 lines)
├── config.py              # Environment configuration (~154 lines)
├── logger.py              # Logging with rotation (~281 lines)
├── ssh_keys.py            # SSH key generation/management (~261 lines)
├── shodan_integration.py  # Shodan API for recon (~307 lines)
├── traffic_metrics.py     # Connection metrics, time series, Chart.js data (~400 lines)
├── vulnerability_scanner.py # CVE/port scanning (~1,525 lines)
├── cert_manager.py        # TLS certificate lifecycle (~492 lines)
├── setup.py               # Interactive setup wizard + MediaMTX installer (~1,265 lines)
├── system_monitor.py      # Process, systemd service, and network monitoring (~368 lines)
├── file_manager.py        # Local filesystem operations (admin) (~279 lines)
├── sftp_browser.py        # Remote SFTP file browsing (per-user) (~183 lines)
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
├── static/                # 19 HTML pages, 9 JS modules, 1 CSS file (~38,164 lines frontend)
│   ├── index.html         # Dashboard
│   ├── login.html         # Login page
│   ├── admin.html         # Admin panel
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
│   ├── about.html         # Feature guide & docs
│   ├── guides.html        # Connection setup guides (75 types)
│   ├── files.html         # File manager (SFTP, admin local in admin panel)
│   ├── sysmon.html        # Redirects to /admin#system
│   ├── unauthorized.html  # Auth error page
│   ├── css/portal.css     # Shared styles (~3,476 lines, 6 responsive breakpoints)
│   ├── uploads/           # User-uploaded content (gitignored)
│   │   └── chat/          # Chat image uploads
│   └── js/
│       ├── portal.js      # Core utilities, Portal.isAdmin(), Portal.getRoleLabel()
│       ├── dashboard.js   # Dashboard logic
│       ├── admin.js       # Admin panel
│       ├── user-connections.js # Connection CRUD, edit, type schemas
│       ├── ssh-keys.js    # SSH key management
│       ├── streams.js     # Stream management
│       ├── vods.js        # VOD file manager
│       ├── voice.js       # WebRTC voice chat (VAD/PTT)
│       └── terminal.js    # Terminal WebSocket client
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
    type TEXT NOT NULL,              -- ssh, vnc, rdp, proxmox, etc.
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

-- Invite codes (3 types: daily, single_use, timed)
CREATE TABLE invite_codes (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL DEFAULT 'daily',  -- daily, single_use, timed
    label TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT,
    expires_at TEXT,
    max_uses INTEGER,
    use_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

-- Notifications (persistent, pushed via WebSocket)
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    data TEXT DEFAULT '{}',
    is_read INTEGER DEFAULT 0,
    created_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- App settings (key-value, used for data retention config, encryption version, etc.)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

---

## API Reference

### Authentication & Registration

```
POST /login              - Session login (form)
GET  /logout             - End session
POST /api/register       - Register new account (requires invite code)
POST /api/token          - Create JWT token
GET  /api/tokens         - List active tokens
POST /api/token/revoke   - Revoke a token
POST /api/api-keys       - Create API key
GET  /api/api-keys       - List API keys
DELETE /api/api-keys/:id - Delete API key
```

### Invite Codes (Admin)

Three types of invite codes for registration: **daily** (auto-cycles every 24h), **single-use** (one registration, then invalidated), and **timed** (valid for a configurable duration).

```
GET    /api/invite-code                       - List all invite codes (admin)
POST   /api/admin/invite-codes                - Create invite code (admin)
DELETE /api/admin/invite-codes/:id            - Deactivate code (admin)
GET    /api/admin/invite-codes/:id/registrations - Users who registered with code (admin)
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
GET  /api/2fa/status     - Check 2FA status
POST /api/2fa/setup      - Generate TOTP secret and URI
POST /api/2fa/verify     - Verify code and enable 2FA
POST /api/2fa/disable    - Disable 2FA (requires password)
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
GET  /api/stream/:key/thumbnail - Dynamic stream thumbnail (ffmpeg)
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

FTS5 full-text search across channels and DMs. Contentless index tables store plaintext alongside encrypted message data. Filters: scope (all/channels/dms), from (username), has (image), before/after (date), channel_id, conversation_id. DM results restricted to user's own conversations. Rate limited: 10 searches/min/user.

### Voice Chat

```
GET  /api/voice/ice-servers          - ICE server config (STUN/TURN)
WS   /ws/chat                        - Voice signaling (piggybacks on chat WS)
```

Voice chat uses WebRTC P2P mesh (2-10 users). Server relays signaling only — no audio processing or storage. Audio encrypted via DTLS-SRTP natively.

### System Info

```
GET  /api/shells                     - Available shells (admin)
GET  /api/plugins                    - Available plugins with schemas
```

### Notifications

```
GET  /api/notifications              - List notifications (paginated)
POST /api/notifications/{id}/read    - Mark notification as read
POST /api/notifications/read-all     - Mark all as read
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
GET /watch/:id           - Stream viewer (HLS)
GET /api-docs            - Interactive API documentation
GET /about               - About page (feature guide)
GET /files               - File manager (admin local + user SFTP)
GET /sysmon              - System monitor (redirects to /admin#system)
GET /guides              - Connection setup guides (75 types)
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
8. **Config Encryption** - Connection, service, and VOD configs encrypted at rest (Fernet, `enc:` prefix, separate PBKDF2 key from chat); keys bound to machine hardware
9. **Stream Key Encryption** - Stream keys encrypted at rest (Fernet); SHA-256 hashes stored for indexed lookups; decryption keys machine-bound
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
22. **Voice Chat Security** - WebRTC DTLS-SRTP encryption for all audio; `Permissions-Policy: microphone=(self)` restricts mic access to same origin; voice state is ephemeral (in-memory only, no database persistence); multi-tab voice rejection; speaking broadcasts rate-limited (1 per 100ms); signaling validates target user presence before forwarding
23. **RTMP Token Security** - Plain RTMP publish uses temporary `rtmp_` prefixed tokens; tokens are SHA-256 hashed in the database; single-use with a configurable grace period for reconnects; per-stream toggle (`rtmp_enabled`) prevents unauthorized plain RTMP usage
24. **Certificate Management** - Admin-only cert operations (upload, generation, Let's Encrypt); private keys never exposed via API; cert/key pair validation before activation; file permissions 0o600 on private keys
25. **File Manager Security** - Path traversal prevention via `Path.resolve()` + root check; blocked files list (`.env`, credentials); symlinks resolved and checked; configurable root directory; upload size limits enforced server-side
26. **SFTP Browser Security** - Per-user connection ownership enforced on every request; only SSH/SFTP connection types eligible; SFTP connections are ephemeral (opened per-request, closed after); no path traversal possible (remote filesystem)
27. **System Monitor Safety** - Process kill refuses PID 1, kernel threads, and portal process; systemd service control limited to start/stop/restart/enable/disable (no mask/daemon-reload); all subprocess calls use list args (no shell=True); service names validated with regex
28. **Machine-Bound Encryption** - Encryption keys are derived from `JWT_SECRET` + a machine-specific salt (SHA-256 of `/etc/machine-id` + random bytes). The salt file (`.encryption_salt`) is auto-generated on first run, chmod 600, and gitignored. Even with the same `.env`, a different machine produces different keys — cloning the repo cannot decrypt existing data. One-time migration re-encrypts all data on upgrade.

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
- **Chat mobile sidebar**: Channels/Users toggle buttons appear at <900px with overlay dismiss (max-width: 80vw)
- **Chat virtual keyboard**: `visualViewport` API resizes chat container when keyboard opens; `interactive-widget=resizes-content` viewport meta; input auto-scrolls into view on focus
- **Chat dynamic navbar offset**: JS measures actual navbar height on load/resize instead of hardcoded `70px`; sidebar overlay `top` matches measured height
- **Chat mobile input**: Send button icon-only on mobile, reduced padding, 480px breakpoint for extra-tight layouts
- **Notification dropdown**: Responsive width `min(320px, calc(100vw - 1rem))`
- **Table scroll**: `.table-responsive` wrapper and `overflow-x: auto` on docs content
- **Dynamic viewport height**: Chat uses `100dvh` with `100vh` fallback for correct height on mobile browsers
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
1. Hostname, port, and optional stream hostname configuration
2. Auto-generates a self-signed TLS certificate on fresh installs (openssl or Python cryptography)
3. JWT secret generation and `.env` file creation (chmod 600)
4. Virtual environment creation and `pip install -r requirements.txt`
5. **Downloads and installs MediaMTX** streaming server (Linux amd64)
6. Database initialization and admin user creation
7. Systemd service file generation, installation, and startup

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

The setup wizard auto-generates a service file with correct paths. A template is also provided at `portal.service.example`. Manual setup:

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
# Setup wizard (works on fresh clone, no venv needed, downloads MediaMTX)
sudo python3 server.py setup

# Initialize admin user (if not using setup wizard)
sudo venv/bin/python server.py init

# Start server directly (port 443 requires root)
sudo venv/bin/python server.py serve

# Install/update MediaMTX streaming server
sudo python server.py install-mediamtx

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
