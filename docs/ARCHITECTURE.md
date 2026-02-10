# Open Relay Portal - Architecture Documentation

## Overview

Open Relay Portal is a secure, authenticated gateway for home infrastructure that provides:

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
| **UI Location** | Dashboard > Services (admin) | Dashboard > Services (admin) | Dashboard > My Connections |
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
├── server.py              # Main aiohttp server (~8100 lines)
├── database.py            # SQLite async database layer (~2500 lines)
├── auth.py                # JWT/API key authentication (~450 lines)
├── config.py              # Environment configuration
├── logger.py              # Logging with rotation
├── ssh_keys.py            # SSH key generation/management
├── shodan_integration.py  # Shodan API for recon
├── traffic_metrics.py     # Connection metrics, time series, Chart.js data
├── vulnerability_scanner.py # CVE/port scanning
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
├── static/                # 16 HTML pages, 8 JS modules, 1 CSS file
│   ├── index.html         # Dashboard
│   ├── login.html         # Login page
│   ├── admin.html         # Admin panel
│   ├── chat.html          # Community chat (mobile sidebar toggle)
│   ├── streams.html       # Community streams
│   ├── live.html          # Public live streams (unauthenticated)
│   ├── watch.html         # Stream viewer (HLS playback)
│   ├── terminal.html      # Terminal UI
│   ├── vnc.html           # VNC viewer
│   ├── spice.html         # SPICE viewer
│   ├── proxmox.html       # Proxmox dashboard
│   ├── mediamtx.html      # MediaMTX management
│   ├── github.html        # GitHub browser
│   ├── api-docs.html      # Interactive API documentation
│   ├── about.html         # Feature guide & docs
│   ├── unauthorized.html  # Auth error page
│   ├── css/portal.css     # Shared styles (~3100 lines, 6 responsive breakpoints)
│   ├── uploads/           # User-uploaded content (gitignored)
│   │   └── chat/          # Chat image uploads
│   └── js/
│       ├── portal.js      # Core utilities
│       ├── dashboard.js   # Dashboard logic
│       ├── admin.js       # Admin panel
│       ├── user-connections.js # Connection CRUD, edit, type schemas
│       ├── ssh-keys.js    # SSH key management
│       ├── streams.js     # Stream management
│       ├── vods.js        # VOD file manager
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
- **RTMPS** (port 1936) - Primary method, encrypted, always available: `rtmps://stream.dddvm.xyz:1936/live`
- **RTMP** (port 1935) - Optional plain RTMP ingress using temporary tokens for security; enabled per-stream via `rtmp_enabled` flag

Playback is proxied through Cloudflare: `https://portal.dddvm.xyz/api/stream/{key}/hls/...`

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
22. **Voice Chat Security** - WebRTC DTLS-SRTP encryption for all audio; `Permissions-Policy: microphone=(self)` restricts mic access to same origin; voice state is ephemeral (in-memory only, no database persistence); multi-tab voice rejection; speaking broadcasts rate-limited (1 per 100ms); signaling validates target user presence before forwarding
23. **RTMP Token Security** - Plain RTMP publish uses temporary `rtmp_` prefixed tokens; tokens are SHA-256 hashed in the database; single-use with a configurable grace period for reconnects; per-stream toggle (`rtmp_enabled`) prevents unauthorized plain RTMP usage

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
```

---

## Deployment

### Systemd Service

```ini
[Unit]
Description=Open Relay Portal
After=network.target

[Service]
Type=simple
User=portal
WorkingDirectory=/opt/portal
ExecStart=/opt/portal/venv/bin/python server.py serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Commands

```bash
# Start/stop/restart
sudo systemctl start portal
sudo systemctl stop portal
sudo systemctl restart portal

# View logs
sudo journalctl -u portal -f

# Check status
sudo systemctl status portal
```
