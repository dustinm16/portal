# Portal Gateway - Architecture Documentation

## Overview

Portal Gateway is a secure, authenticated gateway for home infrastructure that provides:

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
│                            Portal Gateway                                      │
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
│  4. WebSocket Auth    - Token in query/header               │
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
├── server.py              # Main aiohttp server (routes, handlers)
├── database.py            # SQLite async database layer
├── auth.py                # JWT/API key authentication
├── config.py              # Environment configuration
├── logger.py              # Logging with rotation
├── ssh_keys.py            # SSH key generation/management
├── shodan_integration.py  # Shodan API for recon
├── traffic_metrics.py     # Connection metrics
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
├── static/
│   ├── index.html         # Dashboard
│   ├── login.html         # Login page
│   ├── admin.html         # Admin panel
│   ├── chat.html          # Community chat
│   ├── terminal.html      # Terminal UI
│   ├── vnc.html           # VNC viewer
│   ├── spice.html         # SPICE viewer
│   ├── proxmox.html       # Proxmox dashboard
│   ├── github.html        # GitHub browser
│   ├── media.html         # Media player
│   ├── css/portal.css     # Shared styles
│   └── js/
│       ├── portal.js      # Core utilities
│       ├── dashboard.js   # Dashboard logic
│       ├── admin.js       # Admin panel
│       ├── streams.js     # Stream management
│       ├── vods.js        # VOD file manager
│       └── ...
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
    FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE
);
```

---

## API Reference

### Authentication

```
POST /login              - Session login (form)
GET  /logout             - End session
POST /api/token          - Create JWT token
POST /api/api-keys       - Create API key
GET  /api/api-keys       - List API keys
DELETE /api/api-keys/:id - Delete API key
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
PUT  /api/users/:id/role        - Change user role (admin)
DELETE /api/users/:id           - Delete user (superadmin)
```

### User Connections (Personal)

```
GET  /api/connections           - List user's connections
POST /api/connections           - Create connection
GET  /api/connections/:id       - Get connection details
PUT  /api/connections/:id       - Update connection
DELETE /api/connections/:id     - Delete connection
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

### VOD Storage (Personal)

```
GET  /api/vods/storage               - Get storage config
POST /api/vods/storage               - Save storage config
DELETE /api/vods/storage              - Remove storage config
POST /api/vods/storage/test          - Test SFTP connection
GET  /api/vods                       - List MKV files
GET  /api/vods/download/{filename}   - Download VOD file
DELETE /api/vods/{filename}          - Delete VOD file
```

### Chat

```
GET  /api/chat/channels              - List channels
POST /api/chat/channels              - Create channel
PUT  /api/chat/channels/:id          - Update channel
DELETE /api/chat/channels/:id        - Delete channel
POST /api/chat/channels/:id/clear    - Clear history (superadmin)
WS   /ws/chat                        - Chat WebSocket
```

### WebSocket Endpoints

```
WS /ws/chat                     - Chat real-time
WS /ws/terminal/:id             - Terminal session
WS /ws/vnc/:id                  - VNC connection
WS /ws/spice/:id                - SPICE connection
WS /ws/user-connection/:id      - User connection relay
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
| terminal | Web PTY terminal | - |
| ssh | SSH over WebSocket | 22 |
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
│ Localhost Check│ ─── User connection to localhost? → 403 Blocked
└───────┬────────┘
        │
        ▼
    Handler
```

### Security Features

Portal Gateway is designed with privacy and security as core principles:

1. **Password Security** - Argon2id hashing with secure defaults
2. **JWT Tokens** - Short-lived, scoped access tokens
3. **API Keys** - Prefix-based lookup, hashed storage
4. **2FA Support** - TOTP with encrypted backup codes
5. **Rate Limiting** - Per-IP request throttling
6. **Localhost Blocking** - User connections cannot target localhost
7. **Chat Encryption** - Messages encrypted at rest (Fernet)
8. **HTTPS/WSS Only** - All traffic encrypted via TLS
9. **No Session Recording** - Privacy-first design, no session logging
10. **WebSocket Security** - All WebSocket connections use WSS (TLS encrypted)

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
```

---

## Deployment

### Systemd Service

```ini
[Unit]
Description=Portal Gateway
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
