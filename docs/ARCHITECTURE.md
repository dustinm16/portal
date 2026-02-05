# Portal Gateway - Architecture Documentation

## Overview

Portal Gateway is a secure, authenticated gateway for home infrastructure that provides:

1. **Managed Services** - Server processes Portal provisions and manages (MediaMTX, TURN, etc.)
2. **Remote Connections** - Authenticated access to external resources (SSH, VNC, Proxmox, etc.)
3. **Community Features** - Chat, user management, and collaboration tools

**Public Endpoint:** `https://portal.dddvm.xyz`

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

### 1. Managed Services vs Remote Connections

| Aspect | Managed Services | Remote Connections |
|--------|------------------|-------------------|
| **Definition** | Server processes Portal starts/stops | External resources Portal proxies to |
| **Lifecycle** | Managed by Portal (start/stop/restart) | Always external, Portal just connects |
| **Examples** | MediaMTX relay, TURN server, Local PTY | SSH servers, VNC desktops, Proxmox |
| **Storage** | `managed_services` table | `user_connections` table |
| **Ownership** | System-wide (admin managed) | Per-user (private) |
| **Process** | Runs on Portal server | Runs elsewhere |

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
/home/dustin/scripts/portal/
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
├── services/              # Managed service controllers (TODO)
│   ├── __init__.py        # Service manager
│   ├── base.py            # ManagedService base class
│   ├── mediamtx.py        # MediaMTX process manager
│   └── turn.py            # TURN server manager
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
│       └── ...
│
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md    # This file
│   ├── API.md             # API reference
│   └── SERVICES_PLAN.md   # Service implementation plan
│
├── certs/                 # SSL certificates
├── recordings/            # Session recordings
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
    enabled INTEGER DEFAULT 0,
    config TEXT DEFAULT '{}',        -- JSON configuration
    status TEXT DEFAULT 'stopped',   -- running, stopped, error
    pid INTEGER,                     -- Process ID when running
    port INTEGER,                    -- Listening port
    created_at TEXT,
    updated_at TEXT
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

### Connections (User)

```
GET  /api/connections           - List user's connections
POST /api/connections           - Create connection
GET  /api/connections/:id       - Get connection details
PUT  /api/connections/:id       - Update connection
DELETE /api/connections/:id     - Delete connection
GET  /api/connections/types     - Available connection types
```

### Managed Services (Admin)

```
GET  /api/services              - List managed services
POST /api/services              - Create service
GET  /api/services/:id          - Get service details
PUT  /api/services/:id          - Update service config
DELETE /api/services/:id        - Delete service
POST /api/services/:id/start    - Start service
POST /api/services/:id/stop     - Stop service
POST /api/services/:id/restart  - Restart service
GET  /api/services/:id/status   - Get service status
GET  /api/services/:id/logs     - Get service logs
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

1. **Password Security** - Argon2id hashing
2. **JWT Tokens** - Short-lived, scoped access
3. **API Keys** - Prefix-based lookup, hashed storage
4. **2FA Support** - TOTP with backup codes
5. **Rate Limiting** - Per-IP request throttling
6. **Localhost Blocking** - User connections cannot target localhost
7. **Chat Encryption** - Messages encrypted at rest (Fernet)
8. **HTTPS Only** - TLS termination via Cloudflare

---

## Configuration

### Environment Variables

```bash
# Server
PORTAL_HOST=0.0.0.0
PORTAL_PORT=443
PORTAL_DOMAIN=portal.dddvm.xyz

# Security
JWT_SECRET=<random-secret>
INVITE_CODE_SEED=<random-seed>

# Database
DATABASE_PATH=/home/dustin/scripts/portal/portal.db

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
User=dustin
WorkingDirectory=/home/dustin/scripts/portal
ExecStart=/home/dustin/scripts/portal/venv/bin/python server.py serve
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
