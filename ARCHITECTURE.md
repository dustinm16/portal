# Portal Gateway - Architecture Documentation

## Overview

Portal Gateway is a modular, secure gateway for accessing home infrastructure resources remotely. It provides authenticated access to various services through a unified interface with support for multiple protocols.

**Public Endpoint:** `https://portal.example.com`

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
┌───────────────────────────────────────────────────────────────────────────┐
│                           Portal Gateway                                   │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                         Core Services                                │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │  │
│  │  │   Auth   │  │  Router  │  │ Registry │  │  Session Manager │    │  │
│  │  │  (JWT)   │  │          │  │          │  │                  │    │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│  ┌─────────────────────────────────┴───────────────────────────────────┐  │
│  │                        Protocol Handlers                             │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │WebSocket │  │   HTTP   │  │   TCP    │  │   UDP    │            │  │
│  │  │  Relay   │  │  Proxy   │  │  Tunnel  │  │  Relay   │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│  ┌─────────────────────────────────┴───────────────────────────────────┐  │
│  │                     Service Plugins (11 total)                       │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │ Terminal │  │   VNC    │  │  SPICE   │  │   SSH    │            │  │
│  │  │ (pty)    │  │ (noVNC)  │  │          │  │          │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │ Proxmox  │  │  GitHub  │  │ MediaMTX │  │   HTTP   │            │  │
│  │  │          │  │          │  │          │  │  Proxy   │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │  │
│  │  │TCP Tunnel│  │  Secure  │  │   VPN    │                          │  │
│  │  │          │  │  Tunnel  │  │  Tunnel  │                          │  │
│  │  └──────────┘  └──────────┘  └──────────┘                          │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                         Web Dashboard                                │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │ Service  │  │ Terminal │  │  VNC     │  │  Status  │            │  │
│  │  │ Launcher │  │ Emulator │  │  Viewer  │  │  Monitor │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │  Linux PC   │ │  Proxmox    │ │  TrueNAS    │
            │  (SSH/VNC)  │ │  (API/VNC)  │ │  (API/SSH)  │
            └─────────────┘ └─────────────┘ └─────────────┘
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │    Plex     │ │  Seedbox    │ │  AI Asst    │
            │   (HTTP)    │ │  (SSH/HTTP) │ │    (WS)     │
            └─────────────┘ └─────────────┘ └─────────────┘
```

## Directory Structure

```
/opt/portal/
├── server.py              # Main entry point
├── config.py              # Configuration management
├── database.py            # SQLite database layer
├── auth.py                # JWT authentication
├── ssh_keys.py            # SSH key management (secure)
├── logger.py              # Logging with rotation
├── router.py              # Request routing
├── registry.py            # Plugin registry
├── shodan_integration.py  # Shodan API integration
├── traffic_metrics.py     # Traffic metrics tracking
├── vulnerability_scanner.py # CVE analysis and port scanning
│
├── protocols/             # Protocol handlers
│   ├── __init__.py
│   ├── base.py            # Base protocol class
│   ├── websocket.py       # WebSocket relay
│   ├── http.py            # HTTP reverse proxy
│   ├── tcp.py             # TCP tunnel over WebSocket
│   └── udp.py             # UDP relay (for gaming)
│
├── plugins/               # Service plugins (11 plugins)
│   ├── __init__.py        # Plugin registry and loader
│   ├── base.py            # Base plugin class
│   ├── terminal.py        # Web terminal (PTY)
│   ├── ssh.py             # SSH over WebSocket
│   ├── vnc.py             # VNC proxy (noVNC)
│   ├── spice.py           # SPICE proxy
│   ├── proxmox.py         # Proxmox VE integration
│   ├── github.py          # GitHub repository management
│   ├── mediamtx.py        # MediaMTX streaming (WebRTC/HLS)
│   ├── tcp_tunnel.py      # Generic TCP tunnel
│   ├── secure_tunnel.py   # Encrypted tunnel with rate limiting
│   ├── vpn_tunnel.py      # VPN bridge (TUN/TAP/SOCKS)
│   └── http_proxy.py      # HTTP reverse proxy
│
├── static/                # Web assets
│   ├── index.html         # Dashboard with service management
│   ├── login.html         # Login page with security features
│   ├── admin.html         # Admin panel (metrics, Shodan, monitoring)
│   ├── terminal.html      # Terminal UI (xterm.js)
│   ├── vnc.html           # VNC viewer (noVNC)
│   ├── spice.html         # SPICE viewer
│   ├── proxmox.html       # Proxmox management UI
│   ├── github.html        # GitHub repository browser
│   ├── media.html         # MediaMTX streaming player
│   ├── unauthorized.html  # Auth error page
│   ├── css/portal.css     # Shared dark theme styles
│   └── js/
│       ├── portal.js      # Core utilities
│       ├── dashboard.js   # Service grid and categories
│       ├── admin.js       # Service/user management
│       └── ssh-keys.js    # SSH key management
│
├── templates/             # HTML templates
├── certs/                 # SSL certificates
├── portal.db              # SQLite database
├── portal.service         # Systemd service
└── requirements.txt       # Dependencies
```

## Plugin System

### Base Plugin Interface

```python
class PluginBase:
    name: str                    # Plugin identifier
    display_name: str            # Human-readable name
    description: str             # Plugin description
    version: str                 # Plugin version
    protocols: list[str]         # Supported protocols: ws, http, tcp, udp
    icon: str                    # Icon identifier

    async def initialize(self) -> None:
        """Called when plugin is loaded."""

    async def handle_connection(self, request, target) -> Response:
        """Handle incoming connection."""

    async def health_check(self, target) -> bool:
        """Check if target service is healthy."""

    def get_config_schema(self) -> dict:
        """Return JSON schema for target configuration."""
```

### Plugin Registration

Plugins auto-register on import via decorator:

```python
@register_plugin
class TerminalPlugin(PluginBase):
    name = "terminal"
    display_name = "Web Terminal"
    protocols = ["websocket"]
```

## Service Configuration

Services are stored in the database with plugin-specific configuration:

```json
{
  "id": 1,
  "name": "Home PC",
  "plugin": "terminal",
  "path": "/pc",
  "enabled": true,
  "config": {
    "host": "192.168.1.100",
    "port": 22,
    "username": "admin",
    "auth_method": "key"
  },
  "required_scopes": ["access:pc"],
  "icon": "computer",
  "category": "computers"
}
```

## User Connections vs Admin Services

Portal Gateway provides two complementary access models:

### Admin Services (Shared Infrastructure)
- Created by administrators through the Admin panel
- Visible to all users with matching scopes
- Intended for **shared infrastructure** used by many users
- **Can target localhost** (for local terminals, PTY, etc.)
- Full plugin access including local PTY terminal
- Configurable access scopes

**Examples:**
- Community forum for all users
- Video streaming relay (Twitch/Kick/YouTube alternative)
- Shared file storage server
- Company-wide development tools

### User Connections (Personal Remote Access)
- Created by individual users through the Connections modal
- **Private to the creating user** (not shared)
- Intended for **personal remote resources** the user owns
- **Cannot target localhost** (security restriction - returns 403)
- Uses same plugin system as services
- No scope configuration needed (user owns it)

**Examples:**
- My home SSH server
- My NAS at home
- My personal database server
- My Proxmox cluster

### Security: Localhost Blocking

User Connections block access to local addresses for security:

| Blocked Pattern | Reason |
|-----------------|--------|
| `localhost` | Local loopback |
| `127.0.0.1` | IPv4 loopback |
| `127.*.*.*` | All IPv4 loopback range |
| `::1` | IPv6 loopback |
| `::ffff:127.*` | IPv4-mapped IPv6 loopback |
| `0.0.0.0` | All interfaces |
| `host.docker.internal` | Docker host access |
| `kubernetes.default` | Kubernetes internal |

Attempting to create a User Connection to a blocked host returns HTTP 403.

### Connection Types to Plugin Mapping

User Connections support all remote-access plugins:

| Connection Type | Plugin | Default Port | Use Case |
|-----------------|--------|--------------|----------|
| ssh | ssh | 22 | Remote shell access |
| vnc | vnc | 5900 | Remote desktop (VNC) |
| rdp | vnc | 3389 | Windows remote desktop |
| spice | spice | 5930 | VM console (SPICE) |
| mediamtx | mediamtx | 8554 | Media streaming |
| proxmox | proxmox | 8006 | Proxmox VE management |
| github | github | 443 | GitHub integration |
| tcp_tunnel | tcp_tunnel | - | Generic TCP forwarding |
| secure_tunnel | secure_tunnel | - | Encrypted tunnel |
| http_proxy | http_proxy | 80 | HTTP reverse proxy |
| database | tcp_tunnel | 3306 | Database access |
| redis | tcp_tunnel | 6379 | Redis access |
| custom | tcp_tunnel | - | Custom TCP service |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/connections` | List user's connections |
| POST | `/api/connections` | Create connection |
| GET | `/api/connections/{id}` | Get connection details |
| PUT | `/api/connections/{id}` | Update connection |
| DELETE | `/api/connections/{id}` | Delete connection |
| GET | `/api/connections/{id}/connect` | Get connect info |
| GET | `/api/connections/types` | List types with schemas |

### WebSocket Endpoints

| Path | Description |
|------|-------------|
| `/ws/connection/{id}` | Connect to user connection |

---

## Supported Plugins

### Terminal (terminal.py)
Web-based terminal using xterm.js and PTY.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket |
| Backend | Local PTY or SSH |
| Frontend | xterm.js |
| Auth | JWT + optional SSH key |

### SSH Relay (ssh.py)
SSH over WebSocket for browser-based SSH clients.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket |
| Backend | SSH connection |
| Frontend | xterm.js |
| Auth | JWT + SSH credentials |

### VNC (vnc.py)
VNC access via noVNC HTML5 client.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket |
| Backend | VNC server |
| Frontend | noVNC |
| Auth | JWT + VNC password |

### SPICE (spice.py)
SPICE protocol for VM consoles (Proxmox, oVirt).

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket |
| Backend | SPICE server |
| Frontend | spice-html5 |
| Auth | JWT + SPICE ticket |

### Proxmox (proxmox.py)
Proxmox VE integration with console access.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket + HTTP |
| Backend | Proxmox API |
| Features | VM list, console, start/stop |
| Auth | JWT + Proxmox API token |

### GitHub (github.py)
GitHub repository management and CI/CD integration.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket + HTTP |
| Backend | GitHub API |
| Features | Repos, branches, PRs, Actions workflows |
| Auth | JWT + OAuth App or Personal Access Token |

Configuration options:
- `client_id`: GitHub OAuth App Client ID
- `client_secret`: GitHub OAuth App Client Secret
- `personal_token`: Personal Access Token (alternative to OAuth)
- `default_org`: Default organization to show
- `webhook_secret`: Secret for validating webhooks
- `allowed_repos`: Restrict access to specific repos

### VPN Tunnel (vpn_tunnel.py)
VPN bridge for TUN/TAP/SOCKS connections.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket (binary) |
| Backend | VPN server |
| Modes | TUN, TAP, SOCKS proxy |
| Auth | JWT |

Configuration options:
- `mode`: Connection mode (tun, tap, socks)
- `mtu`: Maximum transmission unit
- `dns`: DNS server addresses

### HTTP Proxy (http_proxy.py)
HTTP reverse proxy for web applications.

| Feature | Description |
|---------|-------------|
| Protocol | HTTP/HTTPS |
| Backend | Any HTTP service |
| Features | Header rewriting, path mapping |
| Auth | JWT |

Configuration options:
- `target_url`: Backend URL to proxy to
- `rewrite_host`: Rewrite Host header
- `preserve_host`: Keep original Host header

### Secure Tunnel (secure_tunnel.py)
Multiplexed secure TCP tunneling with advanced features.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket (binary frames) |
| Backend | Any TCP service |
| Features | Connection pooling, bandwidth limiting, statistics |
| Auth | JWT |
| Multiplexing | Multiple connections per WebSocket |
| Rate Limiting | Token bucket algorithm for bandwidth control |

Configuration options:
- `bandwidth_limit`: Bytes per second (0 = unlimited)
- `max_connections`: Maximum concurrent connections per session
- `connection_timeout`: Timeout for new connections
- `idle_timeout`: Idle session timeout

### TCP Tunnel (tcp_tunnel.py)
Generic TCP over WebSocket for any TCP protocol.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket (binary) |
| Backend | Any TCP service |
| Features | VNC, RDP, database, Redis support |
| Statistics | Per-connection bytes sent/received |
| Auth | JWT |

### MediaMTX (mediamtx.py)
Live video streaming via MediaMTX server.

| Feature | Description |
|---------|-------------|
| Protocol | WebSocket (signaling) + WebRTC |
| Backend | MediaMTX server |
| Playback | WebRTC (low latency), HLS (compatibility) |
| Auth | JWT + stream-level access control |
| Features | Stream listing, multi-stream, live stats |

Configuration options (all traffic encrypted - mandatory):
- `api_url`: MediaMTX API endpoint (default: https://127.0.0.1:9997)
- `webrtc_url`: WebRTC WHEP endpoint (default: https://127.0.0.1:8889)
- `hls_url`: HLS streaming endpoint (default: https://127.0.0.1:8888)
- `default_stream`: Stream to auto-play on connect
- `allowed_streams`: Restrict access to specific streams

**Security**: Encryption is mandatory and cannot be disabled. Self-signed certificates are auto-generated for internal services. All API endpoints require valid authentication tokens.

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/favicon.ico` | Browser favicon (returns 204) |
| GET | `/api/stats` | Server statistics (admin) |
| GET | `/api/plugins` | List available plugins |
| GET | `/api/tunnels` | View active tunnel sessions (admin) |
| POST | `/api/token` | Create access token |
| GET | `/api/tokens` | List user tokens |
| POST | `/api/token/revoke` | Revoke token |

### Service Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/services` | List all services |
| POST | `/api/services` | Create service (admin) |
| GET | `/api/services/{id}` | Get service details |
| PUT | `/api/services/{id}` | Update service (admin) |
| DELETE | `/api/services/{id}` | Delete service (admin) |
| GET | `/api/services/{id}/health` | Check service health |

### Plugin Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/plugins` | List available plugins |
| GET | `/api/plugins/{name}` | Get plugin info |
| GET | `/api/plugins/{name}/schema` | Get config schema |

### Categories

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/categories` | List categories |
| POST | `/api/categories` | Create category |

### SSH Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ssh-keys` | List user's SSH keys |
| POST | `/api/ssh-keys` | Generate new SSH key pair |
| GET | `/api/ssh-keys/{id}` | Get key details (incl. public key) |
| DELETE | `/api/ssh-keys/{id}` | Delete SSH key |
| GET | `/api/ssh-keys/all` | List all keys (admin only) |
| GET | `/api/ssh-keys/authorized` | Get authorized_keys format |

**Security:** Private keys are returned only once during creation and are never stored. Users must save their private key immediately.

### User Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | List all users (admin only) |
| POST | `/api/users` | Create user (admin only) |
| PUT | `/api/users/{id}/admin` | Update admin status |
| DELETE | `/api/users/{id}` | Delete user (admin only) |
| GET | `/api/me` | Get current user info |
| POST | `/api/me/password` | Change current user's password |
| POST | `/api/register` | Register with invite code |
| GET | `/api/invite-code` | Get invite code (admin only) |

### Logging (Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/logs` | Get log file contents |
| GET | `/api/logs/files` | List log files |
| GET | `/api/logs/settings` | Get log settings |
| PUT | `/api/logs/settings` | Update log settings |

### Chat System

Real-time encrypted messaging system for authenticated users.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/chat/channels` | List chat channels |
| POST | `/api/chat/channels` | Create channel (admin) |
| PUT | `/api/chat/channels/{id}` | Update channel (admin) |
| DELETE | `/api/chat/channels/{id}` | Delete channel (admin) |

**Features:**
- Real-time WebSocket messaging (`/ws/chat`)
- Multiple channels (general, random, help)
- Message encryption using Fernet (AES)
- Admin-only channel management
- User presence tracking (connect/disconnect events)
- Message history with pagination

### WebSocket Endpoints

| Path | Description |
|------|-------------|
| `/ws` | General WebSocket (ping/pong) |
| `/ws/terminal/{service_id}` | Terminal session |
| `/ws/ssh/{service_id}` | SSH session |
| `/ws/vnc/{service_id}` | VNC session |
| `/ws/spice/{service_id}` | SPICE session |
| `/ws/proxmox/{service_id}` | Proxmox console |
| `/ws/github/{service_id}` | GitHub operations |
| `/ws/mediamtx/{service_id}` | MediaMTX signaling |
| `/ws/tunnel/{service_id}` | TCP/Secure tunnel |
| `/ws/chat` | Real-time chat messaging |

### Web UI Routes

| Path | Description |
|------|-------------|
| `/login` | Login page |
| `/logout` | Logout (clears session) |
| `/dashboard` | Main dashboard |
| `/admin` | Admin panel (metrics, security, monitoring) |
| `/terminal/{service_id}` | Terminal UI |
| `/vnc/{service_id}` | VNC viewer |
| `/spice/{service_id}` | SPICE viewer |
| `/proxmox/{service_id}` | Proxmox management |
| `/github/{service_id}` | GitHub browser |
| `/media/{service_id}` | Media player |
| `/chat` | Real-time chat system |
| `/docs` | API documentation |

## Service Presets

The Add Service modal includes quick-start presets for common configurations:

| Preset | Plugin | Description |
|--------|--------|-------------|
| Local Shell | terminal | Local PTY terminal |
| Local VNC | vnc | VNC on localhost:5900 |
| SSH Server | ssh | Remote SSH connection |
| VNC Server | vnc | Remote VNC connection |
| MediaMTX RTSP | mediamtx | RTSP stream relay |
| MediaMTX WebRTC | mediamtx | WebRTC low-latency stream |
| Proxmox Cluster | proxmox | Proxmox VE management |
| SPICE VM | spice | SPICE VM console |
| GitHub | github | GitHub repository manager |
| HTTP Proxy | http_proxy | HTTP reverse proxy |
| TCP Tunnel | tcp_tunnel | Generic TCP tunnel |
| Secure Tunnel | secure_tunnel | Encrypted tunnel |
| VPN Bridge | vpn_tunnel | VPN TUN/TAP bridge |

## Database Schema

### services (updated)
```sql
CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    plugin TEXT NOT NULL,
    path TEXT UNIQUE NOT NULL,
    config TEXT NOT NULL,  -- JSON
    required_scopes TEXT,
    icon TEXT,
    category_id INTEGER,
    enabled INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);
```

### categories
```sql
CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    icon TEXT,
    sort_order INTEGER DEFAULT 0
);
```

### sessions
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    client_ip TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
```

### user_connections
```sql
CREATE TABLE user_connections (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    icon TEXT,
    config TEXT,  -- JSON with plugin-specific settings
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Note:** User connections are private to each user. The `type` maps to a plugin via `CONNECTION_TYPES` in server.py. The `config` field stores plugin-specific settings as JSON.

### ssh_keys
```sql
CREATE TABLE ssh_keys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ed25519',
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, name)
);
```

**Security Note:** Only public keys are stored in the database. Private keys are generated in-memory and returned to the user exactly once during key creation. They are never persisted, ensuring that even a database breach cannot expose private keys.

### recordings
```sql
CREATE TABLE recordings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'asciicast',
    size INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    created_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
```

### settings
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

Persistent configuration storage for admin-configurable settings that survive service restarts:
- `shodan_api_key` - Shodan API key
- `nvd_api_key` - NVD API key for vulnerability scanning
- `log_settings` - JSON with log level, max_size_mb, backup_count

### chat_channels
```sql
CREATE TABLE chat_channels (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    topic TEXT,
    is_default INTEGER DEFAULT 0,
    created_by INTEGER,
    created_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);
```

### chat_messages
```sql
CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    message TEXT NOT NULL,  -- Encrypted with Fernet
    message_type TEXT DEFAULT 'message',
    created_at TEXT,
    FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Note:** Chat messages are encrypted at rest using Fernet (AES-128-CBC) derived from JWT_SECRET via PBKDF2.

## Database Usage

The database module (`database.py`) provides a singleton instance for all database operations:

```python
from database import db

# Must connect before any operations
await db.connect()

# Use high-level methods when available
user = await db.get_user_by_username("admin")
services = await db.get_all_services()

# For custom queries, use db.conn after connect()
async with db.conn.execute("SELECT * FROM users") as cursor:
    rows = await cursor.fetchall()

# Always close when done (handled by server lifecycle)
await db.close()
```

**Important:**
- Always call `db.connect()` before using database operations
- The `db.conn` property raises `RuntimeError` if not connected
- Use provided methods (`get_user_by_id`, `create_service`, etc.) for common operations
- Direct SQL via `db.conn` is available for complex queries

## Scopes

| Scope | Access |
|-------|--------|
| `*` | Full access |
| `admin` | Admin endpoints |
| `services:read` | View services |
| `services:write` | Manage services |
| `access:{service}` | Access specific service |
| `access:*` | Access all services |
| `category:{name}` | Access category |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Token signing key | Required |
| `HOST` | Bind address | 0.0.0.0 |
| `PORT` | Listen port | 443 |
| `HOSTNAME` | Public hostname | portal.example.com |
| `SSL_CERT` | Certificate path | - |
| `SSL_KEY` | Private key path | - |
| `DATABASE_PATH` | SQLite path | portal.db |
| `PLUGIN_DIR` | Plugin directory | plugins/ |
| `STATIC_DIR` | Static files | static/ |

## Admin Panel (`/admin`)

The admin panel provides system monitoring and security scanning capabilities.

### Traffic Metrics
- Real-time connection monitoring
- Per-service bandwidth tracking
- Connection history and statistics
- Active user monitoring
- Time series data (24-hour retention)

### Shodan Integration
- IP lookup for exposure assessment
- Risk scoring based on open ports and CVEs
- Vulnerability tracking
- Service discovery
- API key management (persisted to database)

### CVE Analysis & Vulnerability Scanner
- **Nmap Integration**: Full nmap support with multiple scan types
  - Basic: Quick port scan (`-sS -T4`)
  - Version: Service version detection (`-sV -sC -T4`)
  - Vulnerability: NSE scripts (`--script=vuln,vulners,vulscan`)
  - Full: Comprehensive scan (`-A` + vuln scripts)
- **Dynamic CVE Database**: Real-time CVE fetching from multiple sources
  - NVD (NIST National Vulnerability Database) API
  - CIRCL CVE database (fallback)
  - Local curated CVE database with mitigations
  - File and memory caching with configurable TTL
- **CPE-based Matching**: Accurate vulnerability detection using Common Platform Enumeration
- **CVE Search**: Search NVD by keyword (product, vendor, etc.)
- Automated risk scoring (0-100) and severity levels
- Mitigation recommendations for each vulnerability
- OS detection and service fingerprinting

#### API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vuln/scan/{host}` | Scan host (query: ports, scan_type, use_nmap) |
| GET | `/api/vuln/scan-service/{id}` | Scan Portal service |
| GET | `/api/vuln/cve/{cve_id}` | Lookup CVE details |
| GET | `/api/vuln/mitigations/{cve_id}` | Get mitigation steps |
| GET | `/api/vuln/known-cves` | List local CVE database |
| GET | `/api/vuln/search?q={keyword}` | Search NVD by keyword |
| GET | `/api/vuln/status` | Scanner status (nmap, NVD API) |
| POST | `/api/vuln/nvd-api-key` | Set NVD API key (persisted) |

#### Known CVE Coverage
| CVE ID | Service | Severity | Description |
|--------|---------|----------|-------------|
| CVE-2024-6387 | SSH | Critical | RegreSSHion remote code execution |
| CVE-2023-38408 | SSH | Critical | PKCS#11 remote code execution |
| CVE-2021-44228 | Java | Critical | Log4Shell RCE |
| CVE-2023-44487 | HTTP | High | HTTP/2 Rapid Reset attack |
| CVE-2024-21626 | Docker | Critical | runc container escape |
| CVE-2022-0543 | Redis | Critical | Lua sandbox escape |
| CVE-GENERIC-* | Various | High | Telnet, FTP, SMB, RDP exposure |

### Session Recording
- Terminal session recording in asciicast v2 format
- Automatic recording when enabled per-service
- Admin panel for viewing and downloading recordings
- Playback with `asciinema play recording.cast`

### Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SHODAN_API_KEY` | Shodan API key (also settable via Admin UI) | - |
| `METRICS_ENABLED` | Enable metrics | true |
| `METRICS_RETENTION_HOURS` | Data retention | 24 |
| `NVD_API_KEY` | NVD API key (also settable via Admin UI) | - |
| `NMAP_PATH` | Path to nmap binary | /usr/bin/nmap |
| `CVE_CACHE_TTL` | CVE cache duration in seconds | 3600 |
| `VULN_SCAN_TIMEOUT` | Vulnerability scan timeout | 300 |
| `TOTP_ISSUER` | 2FA issuer name | Portal Gateway |
| `RECORDINGS_DIR` | Session recordings directory | ./recordings |
| `RECORDING_ENABLED` | Enable session recording | true |

**Note:** API keys (Shodan, NVD) can be configured via environment variables or through the Admin UI. Keys set via the Admin UI are persisted to the database and survive service restarts.

## Security

1. **Authentication**: JWT tokens with configurable expiry
2. **Authorization**: Scope-based access control per service
3. **Encryption**: TLS 1.2+ for all connections
4. **Rate Limiting**: Per-IP request limits
5. **Session Tracking**: Audit log of connections
6. **Credential Storage**: Encrypted service credentials
7. **SSH Key Security**:
   - Private keys are NEVER stored in the database
   - Keys are generated in-memory and returned to user only once
   - Only public keys and fingerprints are persisted
   - Database breach cannot expose private keys
   - Supports Ed25519 (recommended) and RSA 4096-bit keys
8. **Security Headers**:
   - X-Frame-Options: SAMEORIGIN
   - X-Content-Type-Options: nosniff
   - Content-Security-Policy (HTML pages)
   - Referrer-Policy: strict-origin-when-cross-origin
   - Permissions-Policy restrictions
9. **Login Security**:
   - Password visibility toggle
   - Password strength indicator
   - Session timeout warnings
   - Remember me option (30 days)
10. **Two-Factor Authentication (TOTP)**:
    - Time-based One-Time Password support
    - QR code setup with authenticator apps
    - 10 backup codes for recovery
    - Secure secret storage with Argon2

## Roadmap

### Phase 1: Core Infrastructure ✓
- [x] JWT authentication
- [x] WebSocket relay
- [x] Service management API
- [x] Rate limiting
- [x] Cloudflare integration

### Phase 2: Plugin System ✓
- [x] Plugin base classes
- [x] Plugin registry
- [x] Dynamic plugin loading
- [x] Terminal plugin (PTY)
- [x] SSH plugin

### Phase 3: Remote Desktop (Current)
- [x] VNC plugin (noVNC)
- [x] SPICE plugin (spice-html5)
- [ ] RDP plugin (future)

### Phase 4: Infrastructure Integration
- [x] Proxmox plugin
- [x] GitHub plugin (repos, PRs, Actions)
- [ ] TrueNAS plugin
- [ ] Network device plugin

### Phase 5: Media & Gaming
- [x] MediaMTX plugin (WebRTC/HLS streaming)
- [ ] Plex plugin
- [ ] Moonlight/Sunshine plugin

### Phase 6: Dashboard ✓
- [x] Web dashboard UI
- [x] Service launcher with plugin icons
- [x] Admin panel (users, services, logs)
- [x] Add Service modal with presets
- [x] Edit Service modal
- [x] Daily invite code system
- [x] Mobile-friendly design

### Phase 7: Advanced Features ✓
- [x] Two-factor authentication (TOTP with QR codes and backup codes)
- [x] SSH key management (secure, no private key storage)
- [x] Session recording (asciicast v2 format)
- [x] Bandwidth monitoring and limiting
- [x] Connection statistics tracking
- [x] Secure tunnel with multiplexing
- [x] VPN tunnel (TUN/TAP/SOCKS)
- [x] HTTP reverse proxy
- [x] Shodan API integration (with database persistence)
- [x] Traffic metrics dashboard
- [x] Admin panel with monitoring
- [x] Security headers middleware
- [x] Enhanced login page (password strength, visibility toggle)
- [x] CVE analysis and vulnerability scanner
- [x] Nmap integration for advanced scanning
- [x] Dynamic CVE fetching from NVD/CIRCL
- [x] CPE-based vulnerability matching
- [x] Known CVE database with mitigations
- [x] Host port scanning with risk scoring
- [x] NVD API integration for CVE lookups
- [x] Persistent settings storage (Shodan/NVD keys, log settings)
- [x] Real-time chat system (encrypted, multi-channel)
- [x] API documentation page (`/docs`)
- [x] User connections (personal remote access)
- [x] Favicon handler (eliminates 404 noise)
