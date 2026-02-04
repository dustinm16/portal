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
│   ├── login.html         # Login page
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

Configuration options:
- `api_url`: MediaMTX API endpoint (default: http://localhost:9997)
- `webrtc_url`: WebRTC WHEP endpoint (default: http://localhost:8889)
- `hls_url`: HLS streaming endpoint (default: http://localhost:8888)
- `default_stream`: Stream to auto-play on connect
- `allowed_streams`: Restrict access to specific streams

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
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

### Web UI Routes

| Path | Description |
|------|-------------|
| `/login` | Login page |
| `/dashboard` | Main dashboard |
| `/terminal/{service_id}` | Terminal UI |
| `/vnc/{service_id}` | VNC viewer |
| `/spice/{service_id}` | SPICE viewer |
| `/proxmox/{service_id}` | Proxmox management |
| `/github/{service_id}` | GitHub browser |
| `/media/{service_id}` | Media player |

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

### Phase 7: Advanced Features (Current)
- [ ] Two-factor authentication (TOTP)
- [x] SSH key management (secure, no private key storage)
- [ ] Connection recording
- [x] Bandwidth monitoring and limiting
- [x] Connection statistics tracking
- [x] Secure tunnel with multiplexing
- [x] VPN tunnel (TUN/TAP/SOCKS)
- [x] HTTP reverse proxy
