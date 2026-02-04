# Portal Gateway - Architecture Documentation

## Overview

Portal Gateway is a modular, secure gateway for accessing home infrastructure resources remotely. It provides authenticated access to various services through a unified interface with support for multiple protocols.

**Public Endpoint:** `https://portal.dddvm.xyz`

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
│  │                        Service Plugins                               │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │ Terminal │  │   VNC    │  │  SPICE   │  │   SSH    │            │  │
│  │  │ (pty)    │  │ (noVNC)  │  │          │  │          │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │  │
│  │  │ Proxmox  │  │ TrueNAS  │  │   Plex   │  │Moonlight │            │  │
│  │  │          │  │          │  │          │  │          │            │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │  │
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
/home/dustin/scripts/portal/
├── server.py              # Main entry point
├── config.py              # Configuration management
├── database.py            # SQLite database layer
├── auth.py                # JWT authentication
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
├── plugins/               # Service plugins
│   ├── __init__.py
│   ├── base.py            # Base plugin class
│   ├── terminal.py        # Web terminal (PTY)
│   ├── ssh.py             # SSH over WebSocket
│   ├── vnc.py             # VNC proxy (noVNC)
│   ├── spice.py           # SPICE proxy
│   ├── proxmox.py         # Proxmox integration
│   ├── truenas.py         # TrueNAS integration
│   ├── plex.py            # Plex proxy
│   └── moonlight.py       # Moonlight/Sunshine
│
├── static/                # Web assets
│   ├── index.html         # Dashboard
│   ├── terminal.html      # Terminal UI
│   ├── vnc.html           # VNC viewer
│   ├── unauthorized.html  # Auth error page
│   ├── css/
│   └── js/
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
    "username": "dustin",
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

### TrueNAS (truenas.py)
TrueNAS SCALE/CORE integration.

| Feature | Description |
|---------|-------------|
| Protocol | HTTP + WebSocket |
| Backend | TrueNAS API |
| Features | Pools, datasets, services |
| Auth | JWT + TrueNAS API key |

### Plex (plex.py)
Plex Media Server proxy.

| Feature | Description |
|---------|-------------|
| Protocol | HTTP |
| Backend | Plex server |
| Features | Media access, transcoding |
| Auth | JWT + Plex token |

### Moonlight (moonlight.py)
Game streaming via Moonlight/Sunshine.

| Feature | Description |
|---------|-------------|
| Protocol | UDP + TCP |
| Backend | Sunshine server |
| Features | Game streaming, input relay |
| Auth | JWT + pairing |

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/api/stats` | Server statistics |
| POST | `/api/token` | Create access token |
| GET | `/api/tokens` | List user tokens |
| POST | `/api/token/revoke` | Revoke token |

### Service Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/services` | List all services |
| POST | `/api/services` | Create service |
| GET | `/api/services/{id}` | Get service details |
| PUT | `/api/services/{id}` | Update service |
| DELETE | `/api/services/{id}` | Delete service |
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

### WebSocket Endpoints

| Path | Description |
|------|-------------|
| `/ws` | General WebSocket (ping/pong) |
| `/ws/terminal/{service_id}` | Terminal session |
| `/ws/vnc/{service_id}` | VNC session |
| `/ws/spice/{service_id}` | SPICE session |
| `/ws/ssh/{service_id}` | SSH session |

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
| `HOSTNAME` | Public hostname | portal.dddvm.xyz |
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

## Roadmap

### Phase 1: Core Infrastructure ✓
- [x] JWT authentication
- [x] WebSocket relay
- [x] Service management API
- [x] Rate limiting
- [x] Cloudflare integration

### Phase 2: Plugin System (Current)
- [ ] Plugin base classes
- [ ] Plugin registry
- [ ] Dynamic plugin loading
- [ ] Terminal plugin (PTY)
- [ ] SSH plugin

### Phase 3: Remote Desktop
- [ ] VNC plugin (noVNC)
- [ ] SPICE plugin
- [ ] RDP plugin (future)

### Phase 4: Infrastructure Integration
- [ ] Proxmox plugin
- [ ] TrueNAS plugin
- [ ] Network device plugin

### Phase 5: Media & Gaming
- [ ] Plex plugin
- [ ] Moonlight/Sunshine plugin
- [ ] Seedbox plugin

### Phase 6: Dashboard
- [ ] Web dashboard UI
- [ ] Service launcher
- [ ] Status monitoring
- [ ] Mobile-friendly design

### Phase 7: Advanced Features
- [ ] Two-factor authentication
- [ ] SSH key management
- [ ] Connection recording
- [ ] Bandwidth monitoring
