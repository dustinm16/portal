# Portal Gateway - Managed Services Implementation Plan

## Current State

Currently, "services" in Portal are just database entries pointing to remote resources. When you "enable" MediaMTX, you're creating a config entry - **no actual MediaMTX server starts**.

## Goal

Transform the services system so that enabling a service **actually provisions and runs** the server process. Portal becomes a service orchestrator, not just a proxy configurator.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Service Manager                             │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Registry   │  │  Lifecycle  │  │  Health Monitor         │  │
│  │  (configs)  │  │  (start/    │  │  (watchdog, restart)    │  │
│  │             │  │   stop)     │  │                         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
      ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
      │  MediaMTX   │ │    TURN     │ │   Custom    │
      │  Service    │ │   Service   │ │   Service   │
      └─────────────┘ └─────────────┘ └─────────────┘
              │               │               │
              ▼               ▼               ▼
      ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
      │  mediamtx   │ │  coturn     │ │  <binary>   │
      │  process    │ │  process    │ │  process    │
      └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Phase 1: Core Service Manager

### 1.1 Database Schema

```sql
-- Replace current services table
CREATE TABLE managed_services (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,                -- mediamtx, turn, coturn, custom
    display_name TEXT,
    description TEXT,

    -- State
    enabled INTEGER DEFAULT 0,
    status TEXT DEFAULT 'stopped',     -- stopped, starting, running, stopping, error
    pid INTEGER,                       -- OS process ID

    -- Configuration
    config TEXT DEFAULT '{}',          -- JSON: type-specific config
    port INTEGER,                      -- Primary listening port
    ports TEXT DEFAULT '[]',           -- JSON: additional ports

    -- Binary/execution
    binary_path TEXT,                  -- Path to executable
    config_path TEXT,                  -- Path to generated config file
    working_dir TEXT,                  -- Working directory

    -- Monitoring
    last_health_check TEXT,
    health_status TEXT,                -- healthy, unhealthy, unknown
    restart_count INTEGER DEFAULT 0,
    last_started_at TEXT,
    last_stopped_at TEXT,
    error_message TEXT,

    -- Metadata
    icon TEXT DEFAULT 'server',
    created_at TEXT,
    updated_at TEXT
);

-- Service logs
CREATE TABLE service_logs (
    id INTEGER PRIMARY KEY,
    service_id INTEGER NOT NULL,
    level TEXT DEFAULT 'info',         -- debug, info, warn, error
    message TEXT NOT NULL,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES managed_services(id) ON DELETE CASCADE
);
CREATE INDEX idx_service_logs_service ON service_logs(service_id);
CREATE INDEX idx_service_logs_timestamp ON service_logs(timestamp);
```

### 1.2 Service Manager Class

```python
# /services/__init__.py

class ServiceManager:
    """Manages lifecycle of all managed services."""

    def __init__(self):
        self._services: dict[int, ManagedService] = {}
        self._health_task: asyncio.Task = None

    async def initialize(self):
        """Load services from database and start enabled ones."""
        services = await db.get_all_managed_services()
        for svc in services:
            handler = self._get_handler(svc['type'])
            self._services[svc['id']] = handler(svc)
            if svc['enabled']:
                await self.start_service(svc['id'])

        # Start health monitor
        self._health_task = asyncio.create_task(self._health_monitor())

    async def start_service(self, service_id: int) -> bool:
        """Start a managed service."""

    async def stop_service(self, service_id: int) -> bool:
        """Stop a managed service."""

    async def restart_service(self, service_id: int) -> bool:
        """Restart a managed service."""

    async def get_status(self, service_id: int) -> dict:
        """Get service status and health."""

    async def get_logs(self, service_id: int, lines: int = 100) -> list:
        """Get recent service logs."""

    async def _health_monitor(self):
        """Background task checking service health."""
        while True:
            for svc in self._services.values():
                if svc.status == 'running':
                    healthy = await svc.health_check()
                    if not healthy:
                        await self._handle_unhealthy(svc)
            await asyncio.sleep(30)
```

### 1.3 Base Service Class

```python
# /services/base.py

class ManagedService(ABC):
    """Base class for managed services."""

    def __init__(self, config: dict):
        self.id = config['id']
        self.name = config['name']
        self.config = json.loads(config.get('config', '{}'))
        self.process: asyncio.subprocess.Process = None
        self.status = 'stopped'

    @abstractmethod
    async def generate_config(self) -> str:
        """Generate configuration file content."""

    @abstractmethod
    async def start(self) -> bool:
        """Start the service process."""

    @abstractmethod
    async def stop(self) -> bool:
        """Stop the service process."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if service is healthy."""

    @property
    @abstractmethod
    def binary_name(self) -> str:
        """Name of the binary to execute."""

    @property
    @abstractmethod
    def default_config(self) -> dict:
        """Default configuration values."""
```

---

## Phase 2: MediaMTX Service

### 2.1 MediaMTX Service Implementation

```python
# /services/mediamtx.py

class MediaMTXService(ManagedService):
    """MediaMTX media server service."""

    binary_name = 'mediamtx'

    default_config = {
        'rtsp_port': 8554,
        'rtmp_port': 1935,
        'hls_port': 8888,
        'webrtc_port': 8889,
        'api_port': 9997,
        'paths': {},            # Stream path configs
        'read_auth': True,      # Require auth for reading
        'publish_auth': True,   # Require auth for publishing
    }

    async def generate_config(self) -> str:
        """Generate mediamtx.yml configuration."""
        cfg = {**self.default_config, **self.config}

        yaml_config = f'''
# MediaMTX Configuration (Auto-generated by Portal)
# Do not edit manually - changes will be overwritten

logLevel: info
logDestinations: [stdout]

api: yes
apiAddress: 127.0.0.1:{cfg['api_port']}

rtsp: yes
rtspAddress: :{cfg['rtsp_port']}

rtmp: yes
rtmpAddress: :{cfg['rtmp_port']}

hls: yes
hlsAddress: :{cfg['hls_port']}

webrtc: yes
webrtcAddress: :{cfg['webrtc_port']}

paths:
  all:
    source: publisher
'''
        return yaml_config

    async def start(self) -> bool:
        """Start MediaMTX process."""
        # Generate config file
        config_content = await self.generate_config()
        config_path = f'/tmp/portal_mediamtx_{self.id}.yml'
        async with aiofiles.open(config_path, 'w') as f:
            await f.write(config_content)

        # Start process
        self.process = await asyncio.create_subprocess_exec(
            self.binary_name,
            config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        self.status = 'running'
        await db.update_service_status(self.id, 'running', self.process.pid)

        # Start log reader
        asyncio.create_task(self._read_logs())

        return True

    async def stop(self) -> bool:
        """Stop MediaMTX process."""
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
            self.process = None

        self.status = 'stopped'
        await db.update_service_status(self.id, 'stopped', None)
        return True

    async def health_check(self) -> bool:
        """Check MediaMTX API health."""
        try:
            api_port = self.config.get('api_port', 9997)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'http://127.0.0.1:{api_port}/v3/paths/list',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except:
            return False
```

### 2.2 MediaMTX API Integration

Portal should expose MediaMTX streams via authenticated endpoints:

```python
# In server.py

async def http_media_streams(request: web.Request) -> web.Response:
    """List available media streams (proxied from MediaMTX)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    service = await service_manager.get_service_by_type('mediamtx')
    if not service or service.status != 'running':
        return web.json_response({'error': 'Media service not running'}, status=503)

    streams = await service.list_streams()
    return web.json_response({'streams': streams})

async def http_media_publish_token(request: web.Request) -> web.Response:
    """Generate a temporary publish token for a stream."""
    # Creates time-limited token for RTSP/RTMP publishing
    pass

# WebSocket relay for WebRTC signaling
async def ws_media_webrtc(request: web.Request) -> web.WebSocketResponse:
    """WebRTC signaling relay to MediaMTX."""
    pass
```

---

## Phase 3: TURN/STUN Service

For WebRTC to work reliably, we need a TURN server.

### 3.1 TURN Service Implementation

```python
# /services/turn.py

class TurnService(ManagedService):
    """Coturn TURN/STUN server service."""

    binary_name = 'turnserver'

    default_config = {
        'listening_port': 3478,
        'tls_port': 5349,
        'min_port': 49152,
        'max_port': 65535,
        'realm': 'portal.local',
        'use_auth_secret': True,
    }

    async def generate_config(self) -> str:
        """Generate turnserver.conf."""
        cfg = {**self.default_config, **self.config}

        return f'''
# Coturn Configuration (Auto-generated by Portal)
listening-port={cfg['listening_port']}
tls-listening-port={cfg['tls_port']}
min-port={cfg['min_port']}
max-port={cfg['max_port']}
realm={cfg['realm']}
use-auth-secret
static-auth-secret={cfg.get('auth_secret', secrets.token_hex(32))}
no-cli
'''
```

---

## Phase 4: API Endpoints

### 4.1 Service Management API

```python
# Service CRUD
GET    /api/services                    # List all managed services
POST   /api/services                    # Create new service
GET    /api/services/:id                # Get service details
PUT    /api/services/:id                # Update service config
DELETE /api/services/:id                # Delete service

# Service lifecycle
POST   /api/services/:id/start          # Start service
POST   /api/services/:id/stop           # Stop service
POST   /api/services/:id/restart        # Restart service
GET    /api/services/:id/status         # Get status/health
GET    /api/services/:id/logs           # Get service logs

# Service-specific
GET    /api/services/:id/streams        # MediaMTX: list streams
POST   /api/services/:id/publish-token  # MediaMTX: get publish token
```

### 4.2 Admin UI Updates

```javascript
// Dashboard should show:
// 1. Service status cards with start/stop buttons
// 2. Real-time status updates via WebSocket
// 3. Log viewer for each service
// 4. Configuration editor

async function startService(serviceId) {
    const response = await fetch(`/api/services/${serviceId}/start`, {
        method: 'POST',
        credentials: 'include'
    });
    if (response.ok) {
        await refreshServiceStatus(serviceId);
    }
}
```

---

## Phase 5: Health Monitoring & Auto-Restart

### 5.1 Health Monitor

```python
class HealthMonitor:
    """Monitors service health and handles failures."""

    def __init__(self, service_manager: ServiceManager):
        self.manager = service_manager
        self.restart_delays = {}  # service_id -> next restart time

    async def run(self):
        """Main monitoring loop."""
        while True:
            for service in self.manager.get_running_services():
                await self._check_service(service)
            await asyncio.sleep(10)

    async def _check_service(self, service: ManagedService):
        """Check single service health."""
        healthy = await service.health_check()

        if not healthy:
            logger.warning(f"Service {service.name} unhealthy")

            # Check if process died
            if service.process and service.process.returncode is not None:
                await self._handle_crash(service)
            else:
                await self._handle_unhealthy(service)

    async def _handle_crash(self, service: ManagedService):
        """Handle crashed service with exponential backoff restart."""
        restart_count = service.restart_count + 1
        delay = min(300, 5 * (2 ** restart_count))  # Max 5 min delay

        logger.info(f"Restarting {service.name} in {delay}s (attempt {restart_count})")
        await asyncio.sleep(delay)

        await self.manager.start_service(service.id)
```

---

## Implementation Order

### Week 1: Foundation ✅ COMPLETE
- [x] Create `managed_services` table migration
- [x] Implement `ServiceManager` class
- [x] Implement `ManagedService` base class
- [x] Add service CRUD API endpoints (`/api/managed-services/*`)
- [x] Health monitoring background task
- [x] Auto-restart with exponential backoff

### Week 2: MediaMTX ✅ COMPLETE
- [x] Implement `MediaMTXService` class
- [x] Add config generation (mediamtx.yml)
- [x] Add stream listing API (via MediaMTX API)
- [ ] Add WebRTC signaling relay
- [ ] Test RTSP/HLS/WebRTC playback

### Week 3: TURN Server
- [ ] Implement `TurnService` class
- [ ] Add credential generation
- [ ] Integrate with MediaMTX WebRTC
- [ ] Test NAT traversal

### Week 4: UI & Polish
- [ ] Update admin panel with service controls
- [ ] Add service log viewer
- [ ] Add real-time status updates
- [ ] Documentation updates

---

## Service Types to Support

| Service | Binary | Purpose |
|---------|--------|---------|
| mediamtx | mediamtx | RTSP/RTMP/HLS/WebRTC streaming |
| turn | turnserver (coturn) | TURN/STUN for WebRTC |
| terminal | (built-in) | Local PTY shell |
| codeserver | code-server | VS Code in browser |
| filebrowser | filebrowser | Web file manager |

---

## Security Considerations

1. **Process Isolation** - Services run as unprivileged user
2. **Port Binding** - Only bind to configured ports
3. **Config Security** - Secrets stored encrypted in database
4. **Access Control** - Only admins can manage services
5. **Audit Logging** - All start/stop/config changes logged
6. **Resource Limits** - CPU/memory limits via cgroups (future)

---

## Open Questions

1. Should services auto-start on Portal boot? (Probably yes for enabled services)
2. How to handle service dependencies? (e.g., TURN must start before MediaMTX WebRTC)
3. Should we support Docker containers as services? (Future enhancement)
4. How to handle service upgrades/binary updates?
