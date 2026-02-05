# Portal Gateway - API Reference

## Security

**All API traffic must use HTTPS on port 443.** HTTP is not supported.

- **Protocol**: HTTPS only (TLS 1.2+)
- **Port**: 443
- **WebSocket**: WSS only (wss://portal.dddvm.xyz/ws/)
- **HSTS**: Enabled with 1-year max-age

## Authentication

All API endpoints require authentication via one of:

1. **Session Cookie** - Obtained via `/login` form submission
2. **Bearer Token** - `Authorization: Bearer <jwt_token>`
3. **API Key** - `Authorization: Api-Key portal_xxx` or `X-API-Key: portal_xxx`

---

## Response Format

All responses are JSON with consistent structure:

**Success:**
```json
{
  "data": { ... },
  "message": "Optional success message"
}
```

**Error:**
```json
{
  "error": "Error description",
  "code": "ERROR_CODE"  // Optional
}
```

---

## Endpoints

### Authentication

#### POST /login
Form-based login, sets session cookie.

**Request (form-data):**
```
username=admin&password=secret
```

**Response:** Redirect to `/dashboard` or error page

---

#### GET /logout
End current session.

**Response:** Redirect to `/login`

---

#### POST /api/token
Create a JWT token.

**Request:**
```json
{
  "scopes": ["*"],
  "expires_hours": 24
}
```

**Response:**
```json
{
  "token": "eyJhbGc...",
  "expires_at": "2026-02-06T12:00:00Z"
}
```

---

### API Keys

#### POST /api/api-keys
Create a new API key.

**Request:**
```json
{
  "name": "My Script",
  "scopes": "*",
  "expires_days": 90
}
```

**Response:**
```json
{
  "id": 1,
  "name": "My Script",
  "key": "portal_a1b2c3d4...",  // Only shown once!
  "prefix": "portal_a1b2",
  "scopes": "*",
  "expires_at": "2026-05-06T00:00:00Z",
  "warning": "Save this key now - it cannot be retrieved later!"
}
```

---

#### GET /api/api-keys
List user's API keys.

**Response:**
```json
{
  "api_keys": [
    {
      "id": 1,
      "name": "My Script",
      "prefix": "portal_a1b2",
      "scopes": "*",
      "created_at": "2026-02-05T00:00:00Z",
      "last_used_at": "2026-02-05T12:00:00Z",
      "revoked": false
    }
  ]
}
```

---

#### POST /api/api-keys/:id/revoke
Revoke an API key (soft delete).

**Response:**
```json
{
  "success": true
}
```

---

#### DELETE /api/api-keys/:id
Permanently delete an API key.

**Response:**
```json
{
  "success": true
}
```

---

### User Profile

#### GET /api/me
Get current user information.

**Response:**
```json
{
  "id": 1,
  "username": "dustin",
  "nickname": "Dustin",
  "role": "superadmin",
  "status": "online",
  "avatar": {"color": "#3b82f6", "emoji": null},
  "chat_anonymous": false,
  "is_admin": true,
  "permissions": {
    "can_manage_users": true,
    "can_reset_passwords": true,
    "can_delete_users": true,
    "manageable_roles": ["admin", "moderator", "user"]
  }
}
```

---

#### POST /api/me/password
Change password.

**Request:**
```json
{
  "current_password": "oldpass",
  "new_password": "newpass"
}
```

**Response:**
```json
{
  "success": true
}
```

---

#### PUT /api/me/status
Update chat status.

**Request:**
```json
{
  "status": "away",
  "status_message": "In a meeting"
}
```

**Response:**
```json
{
  "status": "away",
  "status_message": "In a meeting"
}
```

Status options: `online`, `away`, `busy`, `dnd`, `offline`

---

#### PUT /api/me/nickname
Update display nickname.

**Request:**
```json
{
  "nickname": "DustinM"
}
```

---

#### PUT /api/me/avatar
Update avatar.

**Request:**
```json
{
  "color": "#3b82f6",
  "emoji": "🚀"
}
```

---

#### PUT /api/me/anonymous
Toggle anonymous mode in chat.

**Request:**
```json
{
  "anonymous": true
}
```

---

### User Management (Admin)

#### GET /api/users
List all users.

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "role": "superadmin",
      "is_admin": true,
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "manageable_roles": ["admin", "moderator", "user"]
}
```

---

#### POST /api/users
Create a new user (admin only).

**Request:**
```json
{
  "username": "newuser",
  "password": "temppass",
  "role": "user"
}
```

---

#### PUT /api/users/:id/role
Change user role.

**Request:**
```json
{
  "role": "moderator"
}
```

**Permissions:**
- Superadmin can set: admin, moderator, user
- Admin can set: moderator, user
- Cannot change own role or equal/higher role

---

#### POST /api/users/:id/reset-password
Reset user password (admin only).

**Request:**
```json
{
  "new_password": "newpass"
}
```

---

#### DELETE /api/users/:id
Delete user (superadmin only).

---

### User Connections

#### GET /api/connections
List user's remote connections.

**Response:**
```json
{
  "connections": [
    {
      "id": 1,
      "name": "Home Server",
      "type": "ssh",
      "host": "192.168.1.100",
      "port": 22,
      "config": {"username": "dustin"},
      "icon": "terminal",
      "created_at": "2026-02-01T00:00:00Z"
    }
  ]
}
```

---

#### POST /api/connections
Create a new connection.

**Request:**
```json
{
  "name": "Home Server",
  "type": "ssh",
  "host": "192.168.1.100",
  "port": 22,
  "config": {
    "username": "dustin",
    "auth_method": "key"
  },
  "ssh_key_id": 1,
  "portal_access": 1,
  "api_access": 0
}
```

**Access Control Fields:**
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `portal_access` | int | 1 | Show connection in user's Portal dashboard |
| `api_access` | int | 0 | Allow other authorized users to connect via API relay |

**Connection Types:**
- `ssh` - SSH terminal
- `vnc` - VNC desktop
- `rdp` - Remote Desktop
- `spice` - SPICE console
- `proxmox` - Proxmox VE
- `http` / `https` - Web proxy
- `tcp_tunnel` - Generic TCP
- `secure_tunnel` - Encrypted tunnel
- `vpn_tunnel` - VPN bridge
- `database` - Database connection
- `redis` - Redis connection
- `custom` - Custom protocol

---

#### GET /api/connections/:id
Get connection details.

---

#### PUT /api/connections/:id
Update connection.

---

#### DELETE /api/connections/:id
Delete connection.

---

#### GET /api/connections/types
Get available connection types with schemas.

**Response:**
```json
{
  "types": {
    "ssh": {
      "plugin": "ssh",
      "default_port": 22,
      "schema": {
        "username": {"type": "string"},
        "auth_method": {"type": "string", "enum": ["password", "key", "agent"]}
      }
    }
  }
}
```

---

### User Streams

User streams allow broadcasting from OBS or other streaming software. All traffic is encrypted via RTMPS/RTSPS.

#### GET /api/streams
List user's streams.

**Response:**
```json
{
  "streams": [
    {
      "id": 1,
      "name": "My Live Stream",
      "description": "Gaming session",
      "stream_key": "live_abc123...",
      "is_public": false,
      "is_live": true,
      "viewer_count": 5,
      "total_views": 150,
      "created_at": "2026-02-01T00:00:00Z"
    }
  ]
}
```

---

#### POST /api/streams
Create a new stream.

**Request:**
```json
{
  "name": "My Stream",
  "description": "Optional description",
  "is_public": false
}
```

**Response:**
```json
{
  "stream": {
    "id": 1,
    "name": "My Stream",
    "stream_key": "live_abc123xyz..."
  }
}
```

---

#### GET /api/streams/public
List all public (community) streams.

**Response:**
```json
{
  "streams": [
    {
      "id": 1,
      "name": "Public Stream",
      "owner_username": "dustin",
      "is_live": true,
      "viewer_count": 10,
      "total_views": 500
    }
  ]
}
```

---

#### GET /api/streams/:id
Get stream details.

**Response:**
```json
{
  "stream": {
    "id": 1,
    "name": "My Stream",
    "stream_key": "live_abc123...",
    "is_public": true,
    "is_live": false,
    "chat_channel_id": 5
  }
}
```

---

#### PUT /api/streams/:id
Update stream settings.

**Request:**
```json
{
  "name": "New Name",
  "description": "Updated description",
  "is_public": true
}
```

---

#### DELETE /api/streams/:id
Delete a stream.

**Response:**
```json
{
  "success": true
}
```

---

#### POST /api/streams/:id/regenerate-key
Regenerate stream key.

**Response:**
```json
{
  "stream": {
    "id": 1,
    "stream_key": "live_newkey456..."
  }
}
```

---

#### POST /api/stream/auth
MediaMTX authentication hook (internal use).

**Request (from MediaMTX):**
```json
{
  "action": "publish",
  "path": "live_abc123...",
  "user": "",
  "password": ""
}
```

**Response:**
```json
{
  "ok": true
}
```

---

#### POST /api/stream/event
MediaMTX event notifications (internal use).

Handles stream start/stop events to update live status.

---

### Streaming Configuration

**OBS Studio Settings:**
1. Go to Settings > Stream
2. Service: Custom...
3. Server: `rtmps://your-server.com:1936/live`
4. Stream Key: Your stream key from the My Streams tab

**Playback URLs (all TLS encrypted):**
- HLS: `https://your-server.com:8888/{stream_key}/index.m3u8`
- WebRTC WHEP: `https://your-server.com:8889/{stream_key}/whep`
- RTSPS: `rtsps://your-server.com:8322/{stream_key}`

**Ports (all encrypted):**
| Protocol | Port | Description |
|----------|------|-------------|
| RTMPS | 1936 | RTMP with TLS (ingest) |
| RTSPS | 8322 | RTSP with TLS |
| HLS | 8888 | HTTP Live Streaming (HTTPS) |
| WebRTC | 8889 | WebRTC signaling (HTTPS) |
| API | 9997 | MediaMTX API (HTTPS, internal) |

---

### Chat

#### GET /api/chat/channels
List chat channels.

**Response:**
```json
{
  "channels": [
    {
      "id": 1,
      "name": "general",
      "description": "General discussion",
      "is_default": true
    }
  ]
}
```

---

#### POST /api/chat/channels
Create channel.

**Request:**
```json
{
  "name": "dev-talk",
  "description": "Developer discussion"
}
```

---

#### POST /api/chat/channels/:id/clear
Clear channel history (superadmin only).

**Response:**
```json
{
  "success": true,
  "deleted_count": 150
}
```

---

### WebSocket Endpoints

#### WS /ws/chat
Real-time chat.

**Messages (Client → Server):**
```json
{"type": "join", "channel": "general"}
{"type": "message", "channel": "general", "message": "Hello!"}
{"type": "typing", "channel": "general"}
```

**Messages (Server → Client):**
```json
{"type": "channel_info", "name": "general", "description": "..."}
{"type": "history", "messages": [...]}
{"type": "users", "users": [...]}
{"type": "message", "id": 1, "username": "dustin", "message": "Hello!", "role": "superadmin"}
{"type": "user_joined", "username": "newuser"}
{"type": "user_left", "username": "newuser"}
{"type": "typing", "username": "dustin"}
{"type": "channel_cleared", "cleared_by": "admin", "message_count": 150}
```

---

#### WS /ws/user-connection/:id
Connect to a user connection.

Binary WebSocket relay to the target service.

---

#### WS /ws/terminal/:id
Terminal session.

Text-based terminal I/O.

---

#### WS /ws/vnc/:id
VNC connection.

Binary noVNC protocol relay.

---

### Health & Stats

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-02-05T12:00:00Z",
  "connections": 5
}
```

---

#### GET /api/stats
System statistics.

**Response:**
```json
{
  "total_users": 10,
  "active_connections": 5,
  "total_services": 3,
  "uptime_check": "2026-02-05T12:00:00Z"
}
```

---

### Services

Services are backend endpoints that Portal routes traffic to. There are two types:

- **Proxy Services** (`service_type: "proxy"`) - External backend servers that Portal proxies to
- **Managed Services** (`service_type: "managed"`) - Server processes that Portal runs and manages (e.g., MediaMTX media server, TURN server)

All services use the unified `/api/services` endpoint.

#### GET /api/services
List all services.

**Query Parameters:**
- `type` (optional): Filter by service type (`proxy`, `managed`)

**Response:**
```json
{
  "services": [
    {
      "id": 1,
      "name": "homeassistant",
      "display_name": "Home Assistant",
      "service_type": "proxy",
      "host": "192.168.1.50",
      "port": 8123,
      "status": "stopped",
      "health_status": "unknown",
      "enabled": true
    },
    {
      "id": 2,
      "name": "media-server",
      "display_name": "Media Server",
      "service_type": "managed",
      "host": "127.0.0.1",
      "port": 8554,
      "status": "running",
      "pid": 12345,
      "health_status": "healthy",
      "enabled": true
    }
  ]
}
```

---

#### POST /api/services
Create a new service (admin only).

**Request (Proxy Service):**
```json
{
  "name": "homeassistant",
  "display_name": "Home Assistant",
  "service_type": "proxy",
  "plugin": "http",
  "path": "/ha",
  "host": "192.168.1.50",
  "port": 8123,
  "icon": "home"
}
```

**Request (Managed Service):**
```json
{
  "name": "media-server",
  "display_name": "Media Server",
  "service_type": "managed",
  "plugin": "mediamtx",
  "description": "Primary media streaming server",
  "binary_path": "/usr/local/bin/mediamtx",
  "working_dir": "/var/lib/mediamtx",
  "config": {
    "rtsp_port": 8554,
    "rtmp_port": 1935
  },
  "ports": [8554, 1935, 8888, 8889],
  "enabled": false
}
```

**Response:**
```json
{
  "service": {
    "id": 1,
    "name": "media-server",
    "service_type": "managed",
    "status": "stopped",
    "enabled": false
  },
  "message": "Service created successfully"
}
```

---

#### GET /api/services/:id
Get a service by ID.

**Response:**
```json
{
  "service": {
    "id": 1,
    "name": "media-server",
    "display_name": "Media Server",
    "service_type": "managed",
    "status": "running",
    "pid": 12345,
    "enabled": true,
    "port": 8554,
    "ports": [8554, 1935, 8888, 8889],
    "config": {"rtsp_port": 8554},
    "health_status": "healthy",
    "last_health_check": "2026-02-05T12:00:00Z",
    "restart_count": 0
  }
}
```

---

#### PUT /api/services/:id
Update a service (admin only).

**Request:**
```json
{
  "display_name": "Updated Name",
  "config": {
    "rtsp_port": 8555,
    "log_level": "debug"
  },
  "enabled": true
}
```

---

#### DELETE /api/services/:id
Delete a service (admin only).

**Response:**
```json
{
  "success": true,
  "message": "Service deleted"
}
```

---

#### GET /api/services/types
Get available managed service types (for creating managed services).

**Response:**
```json
{
  "types": {
    "mediamtx": {
      "name": "mediamtx",
      "display_name": "MediaMTX",
      "description": "RTSP/RTMP/HLS/WebRTC media streaming server",
      "version": "1.0.0",
      "icon": "video",
      "default_port": 8554,
      "config_schema": {
        "type": "object",
        "properties": {
          "rtsp_port": {"type": "integer", "default": 8554},
          "rtmp_port": {"type": "integer", "default": 1935},
          "hls_port": {"type": "integer", "default": 8888},
          "webrtc_port": {"type": "integer", "default": 8889},
          "api_port": {"type": "integer", "default": 9997}
        }
      }
    }
  }
}
```

---

#### POST /api/services/:id/start
Start a managed service (admin only). Only valid for `service_type: "managed"`.

**Response:**
```json
{
  "success": true,
  "service": {
    "id": 1,
    "status": "running",
    "pid": 12345
  }
}
```

---

#### POST /api/services/:id/stop
Stop a managed service (admin only). Only valid for `service_type: "managed"`.

**Response:**
```json
{
  "success": true,
  "service": {
    "id": 1,
    "status": "stopped",
    "pid": null
  }
}
```

---

#### POST /api/services/:id/restart
Restart a managed service (admin only). Only valid for `service_type: "managed"`.

**Response:**
```json
{
  "success": true,
  "service": {
    "id": 1,
    "status": "running",
    "pid": 12346
  }
}
```

---

#### GET /api/services/:id/logs
Get logs for a managed service. Only valid for `service_type: "managed"`.

**Query Parameters:**
- `limit` (optional): Max log entries (default: 100)
- `level` (optional): Filter by log level (info, warn, error)

**Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2026-02-05T12:00:00Z",
      "level": "info",
      "message": "Service started with PID 12345"
    },
    {
      "id": 2,
      "timestamp": "2026-02-05T12:00:01Z",
      "level": "info",
      "message": "RTSP server listening on :8554"
    }
  ]
}
```

---

### Deprecated Endpoints

The following endpoints are deprecated and will be removed in a future version. Use the unified `/api/services` endpoints instead.

| Deprecated | Use Instead |
|------------|-------------|
| `GET /api/managed-services` | `GET /api/services?type=managed` |
| `POST /api/managed-services` | `POST /api/services` with `service_type: "managed"` |
| `GET /api/managed-services/:id` | `GET /api/services/:id` |
| `PUT /api/managed-services/:id` | `PUT /api/services/:id` |
| `DELETE /api/managed-services/:id` | `DELETE /api/services/:id` |
| `POST /api/managed-services/:id/start` | `POST /api/services/:id/start` |
| `POST /api/managed-services/:id/stop` | `POST /api/services/:id/stop` |
| `POST /api/managed-services/:id/restart` | `POST /api/services/:id/restart` |
| `GET /api/managed-services/:id/logs` | `GET /api/services/:id/logs` |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service not running |

---

## Web Pages

| Path | Description |
|------|-------------|
| `/login` | Login page |
| `/logout` | Logout (clears session) |
| `/dashboard` | Main dashboard with tabs |
| `/admin` | Admin panel (metrics, services, users) |
| `/chat` | Community chat |
| `/streams` | Community streams |
| `/docs` | API documentation |
| `/terminal/{id}` | Terminal UI |
| `/vnc/{id}` | VNC viewer |
| `/spice/{id}` | SPICE viewer |
| `/proxmox/{id}` | Proxmox management |
| `/github/{id}` | GitHub browser |
| `/media/{id}` | Media player |

### Navigation Structure

All pages use a standardized navbar:
```
Dashboard | Chat | Streams | API Docs | [username] | Logout
```

### Dashboard Tabs

| Tab | Visibility | Description |
|-----|------------|-------------|
| Services | Admin only | Backend services (proxy routes and managed processes) |
| My Connections | All users | Personal SSH, VNC, RDP, database connections |
| My Streams | All users | Personal streaming configurations |
| Quick Access | All users | Shortcuts to SSH Keys, API Keys, Profile |

Regular users default to the "My Connections" tab. Admins default to "Services".

### Dashboard Sidebar

| Section | Description |
|---------|-------------|
| Categories | Filter services by category |
| Community | Links to Chat and Streams pages |
| Quick Actions | Refresh Services button |
| Administration | Admin-only: Add Service, Manage Users, Invite Code, View Logs, Admin Panel |

---

## Rate Limiting

- Default: 100 requests per minute per IP
- WebSocket connections: 10 per minute per IP
- Login attempts: 5 per minute per IP

When rate limited, response includes:
```json
{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```
