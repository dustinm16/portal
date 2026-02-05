# Portal Gateway - API Reference

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
  "ssh_key_id": 1
}
```

**Connection Types:**
- `ssh` - SSH terminal
- `vnc` - VNC desktop
- `rdp` - Remote Desktop
- `spice` - SPICE console
- `proxmox` - Proxmox VE
- `http` / `https` - Web proxy
- `tcp_tunnel` - Generic TCP
- `database` - Database connection
- `redis` - Redis connection

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
