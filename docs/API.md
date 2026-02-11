# Open Relay Portal - API Reference

## Security

**All API traffic must use HTTPS on port 443.** HTTP is not supported.

- **Protocol**: HTTPS only (TLS 1.2+)
- **Port**: 443
- **WebSocket**: WSS only (wss://portal.example.com/ws/)
- **HSTS**: Enabled with 1-year max-age

## Authentication

All API endpoints require authentication via one of:

1. **Session Cookie** - Obtained via `/login` form submission
2. **Bearer Token** - `Authorization: Bearer <jwt_token>`
3. **API Key** - `Authorization: Api-Key portal_xxx` or `X-API-Key: portal_xxx`
4. **Stream Key** - `Authorization: Stream-Key live_xxx` or `X-Stream-Key: live_xxx`

### Stream Keys as API Keys

**Stream keys and API keys are interchangeable for stream-related operations.** This allows streaming software (OBS, etc.) to use a single key for both:
- Publishing the stream (WHIP/RTMP authentication)
- Making API calls (checking stream status, updating settings)

When authenticated with a stream key:
- You are authenticated as the stream owner
- Access is limited to stream-related operations
- Full API access requires a regular API key

**Example - Using stream key for API access:**
```bash
# Check stream status using stream key
curl -H "X-Stream-Key: live_abc123..." https://portal.example.com/api/streams

# Same result with Api-Key header
curl -H "X-API-Key: portal_xxx..." https://portal.example.com/api/streams
```

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

#### POST /api/register
Register a new account (requires invite code).

**Rate limit:** 1 account per IP per 24 hours.

**Request:**
```json
{
  "username": "newuser",
  "password": "securepass",
  "invite_code": "ABC123"
}
```

**Response (201):**
```json
{
  "id": 5,
  "username": "newuser",
  "message": "Registration successful"
}
```

**Error (429):**
```json
{
  "error": "Registration limit reached. Only one account per IP per 24 hours."
}
```

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

#### GET /api/tokens
List active tokens for the current user.

**Response:**
```json
{
  "tokens": [
    {
      "token_id": "XVzl9pJ...",
      "name": "my-token",
      "scopes": ["*"],
      "created_at": "2026-02-05T00:00:00Z",
      "last_used_at": "2026-02-06T10:00:00Z",
      "expires_at": "2026-03-05T00:00:00Z"
    }
  ]
}
```

---

#### POST /api/token/revoke
Revoke a token.

**Request:**
```json
{
  "token_id": "XVzl9pJ..."
}
```

**Response:**
```json
{
  "success": true
}
```

---

#### GET /api/invite-code
Get the current daily invite code (admin only).

**Response:**
```json
{
  "invite_code": "ABC123",
  "expires_at": "2026-02-07T00:00:00Z"
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
  "username": "john",
  "nickname": "John",
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
Toggle anonymous mode in chat. Anonymous state is stored per-message, so messages sent while anonymous remain anonymous even after the mode is turned off.

Display name priority: **Anonymous** (if enabled) > **Nickname** > **Username**

**Request:**
```json
{
  "anonymous": true
}
```

---

### SSH Keys

Generate and manage SSH key pairs for authentication. Private keys are returned only once upon creation and are never stored.

#### POST /api/ssh-keys
Generate a new SSH key pair.

**Request:**
```json
{
  "name": "my-server-key",
  "key_type": "ed25519"
}
```

Key types: `ed25519` (default, recommended) or `rsa`.

**Response:**
```json
{
  "id": 1,
  "name": "my-server-key",
  "public_key": "ssh-ed25519 AAAA...",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "fingerprint": "SHA256:..."
}
```

> **Warning:** The private key is only returned once. Store it securely.

---

#### GET /api/ssh-keys
List user's SSH keys (public keys only).

**Response:**
```json
{
  "keys": [
    {
      "id": 1,
      "name": "my-server-key",
      "public_key": "ssh-ed25519 AAAA...",
      "fingerprint": "SHA256:...",
      "created_at": "2026-02-05T00:00:00Z"
    }
  ]
}
```

---

#### GET /api/ssh-keys/{id}
Get details for a specific SSH key.

---

#### DELETE /api/ssh-keys/{id}
Delete an SSH key.

---

#### GET /api/ssh-keys/authorized
Get all public keys in `authorized_keys` format for adding to remote servers.

**Response:** Plain text, one key per line.

---

#### GET /api/ssh-keys/all
List all SSH keys across all users (admin only).

---

### Two-Factor Authentication (2FA)

TOTP-based two-factor authentication using authenticator apps.

#### GET /api/user/2fa/status
Get current 2FA status.

**Response:**
```json
{
  "enabled": false,
  "backup_codes_remaining": 0
}
```

---

#### POST /api/user/2fa/setup
Start 2FA setup. Generates a TOTP secret and provisioning URI.

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "provisioning_uri": "otpauth://totp/Portal:user?secret=..."
}
```

---

#### POST /api/user/2fa/verify
Verify a TOTP code to enable 2FA. Returns backup codes.

**Request:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "backup_codes": ["AAAA-BBBB", "CCCC-DDDD", ...]
}
```

---

#### POST /api/user/2fa/disable
Disable 2FA.

**Request:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true
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

#### PUT /api/users/:id/admin
Legacy endpoint. Redirects to `PUT /api/users/:id/role`.

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
List user's remote connections. Sensitive config fields (passwords, private keys) are **redacted** — replaced with boolean `has_<field>` flags.

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
      "config": {"username": "john", "auth_method": "password", "has_password": true},
      "icon": "terminal",
      "created_at": "2026-02-01T00:00:00Z"
    }
  ]
}
```

**Redacted fields:** `password`, `private_key`, `private_key_path`, `auth_header`, `psk` are never returned. If a field has a value, `has_<field>: true` is returned instead.

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
    "username": "john",
    "auth_method": "key",
    "shell": "/usr/bin/fish"
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

**SSH Config Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `username` | string | SSH username |
| `auth_method` | string | `password` or `key` |
| `private_key` | string | PEM private key (for key auth) |
| `shell` | string | Remote shell path (e.g. `/bin/bash`, `/usr/bin/fish`). Empty = default login shell |

**Connection Types:**

| Category | Types |
|----------|-------|
| Remote Access | `ssh`, `vnc`, `rdp`, `spice`, `telnet` |
| Virtualization | `proxmox` |
| Web Panels | `home_assistant`, `portainer`, `truenas`, `pfsense`, `http`, `https`, `http_proxy` |
| Databases | `database`, `redis`, `mongodb`, `elasticsearch` |
| Dev Tools | `jupyter`, `grafana`, `prometheus`, `github` |
| Media | `mediamtx`, `stream` |
| Game Servers | `minecraft_rcon` |
| Network | `tcp_tunnel`, `secure_tunnel`, `vpn_tunnel` |
| Generic | `custom` |

---

#### GET /api/connections/:id
Get connection details. Sensitive config fields are redacted (same as list endpoint).

---

#### PUT /api/connections/:id
Update connection. Config fields are merged server-side with existing config — sensitive fields not included in the request are preserved from the encrypted database record. Credentials never need to round-trip through the client.

**Request:**
```json
{
  "name": "Updated Name",
  "host": "192.168.1.200",
  "port": 2222,
  "config": {
    "username": "newuser",
    "auth_method": "password"
  }
}
```

**Response (200):**
```json
{
  "status": "updated"
}
```

---

#### DELETE /api/connections/:id
Delete connection.

---

#### POST /api/connections/{id}/pin
Toggle the pinned status of a connection. Pinned connections sort to the top of the connections list.

**Response:**
```json
{
  "is_pinned": true
}
```

---

#### GET /api/connections/{id}/connect
Get connection details needed to establish a WebSocket relay (plugin info, WebSocket URL).

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

**Stream Keys:**
Portal uses two types of keys for stream access control:

| Key Type | Format | Purpose | Visibility |
|----------|--------|---------|------------|
| **Private Key** | `live_xxx...` | Publishing (OBS/RTMP) and full management | Owner only |
| **Public Key** | `pub_xxx...` | Read-only viewing access (HLS/WebRTC playback) | Viewers of public streams |

- **Private key (`stream_key`)**: Used for OBS publishing and stream management. Never share this key.
- **Public key (`public_key`)**: Safe to share with viewers for read-only playback access.

**Stream Status (`is_live`):**

| Value | State | Description |
|-------|-------|-------------|
| `0` | Offline | Stream is not broadcasting |
| `1` | Live | Stream is actively broadcasting |
| `2` | Encoding | Stream ended, VOD chunks being finalized and uploaded to SFTP |

Stream lifecycle: **Live** (1) → **Encoding** (2) → **Offline** (0). The encoding state ensures all VOD chunks are fully written and offloaded before the stream goes offline.

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
      "public_key": "pub_xyz789...",
      "is_public": false,
      "is_live": 1,
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
    "stream_key": "live_abc123xyz...",
    "public_key": "pub_def456..."
  }
}
```

---

#### GET /api/streams/public
List all public (community) streams. Requires authentication.

**Response:**
```json
{
  "streams": [
    {
      "id": 1,
      "name": "Public Stream",
      "owner_username": "john",
      "owner_nickname": "John",
      "public_key": "pub_xyz789...",
      "is_live": 1,
      "viewer_count": 10,
      "total_views": 500
    }
  ]
}
```

Note: `stream_key` is never included in public listings (security).

---

#### GET /api/streams/:id
Get stream details.

**Key Visibility Rules:**
- **Owner**: Sees both `stream_key` (for OBS) and `public_key` (for sharing)
- **Non-owner (public stream)**: Sees `public_key` only (for playback)
- **Non-owner (private stream)**: No keys visible

**Response (owner):**
```json
{
  "stream": {
    "id": 1,
    "name": "My Stream",
    "stream_key": "live_abc123...",
    "public_key": "pub_xyz789...",
    "is_public": true,
    "is_live": 0,
    "chat_channel_id": 5
  }
}
```

**Response (non-owner viewing public stream):**
```json
{
  "stream": {
    "id": 1,
    "name": "My Stream",
    "public_key": "pub_xyz789...",
    "is_public": true,
    "is_live": 0,
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

#### POST /api/streams/{id}/rtmp-token
Generate a temporary, single-use token for plain RTMP (non-TLS) publishing.

**Authentication:** Required (stream owner only)

**Prerequisites:** `rtmp_enabled` must be true on the stream, and `RTMP_PLAIN_ENABLED` must be true server-side.

**Response:**
```json
{
  "token": "rtmp_...",
  "expires_in": 900,
  "rtmp_url": "rtmp://<STREAM_HOSTNAME>:1935/live"
}
```

**Notes:**
- Token expires after 15 minutes (configurable via `RTMP_TOKEN_EXPIRY_MINUTES`)
- Single-use with 30-second grace period for OBS reconnect
- Use as the stream key in OBS: `rtmp://<STREAM_HOSTNAME>:1935/live` with token as key
- Tokens are revoked when `rtmp_enabled` is toggled off
- Internally, the token is used as the MediaMTX publish path (`live/rtmp_xxx`). Portal maps this back to the stream so HLS playback, dynamic thumbnails, and VOD recording all work seamlessly regardless of whether the stream publishes via RTMPS (`live_` key) or plain RTMP (`rtmp_` token).

---

#### GET /api/streams/open
List all currently live and public streams (for community streams page).

**Response:**
```json
{
  "streams": [
    {
      "id": 1,
      "name": "Gaming Stream",
      "owner_username": "alice",
      "is_live": 1,
      "viewer_count": 10,
      "public_key": "pub_xyz789..."
    }
  ]
}
```

---

#### POST /api/streams/{id}/thumbnail
Upload a custom thumbnail image for a stream (owner only). Multipart form data with field `thumbnail`. Max 2MB, JPEG/PNG.

**Response:**
```json
{
  "success": true,
  "thumbnail_url": "/static/uploads/thumbnails/stream_1.jpg"
}
```

---

#### DELETE /api/streams/{id}/thumbnail
Remove custom thumbnail for a stream (owner only).

---

#### GET /api/stream/{key}/thumbnail
Get a dynamic thumbnail for a live stream. Returns a JPEG image captured from the stream via ffmpeg. Thumbnails are cached for 15 seconds.

**Key Types:** Accepts either `live_xxx` or `pub_xxx` key.

**Response:** `image/jpeg` binary data, or 404 if stream is not live.

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

Handles stream start/stop events to update live status. Stream lifecycle: **Live** (`is_live=1`) → **Encoding** (`is_live=2`, VOD chunks finalizing) → **Offline** (`is_live=0`).

---

#### GET /api/stream/{key}/info
Get stream information and playback URLs.

**Key Types:** Accepts either `live_xxx` (private) or `pub_xxx` (public) key.

**Response:**
```json
{
  "stream_key": "live_abc123...",
  "public_key": "pub_xyz789...",
  "name": "My Stream",
  "is_live": 1,
  "is_public": true,
  "playback": {
    "hls": "https://portal.example.com/api/stream/pub_xyz789/hls/index.m3u8",
    "webrtc_whep": "https://portal.example.com/api/stream/pub_xyz789/webrtc/whep"
  },
  "publish": {
    "webrtc_whip": "https://portal.example.com/api/stream/live_abc123/webrtc/whip"
  }
}
```

---

#### GET /api/stream/{key}/hls/{path}
Proxy HLS playback through Portal (port 443).

**Key Types:** Accepts either `live_xxx` (private) or `pub_xxx` (public) key for playback.

Returns HLS playlist and segments for the specified stream.

---

#### POST /api/stream/{key}/webrtc/whep
WebRTC WHEP endpoint for playback.

**Key Types:** Accepts either `live_xxx` (private) or `pub_xxx` (public) key for playback.

**Request:**
- Body: SDP offer (application/sdp)

**Response:**
- Status: 201 Created
- Body: SDP answer (application/sdp)
- Headers: `Location` - Session URL for ICE candidates

---

#### POST /api/stream/{key}/webrtc/whip
WebRTC WHIP endpoint for publishing.

**Key Types:** Requires private key (`live_xxx`) - public keys cannot publish.

**Request:**
- Body: SDP offer (application/sdp)

**Response:**
- Status: 201 Created
- Body: SDP answer (application/sdp)
- Headers: `Location` - Session URL for ICE candidates

---

### Streaming Configuration

Open Relay Portal provides a complete streaming solution with MediaMTX. Publishing uses a dedicated subdomain (`stream.example.com`) for direct RTMPS access, while playback is proxied through Portal on port 443.

**Key Types:**
| Key | Format | Use Case |
|-----|--------|----------|
| Private Key | `live_xxx...` | Publishing (OBS), API access, stream management |
| Public Key | `pub_xxx...` | Read-only playback URLs (safe to share with viewers) |

**Stream Key = API Key**: Your private stream key (`live_xxx...`) can be used for both streaming AND API access.

**Publishing Options (requires private key `live_xxx`):**

1. **RTMPS (Recommended for OBS)** - Direct connection with Let's Encrypt certificate
   - Server: `rtmps://stream.example.com:1936/live`
   - Stream Key: Your private stream key from My Streams tab
   - Works with all versions of OBS Studio

2. **WebRTC WHIP** - Works through port 443 (OBS 30.0+)
   - URL: `https://portal.example.com/api/stream/{stream_key}/webrtc/whip`
   - Service: WHIP in OBS settings

**OBS Studio Settings (RTMPS - Recommended):**
1. Go to Settings > Stream
2. Service: Custom
3. Server: `rtmps://stream.example.com:1936/live`
4. Stream Key: Your private stream key (e.g., `live_abc123...`)

**Playback URLs (accepts either key type):**
- HLS: `https://portal.example.com/api/stream/{key}/hls/index.m3u8`
- WebRTC WHEP: `https://portal.example.com/api/stream/{key}/webrtc/whep`

For public streams, share the `public_key` (`pub_xxx`) for playback URLs instead of the private key.

**Using Stream Key for API Access:**
```bash
# Your private stream key works as an API key for stream operations
curl -H "X-Stream-Key: live_abc123..." https://portal.example.com/api/streams
```

**Network Architecture:**
| Service | Host | Port | Description |
|---------|------|------|-------------|
| RTMPS Publishing | stream.example.com | 1936 | Direct connection (Let's Encrypt TLS) |
| HLS/WebRTC Playback | portal.example.com | 443 | Proxied through Cloudflare |
| Portal API | portal.example.com | 443 | Proxied through Cloudflare |

**TLS Certificates:**
- `stream.example.com` uses Let's Encrypt (auto-renewed via certbot)
- `portal.example.com` uses Cloudflare Origin CA

---

### Stream Moderation

Stream owners can ban users from their stream's chat.

#### GET /api/streams/:id/bans
List banned users for a stream (owner only).

**Response:**
```json
{
  "bans": [
    {
      "id": 1,
      "stream_id": 5,
      "user_id": 42,
      "banned_by": 10,
      "reason": "Spam",
      "created_at": "2026-02-05T12:00:00Z",
      "banned_username": "spammer123",
      "banned_by_username": "streamowner"
    }
  ]
}
```

---

#### POST /api/streams/:id/bans
Ban a user from stream chat (owner only).

**Request:**
```json
{
  "user_id": 42,
  "reason": "Spam"
}
```

**Response:**
```json
{
  "success": true,
  "ban_id": 1,
  "message": "User banned from stream chat"
}
```

---

#### DELETE /api/streams/:id/bans/:user_id
Remove a ban from stream chat (owner only).

**Response:**
```json
{
  "success": true,
  "message": "User unbanned"
}
```

---

### Stream Chat WebSocket Commands

Additional WebSocket message types for stream chat moderation:

**Ban a user:**
```json
{
  "type": "ban",
  "user_id": 42,
  "reason": "Spam"
}
```

**Unban a user:**
```json
{
  "type": "unban",
  "user_id": 42
}
```

**Get ban list:**
```json
{
  "type": "get_bans"
}
```

**Server responses:**
- `user_banned` - Broadcast when a user is banned
- `ban_success` - Confirmation of successful ban
- `unban_success` - Confirmation of successful unban
- `bans_list` - Response to get_bans request

**Stream status broadcasts** (sent to all users in the stream's chat channel):
```json
{
  "type": "stream_status",
  "stream_id": 3,
  "is_live": 2
}
```

The `is_live` field follows the tri-state model: `1`=live (stream started), `2`=encoding (stream ended, VODs finalizing), `0`=offline (all VODs uploaded).

---

### Chat

#### GET /api/chat/channels
List chat channels. Stream-associated channels include live status and stream metadata for UI grouping (Live / Encoding / Offline sections). The `stream_is_live` field uses the tri-state integer: `0`=offline, `1`=live, `2`=encoding.

**Response:**
```json
{
  "channels": [
    {
      "id": 1,
      "name": "general",
      "description": "General discussion",
      "is_default": 1,
      "is_stream_channel": false,
      "unread_count": 5
    },
    {
      "id": 5,
      "name": "My Stream",
      "description": "Stream chat",
      "is_default": 0,
      "is_stream_channel": true,
      "stream_id": 3,
      "stream_is_live": 1,
      "stream_public_key": "pub_xyz789...",
      "stream_owner": "dustin",
      "unread_count": 0
    }
  ]
}
```

- `unread_count`: Number of unread messages since the user's last read position in this channel.

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

#### PUT /api/chat/channels/:id
Update channel (admin/superadmin only). Cannot rename default or stream-associated channels.

**Request:**
```json
{
  "name": "new-name",
  "description": "Updated description",
  "topic": "New topic"
}
```

Broadcasts `channel_renamed` to all connected clients if name changes.

---

#### DELETE /api/chat/channels/:id
Delete channel (admin/superadmin only). Cannot delete default or stream-associated channels.

Broadcasts `channel_deleted` to all connected clients before deletion.

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

#### POST /api/chat/upload
Upload an image for embedding in chat messages (max 5MB, JPEG/PNG/GIF/WebP).

**Request:** Multipart form data with field name `image`.

**Response:**
```json
{
  "url": "/static/uploads/chat/abc123def.jpg"
}
```

Include the returned URL as `image_url` in the WS message payload.

---

#### GET /api/chat/link-preview
Fetch OpenGraph metadata for a URL (for link preview cards in chat).

**Query Parameters:**
- `url` (required): The URL to fetch preview data for (http/https only)

**Response:**
```json
{
  "url": "https://github.com",
  "title": "GitHub",
  "description": "Where the world builds software",
  "image": "https://github.githubassets.com/images/modules/open_graph/github-octocat.png",
  "site_name": "GitHub",
  "domain": "github.com"
}
```

**Security:** Blocks private/loopback IPs (SSRF protection), 5s timeout, 1MB max response. Results cached for 1 hour.

---

#### GET /api/chat/thread/:id
Get the reply chain for a message (thread view). Walks the `reply_to` chain backwards up to 20 messages.

**Response:**
```json
{
  "thread": [
    {"id": 10, "user_id": 1, "username": "alice", "message": "Original message", "created_at": "..."},
    {"id": 15, "user_id": 2, "username": "bob", "message": "Reply to alice", "reply_to": 10, "created_at": "..."},
    {"id": 20, "user_id": 1, "username": "alice", "message": "Reply to bob", "reply_to": 15, "created_at": "..."}
  ]
}
```

Messages are returned in chronological order with user enrichment (nickname, avatar, role).

---

### Voice Chat

Live voice chat uses WebRTC P2P mesh (2-10 users per channel). The server acts purely as a signaling relay — no audio is processed or stored server-side. Audio is encrypted via WebRTC DTLS-SRTP.

Voice signaling piggybacks on the existing `/ws/chat` WebSocket. No separate WebSocket connection is needed.

#### GET /api/voice/ice-servers
Get ICE server configuration for WebRTC peer connections.

**Response:**
```json
{
  "ice_servers": [
    {"urls": "stun:stun.l.google.com:19302"},
    {"urls": "turn:turn.example.com:3478", "username": "user", "credential": "pass"}
  ]
}
```

TURN server is optional — only included if configured via environment variables (`TURN_SERVER`, `TURN_USERNAME`, `TURN_PASSWORD`).

---

#### Voice WebSocket Messages (via /ws/chat)

**Client → Server:**
```json
{"type": "voice_join"}
{"type": "voice_leave"}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "offer", "sdp": "..."}}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "answer", "sdp": "..."}}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "ice-candidate", "candidate": {...}}}
{"type": "voice_mute", "muted": true}
{"type": "voice_deafen", "deafened": true}
{"type": "voice_speaking", "speaking": true}
```

**Server → Client:**
```json
{"type": "voice_state", "channel": "general", "users": [{"user_id": 1, "username": "alice", "muted": false, "deafened": false, "speaking": false}]}
{"type": "voice_user_joined", "user_id": 2, "username": "bob"}
{"type": "voice_user_left", "user_id": 2}
{"type": "voice_signal", "from_user_id": 2, "signal": {"type": "offer", "sdp": "..."}}
{"type": "voice_mute_changed", "user_id": 2, "muted": true}
{"type": "voice_deafen_changed", "user_id": 2, "deafened": true}
{"type": "voice_speaking_changed", "user_id": 2, "speaking": true}
```

- `voice_state`: Sent to joiner with list of all current voice users in the channel
- `voice_signal`: Targeted relay — only sent to the specified user, never broadcast
- `voice_speaking`: Rate-limited to 1 broadcast per 100ms per user
- Users can only be in voice in one channel at a time; switching text channels auto-leaves voice
- User list (`users` messages) includes `in_voice`, `voice_muted`, `voice_deafened`, `voice_speaking` fields

---

### WebSocket Endpoints

#### WS /ws/chat
Real-time chat. Messages are rate limited to **5 per 5 seconds** per user.

Display name priority: **Anonymous** > **Nickname** > **Username**. Anonymous state is stored per-message in the database, so historical messages preserve their anonymity regardless of the user's current setting.

**Messages (Client → Server):**
```json
{"type": "join", "channel": "general"}
{"type": "message", "channel": "general", "message": "Hello!"}
{"type": "message", "channel": "general", "message": "Reply!", "reply_to": 42}
{"type": "message", "channel": "general", "message": "", "image_url": "/static/uploads/chat/abc.jpg"}
{"type": "typing", "channel": "general"}
{"type": "delete", "message_id": 42}
{"type": "react", "message_id": 42, "emoji": "👍"}
{"type": "edit_message", "message_id": 42, "message": "Updated text"}
{"type": "pin_message", "message_id": 42}
{"type": "unpin_message", "message_id": 42}
{"type": "mark_read", "message_id": 50}
```

- `reply_to` (optional): Message ID to reply to. Must be in the same channel.
- `delete`: Admins/moderators can delete any message; regular users can only delete their own.
- `react`: Toggles a reaction on a message (add if not present, remove if present). Max 10 chars per emoji.
- `edit_message`: Edit own message within 5-minute window. Re-encrypted before storage.
- `pin_message` / `unpin_message`: Moderator/admin only. Pin or unpin a message in the current channel.
- `mark_read`: Update the user's read position for unread tracking.

**Messages (Server → Client):**
```json
{"type": "channel_info", "name": "general", "description": "..."}
{"type": "history", "messages": [...]}
{"type": "users", "users": [{"user_id": 1, "username": "john", "nickname": "Johnny", "role": "user", "anonymous": false, "avatar": {...}}]}
{"type": "message", "id": 43, "user_id": 1, "username": "john", "nickname": "Johnny", "role": "user", "anonymous": false, "avatar": {"color": "#3b82f6", "emoji": "🚀"}, "message": "Reply!", "reply_to": 42, "reply_preview": {"id": 42, "username": "alice", "message": "Hello!"}}
{"type": "user_joined", "username": "newuser", "role": "user", "anonymous": false}
{"type": "user_left", "username": "newuser"}
{"type": "typing", "username": "john"}
{"type": "message_deleted", "message_id": 42, "deleted_by": 1}
{"type": "channel_renamed", "old_name": "dev-talk", "new_name": "engineering"}
{"type": "channel_deleted", "channel": "old-channel"}
{"type": "channel_cleared", "cleared_by": "admin", "message_count": 150}
{"type": "error", "message": "Slow down! You're sending messages too fast."}
{"type": "reaction_update", "message_id": 42, "emoji": "👍", "user_id": 1, "added": true, "count": 3}
{"type": "message_edited", "message_id": 42, "message": "Updated text", "edited_at": "2026-02-10T..."}
{"type": "message_pinned", "message_id": 42, "message": "Important info", "username": "alice", "pinned_by": "admin"}
{"type": "message_unpinned", "message_id": 42}
{"type": "pinned_messages", "messages": [{"id": 42, "username": "alice", "message": "Important info", "pinned_at": "..."}]}
```

- `reply_to` / `reply_preview`: Present on messages that are replies. Preview includes parent message's username and text (truncated to 100 chars). Anonymous parent messages show "Anonymous" as username.
- `reactions`: Array of `{emoji, count, user_ids}` included in history messages. Real-time updates sent as `reaction_update`.
- `message_edited`: Broadcast when a message is edited (includes new plaintext).
- `message_pinned` / `message_unpinned`: Broadcast when a mod pins/unpins a message.
- `pinned_messages`: Sent on channel join with all pinned messages for the channel.
- `message_deleted`: Broadcast when a message is deleted.
- `channel_renamed`: Broadcast when an admin renames a channel via REST API.
- `channel_deleted`: Broadcast when an admin deletes a channel via REST API.

---

#### WS /ws/user-connection/:id
Connect to a user connection.

Binary WebSocket relay to the target service.

---

#### WS /ws/terminal/local
Admin-only local server terminal. Supports shell selection via query parameter.

**Query Parameters:**
- `shell` (optional): Shell path (e.g., `/usr/bin/fish`). Must be in the server's allowed shells list. Defaults to `/bin/bash`.

Text-based terminal I/O with server-side terminal compatibility (DA1/DA2/DSR queries are intercepted and responded to immediately with xterm.js-matching responses to prevent shell timeouts).

---

#### WS /ws/user-connection/:id
User connection relay. For SSH connections, supports shell override via query parameter.

**Query Parameters:**
- `shell` (optional): Remote shell path override (e.g., `/usr/bin/fish`). Overrides the connection's configured shell.

Terminal capability queries (DA1/DA2/DSR) pass through to xterm.js which responds natively. Unlike the local terminal, SSH connections do not intercept queries server-side — asyncssh's line-buffered `readline()` would delay escape sequences that lack newlines, so queries flow through the WebSocket to xterm.js for reliable sub-200ms round-trip responses. The client also sends a resize on connect to sync terminal dimensions after the auth phase.

---

#### WS /ws/terminal/:id
Terminal session for a service.

Text-based terminal I/O.

---

#### WS /ws/vnc/:id
VNC connection.

Binary noVNC protocol relay.

---

### VOD Storage

Users can configure remote SFTP storage for recorded VODs (MKV files). Each user has their own storage configuration.

#### GET /api/vods/storage
Get current user's VOD storage configuration.

**Response:**
```json
{
  "storage": {
    "host": "storage.example.com",
    "port": 22,
    "username": "user",
    "auth_method": "password",
    "remote_path": "/home/user/vods",
    "has_password": true,
    "has_key": false
  }
}
```

Note: Passwords and private keys are never returned (only `has_password`/`has_key` flags).

---

#### POST /api/vods/storage
Create or update VOD storage configuration.

**Request:**
```json
{
  "host": "storage.example.com",
  "port": 22,
  "username": "user",
  "auth_method": "password",
  "password": "secret",
  "remote_path": "/home/user/vods"
}
```

For SSH key authentication, use `"auth_method": "key"` and `"private_key": "..."` instead of password.

---

#### DELETE /api/vods/storage
Remove VOD storage configuration. Does not delete remote files.

**Response:**
```json
{
  "success": true
}
```

---

#### POST /api/vods/storage/test
Test SFTP connection with provided credentials.

**Request:** Same format as POST /api/vods/storage.

**Response:**
```json
{
  "success": true,
  "message": "Connected successfully. Found 5 MKV files in /home/user/vods"
}
```

---

#### GET /api/vods
List MKV files in user's remote storage. Recursively scans all subdirectories.

VOD files are organized in a directory structure created by the automatic recording pipeline, sourced from RTSPS:
```
{remote_path}/
├── StreamName/
│   ├── 2026-02-08/
│   │   ├── chunk_000.mkv
│   │   ├── chunk_001.mkv
│   │   └── chunk_002.mkv
│   └── 2026-02-09/
│       └── chunk_000.mkv
└── standalone-recording.mkv
```

Sessions on the same date accumulate in the same directory with chunk numbering continuing from the highest existing chunk.

**Query Parameters:**
- `sort` (optional): Sort by `name`, `size`, or `modified` (default: `modified`)
- `order` (optional): `asc` or `desc` (default: `desc`)

**Response:**
```json
{
  "files": [
    {
      "name": "StreamName/2026-02-08/chunk_000.mkv",
      "size": 233436982,
      "modified": 1770525031
    },
    {
      "name": "StreamName/2026-02-08/chunk_001.mkv",
      "size": 6102991,
      "modified": 1770525033
    }
  ],
  "path": "/home/user/vods"
}
```

Returns 404 if no storage is configured.

---

#### GET /api/vods/download/{filename}
Stream-download a VOD file from remote storage. Only `.mkv` files allowed. Supports subdirectory paths (e.g., `StreamName/session/chunk_000.mkv`).

**Response:** Binary file stream with `Content-Disposition: attachment` header.

**Security:** Path traversal (`..`, absolute paths) is rejected.

---

#### POST /api/vods/download-archive
Download multiple VOD files as a single zip archive streamed from SFTP. The zip is constructed on-the-fly with proper central directory entries — no server-side buffering of the full archive.

**Request:**
```json
{
  "files": [
    "StreamName/2026-02-08/chunk_000.mkv",
    "StreamName/2026-02-08/chunk_001.mkv"
  ]
}
```

**Limits:** Maximum 500 files per archive. All paths must end in `.mkv`.

**Response:** Binary zip stream with `Content-Disposition: attachment; filename="archive_name.zip"` header. Archive name is derived from the common directory prefix of the selected files.

**Security:** Path traversal (`..`, absolute paths) is rejected.

---

#### DELETE /api/vods/{filename}
Delete a VOD file from remote storage. Only `.mkv` files allowed. Supports subdirectory paths.

**Response:**
```json
{
  "success": true,
  "message": "Deleted StreamName/session/chunk_000.mkv"
}
```

---

### Notifications

#### GET /api/notifications
Get notifications for the current user. Supports filtering to unread-only.

**Query Parameters:**
- `unread` (optional): Set to `1` to return only unread notifications

**Response:**
```json
{
  "notifications": [
    {
      "id": 1,
      "user_id": 10,
      "type": "stream_live",
      "title": "Stream Live",
      "message": "alice started streaming 'Gaming Session'",
      "data": {"stream_id": 5},
      "is_read": false,
      "created_at": "2026-02-08T12:00:00"
    }
  ],
  "unread_count": 3
}
```

---

#### POST /api/notifications/{id}/read
Mark a single notification as read. Only affects notifications owned by the authenticated user.

**Response:**
```json
{
  "success": true
}
```

---

#### POST /api/notifications/read-all
Mark all notifications as read for the authenticated user.

**Response:**
```json
{
  "success": true,
  "count": 5
}
```

---

### System Info

#### GET /api/shells
List available shells on the server (admin only). Used by the terminal shell selector.

**Response:**
```json
{
  "shells": [
    {"path": "/usr/bin/bash", "name": "bash"},
    {"path": "/usr/bin/fish", "name": "fish"},
    {"path": "/usr/bin/zsh", "name": "zsh"}
  ]
}
```

---

#### GET /api/plugins
List available plugins with their configuration schemas.

**Response:**
```json
{
  "plugins": [
    {
      "name": "ssh",
      "display_name": "SSH Terminal",
      "description": "SSH connection over WebSocket",
      "version": "1.0.0",
      "config_schema": { ... }
    }
  ]
}
```

---

#### GET /api/tunnels
Get active secure tunnel sessions (admin only).

**Response:**
```json
{
  "sessions": [...]
}
```

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

#### GET /api/stats/public
Public statistics available to all authenticated users.

**Response:**
```json
{
  "live_streams": 3,
  "online_users": 12
}
```

---

#### GET /api/stats
System statistics (admin only).

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

#### GET /api/system/health
Detailed system resource metrics (admin only). Returns CPU, memory, disk usage, load averages, and Portal process stats via psutil.

**Response:**
```json
{
  "cpu": {
    "percent": 12.5,
    "count": 4,
    "load_avg": [0.5, 0.3, 0.2]
  },
  "memory": {
    "total": 8589934592,
    "used": 4294967296,
    "available": 4294967296,
    "percent": 50.0
  },
  "disk": {
    "total": 107374182400,
    "used": 53687091200,
    "free": 53687091200,
    "percent": 50.0
  },
  "process": {
    "rss": 67108864,
    "vms": 134217728,
    "threads": 8,
    "pid": 12345
  },
  "uptime_seconds": 86400
}
```

---

#### GET /api/activity
Recent activity feed. Admins see all activity; regular users see only their own.

**Query Parameters:**
- `limit` (optional): Max entries to return, 1-50 (default: `20`)

**Response:**
```json
{
  "activities": [
    {
      "id": 1,
      "user_id": 10,
      "username": "john",
      "action": "stream_started",
      "details": "Started streaming 'Gaming Session'",
      "created_at": "2026-02-08T12:00:00"
    }
  ]
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

#### GET /api/services/:id/health
Check health of a specific service. Runs a live health check via the service's plugin (TCP connect, HTTP probe, etc.).

**Response:**
```json
{
  "healthy": true,
  "message": "Service is responding on port 8554"
}
```

**Error (plugin not found):**
```json
{
  "healthy": false,
  "message": "Plugin not found: unknown_plugin"
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

### Traffic Metrics (Admin)

#### GET /api/metrics
Get overall traffic metrics summary including active connections, bandwidth, and request counts.

**Response:**
```json
{
  "uptime_seconds": 3600,
  "total_connections": 42,
  "active_connections": 3,
  "total_bytes_sent": 1048576,
  "total_bytes_received": 2097152,
  "total_bytes": 3145728,
  "total_errors": 0,
  "unique_users_today": 5,
  "active_users": 2,
  "connections_per_hour": 42.0,
  "bandwidth_per_hour": 3145728,
  "services_active": 1,
  "started_at": "2026-02-07T00:00:00+00:00"
}
```

---

#### GET /api/metrics/services
Get traffic breakdown per service.

---

#### GET /api/metrics/active
Get list of currently active connections with user and service info. Tracks both WebSocket service connections and chat connections.

---

#### GET /api/metrics/timeseries
Get time-series data for traffic metrics. Data is recorded every 60 seconds and retained for 24 hours. Used by admin panel charts (Connections & Users line chart, Bandwidth bar chart).

**Query Parameters:**
- `hours` (optional): Number of hours to look back, 1-24 (default: `1`)

**Response:**
```json
{
  "data": [
    {
      "timestamp": "2026-02-07T01:00:00+00:00",
      "connections": 3,
      "active_users": 2,
      "bytes_sent": 1024,
      "bytes_received": 2048
    }
  ]
}
```

> **Note:** `bytes_sent` and `bytes_received` are per-interval deltas (bandwidth per minute), not cumulative totals.

---

#### GET /api/metrics/top
Get top users and services by traffic volume.

---

### Server Logs (Admin)

#### GET /api/logs
Get log file contents.

**Query Parameters:**
- `lines` (optional): Number of lines to return (default: 100)
- `file` (optional): Log file name (default: current)

---

#### GET /api/logs/files
List available log files.

---

#### GET /api/logs/settings
Get current log configuration settings.

---

#### PUT /api/logs/settings
Update log settings (admin only).

**Request:**
```json
{
  "level": "info",
  "max_size": 10485760,
  "backup_count": 5
}
```

---

### Shodan Integration (Admin)

#### GET /api/shodan/info
Get Shodan API key status and account info.

---

#### POST /api/shodan/api-key
Set the Shodan API key (persists to database).

**Request:**
```json
{
  "api_key": "your-shodan-key"
}
```

---

#### GET /api/shodan/lookup/{ip}
Look up an IP address in Shodan.

---

#### GET /api/shodan/search
Search Shodan.

**Query Parameters:**
- `q` (required): Search query

---

### Vulnerability Scanner (Admin)

Scan hosts and services for known vulnerabilities using nmap and CVE databases.

#### GET /api/vuln/status
Get vulnerability scanner status (nmap availability, NVD API configuration).

**Response:**
```json
{
  "nmap_available": true,
  "nvd_api_configured": false,
  "known_cves_count": 42
}
```

---

#### GET /api/vuln/scan/{host}
Scan a host for open ports and vulnerabilities.

**Query Parameters:**
- `ports` (optional): Port range to scan (default: "1-1000")
- `scan_type` (optional): `basic`, `version`, `vulnerability`, or `full` (default: `version`)

---

#### GET /api/vuln/scan-service/{service_id}
Scan a Portal service's host and port for vulnerabilities.

**Query Parameters:**
- `scan_type` (optional): `basic`, `version`, `vuln`, `full` (default: `version`)

---

#### GET /api/vuln/cve/{cve_id}
Look up detailed information about a specific CVE from NVD.

---

#### GET /api/vuln/mitigations/{cve_id}
Get mitigation steps for a specific CVE.

**Response:**
```json
{
  "cve_id": "CVE-2024-6387",
  "mitigations": [...]
}
```

---

#### GET /api/vuln/known-cves
List all known CVEs in the local database, sorted by CVSS score.

---

#### GET /api/vuln/search
Search CVEs by keyword.

**Query Parameters:**
- `q` (required): Search keyword (product, vendor, etc.)

---

#### POST /api/vuln/nvd-api-key
Set the NVD API key for higher rate limits (persists to database).

**Request:**
```json
{
  "api_key": "your-nvd-key"
}
```

---

### Certificate Management (Admin)

Manage TLS certificates from the admin panel or via API. Supports custom uploads, self-signed generation, and Let's Encrypt automation.

#### GET /api/certs/info
Get current certificate details. Never exposes private key material.

**Response:**
```json
{
  "subject": {"CN": "portal.example.com", "O": "..."},
  "issuer": {"CN": "...", "O": "..."},
  "sans": ["portal.example.com", "*.example.com"],
  "not_before": "2026-02-10T00:00:00+00:00",
  "not_after": "2027-02-10T00:00:00+00:00",
  "days_until_expiry": 365,
  "is_expired": false,
  "is_self_signed": false,
  "fingerprint_sha256": "AB:CD:...",
  "key_type": "RSA 4096",
  "method": "custom"
}
```

---

#### POST /api/certs/upload
Upload a custom PEM certificate and private key. Validates that the cert and key match before saving.

**Request:**
```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

**Response:** `{"status": "success", "message": "...", "cert_info": {...}}`

---

#### POST /api/certs/self-signed
Generate a self-signed RSA 4096-bit certificate with SANs for hostname, localhost, and 127.0.0.1.

**Request:**
```json
{
  "hostname": "portal.example.com",
  "validity_days": 365
}
```

---

#### POST /api/certs/letsencrypt
Request a Let's Encrypt certificate via certbot standalone mode. Requires port 80 accessible from the internet. Installs auto-renewal hook.

**Request:**
```json
{
  "hostname": "portal.example.com",
  "email": "admin@example.com"
}
```

---

#### POST /api/certs/apply
Validate staged certificates and trigger a graceful server restart (2-second delay). All active connections will be briefly interrupted.

---

### Server Settings (Admin)

#### GET /api/settings/hostname
Get current server hostname and port.

**Response:** `{"hostname": "portal.example.com", "port": 443}`

---

#### PUT /api/settings/hostname
Update the server hostname in the configuration.

**Request:**
```json
{
  "hostname": "new-hostname.example.com"
}
```

---

### System Monitor (Admin)

#### GET /api/sysmon/processes
List running processes sorted by CPU, memory, PID, or name.

**Query:** `?sort=cpu&limit=100`

**Response:** Array of process objects:
```json
[{
  "pid": 1234,
  "name": "python",
  "username": "root",
  "cpu_percent": 2.5,
  "memory_percent": 1.0,
  "memory_rss": 86216704,
  "status": "running",
  "cmdline": "/usr/bin/python server.py serve",
  "create_time": 1770762758.51
}]
```

---

#### GET /api/sysmon/processes/:pid
Get detailed info for a single process.

---

#### POST /api/sysmon/processes/:pid/kill
Kill a process. Refuses PID 1, kernel threads, and the portal process.

**Request:** `{"signal": "SIGTERM"}` (SIGTERM, SIGKILL, SIGINT, SIGHUP)

**Response:** `{"success": true, "message": "Sent SIGTERM to python (PID 1234)"}`

---

#### GET /api/sysmon/services
List systemd services.

**Query:** `?filter=running` (running, failed, or search text)

**Response:** Array of service objects:
```json
[{
  "name": "portal",
  "unit": "portal.service",
  "load_state": "loaded",
  "active_state": "active",
  "sub_state": "running",
  "description": "Open Relay Portal"
}]
```

---

#### GET /api/sysmon/services/:name
Detailed service status including PID, memory, start time, enabled state.

---

#### GET /api/sysmon/services/:name/logs
Service journal logs.

**Query:** `?lines=50` (10-500)

**Response:** `{"logs": "...", "service": "portal", "lines": 50}`

---

#### POST /api/sysmon/services/:name/control
Control a systemd service.

**Request:** `{"action": "restart"}` (start, stop, restart, enable, disable)

**Response:** `{"success": true, "message": "Service portal restart successful"}`

---

#### GET /api/sysmon/network
Network interface information (IPs, MAC, speed, TX/RX bytes).

---

#### GET /api/sysmon/ports
Listening TCP ports with process info.

**Response:** Array of port objects:
```json
[{"proto": "tcp", "address": "0.0.0.0", "port": 443, "pid": 1234, "process": "python"}]
```

---

### File Manager (Admin)

#### GET /api/files/list
List directory contents (sorted: directories first).

**Query:** `?path=/home`

**Response:** Array of file entries:
```json
[{
  "name": "portal",
  "type": "directory",
  "size": 4096,
  "permissions": "drwxr-xr-x",
  "modified": 1770762210.45,
  "owner": "dustin",
  "group": "dustin"
}]
```

---

#### GET /api/files/info
File stat information.

**Query:** `?path=/home/file.txt`

---

#### GET /api/files/read
Read text file content (max 5MB).

**Query:** `?path=/home/file.txt`

**Response:** `{"content": "file contents...", "path": "/home/file.txt"}`

---

#### GET /api/files/download
Download file as streaming attachment.

**Query:** `?path=/home/file.txt`

---

#### POST /api/files/upload
Upload file (multipart form: `path` + `file`).

---

#### POST /api/files/write
Write/save text file.

**Request:** `{"path": "/home/file.txt", "content": "new content"}`

---

#### POST /api/files/mkdir
Create directory.

**Request:** `{"path": "/home/new-folder"}`

---

#### POST /api/files/rename
Rename/move file or directory.

**Request:** `{"old_path": "/home/old", "new_path": "/home/new"}`

---

#### DELETE /api/files/delete
Delete file or empty directory.

**Query:** `?path=/home/file.txt`

---

### SFTP Browser (Per-User)

SFTP endpoints require the user to own the connection. Only SSH/SFTP connection types are eligible.

#### GET /api/sftp/:conn_id/list
List remote directory contents.

**Query:** `?path=/`

---

#### GET /api/sftp/:conn_id/read
Read remote text file (max 5MB).

**Query:** `?path=/home/file.txt`

**Response:** `{"content": "...", "path": "/home/file.txt"}`

---

#### GET /api/sftp/:conn_id/download
Download remote file.

**Query:** `?path=/home/file.txt`

---

#### POST /api/sftp/:conn_id/upload
Upload to remote (multipart form: `path` + `file`).

---

#### POST /api/sftp/:conn_id/write
Write remote text file.

**Request:** `{"path": "/home/file.txt", "content": "new content"}`

---

#### POST /api/sftp/:conn_id/mkdir
Create remote directory.

**Request:** `{"path": "/home/new-folder"}`

---

#### POST /api/sftp/:conn_id/rename
Rename/move remote path.

**Request:** `{"old_path": "/home/old", "new_path": "/home/new"}`

---

#### DELETE /api/sftp/:conn_id/delete
Delete remote file or empty directory.

**Query:** `?path=/home/file.txt`

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
| `/watch/{id}` | Stream viewer with integrated chat |
| `/live` | Public live streams (unauthenticated) |
| `/docs` | API documentation (interactive) |
| `/api-docs` | API documentation (alias) |
| `/terminal/{id}` | Terminal UI (shell selector for local terminal and SSH user connections) |
| `/vnc/{id}` | VNC viewer |
| `/spice/{id}` | SPICE viewer |
| `/proxmox/{id}` | Proxmox management |
| `/github/{id}` | GitHub browser |
| `/media/{id}` | Media player |
| `/about` | About page (feature guide) |

### Navigation Structure

All pages use a standardized navbar with a responsive hamburger menu on mobile:
```
Dashboard | Chat | Streams | API Docs | About | [username] | Logout
```

### Dashboard Tabs

| Tab | Visibility | Description |
|-----|------------|-------------|
| Services | Admin only | Backend services (proxy routes and managed processes) |
| My Connections | All users | Personal SSH, VNC, RDP, database connections. Includes Quick Add bar with connection presets. |
| My Streams | All users | Personal streaming configurations |
| My VODs | All users | Remote VOD file management (SFTP) |
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
- Registration: 1 account per IP per 24 hours
- Chat messages: 5 per 5 seconds per user

When rate limited, response includes:
```json
{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```
