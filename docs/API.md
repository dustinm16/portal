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
4. **Stream Key** - `Authorization: Stream-Key live_xxx` or `X-Stream-Key: live_xxx` (publishing only since 1.16.0: it signs in on no route, and a request that offers one is refused (`403` where the route reports why, otherwise `401`); see below)

An API key must be sent with the `Api-Key` scheme or the `X-API-Key` header. `Authorization: Bearer` accepts JWTs only, so a `portal_...` key sent as a Bearer token is rejected with `401`. Checking a key that has not been used since the server started is deliberately rate limited: when too many such checks are pending for one key, the request is answered with `503` and a `Retry-After` header instead of `401`. Retry after the given delay; the key itself is not affected.

### Stream Keys (publishing only)

**A stream key authorises publishing only (changed in 1.16.0).** Use it for:
- Publishing the stream (RTMP authentication; WHIP only where the WebRTC media port is reachable, see Streaming Configuration)
- The stream event call MediaMTX makes (`/api/stream/event`)

It is **not** a way to sign in as the stream's owner, on any route: no route of the portal accepts a stream key as a login, and a request that offers one as its credential is refused (`403` where the route reports why, otherwise `401`). Every route under `/api/streams` and `/api/me/follows` answers a stream key with `403`: listing, reading, changing and deleting streams, rotating keys, RTMP tokens, thumbnails, relays, bans, follows and the live list. These routes need a browser session, or a token or API key with the all-scope `*`; a narrowly scoped API key (for example `services:read`) gets `403` as well. There is no streams-specific API key scope, and a non-administrator's API key is always made with the scoped `services:read,access:*` set, so a non-administrator has no API-key path to these routes. The playback routes under `/api/stream/{key}/` (HLS, thumbnail, info, WHEP and its sessions) ignore a stream key and answer `404` as described under Access; the publish-side routes (`/api/stream/auth`, `/api/stream/event` for MediaMTX on the host, and WHIP, which takes the `live_` key in its URL) keep working; `/api/streams/open` needs no credential.

**Example - what no longer works:**
```bash
# 403: a stream key does not list or manage streams
curl -H "X-Stream-Key: live_abc123..." https://portal.example.com/api/streams

# works: a full-access API key
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
username=admin&password=secret&remember_me=on
```

| Field | Required | Description |
|-------|----------|-------------|
| `username` | Yes | Account username |
| `password` | Yes | Account password |
| `totp_code` | No | 2FA code (required if 2FA is enabled) |
| `remember_me` | No | If `on`, session cookie lasts 30 days instead of 24 hours |

**Response:** Redirect to `/dashboard` or error page

---

#### GET /logout
End current session. The chat sockets opened with this session are closed (code 4001), its voice call ends and its in-flight proxied downloads are cut; the account's other sessions are not affected.

**Response:** Redirect to `/login`

#### POST /logout
The same, for a script. With `{"endpoint": "<push endpoint>"}` in the JSON body (never in the URL) it also removes the caller's own push device with that endpoint, even one an earlier session of the member registered; an endpoint of another member removes nothing. Any other body is ignored. **Response:** `200 {"success": true}` and the session cookie is cleared.

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

**Validation:**
- Username: 3-32 characters, alphanumeric + underscores only (`^[a-zA-Z0-9_]+$`)
- Password: minimum 8 characters

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
Create a JWT token with username and password. If the account has 2FA enabled, also send `totp_code` (authenticator code or a one-time backup code). Without it the response is `401` with `"totp_required": true` (sent only after the password verified). After 5 wrong codes in 5 minutes from one address the account gets a 5-minute cooldown for that address (`429` with `Retry-After`); a higher per-account limit across all addresses applies too (20 wrong codes in 15 minutes refuse further codes, from any address, until the oldest of them is 15 minutes old; `Retry-After` states the exact wait; when that happens an entry is added to the account's activity feed). Correct codes are also refused during a cooldown. Scripts that cannot supply a code should use an API key.

**Request:**
```json
{
  "username": "user",
  "password": "pass",
  "totp_code": "123456",
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

Users can revoke only their own tokens. Admins can revoke tokens of users they are allowed to manage (the same hierarchy as password resets), and the credential used must carry the `admin` scope. A token that does not exist, or that the caller may not revoke, returns `404`. What was opened with the revoked token ends with it: its chat sockets (close code 4001), its voice call and its in-flight proxied downloads. The owner's other sessions are not affected, also when an admin revokes one of a member's sessions.

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

#### GET /api/me/sessions
List the signed-in sessions of the current account: browser logins and tokens made through `POST /api/token`. API keys are not sessions; they are listed under `/api/api-keys`.

Needs a browser session or an all-scope (`*`) credential. A stream key or a narrowly scoped API key or token gets `403`. Only the caller's own sessions are returned, and never a token or its id: `id` is an opaque public id (a truncated hash) that only identifies the row for sign-out. Timestamps are ISO-8601 UTC. `device` is read from the stored User-Agent by a local parser ("Unknown device" when there is none, as for sessions that predate the upgrade). `ip` is the address of the login, `last_ip` the address of the last use (written at most once a minute). `current` is true for the credential making the request.

**Response:**
```json
{
  "sessions": [
    {
      "id": "9471afa903bc501b",
      "kind": "browser",
      "name": null,
      "device": "Firefox on Linux",
      "browser": "Firefox",
      "os": "Linux",
      "created_at": "2026-11-18T16:52:29Z",
      "last_used_at": "2026-11-18T16:52:29Z",
      "expires_at": "2026-11-19T16:52:29Z",
      "ip": "203.0.113.7",
      "last_ip": "203.0.113.7",
      "current": true
    }
  ]
}
```

`kind` is `browser` for a login session and `token` for a token made through the API (`name` is then its name).

---

#### DELETE /api/me/sessions/{id}
Sign out one session of the current account, by the `id` from the list. Same credential rules as the list. The session making the request cannot be signed out here (`400`, use logout); an id that is unknown or belongs to someone else returns `404`. The sockets, voice call and in-flight proxied downloads opened with that session end at once (close code 4001); the other sessions are not affected.

**Response:**
```json
{ "status": "revoked" }
```

---

#### POST /api/me/sessions/revoke-others
Sign out every session of the current account except the one making the request (browser sessions and tokens made through the API). API keys and stream keys are not revoked, and the sockets opened with them stay open. Same credential rules as the list. A credential that is not itself a session (an all-scope API key) keeps all of its own sockets and signs out every session.

**Response:**
```json
{ "status": "ok", "revoked": 2, "websockets_closed": 1 }
```

---

#### POST /api/users/{id}/sessions/revoke
Admin "sign out everywhere": revoke every browser session and token of one user and close what was opened with them. Needs the admin role (read from the database, so someone just promoted can use the session they already hold) and a full-scope credential (a browser session, or a token or key made with `*`; a stream key or scoped key gets `403`), and the same role hierarchy as password resets (a plain admin cannot act on an admin or superadmin; `403`). API keys and stream keys of the user are not revoked. On the caller's own account the session being used is kept (`kept_current_session` is true). Recorded in the audit log as `sessions_revoke`. `404` for an unknown user.

**Response:**
```json
{ "status": "ok", "revoked": 3, "kept_current_session": false }
```

---

#### Web push (1.19.0)
A push is sent for a direct message, an @mention or @everyone and a followed stream going live, only to a member with a device and no open chat socket; the payload has no message text and no sender name (see the README upgrade notes for 1.19.0). The device routes need a **browser session or a bearer token with the user's full scope**; API keys (even `*`), stream keys, a token given in the URL and narrow tokens get `403`.

- `GET /api/push/config` returns `{"enabled": true, "public_key": "<base64url VAPID key>", "max_devices": 10, "worker_url": "/sw.js", "worker_scope": "/push-sw/"}`; `enabled` is false (and `public_key` null) while the feature is switched off or the key is unavailable.
- `GET /api/push/subscriptions` returns `{"devices": [{"id", "label", "service", "created_at", "last_success_at", "failure_count", "this_session"}]}`: the caller's own devices, never the endpoint or the keys.
- `POST /api/push/subscriptions` with a `PushSubscription` as JSON (`{"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}}`). `201 {"status": "created"}`, `200 {"status": "updated"}` for a known endpoint. `400` for an endpoint that is not `https` on port 443 to an allowed push service, one whose name resolves to a private, loopback, link-local or metadata address, or keys that are not a P-256 point and a 16 byte secret; `403` while the feature is off; `409` at 10 devices or when the endpoint belongs to another account with other keys; `429` after 10 lookups a minute.
- `DELETE /api/push/subscriptions/{id}` removes one of the caller's own devices (`404` otherwise). `POST /api/push/unsubscribe` with `{"endpoint": "..."}` removes the caller's device with that endpoint and always answers `{"status": "ok"}`. `DELETE /api/push/subscriptions` removes all of the caller's devices: `{"status": "ok", "removed": 2}`.
- Superadmin (the same credential rule, and the account must be a superadmin): `GET /api/admin/push` returns `{"enabled", "default_hosts", "allowed_hosts", "subject", "effective_subject", "device_count", "key_state", "key_problem"}` (`key_state` is `ok`, `none`, `unreadable` or `plain`; `key_problem` says why push stays off when the stored key cannot be decrypted); `PUT /api/admin/push` takes any of `enabled` (boolean), `allowed_hosts` (host names or `*.suffix`, no IP addresses, `localhost` or internal names; added to the built-in list) and `subject` (an `https://` address or null); changing `allowed_hosts` needs a superadmin's browser login session (a bearer token gets `403`, as for the webhook `allow_private` switch) and is audited with the new list, the other fields work with a bearer token as before; `POST /api/admin/push/test` sends a test push to the caller's own devices and returns `{"devices": 1, "results": [{"id", "outcome", "status"}]}` where `outcome` is `sent`, `gone`, `slow_down`, `paused`, `failed`, `pruned`, `error`, `refused`, `rate_limited`, `staged` or `unavailable`. `POST /api/admin/push/reset-key` with `{"confirm": true}` replaces the VAPID key pair and deletes every device of every member (they must turn the feature on again); it needs a superadmin's browser login session (a token or key gets `403`), is audited (`push_key_reset`) and is the way out when the stored key cannot be decrypted. `POST /api/push/subscriptions` with `"rebind": true` in the body only ties a device this member already holds (same endpoint and keys) to the calling session and answers `200`, or `404` when the member does not hold it; it never registers or moves a device, needs no name lookup and is not counted against the subscribe limit. When the endpoint and both keys belong to a different member (this browser, signed in as someone else now), that member's device is deleted and the answer is still `404`. A subscribe by a session that has ended answers `401`. A device records when a signed-in session last announced it (a subscribe, or a re-announcement with `"rebind": true`); when its registering session has expired, is gone or was never recorded and no session announced it for 30 days, nothing is sent to it and the periodic cleanup of expired sessions deletes it. A device whose session is live is not affected, and a phone that opens the portal signed in at least once a month keeps working.
- `GET /api/push/prefs` returns `{"prefs": {"dm": true, "mention": true, "golive": true}, "kinds": ["dm", "mention", "golive"]}`, the caller's own switches (all on until switched off). `PUT /api/push/prefs` takes one or more of those keys with `true` or `false` and returns the full set; an unknown key, a non-boolean value or an empty body is `400`. Same credential rule as the device routes.
- `GET /sw.js` and `GET /manifest.webmanifest` need no session and are the same for everyone. The worker has `push` and `notificationclick` handlers only, `Cache-Control: no-cache` and `Service-Worker-Allowed: /push-sw/`.

A device belongs to the session that registered it: it is deleted when that session is revoked, and nothing is sent to it while the session is not live.

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

### Invite Code Management (Admin)

#### GET /api/admin/invite-code
Get all invite codes (daily + custom). Returns both the auto-generated daily code and any custom codes created by admins.

**Response:**
```json
{
  "daily_code": {
    "code": "ABC123",
    "expires_at": "2026-02-07T00:00:00Z"
  },
  "custom_codes": [
    {
      "id": 1,
      "code": "WELCOME2026",
      "type": "timed",
      "uses": 5,
      "max_uses": null,
      "expires_at": "2026-03-01T00:00:00Z",
      "is_active": true,
      "created_by": "admin",
      "created_at": "2026-02-10T12:00:00Z"
    }
  ]
}
```

---

#### POST /api/admin/invite-codes
Create a new invite code.

**Request:**
```json
{
  "code": "WELCOME2026",
  "type": "timed",
  "max_uses": 10,
  "expires_hours": 48
}
```

**Code Types:**

| Type | Description |
|------|-------------|
| `daily` | Regenerates automatically each day |
| `single_use` | Deactivates after one registration |
| `timed` | Active until expiry time (set via `expires_hours`) |

**Response (201):**
```json
{
  "id": 2,
  "code": "WELCOME2026",
  "type": "timed",
  "max_uses": 10,
  "expires_at": "2026-02-12T12:00:00Z",
  "message": "Invite code created"
}
```

---

#### DELETE /api/admin/invite-codes/{id}
Deactivate an invite code. Does not delete the record (preserves registration history).

**Response:**
```json
{
  "success": true,
  "message": "Invite code deactivated"
}
```

---

#### GET /api/admin/invite-codes/{id}/registrations
View all user registrations that used a specific invite code.

**Response:**
```json
{
  "code": "WELCOME2026",
  "registrations": [
    {
      "user_id": 15,
      "username": "newuser",
      "registered_at": "2026-02-11T08:30:00Z",
      "ip_address": "redacted"
    }
  ],
  "total": 1
}
```

---

### API Keys

#### POST /api/api-keys
Create a new API key.

A key cannot create keys: a request authenticated with an API key (any scopes) gets `403`. Use a browser session or a bearer token from `POST /api/token`.

**Request:**
```json
{
  "name": "My Script",
  "scopes": "services:read",
  "expires_days": 90,
  "allowed_cidrs": ["203.0.113.0/24", "2001:db8::/32"]
}
```

- `name` - required, unique per user.
- `scopes` - comma-separated text or a list, default `*`. Every scope is checked against the scope registry (below); an unknown one is a `400`. Only admins can choose scopes: for a non-admin user a valid request is accepted but the key always gets `services:read,access:*`.
- `expires_days` - a whole number of days from 1 to 3650, or `"never"`. **When omitted (or `null`) the key expires in 90 days.** `0` also means no expiry (kept for old scripts). A value that is not a number of days, is negative or is above 3650 is a `400` (it used to be ignored, which meant "never"). The older spelling `expires_in_days` is read when `expires_days` is absent.
- `allowed_cidrs` - optional, a list or comma-separated text of at most 10 addresses or networks, IPv4 or IPv6 (`203.0.113.0/24`, `2001:db8::/32`, a bare address is a /32 or /128; host bits are cleared). The key then works only from those addresses, judged by the address the portal sees (see the proxy-trust note below); from any other address it answers the same `401` as a wrong key. A `/0` network is a `400`; write `"any"` (alone) for a key that works from anywhere, which is also what omitting it means. Bad input is a `400`.

**Response (201):**
```json
{
  "id": 1,
  "name": "My Script",
  "key": "portal_a1b2c3d4...",  // Only shown once!
  "prefix": "portal_a1b",
  "scopes": "services:read",
  "expires_at": "2027-02-18T00:00:00+00:00",
  "expires_days": 90,
  "allowed_cidrs": ["203.0.113.0/24", "2001:db8::/32"],
  "created_ip": "198.51.100.7",
  "warning": "Save this key now - it cannot be retrieved later!"
}
```

A key with scope `*` and no expiry also carries `expiry_warning` (text); the key is still created. Creating a key writes the security event `api_key_created` (scopes, expiry and the binding, never the key).

Keys are `portal_` followed by 64 hex characters. Only an Argon2id hash and the 10-character prefix (`portal_` + 3 hex) are stored; the full key cannot be recovered, so a lost key must be replaced. A key authenticates while it is not revoked, not past `expires_at` and used from an allowed address; each successful use updates `last_used_at` and `last_used_ip` (written at most once a minute per key), which is the quickest way to confirm a key is actually being used.

**Address binding and proxy trust.** The address checked is the one `get_client_ip` returns: the connecting address, or the `CF-Connecting-IP` / `X-Forwarded-For` value when the connection comes from a proxy listed in `TRUSTED_PROXIES`. If that setting is wrong, every request looks like one address (the proxy's) and a bound key stops working for everybody. **Before binding keys, check that the proxy-trust self-check is clean** (`GET /api/admin/proxy-trust` reports `suspect: false`, and the admin Overview shows no Proxy Trust note), then bind one key and test it. A bound key is refused when the address is unknown. A refusal for the address is recorded as the security event `api_key_ip_denied` (result `address_not_allowed`, with the key id and prefix; aggregated per source, minute and key: at most 5 distinct keys per address and minute get a row of their own under the key's owner, further ones are folded into one row of that address with no account or key); the caller only sees the generic `401`.

**Verifying a key** - any authenticated endpoint works; private search is a convenient one:
```bash
curl -H "Authorization: Api-Key $PORTAL_KEY" \
  "https://your-domain/search/search?q=test&format=json"
```
`200` with a `results` array means the key is valid. `401` means the key is wrong, revoked, expired, used from an address it is not bound to, or was sent as `Bearer`. `503` means the key is fine but SearXNG is disabled or stopped.

---

#### GET /api/api-keys/scopes
The scopes a key can carry, for the key window's picker.

**Response:**
```json
{
  "scopes": [
    {"scope": "*", "description": "Everything the account may do...", "kind": "built-in"},
    {"scope": "admin", "description": "Administrator routes...", "kind": "built-in"},
    {"scope": "services:read", "description": "...", "kind": "built-in"},
    {"scope": "access:*", "description": "...", "kind": "built-in"}
  ],
  "can_choose": true,
  "limited_scopes": ["services:read", "access:*"],
  "default_expiry_days": 90,
  "max_cidrs": 10
}
```

The registry is the module `apikey_policy.py`; it lists every scope the portal's own code checks. Scopes that an administrator made up for a service (`required_scopes`) are also accepted, and are listed (kind `service`) for administrators only; a wildcard such as `relay:*` is accepted when it covers one of them. A scope is compared and stored exactly as written (case included; a service scope such as `Relay:Media` or `files/read` is accepted as the service lists it, up to 128 characters, no control characters or commas), and only a caller who may choose scopes (an administrator) can name a service scope; for anybody else a service scope is as unknown as a made-up one (`400`). An empty `scopes` (`[]` or `""`) is a `400`; leave the field out for the default `*`. An `allowed_cidrs` entry with an IPv6 zone id (`fe80::1%eth0`) is a `400`. Two live keys may share the first 10 characters (12 bits of the key); every non-revoked key with the prefix is checked (at most 4), and a failed check is the same generic `401`. `can_choose` is false for a non-admin user, whose keys always get `limited_scopes`.

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
      "key_prefix": "portal_a1b",
      "scopes": "services:read",
      "allowed_cidrs": ["203.0.113.0/24"],
      "created_at": "2026-02-05 00:00:00",
      "created_ip": "198.51.100.7",
      "last_used_at": "2026-02-05 12:00:00",
      "last_used_ip": "203.0.113.9",
      "expires_at": "2026-05-06T00:00:00+00:00",
      "revoked": 0,
      "stale": false
    }
  ],
  "stale_after_days": 90
}
```

`created_ip` and `last_used_ip` are shown to the key's owner only; they are empty for a key made or used before 1.18.0. `stale` (and `stale_after_days`) appear only for an administrator (database role admin or superadmin): a key that is not revoked, not expired and has not been used for 90 days (or was never used and is 90 days old). For anybody else both are absent.

---

#### POST /api/api-keys/:id/revoke
Revoke an API key (soft delete). WebSockets, voice calls and in-flight proxied downloads that were opened with that key end at once; the account's sessions and other keys are not affected.

**Response:**
```json
{
  "success": true
}
```

---

#### DELETE /api/api-keys/:id
Permanently delete an API key. What was opened with the key (WebSockets, voice calls, in-flight proxied downloads) ends at once, as for a revoke.

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

Other browser sessions and tokens of the account are revoked and their WebSocket connections are closed; the session making the request stays signed in. API keys are **not** revoked: they are separately managed credentials (often used by scripts) and stay valid, together with any WebSocket opened with them, until you revoke them under `/api/api-keys`. If you suspect an account is compromised, revoke its API keys as well. An admin password reset (below) does revoke API keys.

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
  "nickname": "JohnN"
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

Changing a role signs the user out: their sessions, tokens and API keys are revoked and their open WebSocket connections are closed, so credentials created under the old role do not keep its scopes.

---

#### POST /api/users/:id/reset-password
Reset user password (admin only).

Signs the user out everywhere: all of their sessions, tokens and API keys are revoked and their open WebSocket connections are closed. When an admin resets their own password, the credential making the request is kept. The body must be a JSON object, otherwise `400` is returned.

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

> **Opaque IDs:** Connection IDs are opaque, URL-safe string tokens (e.g., `aB3x_kLm9pQ2rStU`). They are not sequential integers. Use the `id` field returned by the API in all subsequent requests.

#### GET /api/connections
List user's remote connections. Sensitive config fields (passwords, private keys) are **redacted** — replaced with boolean `has_<field>` flags.

**Response:**
```json
{
  "connections": [
    {
      "id": "aB3x_kLm9pQ2rStU",
      "name": "Home Server",
      "type": "ssh",
      "host": "192.168.1.100",
      "port": 22,
      "config": {"username": "john", "auth_method": "password", "credential_mode": "stored", "has_stored_password": true},
      "icon": "terminal",
      "created_at": "2026-02-01T00:00:00Z"
    }
  ]
}
```

**Redacted fields:** `password`, `private_key`, `private_key_path`, `auth_header`, `psk` are never returned. If a field has a value, `has_<field>: true` is returned instead. For `ssh` and `sftp` connections the password is the **stored password** (1.18.0) and the flag is `has_stored_password: true` (the older `has_password` is no longer sent for these two types; other types keep `has_<field>`). The same redaction applies to every route that returns a connection (list, details, `/connect`) for the owner and for a user the connection is shared with; the value is never in any response, WebSocket frame, log line or error text.

**Stored SSH password (1.18.0).** An `ssh` or `sftp` connection's config takes `credential_mode` (`"prompt"`, the default, or `"stored"`) and `password`. With `"stored"` the terminal opens without asking for a password and the SFTP browser uses the same password, for the owner and for everyone the connection is shared with; with `"prompt"` the terminal asks every time and the file browser reports that no password is stored. The password is write-only and only the owner's `POST`/`PUT` can set it (a user the connection is shared with gets `404` from `PUT`). Rules: a `credential_mode` other than `prompt` or `stored`, a `password` that is not a string, longer than 1024 characters or holds a NUL, `"stored"` without a password, `"stored"` with `host_key_ignore: true` and a stored password with `auth_method: "key"` answer `400`. On `PUT` an absent `password` keeps the stored one, a new `password` replaces it, an empty `password` or `credential_mode: "prompt"` clears it, and changing `host`, `port` or `config.username` clears it unless the same request carries a new `password` (the response then has `"stored_password_cleared": true` and the mode falls back to `"prompt"`; it also has it when you clear the password yourself with `credential_mode: "prompt"` or an empty `password`). A `password` sent without `credential_mode` never switches a connection to `"stored"`: on a row whose mode is `"prompt"` it answers `400`; on `POST`, or on a row that has no mode, it is kept and the row stays without a mode (the terminal still asks, the file browser uses the password); on a `"stored"` row it replaces the password. Only `credential_mode: "stored"` makes the terminal use a password without asking. The password is only sent to a host whose key is pinned and verified: an unpinned or changed key refuses the connect before any credential goes out (see the host-key route), and a connection with `host_key_ignore: true` is refused when it would use a stored password. Revoking or expiring a share closes the grantee's open terminal and SFTP connections (close code `4010`).

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
| Remote Access | `ssh`, `vnc`, `rdp` (Desktop over the VNC protocol; not Windows Remote Desktop), `spice`, `telnet` |
| File Transfer | `sftp` |
| Virtualization | `proxmox` |
| Web Panels | `home_assistant`, `portainer`, `truenas`, `pfsense`, `http`, `https`, `http_proxy` |
| Databases | `database`, `redis`, `mongodb`, `elasticsearch` |
| Dev Tools | `jupyter`, `grafana`, `prometheus`, `github` |
| Media | `mediamtx`, `stream` |
| Game Servers | `minecraft_rcon` |
| Network | `tcp_tunnel`, `secure_tunnel`, `vpn_tunnel` |
| Generic | `custom` |

---

#### GET /api/connections/{id}
Get connection details. `{id}` is the opaque string token. Sensitive config fields are redacted (same as list endpoint).

---

#### PUT /api/connections/{id}
Update connection. `{id}` is the opaque string token. Config fields are merged server-side with existing config — sensitive fields not included in the request are preserved from the encrypted database record. Credentials never need to round-trip through the client.

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

`"stored_password_cleared": true` is added whenever a stored SSH password was removed: because the request asked for it (`credential_mode: "prompt"` or an empty `password`), because the host, port, username or connection type changed, or because the connection now uses key authentication, and the request did not carry a new one. The edit form sends `credential_mode` only when the "Prompt each time" switch was changed, so a rename of an older connection that holds a password (and has no mode) keeps it. A connection moved to a type other than `ssh` or `sftp` keeps no stored password and no `credential_mode` (a `password` in the same request stays as the new type's own). See "Stored SSH password" above.

---

#### DELETE /api/connections/{id}
Delete connection. `{id}` is the opaque string token.

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

#### POST /api/connections/{id}/host-key/accept
Trust (pin) the SSH host key of an `ssh`/`sftp` connection. **Owner only** (a user the connection is shared with gets 404). The caller's credential must carry its user's full scope: a browser session or an all-scope (`*`) token or API key. Stream keys, scoped API keys and scoped tokens get 403, and the prompt they receive has `can_accept: false` and no `accept_url` or `accept_token`. Body `{"fingerprint": "SHA256:...", "host", "port", "token"}` where all four come from the `host_key` prompt (`fingerprint` is 43 base64 characters, as `ssh-keygen -lf` prints it; `token` is the prompt's `accept_token`) -> `{"status": "accepted", "fingerprint": "..."}`. A missing or malformed `fingerprint`, `host` or `port` gives 400; a missing, forged or expired `token` gives 409 like any other stale prompt. HTTP 409 `{"error", "type": "host_key_stale"}` means the prompt is stale: the connection's host or port changed, the fingerprint is not the one the portal presented (or the token expired after 30 minutes), or the connection was edited while the prompt was open; connect again for a fresh prompt. The pin is stored in the connection's encrypted config as `host_key_fingerprint`; it cannot be set or overwritten through `PUT /api/connections/{id}`, and changing `host` or `port` clears it. Until a key is pinned (and whenever the server presents a different key) connecting is refused before any credential is sent:
- WebSocket `/ws/user-connection/{id}`: a text message `{"type": "host_key", "state": "unpinned"|"changed", "fingerprint", "expected", "algorithm", "can_accept", "accept_url", "host", "port", "accept_token", "message"}`, then a normal close. `can_accept` is true only for the owner using a full-scope credential; `accept_url`, `host`, `port` and `accept_token` are present only then.
- SFTP routes `/api/sftp/{id}/...`: HTTP 409 with the same body.
- Config `host_key_ignore: true` (boolean) is the explicit per-connection opt-out and skips the check. The older `known_hosts` setting is no longer read.

#### GET /api/connections/{id}/shares
List who a connection is shared with (owner only), live shares only. → `{"shares": [{"user_id", "username", "created_at", "granted_by_username", "expires_at", "expires_in"}]}`. `expires_at` (ISO, `Z`) and `expires_in` (seconds left) are `null` for a share that never expires.

#### POST /api/connections/{id}/shares
Share a connection with users (owner only). Body `{"usernames": ["alice", "bob"], "expires_in": "7d"}` — unknown names and self are skipped. → `{"added": [...], "skipped": [...], "shares": [...]}`. Audited as `connection.share`.

`expires_in` is one of `1h`, `8h`, `1d`, `7d`, `30d`, `90d`, `never`; the server computes the end time. Omitted or `null` means `never` for a new share (the API default, unchanged from before expiry existed; the share dialog preselects `30d` for a new share) and means *keep the current end time* when the user already has a live share (an expired share not yet swept counts as new). Any other value, a non-string, or a body that carries `expires_at` answers 400 and writes nothing. Sharing again with the same user and an `expires_in` replaces the end time. When the time passes the grantee no longer lists the connection and cannot open it (HTTP, SFTP, proxy, `/ws/...`), without waiting for anything; a sweeper (every 60 s) then deletes the row, audits `connection.share_expired` (actor: the grantor) and closes what the grantee holds open through it (WebSockets with close code `4010` "access ended", SFTP connections, proxied calls). The grantee's other sockets are not touched.

#### DELETE /api/connections/{id}/shares/{grantee_id}
Revoke a share (owner only). `{grantee_id}` may be the literal `me` for a grantee removing their own access. Closes what the grantee holds open through it (code `4010`), as does deleting the connection. Audited as `connection.unshare`.

#### GET /api/me/shares
Every live share of every connection the caller owns: `{"shares": [{"connection_id", "connection_name", "connection_type", "user_id", "username", "created_at", "granted_by_username", "expires_at", "expires_in"}]}`. A connection shared with the caller carries `share_expires_at` and `share_expires_in` in `GET /api/connections`.

> A shared connection appears on the grantee's dashboard (`shared: true`, `owner_username`), is usable through the in-browser tools and `/proxy/{id}`, but **not** the raw `/ws` relay. Edit / delete / pin remain owner-only.

---

#### GET /api/users/lookup?q=
Username prefix search for the share / grant pickers. Any authenticated user; returns at most 10 `{id, username}` — no role, email or status.

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
        "auth_method": {"type": "string", "enum": ["password", "key"]}
      }
    }
  }
}
```

---

#### GET /browser?connection={id}
Open the embedded browser for an HTTP proxy connection. `{id}` is the opaque connection token. The connection must use the `http_proxy` plugin type.

The embedded browser provides tabbed browsing, navigation controls (back/forward/refresh), an address bar, and keyboard shortcuts (Ctrl+T new tab, Ctrl+W close tab, Ctrl+Tab switch tabs, Alt+arrows navigate, Ctrl+L focus URL bar). Connections with `browser_mode: true` support multi-site navigation — users can browse any website through the proxy.

A default "Web Browser" connection is created automatically for new users (also available from the connection form's "Web Browser (private search)" preset). Its home page is the portal's own private search (SearXNG at `/search/`, same origin) when that managed service is enabled, falling back to DuckDuckGo when it is not. An explicit `config.home_url` (any same-origin absolute path) overrides this. From the private-search home page, clicking an external result opens a new tab **inside** the embedded browser (routed through the proxy) for `browser_mode` connections, or a real top-level browser tab for single-origin connections.

The page polls `GET /api/me` and watches for a same-origin redirect to `/login`; when the session ends (logout in this or another tab) it navigates the whole window to `/login` so a logged-out user can't keep viewing a rendered page.

---

#### ALL /proxy/{connection_id}/{path}
Reverse proxy passthrough for HTTP connections. `{connection_id}` is the opaque connection token. Proxies all HTTP methods and WebSocket upgrades to the backend. Portal session cookies and Authorization headers are stripped from upstream requests. Proxied HTML receives a JS interceptor that rewrites URLs to stay within the proxy layer.

Headers sent to the upstream: `X-Forwarded-For` and `X-Real-IP` carry the client's address (resolved the same way as for rate limiting), `X-Forwarded-Proto` the scheme the client used (`CF-Visitor` / `X-Forwarded-Proto` are believed only from a trusted proxy), and, only when the connection has `forwarded_host: true` (default off), `X-Forwarded-Host` the portal's configured host name (the client's own `Host` is used only when it names that host, so a client cannot pick the name) and `X-Forwarded-Prefix` the proxy path (`/proxy/{id}`); an app that honours the host without the prefix would write links outside the proxy path. A `?token=` query parameter that authenticated the request is removed before the request (HTTP or WebSocket) is forwarded. Copies of these headers (and of `Forwarded`, `CF-Connecting-IP`, `True-Client-IP` and `X-Client-IP`) sent by the client are never passed on, even when `forward_headers` matches them. Neither are `Authorization`, the portal session cookie, `X-API-Key` or `X-Stream-Key`. In `browser_mode` only `X-Forwarded-Proto` is sent.

Upstream redirects are followed by the portal itself (at most 5 hops, every hop dialled through the outbound host policy, so a redirect to a blocked address is refused); a `Set-Cookie` sent by an intermediate hop is not passed on to the browser. No further hop is made once the member's session was revoked. In general-browsing mode the `3xx` goes to the browser instead, with its `Location` kept under that site's own path (a protocol-relative `//host/path` names that host, with the current site's scheme). A `Location` that still reaches the browser from a single-site connection (a `201`, a `300`) is kept under `/proxy/{id}/`: a value already under it is left as is, an absolute URL on the portal's own host is mapped to its path, and one on the upstream's host with another scheme or port is returned unchanged.

Every upstream `Set-Cookie` is kept: each `Path` is moved under the proxy path, a missing `Path` becomes the proxy root (in `browser_mode` the path of that site, `/proxy/{id}/<origin>/`), and `Domain` is removed. An upstream cookie named like the portal session cookie is dropped.

The connection's `timeout` (5-300 seconds, default 60, out-of-range values are adjusted) is the longest the upstream may stay silent; connecting is limited to 10 seconds. A download that is passed through as it arrives has no total limit and continues while data arrives; a response that is rewritten in memory (HTML, CSS, JavaScript, JSON) must arrive within this time in total. A silent upstream gives `504`. Revoking the member's sessions (password change, admin reset, role change, deletion, signing out, revoking one session or an API key) ends the in-progress downloads opened with them.

In `browser_mode`, the path encodes the full target URL (e.g., `/proxy/{id}/https://example.com/page`), enabling multi-site navigation. Localhost and private IPs are blocked for browser-mode targets.

---

### Private Search (SearXNG)

Portal can run [SearXNG](https://github.com/searxng/searxng) (AGPL-3.0) as an optional managed service, reverse-proxied under `/search/` behind Portal authentication. Endpoints exist only while an admin has added and **enabled** a managed service of type `searxng`; otherwise they return `503`.

#### GET /api/search/status
Returns `{ "available": true|false }` — whether the `searxng` service is enabled and running. Used by the dashboard to show or hide the "Search" nav link and the dashboard search bar's "Internet" toggle. Requires authentication.

#### GET /chat?q=&lt;query&gt;
Deep link from the dashboard search bar's "Portal" mode. `chat.html` opens the message-search panel, runs the query against `/api/chat/search`, and cleans the URL.

#### ALL /search  •  ALL /search/{path}
Auth-gated reverse proxy to the local SearXNG instance. Any authenticated user may use it: session cookie, JWT (`Bearer`) or API key (a stream key signs in nowhere). No scope is checked, so every valid API key can search regardless of its `scopes`. Unauthenticated browser requests redirect to `/login`; unauthenticated API requests (`Accept: application/json` or `?format=json`) get `401`.

Requests are forwarded verbatim — SearXNG mounts its whole app under `/search/` via its `base_url`, so no path rewriting is done. The Portal session cookie and `Authorization` header are stripped from the upstream request. Responses get `Cache-Control: private, no-store`.

```bash
# HTML search UI
GET /search/

# JSON results for automation - API key (recommended for scripts)
curl -H "Authorization: Api-Key $PORTAL_KEY" \
  "https://your-domain/search/search?q=debian&format=json"

# JSON results - JWT access token
curl -H "Authorization: Bearer $TOKEN" \
  "https://your-domain/search/search?q=debian&format=json"
```

Prefer `Authorization: Api-Key` over `X-API-Key` here: the `Authorization` header is stripped before the request reaches SearXNG, while `X-API-Key` is currently forwarded to the local SearXNG process.

| Status | Meaning |
|--------|---------|
| `200` | Results returned |
| `401` | Missing or invalid credentials (wrong, revoked or expired key, or a key sent as `Bearer`) |
| `503` | Credentials accepted, but the `searxng` service is disabled or not running |

JSON output requires `formats: [html, json]` in the generated `settings.yml` (the default for Portal-managed SearXNG).

---

### User Streams

User streams allow broadcasting from OBS or other streaming software. All traffic is encrypted via RTMPS/RTSPS.

**Stream Keys:**
Portal uses two types of keys for stream access control:

| Key Type | Format | Purpose | Visibility |
|----------|--------|---------|------------|
| **Private Key** | `live_xxx...` | Publishing only (OBS/RTMP, WHIP); not accepted on the management API | Owner only |
| **Public Key** | `pub_xxx...` | Read-only viewing access (HLS playback; WebRTC only on a reachable network) | Viewers of public streams |

- **Private key (`stream_key`)**: Used for OBS publishing only (1.16.0); never share this key.
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
  "game": "Optional game, at most 60 characters",
  "is_public": false
}
```

`game` (1.17.0) is a string of at most 60 characters or `null`; control characters are removed (tab and line break become a space), an empty string clears it, and a longer value, a lone surrogate or a non-string is a `400`. The same rules apply to `PUT /api/streams/{id}`. A member sees the game of any stream they may see (the public listing, the detail route and the live list); it is never part of a stream the member may not watch.

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
- **Non-owner (private stream)**: No keys visible, except to an administrator (the `admin` or `superadmin` role with a full credential, not a scoped key), who sees the `public_key` because the viewing rule lets them watch it. The `stream_key` (publish key) and the key hashes are never shown to a non-owner.

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

Only `name`, `description`, `is_public`, `allow_unauthenticated`, `rtmp_enabled`, `game`, `golive_message` and `golive_audience` are taken from the request; server-owned fields (`chat_channel_id`, `is_live`, `viewer_count`, `started_at`, `ended_at`) are ignored, and a request with none of the editable fields answers `400`. Setting `is_public` to `false` also removes members who can no longer read the stream's chat from its room.

**`golive_message` (1.16.0):** the owner's go-live message, a string of at most 200 characters (`400` above that, or when it is not a string or `null`; a body-sized value is refused before it is cleaned, so a message longer than 1000 characters is refused even if control characters would shrink it below 200); control characters are removed (tab and line break become a space) and an empty string or `null` clears it, so the default (`{title} just went live`) is used. Only `{streamer}`, `{title}`, `{game}` (1.17.0, empty when the stream has no game) and `{url}` are replaced, by literal text in a single pass; any other brace text (for example `{0.__class__}`) is kept as typed. It is the text of the go-live notification and the `message` of the `stream.live` webhook payload. A stream is announced at most once per 10 minutes (stored in the database), however often it starts again. It can be sent to `POST /api/streams` as well as `PUT /api/streams/{id}`; both validate it the same way. The field is returned with the stream.

Changing `is_public` from `true` to `false` rotates the stream's playback key automatically; the old key stops resolving at once. The response then also carries the new key as `public_key` (alongside the updated `stream` object).

**`golive_audience` (1.16.0):** who is notified when the stream goes live, `"followers"` (members who follow it) or `"everyone"` (every member who may watch it); anything else is a `400`. A stream created through `POST /api/streams` is `"followers"` unless the request says otherwise; a stream that existed before 1.16.0 is `"everyone"`. In both modes a notification goes only to a member who may watch the stream at that moment, and never to its owner. The field is returned with the stream. Changing `is_public` from `true` to `false` also removes every follow of the stream and deletes its go-live cards from every channel ordinary members can read; making it public again does not bring the follows back.

The owner's own responses (`GET /api/streams`, `GET /api/streams/{id}`) carry `follower_count`, a number: who follows is never returned to anyone, the owner and administrators included.

---

#### PUT /api/streams/{id}/follow  and  DELETE /api/streams/{id}/follow
Follow a stream, or stop following it (1.16.0). Needs a signed-in member with a full credential (a browser session, or a token or API key with `*`); a stream key or a scoped key is refused (`403`). `PUT` answers `{"following": true, "stream_id": 5}`. A member may follow only a stream they may watch (the playback rule: the owner and administrators always, other members only a public stream); an unknown, a non-numeric and an unviewable stream all answer the same `404 {"error": "Stream not found"}`. A member may follow at most 200 streams (`400`). `DELETE` removes the member's own follow and answers `{"following": false, "stream_id": 5}` whatever the stream is (it reveals nothing). A follow is for the in-portal go-live notification of a stream whose audience is `followers`.

#### GET /api/me/follows
The streams the signed-in member follows: `{"stream_ids": [5, 9]}`. Only the member's own list exists; there is no route that lists who follows a stream. `GET /api/streams/public` and `GET /api/streams/{id}` carry `following` (the viewer's own state). Both routes, like the follow list, need a full credential: a stream key or a scoped key gets `403`.

#### GET /api/streams/games
Suggestions for the stream settings form's game field (1.17.0): `{"games": ["Chess", "Doom"]}`, at most 50 distinct values (case-insensitive), first the games the signed-in member used before (a per-member history kept when a game is set on a stream, at most 100 entries, plus the current game of their own streams), newest first, then the current game of streams that are public now. A stream that is not public never contributes its game, whoever owns it (an administrator gets no more than a member), and nobody sees another member's history. Needs a full credential (`403` for a stream key or scoped key, `401` without one).

#### GET /api/streams/live
The streams that are live now and that the signed-in member may watch (same rule as playback), for the chat page's "Live now" strip: `{"streams": [{"id": 5, "name": "...", "game": "Chess", "streamer": "alice", "viewer_count": 3, "started_at": "...", "following": true}]}` (`game` is `null` when the stream has none). It carries no stream key, `pub_` key or RTMP address; watch a stream at `/watch/{id}`. A stream key or a scoped key gets `403` (it was an empty list for a scoped key before this change).

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

#### POST /api/streams/:id/regenerate-public-key
Rotate the stream's playback key (share link). The old key stops resolving at once, so existing viewing links and embeds built from it stop working.

**Authentication:** Required (stream owner only)

**Response:**
```json
{
  "public_key": "pub_newkey789..."
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
Get a dynamic thumbnail for a live stream. Returns a JPEG image captured from the stream via ffmpeg. Thumbnails are cached for 15 seconds. Only one capture runs per stream at a time (requests for the same stream wait for it) and at most two captures run at once on the server. A capture that takes longer than 10 seconds is stopped. When all capture slots are busy the last good frame is returned if it is at most 5 minutes old, otherwise 503 with `Retry-After: 3`.

**Key Types:** `pub_xxx` (or `live_xxx`, which only names the stream: it does not give the right to watch).

**Access (1.16.0):** one rule decides who may watch, for this route, the thumbnail, WHEP and its session calls, the info route and the HLS route. The stream's owner and administrators always may; any other signed-in member only when the stream is public; somebody not signed in only when the stream is public with `allow_unauthenticated` on and the address carries the stream's current `pub_` key. Credentials: the session cookie, or a token or API key with the all-scope `*`; a stream key (`live_`, also as `Authorization: Stream-Key` or `X-Stream-Key`) and scoped API keys never authorise watching. Everything else is `404` with `{"error": "Stream not found"}` (never `401` or `403`), the same for a private stream, a rotated or wrong key and an unknown stream. Decisions are cached for at most 5 seconds per credential and stream and dropped at once when the stream's visibility, open link or keys change or the viewer is signed out. `Access-Control-Allow-Origin: *` is sent only for a public stream with the open link on; other answers are `Cache-Control: private`.

**Response:** `image/jpeg` binary data, or 404 if stream is not live. When a new frame cannot be made (capture failed or timed out, or all capture slots are busy) the last good frame is returned with `Cache-Control: max-age=5` (`public` for an open link, `private` otherwise) if there is one. Without a last frame the answer is `503` with a `Retry-After` header when all capture slots are busy, when the capture failed, when it timed out, and when MediaMTX is not configured; never `500` or `504`.

---

#### POST /api/stream/auth
MediaMTX authentication hook (internal use, loopback or private callers only). Its `read` and `playback` actions follow the same viewing rule: a reader on loopback (the portal's own HLS proxy, thumbnail capture, recorder and relays) is allowed; any other reader must send a full-scope API key as `password` and have the right to watch. MediaMTX is configured to skip the hook for reads (`authHTTPExclude`), so this only matters if that exclusion is removed.

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

**Key Types:** `pub_xxx` (or `live_xxx`, which only names the stream).

**Access (1.16.0):** one rule decides who may watch, for this route, the thumbnail, WHEP and its session calls, the info route and the HLS route. The stream's owner and administrators always may; any other signed-in member only when the stream is public; somebody not signed in only when the stream is public with `allow_unauthenticated` on and the address carries the stream's current `pub_` key. Credentials: the session cookie, or a token or API key with the all-scope `*`; a stream key (`live_`, also as `Authorization: Stream-Key` or `X-Stream-Key`) and scoped API keys never authorise watching. Everything else is `404` with `{"error": "Stream not found"}` (never `401` or `403`), the same for a private stream, a rotated or wrong key and an unknown stream. Decisions are cached for at most 5 seconds per credential and stream and dropped at once when the stream's visibility, open link or keys change or the viewer is signed out. `Access-Control-Allow-Origin: *` is sent only for a public stream with the open link on; other answers are `Cache-Control: private`.

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

The `webrtc_whep` and `webrtc_whip` URLs work only on a network that can reach MediaMTX's WebRTC media port directly; they do not work through the public proxy. See Streaming Configuration. `hls` is the playback URL that works everywhere.

---

#### GET /api/stream/{key}/hls/{path}
Proxy HLS playback through Portal (port 443).

**Key Types:** `pub_xxx` (or `live_xxx`, which only names the stream).

**Access (1.16.0):** one rule decides who may watch, for this route, the thumbnail, WHEP and its session calls, the info route and the HLS route. The stream's owner and administrators always may; any other signed-in member only when the stream is public; somebody not signed in only when the stream is public with `allow_unauthenticated` on and the address carries the stream's current `pub_` key. Credentials: the session cookie, or a token or API key with the all-scope `*`; a stream key (`live_`, also as `Authorization: Stream-Key` or `X-Stream-Key`) and scoped API keys never authorise watching. Everything else is `404` with `{"error": "Stream not found"}` (never `401` or `403`), the same for a private stream, a rotated or wrong key and an unknown stream. Decisions are cached for at most 5 seconds per credential and stream and dropped at once when the stream's visibility, open link or keys change or the viewer is signed out. `Access-Control-Allow-Origin: *` is sent only for a public stream with the open link on; other answers are `Cache-Control: private`.

Returns HLS playlist and segments for the specified stream. `{path}` must be one plain file name (letters, digits, `_`, `.` and `-`, at most 128 characters, ending in `.m3u8`, `.mp4`, `.m4s`, `.ts`, `.aac` or `.m4a`); a folder, a `..`, a backslash or an encoded form answers the same `404` as a refusal. A `?token=` query parameter is accepted as the viewer's credential but is not passed on to MediaMTX. Relays, the recorder and the thumbnail capture read MediaMTX directly on loopback and do not use this route.

---

#### POST /api/stream/{key}/webrtc/whep
WebRTC WHEP endpoint for playback. **Same-network only:** only the signaling goes through Portal; the media needs a direct path to MediaMTX's WebRTC port (see Streaming Configuration). Use HLS from the internet.

**Key Types:** `pub_xxx` (or `live_xxx`, which only names the stream).

**Access (1.16.0):** one rule decides who may watch, for this route, the thumbnail, WHEP and its session calls, the info route and the HLS route. The stream's owner and administrators always may; any other signed-in member only when the stream is public; somebody not signed in only when the stream is public with `allow_unauthenticated` on and the address carries the stream's current `pub_` key. Credentials: the session cookie, or a token or API key with the all-scope `*`; a stream key (`live_`, also as `Authorization: Stream-Key` or `X-Stream-Key`) and scoped API keys never authorise watching. Everything else is `404` with `{"error": "Stream not found"}` (never `401` or `403`), the same for a private stream, a rotated or wrong key and an unknown stream. Decisions are cached for at most 5 seconds per credential and stream and dropped at once when the stream's visibility, open link or keys change or the viewer is signed out. `Access-Control-Allow-Origin: *` is sent only for a public stream with the open link on; other answers are `Cache-Control: private`.

The session calls (`PATCH` and `DELETE /api/stream/{key}/webrtc/session/{id}`) need the same permission, and a publishing (WHIP) session needs the `live_xxx` key. Media that is already flowing goes straight to MediaMTX and is not stopped by a change of access.

**Staying counted (1.17.0):** the offer counts the viewer for 15 seconds, and so does a successful `PATCH` on the session (the trickle ICE call most players send right after the offer; a `DELETE` counts nobody). A WHEP player sends nothing after that, so an **external WHEP player must call the heartbeat route, `POST /api/stream/{key}/viewer`, about every 10 seconds** (with the same credentials) to stay in the stream's `viewer_count`; without it the viewer drops out 15 seconds after the last offer or `PATCH`. The portal's own watch page does this already.

**Request:**
- Body: SDP offer (application/sdp)

**Response:**
- Status: 201 Created
- Body: SDP answer (application/sdp)
- Headers: `Location` - Session URL for ICE candidates

---

#### POST /api/stream/{key}/viewer
The watch page's heartbeat (1.17.0), sent every 10 seconds while the video plays. It tells the portal that this viewer is still watching so the stream's `viewer_count` is right; it carries no body and is not needed for playback to work.

**Key Types:** `pub_xxx` (or `live_xxx`, which only names the stream).

**Access:** the same single rule and the same credentials as playback (see HLS above). A request that is not allowed to watch, a key that matches nothing and a stream key used as a credential all answer the same `404` with `{"error": "Stream not found"}`, and count nobody.

**Who is one viewer:** a signed-in viewer is the account (several tabs count once). A viewer who is not signed in (open-link streams) is identified by the optional request header `X-Viewer-Id` (16 to 64 characters from `A-Z a-z 0-9 - _`; any other value is ignored), or, without it, by a salted hash of the client address and `User-Agent` (the portal's watch page sends the header, but it requires a sign-in, so a logged-out viewer is normally a player that sends none). At most 5 anonymous viewers per address and 5000 viewers per stream are counted. Playlist fetches (`GET .../hls/*.m3u8`), WHEP offers and the `PATCH` of a WHEP session count in the same way (an external WHEP player must send this heartbeat to stay counted); segments, thumbnails and the info route do not. Nothing about who is watching is stored, logged or returned.

**Response:** `200` with `{"ok": true}` (also for a stream that is not live: nothing is counted then). `429` with `Retry-After` when one client address sends more than 300 heartbeats in a minute (about 40 viewers beating every 10 seconds behind one address), or has had 60 heartbeats refused with `404` in the last minute; this is checked before the stream is looked up. A refused heartbeat is charged only to the 60-refusals allowance, not to the 300, so one refused viewer cannot use up the others' beats behind the same address. The cap of 5 anonymous viewers per address is a separate limit and is unchanged.

A viewer drops out of the count 15 seconds after the last heartbeat (20 seconds after the last playlist fetch); `viewer_count` is refreshed every 5 seconds. The owner's stream detail (`GET /api/streams/{id}` and the list) also carries `last_peak_viewers` and `last_unique_viewers`, the highest count and the number of distinct viewers of the last finished live session (`null` until one is recorded); other members get neither field.

---

#### POST /api/stream/{key}/webrtc/whip
WebRTC WHIP endpoint for publishing. **Same-network only:** only the signaling goes through Portal; the media needs a direct path to MediaMTX's WebRTC port (see Streaming Configuration). Use RTMPS from the internet.

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
| Private Key | `live_xxx...` | Publishing (OBS) only |
| Public Key | `pub_xxx...` | Read-only playback URLs (safe to share with viewers) |

**Stream Key is not an API Key**: Your private stream key (`live_xxx...`) authorises publishing only; stream management needs a session or a full-access API key (see Authentication).

**Publishing Options (requires private key `live_xxx`):**

1. **RTMPS (Recommended for OBS)** - Direct connection with Let's Encrypt certificate
   - Server: `rtmps://stream.example.com:1936/live`
   - Stream Key: Your private stream key from My Streams tab
   - Works with all versions of OBS Studio

2. **WebRTC WHIP** - Same network only (OBS 30.0+). Not available through the public proxy.
   - URL: `https://portal.example.com/api/stream/{stream_key}/webrtc/whip`
   - Service: WHIP in OBS settings
   - WebRTC (WHIP and WHEP) is **not available through the public proxy**. The offer and answer travel through Portal on port 443, but the media does not: it flows directly between the client and MediaMTX's WebRTC media port (UDP/TCP 8189 by default). The configuration Portal generates binds that port to loopback, and it never passes through the public proxy or Cloudflare. WHIP and WHEP therefore work only where the client can reach MediaMTX's media port directly (for example the same network, after you change the WebRTC bind addresses in the MediaMTX configuration). From the internet, publish with RTMPS and play back with HLS.

**OBS Studio Settings (RTMPS - Recommended):**
1. Go to Settings > Stream
2. Service: Custom
3. Server: `rtmps://stream.example.com:1936/live`
4. Stream Key: Your private stream key (e.g., `live_abc123...`)

**Playback URLs (accepts either key type):**
- HLS: `https://portal.example.com/api/stream/{key}/hls/index.m3u8`
- WebRTC WHEP (same network only, see the WHIP note above): `https://portal.example.com/api/stream/{key}/webrtc/whep`

For public streams, share the `public_key` (`pub_xxx`) for playback URLs instead of the private key.

**Stream management:** the stream key is not accepted by `/api/streams` (403 since 1.16.0); use a session or an all-scope API key:
```bash
curl -H "X-API-Key: portal_xxx..." https://portal.example.com/api/streams
```

**Network Architecture:**
| Service | Host | Port | Description |
|---------|------|------|-------------|
| RTMPS Publishing | stream.example.com | 1936 | Direct connection (Let's Encrypt TLS) |
| HLS Playback | portal.example.com | 443 | Proxied through Cloudflare |
| WebRTC (WHIP/WHEP) media | MediaMTX host | 8189 (UDP/TCP) | Direct only; not proxied, bound to loopback by the generated configuration |
| Portal API | portal.example.com | 443 | Proxied through Cloudflare |

**TLS Certificates:**
- `stream.example.com` uses Let's Encrypt (auto-renewed via certbot)
- `portal.example.com` uses Cloudflare Origin CA

---

### Stream Moderation

The stream's owner, its stream mods and staff can ban members from the stream (chat and signed-in viewing).

#### GET /api/streams/:id/bans
List banned users for a stream (owner, the stream's mods and staff).

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
Ban a user from stream chat and from signed-in viewing (owner, the stream's mods and staff; see below for whom).

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
Remove a ban from stream chat (owner, the stream's mods and staff). The owner and stream mods lift only bans on members they may act on (`400` "Not allowed" otherwise); an administrator or superadmin lifts any ban, including one on staff and their own. The same holds for `DELETE /api/streams/:id/bans/id/:ban_id` and the `unban` socket message.

**Response:**
```json
{
  "success": true,
  "message": "User unbanned"
}
```

---

#### Who may moderate (1.17.0)

The ban routes above, and the chat actions below, are open to three kinds of caller, decided by one helper at every request: global staff (moderator, admin, superadmin role), the owner of the stream, and a **stream mod** appointed by the owner. A stream mod's power exists only in that stream's own chat (a channel bound to exactly one stream), and only while the mod can still read it (a ban or a private stream removes it). A stream mod acts only on ordinary members: never on the owner, another mod, global staff or themselves (`400` on the HTTP routes, an `error` frame with the text `Not allowed` on the socket). The owner never acts on staff. Everybody else gets `403`. Each action is written to the audit log with the actor, target, channel and level.

A ban applies to the member's **signed-in viewing** of the stream as well as its chat: the member gets the same `404` as for a stream that does not exist on `/api/stream/{key}/` HLS, thumbnail, info, WHEP and viewer heartbeat, from the next request after the ban. `GET /api/streams/{id}` answers `403 {"error": "banned", "banned": true}` to a banned member of a public stream (still `404` for a stream they could not see anyway). The owner and administrators are never banned from viewing, and a stream with the open link can still be watched signed out.

#### GET /api/streams/:id/mods
List the chat mods of a stream. Owner and administrators only; anybody else and an unknown stream get `404`. A stream with no chat of its own (a default or shared channel) lists no mods: those rows belong to the channel.

```json
{ "max": 20, "mods": [ { "user_id": 7, "username": "friend", "nickname": null, "added_at": "2026-11-20 10:00:00" } ] }
```

#### POST /api/streams/:id/mods
Appoint a mod: `{"user_id": 7}`. Owner and administrators only (`404` otherwise). `201` on success; `404` for an unknown user; `400` for a bad id, the owner or a member banned from the stream; `409` when already a mod, when the stream already has 20 mods, or when the stream has no chat of its own (a default or shared channel). Appointing does not let the member watch or read a private stream.

#### DELETE /api/streams/:id/mods/:user_id
End an appointment. Owner and administrators only; `404` when the member is not a mod of this stream; `409` when the stream has no chat of its own (a default or shared channel), whose moderator rows are never removed here. The member's open chat page gets a `mod_level` frame.

The generic `/api/chat/channels/{id}/members` routes do not manage a stream chat's mods: a channel moderator cannot list, add or remove members of a stream's chat, and nobody can set role `moderator` through them there (`400`); use the routes above.

---

### Stream Chat WebSocket Commands

Additional WebSocket message types for stream chat moderation. `pin_message`, `unpin_message`, `timeout_user` (`duration` in seconds, at least 1; the target is `target_user_id`, or `message_id` of one of the member's messages, which also works for an anonymous post), `delete` of another member's message, `ban`, `unban`, `get_bans` and `create_poll` (in a stream's own chat only the owner, its mods and staff may start a poll) use the helper above. `channel_info` carries `slowmode_seconds`, `mod_level` (`none`, `mod`, `owner`, `staff`) and `stream_chat`; messages of the owner and of mods carry `stream_role` (`owner` or `mod`, never on an anonymous post).

**Set slow mode** (owner, the stream's mods and staff; stream chat only):
```json
{
  "type": "set_slowmode",
  "seconds": 15
}
```
`seconds` is 0, 5, 15 or 30; anything else is an `error` frame. The room receives `{"type": "slowmode_changed", "seconds": 15, "channel_id": 3}`. Viewers wait that long between messages; the owner, the mods and staff are not held back. A member's mod level changing sends them `{"type": "mod_level", "channel_id": 3, "mod_level": "mod"}`.

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

**Stream info frames (1.17.0).** When the owner changes the `name` or `game` of a stream that is live, the sockets in its chat room receive
```json
{"type": "stream_info", "stream_id": 3, "name": "New title", "game": "Chess"}
```
(`game` is `null` when cleared). It is not a room broadcast: each socket is judged on its own, by the chat read rule and the playback rule, so a stream that is not public sends it only to its owner and administrators (also when it is bound to the default channel), and a member banned from the chat gets nothing. No frame is sent while the stream is offline or when nothing changed. The watch page, the streams page viewer and the chat page's live-now strip update from it without a reload.

---

### Chat

#### GET /api/chat/channels
List chat channels the caller may see: public channels, private channels the caller belongs to (admins and superadmins: all), and stream chat channels only when the stream is public or the caller is its owner or an admin (the chat of a stream that is not public is left out, with its stream, live state and owner). Stream-associated channels include live status and stream metadata for UI grouping (Live / Encoding / Offline sections). The `stream_is_live` field uses the tri-state integer: `0`=offline, `1`=live, `2`=encoding.

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
      "stream_owner": "John",
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

The messages' upload files are removed with them unless another message still names them. When that check could not be made (for example a message could not be decrypted), no file is removed and the answer also carries `"chat_files_skipped": "<reason>"`.

---

#### PUT /api/chat/channels/:id/retention
Set the retention of one channel (1.20.0). **Administrators only** (a moderator or channel moderator gets `403`; the generic `PUT /api/chat/channels/:id` ignores these fields). This REST route is the only way to set it: the chat socket has no channel-settings path for retention.

**Request** (a field left out is kept):
```json
{"retention_days": 30, "file_retention_days": 7, "confirm": true}
```
- `retention_days`: days after which the periodic cleanup removes the channel's messages (pinned messages are kept). A number, `0` or `"forever"` (both stored as the cap, the setting `retention_chat_max_days`, default 3650, 1 to 3650), or `null` for "follow the global setting `retention_chat_days`". A number above the cap is stored as the cap (`"capped": true`). A channel with its own value is no longer touched by the global chat retention.
- `file_retention_days`: days after which only the **uploaded files** of older messages are removed; the message stays and is marked `file_removed`. It can never exceed the message retention: a larger number is `400`, `0` or `"forever"` means "as long as the messages", and shortening `retention_days` below it cuts it to the same value. `null` = files stay with their messages.
- `confirm`: required to apply a change that makes removal sooner (a shorter value, or a value where there was none). Without it nothing is changed and the answer is `{"applied": false, "confirm_required": true, "would_remove_messages": 12, "would_remove_files": 3, "old": {...}, "new": {...}, "cap_days": 3650}`; the counts are what the next cleanup would remove. `"dry_run": true` only looks, for any change.

**Response (applied):** `{"applied": true, "retention_days": 30, "file_retention_days": 7, "capped": false, "cap_days": 3650, "old": {...}, "new": {...}, "next_cleanup_at": "..."}`. Every change is audited (`channel_retention_change`, old and new value). **Errors:** `400` (bad value, a file value above the message value, an empty body, or a stream's own chat: it keeps the global setting), `403`, `404`. Default channels are allowed. DMs are not channels and are untouched.

The channel list (`GET /api/chat/channels`) and the `channel_info` frame carry `retention_days`, `file_retention_days` and `retention_next_cleanup` (the time of the next periodic cleanup, null until the cleanup task has started) for a channel with its own value; a stream's chat carries none.

---

#### POST /api/chat/channels/:id/prune
Remove the messages of a channel inside a date range (1.20.0). **Allowed:** administrators and the moderators of that chat per `chat_mod_level` (global staff, a stream's owner, a stream mod). A channel the caller may not read, and a caller with no moderator level in it, get the `404 {"error": "Channel not found"}` of a missing channel. **Rank:** the prune removes only what the caller could delete one message at a time over the chat socket: a stream mod the posts of ordinary members only, the stream's owner everybody's but staff (the go-live card is the owner's), a global moderator or administrator everybody's of a lower role; everybody their own. A user filter on someone the caller may not act on gives `count` 0, and a range prune leaves those posts (the count says how many remain to be removed).

**Request:**
```json
{"from": "2026-11-21T10:00:00Z", "to": "2026-11-21T11:00:00Z", "user": "alice", "skip_pinned": true, "dry_run": true}
```
- `from`, `to`: ISO 8601, both required, both ends inclusive (no offset = UTC).
- `user`: optional, an account id or a username (an unknown one matches nothing). A user filter from anybody but an administrator never matches that user's **anonymous** messages, so the count cannot reveal them; an administrator's does (the audit entry then says `anonymous_included`). Without a user filter, an **anonymous** message in the range is matched for every caller but an administrator whoever wrote it: the rank rules apply to named messages only, so a count can never tell the rank of an anonymous author (this includes anonymous messages of higher-ranked authors that a single delete would refuse). An administrator's prune without a user filter leaves every **anonymous** message alone when the rank rules exclude any author (another administrator, or a superadmin), so no frame or count shows which anonymous messages survived; with a user filter an administrator matches that user's anonymous messages, subject to the same rank rules.
- `skip_pinned`: default `true`; `false` includes pinned messages.
- `dry_run`: `{"dry_run": true, "count": 12, "margin": 2, "skip_pinned": true}` and nothing is removed.
- A real run (no `dry_run`) must send the count of the dry run as `expected_count`; it is refused with `409 {"error": ..., "count": <live>, "expected_count": <sent>}` when the live count differs by more than the margin, `max(2, 2 percent of expected_count)`. `400` when `expected_count` is missing.

**Response:** `202 {"started": true, "count": 12}`. The prune runs as a background task in batches of 200 that yield to the event loop; the room receives one `messages_pruned` frame per batch (below); one audit entry `chat_prune` (who, channel, range, user filter, count, status `completed`, `failed` or `interrupted`, files removed) is written when it ends. The messages' upload files are removed with them unless another row still names them; a prune that a shutdown stopped or cancelled leaves its files to the next start or cleanup (their names are kept in the database, so none is forgotten). When an administrator's `user` filter includes that user's anonymous messages, the frames go per socket: staff and that user get every id, everybody else only the ids of the named messages (no frame when a batch has none), so the room cannot link the anonymous poster; the anonymous messages leave an ordinary member's screen at the next load. One prune per channel at a time: a second one is `409 {"error": "A prune is already running in this channel"}`.

#### GET /api/chat/channels/:id/prune
State of the last prune in the channel, same gate: `{"running": false, "status": "completed", "removed": 12, "total": 12, "files": 1}` (`{"running": false, "status": "none"}` when there was none since the portal started). After an administrator's `user`-filtered prune that includes that user's anonymous messages, `removed`, `total` and `files` count those too, so they go only to staff and to the administrator who started the prune; a stream owner or stream mod gets `{"running", "status"}` only.

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

The message shape is the one of the channel history (`GET /api/chat/channels/:id/messages`: reactions, polls, reply previews, anonymous posts masked for ordinary members), and the chain is readable under the same rule as the channel's history. **Errors:** `400` (message id is not a number), `401`, `404 {"error": "Message not found"}` for a message that does not exist and for one the caller may not read (private channel and not a member, removed member, banned from the stream chat, or the chat of a stream that is not public and the caller is neither its owner nor an admin). The answer carries `Cache-Control: private, no-store`.

---

#### GET /api/chat/channels/:id/messages
Read older messages of a channel, or a window around one message (for a link to a message). Same authentication as the other chat routes. DMs are not served here.

**Query parameters** (`before_id` and `around_id` are exclusive; with neither, the newest page is returned):
- `before_id`: return the messages older than this message id (the next page up).
- `around_id`: return a window centred on this message (about `limit` messages, half before it, half after).
- `limit`: page size, default 50, at most 100 (larger values are cut to 100). `0` or a non-number is a `400`.
- A `before_id` or `around_id` that is not a whole number from 1 to 9223372036854775807 is a `400`; a channel id outside that range is a `404`.

**Response:**
```json
{
  "channel_id": 3,
  "messages": [{"id": 101, "user_id": 1, "username": "alice", "message": "...", "reply_preview": {...}, "reactions": [...], "created_at": "..."}],
  "has_more": true,
  "has_newer": false,
  "found": true
}
```

- `messages` are oldest first, in the same shape as the `history` reply of the WebSocket (user enrichment, reactions, polls, reply previews). The three ways to read a channel (join, `history_page`, this route) build them in one shared function, so the same viewer gets byte-identical message objects from each.
- `has_more`: older messages exist. `has_newer`: newer messages exist than the window shows (only for `around_id`). `found` is `false`, with an empty list, when `around_id` is not a message of this channel (deleted, removed by the chat retention, or in another channel).
- Anonymous posts are masked for ordinary members exactly as in the join history: no account id, role, nickname, avatar or name, in the message, its reactions, reply previews and poll. Moderators, admins and the author keep the id.
- Messages older than the chat retention (`retention_chat_days`, or the channel's own `retention_days` since 1.20.0) no longer exist and are never returned. A message whose uploaded file was removed by the channel's file retention has `"file_removed": 1` and no `image_url` / `attachment_url`.
- Reading never marks anything as read and sends no notification.
- A go-live card (1.16.0) is a message with `"message_type": "stream_card"` and `"card": {"stream_id": 5, "streamer": "alice", "title": "..."}`; `message` holds a plain-text fallback (`alice is live: title - https://host/watch/5`) for a client that does not know the type. A client builds the watch link from `card.stream_id` (`/watch/{id}`). The card is a system post written through the normal encrypted insert, authored by the streamer's account, and cannot be edited. It is posted into the stream's own chat and, for a public stream, into the announce channel an administrator chose; it is never posted into a channel ordinary members can read for a stream that is not public. It is deleted from every channel except the stream's own closed chat when the stream becomes private (also from a channel that was made private later and has members) and everywhere when the stream is deleted, and the chat retention removes it like any message. It carries no stream key and no thumbnail. The room receives `message_deleted` when it is removed.
- The chat of a stream that is not public (`is_public` off) can be read, joined and written to only by the stream's owner and admins; everyone else gets the answer for a missing channel. The answer carries `Cache-Control: private, no-store`.

**Errors:** `400` (bad parameter), `401` (not authenticated), `404 {"error": "Channel not found"}` for a channel the caller cannot read (private and not a member, banned from the stream chat, removed member, the chat of a stream that is not public and the caller is neither owner nor admin) and for one that does not exist, `429` with `Retry-After` when the caller made more than 30 history requests in a minute (this budget is shared with the WebSocket `history_page` message and all of the caller's sockets).


#### GET /api/chat/channels/:id/notify

The caller's own notification choice for one channel they may read (added in 1.19.0). Nobody can read another member's choice.

```json
{"channel_id": 3, "notify_level": null, "muted_until": 0}
```

- `notify_level` is `"all"`, `"mentions"`, `"none"` or `null` (no choice made: the default, which gives a live unread badge and nothing else).
- `muted_until` is the end of a timed mute in epoch seconds, `0` when not muted (an ended mute reads as `0`).
- **Errors:** `401`; `404 {"error": "Channel not found"}` for a channel that does not exist and, byte for byte the same, for one the caller may not read (private and not a member, banned from the stream chat, the chat of a stream that is not public and the caller is neither its owner nor an admin).

#### PUT /api/chat/channels/:id/notify

Sets the caller's level and/or timed mute for a channel they may read. Body: `{"level": "all" | "mentions" | "none" | "default", "mute_hours": 0 | 1 | 8 | 24}`; send either key or both, a missing key keeps its value. `"default"` removes the choice; `mute_hours: 0` ends a mute. The answer is the new state in the shape of the GET route. The server keeps the choice in memory for every member with an open chat socket and replaces it on this write, so it applies to the next message.

- Level `all`: badge, and the chat page plays a sound and shows a desktop alert. `mentions`: only an @mention counts. `none`: nothing, an @mention does not notify either. An active mute stops the badge and the ordinary signal; an @mention still notifies (unless the level is `none`).
- **Errors:** `400` (neither key, a level or an hour count that is not in the lists above), `401`, `404` as above. `GET /api/chat/channels` also carries `notify_level` and `muted_until` on every channel.

---

### Direct Messages

Private messaging between users, supporting both 1:1 and group conversations (up to 10 participants). All DM messages are encrypted at rest with Fernet (same key derivation as channel chat). Every endpoint verifies participant membership.

#### GET /api/dm/conversations
List the authenticated user's DM conversations with last message preview and unread counts.

**Response:**
```json
{
  "conversations": [
    {
      "id": 1,
      "type": "direct",
      "participants": [
        {"user_id": 1, "username": "alice", "nickname": "Alice"},
        {"user_id": 2, "username": "bob", "nickname": "Bob"}
      ],
      "last_message": {
        "id": 50,
        "user_id": 2,
        "username": "bob",
        "message": "Hey, are you around?",
        "created_at": "2026-02-11T10:30:00Z"
      },
      "unread_count": 3,
      "muted": false,
      "created_at": "2026-02-10T08:00:00Z"
    },
    {
      "id": 2,
      "type": "group",
      "name": "Project Team",
      "participants": [
        {"user_id": 1, "username": "alice"},
        {"user_id": 3, "username": "charlie"},
        {"user_id": 4, "username": "dana"}
      ],
      "last_message": null,
      "unread_count": 0,
      "muted": false,
      "created_at": "2026-02-11T09:00:00Z"
    }
  ]
}
```

---

#### POST /api/dm/conversations
Create a new DM conversation.

**Request (1:1):**
```json
{
  "user_id": 2
}
```

**Request (Group):**
```json
{
  "user_ids": [2, 3, 4],
  "name": "Project Team"
}
```

**Response (201):**
```json
{
  "conversation": {
    "id": 2,
    "type": "group",
    "name": "Project Team",
    "participants": [
      {"user_id": 1, "username": "alice"},
      {"user_id": 2, "username": "bob"},
      {"user_id": 3, "username": "charlie"},
      {"user_id": 4, "username": "dana"}
    ],
    "created_at": "2026-02-11T09:00:00Z"
  }
}
```

**Notes:**
- For 1:1 DMs, if a conversation already exists between the two users, the existing conversation is returned instead of creating a duplicate.
- Group DMs require at least 2 other participants (`user_ids`). Maximum 10 total participants.

---

#### GET /api/dm/conversations/{id}
Get conversation details with participants. Requires the authenticated user to be a participant.

**Response:**
```json
{
  "conversation": {
    "id": 1,
    "type": "direct",
    "participants": [
      {"user_id": 1, "username": "alice", "nickname": "Alice", "avatar": {"color": "#3b82f6", "emoji": null}},
      {"user_id": 2, "username": "bob", "nickname": "Bob", "avatar": {"color": "#ef4444", "emoji": null}}
    ],
    "muted": false,
    "created_at": "2026-02-10T08:00:00Z"
  }
}
```

---

#### GET /api/dm/conversations/{id}/messages
Get messages in a conversation. Requires participant membership. Uses cursor-based pagination.

**Query Parameters:**
- `limit` (optional): Number of messages to return, 1-100 (default: `100`)
- `before_id` (optional): Return messages with IDs less than this value (for loading older messages)

**Response:**
```json
{
  "messages": [
    {
      "id": 45,
      "conversation_id": 1,
      "user_id": 2,
      "username": "bob",
      "nickname": "Bob",
      "message": "Hey, are you around?",
      "reply_to": null,
      "image_url": null,
      "reactions": [],
      "edited_at": null,
      "created_at": "2026-02-11T10:30:00Z"
    }
  ],
  "has_more": true
}
```

---

#### POST /api/dm/conversations/{id}/mute
Toggle mute on a conversation. Muted conversations do not generate notifications.

**Request:**
```json
{
  "muted": true
}
```

**Response:**
```json
{
  "muted": true
}
```

---

#### POST /api/dm/conversations/{id}/leave
Leave a group DM. Cannot leave a 1:1 conversation.

**Response:**
```json
{
  "success": true
}
```

**Error (400):**
```json
{
  "error": "Cannot leave a 1:1 conversation"
}
```

---

#### POST /api/dm/conversations/{id}/participants
Add users to a group DM. Cannot add participants to a 1:1 conversation. Maximum 10 total participants.

**Request:**
```json
{
  "user_ids": [5, 6]
}
```

**Response:**
```json
{
  "success": true,
  "participants": [
    {"user_id": 1, "username": "alice"},
    {"user_id": 2, "username": "bob"},
    {"user_id": 5, "username": "eve"},
    {"user_id": 6, "username": "frank"}
  ]
}
```

**Error (400):**
```json
{
  "error": "Cannot add participants to a 1:1 conversation"
}
```

---

#### DM WebSocket Messages (via /ws/chat)

DM signaling piggybacks on the existing `/ws/chat` WebSocket connection. No separate WebSocket is needed.

**Client -> Server:**

| Type | Fields | Description |
|------|--------|-------------|
| `dm_open` | `user_id` or `conversation_id` | Open/create a 1:1 DM (by user_id) or open an existing conversation (by conversation_id) |
| `dm_create_group` | `user_ids[]`, `name?` | Create a new group DM |
| `dm_message` | `conversation_id`, `message`, `reply_to?`, `image_url?` | Send a DM message (encrypted at rest) |
| `dm_typing` | `conversation_id` | Broadcast typing indicator to other participants |
| `dm_delete` | `conversation_id`, `message_id` | Delete own message |
| `dm_react` | `conversation_id`, `message_id`, `emoji` | Toggle a reaction on a message |
| `dm_edit` | `conversation_id`, `message_id`, `message` | Edit own message (5-minute window) |
| `dm_mark_read` | `conversation_id`, `message_id` | Update read position for unread tracking |
| `dm_history` | `conversation_id`, `before_id?` | Load older messages (cursor pagination) |

**Examples:**
```json
{"type": "dm_open", "user_id": 5}
{"type": "dm_open", "conversation_id": 1}
{"type": "dm_create_group", "user_ids": [2, 3], "name": "Team Chat"}
{"type": "dm_message", "conversation_id": 1, "message": "Hello!"}
{"type": "dm_message", "conversation_id": 1, "message": "Check this out", "image_url": "/static/uploads/chat/abc.jpg"}
{"type": "dm_message", "conversation_id": 1, "message": "Agreed!", "reply_to": 45}
{"type": "dm_typing", "conversation_id": 1}
{"type": "dm_delete", "conversation_id": 1, "message_id": 50}
{"type": "dm_react", "conversation_id": 1, "message_id": 45, "emoji": "👍"}
{"type": "dm_edit", "conversation_id": 1, "message_id": 45, "message": "Updated text"}
{"type": "dm_mark_read", "conversation_id": 1, "message_id": 50}
{"type": "dm_history", "conversation_id": 1, "before_id": 40}
```

**Server -> Client:**

| Type | Fields | Description |
|------|--------|-------------|
| `dm_conversations_list` | `conversations[]`, `unread_counts` | Sent on WebSocket connect with all user's conversations |
| `dm_conversation_opened` | `conversation`, `messages[]` | Response to `dm_open` or `dm_create_group` |
| `dm_message` | `conversation_id`, `id`, `user_id`, `username`, `message`, etc. | New DM message broadcast to participants |
| `dm_typing` | `conversation_id`, `username` | Typing indicator broadcast |
| `dm_message_deleted` | `conversation_id`, `message_id` | Message deleted broadcast |
| `dm_reaction_update` | `conversation_id`, `message_id`, `emoji`, `added`, `count` | Reaction toggled broadcast |
| `dm_message_edited` | `conversation_id`, `message_id`, `message`, `edited_at` | Message edited broadcast |
| `dm_history` | `conversation_id`, `messages[]` | Response to `dm_history` request |
| `dm_unread_update` | `conversation_id`, `unread_count` | Unread count changed (sent when another participant reads messages) |

**Examples:**
```json
{"type": "dm_conversations_list", "conversations": [...], "unread_counts": {"1": 3, "2": 0}}
{"type": "dm_conversation_opened", "conversation": {"id": 1, "type": "direct", "participants": [...]}, "messages": [...]}
{"type": "dm_message", "conversation_id": 1, "id": 51, "user_id": 2, "username": "bob", "nickname": "Bob", "message": "Hey!", "created_at": "2026-02-11T10:35:00Z"}
{"type": "dm_typing", "conversation_id": 1, "username": "bob"}
{"type": "dm_message_deleted", "conversation_id": 1, "message_id": 50}
{"type": "dm_reaction_update", "conversation_id": 1, "message_id": 45, "emoji": "👍", "added": true, "count": 2}
{"type": "dm_message_edited", "conversation_id": 1, "message_id": 45, "message": "Updated text", "edited_at": "2026-02-11T10:36:00Z"}
{"type": "dm_history", "conversation_id": 1, "messages": [...]}
{"type": "dm_unread_update", "conversation_id": 1, "unread_count": 0}
```

**Security Notes:**
- All DM messages are encrypted at rest with Fernet (same derivation as channel chat)
- Every DM endpoint and WebSocket message type verifies participant membership
- Users can only see conversations they are a participant in
- Message edit window is 5 minutes (same as channel chat)

---

### User Blocking

Users can block other users. Blocking prevents DM communication in both directions.

#### GET /api/users/blocked
List user IDs the current user has blocked.

**Response:**
```json
{ "blocked": [1, 5, 12] }
```

#### POST /api/users/{id}/block
Block a user. Cannot block yourself.

**Response:** `{ "success": true }`

#### DELETE /api/users/{id}/block
Unblock a user.

**Response:** `{ "success": true }`

**Enforcement:**
- Blocked users' messages are collapsed in chat (click-to-reveal)
- DM creation is blocked bidirectionally
- DM messages are blocked bidirectionally

---

### Polls

Inline polls in chat channels. Created via WebSocket, voted on in real-time.

**WebSocket Message Types:**
- `create_poll` — Create a poll: `{ type: "create_poll", question, options: ["A","B"], allow_multiple?, anonymous_votes?, duration_seconds? }`
- `vote_poll` — Vote: `{ type: "vote_poll", poll_id, option_index }`
- `close_poll` — Close (creator or mod+): `{ type: "close_poll", poll_id }`

**Broadcast Types:**
- `poll_created` — New poll with message
- `poll_updated` — Vote count changed
- `poll_closed` — Poll closed

**Constraints:**
- Question: max 500 chars
- Options: 2-10, max 200 chars each
- Duration: optional, in seconds
- Only creator or mod+ can close

---

### Channel Permissions

Channels support visibility and mode settings for access control.

**Fields on channels:**
- `visibility`: `public` (default) or `private` — private channels require membership
- `mode`: `open` (default) or `readonly` — readonly channels only allow mod+/channel-moderator to send

#### GET /api/chat/channels/{id}/members
List members of a channel. Accessible to members and moderator+.

**Response:**
```json
{ "members": [{ "id": 1, "channel_id": 5, "user_id": 10, "role": "moderator", "username": "alice" }] }
```

#### POST /api/chat/channels/{id}/members
Add a member to a channel. Requires moderator+ or channel-moderator.

**Request:** `{ "user_id": 10, "role": "member" }`

#### DELETE /api/chat/channels/{id}/members/{user_id}
Remove a member. Users can remove themselves; moderator+ can remove others.

#### PUT /api/chat/channels/{id}/members/{user_id}
Update a member's channel role. Requires moderator+.

**Request:** `{ "role": "moderator" }`

**Channel roles:** `member` (can view/send), `moderator` (can manage members)

---

### Chat User Search

#### GET /api/chat/users
Search users for DM creation. Available to all authenticated users. Returns basic info only (id, username, nickname).

**Query Parameters:**
- `q` — Search query (matches username or nickname)

**Response:**
```json
{ "users": [{ "id": 1, "username": "alice", "nickname": "Alice" }] }
```

---

### Message Search

Full-text search across chat messages (both channel messages and DMs) with search operators. Uses SQLite FTS5 for the words and a small per-message flag table for the operators. Results are filtered by the user's access: channel messages from channels the user may read (the same decision as for joining a channel and for scrollback, so a member banned from a stream's chat finds nothing in it, and a private channel the member does not belong to behaves like one that does not exist), and DM messages from conversations the user participates in.

#### GET /api/chat/search
Search messages across channels and/or DMs.

Channel results cover only the channels the caller may read: a private channel needs membership (admins and superadmins search every channel), and the chat of a stream that is not public (`is_public` off) is searched only for the stream's owner and admins, the rule of the channel history. The search fails closed: if the readable channels cannot be worked out, the answer is `503 {"error": "Search is unavailable right now"}` and nothing is searched.

**Rate Limit:** 10 requests per minute per user (a request refused for a bad query or parameter does not count).

**Query Parameters:**
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `q` | Yes | - | Words and operators (2-200 characters), see below |
| `scope` | No | `all` | Search scope: `all`, `channels`, or `dms` |
| `channel_id` | No | - | Restrict to a specific channel (1 to 9223372036854775807; any other value answers `400`) |
| `conversation_id` | No | - | Restrict to a specific DM conversation (same range) |
| `from`, `has`, `before`, `after` | No | - | The older way to give those operators; same checks as in `q` |
| `limit` | No | `25` | Results per page (max 50) |
| `offset` | No | `0` | Pagination offset (0 to 2000; a larger value answers `400` with `offset must not exceed 2000`) |

**Operators in `q`** (separated by spaces; names are not case-sensitive; at most 10 per query):
| Operator | Meaning |
|----------|---------|
| `from:name`, `-from:name` | Author by account name or nickname (any case). `-` leaves that author out |
| `in:channel`, `-in:channel` | Channel by name (a leading `#` is ignored). `-` leaves it out. DMs are not searched when `in:` is given |
| `has:link`, `has:file`, `has:image` | Text with an `http://` or `https://` address; an attachment that is not an image; an image or an image attachment |
| `is:pinned` | Pinned channel messages (no DM results) |
| `before:YYYY-MM-DD`, `after:YYYY-MM-DD` | Created before the start of that day, or from the start of that day (UTC), so the two together cover every message |
| `"two words"` | A phrase |

Anything else is a word that must appear. A query with no words (only operators) is allowed: results are newest first, at most 200 in total (`capped`). A token counts as an operator only when it is letters, a colon and a value, so `12:30` and `https://example.com` are searched as text; any other `name:value` is an unknown operator. To search for such text, put it in double quotes.

**Errors:** an unknown operator, an unknown `has:` or `is:` value, a value missing after an operator, a date that is not `YYYY-MM-DD` or not a real date, `-` before an operator other than `from:` and `in:`, an operator given too often, or more than 10 operators all give `400` with a message in `error`. An `in:` or `from:` that names nothing the caller may see is not an error: it matches nothing.

**Anonymous posts:** a positive `from:` never matches an anonymous post for an ordinary member (not even the author's own), a negated `-from:` never removes one, so neither an author filter nor a count can show who wrote it. Moderators, admins and superadmins, who already receive the author's id, can match it. Result objects are masked exactly like history.

**Response:**
```json
{
  "results": [
    {
      "id": 123,
      "source": "channel",
      "source_id": 1,
      "source_name": "#general",
      "message": "Has anyone tried the new deployment pipeline?",
      "username": "bob",
      "display_name": "Bobby",
      "nickname": "Bobby",
      "avatar": {},
      "user_id": 2,
      "role": "user",
      "anonymous": false,
      "edited_at": null,
      "image_url": null,
      "attachment_url": null,
      "attachment_name": null,
      "attachment_type": null,
      "attachment_size": null,
      "has_image": 0,
      "has_file": 0,
      "has_link": 0,
      "is_pinned": 0,
      "created_at": "2026-02-11T09:15:00+00:00"
    },
    {
      "id": 456,
      "source": "dm",
      "source_id": 3,
      "source_name": "alice",
      "message": "The pipeline is ready for testing",
      "user_id": 1,
      "username": "alice",
      "display_name": "alice",
      "image_url": null,
      "created_at": "2026-02-11T10:00:00+00:00",
      "has_image": 0, "has_file": 0, "has_link": 0
    }
  ],
  "total": 42,
  "has_more": true,
  "capped": false,
  "query": "pipeline in:general",
  "terms": ["pipeline"],
  "operator_only": false,
  "index_complete": true
}
```

**Notes:**
- Word queries with `scope=channels` or `scope=dms` are ordered by relevance (FTS5 rank). With `scope=all` (the default) they are ordered newest first across channels and DMs, so `offset` pages through every match once without repeats or gaps; operator-only queries are newest first.
- `source` is `channel` or `dm`; `source_id` is the channel id or conversation id. To show a channel result in context, call `GET /api/chat/channels/{source_id}/messages?around_id={id}` (the chat page does this).
- For a channel result `username` is the account name and `display_name` is what the chat shows (nickname when set). An anonymous post has `username` and `display_name` `"Anonymous"`, `user_id`, `role` and `nickname` null and an empty `avatar` (staff and the author keep `user_id` and `role`).
- `total` is exact for word queries. For operator-only queries it stops at 200 and `capped` is true when more exist; `offset` plus `limit` cannot go past 200. `has_more` is true when more matches exist than were returned; for a capped query it is false once `offset` plus the number returned reaches 200, so a client that follows it pages through all 200 results and stops. An `offset` of 200 or more answers an empty list without reading any rows. `has_more` is also false when `offset` plus the number returned is above 2000 (the `offset` limit), even if more matches exist, because the next page would be refused with `400`.
- `terms` holds the free-text words, for highlighting. `index_complete` is false until the one-time backfill that fills `has_link`/`has_file` for messages written before the upgrade (and indexes attachment-only messages) has finished; until then `has:` queries can miss old messages.
- The `has:image` flag now means an image or an image attachment; the older channel rule (any attachment) is corrected by the backfill.

---

#### POST /api/chat/search/rebuild
Rebuild the FTS5 search index from encrypted messages. Decrypts all messages, tokenizes, and repopulates the full-text index. This is a potentially long-running operation on large databases.

**Authentication:** Superadmin only.

**Response:**
```json
{
  "rebuilt": true,
  "indexed": {"channel": 15000, "dm": 320}
}
```
The rebuild writes the operator flags itself and marks the backfill as done.

**Errors:** `403` for anyone but a superadmin. `409` when the search index is being backfilled or rebuilt (the one-time backfill can run for minutes on a large history): the answer comes at once and nothing is changed; try again when it has finished.

**Security Notes:**
- FTS5 index stores plaintext tokens alongside encrypted message data (contentless tables — no raw message text stored in the index)
- The rebuild endpoint is restricted to superadmin to prevent abuse
- Search rate limiting (10/min/user) prevents index scanning attacks

---

### Voice Chat

Live voice chat uses WebRTC P2P mesh (up to `voice_room_cap` users per room, default 8). The server acts purely as a signaling relay — no audio is processed or stored server-side. Audio is encrypted via WebRTC DTLS-SRTP.

Voice signaling piggybacks on the existing `/ws/chat` WebSocket. No separate WebSocket connection is needed.

**Voice rooms:** Voice works in both channels and DMs. For channels, the room is the channel name. For DMs, pass `room: "dm:{conversation_id}"` in the `voice_join` message.

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
{"type": "voice_join", "room": "dm:42"}
{"type": "voice_join", "resume": true, "room": "general", "resume_token": "..."}
{"type": "voice_leave"}
{"type": "voice_leave", "room": "general", "resume_token": "..."}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "offer", "sdp": "..."}}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "answer", "sdp": "..."}}
{"type": "voice_signal", "target_user_id": 5, "signal": {"type": "ice-candidate", "candidate": {...}}}
{"type": "voice_mute", "muted": true}
{"type": "voice_deafen", "deafened": true}
{"type": "voice_speaking", "speaking": true}
{"type": "voice_kick", "target_user_id": 5}
{"type": "voice_server_mute", "target_user_id": 5}
{"type": "voice_server_unmute", "target_user_id": 5}
{"type": "voice_lock_room"}
{"type": "voice_unlock_room"}
```

**Server → Client:**
```json
{"type": "voice_state", "channel": "general", "resume_token": "...", "users": [{"user_id": 1, "username": "alice", "muted": false, "deafened": false, "speaking": false, "screen_sharing": false, "reconnecting": false}]}
{"type": "voice_user_joined", "user_id": 2, "username": "bob"}
{"type": "voice_user_left", "user_id": 2}
{"type": "voice_user_reconnecting", "user_id": 2}
{"type": "voice_user_resumed", "user_id": 2}
{"type": "voice_resume_failed", "message": "Voice session could not be resumed"}
{"type": "voice_denied", "message": "Already in voice chat"}
{"type": "voice_signal", "from_user_id": 2, "signal": {"type": "offer", "sdp": "..."}}
{"type": "voice_mute_changed", "user_id": 2, "muted": true}
{"type": "voice_deafen_changed", "user_id": 2, "deafened": true}
{"type": "voice_speaking_changed", "user_id": 2, "speaking": true}
{"type": "voice_denied", "code": "room_full", "message": "This voice room is full (8 people)."}
{"type": "voice_server_mute_changed", "user_id": 2, "server_muted": true}
{"type": "voice_room_lock_changed", "locked": true}
```

- **Voice moderation and the room cap (1.20.0).** `voice_state` (join and resume) also carries `"locked"` (bool), `"can_moderate"` (bool, true for staff and, in a stream's own chat, its owner and stream mods; always false in a DM call) and `"room_cap"`; each user entry has `"server_muted"`. A `voice_join` is refused with `voice_denied` (a `code` and a `message`, sent to the joiner only, nothing to the room) when: the member is timed out or muted in that channel (`"timed_out"`; anyone with moderation power there is exempt), the room already holds `voice_room_cap` people (`"room_full"`, default 8, 2 to 25; counts members that are reconnecting; applies to DM calls too; a resume of a member already in the room is never refused for it), the room is locked and the member has no moderation power (`"locked"`), or the member was removed by a moderator less than 60 seconds ago (`"kicked"`). A refusal for a channel the member cannot read stays as before (no code, nothing about the room). `voice_kick` removes the target for everyone (they receive `voice_denied` with code `"kicked"`, the others `voice_user_left`) and blocks their rejoin to that room for 60 seconds. `voice_server_mute` / `voice_server_unmute` set or clear a mark that everyone receives as `voice_server_mute_changed`; it is advisory (the target client closes its own microphone; an unmute the member sends is ignored while the mark is set) and ends when the member leaves. `voice_lock_room` / `voice_unlock_room` broadcast `voice_room_lock_changed`; a lock is held in memory and ends when the room empties or the server restarts. The sender must be in the room and have a moderation level there (`error` "Moderator access required" otherwise); nobody can act on themselves, and a moderator cannot act on a member of equal or higher level (`error` "Not allowed"). The five frames are refused with an `error` in a DM call. Each change is audited (`voice_kick`, `voice_server_mute`, `voice_server_unmute`, `voice_lock`, `voice_unlock`, with the level). A timeout or mute in a channel (by a moderator or AutoMod) also removes the member from that channel's voice room (`voice_denied`, code `"timed_out"`). Every `voice_signal` (and the mute, deafen, speaking and screen share frames) is dropped unless the sender is currently in that room, on the socket that owns the session, and the target is too. A kick is enforced against normal clients only: the server cannot cut an existing peer-to-peer link of a modified client.
- `voice_state`: Sent to joiner with list of all current voice users in the channel, plus `resume_token` (random per join, sent only to the joining socket). After a resume the same message is sent with `"resumed": true`
- One voice session per account. A second `voice_join` from another socket of the same account (a second tab) is answered with `voice_denied` ("Already in voice chat"), also while the first session is waiting to reconnect. Closing a tab that does not own the session does not affect the call, and only the owning socket can leave, mute, deafen, signal or share a screen
- **Reconnecting:** when the socket that owns a session closes, the session is kept for 20 seconds. Other members receive `voice_user_reconnecting` (no `voice_user_left`), and the member's entry has `"reconnecting": true` in `voice_state` and `voice_reconnecting: true` in the `users` list. Reconnecting members receive no voice messages and cannot be signalled. If nothing resumes the session within 20 seconds, `voice_user_left` is sent
- **Resume:** on the new socket, send `voice_join` with `resume: true`, the `room` from `voice_state.channel` and the `resume_token`. It is accepted only for the caller's own account, only with the matching token, and only while the session is reconnecting or is owned by an older socket of the same account (the older socket then receives `voice_denied`). Room access is checked again (private channel membership, stream bans, DM participation) and a channel room is refused for an anonymous member. No channel `join` is needed first. On success the new socket gets `voice_state` with `resumed: true` and the others get `voice_user_resumed`; otherwise the socket gets `voice_resume_failed` and the session is left as it was. The token stays valid for the lifetime of the session and is never put in broadcasts or logs; clients should keep it in memory only
- **No grace period** for a `voice_leave`, for a revoked session (password reset, role change, account delete, password change, logout: close code 4001, also when the call is only being held) or for switching anonymous mode on: the session is removed at once and `voice_user_left` is sent. A logout closes only the chat sockets opened with that session and ends that session's call; the account's other sessions stay
- **Leave while disconnected:** a `voice_leave` that carries `resume_token` (and optionally `room`) ends the account's own voice session from any of its sockets, also while the session is only being held. It is accepted only with the matching token for the caller's own account and removes the session at once; with a wrong token nothing happens. A client whose user clicks Leave while its socket is down sends this on the next socket instead of a resume
- **Removed from the room:** a member who is banned from the stream chat, removed from a private channel, left out when the channel is made private, or leaves a group DM while in that room's call is taken out of the call at once (`voice_denied`, then `voice_user_left` for the others)
- A `voice_signal` offer may carry `"fresh": true`: the receiver discards its existing connection to the sender and starts over (used when joining and when resuming)
- `voice_signal`: Targeted relay — only sent to the specified user, never broadcast
- `voice_speaking`: Rate-limited to 1 broadcast per 100ms per user
- Users can only be in voice in one channel at a time; switching text channels auto-leaves voice
- User list (`users` messages) includes `in_voice`, `voice_muted`, `voice_deafened`, `voice_speaking` fields

**Per-user volume and local mute (client only):** the voice bar and the user list let each member set a playback volume (0 to 200%) and a local mute for every other member of the call they are in; right-click or long-press a name in the voice bar or the online-users list (or focus it and press Enter, the context-menu key or Shift+F10) to open the popover. Both settings change only what that browser plays. They are kept in that browser's `localStorage` under `voice_peer_prefs_<own user id>`, keyed by the other member's user id, and are never sent to the server, so there is no API and no message for them and other members cannot see them. Deafen silences everyone regardless of these settings. On iPhone and iPad (and where Web Audio is unavailable) audio plays through the audio element and the slider stops at 100%; iOS Safari may ignore element volume, so there only the local mute is certain to work, and the popover says so when the device refuses a volume. A member who is anonymous in a channel is not in a channel call (see above), and the online-users list gives other members no `user_id` for them, so no setting can be attached to them there; in a direct-message call they appear as "Anonymous" with the account id the call payload already carries.

**Voice setup (client only):** the voice settings window in chat sets the microphone and speaker, the voice-activity threshold, the push-to-talk key and release delay, and offers a level meter and a loopback test. All of it lives in that browser's `localStorage` (`voice_prefs`: `mode`, `pttKey`, `vadThreshold`, `pttDelay`, `inputDeviceId`, `outputDeviceId`; plus the marker `voice_gate_notice_seen`, value `1`, which records that the one-time notice about a strict saved threshold has been shown) and is never sent to the server, so there is no endpoint and no WebSocket message for it, no database change, and `voice_join`, `voice_speaking` and `voice_signal` are unchanged. In VAD mode `voice_speaking` now follows the real gate: the track sent to peers is disabled while the member is silent (a disabled track carries silence; some browsers still send keep-alive packets) and enabled for 750 ms after the level was last above the threshold. With a push-to-talk release delay (0 to 1000 ms) `voice_speaking` with `speaking: false` is sent when the delay ends, not when the key is released. Changing the microphone during a call replaces the track in each connection (`RTCRtpSender.replaceTrack`) with no new offer, no `voice_leave` and no new join; the resume token is unaffected.

---

### Public Endpoints

These endpoints are publicly accessible without authentication.

#### GET /robots.txt
Returns robots directives for search engine crawlers. Allows access to public pages (`/about`, `/live`, `/login`, `/guides`, `/api-docs`) while blocking authenticated areas. Includes per-bot directives for Googlebot, Bingbot, DuckDuckBot, and Yandex.

**Response:** `text/plain`

---

#### GET /sitemap.xml
Returns an XML sitemap listing public pages with the portal's configured hostname, last modification dates, change frequencies, and priorities.

**Response:** `application/xml`

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
{"type": "history_page", "before_id": 101, "limit": 50, "req": 7}
{"type": "history_page", "around_id": 42, "req": 8}
{"type": "history_page", "req": 9}
```

- `reply_to` (optional): Message ID to reply to. Must be in the same channel.
- `delete`: Admins/moderators can delete any message; regular users can only delete their own.
- `react`: Toggles a reaction on a message (add if not present, remove if present). Max 10 chars per emoji.
- `edit_message`: Edit own message within 5-minute window. Re-encrypted before storage.
- `pin_message` / `unpin_message`: Moderator/admin only. Pin or unpin a message in the current channel.
- `mark_read`: Update the user's read position for unread tracking.
- `history_page`: Read more of the channel this socket joined (the channel is never taken from the request). `before_id` asks for the page older than that message, `around_id` for a window around a message, neither for the newest page again (used by "Jump to present"). `limit` defaults to 50 and is capped at 100; an id outside 1 to 9223372036854775807 is a `history_error` with `invalid` and the socket stays open; `req` (a number or short string, optional) is echoed in the reply so a client can drop replies it no longer wants. The access check runs on every request, so a member removed from a private channel, or banned from the stream chat, gets `history_error` with `not_found` even on a socket that joined earlier. At most 30 requests per minute per member over all sockets (and the HTTP route): then `history_error` with `rate_limited` and `retry_after` seconds. Never marks anything as read.
- `channel_activity` (server to client, 1.19.0): an ephemeral signal that a channel has a new message, so a page can raise the unread badge of a channel it has not joined. The frame holds the channel id and nothing else: no text, no author, no flag. It goes to the sockets of online members who are not in that channel's room (not to the sender, not to a member who is in the room), and only to a member who may read the channel (the same check as join and history), so a private channel's or a non-public stream chat's signal never reaches anyone else. A member whose level for the channel is `mentions` or `none`, or whose timed mute is running, gets none (an @mention reaches them as a notification). Direct messages do not use it (`dm_unread_update`). Nothing is stored. `message` frames of a channel also carry `channel` (name) and `channel_id` now, so a client can tell which room a frame is from while it switches.
- `@here` and `@everyone` (1.19.0): in a `message` the plain-text tokens `@everyone` and `@here` (not in a code span, not part of a longer word) notify members when the sender may use them: global staff, anyone with a moderator level in that chat (`channel_info.mod_level` not `none`), or any member when the channel's switch is on. `@everyone` reaches every member who may read the channel (a private channel's members), `@here` those with an open chat socket who do not appear offline; a member whose level is `none` or whose timed mute runs is left out, as is the sender; at most 500 members per message, one `mention` notification row each, written in one transaction together with the members also named in the text (one row per member, a named member keeps the personal text). A sender under a chat timeout or mute cannot post at all; a recipient under one is still notified. The notification's `data` carries `channel`, `channel_id`, `message_id` and `mass` (`everyone` or `here`). Where the sender may not, the text is ordinary text. A sender who is not admin or superadmin gets one per 60 seconds: the message is posted and only the sender receives `{"type": "notice", "code": "mass_mention_limited", "retry_after": 31, "message": "..."}` (`code` `mass_mention_capped` when the 500 limit cut the list). An anonymous sender's is dropped silently, as an anonymous @mention is. In the `mention_spam` auto-moderation rule each counts as 5 mentions where the sender may use it (elsewhere it is plain text and counts as one); staff are blocked by the rule like everybody else. `here` and `everyone` are refused as username and nickname. The switch: `{"type": "set_mass_mentions", "allowed": true}` (staff in any channel they can read, the owner of a stream in its own chat; anyone else gets `Not authorized`, a non-boolean `allowed` is an `error` frame) answers the room with `{"type": "mass_mentions_changed", "channel_id": 3, "allowed": true}` and is audited as `mass_mentions_set`. `channel_info` carries `allow_mass_mentions` (the switch) and `can_mass_mention` (whether the asking member may use the tokens); `GET /api/chat/channels` rows carry `allow_mass_mentions`.
- **Access is checked again on every action.** `message`, `edit_message`, `react`, `create_poll`, `vote_poll`, `close_poll`, `delete`, `pin_message`, `unpin_message`, `timeout_user`, `mute_user`, `unmute_user` and `history_page` are refused with the error of a missing channel (`Channel not found`, or the stream-ban or private-channel text) when the socket's channel has been closed to the member since it joined: the stream was made private, the member was banned from its chat or removed from the private channel. A `voice_join` into the channel's voice room gets `voice_denied` with that text instead (so the client ends the join it started), and a `voice_join` with `resume` for a room the member can no longer read gets `voice_resume_failed` and the held call is dropped. `typing` is dropped without an answer. A `join` that is refused (same checks) answers with an `error` frame that carries the same `channel` field (the channel's name; for a join by `channel` name of a channel that does not exist, the name asked for; absent for a join by id or stream key that finds nothing) and leaves the socket in no channel, so its next `message`, `react`, `create_poll` or `history_page` is dropped or answered as above; the client must send a successful `join` first.
- **Sockets are put out when access is lost.** When the stream is made not public, a member is removed from a private channel (`DELETE /api/chat/channels/{id}/members/{user_id}`, by a moderator or by the member), a member is banned from a stream's chat (the `ban` message or `POST /api/streams/{id}/bans`) or a channel is made private, every socket in that channel's room whose member can no longer read it is removed from the room at once. It receives one `{"type": "error", "message": "Channel not found", "channel": "<name>"}` frame (`channel` is the name of the room it was put out of, so a page showing another channel ignores it) and nothing more from the room (no messages, edits, reactions, typing or user lists), its voice call in that room ends (`voice_denied`, then `voice_user_left` for the others), and it has no current channel until it sends a successful `join`. The others in the room get `user_left` and a new `users` list.

**Messages (Server → Client):**
```json
{"type": "channel_info", "name": "general", "description": "..."}
{"type": "history", "channel_id": 3, "messages": [...], "has_more": true}
{"type": "history_older", "req": 7, "channel_id": 3, "messages": [...], "has_more": true, "has_newer": false, "found": true}
{"type": "history_around", "req": 8, "channel_id": 3, "messages": [...], "has_more": true, "has_newer": true, "found": true}
{"type": "history_error", "req": 7, "error_code": "rate_limited", "message": "Too many history requests, try again shortly", "retry_after": 12}
{"type": "users", "users": [{"user_id": 1, "username": "john", "nickname": "Johnny", "role": "user", "anonymous": false, "avatar": {...}}]}
{"type": "channel_activity", "channel_id": 3}
{"type": "message", "id": 43, "user_id": 1, "username": "john", "nickname": "Johnny", "role": "user", "anonymous": false, "avatar": {"color": "#3b82f6", "emoji": "🚀"}, "message": "Reply!", "reply_to": 42, "reply_preview": {"id": 42, "username": "alice", "message": "Hello!"}}
{"type": "user_joined", "username": "newuser", "role": "user", "anonymous": false}
{"type": "user_left", "username": "newuser"}
{"type": "typing", "username": "john"}
{"type": "message_deleted", "message_id": 42, "deleted_by": 1}
{"type": "channel_renamed", "old_name": "dev-talk", "new_name": "engineering"}
{"type": "channel_deleted", "channel": "old-channel"}
{"type": "channel_cleared", "cleared_by": "admin", "message_count": 150}
{"type": "messages_pruned", "channel": "general", "ids": [41, 42, 43]}
{"type": "error", "message": "Slow down! You're sending messages too fast."}
{"type": "reaction_update", "message_id": 42, "emoji": "👍", "user_id": 1, "added": true, "count": 3}
{"type": "message_edited", "message_id": 42, "message": "Updated text", "edited_at": "2026-02-10T..."}
{"type": "message_pinned", "message_id": 42, "message": "Important info", "username": "alice", "pinned_by": "admin"}
{"type": "message_unpinned", "message_id": 42}
{"type": "pinned_messages", "messages": [{"id": 42, "username": "alice", "message": "Important info", "pinned_at": "..."}]}
```

- `reply_to` / `reply_preview`: Present on messages that are replies. Preview includes parent message's username and text (truncated to 100 chars). Anonymous parent messages show "Anonymous" as username.
- `history`, `history_older` and `history_around` carry messages in one shape (see `GET /api/chat/channels/:id/messages`); `has_more` says older messages exist. `error_code` of `history_error` is `invalid`, `rate_limited` or `not_found`. A `history_around` with `found: false` has no messages.
- `reactions`: Array of `{emoji, count, user_ids}` included in history messages. Real-time updates sent as `reaction_update`.
- `message_edited`: Broadcast when a message is edited (includes new plaintext).
- `message_pinned` / `message_unpinned`: Broadcast when a mod pins/unpins a message.
- `pinned_messages`: Sent on channel join with all pinned messages for the channel. The messages carry no `pinned_by` or `pinned_by_username` (a pinner may chat anonymously).
- `message_deleted`: Broadcast when a message is deleted.
- `channel_renamed`: Broadcast when an admin renames a channel via REST API.
- `channel_deleted`: Broadcast when an admin deletes a channel via REST API.

---

#### WS /ws/user-connection/{id}
Connect to a user connection. `{id}` is the opaque string token.

Binary WebSocket relay to the target service.

---

#### WS /ws/terminal/local
Admin-only local server terminal. Supports shell selection via query parameter.

**Query Parameters:**
- `shell` (optional): Shell path (e.g., `/usr/bin/fish`). Must be in the server's allowed shells list. Defaults to `/bin/bash`.

Text-based terminal I/O with server-side terminal compatibility (DA1/DA2/DSR queries are intercepted and responded to immediately with xterm.js-matching responses to prevent shell timeouts).

---

#### WS /ws/user-connection/{id}
User connection relay. `{id}` is the opaque string token. For SSH connections, supports shell override via query parameter.

**Query Parameters:**
- `shell` (optional): Remote shell path override (e.g., `/usr/bin/fish`). Overrides the connection's configured shell.

Terminal capability queries (DA1/DA2/DSR) pass through to xterm.js which responds natively. Unlike the local terminal, SSH connections do not intercept queries server-side — asyncssh's line-buffered `readline()` would delay escape sequences that lack newlines, so queries flow through the WebSocket to xterm.js for reliable sub-200ms round-trip responses. The client also sends a resize on connect to sync terminal dimensions after the auth phase.

---

#### WS /ws/terminal/:id
Terminal session for a service.

Text-based terminal I/O. Keys that are not text are ordinary `input` data: Ctrl+C is `"\u0003"`, Tab is `"\t"`, Esc is `"\u001b"`, and the arrow keys are `"\u001b[A"` to `"\u001b[D"` (`"\u001bOA"` to `"\u001bOD"` while an application has switched on application cursor keys). The touch key bar in the web terminal sends exactly these.

---

#### WS /ws/vnc/:id
VNC connection.

Binary noVNC protocol relay.

---

### VOD Storage

Users can configure remote SFTP storage for recorded VODs (MKV files). Each user has their own storage configuration.

**Credentials (1.16.0):** every route in this section needs a browser session or a token or API key with the all-scope `*`. A stream key (`live_`) authorises publishing only and a narrowly scoped API key is not enough: both get `403`.

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

#### POST /api/vods/storage/host-key/accept
Pin the VOD storage host key. Needs a full-scope credential (a browser session or an all-scope token or API key; stream keys and scoped keys get 403). Body `{"fingerprint": "SHA256:..."}`, which must be the `host_key_refused.fingerprint` the settings showed; any other fingerprint, or no refused key being stored, gives 409 `{"error", "type": "host_key_stale"}`. The storage pins the key it sees on its first connect automatically (logged in the activity feed); a different key later is refused and logged (`vod_host_key_refused`), `GET /api/vods/storage` then shows `host_key_refused: {fingerprint, at}` next to `host_key_fingerprint`, and this route accepts the new key. `host_key_ignore` (boolean, in the save body) turns the check off.

#### POST /api/services/{id}/host-key/accept
Same for an admin-defined `ssh` service (admin only, with the same full-scope credential rule), with the same body and the same 409 for a stale prompt. An admin may also set `config.host_key_fingerprint` when creating or editing the service. An edit that changes the host or port the plugin dials (`config.host` / `config.port` when set, else the service's own) clears the pin.

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

Notifications are delivered two ways:
1. **REST** — poll `/api/notifications` on page load and every 30 seconds
2. **WebSocket push** — the chat WebSocket (`/ws/chat`) sends `{"type": "notification", "notification": {...}}` in real time when a new notification is created

The browser's `Notification` API is used for **desktop alerts** when the page is in the background. Users opt in via the "Enable alerts" button in the notification bell dropdown. Desktop notifications are tagged by type (e.g., `stream_live`) so repeat events replace rather than stack.

**Notification types:** `stream_live`, `stream_offline`, `dm_received`, `mention`, `system`

**`stream_live` (1.16.0):** sent once per 10 minutes per stream, and an `everyone` notice (like a card in the shared announce channel) at most once per 10 minutes per streamer whatever stream it is for (stored per streamer, so deleting and recreating a stream does not reset it; while it is taken only the stream's followers are told), to the stream's audience (`golive_audience`: its followers, or everyone) and only to members who may watch it at that moment: a public stream's audience members, the audience's administrators for a private one; never the owner. It is written in the background in batches, a moment after the stream goes live. `data` has `stream_id`, `streamer`, `title` and `url` (the logged-in watch page, built from `PUBLIC_BASE_URL` or `HOSTNAME`, never from a request header); it never carries a stream key, a `pub_` key or an RTMP address. `message` is the owner's go-live message, filled in.

---

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
      "title": "alice is live!",
      "message": "Gaming Session just went live",
      "data": {"stream_id": 5, "streamer": "alice", "title": "Gaming Session", "url": "https://portal.example.com/watch/5"},
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
  "description": "New description",
  "port": 8555,
  "config": {
    "rtsp_port": 8555,
    "log_level": "debug"
  },
  "enabled": true
}
```

All fields are optional. For managed services, `display_name`, `description`
and `port` are metadata-only; changing `config` restarts the process to
apply it (except for `systemd`-type services, whose `config` only selects
which unit to track). `enabled` controls whether the service auto-starts on
Portal boot — it is honored at creation time too (services are **not**
force-enabled by default).

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
    },
    "systemd": {
      "name": "systemd",
      "display_name": "Systemd Unit",
      "description": "Control a systemd service already installed on the host",
      "version": "1.0.0",
      "icon": "server",
      "default_port": null,
      "config_schema": {
        "type": "object",
        "properties": {
          "unit": {"type": "string", "description": "unit name without .service"}
        },
        "required": ["unit"]
      }
    }
  }
}
```

**`systemd` service type.** Wraps a unit that is already installed on the
host (a game server, a file share, a database). Portal does not run the
process — `start`/`stop`/`restart` shell out to `systemctl`, status and
health come from `systemctl show` / `is-active`, and logs come from
`journalctl`. `config.unit` must resolve to a real unit or the create/update
call returns `400`. Portal never stops the unit implicitly: not on Portal
shutdown, not when the wrapper is deleted — only an explicit `stop` call
does. A unit started or stopped outside Portal is reconciled onto the card
within one health-monitor cycle (and immediately on any status read).

---

#### Service access grants

An admin can let a non-admin control or read one managed service:

- `GET  /api/managed-services/{id}/grants` — list the live grants `[{user_id, username, actions, created_at, granted_by_username, expires_at, expires_in}]`
- `GET  /api/admin/grants` — every live service grant and connection share on the portal (admin): `{"service_grants": [...], "connection_shares": [...]}`, each with grantee, grantor, `created_at`, `expires_at`, `expires_in`.
- `POST /api/managed-services/{id}/grants` — body `{"usernames": [...], "actions": ["control","logs","files"], "expires_in": "30d"}`. `expires_in` works as for connection shares (`1h` ... `90d`, `never`; omitted means `never` for a new grant and keeps the current end time of a live one; anything else, or an `expires_at` in the body, is 400); granting again replaces the actions and, when `expires_in` is sent, the end time; after the end time every check refuses at once and the sweeper deletes the row and audits `service.grant_expired`. `control` = start/stop/restart; `logs` = logs + status; `files` = the jailed file browser — browse/edit the server's files and download backups (game servers only). Audited `service.grant`.
- `DELETE /api/managed-services/{id}/grants/{grantee_id}` — revoke. Audited `service.ungrant`.

Once granted, `POST /api/services/{id}/start|stop|restart` (and the
`/api/managed-services/{id}/...` equivalents) and the logs/status endpoints
accept that user; `GET /api/me` returns `granted_services: {id: ["control","logs"]}`.

---

#### Game servers (SteamCMD)

Deploy and run dedicated game servers. A deployed server is a `game_servers`
row + a generated `portal-gs-<name>.service` systemd unit + a managed service
(`plugin: "gameserver"`) — so lifecycle control (`/api/services/{service_id}/...`)
and the grant system above apply unchanged. SteamCMD runs under an unprivileged
account; installs go under a dedicated game-data disk.

- `GET  /api/game-catalog` — list catalog entries (any authenticated user).
- `POST /api/game-catalog` — add/replace a custom entry (admin). Body `{key, name, steam_app_id, start_cmd, start_args?, stop_signal?, steam_login?, config_paths?[], backup_paths?[], config_root?, game_port?}`. `config_root` (`~` expands to the run-as account's home) overrides the install dir for the config editor and backup — for games that keep config/saves elsewhere. The ~85 built-in entries are re-synced from code on every restart; admin-added entries (`builtin: 0`) are left alone.
- `DELETE /api/game-catalog/{key}` — remove a custom entry (admin; built-ins are protected).
- `GET  /api/game-storage-roots` — list registered game-data storage roots (admin). Each entry has `disk: {total, used, free}` (`shutil.disk_usage`, `null` if unreadable) and `server_count` (deployed servers installed under it).
- `POST /api/game-storage-roots` — register a new root (admin). Body `{path, label?, create_if_missing?}`. `path` must be absolute, outside Portal's own source tree and the run-as account's home, and non-overlapping with every already-registered root. The first-ever root is always the default.
- `POST /api/game-storage-roots/{id}/set-default` — make a root the default for future deploys (admin).
- `DELETE /api/game-storage-roots/{id}` — remove a root (admin). Refused if it's the default, the only remaining root, or any `game_servers` row is installed under it — the registration is removed, files on disk are untouched.
- `GET  /api/game-servers` — admin: all; non-admin: only servers they hold a grant on. Each row is enriched with live `status`; `installed_build`/`latest_build` are refreshed by a background check every 6 h (drives the "up to date / update available" badge).
- `POST /api/game-servers` — deploy (admin). Body `{catalog_key | custom{...}, name, install_dir?, storage_root_id?, start_args?, steam_login?, enable?, start?}`. `install_dir` (an explicit path) wins if given; otherwise `storage_root_id` picks which registered root the deploy lands under (default: the admin-designated default root). Returns `201 {game_server, job_id}` and kicks off the SteamCMD install job.
- `GET  /api/game-servers/{id}` — one server (admin or any grant).
- `DELETE /api/game-servers/{id}?delete_files=<bool>` — disable + remove the unit, service row and `game_servers` row; optionally delete the install directory (admin).
- `POST /api/game-servers/{id}/update` — start a SteamCMD update job; no-op if already on the latest build, unless the launch file is missing, which repairs the install (admin or `control` grant). Returns `{job_id}`.
- `POST /api/game-servers/{id}/check-build` — refresh `installed_build` / `latest_build` (admin or `logs` grant).
- `GET  /api/game-servers/jobs/{job_id}` — poll an install/update job: `{id, name, status, log[], started_at, finished_at}`. `status` ∈ `running | completed | failed`.
- `GET  /api/game-servers/{id}/config` — list editable config files plus the full backup set (admin or `files` grant). Returns `{files[], backup_files[], backup_total, install_dir}`. `files` is scoped to the catalog entry's `config_paths` globs; `backup_files` also includes its `backup_paths` (save/world) globs.
- `GET  /api/game-servers/{id}/config/read?path=<rel>` — read one file (admin or `files` grant).
- `POST /api/game-servers/{id}/config/write` — body `{path, content}`; written back as the game account. Audited `gameserver.config_edit` (admin or `files` grant).
- `GET  /api/game-servers/{id}/config/download` — download a `.tar.gz` of the config + save/world files (admin or `files` grant). Capped at 512 MB total / 128 MB per file. Audited `gameserver.backup_download`.
- `GET  /api/game-servers/{id}/files?root=<key>&path=<rel>` — one directory level of the jailed file browser (admin or `files` grant). `root` is one of the keys in the response `roots[]` (`install` = the install dir; `config` = the config/saves dir when it resolves elsewhere). Returns `{root, path, entries[], roots[], pinned[]}`; `entries` are `{name, type, size, mtime, path, writable}` with symlinks omitted; `pinned` is the catalog's `config_paths` matches (each tagged with its `root`). Every path is resolved and confined to a root; `..`, absolute paths and symlinks are rejected.
- `GET  /api/game-servers/{id}/files/read?root=&path=` — read one file (admin or `files` grant). Returns `{path, content, writable}`. `writable` is false for non-text/config extensions and files over 2 MB.
- `POST /api/game-servers/{id}/files/write` — body `{root, path, content}`; only existing files with a config-like extension (`.ini .cfg .conf .json .xml .yaml .lua .txt .toml …`) are writable, written back as the game account. Audited `gameserver.file_edit`.
- `GET  /api/game-servers/{id}/files/download?root=&path=` — download a single file (admin or `files` grant). Capped at 128 MB.
- `POST /api/game-servers/{id}/files/upload` — multipart, one or more `file` parts plus `root`/`path` fields naming the target directory (admin or `files` grant). Send `root`/`path` *before* the `file` parts — they're read as encountered, streaming, so a `file` part seen before them falls back to `root=install, path=""` (still jailed, just possibly the wrong directory). Upload is a notch stricter than `files/write`'s allowlist: same config-like extensions minus `.lua` (creating a brand-new file is a bigger step than editing one already on disk — see `docs/SECURITY-AUDIT-2026-09.md` F6), and the target need not already exist. Per-file cap 8 MB, 64 MB per request; oversized or disallowed-extension files are rejected individually. Returns `{results: [{name, ok, path?, size?, replaced?, error?}]}`. Audited `gameserver.file_upload` when at least one file succeeds.
- `DELETE /api/game-servers/{id}/files/delete?root=&path=` — delete one file (admin or `files` grant). Same allowlist as upload (no `.lua`); never a directory. Audited `gameserver.file_delete`.
- `POST /api/game-servers/{id}/files/rename` — body `{root, path, new_name}`; renames a file in place, same directory only, `new_name` must keep the source file's extension (admin or `files` grant). Same allowlist as upload. Audited `gameserver.file_rename`.
- `POST /api/game-servers/{id}/resync-catalog` — re-pull `config_paths` / `backup_paths` / `config_root` for a deployed server from its (builtin) catalog entry; a server with a missing launch file also takes the entry's `runtime` and `start_cmd` (admin). Also runs automatically for every builtin-based server on restart.
- `POST /api/game-servers/{id}/launch-options` — edit the launch config and regenerate the unit. Body `{start_args?, stop_signal?, start_cmd?, runtime?}`. `start_args` (shell-style quoting, no shell is run — split to argv) and `stop_signal` (`SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT`/`SIGKILL`) take **admin or a `control` grant**; `start_cmd` (a plain relative path that must exist under the install dir) and `runtime` (`native`/`wine`, see [WINDOWS-GAME-SERVERS.md](WINDOWS-GAME-SERVERS.md)) are **admin only** → `403` otherwise. Returns `{success, game_server, restart_required}`; does not restart the server. Audited `gameserver.launch_options`.

Deploy/destroy are audited `gameserver.deploy` / `gameserver.delete`. Start/stop/restart/logs reuse `/api/services/{service_id}/...`. Start, stop and restart (managed or systemd-bound) write an audit entry `service.start`, `service.stop` or `service.restart` (actor, service id and name, action) when they succeed; a stop done this way is deliberately silent to the `service.health_changed` alerts, so the audit entry is its record.

---

#### POST /api/services/:id/start
Start a managed service — admin, or a user holding a `control` grant. A successful start, stop or restart is audited as `service.start`, `service.stop` or `service.restart`.

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

### Device-Wide Metrics (Admin)

Whole-host activity persisted to SQLite, sampled every 60s (independent of the
Portal-traffic metrics above). Retained per the `retention_device_metrics_days`
setting (default 14). All three endpoints take `?hours=N` (1–336, default 6)
and return downsampled, chart-ready series plus the latest raw snapshot.

#### GET /api/metrics/device/processes
CPU and RSS over time, grouped by systemd unit (from each pid's cgroup) or, for
unmanaged processes, by process name.

```json
{
  "hours": 24, "sample_interval": 60, "ncpu": 4, "truncated": 6,
  "series": [
    {"key": "portal.service", "label": "portal", "kind": "service",
     "points": [{"t": "...", "cpu": 3.1, "mem_rss": 512000000, "mem_percent": 3.0}]}
  ],
  "current": [{"key": "...", "label": "...", "kind": "service|process",
               "cpu_percent": 3.1, "mem_rss": 512000000, "mem_percent": 3.0, "count": 7}]
}
```

#### GET /api/metrics/device/ports
Per listening port, the count of established connections on that local port over
time, plus the owning process/unit.

```json
{
  "series": [{"key": "tcp/443", "proto": "tcp", "port": 443,
              "process": "python", "unit": "portal.service",
              "points": [{"t": "...", "established": 12.0}]}],
  "current": [{"proto": "tcp", "addr": "0.0.0.0", "port": 443, "pid": 1234,
               "process": "python", "unit": "portal.service", "established": 12}],
  "truncated": 0
}
```

#### GET /api/metrics/device/ips
Remote IPs with an active connection to the host. `ips` aggregates the whole
window (peak connections, first/last seen, ports hit, serving processes);
`timeline` is distinct-IP and total-connection counts over time.

```json
{
  "ips": [{"ip": "203.0.113.4", "max_conns": 3, "samples": 40,
           "first_seen": "...", "last_seen": "...",
           "ports": [443], "processes": ["python"]}],
  "timeline": [{"t": "...", "distinct_ips": 18, "conns": 42.0}],
  "current": [{"ip": "203.0.113.4", "conns": 3, "ports": [443],
               "processes": ["python"], "states": {"ESTABLISHED": 3}}],
  "unique_ips_window": 220, "truncated": 0
}
```

> Loopback addresses are excluded. Connection counts are point-in-time samples —
> a connection that opens and closes between ticks is not recorded.

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

#### GET /api/settings/permissions  and  PUT /api/settings/permissions
Feature switches (admin). `allow_user_connections` and `allow_user_streams` are booleans. **`stream_announce_channel_id` (1.16.0)** is the channel a go-live card of a public stream is posted into, in addition to the stream's own chat: a channel id, or `null` for none (the default). The channel must exist (`404`), must not be a stream's own chat (`400`) and must be readable by every member, not private (`400`); the same is checked again at every go-live, so a channel made private later receives nothing.

---

### Data Retention (Admin)

Data retention settings control automatic cleanup of old chat messages, DMs, notifications, activity logs, and service logs.

#### GET /api/admin/retention
Get data retention configuration settings.

**Auth**: Admin or higher

**Response (200)**:
```json
{
  "retention_chat_days": "7",
  "retention_chat_max_days": "3650",
  "retention_dm_days": "30",
  "retention_notifications_days": "30",
  "retention_activity_max": "500",
  "retention_service_logs_max": "1000",
  "retention_device_metrics_days": "14",
  "retention_recordings_days": "30",
  "retention_security_events_days": "180",
  "cleanup_interval_hours": "6",
  "auto_vacuum": "true"
}
```

---

#### PUT /api/admin/retention
Update data retention settings.

**Auth**: Superadmin only

**Request**:
```json
{
  "retention_chat_days": "14",
  "retention_dm_days": "60",
  "retention_notifications_days": "30",
  "retention_activity_max": "500",
  "retention_service_logs_max": "1000",
  "retention_device_metrics_days": "14",
  "retention_recordings_days": "30",
  "retention_security_events_days": "180",
  "cleanup_interval_hours": "6",
  "auto_vacuum": "true"
}
```

Setting any value to `0` disables cleanup for that category (keeps forever).

**Response (200)**:
```json
{
  "updated": true,
  "config": {
    "retention_chat_days": "14",
    "retention_dm_days": "60",
    "retention_notifications_days": "30",
    "retention_activity_max": "500",
    "retention_service_logs_max": "1000",
    "retention_device_metrics_days": "14",
    "retention_recordings_days": "30",
    "retention_security_events_days": "180",
    "cleanup_interval_hours": "6",
    "auto_vacuum": "true"
  }
}
```

---

#### POST /api/admin/retention/run
Trigger immediate data cleanup cycle.

**Auth**: Superadmin only

**Response (200)**:
```json
{
  "cleanup_complete": true,
  "deleted": {
    "chat_messages": 0,
    "dm_messages": 0,
    "notifications": 0,
    "activity_log": 0,
    "expired_tokens": 59,
    "expired_api_keys": 0,
    "service_logs": 4998,
    "chat_files": 12,
    "chat_file_bytes": 3407872,
    "chat_orphan_sweep": {
      "report_only": true, "scanned": 140, "orphans": 3, "bytes": 52114,
      "names": ["0123456789abcdef0123456789abcdef.png"], "deleted": 0, "deleted_bytes": 0
    },
    "vacuumed": true
  }
}
```

`chat_files` and `chat_file_bytes` are the upload files removed together with the deleted chat and DM messages. A file that another row still names is kept: in a message image or attachment, in message or DM text, a reply preview, a poll question or option, a user status message, a channel topic or description, or a stream name or description. If a message cannot be decrypted, or the check cannot complete, no file is removed and `chat_files_skipped` (present only then) says why. `chat_orphan_sweep` reports upload files that no message refers to (older than 24 hours, `names` lists at most 20). `report_only` is `true` unless the server setting `chat_orphan_sweep_delete` is `"true"`; in that case `deleted` and `deleted_bytes` say what was removed. `skipped` appears instead of results when the upload folder is missing or a link, a message could not be decrypted, or the check could not complete.

---

### Backups (Superadmin)

Backup archives hold the database, `.env`, the encryption salt and the invite code, so they are as sensitive as root access to the portal. All five routes need a superadmin whose credential carries admin power: stream keys and narrowly scoped API keys or tokens get `403`. Download, delete, changing the extra destination and lowering the number of archives to keep also need the superadmin's own browser login session: an API key, bearer token or `?token=` value gets `403` with `A browser login session is required`.

#### GET /api/admin/backups
List the archives (newest first) with the settings and the last result.

**Auth**: Superadmin (any full-power credential)

**Response (200)**:
```json
{
  "archives": [{"name": "portal-backup-20261118-030000.tar.gz", "size": 1048576,
                "created_at": "2026-11-18T03:00:00+00:00", "portal_version": "v1.11.0",
                "members": [".encryption_salt", ".env", ".invite_code", "portal.db"], "readable": true}],
  "config": {"enabled": true, "interval_hours": 24, "keep": 7, "extra_dir": ""},
  "status": {"backup_last_run_at": "...", "backup_last_ok_at": "...", "backup_last_status": "ok",
             "backup_last_error": "", "backup_last_name": "portal-backup-20261118-030000.tar.gz"},
  "free_bytes": 52428800000,
  "stage_mode": false
}
```

---

#### POST /api/admin/backups/run
Take a backup archive now. Returns at once with `409` when a backup is already running (updates, by contrast, wait up to ten minutes for a running backup). Each run first removes leftover `.work-*` directories and `.partial-*.tar.gz` files older than one hour from `backups/archives/`. Audited `backup.run` (size, names pruned, stale files removed).

**Auth**: Superadmin (any full-power credential)

**Response (201)**: `{"name", "path", "size", "created_at", "portal_version", "pruned": [names], "stale_removed": [names], "missing": [], "extra_path", "extra_error"}`. A failed copy to the extra destination does not fail the backup; it is reported in `extra_error`.

**Errors**: `409` a backup is already running; `500` the backup failed (for example less than twice the database size is free).

---

#### PUT /api/admin/backups/settings
Change the schedule. All fields are optional.

**Auth**: Superadmin; browser login session only when `extra_dir` is changed or `keep` is lowered below the saved value

**Request:**
```json
{"enabled": true, "interval_hours": 24, "keep": 7, "extra_dir": "/mnt/other-disk/portal-backups"}
```
- `enabled` (bool), `interval_hours` (whole number 1-720), `keep` (whole number 1-100)
- `extra_dir`: absolute path of an existing directory, or `""` to turn the extra copy off. It may not be under `/tmp`, `/var/tmp` or `/dev/shm`, inside the installation directory, or inside a directory the portal serves. An unchanged value is not checked again.

**Response (200)**: `{"updated": true, "config": {...}}`. Audited `backup.settings`.

**Errors**: `400` invalid value; `403` a browser login session is required.

---

#### GET /api/admin/backups/{name}/download
Download one archive as `application/gzip`.

**Auth**: Superadmin, browser login session only. Audited `backup.download` (with the client address).

**Errors**: `400` invalid archive name; `403` not a browser session; `404` no such archive.

---

#### DELETE /api/admin/backups/{name}
Delete one archive.

**Auth**: Superadmin, browser login session only. Audited `backup.delete`.

**Response (200)**: `{"deleted": true}`

**Errors**: `400` invalid archive name; `403` not a browser session; `404` no such archive.

---

### IP Blocking, Never-Ban List and Proxy Trust (Admin)

Blocked IPs are rejected app-wide (every page and API call) before authentication. Admin routes need a credential with admin power. The never-ban list and the Cloudflare setting are changed by a superadmin only.

#### GET /api/admin/blocked-ips
List every block, including expired ones. Rows have `ip_address`, `reason`, `blocked_by`, `blocked_by_username`, `created_at`, `expires_at` (`null` is permanent), `source` (`manual` or `auto`) and `kind`: `manual`, `login` (failed sign-ins), `probe` (scanner paths), or `auto` for an automatic row written before 1.18.0. Automatic rows always have an `expires_at`; expired ones are ignored at once and deleted at start and by the data cleanup.

**Auth**: Admin

#### POST /api/admin/blocked-ips
Block an address by hand: `{"ip_address": "203.0.113.7", "reason": "...", "duration_hours": 24}` (`reason` and `duration_hours` optional; without a duration the block is permanent). A manual block replaces any existing row for that address. Refuses the caller's own current address. Response `201`: `{"success": true, "ip_address", "expires_at"}`.

**Auth**: Admin

#### DELETE /api/admin/blocked-ips/{ip}
Remove the block for an address (and any temporary scanner block held in memory for it). It also forgets the address's escalation history and failed-sign-in count, so its next automatic ban starts at the base duration.

**Auth**: Admin

An automatic block never overwrites or shortens a manual block, never shortens an automatic one and never turns a permanent block into a timed one; it only replaces a row whose own expiry has passed. Failed sign-ins (see `PUT /api/admin/login-ban`) and, when `PROBE_BLOCK_STRIKES` is on, scanner probes write automatic blocks with kind `login` or `probe`, always with an expiry.

To lift a block while locked out, stop the portal and run `sudo venv/bin/python server.py unblock <ip>` or `sudo venv/bin/python server.py clear-bans` (no migration is run; the output lists what was removed). Both also delete the escalation history of the address (all of it, for `clear-bans`).

#### GET /api/admin/login-ban
The failed sign-in blocking settings: `{"enabled": false, "max_failures": 20, "find_minutes": 10, "base_minutes": 15, "defaults": {...}, "limits": {"max_failures": {"min": 3, "max": 1000}, "find_minutes": {"min": 1, "max": 1440}, "base_minutes": {"min": 1, "max": 1440}}, "cap_hours": 24, "repeat_days": 7, "your_ip": "...", "your_ip_exempt": null}` (`your_ip_exempt` names the reason when the caller's address can never be blocked).

**Auth**: Admin

#### PUT /api/admin/login-ban
Change any of `enabled` (boolean), `max_failures`, `find_minutes`, `base_minutes` (whole numbers within the limits; anything else, an unknown key or a non-object body is `400` and nothing changes). Response (200): the same object as GET plus `"saved": true`.

The caller's address is counted for each wrong password on the web login and `POST /api/token` and each wrong 2FA code (a code refused by the 2FA limiter is not a failure here); there is no 4xx counter and no account lockout. After `max_failures` within `find_minutes` the address is blocked with kind `login` for `base_minutes`; each repeat within 7 days doubles the time up to 24 hours (a longer base is kept), and no automatic block is permanent. **Off by default**; with it off the count is still kept and nothing is blocked. Never applied to an exempt address (loopback, private, trusted proxy and Cloudflare, this host, `NEVER_BAN_CIDRS`, the never-ban list) and not counted when any account signed in from that address within the last 30 days. Every ban is an `ip_blocked` security event (no user, `result` `auto`, details `kind`, `target_ip`, `expires_at`, `seconds`, `offences`).

**Auth**: Superadmin. Audited as `login_ban.update` and recorded as a `login_ban_changed` security event (`was` and `now` of the changed values).

#### GET /api/admin/voice
The voice room cap: `{"voice_room_cap": 8, "default": 8, "min": 2, "max": 25}`.

**Auth**: Admin

#### PUT /api/admin/voice
Body `{"voice_room_cap": 6}`: a whole number from 2 to 25 (anything else, a boolean, an unknown key or a non-object body is `400` and nothing changes). Response (200): the same object as GET plus `"saved": true`. The value is read from memory and the copy is dropped on every write, so it applies to the next join; a lower cap does not remove anyone already in a room.

**Auth**: Superadmin. Audited as `voice.room_cap` (`was` and `now`).

#### GET /api/admin/proxy-limit
The logged-out request limit settings: `{"enabled": true, "per_minute": 30, "defaults": {...}, "limits": {"per_minute": {"min": 5, "max": 600}}, "your_ip": "...", "your_ip_exempt": null}` (`your_ip_exempt` names the reason when the caller's address is never limited).

**Auth**: Admin

#### PUT /api/admin/proxy-limit
Change `enabled` (boolean) and/or `per_minute` (whole number from 5 to 600; anything else, an unknown key or a non-object body is `400` and nothing changes). Response (200): the same object as GET plus `"saved": true`. A change applies at once, is kept across restarts and clears the current counts.

The limit: a request under `/proxy/`, `/search` (and `/search/...`) or `/browser` (and `/browser/...`) that carries no valid credential is counted against its client address in a token bucket of `per_minute` (30 at once, refilled at `per_minute` a minute). Over it the answer is `429` with `Retry-After` (seconds) and `{"error": "Too many requests, retry shortly"}`; the request never reaches the handler. A valid session cookie, `Authorization: Bearer` token or `?token=` is never counted; a bogus, forged, expired or revoked one is counted like none. An API key is not counted once it has been verified by an earlier request, and counted before that (the check never runs the key hash). `/login`, `/api`, `/admin`, `/health`, WebSockets elsewhere and static files are never limited. Exempt addresses (loopback, private, trusted proxy and Cloudflare, this host, `NEVER_BAN_CIDRS`, the never-ban list) are never limited; an IPv6 address is counted as its /64. **On by default.** Nothing is blocked or banned by it; each refusal is counted in the aggregated `rate_limited` security event (details `scope` `logged_out_proxy`).

**Auth**: Superadmin. Audited as `proxy_limit.update` and recorded as a `proxy_limit_changed` security event (`was` and `now` of the changed values).

#### GET /api/admin/never-ban
The admin-edited never-ban list and the effective list that no automatic block may cover.

**Auth**: Superadmin (any full-power credential)

**Response (200)**:
```json
{
  "entries": ["203.0.113.0/24"],
  "env_warnings": [],
  "effective": [
    {"source": "loopback", "label": "Loopback (always)", "entries": ["127.0.0.0/8", "::1"]},
    {"source": "private", "label": "Private and link-local networks, and the other ranges Python treats as private (always)", "entries": ["10.0.0.0/8", "..."]},
    {"source": "host", "label": "This host's own addresses (always)", "entries": ["198.51.100.4"]},
    {"source": "cloudflare", "label": "Cloudflare ranges (built-in) (always)", "entries": ["173.245.48.0/20", "..."]},
    {"source": "trusted_proxies", "label": "TRUSTED_PROXIES in .env (always)", "entries": []},
    {"source": "env", "label": "NEVER_BAN_CIDRS in .env", "entries": []},
    {"source": "admin", "label": "Never-ban list set on this page", "entries": ["203.0.113.0/24"]}
  ],
  "limits": {"max_entries": 100, "min_prefix_ipv4": 8, "min_prefix_ipv6": 16},
  "your_ip": "198.51.100.77",
  "your_ip_covered": false,
  "your_ip_source": null
}
```
`your_ip_covered` says whether the caller's own current address is exempt (and `your_ip_source` why). It is informational only.

#### PUT /api/admin/never-ban
Replace the admin list: `{"entries": ["203.0.113.0/24", "198.51.100.7"]}`. A bare address becomes /32 or /128; duplicates are collapsed. Entries must be strict CIDR (no host bits set), at most 100. Refused with `400`: `0.0.0.0/0`, `::/0`, an IPv4 prefix shorter than /8, an IPv6 prefix shorter than /16, anything overlapping the IPv4-mapped range, host bits, anything that is not an address or network, more than 100 entries, a non-list. Saving also drops scanner strikes, failed-sign-in counts and automatic (`login`, `probe`) blocks, stored or in memory, for covered addresses.

**Auth**: Superadmin. Audited as `never_ban.update` and recorded as a `never_ban_changed` security event. Both hold counts only (`added`, `removed`, `total`), never the entries: the audit log can be read by moderators, the never-ban list only by superadmins.

**Response (200)**: the same object as GET plus `"saved": true` and `"scanner_blocks_cleared": <n>`.

#### GET /api/admin/proxy-trust
The proxy-trust self-check. `suspect` is true when at least 30 of the last 100 requests were seen and more than half came from a loopback or private address that carries `CF-Connecting-IP` or `CF-Ray` while that address is not a trusted proxy (usually `TRUSTED_PROXIES` is missing `127.0.0.1,::1`). The warning is logged once per episode and logged again only after the share has fallen to a quarter or less. It only reports and never changes trust.

**Auth**: Admin

**Response (200)**:
```json
{"suspect": true, "samples": 100, "suspicious": 100, "peers": ["127.0.0.1"], "loopback_trusted": false, "message": "Most recent requests arrive from ..."}
```
`message` is `null` when `suspect` is false. The same condition logs one warning. A warning is also logged at start when the portal listens on loopback only but loopback is not trusted.

#### GET /api/admin/cf-ranges
The Cloudflare range refresh: `{"enabled": true, "source": "built-in"|"fetched", "fetched_at": "2026-11-18 03:00:00"|null, "v4": 15, "v6": 7, "last": {"ok": true, "at": "...", "message": "...", "v4": 15, "v6": 7, "added": [], "removed": [], "last_ok_at": "..."}|null, "stage_mode": false}`. A failed refresh has `"ok": false`, a `message` and the time of the last good refresh in `last_ok_at`; the list in use is then unchanged. A refresh that was discarded because of a reset has `"ok": false` and `"discarded": true` (not a failure: the admin panel shows it as discarded, not as "Last refresh failed"). A fetched list that is identical to the saved list a superadmin approved is accepted without being held as pending again, and the saved list keeps its approval. `saved_list` is true when a fetched list is saved, `saved_list_applied` when it is the one in use and `saved_list_ignored` when it is saved but the built-in list is in use (the weekly refresh was off at start, or the list failed the checks then). `fetched_in_use_until_restart` is true when the refresh was switched off while a fetched list is in use: it stays in use until the next start unless the built-in list is chosen (`POST /api/admin/cf-ranges/reset`). `saved_list_ignored_reason` says why a saved list is ignored: `refresh_off` (the refresh was off when the portal started; it stays so if the refresh is switched on later, until the next start) or `failed_checks` (the saved list failed the checks then); `null` when nothing is ignored. `pending` is `null` or a list a refresh fetched but an automatic limit refused, held for approval: `{"id": "<16 hex>", "fetched_at": "...", "reason": "6 new IPv4 ranges in one refresh; at most 5 are accepted", "v4": 21, "v6": 7, "added": ["45.0.0.0/16", ...], "removed": [], "diff_is_current": true}`. `added` and `removed` are the exact ranges against the list in use when the list was refused (`diff_is_current` is false when the list in use has changed since). The list in use stays as it is until the pending list is approved.

**Auth**: Admin

#### PUT /api/admin/cf-ranges
`{"enabled": true|false}` turns the weekly refresh on or off (setting `cf_ranges_refresh`, default on). Turning it off keeps the list now in use. Returns the same object as GET. `400` unless `enabled` is a boolean.

**Auth**: Superadmin. Audited `cf_ranges.settings`. With the refresh off, a saved fetched list is not applied at the next start (it is kept).

#### POST /api/admin/cf-ranges/reset
Use the built-in Cloudflare list: clears the saved fetched list and swaps to the built-in list at once, without a restart. Returns the same object as GET plus `"reset": true`. Without the portal running, `sudo venv/bin/python server.py cf-ranges-reset` clears the saved list (no migration; the built-in list is used from the next start).

**Auth**: Superadmin. Audited `cf_ranges.reset` and recorded as the security event `cf_ranges_reset`.
A reset that happens while a refresh is fetching wins: that refresh's result is discarded. It also clears a pending list. With the weekly refresh on, a fetched list returns at the next scheduled refresh, not at once.

#### POST /api/admin/cf-ranges/pending/approve
`{"id": "<id of the pending list>"}` applies the pending list (see `pending` above). The id must be the one the page showed (`409` when the pending list has changed since, `404` when there is none, `400` without an id). The hard rules are checked again and cannot be overridden: every line a public network of its family, no range broader than /13 IPv4 or /29 IPv6, 10 to 100 IPv4 and 5 to 100 IPv6 ranges (`400` otherwise, nothing changes). The list is applied at once and saved with an approval flag, so it is loaded at the next start by those rules only. Returns the same object as GET plus `"approved": true`.

**Auth**: Superadmin with the browser login session; an API key, a bearer token or `?token=` value (full scope or not) is refused. Audited `cf_ranges.approve` and recorded as the security event `cf_ranges_approved`; both hold counts only (`v4`, `v6`, `added`, `removed`), never the ranges.

#### POST /api/admin/cf-ranges/pending/dismiss
`{"id": "<id of the pending list>"}` drops the pending list without applying it. The same list fetched again is not held again (and writes no failure event); a different refused list is. Same errors and **Auth** as approve. Audited `cf_ranges.dismiss`, security event `cf_ranges_dismissed`, counts only. Returns the same object as GET plus `"dismissed": true`.

A refresh that fails only the limits on new ranges or on dropped built-in or current ranges is held as the pending list instead of being lost; the limits themselves are unchanged. A list that fails any other rule is refused and cannot be held. A refused list written as a failure event (`cf_ranges_refreshed`, result `failed`, with `pending: true` and `list_id`) is written once per distinct list, not on every retry.

The weekly job fetches `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6` (certificate verified, 10 s timeout, 64 KB cap, no cookies, no redirect to another host, nothing sent about the portal). It accepts a list only if every line is a network, there are at least 10 IPv4 and 5 IPv6 ranges, no range is private, loopback or reserved, no range is broader than the broadest built-in range of its family (/13 IPv4, /29 IPv6), at most 5 ranges per family are new compared with the list trusted now (the built-in list at the first refresh), and for each family the list still covers at least half of the built-in ranges and at least half of the current ones. The same checks run when the saved list is loaded at start (except the count of new ranges). It then swaps the trusted list at once (no restart), clears the trusted-peer cache and saves the list and the result in settings. It does not run in a staged instance.

---

### Webhooks (Admin)

Outgoing webhooks send an event to a URL; incoming webhooks post a message into a chat channel. Management needs an admin; owners and admins reach `/api/webhooks/{id}` (a **system** webhook is never reachable there, see below). Destinations and credentials are encrypted at rest.

Credentials: a stream key is refused with `403` on every webhook route, user and system. Creating, changing or deleting a user webhook and getting a new signing secret need a credential that carries its user's whole authority (a browser session, or a token or API key with the `*` scope); a narrowly scoped key can still list, read and view the delivery log of its own hooks. Testing a hook (`POST /api/webhooks/{id}/test`) triggers a delivery, so it needs a full-scope credential too. Acting on a hook of another user (list all, read, change) needs the administrator role and a credential with the `admin` or `*` scope; a narrowly scoped key of an administrator sees and reaches only its own hooks. System webhook routes need a superadmin and a credential with the `admin` scope.

#### POST /api/webhooks

Create a webhook (maximum 25 per user). Fields:

| Field | Type | Notes |
|---|---|---|
| `name` | string | 1-100 characters, required |
| `type` | string | `outgoing` (default) or `incoming` |
| `url` | string | outgoing: the destination, required |
| `events` | array | outgoing: `message.created`, `message.deleted`, `stream.live`, `stream.offline`, `user.joined`, `user.connected`, `user.disconnected` or `*` (a user hook can list only these; any other event is system-only) |
| `channel_id` | integer | incoming: the target channel |
| `format` | string | `generic` (default), `ntfy`, `gotify`, `discord` or `slack` |
| `format_config` | object | credentials, write-only: gotify `{"token"}` (required), ntfy `{"token"}` or `{"username","password"}`; the other formats take none |
| `include_details` | boolean | non-generic formats: add the detail fields of the event (default `false`) |
| `allow_private` | boolean | let the hook reach loopback and private (LAN) addresses (default `false`); only a superadmin using a browser login session may turn it on (a request that authenticates by API key or bearer token never can, whatever cookie it also carries), any editor may turn it off, and turning it off is never re-checked against the address |

Formats:

- `generic`: unchanged. A JSON body `{"event", "timestamp", "data"}` signed with HMAC-SHA256 in `X-Portal-Signature`. The secret is returned once, on creation.
- `ntfy`, `gotify`, `discord`, `slack`: no signature and no secret. The message carries an event title, a one-line summary and the portal name, nothing else, unless `include_details` is on: then a short allow-listed set of fields of that event is added (for alert events also the address and user agent involved; never email addresses or tokens). Message text is cut to 200 characters. Mentions (`@everyone`, `@here`, `<@id>`, `<!channel>`) are removed; Discord payloads set `allowed_mentions` to none, and markdown link and formatting syntax in Discord text is escaped so `[text](url)` shows as typed; Slack text is escaped. Redirects are not followed. These formats need an `https://` URL unless `allow_private` is on; a hook saved with a plain `http://` URL whose `allow_private` was switched off later is not delivered (the Test route reports it) until the URL is changed to `https://`. ntfy: the URL is the topic URL; the token goes in an `Authorization` header. Gotify: the URL is the server address, the message is posted to `/message` with the token in `X-Gotify-Key`. Discord and Slack: the URL is the webhook URL itself.
- A non-generic hook receives `message.created`, `user.connected` and `user.disconnected` only when it lists them by name (`*` does not include them); `user.connected` and `user.disconnected` are never sent for a member whose status preference is appear-offline. `message.created` goes only for a channel an ordinary member can read (never a private channel, never the chat of a stream that is not public; anonymous posts are shown as "Anonymous"), and `stream.live` / `stream.offline` only for public streams. The `generic` format receives full event payloads, including the text of messages in private channels: point it only at a receiver you control. Two rules hold for every format, generic included: `user.connected` and `user.disconnected` are sent to no hook for a member whose status preference is appear-offline, and for an anonymous post `message.created` carries `user_id: null` (and `message.deleted` carries `deleted_by: null` when the author deleted it), never the real account.

**The `stream.live` payload (1.16.0).** `data` carries `stream_id`, `stream_name`, `owner_username`, `streamer` (nickname, else username), `title` (the stream name), `game` (1.17.0; an empty string when the stream has none), `url` (the logged-in watch page, `<base>/watch/<id>`, no share key) and `message` (the owner's go-live message, filled in; at most 400 characters). `public_key` is no longer part of it, and no payload carries a stream key, a `pub_` key, an RTMP address or a path. The event is sent once per 10 minutes per stream. For a stream that is not public (`stream.live` and `stream.offline`) it goes only to system hooks in the generic format, never to a member's own hook and never to a non-generic hook. In the non-generic formats the streamer, title, message and watch URL appear only with `include_details` on.

The destination URL of a non-generic hook, and every credential, is never returned by any route. Responses show `url: null`, `url_set`, `url_host` (scheme and host only) and `has_format_secret`. A rename or other edit that does not send `format_config` keeps the stored credentials, as does a change of the URL path on the same scheme, host and port. A new scheme, host or port (or switching `allow_private` off in the same request as a URL change) does not keep them: the stored credentials are dropped, and for a format that needs one (gotify) the request is refused with `400` until `format_config` is sent again; a `format_config` sent with the new destination replaces the stored one as a whole (nothing is merged from the old one). This applies to user and system hooks alike. sending a new value replaces it, an empty string removes that key. Changing the `format` of a hook from `ntfy`, `gotify`, `discord` or `slack` to `generic` needs a new `url` in the same request (otherwise `400`), because the URL of a generic hook is returned. A non-generic hook has no signing secret (`has_secret` is `false`); changing it to `generic` creates one that no response shows, so read it with `regenerate-secret`, and changing a hook away from `generic` removes it.

`allow_private` hooks still cannot reach link-local addresses, cloud metadata addresses, the unspecified address and the rest of 0.0.0.0/8, or the portal's own listening ports; plain `http://` is accepted only when every resolved address is private or loopback (`http://` to a public address is refused, use `https://`); the checks run when the hook is saved and again at every connection (redirects included). Changing the URL or format of an `allow_private` hook needs the same superadmin browser session. Turning it on or off writes a `webhook_allow_private` security event and an audit entry. A hook is re-checked against the default policy only when it is created, when its URL or format changes, or when allow_private is switched on; saving it with the same URL and format (rename, disable, other events, allow_private off) is not a change of destination and is never refused for the address.

#### GET /api/webhooks, GET /api/webhooks/{id}, PUT /api/webhooks/{id}, DELETE /api/webhooks/{id}

List (admins see every user hook with `owner_username`), read, update (same fields as create) and delete. `PUT` also takes `enabled`.

The URL `token` of an incoming hook (the `{token}` in `POST /api/webhooks/incoming/{token}`, a credential: whoever holds it can post into the channel) is returned by `POST /api/webhooks` at creation, and afterwards by these read and update routes only to the hook's own owner using a full-scope credential (a browser session or an all-scope token or key). An administrator reading another user's hook, a narrowly scoped key and an admin-only scope get `has_token: true` and no `token`.

#### GET /api/webhooks/{id}/logs

Delivery records (`event`, `response_status`, `success`, `attempt`, `duration_ms`). Records of non-generic hooks hold no payload and no response body.

#### POST /api/webhooks/{id}/test

Needs a full-scope credential (a browser session or an all-scope token or key; a narrowly scoped key gets `403`), because it triggers a delivery. Sends one sample message in the hook's format (event `webhook.test`) and waits for the receiver. Answers `{"message", "format", "sent", "success", "status", "error"}`: `status` is the receiver's HTTP status code (a 429 is reported at once, without waiting). The Test button of a hook that is disabled answers 400.

#### POST /api/webhooks/{id}/regenerate-secret

New HMAC secret, shown once. Generic format only.

#### Delivery rules

Failures are retried after 10 s, 60 s and 5 minutes; 10 consecutive failures disable the hook. A `429` answer waits for `Retry-After` (seconds or an HTTP date, capped at 10 minutes, at most 3 waits in all for one delivery, retries after a failure included; the hook is checked again after each wait and nothing more is sent if it was switched off, deleted, changed or unsubscribed meanwhile) and never counts toward the 10. A delivery refused by policy before anything is sent (a non-generic hook over plain `http://` with allow_private off) sets the hook's last failure reason to a fixed text without the URL and counts toward the 10 at most once per hour. A hook is limited to 30 deliveries per minute.

#### System webhooks (Superadmin)

A system webhook has no owner and survives the deletion of the account that created it. Only the receiver classes below differ from a user hook: system-only events (`webhook.test` and the alert events below) can be delivered to system hooks only, never to a user hook, not even through `*`. Routes (superadmin, any full credential; `allow_private` still needs a browser session):

| Route | Purpose |
|---|---|
| `GET /api/admin/webhooks` | `{"webhooks", "formats", "events", "system_only_events", "alert_groups"}` |
| `POST /api/admin/webhooks` | create (same fields as above; `events` required; maximum 20) |
| `GET`, `PUT`, `DELETE /api/admin/webhooks/{id}` | read, update (also `enabled`), delete |
| `GET /api/admin/webhooks/{id}/logs` | recent deliveries: `id`, `event`, `response_status`, `success`, `attempt`, `duration_ms`, `created_at`; never payloads |
| `POST /api/admin/webhooks/{id}/test` | as the user test route |
| `POST /api/admin/webhooks/{id}/regenerate-secret` | generic format only |

The same hooks are managed in **Admin > Webhooks** (visible to superadmins only).

#### Alert events (system webhooks only)

Fifteen ops, security and moderation events, in three groups, can be delivered to system webhooks. **A hook receives an alert only when it lists the event by name**: `*` never includes one, a user hook cannot subscribe to one, and nothing is subscribed by default. Delivery is the hook's own format (generic bodies stay HMAC-signed).

| Group | Events |
|---|---|
| Security | `auth.login_failed_burst`, `2fa.disabled`, `apikey.created`, `role.changed`, `ip.blocked` |
| Operations | `update.available`, `service.health_changed`, `cert.expiring`, `cert.renewal_failed`, `gameserver.crashed`, `backup.ok`, `backup.failed`, `alerts.suppressed` |
| Moderation | `moderation.action` (timeout, mute, ban, kick), `automod.triggered` |

Generic body: `{"event", "timestamp", "data": {"title", "summary", "severity", "group"}}`, and `"details": {label: text}` inside `data` only for a hook with `include_details`. IP addresses, user agents, reasons and rule names are details only. Account names may appear in the summary of an admin or moderation event (role change, block, timeout, ban); the sign-in burst, 2FA and API key alerts name the account in the details only; a member who posts anonymously is never named (the summary says "an anonymous member" and no name or id is in the details). The other formats show the same title and summary.

Every alert has a cooldown or transition rule: `auth.login_failed_burst` fires at 5 failed sign-ins in 60 seconds per address (an IPv6 address counts as its /64) or per existing account, then rests 10 minutes per key; automatic IP blocks are reported once a minute with a count; `service.health_changed` fires on a change only (down after 3 consecutive failed health checks of an enabled service, up after 2 good ones); `cert.expiring` fires once per threshold (14, 7 and 1 days) and certificate serial; `update.available` once per version; `automod.triggered` at most once per rule and member per minute; `moderation.action` once per moderator, member and action per minute. All alerts together are capped at 30 per 10 minutes; whenever an alert is held back an `alerts.suppressed` notice is due (it counts in the window); so is an alert event dropped for a system hook that is waiting out a `429` from its receiver (reason "receiver asked to slow down") or over its per-hook rate limit, each such event counted once however many hooks drop it, so a receiver cannot swallow alerts unseen. When a hook cannot take the notice itself for the same reason, its counts are kept and the notice is sent again once the pause ends (one retry pending, at most 5 in a row, then those counts are dropped; a retry can follow sooner than the usual 10 minutes after the previous notice, and a hook that had already received the notice receives it again with the same counts). What a stranger or an ordinary member can set off has its own smaller cap in the same window, so it cannot use up the room of the others: 5 `auth.login_failed_burst` and 5 automatic-block `ip.blocked` alerts per 10 minutes, 5 in all for the moderation alerts any signed-in member can set off (`moderation.action` and `automod.triggered` share that one cap), 3 `2fa.disabled` and 2 `apikey.created` (a cap each, apart from moderation, so moderation cannot hold back an account-security alert). That leaves room for at least 9 other alerts in each window. These caps bind only alerts caused by non-staff accounts: an alert whose actor is a moderator, admin or superadmin, an alert about a staff account (a failed-sign-in burst against a staff account name, `2fa.disabled` or `apikey.created` on one) and every operations alert bypass them and are limited only by their own cooldown or transition rule and the global cap; the global cap keeps a reserve of 10 of the 30 that an alert subject to a sub-cap can never use. The one exception is the failed-sign-in burst against a staff account name, which a stranger can set off by guessing names: those may use at most 5 of the 10 reserved slots in a 10-minute window (they are held back once 25 of the 30 slots are used), so the other 5 slots stay for operations alerts and alerts caused by staff. The first `alerts.suppressed` notice is sent 30 seconds after the first alert is held back, then at most one per 10 minutes; each names every kind held back since the previous notice with its count (the commonest first; kinds that do not fit in the summary are counted as "and N more kinds") and the limit that held it back (the global limit, the reserve or a per-kind limit; per kind when mixed), then clears those counts, so a member who keeps a limit tripped cannot keep later refusals from being reported. It is never held back by a cap and goes to every system hook with any alert event subscribed (not only hooks that list `alerts.suppressed`). Wrong second-factor codes count toward `auth.login_failed_burst` like wrong passwords, and a burst held back by its cooldown or a cap is still written once to the security event log. For `moderation.action` and `automod.triggered` from a private channel, a conversation or the chat of a stream that is not public, the ntfy, Gotify, Discord and Slack formats say "in a private channel" and carry no channel or stream name, also in their details; the generic format is unchanged. A backup whose extra copy failed sends `backup.failed`, not `backup.ok`; `update.available` is marked announced only when a hook was sent it or the in-portal notice was raised. `role.changed` rests 60 seconds per account and role change: a second, different change of the same account is still sent. A cooldown that names a combination (rule and member; moderator, member and action) counts the combination as one key. A stream chat ban sends `moderation.action` over the REST route (`POST /api/streams/{id}/bans`) as well as over the websocket. `gameserver.crashed` is sent when a game server unit ends in the failed state or when systemd restarts it on its own (its restart count grew since the last 30 second check); it is not sent for a stop or restart asked for through the portal.

| Route (superadmin, any full credential) | Purpose |
|---|---|
| `GET /api/admin/alerts` | `{"groups": [{"group", "label", "events": [{"event", "title", "notify_default"}]}], "notify": {event: bool}}` |
| `PUT /api/admin/alerts/notify` | body `{"event", "enabled"}`: whether the alert also creates an in-portal notification (type `alert`) for every administrator. Default on, except `backup.ok`, `moderation.action` and `automod.triggered` |

### Audit Log (Moderator+)

View log of all moderation actions. Entries are automatically created for: message_delete, pin/unpin_message, timeout/mute/unmute/ban/unban, channel CRUD, role changes (`role_change`), user deletes (`user_delete`), automod triggers, channel member management.

#### GET /api/admin/audit-log
Query audit log with optional filters.

**Query Parameters:**
- `limit` (default 50, max 100), `offset` (default 0)
- `action` — Filter by action type
- `actor_id` — Filter by who performed the action
- `channel_id` — Filter by channel
- `since` — ISO datetime cutoff

**Response:**
```json
{
  "entries": [{
    "id": 1, "action": "message_delete", "actor_id": 10,
    "actor_username": "admin", "target_id": 5, "target_type": "message",
    "target_name": null, "details": "{}", "channel_id": 1,
    "channel_name": "general", "created_at": "2026-02-13 19:00:00"
  }],
  "total": 42
}
```

**Retention:** Configurable, default 90 days.

---

### Session Recordings (Admin)

Recorded terminal and SSH sessions (asciicast v2). Only administrators (role `admin` or `superadmin`) can use these routes, and only with a browser session or an all-scope (`*`) bearer token. A member, a moderator or the owner of the connection gets **404** for every route and every id (an existing id and a missing one answer alike); without a credential the answer is `401`; every API key, also one made with `*`, and every narrowly scoped token get `403` (no existing scope covers recordings). A file name or path is never returned. Recording is off per connection unless its config has `"recording": true`.

#### GET /api/recordings
One page, newest first. Query: `user` (name, any case, or id), `connection` (part of the connection name), `from` and `to` (`YYYY-MM-DD`, both days included), `page` (default 1), `limit` (default 25, max 100). A bad date or number is `400`. Not audited.

**Response:** `{"recordings": [{"id": 7, "user": "bob", "user_id": 3, "connection": "build box", "type": "ssh", "started_at": "2026-11-21T12:00:00Z", "ended_at": "2026-11-21T12:04:10Z", "duration": 250.0, "size": 18234, "live": false}], "total": 1, "page": 1, "limit": 25}`. A session that is still running has `live: true` and no end time.

#### GET /api/recordings/{id}/cast
The recording file (`application/x-asciicast`, `Cache-Control: no-store`). `?download=1` sends it as an attachment. The file is found through the database row only and must be a plain file inside the recordings folder (no symlink, no path in the name): a row that points anywhere else is `403`, a missing file `404`. Audited as `recording_play` or `recording_download` (administrator, recording id, owner, connection); if the entry cannot be written the request is `500` and nothing is sent.

#### DELETE /api/recordings/{id}
Removes the row and the file. `409` while the session is still running. Audited as `recording_delete` (written before anything is removed, details `outcome: "requested"`, so it records the request, not the result). If the file cannot be removed, or the row cannot be deleted afterwards, the answer is `500` and a second entry, `recording_delete_failed`, with the reason, is written; entries are never rewritten. **Response:** `{"deleted": 7, "file_removed": true}` (`false` when the row's name was not a plain file name, in which case no file was touched).

The audit actions `recording_play`, `recording_download`, `recording_delete` and `recording_delete_failed` are visible to administrators, not to moderators.

---

### Security Events (Superadmin)

A separate log of authentication and credential events, in its own table (`security_events`) because the audit log needs a signed-in actor and cannot hold a failed login for an unknown user. Rows are kept when an account is deleted. Reading and exporting need the **superadmin** role on a credential with admin scope; moderators, admins and narrower keys get `403`.

Events (category `auth`): `login_success`, `login_failed` (result `unknown_user` or `bad_password`), `2fa_required`, `2fa_passed`, `2fa_failed`, `2fa_throttled`, `backup_code_used`, `logout`, `session_revoked` (result `own`, `others` or `admin_all` for the sessions page and the admin sign-out, none for a token revoked by id), `register_failed`. Events (category `security`): `2fa_enabled`, `2fa_disabled`, `2fa_disable_failed`, `api_key_created`, `api_key_revoked`, `api_key_deleted`, `password_changed`, `password_change_failed`, `password_reset` (admin or command line), `user_created`, `user_deleted`, `role_changed`, `invite_created`, `invite_deactivated`, `ip_blocked` (an administrator, or automatic with `kind` `login` or `probe` and `expires_at`), `ip_unblocked` (admin or command line), `probe_block` (automatic), `never_ban_changed`, `login_ban_changed` (the sign-in ban settings changed), `cf_ranges_refreshed` (result `ok` or `failed`, run by the weekly job), `cf_ranges_reset` (use the built-in list), `cf_ranges_approved` and `cf_ranges_dismissed` (a pending list approved or dismissed, counts only), `cf_refresh_toggled` (the weekly refresh turned on or off, `was` and `enabled`), `security_retention_changed` (`old_days`, `new_days` of `retention_security_events_days`), `security_events_pruned` (a manual run of cleanup deleted events: `deleted`, `days`), `rate_limited`, `host_key_accepted`, `security_log_export`. Backup runs, downloads, deletes and settings changes stay in the audit log only.

**Aggregation.** Wrong passwords, bad or missing 2FA codes, failed registrations, wrong current-password attempts, probe blocks and rate-limit trips are counted per (source IP, event, result, minute) and written as one row with `count`, flushed every few seconds and at shutdown. An IPv6 source is counted as its /64 network (`ip` is then written `2001:db8:1:2::/64`; a full IPv6 address typed in the `ip` filter also matches its /64 row, and a typed /64 matches it directly). At most 300 aggregated rows are created per minute across all sources, counted over every flush; further sources in that minute are added to one shared row per event and result with `ip` `*`, no `username_tried`, `user_agent` or `details`. Such a row keeps the first `username_tried` and `user_agent` seen in that minute. All other events are written at once, at most 30 rows per minute for each account (or address, without an account) and event; the rest of that minute is counted in one aggregated row per account, which keeps the account and has `ip` `*`. These events are never held to that limit or folded into an overflow row: `role_changed`, `user_deleted`, `password_reset`, `never_ban_changed`, `login_ban_changed`, every `cf_*` event, `security_retention_changed`, `security_events_pruned`, `security_log_export`, and `ip_blocked` and `ip_unblocked` made by an administrator (they need a staff session, and their details must not be lost). A database error never stops the request that caused the event. Passwords, 2FA and backup codes, tokens, API keys and invite codes are never stored; `username_tried` is cut to 64 characters, `user_agent` to 200; control characters, zero-width characters (U+200B to U+200F, U+FEFF) and bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069) are removed.

#### GET /api/admin/security-events
**Query parameters** (all optional): `category` (`auth`, `security`; omit or `all` for every row), `event`, `ip`, `username` (exact match on `username_tried`), `user_id`, `since` / `until` (`YYYY-MM-DD`, or a date and time in UTC, with `Z` or an offset; an `until` date covers that whole day), `limit` (default 50, max 200), `offset`. Newest first. An invalid `category`, `user_id`, `since` or `until` gives `400`.

**Response:**
```json
{
  "events": [{
    "id": 12, "ts": "2026-11-18 16:59:01", "event": "login_failed", "category": "auth",
    "user_id": null, "username_tried": "(unknown account)", "ip": "203.0.113.9",
    "user_agent": "Mozilla/5.0 ...", "result": "unknown_user",
    "details": "{\"via\":\"web\"}", "count": 37, "agg_key": "203.0.113.9|login_failed|unknown_user|2026-11-18 16:59"
  }],
  "total": 1
}
```
`username_tried` holds the account that was typed when it is an existing account (failed logins and registrations; an unknown name is stored as `(unknown account)`, never as typed) or the account that acted (other events); the target of an admin action is in `details`.

#### GET /api/admin/security-events/export
Streams the filtered rows as a download. `format=csv` (default) or `format=json`, plus the filters above. At most 50,000 rows, newest first; the headers `X-Export-Rows` and `X-Export-Truncated` say what was sent and whether older rows were left out (narrow `since` / `until` to get them). JSON is `{"events": [...], "count": N, "truncated": false}`. CSV columns: `id, ts, event, category, user_id, username_tried, ip, user_agent, result, count, details`; a text cell that starts with `=`, `+`, `-`, `@`, tab or carriage return gets a leading apostrophe so a spreadsheet does not run it. Every export is recorded as one `security_log_export` event (reading the list is not).

**Retention:** `retention_security_events_days`, default 180, `0` keeps everything.

---

### Auto-Moderation (Admin)

Automated message filtering with 5 rule types and 4 action types. Rules run on new messages and on edits; a blocked message or edit is not stored and only its author is told (`error` with `error_code: "automod"`; for an edit the client also gets `edit_rejected` with the stored text). Moderators and above are still blocked but are exempt from the timeout and mute penalties.

#### GET /api/admin/automod
List all automod rules. Each rule has `not_enforced_reason`: `null` when it is enforced as written, otherwise why chat skips part of it (a stored regex pattern that no longer passes the checks below is skipped; the rule's other patterns still run). Only enabled rules are reported: a disabled rule always has `null`. The admin list shows it as "not enforced: <reason>".

#### POST /api/admin/automod
Create a new rule.

**Request:**
```json
{
  "type": "word_filter",
  "name": "Bad Words",
  "config": { "words": ["badword"], "match_mode": "contains" },
  "action": "delete",
  "action_duration": null
}
```

**Rule types:** `word_filter`, `spam_filter` (not enforced: stored, but chat does not act on it; an enabled one carries a `not_enforced_reason` in the list), `link_filter`, `caps_filter`, `mention_spam`
**Actions:** `warn`, `delete`, `timeout`, `mute`

The config is validated on create and on update (400 on failure). Regex mode (`word_filter` with `match_mode: "regex"`):
- each pattern at most 500 characters, at most 100 patterns per rule, and it must compile
- a pattern that repeats a group already containing an unbounded repeat (`(a+)+$`, `(\w+\s?)+`, `(?:a+){2,}`) is refused; this heuristic cannot catch every slow pattern (for example `a*a*a*b` or `(a|aa)+$`)
- text is truncated to 2000 characters before a regex rule sees it, so text after that is not checked by regex rules; this bounds simple patterns only
- patterns run in a separate worker process with a 0.25 s limit; a pattern that overruns it is stopped and the message (or edit) being checked is rejected for its author with error code `automod_unchecked` ("could not be checked; shorten or rephrase it"); no penalty is booked, nobody else is told, and the pattern is tried again for the next message. Each rule in `GET /api/admin/automod` carries `slow_pattern_timeouts`, the number of such overruns of its patterns in the last hour
- messages over the chat length limit (4000 characters, for new messages and edits) are rejected by chat and never reach automod
- rules saved before these limits existed are re-checked at run time; a pattern that fails is skipped and the rule is marked in `not_enforced_reason`

#### PUT /api/admin/automod/{id}
Update a rule. Fields are optional; the resulting rule (including a changed `type` with the stored config) is validated like a new one.

#### DELETE /api/admin/automod/{id}
Delete a rule.

#### GET /api/admin/automod/actions
View automod trigger log.

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
  "owner": "John",
  "group": "John"
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
| `/watch/{id}` | Stream viewer with integrated chat and a picture-in-picture button (shown only in browsers that support it). `/watch/{id}?chat=only` is the pop-out chat window: the same page without the player, served and authorised exactly like `/watch/{id}`; the stream is loaded through `GET /api/streams/{id}` and the chat joined over `/ws/chat` as on the normal page. A member's second chat socket in a room (the pop-out beside the main tab) is not announced again and does not appear twice in the users list; a leave is announced when the last socket of that member closes |
| `/live` | Public live streams (unauthenticated), with the same picture-in-picture button |
| `/about` | Feature guide (public; all features visible to everyone) |
| `/guides` | Connection setup guides for 75+ types (public) |
| `/docs` | API documentation (public; admin endpoints stripped server-side for non-admins) |
| `/api-docs` | API documentation (alias for `/docs`) |
| `/terminal/{id}` | Terminal UI (shell selector for local terminal and SSH user connections; touch key bar with Esc, Tab, sticky Ctrl and Alt, arrows, Paste and text size, shown by default on touch devices only) |
| `/vnc/{id}` | VNC viewer |
| `/spice/{id}` | SPICE viewer |
| `/proxmox/{id}` | Proxmox management |
| `/github/{id}` | GitHub browser |
| `/media/{id}` | Media player |
| `/files` | File manager (SFTP for all users) |
| `/sysmon` | System monitor (redirects to /admin#system) |

### Navigation Structure

All pages use a standardized navbar with a responsive hamburger menu on mobile:
```
Dashboard | Chat | Streams | API Docs | About | Guides | [username] | Logout
```

### Dashboard Tabs

| Tab | Visibility | Description |
|-----|------------|-------------|
| Services | Admin only | Backend services (proxy routes and managed processes) |
| My Connections | All users | Personal SSH, VNC, database connections. Includes Quick Add bar with connection presets. |
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
- Logged-out requests under `/proxy/`, `/search` and `/browser`: 30 per minute per IP (adjustable, can be turned off; see `PUT /api/admin/proxy-limit`); `429` with `Retry-After`, never applied to a valid session
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
