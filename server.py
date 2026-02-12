#!/usr/bin/env python3
"""Open Relay Portal - Secure WebSocket Authentication and Relay Server."""

# Early intercept: run setup wizard before loading dependencies.
# On a fresh clone, aiohttp/asyncssh/etc. aren't installed yet,
# so 'python server.py setup' must work without them.
import sys as _sys
if len(_sys.argv) > 1 and _sys.argv[1] == "setup":
    from setup import run_setup_wizard
    run_setup_wizard()
    _sys.exit(0)
del _sys

import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import secrets
import signal
import ssl
import sys
import uuid
import weakref
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic, time
from typing import Optional
import re

import aiohttp
import asyncssh
import psutil
from aiohttp import web, WSMsgType

from config import Config
from database import db, ROLE_HIERARCHY, get_role_level, can_manage_role, can_assign_role, get_manageable_roles
from auth import (
    AuthError,
    TokenPayload,
    authenticate_user,
    create_access_token,
    create_user,
    extract_token_from_request,
    validate_token,
    revoke_token,
    validate_invite_code,
    get_invite_code_info,
    log_invite_code_usage,
    get_daily_invite_code,
    hash_password,
    verify_password,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    generate_backup_codes,
)
from plugins import (
    load_builtin_plugins,
    initialize_plugins,
    shutdown_plugins,
    get_plugin,
    get_all_plugins,
)
from plugins.base import ServiceTarget

# Configure logging with rotation
from logger import (
    setup_logging,
    get_log_settings,
    update_log_settings,
    read_log_file,
    get_log_files,
    set_log_level,
)
from ssh_keys import (
    create_user_key,
    get_user_keys,
    get_key_by_id,
    delete_user_key,
    admin_delete_key,
    get_all_keys,
    get_authorized_keys,
)
from shodan_integration import shodan_client, init_shodan, shutdown_shodan
from traffic_metrics import traffic_metrics, start_metrics_recorder, stop_metrics_recorder
from vulnerability_scanner import vulnerability_scanner, init_scanner, shutdown_scanner
from services import (
    ServiceManager,
    init_service_manager,
    shutdown_service_manager,
    get_available_service_types,
    load_service_types,
)
import cert_manager
import system_monitor
import file_manager
import sftp_browser
setup_logging()
logger = logging.getLogger("portal")

# Rate limiting storage
rate_limits: dict[str, list[float]] = defaultdict(list)


def safe_error_message(e: Exception) -> str:
    """Return a safe error message without exposing internal details."""
    error_msg = str(e)
    # Don't expose file paths or internal details
    if '/' in error_msg or '\\' in error_msg:
        return "An internal error occurred"
    # Truncate very long messages
    if len(error_msg) > 200:
        return error_msg[:200] + "..."
    # Allow UNIQUE constraint errors to pass through (helpful for duplicate names)
    if "UNIQUE constraint" in error_msg:
        return "A record with this name or identifier already exists"
    return error_msg

# Active WebSocket connections for monitoring
active_connections: weakref.WeakSet = weakref.WeakSet()

# Track online users globally (user_id -> active connection count)
_online_users: dict[int, int] = {}

# Server start time for uptime tracking
_server_start_time: datetime = datetime.now(timezone.utc)

# Notification subscribers: user_id -> set of WebSocket connections
notification_subscribers: dict[int, set] = {}

# Active VOD recordings: stream_id -> {process, local_path, filename, user_id, stream_name, started_at}
active_recordings: dict[int, dict] = {}

# Pending disconnect grace tasks: stream_id -> asyncio.Task
# Allows cancellation if the stream reconnects during the grace period
_disconnect_grace_tasks: dict[int, "asyncio.Task"] = {}

# Active RTMP token paths: stream_id -> rtmp_token_key (MediaMTX path override)
# When a stream publishes via rtmp_ token, MediaMTX uses the token as the path
# instead of the live_ key. This mapping lets HLS/thumbnail/VOD find the right path.
_rtmp_stream_paths: dict[int, str] = {}
VOD_TEMP_DIR = "/tmp/portal_vods"

# Static files cache
STATIC_DIR = Path(__file__).parent / "static"
_static_cache: dict[str, str] = {}


def load_static_file(filename: str, use_cache: bool = False) -> str:
    """Load a static file, optionally caching it."""
    if use_cache and filename in _static_cache:
        return _static_cache[filename]

    filepath = STATIC_DIR / filename
    if filepath.exists():
        content = filepath.read_text()
        if use_cache:
            _static_cache[filename] = content
        return content
    return f"<h1>404 - {filename} not found</h1>"


def unauthorized_response(request: web.Request) -> web.Response:
    """Return appropriate unauthorized response based on client type."""
    # Check if client expects JSON (API client) vs HTML (browser)
    accept = request.headers.get("Accept", "")
    if "application/json" in accept:
        return web.json_response({"error": "Unauthorized"}, status=401)
    return web.Response(
        status=401,
        text=load_static_file("unauthorized.html"),
        content_type="text/html"
    )


def forbidden_response(request: web.Request) -> web.Response:
    """Return appropriate forbidden response based on client type."""
    accept = request.headers.get("Accept", "")
    if "application/json" in accept:
        return web.json_response({"error": "Admin access required"}, status=403)
    return web.Response(
        status=403,
        text=load_static_file("unauthorized.html"),
        content_type="text/html"
    )


def get_client_ip(request: web.Request) -> str:
    """Extract client IP from request, considering proxies."""
    # Check for Cloudflare header first
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip

    # Check X-Forwarded-For
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()

    # Fall back to direct connection
    peername = request.transport.get_extra_info("peername")
    if peername:
        return peername[0]
    return "unknown"


def get_display_name(user: dict) -> str:
    """Get display name for a user dict: nickname > username."""
    return user.get("nickname") or user.get("owner_nickname") or user.get("username") or user.get("owner_username") or "unknown"


def check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit. Returns True if allowed."""
    now = time()
    window_start = now - Config.RATE_LIMIT_WINDOW

    # Clean old entries
    rate_limits[client_ip] = [t for t in rate_limits[client_ip] if t > window_start]

    # Check limit
    if len(rate_limits[client_ip]) >= Config.RATE_LIMIT_REQUESTS:
        return False

    rate_limits[client_ip].append(now)
    return True


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context with secure settings."""
    cert_path = Config.SSL_CERT
    key_path = Config.SSL_KEY

    # Check cert files exist before attempting to load
    if not Path(cert_path).exists():
        logger.error(f"SSL certificate file not found: {cert_path}")
        logger.error("Fix with one of:")
        logger.error("  1. Run 'sudo python server.py setup' to configure TLS")
        logger.error("  2. Set SSL_CERT and SSL_KEY in .env to valid PEM file paths")
        logger.error("  3. Generate self-signed cert: python -c \"import cert_manager; cert_manager.generate_self_signed_cert('localhost', 'certs')\"")
        sys.exit(1)

    if not Path(key_path).exists():
        logger.error(f"SSL private key file not found: {key_path}")
        logger.error("Set SSL_KEY in .env to the correct private key path, or run 'sudo python server.py setup'")
        sys.exit(1)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load certificates with clear error on failure
    try:
        ssl_context.load_cert_chain(cert_path, key_path)
    except ssl.SSLError as e:
        logger.error(f"Failed to load TLS certificate: {e}")
        logger.error(f"  Certificate: {cert_path}")
        logger.error(f"  Private key: {key_path}")
        logger.error("The certificate and key may be invalid or mismatched.")
        logger.error("Run 'sudo python server.py setup' to reconfigure TLS.")
        sys.exit(1)
    except PermissionError:
        logger.error(f"Permission denied reading TLS files. Run as root or fix permissions:")
        logger.error(f"  sudo chmod 644 {cert_path}")
        logger.error(f"  sudo chmod 600 {key_path}")
        sys.exit(1)

    # Secure cipher suite
    ssl_context.set_ciphers(
        "ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )

    return ssl_context


async def authenticate_request(request: web.Request) -> Optional[TokenPayload]:
    """Authenticate a request via header, query param, session cookie, or API key."""
    # Check Authorization header for Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            return await validate_token(auth_header[7:])
        except AuthError:
            pass

    # Check for API key or Stream key authentication
    # API keys: Authorization: Api-Key portal_xxx or X-API-Key header
    # Stream keys: Authorization: Stream-Key live_xxx or X-Stream-Key header
    api_key = None
    stream_key = None

    if auth_header.startswith("Api-Key "):
        api_key = auth_header[8:].strip()
    elif auth_header.startswith("Stream-Key "):
        stream_key = auth_header[11:].strip()
    elif request.headers.get("X-API-Key"):
        api_key = request.headers.get("X-API-Key").strip()
    elif request.headers.get("X-Stream-Key"):
        stream_key = request.headers.get("X-Stream-Key").strip()

    # Stream keys and API keys are interchangeable for stream-related operations
    if api_key:
        token_payload = await authenticate_api_key(api_key)
        if token_payload:
            return token_payload

    if stream_key:
        token_payload = await authenticate_stream_key(stream_key)
        if token_payload:
            return token_payload

    # Check query parameter
    token_str = request.query.get("token")
    if token_str:
        try:
            return await validate_token(token_str)
        except AuthError:
            pass

    # Check session cookie
    session_token = request.cookies.get(Config.SESSION_COOKIE_NAME)
    if session_token:
        try:
            return await validate_token(session_token)
        except AuthError:
            pass

    return None


async def authenticate_api_key(api_key: str) -> Optional[TokenPayload]:
    """Authenticate using an API key.

    Args:
        api_key: The full API key (portal_xxx...)

    Returns:
        TokenPayload if valid, None otherwise
    """
    from auth import parse_api_key, verify_api_key

    # Parse key to get prefix
    prefix = parse_api_key(api_key)
    if not prefix:
        return None

    # Look up key by prefix
    key_record = await db.get_api_key_by_prefix(prefix)
    if not key_record:
        return None

    # Check if revoked
    if key_record.get("revoked"):
        return None

    # Check expiration
    expires_at = key_record.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_dt < datetime.now(timezone.utc):
                return None
        except ValueError:
            pass

    # Verify the key hash
    if not verify_api_key(api_key, key_record["key_hash"]):
        return None

    # Update last used timestamp
    await db.update_api_key_last_used(key_record["id"])

    # Create a TokenPayload for the API key
    scopes = key_record.get("scopes", "*").split(",")
    return TokenPayload({
        "sub": str(key_record["user_id"]),
        "scopes": scopes,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": f"apikey-{key_record['id']}"
    })


async def authenticate_stream_key(stream_key: str) -> Optional[TokenPayload]:
    """Authenticate using a stream key.

    Stream keys can be used as API keys for stream-related operations.
    This allows OBS and other tools to use the stream key for both
    publishing AND API access (e.g., checking stream status).

    Args:
        stream_key: The full stream key (live_xxx...)

    Returns:
        TokenPayload if valid, None otherwise
    """
    # Ensure proper format
    if not stream_key.startswith("live_"):
        return None

    # Look up stream by key
    stream = await db.get_stream_by_key(stream_key)
    if not stream:
        return None

    # Get the stream owner's info
    user = await db.get_user_by_id(stream["user_id"])
    if not user:
        return None

    # Create a TokenPayload with stream-related scopes
    # Stream keys grant access to stream operations only
    return TokenPayload({
        "sub": str(user["id"]),
        "scopes": ["stream", "stream:read", "stream:write"],
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": f"streamkey-{stream['id']}"
    })


# =============================================================================
# HTTP API Endpoints
# =============================================================================

async def http_health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connections": len(active_connections)
    })


async def http_favicon(request: web.Request) -> web.Response:
    """Return empty response for favicon requests to avoid 404 logs."""
    return web.Response(status=204)


async def http_authenticated_upload(request: web.Request) -> web.Response:
    """Serve uploaded files (chat images, thumbnails) only to authenticated users."""
    token = await authenticate_request(request)
    if not token:
        return web.Response(status=401, text="Unauthorized")

    rel_path = request.match_info["path"]
    # Prevent directory traversal
    if ".." in rel_path or rel_path.startswith("/"):
        return web.Response(status=400, text="Bad request")

    filepath = STATIC_DIR / "uploads" / rel_path
    if not filepath.is_file():
        return web.Response(status=404, text="Not found")

    # Determine content type
    content_type, _ = mimetypes.guess_type(str(filepath))
    if not content_type:
        content_type = "application/octet-stream"

    return web.FileResponse(filepath, headers={"Content-Type": content_type})


async def http_create_token(request: web.Request) -> web.Response:
    """Create a new access token."""
    client_ip = get_client_ip(request)

    if not check_rate_limit(client_ip):
        return web.json_response({"error": "Rate limit exceeded"}, status=429)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    username = data.get("username")
    password = data.get("password")
    scopes = data.get("scopes", ["*"])
    token_name = data.get("name")
    expires_hours = data.get("expires_hours")

    if not username or not password:
        return web.json_response(
            {"error": "username and password required"},
            status=400
        )

    # Authenticate user
    user = await authenticate_user(username, password)
    if not user:
        logger.warning(f"Failed login attempt for '{username}' from {client_ip}")
        return web.json_response({"error": "Invalid credentials"}, status=401)

    # Create token
    jwt_token, token_id = await create_access_token(
        user_id=user["id"],
        scopes=scopes,
        name=token_name,
        expires_in_hours=expires_hours
    )

    logger.info(f"Token created for user '{username}' from {client_ip}")
    await db.log_activity(user["id"], get_display_name(user), "login", "Signed in", client_ip)

    return web.json_response({
        "token": jwt_token,
        "token_id": token_id,
        "user_id": user["id"],
        "scopes": scopes
    })


async def http_revoke_token(request: web.Request) -> web.Response:
    """Revoke a token."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    token_id = data.get("token_id")
    if not token_id:
        return web.json_response({"error": "token_id required"}, status=400)

    if await revoke_token(token_id):
        logger.info(f"Token {token_id[:8]}... revoked by user {token.user_id}")
        return web.json_response({"status": "revoked"})
    else:
        return web.json_response({"error": "Token not found"}, status=404)


async def http_list_tokens(request: web.Request) -> web.Response:
    """List tokens for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    tokens = await db.get_user_tokens(token.user_id)
    return web.json_response({
        "tokens": [
            {
                "id": t["id"],
                "token_id": t["token_id"][:8] + "...",
                "name": t["name"],
                "scopes": t["scopes"],
                "revoked": bool(t["revoked"]),
                "created_at": t["created_at"],
                "last_used_at": t["last_used_at"],
                "expires_at": t["expires_at"]
            }
            for t in tokens
        ]
    })


async def http_list_services(request: web.Request) -> web.Response:
    """List available services.

    Query params:
        type: Filter by service_type ('proxy' or 'managed')
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Check for type filter
    service_type = request.query.get("type")
    if service_type and service_type in ("proxy", "managed"):
        services = await db.get_enabled_services_by_type(service_type)
    else:
        services = await db.get_all_services()

    def serialize_service(s):
        """Serialize service for API response."""
        result = {
            "id": s["id"],
            "name": s["name"],
            "path": s["path"],
            "plugin": s.get("plugin", "tcp_tunnel"),
            "host": s.get("host", ""),
            "port": s.get("port", 0),
            "required_scopes": s["required_scopes"],
            "enabled": bool(s["enabled"]),
            "service_type": s.get("service_type", "proxy"),
            "icon": s.get("icon", "server"),
        }
        # Include process management fields for managed services
        if s.get("service_type") == "managed":
            result.update({
                "display_name": s.get("display_name") or s["name"],
                "description": s.get("description", ""),
                "status": s.get("status", "stopped"),
                "pid": s.get("pid"),
                "health_status": s.get("health_status", "unknown"),
            })
        return result

    return web.json_response({
        "services": [serialize_service(s) for s in services]
    })


async def http_create_service(request: web.Request) -> web.Response:
    """Create a new service (admin only).

    Supports both proxy services (routing to external backends) and
    managed services (Portal-run processes).
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Check admin scope
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name")
    path = data.get("path")
    plugin = data.get("plugin", "tcp_tunnel")
    host = data.get("host", "localhost")
    port = data.get("port", 0)
    config = data.get("config", {})
    required_scopes = data.get("required_scopes", "*")

    # Unified services fields
    service_type = data.get("service_type", "proxy")
    display_name = data.get("display_name")
    description = data.get("description")
    binary_path = data.get("binary_path")
    working_dir = data.get("working_dir")
    ports = data.get("ports", [])
    icon = data.get("icon", "server")

    # Handle scopes as string or list
    if isinstance(required_scopes, str):
        required_scopes = [s.strip() for s in required_scopes.split(",") if s.strip()]

    if not name or not path:
        return web.json_response(
            {"error": "name and path required"},
            status=400
        )

    # Validate service_type
    if service_type not in ("proxy", "managed"):
        return web.json_response(
            {"error": "service_type must be 'proxy' or 'managed'"},
            status=400
        )

    # For managed services, use 127.0.0.1 as default host
    if service_type == "managed" and host == "localhost":
        host = "127.0.0.1"

    try:
        service_id = await db.create_service(
            name=name,
            path=path,
            plugin=plugin,
            host=host,
            port=port,
            config=config,
            required_scopes=required_scopes,
            icon=icon,
            service_type=service_type,
            display_name=display_name,
            description=description,
            binary_path=binary_path,
            working_dir=working_dir,
            ports=ports
        )
        logger.info(f"Service '{name}' ({service_type}) created by user {token.user_id}")

        response = {
            "id": service_id,
            "name": name,
            "path": path,
            "plugin": plugin,
            "host": host,
            "port": port,
            "required_scopes": required_scopes,
            "service_type": service_type,
            "icon": icon,
        }
        if service_type == "managed":
            response.update({
                "display_name": display_name or name,
                "description": description,
                "status": "stopped",
            })
        return web.json_response(response, status=201)
    except Exception as e:
        logger.warning(f"Failed to create service: {e}")
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_delete_service(request: web.Request) -> web.Response:
    """Delete a relay service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    if await db.delete_service(int(service_id)):
        logger.info(f"Service {service_id} deleted by user {token.user_id}")
        return web.json_response({"status": "deleted"})
    else:
        return web.json_response({"error": "Service not found"}, status=404)


async def http_update_service(request: web.Request) -> web.Response:
    """Update a service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)

    # Check service exists
    service = await db.get_service_by_id(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Build update fields
    updates = {}
    # Common fields
    for field in ["name", "path", "plugin", "host", "port", "icon"]:
        if field in data:
            updates[field] = data[field]
    if "enabled" in data:
        updates["enabled"] = 1 if data["enabled"] else 0
    if "required_scopes" in data:
        scopes = data["required_scopes"]
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split(",") if s.strip()]
        updates["required_scopes"] = ",".join(scopes)
    if "config" in data:
        updates["config"] = json.dumps(data["config"])

    # Managed service fields
    for field in ["display_name", "description", "binary_path", "working_dir"]:
        if field in data:
            updates[field] = data[field]
    if "ports" in data:
        updates["ports"] = json.dumps(data["ports"])

    if not updates:
        return web.json_response({"error": "No fields to update"}, status=400)

    try:
        # Use the unified update method
        await db.update_service_full(service_id, **updates)

        # Get updated service
        updated = await db.get_service_by_id(service_id)
        logger.info(f"Service {service_id} updated by user {token.user_id}: {list(updates.keys())}")

        response = {
            "id": updated["id"],
            "name": updated["name"],
            "path": updated["path"],
            "plugin": updated.get("plugin", "tcp_tunnel"),
            "host": updated.get("host", ""),
            "port": updated.get("port", 0),
            "enabled": bool(updated["enabled"]),
            "required_scopes": updated["required_scopes"],
            "service_type": updated.get("service_type", "proxy"),
            "icon": updated.get("icon", "server"),
        }
        if updated.get("service_type") == "managed":
            response.update({
                "display_name": updated.get("display_name") or updated["name"],
                "description": updated.get("description", ""),
                "status": updated.get("status", "stopped"),
            })
        return web.json_response(response)
    except Exception as e:
        logger.warning(f"Failed to update service {service_id}: {e}")
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_get_service(request: web.Request) -> web.Response:
    """Get a single service by ID."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service = await db.get_service_by_id(int(service_id))
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    # Check authorization for non-admin users
    if not token.has_scope("admin") and not token.has_scope("*"):
        if not check_service_authorization(service, token):
            return web.json_response({"error": "Access denied"}, status=403)

    response = {
        "id": service["id"],
        "name": service["name"],
        "path": service["path"],
        "plugin": service.get("plugin", "tcp_tunnel"),
        "host": service.get("host", ""),
        "port": service.get("port", 0),
        "enabled": bool(service["enabled"]),
        "required_scopes": service["required_scopes"],
        "config": service.get("config", {}),
        "service_type": service.get("service_type", "proxy"),
        "icon": service.get("icon", "server"),
    }

    # Include process management fields for managed services
    if service.get("service_type") == "managed":
        response.update({
            "display_name": service.get("display_name") or service["name"],
            "description": service.get("description", ""),
            "status": service.get("status", "stopped"),
            "pid": service.get("pid"),
            "binary_path": service.get("binary_path"),
            "working_dir": service.get("working_dir"),
            "ports": service.get("ports", []),
            "health_status": service.get("health_status", "unknown"),
            "last_health_check": service.get("last_health_check"),
            "restart_count": service.get("restart_count", 0),
            "last_started_at": service.get("last_started_at"),
            "last_stopped_at": service.get("last_stopped_at"),
            "error_message": service.get("error_message"),
        })

    return web.json_response(response)


async def http_get_service_types(request: web.Request) -> web.Response:
    """Get available managed service types."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    types = get_available_service_types()
    return web.json_response({"types": types})


async def http_start_service(request: web.Request) -> web.Response:
    """Start a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)

    # Check service exists and is managed type
    service = await db.get_service_by_id(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)
    if service.get("service_type") != "managed":
        return web.json_response({"error": "Only managed services can be started"}, status=400)

    success, error = await _service_manager.start_service(service_id)
    if success:
        logger.info(f"Service {service_id} started by user {token.user_id}")
        updated = await db.get_service_by_id(service_id)
        admin_user = await db.get_user_by_id(token.user_id)
        await db.log_activity(token.user_id, get_display_name(admin_user) if admin_user else "admin", "service_start", f"Started service '{service.get('name', service_id)}'")
        return web.json_response({
            "success": True,
            "service": {
                "id": updated["id"],
                "name": updated["name"],
                "status": updated.get("status", "stopped"),
                "pid": updated.get("pid"),
            }
        })
    else:
        return web.json_response({"error": error}, status=400)


async def http_stop_service(request: web.Request) -> web.Response:
    """Stop a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)

    # Check service exists and is managed type
    service = await db.get_service_by_id(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)
    if service.get("service_type") != "managed":
        return web.json_response({"error": "Only managed services can be stopped"}, status=400)

    success, error = await _service_manager.stop_service(service_id)
    if success:
        logger.info(f"Service {service_id} stopped by user {token.user_id}")
        updated = await db.get_service_by_id(service_id)
        admin_user = await db.get_user_by_id(token.user_id)
        await db.log_activity(token.user_id, get_display_name(admin_user) if admin_user else "admin", "service_stop", f"Stopped service '{service.get('name', service_id)}'")
        return web.json_response({
            "success": True,
            "service": {
                "id": updated["id"],
                "name": updated["name"],
                "status": updated.get("status", "stopped"),
                "pid": updated.get("pid"),
            }
        })
    else:
        return web.json_response({"error": error}, status=400)


async def http_restart_service(request: web.Request) -> web.Response:
    """Restart a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)

    # Check service exists and is managed type
    service = await db.get_service_by_id(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)
    if service.get("service_type") != "managed":
        return web.json_response({"error": "Only managed services can be restarted"}, status=400)

    success, error = await _service_manager.restart_service(service_id)
    if success:
        logger.info(f"Service {service_id} restarted by user {token.user_id}")
        updated = await db.get_service_by_id(service_id)
        return web.json_response({
            "success": True,
            "service": {
                "id": updated["id"],
                "name": updated["name"],
                "status": updated.get("status", "stopped"),
                "pid": updated.get("pid"),
            }
        })
    else:
        return web.json_response({"error": error}, status=400)


async def http_get_service_logs(request: web.Request) -> web.Response:
    """Get logs for a managed service."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)

    # Check service exists and is managed type
    service = await db.get_service_by_id(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)
    if service.get("service_type") != "managed":
        return web.json_response({"error": "Only managed services have logs"}, status=400)

    # Get query params
    try:
        limit = min(int(request.query.get("limit", 100)), 1000)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit parameter"}, status=400)
    level = request.query.get("level")

    logs = await db.get_service_logs(service_id, limit=limit, level=level)
    return web.json_response({"logs": logs})


async def http_create_user(request: web.Request) -> web.Response:
    """Create a new user (admin only, no invite code required)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    username = data.get("username")
    password = data.get("password")
    is_admin = data.get("is_admin", False)

    if not username or not password:
        return web.json_response(
            {"error": "username and password required"},
            status=400
        )

    try:
        user = await create_user(username, password, is_admin)
        logger.info(f"User '{username}' created by admin user {token.user_id}")
        return web.json_response({
            "id": user["id"],
            "username": user["username"],
            "is_admin": bool(user["is_admin"])
        }, status=201)
    except Exception as e:
        logger.warning(f"Failed to create user '{username}': {e}")
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_register(request: web.Request) -> web.Response:
    """Register a new user with invite code."""
    client_ip = get_client_ip(request)

    if not check_rate_limit(client_ip):
        return web.json_response({"error": "Rate limit exceeded"}, status=429)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    username = data.get("username")
    password = data.get("password")
    invite_code = data.get("invite_code")

    if not username or not password:
        return web.json_response(
            {"error": "username and password required"},
            status=400
        )

    if not invite_code:
        return web.json_response(
            {"error": "invite_code required"},
            status=400
        )

    # Validate invite code
    is_valid, code_id = await validate_invite_code(invite_code, db)
    if not is_valid:
        log_invite_code_usage(username, False, client_ip)
        logger.warning(f"Invalid invite code used for registration attempt: {username} from {client_ip}")
        return web.json_response(
            {"error": "Invalid or expired invite code"},
            status=403
        )

    # Check registration limit: 1 account per IP per 24 hours
    cursor = await db.conn.execute(
        """SELECT COUNT(*) FROM users
           WHERE registration_ip = ?
           AND created_at > datetime('now', '-24 hours')""",
        (client_ip,)
    )
    row = await cursor.fetchone()
    if row and row[0] > 0:
        logger.warning(f"Registration rate limit: {username} from {client_ip} (already registered in last 24h)")
        return web.json_response(
            {"error": "Registration limit reached. Only one account per IP per 24 hours."},
            status=429
        )

    try:
        user = await create_user(username, password, is_admin=False, registration_ip=client_ip)
        log_invite_code_usage(username, True, client_ip)
        logger.info(f"User '{username}' registered with invite code from {client_ip}")
        await db.log_activity(user["id"], username, "register", "Account created", client_ip)

        # Track invite code usage
        if code_id:
            await db.increment_invite_code_usage(code_id)
            await db.set_user_invite_code(user["id"], code_id)

        return web.json_response({
            "id": user["id"],
            "username": user["username"],
            "message": "Registration successful"
        }, status=201)
    except Exception as e:
        logger.warning(f"Failed to register user '{username}': {e}")
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_get_invite_code(request: web.Request) -> web.Response:
    """Get all invite codes (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # Get all codes from DB (active and inactive for history)
    codes = await db.get_invite_codes(include_inactive=True)

    # Also include legacy daily code info
    legacy_code = get_daily_invite_code()

    return web.json_response({
        "codes": codes,
        "legacy_daily_code": legacy_code
    })


async def http_create_invite_code(request: web.Request) -> web.Response:
    """Create a new invite code (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    code_type = data.get("type", "single_use")
    if code_type not in ("daily", "single_use", "timed"):
        return web.json_response({"error": "Invalid type. Must be: daily, single_use, timed"}, status=400)

    label = data.get("label", "").strip() or None

    # Generate code
    from auth import _generate_invite_code
    code = _generate_invite_code()

    expires_at = None
    max_uses = None

    if code_type == "single_use":
        max_uses = 1
        # Optional expiry in days
        duration_days = data.get("duration_days")
        if duration_days:
            try:
                days = int(duration_days)
                if days < 1 or days > 365:
                    return web.json_response({"error": "Duration must be 1-365 days"}, status=400)
                from datetime import datetime, timezone, timedelta
                expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
            except (ValueError, TypeError):
                return web.json_response({"error": "Invalid duration_days"}, status=400)

    elif code_type == "timed":
        duration_days = data.get("duration_days", 30)
        try:
            days = int(duration_days)
            if days < 1 or days > 365:
                return web.json_response({"error": "Duration must be 1-365 days"}, status=400)
            from datetime import datetime, timezone, timedelta
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid duration_days"}, status=400)
        max_uses = None  # Unlimited uses

    elif code_type == "daily":
        # Daily codes are managed by ensure_daily_invite_code
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        expires_at = f"{today}T23:59:59"
        max_uses = None

    code_id = await db.create_invite_code(code, code_type, token.user_id, label, expires_at, max_uses)

    logger.info(f"Invite code created: type={code_type} id={code_id} by user {token.user_id}")

    return web.json_response({
        "id": code_id,
        "code": code,
        "type": code_type,
        "label": label,
        "expires_at": expires_at,
        "max_uses": max_uses
    }, status=201)


async def http_deactivate_invite_code(request: web.Request) -> web.Response:
    """Deactivate an invite code (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        code_id = int(request.match_info["id"])
    except (ValueError, KeyError):
        return web.json_response({"error": "Invalid code ID"}, status=400)

    await db.deactivate_invite_code(code_id)
    logger.info(f"Invite code {code_id} deactivated by user {token.user_id}")

    return web.json_response({"status": "deactivated"})


async def http_get_invite_code_registrations(request: web.Request) -> web.Response:
    """Get users who registered with a specific invite code (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        code_id = int(request.match_info["id"])
    except (ValueError, KeyError):
        return web.json_response({"error": "Invalid code ID"}, status=400)

    users = await db.get_invite_code_registrations(code_id)
    return web.json_response({"registrations": users})


async def http_get_logs(request: web.Request) -> web.Response:
    """Get log file contents (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # Get query params
    filename = request.query.get("file", "portal.log")
    try:
        lines = int(request.query.get("lines", 200))
        offset = int(request.query.get("offset", 0))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid lines/offset parameter"}, status=400)

    lines = min(lines, 1000)  # Limit to 1000 lines

    result = read_log_file(filename, lines, offset)
    return web.json_response(result)


async def http_get_log_files(request: web.Request) -> web.Response:
    """Get list of log files (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    files = get_log_files()
    return web.json_response({"files": files})


async def http_get_log_settings(request: web.Request) -> web.Response:
    """Get log settings (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    settings = get_log_settings()
    return web.json_response(settings)


async def http_update_log_settings(request: web.Request) -> web.Response:
    """Update log settings (admin only) - persists to database."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    try:
        settings = update_log_settings(data)
        # Persist log settings to database
        await db.set_setting("log_settings", json.dumps({
            "level": settings["level"],
            "max_size_mb": settings["max_size_mb"],
            "backup_count": settings["backup_count"],
        }))
        logger.info(f"Log settings updated and persisted by user {token.user_id}: {data}")
        return web.json_response(settings)
    except ValueError as e:
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_create_ssh_key(request: web.Request) -> web.Response:
    """Generate a new SSH key pair for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    key_name = data.get("name")
    key_type = data.get("key_type", "ed25519")

    if not key_name:
        return web.json_response({"error": "Key name required"}, status=400)

    if key_type not in ["ed25519", "rsa"]:
        return web.json_response(
            {"error": "Invalid key type. Use 'ed25519' or 'rsa'"},
            status=400
        )

    try:
        key_info = await create_user_key(token.user_id, key_name, key_type)
        logger.info(f"SSH key '{key_name}' created for user {token.user_id}")
        return web.json_response(key_info, status=201)
    except ValueError as e:
        return web.json_response({"error": safe_error_message(e)}, status=400)
    except Exception as e:
        logger.error(f"Failed to create SSH key: {e}")
        return web.json_response({"error": "Failed to create SSH key"}, status=500)


async def http_list_ssh_keys(request: web.Request) -> web.Response:
    """List SSH keys for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        keys = await get_user_keys(token.user_id)
        # Remove public_key from list response for brevity
        return web.json_response({
            "keys": [
                {
                    "id": k["id"],
                    "name": k["name"],
                    "key_type": k["key_type"],
                    "fingerprint": k["fingerprint"],
                    "created_at": k["created_at"],
                    "last_used_at": k["last_used_at"]
                }
                for k in keys
            ]
        })
    except Exception as e:
        logger.error(f"Failed to list SSH keys: {e}")
        return web.json_response({"error": "Failed to list SSH keys"}, status=500)


async def http_get_ssh_key(request: web.Request) -> web.Response:
    """Get a specific SSH key (including public key)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    key_id = request.match_info.get("id")
    if not key_id or not key_id.isdigit():
        return web.json_response({"error": "Invalid key ID"}, status=400)

    key = await get_key_by_id(int(key_id))
    if not key:
        return web.json_response({"error": "Key not found"}, status=404)

    # Users can only view their own keys (unless admin)
    if key["user_id"] != token.user_id:
        if not token.has_scope("admin") and not token.has_scope("*"):
            return web.json_response({"error": "Key not found"}, status=404)

    return web.json_response({
        "id": key["id"],
        "name": key["name"],
        "key_type": key["key_type"],
        "public_key": key["public_key"],
        "fingerprint": key["fingerprint"],
        "created_at": key["created_at"],
        "last_used_at": key["last_used_at"]
    })


async def http_delete_ssh_key(request: web.Request) -> web.Response:
    """Delete an SSH key."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    key_id = request.match_info.get("id")
    if not key_id or not key_id.isdigit():
        return web.json_response({"error": "Invalid key ID"}, status=400)

    key_id = int(key_id)

    # Try to delete as user first
    if await delete_user_key(key_id, token.user_id):
        logger.info(f"SSH key {key_id} deleted by user {token.user_id}")
        return web.json_response({"status": "deleted"})

    # If not found, check if admin and try admin delete
    if token.has_scope("admin") or token.has_scope("*"):
        if await admin_delete_key(key_id):
            return web.json_response({"status": "deleted"})

    return web.json_response({"error": "Key not found"}, status=404)


async def http_get_authorized_keys(request: web.Request) -> web.Response:
    """Get authorized_keys format for a user (for SSH server integration)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # User ID can be specified by admin, otherwise use authenticated user
    user_id = request.query.get("user_id")
    if user_id:
        if not token.has_scope("admin") and not token.has_scope("*"):
            return forbidden_response(request)
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid user_id parameter"}, status=400)
    else:
        user_id = token.user_id

    try:
        authorized_keys = await get_authorized_keys(user_id)
        return web.Response(text=authorized_keys, content_type="text/plain")
    except Exception as e:
        logger.error(f"Failed to get authorized_keys: {e}")
        return web.json_response({"error": "Failed to get authorized keys"}, status=500)


async def http_admin_list_all_keys(request: web.Request) -> web.Response:
    """List all SSH keys (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        keys = await get_all_keys()
        return web.json_response({
            "keys": [
                {
                    "id": k["id"],
                    "user_id": k["user_id"],
                    "username": k["username"],
                    "name": k["name"],
                    "key_type": k["key_type"],
                    "fingerprint": k["fingerprint"],
                    "created_at": k["created_at"],
                    "last_used_at": k["last_used_at"]
                }
                for k in keys
            ]
        })
    except Exception as e:
        logger.error(f"Failed to list all SSH keys: {e}")
        return web.json_response({"error": "Failed to list SSH keys"}, status=500)


# =============================================================================
# API Key Management
# =============================================================================

from auth import generate_api_key, verify_api_key, parse_api_key


async def http_create_api_key(request: web.Request) -> web.Response:
    """Create a new API key for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name", "").strip()
    if not name:
        return web.json_response({"error": "API key name required"}, status=400)

    # Optional: scopes (comma-separated) and expiration
    scopes = data.get("scopes", "*")
    expires_days = data.get("expires_days")  # None = never expires

    expires_at = None
    if expires_days:
        try:
            expires_days = int(expires_days)
            if expires_days > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        except ValueError:
            pass

    try:
        # Generate the API key
        full_key, key_hash, key_prefix = generate_api_key()

        # Store in database
        key_id = await db.create_api_key(
            user_id=token.user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=scopes,
            expires_at=expires_at
        )

        logger.info(f"API key '{name}' created for user {token.user_id}")

        # Return the full key ONLY ONCE - it cannot be retrieved later
        return web.json_response({
            "id": key_id,
            "name": name,
            "key": full_key,  # Only shown once!
            "prefix": key_prefix,
            "scopes": scopes,
            "expires_at": expires_at,
            "warning": "Save this key now - it cannot be retrieved later!"
        }, status=201)

    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return web.json_response({"error": "API key with this name already exists"}, status=400)
        logger.error(f"Failed to create API key: {e}")
        return web.json_response({"error": "Failed to create API key"}, status=500)


async def http_list_api_keys(request: web.Request) -> web.Response:
    """List API keys for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        keys = await db.get_user_api_keys(token.user_id)
        return web.json_response({"api_keys": keys})
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        return web.json_response({"error": "Failed to list API keys"}, status=500)


async def http_revoke_api_key(request: web.Request) -> web.Response:
    """Revoke an API key (soft delete)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    key_id = request.match_info.get("id")
    if not key_id or not key_id.isdigit():
        return web.json_response({"error": "Invalid key ID"}, status=400)

    if await db.revoke_api_key(int(key_id), token.user_id):
        logger.info(f"API key {key_id} revoked by user {token.user_id}")
        return web.json_response({"status": "revoked"})
    else:
        return web.json_response({"error": "API key not found"}, status=404)


async def http_delete_api_key(request: web.Request) -> web.Response:
    """Delete an API key permanently."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    key_id = request.match_info.get("id")
    if not key_id or not key_id.isdigit():
        return web.json_response({"error": "Invalid key ID"}, status=400)

    if await db.delete_api_key(int(key_id), token.user_id):
        logger.info(f"API key {key_id} deleted by user {token.user_id}")
        return web.json_response({"status": "deleted"})
    else:
        return web.json_response({"error": "API key not found"}, status=404)


# =============================================================================
# User Connections Management
# =============================================================================

# Blocked hosts for user connections (security - no local server access)
BLOCKED_HOSTS = {'localhost', '127.0.0.1', '::1', '0.0.0.0', 'host.docker.internal', 'kubernetes.default'}


def is_blocked_host(host: str) -> bool:
    """Check if host is blocked for user connections (localhost variants)."""
    if not host:
        return False
    h = host.lower().strip()
    # Direct matches
    if h in BLOCKED_HOSTS:
        return True
    # 127.x.x.x range
    if h.startswith('127.'):
        return True
    # IPv6 localhost variants
    if h.startswith('::ffff:127.'):
        return True
    return False


# Connection types mapped to plugins with full config support
# Sensitive config fields that must never be returned in API responses
_SENSITIVE_CONFIG_FIELDS = {"password", "private_key", "private_key_path", "auth_header", "psk"}


def redact_connection_config(connection: dict) -> dict:
    """Redact sensitive fields from a connection dict for API responses.

    Replaces sensitive values with has_<field>: True flags so the frontend
    knows a credential exists without exposing the actual value.
    """
    conn = dict(connection)
    config = conn.get("config", {})
    if isinstance(config, str):
        try:
            config = json.loads(config) if config else {}
        except json.JSONDecodeError:
            config = {}

    redacted_config = {}
    for key, value in config.items():
        if key in _SENSITIVE_CONFIG_FIELDS:
            if value:
                redacted_config[f"has_{key}"] = True
        else:
            redacted_config[key] = value

    conn["config"] = redacted_config
    return conn


CONNECTION_TYPES = {
    # Remote Access
    "ssh": {"name": "SSH Terminal", "icon": "terminal", "default_port": 22, "plugin": "ssh"},
    "sftp": {"name": "SFTP File Transfer", "icon": "server", "default_port": 22, "plugin": "ssh"},
    "vnc": {"name": "VNC Desktop", "icon": "desktop", "default_port": 5900, "plugin": "vnc"},
    "rdp": {"name": "RDP Desktop", "icon": "desktop", "default_port": 3389, "plugin": "vnc"},
    "spice": {"name": "SPICE Console", "icon": "desktop", "default_port": 5930, "plugin": "spice"},

    # Media & Streaming
    "mediamtx": {"name": "MediaMTX Stream", "icon": "play", "default_port": 8554, "plugin": "mediamtx"},
    "stream": {"name": "Media Stream", "icon": "play", "default_port": None, "plugin": "mediamtx"},

    # Virtualization
    "proxmox": {"name": "Proxmox VE", "icon": "server", "default_port": 8006, "plugin": "proxmox"},

    # Development
    "github": {"name": "GitHub", "icon": "globe", "default_port": 443, "plugin": "github"},

    # Network & Tunneling
    "tcp_tunnel": {"name": "TCP Tunnel", "icon": "link", "default_port": None, "plugin": "tcp_tunnel"},
    "secure_tunnel": {"name": "Secure Tunnel", "icon": "lock", "default_port": None, "plugin": "secure_tunnel"},
    "vpn_tunnel": {"name": "VPN Bridge", "icon": "link", "default_port": None, "plugin": "vpn_tunnel"},
    "http_proxy": {"name": "HTTP Proxy", "icon": "globe", "default_port": 80, "plugin": "http_proxy"},

    # Web Services
    "http": {"name": "HTTP Service", "icon": "globe", "default_port": 80, "plugin": "http_proxy"},
    "https": {"name": "HTTPS Service", "icon": "lock", "default_port": 443, "plugin": "http_proxy"},

    # Databases (via TCP tunnel)
    "database": {"name": "Database", "icon": "database", "default_port": 3306, "plugin": "tcp_tunnel"},
    "redis": {"name": "Redis", "icon": "database", "default_port": 6379, "plugin": "tcp_tunnel"},
    "mongodb": {"name": "MongoDB", "icon": "database", "default_port": 27017, "plugin": "tcp_tunnel"},
    "elasticsearch": {"name": "Elasticsearch", "icon": "database", "default_port": 9200, "plugin": "tcp_tunnel"},

    # Web Panels (via HTTP proxy)
    "home_assistant": {"name": "Home Assistant", "icon": "home", "default_port": 8123, "plugin": "http_proxy"},
    "portainer": {"name": "Portainer", "icon": "server", "default_port": 9443, "plugin": "http_proxy"},
    "truenas": {"name": "TrueNAS", "icon": "server", "default_port": 443, "plugin": "http_proxy"},
    "pfsense": {"name": "pfSense", "icon": "lock", "default_port": 443, "plugin": "http_proxy"},

    # Dev Tools (via HTTP proxy)
    "jupyter": {"name": "Jupyter Notebook", "icon": "globe", "default_port": 8888, "plugin": "http_proxy"},
    "grafana": {"name": "Grafana", "icon": "globe", "default_port": 3000, "plugin": "http_proxy"},
    "prometheus": {"name": "Prometheus", "icon": "globe", "default_port": 9090, "plugin": "http_proxy"},
    "gitea": {"name": "Gitea", "icon": "globe", "default_port": 3000, "plugin": "http_proxy"},
    "gitlab": {"name": "GitLab", "icon": "globe", "default_port": 80, "plugin": "http_proxy"},
    "code_server": {"name": "code-server", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},

    # Media & Self-Hosted Apps (via HTTP proxy)
    "plex": {"name": "Plex", "icon": "play", "default_port": 32400, "plugin": "http_proxy"},
    "jellyfin": {"name": "Jellyfin", "icon": "play", "default_port": 8096, "plugin": "http_proxy"},
    "emby": {"name": "Emby", "icon": "play", "default_port": 8096, "plugin": "http_proxy"},
    "navidrome": {"name": "Navidrome", "icon": "play", "default_port": 4533, "plugin": "http_proxy"},
    "audiobookshelf": {"name": "Audiobookshelf", "icon": "play", "default_port": 13378, "plugin": "http_proxy"},
    "jellyseerr": {"name": "Jellyseerr", "icon": "play", "default_port": 5055, "plugin": "http_proxy"},
    "overseerr": {"name": "Overseerr", "icon": "play", "default_port": 5055, "plugin": "http_proxy"},
    "tautulli": {"name": "Tautulli", "icon": "play", "default_port": 8181, "plugin": "http_proxy"},
    "sonarr": {"name": "Sonarr", "icon": "globe", "default_port": 8989, "plugin": "http_proxy"},
    "radarr": {"name": "Radarr", "icon": "globe", "default_port": 7878, "plugin": "http_proxy"},
    "lidarr": {"name": "Lidarr", "icon": "globe", "default_port": 8686, "plugin": "http_proxy"},
    "readarr": {"name": "Readarr", "icon": "globe", "default_port": 8787, "plugin": "http_proxy"},
    "prowlarr": {"name": "Prowlarr", "icon": "globe", "default_port": 9696, "plugin": "http_proxy"},
    "bazarr": {"name": "Bazarr", "icon": "globe", "default_port": 6767, "plugin": "http_proxy"},
    "sabnzbd": {"name": "SABnzbd", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},
    "qbittorrent": {"name": "qBittorrent", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},
    "transmission": {"name": "Transmission", "icon": "globe", "default_port": 9091, "plugin": "http_proxy"},

    # Files, Photos & Docs (via HTTP proxy)
    "nextcloud": {"name": "Nextcloud", "icon": "globe", "default_port": 443, "plugin": "http_proxy"},
    "immich": {"name": "Immich", "icon": "globe", "default_port": 2283, "plugin": "http_proxy"},
    "photoprism": {"name": "PhotoPrism", "icon": "globe", "default_port": 2342, "plugin": "http_proxy"},
    "syncthing": {"name": "Syncthing", "icon": "globe", "default_port": 8384, "plugin": "http_proxy"},
    "paperless_ngx": {"name": "Paperless-ngx", "icon": "globe", "default_port": 8000, "plugin": "http_proxy"},
    "calibre_web": {"name": "Calibre-Web", "icon": "globe", "default_port": 8083, "plugin": "http_proxy"},
    "komga": {"name": "Komga", "icon": "globe", "default_port": 25600, "plugin": "http_proxy"},
    "filebrowser": {"name": "File Browser", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},

    # Security & Auth (via HTTP proxy)
    "vaultwarden": {"name": "Vaultwarden", "icon": "lock", "default_port": 80, "plugin": "http_proxy"},
    "authelia": {"name": "Authelia", "icon": "lock", "default_port": 9091, "plugin": "http_proxy"},

    # Monitoring & Networking (via HTTP proxy)
    "uptime_kuma": {"name": "Uptime Kuma", "icon": "globe", "default_port": 3001, "plugin": "http_proxy"},
    "pihole": {"name": "Pi-hole", "icon": "lock", "default_port": 80, "plugin": "http_proxy"},
    "adguard_home": {"name": "AdGuard Home", "icon": "lock", "default_port": 3000, "plugin": "http_proxy"},
    "nginx_proxy_manager": {"name": "Nginx Proxy Manager", "icon": "globe", "default_port": 81, "plugin": "http_proxy"},
    "traefik": {"name": "Traefik", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},
    "cockpit": {"name": "Cockpit", "icon": "server", "default_port": 9090, "plugin": "http_proxy"},
    "netdata": {"name": "Netdata", "icon": "globe", "default_port": 19999, "plugin": "http_proxy"},
    "dozzle": {"name": "Dozzle", "icon": "globe", "default_port": 8080, "plugin": "http_proxy"},

    # Automation & Dashboards (via HTTP proxy)
    "n8n": {"name": "n8n", "icon": "globe", "default_port": 5678, "plugin": "http_proxy"},
    "node_red": {"name": "Node-RED", "icon": "globe", "default_port": 1880, "plugin": "http_proxy"},
    "homepage": {"name": "Homepage", "icon": "globe", "default_port": 3000, "plugin": "http_proxy"},
    "homarr": {"name": "Homarr", "icon": "globe", "default_port": 7575, "plugin": "http_proxy"},
    "organizr": {"name": "Organizr", "icon": "globe", "default_port": 80, "plugin": "http_proxy"},

    # Databases (via TCP tunnel)
    "postgresql": {"name": "PostgreSQL", "icon": "database", "default_port": 5432, "plugin": "tcp_tunnel"},
    "mariadb": {"name": "MariaDB", "icon": "database", "default_port": 3306, "plugin": "tcp_tunnel"},
    "influxdb": {"name": "InfluxDB", "icon": "database", "default_port": 8086, "plugin": "tcp_tunnel"},

    # Legacy / Game Servers (via TCP tunnel)
    "telnet": {"name": "Telnet", "icon": "terminal", "default_port": 23, "plugin": "tcp_tunnel"},
    "minecraft_rcon": {"name": "Minecraft RCON", "icon": "link", "default_port": 25575, "plugin": "tcp_tunnel"},

    # Generic
    "custom": {"name": "Custom", "icon": "link", "default_port": None, "plugin": "tcp_tunnel"},
}

# Allowed shells for terminal and SSH connections
ALLOWED_SHELLS = {
    "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh",
    "/usr/bin/fish", "/usr/bin/zsh", "/bin/zsh",
}


async def http_create_user_connection(request: web.Request) -> web.Response:
    """Create a new user connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name", "").strip()
    conn_type = data.get("type", "").strip().lower()
    host = data.get("host", "").strip()
    port = data.get("port")
    config = data.get("config", {})
    ssh_key_id = data.get("ssh_key_id")
    icon = data.get("icon")
    portal_access = 1 if data.get("portal_access", 1) else 0
    api_access = 1 if data.get("api_access", 0) else 0

    # Validate required fields
    if not name:
        return web.json_response({"error": "Connection name required"}, status=400)

    if conn_type not in CONNECTION_TYPES:
        return web.json_response({
            "error": f"Invalid connection type. Use one of: {', '.join(CONNECTION_TYPES.keys())}"
        }, status=400)

    if not host:
        return web.json_response({"error": "Host required"}, status=400)

    # Block localhost for user connections (security)
    if is_blocked_host(host):
        return web.json_response({
            "error": "Local server access not allowed for user connections"
        }, status=403)

    # Get default port if not specified
    type_info = CONNECTION_TYPES[conn_type]
    if port is None:
        port = type_info["default_port"]
    elif port:
        try:
            port = int(port)
            if port < 1 or port > 65535:
                return web.json_response({"error": "Invalid port number"}, status=400)
        except ValueError:
            return web.json_response({"error": "Invalid port number"}, status=400)

    # Validate SSH key ownership if specified
    if ssh_key_id:
        from ssh_keys import get_key_by_id
        key = await get_key_by_id(int(ssh_key_id))
        if not key or key["user_id"] != token.user_id:
            return web.json_response({"error": "Invalid SSH key"}, status=400)

    # Use default icon if not specified
    if not icon:
        icon = type_info["icon"]

    try:
        conn_id = await db.create_user_connection(
            user_id=token.user_id,
            name=name,
            conn_type=conn_type,
            host=host,
            port=port,
            config=json.dumps(config) if isinstance(config, dict) else config,
            ssh_key_id=ssh_key_id,
            icon=icon,
            portal_access=portal_access,
            api_access=api_access
        )

        logger.info(f"Connection '{name}' ({conn_type}) created by user {token.user_id}")
        user = await db.get_user_by_id(token.user_id)
        await db.log_activity(token.user_id, get_display_name(user) if user else "unknown", "connection_create", f"Created {conn_type} connection '{name}'")

        return web.json_response({
            "id": conn_id,
            "name": name,
            "type": conn_type,
            "host": host,
            "port": port,
            "icon": icon,
            "portal_access": portal_access,
            "api_access": api_access
        }, status=201)

    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return web.json_response({"error": "Connection with this name already exists"}, status=400)
        logger.error(f"Failed to create connection: {e}")
        return web.json_response({"error": "Failed to create connection"}, status=500)


async def http_list_user_connections(request: web.Request) -> web.Response:
    """List all connections for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Optional filter by type
    conn_type = request.query.get("type")

    try:
        if conn_type:
            connections = await db.get_user_connections_by_type(token.user_id, conn_type)
        else:
            connections = await db.get_user_connections(token.user_id)

        return web.json_response({
            "connections": [redact_connection_config(c) for c in connections]
        })
    except Exception as e:
        logger.error(f"Failed to list connections: {e}")
        return web.json_response({"error": "Failed to list connections"}, status=500)


async def http_get_user_connection(request: web.Request) -> web.Response:
    """Get a specific user connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    conn_id = request.match_info.get("id")
    if not conn_id or not conn_id.isdigit():
        return web.json_response({"error": "Invalid connection ID"}, status=400)

    connection = await db.get_user_connection(int(conn_id), token.user_id)
    if not connection:
        return web.json_response({"error": "Connection not found"}, status=404)

    return web.json_response(redact_connection_config(connection))


async def http_update_user_connection(request: web.Request) -> web.Response:
    """Update a user connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    conn_id = request.match_info.get("id")
    if not conn_id or not conn_id.isdigit():
        return web.json_response({"error": "Invalid connection ID"}, status=400)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Validate port if being updated
    if "port" in data and data["port"]:
        try:
            port = int(data["port"])
            if port < 1 or port > 65535:
                return web.json_response({"error": "Invalid port number"}, status=400)
            data["port"] = port
        except ValueError:
            return web.json_response({"error": "Invalid port number"}, status=400)

    # Block localhost for user connections (security)
    if "host" in data and is_blocked_host(data["host"]):
        return web.json_response({
            "error": "Local server access not allowed for user connections"
        }, status=403)

    # Merge incoming config with existing config to preserve fields not in the form
    # (e.g., passwords, private keys, and other sensitive fields that are not shown during edit)
    config = data.get("config", {})
    if isinstance(config, dict):
        existing = await db.get_user_connection(int(conn_id), token.user_id)
        if existing:
            existing_config = existing.get("config", {})
            if isinstance(existing_config, str):
                existing_config = json.loads(existing_config) if existing_config else {}
            if isinstance(existing_config, dict):
                # Existing config provides defaults; incoming config overrides
                merged = {**existing_config, **config}
                data["config"] = merged

    try:
        if await db.update_user_connection(int(conn_id), token.user_id, **data):
            logger.info(f"Connection {conn_id} updated by user {token.user_id}")
            return web.json_response({"status": "updated"})
        else:
            return web.json_response({"error": "Connection not found or no changes"}, status=404)
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return web.json_response({"error": "Connection with this name already exists"}, status=400)
        logger.error(f"Failed to update connection: {e}")
        return web.json_response({"error": "Failed to update connection"}, status=500)


async def http_delete_user_connection(request: web.Request) -> web.Response:
    """Delete a user connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    conn_id = request.match_info.get("id")
    if not conn_id or not conn_id.isdigit():
        return web.json_response({"error": "Invalid connection ID"}, status=400)

    if await db.delete_user_connection(int(conn_id), token.user_id):
        logger.info(f"Connection {conn_id} deleted by user {token.user_id}")
        return web.json_response({"status": "deleted"})
    else:
        return web.json_response({"error": "Connection not found"}, status=404)


async def http_toggle_connection_pin(request: web.Request) -> web.Response:
    """Toggle pin status for a connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    conn_id = request.match_info.get("id")
    if not conn_id or not conn_id.isdigit():
        return web.json_response({"error": "Invalid connection ID"}, status=400)

    result = await db.toggle_connection_pin(int(conn_id), token.user_id)
    if result is None:
        return web.json_response({"error": "Connection not found"}, status=404)
    return web.json_response({"is_pinned": result})


async def http_get_connection_types(request: web.Request) -> web.Response:
    """Get available connection types with plugin config schemas."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Include plugin schemas for dynamic form generation
    types_with_schemas = {}
    for type_name, type_info in CONNECTION_TYPES.items():
        plugin_name = type_info.get("plugin")
        plugin = get_plugin(plugin_name) if plugin_name else None

        types_with_schemas[type_name] = {
            **type_info,
            "config_schema": plugin.info.config_schema if plugin and hasattr(plugin, 'info') else {}
        }

    return web.json_response({"types": types_with_schemas})


async def http_connect_user_connection(request: web.Request) -> web.Response:
    """Get connection details for launching a user connection."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    conn_id = request.match_info.get("id")
    if not conn_id or not conn_id.isdigit():
        return web.json_response({"error": "Invalid connection ID"}, status=400)

    connection = await db.get_user_connection(int(conn_id), token.user_id)
    if not connection:
        return web.json_response({"error": "Connection not found"}, status=404)

    # Get SSH key public key if associated
    ssh_public_key = None
    if connection.get("ssh_key_id"):
        from ssh_keys import get_key_by_id
        key = await get_key_by_id(connection["ssh_key_id"])
        if key:
            ssh_public_key = key["public_key"]

    return web.json_response({
        "connection": connection,
        "ssh_public_key": ssh_public_key,
        "websocket_url": f"/ws/user-connection/{conn_id}"
    })


# =============================================================================
# User Streams API (OBS/RTMP streaming)
# =============================================================================


def generate_stream_key() -> str:
    """Generate a unique private stream key for OBS/RTMP publishing."""
    import secrets
    return f"live_{secrets.token_urlsafe(24)}"


def generate_public_key() -> str:
    """Generate a unique public key for read-only stream access (viewing)."""
    import secrets
    return f"pub_{secrets.token_urlsafe(16)}"


async def http_list_user_streams(request: web.Request) -> web.Response:
    """List all streams for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    streams = await db.get_user_streams(token.user_id)
    return web.json_response({"streams": streams})


async def http_create_user_stream(request: web.Request) -> web.Response:
    """Create a new stream for the authenticated user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name", "").strip()
    if not name:
        return web.json_response({"error": "Stream name is required"}, status=400)

    description = data.get("description", "").strip()
    is_public = bool(data.get("is_public", False))

    # Generate unique keys
    stream_key = generate_stream_key()  # Private key for publishing
    public_key = generate_public_key()  # Public key for viewing

    try:
        stream_id = await db.create_user_stream(
            user_id=token.user_id,
            name=name,
            stream_key=stream_key,
            public_key=public_key,
            description=description,
            is_public=is_public
        )

        # Create a chat channel for every stream
        user = await db.get_user_by_id(token.user_id)
        channel_name = f"stream-{user['username']}-{stream_id}"
        chat_channel_id = await db.create_chat_channel(
            name=channel_name,
            description=f"Chat for {name} by {user['username']}",
            created_by=token.user_id
        )
        await db.update_user_stream(stream_id, chat_channel_id=chat_channel_id)

        stream = await db.get_user_stream(stream_id)
        return web.json_response({"stream": stream}, status=201)

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return web.json_response({"error": "Stream name already exists"}, status=409)
        logger.error(f"Failed to create stream: {e}")
        return web.json_response({"error": "Failed to create stream"}, status=500)


async def http_get_user_stream(request: web.Request) -> web.Response:
    """Get a specific stream by numeric ID or public key (pub_xxx).

    Key visibility rules:
    - Owner: sees both stream_key (for OBS) and public_key (for sharing)
    - Non-owner viewing public stream: sees public_key only (for playback)
    - Non-owner viewing private stream: no keys visible
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")

    # Accept either numeric ID or public key (pub_xxx)
    stream = None
    if stream_id and stream_id.startswith("pub_"):
        stream = await db.get_stream_by_public_key(stream_id)
    else:
        try:
            stream = await db.get_user_stream(int(stream_id))
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid stream ID"}, status=400)

    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    is_owner = stream["user_id"] == token.user_id
    is_public = stream.get("is_public", False)

    if not is_owner:
        # Always hide the private stream_key from non-owners
        stream.pop("stream_key", None)
        stream.pop("stream_key_hash", None)
        stream.pop("public_key_hash", None)
        # Also hide public_key for private streams
        if not is_public:
            stream.pop("public_key", None)

    return web.json_response({"stream": stream})


async def http_update_user_stream(request: web.Request) -> web.Response:
    """Update a stream (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Get existing stream to check ownership
    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    if stream["user_id"] != token.user_id:
        return web.json_response({"error": "Not authorized"}, status=403)

    # Create chat channel if one doesn't exist (for legacy streams)
    if not stream.get("chat_channel_id"):
        user = await db.get_user_by_id(token.user_id)
        channel_name = f"stream-{user['username']}-{stream_id}"
        chat_channel_id = await db.create_chat_channel(
            name=channel_name,
            description=f"Chat for {stream['name']} by {user['username']}",
            created_by=token.user_id
        )
        data["chat_channel_id"] = chat_channel_id

    success = await db.update_user_stream(stream_id, user_id=token.user_id, **data)
    if success:
        # Revoke all RTMP tokens if rtmp_enabled was toggled off
        if data.get("rtmp_enabled") is False or data.get("rtmp_enabled") == 0:
            revoked = await db.revoke_rtmp_tokens_for_stream(stream_id)
            if revoked:
                logger.info(f"Revoked {revoked} RTMP token(s) for stream {stream_id}")
        updated_stream = await db.get_user_stream(stream_id)
        return web.json_response({"stream": updated_stream})
    return web.json_response({"error": "Failed to update stream"}, status=500)


async def http_delete_user_stream(request: web.Request) -> web.Response:
    """Delete a stream (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    # Delete associated chat channel if exists
    if stream.get("chat_channel_id"):
        await db.delete_chat_channel(stream["chat_channel_id"])

    success = await db.delete_user_stream(stream_id, user_id=token.user_id)
    if success:
        return web.json_response({"success": True})
    return web.json_response({"error": "Not authorized or stream not found"}, status=403)


async def http_regenerate_stream_key(request: web.Request) -> web.Response:
    """Regenerate stream key (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    new_key = generate_stream_key()

    success = await db.regenerate_stream_key(stream_id, new_key, user_id=token.user_id)
    if success:
        return web.json_response({"stream_key": new_key})
    return web.json_response({"error": "Not authorized or stream not found"}, status=403)


async def http_create_rtmp_token(request: web.Request) -> web.Response:
    """Generate a temporary RTMP publish token (owner only).

    Returns a single-use token for plain RTMP (non-TLS) publishing.
    Token expires after RTMP_TOKEN_EXPIRY_MINUTES (default 15 min).
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Global kill switch
    if not Config.RTMP_PLAIN_ENABLED:
        return web.json_response({"error": "Plain RTMP is not enabled on this server"}, status=403)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    # Verify ownership and rtmp_enabled
    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)
    if stream["user_id"] != token.user_id:
        return web.json_response({"error": "Not authorized"}, status=403)
    if not stream.get("rtmp_enabled"):
        return web.json_response({"error": "RTMP is not enabled for this stream"}, status=400)

    # Generate token: rtmp_ prefix + 32 random URL-safe chars
    rtmp_token = f"rtmp_{secrets.token_urlsafe(24)}"
    token_hash = hashlib.sha256(rtmp_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=Config.RTMP_TOKEN_EXPIRY_MINUTES)).isoformat()

    await db.create_rtmp_token(stream_id, token.user_id, token_hash, expires_at)

    # RTMP URL uses the streaming hostname (direct, bypasses Cloudflare)
    rtmp_url = f"rtmp://{Config.STREAM_HOSTNAME}:{Config.RTMP_PLAIN_PORT}/live"

    return web.json_response({
        "token": rtmp_token,
        "expires_in": Config.RTMP_TOKEN_EXPIRY_MINUTES * 60,
        "rtmp_url": rtmp_url,
    })


async def http_upload_stream_thumbnail(request: web.Request) -> web.Response:
    """Upload a thumbnail for a stream (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    # Get existing stream to check ownership
    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    if stream["user_id"] != token.user_id:
        return web.json_response({"error": "Not authorized"}, status=403)

    # Parse multipart data
    try:
        reader = await request.multipart()
        field = await reader.next()

        if field is None or field.name != "thumbnail":
            return web.json_response({"error": "No thumbnail file provided"}, status=400)

        # Validate content type
        content_type = field.headers.get(aiohttp.hdrs.CONTENT_TYPE, "")
        if not content_type.startswith("image/"):
            return web.json_response({"error": "File must be an image"}, status=400)

        # Determine file extension
        ext_map = {
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        ext = ext_map.get(content_type, ".jpg")

        # Generate unique filename
        filename = f"{uuid.uuid4().hex}{ext}"
        upload_dir = Path(__file__).parent / "static" / "uploads" / "thumbnails"
        upload_dir.mkdir(parents=True, exist_ok=True)
        filepath = upload_dir / filename

        # Read and save file (limit to 5MB)
        size = 0
        max_size = 5 * 1024 * 1024  # 5MB

        with open(filepath, "wb") as f:
            while True:
                chunk = await field.read_chunk()
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    f.close()
                    filepath.unlink()
                    return web.json_response({"error": "File too large (max 5MB)"}, status=400)
                f.write(chunk)

        # Delete old thumbnail if exists
        if stream.get("thumbnail_url"):
            old_path = Path(__file__).parent / stream["thumbnail_url"].lstrip("/")
            if old_path.exists() and "uploads/thumbnails" in str(old_path):
                try:
                    old_path.unlink()
                except Exception:
                    pass

        # Update database with new thumbnail URL
        thumbnail_url = f"/static/uploads/thumbnails/{filename}"
        await db.update_user_stream(stream_id, user_id=token.user_id, thumbnail_url=thumbnail_url)

        return web.json_response({
            "success": True,
            "thumbnail_url": thumbnail_url
        })

    except Exception as e:
        logger.error(f"Thumbnail upload error: {e}")
        return web.json_response({"error": "Upload failed"}, status=500)


async def http_delete_stream_thumbnail(request: web.Request) -> web.Response:
    """Delete a stream's thumbnail (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    try:
        stream_id = int(stream_id)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    if stream["user_id"] != token.user_id:
        return web.json_response({"error": "Not authorized"}, status=403)

    # Delete file if exists
    if stream.get("thumbnail_url"):
        old_path = Path(__file__).parent / stream["thumbnail_url"].lstrip("/")
        if old_path.exists() and "uploads/thumbnails" in str(old_path):
            try:
                old_path.unlink()
            except Exception:
                pass

    # Clear thumbnail URL in database
    await db.update_user_stream(stream_id, user_id=token.user_id, thumbnail_url=None)

    return web.json_response({"success": True})


async def http_get_stream_bans(request: web.Request) -> web.Response:
    """Get all bans for a stream (stream owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        stream_id = int(request.match_info.get("id"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    # Verify ownership
    stream = await db.get_user_stream(stream_id)
    if not stream or stream["user_id"] != token.user_id:
        # Allow admins to view bans
        if not token.has_scope("admin") and not token.has_scope("*"):
            return web.json_response({"error": "Not authorized"}, status=403)

    bans = await db.get_stream_bans(stream_id)
    return web.json_response({"bans": bans})


async def http_create_stream_ban(request: web.Request) -> web.Response:
    """Ban a user from stream chat (stream owner only).

    Request body:
    - user_id: int - User ID to ban
    - reason: str (optional) - Reason for ban
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        stream_id = int(request.match_info.get("id"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid stream ID"}, status=400)

    # Verify ownership
    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    # Only owner or admin can ban
    if stream["user_id"] != token.user_id:
        if not token.has_scope("admin") and not token.has_scope("*"):
            return web.json_response({"error": "Not authorized"}, status=403)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    user_id = data.get("user_id")
    if not user_id:
        return web.json_response({"error": "user_id required"}, status=400)

    # Can't ban yourself
    if user_id == token.user_id:
        return web.json_response({"error": "Cannot ban yourself"}, status=400)

    # Can't ban the stream owner
    if user_id == stream["user_id"]:
        return web.json_response({"error": "Cannot ban the stream owner"}, status=400)

    reason = data.get("reason", "")

    ban_id = await db.create_stream_ban(
        stream_id=stream_id,
        user_id=user_id,
        banned_by=token.user_id,
        reason=reason
    )

    if ban_id:
        # Get banned user's username for the response
        banned_user = await db.get_user_by_id(user_id)
        logger.info(f"User {banned_user['username'] if banned_user else user_id} banned from stream {stream['name']} by user {token.user_id}")
        return web.json_response({
            "success": True,
            "ban_id": ban_id,
            "message": f"User banned from stream chat"
        }, status=201)

    return web.json_response({"error": "User may already be banned"}, status=400)


async def http_remove_stream_ban(request: web.Request) -> web.Response:
    """Remove a ban from stream chat (stream owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        stream_id = int(request.match_info.get("id"))
        user_id = int(request.match_info.get("user_id"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid ID"}, status=400)

    # Verify ownership
    stream = await db.get_user_stream(stream_id)
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    # Only owner or admin can unban
    if stream["user_id"] != token.user_id:
        if not token.has_scope("admin") and not token.has_scope("*"):
            return web.json_response({"error": "Not authorized"}, status=403)

    success = await db.remove_stream_ban(stream_id, user_id)
    if success:
        logger.info(f"User {user_id} unbanned from stream {stream['name']} by user {token.user_id}")
        return web.json_response({"success": True, "message": "User unbanned"})

    return web.json_response({"error": "Ban not found"}, status=404)


async def http_get_public_streams(request: web.Request) -> web.Response:
    """Get all public streams (community streams).

    This endpoint is accessible to all authenticated users.
    - Private stream_key is never included (security)
    - Public key (pub_xxx) is included for playback URLs
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    live_only = request.query.get("live", "false").lower() == "true"
    streams = await db.get_public_streams(live_only=live_only)

    # Remove private stream keys and internal hashes from public listing (security)
    # Keep public_key for playback URLs
    for stream in streams:
        stream.pop("stream_key", None)
        stream.pop("stream_key_hash", None)
        stream.pop("public_key_hash", None)

    return web.json_response({"streams": streams})


async def http_get_open_streams(request: web.Request) -> web.Response:
    """Get streams that allow unauthenticated public access.

    No authentication required. Returns streams where
    is_public=1 AND allow_unauthenticated=1.
    Private stream_key is never included.
    """
    streams = await db.get_open_streams()
    return web.json_response({"streams": streams})


async def http_live_page(request: web.Request) -> web.Response:
    """Serve the public live streams page (no auth required)."""
    html = load_static_file("live.html")
    return web.Response(text=html, content_type="text/html")


# =============================================================================
# VOD Recording Pipeline — Chunked recording with live SFTP offload
#
# Architecture:
#   1. On stream publish, ffmpeg segments the HLS input into 5-minute MKV
#      chunks in a local staging directory.
#   2. A background uploader task polls for completed chunks and uploads
#      each to the user's remote SFTP storage, deleting the local copy
#      once confirmed.
#   3. On stream disconnect, ffmpeg is stopped, the final chunk is
#      uploaded, and the local staging directory is cleaned up.
#
# Remote folder structure:
#   {remote_path}/{StreamName}/{YYYY-MM-DD_HH-MM-SS}/
#     chunk_000.mkv
#     chunk_001.mkv
#     ...
# =============================================================================

VOD_SEGMENT_DURATION = 300  # seconds per chunk (5 minutes)


async def start_vod_recording(stream: dict, stream_key: str) -> None:
    """Start chunked VOD recording with live SFTP offload."""
    stream_id = stream["id"]
    user_id = stream["user_id"]

    if stream_id in active_recordings:
        return

    # Only record if user has VOD storage configured
    storage = await db.get_vod_storage(user_id)
    if not storage:
        logger.debug(f"No VOD storage for user {user_id}, skipping recording")
        return

    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        logger.warning("MediaMTX not configured, cannot start VOD recording")
        return

    # Use RTSPS for reliable recording (HLS LL-HLS segments expire too fast for ffmpeg)
    rtsps_port = 8322  # MediaMTX default RTSPS port (strict TLS)
    source_url = f"rtsps://127.0.0.1:{rtsps_port}/live/{stream_key}"

    # Build paths — date-only remote dir so chunks accumulate across restarts
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_name = re.sub(r'[^\w\s-]', '', stream.get("name", "stream")).strip().replace(' ', '_')[:50] or "stream"
    session_dir = os.path.join(VOD_TEMP_DIR, f"{stream_id}_{date_str}_{int(time())}")
    os.makedirs(session_dir, exist_ok=True)

    remote_base = storage["remote_path"].rstrip("/")
    remote_session_dir = f"{remote_base}/{safe_name}/{date_str}"

    # Check remote SFTP for existing chunks to continue numbering
    start_number = 0
    conn, sftp, error = await _connect_vod_sftp(user_id)
    if not error:
        try:
            await _sftp_makedirs(sftp, remote_session_dir)
            existing = await sftp.listdir(remote_session_dir)
            for fname in existing:
                m = re.match(r'chunk_(\d+)\.mkv$', fname)
                if m:
                    n = int(m.group(1)) + 1
                    if n > start_number:
                        start_number = n
            if start_number > 0:
                logger.info(f"VOD resuming at chunk_{start_number:03d} in {safe_name}/{date_str}")
        except Exception as e:
            logger.debug(f"Could not check remote chunks: {e}")
        finally:
            conn.close()

    # Wait for MediaMTX stream to be ready
    await asyncio.sleep(2)

    # ffmpeg segment muxer: lossless remux into 5-minute MKV chunks via RTSPS
    cmd = [
        "ffmpeg", "-y",
        "-rtsp_transport", "tcp",
        "-i", source_url,
        "-c", "copy",
        "-f", "segment",
        "-segment_time", str(VOD_SEGMENT_DURATION),
        "-segment_format", "matroska",
        "-segment_start_number", str(start_number),
        "-reset_timestamps", "1",
        os.path.join(session_dir, "chunk_%03d.mkv"),
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.error("ffmpeg not found, cannot start VOD recording")
        os.rmdir(session_dir)
        return
    except Exception as e:
        logger.error(f"Failed to start VOD recording: {e}")
        os.rmdir(session_dir)
        return

    stop_event = asyncio.Event()
    recording = {
        "process": process,
        "session_dir": session_dir,
        "remote_session_dir": remote_session_dir,
        "user_id": user_id,
        "stream_name": stream.get("name", ""),
        "started_at": datetime.now(timezone.utc),
        "stop_event": stop_event,
        "upload_task": None,
        "uploaded": set(),  # local paths already uploaded
    }

    # Start background chunk uploader
    recording["upload_task"] = asyncio.create_task(
        _vod_chunk_uploader(recording)
    )

    active_recordings[stream_id] = recording
    logger.info(f"VOD recording started: {safe_name}/{date_str}/ from chunk_{start_number:03d} (every {VOD_SEGMENT_DURATION}s)")


async def _vod_chunk_uploader(recording: dict) -> None:
    """Background loop that uploads completed chunks to SFTP during broadcast."""
    stop_event: asyncio.Event = recording["stop_event"]
    session_dir = recording["session_dir"]
    uploaded: set = recording["uploaded"]
    process = recording["process"]

    while not stop_event.is_set():
        # Detect if ffmpeg exited on its own (e.g. HLS source 404)
        if process.returncode is not None:
            logger.info(f"VOD ffmpeg exited (code {process.returncode}), finalizing upload")
            break
        await _do_vod_chunk_upload(recording, final=False)
        # Wait up to 30 seconds or until stop signal
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass

    # Final pass — ffmpeg has exited, all chunks are complete
    await _do_vod_chunk_upload(recording, final=True)

    # If ffmpeg exited on its own (not via stop_vod_recording), clean up
    if not stop_event.is_set():
        stop_event.set()
        # Remove from active_recordings
        for sid, rec in list(active_recordings.items()):
            if rec is recording:
                active_recordings.pop(sid, None)
                break
        # Clean up local staging directory
        try:
            remaining = list(Path(session_dir).iterdir())
            if remaining:
                logger.warning(f"VOD staging dir has {len(remaining)} leftover file(s): {session_dir}")
            else:
                Path(session_dir).rmdir()
        except OSError:
            pass
        logger.info(f"VOD recording auto-stopped for '{recording['stream_name']}' (ffmpeg exited)")


async def _do_vod_chunk_upload(recording: dict, final: bool = False) -> None:
    """Upload pending completed chunks to SFTP."""
    session_dir = recording["session_dir"]
    remote_dir = recording["remote_session_dir"]
    user_id = recording["user_id"]
    uploaded: set = recording["uploaded"]

    # Discover chunk files
    try:
        chunk_files = sorted(
            p for p in Path(session_dir).glob("chunk_*.mkv")
        )
    except OSError:
        return

    if not chunk_files:
        return

    # While recording, the last file is still being written by ffmpeg
    pending = chunk_files if final else chunk_files[:-1]
    pending = [p for p in pending if str(p) not in uploaded and p.stat().st_size > 0]

    if not pending:
        return

    conn, sftp, error = await _connect_vod_sftp(user_id)
    if error:
        logger.error(f"VOD chunk upload SFTP connect failed: {error}")
        return

    try:
        # Ensure remote directory tree exists
        await _sftp_makedirs(sftp, remote_dir)

        for local_path in pending:
            remote_path = f"{remote_dir}/{local_path.name}"
            try:
                await sftp.put(str(local_path), remote_path)
                uploaded.add(str(local_path))
                local_path.unlink()
                logger.info(f"VOD chunk uploaded: {remote_path}")
            except Exception as e:
                logger.error(f"VOD chunk upload failed ({local_path.name}): {e}")
    finally:
        conn.close()


async def _sftp_makedirs(sftp, path: str) -> None:
    """Recursively create remote directories (like os.makedirs)."""
    parts = path.strip("/").split("/")
    current = ""
    for part in parts:
        current += f"/{part}"
        try:
            await sftp.stat(current)
        except asyncssh.SFTPNoSuchFile:
            try:
                await sftp.mkdir(current)
            except asyncssh.SFTPError:
                pass  # May already exist from race condition


async def stop_vod_recording(stream_id: int, force: bool = False) -> None:
    """Stop recording, finalize last chunk, upload remaining, clean up.

    When force=False (stream disconnect), wait for ffmpeg to exit naturally
    as the RTSPS source disappearing causes ffmpeg to finish the current
    chunk and exit cleanly. Only use force=True on server shutdown.
    """
    recording = active_recordings.pop(stream_id, None)
    if not recording:
        return

    process = recording["process"]

    if force:
        # Server shutdown — SIGINT immediately to finalize MKV headers
        try:
            process.send_signal(signal.SIGINT)
            await asyncio.wait_for(process.wait(), timeout=15)
        except asyncio.TimeoutError:
            logger.warning("ffmpeg did not exit cleanly, terminating")
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        except ProcessLookupError:
            pass
    else:
        # Normal disconnect — let ffmpeg finish the current chunk naturally.
        # When the RTSPS source ends, ffmpeg finalizes the segment and exits.
        try:
            await asyncio.wait_for(process.wait(), timeout=300)
            logger.info(f"VOD ffmpeg exited naturally (code {process.returncode})")
        except asyncio.TimeoutError:
            logger.warning("ffmpeg did not exit after source ended, sending SIGINT")
            try:
                process.send_signal(signal.SIGINT)
                await asyncio.wait_for(process.wait(), timeout=15)
            except asyncio.TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            except ProcessLookupError:
                pass

    # Signal uploader to do final pass then exit
    recording["stop_event"].set()

    # Wait for uploader to finish final upload
    upload_task = recording.get("upload_task")
    if upload_task:
        try:
            await asyncio.wait_for(upload_task, timeout=120)
        except asyncio.TimeoutError:
            logger.warning("VOD final upload timed out")
            upload_task.cancel()
        except asyncio.CancelledError:
            pass

    # Clean up local staging directory
    session_dir = recording["session_dir"]
    try:
        remaining = list(Path(session_dir).iterdir())
        if remaining:
            logger.warning(f"VOD staging dir has {len(remaining)} leftover file(s): {session_dir}")
        else:
            Path(session_dir).rmdir()
    except OSError:
        pass

    logger.info(f"VOD recording stopped for '{recording['stream_name']}'")


async def stop_all_recordings() -> None:
    """Stop all active VOD recordings (called on server shutdown)."""
    # Cancel any pending disconnect grace tasks
    for stream_id, task in list(_disconnect_grace_tasks.items()):
        if not task.done():
            task.cancel()
    _disconnect_grace_tasks.clear()

    if not active_recordings:
        return
    logger.info(f"Stopping {len(active_recordings)} active VOD recording(s)...")
    stream_ids = list(active_recordings.keys())
    for stream_id in stream_ids:
        await stop_vod_recording(stream_id, force=True)


async def _handle_disconnect_grace(stream: dict) -> None:
    """Grace period before triggering encoding/offline on stream disconnect.

    Waits 7 seconds, then re-checks if the stream reconnected. If still disconnected,
    proceeds with encoding (if VOD active) or offline transition. This prevents
    accidental brief disconnects from triggering the full finalization flow.
    """
    stream_id = stream["id"]
    stream_name = stream.get("name", "?")
    try:
        await asyncio.sleep(7)

        # Re-check stream state — did it reconnect during grace period?
        current = await db.get_user_stream(stream_id)
        if current and current.get("is_live") == 1:
            logger.info(f"Stream {stream_name} reconnected during grace period, aborting disconnect")
            return

        # Still disconnected — proceed with encoding/offline transition
        has_vod = stream_id in active_recordings

        if has_vod:
            # Transition to encoding state — VOD chunks still being finalized
            await db.set_stream_encoding(stream_id)
            logger.info(f"Stream {stream_name} ended (after grace period), encoding VODs...")

            # Broadcast encoding status to chat channel
            if stream.get("chat_channel_id"):
                channel = await db.get_chat_channel(stream["chat_channel_id"])
                if channel:
                    await broadcast_to_channel(channel["name"], {
                        "type": "stream_status",
                        "stream_id": stream_id,
                        "is_live": 2  # encoding
                    })

            # Finalize VOD in background, then transition to offline
            asyncio.create_task(_finalize_stream_offline(stream))
        else:
            # No VOD recording — go straight to offline
            await db.set_stream_live(stream_id, False)
            logger.info(f"Stream {stream_name} ended (after grace period)")
            await db.log_activity(stream.get("user_id"), get_display_name(stream), "stream_offline", f"Stream '{stream_name}' went offline")

            if stream.get("chat_channel_id"):
                channel = await db.get_chat_channel(stream["chat_channel_id"])
                if channel:
                    await broadcast_to_channel(channel["name"], {
                        "type": "stream_status",
                        "stream_id": stream_id,
                        "is_live": 0
                    })

            # Clear chat history for the stream's channel
            if stream.get("chat_channel_id"):
                deleted = await db.clear_channel_messages(stream["chat_channel_id"])
                if deleted > 0:
                    logger.info(f"Cleared {deleted} chat messages for stream {stream_name}")
    except asyncio.CancelledError:
        logger.info(f"Stream {stream_name} disconnect grace period cancelled (reconnected)")
    except Exception as e:
        logger.error(f"Error in disconnect grace for stream {stream_name}: {e}")
    finally:
        _disconnect_grace_tasks.pop(stream_id, None)


async def _finalize_stream_offline(stream: dict) -> None:
    """Background task: wait for VOD finalization, then transition stream to offline."""
    stream_id = stream["id"]
    stream_name = stream.get("name", "?")
    try:
        # Wait for ffmpeg to finish the current chunk and upload all chunks
        await stop_vod_recording(stream_id)

        # Now transition to fully offline
        await db.set_stream_live(stream_id, False)
        logger.info(f"Stream {stream_name} VOD finalized, now offline")
        await db.log_activity(stream.get("user_id"), get_display_name(stream), "stream_offline", f"Stream '{stream_name}' went offline")

        # Broadcast offline status to chat channel
        if stream.get("chat_channel_id"):
            channel = await db.get_chat_channel(stream["chat_channel_id"])
            if channel:
                await broadcast_to_channel(channel["name"], {
                    "type": "stream_status",
                    "stream_id": stream_id,
                    "is_live": 0
                })

        # Clear chat history for the stream's channel
        if stream.get("chat_channel_id"):
            deleted = await db.clear_channel_messages(stream["chat_channel_id"])
            if deleted > 0:
                logger.info(f"Cleared {deleted} chat messages for stream {stream_name}")
    except Exception as e:
        logger.error(f"Error finalizing stream {stream_name} offline: {e}")
        # Ensure stream goes offline even if VOD finalization fails
        try:
            await db.set_stream_live(stream_id, False)
        except Exception:
            pass


async def http_stream_auth(request: web.Request) -> web.Response:
    """MediaMTX stream authentication hook.

    Called by MediaMTX when a client tries to publish or play a stream.
    Validates stream key for publishing, allows viewing of public streams.
    """
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    action = data.get("action", "publish")  # publish, read, playback
    path = data.get("path", "")
    query = data.get("query", "")
    user = data.get("user", "")
    password = data.get("password", "")
    ip = data.get("ip", "")

    logger.debug(f"Stream auth request: action={action}, path={path}, user={user}, ip={ip}")

    # For publishing, the stream key is passed as the password or in the path
    # OBS typically sends: rtmp://server/live/stream_key or uses username/password
    stream_key = password or path.split("/")[-1] if path else ""

    if action == "publish":
        # Resolve stream from key — supports live_ (permanent) and rtmp_ (temporary token)
        real_stream_key = None  # The live_ key for VOD recording
        stream = None

        if stream_key and stream_key.startswith("rtmp_"):
            # Validate temporary RTMP publish token
            if not Config.RTMP_PLAIN_ENABLED:
                logger.warning(f"RTMP token rejected (plain RTMP disabled globally) from {ip}")
                return web.json_response({"error": "Plain RTMP is disabled"}, status=401)

            token_hash = hashlib.sha256(stream_key.encode()).hexdigest()
            token_record = await db.get_rtmp_token(token_hash)
            if not token_record:
                logger.warning(f"Unknown RTMP token from {ip}")
                return web.json_response({"error": "Invalid token"}, status=401)
            if token_record["revoked"]:
                logger.warning(f"Revoked RTMP token from {ip}")
                return web.json_response({"error": "Token revoked"}, status=401)
            if datetime.fromisoformat(token_record["expires_at"]) < datetime.now(timezone.utc):
                logger.warning(f"Expired RTMP token from {ip}")
                return web.json_response({"error": "Token expired"}, status=401)
            # Grace period: allow re-auth within window after first use (OBS reconnect)
            if token_record["used"]:
                used_at = datetime.fromisoformat(token_record["used_at"])
                grace = timedelta(seconds=Config.RTMP_TOKEN_GRACE_SECONDS)
                if datetime.now(timezone.utc) - used_at > grace:
                    logger.warning(f"RTMP token grace period expired from {ip}")
                    return web.json_response({"error": "Token already used"}, status=401)
            else:
                await db.mark_rtmp_token_used(token_record["id"])
            # Verify stream has rtmp_enabled
            if not token_record.get("rtmp_enabled"):
                logger.warning(f"RTMP token for stream with RTMP disabled from {ip}")
                return web.json_response({"error": "RTMP disabled on this stream"}, status=401)

            # Build a stream-like dict from JOIN result for downstream compatibility
            real_stream_key = token_record.get("stream_key", "")
            stream = {
                "id": token_record["stream_id"],
                "user_id": token_record.get("stream_user_id", token_record.get("user_id")),
                "name": token_record.get("stream_name", ""),
                "is_public": token_record.get("is_public"),
                "is_live": token_record.get("is_live"),
                "chat_channel_id": token_record.get("chat_channel_id"),
                "allow_unauthenticated": token_record.get("allow_unauthenticated"),
                "viewer_count": token_record.get("viewer_count", 0),
                "started_at": token_record.get("started_at"),
                "ended_at": token_record.get("ended_at"),
                "thumbnail_url": token_record.get("thumbnail_url"),
                "owner_username": token_record.get("owner_username"),
                "owner_nickname": token_record.get("owner_nickname"),
                "public_key": token_record.get("public_key"),
            }
            logger.info(f"RTMP token auth successful for stream {stream['name']} from {ip}")
            # Store path mapping so HLS/thumbnail/VOD can find the MediaMTX path
            _rtmp_stream_paths[token_record["stream_id"]] = stream_key

        elif stream_key and stream_key.startswith("live_"):
            stream = await db.get_stream_by_key(stream_key)
            if not stream:
                logger.warning(f"Unknown stream key from {ip}")
                return web.json_response({"error": "Invalid stream key"}, status=401)
            real_stream_key = stream_key
        else:
            logger.warning(f"Invalid stream key attempt from {ip}")
            return web.json_response({"error": "Invalid stream key"}, status=401)

        # Cancel any pending disconnect grace task (stream reconnected)
        stream_id = stream["id"]
        grace_task = _disconnect_grace_tasks.pop(stream_id, None)
        if grace_task and not grace_task.done():
            grace_task.cancel()
            logger.info(f"Stream {stream['name']} reconnected, cancelled disconnect grace period")

        # Mark stream as live (only log activity on state change)
        was_live = stream.get("is_live")
        await db.set_stream_live(stream_id, True)
        if not was_live:
            logger.info(f"Stream {stream['name']} started by user {stream.get('owner_username', '?')} from {ip}")
            await db.log_activity(stream.get("user_id"), get_display_name(stream), "stream_live", f"Stream '{stream['name']}' went live", ip)
            # Notify chat channel that stream went live
            if stream.get("chat_channel_id"):
                channel = await db.get_chat_channel(stream["chat_channel_id"])
                if channel:
                    await broadcast_to_channel(channel["name"], {
                        "type": "stream_status",
                        "stream_id": stream_id,
                        "is_live": True
                    })
            # Send notification to all users
            streamer_name = stream.get("owner_nickname") or stream.get("owner_username", "Someone")
            await broadcast_notification(
                "stream_live", f"{streamer_name} is live!",
                f"{stream['name']} just went live",
                data={"stream_id": stream_id, "public_key": stream.get("public_key", "")},
                exclude_user_id=stream.get("user_id")
            )

        # Start VOD recording on every publish (guards against duplicates internally)
        # Use the actual MediaMTX path key (rtmp_ token or live_ key)
        vod_stream_key = stream_key if stream_key.startswith("rtmp_") else (real_stream_key or stream_key)
        asyncio.create_task(start_vod_recording(stream, vod_stream_key))

        return web.json_response({"allowed": True})

    elif action in ("read", "playback"):
        # For reading/playback, extract stream key from path
        if not path:
            return web.json_response({"error": "Path required"}, status=400)

        # Try to find stream by the path (which should be the stream key)
        stream_key_from_path = path.split("/")[-1] if "/" in path else path
        stream = await db.get_stream_by_key(f"live_{stream_key_from_path}") if not stream_key_from_path.startswith("live_") else await db.get_stream_by_key(stream_key_from_path)

        if not stream:
            # Try direct stream key lookup
            stream = await db.get_stream_by_key(path)

        if stream:
            # Allow if public or owner is viewing
            if stream.get("is_public"):
                return web.json_response({"allowed": True})

            # Check if viewer has auth (via query param or password)
            if password:
                # Validate via API key
                api_key = await db.get_api_key(password)
                if api_key and api_key["user_id"] == stream["user_id"]:
                    return web.json_response({"allowed": True})

        # Default deny for unrecognized streams or unauthorized access
        return web.json_response({"error": "Access denied"}, status=403)

    return web.json_response({"error": "Unknown action"}, status=400)


async def http_stream_event(request: web.Request) -> web.Response:
    """MediaMTX stream event hook.

    Called when streams start/stop for updating live status.
    """
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    event = data.get("event", "")
    path = data.get("path", "")

    logger.debug(f"Stream event: event={event}, path={path}")

    if event == "disconnect" and path:
        # Find stream and mark as offline (after grace period)
        stream_key = path.split("/")[-1] if "/" in path else path
        # Handle rtmp_ token paths — map back to parent stream
        if stream_key.startswith("rtmp_"):
            token_hash = hashlib.sha256(stream_key.encode()).hexdigest()
            token_record = await db.get_rtmp_token(token_hash)
            if token_record and token_record.get("stream_key"):
                stream = await db.get_stream_by_key(token_record["stream_key"])
            else:
                stream = None
        else:
            stream = await db.get_stream_by_key(stream_key)
        if stream:
            stream_id = stream["id"]

            # Clean up rtmp_ path mapping
            _rtmp_stream_paths.pop(stream_id, None)

            # Cancel any existing grace task for this stream (shouldn't happen, but be safe)
            existing_task = _disconnect_grace_tasks.pop(stream_id, None)
            if existing_task and not existing_task.done():
                existing_task.cancel()

            # Spawn grace period task — waits before triggering encoding/offline
            logger.info(f"Stream {stream['name']} disconnected, starting 7s grace period...")
            task = asyncio.create_task(_handle_disconnect_grace(stream))
            _disconnect_grace_tasks[stream_id] = task

    return web.json_response({"ok": True})


# =============================================================================
# Stream Proxy API (routes MediaMTX traffic through port 443)
# =============================================================================


async def _get_mediamtx_config() -> dict:
    """Get MediaMTX service configuration."""
    if not _service_manager:
        return {}

    # Find MediaMTX service
    for svc in _service_manager.get_all_services():
        if svc.get_info().name == "mediamtx":
            return svc.get_merged_config()
    return {}


async def _validate_stream_access(key: str, require_publish: bool = False) -> tuple[dict | None, str]:
    """Validate stream access key and return (stream_info, error_message).

    Supports two key types:
    - Private key (live_xxx): Used for publishing and full access
    - Public key (pub_xxx): Used for read-only viewing access

    Args:
        key: The stream key (private or public) to validate
        require_publish: If True, requires private stream key for publishing

    Returns:
        Tuple of (stream_dict or None, error_message or empty string)
    """
    if not key:
        return None, "Stream key required"

    stream = None

    # Check if it's a public key (read-only access)
    if key.startswith("pub_"):
        if require_publish:
            return None, "Public key cannot be used for publishing"
        stream = await db.get_stream_by_public_key(key)
        if not stream:
            return None, "Invalid public key"
        return stream, ""

    # It's a private key (live_xxx) - full access
    if not key.startswith("live_"):
        key = f"live_{key}"

    stream = await db.get_stream_by_key(key)
    if not stream:
        return None, "Invalid stream key"

    return stream, ""


async def http_stream_hls_proxy(request: web.Request) -> web.Response:
    """Proxy HLS requests to MediaMTX through port 443.

    Route: /api/stream/{key}/hls/{path:.*}

    Accepts either:
    - Public key (pub_xxx): Read-only access for viewers
    - Private key (live_xxx): Full access for stream owner

    Allows viewing streams via HLS through the portal, keeping MediaMTX
    bound to localhost.
    """
    key = request.match_info.get("stream_key", "")
    hls_path = request.match_info.get("path", "index.m3u8")

    # Validate stream access (supports both public and private keys)
    stream, error = await _validate_stream_access(key)
    if error:
        return web.json_response({"error": error}, status=403)

    # Get MediaMTX configuration
    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        return web.json_response({"error": "MediaMTX not configured"}, status=503)

    hls_port = mtx_config.get("hls_port", 8888)

    # MediaMTX uses the private stream_key for paths (not public_key)
    # When publishing via rtmp_ token, MediaMTX path is the token, not the live_ key
    private_key = _rtmp_stream_paths.get(stream["id"], stream["stream_key"])
    # MediaMTX path includes the RTMP app name "live"
    mtx_path = f"live/{private_key}"
    url = f"https://127.0.0.1:{hls_port}/{mtx_path}/{hls_path}"

    try:
        # Create SSL context that allows self-signed certs (internal communication)
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.read()

                # Rewrite URLs in m3u8 files to go through our proxy
                content_type = resp.content_type or "application/octet-stream"
                if content_type.startswith("application/vnd.apple.mpegurl") or hls_path.endswith(".m3u8"):
                    text = content.decode("utf-8")
                    # Rewrite segment URLs to go through our proxy
                    # Use the same key type that was used to access (preserves public/private key)
                    text = text.replace(f"/{mtx_path}/", f"/api/stream/{key}/hls/")
                    content = text.encode("utf-8")

                return web.Response(
                    body=content,
                    status=resp.status,
                    content_type=content_type,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-cache",
                    }
                )
    except asyncio.TimeoutError:
        return web.json_response({"error": "Stream timeout"}, status=504)
    except Exception as e:
        logger.error(f"HLS proxy error: {e}")
        return web.json_response({"error": "Stream unavailable"}, status=502)


# Cache for stream thumbnails (key -> (timestamp, image_bytes))
_thumbnail_cache: dict[str, tuple[float, bytes]] = {}
_THUMBNAIL_CACHE_TTL = 15  # seconds


async def http_stream_thumbnail(request: web.Request) -> web.Response:
    """Generate a live thumbnail from an active stream.

    Route: GET /api/stream/{key}/thumbnail

    Captures a frame from the HLS stream using ffmpeg.
    Thumbnails are cached for 15 seconds to reduce load.
    """
    key = request.match_info.get("stream_key", "")

    # Validate stream access
    stream, error = await _validate_stream_access(key, require_publish=False)
    if error:
        return web.json_response({"error": error}, status=403)

    # Check if stream is live (only generate dynamic thumbnail for active broadcast)
    if stream.get("is_live") != 1:
        # Return static thumbnail if available, or 404
        if stream.get("thumbnail_url"):
            raise web.HTTPFound(stream["thumbnail_url"])
        return web.json_response({"error": "Stream is offline"}, status=404)

    # Check cache
    cache_key = stream["stream_key"]
    now = time()
    if cache_key in _thumbnail_cache:
        cached_time, cached_bytes = _thumbnail_cache[cache_key]
        if now - cached_time < _THUMBNAIL_CACHE_TTL:
            return web.Response(
                body=cached_bytes,
                content_type="image/jpeg",
                headers={
                    "Cache-Control": f"public, max-age={_THUMBNAIL_CACHE_TTL}",
                    "Access-Control-Allow-Origin": "*",
                }
            )

    # Get MediaMTX configuration
    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        return web.json_response({"error": "MediaMTX not configured"}, status=503)

    hls_port = mtx_config.get("hls_port", 8888)
    # When publishing via rtmp_ token, MediaMTX path is the token, not the live_ key
    private_key = _rtmp_stream_paths.get(stream["id"], stream["stream_key"])
    hls_url = f"https://127.0.0.1:{hls_port}/live/{private_key}/index.m3u8"

    try:
        # Use ffmpeg to capture a frame from the HLS stream
        # -i: input URL
        # -vframes 1: capture only 1 frame
        # -f image2: output format
        # -q:v 2: quality (2-5 is good, lower is better)
        # pipe:1: output to stdout
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg",
            "-y",  # Overwrite without asking
            "-i", hls_url,
            "-vframes", "1",
            "-f", "image2",
            "-vcodec", "mjpeg",
            "-q:v", "3",
            "-vf", "scale=640:-1",  # Scale to 640px width, maintain aspect ratio
            "pipe:1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "AV_LOG_FORCE_NOCOLOR": "1"}
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode != 0 or not stdout:
            logger.warning(f"ffmpeg thumbnail capture failed for {cache_key}: {stderr.decode()[:200]}")
            return web.json_response({"error": "Failed to capture thumbnail"}, status=500)

        # Cache the thumbnail
        _thumbnail_cache[cache_key] = (now, stdout)

        # Clean old cache entries
        for k in list(_thumbnail_cache.keys()):
            if now - _thumbnail_cache[k][0] > _THUMBNAIL_CACHE_TTL * 2:
                del _thumbnail_cache[k]

        return web.Response(
            body=stdout,
            content_type="image/jpeg",
            headers={
                "Cache-Control": f"public, max-age={_THUMBNAIL_CACHE_TTL}",
                "Access-Control-Allow-Origin": "*",
            }
        )

    except asyncio.TimeoutError:
        return web.json_response({"error": "Thumbnail capture timeout"}, status=504)
    except Exception as e:
        logger.error(f"Thumbnail capture error: {e}")
        return web.json_response({"error": "Failed to capture thumbnail"}, status=500)


async def http_stream_webrtc_whep(request: web.Request) -> web.Response:
    """WebRTC WHEP endpoint for playback through port 443.

    Route: POST /api/stream/{key}/webrtc/whep

    Accepts either public key (pub_xxx) or private key (live_xxx) for viewing.
    Proxies WebRTC offers to MediaMTX and returns the answer.
    """
    key = request.match_info.get("stream_key", "")

    # Validate stream access (read-only, no publish required)
    stream, error = await _validate_stream_access(key, require_publish=False)
    if error:
        return web.json_response({"error": error}, status=403)

    # Get MediaMTX configuration
    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        return web.json_response({"error": "MediaMTX not configured"}, status=503)

    webrtc_port = mtx_config.get("webrtc_port", 8889)

    # Get SDP offer from request
    sdp_offer = await request.text()
    if not sdp_offer:
        return web.json_response({"error": "SDP offer required"}, status=400)

    # MediaMTX uses private stream_key for paths
    private_key = stream["stream_key"]
    # WebRTC uses plain HTTP internally (localhost only) - DTLS-SRTP handles media encryption
    url = f"http://127.0.0.1:{webrtc_port}/{private_key}/whep"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=sdp_offer,
                headers={"Content-Type": "application/sdp"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                sdp_answer = await resp.text()

                if resp.status == 201:
                    # Rewrite Location header to go through our proxy
                    location = resp.headers.get("Location", "")
                    if location:
                        # Extract session ID from location
                        session_id = location.split("/")[-1]
                        # Use the same key type that was used to access
                        location = f"/api/stream/{key}/webrtc/session/{session_id}"

                    return web.Response(
                        text=sdp_answer,
                        status=201,
                        content_type="application/sdp",
                        headers={
                            "Location": location,
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Expose-Headers": "Location",
                        }
                    )
                else:
                    return web.Response(
                        text=sdp_answer,
                        status=resp.status,
                        content_type=resp.content_type
                    )
    except asyncio.TimeoutError:
        return web.json_response({"error": "Connection timeout"}, status=504)
    except Exception as e:
        logger.error(f"WHEP proxy error: {e}")
        return web.json_response({"error": "WebRTC unavailable"}, status=502)


async def http_stream_webrtc_whip(request: web.Request) -> web.Response:
    """WebRTC WHIP endpoint for publishing through port 443.

    Route: POST /api/stream/{stream_key}/webrtc/whip

    Allows OBS and other tools to publish streams via WebRTC through the portal.
    """
    stream_key = request.match_info.get("stream_key", "")

    # Validate stream key for publishing
    stream, error = await _validate_stream_access(stream_key, require_publish=True)
    if error:
        return web.json_response({"error": error}, status=403)

    # Get MediaMTX configuration
    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        return web.json_response({"error": "MediaMTX not configured"}, status=503)

    webrtc_port = mtx_config.get("webrtc_port", 8889)

    # Get SDP offer from request
    sdp_offer = await request.text()
    if not sdp_offer:
        return web.json_response({"error": "SDP offer required"}, status=400)

    # The stream path in MediaMTX is the stream key
    full_stream_key = stream_key if stream_key.startswith("live_") else f"live_{stream_key}"
    # WebRTC uses plain HTTP internally (localhost only) - DTLS-SRTP handles media encryption
    url = f"http://127.0.0.1:{webrtc_port}/{full_stream_key}/whip"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=sdp_offer,
                headers={"Content-Type": "application/sdp"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                sdp_answer = await resp.text()

                if resp.status == 201:
                    # Mark stream as live
                    await db.set_stream_live(stream["id"], True)
                    logger.info(f"Stream {stream['name']} started via WHIP")

                    # Rewrite Location header
                    location = resp.headers.get("Location", "")
                    if location:
                        session_id = location.split("/")[-1]
                        location = f"/api/stream/{stream_key}/webrtc/session/{session_id}"

                    return web.Response(
                        text=sdp_answer,
                        status=201,
                        content_type="application/sdp",
                        headers={
                            "Location": location,
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Expose-Headers": "Location",
                        }
                    )
                else:
                    return web.Response(
                        text=sdp_answer,
                        status=resp.status,
                        content_type=resp.content_type
                    )
    except asyncio.TimeoutError:
        return web.json_response({"error": "Connection timeout"}, status=504)
    except Exception as e:
        logger.error(f"WHIP proxy error: {e}")
        return web.json_response({"error": "WebRTC unavailable"}, status=502)


async def http_stream_webrtc_session(request: web.Request) -> web.Response:
    """Proxy WebRTC session management (ICE candidates, etc.).

    Route: PATCH/DELETE /api/stream/{stream_key}/webrtc/session/{session_id}
    """
    stream_key = request.match_info.get("stream_key", "")
    session_id = request.match_info.get("session_id", "")

    # Validate stream access
    stream, error = await _validate_stream_access(stream_key)
    if error:
        return web.json_response({"error": error}, status=403)

    # Get MediaMTX configuration
    mtx_config = await _get_mediamtx_config()
    if not mtx_config:
        return web.json_response({"error": "MediaMTX not configured"}, status=503)

    webrtc_port = mtx_config.get("webrtc_port", 8889)

    # The stream path in MediaMTX is the stream key
    full_stream_key = stream_key if stream_key.startswith("live_") else f"live_{stream_key}"

    # Determine the correct MediaMTX endpoint based on request method
    method = request.method
    # WebRTC uses plain HTTP internally (localhost only)
    url = f"http://127.0.0.1:{webrtc_port}/{full_stream_key}/whep/{session_id}"

    try:
        body = await request.read()
        headers = {"Content-Type": request.content_type} if request.content_type else {}

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method,
                url,
                data=body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                content = await resp.read()
                return web.Response(
                    body=content,
                    status=resp.status,
                    content_type=resp.content_type,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
    except Exception as e:
        logger.error(f"WebRTC session proxy error: {e}")
        return web.json_response({"error": "Session error"}, status=502)


async def http_stream_info(request: web.Request) -> web.Response:
    """Get stream information and playback URLs.

    Route: GET /api/stream/{stream_key}/info
    """
    stream_key = request.match_info.get("stream_key", "")

    # Validate stream access
    stream, error = await _validate_stream_access(stream_key)
    if error:
        return web.json_response({"error": error}, status=403)

    # Get the full stream key
    full_stream_key = stream_key if stream_key.startswith("live_") else f"live_{stream_key}"

    # Base URL for the portal
    host = request.headers.get("Host", Config.HOSTNAME)
    base_url = f"https://{host}"

    return web.json_response({
        "stream_key": full_stream_key,
        "name": stream.get("name", ""),
        "is_live": stream.get("is_live", 0),
        "is_public": stream.get("is_public", False),
        "playback": {
            "hls": f"{base_url}/api/stream/{stream_key}/hls/index.m3u8",
            "webrtc_whep": f"{base_url}/api/stream/{stream_key}/webrtc/whep"
        },
        "publish": {
            "webrtc_whip": f"{base_url}/api/stream/{stream_key}/webrtc/whip"
        }
    })


# =============================================================================
# Traffic Metrics API
# =============================================================================


async def http_get_metrics_summary(request: web.Request) -> web.Response:
    """Get traffic metrics summary (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    return web.json_response(traffic_metrics.get_summary())


async def http_get_metrics_services(request: web.Request) -> web.Response:
    """Get per-service traffic metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    service_metrics = traffic_metrics.get_all_service_metrics()

    # Enrich with service names
    all_services = await db.get_all_services()
    name_map = {s["id"]: s["name"] for s in all_services}
    special_names = {-1: "Local Terminal", -2: "Chat", 0: "Unresolved"}
    for m in service_metrics:
        sid = m["service_id"]
        if sid in special_names:
            m["service_name"] = special_names[sid]
        elif sid > 0:
            m["service_name"] = name_map.get(sid, f"Service #{sid}")
        else:
            m["service_name"] = f"User Connection #{abs(sid)}"

    return web.json_response({"services": service_metrics})


async def http_get_metrics_active(request: web.Request) -> web.Response:
    """Get active connections with metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    connections = traffic_metrics.get_active_connections()
    # Enrich with service names
    all_services = await db.get_all_services()
    name_map = {s["id"]: s["name"] for s in all_services}
    special_names = {-1: "Local Terminal", -2: "Chat", 0: "Unresolved"}
    for c in connections:
        sid = c["service_id"]
        if sid in special_names:
            c["service_name"] = special_names[sid]
        elif sid > 0:
            c["service_name"] = name_map.get(sid, f"Service #{sid}")
        else:
            c["service_name"] = f"User Connection #{abs(sid)}"

    return web.json_response({"connections": connections})


async def http_get_metrics_time_series(request: web.Request) -> web.Response:
    """Get time series metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        hours = int(request.query.get("hours", "1"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid hours parameter"}, status=400)
    hours = min(max(hours, 1), 24)  # Clamp between 1 and 24

    return web.json_response({
        "data": traffic_metrics.get_time_series(hours)
    })


async def http_get_metrics_top(request: web.Request) -> web.Response:
    """Get top services and users (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        limit = int(request.query.get("limit", "10"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit parameter"}, status=400)
    limit = min(max(limit, 1), 50)  # Clamp between 1 and 50

    top_services = traffic_metrics.get_top_services(limit)
    # Enrich with service names
    all_services = await db.get_all_services()
    name_map = {s["id"]: s["name"] for s in all_services}
    special_names = {-1: "Local Terminal", -2: "Chat", 0: "Unresolved"}
    for m in top_services:
        sid = m["service_id"]
        if sid in special_names:
            m["service_name"] = special_names[sid]
        elif sid > 0:
            m["service_name"] = name_map.get(sid, f"Service #{sid}")
        else:
            m["service_name"] = f"User Connection #{abs(sid)}"

    return web.json_response({
        "top_services": top_services,
        "top_users": traffic_metrics.get_top_users(limit)
    })


# =============================================================================
# Shodan Integration API
# =============================================================================


async def http_shodan_lookup(request: web.Request) -> web.Response:
    """Look up an IP address in Shodan (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    ip = request.match_info.get("ip")
    if not ip:
        return web.json_response({"error": "IP address required"}, status=400)

    # Validate IP format
    import ipaddress as _ipaddress
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        return web.json_response({"error": "Invalid IP address format"}, status=400)

    if not Config.SHODAN_API_KEY and not shodan_client.api_key:
        return web.json_response({"error": "Shodan API key not configured"}, status=503)

    result = await shodan_client.lookup_host(ip)
    if result:
        return web.json_response(result.to_dict())
    else:
        return web.json_response({"error": "No data found for IP", "ip": ip}, status=404)


async def http_shodan_search(request: web.Request) -> web.Response:
    """Search Shodan (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not Config.SHODAN_API_KEY and not shodan_client.api_key:
        return web.json_response({"error": "Shodan API key not configured"}, status=503)

    query = request.query.get("query")
    if not query:
        return web.json_response({"error": "Query parameter required"}, status=400)

    try:
        limit = int(request.query.get("limit", "10"))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit parameter"}, status=400)
    limit = min(max(limit, 1), 100)

    results = await shodan_client.search(query, limit)
    return web.json_response({"results": results})


async def http_shodan_api_info(request: web.Request) -> web.Response:
    """Get Shodan API info (credits remaining, etc.) - admin only."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # Check both Config and the client (client may have been set at runtime)
    if not Config.SHODAN_API_KEY and not shodan_client.api_key:
        return web.json_response({
            "configured": False,
            "message": "Shodan API key not configured"
        })

    info = await shodan_client.get_api_info()
    if info:
        return web.json_response({
            "configured": True,
            "plan": info.get("plan", "unknown"),
            "query_credits": info.get("query_credits", 0),
            "scan_credits": info.get("scan_credits", 0)
        })
    else:
        return web.json_response({
            "configured": bool(Config.SHODAN_API_KEY or shodan_client.api_key),
            "error": "Failed to get API info"
        }, status=500)


async def http_shodan_set_api_key(request: web.Request) -> web.Response:
    """Set Shodan API key (admin only) - persists to database."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    api_key = data.get("api_key", "").strip()
    if not api_key:
        return web.json_response({"error": "API key required"}, status=400)

    # Set the API key in both the client and Config
    shodan_client.set_api_key(api_key)
    Config.SHODAN_API_KEY = api_key

    # Verify the key works before persisting
    info = await shodan_client.get_api_info()
    if info:
        # Persist to database for survival across restarts
        await db.set_setting("shodan_api_key", api_key)
        logger.info(f"Shodan API key updated and persisted by user {token.user_id}")
        return web.json_response({
            "status": "success",
            "plan": info.get("plan", "unknown"),
            "query_credits": info.get("query_credits", 0)
        })
    else:
        return web.json_response({"error": "Invalid API key"}, status=400)


# =============================================================================
# VOD Manager API
# =============================================================================


async def _connect_vod_sftp(user_id: int):
    """Connect to user's VOD SFTP storage. Returns (conn, sftp, None) or (None, None, error)."""
    storage = await db.get_vod_storage(user_id)
    if not storage:
        return None, None, "No VOD storage configured"

    try:
        config = json.loads(storage.get("config", "{}"))
    except json.JSONDecodeError:
        config = {}
    connect_opts = {
        "host": storage["host"],
        "port": storage["port"] or 22,
        "username": storage["username"],
        "known_hosts": None,
    }

    if storage["auth_method"] == "key":
        key_content = config.get("private_key")
        if key_content:
            connect_opts["client_keys"] = [asyncssh.import_private_key(key_content)]
        else:
            return None, None, "No private key configured"
    elif storage["auth_method"] == "password":
        connect_opts["password"] = config.get("password", "")

    try:
        conn = await asyncio.wait_for(asyncssh.connect(**connect_opts), timeout=10)
        sftp = await conn.start_sftp_client()
        return conn, sftp, None
    except asyncio.TimeoutError:
        return None, None, "Connection timed out"
    except asyncssh.Error as e:
        return None, None, f"SSH error: {e}"
    except OSError as e:
        return None, None, f"Connection error: {e}"


async def http_get_vod_storage(request: web.Request) -> web.Response:
    """Get current user's VOD storage config (password/key redacted)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    storage = await db.get_vod_storage(token.user_id)
    if not storage:
        return web.json_response({"storage": None})

    # Redact sensitive fields - strip config entirely, expose only flags
    try:
        config = json.loads(storage.get("config", "{}"))
    except json.JSONDecodeError:
        config = {}
    redacted = dict(storage)
    del redacted["config"]
    redacted["has_password"] = bool(config.get("password"))
    redacted["has_key"] = bool(config.get("private_key"))

    return web.json_response({"storage": redacted})


async def http_save_vod_storage(request: web.Request) -> web.Response:
    """Create or update VOD storage config."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    host = data.get("host", "").strip()
    username = data.get("username", "").strip()
    remote_path = data.get("remote_path", "").strip()
    auth_method = data.get("auth_method", "password")

    if not host:
        return web.json_response({"error": "Host is required"}, status=400)
    if not username:
        return web.json_response({"error": "Username is required"}, status=400)
    if not remote_path:
        return web.json_response({"error": "Remote path is required"}, status=400)
    if auth_method not in ("password", "key"):
        return web.json_response({"error": "Invalid auth method"}, status=400)

    port = data.get("port", 22)
    try:
        port = int(port)
        if port < 1 or port > 65535:
            raise ValueError
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid port"}, status=400)

    # Build config JSON with sensitive data
    config = {}
    if auth_method == "password":
        password = data.get("password", "")
        # If password is "***", keep existing password
        if password == "***":
            existing = await db.get_vod_storage(token.user_id)
            if existing:
                try:
                    existing_config = json.loads(existing.get("config", "{}"))
                except json.JSONDecodeError:
                    existing_config = {}
                password = existing_config.get("password", "")
        config["password"] = password
    elif auth_method == "key":
        private_key = data.get("private_key", "")
        # If key is "***", keep existing key
        if private_key == "***":
            existing = await db.get_vod_storage(token.user_id)
            if existing:
                try:
                    existing_config = json.loads(existing.get("config", "{}"))
                except json.JSONDecodeError:
                    existing_config = {}
                private_key = existing_config.get("private_key", "")
        config["private_key"] = private_key

    storage_id = await db.save_vod_storage(
        token.user_id,
        name=data.get("name", "My VOD Storage"),
        host=host,
        port=port,
        username=username,
        auth_method=auth_method,
        remote_path=remote_path,
        config=json.dumps(config),
    )

    return web.json_response({"id": storage_id, "message": "Storage config saved"})


async def http_delete_vod_storage(request: web.Request) -> web.Response:
    """Delete VOD storage config."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    deleted = await db.delete_vod_storage(token.user_id)
    if not deleted:
        return web.json_response({"error": "No storage config found"}, status=404)
    return web.json_response({"message": "Storage config deleted"})


async def http_test_vod_storage(request: web.Request) -> web.Response:
    """Test SFTP connection with provided or saved credentials."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    host = data.get("host", "").strip()
    username = data.get("username", "").strip()
    remote_path = data.get("remote_path", "").strip()
    auth_method = data.get("auth_method", "password")
    try:
        port = int(data.get("port", 22))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid port"}, status=400)

    if not host or not username:
        return web.json_response({"error": "Host and username are required"}, status=400)

    connect_opts = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": None,
    }

    # Resolve credentials (may need to fetch existing if "***")
    if auth_method == "key":
        private_key = data.get("private_key", "")
        if private_key == "***":
            existing = await db.get_vod_storage(token.user_id)
            if existing:
                try:
                    existing_config = json.loads(existing.get("config", "{}"))
                except json.JSONDecodeError:
                    existing_config = {}
                private_key = existing_config.get("private_key", "")
        if private_key:
            try:
                connect_opts["client_keys"] = [asyncssh.import_private_key(private_key)]
            except asyncssh.KeyImportError as e:
                return web.json_response({"success": False, "error": f"Invalid private key: {e}"})
    else:
        password = data.get("password", "")
        if password == "***":
            existing = await db.get_vod_storage(token.user_id)
            if existing:
                try:
                    existing_config = json.loads(existing.get("config", "{}"))
                except json.JSONDecodeError:
                    existing_config = {}
                password = existing_config.get("password", "")
        connect_opts["password"] = password

    conn = None
    try:
        conn = await asyncio.wait_for(asyncssh.connect(**connect_opts), timeout=10)
        sftp = await conn.start_sftp_client()

        # Try to list the remote path
        if remote_path:
            files = await sftp.listdir(remote_path)
            mkv_count = sum(1 for f in files if f.lower().endswith(".mkv"))
            return web.json_response({
                "success": True,
                "message": f"Connected successfully. Found {mkv_count} MKV file(s) in {remote_path}."
            })
        else:
            return web.json_response({"success": True, "message": "Connected successfully."})

    except asyncio.TimeoutError:
        return web.json_response({"success": False, "error": "Connection timed out"})
    except asyncssh.Error as e:
        return web.json_response({"success": False, "error": f"SSH error: {e}"})
    except OSError as e:
        return web.json_response({"success": False, "error": f"Connection failed: {e}"})
    finally:
        if conn:
            conn.close()


async def http_list_vods(request: web.Request) -> web.Response:
    """List MKV files on user's remote SFTP storage (recursive).

    Returns files with paths relative to the VOD root, e.g.
    "StreamName/2026-02-08_12-00-00/chunk_000.mkv" or "old_recording.mkv".
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    storage = await db.get_vod_storage(token.user_id)
    if not storage:
        return web.json_response({"error": "No VOD storage configured"}, status=404)

    conn, sftp, error = await _connect_vod_sftp(token.user_id)
    if error:
        return web.json_response({"error": error}, status=502)

    try:
        remote_root = storage["remote_path"].rstrip("/")
        files = []

        async def scan_dir(dir_path: str, rel_prefix: str):
            try:
                entries = await sftp.listdir(dir_path)
            except (asyncssh.SFTPError, OSError):
                return
            for name in entries:
                if name.startswith("."):
                    continue
                full_path = f"{dir_path}/{name}"
                rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
                try:
                    attrs = await sftp.stat(full_path)
                except (asyncssh.SFTPError, OSError):
                    continue
                if attrs.permissions is not None and (attrs.permissions & 0o40000):
                    # Directory — recurse
                    await scan_dir(full_path, rel_path)
                elif name.lower().endswith(".mkv"):
                    files.append({
                        "name": rel_path,
                        "size": attrs.size or 0,
                        "modified": attrs.mtime or 0,
                    })

        await scan_dir(remote_root, "")

        # Sort
        sort_by = request.query.get("sort", "modified")
        reverse = request.query.get("order", "desc") == "desc"
        if sort_by == "name":
            files.sort(key=lambda f: f["name"].lower(), reverse=reverse)
        elif sort_by == "size":
            files.sort(key=lambda f: f["size"], reverse=reverse)
        else:
            files.sort(key=lambda f: f["modified"], reverse=reverse)

        return web.json_response({"files": files, "path": remote_root})
    except asyncssh.SFTPError as e:
        return web.json_response({"error": f"SFTP error: {e}"}, status=502)
    except OSError as e:
        return web.json_response({"error": f"Connection error: {e}"}, status=502)
    finally:
        conn.close()


async def http_download_vod(request: web.Request) -> web.Response:
    """Stream-download a VOD file from remote SFTP storage.

    Supports subdirectory paths like "StreamName/session/chunk_000.mkv".
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    filename = request.match_info["filename"]

    # Security: prevent path traversal
    if ".." in filename or filename.startswith("/"):
        return web.json_response({"error": "Invalid filename"}, status=400)
    if not filename.lower().endswith(".mkv"):
        return web.json_response({"error": "Only MKV files can be downloaded"}, status=400)

    storage = await db.get_vod_storage(token.user_id)
    if not storage:
        return web.json_response({"error": "No VOD storage configured"}, status=404)

    conn, sftp, error = await _connect_vod_sftp(token.user_id)
    if error:
        return web.json_response({"error": error}, status=502)

    response_started = False
    try:
        remote_path = f"{storage['remote_path'].rstrip('/')}/{filename}"
        attrs = await sftp.stat(remote_path)

        response = web.StreamResponse()
        response.content_type = "video/x-matroska"
        response.content_length = attrs.size
        safe_name = filename.split("/")[-1].replace('"', '\\"')
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
        await response.prepare(request)
        response_started = True

        CHUNK_SIZE = 262144  # 256 KB
        async with sftp.open(remote_path, "rb") as f:
            while True:
                chunk = await f.read(CHUNK_SIZE)
                if not chunk:
                    break
                await response.write(chunk)

        await response.write_eof()
        return response
    except asyncssh.SFTPError as e:
        if response_started:
            return response  # Headers already sent, can't send error JSON
        return web.json_response({"error": f"SFTP error: {e}"}, status=502)
    except OSError as e:
        if response_started:
            return response
        return web.json_response({"error": f"Download error: {e}"}, status=502)
    finally:
        conn.close()


async def http_download_vod_archive(request: web.Request) -> web.Response:
    """Download multiple VOD files as a zip archive streamed from SFTP.

    POST body: {"files": ["StreamName/session/chunk_000.mkv", ...]}
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    files = data.get("files", [])
    if not files or not isinstance(files, list):
        return web.json_response({"error": "No files specified"}, status=400)
    if len(files) > 500:
        return web.json_response({"error": "Too many files (max 500)"}, status=400)

    # Validate all paths
    for f in files:
        if ".." in f or f.startswith("/"):
            return web.json_response({"error": f"Invalid path: {f}"}, status=400)
        if not f.lower().endswith(".mkv"):
            return web.json_response({"error": f"Not an MKV file: {f}"}, status=400)

    storage = await db.get_vod_storage(token.user_id)
    if not storage:
        return web.json_response({"error": "No VOD storage configured"}, status=404)

    conn, sftp, error = await _connect_vod_sftp(token.user_id)
    if error:
        return web.json_response({"error": error}, status=502)

    # Derive archive name from common prefix
    parts_list = [f.split("/") for f in files]
    if len(parts_list) > 1 and len(parts_list[0]) > 1 and all(p[0] == parts_list[0][0] for p in parts_list):
        archive_name = parts_list[0][0]
        if len(parts_list[0]) > 2 and all(len(p) > 1 and p[1] == parts_list[0][1] for p in parts_list):
            archive_name += f"_{parts_list[0][1]}"
    elif len(files) == 1:
        archive_name = files[0].rsplit("/", 1)[-1].replace(".mkv", "")
    else:
        archive_name = "vods"
    archive_name = re.sub(r'[^\w\s-]', '_', archive_name)

    response = web.StreamResponse()
    response.content_type = "application/zip"
    response.headers["Content-Disposition"] = f'attachment; filename="{archive_name}.zip"'
    await response.prepare(request)

    remote_root = storage["remote_path"].rstrip("/")

    import struct
    import binascii

    # Track entries for central directory (written after all file data)
    entries = []  # list of (fname_bytes, crc32, size, local_header_offset)
    offset = 0    # running byte offset in the stream

    for filepath in files:
        remote_path = f"{remote_root}/{filepath}"
        try:
            fname_bytes = filepath.encode("utf-8")
            local_header_offset = offset

            # Local file header (no compression, data descriptor flag set)
            header = struct.pack(
                '<4sHHHHHIIIHH',
                b'PK\x03\x04',     # signature
                20,                 # version needed (2.0)
                0x08,               # flags: bit 3 = data descriptor follows
                0,                  # compression: stored
                0,                  # mod time
                0,                  # mod date
                0,                  # crc32 (deferred to data descriptor)
                0,                  # compressed size (deferred)
                0,                  # uncompressed size (deferred)
                len(fname_bytes),   # filename length
                0,                  # extra field length
            ) + fname_bytes
            await response.write(header)
            offset += len(header)

            # Stream file data from SFTP, computing CRC as we go
            crc = 0
            total_size = 0
            CHUNK_SIZE = 262144
            async with sftp.open(remote_path, "rb") as f:
                while True:
                    chunk = await f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    crc = binascii.crc32(chunk, crc) & 0xFFFFFFFF
                    total_size += len(chunk)
                    await response.write(chunk)
            offset += total_size

            # Data descriptor (with signature)
            desc = struct.pack('<4sIII',
                b'PK\x07\x08',   # signature
                crc,              # crc32
                total_size,       # compressed size (same as uncompressed for stored)
                total_size,       # uncompressed size
            )
            await response.write(desc)
            offset += len(desc)

            entries.append((fname_bytes, crc, total_size, local_header_offset))

        except (asyncssh.SFTPError, OSError) as e:
            logger.warning(f"Skipping VOD file in archive {filepath}: {e}")
            continue

    # Central directory
    cd_offset = offset
    cd_size = 0
    for fname_bytes, crc, size, local_offset in entries:
        cd_entry = struct.pack(
            '<4sHHHHHHIIIHHHHHII',
            b'PK\x01\x02',     # central directory signature
            20,                 # version made by (2.0)
            20,                 # version needed (2.0)
            0x08,               # flags: data descriptor
            0,                  # compression: stored
            0,                  # mod time
            0,                  # mod date
            crc,                # crc32
            size,               # compressed size
            size,               # uncompressed size
            len(fname_bytes),   # filename length
            0,                  # extra field length
            0,                  # file comment length
            0,                  # disk number start
            0,                  # internal file attributes
            0,                  # external file attributes
            local_offset,       # relative offset of local header
        ) + fname_bytes
        await response.write(cd_entry)
        cd_size += len(cd_entry)

    # End of central directory record
    entry_count = len(entries)
    eocd = struct.pack(
        '<4sHHHHIIH',
        b'PK\x05\x06',     # EOCD signature
        0,                  # disk number
        0,                  # disk with central dir
        entry_count,        # entries on this disk
        entry_count,        # total entries
        cd_size,            # size of central directory
        cd_offset,          # offset of central directory
        0,                  # comment length
    )
    await response.write(eocd)

    await response.write_eof()
    conn.close()
    return response


async def http_delete_vod(request: web.Request) -> web.Response:
    """Delete a VOD file from remote SFTP storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    filename = request.match_info["filename"]

    # Security: prevent path traversal
    if ".." in filename or filename.startswith("/"):
        return web.json_response({"error": "Invalid filename"}, status=400)
    if not filename.lower().endswith(".mkv"):
        return web.json_response({"error": "Only MKV files can be deleted"}, status=400)

    storage = await db.get_vod_storage(token.user_id)
    if not storage:
        return web.json_response({"error": "No VOD storage configured"}, status=404)

    conn, sftp, error = await _connect_vod_sftp(token.user_id)
    if error:
        return web.json_response({"error": error}, status=502)

    try:
        remote_path = f"{storage['remote_path'].rstrip('/')}/{filename}"
        await sftp.remove(remote_path)
        return web.json_response({"message": f"Deleted {filename}"})
    except asyncssh.SFTPError as e:
        return web.json_response({"error": f"SFTP error: {e}"}, status=502)
    except OSError as e:
        return web.json_response({"error": f"Delete error: {e}"}, status=502)
    finally:
        conn.close()


# =============================================================================
# Vulnerability Scanner API
# =============================================================================


async def http_vuln_scan_host(request: web.Request) -> web.Response:
    """Scan a host for vulnerabilities (admin only).

    Query parameters:
    - ports: Comma-separated list of ports to scan (optional)
    - scan_type: Type of scan - "basic", "version", "vuln", "full" (default: "version")
    - use_nmap: Whether to use nmap if available (default: true)
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    host = request.match_info.get("host")
    if not host:
        return web.json_response({"error": "Host required"}, status=400)

    # Validate host format (IP or hostname)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'

    if not (re.match(ip_pattern, host) or re.match(hostname_pattern, host)):
        return web.json_response({"error": "Invalid host format"}, status=400)

    # Parse optional ports parameter
    ports_param = request.query.get("ports", "")
    ports = None
    if ports_param:
        try:
            ports = [int(p.strip()) for p in ports_param.split(",") if p.strip()]
            if any(p < 1 or p > 65535 for p in ports):
                return web.json_response({"error": "Invalid port number"}, status=400)
        except ValueError:
            return web.json_response({"error": "Invalid ports format"}, status=400)

    # Parse scan type - basic, version, vuln, full
    scan_type = request.query.get("scan_type", "version")
    if scan_type not in ("basic", "version", "vuln", "full"):
        return web.json_response({"error": "Invalid scan_type. Use: basic, version, vuln, or full"}, status=400)

    # Parse use_nmap flag
    use_nmap = request.query.get("use_nmap", "true").lower() != "false"

    try:
        result = await vulnerability_scanner.scan_host(
            host, ports,
            scan_type=scan_type,
            use_nmap=use_nmap
        )
        logger.info(f"Vulnerability scan ({scan_type}) completed for {host} by user {token.user_id}")
        return web.json_response(result.to_dict())
    except RuntimeError as e:
        logger.warning(f"Vulnerability scan warning for {host}: {e}")
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Vulnerability scan failed for {host}: {e}")
        return web.json_response({"error": "Scan failed"}, status=500)


async def http_vuln_scan_service(request: web.Request) -> web.Response:
    """Scan a Portal service for vulnerabilities (admin only).

    Query parameters:
    - scan_type: Type of scan - "basic", "version", "vuln", "full" (default: "version")
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    service_id = request.match_info.get("service_id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service = await db.get_service_by_id(int(service_id))
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    host = service.get("host", "localhost")
    port = service.get("port")

    if not port:
        return web.json_response({"error": "Service has no port configured"}, status=400)

    # Parse scan type
    scan_type = request.query.get("scan_type", "version")
    if scan_type not in ("basic", "version", "vuln", "full"):
        scan_type = "version"

    try:
        result = await vulnerability_scanner.scan_host(host, [port], scan_type=scan_type)
        logger.info(f"Vulnerability scan ({scan_type}) completed for service {service_id} by user {token.user_id}")
        return web.json_response({
            "service": {
                "id": service["id"],
                "name": service["name"],
                "host": host,
                "port": port
            },
            "scan": result.to_dict()
        })
    except RuntimeError as e:
        logger.warning(f"Vulnerability scan warning for service {service_id}: {e}")
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Vulnerability scan failed for service {service_id}: {e}")
        return web.json_response({"error": "Scan failed"}, status=500)


async def http_vuln_search_cves(request: web.Request) -> web.Response:
    """Search CVEs by keyword (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    keyword = request.query.get("q", "").strip()
    if not keyword or len(keyword) < 2:
        return web.json_response({"error": "Search query must be at least 2 characters"}, status=400)

    try:
        limit = min(int(request.query.get("limit", "20")), 50)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit parameter"}, status=400)

    try:
        results = await vulnerability_scanner.search_cves(keyword, limit)
        logger.info(f"CVE search for '{keyword}' by user {token.user_id}: {len(results)} results")
        return web.json_response({
            "query": keyword,
            "count": len(results),
            "cves": results
        })
    except Exception as e:
        logger.error(f"CVE search failed: {e}")
        return web.json_response({"error": "Search failed"}, status=500)


async def http_vuln_scanner_status(request: web.Request) -> web.Response:
    """Get vulnerability scanner status (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    return web.json_response({
        "nmap_available": vulnerability_scanner.nmap.is_available(),
        "nmap_path": vulnerability_scanner.nmap.nmap_path,
        "nvd_api_configured": bool(vulnerability_scanner.cve_db._nvd_api_key),
        "cache_ttl": vulnerability_scanner._cache_ttl,
        "scan_timeout": vulnerability_scanner.nmap.timeout,
        "known_cves_count": len(KNOWN_CVES)
    })


async def http_vuln_set_nvd_api_key(request: web.Request) -> web.Response:
    """Set NVD API key (admin only) - persists to database."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    api_key = data.get("api_key", "").strip()
    if not api_key:
        return web.json_response({"error": "API key required"}, status=400)

    # Set the API key in the scanner and Config
    vulnerability_scanner.set_nvd_api_key(api_key)
    Config.NVD_API_KEY = api_key

    # Persist to database for survival across restarts
    await db.set_setting("nvd_api_key", api_key)
    logger.info(f"NVD API key updated and persisted by user {token.user_id}")

    return web.json_response({
        "status": "success",
        "message": "NVD API key configured. You now have higher rate limits (50 requests/30 seconds)."
    })


# Import KNOWN_CVES for the status endpoint
from vulnerability_scanner import KNOWN_CVES


async def http_vuln_lookup_cve(request: web.Request) -> web.Response:
    """Look up CVE details (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    cve_id = request.match_info.get("cve_id", "").upper()
    if not cve_id:
        return web.json_response({"error": "CVE ID required"}, status=400)

    # Validate CVE format
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id) and not cve_id.startswith("CVE-GENERIC-"):
        # Also allow INFO- prefixed IDs for informational findings
        if not cve_id.startswith("INFO-") and not cve_id.startswith("CVE-WEAK-"):
            return web.json_response({"error": "Invalid CVE ID format"}, status=400)

    result = await vulnerability_scanner.lookup_cve(cve_id)
    if result:
        return web.json_response(result)
    else:
        return web.json_response({"error": "CVE not found"}, status=404)


async def http_vuln_get_mitigations(request: web.Request) -> web.Response:
    """Get mitigation steps for a CVE (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    cve_id = request.match_info.get("cve_id", "").upper()
    if not cve_id:
        return web.json_response({"error": "CVE ID required"}, status=400)

    mitigations = await vulnerability_scanner.get_mitigations(cve_id)
    return web.json_response({
        "cve_id": cve_id,
        "mitigations": mitigations
    })


async def http_vuln_known_cves(request: web.Request) -> web.Response:
    """List all known CVEs in local database (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    from vulnerability_scanner import KNOWN_CVES

    cves = []
    for cve_id, info in KNOWN_CVES.items():
        cves.append({
            "cve_id": cve_id,
            "service": info["service"],
            "severity": info["severity"],
            "cvss": info["cvss"],
            "description": info["description"][:100] + "..." if len(info["description"]) > 100 else info["description"]
        })

    # Sort by CVSS score descending
    cves.sort(key=lambda x: x["cvss"], reverse=True)

    return web.json_response({"cves": cves})


async def http_stats(request: web.Request) -> web.Response:
    """Get server statistics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    services = await db.get_all_services()

    # Include traffic metrics summary
    metrics = traffic_metrics.get_summary()

    return web.json_response({
        "active_connections": len(active_connections),
        "total_services": len(services),
        "rate_limit_entries": len(rate_limits),
        "uptime_check": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics
    })


async def http_public_stats(request: web.Request) -> web.Response:
    """Get public statistics.

    Returns metrics visible to all authenticated users:
    - live_streams: Count of currently live public streams
    - online_users: Count of unique users in chat
    - total_services: Count of enabled services

    Admin-only fields (included when requester is admin):
    - total_users: Count of registered users
    - active_connections: Count of active WebSocket connections
    - uptime: Server uptime string
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Get live public streams count
    live_streams = await db.get_public_streams(live_only=True)
    live_count = len(live_streams)

    # Get enabled services count
    services = await db.get_all_services()

    stats = {
        "live_streams": live_count,
        "online_users": len(_online_users),
        "total_services": len(services),
    }

    # Admin-only stats
    is_admin = token.has_scope("admin") or token.has_scope("*")
    if is_admin:
        users = await db.get_all_users()
        uptime_delta = datetime.now(timezone.utc) - _server_start_time
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes = remainder // 60
        if days > 0:
            uptime_str = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            uptime_str = f"{hours}h {minutes}m"
        else:
            uptime_str = f"{minutes}m"

        stats["total_users"] = len(users)
        stats["active_connections"] = len(active_connections)
        stats["uptime"] = uptime_str

    return web.json_response(stats)


async def http_system_health(request: web.Request) -> web.Response:
    """Get system resource metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.5)
    load_avg = os.getloadavg()

    # Memory
    mem = psutil.virtual_memory()

    # Disk (root partition)
    disk = psutil.disk_usage('/')

    # Portal process stats
    proc = psutil.Process(os.getpid())
    proc_mem = proc.memory_info()

    # Uptime
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_delta = datetime.now(timezone.utc) - boot_time

    return web.json_response({
        "cpu": {
            "percent": cpu_percent,
            "count": psutil.cpu_count(),
            "load_avg": list(load_avg)
        },
        "memory": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percent": mem.percent
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        },
        "process": {
            "rss": proc_mem.rss,
            "vms": proc_mem.vms,
            "threads": proc.num_threads(),
            "pid": os.getpid()
        },
        "uptime_seconds": int(uptime_delta.total_seconds())
    })


# =============================================================================
# Certificate Management (admin only)
# =============================================================================

async def http_get_cert_info(request: web.Request) -> web.Response:
    """GET /api/certs/info - Get current certificate information."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        info = cert_manager.get_cert_info(Config.SSL_CERT)
    except FileNotFoundError:
        return web.json_response({"error": "Certificate file not found"}, status=404)
    except Exception as e:
        return web.json_response({"error": f"Failed to read certificate: {e}"}, status=500)

    # Override method from env if set
    if Config.CERT_METHOD:
        info["method"] = Config.CERT_METHOD

    return web.json_response(info)


async def http_upload_cert(request: web.Request) -> web.Response:
    """POST /api/certs/upload - Upload custom PEM cert+key."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    cert_pem = data.get("cert", "").strip()
    key_pem = data.get("key", "").strip()

    if not cert_pem or not key_pem:
        return web.json_response({"error": "Both 'cert' and 'key' fields are required"}, status=400)

    cert_bytes = cert_pem.encode()
    key_bytes = key_pem.encode()

    # Validate pair
    is_valid, error = cert_manager.validate_cert_key_pair(cert_bytes, key_bytes)
    if not is_valid:
        return web.json_response({"error": error}, status=400)

    try:
        cert_path, key_path = cert_manager.save_uploaded_cert(
            cert_bytes, key_bytes, Config.CERTS_DIR
        )
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        return web.json_response({"error": f"Failed to save certificate: {e}"}, status=500)

    # Update .env
    env_path = str(Path(__file__).parent / ".env")
    cert_manager.update_env_ssl_paths(env_path, cert_path, key_path)
    cert_manager.update_env_value(env_path, "CERT_METHOD", "custom")

    logger.info(f"Custom certificate uploaded by user {token.user_id}")

    info = cert_manager.get_cert_info(cert_path)
    return web.json_response({
        "status": "success",
        "message": "Certificate uploaded. Click 'Apply & Restart' to activate.",
        "cert_info": info,
    })


async def http_generate_selfsigned(request: web.Request) -> web.Response:
    """POST /api/certs/self-signed - Generate a self-signed certificate."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        data = {}

    hostname = data.get("hostname", Config.HOSTNAME).strip()
    validity_days = data.get("validity_days", 365)

    if not hostname:
        return web.json_response({"error": "Hostname is required"}, status=400)

    try:
        validity_days = int(validity_days)
        if validity_days < 30 or validity_days > 3650:
            return web.json_response({"error": "Validity must be between 30 and 3650 days"}, status=400)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid validity_days"}, status=400)

    try:
        cert_path, key_path = cert_manager.generate_self_signed_cert(
            hostname, Config.CERTS_DIR, validity_days
        )
    except Exception as e:
        return web.json_response({"error": f"Failed to generate certificate: {e}"}, status=500)

    # Update .env
    env_path = str(Path(__file__).parent / ".env")
    cert_manager.update_env_ssl_paths(env_path, cert_path, key_path)
    cert_manager.update_env_value(env_path, "CERT_METHOD", "selfsigned")

    logger.info(f"Self-signed certificate generated for {hostname} by user {token.user_id}")

    info = cert_manager.get_cert_info(cert_path)
    return web.json_response({
        "status": "success",
        "message": "Self-signed certificate generated. Click 'Apply & Restart' to activate.",
        "cert_info": info,
    })


async def http_trigger_letsencrypt(request: web.Request) -> web.Response:
    """POST /api/certs/letsencrypt - Request/renew a Let's Encrypt certificate."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    hostname = data.get("hostname", Config.HOSTNAME).strip()
    email = data.get("email", "").strip()

    if not hostname:
        return web.json_response({"error": "Hostname is required"}, status=400)
    if not email:
        return web.json_response({"error": "Email is required for Let's Encrypt"}, status=400)

    logger.info(f"Let's Encrypt certificate requested for {hostname} by user {token.user_id}")

    success, message = cert_manager.request_letsencrypt_cert(hostname, email)
    if not success:
        return web.json_response({"error": message}, status=500)

    # Get cert paths and update .env
    cert_path, key_path = cert_manager.get_letsencrypt_cert_paths(hostname)
    env_path = str(Path(__file__).parent / ".env")
    cert_manager.update_env_ssl_paths(env_path, cert_path, key_path)
    cert_manager.update_env_value(env_path, "CERT_METHOD", "letsencrypt")
    cert_manager.update_env_value(env_path, "CERT_EMAIL", email)

    # Install renewal hook
    cert_manager.install_renewal_hook("portal")

    info = cert_manager.get_cert_info(cert_path)
    return web.json_response({
        "status": "success",
        "message": "Let's Encrypt certificate issued. Click 'Apply & Restart' to activate.",
        "cert_info": info,
    })


async def http_apply_certs(request: web.Request) -> web.Response:
    """POST /api/certs/apply - Graceful restart to apply new certificates."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    import subprocess as _sp

    # Validate that cert files exist before restarting
    env_path = str(Path(__file__).parent / ".env")
    # Re-read .env to get latest paths
    from dotenv import dotenv_values
    env_vals = dotenv_values(env_path)
    cert_path = env_vals.get("SSL_CERT", Config.SSL_CERT)
    key_path = env_vals.get("SSL_KEY", Config.SSL_KEY)

    if not Path(cert_path).exists():
        return web.json_response({"error": f"Certificate file not found: {cert_path}"}, status=400)
    if not Path(key_path).exists():
        return web.json_response({"error": f"Key file not found: {key_path}"}, status=400)

    # Validate the pair
    try:
        cert_data = Path(cert_path).read_bytes()
        key_data = Path(key_path).read_bytes()
        is_valid, error = cert_manager.validate_cert_key_pair(cert_data, key_data)
        if not is_valid:
            return web.json_response({"error": f"Invalid certificate pair: {error}"}, status=400)
    except Exception as e:
        return web.json_response({"error": f"Failed to validate certificates: {e}"}, status=400)

    logger.warning(f"Server restart requested by user {token.user_id} to apply new certificates")

    # Schedule restart after response is sent
    async def _restart():
        await asyncio.sleep(2)
        _sp.run(["systemctl", "restart", "portal"], capture_output=True)

    asyncio.ensure_future(_restart())

    return web.json_response({
        "status": "success",
        "message": "Server will restart in 2 seconds to apply new certificates.",
    })


async def http_get_server_hostname(request: web.Request) -> web.Response:
    """GET /api/settings/hostname - Get current hostname."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    return web.json_response({"hostname": Config.HOSTNAME, "port": Config.PORT})


async def http_update_server_hostname(request: web.Request) -> web.Response:
    """PUT /api/settings/hostname - Update server hostname."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    hostname = data.get("hostname", "").strip()
    if not hostname:
        return web.json_response({"error": "Hostname is required"}, status=400)

    # Basic validation: no spaces, no special chars except dots and hyphens
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$', hostname) and hostname != "localhost":
        return web.json_response({"error": "Invalid hostname format"}, status=400)

    env_path = str(Path(__file__).parent / ".env")
    cert_manager.update_env_value(env_path, "HOSTNAME", hostname)
    Config.HOSTNAME = hostname

    logger.info(f"Hostname updated to {hostname} by user {token.user_id}")

    return web.json_response({
        "status": "success",
        "hostname": hostname,
        "message": "Hostname updated. Restart the server for full effect.",
    })


# =============================================================================
# System Monitor (admin only)
# =============================================================================

async def http_sysmon_processes(request: web.Request) -> web.Response:
    """GET /api/sysmon/processes - List running processes."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    sort_by = request.query.get("sort", "cpu")
    try:
        limit = min(int(request.query.get("limit", "100")), 500)
    except (ValueError, TypeError):
        limit = 100

    procs = system_monitor.list_processes(sort_by=sort_by, limit=limit)
    return web.json_response(procs)


async def http_sysmon_process_detail(request: web.Request) -> web.Response:
    """GET /api/sysmon/processes/{pid} - Process details."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        pid = int(request.match_info["pid"])
    except (ValueError, KeyError):
        return web.json_response({"error": "Invalid PID"}, status=400)

    info = system_monitor.get_process_info(pid)
    if not info:
        return web.json_response({"error": "Process not found"}, status=404)
    return web.json_response(info)


async def http_sysmon_kill_process(request: web.Request) -> web.Response:
    """POST /api/sysmon/processes/{pid}/kill - Kill a process."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        pid = int(request.match_info["pid"])
    except (ValueError, KeyError):
        return web.json_response({"error": "Invalid PID"}, status=400)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        data = {}

    signal_name = data.get("signal", "SIGTERM")
    success, message = system_monitor.kill_process(pid, signal_name)
    status = 200 if success else 400
    return web.json_response({"success": success, "message": message}, status=status)


async def http_sysmon_services(request: web.Request) -> web.Response:
    """GET /api/sysmon/services - List systemd services."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    filter_str = request.query.get("filter")
    services = system_monitor.list_services(filter_str)
    return web.json_response(services)


async def http_sysmon_service_status(request: web.Request) -> web.Response:
    """GET /api/sysmon/services/{name} - Service status."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    name = request.match_info["name"]
    status = system_monitor.get_service_status(name)
    if not status:
        return web.json_response({"error": "Service not found"}, status=404)
    return web.json_response(status)


async def http_sysmon_service_logs(request: web.Request) -> web.Response:
    """GET /api/sysmon/services/{name}/logs - Service journal logs."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    name = request.match_info["name"]
    try:
        lines = int(request.query.get("lines", "50"))
    except (ValueError, TypeError):
        lines = 50

    logs = system_monitor.get_service_logs(name, lines)
    return web.json_response({"logs": logs, "service": name, "lines": lines})


async def http_sysmon_service_control(request: web.Request) -> web.Response:
    """POST /api/sysmon/services/{name}/control - Control a service."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    name = request.match_info["name"]
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    action = data.get("action", "")
    success, message = system_monitor.control_service(name, action)
    status = 200 if success else 400
    return web.json_response({"success": success, "message": message}, status=status)


async def http_sysmon_network(request: web.Request) -> web.Response:
    """GET /api/sysmon/network - Network interfaces."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    interfaces = system_monitor.get_network_interfaces()
    return web.json_response(interfaces)


async def http_sysmon_ports(request: web.Request) -> web.Response:
    """GET /api/sysmon/ports - Listening ports."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    ports = system_monitor.get_listening_ports()
    return web.json_response(ports)


# =============================================================================
# File Manager (admin only)
# =============================================================================

async def http_list_files(request: web.Request) -> web.Response:
    """GET /api/files/list - List directory contents."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    path = request.query.get("path", "/")
    try:
        entries = file_manager.list_directory(path, Config.FILE_MANAGER_ROOT)
        return web.json_response(entries)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        return web.json_response({"error": "Failed to list directory"}, status=500)


async def http_file_info(request: web.Request) -> web.Response:
    """GET /api/files/info - File info/stat."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    path = request.query.get("path", "")
    if not path:
        return web.json_response({"error": "path parameter required"}, status=400)
    try:
        info = file_manager.get_file_info(path, Config.FILE_MANAGER_ROOT)
        return web.json_response(info)
    except (ValueError, FileNotFoundError) as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_read_file(request: web.Request) -> web.Response:
    """GET /api/files/read - Read text file content."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    path = request.query.get("path", "")
    if not path:
        return web.json_response({"error": "path parameter required"}, status=400)
    try:
        content = file_manager.read_file(path, Config.FILE_MANAGER_ROOT)
        # Try to decode as text
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return web.json_response({"error": "File is not a text file"}, status=400)
        return web.json_response({"content": text, "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_download_file(request: web.Request) -> web.Response:
    """GET /api/files/download - Download file (streaming)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    path = request.query.get("path", "")
    if not path:
        return web.json_response({"error": "path parameter required"}, status=400)

    try:
        resolved = file_manager._validate_path(path, Config.FILE_MANAGER_ROOT)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)

    if not resolved.is_file():
        return web.json_response({"error": "Not a file"}, status=400)

    mime = file_manager.get_mime_type(path, Config.FILE_MANAGER_ROOT)
    filename = resolved.name

    response = web.StreamResponse()
    response.content_type = mime
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Length"] = str(resolved.stat().st_size)
    await response.prepare(request)

    with open(resolved, "rb") as f:
        while chunk := f.read(65536):
            await response.write(chunk)

    await response.write_eof()
    return response


async def http_upload_file(request: web.Request) -> web.Response:
    """POST /api/files/upload - Upload file (multipart)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    reader = await request.multipart()
    target_path = "/"
    file_data = None
    file_name = None

    async for part in reader:
        if part.name == "path":
            target_path = (await part.text()).strip()
        elif part.name == "file":
            file_name = part.filename
            file_data = await part.read(Config.FILE_MANAGER_MAX_UPLOAD)
            # Check if there's more data (file too large)
            extra = await part.read(1)
            if extra:
                return web.json_response({"error": f"File too large (max {Config.FILE_MANAGER_MAX_UPLOAD // (1024*1024)}MB)"}, status=400)

    if not file_data or not file_name:
        return web.json_response({"error": "No file provided"}, status=400)

    dest = target_path.rstrip("/") + "/" + file_name
    try:
        file_manager.write_file(dest, Config.FILE_MANAGER_ROOT, file_data)
        return web.json_response({"status": "success", "path": dest})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_write_file(request: web.Request) -> web.Response:
    """POST /api/files/write - Write/save text file."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    path = data.get("path", "")
    content = data.get("content", "")
    if not path:
        return web.json_response({"error": "path is required"}, status=400)

    try:
        file_manager.write_file(path, Config.FILE_MANAGER_ROOT, content.encode("utf-8"))
        return web.json_response({"status": "success", "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_mkdir(request: web.Request) -> web.Response:
    """POST /api/files/mkdir - Create directory."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    path = data.get("path", "")
    if not path:
        return web.json_response({"error": "path is required"}, status=400)

    try:
        file_manager.create_directory(path, Config.FILE_MANAGER_ROOT)
        return web.json_response({"status": "success", "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_rename_file(request: web.Request) -> web.Response:
    """POST /api/files/rename - Rename/move file."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    old_path = data.get("old_path", "")
    new_path = data.get("new_path", "")
    if not old_path or not new_path:
        return web.json_response({"error": "old_path and new_path are required"}, status=400)

    try:
        file_manager.rename_path(old_path, new_path, Config.FILE_MANAGER_ROOT)
        return web.json_response({"status": "success"})
    except (ValueError, FileNotFoundError) as e:
        return web.json_response({"error": str(e)}, status=400)


async def http_delete_file(request: web.Request) -> web.Response:
    """DELETE /api/files/delete - Delete file/directory."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    path = request.query.get("path", "")
    if not path:
        return web.json_response({"error": "path parameter required"}, status=400)

    try:
        file_manager.delete_path(path, Config.FILE_MANAGER_ROOT)
        return web.json_response({"status": "success"})
    except (ValueError, FileNotFoundError) as e:
        return web.json_response({"error": str(e)}, status=400)


# =============================================================================
# SFTP Browser (per-user, connection ownership checked)
# =============================================================================

async def _get_vod_sftp(request: web.Request, token: TokenPayload):
    """Helper: connect to user's VOD SFTP storage. Returns (conn, sftp, error_response)."""
    conn, sftp, error = await _connect_vod_sftp(token.user_id)
    if error:
        return None, None, web.json_response({"error": error}, status=502)
    return conn, sftp, None


async def http_sftp_vod_list(request: web.Request) -> web.Response:
    """GET /api/sftp/vod/list - List VOD storage directory."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        path = request.query.get("path", "/")
        entries = await sftp_browser.list_remote_directory(sftp, path)
        return web.json_response(entries)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_read(request: web.Request) -> web.Response:
    """GET /api/sftp/vod/read - Read file from VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        path = request.query.get("path")
        if not path:
            return web.json_response({"error": "path required"}, status=400)
        content = await sftp_browser.read_remote_file(sftp, path)
        return web.json_response({"path": path, "content": content.decode("utf-8", errors="replace")})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_download(request: web.Request) -> web.Response:
    """GET /api/sftp/vod/download - Download file from VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        path = request.query.get("path")
        if not path:
            return web.json_response({"error": "path required"}, status=400)
        content = await sftp_browser.read_remote_file(sftp, path, max_size=100 * 1024 * 1024)
        filename = path.split("/")[-1]
        return web.Response(
            body=content,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/octet-stream",
            }
        )
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_mkdir(request: web.Request) -> web.Response:
    """POST /api/sftp/vod/mkdir - Create directory on VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        data = await request.json()
        path = data.get("path")
        if not path:
            return web.json_response({"error": "path required"}, status=400)
        await sftp_browser.create_remote_directory(sftp, path)
        return web.json_response({"status": "created", "path": path})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_delete(request: web.Request) -> web.Response:
    """DELETE /api/sftp/vod/delete - Delete file/dir on VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        path = request.query.get("path")
        if not path:
            return web.json_response({"error": "path required"}, status=400)
        await sftp_browser.delete_remote_path(sftp, path)
        return web.json_response({"status": "deleted"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_upload(request: web.Request) -> web.Response:
    """POST /api/sftp/vod/upload - Upload file to VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        reader = await request.multipart()
        target_path = "/"
        file_data = None
        file_name = None

        async for part in reader:
            if part.name == "path":
                target_path = (await part.text()).strip()
            elif part.name == "file":
                file_name = part.filename
                file_data = await part.read(Config.FILE_MANAGER_MAX_UPLOAD)

        if not file_data or not file_name:
            return web.json_response({"error": "No file provided"}, status=400)

        dest = target_path.rstrip("/") + "/" + file_name
        await sftp_browser.write_remote_file(sftp, dest, file_data)
        return web.json_response({"status": "success", "path": dest})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_write(request: web.Request) -> web.Response:
    """POST /api/sftp/vod/write - Write text file to VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        ssh_conn.close()
        return web.json_response({"error": "Invalid JSON"}, status=400)

    path = data.get("path", "")
    content = data.get("content", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path is required"}, status=400)

    try:
        await sftp_browser.write_remote_file(sftp, path, content.encode("utf-8"))
        return web.json_response({"status": "success", "path": path})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def http_sftp_vod_rename(request: web.Request) -> web.Response:
    """POST /api/sftp/vod/rename - Rename path on VOD storage."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_vod_sftp(request, token)
    if err:
        return err
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        ssh_conn.close()
        return web.json_response({"error": "Invalid JSON"}, status=400)

    old_path = data.get("old_path", "")
    new_path = data.get("new_path", "")
    if not old_path or not new_path:
        ssh_conn.close()
        return web.json_response({"error": "old_path and new_path are required"}, status=400)

    try:
        await sftp_browser.rename_remote_path(sftp, old_path, new_path)
        return web.json_response({"status": "success"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    finally:
        ssh_conn.close()


async def _get_sftp_connection(request: web.Request, token: TokenPayload):
    """Helper: get user connection and establish SFTP. Returns (conn, sftp, error_response)."""
    try:
        conn_id = int(request.match_info["conn_id"])
    except (ValueError, KeyError):
        return None, None, web.json_response({"error": "Invalid connection ID"}, status=400)

    connection = await db.get_user_connection(conn_id, token.user_id)
    if not connection:
        return None, None, web.json_response({"error": "Connection not found"}, status=404)

    if connection.get("connection_type") not in sftp_browser.SFTP_ELIGIBLE_TYPES:
        return None, None, web.json_response({"error": "Connection is not SSH/SFTP type"}, status=400)

    ssh_conn, sftp_client, error = await sftp_browser.connect_sftp(connection)
    if error:
        return None, None, web.json_response({"error": error}, status=502)

    return ssh_conn, sftp_client, None


async def http_sftp_list(request: web.Request) -> web.Response:
    """GET /api/sftp/{conn_id}/list - List remote directory."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    path = request.query.get("path", "/")
    try:
        entries = await sftp_browser.list_remote_directory(sftp, path)
        return web.json_response(entries)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_read(request: web.Request) -> web.Response:
    """GET /api/sftp/{conn_id}/read - Read remote text file."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    path = request.query.get("path", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path parameter required"}, status=400)

    try:
        content = await sftp_browser.read_remote_file(sftp, path)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return web.json_response({"error": "File is not a text file"}, status=400)
        return web.json_response({"content": text, "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_download(request: web.Request) -> web.Response:
    """GET /api/sftp/{conn_id}/download - Download remote file."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    path = request.query.get("path", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path parameter required"}, status=400)

    try:
        content = await sftp_browser.read_remote_file(sftp, path, max_size=100 * 1024 * 1024)
        filename = path.rsplit("/", 1)[-1] or "download"
        response = web.Response(body=content)
        response.content_type = "application/octet-stream"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_upload(request: web.Request) -> web.Response:
    """POST /api/sftp/{conn_id}/upload - Upload to remote."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    try:
        reader = await request.multipart()
        target_path = "/"
        file_data = None
        file_name = None

        async for part in reader:
            if part.name == "path":
                target_path = (await part.text()).strip()
            elif part.name == "file":
                file_name = part.filename
                file_data = await part.read(Config.FILE_MANAGER_MAX_UPLOAD)

        if not file_data or not file_name:
            return web.json_response({"error": "No file provided"}, status=400)

        dest = target_path.rstrip("/") + "/" + file_name
        await sftp_browser.write_remote_file(sftp, dest, file_data)
        return web.json_response({"status": "success", "path": dest})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_write(request: web.Request) -> web.Response:
    """POST /api/sftp/{conn_id}/write - Write remote text file."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        ssh_conn.close()
        return web.json_response({"error": "Invalid JSON"}, status=400)

    path = data.get("path", "")
    content = data.get("content", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path is required"}, status=400)

    try:
        await sftp_browser.write_remote_file(sftp, path, content.encode("utf-8"))
        return web.json_response({"status": "success", "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_mkdir(request: web.Request) -> web.Response:
    """POST /api/sftp/{conn_id}/mkdir - Create remote directory."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        ssh_conn.close()
        return web.json_response({"error": "Invalid JSON"}, status=400)

    path = data.get("path", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path is required"}, status=400)

    try:
        await sftp_browser.create_remote_directory(sftp, path)
        return web.json_response({"status": "success", "path": path})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_rename(request: web.Request) -> web.Response:
    """POST /api/sftp/{conn_id}/rename - Rename remote path."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        ssh_conn.close()
        return web.json_response({"error": "Invalid JSON"}, status=400)

    old_path = data.get("old_path", "")
    new_path = data.get("new_path", "")
    if not old_path or not new_path:
        ssh_conn.close()
        return web.json_response({"error": "old_path and new_path are required"}, status=400)

    try:
        await sftp_browser.rename_remote_path(sftp, old_path, new_path)
        return web.json_response({"status": "success"})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_sftp_delete(request: web.Request) -> web.Response:
    """DELETE /api/sftp/{conn_id}/delete - Delete remote path."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ssh_conn, sftp, err = await _get_sftp_connection(request, token)
    if err:
        return err

    path = request.query.get("path", "")
    if not path:
        ssh_conn.close()
        return web.json_response({"error": "path parameter required"}, status=400)

    try:
        await sftp_browser.delete_remote_path(sftp, path)
        return web.json_response({"status": "success"})
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    finally:
        ssh_conn.close()


async def http_activity_feed(request: web.Request) -> web.Response:
    """Get recent activity feed. Admins see all; regular users see their own."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        limit = min(int(request.query.get("limit", "20")), 50)
        offset = max(int(request.query.get("offset", "0")), 0)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit or offset parameter"}, status=400)
    is_admin = token.has_scope("admin") or token.has_scope("*")

    if is_admin:
        activities = await db.get_recent_activity(limit=limit, offset=offset)
    else:
        activities = await db.get_recent_activity(limit=limit, offset=offset, user_id=token.user_id)

    return web.json_response({"activities": activities})


async def http_list_shells(request: web.Request) -> web.Response:
    """List available shells on the server (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    if not token.has_scope("admin") and not token.has_scope("*"):
        return web.json_response({"error": "Admin access required"}, status=403)

    shells = []
    try:
        with open("/etc/shells") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and os.path.isfile(line) and os.access(line, os.X_OK):
                    shells.append({
                        "path": line,
                        "name": os.path.basename(line),
                    })
    except FileNotFoundError:
        pass

    # Deduplicate by name, preferring /usr/bin paths
    seen = {}
    for s in shells:
        name = s["name"]
        if name not in seen or s["path"].startswith("/usr/bin"):
            seen[name] = s
    shells = sorted(seen.values(), key=lambda s: s["name"])

    return web.json_response({"shells": shells})


async def http_list_plugins(request: web.Request) -> web.Response:
    """List available plugins with their configuration schemas."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    from plugins import get_all_plugins

    plugins = get_all_plugins()
    return web.json_response({
        "plugins": [
            {
                "name": p.info.name,
                "display_name": p.info.display_name,
                "description": p.info.description,
                "version": p.info.version,
                "icon": p.info.icon,
                "protocols": p.info.protocols,
                "config_schema": p.info.config_schema,
            }
            for p in plugins.values()
        ]
    })


async def http_get_tunnel_sessions(request: web.Request) -> web.Response:
    """Get active tunnel sessions (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # Get secure tunnel plugin sessions
    secure_tunnel = get_plugin("secure_tunnel")
    secure_sessions = []
    if secure_tunnel and hasattr(secure_tunnel, "get_active_sessions"):
        secure_sessions = secure_tunnel.get_active_sessions()

    # Get TCP tunnel plugin connections
    tcp_tunnel = get_plugin("tcp_tunnel")
    tcp_connections = []
    if tcp_tunnel and hasattr(tcp_tunnel, "get_active_connections"):
        tcp_connections = tcp_tunnel.get_active_connections()

    return web.json_response({
        "secure_tunnel_sessions": secure_sessions,
        "tcp_tunnel_connections": tcp_connections,
        "active_websockets": len(active_connections)
    })


async def http_service_health(request: web.Request) -> web.Response:
    """Check health of a specific service."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service = await db.get_service_by_id(int(service_id))
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    # Check authorization
    if not token.has_scope("admin") and not token.has_scope("*"):
        if not check_service_authorization(service, token):
            return web.json_response({"error": "Access denied"}, status=403)

    # Get plugin and run health check
    plugin_name = service.get("plugin", "tcp_tunnel")
    plugin = get_plugin(plugin_name)

    if not plugin:
        return web.json_response({
            "healthy": False,
            "message": f"Plugin not found: {plugin_name}"
        })

    from plugins.base import ServiceTarget
    target = ServiceTarget(
        id=service["id"],
        name=service["name"],
        plugin=plugin_name,
        host=service.get("host", ""),
        port=service.get("port", 0),
        config=service.get("config", {})
    )

    health = await plugin.health_check(target)
    return web.json_response(health)


# =============================================================================
# Managed Services API (Server Processes Portal Runs)
# =============================================================================

# Global service manager reference (initialized in PortalServer.start)
_service_manager: Optional[ServiceManager] = None


async def http_list_managed_services(request: web.Request) -> web.Response:
    """List all managed services."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    services = _service_manager.get_all_services()
    return web.json_response({
        "managed_services": [svc.get_status() for svc in services]
    })


async def http_get_managed_service_types(request: web.Request) -> web.Response:
    """Get available managed service types."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    types = get_available_service_types()
    return web.json_response({
        "types": {
            name: {
                "name": info.name,
                "display_name": info.display_name,
                "description": info.description,
                "version": info.version,
                "icon": info.icon,
                "default_port": info.default_port,
                "config_schema": info.config_schema
            }
            for name, info in types.items()
        }
    })


async def http_create_managed_service(request: web.Request) -> web.Response:
    """Create a new managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name")
    service_type = data.get("type")

    if not name or not service_type:
        return web.json_response({"error": "name and type required"}, status=400)

    # Check service type exists
    if service_type not in get_available_service_types():
        return web.json_response({
            "error": f"Unknown service type: {service_type}",
            "available_types": list(get_available_service_types().keys())
        }, status=400)

    try:
        service = await _service_manager.create_service(
            name=name,
            service_type=service_type,
            display_name=data.get("display_name"),
            description=data.get("description"),
            config=data.get("config", {}),
            port=data.get("port"),
            enabled=data.get("enabled", False)
        )

        if not service:
            return web.json_response({"error": "Failed to create service"}, status=500)

        logger.info(f"Managed service '{name}' created by user {token.user_id}")
        return web.json_response({
            "service": service.get_status(),
            "message": "Service created successfully"
        }, status=201)

    except Exception as e:
        logger.error(f"Error creating managed service: {e}")
        return web.json_response({"error": safe_error_message(e)}, status=500)


async def http_get_managed_service(request: web.Request) -> web.Response:
    """Get a managed service by ID."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service = await _service_manager.get_service(int(service_id))
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    status = await _service_manager.get_service_status(int(service_id))
    return web.json_response({"service": status})


async def http_update_managed_service(request: web.Request) -> web.Response:
    """Update a managed service configuration (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    service_id = int(service_id)
    service = await _service_manager.get_service(service_id)
    if not service:
        return web.json_response({"error": "Service not found"}, status=404)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Update config if provided
    if "config" in data:
        success, error = await _service_manager.update_service_config(service_id, data["config"])
        if not success:
            return web.json_response({"error": error}, status=400)

    # Update enabled status if provided
    if "enabled" in data:
        if data["enabled"]:
            await _service_manager.enable_service(service_id)
        else:
            await _service_manager.disable_service(service_id)

    logger.info(f"Managed service {service_id} updated by user {token.user_id}")
    status = await _service_manager.get_service_status(service_id)
    return web.json_response({"service": status, "message": "Service updated"})


async def http_delete_managed_service(request: web.Request) -> web.Response:
    """Delete a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    if await _service_manager.delete_service(int(service_id)):
        logger.info(f"Managed service {service_id} deleted by user {token.user_id}")
        return web.json_response({"success": True, "message": "Service deleted"})
    else:
        return web.json_response({"error": "Service not found"}, status=404)


async def http_start_managed_service(request: web.Request) -> web.Response:
    """Start a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    success, error = await _service_manager.start_service(int(service_id))
    if success:
        logger.info(f"Managed service {service_id} started by user {token.user_id}")
        status = await _service_manager.get_service_status(int(service_id))
        return web.json_response({"success": True, "service": status})
    else:
        return web.json_response({"error": error}, status=400)


async def http_stop_managed_service(request: web.Request) -> web.Response:
    """Stop a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    success, error = await _service_manager.stop_service(int(service_id))
    if success:
        logger.info(f"Managed service {service_id} stopped by user {token.user_id}")
        status = await _service_manager.get_service_status(int(service_id))
        return web.json_response({"success": True, "service": status})
    else:
        return web.json_response({"error": error}, status=400)


async def http_restart_managed_service(request: web.Request) -> web.Response:
    """Restart a managed service (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    success, error = await _service_manager.restart_service(int(service_id))
    if success:
        logger.info(f"Managed service {service_id} restarted by user {token.user_id}")
        status = await _service_manager.get_service_status(int(service_id))
        return web.json_response({"success": True, "service": status})
    else:
        return web.json_response({"error": error}, status=400)


async def http_managed_service_status(request: web.Request) -> web.Response:
    """Get status of a managed service."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    status = await _service_manager.get_service_status(int(service_id))
    if not status:
        return web.json_response({"error": "Service not found"}, status=404)

    return web.json_response({"status": status})


async def http_managed_service_logs(request: web.Request) -> web.Response:
    """Get logs for a managed service."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not _service_manager:
        return web.json_response({"error": "Service manager not initialized"}, status=503)

    service_id = request.match_info.get("id")
    if not service_id or not service_id.isdigit():
        return web.json_response({"error": "Invalid service ID"}, status=400)

    # Parse query params
    try:
        limit = int(request.query.get("limit", 100))
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit parameter"}, status=400)
    level = request.query.get("level")

    logs = await _service_manager.get_service_logs(int(service_id), limit, level)
    return web.json_response({"logs": logs})


# =============================================================================
# Root Redirect Handler
# =============================================================================

async def http_root_redirect(request: web.Request) -> web.Response:
    """Redirect root path to dashboard or login based on auth status."""
    # Check if this is a WebSocket upgrade request
    # Connection header can contain multiple values like "keep-alive, Upgrade"
    upgrade_header = request.headers.get("Upgrade", "").lower()
    connection_header = request.headers.get("Connection", "").lower()

    if upgrade_header == "websocket" or "upgrade" in connection_header:
        # WebSocket request - delegate to websocket_handler
        return await websocket_handler(request)

    # HTTP request - redirect based on auth status
    token = await authenticate_request(request)
    if token:
        raise web.HTTPFound("/dashboard")
    else:
        raise web.HTTPFound("/login")


# =============================================================================
# WebSocket Handler
# =============================================================================

# Service ID constants for non-service connections
SERVICE_ID_TERMINAL = -1
SERVICE_ID_CHAT = -2


class MetricsWebSocket:
    """Transparent wrapper around WebSocketResponse that records traffic metrics."""

    def __init__(self, ws: web.WebSocketResponse, conn_id: str):
        self._ws = ws
        self._conn_id = conn_id

    @property
    def conn_id(self) -> str:
        return self._conn_id

    async def send_str(self, data: str, compress=None):
        traffic_metrics.record_traffic(self._conn_id, bytes_sent=len(data.encode('utf-8')))
        return await self._ws.send_str(data, compress=compress)

    async def send_bytes(self, data: bytes, compress=None):
        traffic_metrics.record_traffic(self._conn_id, bytes_sent=len(data))
        return await self._ws.send_bytes(data, compress=compress)

    async def send_json(self, data, compress=None, *, dumps=json.dumps):
        serialized = dumps(data)
        traffic_metrics.record_traffic(self._conn_id, bytes_sent=len(serialized.encode('utf-8')))
        return await self._ws.send_json(data, compress=compress, dumps=dumps)

    async def receive(self, timeout=None):
        msg = await self._ws.receive(timeout=timeout)
        if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
            byte_len = len(msg.data) if isinstance(msg.data, bytes) else len(msg.data.encode('utf-8'))
            traffic_metrics.record_traffic(self._conn_id, bytes_received=byte_len)
        return msg

    def __aiter__(self):
        return self._MetricsIter(self._ws.__aiter__(), self._conn_id)

    class _MetricsIter:
        def __init__(self, inner, conn_id):
            self._inner = inner
            self._conn_id = conn_id

        def __aiter__(self):
            return self

        async def __anext__(self):
            msg = await self._inner.__anext__()
            if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
                byte_len = len(msg.data) if isinstance(msg.data, bytes) else len(msg.data.encode('utf-8'))
                traffic_metrics.record_traffic(self._conn_id, bytes_received=byte_len)
            return msg

    def __getattr__(self, name):
        return getattr(self._ws, name)


async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    """Handle WebSocket connections for relay and ping."""
    client_ip = get_client_ip(request)
    path = request.path

    # Check if this is a WebSocket upgrade request
    # Connection header can contain multiple values like "keep-alive, Upgrade"
    upgrade_header = request.headers.get("Upgrade", "").lower()
    connection_header = request.headers.get("Connection", "").lower()
    is_websocket = (upgrade_header == "websocket" or "upgrade" in connection_header)

    # Rate limiting
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        if is_websocket:
            return web.Response(status=429, text="Rate limit exceeded")
        return web.Response(
            status=429,
            text=load_static_file("rate_limited.html") if (STATIC_DIR / "rate_limited.html").exists()
                 else "Rate limit exceeded",
            content_type="text/html"
        )

    # Authenticate
    token = await authenticate_request(request)
    if not token:
        logger.warning(f"Unauthenticated request from {client_ip} to {path}")
        if is_websocket:
            return web.Response(status=401, text="Unauthorized")
        # Serve HTML page for browser requests
        return web.Response(
            status=401,
            text=load_static_file("unauthorized.html"),
            content_type="text/html"
        )

    logger.info(f"WebSocket connection from {client_ip} (user {token.user_id}) to {path}")
    logger.debug(f"WebSocket headers: {dict(request.headers)}")

    # Create WebSocket response
    ws = web.WebSocketResponse(heartbeat=30)
    try:
        await ws.prepare(request)
        logger.debug(f"WebSocket prepared for {path}")
    except Exception as e:
        logger.error(f"Failed to prepare WebSocket for {path}: {e}")
        return web.Response(status=500, text="WebSocket preparation failed")

    active_connections.add(ws)
    _online_users[token.user_id] = _online_users.get(token.user_id, 0) + 1

    # Determine connection type for metrics
    if path == "/ws/terminal/local":
        _plugin = "terminal"
    elif "/terminal/" in path:
        _plugin = "terminal"
    elif "/vnc/" in path:
        _plugin = "vnc"
    elif "/spice/" in path:
        _plugin = "spice"
    elif "/proxmox/" in path:
        _plugin = "proxmox"
    elif "/media/" in path:
        _plugin = "mediamtx"
    elif "/user-connection/" in path:
        _plugin = "user_connection"
    else:
        _plugin = "websocket"

    conn_id = str(uuid.uuid4())
    traffic_metrics.start_connection(conn_id, 0, token.user_id, _plugin, client_ip)
    mws = MetricsWebSocket(ws, conn_id)

    try:
        if path == "/" or path == "/ws":
            await handle_ping_ws(mws, token)
        elif path == "/ws/terminal/local":
            await handle_local_terminal_ws(mws, token, client_ip)
        elif path.startswith("/ws/user-connection/"):
            await handle_user_connection_ws(mws, path, token, client_ip)
        else:
            await handle_relay_ws(mws, path, token, client_ip)
    finally:
        active_connections.discard(ws)
        metrics = traffic_metrics.end_connection(conn_id)
        # Persist session to database for real services (service_id > 0)
        if metrics and metrics.service_id > 0:
            try:
                session_id = await db.create_session(token.user_id, metrics.service_id, client_ip)
                await db.end_session(session_id, metrics.bytes_sent, metrics.bytes_received)
            except Exception as e:
                logger.debug(f"Failed to persist session: {e}")
        count = _online_users.get(token.user_id, 1) - 1
        if count <= 0:
            _online_users.pop(token.user_id, None)
        else:
            _online_users[token.user_id] = count
        logger.info(f"WebSocket closed for user {token.user_id} from {client_ip}")

    return ws


async def handle_ping_ws(ws: web.WebSocketResponse, token: TokenPayload) -> None:
    """Handle ping/echo WebSocket connections."""
    await ws.send_json({
        "type": "connected",
        "user_id": token.user_id,
        "scopes": token.scopes,
        "message": "Open Relay Portal connected"
    })

    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            try:
                data = json.loads(msg.data)
                if data.get("type") == "ping":
                    await ws.send_json({
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                else:
                    await ws.send_json({
                        "type": "echo",
                        "data": data
                    })
            except json.JSONDecodeError:
                await ws.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
        elif msg.type == WSMsgType.ERROR:
            logger.error(f"WebSocket error: {ws.exception()}")
            break


async def handle_local_terminal_ws(
    ws: web.WebSocketResponse,
    token: TokenPayload,
    client_ip: str
) -> None:
    """Handle local server terminal WebSocket (admin only)."""
    # Check admin access
    if not token.has_scope("admin") and not token.has_scope("*"):
        logger.warning(f"Non-admin user {token.user_id} attempted local terminal access from {client_ip}")
        await ws.send_json({"type": "error", "message": "Admin access required"})
        await ws.close(code=4003, message=b"Forbidden")
        return

    # Get terminal plugin
    plugin = get_plugin("terminal")
    if not plugin:
        logger.error("Terminal plugin not found for local terminal")
        await ws.send_json({"type": "error", "message": "Terminal plugin not available"})
        await ws.close(code=4005, message=b"Plugin not found")
        return

    # Support shell selection via query parameter
    requested_shell = ws._req.query.get("shell", "") if hasattr(ws, '_req') else ""
    if requested_shell and requested_shell in ALLOWED_SHELLS and os.path.isfile(requested_shell):
        shell = requested_shell
    else:
        shell = "/bin/bash"

    # Create a virtual target for local terminal
    target = ServiceTarget(
        id="local",
        name="Server Terminal",
        plugin="terminal",
        host="localhost",
        port=0,
        config={"shell": shell}
    )

    logger.info(f"Local terminal session started for user {token.user_id} from {client_ip}")
    if hasattr(ws, 'conn_id'):
        traffic_metrics.update_service_id(ws.conn_id, SERVICE_ID_TERMINAL)

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"Local terminal error for user {token.user_id}: {e}")
        traffic_metrics.record_error(SERVICE_ID_TERMINAL)
        if not ws.closed:
            await ws.send_json({"type": "error", "message": f"Terminal error: {type(e).__name__}"})
            await ws.close(code=4500, message=b"Terminal error")


async def handle_user_connection_ws(
    ws: web.WebSocketResponse,
    path: str,
    token: TokenPayload,
    client_ip: str
) -> None:
    """Handle WebSocket for user-defined connections using plugin system."""
    # Extract connection ID from path
    match = re.match(r"^/ws/user-connection/(\d+)$", path)
    if not match:
        await ws.send_json({"type": "error", "message": "Invalid connection path"})
        await ws.close(code=4004, message=b"Invalid path")
        return

    conn_id = int(match.group(1))

    # Fetch connection (ensures user owns it)
    connection = await db.get_user_connection(conn_id, token.user_id)
    if not connection:
        logger.warning(f"User {token.user_id} tried to access non-existent connection {conn_id}")
        await ws.send_json({"type": "error", "message": "Connection not found"})
        await ws.close(code=4004, message=b"Connection not found")
        return

    # Record connection usage
    await db.record_connection_usage(conn_id, token.user_id)

    conn_type = connection.get("type", "custom")
    config = connection.get("config", {})
    if isinstance(config, str):
        try:
            config = json.loads(config) if config else {}
        except json.JSONDecodeError:
            config = {}

    # Get plugin from CONNECTION_TYPES mapping
    type_info = CONNECTION_TYPES.get(conn_type, {"plugin": "tcp_tunnel"})
    plugin_name = type_info.get("plugin", "tcp_tunnel")

    # Ensure host/port are in config for plugins that need them
    config["host"] = connection.get("host")
    config["port"] = connection.get("port") or type_info.get("default_port")

    # Plugin-specific adjustments
    if plugin_name == "ssh":
        # SSH: set known_hosts to ignore for user connections
        config.setdefault("known_hosts", "ignore")
        if config.get("auth_method") == "key" and config.get("private_key"):
            logger.info(f"Using SSH key auth for connection {conn_id}")
        elif not config.get("auth_method"):
            config["auth_method"] = "password"
        # Allow shell override from query parameter (validated against whitelist)
        shell_override = ws._req.query.get("shell", "") if hasattr(ws, "_req") else ""
        if shell_override and shell_override in ALLOWED_SHELLS:
            config["shell"] = shell_override
    elif plugin_name == "http_proxy":
        # HTTP proxy: build target_url if not set
        if not config.get("target_url"):
            scheme = "https" if conn_type == "https" else "http"
            port = config.get("port") or (443 if conn_type == "https" else 80)
            config["target_url"] = f"{scheme}://{config['host']}:{port}"

    # Get the plugin
    plugin = get_plugin(plugin_name)
    if not plugin:
        logger.error(f"Plugin not found: {plugin_name} for user connection {conn_id}")
        await ws.send_json({"type": "error", "message": f"Plugin not found: {plugin_name}"})
        await ws.close(code=4005, message=b"Plugin not found")
        return

    # Create ServiceTarget
    target = ServiceTarget(
        id=f"user-conn-{conn_id}",
        name=connection.get("name", f"Connection {conn_id}"),
        plugin=plugin_name,
        host=connection.get("host", ""),
        port=connection.get("port") or type_info.get("default_port") or 0,
        config=config
    )

    logger.info(f"User connection {conn_id} ({conn_type}) for user {token.user_id} via {plugin_name}")
    if hasattr(ws, 'conn_id'):
        traffic_metrics.update_service_id(ws.conn_id, -conn_id)

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"User connection {conn_id} error: {e}")
        traffic_metrics.record_error(-conn_id)
        if not ws.closed:
            await ws.send_json({"type": "error", "message": f"Connection error: {type(e).__name__}"})
            await ws.close(code=4500, message=b"Connection error")


async def handle_relay_ws(
    ws: web.WebSocketResponse,
    path: str,
    token: TokenPayload,
    client_ip: str
) -> None:
    """Handle WebSocket relay to internal services via plugins."""
    logger.debug(f"handle_relay_ws called with path: {path}")

    # Check for /ws/terminal/{id}, /ws/vnc/{id}, /ws/media/{id}, /ws/spice/{id}, /ws/proxmox/{id} patterns
    service = None
    terminal_match = re.match(r"^/ws/terminal/(\d+)$", path)
    vnc_match = re.match(r"^/ws/vnc/(\d+)$", path)
    media_match = re.match(r"^/ws/media/(\d+)$", path)
    spice_match = re.match(r"^/ws/spice/(\d+)$", path)
    proxmox_match = re.match(r"^/ws/proxmox/(\d+)$", path)

    if terminal_match or vnc_match or media_match or spice_match or proxmox_match:
        match = terminal_match or vnc_match or media_match or spice_match or proxmox_match
        service_id = int(match.group(1))
        logger.debug(f"Looking up service by ID: {service_id}")
        service = await db.get_service_by_id(service_id)
        logger.debug(f"Service lookup result: {service}")
    else:
        # Find matching service by path
        logger.debug(f"Looking up service by path: {path}")
        service = await get_service_for_path(path)

    if not service:
        # No service found — check if this ID matches a user connection instead.
        # This handles cases where the browser connects to /ws/terminal/{id} but
        # the ID is actually a user connection (not a service).
        match = terminal_match or vnc_match or media_match or spice_match or proxmox_match
        if match:
            conn_id = int(match.group(1))
            user_conn = await db.get_user_connection(conn_id, token.user_id)
            if user_conn:
                logger.info(f"Redirecting /ws path to user connection {conn_id} for user {token.user_id}")
                await handle_user_connection_ws(ws, f"/ws/user-connection/{conn_id}", token, client_ip)
                return

        logger.warning(f"No service found for path: {path}")
        await ws.send_json({"type": "error", "message": "Service not found"})
        await ws.close(code=4004, message=b"Service not found")
        return

    # Check authorization
    if not check_service_authorization(service, token):
        logger.warning(
            f"Unauthorized access to {service['name']} by user {token.user_id}"
        )
        await ws.send_json({"type": "error", "message": "Forbidden - insufficient scopes"})
        await ws.close(code=4003, message=b"Forbidden")
        return

    # Get plugin for this service
    plugin_name = service.get("plugin", "tcp_tunnel")
    plugin = get_plugin(plugin_name)

    if not plugin:
        logger.error(f"Plugin not found: {plugin_name} for service {service['name']}")
        await ws.send_json({"type": "error", "message": f"Plugin not found: {plugin_name}"})
        await ws.close(code=4005, message=b"Plugin not found")
        return

    # Create ServiceTarget from service data
    target = ServiceTarget(
        id=service["id"],
        name=service["name"],
        plugin=plugin_name,
        host=service.get("host", ""),
        port=service.get("port", 0),
        config=service.get("config", {})
    )

    logger.info(f"Routing {service['name']} via {plugin_name} plugin for user {token.user_id}")
    if hasattr(ws, 'conn_id'):
        traffic_metrics.update_service_id(ws.conn_id, service["id"])

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"Plugin {plugin_name} error for {service['name']}: {e}")
        traffic_metrics.record_error(service["id"])
        if not ws.closed:
            await ws.send_json({
                "type": "error",
                "message": f"Service error: {type(e).__name__}"
            })
            await ws.close(code=4500, message=b"Service error")


async def relay_client_to_upstream(
    client_ws: web.WebSocketResponse,
    upstream_ws: aiohttp.ClientWebSocketResponse
) -> None:
    """Forward messages from client to upstream."""
    try:
        async for msg in client_ws:
            if msg.type == WSMsgType.TEXT:
                await upstream_ws.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await upstream_ws.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    except Exception as e:
        logger.debug(f"Client to upstream relay ended: {e}")


async def relay_upstream_to_client(
    client_ws: web.WebSocketResponse,
    upstream_ws: aiohttp.ClientWebSocketResponse
) -> None:
    """Forward messages from upstream to client."""
    try:
        async for msg in upstream_ws:
            if msg.type == WSMsgType.TEXT:
                await client_ws.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await client_ws.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    except Exception as e:
        logger.debug(f"Upstream to client relay ended: {e}")


async def get_service_for_path(path: str) -> Optional[dict]:
    """Find a service matching the given path."""
    if not path.startswith("/"):
        path = "/" + path

    # Try exact match
    service = await db.get_service_by_path(path)
    if service:
        return service

    # Try prefix match
    parts = path.split("/")
    for i in range(len(parts) - 1, 0, -1):
        prefix = "/".join(parts[:i])
        if prefix:
            service = await db.get_service_by_path(prefix)
            if service:
                return service

    return None


def check_service_authorization(service: dict, token: TokenPayload) -> bool:
    """Check if token is authorized for service."""
    required_scopes = service.get("required_scopes", [])
    if not required_scopes:
        return True
    return token.has_any_scope(required_scopes)


# =============================================================================
# Web UI Endpoints
# =============================================================================

async def http_login_page(request: web.Request) -> web.Response:
    """Serve login page."""
    # If already authenticated, redirect to dashboard
    token = await authenticate_request(request)
    if token:
        raise web.HTTPFound("/dashboard")

    return web.Response(
        text=load_static_file("login.html"),
        content_type="text/html"
    )


async def http_login_submit(request: web.Request) -> web.Response:
    """Handle login form submission with optional 2FA support."""
    client_ip = get_client_ip(request)

    if not check_rate_limit(client_ip):
        return web.json_response({"error": "Rate limit exceeded"}, status=429)

    # Handle both form data and JSON
    content_type = request.content_type
    if "application/json" in content_type:
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
    else:
        data = await request.post()

    username = data.get("username")
    password = data.get("password")
    totp_code = data.get("totp_code")  # Optional 2FA code

    if not username or not password:
        if "application/json" in content_type:
            return web.json_response({"error": "Username and password required"}, status=400)
        return web.Response(
            status=401,
            text=load_static_file("login.html"),
            content_type="text/html"
        )

    user = await authenticate_user(username, password)
    if not user:
        logger.warning(f"Failed web login for '{username}' from {client_ip}")
        if "application/json" in content_type:
            return web.json_response({"error": "Invalid credentials"}, status=401)
        return web.Response(
            status=401,
            text=load_static_file("login.html"),
            content_type="text/html"
        )

    # Check if 2FA is enabled for this user
    if user.get("totp_enabled"):
        if not totp_code:
            # 2FA required but not provided - request it
            logger.info(f"2FA required for user '{username}' from {client_ip}")
            return web.json_response({
                "status": "2fa_required",
                "message": "Two-factor authentication required"
            }, status=200)

        # Verify TOTP code
        if not verify_totp(user.get("totp_secret"), totp_code):
            # Try backup code
            if not await db.use_backup_code(user["id"], totp_code):
                logger.warning(f"Failed 2FA for user '{username}' from {client_ip}")
                return web.json_response({"error": "Invalid 2FA code"}, status=401)
            logger.info(f"Backup code used for user '{username}' from {client_ip}")
        else:
            logger.info(f"2FA verified for user '{username}' from {client_ip}")

    # Create session token
    scopes = ["*"] if user["is_admin"] else ["services:read", "access:*"]
    jwt_token, _ = await create_access_token(
        user_id=user["id"],
        scopes=scopes,
        name="web_session",
        expires_in_hours=Config.SESSION_COOKIE_MAX_AGE // 3600
    )

    logger.info(f"Web login for user '{username}' from {client_ip}")

    # For JSON requests, return token directly
    if "application/json" in content_type:
        response = web.json_response({
            "status": "logged_in",
            "user_id": user["id"],
            "username": user["username"]
        })
    else:
        # For form submissions, redirect to dashboard
        response = web.HTTPFound("/dashboard")

    response.set_cookie(
        Config.SESSION_COOKIE_NAME,
        jwt_token,
        max_age=Config.SESSION_COOKIE_MAX_AGE,
        secure=Config.SESSION_COOKIE_SECURE,
        httponly=Config.SESSION_COOKIE_HTTPONLY,
        samesite=Config.SESSION_COOKIE_SAMESITE,
    )

    if "application/json" not in content_type:
        raise response

    return response


async def http_logout(request: web.Request) -> web.Response:
    """Handle logout."""
    response = web.HTTPFound("/login")
    response.del_cookie(Config.SESSION_COOKIE_NAME)
    raise response


async def http_dashboard(request: web.Request) -> web.Response:
    """Serve dashboard page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    return web.Response(
        text=load_static_file("index.html"),
        content_type="text/html"
    )


async def http_terminal_page(request: web.Request) -> web.Response:
    """Serve terminal page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Handle local terminal (server shell access)
    if service_id == "local":
        # Only admins can access local terminal
        if not token.has_scope("admin") and not token.has_scope("*"):
            return web.Response(status=403, text="Admin access required for local terminal")

        # Support shell selection via query parameter
        shell = request.query.get("shell", "")
        ws_path = "/ws/terminal/local"
        if shell:
            ws_path += f"?shell={shell}"
        shell_name = os.path.basename(shell) if shell else "bash"

        html = load_static_file("terminal.html")
        html = html.replace("{{SERVICE_ID}}", "local")
        html = html.replace("{{SERVICE_NAME}}", f"Server Terminal ({shell_name})")
        html = html.replace("{{CONN_TYPE}}", "local")
        html = html.replace("{{WS_PATH}}", ws_path)
        return web.Response(text=html, content_type="text/html")

    # Check for user connection mode: /terminal/connect?connection={id}
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        conn_type = connection.get("type", "")
        # Build WS path with shell override if specified
        ws_path = f"/ws/user-connection/{conn_id}"
        shell_param = request.query.get("shell", "")
        if shell_param:
            ws_path += f"?shell={shell_param}"
        html = load_static_file("terminal.html")
        html = html.replace("{{SERVICE_ID}}", conn_id)
        html = html.replace("{{SERVICE_NAME}}", connection.get("name", "Terminal"))
        html = html.replace("{{CONN_TYPE}}", conn_type)
        html = html.replace("{{WS_PATH}}", ws_path)
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("terminal.html")
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Terminal"))
    html = html.replace("{{CONN_TYPE}}", service.get("plugin", ""))
    html = html.replace("{{WS_PATH}}", f"/ws/terminal/{service_id}")

    return web.Response(text=html, content_type="text/html")


async def http_vnc_page(request: web.Request) -> web.Response:
    """Serve VNC page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Check for user connection mode: /vnc/connect?connection={id}
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        html = load_static_file("vnc.html")
        html = html.replace("{{SERVICE_ID}}", conn_id)
        html = html.replace("{{SERVICE_NAME}}", connection.get("name", "VNC"))
        html = html.replace("{{WS_PATH}}", f"/ws/user-connection/{conn_id}")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("vnc.html")
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "VNC"))
    html = html.replace("{{WS_PATH}}", f"/ws/vnc/{service_id}")

    return web.Response(text=html, content_type="text/html")


async def http_media_page(request: web.Request) -> web.Response:
    """Serve media streaming page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Check for user connection mode
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        html = load_static_file("mediamtx.html")
        html = html.replace("{{SERVICE_ID}}", conn_id)
        html = html.replace("{{SERVICE_NAME}}", connection.get("name", "Media"))
        html = html.replace("{{WS_PATH}}", f"/ws/user-connection/{conn_id}")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("mediamtx.html")
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Media"))
    html = html.replace("{{WS_PATH}}", f"/ws/media/{service_id}")

    return web.Response(text=html, content_type="text/html")


async def http_spice_page(request: web.Request) -> web.Response:
    """Serve SPICE console page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Check for user connection mode: /spice/connect?connection={id}
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        html = load_static_file("spice.html")
        html = html.replace("{{SERVICE_ID}}", conn_id)
        html = html.replace("{{SERVICE_NAME}}", connection.get("name", "SPICE Console"))
        html = html.replace("{{WS_PATH}}", f"/ws/user-connection/{conn_id}")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("spice.html")
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "SPICE Console"))
    html = html.replace("{{WS_PATH}}", f"/ws/spice/{service_id}")

    return web.Response(text=html, content_type="text/html")


async def http_proxmox_page(request: web.Request) -> web.Response:
    """Serve Proxmox management page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Check for user connection mode
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        html = load_static_file("proxmox.html")
        html = html.replace("{{SERVICE_ID}}", conn_id)
        html = html.replace("{{SERVICE_NAME}}", connection.get("name", "Proxmox VE"))
        html = html.replace("{{WS_PATH}}", f"/ws/user-connection/{conn_id}")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("proxmox.html")
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Proxmox VE"))
    html = html.replace("{{WS_PATH}}", f"/ws/proxmox/{service_id}")

    return web.Response(text=html, content_type="text/html")


async def http_github_page(request: web.Request) -> web.Response:
    """Serve GitHub management page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Check for user connection mode
    conn_id = request.query.get("connection") if service_id == "connect" else None
    if conn_id and conn_id.isdigit():
        connection = await db.get_user_connection(int(conn_id), token.user_id)
        if not connection:
            return web.Response(status=404, text="Connection not found")
        html = load_static_file("github.html")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("github.html")
    return web.Response(text=html, content_type="text/html")


async def http_admin_page(request: web.Request) -> web.Response:
    """Serve admin panel page (admin only)."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    # Check admin access
    if not token.has_scope("admin") and not token.has_scope("*"):
        raise web.HTTPFound("/dashboard")

    html = load_static_file("admin.html")
    return web.Response(text=html, content_type="text/html")


async def http_api_docs_page(request: web.Request) -> web.Response:
    """Serve API documentation page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("api-docs.html")
    return web.Response(text=html, content_type="text/html")


async def http_about_page(request: web.Request) -> web.Response:
    """Serve About page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("about.html")
    return web.Response(text=html, content_type="text/html")


async def http_guides_page(request: web.Request) -> web.Response:
    """Serve Guides page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("guides.html")
    return web.Response(text=html, content_type="text/html")


async def http_files_page(request: web.Request) -> web.Response:
    """Serve file manager page (authenticated users - SFTP tab; admin - both tabs)."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("files.html")
    return web.Response(text=html, content_type="text/html")


async def http_sysmon_page(request: web.Request) -> web.Response:
    """Serve system monitor page (admin only)."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")
    if not token.has_scope("admin") and not token.has_scope("*"):
        raise web.HTTPFound("/dashboard")

    html = load_static_file("sysmon.html")
    return web.Response(text=html, content_type="text/html")


async def http_chat_page(request: web.Request) -> web.Response:
    """Serve chat page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("chat.html")
    return web.Response(text=html, content_type="text/html")


async def http_streams_page(request: web.Request) -> web.Response:
    """Serve community streams page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("streams.html")
    return web.Response(text=html, content_type="text/html")


async def http_watch_stream_page(request: web.Request) -> web.Response:
    """Serve stream watch page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    html = load_static_file("watch.html")
    return web.Response(text=html, content_type="text/html")


# =============================================================================
# Chat/Forum System
# =============================================================================

# Chat room state: channel -> set of (ws, user_id, username)
chat_rooms: dict[str, set] = {}

# Mutable chat user state: user_id -> dict with anonymous, nickname, avatar
# Updated by HTTP handlers so WS handlers see changes immediately
chat_user_state: dict[int, dict] = {}

# Voice chat state: channel_name -> {user_id -> {ws, username, muted, deafened, speaking}}
voice_state: dict[str, dict[int, dict]] = {}
# Rate-limit speaking broadcasts: (channel, user_id) -> last_broadcast_time
_voice_speaking_last: dict[tuple, float] = {}

# DM WebSocket tracking: user_id -> set of ws connections for DM delivery
dm_user_connections: dict[int, set] = {}


async def http_get_chat_channels(request: web.Request) -> web.Response:
    """Get all chat channels."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    channels = await db.get_chat_channels()
    # Enrich with stream association data
    for ch in channels:
        stream = await db.get_stream_by_chat_channel(ch["id"])
        ch["is_stream_channel"] = bool(stream)
        if stream:
            ch["stream_id"] = stream["id"]
            ch["stream_is_live"] = stream.get("is_live", 0)
            ch["stream_public_key"] = stream.get("public_key", "")
            ch["stream_owner"] = stream.get("owner_nickname") or stream.get("owner_username", "")
    # Enrich with unread counts
    unread_counts = await db.get_unread_counts(token.user_id)
    for ch in channels:
        ch["unread_count"] = unread_counts.get(ch["id"], 0)
    return web.json_response({"channels": channels})


async def http_create_chat_channel(request: web.Request) -> web.Response:
    """Create a new chat channel."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    name = data.get("name", "").strip().lower()
    description = data.get("description", "").strip()

    if not name:
        return web.json_response({"error": "Channel name is required"}, status=400)

    # Validate channel name
    if not re.match(r'^[a-z0-9-]+$', name):
        return web.json_response({
            "error": "Channel name must be lowercase letters, numbers, and hyphens only"
        }, status=400)

    if len(name) > 32:
        return web.json_response({"error": "Channel name too long (max 32 chars)"}, status=400)

    # Check if exists
    existing = await db.get_chat_channel_by_name(name)
    if existing:
        return web.json_response({"error": "Channel already exists"}, status=409)

    channel_id = await db.create_chat_channel(name, description, token.user_id)

    return web.json_response({
        "id": channel_id,
        "name": name,
        "description": description
    }, status=201)


async def http_update_chat_channel(request: web.Request) -> web.Response:
    """Update a chat channel (admin only, cannot modify defaults or stream channels)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Require admin role
    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)
    role = user.get("role") or ("superadmin" if user.get("is_admin") else "user")
    if role not in ("admin", "superadmin"):
        return web.json_response({"error": "Admin access required"}, status=403)

    try:
        channel_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid channel ID"}, status=400)

    channel = await db.get_chat_channel(channel_id)
    if not channel:
        return web.json_response({"error": "Channel not found"}, status=404)

    if channel.get("is_default"):
        return web.json_response({"error": "Cannot modify default channels"}, status=400)

    stream = await db.get_stream_by_chat_channel(channel_id)
    if stream:
        return web.json_response({"error": "Cannot modify stream-associated channels"}, status=400)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    old_name = channel["name"]
    success = await db.update_chat_channel(channel_id, **data)
    if not success:
        return web.json_response({"error": "No updates applied"}, status=400)

    # If name was changed, broadcast rename and move chat_rooms entry
    new_name = data.get("name")
    if new_name and new_name != old_name:
        if old_name in chat_rooms:
            await broadcast_to_channel(old_name, {
                "type": "channel_renamed",
                "old_name": old_name,
                "new_name": new_name
            })
            chat_rooms[new_name] = chat_rooms.pop(old_name)

    return web.json_response({"success": True})


async def http_delete_chat_channel(request: web.Request) -> web.Response:
    """Delete a chat channel (admin only, cannot delete defaults or stream channels)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return web.json_response({"error": "Admin access required"}, status=403)

    try:
        channel_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid channel ID"}, status=400)

    # Look up channel before deleting (need name for cleanup)
    channel = await db.get_chat_channel(channel_id)
    if not channel:
        return web.json_response({"error": "Channel not found"}, status=404)

    if channel.get("is_default"):
        return web.json_response({"error": "Cannot delete default channels"}, status=400)

    stream = await db.get_stream_by_chat_channel(channel_id)
    if stream:
        return web.json_response({"error": "Cannot delete stream-associated channels"}, status=400)

    success = await db.delete_chat_channel(channel_id)
    if not success:
        return web.json_response({"error": "Failed to delete channel"}, status=500)

    # Notify connected users and clean up
    channel_name = channel["name"]
    if channel_name in chat_rooms:
        await broadcast_to_channel(channel_name, {
            "type": "channel_deleted",
            "channel": channel_name
        })
        del chat_rooms[channel_name]

    return web.json_response({"success": True})


async def http_clear_chat_channel(request: web.Request) -> web.Response:
    """Clear all messages in a chat channel (superadmin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    # Only superadmins can clear channel history
    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    role = user.get("role") or ("superadmin" if user.get("is_admin") else "user")
    if role != "superadmin":
        return web.json_response({"error": "Super admin access required"}, status=403)

    try:
        channel_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid channel ID"}, status=400)

    # Get channel info for broadcasting
    channel = await db.get_chat_channel(channel_id)
    if not channel:
        return web.json_response({"error": "Channel not found"}, status=404)

    # Clear all messages
    deleted_count = await db.clear_channel_messages(channel_id)

    # Broadcast to channel that history was cleared
    channel_name = channel["name"]
    if channel_name in chat_rooms:
        await broadcast_to_channel(channel_name, {
            "type": "channel_cleared",
            "channel": channel_name,
            "cleared_by": user["username"],
            "message_count": deleted_count
        })

    return web.json_response({
        "success": True,
        "deleted_count": deleted_count
    })


async def http_upload_chat_image(request: web.Request) -> web.Response:
    """Upload an image for chat embedding."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        reader = await request.multipart()
        field = await reader.next()

        if field is None or field.name != "image":
            return web.json_response({"error": "No image file provided"}, status=400)

        content_type = field.headers.get(aiohttp.hdrs.CONTENT_TYPE, "")
        if not content_type.startswith("image/"):
            return web.json_response({"error": "File must be an image"}, status=400)

        ext_map = {
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        ext = ext_map.get(content_type)
        if not ext:
            return web.json_response({"error": "Unsupported image format"}, status=400)

        filename = f"{uuid.uuid4().hex}{ext}"
        upload_dir = Path(__file__).parent / "static" / "uploads" / "chat"
        upload_dir.mkdir(parents=True, exist_ok=True)
        filepath = upload_dir / filename

        size = 0
        max_size = 5 * 1024 * 1024  # 5MB

        with open(filepath, "wb") as f:
            while True:
                chunk = await field.read_chunk()
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    f.close()
                    filepath.unlink()
                    return web.json_response({"error": "File too large (max 5MB)"}, status=400)
                f.write(chunk)

        image_url = f"/static/uploads/chat/{filename}"
        return web.json_response({"url": image_url})

    except Exception as e:
        logger.error(f"Chat image upload error: {e}")
        return web.json_response({"error": "Upload failed"}, status=500)


# Link preview cache: url -> (preview_data, timestamp)
_link_preview_cache: dict[str, tuple[dict, float]] = {}
_LINK_PREVIEW_TTL = 3600  # 1 hour


def _parse_opengraph(html: str, url: str) -> dict:
    """Extract OpenGraph metadata from HTML."""
    import urllib.parse as _urlparse

    def get_meta(prop):
        m = re.search(rf'<meta[^>]+(?:property|name)=["\']og:{prop}["\'][^>]+content=["\']([^"\']*)["\']', html, re.I)
        if not m:
            m = re.search(rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']og:{prop}["\']', html, re.I)
        return m.group(1) if m else None

    title = get_meta("title")
    if not title:
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        title = m.group(1).strip() if m else None

    description = get_meta("description")
    if not description:
        m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', html, re.I)
        if not m:
            m = re.search(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']description["\']', html, re.I)
        description = m.group(1) if m else None

    image = get_meta("image")
    site_name = get_meta("site_name")
    parsed = _urlparse.urlparse(url)
    domain = parsed.hostname

    return {
        "url": url,
        "title": title,
        "description": description[:300] if description else None,
        "image": image,
        "site_name": site_name or domain,
        "domain": domain
    }


async def http_link_preview(request: web.Request) -> web.Response:
    """Fetch link preview (OpenGraph metadata) for a URL."""
    import urllib.parse as _urlparse
    import ipaddress

    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    url = request.query.get("url", "").strip()
    if not url:
        return web.json_response({"error": "url parameter required"}, status=400)

    parsed = _urlparse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return web.json_response({"error": "Only http/https URLs allowed"}, status=400)

    hostname = parsed.hostname
    if not hostname:
        return web.json_response({"error": "Invalid URL"}, status=400)

    # SSRF protection
    if is_blocked_host(hostname):
        return web.json_response({"error": "Blocked host"}, status=403)
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return web.json_response({"error": "Blocked host"}, status=403)
    except ValueError:
        pass

    # Check cache
    now = time()
    if url in _link_preview_cache:
        cached, ts = _link_preview_cache[url]
        if now - ts < _LINK_PREVIEW_TTL:
            return web.json_response(cached)

    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers={"User-Agent": "PortalBot/1.0"}, allow_redirects=True, max_redirects=3) as resp:
                if resp.status != 200:
                    return web.json_response({"error": "Failed to fetch URL"}, status=502)
                content_type = resp.content_type or ""
                if "html" not in content_type:
                    return web.json_response({"error": "Not an HTML page"}, status=400)
                body = await resp.content.read(1_048_576)  # 1MB max
                html = body.decode("utf-8", errors="replace")

        preview = _parse_opengraph(html, url)
        _link_preview_cache[url] = (preview, now)

        # Trim cache if too large
        if len(_link_preview_cache) > 500:
            sorted_items = sorted(_link_preview_cache.items(), key=lambda x: x[1][1])
            for k, _ in sorted_items[:250]:
                _link_preview_cache.pop(k, None)

        return web.json_response(preview)
    except asyncio.TimeoutError:
        return web.json_response({"error": "Timeout"}, status=504)
    except Exception as e:
        logger.debug(f"Link preview error for {url}: {e}")
        return web.json_response({"error": "Failed to fetch preview"}, status=502)


async def http_get_chat_thread(request: web.Request) -> web.Response:
    """Get reply chain for a message (thread view)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        message_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid message ID"}, status=400)

    chain = await db.get_reply_chain(message_id)
    if not chain:
        return web.json_response({"error": "Message not found"}, status=404)

    # Enrich with user data
    user_ids = list(set(m["user_id"] for m in chain if m.get("user_id")))
    users_info = await db.get_users_status(user_ids)
    users_map = {}
    for u in users_info:
        u_avatar = {}
        if u.get("avatar"):
            try:
                u_avatar = json.loads(u["avatar"])
            except (json.JSONDecodeError, TypeError):
                pass
        users_map[u["id"]] = {
            "nickname": u.get("nickname"),
            "avatar": u_avatar,
            "role": u.get("role", "user"),
            "anonymous": bool(u.get("chat_anonymous"))
        }

    for m in chain:
        ui = users_map.get(m.get("user_id"), {})
        was_anonymous = bool(m.get("anonymous"))
        m["nickname"] = ui.get("nickname") if not was_anonymous else None
        m["avatar"] = ui.get("avatar", {}) if not was_anonymous else {}
        m["role"] = ui.get("role", "user")
        if was_anonymous:
            m["username"] = "Anonymous"
        elif ui.get("nickname"):
            m["username"] = ui["nickname"]

    return web.json_response({"thread": chain})


async def handle_chat_websocket(request: web.Request) -> web.WebSocketResponse:
    """Handle chat WebSocket connections."""
    token = await authenticate_request(request)
    if not token:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "error", "message": "Authentication required"})
        await ws.close()
        return ws

    user = await db.get_user_by_id(token.user_id)
    if not user:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "error", "message": "User not found"})
        await ws.close()
        return ws

    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    username = user["username"]
    user_id = user["id"]
    user_role = user.get("role") or ("superadmin" if user.get("is_admin") else "user")
    current_channel = None

    # Mutable state dict - HTTP handlers update this directly
    _avatar = {}
    if user.get("avatar"):
        try:
            _avatar = json.loads(user["avatar"])
        except (json.JSONDecodeError, TypeError):
            pass
    my_state = {
        "anonymous": bool(user.get("chat_anonymous")),
        "nickname": user.get("nickname"),
        "avatar": _avatar,
    }
    chat_user_state[user_id] = my_state

    # Rate limiting: max 5 messages per 5 seconds
    chat_rate_limit = 5
    chat_rate_window = 5.0
    chat_msg_times: list[float] = []

    logger.info(f"[Chat] User {username} connected")

    raw_ws = ws  # Keep raw reference for active_connections and notification cleanup
    active_connections.add(raw_ws)
    _online_users[user_id] = _online_users.get(user_id, 0) + 1
    chat_conn_id = str(uuid.uuid4())
    client_ip = get_client_ip(request)
    traffic_metrics.start_connection(chat_conn_id, SERVICE_ID_CHAT, user_id, "chat", client_ip)
    ws = MetricsWebSocket(raw_ws, chat_conn_id)  # Shadow ws for automatic traffic recording

    user_entry = (ws, user_id, username, user_role)

    # Subscribe to notifications
    if user_id not in notification_subscribers:
        notification_subscribers[user_id] = set()
    notification_subscribers[user_id].add(raw_ws)

    # Register for DM delivery
    if user_id not in dm_user_connections:
        dm_user_connections[user_id] = set()
    dm_user_connections[user_id].add(raw_ws)

    # Send DM conversations list on connect
    try:
        dm_convs = await db.get_dm_conversations(user_id)
        dm_unread = await db.get_dm_unread_counts(user_id)
        await ws.send_json({
            "type": "dm_conversations_list",
            "conversations": dm_convs,
            "unread_counts": dm_unread
        })
    except Exception:
        pass

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    msg_type = data.get("type")

                    if msg_type == "join":
                        # Support multiple join methods:
                        # 1. stream_key (pub_xxx or live_xxx) - preferred for stream chat
                        # 2. channel_id (integer) - direct channel ID
                        # 3. channel (string) - channel name (legacy)
                        stream_key = data.get("stream_key")
                        channel_id = data.get("channel_id")
                        channel_name = data.get("channel")
                        channel = None
                        stream = None

                        if stream_key:
                            # Look up stream by key (public or private)
                            if stream_key.startswith("pub_"):
                                stream = await db.get_stream_by_public_key(stream_key)
                            elif stream_key.startswith("live_"):
                                stream = await db.get_stream_by_key(stream_key)
                            else:
                                # Try both formats
                                stream = await db.get_stream_by_public_key(stream_key)
                                if not stream:
                                    stream = await db.get_stream_by_key(f"live_{stream_key}")

                            if not stream:
                                await ws.send_json({"type": "error", "message": "Invalid stream key"})
                                continue

                            if not stream.get("chat_channel_id"):
                                await ws.send_json({"type": "error", "message": "Stream has no chat channel"})
                                continue

                            channel = await db.get_chat_channel(stream["chat_channel_id"])
                        elif channel_id:
                            # Direct channel ID lookup
                            try:
                                channel = await db.get_chat_channel(int(channel_id))
                            except (ValueError, TypeError):
                                await ws.send_json({"type": "error", "message": "Invalid channel ID"})
                                continue
                            if channel:
                                stream = await db.get_stream_by_chat_channel(channel["id"])
                        else:
                            # Channel name lookup (default to "general")
                            channel_name = channel_name or "general"
                            channel = await db.get_chat_channel_by_name(channel_name)
                            if channel:
                                stream = await db.get_stream_by_chat_channel(channel["id"])

                        if not channel:
                            await ws.send_json({"type": "error", "message": "Channel not found"})
                            continue

                        # Leave current channel
                        if current_channel and current_channel in chat_rooms:
                            # Auto-leave voice in old channel
                            if current_channel in voice_state and user_id in voice_state[current_channel]:
                                del voice_state[current_channel][user_id]
                                await broadcast_to_channel(current_channel, {
                                    "type": "voice_user_left",
                                    "user_id": user_id
                                })
                                if not voice_state[current_channel]:
                                    del voice_state[current_channel]

                            chat_rooms[current_channel].discard(user_entry)
                            display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                            await broadcast_to_channel(current_channel, {
                                "type": "user_left",
                                "user_id": user_id,
                                "username": display_name
                            }, exclude=ws)
                            # Broadcast updated users list to remaining users
                            await broadcast_users_list(current_channel)

                        # Check if user is banned from this stream's chat
                        if stream and await db.is_user_banned_from_stream(stream["id"], user_id):
                            await ws.send_json({
                                "type": "error",
                                "message": "You are banned from this stream's chat"
                            })
                            continue

                        # Join new channel (use channel name from DB)
                        current_channel = channel["name"]
                        if current_channel not in chat_rooms:
                            chat_rooms[current_channel] = set()
                        chat_rooms[current_channel].add(user_entry)

                        # Send channel info (include stream data if this is a stream channel)
                        channel_info = {
                            "type": "channel_info",
                            "id": channel["id"],
                            "name": channel["name"],
                            "description": channel.get("description"),
                            "topic": channel.get("topic")
                        }
                        if stream:
                            channel_info["stream_id"] = stream["id"]
                            channel_info["stream_name"] = stream.get("name", "")
                            channel_info["stream_is_live"] = stream.get("is_live", 0)
                            channel_info["stream_public_key"] = stream.get("public_key", "")
                        await ws.send_json(channel_info)

                        # Send message history enriched with user data
                        messages = await db.get_chat_messages(channel["id"], limit=50)
                        if messages:
                            # Collect unique user IDs and fetch their profiles
                            msg_user_ids = list(set(m["user_id"] for m in messages if m.get("user_id")))
                            msg_users_info = await db.get_users_status(msg_user_ids)
                            msg_users_map = {}
                            for u in msg_users_info:
                                u_avatar = {}
                                if u.get("avatar"):
                                    try:
                                        u_avatar = json.loads(u["avatar"])
                                    except (json.JSONDecodeError, TypeError):
                                        pass
                                msg_users_map[u["id"]] = {
                                    "nickname": u.get("nickname"),
                                    "avatar": u_avatar,
                                    "role": u.get("role", "user"),
                                    "anonymous": bool(u.get("chat_anonymous"))
                                }
                            # Enrich each message using per-message anonymous flag
                            # Display priority: Anon > Nickname > Username
                            for m in messages:
                                ui = msg_users_map.get(m.get("user_id"), {})
                                was_anonymous = bool(m.get("anonymous"))
                                m["nickname"] = ui.get("nickname") if not was_anonymous else None
                                m["avatar"] = ui.get("avatar", {}) if not was_anonymous else {}
                                m["role"] = ui.get("role", "user")
                                m["anonymous"] = was_anonymous
                                if was_anonymous:
                                    m["username"] = "Anonymous"
                                elif ui.get("nickname"):
                                    m["username"] = ui["nickname"]

                            # Enrich reply previews
                            reply_ids = [m["reply_to"] for m in messages if m.get("reply_to")]
                            if reply_ids:
                                reply_msgs = {}
                                for rid in set(reply_ids):
                                    rmsg = await db.get_chat_message(rid)
                                    if rmsg:
                                        r_ui = msg_users_map.get(rmsg.get("user_id"), {})
                                        r_anon = bool(rmsg.get("anonymous"))
                                        r_username = "Anonymous" if r_anon else (r_ui.get("nickname") or rmsg["username"])
                                        r_text = rmsg["message"]
                                        if len(r_text) > 100:
                                            r_text = r_text[:100] + "..."
                                        reply_msgs[rid] = {
                                            "id": rid,
                                            "username": r_username,
                                            "message": r_text
                                        }
                                for m in messages:
                                    if m.get("reply_to"):
                                        if m["reply_to"] in reply_msgs:
                                            m["reply_preview"] = reply_msgs[m["reply_to"]]
                                        elif m.get("reply_preview_username"):
                                            # Original message was deleted — use stored preview
                                            m["reply_preview"] = {
                                                "id": m["reply_to"],
                                                "username": m["reply_preview_username"],
                                                "message": m.get("reply_preview_text") or "",
                                                "deleted": True
                                            }

                        # Enrich messages with reactions
                        if messages:
                            msg_ids = [m["id"] for m in messages]
                            all_reactions = await db.get_bulk_reactions(msg_ids)
                            for m in messages:
                                m["reactions"] = all_reactions.get(m["id"], [])

                        await ws.send_json({
                            "type": "history",
                            "messages": messages
                        })

                        # Send pinned messages
                        if channel:
                            pinned = await db.get_pinned_messages(channel["id"])
                            if pinned:
                                # Enrich pinned messages with user info
                                for p in pinned:
                                    p_ui = msg_users_map.get(p.get("user_id"), {}) if messages else {}
                                    if p.get("anonymous"):
                                        p["username"] = "Anonymous"
                                    elif p_ui.get("nickname"):
                                        p["username"] = p_ui["nickname"]
                                await ws.send_json({
                                    "type": "pinned_messages",
                                    "messages": pinned
                                })

                        # Mark channel as read
                        if messages and channel:
                            last_msg_id = messages[-1]["id"]
                            await db.update_read_position(user_id, channel["id"], last_msg_id)

                        # Send user list with status info
                        user_ids = [entry[1] for entry in chat_rooms[current_channel]]
                        users_info = await db.get_users_status(list(set(user_ids)))
                        users_list = []
                        for u in users_info:
                            avatar = {}
                            if u.get("avatar"):
                                try:
                                    avatar = json.loads(u["avatar"])
                                except (json.JSONDecodeError, TypeError):
                                    pass
                            voice_info = voice_state.get(current_channel, {}).get(u["id"], {})
                            users_list.append({
                                "user_id": u["id"],
                                "username": "Anonymous" if u.get("chat_anonymous") else (u.get("nickname") or u["username"]),
                                "nickname": u.get("nickname"),
                                "status": u.get("status", "online"),
                                "status_message": u.get("status_message"),
                                "role": u.get("role", "user"),
                                "anonymous": bool(u.get("chat_anonymous")),
                                "avatar": avatar,
                                "in_voice": bool(voice_info),
                                "voice_muted": voice_info.get("muted", False),
                                "voice_deafened": voice_info.get("deafened", False),
                                "voice_speaking": voice_info.get("speaking", False)
                            })
                        await ws.send_json({
                            "type": "users",
                            "users": users_list
                        })

                        # Notify others
                        display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                        await broadcast_to_channel(current_channel, {
                            "type": "user_joined",
                            "user_id": user_id,
                            "username": display_name,
                            "role": user_role,
                            "anonymous": my_state["anonymous"]
                        }, exclude=ws)
                        # Broadcast updated users list to all in channel
                        await broadcast_users_list(current_channel)

                    elif msg_type == "message":
                        if not current_channel:
                            continue

                        message_text = data.get("message", "").strip()
                        image_url = data.get("image_url", "").strip() or None

                        # Validate image_url if provided
                        if image_url and not image_url.startswith("/static/uploads/chat/"):
                            image_url = None

                        # Must have text or image
                        if not message_text and not image_url:
                            continue
                        if len(message_text) > 4000:
                            continue

                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel:
                            continue

                        # Check if user is banned from this stream's chat
                        stream = await db.get_stream_by_chat_channel(channel["id"])
                        if stream and await db.is_user_banned_from_stream(stream["id"], user_id):
                            await ws.send_json({
                                "type": "error",
                                "message": "You are banned from this stream's chat"
                            })
                            continue

                        # Rate limit: max N messages per window
                        now = monotonic()
                        chat_msg_times[:] = [t for t in chat_msg_times if now - t < chat_rate_window]
                        if len(chat_msg_times) >= chat_rate_limit:
                            await ws.send_json({
                                "type": "error",
                                "message": "Slow down! You're sending messages too fast."
                            })
                            continue
                        chat_msg_times.append(monotonic())

                        # Handle reply_to
                        reply_to_id = data.get("reply_to")
                        reply_preview = None
                        if reply_to_id:
                            try:
                                reply_to_id = int(reply_to_id)
                            except (ValueError, TypeError):
                                reply_to_id = None
                        if reply_to_id:
                            replied_msg = await db.get_chat_message(reply_to_id)
                            if replied_msg and replied_msg["channel_id"] == channel["id"]:
                                r_username = replied_msg["username"]
                                r_text = replied_msg["message"]
                                if replied_msg.get("anonymous"):
                                    r_username = "Anonymous"
                                if len(r_text) > 100:
                                    r_text = r_text[:100] + "..."
                                reply_preview = {
                                    "id": replied_msg["id"],
                                    "username": r_username,
                                    "message": r_text
                                }
                            else:
                                reply_to_id = None

                        # Save message (always save real username in DB)
                        msg_id = await db.create_chat_message(
                            channel["id"], user_id, username, message_text or "",
                            anonymous=my_state["anonymous"],
                            reply_to=reply_to_id,
                            image_url=image_url,
                            reply_preview_username=reply_preview["username"] if reply_preview else None,
                            reply_preview_text=reply_preview["message"] if reply_preview else None
                        )

                        # Broadcast to channel (display: Anon > Nickname > Username)
                        display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                        broadcast_payload = {
                            "type": "message",
                            "id": msg_id,
                            "user_id": user_id,
                            "username": display_name,
                            "nickname": my_state["nickname"] if not my_state["anonymous"] else None,
                            "role": user_role,
                            "anonymous": my_state["anonymous"],
                            "avatar": my_state["avatar"] if not my_state["anonymous"] else {},
                            "message": message_text,
                            "created_at": datetime.now(timezone.utc).isoformat()
                        }
                        if reply_to_id and reply_preview:
                            broadcast_payload["reply_to"] = reply_to_id
                            broadcast_payload["reply_preview"] = reply_preview
                        if image_url:
                            broadcast_payload["image_url"] = image_url
                        await broadcast_to_channel(current_channel, broadcast_payload)

                    elif msg_type == "typing":
                        if current_channel:
                            typing_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                            await broadcast_to_channel(current_channel, {
                                "type": "typing",
                                "username": typing_name
                            }, exclude=ws)

                    elif msg_type == "delete":
                        if not current_channel:
                            continue
                        message_id = data.get("message_id")
                        if not message_id:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        # Admins/mods can delete any; users delete own only
                        is_mod = user_role in ("admin", "superadmin", "moderator")
                        if is_mod:
                            success = await db.delete_chat_message(message_id)
                        else:
                            success = await db.delete_chat_message(message_id, user_id=user_id)
                        if success:
                            await broadcast_to_channel(current_channel, {
                                "type": "message_deleted",
                                "message_id": message_id,
                                "deleted_by": user_id
                            })

                    elif msg_type == "react":
                        if not current_channel:
                            continue
                        message_id = data.get("message_id")
                        emoji = data.get("emoji", "").strip()
                        if not message_id or not emoji or len(emoji) > 10:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        # Verify message belongs to current channel
                        msg = await db.get_chat_message(message_id)
                        if not msg:
                            continue
                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel or msg["channel_id"] != channel["id"]:
                            continue
                        added, count = await db.toggle_reaction(message_id, user_id, emoji)
                        await broadcast_to_channel(current_channel, {
                            "type": "reaction_update",
                            "message_id": message_id,
                            "emoji": emoji,
                            "user_id": user_id,
                            "added": added,
                            "count": count
                        })

                    elif msg_type == "edit_message":
                        if not current_channel:
                            continue
                        message_id = data.get("message_id")
                        new_text = data.get("message", "").strip()
                        if not message_id or not new_text:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        if len(new_text) > 4000:
                            continue
                        updated = await db.edit_chat_message(message_id, user_id, new_text)
                        if updated:
                            await broadcast_to_channel(current_channel, {
                                "type": "message_edited",
                                "message_id": message_id,
                                "message": new_text,
                                "edited_at": updated["edited_at"]
                            })
                        else:
                            await ws.send_json({"type": "error", "message": "Cannot edit (5-minute window expired or not your message)"})

                    elif msg_type == "pin_message":
                        if not current_channel:
                            continue
                        is_mod = user_role in ("admin", "superadmin", "moderator")
                        if not is_mod:
                            await ws.send_json({"type": "error", "message": "Only moderators can pin messages"})
                            continue
                        message_id = data.get("message_id")
                        if not message_id:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel:
                            continue
                        msg = await db.get_chat_message(message_id)
                        if not msg or msg["channel_id"] != channel["id"]:
                            continue
                        success = await db.pin_message(message_id, user_id)
                        if success:
                            my_state = chat_user_state.get(user_id, {})
                            display_name = "Anonymous" if my_state.get("anonymous") else (my_state.get("nickname") or username)
                            msg_author = msg.get("username", "Unknown")
                            if msg.get("anonymous"):
                                msg_author = "Anonymous"
                            await broadcast_to_channel(current_channel, {
                                "type": "message_pinned",
                                "message_id": message_id,
                                "message": msg["message"],
                                "username": msg_author,
                                "pinned_by": display_name
                            })

                    elif msg_type == "unpin_message":
                        if not current_channel:
                            continue
                        is_mod = user_role in ("admin", "superadmin", "moderator")
                        if not is_mod:
                            await ws.send_json({"type": "error", "message": "Only moderators can unpin messages"})
                            continue
                        message_id = data.get("message_id")
                        if not message_id:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        success = await db.unpin_message(message_id)
                        if success:
                            await broadcast_to_channel(current_channel, {
                                "type": "message_unpinned",
                                "message_id": message_id
                            })

                    elif msg_type == "mark_read":
                        if not current_channel:
                            continue
                        message_id = data.get("message_id")
                        if not message_id:
                            continue
                        try:
                            message_id = int(message_id)
                        except (ValueError, TypeError):
                            continue
                        channel = await db.get_chat_channel_by_name(current_channel)
                        if channel:
                            await db.update_read_position(user_id, channel["id"], message_id)

                    elif msg_type == "ban":
                        # Stream owner can ban a user from chat
                        if not current_channel:
                            continue

                        target_user_id = data.get("user_id")
                        reason = data.get("reason", "")

                        if not target_user_id:
                            await ws.send_json({"type": "error", "message": "user_id required"})
                            continue

                        # Get the stream for this chat channel
                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel:
                            continue

                        stream = await db.get_stream_by_chat_channel(channel["id"])
                        if not stream:
                            await ws.send_json({"type": "error", "message": "Not a stream chat"})
                            continue

                        # Only stream owner or admin can ban
                        is_owner = stream["user_id"] == user_id
                        is_admin = user_role in ("admin", "superadmin")
                        if not is_owner and not is_admin:
                            await ws.send_json({"type": "error", "message": "Not authorized"})
                            continue

                        # Can't ban yourself or the stream owner
                        if target_user_id == user_id:
                            await ws.send_json({"type": "error", "message": "Cannot ban yourself"})
                            continue
                        if target_user_id == stream["user_id"]:
                            await ws.send_json({"type": "error", "message": "Cannot ban stream owner"})
                            continue

                        # Create the ban
                        ban_id = await db.create_stream_ban(
                            stream_id=stream["id"],
                            user_id=target_user_id,
                            banned_by=user_id,
                            reason=reason
                        )

                        if ban_id:
                            # Get banned user info
                            banned_user = await db.get_user_by_id(target_user_id)
                            banned_username = banned_user["username"] if banned_user else f"User {target_user_id}"

                            # Notify the channel
                            await broadcast_to_channel(current_channel, {
                                "type": "user_banned",
                                "user_id": target_user_id,
                                "username": banned_username,
                                "banned_by": username,
                                "reason": reason
                            })

                            # Send confirmation to the banner
                            await ws.send_json({
                                "type": "ban_success",
                                "user_id": target_user_id,
                                "username": banned_username
                            })

                            logger.info(f"User {banned_username} banned from stream {stream['name']} by {username}")
                        else:
                            await ws.send_json({"type": "error", "message": "User may already be banned"})

                    elif msg_type == "unban":
                        # Stream owner can unban a user
                        if not current_channel:
                            continue

                        target_user_id = data.get("user_id")
                        if not target_user_id:
                            await ws.send_json({"type": "error", "message": "user_id required"})
                            continue

                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel:
                            continue

                        stream = await db.get_stream_by_chat_channel(channel["id"])
                        if not stream:
                            await ws.send_json({"type": "error", "message": "Not a stream chat"})
                            continue

                        # Only stream owner or admin can unban
                        is_owner = stream["user_id"] == user_id
                        is_admin = user_role in ("admin", "superadmin")
                        if not is_owner and not is_admin:
                            await ws.send_json({"type": "error", "message": "Not authorized"})
                            continue

                        success = await db.remove_stream_ban(stream["id"], target_user_id)
                        if success:
                            banned_user = await db.get_user_by_id(target_user_id)
                            banned_username = banned_user["username"] if banned_user else f"User {target_user_id}"

                            await ws.send_json({
                                "type": "unban_success",
                                "user_id": target_user_id,
                                "username": banned_username
                            })
                            logger.info(f"User {banned_username} unbanned from stream {stream['name']} by {username}")
                        else:
                            await ws.send_json({"type": "error", "message": "Ban not found"})

                    elif msg_type == "get_bans":
                        # Get list of banned users (stream owner only)
                        if not current_channel:
                            continue

                        channel = await db.get_chat_channel_by_name(current_channel)
                        if not channel:
                            continue

                        stream = await db.get_stream_by_chat_channel(channel["id"])
                        if not stream:
                            await ws.send_json({"type": "error", "message": "Not a stream chat"})
                            continue

                        # Only stream owner or admin can view bans
                        is_owner = stream["user_id"] == user_id
                        is_admin = user_role in ("admin", "superadmin")
                        if not is_owner and not is_admin:
                            await ws.send_json({"type": "error", "message": "Not authorized"})
                            continue

                        bans = await db.get_stream_bans(stream["id"])
                        await ws.send_json({
                            "type": "bans_list",
                            "bans": bans
                        })

                    # =========================================================
                    # Voice Chat Signaling
                    # =========================================================
                    elif msg_type == "voice_join":
                        if not current_channel:
                            await ws.send_json({"type": "error", "message": "Join a channel first"})
                            continue

                        # Check not already in voice anywhere
                        already_in = None
                        for vc, vc_users in voice_state.items():
                            if user_id in vc_users:
                                already_in = vc
                                break
                        if already_in:
                            await ws.send_json({"type": "error", "message": "Already in voice chat"})
                            continue

                        # Add to voice state
                        display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                        if current_channel not in voice_state:
                            voice_state[current_channel] = {}
                        voice_state[current_channel][user_id] = {
                            "ws": ws,
                            "username": display_name,
                            "muted": False,
                            "deafened": False,
                            "speaking": False
                        }

                        # Send current voice users to joiner
                        voice_users = []
                        for vid, vdata in voice_state[current_channel].items():
                            voice_users.append({
                                "user_id": vid,
                                "username": vdata["username"],
                                "muted": vdata["muted"],
                                "deafened": vdata["deafened"],
                                "speaking": vdata["speaking"]
                            })
                        await ws.send_json({
                            "type": "voice_state",
                            "channel": current_channel,
                            "users": voice_users
                        })

                        # Broadcast to channel that user joined voice
                        await broadcast_to_channel(current_channel, {
                            "type": "voice_user_joined",
                            "user_id": user_id,
                            "username": display_name
                        }, exclude=ws)

                        # Broadcast updated users list with voice state
                        await broadcast_users_list(current_channel)
                        logger.info(f"[Voice] {display_name} joined voice in #{current_channel}")

                    elif msg_type == "voice_leave":
                        if not current_channel:
                            continue
                        if current_channel in voice_state and user_id in voice_state[current_channel]:
                            del voice_state[current_channel][user_id]
                            await broadcast_to_channel(current_channel, {
                                "type": "voice_user_left",
                                "user_id": user_id
                            })
                            if not voice_state[current_channel]:
                                del voice_state[current_channel]
                            await broadcast_users_list(current_channel)
                            display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
                            logger.info(f"[Voice] {display_name} left voice in #{current_channel}")

                    elif msg_type == "voice_signal":
                        # Forward WebRTC signaling to target user
                        target_user_id = data.get("target_user_id")
                        signal_data = data.get("signal")
                        if not target_user_id or not signal_data:
                            continue

                        try:
                            target_user_id = int(target_user_id)
                        except (ValueError, TypeError):
                            continue

                        # Find target in voice state
                        if current_channel in voice_state and target_user_id in voice_state[current_channel]:
                            target_ws = voice_state[current_channel][target_user_id]["ws"]
                            try:
                                if not target_ws.closed:
                                    await target_ws.send_json({
                                        "type": "voice_signal",
                                        "from_user_id": user_id,
                                        "signal": signal_data
                                    })
                            except Exception:
                                pass

                    elif msg_type == "voice_mute":
                        muted = bool(data.get("muted", False))
                        if current_channel in voice_state and user_id in voice_state[current_channel]:
                            voice_state[current_channel][user_id]["muted"] = muted
                            await broadcast_to_channel(current_channel, {
                                "type": "voice_mute_changed",
                                "user_id": user_id,
                                "muted": muted
                            })

                    elif msg_type == "voice_deafen":
                        deafened = bool(data.get("deafened", False))
                        if current_channel in voice_state and user_id in voice_state[current_channel]:
                            voice_state[current_channel][user_id]["deafened"] = deafened
                            await broadcast_to_channel(current_channel, {
                                "type": "voice_deafen_changed",
                                "user_id": user_id,
                                "deafened": deafened
                            })

                    elif msg_type == "voice_speaking":
                        speaking = bool(data.get("speaking", False))
                        if current_channel in voice_state and user_id in voice_state[current_channel]:
                            # Rate-limit speaking broadcasts (max 1 per 100ms)
                            rate_key = (current_channel, user_id)
                            now = monotonic()
                            last = _voice_speaking_last.get(rate_key, 0)
                            if now - last < 0.1:
                                continue
                            _voice_speaking_last[rate_key] = now

                            voice_state[current_channel][user_id]["speaking"] = speaking
                            await broadcast_to_channel(current_channel, {
                                "type": "voice_speaking_changed",
                                "user_id": user_id,
                                "speaking": speaking
                            })

                    # ==============================================
                    # Direct Message handlers
                    # ==============================================

                    elif msg_type == "dm_open":
                        # Open/create a 1:1 DM conversation
                        target_user_id = data.get("user_id")
                        conv_id = data.get("conversation_id")
                        conv = None
                        if target_user_id:
                            try:
                                target_user_id = int(target_user_id)
                            except (ValueError, TypeError):
                                continue
                            if target_user_id == user_id:
                                await ws.send_json({"type": "error", "message": "Cannot DM yourself"})
                                continue
                            target = await db.get_user_by_id(target_user_id)
                            if not target:
                                await ws.send_json({"type": "error", "message": "User not found"})
                                continue
                            conv = await db.create_dm_conversation(user_id, [target_user_id], conv_type="1on1")
                        elif conv_id:
                            try:
                                conv_id = int(conv_id)
                            except (ValueError, TypeError):
                                continue
                            if not await db.is_dm_participant(conv_id, user_id):
                                continue
                            conv = await db.get_dm_conversation(conv_id)
                        if conv:
                            messages = await db.get_dm_messages(conv["id"], limit=50)
                            msg_ids = [m["id"] for m in messages]
                            reactions = await db.get_bulk_dm_reactions(msg_ids) if msg_ids else {}
                            for m in messages:
                                m["reactions"] = reactions.get(m["id"], [])
                            await ws.send_json({
                                "type": "dm_conversation_opened",
                                "conversation": conv,
                                "messages": messages
                            })

                    elif msg_type == "dm_create_group":
                        # Create a group DM
                        try:
                            target_ids = [int(uid) for uid in data.get("user_ids", [])]
                        except (ValueError, TypeError):
                            continue
                        if user_id in target_ids:
                            target_ids.remove(user_id)
                        if not target_ids or len(target_ids) > 9:
                            await ws.send_json({"type": "error", "message": "Need 1-9 other participants"})
                            continue
                        name = data.get("name", "").strip() or None
                        conv = await db.create_dm_conversation(user_id, target_ids, name=name, conv_type="group")
                        await ws.send_json({
                            "type": "dm_conversation_opened",
                            "conversation": conv,
                            "messages": []
                        })
                        # Notify other participants
                        for uid in target_ids:
                            await _send_dm_to_user(uid, {
                                "type": "dm_conversations_list",
                                "conversations": await db.get_dm_conversations(uid),
                                "unread_counts": await db.get_dm_unread_counts(uid)
                            })

                    elif msg_type == "dm_message":
                        # Send a DM message
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                        except (ValueError, TypeError):
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        text = data.get("message", "").strip()
                        image_url = data.get("image_url")
                        if image_url and not image_url.startswith("/static/uploads/chat/"):
                            image_url = None
                        if not text and not image_url:
                            continue
                        if text and len(text) > 4000:
                            text = text[:4000]
                        # Rate limit (shared with channel chat)
                        now_mono = monotonic()
                        chat_msg_times[:] = [t for t in chat_msg_times if now_mono - t < chat_rate_window]
                        if len(chat_msg_times) >= chat_rate_limit:
                            await ws.send_json({"type": "error", "message": "Rate limit exceeded"})
                            continue
                        chat_msg_times.append(now_mono)

                        reply_to = data.get("reply_to")
                        reply_preview_username = None
                        reply_preview_text = None
                        if reply_to:
                            try:
                                reply_to = int(reply_to)
                                orig = await db.get_dm_message(reply_to)
                                if orig and orig.get("conversation_id") == conv_id:
                                    reply_preview_username = orig.get("username", "")
                                    reply_preview_text = orig.get("message", "")[:100]
                                else:
                                    reply_to = None
                            except (ValueError, TypeError):
                                reply_to = None

                        display_name = "Anonymous" if my_state.get("anonymous") else (my_state.get("nickname") or username)
                        msg_id = await db.create_dm_message(
                            conv_id, user_id, username, text,
                            reply_to=reply_to, image_url=image_url,
                            reply_preview_username=reply_preview_username,
                            reply_preview_text=reply_preview_text
                        )
                        payload = {
                            "type": "dm_message",
                            "conversation_id": conv_id,
                            "id": msg_id,
                            "user_id": user_id,
                            "username": display_name,
                            "message": text,
                            "image_url": image_url,
                            "reply_to": reply_to,
                            "reply_preview_username": reply_preview_username,
                            "reply_preview_text": reply_preview_text,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "reactions": []
                        }
                        await _broadcast_to_dm(conv_id, payload)
                        # Send notification to offline participants
                        participants = await db.get_dm_participant_ids(conv_id)
                        for pid in participants:
                            if pid != user_id and pid not in dm_user_connections:
                                preview = text[:80] + "..." if len(text) > 80 else text
                                await send_notification(
                                    pid, "dm_message",
                                    f"Message from {display_name}",
                                    preview,
                                    {"conversation_id": conv_id, "message_id": msg_id}
                                )

                    elif msg_type == "dm_typing":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                        except (ValueError, TypeError):
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        display_name = "Anonymous" if my_state.get("anonymous") else (my_state.get("nickname") or username)
                        await _broadcast_to_dm(conv_id, {
                            "type": "dm_typing",
                            "conversation_id": conv_id,
                            "user_id": user_id,
                            "username": display_name
                        }, exclude_user_id=user_id)

                    elif msg_type == "dm_delete":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                            message_id = int(data.get("message_id", 0))
                        except (ValueError, TypeError):
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        msg = await db.get_dm_message(message_id)
                        if not msg or msg.get("conversation_id") != conv_id:
                            continue
                        deleted = await db.delete_dm_message(message_id, user_id)
                        if deleted:
                            await _broadcast_to_dm(conv_id, {
                                "type": "dm_message_deleted",
                                "conversation_id": conv_id,
                                "message_id": message_id
                            })

                    elif msg_type == "dm_react":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                            message_id = int(data.get("message_id", 0))
                        except (ValueError, TypeError):
                            continue
                        emoji = data.get("emoji", "")
                        if not emoji or len(emoji) > 10:
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        react_msg = await db.get_dm_message(message_id)
                        if not react_msg or react_msg.get("conversation_id") != conv_id:
                            continue
                        added, count = await db.toggle_dm_reaction(message_id, user_id, emoji)
                        await _broadcast_to_dm(conv_id, {
                            "type": "dm_reaction_update",
                            "conversation_id": conv_id,
                            "message_id": message_id,
                            "emoji": emoji,
                            "added": added,
                            "count": count,
                            "user_id": user_id
                        })

                    elif msg_type == "dm_edit":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                            message_id = int(data.get("message_id", 0))
                        except (ValueError, TypeError):
                            continue
                        new_text = data.get("message", "").strip()
                        if not new_text or len(new_text) > 4000:
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        edit_msg = await db.get_dm_message(message_id)
                        if not edit_msg or edit_msg.get("conversation_id") != conv_id:
                            continue
                        updated = await db.edit_dm_message(message_id, user_id, new_text)
                        if updated:
                            await _broadcast_to_dm(conv_id, {
                                "type": "dm_message_edited",
                                "conversation_id": conv_id,
                                "message_id": message_id,
                                "message": new_text,
                                "edited_at": updated["edited_at"]
                            })

                    elif msg_type == "dm_mark_read":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                            message_id = int(data.get("message_id", 0))
                        except (ValueError, TypeError):
                            continue
                        if await db.is_dm_participant(conv_id, user_id):
                            await db.update_dm_read_position(user_id, conv_id, message_id)

                    elif msg_type == "dm_history":
                        try:
                            conv_id = int(data.get("conversation_id", 0))
                        except (ValueError, TypeError):
                            continue
                        if not await db.is_dm_participant(conv_id, user_id):
                            continue
                        before_id = data.get("before_id")
                        if before_id:
                            try:
                                before_id = int(before_id)
                            except (ValueError, TypeError):
                                before_id = None
                        messages = await db.get_dm_messages(conv_id, limit=50, before_id=before_id)
                        msg_ids = [m["id"] for m in messages]
                        reactions = await db.get_bulk_dm_reactions(msg_ids) if msg_ids else {}
                        for m in messages:
                            m["reactions"] = reactions.get(m["id"], [])
                        await ws.send_json({
                            "type": "dm_history",
                            "conversation_id": conv_id,
                            "messages": messages
                        })

                except json.JSONDecodeError:
                    await ws.send_json({"type": "error", "message": "Invalid JSON"})

            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error(f"[Chat] WebSocket error: {ws.exception()}")
                break

    except Exception as e:
        logger.error(f"[Chat] Error: {e}")
        traffic_metrics.record_error(SERVICE_ID_CHAT)

    finally:
        # Clean up global connection tracking
        active_connections.discard(raw_ws)
        traffic_metrics.end_connection(chat_conn_id)
        count = _online_users.get(user_id, 1) - 1
        if count <= 0:
            _online_users.pop(user_id, None)
        else:
            _online_users[user_id] = count

        # Clean up voice state (remove from any channel)
        for vc in list(voice_state.keys()):
            if user_id in voice_state[vc]:
                del voice_state[vc][user_id]
                try:
                    await broadcast_to_channel(vc, {
                        "type": "voice_user_left",
                        "user_id": user_id
                    })
                    await broadcast_users_list(vc)
                except Exception:
                    pass
                if not voice_state[vc]:
                    del voice_state[vc]
        # Clean up speaking rate-limit entries
        for key in [k for k in _voice_speaking_last if k[1] == user_id]:
            _voice_speaking_last.pop(key, None)

        # Clean up chat room
        if current_channel and current_channel in chat_rooms:
            chat_rooms[current_channel].discard(user_entry)
            display_name = "Anonymous" if my_state["anonymous"] else (my_state["nickname"] or username)
            await broadcast_to_channel(current_channel, {
                "type": "user_left",
                "user_id": user_id,
                "username": display_name
            })
            # Broadcast updated users list to remaining users
            await broadcast_users_list(current_channel)
            # Remove empty rooms
            if not chat_rooms[current_channel]:
                del chat_rooms[current_channel]

        # Clean up mutable state (only if no other WS for this user)
        has_other_ws = False
        for ch_users in chat_rooms.values():
            for entry in ch_users:
                if entry[1] == user_id and entry[0] != ws:
                    has_other_ws = True
                    break
            if has_other_ws:
                break
        if not has_other_ws:
            chat_user_state.pop(user_id, None)

        # Unsubscribe from notifications
        if user_id in notification_subscribers:
            notification_subscribers[user_id].discard(raw_ws)
            if not notification_subscribers[user_id]:
                del notification_subscribers[user_id]

        # Unregister from DM delivery
        if user_id in dm_user_connections:
            dm_user_connections[user_id].discard(raw_ws)
            if not dm_user_connections[user_id]:
                del dm_user_connections[user_id]

        logger.info(f"[Chat] User {username} disconnected")

    return raw_ws


async def http_voice_ice_servers(request: web.Request) -> web.Response:
    """Get ICE server configuration for WebRTC voice chat."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    ice_servers = []
    # STUN server
    if Config.STUN_SERVER:
        ice_servers.append({"urls": Config.STUN_SERVER})
    # TURN server (optional)
    if Config.TURN_SERVER:
        turn_entry = {"urls": Config.TURN_SERVER}
        if Config.TURN_USERNAME:
            turn_entry["username"] = Config.TURN_USERNAME
        if Config.TURN_PASSWORD:
            turn_entry["credential"] = Config.TURN_PASSWORD
        ice_servers.append(turn_entry)

    return web.json_response({"ice_servers": ice_servers})


# =========================================================================
# Direct Messages — REST Endpoints
# =========================================================================

async def http_get_dm_conversations(request: web.Request) -> web.Response:
    """Get all DM conversations for the current user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        limit = min(int(request.query.get("limit", "50")), 100)
        offset = max(int(request.query.get("offset", "0")), 0)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit or offset"}, status=400)
    convs = await db.get_dm_conversations(token.user_id, limit=limit, offset=offset)
    return web.json_response({"conversations": convs})


async def http_create_dm_conversation(request: web.Request) -> web.Response:
    """Create or find a DM conversation."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # 1:1 DM
    if "user_id" in data:
        try:
            target_id = int(data["user_id"])
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid user_id"}, status=400)
        if target_id == token.user_id:
            return web.json_response({"error": "Cannot DM yourself"}, status=400)
        target = await db.get_user_by_id(target_id)
        if not target:
            return web.json_response({"error": "User not found"}, status=404)
        conv = await db.create_dm_conversation(token.user_id, [target_id], conv_type="1on1")
        return web.json_response({"conversation": conv})

    # Group DM
    if "user_ids" in data:
        try:
            user_ids = [int(uid) for uid in data["user_ids"]]
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid user_ids"}, status=400)
        if token.user_id in user_ids:
            user_ids.remove(token.user_id)
        if not user_ids:
            return web.json_response({"error": "Need at least one other participant"}, status=400)
        if len(user_ids) > 9:
            return web.json_response({"error": "Max 10 participants (including you)"}, status=400)
        name = data.get("name", "").strip() or None
        conv = await db.create_dm_conversation(token.user_id, user_ids, name=name, conv_type="group")
        return web.json_response({"conversation": conv})

    return web.json_response({"error": "Provide user_id or user_ids"}, status=400)


async def http_get_dm_conversation(request: web.Request) -> web.Response:
    """Get a DM conversation with participants."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        conv_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid conversation ID"}, status=400)
    if not await db.is_dm_participant(conv_id, token.user_id):
        return web.json_response({"error": "Not a participant"}, status=403)
    conv = await db.get_dm_conversation(conv_id)
    if not conv:
        return web.json_response({"error": "Conversation not found"}, status=404)
    return web.json_response({"conversation": conv})


async def http_get_dm_messages(request: web.Request) -> web.Response:
    """Get messages for a DM conversation."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        conv_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid conversation ID"}, status=400)
    if not await db.is_dm_participant(conv_id, token.user_id):
        return web.json_response({"error": "Not a participant"}, status=403)
    try:
        limit = min(int(request.query.get("limit", "100")), 200)
        before_id = int(request.query["before_id"]) if "before_id" in request.query else None
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid parameters"}, status=400)
    messages = await db.get_dm_messages(conv_id, limit=limit, before_id=before_id)
    # Enrich with reactions
    msg_ids = [m["id"] for m in messages]
    reactions = await db.get_bulk_dm_reactions(msg_ids) if msg_ids else {}
    for m in messages:
        m["reactions"] = reactions.get(m["id"], [])
    return web.json_response({"messages": messages})


async def http_toggle_dm_mute(request: web.Request) -> web.Response:
    """Toggle mute for a DM conversation."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        conv_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid conversation ID"}, status=400)
    if not await db.is_dm_participant(conv_id, token.user_id):
        return web.json_response({"error": "Not a participant"}, status=403)
    try:
        data = await request.json()
        muted = bool(data.get("muted", False))
    except (json.JSONDecodeError, Exception):
        return web.json_response({"error": "Invalid JSON"}, status=400)
    await db.update_dm_mute(conv_id, token.user_id, muted)
    return web.json_response({"muted": muted})


async def http_leave_dm_conversation(request: web.Request) -> web.Response:
    """Leave a group DM conversation."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        conv_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid conversation ID"}, status=400)
    conv = await db.get_dm_conversation(conv_id)
    if not conv:
        return web.json_response({"error": "Conversation not found"}, status=404)
    if conv["type"] != "group":
        return web.json_response({"error": "Cannot leave a 1:1 DM"}, status=400)
    if not await db.is_dm_participant(conv_id, token.user_id):
        return web.json_response({"error": "Not a participant"}, status=403)
    await db.leave_dm_conversation(conv_id, token.user_id)
    return web.json_response({"left": True})


async def http_add_dm_participants(request: web.Request) -> web.Response:
    """Add participants to a group DM."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    try:
        conv_id = int(request.match_info["id"])
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid conversation ID"}, status=400)
    conv = await db.get_dm_conversation(conv_id)
    if not conv:
        return web.json_response({"error": "Conversation not found"}, status=404)
    if conv["type"] != "group":
        return web.json_response({"error": "Cannot add participants to a 1:1 DM"}, status=400)
    if not await db.is_dm_participant(conv_id, token.user_id):
        return web.json_response({"error": "Not a participant"}, status=403)
    try:
        data = await request.json()
        user_ids = [int(uid) for uid in data.get("user_ids", [])]
    except (json.JSONDecodeError, ValueError, TypeError):
        return web.json_response({"error": "Invalid JSON or user_ids"}, status=400)
    if not user_ids:
        return web.json_response({"error": "No user_ids provided"}, status=400)
    added = await db.add_dm_participants(conv_id, user_ids)
    if not added and user_ids:
        return web.json_response({"error": "Max 10 participants reached"}, status=400)
    return web.json_response({"added": added})


# =========================================================================
# Message Search — REST Endpoints
# =========================================================================

# Rate limiting for search: user_id -> list of timestamps
_search_rate_limits: dict[int, list[float]] = {}

async def http_search_messages(request: web.Request) -> web.Response:
    """Search messages across channels and DMs."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    query = request.query.get("q", "").strip()
    if len(query) < 2:
        return web.json_response({"error": "Query must be at least 2 characters"}, status=400)
    if len(query) > 200:
        return web.json_response({"error": "Query too long (max 200 chars)"}, status=400)

    # Rate limit: 10 searches per minute
    now = monotonic()
    user_times = _search_rate_limits.setdefault(token.user_id, [])
    user_times[:] = [t for t in user_times if now - t < 60]
    if len(user_times) >= 10:
        return web.json_response({"error": "Rate limit exceeded (10 searches/min)"}, status=429)
    user_times.append(now)
    # Prune stale entries for users who haven't searched recently
    for uid in [k for k, v in _search_rate_limits.items() if not v]:
        del _search_rate_limits[uid]

    scope = request.query.get("scope", "all")
    if scope not in ("all", "channels", "dms"):
        scope = "all"

    try:
        channel_id = int(request.query["channel_id"]) if "channel_id" in request.query else None
        conversation_id = int(request.query["conversation_id"]) if "conversation_id" in request.query else None
        limit = max(1, min(int(request.query.get("limit", "25")), 50))
        offset = max(int(request.query.get("offset", "0")), 0)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid parameters"}, status=400)

    from_user = request.query.get("from", None)
    has_image = request.query.get("has") == "image"
    before = request.query.get("before", None)
    after = request.query.get("after", None)

    results = await db.search_messages(
        query=query, user_id=token.user_id, scope=scope,
        channel_id=channel_id, conversation_id=conversation_id,
        from_user=from_user, has_image=has_image if has_image else None,
        before=before, after=after, limit=limit, offset=offset
    )
    results["query"] = query
    return web.json_response(results)


async def http_rebuild_search_index(request: web.Request) -> web.Response:
    """Rebuild FTS search indexes. Superadmin only."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    user = await db.get_user_by_id(token.user_id)
    if not user or user.get("role") != "superadmin":
        return web.json_response({"error": "Superadmin required"}, status=403)
    counts = await db.rebuild_search_index()
    return web.json_response({"rebuilt": True, "indexed": counts})


# =========================================================================
# Data Retention / Cleanup API
# =========================================================================

async def http_get_retention_config(request: web.Request) -> web.Response:
    """Get data retention configuration. Admin only."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    user = await db.get_user_by_id(token.user_id)
    if not user or not (user.get("is_admin") or user.get("role") in ("superadmin", "admin")):
        return web.json_response({"error": "Admin required"}, status=403)
    config = await db.get_retention_config()
    return web.json_response(config)


async def http_set_retention_config(request: web.Request) -> web.Response:
    """Update data retention configuration. Superadmin only."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    user = await db.get_user_by_id(token.user_id)
    if not user or user.get("role") != "superadmin":
        return web.json_response({"error": "Superadmin required"}, status=403)
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON"}, status=400)
    await db.set_retention_config(data)
    config = await db.get_retention_config()
    return web.json_response({"updated": True, "config": config})


async def http_run_cleanup_now(request: web.Request) -> web.Response:
    """Run data cleanup immediately. Superadmin only."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)
    user = await db.get_user_by_id(token.user_id)
    if not user or user.get("role") != "superadmin":
        return web.json_response({"error": "Superadmin required"}, status=403)
    config = await db.get_retention_config()
    results = {}
    errors = []
    try:
        chat_days = int(config.get("retention_chat_days", 7))
        if chat_days > 0:
            results["chat_messages"] = await db.cleanup_old_chat_messages(days=chat_days)
    except Exception as e:
        errors.append(f"chat: {e}")
    try:
        dm_days = int(config.get("retention_dm_days", 30))
        if dm_days > 0:
            results["dm_messages"] = await db.cleanup_old_dm_messages(days=dm_days)
    except Exception as e:
        errors.append(f"dm: {e}")
    try:
        notif_days = int(config.get("retention_notifications_days", 30))
        if notif_days > 0:
            results["notifications"] = await db.cleanup_old_notifications(days=notif_days)
    except Exception as e:
        errors.append(f"notifications: {e}")
    try:
        activity_max = int(config.get("retention_activity_max", 500))
        results["activity_log"] = await db.cleanup_old_activity_log(keep=activity_max)
    except Exception as e:
        errors.append(f"activity: {e}")
    try:
        results["expired_tokens"] = await db.cleanup_expired_tokens()
        results["expired_api_keys"] = await db.cleanup_expired_api_keys()
    except Exception as e:
        errors.append(f"tokens: {e}")
    try:
        logs_max = int(config.get("retention_service_logs_max", 1000))
        service_ids = await db.get_all_service_ids()
        svc_total = 0
        for sid in service_ids:
            svc_total += await db.clear_service_logs(sid, keep_recent=logs_max)
        results["service_logs"] = svc_total
    except Exception as e:
        errors.append(f"service_logs: {e}")
    try:
        if config.get("auto_vacuum", "true") == "true":
            await db.vacuum_database()
            results["vacuumed"] = True
    except Exception as e:
        errors.append(f"vacuum: {e}")
    resp = {"cleanup_complete": True, "deleted": results}
    if errors:
        resp["errors"] = errors
    return web.json_response(resp)


async def _broadcast_to_dm(conversation_id: int, message: dict, exclude_user_id: int = None):
    """Broadcast a message to all online participants of a DM conversation."""
    try:
        participants = await db.get_dm_participant_ids(conversation_id)
    except Exception:
        return
    for uid in participants:
        if uid == exclude_user_id:
            continue
        dead = set()
        for raw in dm_user_connections.get(uid, set()).copy():
            try:
                if not raw.closed:
                    await raw.send_json(message)
                else:
                    dead.add(raw)
            except Exception:
                dead.add(raw)
        if dead and uid in dm_user_connections:
            dm_user_connections[uid] -= dead


async def _send_dm_to_user(user_id: int, message: dict):
    """Send a message to all WebSocket connections for a specific user."""
    dead = set()
    for raw in dm_user_connections.get(user_id, set()).copy():
        try:
            if not raw.closed:
                await raw.send_json(message)
            else:
                dead.add(raw)
        except Exception:
            dead.add(raw)
    if dead and user_id in dm_user_connections:
        dm_user_connections[user_id] -= dead


async def broadcast_users_list(channel: str):
    """Broadcast the full users list to everyone in a channel."""
    if channel not in chat_rooms or not chat_rooms[channel]:
        return
    user_ids = [entry[1] for entry in chat_rooms[channel]]
    users_info = await db.get_users_status(list(set(user_ids)))
    users_list = []
    for u in users_info:
        avatar = {}
        if u.get("avatar"):
            try:
                avatar = json.loads(u["avatar"])
            except (json.JSONDecodeError, TypeError):
                pass
        voice_info = voice_state.get(channel, {}).get(u["id"], {})
        users_list.append({
            "user_id": u["id"],
            "username": "Anonymous" if u.get("chat_anonymous") else (u.get("nickname") or u["username"]),
            "nickname": u.get("nickname"),
            "status": u.get("status", "online"),
            "status_message": u.get("status_message"),
            "role": u.get("role", "user"),
            "anonymous": bool(u.get("chat_anonymous")),
            "avatar": avatar,
            "in_voice": bool(voice_info),
            "voice_muted": voice_info.get("muted", False),
            "voice_deafened": voice_info.get("deafened", False),
            "voice_speaking": voice_info.get("speaking", False)
        })
    await broadcast_to_channel(channel, {
        "type": "users",
        "users": users_list
    })


async def broadcast_to_channel(channel: str, message: dict, exclude=None):
    """Broadcast a message to all users in a channel."""
    if channel not in chat_rooms:
        return

    dead_connections = set()
    for entry in chat_rooms[channel]:
        # Handle both old (3-tuple) and new (5-tuple) formats during transition
        ws = entry[0]
        if ws == exclude:
            continue
        try:
            if not ws.closed:
                await ws.send_json(message)
            else:
                dead_connections.add(entry)
        except Exception:
            dead_connections.add(entry)

    # Clean up dead connections
    chat_rooms[channel] -= dead_connections


async def send_notification(user_id: int, type: str, title: str,
                            message: str = "", data: dict = None):
    """Create a notification and push it to connected WebSockets."""
    notif_id = await db.create_notification(user_id, type, title, message, data)
    # Push to connected subscribers
    if user_id in notification_subscribers:
        dead = set()
        payload = {
            "type": "notification",
            "notification": {
                "id": notif_id,
                "type": type,
                "title": title,
                "message": message,
                "data": data or {},
                "is_read": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        }
        for ws in notification_subscribers[user_id]:
            try:
                if not ws.closed:
                    await ws.send_json(payload)
                else:
                    dead.add(ws)
            except Exception:
                dead.add(ws)
        notification_subscribers[user_id] -= dead


async def broadcast_notification(type: str, title: str, message: str = "",
                                  data: dict = None, exclude_user_id: int = None):
    """Send a notification to all users (e.g., stream went live)."""
    users = await db.get_all_users()
    for user in users:
        if user["id"] != exclude_user_id:
            await send_notification(user["id"], type, title, message, data)


async def http_get_notifications(request: web.Request) -> web.Response:
    """Get notifications for the current user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    unread_only = request.query.get("unread") == "1"
    try:
        limit = min(int(request.query.get("limit", "50")), 100)
        offset = max(int(request.query.get("offset", "0")), 0)
    except (ValueError, TypeError):
        return web.json_response({"error": "Invalid limit or offset parameter"}, status=400)
    notifications = await db.get_notifications(token.user_id, unread_only=unread_only,
                                                limit=limit, offset=offset)
    unread_count = await db.get_unread_notification_count(token.user_id)
    return web.json_response({"notifications": notifications, "unread_count": unread_count})


async def http_mark_notification_read(request: web.Request) -> web.Response:
    """Mark a notification as read."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    notif_id = request.match_info.get("id")
    if not notif_id or not notif_id.isdigit():
        return web.json_response({"error": "Invalid notification ID"}, status=400)

    await db.mark_notification_read(int(notif_id), token.user_id)
    return web.json_response({"success": True})


async def http_mark_all_notifications_read(request: web.Request) -> web.Response:
    """Mark all notifications as read."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    count = await db.mark_all_notifications_read(token.user_id)
    return web.json_response({"success": True, "count": count})


async def http_get_current_user(request: web.Request) -> web.Response:
    """Get current authenticated user info."""
    token = await authenticate_request(request)
    if not token:
        return web.json_response({"error": "Not authenticated"}, status=401)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    role = user.get("role") or ("admin" if user.get("is_admin") else "user")
    # Parse avatar JSON
    avatar = {}
    if user.get("avatar"):
        try:
            avatar = json.loads(user["avatar"])
        except (json.JSONDecodeError, TypeError):
            pass
    return web.json_response({
        "id": user["id"],
        "username": user["username"],
        "nickname": user.get("nickname"),
        "status": user.get("status", "online"),
        "status_message": user.get("status_message"),
        "role": role,
        "chat_anonymous": bool(user.get("chat_anonymous")),
        "avatar": avatar,
        "is_admin": bool(user["is_admin"]),
        "scopes": token.scopes,
        "permissions": {
            "can_manage_users": get_role_level(role) >= get_role_level("moderator"),
            "can_reset_passwords": get_role_level(role) >= get_role_level("admin"),
            "can_delete_users": role == "superadmin",
            "manageable_roles": get_manageable_roles(role)
        }
    })


async def http_change_password(request: web.Request) -> web.Response:
    """Change the current user's password."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not current_password or not new_password:
        return web.json_response(
            {"error": "current_password and new_password required"},
            status=400
        )

    if len(new_password) < 8:
        return web.json_response(
            {"error": "New password must be at least 8 characters"},
            status=400
        )

    # Get user and verify current password
    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    if not verify_password(current_password, user["password_hash"]):
        logger.warning(f"Failed password change attempt for user {token.user_id}")
        return web.json_response({"error": "Current password is incorrect"}, status=401)

    # Update password
    new_hash = hash_password(new_password)
    await db.conn.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (new_hash, datetime.now(timezone.utc).isoformat(), token.user_id)
    )
    await db.conn.commit()

    logger.info(f"Password changed for user {token.user_id}")

    return web.json_response({"message": "Password changed successfully"})


async def http_update_user_status(request: web.Request) -> web.Response:
    """Update user's chat status."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    status = data.get("status")
    status_message = data.get("status_message", "")

    if not status:
        return web.json_response({"error": "status required"}, status=400)

    valid_statuses = ('online', 'away', 'busy', 'dnd', 'offline')
    if status not in valid_statuses:
        return web.json_response(
            {"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"},
            status=400
        )

    if status_message and len(status_message) > 100:
        return web.json_response({"error": "Status message too long (max 100 chars)"}, status=400)

    await db.set_user_status(token.user_id, status, status_message)

    # Broadcast status change to all chat rooms the user is in
    user = await db.get_user_by_id(token.user_id)
    username = user["username"] if user else "Unknown"
    for channel, users in chat_rooms.items():
        for entry in users:
            if entry[1] == token.user_id:
                await broadcast_to_channel(channel, {
                    "type": "user_status_changed",
                    "user_id": token.user_id,
                    "username": username,
                    "status": status,
                    "status_message": status_message
                })
                break

    return web.json_response({
        "status": status,
        "status_message": status_message
    })


async def http_update_user_nickname(request: web.Request) -> web.Response:
    """Update user's chat nickname."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    nickname = data.get("nickname", "").strip()

    # Validate nickname (allow empty to clear)
    if nickname:
        if len(nickname) < 2 or len(nickname) > 32:
            return web.json_response({"error": "Nickname must be 2-32 characters"}, status=400)
        # Only allow alphanumeric, spaces, underscores, dashes
        if not re.match(r'^[\w\s\-]+$', nickname):
            return web.json_response({"error": "Nickname can only contain letters, numbers, spaces, underscores and dashes"}, status=400)

    await db.set_user_nickname(token.user_id, nickname if nickname else None)

    # Update live WS handler state immediately
    if token.user_id in chat_user_state:
        chat_user_state[token.user_id]["nickname"] = nickname if nickname else None

    # Broadcast nickname change to all chat rooms
    user = await db.get_user_by_id(token.user_id)
    username = user["username"] if user else "Unknown"
    for channel, users in chat_rooms.items():
        for entry in users:
            if entry[1] == token.user_id:
                await broadcast_to_channel(channel, {
                    "type": "user_nickname_changed",
                    "user_id": token.user_id,
                    "username": username,
                    "nickname": nickname if nickname else None
                })
                break

    return web.json_response({
        "nickname": nickname if nickname else None
    })


async def http_update_chat_anonymous(request: web.Request) -> web.Response:
    """Update user's chat anonymous mode (hide username)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    anonymous = bool(data.get("anonymous", False))

    await db.set_chat_anonymous(token.user_id, anonymous)

    # Update live WS handler state immediately
    if token.user_id in chat_user_state:
        chat_user_state[token.user_id]["anonymous"] = anonymous

    # Broadcast change to all chat rooms
    user = await db.get_user_by_id(token.user_id)
    username = user["username"] if user else "Unknown"
    nickname = chat_user_state.get(token.user_id, {}).get("nickname")
    display_name = "Anonymous" if anonymous else (nickname or username)
    for channel, users in chat_rooms.items():
        for entry in users:
            if entry[1] == token.user_id:
                await broadcast_to_channel(channel, {
                    "type": "user_anonymous_changed",
                    "user_id": token.user_id,
                    "username": display_name,
                    "anonymous": anonymous
                })
                break

    return web.json_response({
        "anonymous": anonymous
    })


async def http_update_avatar(request: web.Request) -> web.Response:
    """Update user's avatar settings."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Validate avatar settings
    avatar = {}
    if "color" in data:
        color = data["color"]
        # Validate hex color
        if not isinstance(color, str) or not color.startswith("#") or len(color) != 7:
            return web.json_response({"error": "Invalid color format. Use #RRGGBB"}, status=400)
        avatar["color"] = color

    if "emoji" in data:
        emoji = data["emoji"]
        if emoji and len(emoji) > 4:  # Emoji can be up to 4 chars with modifiers
            return web.json_response({"error": "Invalid emoji"}, status=400)
        avatar["emoji"] = emoji if emoji else None

    if "initials" in data:
        initials = data["initials"].upper()[:2] if data["initials"] else None
        avatar["initials"] = initials

    await db.set_avatar(token.user_id, avatar)

    # Update live WS handler state immediately
    if token.user_id in chat_user_state:
        chat_user_state[token.user_id]["avatar"] = avatar

    # Broadcast avatar change to all chat rooms
    user = await db.get_user_by_id(token.user_id)
    username = user["username"] if user else "Unknown"
    for channel, users in chat_rooms.items():
        for entry in users:
            if entry[1] == token.user_id:
                await broadcast_to_channel(channel, {
                    "type": "user_avatar_changed",
                    "user_id": token.user_id,
                    "username": username,
                    "avatar": avatar
                })
                break

    return web.json_response({"avatar": avatar})


# =============================================================================
# Two-Factor Authentication Endpoints
# =============================================================================

async def http_2fa_status(request: web.Request) -> web.Response:
    """Get 2FA status for current user."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    backup_codes_remaining = 0
    if user.get("backup_codes"):
        backup_codes_remaining = len([c for c in user["backup_codes"].split(",") if c])

    logger.debug(f"2FA status checked for user {token.user_id}")

    return web.json_response({
        "enabled": bool(user.get("totp_enabled")),
        "backup_codes_remaining": backup_codes_remaining
    })


async def http_2fa_setup(request: web.Request) -> web.Response:
    """Start 2FA setup - generate secret and return provisioning URI."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    if user.get("totp_enabled"):
        return web.json_response({"error": "2FA is already enabled"}, status=400)

    # Generate new TOTP secret
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user["username"], Config.TOTP_ISSUER)

    # Store secret temporarily (not enabled yet until verified)
    await db.set_user_totp_secret(token.user_id, secret)

    logger.info(f"2FA setup initiated for user {token.user_id}")

    return web.json_response({
        "secret": secret,
        "uri": uri,
        "issuer": Config.TOTP_ISSUER
    })


async def http_2fa_verify(request: web.Request) -> web.Response:
    """Verify TOTP code and enable 2FA."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    code = data.get("code")
    if not code:
        return web.json_response({"error": "Verification code required"}, status=400)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    if user.get("totp_enabled"):
        return web.json_response({"error": "2FA is already enabled"}, status=400)

    secret = user.get("totp_secret")
    if not secret:
        return web.json_response(
            {"error": "2FA not set up. Call /api/user/2fa/setup first"},
            status=400
        )

    # Verify the code
    if not verify_totp(secret, code):
        logger.warning(f"Invalid 2FA verification code for user {token.user_id}")
        return web.json_response({"error": "Invalid verification code"}, status=400)

    # Generate backup codes and enable 2FA
    backup_codes = generate_backup_codes(10)
    await db.enable_user_totp(token.user_id, backup_codes)

    logger.info(f"2FA enabled for user {token.user_id}")

    return web.json_response({
        "status": "enabled",
        "backup_codes": backup_codes,
        "message": "2FA enabled successfully. Save your backup codes securely."
    })


async def http_2fa_disable(request: web.Request) -> web.Response:
    """Disable 2FA (requires password confirmation)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    password = data.get("password")
    if not password:
        return web.json_response({"error": "Password required to disable 2FA"}, status=400)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    if not user.get("totp_enabled"):
        return web.json_response({"error": "2FA is not enabled"}, status=400)

    # Verify password
    if not verify_password(password, user["password_hash"]):
        logger.warning(f"Failed 2FA disable attempt for user {token.user_id} - wrong password")
        return web.json_response({"error": "Invalid password"}, status=401)

    # Disable 2FA
    await db.disable_user_totp(token.user_id)

    logger.info(f"2FA disabled for user {token.user_id}")

    return web.json_response({
        "status": "disabled",
        "message": "Two-factor authentication has been disabled"
    })


async def get_user_role_from_token(token) -> str:
    """Get the role of the user from their token."""
    user = await db.get_user_by_id(token.user_id)
    if not user:
        return "user"
    return user.get("role") or ("admin" if user.get("is_admin") else "user")


async def http_list_users(request: web.Request) -> web.Response:
    """List all users (moderator+ only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    actor_role = await get_user_role_from_token(token)
    if get_role_level(actor_role) < get_role_level("moderator"):
        return forbidden_response(request)

    users = await db.get_all_users()

    return web.json_response({
        "users": [
            {
                "id": u["id"],
                "username": u["username"],
                "role": u.get("role", "user"),
                "is_admin": bool(u.get("is_admin")),
                "created_at": u["created_at"]
            }
            for u in users
        ],
        "actor_role": actor_role,
        "manageable_roles": get_manageable_roles(actor_role)
    })


async def http_update_user_role(request: web.Request) -> web.Response:
    """Update user role (requires appropriate permissions).

    Permission rules:
    - superadmin: can assign any role (admin, moderator, user)
    - admin: can assign moderator, user
    - moderator: can assign user only
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    actor_role = await get_user_role_from_token(token)
    if get_role_level(actor_role) < get_role_level("moderator"):
        return forbidden_response(request)

    user_id = request.match_info.get("id")
    if not user_id or not user_id.isdigit():
        return web.json_response({"error": "Invalid user ID"}, status=400)

    user_id = int(user_id)

    # Don't allow modifying yourself
    if user_id == token.user_id:
        return web.json_response(
            {"error": "Cannot modify your own role"},
            status=400
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    new_role = data.get("role")

    # Handle legacy is_admin field for backward compatibility
    if new_role is None and "is_admin" in data:
        new_role = "admin" if data["is_admin"] else "user"

    if not new_role:
        return web.json_response({"error": "role field required"}, status=400)

    if new_role not in ROLE_HIERARCHY:
        return web.json_response(
            {"error": f"Invalid role. Must be one of: {', '.join(ROLE_HIERARCHY)}"},
            status=400
        )

    target_user = await db.get_user_by_id(user_id)
    if not target_user:
        return web.json_response({"error": "User not found"}, status=404)

    target_role = target_user.get("role") or ("admin" if target_user.get("is_admin") else "user")

    # Check if actor can manage the target user
    if not can_manage_role(actor_role, target_role):
        return web.json_response(
            {"error": f"You cannot modify users with role '{target_role}'"},
            status=403
        )

    # Check if actor can assign the new role
    if not can_assign_role(actor_role, new_role):
        return web.json_response(
            {"error": f"You cannot assign the role '{new_role}'"},
            status=403
        )

    await db.set_user_role(user_id, new_role)

    logger.info(f"Role changed for user {target_user['username']} from {target_role} to {new_role} by user {token.user_id}")

    return web.json_response({
        "id": user_id,
        "username": target_user["username"],
        "role": new_role,
        "is_admin": new_role in ("admin", "superadmin"),
        "message": f"Role updated to {new_role}"
    })


async def http_update_user_admin(request: web.Request) -> web.Response:
    """Legacy endpoint - redirects to role update."""
    return await http_update_user_role(request)


async def http_delete_user(request: web.Request) -> web.Response:
    """Delete a user (superadmin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    actor_role = await get_user_role_from_token(token)

    # Only superadmins can delete users
    if actor_role != "superadmin":
        return web.json_response(
            {"error": "Only superadmins can delete users"},
            status=403
        )

    user_id = request.match_info.get("id")
    if not user_id or not user_id.isdigit():
        return web.json_response({"error": "Invalid user ID"}, status=400)

    user_id = int(user_id)

    # Don't allow deleting yourself
    if user_id == token.user_id:
        return web.json_response(
            {"error": "Cannot delete your own account"},
            status=400
        )

    target_user = await db.get_user_by_id(user_id)
    if not target_user:
        return web.json_response({"error": "User not found"}, status=404)

    # Superadmins can delete anyone (except themselves, checked above)
    target_role = target_user.get("role") or ("admin" if target_user.get("is_admin") else "user")

    # Delete user's tokens first
    await db.conn.execute("DELETE FROM tokens WHERE user_id = ?", (user_id,))
    # Delete the user
    await db.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.conn.commit()

    logger.info(f"User {target_user['username']} deleted by superadmin {token.user_id}")

    return web.json_response({
        "message": f"User '{target_user['username']}' deleted"
    })


async def http_reset_user_password(request: web.Request) -> web.Response:
    """Reset a user's password (admin+ for managed users, moderator for self only).

    Permission rules:
    - superadmin: can reset any user's password (including other superadmins)
    - admin: can reset moderator and user passwords
    - moderator: can only reset their own password via /api/me/password
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    actor_role = await get_user_role_from_token(token)
    if get_role_level(actor_role) < get_role_level("admin"):
        return web.json_response(
            {"error": "Only admins and superadmins can reset passwords"},
            status=403
        )

    user_id = request.match_info.get("id")
    if not user_id or not user_id.isdigit():
        return web.json_response({"error": "Invalid user ID"}, status=400)

    user_id = int(user_id)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    new_password = data.get("new_password")
    if not new_password:
        return web.json_response({"error": "new_password required"}, status=400)

    if len(new_password) < 8:
        return web.json_response(
            {"error": "Password must be at least 8 characters"},
            status=400
        )

    target_user = await db.get_user_by_id(user_id)
    if not target_user:
        return web.json_response({"error": "User not found"}, status=404)

    target_role = target_user.get("role") or ("admin" if target_user.get("is_admin") else "user")

    # Check if actor can manage the target user
    if not can_manage_role(actor_role, target_role):
        return web.json_response(
            {"error": f"You cannot reset passwords for users with role '{target_role}'"},
            status=403
        )

    # Hash and save new password
    new_hash = hash_password(new_password)
    await db.reset_user_password(user_id, new_hash)

    logger.info(f"Password reset for user {target_user['username']} by {actor_role} {token.user_id}")

    return web.json_response({
        "message": f"Password reset for user '{target_user['username']}'"
    })


# =============================================================================
# Application Setup
# =============================================================================

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    """Add security headers to all responses."""
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        # HTTPException (redirects, 404s, etc.) are also Response objects.
        # Catch them so we can add security headers before returning.
        response = exc

    # HSTS - Enforce HTTPS for 1 year, include subdomains
    response.headers.setdefault('Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload')

    # Prevent clickjacking
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')

    # Prevent MIME type sniffing
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')

    # Enable XSS filter in older browsers
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')

    # Referrer policy
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')

    # Permissions policy - restrict sensitive features
    response.headers.setdefault('Permissions-Policy',
        'geolocation=(), microphone=(self), camera=(), payment=()')

    # Content Security Policy for HTML pages
    content_type = response.headers.get('Content-Type', '')
    if 'text/html' in content_type:
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net blob:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' wss:; "
            "media-src 'self' blob:; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers.setdefault('Content-Security-Policy', csp)

    # Suppress server version to prevent information leakage
    response.headers['Server'] = 'Open Relay Portal'

    return response


def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application(middlewares=[security_headers_middleware])

    # Authenticated uploads (must be registered before the static catch-all)
    app.router.add_get("/static/uploads/{path:.*}", http_authenticated_upload)

    # Static files (CSS, JS, HTML - public for login page)
    app.router.add_static("/static", STATIC_DIR)

    # HTTP API routes
    app.router.add_get("/health", http_health)
    app.router.add_get("/favicon.ico", http_favicon)
    app.router.add_get("/api/stats", http_stats)
    app.router.add_get("/api/stats/public", http_public_stats)
    app.router.add_get("/api/system/health", http_system_health)
    app.router.add_get("/api/activity", http_activity_feed)
    app.router.add_get("/api/plugins", http_list_plugins)
    app.router.add_get("/api/shells", http_list_shells)
    app.router.add_get("/api/tunnels", http_get_tunnel_sessions)

    # Token management
    app.router.add_post("/api/token", http_create_token)
    app.router.add_post("/api/token/revoke", http_revoke_token)
    app.router.add_get("/api/tokens", http_list_tokens)

    # Unified service management (proxy routes + managed processes)
    app.router.add_get("/api/services", http_list_services)
    app.router.add_post("/api/services", http_create_service)
    app.router.add_get("/api/services/types", http_get_service_types)
    app.router.add_get("/api/services/{id}", http_get_service)
    app.router.add_put("/api/services/{id}", http_update_service)
    app.router.add_delete("/api/services/{id}", http_delete_service)
    app.router.add_get("/api/services/{id}/health", http_service_health)
    app.router.add_post("/api/services/{id}/start", http_start_service)
    app.router.add_post("/api/services/{id}/stop", http_stop_service)
    app.router.add_post("/api/services/{id}/restart", http_restart_service)
    app.router.add_get("/api/services/{id}/logs", http_get_service_logs)

    # Managed services (DEPRECATED - use /api/services with service_type=managed)
    app.router.add_get("/api/managed-services/types", http_get_managed_service_types)
    app.router.add_get("/api/managed-services", http_list_managed_services)
    app.router.add_post("/api/managed-services", http_create_managed_service)
    app.router.add_get("/api/managed-services/{id}", http_get_managed_service)
    app.router.add_put("/api/managed-services/{id}", http_update_managed_service)
    app.router.add_delete("/api/managed-services/{id}", http_delete_managed_service)
    app.router.add_post("/api/managed-services/{id}/start", http_start_managed_service)
    app.router.add_post("/api/managed-services/{id}/stop", http_stop_managed_service)
    app.router.add_post("/api/managed-services/{id}/restart", http_restart_managed_service)
    app.router.add_get("/api/managed-services/{id}/status", http_managed_service_status)
    app.router.add_get("/api/managed-services/{id}/logs", http_managed_service_logs)

    # User management
    app.router.add_get("/api/users", http_list_users)
    app.router.add_post("/api/users", http_create_user)
    app.router.add_put("/api/users/{id}/admin", http_update_user_admin)  # Legacy endpoint
    app.router.add_put("/api/users/{id}/role", http_update_user_role)
    app.router.add_post("/api/users/{id}/reset-password", http_reset_user_password)
    app.router.add_delete("/api/users/{id}", http_delete_user)
    app.router.add_get("/api/me", http_get_current_user)
    app.router.add_post("/api/me/password", http_change_password)
    app.router.add_put("/api/me/status", http_update_user_status)
    app.router.add_put("/api/me/nickname", http_update_user_nickname)
    app.router.add_put("/api/me/anonymous", http_update_chat_anonymous)
    app.router.add_put("/api/me/avatar", http_update_avatar)

    # Notifications
    app.router.add_get("/api/notifications", http_get_notifications)
    app.router.add_post("/api/notifications/read-all", http_mark_all_notifications_read)
    app.router.add_post("/api/notifications/{id}/read", http_mark_notification_read)

    # Two-Factor Authentication
    app.router.add_get("/api/user/2fa/status", http_2fa_status)
    app.router.add_post("/api/user/2fa/setup", http_2fa_setup)
    app.router.add_post("/api/user/2fa/verify", http_2fa_verify)
    app.router.add_post("/api/user/2fa/disable", http_2fa_disable)

    # Registration (public with invite code)
    app.router.add_post("/api/register", http_register)
    app.router.add_get("/api/invite-code", http_get_invite_code)

    # Invite code management (admin only)
    app.router.add_post("/api/admin/invite-codes", http_create_invite_code)
    app.router.add_delete("/api/admin/invite-codes/{id}", http_deactivate_invite_code)
    app.router.add_get("/api/admin/invite-codes/{id}/registrations", http_get_invite_code_registrations)

    # Logging (admin only)
    app.router.add_get("/api/logs", http_get_logs)
    app.router.add_get("/api/logs/files", http_get_log_files)
    app.router.add_get("/api/logs/settings", http_get_log_settings)
    app.router.add_put("/api/logs/settings", http_update_log_settings)

    # SSH Keys
    app.router.add_post("/api/ssh-keys", http_create_ssh_key)
    app.router.add_get("/api/ssh-keys", http_list_ssh_keys)
    app.router.add_get("/api/ssh-keys/all", http_admin_list_all_keys)
    app.router.add_get("/api/ssh-keys/authorized", http_get_authorized_keys)
    app.router.add_get("/api/ssh-keys/{id}", http_get_ssh_key)
    app.router.add_delete("/api/ssh-keys/{id}", http_delete_ssh_key)

    # API Keys
    app.router.add_post("/api/api-keys", http_create_api_key)
    app.router.add_get("/api/api-keys", http_list_api_keys)
    app.router.add_post("/api/api-keys/{id}/revoke", http_revoke_api_key)
    app.router.add_delete("/api/api-keys/{id}", http_delete_api_key)

    # User Connections
    app.router.add_get("/api/connections/types", http_get_connection_types)
    app.router.add_post("/api/connections", http_create_user_connection)
    app.router.add_get("/api/connections", http_list_user_connections)
    app.router.add_get("/api/connections/{id}", http_get_user_connection)
    app.router.add_put("/api/connections/{id}", http_update_user_connection)
    app.router.add_delete("/api/connections/{id}", http_delete_user_connection)
    app.router.add_post("/api/connections/{id}/pin", http_toggle_connection_pin)
    app.router.add_get("/api/connections/{id}/connect", http_connect_user_connection)

    # User Streams (OBS/RTMP streaming)
    app.router.add_get("/api/streams", http_list_user_streams)
    app.router.add_post("/api/streams", http_create_user_stream)
    app.router.add_get("/api/streams/public", http_get_public_streams)
    app.router.add_get("/api/streams/open", http_get_open_streams)
    app.router.add_get("/api/streams/{id}", http_get_user_stream)
    app.router.add_put("/api/streams/{id}", http_update_user_stream)
    app.router.add_delete("/api/streams/{id}", http_delete_user_stream)
    app.router.add_post("/api/streams/{id}/regenerate-key", http_regenerate_stream_key)
    app.router.add_post("/api/streams/{id}/rtmp-token", http_create_rtmp_token)
    # Stream thumbnails
    app.router.add_post("/api/streams/{id}/thumbnail", http_upload_stream_thumbnail)
    app.router.add_delete("/api/streams/{id}/thumbnail", http_delete_stream_thumbnail)
    # Stream moderation (owner can ban users from stream chat)
    app.router.add_get("/api/streams/{id}/bans", http_get_stream_bans)
    app.router.add_post("/api/streams/{id}/bans", http_create_stream_ban)
    app.router.add_delete("/api/streams/{id}/bans/{user_id}", http_remove_stream_ban)
    # MediaMTX hooks
    app.router.add_post("/api/stream/auth", http_stream_auth)
    app.router.add_post("/api/stream/event", http_stream_event)

    # Stream Proxy API (routes all MediaMTX traffic through port 443)
    app.router.add_get("/api/stream/{stream_key}/info", http_stream_info)
    app.router.add_get("/api/stream/{stream_key}/thumbnail", http_stream_thumbnail)
    app.router.add_get("/api/stream/{stream_key}/hls/{path:.*}", http_stream_hls_proxy)
    app.router.add_post("/api/stream/{stream_key}/webrtc/whep", http_stream_webrtc_whep)
    app.router.add_post("/api/stream/{stream_key}/webrtc/whip", http_stream_webrtc_whip)
    app.router.add_patch("/api/stream/{stream_key}/webrtc/session/{session_id}", http_stream_webrtc_session)
    app.router.add_delete("/api/stream/{stream_key}/webrtc/session/{session_id}", http_stream_webrtc_session)

    # Traffic Metrics (admin only)
    app.router.add_get("/api/metrics", http_get_metrics_summary)
    app.router.add_get("/api/metrics/services", http_get_metrics_services)
    app.router.add_get("/api/metrics/active", http_get_metrics_active)
    app.router.add_get("/api/metrics/timeseries", http_get_metrics_time_series)
    app.router.add_get("/api/metrics/top", http_get_metrics_top)

    # Shodan Integration (admin only)
    app.router.add_get("/api/shodan/info", http_shodan_api_info)
    app.router.add_post("/api/shodan/api-key", http_shodan_set_api_key)
    app.router.add_get("/api/shodan/lookup/{ip}", http_shodan_lookup)
    app.router.add_get("/api/shodan/search", http_shodan_search)

    # VOD Manager
    app.router.add_get("/api/vods/storage", http_get_vod_storage)
    app.router.add_post("/api/vods/storage", http_save_vod_storage)
    app.router.add_delete("/api/vods/storage", http_delete_vod_storage)
    app.router.add_post("/api/vods/storage/test", http_test_vod_storage)
    app.router.add_get("/api/vods", http_list_vods)
    app.router.add_get("/api/vods/download/{filename:.*}", http_download_vod)
    app.router.add_post("/api/vods/download-archive", http_download_vod_archive)
    app.router.add_delete("/api/vods/{filename:.*}", http_delete_vod)

    # Vulnerability Scanner (admin only)
    app.router.add_get("/api/vuln/scan/{host}", http_vuln_scan_host)
    app.router.add_get("/api/vuln/scan-service/{service_id}", http_vuln_scan_service)
    app.router.add_get("/api/vuln/cve/{cve_id}", http_vuln_lookup_cve)
    app.router.add_get("/api/vuln/mitigations/{cve_id}", http_vuln_get_mitigations)
    app.router.add_get("/api/vuln/known-cves", http_vuln_known_cves)
    app.router.add_get("/api/vuln/search", http_vuln_search_cves)
    app.router.add_get("/api/vuln/status", http_vuln_scanner_status)
    app.router.add_post("/api/vuln/nvd-api-key", http_vuln_set_nvd_api_key)

    # Certificate Management (admin only)
    app.router.add_get("/api/certs/info", http_get_cert_info)
    app.router.add_post("/api/certs/upload", http_upload_cert)
    app.router.add_post("/api/certs/self-signed", http_generate_selfsigned)
    app.router.add_post("/api/certs/letsencrypt", http_trigger_letsencrypt)
    app.router.add_post("/api/certs/apply", http_apply_certs)

    # Server Settings (admin only)
    app.router.add_get("/api/settings/hostname", http_get_server_hostname)
    app.router.add_put("/api/settings/hostname", http_update_server_hostname)

    # System Monitor (admin only)
    app.router.add_get("/api/sysmon/processes", http_sysmon_processes)
    app.router.add_get("/api/sysmon/processes/{pid}", http_sysmon_process_detail)
    app.router.add_post("/api/sysmon/processes/{pid}/kill", http_sysmon_kill_process)
    app.router.add_get("/api/sysmon/services", http_sysmon_services)
    app.router.add_get("/api/sysmon/services/{name}", http_sysmon_service_status)
    app.router.add_get("/api/sysmon/services/{name}/logs", http_sysmon_service_logs)
    app.router.add_post("/api/sysmon/services/{name}/control", http_sysmon_service_control)
    app.router.add_get("/api/sysmon/network", http_sysmon_network)
    app.router.add_get("/api/sysmon/ports", http_sysmon_ports)

    # File Manager (admin only)
    app.router.add_get("/api/files/list", http_list_files)
    app.router.add_get("/api/files/info", http_file_info)
    app.router.add_get("/api/files/read", http_read_file)
    app.router.add_get("/api/files/download", http_download_file)
    app.router.add_post("/api/files/upload", http_upload_file)
    app.router.add_post("/api/files/write", http_write_file)
    app.router.add_post("/api/files/mkdir", http_mkdir)
    app.router.add_post("/api/files/rename", http_rename_file)
    app.router.add_delete("/api/files/delete", http_delete_file)

    # SFTP Browser (per-user)
    # VOD Storage SFTP (must be before {conn_id} routes)
    app.router.add_get("/api/sftp/vod/list", http_sftp_vod_list)
    app.router.add_get("/api/sftp/vod/read", http_sftp_vod_read)
    app.router.add_get("/api/sftp/vod/download", http_sftp_vod_download)
    app.router.add_post("/api/sftp/vod/mkdir", http_sftp_vod_mkdir)
    app.router.add_post("/api/sftp/vod/upload", http_sftp_vod_upload)
    app.router.add_post("/api/sftp/vod/write", http_sftp_vod_write)
    app.router.add_post("/api/sftp/vod/rename", http_sftp_vod_rename)
    app.router.add_delete("/api/sftp/vod/delete", http_sftp_vod_delete)

    app.router.add_get("/api/sftp/{conn_id}/list", http_sftp_list)
    app.router.add_get("/api/sftp/{conn_id}/read", http_sftp_read)
    app.router.add_get("/api/sftp/{conn_id}/download", http_sftp_download)
    app.router.add_post("/api/sftp/{conn_id}/upload", http_sftp_upload)
    app.router.add_post("/api/sftp/{conn_id}/write", http_sftp_write)
    app.router.add_post("/api/sftp/{conn_id}/mkdir", http_sftp_mkdir)
    app.router.add_post("/api/sftp/{conn_id}/rename", http_sftp_rename)
    app.router.add_delete("/api/sftp/{conn_id}/delete", http_sftp_delete)

    # Web UI routes
    app.router.add_get("/live", http_live_page)
    app.router.add_get("/login", http_login_page)
    app.router.add_post("/login", http_login_submit)
    app.router.add_get("/logout", http_logout)
    app.router.add_get("/dashboard", http_dashboard)
    app.router.add_get("/terminal/{service_id}", http_terminal_page)
    app.router.add_get("/vnc/{service_id}", http_vnc_page)
    app.router.add_get("/media/{service_id}", http_media_page)
    app.router.add_get("/spice/{service_id}", http_spice_page)
    app.router.add_get("/proxmox/{service_id}", http_proxmox_page)
    app.router.add_get("/github/{service_id}", http_github_page)
    app.router.add_get("/admin", http_admin_page)
    app.router.add_get("/admin/", http_admin_page)  # Handle trailing slash
    app.router.add_get("/docs", http_api_docs_page)
    app.router.add_get("/api-docs", http_api_docs_page)  # Alias
    app.router.add_get("/about", http_about_page)
    app.router.add_get("/guides", http_guides_page)
    app.router.add_get("/files", http_files_page)
    app.router.add_get("/sysmon", http_sysmon_page)
    app.router.add_get("/chat", http_chat_page)
    app.router.add_get("/streams", http_streams_page)
    app.router.add_get("/watch/{id}", http_watch_stream_page)

    # Chat API
    app.router.add_get("/api/chat/channels", http_get_chat_channels)
    app.router.add_post("/api/chat/channels", http_create_chat_channel)
    app.router.add_put("/api/chat/channels/{id}", http_update_chat_channel)
    app.router.add_delete("/api/chat/channels/{id}", http_delete_chat_channel)
    app.router.add_post("/api/chat/channels/{id}/clear", http_clear_chat_channel)
    app.router.add_post("/api/chat/upload", http_upload_chat_image)
    app.router.add_get("/api/chat/link-preview", http_link_preview)
    app.router.add_get("/api/chat/thread/{id}", http_get_chat_thread)

    # Voice chat
    app.router.add_get("/api/voice/ice-servers", http_voice_ice_servers)

    # Direct Messages
    app.router.add_get("/api/dm/conversations", http_get_dm_conversations)
    app.router.add_post("/api/dm/conversations", http_create_dm_conversation)
    app.router.add_get("/api/dm/conversations/{id}", http_get_dm_conversation)
    app.router.add_get("/api/dm/conversations/{id}/messages", http_get_dm_messages)
    app.router.add_post("/api/dm/conversations/{id}/mute", http_toggle_dm_mute)
    app.router.add_post("/api/dm/conversations/{id}/leave", http_leave_dm_conversation)
    app.router.add_post("/api/dm/conversations/{id}/participants", http_add_dm_participants)

    # Message Search
    app.router.add_get("/api/chat/search", http_search_messages)
    app.router.add_post("/api/chat/search/rebuild", http_rebuild_search_index)

    # Data Retention
    app.router.add_get("/api/admin/retention", http_get_retention_config)
    app.router.add_put("/api/admin/retention", http_set_retention_config)
    app.router.add_post("/api/admin/retention/run", http_run_cleanup_now)

    # Root redirect (handles both HTTP and WebSocket upgrade)
    app.router.add_get("/", http_root_redirect)
    # Chat WebSocket (before catch-all)
    app.router.add_get("/ws/chat", handle_chat_websocket)
    # WebSocket endpoints - catch all paths for relay (must be last)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/ws/{path:.*}", websocket_handler)

    return app


class PortalServer:
    """Main Open Relay Portal server."""

    def __init__(self):
        self.runner = None
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the server."""
        # Validate configuration
        if Config.validate_or_warn():
            logger.error("Configuration errors detected. Please fix and restart.")
            sys.exit(1)

        # Initialize database
        await db.connect()
        logger.info(f"Database connected: {Config.DATABASE_PATH}")

        # Reset all streams to offline on startup (no stream can be live before MediaMTX starts)
        stale = await db.reset_all_streams_offline()
        if stale:
            logger.info(f"Reset {stale} stale stream(s) to offline")

        # Load persisted settings from database
        log_settings_json = await db.get_setting("log_settings")
        if log_settings_json:
            try:
                log_settings_data = json.loads(log_settings_json)
                update_log_settings(log_settings_data)
                logger.info("Log settings restored from database")
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Could not restore log settings: {e}")

        # Load and initialize plugins
        load_builtin_plugins()
        await initialize_plugins()
        logger.info("Plugins initialized")

        # Initialize Shodan client - check database first, then env var
        shodan_api_key = await db.get_setting("shodan_api_key") or Config.SHODAN_API_KEY
        if shodan_api_key:
            await init_shodan(shodan_api_key)
            Config.SHODAN_API_KEY = shodan_api_key  # Update Config for runtime checks
            shodan_client.set_api_key(shodan_api_key)  # Ensure client has the key
            logger.info("Shodan integration initialized (key from database)" if await db.get_setting("shodan_api_key") else "Shodan integration initialized (key from env)")

        # Start traffic metrics recorder
        if Config.METRICS_ENABLED:
            await start_metrics_recorder()
            logger.info("Traffic metrics recorder started")

        # Start unified data retention cleanup task
        asyncio.create_task(self._data_cleanup_task())

        # Start viewer count sync task (syncs MediaMTX reader counts every 10 seconds)
        asyncio.create_task(self._viewer_sync_task())

        # Start RTMP token cleanup task (runs every 5 minutes)
        asyncio.create_task(self._rtmp_token_cleanup_task())

        # Initialize vulnerability scanner - check database for NVD API key
        nvd_api_key = await db.get_setting("nvd_api_key") or Config.NVD_API_KEY
        await init_scanner(
            nvd_api_key=nvd_api_key or None,
            nmap_path=Config.NMAP_PATH,
            cache_ttl=Config.CVE_CACHE_TTL,
            timeout=Config.VULN_SCAN_TIMEOUT
        )
        if nvd_api_key:
            Config.NVD_API_KEY = nvd_api_key
        logger.info("Vulnerability scanner initialized")

        # Initialize managed services
        global _service_manager
        load_service_types()  # Load service type plugins
        _service_manager = await init_service_manager(db)
        logger.info("Managed services initialized")

        # Create SSL context
        ssl_context = create_ssl_context()
        logger.info("SSL context created")

        # Create and start application
        app = create_app()
        self.runner = web.AppRunner(app)
        await self.runner.setup()

        site = web.TCPSite(
            self.runner,
            Config.HOST,
            Config.PORT,
            ssl_context=ssl_context
        )
        await site.start()

        # Generate/log daily invite code (DB-backed + legacy file)
        invite_code = get_daily_invite_code()  # Legacy file-based
        # Seed daily code in DB (uses first admin user)
        try:
            cursor = await db.conn.execute(
                "SELECT id FROM users WHERE is_admin = 1 OR role IN ('admin', 'superadmin') LIMIT 1"
            )
            admin_row = await cursor.fetchone()
            if admin_row:
                db_daily_code = await db.ensure_daily_invite_code(admin_row["id"])
                logger.info(f"Daily invite code (DB): {db_daily_code}")
        except Exception as e:
            logger.warning(f"Failed to seed daily invite code in DB: {e}")
        logger.info(f"Daily invite code (legacy): {invite_code}")

        logger.info(f"Open Relay Portal started on https://{Config.HOSTNAME}:{Config.PORT}")
        logger.info("Endpoints:")
        logger.info(f"  - Health:     GET  /health")
        logger.info(f"  - Login:      GET  /login")
        logger.info(f"  - Dashboard:  GET  /dashboard")
        logger.info(f"  - Register:   POST /api/register (requires invite code)")
        logger.info(f"  - WebSocket:  wss://{Config.HOSTNAME}/ws/")

    async def _rtmp_token_cleanup_task(self) -> None:
        """Background task to clean up expired RTMP tokens (runs every 5 minutes)."""
        while True:
            try:
                await asyncio.sleep(5 * 60)  # 5 minutes
                deleted = await db.cleanup_expired_rtmp_tokens()
                if deleted > 0:
                    logger.debug(f"Cleaned up {deleted} expired RTMP token(s)")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"RTMP token cleanup error: {e}")

    async def _data_cleanup_task(self) -> None:
        """Unified data retention cleanup — interval configurable via settings."""
        while True:
            try:
                config = await db.get_retention_config()
                interval = max(1, int(config.get("cleanup_interval_hours", 6)))
                await asyncio.sleep(interval * 60 * 60)

                config = await db.get_retention_config()
                total = 0

                # Chat messages
                try:
                    chat_days = int(config.get("retention_chat_days", 7))
                    if chat_days > 0:
                        d = await db.cleanup_old_chat_messages(days=chat_days)
                        if d > 0:
                            logger.info(f"[Retention] Cleaned {d} chat messages older than {chat_days} days")
                        total += d
                except Exception as e:
                    logger.error(f"[Retention] Chat cleanup failed: {e}")

                # DM messages
                try:
                    dm_days = int(config.get("retention_dm_days", 30))
                    if dm_days > 0:
                        d = await db.cleanup_old_dm_messages(days=dm_days)
                        if d > 0:
                            logger.info(f"[Retention] Cleaned {d} DM messages older than {dm_days} days")
                        total += d
                except Exception as e:
                    logger.error(f"[Retention] DM cleanup failed: {e}")

                # Notifications
                try:
                    notif_days = int(config.get("retention_notifications_days", 30))
                    if notif_days > 0:
                        d = await db.cleanup_old_notifications(days=notif_days)
                        if d > 0:
                            logger.info(f"[Retention] Cleaned {d} notifications older than {notif_days} days")
                        total += d
                except Exception as e:
                    logger.error(f"[Retention] Notification cleanup failed: {e}")

                # Activity log
                try:
                    activity_max = int(config.get("retention_activity_max", 500))
                    d = await db.cleanup_old_activity_log(keep=activity_max)
                    if d > 0:
                        logger.info(f"[Retention] Trimmed {d} activity log entries (keeping {activity_max})")
                    total += d
                except Exception as e:
                    logger.error(f"[Retention] Activity log cleanup failed: {e}")

                # Expired tokens & API keys
                try:
                    d = await db.cleanup_expired_tokens()
                    total += d
                    d = await db.cleanup_expired_api_keys()
                    total += d
                except Exception as e:
                    logger.error(f"[Retention] Token cleanup failed: {e}")

                # Service logs
                try:
                    logs_max = int(config.get("retention_service_logs_max", 1000))
                    service_ids = await db.get_all_service_ids()
                    for sid in service_ids:
                        d = await db.clear_service_logs(sid, keep_recent=logs_max)
                        total += d
                except Exception as e:
                    logger.error(f"[Retention] Service log cleanup failed: {e}")

                # VACUUM
                try:
                    if config.get("auto_vacuum", "true") == "true":
                        await db.vacuum_database()
                except Exception as e:
                    logger.error(f"[Retention] VACUUM failed: {e}")

                if total > 0:
                    logger.info(f"[Retention] Cleanup complete: {total} total items removed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Retention] Cleanup error: {e}")

    async def _viewer_sync_task(self) -> None:
        """Background task to sync viewer counts from MediaMTX (runs every 10 seconds)."""
        while True:
            try:
                await asyncio.sleep(10)  # 10 seconds

                # Get MediaMTX API config
                mtx_config = await _get_mediamtx_config()
                if not mtx_config:
                    continue

                api_port = mtx_config.get("api_port", 9997)

                # Query MediaMTX paths API for reader counts
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://127.0.0.1:{api_port}/v3/paths/list",
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp:
                            if resp.status != 200:
                                continue
                            data = await resp.json()
                except Exception:
                    continue

                # Update viewer counts for each active path
                items = data.get("items") or []
                for item in items:
                    path_name = item.get("name", "")
                    readers = item.get("readers") or []
                    reader_count = len(readers)

                    # Path format is "live/{stream_key}"
                    if path_name.startswith("live/"):
                        stream_key = path_name[5:]  # Remove "live/" prefix

                        # Get current stream
                        stream = await db.get_stream_by_key(stream_key)
                        if stream and stream.get("is_live") == 1:
                            # Update viewer count directly
                            current_count = stream.get("viewer_count", 0)
                            if current_count != reader_count:
                                await db.conn.execute(
                                    "UPDATE user_streams SET viewer_count = ? WHERE id = ?",
                                    (reader_count, stream["id"])
                                )
                                await db.conn.commit()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Viewer sync] Error: {e}")

    async def stop(self) -> None:
        """Stop the server gracefully."""
        logger.info("Shutting down...")

        # Stop any active VOD recordings and upload to SFTP
        await stop_all_recordings()

        # Stop metrics recorder
        await stop_metrics_recorder()

        # Shutdown managed services (stops all running service processes)
        await shutdown_service_manager()
        logger.info("Managed services stopped")

        # Shutdown Shodan client
        await shutdown_shodan()

        # Shutdown vulnerability scanner
        await shutdown_scanner()

        # Shutdown plugins
        await shutdown_plugins()

        if self.runner:
            await self.runner.cleanup()

        await db.close()
        logger.info("Server stopped")

    async def run(self) -> None:
        """Run the server until shutdown signal."""
        await self.start()

        loop = asyncio.get_event_loop()

        def signal_handler():
            self._shutdown_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)

        await self._shutdown_event.wait()
        await self.stop()


# =============================================================================
# CLI Commands
# =============================================================================

async def init_admin_user() -> None:
    """Initialize admin user if not exists."""
    import secrets

    await db.connect()

    admin = await db.get_user_by_username("admin")
    if not admin:
        password = secrets.token_urlsafe(16)
        await create_user("admin", password, is_admin=True)
        # Write to secure file instead of stdout for security
        creds_file = Path(__file__).parent / "admin_credentials.txt"
        creds_file.write_text(f"Username: admin\nPassword: {password}\n")
        creds_file.chmod(0o600)  # Only owner can read
        logger.warning(f"Initial admin user created. Credentials saved to: {creds_file}")
        print(f"\n{'='*50}")
        print("INITIAL ADMIN USER CREATED")
        print(f"Username: admin")
        print(f"Credentials saved to: {creds_file}")
        print("IMPORTANT: Read and delete this file after noting the password!")
        print(f"{'='*50}\n")
    else:
        logger.info("Admin user already exists.")

    # Create default services if none exist
    services = await db.get_all_services()
    if not services:
        await db.create_service(
            name="Local Shell", path="/shell", plugin="terminal",
            host="localhost", port=0, config={},
            required_scopes=["admin"], icon="terminal",
            service_type="proxy", display_name="Local Shell",
            description="Admin local terminal access"
        )
        logger.info("Default Local Shell service created")
        print("Default service created: Local Shell")

    await db.close()


async def add_service_cli(
    name: str,
    path: str,
    host: str,
    plugin: str = "terminal",
    port: int = 0,
    scopes: str = ""
) -> None:
    """Add a service via CLI."""
    await db.connect()

    scope_list = [s.strip() for s in scopes.split(",") if s.strip()] if scopes else []
    service_id = await db.create_service(
        name=name,
        path=path,
        plugin=plugin,
        host=host,
        port=port,
        required_scopes=scope_list
    )
    print(f"Service '{name}' created with ID {service_id}")
    print(f"  Path: {path}")
    print(f"  Plugin: {plugin}")
    print(f"  Host: {host}")
    print(f"  Port: {port or 'N/A'}")
    print(f"  Required scopes: {scope_list or ['*']}")

    await db.close()


async def list_services_cli() -> None:
    """List all services via CLI."""
    await db.connect()

    services = await db.get_all_services()
    if not services:
        print("No services configured.")
    else:
        print(f"\n{'ID':<4} {'Name':<20} {'Plugin':<12} {'Path':<15} {'Host':<20} {'Port':<6} {'Scopes'}")
        print("-" * 100)
        for s in services:
            scopes = ",".join(s["required_scopes"]) or "*"
            host = s.get("host", "") or "localhost"
            port = s.get("port", 0) or "-"
            plugin = s.get("plugin", "tcp_tunnel")
            print(f"{s['id']:<4} {s['name']:<20} {plugin:<12} {s['path']:<15} {host:<20} {str(port):<6} {scopes}")

    await db.close()


def show_invite_code() -> None:
    """Show current daily invite code."""
    code = get_daily_invite_code()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Log securely (code is time-based so less sensitive than password)
    logger.info(f"Daily invite code requested for {today}")

    print(f"\n{'='*50}")
    print("PORTAL GATEWAY - DAILY INVITE CODE")
    print(f"{'='*50}")
    print(f"Date:    {today}")
    print(f"Code:    {code}")
    print(f"Expires: {today} 23:59:59 UTC")
    print(f"{'='*50}")
    print("\nUsers can register at POST /api/register with:")
    print('  {"username": "...", "password": "...", "invite_code": "<code>"}')
    print(f"{'='*50}\n")


async def set_admin_cli(username: str, remove: bool = False) -> None:
    """Set or remove admin status for a user."""
    await db.connect()

    user = await db.get_user_by_username(username)
    if not user:
        print(f"Error: User '{username}' not found")
        await db.close()
        return

    action = "Removing" if remove else "Granting"
    new_status = 0 if remove else 1

    if user["is_admin"] == new_status:
        status_word = "already" if new_status else "not"
        print(f"User '{username}' is {status_word} an admin")
        await db.close()
        return

    await db.conn.execute(
        "UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_status, user["id"])
    )
    await db.conn.commit()

    status_word = "removed from" if remove else "added to"
    print(f"User '{username}' has been {status_word} admin group")

    await db.close()


async def list_users_cli() -> None:
    """List all users."""
    await db.connect()

    async with db.conn.execute(
        "SELECT id, username, is_admin, created_at FROM users ORDER BY id"
    ) as cursor:
        rows = await cursor.fetchall()

    if not rows:
        print("No users found")
        await db.close()
        return

    print(f"\n{'ID':<5} {'Username':<20} {'Admin':<7} {'Created'}")
    print("-" * 60)
    for row in rows:
        admin_str = "Yes" if row["is_admin"] else "No"
        print(f"{row['id']:<5} {row['username']:<20} {admin_str:<7} {row['created_at']}")
    print(f"\nTotal: {len(rows)} users\n")

    await db.close()


def shell_cli(shell: str = None) -> None:
    """Start a local interactive shell."""
    import pty

    shell = shell or os.environ.get("SHELL", "/bin/bash")

    print(f"Starting shell: {shell}")
    print("Type 'exit' to quit.\n")

    try:
        pty.spawn(shell)
    except Exception as e:
        print(f"Error starting shell: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Open Relay Portal Server")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Serve
    subparsers.add_parser("serve", help="Start the server")

    # Init
    subparsers.add_parser("init", help="Initialize admin user")

    # Add service
    add_svc = subparsers.add_parser("add-service", help="Add a relay service")
    add_svc.add_argument("name", help="Service name")
    add_svc.add_argument("path", help="URL path (e.g., /myservice)")
    add_svc.add_argument("host", help="Target host (e.g., localhost, 192.168.1.100)")
    add_svc.add_argument("--plugin", default="terminal", help="Plugin type: terminal, ssh, vnc, http_proxy, tcp_tunnel")
    add_svc.add_argument("--port", type=int, default=0, help="Target port (e.g., 22 for SSH)")
    add_svc.add_argument("--scopes", default="", help="Required scopes (comma-separated)")

    # List services
    subparsers.add_parser("list-services", help="List all relay services")

    # Show invite code
    subparsers.add_parser("invite-code", help="Show current daily invite code")

    # Set admin status
    set_admin = subparsers.add_parser("set-admin", help="Set or remove admin status for a user")
    set_admin.add_argument("username", help="Username to modify")
    set_admin.add_argument("--remove", action="store_true", help="Remove admin status instead of granting it")

    # List users
    subparsers.add_parser("list-users", help="List all users")

    # Setup wizard
    subparsers.add_parser("setup", help="Interactive setup wizard")

    args = parser.parse_args()

    if args.command == "serve" or args.command is None:
        server = PortalServer()
        asyncio.run(server.run())
    elif args.command == "init":
        asyncio.run(init_admin_user())
    elif args.command == "add-service":
        asyncio.run(add_service_cli(args.name, args.path, args.host, args.plugin, args.port, args.scopes))
    elif args.command == "list-services":
        asyncio.run(list_services_cli())
    elif args.command == "invite-code":
        show_invite_code()
    elif args.command == "set-admin":
        asyncio.run(set_admin_cli(args.username, args.remove))
    elif args.command == "list-users":
        asyncio.run(list_users_cli())
    elif args.command == "setup":
        from setup import run_setup_wizard
        run_setup_wizard()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
