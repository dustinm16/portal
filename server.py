#!/usr/bin/env python3
"""Portal Gateway - Secure WebSocket Authentication and Relay Server."""

import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import uuid
import weakref
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Optional
from urllib.parse import parse_qs, urlparse

import aiohttp
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
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load certificates
    ssl_context.load_cert_chain(Config.SSL_CERT, Config.SSL_KEY)

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
    from datetime import datetime, timezone

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
    if not service_id:
        return web.json_response({"error": "Service ID required"}, status=400)

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
        import json as json_module
        updates["config"] = json_module.dumps(data["config"])

    # Managed service fields
    for field in ["display_name", "description", "binary_path", "working_dir"]:
        if field in data:
            updates[field] = data[field]
    if "ports" in data:
        import json as json_module
        updates["ports"] = json_module.dumps(data["ports"])

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
    limit = min(int(request.query.get("limit", 100)), 1000)
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
    if not validate_invite_code(invite_code):
        log_invite_code_usage(username, False, client_ip)
        logger.warning(f"Invalid invite code used for registration attempt: {username} from {client_ip}")
        return web.json_response(
            {"error": "Invalid or expired invite code"},
            status=403
        )

    try:
        user = await create_user(username, password, is_admin=False)
        log_invite_code_usage(username, True, client_ip)
        logger.info(f"User '{username}' registered with invite code from {client_ip}")
        return web.json_response({
            "id": user["id"],
            "username": user["username"],
            "message": "Registration successful"
        }, status=201)
    except Exception as e:
        logger.warning(f"Failed to register user '{username}': {e}")
        return web.json_response({"error": safe_error_message(e)}, status=400)


async def http_get_invite_code(request: web.Request) -> web.Response:
    """Get current invite code info (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # For admin, return the full code
    code = get_daily_invite_code()
    info = get_invite_code_info()
    info["code"] = code  # Full code for admins

    return web.json_response(info)


async def http_get_logs(request: web.Request) -> web.Response:
    """Get log file contents (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    # Get query params
    filename = request.query.get("file", "portal.log")
    lines = int(request.query.get("lines", 200))
    offset = int(request.query.get("offset", 0))

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
        user_id = int(user_id)
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
                from datetime import datetime, timezone, timedelta
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
CONNECTION_TYPES = {
    # Remote Access
    "ssh": {"name": "SSH Terminal", "icon": "terminal", "default_port": 22, "plugin": "ssh"},
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

    # Generic
    "custom": {"name": "Custom", "icon": "link", "default_port": None, "plugin": "tcp_tunnel"},
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

        return web.json_response({"connections": connections})
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

    return web.json_response(connection)


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

    # Preserve existing private_key if not provided but auth_method is 'key'
    config = data.get("config", {})
    if isinstance(config, dict) and config.get("auth_method") == "key" and not config.get("private_key"):
        # Fetch existing connection to preserve the key
        existing = await db.get_user_connection(int(conn_id), token.user_id)
        if existing:
            existing_config = existing.get("config", {})
            if isinstance(existing_config, str):
                existing_config = json.loads(existing_config) if existing_config else {}
            if existing_config.get("private_key"):
                config["private_key"] = existing_config["private_key"]
                data["config"] = config

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
    """Get a specific stream by ID.

    Key visibility rules:
    - Owner: sees both stream_key (for OBS) and public_key (for sharing)
    - Non-owner viewing public stream: sees public_key only (for playback)
    - Non-owner viewing private stream: no keys visible
    """
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    stream = await db.get_user_stream(int(stream_id))

    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    is_owner = stream["user_id"] == token.user_id
    is_public = stream.get("is_public", False)

    if not is_owner:
        # Always hide the private stream_key from non-owners
        stream.pop("stream_key", None)
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
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    # Get existing stream to check ownership
    stream = await db.get_user_stream(int(stream_id))
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

    success = await db.update_user_stream(int(stream_id), user_id=token.user_id, **data)
    if success:
        updated_stream = await db.get_user_stream(int(stream_id))
        return web.json_response({"stream": updated_stream})
    return web.json_response({"error": "Failed to update stream"}, status=500)


async def http_delete_user_stream(request: web.Request) -> web.Response:
    """Delete a stream (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")

    stream = await db.get_user_stream(int(stream_id))
    if not stream:
        return web.json_response({"error": "Stream not found"}, status=404)

    # Delete associated chat channel if exists
    if stream.get("chat_channel_id"):
        await db.delete_chat_channel(stream["chat_channel_id"])

    success = await db.delete_user_stream(int(stream_id), user_id=token.user_id)
    if success:
        return web.json_response({"success": True})
    return web.json_response({"error": "Not authorized or stream not found"}, status=403)


async def http_regenerate_stream_key(request: web.Request) -> web.Response:
    """Regenerate stream key (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")
    new_key = generate_stream_key()

    success = await db.regenerate_stream_key(int(stream_id), new_key, user_id=token.user_id)
    if success:
        return web.json_response({"stream_key": new_key})
    return web.json_response({"error": "Not authorized or stream not found"}, status=403)


async def http_upload_stream_thumbnail(request: web.Request) -> web.Response:
    """Upload a thumbnail for a stream (owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = request.match_info.get("id")

    # Get existing stream to check ownership
    stream = await db.get_user_stream(int(stream_id))
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
        await db.update_user_stream(int(stream_id), user_id=token.user_id, thumbnail_url=thumbnail_url)

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

    stream = await db.get_user_stream(int(stream_id))
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
    await db.update_user_stream(int(stream_id), user_id=token.user_id, thumbnail_url=None)

    return web.json_response({"success": True})


async def http_get_stream_bans(request: web.Request) -> web.Response:
    """Get all bans for a stream (stream owner only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    stream_id = int(request.match_info.get("id"))

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

    stream_id = int(request.match_info.get("id"))

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

    stream_id = int(request.match_info.get("id"))
    user_id = int(request.match_info.get("user_id"))

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

    # Remove private stream keys from public listing (security)
    # Keep public_key for playback URLs
    for stream in streams:
        stream.pop("stream_key", None)

    return web.json_response({"streams": streams})


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
        # Validate stream key
        if not stream_key or not stream_key.startswith("live_"):
            logger.warning(f"Invalid stream key attempt from {ip}")
            return web.json_response({"error": "Invalid stream key"}, status=401)

        stream = await db.get_stream_by_key(stream_key)
        if not stream:
            logger.warning(f"Unknown stream key from {ip}")
            return web.json_response({"error": "Invalid stream key"}, status=401)

        # Mark stream as live
        await db.set_stream_live(stream["id"], True)
        logger.info(f"Stream {stream['name']} started by user {stream['owner_username']} from {ip}")

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

        # For public streams, always allow
        return web.json_response({"allowed": True})

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
        # Find stream and mark as offline
        stream_key = path.split("/")[-1] if "/" in path else path
        stream = await db.get_stream_by_key(stream_key)
        if stream:
            await db.set_stream_live(stream["id"], False)
            logger.info(f"Stream {stream['name']} ended")

            # Clear chat history for the stream's channel
            if stream.get("chat_channel_id"):
                deleted = await db.clear_channel_messages(stream["chat_channel_id"])
                if deleted > 0:
                    logger.info(f"Cleared {deleted} chat messages for stream {stream['name']}")

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
    private_key = stream["stream_key"]
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
    host = request.headers.get("Host", "portal.dddvm.xyz")
    base_url = f"https://{host}"

    return web.json_response({
        "stream_key": full_stream_key,
        "name": stream.get("name", ""),
        "is_live": stream.get("is_live", False),
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

    return web.json_response({
        "services": traffic_metrics.get_all_service_metrics()
    })


async def http_get_metrics_active(request: web.Request) -> web.Response:
    """Get active connections with metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    return web.json_response({
        "connections": traffic_metrics.get_active_connections()
    })


async def http_get_metrics_time_series(request: web.Request) -> web.Response:
    """Get time series metrics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    hours = int(request.query.get("hours", "1"))
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

    limit = int(request.query.get("limit", "10"))
    limit = min(max(limit, 1), 50)  # Clamp between 1 and 50

    return web.json_response({
        "top_services": traffic_metrics.get_top_services(limit),
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
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
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

    limit = int(request.query.get("limit", "10"))
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
    except Exception:
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
    import re
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

    limit = min(int(request.query.get("limit", "20")), 50)

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
    except Exception:
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
    import re
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
    limit = int(request.query.get("limit", 100))
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

    try:
        if path == "/" or path == "/ws":
            await handle_ping_ws(ws, token)
        elif path == "/ws/terminal/local":
            await handle_local_terminal_ws(ws, token, client_ip)
        elif path.startswith("/ws/user-connection/"):
            await handle_user_connection_ws(ws, path, token, client_ip)
        else:
            await handle_relay_ws(ws, path, token, client_ip)
    finally:
        active_connections.discard(ws)
        logger.info(f"WebSocket closed for user {token.user_id} from {client_ip}")

    return ws


async def handle_ping_ws(ws: web.WebSocketResponse, token: TokenPayload) -> None:
    """Handle ping/echo WebSocket connections."""
    await ws.send_json({
        "type": "connected",
        "user_id": token.user_id,
        "scopes": token.scopes,
        "message": "Portal Gateway connected"
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

    # Create a virtual target for local terminal
    target = ServiceTarget(
        id="local",
        name="Server Terminal",
        plugin="terminal",
        host="localhost",
        port=0,
        config={"shell": "/bin/bash"}
    )

    logger.info(f"Local terminal session started for user {token.user_id} from {client_ip}")

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"Local terminal error for user {token.user_id}: {e}")
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
    import re

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

    conn_type = connection.get("type", "custom")
    config = connection.get("config", {})
    if isinstance(config, str):
        import json as json_module
        config = json_module.loads(config) if config else {}

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

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"User connection {conn_id} error: {e}")
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
    import re

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

    try:
        await plugin.handle_websocket(ws, target, token.user_id)
    except Exception as e:
        logger.error(f"Plugin {plugin_name} error for {service['name']}: {e}")
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

        html = load_static_file("terminal.html")
        html = html.replace("{{SERVICE_ID}}", "local")
        html = html.replace("{{SERVICE_NAME}}", "Server Terminal")
        return web.Response(text=html, content_type="text/html")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("terminal.html")
    # Inject service info
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Terminal"))

    return web.Response(text=html, content_type="text/html")


async def http_vnc_page(request: web.Request) -> web.Response:
    """Serve VNC page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("vnc.html")
    # Inject service info
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "VNC"))

    return web.Response(text=html, content_type="text/html")


async def http_media_page(request: web.Request) -> web.Response:
    """Serve media streaming page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("mediamtx.html")
    # Inject service info
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Media"))

    return web.Response(text=html, content_type="text/html")


async def http_spice_page(request: web.Request) -> web.Response:
    """Serve SPICE console page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("spice.html")
    # Inject service info
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "SPICE Console"))

    return web.Response(text=html, content_type="text/html")


async def http_proxmox_page(request: web.Request) -> web.Response:
    """Serve Proxmox management page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

    # Verify service exists and user has access
    service = await db.get_service_by_id(int(service_id)) if service_id.isdigit() else None
    if not service:
        return web.Response(status=404, text="Service not found")

    if not check_service_authorization(service, token):
        return web.Response(status=403, text="Access denied")

    html = load_static_file("proxmox.html")
    # Inject service info
    html = html.replace("{{SERVICE_ID}}", service_id)
    html = html.replace("{{SERVICE_NAME}}", service.get("name", "Proxmox VE"))

    return web.Response(text=html, content_type="text/html")


async def http_github_page(request: web.Request) -> web.Response:
    """Serve GitHub management page."""
    token = await authenticate_request(request)
    if not token:
        raise web.HTTPFound("/login")

    service_id = request.match_info.get("service_id", "")

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


# =============================================================================
# Chat/Forum System
# =============================================================================

# Chat room state: channel -> set of (ws, user_id, username)
chat_rooms: dict[str, set] = {}


async def http_get_chat_channels(request: web.Request) -> web.Response:
    """Get all chat channels."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    channels = await db.get_chat_channels()
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
    import re
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
    """Update a chat channel (topic, description)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    channel_id = int(request.match_info["id"])

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    success = await db.update_chat_channel(channel_id, **data)
    if not success:
        return web.json_response({"error": "Channel not found or no updates"}, status=404)

    return web.json_response({"success": True})


async def http_delete_chat_channel(request: web.Request) -> web.Response:
    """Delete a chat channel (admin only, cannot delete defaults)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return web.json_response({"error": "Admin access required"}, status=403)

    channel_id = int(request.match_info["id"])
    success = await db.delete_chat_channel(channel_id)

    if not success:
        return web.json_response({
            "error": "Channel not found or is a default channel"
        }, status=400)

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

    channel_id = int(request.match_info["id"])

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
    user_anonymous = bool(user.get("chat_anonymous"))
    current_channel = None
    user_entry = (ws, user_id, username, user_role, user_anonymous)

    logger.info(f"[Chat] User {username} connected")

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    msg_type = data.get("type")

                    if msg_type == "join":
                        channel_name = data.get("channel", "general")

                        # Leave current channel
                        if current_channel and current_channel in chat_rooms:
                            chat_rooms[current_channel].discard(user_entry)
                            display_name = "Anonymous" if user_anonymous else username
                            await broadcast_to_channel(current_channel, {
                                "type": "user_left",
                                "user_id": user_id,
                                "username": display_name
                            }, exclude=ws)

                        # Get channel info
                        channel = await db.get_chat_channel_by_name(channel_name)
                        if not channel:
                            await ws.send_json({"type": "error", "message": "Channel not found"})
                            continue

                        # Check if this is a stream chat and user is banned
                        stream = await db.get_stream_by_chat_channel(channel["id"])
                        if stream and await db.is_user_banned_from_stream(stream["id"], user_id):
                            await ws.send_json({
                                "type": "error",
                                "message": "You are banned from this stream's chat"
                            })
                            continue

                        # Join new channel
                        current_channel = channel_name
                        if current_channel not in chat_rooms:
                            chat_rooms[current_channel] = set()
                        chat_rooms[current_channel].add(user_entry)

                        # Send channel info
                        await ws.send_json({
                            "type": "channel_info",
                            "id": channel["id"],
                            "name": channel["name"],
                            "description": channel.get("description"),
                            "topic": channel.get("topic")
                        })

                        # Send message history
                        messages = await db.get_chat_messages(channel["id"], limit=50)
                        await ws.send_json({
                            "type": "history",
                            "messages": messages
                        })

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
                            users_list.append({
                                "user_id": u["id"],
                                "username": "Anonymous" if u.get("chat_anonymous") else u["username"],
                                "nickname": u.get("nickname"),
                                "status": u.get("status", "online"),
                                "status_message": u.get("status_message"),
                                "role": u.get("role", "user"),
                                "anonymous": bool(u.get("chat_anonymous")),
                                "avatar": avatar
                            })
                        await ws.send_json({
                            "type": "users",
                            "users": users_list
                        })

                        # Notify others
                        display_name = "Anonymous" if user_anonymous else username
                        await broadcast_to_channel(current_channel, {
                            "type": "user_joined",
                            "user_id": user_id,
                            "username": display_name,
                            "role": user_role,
                            "anonymous": user_anonymous
                        }, exclude=ws)

                    elif msg_type == "message":
                        if not current_channel:
                            continue

                        message_text = data.get("message", "").strip()
                        if not message_text or len(message_text) > 4000:
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

                        # Save message (always save real username in DB)
                        msg_id = await db.create_chat_message(
                            channel["id"], user_id, username, message_text
                        )

                        # Broadcast to channel (display anonymous if set)
                        display_name = "Anonymous" if user_anonymous else username
                        await broadcast_to_channel(current_channel, {
                            "type": "message",
                            "id": msg_id,
                            "user_id": user_id,
                            "username": display_name,
                            "role": user_role,
                            "anonymous": user_anonymous,
                            "message": message_text,
                            "created_at": datetime.now(timezone.utc).isoformat()
                        })

                    elif msg_type == "typing":
                        if current_channel:
                            await broadcast_to_channel(current_channel, {
                                "type": "typing",
                                "username": username
                            }, exclude=ws)

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

                except json.JSONDecodeError:
                    await ws.send_json({"type": "error", "message": "Invalid JSON"})

            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error(f"[Chat] WebSocket error: {ws.exception()}")
                break

    except Exception as e:
        logger.error(f"[Chat] Error: {e}")

    finally:
        # Clean up
        if current_channel and current_channel in chat_rooms:
            chat_rooms[current_channel].discard(user_entry)
            display_name = "Anonymous" if user_anonymous else username
            await broadcast_to_channel(current_channel, {
                "type": "user_left",
                "user_id": user_id,
                "username": display_name
            })
            # Remove empty rooms
            if not chat_rooms[current_channel]:
                del chat_rooms[current_channel]

        logger.info(f"[Chat] User {username} disconnected")

    return ws


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
        import re
        if not re.match(r'^[\w\s\-]+$', nickname):
            return web.json_response({"error": "Nickname can only contain letters, numbers, spaces, underscores and dashes"}, status=400)

    await db.set_user_nickname(token.user_id, nickname if nickname else None)

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

    # Broadcast change to all chat rooms - user needs to rejoin for full effect
    user = await db.get_user_by_id(token.user_id)
    username = user["username"] if user else "Unknown"
    display_name = "Anonymous" if anonymous else username
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
    response = await handler(request)

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
        'geolocation=(), microphone=(), camera=(), payment=()')

    # Content Security Policy for HTML pages
    content_type = response.headers.get('Content-Type', '')
    if 'text/html' in content_type:
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' wss:;"
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers.setdefault('Content-Security-Policy', csp)

    return response


def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application(middlewares=[security_headers_middleware])

    # Static files
    app.router.add_static("/static", STATIC_DIR)

    # HTTP API routes
    app.router.add_get("/health", http_health)
    app.router.add_get("/favicon.ico", http_favicon)
    app.router.add_get("/api/stats", http_stats)
    app.router.add_get("/api/plugins", http_list_plugins)
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

    # Two-Factor Authentication
    app.router.add_get("/api/user/2fa/status", http_2fa_status)
    app.router.add_post("/api/user/2fa/setup", http_2fa_setup)
    app.router.add_post("/api/user/2fa/verify", http_2fa_verify)
    app.router.add_post("/api/user/2fa/disable", http_2fa_disable)

    # Registration (public with invite code)
    app.router.add_post("/api/register", http_register)
    app.router.add_get("/api/invite-code", http_get_invite_code)

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
    app.router.add_get("/api/connections/{id}/connect", http_connect_user_connection)

    # User Streams (OBS/RTMP streaming)
    app.router.add_get("/api/streams", http_list_user_streams)
    app.router.add_post("/api/streams", http_create_user_stream)
    app.router.add_get("/api/streams/public", http_get_public_streams)
    app.router.add_get("/api/streams/{id}", http_get_user_stream)
    app.router.add_put("/api/streams/{id}", http_update_user_stream)
    app.router.add_delete("/api/streams/{id}", http_delete_user_stream)
    app.router.add_post("/api/streams/{id}/regenerate-key", http_regenerate_stream_key)
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

    # Vulnerability Scanner (admin only)
    app.router.add_get("/api/vuln/scan/{host}", http_vuln_scan_host)
    app.router.add_get("/api/vuln/scan-service/{service_id}", http_vuln_scan_service)
    app.router.add_get("/api/vuln/cve/{cve_id}", http_vuln_lookup_cve)
    app.router.add_get("/api/vuln/mitigations/{cve_id}", http_vuln_get_mitigations)
    app.router.add_get("/api/vuln/known-cves", http_vuln_known_cves)
    app.router.add_get("/api/vuln/search", http_vuln_search_cves)
    app.router.add_get("/api/vuln/status", http_vuln_scanner_status)
    app.router.add_post("/api/vuln/nvd-api-key", http_vuln_set_nvd_api_key)

    # Web UI routes
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
    app.router.add_get("/chat", http_chat_page)
    app.router.add_get("/streams", http_streams_page)

    # Chat API
    app.router.add_get("/api/chat/channels", http_get_chat_channels)
    app.router.add_post("/api/chat/channels", http_create_chat_channel)
    app.router.add_put("/api/chat/channels/{id}", http_update_chat_channel)
    app.router.add_delete("/api/chat/channels/{id}", http_delete_chat_channel)
    app.router.add_post("/api/chat/channels/{id}/clear", http_clear_chat_channel)

    # Root redirect (handles both HTTP and WebSocket upgrade)
    app.router.add_get("/", http_root_redirect)
    # Chat WebSocket (before catch-all)
    app.router.add_get("/ws/chat", handle_chat_websocket)
    # WebSocket endpoints - catch all paths for relay (must be last)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/ws/{path:.*}", websocket_handler)

    return app


class PortalServer:
    """Main Portal Gateway server."""

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

        # Start chat message cleanup task (runs every 6 hours)
        asyncio.create_task(self._chat_cleanup_task())

        # Start viewer count sync task (syncs MediaMTX reader counts every 10 seconds)
        asyncio.create_task(self._viewer_sync_task())

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

        # Generate/log daily invite code
        invite_code = get_daily_invite_code()
        logger.info(f"Daily invite code active: {invite_code}")

        logger.info(f"Portal Gateway started on https://{Config.HOSTNAME}:{Config.PORT}")
        logger.info("Endpoints:")
        logger.info(f"  - Health:     GET  /health")
        logger.info(f"  - Login:      GET  /login")
        logger.info(f"  - Dashboard:  GET  /dashboard")
        logger.info(f"  - Register:   POST /api/register (requires invite code)")
        logger.info(f"  - WebSocket:  wss://{Config.HOSTNAME}/ws/")

    async def _chat_cleanup_task(self) -> None:
        """Background task to clean up old chat messages (runs every 6 hours)."""
        while True:
            try:
                await asyncio.sleep(6 * 60 * 60)  # 6 hours
                deleted = await db.cleanup_old_chat_messages(days=7)
                if deleted > 0:
                    logger.info(f"[Chat] Cleaned up {deleted} messages older than 7 days")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Chat] Cleanup error: {e}")

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
                        if stream and stream.get("is_live"):
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
    from datetime import datetime, timezone

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
    import os

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

    parser = argparse.ArgumentParser(description="Portal Gateway Server")
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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
