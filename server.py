#!/usr/bin/env python3
"""Portal Gateway - Secure WebSocket Authentication and Relay Server."""

import asyncio
import json
import logging
import signal
import ssl
import sys
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
from database import db
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
    """Authenticate a request via header, query param, or session cookie."""
    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            return await validate_token(auth_header[7:])
        except AuthError:
            pass

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
    """List available services."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    services = await db.get_all_services()
    return web.json_response({
        "services": [
            {
                "id": s["id"],
                "name": s["name"],
                "path": s["path"],
                "plugin": s.get("plugin", "tcp_tunnel"),
                "host": s.get("host", ""),
                "port": s.get("port", 0),
                "required_scopes": s["required_scopes"],
                "enabled": bool(s["enabled"])
            }
            for s in services
        ]
    })


async def http_create_service(request: web.Request) -> web.Response:
    """Create a new relay service (admin only)."""
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

    # Handle scopes as string or list
    if isinstance(required_scopes, str):
        required_scopes = [s.strip() for s in required_scopes.split(",") if s.strip()]

    if not name or not path:
        return web.json_response(
            {"error": "name and path required"},
            status=400
        )

    try:
        service_id = await db.create_service(
            name=name,
            path=path,
            plugin=plugin,
            host=host,
            port=port,
            config=config,
            required_scopes=required_scopes
        )
        logger.info(f"Service '{name}' created by user {token.user_id}")
        return web.json_response({
            "id": service_id,
            "name": name,
            "path": path,
            "plugin": plugin,
            "host": host,
            "port": port,
            "required_scopes": required_scopes
        }, status=201)
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
    """Update a relay service (admin only)."""
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
    if "name" in data:
        updates["name"] = data["name"]
    if "path" in data:
        updates["path"] = data["path"]
    if "plugin" in data:
        updates["plugin"] = data["plugin"]
    if "host" in data:
        updates["host"] = data["host"]
    if "port" in data:
        updates["port"] = data["port"]
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

    if not updates:
        return web.json_response({"error": "No fields to update"}, status=400)

    try:
        # Build SQL
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = ?"
        values = list(updates.values()) + [datetime.now(timezone.utc).isoformat(), service_id]

        await db.conn.execute(
            f"UPDATE services SET {set_clause} WHERE id = ?",
            values
        )
        await db.conn.commit()

        # Get updated service
        updated = await db.get_service_by_id(service_id)
        logger.info(f"Service {service_id} updated by user {token.user_id}: {list(updates.keys())}")

        return web.json_response({
            "id": updated["id"],
            "name": updated["name"],
            "path": updated["path"],
            "plugin": updated.get("plugin", "tcp_tunnel"),
            "host": updated.get("host", ""),
            "port": updated.get("port", 0),
            "enabled": bool(updated["enabled"]),
            "required_scopes": updated["required_scopes"]
        })
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

    return web.json_response({
        "id": service["id"],
        "name": service["name"],
        "path": service["path"],
        "plugin": service.get("plugin", "tcp_tunnel"),
        "host": service.get("host", ""),
        "port": service.get("port", 0),
        "enabled": bool(service["enabled"]),
        "required_scopes": service["required_scopes"],
        "config": service.get("config", {})
    })


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
    """Update log settings (admin only)."""
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
        logger.info(f"Log settings updated by user {token.user_id}: {data}")
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

    if not Config.SHODAN_API_KEY:
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

    if not Config.SHODAN_API_KEY:
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

    if not Config.SHODAN_API_KEY:
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
            "configured": True,
            "error": "Failed to get API info"
        }, status=500)


async def http_shodan_set_api_key(request: web.Request) -> web.Response:
    """Set Shodan API key (admin only) - stores in memory only."""
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

    # Set the API key (memory only - for persistence, set SHODAN_API_KEY env var)
    shodan_client.set_api_key(api_key)

    # Verify the key works
    info = await shodan_client.get_api_info()
    if info:
        logger.info(f"Shodan API key updated by user {token.user_id}")
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
    """Scan a host for vulnerabilities (admin only)."""
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

    try:
        result = await vulnerability_scanner.scan_host(host, ports)
        logger.info(f"Vulnerability scan completed for {host} by user {token.user_id}")
        return web.json_response(result.to_dict())
    except Exception as e:
        logger.error(f"Vulnerability scan failed for {host}: {e}")
        return web.json_response({"error": "Scan failed"}, status=500)


async def http_vuln_scan_service(request: web.Request) -> web.Response:
    """Scan a Portal service for vulnerabilities (admin only)."""
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

    try:
        result = await vulnerability_scanner.scan_host(host, [port])
        logger.info(f"Vulnerability scan completed for service {service_id} by user {token.user_id}")
        return web.json_response({
            "service": {
                "id": service["id"],
                "name": service["name"],
                "host": host,
                "port": port
            },
            "scan": result.to_dict()
        })
    except Exception as e:
        logger.error(f"Vulnerability scan failed for service {service_id}: {e}")
        return web.json_response({"error": "Scan failed"}, status=500)


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
# WebSocket Handler
# =============================================================================

async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    """Handle WebSocket connections for relay and ping."""
    client_ip = get_client_ip(request)
    path = request.path

    # Check if this is a WebSocket upgrade request
    is_websocket = (
        request.headers.get("Upgrade", "").lower() == "websocket" or
        request.headers.get("Connection", "").lower() == "upgrade"
    )

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
    """Handle login form submission."""
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


async def http_get_current_user(request: web.Request) -> web.Response:
    """Get current authenticated user info."""
    token = await authenticate_request(request)
    if not token:
        return web.json_response({"error": "Not authenticated"}, status=401)

    user = await db.get_user_by_id(token.user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    return web.json_response({
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
        "scopes": token.scopes
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


async def http_list_users(request: web.Request) -> web.Response:
    """List all users (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    async with db.conn.execute(
        "SELECT id, username, is_admin, created_at FROM users ORDER BY id"
    ) as cursor:
        rows = await cursor.fetchall()

    return web.json_response({
        "users": [
            {
                "id": row["id"],
                "username": row["username"],
                "is_admin": bool(row["is_admin"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ]
    })


async def http_update_user_admin(request: web.Request) -> web.Response:
    """Update user admin status (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    user_id = request.match_info.get("id")
    if not user_id or not user_id.isdigit():
        return web.json_response({"error": "Invalid user ID"}, status=400)

    user_id = int(user_id)

    # Don't allow modifying yourself
    if user_id == token.user_id:
        return web.json_response(
            {"error": "Cannot modify your own admin status"},
            status=400
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    is_admin = data.get("is_admin")
    if is_admin is None:
        return web.json_response({"error": "is_admin field required"}, status=400)

    user = await db.get_user_by_id(user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    await db.conn.execute(
        "UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (1 if is_admin else 0, user_id)
    )
    await db.conn.commit()

    action = "granted" if is_admin else "revoked"
    logger.info(f"Admin {action} for user {user['username']} by user {token.user_id}")

    return web.json_response({
        "id": user_id,
        "username": user["username"],
        "is_admin": bool(is_admin),
        "message": f"Admin status {action}"
    })


async def http_delete_user(request: web.Request) -> web.Response:
    """Delete a user (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

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

    user = await db.get_user_by_id(user_id)
    if not user:
        return web.json_response({"error": "User not found"}, status=404)

    # Delete user's tokens first
    await db.conn.execute("DELETE FROM tokens WHERE user_id = ?", (user_id,))
    # Delete the user
    await db.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.conn.commit()

    logger.info(f"User {user['username']} deleted by admin {token.user_id}")

    return web.json_response({
        "message": f"User '{user['username']}' deleted"
    })


# =============================================================================
# Application Setup
# =============================================================================

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    """Add security headers to all responses."""
    response = await handler(request)

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
            "connect-src 'self' wss: ws:; "
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
    app.router.add_get("/api/stats", http_stats)
    app.router.add_get("/api/plugins", http_list_plugins)
    app.router.add_get("/api/tunnels", http_get_tunnel_sessions)

    # Token management
    app.router.add_post("/api/token", http_create_token)
    app.router.add_post("/api/token/revoke", http_revoke_token)
    app.router.add_get("/api/tokens", http_list_tokens)

    # Service management
    app.router.add_get("/api/services", http_list_services)
    app.router.add_post("/api/services", http_create_service)
    app.router.add_get("/api/services/{id}", http_get_service)
    app.router.add_put("/api/services/{id}", http_update_service)
    app.router.add_delete("/api/services/{id}", http_delete_service)
    app.router.add_get("/api/services/{id}/health", http_service_health)

    # User management
    app.router.add_get("/api/users", http_list_users)
    app.router.add_post("/api/users", http_create_user)
    app.router.add_put("/api/users/{id}/admin", http_update_user_admin)
    app.router.add_delete("/api/users/{id}", http_delete_user)
    app.router.add_get("/api/me", http_get_current_user)
    app.router.add_post("/api/me/password", http_change_password)

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

    # WebSocket endpoints - catch all paths for relay (must be last)
    app.router.add_get("/", websocket_handler)
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

        # Load and initialize plugins
        load_builtin_plugins()
        await initialize_plugins()
        logger.info("Plugins initialized")

        # Initialize Shodan client if API key is configured
        if Config.SHODAN_API_KEY:
            await init_shodan(Config.SHODAN_API_KEY)
            logger.info("Shodan integration initialized")

        # Start traffic metrics recorder
        if Config.METRICS_ENABLED:
            await start_metrics_recorder()
            logger.info("Traffic metrics recorder started")

        # Initialize vulnerability scanner
        await init_scanner()
        logger.info("Vulnerability scanner initialized")

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

    async def stop(self) -> None:
        """Stop the server gracefully."""
        logger.info("Shutting down...")

        # Stop metrics recorder
        await stop_metrics_recorder()

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
        print(f"\n{'='*50}")
        print("INITIAL ADMIN USER CREATED")
        print(f"Username: admin")
        print(f"Password: {password}")
        print("SAVE THIS PASSWORD - it will not be shown again!")
        print(f"{'='*50}\n")
    else:
        print("Admin user already exists.")

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

    print(f"\n{'='*50}")
    print("PORTAL GATEWAY - DAILY INVITE CODE")
    print(f"{'='*50}")
    print(f"Date:    {today}")
    print(f"Code:    {code}")
    print(f"Expires: {today} 23:59:59 UTC")
    print(f"{'='*50}")
    print("\nUsers can register at POST /api/register with:")
    print('  {"username": "...", "password": "...", "invite_code": "' + code + '"}')
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
