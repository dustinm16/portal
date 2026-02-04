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
)
from plugins import (
    load_builtin_plugins,
    initialize_plugins,
    shutdown_plugins,
    get_plugin,
)
from plugins.base import ServiceTarget

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("portal")

# Rate limiting storage
rate_limits: dict[str, list[float]] = defaultdict(list)

# Active WebSocket connections for monitoring
active_connections: weakref.WeakSet = weakref.WeakSet()

# Static files cache
STATIC_DIR = Path(__file__).parent / "static"
_static_cache: dict[str, str] = {}


def load_static_file(filename: str) -> str:
    """Load and cache a static file."""
    if filename not in _static_cache:
        filepath = STATIC_DIR / filename
        if filepath.exists():
            _static_cache[filename] = filepath.read_text()
        else:
            _static_cache[filename] = f"<h1>404 - {filename} not found</h1>"
    return _static_cache[filename]


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
    internal_url = data.get("internal_url")
    required_scopes = data.get("required_scopes", [])

    if not all([name, path, internal_url]):
        return web.json_response(
            {"error": "name, path, and internal_url required"},
            status=400
        )

    try:
        service_id = await db.create_service(name, path, internal_url, required_scopes)
        logger.info(f"Service '{name}' created by user {token.user_id}")
        return web.json_response({
            "id": service_id,
            "name": name,
            "path": path,
            "internal_url": internal_url,
            "required_scopes": required_scopes
        }, status=201)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)


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
        return web.json_response({"error": str(e)}, status=400)


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
        return web.json_response({"error": str(e)}, status=400)


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


async def http_stats(request: web.Request) -> web.Response:
    """Get server statistics (admin only)."""
    token = await authenticate_request(request)
    if not token:
        return unauthorized_response(request)

    if not token.has_scope("admin") and not token.has_scope("*"):
        return forbidden_response(request)

    services = await db.get_all_services()

    return web.json_response({
        "active_connections": len(active_connections),
        "total_services": len(services),
        "rate_limit_entries": len(rate_limits),
        "uptime_check": datetime.now(timezone.utc).isoformat()
    })


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

    # Create WebSocket response
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

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
    # Find matching service
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


# =============================================================================
# Application Setup
# =============================================================================

def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application()

    # Static files
    app.router.add_static("/static", STATIC_DIR)

    # HTTP API routes
    app.router.add_get("/health", http_health)
    app.router.add_get("/api/stats", http_stats)

    # Token management
    app.router.add_post("/api/token", http_create_token)
    app.router.add_post("/api/token/revoke", http_revoke_token)
    app.router.add_get("/api/tokens", http_list_tokens)

    # Service management
    app.router.add_get("/api/services", http_list_services)
    app.router.add_post("/api/services", http_create_service)
    app.router.add_delete("/api/services/{id}", http_delete_service)

    # User management
    app.router.add_post("/api/users", http_create_user)
    app.router.add_get("/api/me", http_get_current_user)

    # Registration (public with invite code)
    app.router.add_post("/api/register", http_register)
    app.router.add_get("/api/invite-code", http_get_invite_code)

    # Web UI routes
    app.router.add_get("/login", http_login_page)
    app.router.add_post("/login", http_login_submit)
    app.router.add_get("/logout", http_logout)
    app.router.add_get("/dashboard", http_dashboard)
    app.router.add_get("/terminal/{service_id}", http_terminal_page)
    app.router.add_get("/vnc/{service_id}", http_vnc_page)

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


async def add_service_cli(name: str, path: str, internal_url: str, scopes: str = "") -> None:
    """Add a service via CLI."""
    await db.connect()

    scope_list = [s.strip() for s in scopes.split(",") if s.strip()] if scopes else []
    service_id = await db.create_service(name, path, internal_url, scope_list)
    print(f"Service '{name}' created with ID {service_id}")
    print(f"  Path: {path}")
    print(f"  Internal URL: {internal_url}")
    print(f"  Required scopes: {scope_list or 'none'}")

    await db.close()


async def list_services_cli() -> None:
    """List all services via CLI."""
    await db.connect()

    services = await db.get_all_services()
    if not services:
        print("No services configured.")
    else:
        print(f"\n{'ID':<4} {'Name':<20} {'Path':<20} {'Internal URL':<40} {'Scopes'}")
        print("-" * 100)
        for s in services:
            scopes = ",".join(s["required_scopes"]) or "none"
            print(f"{s['id']:<4} {s['name']:<20} {s['path']:<20} {s['internal_url']:<40} {scopes}")

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
    add_svc.add_argument("internal_url", help="Internal WebSocket URL")
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
        asyncio.run(add_service_cli(args.name, args.path, args.internal_url, args.scopes))
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
