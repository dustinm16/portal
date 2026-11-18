"""HTTP Proxy plugin - Reverse proxy for web UIs."""

import ipaddress
import logging
from urllib.parse import urlparse

import asyncio

import aiohttp
from aiohttp import web, WSMsgType

from host_check import HostCheckError, _SSRFSafeConnector, resolve_checked_host
from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.http_proxy")


def _is_blocked_proxy_host(host: str) -> bool:
    """Check if a proxy target host is blocked (SSRF prevention).

    Literal-name check kept for admin-defined services, which may target
    internal backends by name.
    """
    if not host:
        return True
    h = host.lower().strip()
    blocked_names = {'localhost', '127.0.0.1', '::1', '0.0.0.0',
                     'host.docker.internal', 'metadata.google.internal',
                     '169.254.169.254'}
    if h in blocked_names or h.startswith('127.'):
        return True
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
            return True
    except ValueError:
        pass
    return False


def _user_policy(config: dict) -> bool:
    """True for user-defined connections.

    Only the user-connection handler sets `_ssrf_safe` (it resets the key
    first, so a stored config cannot supply it). Admin-defined services do
    not carry it and keep the literal-name check and a plain connector.
    """
    return bool(config.get("_ssrf_safe"))


def _new_connector(config: dict, verify_ssl):
    if _user_policy(config):
        return _SSRFSafeConnector(ssl=verify_ssl)
    return aiohttp.TCPConnector(ssl=verify_ssl)


async def _check_proxy_target(url: str, config: dict) -> bool:
    """True if the target URL's host is allowed for this service.

    User connections: resolve the name and refuse it if any address it
    resolves to is blocked (the connector used for the request applies the
    same policy again at connect time, so a different DNS answer cannot slip
    in; the hostname stays for TLS SNI and the Host header). Admin-defined
    services: the literal-name check only.
    """
    if not _user_policy(config):
        return not _is_blocked_proxy_host(urlparse(url or "").hostname or "")
    try:
        parsed = urlparse(url or "")
        await resolve_checked_host(parsed.hostname or "", parsed.port or 0)
    except (HostCheckError, ValueError):
        return False
    return True


@register_plugin
class HTTPProxyPlugin(PluginBase):
    """HTTP reverse proxy for web interfaces.

    Proxies HTTP requests to internal web services like:
    - Proxmox web UI
    - TrueNAS web UI
    - Plex web interface
    - Home Assistant
    - Router/switch web interfaces
    """

    info = PluginInfo(
        name="http_proxy",
        display_name="Web Interface",
        description="Proxy access to web-based admin interfaces",
        version="1.0.0",
        icon="globe",
        protocols=["http", "websocket"],
        config_schema={
            "type": "object",
            "required": ["target_url"],
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target base URL (e.g., https://192.168.1.1:8006)"
                },
                "verify_ssl": {
                    "type": "boolean",
                    "description": "Verify SSL certificates",
                    "default": False
                },
                "auth_header": {
                    "type": "string",
                    "format": "password",
                    "title": "Auth Header",
                    "description": "Authorization header value injected as the upstream Authorization header (e.g. Bearer token123)"
                },
                "extra_headers": {
                    "type": "object",
                    "description": "Extra headers to add to requests"
                },
                "timeout": {
                    "type": "integer",
                    "title": "Timeout (seconds)",
                    "description": "Longest wait for the upstream in seconds: connecting is limited to 10 s, and a response is cut off only after this long without any data. A long download is not cut off while data keeps flowing, but a response that is rewritten in memory (HTML, CSS, JavaScript, JSON) must arrive within this time in total. Values outside 5-300 are adjusted.",
                    "default": 60,
                    "minimum": 5,
                    "maximum": 300
                },
                "websocket_path": {
                    "type": "string",
                    "description": "WebSocket endpoint path (e.g., /api/websocket)"
                },
                "path_rewrite_rules": {
                    "type": "array",
                    "title": "Path Rewrite Rules",
                    "description": "Regex match/replace pairs applied to the upstream request path (e.g. strip a prefix or rewrite versioned paths)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "match": {"type": "string", "description": "Regex pattern to match"},
                            "replace": {"type": "string", "description": "Replacement string (supports \\1 backreferences)"}
                        }
                    },
                    "default": []
                },
                "forward_headers": {
                    "type": "array",
                    "title": "Forward Headers",
                    "description": "Header names or glob patterns to forward from the client to upstream (e.g. X-User-*, X-Request-ID). The portal session cookie, Authorization, Host and every X-Forwarded-* / X-Real-IP / CF-Connecting-IP / True-Client-IP / X-Client-IP header are never copied from the client.",
                    "items": {"type": "string"},
                    "default": []
                },
                "forwarded_host": {
                    "type": "boolean",
                    "title": "Send Forwarded Host and Prefix",
                    "description": "Send X-Forwarded-Host (the portal's host name) and X-Forwarded-Prefix (/proxy/<id>) to the app. Turn on only for an app that builds its links from both (for example an app with a base path setting); an app that honours the host but not the prefix writes links outside the proxy path. X-Forwarded-Proto, X-Forwarded-For and X-Real-IP are always sent.",
                    "default": False
                },
                "browser_mode": {
                    "type": "boolean",
                    "title": "General Browsing Mode",
                    "description": "Allow navigating to other domains and opening new tabs, like a sandboxed general-purpose browser. Leave off to keep this connection confined to its own target's root — recommended for admin panels (Proxmox, TrueNAS, etc.) and required for anything to work reliably.",
                    "default": False
                }
            }
        }
    )

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Proxy WebSocket connection."""
        config = target.config
        target_url = config.get("target_url")
        ws_path = config.get("websocket_path", "")

        # Convert http(s) to ws(s)
        parsed = urlparse(target_url)
        # SSRF check on WebSocket target (same as HTTP handler)
        if not await _check_proxy_target(target_url, config):
            logger.warning(f"WebSocket proxy blocked: {parsed.hostname}")
            return
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"

        verify_ssl = config.get("verify_ssl", False)

        logger.info(f"WebSocket proxy to {ws_url} for user {user_id}")

        try:
            connector = _new_connector(config, verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.ws_connect(ws_url) as upstream:
                    tasks = [
                        asyncio.create_task(self._ws_to_upstream(ws, upstream)),
                        asyncio.create_task(self._upstream_to_ws(upstream, ws)),
                    ]
                    try:
                        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        for t in tasks:
                            if not t.done():
                                t.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")

    async def _ws_to_upstream(
        self,
        client_ws: web.WebSocketResponse,
        upstream_ws: aiohttp.ClientWebSocketResponse
    ) -> None:
        """Forward client WebSocket to upstream."""
        try:
            async for msg in client_ws:
                if msg.type == WSMsgType.TEXT:
                    await upstream_ws.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await upstream_ws.send_bytes(msg.data)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"WS-to-upstream relay error: {e}")

    async def _upstream_to_ws(
        self,
        upstream_ws: aiohttp.ClientWebSocketResponse,
        client_ws: web.WebSocketResponse
    ) -> None:
        """Forward upstream WebSocket to client."""
        try:
            async for msg in upstream_ws:
                if msg.type == WSMsgType.TEXT:
                    await client_ws.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await client_ws.send_bytes(msg.data)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Upstream-to-WS relay error: {e}")

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check if target web service is reachable."""
        config = target.config
        target_url = config.get("target_url")
        verify_ssl = config.get("verify_ssl", False)

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=verify_ssl)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                async with session.head(target_url) as resp:
                    return {
                        "healthy": resp.status < 500,
                        "message": f"HTTP {resp.status}"
                    }
        except Exception as e:
            return {"healthy": False, "message": str(e)}
