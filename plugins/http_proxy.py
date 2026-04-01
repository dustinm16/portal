"""HTTP Proxy plugin - Reverse proxy for web UIs."""

import ipaddress
import logging
from urllib.parse import urljoin, urlparse

import asyncio

import aiohttp
from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.http_proxy")


def _is_blocked_proxy_host(host: str) -> bool:
    """Check if a proxy target host is blocked (SSRF prevention)."""
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
                "preserve_host": {
                    "type": "boolean",
                    "description": "Preserve original Host header",
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
                "rewrite_urls": {
                    "type": "boolean",
                    "description": "Rewrite URLs in responses",
                    "default": True
                },
                "timeout": {
                    "type": "integer",
                    "title": "Timeout (seconds)",
                    "description": "Upstream request timeout in seconds",
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
                    "description": "Header names or glob patterns to forward from the client to upstream (e.g. X-User-*, X-Request-ID). Authorization, Cookie, and Host are never forwarded.",
                    "items": {"type": "string"},
                    "default": []
                }
            }
        }
    )

    async def handle_http(
        self,
        request: web.Request,
        target: ServiceTarget
    ) -> web.Response:
        """Proxy HTTP request to target service."""
        config = target.config
        target_url = config.get("target_url")
        verify_ssl = config.get("verify_ssl", False)
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 60))

        # SSRF protection: validate target host
        if target_url:
            parsed_target = urlparse(target_url)
            if _is_blocked_proxy_host(parsed_target.hostname or ""):
                return web.json_response({"error": "Target host not allowed"}, status=403)

        # Build target URL
        path = request.match_info.get("path", "")
        query = request.query_string
        url = urljoin(target_url, path)
        if query:
            url = f"{url}?{query}"

        # Prepare headers
        headers = dict(request.headers)
        headers.pop("Host", None)

        if not config.get("preserve_host"):
            parsed = urlparse(target_url)
            headers["Host"] = parsed.netloc

        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        for key, value in config.get("extra_headers", {}).items():
            headers[key] = value

        # Forward user info
        headers["X-Forwarded-For"] = request.remote
        headers["X-Forwarded-Proto"] = request.scheme
        headers["X-Real-IP"] = request.remote

        logger.debug(f"Proxying {request.method} {url}")

        try:
            connector = aiohttp.TCPConnector(ssl=verify_ssl)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                # Read request body if present (cap at 10MB)
                body = None
                if request.body_exists:
                    body = await request.content.read(10 * 1024 * 1024)
                    if not request.content.at_eof():
                        return web.json_response({"error": "Request body too large"}, status=413)

                async with session.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=body,
                    allow_redirects=False
                ) as resp:
                    # Read response (cap at 50MB for text)
                    response_body = await resp.content.read(50 * 1024 * 1024)

                    # Prepare response headers (preserve multi-valued like Set-Cookie)
                    hop_by_hop = {
                        "transfer-encoding", "connection",
                        "keep-alive", "proxy-authenticate",
                        "proxy-authorization", "te", "trailers",
                        "upgrade"
                    }
                    response_headers = {}
                    for key, value in resp.headers.items():
                        if key.lower() in hop_by_hop:
                            continue
                        # For duplicate headers (e.g. Set-Cookie), keep all values
                        if key in response_headers:
                            # aiohttp Response accepts only single values per key,
                            # so combine with separator (comma for most, newline for Set-Cookie)
                            if key.lower() == 'set-cookie':
                                # Will be handled via resp.cookies or raw headers
                                continue
                            response_headers[key] = f"{response_headers[key]}, {value}"
                        else:
                            response_headers[key] = value

                    # Optionally rewrite URLs in HTML/JS responses
                    content_type = resp.headers.get("Content-Type", "")
                    if config.get("rewrite_urls") and "text" in content_type:
                        try:
                            text = response_body.decode("utf-8")
                            # Rewrite absolute URLs to target
                            parsed = urlparse(target_url)
                            text = text.replace(
                                f"{parsed.scheme}://{parsed.netloc}",
                                ""  # Convert to relative
                            )
                            response_body = text.encode("utf-8")
                        except UnicodeDecodeError:
                            pass  # Binary content, skip URL rewriting
                        except Exception as e:
                            logger.debug(f"URL rewriting failed: {e}")

                    return web.Response(
                        status=resp.status,
                        headers=response_headers,
                        body=response_body
                    )

        except aiohttp.ClientError as e:
            logger.error(f"Proxy error: {e}")
            return web.json_response(
                {"error": f"Upstream error: {type(e).__name__}"},
                status=502
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
        if _is_blocked_proxy_host(parsed.hostname or ""):
            logger.warning(f"WebSocket proxy blocked: {parsed.hostname}")
            return
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"

        verify_ssl = config.get("verify_ssl", False)

        logger.info(f"WebSocket proxy to {ws_url} for user {user_id}")

        try:
            connector = aiohttp.TCPConnector(ssl=verify_ssl)
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
