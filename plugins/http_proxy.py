"""HTTP Proxy plugin - Reverse proxy for web UIs."""

import ipaddress
import logging
from urllib.parse import urljoin, urlparse

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
                    "description": "Authorization header to inject"
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
                    "description": "Request timeout in seconds",
                    "default": 60
                },
                "websocket_path": {
                    "type": "string",
                    "description": "WebSocket endpoint path (e.g., /api/websocket)"
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
                # Read request body if present
                body = await request.read() if request.body_exists else None

                async with session.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=body,
                    allow_redirects=False
                ) as resp:
                    # Read response
                    response_body = await resp.read()

                    # Prepare response headers
                    response_headers = {}
                    for key, value in resp.headers.items():
                        # Skip hop-by-hop headers
                        if key.lower() in (
                            "transfer-encoding", "connection",
                            "keep-alive", "proxy-authenticate",
                            "proxy-authorization", "te", "trailers",
                            "upgrade"
                        ):
                            continue
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
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"

        verify_ssl = config.get("verify_ssl", False)

        logger.info(f"WebSocket proxy to {ws_url} for user {user_id}")

        try:
            connector = aiohttp.TCPConnector(ssl=verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.ws_connect(ws_url) as upstream:
                    await asyncio.gather(
                        self._ws_to_upstream(ws, upstream),
                        self._upstream_to_ws(upstream, ws),
                    )
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")

    async def _ws_to_upstream(
        self,
        client_ws: web.WebSocketResponse,
        upstream_ws: aiohttp.ClientWebSocketResponse
    ) -> None:
        """Forward client WebSocket to upstream."""
        async for msg in client_ws:
            if msg.type == WSMsgType.TEXT:
                await upstream_ws.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await upstream_ws.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break

    async def _upstream_to_ws(
        self,
        upstream_ws: aiohttp.ClientWebSocketResponse,
        client_ws: web.WebSocketResponse
    ) -> None:
        """Forward upstream WebSocket to client."""
        async for msg in upstream_ws:
            if msg.type == WSMsgType.TEXT:
                await client_ws.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await client_ws.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break

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


# Import asyncio at module level for WebSocket handling
import asyncio
