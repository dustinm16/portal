"""MediaMTX plugin - Media streaming relay with authentication.

This plugin provides authenticated access to MediaMTX streams via:
- WebRTC playback in browser
- Stream listing and management
- HLS fallback for compatibility

MediaMTX is a ready-to-use RTSP/RTMP/HLS/WebRTC/SRT media server.
https://github.com/bluenviron/mediamtx
"""

import asyncio
import json
import logging
from typing import Optional, Dict, List
from urllib.parse import urljoin

import aiohttp
from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.mediamtx")


@register_plugin
class MediaMTXPlugin(PluginBase):
    """MediaMTX streaming media plugin.

    Provides authenticated WebRTC/HLS streaming through the portal.
    Supports live streams from RTSP, RTMP, and other sources.
    """

    info = PluginInfo(
        name="mediamtx",
        display_name="Media Streaming",
        description="Live video streaming via WebRTC/HLS with MediaMTX",
        version="1.0.0",
        icon="video",
        protocols=["websocket", "http"],
        config_schema={
            "type": "object",
            "required": ["api_url"],
            "properties": {
                "api_url": {
                    "type": "string",
                    "description": "MediaMTX API URL (use HTTPS for encrypted communication)",
                    "default": "https://127.0.0.1:9997"
                },
                "webrtc_url": {
                    "type": "string",
                    "description": "MediaMTX WebRTC URL (use HTTPS for encrypted communication)",
                    "default": "https://127.0.0.1:8889"
                },
                "hls_url": {
                    "type": "string",
                    "description": "MediaMTX HLS URL (use HTTPS for encrypted communication)",
                    "default": "https://127.0.0.1:8888"
                },
                "default_stream": {
                    "type": "string",
                    "description": "Default stream path to display",
                    "default": ""
                },
                "allowed_streams": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed stream paths (empty = all)",
                    "default": []
                },
                "api_timeout": {
                    "type": "integer",
                    "description": "API request timeout in seconds",
                    "default": 10
                }
            }
        }
    )

    def __init__(self):
        super().__init__()
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def initialize(self) -> None:
        """Initialize HTTP session for API calls."""
        self._http_session = aiohttp.ClientSession()

    async def shutdown(self) -> None:
        """Close HTTP session."""
        if self._http_session:
            await self._http_session.close()

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle WebRTC signaling WebSocket connection."""
        config = target.config
        api_url = config.get("api_url", "http://localhost:9997")
        webrtc_url = config.get("webrtc_url", "http://localhost:8889")
        default_stream = config.get("default_stream", "")
        allowed_streams = config.get("allowed_streams", [])
        timeout = config.get("api_timeout", 10)

        logger.info(f"MediaMTX session started for user {user_id}")

        # Send available streams on connect
        try:
            streams = await self._get_streams(api_url, timeout)
            if allowed_streams:
                streams = [s for s in streams if s["name"] in allowed_streams]

            await ws.send_json({
                "type": "init",
                "streams": streams,
                "default_stream": default_stream,
                "webrtc_supported": True
            })
        except Exception as e:
            logger.error(f"Failed to get streams: {e}")
            await ws.send_json({
                "type": "error",
                "message": f"Failed to connect to MediaMTX: {e}"
            })
            return

        # Handle WebRTC signaling
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_signaling(
                            ws, data, webrtc_url, allowed_streams, timeout, user_id
                        )
                    except json.JSONDecodeError:
                        await ws.send_json({
                            "type": "error",
                            "message": "Invalid JSON"
                        })
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        finally:
            logger.info(f"MediaMTX session ended for user {user_id}")

    async def _handle_signaling(
        self,
        ws: web.WebSocketResponse,
        data: dict,
        webrtc_url: str,
        allowed_streams: List[str],
        timeout: int,
        user_id: int
    ) -> None:
        """Handle WebRTC signaling messages."""
        msg_type = data.get("type")
        stream = data.get("stream", "")

        # Validate stream access
        if allowed_streams and stream not in allowed_streams:
            await ws.send_json({
                "type": "error",
                "message": f"Access denied to stream: {stream}"
            })
            return

        if msg_type == "watch":
            # Client wants to watch a stream - initiate WebRTC
            logger.debug(f"User {user_id} requesting stream: {stream}")
            await ws.send_json({
                "type": "watching",
                "stream": stream,
                "message": "Ready for WebRTC offer"
            })

        elif msg_type == "offer":
            # Forward SDP offer to MediaMTX and get answer
            sdp_offer = data.get("sdp")
            if not sdp_offer:
                await ws.send_json({"type": "error", "message": "Missing SDP offer"})
                return

            try:
                # MediaMTX WebRTC WHEP endpoint
                whep_url = f"{webrtc_url}/{stream}/whep"

                async with self._http_session.post(
                    whep_url,
                    data=sdp_offer,
                    headers={"Content-Type": "application/sdp"},
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status == 201:
                        sdp_answer = await resp.text()
                        # Get the resource URL for ICE candidates
                        location = resp.headers.get("Location", "")

                        await ws.send_json({
                            "type": "answer",
                            "sdp": sdp_answer,
                            "resource": location
                        })
                        logger.debug(f"WebRTC answer sent for stream {stream}")
                    else:
                        error_text = await resp.text()
                        logger.error(f"WHEP error {resp.status}: {error_text}")
                        await ws.send_json({
                            "type": "error",
                            "message": f"Stream error: {resp.status}"
                        })

            except asyncio.TimeoutError:
                await ws.send_json({"type": "error", "message": "Connection timeout"})
            except Exception as e:
                logger.error(f"WebRTC signaling error: {e}")
                await ws.send_json({"type": "error", "message": str(e)})

        elif msg_type == "ice":
            # Forward ICE candidate to MediaMTX
            candidate = data.get("candidate")
            resource = data.get("resource")

            if candidate and resource:
                try:
                    # PATCH the resource with ICE candidate
                    async with self._http_session.patch(
                        resource,
                        data=json.dumps({"candidate": candidate}),
                        headers={"Content-Type": "application/trickle-ice-sdpfrag"},
                        timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as resp:
                        if resp.status not in (200, 204):
                            logger.warning(f"ICE candidate rejected: {resp.status}")
                except Exception as e:
                    logger.debug(f"ICE candidate error: {e}")

        elif msg_type == "get_streams":
            # Refresh stream list
            api_url = data.get("api_url", webrtc_url.replace(":8889", ":9997"))
            try:
                streams = await self._get_streams(api_url, timeout)
                if allowed_streams:
                    streams = [s for s in streams if s["name"] in allowed_streams]
                await ws.send_json({"type": "streams", "streams": streams})
            except Exception as e:
                await ws.send_json({"type": "error", "message": str(e)})

        elif msg_type == "ping":
            await ws.send_json({"type": "pong"})

    async def _get_streams(self, api_url: str, timeout: int) -> List[dict]:
        """Get list of active streams from MediaMTX API."""
        try:
            url = urljoin(api_url, "/v3/paths/list")
            async with self._http_session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    items = data.get("items", [])
                    return [
                        {
                            "name": item.get("name", ""),
                            "ready": item.get("ready", False),
                            "source": self._get_source_type(item),
                            "readers": len(item.get("readers", [])),
                            "bytesReceived": item.get("bytesReceived", 0),
                        }
                        for item in items
                    ]
                else:
                    logger.warning(f"MediaMTX API returned {resp.status}")
                    return []
        except Exception as e:
            logger.error(f"Failed to get streams from MediaMTX: {e}")
            raise

    def _get_source_type(self, item: dict) -> str:
        """Determine stream source type."""
        source = item.get("source", {})
        if not source:
            return "waiting"

        source_type = source.get("type", "unknown")
        if source_type == "rtspSession":
            return "RTSP"
        elif source_type == "rtmpConn":
            return "RTMP"
        elif source_type == "webRTCSession":
            return "WebRTC"
        elif source_type == "hlsMuxer":
            return "HLS"
        elif source_type == "rpiCameraSource":
            return "Camera"
        return source_type

    async def handle_http(
        self,
        request: web.Request,
        target: ServiceTarget
    ) -> web.Response:
        """Handle HTTP requests for HLS streams."""
        config = target.config
        hls_url = config.get("hls_url", "http://localhost:8888")
        allowed_streams = config.get("allowed_streams", [])
        timeout = config.get("api_timeout", 10)

        # Get the requested path after the service path
        path = request.match_info.get("path", "")

        # Validate stream access
        stream_name = path.split("/")[0] if path else ""
        if allowed_streams and stream_name not in allowed_streams:
            return web.json_response(
                {"error": "Access denied"},
                status=403
            )

        # Proxy HLS request to MediaMTX
        try:
            url = f"{hls_url}/{path}"
            async with self._http_session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                content = await resp.read()
                return web.Response(
                    body=content,
                    status=resp.status,
                    content_type=resp.content_type
                )
        except Exception as e:
            logger.error(f"HLS proxy error: {e}")
            return web.json_response(
                {"error": "Stream unavailable"},
                status=502
            )

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check MediaMTX connectivity."""
        config = target.config
        api_url = config.get("api_url", "http://localhost:9997")
        timeout = config.get("api_timeout", 10)

        try:
            url = urljoin(api_url, "/v3/paths/list")
            async with self._http_session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    count = len(data.get("items", []))
                    return {
                        "healthy": True,
                        "message": f"MediaMTX online, {count} streams"
                    }
                return {
                    "healthy": False,
                    "message": f"API returned {resp.status}"
                }
        except Exception as e:
            return {
                "healthy": False,
                "message": f"Cannot connect: {e}"
            }

    def get_client_assets(self) -> dict:
        return {
            "js": [],
            "css": [],
            "html": "mediamtx.html"
        }
