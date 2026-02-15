"""VNC plugin - VNC over WebSocket for noVNC."""

import asyncio
import logging

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.vnc")


@register_plugin
class VNCPlugin(PluginBase):
    """VNC over WebSocket plugin for noVNC client."""

    info = PluginInfo(
        name="vnc",
        display_name="VNC Desktop",
        description="Remote desktop access via VNC (noVNC compatible)",
        version="1.0.0",
        icon="monitor",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "VNC server hostname or IP"
                },
                "port": {
                    "type": "integer",
                    "description": "VNC port",
                    "default": 5900
                },
                "password": {
                    "type": "string",
                    "description": "VNC password (if required)"
                },
                "quality": {
                    "type": "integer",
                    "description": "JPEG quality (1-9)",
                    "default": 6
                },
                "resize": {
                    "type": "string",
                    "enum": ["off", "scale", "remote"],
                    "description": "Resize mode",
                    "default": "scale"
                },
                "view_only": {
                    "type": "boolean",
                    "description": "View only mode",
                    "default": False
                },
                "shared": {
                    "type": "boolean",
                    "description": "Shared session",
                    "default": True
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
        """Handle VNC WebSocket connection (binary passthrough for noVNC)."""
        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port or 5900)

        logger.info(f"VNC connection for user {user_id}: {host}:{port}")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=30
            )
        except asyncio.TimeoutError:
            logger.error(f"VNC connection timeout: {host}:{port}")
            return
        except Exception as e:
            logger.error(f"VNC connection failed: {e}")
            return

        logger.info(f"VNC connected to {host}:{port}")

        tasks = [
            asyncio.ensure_future(self._vnc_to_ws(reader, ws)),
            asyncio.ensure_future(self._ws_to_vnc(ws, writer)),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"VNC disconnected from {host}:{port}")

    async def _vnc_to_ws(
        self,
        reader: asyncio.StreamReader,
        ws: web.WebSocketResponse
    ) -> None:
        """Forward VNC data to WebSocket."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"VNC read error: {e}")

    async def _ws_to_vnc(
        self,
        ws: web.WebSocketResponse,
        writer: asyncio.StreamWriter
    ) -> None:
        """Forward WebSocket data to VNC."""
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"WS read error: {e}")

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check VNC server availability."""
        host = target.config.get("host", target.host)
        port = target.config.get("port", target.port or 5900)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            # Read VNC protocol version
            data = await asyncio.wait_for(reader.read(12), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            if data.startswith(b"RFB"):
                version = data.decode().strip()
                return {"healthy": True, "message": f"VNC server: {version}"}
            return {"healthy": False, "message": "Invalid VNC response"}
        except Exception as e:
            return {"healthy": False, "message": f"Cannot reach {host}:{port}: {e}"}

    def get_client_assets(self) -> dict:
        return {
            "js": ["novnc/vnc.min.js"],
            "css": [],
            "html": "vnc.html"
        }
