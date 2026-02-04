"""TCP Tunnel plugin - TCP over WebSocket."""

import asyncio
import logging
import struct
import time
from typing import Dict, Optional

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget, ConnectionStats
from . import register_plugin

logger = logging.getLogger("portal.plugins.tcp_tunnel")


@register_plugin
class TCPTunnelPlugin(PluginBase):
    """Generic TCP tunnel over WebSocket.

    Allows any TCP protocol to be tunneled through WebSocket,
    useful for VNC, RDP, database connections, etc.
    """

    def __init__(self):
        super().__init__()
        self._active_connections: Dict[str, ConnectionStats] = {}

    def get_active_connections(self) -> list:
        """Get list of active connections with stats."""
        return [stats.to_dict() for stats in self._active_connections.values()]

    info = PluginInfo(
        name="tcp_tunnel",
        display_name="TCP Tunnel",
        description="Tunnel any TCP connection over WebSocket",
        version="1.0.0",
        icon="swap-horizontal",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target host"
                },
                "port": {
                    "type": "integer",
                    "description": "Target port"
                },
                "protocol_hint": {
                    "type": "string",
                    "enum": ["vnc", "rdp", "spice", "mysql", "postgres", "redis", "other"],
                    "description": "Protocol hint for logging",
                    "default": "other"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Connection timeout in seconds",
                    "default": 30
                },
                "buffer_size": {
                    "type": "integer",
                    "description": "Read buffer size",
                    "default": 65536
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
        """Handle TCP tunnel WebSocket connection."""
        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port)
        timeout = config.get("timeout", 30)
        buffer_size = config.get("buffer_size", 65536)
        protocol_hint = config.get("protocol_hint", "other")

        # Create connection stats
        conn_id = f"{user_id}:{target.id}:{time.time()}"
        stats = ConnectionStats(
            user_id=user_id,
            service_id=target.id,
            service_name=target.name
        )
        self._active_connections[conn_id] = stats

        logger.info(f"TCP tunnel for user {user_id}: {host}:{port} ({protocol_hint})")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            await ws.send_bytes(self._error_frame(f"Connection timeout: {host}:{port}"))
            del self._active_connections[conn_id]
            return
        except Exception as e:
            await ws.send_bytes(self._error_frame(f"Connection failed: {e}"))
            del self._active_connections[conn_id]
            return

        await ws.send_bytes(self._control_frame("connected", {"host": host, "port": port}))

        try:
            await asyncio.gather(
                self._tcp_to_ws(reader, ws, buffer_size, stats),
                self._ws_to_tcp(ws, writer, stats),
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            del self._active_connections[conn_id]
            logger.info(
                f"TCP tunnel closed for user {user_id}: {host}:{port} "
                f"(sent={stats.bytes_sent}, recv={stats.bytes_received})"
            )

    async def _tcp_to_ws(
        self,
        reader: asyncio.StreamReader,
        ws: web.WebSocketResponse,
        buffer_size: int,
        stats: Optional[ConnectionStats] = None
    ) -> None:
        """Forward TCP data to WebSocket."""
        try:
            while True:
                data = await reader.read(buffer_size)
                if not data:
                    break
                await ws.send_bytes(data)
                if stats:
                    stats.bytes_received += len(data)
                    stats.messages_received += 1
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"TCP read error: {e}")

    async def _ws_to_tcp(
        self,
        ws: web.WebSocketResponse,
        writer: asyncio.StreamWriter,
        stats: Optional[ConnectionStats] = None
    ) -> None:
        """Forward WebSocket data to TCP."""
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                    if stats:
                        stats.bytes_sent += len(msg.data)
                        stats.messages_sent += 1
                elif msg.type == WSMsgType.TEXT:
                    # Handle control messages
                    pass
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"WS read error: {e}")

    def _control_frame(self, msg_type: str, data: dict = None) -> bytes:
        """Create a control frame (type 0x00)."""
        import json
        payload = json.dumps({"type": msg_type, **(data or {})}).encode()
        return b"\x00" + struct.pack(">H", len(payload)) + payload

    def _error_frame(self, message: str) -> bytes:
        """Create an error frame."""
        return self._control_frame("error", {"message": message})

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check TCP connectivity."""
        host = target.config.get("host", target.host)
        port = target.config.get("port", target.port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return {"healthy": True, "message": f"Port open: {host}:{port}"}
        except Exception as e:
            return {"healthy": False, "message": f"Cannot reach {host}:{port}: {e}"}
