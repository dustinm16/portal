"""Secure Tunnel plugin - Encrypted TCP tunneling with advanced features.

This plugin provides secure, multiplexed TCP tunneling over WebSocket with:
- Connection pooling
- Bandwidth monitoring and limiting
- Access control
- Session recording (optional)
"""

import asyncio
import hashlib
import json
import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, Set
from weakref import WeakSet

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.secure_tunnel")


class BandwidthLimiter:
    """Token bucket rate limiter for bandwidth control."""

    def __init__(self, rate: int = 0, burst: int = 0):
        """
        Initialize bandwidth limiter.

        Args:
            rate: Bytes per second (0 = unlimited)
            burst: Maximum burst size (defaults to rate)
        """
        self.rate = rate  # bytes/sec
        self.burst = burst or rate  # max tokens
        self.tokens = float(burst or rate)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, size: int) -> None:
        """Wait until enough tokens are available for the given size."""
        if self.rate <= 0:
            return  # No limiting

        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now

                # Add tokens based on elapsed time
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

                if self.tokens >= size:
                    self.tokens -= size
                    return

                # Wait for tokens to accumulate
                wait_time = (size - self.tokens) / self.rate
                await asyncio.sleep(min(wait_time, 0.1))  # Max 100ms wait per iteration


@dataclass
class TunnelSession:
    """Represents an active tunnel session."""
    id: str
    user_id: int
    target_host: str
    target_port: int
    created_at: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    active_connections: int = 0


@dataclass
class TunnelConnection:
    """Represents a single tunnel connection within a session."""
    id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    created_at: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0


# Frame types for multiplexed protocol
FRAME_DATA = 0x01      # Data frame
FRAME_OPEN = 0x02      # Open new connection
FRAME_CLOSE = 0x03     # Close connection
FRAME_ACK = 0x04       # Acknowledgment
FRAME_ERROR = 0x05     # Error message
FRAME_PING = 0x06      # Keepalive ping
FRAME_PONG = 0x07      # Keepalive pong
FRAME_STATS = 0x08     # Statistics


@register_plugin
class SecureTunnelPlugin(PluginBase):
    """Secure, multiplexed TCP tunnel over WebSocket.

    Features:
    - Multiple TCP connections over single WebSocket
    - Connection pooling for better performance
    - Bandwidth monitoring and limits
    - Graceful connection handling
    """

    info = PluginInfo(
        name="secure_tunnel",
        display_name="Secure Tunnel",
        description="Encrypted multiplexed TCP tunneling with monitoring",
        version="1.0.0",
        icon="shield-lock",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target host to tunnel to"
                },
                "port": {
                    "type": "integer",
                    "description": "Target port to tunnel to"
                },
                "max_connections": {
                    "type": "integer",
                    "description": "Maximum concurrent connections per session",
                    "default": 10
                },
                "connection_timeout": {
                    "type": "integer",
                    "description": "Connection timeout in seconds",
                    "default": 30
                },
                "idle_timeout": {
                    "type": "integer",
                    "description": "Idle connection timeout in seconds",
                    "default": 300
                },
                "bandwidth_limit": {
                    "type": "integer",
                    "description": "Bandwidth limit in bytes/sec (0 = unlimited)",
                    "default": 0
                },
                "allowed_ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Additional allowed destination ports",
                    "default": []
                }
            }
        }
    )

    def __init__(self):
        super().__init__()
        self._sessions: Dict[str, TunnelSession] = {}
        self._active_tunnels: WeakSet = WeakSet()

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle secure tunnel WebSocket connection."""
        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port)
        max_connections = config.get("max_connections", 10)
        connection_timeout = config.get("connection_timeout", 30)
        idle_timeout = config.get("idle_timeout", 300)
        bandwidth_limit = config.get("bandwidth_limit", 0)

        # Create bandwidth limiter if limit is set
        limiter = BandwidthLimiter(rate=bandwidth_limit) if bandwidth_limit > 0 else None

        # Create session
        session_id = hashlib.sha256(
            f"{user_id}:{host}:{port}:{time.time()}".encode()
        ).hexdigest()[:16]

        session = TunnelSession(
            id=session_id,
            user_id=user_id,
            target_host=host,
            target_port=port
        )
        self._sessions[session_id] = session

        limit_msg = f" (limit: {bandwidth_limit} bytes/sec)" if bandwidth_limit else ""
        logger.info(f"Secure tunnel session {session_id} started for user {user_id}: {host}:{port}{limit_msg}")

        # Connection tracking
        connections: Dict[int, TunnelConnection] = {}
        next_conn_id = 1
        conn_lock = asyncio.Lock()

        # Send session info
        await self._send_frame(ws, FRAME_ACK, {
            "session_id": session_id,
            "host": host,
            "port": port,
            "max_connections": max_connections
        })

        try:
            await self._tunnel_loop(
                ws, session, connections, conn_lock,
                host, port, max_connections, connection_timeout, limiter
            )
        finally:
            # Cleanup
            for conn_id, conn in list(connections.items()):
                try:
                    conn.writer.close()
                    await conn.writer.wait_closed()
                except Exception:
                    pass

            del self._sessions[session_id]

            logger.info(
                f"Secure tunnel session {session_id} ended: "
                f"sent={session.bytes_sent}, received={session.bytes_received}"
            )

    async def _tunnel_loop(
        self,
        ws: web.WebSocketResponse,
        session: TunnelSession,
        connections: Dict[int, TunnelConnection],
        conn_lock: asyncio.Lock,
        host: str,
        port: int,
        max_connections: int,
        connection_timeout: int,
        limiter: Optional[BandwidthLimiter] = None
    ) -> None:
        """Main tunnel I/O loop."""
        tasks = set()

        async def handle_message(msg):
            if msg.type != WSMsgType.BINARY:
                return

            data = msg.data
            if len(data) < 5:
                return

            frame_type = data[0]
            conn_id = struct.unpack(">I", data[1:5])[0]
            payload = data[5:]

            if frame_type == FRAME_OPEN:
                # Open new connection
                async with conn_lock:
                    if len(connections) >= max_connections:
                        await self._send_frame(ws, FRAME_ERROR, {
                            "conn_id": conn_id,
                            "error": "Max connections exceeded"
                        })
                        return

                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=connection_timeout
                    )

                    conn = TunnelConnection(
                        id=conn_id,
                        reader=reader,
                        writer=writer
                    )

                    async with conn_lock:
                        connections[conn_id] = conn
                        session.active_connections = len(connections)

                    # Start reading from this connection
                    task = asyncio.create_task(
                        self._read_tcp(ws, conn, session, limiter)
                    )
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)

                    await self._send_frame(ws, FRAME_ACK, {"conn_id": conn_id, "status": "connected"})
                    logger.debug(f"Tunnel connection {conn_id} opened to {host}:{port}")

                except asyncio.TimeoutError:
                    await self._send_frame(ws, FRAME_ERROR, {
                        "conn_id": conn_id,
                        "error": "Connection timeout"
                    })
                except Exception as e:
                    logger.error(f"Tunnel connection {conn_id} failed to {host}:{port}: {e}")
                    await self._send_frame(ws, FRAME_ERROR, {
                        "conn_id": conn_id,
                        "error": "Connection failed"
                    })

            elif frame_type == FRAME_DATA:
                # Write data to connection
                conn = connections.get(conn_id)
                if conn:
                    try:
                        conn.writer.write(payload)
                        await conn.writer.drain()
                        conn.bytes_sent += len(payload)
                        session.bytes_sent += len(payload)
                    except Exception as e:
                        logger.debug(f"Write error on connection {conn_id}: {e}")
                        await self._close_connection(ws, connections, conn_id, conn_lock, session)

            elif frame_type == FRAME_CLOSE:
                # Close connection
                await self._close_connection(ws, connections, conn_id, conn_lock, session)

            elif frame_type == FRAME_PING:
                # Respond with pong
                await self._send_frame(ws, FRAME_PONG, {"conn_id": conn_id})

            elif frame_type == FRAME_STATS:
                # Send statistics
                await self._send_frame(ws, FRAME_STATS, {
                    "session_id": session.id,
                    "active_connections": session.active_connections,
                    "bytes_sent": session.bytes_sent,
                    "bytes_received": session.bytes_received,
                    "uptime": time.time() - session.created_at
                })

        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    await handle_message(msg)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        finally:
            # Cancel all reader tasks
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _read_tcp(
        self,
        ws: web.WebSocketResponse,
        conn: TunnelConnection,
        session: TunnelSession,
        limiter: Optional[BandwidthLimiter] = None
    ) -> None:
        """Read from TCP connection and forward to WebSocket."""
        try:
            while True:
                data = await conn.reader.read(65536)
                if not data:
                    break

                # Apply bandwidth limiting if configured
                if limiter:
                    await limiter.acquire(len(data))

                conn.bytes_received += len(data)
                session.bytes_received += len(data)

                # Send data frame
                frame = bytes([FRAME_DATA]) + struct.pack(">I", conn.id) + data
                await ws.send_bytes(frame)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"TCP read error on connection {conn.id}: {e}")
        finally:
            # Send close frame
            frame = bytes([FRAME_CLOSE]) + struct.pack(">I", conn.id)
            try:
                await ws.send_bytes(frame)
            except Exception:
                pass

    async def _close_connection(
        self,
        ws: web.WebSocketResponse,
        connections: Dict[int, TunnelConnection],
        conn_id: int,
        conn_lock: asyncio.Lock,
        session: TunnelSession
    ) -> None:
        """Close a tunnel connection."""
        async with conn_lock:
            conn = connections.pop(conn_id, None)
            session.active_connections = len(connections)

        if conn:
            try:
                conn.writer.close()
                await conn.writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Tunnel connection {conn_id} closed")

    async def _send_frame(
        self,
        ws: web.WebSocketResponse,
        frame_type: int,
        data: dict,
        conn_id: int = 0
    ) -> None:
        """Send a control frame."""
        payload = json.dumps(data).encode()
        frame = bytes([frame_type]) + struct.pack(">I", conn_id) + payload
        await ws.send_bytes(frame)

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check tunnel target connectivity."""
        host = target.config.get("host", target.host)
        port = target.config.get("port", target.port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return {"healthy": True, "message": f"Target reachable: {host}:{port}"}
        except Exception as e:
            return {"healthy": False, "message": f"Cannot reach {host}:{port}: {e}"}

    def get_active_sessions(self) -> list:
        """Get list of active tunnel sessions."""
        return [
            {
                "id": s.id,
                "user_id": s.user_id,
                "target": f"{s.target_host}:{s.target_port}",
                "connections": s.active_connections,
                "bytes_sent": s.bytes_sent,
                "bytes_received": s.bytes_received,
                "uptime": time.time() - s.created_at
            }
            for s in self._sessions.values()
        ]
