"""SPICE plugin - SPICE remote desktop protocol over WebSocket.

This plugin provides SPICE console access for virtual machines via:
- WebSocket to SPICE proxy
- spice-html5 viewer support
- Ticket-based authentication (Proxmox, oVirt)
"""

import asyncio
import logging

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.spice")

# SPICE protocol constants
SPICE_MAGIC = b"REDQ"  # SPICE handshake magic
SPICE_VERSION_MAJOR = 2
SPICE_VERSION_MINOR = 2

# SPICE channel types
SPICE_CHANNEL_MAIN = 1
SPICE_CHANNEL_DISPLAY = 2
SPICE_CHANNEL_INPUTS = 3
SPICE_CHANNEL_CURSOR = 4
SPICE_CHANNEL_PLAYBACK = 5
SPICE_CHANNEL_RECORD = 6
SPICE_CHANNEL_TUNNEL = 7
SPICE_CHANNEL_SMARTCARD = 8
SPICE_CHANNEL_USBREDIR = 9
SPICE_CHANNEL_PORT = 10
SPICE_CHANNEL_WEBDAV = 11


@register_plugin
class SPICEPlugin(PluginBase):
    """SPICE remote desktop plugin.

    Proxies SPICE connections for VM consoles through WebSocket,
    compatible with spice-html5 viewer.
    """

    info = PluginInfo(
        name="spice",
        display_name="SPICE Console",
        description="SPICE remote desktop for VMs (Proxmox, oVirt)",
        version="1.0.0",
        icon="desktop",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "SPICE server host"
                },
                "port": {
                    "type": "integer",
                    "description": "SPICE server port",
                    "default": 5900
                },
                "password": {
                    "type": "string",
                    "description": "SPICE password/ticket"
                },
                "tls": {
                    "type": "boolean",
                    "description": "Use TLS encryption",
                    "default": False
                },
                "tls_port": {
                    "type": "integer",
                    "description": "TLS port (if different from port)"
                },
                "ca_cert": {
                    "type": "string",
                    "description": "CA certificate for TLS verification"
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
        """Handle SPICE WebSocket connection."""
        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port or 5900)
        password = config.get("password", "")
        use_tls = config.get("tls", False)
        tls_port = config.get("tls_port", port)
        timeout = config.get("timeout", 30)
        buffer_size = config.get("buffer_size", 65536)

        if use_tls:
            port = tls_port

        logger.info(f"SPICE connection for user {user_id}: {host}:{port}")

        try:
            # Connect to SPICE server
            if use_tls:
                import ssl
                ssl_context = ssl.create_default_context()
                ca_cert = config.get("ca_cert")
                if ca_cert:
                    ssl_context.load_verify_locations(cadata=ca_cert)
                else:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )

            logger.debug(f"Connected to SPICE server {host}:{port}")

        except asyncio.TimeoutError:
            logger.error(f"SPICE connection timeout: {host}:{port}")
            await ws.send_json({
                "type": "error",
                "message": "Connection timeout"
            })
            return
        except Exception as e:
            logger.error(f"SPICE connection failed for user {user_id}: {e}")
            await ws.send_json({
                "type": "error",
                "message": "Connection failed"
            })
            return

        # Send connected notification to client
        await ws.send_json({
            "type": "connected",
            "host": host,
            "port": port,
            "tls": use_tls
        })

        # If password is configured, send it to the client for SPICE auth
        if password:
            await ws.send_json({
                "type": "auth",
                "password": password
            })

        try:
            # Bidirectional relay
            await asyncio.gather(
                self._spice_to_ws(reader, ws, buffer_size, user_id),
                self._ws_to_spice(ws, writer, user_id),
            )
        except Exception as e:
            logger.error(f"SPICE relay error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"SPICE connection closed for user {user_id}")

    async def _spice_to_ws(
        self,
        reader: asyncio.StreamReader,
        ws: web.WebSocketResponse,
        buffer_size: int,
        user_id: int
    ) -> None:
        """Forward SPICE data to WebSocket."""
        try:
            while not ws.closed:
                data = await reader.read(buffer_size)
                if not data:
                    logger.debug("SPICE server closed connection")
                    break
                await ws.send_bytes(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"SPICE read error: {e}")

    async def _ws_to_spice(
        self,
        ws: web.WebSocketResponse,
        writer: asyncio.StreamWriter,
        user_id: int
    ) -> None:
        """Forward WebSocket data to SPICE server."""
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                elif msg.type == WSMsgType.TEXT:
                    # Handle control messages from client
                    try:
                        import json
                        data = json.loads(msg.data)
                        if data.get("type") == "ping":
                            await ws.send_json({"type": "pong"})
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"WS read error: {e}")

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check SPICE server connectivity."""
        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port or 5900)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return {
                "healthy": True,
                "message": f"SPICE port open: {host}:{port}"
            }
        except Exception as e:
            return {
                "healthy": False,
                "message": f"Cannot reach {host}:{port}: {e}"
            }

    def get_client_assets(self) -> dict:
        return {
            "js": ["spice-html5/spicearraybuffer.js", "spice-html5/enums.js",
                   "spice-html5/atKeynames.js", "spice-html5/utils.js",
                   "spice-html5/png.js", "spice-html5/lz.js", "spice-html5/quic.js",
                   "spice-html5/bitmap.js", "spice-html5/spicedataview.js",
                   "spice-html5/spicetype.js", "spice-html5/spicemsg.js",
                   "spice-html5/wire.js", "spice-html5/spiceconn.js",
                   "spice-html5/display.js", "spice-html5/main.js",
                   "spice-html5/inputs.js", "spice-html5/cursor.js",
                   "spice-html5/playback.js", "spice-html5/simulatecursor.js",
                   "spice-html5/spice.js"],
            "css": ["spice-html5/spice.css"],
            "html": "spice.html"
        }
