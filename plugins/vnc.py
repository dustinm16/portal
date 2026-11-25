"""VNC plugin - VNC over WebSocket for noVNC."""

import asyncio
import logging

from aiohttp import web, WSMsgType

from host_check import try_each_address
from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.vnc")

# How long to wait for the server's first bytes before relaying anyway. An RFB
# server speaks first; some wait for the client, so silence is not an error.
BANNER_PEEK_TIMEOUT = 5.0

# Application close codes (4000-4999) sent to the browser when the target is
# not a VNC server. vnc.html shows a message for each; the reason text is
# readable on its own as well.
CLOSE_RDP_HOST = 4010
CLOSE_NOT_VNC = 4011
CLOSE_REASONS = {
    CLOSE_RDP_HOST: b"This host speaks RDP, not VNC",
    CLOSE_NOT_VNC: b"This host does not speak VNC",
}

# An RDP server never speaks first, so a silent host is asked on a separate
# connection with the smallest valid RDP opening (TPKT header + X.224
# Connection Request asking for standard RDP security). Any RDP server answers
# with a TPKT-framed reply; a VNC server does not.
# The probe only makes sense on the standard RDP port; a silent host anywhere
# else is relayed as before. The timeout is short so a silent VNC server waits
# at most BANNER_PEEK_TIMEOUT plus this before the relay starts.
RDP_PORT = 3389
RDP_PROBE_TIMEOUT = 2.0
RDP_CONNECTION_REQUEST = (
    b"\x03\x00\x00\x13"                      # TPKT: version 3, length 19
    b"\x0e\xe0\x00\x00\x00\x00\x00"          # X.224 Connection Request
    b"\x01\x00\x08\x00\x00\x00\x00\x00"      # negotiation request: standard RDP security
)

RFB_MAGIC = b"RFB "
TPKT_PREFIX = b"\x03\x00"


async def peek_banner(reader: asyncio.StreamReader, timeout: float | None = None) -> tuple[bytes, bool]:
    """Read the server's first bytes without losing any of them.

    Returns (data, eof). Reads until four bytes are in hand, the bytes can no
    longer be the start of "RFB ", the server closes, or the timeout passes.
    Everything read is returned; the caller must forward it unchanged.
    """
    if timeout is None:
        timeout = BANNER_PEEK_TIMEOUT
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    data = b""
    while len(data) < len(RFB_MAGIC) and RFB_MAGIC.startswith(data):
        remaining = deadline - loop.time()
        if remaining <= 0:
            return data, False
        try:
            chunk = await asyncio.wait_for(reader.read(len(RFB_MAGIC) - len(data)), remaining)
        except asyncio.TimeoutError:
            return data, False
        if not chunk:
            return data, True
        data += chunk
    return data, False


async def probe_rdp(addresses: list[str], port: int, timeout: float | None = None) -> bool:
    """True when the host answers an RDP connection request.

    Dials the given (already policy-checked) addresses on a fresh connection,
    never the one carrying the session, and always closes it. Any failure
    counts as "not RDP".
    """
    if timeout is None:
        timeout = RDP_PROBE_TIMEOUT
    writer = None
    try:
        reader, writer = await try_each_address(
            addresses, lambda a: asyncio.open_connection(a, port), timeout
        )
        writer.write(RDP_CONNECTION_REQUEST)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout)
        return reply == TPKT_PREFIX
    except Exception:
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def classify_banner(data: bytes) -> str:
    """'rfb' (VNC, or too short to tell), 'rdp' (TPKT header), 'other', or 'silent'."""
    if not data:
        return "silent"
    if RFB_MAGIC.startswith(data) or data.startswith(RFB_MAGIC):
        return "rfb"
    if data.startswith(TPKT_PREFIX):
        return "rdp"
    return "other"


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
                    "writeOnly": True,
                    "format": "password",
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
            # User connections arrive with the already policy-checked address
            # in _pinned_hosts (set by the connection handler); dial those,
            # trying each in turn.
            reader, writer = await try_each_address(
                config.get("_pinned_hosts") or [host],
                lambda a: asyncio.open_connection(a, port),
                30
            )
        except asyncio.TimeoutError:
            logger.error(f"VNC connection timeout for user {user_id}: {host}:{port}")
            try:
                await ws.send_json({"type": "error", "message": "VNC connection timed out"})
            except Exception:
                pass
            return
        except Exception as e:
            logger.error(f"VNC connection failed for user {user_id}: {host}:{port}: {e}")
            try:
                await ws.send_json({"type": "error", "message": "VNC connection failed"})
            except Exception:
                pass
            return

        logger.info(f"VNC connected to {host}:{port}")

        # Peek at the first bytes. Anything read is forwarded unchanged so the
        # RFB handshake sees the exact stream; a host that is clearly not VNC
        # is refused with a reason the page can show. The upstream socket is
        # closed if the handler is cancelled or fails while peeking or probing.
        try:
            try:
                first, eof = await peek_banner(reader)
            except Exception as e:
                logger.debug(f"VNC banner read error: {e}")
                first, eof = b"", False
            kind = classify_banner(first)
            if kind == "silent" and not eof and self._is_rdp_port(port):
                # Nothing arrived: either a VNC server that waits for the client
                # or an RDP server, which never speaks first. Ask on a second
                # connection; the session socket stays untouched either way.
                if await probe_rdp(config.get("_pinned_hosts") or [host], port):
                    kind = "rdp"
        except BaseException:
            writer.close()
            raise
        if kind in ("rdp", "other"):
            code = CLOSE_RDP_HOST if kind == "rdp" else CLOSE_NOT_VNC
            logger.info(f"VNC target {host}:{port} is not VNC ({kind})")
            await self._close_refused(ws, writer, code)
            return
        if first:
            try:
                await ws.send_bytes(first)
            except Exception as e:
                logger.debug(f"VNC banner forward error: {e}")
                writer.close()
                return

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

    @staticmethod
    def _is_rdp_port(port) -> bool:
        try:
            return int(port) == RDP_PORT
        except (TypeError, ValueError):
            return False

    @staticmethod
    async def _close_refused(ws: web.WebSocketResponse, writer: asyncio.StreamWriter, code: int) -> None:
        """Close the upstream socket and tell the browser why."""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        try:
            await ws.close(code=code, message=CLOSE_REASONS[code])
        except Exception:
            pass

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
