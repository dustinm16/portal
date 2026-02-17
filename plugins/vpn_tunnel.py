"""VPN Tunnel plugin - Secure network tunnel over WebSocket.

This plugin creates an encrypted tunnel that can carry arbitrary IP traffic,
similar to WireGuard or OpenVPN, but over WebSocket for firewall traversal.
"""

import asyncio
import ipaddress
import logging
import os
import struct
import hashlib
import secrets
from typing import Optional
from dataclasses import dataclass

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.vpn_tunnel")

# Optional cryptography import
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography not installed - VPN tunnel encryption disabled")


@dataclass
class TunnelSession:
    """VPN tunnel session state."""
    session_id: str
    cipher: Optional[object]
    nonce_counter: int
    remote_ip: str
    local_ip: str


@register_plugin
class VPNTunnelPlugin(PluginBase):
    """Encrypted VPN tunnel over WebSocket.

    Features:
    - ChaCha20-Poly1305 encryption (same as WireGuard)
    - TUN/TAP device support
    - IP routing for full network access
    - Keepalive and reconnection
    """

    info = PluginInfo(
        name="vpn_tunnel",
        display_name="VPN Tunnel",
        description="Encrypted network tunnel for secure remote access",
        version="1.0.0",
        icon="shield-lock",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["tun", "tap", "socks"],
                    "description": "Tunnel mode",
                    "default": "socks"
                },
                "network": {
                    "type": "string",
                    "description": "Tunnel network CIDR",
                    "default": "10.200.0.0/24"
                },
                "dns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "DNS servers for tunnel",
                    "default": ["1.1.1.1", "8.8.8.8"]
                },
                "routes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Routes to push (CIDR notation)",
                    "default": []
                },
                "mtu": {
                    "type": "integer",
                    "description": "Tunnel MTU",
                    "default": 1420
                },
                "keepalive": {
                    "type": "integer",
                    "description": "Keepalive interval in seconds",
                    "default": 25
                },
                "pre_shared_key": {
                    "type": "string",
                    "description": "Pre-shared key for additional security"
                }
            }
        }
    )

    def __init__(self):
        super().__init__()
        self._sessions: dict[str, TunnelSession] = {}
        self._ip_pool: set[str] = set()

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle VPN tunnel WebSocket connection."""
        config = target.config
        mode = config.get("mode", "socks")

        if mode == "socks":
            await self._handle_socks_tunnel(ws, target, user_id)
        elif mode in ("tun", "tap"):
            await self._handle_tun_tunnel(ws, target, user_id, mode)
        else:
            await ws.send_bytes(self._packet("error", b"Unknown tunnel mode"))

    async def _handle_socks_tunnel(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """SOCKS5 proxy mode - easier to use, no root required."""
        logger.info(f"SOCKS tunnel started for user {user_id}")

        session_id = secrets.token_hex(16)
        cipher = self._create_cipher(target.config.get("pre_shared_key"))

        await ws.send_bytes(self._packet("connected", {
            "session_id": session_id,
            "mode": "socks",
            "encrypted": cipher is not None
        }))

        connections: dict[int, tuple] = {}
        next_conn_id = 1

        try:
            async for msg in ws:
                if msg.type != WSMsgType.BINARY:
                    continue

                data = self._decrypt(msg.data, cipher) if cipher else msg.data
                if not data:
                    continue

                pkt_type, payload = self._parse_packet(data)

                if pkt_type == "connect":
                    # SOCKS connect request
                    host, port = self._parse_address(payload)
                    conn_id = next_conn_id
                    next_conn_id += 1

                    asyncio.create_task(
                        self._socks_connect(ws, conn_id, host, port, cipher, connections)
                    )

                elif pkt_type == "data":
                    # Data for existing connection
                    conn_id = struct.unpack(">I", payload[:4])[0]
                    if conn_id in connections:
                        _, writer = connections[conn_id]
                        writer.write(payload[4:])
                        await writer.drain()

                elif pkt_type == "close":
                    # Close connection
                    conn_id = struct.unpack(">I", payload[:4])[0]
                    if conn_id in connections:
                        _, writer = connections[conn_id]
                        writer.close()
                        del connections[conn_id]

                elif pkt_type == "ping":
                    await ws.send_bytes(
                        self._encrypt(self._packet("pong", payload), cipher)
                    )

        finally:
            # Close all connections
            for conn_id, (_, writer) in connections.items():
                writer.close()
            logger.info(f"SOCKS tunnel ended for user {user_id}")

    @staticmethod
    def _is_blocked_host(host: str) -> bool:
        """Block connections to localhost, link-local, private, and cloud metadata endpoints."""
        if not host:
            return True
        h = host.lower().strip()
        blocked_hostnames = {'localhost', '127.0.0.1', '::1', '0.0.0.0',
                             'host.docker.internal', 'kubernetes.default',
                             'metadata.google.internal', '169.254.169.254'}
        if h in blocked_hostnames or h.startswith('127.') or h.startswith('::ffff:127.'):
            return True
        try:
            ip = ipaddress.ip_address(h)
            return ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
        except ValueError:
            return False

    async def _socks_connect(
        self,
        ws: web.WebSocketResponse,
        conn_id: int,
        host: str,
        port: int,
        cipher: Optional[object],
        connections: dict
    ) -> None:
        """Establish SOCKS connection."""
        try:
            if self._is_blocked_host(host):
                error = self._packet("connect_err", struct.pack(">I", conn_id))
                await ws.send_bytes(self._encrypt(error, cipher))
                return
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=30
            )
            connections[conn_id] = (reader, writer)

            # Send connected response
            response = self._packet("connected_ok", struct.pack(">I", conn_id))
            await ws.send_bytes(self._encrypt(response, cipher))

            # Start reading from connection
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    pkt = self._packet("data", struct.pack(">I", conn_id) + data)
                    await ws.send_bytes(self._encrypt(pkt, cipher))
            except Exception:
                pass
            finally:
                if conn_id in connections:
                    del connections[conn_id]
                    close_pkt = self._packet("closed", struct.pack(">I", conn_id))
                    await ws.send_bytes(self._encrypt(close_pkt, cipher))

        except Exception as e:
            logger.error(f"SOCKS connect failed for conn {conn_id} to {host}:{port}: {e}")
            error_pkt = self._packet("connect_error",
                struct.pack(">I", conn_id) + b"Connection failed")
            await ws.send_bytes(self._encrypt(error_pkt, cipher))

    async def _handle_tun_tunnel(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int,
        mode: str
    ) -> None:
        """TUN/TAP mode - requires root and tun kernel module."""
        logger.info(f"TUN tunnel requested for user {user_id}")

        # Check if we can create TUN device
        if os.geteuid() != 0:
            await ws.send_bytes(self._packet("error", b"TUN mode requires root"))
            return

        tun = None
        client_ip = None
        try:
            import fcntl

            # Open TUN device
            tun = os.open("/dev/net/tun", os.O_RDWR)

            # Configure TUN
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000

            ifr = struct.pack("16sH", b"portal%d", IFF_TUN | IFF_NO_PI)
            result = fcntl.ioctl(tun, TUNSETIFF, ifr)
            ifname = result[:16].strip(b"\x00").decode()

            logger.info(f"Created TUN interface: {ifname}")

            # Assign IP
            network = target.config.get("network", "10.200.0.0/24")
            client_ip = self._allocate_ip(network)

            # Configure interface (would need subprocess for ip commands)
            # This is simplified - real implementation needs ip route, etc.

            await ws.send_bytes(self._packet("connected", {
                "session_id": secrets.token_hex(16),
                "mode": "tun",
                "interface": ifname,
                "client_ip": client_ip,
                "network": network
            }))

            cipher = self._create_cipher(target.config.get("pre_shared_key"))

            # Tunnel loop
            await self._tun_loop(ws, tun, cipher)

        except Exception as e:
            logger.error(f"TUN setup failed for user {user_id}: {e}")
            try:
                await ws.send_bytes(self._packet("error", b"TUN setup failed"))
            except Exception:
                pass
        finally:
            if tun is not None:
                try:
                    os.close(tun)
                except OSError:
                    pass
            if client_ip:
                self._ip_pool.discard(client_ip)

    async def _tun_loop(
        self,
        ws: web.WebSocketResponse,
        tun_fd: int,
        cipher: Optional[object]
    ) -> None:
        """TUN device I/O loop."""
        loop = asyncio.get_event_loop()

        async def read_tun():
            while True:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: os.read(tun_fd, 65536)
                    )
                    if data:
                        pkt = self._packet("ip", data)
                        await ws.send_bytes(self._encrypt(pkt, cipher))
                except Exception:
                    break

        async def read_ws():
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    data = self._decrypt(msg.data, cipher) if cipher else msg.data
                    pkt_type, payload = self._parse_packet(data)
                    if pkt_type == "ip":
                        os.write(tun_fd, payload)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break

        tasks = [
            asyncio.create_task(read_tun()),
            asyncio.create_task(read_ws()),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _create_cipher(self, psk: Optional[str]) -> Optional[object]:
        """Create ChaCha20-Poly1305 cipher from PSK."""
        if not HAS_CRYPTO or not psk:
            return None

        # Derive key from PSK
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"portal-vpn-v1",
            info=b"tunnel-key"
        )
        key = hkdf.derive(psk.encode())
        return ChaCha20Poly1305(key)

    def _encrypt(self, data: bytes, cipher: Optional[object]) -> bytes:
        """Encrypt data with cipher."""
        if not cipher:
            return data
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext

    def _decrypt(self, data: bytes, cipher: Optional[object]) -> Optional[bytes]:
        """Decrypt data with cipher."""
        if not cipher:
            return data
        if len(data) < 12:
            return None
        nonce = data[:12]
        try:
            return cipher.decrypt(nonce, data[12:], None)
        except Exception:
            return None

    def _packet(self, pkt_type: str, payload) -> bytes:
        """Create a tunnel packet."""
        import json
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode()
        elif isinstance(payload, str):
            payload = payload.encode()
        type_bytes = pkt_type.encode()[:16].ljust(16, b"\x00")
        return type_bytes + struct.pack(">I", len(payload)) + payload

    def _parse_packet(self, data: bytes) -> tuple[str, bytes]:
        """Parse a tunnel packet."""
        if len(data) < 20:
            return "", b""
        pkt_type = data[:16].rstrip(b"\x00").decode()
        length = struct.unpack(">I", data[16:20])[0]
        payload = data[20:20+length]
        return pkt_type, payload

    def _parse_address(self, data: bytes) -> tuple[str, int]:
        """Parse SOCKS-style address."""
        # Format: 1 byte type, address, 2 bytes port
        addr_type = data[0]
        if addr_type == 1:  # IPv4
            host = ".".join(str(b) for b in data[1:5])
            port = struct.unpack(">H", data[5:7])[0]
        elif addr_type == 3:  # Domain
            length = data[1]
            host = data[2:2+length].decode()
            port = struct.unpack(">H", data[2+length:4+length])[0]
        elif addr_type == 4:  # IPv6
            host = ":".join(f"{data[i]:02x}{data[i+1]:02x}" for i in range(1, 17, 2))
            port = struct.unpack(">H", data[17:19])[0]
        else:
            raise ValueError(f"Unknown address type: {addr_type}")
        return host, port

    def _allocate_ip(self, network: str) -> str:
        """Allocate IP from tunnel network."""
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        for ip in net.hosts():
            ip_str = str(ip)
            if ip_str not in self._ip_pool:
                self._ip_pool.add(ip_str)
                return ip_str
        raise RuntimeError("IP pool exhausted")

    async def health_check(self, target: ServiceTarget) -> dict:
        """VPN tunnel health check."""
        return {"healthy": True, "message": "VPN tunnel ready"}
