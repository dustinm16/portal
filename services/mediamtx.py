"""MediaMTX media server service.

MediaMTX is a ready-to-use SRT / WebRTC / RTSP / RTMP / LL-HLS media server.
https://github.com/bluenviron/mediamtx
"""

import aiohttp
import asyncio
import os
import ssl
import subprocess
from pathlib import Path
from time import monotonic
from typing import Callable, Optional

from . import register_service
from .base import ManagedService, ServiceInfo
from config import Config


# The one consumer of the paths list the health check already fetches (server.py sets it at startup):
# an async callable (payload, monotonic time of the answer). It is not a second API call: the answer
# is the one health_check reads every HEALTH_INTERVAL seconds to tell whether MediaMTX is up.
_paths_listener: Optional[Callable] = None

# The paths list is paged by MediaMTX (100 items a page unless asked otherwise; the answer carries
# "pageCount"; page numbers start at 0). The listener gets every page up to this many, so streams beyond
# the first 100 paths have numbers too. A list with more pages than this is read up to the bound and the
# paths on the pages after it get no reading (nothing is asked for them). Pages after the first are only
# fetched when a listener is set and the first answer reports more than one.
MAX_PATH_PAGES = 10


def set_paths_listener(listener: Optional[Callable]) -> None:
    global _paths_listener
    _paths_listener = listener


@register_service("mediamtx")
class MediaMTXService(ManagedService):
    """MediaMTX media streaming server.

    Supports:
    - RTSP (Real Time Streaming Protocol)
    - RTMP (Real Time Messaging Protocol)
    - HLS (HTTP Live Streaming)
    - WebRTC (Web Real-Time Communication)
    """

    @classmethod
    def get_info(cls) -> ServiceInfo:
        return ServiceInfo(
            name="mediamtx",
            display_name="MediaMTX",
            description="RTSP/RTMP/HLS/WebRTC media streaming server",
            version="1.0.0",
            icon="video",
            default_port=8554,
            config_schema={
                "type": "object",
                "properties": {
                    "rtsp_port": {
                        "type": "integer",
                        "default": 8554,
                        "description": "RTSP server port"
                    },
                    "rtmp_port": {
                        "type": "integer",
                        "default": 1935,
                        "description": "RTMP server port"
                    },
                    "hls_port": {
                        "type": "integer",
                        "default": 8888,
                        "description": "HLS server port"
                    },
                    "webrtc_port": {
                        "type": "integer",
                        "default": 8889,
                        "description": "WebRTC HTTP server port"
                    },
                    "api_port": {
                        "type": "integer",
                        "default": 9997,
                        "description": "API server port"
                    },
                    "log_level": {
                        "type": "string",
                        "enum": ["debug", "info", "warn", "error"],
                        "default": "info"
                    },
                    "read_timeout": {
                        "type": "string",
                        "default": "10s",
                        "description": "Read timeout"
                    },
                    "write_timeout": {
                        "type": "string",
                        "default": "10s",
                        "description": "Write timeout"
                    },
                    "tls_cert_path": {
                        "type": "string",
                        "default": "",
                        "description": "Path to TLS certificate (auto-generated if empty)"
                    },
                    "tls_key_path": {
                        "type": "string",
                        "default": "",
                        "description": "Path to TLS private key (auto-generated if empty)"
                    },
                    "rtmp_plain_enabled": {
                        "type": "boolean",
                        "default": False,
                        "description": "Allow plain RTMP (non-TLS) on port 1935 for temporary token auth"
                    }
                }
            }
        )

    @property
    def binary_name(self) -> str:
        return "mediamtx"

    @property
    def default_config(self) -> dict:
        return {
            "rtsp_port": 8554,
            "rtmp_port": 1935,
            "hls_port": 8888,
            "webrtc_port": 8889,
            "api_port": 9997,
            "log_level": "info",
            "read_timeout": "10s",
            "write_timeout": "10s",
            "tls_cert_path": "",
            "tls_key_path": "",
            "rtmp_plain_enabled": False
        }
        # Note: TLS is mandatory for RTSP/HLS/WebRTC/API
        # RTMP can optionally allow plain (non-TLS) when rtmp_plain_enabled=True

    def _get_tls_paths(self) -> tuple[str, str]:
        """Get TLS certificate and key paths.

        Priority:
        1. Explicit config paths
        2. Let's Encrypt certificates (auto-renewed)
        3. Self-signed fallback
        """
        cfg = self.get_merged_config()

        # Check for explicit config paths first
        if cfg.get("tls_cert_path") and cfg.get("tls_key_path"):
            return cfg["tls_cert_path"], cfg["tls_key_path"]

        # Prefer Let's Encrypt certificates (trusted by OBS and other clients)
        letsencrypt_cert = "/etc/letsencrypt/live/portal-mediamtx/fullchain.pem"
        letsencrypt_key = "/etc/letsencrypt/live/portal-mediamtx/privkey.pem"
        if os.path.exists(letsencrypt_cert) and os.path.exists(letsencrypt_key):
            return letsencrypt_cert, letsencrypt_key

        # Fall back to self-signed in a restricted project-local directory
        cert_dir = Path(__file__).parent.parent / 'certs' / 'mediamtx'
        cert_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(cert_dir), 0o700)
        return str(cert_dir / f"{self.id}_cert.pem"), str(cert_dir / f"{self.id}_key.pem")

    def _generate_self_signed_cert(self) -> tuple[str, str]:
        """Ensure TLS certificates exist, generating self-signed if needed."""
        cert_path, key_path = self._get_tls_paths()

        # If using Portal's certs, no need to generate
        if "origin.pem" in cert_path:
            return cert_path, key_path

        # Check if self-signed certs already exist
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path

        # Generate self-signed certificate using openssl
        # The parent directory already has 0o700 permissions from _get_tls_paths(),
        # so files created inside are not world-readable even briefly.
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "365",
                "-nodes",
                "-subj", f"/CN=portal-mediamtx-{self.id}/O=Open Relay Portal"
            ], check=True, capture_output=True)
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o600)
            return cert_path, key_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to generate TLS certificate: {e.stderr.decode()}")

    async def generate_config_file(self) -> str:
        """Generate mediamtx.yml configuration with mandatory TLS encryption."""
        cfg = self.get_merged_config()

        # Generate TLS certificate (mandatory - encryption is required)
        cert_path, key_path = self._generate_self_signed_cert()

        rtsp_port = cfg.get('rtsp_port', 8554)
        rtsps_port = cfg.get('rtsps_port', 8322)  # TLS RTSP port
        rtmp_port = cfg.get('rtmp_port', 1935)
        rtmps_port = cfg.get('rtmps_port', 1936)  # TLS RTMP port
        hls_port = cfg.get('hls_port', 8888)
        webrtc_port = cfg.get('webrtc_port', 8889)
        api_port = cfg.get('api_port', 9997)

        # Portal API URL for authentication hooks
        portal_url = cfg.get('portal_url', f'https://{Config.STREAM_HOSTNAME}')

        # RTMP plain (non-TLS) support for temporary token auth
        rtmp_plain_enabled = cfg.get('rtmp_plain_enabled', False)
        rtmp_encryption = 'optional' if rtmp_plain_enabled else 'strict'
        rtmp_bind = f'0.0.0.0:{rtmp_port}' if rtmp_plain_enabled else f'127.0.0.1:{rtmp_port}'

        # Config key names are stable across all supported MediaMTX versions (v1.9+).
        # The only deprecated key is readBufferCount (renamed to writeQueueSize in later
        # versions) but it is accepted as a warning-only alias so we keep it for
        # compatibility with older installs.
        yaml_content = f'''# MediaMTX Configuration
# Auto-generated by Open Relay Portal - Do not edit manually
# ALL services bound to localhost - external access via Open Relay Portal (port 443)
# TLS encryption is mandatory for all internal communication

###############################################
# General settings

logLevel: {cfg.get('log_level', 'info')}
logDestinations: [stdout]
readTimeout: {cfg.get('read_timeout', '10s')}
writeTimeout: {cfg.get('write_timeout', '10s')}

# Global TLS certificate (used by RTSP)
serverKey: {key_path}
serverCert: {cert_path}

###############################################
# Authentication settings
# Uses Open Relay Portal for stream key validation

authMethod: http
authHTTPAddress: {portal_url}/api/stream/auth
authHTTPExclude:
  - action: read
  - action: playback
  - action: api

###############################################
# API settings (localhost only, TLS encrypted)

api: yes
apiAddress: 127.0.0.1:{api_port}
apiEncryption: yes
apiServerKey: {key_path}
apiServerCert: {cert_path}

###############################################
# RTSP/RTSPS settings (localhost only, TLS encrypted)

rtsp: yes
protocols: [tcp]
encryption: optional
rtspAddress: 127.0.0.1:{rtsp_port}
rtspsAddress: 127.0.0.1:{rtsps_port}

###############################################
# RTMP/RTMPS settings
# RTMPS (1936) is exposed externally for OBS publishing
# Plain RTMP (1935): {'exposed for temporary token auth' if rtmp_plain_enabled else 'localhost only for security'}

rtmp: yes
rtmpEncryption: {rtmp_encryption}
rtmpAddress: {rtmp_bind}
rtmpsAddress: 0.0.0.0:{rtmps_port}
rtmpServerKey: {key_path}
rtmpServerCert: {cert_path}

###############################################
# HLS settings (localhost only, TLS encrypted)
# Playback via Portal: /api/stream/{{stream_key}}/hls/...

hls: yes
hlsAddress: 127.0.0.1:{hls_port}
hlsEncryption: yes
hlsServerKey: {key_path}
hlsServerCert: {cert_path}
hlsAlwaysRemux: no
hlsVariant: lowLatency
hlsSegmentCount: 7
hlsSegmentDuration: 1s
hlsPartDuration: 200ms
hlsSegmentMaxSize: 50M

###############################################
# WebRTC settings (localhost only)

webrtc: yes
webrtcAddress: 127.0.0.1:{webrtc_port}
webrtcLocalUDPAddress: 127.0.0.1:8189
webrtcLocalTCPAddress: 127.0.0.1:8189
webrtcICEServers2: []

###############################################
# SRT settings (disabled)

srt: no

###############################################
# Path settings

paths:
  all_others:
    runOnNotReady: |-
      curl -sk -X POST https://127.0.0.1:443/api/stream/event -H "Content-Type: application/json" -d '{{"event":"disconnect","path":"$MTX_PATH"}}'
'''
        return yaml_content

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate MediaMTX configuration."""
        # Check port ranges
        port_fields = ['rtsp_port', 'rtmp_port', 'hls_port', 'webrtc_port', 'api_port']
        for field in port_fields:
            if field in config:
                port = config[field]
                if not isinstance(port, int) or port < 1 or port > 65535:
                    return False, f"Invalid {field}: must be 1-65535"

        # Check log level
        if 'log_level' in config:
            if config['log_level'] not in ['debug', 'info', 'warn', 'error']:
                return False, "Invalid log_level: must be debug, info, warn, or error"

        return True, ""

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Get SSL context for internal HTTPS calls (allows self-signed certs)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Allow self-signed for internal use
        return ctx

    async def health_check(self) -> bool:
        """Check MediaMTX API health (always uses HTTPS)."""
        cfg = self.get_merged_config()
        api_port = cfg.get('api_port', 9997)

        try:
            connector = aiohttp.TCPConnector(ssl=self._get_ssl_context())
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    f'https://127.0.0.1:{api_port}/v3/paths/list',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status != 200:
                        return False
                    await self._offer_paths(session, api_port, resp)
                    return True
        except Exception:
            return False

    async def _offer_paths(self, session, api_port, resp) -> None:
        """Hand the answer of a successful health check to the listener, once: the first page, plus the
        further pages MediaMTX reports (at most MAX_PATH_PAGES in all, each with its own 5 s timeout). When a
        further page cannot be read nothing is handed over this time (a part of the paths would read as
        "stream gone"). Whatever goes wrong here (an unreadable body, a failing listener) never changes
        the health result, which depends on the first page alone."""
        listener = _paths_listener
        if listener is None:
            return
        try:
            payload = await resp.json()
            pages = payload.get("pageCount") if isinstance(payload, dict) else None
            if isinstance(pages, int) and not isinstance(pages, bool) and pages > 1:
                items = list(payload.get("items") or [])
                for page in range(1, min(pages, MAX_PATH_PAGES)):
                    async with session.get(
                        f'https://127.0.0.1:{api_port}/v3/paths/list?page={page}',
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as more:
                        if more.status != 200:
                            return
                        extra = await more.json()
                    items.extend(extra.get("items") or [])
                payload = {**payload, "items": items}
            await listener(payload, monotonic())
        except Exception:
            pass

    async def list_streams(self) -> list[dict]:
        """List active streams from MediaMTX API (always uses HTTPS).

        Returns:
            List of stream info dicts
        """
        cfg = self.get_merged_config()
        api_port = cfg.get('api_port', 9997)

        try:
            connector = aiohttp.TCPConnector(ssl=self._get_ssl_context())
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    f'https://127.0.0.1:{api_port}/v3/paths/list',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('items', [])
                    return []
        except Exception:
            return []

    async def get_stream_info(self, path: str) -> Optional[dict]:
        """Get info about a specific stream (always uses HTTPS).

        Args:
            path: Stream path name

        Returns:
            Stream info dict or None
        """
        cfg = self.get_merged_config()
        api_port = cfg.get('api_port', 9997)

        try:
            connector = aiohttp.TCPConnector(ssl=self._get_ssl_context())
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    f'https://127.0.0.1:{api_port}/v3/paths/get/{path}',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
        except Exception:
            return None

    def get_stream_urls(self, stream_path: str, portal_host: str = None) -> dict:
        """Get URLs for accessing a stream via Open Relay Portal (port 443).

        HLS goes through Portal on port 443; direct MediaMTX ports are
        localhost-only. The webrtc entries (WHEP/WHIP) carry only the
        signaling through Portal: the media flows straight to MediaMTX's WebRTC
        port, which the generated configuration binds to loopback, so they
        work only where a client can reach that port (same network), not
        through the public proxy.

        Args:
            stream_path: The stream path name (stream key)
            portal_host: The portal host for external URLs

        Returns:
            Dict with playback and publish URLs via Portal
        """
        # External URLs go through Portal on 443
        if not portal_host:
            portal_host = Config.HOSTNAME
        base_url = f"https://{portal_host}"

        return {
            "playback": {
                "hls": f"{base_url}/api/stream/{stream_path}/hls/index.m3u8",
                "webrtc": f"{base_url}/api/stream/{stream_path}/webrtc/whep",
            },
            "publish": {
                "webrtc": f"{base_url}/api/stream/{stream_path}/webrtc/whip",
            },
            "info": f"{base_url}/api/stream/{stream_path}/info"
        }
