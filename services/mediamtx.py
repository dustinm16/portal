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
from typing import Optional

from . import register_service
from .base import ManagedService, ServiceInfo
from config import Config


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
        # Uses the hostname for proper TLS certificate validation
        portal_url = cfg.get('portal_url', f'https://{Config.HOSTNAME}')

        # RTMP plain (non-TLS) support for temporary token auth
        rtmp_plain_enabled = cfg.get('rtmp_plain_enabled', False)
        rtmp_encryption = 'optional' if rtmp_plain_enabled else 'strict'
        rtmp_bind = f'0.0.0.0:{rtmp_port}' if rtmp_plain_enabled else f'127.0.0.1:{rtmp_port}'

        # YAML configuration for MediaMTX v1.9.x with mandatory TLS
        # All services bound to localhost - external access via Portal proxy on 443
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
readBufferCount: 512

# Global TLS certificate (used by RTSP/RTMP)
serverKey: {key_path}
serverCert: {cert_path}

###############################################
# Authentication settings
# Uses Open Relay Portal for stream key validation
# API, read, and internal actions excluded (Portal handles auth)

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
# Publishing: Use WHIP via Portal on 443 instead
# Direct RTSP kept for local testing only

rtsp: yes
protocols: [tcp]
encryption: strict
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
# Playback via Portal: /api/stream/{{stream_key}}/webrtc/whep
# Publishing via Portal: /api/stream/{{stream_key}}/webrtc/whip
# ICE over TCP through Portal on 443

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
# Stream key is used as the path name

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
                    return resp.status == 200
        except Exception:
            return False

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

        All external access goes through Portal on port 443.
        Direct MediaMTX ports are localhost-only.

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
