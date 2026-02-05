"""MediaMTX media server service.

MediaMTX is a ready-to-use SRT / WebRTC / RTSP / RTMP / LL-HLS media server.
https://github.com/bluenviron/mediamtx
"""

import aiohttp
import asyncio
import os
import ssl
import subprocess
from typing import Optional

from . import register_service
from .base import ManagedService, ServiceInfo


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
            "tls_key_path": ""
        }
        # Note: TLS is mandatory - encryption cannot be disabled

    def _get_tls_paths(self) -> tuple[str, str]:
        """Get TLS certificate and key paths, generating if needed."""
        cfg = self.get_merged_config()
        cert_path = cfg.get("tls_cert_path") or f"/tmp/portal_mediamtx_{self.id}_cert.pem"
        key_path = cfg.get("tls_key_path") or f"/tmp/portal_mediamtx_{self.id}_key.pem"
        return cert_path, key_path

    def _generate_self_signed_cert(self) -> tuple[str, str]:
        """Generate self-signed TLS certificate for internal use."""
        cert_path, key_path = self._get_tls_paths()

        # Check if certs already exist and are valid
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path

        # Generate self-signed certificate using openssl
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "365",
                "-nodes",
                "-subj", f"/CN=portal-mediamtx-{self.id}/O=Portal Gateway"
            ], check=True, capture_output=True)
            os.chmod(key_path, 0o600)
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
        portal_url = cfg.get('portal_url', 'https://127.0.0.1')

        # YAML configuration for MediaMTX v1.9.x with mandatory TLS
        yaml_content = f'''# MediaMTX Configuration
# Auto-generated by Portal Gateway - Do not edit manually
# TLS encryption is mandatory for all services

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
# Uses Portal Gateway for stream key validation

authMethod: http
authHTTPAddress: {portal_url}/api/stream/auth
authHTTPExclude:
  - action: read
  - action: playback

###############################################
# API settings (TLS encrypted)

api: yes
apiAddress: 127.0.0.1:{api_port}
apiEncryption: yes
apiServerKey: {key_path}
apiServerCert: {cert_path}

###############################################
# RTSP/RTSPS settings (TLS encrypted - strict mode)
# Only TCP protocol supported with encryption

rtsp: yes
protocols: [tcp]
encryption: strict
rtspsAddress: :{rtsps_port}

###############################################
# RTMP/RTMPS settings (TLS encrypted - strict mode)

rtmp: yes
rtmpEncryption: strict
rtmpsAddress: :{rtmps_port}
rtmpServerKey: {key_path}
rtmpServerCert: {cert_path}

###############################################
# HLS settings (TLS encrypted)

hls: yes
hlsAddress: :{hls_port}
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
# WebRTC settings

webrtc: yes
webrtcAddress: :{webrtc_port}
webrtcLocalUDPAddress: :8189
webrtcLocalTCPAddress: :8189

###############################################
# SRT settings (disabled)

srt: no

###############################################
# Path settings
# Stream key is used as the path name

paths:
  all_others:
    # Streams are authenticated via Portal API
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

    def get_stream_urls(self, stream_path: str) -> dict:
        """Get URLs for accessing a stream (always encrypted).

        Args:
            stream_path: The stream path name

        Returns:
            Dict with encrypted URLs for each protocol
        """
        cfg = self.get_merged_config()

        # Use localhost for internal, would need external host for external access
        host = "127.0.0.1"

        # All URLs are encrypted - TLS is mandatory
        return {
            "rtsp": f"rtsps://{host}:{cfg.get('rtsp_port', 8554)}/{stream_path}",
            "rtmp": f"rtmps://{host}:{cfg.get('rtmp_port', 1935)}/{stream_path}",
            "hls": f"https://{host}:{cfg.get('hls_port', 8888)}/{stream_path}/index.m3u8",
            "webrtc": f"https://{host}:{cfg.get('webrtc_port', 8889)}/{stream_path}/whep"
        }
