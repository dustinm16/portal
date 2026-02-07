"""Base class for managed services."""

import asyncio
import json
import os
import re
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any

import aiofiles

# PII redaction patterns for service logs
_LOG_REDACT_PATTERNS = [
    # IPv4 addresses (preserve port if present)
    (re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?\b'), r'[IP]\2'),
    # Stream keys (live_xxx, pub_xxx)
    (re.compile(r'(live_|pub_)[A-Za-z0-9_-]{10,}'), r'\1[REDACTED]'),
    # Generic tokens/secrets
    (re.compile(r'(password["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token["\s:=]+)[A-Za-z0-9_-]{20,}', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
]


def _redact_log_message(message: str) -> str:
    """Redact PII from a service log message."""
    for pattern, replacement in _LOG_REDACT_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


@dataclass
class ServiceInfo:
    """Information about a service type."""
    name: str
    display_name: str
    description: str
    version: str = "1.0.0"
    icon: str = "server"
    default_port: Optional[int] = None
    config_schema: dict = field(default_factory=dict)


class ManagedService(ABC):
    """Base class for managed services.

    A managed service is a server process that Portal starts, stops,
    and monitors. Examples: MediaMTX, TURN server, code-server.
    """

    def __init__(self, service_data: dict):
        """Initialize from database record.

        Args:
            service_data: Dict from unified services table (service_type='managed')
        """
        self.id = service_data['id']
        self.name = service_data['name']
        self.display_name = service_data.get('display_name') or self.name
        self.description = service_data.get('description', '')

        # Parse JSON config
        config_str = service_data.get('config', '{}')
        self.config = json.loads(config_str) if isinstance(config_str, str) else config_str

        self.port = service_data.get('port')
        self.binary_path = service_data.get('binary_path')
        self.config_path = service_data.get('config_path')
        self.working_dir = service_data.get('working_dir')
        self.enabled = bool(service_data.get('enabled', False))

        # Runtime state
        self.process: Optional[asyncio.subprocess.Process] = None
        self.status = service_data.get('status', 'stopped')
        self._log_task: Optional[asyncio.Task] = None
        self._db = None  # Set by ServiceManager

    @classmethod
    @abstractmethod
    def get_info(cls) -> ServiceInfo:
        """Return service type information."""
        pass

    @property
    @abstractmethod
    def binary_name(self) -> str:
        """Name of the binary executable."""
        pass

    @property
    def default_config(self) -> dict:
        """Default configuration values. Override in subclasses."""
        return {}

    def get_merged_config(self) -> dict:
        """Get config merged with defaults."""
        return {**self.default_config, **self.config}

    @abstractmethod
    async def generate_config_file(self) -> str:
        """Generate configuration file content.

        Returns:
            String content of the config file
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        pass

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate configuration.

        Args:
            config: Configuration dict to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        return True, ""

    def get_command(self) -> list[str]:
        """Get the command to start the service.

        Returns:
            List of command arguments
        """
        binary = self.binary_path or self.binary_name
        if self.config_path:
            return [binary, self.config_path]
        return [binary]

    def get_environment(self) -> dict:
        """Get environment variables for the process.

        Returns:
            Dict of environment variables
        """
        return os.environ.copy()

    async def _write_config_file(self) -> str:
        """Write config file and return path."""
        content = await self.generate_config_file()
        if not self.config_path:
            self.config_path = f'/tmp/portal_service_{self.id}.conf'

        async with aiofiles.open(self.config_path, 'w') as f:
            await f.write(content)

        return self.config_path

    async def start(self) -> tuple[bool, str]:
        """Start the service process.

        Returns:
            Tuple of (success, error_message)
        """
        if self.process and self.process.returncode is None:
            return False, "Service already running"

        try:
            # Write config file
            await self._write_config_file()

            # Get command and environment
            cmd = self.get_command()
            env = self.get_environment()
            cwd = self.working_dir or os.path.dirname(self.config_path or '/tmp')

            await self._log("info", f"Starting service: {' '.join(cmd)}")

            # Start process
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd
            )

            self.status = 'running'

            # Update database
            if self._db:
                await self._db.update_service_process_status(self.id, 'running', self.process.pid)

            # Start log reader task
            self._log_task = asyncio.create_task(self._read_process_output())

            await self._log("info", f"Service started with PID {self.process.pid}")
            return True, ""

        except FileNotFoundError:
            error = f"Binary not found: {self.binary_path or self.binary_name}"
            await self._log("error", error)
            self.status = 'error'
            if self._db:
                await self._db.update_service_process_status(self.id, 'error', error_message=error)
            return False, error

        except Exception as e:
            error = f"Failed to start: {str(e)}"
            await self._log("error", error)
            self.status = 'error'
            if self._db:
                await self._db.update_service_process_status(self.id, 'error', error_message=error)
            return False, error

    async def stop(self, timeout: float = 10.0) -> tuple[bool, str]:
        """Stop the service process.

        Args:
            timeout: Seconds to wait for graceful shutdown

        Returns:
            Tuple of (success, error_message)
        """
        if not self.process:
            self.status = 'stopped'
            if self._db:
                await self._db.update_service_process_status(self.id, 'stopped')
            return True, ""

        try:
            await self._log("info", "Stopping service...")

            # Try graceful termination first
            self.process.terminate()

            try:
                await asyncio.wait_for(self.process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                await self._log("warn", "Graceful shutdown timed out, killing process")
                self.process.kill()
                await self.process.wait()

            self.process = None
            self.status = 'stopped'

            # Cancel log reader
            if self._log_task:
                self._log_task.cancel()
                self._log_task = None

            # Update database
            if self._db:
                await self._db.update_service_process_status(self.id, 'stopped')

            await self._log("info", "Service stopped")
            return True, ""

        except Exception as e:
            error = f"Failed to stop: {str(e)}"
            await self._log("error", error)
            return False, error

    async def restart(self) -> tuple[bool, str]:
        """Restart the service.

        Returns:
            Tuple of (success, error_message)
        """
        await self._log("info", "Restarting service...")

        success, error = await self.stop()
        if not success:
            return False, f"Failed to stop: {error}"

        # Brief pause before restart
        await asyncio.sleep(1)

        success, error = await self.start()
        if not success:
            return False, f"Failed to start: {error}"

        if self._db:
            await self._db.increment_service_restart(self.id)

        return True, ""

    async def _read_process_output(self):
        """Read and log process stdout/stderr."""
        if not self.process:
            return

        async def read_stream(stream, level):
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode('utf-8', errors='replace').rstrip()
                if text:
                    await self._log(level, text)

        try:
            await asyncio.gather(
                read_stream(self.process.stdout, "info"),
                read_stream(self.process.stderr, "error")
            )
        except asyncio.CancelledError:
            pass

        # Process exited
        if self.process and self.process.returncode is not None:
            code = self.process.returncode
            if code != 0:
                await self._log("error", f"Process exited with code {code}")
                self.status = 'error'
                if self._db:
                    await self._db.update_service_process_status(
                        self.id, 'error',
                        error_message=f"Process exited with code {code}"
                    )
            else:
                self.status = 'stopped'
                if self._db:
                    await self._db.update_service_process_status(self.id, 'stopped')

    async def _log(self, level: str, message: str):
        """Log a message for this service (PII redacted)."""
        if self._db:
            await self._db.add_service_log(self.id, _redact_log_message(message), level)

    def get_status(self) -> dict:
        """Get current service status.

        Returns:
            Dict with status information
        """
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'status': self.status,
            'pid': self.process.pid if self.process else None,
            'enabled': self.enabled,
            'port': self.port,
            'config': self.config
        }

    async def cleanup(self):
        """Clean up resources (called on shutdown)."""
        if self.status == 'running':
            await self.stop()

        # Remove config file
        if self.config_path and os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
            except OSError:
                pass
