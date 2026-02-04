"""Base plugin class for Portal Gateway."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
from aiohttp import web


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    display_name: str
    description: str
    version: str = "1.0.0"
    author: str = ""
    icon: str = "cube"
    protocols: list[str] = field(default_factory=lambda: ["websocket"])
    config_schema: dict = field(default_factory=dict)


@dataclass
class ServiceTarget:
    """Target service configuration."""
    id: int
    name: str
    plugin: str
    host: str
    port: int
    config: dict = field(default_factory=dict)


class PluginBase(ABC):
    """Base class for all Portal Gateway plugins."""

    # Plugin metadata - override in subclass
    info: PluginInfo = None

    def __init__(self):
        if self.info is None:
            raise ValueError(f"Plugin {self.__class__.__name__} must define 'info'")

    @property
    def name(self) -> str:
        return self.info.name

    @property
    def display_name(self) -> str:
        return self.info.display_name

    async def initialize(self) -> None:
        """Called when plugin is loaded. Override for setup logic."""
        pass

    async def shutdown(self) -> None:
        """Called when plugin is unloaded. Override for cleanup."""
        pass

    @abstractmethod
    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle WebSocket connection to target service.

        Args:
            ws: Client WebSocket connection
            target: Target service configuration
            user_id: Authenticated user ID
        """
        pass

    async def handle_http(
        self,
        request: web.Request,
        target: ServiceTarget
    ) -> web.Response:
        """Handle HTTP request to target service.

        Override for HTTP proxy functionality.
        """
        return web.json_response(
            {"error": f"Plugin {self.name} does not support HTTP"},
            status=501
        )

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check if target service is healthy.

        Returns:
            Dict with 'healthy' bool and optional 'message'
        """
        return {"healthy": True, "message": "No health check implemented"}

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate service configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        return True, ""

    def get_client_assets(self) -> dict:
        """Return client-side assets needed for this plugin.

        Returns:
            Dict with 'js', 'css', 'html' keys containing asset paths
        """
        return {"js": [], "css": [], "html": None}

    def to_dict(self) -> dict:
        """Convert plugin info to dictionary."""
        return {
            "name": self.info.name,
            "display_name": self.info.display_name,
            "description": self.info.description,
            "version": self.info.version,
            "author": self.info.author,
            "icon": self.info.icon,
            "protocols": self.info.protocols,
            "config_schema": self.info.config_schema,
        }
