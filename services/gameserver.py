"""Managed-service plugin for a Portal-deployed game server.

A thin subclass of SystemdService: the unit (``portal-gs-<name>``) is
generated and installed by ``gameservers.py`` at deploy time, then this
plugin drives its lifecycle via systemctl exactly like any other systemd
service — so the Services panel, the health monitor and the v1.9 grant
system all apply unchanged.
"""

from . import register_service
from .base import ServiceInfo
from .systemd import SystemdService


@register_service("gameserver")
class GameServerService(SystemdService):
    """A game server deployed by Portal (SteamCMD + generated systemd unit)."""

    @classmethod
    def get_info(cls) -> ServiceInfo:
        return ServiceInfo(
            name="gameserver",
            display_name="Game Server",
            description="A dedicated game server deployed by Portal via SteamCMD",
            version="1.0.0",
            icon="game",
            default_port=None,
            config_schema={
                "type": "object",
                "properties": {
                    "unit": {"type": "string", "description": "generated portal-gs-<name> unit"},
                    "game_server_id": {"type": "integer", "description": "game_servers.id"},
                },
                "required": ["unit"],
            },
        )

    def get_status(self) -> dict:
        status = super().get_status()
        status["game_server_id"] = (self.config or {}).get("game_server_id")
        return status
