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

    def _announce_crash(self) -> None:
        self._emit_event("gameserver.crashed", {
            "id": self.id, "name": self.name, "display_name": self.display_name,
            "unit": self.unit})

    async def _observe(self, info) -> None:
        """The unit the portal writes has Restart=on-failure: after a crash systemd starts it again
        within seconds and it never rests in "failed", so a poll usually sees running both times.
        systemd counts those automatic restarts (NRestarts), so a count that grew since the last
        poll is a crash, unless a stop or restart was asked for through the portal. The first
        poll only sets the baseline (an earlier crash is not news after a portal restart); a
        count that fell (the unit was started by hand) sets the baseline again. systemd that does
        not report the count (older than v235) leaves this path off and the "failed" rule below."""
        count = info.get('n_restarts') if info is not None else None
        if not isinstance(count, int):
            return
        previous = getattr(self, '_n_restarts', None)
        self._n_restarts = count
        if previous is not None and count > previous and not self._expected_stop:
            self._announce_crash()

    async def _status_transition(self, old: str, new: str, info) -> None:
        """A unit that was running and is now "failed" without a stop or restart asked for through
        the portal exited unexpectedly: alert (a requested stop is "inactive" or flagged). This
        is the case where systemd gave up restarting; the restart count catches the others."""
        if (old == 'running' and new == 'error' and info is not None
                and info.get('active_state') == 'failed' and not self._expected_stop):
            self._announce_crash()

    def get_status(self) -> dict:
        status = super().get_status()
        status["game_server_id"] = (self.config or {}).get("game_server_id")
        return status
