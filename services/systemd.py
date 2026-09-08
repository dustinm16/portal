"""Managed wrapper around an existing systemd unit.

Unlike MediaMTX or SearXNG, Portal does **not** spawn the process for this
service type — systemd owns it. This wrapper lets the Services panel
start / stop / restart and monitor a unit that is already installed on the
host (a game server, a file share, a database, anything shipped as a
``*.service``), so an admin doesn't need SSH for routine control.

Config: ``{"unit": "<name>"}`` — the unit name without the ``.service``
suffix (templated units like ``game@zomboid`` are allowed).

Lifecycle methods delegate to ``system_monitor`` (``sudo systemctl ...``);
status and health come from ``systemctl show`` / ``is-active``; logs come
from ``journalctl``. ``sync_status()`` is called by the ServiceManager
health monitor so the card stays accurate even when the unit is started or
stopped outside Portal.
"""

import asyncio

import system_monitor

from . import register_service
from .base import ManagedService, ServiceInfo


@register_service("systemd")
class SystemdService(ManagedService):
    """Control an existing systemd unit from Portal."""

    # Portal doesn't own the process. Never stop the unit implicitly — not
    # on Portal shutdown, not when the wrapper is deleted — only via an
    # explicit Stop. And don't restart it just because its config (which
    # unit to track) changed.
    stop_on_shutdown = False
    restart_on_config_change = False

    def __init__(self, service_data: dict):
        super().__init__(service_data)
        self._main_pid = None

    @classmethod
    def get_info(cls) -> ServiceInfo:
        return ServiceInfo(
            name="systemd",
            display_name="Systemd Unit",
            description=(
                "Control a systemd service that is already installed on the host "
                "(Portal starts/stops it via systemctl rather than running it)."
            ),
            version="1.0.0",
            icon="server",
            default_port=None,
            config_schema={
                "type": "object",
                "properties": {
                    "unit": {
                        "type": "string",
                        "default": "",
                        "description": (
                            "systemd unit name without the .service suffix "
                            "(e.g. palworld, or game@zomboid for a templated unit)"
                        ),
                    },
                },
                "required": ["unit"],
            },
        )

    @property
    def binary_name(self) -> str:
        return "systemctl"

    @property
    def unit(self) -> str:
        return str((self.config or {}).get("unit", "")).strip()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @staticmethod
    def check_config(config: dict) -> tuple[bool, str]:
        """Syntactic validation of a config dict (no instance needed)."""
        unit = str((config or {}).get("unit", "")).strip()
        if not unit:
            return False, "A systemd unit name is required"
        if not system_monitor._validate_service_name(unit):
            return False, f"Invalid systemd unit name: {unit!r}"
        return True, ""

    @staticmethod
    async def unit_exists(unit: str) -> bool:
        """True if `<unit>.service` is a known unit on this host."""
        unit = str(unit or "").strip()
        if not unit or not system_monitor._validate_service_name(unit):
            return False
        info = await asyncio.to_thread(system_monitor.get_service_status, unit)
        return info is not None

    def validate_config(self, config: dict) -> tuple[bool, str]:
        return self.check_config(config)

    # ------------------------------------------------------------------
    # Base-class abstract methods that don't apply here
    # ------------------------------------------------------------------
    async def generate_config_file(self) -> str:
        return ""

    async def _write_config_file(self) -> str:
        # systemd owns the unit file; nothing for Portal to write.
        return ""

    def get_command(self) -> list[str]:
        return ["systemctl", "status", f"{self.unit}.service"]

    async def cleanup(self):
        # Never touch the unit on Portal shutdown.
        return

    # ------------------------------------------------------------------
    # Status reconciliation
    # ------------------------------------------------------------------
    async def _show(self) -> dict | None:
        if not self.unit:
            return None
        return await asyncio.to_thread(system_monitor.get_service_status, self.unit)

    async def sync_status(self):
        """Reconcile self.status/pid with the actual systemd state."""
        info = await self._show()

        if info is None:
            new_status = 'error'
            new_pid = None
            err = f"systemd unit '{self.unit}.service' not found"
        else:
            active = info.get('active_state', '')
            if active == 'active':
                new_status = 'running'
            elif active == 'failed':
                new_status = 'error'
            else:  # inactive, activating, deactivating, reloading
                new_status = 'stopped'
            new_pid = info.get('main_pid') or None
            err = None

        self._main_pid = new_pid

        if new_status != self.status:
            self.status = new_status
            if self._db:
                await self._db.update_service_process_status(
                    self.id, new_status, new_pid, error_message=err
                )

    # ------------------------------------------------------------------
    # Lifecycle — delegate to systemctl
    # ------------------------------------------------------------------
    async def _control(self, action: str) -> tuple[bool, str]:
        ok, msg = self.check_config(self.config)
        if not ok:
            self.status = 'error'
            if self._db:
                await self._db.update_service_process_status(
                    self.id, 'error', error_message=msg
                )
            return False, msg

        await self._log("info", f"systemctl {action} {self.unit}.service")
        success, message = await asyncio.to_thread(
            system_monitor.control_service, self.unit, action
        )
        if success:
            # Let systemd settle, then read the real state back.
            await asyncio.sleep(0.5)
            await self.sync_status()
            await self._log("info", message)
            return True, ""

        self.status = 'error'
        if self._db:
            await self._db.update_service_process_status(
                self.id, 'error', error_message=message
            )
        await self._log("error", message)
        return False, message

    async def start(self) -> tuple[bool, str]:
        return await self._control("start")

    async def stop(self, timeout: float = 10.0) -> tuple[bool, str]:
        if not self.unit:
            return False, "No systemd unit configured"
        await self._log("info", f"systemctl stop {self.unit}.service")
        success, message = await asyncio.to_thread(
            system_monitor.control_service, self.unit, "stop"
        )
        if success:
            await asyncio.sleep(0.5)
            await self.sync_status()
            return True, ""
        await self._log("error", message)
        return False, message

    async def restart(self) -> tuple[bool, str]:
        ok, msg = await self._control("restart")
        if ok and self._db:
            await self._db.increment_service_restart(self.id)
        return ok, msg

    # ------------------------------------------------------------------
    # Health + logs + status payload
    # ------------------------------------------------------------------
    async def health_check(self) -> bool:
        info = await self._show()
        return bool(info and info.get('active_state') == 'active')

    async def get_journal_logs(self, limit: int = 100) -> list[dict]:
        if not self.unit:
            return []
        raw = await asyncio.to_thread(
            system_monitor.get_service_logs, self.unit, limit
        )
        entries = []
        for line in raw.splitlines():
            line = line.rstrip()
            if not line:
                continue
            ts, sep, rest = line.partition(' ')
            created_at = ''
            message = line
            if sep and len(ts) >= 19 and ts[4] == '-' and 'T' in ts:
                created_at = ts[:19]  # 2026-09-08T12:34:56 (naive UTC-ish)
                # rest is "<host> <unit>[<pid>]: <message>"
                _, _, after = rest.partition(': ')
                message = after or rest
            low = message.lower()
            if 'error' in low or 'fatal' in low or 'failed' in low:
                level = 'error'
            elif 'warn' in low:
                level = 'warn'
            else:
                level = 'info'
            entries.append({
                'level': level,
                'message': message,
                'created_at': created_at,
            })
        return entries

    def get_status(self) -> dict:
        status = super().get_status()
        status['pid'] = self._main_pid
        status['unit'] = self.unit
        status['external'] = True  # process owned by systemd, not Portal
        return status
