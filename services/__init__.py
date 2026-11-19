"""Managed Services Module.

This module provides the ServiceManager for controlling server processes
that Portal runs and manages (MediaMTX, TURN, etc.).
"""

import asyncio
import logging
from typing import Dict, Optional, Type

from config import Config

from .base import ManagedService, ServiceInfo

logger = logging.getLogger("portal.services")

# Registry of service type handlers
_service_types: Dict[str, Type[ManagedService]] = {}


def register_service(service_type: str):
    """Decorator to register a service type handler.

    Usage:
        @register_service("mediamtx")
        class MediaMTXService(ManagedService):
            ...
    """
    def decorator(cls: Type[ManagedService]):
        _service_types[service_type] = cls
        logger.info(f"Registered service type: {service_type}")
        return cls
    return decorator


def get_service_class(service_type: str) -> Optional[Type[ManagedService]]:
    """Get the handler class for a service type."""
    return _service_types.get(service_type)


def get_available_service_types() -> Dict[str, ServiceInfo]:
    """Get info about all available service types."""
    return {
        name: cls.get_info()
        for name, cls in _service_types.items()
    }


HEALTH_INTERVAL = 30.0          # seconds between health checks
HEALTH_FAIL_THRESHOLD = 3       # consecutive failed checks before a service counts as down
HEALTH_OK_THRESHOLD = 2         # consecutive good checks before a down service counts as up again


class ServiceManager:
    """Manages lifecycle of all managed services.

    The ServiceManager:
    - Loads service configurations from database
    - Starts/stops service processes
    - Monitors health and handles restarts
    - Provides API for service control
    """

    def __init__(self, db, on_event=None):
        """Initialize the service manager.

        Args:
            db: Database instance for persistence
            on_event: optional callable(event, data) told about service.health_changed
                (a transition only: down after HEALTH_FAIL_THRESHOLD failed checks, up after
                HEALTH_OK_THRESHOLD good ones) and about events the services raise themselves
                (gameserver.crashed). It must not block; errors in it are swallowed.
        """
        self._db = db
        self._on_event = on_event
        self._health_state: Dict[int, dict] = {}
        # Services stopped on purpose through stop_service: a stop someone asked for is not an
        # outage. Cleared by the next start_service (a start that then fails does count).
        self._stopped_on_purpose: set[int] = set()
        # Services found enabled and not running at the first check after the portal started:
        # the state found at startup is the baseline, not news. A service leaves this set once
        # it is seen running (or started through start_service), after which a stop counts.
        # A service whose auto-start was attempted by initialize() is never in it: the start
        # failing is exactly the outage to report, not a state found at startup.
        self._baseline_quiet: set[int] = set()
        self._autostart_attempted: set[int] = set()
        self._first_pass_done = False
        self._services: Dict[int, ManagedService] = {}
        self._health_task: Optional[asyncio.Task] = None
        self._shutdown = False

    async def initialize(self):
        """Initialize services from database.

        Loads all managed services (service_type='managed') and starts enabled ones.
        """
        logger.info("Initializing service manager...")

        # Load all managed services from unified services table
        services = await self._db.get_services_by_type('managed')

        for svc_data in services:
            # In unified table, 'plugin' field stores the handler type (e.g., 'mediamtx')
            service_type = svc_data.get('plugin')
            handler_class = get_service_class(service_type)

            if not handler_class:
                logger.warning(f"Unknown service type: {service_type} for {svc_data['name']}")
                continue

            try:
                service = handler_class(svc_data)
                service._db = self._db
                service._on_event = self._on_event
                self._services[svc_data['id']] = service
                logger.info(f"Loaded service: {svc_data['name']} ({service_type})")

                # Reconcile status against the outside world (systemd units)
                if hasattr(service, 'sync_status'):
                    try:
                        await service.sync_status()
                    except Exception as e:
                        logger.warning(f"sync_status failed for {svc_data['name']}: {e}")

                # Start if enabled (never in staged test mode: no side effects on the host)
                if svc_data.get('enabled') and not Config.STAGE_MODE:
                    logger.info(f"Auto-starting enabled service: {svc_data['name']}")
                    self._autostart_attempted.add(svc_data['id'])
                    success, error = await service.start()
                    if not success:
                        logger.error(f"Failed to auto-start {svc_data['name']}: {error}")

            except Exception as e:
                logger.error(f"Failed to load service {svc_data['name']}: {e}")

        # Start health monitor
        self._health_task = asyncio.create_task(self._health_monitor())
        logger.info(f"Service manager initialized with {len(self._services)} services")

    async def shutdown(self):
        """Shutdown all services gracefully."""
        logger.info("Shutting down service manager...")
        self._shutdown = True

        # Stop health monitor
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        # Stop all running services. Services that wrap an externally-owned
        # process (systemd units) are left running — Portal shutting down
        # must not take the host's services down with it.
        for service in self._services.values():
            if service.status == 'running' and getattr(service, 'stop_on_shutdown', True):
                logger.info(f"Stopping service: {service.name}")
                await service.stop()

        logger.info("Service manager shutdown complete")

    async def create_service(
        self,
        name: str,
        service_type: str,
        display_name: str = None,
        description: str = None,
        config: dict = None,
        port: int = None,
        enabled: bool = False,
        path: str = None
    ) -> Optional[ManagedService]:
        """Create a new managed service.

        Args:
            name: Unique service name
            service_type: Type of service (mediamtx, turn, etc.)
            display_name: Human-readable name
            description: Service description
            config: Service configuration
            port: Primary port
            enabled: Whether to enable immediately
            path: URL path for service (defaults to /managed/{name})

        Returns:
            The created ManagedService or None on error
        """
        handler_class = get_service_class(service_type)
        if not handler_class:
            logger.error(f"Unknown service type: {service_type}")
            return None

        try:
            # Get default port from service info
            info = handler_class.get_info()
            if port is None:
                port = info.default_port

            # Generate path if not provided
            if path is None:
                path = f"/managed/{name}"

            # Create in unified services table. Pass `enabled` explicitly — the
            # column defaults to 1, so without this every service would be
            # enabled regardless of the caller's intent.
            service_id = await self._db.create_service(
                name=name,
                path=path,
                plugin=service_type,
                host='127.0.0.1',
                port=port,
                config=config,
                icon=info.icon,
                service_type='managed',
                display_name=display_name or name,
                description=description,
                enabled=enabled,
            )

            # Load the service
            svc_data = await self._db.get_service_by_id(service_id)
            service = handler_class(svc_data)
            service._db = self._db
            service._on_event = self._on_event
            self._services[service_id] = service

            # Reconcile status for services that track an external process
            # (e.g. systemd units) so the card is accurate immediately.
            if hasattr(service, 'sync_status'):
                try:
                    await service.sync_status()
                except Exception as e:
                    logger.warning(f"sync_status failed for new service {name}: {e}")

            logger.info(f"Created service: {name} ({service_type})")

            # Start now if requested (enabled was already persisted above)
            if enabled:
                await self.start_service(service_id)

            return service

        except Exception as e:
            logger.error(f"Failed to create service {name}: {e}")
            return None

    async def delete_service(self, service_id: int) -> bool:
        """Delete a managed service.

        Args:
            service_id: ID of service to delete

        Returns:
            True if deleted successfully
        """
        service = self._services.get(service_id)
        if service:
            # Stop if running — but never take down an externally-owned
            # process (systemd unit) just because its Portal wrapper is
            # being removed.
            if service.status == 'running' and getattr(service, 'stop_on_shutdown', True):
                await service.stop()
            await service.cleanup()
            del self._services[service_id]
        self._health_state.pop(service_id, None)
        self._stopped_on_purpose.discard(service_id)
        self._baseline_quiet.discard(service_id)
        self._autostart_attempted.discard(service_id)

        # Delete from unified services table
        success = await self._db.delete_service(service_id)
        if success:
            logger.info(f"Deleted service ID {service_id}")
        return success

    async def get_service(self, service_id: int) -> Optional[ManagedService]:
        """Get a service by ID."""
        return self._services.get(service_id)

    async def get_service_by_name(self, name: str) -> Optional[ManagedService]:
        """Get a service by name."""
        for service in self._services.values():
            if service.name == name:
                return service
        return None

    async def get_service_by_type(self, service_type: str) -> Optional[ManagedService]:
        """Get the first service of a given type."""
        for service in self._services.values():
            info = service.get_info()
            if info.name == service_type:
                return service
        return None

    def get_all_services(self) -> list[ManagedService]:
        """Get all managed services."""
        return list(self._services.values())

    def get_running_services(self) -> list[ManagedService]:
        """Get all running services."""
        return [s for s in self._services.values() if s.status == 'running']

    async def start_service(self, service_id: int) -> tuple[bool, str]:
        """Start a managed service.

        Args:
            service_id: ID of service to start

        Returns:
            Tuple of (success, error_message)
        """
        service = self._services.get(service_id)
        if not service:
            return False, "Service not found"

        if service.status == 'running':
            return False, "Service already running"

        logger.info(f"Starting service: {service.name}")
        self._stopped_on_purpose.discard(service_id)
        self._baseline_quiet.discard(service_id)
        return await service.start()

    async def stop_service(self, service_id: int) -> tuple[bool, str]:
        """Stop a managed service.

        Args:
            service_id: ID of service to stop

        Returns:
            Tuple of (success, error_message)
        """
        service = self._services.get(service_id)
        if not service:
            return False, "Service not found"

        if service.status != 'running':
            return False, "Service not running"

        logger.info(f"Stopping service: {service.name}")
        result = await service.stop()
        if result[0]:
            self._stopped_on_purpose.add(service_id)
        return result

    async def restart_service(self, service_id: int) -> tuple[bool, str]:
        """Restart a managed service.

        Args:
            service_id: ID of service to restart

        Returns:
            Tuple of (success, error_message)
        """
        service = self._services.get(service_id)
        if not service:
            return False, "Service not found"

        logger.info(f"Restarting service: {service.name}")
        return await service.restart()

    async def enable_service(self, service_id: int) -> bool:
        """Enable a service (will auto-start on Portal boot).

        Args:
            service_id: ID of service to enable

        Returns:
            True if enabled successfully
        """
        service = self._services.get(service_id)
        if service:
            service.enabled = True
        return await self._db.update_service_full(service_id, enabled=1)

    async def disable_service(self, service_id: int) -> bool:
        """Disable a service (won't auto-start).

        Args:
            service_id: ID of service to disable

        Returns:
            True if disabled successfully
        """
        service = self._services.get(service_id)
        if service:
            service.enabled = False
        return await self._db.update_service_full(service_id, enabled=0)

    async def update_service_config(
        self,
        service_id: int,
        config: dict
    ) -> tuple[bool, str]:
        """Update service configuration.

        Args:
            service_id: ID of service to update
            config: New configuration

        Returns:
            Tuple of (success, error_message)
        """
        service = self._services.get(service_id)
        if not service:
            return False, "Service not found"

        # Validate config
        valid, error = service.validate_config(config)
        if not valid:
            return False, error

        # Update in unified services table
        await self._db.update_service_full(service_id, config=config)

        # Update in memory
        service.config = config

        # Restart if running to apply new config. Services that wrap an
        # external process (systemd) opt out — their "config" selects which
        # unit to track, and restarting wouldn't apply anything.
        if service.status == 'running' and getattr(service, 'restart_on_config_change', True):
            logger.info(f"Restarting {service.name} to apply config changes")
            return await service.restart()

        return True, ""

    async def get_service_status(self, service_id: int) -> Optional[dict]:
        """Get detailed service status.

        Args:
            service_id: ID of service

        Returns:
            Status dict or None if not found
        """
        service = self._services.get(service_id)
        if not service:
            return None

        # Reconcile with the outside world first (systemd units) so callers
        # that read status on demand (admin panel) see the real state. This
        # costs one `systemctl show` subprocess per systemd service per call —
        # fine for a handful; revisit if that grows large.
        if hasattr(service, 'sync_status'):
            try:
                await service.sync_status()
            except Exception as e:
                logger.error(f"sync_status failed for {service.name}: {e}")

        status = service.get_status()

        # Add health info from unified services table
        svc_data = await self._db.get_service_by_id(service_id)
        if svc_data:
            status['health_status'] = svc_data.get('health_status', 'unknown')
            status['last_health_check'] = svc_data.get('last_health_check')
            status['restart_count'] = svc_data.get('restart_count', 0)
            status['last_started_at'] = svc_data.get('last_started_at')
            status['last_stopped_at'] = svc_data.get('last_stopped_at')
            status['error_message'] = svc_data.get('error_message')
            if svc_data.get('description'):
                status['description'] = svc_data['description']

        return status

    async def get_service_logs(
        self,
        service_id: int,
        limit: int = 100,
        level: str = None
    ) -> list[dict]:
        """Get logs for a service.

        Args:
            service_id: ID of service
            limit: Max number of log entries
            level: Filter by log level

        Returns:
            List of log entries
        """
        service = self._services.get(service_id)
        if service is not None and hasattr(service, 'get_journal_logs'):
            # systemd-wrapped services have no Portal-captured output; pull
            # their logs from journalctl instead. Errors propagate: an empty
            # list would read as "No logs." rather than a failed fetch.
            return await service.get_journal_logs(limit)
        return await self._db.get_service_logs(service_id, limit, level)

    def _emit(self, event: str, data: dict) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event, data)
        except Exception as e:
            logger.warning(f"on_event hook failed for {event}: {type(e).__name__}")

    def _track_health(self, service: ManagedService, ok: bool) -> None:
        """Count one check for a service and report a transition. A service is down after
        HEALTH_FAIL_THRESHOLD failed checks in a row and up again after HEALTH_OK_THRESHOLD good
        ones, so a flapping service sends nothing and a steady one sends one alert per change."""
        st = self._health_state.setdefault(service.id, {"fails": 0, "oks": 0, "down": False})
        if ok:
            st["fails"] = 0
            if st["down"]:
                st["oks"] += 1
                if st["oks"] >= HEALTH_OK_THRESHOLD:
                    st.update(down=False, oks=0)
                    self._emit("service.health_changed", {
                        "id": service.id, "name": service.name, "display_name": service.display_name,
                        "state": "up", "status": service.status})
        else:
            st["oks"] = 0
            st["fails"] += 1
            if not st["down"] and st["fails"] >= HEALTH_FAIL_THRESHOLD:
                st["down"] = True
                self._emit("service.health_changed", {
                    "id": service.id, "name": service.name, "display_name": service.display_name,
                    "state": "down", "status": service.status, "failed_checks": st["fails"]})

    async def _check_services_once(self):
        """One pass of the health monitor over all services."""
        if not self._first_pass_done:
            # Baseline: an enabled service that is already stopped when the portal starts raises
            # no alert for that state; only a stop seen after it was running does. That holds
            # only for a service nobody tried to start: initialize() auto-starts every enabled
            # service (outside stage mode) before this pass, so one that is not running now
            # failed to start and counts as failing from this first pass.
            self._first_pass_done = True
            self._baseline_quiet = {
                sid for sid, sv in self._services.items()
                if sv.enabled and sv.status not in ('running', 'starting', 'stopping')
                and sid not in self._autostart_attempted}
        for service in list(self._services.values()):
            # Services that wrap an external process (systemd units)
            # reconcile their status from the outside world here — they
            # can start/stop without Portal's involvement.
            if hasattr(service, 'sync_status'):
                try:
                    await service.sync_status()
                except Exception as e:
                    logger.error(f"sync_status failed for {service.name}: {e}")

            # A service that is not enabled is not expected to run: no state, no alerts
            if service.status == 'running':
                self._baseline_quiet.discard(service.id)
                self._stopped_on_purpose.discard(service.id)
            if not service.enabled:
                self._health_state.pop(service.id, None)
            elif service.status in ('starting', 'stopping'):
                pass
            elif service.status != 'running':
                if service.id in self._stopped_on_purpose or service.id in self._baseline_quiet:
                    # stopped through the portal, or already stopped at startup: not failing
                    self._health_state.pop(service.id, None)
                else:
                    self._track_health(service, False)

            if service.status != 'running':
                continue

            try:
                healthy = await service.health_check()
                health_status = 'healthy' if healthy else 'unhealthy'

                await self._db.update_service_health_status(service.id, health_status)
                if service.enabled:
                    self._track_health(service, bool(healthy))

                if not healthy:
                    logger.warning(f"Service {service.name} is unhealthy")

                    # Check if process died
                    if service.process and service.process.returncode is not None:
                        await self._handle_crashed_service(service)

            except Exception as e:
                logger.error(f"Health check failed for {service.name}: {e}")
                await self._db.update_service_health_status(service.id, 'unknown')
                if service.enabled:
                    self._track_health(service, False)

    async def _stage_interval(self) -> float:
        try:
            return min(max(float(await self._db.get_setting("stage_health_interval") or HEALTH_INTERVAL), 0.25), HEALTH_INTERVAL)
        except Exception:
            return HEALTH_INTERVAL

    async def _wait_next_check(self):
        """Sleep until the next check. A staged instance (a test) may shorten the wait with the
        stage_health_interval setting, which a production instance never reads."""
        if not Config.STAGE_MODE:
            await asyncio.sleep(HEALTH_INTERVAL)
            return
        waited = 0.0
        while not self._shutdown and waited < await self._stage_interval():
            await asyncio.sleep(0.25)
            waited += 0.25

    async def _health_monitor(self):
        """Background task to monitor service health."""
        logger.info("Health monitor started")

        while not self._shutdown:
            try:
                await self._check_services_once()
            except Exception as e:
                logger.error(f"Health monitor error: {e}")

            await self._wait_next_check()

    async def _handle_crashed_service(self, service: ManagedService):
        """Handle a crashed service with exponential backoff restart."""
        svc_data = await self._db.get_service_by_id(service.id)
        restart_count = svc_data.get('restart_count', 0) + 1

        # Exponential backoff: 5s, 10s, 20s, 40s, ... max 5 min
        delay = min(300, 5 * (2 ** min(restart_count - 1, 6)))

        logger.info(f"Service {service.name} crashed. Restarting in {delay}s (attempt {restart_count})")

        await self._db.add_service_log(
            service.id,
            f"Service crashed. Restarting in {delay}s (attempt {restart_count})",
            "warn"
        )

        async def _delayed_restart():
            await asyncio.sleep(delay)
            if not self._shutdown:
                success, error = await service.start()
                if success:
                    await self._db.increment_service_restart(service.id)
                else:
                    logger.error(f"Failed to restart {service.name}: {error}")

        asyncio.ensure_future(_delayed_restart())


# Global service manager instance (initialized by server.py)
service_manager: Optional[ServiceManager] = None


async def init_service_manager(db, on_event=None) -> ServiceManager:
    """Initialize the global service manager.

    Args:
        db: Database instance

    Returns:
        Initialized ServiceManager
    """
    global service_manager
    service_manager = ServiceManager(db, on_event=on_event)
    await service_manager.initialize()
    return service_manager


async def shutdown_service_manager():
    """Shutdown the global service manager."""
    global service_manager
    if service_manager:
        await service_manager.shutdown()
        service_manager = None


# Import service implementations to register them
def load_service_types():
    """Load all service type implementations."""
    try:
        from . import mediamtx
    except ImportError as e:
        logger.warning(f"Failed to load mediamtx service: {e}")

    try:
        from . import searxng
    except ImportError as e:
        logger.warning(f"Failed to load searxng service: {e}")

    try:
        from . import systemd
    except ImportError as e:
        logger.warning(f"Failed to load systemd service: {e}")

    try:
        from . import gameserver
    except ImportError as e:
        logger.warning(f"Failed to load gameserver service: {e}")

    # Add more service imports here as they're implemented
    # from . import turn
    # from . import codeserver
