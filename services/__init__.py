"""Managed Services Module.

This module provides the ServiceManager for controlling server processes
that Portal runs and manages (MediaMTX, TURN, etc.).
"""

import asyncio
import logging
from typing import Dict, Optional, Type

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


class ServiceManager:
    """Manages lifecycle of all managed services.

    The ServiceManager:
    - Loads service configurations from database
    - Starts/stops service processes
    - Monitors health and handles restarts
    - Provides API for service control
    """

    def __init__(self, db):
        """Initialize the service manager.

        Args:
            db: Database instance for persistence
        """
        self._db = db
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
                self._services[svc_data['id']] = service
                logger.info(f"Loaded service: {svc_data['name']} ({service_type})")

                # Start if enabled
                if svc_data.get('enabled'):
                    logger.info(f"Auto-starting enabled service: {svc_data['name']}")
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

        # Stop all running services
        for service in self._services.values():
            if service.status == 'running':
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

            # Create in unified services table
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
            )

            # Load the service
            svc_data = await self._db.get_service_by_id(service_id)
            service = handler_class(svc_data)
            service._db = self._db
            self._services[service_id] = service

            logger.info(f"Created service: {name} ({service_type})")

            # Enable and start if requested
            if enabled:
                await self.enable_service(service_id)
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
            # Stop if running
            if service.status == 'running':
                await service.stop()
            await service.cleanup()
            del self._services[service_id]

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
        return await service.stop()

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

        # Restart if running to apply new config
        if service.status == 'running':
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
        return await self._db.get_service_logs(service_id, limit, level)

    async def _health_monitor(self):
        """Background task to monitor service health."""
        logger.info("Health monitor started")

        while not self._shutdown:
            try:
                for service in self._services.values():
                    if service.status != 'running':
                        continue

                    try:
                        healthy = await service.health_check()
                        health_status = 'healthy' if healthy else 'unhealthy'

                        await self._db.update_service_health_status(service.id, health_status)

                        if not healthy:
                            logger.warning(f"Service {service.name} is unhealthy")

                            # Check if process died
                            if service.process and service.process.returncode is not None:
                                await self._handle_crashed_service(service)

                    except Exception as e:
                        logger.error(f"Health check failed for {service.name}: {e}")
                        await self._db.update_service_health_status(service.id, 'unknown')

            except Exception as e:
                logger.error(f"Health monitor error: {e}")

            # Check every 30 seconds
            await asyncio.sleep(30)

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


async def init_service_manager(db) -> ServiceManager:
    """Initialize the global service manager.

    Args:
        db: Database instance

    Returns:
        Initialized ServiceManager
    """
    global service_manager
    service_manager = ServiceManager(db)
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

    # Add more service imports here as they're implemented
    # from . import turn
    # from . import codeserver
