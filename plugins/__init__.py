"""Plugin system for Open Relay Portal."""

import importlib
import logging
from pathlib import Path
from typing import Optional

from .base import PluginBase, PluginInfo, ServiceTarget

logger = logging.getLogger("portal.plugins")

# Global plugin registry
_plugins: dict[str, PluginBase] = {}


def register_plugin(plugin_class: type[PluginBase]) -> type[PluginBase]:
    """Decorator to register a plugin class."""
    instance = plugin_class()
    _plugins[instance.name] = instance
    logger.info(f"Registered plugin: {instance.name} ({instance.display_name})")
    return plugin_class


def get_plugin(name: str) -> Optional[PluginBase]:
    """Get a plugin by name."""
    return _plugins.get(name)


def get_all_plugins() -> dict[str, PluginBase]:
    """Get all registered plugins."""
    return _plugins.copy()


def list_plugins() -> list[dict]:
    """List all plugins as dictionaries."""
    return [p.to_dict() for p in _plugins.values()]


async def initialize_plugins() -> None:
    """Initialize all registered plugins."""
    for name, plugin in _plugins.items():
        try:
            await plugin.initialize()
            logger.info(f"Initialized plugin: {name}")
        except Exception as e:
            logger.error(f"Failed to initialize plugin {name}: {e}")


async def shutdown_plugins() -> None:
    """Shutdown all registered plugins."""
    for name, plugin in _plugins.items():
        try:
            await plugin.shutdown()
            logger.info(f"Shutdown plugin: {name}")
        except Exception as e:
            logger.error(f"Failed to shutdown plugin {name}: {e}")


def load_builtin_plugins() -> None:
    """Load all built-in plugins."""
    plugin_dir = Path(__file__).parent

    # Import all Python files in plugins directory (except base and __init__)
    for path in plugin_dir.glob("*.py"):
        if path.stem in ("__init__", "base"):
            continue
        try:
            module_name = f"plugins.{path.stem}"
            importlib.import_module(module_name)
            logger.debug(f"Loaded plugin module: {module_name}")
        except Exception as e:
            logger.error(f"Failed to load plugin {path.stem}: {e}")


# Export public API
__all__ = [
    "PluginBase",
    "PluginInfo",
    "ServiceTarget",
    "register_plugin",
    "get_plugin",
    "get_all_plugins",
    "list_plugins",
    "initialize_plugins",
    "shutdown_plugins",
    "load_builtin_plugins",
]
