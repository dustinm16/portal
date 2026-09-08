"""SearXNG metasearch engine service.

SearXNG is a privacy-respecting, hackable metasearch engine.
https://github.com/searxng/searxng

Portal runs it under uWSGI on a localhost port and reverse-proxies it (with an
auth gate) at ``https://<portal-host>/search/``.  SearXNG mounts its whole app
under that sub-path natively via ``server.base_url`` -- no SCRIPT_NAME/mount
tricks needed.

Install the SearXNG tree first with ``~/scripts/install-searxng.sh`` (creates the
``searxng`` system user, clones the source, builds the venv).  This module only
generates the runtime config and manages the uWSGI process.
"""

import os
import secrets
import stat

import aiohttp

from . import register_service
from .base import ManagedService, ServiceInfo
from config import Config

# Layout produced by ~/scripts/install-searxng.sh
SEARXNG_SRC = "/usr/local/searxng/searxng-src"
SEARXNG_VENV = "/usr/local/searxng/searx-pyenv"
SEARXNG_USER = "searxng"
SETTINGS_PATH = "/etc/searxng/settings.yml"
UWSGI_BIN = "/usr/bin/uwsgi"

# 8888/8889 are taken by the MediaMTX managed service on 127.0.0.1.
DEFAULT_PORT = 8890


@register_service("searxng")
class SearXNGService(ManagedService):
    """SearXNG metasearch engine, hosted under uWSGI."""

    @classmethod
    def get_info(cls) -> ServiceInfo:
        return ServiceInfo(
            name="searxng",
            display_name="SearXNG",
            description="Privacy-respecting metasearch engine (proxied at /search/)",
            version="1.0.0",
            icon="search",
            default_port=DEFAULT_PORT,
            config_schema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "default": DEFAULT_PORT,
                        "description": "Localhost port uWSGI serves SearXNG on",
                    },
                    "workers": {
                        "type": "integer",
                        "default": 4,
                        "minimum": 1,
                        "maximum": 16,
                        "description": "uWSGI worker processes",
                    },
                    "instance_name": {
                        "type": "string",
                        "default": "SearXNG",
                        "description": "Display name shown in the SearXNG UI",
                    },
                    "base_url": {
                        "type": "string",
                        "default": "",
                        "description": (
                            "Public URL SearXNG is served at (must end with /search/). "
                            "Defaults to https://<portal-host>/search/."
                        ),
                    },
                    "enable_json_api": {
                        "type": "boolean",
                        "default": True,
                        "description": "Expose ?format=json output (behind the portal auth gate)",
                    },
                    "safe_search": {
                        "type": "integer",
                        "enum": [0, 1, 2],
                        "default": 0,
                        "description": "0 none, 1 moderate, 2 strict",
                    },
                },
            },
        )

    @property
    def binary_name(self) -> str:
        return "uwsgi"

    @property
    def default_config(self) -> dict:
        return {
            "port": DEFAULT_PORT,
            "workers": 4,
            "instance_name": "SearXNG",
            "base_url": "",
            "enable_json_api": True,
            "safe_search": 0,
        }

    # ------------------------------------------------------------------ helpers

    def _base_url(self, cfg: dict) -> str:
        base = (cfg.get("base_url") or "").strip()
        if not base:
            base = f"https://{Config.HOSTNAME}/search/"
        if not base.endswith("/"):
            base += "/"
        return base

    async def _ensure_secret_key(self) -> str:
        """Return a stable secret_key, generating & persisting one on first run.

        The base class deletes and regenerates the uWSGI config on every
        stop/start, so the key cannot live in the generated file -- it is kept
        in the service's DB ``config`` (encrypted at rest).
        """
        key = self.config.get("secret_key")
        if not key:
            key = secrets.token_hex(32)
            self.config = {**self.config, "secret_key": key}
            if self._db:
                await self._db.update_service_full(self.id, config=self.config)
        return key

    async def _write_settings_yml(self, cfg: dict, secret_key: str) -> None:
        """Write /etc/searxng/settings.yml (readable by the searxng user)."""
        base_url = self._base_url(cfg)
        formats = ["html", "json"] if cfg.get("enable_json_api", True) else ["html"]
        formats_yml = "\n".join(f"    - {f}" for f in formats)

        content = f"""# Auto-generated by Open Relay Portal (services/searxng.py) - do not edit manually.
use_default_settings: true

general:
  debug: false
  instance_name: "{cfg.get('instance_name', 'SearXNG')}"

server:
  port: {int(cfg.get('port', DEFAULT_PORT))}
  bind_address: "127.0.0.1"
  base_url: "{base_url}"
  secret_key: "{secret_key}"
  limiter: false
  public_instance: false
  image_proxy: true

search:
  safe_search: {int(cfg.get('safe_search', 0))}
  formats:
{formats_yml}
"""
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        # root-owned, group-readable by the searxng user, no world access.
        try:
            import grp

            gid = grp.getgrnam(SEARXNG_USER).gr_gid
            os.chown(tmp, 0, gid)
        except (KeyError, PermissionError):
            pass
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0640
        os.replace(tmp, SETTINGS_PATH)

    # ------------------------------------------------------------- lifecycle

    async def generate_config_file(self) -> str:
        """Generate the uWSGI ini and (as a side effect) settings.yml."""
        cfg = self.get_merged_config()
        secret_key = await self._ensure_secret_key()
        await self._write_settings_yml(cfg, secret_key)

        port = int(cfg.get("port", DEFAULT_PORT))
        workers = int(cfg.get("workers", 4))

        return f"""# Auto-generated by Open Relay Portal (services/searxng.py) - do not edit manually.
[uwsgi]
http-socket = 127.0.0.1:{port}
chdir = {SEARXNG_SRC}
virtualenv = {SEARXNG_VENV}
plugin = python3
module = searx.webapp:application
env = SEARXNG_SETTINGS_PATH={SETTINGS_PATH}
master = true
workers = {workers}
enable-threads = true
lazy-apps = true
need-app = true
die-on-term = true
buffer-size = 8192
uid = {SEARXNG_USER}
gid = {SEARXNG_USER}
disable-logging = true
"""

    def get_command(self) -> list[str]:
        binary = self.binary_path or UWSGI_BIN
        return [binary, "--ini", self.config_path]

    def get_environment(self) -> dict:
        env = os.environ.copy()
        env["SEARXNG_SETTINGS_PATH"] = SETTINGS_PATH
        return env

    def validate_config(self, config: dict) -> tuple[bool, str]:
        port = config.get("port", DEFAULT_PORT)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            return False, "port must be an integer 1-65535"
        if port in (8888, 8889, 9997, 443):
            return False, f"port {port} collides with another portal service"
        workers = config.get("workers", 4)
        if not isinstance(workers, int) or not (1 <= workers <= 16):
            return False, "workers must be an integer 1-16"
        base = (config.get("base_url") or "").strip()
        if base and not (base.startswith("https://") and "/search" in base):
            return False, "base_url must be https:// and contain the /search/ path"
        if config.get("safe_search", 0) not in (0, 1, 2):
            return False, "safe_search must be 0, 1 or 2"
        return True, ""

    async def health_check(self) -> bool:
        cfg = self.get_merged_config()
        port = int(cfg.get("port", DEFAULT_PORT))
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{port}/search/healthz",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False
