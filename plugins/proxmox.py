"""Proxmox plugin - Proxmox VE integration.

This plugin provides integration with Proxmox Virtual Environment:
- List nodes, VMs, and containers
- Start/stop/restart operations
- Console access (VNC/SPICE)
- Resource monitoring
"""

import asyncio
import json
import logging
import ssl
from typing import Optional, Dict, List, Any
from urllib.parse import urljoin

import aiohttp
from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.proxmox")


class ProxmoxAPI:
    """Proxmox VE API client."""

    def __init__(
        self,
        host: str,
        port: int = 8006,
        verify_ssl: bool = False,
        timeout: int = 30
    ):
        self.base_url = f"https://{host}:{port}/api2/json"
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._ticket: Optional[str] = None
        self._csrf_token: Optional[str] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def authenticate(self, username: str, password: str = None, api_token: str = None):
        """Authenticate with Proxmox API."""
        session = await self._get_session()

        if api_token:
            # API token authentication (format: user@realm!tokenid=secret)
            self._ticket = None
            self._csrf_token = None
            # Token is used directly in headers
            return True

        # Password authentication
        url = f"{self.base_url}/access/ticket"
        data = {
            "username": username,
            "password": password
        }

        try:
            async with session.post(
                url,
                data=data,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    data = result.get("data", {})
                    self._ticket = data.get("ticket")
                    self._csrf_token = data.get("CSRFPreventionToken")
                    return True
                else:
                    logger.error(f"Proxmox auth failed: {resp.status}")
                    return False
        except Exception as e:
            logger.error(f"Proxmox auth error: {e}")
            return False

    def _get_headers(self, api_token: str = None) -> dict:
        """Get request headers with authentication."""
        headers = {}
        if api_token:
            headers["Authorization"] = f"PVEAPIToken={api_token}"
        elif self._ticket:
            headers["Cookie"] = f"PVEAuthCookie={self._ticket}"
            if self._csrf_token:
                headers["CSRFPreventionToken"] = self._csrf_token
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        data: dict = None,
        api_token: str = None
    ) -> Optional[dict]:
        """Make API request."""
        session = await self._get_session()
        url = f"{self.base_url}{path}"
        headers = self._get_headers(api_token)

        try:
            async with session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    return result.get("data")
                else:
                    text = await resp.text()
                    logger.warning(f"Proxmox API {method} {path}: {resp.status} - {text}")
                    return None
        except Exception as e:
            logger.error(f"Proxmox API error: {e}")
            return None

    async def get_nodes(self, api_token: str = None) -> List[dict]:
        """Get list of nodes."""
        data = await self._request("GET", "/nodes", api_token=api_token)
        return data or []

    async def get_vms(self, node: str, api_token: str = None) -> List[dict]:
        """Get list of VMs on a node."""
        data = await self._request("GET", f"/nodes/{node}/qemu", api_token=api_token)
        return data or []

    async def get_containers(self, node: str, api_token: str = None) -> List[dict]:
        """Get list of containers on a node."""
        data = await self._request("GET", f"/nodes/{node}/lxc", api_token=api_token)
        return data or []

    async def get_vm_status(self, node: str, vmid: int, api_token: str = None) -> Optional[dict]:
        """Get VM status."""
        return await self._request("GET", f"/nodes/{node}/qemu/{vmid}/status/current", api_token=api_token)

    async def get_container_status(self, node: str, vmid: int, api_token: str = None) -> Optional[dict]:
        """Get container status."""
        return await self._request("GET", f"/nodes/{node}/lxc/{vmid}/status/current", api_token=api_token)

    async def start_vm(self, node: str, vmid: int, api_token: str = None) -> bool:
        """Start a VM."""
        result = await self._request("POST", f"/nodes/{node}/qemu/{vmid}/status/start", api_token=api_token)
        return result is not None

    async def stop_vm(self, node: str, vmid: int, api_token: str = None) -> bool:
        """Stop a VM."""
        result = await self._request("POST", f"/nodes/{node}/qemu/{vmid}/status/stop", api_token=api_token)
        return result is not None

    async def shutdown_vm(self, node: str, vmid: int, api_token: str = None) -> bool:
        """Gracefully shutdown a VM."""
        result = await self._request("POST", f"/nodes/{node}/qemu/{vmid}/status/shutdown", api_token=api_token)
        return result is not None

    async def reset_vm(self, node: str, vmid: int, api_token: str = None) -> bool:
        """Reset a VM."""
        result = await self._request("POST", f"/nodes/{node}/qemu/{vmid}/status/reset", api_token=api_token)
        return result is not None

    async def get_vnc_ticket(self, node: str, vmid: int, vm_type: str = "qemu", api_token: str = None) -> Optional[dict]:
        """Get VNC console ticket."""
        path = f"/nodes/{node}/{vm_type}/{vmid}/vncproxy"
        return await self._request("POST", path, data={"websocket": 1}, api_token=api_token)

    async def get_spice_ticket(self, node: str, vmid: int, vm_type: str = "qemu", api_token: str = None) -> Optional[dict]:
        """Get SPICE console ticket."""
        path = f"/nodes/{node}/{vm_type}/{vmid}/spiceproxy"
        return await self._request("POST", path, api_token=api_token)

    async def get_termproxy(self, node: str, vmid: int, vm_type: str = "lxc", api_token: str = None) -> Optional[dict]:
        """Get terminal proxy ticket for container."""
        path = f"/nodes/{node}/{vm_type}/{vmid}/termproxy"
        return await self._request("POST", path, api_token=api_token)


@register_plugin
class ProxmoxPlugin(PluginBase):
    """Proxmox VE integration plugin.

    Provides VM/container management and console access.
    """

    info = PluginInfo(
        name="proxmox",
        display_name="Proxmox VE",
        description="Proxmox Virtual Environment integration",
        version="1.0.0",
        icon="server",
        protocols=["websocket", "http"],
        config_schema={
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Proxmox host/IP"
                },
                "port": {
                    "type": "integer",
                    "description": "Proxmox API port",
                    "default": 8006
                },
                "api_token": {
                    "type": "string",
                    "description": "API token (user@realm!tokenid=secret)"
                },
                "username": {
                    "type": "string",
                    "description": "Username for password auth"
                },
                "password": {
                    "type": "string",
                    "description": "Password for password auth"
                },
                "verify_ssl": {
                    "type": "boolean",
                    "description": "Verify SSL certificate",
                    "default": False
                },
                "default_node": {
                    "type": "string",
                    "description": "Default node name"
                },
                "allowed_vmids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Allowed VM IDs (empty = all)",
                    "default": []
                },
                "allow_power": {
                    "type": "boolean",
                    "description": "Allow power operations",
                    "default": False
                }
            }
        }
    )

    def __init__(self):
        super().__init__()
        self._clients: Dict[str, ProxmoxAPI] = {}

    async def shutdown(self) -> None:
        """Close all API clients."""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()

    def _get_client(self, config: dict) -> ProxmoxAPI:
        """Get or create API client for config."""
        host = config.get("host", "")
        port = config.get("port", 8006)
        key = f"{host}:{port}"

        if key not in self._clients:
            self._clients[key] = ProxmoxAPI(
                host=host,
                port=port,
                verify_ssl=config.get("verify_ssl", False)
            )
        return self._clients[key]

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle Proxmox management WebSocket connection."""
        config = target.config
        api_token = config.get("api_token")
        allowed_vmids = config.get("allowed_vmids", [])
        allow_power = config.get("allow_power", False)

        client = self._get_client(config)

        # Authenticate if using password auth
        if not api_token:
            username = config.get("username", "root@pam")
            password = config.get("password", "")
            if not await client.authenticate(username, password):
                await ws.send_json({
                    "type": "error",
                    "message": "Failed to authenticate with Proxmox"
                })
                return

        logger.info(f"Proxmox session started for user {user_id}")

        # Send initial data
        await self._send_cluster_info(ws, client, api_token, allowed_vmids)

        # Handle commands
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_command(
                            ws, client, data, api_token,
                            allowed_vmids, allow_power, user_id
                        )
                    except json.JSONDecodeError:
                        await ws.send_json({"type": "error", "message": "Invalid JSON"})
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        finally:
            logger.info(f"Proxmox session ended for user {user_id}")

    async def _send_cluster_info(
        self,
        ws: web.WebSocketResponse,
        client: ProxmoxAPI,
        api_token: str,
        allowed_vmids: List[int]
    ) -> None:
        """Send cluster information to client."""
        nodes = await client.get_nodes(api_token)

        cluster_data = {
            "type": "cluster",
            "nodes": []
        }

        for node in nodes:
            node_name = node.get("node", "")
            node_data = {
                "name": node_name,
                "status": node.get("status", "unknown"),
                "cpu": node.get("cpu", 0),
                "mem": node.get("mem", 0),
                "maxmem": node.get("maxmem", 0),
                "vms": [],
                "containers": []
            }

            # Get VMs
            vms = await client.get_vms(node_name, api_token)
            for vm in vms:
                vmid = vm.get("vmid")
                if allowed_vmids and vmid not in allowed_vmids:
                    continue
                node_data["vms"].append({
                    "vmid": vmid,
                    "name": vm.get("name", f"VM {vmid}"),
                    "status": vm.get("status", "unknown"),
                    "cpu": vm.get("cpu", 0),
                    "mem": vm.get("mem", 0),
                    "maxmem": vm.get("maxmem", 0),
                    "uptime": vm.get("uptime", 0)
                })

            # Get containers
            containers = await client.get_containers(node_name, api_token)
            for ct in containers:
                vmid = ct.get("vmid")
                if allowed_vmids and vmid not in allowed_vmids:
                    continue
                node_data["containers"].append({
                    "vmid": vmid,
                    "name": ct.get("name", f"CT {vmid}"),
                    "status": ct.get("status", "unknown"),
                    "cpu": ct.get("cpu", 0),
                    "mem": ct.get("mem", 0),
                    "maxmem": ct.get("maxmem", 0),
                    "uptime": ct.get("uptime", 0)
                })

            cluster_data["nodes"].append(node_data)

        await ws.send_json(cluster_data)

    async def _handle_command(
        self,
        ws: web.WebSocketResponse,
        client: ProxmoxAPI,
        data: dict,
        api_token: str,
        allowed_vmids: List[int],
        allow_power: bool,
        user_id: int
    ) -> None:
        """Handle client command."""
        cmd = data.get("command")
        node = data.get("node")
        vmid = data.get("vmid")
        vm_type = data.get("type", "qemu")  # qemu or lxc

        # Check VMID access
        if vmid and allowed_vmids and vmid not in allowed_vmids:
            await ws.send_json({
                "type": "error",
                "message": f"Access denied to VM {vmid}"
            })
            return

        if cmd == "refresh":
            await self._send_cluster_info(ws, client, api_token, allowed_vmids)

        elif cmd == "status":
            if vm_type == "qemu":
                status = await client.get_vm_status(node, vmid, api_token)
            else:
                status = await client.get_container_status(node, vmid, api_token)

            await ws.send_json({
                "type": "status",
                "node": node,
                "vmid": vmid,
                "status": status
            })

        elif cmd == "vnc":
            ticket = await client.get_vnc_ticket(node, vmid, vm_type, api_token)
            if ticket:
                await ws.send_json({
                    "type": "vnc_ticket",
                    "node": node,
                    "vmid": vmid,
                    "ticket": ticket.get("ticket"),
                    "port": ticket.get("port"),
                    "upid": ticket.get("upid")
                })
            else:
                await ws.send_json({
                    "type": "error",
                    "message": "Failed to get VNC ticket"
                })

        elif cmd == "spice":
            ticket = await client.get_spice_ticket(node, vmid, vm_type, api_token)
            if ticket:
                await ws.send_json({
                    "type": "spice_ticket",
                    "node": node,
                    "vmid": vmid,
                    "ticket": ticket
                })
            else:
                await ws.send_json({
                    "type": "error",
                    "message": "Failed to get SPICE ticket"
                })

        elif cmd in ("start", "stop", "shutdown", "reset"):
            if not allow_power:
                await ws.send_json({
                    "type": "error",
                    "message": "Power operations not allowed"
                })
                return

            logger.info(f"User {user_id} executing {cmd} on {node}/{vmid}")

            success = False
            if cmd == "start":
                success = await client.start_vm(node, vmid, api_token)
            elif cmd == "stop":
                success = await client.stop_vm(node, vmid, api_token)
            elif cmd == "shutdown":
                success = await client.shutdown_vm(node, vmid, api_token)
            elif cmd == "reset":
                success = await client.reset_vm(node, vmid, api_token)

            await ws.send_json({
                "type": "power_result",
                "command": cmd,
                "node": node,
                "vmid": vmid,
                "success": success
            })

        elif cmd == "ping":
            await ws.send_json({"type": "pong"})

    async def handle_http(
        self,
        request: web.Request,
        target: ServiceTarget
    ) -> web.Response:
        """Handle HTTP API requests for Proxmox."""
        config = target.config
        api_token = config.get("api_token")
        allowed_vmids = config.get("allowed_vmids", [])

        client = self._get_client(config)

        # Authenticate if using password auth
        if not api_token:
            username = config.get("username", "root@pam")
            password = config.get("password", "")
            if not await client.authenticate(username, password):
                return web.json_response(
                    {"error": "Authentication failed"},
                    status=401
                )

        # Get cluster info
        nodes = await client.get_nodes(api_token)
        result = {"nodes": []}

        for node in nodes:
            node_name = node.get("node", "")
            node_data = {
                "name": node_name,
                "status": node.get("status", "unknown"),
                "vms": [],
                "containers": []
            }

            vms = await client.get_vms(node_name, api_token)
            for vm in vms:
                vmid = vm.get("vmid")
                if allowed_vmids and vmid not in allowed_vmids:
                    continue
                node_data["vms"].append({
                    "vmid": vmid,
                    "name": vm.get("name", f"VM {vmid}"),
                    "status": vm.get("status", "unknown")
                })

            containers = await client.get_containers(node_name, api_token)
            for ct in containers:
                vmid = ct.get("vmid")
                if allowed_vmids and vmid not in allowed_vmids:
                    continue
                node_data["containers"].append({
                    "vmid": vmid,
                    "name": ct.get("name", f"CT {vmid}"),
                    "status": ct.get("status", "unknown")
                })

            result["nodes"].append(node_data)

        return web.json_response(result)

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check Proxmox connectivity."""
        config = target.config
        host = config.get("host", "")
        port = config.get("port", 8006)

        try:
            # Just check TCP connectivity
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()

            return {
                "healthy": True,
                "message": f"Proxmox API reachable: {host}:{port}"
            }
        except Exception as e:
            return {
                "healthy": False,
                "message": f"Cannot reach {host}:{port}: {e}"
            }

    def get_client_assets(self) -> dict:
        return {
            "js": [],
            "css": [],
            "html": "proxmox.html"
        }
