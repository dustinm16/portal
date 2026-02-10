"""System monitoring module for Open Relay Portal.

Provides process management, systemd service management, and network info.
All operations are admin-only (enforced by API handlers in server.py).
"""

import os
import subprocess
import logging
from datetime import datetime, timezone

import psutil

logger = logging.getLogger("portal")

# Safety: refuse to kill these
_PORTAL_PID = os.getpid()
_MIN_SAFE_PID = 2  # Never kill PID 1 (init) or kernel threads


def list_processes(sort_by: str = "cpu", limit: int = 100) -> list[dict]:
    """List running processes sorted by the given field.

    Args:
        sort_by: One of 'cpu', 'memory', 'pid', 'name'
        limit: Max number of processes to return
    """
    attrs = ["pid", "name", "username", "cpu_percent", "memory_percent",
             "memory_info", "status", "cmdline", "create_time"]
    procs = []
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        info = p.info
        procs.append({
            "pid": info["pid"],
            "name": info["name"] or "",
            "username": info["username"] or "",
            "cpu_percent": info["cpu_percent"] or 0.0,
            "memory_percent": round(info["memory_percent"] or 0.0, 1),
            "memory_rss": info["memory_info"].rss if info["memory_info"] else 0,
            "status": info["status"] or "",
            "cmdline": " ".join(info["cmdline"]) if info["cmdline"] else "",
            "create_time": info["create_time"] or 0,
        })

    sort_keys = {
        "cpu": lambda p: p["cpu_percent"],
        "memory": lambda p: p["memory_percent"],
        "pid": lambda p: p["pid"],
        "name": lambda p: p["name"].lower(),
    }
    key_fn = sort_keys.get(sort_by, sort_keys["cpu"])
    reverse = sort_by in ("cpu", "memory")
    procs.sort(key=key_fn, reverse=reverse)
    return procs[:limit]


def get_process_info(pid: int) -> dict | None:
    """Get detailed info for a single process."""
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            mem = p.memory_info()
            return {
                "pid": p.pid,
                "name": p.name(),
                "username": p.username(),
                "cpu_percent": p.cpu_percent(),
                "memory_percent": round(p.memory_percent(), 1),
                "memory_rss": mem.rss,
                "memory_vms": mem.vms,
                "status": p.status(),
                "cmdline": " ".join(p.cmdline()),
                "create_time": p.create_time(),
                "num_threads": p.num_threads(),
                "nice": p.nice(),
                "cwd": p.cwd() if p.pid != 0 else "",
                "exe": p.exe() or "",
                "ppid": p.ppid(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def kill_process(pid: int, signal_name: str = "SIGTERM") -> tuple[bool, str]:
    """Kill a process by PID.

    Returns (success, message).
    """
    if pid < _MIN_SAFE_PID:
        return False, "Cannot kill system processes (PID < 2)"

    if pid == _PORTAL_PID:
        return False, "Cannot kill the portal process itself"

    import signal as sig
    signal_map = {
        "SIGTERM": sig.SIGTERM,
        "SIGKILL": sig.SIGKILL,
        "SIGINT": sig.SIGINT,
        "SIGHUP": sig.SIGHUP,
    }
    sig_val = signal_map.get(signal_name.upper())
    if not sig_val:
        return False, f"Unknown signal: {signal_name}"

    try:
        p = psutil.Process(pid)
        name = p.name()
        p.send_signal(sig_val)
        logger.info(f"Sent {signal_name} to process {pid} ({name})")
        return True, f"Sent {signal_name} to {name} (PID {pid})"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} not found"
    except psutil.AccessDenied:
        return False, f"Access denied killing process {pid}"


# =============================================================================
# Systemd Service Management
# =============================================================================

_ALLOWED_ACTIONS = {"start", "stop", "restart", "enable", "disable"}


def list_services(filter_str: str | None = None) -> list[dict]:
    """List systemd services.

    Args:
        filter_str: Optional filter - 'running', 'failed', 'enabled', or search string
    """
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager",
             "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=10
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    services = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        load_state = parts[1]
        active_state = parts[2]
        sub_state = parts[3]
        description = parts[4] if len(parts) > 4 else ""

        # Clean unit name
        if not unit.endswith(".service"):
            continue
        name = unit.removesuffix(".service")

        svc = {
            "name": name,
            "unit": unit,
            "load_state": load_state,
            "active_state": active_state,
            "sub_state": sub_state,
            "description": description,
        }

        # Apply filter
        if filter_str:
            f = filter_str.lower()
            if f == "running" and sub_state != "running":
                continue
            elif f == "failed" and active_state != "failed":
                continue
            elif f == "enabled" and load_state != "loaded":
                continue
            elif f not in ("running", "failed", "enabled"):
                # Text search
                if f not in name.lower() and f not in description.lower():
                    continue

        services.append(svc)

    return services


def get_service_status(name: str) -> dict | None:
    """Get detailed status for a systemd service."""
    # Validate service name (alphanumeric, hyphens, underscores, @)
    if not _validate_service_name(name):
        return None

    try:
        result = subprocess.run(
            ["systemctl", "show", f"{name}.service",
             "--property=ActiveState,SubState,LoadState,Description,MainPID,"
             "ExecMainStartTimestamp,MemoryCurrent,TasksCurrent,Restart,"
             "FragmentPath,UnitFileState"],
            capture_output=True, text=True, timeout=10
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if result.returncode != 0:
        return None

    props = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            props[key.strip()] = val.strip()

    if not props.get("LoadState") or props["LoadState"] == "not-found":
        return None

    return {
        "name": name,
        "active_state": props.get("ActiveState", ""),
        "sub_state": props.get("SubState", ""),
        "load_state": props.get("LoadState", ""),
        "description": props.get("Description", ""),
        "main_pid": int(props.get("MainPID", "0")),
        "started_at": props.get("ExecMainStartTimestamp", ""),
        "memory": props.get("MemoryCurrent", ""),
        "tasks": props.get("TasksCurrent", ""),
        "restart_policy": props.get("Restart", ""),
        "unit_file": props.get("FragmentPath", ""),
        "enabled": props.get("UnitFileState", "") == "enabled",
    }


def get_service_logs(name: str, lines: int = 50) -> str:
    """Get journal logs for a systemd service."""
    if not _validate_service_name(name):
        return "Invalid service name"

    lines = min(max(lines, 10), 500)  # Clamp 10-500

    try:
        result = subprocess.run(
            ["journalctl", "-u", f"{name}.service", "-n", str(lines),
             "--no-pager", "--output=short-iso"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout or "No logs available"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "Failed to retrieve logs"


def control_service(name: str, action: str) -> tuple[bool, str]:
    """Control a systemd service (start/stop/restart/enable/disable).

    Returns (success, message).
    """
    if not _validate_service_name(name):
        return False, "Invalid service name"

    if action not in _ALLOWED_ACTIONS:
        return False, f"Invalid action: {action}. Allowed: {', '.join(_ALLOWED_ACTIONS)}"

    try:
        result = subprocess.run(
            ["sudo", "systemctl", action, f"{name}.service"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            logger.info(f"Service {name}: {action} successful")
            return True, f"Service {name} {action} successful"
        else:
            err = result.stderr.strip() or f"Exit code {result.returncode}"
            return False, f"Failed to {action} {name}: {err}"
    except subprocess.TimeoutExpired:
        return False, f"Timed out trying to {action} {name}"
    except FileNotFoundError:
        return False, "systemctl not found"


def _validate_service_name(name: str) -> bool:
    """Validate a systemd service name to prevent injection."""
    import re
    return bool(re.match(r'^[a-zA-Z0-9_@\-\.]+$', name)) and len(name) < 256


# =============================================================================
# Network Information
# =============================================================================

def get_network_interfaces() -> list[dict]:
    """Get network interface information."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)

    interfaces = []
    for name, addr_list in addrs.items():
        iface = {
            "name": name,
            "addresses": [],
            "mac": "",
            "is_up": False,
            "speed": 0,
            "mtu": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
        }

        for addr in addr_list:
            if addr.family.name == "AF_INET":
                iface["addresses"].append({
                    "type": "ipv4",
                    "address": addr.address,
                    "netmask": addr.netmask,
                })
            elif addr.family.name == "AF_INET6":
                iface["addresses"].append({
                    "type": "ipv6",
                    "address": addr.address,
                })
            elif addr.family.name == "AF_PACKET":
                iface["mac"] = addr.address

        if name in stats:
            s = stats[name]
            iface["is_up"] = s.isup
            iface["speed"] = s.speed
            iface["mtu"] = s.mtu

        if name in io:
            c = io[name]
            iface["bytes_sent"] = c.bytes_sent
            iface["bytes_recv"] = c.bytes_recv

        interfaces.append(iface)

    return interfaces


def get_listening_ports() -> list[dict]:
    """Get listening TCP/UDP ports with process info."""
    ports = []
    seen = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "LISTEN":
            continue

        addr = conn.laddr
        key = (conn.type.name, addr.ip, addr.port)
        if key in seen:
            continue
        seen.add(key)

        proc_name = ""
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        ports.append({
            "proto": "tcp" if conn.type.name == "SOCK_STREAM" else "udp",
            "address": addr.ip,
            "port": addr.port,
            "pid": conn.pid or 0,
            "process": proc_name,
        })

    ports.sort(key=lambda p: p["port"])
    return ports
