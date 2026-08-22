"""System resource (CPU/memory/network) time series tracking for Open Relay Portal.

Mirrors the traffic_metrics.py pattern: an in-memory ring of per-minute
samples, retained for 24 hours, recorded by a background task. This is
distinct from traffic_metrics (which tracks Portal-relayed connection
traffic) — this tracks the host's own resource utilization, the thing
people actually want to see when using Portal as a VPS/homelab dashboard.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

import psutil

logger = logging.getLogger("portal.metrics")


@dataclass
class ResourcePoint:
    """A single point-in-time resource sample."""
    timestamp: datetime
    cpu_percent: float
    mem_percent: float
    mem_used: int
    disk_percent: float
    net_bytes_sent: int
    net_bytes_recv: int


class ResourceMetrics:
    """Tracks host CPU/memory/disk/network utilization over time."""

    def __init__(self):
        self._points: list[ResourcePoint] = []
        self._lock = asyncio.Lock()
        # Non-blocking cpu_percent() needs one primed call before it reports
        # anything meaningful; do it once at startup so the first real sample
        # (60s later) already has a baseline to compare against.
        psutil.cpu_percent(interval=None)

    async def record_point(self):
        """Sample current resource usage and append it to the time series."""
        async with self._lock:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net = psutil.net_io_counters()
            except Exception as e:
                logger.error(f"Failed to sample resource metrics: {e}")
                return

            point = ResourcePoint(
                timestamp=datetime.now(timezone.utc),
                cpu_percent=cpu,
                mem_percent=mem.percent,
                mem_used=mem.used,
                disk_percent=disk.percent,
                net_bytes_sent=net.bytes_sent,
                net_bytes_recv=net.bytes_recv,
            )
            self._points.append(point)

            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            self._points = [p for p in self._points if p.timestamp > cutoff]

    def get_time_series(self, hours: int = 1) -> list[dict]:
        """Get resource time series for the last N hours.

        Network fields are per-interval deltas (not cumulative totals),
        matching the convention used by traffic_metrics.get_time_series().
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        points = [p for p in self._points if p.timestamp > cutoff]
        result = []
        prev_sent: Optional[int] = None
        prev_recv: Optional[int] = None
        for p in points:
            delta_sent = max(0, p.net_bytes_sent - prev_sent) if prev_sent is not None else 0
            delta_recv = max(0, p.net_bytes_recv - prev_recv) if prev_recv is not None else 0
            prev_sent = p.net_bytes_sent
            prev_recv = p.net_bytes_recv
            result.append({
                "timestamp": p.timestamp.isoformat(),
                "cpu_percent": round(p.cpu_percent, 1),
                "mem_percent": round(p.mem_percent, 1),
                "mem_used": p.mem_used,
                "disk_percent": round(p.disk_percent, 1),
                "net_bytes_sent": delta_sent,
                "net_bytes_recv": delta_recv,
            })
        return result


# Global resource metrics instance
resource_metrics = ResourceMetrics()


_recorder_task: Optional[asyncio.Task] = None


async def _resource_recorder_task():
    """Background task to record a resource sample every minute."""
    while True:
        try:
            await resource_metrics.record_point()
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error recording resource metrics: {e}")
            await asyncio.sleep(60)


async def start_resource_metrics_recorder():
    """Start the background resource metrics recorder."""
    global _recorder_task
    if _recorder_task is None:
        _recorder_task = asyncio.create_task(_resource_recorder_task())
        logger.info("Resource metrics recorder started")


async def stop_resource_metrics_recorder():
    """Stop the background resource metrics recorder."""
    global _recorder_task
    if _recorder_task:
        _recorder_task.cancel()
        try:
            await _recorder_task
        except asyncio.CancelledError:
            pass
        _recorder_task = None
        logger.info("Resource metrics recorder stopped")
