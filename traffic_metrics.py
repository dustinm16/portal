"""Traffic Metrics Tracking for Open Relay Portal."""

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
import json

logger = logging.getLogger("portal.metrics")


@dataclass
class ConnectionMetrics:
    """Metrics for a single connection."""
    service_id: int
    user_id: int
    plugin: str
    connected_at: datetime
    disconnected_at: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        """Get connection duration in seconds."""
        end_time = self.disconnected_at or datetime.now(timezone.utc)
        return (end_time - self.connected_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "service_id": self.service_id,
            "user_id": self.user_id,
            "plugin": self.plugin,
            "connected_at": self.connected_at.isoformat(),
            "disconnected_at": self.disconnected_at.isoformat() if self.disconnected_at else None,
            "duration_seconds": self.duration_seconds,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "client_ip": self.client_ip
        }


@dataclass
class ServiceMetrics:
    """Aggregated metrics for a service."""
    service_id: int
    total_connections: int = 0
    active_connections: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_duration_seconds: float = 0
    unique_users: set = field(default_factory=set)
    peak_concurrent: int = 0
    last_connection: Optional[datetime] = None
    errors: int = 0

    def to_dict(self) -> dict:
        return {
            "service_id": self.service_id,
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "total_bytes": self.total_bytes_sent + self.total_bytes_received,
            "avg_duration_seconds": self.total_duration_seconds / max(self.total_connections, 1),
            "unique_users": len(self.unique_users),
            "peak_concurrent": self.peak_concurrent,
            "last_connection": self.last_connection.isoformat() if self.last_connection else None,
            "errors": self.errors
        }


@dataclass
class TimeSeriesPoint:
    """A single point in time series data."""
    timestamp: datetime
    connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    active_users: int = 0


class TrafficMetrics:
    """Traffic metrics tracker for Open Relay Portal."""

    def __init__(self):
        # Active connections by connection ID
        self._active: dict[str, ConnectionMetrics] = {}

        # Service-level aggregated metrics
        self._service_metrics: dict[int, ServiceMetrics] = defaultdict(
            lambda: ServiceMetrics(service_id=0)
        )

        # Time series data (per minute, last 24 hours)
        self._time_series: list[TimeSeriesPoint] = []
        self._time_series_lock = asyncio.Lock()

        # Global counters
        self._total_connections = 0
        self._total_bytes_sent = 0
        self._total_bytes_received = 0
        self._total_errors = 0

        # User activity tracking
        self._user_activity: dict[int, datetime] = {}

        # IP-based tracking for security
        self._ip_connections: dict[str, list[datetime]] = defaultdict(list)

        # Start time
        self._started_at = datetime.now(timezone.utc)

    def start_connection(
        self,
        connection_id: str,
        service_id: int,
        user_id: int,
        plugin: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ConnectionMetrics:
        """Record a new connection."""
        metrics = ConnectionMetrics(
            service_id=service_id,
            user_id=user_id,
            plugin=plugin,
            connected_at=datetime.now(timezone.utc),
            client_ip=client_ip,
            user_agent=user_agent
        )

        self._active[connection_id] = metrics
        self._total_connections += 1

        # Update service metrics
        svc = self._service_metrics[service_id]
        svc.service_id = service_id
        svc.total_connections += 1
        svc.active_connections += 1
        svc.unique_users.add(user_id)
        svc.last_connection = metrics.connected_at
        svc.peak_concurrent = max(svc.peak_concurrent, svc.active_connections)

        # Track user activity
        self._user_activity[user_id] = datetime.now(timezone.utc)

        # Track IP connections (for rate limiting detection)
        if client_ip:
            self._ip_connections[client_ip].append(datetime.now(timezone.utc))
            # Keep only last hour
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            self._ip_connections[client_ip] = [
                t for t in self._ip_connections[client_ip] if t > cutoff
            ]

        logger.debug(f"Connection started: {connection_id} (service={service_id}, user={user_id})")
        return metrics

    def end_connection(self, connection_id: str) -> Optional[ConnectionMetrics]:
        """Record connection end."""
        if connection_id not in self._active:
            return None

        metrics = self._active.pop(connection_id)
        metrics.disconnected_at = datetime.now(timezone.utc)

        # Update service metrics
        svc = self._service_metrics[metrics.service_id]
        svc.active_connections = max(0, svc.active_connections - 1)
        svc.total_bytes_sent += metrics.bytes_sent
        svc.total_bytes_received += metrics.bytes_received
        svc.total_duration_seconds += metrics.duration_seconds

        # Update global counters
        self._total_bytes_sent += metrics.bytes_sent
        self._total_bytes_received += metrics.bytes_received

        logger.debug(f"Connection ended: {connection_id} (duration={metrics.duration_seconds:.1f}s)")
        return metrics

    def record_traffic(self, connection_id: str, bytes_sent: int = 0, bytes_received: int = 0):
        """Record traffic for a connection."""
        if connection_id in self._active:
            metrics = self._active[connection_id]
            metrics.bytes_sent += bytes_sent
            metrics.bytes_received += bytes_received
            if bytes_sent > 0:
                metrics.messages_sent += 1
            if bytes_received > 0:
                metrics.messages_received += 1

    def update_service_id(self, connection_id: str, service_id: int):
        """Update the service_id for an active connection (deferred resolution)."""
        if connection_id not in self._active:
            return
        metrics = self._active[connection_id]
        old_id = metrics.service_id
        if old_id == service_id:
            return
        metrics.service_id = service_id
        # Move counters from old service to new service
        old_svc = self._service_metrics[old_id]
        old_svc.active_connections = max(0, old_svc.active_connections - 1)
        old_svc.total_connections = max(0, old_svc.total_connections - 1)
        old_svc.unique_users.discard(metrics.user_id)
        new_svc = self._service_metrics[service_id]
        new_svc.service_id = service_id
        new_svc.active_connections += 1
        new_svc.total_connections += 1
        new_svc.unique_users.add(metrics.user_id)
        new_svc.last_connection = metrics.connected_at
        new_svc.peak_concurrent = max(new_svc.peak_concurrent, new_svc.active_connections)

    def record_error(self, service_id: int):
        """Record an error for a service."""
        self._total_errors += 1
        self._service_metrics[service_id].errors += 1

    def get_active_connections(self) -> list[dict]:
        """Get list of active connections."""
        return [m.to_dict() for m in self._active.values()]

    def get_service_metrics(self, service_id: int) -> dict:
        """Get metrics for a specific service."""
        return self._service_metrics[service_id].to_dict()

    def get_all_service_metrics(self) -> list[dict]:
        """Get metrics for all services."""
        return [m.to_dict() for m in self._service_metrics.values()]

    def get_summary(self) -> dict:
        """Get overall traffic summary."""
        now = datetime.now(timezone.utc)
        uptime = (now - self._started_at).total_seconds()

        # Count active users (activity in last 5 minutes)
        active_cutoff = now - timedelta(minutes=5)
        active_users = sum(1 for t in self._user_activity.values() if t > active_cutoff)

        # Calculate rates
        hours = max(uptime / 3600, 1)
        conn_per_hour = self._total_connections / hours
        bytes_per_hour = (self._total_bytes_sent + self._total_bytes_received) / hours

        return {
            "uptime_seconds": uptime,
            "total_connections": self._total_connections,
            "active_connections": len(self._active),
            "total_bytes_sent": self._total_bytes_sent,
            "total_bytes_received": self._total_bytes_received,
            "total_bytes": self._total_bytes_sent + self._total_bytes_received,
            "total_errors": self._total_errors,
            "unique_users_today": len(self._user_activity),
            "active_users": active_users,
            "connections_per_hour": round(conn_per_hour, 2),
            "bandwidth_per_hour": round(bytes_per_hour),
            "services_active": sum(1 for m in self._service_metrics.values() if m.active_connections > 0),
            "started_at": self._started_at.isoformat()
        }

    def get_user_activity(self, user_id: int) -> dict:
        """Get activity metrics for a specific user."""
        user_connections = [m for m in self._active.values() if m.user_id == user_id]
        return {
            "user_id": user_id,
            "active_connections": len(user_connections),
            "last_activity": self._user_activity.get(user_id, None),
            "connections": [m.to_dict() for m in user_connections]
        }

    def get_ip_activity(self, ip: str) -> dict:
        """Get connection activity for an IP address."""
        connections = self._ip_connections.get(ip, [])
        now = datetime.now(timezone.utc)

        # Calculate connection rates
        last_hour = sum(1 for t in connections if (now - t).total_seconds() < 3600)
        last_minute = sum(1 for t in connections if (now - t).total_seconds() < 60)

        return {
            "ip": ip,
            "connections_last_hour": last_hour,
            "connections_last_minute": last_minute,
            "rate_limited": last_minute > 30,  # More than 30 connections/minute
            "active_connections": sum(1 for m in self._active.values() if m.client_ip == ip)
        }

    def get_top_services(self, limit: int = 10) -> list[dict]:
        """Get top services by connection count."""
        services = sorted(
            self._service_metrics.values(),
            key=lambda s: s.total_connections,
            reverse=True
        )[:limit]
        return [s.to_dict() for s in services]

    def get_top_users(self, limit: int = 10) -> list[dict]:
        """Get top users by activity."""
        # Count connections per user across all services
        user_counts: dict[int, int] = defaultdict(int)
        for svc in self._service_metrics.values():
            for user_id in svc.unique_users:
                user_counts[user_id] += 1

        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"user_id": uid, "service_count": count} for uid, count in sorted_users]

    async def record_time_series_point(self):
        """Record a point in the time series (call periodically)."""
        async with self._time_series_lock:
            point = TimeSeriesPoint(
                timestamp=datetime.now(timezone.utc),
                connections=len(self._active),
                bytes_sent=self._total_bytes_sent,
                bytes_received=self._total_bytes_received,
                active_users=len([
                    u for u, t in self._user_activity.items()
                    if (datetime.now(timezone.utc) - t).total_seconds() < 300
                ])
            )
            self._time_series.append(point)

            # Keep only last 24 hours (1440 minutes)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            self._time_series = [p for p in self._time_series if p.timestamp > cutoff]

    def get_time_series(self, hours: int = 1) -> list[dict]:
        """Get time series data for the last N hours.

        Returns per-interval bandwidth deltas (not cumulative totals).
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        points = [p for p in self._time_series if p.timestamp > cutoff]
        result = []
        prev_sent = 0
        prev_recv = 0
        for p in points:
            delta_sent = max(0, p.bytes_sent - prev_sent) if prev_sent else 0
            delta_recv = max(0, p.bytes_received - prev_recv) if prev_recv else 0
            prev_sent = p.bytes_sent
            prev_recv = p.bytes_received
            result.append({
                "timestamp": p.timestamp.isoformat(),
                "connections": p.connections,
                "active_users": p.active_users,
                "bytes_sent": delta_sent,
                "bytes_received": delta_recv,
            })
        return result


# Global traffic metrics instance
traffic_metrics = TrafficMetrics()


# Background task for time series recording
async def metrics_recorder_task():
    """Background task to record time series data every minute."""
    while True:
        try:
            await traffic_metrics.record_time_series_point()
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error recording metrics: {e}")
            await asyncio.sleep(60)


_recorder_task: Optional[asyncio.Task] = None


async def start_metrics_recorder():
    """Start the background metrics recorder."""
    global _recorder_task
    if _recorder_task is None:
        _recorder_task = asyncio.create_task(metrics_recorder_task())
        logger.info("Metrics recorder started")


async def stop_metrics_recorder():
    """Stop the background metrics recorder."""
    global _recorder_task
    if _recorder_task:
        _recorder_task.cancel()
        try:
            await _recorder_task
        except asyncio.CancelledError:
            pass
        _recorder_task = None
        logger.info("Metrics recorder stopped")
