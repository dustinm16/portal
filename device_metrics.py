"""Device-wide metrics sampling for Open Relay Portal.

`traffic_metrics` tracks Portal-relayed connection traffic; `resource_metrics`
tracks the host's aggregate CPU/mem/disk/net. This module fills the gap: a
periodic sample of the *whole box*, persisted to SQLite so it survives
restarts and covers days rather than the last 24h in RAM.

Three categories, one sample row each per tick:

- **process** — resource usage grouped by systemd unit (from the pid's
  cgroup) or, for unmanaged processes, by process name.
- **port** — every listening TCP/UDP socket, its owning process/unit, and how
  many established connections currently sit on that local port.
- **ip** — remote IPs with at least one active connection to the host, the
  local ports they're hitting, and the processes serving them.

Everything here is **sampled** (default every 60s), not a packet or
connection log — a connection that opens and closes between ticks is not
seen. The whole sample body runs off the event loop via
``asyncio.to_thread`` because ``psutil.net_connections()`` and
``process_iter()`` are full ``/proc`` walks that take tens to hundreds of ms
on a busy host.
"""

import asyncio
import json
import logging
import re
import socket
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import psutil

logger = logging.getLogger("portal.metrics")

SAMPLE_INTERVAL = 60          # seconds between samples
MAX_PROCESS_GROUPS = 40       # keep the busiest N process/service groups per tick
MAX_PORTS = 250              # listening ports kept per tick (there are rarely many)
MAX_IPS = 120                # remote IPs kept per tick — bounds a port-scan blast
MAX_PORTS_PER_IP = 12
MAX_PROCS_PER_IP = 6

_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "::"}
# cgroup v2 line looks like "0::/system.slice/system-foo.slice/bar@baz.service"
_SERVICE_RE = re.compile(r"/([A-Za-z0-9_.@\\:-]+\.service)(?:/|$)")


def _unit_for_pid(pid: Optional[int], cache: dict) -> Optional[str]:
    """systemd unit owning `pid` (from cgroup v2), or None. Cached per sample."""
    if not pid:
        return None
    if pid in cache:
        return cache[pid]
    unit = None
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            data = f.read()
        matches = _SERVICE_RE.findall(data)
        if matches:
            # innermost .service is the most specific owner
            unit = matches[-1].replace("\\x2d", "-")
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        pass
    cache[pid] = unit
    return unit


def _pid_name(pid: Optional[int], cache: dict) -> str:
    if not pid:
        return ""
    if pid in cache:
        return cache[pid]
    name = ""
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        pass
    cache[pid] = name
    return name


class DeviceMetrics:
    """Collects and persists whole-device metric samples."""

    def _collect(self) -> dict:
        """Synchronous — MUST run under asyncio.to_thread."""
        unit_cache: dict = {}
        name_cache: dict = {}

        # ---- connections: listening ports + remote IPs -------------------
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as e:
            logger.warning(f"net_connections unavailable: {e}")
            conns = []

        listening: dict = {}
        established_by_port: dict = defaultdict(int)
        ip_agg: dict = defaultdict(
            lambda: {"conns": 0, "ports": set(), "procs": set(), "states": defaultdict(int)}
        )

        for c in conns:
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            if c.status == psutil.CONN_LISTEN:
                if not c.laddr:
                    continue
                key = (proto, c.laddr.ip, c.laddr.port)
                listening[key] = {
                    "proto": proto,
                    "addr": c.laddr.ip,
                    "port": c.laddr.port,
                    "pid": c.pid or 0,
                    "process": _pid_name(c.pid, name_cache),
                    "unit": _unit_for_pid(c.pid, unit_cache),
                }
                continue

            if c.laddr:
                established_by_port[c.laddr.port] += 1
            raddr = c.raddr
            if raddr and raddr.ip and raddr.ip not in _LOOPBACK:
                e = ip_agg[raddr.ip]
                e["conns"] += 1
                if c.laddr:
                    e["ports"].add(c.laddr.port)
                e["states"][c.status or "?"] += 1
                pn = _pid_name(c.pid, name_cache)
                if pn:
                    e["procs"].add(pn)

        port_entries = []
        for v in listening.values():
            v = dict(v)
            v["established"] = established_by_port.get(v["port"], 0)
            port_entries.append(v)
        port_entries.sort(key=lambda x: (-x["established"], x["port"]))
        port_trunc = max(0, len(port_entries) - MAX_PORTS)

        ip_entries = []
        for ip, v in ip_agg.items():
            ip_entries.append({
                "ip": ip,
                "conns": v["conns"],
                "ports": sorted(v["ports"])[:MAX_PORTS_PER_IP],
                "processes": sorted(v["procs"])[:MAX_PROCS_PER_IP],
                "states": dict(v["states"]),
            })
        ip_entries.sort(key=lambda x: -x["conns"])
        ip_trunc = max(0, len(ip_entries) - MAX_IPS)

        # ---- processes grouped by unit / name ---------------------------
        # process_iter() reuses Process objects across calls, so cpu_percent()
        # here is "% over the interval since the previous sample". A process
        # seen for the first time reads 0.0 (one tick of warm-up).
        groups: dict = {}
        for p in psutil.process_iter(["pid", "name", "memory_info", "memory_percent"]):
            try:
                info = p.info
                pid = info["pid"]
                if not pid:
                    continue
                try:
                    cpu = p.cpu_percent(None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu = 0.0
                unit = _unit_for_pid(pid, unit_cache)
                if unit:
                    gkey, glabel, kind = unit, unit[:-8], "service"
                else:
                    nm = info["name"] or "?"
                    gkey, glabel, kind = f"proc:{nm}", nm, "process"
                g = groups.get(gkey)
                if g is None:
                    g = groups[gkey] = {
                        "key": gkey, "label": glabel, "kind": kind,
                        "cpu_percent": 0.0, "mem_rss": 0, "mem_percent": 0.0, "count": 0,
                    }
                g["cpu_percent"] += cpu
                mi = info["memory_info"]
                g["mem_rss"] += mi.rss if mi else 0
                g["mem_percent"] += info["memory_percent"] or 0.0
                g["count"] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Drop groups using no measurable CPU and no measurable memory — kernel
        # threads and transient helpers that only pad the truncation count.
        proc_entries = [
            g for g in groups.values()
            if g["cpu_percent"] > 0 or g["mem_rss"] > 0
        ]
        for g in proc_entries:
            g["cpu_percent"] = round(g["cpu_percent"], 1)
            g["mem_percent"] = round(g["mem_percent"], 1)
        proc_entries.sort(key=lambda x: (-x["cpu_percent"], -x["mem_rss"]))
        proc_trunc = max(0, len(proc_entries) - MAX_PROCESS_GROUPS)

        return {
            "process": {
                "entries": proc_entries[:MAX_PROCESS_GROUPS],
                "truncated": proc_trunc,
                "ncpu": psutil.cpu_count() or 1,
            },
            "port": {"entries": port_entries[:MAX_PORTS], "truncated": port_trunc},
            "ip": {"entries": ip_entries[:MAX_IPS], "truncated": ip_trunc},
        }

    async def record_sample(self, db) -> None:
        """Take one sample and persist a row per category."""
        try:
            sample = await asyncio.to_thread(self._collect)
        except Exception as e:
            logger.error(f"Device metrics sample failed: {e}")
            return

        ts = datetime.now(timezone.utc).isoformat()
        for category, payload in sample.items():
            try:
                await db.add_device_metric_sample(category, json.dumps(payload), ts)
            except Exception as e:
                logger.error(f"Device metrics persist failed ({category}): {e}")


device_metrics = DeviceMetrics()


# ---------------------------------------------------------------------------
# Read-side shaping — turn stored sample rows into chart-ready payloads.
# ---------------------------------------------------------------------------

def _bucket_index(ts_list: list, n_buckets: int):
    """Map each timestamp to a bucket 0..n_buckets-1 spread over the window."""
    if not ts_list:
        return []
    lo, hi = ts_list[0], ts_list[-1]
    span = (hi - lo).total_seconds() or 1.0
    return [min(n_buckets - 1, int((t - lo).total_seconds() / span * n_buckets)) for t in ts_list]


def summarize_process_samples(rows: list, top_n: int = 12, target_points: int = 240) -> dict:
    parsed = []
    for r in rows:
        try:
            p = json.loads(r["entries_json"])
            parsed.append((datetime.fromisoformat(r["ts"]), p))
        except (ValueError, KeyError):
            continue
    if not parsed:
        return {"series": [], "current": [], "ncpu": psutil.cpu_count() or 1, "truncated": 0}

    # rank groups by peak CPU across the window (memory as tiebreak)
    peak = {}
    labels = {}
    kinds = {}
    for _, p in parsed:
        for e in p.get("entries", []):
            k = e["key"]
            score = (e.get("cpu_percent", 0), e.get("mem_rss", 0))
            if k not in peak or score > peak[k]:
                peak[k] = score
            labels[k] = e.get("label", k)
            kinds[k] = e.get("kind", "process")
    top = [k for k, _ in sorted(peak.items(), key=lambda kv: kv[1], reverse=True)[:top_n]]

    n_buckets = min(target_points, len(parsed))
    idx = _bucket_index([t for t, _ in parsed], n_buckets)
    # accumulate per-bucket sums + counts per group
    acc = {k: [dict(cpu=0.0, mem=0, memp=0.0, n=0) for _ in range(n_buckets)] for k in top}
    bucket_ts = [None] * n_buckets
    for (t, p), b in zip(parsed, idx):
        bucket_ts[b] = t
        emap = {e["key"]: e for e in p.get("entries", [])}
        for k in top:
            e = emap.get(k)
            cell = acc[k][b]
            cell["n"] += 1
            if e:
                cell["cpu"] += e.get("cpu_percent", 0.0)
                cell["mem"] += e.get("mem_rss", 0)
                cell["memp"] += e.get("mem_percent", 0.0)

    series = []
    for k in top:
        pts = []
        for b in range(n_buckets):
            if bucket_ts[b] is None:
                continue
            cell = acc[k][b]
            n = max(cell["n"], 1)
            pts.append({
                "t": bucket_ts[b].isoformat(),
                "cpu": round(cell["cpu"] / n, 1),
                "mem_rss": int(cell["mem"] / n),
                "mem_percent": round(cell["memp"] / n, 1),
            })
        series.append({"key": k, "label": labels[k], "kind": kinds[k], "points": pts})

    latest = parsed[-1][1]
    return {
        "series": series,
        "current": latest.get("entries", []),
        "ncpu": latest.get("ncpu", psutil.cpu_count() or 1),
        "truncated": latest.get("truncated", 0),
        "sample_count": len(parsed),
    }


def summarize_port_samples(rows: list, top_n: int = 15, target_points: int = 240) -> dict:
    parsed = []
    for r in rows:
        try:
            p = json.loads(r["entries_json"])
            parsed.append((datetime.fromisoformat(r["ts"]), p))
        except (ValueError, KeyError):
            continue
    if not parsed:
        return {"series": [], "current": [], "truncated": 0}

    peak = {}
    meta = {}
    for _, p in parsed:
        for e in p.get("entries", []):
            k = f"{e['proto']}/{e['port']}"
            peak[k] = max(peak.get(k, 0), e.get("established", 0))
            meta[k] = {"proto": e["proto"], "port": e["port"],
                       "process": e.get("process", ""), "unit": e.get("unit")}
    top = [k for k, _ in sorted(peak.items(), key=lambda kv: kv[1], reverse=True)[:top_n]]

    n_buckets = min(target_points, len(parsed))
    idx = _bucket_index([t for t, _ in parsed], n_buckets)
    acc = {k: [dict(v=0, n=0) for _ in range(n_buckets)] for k in top}
    bucket_ts = [None] * n_buckets
    for (t, p), b in zip(parsed, idx):
        bucket_ts[b] = t
        emap = {f"{e['proto']}/{e['port']}": e for e in p.get("entries", [])}
        for k in top:
            cell = acc[k][b]
            cell["n"] += 1
            e = emap.get(k)
            if e:
                cell["v"] += e.get("established", 0)

    series = []
    for k in top:
        pts = []
        for b in range(n_buckets):
            if bucket_ts[b] is None:
                continue
            cell = acc[k][b]
            pts.append({"t": bucket_ts[b].isoformat(),
                        "established": round(cell["v"] / max(cell["n"], 1), 1)})
        series.append({"key": k, **meta[k], "points": pts})

    latest = parsed[-1][1]
    return {
        "series": series,
        "current": latest.get("entries", []),
        "truncated": latest.get("truncated", 0),
        "sample_count": len(parsed),
    }


def summarize_ip_samples(rows: list, top_n: int = 100, target_points: int = 240) -> dict:
    parsed = []
    for r in rows:
        try:
            p = json.loads(r["entries_json"])
            parsed.append((datetime.fromisoformat(r["ts"]), p))
        except (ValueError, KeyError):
            continue
    if not parsed:
        return {"ips": [], "timeline": [], "current": [], "truncated": 0}

    agg = {}
    for t, p in parsed:
        for e in p.get("entries", []):
            ip = e["ip"]
            a = agg.get(ip)
            if a is None:
                a = agg[ip] = {"ip": ip, "max_conns": 0, "samples": 0,
                               "first_seen": t, "last_seen": t,
                               "ports": set(), "processes": set()}
            a["max_conns"] = max(a["max_conns"], e.get("conns", 0))
            a["samples"] += 1
            a["first_seen"] = min(a["first_seen"], t)
            a["last_seen"] = max(a["last_seen"], t)
            a["ports"].update(e.get("ports", []))
            a["processes"].update(e.get("processes", []))

    ips = sorted(agg.values(), key=lambda a: (a["max_conns"], a["samples"]), reverse=True)[:top_n]
    ips_out = [{
        "ip": a["ip"],
        "max_conns": a["max_conns"],
        "samples": a["samples"],
        "first_seen": a["first_seen"].isoformat(),
        "last_seen": a["last_seen"].isoformat(),
        "ports": sorted(a["ports"])[:20],
        "processes": sorted(a["processes"])[:8],
    } for a in ips]

    n_buckets = min(target_points, len(parsed))
    idx = _bucket_index([t for t, _ in parsed], n_buckets)
    tl = [dict(ips=set(), conns=0, n=0, ts=None) for _ in range(n_buckets)]
    for (t, p), b in zip(parsed, idx):
        cell = tl[b]
        cell["ts"] = t
        cell["n"] += 1
        for e in p.get("entries", []):
            cell["ips"].add(e["ip"])
            cell["conns"] += e.get("conns", 0)
    timeline = [{
        "t": c["ts"].isoformat(),
        "distinct_ips": len(c["ips"]),
        "conns": round(c["conns"] / max(c["n"], 1), 1),
    } for c in tl if c["ts"] is not None]

    latest = parsed[-1][1]
    return {
        "ips": ips_out,
        "timeline": timeline,
        "current": latest.get("entries", []),
        "truncated": latest.get("truncated", 0),
        "sample_count": len(parsed),
        "unique_ips_window": len(agg),
    }

_recorder_task: Optional[asyncio.Task] = None


async def _recorder_loop(db) -> None:
    # one warm-up sample primes per-process cpu_percent; skip persisting it
    try:
        await asyncio.to_thread(device_metrics._collect)
    except Exception:
        pass
    await asyncio.sleep(SAMPLE_INTERVAL)
    while True:
        try:
            await device_metrics.record_sample(db)
            await asyncio.sleep(SAMPLE_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Device metrics recorder error: {e}")
            await asyncio.sleep(SAMPLE_INTERVAL)


async def start_device_metrics_recorder(db) -> None:
    global _recorder_task
    if _recorder_task is None:
        _recorder_task = asyncio.create_task(_recorder_loop(db))
        logger.info("Device metrics recorder started")


async def stop_device_metrics_recorder() -> None:
    global _recorder_task
    if _recorder_task:
        _recorder_task.cancel()
        try:
            await _recorder_task
        except asyncio.CancelledError:
            pass
        _recorder_task = None
        logger.info("Device metrics recorder stopped")
