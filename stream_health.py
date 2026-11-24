"""Stream health: what the server receives from a publisher, kept in memory only.

Pure functions and small value objects; nothing here reads the database, the network or the clock
(callers pass `now`). server.py feeds `observe` from a MediaMTX paths list and reads `snapshot`
and `warnings` for the owner's health route.

The paths list is read tolerantly. MediaMTX names its received-bytes counter `bytesReceived` in
the versions the project has run and `inboundBytes` in newer ones (v1.21.3 sends both); a missing
field means "no number this time", never an error. The fixtures of tests/fixtures/mediamtx-1.21.3
are real captures of v1.21.3 (RTMP, RTMPS, RTSP), plus one hand-written WebRTC item; those of
tests/fixtures/mediamtx-1.9.3 are real captures of v1.9.3, the release setup.py installs (RTMP and RTSP;
there the list carries itemCount and pageCount, and the counter is bytesReceived only).
"""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime
from typing import Optional

RING_SIZE = 30                    # samples kept per stream
NO_DATA_SECONDS = 75.0            # the counter has not grown for this long: "no data" (two readings and slack)
DROP_RECENT_SAMPLES = 3           # the newest samples that must all be low
DROP_BASELINE_SECONDS = 300.0     # the baseline is the average of the samples of these last five minutes...
DROP_BASELINE_MIN_SAMPLES = 4     # ...needing at least this many of them (older than the recent ones)
DROP_BASELINE_MIN_BPS = 50_000    # a baseline under 50 kbit/s is too small to call a "drop"
DROP_RATIO = 0.5                  # each recent sample under half of the baseline

# MediaMTX source types (v1.9 to v1.21) and the route that disconnects the publisher of each.
KICK_ROUTES = {
    "rtmpConn": "/v3/rtmpconns/kick/{id}",
    "rtmpsConn": "/v3/rtmpsconns/kick/{id}",
    "rtspSession": "/v3/rtspsessions/kick/{id}",
    "rtspsSession": "/v3/rtspssessions/kick/{id}",
    "webRTCSession": "/v3/webrtcsessions/kick/{id}",
}
SOURCE_LABELS = {
    "rtmpConn": "RTMP", "rtmpsConn": "RTMPS", "rtspSession": "RTSP", "rtspsSession": "RTSPS",
    "webRTCSession": "WebRTC", "srtConn": "SRT", "hlsSource": "HLS", "rpiCameraSource": "Camera",
}
_ID_RE = re.compile(r"[A-Za-z0-9-]{8,64}\Z")


def parse_time(value) -> Optional[float]:
    """An RFC 3339 time from MediaMTX (nanoseconds, Z) as epoch seconds, or None."""
    if not isinstance(value, str) or not value:
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)\Z", value)
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    try:
        return datetime.fromisoformat(m.group(1) + frac + tz).timestamp()
    except ValueError:
        return None


def _num(value) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if value >= 0 else None


def parse_item(item) -> Optional[dict]:
    """One item of /v3/paths/list as {name, ready, ready_at, source_type, source_id, codecs, bytes},
    or None when it is not a usable object. `bytes` is None when no counter is present."""
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        return None
    src = item.get("source") if isinstance(item.get("source"), dict) else {}
    codecs = []
    raw = item.get("tracks")
    if isinstance(raw, list):
        codecs = [t for t in raw if isinstance(t, str)]
    if not codecs and isinstance(item.get("tracks2"), list):
        codecs = [t.get("codec") for t in item["tracks2"] if isinstance(t, dict) and isinstance(t.get("codec"), str)]
    counter = None
    for field in ("bytesReceived", "inboundBytes"):
        counter = _num(item.get(field))
        if counter is not None:
            break
    sid = src.get("id") if isinstance(src.get("id"), str) else None
    return {
        "name": item["name"],
        "ready": item.get("ready") is True,
        "ready_at": parse_time(item.get("readyTime")),
        "source_type": src.get("type") if isinstance(src.get("type"), str) else None,
        "source_id": sid if sid and _ID_RE.match(sid) else None,
        "codecs": [c[:40] for c in codecs][:8],
        "bytes": counter,
    }


def parse_paths(payload) -> dict:
    """{path name: parsed item} of a /v3/paths/list answer; anything unreadable gives {}."""
    items = payload.get("items") if isinstance(payload, dict) else None
    out = {}
    for it in items if isinstance(items, list) else ():
        p = parse_item(it)
        if p:
            out[p["name"]] = p
    return out


def new_entry(now: float) -> dict:
    return {"since": now, "samples": deque(maxlen=RING_SIZE), "bytes": None, "at": None,
            "last_data": now, "source_type": None, "source_id": None, "ready_at": None,
            "codecs": [], "ready": False, "resets": 0}


def observe(entry: dict, parsed: Optional[dict], now: float) -> None:
    """Fold one reading of the stream's path into its entry (mutates `entry`; `now` is monotonic).

    The rate is the counter delta over the time since the previous reading. A counter that went
    down, a different source id or a different ready time (the publisher reconnected) gives one
    zero sample and a new base instead of a negative or absurd rate. A reading with no path or
    no counter adds no sample; it only leaves the old values to age, so "no data" can fire."""
    if not parsed or parsed.get("bytes") is None:
        entry["ready"] = bool(parsed and parsed.get("ready"))
        return
    reconnected = (entry["source_id"] is not None and parsed["source_id"] is not None
                   and entry["source_id"] != parsed["source_id"]) or \
                  (entry["ready_at"] is not None and parsed["ready_at"] is not None
                   and entry["ready_at"] != parsed["ready_at"])
    prev_bytes, prev_at = entry["bytes"], entry["at"]
    entry.update(source_type=parsed["source_type"], source_id=parsed["source_id"],
                 ready_at=parsed["ready_at"], codecs=parsed["codecs"], ready=parsed["ready"])
    if prev_bytes is None or prev_at is None or now <= prev_at:
        entry["bytes"], entry["at"] = parsed["bytes"], now
        entry["last_data"] = now
        return
    if reconnected or parsed["bytes"] < prev_bytes:
        entry["resets"] += 1
        bps = 0.0
        entry["last_data"] = now
    else:
        delta = parsed["bytes"] - prev_bytes
        bps = delta * 8.0 / (now - prev_at)
        if delta > 0:
            entry["last_data"] = now
    entry["bytes"], entry["at"] = parsed["bytes"], now
    entry["samples"].append((now, bps))


def snapshot(entry: dict, now: float, wall_now: float) -> dict:
    """The entry as the health route shows it: seconds are ages relative to `now`."""
    samples = [(round(now - t, 1), int(bps)) for t, bps in entry["samples"]]
    ready_at = entry["ready_at"]
    return {
        "bitrate_bps": samples[-1][1] if samples else None,
        "samples": [{"age_s": a, "bps": b} for a, b in samples],
        "source": SOURCE_LABELS.get(entry["source_type"] or "", entry["source_type"]),
        "codecs": list(entry["codecs"]),
        "ready": entry["ready"],
        "ready_for_s": int(max(0.0, wall_now - ready_at)) if ready_at else None,
        "last_data_age_s": round(now - entry["last_data"], 1),
        "reconnects": entry["resets"],
    }


def warnings(entry: Optional[dict], now: float, *, relays=(), recorder: Optional[dict] = None,
             no_data_seconds: float = NO_DATA_SECONDS) -> list:
    """Smoothed warnings as [{code, level, text}]. Each rests on a window, never on one sample:
    no data needs the counter flat for `no_data_seconds`; a drop needs each of the newest three
    samples under half of the average of the five minutes before them; relay and recorder warnings read a
    state that is already sticky (a failed relay stays failed until it runs again)."""
    out = []
    if entry is not None:
        flat = now - entry["last_data"]
        if flat >= no_data_seconds:
            out.append({"code": "no_data", "level": "error",
                        "text": f"No data received for {int(flat)} seconds (warning from {int(no_data_seconds)} s)."})
        else:
            samples = list(entry["samples"])
            recent, older = samples[-DROP_RECENT_SAMPLES:], samples[:-DROP_RECENT_SAMPLES]
            base = [bps for t, bps in older if now - t <= DROP_BASELINE_SECONDS]
            if len(recent) == DROP_RECENT_SAMPLES and len(base) >= DROP_BASELINE_MIN_SAMPLES:
                base_avg = sum(base) / len(base)
                if base_avg >= DROP_BASELINE_MIN_BPS and all(b < DROP_RATIO * base_avg for _t, b in recent):
                    out.append({"code": "bitrate_drop", "level": "warn",
                                "text": "The bitrate dropped by more than half against the last five minutes."})
    if any(r.get("state") == "failed" for r in relays):
        out.append({"code": "relay_failing", "level": "warn", "text": "A relay is failing."})
    if recorder and recorder.get("state") == "stopped_by_guard":
        out.append({"code": "recording_stopped_by_guard", "level": "warn",
                    "text": "The recording was stopped by the disk guard. The stream itself is not affected."})
    elif recorder and recorder.get("state") == "refused_by_guard":
        out.append({"code": "recording_refused_by_guard", "level": "warn",
                    "text": "The recording was not started because of the disk guard."})
    elif recorder and recorder.get("state") == "failed":
        out.append({"code": "recording_failed", "level": "warn", "text": "The recorder ended with an error."})
    return out


# ---------------------------------------------------------------------------
# Error texts shown to an owner: chosen from a fixed list, never the raw line.
# ---------------------------------------------------------------------------

_ERROR_CLASSES = (
    (re.compile(r"refused host|host not allowed|not allowed", re.I), "The destination address is not allowed."),
    (re.compile(r"could not be resolved|name or service not known|resolve|getaddrinfo|dns", re.I),
     "The destination name could not be resolved."),
    (re.compile(r"connection refused", re.I), "The destination refused the connection."),
    (re.compile(r"timed out|timeout", re.I), "The connection timed out."),
    (re.compile(r"unauthori[sz]ed|forbidden|denied|authentication|401|403|invalid (stream )?key|bad key", re.I),
     "The destination did not accept the credentials."),
    (re.compile(r"no space left|disk full|free space", re.I), "The disk is full or nearly full."),
    (re.compile(r"input/output error|i/o error|broken pipe|connection reset|invalidated|end of file", re.I),
     "The connection broke."),
    (re.compile(r"auto-restart exhausted", re.I), "Restarts did not help; the relay gave up."),
    (re.compile(r"tls|ssl|certificate|handshake", re.I), "The secure connection could not be set up."),
)


def sanitise_error(text) -> Optional[str]:
    """A fixed description of a failure text, or None for no text. Only an exit code number is
    carried over from the original, so no host name, address, URL, key or path can appear."""
    if not isinstance(text, str) or not text.strip():
        return None
    code = re.match(r"\s*Exit code (-?\d{1,3})", text)
    label = next((msg for rx, msg in _ERROR_CLASSES if rx.search(text)), "The process ended with an error.")
    return f"{label} (exit code {code.group(1)})" if code else label
