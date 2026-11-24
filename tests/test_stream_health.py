"""stream_health.py: the paths-list parser, the bitrate and ring logic, the smoothed warnings and the
error-text sanitiser, against real captures of MediaMTX v1.21.3 (tests/fixtures/mediamtx-1.21.3).

Proven: parsing of RTMP, RTMPS and RTSP captures (rtmp_ prefixed path included), tolerance of missing
fields, the rate against the captured counters, clamping on counter reset and reconnect, the ring bound,
the no-data and bitrate-drop warnings with a shortened threshold, the fixed error vocabulary.
Not proven: a WebRTC capture (the fixture is hand-written), MediaMTX 1.9.3 (not available).

Run: venv/bin/python tests/test_stream_health.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import stream_health as sh  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "mediamtx-1.21.3"


def fx(name):
    return json.loads((FIX / name).read_text())


def test_parse_captures():
    p = sh.parse_paths(fx("paths_list_rtmp_rtmps.json"))
    a, b = p["live/livekey_a"], p["live/livekey_b"]
    assert a["source_type"] == "rtmpConn" and b["source_type"] == "rtmpsConn"
    assert a["codecs"] == ["H264", "MPEG-4 Audio"] and a["ready"] is True
    assert a["bytes"] == 950222 and a["ready_at"] > 1.7e9 and a["source_id"]
    q = sh.parse_paths(fx("paths_list_rtsp_rtmp_prefixed.json"))
    assert q["live/rtmp_tokx"]["source_type"] == "rtspSession" and q["live/rtmp_tokx"]["codecs"] == ["H264"]
    full = sh.parse_paths(fx("paths_list_rtmp_full_item.json"))["live/livekey_a"]
    assert full["codecs"] == ["H264", "MPEG-4 Audio"]
    w = sh.parse_paths(fx("paths_list_webrtc_HANDWRITTEN.json"))["livekey_w"]
    assert w["source_type"] == "webRTCSession" and sh.SOURCE_LABELS["webRTCSession"] == "WebRTC"
    assert sh.parse_paths(fx("paths_list_empty.json")) == {}


def test_tolerant_parser():
    assert sh.parse_paths(None) == {} and sh.parse_paths({"items": "x"}) == {} and sh.parse_paths([]) == {}
    assert sh.parse_item({"name": "live/x"})["bytes"] is None
    it = sh.parse_item({"name": "live/x", "inboundBytes": 77, "source": None, "tracks": None,
                        "tracks2": [{"codec": "AV1"}, 5]})
    assert it["bytes"] == 77 and it["source_type"] is None and it["codecs"] == ["AV1"]
    assert sh.parse_item({"name": "n", "bytesReceived": -1, "inboundBytes": 5})["bytes"] == 5
    assert sh.parse_item({"name": "n", "bytesReceived": "9"})["bytes"] is None
    assert sh.parse_item({"name": 3}) is None and sh.parse_item("x") is None
    assert sh.parse_item({"name": "n", "source": {"id": "x" * 500}})["source_id"] is None


def test_bitrate_from_captured_counters():
    a = sh.parse_paths(fx("paths_list_two_samples_5s_apart_a.json"))["live/livekey_a"]
    b = sh.parse_paths(fx("paths_list_two_samples_5s_apart_b.json"))["live/livekey_a"]
    e = sh.new_entry(100.0)
    sh.observe(e, a, 100.0)
    assert not e["samples"]                     # the first reading only sets the base
    sh.observe(e, b, 105.0)
    bps = e["samples"][-1][1]
    # the publisher was configured for 800 kbit/s video plus 64 kbit/s audio
    assert abs(bps - 864_000) / 864_000 < 0.10, bps
    snap = sh.snapshot(e, 105.0, 1.8e9)
    assert snap["source"] == "RTMP" and snap["codecs"] == ["H264", "MPEG-4 Audio"] and snap["bitrate_bps"] == int(bps)


def test_clamp_on_reset_and_reconnect():
    e = sh.new_entry(0.0)
    mk = lambda n, sid="aaaaaaaa-1", ra=1.0: {"bytes": n, "source_id": sid, "ready_at": ra, "ready": True,
                                              "source_type": "rtmpConn", "codecs": []}
    sh.observe(e, mk(1000), 0.0)
    sh.observe(e, mk(51000), 5.0)
    assert e["samples"][-1][1] == 80_000
    sh.observe(e, mk(10), 10.0)                 # counter went down
    assert e["samples"][-1][1] == 0 and e["resets"] == 1
    sh.observe(e, mk(500000, sid="bbbbbbbb-2"), 15.0)   # new source id: reconnect, not a 800 kbit/s burst
    assert e["samples"][-1][1] == 0 and e["resets"] == 2
    sh.observe(e, mk(500000 + 25000, sid="bbbbbbbb-2"), 20.0)
    assert e["samples"][-1][1] == 40_000
    sh.observe(e, mk(600000, sid="bbbbbbbb-2", ra=9.0), 25.0)   # same id, new ready time
    assert e["samples"][-1][1] == 0 and e["resets"] == 3


def test_ring_bound_and_missing_counter():
    e = sh.new_entry(0.0)
    for i in range(100):
        sh.observe(e, {"bytes": i * 1000, "source_id": None, "ready_at": None, "ready": True,
                       "source_type": "rtmpConn", "codecs": []}, float(i))
    assert len(e["samples"]) == sh.RING_SIZE
    n = len(e["samples"])
    sh.observe(e, {"bytes": None, "ready": False}, 101.0)
    sh.observe(e, None, 102.0)
    assert len(e["samples"]) == n and e["ready"] is False


def test_no_data_warning_with_short_threshold():
    a = sh.parse_paths(fx("paths_list_stalled_a.json"))["live/livekey_a"]
    b = sh.parse_paths(fx("paths_list_stalled_b_publisher_stopped_by_SIGSTOP.json"))["live/livekey_a"]
    assert a["bytes"] == b["bytes"] and b["ready"]   # captured: the publisher was stopped, the path stayed ready
    e = sh.new_entry(0.0)
    sh.observe(e, a, 0.0)
    sh.observe(e, {**a, "bytes": a["bytes"] + 100000}, 5.0)
    assert sh.warnings(e, 5.0, no_data_seconds=12) == []
    t = 5.0
    for t in (10.0, 15.0):
        sh.observe(e, b if False else {**a, "bytes": a["bytes"] + 100000}, t)
    assert sh.warnings(e, 15.0, no_data_seconds=12) == []   # 10 s flat: not yet
    sh.observe(e, {**a, "bytes": a["bytes"] + 100000}, 20.0)
    w = sh.warnings(e, 20.0, no_data_seconds=12)
    assert [x["code"] for x in w] == ["no_data"]
    # the real threshold (75 s) is longer than the gap between two readings of the 30 s health check
    assert sh.NO_DATA_SECONDS >= 2 * 30.0
    assert [x["code"] for x in sh.warnings(e, 20.0)] == []
    assert [x["code"] for x in sh.warnings(e, 5.0 + 74.0)] == []
    assert [x["code"] for x in sh.warnings(e, 5.0 + 75.0)] == ["no_data"]
    sh.observe(e, {**a, "bytes": a["bytes"] + 200000}, 85.0)           # data again: the warning clears
    assert sh.warnings(e, 85.0) == []


def test_healthy_stream_read_every_30_seconds_never_warns():
    # readings 30 s apart, 3 Mbit/s: the age of the last growth is never over 30 s between two readings
    e, t = _entry_with([3_000_000] * 12, step=30.0)
    for wait in (0.0, 15.0, 29.9):
        assert sh.warnings(e, t + wait) == [], wait


def _entry_with(rates, step=5.0):
    e = sh.new_entry(0.0)
    n, t = 0, 0.0
    sh.observe(e, {"bytes": 0, "source_id": None, "ready_at": None, "ready": True, "source_type": "x", "codecs": []}, t)
    for r in rates:
        t += step
        n += int(r * step / 8)
        sh.observe(e, {"bytes": n, "source_id": None, "ready_at": None, "ready": True, "source_type": "x", "codecs": []}, t)
    return e, t


def test_drop_warning_is_smoothed():
    steady = [800_000] * 10
    e, t = _entry_with(steady + [100_000])
    assert sh.warnings(e, t) == []                      # one low sample does not flap
    e, t = _entry_with(steady + [100_000, 100_000])
    assert sh.warnings(e, t) == []
    e, t = _entry_with(steady + [100_000, 100_000, 100_000])
    assert [x["code"] for x in sh.warnings(e, t)] == ["bitrate_drop"]
    e, t = _entry_with(steady + [500_000] * 3)           # down by less than half: no warning
    assert sh.warnings(e, t) == []
    e, t = _entry_with([20_000] * 10 + [1_000] * 3)      # a tiny baseline is not a drop
    assert sh.warnings(e, t) == []
    e, t = _entry_with([800_000] * 2 + [100_000] * 3)    # too little history
    assert sh.warnings(e, t) == []


def test_drop_warning_works_with_readings_30_seconds_apart():
    steady = [3_000_000] * 10
    e, t = _entry_with(steady + [500_000] * 3, step=30.0)
    assert [x["code"] for x in sh.warnings(e, t)] == ["bitrate_drop"]
    e, t = _entry_with(steady + [500_000] * 2, step=30.0)       # two low readings are not three
    assert sh.warnings(e, t) == []
    e, t = _entry_with([3_000_000] * 3 + [500_000] * 3, step=30.0)   # under four older readings: too little history
    assert sh.warnings(e, t) == []


def test_relay_and_recorder_warnings():
    codes = lambda **kw: [x["code"] for x in sh.warnings(None, 0.0, **kw)]
    assert codes(relays=[{"state": "failed"}]) == ["relay_failing"]
    assert codes(relays=[{"state": "running"}, {"state": "idle"}]) == []
    assert codes(recorder={"state": "stopped_by_guard"}) == ["recording_stopped_by_guard"]
    assert codes(recorder={"state": "refused_by_guard"}) == ["recording_refused_by_guard"]
    assert codes(recorder={"state": "recording"}) == []


def test_sanitise_error_has_no_origin_text():
    raw = [
        "Exit code 1: [tcp @ 0x1] Connection to tcp://live.example.net:1935?timeout=0 failed: Connection refused",
        "Exit code 1: rtmp://user:pw@10.1.2.3/app/[KEY_REDACTED]: Input/output error /home/dustin/x.flv",
        "Host not allowed", "Host could not be resolved", "Auto-restart exhausted after repeated failures",
        "weird secret-token-XYZ at /var/lib/portal", "Exit code 183: 403 Forbidden"]
    for r in raw:
        s = sh.sanitise_error(r)
        assert s and not any(x in s for x in ("example", "10.1", "user", "pw", "/", "XYZ", "dustin", "rtmp", "tcp"))
    assert sh.sanitise_error(raw[0]).startswith("The destination refused the connection.")
    assert sh.sanitise_error(raw[0]).endswith("(exit code 1)")
    assert sh.sanitise_error("Exit code 183: 403 Forbidden").startswith("The destination did not accept")
    assert sh.sanitise_error("") is None and sh.sanitise_error(None) is None
    assert sh.sanitise_error(raw[5]) == "The process ended with an error."


def test_kick_routes_match_captured_exchanges():
    ex = fx("kick_exchanges.json")
    assert ex["source_type_to_kick_route"] == sh.KICK_ROUTES
    assert "srtConn" not in sh.KICK_ROUTES


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception:
                import traceback
                traceback.print_exc()
                print("FAIL", name)
                failed += 1
    sys.exit(1 if failed else 0)
