"""Stream schedule: date arithmetic across a change of offset, input checks and the hand-written .ics.

The .ics text is read back by a small parser written here (it shares no code with stream_schedule.py):
unfold, split into components, read the VTIMEZONE observances, expand the weekly RRULE in the TZID zone and
compare every occurrence with what zoneinfo says. Not proven here: any real calendar application (Apple
Calendar, Google Calendar, Thunderbird) reading the file.

Run: venv/bin/python tests/test_schedule_ics.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import stream_schedule as ss  # noqa: E402

failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


# ---------------------------------------------------------------- a small independent reader
def read_ics(text):
    assert text.endswith("\r\n"), "ends with CRLF"
    assert "\n" not in text.replace("\r\n", ""), "a bare line feed"
    physical = text[:-2].split("\r\n")
    for p in physical:
        assert len(p.encode("utf-8")) <= 75, f"line over 75 octets: {p!r}"
    logical = []
    for p in physical:
        if p.startswith(" "):
            logical[-1] += p[1:]
        else:
            logical.append(p)
    root = {"name": "ROOT", "props": [], "kids": []}
    stack = [root]
    for line in logical:
        head, _, value = line.partition(":")
        name, *params = head.split(";")
        if name == "BEGIN":
            node = {"name": value, "props": [], "kids": []}
            stack[-1]["kids"].append(node)
            stack.append(node)
        elif name == "END":
            assert stack[-1]["name"] == value, "mismatched END"
            stack.pop()
        else:
            stack[-1]["props"].append((name, dict(p.split("=", 1) for p in params), value))
    assert len(stack) == 1, "unclosed component"
    return root["kids"][0]


def prop(node, name):
    return [(p, v) for n, p, v in node["props"] if n == name]


def utc_by_vtimezone(local, vtz):
    """UTC of a local time using nothing but the VTIMEZONE observances in the file."""
    best = None
    for obs in vtz["kids"]:
        onset = datetime.strptime(prop(obs, "DTSTART")[0][1], "%Y%m%dT%H%M%S")
        if onset <= local and (best is None or onset > best[0]):
            best = (onset, obs)
    to = prop(best[1], "TZOFFSETTO")[0][1]
    sign = 1 if to[0] == "+" else -1
    return (local - sign * timedelta(hours=int(to[1:3]), minutes=int(to[3:5]))).replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- DST: weekly keeps the local time
BERLIN = "Europe/Berlin"       # leaves summer time on Sunday 25 October 2026
entry = {"id": 7, "title": "Friday show", "local_start": "2026-10-16T21:00", "tz": BERLIN, "duration_min": 90,
         "weekly": True}
starts = [ss.occurrence_start(entry, n) for n in range(4)]     # 16, 23, 30 October, 6 November
locals_ = [ss.utc_to_local(s, BERLIN) for s in starts]
check("every week of a weekly entry is 21:00 on the wall clock", all(l.hour == 21 and l.minute == 0 for l in locals_),
      str(locals_))
gaps = [(b - a) / 3600 for a, b in zip(starts, starts[1:])]
check("the UTC gap is 168 hours, then 169 across the change back to winter time", gaps == [168, 169, 168], str(gaps))
ny = [ss.occurrence_start({**entry, "tz": "America/New_York"}, n) for n in range(4)]
check("the same weeks in New York (change on 1 November) are 168, 168, 169 hours apart",
      [(b - a) / 3600 for a, b in zip(ny, ny[1:])] == [168, 168, 169])
spring = {**entry, "local_start": "2027-03-19T21:00"}          # Berlin changes on Sunday 28 March 2027
gaps = [(ss.occurrence_start(spring, n + 1) - ss.occurrence_start(spring, n)) / 3600 for n in range(2)]
check("across the change to summer time the gap is 167 hours", gaps == [168, 167], str(gaps))
check("a zone that never changes keeps 168 hours",
      ss.occurrence_start({**entry, "tz": "Asia/Tokyo"}, 3) - ss.occurrence_start({**entry, "tz": "Asia/Tokyo"}, 2) == 7 * 86400)

# ---------------------------------------------------------------- occurrence lookup
first = starts[0]
check("occurrences in a range", ss.occurrences(entry, starts[1], starts[2]) == [starts[1], starts[2]])
check("a one-off entry has exactly one occurrence",
      ss.occurrences({**entry, "weekly": False}, 0, first + 70 * 86400) == [first])
check("next_occurrences skips cancelled and started ones",
      ss.next_occurrences(entry, first - 3600, cancelled=[starts[0]], started=[starts[1]], count=2) == [starts[2], starts[3]])
check("an occurrence that began ten minutes ago still counts down (starting now)",
      ss.next_occurrences(entry, first + 600, count=1) == [first])
check("an occurrence that began an hour ago does not", ss.next_occurrences(entry, first + 3600, count=1) == [starts[1]])
check("a made-up time is not an occurrence", not ss.is_occurrence(entry, first + 60) and ss.is_occurrence(entry, first))
check("go-live 10 minutes before the start belongs to the slot", ss.occurrence_covering(entry, first - 600) == first)
check("go-live 20 minutes after the start belongs to the slot", ss.occurrence_covering(entry, first + 1200) == first)
check("go-live 2 hours late belongs to no slot", ss.occurrence_covering(entry, first + 7200) is None)
check("go-live an hour early belongs to no slot", ss.occurrence_covering(entry, first - 3600) is None)
check("a started or cancelled slot is not offered again", ss.occurrence_covering(entry, first, started=[first]) is None
      and ss.occurrence_covering(entry, first, cancelled=[first]) is None)

# ---------------------------------------------------------------- input
now = int(datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc).timestamp())
ok_in = {"title": "Friday show", "start": "2026-10-16T21:00", "tz": BERLIN, "duration_min": 90, "recurrence": "weekly"}
clean, err = ss.validate_entry(ok_in, now)
check("a good entry is accepted", err is None and clean["weekly"] is True and clean["tz"] == BERLIN, str(err))
for label, bad in {
        "a title that is too long": {**ok_in, "title": "x" * 101}, "an empty title": {**ok_in, "title": "  "},
        "a title that is not text": {**ok_in, "title": 5}, "an unknown zone": {**ok_in, "tz": "Mars/Base"},
        "an offset instead of a zone": {**ok_in, "tz": "+02:00"}, "a start that is not a date": {**ok_in, "start": "friday"},
        "a start with seconds": {**ok_in, "start": "2026-10-16T21:00:00"}, "a start in the past": {**ok_in, "start": "2026-09-01T21:00"},
        "a start years away": {**ok_in, "start": "2031-10-16T21:00"}, "a duration of zero": {**ok_in, "duration_min": 0},
        "a duration of a boolean": {**ok_in, "duration_min": True}, "a recurrence of daily": {**ok_in, "recurrence": "daily"},
        "no zone": {k: v for k, v in ok_in.items() if k != "tz"}}.items():
    check("refused: " + label, ss.validate_entry(bad, now)[1] is not None)
clean, _ = ss.validate_entry({"title": "a b\nc"}, now, existing={**entry})
check("control characters and line separators in a title become spaces", clean == {"title": "a b c"}, str(clean))
check("an edit with nothing to change is refused", ss.validate_entry({}, now, existing={**entry})[1] is not None)

# ---------------------------------------------------------------- the feed token
t1, t2 = ss.new_feed_token(), ss.new_feed_token()
check("tokens are random, well formed and prefixed", t1 != t2 and ss.feed_token_wellformed(t1) and t1.startswith("sf_"))
check("a malformed token is not well formed", not any(ss.feed_token_wellformed(x) for x in (
    "", "sf_", "sf_" + "a" * 42, "sf_" + "a" * 44, "xx_" + "a" * 43, "sf_" + "a" * 42 + "!", None, 5)))
check("the stored hash is not the token", ss.hash_feed_token(t1) != t1 and len(ss.hash_feed_token(t1)) == 64)

# ---------------------------------------------------------------- text
check("text escaping covers backslash, semicolon, comma, newline",
      ss.escape_text("a\\b;c,d\ne\r\nf") == "a\\\\b\\;c\\,d\\ne\\nf")
long = "SUMMARY:" + "ä" * 100 + "x" * 40
folded = ss.fold_line(long)
parts = folded.split("\r\n ")
check("a long line folds at 75 octets and no character is split",
      all(len(p.encode()) <= 75 for p in folded.split("\r\n")) and "".join(parts) == long
      and all(not p.encode().startswith(b"\x80") for p in parts))
check("a short line is not folded", ss.fold_line("SUMMARY:x") == "SUMMARY:x")

# ---------------------------------------------------------------- the .ics
cancelled = starts[2]                         # 30 October
items = [{**entry, "streamer": "Anna; the, streamer", "url": "https://portal.example.test/watch/3", "cancelled": [cancelled],
          "updated_at": now},
         {"id": 8, "title": "One off, special; with \\ and\nnewline " + "ä" * 60, "local_start": "2026-11-20T18:30",
          "tz": "America/New_York", "duration_min": 30, "weekly": False, "streamer": "Bo", "url": "", "cancelled": [],
          "updated_at": now},
         {"id": 9, "title": "Cancelled one-off", "local_start": "2026-11-21T10:00", "tz": "UTC", "duration_min": 60,
          "weekly": False, "streamer": "Cy", "url": "", "cancelled": [ss.occurrence_start(
              {"local_start": "2026-11-21T10:00", "tz": "UTC"}, 0)], "updated_at": now}]
text = ss.build_calendar(items, "portal.example.test", now)
cal = None
try:
    cal = read_ics(text)
except AssertionError as e:
    check("the text is strict RFC 5545 structure (CRLF, folding, nesting)", False, str(e))
if cal:
    check("the text is strict RFC 5545 structure (CRLF, folding, nesting)", True)
    check("VCALENDAR with VERSION 2.0 and a PRODID", cal["name"] == "VCALENDAR" and prop(cal, "VERSION")[0][1] == "2.0"
          and prop(cal, "PRODID"))
    vtzs = {prop(k, "TZID")[0][1]: k for k in cal["kids"] if k["name"] == "VTIMEZONE"}
    events = [k for k in cal["kids"] if k["name"] == "VEVENT"]
    check("one VTIMEZONE per zone used (Berlin, New York; UTC from the left-out entry is not used)",
          set(vtzs) == {BERLIN, "America/New_York", "UTC"} or set(vtzs) == {BERLIN, "America/New_York"}, str(set(vtzs)))
    check("the cancelled one-off entry is left out", len(events) == 2)
    uids = [prop(e, "UID")[0][1] for e in events]
    check("UIDs are stable and use the configured host, not a request header",
          uids == ["schedule-7@portal.example.test", "schedule-8@portal.example.test"]
          and uids == [prop(e, "UID")[0][1] for e in [k for k in read_ics(ss.build_calendar(items, "portal.example.test", now + 99))["kids"] if k["name"] == "VEVENT"]])
    weekly = events[0]
    check("the weekly entry is one event with RRULE:FREQ=WEEKLY", prop(weekly, "RRULE")[0][1] == "FREQ=WEEKLY"
          and len(prop(weekly, "RRULE")) == 1)
    dt_params, dt_val = prop(weekly, "DTSTART")[0]
    check("its DTSTART is local time with TZID (a UTC time would drift with daylight saving)",
          dt_params == {"TZID": BERLIN} and dt_val == "20261016T210000", f"{dt_params} {dt_val}")
    ex_params, ex_val = prop(weekly, "EXDATE")[0]
    check("the cancelled week is an EXDATE in the same form as DTSTART",
          ex_params == {"TZID": BERLIN} and ex_val == "20261030T210000", f"{ex_params} {ex_val}")
    check("duration, summary (escaped), URL",
          prop(weekly, "DURATION")[0][1] == "PT90M" and prop(weekly, "SUMMARY")[0][1] == "Anna\\; the\\, streamer: Friday show"
          and prop(weekly, "URL")[0][1] == "https://portal.example.test/watch/3")
    summ = prop(events[1], "SUMMARY")[0][1]
    check("a title with semicolon, comma, backslash and newline is escaped; the unfolded value matches",
          summ.startswith("Bo: One off\\, special\\; with \\\\ and\\nnewline ") and "\n" not in summ, summ[:60])
    check("DTSTAMP is UTC", prop(weekly, "DTSTAMP")[0][1].endswith("Z"))
    # expand the RRULE the way a calendar would, using only what is in the file
    vtz = vtzs[BERLIN]
    local = datetime.strptime(dt_val, "%Y%m%dT%H%M%S")
    exdates = {datetime.strptime(v, "%Y%m%dT%H%M%S") for v in ex_val.split(",")}
    expanded = []
    while len(expanded) < 8:
        if local not in exdates:
            expanded.append((local, utc_by_vtimezone(local, vtz)))
        local += timedelta(days=7)
    truth = [datetime.fromtimestamp(ss.occurrence_start(entry, n), timezone.utc) for n in (0, 1, 3, 4, 5, 6, 7, 8)]
    check("expanded from the file alone, the weeks are the right UTC instants (the file agrees with zoneinfo)",
          [u for _, u in expanded] == truth, str([(str(a), str(b)) for (a, _), b in zip(expanded, truth) if _ != b][:2]))
    check("... every one of them is 21:00 on the Berlin wall clock", all(l.hour == 21 for l, _ in expanded))
    check("... and the 30 October week is not there", datetime(2026, 10, 30, 21, 0) not in [l for l, _ in expanded])
    check("... the UTC hour is 19 in summer time (16 and 23 October) and 20 in winter time (6 November)",
          [u.hour for _, u in expanded[:3]] == [19, 19, 20], str([str(u) for _, u in expanded[:3]]))
    # the VTIMEZONE itself against zoneinfo, for every transition it lists
    zone = ZoneInfo(BERLIN)
    bad = []
    for obs in vtz["kids"]:
        onset = datetime.strptime(prop(obs, "DTSTART")[0][1], "%Y%m%dT%H%M%S")
        off_to = prop(obs, "TZOFFSETTO")[0][1]
        if onset.year < 2020:
            continue
        probe = (onset + timedelta(hours=3)).replace(tzinfo=zone)
        got = probe.utcoffset().total_seconds()
        want = (1 if off_to[0] == "+" else -1) * (int(off_to[1:3]) * 3600 + int(off_to[3:5]) * 60)
        if got != want:
            bad.append((str(onset), off_to, got))
    check("every VTIMEZONE observance matches the zone's real offset", not bad, str(bad))
    onsets = sorted(prop(o, "DTSTART")[0][1] for o in vtz["kids"] if o["name"] in ("STANDARD", "DAYLIGHT"))
    check("the Berlin change back is at 2026-10-25 03:00 local (summer-time clock) and forward at 2027-03-28 02:00",
          "20261025T030000" in onsets and "20270328T020000" in onsets, str(onsets[:12]))
    kinds = {prop(o, "DTSTART")[0][1]: o["name"] for o in vtz["kids"]}
    check("the change into winter time is a STANDARD observance, into summer time a DAYLIGHT one",
          kinds.get("20261025T030000") == "STANDARD" and kinds.get("20270328T020000") == "DAYLIGHT")
    check("a zone without changes has one observance", len(read_ics(ss.build_calendar(
        [{**items[2], "id": 10, "tz": "Asia/Tokyo", "cancelled": []}], "h", now))["kids"][0]["kids"]) == 1)

# ---------------------------------------------------------------- EXDATE is the wall-clock time the RRULE produces
def _exdates(ics_text):
    got = [l for l in ics_text.replace("\r\n ", "").split("\r\n") if l.startswith("EXDATE")]
    return got


gap = {"id": 21, "title": "Late show", "local_start": "2027-03-14T02:30", "tz": BERLIN, "duration_min": 60, "weekly": True,
       "streamer": "A", "url": "", "updated_at": now}
gap_start = ss.occurrence_start(gap, 2)                      # Sunday 28 March 2027 02:30 does not exist in Berlin
check("(setup) the cancelled week's own instant, read back in the zone, is 03:30 (the old EXDATE) and not 02:30",
      ss.utc_to_local(gap_start, BERLIN) == datetime(2027, 3, 28, 3, 30), str(ss.utc_to_local(gap_start, BERLIN)))
check("(setup) that week is the 3rd occurrence of the rule", ss.occurrence_index(gap, gap_start) == 2)
out = ss.build_calendar([{**gap, "cancelled": [gap_start]}], "h", now)
check("a cancelled week inside the spring-forward gap is an EXDATE at the rule's own 02:30, not 03:30",
      _exdates(out) == ["EXDATE;TZID=Europe/Berlin:20270328T023000"], str(_exdates(out)))
fold = {**gap, "id": 22, "local_start": "2026-10-11T02:30"}
fold_start = ss.occurrence_start(fold, 2)                    # Sunday 25 October 2026 02:30 happens twice
out = ss.build_calendar([{**fold, "cancelled": [fold_start]}], "h", now)
check("a cancelled week inside the autumn fold is an EXDATE at 02:30",
      _exdates(out) == ["EXDATE;TZID=Europe/Berlin:20261025T023000"], str(_exdates(out)))
out = ss.build_calendar([{**gap, "cancelled": [ss.occurrence_start(gap, 1), gap_start, ss.occurrence_start(gap, 3)]}], "h", now)
check("several cancelled weeks, the gap one among them, are each at their own wall-clock time",
      _exdates(out) == ["EXDATE;TZID=Europe/Berlin:20270321T023000,20270328T023000,20270404T023000"], str(_exdates(out)))
out = ss.build_calendar([{**gap, "cancelled": [gap_start + 60, 5]}], "h", now)
check("a cancelled time that is none of the entry's occurrences leaves no EXDATE", _exdates(out) == [], str(_exdates(out)))

if failed:
    print(f"\ntest_schedule_ics: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_schedule_ics: all checks passed")
