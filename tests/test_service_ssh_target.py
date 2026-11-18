"""The (host, port) an admin ssh service dials, and when an edit changes it.

The accept-host-key dialog compares the port it was shown with this target, and
an edit that changes the target must drop the stored host-key pin.

Run: venv/bin/python tests/test_service_ssh_target.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402


def svc(host="h.example", port=22):
    return {"host": host, "port": port, "config": {}}


def test_target_coerces_port():
    t = server._service_ssh_target
    assert t(svc(port=2222)) == ("h.example", 2222)
    assert t(svc(port=None)) == ("h.example", 22)
    # config port as text, null, junk, out of range, bool
    for bad in (None, "", "abc", "0", 0, 70000, -1, True, [], {}):
        assert t({"host": "h", "port": 2222, "config": {"port": bad}}) == ("h", 2222), bad
        assert t({"host": "h", "port": None, "config": {"port": bad}}) == ("h", 22), bad
    assert t({"host": "h", "port": 2222, "config": {"port": "2200"}}) == ("h", 2200)
    assert t({"host": "h", "port": 2222, "config": {"port": " 2200 "}}) == ("h", 2200)
    assert t({"host": "h", "port": 2222, "config": {"port": 2200}}) == ("h", 2200)
    assert t({"host": "h", "port": "2222", "config": {}}) == ("h", 2222)
    assert t({"host": "h", "port": "junk", "config": {}}) == ("h", 22)
    assert t({"host": None, "port": None, "config": None}) == ("", 22)
    assert isinstance(t({"host": "h", "port": 22, "config": {"port": "22"}})[1], int)


def test_target_changed_includes_config_overrides():
    ch = server._service_target_changed
    base = {"host": "h.example", "port": 22, "config": {"username": "u"}}
    assert not ch(base, {})
    assert not ch(base, {}, {"username": "other"})
    # column edits
    assert ch(base, {"host": "other.example"})
    assert ch(base, {"port": 2222})
    assert not ch(base, {"host": "h.example", "port": "22"})
    assert not ch(base, {"port": None})
    # config-only edits that move the effective target
    assert ch(base, {}, {"host": "other.example"})
    assert ch(base, {}, {"port": 2222})
    assert ch(base, {}, {"port": "2222"})
    assert not ch(base, {}, {"port": "22"})
    # a config override hides a column edit, and removing it exposes the column
    over = {"host": "h.example", "port": 22, "config": {"host": "real.example", "port": 2200}}
    assert not ch(over, {"host": "moved.example", "port": 9999})
    assert ch(over, {}, {"username": "u"})          # override removed: back to the columns
    assert not ch(over, {}, {"host": "real.example", "port": "2200"})
    # a config that is not an object leaves the target alone
    assert not ch(base, {}, "not a dict")


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e!r}")
    sys.exit(1 if failed else 0)
