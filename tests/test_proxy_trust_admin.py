"""Admin > Settings > Shared web connections (static/js/proxy-trust-admin.js, 1.24.1): the list of members' shared web
connections with Trust and Remove trust, each asking first on its own row, guarded while the request is in flight, built
with textContent. Driven in Node against a fake DOM and a fake Portal.fetch (tests/proxy_trust_admin_harness.js), plus
static checks of admin.html. No browser: layout is not covered. Run: venv/bin/python tests/test_proxy_trust_admin.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


node = shutil.which("node")
if not node:
    check("node is available", False, "install node to run the client checks")
else:
    try:
        out = subprocess.run([node, str(ROOT / "tests" / "proxy_trust_admin_harness.js"), str(ROOT / "static" / "js" / "proxy-trust-admin.js")],
                             capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as e:
        out = subprocess.CompletedProcess(e.cmd, 1, "", "the harness did not finish within 60 seconds")
    lines = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", bool(lines) and out.returncode == 0, (out.stderr or out.stdout)[-600:])
    for line in lines:
        r = json.loads(line[7:])
        check("client: " + r["name"], r["ok"], r["detail"])

admin = (ROOT / "static" / "admin.html").read_text()
card = admin[admin.index('id="proxy-trust-card"'):admin.index("Certificate Management Card")]
check("admin.html has the card, hidden until the list loads, with no inline handler", 'style="display:none;"' in card and "onclick" not in card)
check("admin.html loads the script with a version", '/static/js/proxy-trust-admin.js?v=1"' in admin)
route = (ROOT / "server.py").read_text()
check("the screen only uses the two existing superadmin routes",
      "/api/admin/proxy-trust-connections" in (ROOT / "static" / "js" / "proxy-trust-admin.js").read_text()
      and "/proxy-trust'" in (ROOT / "static" / "js" / "proxy-trust-admin.js").read_text()
      and 'add_get("/api/admin/proxy-trust-connections"' in route)

# (1.24.2, E6) the fingerprint a trust mark and an accepted share notice are bound to: also the port in the config, the
# Host entry of extra_headers and the path rewrite rules. A connection that uses none of them keeps its 1.24.1 value.
sys.path.insert(0, str(ROOT))
import proxy_origin as po  # noqa: E402

_c = {"type": "http", "host": "example.org", "port": 80}
check("E6 fingerprint: a connection with none of the three fields keeps its 1.24.1 value",
      po.target_fingerprint(_c, {}) == "48e82b33944de8653a982491e041a4e3"
      and po.target_fingerprint({"type": "http", "host": "Example.org", "port": 8080}, {"target_url": "", "browser_mode": False})
      == "4b8a1e3c1b30e945bf4ba5bef9f295c1"
      and po.target_fingerprint(_c, {"target_url": "http://x.org", "browser_mode": True, "extra_headers": {"X-A": "1"},
                                     "port": "", "path_rewrite_rules": []}) == "31a707a299782c182660880f41b9187d")
_f0 = po.target_fingerprint(_c, {})
check("E6 fingerprint: empty values of the three fields do not change it",
      po.target_fingerprint(_c, {"port": None, "extra_headers": {"Host": ""}, "path_rewrite_rules": None}) == _f0
      and po.target_fingerprint(_c, {"extra_headers": "junk", "path_rewrite_rules": []}) == _f0)
_fp = po.target_fingerprint(_c, {"port": 8443})
_fh = po.target_fingerprint(_c, {"extra_headers": {"Host": "Internal.Example"}})
_fr = po.target_fingerprint(_c, {"path_rewrite_rules": [{"match": "^/a", "replace": "/b"}]})
check("E6 fingerprint: a config port, a Host header and a rewrite rule each end the match",
      len({_f0, _fp, _fh, _fr}) == 4, (_f0, _fp, _fh, _fr))
check("E6 fingerprint: the Host header name is case-insensitive and its value is lower-cased",
      po.target_fingerprint(_c, {"extra_headers": {"hOsT": "INTERNAL.example"}}) == _fh)
check("E6 fingerprint: another Host value or another rule gives another value",
      po.target_fingerprint(_c, {"extra_headers": {"Host": "other.example"}}) != _fh
      and po.target_fingerprint(_c, {"path_rewrite_rules": [{"match": "^/a", "replace": "/c"}]}) != _fr)
check("E6 fingerprint: other extra headers are not part of it",
      po.target_fingerprint(_c, {"extra_headers": {"X-Other": "1"}}) == _f0)
check("E6 fingerprint: rule key order does not matter",
      po.target_fingerprint(_c, {"path_rewrite_rules": [{"replace": "/b", "match": "^/a"}]}) == _fr)

if failed:
    print(f"\ntest_proxy_trust_admin: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_proxy_trust_admin: all checks passed")
