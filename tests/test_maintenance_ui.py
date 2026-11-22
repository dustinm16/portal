"""The administrator's forms for maintenance and announcements: the service and connection forms, the
Settings cards and the script behind them.

Source checks (ids, no inline handlers, no innerHTML in the script that shows announcement text) and the
form helpers run under Node against a fake document. No browser: how the forms look and the date picker
in a real browser are not proven here.

Run: venv/bin/python tests/test_maintenance_ui.py
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
index = (STATIC / "index.html").read_text()
admin_html = (STATIC / "admin.html").read_text()
admin_js = (STATIC / "js" / "admin.js").read_text()
uc_js = (STATIC / "js" / "user-connections.js").read_text()
mad = (STATIC / "js" / "maintenance-admin.js").read_text()
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


for prefix in ("service", "edit-service"):
    for suffix in ("maint", "maint-until", "maint-msg"):
        check(f"index.html has #{prefix}-{suffix}", f'id="{prefix}-{suffix}"' in index)
for ident in ("connection-maint-group", "connection-maint", "connection-maint-until", "connection-maint-msg"):
    check(f"index.html has #{ident}", f'id="{ident}"' in index)
check("the connection group is hidden until the script shows it to an administrator",
      re.search(r'id="connection-maint-group" style="display: none;"', index) is not None)
_blocks = [index[i:index.index("</small>", i)] for i in
           (m.start() for m in re.finditer(r"Maintenance \(administrators only", index))]
check("the three maintenance blocks have no inline handlers", len(_blocks) == 3 and not any("onclick" in b_ for b_ in _blocks), str(len(_blocks)))
check("admin.html has the two cards and loads the script with a version",
      'id="maintenance-body"' in admin_html and 'id="announcements-body"' in admin_html
      and re.search(r'src="/static/js/maintenance-admin\.js\?v=\d+"', admin_html) is not None)
check("the script puts server text in with textContent only: no innerHTML, no insertAdjacentHTML, no inline handlers",
      not re.search(r"innerHTML|insertAdjacentHTML|outerHTML|document\.write|\bonclick\b|setAttribute\('on", mad))
check("the script adds its handlers with addEventListener", mad.count("addEventListener('click'") >= 6)

m1 = re.search(r"function maintenanceFormValues\(.*?\n}\n", admin_js, re.S)
m2 = re.search(r"function fillMaintenanceForm\(.*?\n}\n", admin_js, re.S)
check("the service form helpers are in admin.js", bool(m1 and m2))
check("the add form sends the fields only when ticked, the edit form always",
      "maintenanceFormValues('service', false)" in admin_js and "maintenanceFormValues('edit-service', true)" in admin_js
      and "fillMaintenanceForm('edit-service', service)" in admin_js)
check("the connection form shows the group to an administrator only and sends nothing for a member",
      "connectionRecordingAllowed() ? 'block' : 'none'" in uc_js and "if (!connectionRecordingAllowed()" in uc_js
      and "...connectionMaintenanceValues(isEdit)" in uc_js)

if m1 and m2:
    script = """
const els = new Proxy({}, { get(t, id) { if (!(id in t)) t[id] = { value: '', checked: false }; return t[id]; } });
global.document = { getElementById: (id) => els[id] };
""" + m1.group(0) + m2.group(0) + """
const out = {};
els['service-maint'].checked = false;
out.addOff = maintenanceFormValues('service', false);
out.editOff = maintenanceFormValues('edit-service', true);
els['service-maint'].checked = true;
els['service-maint-until'].value = '2030-03-04T20:00';
els['service-maint-msg'].value = '  swapping a disk  ';
out.addOn = maintenanceFormValues('service', false);
els['service-maint-until'].value = '';
els['service-maint-msg'].value = '';
out.open = maintenanceFormValues('service', false);
fillMaintenanceForm('edit-service', { maintenance: true, maintenance_active: true, maintenance_until: '2030-03-04T20:00:00Z', maintenance_message: 'm' });
out.filled = { on: els['edit-service-maint'].checked, until: els['edit-service-maint-until'].value, msg: els['edit-service-maint-msg'].value };
fillMaintenanceForm('edit-service', { maintenance: true, maintenance_active: false, maintenance_until: '2020-03-04T20:00:00Z', maintenance_message: 'old' });
out.expired = { on: els['edit-service-maint'].checked, until: els['edit-service-maint-until'].value, msg: els['edit-service-maint-msg'].value };
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d, env={"TZ": "UTC", "PATH": "/usr/bin:/bin"})
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the helpers", bool(got), r.stderr[-300:])
    check("unticked: nothing on add, maintenance false on edit", got.get("addOff") == {} and got.get("editOff") == {"maintenance": False}, str(got))
    check("ticked: UTC end time, trimmed message", got.get("addOn") == {
        "maintenance": True, "maintenance_until": "2030-03-04T20:00:00Z", "maintenance_message": "swapping a disk"}, str(got.get("addOn")))
    check("ticked without an end time: open-ended", got.get("open", {}).get("maintenance_until") is None
          and got["open"].get("maintenance_message") is None)
    check("an active maintenance fills the edit form", got.get("filled") == {"on": True, "until": "2030-03-04T20:00", "msg": "m"}, str(got.get("filled")))
    check("one that has ended opens as off, with no end time (saving never sends a past time)",
          got.get("expired") == {"on": False, "until": "", "msg": ""}, str(got.get("expired")))

# ---- the announcement form and the list of connections in maintenance, under Node --------------------------
with tempfile.TemporaryDirectory() as d:
    r = subprocess.run(["node", str(Path(__file__).resolve().parent / "maintenance_admin_harness.js"),
                        str(STATIC / "js" / "maintenance-admin.js")], capture_output=True, text=True, timeout=30,
                       cwd=d, env={"TZ": "UTC", "PATH": "/usr/bin:/bin"})
got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
check("node ran the admin script", bool(got), r.stderr[-300:])
check("editing an announcement without touching its times sends neither (an ended one stays editable)",
      "ends_at" not in got.get("unchanged", {"ends_at": 1}) and "starts_at" not in got.get("unchanged", {"starts_at": 1})
      and got.get("unchanged", {}).get("body") == "old news", str(got.get("unchanged")))
check("... a changed end time is sent, as UTC",
      got.get("changedEnd", {}).get("ends_at") == "2030-01-01T10:00:00Z" and "starts_at" not in got.get("changedEnd", {}), str(got.get("changedEnd")))
check("a new announcement always sends both times", set(got.get("create", {})) >= {"starts_at", "ends_at"}
      and got["create"]["ends_at"] == "2030-01-01T10:00:00Z", str(got.get("create")))
check("the clear button posts to the connection's clear route, the id escaped",
      got.get("clear", {}).get("method") == "POST"
      and got["clear"]["url"] == "/api/admin/connections/abc%2Fdef/maintenance/clear", str(got.get("clear")))
check("admin.html has the container for that list and the card says the scope",
      'id="maintenance-conns"' in admin_html and "only one they own" in mad and "Any administrator can clear it here" in mad)

if failures:
    print(f"\ntest_maintenance_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_maintenance_ui: all checks passed")
