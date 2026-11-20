"""Sharing or granting again with expires_in left out keeps the end time of a live share or
grant (it used to make a time-limited one permanent). A first-time share still defaults to never.

Run: venv/bin/python tests/test_grant_reshare.py
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402  (sets the import path)
from grant_harness import check, server  # noqa: E402
import grant_expiry  # noqa: E402

T0 = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
clock = {"now": T0}
grant_expiry.set_clock(lambda: clock["now"])


async def main():
    env = await h.boot()
    db, owner, adm = env.db, env.sessions["owner"], env.sessions["adm"]
    uuid, cid = await h.connection(env, "owner")
    url = f"{env.base}/api/connections/{uuid}/shares"

    async def share(body):
        async with owner.post(url, json=body) as r:
            data = await r.json()
            return r.status, {s["username"]: s for s in data.get("shares", [])}

    # ---- connection shares ---------------------------------------------------------------------
    st, shares = await share({"usernames": ["bob"], "expires_in": "7d"})
    check("a 7 day share", st == 200 and shares["bob"]["expires_in"] == 7 * 86400, str(shares))
    clock["now"] = T0 + timedelta(days=1)
    st, shares = await share({"usernames": ["bob"]})
    check("sharing again without expires_in keeps the end time (6 days left)",
          st == 200 and shares["bob"]["expires_in"] == 6 * 86400 and shares["bob"]["expires_at"] == "2030-01-08T12:00:00Z", str(shares))
    st, shares = await share({"usernames": ["bob"], "expires_in": None})
    check("expires_in null means the same as left out", shares["bob"]["expires_in"] == 6 * 86400, str(shares))
    st, shares = await share({"usernames": ["bob", "carol"]})
    check("a new person in the same request gets never, the existing one keeps hers",
          shares["bob"]["expires_in"] == 6 * 86400 and shares["carol"]["expires_in"] is None, str(shares))
    st, shares = await share({"usernames": ["bob"], "expires_in": "1d"})
    check("an explicit duration still replaces the end time", shares["bob"]["expires_in"] == 86400, str(shares))
    st, shares = await share({"usernames": ["bob"], "expires_in": "never"})
    check("an explicit never makes it permanent", shares["bob"]["expires_in"] is None, str(shares))
    st, shares = await share({"usernames": ["bob"]})
    check("left out on a permanent share stays permanent", shares["bob"]["expires_in"] is None, str(shares))

    # the expired row the sweeper has not deleted yet counts as gone
    await share({"usernames": ["bob"], "expires_in": "1h"})
    clock["now"] = T0 + timedelta(days=1, hours=2)
    check("the 1 hour share has passed", await db.get_accessible_connection(uuid, env.uid["bob"]) is None)
    st, shares = await share({"usernames": ["bob"]})
    check("left out on an expired, unswept share gives a fresh never share", shares["bob"]["expires_in"] is None, str(shares))
    check("... and the share is live again", await db.get_accessible_connection(uuid, env.uid["bob"]) is not None)

    # the audit entry says what happened
    log = [e for e in await db.get_audit_log(limit=200) if e["action"] == "connection.share"]
    check("the audit entry for a request without expires_in says unchanged", any("unchanged" in str(e["details"]) for e in log))

    # ---- service grants -------------------------------------------------------------------------------
    sid = await db.create_service("mgd", "/mgd", plugin="mediamtx", service_type="managed")
    gurl = f"{env.base}/api/managed-services/{sid}/grants"

    async def grant(body):
        async with adm.post(gurl, json=body) as r:
            data = await r.json()
            return r.status, {g["username"]: g for g in data.get("grants", [])}

    clock["now"] = T0
    st, gs = await grant({"usernames": ["bob"], "actions": ["control"], "expires_in": "8h"})
    check("an 8 hour grant", st == 200 and gs["bob"]["expires_in"] == 8 * 3600, str(gs))
    clock["now"] = T0 + timedelta(hours=1)
    st, gs = await grant({"usernames": ["bob"], "actions": ["control", "logs"]})
    check("granting again without expires_in keeps the end time and replaces the actions",
          gs["bob"]["expires_in"] == 7 * 3600 and gs["bob"]["actions"] == ["control", "logs"], str(gs))
    st, gs = await grant({"usernames": ["bob", "carol"], "actions": ["logs"]})
    check("a new grantee gets never, the existing one keeps hers",
          gs["bob"]["expires_in"] == 7 * 3600 and gs["carol"]["expires_in"] is None, str(gs))
    st, gs = await grant({"usernames": ["bob"], "actions": ["logs"], "expires_in": "never"})
    check("an explicit never makes the grant permanent", gs["bob"]["expires_in"] is None, str(gs))

    # ---- the pure helpers -----------------------------------------------------------------------------
    check("duration_from_body: left out and null mean keep", grant_expiry.duration_from_body({}) is None
          and grant_expiry.duration_from_body({"expires_in": None}) is None)
    check("duration_from_body: a key is returned", grant_expiry.duration_from_body({"expires_in": "7d"}) == "7d")
    check("expires_at_for(None) is the first-time default (never)", grant_expiry.expires_at_for(None) is None)

    grant_expiry.set_clock(None)
    await h.shutdown(env)


asyncio.run(main())
h.finish("test_grant_reshare")
