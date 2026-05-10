# Jenkins posture testing — runbook

The Jenkins posture rules (`PLAT-JK-*`) talk to a live Jenkins controller's
REST API. Unit tests stub the API responses, which catches regressions in
rule logic but doesn't verify that taintly's assumptions about API shapes
match what real Jenkins actually returns.

This runbook walks through end-to-end verification using the ephemeral
Jenkins controller in `dev/jenkins-test/`.

**Prerequisites**: Docker (or any compatible runtime), Python 3.10+, the
taintly checkout.

---

## Quick start — verify all rules in 5 minutes

```bash
cd dev/jenkins-test
docker compose up -d
# Wait ~60s for boot
sleep 60

# Run posture audit against the throwaway controller
JENKINS_USER=admin JENKINS_TOKEN=admin python -m taintly \
    --jenkins-url http://localhost:8080
```

The default `docker-compose.yml` launches Jenkins with
`-Djenkins.install.runSetupWizard=false` — i.e. with **security
deliberately disabled**. Expected findings:

| Rule | Expected | Why |
|---|---|---|
| `PLAT-JK-007` | **CRITICAL fire** | Controller has `useSecurity: false`. This is the headline test. |
| `PLAT-JK-001` | **CRITICAL fire** | Anonymous read works (no auth required). |
| `PLAT-JK-004` | **HIGH fire** | `/script` is reachable. |
| `PLAT-JK-005` | possibly fires | CSRF state varies by Jenkins version. |
| `PLAT-JK-002` | LOW or no fire | Fresh controller has no plugins yet — no outdated. |
| `PLAT-JK-006` | LOW fire (feed unavailable) on first run, then silent | Network reach to GitHub raw varies; subsequent runs work once cached. |
| `PLAT-JK-010` | silent | Default update center URL is canonical. |

When done:

```bash
docker compose down -v   # wipe the volume so next run is fresh
```

---

## Per-rule verification

### `PLAT-JK-006` — Plugin advisory cross-check

The unit tests verify the parser logic; this verifies that the parser
matches the **real** feed shape published at
[`jenkins-infra/update-center2/resources/warnings.json`](https://github.com/jenkins-infra/update-center2/blob/master/resources/warnings.json).

**Step 1** — confirm the feed shape directly:

```bash
curl -sfL https://raw.githubusercontent.com/jenkins-infra/update-center2/master/resources/warnings.json \
  | python -c 'import json,sys; d=json.load(sys.stdin); e=d[0] if isinstance(d,list) else d; print("type:", type(d).__name__); print("first entry keys:", list(e.keys() if isinstance(d,dict) else d[0].keys()))'
```

Expected output: list of warning entries with keys including `id`,
`type`, `name`, `message`, `url`, `versions`. If the schema has changed,
update `_version_matches_warning_entry` and the schema doc-comment in
`taintly/platform/jenkins_checks.py`.

**Step 2** — install a known-vulnerable plugin to verify a fire:

1. Visit `http://localhost:8080/manage/pluginManager/available`
2. Install an old version of any plugin that has a published
   advisory — e.g. `script-security` 1.x. (Jenkins's UI defaults to the
   latest version; you may need to use `Advanced > Upload Plugin` with a
   manually-downloaded `.hpi`.)
3. Re-run the posture audit. PLAT-JK-006 should fire HIGH naming the
   plugin and the matching `SECURITY-NNN` advisory ID.

**Step 3** — verify silence on patched versions:

1. Install the same plugin at its current version.
2. Re-run the audit. PLAT-JK-006 should be silent for that plugin.

### `PLAT-JK-007` — Security disabled

Already verified by the default docker-compose (security off). To
verify the **negative** path (rule silent when security is on):

```bash
docker compose down -v   # reset
# Edit docker-compose.yml to remove the runSetupWizard=false flag
# (or override JAVA_OPTS to ""). Re-run:
docker compose up -d
sleep 60
# Visit http://localhost:8080 — Jenkins will show the setup wizard.
# Complete it: choose "Install suggested plugins", create an admin user.
JENKINS_USER=admin JENKINS_TOKEN=<your-admin-token> python -m taintly \
    --jenkins-url http://localhost:8080
```

PLAT-JK-007 should not fire. PLAT-JK-001 (anonymous read) and
PLAT-JK-004 (script console exposure) should also be silent at this
point.

### `PLAT-JK-010` — Update Center URL integrity

**Step 1** — verify silence on default URL: covered by the quick-start
run above.

**Step 2** — verify fire on replaced URL:

```bash
# In the running controller's Manage Jenkins UI:
#   Manage Jenkins > Manage Plugins > Advanced
#   Update Site URL: change to https://my-mirror.invalid/update-center.json
#   Click Submit, wait for the change to apply
JENKINS_USER=admin JENKINS_TOKEN=admin python -m taintly \
    --jenkins-url http://localhost:8080
```

PLAT-JK-010 should fire HIGH naming the non-canonical URL.

### `PLAT-JK-001`, `PLAT-JK-002`, `PLAT-JK-003`, `PLAT-JK-004`, `PLAT-JK-005`

The phase-1 rules. Their unit tests are in the existing test suite. The
quick-start run above exercises them end-to-end against a real
controller — if any of them silently miss a misconfiguration that the
unit test claims they catch, the integration is broken.

---

## Verifying the schema assumptions in the rule code

When a Jenkins major version ships, three things to spot-check:

1. **`/api/json` includes `useSecurity`** — `PLAT-JK-007` depends on this.
   ```bash
   curl -sfL -u admin:admin http://localhost:8080/api/json \
     | python -c 'import json,sys; print("useSecurity in:", "useSecurity" in json.load(sys.stdin))'
   ```
   Should print `True`. The field comes from `isUseSecurity()` in
   [Jenkins.java](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/jenkins/model/Jenkins.java),
   which is `@Exported`.

2. **`/updateCenter/api/json` returns `sites`** — `PLAT-JK-010` depends
   on this.
   ```bash
   curl -sfL -u admin:admin http://localhost:8080/updateCenter/api/json \
     | python -c 'import json,sys; d=json.load(sys.stdin); print("sites count:", len(d.get("sites", [])))'
   ```
   Should print a positive integer.

3. **Plugin response includes `shortName`, `version`, `active`** —
   `PLAT-JK-002` and `PLAT-JK-006` depend on these.
   ```bash
   curl -sfL -u admin:admin "http://localhost:8080/pluginManager/api/json?depth=1" \
     | python -c 'import json,sys; d=json.load(sys.stdin); p=d.get("plugins",[{}])[0]; print("plugin keys:", sorted(p.keys())[:10])'
   ```
   Should include `shortName`, `version`, `active`, and `hasUpdate`.

If any of these schema checks fail on a new Jenkins version, the
corresponding rule needs updating. Pin the failing assumption in a
unit test using the StubClient pattern in
`tests/unit/test_platform_jenkins_phase2.py`.

---

## CI integration (future)

Spinning up Jenkins in CI to run this verification on every PR is
overkill (60s startup + flakiness). A reasonable middle ground is a
**weekly cron job** that:

1. Runs the docker-compose verification.
2. Records the actual feed shape into a local fixture.
3. Compares the recorded fixture against a committed baseline.
4. Fails (alerts maintainers) on schema drift.

Tracked as a follow-up in the docs PR's "Known gaps" section.

---

## When this runbook is wrong

If you run through it and the expected output doesn't match: the rule
logic, the schema doc-comment, or this runbook is out of date. File an
issue with the actual output and the Jenkins version
(`http://localhost:8080/api/json` `version` field) so the gap can be
closed.
