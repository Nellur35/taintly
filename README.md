# taintly

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Security scanner for CI/CD pipelines. Reads GitHub Actions, GitLab CI, Jenkins, and AWS CodeBuild buildspec configuration and reports misconfigurations mapped to the [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

- Multi-stage taint analysis with provenance — traces tracked values through environment variables, `$GITHUB_ENV`, step outputs and job outputs, with source locations and propagation paths.

- [Secret-to-request-body review](docs/SECRET_NETWORK_FLOW.md) — traces supported GitHub Actions secrets, GitLab job-token references, Jenkins credential bindings and CodeBuild Secrets Manager variables through bounded shell operations into a `curl` body. Each platform has its own source and execution limits.

- Cross-artifact and cross-workflow input-flow analysis across local composite `action.yml` and reusable-workflow calls. Findings describe configured local source-to-sink candidates; execution, checkout correspondence, token authority and secrets remain review questions.

- Attack-path composition — combines compatible source, execution and privilege evidence in the relevant jobs and steps. Composite findings retain review requirements where runtime prerequisites are unverified.

- Contextual exploitability — uses owning events, guards, declared permissions and credential references to qualify findings. A reference or configured grant does not establish effective runtime access.

- AI / ML category — pickle deserialization, `trust_remote_code=True`, agent-output taint, MCP server hygiene.

Pure Python 3.10+. Zero mandatory runtime dependencies. No telemetry.

Taintly is a static review and CI-gating tool. It reports supported security
patterns and paths in configuration; it does not execute pipelines, establish
that a credential was available, or prove that an attack succeeded.

## Platform support

| Platform | Examples of supported analysis | Important boundary |
|---|---|---|
| GitHub Actions | Expressions, environment and output propagation, local action/workflow calls, permissions and source-to-consumer paths | Available source and supported ownership/condition profiles determine which paths can be joined. |
| GitLab CI | Owned job/script structure, variable consumers, artifact selections and bounded job-token transfers | Includes, variable precedence, runner behavior and external settings can leave questions unresolved. |
| Jenkins | Jenkinsfile structure, credential bindings, Groovy/shell boundaries and bounded HTTP consumers | Plugin/job configuration, checkout identity and unsupported Groovy remain separate evidence requirements. |
| AWS CodeBuild | Buildspec configuration, secret declarations, bounded shell/body transfers and secret build arguments. An optional project snapshot identifies a configured buildspec at a pinned commit. | Runtime overrides, effective IAM and actual execution require separate evidence. |

The platforms have different supported profiles. A rule inventory is not a
measure of equal coverage, precision or recall. See the exact
[secret-transfer profiles](docs/SECRET_NETWORK_FLOW.md),
[structural-reader scope](docs/STRUCTURAL_READER_SCOPE.md) and
[Jenkinsfile-reader scope](docs/JENKINSFILE_READER_SCOPE.md).

**The score is computed against a fixed threat model:** public-OSS deployment, fork PRs reachable, runners shared, secrets repo-scoped, no OIDC-only posture. Whether a flagged pattern is actually exploitable in your deployment depends on context taintly cannot see — your network topology, your contributor policy, your runner posture. The score is a starting point for assessment, not a verdict. For details, see [docs/SCORING.md](docs/SCORING.md).

## Install

Pure stdlib, zero deps — clone and run:

```bash
git clone https://github.com/Nellur35/taintly.git
cd taintly
git checkout --detach 1b93648956b1abf303e8e4abb69900bf241cd10f
python -m taintly /path/to/your/repo
```

No build step, no install step, no PyPI dependency. This pins the scanner source
to the reviewed commit used below; no release tag is assumed.

## Usage

```bash
python -m taintly [path] [options]
```

Common flags:

| Flag | What it does |
|---|---|
| `--score` | Print a 0–100 grade and a debt profile |
| `--platform {github,gitlab,jenkins,codebuild}` | Select one platform instead of automatic discovery |
| `--format {text,json,csv,sarif,html}` | Report format |
| `--fix` / `--fix-dry-run` | Preview or apply supported edits; review the resulting diff |
| `--platform-audit` | API-based posture check (with `--github-repo` or `--gitlab-project`) |
| `--baseline [FILE]` / `--diff [FILE]` | Save a baseline, then later report only new findings |
| `--transitive` | Walk into composite actions and check sub-actions |
| `--guide [RULE_ID]` | List available detailed guides, or open one; other rules include remediation in findings |
| `--token-stdin` | Read API token from stdin |
| `--check-imposter-commits` | Verify pinned action SHAs are reachable in their upstream repo's ref history (opt-in, network) |
| `--respect-zizmor-ignores` | Honor zizmor's inline suppression markers (opt-in) |

Run `python -m taintly --help` for the full list.

### Config file

Drop a `.taintly.yml` at the repo root:

```yaml
version: 1
min-severity: HIGH
fail-on: HIGH
exclude-rules:
  - SEC2-GH-001
ignore:
  - id: SEC3-GH-001
    path: legacy/
```

CLI flags override config values. Preview fixes with `--fix-dry-run` before
applying them. Fixes have provider-specific limits and can require network
access; they do not establish that the pipeline's behavior is preserved.

For enforcement against an untrusted checkout, use a trusted scanner invocation
and an explicit policy from protected state:

```bash
python -m taintly /work/target --config /policy/taintly.yml --no-inline-suppressions --fail-on HIGH
```

`--no-inline-suppressions` disregards source-comment waivers, including opted-in
zizmor markers. Exceptions in the selected config still apply. The scanner,
launcher, policy and any baseline must come from trusted state; an external
pathname alone does not make them trusted. `--strict-config` rejects config rule
exclusions and does not reject `ignore` exceptions. Default behavior is unchanged.

### Inline suppressions

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # taintly: ignore
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # taintly: ignore[SEC4-GH-005]
```

`--respect-zizmor-ignores` extends recognition to zizmor's `# zizmor: ignore` / `# zizmor: ignore[<rule>]` form via a small mapped allowlist; default off.

### Remote scans

```bash
# Set GITHUB_TOKEN or GITLAB_TOKEN through your environment or secret store.
python -m taintly --github-org my-org
python -m taintly --gitlab-group my-group
python -m taintly /path/to/repo --platform jenkins
python -m taintly /path/to/repo --platform codebuild
```

### Saved Jenkins Incrementals publications

```sh
taintly ./saved-source-and-package --format json \
  --jenkins-incrementals-observation observation.json OWNER/REPO PR JENKINS_CHECK
```

This offline profile corroborates one published Incrementals package for
a Jenkins project PR revision. Supply the exact head `Jenkinsfile`, the
observed base version as `base.Jenkinsfile`, and a downloaded JAR or HPI
as `package.zip`. The package limit is 2 MiB. The command reads its
manifest without extracting or executing code.

The trusted `jenkins-incrementals-v1` JSON capture has `repository`,
`pr` (`number`, `head`, `base`, `head_repo`), `source` (`head` and
`base` records with `commit`, `sha256`, and Git `blob`), GitHub
`checks` (`id`, `app` with `id` and `slug`, `name`, `head_sha`,
`conclusion`, `details_url`, `external_id`, `started_at`, `completed_at`,
and `summary` from the publisher check), and the Artifactory File Info
`registry` record. Preserve file size, path, creation time, creation and
modification identities, and the SHA-256 checksum.

The report links the observed registry operation, writing identity,
package bytes, revision and exact target. It also reports the Jenkins PR
job whose check identifies the same revision. The publisher check does
not identify which exact Jenkins invocation supplied the bytes. Loaded
shared libraries, credentials accessible to PR code and wider registry
permissions require independent evidence. Absent or incompatible
evidence returns exit `11`.

### Saved ASF Jenkins Maven snapshot observations

~~~sh
taintly ./saved-jenkins-run --format json \
  --jenkins-maven-snapshot-observation OWNER/REPO PR JENKINS_JOB_URL MAVEN_SNAPSHOT_URL
~~~

This offline profile corroborates one observed Maven snapshot JAR write
from an Apache Jenkins fork PR. The evidence directory contains the exact
loaded Jenkinsfile at `source/Jenkinsfile`, the Jenkins job archive
at `artifact.jar`, the hosted snapshot bytes at `registry-artifact.jar`
and a trusted `snapshot.json` capture. Each JAR is limited to 8 MiB.
The scanner compares bytes without extracting or executing either file.

The `jenkins-asf-maven-snapshot-v1` capture contains an exact GitHub PR
identity (`pull`), Jenkins run, top-level execution flow and stage
(`run`, `flow`, `stage`), the exact Git blob and SHA-256 of the loaded
Jenkinsfile (`source` and `jenkinsfile_loader`), the job-relative
`archive_path` and exact `archive_url`. Preserve the owning checkout
node's `checkout_log` with its URL, selected revision and workspace line.

The `deploy_log` projection carries `url`, `node_id`, `complete`,
`command_line`, `digest_line` and `artifact_install_line` from the
selected shell node. The `registry` projection contains the hosted
Nexus item's `provider_url`, `response` identity, `stored_attributes`
and `stored_properties`. Preserve the stored first-write principal
separately from the account that retrieved the evidence.

The result reports the selected historical run, source line, Maven
operation, exact JAR and recorded Nexus writer. It keeps wider
permissions, production promotion and future fork admission unresolved.
Missing or incompatible evidence returns exit `11`.

For the supported explicit upstream Git checkout variant, also supply
`source/base.Jenkinsfile`, its `upstream_definition` blob record, the
PR's captured base revision, and the trusted GitHub `comparison` with
repository, base, head, merge base, status and revision counts. The
loaded definition must match the base file. The selected Jenkins stage
must show a clean workspace and the bounded command sequence from the
upstream checkout to Maven, with matching job artifact and registry
bytes. The `upstream-checkout-observed` result reports the upstream
commit and the separate PR head. The registry writer remains unresolved
for this result. A later PR checkout or an unsupported intermediate
operation leaves the source unresolved.

### Saved GitLab fork MR artifact observations

```sh
taintly ./saved-gitlab-source --format json \
  --gitlab-mr-artifact-observation observation.json PROJECT PIPELINE JOB
```

This offline profile verifies one successful job artifact upload or one
unstarted manual job in a target-project merged-result pipeline for a fork
MR. Use trusted reduced GitLab API and runner records. Supply the selected
commit's original `.gitlab-ci.yml` and, for an upload, the original
downloaded member as `published-file.bin` (at most 128 KiB). The scanner
compares the original bytes without running the build or inspecting code
inside the artifact.

The `gitlab-mr-artifact-v1` receipt contains a `project` (`id`, `path`),
`mr` (`iid`, `source_project_id`, `target_project_id`, `sha`), `pipeline`
identity (`id`, `project_id`, `sha`, `ref`, `source`), merge commit
(`id`, `parent_ids`) and `source_sha256`. Preserve the job's `id`,
`name`, `status`, `started_at`, `finished_at`, `artifacts`, `web_url`,
and `pipeline` from the pipeline-jobs API. Reduce the selected job log
to timestamped `trace` records for `checkout`, selected literal
`command` entries, and the `upload` status and job number. The
`artifact` retrieval record provides `url`, `path`, `http_status`,
`size`, `sha256`, and `observed_at`. Exclude tokens from the capture.

The profile resolves one literal artifact directory with an owned build
command, including one supported local `extends` template. It can also
corroborate an explicit same-project job guard and manual fallback using
the supplied project IDs and a job with no recorded start. For that
case use empty `trace` and null `artifact`.

For a successful archive observation, include the provider's pipeline
`created_at` and `updated_at` in `job.pipeline`. The recorded job and
its runner events must fit the pipeline and job windows.

An observed archive upload covers only the selected job and artifact
member. Published Pages content, push access to registries, protected
variables, and authorization to play a manual job require separate
evidence. Missing or conflicting evidence returns exit `11`.

For the supported npm profile, add `--gitlab-mr-publish-job JOB_NAME`
to check whether the named npm publication job was absent from that
same completed fork pipeline. The scanner binds the job's local rules,
literal archive selector, configured npm identity audience, and single
local archive producer. A matching archived file is evidence that the
producer created a candidate for the configured selector. It does not
establish the result of that recursive selector at runtime.

Add `publication_inventory` from the pipeline jobs API with
`?per_page=100&include_retried=true` and `publisher_artifact_listing`
from the producer's artifact tree API with `?path=tmp%2Fpackages&per_page=100`.
Each saved page carries its `url`, `page`, `total_pages`, `next_page`,
`total`, and `observed_at`. Inventory `jobs` need names, IDs, status,
pipeline identity and job URLs. The producer row also needs its start
and finish timestamps and `archive_present` from its archive metadata.
Save listing `entries` with `type`, `name`, `path` and `size` for files.
Both pages must be complete. The result preserves the primary job
artifact observation if the requested check returns `unresolved` and
exit `11`. Historical includes, registry authorization, and other
publication routes remain unverified.

### Saved GitHub-to-CodeBuild start observations

```sh
taintly /path/to/git-checkout --format json \
  --codebuild-start-observation observation.json https://github.com/OWNER/REPO RUN JOB
```

This offline profile reads trusted saved evidence for a GitHub
`pull_request_target` job that uses the collaborator permission to decide
whether to launch standalone CodeBuild runs. It reads the caller workflow,
its launcher and selected buildspecs from the exact local Git commits.
The start result is scoped to the named job, AWS initiator session and
returned build IDs. An observed guard stop is scoped to automatic
launches by that job.

The `codebuild-start-v1` capture contains a GitHub `run` and its `job`
from the attempt-scoped jobs API, a `pr` with `number` and `base` and
`head` objects (`repo` and `sha`), `observations`, `build_responses`, and
`build_commands`. The run uses a literal `head_repository` full name.
`observations` are reduced log rows with `run_id`, `job_id`, `attempt`,
`time`, `role`, and `value`. Capture the reported base checkout revision,
assumed-role run session, PR author permission, and returned standalone
build IDs or explicit guard stop. Preserve the step timestamps from the
attempt-scoped job. Enter selected AWS public build responses unchanged
in `build_responses`.

Optional CodeBuild log rows in `build_commands` use the exact `build_id`,
`time`, `kind`, and `command`. They can corroborate `running-command`
entries from a supported buildspec. A `nix-copy-summary` row also carries
the integer `paths` reported by the copy. The CLI keeps the configured S3
destination, observed path count and S3 object-write evidence separate.
The caller role cannot establish the build's own publication permission.
Missing or incompatible start evidence returns exit `11`. The report
retains existing CodeBuild analysis limits.

### Saved GitHub Release publication

```bash
python -m taintly ./saved-source --format json --github-release-observation \
  observation.json owner/repo PRODUCER_RUN RELEASE_RUN
```

Use a trusted offline `github-workflow-run-release-v1` receipt and the exact
publisher workflow at its repository-relative path. The receipt binds the PR
and its selected checkout to the producer job, uploaded artifact ID, digest
and owning upload window. It also records the downstream download of that
artifact ID, the publishing job, the exact release tag and commit, and
GitHub's release and asset metadata.

The supported workflow binds its origin lookup and artifact download to the
triggering run and uses an explicitly configured secret through `GH_TOKEN`
for a SHA-suffixed `gh release create` command. The result identifies the
recorded asset uploader and the configured credential name. The credential
contents, other permissions, archive bytes and later installations remain
unverified. Conflicting or incomplete evidence returns exit 11.

### Saved GitHub Preview observations

When reviewing a completed fork build, use the named operation and both
run IDs to check whether saved evidence links its artifact to a Cloudflare
Workers Preview. The source directory must contain the two original
workflow files at their recorded relative paths.

```sh
taintly ./source-projection --format json \
  --github-preview-observation observation.json OWNER/REPO PRODUCER_RUN CONSUMER_RUN
```

The offline input is a trusted, reduced capture, rather than GitHub
credentials or executable content. The `github-preview-v1` schema uses
the following records:

- `producer` and `consumer`: `id`, `html_url`, `event`, `conclusion`,
  `head_sha`, `head_repo`, `path`, `run_attempt`, and `referenced_workflows`.
- `producer_job` and `consumer_job`: `id`, `name`, `conclusion`, `run_id`,
  `run_attempt`, `head_sha`, timestamps `started_at` and `completed_at`,
  and `steps` with matching names, conclusions, timestamps and `number`.
- `producer_source` and `consumer_source`: `path`, `revision`, and
  `sha256` of the original workflow bytes. Use the checked-out PR merge
  and the consumer workflow revision respectively.
- `pr`: `number`, `head`, `base`, `head_repo`, and `base_repo`.
  `merge`: the checked-out `sha` and ordered `parents`.
- `artifacts`: objects with `id`, `name`, `digest` (prefixed with
  `sha256:`), `run`, `head_sha`, `created_at`, and `size_in_bytes`.
- `steps`: names of the selected steps under `checkout`, `build`,
  `upload`, `download`, and `publish`.
- `receipts`: rows with `run_id`, `job_id`, `attempt`, `time`, `kind`,
  and `value`. Use verified log or other trusted step records and preserve
  their ownership and times. The producer needs `checkout` and
  `upload-id`. The consumer needs `producer-id`, `download-id`,
  `download-digest`, `preview-command`, and `version-url`. Use strings
  for receipt values and ISO 8601 timestamps with timezone offsets.

This profile uses one producer and one consumer, exact audited action pins,
the trigger's run ID, the default download destination, and an adjacent
literal Worker Preview action. `preview-reported` means the selected
records agree about this publication. The report locates the configured
`apiToken` secret reference in the workflow and preserves uncertainty about the principal,
archive contents, and wider permissions. Incompatible or missing evidence
returns `unresolved` and exit `11`. The separate observation mode leaves
ordinary repository scans and finding policy intact.

### Saved GitHub Worker version uploads and fork skips

```sh
taintly ./source-projection --format json \
  --github-version-upload-observation observation.json OWNER/REPO RUN JOB
```

The `github-version-upload-v1` capture uses a single `run`, `job` and
`source` using the records above. Set `source_job` to the literal ID of
the workflow job. For an observed upload, include `pr`, `merge` and
`config_source`, a source identity for the original Wrangler JSON or JSONC
file. Set `steps.build` and `steps.upload` to the selected step names.
The `receipts` use the same ownership fields as Preview observations,
with kinds `checkout`, `workspace`, `version-command`, `reported-worker`
and `worker-version`.

The profile resolves one literal matrix row and requires agreement between
its build workspace, config, reported upload command, named Worker and
version ID. A sibling job or a later route operation cannot supply this
evidence. It reports a version upload under the configured credential and
account bindings. Principal identity, exact published bytes and broader
grants need separate evidence.

For a fork skip, the recorded job must be skipped with empty `steps`
and `receipts`. Use the known fork-head workflow in `source`. The command
reports when that source's guard excludes the fork and the saved job was
observed to skip. The exact source GitHub evaluated and the actual reason
for the skip remain unverified. Missing or incompatible evidence exits `11`.

### CodeBuild project snapshots

With Git installed, you can scan the configured buildspec for a single project
using a complete, trusted `BatchGetProjects` JSON response and a trusted local
checkout. Pass the project ARN and the repository's HTTPS GitHub.com identity
from a trusted source independent of the response:

```bash
python -m taintly /path/to/checkout --format json \
  --codebuild-project-snapshot projects.json \
  arn:aws:codebuild:us-east-1:123456789012:project/example \
  https://github.com/example-org/example-repo
```

The project must name a full commit ID available locally. An omitted or empty
buildspec selector uses `buildspec.yml` at the repository root. A nonempty
selector must be a supported literal repository-relative YAML path. The report
identifies the selected file, commit and SHA-256. Missing or ambiguous selection
produces an incomplete report. Analysis supports Linux containers with an empty
project environment variable list and no fleet or secondary sources.

Keep captures private because project metadata can include plaintext environment
values. This offline mode reads the committed file with Git and supports text
and JSON. It disregards checkout configuration and inline waivers, and applies
no fixes. The report describes project defaults. A build can override them.

### Saved public CodeBuild runs

To analyze the committed buildspec selected for a specific build, use a saved
CodeBuild public console JSON response with one top-level `build` record.
Supply the expected build ID and repository identity from trusted sources:

```bash
python -m taintly /path/to/checkout --format json \
  --codebuild-public-build receipt.json example:01234567-89ab-cdef-0123-456789abcdef \
  https://github.com/example-org/example-repo
```

The offline command uses a completed build's successful `DOWNLOAD_SOURCE`,
explicit repository-relative YAML selector, and full `resolvedSourceVersion`.
The exact commit and buildspec blob must already be available locally. The
same Linux profile, configuration and waiver handling as project snapshots
apply. Use the child build's own response and ID. A batch response, authenticated
`BatchGetBuilds` response, or omitted selector cannot establish the selection.
The report can identify the selected blob and still mark analysis incomplete
when the selected file contains batch orchestration, root YAML merges,
YAML document markers or an unsupported execution context.

For a saved `LINUX_EC2` build with a `pr/<number>` source ref, Taintly
can also identify a literal checkout script passed to Bash `source` or
`.` inside a supported `nix develop` command in a version 0.2 Bash
buildspec. This profile accepts a single leading YAML document marker.
The report identifies the phase, command and matching regular Git tree
entry when available. Runtime resolution depends on the working directory
and filesystem state. The overall scan remains incomplete in this profile.

Keep captures private. Taintly does not authenticate the saved response or
establish the AWS account, command execution, secret delivery or effective IAM.

### Saved CodeBuild-managed S3 ZIP

```bash
python -m taintly ./repo --format json --codebuild-public-s3-observation \
  observation.json arn:aws:codebuild:us-east-1:123456789012:build/example:01234567-89ab-cdef-0123-456789abcdef \
  https://github.com/owner/repo
```

Supply a trusted local `codebuild-managed-s3-v1` JSON receipt and the downloaded
`archive.zip` beside it. The local Git repository must contain the exact PR head
and base objects and have the matching HTTPS origin. The receipt contains:

- `pr`: `number`, `head`, `base`, `repository`, and `fork` (the PR head repository).
- `build`: provider run fields including the selected revision, inline buildspec,
  S3 artifact type, output packaging, status, and phase timestamps.
- `logs`: `build` (the exact build ID), the inline buildspec-selection log row
  under `selection`, and owned command, artifact, and phase rows under `rows`.
- `artifact.provider`: the separately captured artifact directory lookup,
  with `build` and `s3Arn`. `artifact.object`
  contains `build_id`, canonical S3 `url`,
  `http_status`, `archive_sha256` and the S3 response `headers` for length,
  last modification time and CodeBuild build ARN metadata.
- `witness`: the changed `source_path` and its exact ZIP `archive_member`.

The supported profile runs `make dist-src` with a version 0.2 inline buildspec
that selects a root ZIP. The observation checks that the published member
matches the PR head and differs from the base, permitting LF/CRLF conversion
for UTF-8 text. The archive is read with size limits and is never extracted.
This directory profile applies to CodeBuild output files with `NONE` packaging.
It preserves the retrieved object and matched member, returns
`managed-s3-link-unverified` and exits `11`. Binding the exact object to the
build requires independent evidence for that object. A checksum supplied
alongside the directory ARN has unverified scope for the retrieved file.
CodeBuild-packaged archives require a different profile.
The exact service-role session, general IAM permissions and subsequent use
remain unverified. Inconsistent or missing evidence returns exit 11.

### Saved CodeBuild deployment skip

Use a trusted saved CodeBuild build and runner receipt with the matching Git checkout.

```bash
python -m taintly ./repo --format json --codebuild-public-deploy-observation \
  observation.json example:01234567-89ab-cdef-0123-456789abcdef https://github.com/owner/repo
```

The JSON object contains `schema: "codebuild-deploy-observation-v1"`, the public
`build` record, and `trace`. Set `trace.build` to the selected build ID.
Save the three ordered runner rows for the source workspace, the root
`buildspec.yml` selection, and successful source download in `trace.download`.
Save four ordered deployment rows in `trace.deployment`: invocation, emitted
branch and PR source ref, skip message, and the owning successful BUILD phase
completion. Capture the invocation and its output together, from that build.
The supported profile uses a directly declared literal `bash` script in a
version 0.2 buildspec on Linux, with a branch and PR-ref guard around S3
sync and CloudFront invalidation.

The command describes the reported invocation and points to the configured
script and target. Effective AWS permissions, runtime script bytes and the producer of log lines
remain unverified. Missing or conflicting evidence returns exit 11. The
receipt is local and must come from a trusted capture of the selected run.

### Saved CodeBuild webhook filters

The offline webhook assessment takes a trusted project snapshot and an
explicit GitHub PR event. Supply the project selector independently from a
trusted CodeBuild public project URL. It is `public:REGION:SHA256`, where
`SHA256` is the lowercase SHA-256 of the UTF-8 public project alias after
percent-decoding the path segment immediately after `/project/` once.

```bash
python -m taintly --format json --codebuild-webhook-snapshot filters.json \
  public:us-east-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  https://github.com/example-org/example-repo PULL_REQUEST_UPDATED \
  --codebuild-webhook-sender 123456789
```

Save `project_id`, `region`, `observed_at` (UTC with trailing `Z`),
and the public response's `project` fields `name`, `source.type`,
`source.location`, and `webhook.filterGroups`. Preserve all the groups and
their filters, including each filter's `excludeMatchedPattern` boolean. The
CLI reads the saved receipt offline. Exclude delivery URLs and environment
values from the capture. For a specific delivery, pass its GitHub
`sender.id`. Leave the sender absent if that identity is unavailable.

The evaluator models event lists and a bounded numeric subset of sender
patterns. It reports whether every group is excluded, a group matches, or
more information is required. Exit 0 means the filter question was answered,
and exit 11 indicates unresolved evidence. This query does no repository
scan. Its result is limited to the supplied event and captured settings.
Approval, actual execution and effective publication permissions require
separate evidence.

## CI integration

**GitHub Actions** — after checking out the target repository:

```yaml
- uses: Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f  # reviewed commit
  with:
    version: 1b93648956b1abf303e8e4abb69900bf241cd10f
    fail-on: HIGH
```

The `uses:` SHA selects the Action wrapper; `version` independently selects the
installed scanner source. Both examples use immutable commits. Review each
component before updating its pin; they need not share a commit. The Action
sets up Python and installs from GitHub, which needs network access during
setup. Its local configuration scan is offline unless network options are
explicitly enabled.

**GitLab CI** — taintly is hosted on GitHub, so run it as a normal job (there is no GitLab CI *component*):

```yaml
taintly:
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends git ca-certificates
    - python -m pip install "git+https://github.com/Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f"
  script:
    - python -m taintly . --fail-on HIGH
```

This example installs Git and the pinned scanner in a Debian-based job image.
It requires network access during setup; the local scan itself is offline.
For enforcement, keep the scanner, job definition and policy in trusted state
as described above.

### SARIF output

After checking out the target repository:

```yaml
- uses: Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f  # reviewed commit
  with:
    version: 1b93648956b1abf303e8e4abb69900bf241cd10f
    fail-on: HIGH
    upload-sarif: true
    sarif-file: taintly.sarif
- uses: github/codeql-action/upload-sarif@181d5eefc20863364f96762470ba6f862bdef56b  # v3.29.2
  if: ${{ !cancelled() && hashFiles('taintly.sarif') != '' }}
  with:
    sarif_file: taintly.sarif
```

The job needs `contents: read` and `security-events: write`. Upload still runs
after a scan step reports findings, provided a report exists. The Action writes
the file; the separate upload step publishes it to GitHub code scanning.

## Using taintly as a CI gate

Choose a gate according to whether the codebase already has findings.

Pass `--require-files` to a local scan when CI expects at least one pipeline
configuration file. If the selected path and platform yield zero files,
taintly emits a coverage diagnostic and exits with code `11`. With
`--baseline`, this also prevents writing an empty baseline. In the
composite Action, choose a scanner version that includes this flag and pass it
via `extra-args`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH or CRITICAL findings, no configured `--fail-on` threshold reached, and no coverage error |
| `1` | HIGH finding or configured `--fail-on` threshold reached; coverage may also be degraded |
| `2` | CLI argument error OR CRITICAL-severity findings — distinguish via stderr (argparse usage on argument error vs. severity summary on findings) |
| `3` | Initialization or configuration error (rule module failed to load, missing config file, invalid YAML, unknown rule ID) |
| `10` | `--self-test` failed: a positive sample didn't fire, or a negative sample did, or `--integration-test` reported a non-bypass failure |
| `11` | Reported coverage error, unless a severity exit (`1` or `2`) takes precedence — at least one `ENGINE-ERR` finding present (file unreadable, ReDoS cap hit, rule crashed) |
| `12` | `--self-test --mutate` detected a surviving mutation |

The table describes the default severity gate. With `--review-advisory`, the
gate considers findings without the review-needed marker. Review findings stay
in the report and coverage errors still apply. Creating a baseline accepts
existing security findings rather than fixing them. It returns
`0` when creation succeeds without a reported coverage error; incomplete analysis
still returns `11`, even when the snapshot was written.

CI gates should distinguish `0` from non-zero. A non-zero result can mean
findings, a scanner error, or both. Inspect JSON `errors`
as well as the exit code: a HIGH/CRITICAL finding and a coverage error can
coexist. Exit `0` does not prove complete semantic coverage.

When an explicitly selected file resolves outside the repository, taintly
refuses it and reports a coverage error. Jenkins discovery also reports
refused pipeline paths. During a Jenkins controller audit, check failures
are reported as coverage errors alongside findings from successful checks.

### Pattern A — fail-fast for clean codebases

Run on every PR and fail on any HIGH-or-above finding. Use this without a
baseline when the codebase has no accepted findings at the threshold.

```yaml
# .github/workflows/security.yml
on: [pull_request]
jobs:
  taintly:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f  # reviewed commit
        with:
          version: 1b93648956b1abf303e8e4abb69900bf241cd10f
          fail-on: HIGH
```

### Pattern B — diff-only for repos with existing findings

Maintain an agreed baseline for existing findings. Per-PR scans gate on
**new** findings; coverage errors still matter. Reduce the baseline as findings
are fixed.

**One-time setup** (run locally, commit the baseline):

```bash
python -m taintly . --baseline .taintly-baseline.json
git add .taintly-baseline.json
git commit -m "Add taintly baseline"
```

Create the baseline and run `--diff` as separate operations. Baseline status is
written to stderr so requested JSON, SARIF and CSV remain machine-readable.
Recorded analysis errors cannot be accepted away by the baseline or config ignores.

**Per-PR workflow:**

```yaml
on: [pull_request]
jobs:
  taintly-diff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f  # reviewed commit
        with:
          version: 1b93648956b1abf303e8e4abb69900bf241cd10f
          extra-args: --diff .taintly-baseline.json --fail-on HIGH
```

Review the baseline periodically so fixed findings no longer remain accepted.
Generate it from the team's agreed `main` state and protect its integrity;
do not accept a feature branch's replacement baseline as enforcement policy.

### Pattern C — scheduled deep scan

`--check-imposter-commits` checks pinned Action references; `--platform-audit`
inspects repository settings. These are separate scan modes, both requiring
network access. Run them separately on a trusted scheduled workflow.

```yaml
# .github/workflows/taintly-deep-scan.yml
on:
  schedule:
    - cron: '0 6 * * 1'  # Mondays 06:00 UTC
  workflow_dispatch:
jobs:
  deep-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - name: Install a reviewed scanner revision
        run: python -m pip install "git+https://github.com/Nellur35/taintly@1b93648956b1abf303e8e4abb69900bf241cd10f"
      - name: Static scan and pinned-reference checks
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python -m taintly . --check-imposter-commits --fail-on HIGH
      - name: Repository posture audit
        if: ${{ !cancelled() }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAINTLY_REPOSITORY: ${{ github.repository }}
        run: python -m taintly --platform-audit --github-repo "$TAINTLY_REPOSITORY" --fail-on HIGH
```

The second check runs even if the first reports findings. The default token
can inspect only settings its permissions allow; unavailable settings remain
unresolved. Some repository or organization checks require additional read
permissions. Supply a narrowly scoped token through the environment or
`--token-stdin`; do not embed it in the workflow.

Use the offline PR gate and scheduled posture review together when both fit
your project's policy.

### Pre-commit hook (individual contributors)

For local feedback, add this to `.pre-commit-config.yaml`. Install the pinned
scanner into the hook's Python environment first, using the VCS installation
shown above; `language: system` does not install it. The CLI takes one path,
so use `pass_filenames: false` to scan the repository rather than passing a
list of changed files.

```yaml
repos:
  - repo: local
    hooks:
      - id: taintly
        name: taintly (full repo, fail on HIGH)
        entry: python -m taintly .
        language: system
        pass_filenames: false
        args: [--min-severity=HIGH, --no-color]
```

This runs on every commit and fails if a HIGH or CRITICAL finding is reported
in the scanned CI configuration.

### Configuration sources, in priority order

When using taintly in CI, three sources can configure it:

1. **CLI flags** (highest priority), including Action `extra-args` or `with:`.
2. **`.taintly.yml`** at the repository root.
3. **Defaults** — what taintly does without configuration.

Use config for stable policy and CLI flags for run-specific options such as
`--diff`. When evaluating an untrusted checkout, select the trusted policy
explicitly as described above.

## How findings are reported

Findings are grouped into **families** by root cause, not by rule ID. A workflow that pins a reusable workflow to `@main` typically trips three related rules; taintly shows one family with the rule IDs underneath.

Each finding carries three signals:

| Signal | Meaning |
|---|---|
| Severity | Potential impact of the supported risk pattern; not proof of exploitation or a policy violation |
| Confidence | How strongly the supported detector evidence establishes the reported pattern |
| Exploitability | Static estimate of leverage suggested by workflow context; runtime authority may be unknown |

JSON and SARIF also carry decision metadata when available:

`context_notes`, `context_tags`, `triage_needed`, `suppression_reason`,
and `calibration_reason`. Reporters render engine decisions; they do not
recompute risk. Available fields differ between report formats.

The text report shares review details when more than five occurrences of one
rule have identical evidence, remediation and decision metadata. Every occurrence
keeps its file, line and source preview; differing details stay separate. Full
descriptions, multi-line fixes and references remain visible. Use `--verbose` to
repeat the details for every occurrence. This grouping does not change findings,
scores or machine-readable output, and does not prove a shared attack path.

`SEC6-JK-013` text findings also show a short ASCII evidence path from the
credential binding through its owning `sh` command to the `curl` URL query.
The path comes from the rule's structured witness. It does not establish that
the request ran or that the endpoint was unintended, and it does not change
severity, coverage or machine-readable conclusions.

`--score` prints a 0–100 grade based on reported findings and a family profile labelled No finding, Moderate, Weak, or Needs review. **No finding** means only that no finding was emitted for that family; it does not certify complete analysis or prove the family is inapplicable. Candidate anchors cover only some rules and cannot establish a family-wide negative result.

The numeric score deducts for confirmed clusters. Review-needed clusters remain
visible but do not deduct points, so `100` can coexist with pending reviews.
The severity-based CI gate includes review-needed findings by default. To keep
those findings visible while treating them as advisory for the exit code,
pass `--review-advisory`. In the GitHub Action, pass it through `extra-args`
with a scanner version that supports the option.
Findings without the review-needed marker still use the normal severity
threshold. Incomplete coverage still returns 11 when no finding blocks.
Notes from `.taintly-context.yml` add triage information and do not rescore
findings. See [scoring](docs/SCORING.md) and
[deployment context](docs/CONTEXT.md).

JSON `coverage_status` is `incomplete` when an engine diagnostic is present,
and `not_established` otherwise. Absence of an engine error does not establish
that every security question was analyzed. A valid finding can coexist with
unresolved analysis elsewhere.

## Coverage

### Interpreting findings
Taintly analyzes configuration; it does not execute your workflows or prove
that an attack succeeded. Follow the cited source-to-sink path and read the
confidence, `review_needed`, context notes and remediation together. Missing
runtime information remains a review question.

For GitHub Actions, a direct `uses:` reference to a mutable tag or branch is
treated as commit-bound only when the on-disk `.github/workflows/actions.lock`
lists that exact reference for that exact workflow and records a full commit
identifier and repository identity. This supports the documented v0.0.2 and
v0.0.3 direct-reference formats. Missing, malformed, unsupported or mismatched
lockfiles leave the original finding in place. A lockfile binding does not prove
that the action is safe, ran successfully, or that a called reusable workflow's
own dependencies are pinned. See [GitHub's workflow lockfile documentation](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles).

For Jenkins, `LOTP-JK-001` and `LOTP-JK-003` report build or install commands
in a Jenkinsfile that references PR metadata. That combination requires review:
it does not prove that the job builds an untrusted revision or exposes credentials.
Context notes distinguish supported checkout declarations and enclosing credential
bindings from unknown runtime state. Check the job's plugin configuration, source
revision, workspace and credential permissions before treating the candidate as
an exploitable path.

Environment transport, shell source interpolation and interpreter input have
different meanings. Ordinary shell parameter expansion does not recursively
execute syntax stored in a variable. Unquoted expansion can still split words
or expand file globs; `eval`, interpreter code operands and interpreter stdin
can treat values as code. Quoting alone does not establish what an arbitrary
downstream program does with a value.

In the GitHub shell-use profile, a supported quoted default such as
`eval "${TITLE:-fallback}"` uses TITLE as code only when TITLE is set and nonempty. The
finding and chain retain that condition and require review. A supported
fixed-format `printf` argument remains data use; other parameter operators and
unresolved shell bindings remain review questions.

GitLab shallow variable findings use a separate bounded, source-bound profile:
ordinary fixed-format `printf` arguments are data; supported `eval` and literal
interpreter-input forms are conditional code candidates; unsupported shell
syntax, variable precedence, or ownership stays unknown for review. Ordinary
quoted data arguments retain their existing quiet behavior. The composite OIDC
chain requires the exact sink job to declare a token with an audience and
respects supported ordered MR-rule exclusions. Unresolved MR activation remains
qualified for review. This does not
establish runner behavior, variable availability, token issuance, federation,
or cloud permissions.

Static coverage is bounded by supported syntax, available local files and
configured tool profiles. Review incomplete-scan diagnostics and unsupported
cases alongside findings. A clean scan or a high score is not a security
certificate.

<!-- AUTOGEN:summary -->
336 file-based rules and 32 platform-posture checks across GitHub Actions, GitLab CI, Jenkins, and AWS CodeBuild. Includes a dedicated AI / ML category for workflows that load models or run AI coding agents.
<!-- /AUTOGEN:summary -->

<!-- AUTOGEN:coverage -->
| Category | GitHub | GitLab | Jenkins | CodeBuild |
|----------|--------|--------|---------|-----------|
| SEC-1 — Insufficient Flow Control | 6 | 3 | 2 | 0 |
| SEC-2 — Inadequate IAM | 7 | 4 | 3 | 0 |
| SEC-3 — Dependency Chain Abuse | 35 | 19 | 14 | 4 |
| SEC-4 — Poisoned Pipeline Execution | 77 | 30 | 24 | 2 |
| SEC-5 — Insufficient PBAC | 3 | 1 | 2 | 0 |
| SEC-6 — Insufficient Credential Hygiene | 17 | 13 | 14 | 5 |
| SEC-7 — Insecure System Configuration | 4 | 1 | 4 | 0 |
| SEC-8 — Ungoverned 3rd Party Services | 6 | 3 | 5 | 0 |
| SEC-9 — Improper Artifact Integrity | 7 | 5 | 4 | 2 |
| SEC-10 — Insufficient Logging | 5 | 3 | 2 | 0 |
| AI / ML | 0 | 0 | 0 | 0 |
| TAINT — Multi-stage taint flows | 0 | 0 | 0 | 0 |
<!-- /AUTOGEN:coverage -->

The table groups rules by their primary OWASP category. AI and taint rules
mapped into those categories are counted there, so zero in their separate rows
does not mean those analyses are absent. Counts describe the inventory, not
verified coverage of every question or every standard.

The 32 API-based platform-posture checks cover GitHub, GitLab and Jenkins
settings; they do not imply a CodeBuild project/IAM posture audit.

## Network behaviour

Local scans make no network calls. `--fix` calls `git ls-remote` to resolve action tags to commit SHAs. `--platform-audit`, `--github-org`, `--gitlab-group`, `--transitive`, and `--check-imposter-commits` call the GitHub or GitLab API and need a token.

GitLab group-source ingestion and project/group posture requests require an
unambiguous HTTPS `GITLAB_URL` (default `https://gitlab.com`). HTTPS self-hosted
prefixes are supported. In these routes, credentialed redirects stay on that
origin, including its port. A refused recipient before analysis exits `3`.
If group posture checks are refused after source analysis, the report retains
earlier findings and an explicit coverage error: exit `11`, or `1`/`2` when an
existing security finding takes precedence. The refusal cannot become a clean scan.
This confines transport and does not establish that your organization authorized
the configured instance to receive the credential.

Organization/group source scans retain available files and report known fetch
or decoding failures with their source identities. Such gaps remain incomplete
(`11`, unless a security failure takes precedence); a successfully empty
enumeration remains distinct. If GitLab refuses a recipient after acquiring
sources, those sources remain reportable and further acquisition/posture
requests stop. An early refusal with no acquired source still exits `3`.
No scan establishes access to hidden repositories or full semantic coverage;
endpoint-specific not-found behavior and local include limitations still apply.

GitHub organization scans acquire workflow files. The agent instruction file
inventory and content rules (`AI-GH-036` and `AI-GH-039`) report incomplete
coverage when repository file evidence is unavailable. A local checkout of the
repository supplies that evidence for those rules.

## Documentation

- [Scoring and review status](docs/SCORING.md)
- [Deployment context and triage](docs/CONTEXT.md)
- [Secret-derived HTTP transfers: exact supported profiles](docs/SECRET_NETWORK_FLOW.md)
- [Expression analysis](docs/EXPRESSION_ANALYSIS.md)
- [Structural-reader limits](docs/STRUCTURAL_READER_SCOPE.md)
- [Jenkinsfile-reader limits](docs/JENKINSFILE_READER_SCOPE.md)

## Requirements

Python 3.10+. No third-party dependencies.

## License

MIT
