# Saved CI/CD observations

These commands review saved records for specific providers and operations. Each profile lists the evidence it accepts and the questions that remain open. Start with the [configuration scanner](../README.md) for a local repository scan.

- [Saved Jenkins Incrementals publications](#saved-jenkins-incrementals-publications)
- [Saved ASF Jenkins Maven snapshot observations](#saved-asf-jenkins-maven-snapshot-observations)
- [Saved GitLab fork MR artifact observations](#saved-gitlab-fork-mr-artifact-observations)
- [Saved GitLab merge-request image pushes](#saved-gitlab-merge-request-image-pushes)
- [Saved GitHub-to-CodeBuild start observations](#saved-github-to-codebuild-start-observations)
- [Saved GitHub Release publication](#saved-github-release-publication)
- [Saved GitHub draft-release request](#saved-github-draft-release-request)
- [Saved GitHub Preview observations](#saved-github-preview-observations)
- [Saved GitHub Pages publication](#saved-github-pages-publication)
- [Saved GitHub Worker version uploads and fork skips](#saved-github-worker-version-uploads-and-fork-skips)
- [CodeBuild project snapshots](#codebuild-project-snapshots)
- [Saved public CodeBuild runs](#saved-public-codebuild-runs)
- [Saved direct CodeBuild S3 request](#saved-direct-codebuild-s3-request)
- [Saved CodeBuild-managed S3 ZIP](#saved-codebuild-managed-s3-zip)
- [Saved CodeBuild deployment skip](#saved-codebuild-deployment-skip)
- [Saved CodeBuild webhook filters](#saved-codebuild-webhook-filters)

## Saved Jenkins Incrementals publications

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
modification identities, the SHA-256 checksum and `lastUpdated` when
available. A reported upload after the publication check leaves the
historical attribution unresolved. Older captures without `lastUpdated`
leave subsequent uploads unverified.

For plugin HPIs, supported Maven groups are `org.jenkins-ci.plugins`,
`org.jenkins-ci.plugins.workflow` and `io.jenkins.plugins`. The plugin
publisher check's target and its download link must identify the exact
directory of the saved registry object. A Jenkins Core check can list
several modules.

For a plugin whose Maven coordinate differs from the conventional
repository name or group, also save the head `pom.xml` and the base version
as `base.pom.xml`. Add `coordinate_source` to the receipt with `head` and
`base` records containing `commit`, `sha256`, Git `blob`, and the exact
GitHub file `url` at that commit. The files must be identical and declare
a literal artifact ID, `hpi` packaging and a literal group ID in the
project or parent. The HPI manifest's group ID, artifact ID and short name
must match that coordinate and the selected registry path. Changed POMs,
dynamic coordinates and module selection are outside this profile.

The report links the observed registry operation, writing identity,
package bytes, revision and exact target. It also reports the Jenkins PR
job whose check identifies the same revision. The publisher check does
not identify which exact Jenkins invocation supplied the bytes. Loaded
shared libraries, credentials accessible to PR code and wider registry
permissions require independent evidence. Absent or incompatible
evidence returns exit `11`.

## Saved ASF Jenkins Maven snapshot observations

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

When the collector retained the complete trusted Maven deployment-node
log, it may include it as `maven-node.log` (up to 2 MiB) and set
`deploy_log.credential_log_sha256` to the original file's SHA-256. Keep
the evidence directory private if it contains sensitive log data. The
scanner checks the selected command, artifact path and digest lines in
that log before reporting the supported Maven origin-scope warning and
its settings server ID. This is the authentication selection reported
by Maven. The actual Jenkins credential reference and wider registry
permissions remain unresolved. A missing or incompatible optional log
does not change the independently established publication result.
When a record provides the matching Jenkins archive without a Nexus
receipt, the same log can corroborate the Maven authentication selection.
Nexus storage and writer attribution remain unresolved.

For optional workspace ownership evidence, retain the complete trusted
controller response at the owning job's `logText/progressiveHtml?start=0`
as `maven-workspace-console.html` (up to 4 MiB). The capture's
`workspace_console` sets `url` to that exact response URL, `sha256` to
the saved bytes' SHA-256, and `complete` to true after the collector
checks that there is no further log output. Keep this file private.
The observer follows the controller's enclosing node identifiers from
checkout and deployment to their allocation. It reports the assigned
agent and workspace only when the selected records agree. A complete
matching log that shows different allocations leaves source-to-write
attribution unresolved. A missing or incompatible optional log leaves
the allocation unresolved. The assigned workspace alone does not
establish the process working directory or executable identity.

The result reports the selected historical run, source line, Maven
operation, exact JAR and recorded Nexus writer. It keeps wider
permissions, production promotion and future fork admission unresolved.
The selected checkout and deploy nodes must be adjacent or connected by
the reviewed Maven preparation sequence within the same recorded stage.
Conflicting revisions and unsupported intervening steps leave this
source-to-publication relationship unresolved.
If the fork checkout, Maven command and exact snapshot bytes match but
the stored record cannot identify the original writer, the result reports
the checkout and matching object while leaving authority unresolved.
Missing or incompatible evidence and unresolved writer attribution return
exit `11`.

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

If a failed parent run has an owned, successful checkout and Maven
node but the original Nexus record is missing, supply `registry: null`
and the snapshot alias matching the archived JAR. The result preserves
the checked-out commit and verified Jenkins artifact. Registry write
and writer remain unresolved.

For a same-repository FileVault Package Maven Plugin PR with the reviewed
shared library, use the same command with the Nexus snapshots repository URL
as the last argument and `jenkins-asf-filevault-exclusion-v1` in
`snapshot.json`. Supply the `pull` and completed `run` records with Git
`BuildData`, the complete run `graph`, the owning stage and its flow nodes,
and the scoped `checkout_log` and `maven_log`. Include the controller's
branch and library log records and `jenkinsfile_checkout` with the exact
loaded merge revision, parents, and loader line. Save the loaded Jenkinsfile
with its `source` digest and Git blob record and the reviewed library files
under `source/library/` at their original paths. Those files are
`vars/vaultPipeline.groovy`, `vars/vaultStageBuild.groovy`,
`vars/vaultStageDeploy.groovy`, and
`src/org/apache/jackrabbit/vault/PipelineSupport.groovy`.

The `remote-publisher-excluded` result distinguishes the observed
workspace-local Maven deployment from the configured remote Wagon stage.
It requires the original branch guard, a complete stage inventory, and
matching command and workspace evidence. It leaves Nexus permissions and
other publication paths unresolved. The review action identifies which
Maven server binding to verify on the trusted publishing executor.

For the pinned Apache Shiro matrix definition, use
`jenkins-asf-matrix-maven-guard-v1` in `snapshot.json`. Supply the GitHub PR
and merge-parent records, the exact loaded `.jenkins.groovy` as
`source/pipeline.groovy` with its `source` blob record, and the trusted
`fork` run and graph with owning stage details, controller markers and
scoped checkout logs. The last argument is the hosted snapshots repository
URL. This offline profile accepts saved records from a trusted collector.
Receipt hashes help retain provenance and do not authenticate the supplied
controller records.

`remote-matrix-publisher-skipped` reports that all three recorded `Deploy`
instances were skipped by their conditions after the recorded build and
stash restores. It identifies the change-request guard in the exact loaded
definition. Skips caused by an earlier build failure are unresolved for
this profile. Stash contents, registry authority and other publication
paths remain unresolved. If included, a `comparison` section can show an
owned deploy invocation from the same definition on `main`. A separate
same-window Nexus object record still leaves run-to-object attribution
unverified.

For an external Apache Sling pull request using the reviewed shared library,
the same command accepts a trusted `jenkins-asf-sling-shared-guard-v1` capture.
Save the GitHub PR identity as `pull`, the Jenkins `run` with Git BuildData,
the complete `graph`, the selected Maven verify `stage`, and owned
`console`, `checkout` and `maven` log projections. Put the exact loaded
`Jenkinsfile` and the reviewed shared library file at `source/Jenkinsfile`
and `source/library.groovy`. The `source` record identifies the loaded
Jenkinsfile commit, blob and SHA-256. The controller must identify the pinned
library revision and report the branch restriction. Select the Nexus
snapshots repository URL as the last argument.

`remote-shared-library-publisher-excluded` means this fork build reached the
reviewed Maven verify command and the library excluded its named remote
publisher. It does not determine whether Nexus would authorize a request
from the PR executor or whether another step could publish. The Jenkins checkout
revision may be a reported merge of the PR head and historical base.
Missing or conflicting evidence keeps the observation unresolved.

## Saved GitLab fork MR artifact observations

```sh
taintly ./saved-gitlab-source --format json \
  --gitlab-mr-artifact-observation observation.json PROJECT PIPELINE JOB
```

This offline profile verifies one observed job artifact upload or one
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

For the verified GitLab.com Docker Machine runner image, an optional
`archive_runner_evidence` object corroborates the native uploader's
job token for this archive POST. Supply the trusted redacted log's
`trace_url`, `trace_sha256`, `executor`, `runner_revision`,
`helper_index`, `helper_config`, `checkout_directory`, and owning
`job`, `pipeline`, and `revision`. Supply `runner_line`, `helper_line`,
`archive_start_line`, `archive_line`, `archive_end_line`,
`archive_start_time`, `archive_time`, `archive_end_time`, and the archive
response's `correlation_id`. Use the originating archive stage and its
response, with no token fields. The profile is limited to Runner
`7a0f126423ab4aefa71be5cda32668e29bc59b2d` and the compatible verified
helper image. Actual process bytes and mounts, the token instance and
permissions for other operations require separate evidence. An invalid
optional record reports unresolved with exit 11 while preserving any
already corroborated archive. Omitting the object preserves the
existing outcome.

For an archive uploaded after script failure, supply `failed_archive`
alongside the same source file, downloaded member and `artifact` record.
Use matching `created_at` and `updated_at` values in `pipeline` and
`job.pipeline`. Include `failure_reason` in `job` and the archive's
`file_format`. The `failed_archive` object contains:

- `historical_pipeline` with the pipeline JSON `url`, `project`, `pipeline`,
  `mr`, `revision`, `source_sha`, `target_sha`, `event` (`merged_result`), and
  `sha256` of the response. Use the historical fork head the pipeline recorded.
- `fork_commit` with the source `project`, commit `sha` and `receipt_sha256`
  from its repository commit response.
- `log` with `job`, the owning job `/raw` URL, full log `sha256`, and `rows`.
  Retain the source section start, detached checkout, source section end,
  script start, one supported literal `yarn` or Gradle command, script end,
  failure-upload start, the runner's file or directory match, archive HTTP
  201, failure-upload end, and final job failure, in order. Every row keeps
  `time`, redacted `value`, and the SHA-256 of `time`, one space, and `value`.
  Strip terminal escapes and omit token fields. Keep the runner's stream prefixes.
  Each runner section epoch must match the second recorded in its line timestamp.

`job-artifact-uploaded-after-failure` identifies an archive accepted by
the coordinator and a member retrieved for that job. The command comes
from the owned runner script section. Effective configuration and the
effect of the fork code on the member's bytes remain unverified.

For a canceled fork merge-train job, use `canceled_archive` instead of
`failed_archive`. Supply the same historical pipeline and fork commit
fields with `event` set to `merge_train`. Retain eight ordered runner
rows in `log`: source section start, detached checkout, source section
end, script section start and end, the start of the success or failure
upload section, the job's archive HTTP 201 response with its correlation
ID, and the matching upload section end. Use the provider's canceled
job, canceled pipeline and ZIP archive inventory. The result
`job-artifact-accepted-canceled-job` establishes the runner-reported
archive acceptance and preserves the final job status. Archive bytes,
later availability and wider permissions require separate evidence.

For a canceled job in a target project's detached fork MR pipeline on a
saved GitLab origin, keep schema `gitlab-target-project-head-archive-v1`
and pass `--gitlab-artifact-origin https://gitlab.example.org`. This
option requires the exact HTTPS origin, with no path or credentials.
The observer runs offline and checks the saved project, MR, pipeline,
job, trace and fork source URLs against that origin. Preserve canonical
project path capitalization.

For an explicitly selected origin, schema `gitlab-fork-project-archive-v1`
also accepts a failed fork-owned pipeline and job at the recorded MR head.
The job must report `script_failure`, one ZIP archive entry, and the eight
ordered rows through its failure-phase archive response, with the runner's
ULID correlation ID. When adjoining section end and start rows share a
timestamp, preserve strictly increasing original trace row positions as
`line` on all eight rows. Leave `rows_format` absent for this timestamped
trace. Supply the source file record from the fork project at the exact revision, as well as the matching local `.gitlab-ci.yml`. The
observer reports a recorded acceptance in the fork project. Exact uploader
credentials, artifact bytes, and permissions in the target project require
separate evidence.

For the canceled target-project profile, add the trusted historical pipeline
view projection and its digest
under `historical_pipeline`, as for the detached profile below. Use the
target project's MR head ref and the historical revision reported by
that pipeline. Preserve the ZIP entry and the eight ordered trace rows
through the HTTP 201 failure-phase archive response. A current MR head
that has advanced can coexist with an older checkout. The output
`target-project-head-archive-accepted-canceled-job` retains both the
recorded cancellation and the accepted upload. Review the historical
job as the producer if a downstream step uses the archive.

For a successful job or a script failure in a merge-request pipeline running
in the fork's own project, use schema `gitlab-fork-project-archive-v1`.
Pass the fork's project ID to the same command. Supply `fork`, `target`, `mr`, `pipeline`, `job`,
`commit`, `mr_pipeline`, `source_sha256` and `log`. The project records
use `id`, `path_with_namespace` and `web_url`. The fork's `forked_from`
record uses the target's `id` and `path_with_namespace`. `mr_pipeline` is
the selected entry in GitLab's target MR pipeline list. Set the fork's
current MR head, checkout revision and source branch from provider records.
If the MR head has advanced, also supply `historical_pipeline` from the
fork pipeline's `.json` view. Include `url`, `sha256` of the saved response,
numeric `project` and `pipeline`, `mr_url`, `event` (`detached`),
`source`, `ref`, `revision` and `created_at`. The view must agree with
the independently saved MR pipeline membership and checkout.
Supply `.gitlab-ci.yml` at that exact commit. Preserve the eight runner
rows above, with the upload section matching the job outcome and its owned
HTTP 201. A successful job requires the success-upload section and no
failure reason. A script failure requires the failure-upload section.
The result `fork-project-archive-upload-observed` names the fork's job
archive. To corroborate a saved download, supply `published-archive.zip`
in the source projection and an optional `archive_download` record with
`job`, the original job download `url`, `observed_at`, `bytes`, `sha256`
and `responses`. Use a UTC timestamp ending in `Z`. Record the host and
HTTP status for each response. The profile accepts a direct GitLab.com 200
or its 302 to the GitLab artifact
CDN followed by 200. Keep signed URLs and request credentials out of the
receipt. The ZIP size must match the job inventory and stay within
5,000,000 bytes. An incompatible receipt leaves the upload observation
visible and exits 11. A verified download establishes byte identity at
the recorded time. Content provenance, present access and authority in
the MR target project require separate evidence.

For a successful MR job that runs in the target project and checks out the
fork head directly, use `gitlab-target-project-head-archive-v1`. Pass the
target project ID. Supply the same project, MR membership, commit, job,
source and trace records, with these requirements.

- The selected pipeline and job belong to the target project. The pipeline
  ref is `refs/merge-requests/IID/head` and its SHA matches the recorded
  current MR head, the fork commit and the job's `commit.id`.
- The source checkout contains the fork's exact `.gitlab-ci.yml`. Supply
  `source_file` with the saved fork file response's `file_path`,
  `commit_id` and `content_sha256`, plus the canonical API URL
  `https://gitlab.com/api/v4/projects/FORK_ID/repository/files/.gitlab-ci.yml?ref=SHA`.
- Both pipeline and job succeeded. The ordered trace must show checkout
  of that head, the script section, and the owning job's HTTP 201 in the
  success-upload section. This profile accepts the archive receipt alone
  or with the same optional download evidence and byte limit as above.
- Optional `archive_runner_evidence` uses the verified runner and helper
  profile below. The saved checkout directory must name the target project
  under `/builds/`. The trace digest, upload lines, timestamps and correlation
  ID must match this job's recorded upload. Incomplete or mismatched runner
  evidence leaves the credential class unresolved with exit 11 and retains
  the accepted archive.

`target-project-head-archive-upload-observed` identifies the accepted archive for
that target job. Exact credential, effective configuration, file content
provenance and deployment require separate evidence. A stale MR head,
failed admission with no job, mismatched job or missing 201 stays unresolved.
A missing or mismatched optional download does not undo the observed
upload. An explicitly supplied incompatible download exits 11.

To compare one Go coverage panel in that verified ZIP with its source, add
`archive_member_origin` with `format: go-cover-html-v1`, the HTML `member`,
Go file `path`, package name `package`, and `source` and `parent` file
records. Each record retains the exact GitLab repository file API `url`,
`commit`, `file_path`, `size`, `sha256` and `blob_id`. Supply the
original file bytes as `coverage-source.go` and `coverage-parent.go`
alongside `.gitlab-ci.yml`, and retain the unique parent in
`commit.parent_ids`. The CLI reports `fork-source-display-matched` when
the panel matches the fork file's display and differs from its parent's.
An unresolved comparison preserves the archive upload observation and
returns exit `11`. The panel comparison establishes displayed content.
Execution, the generator and other member origins require their own evidence.

An observed archive upload covers only the selected job and artifact
member. Published Pages content, push access to registries, protected
variables, and authorization to play a manual job require separate
evidence. The review action identifies archive audience and downstream
deployment checks. Missing or conflicting evidence returns exit `11`.

To correlate an observed archive with a parallel Pages preview, add
`pages_preview` from the same job's GitLab `/-/jobs/JOB.json` view.
Supply `url`, response `sha256`, `observed_at`, `job_id`, `job_name`,
and `action`, `status`, and `environment` from `deployment_status`.
Keep the environment's `id`, `name`, `state`, `external_url` and
`last_deployment`. The last deployment retains `id`, `iid`, `sha`,
`ref` (the ref name), `status`, `created_at`, `deployed_at`, `is_last`,
`web_path`, and `deployable` (`name` and `build_path`). Omit names, email
addresses and credential data. To request the recorded deployment account,
include an optional `account` under `pages_preview`. Project the `job_id`,
`pipeline_id`, `sha`, `deployment_id`, `job_user_id` and
`deployment_user_id` from the same trusted job view. The account IDs must
be numeric and match. Disagreement or missing data in an included account
projection returns exit `11` and preserves the separately verified
deployment. The account identifies this deployment and job only.

The supported source declares a default-directory Pages preview with
`$CI_COMMIT_REF_SLUG` and an environment URL of `$CI_PAGES_URL`. The
environment starts by default or explicitly. A local parent may supply
the build and archive, with Pages and environment settings owned by the
job. The selected index member is `public/index.html`. The job view must bind
the successful deployment to the same job and merged-result revision.
The result retains the environment state recorded at capture, including
a stopped preview. Serving the file at that URL and access policy require
separate evidence. When the preview evidence is unresolved, exit `11`
preserves the independently corroborated archive result.

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

## Saved GitLab merge-request image pushes

The same `--gitlab-mr-artifact-observation` command also reads
`gitlab-mr-branch-image-v1` receipts. This profile covers a same-project
merge train or merged-result pipeline with a job-local Dockerfile and
an image tag derived from `CI_COMMIT_REF_NAME`. Supply the original
`.gitlab-ci.yml` and configured Dockerfile from the exact checkout.
The source must have an owned plain three-command script and a job rule
sequence. A definite local exclusion is incompatible with the saved run.

- Use the same `project`, `mr`, `pipeline`, `job` and `merge` identities
  as the artifact mode. Include the MR `source_branch` and the job's
  ref, commit ID, start, finish and terminal status. Preserve
  `created_at` and `updated_at` in the pipeline and job's pipeline record.
  The `historical_view` includes its owning pipeline JSON URL, response
  status and SHA-256, pipeline ID, source, event type, ref, revision,
  source SHA and target SHA.
- Provide source snapshots under `executed`, `base`, `merge_input`
  and `mr_historical_head`. Each records its `revision` and `files` records
  for the workflow and Dockerfile, including raw API URL, status and
  SHA-256 for retrieved bytes. A recorded base Dockerfile 404 can
  establish a newly introduced Dockerfile if the base workflow is available.
- Retain the runner log URL, response status and SHA-256, job ID,
  source/script/cleanup
  section boundaries, and the eight ordered checkout, login, build,
  push and completion rows. Sections contain `line`, epoch `seconds`,
  `stage` and `event` (`start` or `end`). Rows contain `line`, `row`
  (runner text with terminal color escapes stripped), and its `sha256`.
  Supply every logged shell command in the script section under
  `script_commands`. Omit credentials and unrelated log rows.
- To corroborate the push, provide registry `tag` and `digest` manifest
  reads from the exact repository. Each includes `url`, `reference`,
  `status`, `time`, `server_digest`, `calculated_digest`,
  `digest_matches` and `bytes`. Save the original response bytes
  as `image-manifest.json`.

Exit 0 with `registry-image-push-observed` means the selected job reported
a push and both saved manifest reads and the local manifest bytes match
its digest. `registry-image-push-reported` (exit 11) retains the push
reported by the runner when the registry match remains unverified.
The terminal job state is reported separately. This evidence does not
establish an exclusive writer, the exact runtime token or wider grants.
Ordinary source scans continue to use their source-only evidence.

## Saved GitHub-to-CodeBuild start observations

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

For a reported start, the reviewed launcher must explicitly select the
standalone project and region and pass the supplied PR ref to the AWS CLI.
The report identifies this request from the pinned executable source.
A saved provider build ARN, when present, must agree with the request
and configured caller account. Public responses without that ARN leave
the provider-side account and region unverified.

Optional CodeBuild log rows in `build_commands` use the exact `build_id`,
`time`, `kind`, and `command`. They can corroborate `running-command`
entries from a supported buildspec. A `nix-copy-summary` row also carries
the integer `paths` reported by the copy. The CLI keeps the configured S3
destination, observed path count and S3 object-write evidence separate.
If cache-copy text appears in a mapping under `commands`, the build reports
`publication_analysis_limit` and omits the unsupported destination. The saved
launch result still applies to the reported start.
The caller role cannot establish the build's own publication permission.
Missing or incompatible start evidence returns exit `11`. The report
retains existing CodeBuild analysis limits.

## Saved GitHub Release publication

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
recorded asset uploader and the source line of the configured credential.
Its value, other permissions, archive bytes and later installations remain
unverified. The review action identifies producer and asset checks to
perform before publishing previews. Conflicting or incomplete evidence
returns exit 11.

For a failed publisher that completed the supported Git tag-push step,
the same command accepts a `github-workflow-run-tag-push-v1` receipt.
Supply the same producer, consumer and publisher source records. The
`tag_push` record binds `run`, `job` and `attempt` to the adjacent
`remote` and `new_tag` log rows, each with `row`, `time` and `value`.
Record the literal remote URL and the SHA-suffixed tag reported as newly
created. Preserve the log group headers of the push and immediately
following release-cleanup step as `push_start` and `next_start`, using
the same row shape and keeping fractional timestamps.
Include the GitHub Git ref API record as `ref` and its read time
as `retrieved_at`. The result covers the exact source tag and commit.
Authentication identity, release assets and downstream use require
separate evidence.

### Producer archive credential

The artifact-to-release, tag-push and Preview receipts accept an optional
top-level `producer_artifact_authority` record from the trusted producer log.
Save the `run`, `attempt`, `job` and `step`, plus the runner's
`runner_version` and the upload action's requested `action` and resolved
`action_revision`. Save the runner's full `repository_token_permissions`
map and its `permissions_line`, the resolved action's `action_line`, and the
archive `artifact_id` and `sha256` (including the prefix). Preserve
`digest_line`, `digest_at`, `finalize_line` and `finalized_at` from the same
upload step, and `log_sha256` for the original producer log.

The profile checks a read-only repository permission banner and the
successful archive finalization against the same job, action and artifact.
The reviewed upload builds use the runner's separate run artifact service
credential. The product reports the credential class without its value
and keeps downstream release or Preview authority separate. A conflicting
optional record preserves the independently supported publication result
and returns exit 11. Omit token values and signed URLs from the capture.

The same command also accepts a trusted `github-signed-release-v1`
receipt for a bounded same-repository PR recipe with separate build,
reusable signing, and publishing jobs. Preserve their source files under
`producer/`, `signer/`, and `publisher/`, each with its original workflow
path, plus the downloaded `published-SHA256SUMS.txt` at the root. Supply the
producer and publisher run records, the three job records, the PR and its
producer merge record, and the original and signed archive inventories.
The reduced trace records identify the owning job, attempt and step, the
archive transfers, and the signer-reported member digest. The hosted
release records must identify the checksum manifest and the exact APK.

This profile verifies reviewed command bodies, the configured App-token
target, the recorded uploader, and agreement across the three digest
records. APK bytes, signature validity, signing approval and broader
App permissions require separate evidence.

## Saved GitHub draft-release request

```bash
python -m taintly ./saved-source --format json --github-release-request-observation \
  observation.json owner/repo RUN JOB
```

Use a trusted offline `github-draft-release-request-v1` receipt and the
workflow from the recorded fork head at its original relative path.
Supply the `repository`, attempt-specific `run`, `job`, `check_run`,
and a `pr` containing `number`, `base_repository`, `head_repository`
and `head_sha`. Save repository names as full names in `run.head_repository`
and the PR fields. Use `check_run.app` for the GitHub App slug and
`check_run.check_suite_id` for the run's check suite ID. The `source`
record holds the workflow `path`, fork-head `revision` and `sha256`.

Use the owning check run's request/response annotation to build the
`denial` record. Include `check_run`, `run`, `attempt`, `action`,
`annotation_sha256`, `action_annotation_sha256`, `method`, `url`, `target_commitish`, `draft`,
`status`, `message`, `request_id`, `response_at` and `accepted_permissions`.
Use the action annotation from the same check to corroborate the action
identity and record its message hash.
Keep the response timestamp in ISO 8601 with its offset and retain the
GitHub permissions header exactly. Omit credentials, request authorization
headers and unrelated event data.

The supported profile uses one Release Drafter v6 step with a configured
job token in a direct fork PR run. Match the exact action ref in the
workflow and annotation, including any v6 patch version. A single leading
YAML document marker and literal job and step names are supported. The
recorded job name must identify the sole job. A job condition comparing
`github.repository` with the literal target repository is supported.
The comparison describes the repository running the workflow. It can
match a run triggered by an external fork. The requested Contents
permission comes from that job's permission map when present, or the
workflow's map when the job has none. Exit 0 with `draft-release-create-denied`
means the saved GitHub response corroborates a 403 for that draft request,
even when GitHub reports a successful job. Missing or incompatible evidence
returns exit 11. Exact merged workflow bytes, runtime token identity,
the effective policy and release asset publication remain unverified.

For the direct single-step fork profile, include `effective_permission_log`
to corroborate the runner's recorded `Contents: read` for that job. Supply
the owning `run`, `job`, `attempt`, `log_sha256`, `response_request_id` and
`response_block_sha256`, plus the six ordered `rows` with their original
timestamp, line content and SHA-256. Save the job log digest in
`custody.job_log_sha256`. Retain the permission group's opening line,
`Contents: read`, and closing line, then the recorded action download,
action invocation, and error beginning the block containing the same
request ID as the check annotation. The response block hash refers to
that block in the trusted log, with line endings normalized to LF. Omit
authorization headers and complete error bodies. A literal pin to the
reviewed Release Drafter v6.1.0 also supports `disable-autolabeler: false`.
The reported grant describes the owning job's token setup.

The draft-request command also supports one explicit reusable invocation in a
direct external fork PR. The saved job name identifies the caller and called
jobs as `caller / called`. The fork-head source must have one literal
branch-based workflow call and one named secret bound to `secrets.GITHUB_TOKEN`.
Provide the run's single selected `referenced_workflows` entry with its
`path`, `ref` and commit `sha`. Supply `reusable_source` with
`repository`, `path`, `revision` and `sha256`, keeping the called workflow
at `reusable/<revision>/<path>` relative to the source projection. In the
called workflow the same named secret is a required `workflow_call` input and
feeds the only Release Drafter action's `GITHUB_TOKEN` environment entry.
This profile covers inherited grants and retains the existing exact owned
request checks. It records the source locations of the configured handoff
and the observed 403.
Runtime token identity, effective grant, resolved action bytes and exact
caller merge bytes require separate evidence.

For the pinned Release Drafter v7.7.0 checkout profile, the same command
accepts an owned job-log projection in `verified_log`. The fork trigger
must declare the usual opened, reopened and synchronize events without
branch or path filters. Use the workflow
bytes from the observed synthetic PR merge. Include `run`, `job`, `attempt`,
`log_sha256`, `merge_commit`, `base_commit`, `merge_parents`,
`merge_record_sha256`, `annotation_list_sha256`, `action_commit`, an owned `failure_annotation` (check ID, level, and message), and the
bounded `rows` projection. Retain these markers in order:

1. The GitHub token-permissions group with `Contents: read`, then the
   pinned action download in job setup.
2. The checkout action group and checked-out merge commit in the checkout step.
3. The Release Drafter step's start, config fetched from the owning PR merge
   ref, absence of an existing draft, target, draft flag, create branch and
   error identifying the create-release operation.
4. The checkout post-job and runner cleanup markers.

Use the same timestamp and per-line hash format described below. Supply the
matching run, actor, check, custody hashes, job steps and fork identity. Exit 0 with
`draft-release-create-rejection-reported` means the job log supplies the
effective Contents grant and the action's rejection. The transport status
is unknown and shown as `null` in JSON. An update, ambiguous permission
group or unrelated log does not answer this question.

The same command accepts a direct repository push with a single Release Drafter
`@v7` step when the saved setup log identifies action commit
`978bb0b30c5ee8cdd332ced253758157150d43f0`. Supply the matching job `steps`, run
`head_branch`, the workflow from the push revision, and a `creation` record
with `run`, `job`, `attempt`, `log_sha256`, and `rows`. Keep the action download
line from setup, the action's `##[group]Run` marker, the logged tag, target
branch, `draft: true`, `Creating new release...` and `Release created!` lines,
and the runner's `Cleaning up orphan processes` marker, in that order.
Each row contains `time`, `value`, and the `sha256` of the original line
without its newline. Preserve the spaces between the timestamp and message
and within the message when calculating the hash.

To supply the effective job grant, add `creation.effective_permission_rows`
with three `time`, `value` and `sha256` records from the same job log.
Save the opening `GITHUB_TOKEN Permissions` group, its `Contents: write`
row and the closing group marker. These rows must belong to the setup
step and precede the action download. The result reports the grant
separately from the workflow's requested permission.

The push profile accepts the workflow's literal `permissions.contents`
when the owning job has no `permissions` declaration. If the job
declares permissions, use its own `contents` setting. The create log
normally reports a numeric three-part tag, optionally prefixed by lowercase `v`.

A workflow may also declare `pull_request` alongside the literal push.
When neither the workflow nor the job declares permissions, the saved
setup grant is required. In that case the reported permission request
is `null`. The pinned action uses its default `github.token` input.
The receipt must still bind the step's `GITHUB_TOKEN` environment entry
to `secrets.GITHUB_TOKEN`. A blank tag field is reported as `null`.

Exit 0 with `draft-release-create-reported` means that the saved action log
reports completion after the create call returned for the requested draft.
The raw HTTP status, returned release ID, effective token identity, later
publication and any fork's ability to write remain unverified. A successful
job with an update, dry run or missing completion stays unresolved for this
creation question.

### Saved GitHub Release metadata PATCH comparison

Use the same observation command with schema
`github-release-patch-comparison-v1` to compare a narrow series of reported
metadata updates in one successful repository push job. Supply the direct
run and job records, the exact workflow source projection, and the public
job log saved as `release-patch.log` in the source projection. Use this mode
only with trusted saved records. It reads evidence offline and performs no
requests to the provider.

Supply `patch_log.url`, `sha256` of the saved log, `last_source_line` of the
last compared PATCH call, and the ordered `permissions`, `bindings` and
`responses` rows. Each row gives its physical log `line`, timestamp `time`,
value without trailing whitespace and SHA-256 `sha256` of
`"<time> <value>"`. The validator matches the rows against the saved log and
their owning setup or script step. The step transcript must also echo the exact supported shell body
and its environment, including the target references present in the source.

- The supported script runs the GitHub CLI under a job token and records
  the HTTP status each time. It contains one of two bounded comparisons:
  a draft update with the original commit, a distinct commit, then the
  original again, or a published release update sending no field, name,
  tag name and finally target commit.
- The draft comparison also needs three owned binding rows for the
  resolved main commit, the literal alternative commit and the created
  draft ID. The published comparison needs no binding rows because the
  release ID and target commit are literal workflow environment values.
- Unmatched source, request, log, step or token grant leaves the result
  unresolved. An accepted comparison exits 0 even if one of its recorded
  requests returned 403. The recorded request statuses describe the
  selected release only. Token values, denial policy, fork permissions
  and asset writes require separate evidence.

## Saved GitHub Preview observations

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

The optional [producer archive credential](#producer-archive-credential)
uses the same proof of the owning upload in this profile.

## Saved GitHub Pages publication

Use a saved evidence projection to check whether an external-fork benchmark
archive reached a historical GitHub Pages deployment in a separate repository.

```sh
taintly ./source-projection --format json \
  --github-pages-observation observation.json OWNER/REPO PRODUCER_RUN CONSUMER_RUN
```

Put both original workflow files at their recorded paths beneath
`source-projection`, with the original job archive as `publication.zip`.
Use trusted GitHub metadata, job log excerpts and Git object records.
Keep credentials out of the projection. The verifier performs no network
requests and reads selected archive members without extracting them.

For schema `github-workflow-run-pages-publication-v1`, supply:

- `repository` and `pr` with `number`, `head_sha`, `head_repository` and
  `base_repository`.
- `producer` and `consumer` with `id`, `path`, `html_url`, `event`,
  `conclusion`, `head_sha`, `head_repository`, `run_attempt`,
  `referenced_workflows`, `created_at`, `updated_at` and the selected `job`.
  Preserve the job's ID, run ID, attempt, revision, conclusion, name, time
  bounds and numbered step records.
- `producer_source` and `source` with `path`, `revision` and `sha256`.
  Supply `steps` with the actual checkout, generation (`generate`), upload,
  download, guard and deploy step names. Supply the original `archive_prefix`
  and `artifact` ID, producer run (`run`), `head`, `name`, `size` and
  `digest` (`sha256:<hex>`).
- `producer_rows` for `checkout`, `upload` and, on publication, `generate`.
  The consumer `rows` cover `run`, `artifact` and `downloaded`. A successful
  write also uses `action`, `credential`, `destination`, `repository`,
  `token-setup`, `copy`, `command`, `remote` and `result`. For each row,
  preserve its `kind`, `job`, `attempt`, `time`, `value` and SHA-256 of
  the UTF-8 `time + " " + value`. Use masked values for credential rows.
- For a deployment, supply `result` with `repository`, `branch`,
  `previous`, `commit`, its raw UTF-8 `commit_bytes` and a
  `tree_objects` mapping from tree ID to raw hex bytes. List the selected
  relative archive `members`. Include GitHub's `deployment`, `success`,
  `run` and `job` records under `pages`.
- To corroborate a specific unparameterized ASV result, include `benchmark`
  with its `step`, benchmark `name`, raw `result` archive path and owned
  `command`, `head` and `sample` rows. Select both the published
  `index.json` and the corresponding summary graph for byte comparison.
- To corroborate the historical push account, optionally include the
  original destination repository `PushEvent` as `push_event`. Its
  repository, ref, previous and new head, and timestamp must agree with
  the selected Git update and owned push logs.

The profile supports a direct fork checkout, an ASV archive, and the reviewed
`peaceiris/actions-gh-pages` action revision with an observed personal-token
setup. `pages-deployment-observed` confirms a historical deployment for
the exact published commit and named files. `pages-publication-skipped`
records the missing HTML directory and the actual guard skip. The push
account is corroborated when the optional event matches. The specific
token, wider permissions, benchmark validity and current deployed revision
stay unverified. Missing or incompatible deployment evidence
returns `unresolved` and exit `11`. Missing optional benchmark evidence
leaves only that part unresolved. Ordinary scans retain their existing behavior.

## Saved GitHub Worker version uploads and fork skips

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

## CodeBuild project snapshots

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

## Saved public CodeBuild runs

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

## Saved direct CodeBuild S3 request

Use the S3 observation command with a trusted saved capture with
`schema: codebuild-direct-s3-put-v1`. Pass the exact CodeBuild ARN and
GitHub repository URL. The supplied Git checkout must contain the resolved
commit and have the same origin. This profile covers a pinned branch in
GitHub and one trusted inline Bash command block on the supported CodeBuild
managed image. The block must verify the commit and file checksum, obtain its
STS identity, and make one versioned `aws s3api put-object` request with that
file. See the [supported inline block](../taintly/ingestion/codebuild_put.py).

For a native external GitHub PR source, supply `pr` with `repository`,
`number`, `fork`, `head` and `base` from the saved GitHub PR response.
The saved build must select `refs/pull/<number>/head^{<full-head-SHA>}`
and resolve the same head. The Git checkout must contain both commits.
The uploaded marker must have a different Git blob at the fork head from
the file at the PR base. These facts verify the selected source for the
saved request. Automatic PR admission requires separate evidence.

For the operator-prepared S3 input profile, supply `s3_input` with
`bucket`, `key`, `operator_selected_head`, `receipt` and
`archive_base64`. The receipt contains the version and full-object
SHA-256 of the input ZIP. The ZIP must contain one stored regular file
matching the supplied Git blob. The source-version check uses
`CODEBUILD_SOURCE_VERSION` and the corresponding environment binding.
The result identifies the selected S3 version and shows which Git file
its contents match. It makes no native GitHub checkout claim for that build.

Use the selected `BatchGetBuilds` row as `build` and the owning CloudWatch
`GetLogEvents` result as `logs`, with `group` and `stream` from the export
request. For a successful write, add `retrieval` with `bucket`, `key`, the
version-pinned `GetObject` `response`, and `bytes_base64`. For a denial,
provide the matching CloudTrail record as `s3_event`.
For successful writes, an optional CloudTrail record must identify the same
object version before the report attaches its request ID. An event without
a version leaves audit corroboration unresolved. The write can still be
observed through the command response and verified version-pinned retrieval.
Without a bound S3 data event, `publication.acting_session` is `unverified`.
`reported_sts_session` records the session shown by the runner's separate
STS call.
The owning runner log can also corroborate entry into the primary source
workspace before the command. The declaration, directory entry and successful
DOWNLOAD_SOURCE must agree in this managed-image profile. Conflicting or
partial workspace records leave the observation unresolved. Compact logs
with neither workspace marker leave the workspace unverified while retaining
an independently corroborated request. Operating-system process and
filesystem identity require separate evidence.

If the owning pre-command logs record a YAML location, that selection must
uniquely identify the managed inline buildspec in DOWNLOAD_SOURCE. A
contradictory selection leaves the observation unresolved. A compact log
without this optional row can still bind the build response to the exact
observed command.

The Git file, command, request time, role and session, target, checksum,
and version are checked when relevant. Provide an optional redacted
`runtime_sts_event` from CloudTrail to bind the build's
`GetCallerIdentity` call to the same temporary credential as the independently
matched S3 data event. Keep the event identity and time and use
`userIdentity.credential_id_sha256` for the STS event instead of its credential
identifier. The report identifies the STS event and omits that identifier and
its digest. Use captures made by a trusted operator and keep them private.

An optional `launch_event` can corroborate a same-account IAM user's
`StartBuild` call. Preserve the CloudTrail management event identity,
time, account, region, request and returned build. The request and response
must agree with the saved build and exact source selector. The caller who
started the build is reported separately from the build role and S3 session.

For a single request, exit `0` indicates a corroborated write or denial. Read the reported state to
tell which occurred. Missing or mismatched evidence exits `11`. A successful
write can be corroborated by the independent version retrieval when the
matching CloudTrail data event is unavailable. The result applies to the
captured request. Future policy decisions, fork admission and artifact audience
require their own evidence.

To compare an observed write with a later explicit resource-policy denial,
add `policy_comparison` to the denial receipt. Include:

- `earlier`, the complete earlier direct S3 write receipt from the same
  project, with the matching source, build settings, role and target.
- `policy_event`, a trusted successful CloudTrail `PutBucketPolicy` management
  event. Preserve `eventID`, `requestID`, `eventSource`, `eventName`, `eventTime`,
  `eventCategory`, `managementEvent`, `readOnly`, `awsRegion` and `recipientAccountId`.
  Preserve `requestParameters.bucketName` and the complete parsed
  `requestParameters.bucketPolicy` object. The supported policy has one
  `Deny` statement for the exact `s3:PutObject` target, a wildcard principal,
  and an `ArnEquals` condition on `aws:PrincipalArn` for the exact build role.

The recorded policy change must fall between the builds. An independently
bound S3 data event for each request yields `matched-policy-change` and exit
`0`. If the earlier version was retrieved but its request actor remains
unverified, the result retains the matched policy event and exits `11`.
An unsupported or conflicting comparison also exits `11` while preserving
the selected request's corroborated result. The comparison does not recover
complete policy history or prove that the change was the sole cause.

## Saved CodeBuild-managed S3 ZIP

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
The report names the object write record, build session and byte linkage
needed to follow up. The packaged ZIP profile below covers a separate observation.
The exact service-role session, general IAM permissions and subsequent use
remain unverified. Inconsistent or missing evidence returns exit 11.

Use the same command with a full public `BUILD_ID` (`project:uuid`) and
`codebuild-managed-s3-empty-primary-v1` for a failed, completed PR build
with no matching primary artifact paths. The trusted receipt contains
`build` (including the selected revision, inline buildspec and exact phase
records), `provider` (the selected `build` ID and build-specific `s3Arn`
directory), and `logs` (the selected `build` ID, the inline buildspec
`selection` row, and the ordered `upload` rows). Preserve the primary
root archive-selector expansion rows, report auto-discovery boundary,
terminal failed upload row and the corresponding no-paths client error.
The local repository must contain the selected PR commit.

`primary-artifact-paths-unmatched` reports the CodeBuild selection result
and exact directory. The profile requires a failed BUILD phase followed
by POST_BUILD and primary S3 directory output at `codebuild/project/uuid/project`
with `NONE` packaging. The root selectors must be a plain block list.
Automatic report discovery is separate from primary
artifact selection. The mode retains exit 11 because effective S3 authority
and other writes remain unverified.

For CodeBuild-packaged primary ZIPs, use a full public build ID and
`codebuild-managed-s3-reported-zip-v1`. Supply trusted saved records for
an external GitHub PR with a selected SHA, a literal repository buildspec,
and one primary archive selector. The record contains:

- `pr`: `number`, `head`, `repository`, and `fork`.
- `build`: CodeBuild's completed build record with its selection, status,
  phase timestamps and primary S3 ZIP configuration.
- `logs`: `build` plus the runner's buildspec selection under `source`,
  one literal `bash path/to/script.sh` BUILD invocation under `command`,
  and the ordered selector expansion, positive match count, report
  auto-discovery boundary and terminal success under `upload`.
- `provider`: the exact `build` ID, the build-specific object `s3Arn`
  and `sha256Checksum` from CodeBuild's public artifact lookup. Omit
  signed URLs and tokens.

The local repository must contain the exact PR commit. The
`managed-s3-zip-reported` state records the successful upload phase and
the provider-reported object and checksum, including after a failed BUILD
phase. The selected commit matches the supplied PR head. The evidence
needed to identify the triggering event is separate. The mode retains exit
11 pending verification of the archive and writer. A reported selector
match does not establish the contents of each member.

## Saved CodeBuild deployment skip

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

## Saved CodeBuild webhook filters

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
