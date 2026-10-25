# Secret-derived HTTP transfers

These rules report a **configured potential transfer**, not confirmed
exfiltration. `SEC6-GH-019` requires a source-bound GitHub Actions workflow, a direct
`${{ secrets.NAME }}` environment binding, and an evidenced path to the body of
one `curl` HTTP(S) request. The finding names the source binding and each
supported assignment, file write, Base64 transform, and request-body line.

The supported profile is a literal Bash `run: |` block in a directly owned step
on a GitHub-hosted Ubuntu runner. It models simple variable assignments,
`echo` redirection, `base64 -w0` file transforms, and one `curl --data`,
`--data-binary`, `--data-raw`, or `-d` body. Files may pass between adjacent
supported steps in the same job. Shell variables do not pass between steps.
Step guards prevent cross-step file joins unless the path is wholly in one
step. Unrecognized commands cut the path; they are not assumed harmless.

A secret in an authentication header is not by itself a body transfer. A
single-quoted `$TOKEN` is literal data in this profile. A secret used as a
legitimate API request body may still be reported for review; the rule does not
classify the destination as malicious. It does not prove the job ran, the
secret was available, the file contained particular bytes, or the HTTP request
succeeded. Expressions, unknown shells or runners, generated scripts,
nonliteral paths, and unsupported file effects require separate analysis.

Release-source substitution, temporary deleted branches, platform token
governance, and published-package provenance remain outside this static
source-to-body proof. A changed release source requires evidence binding the
checkout, build, artifact, and publication identities. Runtime confirmation
would require trusted execution and network records.

## GitLab CI

`SEC6-GL-010` follows the predefined `CI_JOB_TOKEN` reference in one literal
block-style `script` item owned by a single job. It supports assignments,
`echo` file writes, a Base64 file transform, and a `curl` request body within
that item. GitLab documents that a job receives `CI_JOB_TOKEN`, but the file
does not establish the runner's actual shell, token availability at execution,
or any external variable override. The finding is conditional on a POSIX shell
and requires review. Includes, defaults, inherited or preceding scripts,
explicit variables, and multiple script items remain unresolved in this
profile; they are not treated as clean scans for this path.

## Jenkins

`SEC6-JK-013` separately reviews a directly bound Jenkins credential in the
query of a direct `curl` HTTP(S) URL. It requires an exact physical Jenkinsfile,
one structurally owned `withCredentials` string or password binding, and an
owned `sh` operand whose simple command passes the URL directly to `curl`.
The supported profile also includes command-style `sh script: "..."`, a
legacy `$class: 'UsernamePasswordMultiBinding'` map with an exactly bound
password variable, and `curl -XPOST` or `curl --data` with a recognized
operand before the direct URL. URLs embedded in request data or headers are
not treated as destination operands.
It distinguishes Groovy GString interpolation from shell expansion. An
authentication header or `curl -u` alone is not this URL-query path. A prior
shell command that may change the variable, an ambiguous binding owner, an
unrecognized command form, or shell quoting that may prevent URL delivery
remains unresolved. The rule does not classify the endpoint as malicious or
prove that the job ran, the credential was available, the request succeeded,
or a third party saw the URL. Review whether the API accepts a header and
whether URLs are recorded in logs or telemetry. Mixed line endings are
normalized only for source comparison; the reported SHA256 still identifies
the original bytes.

The text report renders an ASCII evidence path for supported `SEC6-JK-013`
findings. Its steps and references are produced by the rule's validated
binding-to-shell-to-query witness; the reporter does not reparse Jenkinsfile
text or infer a missing hop. It shows the owning scope, interpolation stage,
source lines and unresolved runtime conditions. JSON and SARIF retain their
existing finding contracts. If the witness is unavailable, no path is drawn.

`SEC6-JK-012` requires a direct `withCredentials([string(...)])` binding
whose closure contains one literal triple-single-quoted `sh` body. The
Jenkinsfile reader independently binds the variable and shell body to the
same owner before the shell transfer logic runs. Groovy-interpolated strings,
other credential bindings, nested wrappers, and separate shell steps remain
unresolved. A credential in an authentication header alone is not a body
transfer.

The platform additions are MEDIUM and review-needed. They preserve the source-file
hash, owner, credential reference and modeled hops; they do not prove the
request ran, reached its destination or disclosed usable credentials. Their
authored tests prove the supported profile, not field precision or recall.

## AWS CodeBuild

`SEC6-CB-003` follows an `env.secrets-manager` variable through one literal
command block in a version 0.2 buildspec with `env.shell: bash`. Its source
binding, shell and command owner must each come from the same physical file.
Multiple command items, other shells and buildspec versions, ambiguous YAML,
and a buildspec variable with the same name remain unresolved. A CodeBuild
project or start-build request can override the buildspec variable or even the
buildspec itself; these external settings are not visible from the file.

GitLab source semantics: [job tokens](https://docs.gitlab.com/ci/jobs/ci_job_token/)
and [script variables](https://docs.gitlab.com/ci/variables/job_scripts/).
Jenkins source semantics: [Credentials Binding Plugin](https://www.jenkins.io/doc/pipeline/steps/credentials-binding/).
CodeBuild source semantics: [buildspec reference](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html).
