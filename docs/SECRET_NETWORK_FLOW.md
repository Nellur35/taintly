# Secret-derived HTTP request bodies

`SEC6-GH-019` reports a **configured potential transfer**, not confirmed
exfiltration. It requires a source-bound GitHub Actions workflow, a direct
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
