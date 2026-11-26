# Observe the process for one CodeBuild S3 probe

Use this diagnostic when you need to verify which executable and working
directory made a controlled S3 request in your AWS test account. Start with
the example and Taintly installed from the same checked-out revision.
The procedure is for an authorized operator using a private test target.

## Set up the probe

1. Select a reviewed external GitHub fork PR whose head changes a root
   file named `hello.txt`. The file must be an inert UTF-8 test marker, at
   most 128 bytes. Confirm its exact Git blob and SHA-256 before the run.
   The local evidence checkout must contain the selected head and base.
2. Use a Linux CodeBuild project with image `aws/codebuild/standard:7.0`
   and CodeBuild image-pull credentials. Keep TLS verification enabled and
   turn off submodules, privileged mode and caching. Configure neither
   secondary sources nor artifact delivery. Use a dedicated test role and
   private S3 bucket. Scope the write to `controlled/hello.txt`. For an
   allowed write, enable versioning and allow it to
   [propagate](https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html)
   before testing. For a refusal, use a bucket policy that denies the
   test role's write to the exact key. Save before and after object listings
   if you want to verify the target stayed empty. Enable CloudWatch build
   logs and CloudTrail S3 data events for the exact object before the run.
3. Set the three plain build environment variables
   `EXPERIMENT_SOURCE_SHA` (the exact selected head),
   `EXPERIMENT_MARKER_SHA256` (the marker's SHA-256), and
   `EXPERIMENT_BUCKET` (the private test bucket). None holds a secret.
   Select the source as `refs/pull/<number>/head^{<full-head-SHA>}`.
4. Start the build with [the reviewed buildspec](probe.buildspec.yml) as
   the **inline StartBuild override**. Use an operator-controlled definition
   and preserve the exact bytes. The observer requires the corresponding
   same-account IAM user StartBuild event. The plan copies the expected
   marker to a private scratch directory and runs its own commands there.

The plan embeds the collector so it can run independently of the fork.
Review its [readable source](taintly_receipt.py), which uses LF line
endings. The collector records an
executable fingerprint, a directory, process identity and the response
request ID. It uses no third-party Python package. It does not record
AWS credentials or request headers. Keep the AWS and GitHub evidence
private because it contains account, source and runtime identifiers.

## Assemble and check the saved evidence

Create a private JSON file with `schema: "codebuild-direct-s3-put-v1"`.
Use the following provider records as the named JSON objects.

| Field | Record to save |
| --- | --- |
| `pr` | The exact GitHub PR, projected to `repository`, `number`, `fork`, `head` and `base`. |
| `build` | The single selected build from AWS `BatchGetBuilds`. Keep the effective inline buildspec bytes and phase times. |
| `launch_event` | The CloudTrail `StartBuild` management event for the same build. Preserve AWS's original redaction in the request and response when present. |
| `logs` | The owning CloudWatch stream, with its `group` and `stream` names and `events` array. Preserve the full command announcement, provider phase rows and the single `taintly_process_receipt=` line. |
| `s3_event` | The independently delivered CloudTrail S3 `PutObject` event. Keep the top-level request ID, acting session, target, result and version when present. |
| `retrieval` | For an allowed write, include `bucket`, `key`, the version-pinned `GetObject` response under `response` and the downloaded marker under `bytes_base64`. Omit this field for a denial. |

The launch and S3 events do not need `userIdentity.accessKeyId`. Do not
include credential values, raw headers or presigned URLs. Use the build
ARN and repository origin that identify the supplied evidence.

```bash
python -m taintly ./repo --format json --codebuild-public-s3-observation \
  ./observation.json "$BUILD_ARN" "$GITHUB_REPOSITORY_URL"
```

Read the report's decision. Exit `0` means the evidence corroborated the
observed write **or** refusal. A missing process receipt or a different
request ID leaves the process unresolved and returns `11`, keeping
separately verified facts visible. If AWS redacted the buildspec at launch,
the report records that and checks the effective build and owning command.
The result concerns the exact probe request. It does not establish future
IAM permissions or discover process identities in general buildspecs.
