# IAM evidence for AI-agent workflow findings

PSE-GH-001 detects a fork-reachable AI-agent workflow with a cloud-credential
capability. Local policy enrichment supplies additional context. It does not
connect to AWS or certify effective permissions.

## Policy candidates

A role name or ARN in a JSON filename, description, or Terraform heredoc is
an association clue. These candidates remain HIGH and review-needed. Their
policy source, digest and classified actions are retained for review; a name
match cannot establish attachment. Missing local policies do not establish
restricted permissions.

## Supported attachment evidence

A saved JSON IAM role inventory can declare an inline identity policy attached
to an exact role. The supported shape is the role portion of
[get-account-authorization-details](https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-authorization-details.html):

```json
{
  "RoleDetailList": [{
    "Arn": "arn:aws:iam::123456789012:role/AgentRole",
    "RolePolicyList": [{
      "PolicyName": "agent-inline",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": "iam:PassRole",
          "Resource": "*"
        }]
      }
    }]
  }]
}
```

Place the saved JSON at the repository root or in an IAM/infrastructure policy
directory such as `iam/` or `policies/`. Documents may be JSON objects, JSON
strings, or URL-encoded JSON strings. Plain strings are parsed before decoding
so literal percent escapes retain their meaning. Duplicate JSON keys, ambiguous
role entries, trust policies and unsupported statement forms supply no positive
attachment proof. Managed-policy references alone do not supply policy bodies.

The workflow relation requires a unique, preceding
`aws-actions/configure-aws-credentials@REF` step in the finding's own job, with
a literal full `role-to-assume` ARN and required `aws-region` input. A role in
another job, a shell example, a missing action reference, unresolved YAML,
conditional configuration, redirected credential output, or multiple credential
configurations remains unresolved. This finite profile does not evaluate arbitrary
Terraform, CloudFormation, reusable workflows or dynamic role expressions.

If that represented inline policy's Allow classification is CRITICAL, the
finding can show **CRITICAL configured inline-policy Allow upper bound**, with
the exact role, JSON pointer, source SHA256 and owning invocation. It remains
review-needed. The snapshot does not authenticate current AWS deployment.
Denies, conditions, permission boundaries, session policies, SCPs, trust and
successful execution are not evaluated. This is a bound on the represented Allow
contribution, not a complete bound on the role's other grants.

Review the cited attachment and current effective controls, narrow the specific
actions/resources, and separate agent execution from cloud credentials.

## Search limits

Search retains the existing policy-directory hints and excludes vendor/build
directories and symlinks. It examines at most 500 files, 2 MiB per file and
16 MiB of read policy bytes per scan. Inventory parsing admits at most 1,000
roles and 1,000 inline policies per matched role. Unresolved lexical role lookup
is limited to 16 candidates. Bounds and unreadable policy sources retain
review-needed state; they never support an absence-of-permissions conclusion.
Source bytes are reused only within the scan. A new scan reads new bytes and
creates new digests; an earlier witness is not a live AWS attestation.
