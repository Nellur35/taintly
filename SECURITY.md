# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in taintly itself — not a rule-coverage gap, but a bug in the scanner that could be exploited — please report it privately.

**Preferred channel:** [GitHub private vulnerability report](https://github.com/Nellur35/taintly/security/advisories/new).

Use this for issues that meet any of:

- The scanner executes attacker-controlled input as code (e.g. unsafe deserialisation, YAML exploit via the vendored parser once it lands)
- The scanner writes attacker-controlled data outside the user's repo (path traversal in `--fix`)
- The scanner corrupts state on a compromised workflow file in a way that could be weaponised
- A CVE against a runtime dependency we ship (none today — the project is zero-dep)
- A supply-chain compromise of the released PyPI package

Do **not** open a public issue for these. Once a fix is ready we'll publish an advisory with credit.

## What is *not* a vulnerability

Rule-coverage gaps — a workflow that should fire a rule but doesn't, or a false positive that should be narrowed — are not security vulnerabilities in the tool. File them as regular issues.

## Response timeline

- **24 hours** — acknowledgement of receipt
- **7 days** — triage outcome (confirmed / rejected / needs info)
- **90 days** — fix released, or a coordinated disclosure deadline agreed

We follow a standard 90-day disclosure window. If the maintainer doesn't ship a fix within 90 days of a confirmed report, the reporter is free to publish. We'll coordinate on the wording.

## Supported versions

| Version | Supported |
|---------|-----------|
| `1.x`   | ✅ — active |
| `0.9.x` | ✅ — security fixes only (pre-1.0 shakedown line) |
| `< 0.9` | ❌ — no longer supported |

## Credit

Unless you ask otherwise, we credit reporters in the release notes and in the GitHub advisory. Anonymous reports accepted on request.

## Scope

This policy covers the taintly Python package and the GitHub composite Action at the repo root (`action.yml`).

Downstream consumers' CI configurations — even if they use taintly — are the consumer's responsibility. The tool's purpose is to help them audit those configs.
