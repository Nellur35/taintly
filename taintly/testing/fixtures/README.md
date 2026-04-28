# Test Fixtures

This directory contains sanitized real-world CI/CD config files for integration testing.

Fixtures should be named descriptively:
- `github_prt_checkout.yml` — pull_request_target with untrusted checkout
- `github_unpinned_actions.yml` — workflow with unpinned action references
- `gitlab_remote_include.yml` — pipeline with remote include
- `gitlab_curl_bash.yml` — pipeline with curl|bash pattern

Each fixture should trigger at least one rule when scanned.
