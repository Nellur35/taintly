"""Platform-posture scanning — API-based checks of GitHub / GitLab
organization and repository settings that are not visible in the YAML.

The scanner's file-based rules read pipeline configs; platform rules
complement them by inspecting the settings that make a given workflow
more or less dangerous than its YAML alone suggests (branch protection,
default GITHUB_TOKEN permission, fork-PR approval gates, etc.).

Each finding carries ``origin="platform"`` so downstream consumers can
distinguish static-YAML findings from API-observed findings.
"""
