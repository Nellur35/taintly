"""GitLab REST API client for platform-posture checks.

Mirrors the GitHub client's shape — same "None means 404, APIError means
anything else" contract — but uses GitLab's authentication header
(``PRIVATE-TOKEN``) and honours the ``GITLAB_URL`` environment variable
for self-hosted instances.

The project identifier can be a numeric ID or a URL-encoded path
(``group/project`` becomes ``group%2Fproject``); clients receive the
raw form and the helper encodes on demand.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .token import TokenManager


def _base_url() -> str:
    return os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")


class APIError(Exception):
    def __init__(self, endpoint: str, status: int, body: str = "") -> None:
        self.endpoint = endpoint
        self.status = status
        self.body = body
        super().__init__(f"{endpoint}: HTTP {status} {body[:200]}")


class GitLabClient:
    """Minimal authenticated GitLab API client.

    Each method returns parsed JSON on success, ``None`` on 404, or
    raises :class:`APIError` on any other failure.
    """

    def __init__(
        self,
        token: TokenManager,
        *,
        base_url: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._token = token
        self._base_url = base_url or _base_url()
        self._timeout = timeout

    # ---------------------------------------------------------------------
    # Low-level
    # ---------------------------------------------------------------------

    @staticmethod
    def encode_project(project: str) -> str:
        """URL-encode a project identifier (numeric ID or group/name path)."""
        return urllib.parse.quote(str(project), safe="")

    def _request(self, endpoint: str) -> Any | None:
        url = f"{self._base_url}/api/v4{endpoint}"
        req = urllib.request.Request(
            url,
            headers={
                "PRIVATE-TOKEN": self._token.value,
                "Accept": "application/json",
                "User-Agent": "taintly",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310 — https via _base_url
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                # Informational body only; raising APIError with the
                # status code is sufficient when the body is unreadable.
                pass  # nosec B110
            raise APIError(endpoint, e.code, body) from None

    # ---------------------------------------------------------------------
    # Typed accessors for platform checks
    # ---------------------------------------------------------------------

    def project(self, project: str) -> dict[str, Any] | None:
        return self._request(f"/projects/{self.encode_project(project)}")

    def protected_branch(self, project: str, branch: str) -> dict[str, Any] | None:
        return self._request(
            f"/projects/{self.encode_project(project)}/protected_branches/"
            f"{urllib.parse.quote(branch, safe='')}"
        )

    def approval_rules(self, project: str) -> list[dict[str, Any]]:
        """MR approval rules. Returns empty list on 404."""
        data = self._request(f"/projects/{self.encode_project(project)}/approval_rules")
        return data if isinstance(data, list) else []

    def approvals_summary(self, project: str) -> dict[str, Any] | None:
        """Legacy approvals endpoint — older GitLab versions expose this."""
        return self._request(f"/projects/{self.encode_project(project)}/approvals")

    def variables(self, project: str) -> list[dict[str, Any]]:
        """Project-level CI/CD variables. Requires Maintainer access.

        Returns empty list on 404 (token lacks scope) so checks degrade
        gracefully rather than crashing the whole audit.
        """
        data = self._request(f"/projects/{self.encode_project(project)}/variables")
        return data if isinstance(data, list) else []

    def deploy_keys(self, project: str) -> list[dict[str, Any]]:
        data = self._request(f"/projects/{self.encode_project(project)}/deploy_keys")
        return data if isinstance(data, list) else []

    def hooks(self, project: str) -> list[dict[str, Any]]:
        data = self._request(f"/projects/{self.encode_project(project)}/hooks")
        return data if isinstance(data, list) else []

    def members(self, project: str) -> list[dict[str, Any]]:
        """Direct project members (not inherited from group)."""
        data = self._request(f"/projects/{self.encode_project(project)}/members")
        return data if isinstance(data, list) else []

    def group(self, group: str) -> dict[str, Any] | None:
        return self._request(f"/groups/{self.encode_project(group)}")

    def group_variables(self, group: str) -> list[dict[str, Any]]:
        data = self._request(f"/groups/{self.encode_project(group)}/variables")
        return data if isinstance(data, list) else []
