"""GitHub REST API client for platform-posture checks.

Wraps the shared helpers in :mod:`taintly.ingestion.github_api` with a
thin class that makes endpoint patterns explicit, caches 404s per URL
(branch protection returns 404 when absent — no retry value), and maps
HTTP errors into values the check functions can reason about instead of
exceptions they have to catch.

All state lives on the client instance; the token is borrowed from a
:class:`~taintly.platform.token.TokenManager` and never stored as an
attribute on this class so it is not captured in tracebacks or
``__repr__``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .token import TokenManager

_BASE = "https://api.github.com"


class APIError(Exception):
    """Raised when a request fails for a non-404 reason."""

    def __init__(self, endpoint: str, status: int, body: str = "") -> None:
        self.endpoint = endpoint
        self.status = status
        self.body = body
        super().__init__(f"{endpoint}: HTTP {status} {body[:200]}")


class GitHubClient:
    """Minimal authenticated GitHub API client.

    Methods return:
      - dict / list for successful responses
      - ``None`` for 404 (the absence signal — e.g. "no branch protection")
      - raise :class:`APIError` for any other failure
    """

    def __init__(self, token: TokenManager, *, base_url: str = _BASE, timeout: int = 30) -> None:
        self._token = token
        self._base_url = base_url
        self._timeout = timeout

    # ---------------------------------------------------------------------
    # Low-level
    # ---------------------------------------------------------------------

    def _request(self, endpoint: str) -> Any | None:
        """GET an endpoint. Returns parsed JSON, or ``None`` for 404."""
        url = f"{self._base_url}{endpoint}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._token.value}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "taintly",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310 — https-only
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                # The error body is informational for the APIError; a
                # failed read is acceptable — we still raise with the
                # HTTP status and endpoint.
                pass  # nosec B110
            raise APIError(endpoint, e.code, body) from None

    def _request_status_only(self, endpoint: str) -> int | None:
        """GET an endpoint, return HTTP status only (no body parse).

        Used for endpoints that signal state via status code rather than
        response body — e.g. GitHub's ``/vulnerability-alerts`` returns
        ``204 No Content`` when enabled and ``404`` when disabled, with
        no JSON body either way. ``_request`` would fail on the empty
        body.

        Returns the status integer on a 2xx or 4xx response, or
        ``None`` on transport error.
        """
        url = f"{self._base_url}{endpoint}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._token.value}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "taintly",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310 — https-only
                # HTTPResponse.status is typed Any in urllib's stubs;
                # coerce to int so the method honours its own signature.
                return int(resp.status)
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, OSError):
            return None

    # ---------------------------------------------------------------------
    # High-level typed accessors used by platform rules
    # ---------------------------------------------------------------------

    def repo(self, owner_repo: str) -> dict[str, Any] | None:
        return self._request(f"/repos/{owner_repo}")

    def default_branch(self, owner_repo: str) -> str | None:
        r = self.repo(owner_repo)
        return r.get("default_branch") if r else None

    def branch_protection(self, owner_repo: str, branch: str) -> dict[str, Any] | None:
        """Classic branch protection. Returns None if none exists."""
        return self._request(f"/repos/{owner_repo}/branches/{branch}/protection")

    def rulesets(self, owner_repo: str) -> list[dict[str, Any]]:
        """Repository rulesets — the modern replacement for classic branch
        protection.  Returns an empty list on 404 / unsupported.
        """
        data = self._request(f"/repos/{owner_repo}/rulesets")
        return data if isinstance(data, list) else []

    def ruleset_detail(self, owner_repo: str, ruleset_id: int) -> dict[str, Any] | None:
        return self._request(f"/repos/{owner_repo}/rulesets/{ruleset_id}")

    def actions_permissions_repo(self, owner_repo: str) -> dict[str, Any] | None:
        return self._request(f"/repos/{owner_repo}/actions/permissions")

    def actions_permissions_workflow(self, owner_repo: str) -> dict[str, Any] | None:
        """The 'workflow permissions' setting (GITHUB_TOKEN default + PR approval)."""
        return self._request(f"/repos/{owner_repo}/actions/permissions/workflow")

    def actions_permissions_access(self, owner_repo: str) -> dict[str, Any] | None:
        """The fork-PR approval gate setting."""
        return self._request(f"/repos/{owner_repo}/actions/permissions/access")

    def deploy_keys(self, owner_repo: str) -> list[dict[str, Any]]:
        data = self._request(f"/repos/{owner_repo}/keys")
        return data if isinstance(data, list) else []

    def webhooks(self, owner_repo: str) -> list[dict[str, Any]]:
        data = self._request(f"/repos/{owner_repo}/hooks")
        return data if isinstance(data, list) else []

    def collaborators(self, owner_repo: str, affiliation: str = "outside") -> list[dict[str, Any]]:
        data = self._request(f"/repos/{owner_repo}/collaborators?affiliation={affiliation}")
        return data if isinstance(data, list) else []

    def vulnerability_alerts_enabled(self, owner_repo: str) -> bool | None:
        """Returns True if enabled, False if disabled, None on transport error.

        GitHub signals this via status code, not body:

          * ``204 No Content`` — Dependabot alerts enabled
          * ``404 Not Found``  — disabled (or the token lacks scope)

        Routed through :meth:`_request_status_only` so the method stays
        behind the client's public interface — previously it reached
        into ``self._base_url`` directly, bypassing any stub that only
        overrode ``_request``.
        """
        status = self._request_status_only(f"/repos/{owner_repo}/vulnerability-alerts")
        if status == 204:
            return True
        if status == 404:
            return False
        return None

    def user(self, username: str) -> dict[str, Any] | None:
        return self._request(f"/users/{username}")

    def org(self, org_name: str) -> dict[str, Any] | None:
        return self._request(f"/orgs/{org_name}")

    def codeowners_exists(self, owner_repo: str) -> tuple[bool, str | None]:
        """Check all three canonical CODEOWNERS locations.

        Returns (exists, content_or_none). Content is base64-decoded.
        """
        import base64

        for path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            data = self._request(f"/repos/{owner_repo}/contents/{path}")
            if isinstance(data, dict) and data.get("type") == "file":
                try:
                    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                except Exception:
                    content = ""
                return True, content
        return False, None
