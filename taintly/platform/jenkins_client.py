"""Jenkins REST API client for platform-posture checks.

Follows the same contract as the GitHub and GitLab clients:
- dict / list for successful responses
- ``None`` for 404
- raise :class:`APIError` for any other failure

Jenkins authentication uses Basic auth (user:token) passed via the
``JENKINS_USER`` and ``JENKINS_TOKEN`` environment variables, or a
single ``JENKINS_URL`` that embeds credentials
(``https://user:token@jenkins.example.com``).

The ``JENKINS_URL`` environment variable is required and must include
the scheme (``https://...``).
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class APIError(Exception):
    def __init__(self, endpoint: str, status: int, body: str = "") -> None:
        self.endpoint = endpoint
        self.status = status
        self.body = body
        super().__init__(f"{endpoint}: HTTP {status} {body[:200]}")


class JenkinsClient:
    """Minimal authenticated Jenkins API client.

    Methods return parsed JSON on success, ``None`` on 404, or raise
    :class:`APIError`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        user: str | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._user = user or os.environ.get("JENKINS_USER", "")
        self._token = token or os.environ.get("JENKINS_TOKEN", "")
        self._timeout = timeout

    def _request(self, path: str) -> Any | None:
        """GET a Jenkins API endpoint (appends /api/json automatically)."""
        url = f"{self._base_url}{path}"
        if not url.endswith("/api/json"):
            url = url.rstrip("/") + "/api/json"

        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "taintly",
            },
        )
        if self._user and self._token:
            creds = base64.b64encode(f"{self._user}:{self._token}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass  # nosec B110
            raise APIError(path, e.code, body) from None

    # -----------------------------------------------------------------
    # High-level accessors
    # -----------------------------------------------------------------

    def instance_info(self) -> dict[str, Any] | None:
        """Top-level Jenkins instance info."""
        return self._request("/")

    def jobs(self, depth: int = 1) -> list[dict[str, Any]]:
        """List all top-level jobs."""
        data = self._request(f"/?depth={depth}")
        if data is None:
            return []
        return data.get("jobs") or []

    def job(self, job_name: str) -> dict[str, Any] | None:
        return self._request(f"/job/{urllib.parse.quote(job_name, safe='')}")

    def credentials_domains(self) -> list[dict[str, Any]]:
        """List credential domains in the global store."""
        data = self._request("/credentials/store/system/domain/_")
        if data is None:
            return []
        return data.get("credentials") or []

    def plugins(self) -> list[dict[str, Any]]:
        """List installed plugins."""
        data = self._request("/pluginManager")
        if data is None:
            return []
        return data.get("plugins") or []

    def security_realm(self) -> dict[str, Any] | None:
        """Get security configuration."""
        return self._request("/configureSecurity")

    def nodes(self) -> list[dict[str, Any]]:
        """List build nodes/agents."""
        data = self._request("/computer")
        if data is None:
            return []
        return data.get("computer") or []

    def whoami(self) -> dict[str, Any] | None:
        """Current authenticated user info."""
        return self._request("/me")
