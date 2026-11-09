"""Confine authenticated GitLab requests to the configured HTTPS origin."""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any


class GitLabTransportError(ValueError):
    """A credentialed request was refused before accepting its recipient."""


def _origin(url: str) -> tuple[str, int]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise GitLabTransportError("GitLab URL must be an unambiguous HTTPS instance URL") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in url
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
        or (port is not None and not 0 < port < 65536)
    ):
        raise GitLabTransportError("GitLab URL must be an unambiguous HTTPS instance URL")
    return str(parsed.hostname).lower(), port or 443


def validate_gitlab_base(base: str) -> str:
    """Accept HTTPS self-hosted prefixes without userinfo or URL ambiguity."""
    _origin(base)
    if "?" in base or "#" in base:
        raise GitLabTransportError("GitLab URL must be an unambiguous HTTPS instance URL")
    return base.rstrip("/")


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, base: str) -> None:
        self._origin = _origin(base)

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        try:
            allowed = _origin(newurl) == self._origin
        except GitLabTransportError:
            allowed = False
        if not allowed:
            if fp is not None:
                try:
                    fp.close()
                except Exception:
                    raise GitLabTransportError(
                        "GitLab credential request refused an unsafe redirect; response cleanup failed"
                    ) from None
            raise GitLabTransportError("GitLab credential request refused an unsafe redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_gitlab(request: urllib.request.Request, *, base_url: str, timeout: int = 30) -> Any:
    """Open without delegating the credential to another origin."""
    if _origin(request.full_url) != _origin(base_url):
        raise GitLabTransportError(
            "GitLab request does not belong to the configured HTTPS instance"
        )
    opener = urllib.request.build_opener(_SameOriginRedirect(base_url))
    return opener.open(request, timeout=timeout)  # nosec B310 — HTTPS with same-origin redirects
