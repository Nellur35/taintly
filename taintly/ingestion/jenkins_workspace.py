"""Bind the selected Jenkins checkout and publisher to a controller allocation."""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from .jenkins_incrementals import IncrementalsEvidenceError, _project_file, _require

_NODE_ID = re.compile(r"[1-9][0-9]{0,9}")
_ALLOCATION = re.compile(
    r"Running on (?P<agent>[-A-Za-z0-9_.]{1,127}) in (?P<workspace>/[-A-Za-z0-9_./@]{1,4095})"
)
_LOG_SPAN = re.compile(r"pipeline-node-([1-9][0-9]{0,9})")


class _Enclosures(HTMLParser):
    """Read Jenkins metadata spans without interpreting build output as graph edges."""

    def __init__(self) -> None:
        super().__init__()
        self.parents: dict[str, str | None] = {}
        self.functions: dict[str, str] = {}
        self.body_starts: set[str] = set()
        self._current: str | None = None
        self._log_node: str | None = None
        self._log_line = ""
        self.allocations: dict[str, list[tuple[str, str]]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._current = None
        if tag != "span":
            return
        self._finish_log_line()
        attributes = dict(attrs)
        css = attributes.get("class") or ""
        if log_span := _LOG_SPAN.fullmatch(css):
            self._log_node = log_span[1]
            return
        if css != "pipeline-new-node":
            return
        node = attributes.get("nodeid") or ""
        parent = attributes.get("enclosingid")
        _require(
            len(attributes) == len(attrs)
            and _NODE_ID.fullmatch(node)
            and node not in self.parents
            and (parent is None or _NODE_ID.fullmatch(parent))
            and len(self.parents) < 4096,
            "saved Jenkins console has ambiguous node annotations",
        )
        self.parents[node] = parent
        if attributes.get("startid") == node:
            self.body_starts.add(node)
        self._current = node

    def handle_endtag(self, tag: str) -> None:
        if tag == "span":
            self._current = None
            self._finish_log_line()

    def handle_data(self, data: str) -> None:
        first_line, newline, _ = data.partition("\n")
        if self._current is not None:
            self.functions[self._current] = first_line.strip()
            self._current = None
        if self._log_node is not None:
            self._log_line = (self._log_line + first_line)[:4352]
            if newline:
                self._finish_log_line()

    def _finish_log_line(self) -> None:
        if self._log_node is not None and (
            match := _ALLOCATION.fullmatch(self._log_line.rstrip("\r"))
        ):
            self.allocations.setdefault(self._log_node, []).append(
                (match["agent"], match["workspace"])
            )
        self._log_node = None
        self._log_line = ""

    def allocation(self, node: str, stage: str) -> str:
        seen: set[str] = set()
        allocation = None
        current: str | None = node
        while current is not None:
            _require(
                current in self.parents and current not in seen and len(seen) < 40,
                "Jenkins console has incomplete or ambiguous enclosing nodes",
            )
            seen.add(current)
            step = self.functions.get(current, "")
            _require(
                step.startswith("[Pipeline] "),
                "Jenkins console lacks an enclosing controller step label",
            )
            if step == "[Pipeline] node":
                _require(
                    current in self.body_starts,
                    "Jenkins console lacks the start annotation for an enclosing allocation",
                )
                if allocation is None:
                    allocation = current
            current = self.parents[current]
        if allocation is None or stage not in seen:
            raise IncrementalsEvidenceError(
                "no bounded Jenkins executor allocation for the selected stage"
            )
        return allocation


def workspace_allocation(
    root: Path,
    receipt: dict[str, Any],
    job: str,
    loader: str,
    stage: str,
    checkout: str,
    command: str,
    workspace: str,
) -> dict[str, str]:
    """Interpret an opt-in, trusted copy of the matching controller HTML console."""
    reason = "saved workspace console is unavailable, incomplete or differs from the selected run"
    try:
        url = job + "logText/progressiveHtml?start=0"
        _require(receipt["url"] == url and receipt["complete"] is True, reason)
        raw = _project_file(root, "maven-workspace-console.html", 4 * 1024 * 1024)
        digest = hashlib.sha256(raw).hexdigest()
        _require(receipt["sha256"] == digest, reason)
        source = raw.decode("utf-8")
        _require(
            [line.rstrip("\r") for line in source.split("\n", 12)[:12]].count(loader) == 1, reason
        )
        graph = _Enclosures()
        graph.feed(source)
        graph.close()
        _require(
            graph.functions.get(checkout) in ("[Pipeline] checkout", "[Pipeline] git")
            and graph.functions.get(command) == "[Pipeline] sh",
            "Jenkins console does not identify both selected operations",
        )
        start = graph.allocation(checkout, stage)
        end = graph.allocation(command, stage)
        _require(
            len(graph.allocations.get(start, [])) == 1 and len(graph.allocations.get(end, [])) == 1,
            "Jenkins console lacks a unique log for the selected allocations",
        )
        if start != end:
            return {
                "state": "conflicting-allocations",
                "reason": "selected checkout and deployment belong to different Jenkins allocations",
            }
        agent, allocated_path = graph.allocations[start][0]
        _require(
            allocated_path == workspace,
            "Jenkins allocation log differs from the selected workspace",
        )
        return {
            "state": "controller-allocation-correlated",
            "allocation_node": start,
            "agent": agent,
            "workspace": workspace,
            "console_url": url,
            "console_sha256": digest,
        }
    except IncrementalsEvidenceError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        return {"state": "unresolved", "reason": reason}
