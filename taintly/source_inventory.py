"""Available source inputs and explicit acquisition gaps, not semantic coverage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from .models import Finding, Severity

T = TypeVar("T")


@dataclass(frozen=True)
class SourceIssue:
    source: str
    reason: str

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.reason.strip():
            raise ValueError("source issues require an identity and explanation")

    def finding(self) -> Finding:
        return Finding(
            rule_id="ENGINE-ERR",
            severity=Severity.LOW,
            title="Source acquisition incomplete",
            description=self.reason,
            file=self.source,
        )


@dataclass(frozen=True)
class SourceInventory(Generic[T]):
    items: tuple[T, ...] = ()
    issues: tuple[SourceIssue, ...] = ()

    @property
    def complete(self) -> bool:
        """No recorded acquisition issue within this producer's declared scope."""
        return not self.issues
