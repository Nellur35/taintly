"""Independent source-domain and consumer-role facts for one value occurrence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ValueDomain(str, Enum):
    """Literal representation guaranteed by the available source evidence."""

    DECIMAL_INTEGER = "decimal_integer"
    UNKNOWN = "unknown"


class ConsumerRole(str, Enum):
    """How the selected consumer uses the value at this boundary."""

    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ValueUse:
    """Two independently established facts about a single consumption."""

    domain: ValueDomain
    role: ConsumerRole
