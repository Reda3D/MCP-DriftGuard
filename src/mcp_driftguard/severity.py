"""Severity levels and their total order.

Severity is data, not policy: the *policy* decides which severity applies to a
given change, this module only defines the vocabulary and its ordering.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RANK[self]

    # ``Severity`` inherits from ``str``, so a silent fallback to lexical
    # comparison would be available for free — and "HIGH" < "CRITICAL" is
    # False lexicographically, which is the exact opposite of the intended
    # ordering. Comparisons against anything that is not a Severity therefore
    # raise instead of quietly returning a wrong answer.

    def _compare(self, other: object) -> int:
        if not isinstance(other, Severity):
            raise TypeError(
                "cannot compare Severity with %s; use Severity.parse() first" % type(other).__name__
            )
        return self.rank - other.rank

    def __lt__(self, other: object) -> bool:
        return self._compare(other) < 0

    def __le__(self, other: object) -> bool:
        return self._compare(other) <= 0

    def __gt__(self, other: object) -> bool:
        return self._compare(other) > 0

    def __ge__(self, other: object) -> bool:
        return self._compare(other) >= 0

    @property
    def sarif_level(self) -> str:
        """Map onto the three levels allowed by SARIF 2.1.0."""
        if self in (Severity.INFO, Severity.LOW):
            return "note"
        if self is Severity.MEDIUM:
            return "warning"
        return "error"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        if isinstance(value, Severity):
            return value
        if not isinstance(value, str):
            raise ValueError("severity must be a string, got %r" % (value,))
        try:
            return cls(value.strip().upper())
        except ValueError:
            raise ValueError(
                "unknown severity %r (expected one of: %s)"
                % (value, ", ".join(s.value for s in cls))
            ) from None


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def max_severity(values: Iterable[Severity]) -> Severity:
    """Highest severity in ``values``, or ``INFO`` when empty."""
    result = Severity.INFO
    for value in values:
        if value > result:
            result = value
    return result
