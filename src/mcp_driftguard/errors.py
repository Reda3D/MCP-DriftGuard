"""Error types mapped onto a documented, stable exit-code contract.

Exit codes are part of the public interface of a CI tool: pipelines branch on
them. They are defined once, here, and never redefined elsewhere.
"""

from __future__ import annotations

from typing import Optional

#: No finding at or above the configured failure threshold.
EXIT_OK = 0
#: At least one finding at or above the threshold, or a blocking rule fired.
EXIT_POLICY_VIOLATION = 1
#: The inputs could not be read or are invalid (bad JSON, bad arguments...).
EXIT_INPUT_ERROR = 2
#: Fail-closed: a required check could not be completed.
EXIT_FAIL_CLOSED = 3


class DriftGuardError(Exception):
    """Base class for every error raised on purpose by DriftGuard."""

    exit_code = EXIT_INPUT_ERROR
    kind = "error"

    def __init__(self, message: str, *, hint: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        if self.hint:
            return "%s\n  hint: %s" % (self.message, self.hint)
        return self.message


class InputError(DriftGuardError):
    """Malformed or unreadable input. Never a security decision."""

    exit_code = EXIT_INPUT_ERROR
    kind = "input_error"


class PolicyError(DriftGuardError):
    """The policy could not be understood.

    This is deliberately fatal and non-negotiable: a policy that cannot be
    parsed must never be interpreted as "no rules matched".
    """

    exit_code = EXIT_FAIL_CLOSED
    kind = "policy_error"


class FailClosed(DriftGuardError):
    """A check that was required could not be performed."""

    exit_code = EXIT_FAIL_CLOSED
    kind = "fail_closed"
