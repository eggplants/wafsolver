"""Exceptions raised by wafsolver."""

from __future__ import annotations


class WafSolveError(Exception):
    """Base class for every failure while solving a WAF challenge."""


class ChallengePageError(WafSolveError):
    """Raised when a page does not look like an AWS WAF challenge page."""


class UnsupportedChallengeError(WafSolveError):
    """Raised when the WAF serves a challenge type this library cannot solve."""

    def __init__(self, challenge_type: str) -> None:
        """Initialize the error.

        Args:
            challenge_type (str): The unrecognised challenge type identifier.
        """
        self.challenge_type = challenge_type
        super().__init__(f"Unsupported AWS WAF challenge type: {challenge_type}")


class InvalidDifficultyError(WafSolveError):
    """Raised when a challenge reports a difficulty with no known meaning."""

    def __init__(self, difficulty: int) -> None:
        """Initialize the error.

        Args:
            difficulty (int): The unusable difficulty.
        """
        self.difficulty = difficulty
        super().__init__(f"Invalid difficulty {difficulty}")


class TokenRequestError(WafSolveError):
    """Raised when the token endpoint rejects the solution."""


__all__ = (
    "ChallengePageError",
    "InvalidDifficultyError",
    "TokenRequestError",
    "UnsupportedChallengeError",
    "WafSolveError",
)
