"""Exceptions raised by the TraitX SDK."""

from __future__ import annotations

from typing import Any, Optional


class TraitXError(Exception):
    """Base class for every error this SDK raises."""


class ConfigurationError(TraitXError):
    """Raised at construction time for an unusable configuration."""


class ValidationError(TraitXError):
    """Raised for an event the SDK refuses to send.

    This is deliberately an exception rather than a degraded decision: it means
    the calling code is wrong, and it should fail in tests, not in production.
    """


class ApiError(TraitXError):
    """Raised by the management client (policies, lists).

    Those calls are administrative, so they fail loudly instead of degrading to
    an :class:`~traitx.types.Action`.
    """

    def __init__(self, message: str, status_code: int = 0, body: Optional[Any] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


__all__ = ["ApiError", "ConfigurationError", "TraitXError", "ValidationError"]
