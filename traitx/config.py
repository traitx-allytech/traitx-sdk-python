"""Client configuration. See SPEC.md section 8."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from .errors import ConfigurationError
from .types import Action

SDK_VERSION = "1.0.0"

_LOGGER = logging.getLogger("traitx")


@dataclass
class Thresholds:
    """Score bands used only when the policy chain returned no action."""

    challenge: float = 40.0
    deny: float = 70.0


@dataclass
class BreakerOptions:
    failure_threshold: int = 5
    reset_after_ms: int = 30_000


@dataclass
class Config:
    """Resolved client configuration.

    Prefer :func:`build_config`, which validates and applies defaults.
    """

    base_url: str
    api_key: str
    application_id: Optional[str] = None

    timeout_ms: int = 2500
    max_retries: int = 2
    retry_backoff_ms: int = 100

    failure_mode: Action = Action.ALLOW
    client_error_mode: Action = Action.ALLOW

    thresholds: Thresholds = field(default_factory=Thresholds)
    deny_on_signals: Sequence[str] = field(default_factory=tuple)
    challenge_on_signals: Sequence[str] = field(default_factory=tuple)

    enforce_shadow_decisions: bool = False

    breaker: BreakerOptions = field(default_factory=BreakerOptions)

    user_agent: str = f"traitx-sdk-python/{SDK_VERSION}"
    debug: bool = False
    logger: logging.Logger = _LOGGER

    #: Post-process every decision. Return a replacement or ``None``.
    on_decision: Optional[Callable[["object"], Optional["object"]]] = None


def redact_key(key: str) -> str:
    """Render a key for logs: ``trx_pvk_...a9f3``. Never log the full value."""
    if not key:
        return "<empty>"
    tail = key[-4:] if len(key) > 4 else ""
    return f"{key[:8]}...{tail}"


def build_config(
    base_url: str,
    api_key: str,
    *,
    application_id: Optional[str] = None,
    timeout_ms: int = 2500,
    max_retries: int = 2,
    retry_backoff_ms: int = 100,
    failure_mode: Action = Action.ALLOW,
    client_error_mode: Action = Action.ALLOW,
    challenge_threshold: float = 40.0,
    deny_threshold: float = 70.0,
    deny_on_signals: Optional[Sequence[str]] = None,
    challenge_on_signals: Optional[Sequence[str]] = None,
    enforce_shadow_decisions: bool = False,
    breaker_failure_threshold: int = 5,
    breaker_reset_after_ms: int = 30_000,
    user_agent: Optional[str] = None,
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
    on_decision: Optional[Callable] = None,
) -> Config:
    """Validate inputs and return a :class:`Config`."""
    cleaned_url = (base_url or "").strip().rstrip("/")
    if not cleaned_url:
        raise ConfigurationError("base_url is required")
    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://")):
        raise ConfigurationError(
            f'base_url must be an absolute http(s) URL, got "{base_url}"'
        )

    cleaned_key = (api_key or "").strip()
    if not cleaned_key:
        raise ConfigurationError("api_key is required")
    if cleaned_key.startswith("trx_") and not cleaned_key.startswith("trx_pvk_"):
        raise ConfigurationError(
            "api_key looks like a PUBLIC collector key (trx_...). The decision SDK needs "
            "the PRIVATE key (trx_pvk_...) and must only ever run server-side."
        )

    if challenge_threshold > deny_threshold:
        raise ConfigurationError(
            f"challenge_threshold ({challenge_threshold}) must not exceed "
            f"deny_threshold ({deny_threshold})"
        )
    if timeout_ms <= 0:
        raise ConfigurationError("timeout_ms must be greater than 0")
    if max_retries < 0:
        raise ConfigurationError("max_retries must not be negative")

    return Config(
        base_url=cleaned_url,
        api_key=cleaned_key,
        application_id=application_id,
        timeout_ms=timeout_ms,
        max_retries=max_retries,
        retry_backoff_ms=retry_backoff_ms,
        failure_mode=Action(failure_mode),
        client_error_mode=Action(client_error_mode),
        thresholds=Thresholds(challenge=challenge_threshold, deny=deny_threshold),
        deny_on_signals=tuple(deny_on_signals or ()),
        challenge_on_signals=tuple(challenge_on_signals or ()),
        enforce_shadow_decisions=enforce_shadow_decisions,
        breaker=BreakerOptions(
            failure_threshold=breaker_failure_threshold,
            reset_after_ms=breaker_reset_after_ms,
        ),
        user_agent=user_agent or f"traitx-sdk-python/{SDK_VERSION}",
        debug=debug,
        logger=logger or _LOGGER,
        on_decision=on_decision,
    )


__all__ = [
    "BreakerOptions",
    "Config",
    "SDK_VERSION",
    "Thresholds",
    "build_config",
    "redact_key",
]
