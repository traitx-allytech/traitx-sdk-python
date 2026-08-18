"""Shared types for the TraitX decision SDK.

Wire values are the strings the Risk API and the policy engine
(``models/policy.go``) actually use. Mirrors ``sdk/SPEC.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


class Action(str, Enum):
    """The three answers the SDK can give. See SPEC.md section 1."""

    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"


class Reason(str, Enum):
    """How the decision was reached. See SPEC.md section 6."""

    POLICY_MATCH = "policy_match"
    SHADOW = "shadow"
    SCORE_THRESHOLD = "score_threshold"
    SIGNAL_OVERRIDE = "signal_override"
    NO_MATCH = "no_match"
    DEGRADED = "degraded"
    CLIENT_ERROR = "client_error"


class RiskLevel(str, Enum):
    """Informational banding derived from the score. See SPEC.md section 6.2."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Policy event groups, mirroring ``PolicyEventGroup`` in models/policy.go.

    ``$before_all`` and ``$after_all`` are intentionally absent: they are chain
    hooks that run on every event, not event types you can send.
    """

    LOGIN = "$login"
    REGISTRATION = "$registration"
    LOGOUT = "$logout"
    TRANSACTION = "$transaction"
    CHALLENGE = "$challenge"
    PROFILE = "$profile"
    PROFILE_UPDATE = "$profile_update"
    PROFILE_RESET = "$profile_reset"
    PASSWORD_RESET_REQUEST = "$password_reset_request"
    CUSTOM = "$custom"
    GENERIC = "$generic"


class EventStatus(str, Enum):
    SUCCEEDED = "$succeeded"
    FAILED = "$failed"


Timestamp = Union[datetime, str, None]


@dataclass
class UserAddress:
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    region_code: Optional[str] = None
    postal_code: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


@dataclass
class EventUser:
    id: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    national_id: Optional[str] = None
    created_at: Timestamp = None
    registered_at: Timestamp = None
    updated_at: Timestamp = None
    address: Optional[UserAddress] = None


@dataclass
class EventSession:
    id: Optional[str] = None
    created_at: Timestamp = None


@dataclass
class EventContext:
    """Request context describing the **end user**, not your server.

    ``headers`` is a sequence of ``(name, value)`` pairs because headers can
    repeat and the policy engine matches on ordered pairs. See SPEC.md 3.1.
    """

    ip: Optional[str] = None
    headers: Sequence[Tuple[str, str]] = field(default_factory=list)


@dataclass
class RiskEvent:
    """One input to :meth:`TraitXClient.evaluate`."""

    request_id: str
    type: Union[EventType, str]
    status: Union[EventStatus, str] = EventStatus.SUCCEEDED
    created_at: Timestamp = None
    session: Optional[EventSession] = None
    context: Optional[EventContext] = None
    user: Optional[EventUser] = None
    #: Business attributes merged into the event root, e.g. ``amount``,
    #: ``{"merchant.mcc": "5967"}``. A dotted key is a literal key name, never a
    #: nested object. See SPEC.md 3.2.
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchedPolicy:
    """A policy the chain reported as matched."""

    id: str
    name: str
    action: Optional[Action] = None
    event_group: Optional[str] = None
    #: True when the policy is deployed in shadow mode and must not enforce.
    pass_through: bool = False


def risk_level_for(score: float) -> RiskLevel:
    """Score to risk level. See SPEC.md section 6.2."""
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def severity(action: Action) -> int:
    """Ordering used when escalating between actions. See SPEC.md section 6."""
    if action == Action.DENY:
        return 2
    if action == Action.CHALLENGE:
        return 1
    return 0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: Timestamp, fallback: Optional[datetime] = None) -> Optional[str]:
    """RFC 3339 with milliseconds, always UTC — what the Risk API expects."""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
    if isinstance(value, str) and value.strip():
        return value
    if fallback is not None:
        return to_iso(fallback)
    return None


__all__ = [
    "Action",
    "EventContext",
    "EventSession",
    "EventStatus",
    "EventType",
    "EventUser",
    "MatchedPolicy",
    "Reason",
    "RiskEvent",
    "RiskLevel",
    "UserAddress",
    "risk_level_for",
    "severity",
    "to_iso",
    "utcnow",
]
