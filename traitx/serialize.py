"""Event to wire payload. See SPEC.md section 3.

The Risk API is snake_case, expects ``context.headers`` as a list of
``[name, value]`` pairs, and takes custom attributes at the event root.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .errors import ValidationError
from .types import EventStatus, EventType, RiskEvent, to_iso, utcnow

CHAIN_HOOKS = frozenset({"$before_all", "$after_all"})

KNOWN_EVENT_TYPES = tuple(member.value for member in EventType)

#: Fields the SDK owns; a custom attribute may not shadow them.
RESERVED_ROOT_KEYS = frozenset(
    {"request_id", "type", "status", "created_at", "session", "context", "user"}
)

#: Headers worth forwarding from an inbound request.
INTERESTING_HEADERS = (
    "user-agent",
    "accept-language",
    "accept",
    "referer",
    "x-forwarded-for",
)


def _compact(source: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in source.items():
        if value is None:
            continue
        if isinstance(value, Mapping):
            nested = _compact(value)
            if nested:
                out[key] = nested
            continue
        out[key] = value
    return out


def _event_type_value(event: RiskEvent) -> str:
    raw = event.type
    return raw.value if isinstance(raw, EventType) else str(raw or "").strip()


def validate_event(event: RiskEvent) -> None:
    """Reject events the SDK will not send. Raises :class:`ValidationError`."""
    if not isinstance(event, RiskEvent):
        raise ValidationError("a RiskEvent is required")

    event_type = _event_type_value(event)
    if not event_type:
        raise ValidationError("event.type is required, e.g. EventType.LOGIN")
    if event_type in CHAIN_HOOKS:
        raise ValidationError(
            f'"{event_type}" is a policy chain hook, not an event type — it runs '
            "automatically on every event. Send the concrete group instead "
            "(EventType.LOGIN, EventType.TRANSACTION, ...)."
        )
    if not event_type.startswith("$"):
        raise ValidationError(
            f'event.type must be a policy event group starting with "$", got "{event_type}". '
            f"Known groups: {', '.join(KNOWN_EVENT_TYPES)}."
        )

    if not str(event.request_id or "").strip():
        raise ValidationError(
            "event.request_id is required — it is the requestId returned by the browser "
            "collector's get(). Without it the event carries no device context and "
            "device/IP policies cannot match."
        )

    for key in (event.attributes or {}):
        if key in RESERVED_ROOT_KEYS:
            raise ValidationError(
                f'attribute "{key}" collides with a reserved root field; use a different name'
            )


def serialize_event(event: RiskEvent, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Build the JSON body for ``POST /api/v1/risk``."""
    validate_event(event)
    now = now or utcnow()

    status = event.status
    status_value = status.value if isinstance(status, EventStatus) else str(status or EventStatus.SUCCEEDED.value)

    payload: Dict[str, Any] = {
        "request_id": str(event.request_id).strip(),
        "type": _event_type_value(event),
        "status": status_value,
        "created_at": to_iso(event.created_at, now),
    }

    if event.session is not None:
        session = _compact(
            {"id": event.session.id, "created_at": to_iso(event.session.created_at)}
        )
        if session:
            payload["session"] = session

    if event.context is not None:
        context: Dict[str, Any] = {}
        if event.context.ip:
            context["ip"] = event.context.ip
        if event.context.headers:
            # Pairs, not an object — see SPEC.md 3.1.
            context["headers"] = [[str(name), str(value)] for name, value in event.context.headers]
        if context:
            payload["context"] = context

    if event.user is not None:
        address = None
        if event.user.address is not None:
            address = _compact(
                {
                    "line1": event.user.address.line1,
                    "line2": event.user.address.line2,
                    "city": event.user.address.city,
                    "region_code": event.user.address.region_code,
                    "postal_code": event.user.address.postal_code,
                    "country_code": event.user.address.country_code,
                    "latitude": event.user.address.latitude,
                    "longitude": event.user.address.longitude,
                }
            )
        user = _compact(
            {
                "id": event.user.id,
                "email": event.user.email,
                "name": event.user.name,
                "first_name": event.user.first_name,
                "last_name": event.user.last_name,
                "username": event.user.username,
                "phone": event.user.phone,
                "national_id": event.user.national_id,
                "created_at": to_iso(event.user.created_at),
                "registered_at": to_iso(event.user.registered_at),
                "updated_at": to_iso(event.user.updated_at),
                "address": address,
            }
        )
        if user:
            payload["user"] = user

    for key, value in (event.attributes or {}).items():
        if value is not None:
            payload[key] = value

    return payload


def _canonical_header_name(lower: str) -> str:
    return "-".join(part.capitalize() for part in lower.split("-"))


def context_from_headers(
    headers: Mapping[str, str], remote_addr: Optional[str] = None
) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """Extract the end user's IP and interesting headers from a header mapping.

    Handles ``X-Forwarded-For`` so you send the client IP rather than your
    proxy's. Works with any framework: pass ``request.headers``.
    """
    lowered = {str(k).lower(): v for k, v in headers.items()}
    forwarded = lowered.get("x-forwarded-for")

    ip: Optional[str] = None
    if forwarded:
        ip = forwarded.split(",")[0].strip() or None
    if not ip:
        ip = remote_addr or None

    collected: List[Tuple[str, str]] = []
    for name in INTERESTING_HEADERS:
        value = lowered.get(name)
        if value:
            collected.append((_canonical_header_name(name), value))

    return ip, collected


__all__ = [
    "CHAIN_HOOKS",
    "RESERVED_ROOT_KEYS",
    "context_from_headers",
    "serialize_event",
    "validate_event",
]
