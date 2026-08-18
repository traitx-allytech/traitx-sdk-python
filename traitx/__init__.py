"""TraitX decision SDK for Python.

Evaluate a risk event against your policy chain and get back one of three
answers: ``allow``, ``challenge`` or ``deny``.

::

    from traitx import TraitXClient, EventUser

    traitx = TraitXClient(
        base_url=os.environ["TRAITX_BASE_URL"],
        api_key=os.environ["TRAITX_PRIVATE_KEY"],
        application_id=os.environ.get("TRAITX_APPLICATION_ID"),
    )

    decision = traitx.evaluate_login(
        request_id=request.headers["X-TraitX-Request-Id"],
        user=EventUser(id=user.id, email=user.email),
        context=traitx.context_from_request(request.headers, request.remote_addr),
    )

    if decision.is_denied():
        abort(403)
    if decision.requires_challenge():
        return send_otp(user)

Requires Python 3.8+. No third-party dependencies.
"""

from .breaker import BreakerState, CircuitBreaker
from .client import TraitXClient
from .config import (
    BreakerOptions,
    Config,
    SDK_VERSION,
    Thresholds,
    build_config,
    redact_key,
)
from .decision import Decision, HttpOutcome, parse_action, resolve_decision
from .errors import ApiError, ConfigurationError, TraitXError, ValidationError
from .management import ManagementClient
from .serialize import context_from_headers, serialize_event, validate_event
from .types import (
    Action,
    EventContext,
    EventSession,
    EventStatus,
    EventType,
    EventUser,
    MatchedPolicy,
    Reason,
    RiskEvent,
    RiskLevel,
    UserAddress,
    risk_level_for,
    severity,
)

__version__ = SDK_VERSION

__all__ = [
    "Action",
    "ApiError",
    "BreakerOptions",
    "BreakerState",
    "CircuitBreaker",
    "Config",
    "ConfigurationError",
    "Decision",
    "EventContext",
    "EventSession",
    "EventStatus",
    "EventType",
    "EventUser",
    "HttpOutcome",
    "ManagementClient",
    "MatchedPolicy",
    "Reason",
    "RiskEvent",
    "RiskLevel",
    "SDK_VERSION",
    "Thresholds",
    "TraitXClient",
    "TraitXError",
    "UserAddress",
    "ValidationError",
    "build_config",
    "context_from_headers",
    "parse_action",
    "redact_key",
    "resolve_decision",
    "risk_level_for",
    "serialize_event",
    "severity",
    "validate_event",
    "__version__",
]
