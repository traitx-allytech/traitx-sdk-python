"""``TraitXClient`` — the object your application holds.

Construct one per process and reuse it: the circuit breaker state lives on the
instance, so a client per request would never open and would buy you nothing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .breaker import CircuitBreaker
from .config import Config, SDK_VERSION, build_config, redact_key
from .decision import Decision, resolve_decision
from .errors import ApiError, ValidationError
from .http import RequestSpec, Transport
from .management import ManagementClient
from .serialize import context_from_headers, serialize_event
from .types import (
    Action,
    EventContext,
    EventSession,
    EventStatus,
    EventType,
    EventUser,
    RiskEvent,
)


class TraitXClient:
    """Evaluate risk events and get back allow / challenge / deny.

    ::

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
    """

    version = SDK_VERSION

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        transport: Optional[Transport] = None,
        **options: Any,
    ) -> None:
        self.config: Config = build_config(base_url, api_key, **options)
        self._breaker = CircuitBreaker(self.config.breaker)
        self._transport = transport or Transport(self.config, self._breaker)
        self.management = ManagementClient(self.config, self._transport)

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, event: RiskEvent) -> Decision:
        """Evaluate an event and return the decision to act on.

        Never raises for network or API problems — those degrade to
        ``failure_mode`` / ``client_error_mode`` with ``degraded=True``, so a
        TraitX outage cannot take your login or checkout path down. It *does*
        raise :class:`~traitx.errors.ValidationError` for an event the SDK will
        not send, because that is a bug in the calling code.
        """
        payload = serialize_event(event)

        outcome = self._transport.send(
            RequestSpec(method="POST", path="/api/v1/risk", body=payload)
        )

        decision = resolve_decision(outcome, self.config, str(event.request_id))

        if self.config.on_decision is not None:
            replacement = self.config.on_decision(decision)
            if replacement is not None:
                decision = replacement  # type: ignore[assignment]

        if self.config.debug:
            self.config.logger.debug("decision %s", decision)

        return decision

    def _evaluate(
        self,
        event_type: EventType,
        request_id: str,
        *,
        status: Union[EventStatus, str] = EventStatus.SUCCEEDED,
        user: Optional[EventUser] = None,
        session: Optional[EventSession] = None,
        context: Optional[EventContext] = None,
        created_at: Optional[datetime] = None,
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> Decision:
        return self.evaluate(
            RiskEvent(
                request_id=request_id,
                type=event_type,
                status=status,
                created_at=created_at,
                session=session,
                context=context,
                user=user,
                attributes=dict(attributes or {}),
            )
        )

    def evaluate_login(self, request_id: str, **kwargs: Any) -> Decision:
        """``$login`` shorthand."""
        return self._evaluate(EventType.LOGIN, request_id, **kwargs)

    def evaluate_registration(self, request_id: str, **kwargs: Any) -> Decision:
        """``$registration`` shorthand."""
        return self._evaluate(EventType.REGISTRATION, request_id, **kwargs)

    def evaluate_transaction(
        self,
        request_id: str,
        *,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
        payee_id: Optional[str] = None,
        attributes: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Decision:
        """``$transaction`` shorthand.

        ``amount``, ``currency`` and ``payee_id`` are sent as root-level
        attributes, which is where transaction policy triggers look for them.
        """
        merged: Dict[str, Any] = {}
        if amount is not None:
            merged["amount"] = amount
        if currency is not None:
            merged["currency"] = currency
        if payee_id is not None:
            merged["payee_id"] = payee_id
        merged.update(attributes or {})
        return self._evaluate(EventType.TRANSACTION, request_id, attributes=merged, **kwargs)

    def evaluate_password_reset(self, request_id: str, **kwargs: Any) -> Decision:
        """``$password_reset_request`` shorthand."""
        return self._evaluate(EventType.PASSWORD_RESET_REQUEST, request_id, **kwargs)

    def evaluate_profile_update(self, request_id: str, **kwargs: Any) -> Decision:
        """``$profile_update`` shorthand."""
        return self._evaluate(EventType.PROFILE_UPDATE, request_id, **kwargs)

    def report_challenge_outcome(self, request_id: str, passed: bool, **kwargs: Any) -> Decision:
        """Report the outcome of a step-up you issued, so ``$challenge`` policies can react."""
        kwargs.pop("status", None)
        return self._evaluate(
            EventType.CHALLENGE,
            request_id,
            status=EventStatus.SUCCEEDED if passed else EventStatus.FAILED,
            **kwargs,
        )

    # -- auxiliary ----------------------------------------------------------

    def get_fingerprint(self, request_id: str) -> Dict[str, Any]:
        """Full device fingerprint for a collector ``request_id``.

        Useful for case review and for enriching your own fraud store; not
        needed for a decision. Raises :class:`ApiError` on failure.
        """
        if not str(request_id or "").strip():
            raise ValidationError("request_id is required")

        from urllib.parse import quote

        outcome = self._transport.send(
            RequestSpec(method="GET", path=f"/api/v1/fingerprint/{quote(str(request_id), safe='')}")
        )
        if outcome.transport_error:
            raise ApiError(outcome.transport_error, outcome.status_code, outcome.body)
        if outcome.status_code >= 400:
            raise ApiError(
                f"fingerprint lookup failed with HTTP {outcome.status_code}",
                outcome.status_code,
                outcome.body,
            )
        return outcome.body or {}

    def health(self) -> bool:
        """Liveness probe against ``GET /health``."""
        outcome = self._transport.send(RequestSpec(method="GET", path="/health"))
        return not outcome.transport_error and 200 <= outcome.status_code < 300

    @staticmethod
    def context_from_request(
        headers: Mapping[str, str], remote_addr: Optional[str] = None
    ) -> EventContext:
        """Build an :class:`EventContext` from an inbound request's headers."""
        ip, collected = context_from_headers(headers, remote_addr)
        return EventContext(ip=ip, headers=collected)

    @property
    def breaker_state(self) -> str:
        """Current breaker state, for your own health endpoint."""
        return self._breaker.state.value

    def doctor(self, probe_request_id: Optional[str] = None) -> Dict[str, Any]:
        """Connectivity and configuration self-check. See SPEC.md section 13.

        Returns findings rather than raising, so it can run at boot behind a
        feature flag or from the CLI (``python -m traitx.doctor``).
        """
        findings: List[Dict[str, Any]] = []

        is_private = self.config.api_key.startswith("trx_pvk_")
        findings.append(
            {
                "check": "api key class",
                "ok": is_private,
                "detail": (
                    f"private key {redact_key(self.config.api_key)}"
                    if is_private
                    else f"key {redact_key(self.config.api_key)} is not a trx_pvk_ private key"
                ),
            }
        )

        healthy = self.health()
        findings.append(
            {
                "check": "deployment reachable",
                "ok": healthy,
                "detail": f"{self.config.base_url}/health "
                + ("responded" if healthy else "did not respond"),
            }
        )

        findings.append(
            {
                "check": "application scoping",
                "ok": bool(self.config.application_id),
                "detail": (
                    f"X-Application-ID {self.config.application_id}"
                    if self.config.application_id
                    else "no application_id set — management calls will fall back to the "
                    "tenant's oldest active application, which is rarely the one holding "
                    "your policies"
                ),
            }
        )

        if probe_request_id:
            decision = self.evaluate_login(probe_request_id)
            findings.append(
                {
                    "check": "risk api accepts the key",
                    "ok": decision.reason.value != "client_error",
                    "detail": decision.error
                    or f"HTTP {decision.status_code}, reason {decision.reason.value}",
                }
            )
            findings.append(
                {
                    "check": "device enrichment present",
                    "ok": decision.has_device_context(),
                    "detail": (
                        "IP enrichment attached; ip_enrichment.* policies can match"
                        if decision.has_device_context()
                        else "no enrichment for this request_id — ip_enrichment.* triggers "
                        "cannot match"
                    ),
                }
            )
            findings.append(
                {
                    "check": "policy chain returns an action",
                    "ok": decision.observed_action is not None,
                    "detail": (
                        f"chain action {decision.observed_action.value}, "
                        f"{len(decision.matched_policies)} matched"
                        if decision.observed_action is not None
                        else "no chain action in the response; decisions will fall back to "
                        "score thresholds"
                    ),
                }
            )

        return {"ok": all(f["ok"] for f in findings), "findings": findings}


__all__ = ["TraitXClient"]
