"""The decision engine — SPEC.md sections 5 and 6.

No I/O happens here. Everything is a pure function of the HTTP outcome plus
configuration, which is what makes ``sdk/conformance/vectors.json`` runnable
directly against it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .config import Config
from .types import (
    Action,
    MatchedPolicy,
    Reason,
    RiskLevel,
    risk_level_for,
    severity,
)

# ---------------------------------------------------------------------------
# Tolerant parsing — SPEC.md 5.1
# ---------------------------------------------------------------------------

_ACTION_ALIASES = {
    "allow": Action.ALLOW,
    "pass": Action.ALLOW,
    "accept": Action.ALLOW,
    "approve": Action.ALLOW,
    "challenge": Action.CHALLENGE,
    "stepup": Action.CHALLENGE,
    "step_up": Action.CHALLENGE,
    "review": Action.CHALLENGE,
    "deny": Action.DENY,
    "block": Action.DENY,
    "reject": Action.DENY,
    "decline": Action.DENY,
}

_CLIENT_ERROR_STATUSES = frozenset({400, 401, 403, 404, 405, 409, 422})


def parse_action(value: Any) -> Optional[Action]:
    """Parse an action from the wire.

    Case-insensitive, tolerates a leading ``$``. Anything unrecognised yields
    ``None`` — treated as *absent*, never as allow, so a future action name can
    never silently open the gate.
    """
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    if key.startswith("$"):
        key = key[1:]
    return _ACTION_ALIASES.get(key)


def _first(source: Any, keys: Sequence[str]) -> Any:
    if not isinstance(source, dict):
        return None
    for key in keys:
        value = source.get(key)
        if value is not None:
            return value
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    if isinstance(value, (int, float)):
        return value != 0
    return False


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return None
    return None


def extract_chain_action(body: Dict[str, Any]) -> Optional[Action]:
    """Read the chain action from any of the shapes the deployment may return."""
    policy = body.get("policy") if isinstance(body.get("policy"), dict) else None
    decision = body.get("decision") if isinstance(body.get("decision"), dict) else None

    for candidate in (
        _first(policy, ("action", "decision", "inline_action", "inlineAction")),
        _first(decision, ("action", "decision")),
        body.get("decision"),
        body.get("action"),
    ):
        parsed = parse_action(candidate)
        if parsed is not None:
            return parsed
    return None


def extract_matched_policies(body: Dict[str, Any]) -> List[MatchedPolicy]:
    """Read the matched-policy list from any of the shapes the API may return."""
    policy = body.get("policy") if isinstance(body.get("policy"), dict) else None
    raw = _first(policy, ("matched", "matched_policies", "matchedPolicies", "hits"))
    if raw is None:
        raw = _first(body, ("matched_policies", "matchedPolicies", "matched"))
    if not isinstance(raw, list):
        return []

    matched: List[MatchedPolicy] = []
    for entry in raw:
        if isinstance(entry, str):
            # Some deployments return a bare list of policy ids.
            matched.append(MatchedPolicy(id=entry, name=entry))
            continue
        if not isinstance(entry, dict):
            continue
        matched.append(
            MatchedPolicy(
                id=str(_first(entry, ("id", "policy_id", "policyId")) or ""),
                name=str(_first(entry, ("name", "policy_name", "policyName")) or ""),
                action=parse_action(_first(entry, ("action", "inline_action", "inlineAction"))),
                event_group=_first(entry, ("event_group", "eventGroup")),
                pass_through=_as_bool(
                    _first(entry, ("pass_through", "passThrough", "shadow", "pass_through_mode"))
                ),
            )
        )
    return matched


def extract_score(body: Dict[str, Any]) -> float:
    data = body.get("data") if isinstance(body.get("data"), dict) else None
    candidate = _first(body, ("score", "risk_score", "riskScore"))
    if candidate is None:
        candidate = _first(data, ("score", "risk_score", "riskScore"))
    return _as_number(candidate) or 0.0


def extract_signals(body: Dict[str, Any]) -> List[str]:
    data = body.get("data") if isinstance(body.get("data"), dict) else None
    candidate = _first(body, ("signals", "risk_signals", "riskSignals"))
    if candidate is None:
        candidate = _first(data, ("signals", "risk_signals", "riskSignals"))
    if not isinstance(candidate, list):
        return []
    return [s for s in candidate if isinstance(s, str)]


def is_shadowed(matched: Sequence[MatchedPolicy], chain_action: Action) -> bool:
    """Is the chain's action suppressed because the deciding policies are shadow-mode?

    True only when the relevant matched policies are *all* flagged pass-through.
    If none exposes a pass-through flag we assume the server is the authority and
    return False. See SPEC.md 6.1.
    """
    deciding = [p for p in matched if p.action == chain_action]
    relevant = deciding or list(matched)
    if not relevant:
        return False
    return all(p.pass_through for p in relevant)


# ---------------------------------------------------------------------------
# Outcome and Decision
# ---------------------------------------------------------------------------


@dataclass
class HttpOutcome:
    """What the transport managed to obtain. Never an exception."""

    status_code: int = 0
    body: Optional[Dict[str, Any]] = None
    transport_error: Optional[str] = None
    latency_ms: int = 0


@dataclass
class Decision:
    """The result of :meth:`TraitXClient.evaluate`. See SPEC.md section 7."""

    action: Action
    reason: Reason
    score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    observed_action: Optional[Action] = None
    enforced: bool = True
    signals: List[str] = field(default_factory=list)
    matched_policies: List[MatchedPolicy] = field(default_factory=list)
    degraded: bool = False
    error: Optional[str] = None
    status_code: int = 0
    request_id: str = ""
    latency_ms: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    def is_allowed(self) -> bool:
        """True only for ``allow``.

        Do not branch on ``not is_denied()`` — that lets challenges through
        unchallenged, which is the most common way this integration goes wrong.
        """
        return self.action == Action.ALLOW

    def requires_challenge(self) -> bool:
        return self.action == Action.CHALLENGE

    def is_denied(self) -> bool:
        return self.action == Action.DENY

    def is_shadow(self) -> bool:
        return self.reason == Reason.SHADOW

    def has_device_context(self) -> bool:
        """False when no device enrichment was attached to this ``request_id``.

        In that case every ``ip_enrichment.*`` and ``threats.*`` trigger was
        unreachable and those policies could not have matched. See SPEC.md 13.
        """
        debug = self.raw.get("debug")
        if not isinstance(debug, dict):
            return True
        for value in debug.values():
            if isinstance(value, dict) and value.get("reason") == "no_enrichment_data":
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "observed_action": self.observed_action.value if self.observed_action else None,
            "enforced": self.enforced,
            "reason": self.reason.value,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "signals": list(self.signals),
            "matched_policies": [
                {
                    "id": p.id,
                    "name": p.name,
                    "action": p.action.value if p.action else None,
                    "event_group": p.event_group,
                    "pass_through": p.pass_through,
                }
                for p in self.matched_policies
            ],
            "degraded": self.degraded,
            "error": self.error,
            "status_code": self.status_code,
            "request_id": self.request_id,
            "latency_ms": self.latency_ms,
        }

    def __str__(self) -> str:
        bits = [f"action={self.action.value}", f"reason={self.reason.value}", f"score={self.score}"]
        if not self.enforced and self.observed_action:
            bits.append(f"observed={self.observed_action.value}")
        if self.degraded:
            bits.append("degraded")
        return f"TraitXDecision({' '.join(bits)})"


# ---------------------------------------------------------------------------
# Resolution — SPEC.md section 6
# ---------------------------------------------------------------------------


def _describe_api_error(status: int, body: Dict[str, Any]) -> str:
    error = body.get("error") if isinstance(body.get("error"), str) else None
    message = body.get("message") if isinstance(body.get("message"), str) else None
    detail = ": ".join([p for p in (error, message) if p])
    base = f"risk api rejected the request (HTTP {status})"
    return f"{base}: {detail}" if detail else base


def resolve_decision(outcome: HttpOutcome, config: Config, request_id: str) -> Decision:
    """Turn an HTTP outcome into a :class:`Decision`. Pure; unit-testable."""
    body = outcome.body or {}
    score = extract_score(body)
    signals = extract_signals(body)
    matched = extract_matched_policies(body)

    common = dict(
        score=score,
        risk_level=risk_level_for(score),
        signals=signals,
        matched_policies=matched,
        status_code=outcome.status_code,
        request_id=request_id,
        latency_ms=outcome.latency_ms,
        raw=body,
    )

    # Step 1 — transport failure.
    if (
        outcome.transport_error
        or outcome.status_code >= 500
        or outcome.status_code in (408, 429)
        or outcome.status_code == 0
    ):
        return Decision(
            action=config.failure_mode,
            reason=Reason.DEGRADED,
            observed_action=None,
            enforced=False,
            degraded=True,
            error=outcome.transport_error
            or f"risk api returned HTTP {outcome.status_code}",
            **common,
        )

    # Step 2 — client error. A rotated key is an engineering fault, not a verdict.
    if outcome.status_code in _CLIENT_ERROR_STATUSES or outcome.status_code >= 400:
        return Decision(
            action=config.client_error_mode,
            reason=Reason.CLIENT_ERROR,
            observed_action=None,
            enforced=False,
            degraded=True,
            error=_describe_api_error(outcome.status_code, body),
            **common,
        )

    # A 2xx we could not decode is a transport failure, not an allow.
    if outcome.body is None:
        return Decision(
            action=config.failure_mode,
            reason=Reason.DEGRADED,
            observed_action=None,
            enforced=False,
            degraded=True,
            error=(
                f"risk api returned HTTP {outcome.status_code} with a body that is not JSON"
            ),
            **common,
        )

    # Step 3 — the policy chain decided.
    chain_action = extract_chain_action(body)
    if chain_action is not None:
        shadowed = is_shadowed(matched, chain_action)
        enforce = (not shadowed) or config.enforce_shadow_decisions
        return Decision(
            action=chain_action if enforce else Action.ALLOW,
            reason=Reason.SHADOW
            if shadowed and not config.enforce_shadow_decisions
            else Reason.POLICY_MATCH,
            observed_action=chain_action,
            enforced=not shadowed,
            degraded=False,
            **common,
        )

    # Step 4 — derive from score, then let configured signals escalate.
    action = Action.ALLOW
    reason = Reason.NO_MATCH

    if score >= config.thresholds.deny:
        action, reason = Action.DENY, Reason.SCORE_THRESHOLD
    elif score >= config.thresholds.challenge:
        action, reason = Action.CHALLENGE, Reason.SCORE_THRESHOLD

    signal_set = set(signals)
    signal_action = Action.ALLOW
    if any(s in signal_set for s in config.deny_on_signals):
        signal_action = Action.DENY
    elif any(s in signal_set for s in config.challenge_on_signals):
        signal_action = Action.CHALLENGE

    if severity(signal_action) > severity(action):
        action, reason = signal_action, Reason.SIGNAL_OVERRIDE

    return Decision(
        action=action,
        reason=reason,
        observed_action=None,
        enforced=True,
        degraded=False,
        **common,
    )


__all__ = [
    "Decision",
    "HttpOutcome",
    "extract_chain_action",
    "extract_matched_policies",
    "extract_score",
    "extract_signals",
    "is_shadowed",
    "parse_action",
    "resolve_decision",
]
