# TraitX Decision SDK — Python

Turns a TraitX risk evaluation into one of three answers: **allow**, **challenge**,
**deny**. Python 3.8+, **no third-party dependencies**.

Wire contract and decision algorithm: [`SPEC.md`](SPEC.md).

---

## Install

```bash
pip install traitx-sdk
```

From this repository:

```bash
pip install -e .
```

---

## Quick start

```python
import os
from traitx import Action, EventUser, TraitXClient

# One client per process — the circuit breaker lives on the instance.
traitx = TraitXClient(
    base_url=os.environ["TRAITX_BASE_URL"],            # https://traitx.allytech.sa
    api_key=os.environ["TRAITX_PRIVATE_KEY"],          # trx_pvk_…
    application_id=os.environ.get("TRAITX_APPLICATION_ID"),
    timeout_ms=2500,
    failure_mode=Action.ALLOW,      # TraitX unreachable → do not block logins
)

decision = traitx.evaluate_login(
    request_id=request.headers["X-TraitX-Request-Id"],   # from the browser collector
    user=EventUser(id=user.id, email=user.email),
    context=traitx.context_from_request(request.headers, request.remote_addr),
)

if decision.is_denied():
    abort(403)
if decision.requires_challenge():
    return send_otp(user)
return issue_token(user)
```

`request_id` comes from the browser collector — see the
[Node SDK's browser helper](../node/README.md#1--browser-get-a-requestid) or the
manual. Your frontend passes it to your backend; your backend passes it here.

---

## Event helpers

```python
traitx.evaluate_login(request_id, user=…, session=…, context=…)
traitx.evaluate_registration(request_id, user=…, context=…)
traitx.evaluate_password_reset(request_id, user=…, context=…)
traitx.evaluate_profile_update(request_id, user=…, context=…)
traitx.report_challenge_outcome(request_id, passed=True, user=…)

traitx.evaluate_transaction(
    request_id,
    amount=5000,
    currency="SAR",
    payee_id="payee_88213",
    user=EventUser(id=user.id),
    context=…,
    attributes={
        "merchant.mcc": "5967",       # a dotted key is a literal key name
        "payment.channel": "mada",
    },
)
```

Anything else goes through `evaluate()` with an explicit `RiskEvent`:

```python
from traitx import EventType, RiskEvent

decision = traitx.evaluate(RiskEvent(
    request_id=request_id,
    type=EventType.CUSTOM,
    attributes={"promo_code": code, "device_count": 4},
))
```

---

## Reading a decision

```python
decision.action              # Action.ALLOW | Action.CHALLENGE | Action.DENY  ← act on this
decision.reason              # Reason.POLICY_MATCH | SHADOW | SCORE_THRESHOLD | …
decision.score               # 0–100
decision.risk_level          # RiskLevel.LOW | MEDIUM | HIGH | CRITICAL
decision.signals             # ['bot_behavior', 'tor_ip', …]
decision.matched_policies    # [MatchedPolicy(id=…, name=…, action=…, pass_through=…)]
decision.enforced            # False when the deciding policy is shadow-mode
decision.observed_action     # what the chain would have done
decision.degraded            # True when TraitX was unreachable or rejected the call
decision.latency_ms
decision.raw                 # full response body
decision.to_dict()           # log-friendly

decision.is_allowed()
decision.requires_challenge()
decision.is_denied()
decision.has_device_context()  # False → IP enrichment missing, IP policies unreachable
```

Branch on `is_allowed()`, never on `not is_denied()` — the latter lets challenges
through unchallenged, which is the most common way this integration goes wrong.

### Shadow mode

A policy deployed with `pass_through: true` evaluates and logs but does not
enforce. The SDK returns `ALLOW` with `enforced=False` and `observed_action` set
to what would have happened — log the pair to size a policy before turning it on:

```python
if not decision.enforced and decision.observed_action is not Action.ALLOW:
    logger.info("traitx shadow would_%s score=%s", decision.observed_action.value, decision.score)
```

---

## Failure behaviour

`evaluate()` never raises for network or API problems. It returns a decision with
`degraded=True` and the configured fallback:

| Situation | Option | Default |
| --- | --- | --- |
| Timeout, connection error, 5xx, 429, open breaker | `failure_mode` | `Action.ALLOW` |
| 401 / 400 / 403 — bad key or bad payload | `client_error_mode` | `Action.ALLOW` |

Both default to allow deliberately: a rotated key must not lock every customer out
of checkout. Set them to `Action.CHALLENGE` or `Action.DENY` if your risk appetite
says otherwise — that is a business decision, so the SDK makes you state it.

`ValidationError` **is** raised for events the SDK refuses to send (missing
`request_id`, `$before_all` as a type). Those are bugs in calling code.

---

## Configuration

```python
TraitXClient(
    base_url=…,
    api_key=…,
    application_id=None,
    timeout_ms=2500,
    max_retries=2,
    retry_backoff_ms=100,
    failure_mode=Action.ALLOW,
    client_error_mode=Action.ALLOW,
    challenge_threshold=40,          # used only when the chain gives no action
    deny_threshold=70,
    deny_on_signals=("headless_browser",),
    challenge_on_signals=("new_device",),
    enforce_shadow_decisions=False,
    breaker_failure_threshold=5,
    breaker_reset_after_ms=30_000,
    debug=False,
    logger=logging.getLogger("traitx"),
    on_decision=None,                # hook: return a replacement Decision or None
)
```

Worst-case latency is `timeout_ms × (max_retries + 1)` plus backoff — about 7.5 s
with the defaults. Lower `timeout_ms` on latency-critical paths.

---

## Management API (optional)

Policies and lists are administrative and authenticate with a **portal JWT**, not
the private key. These calls raise on failure.

```python
traitx.management.with_token(os.environ["TRAITX_PORTAL_JWT"])

audit = traitx.management.audit_policies()
logger.info("traitx policies: %d live, %d shadow, %d disabled",
            len(audit["live"]), len(audit["shadow"]), len(audit["disabled"]))

# Blocklist a device after a confirmed chargeback.
traitx.management.add_list_entry(
    BLOCKED_DEVICES_LIST_ID,
    value=visitor_id,
    comment=f"chargeback {case_id}",
    expires_at=datetime.now(timezone.utc) + timedelta(days=90),
)
```

---

## Self-check

```bash
TRAITX_BASE_URL=https://traitx.allytech.sa \
TRAITX_PRIVATE_KEY=trx_pvk_… \
TRAITX_APPLICATION_ID=ccf2d2a0-… \
python -m traitx.doctor req_abc123
```

Confirms the key class, connectivity, application scoping, whether IP enrichment
reached the event, and whether the chain returns an action.

## Tests

```bash
python -m unittest discover -s tests -v
```

`tests/test_conformance.py` runs [`conformance/vectors.json`](conformance/vectors.json),
the shared fixture every language binding must satisfy.

## Examples

* [`examples/flask_app.py`](examples/flask_app.py) — login, OTP callback, transfer,
  and a health route that exposes the breaker state.
