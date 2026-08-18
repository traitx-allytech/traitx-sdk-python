"""Flask integration, end to end.

    pip install flask
    TRAITX_BASE_URL=https://traitx.allytech.sa \
    TRAITX_PRIVATE_KEY=trx_pvk_... \
    python examples/flask_app.py

The browser sends the collector's requestId in `X-TraitX-Request-Id`; every route
below reads it and evaluates the matching event group.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

from traitx import Action, EventSession, EventUser, TraitXClient

app = Flask(__name__)

# One client per process. The circuit breaker lives on the instance, so a client
# per request would never open.
traitx = TraitXClient(
    base_url=os.environ["TRAITX_BASE_URL"],
    api_key=os.environ["TRAITX_PRIVATE_KEY"],
    application_id=os.environ.get("TRAITX_APPLICATION_ID"),
    timeout_ms=2500,
    failure_mode=Action.ALLOW,       # TraitX down must not block logins
    client_error_mode=Action.ALLOW,  # a rotated key must not block logins either
)


def request_id() -> str:
    return request.headers.get("X-TraitX-Request-Id", "")


def user_context():
    return traitx.context_from_request(request.headers, request.remote_addr)


@app.post("/api/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "")

    # Authenticate first: TraitX decides whether to trust a *successful* login,
    # and sending the event before you know that muddies the signal.
    user = authenticate(email, payload.get("password", ""))
    if user is None:
        return jsonify(error="invalid credentials"), 401

    decision = traitx.evaluate_login(
        request_id=request_id(),
        user=EventUser(id=user["id"], email=user["email"], registered_at=user["created_at"]),
        session=EventSession(id=request.cookies.get("session")),
        context=user_context(),
    )

    app.logger.info(
        "traitx login decision user=%s %s policies=%s",
        user["id"],
        decision,
        [p.name for p in decision.matched_policies],
    )

    if decision.is_denied():
        return jsonify(error="access denied", reference=decision.request_id), 403

    if decision.requires_challenge():
        send_otp(user)
        return jsonify(next="otp", signals=decision.signals), 200

    return jsonify(token=issue_token(user))


@app.post("/api/verify-otp")
def verify_otp():
    payload = request.get_json(silent=True) or {}
    ok = check_otp(payload.get("user_id"), payload.get("code"))

    # Close the loop so $challenge policies can react to repeated failures.
    traitx.report_challenge_outcome(
        request_id=request_id(),
        passed=ok,
        user=EventUser(id=payload.get("user_id")),
        context=user_context(),
    )

    if not ok:
        return jsonify(error="invalid code"), 401
    return jsonify(token="…")


@app.post("/api/transfer")
def transfer():
    payload = request.get_json(silent=True) or {}

    decision = traitx.evaluate_transaction(
        request_id=request_id(),
        amount=payload.get("amount"),
        currency=payload.get("currency", "SAR"),
        payee_id=payload.get("payee_id"),
        user=EventUser(id=payload.get("user_id")),
        context=user_context(),
        attributes={
            # A dotted key is a literal key name, not a nested object.
            "payment.channel": payload.get("channel", "sarie"),
            "counterparty.country": payload.get("counterparty_country", "SA"),
        },
    )

    if decision.is_denied():
        return jsonify(error="transfer blocked", reference=decision.request_id), 403

    if decision.requires_challenge():
        return jsonify(next="3ds", score=decision.score), 200

    return jsonify(status="submitted")


@app.get("/healthz")
def healthz():
    """Surface the breaker so your own monitoring can see a TraitX outage."""
    return jsonify(traitx_breaker=traitx.breaker_state)


# --- stand-ins for your real application ------------------------------------

def authenticate(email, password):
    return {"id": "usr_1", "email": email, "created_at": None} if password else None


def send_otp(user):
    app.logger.info("otp sent to %s", user["email"])


def check_otp(user_id, code):
    return code == "123456"


def issue_token(user):
    return f"token-for-{user['id']}"


if __name__ == "__main__":
    app.run(port=8000, debug=True)
