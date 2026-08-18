"""Transport, serialisation and client behaviour, with a stub transport.

No network calls are made.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traitx import (  # noqa: E402
    Action,
    ConfigurationError,
    EventContext,
    EventType,
    EventUser,
    HttpOutcome,
    RiskEvent,
    TraitXClient,
    UserAddress,
    ValidationError,
    serialize_event,
)
from traitx.breaker import CircuitBreaker  # noqa: E402
from traitx.config import BreakerOptions  # noqa: E402
from traitx.http import RequestSpec  # noqa: E402

BASE = dict(base_url="https://traitx.example/", api_key="trx_pvk_test_key_abcd")


class StubTransport:
    """Records requests and replays queued outcomes."""

    def __init__(self, outcomes):
        self.calls = []
        self._outcomes = outcomes if isinstance(outcomes, list) else [outcomes]
        self.breaker = CircuitBreaker(BreakerOptions())

    def send(self, spec: RequestSpec) -> HttpOutcome:
        self.calls.append(spec)
        outcome = self._outcomes[min(len(self.calls) - 1, len(self._outcomes) - 1)]
        return outcome() if callable(outcome) else outcome


def make_client(outcomes=None, **options):
    transport = StubTransport(
        outcomes if outcomes is not None else HttpOutcome(status_code=200, body={"score": 5})
    )
    client = TraitXClient(transport=transport, **{**BASE, **options})
    return client, transport


class ConfigurationTest(unittest.TestCase):
    def test_rejects_public_collector_key(self):
        with self.assertRaises(ConfigurationError):
            TraitXClient(base_url="https://x.test", api_key="trx_116d72cb")

    def test_rejects_relative_base_url(self):
        with self.assertRaises(ConfigurationError):
            TraitXClient(base_url="traitx.example", api_key="trx_pvk_k")

    def test_rejects_inverted_thresholds(self):
        with self.assertRaises(ConfigurationError):
            TraitXClient(**BASE, challenge_threshold=90, deny_threshold=50)

    def test_trims_trailing_slash(self):
        client, _ = make_client()
        self.assertEqual(client.config.base_url, "https://traitx.example")


class RequestShapeTest(unittest.TestCase):
    def test_posts_to_risk_endpoint(self):
        client, transport = make_client(application_id="app-123")
        client.evaluate_login("req_1", user=EventUser(id="u1"))

        self.assertEqual(len(transport.calls), 1)
        spec = transport.calls[0]
        self.assertEqual(spec.method, "POST")
        self.assertEqual(spec.path, "/api/v1/risk")
        self.assertEqual(spec.body["request_id"], "req_1")
        self.assertEqual(spec.body["type"], "$login")

    def test_serialises_headers_as_pairs_and_attributes_at_root(self):
        payload = serialize_event(
            RiskEvent(
                request_id="req_2",
                type=EventType.TRANSACTION,
                context=EventContext(
                    ip="66.118.160.25",
                    headers=[("User-Agent", "curl/8"), ("Accept-Language", "ar-SA")],
                ),
                user=EventUser(
                    id="u1", email="a@b.c", first_name="Sara", address=UserAddress(country_code="SA")
                ),
                attributes={"amount": 5000, "merchant.mcc": "5967"},
            )
        )

        self.assertEqual(
            payload["context"]["headers"],
            [["User-Agent", "curl/8"], ["Accept-Language", "ar-SA"]],
        )
        self.assertEqual(payload["amount"], 5000)
        self.assertEqual(payload["merchant.mcc"], "5967")
        self.assertEqual(payload["user"]["first_name"], "Sara")
        self.assertEqual(payload["user"]["address"]["country_code"], "SA")
        self.assertEqual(payload["status"], "$succeeded")
        self.assertTrue(payload["created_at"].endswith("Z"))

    def test_transaction_helper_puts_fields_at_root(self):
        client, transport = make_client()
        client.evaluate_transaction("req_3", amount=1200, currency="SAR", payee_id="payee_9")
        body = transport.calls[0].body
        self.assertEqual(body["amount"], 1200)
        self.assertEqual(body["currency"], "SAR")
        self.assertEqual(body["payee_id"], "payee_9")
        self.assertEqual(body["type"], "$transaction")

    def test_challenge_outcome_maps_to_status(self):
        client, transport = make_client()
        client.report_challenge_outcome("req_4", passed=False)
        body = transport.calls[0].body
        self.assertEqual(body["type"], "$challenge")
        self.assertEqual(body["status"], "$failed")


class ValidationTest(unittest.TestCase):
    def test_rejects_missing_request_id(self):
        client, _ = make_client()
        with self.assertRaises(ValidationError):
            client.evaluate_login("")

    def test_rejects_chain_hook_as_event_type(self):
        client, _ = make_client()
        with self.assertRaises(ValidationError) as ctx:
            client.evaluate(RiskEvent(request_id="req_5", type="$before_all"))
        self.assertIn("chain hook", str(ctx.exception))

    def test_rejects_reserved_attribute(self):
        with self.assertRaises(ValidationError):
            serialize_event(RiskEvent(request_id="r", type="$login", attributes={"user": {}}))


class DegradationTest(unittest.TestCase):
    def test_transport_error_degrades(self):
        client, _ = make_client(
            HttpOutcome(status_code=0, transport_error="ECONNREFUSED"),
            failure_mode=Action.CHALLENGE,
        )
        decision = client.evaluate_login("req_6")
        self.assertEqual(decision.action, Action.CHALLENGE)
        self.assertEqual(decision.reason.value, "degraded")
        self.assertTrue(decision.degraded)

    def test_unauthorized_reports_api_message(self):
        client, _ = make_client(
            HttpOutcome(
                status_code=401,
                body={"error": "Unauthorized", "message": "Invalid or expired API key"},
            )
        )
        decision = client.evaluate_login("req_7")
        self.assertEqual(decision.action, Action.ALLOW)
        self.assertEqual(decision.reason.value, "client_error")
        self.assertIn("Invalid or expired API key", decision.error)


class BreakerTest(unittest.TestCase):
    def test_opens_after_threshold_and_short_circuits(self):
        clock = [0.0]
        breaker = CircuitBreaker(
            BreakerOptions(failure_threshold=2, reset_after_ms=30_000), clock=lambda: clock[0]
        )
        self.assertTrue(breaker.allow_request())
        breaker.record_failure()
        self.assertTrue(breaker.allow_request())
        breaker.record_failure()
        self.assertEqual(breaker.state.value, "open")
        self.assertFalse(breaker.allow_request())

        clock[0] += 31.0
        self.assertEqual(breaker.state.value, "half_open")
        self.assertTrue(breaker.allow_request(), "one probe admitted")
        self.assertFalse(breaker.allow_request(), "concurrent callers short-circuited")

        breaker.record_success()
        self.assertEqual(breaker.state.value, "closed")

    def test_success_resets_counter(self):
        breaker = CircuitBreaker(BreakerOptions(failure_threshold=3, reset_after_ms=1000))
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_success()
        breaker.record_failure()
        self.assertEqual(breaker.state.value, "closed")


class ContextTest(unittest.TestCase):
    def test_prefers_first_forwarded_hop(self):
        context = TraitXClient.context_from_request(
            {
                "X-Forwarded-For": "66.118.160.25, 10.0.0.1",
                "User-Agent": "Mozilla/5.0",
                "Accept-Language": "ar-SA",
            },
            remote_addr="10.0.0.1",
        )
        self.assertEqual(context.ip, "66.118.160.25")
        self.assertIn(("User-Agent", "Mozilla/5.0"), context.headers)

    def test_falls_back_to_remote_addr(self):
        context = TraitXClient.context_from_request({"User-Agent": "x"}, remote_addr="203.0.113.9")
        self.assertEqual(context.ip, "203.0.113.9")


class ManagementTest(unittest.TestCase):
    def test_requires_portal_token(self):
        client, _ = make_client()
        with self.assertRaises(ConfigurationError):
            client.management.list_policies()

    def test_sends_bearer_and_omits_api_key(self):
        client, transport = make_client(
            HttpOutcome(status_code=200, body={"policies": []}), application_id="app-1"
        )
        client.management.with_token("jwt-abc")
        client.management.list_policies()

        spec = transport.calls[0]
        self.assertEqual(spec.headers["Authorization"], "Bearer jwt-abc")
        self.assertTrue(spec.omit_api_key)
        self.assertEqual(spec.query["application_id"], "app-1")

    def test_audit_splits_policies(self):
        client, _ = make_client(
            HttpOutcome(
                status_code=200,
                body={
                    "policies": [
                        {"name": "live", "enabled": True, "pass_through": False},
                        {"name": "shadow", "enabled": True, "pass_through": True},
                        {"name": "off", "enabled": False, "pass_through": False},
                    ]
                },
            )
        )
        client.management.with_token("jwt")
        audit = client.management.audit_policies()

        self.assertEqual(audit["live"], ["live"])
        self.assertEqual(audit["shadow"], ["shadow"])
        self.assertEqual(audit["disabled"], ["off"])
        self.assertEqual(audit["total"], 3)

    def test_bulk_add_rejects_over_1000(self):
        client, _ = make_client()
        client.management.with_token("jwt")
        with self.assertRaises(ValidationError):
            client.management.add_list_entries("list-1", [{"value": str(i)} for i in range(1001)])


if __name__ == "__main__":
    unittest.main()
